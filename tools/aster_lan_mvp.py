#!/usr/bin/env python3
# Copyright 2026 Defense Unicorns, Inc.
# SPDX-License-Identifier: Apache-2.0
"""Bounded operator client for the Aster LAN discovery MVP.

The client deliberately talks only to an agent's loopback, plaintext HTTP
application endpoint.  It does not control mesh discovery or inspect mesh
traffic.  Presence is established only when ``QueryEvents`` returns the exact
32-byte Event identifier supplied by the operator.
"""

from __future__ import annotations

import argparse
import base64
import binascii
import http.client
import ipaddress
import json
import math
import subprocess
import os
from pathlib import Path
import re
import secrets
import stat
import sys
import time
from typing import Any, Dict, List, Mapping, Optional, Sequence, Tuple
from urllib.parse import urlparse


SERVICE = "aster.application.v1alpha1.AsterApplicationService"
DEFAULT_URL = "http://127.0.0.1:8181"
DEFAULT_TOPIC = "mesh.messages"
DEFAULT_SCOPE = "demo/playground"

TOKEN_BYTES = 32
TOKEN_HEX_CHARACTERS = TOKEN_BYTES * 2
MAX_TOKEN_FILE_BYTES = 4 * 1024
MAX_OPERATION_KEY_BYTES = 256
MAX_TOPIC_BYTES = 128
MAX_SCOPE_BYTES = 128
MAX_LOGICAL_KEY_BYTES = 4 * 1024
MAX_PAYLOAD_BYTES = 4 * 1024
MAX_RPC_RESPONSE_BYTES = 2 * 1024 * 1024
QUERY_PAGE_LIMIT = 128
MAX_QUERY_PAGES = 9
MAX_REQUEST_SECONDS = 30.0
MAX_WAIT_SECONDS = 300.0
MAX_POLL_SECONDS = 10.0

TOKEN_PATTERN = re.compile(r"[0-9a-f]{%d}" % TOKEN_HEX_CHARACTERS)
METHOD_PATTERN = re.compile(r"[A-Za-z][A-Za-z0-9]*")


class OperatorError(RuntimeError):
    """A bounded, user-safe operator failure."""


class RpcError(OperatorError):
    """A bounded failure from the process-local Connect JSON endpoint."""


def _bounded_utf8(
    value: str,
    label: str,
    maximum: int,
    *,
    allow_empty: bool = False,
) -> bytes:
    try:
        encoded = value.encode("utf-8")
    except UnicodeEncodeError as error:
        raise OperatorError("%s is not valid UTF-8 text" % label) from error
    if (not allow_empty and not encoded) or len(encoded) > maximum:
        minimum = 0 if allow_empty else 1
        raise OperatorError("%s must be %d..=%d UTF-8 bytes" % (label, minimum, maximum))
    return encoded


def _canonical_route_name(value: str, label: str) -> str:
    maximum = MAX_TOPIC_BYTES if label == "topic" else MAX_SCOPE_BYTES
    encoded = _bounded_utf8(value, label, maximum)
    hierarchical = label == "scope"
    allowed = all(
        chr(byte).isalnum() and byte < 128
        or byte in b"._-"
        or hierarchical and byte == ord("/")
        for byte in encoded
    )
    if not allowed:
        raise OperatorError("%s contains a noncanonical character" % label)
    if hierarchical and (
        value.startswith("/")
        or value.endswith("/")
        or any(segment in ("", ".", "..") for segment in value.split("/"))
    ):
        raise OperatorError("scope contains a noncanonical path form")
    return value


def _encode_b64(value: bytes) -> str:
    return base64.b64encode(value).decode("ascii")


def canonical_event_id(value: str) -> str:
    """Validate and return one canonical standard-base64 32-byte Event ID."""

    try:
        decoded = base64.b64decode(value, validate=True)
    except (binascii.Error, ValueError) as error:
        raise OperatorError("event ID must be canonical base64 for exactly 32 bytes") from error
    if len(decoded) != 32 or _encode_b64(decoded) != value:
        raise OperatorError("event ID must be canonical base64 for exactly 32 bytes")
    return value


def _validate_token(token: str) -> str:
    if TOKEN_PATTERN.fullmatch(token) is None:
        raise OperatorError("client token must contain exactly 64 lowercase hexadecimal characters")
    # Authorization tokens are case-sensitive. Never normalize file contents:
    # the agent authenticates the exact bytes it loaded from this same file.
    return token


def create_token_file(path: Path) -> None:
    """Create one new 32-byte hexadecimal bearer token without overwriting."""

    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    flags |= getattr(os, "O_CLOEXEC", 0)
    flags |= getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags, 0o600)
    except FileExistsError as error:
        raise OperatorError("token file already exists: %s" % path) from error
    except OSError as error:
        raise OperatorError("could not create token file: %s" % path) from error

    complete = False
    try:
        os.fchmod(descriptor, 0o600)
        contents = (secrets.token_hex(TOKEN_BYTES) + "\n").encode("ascii")
        offset = 0
        while offset < len(contents):
            written = os.write(descriptor, contents[offset:])
            if written <= 0:
                raise OSError("short token write")
            offset += written
        os.fsync(descriptor)
        complete = True
    except OSError as error:
        raise OperatorError("could not write token file: %s" % path) from error
    finally:
        os.close(descriptor)
        if not complete:
            try:
                path.unlink()
            except OSError:
                pass


def read_token_file(path: Path) -> str:
    """Read one private, regular token file through a bounded descriptor."""

    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags)
    except OSError as error:
        raise OperatorError("could not open client token file: %s" % path) from error
    try:
        metadata = os.fstat(descriptor)
        if not stat.S_ISREG(metadata.st_mode):
            raise OperatorError("client token path is not a regular file")
        if metadata.st_mode & 0o077:
            raise OperatorError("client token file must not be accessible by group or others")
        chunks = []
        remaining = MAX_TOKEN_FILE_BYTES + 1
        while remaining:
            chunk = os.read(descriptor, remaining)
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        contents = b"".join(chunks)
    except OSError as error:
        raise OperatorError("could not read client token file: %s" % path) from error
    finally:
        os.close(descriptor)
    if len(contents) > MAX_TOKEN_FILE_BYTES:
        raise OperatorError("client token file exceeds the 4096-byte bound")
    try:
        token = contents.decode("ascii").strip()
    except UnicodeDecodeError as error:
        raise OperatorError("client token file is not ASCII") from error
    return _validate_token(token)


def _bounded_float(value: float, label: str, maximum: float, minimum: float = 0.1) -> float:
    if not minimum <= value <= maximum:
        raise OperatorError("%s must be between %s and %s seconds" % (label, minimum, maximum))
    return value


def _uint64(value: object, label: str) -> int:
    if isinstance(value, bool):
        raise RpcError("%s is malformed" % label)
    try:
        parsed = int(value)
    except (TypeError, ValueError) as error:
        raise RpcError("%s is malformed" % label) from error
    if parsed < 0 or parsed > (1 << 64) - 1:
        raise RpcError("%s is outside the uint64 range" % label)
    return parsed


class ConnectJsonClient:
    """Small stdlib client restricted to a literal loopback HTTP endpoint."""

    def __init__(self, base_url: str, token: str, timeout: float = 3.0) -> None:
        parsed = urlparse(base_url)
        try:
            loopback = parsed.hostname is not None and ipaddress.ip_address(parsed.hostname).is_loopback
            port = parsed.port
        except ValueError as error:
            raise OperatorError("application URL must use a literal loopback IP address") from error
        if (
            parsed.scheme != "http"
            or not loopback
            or port is None
            or parsed.username is not None
            or parsed.password is not None
            or parsed.path not in ("", "/")
            or parsed.params
            or parsed.query
            or parsed.fragment
        ):
            raise OperatorError(
                "application URL must be plain HTTP on a literal loopback IP and explicit port"
            )
        self.host = parsed.hostname
        self.port = port
        self.token = _validate_token(token)
        self.timeout = _bounded_float(timeout, "request timeout", MAX_REQUEST_SECONDS)

    def call(self, method: str, payload: Mapping[str, object]) -> Dict[str, object]:
        if METHOD_PATTERN.fullmatch(method) is None:
            raise RpcError("invalid local application method")
        body = json.dumps(payload, ensure_ascii=True, separators=(",", ":")).encode("utf-8")
        path = "/%s/%s" % (SERVICE, method)
        connection = http.client.HTTPConnection(self.host, self.port, timeout=self.timeout)
        try:
            connection.request(
                "POST",
                path,
                body=body,
                headers={
                    "Authorization": "Bearer " + self.token,
                    "Content-Type": "application/json",
                },
            )
            response = connection.getresponse()
            data = response.read(MAX_RPC_RESPONSE_BYTES + 1)
            status_code = response.status
        except (OSError, TimeoutError, http.client.HTTPException) as error:
            raise RpcError("local application request %s is unavailable" % method) from error
        finally:
            connection.close()
        if status_code < 200 or status_code >= 300:
            raise RpcError("local application request %s failed with HTTP %d" % (method, status_code))
        if len(data) > MAX_RPC_RESPONSE_BYTES:
            raise RpcError("local application response exceeds the 2 MiB bound")
        try:
            decoded = json.loads(data.decode("utf-8"))
        except (UnicodeDecodeError, ValueError, RecursionError) as error:
            raise RpcError("local application response is malformed") from error
        if not isinstance(decoded, dict):
            raise RpcError("local application response is not an object")
        return decoded

    def status(self) -> Dict[str, object]:
        return self.call("GetStatus", {})

    def subscribe(self, operation_key: bytes, topic: str, scope: str) -> Dict[str, object]:
        response = self.call(
            "CreateEventSubscription",
            {
                "operationKey": _encode_b64(operation_key),
                "topic": topic,
                "scope": scope,
                "includeDescendantScopes": False,
            },
        )
        subscription_id = response.get("subscriptionId")
        if not isinstance(subscription_id, str):
            raise RpcError("CreateEventSubscription returned no subscription ID")
        try:
            canonical_event_id(subscription_id)
        except OperatorError as error:
            raise RpcError("CreateEventSubscription returned a malformed subscription ID") from error
        return response

    def query_events(
        self,
        topic: str,
        scope: str,
        logical_key: Optional[bytes] = None,
        *,
        after_marker: int = 0,
    ) -> Tuple[List[Dict[str, object]], int]:
        marker = _uint64(after_marker, "starting scan marker")
        events: List[Dict[str, object]] = []
        for _ in range(MAX_QUERY_PAGES):
            request: Dict[str, object] = {
                "topic": topic,
                "scope": scope,
                "includeDescendantScopes": False,
                "afterAcceptanceMarker": str(marker),
                "limit": QUERY_PAGE_LIMIT,
            }
            if logical_key is not None:
                request["logicalKey"] = _encode_b64(logical_key)
            response = self.call("QueryEvents", request)
            page = response.get("events", [])
            if (
                not isinstance(page, list)
                or len(page) > QUERY_PAGE_LIMIT
                or not all(isinstance(item, dict) for item in page)
            ):
                raise RpcError("QueryEvents returned a malformed or oversized Event page")
            for item in page:
                event_id = item.get("id")
                if not isinstance(event_id, str):
                    raise RpcError("QueryEvents returned an Event without an ID")
                try:
                    canonical_event_id(event_id)
                except OperatorError as error:
                    raise RpcError("QueryEvents returned a malformed Event ID") from error
            scanned = _uint64(response.get("scannedThrough", marker), "QueryEvents scan marker")
            if scanned < marker:
                raise RpcError("QueryEvents scan marker moved backward")
            has_more = response.get("hasMore", False)
            if not isinstance(has_more, bool):
                raise RpcError("QueryEvents hasMore is malformed")
            previous_marker = marker
            events.extend(page)
            marker = scanned
            if not has_more:
                return events, marker
            if not page and marker == previous_marker:
                raise RpcError("QueryEvents pagination made no progress")
        raise RpcError("QueryEvents exceeded the nine-page operator bound")


def wait_for_exact_event(
    client: ConnectJsonClient,
    event_id: str,
    topic: str,
    scope: str,
    logical_key: Optional[bytes],
    wait_seconds: float,
    poll_seconds: float,
) -> Dict[str, object]:
    """Return only after a completed query contains the exact Event identity."""

    expected = canonical_event_id(event_id)
    wait_seconds = _bounded_float(wait_seconds, "wait timeout", MAX_WAIT_SECONDS)
    poll_seconds = _bounded_float(poll_seconds, "poll interval", MAX_POLL_SECONDS)
    deadline = time.monotonic() + wait_seconds
    marker = 0
    while True:
        events, marker = client.query_events(
            topic,
            scope,
            logical_key,
            after_marker=marker,
        )
        for event in events:
            if event["id"] == expected:
                return event
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise OperatorError("exact Event ID was not observed before the wait timeout")
        time.sleep(min(poll_seconds, remaining))


def _add_connection_arguments(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--url", default=DEFAULT_URL, help="loopback agent URL")
    parser.add_argument("--token-file", type=Path, required=True, help="private bearer token file")
    parser.add_argument("--timeout", type=float, default=3.0, help="per-request timeout in seconds")


def _add_route_arguments(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--topic", default=DEFAULT_TOPIC)
    parser.add_argument("--scope", default=DEFAULT_SCOPE)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Bounded loopback operator client for the Aster LAN MVP"
    )
    commands = parser.add_subparsers(dest="command", required=True)

    token = commands.add_parser("token", help="create a new private client token")
    token.add_argument("--file", type=Path, required=True)

    initialize = commands.add_parser("publication-init", help="explicitly create one numbered publication journal")
    _add_connection_arguments(initialize)
    _add_route_arguments(initialize)
    initialize.add_argument("--journal", type=Path, required=True)
    initialize.add_argument("--client-id", required=True)
    initialize.add_argument("--cli", default="asterctl")

    status = commands.add_parser("status", help="read one local status snapshot")
    _add_connection_arguments(status)

    subscribe = commands.add_parser("subscribe", help="create or replay one Event subscription")
    _add_connection_arguments(subscribe)
    _add_route_arguments(subscribe)
    subscribe.add_argument("--operation-key", required=True)

    publish = commands.add_parser("publish", help="publish one routine Event")
    _add_connection_arguments(publish)
    _add_route_arguments(publish)
    publish.add_argument("--journal", type=Path, required=True)
    publish.add_argument("--client-id", required=True)
    publish.add_argument("--cli", default="asterctl", help="journaled publication CLI")
    publish.add_argument("--logical-key", required=True)
    publish.add_argument("--payload", required=True)
    publish.add_argument(
        "--id-only",
        action="store_true",
        help="print only the canonical base64 Event ID for shell capture",
    )

    query = commands.add_parser("query", help="read a bounded complete Event query")
    _add_connection_arguments(query)
    _add_route_arguments(query)
    query.add_argument("--logical-key")

    wait = commands.add_parser("wait", help="wait for one exact Event ID")
    _add_connection_arguments(wait)
    _add_route_arguments(wait)
    wait.add_argument("--logical-key")
    wait.add_argument("--event-id", required=True)
    wait.add_argument("--wait-seconds", type=float, default=20.0)
    wait.add_argument("--poll-seconds", type=float, default=0.35)
    return parser


def _client_from_args(arguments: argparse.Namespace) -> ConnectJsonClient:
    token = read_token_file(arguments.token_file)
    return ConnectJsonClient(arguments.url, token, arguments.timeout)


def _route_from_args(arguments: argparse.Namespace) -> Tuple[str, str]:
    return (
        _canonical_route_name(arguments.topic, "topic"),
        _canonical_route_name(arguments.scope, "scope"),
    )


def _optional_logical_key(arguments: argparse.Namespace) -> Optional[bytes]:
    if arguments.logical_key is None:
        return None
    return _bounded_utf8(
        arguments.logical_key,
        "logical key",
        MAX_LOGICAL_KEY_BYTES,
        allow_empty=True,
    )


def _print_json(value: Mapping[str, object]) -> None:
    print(json.dumps(value, ensure_ascii=True, indent=2, sort_keys=True))


def _numbered_cli(arguments: argparse.Namespace, *, initialize: bool = False) -> Dict[str, object]:
    _bounded_utf8(arguments.client_id, "client ID", 64)
    command = [arguments.cli]
    if not initialize:
        parsed = urlparse(arguments.url)
        command.extend(["--host", str(parsed.hostname), "--port", str(parsed.port),
                        "--token-file", str(arguments.token_file), "--timeout", str(max(1, math.ceil(arguments.timeout))), "--json"])
    command.extend(["publication-init" if initialize else "publish", "--journal", str(arguments.journal), "--client-id", arguments.client_id])
    payload = None
    if not initialize:
        topic, scope = _route_from_args(arguments)
        _bounded_utf8(arguments.logical_key, "logical key", MAX_LOGICAL_KEY_BYTES, allow_empty=True)
        payload = _bounded_utf8(arguments.payload, "payload", MAX_PAYLOAD_BYTES, allow_empty=True)
        command.extend(["--topic", topic, "--scope", scope, "--priority", "routine", "--logical-key", arguments.logical_key])
    try:
        completed = subprocess.run(command, input=payload, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=35, check=False)
    except (OSError, subprocess.TimeoutExpired) as error:
        raise OperatorError("numbered publication interrupted; original journal retained") from error
    if completed.returncode != 0:
        raise OperatorError("numbered publication failed; use asterctl publication-recover/retry with the original journal")
    if initialize:
        return {"initialized": True}
    if len(completed.stdout) > MAX_RPC_RESPONSE_BYTES:
        raise OperatorError("numbered publication response exceeded its bound")
    try:
        result = json.loads(completed.stdout)
        canonical_event_id(result["result"]["receipt"]["eventId"])
    except (ValueError, TypeError, KeyError, OperatorError) as error:
        raise OperatorError("numbered publication returned an invalid committed receipt") from error
    return result


def run(arguments: argparse.Namespace) -> None:
    if arguments.command == "token":
        create_token_file(arguments.file)
        _print_json({"created": True, "tokenFile": str(arguments.file)})
        return

    if arguments.command == "publication-init":
        _print_json(_numbered_cli(arguments, initialize=True))
        return

    client = _client_from_args(arguments)
    if arguments.command == "status":
        _print_json(client.status())
        return

    topic, scope = _route_from_args(arguments)
    if arguments.command == "subscribe":
        operation_key = _bounded_utf8(
            arguments.operation_key,
            "operation key",
            MAX_OPERATION_KEY_BYTES,
        )
        _print_json(client.subscribe(operation_key, topic, scope))
        return
    if arguments.command == "publish":
        response = _numbered_cli(arguments)
        if arguments.id_only:
            print(response["result"]["receipt"]["eventId"])
        else:
            _print_json(response)
        return
    logical_key = _optional_logical_key(arguments)
    if arguments.command == "query":
        events, marker = client.query_events(topic, scope, logical_key)
        _print_json({"events": events, "scannedThrough": str(marker), "hasMore": False})
        return
    if arguments.command == "wait":
        event = wait_for_exact_event(
            client,
            arguments.event_id,
            topic,
            scope,
            logical_key,
            arguments.wait_seconds,
            arguments.poll_seconds,
        )
        _print_json(event)
        return
    raise OperatorError("unsupported command")


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = build_parser()
    arguments = parser.parse_args(argv)
    try:
        run(arguments)
    except OperatorError as error:
        print("aster-lan-mvp: %s" % error, file=sys.stderr)
        return 2
    except KeyboardInterrupt:
        print("aster-lan-mvp: interrupted", file=sys.stderr)
        return 130
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
