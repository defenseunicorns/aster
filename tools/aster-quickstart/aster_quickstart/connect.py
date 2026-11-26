"""Bounded local Aster application and numbered-publication clients."""

from __future__ import annotations

import base64
from dataclasses import dataclass
import http.client
import ipaddress
import io
import json
import math
import os
from pathlib import Path
import re
import subprocess
import threading
import time
from typing import Callable, Mapping, Sequence
from urllib.parse import urlparse

from .linux_process import OwnedProcessGroup, ProcessIdentity, ProcessSafetyError
from .transcript import TranscriptJournal


TOPIC = "mesh.messages"
SCOPE = "demo/playground"
SERVICE = "aster.application.v1alpha1.AsterApplicationService"
MAX_RPC_RESPONSE_BYTES = 2 * 1024 * 1024
QUERY_PAGE_LIMIT = 128
MAX_QUERY_PAGES = 9
MAX_EVENT_BYTES = 4_096


class ConnectError(RuntimeError):
    """A sanitized failure at a local Aster application boundary."""


class _PublicationCancelled(RuntimeError):
    pass


def _remaining_time(deadline: float) -> float:
    remaining = deadline - time.monotonic()
    if remaining <= 0:
        raise TimeoutError("local application request deadline expired")
    return remaining


class _DeadlineRaw(io.RawIOBase):
    """Socket reads whose timeout always reflects one absolute deadline."""

    def __init__(self, sock: object, deadline: float) -> None:
        super().__init__()
        self._sock = sock
        self._deadline = deadline

    def readable(self) -> bool:
        return True

    def readinto(self, buffer: object) -> int:
        self._sock.settimeout(_remaining_time(self._deadline))
        return self._sock.recv_into(buffer)

    def fileno(self) -> int:
        return self._sock.fileno()

    def close(self) -> None:
        if not self.closed:
            self._sock.close()
        super().close()


class _DeadlineSocket:
    """Only replace ``makefile``; all other socket operations stay native."""

    def __init__(self, sock: object, deadline: float) -> None:
        self._sock = sock
        self._deadline = deadline

    def makefile(self, mode: str, buffering: int | None = None) -> io.BufferedReader:
        if mode != "rb":
            raise ValueError("deadline socket only supports binary reads")
        size = io.DEFAULT_BUFFER_SIZE if buffering is None or buffering < 0 else buffering
        return io.BufferedReader(
            _DeadlineRaw(self._sock.dup(), self._deadline),
            buffer_size=size,
        )

    def __getattr__(self, name: str) -> object:
        return getattr(self._sock, name)


def _group_has_live_members(pgid: int) -> bool:
    try:
        entries = Path("/proc").iterdir()
    except OSError:
        return True
    for entry in entries:
        if not entry.name.isdigit():
            continue
        try:
            text = (entry / "stat").read_text()
            fields = text[text.rfind(")") + 2 :].split()
            state = fields[0]
            process_group = int(fields[2])
        except (OSError, ValueError, IndexError):
            continue
        if process_group == pgid and state != "Z":
            return True
    return False


def _stop_process_group(
    process: subprocess.Popen[bytes], ownership: OwnedProcessGroup
) -> None:
    try:
        ownership.stop(process, 1.2)
    except ProcessSafetyError as error:
        raise ConnectError(str(error)) from error


def _loopback_endpoint(url: str) -> tuple[str, int, str]:
    parsed = urlparse(url)
    try:
        host = parsed.hostname
        loopback = host is not None and ipaddress.ip_address(host).is_loopback
        port = parsed.port
    except ValueError as error:
        raise ConnectError("agent returned a malformed application URL") from error
    if (
        parsed.scheme != "http"
        or not loopback
        or port is None
        or parsed.username is not None
        or parsed.password is not None
        or parsed.query
        or parsed.fragment
    ):
        raise ConnectError("agent returned a non-loopback application URL")
    return host, port, parsed.path.rstrip("/")


def _decode_base64(value: object, label: str, *, length: int | None = None) -> bytes:
    if not isinstance(value, str):
        raise ConnectError(f"{label} is malformed")
    try:
        decoded = base64.b64decode(value, validate=True)
    except (ValueError, TypeError) as error:
        raise ConnectError(f"{label} is malformed") from error
    if length is not None and len(decoded) != length:
        raise ConnectError(f"{label} is malformed")
    return decoded


class ConnectJsonClient:
    """Small stdlib Connect JSON client restricted to an IP-literal loopback URL."""

    def __init__(self, base_url: str, token: str, timeout: float = 3.0) -> None:
        self.host, self.port, self.base_path = _loopback_endpoint(base_url)
        if not isinstance(token, str) or not token:
            raise ConnectError("agent application token is unavailable")
        if not isinstance(timeout, (int, float)) or not math.isfinite(timeout) or timeout <= 0:
            raise ConnectError("local application timeout must be positive and finite")
        self.token = token
        self.timeout = float(timeout)

    def call(
        self,
        method: str,
        payload: Mapping[str, object],
        *,
        deadline: float | None = None,
    ) -> dict[str, object]:
        if re.fullmatch(r"[A-Za-z][A-Za-z0-9]*", method) is None:
            raise ConnectError("invalid local application method")
        body = json.dumps(payload, ensure_ascii=True, separators=(",", ":")).encode("utf-8")
        path = f"{self.base_path}/{SERVICE}/{method}"
        request_deadline = time.monotonic() + self.timeout
        if deadline is not None:
            request_deadline = min(request_deadline, deadline)
        try:
            request_timeout = _remaining_time(request_deadline)
        except TimeoutError as error:
            raise ConnectError("local application request deadline expired") from error
        connection = http.client.HTTPConnection(self.host, self.port, timeout=request_timeout)
        try:
            connection.connect()
            if connection.sock is None:
                raise OSError("local application connection has no socket")
            connection.sock.settimeout(_remaining_time(request_deadline))
            connection.request(
                "POST",
                path,
                body=body,
                headers={
                    "Authorization": "Bearer " + self.token,
                    "Content-Type": "application/json",
                },
            )
            if connection.sock is None:
                raise OSError("local application connection closed before its response")
            connection.sock = _DeadlineSocket(connection.sock, request_deadline)
            response = connection.getresponse()
            status = response.status
            chunks = []
            remaining_bytes = MAX_RPC_RESPONSE_BYTES + 1
            while remaining_bytes:
                _remaining_time(request_deadline)
                chunk = response.read1(min(64 * 1024, remaining_bytes))
                if not chunk:
                    break
                chunks.append(chunk)
                remaining_bytes -= len(chunk)
            data = b"".join(chunks)
        except (OSError, TimeoutError, http.client.HTTPException) as error:
            raise ConnectError(f"local application request {method} is unavailable") from error
        finally:
            connection.close()
        if len(data) > MAX_RPC_RESPONSE_BYTES:
            raise ConnectError("local application response exceeds the quickstart bound")
        if not 200 <= status < 300:
            raise ConnectError(f"local application request {method} failed with HTTP {status}")
        try:
            decoded = json.loads(data.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as error:
            raise ConnectError("local application response is malformed") from error
        if not isinstance(decoded, dict):
            raise ConnectError("local application response is not an object")
        return decoded

    def query_events(
        self,
        after_marker: int = 0,
        *,
        deadline: float | None = None,
    ) -> tuple[list[dict[str, object]], int]:
        if type(after_marker) is not int or after_marker < 0:
            raise ConnectError("QueryEvents scan marker is invalid")
        if deadline is None:
            deadline = time.monotonic() + self.timeout
        events: list[dict[str, object]] = []
        marker = after_marker
        for _ in range(MAX_QUERY_PAGES):
            previous = marker
            response = self.call(
                "QueryEvents",
                {
                    "topic": TOPIC,
                    "scope": SCOPE,
                    "includeDescendantScopes": False,
                    "afterAcceptanceMarker": str(marker),
                    "limit": QUERY_PAGE_LIMIT,
                },
                deadline=deadline,
            )
            page = response.get("events", [])
            if not isinstance(page, list) or any(not isinstance(item, dict) for item in page):
                raise ConnectError("QueryEvents returned a malformed Event page")
            try:
                scanned = int(response.get("scannedThrough", marker))
            except (TypeError, ValueError) as error:
                raise ConnectError("QueryEvents returned a malformed scan marker") from error
            if scanned < marker:
                raise ConnectError("QueryEvents scan marker moved backward")
            events.extend(page)
            marker = scanned
            if response.get("hasMore", False) is not True:
                return events, marker
            if not page and marker == previous:
                raise ConnectError("QueryEvents pagination made no progress")
        raise ConnectError("QueryEvents exceeded the quickstart page bound")

    def query_exact_event(
        self,
        event_id: bytes,
        payload: bytes,
        after_marker: int = 0,
        *,
        deadline: float | None = None,
    ) -> tuple[dict[str, object] | None, int]:
        if not isinstance(event_id, bytes) or len(event_id) != 32:
            raise ConnectError("expected Event ID is malformed")
        if not isinstance(payload, bytes) or not payload or len(payload) > MAX_EVENT_BYTES:
            raise ConnectError("expected Event payload is malformed")
        events, marker = self.query_events(after_marker, deadline=deadline)
        for event in events:
            if event.get("topic") != TOPIC or event.get("scope") != SCOPE:
                raise ConnectError("QueryEvents crossed the quickstart selector")
            observed_id = _decode_base64(event.get("id"), "observed Event ID", length=32)
            observed_payload = _decode_base64(event.get("payload"), "observed Event payload")
            if observed_id == event_id:
                if observed_payload != payload:
                    raise ConnectError("the expected Event identity resolved to a different payload")
                return event, marker
        return None, marker


@dataclass(frozen=True)
class Publication:
    event_id: bytes
    inserted: bool
    sequence: str


class NumberedPublisher:
    """Direct wrapper for the durable numbered ``asterctl`` publication surface."""

    def __init__(
        self,
        ctl: Path,
        journal: Path,
        client_id: str,
        timeout: float = 3.0,
        cancel_event: threading.Event | None = None,
        before_spawn: Callable[[str], None] | None = None,
        after_spawn: Callable[[str, ProcessIdentity], None] | None = None,
        after_gone: Callable[[str], None] | None = None,
        transcript: TranscriptJournal | None = None,
        transcript_step: str = "event",
    ) -> None:
        self.ctl = ctl
        self.journal = journal
        self.client_id = client_id
        self.timeout = float(timeout)
        self.cancel_event = cancel_event
        self.before_spawn = before_spawn
        self.after_spawn = after_spawn
        self.after_gone = after_gone
        self.transcript = transcript
        self.transcript_step = transcript_step
        self.host: str | None = None
        self.port: int | None = None
        self.token_path: Path | None = None

    def initialize(self) -> None:
        self._run("publication-init", local=True, transcript_step="setup")

    def connect(self, url: str, token_path: Path) -> None:
        self.host, self.port, _ = _loopback_endpoint(url)
        self.token_path = token_path

    def create_subscription(self, operation_key: bytes, *, transcript_step: str | None = None) -> bytes:
        try:
            key = operation_key.decode("ascii")
        except (AttributeError, UnicodeDecodeError) as error:
            raise ConnectError("subscription operation key is malformed") from error
        response = self._run(
            "subscribe",
            ["--operation-key", key, "--scope", SCOPE, TOPIC],
            json_response=True,
            transcript_step=transcript_step,
        )
        return _decode_base64(response.get("subscriptionId"), "subscription ID", length=32)

    def publish(
        self,
        logical_key: bytes,
        payload: bytes,
        *,
        transcript_step: str | None = None,
    ) -> Publication:
        try:
            key = logical_key.decode("ascii")
        except (AttributeError, UnicodeDecodeError) as error:
            raise ConnectError("publication logical key is malformed") from error
        if not payload or len(payload) > MAX_EVENT_BYTES:
            raise ConnectError("publication payload violates the 4096-byte bound")
        response = self._run(
            "publish",
            ["--topic", TOPIC, "--scope", SCOPE, "--logical-key", key],
            payload=payload,
            json_response=True,
            transcript_step=transcript_step,
        )
        result = response.get("result")
        inserted = response.get("inserted")
        if not isinstance(result, dict) or not isinstance(inserted, bool):
            raise ConnectError("numbered publisher returned a malformed outcome")
        receipt = result.get("receipt")
        if not isinstance(receipt, dict):
            raise ConnectError("numbered publication omitted its receipt")
        event_id = _decode_base64(receipt.get("eventId"), "published Event ID", length=32)
        sequence = result.get("operationSequence")
        if not isinstance(sequence, str) or not sequence.isdigit() or int(sequence) < 1:
            raise ConnectError("numbered publisher returned an invalid sequence")
        return Publication(event_id, inserted, sequence)

    def acknowledge(self, publication: Publication, *, transcript_step: str | None = None) -> None:
        self._run("publication-ack", ["--sequence", publication.sequence], transcript_step=transcript_step)

    def _run(
        self,
        action: str,
        options: Sequence[str] = (),
        *,
        payload: bytes | None = None,
        local: bool = False,
        json_response: bool = False,
        transcript_step: str | None = None,
    ) -> dict[str, object]:
        command = [str(self.ctl)]
        if not local:
            if self.host is None or self.port is None or self.token_path is None:
                raise ConnectError("numbered publisher is not connected")
            command.extend(
                [
                    "--token-file",
                    str(self.token_path),
                    "--host",
                    self.host,
                    "--port",
                    str(self.port),
                    "--timeout",
                    str(max(1, math.ceil(self.timeout))),
                    "--json",
                ]
            )
        command.extend([action, "--journal", str(self.journal), "--client-id", self.client_id])
        command.extend(options)
        label = f"asterctl-{action}"
        if self.before_spawn is not None:
            self.before_spawn(label)
        handle = (
            self.transcript.start_command(
                transcript_step or self.transcript_step,
                command,
                cwd=os.getcwd(),
                stdin=payload,
            )
            if self.transcript is not None
            else None
        )
        try:
            process = subprocess.Popen(
                command,
                stdin=subprocess.PIPE if payload is not None else subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                start_new_session=True,
                bufsize=0,
            )
        except OSError as error:
            if handle is not None:
                handle.finish(None, outcome="spawn failed")
            if self.after_gone is not None:
                self.after_gone(label)
            raise ConnectError("numbered publication command was unavailable") from error
        try:
            ownership = OwnedProcessGroup.capture(process.pid)
        except BaseException as error:
            try:
                process.kill()
                process.wait(timeout=1.0)
            finally:
                for stream in (process.stdout, process.stderr):
                    if stream is not None:
                        stream.close()
            if handle is not None:
                handle.finish(process.returncode, outcome="identity failed")
            raise ConnectError("numbered publication command identity is uncertain") from error
        try:
            if self.after_spawn is not None:
                self.after_spawn(label, ownership.identity)
        except BaseException:
            try:
                _stop_process_group(process, ownership)
            finally:
                if handle is not None:
                    handle.finish(process.returncode, outcome="spawn rejected")
                if self.after_gone is not None:
                    self.after_gone(label)
            raise
        assert process.stdout is not None and process.stderr is not None
        buffers = {"stdout": bytearray(), "stderr": bytearray()}
        overflow = {"stdout": False, "stderr": False}

        def collect(name: str, stream: object) -> None:
            try:
                while True:
                    chunk = stream.read(4096)
                    if not chunk:
                        return
                    remaining = max(0, MAX_RPC_RESPONSE_BYTES - len(buffers[name]))
                    if remaining:
                        retained = chunk[:remaining]
                        buffers[name].extend(retained)
                        if handle is not None:
                            handle.update(**{name: retained})
                    if len(chunk) > remaining:
                        overflow[name] = True
            finally:
                stream.close()

        threads = [
            threading.Thread(target=collect, args=(name, stream), daemon=True)
            for name, stream in (("stdout", process.stdout), ("stderr", process.stderr))
        ]
        for thread in threads:
            thread.start()
        deadline = time.monotonic() + max(0.1, self.timeout + 0.25)
        try:
            if process.stdin is not None:
                process.stdin.write(payload or b"")
                process.stdin.close()
            while True:
                if self.cancel_event is not None and self.cancel_event.is_set():
                    raise _PublicationCancelled
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise subprocess.TimeoutExpired(command, max(0.1, self.timeout + 0.25))
                try:
                    process.wait(timeout=min(0.03, remaining))
                    break
                except subprocess.TimeoutExpired:
                    continue
        except _PublicationCancelled as error:
            try:
                _stop_process_group(process, ownership)
            finally:
                for thread in threads:
                    thread.join(timeout=1.0)
                if handle is not None:
                    handle.finish(process.returncode, outcome="cancelled")
                if self.after_gone is not None:
                    self.after_gone(label)
            raise ConnectError("Aster session preparation was cancelled") from error
        except (BrokenPipeError, OSError, subprocess.TimeoutExpired) as error:
            try:
                _stop_process_group(process, ownership)
            finally:
                for thread in threads:
                    thread.join(timeout=1.0)
                if handle is not None:
                    handle.finish(
                        process.returncode,
                        outcome="timed out" if isinstance(error, subprocess.TimeoutExpired) else "failed",
                    )
                if self.after_gone is not None:
                    self.after_gone(label)
            raise ConnectError("numbered publication command was unavailable") from error
        for thread in threads:
            thread.join(timeout=0.2)
        if any(thread.is_alive() for thread in threads):
            try:
                _stop_process_group(process, ownership)
            finally:
                for thread in threads:
                    thread.join(timeout=1.0)
                if handle is not None:
                    handle.finish(process.returncode, outcome="output pipe retained")
                if self.after_gone is not None:
                    self.after_gone(label)
            raise ConnectError("numbered publication command retained an output pipe")
        if _group_has_live_members(process.pid):
            try:
                _stop_process_group(process, ownership)
            finally:
                if handle is not None:
                    handle.finish(process.returncode, outcome="process group retained")
                if self.after_gone is not None:
                    self.after_gone(label)
            raise ConnectError("numbered publication command left a live process group")
        ownership.close()
        if process.returncode != 0:
            if handle is not None:
                handle.finish(process.returncode, outcome="failed")
            if self.after_gone is not None:
                self.after_gone(label)
            raise ConnectError("numbered publication command failed")
        if any(overflow.values()):
            if handle is not None:
                handle.finish(process.returncode, outcome="output overflow")
            if self.after_gone is not None:
                self.after_gone(label)
            raise ConnectError("numbered publication output exceeded the quickstart bound")
        if handle is not None:
            handle.finish(process.returncode, outcome="succeeded")
        if self.after_gone is not None:
            self.after_gone(label)
        if not json_response:
            return {}
        try:
            decoded = json.loads(bytes(buffers["stdout"]).decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as error:
            raise ConnectError("numbered publication returned malformed JSON") from error
        if not isinstance(decoded, dict):
            raise ConnectError("numbered publication returned a malformed result")
        return decoded
