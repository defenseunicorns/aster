#!/usr/bin/env python3
# Copyright 2026 Defense Unicorns, Inc.
# SPDX-License-Identifier: Apache-2.0
"""Run the bounded single-host Docker Compose smoke for the LAN MVP.

This is a developer acceptance path, not physical-LAN evidence.  It creates a
fresh project-scoped bridge and four private state volumes, proves the staged
A-to-B-to-C Event path plus outsider rejection and restart persistence, then
removes only those project-scoped containers, network, and volumes.
"""

from __future__ import annotations

import argparse
import base64
import json
import os
from pathlib import Path
import re
import secrets
import signal
import shutil
import subprocess
import sys
import tempfile
import time
from typing import Mapping, Sequence


ROOT = Path(__file__).resolve().parents[1]
COMPOSE_FILE = ROOT / "docker" / "lan-mvp" / "compose.yaml"
HELPER = "/usr/local/libexec/aster/aster_lan_mvp.py"
API_URL = "http://127.0.0.1:8181"
TOKEN_FILE = "/state/client.token"
LOGICAL_KEY = "message/1"
PAYLOAD = "hello from isolated A"
MAX_RETAINED_OUTPUT = 2 * 1024 * 1024
PROJECT_RE = re.compile(r"aster-lan-mvp-[0-9]+-[0-9a-f]{8}\Z")
SERVICES = ("a", "b", "c", "d")


class SmokeError(RuntimeError):
    """Expected, sanitized Compose-smoke failure."""


def project_name(pid: int | None = None, suffix: str | None = None) -> str:
    """Return one non-user-controlled, project-scoped Compose name."""

    value = f"aster-lan-mvp-{pid or os.getpid()}-{suffix or secrets.token_hex(4)}"
    if PROJECT_RE.fullmatch(value) is None:
        raise SmokeError("failed to construct a bounded Compose project name")
    return value


def discovery_environment(enabled: Sequence[str]) -> dict[str, str]:
    """Return a complete Compose interpolation environment for one phase."""

    selected = set(enabled)
    if not selected.issubset(SERVICES):
        raise SmokeError("unknown node in discovery phase")
    environment = dict(os.environ)
    for service in SERVICES:
        environment[f"ASTER_{service.upper()}_DISCOVER_LAN"] = (
            "1" if service in selected else "0"
        )
    return environment


def _read_retained(stream) -> str:
    size = stream.tell()
    if size > MAX_RETAINED_OUTPUT:
        stream.seek(size - MAX_RETAINED_OUTPUT)
        prefix = "[earlier command output omitted]\n"
    else:
        stream.seek(0)
        prefix = ""
    return prefix + stream.read(MAX_RETAINED_OUTPUT).decode("utf-8", errors="replace")


class Compose:
    """Bounded subprocess wrapper for one exact Compose project."""

    def __init__(self, docker: str, project: str):
        candidate = Path(docker)
        if not candidate.is_absolute() or candidate.name != "docker":
            raise SmokeError("Docker executable must be an absolute path named docker")
        if PROJECT_RE.fullmatch(project) is None:
            raise SmokeError("invalid Compose project name")
        self.image = f"{project}:local"
        self.prefix = (
            str(candidate),
            "compose",
            "--file",
            str(COMPOSE_FILE),
            "--project-name",
            project,
        )

    def run(
        self,
        arguments: Sequence[str],
        *,
        timeout: float,
        environment: Mapping[str, str] | None = None,
    ) -> str:
        command = [*self.prefix, *arguments]
        run_environment = (
            dict(environment) if environment is not None else dict(os.environ)
        )
        run_environment["ASTER_LAN_MVP_IMAGE"] = self.image
        with tempfile.TemporaryFile() as stdout, tempfile.TemporaryFile() as stderr:
            try:
                completed = subprocess.run(
                    command,
                    cwd=ROOT,
                    env=run_environment,
                    stdin=subprocess.DEVNULL,
                    stdout=stdout,
                    stderr=stderr,
                    timeout=timeout,
                    check=False,
                )
            except subprocess.TimeoutExpired as error:
                raise SmokeError(
                    f"Compose command timed out after {timeout:.0f} seconds: {arguments[0]}"
                ) from error
            out = _read_retained(stdout)
            err = _read_retained(stderr)
        if completed.returncode != 0:
            detail = (err or out).strip()
            if len(detail) > 2_000:
                detail = detail[-2_000:]
            raise SmokeError(
                f"Compose command failed ({arguments[0]}, exit {completed.returncode}): "
                f"{detail or 'no diagnostic'}"
            )
        return out

    def helper(
        self,
        service: str,
        arguments: Sequence[str],
        *,
        timeout: float = 15,
    ) -> str:
        if service not in SERVICES:
            raise SmokeError("unknown helper service")
        return self.run(
            (
                "exec",
                "-T",
                service,
                "python3",
                HELPER,
                *arguments,
                "--token-file",
                TOKEN_FILE,
                "--url",
                API_URL,
            ),
            timeout=timeout,
        )

    def logs(self, services: Sequence[str]) -> str:
        if not services or not set(services).issubset(SERVICES):
            raise SmokeError("invalid service log selection")
        return self.run(
            ("logs", "--no-color", "--tail", "500", *services),
            timeout=20,
        )


def _progress(message: str) -> None:
    print(f"aster-lan-mvp-compose: {message}", file=sys.stderr, flush=True)


def _json_object(raw: str, label: str) -> dict[str, object]:
    try:
        value = json.loads(raw)
    except (json.JSONDecodeError, UnicodeError) as error:
        raise SmokeError(f"{label} returned malformed JSON") from error
    if not isinstance(value, dict):
        raise SmokeError(f"{label} returned a non-object JSON value")
    return value


def validate_event(raw: str, expected_id: str, label: str) -> dict[str, object]:
    """Validate the exact Event identity, logical key, and payload."""

    event = _json_object(raw, label)
    expected_key = base64.b64encode(LOGICAL_KEY.encode("utf-8")).decode("ascii")
    expected_payload = base64.b64encode(PAYLOAD.encode("utf-8")).decode("ascii")
    if event.get("id") != expected_id:
        raise SmokeError(f"{label} returned a different Event ID")
    if event.get("logicalKey") != expected_key:
        raise SmokeError(f"{label} returned a different logical key")
    if event.get("payload") != expected_payload:
        raise SmokeError(f"{label} returned a different payload")
    return event


def validate_empty_query(raw: str, label: str) -> None:
    """Require a complete negative Event query."""

    document = _json_object(raw, label)
    if document.get("events") != [] or document.get("hasMore") is not False:
        raise SmokeError(f"{label} unexpectedly returned an Event")


def receipt_fields(logs: str, receipt: str) -> list[dict[str, str]]:
    """Parse bounded key/value receipts from plain or Compose-prefixed logs."""

    records: list[dict[str, str]] = []
    marker = re.compile(rf"(?:^|[|\s]){re.escape(receipt)}\s+(.*)$")
    for line in logs.splitlines():
        match = marker.search(line)
        if match is None:
            continue
        fields: dict[str, str] = {}
        for item in match.group(1).split():
            key, separator, value = item.partition("=")
            if separator and key and key not in fields:
                fields[key] = value
        records.append(fields)
    return records


def ready_identity(logs: str, label: str) -> tuple[str, str]:
    """Return the latest selected carrier and mission authority receipt."""

    ready = [
        fields
        for fields in receipt_fields(logs, "READY")
        if fields.get("selected") == "true"
    ]
    if not ready:
        raise SmokeError(f"{label} did not emit a selected READY receipt")
    carrier = ready[-1].get("carrier_id", "")
    authority = ready[-1].get("mission_authority", "")
    if not carrier or not authority:
        raise SmokeError(f"{label} READY receipt omitted identity fields")
    return carrier, authority


def validate_authority_partition(
    identities: Mapping[str, tuple[str, str]],
) -> None:
    """Require A/B to share one authority and outsider D to be disjoint."""

    if set(identities) != {"a", "b", "d"}:
        raise SmokeError("authority partition omitted a required node")
    carriers = {identity[0] for identity in identities.values()}
    if len(carriers) != len(identities):
        raise SmokeError("Compose nodes did not have distinct carrier identities")
    if identities["a"][1] != identities["b"][1]:
        raise SmokeError("A and B did not share one mission authority")
    if identities["d"][1] == identities["a"][1]:
        raise SmokeError("outsider D unexpectedly shared the A/B mission authority")


def outsider_contact_rejected(
    logs: Mapping[str, str], identities: Mapping[str, tuple[str, str]]
) -> bool:
    """Reject any D-correlated pass and report a D-correlated mission failure."""

    expected_peers = {
        "a": {identities["d"][0]},
        "b": {identities["d"][0]},
        "d": {identities["a"][0], identities["b"][0]},
    }
    rejection_seen = False
    for local, peers in expected_peers.items():
        for contact in receipt_fields(logs[local], "CONTACT"):
            if contact.get("carrier_peer") not in peers:
                continue
            if contact.get("status") == "pass":
                raise SmokeError("outsider D completed an authenticated contact")
            if contact.get("status") == "error" and contact.get("error", "").startswith(
                "mission%20authentication"
            ):
                rejection_seen = True
    return rejection_seen


def wait_for_outsider_rejection(
    compose: Compose,
    identities: Mapping[str, tuple[str, str]],
    *,
    seconds: float = 45,
) -> None:
    """Wait for a carrier-correlated mission-authentication rejection."""

    deadline = time.monotonic() + seconds
    while True:
        logs = {service: compose.logs((service,)) for service in ("a", "b", "d")}
        if outsider_contact_rejected(logs, identities):
            return
        if time.monotonic() >= deadline:
            raise SmokeError(
                "outsider D did not produce a carrier-correlated mission rejection"
            )
        time.sleep(0.75)


def wait_ready(compose: Compose, service: str, seconds: float = 45) -> None:
    deadline = time.monotonic() + seconds
    while True:
        try:
            compose.helper(service, ("status",), timeout=5)
            return
        except SmokeError:
            if time.monotonic() >= deadline:
                raise SmokeError(f"node {service.upper()} did not become ready") from None
            time.sleep(0.5)


def wait_for_peer_evidence(
    compose: Compose,
    left: str,
    right: str,
    left_carrier: str,
    right_carrier: str,
    *,
    seconds: float = 45,
) -> None:
    """Require pair-correlated discovery and authenticated contact receipts."""

    deadline = time.monotonic() + seconds
    while True:
        pair = (
            (compose.logs((left,)), right_carrier),
            (compose.logs((right,)), left_carrier),
        )
        candidate = any(
            receipt.get("status") == "candidate"
            and receipt.get("carrier_peer") == remote
            for logs, remote in pair
            for receipt in receipt_fields(logs, "DISCOVERY")
        )
        contact = any(
            receipt.get("status") == "pass"
            and receipt.get("carrier_peer") == remote
            for logs, remote in pair
            for receipt in receipt_fields(logs, "CONTACT")
        )
        if candidate and contact:
            return
        if time.monotonic() >= deadline:
            raise SmokeError(
                f"nodes {left.upper()} and {right.upper()} did not emit correlated "
                "discovery/contact evidence before the deadline"
            )
        time.sleep(0.75)


def up(compose: Compose, services: Sequence[str], discovery: Sequence[str]) -> None:
    compose.run(
        ("up", "--detach", "--no-build", "--force-recreate", *services),
        timeout=90,
        environment=discovery_environment(discovery),
    )
    for service in services:
        wait_ready(compose, service)


def stop(compose: Compose, services: Sequence[str]) -> None:
    compose.run(("stop", "--timeout", "15", *services), timeout=60)
    for service in services:
        stops = receipt_fields(compose.logs((service,)), "STOP")
        if not any(receipt.get("lifecycle") == "complete" for receipt in stops):
            raise SmokeError(f"node {service.upper()} did not emit a clean STOP receipt")
    validate_stopped_services(
        compose.run(
            ("ps", "--all", "--format", "json", *services),
            timeout=15,
        ),
        services,
    )


def validate_stopped_services(raw: str, services: Sequence[str]) -> None:
    """Require each selected container to be exited successfully."""

    try:
        document = json.loads(raw)
        records = document if isinstance(document, list) else [document]
    except (json.JSONDecodeError, UnicodeError):
        try:
            records = [json.loads(line) for line in raw.splitlines() if line.strip()]
        except (json.JSONDecodeError, UnicodeError) as error:
            raise SmokeError("Compose ps returned malformed JSON") from error
    if not all(isinstance(record, dict) for record in records):
        raise SmokeError("Compose ps returned an invalid service list")
    expected = set(services)
    actual = {str(record.get("Service", "")) for record in records}
    if actual != expected or len(records) != len(expected):
        raise SmokeError("Compose ps omitted or duplicated a stopped node")
    for record in records:
        service = str(record["Service"])
        if record.get("State") != "exited" or record.get("ExitCode") not in (0, "0"):
            raise SmokeError(
                f"node {service.upper()} did not exit cleanly after its STOP receipt"
            )


def helper_wait(compose: Compose, service: str, event_id: str, seconds: int) -> str:
    return compose.helper(
        service,
        (
            "wait",
            "--event-id",
            event_id,
            "--logical-key",
            LOGICAL_KEY,
            "--wait-seconds",
            str(seconds),
        ),
        timeout=seconds + 10,
    )


def run_smoke(compose: Compose) -> dict[str, object]:
    """Execute the complete staged Compose acceptance flow."""

    compose.run(("config", "--quiet"), timeout=15)
    compose.run(("version",), timeout=15)
    _progress("building the discovery-enabled image (cached after the first run)")
    compose.run(("build", "init"), timeout=1_800)

    _progress("provisioning four fresh state volumes under two authorities")
    compose.run(("run", "--rm", "--no-deps", "init"), timeout=90)

    _progress("creating durable subscriptions with discovery disabled")
    up(compose, SERVICES, ())
    for service in SERVICES:
        compose.helper(
            service,
            ("subscribe", "--operation-key", f"demo/consume/{service.upper()}"),
        )
    stop(compose, SERVICES)

    _progress("publishing one Event at isolated A")
    up(compose, ("a",), ())
    compose.helper("a", ("publication-init", "--journal", "/state/publication.redb", "--client-id", "lan-mvp-source-a"))
    event_id = compose.helper(
        "a",
        (
            "publish",
            "--journal", "/state/publication.redb",
            "--client-id", "lan-mvp-source-a",
            "--logical-key",
            LOGICAL_KEY,
            "--payload",
            PAYLOAD,
            "--id-only",
        ),
    ).strip()
    if len(event_id) != 44:
        raise SmokeError("A returned a malformed canonical Event ID")
    stop(compose, ("a",))

    _progress("starting A, B, and outsider D with rosterless LAN discovery")
    up(compose, ("a", "b", "d"), ("a", "b", "d"))
    identities = {
        service: ready_identity(compose.logs((service,)), service.upper())
        for service in ("a", "b", "d")
    }
    validate_authority_partition(identities)
    validate_event(helper_wait(compose, "b", event_id, 75), event_id, "B wait")
    wait_for_peer_evidence(
        compose,
        "a",
        "b",
        identities["a"][0],
        identities["b"][0],
    )
    wait_for_outsider_rejection(compose, identities)
    validate_empty_query(
        compose.helper("d", ("query", "--logical-key", LOGICAL_KEY)),
        "D query",
    )
    stop(compose, ("a", "d"))
    outsider_contact_rejected(
        {service: compose.logs((service,)) for service in ("a", "b", "d")},
        identities,
    )

    _progress("keeping B online while C discovers it and fetches A's Event")
    up(compose, ("c",), ("b", "c"))
    c_carrier, c_authority = ready_identity(compose.logs(("c",)), "C")
    if c_authority != identities["b"][1]:
        raise SmokeError("C did not share the A/B mission authority")
    if c_carrier in {identity[0] for identity in identities.values()}:
        raise SmokeError("C did not have a distinct carrier identity")
    validate_event(helper_wait(compose, "c", event_id, 75), event_id, "C wait")
    wait_for_peer_evidence(
        compose,
        "b",
        "c",
        identities["b"][0],
        c_carrier,
    )
    stop(compose, ("b", "c"))

    _progress("restarting C with discovery disabled and reopening durable state")
    up(compose, ("c",), ())
    validate_event(helper_wait(compose, "c", event_id, 5), event_id, "C restart")
    logs = compose.logs(("c",))
    ready_lines = [line for line in logs.splitlines() if "READY selected=true" in line]
    if not ready_lines or "nearby_discovery=disabled" not in ready_lines[-1]:
        raise SmokeError("C restart did not prove discovery was disabled")
    stop(compose, ("c",))

    return {
        "schema": "aster-lan-mvp-compose-smoke/v1",
        "status": "pass",
        "eventId": event_id,
        "checks": [
            "rosterless-mdns-candidate",
            "mission-authenticated-a-to-b",
            "foreign-authority-rejected-with-empty-query",
            "offline-a-to-b-to-c-store-and-forward",
            "c-peerless-restart-persistence",
        ],
        "boundary": (
            "single-host Docker bridge; same implementation; Event only; "
            "not retained physical-LAN, hostile-LAN, NAT/WAN, or production evidence"
        ),
    }


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Run the bounded Docker Compose smoke for the Aster LAN MVP"
    )
    parser.add_argument(
        "--config-only",
        action="store_true",
        help="validate Compose interpolation without contacting the Docker daemon",
    )
    return parser


def _interrupt(_signum: int, _frame: object) -> None:
    """Route termination through the cleanup path."""

    raise KeyboardInterrupt


def main(argv: Sequence[str] | None = None) -> int:
    arguments = build_parser().parse_args(argv)
    signal.signal(signal.SIGINT, _interrupt)
    signal.signal(signal.SIGTERM, _interrupt)
    docker = shutil.which("docker")
    if docker is None:
        print("aster-lan-mvp-compose: docker was not found", file=sys.stderr)
        return 2
    compose = Compose(str(Path(docker).resolve()), project_name())
    cleanup_needed = False
    exit_code = 0
    result: dict[str, object] | None = None
    try:
        compose.run(("config", "--quiet"), timeout=15)
        compose.run(("version",), timeout=15)
        if arguments.config_only:
            print(
                json.dumps(
                    {
                        "schema": "aster-lan-mvp-compose-config/v1",
                        "status": "pass",
                        "composeFile": str(COMPOSE_FILE.relative_to(ROOT)),
                    },
                    sort_keys=True,
                )
            )
            return 0
        try:
            compose.run(("ps",), timeout=15)
        except SmokeError as error:
            raise SmokeError(
                "Docker daemon access is required; ensure the current user can access "
                "the configured Docker socket"
            ) from error
        cleanup_needed = True
        result = run_smoke(compose)
    except SmokeError as error:
        print(f"aster-lan-mvp-compose: {error}", file=sys.stderr)
        exit_code = 2
    except KeyboardInterrupt:
        print("aster-lan-mvp-compose: interrupted", file=sys.stderr)
        exit_code = 130
    finally:
        if cleanup_needed:
            try:
                compose.run(
                    (
                        "down",
                        "--volumes",
                        "--remove-orphans",
                        "--rmi",
                        "all",
                        "--timeout",
                        "15",
                    ),
                    timeout=90,
                    environment=discovery_environment(()),
                )
            except SmokeError as error:
                print(f"aster-lan-mvp-compose: cleanup warning: {error}", file=sys.stderr)
                exit_code = 2
    if result is not None and exit_code == 0:
        print(json.dumps(result, indent=2, sort_keys=True))
    return exit_code


if __name__ == "__main__":
    raise SystemExit(main())
