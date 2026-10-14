#!/usr/bin/env python3
# Copyright 2026 Defense Unicorns, Inc.
# SPDX-License-Identifier: Apache-2.0
"""Run a bounded, generated Docker Compose LAN scale diagnostic.

The diagnostic is intentionally limited to 8, 16, or 32 authorized Event
nodes plus one differently authorized outsider on one private Docker bridge.
It is same-host development evidence, not physical-LAN, target-resource, or
production evidence.
"""

from __future__ import annotations

import argparse
import base64
from collections import Counter, defaultdict
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from datetime import datetime
import json
import math
import os
from pathlib import Path
import platform
import re
import secrets
import shutil
import signal
import statistics
import subprocess
import sys
import tempfile
import threading
import time
from typing import Callable, Iterable, Mapping, Sequence, TypeVar


ROOT = Path(__file__).resolve().parents[1]
DOCKERFILE = "docker/lan-mvp/Dockerfile"
INIT_HELPER = "/usr/local/libexec/aster/init-scale-state.sh"
AGENT_HELPER = "/usr/local/libexec/aster/agent-entrypoint.sh"
OPERATOR_HELPER = "/usr/local/libexec/aster/aster_lan_mvp.py"
API_URL = "http://127.0.0.1:8181"
TOKEN_FILE = "/state/client.token"
TOPIC = "mesh.messages"
SCOPE = "demo/playground"
ALLOWED_NODE_COUNTS = (8, 16, 32)
OUTSIDER_COUNT = 1
PAYLOAD_BYTES = 1024
MAX_RETAINED_OUTPUT = 4 * 1024 * 1024
PROJECT_RE = re.compile(r"aster-lan-scale-[0-9]+-[0-9a-f]{8}\Z")
SERVICE_RE = re.compile(r"(?:n[0-9]{3}|o[0-9]{3})\Z")
CONTAINER_ID_RE = re.compile(r"[0-9a-f]{12,64}\Z")
EVENT_ID_RE = re.compile(r"[A-Za-z0-9+/]{43}=\Z")
DEFAULT_CONVERGENCE_SECONDS = {8: 120, 16: 180, 32: 300}
DEFAULT_SYNC_MS = {8: 5_000, 16: 10_000, 32: 20_000}


class ScaleError(RuntimeError):
    """Expected, sanitized scale-diagnostic failure."""


@dataclass(frozen=True)
class ExpectedEvent:
    """One exact offline publication expected at every authorized node."""

    event_id: str
    logical_key: str
    payload: str


@dataclass(frozen=True)
class ReadyIdentity:
    """Sanitized fields needed to correlate one running node."""

    carrier: str
    mission: str
    authority: str
    nearby: str


def validate_node_count(value: int) -> int:
    if value not in ALLOWED_NODE_COUNTS:
        choices = ", ".join(str(item) for item in ALLOWED_NODE_COUNTS)
        raise ScaleError(f"authorized node count must be one of: {choices}")
    return value


def authorized_services(nodes: int) -> tuple[str, ...]:
    validate_node_count(nodes)
    return tuple(f"n{index:03d}" for index in range(nodes))


def outsider_services() -> tuple[str, ...]:
    return tuple(f"o{index:03d}" for index in range(OUTSIDER_COUNT))


def all_services(nodes: int) -> tuple[str, ...]:
    return (*authorized_services(nodes), *outsider_services())


def project_name(pid: int | None = None, suffix: str | None = None) -> str:
    value = f"aster-lan-scale-{pid or os.getpid()}-{suffix or secrets.token_hex(4)}"
    if PROJECT_RE.fullmatch(value) is None:
        raise ScaleError("failed to construct a bounded Compose project name")
    return value


def event_logical_key(service: str) -> str:
    if SERVICE_RE.fullmatch(service) is None or not service.startswith("n"):
        raise ScaleError("Event publisher must be an authorized scale service")
    return f"scale/{service}/event/1"


def event_payload(service: str) -> str:
    if SERVICE_RE.fullmatch(service) is None or not service.startswith("n"):
        raise ScaleError("Event publisher must be an authorized scale service")
    prefix = f"aster LAN scale Event from {service}\n"
    prefix_size = len(prefix.encode("utf-8"))
    if prefix_size >= PAYLOAD_BYTES:
        raise ScaleError("scale Event prefix exceeds its payload bound")
    return prefix + (service[-1] * (PAYLOAD_BYTES - prefix_size))


def _node_service(service: str, sync_ms: int) -> dict[str, object]:
    return {
        "image": "${ASTER_LAN_SCALE_IMAGE:-aster-lan-scale:local}",
        "user": "10001:10001",
        "init": True,
        "read_only": True,
        "restart": "no",
        "command": [AGENT_HELPER],
        "environment": {
            "ASTER_STATE_DIR": "/state",
            "ASTER_DISCOVER_LAN": "${ASTER_DISCOVER_LAN:-0}",
            "ASTER_NEARBY_WINDOW": "3",
            "ASTER_SYNC_MS": str(sync_ms),
            "TOKIO_WORKER_THREADS": "1",
            "HOME": "/tmp",
            "PYTHONDONTWRITEBYTECODE": "1",
        },
        "networks": ["mesh"],
        "tmpfs": [
            "/tmp:rw,nosuid,nodev,noexec,size=16m,mode=0700,uid=10001,gid=10001"
        ],
        "cap_drop": ["ALL"],
        "security_opt": ["no-new-privileges:true"],
        "stop_signal": "SIGINT",
        "stop_grace_period": "15s",
        "logging": {
            "driver": "json-file",
            "options": {"max-size": "4m", "max-file": "2"},
        },
        "volumes": [f"{service}-state:/state"],
    }


def compose_model(nodes: int) -> dict[str, object]:
    """Return one deterministic hardened Compose model."""

    authorized = authorized_services(nodes)
    outsiders = outsider_services()
    services = (*authorized, *outsiders)
    sync_ms = DEFAULT_SYNC_MS[nodes]
    volumes = {f"{service}-state": {} for service in services}
    init_volumes = [f"{service}-state:/nodes/{service}" for service in services]
    model_services: dict[str, object] = {
        "init": {
            "image": "${ASTER_LAN_SCALE_IMAGE:-aster-lan-scale:local}",
            "build": {"context": str(ROOT), "dockerfile": DOCKERFILE},
            "profiles": ["setup"],
            "network_mode": "none",
            "user": "0:0",
            "read_only": True,
            "command": [INIT_HELPER],
            "environment": {
                "ASTER_SCALE_NODES": str(nodes),
                "ASTER_SCALE_OUTSIDERS": str(OUTSIDER_COUNT),
            },
            "tmpfs": [
                "/seed:rw,nosuid,nodev,noexec,size=64m,mode=0700",
                "/tmp:rw,nosuid,nodev,noexec,size=8m,mode=0700",
            ],
            "volumes": init_volumes,
            "cap_drop": ["ALL"],
            "cap_add": ["CHOWN"],
            "security_opt": ["no-new-privileges:true"],
        }
    }
    for service in services:
        model_services[service] = _node_service(service, sync_ms)
    return {
        "services": model_services,
        "networks": {
            "mesh": {
                "driver": "bridge",
                "driver_opts": {"com.docker.network.bridge.enable_icc": "true"},
            }
        },
        "volumes": volumes,
    }


def write_compose_model(directory: Path, nodes: int) -> Path:
    path = directory / "compose.json"
    data = (json.dumps(compose_model(nodes), indent=2, sort_keys=True) + "\n").encode(
        "utf-8"
    )
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    flags |= getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags, 0o600)
    except OSError as error:
        raise ScaleError("could not create the private generated Compose model") from error
    complete = False
    try:
        os.fchmod(descriptor, 0o600)
        offset = 0
        while offset < len(data):
            written = os.write(descriptor, data[offset:])
            if written <= 0:
                raise OSError("short Compose-model write")
            offset += written
        os.fsync(descriptor)
        complete = True
    except OSError as error:
        raise ScaleError("could not write the private generated Compose model") from error
    finally:
        os.close(descriptor)
        if not complete:
            try:
                path.unlink()
            except OSError:
                pass
    return path


def _read_retained(stream) -> str:
    size = stream.tell()
    if size > MAX_RETAINED_OUTPUT:
        stream.seek(size - MAX_RETAINED_OUTPUT)
        prefix = "[earlier command output omitted]\n"
    else:
        stream.seek(0)
        prefix = ""
    return prefix + stream.read(MAX_RETAINED_OUTPUT).decode("utf-8", errors="replace")


class Docker:
    """Bounded Docker CLI wrapper with no shell evaluation."""

    def __init__(self, executable: str):
        candidate = Path(executable)
        if not candidate.is_absolute() or candidate.name != "docker":
            raise ScaleError("Docker executable must be an absolute path named docker")
        self.executable = str(candidate)

    def run(
        self,
        arguments: Sequence[str],
        *,
        timeout: float,
        environment: Mapping[str, str] | None = None,
    ) -> str:
        command = [self.executable, *arguments]
        with tempfile.TemporaryFile() as stdout, tempfile.TemporaryFile() as stderr:
            try:
                completed = subprocess.run(
                    command,
                    cwd=ROOT,
                    env=dict(environment) if environment is not None else dict(os.environ),
                    stdin=subprocess.DEVNULL,
                    stdout=stdout,
                    stderr=stderr,
                    timeout=timeout,
                    check=False,
                )
            except subprocess.TimeoutExpired as error:
                raise ScaleError(
                    f"Docker command timed out after {timeout:.0f} seconds: {arguments[0]}"
                ) from error
            out = _read_retained(stdout)
            err = _read_retained(stderr)
        if completed.returncode != 0:
            detail = (err or out).strip()
            if len(detail) > 2_000:
                detail = detail[-2_000:]
            raise ScaleError(
                f"Docker command failed ({arguments[0]}, exit {completed.returncode}): "
                f"{detail or 'no diagnostic'}"
            )
        return out


class Compose:
    """One exact generated Compose project and its bounded service set."""

    def __init__(
        self,
        docker: Docker,
        compose_file: Path,
        project: str,
        services: Sequence[str],
    ):
        if PROJECT_RE.fullmatch(project) is None:
            raise ScaleError("invalid Compose project name")
        if not services or any(SERVICE_RE.fullmatch(item) is None for item in services):
            raise ScaleError("invalid generated scale service set")
        if len(set(services)) != len(services):
            raise ScaleError("duplicate generated scale service")
        self.docker = docker
        self.compose_file = compose_file
        self.project = project
        self.services = tuple(services)
        self.service_set = frozenset(services)
        self.image = f"{project}:local"
        self.prefix = (
            "compose",
            "--file",
            str(compose_file),
            "--project-name",
            project,
        )

    def environment(self, discovery: bool) -> dict[str, str]:
        environment = dict(os.environ)
        environment["ASTER_LAN_SCALE_IMAGE"] = self.image
        environment["ASTER_DISCOVER_LAN"] = "1" if discovery else "0"
        return environment

    def run(
        self,
        arguments: Sequence[str],
        *,
        timeout: float,
        discovery: bool = False,
    ) -> str:
        return self.docker.run(
            (*self.prefix, *arguments),
            timeout=timeout,
            environment=self.environment(discovery),
        )

    def _service(self, service: str) -> str:
        if service not in self.service_set:
            raise ScaleError("unknown generated scale service")
        return service

    def helper(
        self, service: str, arguments: Sequence[str], *, timeout: float = 20
    ) -> str:
        service = self._service(service)
        return self.run(
            (
                "exec",
                "-T",
                service,
                "python3",
                OPERATOR_HELPER,
                *arguments,
                "--token-file",
                TOKEN_FILE,
                "--url",
                API_URL,
            ),
            timeout=timeout,
        )

    def logs(self, service: str) -> str:
        service = self._service(service)
        return self.run(
            ("logs", "--no-color", "--tail", "all", service), timeout=30
        )

    def ps(self, services: Sequence[str], *, all_states: bool) -> list[dict[str, object]]:
        for service in services:
            self._service(service)
        arguments = ["ps"]
        if all_states:
            arguments.append("--all")
        arguments.extend(("--no-trunc", "--format", "json", *services))
        return parse_ps_records(self.run(tuple(arguments), timeout=20))


def _json_object(raw: str, label: str) -> dict[str, object]:
    try:
        value = json.loads(raw)
    except (json.JSONDecodeError, UnicodeError) as error:
        raise ScaleError(f"{label} returned malformed JSON") from error
    if not isinstance(value, dict):
        raise ScaleError(f"{label} returned a non-object JSON value")
    return value


def parse_ps_records(raw: str) -> list[dict[str, object]]:
    """Accept Compose v2 arrays and Compose v5 newline-delimited JSON."""

    try:
        document = json.loads(raw)
        records = document if isinstance(document, list) else [document]
    except (json.JSONDecodeError, UnicodeError):
        try:
            records = [json.loads(line) for line in raw.splitlines() if line.strip()]
        except (json.JSONDecodeError, UnicodeError) as error:
            raise ScaleError("Compose ps returned malformed JSON") from error
    if not records or not all(isinstance(record, dict) for record in records):
        raise ScaleError("Compose ps returned an invalid service list")
    return records


def validate_service_records(
    records: Sequence[Mapping[str, object]],
    services: Sequence[str],
    *,
    expected_state: str,
) -> dict[str, str]:
    expected = set(services)
    actual = {str(record.get("Service", "")) for record in records}
    if actual != expected or len(records) != len(expected):
        raise ScaleError("Compose ps omitted or duplicated a scale node")
    container_ids: dict[str, str] = {}
    for record in records:
        service = str(record["Service"])
        state = str(record.get("State", ""))
        if state != expected_state:
            raise ScaleError(f"node {service} was {state or 'unknown'}, expected {expected_state}")
        if expected_state == "exited" and record.get("ExitCode") not in (0, "0"):
            raise ScaleError(f"node {service} did not exit cleanly")
        container_id = str(record.get("ID", ""))
        if CONTAINER_ID_RE.fullmatch(container_id) is None:
            raise ScaleError(f"node {service} has a malformed container ID")
        container_ids[service] = container_id
    if len(set(container_ids.values())) != len(expected):
        raise ScaleError("scale nodes did not have distinct containers")
    return container_ids


def receipt_fields(logs: str, receipt: str) -> list[dict[str, str]]:
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


def parse_ready_identity(logs: str, service: str) -> ReadyIdentity:
    records = [
        record
        for record in receipt_fields(logs, "READY")
        if record.get("selected") == "true"
    ]
    if not records:
        raise ScaleError(f"node {service} did not emit a selected READY receipt")
    record = records[-1]
    values = (
        record.get("carrier_id", ""),
        record.get("mission_id", ""),
        record.get("mission_authority", ""),
        record.get("nearby_discovery", ""),
    )
    if any(not value for value in values):
        raise ScaleError(f"node {service} READY receipt omitted identity fields")
    return ReadyIdentity(*values)


def validate_identity_cohort(
    identities: Mapping[str, ReadyIdentity],
    authorized: Sequence[str],
    outsiders: Sequence[str],
    *,
    discovery: bool,
) -> None:
    services = (*authorized, *outsiders)
    if set(identities) != set(services):
        raise ScaleError("READY identity cohort omitted a scale node")
    if len({item.carrier for item in identities.values()}) != len(services):
        raise ScaleError("scale nodes did not have distinct carrier identities")
    if len({item.mission for item in identities.values()}) != len(services):
        raise ScaleError("scale nodes did not have distinct mission identities")
    authorized_authorities = {identities[item].authority for item in authorized}
    outsider_authorities = {identities[item].authority for item in outsiders}
    if len(authorized_authorities) != 1:
        raise ScaleError("authorized nodes did not share one mission authority")
    if len(outsider_authorities) != 1 or authorized_authorities & outsider_authorities:
        raise ScaleError("outsider authority was not distinct")
    expected_nearby = "active-evaluation" if discovery else "disabled"
    if any(identities[item].nearby != expected_nearby for item in services):
        raise ScaleError(f"a node did not report nearby discovery {expected_nearby}")


def canonical_event_id(raw: str) -> str:
    if EVENT_ID_RE.fullmatch(raw) is None:
        raise ScaleError("publisher returned a malformed Event ID")
    try:
        decoded = base64.b64decode(raw, validate=True)
    except ValueError as error:
        raise ScaleError("publisher returned a malformed Event ID") from error
    if len(decoded) != 32 or base64.b64encode(decoded).decode("ascii") != raw:
        raise ScaleError("publisher returned a malformed Event ID")
    return raw


def validate_inventory(
    raw: str,
    expected: Mapping[str, ExpectedEvent],
    label: str,
    *,
    require_complete: bool,
) -> bool:
    document = _json_object(raw, label)
    events = document.get("events")
    if not isinstance(events, list) or not all(isinstance(item, dict) for item in events):
        raise ScaleError(f"{label} returned a malformed Event inventory")
    if document.get("hasMore") is not False:
        raise ScaleError(f"{label} returned an incomplete Event inventory")
    observed: set[str] = set()
    for item in events:
        event_id = item.get("id")
        if not isinstance(event_id, str) or event_id not in expected:
            raise ScaleError(f"{label} returned an unexpected Event")
        if event_id in observed:
            raise ScaleError(f"{label} returned a duplicate Event")
        receipt = expected[event_id]
        logical_key = base64.b64encode(receipt.logical_key.encode("utf-8")).decode("ascii")
        payload = base64.b64encode(receipt.payload.encode("utf-8")).decode("ascii")
        if item.get("logicalKey") != logical_key or item.get("payload") != payload:
            raise ScaleError(f"{label} returned changed Event content")
        observed.add(event_id)
    complete = observed == set(expected)
    if require_complete and not complete:
        raise ScaleError(f"{label} did not contain the complete Event inventory")
    return complete


T = TypeVar("T")


def run_parallel(
    services: Sequence[str], operation: Callable[[str], T], label: str
) -> dict[str, T]:
    if not services:
        raise ScaleError(f"{label} received an empty service set")
    results: dict[str, T] = {}
    with ThreadPoolExecutor(max_workers=min(32, len(services))) as executor:
        futures = {executor.submit(operation, service): service for service in services}
        try:
            for future in as_completed(futures):
                service = futures[future]
                results[service] = future.result()
        except Exception as error:
            for future in futures:
                future.cancel()
            if isinstance(error, ScaleError):
                raise
            raise ScaleError(f"{label} worker failed") from error
    if set(results) != set(services):
        raise ScaleError(f"{label} omitted a scale node")
    return results


def query_all(compose: Compose, services: Sequence[str]) -> dict[str, str]:
    return run_parallel(
        services,
        lambda service: compose.helper(service, ("query",), timeout=20),
        "concurrent Event query",
    )


def percentile(values: Sequence[float], quantile: float) -> float:
    if not values:
        raise ScaleError("cannot calculate a percentile of an empty sample")
    ordered = sorted(values)
    index = max(0, math.ceil(quantile * len(ordered)) - 1)
    return ordered[index]


def wait_for_full_convergence(
    compose: Compose,
    authorized: Sequence[str],
    outsiders: Sequence[str],
    expected: Mapping[str, ExpectedEvent],
    started: float,
    seconds: float,
) -> tuple[dict[str, float], int, float]:
    first_completed: dict[str, float] = {}
    transient_query_errors = 0
    deadline = started + seconds
    while True:
        poll_started = time.monotonic()
        if poll_started >= deadline:
            raise ScaleError(
                f"{len(authorized)} authorized nodes did not converge before the deadline"
            )
        services = (*authorized, *outsiders)
        query_timeout = min(20.0, deadline - poll_started)

        def query_for_convergence(service: str) -> str | None:
            try:
                return compose.helper(service, ("query",), timeout=query_timeout)
            except ScaleError:
                return None

        inventories = run_parallel(
            services,
            query_for_convergence,
            "concurrent convergence query",
        )
        now = time.monotonic()
        current_outsiders_exact = True
        for service in outsiders:
            if inventories[service] is None:
                transient_query_errors += 1
                current_outsiders_exact = False
                continue
            validate_inventory(
                inventories[service], {}, f"outsider {service}", require_complete=True
            )
        current_authorized_complete: set[str] = set()
        for service in authorized:
            if inventories[service] is None:
                transient_query_errors += 1
                continue
            complete = validate_inventory(
                inventories[service],
                expected,
                f"node {service}",
                require_complete=False,
            )
            if not complete and service in first_completed:
                raise ScaleError(
                    f"node {service} inventory regressed after exact convergence"
                )
            if complete:
                current_authorized_complete.add(service)
                first_completed.setdefault(service, now - started)
        if any(inventories[service] is None for service in services):
            validate_service_records(
                compose.ps(services, all_states=False),
                services,
                expected_state="running",
            )
        if now >= deadline:
            missing = len(authorized) - len(current_authorized_complete)
            raise ScaleError(
                f"{missing} authorized nodes did not converge before the deadline"
            )
        if (
            current_authorized_complete == set(authorized)
            and current_outsiders_exact
        ):
            return first_completed, transient_query_errors, now - started
        time.sleep(min(0.75, max(0.0, deadline - now)))


_SIZE_UNITS = {
    "B": 1,
    "kB": 1000,
    "MB": 1000**2,
    "GB": 1000**3,
    "TB": 1000**4,
    "KiB": 1024,
    "MiB": 1024**2,
    "GiB": 1024**3,
    "TiB": 1024**4,
}
_SIZE_RE = re.compile(r"([0-9]+(?:\.[0-9]+)?)(B|kB|MB|GB|TB|KiB|MiB|GiB|TiB)\Z")


def parse_docker_size(value: str) -> int:
    match = _SIZE_RE.fullmatch(value.strip())
    if match is None:
        raise ScaleError("Docker stats returned a malformed byte quantity")
    amount = float(match.group(1))
    result = int(round(amount * _SIZE_UNITS[match.group(2)]))
    if result < 0:
        raise ScaleError("Docker stats returned a negative byte quantity")
    return result


def parse_io_pair(value: str) -> tuple[int, int]:
    parts = [part.strip() for part in value.split("/")]
    if len(parts) != 2:
        raise ScaleError("Docker stats returned a malformed I/O pair")
    return parse_docker_size(parts[0]), parse_docker_size(parts[1])


def parse_stats_records(raw: str) -> list[dict[str, object]]:
    records: list[dict[str, object]] = []
    for line in raw.splitlines():
        if not line.strip():
            continue
        try:
            value = json.loads(line)
        except (json.JSONDecodeError, UnicodeError) as error:
            raise ScaleError("Docker stats returned malformed JSON") from error
        if not isinstance(value, dict):
            raise ScaleError("Docker stats returned a non-object record")
        records.append(value)
    if not records:
        raise ScaleError("Docker stats returned no container records")
    return records


@dataclass
class ResourceAccumulator:
    """Aggregate bounded sampled cgroup/container-interface diagnostics."""

    services_by_id: Mapping[str, str]
    phase_samples: Counter[str] = field(default_factory=Counter)
    aggregate_peaks: dict[str, dict[str, float | int]] = field(default_factory=dict)
    per_service: dict[str, dict[str, float | int]] = field(default_factory=dict)
    final_io: dict[str, dict[str, int]] = field(default_factory=dict)

    def _service_for_id(self, container_id: str) -> str:
        for known, service in self.services_by_id.items():
            if container_id == known or container_id.startswith(known) or known.startswith(
                container_id
            ):
                return service
        raise ScaleError("Docker stats returned an unowned container")

    def add(self, phase: str, raw: str) -> None:
        if phase not in ("convergence", "steady"):
            raise ScaleError("unknown resource-sample phase")
        parsed: dict[str, dict[str, float | int]] = {}
        for record in parse_stats_records(raw):
            container_id = str(record.get("ID") or record.get("Container") or "")
            service = self._service_for_id(container_id)
            try:
                cpu_text = str(record["CPUPerc"]).strip()
                if not cpu_text.endswith("%"):
                    raise ValueError
                cpu = float(cpu_text[:-1])
                memory, _limit = parse_io_pair(str(record["MemUsage"]))
                network_rx, network_tx = parse_io_pair(str(record["NetIO"]))
                block_read, block_write = parse_io_pair(str(record["BlockIO"]))
                pids = int(record["PIDs"])
            except (KeyError, TypeError, ValueError) as error:
                raise ScaleError("Docker stats returned malformed resource fields") from error
            if cpu < 0 or pids < 0 or service in parsed:
                raise ScaleError("Docker stats returned invalid or duplicate resources")
            parsed[service] = {
                "cpuPercent": cpu,
                "memoryBytes": memory,
                "pids": pids,
                "networkRxBytes": network_rx,
                "networkTxBytes": network_tx,
                "blockReadBytes": block_read,
                "blockWriteBytes": block_write,
            }
        expected = set(self.services_by_id.values())
        if set(parsed) != expected:
            raise ScaleError("Docker stats omitted a scale container")
        aggregate = {
            key: sum(float(item[key]) for item in parsed.values())
            for key in ("cpuPercent", "memoryBytes", "pids")
        }
        peak = self.aggregate_peaks.setdefault(
            phase, {"cpuPercent": 0.0, "memoryBytes": 0, "pids": 0}
        )
        for key, value in aggregate.items():
            peak[key] = max(float(peak[key]), value)
        for service, values in parsed.items():
            service_peak = self.per_service.setdefault(
                service, {"cpuPercent": 0.0, "memoryBytes": 0, "pids": 0}
            )
            for key in ("cpuPercent", "memoryBytes", "pids"):
                service_peak[key] = max(float(service_peak[key]), float(values[key]))
            self.final_io[service] = {
                key: int(values[key])
                for key in (
                    "networkRxBytes",
                    "networkTxBytes",
                    "blockReadBytes",
                    "blockWriteBytes",
                )
            }
        self.phase_samples[phase] += 1

    def summary(self) -> dict[str, object]:
        for phase in ("convergence", "steady"):
            if self.phase_samples[phase] < 1:
                raise ScaleError(f"resource sampler retained no {phase} sample")
        aggregate_io = {
            key: sum(item[key] for item in self.final_io.values())
            for key in (
                "networkRxBytes",
                "networkTxBytes",
                "blockReadBytes",
                "blockWriteBytes",
            )
        }
        return {
            "samples": dict(sorted(self.phase_samples.items())),
            "aggregatePeaks": self.aggregate_peaks,
            "aggregateFinalIo": aggregate_io,
            "perNodePeaks": dict(sorted(self.per_service.items())),
            "measurementBoundary": (
                "sampled Docker cgroup memory/CPU/PIDs and cumulative container-interface "
                "I/O; not host RSS, physical-wire bytes, energy, or a target-tier threshold"
            ),
        }


class StatsSampler:
    """Periodically sample exactly the project-owned running containers."""

    def __init__(
        self,
        docker: Docker,
        containers: Mapping[str, str],
        interval: float,
    ):
        if not 0.25 <= interval <= 10.0:
            raise ScaleError("stats sample interval must be between 0.25 and 10 seconds")
        self.docker = docker
        self.containers = dict(containers)
        self.interval = interval
        self.accumulator = ResourceAccumulator(
            {container_id: service for service, container_id in containers.items()}
        )
        self._phase = "convergence"
        self._phase_lock = threading.Lock()
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None
        self.errors: list[str] = []

    def set_phase(self, phase: str) -> None:
        if phase not in ("convergence", "steady"):
            raise ScaleError("invalid sampler phase")
        with self._phase_lock:
            self._phase = phase

    def _sample(self) -> None:
        raw = self.docker.run(
            (
                "stats",
                "--no-stream",
                "--no-trunc",
                "--format",
                "json",
                *self.containers.values(),
            ),
            timeout=20,
        )
        with self._phase_lock:
            phase = self._phase
        self.accumulator.add(phase, raw)

    def _run(self) -> None:
        while not self._stop.is_set():
            try:
                self._sample()
            except ScaleError:
                self.errors.append("sample-failed")
            self._stop.wait(self.interval)

    def start(self) -> None:
        if self._thread is not None:
            raise ScaleError("resource sampler was started twice")
        self._thread = threading.Thread(target=self._run, name="aster-stats", daemon=True)
        self._thread.start()

    def _finish(self) -> None:
        self._stop.set()
        if self._thread is None:
            raise ScaleError("resource sampler was not started")
        self._thread.join(timeout=25)
        if self._thread.is_alive():
            raise ScaleError("resource sampler did not stop")

    def abort(self) -> None:
        """Stop sampling without converting an earlier run failure into metrics."""

        self._finish()

    def stop(self) -> dict[str, object]:
        self._finish()
        summary = self.accumulator.summary()
        summary["failedSamples"] = len(self.errors)
        return summary


def _integer_field(record: Mapping[str, str], key: str) -> int:
    value = record.get(key, "0")
    try:
        parsed = int(value)
    except ValueError as error:
        raise ScaleError(f"CONTACT receipt contained malformed {key}") from error
    if parsed < 0:
        raise ScaleError(f"CONTACT receipt contained negative {key}")
    return parsed


def contact_graph_summary(
    logs: Mapping[str, str],
    identities: Mapping[str, ReadyIdentity],
    authorized: Sequence[str],
    outsiders: Sequence[str],
) -> dict[str, object]:
    carrier_to_service = {item.carrier: service for service, item in identities.items()}
    if len(carrier_to_service) != len(identities):
        raise ScaleError("carrier identity map is ambiguous")
    edges: set[tuple[str, str]] = set()
    degrees: dict[str, set[str]] = defaultdict(set)
    candidate_counts: Counter[str] = Counter()
    pass_counts: Counter[str] = Counter()
    error_counts: Counter[str] = Counter()
    transfer_contacts = 0
    noop_contacts = 0
    outsider_rejection = False
    outsider_set = set(outsiders)
    authorized_set = set(authorized)
    for local, text in logs.items():
        if local not in identities:
            raise ScaleError("contact logs contain an unknown local service")
        for receipt in receipt_fields(text, "DISCOVERY"):
            status = receipt.get("status", "")
            if status == "dropped" and receipt.get("reason") == "candidate-limit":
                raise ScaleError("automatic discovery exceeded its exact candidate bound")
            if status == "candidate":
                remote = carrier_to_service.get(receipt.get("carrier_peer", ""))
                if remote is None:
                    raise ScaleError("automatic discovery retained an unknown carrier")
                candidate_counts[local] += 1
        for receipt in receipt_fields(text, "CONTACT"):
            status = receipt.get("status", "")
            remote = carrier_to_service.get(receipt.get("carrier_peer", ""))
            if status == "pass":
                if remote is None:
                    raise ScaleError("a contact passed for an unknown carrier")
                if local in outsider_set or remote in outsider_set:
                    raise ScaleError("outsider completed an authenticated contact")
                if local not in authorized_set or remote not in authorized_set:
                    raise ScaleError("authenticated contact escaped the authorized cohort")
                edge = tuple(sorted((local, remote)))
                edges.add(edge)
                degrees[local].add(remote)
                degrees[remote].add(local)
                pass_counts[local] += 1
                moved = sum(
                    _integer_field(receipt, key)
                    for key in ("fetched", "inserted", "control_fetched", "blob_ranges_fetched")
                )
                remaining = sum(
                    _integer_field(receipt, key)
                    for key in ("remaining", "control_remaining", "mutable_remaining", "blob_remaining")
                )
                if moved > 0:
                    transfer_contacts += 1
                elif remaining == 0:
                    noop_contacts += 1
            elif status == "error":
                error = receipt.get("error", "")
                if "capacity%20reached" in error:
                    raise ScaleError("automatic mission admission exceeded its exact bound")
                crosses_authority_partition = (
                    local in outsider_set and remote in authorized_set
                ) or (local in authorized_set and remote in outsider_set)
                if crosses_authority_partition and error.startswith(
                    "mission%20authentication"
                ):
                    outsider_rejection = True
                category = error.split("%20", 1)[0] if error else "unknown"
                error_counts[category] += 1
    if not outsider_rejection:
        raise ScaleError("outsider did not produce a correlated mission rejection")
    if not edges:
        raise ScaleError("no authorized mission-authenticated contact edge was observed")
    visited: set[str] = set()
    frontier = [authorized[0]]
    while frontier:
        service = frontier.pop()
        if service in visited:
            continue
        visited.add(service)
        frontier.extend(degrees[service] - visited)
    connected = visited == authorized_set
    if not connected:
        raise ScaleError("retained authenticated contact graph was disconnected")
    degree_values = [len(degrees[service]) for service in authorized]
    return {
        "candidateReceipts": sum(candidate_counts.values()),
        "authenticatedPassReceipts": sum(pass_counts.values()),
        "errorReceiptsByCategory": dict(sorted(error_counts.items())),
        "undirectedAuthenticatedEdges": len(edges),
        "connected": connected,
        "degree": {
            "min": min(degree_values),
            "median": statistics.median(degree_values),
            "max": max(degree_values),
        },
        "transferContacts": transfer_contacts,
        "zeroDifferenceContacts": noop_contacts,
        "outsiderMissionRejection": True,
    }


def collect_logs(compose: Compose, services: Sequence[str]) -> dict[str, str]:
    return run_parallel(services, compose.logs, "concurrent log collection")


def wait_services_ready(
    compose: Compose, services: Sequence[str], *, seconds: float
) -> None:
    """Poll every process-local application surface without a healthcheck loop."""

    deadline = time.monotonic() + seconds

    def wait_one(service: str) -> None:
        while True:
            try:
                compose.helper(service, ("status",), timeout=5)
                return
            except ScaleError:
                if time.monotonic() >= deadline:
                    raise ScaleError(
                        f"node {service} did not become application-ready"
                    ) from None
                time.sleep(0.25)

    run_parallel(services, wait_one, "concurrent application readiness")


def start_services(
    compose: Compose,
    services: Sequence[str],
    *,
    discovery: bool,
    wait_seconds: int,
) -> tuple[float, dict[str, str]]:
    compose.run(
        ("create", "--no-build", "--force-recreate", *services),
        timeout=180,
        discovery=discovery,
    )
    records = compose.ps(services, all_states=True)
    validate_service_records(records, services, expected_state="created")
    started = time.monotonic()
    compose.run(
        ("start", "--wait", "--wait-timeout", str(wait_seconds), *services),
        timeout=wait_seconds + 30,
        discovery=discovery,
    )
    containers = validate_service_records(
        compose.ps(services, all_states=False), services, expected_state="running"
    )
    wait_services_ready(compose, services, seconds=wait_seconds)
    return started, containers


def stop_services(compose: Compose, services: Sequence[str]) -> None:
    compose.run(("stop", "--timeout", "15", *services), timeout=120)
    logs = collect_logs(compose, services)
    for service in services:
        stops = receipt_fields(logs[service], "STOP")
        if not any(item.get("lifecycle") == "complete" for item in stops):
            raise ScaleError(f"node {service} did not emit a clean STOP receipt")
    validate_service_records(
        compose.ps(services, all_states=True), services, expected_state="exited"
    )


def read_state_sizes(compose: Compose, services: Sequence[str]) -> dict[str, int]:
    def read_one(service: str) -> int:
        raw = compose.run(
            ("exec", "-T", service, "du", "-sb", "/state"), timeout=15
        )
        value = raw.strip().split(maxsplit=1)[0] if raw.strip() else ""
        try:
            size = int(value)
        except ValueError as error:
            raise ScaleError(f"node {service} returned a malformed state size") from error
        if size < 0:
            raise ScaleError(f"node {service} returned a negative state size")
        return size

    return run_parallel(services, read_one, "concurrent state-size collection")


def parse_started_at(raw: str) -> list[datetime]:
    values: list[datetime] = []
    for line in raw.splitlines():
        value = line.strip()
        if not value:
            continue
        try:
            values.append(datetime.fromisoformat(value.replace("Z", "+00:00")))
        except ValueError as error:
            raise ScaleError("Docker inspect returned a malformed start time") from error
    if not values:
        raise ScaleError("Docker inspect returned no start times")
    return values


def start_skew_seconds(docker: Docker, containers: Mapping[str, str]) -> float:
    raw = docker.run(
        (
            "inspect",
            "--format",
            "{{.State.StartedAt}}",
            *containers.values(),
        ),
        timeout=20,
    )
    values = parse_started_at(raw)
    if len(values) != len(containers):
        raise ScaleError("Docker inspect omitted a scale container start time")
    return (max(values) - min(values)).total_seconds()


def validate_full_inventories(
    compose: Compose,
    authorized: Sequence[str],
    outsiders: Sequence[str],
    expected: Mapping[str, ExpectedEvent],
    *,
    seconds: float = 30,
) -> int:
    """Require exact inventories within a bounded window and report query pressure."""

    _completed, transient_query_errors, _all_exact = wait_for_full_convergence(
        compose,
        authorized,
        outsiders,
        expected,
        time.monotonic(),
        seconds,
    )
    return transient_query_errors


def _progress(message: str) -> None:
    print(f"aster-lan-scale-compose: {message}", file=sys.stderr, flush=True)


def run_case(
    compose: Compose,
    nodes: int,
    convergence_seconds: int,
    steady_seconds: int,
    sample_seconds: float,
) -> dict[str, object]:
    authorized = authorized_services(nodes)
    outsiders = outsider_services()
    services = (*authorized, *outsiders)

    compose.run(("config", "--quiet"), timeout=20)
    compose.run(("version",), timeout=20)
    _progress("building the discovery-enabled image (cached after the first run)")
    compose.run(("build", "init"), timeout=1_800)
    _progress(f"provisioning {nodes} authorized nodes and one outsider")
    compose.run(("run", "--rm", "--no-deps", "init"), timeout=240)

    _progress("publishing one 1-KiB Event per authorized node while discovery is off")
    start_services(compose, services, discovery=False, wait_seconds=120)
    offline_logs = collect_logs(compose, services)
    offline_identities = {
        service: parse_ready_identity(offline_logs[service], service) for service in services
    }
    validate_identity_cohort(
        offline_identities, authorized, outsiders, discovery=False
    )

    def seed(service: str) -> ExpectedEvent | None:
        compose.helper(
            service,
            ("subscribe", "--operation-key", f"scale/consume/{service}"),
            timeout=20,
        )
        if service in outsiders:
            return None
        compose.helper(service, ("publication-init", "--journal", "/state/publication.redb", "--client-id", "lan-scale-source"))
        logical_key = event_logical_key(service)
        payload = event_payload(service)
        event_id = canonical_event_id(
            compose.helper(
                service,
                (
                    "publish",
                    "--journal", "/state/publication.redb",
                    "--client-id", "lan-scale-source",
                    "--logical-key",
                    logical_key,
                    "--payload",
                    payload,
                    "--id-only",
                ),
                timeout=30,
            ).strip()
        )
        return ExpectedEvent(event_id, logical_key, payload)

    seeded = run_parallel(services, seed, "concurrent offline publication")
    expected = {
        item.event_id: item
        for service in authorized
        for item in (seeded[service],)
        if item is not None
    }
    if len(expected) != nodes:
        raise ScaleError("offline publishers did not return distinct Event IDs")
    offline_inventories = query_all(compose, services)
    for service in authorized:
        own = seeded[service]
        assert own is not None
        validate_inventory(
            offline_inventories[service],
            {own.event_id: own},
            f"isolated node {service}",
            require_complete=True,
        )
    for service in outsiders:
        validate_inventory(
            offline_inventories[service],
            {},
            f"isolated outsider {service}",
            require_complete=True,
        )
    stop_services(compose, services)

    _progress("starting the complete rosterless discovery cohort concurrently")
    started, containers = start_services(
        compose, services, discovery=True, wait_seconds=150
    )
    skew = start_skew_seconds(compose.docker, containers)
    scale_logs = collect_logs(compose, services)
    identities = {
        service: parse_ready_identity(scale_logs[service], service) for service in services
    }
    validate_identity_cohort(identities, authorized, outsiders, discovery=True)

    sampler = StatsSampler(compose.docker, containers, sample_seconds)
    sampler.start()
    try:
        convergence, transient_query_errors, all_exact_seconds = (
            wait_for_full_convergence(
                compose,
                authorized,
                outsiders,
                expected,
                started,
                convergence_seconds,
            )
        )
        sampler.set_phase("steady")
        _progress("sampling a short post-convergence zero-difference window")
        steady_deadline = time.monotonic() + steady_seconds
        while time.monotonic() < steady_deadline:
            validate_service_records(
                compose.ps(services, all_states=False),
                services,
                expected_state="running",
            )
            time.sleep(min(1.0, max(0.0, steady_deadline - time.monotonic())))
        steady_query_errors = validate_full_inventories(
            compose, authorized, outsiders, expected
        )
    except BaseException:
        sampler.abort()
        raise
    resource_summary = sampler.stop()

    scale_logs = collect_logs(compose, services)
    graph = contact_graph_summary(scale_logs, identities, authorized, outsiders)
    stop_services(compose, services)

    _progress("reopening every store with discovery disabled")
    start_services(compose, services, discovery=False, wait_seconds=120)
    restart_logs = collect_logs(compose, services)
    restart_identities = {
        service: parse_ready_identity(restart_logs[service], service)
        for service in services
    }
    validate_identity_cohort(
        restart_identities, authorized, outsiders, discovery=False
    )
    for service in services:
        if restart_identities[service].carrier != identities[service].carrier:
            raise ScaleError(f"node {service} changed carrier identity across restart")
        if restart_identities[service].mission != identities[service].mission:
            raise ScaleError(f"node {service} changed mission identity across restart")
    restart_query_errors = validate_full_inventories(
        compose, authorized, outsiders, expected
    )
    state_sizes = read_state_sizes(compose, services)
    stop_services(compose, services)

    convergence_values = list(convergence.values())
    return {
        "schema": "aster-lan-scale-compose/v1",
        "status": "pass",
        "authorizedNodes": nodes,
        "outsiderNodes": len(outsiders),
        "totalContainers": len(services),
        "offlineEvents": len(expected),
        "offlinePayloadBytesEach": PAYLOAD_BYTES,
        "exactApplicationObservations": nodes * nodes,
        "runtimeControls": {
            "syncIntervalMs": DEFAULT_SYNC_MS[nodes],
            "tokioWorkerThreads": 1,
            "continuousHealthcheck": False,
            "nearbyWindowSeconds": 3,
        },
        "convergenceSeconds": {
            "firstExact": {
                "min": min(convergence_values),
                "p50": percentile(convergence_values, 0.50),
                "p95": percentile(convergence_values, 0.95),
                "max": max(convergence_values),
            },
            "allExact": all_exact_seconds,
            "deadline": convergence_seconds,
            "transientQueryErrors": transient_query_errors,
        },
        "composeStartSkewSeconds": skew,
        "contactGraph": graph,
        "resources": resource_summary,
        "stateBytes": {
            "aggregate": sum(state_sizes.values()),
            "minPerNode": min(state_sizes.values()),
            "medianPerNode": statistics.median(state_sizes.values()),
            "maxPerNode": max(state_sizes.values()),
        },
        "restart": {
            "discovery": "disabled",
            "authorizedExactInventories": nodes,
            "outsiderInventoryEmpty": True,
            "identitiesStable": True,
            "transientQueryErrors": restart_query_errors,
        },
        "diagnosticWarnings": (
            ["transient-local-query-errors"]
            if transient_query_errors + steady_query_errors + restart_query_errors > 0
            else []
        ),
        "steadyState": {"transientQueryErrors": steady_query_errors},
        "host": {
            "os": platform.system(),
            "arch": platform.machine(),
            "logicalCpus": os.cpu_count(),
        },
        "boundary": (
            "single-host private Docker bridge; same implementation; Event only; "
            "unprotected reference provisioning; sampled diagnostics include "
            "concurrent compose-exec Python query overhead; not retained "
            "physical-LAN, hostile-LAN, target-tier, hierarchy, 100-node, or production evidence"
        ),
    }


def audit_cleanup(docker: Docker, project: str, image: str) -> None:
    filters = (
        ("container", ("ps", "--all", "--quiet", "--filter")),
        ("volume", ("volume", "ls", "--quiet", "--filter")),
        ("network", ("network", "ls", "--quiet", "--filter")),
    )
    label = f"label=com.docker.compose.project={project}"
    for kind, prefix in filters:
        if docker.run((*prefix, label), timeout=20).strip():
            raise ScaleError(f"cleanup left a project-scoped {kind}")
    if docker.run(
        ("image", "ls", "--quiet", "--no-trunc", image), timeout=20
    ).strip():
        raise ScaleError("cleanup left the uniquely named scale image")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Run a bounded generated Docker Compose LAN scale diagnostic"
    )
    parser.add_argument("--nodes", type=int, default=8, choices=ALLOWED_NODE_COUNTS)
    parser.add_argument(
        "--convergence-seconds",
        type=int,
        help="exact all-node convergence deadline (default scales with --nodes)",
    )
    parser.add_argument("--steady-seconds", type=int, default=10)
    parser.add_argument("--sample-seconds", type=float, default=1.0)
    parser.add_argument(
        "--config-only",
        action="store_true",
        help="validate the generated Compose model without contacting the daemon",
    )
    return parser


def _interrupt(_signum: int, _frame: object) -> None:
    raise KeyboardInterrupt


def main(argv: Sequence[str] | None = None) -> int:
    arguments = build_parser().parse_args(argv)
    try:
        nodes = validate_node_count(arguments.nodes)
        convergence_seconds = (
            arguments.convergence_seconds
            if arguments.convergence_seconds is not None
            else DEFAULT_CONVERGENCE_SECONDS[nodes]
        )
        if not 30 <= convergence_seconds <= 600:
            raise ScaleError("convergence deadline must be between 30 and 600 seconds")
        if not 5 <= arguments.steady_seconds <= 60:
            raise ScaleError("steady window must be between 5 and 60 seconds")
        if not 0.25 <= arguments.sample_seconds <= 10:
            raise ScaleError("sample interval must be between 0.25 and 10 seconds")
    except ScaleError as error:
        print(f"aster-lan-scale-compose: {error}", file=sys.stderr)
        return 2

    signal.signal(signal.SIGINT, _interrupt)
    signal.signal(signal.SIGTERM, _interrupt)
    executable = shutil.which("docker")
    if executable is None:
        print("aster-lan-scale-compose: docker was not found", file=sys.stderr)
        return 2

    docker = Docker(str(Path(executable).resolve()))
    project = project_name()
    services = all_services(nodes)
    cleanup_needed = False
    exit_code = 0
    result: dict[str, object] | None = None
    with tempfile.TemporaryDirectory(prefix="aster-lan-scale-compose-") as directory:
        compose_file = write_compose_model(Path(directory), nodes)
        compose = Compose(docker, compose_file, project, services)
        try:
            compose.run(("config", "--quiet"), timeout=20)
            compose.run(("version",), timeout=20)
            if arguments.config_only:
                print(
                    json.dumps(
                        {
                            "schema": "aster-lan-scale-compose-config/v1",
                            "status": "pass",
                            "authorizedNodes": nodes,
                            "outsiderNodes": OUTSIDER_COUNT,
                            "generatedServices": len(services),
                            "runtimeControls": {
                                "syncIntervalMs": DEFAULT_SYNC_MS[nodes],
                                "tokioWorkerThreads": 1,
                                "continuousHealthcheck": False,
                                "nearbyWindowSeconds": 3,
                            },
                        },
                        sort_keys=True,
                    )
                )
                return 0
            try:
                compose.run(("ps",), timeout=20)
            except ScaleError as error:
                raise ScaleError(
                    "Docker daemon access is required; ensure the current user can access "
                    "the configured Docker socket"
                ) from error
            cleanup_needed = True
            result = run_case(
                compose,
                nodes,
                convergence_seconds,
                arguments.steady_seconds,
                arguments.sample_seconds,
            )
        except ScaleError as error:
            print(f"aster-lan-scale-compose: {error}", file=sys.stderr)
            exit_code = 2
        except KeyboardInterrupt:
            print("aster-lan-scale-compose: interrupted", file=sys.stderr)
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
                        timeout=180,
                    )
                    audit_cleanup(docker, project, compose.image)
                except ScaleError as error:
                    print(
                        f"aster-lan-scale-compose: cleanup warning: {error}",
                        file=sys.stderr,
                    )
                    exit_code = 2
    if result is not None and exit_code == 0:
        print(json.dumps(result, indent=2, sort_keys=True))
    return exit_code


if __name__ == "__main__":
    raise SystemExit(main())
