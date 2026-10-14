#!/usr/bin/env python3
"""Reproducible, fail-closed OrbStack/Docker controller for the Aster lab.

The controller is dry-run by default.  Docker mutation requires the explicit
``--execute`` option.  It never invokes a shell and never pulls an image.
"""

from __future__ import annotations

import argparse
import base64
import dataclasses
import datetime as dt
import hashlib
import ipaddress
import json
import math
import os
from pathlib import Path
import platform
import re
import secrets
import shlex
import shutil
import stat
import subprocess
import sys
import tempfile
import time
from typing import Any, Iterable, Sequence, TextIO


SCHEMA = "aster-lab-controller/v1"
PREFIX = "aster-lab-"
IMAGE = "aster-lab:validation"
SELECTED_NAT_IMAGE = "aster-lab:selected-nat"
LAB_BASE_IMAGE = "rust@sha256:0e2bcaef56d041a486784e54104a81aebe0da44bd03019bd70bc0401e42e4a97"
BASE_IMAGE_SOURCE_LABEL = "org.opencontainers.image.source"
BASE_IMAGE_SOURCE = "https://github.com/rust-lang/docker-rust"
PINNED_BASE_IMAGE_LABELS = {BASE_IMAGE_SOURCE_LABEL: BASE_IMAGE_SOURCE}
SELECTED_NAT_LOCAL_REPOSITORY = "aster-lab"
SELECTED_NAT_IMAGE_ENVIRONMENT = [
    "PATH=/usr/local/cargo/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
    "RUSTUP_HOME=/usr/local/rustup",
    "CARGO_HOME=/usr/local/cargo",
    "RUST_VERSION=1.97.1",
]
MANAGED_LABEL = "com.defenseunicorns.aster-lab.managed"
RUN_LABEL = "com.defenseunicorns.aster-lab.run-id"
ROLE_LABEL = "com.defenseunicorns.aster-lab.role"
IMAGE_SCHEMA_LABEL = "com.defenseunicorns.aster-lab.image-schema"
IMAGE_INPUT_LABEL = "com.defenseunicorns.aster-lab.build-input-sha256"
IMAGE_BASE_LABEL = "com.defenseunicorns.aster-lab.base-image"
IMAGE_SCHEMA = "aster-lab-image/v1"
SELECTED_NAT_IMAGE_SCHEMA = "aster-selected-nat-image/v1"
SELECTED_NAT_RELAY_DNS = "relay.aster.test"
SELECTED_NAT_RELAY_IP = "10.250.0.20"
SELECTED_NAT_RELAY_HTTPS_PORT = 8_443
SELECTED_NAT_RELAY_HTTP_PORT = 8_080
SELECTED_NAT_NODE_PORT = 44_000
SELECTED_NAT_RUN_FOR_SECONDS = 30
SELECTED_NAT_SYNC_MS = 15_001
SELECTED_NAT_MAX_PATH_TRANSITIONS = 1_024
SELECTED_NAT_RELAY_MAX_ADMITTED_CONNECTIONS = 8
SELECTED_NAT_RELAY_BYTES_PER_SECOND = 1_048_576
SELECTED_NAT_RELAY_MAX_BURST_BYTES = 1_048_576
SELECTED_NAT_RELAY_KEY_CACHE_CAPACITY = 256
SELECTED_NAT_RECEIPT_SCHEMA = "aster-selected-iroh-nat-receipt/v2"
SELECTED_NAT_RECEIPT_CLAIM = (
    "selected-iroh-one-host-namespace-nat-two-cell-acceptance"
)
SELECTED_NAT_MAX_PCAP_BYTES = 128 * 1024 * 1024
SELECTED_NAT_MAX_BUNDLE_BYTES = 1 * 1024 * 1024
SELECTED_NAT_MAX_CURATED_ARTIFACT_BYTES = 1024 * 1024 * 1024
SELECTED_NAT_MAX_COMMITTED_INPUTS = 1024

WORKSPACE = Path(__file__).resolve().parents[1]
DOCKERFILE = WORKSPACE / "lab" / "Dockerfile"
SELECTED_NAT_DOCKERFILE = WORKSPACE / "lab" / "Dockerfile.selected-nat"
DEFAULT_EVIDENCE_ROOT = WORKSPACE / "lab" / "runs"
DEFAULT_SELECTED_NAT_EVIDENCE_ROOT = Path(tempfile.gettempdir()) / "aster-selected-nat-runs"

DIRECT_NETWORK = "aster-lab-direct"
NAT_NETWORKS = {
    "lan-a": ("aster-lab-lan-a", "10.250.1.0/24", "10.250.1.254"),
    "wan": ("aster-lab-wan", "10.250.0.0/24", "10.250.0.254"),
    "lan-b": ("aster-lab-lan-b", "10.250.2.0/24", "10.250.2.254"),
}
DIRECT_SPEC = (DIRECT_NETWORK, "10.250.10.0/24", "10.250.10.254")

FIXED_CONTAINER_NAMES = {
    "transfer": "aster-lab-transfer",
    "blob": "aster-lab-blob",
    "scale": "aster-lab-scale",
    "resource": "aster-lab-resource",
    "provision": "aster-lab-provision",
    "node-a": "aster-lab-node-a",
    "node-b": "aster-lab-node-b",
    "nat-a": "aster-lab-nat-a",
    "nat-b": "aster-lab-nat-b",
    "infra": "aster-lab-infra",
    "route-a": "aster-lab-route-a",
    "route-b": "aster-lab-route-b",
}

RESOURCE_NAME = re.compile(r"^aster-lab-[a-z0-9][a-z0-9-]{0,62}$")
RUN_ID = re.compile(r"^[0-9a-f]{16}$")
MEMORY_VALUE = re.compile(r"^[1-9][0-9]*(?:[kmgt]b?|b)?$", re.IGNORECASE)
CPU_VALUE = re.compile(r"^(?:[1-9][0-9]*|0\.[0-9]+|[1-9][0-9]*\.[0-9]+)$")
EXPECTED_DOCKERIGNORE = """**
!Cargo.toml
!Cargo.lock
!LICENSE
!THIRD_PARTY_NOTICES.md
!crates/
!crates/**
!third-party/
!third-party/**
!lab/
!lab/Dockerfile
!lab/Dockerfile.selected-nat
!lab/Dockerfile.dockerignore
!lab/debian.sources
"""
TIMEOUT_CAPTURE_LIMIT = 4 * 1024 * 1024

SELECTED_NAT_GLOBAL_MANIFEST_PATHS = {
    "suite-controller": "controller.json",
    "suite-summary": "selected-nat-suite.json",
    "suite-source-identity": "source-identity.json",
    "suite-build-identity": "selected-build.json",
}
SELECTED_NAT_COMMON_CELL_MANIFEST_PATHS = {
    "controller-receipt": "controller.json",
    "scenario-receipt": "scenario-request.json",
    "source-identity": "source-identity.json",
    "build-identity": "binary-inventory.json",
    "image-identity": "image-identity.json",
    "prepare-manifest": "outputs/provision/manifest.tsv",
    "prepare-log": "prepare.log",
    "publish-log": "publish.log",
    "verify-log": "verify.log",
    "node-a-result": "node-a-result.json",
    "node-a-log": "node-a.log",
    "node-b-result": "node-b-result.json",
    "node-b-log": "node-b.log",
    "nat-runtime": "selected-nat-runtime.json",
    "nat-finalization": "selected-nat-finalization.json",
    "nat-a-nft-before": "nat-a-nft-before.json",
    "nat-a-nft-after": "nat-a-nft-after.json",
    "nat-b-nft-before": "nat-b-nft-before.json",
    "nat-b-nft-after": "nat-b-nft-after.json",
    "nat-a-nft-program": "nat-a.nft",
    "nat-b-nft-program": "nat-b.nft",
    "nat-a-config": "aster-lab-nat-a-configuration.json",
    "nat-b-config": "aster-lab-nat-b-configuration.json",
    "lan-a-network-config": "aster-lab-lan-a-network.json",
    "wan-network-config": "aster-lab-wan-network.json",
    "lan-b-network-config": "aster-lab-lan-b-network.json",
    "nat-a-wan-pcap": "outputs/nat-a/nat-a-wan.pcap",
    "nat-b-wan-pcap": "outputs/nat-b/nat-b-wan.pcap",
    "pcap-tuple-summary": "pcap-tuple-summary.json",
    "route-init-removal": "route-init-removal.json",
    "route-a-config": "aster-lab-route-a-configuration.json",
    "route-b-config": "aster-lab-route-b-configuration.json",
    "provision-prepare-config": "aster-lab-provision-configuration.json",
    "provision-verify-config": "aster-lab-provision-verifier-configuration.json",
    "node-a-config": "aster-lab-node-a-configuration.json",
    "node-b-config": "aster-lab-node-b-configuration.json",
    "node-a-runtime-privilege": "node-a-runtime-privilege.json",
    "node-b-runtime-privilege": "node-b-runtime-privilege.json",
    "cleanup-log": "cleanup-summary.json",
    "events": "events.jsonl",
    "canary-scan": "canary-scan.json",
    "canary-destroy-log": "canary-destroy.log",
    "secret-cleanup-receipt": "secret-cleanup.json",
}
SELECTED_NAT_CELL_EXTRA_MANIFEST_PATHS = {
    "cone-direct": {"relay-disabled-receipt": "relay-disabled.json"},
    "restrictive-relay": {
        "relay-log": "relay.log",
        "relay-material-log": "relay-material.log",
        "relay-material-destroy-log": "relay-material-destroy.log",
        "relay-ca-der": "outputs/provision/relay/ca.der",
        "relay-cert-der": "outputs/provision/relay/server.cert.der",
        "relay-config": "relay-config.json",
        "relay-runtime-config": "aster-lab-infra-configuration.json",
        "relay-runtime-privilege": "infra-runtime-privilege.json",
    },
}
SELECTED_NAT_LIMITATIONS = {
    "claim_scope": "observed-bounded-selected-iroh-carrier",
    "physical_hosts": 1,
    "topology": "linux-network-namespaces-on-one-host",
    "namespace_nat": "observed-bounded",
    "physical_nat": "not-claimed",
    "nat_hardware": "not-claimed",
    "public_internet": "not-claimed",
    "physical_path": "not-claimed",
    "relay_fallback_chronology": "not-claimed",
    "btle": "not-claimed",
    "independent_implementation": "not-claimed",
    "resource_thresholds": "not-claimed",
    "clock_assurance": "filesystem-metadata-not-independent",
    "sealed_representation_hash": "not-exposed-by-production-api",
    "hosted_or_public_relay": "not-used",
    "port_mapping": "disabled-not-used",
    "path_witness": "selected-final-path-not-route-authorization",
    "control_file_destruction": (
        "bounded-software-only-standalone-control-files-physical-sanitization-not-claimed"
    ),
    "encrypted_event_state_and_credentials": (
        "retained-external-restricted-not-sanitized-by-control-file-cleanup"
    ),
    "registry_image_digest": "not-claimed-local-image-id-only",
    "build_network": "explicit-default-network-no-cache-not-hermetic",
    "lab_network_exclusivity": "not-claimed",
    "relay_pre_auth_connection_cap": "not-enforced",
}


class LabError(RuntimeError):
    """Controlled laboratory failure."""


@dataclasses.dataclass(frozen=True)
class NetworkSpec:
    name: str
    subnet: ipaddress.IPv4Network
    gateway: ipaddress.IPv4Address

    @classmethod
    def from_tuple(cls, value: tuple[str, str, str]) -> "NetworkSpec":
        result = cls(
            name=value[0],
            subnet=ipaddress.ip_network(value[1]),
            gateway=ipaddress.ip_address(value[2]),
        )
        if result.gateway not in result.subnet:
            raise LabError(f"gateway {result.gateway} is outside {result.subnet}")
        validate_resource_name(result.name)
        return result


@dataclasses.dataclass(frozen=True)
class PlannedResource:
    kind: str
    name: str
    role: str

    def as_dict(self) -> dict[str, str]:
        return dataclasses.asdict(self)


@dataclasses.dataclass(frozen=True)
class BuildInput:
    relative_path: str
    content: bytes
    sha256: str

    def receipt(self) -> dict[str, Any]:
        return {
            "path": self.relative_path,
            "bytes": len(self.content),
            "sha256": self.sha256,
        }


class CommandRunner:
    """Runs explicit argument arrays and appends a command receipt."""

    def __init__(self, run_dir: Path):
        self.run_dir = run_dir
        self.sequence = existing_command_sequence(run_dir / "commands.jsonl")

    def run(
        self,
        arguments: Sequence[str],
        *,
        input_text: str | None = None,
        check: bool = True,
        timeout: float | None = None,
    ) -> subprocess.CompletedProcess[str]:
        args = [str(value) for value in arguments]
        if not args or any("\x00" in value for value in args):
            raise LabError("invalid empty command or NUL-containing argument")
        self.sequence += 1
        sequence = self.sequence
        stdout_name = f"command-{sequence:04d}.stdout"
        stderr_name = f"command-{sequence:04d}.stderr"
        started = utc_now()
        monotonic_start = time.monotonic()
        try:
            completed = subprocess.run(
                args,
                input=input_text,
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                shell=False,
                check=False,
                timeout=timeout,
            )
        except subprocess.TimeoutExpired as error:
            full_stdout = timeout_output(error.stdout)
            full_stderr = timeout_output(error.stderr)
            stdout, stdout_truncated = bounded_timeout_output(full_stdout)
            stderr, stderr_truncated = bounded_timeout_output(full_stderr)
            write_exclusive_text(self.run_dir / stdout_name, stdout)
            write_exclusive_text(self.run_dir / stderr_name, stderr)
            append_jsonl(
                self.run_dir / "commands.jsonl",
                {
                    "schema": SCHEMA,
                    "sequence": sequence,
                    "started_utc": started,
                    "elapsed_ms": int((time.monotonic() - monotonic_start) * 1000),
                    "arguments": args,
                    "stdin_sha256": sha256_text(input_text) if input_text is not None else None,
                    "timed_out": True,
                    "partial_stdout_sha256": sha256_text(full_stdout),
                    "partial_stderr_sha256": sha256_text(full_stderr),
                    "stdout_truncated": stdout_truncated,
                    "stderr_truncated": stderr_truncated,
                    "stdout": stdout_name,
                    "stderr": stderr_name,
                    "error": str(error),
                },
            )
            raise LabError(f"command could not run: {shlex.join(args)}: {error}") from error
        except OSError as error:
            write_exclusive_text(self.run_dir / stdout_name, "")
            write_exclusive_text(self.run_dir / stderr_name, "")
            append_jsonl(
                self.run_dir / "commands.jsonl",
                {
                    "schema": SCHEMA,
                    "sequence": sequence,
                    "started_utc": started,
                    "elapsed_ms": int((time.monotonic() - monotonic_start) * 1000),
                    "arguments": args,
                    "stdin_sha256": sha256_text(input_text) if input_text is not None else None,
                    "stdout": stdout_name,
                    "stderr": stderr_name,
                    "error": str(error),
                },
            )
            raise LabError(f"command could not run: {shlex.join(args)}: {error}") from error
        write_exclusive_text(self.run_dir / stdout_name, completed.stdout)
        write_exclusive_text(self.run_dir / stderr_name, completed.stderr)
        append_jsonl(
            self.run_dir / "commands.jsonl",
            {
                "schema": SCHEMA,
                "sequence": sequence,
                "started_utc": started,
                "elapsed_ms": int((time.monotonic() - monotonic_start) * 1000),
                "arguments": args,
                "stdin_sha256": sha256_text(input_text) if input_text is not None else None,
                "returncode": completed.returncode,
                "stdout": stdout_name,
                "stderr": stderr_name,
            },
        )
        if check and completed.returncode != 0:
            detail = completed.stderr.strip() or completed.stdout.strip()
            raise LabError(
                f"command failed ({completed.returncode}): {shlex.join(args)}"
                + (f": {detail}" if detail else "")
            )
        return completed

    def start(self, arguments: Sequence[str]) -> "RunningCommand":
        """Start one long-running command while retaining ordered evidence."""
        args = [str(value) for value in arguments]
        if not args or any("\x00" in value for value in args):
            raise LabError("invalid empty command or NUL-containing argument")
        self.sequence += 1
        sequence = self.sequence
        stdout_name = f"command-{sequence:04d}.stdout"
        stderr_name = f"command-{sequence:04d}.stderr"
        started = utc_now()
        monotonic_start = time.monotonic()
        stdout_stream = open_exclusive_text_0600(self.run_dir / stdout_name)
        try:
            stderr_stream = open_exclusive_text_0600(self.run_dir / stderr_name)
        except BaseException:
            stdout_stream.close()
            raise
        try:
            process = subprocess.Popen(
                args,
                text=True,
                stdout=stdout_stream,
                stderr=stderr_stream,
                shell=False,
            )
        except OSError as error:
            stdout_stream.close()
            stderr_stream.close()
            append_jsonl(
                self.run_dir / "commands.jsonl",
                {
                    "schema": SCHEMA,
                    "sequence": sequence,
                    "phase": "start-failed",
                    "started_utc": started,
                    "elapsed_ms": int((time.monotonic() - monotonic_start) * 1000),
                    "arguments": args,
                    "stdout": stdout_name,
                    "stderr": stderr_name,
                    "error": str(error),
                },
            )
            raise LabError(f"command could not start: {shlex.join(args)}: {error}") from error
        stdout_stream.close()
        stderr_stream.close()
        append_jsonl(
            self.run_dir / "commands.jsonl",
            {
                "schema": SCHEMA,
                "sequence": sequence,
                "phase": "started",
                "started_utc": started,
                "arguments": args,
                "stdout": stdout_name,
                "stderr": stderr_name,
            },
        )
        return RunningCommand(
            runner=self,
            process=process,
            arguments=args,
            sequence=sequence,
            started_utc=started,
            monotonic_start=monotonic_start,
            stdout_name=stdout_name,
            stderr_name=stderr_name,
        )


@dataclasses.dataclass
class RunningCommand:
    runner: CommandRunner
    process: subprocess.Popen[str]
    arguments: list[str]
    sequence: int
    started_utc: str
    monotonic_start: float
    stdout_name: str
    stderr_name: str
    finished: bool = False

    def poll(self) -> int | None:
        return self.process.poll()

    def finish(self, *, check: bool = True) -> int:
        if self.finished:
            if self.process.returncode is None:
                raise LabError("finished command has no return code")
            return self.process.returncode
        returncode = self.process.wait()
        self.finished = True
        append_jsonl(
            self.runner.run_dir / "commands.jsonl",
            {
                "schema": SCHEMA,
                "sequence": self.sequence,
                "phase": "completed",
                "started_utc": self.started_utc,
                "elapsed_ms": int((time.monotonic() - self.monotonic_start) * 1000),
                "arguments": self.arguments,
                "returncode": returncode,
                "stdout": self.stdout_name,
                "stderr": self.stderr_name,
            },
        )
        if check and returncode != 0:
            stderr = (self.runner.run_dir / self.stderr_name).read_text(
                encoding="utf-8", errors="replace"
            ).strip()
            raise LabError(
                f"command failed ({returncode}): {shlex.join(self.arguments)}"
                + (f": {stderr}" if stderr else "")
            )
        return returncode

    def terminate(self) -> int:
        if self.poll() is None:
            self.process.terminate()
            try:
                self.process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                self.process.kill()
        return self.finish(check=False)


@dataclasses.dataclass
class RunContext:
    label: str
    run_id: str
    run_dir: Path
    resources: list[PlannedResource]
    runner: CommandRunner
    image_id: str | None = None
    daemon_architecture: str | None = None
    image: str = IMAGE
    image_environment: list[str] | None = None

    @classmethod
    def create(
        cls,
        evidence_root: Path,
        label: str,
        resources: Iterable[PlannedResource],
        *,
        image: str = IMAGE,
    ) -> "RunContext":
        if not re.fullmatch(r"[a-z0-9-]{1,32}", label):
            raise LabError("invalid run label")
        root = evidence_root.resolve()
        root.mkdir(parents=True, exist_ok=True)
        run_id = secrets.token_hex(8)
        timestamp = dt.datetime.now(dt.timezone.utc).strftime("%Y%m%dT%H%M%SZ")
        run_dir = root / f"{timestamp}-{label}-{run_id}"
        run_dir.mkdir(mode=0o700)
        planned = list(resources)
        manifest = {
            "schema": SCHEMA,
            "created_utc": utc_now(),
            "run_id": run_id,
            "label": label,
            "workspace": str(WORKSPACE),
            "evidence_dir": str(run_dir),
            "image": image,
            "resources": [resource.as_dict() for resource in planned],
        }
        write_exclusive_json(run_dir / "controller.json", manifest)
        return cls(label, run_id, run_dir, planned, CommandRunner(run_dir), image=image)

    @classmethod
    def create_at(
        cls,
        run_dir: Path,
        label: str,
        resources: Iterable[PlannedResource],
        *,
        image: str = IMAGE,
    ) -> "RunContext":
        """Create one exact, single-use nested evidence directory."""
        if not re.fullmatch(r"[a-z0-9-]{1,32}", label):
            raise LabError("invalid run label")
        resolved = run_dir.resolve()
        resolved.parent.mkdir(parents=True, exist_ok=True)
        resolved.mkdir(mode=0o700)
        run_id = secrets.token_hex(8)
        planned = list(resources)
        write_exclusive_json(
            resolved / "controller.json",
            {
                "schema": SCHEMA,
                "created_utc": utc_now(),
                "run_id": run_id,
                "label": label,
                "workspace": str(WORKSPACE),
                "evidence_dir": str(resolved),
                "image": image,
                "resources": [resource.as_dict() for resource in planned],
            },
        )
        return cls(
            label,
            run_id,
            resolved,
            planned,
            CommandRunner(resolved),
            image=image,
        )

    def event(self, event: str, **fields: Any) -> None:
        selected_fields = (
            {"run_id": self.run_id, "profile": self.label}
            if self.image == SELECTED_NAT_IMAGE
            else {}
        )
        append_jsonl(
            self.run_dir / "events.jsonl",
            {
                "schema": SCHEMA,
                **selected_fields,
                "utc": utc_now(),
                "event": event,
                **fields,
            },
        )


def utc_now() -> str:
    return dt.datetime.now(dt.timezone.utc).isoformat().replace("+00:00", "Z")


def sha256_text(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def timeout_output(value: str | bytes | None) -> str:
    if value is None:
        return ""
    if isinstance(value, bytes):
        return value.decode("utf-8", errors="replace")
    return value


def bounded_timeout_output(value: str) -> tuple[str, bool]:
    if len(value) <= TIMEOUT_CAPTURE_LIMIT:
        return value, False
    half = TIMEOUT_CAPTURE_LIMIT // 2
    marker = "\n[... timeout output truncated by controller ...]\n"
    return value[:half] + marker + value[-half:], True


def open_exclusive_text_0600(path: Path) -> TextIO:
    """Create one evidence stream owner-only, independent of process umask."""
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_CLOEXEC", 0)
    descriptor = os.open(path, flags, 0o600)
    try:
        return os.fdopen(descriptor, "w", encoding="utf-8")
    except BaseException:
        os.close(descriptor)
        raise


def write_exclusive_json(path: Path, value: Any) -> None:
    with path.open("x", encoding="utf-8") as stream:
        json.dump(value, stream, indent=2, sort_keys=True)
        stream.write("\n")


def write_exclusive_canonical_json(path: Path, value: Any) -> None:
    """Write the byte-exact compact ASCII form used by retained receipts."""
    encoded = json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=True
    ).encode("ascii") + b"\n"
    with path.open("xb") as stream:
        stream.write(encoded)
        stream.flush()
        os.fsync(stream.fileno())


def write_atomic_exclusive_json(path: Path, value: Any) -> None:
    """Publish a complete state marker atomically without overwriting evidence."""
    temporary = path.with_name(f"{path.name}.pending-{secrets.token_hex(8)}")
    try:
        with temporary.open("x", encoding="utf-8") as stream:
            json.dump(value, stream, indent=2, sort_keys=True)
            stream.write("\n")
            stream.flush()
            os.fsync(stream.fileno())
        os.link(temporary, path)
    finally:
        try:
            temporary.unlink()
        except FileNotFoundError:
            pass


def write_exclusive_text(path: Path, value: str) -> None:
    with open_exclusive_text_0600(path) as stream:
        stream.write(value)


def append_jsonl(path: Path, value: Any) -> None:
    with path.open("a", encoding="utf-8") as stream:
        stream.write(json.dumps(value, sort_keys=True, separators=(",", ":")))
        stream.write("\n")


def existing_command_sequence(path: Path) -> int:
    maximum = 0
    if path.exists():
        with path.open(encoding="utf-8") as stream:
            for line in stream:
                try:
                    value = json.loads(line)
                except json.JSONDecodeError as error:
                    raise LabError("existing command receipt is malformed") from error
                sequence = value.get("sequence")
                if not isinstance(sequence, int) or sequence <= 0:
                    raise LabError("existing command receipt has an invalid sequence")
                maximum = max(maximum, sequence)
    for candidate in path.parent.glob("command-*.*"):
        match = re.fullmatch(r"command-([0-9]{4,})\.(?:stdout|stderr)", candidate.name)
        if match is not None:
            maximum = max(maximum, int(match.group(1)))
    return maximum


def validate_resource_name(name: str) -> None:
    if not RESOURCE_NAME.fullmatch(name):
        raise LabError(f"resource name is outside the fixed Aster lab namespace: {name}")


def network_specs(values: Iterable[tuple[str, str, str]]) -> list[NetworkSpec]:
    result = [NetworkSpec.from_tuple(value) for value in values]
    for index, left in enumerate(result):
        for right in result[index + 1 :]:
            if left.subnet.overlaps(right.subnet):
                raise LabError(f"fixed lab CIDRs overlap: {left.subnet} and {right.subnet}")
    return result


def labels(ctx: RunContext, role: str) -> list[str]:
    return [
        "--label",
        f"{MANAGED_LABEL}=true",
        "--label",
        f"{RUN_LABEL}={ctx.run_id}",
        "--label",
        f"{ROLE_LABEL}={role}",
    ]


def require_docker() -> str:
    executable = shutil.which("docker")
    if executable is None:
        raise LabError("docker executable is not available")
    return executable


def normalized_architecture(value: Any) -> str:
    if value in {"arm64", "aarch64"}:
        return "arm64"
    if isinstance(value, str):
        return value.lower()
    return ""


def verify_orbstack(ctx: RunContext) -> tuple[str, dict[str, Any]]:
    """Require the intended daemon and return its executable/capabilities."""
    docker = require_docker()
    context = ctx.runner.run([docker, "context", "show"]).stdout.strip()
    if context != "orbstack":
        raise LabError(f"refusing non-OrbStack Docker context: {context!r}")
    ctx.runner.run([docker, "version", "--format", "{{.Server.Version}}"])
    result = ctx.runner.run(
        [
            docker,
            "info",
            "--format",
            '{"architecture":{{json .Architecture}},"cgroup_version":{{json .CgroupVersion}},"cpus":{{json .NCPU}},"memory":{{json .MemTotal}},"kernel_version":{{json .KernelVersion}},"operating_system":{{json .OperatingSystem}},"server_version":{{json .ServerVersion}},"name":{{json .Name}},"warnings":{{json .Warnings}}}',
        ]
    )
    try:
        capabilities = json.loads(result.stdout)
    except json.JSONDecodeError as error:
        raise LabError("Docker returned malformed capability JSON") from error
    if not isinstance(capabilities, dict):
        raise LabError("Docker capability result is not an object")
    architecture = normalized_architecture(capabilities.get("architecture"))
    if architecture != "arm64":
        raise LabError(
            f"this evidence profile requires ARM64 OrbStack, found {capabilities.get('architecture')!r}"
        )
    ctx.daemon_architecture = architecture
    capability_path = ctx.run_dir / "docker-capabilities.json"
    if not capability_path.exists():
        write_exclusive_text(
            capability_path,
            json.dumps(capabilities, indent=2, sort_keys=True) + "\n",
        )
    host_path = ctx.run_dir / "host-environment.json"
    if not host_path.exists():
        write_exclusive_json(
            host_path,
            {
                "schema": SCHEMA,
                "system": platform.system(),
                "release": platform.release(),
                "version": platform.version(),
                "machine": platform.machine(),
                "docker_context": context,
                "docker_server": capabilities,
            },
        )
    return docker, capabilities


def docker_resource_present(ctx: RunContext, kind: str, name: str) -> bool:
    """Determine exact-name presence with a command whose failure is never absence."""
    docker = require_docker()
    if kind == "container":
        arguments = [docker, "container", "ls", "--all", "--format", "{{.Names}}"]
    elif kind == "network":
        arguments = [docker, "network", "ls", "--format", "{{.Name}}"]
    else:
        raise LabError(f"unsupported Docker resource kind: {kind}")
    result = ctx.runner.run(arguments)
    return name in {line.strip() for line in result.stdout.splitlines() if line.strip()}


def resolve_image(
    ctx: RunContext,
    *,
    image: str,
    image_schema: str,
    input_digest: str,
    expected_build_run_id: str | None = None,
) -> str:
    docker = require_docker()
    result = ctx.runner.run(
        [
            docker,
            "image",
            "inspect",
            image,
            "--format",
            '{"id":{{json .Id}},"repo_digests":{{json .RepoDigests}},"labels":{{json .Config.Labels}},"architecture":{{json .Architecture}},"env":{{json .Config.Env}}}',
        ]
    )
    try:
        record = json.loads(result.stdout)
    except json.JSONDecodeError as error:
        raise LabError("Docker returned malformed image identity JSON") from error
    if not isinstance(record, dict):
        raise LabError("Docker image identity is not an object")
    if ctx.daemon_architecture is None:
        raise LabError("image resolution requires a verified Docker daemon architecture")
    if normalized_architecture(record.get("architecture")) != ctx.daemon_architecture:
        raise LabError("lab image architecture differs from the verified Docker daemon")
    image_id = record.get("id")
    if not isinstance(image_id, str) or not re.fullmatch(r"sha256:[0-9a-f]{64}", image_id):
        raise LabError("Docker image has an invalid immutable identifier")
    labels_value = record.get("labels")
    if not isinstance(labels_value, dict):
        raise LabError("lab image has no provenance labels")
    expected_labels = {
        **PINNED_BASE_IMAGE_LABELS,
        MANAGED_LABEL: "true",
        IMAGE_SCHEMA_LABEL: image_schema,
        IMAGE_INPUT_LABEL: input_digest,
        IMAGE_BASE_LABEL: LAB_BASE_IMAGE,
    }
    for key, expected in expected_labels.items():
        if labels_value.get(key) != expected:
            raise LabError(f"lab image provenance label differs: {key}")
    build_run_id = labels_value.get(RUN_LABEL)
    if not isinstance(build_run_id, str) or not RUN_ID.fullmatch(build_run_id):
        raise LabError("lab image has no valid build run identifier")
    if expected_build_run_id is not None and build_run_id != expected_build_run_id:
        raise LabError("lab image build run identifier differs")
    if labels_value != {**expected_labels, RUN_LABEL: build_run_id}:
        raise LabError("lab image provenance label set differs")
    environment = record.get("env")
    if not isinstance(environment, list) or any(
        not isinstance(item, str)
        or len(item.encode("utf-8")) > 4_096
        or "\n" in item
        or "\r" in item
        or "\x00" in item
        or "=" not in item
        for item in environment
    ):
        raise LabError("lab image environment is malformed or exceeds its bound")
    names = [item.split("=", 1)[0] for item in environment]
    if len(set(names)) != len(names):
        raise LabError("lab image environment repeats a variable")
    if image == SELECTED_NAT_IMAGE:
        if environment != SELECTED_NAT_IMAGE_ENVIRONMENT:
            raise LabError("selected NAT image environment differs from its pinned base")
        expected_repo_digests = [
            f"{SELECTED_NAT_LOCAL_REPOSITORY}@{image_id}"
        ]
        if record.get("repo_digests") != expected_repo_digests:
            raise LabError("selected NAT local image repository digest differs")
    write_exclusive_text(
        ctx.run_dir / "image-identity.json",
        json.dumps(record, indent=2, sort_keys=True) + "\n",
    )
    ctx.image_id = image_id
    ctx.image = image
    ctx.image_environment = list(environment)
    return image_id


def resolve_lab_image(
    ctx: RunContext, *, expected_build_run_id: str | None = None
) -> str:
    return resolve_image(
        ctx,
        image=IMAGE,
        image_schema=IMAGE_SCHEMA,
        input_digest=build_input_digest(collect_build_inputs()),
        expected_build_run_id=expected_build_run_id,
    )


def resolve_selected_nat_image(
    ctx: RunContext, *, expected_build_run_id: str | None = None
) -> str:
    return resolve_image(
        ctx,
        image=SELECTED_NAT_IMAGE,
        image_schema=SELECTED_NAT_IMAGE_SCHEMA,
        input_digest=build_input_digest(collect_selected_nat_build_inputs()),
        expected_build_run_id=expected_build_run_id,
    )


def docker_preflight(
    ctx: RunContext,
    *,
    containers: Iterable[str],
    networks: Iterable[NetworkSpec],
    require_image: bool = True,
    selected_nat_image: bool = False,
    require_cgroup_v2: bool = False,
) -> None:
    _, capabilities = verify_orbstack(ctx)
    if require_cgroup_v2 and str(capabilities.get("cgroup_version")) != "2":
        raise LabError("resource evidence requires Docker cgroup v2")
    if require_image:
        if selected_nat_image:
            resolve_selected_nat_image(ctx)
        else:
            resolve_lab_image(ctx)
    for name in containers:
        validate_resource_name(name)
        if docker_resource_present(ctx, "container", name):
            raise LabError(f"container name collision: {name}")
    desired = list(networks)
    for spec in desired:
        if docker_resource_present(ctx, "network", spec.name):
            raise LabError(f"network name collision: {spec.name}")
    preflight_cidrs(ctx, desired)


def preflight_cidrs(ctx: RunContext, desired: Sequence[NetworkSpec]) -> None:
    """Compare desired CIDRs with custom Docker IPAM configurations only."""
    if not desired:
        return
    docker = require_docker()
    listing = ctx.runner.run(
        [docker, "network", "ls", "--quiet", "--filter", "type=custom"]
    )
    for network_id in listing.stdout.split():
        if not re.fullmatch(r"[0-9a-f]{12,64}", network_id):
            raise LabError("Docker returned a malformed custom-network identifier")
        configured = ctx.runner.run(
            [docker, "network", "inspect", network_id, "--format", "{{json .IPAM.Config}}"]
        )
        try:
            records = json.loads(configured.stdout)
        except json.JSONDecodeError as error:
            raise LabError("Docker returned malformed network IPAM JSON") from error
        for record in records or []:
            subnet_text = record.get("Subnet") if isinstance(record, dict) else None
            if not subnet_text:
                continue
            try:
                existing = ipaddress.ip_network(subnet_text)
            except ValueError as error:
                raise LabError(f"Docker returned an invalid network CIDR: {subnet_text}") from error
            for wanted in desired:
                if wanted.subnet.overlaps(existing):
                    raise LabError(
                        f"CIDR collision: {wanted.subnet} overlaps custom network {network_id[:12]} ({existing})"
                    )


def network_create_args(ctx: RunContext, spec: NetworkSpec, role: str) -> list[str]:
    return [
        require_docker(),
        "network",
        "create",
        "--driver",
        "bridge",
        "--internal",
        "--subnet",
        str(spec.subnet),
        "--gateway",
        str(spec.gateway),
        *labels(ctx, role),
        spec.name,
    ]


def confined_run_path(ctx: RunContext, path: Path) -> Path:
    root = ctx.run_dir.resolve()
    resolved = path.resolve()
    if resolved == root or root not in resolved.parents:
        raise LabError(f"container mount escapes its run directory: {resolved}")
    return resolved


def create_output_directory(ctx: RunContext, role: str) -> Path:
    if not re.fullmatch(r"[a-z0-9-]{1,32}", role):
        raise LabError(f"invalid output role: {role}")
    path = ctx.run_dir / "outputs" / role
    path.parent.mkdir(mode=0o700, exist_ok=True)
    path.mkdir(mode=0o700)
    return confined_run_path(ctx, path)


def mount_argument(ctx: RunContext, source: Path, destination: str, *, read_only: bool) -> str:
    resolved = confined_run_path(ctx, source)
    value = str(resolved)
    if "," in value:
        raise LabError("lab mount path cannot contain a comma for Docker --mount")
    if not destination.startswith("/") or "," in destination:
        raise LabError(f"invalid in-container mount destination: {destination}")
    suffix = ",readonly" if read_only else ""
    return f"type=bind,src={value},dst={destination}{suffix}"


def validate_retained_secret_mount_source(source: Path) -> os.stat_result:
    metadata = os.lstat(source)
    if (
        not stat.S_ISREG(metadata.st_mode)
        or stat.S_ISLNK(metadata.st_mode)
        or metadata.st_uid != os.getuid()
        or stat.S_IMODE(metadata.st_mode) != 0o600
        or metadata.st_nlink != 1
        or metadata.st_size <= 0
        or metadata.st_size > SELECTED_NAT_MAX_BUNDLE_BYTES
    ):
        raise LabError(
            f"retained secret mount source is not an exact owner-only file: {source}"
        )
    return metadata


def retained_secret_mount_witness(
    source: Path,
) -> tuple[int, int, int, int, int, int, int, int]:
    """Capture bounded metadata without reading retained credential contents."""
    before = validate_retained_secret_mount_source(source)
    flags = os.O_RDONLY | os.O_NOFOLLOW
    if hasattr(os, "O_CLOEXEC"):
        flags |= os.O_CLOEXEC
    descriptor = os.open(source, flags)
    try:
        opened = os.fstat(descriptor)
        if (
            (opened.st_dev, opened.st_ino) != (before.st_dev, before.st_ino)
            or opened.st_uid != before.st_uid
            or stat.S_IMODE(opened.st_mode) != stat.S_IMODE(before.st_mode)
            or opened.st_nlink != before.st_nlink
            or opened.st_size != before.st_size
            or opened.st_mtime_ns != before.st_mtime_ns
            or opened.st_ctime_ns != before.st_ctime_ns
        ):
            raise LabError("retained secret mount source changed while opening")
        after = os.fstat(descriptor)
        if (
            (after.st_dev, after.st_ino) != (opened.st_dev, opened.st_ino)
            or after.st_uid != opened.st_uid
            or stat.S_IMODE(after.st_mode) != stat.S_IMODE(opened.st_mode)
            or after.st_nlink != opened.st_nlink
            or after.st_size != opened.st_size
            or after.st_mtime_ns != opened.st_mtime_ns
            or after.st_ctime_ns != opened.st_ctime_ns
        ):
            raise LabError("retained secret mount source changed while witnessing")
    finally:
        os.close(descriptor)
    pathname = validate_retained_secret_mount_source(source)
    if (
        (pathname.st_dev, pathname.st_ino) != (opened.st_dev, opened.st_ino)
        or pathname.st_uid != opened.st_uid
        or stat.S_IMODE(pathname.st_mode) != stat.S_IMODE(opened.st_mode)
        or pathname.st_nlink != opened.st_nlink
        or pathname.st_size != opened.st_size
        or pathname.st_mtime_ns != opened.st_mtime_ns
        or pathname.st_ctime_ns != opened.st_ctime_ns
    ):
        raise LabError("retained secret mount pathname changed while witnessing")
    return (
        opened.st_dev,
        opened.st_ino,
        opened.st_uid,
        stat.S_IMODE(opened.st_mode),
        opened.st_nlink,
        opened.st_size,
        opened.st_mtime_ns,
        opened.st_ctime_ns,
    )


def expected_docker_cap_add(capabilities: Sequence[str]) -> list[str] | None:
    """Project reviewed CLI capability names to Docker's exact inspect form."""
    admitted = {"NET_ADMIN", "NET_RAW", "SETGID", "SETUID"}
    seen: set[str] = set()
    for capability in capabilities:
        if capability not in admitted:
            raise LabError(f"unsupported lab capability: {capability}")
        if capability in seen:
            raise LabError(f"duplicate lab capability: {capability}")
        seen.add(capability)
    return sorted(f"CAP_{capability}" for capability in seen) or None


def exact_output_mount_destination(destination: str) -> str:
    if destination not in {"/output", "/output/node-a", "/output/node-b"}:
        raise LabError("output mount destination is outside the exact lab plan")
    return destination


def selected_nat_state_container_path(role: str) -> str:
    if role not in {"node-a", "node-b"}:
        raise LabError("selected NAT state role is invalid")
    return f"/output/{role}"


def container_run_args(
    ctx: RunContext,
    *,
    name: str,
    role: str,
    command: Sequence[str],
    network: str = "none",
    ip: str | None = None,
    detach: bool = False,
    cpus: str = "1",
    memory: str = "1g",
    pids: int = 256,
    capabilities: Sequence[str] = (),
    root_user: bool = False,
    entrypoint: str | None = None,
    sysctls: Sequence[str] = (),
    extra_hosts: Sequence[tuple[str, str]] = (),
    output_dir: Path | None = None,
    output_destination: str = "/output",
    read_only_mounts: Sequence[tuple[Path, str]] = (),
    retained_secret_mounts: Sequence[tuple[Path, str]] = (),
) -> list[str]:
    validate_resource_name(name)
    if not MEMORY_VALUE.fullmatch(memory):
        raise LabError(f"invalid memory limit: {memory}")
    if not CPU_VALUE.fullmatch(cpus) or float(cpus) <= 0:
        raise LabError(f"invalid CPU limit: {cpus}")
    expected_docker_cap_add(capabilities)
    args = [
        require_docker(),
        "run",
        "--pull=never",
        "--name",
        name,
        *labels(ctx, role),
    ]
    if detach:
        args.append("--detach")
    args.extend(
        [
            "--init",
            "--read-only",
            "--cap-drop=ALL",
            "--security-opt=no-new-privileges",
            "--cgroupns=private",
            "--cpus",
            cpus,
            "--memory",
            memory,
            "--memory-swap",
            memory,
            "--pids-limit",
            str(pids),
            "--ulimit",
            "nofile=65536:65536",
            "--tmpfs",
            "/tmp:rw,nosuid,nodev,noexec,size=32m",
            "--tmpfs",
            "/run:rw,nosuid,nodev,noexec,size=8m",
            "--network",
            network,
        ]
    )
    mount_destinations: set[str] = set()
    if output_dir is not None:
        if output_dir.is_symlink() or not output_dir.is_dir():
            raise LabError(f"output mount source is not a real directory: {output_dir}")
        output_destination = exact_output_mount_destination(output_destination)
        args.extend(
            [
                "--mount",
                mount_argument(
                    ctx, output_dir, output_destination, read_only=False
                ),
            ]
        )
        mount_destinations.add(output_destination)
    elif output_destination != "/output":
        raise LabError("output mount destination requires an output directory")
    for source, destination, read_only in (
        *((source, destination, True) for source, destination in read_only_mounts),
        *((source, destination, False) for source, destination in retained_secret_mounts),
    ):
        if source.is_symlink() or not source.is_file():
            raise LabError(f"file mount source is not a regular file: {source}")
        if not read_only:
            validate_retained_secret_mount_source(source)
        if destination == "/output" or destination.startswith("/output/"):
            raise LabError("file mounts cannot overlap /output")
        if destination in mount_destinations:
            raise LabError(f"duplicate in-container mount destination: {destination}")
        mount_destinations.add(destination)
        args.extend(
            ["--mount", mount_argument(ctx, source, destination, read_only=read_only)]
        )
    if ip is not None:
        ipaddress.ip_address(ip)
        args.extend(["--ip", ip])
    for capability in capabilities:
        args.extend(["--cap-add", capability])
    for sysctl in sysctls:
        if not sysctl.startswith("net.ipv4."):
            raise LabError(f"unsupported lab sysctl: {sysctl}")
        args.extend(["--sysctl", sysctl])
    for host, address in extra_hosts:
        if not re.fullmatch(r"[a-z0-9](?:[a-z0-9.-]{0,251}[a-z0-9])?", host):
            raise LabError(f"invalid extra host name: {host}")
        parsed_address = ipaddress.ip_address(address)
        if parsed_address.version != 4:
            raise LabError("selected lab extra hosts require IPv4 addresses")
        args.extend(["--add-host", f"{host}:{parsed_address}"])
    if not root_user:
        args.extend(["--user", f"{os.getuid()}:{os.getgid()}"])
    if entrypoint is not None:
        if not entrypoint.startswith("/"):
            raise LabError("entrypoint must be an absolute in-image path")
        args.extend(["--entrypoint", entrypoint])
    if ctx.image_id is None or not re.fullmatch(r"sha256:[0-9a-f]{64}", ctx.image_id):
        raise LabError("container execution requires a preflight-resolved immutable image ID")
    args.append(ctx.image_id)
    args.extend(str(value) for value in command)
    return args


def fault_args(args: argparse.Namespace) -> list[str]:
    return [
        "--seed",
        str(args.seed),
        "--mtu",
        str(args.mtu),
        "--bps",
        str(args.bps),
        "--loss-per-mille",
        str(args.loss_per_mille),
        "--reorder-ticks",
        str(args.reorder_ticks),
        "--tick-ms",
        str(args.tick_ms),
    ]


def plan_output(
    label: str,
    resources: Iterable[PlannedResource],
    commands: Any,
    *,
    image: str = IMAGE,
) -> None:
    print(
        json.dumps(
            {
                "schema": SCHEMA,
                "dry_run": True,
                "preview_kind": "structural",
                "label": label,
                "image": image,
                "resources": [resource.as_dict() for resource in resources],
                "commands": commands,
                "note": (
                    "Structural preview only: generated run IDs, immutable image IDs, mounts, "
                    "ownership labels, and preflight-expanded commands exist only under --execute. "
                    "No Docker or filesystem mutation was performed."
                ),
            },
            indent=2,
            sort_keys=True,
        )
    )


def scenario_metrics(
    ctx: RunContext,
    relative: str,
    expected: dict[str, Any] | None = None,
) -> dict[str, Any]:
    path = ctx.run_dir / relative / "metrics.json"
    if not path.is_file():
        raise LabError(f"scenario emitted no metrics: {path}")
    with path.open(encoding="utf-8") as stream:
        metrics = json.load(stream)
    if metrics.get("schema") != "aster-lab-metrics/v1":
        raise LabError("scenario metrics schema mismatch")
    if metrics.get("converged") is not True:
        raise LabError("scenario did not report convergence")
    if expected is not None:
        for key, value in expected.items():
            observed = metrics.get(key)
            if type(observed) is not type(value) or observed != value:
                raise LabError(
                    f"scenario metrics differ for {key}: expected {value!r}, "
                    f"found {observed!r}"
                )
    return metrics


def write_scenario_request(ctx: RunContext, **values: Any) -> None:
    write_exclusive_json(
        ctx.run_dir / "scenario-request.json",
        {"schema": SCHEMA, "operation": ctx.label, **values},
    )


def read_key_value_record(path: Path, prefix: str) -> dict[str, str]:
    if not path.is_file() or path.stat().st_size > 16_384:
        raise LabError(f"missing or oversized evidence record: {path}")
    lines = path.read_text(encoding="utf-8").splitlines()
    if len(lines) != 1:
        raise LabError(f"evidence record must contain exactly one line: {path}")
    fields = lines[0].split("\t")
    if not fields or fields[0] != prefix:
        raise LabError(f"evidence record header mismatch: {path}")
    values: dict[str, str] = {}
    for field in fields[1:]:
        if "=" not in field:
            raise LabError(f"malformed evidence record field: {path}")
        key, value = field.split("=", 1)
        if not key or key in values:
            raise LabError(f"duplicate or empty evidence record field: {path}")
        values[key] = value
    return values


def verify_live_node_metrics(
    ctx: RunContext,
    relative: str,
    *,
    own_identity: str,
    peer_identity: str,
    peer_endpoint: str,
    seed: int,
    items: int,
) -> None:
    expected_total = items * 2
    scenario_metrics(
        ctx,
        relative,
        {
            "scenario": "node-udp",
            "seed": seed,
            "shards": 1,
            "nodes": 1,
            "published_items": items,
            "delivered_items": expected_total,
        },
    )
    live = read_key_value_record(
        ctx.run_dir / relative / "live-metrics.txt", "ASTER_LAB_LIVE_METRICS"
    )
    expected = {
        "version": "1",
        "node": own_identity,
        "peer": peer_identity,
        "carrier": "fixed-udp",
        "local_endpoint": "0.0.0.0:44000",
        "resolved_peer_endpoint": peer_endpoint,
        "durable_reopen": "false",
        "published_this_run": str(items),
        "reused_publications": "0",
        "observed_items": str(expected_total),
        "authenticated": "true",
        "converged": "true",
    }
    for key, value in expected.items():
        if live.get(key) != value:
            raise LabError(
                f"live metrics differ for {relative} {key}: expected {value!r}, "
                f"found {live.get(key)!r}"
            )
    try:
        authenticated_pumps = int(live.get("authenticated_pumps", ""))
    except ValueError as error:
        raise LabError("live metrics authenticated_pumps is not numeric") from error
    if authenticated_pumps <= 0:
        raise LabError("live node reported no authenticated pump")


def exact_resources(label: str, names: Iterable[tuple[str, str]]) -> list[PlannedResource]:
    result = []
    for kind, role in names:
        name = FIXED_CONTAINER_NAMES[role] if kind == "container" else role
        validate_resource_name(name)
        result.append(PlannedResource(kind, name, role))
    return result


def collect_build_inputs() -> list[BuildInput]:
    """Read the complete, deny-all build context into an immutable in-memory set."""
    root_ignore = WORKSPACE / ".dockerignore"
    dockerfile_ignore = WORKSPACE / "lab" / "Dockerfile.dockerignore"
    for path in [root_ignore, dockerfile_ignore]:
        try:
            value = path.read_text(encoding="utf-8")
        except OSError as error:
            raise LabError(f"required deny-all Docker ignore file is unavailable: {path}") from error
        if value != EXPECTED_DOCKERIGNORE:
            raise LabError(f"deny-all Docker ignore policy differs from the reviewed form: {path}")
    dockerfile_text = (WORKSPACE / "lab" / "Dockerfile").read_text(encoding="utf-8")
    expected_base_line = f"ARG LAB_BASE_IMAGE={LAB_BASE_IMAGE}\n"
    if not dockerfile_text.startswith(expected_base_line):
        raise LabError("Dockerfile pinned base differs from the controller allowlist")
    from_sources = [
        line.split()[1]
        for line in dockerfile_text.splitlines()
        if line.strip().upper().startswith("FROM ") and len(line.split()) >= 2
    ]
    if not from_sources or any(source != "${LAB_BASE_IMAGE}" for source in from_sources):
        raise LabError("Dockerfile contains a base outside the single pinned build argument")
    # Hidden directories are always rejected below. These reviewed vendored
    # metadata files are the only hidden regular files admitted from source
    # trees.
    allowed_hidden_files = {
        ".cargo_vcs_info.json",
        ".gitignore",
        ".licenserc.yaml",
        ".rustfmt.toml",
    }
    admitted_files = [
        root_ignore,
        WORKSPACE / "Cargo.toml",
        WORKSPACE / "Cargo.lock",
        WORKSPACE / "LICENSE",
        WORKSPACE / "THIRD_PARTY_NOTICES.md",
        WORKSPACE / "lab" / "Dockerfile",
        dockerfile_ignore,
        WORKSPACE / "lab" / "debian.sources",
    ]
    for tree_name in ["crates", "third-party"]:
        tree = WORKSPACE / tree_name
        if not tree.is_dir() or tree.is_symlink():
            raise LabError(f"{tree_name} build input is missing or is a symbolic link")
        for directory, names, files in os.walk(tree, followlinks=False):
            names.sort()
            files.sort()
            directory_path = Path(directory)
            relative_directory = directory_path.relative_to(tree)
            if directory_path.is_symlink() or any(
                part.startswith(".") for part in relative_directory.parts
            ):
                raise LabError(
                    f"prohibited or symbolic build input directory: {directory_path}"
                )
            for name in [*names, *files]:
                path = directory_path / name
                if (
                    (name.startswith(".") and name not in allowed_hidden_files)
                    or path.is_symlink()
                ):
                    raise LabError(f"prohibited or symbolic build input: {path}")
            admitted_files.extend(directory_path / name for name in files)
    inputs = []
    seen = set()
    for path in sorted(admitted_files):
        if not path.is_file() or path.is_symlink():
            raise LabError(f"admitted build input is not a regular file: {path}")
        relative = str(path.relative_to(WORKSPACE))
        if relative in seen:
            raise LabError(f"duplicate admitted build path: {relative}")
        seen.add(relative)
        content = path.read_bytes()
        inputs.append(BuildInput(relative, content, hashlib.sha256(content).hexdigest()))
    return inputs


def collect_selected_nat_build_inputs() -> list[BuildInput]:
    """Bind the selected-NAT Dockerfile in addition to the admitted Rust tree."""
    inputs = collect_build_inputs()
    path = SELECTED_NAT_DOCKERFILE
    if path.is_symlink() or not path.is_file():
        raise LabError("selected-NAT Dockerfile is missing or symbolic")
    text_value = path.read_text(encoding="utf-8")
    expected_base_line = f"ARG LAB_BASE_IMAGE={LAB_BASE_IMAGE}\n"
    if not text_value.startswith(expected_base_line):
        raise LabError("selected-NAT Dockerfile pinned base differs from the controller allowlist")
    from_sources = [
        line.split()[1]
        for line in text_value.splitlines()
        if line.strip().upper().startswith("FROM ") and len(line.split()) >= 2
    ]
    if not from_sources or any(source != "${LAB_BASE_IMAGE}" for source in from_sources):
        raise LabError("selected-NAT Dockerfile contains an unpinned base")
    selected_paths = [path]
    known = {item.relative_path for item in inputs}
    for selected_path in selected_paths:
        if not selected_path.is_file() or selected_path.is_symlink():
            raise LabError("selected-NAT admitted input is not a regular file")
        relative = str(selected_path.relative_to(WORKSPACE))
        if relative in known:
            raise LabError("selected-NAT input is duplicated in the admitted input set")
        known.add(relative)
        content = selected_path.read_bytes()
        inputs.append(BuildInput(relative, content, hashlib.sha256(content).hexdigest()))
    inputs.sort(key=lambda item: item.relative_path)
    if len(inputs) + 1 > SELECTED_NAT_MAX_COMMITTED_INPUTS:
        # The independent reviewer additionally admits one requirements document.
        raise LabError("selected NAT committed input count exceeds its review bound")
    return inputs


def build_input_digest(inputs: Sequence[BuildInput]) -> str:
    receipt = {
        "dockerignore_sha256": sha256_text(EXPECTED_DOCKERIGNORE),
        "files": [item.receipt() for item in inputs],
    }
    encoded = json.dumps(receipt, sort_keys=True, separators=(",", ":"))
    return sha256_text(encoded)


def canonical_runtime_package_inventory(value: str) -> str:
    """Validate and canonicalize the exact admitted runtime utility versions."""
    expected = {
        "ca-certificates",
        "iproute2",
        "iputils-ping",
        "nftables",
        "procps",
        "tcpdump",
    }
    versions: dict[str, str] = {}
    for line in value.splitlines():
        fields = line.split("\t")
        if len(fields) != 2 or not fields[0] or not fields[1]:
            raise LabError("runtime package inventory contains a malformed row")
        name, version = fields
        if name not in expected:
            raise LabError(f"runtime package inventory contains an unadmitted package: {name}")
        if name in versions:
            raise LabError(f"runtime package inventory repeats package: {name}")
        if any(character.isspace() for character in version):
            raise LabError(f"runtime package inventory contains malformed version: {name}")
        versions[name] = version
    missing = expected.difference(versions)
    if missing:
        raise LabError(
            "runtime package inventory is missing admitted packages: "
            + ", ".join(sorted(missing))
        )
    return "".join(f"{name}\t{versions[name]}\n" for name in sorted(versions))


def seal_build_context(ctx: RunContext, inputs: Sequence[BuildInput]) -> Path:
    destination = ctx.run_dir / "build-context"
    destination.mkdir(mode=0o700)
    for item in inputs:
        target = destination / item.relative_path
        confined_run_path(ctx, target)
        target.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        with target.open("xb") as stream:
            stream.write(item.content)
        if hashlib.sha256(target.read_bytes()).hexdigest() != item.sha256:
            raise LabError(f"sealed build input verification failed: {item.relative_path}")
    return destination


def verify_build_boundary(ctx: RunContext) -> tuple[Path, str]:
    """Seal exactly the bytes described by the build-input receipt."""
    inputs = collect_build_inputs()
    digest = build_input_digest(inputs)
    write_exclusive_json(
        ctx.run_dir / "build-inputs.json",
        {
            "schema": SCHEMA,
            "dockerignore_sha256": sha256_text(EXPECTED_DOCKERIGNORE),
            "aggregate_sha256": digest,
            "files": [item.receipt() for item in inputs],
        },
    )
    sealed = seal_build_context(ctx, inputs)
    ctx.event("build-boundary-verified", files=len(inputs), aggregate_sha256=digest)
    return sealed, digest


def verify_selected_nat_build_boundary(ctx: RunContext) -> tuple[Path, str]:
    """Seal the selected-NAT Dockerfile and every recursively admitted input."""
    inputs = collect_selected_nat_build_inputs()
    digest = build_input_digest(inputs)
    write_exclusive_json(
        ctx.run_dir / "build-inputs.json",
        {
            "schema": SCHEMA,
            "dockerignore_sha256": sha256_text(EXPECTED_DOCKERIGNORE),
            "aggregate_sha256": digest,
            "files": [item.receipt() for item in inputs],
        },
    )
    sealed = seal_build_context(ctx, inputs)
    ctx.event(
        "selected-nat-build-boundary-verified",
        files=len(inputs),
        aggregate_sha256=digest,
    )
    return sealed, digest


def selected_nat_orbstack_version(ctx: RunContext) -> str:
    executable = shutil.which("orbctl")
    if executable is None:
        raise LabError("orbctl is required to bind the OrbStack version")
    result = ctx.runner.run([executable, "version"])
    match = re.search(r"^Version: ([0-9A-Za-z][0-9A-Za-z.+_-]{0,63})(?: |$)", result.stdout, re.MULTILINE)
    if match is None:
        raise LabError("orbctl returned a malformed version receipt")
    return match.group(1)


def selected_nat_build_arguments(
    ctx: RunContext, sealed_context: Path, input_digest: str
) -> list[str]:
    if not re.fullmatch(r"[0-9a-f]{64}", input_digest):
        raise LabError("selected NAT build input digest is malformed")
    return [
        "docker",
        "build",
        "--pull=false",
        "--network=default",
        "--no-cache",
        "--load",
        "--progress=plain",
        "--file",
        str(sealed_context / "lab" / "Dockerfile.selected-nat"),
        "--tag",
        SELECTED_NAT_IMAGE,
        "--label",
        f"{MANAGED_LABEL}=true",
        "--label",
        f"{RUN_LABEL}={ctx.run_id}",
        "--label",
        f"{IMAGE_SCHEMA_LABEL}={SELECTED_NAT_IMAGE_SCHEMA}",
        "--label",
        f"{IMAGE_INPUT_LABEL}={input_digest}",
        "--label",
        f"{IMAGE_BASE_LABEL}={LAB_BASE_IMAGE}",
        "--build-arg",
        f"LAB_BASE_IMAGE={LAB_BASE_IMAGE}",
        "--iidfile",
        str(ctx.run_dir / "image-id.txt"),
        "--metadata-file",
        str(ctx.run_dir / "build-metadata.json"),
        str(sealed_context),
    ]


def run_selected_nat_build(ctx: RunContext, args: argparse.Namespace) -> dict[str, Any]:
    """Build the selected image from the suite's exact sealed context."""
    if not args.allow_build_network:
        raise LabError(
            "selected NAT execution requires explicit --allow-build-network "
            "for the no-cache dependency build"
        )
    source_identity = selected_nat_source_identity(ctx)
    sealed_context, input_digest = verify_selected_nat_build_boundary(ctx)
    git = shutil.which("git")
    if git is None:
        raise LabError("git disappeared while binding selected NAT build provenance")
    validate_selected_nat_source_still_clean(
        ctx, git, source_identity["commit"]
    )
    dockerfile_sha256 = sha256_file(
        sealed_context / "lab" / "Dockerfile.selected-nat"
    )
    if (
        source_identity["build_input_manifest_sha256"] != input_digest
        or source_identity["dockerfile_sha256"] != dockerfile_sha256
    ):
        raise LabError("selected NAT source changed while sealing the build context")
    docker, capabilities = verify_orbstack(ctx)
    base = ctx.runner.run(
        [
            docker,
            "image",
            "inspect",
            LAB_BASE_IMAGE,
            "--format",
            '{"id":{{json .Id}},"digests":{{json .RepoDigests}}}',
        ],
        check=False,
    )
    if base.returncode != 0:
        raise LabError(
            "pinned base image is not local; refusing implicit base acquisition: "
            + LAB_BASE_IMAGE
        )
    write_exclusive_text(ctx.run_dir / "base-image-identity.json", base.stdout)
    command = selected_nat_build_arguments(ctx, sealed_context, input_digest)
    command_record = {
        "schema": SCHEMA,
        "arguments": command,
        "command": shlex.join(command),
        "network": "default",
        "no_cache": True,
        "pull": False,
        "input_manifest_sha256": input_digest,
        "dockerfile_sha256": dockerfile_sha256,
        "build_run_id": ctx.run_id,
        "status": "planned",
    }
    write_exclusive_json(ctx.run_dir / "selected-build-command.json", command_record)
    ctx.runner.run(command, timeout=args.build_timeout)
    image_id = resolve_selected_nat_image(
        ctx, expected_build_run_id=ctx.run_id
    )
    iid_path = ctx.run_dir / "image-id.txt"
    if (
        iid_path.is_symlink()
        or not iid_path.is_file()
        or iid_path.read_text(encoding="utf-8").strip() != image_id
    ):
        raise LabError("selected NAT Docker iidfile differs from the inspected image ID")
    metadata_path = ctx.run_dir / "build-metadata.json"
    if metadata_path.is_symlink() or not metadata_path.is_file() or metadata_path.stat().st_size <= 0:
        raise LabError("selected NAT Docker metadata receipt is missing or empty")
    try:
        metadata = json.loads(metadata_path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as error:
        raise LabError("selected NAT Docker metadata receipt is malformed") from error
    if not isinstance(metadata, dict):
        raise LabError("selected NAT Docker metadata receipt is not an object")
    inventory_result = ctx.runner.run(
        [
            docker,
            "run",
            "--rm",
            "--pull=never",
            "--network",
            "none",
            "--read-only",
            "--cap-drop",
            "ALL",
            "--security-opt",
            "no-new-privileges",
            "--user",
            f"{os.getuid()}:{os.getgid()}",
            "--memory",
            "64m",
            "--memory-swap",
            "64m",
            "--cpus",
            "0.25",
            "--pids-limit",
            "32",
            "--cgroupns",
            "private",
            "--label",
            f"{MANAGED_LABEL}=true",
            "--label",
            f"{RUN_LABEL}={ctx.run_id}",
            "--label",
            f"{ROLE_LABEL}=build-inventory",
            "--entrypoint",
            "/bin/cat",
            image_id,
            "/usr/share/aster-lab/runtime-package-inventory.tsv",
        ],
        timeout=120,
    )
    canonical_inventory = canonical_runtime_package_inventory(inventory_result.stdout)
    write_exclusive_text(
        ctx.run_dir / "selected-runtime-package-inventory.tsv", canonical_inventory
    )
    orbstack_version = selected_nat_orbstack_version(ctx)
    environment = {
        "schema": SCHEMA,
        "physical_hosts": 1,
        "isolation": "docker-linux-network-namespaces",
        "host_os": platform.system(),
        "host_arch": normalized_architecture(platform.machine()),
        "kernel": str(capabilities.get("kernel_version", "")),
        "docker_version": str(capabilities.get("server_version", "")),
        "orbstack_version": orbstack_version,
        "build_network": "explicit-default-network-no-cache-not-hermetic",
    }
    if (
        environment["host_os"] != "Darwin"
        or environment["host_arch"] != "arm64"
        or not environment["kernel"]
        or not re.fullmatch(r"[0-9A-Za-z][0-9A-Za-z.+_-]{0,63}", environment["docker_version"])
    ):
        raise LabError("selected NAT host environment is outside the exact receipt profile")
    write_exclusive_json(ctx.run_dir / "selected-environment.json", environment)
    result = {
        **command_record,
        "status": "pass",
        "image_id": image_id,
        "image_config_digest": image_id,
        "runtime_packages": len(canonical_inventory.splitlines()),
        "runtime_package_inventory_sha256": sha256_text(canonical_inventory),
        "environment": environment,
    }
    write_exclusive_json(ctx.run_dir / "selected-build.json", result)
    ctx.event(
        "selected-nat-build-complete",
        image=SELECTED_NAT_IMAGE,
        image_id=image_id,
        network="default",
        no_cache=True,
    )
    return result


def run_build(args: argparse.Namespace) -> None:
    resources: list[PlannedResource] = []
    network_mode = "default" if args.allow_build_network else "none"
    cache_options = ["--no-cache"] if args.allow_build_network else []
    command_preview = [
        "docker",
        "build",
        "--pull=false",
        f"--network={network_mode}",
        *cache_options,
        "--load",
        "--file",
        str(DOCKERFILE),
        "--tag",
        IMAGE,
        str(WORKSPACE),
    ]
    if not args.execute:
        plan_output("build", resources, [command_preview])
        return
    ctx = RunContext.create(args.evidence_root, "build", resources)
    sealed_context, input_digest = verify_build_boundary(ctx)
    docker, _ = verify_orbstack(ctx)
    images = ctx.runner.run(
        [docker, "image", "ls", "--no-trunc", "--format", "{{.Repository}}:{{.Tag}}"]
    )
    if IMAGE in {line.strip() for line in images.stdout.splitlines()} and not args.replace_image:
        raise LabError(f"image tag {IMAGE} already exists; pass --replace-image intentionally")
    base = ctx.runner.run(
        [
            docker,
            "image",
            "inspect",
            LAB_BASE_IMAGE,
            "--format",
            '{"id":{{json .Id}},"digests":{{json .RepoDigests}}}',
        ],
        check=False,
    )
    if base.returncode != 0:
        raise LabError(
            "pinned base image is not local; refusing a build that could fetch it: "
            + LAB_BASE_IMAGE
        )
    write_exclusive_text(ctx.run_dir / "base-image-identity.json", base.stdout)
    command = [
        docker,
        "build",
        "--pull=false",
        f"--network={network_mode}",
        *cache_options,
        "--load",
        "--progress=plain",
        "--file",
        str(sealed_context / "lab" / "Dockerfile"),
        "--tag",
        IMAGE,
        "--label",
        f"{MANAGED_LABEL}=true",
        "--label",
        f"{RUN_LABEL}={ctx.run_id}",
        "--label",
        f"{IMAGE_SCHEMA_LABEL}={IMAGE_SCHEMA}",
        "--label",
        f"{IMAGE_INPUT_LABEL}={input_digest}",
        "--label",
        f"{IMAGE_BASE_LABEL}={LAB_BASE_IMAGE}",
        "--build-arg",
        f"LAB_BASE_IMAGE={LAB_BASE_IMAGE}",
        "--iidfile",
        str(ctx.run_dir / "image-id.txt"),
        "--metadata-file",
        str(ctx.run_dir / "build-metadata.json"),
        str(sealed_context),
    ]
    ctx.runner.run(command, timeout=args.timeout)
    image_id = resolve_lab_image(ctx, expected_build_run_id=ctx.run_id)
    iid_path = ctx.run_dir / "image-id.txt"
    if not iid_path.is_file() or iid_path.read_text(encoding="utf-8").strip() != image_id:
        raise LabError("Docker iidfile does not match the inspected immutable image ID")
    inventory = ctx.runner.run(
        [
            docker,
            "run",
            "--rm",
            "--network",
            "none",
            "--read-only",
            "--cap-drop",
            "ALL",
            "--security-opt",
            "no-new-privileges",
            "--label",
            f"{MANAGED_LABEL}=true",
            "--label",
            f"{RUN_LABEL}={ctx.run_id}",
            "--entrypoint",
            "/bin/cat",
            image_id,
            "/usr/share/aster-lab/runtime-package-inventory.tsv",
        ]
    )
    canonical_inventory = canonical_runtime_package_inventory(inventory.stdout)
    write_exclusive_text(
        ctx.run_dir / "runtime-package-inventory.tsv", canonical_inventory
    )
    ctx.event(
        "runtime-package-inventory-captured",
        sha256=sha256_text(canonical_inventory),
        packages=6,
    )
    ctx.event("build-complete", image=IMAGE, image_id=image_id, network=network_mode)
    print(ctx.run_dir)


def run_self_contained(args: argparse.Namespace) -> None:
    role = "transfer" if args.scenario == "transfer" else "blob"
    if args.scenario == "blob-recovery" and args.restart_after_frames == 0:
        raise LabError("Blob recovery requires a positive restart checkpoint")
    name = FIXED_CONTAINER_NAMES[role]
    resources = [PlannedResource("container", name, role)]
    command = [args.scenario, "--root", "/output/run", *fault_args(args)]
    if args.scenario == "transfer":
        command.extend(
            [
                "--items",
                str(args.items),
                "--payload-bytes",
                str(args.payload_bytes),
                "--restart-after-frames",
                str(args.restart_after_frames),
                "--max-pumps",
                str(args.max_pumps),
            ]
        )
    else:
        command.extend(
            [
                "--blob-bytes",
                str(args.blob_bytes),
                "--chunk-bytes",
                str(args.chunk_bytes),
                "--restart-after-frames",
                str(args.restart_after_frames),
                "--max-pumps",
                str(args.max_pumps),
            ]
        )
    if not args.execute:
        plan_output(
            role,
            resources,
            [
                {
                    "docker_run": command,
                    "security": "--pull=never, network=none, read-only, cap-drop=ALL",
                }
            ],
        )
        return
    ctx = RunContext.create(args.evidence_root, role, resources)
    docker_preflight(ctx, containers=[name], networks=[])
    write_scenario_request(
        ctx,
        scenario=args.scenario,
        seed=args.seed,
        items=args.items if args.scenario == "transfer" else None,
        payload_bytes=args.payload_bytes if args.scenario == "transfer" else None,
        blob_bytes=args.blob_bytes if args.scenario == "blob-recovery" else None,
        chunk_bytes=args.chunk_bytes if args.scenario == "blob-recovery" else None,
        restart_after_frames=args.restart_after_frames,
        max_pumps=args.max_pumps,
        mtu=args.mtu,
        bits_per_second=args.bps,
        loss_per_mille=args.loss_per_mille,
        reorder_ticks=args.reorder_ticks,
        tick_ms=args.tick_ms,
    )
    verified = False
    try:
        output_dir = create_output_directory(ctx, role)
        completed = ctx.runner.run(
            container_run_args(
                ctx,
                name=name,
                role=role,
                command=command,
                cpus=args.cpus,
                memory=args.memory,
                pids=512,
                output_dir=output_dir,
            ),
            check=False,
            timeout=args.timeout,
        )
        ctx.event("container-run-complete", name=name, returncode=completed.returncode)
        if completed.returncode != 0:
            raise LabError(f"{args.scenario} container failed with {completed.returncode}")
        verify_container_configuration(
            ctx,
            name,
            output_dir=output_dir,
            memory=args.memory,
            cpus=args.cpus,
            pids=512,
            network="none",
        )
        expected = {
            "scenario": args.scenario,
            "seed": args.seed,
            "shards": 1,
            "nodes": 2 if args.scenario == "transfer" else 3,
            "published_items": args.items if args.scenario == "transfer" else 1,
            "delivered_items": args.items if args.scenario == "transfer" else 2,
            "blob_bytes": 0 if args.scenario == "transfer" else args.blob_bytes,
            "configured_bits_per_second": args.bps,
            "configured_loss_per_mille": args.loss_per_mille,
            "loss_window_frames": 1_000,
        }
        if args.scenario == "blob-recovery":
            expected["partial_restart_observed"] = True
            expected["durable_progress_preserved"] = True
        metrics = scenario_metrics(ctx, f"outputs/{role}/run", expected)
        if args.scenario == "blob-recovery":
            partial_bytes = metrics.get("partial_durable_blob_bytes")
            reopened_bytes = metrics.get("reopened_durable_blob_bytes")
            if (
                type(partial_bytes) is not int
                or type(reopened_bytes) is not int
                or partial_bytes <= 0
                or reopened_bytes < partial_bytes
            ):
                raise LabError(
                    "Blob recovery did not preserve measured durable partial bytes across reopen"
                )
        ctx.event("scenario-verified", scenario=args.scenario)
        verified = True
    finally:
        cleanup_context(ctx, tolerate_errors=not verified)
    print(ctx.run_dir)


def create_network(ctx: RunContext, spec: NetworkSpec, role: str) -> None:
    ctx.runner.run(network_create_args(ctx, spec, role))
    ctx.event("resource-created", kind="network", name=spec.name, role=role)


def parse_provision_manifest(path: Path, expected: int) -> list[dict[str, str]]:
    if not path.is_file():
        raise LabError("provisioning manifest is missing")
    lines = path.read_text(encoding="utf-8").splitlines()
    if not lines or not lines[0].startswith("ASTER_LAB_NODE_MANIFEST\t"):
        raise LabError("provisioning manifest header mismatch")
    header = {}
    for field in lines[0].split("\t")[1:]:
        if "=" not in field:
            raise LabError("malformed provisioning manifest header")
        key, value = field.split("=", 1)
        if key in header:
            raise LabError("duplicate provisioning manifest header field")
        header[key] = value
    if (
        header.get("version") != "1"
        or header.get("topic") != "lab.live-ip"
        or header.get("scope") != "lab/live-ip"
        or header.get("nodes") != str(expected)
    ):
        raise LabError("provisioning manifest parameters mismatch")
    if len(lines) < 2 or lines[1] != "index\tserial\tnode_id":
        raise LabError("provisioning manifest column header mismatch")
    records = []
    for expected_index, line in enumerate(lines[2:]):
        fields = line.split("\t")
        if (
            len(fields) != 3
            or fields[0] != str(expected_index)
            or not fields[1].isdigit()
            or int(fields[1]) <= 0
            or not re.fullmatch(r"[0-9a-f]{64}", fields[2])
        ):
            raise LabError("malformed provisioning manifest record")
        records.append(
            {"index": fields[0], "serial": fields[1], "identity": fields[2]}
        )
    if len(records) != expected:
        raise LabError(f"expected {expected} provisioned nodes, found {len(records)}")
    return records


def wait_for_containers(ctx: RunContext, names: Sequence[str], timeout: float) -> None:
    deadline = time.monotonic() + timeout
    pending = set(names)
    while pending:
        if time.monotonic() >= deadline:
            raise LabError(f"container timeout: {', '.join(sorted(pending))}")
        for name in list(pending):
            state = ctx.runner.run(
                [require_docker(), "container", "inspect", name, "--format", "{{json .State}}"]
            )
            try:
                decoded = json.loads(state.stdout)
            except json.JSONDecodeError as error:
                raise LabError("Docker returned malformed container state") from error
            if not decoded.get("Running", False):
                pending.remove(name)
        if pending:
            time.sleep(1.0)


def verify_container_exit(ctx: RunContext, name: str) -> None:
    state = ctx.runner.run(
        [require_docker(), "container", "inspect", name, "--format", "{{json .State}}"]
    )
    decoded = json.loads(state.stdout)
    if decoded.get("ExitCode") != 0:
        logs = ctx.runner.run([require_docker(), "container", "logs", name], check=False)
        raise LabError(
            f"container {name} exited {decoded.get('ExitCode')}: "
            f"{(logs.stderr or logs.stdout).strip()}"
        )
    logs = ctx.runner.run([require_docker(), "container", "logs", name])
    write_exclusive_text(ctx.run_dir / f"{name}.log", logs.stdout + logs.stderr)


def run_two_node(args: argparse.Namespace) -> None:
    spec = NetworkSpec.from_tuple(DIRECT_SPEC)
    names = [
        FIXED_CONTAINER_NAMES["provision"],
        FIXED_CONTAINER_NAMES["node-a"],
        FIXED_CONTAINER_NAMES["node-b"],
    ]
    resources = [
        PlannedResource("network", spec.name, "direct"),
        PlannedResource("container", names[0], "provision"),
        PlannedResource("container", names[1], "node-a"),
        PlannedResource("container", names[2], "node-b"),
    ]
    if not args.execute:
        plan_output(
            "two-node",
            resources,
            [
                "create one internal bridge at 10.250.10.0/24",
                "provision two identities in an offline container",
                "run two unprivileged node-udp containers at .10 and .11",
                "require both metrics records to report authenticated convergence",
            ],
        )
        return
    ctx = RunContext.create(args.evidence_root, "two-node", resources)
    docker_preflight(ctx, containers=names, networks=[spec])
    write_scenario_request(
        ctx,
        scenario="two-node-live-udp",
        workload_seed=args.seed,
        items_per_node=args.items,
        expected_items_per_node=args.items * 2,
        payload_bytes=args.payload_bytes,
        duration_ms=args.duration_ms,
        max_pumps=args.max_pumps,
        responder_settle_ms=args.responder_settle_ms,
    )
    verified = False
    try:
        create_network(ctx, spec, "direct")
        provision_output = create_output_directory(ctx, "provision")
        provision = container_run_args(
            ctx,
            name=names[0],
            role="provision",
            command=[
                "provision",
                "--root",
                "/output",
                "--nodes",
                "2",
                "--scope",
                "lab/live-ip",
                "--topic",
                "lab.live-ip",
            ],
            memory="1g",
            output_dir=provision_output,
        )
        ctx.runner.run(provision, timeout=120)
        verify_container_configuration(
            ctx,
            names[0],
            output_dir=provision_output,
            memory="1g",
            cpus="1",
            pids=256,
            network="none",
        )
        records = parse_provision_manifest(provision_output / "manifest.tsv", 2)
        if records[0]["identity"] == records[1]["identity"]:
            raise LabError("provisioner emitted duplicate node identities")
        scenario_metrics(
            ctx,
            "outputs/provision",
            {"scenario": "provision", "shards": 1, "nodes": 2},
        )
        bundle_a = provision_output / "private" / "node-0000.bundle"
        bundle_b = provision_output / "private" / "node-0001.bundle"
        private_dir = provision_output / "private"
        if private_dir.is_symlink() or not private_dir.is_dir():
            raise LabError("provisioning private directory is missing or symbolic")
        if private_dir.stat().st_mode & 0o777 != 0o700:
            raise LabError("provisioning private directory mode is not 0700")
        for bundle in [bundle_a, bundle_b]:
            if bundle.is_symlink() or not bundle.is_file():
                raise LabError(f"provisioning bundle is missing or symbolic: {bundle}")
            if bundle.resolve().parent != private_dir.resolve():
                raise LabError(f"provisioning bundle escapes its private directory: {bundle}")
            if bundle.stat().st_mode & 0o777 != 0o600:
                raise LabError(f"provisioning bundle mode is not 0600: {bundle}")
        node_a_output = create_output_directory(ctx, "node-a")
        node_b_output = create_output_directory(ctx, "node-b")
        common = [
            "--seed",
            str(args.seed),
            "--duration-ms",
            str(args.duration_ms),
            "--max-pumps",
            str(args.max_pumps),
            "--payload-bytes",
            str(args.payload_bytes),
            "--expect-items",
            str(args.items * 2),
        ]
        node_a = container_run_args(
            ctx,
            name=names[1],
            role="node-a",
            detach=True,
            network=spec.name,
            ip="10.250.10.10",
            memory=args.memory,
            cpus=args.cpus,
            command=[
                "node-udp",
                "--root",
                "/output",
                "--bundle",
                "/run/secrets/node.bundle",
                "--bind",
                "0.0.0.0:44000",
                "--peer-id",
                records[1]["identity"],
                "--peer-address",
                "10.250.10.11:44000",
                "--publish-items",
                str(args.items),
                *common,
            ],
            output_dir=node_a_output,
            read_only_mounts=[(bundle_a, "/run/secrets/node.bundle")],
        )
        node_b = container_run_args(
            ctx,
            name=names[2],
            role="node-b",
            detach=True,
            network=spec.name,
            ip="10.250.10.11",
            memory=args.memory,
            cpus=args.cpus,
            command=[
                "node-udp",
                "--root",
                "/output",
                "--bundle",
                "/run/secrets/node.bundle",
                "--bind",
                "0.0.0.0:44000",
                "--peer-id",
                records[0]["identity"],
                "--peer-address",
                "10.250.10.10:44000",
                "--publish-items",
                str(args.items),
                *common,
            ],
            output_dir=node_b_output,
            read_only_mounts=[(bundle_b, "/run/secrets/node.bundle")],
        )
        commands = [(records[0]["identity"], node_a), (records[1]["identity"], node_b)]
        # MeshService assigns the lexicographically higher NodeID the responder
        # role; start it first so it is listening when the initiator emits flight 1.
        commands.sort(key=lambda value: value[0], reverse=True)
        ctx.runner.run(commands[0][1])
        time.sleep(args.responder_settle_ms / 1000)
        ctx.event("responder-settled", milliseconds=args.responder_settle_ms)
        ctx.runner.run(commands[1][1])
        verify_container_configuration(
            ctx,
            names[1],
            output_dir=node_a_output,
            memory=args.memory,
            cpus=args.cpus,
            pids=256,
            network=spec.name,
            read_only_mounts=[(bundle_a, "/run/secrets/node.bundle")],
        )
        verify_container_configuration(
            ctx,
            names[2],
            output_dir=node_b_output,
            memory=args.memory,
            cpus=args.cpus,
            pids=256,
            network=spec.name,
            read_only_mounts=[(bundle_b, "/run/secrets/node.bundle")],
        )
        wait_for_containers(ctx, names[1:], args.duration_ms / 1000 + 30)
        for name in names[1:]:
            verify_container_exit(ctx, name)
        verify_live_node_metrics(
            ctx,
            "outputs/node-a",
            own_identity=records[0]["identity"],
            peer_identity=records[1]["identity"],
            peer_endpoint="10.250.10.11:44000",
            seed=args.seed,
            items=args.items,
        )
        verify_live_node_metrics(
            ctx,
            "outputs/node-b",
            own_identity=records[1]["identity"],
            peer_identity=records[0]["identity"],
            peer_endpoint="10.250.10.10:44000",
            seed=args.seed,
            items=args.items,
        )
        ctx.event("scenario-verified", scenario="two-node-live-udp")
        verified = True
    finally:
        cleanup_context(ctx, tolerate_errors=not verified)
    print(ctx.run_dir)


CGROUP_FILES = [
    "/sys/fs/cgroup/memory.current",
    "/sys/fs/cgroup/memory.max",
    "/sys/fs/cgroup/memory.peak",
    "/sys/fs/cgroup/memory.events",
    "/sys/fs/cgroup/memory.stat",
    "/sys/fs/cgroup/memory.swap.current",
    "/sys/fs/cgroup/memory.swap.max",
    "/sys/fs/cgroup/cpu.stat",
    "/sys/fs/cgroup/io.stat",
    "/sys/fs/cgroup/pids.current",
    "/sys/fs/cgroup/pids.events",
]

# Pressure Stall Information is a Linux kernel/configuration capability, not a
# cgroups-v2 invariant. OrbStack may expose the cpu controller and cpu.stat
# without exposing cpu.pressure inside a private container cgroup. Preserve an
# explicit availability marker and the failed read receipt, but do not discard
# the mandatory memory-limit/OOM/CPU/accounting evidence when PSI is absent.
OPTIONAL_CGROUP_FILES = ["/sys/fs/cgroup/cpu.pressure"]


def parse_nonnegative_integer(value: Any, label: str) -> int:
    if not isinstance(value, str) or not re.fullmatch(r"[0-9]+", value.strip()):
        raise LabError(f"resource sample {label} is not a nonnegative integer")
    return int(value.strip())


def parse_counter_file(value: Any, label: str) -> dict[str, int]:
    if not isinstance(value, str) or not value.strip():
        raise LabError(f"resource sample {label} is empty")
    counters: dict[str, int] = {}
    for line in value.splitlines():
        fields = line.split()
        if len(fields) != 2 or fields[0] in counters or not fields[1].isdigit():
            raise LabError(f"resource sample {label} is malformed")
        counters[fields[0]] = int(fields[1])
    return counters


def parse_io_stat(value: Any) -> list[dict[str, int | str]]:
    if not isinstance(value, str) or not value.strip():
        raise LabError("resource sample io.stat is empty")
    records: list[dict[str, int | str]] = []
    for line in value.splitlines():
        fields = line.split()
        if not fields or not re.fullmatch(r"[0-9]+:[0-9]+", fields[0]):
            raise LabError("resource sample io.stat has a malformed device")
        record: dict[str, int | str] = {"device": fields[0]}
        for field in fields[1:]:
            if "=" not in field:
                raise LabError("resource sample io.stat has a malformed counter")
            key, counter = field.split("=", 1)
            if not key or key in record or not counter.isdigit():
                raise LabError("resource sample io.stat has a malformed counter")
            record[key] = int(counter)
        if len(record) == 1:
            raise LabError("resource sample io.stat has no counters")
        records.append(record)
    return records


def validate_resource_sample(
    sample: dict[str, Any], expected_memory_bytes: int, *, require_process: bool = True
) -> None:
    for key in ["memory.current", "memory.peak", "pids.current"]:
        parse_nonnegative_integer(sample.get(key), key)
    if parse_nonnegative_integer(sample.get("memory.max"), "memory.max") != expected_memory_bytes:
        raise LabError("cgroup memory.max differs from the requested Docker limit")
    parse_nonnegative_integer(sample.get("memory.swap.current"), "memory.swap.current")
    if parse_nonnegative_integer(sample.get("memory.swap.max"), "memory.swap.max") != 0:
        raise LabError("resource cgroup unexpectedly permits swap")
    memory_events = parse_counter_file(sample.get("memory.events"), "memory.events")
    for key in ["oom", "oom_kill"]:
        if key not in memory_events:
            raise LabError(f"memory.events is missing {key}")
        if memory_events[key] != 0:
            raise LabError(f"resource cgroup reports {key}={memory_events[key]}")
    parse_counter_file(sample.get("memory.stat"), "memory.stat")
    parse_counter_file(sample.get("cpu.stat"), "cpu.stat")
    parse_counter_file(sample.get("pids.events"), "pids.events")
    pressure_available = sample.get("cpu.pressure_available")
    if not isinstance(pressure_available, bool):
        raise LabError("cpu.pressure availability marker is missing")
    pressure = sample.get("cpu.pressure")
    if pressure_available:
        if not isinstance(pressure, str) or "some " not in pressure or "total=" not in pressure:
            raise LabError("available cpu.pressure has malformed pressure counters")
    elif pressure is not None:
        raise LabError("unavailable cpu.pressure unexpectedly contains counters")
    parse_io_stat(sample.get("io.stat"))
    if require_process:
        for key in ["smaps_rollup", "status"]:
            value = sample.get(key)
            if not isinstance(value, str) or not value.strip():
                raise LabError(f"process {key} evidence is missing")
    stats = sample.get("docker_stats")
    if not isinstance(stats, dict) or not stats:
        raise LabError("Docker stats evidence is missing or malformed")


def docker_memory_bytes(value: str) -> int:
    match = re.fullmatch(r"([1-9][0-9]*)([kmgt]?)(?:b)?", value.lower())
    if match is None:
        raise LabError(f"cannot convert Docker memory value: {value}")
    powers = {"": 0, "k": 1, "m": 2, "g": 3, "t": 4}
    return int(match.group(1)) * (1024 ** powers[match.group(2)])


def validate_container_tmpfs(host: dict[str, Any], name: str) -> None:
    if host.get("Init") is not True:
        raise LabError(f"container {name} lacks the exact init boundary")
    if host.get("Ulimits") != [
        {"Name": "nofile", "Hard": 65_536, "Soft": 65_536}
    ]:
        raise LabError(f"container {name} nofile boundary differs")
    tmpfs = host.get("Tmpfs")
    if not isinstance(tmpfs, dict) or set(tmpfs) != {"/tmp", "/run"}:
        raise LabError(f"container {name} tmpfs destinations differ")
    for destination, expected_size in (("/tmp", 32 * 1024 * 1024), ("/run", 8 * 1024 * 1024)):
        raw_options = tmpfs.get(destination)
        if not isinstance(raw_options, str):
            raise LabError(f"container {name} tmpfs options are malformed")
        options = raw_options.split(",")
        size_options = [value for value in options if value.startswith("size=")]
        flags = {value for value in options if not value.startswith("size=")}
        if (
            len(options) != len(set(options))
            or flags != {"rw", "nosuid", "nodev", "noexec"}
            or len(size_options) != 1
            or docker_memory_bytes(size_options[0].split("=", 1)[1]) != expected_size
        ):
            raise LabError(f"container {name} tmpfs confinement differs")


def validate_container_host_isolation(host: dict[str, Any], name: str) -> None:
    """Bind Docker's security-relevant defaults that the fixed argv leaves closed."""
    expected = {
        "Devices": [],
        "DeviceRequests": None,
        "DeviceCgroupRules": None,
        "PidMode": "",
        "IpcMode": "private",
        "UTSMode": "",
        "UsernsMode": "",
        "PortBindings": {},
        "PublishAllPorts": False,
        "AutoRemove": False,
        "RestartPolicy": {"Name": "no", "MaximumRetryCount": 0},
        "Links": None,
        "VolumesFrom": None,
    }
    for field, expected_value in expected.items():
        if host.get(field) != expected_value:
            raise LabError(
                f"container {name} host-isolation field {field} differs"
            )


def verify_container_configuration(
    ctx: RunContext,
    name: str,
    *,
    output_dir: Path | None,
    output_destination: str = "/output",
    memory: str,
    cpus: str,
    pids: int,
    network: str,
    capabilities: Sequence[str] = (),
    read_only_mounts: Sequence[tuple[Path, str]] = (),
    retained_secret_mounts: Sequence[tuple[Path, str]] = (),
    root_user: bool = False,
    sysctls: dict[str, str] | None = None,
    extra_hosts: Sequence[tuple[str, str]] = (),
    network_aliases: Sequence[str] = (),
    network_addresses: dict[str, str] | None = None,
    entrypoint: str = "/usr/local/bin/aster-lab",
    receipt_name: str | None = None,
) -> None:
    result = ctx.runner.run(
        [require_docker(), "container", "inspect", name, "--format", "{{json .}}"]
    )
    try:
        value = json.loads(result.stdout)
    except json.JSONDecodeError as error:
        raise LabError("Docker returned malformed container configuration JSON") from error
    if not isinstance(value, dict):
        raise LabError("Docker container configuration is not an object")
    host = value.get("HostConfig")
    config = value.get("Config")
    mounts = value.get("Mounts")
    if not isinstance(host, dict) or not isinstance(config, dict) or not isinstance(mounts, list):
        raise LabError("Docker container configuration is incomplete")
    if ctx.image_environment is None or config.get("Env") != ctx.image_environment:
        raise LabError(f"container {name} environment differs from its immutable image")
    validate_container_tmpfs(host, name)
    validate_container_host_isolation(host, name)
    if config.get("ExposedPorts") is not None or config.get("Volumes") is not None:
        raise LabError(f"container {name} image exposes an unexpected port or volume")
    expected_user = "" if root_user else f"{os.getuid()}:{os.getgid()}"
    checks = {
        "immutable image": (value.get("Image"), ctx.image_id),
        "not privileged": (host.get("Privileged"), False),
        "read-only root": (host.get("ReadonlyRootfs"), True),
        "memory": (host.get("Memory"), docker_memory_bytes(memory)),
        "memory swap": (host.get("MemorySwap"), docker_memory_bytes(memory)),
        "pids": (host.get("PidsLimit"), pids),
        "CPU": (host.get("NanoCpus"), int(float(cpus) * 1_000_000_000)),
        "cgroup namespace": (host.get("CgroupnsMode"), "private"),
        "user": (config.get("User"), expected_user),
        "entrypoint": (config.get("Entrypoint"), [entrypoint]),
    }
    for label, (observed, expected) in checks.items():
        if observed != expected:
            raise LabError(
                f"container {name} {label} differs: expected {expected!r}, found {observed!r}"
            )
    expected_networks = {network, *network_aliases}
    if host.get("NetworkMode") not in expected_networks:
        raise LabError(
            f"container {name} network differs: expected one of "
            f"{sorted(expected_networks)!r}, found {host.get('NetworkMode')!r}"
        )
    expected_cap_add = expected_docker_cap_add(capabilities)
    if (
        host.get("CapDrop") != ["ALL"]
        or "CapAdd" not in host
        or host["CapAdd"] != expected_cap_add
    ):
        raise LabError(f"container {name} capability configuration differs")
    security = [str(item) for item in host.get("SecurityOpt") or []]
    if len(security) != 1 or security[0] not in {
        "no-new-privileges",
        "no-new-privileges:true",
    }:
        raise LabError(
            f"container {name} lacks the exact enabled no-new-privileges option"
        )
    if {str(key): str(value) for key, value in (host.get("Sysctls") or {}).items()} != (
        sysctls or {}
    ):
        raise LabError(f"container {name} sysctl configuration differs")
    expected_extra_hosts = [f"{host_name}:{address}" for host_name, address in extra_hosts]
    if list(host.get("ExtraHosts") or []) != expected_extra_hosts:
        raise LabError(f"container {name} extra-host configuration differs")
    role = name.removeprefix(PREFIX)
    if not role or name != f"{PREFIX}{role}":
        raise LabError(f"container {name} is outside the exact lab role namespace")
    selected_image = ctx.image == SELECTED_NAT_IMAGE
    expected_image_labels = {
        **PINNED_BASE_IMAGE_LABELS,
        MANAGED_LABEL: "true",
        RUN_LABEL: ctx.run_id,
        ROLE_LABEL: role,
        IMAGE_SCHEMA_LABEL: (
            SELECTED_NAT_IMAGE_SCHEMA if selected_image else IMAGE_SCHEMA
        ),
        IMAGE_INPUT_LABEL: build_input_digest(
            collect_selected_nat_build_inputs()
            if selected_image
            else collect_build_inputs()
        ),
        IMAGE_BASE_LABEL: LAB_BASE_IMAGE,
    }
    if config.get("Labels") != expected_image_labels:
        raise LabError(f"container {name} image/runtime provenance labels differ")
    if output_dir is not None:
        output_destination = exact_output_mount_destination(output_destination)
        expected_mounts = {
            output_destination: (str(confined_run_path(ctx, output_dir)), True)
        }
    else:
        if output_destination != "/output":
            raise LabError("output mount destination requires an output directory")
        expected_mounts = {}
    for source, destination, read_write in (
        *((source, destination, False) for source, destination in read_only_mounts),
        *((source, destination, True) for source, destination in retained_secret_mounts),
    ):
        if destination in expected_mounts:
            raise LabError(f"duplicate expected bind mount destination: {destination}")
        if read_write:
            validate_retained_secret_mount_source(source)
        expected_mounts[destination] = (
            str(confined_run_path(ctx, source)),
            read_write,
        )
    observed_mounts: dict[str, tuple[str, bool]] = {}
    for mount in mounts:
        if not isinstance(mount, dict) or mount.get("Type") != "bind":
            raise LabError(f"container {name} has a non-bind mount")
        destination = mount.get("Destination")
        if not isinstance(destination, str) or destination in observed_mounts:
            raise LabError(f"container {name} has an invalid or duplicate mount")
        if type(mount.get("RW")) is not bool:
            raise LabError(f"container {name} mount access mode is missing")
        observed_mounts[destination] = (
            str(mount.get("Source")),
            mount["RW"],
        )
    if observed_mounts != expected_mounts:
        raise LabError(f"container {name} bind mounts differ from the isolated mount plan")
    if network_addresses is not None:
        network_settings = value.get("NetworkSettings")
        networks = (
            network_settings.get("Networks")
            if isinstance(network_settings, dict)
            else None
        )
        if not isinstance(networks, dict):
            raise LabError(f"container {name} network attachment receipt is missing")
        observed_addresses = {
            str(network_name): network.get("IPAddress")
            for network_name, network in networks.items()
            if isinstance(network, dict)
        }
        if len(observed_addresses) != len(networks) or observed_addresses != network_addresses:
            raise LabError(f"container {name} network attachments differ from the exact plan")
    target_name = receipt_name or f"{name}-configuration.json"
    if not re.fullmatch(r"[A-Za-z0-9_.-]{1,128}\.json", target_name):
        raise LabError("container configuration receipt name is invalid")
    write_exclusive_json(ctx.run_dir / target_name, value)


def resource_sample(
    ctx: RunContext, name: str, expected_memory_bytes: int
) -> dict[str, Any]:
    docker = require_docker()
    sample: dict[str, Any] = {"utc": utc_now(), "monotonic_ns": time.monotonic_ns()}
    stats = ctx.runner.run(
        [docker, "stats", "--no-stream", "--format", "{{json .}}", name], check=False
    )
    if stats.returncode != 0 or not stats.stdout.strip():
        raise LabError("Docker stats failed during mandatory resource sampling")
    try:
        sample["docker_stats"] = json.loads(stats.stdout)
    except json.JSONDecodeError as error:
        raise LabError("Docker stats returned malformed JSON") from error
    for path in CGROUP_FILES:
        result = ctx.runner.run([docker, "exec", name, "/usr/bin/cat", path], check=False)
        if result.returncode != 0:
            raise LabError(f"mandatory cgroup read failed: {path}")
        sample[path.rsplit("/", 1)[-1]] = result.stdout.strip()
    for path in OPTIONAL_CGROUP_FILES:
        result = ctx.runner.run([docker, "exec", name, "/usr/bin/cat", path], check=False)
        key = path.rsplit("/", 1)[-1]
        available = result.returncode == 0
        sample[f"{key}_available"] = available
        sample[key] = result.stdout.strip() if available else None
    process = ctx.runner.run(
        [docker, "exec", name, "/usr/bin/pgrep", "--oldest", "--exact", "aster-lab"],
        check=False,
    )
    if process.returncode not in {0, 1}:
        raise LabError("aster-lab process state probe failed")
    process_id = process.stdout.strip() if process.returncode == 0 else ""
    process_observed = bool(re.fullmatch(r"[1-9][0-9]*", process_id))
    if process.returncode == 0 and not process_observed:
        raise LabError("aster-lab process state probe returned a malformed PID")
    if process_observed:
        sample["process_pid"] = int(process_id)
        for path in [f"/proc/{process_id}/smaps_rollup", f"/proc/{process_id}/status"]:
            result = ctx.runner.run([docker, "exec", name, "/usr/bin/cat", path], check=False)
            if result.returncode != 0:
                # The workload may have exited between pgrep and this read. The
                # already captured cgroup counters remain a valid terminal sample.
                sample.pop("smaps_rollup", None)
                sample.pop("status", None)
                sample.pop("process_pid", None)
                process_observed = False
                break
            sample[path.rsplit("/", 1)[-1]] = result.stdout
    sample["process_observed"] = process_observed
    sample["phase"] = "running" if process_observed else "terminal-cgroup"
    validate_resource_sample(
        sample, expected_memory_bytes, require_process=process_observed
    )
    append_jsonl(ctx.run_dir / "resource-samples.jsonl", sample)
    return sample


def run_resource(args: argparse.Namespace) -> None:
    name = FIXED_CONTAINER_NAMES["resource"]
    resources = [PlannedResource("container", name, "resource")]
    command = [
        "scale",
        "--root",
        "/output/run",
        "--nodes",
        "1",
        "--shards",
        "1",
        "--items",
        str(args.items),
        "--payload-bytes",
        str(args.payload_bytes),
        "--max-pumps",
        str(args.max_pumps),
        *fault_args(args),
    ]
    if not args.execute:
        plan_output(
            "resource",
            resources,
            [
                {
                    "container_pid1": ["/usr/bin/sleep", "infinity"],
                    "foreground_receipted_exec": command,
                    "limits": {"cpus": args.cpus, "memory": args.memory, "swap": args.memory},
                    "capture": CGROUP_FILES
                    + OPTIONAL_CGROUP_FILES
                    + ["/proc/<oldest-exact-aster-lab-pid>/smaps_rollup", "/proc/<pid>/status"],
                }
            ],
        )
        return
    ctx = RunContext.create(args.evidence_root, "resource", resources)
    docker_preflight(ctx, containers=[name], networks=[], require_cgroup_v2=True)
    write_scenario_request(
        ctx,
        scenario="scale-resource",
        seed=args.seed,
        nodes=1,
        shards=1,
        items=args.items,
        payload_bytes=args.payload_bytes,
        max_pumps=args.max_pumps,
        mtu=args.mtu,
        bits_per_second=args.bps,
        loss_per_mille=args.loss_per_mille,
        reorder_ticks=args.reorder_ticks,
        tick_ms=args.tick_ms,
        cpus=args.cpus,
        memory=args.memory,
    )
    verified = False
    try:
        output_dir = create_output_directory(ctx, "resource")
        ctx.runner.run(
            container_run_args(
                ctx,
                name=name,
                role="resource",
                command=["infinity"],
                detach=True,
                cpus=args.cpus,
                memory=args.memory,
                pids=128,
                output_dir=output_dir,
                entrypoint="/usr/bin/sleep",
            )
        )
        verify_container_configuration(
            ctx,
            name,
            output_dir=output_dir,
            memory=args.memory,
            cpus=args.cpus,
            pids=128,
            network="none",
            entrypoint="/usr/bin/sleep",
        )
        workload = ctx.runner.start(
            [
                require_docker(),
                "exec",
                name,
                "/usr/local/bin/aster-lab",
                *command,
            ]
        )
        try:
            deadline = time.monotonic() + args.timeout
            startup_deadline = min(deadline, time.monotonic() + 10.0)
            while workload.poll() is None:
                process = ctx.runner.run(
                    [
                        require_docker(),
                        "exec",
                        name,
                        "/usr/bin/pgrep",
                        "--oldest",
                        "--exact",
                        "aster-lab",
                    ],
                    check=False,
                )
                if process.returncode == 0:
                    break
                if process.returncode != 1:
                    raise LabError("resource workload process state probe failed")
                if time.monotonic() >= startup_deadline:
                    raise LabError("resource workload did not become observable")
                time.sleep(0.05)
            if workload.poll() is not None:
                workload.finish(check=True)
                raise LabError("resource workload ended before its process became observable")

            samples = 0
            expected_memory_bytes = docker_memory_bytes(args.memory)
            while workload.poll() is None:
                sample = resource_sample(ctx, name, expected_memory_bytes)
                if sample["process_observed"] is True:
                    samples += 1
                    sleep_interval = args.sample_interval
                else:
                    sleep_interval = min(args.sample_interval, 0.05)
                if time.monotonic() >= deadline:
                    workload.terminate()
                    raise LabError("resource scenario timed out")
                time.sleep(sleep_interval)
            returncode = workload.finish(check=False)
            terminal_sample = resource_sample(ctx, name, expected_memory_bytes)
            if terminal_sample["process_observed"] is not False:
                raise LabError("terminal cgroup snapshot still observed the workload process")
            if returncode != 0:
                stderr = (ctx.run_dir / workload.stderr_name).read_text(
                    encoding="utf-8", errors="replace"
                ).strip()
                raise LabError(
                    f"resource workload failed with {returncode}"
                    + (f": {stderr}" if stderr else "")
                )
        finally:
            if not workload.finished:
                workload.terminate()
        scenario_metrics(
            ctx,
            "outputs/resource/run",
            {
                "scenario": "scale",
                "seed": args.seed,
                "shards": 1,
                "nodes": 1,
                "published_items": args.items,
                "delivered_items": args.items,
                "configured_bits_per_second": args.bps,
                "configured_loss_per_mille": args.loss_per_mille,
                "loss_window_frames": 1_000,
            },
        )
        if samples == 0:
            raise LabError("resource scenario ended before process RSS was captured")
        ctx.event(
            "resource-capture-verified",
            running_samples=samples,
            terminal_cgroup_samples=1,
        )
        verified = True
    finally:
        cleanup_context(ctx, tolerate_errors=not verified)
    print(ctx.run_dir)


def interface_for_address(ctx: RunContext, container: str, address: str) -> str:
    result = ctx.runner.run(
        [require_docker(), "exec", container, "/usr/sbin/ip", "-j", "-4", "address", "show"]
    )
    try:
        interfaces = json.loads(result.stdout)
    except json.JSONDecodeError as error:
        raise LabError("ip returned malformed interface JSON") from error
    for interface in interfaces:
        for record in interface.get("addr_info", []):
            if record.get("local") == address:
                name = interface.get("ifname")
                if isinstance(name, str) and re.fullmatch(r"[A-Za-z0-9_.-]{1,32}", name):
                    return name
    raise LabError(f"could not resolve interface for {container} address {address}")


def nft_rules(
    *,
    profile: str,
    lan_if: str,
    wan_if: str,
    lan_subnet: str,
    node_ip: str,
    external_ip: str,
) -> str:
    if profile not in {"cone", "restrictive"}:
        raise LabError(f"unsupported NAT profile: {profile}")
    if profile == "cone":
        forward = f'''\
        iifname "{lan_if}" oifname "{wan_if}" counter accept
        iifname "{wan_if}" oifname "{lan_if}" ip daddr {node_ip} udp dport 44000 counter accept
        ct state established,related counter accept'''
        prerouting = f'''\
        iifname "{wan_if}" ip daddr {external_ip} udp dport 44000 counter dnat to {node_ip}:44000'''
        fixed_snat = f'''\
        oifname "{wan_if}" ip saddr {node_ip} udp sport 44000 counter snat to {external_ip}:44000'''
    else:
        forward = f'''\
        iifname "{lan_if}" oifname "{wan_if}" ip daddr 10.250.0.20 udp dport 4476 counter accept
        iifname "{lan_if}" oifname "{wan_if}" ip daddr 10.250.0.20 tcp dport 4477 counter accept
        iifname "{wan_if}" oifname "{lan_if}" ct state established,related counter accept'''
        prerouting = ""
        fixed_snat = ""
    return f'''flush ruleset
table inet aster_lab_filter {{
    chain forward {{
        type filter hook forward priority filter; policy drop;
{forward}
    }}
}}
table ip aster_lab_nat {{
    chain prerouting {{
        type nat hook prerouting priority dstnat;
{prerouting}
    }}
    chain postrouting {{
        type nat hook postrouting priority srcnat;
{fixed_snat}
        oifname "{wan_if}" ip saddr {lan_subnet} counter masquerade
    }}
}}
'''


SELECTED_NAT_COUNTERS = {
    "cone-direct": {
        "aster_cone_dnat",
        "aster_cone_snat",
        "aster_cone_forward_in",
        "aster_cone_forward_out",
    },
    "restrictive-relay": {
        "aster_restrict_direct_drop",
        "aster_restrict_relay_https",
        "aster_restrict_relay_http",
        "aster_restrict_established",
    },
}


def selected_nat_nft_rules(
    *,
    profile: str,
    lan_if: str,
    wan_if: str,
    lan_subnet: str,
    node_ip: str,
    external_ip: str,
    peer_external_ip: str,
) -> str:
    """Return the exact named-counter rules for one selected-Iroh NAT cell."""
    if profile not in SELECTED_NAT_COUNTERS:
        raise LabError(f"unsupported selected NAT profile: {profile}")
    for interface in [lan_if, wan_if]:
        if not re.fullmatch(r"[A-Za-z0-9_.-]{1,32}", interface):
            raise LabError("selected NAT interface name is invalid")
    subnet = ipaddress.ip_network(lan_subnet)
    addresses = [
        ipaddress.ip_address(value)
        for value in [node_ip, external_ip, peer_external_ip, SELECTED_NAT_RELAY_IP]
    ]
    if subnet.version != 4 or any(address.version != 4 for address in addresses):
        raise LabError("selected NAT rules require IPv4")
    if addresses[0] not in subnet:
        raise LabError("selected NAT node address is outside its LAN")
    if profile == "cone-direct":
        return f'''flush ruleset
table inet aster_selected_filter {{
    counter aster_cone_forward_out {{}}
    counter aster_cone_forward_in {{}}
    chain forward {{
        type filter hook forward priority filter; policy drop;
        iifname "{lan_if}" oifname "{wan_if}" ip saddr {node_ip} ip daddr {peer_external_ip} udp sport {SELECTED_NAT_NODE_PORT} udp dport {SELECTED_NAT_NODE_PORT} counter name aster_cone_forward_out accept
        iifname "{wan_if}" oifname "{lan_if}" ip daddr {node_ip} udp dport {SELECTED_NAT_NODE_PORT} counter name aster_cone_forward_in accept
        ct state established,related accept
    }}
}}
table ip aster_selected_nat {{
    counter aster_cone_dnat {{}}
    counter aster_cone_snat {{}}
    chain prerouting {{
        type nat hook prerouting priority dstnat;
        iifname "{wan_if}" ip daddr {external_ip} udp dport {SELECTED_NAT_NODE_PORT} counter name aster_cone_dnat dnat to {node_ip}:{SELECTED_NAT_NODE_PORT}
    }}
    chain postrouting {{
        type nat hook postrouting priority srcnat;
        oifname "{wan_if}" ip saddr {node_ip} udp sport {SELECTED_NAT_NODE_PORT} counter name aster_cone_snat snat to {external_ip}:{SELECTED_NAT_NODE_PORT}
    }}
}}
'''
    return f'''flush ruleset
table inet aster_selected_filter {{
    counter aster_restrict_direct_drop {{}}
    counter aster_restrict_relay_https {{}}
    counter aster_restrict_relay_http {{}}
    counter aster_restrict_established {{}}
    chain forward {{
        type filter hook forward priority filter; policy drop;
        iifname "{lan_if}" oifname "{wan_if}" ip saddr {node_ip} ip daddr {peer_external_ip} udp dport {SELECTED_NAT_NODE_PORT} counter name aster_restrict_direct_drop drop
        iifname "{lan_if}" oifname "{wan_if}" ip saddr {node_ip} ip daddr {SELECTED_NAT_RELAY_IP} tcp dport {SELECTED_NAT_RELAY_HTTPS_PORT} counter name aster_restrict_relay_https accept
        iifname "{lan_if}" oifname "{wan_if}" ip saddr {node_ip} ip daddr {SELECTED_NAT_RELAY_IP} tcp dport {SELECTED_NAT_RELAY_HTTP_PORT} counter name aster_restrict_relay_http accept
        iifname "{wan_if}" oifname "{lan_if}" ct state established,related counter name aster_restrict_established accept
    }}
}}
table ip aster_selected_nat {{
    chain postrouting {{
        type nat hook postrouting priority srcnat;
        oifname "{wan_if}" ip saddr {lan_subnet} masquerade
    }}
}}
'''


def selected_nat_counter_snapshot(value: str, profile: str) -> dict[str, dict[str, int]]:
    expected = SELECTED_NAT_COUNTERS.get(profile)
    if expected is None:
        raise LabError(f"unsupported selected NAT profile: {profile}")
    try:
        decoded = json.loads(value)
    except json.JSONDecodeError as error:
        raise LabError("selected NAT nft output is malformed") from error
    if not isinstance(decoded, dict) or not isinstance(decoded.get("nftables"), list):
        raise LabError("selected NAT nft output has no nftables list")
    counters: dict[str, dict[str, int]] = {}
    for item in decoded["nftables"]:
        record = item.get("counter") if isinstance(item, dict) else None
        if not isinstance(record, dict) or record.get("name") not in expected:
            continue
        name = record["name"]
        packets = record.get("packets")
        bytes_value = record.get("bytes")
        if (
            name in counters
            or type(packets) is not int
            or type(bytes_value) is not int
            or packets < 0
            or bytes_value < 0
        ):
            raise LabError("selected NAT nft named counter is duplicated or malformed")
        counters[name] = {"packets": packets, "bytes": bytes_value}
    if set(counters) != expected:
        raise LabError("selected NAT nft output differs from the exact named counter set")
    return counters


def selected_nat_counter_delta(
    before: dict[str, dict[str, int]],
    after: dict[str, dict[str, int]],
    profile: str,
) -> dict[str, dict[str, int]]:
    expected = SELECTED_NAT_COUNTERS.get(profile)
    if expected is None or set(before) != expected or set(after) != expected:
        raise LabError("selected NAT counter snapshots differ from the profile")
    result = {}
    for name in sorted(expected):
        packets = after[name]["packets"] - before[name]["packets"]
        bytes_value = after[name]["bytes"] - before[name]["bytes"]
        if packets < 0 or bytes_value < 0:
            raise LabError("selected NAT counter regressed")
        result[name] = {"packets": packets, "bytes": bytes_value}
    required = (
        {"aster_cone_forward_in", "aster_cone_forward_out"}
        if profile == "cone-direct"
        else {
            "aster_restrict_relay_https",
            "aster_restrict_established",
        }
    )
    if any(result[name]["packets"] <= 0 or result[name]["bytes"] <= 0 for name in required):
        raise LabError("selected NAT required named counter did not advance")
    if profile == "restrictive-relay" and result["aster_restrict_relay_http"] != {
        "packets": 0,
        "bytes": 0,
    }:
        raise LabError("selected NAT restrictive HTTP counter unexpectedly advanced")
    return result


def selected_nat_node_arguments(
    *,
    docker: str,
    user: str,
    role: str,
    profile: str,
    node_address: str,
    peer_external_address: str,
    peer_carrier_id: str,
    peer_mission_id: str,
) -> list[str]:
    """Return the fixed selected-NAT node command without consulting ambient state."""
    if role not in {"node-a", "node-b"}:
        raise LabError("selected NAT node command role is invalid")
    if profile not in SELECTED_NAT_COUNTERS:
        raise LabError("selected NAT node command profile is invalid")
    try:
        node_ip = ipaddress.ip_address(node_address)
        peer_ip = ipaddress.ip_address(peer_external_address)
    except ValueError as error:
        raise LabError("selected NAT node command address is invalid") from error
    if node_ip.version != 4 or peer_ip.version != 4:
        raise LabError("selected NAT node command requires IPv4")
    if any(
        not re.fullmatch(r"[0-9a-f]{64}", identity)
        for identity in (peer_carrier_id, peer_mission_id)
    ):
        raise LabError("selected NAT node command peer identity is malformed")
    command = [
        docker,
        "exec",
        "--user",
        user,
        FIXED_CONTAINER_NAMES[role],
        "/usr/local/bin/aster",
        "node",
        "--state",
        selected_nat_state_container_path(role),
        "--bind",
        f"{node_address}:{SELECTED_NAT_NODE_PORT}",
        "--mission-bundle-unprotected-reference",
        "/run/secrets/node.bundle",
        "--peer",
        (
            f"{peer_carrier_id}@{peer_external_address}:{SELECTED_NAT_NODE_PORT}="
            f"{peer_mission_id}"
        ),
        "--sync-ms",
        str(SELECTED_NAT_SYNC_MS),
        "--run-for",
        str(SELECTED_NAT_RUN_FOR_SECONDS),
        "--application",
        "relay",
    ]
    if profile == "restrictive-relay":
        command.extend(
            [
                "--controlled-relay-url",
                f"https://{SELECTED_NAT_RELAY_DNS}:{SELECTED_NAT_RELAY_HTTPS_PORT}/",
                "--controlled-relay-trust",
                "der-roots",
                "--controlled-relay-ca-der",
                "/run/relay/ca.der",
            ]
        )
    return command


def validate_selected_nat_cone_directionality(
    *,
    node_results: dict[str, dict[str, Any]],
    nft_deltas: dict[str, dict[str, dict[str, int]]],
    wan_direction_packets: dict[str, dict[str, int]],
) -> dict[str, str]:
    """Bind cone CONTACT direction to its one active conntrack NAT hook."""
    node_to_router = {"node-a": "nat-a", "node-b": "nat-b"}
    if set(node_results) != set(node_to_router):
        raise LabError("selected NAT cone node result set differs")
    if set(nft_deltas) != set(node_to_router.values()):
        raise LabError("selected NAT cone nft router set differs")
    if set(wan_direction_packets) != set(node_to_router.values()):
        raise LabError("selected NAT cone WAN direction set differs")

    directions: dict[str, str] = {}
    carrier_ids: dict[str, str] = {}
    for node in node_to_router:
        ready = node_results[node].get("ready")
        carrier_id = ready.get("carrier_id") if isinstance(ready, dict) else None
        if not isinstance(carrier_id, str) or re.fullmatch(
            r"[0-9a-f]{64}", carrier_id
        ) is None:
            raise LabError("selected NAT cone READY carrier identity is malformed")
        carrier_ids[node] = carrier_id
        contacts = node_results[node].get("contacts")
        if (
            not isinstance(contacts, list)
            or not contacts
            or any(not isinstance(contact, dict) for contact in contacts)
        ):
            raise LabError("selected NAT cone node has no CONTACT direction evidence")
        observed = {contact.get("direction") for contact in contacts}
        if len(observed) != 1 or observed - {"in", "out"}:
            raise LabError("selected NAT cone node CONTACT directions are not homogeneous")
        directions[node] = observed.pop()
    if set(directions.values()) != {"in", "out"}:
        raise LabError("selected NAT cone requires one initiator and one responder")
    if len(set(carrier_ids.values())) != len(carrier_ids):
        raise LabError("selected NAT cone READY carrier identities are not distinct")

    initiator = next(node for node, direction in directions.items() if direction == "out")
    responder = next(node for node, direction in directions.items() if direction == "in")
    expected_initiator = min(carrier_ids, key=carrier_ids.__getitem__)
    if initiator != expected_initiator:
        raise LabError(
            "selected NAT cone CONTACT initiator is not the lower carrier identity"
        )
    for node, direction in directions.items():
        router = node_to_router[node]
        counters = nft_deltas[router]
        directional = wan_direction_packets[router]
        if set(directional) != {"inbound", "outbound"} or any(
            type(packets) is not int or packets < 0
            for packets in directional.values()
        ):
            raise LabError("selected NAT cone WAN direction evidence is malformed")
        active_name, inactive_name, matching_packets = (
            (
                "aster_cone_snat",
                "aster_cone_dnat",
                directional["outbound"],
            )
            if direction == "out"
            else (
                "aster_cone_dnat",
                "aster_cone_snat",
                directional["inbound"],
            )
        )
        active = counters.get(active_name)
        inactive = counters.get(inactive_name)
        if (
            not isinstance(active, dict)
            or type(active.get("packets")) is not int
            or type(active.get("bytes")) is not int
            or active["packets"] <= 0
            or active["bytes"] <= 0
        ):
            raise LabError("selected NAT cone active conntrack NAT hook did not advance")
        if inactive != {"packets": 0, "bytes": 0}:
            raise LabError("selected NAT cone inactive conntrack NAT hook advanced")
        if active["packets"] > matching_packets:
            raise LabError("selected NAT cone active NAT counter exceeds its WAN direction")
    return {
        "initiator_node": initiator,
        "initiator_router": node_to_router[initiator],
        "responder_node": responder,
        "responder_router": node_to_router[responder],
    }


def parse_receipt_fields(line: str, prefix: str) -> dict[str, str]:
    if not line.startswith(f"{prefix} "):
        raise LabError(f"receipt does not start with {prefix}")
    fields: dict[str, str] = {}
    for token in shlex.split(line)[1:]:
        if "=" not in token:
            raise LabError(f"{prefix} receipt contains an unkeyed token")
        key, value = token.split("=", 1)
        if not re.fullmatch(r"[a-z][a-z0-9_]*", key) or not value or key in fields:
            raise LabError(f"{prefix} receipt contains a malformed or duplicate field")
        fields[key] = value
    return fields


def exact_receipt(text_value: str, prefix: str) -> dict[str, str]:
    matches = [
        parse_receipt_fields(line, prefix)
        for line in text_value.splitlines()
        if line.startswith(f"{prefix} ")
    ]
    if len(matches) != 1:
        raise LabError(f"expected exactly one {prefix} receipt")
    return matches[0]


def require_receipt_keys(
    record: dict[str, str], expected: set[str], prefix: str
) -> None:
    if set(record) != expected:
        raise LabError(f"{prefix} receipt fields differ from the exact contract")


def require_receipt_line_prefixes(text_value: str, expected: Sequence[str]) -> None:
    lines = text_value.splitlines()
    observed = [line.split(" ", 1)[0] for line in lines]
    if (
        not expected
        or observed != list(expected)
        or text_value != "\n".join(lines) + "\n"
    ):
        raise LabError("selected NAT helper output lines differ from the exact contract")


def receipt_nonnegative(fields: dict[str, str], name: str) -> int:
    value = fields.get(name)
    if value is None or not re.fullmatch(r"0|[1-9][0-9]*", value):
        raise LabError(f"receipt field {name} is not a canonical nonnegative integer")
    return int(value)


def receipt_hex(fields: dict[str, str], name: str) -> str:
    value = fields.get(name)
    if value is None or not re.fullmatch(r"[0-9a-f]{64}", value):
        raise LabError(f"receipt field {name} is not lowercase hex64")
    return value


def parse_selected_nat_manifest(
    path: Path, *, scope: str, topic: str
) -> dict[str, Any]:
    if path.is_symlink() or not path.is_file():
        raise LabError("selected NAT public manifest is missing or symbolic")
    lines = path.read_text(encoding="utf-8").splitlines()
    header = lines[0].split("\t") if lines else []
    if (
        len(lines) != 4
        or len(header) != 7
        or header[:4]
        != [
            "ASTER_SELECTED_NAT_MANIFEST",
            "version=2",
            f"scope={scope}",
            f"topic={topic}",
        ]
        or not header[4].startswith("mission_authority=")
        or not header[5].startswith("canary_sha256=")
        or header[6] != "nodes=2"
    ):
        raise LabError("selected NAT manifest header or row count differs")
    mission_authority = header[4].removeprefix("mission_authority=")
    canary_sha256 = header[5].removeprefix("canary_sha256=")
    if not re.fullmatch(r"[0-9a-f]{64}", mission_authority):
        raise LabError("selected NAT manifest mission authority is malformed")
    if not re.fullmatch(r"[0-9a-f]{64}", canary_sha256):
        raise LabError("selected NAT manifest canary digest is malformed")
    if lines[1] != "name\tmission_id\tcarrier_id\tsubscription_id":
        raise LabError("selected NAT manifest columns differ")
    records: dict[str, dict[str, str]] = {}
    for expected_name, line in zip(("a", "b"), lines[2:]):
        fields = line.split("\t")
        if len(fields) != 4 or fields[0] != expected_name or fields[0] in records:
            raise LabError("selected NAT manifest node row is malformed")
        name, mission_id, carrier_id, subscription_id = fields
        if not re.fullmatch(r"[0-9a-f]{64}", mission_id):
            raise LabError("selected NAT mission ID is malformed")
        if not re.fullmatch(r"[0-9a-f]{64}", carrier_id):
            raise LabError("selected NAT carrier ID is malformed")
        if not re.fullmatch(r"[0-9a-f]{64}", subscription_id):
            raise LabError("selected NAT subscription ID is malformed")
        records[name] = {
            "name": name,
            "mission_id": mission_id,
            "carrier_id": carrier_id,
            "subscription_id": subscription_id,
        }
    if set(records) != {"a", "b"}:
        raise LabError("selected NAT manifest lacks the exact node set")
    public_ids = {
        *(record["mission_id"] for record in records.values()),
        *(record["carrier_id"] for record in records.values()),
    }
    if len(public_ids) != 4:
        raise LabError("selected NAT mission and carrier identities are not globally distinct")
    if mission_authority in public_ids:
        raise LabError("selected NAT mission authority overlaps a node public identity")
    return {
        "mission_authority": mission_authority,
        "canary_sha256": canary_sha256,
        "nodes": records,
    }


def selected_nat_runtime_identity_domain(
    runtime: dict[str, Any], profile: str
) -> tuple[str, frozenset[str]]:
    if runtime.get("profile") != profile:
        raise LabError("selected NAT runtime profile differs from its cell")
    mission_authority = runtime.get("mission_authority")
    if not isinstance(mission_authority, str) or not re.fullmatch(
        r"[0-9a-f]{64}", mission_authority
    ):
        raise LabError("selected NAT runtime mission authority is malformed")
    nodes = runtime.get("nodes")
    if not isinstance(nodes, dict) or set(nodes) != {"a", "b"}:
        raise LabError("selected NAT runtime node set differs")
    public_ids: list[str] = []
    for name in ("a", "b"):
        node = nodes.get(name)
        if not isinstance(node, dict):
            raise LabError("selected NAT runtime node identity is malformed")
        for field in ("mission_id", "carrier_id"):
            value = node.get(field)
            if not isinstance(value, str) or not re.fullmatch(r"[0-9a-f]{64}", value):
                raise LabError(f"selected NAT runtime {field} is malformed")
            public_ids.append(value)
    public_domain = frozenset(public_ids)
    if len(public_domain) != 4:
        raise LabError("selected NAT runtime mission and carrier identities overlap")
    if mission_authority in public_domain:
        raise LabError("selected NAT runtime mission authority overlaps a node public identity")
    return mission_authority, public_domain


def validate_selected_nat_runtime_identity_domains(
    runtimes: Sequence[tuple[str, dict[str, Any]]],
) -> None:
    if not runtimes:
        raise LabError("selected NAT runtime identity-domain set is empty")
    profiles = [profile for profile, _ in runtimes]
    if len(set(profiles)) != len(profiles):
        raise LabError("selected NAT runtime identity-domain profiles are duplicated")
    domains = [
        selected_nat_runtime_identity_domain(runtime, profile)
        for profile, runtime in runtimes
    ]
    authorities = {authority for authority, _ in domains}
    public_ids = {identity for _, domain in domains for identity in domain}
    if len(authorities) != len(domains):
        raise LabError("selected NAT cells reused a mission authority")
    if len(public_ids) != 4 * len(domains):
        raise LabError("selected NAT cells did not use globally fresh identities")
    if authorities & public_ids:
        raise LabError("selected NAT cell authorities overlap a node public identity")


SELECTED_NAT_NOOP_FIELDS = {
    "control_offered",
    "control_fetched",
    "control_retained",
    "control_duplicates",
    "control_activated",
    "control_remaining",
    "offered",
    "fetched",
    "inserted",
    "duplicates",
    "remaining",
    "deferred_event_lanes",
    "mutable_remaining",
    "deferred_mutable_lanes",
    "blob_ranges_fetched",
    "blob_bytes_fetched",
    "blob_remaining",
    "blob_deferred",
}
SELECTED_NAT_READY_FIELDS = {
    "selected",
    "pid",
    "carrier_id",
    "mission_id",
    "mission_authority",
    "sockets",
    "state",
    "peers",
    "application",
    "carrier_route",
    "controlled_relay_url",
    "controlled_relay_trust",
    "controlled_relay_readiness",
    "public_relay_fallback",
    "hosted_discovery",
    "nat_traversal",
    "path_observation",
    "mission_auth",
    "provisioning",
    "semantics",
    "reconciliation_classes",
    "controls",
    "commit_before_activate",
    "content_admission",
}
SELECTED_NAT_CONTACT_FIELDS = {
    "direction",
    "carrier_peer",
    "mission_peer",
    "rounds",
    *SELECTED_NAT_NOOP_FIELDS,
    "handshake_frames",
    "handshake_bytes",
    "protected_frames",
    "protected_bytes",
    "carrier_path",
    "carrier_path_transitions",
    "carrier_path_transitions_saturated",
    "path_observation",
    "mission_auth",
    "semantics",
    "reconciliation_classes",
    "controls",
    "content_admission",
    "status",
}
SELECTED_NAT_STOP_FIELDS = {
    "lifecycle",
    "sync_status",
    "carrier_id",
    "mission_id",
    "contacts",
    "contact_errors",
    "direct_contacts",
    "relay_contacts",
    "unknown_path_contacts",
    "carrier_path_transitions",
    "carrier_path_transition_saturations",
    "path_observation",
    "opaque_items",
    "opaque_acceptance_markers",
    "events",
    "event_acceptance_markers",
    "route_cached_events",
    "controls",
    "applied_controls",
    "pending_controls",
    "control_highwater",
    "blobs",
    "pending_blobs",
    "blob_ranges_fetched",
    "blob_bytes_fetched",
    "blob_remaining",
    "blob_deferred",
    "mission_auth",
    "provisioning",
    "semantics",
    "reconciliation_classes",
    "controls_semantics",
}


def validate_selected_nat_stderr(value: str, role: str) -> None:
    if role not in {"node-a", "node-b"}:
        raise LabError("selected NAT stderr role is invalid")
    if value:
        raise LabError(f"selected NAT {role} wrote unexpected stderr output")


def validate_selected_nat_node_log(
    value: str,
    *,
    profile: str,
    carrier_id: str,
    mission_id: str,
    mission_authority: str,
    bind_ip: str,
    state_path: str | None = None,
) -> dict[str, Any]:
    if state_path is None:
        state_path = {
            "10.250.1.10": "/output/node-a",
            "10.250.2.10": "/output/node-b",
        }.get(bind_ip)
        if state_path is None:
            raise LabError("selected NAT state path cannot be derived from its bind")
    expected_path = "direct" if profile == "cone-direct" else "relay"
    expected_route = "direct" if profile == "cone-direct" else "direct-plus-controlled-relay"
    if any(
        not isinstance(identity, str) or not re.fullmatch(r"[0-9a-f]{64}", identity)
        for identity in (carrier_id, mission_id, mission_authority)
    ):
        raise LabError("selected NAT expected node identity domain is malformed")
    if mission_authority in {carrier_id, mission_id}:
        raise LabError("selected NAT expected mission authority overlaps its node identity")
    if not value.endswith("\n") or "\r" in value or "\x00" in value:
        raise LabError("selected NAT node stdout has a malformed encoding")
    lines = value.splitlines()
    if (
        len(lines) < 3
        or not lines[0].startswith("READY ")
        or not lines[-1].startswith("STOP ")
        or any(
            not line.startswith("CONTACT ") or not line.endswith("status=pass")
            for line in lines[1:-1]
        )
    ):
        raise LabError("selected NAT node stdout receipt order differs")
    ready = exact_receipt(value, "READY")
    stop = exact_receipt(value, "STOP")
    require_receipt_keys(ready, SELECTED_NAT_READY_FIELDS, "READY")
    require_receipt_keys(stop, SELECTED_NAT_STOP_FIELDS, "STOP")
    if (
        ready.get("selected") != "true"
        or ready.get("carrier_id") != carrier_id
        or ready.get("mission_id") != mission_id
        or ready.get("mission_authority") != mission_authority
        or ready.get("state") != state_path
        or ready.get("carrier_route") != expected_route
        or ready.get("controlled_relay_readiness")
        != ("deferred" if profile == "restrictive-relay" else "not-applicable")
        or ready.get("public_relay_fallback") != "false"
        or ready.get("hosted_discovery") != "false"
        or ready.get("nat_traversal") != "not-claimed"
        or ready.get("path_observation") != "not-authorization"
        or ready.get("peers") != "1"
        or ready.get("application") != "relay"
        or ready.get("mission_auth") != "hybrid-pq"
        or ready.get("provisioning") != "unprotected-reference"
        or ready.get("semantics") != "source-authenticated-event"
        or ready.get("reconciliation_classes") != "event,state,record,blob-v5-opt-in"
        or ready.get("controls") != "source-authenticated-flash"
        or ready.get("commit_before_activate") != "true"
        or ready.get("content_admission") != "capability-gated"
        or receipt_nonnegative(ready, "pid") <= 0
    ):
        raise LabError("selected NAT READY receipt differs from the exact profile")
    sockets = ready.get("sockets", "")
    if sockets != f"{bind_ip}:{SELECTED_NAT_NODE_PORT}":
        raise LabError("selected NAT READY receipt differs from the single private bind socket")
    if profile == "restrictive-relay":
        if (
            ready.get("controlled_relay_url")
            != f"https://{SELECTED_NAT_RELAY_DNS}:{SELECTED_NAT_RELAY_HTTPS_PORT}/"
            or ready.get("controlled_relay_trust") != "explicit-der-roots"
        ):
            raise LabError("selected NAT READY receipt lacks exact pinned relay trust")
    elif (
        ready.get("controlled_relay_url") != "none"
        or ready.get("controlled_relay_trust") != "none"
    ):
        raise LabError("cone-direct unexpectedly configured a relay")
    contacts = [
        parse_receipt_fields(line, "CONTACT")
        for line in lines[1:-1]
    ]
    transition_total = 0
    for contact in contacts:
        require_receipt_keys(contact, SELECTED_NAT_CONTACT_FIELDS, "CONTACT")
        if (
            contact.get("direction") not in {"in", "out"}
            or contact.get("carrier_path") != expected_path
            or contact.get("carrier_path_transitions_saturated") != "false"
            or contact.get("path_observation") != "not-authorization"
            or contact.get("mission_auth") != "hybrid-pq"
            or contact.get("semantics") != "source-authenticated-event"
            or contact.get("reconciliation_classes") != "event,state,record,blob"
            or contact.get("controls") != "source-authenticated-flash"
            or contact.get("content_admission") != "capability-gated"
        ):
            raise LabError("selected NAT contact path witness differs")
        rounds = receipt_nonnegative(contact, "rounds")
        handshake_frames = receipt_nonnegative(contact, "handshake_frames")
        handshake_bytes = receipt_nonnegative(contact, "handshake_bytes")
        protected_frames = receipt_nonnegative(contact, "protected_frames")
        protected_bytes = receipt_nonnegative(contact, "protected_bytes")
        if (
            not 1 <= rounds <= 4_096
            or min(
                handshake_frames,
                handshake_bytes,
                protected_frames,
                protected_bytes,
            )
            <= 0
            or handshake_frames != 4
            or protected_frames % 2 != 0
            or 2 * rounds > protected_frames
            or handshake_frames + protected_frames > 8_192
            or handshake_bytes + protected_bytes > 64 * 1024 * 1024
            or handshake_bytes < handshake_frames
            or protected_bytes < protected_frames
        ):
            raise LabError("selected NAT contact transport accounting differs")
        transitions = receipt_nonnegative(contact, "carrier_path_transitions")
        if transitions > SELECTED_NAT_MAX_PATH_TRANSITIONS:
            raise LabError("selected NAT contact path transition bound was exceeded")
        transition_total += transitions
        if transition_total > SELECTED_NAT_MAX_PATH_TRANSITIONS:
            raise LabError("selected NAT aggregate path transition bound was exceeded")
    final_contact = contacts[-1]
    if any(receipt_nonnegative(final_contact, field) != 0 for field in SELECTED_NAT_NOOP_FIELDS):
        raise LabError("selected NAT final contact was not an exact no-op")
    if (
        stop.get("lifecycle") != "complete"
        or stop.get("sync_status") != "contacts_observed"
        or stop.get("carrier_id") != carrier_id
        or stop.get("mission_id") != mission_id
        or receipt_nonnegative(stop, "contacts") <= 0
        or receipt_nonnegative(stop, "contact_errors") != 0
        or receipt_nonnegative(stop, "unknown_path_contacts") != 0
        or receipt_nonnegative(stop, "carrier_path_transition_saturations") != 0
        or stop.get("path_observation") != "not-authorization"
        or stop.get("mission_auth") != "hybrid-pq"
        or stop.get("provisioning") != "unprotected-reference"
        or stop.get("semantics") != "source-authenticated-event"
        or stop.get("reconciliation_classes") != "event,state,record,blob-v5"
        or stop.get("controls_semantics") != "source-authenticated-flash"
    ):
        raise LabError("selected NAT STOP receipt differs")
    terminal_inventory = {
        "opaque_items": 0,
        "opaque_acceptance_markers": 0,
        "events": 1,
        "event_acceptance_markers": 1,
        "route_cached_events": 0,
        "controls": 0,
        "applied_controls": 0,
        "pending_controls": 0,
        "control_highwater": 0,
        "blobs": 0,
        "pending_blobs": 0,
        "blob_ranges_fetched": 0,
        "blob_bytes_fetched": 0,
        "blob_remaining": 0,
        "blob_deferred": 0,
    }
    if any(
        receipt_nonnegative(stop, field) != expected
        for field, expected in terminal_inventory.items()
    ):
        raise LabError("selected NAT STOP terminal Event inventory differs")
    direct = receipt_nonnegative(stop, "direct_contacts")
    relay = receipt_nonnegative(stop, "relay_contacts")
    total = receipt_nonnegative(stop, "contacts")
    stop_transitions = receipt_nonnegative(stop, "carrier_path_transitions")
    if total != len(contacts) or total > 1_024:
        raise LabError("selected NAT STOP contact count differs from its transcript")
    if stop_transitions > SELECTED_NAT_MAX_PATH_TRANSITIONS:
        raise LabError("selected NAT STOP path transition bound was exceeded")
    if stop_transitions != transition_total:
        raise LabError("selected NAT STOP path transitions differ from CONTACT sum")
    if profile == "cone-direct" and (direct != total or relay != 0):
        raise LabError("cone-direct STOP did not witness only direct contacts")
    if profile == "restrictive-relay" and (relay != total or direct != 0):
        raise LabError("restrictive-relay STOP did not witness only relay contacts")
    return {
        "ready": ready,
        "stop": stop,
        "contacts": contacts,
        "path": "Direct" if profile == "cone-direct" else "Relay",
        "transition_count": stop_transitions,
        "saturated": False,
        "final_noop": {field: receipt_nonnegative(final_contact, field) for field in sorted(SELECTED_NAT_NOOP_FIELDS)},
    }


def validate_runtime_privilege_receipt(status_text: str, uid_text: str, gid_text: str) -> dict[str, Any]:
    fields = {}
    for line in status_text.splitlines():
        if ":" in line:
            key, value = line.split(":", 1)
            fields[key] = value.strip()
    for name in ["CapInh", "CapPrm", "CapEff", "CapBnd", "CapAmb"]:
        value = fields.get(name)
        if value is None or not re.fullmatch(r"[0-9a-fA-F]{16}", value) or int(value, 16) != 0:
            raise LabError(f"selected NAT workload retained capability field {name}")
    if fields.get("NoNewPrivs") != "1":
        raise LabError("selected NAT workload lacks no-new-privileges")
    uid = int(uid_text.strip())
    gid = int(gid_text.strip())
    if uid <= 0 or gid <= 0:
        raise LabError("selected NAT workload must run with non-root UID and GID")
    return {
        "uid": uid,
        "gid": gid,
        "no_new_privs": True,
        "cap_inheritable": 0,
        "cap_permitted": 0,
        "cap_effective": 0,
        "cap_bounding": 0,
        "cap_ambient": 0,
    }


def parse_pcap_ipv4_tuples(path: Path) -> dict[str, Any]:
    size = validate_pcap(path)
    if size > 128 * 1024 * 1024:
        raise LabError("selected NAT packet capture exceeds 128 MiB")
    data = path.read_bytes()
    endian_by_magic = {
        bytes.fromhex("d4c3b2a1"): "little",
        bytes.fromhex("a1b2c3d4"): "big",
        bytes.fromhex("4d3cb2a1"): "little",
        bytes.fromhex("a1b23c4d"): "big",
    }
    endian = endian_by_magic[data[:4]]
    link_type = int.from_bytes(data[20:24], endian)
    if link_type != 1:
        raise LabError("selected NAT capture is not Ethernet pcap")
    offset = 24
    packets = 0
    tuples: dict[tuple[str, str, int, int, str], int] = {}
    while offset < len(data):
        if len(data) - offset < 16:
            raise LabError("selected NAT capture has a truncated record header")
        included = int.from_bytes(data[offset + 8 : offset + 12], endian)
        original = int.from_bytes(data[offset + 12 : offset + 16], endian)
        offset += 16
        if included > original or included > 262_144 or offset + included > len(data):
            raise LabError("selected NAT capture has an invalid record length")
        frame = data[offset : offset + included]
        offset += included
        packets += 1
        if len(frame) < 14:
            continue
        network_offset = 14
        ether_type = int.from_bytes(frame[12:14], "big")
        if ether_type == 0x8100 and len(frame) >= 18:
            ether_type = int.from_bytes(frame[16:18], "big")
            network_offset = 18
        if ether_type != 0x0800 or len(frame) < network_offset + 20:
            continue
        version_ihl = frame[network_offset]
        if version_ihl >> 4 != 4:
            continue
        ihl = (version_ihl & 0x0F) * 4
        if ihl < 20 or len(frame) < network_offset + ihl + 4:
            continue
        protocol_number = frame[network_offset + 9]
        protocol = {6: "tcp", 17: "udp"}.get(protocol_number)
        if protocol is None:
            continue
        source = str(ipaddress.ip_address(frame[network_offset + 12 : network_offset + 16]))
        destination = str(ipaddress.ip_address(frame[network_offset + 16 : network_offset + 20]))
        transport = network_offset + ihl
        source_port = int.from_bytes(frame[transport : transport + 2], "big")
        destination_port = int.from_bytes(frame[transport + 2 : transport + 4], "big")
        key = (source, destination, source_port, destination_port, protocol)
        tuples[key] = tuples.get(key, 0) + 1
    if offset != len(data) or packets == 0:
        raise LabError("selected NAT capture is empty or structurally incomplete")
    return {
        "bytes": size,
        "packets": packets,
        "sha256": sha256_file(path),
        "tuples": [
            {
                "source": key[0],
                "destination": key[1],
                "source_port": key[2],
                "destination_port": key[3],
                "protocol": key[4],
                "packets": count,
            }
            for key, count in sorted(tuples.items())
        ],
    }


def pcap_tuple_count(
    summary: dict[str, Any],
    *,
    addresses: set[str],
    port: int,
    protocol: str,
    both_ports: bool = False,
    server_address: str | None = None,
) -> int:
    return sum(
        int(record["packets"])
        for record in summary["tuples"]
        if record["protocol"] == protocol
        and record["source"] in addresses
        and record["destination"] in addresses
        and record["source"] != record["destination"]
        and (
            record["source_port"] == port and record["destination_port"] == port
            if both_ports
            else (
                (
                    record["source"] == server_address
                    and record["source_port"] == port
                )
                or (
                    record["destination"] == server_address
                    and record["destination_port"] == port
                )
                if server_address is not None
                else record["source_port"] == port
                or record["destination_port"] == port
            )
        )
    )


def tcpdump_terminal_counts(value: str) -> dict[str, int]:
    counts: dict[str, int] = {}
    for name, label in (
        ("captured", "packets captured"),
        ("received_by_filter", "packets received by filter"),
        ("dropped", "packets dropped by kernel"),
    ):
        matches = re.findall(
            rf"^(0|[1-9][0-9]*) {re.escape(label)}$",
            value,
            flags=re.MULTILINE,
        )
        if len(matches) != 1:
            raise LabError(f"tcpdump terminal {name} counter is absent or duplicated")
        counts[name] = int(matches[0])
    if counts["captured"] != counts["received_by_filter"]:
        raise LabError("tcpdump captured and received-by-filter counters differ")
    if counts["dropped"] != 0:
        raise LabError("selected NAT tcpdump reported kernel packet drops")
    return counts


def validate_tcpdump_pcap_packet_count(
    summary: dict[str, Any], counts: dict[str, int]
) -> None:
    if summary.get("packets") != counts.get("captured"):
        raise LabError(
            "selected NAT pcap packet count differs from tcpdump captured count"
        )


def validate_selected_nat_tracked_inputs(
    ctx: RunContext, git: str, inputs: Sequence[BuildInput]
) -> None:
    """Require every sealed input, including ignored paths, to be Git tracked."""
    tracked_scope = [
        ".dockerignore",
        "Cargo.toml",
        "Cargo.lock",
        "LICENSE",
        "crates",
        "third-party",
        "lab/Dockerfile",
        "lab/Dockerfile.selected-nat",
        "lab/Dockerfile.dockerignore",
        "lab/debian.sources",
    ]
    result = ctx.runner.run(
        [git, "-C", str(WORKSPACE), "ls-files", "-z", "--", *tracked_scope]
    )
    if not result.stdout or not result.stdout.endswith("\0"):
        raise LabError("git returned a malformed selected NAT tracked-input set")
    tracked_list = result.stdout[:-1].split("\0")
    if any(not value or value.startswith("/") for value in tracked_list):
        raise LabError("git returned a noncanonical selected NAT tracked path")
    tracked = set(tracked_list)
    if len(tracked) != len(tracked_list):
        raise LabError("git returned a duplicate selected NAT tracked path")
    admitted = {item.relative_path for item in inputs}
    if len(admitted) != len(inputs) or tracked != admitted:
        untracked = sorted(admitted - tracked)
        omitted = sorted(tracked - admitted)
        detail = []
        if untracked:
            detail.append("untracked admitted=" + ",".join(untracked[:8]))
        if omitted:
            detail.append("tracked omitted=" + ",".join(omitted[:8]))
        raise LabError(
            "selected NAT sealed inputs differ from the exact Git-tracked set"
            + (": " + "; ".join(detail) if detail else "")
        )


def git_sha1_blob(content: bytes) -> str:
    header = f"blob {len(content)}\0".encode("ascii")
    return hashlib.sha1(header + content).hexdigest()


def validate_selected_nat_commit_inputs(
    ctx: RunContext,
    git: str,
    commit: str,
    inputs: Sequence[BuildInput],
) -> None:
    """Bind every captured build/requirements byte to the immutable commit tree."""
    if not re.fullmatch(r"[0-9a-f]{40}", commit):
        raise LabError("selected NAT commit input authority is malformed")
    scopes = [
        ".dockerignore",
        "Cargo.toml",
        "Cargo.lock",
        "LICENSE",
        "crates",
        "third-party",
        "lab/Dockerfile",
        "lab/Dockerfile.selected-nat",
        "lab/Dockerfile.dockerignore",
        "lab/debian.sources",
        "data-mesh-requirements.md",
    ]
    result = ctx.runner.run(
        [
            git,
            "--no-replace-objects",
            "-C",
            str(WORKSPACE),
            "ls-tree",
            "-r",
            "-z",
            "--full-tree",
            commit,
            "--",
            *scopes,
        ]
    )
    if not result.stdout or not result.stdout.endswith("\0"):
        raise LabError("git returned a malformed selected NAT commit input tree")
    committed: dict[str, tuple[str, str]] = {}
    for raw_entry in result.stdout[:-1].split("\0"):
        match = re.fullmatch(
            r"(100644|100755) blob ([0-9a-f]{40})\t([^\x00\r\n\t]+)",
            raw_entry,
        )
        if match is None:
            raise LabError("selected NAT commit contains a non-regular admitted input")
        mode, object_id, relative = match.groups()
        if (
            relative.startswith("/")
            or "\\" in relative
            or any(part in {"", ".", ".."} for part in Path(relative).parts)
            or relative in committed
        ):
            raise LabError("selected NAT commit input path is noncanonical or duplicated")
        committed[relative] = (mode, object_id)
    captured = {item.relative_path: item for item in inputs}
    if len(captured) != len(inputs) or set(captured) != set(committed):
        raise LabError("selected NAT captured inputs differ from the immutable commit tree")
    for relative, item in captured.items():
        if item.sha256 != hashlib.sha256(item.content).hexdigest():
            raise LabError("selected NAT captured input SHA-256 differs from its bytes")
        if git_sha1_blob(item.content) != committed[relative][1]:
            raise LabError(
                f"selected NAT captured input bytes differ from commit: {relative}"
            )


def selected_nat_head_commit(ctx: RunContext, git: str) -> str:
    commit = ctx.runner.run(
        [
            git,
            "--no-replace-objects",
            "-C",
            str(WORKSPACE),
            "rev-parse",
            "--verify",
            "HEAD^{commit}",
        ]
    ).stdout.strip()
    if not re.fullmatch(r"[0-9a-f]{40}", commit):
        raise LabError("git returned a malformed selected NAT commit identity")
    return commit


def validate_selected_nat_source_still_clean(
    ctx: RunContext, git: str, commit: str
) -> None:
    status = ctx.runner.run(
        [git, "-C", str(WORKSPACE), "status", "--porcelain=v1"]
    )
    if status.stdout:
        raise LabError(
            "selected NAT source changed after its immutable input snapshot"
        )
    if selected_nat_head_commit(ctx, git) != commit:
        raise LabError("selected NAT HEAD changed after its immutable input snapshot")


def selected_nat_source_identity(ctx: RunContext) -> dict[str, Any]:
    git = shutil.which("git")
    if git is None:
        raise LabError("git is required to bind selected NAT source identity")
    commit = selected_nat_head_commit(ctx, git)
    tree = ctx.runner.run(
        [
            git,
            "--no-replace-objects",
            "-C",
            str(WORKSPACE),
            "rev-parse",
            "--verify",
            f"{commit}^{{tree}}",
        ]
    ).stdout.strip()
    if not re.fullmatch(r"[0-9a-f]{40}", tree):
        raise LabError("git returned malformed selected NAT tree identity")
    status = ctx.runner.run([git, "-C", str(WORKSPACE), "status", "--porcelain=v1"])
    if status.stdout:
        raise LabError(
            "selected NAT evidence requires clean tracked and nonignored untracked paths"
        )
    build_inputs = collect_selected_nat_build_inputs()
    validate_selected_nat_tracked_inputs(ctx, git, build_inputs)
    requirements_content = (WORKSPACE / "data-mesh-requirements.md").read_bytes()
    authority_inputs = [
        *build_inputs,
        BuildInput(
            "data-mesh-requirements.md",
            requirements_content,
            hashlib.sha256(requirements_content).hexdigest(),
        ),
    ]
    validate_selected_nat_commit_inputs(ctx, git, commit, authority_inputs)
    captured_by_path = {item.relative_path: item for item in build_inputs}
    for required in (
        "Cargo.toml",
        "Cargo.lock",
        "lab/Dockerfile.selected-nat",
    ):
        if required not in captured_by_path:
            raise LabError(f"selected NAT captured source omits {required}")
    signature = ctx.runner.run(
        [git, "--no-replace-objects", "-C", str(WORKSPACE), "verify-commit", commit],
        check=False,
    )
    if signature.returncode != 0:
        raise LabError("selected NAT source commit signature did not verify")
    record = {
        "schema": SCHEMA,
        "commit": commit,
        "tree": tree,
        "tracked_and_untracked_nonignored_clean": True,
        "commit_signature_verified": True,
        "cargo_toml_sha256": captured_by_path["Cargo.toml"].sha256,
        "cargo_lock_sha256": captured_by_path["Cargo.lock"].sha256,
        "requirements_sha256": hashlib.sha256(requirements_content).hexdigest(),
        "dockerfile_sha256": captured_by_path["lab/Dockerfile.selected-nat"].sha256,
        "build_input_manifest_sha256": build_input_digest(build_inputs),
    }
    write_exclusive_json(ctx.run_dir / "source-identity.json", record)
    return record


def remove_owned_container(ctx: RunContext, role: str, *, stop: bool = True) -> dict[str, Any]:
    name = FIXED_CONTAINER_NAMES[role]
    resource = PlannedResource("container", name, role)
    current = inspect_labels(ctx, resource)
    if current is None:
        raise LabError(f"cannot reap absent selected NAT container {name}")
    require_owned_labels(ctx, resource, current)
    docker = require_docker()
    if stop and container_is_running(ctx, name):
        ctx.runner.run([docker, "container", "stop", "--time", "5", name])
    logs = ctx.runner.run([docker, "container", "logs", name], check=False)
    if logs.returncode != 0:
        raise LabError(f"could not retain logs for selected NAT container {name}")
    log_path = write_command_linked_receipt(
        ctx, f"reap-{name}", "log", logs.stdout + logs.stderr
    )
    ctx.runner.run([docker, "container", "rm", "--force", name])
    if docker_resource_present(ctx, "container", name):
        raise LabError(f"selected NAT container {name} remained after reap")
    ctx.event("resource-removed", kind="container", name=name, role=role)
    return {
        "role": role,
        "name": name,
        "removed": True,
        "log": log_path.name,
        "log_sha256": sha256_file(log_path),
    }


def selected_nat_route_init(
    ctx: RunContext,
    *,
    role: str,
    node_role: str,
    gateway: str,
) -> dict[str, Any]:
    docker = require_docker()
    name = FIXED_CONTAINER_NAMES[role]
    node = FIXED_CONTAINER_NAMES[node_role]
    node_identity_result = ctx.runner.run(
        [docker, "container", "inspect", node, "--format", "{{json .Id}}"]
    )
    try:
        node_identity = json.loads(node_identity_result.stdout)
    except json.JSONDecodeError as error:
        raise LabError("selected NAT route target identity is malformed") from error
    if not isinstance(node_identity, str) or not re.fullmatch(
        r"[0-9a-f]{64}", node_identity
    ):
        raise LabError("selected NAT route target has no immutable container identity")
    completed = ctx.runner.run(
        container_run_args(
            ctx,
            name=name,
            role=role,
            command=["route", "replace", "default", "via", gateway],
            network=f"container:{node}",
            memory="64m",
            cpus="0.25",
            pids=32,
            capabilities=["NET_ADMIN"],
            root_user=True,
            entrypoint="/usr/sbin/ip",
        )
    )
    if completed.stdout or completed.stderr:
        raise LabError("selected NAT route initializer emitted unexpected output")
    verify_container_configuration(
        ctx,
        name,
        output_dir=None,
        memory="64m",
        cpus="0.25",
        pids=32,
        network=f"container:{node}",
        network_aliases=[f"container:{node_identity}"],
        capabilities=["NET_ADMIN"],
        root_user=True,
        network_addresses={},
        entrypoint="/usr/sbin/ip",
    )
    route_result = ctx.runner.run(
        [docker, "exec", node, "/usr/sbin/ip", "-j", "route", "show", "default"]
    )
    try:
        routes = json.loads(route_result.stdout)
    except json.JSONDecodeError as error:
        raise LabError("selected NAT default route output is malformed") from error
    route = validate_selected_nat_default_route(routes, gateway=gateway)
    reaped = remove_owned_container(ctx, role, stop=False)
    if (
        not re.fullmatch(
            rf"reap-{re.escape(name)}-command-[0-9]{{4,}}\.log",
            str(reaped.get("log", "")),
        )
        or reaped.get("log_sha256") != hashlib.sha256(b"").hexdigest()
    ):
        raise LabError("selected NAT route initializer retained a nonempty or misnamed log")
    return {
        **reaped,
        "node": node_role,
        "gateway": gateway,
        "route": route,
        "exit_code": completed.returncode,
        "exited": True,
    }


def validate_selected_nat_default_route(
    value: Any, *, gateway: str
) -> dict[str, Any]:
    if not isinstance(value, list) or len(value) != 1:
        raise LabError("selected NAT default route differs from the exact router")
    route = value[0]
    if (
        not isinstance(route, dict)
        or set(route) != {"dev", "dst", "flags", "gateway"}
        or route.get("dev") != "eth0"
        or route.get("dst") != "default"
        or route.get("flags") != []
        or route.get("gateway") != gateway
    ):
        raise LabError("selected NAT default route differs from the exact router")
    return route


def selected_nat_command_sequence(
    value: str, *, prefix: str, suffix: str, label: str
) -> int:
    matched = re.fullmatch(
        rf"{re.escape(prefix)}([0-9]{{4,}}){re.escape(suffix)}", value
    )
    if matched is None:
        raise LabError(f"selected NAT {label} command receipt name differs")
    sequence = int(matched.group(1))
    if sequence <= 0 or sequence > 9_999_999:
        raise LabError(f"selected NAT {label} command receipt sequence exceeds its bound")
    return sequence


def validate_selected_nat_command_chronology(
    *,
    route_receipts: Sequence[dict[str, Any]],
    capture_stderr: dict[str, str],
    node_stderr: dict[str, str],
) -> None:
    """Bind route removal, capture, and node starts to their exact command order."""
    if len(route_receipts) != 2 or set(capture_stderr) != {"nat-a", "nat-b"} or set(
        node_stderr
    ) != {"node-a", "node-b"}:
        raise LabError("selected NAT command chronology authorities differ")
    sequences = {
        "route-a": selected_nat_command_sequence(
            str(route_receipts[0].get("log", "")),
            prefix="reap-aster-lab-route-a-command-",
            suffix=".log",
            label="route-a",
        ),
        "route-b": selected_nat_command_sequence(
            str(route_receipts[1].get("log", "")),
            prefix="reap-aster-lab-route-b-command-",
            suffix=".log",
            label="route-b",
        ),
        **{
            role: selected_nat_command_sequence(
                capture_stderr[role],
                prefix="command-",
                suffix=".stderr",
                label=f"{role} capture",
            )
            for role in ("nat-a", "nat-b")
        },
        **{
            role: selected_nat_command_sequence(
                node_stderr[role],
                prefix="command-",
                suffix=".stderr",
                label=role,
            )
            for role in ("node-a", "node-b")
        },
    }
    if not (
        sequences["route-a"]
        < sequences["route-b"]
        < sequences["nat-a"]
        < sequences["nat-b"]
        < sequences["node-b"]
        < sequences["node-a"]
        and sequences["node-a"] == sequences["node-b"] + 1
    ):
        raise LabError("selected NAT command chronology differs from production order")


def selected_nat_privilege_receipt(ctx: RunContext, role: str) -> dict[str, Any]:
    docker = require_docker()
    name = FIXED_CONTAINER_NAMES[role]
    user = f"{os.getuid()}:{os.getgid()}"
    status = ctx.runner.run(
        [docker, "exec", "--user", user, name, "/usr/bin/cat", "/proc/self/status"]
    )
    uid = ctx.runner.run([docker, "exec", "--user", user, name, "/usr/bin/id", "-u"])
    gid = ctx.runner.run([docker, "exec", "--user", user, name, "/usr/bin/id", "-g"])
    receipt = validate_runtime_privilege_receipt(status.stdout, uid.stdout, gid.stdout)
    write_exclusive_json(ctx.run_dir / f"{role}-runtime-privilege.json", receipt)
    return receipt


def selected_nat_network_receipt(
    ctx: RunContext,
    *,
    role: str,
    spec: NetworkSpec,
    expected_members: dict[str, str],
) -> dict[str, Any]:
    """Retain and validate Docker's authoritative internal-network topology."""
    if role not in {"lan-a", "wan", "lan-b"}:
        raise LabError("selected NAT network receipt role is invalid")
    result = ctx.runner.run(
        [
            require_docker(),
            "network",
            "inspect",
            spec.name,
            "--format",
            "{{json .}}",
        ]
    )
    try:
        value = json.loads(result.stdout)
    except json.JSONDecodeError as error:
        raise LabError("Docker returned malformed selected NAT network JSON") from error
    if not isinstance(value, dict):
        raise LabError("selected NAT network configuration is not an object")
    fixed = {
        "Name": spec.name,
        "Driver": "bridge",
        "Internal": True,
        "Attachable": False,
        "Ingress": False,
    }
    if any(value.get(key) != expected for key, expected in fixed.items()):
        raise LabError("selected NAT network differs from its fixed internal topology")
    expected_labels = {
        MANAGED_LABEL: "true",
        RUN_LABEL: ctx.run_id,
        ROLE_LABEL: role,
    }
    if value.get("Labels") != expected_labels:
        raise LabError("selected NAT network ownership labels differ")
    ipam = value.get("IPAM")
    if not isinstance(ipam, dict) or ipam.get("Driver") != "default":
        raise LabError("selected NAT network IPAM driver differs")
    configuration = ipam.get("Config")
    if not isinstance(configuration, list) or len(configuration) != 1:
        raise LabError("selected NAT network has no exact IPAM configuration")
    ipam_record = configuration[0]
    if (
        not isinstance(ipam_record, dict)
        or ipam_record.get("Subnet") != str(spec.subnet)
        or ipam_record.get("Gateway") != str(spec.gateway)
    ):
        raise LabError("selected NAT network CIDR or gateway differs")
    members = value.get("Containers")
    if not isinstance(members, dict):
        raise LabError("selected NAT network has no container membership object")
    observed_members: dict[str, str] = {}
    for member in members.values():
        if not isinstance(member, dict):
            raise LabError("selected NAT network member is malformed")
        name = member.get("Name")
        address = member.get("IPv4Address")
        if (
            not isinstance(name, str)
            or name in observed_members
            or not isinstance(address, str)
        ):
            raise LabError("selected NAT network member identity is malformed")
        observed_members[name] = address
    expected_with_prefix = {
        name: f"{ipaddress.ip_address(address)}/{spec.subnet.prefixlen}"
        for name, address in expected_members.items()
    }
    if observed_members != expected_with_prefix:
        raise LabError("selected NAT network members differ from the exact topology")
    path = ctx.run_dir / f"{spec.name}-network.json"
    write_exclusive_json(path, value)
    return {
        "role": role,
        "name": spec.name,
        "path": path.name,
        "sha256": sha256_file(path),
        "internal": True,
        "subnet": str(spec.subnet),
        "gateway": str(spec.gateway),
        "members": observed_members,
    }


def wait_for_running_marker(
    ctx: RunContext,
    running: RunningCommand,
    marker: str,
    *,
    timeout: float,
) -> None:
    deadline = time.monotonic() + timeout
    path = ctx.run_dir / running.stdout_name
    while time.monotonic() < deadline:
        text_value = path.read_text(encoding="utf-8", errors="replace")
        if marker in text_value:
            if running.poll() is not None:
                running.finish(check=True)
                raise LabError(f"selected NAT process exited after emitting {marker!r}")
            return
        if running.poll() is not None:
            running.finish(check=True)
            raise LabError(f"selected NAT process exited before {marker!r}")
        time.sleep(0.1)
    raise LabError(f"selected NAT process did not emit {marker!r}")


def finish_running_commands(
    commands: Sequence[RunningCommand], *, deadline: float
) -> None:
    pending = list(commands)
    while pending:
        for running in list(pending):
            if running.poll() is not None:
                running.finish(check=True)
                pending.remove(running)
        if not pending:
            return
        if time.monotonic() >= deadline:
            for running in pending:
                running.terminate()
            raise LabError("selected NAT live node processes exceeded their deadline")
        time.sleep(0.1)


def selected_nat_binary_inventory(ctx: RunContext, container: str) -> list[dict[str, Any]]:
    docker = require_docker()
    roles = [
        ("aster-cli", "/usr/local/bin/aster"),
        ("event-helper", "/usr/local/bin/aster-selected-nat"),
        ("relay-helper", "/usr/local/bin/aster-selected-relay"),
    ]
    result = []
    for role, path in roles:
        digest_result = ctx.runner.run(
            [docker, "exec", container, "/usr/bin/sha256sum", path]
        )
        digest_fields = digest_result.stdout.split()
        if len(digest_fields) != 2 or digest_fields[1] != path or not re.fullmatch(
            r"[0-9a-f]{64}", digest_fields[0]
        ):
            raise LabError("selected NAT binary digest output is malformed")
        size_result = ctx.runner.run(
            [docker, "exec", container, "/usr/bin/stat", "--format=%s", path]
        )
        if not re.fullmatch(r"[1-9][0-9]*\n?", size_result.stdout):
            raise LabError("selected NAT binary size output is malformed")
        result.append(
            {
                "role": role,
                "name": Path(path).name,
                "path": path,
                "bytes": int(size_result.stdout),
                "sha256": digest_fields[0],
            }
        )
    write_exclusive_json(ctx.run_dir / "binary-inventory.json", result)
    return result


def start_selected_nat_provisioner(
    ctx: RunContext, output_dir: Path, *, receipt_name: str | None = None
) -> None:
    name = FIXED_CONTAINER_NAMES["provision"]
    ctx.runner.run(
        container_run_args(
            ctx,
            name=name,
            role="provision",
            command=["infinity"],
            detach=True,
            network="none",
            memory="512m",
            cpus="1",
            pids=128,
            entrypoint="/usr/bin/sleep",
            output_dir=output_dir,
        )
    )
    verify_container_configuration(
        ctx,
        name,
        output_dir=output_dir,
        memory="512m",
        cpus="1",
        pids=128,
        network="none",
        network_addresses={"none": ""},
        entrypoint="/usr/bin/sleep",
        receipt_name=receipt_name,
    )


def selected_nat_exec(
    ctx: RunContext,
    container: str,
    command: Sequence[str],
    *,
    timeout: float = 120,
) -> tuple[subprocess.CompletedProcess[str], Path]:
    result = ctx.runner.run(
        [
            require_docker(),
            "exec",
            "--user",
            f"{os.getuid()}:{os.getgid()}",
            container,
            *command,
        ],
        timeout=timeout,
    )
    if result.stderr:
        raise LabError("selected NAT stopped helper wrote unexpected stderr output")
    output = ctx.run_dir / f"command-{ctx.runner.sequence:04d}.stdout"
    if output.is_symlink() or not output.is_file():
        raise LabError("selected NAT command output receipt is missing")
    return result, output


def validate_selected_nat_relay_log(
    value: str,
    *,
    carrier_ids: set[str],
    max_admitted_connections: int,
    client_rx_bytes_per_second: int,
    client_rx_max_burst_bytes: int,
    key_cache_capacity: int,
) -> dict[str, Any]:
    require_receipt_line_prefixes(
        value, ["SELECTED_NAT_RELAY_READY", "SELECTED_NAT_RELAY_STOP"]
    )
    ready = exact_receipt(value, "SELECTED_NAT_RELAY_READY")
    stop = exact_receipt(value, "SELECTED_NAT_RELAY_STOP")
    require_receipt_keys(
        ready,
        {
            "status",
            "version",
            "https",
            "http",
            "tls",
            "server_trust_claim",
            "allowlist",
            "allowlist_count",
            "max_admitted_connections",
            "pre_auth_connection_cap",
            "client_rx_bytes_per_second",
            "client_rx_max_burst_bytes",
            "key_cache_capacity",
            "secrets_logged",
            "public_relay_fallback",
            "hosted_discovery",
            "port_mapper",
        },
        "SELECTED_NAT_RELAY_READY",
    )
    require_receipt_keys(
        stop,
        {
            "status",
            "version",
            "accepted_connections",
            "denied_connections",
            "active_connections",
            "peak_active_connections",
            "sessions",
            "bytes_up",
            "bytes_down",
            "max_admitted_connections",
            "pre_auth_connection_cap",
            "client_rx_bytes_per_second",
            "client_rx_max_burst_bytes",
            "key_cache_capacity",
            "allowlist",
            "allowlist_count",
            "server_trust_claim",
            "graceful",
        },
        "SELECTED_NAT_RELAY_STOP",
    )
    if (
        ready.get("status") != "ready"
        or ready.get("version") != "1"
        or ready.get("https") != f"0.0.0.0:{SELECTED_NAT_RELAY_HTTPS_PORT}"
        or ready.get("http") != f"0.0.0.0:{SELECTED_NAT_RELAY_HTTP_PORT}"
        or ready.get("tls") != "manual-der-certificate"
        or ready.get("server_trust_claim") != "none"
        or ready.get("allowlist") != "exact-cli-identities"
        or ready.get("allowlist_count") != str(len(carrier_ids))
        or ready.get("secrets_logged") != "false"
        or ready.get("public_relay_fallback") != "false"
        or ready.get("hosted_discovery") != "false"
        or ready.get("port_mapper") != "false"
    ):
        raise LabError("selected NAT relay READY receipt differs")
    exact_config = {
        "max_admitted_connections": max_admitted_connections,
        "client_rx_bytes_per_second": client_rx_bytes_per_second,
        "client_rx_max_burst_bytes": client_rx_max_burst_bytes,
        "key_cache_capacity": key_cache_capacity,
    }
    for field, expected in exact_config.items():
        if receipt_nonnegative(ready, field) != expected or receipt_nonnegative(stop, field) != expected:
            raise LabError(f"selected NAT relay bound differs: {field}")
    if (
        stop.get("status") != "pass"
        or stop.get("version") != "1"
        or stop.get("allowlist") != "exact-cli-identities"
        or stop.get("allowlist_count") != str(len(carrier_ids))
        or stop.get("server_trust_claim") != "none"
        or ready.get("pre_auth_connection_cap") != "not-enforced"
        or stop.get("pre_auth_connection_cap") != "not-enforced"
        or stop.get("graceful") != "true"
        or receipt_nonnegative(stop, "active_connections") != 0
    ):
        raise LabError("selected NAT relay STOP receipt differs")
    accepted = receipt_nonnegative(stop, "accepted_connections")
    denied = receipt_nonnegative(stop, "denied_connections")
    sessions = receipt_nonnegative(stop, "sessions")
    peak = receipt_nonnegative(stop, "peak_active_connections")
    if (
        accepted <= 0
        or denied != 0
        or sessions <= 0
        or sessions != accepted
        or peak <= 0
        or peak > max_admitted_connections
    ):
        raise LabError("selected NAT relay did not enforce a bounded observed session")
    if receipt_nonnegative(stop, "bytes_up") <= 0 or receipt_nonnegative(stop, "bytes_down") <= 0:
        raise LabError("selected NAT relay observed no bidirectional bytes")
    return {"ready": ready, "stop": stop}


def validate_selected_nat_material(
    value: str, *, profile: str
) -> dict[str, str]:
    require_receipt_line_prefixes(value, ["SELECTED_NAT_RELAY_MATERIAL"])
    material = exact_receipt(value, "SELECTED_NAT_RELAY_MATERIAL")
    require_receipt_keys(
        material,
        {
            "status",
            "version",
            "dns_name",
            "ip_address",
            "san",
            "ca_sha256",
            "certificate_sha256",
            "certificate_format",
            "private_key_format",
            "private_key",
            "key_mode",
        },
        "SELECTED_NAT_RELAY_MATERIAL",
    )
    if (
        profile != "restrictive-relay"
        or material.get("status") != "pass"
        or material.get("version") != "1"
        or material.get("dns_name") != SELECTED_NAT_RELAY_DNS
        or material.get("ip_address") != SELECTED_NAT_RELAY_IP
        or material.get("san") != "dns+ip"
        or material.get("certificate_format") != "der"
        or material.get("private_key_format") != "pkcs8-der"
        or material.get("private_key") != "redacted"
        or material.get("key_mode") != "0600"
    ):
        raise LabError("selected NAT relay material receipt differs")
    receipt_hex(material, "ca_sha256")
    receipt_hex(material, "certificate_sha256")
    return material


def validate_selected_nat_destroy(
    value: str, *, prefix: str, target: str, expected_bytes: int | None
) -> dict[str, str]:
    require_receipt_line_prefixes(value, [prefix])
    record = exact_receipt(value, prefix)
    expected_version = "2" if prefix == "SELECTED_NAT_CANARY_DESTROY" else "1"
    expected_extra = {"publication_journals_destroyed"} if expected_version == "2" else set()
    if expected_extra and record.get("publication_journals_destroyed") != "2":
        raise LabError("selected NAT publication journals were not destroyed")
    require_receipt_keys(
        record,
        {
            *expected_extra,
            "status",
            "version",
            "artifact_destroyed",
            "global_secret_destruction",
            "target",
            "previous_bytes",
            "previous_mode",
            "owner_uid",
            "overwrite",
            "sync",
            "unlinked",
            "assurance",
            "physical_sanitization",
        },
        prefix,
    )
    if (
        record.get("status") != "pass"
        or record.get("version") != expected_version
        or record.get("artifact_destroyed") != "true"
        or record.get("global_secret_destruction") != "false"
        or record.get("target") != target
        or record.get("previous_mode") != "0600"
        or record.get("overwrite") != "zero"
        or record.get("sync") != "file+directory"
        or record.get("unlinked") != "true"
        or record.get("assurance") != "bounded-software"
        or record.get("physical_sanitization") != "not-claimed"
    ):
        raise LabError(f"{prefix} receipt differs")
    previous_bytes = receipt_nonnegative(record, "previous_bytes")
    if (
        previous_bytes <= 0
        or (expected_bytes is not None and previous_bytes != expected_bytes)
        or (expected_bytes is None and previous_bytes > 16_384)
    ):
        raise LabError(f"{prefix} previous byte count differs")
    if receipt_nonnegative(record, "owner_uid") != os.getuid():
        raise LabError(f"{prefix} owner differs from the current runner")
    return record


def selected_nat_canary_scan(
    ctx: RunContext,
    *,
    canary_path: Path,
    captures: Sequence[Path],
    logs: Sequence[Path],
    public_artifacts: Sequence[Path] = (),
) -> dict[str, Any]:
    original_canary_metadata = os.lstat(canary_path)
    if (
        not stat.S_ISREG(original_canary_metadata.st_mode)
        or stat.S_ISLNK(original_canary_metadata.st_mode)
    ):
        raise LabError("selected NAT private canary is missing or symbolic")
    canary_path = confined_run_path(ctx, canary_path)
    canary_metadata = os.lstat(canary_path)
    if (
        not stat.S_ISREG(canary_metadata.st_mode)
        or stat.S_ISLNK(canary_metadata.st_mode)
        or (canary_metadata.st_dev, canary_metadata.st_ino)
        != (original_canary_metadata.st_dev, original_canary_metadata.st_ino)
        or canary_metadata.st_uid != os.getuid()
        or (canary_metadata.st_mode & 0o777) != 0o600
        or canary_metadata.st_nlink != 1
        or canary_metadata.st_size != 32
    ):
        raise LabError("selected NAT private canary lacks owner-only containment")
    canary_descriptor = os.open(
        canary_path,
        os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0),
    )
    try:
        opened_canary = os.fstat(canary_descriptor)
        if (opened_canary.st_dev, opened_canary.st_ino) != (
            canary_metadata.st_dev,
            canary_metadata.st_ino,
        ):
            raise LabError("selected NAT private canary changed while opening")
        canary = os.read(canary_descriptor, 33)
        if len(canary) != 32 or os.read(canary_descriptor, 1):
            raise LabError("selected NAT private canary length differs")
    finally:
        os.close(canary_descriptor)
    needles = {
        "raw-bytes": canary,
        "lowercase-hex": canary.hex().encode("ascii"),
        "base64-standard": base64.b64encode(canary),
    }

    def count_needles(data: bytes) -> dict[str, int]:
        return {
            representation: data.count(needle)
            for representation, needle in needles.items()
        }

    def scan_path(path: Path) -> tuple[bytes, dict[str, int]]:
        original_metadata = os.lstat(path)
        if (
            not stat.S_ISREG(original_metadata.st_mode)
            or stat.S_ISLNK(original_metadata.st_mode)
            or original_metadata.st_nlink != 1
        ):
            raise LabError("selected NAT canary scan input is not a plain single-link file")
        confined = confined_run_path(ctx, path)
        metadata = os.lstat(confined)
        if (
            not stat.S_ISREG(metadata.st_mode)
            or stat.S_ISLNK(metadata.st_mode)
            or (metadata.st_dev, metadata.st_ino)
            != (original_metadata.st_dev, original_metadata.st_ino)
            or metadata.st_nlink != 1
            or metadata.st_uid not in {0, os.getuid()}
        ):
            raise LabError("selected NAT canary scan input is not a confined regular file")
        if metadata.st_size > 128 * 1024 * 1024:
            raise LabError("selected NAT canary scan input exceeds 128 MiB")
        descriptor = os.open(
            confined,
            os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0),
        )
        try:
            opened = os.fstat(descriptor)
            if (opened.st_dev, opened.st_ino) != (metadata.st_dev, metadata.st_ino):
                raise LabError("selected NAT canary scan input changed while opening")
            chunks = []
            observed_bytes = 0
            while True:
                chunk = os.read(descriptor, 1024 * 1024)
                if not chunk:
                    break
                observed_bytes += len(chunk)
                if observed_bytes > metadata.st_size:
                    raise LabError("selected NAT canary scan input grew while reading")
                chunks.append(chunk)
        finally:
            os.close(descriptor)
        if observed_bytes != metadata.st_size:
            raise LabError("selected NAT canary scan input changed size while reading")
        data = b"".join(chunks)
        return data, count_needles(data)

    positive_bytes = b"\x00ASTER-RAW\x00" + canary + b"\x00ASTER-HEX\x00" + needles[
        "lowercase-hex"
    ] + b"\x00ASTER-B64\x00" + needles["base64-standard"] + b"\x00ASTER-END\x00"
    positive_counts = count_needles(positive_bytes)
    if any(value != 1 for value in positive_counts.values()):
        raise LabError("selected NAT canary positive control failed")
    classes = []
    for name, paths in [
        ("pcap", captures),
        ("log", logs),
        ("public-certificate", public_artifacts),
    ]:
        matches = {representation: 0 for representation in needles}
        checked = []
        for path in paths:
            data, observed = scan_path(path)
            confined = confined_run_path(ctx, path)
            for representation, count in observed.items():
                matches[representation] += count
            checked.append(
                {
                    "path": str(confined.relative_to(ctx.run_dir)),
                    "bytes": len(data),
                    "sha256": hashlib.sha256(data).hexdigest(),
                    "matches": observed,
                }
            )
        classes.append(
            {
                "class": name,
                "matches": matches,
                "total_matches": sum(matches.values()),
                "files": checked,
            }
        )
    if any(record["total_matches"] != 0 for record in classes):
        raise LabError("selected NAT raw canary appeared outside its private control")
    receipt = {
        "schema": SCHEMA,
        "algorithm": "exact-byte-sequence/v1",
        "canary_bytes": 32,
        "canary_sha256": hashlib.sha256(canary).hexdigest(),
        "representations": [
            {
                "name": name,
                "bytes": len(needle),
                "needle_sha256": hashlib.sha256(needle).hexdigest(),
                "positive_control_expected": 1,
                "positive_control_observed": positive_counts[name],
            }
            for name, needle in needles.items()
        ],
        "positive_control": {
            "path_class": "private-ephemeral",
            "bytes": len(positive_bytes),
            "expected": 3,
            "observed": sum(positive_counts.values()),
            "class_match_counts": positive_counts,
            "pass": True,
        },
        "classes": ["raw-bytes", "lowercase-hex", "base64-standard"],
        "artifact_classes": classes,
        "class_match_counts": {
            name: sum(
                record["matches"][name]
                for record in classes
            )
            for name in needles
        },
        "chronology": [
            "positive-control-observed-before-retained-scan",
            "captures-and-logs-finalized-before-retained-scan",
            "retained-artifact-scan-zero-before-destruction",
            "standalone-control-file-overwritten-unlinked-and-absent-after-scan",
        ],
        "matches": 0,
        "status": "pass",
    }
    write_exclusive_json(ctx.run_dir / "canary-scan.json", receipt)
    return receipt


def selected_nat_manifest_paths() -> dict[str, dict[str, str]]:
    """Return the frozen, exact public/restricted metadata projection."""
    return {
        "global": dict(SELECTED_NAT_GLOBAL_MANIFEST_PATHS),
        **{
            cell: {
                **{
                    role: f"cells/{cell}/{relative}"
                    for role, relative in SELECTED_NAT_COMMON_CELL_MANIFEST_PATHS.items()
                },
                **{
                    role: f"cells/{cell}/{relative}"
                    for role, relative in SELECTED_NAT_CELL_EXTRA_MANIFEST_PATHS[cell].items()
                },
            }
            for cell in ["cone-direct", "restrictive-relay"]
        },
    }


def selected_nat_safe_artifact(root: Path, relative: str) -> Path:
    if (
        not relative
        or relative.startswith("/")
        or "\\" in relative
        or any(part in {"", ".", ".."} for part in Path(relative).parts)
    ):
        raise LabError("selected NAT curated artifact path is not canonical")
    root = root.resolve()
    path = root / relative
    current = root
    for part in Path(relative).parts[:-1]:
        current = current / part
        metadata = os.lstat(current)
        if not stat.S_ISDIR(metadata.st_mode) or stat.S_ISLNK(metadata.st_mode):
            raise LabError("selected NAT curated artifact parent is not a plain directory")
    metadata = os.lstat(path)
    if not stat.S_ISREG(metadata.st_mode) or stat.S_ISLNK(metadata.st_mode):
        raise LabError("selected NAT curated artifact is not a plain regular file")
    return path


def validate_selected_nat_control_file_absence(root: Path) -> None:
    root = root.resolve()
    targets = [
        Path("cells") / cell / "outputs" / "provision" / "private" / "canary.bin"
        for cell in ["cone-direct", "restrictive-relay"]
    ]
    targets.extend(
        Path("cells")
        / cell
        / "outputs"
        / "provision"
        / "relay"
        / "private"
        / "server.key.pkcs8.der"
        for cell in ["cone-direct", "restrictive-relay"]
    )
    for relative in targets:
        current = root
        for part in relative.parts[:-1]:
            current /= part
            try:
                metadata = os.lstat(current)
            except FileNotFoundError:
                break
            if (
                not stat.S_ISDIR(metadata.st_mode)
                or stat.S_ISLNK(metadata.st_mode)
                or metadata.st_uid != os.getuid()
                or metadata.st_mode & 0o022
            ):
                raise LabError("selected NAT private control parent is unsafe")
        try:
            os.lstat(root / relative)
        except FileNotFoundError:
            continue
        raise LabError("selected NAT private control file remained after cleanup")


def normalize_selected_nat_restricted_state(
    ctx: RunContext, provision_root: Path, profile: str
) -> dict[str, Any]:
    """Keep credentials/state usable but owner-only and outside sanitized entries."""
    provision_root = confined_run_path(ctx, provision_root)
    private = provision_root / "private"
    if private.is_symlink() or not private.is_dir():
        raise LabError("selected NAT retained private directory is missing or symbolic")
    if {path.name for path in private.iterdir()} != {"node-a.bundle", "node-b.bundle"}:
        raise LabError("selected NAT retained private directory has an unexpected entry")
    for name in ["node-a.bundle", "node-b.bundle"]:
        metadata = os.lstat(private / name)
        if (
            not stat.S_ISREG(metadata.st_mode)
            or stat.S_ISLNK(metadata.st_mode)
            or metadata.st_uid != os.getuid()
            or stat.S_IMODE(metadata.st_mode) != 0o600
            or metadata.st_nlink != 1
            or metadata.st_size <= 0
        ):
            raise LabError("selected NAT retained mission bundle is unsafe or empty")
    roots = [private, provision_root / "node-a", provision_root / "node-b"]
    if profile == "restrictive-relay":
        relay_private = provision_root / "relay" / "private"
        if relay_private.is_symlink() or not relay_private.is_dir():
            raise LabError("selected NAT relay private directory is missing or symbolic")
        if any(relay_private.iterdir()):
            raise LabError("selected NAT relay private directory retained an artifact")
        roots.append(relay_private)
    files = 0
    total_bytes = 0
    state_files = 0
    directories = 0
    total_entries = 0
    for retained_root in roots:
        if retained_root.is_symlink() or not retained_root.is_dir():
            raise LabError("selected NAT retained state root is missing or symbolic")
        is_state_root = retained_root in {
            provision_root / "node-a",
            provision_root / "node-b",
        }
        for directory, names, filenames in os.walk(retained_root, followlinks=False):
            names.sort()
            filenames.sort()
            directory_path = Path(directory)
            directories += 1
            total_entries += len(names) + len(filenames)
            try:
                depth = len(directory_path.relative_to(retained_root).parts)
            except ValueError as error:
                raise LabError("selected NAT retained state directory escaped") from error
            if (
                depth > 32
                or directories > 4_096
                or total_entries > 8_192
                or len(names) + len(filenames) > 4_096
            ):
                raise LabError("selected NAT retained state tree exceeds metadata bounds")
            confined_run_path(ctx, directory_path)
            directory_metadata = os.lstat(directory_path)
            if (
                directory_metadata.st_uid != os.getuid()
                or not stat.S_ISDIR(directory_metadata.st_mode)
                or stat.S_ISLNK(directory_metadata.st_mode)
            ):
                raise LabError("selected NAT retained state escaped owner confinement")
            os.chmod(directory_path, 0o700)
            for name in names:
                child = directory_path / name
                child_metadata = os.lstat(child)
                if (
                    child_metadata.st_uid != os.getuid()
                    or not stat.S_ISDIR(child_metadata.st_mode)
                    or stat.S_ISLNK(child_metadata.st_mode)
                ):
                    raise LabError("selected NAT retained state contains an unsafe directory")
            for name in filenames:
                path = directory_path / name
                confined_run_path(ctx, path)
                metadata = os.lstat(path)
                if metadata.st_uid != os.getuid() or stat.S_ISLNK(metadata.st_mode):
                    raise LabError("selected NAT retained state escaped owner confinement")
                if not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1:
                    raise LabError("selected NAT retained state contains a special or linked file")
                if metadata.st_size > 512 * 1024 * 1024:
                    raise LabError("selected NAT retained state file exceeds its bound")
                os.chmod(path, 0o600)
                files += 1
                total_bytes += metadata.st_size
                if files > 4_096 or total_bytes > 1024 * 1024 * 1024:
                    raise LabError("selected NAT retained state set exceeds its fixed bounds")
                if is_state_root:
                    state_files += 1
    if (
        files < 4
        or files > 4_096
        or state_files < 2
        or state_files > 4_094
        or files != state_files + 2
        or total_bytes < 1
        or total_bytes > 1024 * 1024 * 1024
    ):
        raise LabError("selected NAT retained state set differs from its fixed bounds")
    receipt = {
        "schema": SCHEMA,
        "mission_bundle_files": 2,
        "state_files": state_files,
        "retained_files": files,
        "retained_bytes": total_bytes,
        "owner": "current-runner",
        "file_mode": "0600",
        "directory_mode": "0700",
        "sanitized_manifest": "excluded-external-restricted",
        "encrypted_event_state_retained": True,
        "mission_credentials_retained": True,
        "status": "pass",
    }
    write_exclusive_json(ctx.run_dir / "restricted-state-containment.json", receipt)
    return receipt


def normalize_selected_nat_curated_artifacts(root: Path) -> None:
    """Copy exact curated bytes into owner-only, single-link evidence files."""
    root = root.resolve()
    validate_selected_nat_control_file_absence(root)
    root_metadata = os.lstat(root)
    if not stat.S_ISDIR(root_metadata.st_mode) or stat.S_ISLNK(root_metadata.st_mode):
        raise LabError("selected NAT suite root is not a plain directory")
    if root_metadata.st_uid != os.getuid():
        raise LabError("selected NAT suite root is not owned by the current runner")
    os.chmod(root, 0o700)
    expected = selected_nat_manifest_paths()
    roles_by_relative = {
        relative: role
        for roles in expected.values()
        for role, relative in roles.items()
    }
    if len(roles_by_relative) != sum(len(roles) for roles in expected.values()):
        raise LabError("selected NAT curated artifact path is duplicated")
    for relative, role in sorted(roles_by_relative.items()):
        path = selected_nat_safe_artifact(root, relative)
        current = path.parent
        while current != root:
            parent_metadata = os.lstat(current)
            if (
                not stat.S_ISDIR(parent_metadata.st_mode)
                or stat.S_ISLNK(parent_metadata.st_mode)
                or parent_metadata.st_uid != os.getuid()
            ):
                raise LabError("selected NAT curated artifact has an unsafe parent")
            os.chmod(current, 0o700)
            current = current.parent
        metadata = os.lstat(path)
        maximum = (
            SELECTED_NAT_MAX_PCAP_BYTES
            if role.endswith("-pcap")
            else SELECTED_NAT_MAX_CURATED_ARTIFACT_BYTES
        )
        minimum = 24 if role.endswith("-pcap") else 1
        if metadata.st_size < minimum or metadata.st_size > maximum:
            raise LabError("selected NAT curated artifact is outside its exact size bound")
        temporary = path.with_name(f".{path.name}.normalize-{secrets.token_hex(8)}")
        source_flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
        destination_flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_CLOEXEC", 0)
        source = os.open(path, source_flags)
        destination: int | None = None
        try:
            opened = os.fstat(source)
            if (opened.st_dev, opened.st_ino) != (metadata.st_dev, metadata.st_ino):
                raise LabError("selected NAT curated artifact changed while opening")
            destination = os.open(temporary, destination_flags, 0o600)
            copied = 0
            while True:
                chunk = os.read(source, 1024 * 1024)
                if not chunk:
                    break
                copied += len(chunk)
                if copied > maximum:
                    raise LabError("selected NAT curated artifact grew beyond its bound")
                view = memoryview(chunk)
                while view:
                    written = os.write(destination, view)
                    view = view[written:]
            if copied != metadata.st_size:
                raise LabError("selected NAT curated artifact changed size while copying")
            os.fsync(destination)
            os.close(destination)
            destination = None
            os.replace(temporary, path)
            os.chmod(path, 0o600)
        finally:
            os.close(source)
            if destination is not None:
                os.close(destination)
            try:
                temporary.unlink()
            except FileNotFoundError:
                pass
        normalized = os.lstat(path)
        if (
            not stat.S_ISREG(normalized.st_mode)
            or normalized.st_nlink != 1
            or normalized.st_uid != os.getuid()
            or (normalized.st_mode & 0o777) != 0o600
            or normalized.st_size <= 0
        ):
            raise LabError("selected NAT curated artifact normalization failed")
    for profile in ["cone-direct", "restrictive-relay"]:
        cell_root = root / "cells" / profile
        scan = load_selected_nat_json(cell_root / "canary-scan.json")
        command_stderr = []
        for artifact_class in scan.get("artifact_classes", []):
            if not isinstance(artifact_class, dict) or artifact_class.get("class") != "log":
                continue
            for record in artifact_class.get("files", []):
                if not isinstance(record, dict):
                    raise LabError("selected NAT canary scan file metadata is malformed")
                relative = record.get("path")
                if isinstance(relative, str) and re.fullmatch(
                    r"command-[0-9]{4,}\.stderr", relative
                ):
                    command_stderr.append((relative, record))
        if len(command_stderr) != 4 or len({item[0] for item in command_stderr}) != 4:
            raise LabError("selected NAT canary scan lacks four exact command stderrs")
        for relative, record in command_stderr:
            path = selected_nat_safe_artifact(root, f"cells/{profile}/{relative}")
            metadata = os.lstat(path)
            expected_bytes = record.get("bytes")
            expected_sha256 = record.get("sha256")
            if (
                metadata.st_uid != os.getuid()
                or metadata.st_nlink != 1
                or type(expected_bytes) is not int
                or expected_bytes < 0
                or metadata.st_size != expected_bytes
                or not isinstance(expected_sha256, str)
                or not re.fullmatch(r"[0-9a-f]{64}", expected_sha256)
                or sha256_file(path) != expected_sha256
            ):
                raise LabError("selected NAT command stderr normalization authority differs")
            os.chmod(path, 0o600)
            normalized = os.lstat(path)
            if (
                not stat.S_ISREG(normalized.st_mode)
                or stat.S_ISLNK(normalized.st_mode)
                or normalized.st_uid != os.getuid()
                or normalized.st_nlink != 1
                or stat.S_IMODE(normalized.st_mode) != 0o600
                or normalized.st_size != expected_bytes
            ):
                raise LabError("selected NAT command stderr normalization failed")


def prune_selected_nat_transient_artifacts(
    root: Path, *, require_complete: bool = True
) -> None:
    """Remove controller transients, leaving one exact replayable evidence tree."""
    root = root.resolve()
    validate_selected_nat_control_file_absence(root)
    allowed_files = {
        relative
        for roles in selected_nat_manifest_paths().values()
        for relative in roles.values()
    }
    for profile in ("cone-direct", "restrictive-relay"):
        scan = load_selected_nat_json(root / "cells" / profile / "canary-scan.json")
        stderr_paths = {
            str(record.get("path"))
            for artifact_class in scan.get("artifact_classes", [])
            if isinstance(artifact_class, dict) and artifact_class.get("class") == "log"
            for record in artifact_class.get("files", [])
            if isinstance(record, dict)
            and isinstance(record.get("path"), str)
            and re.fullmatch(r"command-[0-9]{4,}\.stderr", str(record.get("path")))
        }
        if len(stderr_paths) != 4:
            raise LabError("selected NAT transient pruning lacks four stderr authorities")
        allowed_files.update(f"cells/{profile}/{relative}" for relative in stderr_paths)
        allowed_files.update(
            {
                f"cells/{profile}/outputs/provision/private/node-a.bundle",
                f"cells/{profile}/outputs/provision/private/node-b.bundle",
            }
        )
    opaque_roots = {
        f"cells/{profile}/outputs/provision/{node}"
        for profile in ("cone-direct", "restrictive-relay")
        for node in ("node-a", "node-b")
    }
    relay_private = "cells/restrictive-relay/outputs/provision/relay/private"
    allowed_directories = {"", *opaque_roots, relay_private}
    for relative in allowed_files | opaque_roots | {relay_private}:
        for parent in Path(relative).parents:
            if str(parent) != ".":
                allowed_directories.add(parent.as_posix())

    discard_files = {
        "commands.jsonl",
        "events.jsonl",
        "docker-capabilities.json",
        "host-environment.json",
        "build-inputs.json",
        "base-image-identity.json",
        "selected-build-command.json",
        "image-id.txt",
        "build-metadata.json",
        "image-identity.json",
        "binary-inventory.json",
        "selected-runtime-package-inventory.tsv",
        "selected-environment.json",
    }
    route_log_paths: set[str] = set()
    for profile in ("cone-direct", "restrictive-relay"):
        prefix = f"cells/{profile}"
        discard_files.update(
            {
                f"{prefix}/commands.jsonl",
                f"{prefix}/docker-capabilities.json",
                f"{prefix}/host-environment.json",
                f"{prefix}/runtime-package-inventory.tsv",
                f"{prefix}/restricted-state-containment.json",
            }
        )
        if require_complete:
            route_receipts = load_selected_nat_json(root / prefix / "route-init-removal.json")
            if not isinstance(route_receipts, list) or len(route_receipts) != 2:
                raise LabError("selected NAT route initializer pruning authority differs")
            for index, role in enumerate(("route-a", "route-b")):
                record = route_receipts[index]
                expected_name = f"reap-aster-lab-{role}-command-"
                if (
                    not isinstance(record, dict)
                    or record.get("role") != role
                    or not isinstance(record.get("log"), str)
                    or not re.fullmatch(
                        rf"{re.escape(expected_name)}[0-9]{{4,}}\.log",
                        record["log"],
                    )
                    or record.get("log_sha256") != hashlib.sha256(b"").hexdigest()
                ):
                    raise LabError("selected NAT route initializer log authority differs")
                relative = f"{prefix}/{record['log']}"
                route_log_paths.add(relative)
                discard_files.add(relative)

    expected_linked_logs: dict[tuple[str, str], int] = {}
    for profile in ("cone-direct", "restrictive-relay"):
        expected_linked_logs[(profile, "reap-provision")] = 2
        for role in ("node-a", "nat-a", "nat-b", "node-b"):
            expected_linked_logs[(profile, f"cleanup-{role}")] = 1
    expected_linked_logs[("restrictive-relay", "cleanup-infra")] = 1

    def linked_log_key(relative: str) -> tuple[str, str] | None:
        matched = re.fullmatch(
            r"cells/(cone-direct|restrictive-relay)/"
            r"(reap-aster-lab-provision|cleanup-aster-lab-(node-a|nat-a|nat-b|node-b|infra))"
            r"-command-[0-9]{4,}\.log",
            relative,
        )
        if matched is None:
            return None
        profile = matched.group(1)
        stem = matched.group(2)
        key = (profile, "reap-provision")
        if stem != "reap-aster-lab-provision":
            key = (profile, f"cleanup-{stem.removeprefix('cleanup-aster-lab-')}")
        return key if key in expected_linked_logs else None

    for scope in (root, root / "cells" / "cone-direct", root / "cells" / "restrictive-relay"):
        command_receipt = scope / "commands.jsonl"
        try:
            metadata = os.lstat(command_receipt)
        except FileNotFoundError:
            if require_complete:
                raise LabError("selected NAT command receipt is absent before pruning")
            continue
        if (
            not stat.S_ISREG(metadata.st_mode)
            or stat.S_ISLNK(metadata.st_mode)
            or metadata.st_uid != os.getuid()
            or metadata.st_nlink != 1
            or metadata.st_size > 32 * 1024 * 1024
        ):
            raise LabError("selected NAT command receipt is unsafe before pruning")
        prefix = "" if scope == root else f"cells/{scope.name}/"
        try:
            lines = command_receipt.read_text(encoding="utf-8", errors="strict").splitlines()
        except (OSError, UnicodeError) as error:
            raise LabError("selected NAT command receipt could not be read") from error
        for index, line in enumerate(lines):
            try:
                record = json.loads(line)
            except json.JSONDecodeError as error:
                raise LabError("selected NAT command receipt contains malformed JSON") from error
            if not isinstance(record, dict):
                raise LabError("selected NAT command receipt record is not an object")
            for stream in ("stdout", "stderr"):
                name = record.get(stream)
                if not isinstance(name, str) or not re.fullmatch(
                    r"command-[0-9]{4,}\." + stream, name
                ):
                    raise LabError(
                        f"selected NAT command receipt record {index} has an invalid stream"
                    )
                discard_files.add(prefix + name)

    discard_roots = {"build-context"}
    discard_directories = {
        "build-context",
        "cells/restrictive-relay/outputs/infra",
    }
    directory_flags = (
        os.O_RDONLY
        | getattr(os, "O_DIRECTORY", 0)
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_NOFOLLOW", 0)
    )
    file_flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)

    def below(relative: str, roots: set[str]) -> bool:
        return any(relative == value or relative.startswith(value + "/") for value in roots)

    def classify(relative: str, *, directory: bool) -> str:
        if directory:
            if relative in allowed_directories or below(relative, opaque_roots):
                return "keep"
            if relative in discard_directories or below(relative, discard_roots):
                return "discard"
        else:
            if relative in allowed_files or below(relative, opaque_roots):
                return "keep"
            if (
                relative in discard_files
                or linked_log_key(relative) is not None
                or below(relative, discard_roots)
            ):
                return "discard"
        raise LabError(f"selected NAT transient pruning found unexpected path: {relative}")

    budget = {"entries": 0}
    observed_linked_logs: dict[tuple[str, str], int] = {}
    observed_route_logs: set[str] = set()

    def traverse(
        descriptor: int, relative_directory: str, *, mutate: bool, depth: int
    ) -> None:
        if depth > 64:
            raise LabError("selected NAT transient tree exceeds its depth bound")
        if relative_directory in opaque_roots:
            return
        try:
            names = sorted(os.listdir(descriptor))
        except OSError as error:
            raise LabError("selected NAT transient tree could not be enumerated") from error
        budget["entries"] += len(names)
        if budget["entries"] > 200_000:
            raise LabError("selected NAT transient tree exceeds its entry bound")
        removed: set[str] = set()
        for name in names:
            if not name or name in {".", ".."} or "/" in name or "\x00" in name:
                raise LabError("selected NAT transient tree has a noncanonical name")
            relative = (
                f"{relative_directory}/{name}" if relative_directory else name
            )
            try:
                before = os.stat(name, dir_fd=descriptor, follow_symlinks=False)
            except OSError as error:
                raise LabError("selected NAT transient entry could not be inspected") from error
            if before.st_uid != os.getuid() or stat.S_ISLNK(before.st_mode):
                raise LabError("selected NAT transient tree contains an unsafe entry")
            if stat.S_ISDIR(before.st_mode):
                disposition = classify(relative, directory=True)
                try:
                    child = os.open(name, directory_flags, dir_fd=descriptor)
                except OSError as error:
                    raise LabError("selected NAT transient directory changed while opening") from error
                try:
                    opened = os.fstat(child)
                    if (
                        not stat.S_ISDIR(opened.st_mode)
                        or (opened.st_dev, opened.st_ino) != (before.st_dev, before.st_ino)
                    ):
                        raise LabError("selected NAT transient directory identity changed")
                    traverse(child, relative, mutate=mutate, depth=depth + 1)
                    final = os.fstat(child)
                    path_final = os.stat(name, dir_fd=descriptor, follow_symlinks=False)
                    if any(
                        not stat.S_ISDIR(item.st_mode)
                        or (item.st_dev, item.st_ino) != (opened.st_dev, opened.st_ino)
                        for item in (final, path_final)
                    ):
                        raise LabError("selected NAT transient directory changed during traversal")
                    if disposition == "keep" and mutate:
                        os.fchmod(child, 0o700)
                finally:
                    os.close(child)
                if disposition == "discard" and mutate:
                    try:
                        os.rmdir(name, dir_fd=descriptor)
                        os.fsync(descriptor)
                    except OSError as error:
                        raise LabError("selected NAT transient directory could not be removed") from error
                    removed.add(name)
                continue
            if not stat.S_ISREG(before.st_mode) or before.st_nlink != 1:
                raise LabError("selected NAT transient tree contains a special or linked file")
            disposition = classify(relative, directory=False)
            linked_key = linked_log_key(relative)
            if linked_key is not None:
                observed_linked_logs[linked_key] = observed_linked_logs.get(linked_key, 0) + 1
            if relative in route_log_paths:
                observed_route_logs.add(relative)
                if before.st_size != 0:
                    raise LabError("selected NAT route initializer log was not empty")
            try:
                opened_file = os.open(name, file_flags, dir_fd=descriptor)
            except OSError as error:
                raise LabError("selected NAT transient file changed while opening") from error
            try:
                opened = os.fstat(opened_file)
                path_final = os.stat(name, dir_fd=descriptor, follow_symlinks=False)
                if any(
                    not stat.S_ISREG(item.st_mode)
                    or item.st_nlink != 1
                    or (item.st_dev, item.st_ino) != (opened.st_dev, opened.st_ino)
                    for item in (opened, path_final)
                ) or (opened.st_dev, opened.st_ino) != (before.st_dev, before.st_ino):
                    raise LabError("selected NAT transient file identity changed")
                if relative in route_log_paths and any(
                    item.st_size != 0 for item in (opened, path_final)
                ):
                    raise LabError("selected NAT route initializer log changed size")
            finally:
                os.close(opened_file)
            if disposition == "discard" and mutate:
                try:
                    os.unlink(name, dir_fd=descriptor)
                    os.fsync(descriptor)
                except OSError as error:
                    raise LabError("selected NAT transient file could not be removed") from error
                removed.add(name)
        try:
            final_names = sorted(os.listdir(descriptor))
        except OSError as error:
            raise LabError("selected NAT transient tree could not be re-enumerated") from error
        expected_names = sorted(set(names) - removed) if mutate else names
        if final_names != expected_names:
            raise LabError("selected NAT transient tree changed during pruning")

    root_descriptor = os.open(root, directory_flags)
    try:
        opened_root = os.fstat(root_descriptor)
        if (
            not stat.S_ISDIR(opened_root.st_mode)
            or opened_root.st_uid != os.getuid()
            or stat.S_IMODE(opened_root.st_mode) != 0o700
        ):
            raise LabError("selected NAT transient root metadata differs")
        traverse(root_descriptor, "", mutate=False, depth=0)
        if require_complete and (
            observed_linked_logs != expected_linked_logs
            or observed_route_logs != route_log_paths
        ):
            raise LabError("selected NAT linked transient log inventory differs")
        budget["entries"] = 0
        observed_linked_logs.clear()
        observed_route_logs.clear()
        traverse(root_descriptor, "", mutate=True, depth=0)
        if require_complete and (
            observed_linked_logs != expected_linked_logs
            or observed_route_logs != route_log_paths
        ):
            raise LabError("selected NAT linked transient log inventory changed while pruning")
        os.fsync(root_descriptor)
    finally:
        os.close(root_descriptor)
    validate_selected_nat_control_file_absence(root)


def run_selected_nat_replay_tool(arguments: Sequence[str], *, label: str) -> str:
    """Run one bounded replay tool without mutating the completed raw evidence root."""
    try:
        completed = subprocess.run(
            [str(value) for value in arguments],
            cwd=WORKSPACE,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            shell=False,
            check=False,
            timeout=120,
        )
    except (OSError, subprocess.TimeoutExpired) as error:
        raise LabError(f"selected NAT {label} could not complete") from error
    if (
        len(completed.stdout.encode("utf-8")) > 1024 * 1024
        or len(completed.stderr.encode("utf-8")) > 1024 * 1024
    ):
        raise LabError(f"selected NAT {label} output exceeds 1 MiB")
    if completed.returncode != 0:
        diagnostic = completed.stderr.strip().replace("\n", " ")[:512]
        raise LabError(f"selected NAT {label} failed: {diagnostic}")
    return completed.stdout


def selected_nat_curated_manifest(root: Path) -> dict[str, Any]:
    root = root.resolve()
    metadata = os.lstat(root)
    if (
        not stat.S_ISDIR(metadata.st_mode)
        or stat.S_ISLNK(metadata.st_mode)
        or metadata.st_uid != os.getuid()
        or (metadata.st_mode & 0o777) != 0o700
    ):
        raise LabError("selected NAT curated manifest root metadata differs")
    entries = []
    for scope, roles in selected_nat_manifest_paths().items():
        for role, relative in roles.items():
            path = selected_nat_safe_artifact(root, relative)
            item = os.lstat(path)
            if (
                item.st_nlink != 1
                or item.st_uid != os.getuid()
                or (item.st_mode & 0o777) != 0o600
                or item.st_size <= 0
            ):
                raise LabError("selected NAT curated artifact metadata differs")
            if role.endswith("-pcap"):
                if item.st_size < 24 or item.st_size > SELECTED_NAT_MAX_PCAP_BYTES:
                    raise LabError("selected NAT packet capture exceeds its exact bound")
                sensitivity, retention = "restricted-pcap", "external-restricted"
            elif role in {"relay-ca-der", "relay-cert-der"}:
                sensitivity, retention = "public-certificate", "retained-public"
            elif role.endswith("-log") or role in {"events", "prepare-log"}:
                sensitivity, retention = "sanitized-log", "retained-sanitized"
            else:
                sensitivity, retention = "public-metadata", "retained-sanitized"
            entries.append(
                {
                    "cell": scope,
                    "role": role,
                    "path": relative,
                    "type": "regular",
                    "nlink": 1,
                    "bytes": item.st_size,
                    "sha256": sha256_file(path),
                    "mode": "0600",
                    "owner": "current-runner",
                    "sensitivity": sensitivity,
                    "retention": retention,
                }
            )
    entries.sort(key=lambda entry: entry["path"])
    lines = b"".join(
        f"{entry['sha256']}  {entry['path']}\n".encode("ascii")
        for entry in entries
    )
    return {
        "format": "sha256-two-space-relative-v1",
        "root_type": "directory",
        "root_mode": "0700",
        "root_owner": "current-runner",
        "entries": entries,
        "records": len(entries),
        "manifest_bytes": len(lines),
        "artifact_bytes": sum(entry["bytes"] for entry in entries),
        "sha256": hashlib.sha256(lines).hexdigest(),
        "secret_artifacts": (
            "excluded-from-curated-manifest-retained-external-restricted"
        ),
        "pcap_contents": "external-restricted-not-embedded",
    }


def load_selected_nat_json(path: Path, *, maximum: int = 8 * 1024 * 1024) -> Any:
    if path.is_symlink() or not path.is_file():
        raise LabError(f"selected NAT projection input is missing or symbolic: {path}")
    if path.stat().st_size <= 0 or path.stat().st_size > maximum:
        raise LabError(f"selected NAT projection input exceeds its bound: {path}")
    with path.open(encoding="utf-8") as stream:
        return json.load(stream)


def selected_nat_receipt_integer(fields: dict[str, Any], name: str) -> int:
    value = fields.get(name)
    if isinstance(value, int) and not isinstance(value, bool) and value >= 0:
        return value
    if isinstance(value, str) and re.fullmatch(r"0|[1-9][0-9]*", value):
        return int(value)
    raise LabError(f"selected NAT projection field {name} is not a nonnegative integer")


def selected_nat_receipt_boolean(fields: dict[str, Any], name: str) -> bool:
    value = fields.get(name)
    if isinstance(value, bool):
        return value
    if value in {"true", "false"}:
        return value == "true"
    raise LabError(f"selected NAT projection field {name} is not a Boolean")


def project_selected_nat_cell(root: Path, profile: str) -> dict[str, Any]:
    cell_root = root / "cells" / profile
    finalization = load_selected_nat_json(cell_root / "selected-nat-finalization.json")
    runtime = load_selected_nat_json(cell_root / "selected-nat-runtime.json")
    node_results = {
        role: load_selected_nat_json(cell_root / f"{role}-result.json")
        for role in ["node-a", "node-b"]
    }
    if (
        finalization.get("profile") != profile
        or finalization.get("status") != "pass"
        or runtime.get("profile") != profile
        or runtime.get("legacy_ports_4476_4477") is not False
    ):
        raise LabError("selected NAT cell finalization differs during projection")
    mission_authority, _ = selected_nat_runtime_identity_domain(runtime, profile)
    nodes = runtime["nodes"]
    for role in ("node-a", "node-b"):
        ready = node_results[role].get("ready")
        if not isinstance(ready, dict) or ready.get("mission_authority") != mission_authority:
            raise LabError("selected NAT READY mission authority differs during projection")
    endpoints = [
        {
            "role": role,
            "carrier_id": nodes[name]["carrier_id"],
            "mission_id": nodes[name]["mission_id"],
            "fresh": True,
        }
        for role, name in [("sender", "a"), ("receiver", "b")]
    ]
    publish = finalization["event"]["publish"]
    verify = finalization["event"]["verify"]
    if publish["event_id"] != verify["event_id"]:
        raise LabError("selected NAT publish/verify Event IDs differ during projection")
    event = {
        "event_id": publish["event_id"],
        "publisher": publish["publisher"],
        "payload_sha256": publish["payload_sha256"],
        "sealed_sha256": publish["sealed_sha256"],
        "canary_sha256": publish["canary_sha256"],
        "payload_bytes": selected_nat_receipt_integer(publish, "payload_bytes"),
        "source_sequence": selected_nat_receipt_integer(publish, "sequence"),
        "source_inserted": selected_nat_receipt_boolean(publish, "inserted"),
        "destination_deliveries": selected_nat_receipt_integer(verify, "deliveries"),
        "destination_attempt": selected_nat_receipt_integer(verify, "attempt"),
        "acknowledged": selected_nat_receipt_boolean(verify, "acknowledged"),
        "empty_after_ack": selected_nat_receipt_boolean(verify, "empty_after_ack"),
        "replay_ack": verify["replay_ack"],
        "replay_subscription": verify["replay_subscription"],
        "exact_query": (
            selected_nat_receipt_boolean(publish, "exact_query")
            and selected_nat_receipt_boolean(verify, "exact_query")
        ),
        "exact_event_id_match": publish["event_id"] == verify["event_id"],
    }
    final_noops = [node_results[role]["final_noop"] for role in ["node-a", "node-b"]]
    if any(
        selected_nat_receipt_integer(noop, field) != 0
        for noop in final_noops
        for field in SELECTED_NAT_NOOP_FIELDS
    ):
        raise LabError("selected NAT projected reconciliation is not an exact no-op")
    contact_count = sum(
        selected_nat_receipt_integer(node_results[role]["stop"], "contacts")
        for role in ["node-a", "node-b"]
    )
    if not 1 <= contact_count <= 1_024:
        raise LabError("selected NAT projected contact count exceeds its bound")
    reconciliation = {
        "status": "pass",
        "contacts": contact_count,
        **{field: 0 for field in sorted(SELECTED_NAT_NOOP_FIELDS)},
    }
    selected_path = "Direct" if profile == "cone-direct" else "Relay"
    witnesses = []
    for role, node_role in [("sender", "node-a"), ("receiver", "node-b")]:
        result = node_results[node_role]
        if result.get("path") != selected_path or result.get("saturated") is not False:
            raise LabError("selected NAT projected path witness differs")
        witnesses.append(
            {
                "role": role,
                "selected": selected_path,
                "transition_count": selected_nat_receipt_integer(
                    result, "transition_count"
                ),
                "transitions_saturated": False,
            }
        )
    nft_names = (
        [
            "aster_cone_dnat",
            "aster_cone_snat",
            "aster_cone_forward_in",
            "aster_cone_forward_out",
        ]
        if profile == "cone-direct"
        else [
            "aster_restrict_direct_drop",
            "aster_restrict_relay_https",
            "aster_restrict_relay_http",
            "aster_restrict_established",
        ]
    )
    counters = []
    for router in ["nat-a", "nat-b"]:
        evidence = finalization["nft"][router]
        for name in nft_names:
            before = evidence["before"][name]
            after = evidence["after"][name]
            delta = evidence["delta"][name]
            counters.append(
                {
                    "router": router,
                    "name": name,
                    "before_packets": selected_nat_receipt_integer(before, "packets"),
                    "after_packets": selected_nat_receipt_integer(after, "packets"),
                    "delta_packets": selected_nat_receipt_integer(delta, "packets"),
                    "before_bytes": selected_nat_receipt_integer(before, "bytes"),
                    "after_bytes": selected_nat_receipt_integer(after, "bytes"),
                    "delta_bytes": selected_nat_receipt_integer(delta, "bytes"),
                }
            )
    capture_records = []
    for router in ["nat-a", "nat-b"]:
        capture = finalization["pcap"][router]
        capture_records.append(
            {
                "role": f"{router}-wan",
                "bytes": selected_nat_receipt_integer(capture, "bytes"),
                "packets": selected_nat_receipt_integer(capture, "packets"),
                "dropped_packets": selected_nat_receipt_integer(capture, "drop_count"),
                "sha256": capture["sha256"],
                "manifest_role": f"{router}-wan-pcap",
            }
        )
    proof = finalization["tuple_proof"]
    direct_packets = sum(
        selected_nat_receipt_integer(proof[router], "direct_udp_packets")
        for router in ["nat-a", "nat-b"]
    )
    relay_https_packets = sum(
        selected_nat_receipt_integer(proof[router], "relay_https_tcp_packets")
        for router in ["nat-a", "nat-b"]
    )
    relay_http_packets = sum(
        selected_nat_receipt_integer(proof[router], "relay_http_tcp_packets")
        for router in ["nat-a", "nat-b"]
    )
    pcap = {
        "captures": capture_records,
        "tuple_summary_sha256": sha256_file(cell_root / "pcap-tuple-summary.json"),
        "tuple_proof": {
            "direct_cross_nat_packets": direct_packets if profile == "cone-direct" else 0,
            "direct_probe_packets": direct_packets if profile == "cone-direct" else 0,
            "controlled_relay_https_packets": relay_https_packets,
            "controlled_relay_http_packets": relay_http_packets,
            "unexpected_public_relay_packets": 0,
            "unexpected_hosted_discovery_packets": 0,
        },
    }
    if profile == "cone-direct":
        relay = {
            "mode": "disabled",
            "origin": "none",
            "tls_mode": "not-applicable",
            "server_trust_claim": "not-applicable",
            "client_trust_mode": "not-applicable",
            "root_fingerprint_sha256": "not-applicable",
            "allowlist_mode": "not-applicable",
            "allowlist_count": 0,
            "allowlist_sha256": "not-applicable",
            "key_cache_capacity": 0,
            "client_rx_bytes_per_second": 0,
            "client_rx_max_burst_bytes": 0,
            "max_admitted_connections": 0,
            "pre_auth_connection_cap": "not-applicable",
            "observed_active_sessions_peak": 0,
            "accepted_sessions": 0,
            "rejected_sessions": 0,
            "secrets_logged": False,
        }
        relay_origin = "none"
    else:
        config = load_selected_nat_json(cell_root / "relay-config.json")
        relay_receipt = finalization["relay"]
        stop = relay_receipt["stop"]
        allowlist = config["allowlist"]
        if not isinstance(allowlist, list) or len(allowlist) != 2:
            raise LabError("selected NAT relay allowlist differs during projection")
        expected_allowlist = sorted(endpoint["carrier_id"] for endpoint in endpoints)
        if allowlist != expected_allowlist:
            raise LabError("selected NAT relay allowlist is not its exact endpoint identities")
        expected_relay_config = {
            "tls_mode": "manual-der-certificate",
            "server_trust_claim": "none",
            "client_trust_mode": "explicit-der-root-pin",
            "max_admitted_connections": SELECTED_NAT_RELAY_MAX_ADMITTED_CONNECTIONS,
            "pre_auth_connection_cap": "not-enforced",
        }
        if any(config.get(key) != value for key, value in expected_relay_config.items()):
            raise LabError("selected NAT relay trust or admission configuration differs")
        relay_origin = str(config["origin"]).removesuffix("/")
        relay = {
            "mode": "controlled",
            "origin": relay_origin,
            "tls_mode": config["tls_mode"],
            "server_trust_claim": config["server_trust_claim"],
            "client_trust_mode": config["client_trust_mode"],
            "root_fingerprint_sha256": config["root_fingerprint_sha256"],
            "allowlist_mode": "exact-cli-identities",
            "allowlist_count": len(allowlist),
            "allowlist_sha256": sha256_text("\n".join(allowlist) + "\n"),
            "key_cache_capacity": selected_nat_receipt_integer(stop, "key_cache_capacity"),
            "client_rx_bytes_per_second": selected_nat_receipt_integer(
                stop, "client_rx_bytes_per_second"
            ),
            "client_rx_max_burst_bytes": selected_nat_receipt_integer(
                stop, "client_rx_max_burst_bytes"
            ),
            "max_admitted_connections": selected_nat_receipt_integer(
                stop, "max_admitted_connections"
            ),
            "pre_auth_connection_cap": stop["pre_auth_connection_cap"],
            "observed_active_sessions_peak": selected_nat_receipt_integer(
                stop, "peak_active_connections"
            ),
            "accepted_sessions": selected_nat_receipt_integer(stop, "sessions"),
            "rejected_sessions": selected_nat_receipt_integer(
                stop, "denied_connections"
            ),
            "secrets_logged": False,
        }
    scan = finalization["canary_scan"]
    scanned = sum(
        len(artifact_class["files"]) for artifact_class in scan["artifact_classes"]
    )
    canary_scan = {
        "classes": scan["classes"],
        "scan_targets": ["finalized-public-artifacts", "wan-pcaps"],
        "positive_control": {
            "status": "pass",
            "expected_matches": scan["positive_control"]["expected"],
            "observed_matches": scan["positive_control"]["observed"],
            "class_match_counts": scan["positive_control"]["class_match_counts"],
        },
        "chronology": scan["chronology"],
        "artifacts_scanned": scanned,
        "class_match_counts": scan["class_match_counts"],
        "match_count": scan["matches"],
    }
    secret_cleanup = finalization["secret_cleanup"]
    cleanup_summary = load_selected_nat_json(cell_root / "cleanup-summary.json")
    if cleanup_summary.get("all_owned_resources_removed") is not True:
        raise LabError("selected NAT cleanup summary differs during projection")
    cleanup = {
        "status": "pass",
        "canary_control_file_disposition": secret_cleanup[
            "canary_control_file_disposition"
        ],
        "canary_control_file_previous_bytes": secret_cleanup[
            "canary_control_file_previous_bytes"
        ],
        "relay_private_key_file_disposition": secret_cleanup[
            "relay_private_key_file_disposition"
        ],
        "canary_control_file_absent_after_cleanup": secret_cleanup[
            "canary_control_file_absent_after_cleanup"
        ],
        "relay_private_key_file_absent_after_cleanup": secret_cleanup[
            "relay_private_key_file_absent_after_cleanup"
        ],
        "assurance": secret_cleanup["assurance"],
        "physical_sanitization": secret_cleanup["physical_sanitization"],
        "containers_remaining": 0,
        "networks_remaining": 0,
        "namespaces_remaining": 0,
    }
    return {
        "name": profile,
        "status": "pass",
        "nat_profile": "cone" if profile == "cone-direct" else "restrictive",
        "topology": {
            "sender_bind": "10.250.1.10:44000",
            "receiver_bind": "10.250.2.10:44000",
            "nat_a_external": "10.250.0.11:44000",
            "nat_b_external": "10.250.0.12:44000",
            "sender_default_gateway": "10.250.1.1",
            "receiver_default_gateway": "10.250.2.1",
            "relay_origin": relay_origin,
        },
        "infrastructure": {
            "controlled_relay": profile == "restrictive-relay",
            "hosted_discovery": False,
            "public_relay": False,
            "default_relay": False,
            "public_relay_fallback": False,
            "port_mapper": False,
        },
        "endpoints": endpoints,
        "event": event,
        "reconciliation": reconciliation,
        "path": {"witnesses": witnesses},
        "nft": {"namespace": "nat-a,nat-b", "counters": counters},
        "pcap": pcap,
        "relay": relay,
        "canary_scan": canary_scan,
        "cleanup": cleanup,
    }


def project_selected_nat_receipt(root: Path) -> dict[str, Any]:
    """Derive the canonical public receipt solely from a completed raw suite root."""
    root = root.resolve()
    validate_selected_nat_control_file_absence(root)
    summary = load_selected_nat_json(root / "selected-nat-suite.json")
    if summary.get("profile") != "all" or summary.get("status") != "pass":
        raise LabError("selected NAT canonical receipt requires the completed all-profile suite")
    source = summary.get("source_identity")
    build = summary.get("build_identity")
    if not isinstance(source, dict) or not isinstance(build, dict):
        raise LabError("selected NAT suite lacks embedded source/build provenance")
    if source != load_selected_nat_json(root / "source-identity.json"):
        raise LabError("selected NAT suite source identity differs from its raw audit receipt")
    if build != load_selected_nat_json(root / "selected-build.json"):
        raise LabError("selected NAT suite build identity differs from its raw audit receipt")
    if (
        source.get("build_input_manifest_sha256") != build.get("input_manifest_sha256")
        or source.get("dockerfile_sha256") != build.get("dockerfile_sha256")
    ):
        raise LabError("selected NAT projected source/build input bindings differ")
    cells = [
        project_selected_nat_cell(root, profile)
        for profile in ["cone-direct", "restrictive-relay"]
    ]
    validate_selected_nat_runtime_identity_domains(
        [
            (
                profile,
                load_selected_nat_json(
                    root / "cells" / profile / "selected-nat-runtime.json"
                ),
            )
            for profile in ["cone-direct", "restrictive-relay"]
        ]
    )
    inventories = [
        load_selected_nat_json(root / "cells" / profile / "binary-inventory.json")
        for profile in ["cone-direct", "restrictive-relay"]
    ]
    if inventories[0] != inventories[1]:
        raise LabError("selected NAT cells executed different binary inventories")
    for profile in ["cone-direct", "restrictive-relay"]:
        cell_root = root / "cells" / profile
        if load_selected_nat_json(cell_root / "source-identity.json") != source:
            raise LabError("selected NAT cell source identity differs from the suite")
        image = load_selected_nat_json(cell_root / "image-identity.json")
        if image.get("id") != build.get("image_id"):
            raise LabError("selected NAT cell image identity differs from the suite build")
    artifacts = [
        {
            "role": record["role"],
            "name": record["name"],
            "bytes": record["bytes"],
            "sha256": record["sha256"],
        }
        for record in inventories[0]
    ]
    environment = build["environment"]
    image_id = build["image_id"]
    document = {
        "schema": SELECTED_NAT_RECEIPT_SCHEMA,
        "status": "pass",
        "claim": SELECTED_NAT_RECEIPT_CLAIM,
        "source": {
            "commit": source["commit"],
            "tree": source["tree"],
            "signature": "verified",
            "cargo_lock_sha256": source["cargo_lock_sha256"],
            "requirements_sha256": source["requirements_sha256"],
            "worktree": "clean-tracked-and-untracked-nonignored",
        },
        "build": {
            "command": build["command"],
            "target": "aarch64-unknown-linux-gnu",
            "artifacts": artifacts,
            "container": {
                "reference": SELECTED_NAT_IMAGE,
                "dockerfile_sha256": build["dockerfile_sha256"],
                "input_manifest_sha256": build["input_manifest_sha256"],
                "base_image": LAB_BASE_IMAGE,
                "build_run_id": build["build_run_id"],
                "image_id": image_id,
                "image_config_digest": build["image_config_digest"],
            },
        },
        "environment": {
            "physical_hosts": 1,
            "isolation": "docker-linux-network-namespaces",
            "host_os": environment["host_os"],
            "host_arch": environment["host_arch"],
            "kernel": environment["kernel"],
            "docker_version": environment["docker_version"],
            "orbstack_version": environment["orbstack_version"],
            "orchestrator_exit_code": 0,
            "cleanup": "pass",
            "clock_assurance": "filesystem-metadata-not-independent",
        },
        "cells": cells,
        "raw_manifest": selected_nat_curated_manifest(root),
        "limitations": dict(SELECTED_NAT_LIMITATIONS),
    }
    encoded = json.dumps(
        document, sort_keys=True, separators=(",", ":"), ensure_ascii=True
    ).encode("ascii") + b"\n"
    if len(encoded) > 128 * 1024:
        raise LabError("selected NAT canonical receipt exceeds 128 KiB")
    return document


def selected_nat_nft_snapshot(
    ctx: RunContext, *, role: str, profile: str, phase: str
) -> tuple[dict[str, dict[str, int]], Path]:
    if phase not in {"before", "after"}:
        raise LabError("selected NAT nft snapshot phase is invalid")
    result = ctx.runner.run(
        [
            require_docker(),
            "exec",
            FIXED_CONTAINER_NAMES[role],
            "/usr/sbin/nft",
            "--json",
            "list",
            "ruleset",
        ]
    )
    counters = selected_nat_counter_snapshot(result.stdout, profile)
    path = ctx.run_dir / f"{role}-nft-{phase}.json"
    write_exclusive_json(
        path,
        {
            "schema": SCHEMA,
            "profile": profile,
            "role": role,
            "phase": phase,
            "counters": counters,
            "ruleset_sha256": sha256_text(result.stdout),
        },
    )
    return counters, path


def selected_nat_capture_program(
    *, wan_interface: str, capture_path: str, profile: str
) -> list[str]:
    if profile == "cone-direct":
        expression = ["udp", "port", str(SELECTED_NAT_NODE_PORT)]
    elif profile == "restrictive-relay":
        expression = [
            "(",
            "udp",
            "port",
            str(SELECTED_NAT_NODE_PORT),
            ")",
            "or",
            "(",
            "tcp",
            "port",
            str(SELECTED_NAT_RELAY_HTTPS_PORT),
            ")",
            "or",
            "(",
            "tcp",
            "port",
            str(SELECTED_NAT_RELAY_HTTP_PORT),
            ")",
        ]
    else:
        raise LabError(f"unsupported selected NAT profile: {profile}")
    return [
        "/usr/bin/tcpdump",
        "--immediate-mode",
        "-Z",
        "tcpdump",
        "-i",
        wan_interface,
        "-s",
        "0",
        "-U",
        "-w",
        capture_path,
        *expression,
    ]


def start_selected_nat_capture(
    ctx: RunContext,
    *,
    role: str,
    wan_interface: str,
    output_dir: Path,
    profile: str,
) -> tuple[RunningCommand, Path]:
    capture_path = output_dir / f"{role}-wan.pcap"
    in_container = f"/output/{role}-wan.pcap"
    running = ctx.runner.start(
        [
            require_docker(),
            "exec",
            FIXED_CONTAINER_NAMES[role],
            *selected_nat_capture_program(
                wan_interface=wan_interface,
                capture_path=in_container,
                profile=profile,
            ),
        ]
    )
    wait_for_capture_ready(ctx, FIXED_CONTAINER_NAMES[role], in_container, capture_path)
    return running, capture_path


def stop_selected_nat_capture(
    ctx: RunContext,
    *,
    role: str,
    running: RunningCommand,
    capture_path: Path,
) -> dict[str, Any]:
    result = ctx.runner.run(
        [
            require_docker(),
            "exec",
            "--user",
            "tcpdump",
            FIXED_CONTAINER_NAMES[role],
            "/usr/bin/pkill",
            "--signal",
            "INT",
            "--exact",
            "tcpdump",
        ],
        check=False,
    )
    if result.returncode not in {0, 1}:
        raise LabError(f"could not stop selected NAT capture in {role}")
    deadline = time.monotonic() + 10
    while running.poll() is None and time.monotonic() < deadline:
        time.sleep(0.1)
    if running.poll() is None:
        running.terminate()
        raise LabError(f"selected NAT capture did not stop in {role}")
    running.finish(check=True)
    stderr_path = ctx.run_dir / running.stderr_name
    counts = tcpdump_terminal_counts(
        stderr_path.read_text(encoding="utf-8", errors="replace")
    )
    summary = parse_pcap_ipv4_tuples(capture_path)
    validate_tcpdump_pcap_packet_count(summary, counts)
    return {
        **summary,
        "role": role,
        "path": str(capture_path.relative_to(ctx.run_dir)),
        "drop_count": counts["dropped"],
        "tcpdump_stderr": running.stderr_name,
        "tcpdump_stderr_sha256": sha256_file(stderr_path),
    }


def selected_nat_cell_resources(profile: str) -> list[PlannedResource]:
    if profile not in SELECTED_NAT_COUNTERS:
        raise LabError(f"unsupported selected NAT profile: {profile}")
    by_role = {key: NetworkSpec.from_tuple(value) for key, value in NAT_NETWORKS.items()}
    resources = [
        PlannedResource("network", spec.name, role) for role, spec in by_role.items()
    ]
    roles = ["provision", "node-a", "nat-a", "route-a", "nat-b", "node-b", "route-b"]
    if profile == "restrictive-relay":
        roles.append("infra")
    resources.extend(
        PlannedResource("container", FIXED_CONTAINER_NAMES[role], role) for role in roles
    )
    return resources


def validate_selected_nat_prepare(
    value: str,
    *,
    scope: str,
    topic: str,
    manifest: dict[str, Any],
) -> dict[str, Any]:
    mission_authority = manifest.get("mission_authority")
    manifest_nodes = manifest.get("nodes")
    if (
        not isinstance(mission_authority, str)
        or not re.fullmatch(r"[0-9a-f]{64}", mission_authority)
        or not isinstance(manifest_nodes, dict)
        or set(manifest_nodes) != {"a", "b"}
    ):
        raise LabError("selected NAT prepare manifest identity domain is malformed")
    public_ids = [
        node.get(field)
        for node in manifest_nodes.values()
        if isinstance(node, dict)
        for field in ("mission_id", "carrier_id")
    ]
    if (
        len(public_ids) != 4
        or any(
            not isinstance(identity, str)
            or not re.fullmatch(r"[0-9a-f]{64}", identity)
            for identity in public_ids
        )
        or len(set(public_ids)) != 4
        or mission_authority in public_ids
    ):
        raise LabError("selected NAT prepare manifest identity domain overlaps")
    require_receipt_line_prefixes(
        value,
        ["SELECTED_NAT_PREPARE", "SELECTED_NAT_NODE", "SELECTED_NAT_NODE"],
    )
    prepare = exact_receipt(value, "SELECTED_NAT_PREPARE")
    require_receipt_keys(
        prepare,
        {
            "status",
            "version",
            "nodes",
            "scope",
            "topic",
            "manifest",
            "mission_authority",
            "mission_authority_shared",
            "mission_authority_disjoint",
            "mission_ids_distinct",
            "carrier_ids_distinct",
            "mission_carrier_disjoint",
            "subscriptions",
            "pre_inventory_events",
            "canary_sha256",
            "canary_bytes",
            "canary",
        },
        "SELECTED_NAT_PREPARE",
    )
    if (
        prepare.get("status") != "pass"
        or prepare.get("version") != "2"
        or prepare.get("nodes") != "2"
        or prepare.get("scope") != scope
        or prepare.get("topic") != topic
        or prepare.get("manifest") != "/output/manifest.tsv"
        or prepare.get("mission_authority") != mission_authority
        or prepare.get("mission_authority_shared") != "true"
        or prepare.get("mission_authority_disjoint") != "true"
        or prepare.get("mission_ids_distinct") != "true"
        or prepare.get("carrier_ids_distinct") != "true"
        or prepare.get("mission_carrier_disjoint") != "true"
        or prepare.get("subscriptions") != "2"
        or prepare.get("pre_inventory_events") != "0"
        or prepare.get("canary_sha256") != manifest["canary_sha256"]
        or prepare.get("canary_bytes") != "32"
        or prepare.get("canary") != "redacted"
    ):
        raise LabError("selected NAT prepare receipt differs")
    nodes = {}
    for line in value.splitlines():
        if not line.startswith("SELECTED_NAT_NODE "):
            continue
        node = parse_receipt_fields(line, "SELECTED_NAT_NODE")
        require_receipt_keys(
            node,
            {"name", "mission_id", "carrier_id"},
            "SELECTED_NAT_NODE",
        )
        name = node.get("name")
        if name not in {"a", "b"} or name in nodes:
            raise LabError("selected NAT prepare node receipt is invalid")
        expected = manifest["nodes"][name]
        if (
            node.get("mission_id") != expected["mission_id"]
            or node.get("carrier_id") != expected["carrier_id"]
        ):
            raise LabError("selected NAT prepare node identity differs from manifest")
        nodes[name] = node
    if set(nodes) != {"a", "b"}:
        raise LabError("selected NAT prepare omitted a node receipt")
    return {"prepare": prepare, "nodes": nodes}


def validate_selected_nat_publish(
    value: str, *, manifest: dict[str, Any]
) -> dict[str, str]:
    require_receipt_line_prefixes(value, ["SELECTED_NAT_PUBLISH"])
    record = exact_receipt(value, "SELECTED_NAT_PUBLISH")
    require_receipt_keys(
        record,
        {
            "status",
            "version",
            "publication_model",
            "node",
            "event_id",
            "publisher",
            "sequence",
            "inserted",
            "replay_publish",
            "pre_inventory_events",
            "post_inventory_events",
            "canary_sha256",
            "payload_sha256",
            "payload_bytes",
            "sealed_sha256",
            "exact_query",
        },
        "SELECTED_NAT_PUBLISH",
    )
    canary = manifest["canary_sha256"]
    if (
        record.get("status") != "pass"
        or record.get("version") != "2"
        or record.get("publication_model") != "numbered-v1"
        or record.get("node") != "a"
        or record.get("publisher") != manifest["nodes"]["a"]["mission_id"]
        or record.get("sequence") != "1"
        or record.get("inserted") != "true"
        or record.get("replay_publish") != "noop"
        or record.get("pre_inventory_events") != "0"
        or record.get("post_inventory_events") != "1"
        or record.get("canary_sha256") != canary
        or record.get("payload_sha256") != canary
        or record.get("payload_bytes") != "32"
        or record.get("sealed_sha256") != "not-exposed-by-production-api"
        or record.get("exact_query") != "true"
    ):
        raise LabError("selected NAT publish receipt differs")
    receipt_hex(record, "event_id")
    return record


def validate_selected_nat_verify(
    value: str,
    *,
    manifest: dict[str, Any],
    event_id: str,
) -> dict[str, str]:
    require_receipt_line_prefixes(value, ["SELECTED_NAT_VERIFY"])
    record = exact_receipt(value, "SELECTED_NAT_VERIFY")
    require_receipt_keys(
        record,
        {
            "status",
            "version",
            "node",
            "event_id",
            "publisher",
            "pre_inventory_events",
            "post_inventory_events",
            "canary_sha256",
            "payload_sha256",
            "payload_bytes",
            "sealed_sha256",
            "deliveries",
            "attempt",
            "acknowledged",
            "empty_after_ack",
            "replay_ack",
            "replay_subscription",
            "exact_query",
        },
        "SELECTED_NAT_VERIFY",
    )
    canary = manifest["canary_sha256"]
    if (
        record.get("status") != "pass"
        or record.get("version") != "1"
        or record.get("node") != "b"
        or record.get("publisher") != manifest["nodes"]["a"]["mission_id"]
        or record.get("event_id") != event_id
        or record.get("pre_inventory_events") != "0"
        or record.get("post_inventory_events") != "1"
        or record.get("canary_sha256") != canary
        or record.get("payload_sha256") != canary
        or record.get("payload_bytes") != "32"
        or record.get("sealed_sha256") != "not-exposed-by-production-api"
        or record.get("deliveries") != "1"
        or record.get("attempt") != "1"
        or record.get("acknowledged") != "true"
        or record.get("empty_after_ack") != "true"
        or record.get("replay_ack") != "noop"
        or record.get("replay_subscription") != "noop"
        or record.get("exact_query") != "true"
    ):
        raise LabError("selected NAT verify receipt differs")
    return record


def selected_nat_copy_log(source: Path, destination: Path) -> Path:
    if source.is_symlink() or not source.is_file():
        raise LabError("selected NAT source log is missing or symbolic")
    if source.stat().st_size > 16 * 1024 * 1024:
        raise LabError("selected NAT source log exceeds 16 MiB")
    write_exclusive_text(destination, source.read_text(encoding="utf-8", errors="replace"))
    return destination


def validate_selected_nat_command_ports(path: Path) -> None:
    """Reject legacy infrastructure ports without matching unrelated digests."""
    metadata = os.lstat(path)
    if (
        not stat.S_ISREG(metadata.st_mode)
        or stat.S_ISLNK(metadata.st_mode)
        or metadata.st_uid != os.getuid()
        or metadata.st_size > 128 * 1024 * 1024
    ):
        raise LabError("selected NAT command receipt is unsafe or exceeds 128 MiB")
    legacy = re.compile(
        r"(?:(?:[0-9]{1,3}\.){3}[0-9]{1,3}|[A-Za-z0-9.-]+):447[67](?:/|$)"
        r"|(?:^|=)447[67]$|\b(?:sport|dport|port)\s+447[67]\b"
    )
    with path.open(encoding="utf-8") as stream:
        for line in stream:
            try:
                record = json.loads(line)
            except json.JSONDecodeError as error:
                raise LabError("selected NAT command receipt is malformed") from error
            arguments = record.get("arguments") if isinstance(record, dict) else None
            if not isinstance(arguments, list) or any(
                not isinstance(argument, str) for argument in arguments
            ):
                raise LabError("selected NAT command receipt lacks exact arguments")
            if any(legacy.search(argument) for argument in arguments):
                raise LabError("selected NAT command stream contains legacy infrastructure ports")


def nat_container(
    ctx: RunContext,
    *,
    name: str,
    role: str,
    network: str,
    address: str,
    capabilities: Sequence[str],
    output_dir: Path,
    forwarding: bool = False,
) -> list[str]:
    return container_run_args(
        ctx,
        name=name,
        role=role,
        network=network,
        ip=address,
        detach=True,
        memory="256m",
        cpus="0.5",
        pids=64,
        capabilities=capabilities,
        root_user=True,
        entrypoint="/usr/bin/sleep",
        sysctls=["net.ipv4.ip_forward=1"] if forwarding else [],
        output_dir=output_dir,
        command=["infinity"],
    )


def wait_for_log_marker(
    ctx: RunContext, name: str, marker: str, timeout: float = 10.0
) -> None:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        state = ctx.runner.run(
            [require_docker(), "container", "inspect", name, "--format", "{{json .State}}"]
        )
        try:
            decoded = json.loads(state.stdout)
        except json.JSONDecodeError as error:
            raise LabError("Docker returned malformed detached-container state") from error
        logs = ctx.runner.run([require_docker(), "container", "logs", name], check=False)
        if logs.returncode != 0:
            raise LabError(f"could not read readiness logs for {name}")
        if marker in logs.stdout or marker in logs.stderr:
            if decoded.get("Running") is not True:
                raise LabError(f"container {name} emitted readiness then exited")
            return
        if decoded.get("Running") is not True:
            raise LabError(f"container {name} exited before readiness")
        time.sleep(0.25)
    raise LabError(f"container {name} did not emit readiness marker {marker!r}")


def capture_process_running(ctx: RunContext, container: str, capture_path: str) -> bool:
    process_table = ctx.runner.run(
        [require_docker(), "top", container, "-eo", "pid,comm,args"],
        check=False,
    )
    if process_table.returncode != 0:
        raise LabError(f"could not inspect capture process in {container}")
    return any(
        "tcpdump" in line and capture_path in line
        for line in process_table.stdout.splitlines()[1:]
    )


def wait_for_capture_ready(
    ctx: RunContext, container: str, in_container_path: str, host_path: Path
) -> None:
    deadline = time.monotonic() + 10.0
    while time.monotonic() < deadline:
        nonempty = ctx.runner.run(
            [require_docker(), "exec", container, "/usr/bin/test", "-s", in_container_path],
            check=False,
        )
        if capture_process_running(ctx, container, in_container_path) and nonempty.returncode == 0:
            if host_path.is_file() and host_path.stat().st_size >= 24:
                return
        time.sleep(0.25)
    raise LabError(f"tcpdump did not become ready in {container}")


def validate_pcap(path: Path) -> int:
    if path.is_symlink() or not path.is_file():
        raise LabError(f"packet capture is missing or symbolic: {path}")
    size = path.stat().st_size
    if size < 24:
        raise LabError(f"packet capture has no complete global header: {path}")
    with path.open("rb") as stream:
        magic = stream.read(4)
    if magic not in {
        bytes.fromhex("a1b2c3d4"),
        bytes.fromhex("d4c3b2a1"),
        bytes.fromhex("a1b23c4d"),
        bytes.fromhex("4d3cb2a1"),
    }:
        raise LabError(f"packet capture has an unknown pcap header: {path}")
    return size


def nested_values(value: Any, names: set[str]) -> list[Any]:
    result = []
    if isinstance(value, dict):
        for key, item in value.items():
            if str(key).lower() in names:
                result.append(item)
            result.extend(nested_values(item, names))
    elif isinstance(value, list):
        for item in value:
            result.extend(nested_values(item, names))
    return result


def tc_rate_bits(value: Any) -> int | None:
    if isinstance(value, bool):
        return None
    if isinstance(value, (int, float)) and float(value).is_integer():
        # Linux tc JSON exposes the kernel rate value in bytes per second.
        return int(value) * 8
    if not isinstance(value, str):
        return None
    match = re.fullmatch(
        r"([0-9]+(?:\.[0-9]+)?)\s*(bit|kbit|mbit|gbit|tbit|bps)?",
        value.strip().lower(),
    )
    if match is None:
        return None
    multiplier = {
        None: 1,
        "bit": 1,
        "bps": 1,
        "kbit": 1_000,
        "mbit": 1_000_000,
        "gbit": 1_000_000_000,
        "tbit": 1_000_000_000_000,
    }[match.group(2)]
    return round(float(match.group(1)) * multiplier)


def loss_probability_matches(value: Any, expected_percent: int) -> bool:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return False
    observed = float(value)
    expected_fraction = expected_percent / 100
    if math.isclose(observed, expected_fraction, rel_tol=1e-6, abs_tol=1e-9):
        return True
    if math.isclose(observed, float(expected_percent), rel_tol=1e-6, abs_tol=1e-9):
        return True
    if 0 <= observed <= 2**32 - 1:
        encoded_percent = observed / (2**32 - 1) * 100
        return math.isclose(encoded_percent, expected_percent, rel_tol=1e-5, abs_tol=1e-5)
    return False


def verify_qdisc_json(
    value: str,
    *,
    expected_bps: int | None = None,
    expected_loss_percent: int | None = None,
    expected_limit: int | None = None,
    expected_seed: int | None = None,
) -> None:
    try:
        decoded = json.loads(value)
    except json.JSONDecodeError as error:
        raise LabError("tc returned malformed qdisc JSON") from error
    if not isinstance(decoded, list):
        raise LabError("tc qdisc result is not a list")
    netem = [item for item in decoded if isinstance(item, dict) and item.get("kind") == "netem"]
    if len(netem) != 1:
        raise LabError("requested netem qdisc is not installed")
    if all(value is None for value in [expected_bps, expected_loss_percent, expected_limit, expected_seed]):
        return
    options = netem[0].get("options")
    if not isinstance(options, dict):
        raise LabError("netem qdisc has no structured options")
    if expected_limit is not None and expected_limit not in nested_values(options, {"limit"}):
        raise LabError("netem limit differs from the requested value")
    if expected_seed is not None and expected_seed not in nested_values(options, {"seed"}):
        raise LabError("netem random seed differs from the requested value")
    if expected_bps is not None:
        rates = nested_values(options, {"rate", "rate64"})
        if expected_bps not in {rate for item in rates if (rate := tc_rate_bits(item)) is not None}:
            raise LabError("netem rate differs from the requested value")
    if expected_loss_percent is not None:
        probabilities = nested_values(options, {"probability", "loss"})
        if expected_loss_percent == 0 and not probabilities:
            return
        if not any(loss_probability_matches(item, expected_loss_percent) for item in probabilities):
            raise LabError("netem loss differs from the requested value")


def run_nat_up(args: argparse.Namespace) -> None:
    specs = network_specs(NAT_NETWORKS.values())
    by_role = {key: NetworkSpec.from_tuple(value) for key, value in NAT_NETWORKS.items()}
    container_roles = ["node-a", "nat-a", "infra", "nat-b", "node-b"]
    resources = [PlannedResource("network", spec.name, role) for role, spec in by_role.items()]
    resources.extend(
        PlannedResource("container", FIXED_CONTAINER_NAMES[role], role)
        for role in container_roles
    )
    if not args.execute:
        plan_output(
            "nat",
            resources,
            [
                "create three internal bridges with fixed, collision-checked CIDRs",
                "start five exact-name containers: NET_ADMIN on endpoint scaffolds, NET_ADMIN+NET_RAW+SETUID+SETGID on router capture points, no added capability on infra",
                "attach each NAT router to its LAN and WAN",
                f"install explicit {args.profile} nftables rules and node default routes",
                "run the combined unprivileged UDP-rendezvous/TCP-relay service on WAN .20",
                "start WAN-interface packet capture in each NAT namespace",
                "leave topology running; no NAT acceptance is claimed until live node carrier scenarios pass",
            ],
        )
        return
    ctx = RunContext.create(args.evidence_root, "nat", resources)
    names = [FIXED_CONTAINER_NAMES[role] for role in container_roles]
    docker_preflight(ctx, containers=names, networks=specs)
    write_scenario_request(
        ctx,
        scenario="nat-topology",
        profile=args.profile,
        shape_bps=args.shape_bps,
        loss_percent=args.loss_percent,
        requested_netem_seed=args.seed,
        infrastructure_duration_ms=args.duration_ms,
        acceptance_claim=False,
    )
    succeeded = False
    try:
        outputs = {
            role: create_output_directory(ctx, role) for role in container_roles
        }
        for role in ["lan-a", "wan", "lan-b"]:
            create_network(ctx, by_role[role], role)
        ctx.runner.run(
            nat_container(
                ctx,
                name=FIXED_CONTAINER_NAMES["node-a"],
                role="node-a",
                network=by_role["lan-a"].name,
                address="10.250.1.10",
                capabilities=["NET_ADMIN"],
                output_dir=outputs["node-a"],
            )
        )
        ctx.runner.run(
            nat_container(
                ctx,
                name=FIXED_CONTAINER_NAMES["nat-a"],
                role="nat-a",
                network=by_role["lan-a"].name,
                address="10.250.1.1",
                capabilities=["NET_ADMIN", "NET_RAW", "SETUID", "SETGID"],
                output_dir=outputs["nat-a"],
                forwarding=True,
            )
        )
        ctx.runner.run(
            container_run_args(
                ctx,
                name=FIXED_CONTAINER_NAMES["infra"],
                role="infra",
                command=[
                    "infra",
                    "--rendezvous-bind",
                    "0.0.0.0:4476",
                    "--relay-bind",
                    "0.0.0.0:4477",
                    "--duration-ms",
                    str(args.duration_ms),
                    "--poll-ms",
                    "1",
                ],
                detach=True,
                network=by_role["wan"].name,
                ip="10.250.0.20",
                memory="256m",
                cpus="0.5",
                pids=128,
                output_dir=outputs["infra"],
            )
        )
        ctx.runner.run(
            nat_container(
                ctx,
                name=FIXED_CONTAINER_NAMES["nat-b"],
                role="nat-b",
                network=by_role["lan-b"].name,
                address="10.250.2.1",
                capabilities=["NET_ADMIN", "NET_RAW", "SETUID", "SETGID"],
                output_dir=outputs["nat-b"],
                forwarding=True,
            )
        )
        ctx.runner.run(
            nat_container(
                ctx,
                name=FIXED_CONTAINER_NAMES["node-b"],
                role="node-b",
                network=by_role["lan-b"].name,
                address="10.250.2.10",
                capabilities=["NET_ADMIN"],
                output_dir=outputs["node-b"],
            )
        )
        docker = require_docker()
        ctx.runner.run(
            [docker, "network", "connect", "--ip", "10.250.0.11", by_role["wan"].name, FIXED_CONTAINER_NAMES["nat-a"]]
        )
        ctx.runner.run(
            [docker, "network", "connect", "--ip", "10.250.0.12", by_role["wan"].name, FIXED_CONTAINER_NAMES["nat-b"]]
        )
        ctx.runner.run(
            [docker, "exec", FIXED_CONTAINER_NAMES["node-a"], "/usr/sbin/ip", "route", "replace", "default", "via", "10.250.1.1"]
        )
        ctx.runner.run(
            [docker, "exec", FIXED_CONTAINER_NAMES["node-b"], "/usr/sbin/ip", "route", "replace", "default", "via", "10.250.2.1"]
        )
        router_values = [
            ("nat-a", "10.250.1.1", "10.250.0.11", "10.250.1.0/24", "10.250.1.10"),
            ("nat-b", "10.250.2.1", "10.250.0.12", "10.250.2.0/24", "10.250.2.10"),
        ]
        runtime_routers = []
        netem_seed_statuses: set[str] = set()
        for role, lan_address, wan_address, lan_subnet, node_ip in router_values:
            container = FIXED_CONTAINER_NAMES[role]
            lan_if = interface_for_address(ctx, container, lan_address)
            wan_if = interface_for_address(ctx, container, wan_address)
            rules = nft_rules(
                profile=args.profile,
                lan_if=lan_if,
                wan_if=wan_if,
                lan_subnet=lan_subnet,
                node_ip=node_ip,
                external_ip=wan_address,
            )
            rules_path = ctx.run_dir / f"{role}.nft"
            with rules_path.open("x", encoding="utf-8") as stream:
                stream.write(rules)
            ctx.runner.run(
                [docker, "exec", "--interactive", container, "/usr/sbin/nft", "-f", "-"],
                input_text=rules,
            )
            if args.shape_bps > 0:
                netem = [
                    docker,
                    "exec",
                    container,
                    "/usr/sbin/tc",
                    "qdisc",
                    "replace",
                    "dev",
                    wan_if,
                    "root",
                    "netem",
                    "limit",
                    "64",
                    "rate",
                    f"{args.shape_bps}bit",
                    "loss",
                    "random",
                    f"{args.loss_percent}%",
                ]
                seeded = ctx.runner.run(
                    [*netem, "seed", str(args.seed)],
                    check=False,
                )
                if seeded.returncode == 0:
                    seed_status = "applied"
                    applied_seed: int | None = args.seed
                elif 'What is "seed"?' in seeded.stderr:
                    ctx.runner.run(netem)
                    seed_status = "unsupported"
                    applied_seed = None
                else:
                    raise LabError(
                        f"netem seed setup failed unexpectedly on {container} "
                        f"with status {seeded.returncode}"
                    )
                netem_seed_statuses.add(seed_status)
                ctx.event(
                    "netem-seed-capability",
                    role=role,
                    requested_seed=args.seed,
                    status=seed_status,
                )
                stats = ctx.runner.run(
                    [docker, "exec", container, "/usr/sbin/tc", "-s", "-j", "qdisc", "show", "dev", wan_if]
                )
                verify_qdisc_json(
                    stats.stdout,
                    expected_bps=args.shape_bps,
                    expected_loss_percent=args.loss_percent,
                    expected_limit=64,
                    expected_seed=applied_seed,
                )
                write_exclusive_text(ctx.run_dir / f"{role}-qdisc-initial.json", stats.stdout)
            capture_in_container = f"/output/{role}-wan.pcap"
            capture_host = outputs[role] / f"{role}-wan.pcap"
            capture_program = [
                "/usr/bin/tcpdump",
                "-Z",
                "tcpdump",
                "-i",
                wan_if,
                "-s",
                "0",
                "-U",
                "-w",
                capture_in_container,
                "udp",
                "or",
                "tcp",
            ]
            ctx.runner.run(
                [
                    docker,
                    "exec",
                    "--detach",
                    container,
                    *capture_program,
                ]
            )
            try:
                wait_for_capture_ready(ctx, container, capture_in_container, capture_host)
            except LabError as readiness_error:
                diagnostic_capture = f"/tmp/{role}-diagnostic.pcap"
                diagnostic_program = [
                    *capture_program[:9],
                    diagnostic_capture,
                    *capture_program[10:],
                ]
                diagnostic = ctx.runner.run(
                    [
                        docker,
                        "exec",
                        container,
                        "/usr/bin/timeout",
                        "--signal=INT",
                        "2",
                        *diagnostic_program,
                    ],
                    check=False,
                    timeout=5,
                )
                raise LabError(
                    f"{readiness_error}; foreground tcpdump diagnostic exited "
                    f"with status {diagnostic.returncode}"
                ) from readiness_error
            runtime_routers.append(
                {
                    "role": role,
                    "container": container,
                    "wan_interface": wan_if,
                    "capture_container_path": capture_in_container,
                    "capture_relative_path": str(capture_host.relative_to(ctx.run_dir)),
                }
            )
        wait_for_log_marker(
            ctx,
            FIXED_CONTAINER_NAMES["infra"],
            "ASTER_LAB_INFRA_READY\tversion=1",
        )
        verify_container_configuration(
            ctx,
            FIXED_CONTAINER_NAMES["node-a"],
            output_dir=outputs["node-a"],
            memory="256m",
            cpus="0.5",
            pids=64,
            network=by_role["lan-a"].name,
            capabilities=["NET_ADMIN"],
            root_user=True,
            entrypoint="/usr/bin/sleep",
        )
        verify_container_configuration(
            ctx,
            FIXED_CONTAINER_NAMES["node-b"],
            output_dir=outputs["node-b"],
            memory="256m",
            cpus="0.5",
            pids=64,
            network=by_role["lan-b"].name,
            capabilities=["NET_ADMIN"],
            root_user=True,
            entrypoint="/usr/bin/sleep",
        )
        for role, lan_role in [("nat-a", "lan-a"), ("nat-b", "lan-b")]:
            verify_container_configuration(
                ctx,
                FIXED_CONTAINER_NAMES[role],
                output_dir=outputs[role],
                memory="256m",
                cpus="0.5",
                pids=64,
                network=by_role[lan_role].name,
                capabilities=["NET_ADMIN", "NET_RAW", "SETUID", "SETGID"],
                root_user=True,
                sysctls={"net.ipv4.ip_forward": "1"},
                entrypoint="/usr/bin/sleep",
            )
        verify_container_configuration(
            ctx,
            FIXED_CONTAINER_NAMES["infra"],
            output_dir=outputs["infra"],
            memory="256m",
            cpus="0.5",
            pids=128,
            network=by_role["wan"].name,
        )
        if args.shape_bps > 0:
            if len(netem_seed_statuses) != 1:
                raise LabError("NAT routers disagree on netem seed capability")
            netem_seed_status = next(iter(netem_seed_statuses))
            netem_seed = args.seed if netem_seed_status == "applied" else None
        else:
            netem_seed_status = "not-requested"
            netem_seed = None
        write_exclusive_json(
            ctx.run_dir / "nat-runtime.json",
            {
                "schema": SCHEMA,
                "profile": args.profile,
                "shape_bps": args.shape_bps,
                "loss_percent": args.loss_percent,
                "netem_limit": 64,
                "netem_seed_requested": args.seed,
                "netem_seed_status": netem_seed_status,
                "netem_seed": netem_seed,
                "routers": runtime_routers,
                "infra": FIXED_CONTAINER_NAMES["infra"],
            },
        )
        for role in container_roles:
            ctx.event("resource-created", kind="container", name=FIXED_CONTAINER_NAMES[role], role=role)
        ctx.event(
            "nat-topology-ready",
            profile=args.profile,
            acceptance_claim=False,
            limitation="combined rendezvous/relay infra is live; node carrier scenarios are not invoked",
        )
        succeeded = True
    finally:
        if not succeeded:
            cleanup_context(ctx, tolerate_errors=True)
    print(ctx.run_dir)



def run_selected_nat_cell(
    suite_dir: Path, profile: str, args: argparse.Namespace
) -> dict[str, Any]:
    if (
        type(args.duration_seconds) is not int
        or args.duration_seconds != SELECTED_NAT_RUN_FOR_SECONDS
    ):
        raise LabError("selected NAT runtime duration differs from the fixed window")
    resources = selected_nat_cell_resources(profile)
    ctx = RunContext.create_at(
        suite_dir / "cells" / profile,
        profile,
        resources,
        image=SELECTED_NAT_IMAGE,
    )
    specs = network_specs(NAT_NETWORKS.values())
    by_role = {key: NetworkSpec.from_tuple(value) for key, value in NAT_NETWORKS.items()}
    container_names = [resource.name for resource in resources if resource.kind == "container"]
    docker_preflight(
        ctx,
        containers=container_names,
        networks=specs,
        selected_nat_image=True,
    )
    source = selected_nat_source_identity(ctx)
    scope = f"lab/selected-iroh-nat/{profile}"
    topic = "lab.selected-iroh-nat"
    write_scenario_request(
        ctx,
        scenario="selected-iroh-nat-acceptance",
        profile=profile,
        scope=scope,
        topic=topic,
        duration_seconds=SELECTED_NAT_RUN_FOR_SECONDS,
        physical_hosts=1,
        namespace_isolation=True,
        infrastructure_free=profile == "cone-direct",
        controlled_relay=profile == "restrictive-relay",
        physical_nat_claim=False,
        public_internet=False,
    )
    docker = require_docker()
    outputs = {
        role: create_output_directory(ctx, role)
        for role in ["provision", "nat-a", "nat-b"]
    }
    if profile == "restrictive-relay":
        outputs["infra"] = create_output_directory(ctx, "infra")
    succeeded = False
    capture_commands: dict[str, RunningCommand] = {}
    node_commands: dict[str, RunningCommand] = {}
    captures: dict[str, Path] = {}
    try:
        start_selected_nat_provisioner(ctx, outputs["provision"])
        provision_name = FIXED_CONTAINER_NAMES["provision"]
        binary_inventory = selected_nat_binary_inventory(ctx, provision_name)
        prepare_result, prepare_command_path = selected_nat_exec(
            ctx,
            provision_name,
            [
                "/usr/local/bin/aster-selected-nat",
                "prepare",
                "--root",
                "/output",
                "--scope",
                scope,
                "--topic",
                topic,
            ],
        )
        prepare_log = selected_nat_copy_log(
            prepare_command_path, ctx.run_dir / "prepare.log"
        )
        manifest_path = outputs["provision"] / "manifest.tsv"
        manifest = parse_selected_nat_manifest(manifest_path, scope=scope, topic=topic)
        prepare = validate_selected_nat_prepare(
            prepare_result.stdout,
            scope=scope,
            topic=topic,
            manifest=manifest,
        )
        material: dict[str, str] | None = None
        if profile == "restrictive-relay":
            material_result, material_path = selected_nat_exec(
                ctx,
                provision_name,
                [
                    "/usr/local/bin/aster-selected-nat",
                    "relay-material",
                    "--root",
                    "/output/relay",
                    "--dns-name",
                    SELECTED_NAT_RELAY_DNS,
                    "--ip-address",
                    SELECTED_NAT_RELAY_IP,
                ],
            )
            material = validate_selected_nat_material(
                material_result.stdout, profile=profile
            )
            selected_nat_copy_log(material_path, ctx.run_dir / "relay-material.log")
        publish_result, publish_path = selected_nat_exec(
            ctx,
            provision_name,
            [
                "/usr/local/bin/aster-selected-nat",
                "publish",
                "--root",
                "/output",
                "--node",
                "a",
                "--canary-sha256",
                manifest["canary_sha256"],
            ],
        )
        publish = validate_selected_nat_publish(publish_result.stdout, manifest=manifest)
        selected_nat_copy_log(publish_path, ctx.run_dir / "publish.log")
        remove_owned_container(ctx, "provision")
        bundle_paths = {
            role: outputs["provision"] / "private" / f"{role}.bundle"
            for role in ("node-a", "node-b")
        }
        bundle_witnesses = {
            role: retained_secret_mount_witness(path)
            for role, path in bundle_paths.items()
        }

        for role in ["lan-a", "wan", "lan-b"]:
            create_network(ctx, by_role[role], role)
        node_values = {
            "node-a": ("lan-a", "10.250.1.10", "a"),
            "node-b": ("lan-b", "10.250.2.10", "b"),
        }
        for role, (lan_role, address, short_name) in node_values.items():
            node_output = outputs["provision"] / role
            node_state_path = selected_nat_state_container_path(role)
            bundle = bundle_paths[role]
            read_only_mounts: list[tuple[Path, str]] = []
            retained_secret_mounts = [(bundle, "/run/secrets/node.bundle")]
            extra_hosts: list[tuple[str, str]] = []
            if profile == "restrictive-relay":
                read_only_mounts.append(
                    (
                        outputs["provision"] / "relay" / "ca.der",
                        "/run/relay/ca.der",
                    )
                )
                extra_hosts.append((SELECTED_NAT_RELAY_DNS, SELECTED_NAT_RELAY_IP))
            ctx.runner.run(
                container_run_args(
                    ctx,
                    name=FIXED_CONTAINER_NAMES[role],
                    role=role,
                    command=["infinity"],
                    network=by_role[lan_role].name,
                    ip=address,
                    detach=True,
                    memory="1g",
                    cpus="1",
                    pids=256,
                    entrypoint="/usr/bin/sleep",
                    output_dir=node_output,
                    output_destination=node_state_path,
                    read_only_mounts=read_only_mounts,
                    retained_secret_mounts=retained_secret_mounts,
                    extra_hosts=extra_hosts,
                )
            )
            verify_container_configuration(
                ctx,
                FIXED_CONTAINER_NAMES[role],
                output_dir=node_output,
                output_destination=node_state_path,
                memory="1g",
                cpus="1",
                pids=256,
                network=by_role[lan_role].name,
                read_only_mounts=read_only_mounts,
                retained_secret_mounts=retained_secret_mounts,
                extra_hosts=extra_hosts,
                network_addresses={by_role[lan_role].name: address},
                entrypoint="/usr/bin/sleep",
            )
            if short_name not in manifest["nodes"]:
                raise LabError("selected NAT manifest/node mapping differs")

        router_values = {
            "nat-a": {
                "lan_role": "lan-a",
                "lan_address": "10.250.1.1",
                "wan_address": "10.250.0.11",
                "lan_subnet": "10.250.1.0/24",
                "node_ip": "10.250.1.10",
                "peer_external_ip": "10.250.0.12",
            },
            "nat-b": {
                "lan_role": "lan-b",
                "lan_address": "10.250.2.1",
                "wan_address": "10.250.0.12",
                "lan_subnet": "10.250.2.0/24",
                "node_ip": "10.250.2.10",
                "peer_external_ip": "10.250.0.11",
            },
        }
        for role, values in router_values.items():
            ctx.runner.run(
                nat_container(
                    ctx,
                    name=FIXED_CONTAINER_NAMES[role],
                    role=role,
                    network=by_role[values["lan_role"]].name,
                    address=values["lan_address"],
                    capabilities=["NET_ADMIN", "NET_RAW", "SETUID", "SETGID"],
                    output_dir=outputs[role],
                    forwarding=True,
                )
            )
            ctx.runner.run(
                [
                    docker,
                    "network",
                    "connect",
                    "--ip",
                    values["wan_address"],
                    by_role["wan"].name,
                    FIXED_CONTAINER_NAMES[role],
                ]
            )
            verify_container_configuration(
                ctx,
                FIXED_CONTAINER_NAMES[role],
                output_dir=outputs[role],
                memory="256m",
                cpus="0.5",
                pids=64,
                network=by_role[values["lan_role"]].name,
                capabilities=["NET_ADMIN", "NET_RAW", "SETUID", "SETGID"],
                root_user=True,
                sysctls={"net.ipv4.ip_forward": "1"},
                network_addresses={
                    by_role[values["lan_role"]].name: values["lan_address"],
                    by_role["wan"].name: values["wan_address"],
                },
                entrypoint="/usr/bin/sleep",
            )

        route_receipts = [
            selected_nat_route_init(
                ctx,
                role="route-a",
                node_role="node-a",
                gateway="10.250.1.1",
            ),
            selected_nat_route_init(
                ctx,
                role="route-b",
                node_role="node-b",
                gateway="10.250.2.1",
            ),
        ]
        write_exclusive_json(ctx.run_dir / "route-init-removal.json", route_receipts)

        nft_before: dict[str, dict[str, dict[str, int]]] = {}
        runtime_routers = []
        for role, values in router_values.items():
            container = FIXED_CONTAINER_NAMES[role]
            lan_if = interface_for_address(ctx, container, values["lan_address"])
            wan_if = interface_for_address(ctx, container, values["wan_address"])
            rules = selected_nat_nft_rules(
                profile=profile,
                lan_if=lan_if,
                wan_if=wan_if,
                lan_subnet=values["lan_subnet"],
                node_ip=values["node_ip"],
                external_ip=values["wan_address"],
                peer_external_ip=values["peer_external_ip"],
            )
            write_exclusive_text(ctx.run_dir / f"{role}.nft", rules)
            ctx.runner.run(
                [docker, "exec", "--interactive", container, "/usr/sbin/nft", "-f", "-"],
                input_text=rules,
            )
            nft_before[role], _ = selected_nat_nft_snapshot(
                ctx, role=role, profile=profile, phase="before"
            )
            capture, capture_path = start_selected_nat_capture(
                ctx,
                role=role,
                wan_interface=wan_if,
                output_dir=outputs[role],
                profile=profile,
            )
            capture_commands[role] = capture
            captures[role] = capture_path
            runtime_routers.append(
                {
                    "role": role,
                    "container": container,
                    "lan_interface": lan_if,
                    "wan_interface": wan_if,
                    "lan_address": values["lan_address"],
                    "wan_address": values["wan_address"],
                    "node_ip": values["node_ip"],
                    "peer_external_ip": values["peer_external_ip"],
                    "capture_relative_path": str(capture_path.relative_to(ctx.run_dir)),
                }
            )


        relay_log_path: Path | None = None
        relay_config: dict[str, Any] | None = None
        relay_privilege: dict[str, Any] | None = None
        if profile == "restrictive-relay":
            relay_root = outputs["provision"] / "relay"
            relay_mounts = [
                (relay_root / "server.cert.der", "/run/relay/server.cert.der"),
                (
                    relay_root / "private" / "server.key.pkcs8.der",
                    "/run/relay/server.key.pkcs8.der",
                ),
            ]
            relay_command = [
                "--https-bind",
                f"0.0.0.0:{SELECTED_NAT_RELAY_HTTPS_PORT}",
                "--http-bind",
                f"0.0.0.0:{SELECTED_NAT_RELAY_HTTP_PORT}",
                "--certificate-der",
                "/run/relay/server.cert.der",
                "--private-key-pkcs8-der",
                "/run/relay/server.key.pkcs8.der",
            ]
            for carrier in sorted(
                record["carrier_id"] for record in manifest["nodes"].values()
            ):
                relay_command.extend(["--allow-carrier", carrier])
            relay_command.extend(
                [
                    "--max-admitted-connections",
                    str(SELECTED_NAT_RELAY_MAX_ADMITTED_CONNECTIONS),
                    "--client-rx-bytes-per-second",
                    str(SELECTED_NAT_RELAY_BYTES_PER_SECOND),
                    "--client-rx-max-burst-bytes",
                    str(SELECTED_NAT_RELAY_MAX_BURST_BYTES),
                    "--key-cache-capacity",
                    str(SELECTED_NAT_RELAY_KEY_CACHE_CAPACITY),
                ]
            )
            ctx.runner.run(
                container_run_args(
                    ctx,
                    name=FIXED_CONTAINER_NAMES["infra"],
                    role="infra",
                    command=relay_command,
                    network=by_role["wan"].name,
                    ip=SELECTED_NAT_RELAY_IP,
                    detach=True,
                    memory="512m",
                    cpus="1",
                    pids=256,
                    entrypoint="/usr/local/bin/aster-selected-relay",
                    output_dir=outputs["infra"],
                    read_only_mounts=relay_mounts,
                )
            )
            verify_container_configuration(
                ctx,
                FIXED_CONTAINER_NAMES["infra"],
                output_dir=outputs["infra"],
                memory="512m",
                cpus="1",
                pids=256,
                network=by_role["wan"].name,
                read_only_mounts=relay_mounts,
                network_addresses={by_role["wan"].name: SELECTED_NAT_RELAY_IP},
                entrypoint="/usr/local/bin/aster-selected-relay",
            )
            wait_for_log_marker(
                ctx,
                FIXED_CONTAINER_NAMES["infra"],
                "SELECTED_NAT_RELAY_READY status=ready version=1",
                timeout=20,
            )
            relay_privilege = selected_nat_privilege_receipt(ctx, "infra")
            relay_config = {
                "schema": SCHEMA,
                "origin": f"https://{SELECTED_NAT_RELAY_DNS}:{SELECTED_NAT_RELAY_HTTPS_PORT}/",
                "address": SELECTED_NAT_RELAY_IP,
                "https_port": SELECTED_NAT_RELAY_HTTPS_PORT,
                "http_port": SELECTED_NAT_RELAY_HTTP_PORT,
                "tls_mode": "manual-der-certificate",
                "server_trust_claim": "none",
                "client_trust_mode": "explicit-der-root-pin",
                "root_fingerprint_sha256": material["ca_sha256"] if material else None,
                "certificate_sha256": material["certificate_sha256"] if material else None,
                "allowlist": sorted(
                    record["carrier_id"] for record in manifest["nodes"].values()
                ),
                "max_admitted_connections": SELECTED_NAT_RELAY_MAX_ADMITTED_CONNECTIONS,
                "pre_auth_connection_cap": "not-enforced",
                "client_rx_bytes_per_second": SELECTED_NAT_RELAY_BYTES_PER_SECOND,
                "client_rx_max_burst_bytes": SELECTED_NAT_RELAY_MAX_BURST_BYTES,
                "key_cache_capacity": SELECTED_NAT_RELAY_KEY_CACHE_CAPACITY,
                "public_relay_fallback": False,
                "hosted_discovery": False,
                "port_mapper": False,
            }
            write_exclusive_json(ctx.run_dir / "relay-config.json", relay_config)
        else:
            if docker_resource_present(ctx, "container", FIXED_CONTAINER_NAMES["infra"]):
                raise LabError("cone-direct unexpectedly created an infrastructure container")
            write_exclusive_json(
                ctx.run_dir / "relay-disabled.json",
                {
                    "schema": SCHEMA,
                    "profile": profile,
                    "relay_container": False,
                    "relay_configuration": False,
                    "legacy_ports_4476_4477": False,
                    "hosted_discovery": False,
                    "public_relay_fallback": False,
                    "status": "pass",
                },
            )

        expected_network_members = {
            "lan-a": {
                FIXED_CONTAINER_NAMES["node-a"]: "10.250.1.10",
                FIXED_CONTAINER_NAMES["nat-a"]: "10.250.1.1",
            },
            "wan": {
                FIXED_CONTAINER_NAMES["nat-a"]: "10.250.0.11",
                FIXED_CONTAINER_NAMES["nat-b"]: "10.250.0.12",
                **(
                    {FIXED_CONTAINER_NAMES["infra"]: SELECTED_NAT_RELAY_IP}
                    if profile == "restrictive-relay"
                    else {}
                ),
            },
            "lan-b": {
                FIXED_CONTAINER_NAMES["node-b"]: "10.250.2.10",
                FIXED_CONTAINER_NAMES["nat-b"]: "10.250.2.1",
            },
        }
        network_receipts = {
            role: selected_nat_network_receipt(
                ctx,
                role=role,
                spec=by_role[role],
                expected_members=expected_network_members[role],
            )
            for role in ["lan-a", "wan", "lan-b"]
        }
        privileges = {
            role: selected_nat_privilege_receipt(ctx, role)
            for role in ["node-a", "node-b"]
        }
        runtime = {
            "schema": SCHEMA,
            "run_id": ctx.run_id,
            "profile": profile,
            "source": source,
            "image": ctx.image,
            "image_id": ctx.image_id,
            "binary_inventory": binary_inventory,
            "scope": scope,
            "topic": topic,
            "mission_authority": manifest["mission_authority"],
            "nodes": manifest["nodes"],
            "routers": runtime_routers,
            "route_initializers_removed": all(
                record["removed"]
                and record["exited"]
                and record["exit_code"] == 0
                for record in route_receipts
            ),
            "networks": network_receipts,
            "node_privileges": privileges,
            "relay": relay_config,
            "relay_privilege": relay_privilege,
            "legacy_ports_4476_4477": False,
        }
        write_exclusive_json(ctx.run_dir / "selected-nat-runtime.json", runtime)

        node_addresses = {"node-a": "10.250.1.10", "node-b": "10.250.2.10"}
        peer_external = {"node-a": "10.250.0.12", "node-b": "10.250.0.11"}
        peer_name = {"node-a": "b", "node-b": "a"}
        for role in ["node-b", "node-a"]:
            peer = peer_name[role]
            command = selected_nat_node_arguments(
                docker=docker,
                user=f"{os.getuid()}:{os.getgid()}",
                role=role,
                profile=profile,
                node_address=node_addresses[role],
                peer_external_address=peer_external[role],
                peer_carrier_id=manifest["nodes"][peer]["carrier_id"],
                peer_mission_id=manifest["nodes"][peer]["mission_id"],
            )
            node_commands[role] = ctx.runner.start(command)
        validate_selected_nat_command_chronology(
            route_receipts=route_receipts,
            capture_stderr={
                role: capture_commands[role].stderr_name
                for role in ("nat-a", "nat-b")
            },
            node_stderr={
                role: node_commands[role].stderr_name
                for role in ("node-a", "node-b")
            },
        )
        for role in ["node-a", "node-b"]:
            wait_for_running_marker(
                ctx,
                node_commands[role],
                "READY selected=true",
                timeout=20,
            )
        finish_running_commands(
            list(node_commands.values()),
            deadline=time.monotonic() + SELECTED_NAT_RUN_FOR_SECONDS + 30,
        )
        for role, path in bundle_paths.items():
            if retained_secret_mount_witness(path) != bundle_witnesses[role]:
                raise LabError(
                    f"selected NAT {role} mission bundle changed during normal runtime"
                )
        node_results = {}
        node_logs = []
        for role, short_name in [("node-a", "a"), ("node-b", "b")]:
            stdout_path = ctx.run_dir / node_commands[role].stdout_name
            stderr_path = ctx.run_dir / node_commands[role].stderr_name
            if stdout_path.stat().st_size > 16 * 1024 * 1024 or stderr_path.stat().st_size > 16 * 1024 * 1024:
                raise LabError(f"selected NAT {role} transcript exceeds 16 MiB")
            stdout_text = stdout_path.read_text(encoding="utf-8", errors="replace")
            stderr_text = stderr_path.read_text(encoding="utf-8", errors="replace")
            validate_selected_nat_stderr(stderr_text, role)
            transcript = (
                "ASTER_SELECTED_NAT_TRANSCRIPT version=1 stream=stdout\n"
                + stdout_text
                + ("" if stdout_text.endswith("\n") else "\n")
                + "ASTER_SELECTED_NAT_TRANSCRIPT version=1 stream=stderr\n"
                + stderr_text
            )
            log_path = ctx.run_dir / f"{role}.log"
            write_exclusive_text(log_path, transcript)
            node_logs.extend([log_path, stderr_path])
            result = validate_selected_nat_node_log(
                stdout_text,
                profile=profile,
                carrier_id=manifest["nodes"][short_name]["carrier_id"],
                mission_id=manifest["nodes"][short_name]["mission_id"],
                mission_authority=manifest["mission_authority"],
                bind_ip=node_addresses[role],
                state_path=selected_nat_state_container_path(role),
            )
            if receipt_nonnegative(result["stop"], "events") != 1:
                raise LabError("selected NAT terminal store does not contain the exact Event")
            expected_transfer = {
                field: (
                    1
                    if (role == "node-a" and field == "offered")
                    or (role == "node-b" and field in {"fetched", "inserted"})
                    else 0
                )
                for field in SELECTED_NAT_NOOP_FIELDS
            }
            transfer_contacts = 0
            for contact in result["contacts"]:
                observed_transfer = {
                    field: receipt_nonnegative(contact, field)
                    for field in SELECTED_NAT_NOOP_FIELDS
                }
                if observed_transfer == expected_transfer:
                    transfer_contacts += 1
                elif any(observed_transfer.values()):
                    raise LabError("selected NAT contact has an unexpected Event transfer shape")
            if transfer_contacts != 1:
                raise LabError("selected NAT node lacks one exact role-bound Event transfer")
            node_results[role] = result
        all_contacts = [
            contact
            for result in node_results.values()
            for contact in result["contacts"]
        ]
        transfer_insertions = sum(
            receipt_nonnegative(contact, "inserted") for contact in all_contacts
        )
        transfer_fetches = sum(
            receipt_nonnegative(contact, "fetched") for contact in all_contacts
        )
        if transfer_insertions != 1:
            raise LabError("selected NAT live contacts did not insert exactly one Event")
        if transfer_fetches != 1:
            raise LabError("selected NAT live contacts did not fetch exactly one Event")

        relay_receipt: dict[str, Any] | None = None
        if profile == "restrictive-relay":
            ctx.runner.run(
                [
                    docker,
                    "container",
                    "stop",
                    "--time",
                    "10",
                    FIXED_CONTAINER_NAMES["infra"],
                ]
            )
            relay_logs = ctx.runner.run(
                [docker, "container", "logs", FIXED_CONTAINER_NAMES["infra"]]
            )
            relay_log_path = ctx.run_dir / "relay.log"
            write_exclusive_text(relay_log_path, relay_logs.stdout + relay_logs.stderr)
            relay_receipt = validate_selected_nat_relay_log(
                relay_logs.stdout + relay_logs.stderr,
                carrier_ids={record["carrier_id"] for record in manifest["nodes"].values()},
                max_admitted_connections=SELECTED_NAT_RELAY_MAX_ADMITTED_CONNECTIONS,
                client_rx_bytes_per_second=SELECTED_NAT_RELAY_BYTES_PER_SECOND,
                client_rx_max_burst_bytes=SELECTED_NAT_RELAY_MAX_BURST_BYTES,
                key_cache_capacity=SELECTED_NAT_RELAY_KEY_CACHE_CAPACITY,
            )

        pcap_records = {}
        for role in ["nat-a", "nat-b"]:
            pcap_records[role] = stop_selected_nat_capture(
                ctx,
                role=role,
                running=capture_commands[role],
                capture_path=captures[role],
            )
        nft_after: dict[str, dict[str, dict[str, int]]] = {}
        nft_deltas = {}
        for role in ["nat-a", "nat-b"]:
            nft_after[role], _ = selected_nat_nft_snapshot(
                ctx, role=role, profile=profile, phase="after"
            )
            nft_deltas[role] = selected_nat_counter_delta(
                nft_before[role], nft_after[role], profile
            )
        if profile == "restrictive-relay" and sum(
            nft_deltas[role]["aster_restrict_direct_drop"]["packets"]
            for role in ["nat-a", "nat-b"]
        ) <= 0:
            raise LabError("restrictive selected NAT observed no real direct-path drop")
        direct_addresses = {"10.250.0.11", "10.250.0.12"}
        tuple_proof = {}
        wan_direction_packets = {}
        for role in ["nat-a", "nat-b"]:
            direct_packets = pcap_tuple_count(
                pcap_records[role],
                addresses=direct_addresses,
                port=SELECTED_NAT_NODE_PORT,
                protocol="udp",
                both_ports=True,
            )
            own_external = router_values[role]["wan_address"]
            relay_packets = pcap_tuple_count(
                pcap_records[role],
                addresses={own_external, SELECTED_NAT_RELAY_IP},
                port=SELECTED_NAT_RELAY_HTTPS_PORT,
                protocol="tcp",
                server_address=SELECTED_NAT_RELAY_IP,
            )
            relay_http_packets = pcap_tuple_count(
                pcap_records[role],
                addresses={own_external, SELECTED_NAT_RELAY_IP},
                port=SELECTED_NAT_RELAY_HTTP_PORT,
                protocol="tcp",
                server_address=SELECTED_NAT_RELAY_IP,
            )
            captured_packets = selected_nat_receipt_integer(
                pcap_records[role], "packets"
            )
            if profile == "cone-direct" and (
                direct_packets <= 0 or captured_packets != direct_packets
            ):
                raise LabError("cone-direct WAN tuple proof differs")
            if profile == "restrictive-relay" and (
                direct_packets != 0
                or relay_packets <= 0
                or relay_http_packets != 0
                or captured_packets != relay_packets
            ):
                raise LabError("restrictive-relay WAN tuple proof differs")
            tuple_proof[role] = {
                "direct_udp_packets": direct_packets,
                "relay_https_tcp_packets": relay_packets,
                "relay_http_tcp_packets": relay_http_packets,
            }
            outbound = sum(
                selected_nat_receipt_integer(record, "packets")
                for record in pcap_records[role]["tuples"]
                if record.get("source") == own_external
            )
            inbound = sum(
                selected_nat_receipt_integer(record, "packets")
                for record in pcap_records[role]["tuples"]
                if record.get("destination") == own_external
            )
            wan_direction_packets[role] = {
                "inbound": inbound,
                "outbound": outbound,
            }
            expected_counter_packets = (
                {
                    "aster_cone_forward_out": outbound,
                    "aster_cone_forward_in": inbound,
                }
                if profile == "cone-direct"
                else {
                    "aster_restrict_relay_https": outbound,
                    "aster_restrict_established": inbound,
                }
            )
            for counter_name, expected_packets in expected_counter_packets.items():
                if nft_deltas[role][counter_name]["packets"] != expected_packets:
                    raise LabError(
                        "selected NAT nft packet counters differ from the exact WAN tuples"
                    )
        if profile == "cone-direct":
            validate_selected_nat_cone_directionality(
                node_results=node_results,
                nft_deltas=nft_deltas,
                wan_direction_packets=wan_direction_packets,
            )
        write_exclusive_json(
            ctx.run_dir / "pcap-tuple-summary.json",
            {"schema": SCHEMA, "profile": profile, "routers": pcap_records, "proof": tuple_proof},
        )

        start_selected_nat_provisioner(
            ctx,
            outputs["provision"],
            receipt_name="aster-lab-provision-verifier-configuration.json",
        )
        verify_result, verify_path = selected_nat_exec(
            ctx,
            provision_name,
            [
                "/usr/local/bin/aster-selected-nat",
                "verify",
                "--root",
                "/output",
                "--node",
                "b",
                "--publisher",
                manifest["nodes"]["a"]["mission_id"],
                "--canary-sha256",
                manifest["canary_sha256"],
            ],
        )
        verify = validate_selected_nat_verify(
            verify_result.stdout,
            manifest=manifest,
            event_id=publish["event_id"],
        )
        verify_log = selected_nat_copy_log(verify_path, ctx.run_dir / "verify.log")
        for role in ["node-a", "node-b"]:
            write_exclusive_json(ctx.run_dir / f"{role}-result.json", node_results[role])

        scan_logs = [prepare_log, ctx.run_dir / "publish.log", verify_log, *node_logs]
        if profile == "restrictive-relay":
            if relay_log_path is None:
                raise LabError("restrictive selected NAT relay log is absent")
            scan_logs.extend([relay_log_path, ctx.run_dir / "relay-material.log"])
        scan_logs.extend(
            ctx.run_dir / capture_commands[role].stderr_name for role in ["nat-a", "nat-b"]
        )
        canary_scan = selected_nat_canary_scan(
            ctx,
            canary_path=outputs["provision"] / "private" / "canary.bin",
            captures=[captures["nat-a"], captures["nat-b"]],
            logs=scan_logs,
            public_artifacts=(
                [
                    outputs["provision"] / "relay" / "ca.der",
                    outputs["provision"] / "relay" / "server.cert.der",
                ]
                if profile == "restrictive-relay"
                else []
            ),
        )
        canary_destroy_result, canary_destroy_path = selected_nat_exec(
            ctx,
            provision_name,
            [
                "/usr/local/bin/aster-selected-nat",
                "canary-destroy",
                "--root",
                "/output",
            ],
        )
        canary_destroy = validate_selected_nat_destroy(
            canary_destroy_result.stdout,
            prefix="SELECTED_NAT_CANARY_DESTROY",
            target="private/canary.bin",
            expected_bytes=32,
        )
        selected_nat_copy_log(canary_destroy_path, ctx.run_dir / "canary-destroy.log")
        relay_destroy: dict[str, str] | None = None
        if profile == "restrictive-relay":
            relay_destroy_result, relay_destroy_path = selected_nat_exec(
                ctx,
                provision_name,
                [
                    "/usr/local/bin/aster-selected-nat",
                    "relay-material-destroy",
                    "--root",
                    "/output/relay",
                ],
            )
            relay_destroy = validate_selected_nat_destroy(
                relay_destroy_result.stdout,
                prefix="SELECTED_NAT_RELAY_MATERIAL_DESTROY",
                target="private/server.key.pkcs8.der",
                expected_bytes=None,
            )
            selected_nat_copy_log(
                relay_destroy_path, ctx.run_dir / "relay-material-destroy.log"
            )
        if (outputs["provision"] / "private" / "canary.bin").exists():
            raise LabError("selected NAT raw canary control remained after bounded unlink")
        if profile == "restrictive-relay" and (
            outputs["provision"] / "relay" / "private" / "server.key.pkcs8.der"
        ).exists():
            raise LabError("selected NAT relay private key remained after bounded unlink")
        restricted_state = normalize_selected_nat_restricted_state(
            ctx, outputs["provision"], profile
        )
        secret_cleanup = {
            "schema": SCHEMA,
            "raw_canary_control_file": canary_destroy,
            "relay_private_key_file": relay_destroy,
            "canary_control_file_disposition": "destroyed-and-unlinked",
            "canary_control_file_previous_bytes": receipt_nonnegative(
                canary_destroy, "previous_bytes"
            ),
            "canary_control_file_absent_after_cleanup": True,
            "relay_private_key_file_disposition": (
                "destroyed-and-unlinked"
                if profile == "restrictive-relay"
                else "not-created"
            ),
            "relay_private_key_file_absent_after_cleanup": True,
            "assurance": "bounded-software",
            "encrypted_event_state_retained": True,
            "mission_credentials_retained_external_restricted": True,
            "global_secret_destruction": False,
            "physical_sanitization": "not-claimed",
            "status": "pass",
        }
        write_exclusive_json(ctx.run_dir / "secret-cleanup.json", secret_cleanup)
        remove_owned_container(ctx, "provision")

        validate_selected_nat_command_ports(ctx.run_dir / "commands.jsonl")
        finalization = {
            "schema": SCHEMA,
            "run_id": ctx.run_id,
            "profile": profile,
            "status": "pass",
            "manifest_sha256": sha256_file(manifest_path),
            "event": {
                "publish": publish,
                "verify": verify,
                "transfer_insertions": transfer_insertions,
                "transfer_fetches": transfer_fetches,
                "sealed_sha256": "not-exposed-by-production-api",
            },
            "nodes": node_results,
            "nft": {
                role: {
                    "before": nft_before[role],
                    "after": nft_after[role],
                    "delta": nft_deltas[role],
                }
                for role in ["nat-a", "nat-b"]
            },
            "pcap": pcap_records,
            "tuple_proof": tuple_proof,
            "relay": relay_receipt,
            "canary_scan": canary_scan,
            "secret_cleanup": secret_cleanup,
            "restricted_state_containment": restricted_state,
            "legacy_ports_4476_4477": False,
            "limitations": [
                "one physical host with Docker namespace isolation",
                "software/static NAT only; no physical NAT hardware or public Internet",
                "no direct-first fallback chronology claim",
                "no exclusive laboratory network or whole-listener pre-auth connection-cap claim",
                "no BTLE, independent implementation, or resource-threshold claim",
                "filesystem timestamps are not an independent clock",
            ],
        }
        write_exclusive_json(ctx.run_dir / "selected-nat-finalization.json", finalization)
        ctx.event("selected-nat-cell-verified", profile=profile, status="pass")
        cleanup_selected_nat_context(ctx, tolerate_errors=False)
        ctx.event(
            "selected-nat-cleanup-verified",
            profile=profile,
            resources=len(resources),
            status="pass",
        )
        write_exclusive_json(
            ctx.run_dir / "cleanup-summary.json",
            {
                "schema": SCHEMA,
                "run_id": ctx.run_id,
                "resources": len(resources),
                "all_owned_resources_removed": True,
                "status": "pass",
            },
        )
        succeeded = True
        return {
            "profile": profile,
            "status": "pass",
            "run_id": ctx.run_id,
            "path": str(ctx.run_dir.relative_to(suite_dir)),
            "source_commit": source["commit"],
            "source_tree": source["tree"],
            "image_id": ctx.image_id,
            "manifest_sha256": sha256_file(manifest_path),
            "finalization_sha256": sha256_file(
                ctx.run_dir / "selected-nat-finalization.json"
            ),
            "identities": {
                node: {
                    "carrier_id": manifest["nodes"][node]["carrier_id"],
                    "mission_id": manifest["nodes"][node]["mission_id"],
                }
                for node in ["a", "b"]
            },
        }
    finally:
        if not succeeded:
            for running in node_commands.values():
                if not running.finished:
                    running.terminate()
            for role, running in capture_commands.items():
                if running.finished:
                    continue
                try:
                    ctx.runner.run(
                        [
                            docker,
                            "exec",
                            "--user",
                            "tcpdump",
                            FIXED_CONTAINER_NAMES[role],
                            "/usr/bin/pkill",
                            "--signal",
                            "INT",
                            "--exact",
                            "tcpdump",
                        ],
                        check=False,
                    )
                    running.finish(check=False)
                except (LabError, OSError):
                    running.terminate()
            cleanup_selected_nat_context(ctx, tolerate_errors=True)


def run_selected_iroh_nat(args: argparse.Namespace) -> None:
    root = args.evidence_root.resolve()
    workspace = WORKSPACE.resolve()
    if root == workspace or workspace in root.parents:
        raise LabError("selected NAT raw evidence root must be outside the source worktree")
    profiles = (
        ["cone-direct", "restrictive-relay"]
        if args.profile == "all"
        else [args.profile]
    )
    resources: list[PlannedResource] = []
    if not args.execute:
        plan_output(
            "selected-iroh-nat",
            resources,
            {
                "profiles": profiles,
                "build": (
                    "sealed selected-NAT context; --network=default --no-cache only "
                    "with explicit --allow-build-network"
                ),
                "topology": "two isolated LAN cells, two exact NAT namespaces, shared internal WAN; pinned relay only in restrictive-relay",
                "route_setup": "ephemeral exact-name NET_ADMIN initializer removed before either cap-free non-root Aster process starts",
                "cone": "static DNAT/SNAT, no relay container/configuration, Direct witness at both endpoints",
                "restrictive": "real direct UDP drops plus exact pinned HTTPS relay, Relay witness at both endpoints",
                "evidence": "named nft before/after counters, lossless WAN pcaps and exact tuples, Event publish/deliver/ack/empty/replay-noop, secret canary scan and bounded control-file unlink",
            },
            image=SELECTED_NAT_IMAGE,
        )
        return
    suite = RunContext.create(root, "selected-iroh-nat", resources, image=SELECTED_NAT_IMAGE)
    build = run_selected_nat_build(suite, args)
    cell_results = [run_selected_nat_cell(suite.run_dir, profile, args) for profile in profiles]
    commits = {record["source_commit"] for record in cell_results}
    trees = {record["source_tree"] for record in cell_results}
    images = {record["image_id"] for record in cell_results}
    if len(commits) != 1 or len(trees) != 1 or len(images) != 1:
        raise LabError("selected NAT cells differ in source tree or immutable image")
    suite_source = load_selected_nat_json(suite.run_dir / "source-identity.json")
    if (
        commits != {suite_source["commit"]}
        or trees != {suite_source["tree"]}
        or images != {build["image_id"]}
    ):
        raise LabError("selected NAT build and cells differ in source or immutable image")
    runtime_identity_receipts: list[tuple[str, dict[str, Any]]] = []
    for record in cell_results:
        runtime = load_selected_nat_json(
            suite.run_dir / record["path"] / "selected-nat-runtime.json"
        )
        runtime_nodes = runtime.get("nodes")
        projected_identities = (
            {
                name: {
                    "carrier_id": node.get("carrier_id"),
                    "mission_id": node.get("mission_id"),
                }
                for name, node in runtime_nodes.items()
            }
            if isinstance(runtime_nodes, dict)
            and all(isinstance(node, dict) for node in runtime_nodes.values())
            else None
        )
        if projected_identities != record["identities"]:
            raise LabError("selected NAT cell result identities differ from runtime")
        runtime_identity_receipts.append((record["profile"], runtime))
    validate_selected_nat_runtime_identity_domains(runtime_identity_receipts)
    if len(cell_results) == 2:
        public_ids = {
            value[field]
            for record in cell_results
            for value in record["identities"].values()
            for field in ["mission_id", "carrier_id"]
        }
        if len(public_ids) != 8:
            raise LabError("selected NAT cells did not use globally fresh identities")
    summary = {
        "schema": SCHEMA,
        "status": "pass",
        "profile": args.profile,
        "cells": cell_results,
        "source_commit": next(iter(commits)),
        "source_tree": next(iter(trees)),
        "source_identity": suite_source,
        "build_identity": build,
        "image_id": next(iter(images)),
        "build_input_manifest_sha256": build["input_manifest_sha256"],
        "build_command_sha256": sha256_text(build["command"]),
        "physical_hosts": 1,
        "namespace_isolation": True,
        "all_resources_removed": True,
        "retained_claim_eligible": args.profile == "all",
    }
    write_exclusive_json(suite.run_dir / "selected-nat-suite.json", summary)
    suite.event("selected-nat-suite-verified", cells=len(cell_results), status="pass")
    if args.profile == "all":
        normalize_selected_nat_curated_artifacts(suite.run_dir)
        prune_selected_nat_transient_artifacts(suite.run_dir)
        receipt_path = suite.run_dir / "selected-iroh-nat-receipt.json"
        projection_command = [
            sys.executable,
            str(Path(__file__).resolve()),
            "selected-iroh-nat-project",
            "--raw-root",
            str(suite.run_dir),
            "--output",
            str(receipt_path),
        ]
        run_selected_nat_replay_tool(projection_command, label="receipt projection")
        os.chmod(receipt_path, 0o600)
        with tempfile.TemporaryDirectory(prefix="aster-selected-nat-replay-") as replay_root:
            replay_path = Path(replay_root) / "selected-iroh-nat-receipt.json"
            run_selected_nat_replay_tool(
                [
                    sys.executable,
                    str(Path(__file__).resolve()),
                    "selected-iroh-nat-project",
                    "--raw-root",
                    str(suite.run_dir),
                    "--output",
                    str(replay_path),
                ],
                label="independent receipt replay",
            )
            original = receipt_path.read_bytes()
            replay = replay_path.read_bytes()
            if original != replay:
                raise LabError("selected NAT raw-root receipt projection is not byte-identical")
        checker = WORKSPACE / "tools" / "check-selected-iroh-nat-receipt.py"
        if checker.is_symlink() or not checker.is_file():
            raise LabError("selected NAT receipt checker is missing or symbolic")
        run_selected_nat_replay_tool(
            [
                sys.executable,
                str(checker),
                "--raw-root",
                str(suite.run_dir),
                "--source",
                str(WORKSPACE),
                str(receipt_path),
            ],
            label="receipt validation",
        )
    print(suite.run_dir)


def run_selected_nat_project(args: argparse.Namespace) -> None:
    root = args.raw_root.resolve()
    output = args.output.resolve()
    if output.parent != root and root not in output.parents:
        # Replay outputs may intentionally live in another owner-only temporary root.
        if output.parent.is_symlink() or not output.parent.is_dir():
            raise LabError("selected NAT projection output parent is unsafe")
    if output.exists() or output.is_symlink():
        raise LabError("selected NAT projection output must be a fresh path")
    document = project_selected_nat_receipt(root)
    write_exclusive_canonical_json(output, document)
    os.chmod(output, 0o600)
    print(output)


def cleanup_selected_nat_context(ctx: RunContext, *, tolerate_errors: bool) -> None:
    """Remove only exact owned selected-NAT resources; never invoke legacy finalization."""
    errors = []
    try:
        verify_orbstack(ctx)
    except LabError as error:
        ctx.event("cleanup-error", kind="daemon", name="orbstack", error=str(error))
        if tolerate_errors:
            return
        raise
    docker = require_docker()
    ordered = [resource for resource in ctx.resources if resource.kind == "container"]
    ordered.extend(resource for resource in ctx.resources if resource.kind == "network")
    for resource in ordered:
        try:
            validate_cleanup_resource(resource, ctx.run_id)
            current = inspect_labels(ctx, resource)
            if current is None:
                ctx.event(
                    "cleanup-absent",
                    kind=resource.kind,
                    name=resource.name,
                    role=resource.role,
                )
                continue
            require_owned_labels(ctx, resource, current)
            if resource.kind == "container":
                if container_is_running(ctx, resource.name):
                    ctx.runner.run(
                        [docker, "container", "stop", "--time", "5", resource.name]
                    )
                logs = ctx.runner.run(
                    [docker, "container", "logs", resource.name], check=False
                )
                if logs.returncode != 0:
                    raise LabError(f"could not preserve selected NAT cleanup log for {resource.name}")
                write_command_linked_receipt(
                    ctx,
                    f"cleanup-{resource.name}",
                    "log",
                    logs.stdout + logs.stderr,
                )
                command = [docker, "container", "rm", "--force", resource.name]
            else:
                command = [docker, "network", "rm", resource.name]
            ctx.runner.run(command)
            ctx.event(
                "resource-removed",
                kind=resource.kind,
                name=resource.name,
                role=resource.role,
            )
        except LabError as error:
            errors.append(str(error))
            ctx.event(
                "cleanup-error",
                kind=resource.kind,
                name=resource.name,
                role=resource.role,
                error=str(error),
            )
    if not errors:
        for resource in ordered:
            if docker_resource_present(ctx, resource.kind, resource.name):
                errors.append(f"selected NAT resource remained after cleanup: {resource.name}")
    if errors and not tolerate_errors:
        raise LabError("selected NAT cleanup failed: " + "; ".join(errors))


def run_scale(args: argparse.Namespace) -> None:
    name = FIXED_CONTAINER_NAMES["scale"]
    resources = [PlannedResource("container", name, "scale")]
    command = [
        "scale",
        "--root",
        "/output/run",
        "--nodes",
        str(args.nodes),
        "--shards",
        str(args.shards),
        "--items",
        str(args.items),
        "--payload-bytes",
        str(args.payload_bytes),
        "--max-pumps",
        str(args.max_pumps),
        *fault_args(args),
    ]
    if not args.execute:
        plan_output(
            "scale",
            resources,
            [
                {
                    "docker_run": command,
                    "limits": {"cpus": args.cpus, "memory": args.memory},
                    "interpretation": "process-sharded deterministic chain simulation; not bridged live-IP acceptance",
                }
            ],
        )
        return
    ctx = RunContext.create(args.evidence_root, "scale", resources)
    docker_preflight(ctx, containers=[name], networks=[])
    write_scenario_request(
        ctx,
        scenario="scale",
        seed=args.seed,
        nodes=args.nodes,
        shards=args.shards,
        items_per_shard=args.items,
        payload_bytes=args.payload_bytes,
        max_pumps=args.max_pumps,
        mtu=args.mtu,
        bits_per_second=args.bps,
        loss_per_mille=args.loss_per_mille,
        reorder_ticks=args.reorder_ticks,
        tick_ms=args.tick_ms,
        cpus=args.cpus,
        memory=args.memory,
    )
    verified = False
    try:
        output_dir = create_output_directory(ctx, "scale")
        pids = max(128, args.shards * 4 + 32)
        completed = ctx.runner.run(
            container_run_args(
                ctx,
                name=name,
                role="scale",
                command=command,
                cpus=args.cpus,
                memory=args.memory,
                pids=pids,
                output_dir=output_dir,
            ),
            check=False,
            timeout=args.timeout,
        )
        if completed.returncode != 0:
            raise LabError(f"scale container failed with {completed.returncode}")
        verify_container_configuration(
            ctx,
            name,
            output_dir=output_dir,
            memory=args.memory,
            cpus=args.cpus,
            pids=pids,
            network="none",
        )
        scenario_metrics(
            ctx,
            "outputs/scale/run",
            {
                "scenario": "scale",
                "seed": args.seed,
                "nodes": args.nodes,
                "shards": args.shards,
                "published_items": args.items * args.shards,
                "delivered_items": args.items * args.nodes,
                "configured_bits_per_second": args.bps,
                "configured_loss_per_mille": args.loss_per_mille,
                "loss_window_frames": 1_000,
            },
        )
        ctx.event("scenario-verified", scenario="scale", nodes=args.nodes, shards=args.shards)
        verified = True
    finally:
        cleanup_context(ctx, tolerate_errors=not verified)
    print(ctx.run_dir)


def inspect_labels(ctx: RunContext, resource: PlannedResource) -> dict[str, str] | None:
    docker = require_docker()
    if not docker_resource_present(ctx, resource.kind, resource.name):
        return None
    if resource.kind == "container":
        args = [docker, "container", "inspect", resource.name, "--format", "{{json .Config.Labels}}"]
    elif resource.kind == "network":
        args = [docker, "network", "inspect", resource.name, "--format", "{{json .Labels}}"]
    else:
        raise LabError(f"unsupported cleanup resource kind: {resource.kind}")
    result = ctx.runner.run(args)
    try:
        value = json.loads(result.stdout)
    except json.JSONDecodeError as error:
        raise LabError(f"malformed labels for {resource.kind} {resource.name}") from error
    if not isinstance(value, dict):
        raise LabError(f"labels are not an object for {resource.kind} {resource.name}")
    return {str(key): str(item) for key, item in value.items()}


def require_owned_labels(
    ctx: RunContext, resource: PlannedResource, current: dict[str, str]
) -> None:
    expected = {
        MANAGED_LABEL: "true",
        RUN_LABEL: ctx.run_id,
        ROLE_LABEL: resource.role,
    }
    if any(current.get(key) != value for key, value in expected.items()):
        raise LabError(
            f"refusing operation on {resource.kind} {resource.name}: ownership labels differ"
        )


def write_command_linked_receipt(
    ctx: RunContext, stem: str, suffix: str, value: str
) -> Path:
    path = ctx.run_dir / f"{stem}-command-{ctx.runner.sequence:04d}.{suffix}"
    write_exclusive_text(path, value)
    return path


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def validate_linked_receipt(
    ctx: RunContext,
    record: dict[str, Any],
    field: str,
    *,
    prefix: str,
    suffix: str,
) -> str:
    name = record.get(field)
    digest = record.get(f"{field}_sha256")
    if not isinstance(name, str) or not re.fullmatch(
        rf"{re.escape(prefix)}-command-[0-9]{{4,}}\.{re.escape(suffix)}", name
    ):
        raise LabError(f"NAT linked receipt name is invalid: {field}")
    if not isinstance(digest, str) or not re.fullmatch(r"[0-9a-f]{64}", digest):
        raise LabError(f"NAT linked receipt digest is invalid: {field}")
    path = confined_run_path(ctx, ctx.run_dir / name)
    if path.is_symlink() or not path.is_file() or sha256_file(path) != digest:
        raise LabError(f"NAT linked receipt is missing or differs: {field}")
    return path.read_text(encoding="utf-8")


def container_is_running(ctx: RunContext, name: str) -> bool:
    result = ctx.runner.run(
        [require_docker(), "container", "inspect", name, "--format", "{{json .State}}"]
    )
    try:
        state = json.loads(result.stdout)
    except json.JSONDecodeError as error:
        raise LabError("Docker returned malformed container state") from error
    if not isinstance(state, dict) or type(state.get("Running")) is not bool:
        raise LabError("Docker container state has no Running boolean")
    return state["Running"]


def validate_nat_terminal_receipts(
    ctx: RunContext, receipt: dict[str, Any], runtime: dict[str, Any]
) -> list[dict[str, Any]]:
    if receipt.get("schema") != SCHEMA or receipt.get("run_id") != ctx.run_id:
        raise LabError("NAT terminal receipt schema or run ID differs")
    routers = receipt.get("routers")
    if not isinstance(routers, list) or len(routers) != 2:
        raise LabError("NAT terminal receipt has no exact router set")
    seen = set()
    for record in routers:
        if not isinstance(record, dict) or record.get("role") not in {"nat-a", "nat-b"}:
            raise LabError("NAT terminal router receipt is invalid")
        role = record["role"]
        if role in seen:
            raise LabError("NAT terminal router receipt is duplicated")
        seen.add(role)
        qdisc = validate_linked_receipt(
            ctx, record, "qdisc_receipt", prefix=f"{role}-qdisc-final", suffix="json"
        )
        if runtime["shape_bps"] > 0:
            verify_qdisc_json(
                qdisc,
                expected_bps=runtime["shape_bps"],
                expected_loss_percent=runtime["loss_percent"],
                expected_limit=runtime["netem_limit"],
                expected_seed=runtime["netem_seed"],
            )
        else:
            try:
                if not isinstance(json.loads(qdisc), list):
                    raise LabError("terminal qdisc receipt is not a list")
            except json.JSONDecodeError as error:
                raise LabError("terminal qdisc receipt is malformed") from error
        nft = validate_linked_receipt(
            ctx, record, "nft_receipt", prefix=f"{role}-nft-final", suffix="json"
        )
        try:
            if not isinstance(json.loads(nft), dict):
                raise LabError("terminal nft receipt is not an object")
        except json.JSONDecodeError as error:
            raise LabError("terminal nft receipt is malformed") from error
    if seen != {"nat-a", "nat-b"}:
        raise LabError("NAT terminal router roles differ")
    infra = validate_linked_receipt(
        ctx, receipt, "infra_log_receipt", prefix="nat-infra-final", suffix="log"
    )
    if "ASTER_LAB_INFRA_READY\tversion=1" not in infra:
        raise LabError("terminal infrastructure receipt lacks its readiness marker")
    return routers


def finalize_nat(ctx: RunContext) -> None:
    """Idempotently stop captures after binding terminal counter/log receipts."""
    runtime_path = ctx.run_dir / "nat-runtime.json"
    if runtime_path.is_symlink():
        raise LabError("NAT runtime receipt cannot be symbolic")
    if not runtime_path.is_file():
        return
    try:
        runtime = json.loads(runtime_path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as error:
        raise LabError("NAT runtime receipt is malformed") from error
    if not isinstance(runtime, dict) or runtime.get("schema") != SCHEMA:
        raise LabError("NAT runtime receipt schema mismatch")
    if runtime.get("profile") not in {"cone", "restrictive"}:
        raise LabError("NAT runtime profile is invalid")
    integer_fields = {
        "shape_bps": (0, 1_000_000_000),
        "loss_percent": (0, 100),
        "netem_limit": (64, 64),
        "netem_seed_requested": (1, 2**31 - 1),
    }
    for field, (minimum, maximum) in integer_fields.items():
        value = runtime.get(field)
        if type(value) is not int or not minimum <= value <= maximum:
            raise LabError(f"NAT runtime {field} is invalid")
    seed_status = runtime.get("netem_seed_status")
    if seed_status not in {"applied", "unsupported", "not-requested"}:
        raise LabError("NAT runtime netem seed status is invalid")
    applied_seed = runtime.get("netem_seed")
    if seed_status == "applied":
        if applied_seed != runtime["netem_seed_requested"]:
            raise LabError("NAT runtime applied netem seed differs from the request")
    elif applied_seed is not None:
        raise LabError("NAT runtime records a seed that was not applied")
    if runtime["shape_bps"] > 0 and seed_status == "not-requested":
        raise LabError("NAT runtime omitted netem seed capability status")
    if runtime["shape_bps"] == 0 and seed_status != "not-requested":
        raise LabError("NAT runtime records a netem seed for an unshaped topology")
    if runtime.get("infra") != FIXED_CONTAINER_NAMES["infra"]:
        raise LabError("NAT runtime infrastructure differs from the fixed allowlist")
    routers = runtime.get("routers")
    if not isinstance(routers, list) or len(routers) != 2:
        raise LabError("NAT runtime receipt has no exact router set")

    final_path = ctx.run_dir / "nat-finalization.json"
    if final_path.is_symlink():
        raise LabError("NAT finalization receipt cannot be symbolic")
    if final_path.is_file():
        try:
            prior = json.loads(final_path.read_text(encoding="utf-8"))
        except json.JSONDecodeError as error:
            raise LabError("existing NAT finalization receipt is malformed") from error
        if not isinstance(prior, dict):
            raise LabError("existing NAT finalization receipt is not an object")
        final_routers = validate_nat_terminal_receipts(ctx, prior, runtime)
        for record in final_routers:
            role = record["role"]
            expected = f"outputs/{role}/{role}-wan.pcap"
            if record.get("capture") != expected:
                raise LabError("existing NAT finalization capture path differs")
            capture = confined_run_path(ctx, ctx.run_dir / expected)
            size = validate_pcap(capture)
            if size != record.get("capture_bytes") or sha256_file(capture) != record.get(
                "capture_sha256"
            ):
                raise LabError("existing NAT finalization capture differs")
        return

    runtime_by_role: dict[str, dict[str, Any]] = {}
    for record in routers:
        if not isinstance(record, dict):
            raise LabError("NAT router runtime entry is malformed")
        role = record.get("role")
        if role not in {"nat-a", "nat-b"} or role in runtime_by_role:
            raise LabError("NAT router runtime role is invalid or duplicated")
        container = FIXED_CONTAINER_NAMES[role]
        if record.get("container") != container:
            raise LabError("NAT router runtime container differs from the fixed allowlist")
        if record.get("capture_container_path") != f"/output/{role}-wan.pcap":
            raise LabError("NAT capture container path differs from the fixed plan")
        if record.get("capture_relative_path") != f"outputs/{role}/{role}-wan.pcap":
            raise LabError("NAT capture host path differs from the isolated output plan")
        wan_if = record.get("wan_interface")
        if not isinstance(wan_if, str) or not re.fullmatch(r"[A-Za-z0-9_.-]{1,32}", wan_if):
            raise LabError("NAT runtime WAN interface is invalid")
        resource = PlannedResource("container", container, role)
        current = inspect_labels(ctx, resource)
        if current is None:
            raise LabError(f"cannot finalize absent NAT router {container}")
        require_owned_labels(ctx, resource, current)
        runtime_by_role[role] = record

    started_path = ctx.run_dir / "nat-finalization-started.json"
    if started_path.is_symlink():
        raise LabError("NAT finalization-start receipt cannot be symbolic")
    if started_path.is_file():
        try:
            started = json.loads(started_path.read_text(encoding="utf-8"))
        except json.JSONDecodeError as error:
            raise LabError("NAT finalization-start receipt is malformed") from error
        if not isinstance(started, dict):
            raise LabError("NAT finalization-start receipt is not an object")
        terminal_routers = validate_nat_terminal_receipts(ctx, started, runtime)
    else:
        docker = require_docker()
        terminal_routers = []
        for role in ["nat-a", "nat-b"]:
            record = runtime_by_role[role]
            container = FIXED_CONTAINER_NAMES[role]
            if not container_is_running(ctx, container):
                raise LabError(f"NAT router stopped before finalization began: {container}")
            if not capture_process_running(
                ctx, container, record["capture_container_path"]
            ):
                raise LabError(f"tcpdump was not live when finalization began: {container}")
            qdisc = ctx.runner.run(
                [
                    docker,
                    "exec",
                    container,
                    "/usr/sbin/tc",
                    "-s",
                    "-j",
                    "qdisc",
                    "show",
                    "dev",
                    record["wan_interface"],
                ]
            )
            if runtime["shape_bps"] > 0:
                verify_qdisc_json(
                    qdisc.stdout,
                    expected_bps=runtime["shape_bps"],
                    expected_loss_percent=runtime["loss_percent"],
                    expected_limit=runtime["netem_limit"],
                    expected_seed=runtime["netem_seed"],
                )
            else:
                try:
                    if not isinstance(json.loads(qdisc.stdout), list):
                        raise LabError("terminal qdisc output is not a list")
                except json.JSONDecodeError as error:
                    raise LabError("terminal qdisc output is malformed") from error
            qdisc_path = write_command_linked_receipt(
                ctx, f"{role}-qdisc-final", "json", qdisc.stdout
            )
            rules = ctx.runner.run(
                [docker, "exec", container, "/usr/sbin/nft", "--json", "list", "ruleset"]
            )
            try:
                if not isinstance(json.loads(rules.stdout), dict):
                    raise LabError("terminal nft output is not an object")
            except json.JSONDecodeError as error:
                raise LabError("terminal nft output is malformed") from error
            nft_path = write_command_linked_receipt(
                ctx, f"{role}-nft-final", "json", rules.stdout
            )
            terminal_routers.append(
                {
                    "role": role,
                    "qdisc_receipt": qdisc_path.name,
                    "qdisc_receipt_sha256": sha256_file(qdisc_path),
                    "nft_receipt": nft_path.name,
                    "nft_receipt_sha256": sha256_file(nft_path),
                }
            )
        infra_resource = PlannedResource("container", FIXED_CONTAINER_NAMES["infra"], "infra")
        infra_labels = inspect_labels(ctx, infra_resource)
        if infra_labels is None:
            raise LabError("cannot finalize absent NAT infrastructure container")
        require_owned_labels(ctx, infra_resource, infra_labels)
        infra_logs = ctx.runner.run([docker, "container", "logs", infra_resource.name])
        if "ASTER_LAB_INFRA_READY\tversion=1" not in infra_logs.stdout + infra_logs.stderr:
            raise LabError("NAT infrastructure readiness marker is absent at finalization")
        infra_path = write_command_linked_receipt(
            ctx, "nat-infra-final", "log", infra_logs.stdout + infra_logs.stderr
        )
        started = {
            "schema": SCHEMA,
            "run_id": ctx.run_id,
            "started_utc": utc_now(),
            "infra_log_receipt": infra_path.name,
            "infra_log_receipt_sha256": sha256_file(infra_path),
            "routers": terminal_routers,
        }
        validate_nat_terminal_receipts(ctx, started, runtime)
        write_atomic_exclusive_json(started_path, started)

    docker = require_docker()
    summaries = []
    terminal_by_role = {record["role"]: record for record in terminal_routers}
    for role in ["nat-a", "nat-b"]:
        container = FIXED_CONTAINER_NAMES[role]
        if container_is_running(ctx, container):
            stop_capture = ctx.runner.run(
                [
                    docker,
                    "exec",
                    "--user",
                    "tcpdump",
                    container,
                    "/usr/bin/pkill",
                    "--signal",
                    "INT",
                    "--exact",
                    "tcpdump",
                ],
                check=False,
            )
            if stop_capture.returncode not in {0, 1}:
                raise LabError(f"could not signal tcpdump cleanly in {container}")
            deadline = time.monotonic() + 10.0
            while True:
                if not capture_process_running(
                    ctx,
                    container,
                    runtime_by_role[role]["capture_container_path"],
                ):
                    break
                if time.monotonic() >= deadline:
                    raise LabError(f"tcpdump did not stop cleanly in {container}")
                time.sleep(0.25)
        capture_relative = f"outputs/{role}/{role}-wan.pcap"
        capture = confined_run_path(ctx, ctx.run_dir / capture_relative)
        size = validate_pcap(capture)
        summaries.append(
            {
                **terminal_by_role[role],
                "capture": capture_relative,
                "capture_bytes": size,
                "capture_sha256": sha256_file(capture),
            }
        )
    final = {
        "schema": SCHEMA,
        "run_id": ctx.run_id,
        "finalized_utc": utc_now(),
        "infra_log_receipt": started["infra_log_receipt"],
        "infra_log_receipt_sha256": started["infra_log_receipt_sha256"],
        "routers": summaries,
    }
    validate_nat_terminal_receipts(ctx, final, runtime)
    write_atomic_exclusive_json(final_path, final)
    ctx.event("nat-finalized", routers=len(summaries))


def validate_cleanup_resource(resource: PlannedResource, run_id: str) -> None:
    if resource.kind not in {"container", "network"}:
        raise LabError(f"cleanup kind not permitted: {resource.kind}")
    validate_resource_name(resource.name)
    if resource.kind == "container" and resource.name not in FIXED_CONTAINER_NAMES.values():
        raise LabError(f"container is not in the exact cleanup allowlist: {resource.name}")
    allowed_networks = {DIRECT_NETWORK, *(value[0] for value in NAT_NETWORKS.values())}
    if resource.kind == "network" and resource.name not in allowed_networks:
        raise LabError(f"network is not in the exact cleanup allowlist: {resource.name}")
    if not RUN_ID.fullmatch(run_id):
        raise LabError("malformed cleanup run identifier")


def cleanup_context(ctx: RunContext, *, tolerate_errors: bool) -> None:
    errors = []
    try:
        verify_orbstack(ctx)
    except LabError as error:
        ctx.event("cleanup-error", kind="daemon", name="orbstack", error=str(error))
        if tolerate_errors:
            return
        raise
    has_nat_resources = any(
        resource.kind == "container" and resource.role in {"nat-a", "nat-b", "infra"}
        for resource in ctx.resources
    )
    if has_nat_resources:
        try:
            if not (ctx.run_dir / "nat-runtime.json").is_file() and not tolerate_errors:
                raise LabError("NAT cleanup requires its readiness/runtime receipt")
            finalize_nat(ctx)
        except LabError as error:
            errors.append(str(error))
            ctx.event("cleanup-error", kind="finalization", name="nat", error=str(error))
            if not tolerate_errors:
                raise LabError(f"NAT finalization failed; resources were retained: {error}") from error
    ordered = [resource for resource in ctx.resources if resource.kind == "container"]
    ordered.extend(resource for resource in ctx.resources if resource.kind == "network")
    for resource in ordered:
        try:
            validate_cleanup_resource(resource, ctx.run_id)
            current = inspect_labels(ctx, resource)
            if current is None:
                ctx.event("cleanup-absent", kind=resource.kind, name=resource.name)
                continue
            require_owned_labels(ctx, resource, current)
            if resource.kind == "container":
                if has_nat_resources and (ctx.run_dir / "nat-finalization.json").is_file():
                    if container_is_running(ctx, resource.name):
                        ctx.runner.run(
                            [
                                require_docker(),
                                "container",
                                "stop",
                                "--time",
                                "5",
                                resource.name,
                            ]
                        )
                logs = ctx.runner.run(
                    [require_docker(), "container", "logs", resource.name], check=False
                )
                if logs.returncode != 0:
                    raise LabError(f"could not preserve final logs for {resource.name}")
                write_command_linked_receipt(
                    ctx,
                    f"cleanup-{resource.name}",
                    "log",
                    logs.stdout + logs.stderr,
                )
                command = [require_docker(), "container", "rm", "--force", resource.name]
            else:
                command = [require_docker(), "network", "rm", resource.name]
            ctx.runner.run(command)
            ctx.event("resource-removed", kind=resource.kind, name=resource.name)
        except LabError as error:
            errors.append(str(error))
            ctx.event("cleanup-error", kind=resource.kind, name=resource.name, error=str(error))
    if errors and not tolerate_errors:
        raise LabError("cleanup failed: " + "; ".join(errors))


def load_cleanup_context(run_dir: Path) -> RunContext:
    resolved = run_dir.resolve()
    manifest_path = resolved / "controller.json"
    if not manifest_path.is_file():
        raise LabError("cleanup requires an Aster lab controller.json manifest")
    with manifest_path.open(encoding="utf-8") as stream:
        manifest = json.load(stream)
    if manifest.get("schema") != SCHEMA or manifest.get("evidence_dir") != str(resolved):
        raise LabError("cleanup manifest schema or evidence path mismatch")
    run_id = manifest.get("run_id")
    label = manifest.get("label")
    if not isinstance(run_id, str) or not RUN_ID.fullmatch(run_id):
        raise LabError("cleanup manifest run identifier is invalid")
    if not isinstance(label, str) or not re.fullmatch(r"[a-z0-9-]{1,32}", label):
        raise LabError("cleanup manifest label is invalid")
    resources = []
    for value in manifest.get("resources", []):
        if not isinstance(value, dict):
            raise LabError("cleanup manifest resource is invalid")
        resource = PlannedResource(
            kind=str(value.get("kind", "")),
            name=str(value.get("name", "")),
            role=str(value.get("role", "")),
        )
        validate_cleanup_resource(resource, run_id)
        resources.append(resource)
    return RunContext(label, run_id, resolved, resources, CommandRunner(resolved))


def run_cleanup(args: argparse.Namespace) -> None:
    if not args.execute:
        print(
            json.dumps(
                {
                    "schema": SCHEMA,
                    "dry_run": True,
                    "operation": "cleanup",
                    "run_dir": str(args.run_dir.resolve()),
                    "safety": "Only exact manifest resources with matching ownership labels are removable.",
                },
                indent=2,
                sort_keys=True,
            )
        )
        return
    ctx = load_cleanup_context(args.run_dir)
    cleanup_context(ctx, tolerate_errors=False)
    print(ctx.run_dir)


def positive_int(value: str) -> int:
    parsed = int(value)
    if parsed <= 0:
        raise argparse.ArgumentTypeError("must be positive")
    return parsed


def nonnegative_int(value: str) -> int:
    parsed = int(value)
    if parsed < 0:
        raise argparse.ArgumentTypeError("must be nonnegative")
    return parsed


def bounded_int(minimum: int, maximum: int):
    def parse(value: str) -> int:
        parsed = int(value)
        if not minimum <= parsed <= maximum:
            raise argparse.ArgumentTypeError(f"must be in {minimum}..{maximum}")
        return parsed

    return parse


def memory_value(value: str) -> str:
    if not MEMORY_VALUE.fullmatch(value):
        raise argparse.ArgumentTypeError("use a Docker byte value such as 64m or 3g")
    return value.lower()


def cpu_value(value: str) -> str:
    if not CPU_VALUE.fullmatch(value) or float(value) <= 0:
        raise argparse.ArgumentTypeError("use a positive Docker CPU value such as 1 or 1.5")
    return value


def add_execution(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "--execute",
        action="store_true",
        help="perform mutations; without this option only a plan is printed",
    )
    parser.add_argument(
        "--evidence-root",
        type=Path,
        default=DEFAULT_EVIDENCE_ROOT,
        help=f"parent for single-use run directories (default: {DEFAULT_EVIDENCE_ROOT})",
    )


def add_faults(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--seed", type=bounded_int(0, 2**64 - 1), default=1)
    parser.add_argument("--mtu", type=bounded_int(64, 65_535), default=1_200)
    parser.add_argument("--bps", type=positive_int, default=1_000_000)
    parser.add_argument("--loss-per-mille", type=bounded_int(0, 900), default=0)
    parser.add_argument("--reorder-ticks", type=bounded_int(0, 65_535), default=0)
    parser.add_argument("--tick-ms", type=bounded_int(1, 65_535), default=100)


def parser() -> argparse.ArgumentParser:
    result = argparse.ArgumentParser(description=__doc__)
    subparsers = result.add_subparsers(dest="operation", required=True)

    build = subparsers.add_parser(
        "build", help="build the pinned lab image without image pulls (network is opt-in)"
    )
    add_execution(build)
    build.add_argument("--replace-image", action="store_true")
    build.add_argument(
        "--allow-build-network",
        action="store_true",
        help="explicitly permit dependency acquisition with --network=default and --no-cache",
    )
    build.add_argument("--timeout", type=positive_int, default=3_600)
    build.set_defaults(handler=run_build)

    self_contained = subparsers.add_parser(
        "self-contained", help="run deterministic transfer or Blob recovery in one container"
    )
    add_execution(self_contained)
    add_faults(self_contained)
    self_contained.add_argument("scenario", choices=["transfer", "blob-recovery"])
    self_contained.add_argument("--items", type=bounded_int(1, 4_096), default=4)
    self_contained.add_argument("--payload-bytes", type=positive_int, default=65_536)
    self_contained.add_argument("--blob-bytes", type=positive_int, default=105_906_176)
    self_contained.add_argument("--chunk-bytes", type=positive_int, default=65_536)
    self_contained.add_argument("--restart-after-frames", type=nonnegative_int, default=256)
    self_contained.add_argument("--max-pumps", type=positive_int, default=2_000_000)
    self_contained.add_argument("--cpus", type=cpu_value, default="2")
    self_contained.add_argument("--memory", type=memory_value, default="4g")
    self_contained.add_argument("--timeout", type=positive_int, default=1_800)
    self_contained.set_defaults(handler=run_self_contained)

    two_node = subparsers.add_parser("two-node", help="run two real UDP node containers")
    add_execution(two_node)
    two_node.add_argument(
        "--seed",
        type=bounded_int(0, 2**64 - 1),
        default=1,
        help="public canary workload seed; never used for identity or capability material",
    )
    two_node.add_argument("--items", type=bounded_int(1, 2_048), default=4)
    two_node.add_argument("--payload-bytes", type=positive_int, default=1_024)
    two_node.add_argument("--duration-ms", type=positive_int, default=60_000)
    two_node.add_argument("--max-pumps", type=positive_int, default=1_000_000)
    two_node.add_argument("--responder-settle-ms", type=positive_int, default=1_000)
    two_node.add_argument("--cpus", type=cpu_value, default="1")
    two_node.add_argument("--memory", type=memory_value, default="512m")
    two_node.set_defaults(handler=run_two_node)

    resource = subparsers.add_parser("resource", help="capture cgroup-v2 usage for one logical node")
    add_execution(resource)
    add_faults(resource)
    resource.add_argument("--items", type=positive_int, default=10_000)
    resource.add_argument("--payload-bytes", type=positive_int, default=64)
    resource.add_argument("--max-pumps", type=positive_int, default=100_000)
    resource.add_argument("--cpus", type=cpu_value, default="1")
    resource.add_argument("--memory", type=memory_value, default="64m")
    resource.add_argument("--sample-interval", type=float, default=1.0)
    resource.add_argument("--timeout", type=positive_int, default=1_200)
    resource.set_defaults(handler=run_resource)

    nat = subparsers.add_parser("nat-up", help="create the five-unit controlled NAT topology")
    add_execution(nat)
    nat.add_argument("--profile", choices=["cone", "restrictive"], default="cone")
    nat.add_argument("--shape-bps", type=bounded_int(0, 1_000_000_000), default=0)
    nat.add_argument("--loss-percent", type=bounded_int(0, 100), default=0)
    nat.add_argument("--seed", type=bounded_int(1, 2**31 - 1), default=424_242)
    nat.add_argument("--duration-ms", type=positive_int, default=3_600_000)
    nat.set_defaults(handler=run_nat_up)

    selected_nat = subparsers.add_parser(
        "selected-iroh-nat-run",
        help="build and run the explicit two-cell selected-Iroh NAT acceptance",
    )
    add_execution(selected_nat)
    selected_nat.set_defaults(evidence_root=DEFAULT_SELECTED_NAT_EVIDENCE_ROOT)
    selected_nat.add_argument(
        "--profile",
        choices=["cone-direct", "restrictive-relay", "all"],
        default="all",
    )
    selected_nat.add_argument(
        "--allow-build-network",
        action="store_true",
        help=(
            "explicitly permit the selected image's --network=default --no-cache build; "
            "runtime cells remain internal"
        ),
    )
    selected_nat.add_argument("--build-timeout", type=positive_int, default=3_600)
    selected_nat.add_argument(
        "--duration-seconds",
        type=bounded_int(
            SELECTED_NAT_RUN_FOR_SECONDS,
            SELECTED_NAT_RUN_FOR_SECONDS,
        ),
        default=SELECTED_NAT_RUN_FOR_SECONDS,
        help="fixed 30-second selected node run budget",
    )
    selected_nat.set_defaults(handler=run_selected_iroh_nat)

    selected_project = subparsers.add_parser(
        "selected-iroh-nat-project",
        help="derive one canonical sanitized receipt from a completed raw suite root",
    )
    selected_project.add_argument("--raw-root", type=Path, required=True)
    selected_project.add_argument("--output", type=Path, required=True)
    selected_project.set_defaults(handler=run_selected_nat_project)

    scale = subparsers.add_parser("scale", help="run deterministic process-sharded scale simulation")
    add_execution(scale)
    add_faults(scale)
    scale.add_argument("--nodes", type=positive_int, default=100)
    scale.add_argument("--shards", type=positive_int, default=4)
    scale.add_argument("--items", type=bounded_int(1, 4_096), default=1)
    scale.add_argument("--payload-bytes", type=positive_int, default=1_024)
    scale.add_argument("--max-pumps", type=positive_int, default=100_000)
    scale.add_argument("--cpus", type=cpu_value, default="4")
    scale.add_argument("--memory", type=memory_value, default="12g")
    scale.add_argument("--timeout", type=positive_int, default=3_600)
    scale.set_defaults(handler=run_scale)

    cleanup = subparsers.add_parser("cleanup", help="remove only exact, owned resources from one run")
    cleanup.add_argument("--execute", action="store_true")
    cleanup.add_argument("run_dir", type=Path)
    cleanup.set_defaults(handler=run_cleanup)
    return result


def validate_arguments(args: argparse.Namespace) -> None:
    if hasattr(args, "shards") and hasattr(args, "nodes") and args.shards > args.nodes:
        raise LabError("shards cannot exceed nodes")
    if hasattr(args, "sample_interval") and (
        not math.isfinite(args.sample_interval) or args.sample_interval <= 0
    ):
        raise LabError("sample interval must be finite and positive")
    if hasattr(args, "loss_percent") and args.shape_bps == 0 and args.loss_percent != 0:
        raise LabError("--loss-percent requires nonzero --shape-bps")


def main(argv: Sequence[str] | None = None) -> int:
    args = parser().parse_args(argv)
    try:
        validate_arguments(args)
        args.handler(args)
        return 0
    except (LabError, json.JSONDecodeError, OSError, ValueError) as error:
        print(f"aster-lab controller: {error}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
