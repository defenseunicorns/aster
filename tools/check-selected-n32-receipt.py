#!/usr/bin/env python3
# Copyright 2026 Defense Unicorns, Inc.
# SPDX-License-Identifier: Apache-2.0
"""Validate and summarize one selected N=32 process-acceptance run.

The receipt is intentionally narrower than a physical-network acceptance record.
It proves the selected one-host, loopback N=32 demo contract represented by the
retained stdout and child logs.  It does not claim distinct physical hosts, NAT,
relay, BTLE, resource-threshold, or independent-implementation evidence.

Only standard-library modules are used.  The emitted JSON contains no input paths,
node identities, process IDs, ports, transfer identifiers, or hashes of state,
mission, identity, or other secret-bearing files.  Log hashes are computed over a
canonical redacted representation after all semantic checks have passed.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import platform
import re
import stat
import subprocess
import sys
from typing import Any, Iterable


SCHEMA = "aster-selected-n32-receipt/v1"
NODE_COUNT = 32
PHASE_COUNT = 65
PROCESS_COUNT = 158
LOG_COUNT = 158
RECEIPT_MAX_BYTES = 16 * 1024
STDOUT_MAX_BYTES = 64 * 1024
STDERR_MAX_BYTES = 16 * 1024
CHILD_LOG_MAX_BYTES = 128 * 1024
CHILD_ERR_MAX_BYTES = 4 * 1024
CHILD_TOTAL_MAX_BYTES = 4 * 1024 * 1024
CHILD_LOG_MAX_LINES = 128
BINARY_MAX_BYTES = 256 * 1024 * 1024
GIT_OUTPUT_MAX_BYTES = 4 * 1024 * 1024
IDENTITY_BYTES = 32
MISSION_BUNDLE_MAX_BYTES = 1024 * 1024
STORE_MAX_BYTES = 1024 * 1024 * 1024
TRANSCRIPT_MANIFEST_RECORDS = 318
TRANSCRIPT_MANIFEST_BYTES = 33_102
EXPECTED_BUILD_COMMAND = "cargo build --release --locked -p aster-node --bin aster"
EXPECTED_HOST_OS = "Darwin"
EXPECTED_HOST_ARCH = "arm64"
EXPECTED_RUSTC_VERSION = "1.97.1"
EXPECTED_RUSTC_COMMIT = "8bab26f4f68e0e26f0bb7960be334d5b520ea452"
EXPECTED_BUILD_TARGET = "aarch64-apple-darwin"

HEX_32 = re.compile(r"[0-9a-f]{64}\Z")
GIT_OBJECT = re.compile(r"[0-9a-f]{40}\Z")
FIELD_NAME = re.compile(r"[a-z][a-z0-9_]*\Z")
LOOPBACK_SOCKET = re.compile(r"127\.0\.0\.1:([1-9][0-9]{0,4})\Z")
TIME_SUMMARY = re.compile(
    r"\s*([0-9]+(?:\.[0-9]+)?) real\s+"
    r"([0-9]+(?:\.[0-9]+)?) user\s+"
    r"([0-9]+(?:\.[0-9]+)?) sys\s*\Z"
)

SUBSCRIPTION_KEYS = (
    "status",
    "consume",
    "carry",
    "selectors",
    "interest_exchange",
    "lanes",
)
PHASE_KEYS = (
    "status",
    "name",
    "processes",
    "carrier_authenticated_edges",
    "mission_authenticated_edges",
    "provisioning",
)
PING_KEYS = (
    "status",
    "emitted_by",
    "producer_state",
    "destination_state",
    "transfer_id",
    "semantic_id",
    "producer_process_absent",
    "source_authenticated",
    "ttl",
)
PONG_KEYS = (
    "status",
    "emitted_by",
    "producer_state",
    "destination_state",
    "correlation_semantic_id",
    "transfer_id",
    "semantic_id",
    "source_authenticated",
    "causal_observation",
    "ttl",
)
RELAY_KEYS = (
    "status",
    "intermediates",
    "exact_forward",
    "content_access",
    "semantic_acceptance",
)
RESULT_KEYS = (
    "status",
    "scenario",
    "nodes",
    "processes",
    "contacts",
    "mission_auth",
    "provisioning",
    "stores",
    "reconciliation",
    "producer_process_absent",
    "restarts",
    "atomic_reaction",
    "equal_inventory_noop",
    "transfers_each",
    "semantics",
    "emitted_by",
    "payload_blind_relays",
    "ttl",
    "root",
)
READY_KEYS = (
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
)
CONTACT_KEYS = (
    "direction",
    "carrier_peer",
    "mission_peer",
    "rounds",
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
)
STOP_KEYS = (
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
)
PING_APPLICATION_KEYS = (
    "status",
    "kind",
    "transfer_id",
    "semantic_id",
    "publisher",
    "source_authenticated",
    "ttl",
)
PONG_APPLICATION_KEYS = (
    "status",
    "kind",
    "transfer_id",
    "semantic_id",
    "publisher",
    "correlation_semantic_id",
    "ping_publisher",
    "source_authenticated",
    "causal_observation",
    "ttl",
)

ZERO_CONTACT_FIELDS = (
    "control_offered",
    "control_fetched",
    "control_retained",
    "control_duplicates",
    "control_activated",
    "control_remaining",
    "remaining",
    "deferred_event_lanes",
    "mutable_remaining",
    "deferred_mutable_lanes",
    "blob_ranges_fetched",
    "blob_bytes_fetched",
    "blob_remaining",
    "blob_deferred",
)
ZERO_STOP_FIELDS = (
    "contact_errors",
    "relay_contacts",
    "unknown_path_contacts",
    "carrier_path_transitions",
    "carrier_path_transition_saturations",
    "opaque_items",
    "opaque_acceptance_markers",
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
)
SENSITIVE_FIELDS = frozenset(
    {
        "pid",
        "carrier_id",
        "mission_id",
        "mission_authority",
        "carrier_peer",
        "mission_peer",
        "transfer_id",
        "semantic_id",
        "correlation_semantic_id",
        "publisher",
        "ping_publisher",
    }
)
PATH_FIELDS = frozenset({"state", "root"})

DARWIN_TIME_FIELDS = (
    "maximum resident set size",
    "average shared memory size",
    "average unshared data size",
    "average unshared stack size",
    "page reclaims",
    "page faults",
    "swaps",
    "block input operations",
    "block output operations",
    "messages sent",
    "messages received",
    "signals received",
    "voluntary context switches",
    "involuntary context switches",
    "instructions retired",
    "cycles elapsed",
    "peak memory footprint",
)


class ReceiptViolation(ValueError):
    """A retained artifact did not satisfy the selected N=32 contract."""


def fail(message: str) -> None:
    raise ReceiptViolation(message)


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def strict_uint(value: str, label: str, maximum: int = (1 << 63) - 1) -> int:
    if not value or not value.isascii() or not value.isdigit():
        fail(f"{label} is not an unsigned decimal integer")
    if len(value) > 1 and value.startswith("0"):
        fail(f"{label} is not canonically encoded")
    parsed = int(value)
    if parsed > maximum:
        fail(f"{label} exceeds its evidence bound")
    return parsed


def require_hex_32(value: str, label: str) -> None:
    if HEX_32.fullmatch(value) is None:
        fail(f"{label} is not one canonical 32-byte identifier")


def require_fixed(record: dict[str, str], expected: dict[str, str], label: str) -> None:
    for key, value in expected.items():
        if record.get(key) != value:
            fail(f"{label} has an unexpected {key} value")


def receipt_path(value: Path) -> str:
    output: list[str] = []
    for byte in os.fsencode(value):
        character = chr(byte)
        if character.isascii() and (character.isalnum() or character in "-_./:"):
            output.append(character)
        else:
            output.append(f"%{byte:02X}")
    return "".join(output)


def parse_record(
    line: str, expected_prefix: str, label: str
) -> tuple[list[tuple[str, str]], dict[str, str]]:
    if not line or len(line.encode("utf-8")) > 16 * 1024:
        fail(f"{label} is empty or exceeds the line bound")
    parts = line.split(" ")
    if not parts or parts[0] != expected_prefix or any(part == "" for part in parts):
        fail(f"{label} has an unexpected record prefix or delimiter")
    ordered: list[tuple[str, str]] = []
    record: dict[str, str] = {}
    for token in parts[1:]:
        key, separator, value = token.partition("=")
        if separator != "=" or FIELD_NAME.fullmatch(key) is None or not value:
            fail(f"{label} contains a malformed field")
        if key in record:
            fail(f"{label} contains a duplicate field")
        if any(ord(character) < 0x21 or ord(character) > 0x7E for character in value):
            fail(f"{label} contains a non-canonical field value")
        ordered.append((key, value))
        record[key] = value
    return ordered, record


def require_keys(ordered: list[tuple[str, str]], expected: tuple[str, ...], label: str) -> None:
    if tuple(key for key, _ in ordered) != expected:
        fail(f"{label} has missing, extra, or reordered fields")


def _open_regular(path: Path, label: str) -> tuple[int, os.stat_result]:
    try:
        before = os.lstat(path)
    except OSError:
        fail(f"{label} is missing or unreadable")
    if not stat.S_ISREG(before.st_mode) or stat.S_ISLNK(before.st_mode):
        fail(f"{label} is not a plain regular file")
    if before.st_nlink != 1:
        fail(f"{label} has an unsafe hard-link count")
    flags = os.O_RDONLY
    flags |= getattr(os, "O_CLOEXEC", 0)
    flags |= getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags)
    except OSError:
        fail(f"{label} could not be opened without following links")
    try:
        after = os.fstat(descriptor)
        if not stat.S_ISREG(after.st_mode):
            fail(f"{label} changed type while being opened")
        if (before.st_dev, before.st_ino) != (after.st_dev, after.st_ino):
            fail(f"{label} changed identity while being opened")
        return descriptor, after
    except BaseException:
        os.close(descriptor)
        raise


def read_regular(path: Path, label: str, maximum: int) -> tuple[bytes, tuple[int, int]]:
    descriptor, metadata = _open_regular(path, label)
    try:
        if metadata.st_size > maximum:
            fail(f"{label} exceeds its evidence byte cap")
        chunks: list[bytes] = []
        remaining = maximum + 1
        while remaining:
            chunk = os.read(descriptor, min(64 * 1024, remaining))
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        data = b"".join(chunks)
        if len(data) > maximum:
            fail(f"{label} exceeds its evidence byte cap")
        if len(data) != metadata.st_size:
            fail(f"{label} changed size while being read")
        return data, (metadata.st_dev, metadata.st_ino)
    finally:
        os.close(descriptor)


def decode_text(
    data: bytes,
    label: str,
    *,
    allow_empty: bool,
    require_final_newline: bool,
) -> list[str]:
    if not data:
        if allow_empty:
            return []
        fail(f"{label} is empty")
    if b"\x00" in data or b"\r" in data:
        fail(f"{label} contains a forbidden control encoding")
    if require_final_newline and not data.endswith(b"\n"):
        fail(f"{label} is truncated or lacks a final newline")
    try:
        text = data.decode("utf-8", errors="strict")
    except UnicodeDecodeError:
        fail(f"{label} is not canonical UTF-8")
    lines = text.splitlines()
    if any(len(line.encode("utf-8")) > 16 * 1024 for line in lines):
        fail(f"{label} contains an overlong line")
    return lines


def require_directory(path: Path, label: str) -> os.stat_result:
    try:
        metadata = os.lstat(path)
    except OSError:
        fail(f"{label} is missing or unreadable")
    if not stat.S_ISDIR(metadata.st_mode) or stat.S_ISLNK(metadata.st_mode):
        fail(f"{label} is not a plain directory")
    return metadata


def validate_secret_retention(run_root: Path) -> dict[str, Any]:
    parent = require_directory(run_root.parent, "retained evidence parent")
    getuid = getattr(os, "getuid", None)
    if getuid is None or parent.st_uid != getuid():
        fail("retained evidence parent is not owned by the validating user")
    parent_mode = stat.S_IMODE(parent.st_mode)
    if parent_mode != 0o700:
        fail("retained evidence parent does not have exact mode 0700")

    directory_identities: list[tuple[int, int]] = []
    artifact_identities: list[tuple[int, int]] = []
    aggregate_bytes = 0
    expected_names = {
        "identity.key",
        "mesh.redb",
        "mission.unprotected-reference.bundle",
    }
    for node in range(NODE_COUNT):
        state = run_root / f"node-{node}"
        state_metadata = require_directory(state, f"node-{node} state directory")
        directory_identities.append((state_metadata.st_dev, state_metadata.st_ino))
        try:
            names = {entry.name for entry in os.scandir(state)}
        except OSError:
            fail(f"node-{node} state directory could not be enumerated")
        if names != expected_names:
            fail(
                f"node-{node} state directory does not contain exactly the three "
                "expected secret-bearing artifacts"
            )
        for name in sorted(expected_names):
            try:
                metadata = os.lstat(state / name)
            except OSError:
                fail(f"node-{node} state artifact metadata is unavailable")
            if not stat.S_ISREG(metadata.st_mode) or stat.S_ISLNK(metadata.st_mode):
                fail(f"node-{node} state artifact is not a plain regular file")
            if metadata.st_nlink != 1:
                fail(f"node-{node} state artifact has an unsafe hard-link count")
            if stat.S_IMODE(metadata.st_mode) & ~0o600:
                fail(f"node-{node} state artifact mode is broader than 0600")
            if metadata.st_size <= 0:
                fail(f"node-{node} state artifact is empty")
            if name == "identity.key" and metadata.st_size != IDENTITY_BYTES:
                fail(f"node-{node} identity artifact does not have the exact byte count")
            if (
                name == "mission.unprotected-reference.bundle"
                and metadata.st_size > MISSION_BUNDLE_MAX_BYTES
            ):
                fail(f"node-{node} mission artifact exceeds its metadata-only bound")
            if name == "mesh.redb" and metadata.st_size > STORE_MAX_BYTES:
                fail(f"node-{node} store artifact exceeds its metadata-only bound")
            aggregate_bytes += metadata.st_size
            artifact_identities.append((metadata.st_dev, metadata.st_ino))

    if len(set(directory_identities)) != NODE_COUNT:
        fail("state directories do not have 32 distinct inode identities")
    if len(set(artifact_identities)) != NODE_COUNT * 3:
        fail("state artifacts do not have 96 distinct inode identities")
    return {
        "retained_parent_mode": "0700",
        "retained_parent_owner": "current-validator-uid",
        "state_directories": NODE_COUNT,
        "state_directory_inodes": NODE_COUNT,
        "state_artifacts": NODE_COUNT * 3,
        "state_artifact_inodes": NODE_COUNT * 3,
        "identity_artifacts": NODE_COUNT,
        "store_artifacts": NODE_COUNT,
        "mission_artifacts": NODE_COUNT,
        "aggregate_state_artifact_bytes": aggregate_bytes,
        "artifact_modes": "0600-or-narrower",
        "contents": "excluded-not-read-or-hashed",
    }


def run_git(source: Path, arguments: list[str], label: str) -> bytes:
    try:
        completed = subprocess.run(
            ["git", "-C", str(source), *arguments],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
            timeout=30,
        )
    except (OSError, subprocess.TimeoutExpired):
        fail(f"source {label} could not be completed")
    if len(completed.stdout) > GIT_OUTPUT_MAX_BYTES or len(completed.stderr) > GIT_OUTPUT_MAX_BYTES:
        fail(f"source {label} exceeded its evidence byte cap")
    if completed.returncode != 0:
        fail(f"source {label} failed")
    return completed.stdout


def validate_source(source: Path, expected_commit: str) -> dict[str, Any]:
    if GIT_OBJECT.fullmatch(expected_commit) is None:
        fail("expected source commit is not one canonical Git object identifier")
    require_directory(source, "source root")
    top = run_git(source, ["rev-parse", "--show-toplevel"], "root discovery")
    try:
        top_path = Path(os.fsdecode(top.rstrip(b"\n")))
        if not os.path.samefile(source, top_path):
            fail("source root is not the repository top level")
    except (OSError, UnicodeDecodeError):
        fail("source root identity could not be validated")
    head = run_git(source, ["rev-parse", "--verify", "HEAD"], "HEAD validation")
    if head.decode("ascii", errors="strict").strip() != expected_commit:
        fail("source HEAD differs from the expected signed commit")
    run_git(source, ["verify-commit", expected_commit], "commit signature validation")
    tree = run_git(
        source,
        ["show", "-s", "--format=%T", expected_commit],
        "tree validation",
    ).decode("ascii", errors="strict").strip()
    if GIT_OBJECT.fullmatch(tree) is None:
        fail("source commit returned a malformed tree identifier")

    public_hashes: dict[str, str] = {}
    for field, relative in (
        ("cargo_lock_sha256", "Cargo.lock"),
        ("requirements_sha256", "data-mesh-requirements.md"),
    ):
        content = run_git(
            source,
            ["show", f"{expected_commit}:{relative}"],
            f"{relative} validation",
        )
        public_hashes[field] = sha256_bytes(content)
    return {
        "commit": expected_commit,
        "tree": tree,
        "commit_signature": "verified",
        "checkout_head": "exact",
        "worktree": "not-validator-derived",
        **public_hashes,
    }


def validate_binary(path: Path, expected_sha256: str, expected_size: int) -> dict[str, Any]:
    if HEX_32.fullmatch(expected_sha256) is None:
        fail("expected binary SHA-256 is not canonical")
    if expected_size <= 0 or expected_size > BINARY_MAX_BYTES:
        fail("expected binary size is outside the evidence bound")
    descriptor, metadata = _open_regular(path, "release binary")
    try:
        if metadata.st_size != expected_size:
            fail("release binary size differs from the expected size")
        if metadata.st_mode & 0o111 == 0:
            fail("release binary is not executable")
        digest = hashlib.sha256()
        total = 0
        while True:
            chunk = os.read(descriptor, 1024 * 1024)
            if not chunk:
                break
            total += len(chunk)
            if total > BINARY_MAX_BYTES:
                fail("release binary exceeds the evidence byte cap")
            digest.update(chunk)
        if total != expected_size:
            fail("release binary changed size while being hashed")
        if digest.hexdigest() != expected_sha256:
            fail("release binary SHA-256 differs from the expected digest")
    finally:
        os.close(descriptor)
    return {
        "profile": "release",
        "bytes": expected_size,
        "sha256": expected_sha256,
    }


def expected_phases() -> list[dict[str, Any]]:
    phases: list[dict[str, Any]] = [
        {
            "name": "ping-publish",
            "nodes": (0,),
            "kind": "publish",
            "source": None,
            "destination": None,
        }
    ]
    for left in range(NODE_COUNT - 1):
        phases.append(
            {
                "name": f"ping-forward-{left}-to-{left + 1}",
                "nodes": (left, left + 1),
                "kind": "transfer",
                "source": left,
                "destination": left + 1,
            }
        )
    phases.append(
        {
            "name": "pong-publish",
            "nodes": (NODE_COUNT - 1,),
            "kind": "publish",
            "source": None,
            "destination": None,
        }
    )
    for right in range(NODE_COUNT - 1, 0, -1):
        phases.append(
            {
                "name": f"pong-return-{right}-to-{right - 1}",
                "nodes": (right - 1, right),
                "kind": "transfer",
                "source": right,
                "destination": right - 1,
            }
        )
    phases.append(
        {
            "name": "noop",
            "nodes": tuple(range(NODE_COUNT)),
            "kind": "noop",
            "source": None,
            "destination": None,
        }
    )
    if len(phases) != PHASE_COUNT:
        raise AssertionError("internal phase manifest is inconsistent")
    return phases


def expected_log_specs() -> dict[str, dict[str, Any]]:
    output: dict[str, dict[str, Any]] = {}
    for phase in expected_phases():
        for node in phase["nodes"]:
            name = f"{phase['name']}-node-{node}.log"
            if name in output:
                raise AssertionError("internal log manifest contains a duplicate")
            output[name] = {**phase, "node": node}
    if len(output) != LOG_COUNT:
        raise AssertionError("internal log manifest is inconsistent")
    return output


def normalized_record(prefix: str, ordered: list[tuple[str, str]]) -> str:
    fields: list[str] = []
    for key, value in ordered:
        if key in SENSITIVE_FIELDS:
            value = "<redacted-id>"
        elif key in PATH_FIELDS:
            value = "<redacted-path>"
        elif key == "sockets":
            value = "<redacted-loopback-socket>"
        fields.append(f"{key}={value}")
    return f"{prefix} {' '.join(fields)}"


def sanitized_records_sha256(records: Iterable[tuple[str, str, list[tuple[str, str]]]]) -> str:
    digest = hashlib.sha256()
    for scope, prefix, ordered in records:
        digest.update(scope.encode("ascii", errors="strict"))
        digest.update(b"\x00")
        digest.update(normalized_record(prefix, ordered).encode("ascii", errors="strict"))
        digest.update(b"\n")
    return digest.hexdigest()


def validate_outer_stdout(
    data: bytes, run_root: Path
) -> tuple[
    dict[str, Any],
    dict[str, str],
    list[tuple[str, str, list[tuple[str, str]]]],
]:
    lines = decode_text(
        data,
        "outer stdout",
        allow_empty=False,
        require_final_newline=True,
    )
    if len(lines) != 70:
        fail("outer stdout has a truncated, duplicated, or unexpected record count")
    normalized: list[tuple[str, str, list[tuple[str, str]]]] = []
    cursor = 0

    def take(prefix: str, keys: tuple[str, ...], label: str) -> dict[str, str]:
        nonlocal cursor
        if cursor >= len(lines):
            fail(f"outer stdout omitted {label}")
        ordered, record = parse_record(lines[cursor], prefix, label)
        require_keys(ordered, keys, label)
        normalized.append((f"stdout:{cursor:02d}", prefix, ordered))
        cursor += 1
        return record

    subscriptions = take("SUBSCRIPTIONS", SUBSCRIPTION_KEYS, "subscription receipt")
    require_fixed(
        subscriptions,
        {
            "status": "seeded",
            "consume": "2",
            "carry": "30",
            "selectors": "32",
            "interest_exchange": "mission-protected",
            "lanes": "receiver-directed",
        },
        "subscription receipt",
    )

    for phase in expected_phases()[:33]:
        record = take("PHASE", PHASE_KEYS, f"phase {phase['name']}")
        edges = "not-applicable" if phase["kind"] == "publish" else "verified"
        require_fixed(
            record,
            {
                "status": "pass",
                "name": phase["name"],
                "processes": str(len(phase["nodes"])),
                "carrier_authenticated_edges": edges,
                "mission_authenticated_edges": edges,
                "provisioning": "unprotected-reference",
            },
            f"phase {phase['name']}",
        )

    ping = take("PING", PING_KEYS, "Ping receipt")
    require_fixed(
        ping,
        {
            "status": "received",
            "emitted_by": "origin-process",
            "producer_state": "node-0",
            "destination_state": "node-31",
            "producer_process_absent": "true",
            "source_authenticated": "true",
            "ttl": "none",
        },
        "Ping receipt",
    )
    require_hex_32(ping["transfer_id"], "Ping transfer identifier")
    require_hex_32(ping["semantic_id"], "Ping semantic identifier")

    for phase in expected_phases()[33:64]:
        record = take("PHASE", PHASE_KEYS, f"phase {phase['name']}")
        require_fixed(
            record,
            {
                "status": "pass",
                "name": phase["name"],
                "processes": "2",
                "carrier_authenticated_edges": "verified",
                "mission_authenticated_edges": "verified",
                "provisioning": "unprotected-reference",
            },
            f"phase {phase['name']}",
        )

    relay = take("RELAY", RELAY_KEYS, "relay receipt")
    require_fixed(
        relay,
        {
            "status": "pass",
            "intermediates": "30",
            "exact_forward": "true",
            "content_access": "denied",
            "semantic_acceptance": "none",
        },
        "relay receipt",
    )
    pong = take("PONG", PONG_KEYS, "Pong receipt")
    require_fixed(
        pong,
        {
            "status": "received",
            "emitted_by": "destination-process",
            "producer_state": "node-31",
            "destination_state": "node-0",
            "source_authenticated": "true",
            "causal_observation": "verified",
            "ttl": "none",
        },
        "Pong receipt",
    )
    for key in ("correlation_semantic_id", "transfer_id", "semantic_id"):
        require_hex_32(pong[key], f"Pong {key}")
    if pong["correlation_semantic_id"] != ping["semantic_id"]:
        fail("Pong does not correlate the exact Ping semantic identifier")
    if pong["transfer_id"] == ping["transfer_id"] or pong["semantic_id"] == ping["semantic_id"]:
        fail("Ping and Pong identifiers are not distinct")

    noop = take("PHASE", PHASE_KEYS, "phase noop")
    require_fixed(
        noop,
        {
            "status": "pass",
            "name": "noop",
            "processes": "32",
            "carrier_authenticated_edges": "verified",
            "mission_authenticated_edges": "verified",
            "provisioning": "unprotected-reference",
        },
        "phase noop",
    )
    result = take("DEMO_RESULT", RESULT_KEYS, "final demo result")
    require_fixed(
        result,
        {
            "status": "pass",
            "scenario": "ping-pong",
            "nodes": "32",
            "processes": "158",
            "contacts": "real-iroh",
            "mission_auth": "hybrid-pq",
            "provisioning": "unprotected-reference",
            "stores": "independent-redb",
            "reconciliation": "negentropy",
            "producer_process_absent": "true",
            "restarts": "pass",
            "atomic_reaction": "pass",
            "equal_inventory_noop": "pass",
            "transfers_each": "2",
            "semantics": "source-authenticated-event",
            "emitted_by": "running-node-processes",
            "payload_blind_relays": "pass",
            "ttl": "durable-none",
            "root": receipt_path(run_root),
        },
        "final demo result",
    )
    if cursor != len(lines):
        fail("outer stdout contains trailing records")
    ids = {
        "ping_transfer": ping["transfer_id"],
        "ping_semantic": ping["semantic_id"],
        "pong_transfer": pong["transfer_id"],
        "pong_semantic": pong["semantic_id"],
    }
    facts = {
        "bytes": len(data),
        "lines": len(lines),
        "classification": "selected-n32-demo-v1",
        "sanitized_sha256": sanitized_records_sha256(normalized),
    }
    return facts, ids, normalized


def validate_contact(record: dict[str, str], label: str) -> None:
    require_fixed(
        record,
        {
            "rounds": "18",
            "duplicates": "0",
            "remaining": "0",
            "deferred_event_lanes": "0",
            "carrier_path": "direct",
            "carrier_path_transitions": "0",
            "carrier_path_transitions_saturated": "false",
            "path_observation": "not-authorization",
            "mission_auth": "hybrid-pq",
            "semantics": "source-authenticated-event",
            "reconciliation_classes": "event,state,record,blob",
            "controls": "source-authenticated-flash",
            "content_admission": "capability-gated",
            "status": "pass",
        },
        label,
    )
    if record["direction"] not in {"in", "out"}:
        fail(f"{label} has an unexpected direction")
    require_hex_32(record["carrier_peer"], f"{label} carrier peer")
    require_hex_32(record["mission_peer"], f"{label} mission peer")
    for field in ZERO_CONTACT_FIELDS:
        if strict_uint(record[field], f"{label} {field}") != 0:
            fail(f"{label} has a nonzero control, mutable, Blob, or completion counter")
    for field in ("offered", "fetched", "inserted"):
        strict_uint(record[field], f"{label} {field}", 2)
    if strict_uint(record["handshake_frames"], f"{label} handshake_frames", 4096) != 4:
        fail(f"{label} has an unexpected handshake frame count")
    for field in ("handshake_bytes", "protected_frames", "protected_bytes"):
        if strict_uint(record[field], f"{label} {field}", 128 * 1024 * 1024) == 0:
            fail(f"{label} has an empty authenticated exchange")


def validate_ready(
    record: dict[str, str], spec: dict[str, Any], run_root: Path, label: str
) -> None:
    expected_peers = 0
    if spec["kind"] == "transfer":
        expected_peers = 1
    elif spec["kind"] == "noop":
        expected_peers = 1 if spec["node"] in {0, NODE_COUNT - 1} else 2
    application = "relay"
    if spec["name"] == "ping-publish" or (spec["name"] == "noop" and spec["node"] == 0):
        application = "ping-emitter"
    elif spec["name"] == "pong-publish" or (
        spec["name"] == "noop" and spec["node"] == NODE_COUNT - 1
    ):
        application = "pong-responder"
    require_fixed(
        record,
        {
            "selected": "true",
            "state": receipt_path(run_root / f"node-{spec['node']}"),
            "peers": str(expected_peers),
            "application": application,
            "carrier_route": "direct",
            "controlled_relay_url": "none",
            "controlled_relay_trust": "none",
            "controlled_relay_readiness": "not-applicable",
            "public_relay_fallback": "false",
            "hosted_discovery": "false",
            "nat_traversal": "not-claimed",
            "path_observation": "not-authorization",
            "mission_auth": "hybrid-pq",
            "provisioning": "unprotected-reference",
            "semantics": "source-authenticated-event",
            "reconciliation_classes": "event,state,record,blob-v5-opt-in",
            "controls": "source-authenticated-flash",
            "commit_before_activate": "true",
            "content_admission": "capability-gated",
        },
        label,
    )
    if strict_uint(record["pid"], f"{label} pid", (1 << 31) - 1) == 0:
        fail(f"{label} pid is not a positive process identifier")
    require_hex_32(record["carrier_id"], f"{label} carrier identity")
    require_hex_32(record["mission_id"], f"{label} mission identity")
    require_hex_32(record["mission_authority"], f"{label} mission authority")
    match = LOOPBACK_SOCKET.fullmatch(record["sockets"])
    if match is None or int(match.group(1)) > 65535:
        fail(f"{label} does not contain one bounded loopback socket")


def validate_stop(record: dict[str, str], contacts: int, ready: dict[str, str], label: str) -> None:
    require_fixed(
        record,
        {
            "lifecycle": "complete",
            "carrier_id": ready["carrier_id"],
            "mission_id": ready["mission_id"],
            "contacts": str(contacts),
            "direct_contacts": str(contacts),
            "path_observation": "not-authorization",
            "mission_auth": "hybrid-pq",
            "provisioning": "unprotected-reference",
            "semantics": "source-authenticated-event",
            "reconciliation_classes": "event,state,record,blob-v5",
            "controls_semantics": "source-authenticated-flash",
        },
        label,
    )
    for field in ZERO_STOP_FIELDS:
        if strict_uint(record[field], f"{label} {field}") != 0:
            fail(f"{label} has a nonzero error, alternate-path, control, or Blob counter")
    for field in ("events", "event_acceptance_markers", "route_cached_events"):
        strict_uint(record[field], f"{label} {field}", 2)
    expected_sync = "contacts_observed" if contacts else "no_successful_contact"
    if record["sync_status"] != expected_sync:
        fail(f"{label} has a sync status inconsistent with authenticated contacts")


def validate_application(
    record: dict[str, str],
    spec: dict[str, Any],
    ids: dict[str, str],
    node_missions: dict[int, str] | None,
    label: str,
) -> None:
    if record["kind"] == "ping":
        require_fixed(
            record,
            {
                "transfer_id": ids["ping_transfer"],
                "semantic_id": ids["ping_semantic"],
                "source_authenticated": "true",
                "ttl": "none",
            },
            label,
        )
    elif record["kind"] == "pong":
        require_fixed(
            record,
            {
                "transfer_id": ids["pong_transfer"],
                "semantic_id": ids["pong_semantic"],
                "correlation_semantic_id": ids["ping_semantic"],
                "source_authenticated": "true",
                "causal_observation": "verified",
                "ttl": "none",
            },
            label,
        )
    else:
        fail(f"{label} has an unexpected application kind")
    require_hex_32(record["publisher"], f"{label} publisher")
    if "ping_publisher" in record:
        require_hex_32(record["ping_publisher"], f"{label} Ping publisher")
    if node_missions is not None:
        expected_publisher = node_missions[0 if record["kind"] == "ping" else NODE_COUNT - 1]
        if record["publisher"] != expected_publisher:
            fail(f"{label} publisher differs from the selected application node")
        if record.get("ping_publisher", node_missions[0]) != node_missions[0]:
            fail(f"{label} Ping publisher differs from the origin mission identity")


def validate_child_log(
    name: str,
    data: bytes,
    spec: dict[str, Any],
    run_root: Path,
    ids: dict[str, str],
) -> dict[str, Any]:
    lines = decode_text(
        data,
        f"child log {name}",
        allow_empty=False,
        require_final_newline=True,
    )
    if len(lines) > CHILD_LOG_MAX_LINES:
        fail(f"child log {name} exceeds its line cap")
    records: list[tuple[str, list[tuple[str, str]], dict[str, str]]] = []
    for index, line in enumerate(lines):
        prefix = line.partition(" ")[0]
        if prefix not in {"READY", "CONTACT", "APPLICATION", "STOP"}:
            fail(f"child log {name} contains an unclassified record")
        ordered, record = parse_record(line, prefix, f"child log {name} line {index + 1}")
        expected_keys = {
            "READY": READY_KEYS,
            "CONTACT": CONTACT_KEYS,
            "STOP": STOP_KEYS,
            "APPLICATION": (
                PONG_APPLICATION_KEYS
                if record.get("kind") == "pong"
                else PING_APPLICATION_KEYS
            ),
        }[prefix]
        require_keys(ordered, expected_keys, f"child log {name} line {index + 1}")
        records.append((prefix, ordered, record))
    if records[0][0] != "READY" or records[-1][0] != "STOP":
        fail(f"child log {name} is truncated or lacks its READY/STOP envelope")
    if sum(prefix == "READY" for prefix, _, _ in records) != 1:
        fail(f"child log {name} contains a duplicate READY record")
    if sum(prefix == "STOP" for prefix, _, _ in records) != 1:
        fail(f"child log {name} contains a duplicate STOP record")

    ready = records[0][2]
    validate_ready(ready, spec, run_root, f"child log {name} READY")
    contacts = [record for prefix, _, record in records if prefix == "CONTACT"]
    applications = [record for prefix, _, record in records if prefix == "APPLICATION"]
    for index, contact in enumerate(contacts):
        validate_contact(contact, f"child log {name} CONTACT {index + 1}")
    validate_stop(records[-1][2], len(contacts), ready, f"child log {name} STOP")

    expected_application: tuple[str, str] | None = None
    if spec["name"] == "ping-publish":
        expected_application = ("emitted", "ping")
    elif spec["name"] == "pong-publish":
        expected_application = ("emitted", "pong")
    elif spec["name"] == "noop" and spec["node"] == 0:
        expected_application = ("existing", "ping")
    elif spec["name"] == "noop" and spec["node"] == NODE_COUNT - 1:
        expected_application = ("existing", "pong")
    if expected_application is None and applications:
        fail(f"child log {name} contains an unexpected application receipt")
    if expected_application is not None:
        if len(applications) != 1:
            fail(f"child log {name} omitted or duplicated its application receipt")
        require_fixed(
            applications[0],
            {"status": expected_application[0], "kind": expected_application[1]},
            f"child log {name} application receipt",
        )
        validate_application(
            applications[0], spec, ids, None, f"child log {name} application receipt"
        )

    if spec["kind"] == "publish" and contacts:
        fail(f"child log {name} unexpectedly contacted a peer during isolated publication")
    if spec["kind"] in {"transfer", "noop"} and not contacts:
        fail(f"child log {name} contains no successful authenticated contact")
    expected_peers = strict_uint(ready["peers"], f"child log {name} peers", 2)
    if len(contacts) < expected_peers:
        fail(f"child log {name} has fewer contact receipts than configured peers")
    if spec["kind"] == "noop":
        for contact in contacts:
            for field in ("offered", "fetched", "inserted", "duplicates"):
                if strict_uint(contact[field], f"child log {name} noop {field}", 2) != 0:
                    fail(f"child log {name} has a nonzero equal-inventory no-op counter")

    normalized = [(name, prefix, ordered) for prefix, ordered, _ in records]
    return {
        "name": name,
        "node": spec["node"],
        "phase": spec["name"],
        "kind": spec["kind"],
        "source": spec["source"],
        "destination": spec["destination"],
        "bytes": len(data),
        "lines": len(lines),
        "ready": ready,
        "contacts": contacts,
        "applications": applications,
        "stop": records[-1][2],
        "normalized": normalized,
    }


def validate_child_cross_links(logs: list[dict[str, Any]], ids: dict[str, str]) -> dict[str, Any]:
    process_ids = [log["ready"]["pid"] for log in logs]
    noop_process_ids = [
        log["ready"]["pid"] for log in logs if log["kind"] == "noop"
    ]
    if len(noop_process_ids) != NODE_COUNT or len(set(noop_process_ids)) != NODE_COUNT:
        fail("noop logs do not contain 32 distinct process identifiers")
    if len(process_ids) != PROCESS_COUNT or len(set(process_ids)) != PROCESS_COUNT:
        fail("child logs do not contain 158 distinct process identifiers")

    node_facts: dict[int, dict[str, str]] = {}
    for log in logs:
        ready = log["ready"]
        node = log["node"]
        facts = {
            key: ready[key]
            for key in ("carrier_id", "mission_id", "mission_authority", "sockets", "state")
        }
        if node in node_facts and node_facts[node] != facts:
            fail(f"node-{node} changed identity, authority, socket, or state across phases")
        node_facts[node] = facts
    if set(node_facts) != set(range(NODE_COUNT)):
        fail("child logs do not cover exactly 32 node identities")
    if len({facts["carrier_id"] for facts in node_facts.values()}) != NODE_COUNT:
        fail("child logs do not contain 32 unique carrier identities")
    if len({facts["mission_id"] for facts in node_facts.values()}) != NODE_COUNT:
        fail("child logs do not contain 32 unique mission identities")
    if len({facts["sockets"] for facts in node_facts.values()}) != NODE_COUNT:
        fail("child logs do not contain 32 unique loopback sockets")
    if len({facts["mission_authority"] for facts in node_facts.values()}) != 1:
        fail("child logs do not share one selected mission authority")

    phases: dict[str, list[dict[str, Any]]] = {}
    noop_out_edges: set[tuple[int, int]] = set()
    noop_edge_receipts: dict[tuple[int, int], dict[int, dict[str, int]]] = {}
    noop_receipts = 0
    contact_receipts = 0
    for log in logs:
        phases.setdefault(log["phase"], []).append(log)
        node = log["node"]
        allowed_neighbors = {
            candidate
            for candidate in (node - 1, node + 1)
            if 0 <= candidate < NODE_COUNT
        }
        for contact in log["contacts"]:
            contact_receipts += 1
            matches = [
                neighbor
                for neighbor in allowed_neighbors
                if contact["carrier_peer"] == node_facts[neighbor]["carrier_id"]
                and contact["mission_peer"] == node_facts[neighbor]["mission_id"]
            ]
            if len(matches) != 1:
                fail(f"child log {log['name']} authenticated an unexpected peer")
            neighbor = matches[0]
            if log["kind"] == "transfer" and neighbor not in {
                log["source"],
                log["destination"],
            }:
                fail(f"child log {log['name']} contacted a node outside its phase edge")
            if log["kind"] == "noop":
                noop_receipts += 1
                edge = tuple(sorted((node, neighbor)))
                endpoint = noop_edge_receipts.setdefault(edge, {}).setdefault(
                    node, {"in": 0, "out": 0}
                )
                endpoint[contact["direction"]] += 1
                if contact["direction"] == "out":
                    noop_out_edges.add(edge)

    for phase in expected_phases():
        phase_logs = phases.get(phase["name"], [])
        if len(phase_logs) != len(phase["nodes"]):
            fail(f"phase {phase['name']} has an unexpected child-log count")
        if phase["kind"] != "transfer":
            continue
        source_log = next(log for log in phase_logs if log["node"] == phase["source"])
        destination_log = next(log for log in phase_logs if log["node"] == phase["destination"])
        source_totals = {
            field: sum(
                strict_uint(contact[field], f"phase {phase['name']} {field}", 2)
                for contact in source_log["contacts"]
            )
            for field in ("offered", "fetched", "inserted")
        }
        destination_totals = {
            field: sum(
                strict_uint(contact[field], f"phase {phase['name']} {field}", 2)
                for contact in destination_log["contacts"]
            )
            for field in ("offered", "fetched", "inserted")
        }
        if source_totals != {"offered": 1, "fetched": 0, "inserted": 0}:
            fail(f"phase {phase['name']} lacks exactly one source offer")
        if destination_totals != {"offered": 0, "fetched": 1, "inserted": 1}:
            fail(f"phase {phase['name']} lacks exactly one destination fetch and insert")

    expected_edges = {(left, left + 1) for left in range(NODE_COUNT - 1)}
    if noop_out_edges != expected_edges:
        fail("noop logs do not prove every adjacent authenticated edge")
    if set(noop_edge_receipts) != expected_edges:
        fail("noop logs do not cover exactly the 31 adjacent edges")
    noop_cycles = 0
    for left, right in sorted(expected_edges):
        endpoints = noop_edge_receipts[(left, right)]
        if set(endpoints) != {left, right}:
            fail("noop edge is missing one mirrored endpoint receipt")
        left_counts = endpoints[left]
        right_counts = endpoints[right]
        if left_counts["out"] and right_counts["out"]:
            fail("noop edge has competing outbound initiators")
        if left_counts["in"] and right_counts["in"]:
            fail("noop edge has no unique outbound initiator")
        if (
            left_counts["out"] != right_counts["in"]
            or right_counts["out"] != left_counts["in"]
        ):
            fail("noop edge endpoint receipt counts are not mirrored")
        cycles = left_counts["out"] + left_counts["in"]
        if cycles == 0:
            fail("noop edge has no authenticated reconciliation cycle")
        noop_cycles += cycles
    if noop_receipts != noop_cycles * 2:
        fail("noop aggregate endpoint receipts are not exactly mirrored")

    for log in phases["noop"]:
        expected_inventory = (
            {
                "events": "2",
                "event_acceptance_markers": "2",
                "route_cached_events": "0",
            }
            if log["node"] in {0, NODE_COUNT - 1}
            else {
                "events": "0",
                "event_acceptance_markers": "0",
                "route_cached_events": "2",
            }
        )
        require_fixed(
            log["stop"],
            expected_inventory,
            f"child log {log['name']} noop inventory",
        )

    node_missions = {node: facts["mission_id"] for node, facts in node_facts.items()}
    for log in logs:
        for application in log["applications"]:
            validate_application(
                application,
                {"node": log["node"]},
                ids,
                node_missions,
                f"child log {log['name']} application receipt",
            )
    return {
        "distinct_process_ids": PROCESS_COUNT,
        "noop_distinct_process_ids": NODE_COUNT,
        "distinct_carrier_identities": NODE_COUNT,
        "distinct_mission_identities": NODE_COUNT,
        "distinct_loopback_sockets": NODE_COUNT,
        "contact_receipts": contact_receipts,
        "noop_authenticated_edge_receipts": noop_receipts,
        "noop_authenticated_cycles": noop_cycles,
        "noop_authenticated_edges": len(noop_out_edges),
    }


def validate_outer_stderr(data: bytes) -> dict[str, Any]:
    lines = decode_text(
        data,
        "outer stderr",
        allow_empty=True,
        require_final_newline=bool(data),
    )
    if not lines:
        normalized = b"outer-stderr classification=empty\n"
        return {
            "bytes": 0,
            "lines": 0,
            "classification": "empty",
            "sanitized_sha256": sha256_bytes(normalized),
            "resource_metrics": {},
        }
    if len(lines) != 18:
        fail("outer stderr is nonempty but does not match a bounded classification")
    summary = TIME_SUMMARY.fullmatch(lines[0])
    if summary is None:
        fail("outer stderr is nonempty but does not match Darwin time -l output")
    elapsed, user, system = summary.groups()
    for label, value in (("elapsed", elapsed), ("user", user), ("system", system)):
        if float(value) < 0 or float(value) > 86_400:
            fail(f"outer stderr {label} time exceeds its evidence bound")
    metrics: dict[str, int | str] = {
        "elapsed_seconds": elapsed,
        "user_seconds": user,
        "system_seconds": system,
    }
    canonical = [f"time elapsed={elapsed} user={user} system={system}"]
    for index, expected_field in enumerate(DARWIN_TIME_FIELDS, start=1):
        match = re.fullmatch(r"\s*([0-9]+)\s{2}(.+?)\s*", lines[index])
        if match is None or match.group(2) != expected_field:
            fail("outer stderr has an unclassified Darwin time -l metric")
        value = strict_uint(match.group(1), f"outer stderr {expected_field}")
        key = expected_field.replace(" ", "_")
        metrics[key] = value
        canonical.append(f"{key}={value}")
    return {
        "bytes": len(data),
        "lines": len(lines),
        "classification": "darwin-time-l-v1",
        "sanitized_sha256": sha256_bytes(("\n".join(canonical) + "\n").encode("ascii")),
        "resource_metrics": metrics,
    }


def validate_run_root(
    run_root: Path,
    stdout_path: Path,
    stderr_path: Path,
    expected_manifest_sha256: str | None = None,
) -> tuple[dict[str, Any], list[tuple[int, int]]]:
    run_metadata = require_directory(run_root, "run root")
    expected_parent = os.path.abspath(os.fspath(run_root.parent))
    if (
        os.path.abspath(os.fspath(stdout_path))
        != os.path.join(expected_parent, "demo.stdout")
        or os.path.abspath(os.fspath(stderr_path))
        != os.path.join(expected_parent, "demo.stderr")
    ):
        fail("outer stdout and stderr are not the canonical siblings of the run root")
    logs_root = run_root / "logs"
    logs_metadata = require_directory(logs_root, "child log directory")
    try:
        root_names = {entry.name for entry in os.scandir(run_root)}
    except OSError:
        fail("run root could not be enumerated")
    expected_root_names = {"logs", *(f"node-{index}" for index in range(NODE_COUNT))}
    if root_names != expected_root_names:
        fail("run root does not contain exactly 32 state directories and logs")
    directory_identities = [
        (run_metadata.st_dev, run_metadata.st_ino),
        (logs_metadata.st_dev, logs_metadata.st_ino),
    ]
    for index in range(NODE_COUNT):
        metadata = require_directory(
            run_root / f"node-{index}", f"node-{index} state directory"
        )
        directory_identities.append((metadata.st_dev, metadata.st_ino))
    if len(set(directory_identities)) != NODE_COUNT + 2:
        fail("run, log, and state directories do not have distinct inode identities")
    secret_retention = validate_secret_retention(run_root)

    specs = expected_log_specs()
    expected_names = set(specs) | {name.removesuffix(".log") + ".err" for name in specs}
    try:
        log_names = {entry.name for entry in os.scandir(logs_root)}
    except OSError:
        fail("child log directory could not be enumerated")
    if log_names != expected_names:
        fail("child log directory has a missing, duplicate-equivalent, or unexpected artifact")

    stdout_data, stdout_identity = read_regular(stdout_path, "outer stdout", STDOUT_MAX_BYTES)
    stderr_data, stderr_identity = read_regular(stderr_path, "outer stderr", STDERR_MAX_BYTES)
    if stdout_identity == stderr_identity:
        fail("outer stdout and stderr alias the same file")
    stdout_facts, ids, _ = validate_outer_stdout(stdout_data, run_root)
    stderr_facts = validate_outer_stderr(stderr_data)
    transcript_entries: list[tuple[str, bytes]] = [
        ("demo.stdout", stdout_data),
        ("demo.stderr", stderr_data),
    ]

    children: list[dict[str, Any]] = []
    identities = [stdout_identity, stderr_identity]
    total_bytes = 0
    total_lines = 0
    normalized: list[tuple[str, str, list[tuple[str, str]]]] = []
    error_normalized = hashlib.sha256()
    for name in sorted(specs):
        data, identity = read_regular(logs_root / name, f"child log {name}", CHILD_LOG_MAX_BYTES)
        identities.append(identity)
        total_bytes += len(data)
        if total_bytes > CHILD_TOTAL_MAX_BYTES:
            fail("child evidence exceeds its aggregate byte cap")
        child = validate_child_log(name, data, specs[name], run_root, ids)
        transcript_entries.append((f"run/logs/{name}", data))
        children.append(child)
        total_lines += child["lines"]
        normalized.extend(child["normalized"])

        error_name = name.removesuffix(".log") + ".err"
        error_data, error_identity = read_regular(
            logs_root / error_name,
            f"child stderr {error_name}",
            CHILD_ERR_MAX_BYTES,
        )
        identities.append(error_identity)
        total_bytes += len(error_data)
        if total_bytes > CHILD_TOTAL_MAX_BYTES:
            fail("child evidence exceeds its aggregate byte cap")
        if error_data:
            fail(f"child stderr {error_name} is nonempty and unclassified")
        transcript_entries.append((f"run/logs/{error_name}", error_data))
        error_normalized.update(error_name.encode("ascii"))
        error_normalized.update(b"\x00empty\n")
    if len(set(identities)) != len(identities):
        fail("evidence inputs alias one another")

    cross = validate_child_cross_links(children, ids)
    manifest = b"".join(
        f"{sha256_bytes(data)}  {relative}\n".encode("ascii")
        for relative, data in sorted(transcript_entries)
    )
    if len(transcript_entries) != TRANSCRIPT_MANIFEST_RECORDS:
        raise AssertionError("internal transcript manifest record count is inconsistent")
    if len(manifest) != TRANSCRIPT_MANIFEST_BYTES:
        raise AssertionError("internal transcript manifest byte count is inconsistent")
    manifest_sha256 = sha256_bytes(manifest)
    if expected_manifest_sha256 is not None:
        if HEX_32.fullmatch(expected_manifest_sha256) is None:
            fail("expected transcript-manifest SHA-256 is not canonical")
        if manifest_sha256 != expected_manifest_sha256:
            fail("safe transcript manifest differs from the expected aggregate digest")
    child_facts = {
        "stdout_files": LOG_COUNT,
        "stderr_files": LOG_COUNT,
        "stdout_lines": total_lines,
        "stdout_bytes": sum(child["bytes"] for child in children),
        "stderr_bytes": 0,
        "stderr_classifications": {"empty": LOG_COUNT},
        "sanitized_stdout_aggregate_sha256": sanitized_records_sha256(normalized),
        "sanitized_stderr_aggregate_sha256": error_normalized.hexdigest(),
        **cross,
    }
    return {
        "stdout": stdout_facts,
        "stderr": stderr_facts,
        "children": child_facts,
        "transcript_manifest": {
            "scope": "demo.stdout,demo.stderr,run/logs-only",
            "records": TRANSCRIPT_MANIFEST_RECORDS,
            "bytes": TRANSCRIPT_MANIFEST_BYTES,
            "sha256": manifest_sha256,
            "node_state_artifacts": "excluded",
        },
        "secret_retention": secret_retention,
    }, identities


def validate_operator_attestation(
    build_command: str,
    run_argv: str,
    wrapper_exit_code: int,
    host_os: str,
    host_arch: str,
    rustc_version: str,
    rustc_commit: str,
    build_target: str,
    worktree_clean_at_build_and_run: bool,
    run_root: Path,
) -> dict[str, Any]:
    if build_command != EXPECTED_BUILD_COMMAND:
        fail("operator-attested release build command is not the canonical invocation")
    expected_run_argv = (
        "/usr/bin/time -l target/release/aster demo --nodes 32 --root "
        f"{receipt_path(run_root)}"
    )
    if run_argv != expected_run_argv:
        fail("operator-attested run argv does not bind the exact retained run root")
    if wrapper_exit_code != 0:
        fail("operator-attested wrapper exit code is nonzero")
    if host_os != EXPECTED_HOST_OS or host_arch != EXPECTED_HOST_ARCH:
        fail("operator-attested host is not Darwin arm64")
    if platform.system() != host_os or platform.machine() != host_arch:
        fail("validation host does not match the operator-attested run host")
    if (
        rustc_version != EXPECTED_RUSTC_VERSION
        or rustc_commit != EXPECTED_RUSTC_COMMIT
        or build_target != EXPECTED_BUILD_TARGET
    ):
        fail("operator-attested compiler or target metadata is unexpected")
    if not worktree_clean_at_build_and_run:
        fail("operator did not attest a clean worktree at build and run time")
    return {
        "kind": "operator-recorded-provenance",
        "build_command": build_command,
        "run_argv_redacted": (
            "/usr/bin/time -l target/release/aster demo --nodes 32 --root <run-root>"
        ),
        "run_argv_sha256": sha256_bytes(run_argv.encode("utf-8")),
        "redirections": {
            "stdout": "demo.stdout",
            "stderr": "demo.stderr",
        },
        "wrapper_exit_code": wrapper_exit_code,
        "host_os": host_os,
        "host_arch": host_arch,
        "rustc_version": rustc_version,
        "rustc_commit": rustc_commit,
        "build_target": build_target,
        "worktree_clean_at_build_and_run": worktree_clean_at_build_and_run,
        "cryptographic_source_binary_execution_link": "not-proven",
    }


def build_receipt(
    source: dict[str, Any],
    binary: dict[str, Any],
    run: dict[str, Any],
    operator: dict[str, Any],
) -> dict[str, Any]:
    children = run["children"]
    stdout = run["stdout"]
    stderr = run["stderr"]
    transcript = run["transcript_manifest"]
    retention = run["secret_retention"]
    manifest = [
        (
            f"SOURCE commit={source['commit']} tree={source['tree']} "
            "signature=verified checkout_head=exact worktree=not-validator-derived"
        ),
        (
            f"SOURCE_PUBLIC cargo_lock_sha256={source['cargo_lock_sha256']} "
            f"requirements_sha256={source['requirements_sha256']}"
        ),
        f"BINARY profile=release bytes={binary['bytes']} sha256={binary['sha256']}",
        (
            f"OPERATOR build_command={operator['build_command']} "
            f"run_argv_sha256={operator['run_argv_sha256']} wrapper_exit_code=0 "
            "host=Darwin-arm64 provenance=operator-recorded "
            f"rustc={operator['rustc_version']} "
            f"rustc_commit={operator['rustc_commit']} "
            f"target={operator['build_target']} worktree_clean=true "
            "cryptographic_execution_link=not-proven"
        ),
        (
            f"TRANSCRIPT records={transcript['records']} bytes={transcript['bytes']} "
            f"sha256={transcript['sha256']} "
            "scope=demo.stdout,demo.stderr,run/logs-only "
            "node_state_artifacts=excluded"
        ),
        (
            f"SECRET_RETENTION parent_mode={retention['retained_parent_mode']} "
            f"state_directories={retention['state_directories']} "
            f"state_artifacts={retention['state_artifacts']} "
            f"artifact_bytes={retention['aggregate_state_artifact_bytes']} "
            "unique_inodes=96 contents=excluded-not-read-or-hashed"
        ),
        (
            f"OUTER stdout_lines={stdout['lines']} stdout_bytes={stdout['bytes']} "
            f"stdout_sanitized_sha256={stdout['sanitized_sha256']} "
            f"stderr_class={stderr['classification']} stderr_lines={stderr['lines']} "
            f"stderr_bytes={stderr['bytes']} "
            f"stderr_sanitized_sha256={stderr['sanitized_sha256']}"
        ),
        (
            f"CHILDREN processes={PROCESS_COUNT} "
            f"stdout_files={children['stdout_files']} "
            f"stderr_files={children['stderr_files']} "
            f"stdout_lines={children['stdout_lines']} "
            f"stdout_bytes={children['stdout_bytes']} stderr_bytes=0 "
            f"contacts={children['contact_receipts']} "
            f"distinct_process_ids={children['distinct_process_ids']} "
            "stdout_sanitized_aggregate_sha256="
            f"{children['sanitized_stdout_aggregate_sha256']} "
            "stderr_sanitized_aggregate_sha256="
            f"{children['sanitized_stderr_aggregate_sha256']}"
        ),
        (
            f"ACCEPTANCE nodes={NODE_COUNT} phases={PHASE_COUNT} "
            f"processes={PROCESS_COUNT} transfers=2 relay_intermediates=30 "
            f"noop_edges={children['noop_authenticated_edges']} "
            f"noop_cycles={children['noop_authenticated_cycles']} "
            "noop_endpoint_receipts="
            f"{children['noop_authenticated_edge_receipts']} "
            f"noop_distinct_process_ids={children['noop_distinct_process_ids']} "
            "payload_blind_relays=pass"
        ),
    ]
    return {
        "schema": SCHEMA,
        "status": "pass",
        "claim": "selected-one-host-loopback-n32-process-acceptance",
        "claim_limits": {
            "physical_hosts": "not-claimed",
            "nat": "not-claimed",
            "controlled_relay": "not-claimed",
            "btle": "not-claimed",
            "independent_implementation": "not-claimed",
            "resource_thresholds": "measurement-only",
            "worktree_cleanliness": "operator-attested-clean-at-build-and-run",
            "source_binary_execution_link": "operator-attested-not-cryptographically-proven",
        },
        "operator_attestation": operator,
        "source": source,
        "binary": binary,
        "scenario": {
            "nodes": NODE_COUNT,
            "phases": PHASE_COUNT,
            "processes": PROCESS_COUNT,
            "distinct_process_ids": PROCESS_COUNT,
            "noop_distinct_process_ids": NODE_COUNT,
            "subscriptions": {"consume": 2, "carry": 30, "selectors": 32},
            "relay_intermediates": 30,
            "transfers_each": 2,
            "payload_blind_relays": "pass",
            "equal_inventory_noop": "pass",
        },
        "evidence": run,
        "manifest": manifest,
    }


def render_receipt(receipt: dict[str, Any]) -> bytes:
    encoded = (
        json.dumps(receipt, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
        + "\n"
    ).encode("ascii")
    if len(encoded) > RECEIPT_MAX_BYTES:
        fail("sanitized receipt exceeds the 16 KiB output cap")
    return encoded


def write_receipt(output: Path | None, encoded: bytes) -> None:
    if output is None:
        sys.stdout.buffer.write(encoded)
        return
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    flags |= getattr(os, "O_CLOEXEC", 0)
    flags |= getattr(os, "O_NOFOLLOW", 0)
    descriptor: int | None = None
    try:
        descriptor = os.open(output, flags, 0o600)
        written = 0
        while written < len(encoded):
            count = os.write(descriptor, encoded[written:])
            if count <= 0:
                fail("receipt output could not be completed")
            written += count
        os.fsync(descriptor)
    except FileExistsError:
        fail("receipt output already exists; refusing to overwrite it")
    except OSError:
        fail("receipt output could not be created safely")
    finally:
        if descriptor is not None:
            os.close(descriptor)


def parse_args(arguments: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", required=True, type=Path, help="repository root")
    parser.add_argument("--source-commit", required=True, help="expected signed source commit")
    parser.add_argument("--binary", required=True, type=Path, help="release aster binary")
    parser.add_argument("--binary-sha256", required=True, help="expected release binary SHA-256")
    parser.add_argument(
        "--binary-size", required=True, type=int, help="expected release binary bytes"
    )
    parser.add_argument("--root", required=True, type=Path, help="retained demo run root")
    parser.add_argument("--stdout", required=True, type=Path, help="retained outer stdout")
    parser.add_argument("--stderr", required=True, type=Path, help="retained outer stderr")
    parser.add_argument(
        "--transcript-manifest-sha256",
        required=True,
        help="expected safe transcript-only manifest SHA-256",
    )
    parser.add_argument(
        "--build-command", required=True, help="exact executed release build command"
    )
    parser.add_argument(
        "--run-argv", required=True, help="exact executed time-and-demo argv string"
    )
    parser.add_argument(
        "--wrapper-exit-code",
        required=True,
        type=int,
        help="operator-recorded wrapper exit code",
    )
    parser.add_argument("--host-os", required=True, help="operator-recorded host operating system")
    parser.add_argument("--host-arch", required=True, help="operator-recorded host architecture")
    parser.add_argument("--rustc-version", required=True, help="operator-recorded rustc version")
    parser.add_argument(
        "--rustc-commit", required=True, help="operator-recorded rustc commit hash"
    )
    parser.add_argument("--build-target", required=True, help="operator-recorded build target")
    parser.add_argument(
        "--worktree-clean-at-build-and-run",
        required=True,
        action="store_true",
        help="attest that the source worktree was clean for both build and execution",
    )
    parser.add_argument("--output", type=Path, help="exclusive receipt output; defaults to stdout")
    return parser.parse_args(arguments)


def main(arguments: list[str] | None = None) -> None:
    options = parse_args(arguments)
    try:
        source = validate_source(options.source, options.source_commit)
        binary = validate_binary(options.binary, options.binary_sha256, options.binary_size)
        operator = validate_operator_attestation(
            options.build_command,
            options.run_argv,
            options.wrapper_exit_code,
            options.host_os,
            options.host_arch,
            options.rustc_version,
            options.rustc_commit,
            options.build_target,
            options.worktree_clean_at_build_and_run,
            options.root,
        )
        run, _ = validate_run_root(
            options.root,
            options.stdout,
            options.stderr,
            options.transcript_manifest_sha256,
        )
        encoded = render_receipt(build_receipt(source, binary, run, operator))
        write_receipt(options.output, encoded)
    except ReceiptViolation as error:
        print(f"selected N=32 receipt validation failed: {error}", file=sys.stderr)
        raise SystemExit(1) from error


if __name__ == "__main__":
    main()
