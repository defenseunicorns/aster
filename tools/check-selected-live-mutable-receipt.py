#!/usr/bin/env python3
# Copyright 2026 Defense Unicorns, Inc.
# SPDX-License-Identifier: Apache-2.0
"""Project or validate one retained selected live-State/Record receipt.

The raw root is an owner-only, exact-inventory acceptance artifact.  This
validator reads only the public transcript, terminal captures, run metadata,
and copied release executable.  Participant mission bundles, identity keys,
and stores are inspected by metadata only: their contents are never opened,
read, or hashed.

The result is a compact, canonical JSON receipt.  It intentionally makes no
physical-host, NAT, relay, BTLE, independent-implementation, scale, resource
threshold, reproducible-build, or cryptographic source-to-execution claim.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import pwd
import re
import shutil
import stat
import subprocess
import sys
from typing import Any, Iterable, Sequence


SCHEMA = "aster-selected-live-mutable-receipt/v2"
RAW_SCHEMA = "aster-selected-live-mutable-raw/v2"
TRANSCRIPT_SCHEMA = "aster-selected-live-mutable-transcript/v2"
CLAIM = "selected-live-state-causal-successor-tombstone-record-one-host-direct-iroh-two-actor-acceptance"
OLD_RECEIPT_SOURCE_COMMIT = "2ccfba0d18bf8d8221ab11fb485b32fcf6270272"
OLD_RECEIPT_SHA256 = "299a3c3b8d1685deb5980ed091797f7d46119562b67c3d853b94d8552c83b67a"
RECEIPT_NAME = "selected-live-mutable-receipt.json"
RECEIPT_MAX_BYTES = 16 * 1024
RUN_JSON_MAX_BYTES = 64 * 1024
TRANSCRIPT_MAX_BYTES = 64 * 1024
STDOUT_MAX_BYTES = 8 * 1024 * 1024
STDERR_MAX_BYTES = 16 * 1024
BINARY_MAX_BYTES = 128 * 1024 * 1024
MISSION_MAX_BYTES = 1024 * 1024
STORE_MAX_BYTES = 1024 * 1024 * 1024
IDENTITY_BYTES = 32
TRANSCRIPT_RECORDS = 48

HEX_32 = re.compile(r"[0-9a-f]{64}\Z")
GIT_OBJECT = re.compile(r"[0-9a-f]{40}\Z")
RUN_ID = re.compile(r"[0-9a-f]{16}\Z")
FIELD_NAME = re.compile(r"[a-z][a-z0-9_]*\Z")
SIGNER_FINGERPRINT = re.compile(
    r"(?:[0-9A-F]{40,64}|SHA256:[A-Za-z0-9+/]{43})\Z"
)

PRODUCER_PATH = "crates/aster-node/examples/live_mutable_acceptance.rs"
RUNNER_PATH = "tools/run-selected-live-mutable.py"
CHECKER_PATH = "tools/check-selected-live-mutable-receipt.py"
TEST_PATH = "tools/test-selected-live-mutable-receipt.py"
ADMITTED_SOURCE_PATHS = tuple(
    sorted(
        {
            "Cargo.lock",
            "Cargo.toml",
            "mise.toml",
            "crates/aster-core/Cargo.toml",
            "crates/aster-core/src/causal.rs",
            "crates/aster-core/src/crypto/reference.rs",
            "crates/aster-core/src/lib.rs",
            "crates/aster-core/src/source_state.rs",
            "crates/aster-node/Cargo.toml",
            "crates/aster-node/src/application.rs",
            "crates/aster-node/src/application/record.rs",
            "crates/aster-node/src/application/state.rs",
            "crates/aster-node/src/lib.rs",
            "crates/aster-node/src/runtime.rs",
            "crates/aster-redb-store/Cargo.toml",
            "crates/aster-redb-store/src/lib.rs",
            PRODUCER_PATH,
            RUNNER_PATH,
            CHECKER_PATH,
            TEST_PATH,
        }
    )
)
TOOL_PATHS = {
    "producer": PRODUCER_PATH,
    "runner": RUNNER_PATH,
    "checker": CHECKER_PATH,
    "test": TEST_PATH,
}
EXPECTED_BUILD_ARGV = [
    "cargo",
    "build",
    "--release",
    "--locked",
    "-p",
    "aster-node",
    "--example",
    "live_mutable_acceptance",
]

EXPECTED_DIRECTORIES = {
    "",
    "binary",
    "participants",
    "participants/node-a",
    "participants/node-a/state",
    "participants/node-b",
    "participants/node-b/state",
}
EXPECTED_FILES = {
    "run.json": 0o600,
    "stdout.log": 0o600,
    "stderr.log": 0o600,
    "transcript.tsv": 0o600,
    "binary/aster-live-mutable-acceptance": 0o700,
    "participants/node-a/mission.bundle": 0o600,
    "participants/node-a/state/identity.key": 0o600,
    "participants/node-a/state/mesh.redb": 0o600,
    "participants/node-b/mission.bundle": 0o600,
    "participants/node-b/state/identity.key": 0o600,
    "participants/node-b/state/mesh.redb": 0o600,
}
SECRET_FILES = {
    "participants/node-a/mission.bundle",
    "participants/node-a/state/identity.key",
    "participants/node-a/state/mesh.redb",
    "participants/node-b/mission.bundle",
    "participants/node-b/state/identity.key",
    "participants/node-b/state/mesh.redb",
}

RUN_KEYS = (
    "schema",
    "claim",
    "participants",
    "actor_lifetimes",
    "maximum_concurrent_actors",
    "topic",
    "scope",
)
PARTICIPANT_KEYS = (
    "participant",
    "carrier_id",
    "mission_id",
    "mission_authority",
    "expected_carrier_peer",
    "expected_mission_peer",
)
HANDLE_KEYS = (
    "participant",
    "state_identity",
    "state_authority",
    "record_identity",
    "record_authority",
)
PUBLICATION_KEYS = (
    "participant",
    "id",
    "publisher",
    "counter",
    "payload_sha256",
    "inserted",
)
CAUSAL_PUBLICATION_KEYS = (
    "participant",
    "observed_heads",
    "observed_versions",
    "id",
    "publisher",
    "counter",
    "payload_sha256",
    "tombstone",
    "inserted",
)
RETRY_KEYS = ("participant", "original_id", "retry_id", "inserted")
SHUTDOWN_KEYS = (
    "phase",
    "participant",
    "contacts",
    "direct_contacts",
    "relay_contacts",
    "unknown_path_contacts",
    "contact_errors",
)
CLOSED_HANDLE_KEYS = ("participant", "kind", "error_kind", "operation")
STATE_VIEW_KEYS = (
    "phase",
    "participant",
    "current_id",
    "current_publisher",
    "current_counter",
    "current_payload_sha256",
    "current_disposition",
    "recoverable_count",
    "concurrent_id",
    "concurrent_publisher",
    "concurrent_counter",
    "concurrent_payload_sha256",
    "concurrent_disposition",
)
STATE_CAUSAL_VIEW_KEYS = (
    "phase",
    "participant",
    "current_id",
    "current_publisher",
    "current_counter",
    "current_payload_sha256",
    "current_disposition",
    "current_tombstone",
    "superseded_count",
    "superseded",
    "superseded_publishers",
    "superseded_counters",
    "superseded_payload_sha256",
    "superseded_dispositions",
    "superseded_tombstones",
)
RECORD_CONFLICT_KEYS = (
    "phase",
    "participant",
    "current_id",
    "current_publisher",
    "current_counter",
    "current_payload_sha256",
    "current_disposition",
    "concurrent_id",
    "concurrent_publisher",
    "concurrent_counter",
    "concurrent_payload_sha256",
    "concurrent_disposition",
    "conflict",
    "siblings",
    "guard_siblings",
)
RECORD_REJECTION_KEYS = (
    "participant",
    "error_kind",
    "operation",
    "before_siblings",
    "after_siblings",
    "after_conflict",
)
RECORD_RESOLUTION_KEYS = (
    "participant",
    "observed_siblings",
    "id",
    "publisher",
    "counter",
    "payload_sha256",
    "inserted",
)
RESOLUTION_RETRY_KEYS = (
    "phase",
    "participant",
    "original_id",
    "retry_id",
    "inserted",
)
RECORD_RESOLVED_KEYS = (
    "phase",
    "participant",
    "current_id",
    "current_publisher",
    "current_counter",
    "current_payload_sha256",
    "current_disposition",
    "conflict",
    "superseded_count",
    "superseded",
    "superseded_dispositions",
)
BIND_KEYS = ("participant", "status")
RESULT_KEYS = (
    "status",
    "secret_values_emitted",
    "payload_representation",
    "records",
    "actor_lifetimes",
    "maximum_concurrent_actors",
    "graceful_shutdowns",
    "retained_handles",
    "closed_handles",
    "bind_reacquisitions",
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
CONTACT_TRANSFER_FIELDS = ("offered", "fetched", "inserted")
CONTACT_EXCLUDED_ZERO_FIELDS = (
    "control_offered",
    "control_fetched",
    "control_retained",
    "control_duplicates",
    "control_activated",
    "control_remaining",
    "duplicates",
    "remaining",
    "deferred_event_lanes",
    "mutable_remaining",
    "deferred_mutable_lanes",
    "blob_ranges_fetched",
    "blob_bytes_fetched",
    "blob_remaining",
    "blob_deferred",
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
    "events",
    "event_acceptance_markers",
    "route_cached_events",
    "controls",
    "applied_controls",
    "pending_controls",
    "control_highwater",
    "blobs",
    "blob_acceptance_markers",
    "blob_last_acceptance_marker",
    "blob_sealed_bytes",
    "blob_operations",
    "blob_operation_bytes",
    "blob_variants",
    "blob_finalized_variants",
    "blob_committed_chunks",
    "blob_committed_file_bytes",
    "blob_reserved_file_bytes",
    "pending_blobs",
    "blob_carrier_prefixes",
    "blob_carrier_fetch_cursors",
    "blob_network_staging_bytes",
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
STOP_NUMERIC_FIELDS = STOP_KEYS[4:11] + STOP_KEYS[12:-5]
STOP_EXCLUDED_ZERO_FIELDS = (
    "events",
    "event_acceptance_markers",
    "route_cached_events",
    "controls",
    "applied_controls",
    "pending_controls",
    "control_highwater",
    "blobs",
    "blob_acceptance_markers",
    "blob_last_acceptance_marker",
    "blob_sealed_bytes",
    "blob_operations",
    "blob_operation_bytes",
    "blob_variants",
    "blob_finalized_variants",
    "blob_committed_chunks",
    "blob_committed_file_bytes",
    "blob_reserved_file_bytes",
    "pending_blobs",
    "blob_carrier_prefixes",
    "blob_carrier_fetch_cursors",
    "blob_network_staging_bytes",
    "blob_ranges_fetched",
    "blob_bytes_fetched",
    "blob_remaining",
    "blob_deferred",
)
LOOPBACK_SOCKET = re.compile(r"127\.0\.0\.1:([1-9][0-9]{0,4})\Z")

EXPECTED_SEQUENCE: tuple[tuple[str, tuple[str, ...]], ...] = (
    ("RUN", RUN_KEYS),
    ("PARTICIPANT", PARTICIPANT_KEYS),
    ("PARTICIPANT", PARTICIPANT_KEYS),
    ("HANDLE", HANDLE_KEYS),
    ("HANDLE", HANDLE_KEYS),
    ("STATE_PUBLICATION", PUBLICATION_KEYS),
    ("STATE_PUBLICATION", PUBLICATION_KEYS),
    ("STATE_RETRY", RETRY_KEYS),
    ("STATE_RETRY", RETRY_KEYS),
    ("RECORD_PUBLICATION", PUBLICATION_KEYS),
    ("RECORD_PUBLICATION", PUBLICATION_KEYS),
    ("RECORD_RETRY", RETRY_KEYS),
    ("RECORD_RETRY", RETRY_KEYS),
    ("SHUTDOWN", SHUTDOWN_KEYS),
    ("SHUTDOWN", SHUTDOWN_KEYS),
    ("CLOSED_HANDLE", CLOSED_HANDLE_KEYS),
    ("CLOSED_HANDLE", CLOSED_HANDLE_KEYS),
    ("CLOSED_HANDLE", CLOSED_HANDLE_KEYS),
    ("CLOSED_HANDLE", CLOSED_HANDLE_KEYS),
    ("STATE_VIEW", STATE_VIEW_KEYS),
    ("STATE_VIEW", STATE_VIEW_KEYS),
    ("RECORD_CONFLICT", RECORD_CONFLICT_KEYS),
    ("RECORD_CONFLICT", RECORD_CONFLICT_KEYS),
    ("RECORD_REJECTION", RECORD_REJECTION_KEYS),
    ("RECORD_RESOLUTION", RECORD_RESOLUTION_KEYS),
    ("RECORD_RESOLUTION_RETRY", RESOLUTION_RETRY_KEYS),
    ("RECORD_RESOLVED", RECORD_RESOLVED_KEYS),
    ("RECORD_RESOLVED", RECORD_RESOLVED_KEYS),
    ("STATE_SUCCESSOR_PUBLICATION", CAUSAL_PUBLICATION_KEYS),
    ("STATE_SUCCESSOR_RETRY", RETRY_KEYS),
    ("STATE_CAUSAL_VIEW", STATE_CAUSAL_VIEW_KEYS),
    ("STATE_CAUSAL_VIEW", STATE_CAUSAL_VIEW_KEYS),
    ("STATE_TOMBSTONE_PUBLICATION", CAUSAL_PUBLICATION_KEYS),
    ("STATE_TOMBSTONE_RETRY", RETRY_KEYS),
    ("STATE_CAUSAL_VIEW", STATE_CAUSAL_VIEW_KEYS),
    ("STATE_CAUSAL_VIEW", STATE_CAUSAL_VIEW_KEYS),
    ("SHUTDOWN", SHUTDOWN_KEYS),
    ("SHUTDOWN", SHUTDOWN_KEYS),
    ("STATE_CAUSAL_VIEW", STATE_CAUSAL_VIEW_KEYS),
    ("STATE_CAUSAL_VIEW", STATE_CAUSAL_VIEW_KEYS),
    ("RECORD_RESOLVED", RECORD_RESOLVED_KEYS),
    ("RECORD_RESOLVED", RECORD_RESOLVED_KEYS),
    ("RECORD_RESOLUTION_RETRY", RESOLUTION_RETRY_KEYS),
    ("SHUTDOWN", SHUTDOWN_KEYS),
    ("SHUTDOWN", SHUTDOWN_KEYS),
    ("BIND_REACQUIRED", BIND_KEYS),
    ("BIND_REACQUIRED", BIND_KEYS),
    ("RESULT", RESULT_KEYS),
)

PAYLOAD_HASHES = {
    ("state", "node-a"): "88df35f927914acd45fed9c4e539d53c56bc688683246afc8eb28c3520023089",
    ("state", "node-b"): "f42c4365b7ecd070de362a5faee30028c9051e64c1e149f67b3396f08584b5c3",
    ("record", "node-a"): "ea7e65181655ebe13372e8b1d740c2114675ce2d85ba511074158ef1b971e34d",
    ("record", "node-b"): "0572316ec50701364d0e721db4197d4c15667411949b9821ae72c52dd6003ba3",
    ("resolution", "node-a"): "4b631dc38a7dc95cf0d35bc24ff0cdf94bfa9e84aad297bcc1af81fa8970afb3",
    ("successor", "node-a"): "d1604822c53bec359621ef55529767e3e3a586634f8e0218d4a2eea3730e581c",
    ("tombstone", "node-b"): "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
}

LIMITATIONS = [
    "operator-attested-source-binary-execution-link-not-cryptographically-proven",
    "selected-admitted-source-list-is-not-a-complete-reproducible-build-closure",
    "one-host-loopback-same-implementation-observation",
    "participant-secret-artifacts-validated-by-metadata-only",
    "state-causal-observation-and-publication-order-are-producer-attested",
    "restart-observes-one-immediate-peerless-reopen-not-indefinite-tombstone-retention",
]
NONCLAIMS = [
    "distinct-physical-hosts",
    "nat-or-internet-path",
    "controlled-or-public-relay",
    "btle-carrier",
    "independent-implementation-interoperability",
    "scale-beyond-two-participants",
    "resource-thresholds-or-long-duration-soak",
    "event-or-blob-live-application-acceptance",
    "reproducible-build-or-cryptographic-source-to-execution-provenance",
    "tombstone-retention-duration-compaction-or-garbage-collection",
]


class ReceiptViolation(ValueError):
    """The retained run or supplied receipt failed the selected contract."""


def fail(message: str) -> None:
    raise ReceiptViolation(message)


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def exact_string(
    value: Any,
    label: str,
    *,
    expected: str | None = None,
    pattern: re.Pattern[str] | None = None,
    maximum: int = 4096,
) -> str:
    if not isinstance(value, str) or not value or len(value.encode("utf-8")) > maximum:
        fail(f"{label} is not one bounded string")
    if not value.isascii() or any(ord(character) < 0x20 for character in value):
        fail(f"{label} is not canonical printable ASCII")
    if expected is not None and value != expected:
        fail(f"{label} differs from its exact value")
    if pattern is not None and pattern.fullmatch(value) is None:
        fail(f"{label} has a noncanonical encoding")
    return value


def exact_uint(
    value: Any,
    label: str,
    *,
    expected: int | None = None,
    minimum: int = 0,
    maximum: int = (1 << 63) - 1,
) -> int:
    if type(value) is not int or not minimum <= value <= maximum:
        fail(f"{label} is not one bounded unsigned integer")
    if expected is not None and value != expected:
        fail(f"{label} differs from its exact value")
    return value


def exact_bool(value: Any, label: str, *, expected: bool | None = None) -> bool:
    if type(value) is not bool:
        fail(f"{label} is not one Boolean")
    if expected is not None and value is not expected:
        fail(f"{label} differs from its exact value")
    return value


def exact_object(value: Any, keys: Iterable[str], label: str) -> dict[str, Any]:
    expected = set(keys)
    if not isinstance(value, dict) or set(value) != expected:
        fail(f"{label} has missing, extra, or duplicate fields")
    return value


def exact_array(value: Any, label: str, *, length: int | None = None) -> list[Any]:
    if not isinstance(value, list) or (length is not None and len(value) != length):
        fail(f"{label} is not the exact bounded array")
    return value


def canonical_json_bytes(value: Any) -> bytes:
    return (
        json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True) + "\n"
    ).encode("ascii")


def load_canonical_json(data: bytes, label: str, maximum: int) -> dict[str, Any]:
    if not data or len(data) > maximum or not data.endswith(b"\n"):
        fail(f"{label} is empty, truncated, or exceeds its byte cap")
    if b"\x00" in data or b"\r" in data:
        fail(f"{label} contains a forbidden control encoding")

    def pairs_hook(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in pairs:
            if key in result:
                fail(f"{label} contains a duplicate JSON field")
            result[key] = value
        return result

    try:
        text = data.decode("ascii", errors="strict")
        value = json.loads(
            text,
            object_pairs_hook=pairs_hook,
            parse_constant=lambda _value: fail(f"{label} contains a non-finite number"),
        )
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        fail(f"{label} is not canonical JSON: {error}")
    if not isinstance(value, dict):
        fail(f"{label} top level is not one object")
    if canonical_json_bytes(value) != data:
        fail(f"{label} is not compact canonical JSON")
    return value


DIRECTORY_FLAGS = (
    os.O_RDONLY
    | getattr(os, "O_CLOEXEC", 0)
    | getattr(os, "O_DIRECTORY", 0)
    | getattr(os, "O_NOFOLLOW", 0)
)
FILE_FLAGS = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)


def _validate_directory(metadata: os.stat_result, label: str) -> None:
    if not stat.S_ISDIR(metadata.st_mode) or stat.S_ISLNK(metadata.st_mode):
        fail(f"{label} is not one plain directory")
    if metadata.st_uid != os.getuid():
        fail(f"{label} is not owned by the current validator user")
    if stat.S_IMODE(metadata.st_mode) != 0o700:
        fail(f"{label} does not have exact owner-only mode 0700")


def open_raw_root(root: Path) -> tuple[int, os.stat_result]:
    root_text = os.fspath(root)
    candidate = PurePosixPath(root_text)
    if not root_text.startswith("/") or str(candidate) != root_text:
        fail("raw root is not one canonical absolute path")
    try:
        descriptor = os.open("/", DIRECTORY_FLAGS)
    except OSError:
        fail("raw root filesystem anchor could not be opened")
    try:
        for index, part in enumerate(candidate.parts[1:]):
            label = "raw root" if index == len(candidate.parts[1:]) - 1 else "raw root parent"
            try:
                before = os.stat(part, dir_fd=descriptor, follow_symlinks=False)
                following = os.open(part, DIRECTORY_FLAGS, dir_fd=descriptor)
            except OSError:
                fail(f"{label} could not be opened without following links")
            opened = os.fstat(following)
            if (before.st_dev, before.st_ino) != (opened.st_dev, opened.st_ino):
                os.close(following)
                fail(f"{label} changed identity while opening")
            os.close(descriptor)
            descriptor = following
        metadata = os.fstat(descriptor)
        _validate_directory(metadata, "raw root")
        try:
            final = os.lstat(root)
        except OSError:
            fail("raw root path vanished while opening")
        if (final.st_dev, final.st_ino) != (metadata.st_dev, metadata.st_ino):
            fail("raw root path differs from its opened identity")
        return descriptor, metadata
    except BaseException:
        try:
            os.close(descriptor)
        except OSError:
            pass
        raise


def _open_directory_at(root_descriptor: int, relative: str, label: str) -> int:
    parts = PurePosixPath(relative).parts if relative else ()
    if any(part in {"", ".", ".."} for part in parts):
        fail(f"{label} has a noncanonical relative path")
    current = os.dup(root_descriptor)
    try:
        for part in parts:
            try:
                before = os.stat(part, dir_fd=current, follow_symlinks=False)
                following = os.open(part, DIRECTORY_FLAGS, dir_fd=current)
            except OSError:
                fail(f"{label} parent could not be opened without following links")
            opened = os.fstat(following)
            if (before.st_dev, before.st_ino) != (opened.st_dev, opened.st_ino):
                os.close(following)
                fail(f"{label} changed identity while opening")
            _validate_directory(opened, label)
            os.close(current)
            current = following
        return current
    except BaseException:
        try:
            os.close(current)
        except OSError:
            pass
        raise


def read_public_file(
    root_descriptor: int,
    relative: str,
    label: str,
    maximum: int,
) -> tuple[bytes, os.stat_result]:
    path = PurePosixPath(relative)
    parent = _open_directory_at(root_descriptor, str(path.parent) if str(path.parent) != "." else "", label)
    descriptor: int | None = None
    try:
        before = os.stat(path.name, dir_fd=parent, follow_symlinks=False)
        if not stat.S_ISREG(before.st_mode) or stat.S_ISLNK(before.st_mode):
            fail(f"{label} is not one plain regular file")
        if before.st_uid != os.getuid() or before.st_nlink != 1:
            fail(f"{label} has unsafe owner or link metadata")
        if before.st_size > maximum:
            fail(f"{label} exceeds its evidence byte cap")
        descriptor = os.open(path.name, FILE_FLAGS, dir_fd=parent)
        opened = os.fstat(descriptor)
        if (before.st_dev, before.st_ino) != (opened.st_dev, opened.st_ino):
            fail(f"{label} changed identity while opening")
        chunks: list[bytes] = []
        remaining = maximum + 1
        while remaining:
            chunk = os.read(descriptor, min(64 * 1024, remaining))
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        data = b"".join(chunks)
        if len(data) > maximum or len(data) != opened.st_size:
            fail(f"{label} changed size or exceeds its evidence byte cap")
        final = os.fstat(descriptor)
        path_final = os.stat(path.name, dir_fd=parent, follow_symlinks=False)
        if (final.st_dev, final.st_ino, final.st_size) != (
            opened.st_dev,
            opened.st_ino,
            opened.st_size,
        ) or (path_final.st_dev, path_final.st_ino, path_final.st_size) != (
            opened.st_dev,
            opened.st_ino,
            opened.st_size,
        ):
            fail(f"{label} changed while being read")
        return data, opened
    except OSError:
        fail(f"{label} could not be read safely")
    finally:
        if descriptor is not None:
            os.close(descriptor)
        os.close(parent)


def stat_witness(metadata: os.stat_result) -> tuple[int, int, int, int, int, int, int, int]:
    return (
        metadata.st_dev,
        metadata.st_ino,
        metadata.st_mode,
        metadata.st_uid,
        metadata.st_nlink,
        metadata.st_size,
        metadata.st_mtime_ns,
        metadata.st_ctime_ns,
    )


def validate_inventory(root_descriptor: int) -> dict[str, dict[str, os.stat_result]]:
    observed_directories: set[str] = set()
    directory_metadata: dict[str, os.stat_result] = {}
    observed_files: dict[str, os.stat_result] = {}
    identities: list[tuple[int, int]] = []

    def walk(descriptor: int, relative: str) -> None:
        metadata = os.fstat(descriptor)
        _validate_directory(metadata, f"raw directory {relative or '.'}")
        observed_directories.add(relative)
        directory_metadata[relative] = metadata
        identities.append((metadata.st_dev, metadata.st_ino))
        try:
            names = sorted(os.listdir(descriptor))
        except OSError:
            fail(f"raw directory {relative or '.'} could not be enumerated")
        if len(names) > 64:
            fail(f"raw directory {relative or '.'} exceeds its inventory bound")
        for name in names:
            if not name or name in {".", ".."} or "/" in name or "\x00" in name:
                fail("raw inventory contains a noncanonical name")
            child_relative = f"{relative}/{name}" if relative else name
            try:
                before = os.stat(name, dir_fd=descriptor, follow_symlinks=False)
            except OSError:
                fail(f"raw inventory entry {child_relative} could not be inspected")
            if stat.S_ISDIR(before.st_mode):
                if child_relative not in EXPECTED_DIRECTORIES:
                    fail(f"raw inventory contains unexpected directory {child_relative}")
                try:
                    child = os.open(name, DIRECTORY_FLAGS, dir_fd=descriptor)
                except OSError:
                    fail(f"raw directory {child_relative} could not be opened safely")
                try:
                    opened = os.fstat(child)
                    if (before.st_dev, before.st_ino) != (opened.st_dev, opened.st_ino):
                        fail(f"raw directory {child_relative} changed while opening")
                    walk(child, child_relative)
                finally:
                    os.close(child)
            elif stat.S_ISREG(before.st_mode) and not stat.S_ISLNK(before.st_mode):
                expected_mode = EXPECTED_FILES.get(child_relative)
                if expected_mode is None:
                    fail(f"raw inventory contains unexpected file {child_relative}")
                if before.st_uid != os.getuid():
                    fail(f"raw file {child_relative} is not owned by the current user")
                if stat.S_IMODE(before.st_mode) != expected_mode:
                    fail(f"raw file {child_relative} has an unexpected mode")
                if before.st_nlink != 1:
                    fail(f"raw file {child_relative} has an unsafe hard-link count")
                observed_files[child_relative] = before
                identities.append((before.st_dev, before.st_ino))
            else:
                fail(f"raw inventory entry {child_relative} has an unsafe type")

    walk(root_descriptor, "")
    if observed_directories != EXPECTED_DIRECTORIES:
        fail("raw inventory has missing or extra directories")
    if set(observed_files) != set(EXPECTED_FILES):
        fail("raw inventory has missing or extra files")
    if len(set(identities)) != len(identities):
        fail("raw inventory contains aliased directory or file identities")

    for participant in ("node-a", "node-b"):
        mission = observed_files[f"participants/{participant}/mission.bundle"]
        identity = observed_files[f"participants/{participant}/state/identity.key"]
        store = observed_files[f"participants/{participant}/state/mesh.redb"]
        if not 0 < mission.st_size <= MISSION_MAX_BYTES:
            fail(f"{participant} mission artifact violates its metadata-only size bound")
        if identity.st_size != IDENTITY_BYTES:
            fail(f"{participant} identity artifact has the wrong metadata-only byte count")
        if not 0 < store.st_size <= STORE_MAX_BYTES:
            fail(f"{participant} state artifact violates its metadata-only size bound")
    return {"directories": directory_metadata, "files": observed_files}


def require_same_inventory(
    initial: dict[str, dict[str, os.stat_result]],
    final: dict[str, dict[str, os.stat_result]],
) -> None:
    for kind in ("directories", "files"):
        if set(initial[kind]) != set(final[kind]):
            fail(f"raw {kind} inventory changed during validation")
        for relative in initial[kind]:
            if stat_witness(initial[kind][relative]) != stat_witness(final[kind][relative]):
                fail(f"raw inventory metadata changed during validation: {relative or '.'}")


def parse_uint(value: str, label: str, *, positive: bool = False) -> int:
    if not value or not value.isdigit() or (len(value) > 1 and value.startswith("0")):
        fail(f"{label} is not one canonical unsigned decimal integer")
    parsed = int(value)
    if parsed > (1 << 63) - 1 or (positive and parsed == 0):
        fail(f"{label} is outside its evidence bound")
    return parsed


def parse_record(
    line: str,
    expected_type: str,
    expected_keys: tuple[str, ...],
    index: int,
) -> dict[str, str]:
    parts = line.split("\t")
    label = f"transcript record {index + 1}"
    if len(parts) != len(expected_keys) + 2 or parts[:2] != ["LIVE_MUTABLE", expected_type]:
        fail(f"{label} has an unexpected type, delimiter, or field count")
    record: dict[str, str] = {}
    ordered: list[str] = []
    for token in parts[2:]:
        key, separator, value = token.partition("=")
        if separator != "=" or FIELD_NAME.fullmatch(key) is None or not value:
            fail(f"{label} contains a malformed field")
        if key in record:
            fail(f"{label} contains a duplicate field")
        if not value.isascii() or any(ord(character) < 0x21 or ord(character) > 0x7E for character in value):
            fail(f"{label} contains a noncanonical field value")
        ordered.append(key)
        record[key] = value
    if tuple(ordered) != expected_keys:
        fail(f"{label} has missing, extra, or reordered fields")
    return record


def parse_terminal_record(
    line: str,
    expected_prefix: str,
    expected_keys: tuple[str, ...],
    label: str,
) -> dict[str, str]:
    parts = line.split(" ")
    if len(parts) != len(expected_keys) + 1 or parts[0] != expected_prefix or any(not part for part in parts):
        fail(f"{label} has an unexpected prefix, delimiter, or field count")
    record: dict[str, str] = {}
    ordered: list[str] = []
    for token in parts[1:]:
        key, separator, value = token.partition("=")
        if separator != "=" or FIELD_NAME.fullmatch(key) is None or not value:
            fail(f"{label} contains a malformed field")
        if key in record:
            fail(f"{label} contains a duplicate field")
        if not value.isascii() or any(ord(character) < 0x21 or ord(character) > 0x7E for character in value):
            fail(f"{label} contains a noncanonical field value")
        ordered.append(key)
        record[key] = value
    if tuple(ordered) != expected_keys:
        fail(f"{label} has missing, extra, or reordered fields")
    return record


def encoded_path(value: Path) -> str:
    output: list[str] = []
    for byte in os.fsencode(value):
        character = chr(byte)
        if character.isascii() and (character.isalnum() or character in "-_./:"):
            output.append(character)
        else:
            output.append(f"%{byte:02X}")
    return "".join(output)


def require_id(value: str, label: str) -> str:
    if HEX_32.fullmatch(value) is None:
        fail(f"{label} is not one canonical 32-byte identifier")
    return value


def require_fixed(record: dict[str, str], expected: dict[str, str], label: str) -> None:
    for key, value in expected.items():
        if record[key] != value:
            fail(f"{label}.{key} differs from its exact value")


def sorted_pair(first: str, second: str) -> str:
    return ",".join(sorted((first, second)))


def require_csv(
    value: str,
    expected: Sequence[str],
    label: str,
    *,
    identifiers: bool = False,
) -> list[str]:
    observed = value.split(",")
    if observed != list(expected) or any(not item for item in observed):
        fail(f"{label} differs from its exact ordered values")
    if identifiers:
        for index, item in enumerate(observed):
            require_id(item, f"{label}[{index}]")
    return observed


def validate_item(
    record: dict[str, str],
    prefix: str,
    expected: dict[str, str],
    label: str,
) -> None:
    require_id(record[f"{prefix}_id"], f"{label}.{prefix}_id")
    require_id(record[f"{prefix}_publisher"], f"{label}.{prefix}_publisher")
    parse_uint(record[f"{prefix}_counter"], f"{label}.{prefix}_counter", positive=True)
    require_id(record[f"{prefix}_payload_sha256"], f"{label}.{prefix}_payload_sha256")
    for suffix in ("id", "publisher", "counter", "payload_sha256"):
        if record[f"{prefix}_{suffix}"] != expected[suffix]:
            fail(f"{label} has inconsistent {prefix}_{suffix}")


def validate_transcript(data: bytes) -> dict[str, Any]:
    if not data or len(data) > TRANSCRIPT_MAX_BYTES or not data.endswith(b"\n"):
        fail("transcript is empty, truncated, or exceeds its byte cap")
    if b"\x00" in data or b"\r" in data:
        fail("transcript contains a forbidden control encoding")
    try:
        text = data.decode("ascii", errors="strict")
    except UnicodeDecodeError:
        fail("transcript is not canonical ASCII")
    lines = text.splitlines()
    if len(lines) != TRANSCRIPT_RECORDS:
        fail(f"transcript does not contain exactly {TRANSCRIPT_RECORDS} records")
    if any(not line or len(line.encode("ascii")) > 16 * 1024 for line in lines):
        fail("transcript contains an empty or overlong record")
    records = [
        parse_record(lines[index], expected_type, keys, index)
        for index, (expected_type, keys) in enumerate(EXPECTED_SEQUENCE)
    ]

    require_fixed(
        records[0],
        {
            "schema": TRANSCRIPT_SCHEMA,
            "claim": CLAIM,
            "participants": "2",
            "actor_lifetimes": "6",
            "maximum_concurrent_actors": "2",
            "topic": "opaque",
            "scope": "test/runtime-contact",
        },
        "RUN",
    )

    participants: dict[str, dict[str, str]] = {}
    for index, expected_name in zip((1, 2), ("node-a", "node-b"), strict=True):
        record = records[index]
        require_fixed(record, {"participant": expected_name}, f"PARTICIPANT {expected_name}")
        for field in (
            "carrier_id",
            "mission_id",
            "mission_authority",
            "expected_carrier_peer",
            "expected_mission_peer",
        ):
            require_id(record[field], f"PARTICIPANT {expected_name}.{field}")
        participants[expected_name] = record
    a = participants["node-a"]
    b = participants["node-b"]
    if a["carrier_id"] == b["carrier_id"] or a["mission_id"] == b["mission_id"]:
        fail("participant carrier and mission identities are not pairwise distinct")
    identity_domain = {a["carrier_id"], b["carrier_id"], a["mission_id"], b["mission_id"]}
    if len(identity_domain) != 4:
        fail("carrier and mission identity domains overlap")
    if a["mission_authority"] != b["mission_authority"]:
        fail("participants do not share exactly one mission authority")
    if a["mission_authority"] in identity_domain:
        fail("mission authority overlaps a carrier or participant identity")
    if (
        a["expected_carrier_peer"] != b["carrier_id"]
        or b["expected_carrier_peer"] != a["carrier_id"]
        or a["expected_mission_peer"] != b["mission_id"]
        or b["expected_mission_peer"] != a["mission_id"]
    ):
        fail("participant expected carrier or mission peer binding is not reciprocal")

    for index, participant in zip((3, 4), ("node-a", "node-b"), strict=True):
        record = records[index]
        expected = participants[participant]
        require_fixed(
            record,
            {
                "participant": participant,
                "state_identity": expected["mission_id"],
                "state_authority": expected["mission_authority"],
                "record_identity": expected["mission_id"],
                "record_authority": expected["mission_authority"],
            },
            f"HANDLE {participant}",
        )

    state_publications: dict[str, dict[str, str]] = {}
    for index, participant in zip((5, 6), ("node-a", "node-b"), strict=True):
        record = records[index]
        require_fixed(
            record,
            {
                "participant": participant,
                "publisher": participants[participant]["mission_id"],
                "counter": "1",
                "payload_sha256": PAYLOAD_HASHES[("state", participant)],
                "inserted": "true",
            },
            f"STATE_PUBLICATION {participant}",
        )
        require_id(record["id"], f"STATE_PUBLICATION {participant}.id")
        state_publications[participant] = record
    if state_publications["node-a"]["id"] == state_publications["node-b"]["id"]:
        fail("disconnected State publications do not have distinct identities")
    for index, participant in zip((7, 8), ("node-a", "node-b"), strict=True):
        publication = state_publications[participant]
        require_fixed(
            records[index],
            {
                "participant": participant,
                "original_id": publication["id"],
                "retry_id": publication["id"],
                "inserted": "false",
            },
            f"STATE_RETRY {participant}",
        )

    record_publications: dict[str, dict[str, str]] = {}
    for index, participant in zip((9, 10), ("node-a", "node-b"), strict=True):
        record = records[index]
        require_fixed(
            record,
            {
                "participant": participant,
                "publisher": participants[participant]["mission_id"],
                "counter": "2",
                "payload_sha256": PAYLOAD_HASHES[("record", participant)],
                "inserted": "true",
            },
            f"RECORD_PUBLICATION {participant}",
        )
        require_id(record["id"], f"RECORD_PUBLICATION {participant}.id")
        record_publications[participant] = record
    all_publication_ids = {
        state_publications["node-a"]["id"],
        state_publications["node-b"]["id"],
        record_publications["node-a"]["id"],
        record_publications["node-b"]["id"],
    }
    if len(all_publication_ids) != 4:
        fail("State and Record publication identity domains overlap")
    for index, participant in zip((11, 12), ("node-a", "node-b"), strict=True):
        publication = record_publications[participant]
        require_fixed(
            records[index],
            {
                "participant": participant,
                "original_id": publication["id"],
                "retry_id": publication["id"],
                "inserted": "false",
            },
            f"RECORD_RETRY {participant}",
        )

    def validate_shutdown(record: dict[str, str], phase: str, participant: str) -> int:
        require_fixed(record, {"phase": phase, "participant": participant}, f"SHUTDOWN {phase} {participant}")
        counts = {
            field: parse_uint(record[field], f"SHUTDOWN {phase} {participant}.{field}")
            for field in SHUTDOWN_KEYS[2:]
        }
        if counts["contact_errors"] != 0 or counts["relay_contacts"] != 0 or counts["unknown_path_contacts"] != 0:
            fail(f"SHUTDOWN {phase} {participant} contains contact errors or non-direct paths")
        if phase in {"peerless", "restart"}:
            if counts["contacts"] != 0 or counts["direct_contacts"] != 0:
                fail(f"SHUTDOWN {phase} {participant} is not an exact zero-contact phase")
        elif counts["contacts"] <= 0 or counts["direct_contacts"] != counts["contacts"]:
            fail(f"SHUTDOWN connected {participant} is not positive direct-only contact evidence")
        return counts["contacts"]

    shutdown_contacts: dict[str, dict[str, int]] = {
        "peerless": {},
        "connected": {},
        "restart": {},
    }
    for index, participant in zip((13, 14), ("node-a", "node-b"), strict=True):
        shutdown_contacts["peerless"][participant] = validate_shutdown(
            records[index], "peerless", participant
        )

    closed_expected = (
        ("node-a", "state", "state_query"),
        ("node-a", "record", "record_query"),
        ("node-b", "state", "state_query"),
        ("node-b", "record", "record_query"),
    )
    for index, (participant, kind, operation) in zip(range(15, 19), closed_expected, strict=True):
        require_fixed(
            records[index],
            {
                "participant": participant,
                "kind": kind,
                "error_kind": "state_unavailable",
                "operation": operation,
            },
            f"CLOSED_HANDLE {participant} {kind}",
        )

    state_by_id = {
        record["id"]: {
            "id": record["id"],
            "publisher": record["publisher"],
            "counter": record["counter"],
            "payload_sha256": record["payload_sha256"],
        }
        for record in state_publications.values()
    }
    state_ids = sorted(state_by_id)
    expected_state_current = state_by_id[state_ids[1]]
    expected_state_concurrent = state_by_id[state_ids[0]]

    def validate_state_view(record: dict[str, str], phase: str, participant: str) -> None:
        require_fixed(
            record,
            {
                "phase": phase,
                "participant": participant,
                "current_disposition": "current",
                "recoverable_count": "1",
                "concurrent_disposition": "concurrent",
            },
            f"STATE_VIEW {phase} {participant}",
        )
        validate_item(record, "current", expected_state_current, f"STATE_VIEW {phase} {participant}")
        validate_item(record, "concurrent", expected_state_concurrent, f"STATE_VIEW {phase} {participant}")

    for index, participant in zip((19, 20), ("node-a", "node-b"), strict=True):
        validate_state_view(records[index], "connected", participant)

    record_by_id = {
        record["id"]: {
            "id": record["id"],
            "publisher": record["publisher"],
            "counter": record["counter"],
            "payload_sha256": record["payload_sha256"],
        }
        for record in record_publications.values()
    }
    record_ids = sorted(record_by_id)
    siblings = ",".join(record_ids)
    expected_record_current = record_by_id[record_ids[1]]
    expected_record_concurrent = record_by_id[record_ids[0]]
    for index, participant in zip((21, 22), ("node-a", "node-b"), strict=True):
        record = records[index]
        require_fixed(
            record,
            {
                "phase": "connected",
                "participant": participant,
                "current_disposition": "current",
                "concurrent_disposition": "concurrent",
                "conflict": "true",
                "siblings": siblings,
                "guard_siblings": siblings,
            },
            f"RECORD_CONFLICT {participant}",
        )
        validate_item(record, "current", expected_record_current, f"RECORD_CONFLICT {participant}")
        validate_item(record, "concurrent", expected_record_concurrent, f"RECORD_CONFLICT {participant}")

    require_fixed(
        records[23],
        {
            "participant": "node-a",
            "error_kind": "conflict",
            "operation": "record_publish",
            "before_siblings": siblings,
            "after_siblings": siblings,
            "after_conflict": "true",
        },
        "RECORD_REJECTION",
    )

    resolution = records[24]
    require_fixed(
        resolution,
        {
            "participant": "node-a",
            "observed_siblings": siblings,
            "publisher": a["mission_id"],
            "counter": "3",
            "payload_sha256": PAYLOAD_HASHES[("resolution", "node-a")],
            "inserted": "true",
        },
        "RECORD_RESOLUTION",
    )
    resolution_id = require_id(resolution["id"], "RECORD_RESOLUTION.id")
    if resolution_id in all_publication_ids:
        fail("Record resolution identity overlaps an original publication")
    require_fixed(
        records[25],
        {
            "phase": "immediate",
            "participant": "node-a",
            "original_id": resolution_id,
            "retry_id": resolution_id,
            "inserted": "false",
        },
        "RECORD_RESOLUTION_RETRY immediate",
    )
    expected_resolution = {
        "id": resolution_id,
        "publisher": resolution["publisher"],
        "counter": resolution["counter"],
        "payload_sha256": resolution["payload_sha256"],
    }

    def validate_resolved(record: dict[str, str], phase: str, participant: str) -> None:
        require_fixed(
            record,
            {
                "phase": phase,
                "participant": participant,
                "current_disposition": "current",
                "conflict": "false",
                "superseded_count": "2",
                "superseded": siblings,
                "superseded_dispositions": "superseded,superseded",
            },
            f"RECORD_RESOLVED {phase} {participant}",
        )
        validate_item(record, "current", expected_resolution, f"RECORD_RESOLVED {phase} {participant}")

    for index, participant in zip((26, 27), ("node-a", "node-b"), strict=True):
        validate_resolved(records[index], "connected", participant)

    initial_state_versions = [
        {**state_by_id[state_id], "tombstone": "false"} for state_id in state_ids
    ]
    successor = records[28]
    require_fixed(
        successor,
        {
            "participant": "node-a",
            "observed_heads": ",".join(state_ids),
            "observed_versions": ",".join(state_ids),
            "publisher": a["mission_id"],
            "counter": "4",
            "payload_sha256": PAYLOAD_HASHES[("successor", "node-a")],
            "tombstone": "false",
            "inserted": "true",
        },
        "STATE_SUCCESSOR_PUBLICATION",
    )
    require_csv(
        successor["observed_heads"],
        state_ids,
        "STATE_SUCCESSOR_PUBLICATION.observed_heads",
        identifiers=True,
    )
    require_csv(
        successor["observed_versions"],
        state_ids,
        "STATE_SUCCESSOR_PUBLICATION.observed_versions",
        identifiers=True,
    )
    successor_id = require_id(successor["id"], "STATE_SUCCESSOR_PUBLICATION.id")
    if successor_id in all_publication_ids | {resolution_id}:
        fail("State successor identity overlaps an original publication or Record resolution")
    require_fixed(
        records[29],
        {
            "participant": "node-a",
            "original_id": successor_id,
            "retry_id": successor_id,
            "inserted": "false",
        },
        "STATE_SUCCESSOR_RETRY",
    )
    expected_successor = {
        "id": successor_id,
        "publisher": successor["publisher"],
        "counter": successor["counter"],
        "payload_sha256": successor["payload_sha256"],
        "tombstone": successor["tombstone"],
    }

    def validate_causal_state_view(
        record: dict[str, str],
        phase: str,
        participant: str,
        current: dict[str, str],
        superseded_versions: Sequence[dict[str, str]],
    ) -> None:
        ordered = sorted(superseded_versions, key=lambda item: item["id"])
        label = f"STATE_CAUSAL_VIEW {phase} {participant}"
        require_fixed(
            record,
            {
                "phase": phase,
                "participant": participant,
                "current_disposition": "current",
                "current_tombstone": current["tombstone"],
                "superseded_count": str(len(ordered)),
                "superseded": ",".join(item["id"] for item in ordered),
                "superseded_publishers": ",".join(
                    item["publisher"] for item in ordered
                ),
                "superseded_counters": ",".join(
                    item["counter"] for item in ordered
                ),
                "superseded_payload_sha256": ",".join(
                    item["payload_sha256"] for item in ordered
                ),
                "superseded_dispositions": ",".join(
                    "superseded" for _item in ordered
                ),
                "superseded_tombstones": ",".join(
                    item["tombstone"] for item in ordered
                ),
            },
            label,
        )
        validate_item(record, "current", current, label)
        require_csv(
            record["superseded"],
            [item["id"] for item in ordered],
            f"{label}.superseded",
            identifiers=True,
        )
        require_csv(
            record["superseded_publishers"],
            [item["publisher"] for item in ordered],
            f"{label}.superseded_publishers",
            identifiers=True,
        )
        require_csv(
            record["superseded_counters"],
            [item["counter"] for item in ordered],
            f"{label}.superseded_counters",
        )
        require_csv(
            record["superseded_payload_sha256"],
            [item["payload_sha256"] for item in ordered],
            f"{label}.superseded_payload_sha256",
            identifiers=True,
        )
        require_csv(
            record["superseded_dispositions"],
            ["superseded"] * len(ordered),
            f"{label}.superseded_dispositions",
        )
        require_csv(
            record["superseded_tombstones"],
            [item["tombstone"] for item in ordered],
            f"{label}.superseded_tombstones",
        )

    for index, participant in zip((30, 31), ("node-a", "node-b"), strict=True):
        validate_causal_state_view(
            records[index],
            "successor",
            participant,
            expected_successor,
            initial_state_versions,
        )

    pre_tombstone_versions = [*initial_state_versions, expected_successor]
    pre_tombstone_ids = sorted(item["id"] for item in pre_tombstone_versions)
    tombstone = records[32]
    require_fixed(
        tombstone,
        {
            "participant": "node-b",
            "observed_heads": successor_id,
            "observed_versions": ",".join(pre_tombstone_ids),
            "publisher": b["mission_id"],
            "counter": "3",
            "payload_sha256": PAYLOAD_HASHES[("tombstone", "node-b")],
            "tombstone": "true",
            "inserted": "true",
        },
        "STATE_TOMBSTONE_PUBLICATION",
    )
    require_csv(
        tombstone["observed_heads"],
        [successor_id],
        "STATE_TOMBSTONE_PUBLICATION.observed_heads",
        identifiers=True,
    )
    require_csv(
        tombstone["observed_versions"],
        pre_tombstone_ids,
        "STATE_TOMBSTONE_PUBLICATION.observed_versions",
        identifiers=True,
    )
    tombstone_id = require_id(tombstone["id"], "STATE_TOMBSTONE_PUBLICATION.id")
    application_ids = all_publication_ids | {resolution_id, successor_id, tombstone_id}
    if len(application_ids) != 7:
        fail("State, Record, successor, tombstone, and resolution identity domains overlap")
    require_fixed(
        records[33],
        {
            "participant": "node-b",
            "original_id": tombstone_id,
            "retry_id": tombstone_id,
            "inserted": "false",
        },
        "STATE_TOMBSTONE_RETRY",
    )
    expected_tombstone = {
        "id": tombstone_id,
        "publisher": tombstone["publisher"],
        "counter": tombstone["counter"],
        "payload_sha256": tombstone["payload_sha256"],
        "tombstone": tombstone["tombstone"],
    }
    for index, participant in zip((34, 35), ("node-a", "node-b"), strict=True):
        validate_causal_state_view(
            records[index],
            "tombstone",
            participant,
            expected_tombstone,
            pre_tombstone_versions,
        )

    connected_contacts = 0
    for index, participant in zip((36, 37), ("node-a", "node-b"), strict=True):
        observed = validate_shutdown(records[index], "connected", participant)
        shutdown_contacts["connected"][participant] = observed
        connected_contacts += observed
    if (
        shutdown_contacts["connected"]["node-a"]
        != shutdown_contacts["connected"]["node-b"]
    ):
        fail("connected participant contact counts are not equal paired sessions")
    for index, participant in zip((38, 39), ("node-a", "node-b"), strict=True):
        validate_causal_state_view(
            records[index],
            "restart",
            participant,
            expected_tombstone,
            pre_tombstone_versions,
        )
    for index, participant in zip((40, 41), ("node-a", "node-b"), strict=True):
        validate_resolved(records[index], "restart", participant)
    require_fixed(
        records[42],
        {
            "phase": "post_restart",
            "participant": "node-a",
            "original_id": resolution_id,
            "retry_id": resolution_id,
            "inserted": "false",
        },
        "RECORD_RESOLUTION_RETRY post_restart",
    )
    for index, participant in zip((43, 44), ("node-a", "node-b"), strict=True):
        shutdown_contacts["restart"][participant] = validate_shutdown(
            records[index], "restart", participant
        )
    for index, participant in zip((45, 46), ("node-a", "node-b"), strict=True):
        require_fixed(
            records[index],
            {"participant": participant, "status": "reacquired"},
            f"BIND_REACQUIRED {participant}",
        )
    require_fixed(
        records[47],
        {
            "status": "pass",
            "secret_values_emitted": "false",
            "payload_representation": "sha256_only",
            "records": "48",
            "actor_lifetimes": "6",
            "maximum_concurrent_actors": "2",
            "graceful_shutdowns": "6",
            "retained_handles": "4",
            "closed_handles": "4",
            "bind_reacquisitions": "2",
        },
        "RESULT",
    )
    return {
        "records": TRANSCRIPT_RECORDS,
        "bytes": len(data),
        "sha256": sha256_bytes(data),
        "participants": 2,
        "actor_lifetimes": 6,
        "maximum_concurrent_actors": 2,
        "connected_contacts": connected_contacts,
        "state_publications": 4,
        "initial_state_publications": 2,
        "state_successors": 1,
        "state_tombstones": 1,
        "state_causal_views": 6,
        "record_publications": 2,
        "publication_retries": 6,
        "resolution_retries": 2,
        "shutdowns": 6,
        "closed_handles": 4,
        "bind_reacquisitions": 2,
        "_participants": participants,
        "_shutdown_contacts": shutdown_contacts,
        "_application_ids": sorted(application_ids),
    }


def validate_terminal_stdout(
    stdout: bytes,
    transcript: bytes,
    root: Path,
    transcript_facts: dict[str, Any],
) -> dict[str, Any]:
    if not stdout or len(stdout) > STDOUT_MAX_BYTES or not stdout.endswith(b"\n"):
        fail("captured stdout is empty, truncated, or exceeds its byte cap")
    if b"\x00" in stdout or b"\r" in stdout:
        fail("captured stdout contains a forbidden control encoding")
    try:
        text = stdout.decode("ascii", errors="strict")
    except UnicodeDecodeError:
        fail("captured stdout is not canonical ASCII")
    lines = text.splitlines()
    if not lines or len(lines) > 8192:
        fail("captured stdout has an invalid line count")
    if any(not line or len(line.encode("ascii")) > 32 * 1024 for line in lines):
        fail("captured stdout contains an empty or overlong line")
    extracted = b"".join(
        (line + "\n").encode("ascii")
        for line in lines
        if line.startswith("LIVE_MUTABLE\t")
    )
    if extracted != transcript:
        fail("transcript is not the exact ordered LIVE_MUTABLE extraction from stdout")

    participants: dict[str, dict[str, str]] = transcript_facts["_participants"]
    by_carrier = {record["carrier_id"]: name for name, record in participants.items()}
    by_mission = {record["mission_id"]: name for name, record in participants.items()}
    phases = ("peerless", "connected", "restart")
    ready_count = {participant: 0 for participant in participants}
    stop_count = {participant: 0 for participant in participants}
    active: dict[str, str] = {}
    contact_count = {participant: 0 for participant in participants}
    contact_totals = {field: 0 for field in CONTACT_TRANSFER_FIELDS}
    contact_totals_by_participant = {
        participant: {field: 0 for field in CONTACT_TRANSFER_FIELDS}
        for participant in participants
    }
    connected_stop_contacts = 0
    connected_stop_direct_contacts = 0
    connected_sockets: set[str] = set()
    pids: set[int] = set()
    sockets: set[str] = set()
    ports: set[int] = set()
    ready_records = 0
    stop_records = 0
    contact_records = 0

    for line_number, line in enumerate(lines, start=1):
        label = f"captured stdout line {line_number}"
        if line.startswith("LIVE_MUTABLE\t"):
            continue
        if line.startswith("READY "):
            record = parse_terminal_record(line, "READY", READY_KEYS, label)
            carrier_participant = by_carrier.get(record["carrier_id"])
            mission_participant = by_mission.get(record["mission_id"])
            if carrier_participant is None or carrier_participant != mission_participant:
                fail(f"{label} does not bind one transcript participant")
            participant = carrier_participant
            if participant in active or ready_count[participant] >= len(phases):
                fail(f"{label} starts an overlapping or extra participant lifetime")
            phase = phases[ready_count[participant]]
            expected = participants[participant]
            require_fixed(
                record,
                {
                    "selected": "true",
                    "carrier_id": expected["carrier_id"],
                    "mission_id": expected["mission_id"],
                    "mission_authority": expected["mission_authority"],
                    "state": encoded_path(root / "participants" / participant / "state"),
                    "peers": "1" if phase == "connected" else "0",
                    "application": "relay",
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
            pid = parse_uint(record["pid"], f"{label}.pid", positive=True)
            pids.add(pid)
            socket_match = LOOPBACK_SOCKET.fullmatch(record["sockets"])
            if socket_match is None or int(socket_match.group(1)) > 65535:
                fail(f"{label}.sockets is not one bounded loopback socket")
            sockets.add(record["sockets"])
            ports.add(int(socket_match.group(1)))
            if phase == "connected":
                if record["sockets"] in connected_sockets:
                    fail(f"{label}.sockets aliases another concurrent actor bind")
                connected_sockets.add(record["sockets"])
            active[participant] = phase
            ready_count[participant] += 1
            ready_records += 1
            continue
        if line.startswith("CONTACT "):
            record = parse_terminal_record(line, "CONTACT", CONTACT_KEYS, label)
            remote_by_carrier = by_carrier.get(record["carrier_peer"])
            remote_by_mission = by_mission.get(record["mission_peer"])
            if remote_by_carrier is None or remote_by_carrier != remote_by_mission:
                fail(f"{label} does not bind one reciprocal expected peer")
            remote = remote_by_carrier
            local_candidates = [participant for participant in participants if participant != remote]
            if len(local_candidates) != 1:
                raise AssertionError("two-participant local inference is inconsistent")
            local = local_candidates[0]
            if active.get(local) != "connected" or active.get(remote) != "connected":
                fail(f"{label} occurs outside both active connected lifetimes")
            require_fixed(
                record,
                {
                    "direction": record["direction"],
                    "carrier_peer": participants[remote]["carrier_id"],
                    "mission_peer": participants[remote]["mission_id"],
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
                fail(f"{label}.direction is not an admitted contact direction")
            expected_direction = (
                "out"
                if participants[local]["carrier_id"] < participants[remote]["carrier_id"]
                else "in"
            )
            if record["direction"] != expected_direction:
                fail(f"{label}.direction contradicts deterministic carrier initiation")
            numeric_fields = CONTACT_KEYS[3:26] + CONTACT_KEYS[27:28]
            numeric = {
                field: parse_uint(
                    record[field], f"{label}.{field}", positive=field == "rounds"
                )
                for field in numeric_fields
            }
            for field in CONTACT_EXCLUDED_ZERO_FIELDS:
                if numeric[field] != 0:
                    fail(
                        f"{label}.{field} is a nonzero excluded Event, control, mutable-completion, or Blob counter"
                    )
            if numeric["fetched"] != numeric["inserted"]:
                fail(f"{label} fetched content was not inserted exactly once")
            for field in CONTACT_TRANSFER_FIELDS:
                contact_totals[field] += numeric[field]
                contact_totals_by_participant[local][field] += numeric[field]
            for field in (
                "handshake_frames",
                "handshake_bytes",
                "protected_frames",
                "protected_bytes",
            ):
                if numeric[field] == 0:
                    fail(f"{label} has no authenticated or protected protocol traffic")
            contact_count[local] += 1
            contact_records += 1
            continue
        if line.startswith("STOP "):
            record = parse_terminal_record(line, "STOP", STOP_KEYS, label)
            carrier_participant = by_carrier.get(record["carrier_id"])
            mission_participant = by_mission.get(record["mission_id"])
            if carrier_participant is None or carrier_participant != mission_participant:
                fail(f"{label} does not bind one transcript participant")
            participant = carrier_participant
            phase = active.get(participant)
            if phase is None or phase != phases[stop_count[participant]]:
                fail(f"{label} closes an absent or misordered participant lifetime")
            expected_contacts = transcript_facts["_shutdown_contacts"][phase][participant]
            require_fixed(
                record,
                {
                    "lifecycle": "complete",
                    "sync_status": "contacts_observed" if phase == "connected" else "no_successful_contact",
                    "carrier_id": participants[participant]["carrier_id"],
                    "mission_id": participants[participant]["mission_id"],
                    "contacts": str(expected_contacts),
                    "contact_errors": "0",
                    "direct_contacts": str(expected_contacts),
                    "relay_contacts": "0",
                    "unknown_path_contacts": "0",
                    "carrier_path_transitions": "0",
                    "carrier_path_transition_saturations": "0",
                    "path_observation": "not-authorization",
                    "mission_auth": "hybrid-pq",
                    "provisioning": "unprotected-reference",
                    "semantics": "source-authenticated-event",
                    "reconciliation_classes": "event,state,record,blob-v5",
                    "controls_semantics": "source-authenticated-flash",
                },
                label,
            )
            for field in STOP_NUMERIC_FIELDS:
                parse_uint(record[field], f"{label}.{field}")
            for field in STOP_EXCLUDED_ZERO_FIELDS:
                if record[field] != "0":
                    fail(f"{label}.{field} is nonzero outside the selected State/Record receipt")
            if phase == "connected" and contact_count[participant] != expected_contacts:
                fail(f"{label} contact count differs from parsed positive direct CONTACT records")
            if phase == "connected":
                connected_stop_contacts += parse_uint(
                    record["contacts"], f"{label}.contacts"
                )
                connected_stop_direct_contacts += parse_uint(
                    record["direct_contacts"], f"{label}.direct_contacts"
                )
            if phase != "connected" and contact_count[participant] != 0:
                # Counts are reset only after the connected STOP below.
                fail(f"{label} has runtime contacts in a peerless lifetime")
            contact_count[participant] = 0
            del active[participant]
            stop_count[participant] += 1
            stop_records += 1
            continue
        fail(f"{label} belongs to an unadmitted terminal record family")

    if active or any(value != 3 for value in ready_count.values()) or any(value != 3 for value in stop_count.values()):
        fail("captured stdout does not contain exactly three complete lifetimes per participant")
    if ready_records != 6 or stop_records != 6:
        fail("captured stdout does not contain exactly six READY and six STOP records")
    if len(connected_sockets) != 2:
        fail("captured stdout does not bind two distinct concurrent actor sockets")
    if len(pids) != 1:
        fail("captured stdout does not bind all actor receipts to one producer process")
    if contact_records != transcript_facts["connected_contacts"] or contact_records < 2:
        fail("captured stdout CONTACT records differ from connected STOP accounting")
    if (
        connected_stop_contacts != contact_records
        or connected_stop_direct_contacts != contact_records
    ):
        fail("captured stdout CONTACT records do not aggregate exactly to connected STOP accounting")
    expected_contact_totals = {"offered": 7, "fetched": 7, "inserted": 7}
    if contact_totals != expected_contact_totals:
        fail(
            "captured stdout CONTACT reconciliation aggregate does not prove exactly seven offers, fetches, and insertions"
        )
    expected_participant_totals = {
        "node-a": {"offered": 4, "fetched": 3, "inserted": 3},
        "node-b": {"offered": 3, "fetched": 4, "inserted": 4},
    }
    for participant, expected in expected_participant_totals.items():
        if contact_totals_by_participant[participant] != expected:
            fail(
                f"captured stdout {participant} CONTACT reconciliation does not match its exact publication and resolution arithmetic"
            )
    return {
        "lines": len(lines),
        "bytes": len(stdout),
        "sha256": sha256_bytes(stdout),
        "ready_records": ready_records,
        "contact_records": contact_records,
        "stop_records": stop_records,
        "processes": 1,
        "reconciliation": {
            "selected_item_transfer": {
                **contact_totals,
                "duplicates": 0,
            },
            "remaining": {"event": 0, "mutable": 0},
            "deferred_lanes": {"event": 0, "mutable": 0},
            "stop_event_inventory": "all-zero",
            "control_counters": "all-zero",
            "blob_counters": "all-zero",
            "contact_stop_aggregation": "exact",
        },
        "identifiers_paths_ports_pids": "parsed-cross-bound-excluded",
        "_sensitive_values": sorted(
            {
                *(record[field] for record in participants.values() for field in ("carrier_id", "mission_id", "mission_authority")),
                *transcript_facts["_application_ids"],
                *sockets,
                encoded_path(root),
            }
        ),
        "_sensitive_pids": sorted(pids),
        "_sensitive_ports": sorted(ports),
    }


def validate_artifact_record(
    value: Any,
    label: str,
    *,
    path: str,
    data: bytes,
) -> dict[str, Any]:
    record = exact_object(value, ("path", "bytes", "sha256"), label)
    exact_string(record["path"], f"{label}.path", expected=path)
    exact_uint(record["bytes"], f"{label}.bytes", expected=len(data))
    exact_string(record["sha256"], f"{label}.sha256", expected=sha256_bytes(data), pattern=HEX_32)
    return record


def validate_source_metadata(value: Any, authority: dict[str, Any]) -> list[dict[str, Any]]:
    source = exact_object(value, ("commit", "tree", "signature", "admitted"), "run.source")
    exact_string(source["commit"], "run.source.commit", expected=authority["commit"], pattern=GIT_OBJECT)
    exact_string(source["tree"], "run.source.tree", expected=authority["tree"], pattern=GIT_OBJECT)
    signature = exact_object(
        source["signature"], ("status", "fingerprint"), "run.source.signature"
    )
    exact_string(
        signature["status"],
        "run.source.signature.status",
        expected=authority["signature"]["status"],
    )
    exact_string(
        signature["fingerprint"],
        "run.source.signature.fingerprint",
        expected=authority["signature"]["fingerprint"],
        pattern=SIGNER_FINGERPRINT,
    )
    admitted = exact_array(source["admitted"], "run.source.admitted", length=len(ADMITTED_SOURCE_PATHS))
    normalized: list[dict[str, Any]] = []
    for index, expected_path in enumerate(ADMITTED_SOURCE_PATHS):
        label = f"run.source.admitted[{index}]"
        record = exact_object(admitted[index], ("path", "bytes", "sha256"), label)
        exact_string(record["path"], f"{label}.path", expected=expected_path)
        expected = authority["admitted"][expected_path]
        exact_uint(record["bytes"], f"{label}.bytes", expected=expected["bytes"])
        exact_string(record["sha256"], f"{label}.sha256", expected=expected["sha256"], pattern=HEX_32)
        normalized.append(record)
    return normalized


def validate_run_document(
    document: dict[str, Any],
    root: Path,
    source_authority: dict[str, Any],
    binary: bytes,
    stdout: bytes,
    stderr: bytes,
    transcript: bytes,
) -> dict[str, Any]:
    exact_object(
        document,
        ("schema", "claim", "run_id", "source", "commands", "execution", "artifacts", "tools"),
        "run",
    )
    exact_string(document["schema"], "run.schema", expected=RAW_SCHEMA)
    exact_string(document["claim"], "run.claim", expected=CLAIM)
    run_id = exact_string(document["run_id"], "run.run_id", pattern=RUN_ID)
    if run_id != sha256_bytes(transcript)[:16]:
        fail("run.run_id does not derive from the exact transcript")
    admitted = validate_source_metadata(document["source"], source_authority)

    commands = exact_object(document["commands"], ("build_argv", "run_argv"), "run.commands")
    build_argv = exact_array(commands["build_argv"], "run.commands.build_argv", length=len(EXPECTED_BUILD_ARGV))
    if build_argv != EXPECTED_BUILD_ARGV:
        fail("run.commands.build_argv differs from the exact release build invocation")
    run_argv = exact_array(commands["run_argv"], "run.commands.run_argv", length=2)
    expected_binary = os.fspath(root / "binary" / "aster-live-mutable-acceptance")
    if run_argv != [expected_binary, os.fspath(root)]:
        fail("run.commands.run_argv does not bind the copied executable and exact raw root")

    execution = exact_object(
        document["execution"],
        ("exit_code", "worktree_clean_at_run", "source_binary_execution_link"),
        "run.execution",
    )
    exact_uint(execution["exit_code"], "run.execution.exit_code", expected=0)
    exact_bool(execution["worktree_clean_at_run"], "run.execution.worktree_clean_at_run", expected=True)
    exact_string(
        execution["source_binary_execution_link"],
        "run.execution.source_binary_execution_link",
        expected="operator-attested-not-cryptographically-proven",
    )

    artifacts = exact_object(document["artifacts"], ("binary", "stdout", "stderr", "transcript"), "run.artifacts")
    validated_artifacts = {
        "binary": validate_artifact_record(
            artifacts["binary"],
            "run.artifacts.binary",
            path="binary/aster-live-mutable-acceptance",
            data=binary,
        ),
        "stdout": validate_artifact_record(artifacts["stdout"], "run.artifacts.stdout", path="stdout.log", data=stdout),
        "stderr": validate_artifact_record(artifacts["stderr"], "run.artifacts.stderr", path="stderr.log", data=stderr),
        "transcript": validate_artifact_record(
            artifacts["transcript"], "run.artifacts.transcript", path="transcript.tsv", data=transcript
        ),
    }

    tools = exact_object(document["tools"], ("producer", "runner", "checker", "test"), "run.tools")
    admitted_by_path = {record["path"]: record for record in admitted}
    normalized_tools: dict[str, dict[str, Any]] = {}
    for role, path in TOOL_PATHS.items():
        label = f"run.tools.{role}"
        record = exact_object(tools[role], ("path", "bytes", "sha256"), label)
        exact_string(record["path"], f"{label}.path", expected=path)
        if record != admitted_by_path[path]:
            fail(f"{label} differs from the signed admitted-source record")
        normalized_tools[role] = record
    return {
        "run_id": run_id,
        "source": document["source"],
        "build_argv": build_argv,
        "run_argv": run_argv,
        "artifacts": validated_artifacts,
        "tools": normalized_tools,
    }


def validate_raw_root(root: Path, source_authority: dict[str, Any]) -> dict[str, Any]:
    root_descriptor, opened_root = open_raw_root(root)
    try:
        inventory = validate_inventory(root_descriptor)
        run_data, run_metadata = read_public_file(root_descriptor, "run.json", "run metadata", RUN_JSON_MAX_BYTES)
        stdout, stdout_metadata = read_public_file(root_descriptor, "stdout.log", "captured stdout", STDOUT_MAX_BYTES)
        stderr, stderr_metadata = read_public_file(root_descriptor, "stderr.log", "captured stderr", STDERR_MAX_BYTES)
        transcript, transcript_metadata = read_public_file(
            root_descriptor, "transcript.tsv", "selected transcript", TRANSCRIPT_MAX_BYTES
        )
        binary, binary_metadata = read_public_file(
            root_descriptor,
            "binary/aster-live-mutable-acceptance",
            "copied release executable",
            BINARY_MAX_BYTES,
        )
        public_metadata = {
            "run.json": run_metadata,
            "stdout.log": stdout_metadata,
            "stderr.log": stderr_metadata,
            "transcript.tsv": transcript_metadata,
            "binary/aster-live-mutable-acceptance": binary_metadata,
        }
        for relative, metadata in public_metadata.items():
            observed = inventory["files"][relative]
            if (metadata.st_dev, metadata.st_ino, metadata.st_size) != (
                observed.st_dev,
                observed.st_ino,
                observed.st_size,
            ):
                fail(f"public artifact {relative} changed after inventory inspection")
        if not binary:
            fail("copied release executable is empty")
        if stderr != b"":
            fail("captured stderr is nonempty and has no selected acceptance classification")
        transcript_facts = validate_transcript(transcript)
        terminal_facts = validate_terminal_stdout(stdout, transcript, root, transcript_facts)
        document = load_canonical_json(run_data, "run metadata", RUN_JSON_MAX_BYTES)
        run_facts = validate_run_document(
            document,
            root,
            source_authority,
            binary,
            stdout,
            stderr,
            transcript,
        )
        final_inventory = validate_inventory(root_descriptor)
        require_same_inventory(inventory, final_inventory)
        final_public = {
            "run.json": read_public_file(
                root_descriptor, "run.json", "terminal run metadata", RUN_JSON_MAX_BYTES
            )[0],
            "stdout.log": read_public_file(
                root_descriptor, "stdout.log", "terminal captured stdout", STDOUT_MAX_BYTES
            )[0],
            "stderr.log": read_public_file(
                root_descriptor, "stderr.log", "terminal captured stderr", STDERR_MAX_BYTES
            )[0],
            "transcript.tsv": read_public_file(
                root_descriptor,
                "transcript.tsv",
                "terminal selected transcript",
                TRANSCRIPT_MAX_BYTES,
            )[0],
            "binary/aster-live-mutable-acceptance": read_public_file(
                root_descriptor,
                "binary/aster-live-mutable-acceptance",
                "terminal copied release executable",
                BINARY_MAX_BYTES,
            )[0],
        }
        initial_public = {
            "run.json": run_data,
            "stdout.log": stdout,
            "stderr.log": stderr,
            "transcript.tsv": transcript,
            "binary/aster-live-mutable-acceptance": binary,
        }
        for relative, initial_data in initial_public.items():
            if final_public[relative] != initial_data:
                fail(f"public artifact changed after semantic validation: {relative}")
        terminal_inventory = validate_inventory(root_descriptor)
        require_same_inventory(final_inventory, terminal_inventory)
        final_root = os.fstat(root_descriptor)
        _validate_directory(final_root, "raw root")
        if (final_root.st_dev, final_root.st_ino) != (opened_root.st_dev, opened_root.st_ino):
            fail("raw root changed identity during validation")
        try:
            path_final = os.lstat(root)
        except OSError:
            fail("raw root path vanished during terminal validation")
        if (path_final.st_dev, path_final.st_ino) != (final_root.st_dev, final_root.st_ino):
            fail("raw root path changed identity during validation")
        return {
            "run": run_facts,
            "transcript": transcript_facts,
            "terminal": terminal_facts,
            "retention": {
                "root_mode": "0700",
                "directories": len(EXPECTED_DIRECTORIES),
                "files": len(EXPECTED_FILES),
                "participant_directories": 2,
                "mission_artifacts": 2,
                "identity_artifacts": 2,
                "state_artifacts": 2,
                "secret_artifact_contents": "metadata-only-not-opened-read-or-hashed",
                "file_links": "all-one",
                "inventory_aliases": "none",
            },
        }
    finally:
        os.close(root_descriptor)


def reviewer_home_directory() -> str:
    try:
        home = pwd.getpwuid(os.getuid()).pw_dir
    except (KeyError, OSError):
        fail("reviewer account home authority is unavailable")
    if not os.path.isabs(home) or os.path.realpath(home) != home:
        fail("reviewer account home is symbolic or noncanonical")
    try:
        metadata = os.lstat(home)
    except OSError:
        fail("reviewer account home is unavailable")
    if (
        not stat.S_ISDIR(metadata.st_mode)
        or stat.S_ISLNK(metadata.st_mode)
        or metadata.st_uid != os.getuid()
        or stat.S_IMODE(metadata.st_mode) & 0o022
    ):
        fail("reviewer account home metadata is unsafe")
    return home


def _clean_git_environment() -> dict[str, str]:
    environment = os.environ.copy()
    for key in list(environment):
        if key in {
            "GIT_DIR",
            "GIT_WORK_TREE",
            "GIT_COMMON_DIR",
            "GIT_OBJECT_DIRECTORY",
            "GIT_ALTERNATE_OBJECT_DIRECTORIES",
            "GIT_INDEX_FILE",
            "GIT_NAMESPACE",
            "GIT_CONFIG_PARAMETERS",
            "GIT_CONFIG_SYSTEM",
            "GIT_CONFIG_GLOBAL",
        } or key.startswith("GIT_CONFIG_KEY_") or key.startswith("GIT_CONFIG_VALUE_"):
            environment.pop(key, None)
    environment.pop("GIT_CONFIG_COUNT", None)
    environment.pop("GNUPGHOME", None)
    environment.pop("GPG_TTY", None)
    reviewer_home = reviewer_home_directory()
    environment.update(
        {
            "GIT_NO_REPLACE_OBJECTS": "1",
            "GIT_CONFIG_NOSYSTEM": "1",
            "GIT_CONFIG_GLOBAL": os.devnull,
            "GIT_OPTIONAL_LOCKS": "0",
            "HOME": reviewer_home,
        }
    )
    return environment


def trusted_executable(path: str, label: str) -> str:
    if not os.path.isabs(path) or os.path.realpath(path) != path:
        fail(f"{label} executable path is not absolute and canonical")
    try:
        metadata = os.lstat(path)
    except OSError:
        fail(f"{label} executable is unavailable")
    if (
        not stat.S_ISREG(metadata.st_mode)
        or stat.S_ISLNK(metadata.st_mode)
        or metadata.st_uid not in {0, os.getuid()}
        or metadata.st_nlink < 1
        or (metadata.st_uid != 0 and metadata.st_nlink != 1)
        or metadata.st_size <= 0
        or stat.S_IMODE(metadata.st_mode) & 0o022
        or stat.S_IMODE(metadata.st_mode) & 0o111 == 0
    ):
        fail(f"{label} executable metadata is unsafe")
    return path


def system_executable(name: str) -> str:
    search_path = os.confstr("CS_PATH") or "/bin:/usr/bin"
    resolved = shutil.which(name, path=search_path)
    if resolved is None:
        fail(f"system {name} executable is unavailable")
    return trusted_executable(os.path.realpath(resolved), f"system {name}")


def reviewer_signature_options(git: str) -> list[str]:
    reviewer_home = reviewer_home_directory()
    reviewer_global = os.path.abspath(os.path.join(reviewer_home, ".gitconfig"))
    if os.path.realpath(reviewer_global) != reviewer_global:
        fail("reviewer global Git configuration is symbolic or noncanonical")
    try:
        global_metadata = os.lstat(reviewer_global)
    except OSError:
        fail("reviewer global Git configuration is unavailable")
    if (
        not stat.S_ISREG(global_metadata.st_mode)
        or stat.S_ISLNK(global_metadata.st_mode)
        or global_metadata.st_uid != os.getuid()
        or global_metadata.st_nlink != 1
        or global_metadata.st_size <= 0
        or global_metadata.st_size > 1024 * 1024
        or stat.S_IMODE(global_metadata.st_mode) & 0o022
    ):
        fail("reviewer global Git configuration metadata is unsafe")
    environment = _clean_git_environment()
    environment["GIT_CONFIG_GLOBAL"] = reviewer_global

    def global_value(arguments: Sequence[str], label: str) -> str:
        try:
            completed = subprocess.run(
                [git, "config", "--global", *arguments],
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                env=environment,
                shell=False,
                check=False,
                timeout=10,
            )
        except (OSError, subprocess.TimeoutExpired):
            fail(f"reviewer signature {label} could not be read")
        if completed.returncode != 0 or completed.stderr or len(completed.stdout) > 4096:
            fail(f"reviewer signature {label} is unavailable")
        try:
            value = completed.stdout.decode("utf-8", errors="strict").strip()
        except UnicodeDecodeError:
            fail(f"reviewer signature {label} is not UTF-8")
        if not value or "\n" in value or "\x00" in value:
            fail(f"reviewer signature {label} is malformed")
        return value

    signature_format = global_value(["--get", "gpg.format"], "format")
    if signature_format == "ssh":
        allowed = global_value(
            ["--path", "--get", "gpg.ssh.allowedSignersFile"], "allowed signers"
        )
        if allowed.startswith("~/"):
            allowed_path = os.path.join(reviewer_home, allowed[2:])
        elif os.path.isabs(allowed):
            allowed_path = allowed
        else:
            fail("reviewer SSH allowed-signers path is not absolute")
        allowed_path = os.path.abspath(allowed_path)
        if os.path.realpath(allowed_path) != allowed_path:
            fail("reviewer SSH allowed-signers path is symbolic or noncanonical")
        try:
            allowed_metadata = os.lstat(allowed_path)
        except OSError:
            fail("reviewer SSH allowed-signers file is unavailable")
        if (
            not stat.S_ISREG(allowed_metadata.st_mode)
            or stat.S_ISLNK(allowed_metadata.st_mode)
            or allowed_metadata.st_uid != os.getuid()
            or allowed_metadata.st_nlink != 1
            or allowed_metadata.st_size <= 0
            or allowed_metadata.st_size > 1024 * 1024
            or stat.S_IMODE(allowed_metadata.st_mode) & 0o022
        ):
            fail("reviewer SSH allowed-signers file metadata is unsafe")
        ssh_keygen = system_executable("ssh-keygen")
        return [
            "-c",
            "gpg.format=ssh",
            "-c",
            f"gpg.ssh.allowedSignersFile={allowed_path}",
            "-c",
            f"gpg.ssh.program={ssh_keygen}",
            "-c",
            "gpg.minTrustLevel=fully",
        ]
    if signature_format == "openpgp":
        configured_gpg = global_value(["--path", "--get", "gpg.program"], "gpg program")
        gpg = trusted_executable(configured_gpg, "reviewer gpg")
        return [
            "-c",
            "gpg.format=openpgp",
            "-c",
            f"gpg.program={gpg}",
            "-c",
            f"gpg.openpgp.program={gpg}",
            "-c",
            "gpg.minTrustLevel=fully",
        ]
    fail("reviewer signature format is unsupported")


def run_git(
    source: Path,
    arguments: Sequence[str],
    label: str,
    maximum: int = 64 * 1024 * 1024,
    *,
    git: str | None = None,
    trusted_options: Sequence[str] = (),
) -> bytes:
    git = git or system_executable("git")
    if not os.path.isabs(git):
        fail("git is unavailable for independent source validation")
    try:
        completed = subprocess.run(
            [
                git,
                "--no-replace-objects",
                *trusted_options,
                "-c",
                "core.fsmonitor=false",
                "-c",
                "core.hooksPath=/dev/null",
                "-C",
                os.fspath(source),
                *arguments,
            ],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env=_clean_git_environment(),
            shell=False,
            check=False,
            timeout=60,
        )
    except (OSError, subprocess.TimeoutExpired):
        fail(f"source {label} could not be completed")
    if len(completed.stdout) > maximum or len(completed.stderr) > 1024 * 1024:
        fail(f"source {label} exceeded its output bound")
    if completed.returncode != 0:
        fail(f"source {label} failed")
    return completed.stdout


def parse_signature_authority(data: bytes) -> dict[str, str]:
    if len(data) > 4096 or not data.endswith(b"\n") or data.count(b"\x00") != 1:
        fail("source signature status and fingerprint record is malformed")
    raw_status, raw_fingerprint = data[:-1].split(b"\x00", 1)
    try:
        status = raw_status.decode("ascii", errors="strict")
        fingerprint = raw_fingerprint.decode("ascii", errors="strict")
    except UnicodeDecodeError:
        fail("source signature authority is not canonical ASCII")
    if status != "G":
        fail("source signature status is not exactly good and trusted")
    if SIGNER_FINGERPRINT.fullmatch(fingerprint) is None:
        fail("source signer fingerprint is empty or noncanonical")
    return {"status": "good", "fingerprint": fingerprint}


def validate_source(source: Path, raw_root: Path) -> dict[str, Any]:
    source_text = os.path.abspath(os.fspath(source))
    if os.path.realpath(source_text) != source_text:
        fail("source root is symbolic or noncanonical")
    try:
        metadata = os.lstat(source_text)
    except OSError:
        fail("source root is unavailable")
    if not stat.S_ISDIR(metadata.st_mode) or stat.S_ISLNK(metadata.st_mode):
        fail("source root is not one plain directory")
    git = system_executable("git")
    trusted_options = reviewer_signature_options(git)

    def source_git(
        arguments: Sequence[str], label: str, maximum: int = 64 * 1024 * 1024
    ) -> bytes:
        return run_git(
            source,
            arguments,
            label,
            maximum,
            git=git,
            trusted_options=trusted_options,
        )

    top = source_git(["rev-parse", "--show-toplevel"], "root discovery", 4096)
    try:
        top_path = Path(os.fsdecode(top.rstrip(b"\n")))
        if not os.path.samefile(source, top_path):
            fail("source root is not the repository top level")
    except (OSError, UnicodeDecodeError):
        fail("source root identity could not be validated")
    head = source_git(["rev-parse", "--verify", "HEAD"], "HEAD validation", 128).decode("ascii", errors="strict").strip()
    if GIT_OBJECT.fullmatch(head) is None:
        fail("source HEAD is not one canonical commit identifier")
    tree = source_git(["show", "-s", "--format=%T", head], "tree validation", 128).decode("ascii", errors="strict").strip()
    if GIT_OBJECT.fullmatch(tree) is None:
        fail("source tree is not one canonical tree identifier")
    source_git(["verify-commit", head], "commit signature validation", 1024 * 1024)
    signature = parse_signature_authority(
        source_git(
            ["show", "-s", "--format=%G?%x00%GF", head],
            "commit signer fingerprint validation",
            4096,
        )
    )
    status = source_git(["status", "--porcelain=v1", "--untracked-files=all"], "worktree validation", 4 * 1024 * 1024)
    try:
        raw_relative = raw_root.relative_to(source)
    except ValueError:
        raw_relative = None
    if raw_relative is not None:
        fail("raw root must be outside the source checkout")
    if status:
        fail("source worktree is not clean at independent validation time")
    admitted: dict[str, dict[str, Any]] = {}
    for relative in ADMITTED_SOURCE_PATHS:
        content = source_git(["show", f"{head}:{relative}"], f"admitted blob {relative}")
        if not content or len(content) > 16 * 1024 * 1024:
            fail(f"signed admitted source file is empty or exceeds its bound: {relative}")
        working = source / relative
        try:
            working_metadata = os.lstat(working)
        except OSError:
            fail(f"working admitted source file is missing: {relative}")
        if (
            not stat.S_ISREG(working_metadata.st_mode)
            or stat.S_ISLNK(working_metadata.st_mode)
            or working_metadata.st_nlink != 1
            or working_metadata.st_size != len(content)
        ):
            fail(f"working admitted source file has unsafe metadata: {relative}")
        try:
            working_content = working.read_bytes()
        except OSError:
            fail(f"working admitted source file could not be read: {relative}")
        if working_content != content:
            fail(f"working admitted source differs from signed commit: {relative}")
        admitted[relative] = {"bytes": len(content), "sha256": sha256_bytes(content)}
    terminal_status = source_git(
        ["status", "--porcelain=v1", "--untracked-files=all"],
        "terminal worktree validation",
        4 * 1024 * 1024,
    )
    if terminal_status:
        fail("source worktree changed during independent validation")
    return {"commit": head, "tree": tree, "signature": signature, "admitted": admitted}


def build_receipt(source: dict[str, Any], evidence: dict[str, Any]) -> dict[str, Any]:
    run = evidence["run"]
    transcript = evidence["transcript"]
    binary = run["artifacts"]["binary"]
    terminal = evidence["terminal"]
    admitted = [
        {
            "path": path,
            "bytes": source["admitted"][path]["bytes"],
            "sha256": source["admitted"][path]["sha256"],
        }
        for path in ADMITTED_SOURCE_PATHS
    ]
    tools = {
        role: {
            "bytes": source["admitted"][path]["bytes"],
            "sha256": source["admitted"][path]["sha256"],
        }
        for role, path in TOOL_PATHS.items()
    }
    exact_run_argv_sha256 = sha256_bytes(canonical_json_bytes(run["run_argv"]))
    return {
        "schema": SCHEMA,
        "status": "pass",
        "claim": CLAIM,
        "supersedes": {
            "schema": "aster-selected-live-mutable-receipt/v1",
            "source_commit": OLD_RECEIPT_SOURCE_COMMIT,
            "receipt_sha256": OLD_RECEIPT_SHA256,
        },
        "source": {
            "commit": source["commit"],
            "tree": source["tree"],
            "signature": source["signature"],
            "admitted": admitted,
        },
        "build": {
            "argv": EXPECTED_BUILD_ARGV,
            "profile": "release",
            "executable": {"bytes": binary["bytes"], "sha256": binary["sha256"]},
            "source_binary_execution_link": "operator-attested-not-cryptographically-proven",
        },
        "run": {
            "id": run["run_id"],
            "argv_redacted": ["<raw-root>/binary/aster-live-mutable-acceptance", "<raw-root>"],
            "exact_argv_sha256": exact_run_argv_sha256,
            "exit_code": 0,
            "stdout": {
                "bytes": run["artifacts"]["stdout"]["bytes"],
                "sha256": run["artifacts"]["stdout"]["sha256"],
                "lines": terminal["lines"],
                "ready_records": terminal["ready_records"],
                "contact_records": terminal["contact_records"],
                "stop_records": terminal["stop_records"],
                "identifiers_paths_ports_pids": terminal[
                    "identifiers_paths_ports_pids"
                ],
            },
            "stderr": {
                "bytes": run["artifacts"]["stderr"]["bytes"],
                "sha256": run["artifacts"]["stderr"]["sha256"],
                "classification": "exact-empty",
            },
            "transcript": {
                "records": transcript["records"],
                "bytes": transcript["bytes"],
                "sha256": transcript["sha256"],
                "identifiers": "excluded",
                "payloads": "sha256-only",
            },
        },
        "acceptance": {
            "participants": 2,
            "actor_lifetimes": 6,
            "maximum_concurrent_actors": 2,
            "distinct_carrier_ids": 2,
            "distinct_mission_ids": 2,
            "common_disjoint_mission_authority": True,
            "reciprocal_expected_peer_binding": "verified",
            "live_handle_identity_binding": "verified",
            "runtime_ready_stop_identity_binding": "verified",
            "peerless_and_restart_contacts": 0,
            "connected_contacts": transcript["connected_contacts"],
            "connected_path": "positive-direct-only-zero-errors",
            "connected_reconciliation": terminal["reconciliation"],
            "state": {
                "publications": transcript["state_publications"],
                "initial_publications": transcript["initial_state_publications"],
                "initial_reducer": "max-id-current-other-concurrent",
                "initial_connected_views": 2,
                "causal_observed_head_and_version_sets": "exact",
                "successor": {
                    "publications": transcript["state_successors"],
                    "publisher_role": "node-a",
                    "publisher_counter": 4,
                    "observed_heads": 2,
                    "observed_versions": 2,
                    "current_tombstone": False,
                    "superseded_predecessors": 2,
                    "network_views": 2,
                },
                "tombstone": {
                    "publications": transcript["state_tombstones"],
                    "publisher_role": "node-b",
                    "publisher_counter": 3,
                    "empty_payload_sha256": PAYLOAD_HASHES[("tombstone", "node-b")],
                    "observed_heads": 1,
                    "observed_versions": 3,
                    "current_tombstone": True,
                    "superseded_predecessors": 3,
                    "network_views": 2,
                    "peerless_restart_views": 2,
                    "retention_scope": "one-immediate-peerless-restart-observation",
                },
                "causal_views": transcript["state_causal_views"],
            },
            "record": {
                "publications": 2,
                "conflict_siblings": 2,
                "ordinary_publish_rejected_unchanged": True,
                "resolution_observes_all_siblings": True,
                "resolution_publisher_counter": 3,
                "resolved_and_restart_views": 4,
                "superseded_originals": 2,
            },
            "exact_noninserting_publication_retries": transcript["publication_retries"],
            "exact_noninserting_resolution_retries": transcript["resolution_retries"],
            "graceful_shutdowns": transcript["shutdowns"],
            "closed_retained_handles": transcript["closed_handles"],
            "bind_reacquisitions": transcript["bind_reacquisitions"],
        },
        "retention": evidence["retention"],
        "tools": tools,
        "limitations": LIMITATIONS,
        "nonclaims": NONCLAIMS,
    }


def receipt_forbidden_values(
    evidence: dict[str, Any], raw_root: Path, source: Path | None = None
) -> list[str]:
    values = set(evidence["terminal"]["_sensitive_values"])
    values.add(encoded_path(raw_root))
    if source is not None:
        values.add(encoded_path(source))
    return sorted(value for value in values if value)


def receipt_forbidden_pids(evidence: dict[str, Any]) -> list[int]:
    return list(evidence["terminal"]["_sensitive_pids"])


def receipt_forbidden_ports(evidence: dict[str, Any]) -> list[int]:
    return list(evidence["terminal"]["_sensitive_ports"])


def contains_exact_scalar(value: Any, forbidden_strings: set[str], forbidden_ints: set[int]) -> bool:
    if type(value) is int:
        return value in forbidden_ints
    if isinstance(value, str):
        return value in forbidden_strings
    if isinstance(value, list):
        return any(contains_exact_scalar(item, forbidden_strings, forbidden_ints) for item in value)
    if isinstance(value, dict):
        return any(
            contains_exact_scalar(item, forbidden_strings, forbidden_ints)
            for item in value.values()
        )
    return False


def render_receipt(
    document: dict[str, Any],
    *,
    forbidden_values: Iterable[str] = (),
    forbidden_pids: Iterable[int] = (),
    forbidden_ports: Iterable[int] = (),
) -> bytes:
    pid_values = set(forbidden_pids)
    if contains_exact_scalar(document, {str(pid) for pid in pid_values}, pid_values):
        fail("sanitized receipt contains an exact process identifier scalar")
    port_values = set(forbidden_ports)
    if contains_exact_scalar(document, {str(port) for port in port_values}, port_values):
        fail("sanitized receipt contains an exact network port scalar")
    encoded = canonical_json_bytes(document)
    if len(encoded) > RECEIPT_MAX_BYTES:
        fail("sanitized receipt exceeds the 16 KiB output cap")
    forbidden = (b"/private/", b"/Users/", b"127.0.0.1:", b'"pid"', b'"port"')
    if any(token in encoded for token in forbidden):
        fail("sanitized receipt contains a forbidden path, port, or process field")
    for value in forbidden_values:
        raw = value.encode("ascii", errors="strict")
        if raw and raw in encoded:
            fail("sanitized receipt contains a parsed identifier, path, port, or process value")
    return encoded


def read_supplied_receipt(path: Path) -> bytes:
    try:
        metadata = os.lstat(path)
    except OSError:
        fail("supplied receipt is missing or unreadable")
    if (
        not stat.S_ISREG(metadata.st_mode)
        or stat.S_ISLNK(metadata.st_mode)
        or metadata.st_nlink != 1
        or metadata.st_uid != os.getuid()
        or stat.S_IMODE(metadata.st_mode) not in {0o600, 0o644}
        or metadata.st_size > RECEIPT_MAX_BYTES
    ):
        fail("supplied receipt has unsafe metadata or exceeds its cap")
    flags = FILE_FLAGS
    try:
        descriptor = os.open(path, flags)
    except OSError:
        fail("supplied receipt could not be opened without following links")
    try:
        opened = os.fstat(descriptor)
        if stat_witness(opened) != stat_witness(metadata):
            fail("supplied receipt changed metadata while opening")
        data = os.read(descriptor, RECEIPT_MAX_BYTES + 1)
        if len(data) != opened.st_size:
            fail("supplied receipt changed size while reading")
        final_opened = os.fstat(descriptor)
        try:
            final_path = os.lstat(path)
        except OSError:
            fail("supplied receipt path disappeared while reading")
        if (
            stat_witness(final_opened) != stat_witness(opened)
            or stat_witness(final_path) != stat_witness(metadata)
        ):
            fail("supplied receipt changed metadata or path identity while reading")
        return data
    finally:
        os.close(descriptor)


def validate_supplied_receipt(data: bytes, expected: bytes) -> None:
    load_canonical_json(data, "supplied receipt", RECEIPT_MAX_BYTES)
    if data != expected:
        fail("supplied receipt differs byte-for-byte from the canonical projection")


def write_receipt(path: Path | None, data: bytes) -> None:
    if path is None:
        sys.stdout.buffer.write(data)
        return
    if path.name != RECEIPT_NAME:
        fail(f"receipt output must use the exact filename {RECEIPT_NAME}")
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    descriptor: int | None = None
    try:
        descriptor = os.open(path, flags, 0o600)
        os.fchmod(descriptor, 0o600)
        created = os.fstat(descriptor)
        if (
            not stat.S_ISREG(created.st_mode)
            or created.st_uid != os.getuid()
            or created.st_nlink != 1
            or stat.S_IMODE(created.st_mode) != 0o600
        ):
            fail("receipt output was not created as one owner-only regular file")
        written = 0
        while written < len(data):
            count = os.write(descriptor, data[written:])
            if count <= 0:
                fail("receipt output could not be completed")
            written += count
        os.fsync(descriptor)
        final_opened = os.fstat(descriptor)
        try:
            final_path = os.lstat(path)
        except OSError:
            fail("receipt output path disappeared while writing")
        if (
            (final_opened.st_dev, final_opened.st_ino)
            != (created.st_dev, created.st_ino)
            or final_opened.st_size != len(data)
            or stat.S_IMODE(final_opened.st_mode) != 0o600
            or stat_witness(final_path) != stat_witness(final_opened)
        ):
            fail("receipt output changed metadata or path identity while writing")
    except FileExistsError:
        fail("receipt output already exists; refusing to overwrite it")
    except OSError:
        fail("receipt output could not be created safely")
    finally:
        if descriptor is not None:
            os.close(descriptor)


def parse_args(arguments: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "receipt",
        nargs="?",
        default="-",
        help="existing receipt to validate byte-for-byte, or '-' to project",
    )
    parser.add_argument("--raw-root", required=True, type=Path, help="owner-only retained raw root")
    parser.add_argument("--source", required=True, type=Path, help="exact signed source checkout")
    parser.add_argument(
        "--output",
        type=Path,
        help=f"exclusive projected output named {RECEIPT_NAME}; projection defaults to stdout",
    )
    options = parser.parse_args(arguments)
    if options.receipt != "-" and options.output is not None:
        parser.error("--output cannot be combined with an existing receipt")
    return options


def main(arguments: list[str] | None = None) -> None:
    options = parse_args(arguments)
    try:
        raw_root = Path(os.path.abspath(os.fspath(options.raw_root)))
        source = Path(os.path.abspath(os.fspath(options.source)))
        source_authority = validate_source(source, raw_root)
        evidence = validate_raw_root(raw_root, source_authority)
        terminal_source_authority = validate_source(source, raw_root)
        if terminal_source_authority != source_authority:
            fail("signed source authority changed during raw evidence validation")
        encoded = render_receipt(
            build_receipt(source_authority, evidence),
            forbidden_values=receipt_forbidden_values(evidence, raw_root, source),
            forbidden_pids=receipt_forbidden_pids(evidence),
            forbidden_ports=receipt_forbidden_ports(evidence),
        )
        if options.receipt == "-":
            write_receipt(options.output, encoded)
        else:
            supplied = read_supplied_receipt(Path(options.receipt))
            validate_supplied_receipt(supplied, encoded)
    except ReceiptViolation as error:
        print(f"selected live mutable receipt validation failed: {error}", file=sys.stderr)
        raise SystemExit(1) from error


if __name__ == "__main__":
    main()
