#!/usr/bin/env python3
# Copyright 2026 Defense Unicorns, Inc.
# SPDX-License-Identifier: Apache-2.0
"""Project or validate one retained selected live Blob receipt.

The raw root is an owner-only, exact-inventory acceptance artifact.  This
validator reads only the public transcript, terminal captures, run metadata,
and copied release executable. Participant mission bundles, identity keys, redb
databases, depot owner markers, and encrypted chunk files are inspected by metadata only:
their contents are never opened, read, or hashed.

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


SCHEMA = "aster-selected-live-blob-receipt/v2"
RAW_SCHEMA = "aster-selected-live-blob-raw/v2"
TRANSCRIPT_SCHEMA = "aster-selected-live-blob-transcript/v2"
CLAIM = "selected-live-blob-one-host-direct-iroh-peerless-publish-seed-interrupt-reopen-different-peer-resume-read-restart-acceptance"
RECEIPT_NAME = "selected-live-blob-receipt.json"
RECEIPT_MAX_BYTES = 16 * 1024
RUN_JSON_MAX_BYTES = 64 * 1024
TRANSCRIPT_MAX_BYTES = 64 * 1024
STDOUT_MAX_BYTES = 8 * 1024 * 1024
STDERR_MAX_BYTES = 16 * 1024
BINARY_MAX_BYTES = 128 * 1024 * 1024
MISSION_MAX_BYTES = 1024 * 1024
STORE_MAX_BYTES = 1024 * 1024 * 1024
OWNER_MARKER_BYTES = 72
TRANSCRIPT_RECORDS = 81
PARTICIPANTS = ("publisher", "replica", "receiver")
OLD_RECEIPT_SOURCE_COMMIT = "036d068a8d055154beeffe265ceea8cf97079fa6"
OLD_RECEIPT_SHA256 = "484eafe504d958881dc7b871fbf788f733d9c8814e02fc27253ece38e6169735"

HEX_32 = re.compile(r"[0-9a-f]{64}\Z")
BLOB_OBJECT_ID = re.compile(r"02[0-9a-f]{64}\Z")
GIT_OBJECT = re.compile(r"[0-9a-f]{40}\Z")
RUN_ID = re.compile(r"[0-9a-f]{16}\Z")
FIELD_NAME = re.compile(r"[a-z][a-z0-9_]*\Z")
SIGNER_FINGERPRINT = re.compile(
    r"(?:[0-9A-F]{40,64}|SHA256:[A-Za-z0-9+/]{43})\Z"
)

PRODUCER_PATH = "crates/aster-node/examples/live_blob_acceptance.rs"
RUNNER_PATH = "tools/run-selected-live-blob.py"
CHECKER_PATH = "tools/check-selected-live-blob-receipt.py"
TEST_PATH = "tools/test-selected-live-blob-receipt.py"
ADMITTED_SOURCE_PATHS = tuple(
    sorted(
        (
            "Cargo.toml",
            "Cargo.lock",
            "mise.toml",
            "crates/aster-core/Cargo.toml",
            "crates/aster-core/src/blob.rs",
            "crates/aster-core/src/source_blob.rs",
            "crates/aster-core/src/store.rs",
            "crates/aster-core/src/crypto/reference.rs",
            "crates/aster-redb-store/Cargo.toml",
            "crates/aster-redb-store/src/blob.rs",
            "crates/aster-redb-store/src/blob/depot.rs",
            "crates/aster-redb-store/src/lib.rs",
            "crates/aster-node/Cargo.toml",
            "crates/aster-node/src/application.rs",
            "crates/aster-node/src/application/blob.rs",
            "crates/aster-node/src/frame.rs",
            "crates/aster-node/src/lib.rs",
            "crates/aster-node/src/runtime.rs",
            PRODUCER_PATH,
            RUNNER_PATH,
            CHECKER_PATH,
            TEST_PATH,
        )
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
    "live_blob_acceptance",
]

EXPECTED_BASE_DIRECTORIES = {
    "",
    "binary",
    "participants",
    "participants/publisher",
    "participants/publisher/state",
    "participants/publisher/state/blob-depot-v1",
    "participants/replica",
    "participants/replica/state",
    "participants/replica/state/blob-depot-v1",
    "participants/receiver",
    "participants/receiver/state",
    "participants/receiver/state/blob-depot-v1",
}
EXPECTED_BASE_FILES = {
    "run.json": 0o600,
    "stdout.log": 0o600,
    "stderr.log": 0o600,
    "transcript.tsv": 0o600,
    "binary/aster-live-blob-acceptance": 0o700,
    "participants/publisher/mission.bundle": 0o600,
    "participants/publisher/state/identity.key": 0o600,
    "participants/publisher/state/mesh.redb": 0o600,
    "participants/publisher/state/blob-depot-v1/.aster-store-owner-v1": 0o600,
    "participants/replica/mission.bundle": 0o600,
    "participants/replica/state/identity.key": 0o600,
    "participants/replica/state/mesh.redb": 0o600,
    "participants/replica/state/blob-depot-v1/.aster-store-owner-v1": 0o600,
    "participants/receiver/mission.bundle": 0o600,
    "participants/receiver/state/identity.key": 0o600,
    "participants/receiver/state/mesh.redb": 0o600,
    "participants/receiver/state/blob-depot-v1/.aster-store-owner-v1": 0o600,
}
VARIANT_DIRECTORY = re.compile(r"[0-9a-f]{64}\Z")
CHUNK_FILE = re.compile(r"0000000000000000000([01])[.]chunk\Z")

RUN_KEYS = (
    "schema",
    "claim",
    "participants",
    "actor_lifetimes",
    "maximum_concurrent_actors",
    "topic",
    "scope",
    "payload_len",
    "payload_sha256",
    "page_limit",
    "expected_pages",
)
PARTICIPANT_KEYS = (
    "participant",
    "carrier_id",
    "mission_id",
    "mission_authority",
)
PEER_BINDING_KEYS = (
    "phase",
    "local",
    "remote",
    "local_carrier",
    "local_mission",
    "expected_carrier_peer",
    "expected_mission_peer",
)
PHASE_KEYS = ("sequence", "phase", "actors", "outcome")
HANDLE_KEYS = (
    "phase",
    "participant",
    "blob_identity",
    "blob_authority",
)
PUBLICATION_KEYS = (
    "phase",
    "participant",
    "id",
    "publisher",
    "counter",
    "priority",
    "total_len",
    "media_type",
    "schema_id_sha256",
    "acceptance_marker",
    "inserted",
    "payload_sha256",
)
RETRY_KEYS = (
    "phase",
    "participant",
    "original_id",
    "retry_id",
    "publisher",
    "counter",
    "priority",
    "total_len",
    "media_type",
    "schema_id_sha256",
    "acceptance_marker",
    "inserted",
    "exact_match",
)
CONFLICT_KEYS = (
    "phase",
    "participant",
    "original_id",
    "original_payload_sha256",
    "changed_payload_sha256",
    "error_kind",
    "operation",
    "publication_preserved",
)
PAGE_KEYS = (
    "phase",
    "participant",
    "page_index",
    "id",
    "publisher",
    "counter",
    "priority",
    "total_len",
    "media_type",
    "schema_id_sha256",
    "acceptance_marker",
    "offset",
    "max_bytes",
    "page_len",
    "next_offset",
    "complete",
    "page_sha256",
)
READ_KEYS = (
    "phase",
    "participant",
    "id",
    "publisher",
    "counter",
    "priority",
    "total_len",
    "media_type",
    "schema_id_sha256",
    "acceptance_marker",
    "pages",
    "max_page_bytes",
    "payload_sha256",
)
SHUTDOWN_KEYS = (
    "phase",
    "participant",
    "contacts",
    "contact_errors",
    "direct_contacts",
    "relay_contacts",
    "unknown_path_contacts",
    "carrier_path_transitions",
    "carrier_path_transition_saturations",
    "events",
    "event_acceptance_markers",
    "route_cached_events",
    "controls",
    "applied_controls",
    "pending_controls",
    "control_highwater",
    "data_offered",
    "data_fetched",
    "data_inserted",
    "data_duplicates",
    "data_remaining",
    "mutable_remaining",
    "deferred_mutable_lanes",
    "blob_ranges_fetched",
    "blob_bytes_fetched",
    "blob_remaining",
    "blob_deferred",
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
)
CLOSED_HANDLE_KEYS = ("phase", "participant", "error_kind", "operation")
SOURCE_REMOVED_KEYS = (
    "source",
    "participant",
    "status",
    "bytes",
    "sha256",
)
READ_UNAVAILABLE_KEYS = (
    "phase",
    "participant",
    "error_kind",
    "operation",
    "public",
)
PROGRESS_KEYS = (
    "phase",
    "participant",
    "source_transfer_id",
    "id",
    "staging_sha256",
    "public_blobs",
    "pending_sources",
    "carrier_count",
    "progressed_carriers",
    "carrier_prefixes",
    "prefix_bytes",
    "prefix_object_id",
    "prefix_carrier_index",
    "prefix_len",
    "prefix_total_len",
    "total_carrier_bytes",
    "remaining_bytes",
    "remaining_ranges",
    "next_object_id",
    "next_carrier_index",
    "next_offset",
    "next_end",
    "network_staging_bytes",
    "committed_chunks",
    "committed_file_bytes",
    "reserved_file_bytes",
    "public",
)
PERSISTENCE_KEYS = (
    "phase",
    "participant",
    "source_transfer_id",
    "staging_before_sha256",
    "staging_after_sha256",
    "prefix_before",
    "prefix_after",
    "prefix_object_id",
    "prefix_total_len",
    "exact_match",
    "public",
)
SEED_KEYS = (
    "phase",
    "source",
    "replica",
    "status",
    "data_fetched",
    "blob_ranges_fetched",
    "blob_bytes_fetched",
    "public_blobs",
)
RESUME_KEYS = (
    "phase",
    "source",
    "receiver",
    "original_source",
    "source_transfer_id",
    "different_peer",
    "source_refetched",
    "exact_complement",
    "contacts",
    "data_fetched",
    "blob_ranges_fetched",
    "blob_bytes_fetched",
    "prefix_before",
    "prefix_after",
    "prefix_object_id",
    "prefix_total_len",
    "remaining_before",
    "remaining_after",
    "public",
)
FINISH_KEYS = (
    "phase",
    "source",
    "receiver",
    "source_refetched",
    "data_fetched",
    "blob_ranges_fetched",
    "blob_bytes_fetched",
    "reconstructed_transfer_bytes",
    "seed_transfer_bytes",
    "promoted",
)
COMPLETED_PROGRESS_KEYS = (
    "phase",
    "participant",
    "source_transfer_id",
    "id",
    "public_blobs",
    "pending_sources",
    "carrier_prefixes",
    "network_staging_bytes",
    "public",
)
BIND_KEYS = ("participant", "status")
RESULT_KEYS = (
    "status",
    "secret_values_emitted",
    "payload_representation",
    "records",
    "phases",
    "actor_lifetimes",
    "maximum_concurrent_actors",
    "graceful_shutdowns",
    "retained_handles",
    "closed_handles",
    "bind_reacquisitions",
    "source_files_removed",
    "source_removed",
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
CONTACT_BLOB_FIELDS = (
    "blob_ranges_fetched",
    "blob_bytes_fetched",
    "blob_remaining",
    "blob_deferred",
)
CONTACT_DATA_FIELDS = {
    "data_offered": "offered",
    "data_fetched": "fetched",
    "data_inserted": "inserted",
    "data_duplicates": "duplicates",
    "data_remaining": "remaining",
    "mutable_remaining": "mutable_remaining",
    "deferred_mutable_lanes": "deferred_mutable_lanes",
}
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
    "deferred_mutable_lanes",
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
LOOPBACK_SOCKET = re.compile(r"127[.]0[.]0[.]1:([1-9][0-9]{0,4})\Z")

EXPECTED_SEQUENCE: tuple[tuple[str, tuple[str, ...]], ...] = (
    ("RUN", RUN_KEYS),
    ("PARTICIPANT", PARTICIPANT_KEYS),
    ("PARTICIPANT", PARTICIPANT_KEYS),
    ("PARTICIPANT", PARTICIPANT_KEYS),
    ("PEER_BINDING", PEER_BINDING_KEYS),
    ("PEER_BINDING", PEER_BINDING_KEYS),
    ("PEER_BINDING", PEER_BINDING_KEYS),
    ("PEER_BINDING", PEER_BINDING_KEYS),
    ("PEER_BINDING", PEER_BINDING_KEYS),
    ("PEER_BINDING", PEER_BINDING_KEYS),
    ("PHASE", PHASE_KEYS),
    ("HANDLE", HANDLE_KEYS),
    ("BLOB_PUBLICATION", PUBLICATION_KEYS),
    ("BLOB_RETRY", RETRY_KEYS),
    ("BLOB_CONFLICT", CONFLICT_KEYS),
    ("PAGE", PAGE_KEYS),
    ("PAGE", PAGE_KEYS),
    ("READ", READ_KEYS),
    ("SHUTDOWN", SHUTDOWN_KEYS),
    ("CLOSED_HANDLE", CLOSED_HANDLE_KEYS),
    ("SOURCE_REMOVED", SOURCE_REMOVED_KEYS),
    ("SOURCE_REMOVED", SOURCE_REMOVED_KEYS),
    ("PHASE", PHASE_KEYS),
    ("HANDLE", HANDLE_KEYS),
    ("HANDLE", HANDLE_KEYS),
    ("PAGE", PAGE_KEYS),
    ("PAGE", PAGE_KEYS),
    ("READ", READ_KEYS),
    ("SHUTDOWN", SHUTDOWN_KEYS),
    ("SHUTDOWN", SHUTDOWN_KEYS),
    ("CLOSED_HANDLE", CLOSED_HANDLE_KEYS),
    ("CLOSED_HANDLE", CLOSED_HANDLE_KEYS),
    ("SEED", SEED_KEYS),
    ("PHASE", PHASE_KEYS),
    ("HANDLE", HANDLE_KEYS),
    ("HANDLE", HANDLE_KEYS),
    ("READ_UNAVAILABLE", READ_UNAVAILABLE_KEYS),
    ("SHUTDOWN", SHUTDOWN_KEYS),
    ("SHUTDOWN", SHUTDOWN_KEYS),
    ("CLOSED_HANDLE", CLOSED_HANDLE_KEYS),
    ("CLOSED_HANDLE", CLOSED_HANDLE_KEYS),
    ("PROGRESS", PROGRESS_KEYS),
    ("PHASE", PHASE_KEYS),
    ("HANDLE", HANDLE_KEYS),
    ("READ_UNAVAILABLE", READ_UNAVAILABLE_KEYS),
    ("SHUTDOWN", SHUTDOWN_KEYS),
    ("CLOSED_HANDLE", CLOSED_HANDLE_KEYS),
    ("PROGRESS", PROGRESS_KEYS),
    ("PERSISTENCE", PERSISTENCE_KEYS),
    ("PHASE", PHASE_KEYS),
    ("HANDLE", HANDLE_KEYS),
    ("HANDLE", HANDLE_KEYS),
    ("SHUTDOWN", SHUTDOWN_KEYS),
    ("SHUTDOWN", SHUTDOWN_KEYS),
    ("CLOSED_HANDLE", CLOSED_HANDLE_KEYS),
    ("CLOSED_HANDLE", CLOSED_HANDLE_KEYS),
    ("PROGRESS", PROGRESS_KEYS),
    ("RESUME", RESUME_KEYS),
    ("PHASE", PHASE_KEYS),
    ("HANDLE", HANDLE_KEYS),
    ("HANDLE", HANDLE_KEYS),
    ("PAGE", PAGE_KEYS),
    ("PAGE", PAGE_KEYS),
    ("READ", READ_KEYS),
    ("SHUTDOWN", SHUTDOWN_KEYS),
    ("SHUTDOWN", SHUTDOWN_KEYS),
    ("CLOSED_HANDLE", CLOSED_HANDLE_KEYS),
    ("CLOSED_HANDLE", CLOSED_HANDLE_KEYS),
    ("FINISH", FINISH_KEYS),
    ("COMPLETED_PROGRESS", COMPLETED_PROGRESS_KEYS),
    ("PHASE", PHASE_KEYS),
    ("HANDLE", HANDLE_KEYS),
    ("PAGE", PAGE_KEYS),
    ("PAGE", PAGE_KEYS),
    ("READ", READ_KEYS),
    ("SHUTDOWN", SHUTDOWN_KEYS),
    ("CLOSED_HANDLE", CLOSED_HANDLE_KEYS),
    ("BIND_REACQUIRED", BIND_KEYS),
    ("BIND_REACQUIRED", BIND_KEYS),
    ("BIND_REACQUIRED", BIND_KEYS),
    ("RESULT", RESULT_KEYS),
)

PAYLOAD_LEN = 96 * 1024
PAGE_LIMIT = 65_536
CHUNK_FILE_OVERHEAD = 169
COMMITTED_CIPHERTEXT_BYTES = PAYLOAD_LEN + 2 * CHUNK_FILE_OVERHEAD
PAYLOAD_SHA256 = "8609fd29a7c72634fe10beaab26ab44441a97abf85fa428cba0898c69e1ed524"
CHANGED_PAYLOAD_SHA256 = "db24aedc940e3af4d8b49a44db5d486c3c6773213153e6f17e8d72151c196b82"
SCHEMA_ID_SHA256 = "ff1499ba5c4448784c8b5f1137ddcc0dd85dad9e51204b9236b3759e6b9d8826"
PAGE_FACTS = (
    (0, 0, 65_536, 65_536, "false", "1047ab624c89856e2a3c2dea5cea7a299c2d0ba0a9bcbf1cb951a6d54927239a"),
    (1, 65_536, 32_768, 98_304, "true", "256acbd5fca30ff42275d172630103a1f6f087426ead5881fe07e2a7fef2974f"),
)
MEDIA_TYPE = "application/x-aster-live-blob-acceptance"

# The participant authorities, redb stores, depot owner markers, and encrypted
# chunk files are deliberately metadata-only.  They must never be opened,
# read, or hashed by this projector.
LIMITATIONS = [
    "operator-attested-source-binary-execution-link-not-cryptographically-proven",
    "selected-admitted-source-list-is-not-a-complete-reproducible-build-closure",
    "one-host-loopback-same-implementation-observation",
    "participant-secret-and-ciphertext-artifacts-validated-by-metadata-only",
    "interruption-and-restart-are-graceful-same-process-actor-store-and-provider-reopen",
    "intermediate-store-inspection-transcript-timing-and-source-removal-order-are-producer-attested",
]
NONCLAIMS = [
    "distinct-physical-hosts",
    "nat-or-internet-path",
    "controlled-or-public-relay",
    "btle-carrier",
    "independent-implementation-interoperability",
    "scale-beyond-three-participants",
    "resource-thresholds-or-long-duration-soak",
    "event-state-or-record-live-application-acceptance",
    "reproducible-build-or-cryptographic-source-to-execution-provenance",
    "process-crash-or-power-loss-recovery",
    "physical-source-media-sanitization-or-secure-erasure",
    "long-offline-recovery",
    "arbitrary-peer-or-route-only-blob-resume",
    "blob-subscription-status-ttl-or-garbage-collection",
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


def validate_inventory(root_descriptor: int) -> dict[str, Any]:
    observed_directories: set[str] = set()
    directory_metadata: dict[str, os.stat_result] = {}
    observed_files: dict[str, os.stat_result] = {}
    identities: list[tuple[int, int]] = []
    variants: dict[str, str] = {}

    def admitted_directory(relative: str) -> bool:
        if relative in EXPECTED_BASE_DIRECTORIES:
            return True
        parent, separator, name = relative.rpartition("/")
        if (
            separator
            and parent
            in {
                "participants/publisher/state/blob-depot-v1",
                "participants/replica/state/blob-depot-v1",
                "participants/receiver/state/blob-depot-v1",
            }
            and VARIANT_DIRECTORY.fullmatch(name) is not None
        ):
            participant = parent.split("/")[1]
            if participant in variants:
                fail(f"{participant} depot contains more than one variant directory")
            variants[participant] = name
            return True
        return False

    def expected_file_mode(relative: str) -> int | None:
        fixed = EXPECTED_BASE_FILES.get(relative)
        if fixed is not None:
            return fixed
        path = PurePosixPath(relative)
        if (
            len(path.parts) == 6
            and path.parts[0] == "participants"
            and path.parts[1] in set(PARTICIPANTS)
            and path.parts[2:4] == ("state", "blob-depot-v1")
            and VARIANT_DIRECTORY.fullmatch(path.parts[4]) is not None
            and CHUNK_FILE.fullmatch(path.parts[5]) is not None
        ):
            return 0o600
        return None

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
                if not admitted_directory(child_relative):
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
                expected_mode = expected_file_mode(child_relative)
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
    if set(variants) != set(PARTICIPANTS) or len(set(variants.values())) != 1:
        fail("participant depots do not contain one matching canonical variant directory each")
    expected_directories = EXPECTED_BASE_DIRECTORIES | {
        f"participants/{participant}/state/blob-depot-v1/{variants[participant]}"
        for participant in PARTICIPANTS
    }
    expected_files = set(EXPECTED_BASE_FILES)
    for participant in PARTICIPANTS:
        expected_files.update(
            f"participants/{participant}/state/blob-depot-v1/{variants[participant]}/{index:020}.chunk"
            for index in range(2)
        )
    if observed_directories != expected_directories:
        fail("raw inventory has missing or extra directories")
    if set(observed_files) != expected_files:
        fail("raw inventory has missing or extra files")
    if len(set(identities)) != len(identities):
        fail("raw inventory contains aliased directory or file identities")

    chunk_totals: dict[str, int] = {}
    for participant in PARTICIPANTS:
        mission = observed_files[f"participants/{participant}/mission.bundle"]
        identity = observed_files[f"participants/{participant}/state/identity.key"]
        store = observed_files[f"participants/{participant}/state/mesh.redb"]
        marker = observed_files[
            f"participants/{participant}/state/blob-depot-v1/.aster-store-owner-v1"
        ]
        if not 0 < mission.st_size <= MISSION_MAX_BYTES:
            fail(f"{participant} mission artifact violates its metadata-only size bound")
        if not 0 < identity.st_size <= STORE_MAX_BYTES:
            fail(f"{participant} identity key violates its metadata-only size bound")
        if not 0 < store.st_size <= STORE_MAX_BYTES:
            fail(f"{participant} mesh database violates its metadata-only size bound")
        if marker.st_size != OWNER_MARKER_BYTES:
            fail(f"{participant} depot owner marker has the wrong metadata-only byte count")
        chunks = [
            observed_files[
                f"participants/{participant}/state/blob-depot-v1/"
                f"{variants[participant]}/{index:020}.chunk"
            ]
            for index in range(2)
        ]
        for index, (chunk, page) in enumerate(zip(chunks, PAGE_FACTS, strict=True)):
            expected_size = page[2] + CHUNK_FILE_OVERHEAD
            if chunk.st_size != expected_size:
                fail(
                    f"{participant} ciphertext chunk {index} has the wrong "
                    "metadata-only byte count"
                )
        chunk_totals[participant] = sum(chunk.st_size for chunk in chunks)
    return {
        "directories": directory_metadata,
        "files": observed_files,
        "variants": variants,
        "chunk_totals": chunk_totals,
    }
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
    if len(parts) != len(expected_keys) + 2 or parts[:2] != ["LIVE_BLOB", expected_type]:
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


def require_object_id(value: str, label: str) -> str:
    if BLOB_OBJECT_ID.fullmatch(value) is None:
        fail(f"{label} is not one canonical 33-byte Blob object identifier")
    return value


def require_fixed(record: dict[str, str], expected: dict[str, str], label: str) -> None:
    for key, value in expected.items():
        if record[key] != value:
            fail(f"{label}.{key} differs from its exact value")


def sorted_pair(first: str, second: str) -> str:
    return ",".join(sorted((first, second)))


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
            "participants": "3",
            "actor_lifetimes": "11",
            "maximum_concurrent_actors": "2",
            "topic": "opaque",
            "scope": "test/runtime-contact",
            "payload_len": str(PAYLOAD_LEN),
            "payload_sha256": PAYLOAD_SHA256,
            "page_limit": str(PAGE_LIMIT),
            "expected_pages": "2",
        },
        "RUN",
    )

    participants: dict[str, dict[str, str]] = {}
    for index, expected_name in zip(range(1, 4), PARTICIPANTS, strict=True):
        record = records[index]
        require_fixed(record, {"participant": expected_name}, f"PARTICIPANT {expected_name}")
        for field in ("carrier_id", "mission_id", "mission_authority"):
            require_id(record[field], f"PARTICIPANT {expected_name}.{field}")
        participants[expected_name] = record
    identity_domain = {
        record[field]
        for record in participants.values()
        for field in ("carrier_id", "mission_id")
    }
    if len(identity_domain) != 6:
        fail("participant carrier and mission identity domains overlap")
    authorities = {record["mission_authority"] for record in participants.values()}
    if len(authorities) != 1:
        fail("participants do not share exactly one mission authority")
    mission_authority = next(iter(authorities))
    if mission_authority in identity_domain:
        fail("mission authority overlaps a carrier or participant identity")

    binding_expectations = (
        (4, "seed_replica", "publisher", "replica"),
        (5, "seed_replica", "replica", "publisher"),
        (6, "partial_from_publisher", "publisher", "receiver"),
        (7, "partial_from_publisher", "receiver", "publisher"),
        (8, "resume_from_replica", "replica", "receiver"),
        (9, "resume_from_replica", "receiver", "replica"),
    )
    peer_bindings: dict[tuple[str, str], dict[str, str]] = {}
    for index, phase, local, remote in binding_expectations:
        record = records[index]
        require_fixed(
            record,
            {
                "phase": phase,
                "local": local,
                "remote": remote,
                "local_carrier": participants[local]["carrier_id"],
                "local_mission": participants[local]["mission_id"],
                "expected_carrier_peer": participants[remote]["carrier_id"],
                "expected_mission_peer": participants[remote]["mission_id"],
            },
            f"PEER_BINDING {phase} {local} {remote}",
        )
        if local == remote or (local, remote) in peer_bindings:
            fail("peer binding graph contains a self-edge or duplicate edge")
        peer_bindings[(local, remote)] = record
    expected_edges = {
        (local, remote)
        for local in PARTICIPANTS
        for remote in PARTICIPANTS
        if local != remote
    }
    if set(peer_bindings) != expected_edges:
        fail("peer binding graph is not the complete directed three-participant graph")
    for local, remote in peer_bindings:
        if (remote, local) not in peer_bindings:
            fail("peer binding graph is not reciprocal")

    phase_expectations = (
        (10, 1, "peerless_publish", "publisher", "published-and-read"),
        (22, 2, "seed_replica", "publisher+replica", "completed"),
        (33, 3, "partial_from_publisher", "publisher+receiver", "one-contact-interrupted"),
        (42, 4, "partial_receiver_reopen", "receiver", "pending-unchanged"),
        (49, 5, "resume_from_replica", "replica+receiver", "one-contact-resumed"),
        (58, 6, "finish_from_replica", "replica+receiver", "completed"),
        (70, 7, "final_receiver_reopen", "receiver", "completed-read"),
    )
    for index, sequence, phase, actors, outcome in phase_expectations:
        require_fixed(
            records[index],
            {
                "sequence": str(sequence),
                "phase": phase,
                "actors": actors,
                "outcome": outcome,
            },
            f"PHASE {sequence}",
        )

    handle_expectations = (
        (11, "peerless_publish", "publisher"),
        (23, "seed_replica", "publisher"),
        (24, "seed_replica", "replica"),
        (34, "partial_from_publisher", "publisher"),
        (35, "partial_from_publisher", "receiver"),
        (43, "partial_receiver_reopen", "receiver"),
        (50, "resume_from_replica", "replica"),
        (51, "resume_from_replica", "receiver"),
        (59, "finish_from_replica", "replica"),
        (60, "finish_from_replica", "receiver"),
        (71, "final_receiver_reopen", "receiver"),
    )
    for index, phase, participant in handle_expectations:
        require_fixed(
            records[index],
            {
                "phase": phase,
                "participant": participant,
                "blob_identity": participants[participant]["mission_id"],
                "blob_authority": mission_authority,
            },
            f"HANDLE {phase} {participant}",
        )

    publication = records[12]
    require_fixed(
        publication,
        {
            "phase": "peerless_publish",
            "participant": "publisher",
            "publisher": participants["publisher"]["mission_id"],
            "counter": "1",
            "priority": "priority",
            "total_len": str(PAYLOAD_LEN),
            "media_type": MEDIA_TYPE,
            "schema_id_sha256": SCHEMA_ID_SHA256,
            "acceptance_marker": "1",
            "inserted": "true",
            "payload_sha256": PAYLOAD_SHA256,
        },
        "BLOB_PUBLICATION",
    )
    blob_id = require_id(publication["id"], "BLOB_PUBLICATION.id")
    require_fixed(
        records[13],
        {
            "phase": "peerless_publish",
            "participant": "publisher",
            "original_id": blob_id,
            "retry_id": blob_id,
            "publisher": publication["publisher"],
            "counter": publication["counter"],
            "priority": publication["priority"],
            "total_len": publication["total_len"],
            "media_type": publication["media_type"],
            "schema_id_sha256": publication["schema_id_sha256"],
            "acceptance_marker": publication["acceptance_marker"],
            "inserted": "false",
            "exact_match": "true",
        },
        "BLOB_RETRY",
    )
    require_fixed(
        records[14],
        {
            "phase": "peerless_publish",
            "participant": "publisher",
            "original_id": blob_id,
            "original_payload_sha256": PAYLOAD_SHA256,
            "changed_payload_sha256": CHANGED_PAYLOAD_SHA256,
            "error_kind": "conflict",
            "operation": "blob_publish",
            "publication_preserved": "true",
        },
        "BLOB_CONFLICT",
    )
    selected_metadata = {
        "id": blob_id,
        "publisher": publication["publisher"],
        "counter": publication["counter"],
        "priority": publication["priority"],
        "total_len": publication["total_len"],
        "media_type": publication["media_type"],
        "schema_id_sha256": publication["schema_id_sha256"],
        "acceptance_marker": publication["acceptance_marker"],
    }

    def validate_pages(first_index: int, phase: str, participant: str) -> None:
        for page_offset, expected_page in enumerate(PAGE_FACTS):
            page_index, offset, page_len, next_offset, complete, page_hash = expected_page
            require_fixed(
                records[first_index + page_offset],
                {
                    "phase": phase,
                    "participant": participant,
                    "page_index": str(page_index),
                    **selected_metadata,
                    "offset": str(offset),
                    "max_bytes": str(PAGE_LIMIT),
                    "page_len": str(page_len),
                    "next_offset": str(next_offset),
                    "complete": complete,
                    "page_sha256": page_hash,
                },
                f"PAGE {phase} {participant} {page_index}",
            )

    def validate_read(index: int, phase: str, participant: str) -> None:
        require_fixed(
            records[index],
            {
                "phase": phase,
                "participant": participant,
                **selected_metadata,
                "pages": "2",
                "max_page_bytes": str(PAGE_LIMIT),
                "payload_sha256": PAYLOAD_SHA256,
            },
            f"READ {phase} {participant}",
        )

    for first_page, read_index, phase, participant in (
        (15, 17, "peerless_publish", "publisher"),
        (25, 27, "seed_replica", "replica"),
        (61, 63, "finish_from_replica", "receiver"),
        (72, 74, "final_receiver_reopen", "receiver"),
    ):
        validate_pages(first_page, phase, participant)
        validate_read(read_index, phase, participant)
    for index, phase in (
        (36, "partial_from_publisher"),
        (44, "partial_receiver_reopen"),
    ):
        require_fixed(
            records[index],
            {
                "phase": phase,
                "participant": "receiver",
                "error_kind": "unauthorized_or_revoked",
                "operation": "blob_read_page",
                "public": "false",
            },
            f"READ_UNAVAILABLE {phase}",
        )

    for index, source, digest in (
        (20, "original", PAYLOAD_SHA256),
        (21, "conflict-probe", CHANGED_PAYLOAD_SHA256),
    ):
        require_fixed(
            records[index],
            {
                "source": source,
                "participant": "publisher",
                "status": "removed-and-parent-synced",
                "bytes": str(PAYLOAD_LEN),
                "sha256": digest,
            },
            f"SOURCE_REMOVED {source}",
        )

    shutdown_expectations = (
        (18, "peerless_publish", "publisher"),
        (28, "seed_replica", "publisher"),
        (29, "seed_replica", "replica"),
        (37, "partial_from_publisher", "publisher"),
        (38, "partial_from_publisher", "receiver"),
        (45, "partial_receiver_reopen", "receiver"),
        (52, "resume_from_replica", "replica"),
        (53, "resume_from_replica", "receiver"),
        (64, "finish_from_replica", "replica"),
        (65, "finish_from_replica", "receiver"),
        (75, "final_receiver_reopen", "receiver"),
    )
    peerless_phases = {
        "peerless_publish",
        "partial_receiver_reopen",
        "final_receiver_reopen",
    }
    pending_lifetimes = {
        ("partial_from_publisher", "receiver"),
        ("partial_receiver_reopen", "receiver"),
        ("resume_from_replica", "receiver"),
    }
    receiving_lifetimes = {
        ("seed_replica", "replica"): (1, 1, None),
        ("partial_from_publisher", "receiver"): (1, 1, 1),
        ("resume_from_replica", "receiver"): (0, 0, 1),
        ("finish_from_replica", "receiver"): (0, 0, None),
    }
    numeric_fields = SHUTDOWN_KEYS[2:]
    shutdowns: dict[str, dict[str, str]] = {}
    shutdown_numbers: dict[str, dict[str, int]] = {}
    for index, phase, participant in shutdown_expectations:
        record = records[index]
        label = f"SHUTDOWN {phase} {participant}"
        require_fixed(record, {"phase": phase, "participant": participant}, label)
        numbers = {
            field: parse_uint(record[field], f"{label}.{field}")
            for field in numeric_fields
        }
        for field in (
            "events",
            "event_acceptance_markers",
            "route_cached_events",
            "controls",
            "applied_controls",
            "pending_controls",
            "control_highwater",
            "data_remaining",
            "deferred_mutable_lanes",
            "contact_errors",
            "relay_contacts",
            "unknown_path_contacts",
            "carrier_path_transitions",
            "carrier_path_transition_saturations",
            "blob_deferred",
        ):
            if numbers[field] != 0:
                fail(f"{label}.{field} is a nonzero excluded counter")
        if phase in peerless_phases:
            for field in (
                "contacts",
                "direct_contacts",
                "data_offered",
                "data_fetched",
                "data_inserted",
                "data_duplicates",
                "mutable_remaining",
                "blob_ranges_fetched",
                "blob_bytes_fetched",
                "blob_remaining",
                "blob_carrier_fetch_cursors",
            ):
                if numbers[field] != 0:
                    fail(f"{label}.{field} is nonzero in a peerless lifetime")
        else:
            if numbers["contacts"] == 0 or numbers["direct_contacts"] != numbers["contacts"]:
                fail(f"{label} does not prove positive direct-only contact")
            if phase in {"partial_from_publisher", "resume_from_replica"} and numbers["contacts"] != 1:
                fail(f"{label} is not the exact one-contact interrupted phase")

        if (phase, participant) in pending_lifetimes:
            for field in (
                "blobs",
                "blob_acceptance_markers",
                "blob_last_acceptance_marker",
                "blob_sealed_bytes",
                "blob_operations",
                "blob_operation_bytes",
                "blob_finalized_variants",
            ):
                if numbers[field] != 0:
                    fail(f"{label}.{field} exposes an incomplete Blob")
            if (
                numbers["pending_blobs"] != 1
                or numbers["blob_carrier_prefixes"] < 1
                or numbers["blob_network_staging_bytes"] == 0
            ):
                fail(f"{label} does not retain one bounded nonpublic Blob prefix")
        else:
            expected_operations = 1 if participant == "publisher" else 0
            if (
                numbers["blobs"] != 1
                or numbers["blob_acceptance_markers"] != 1
                or numbers["blob_last_acceptance_marker"] != 1
                or numbers["blob_sealed_bytes"] == 0
                or numbers["blob_operations"] != expected_operations
                or (
                    (expected_operations == 1 and numbers["blob_operation_bytes"] == 0)
                    or (expected_operations == 0 and numbers["blob_operation_bytes"] != 0)
                )
                or numbers["blob_variants"] != 1
                or numbers["blob_finalized_variants"] != 1
                or numbers["blob_committed_chunks"] != 2
                or numbers["blob_committed_file_bytes"] != COMMITTED_CIPHERTEXT_BYTES
                or numbers["blob_reserved_file_bytes"] != COMMITTED_CIPHERTEXT_BYTES
                or numbers["pending_blobs"] != 0
                or numbers["blob_carrier_prefixes"] != 0
                or numbers["blob_network_staging_bytes"] != 0
            ):
                fail(f"{label} does not retain the exact completed Blob shape")

        receiver_shape = receiving_lifetimes.get((phase, participant))
        if receiver_shape is not None:
            fetched, inserted, exact_ranges = receiver_shape
            if (
                numbers["data_offered"] != 0
                or numbers["data_fetched"] != fetched
                or numbers["data_inserted"] != inserted
                or numbers["data_duplicates"] != 0
                or numbers["mutable_remaining"] == 0
                or numbers["blob_ranges_fetched"] == 0
                or numbers["blob_bytes_fetched"] == 0
                or (exact_ranges is not None and numbers["blob_ranges_fetched"] != exact_ranges)
                or numbers["blob_carrier_fetch_cursors"] > 1
            ):
                fail(f"{label} does not match exact receiving-side Blob accounting")
            if phase in {"partial_from_publisher", "resume_from_replica"} and numbers[
                "blob_remaining"
            ] == 0:
                fail(f"{label} does not prove bounded work remained after interruption")
        elif phase not in peerless_phases:
            if (
                numbers["data_offered"] == 0
                or numbers["data_fetched"] != 0
                or numbers["data_inserted"] != 0
                or numbers["data_duplicates"] != 0
                or numbers["mutable_remaining"] != 0
                or numbers["blob_ranges_fetched"] != 0
                or numbers["blob_bytes_fetched"] != 0
                or numbers["blob_remaining"] != 0
            ):
                fail(f"{label} does not match exact serving-side Blob accounting")
        key = f"{phase}:{participant}"
        shutdowns[key] = record
        shutdown_numbers[key] = numbers

    for phase, first, second in (
        ("seed_replica", "publisher", "replica"),
        ("partial_from_publisher", "publisher", "receiver"),
        ("resume_from_replica", "replica", "receiver"),
        ("finish_from_replica", "replica", "receiver"),
    ):
        if shutdown_numbers[f"{phase}:{first}"]["contacts"] != shutdown_numbers[f"{phase}:{second}"]["contacts"]:
            fail(f"{phase} participants report different contact counts")

    physical_fields = (
        "blobs",
        "blob_acceptance_markers",
        "blob_last_acceptance_marker",
        "blob_sealed_bytes",
        "blob_variants",
        "blob_finalized_variants",
        "blob_committed_chunks",
        "blob_committed_file_bytes",
        "blob_reserved_file_bytes",
        "pending_blobs",
        "blob_carrier_prefixes",
        "blob_network_staging_bytes",
    )
    completed_keys = (
        "peerless_publish:publisher",
        "seed_replica:publisher",
        "seed_replica:replica",
        "partial_from_publisher:publisher",
        "resume_from_replica:replica",
        "finish_from_replica:replica",
        "finish_from_replica:receiver",
        "final_receiver_reopen:receiver",
    )
    completed_baseline = shutdown_numbers[completed_keys[0]]
    for key in completed_keys[1:]:
        for field in physical_fields:
            if shutdown_numbers[key][field] != completed_baseline[field]:
                fail(f"completed Blob durable field {field} differs at {key}")
    for key in ("peerless_publish:publisher", "seed_replica:publisher", "partial_from_publisher:publisher"):
        if (
            shutdown_numbers[key]["blob_operations"] != completed_baseline["blob_operations"]
            or shutdown_numbers[key]["blob_operation_bytes"] != completed_baseline["blob_operation_bytes"]
        ):
            fail(f"publisher operation accounting changed at {key}")
    for key in ("seed_replica:replica", "resume_from_replica:replica", "finish_from_replica:replica"):
        for field in physical_fields:
            if shutdown_numbers[key][field] != shutdown_numbers["seed_replica:replica"][field]:
                fail(f"replica durable field {field} changed at {key}")
    for field in physical_fields:
        if shutdown_numbers["final_receiver_reopen:receiver"][field] != shutdown_numbers["finish_from_replica:receiver"][field]:
            fail(f"receiver durable field {field} changed after final reopen")

    for index, phase, participant in (
        (19, "peerless_publish", "publisher"),
        (30, "seed_replica", "publisher"),
        (31, "seed_replica", "replica"),
        (39, "partial_from_publisher", "publisher"),
        (40, "partial_from_publisher", "receiver"),
        (46, "partial_receiver_reopen", "receiver"),
        (54, "resume_from_replica", "replica"),
        (55, "resume_from_replica", "receiver"),
        (66, "finish_from_replica", "replica"),
        (67, "finish_from_replica", "receiver"),
        (76, "final_receiver_reopen", "receiver"),
    ):
        require_fixed(
            records[index],
            {
                "phase": phase,
                "participant": participant,
                "error_kind": "state_unavailable",
                "operation": "blob_read_page",
            },
            f"CLOSED_HANDLE {phase} {participant}",
        )

    def validate_progress(index: int, phase: str) -> tuple[dict[str, str], dict[str, int]]:
        record = records[index]
        label = f"PROGRESS {phase}"
        require_fixed(
            record,
            {"phase": phase, "participant": "receiver", "id": blob_id, "public": "false"},
            label,
        )
        for field in ("source_transfer_id", "staging_sha256"):
            require_id(record[field], f"{label}.{field}")
        for field in ("prefix_object_id", "next_object_id"):
            require_object_id(record[field], f"{label}.{field}")
        numeric_names = (
            "public_blobs",
            "pending_sources",
            "carrier_count",
            "progressed_carriers",
            "carrier_prefixes",
            "prefix_bytes",
            "prefix_carrier_index",
            "prefix_len",
            "prefix_total_len",
            "total_carrier_bytes",
            "remaining_bytes",
            "remaining_ranges",
            "next_carrier_index",
            "next_offset",
            "next_end",
            "network_staging_bytes",
            "committed_chunks",
            "committed_file_bytes",
            "reserved_file_bytes",
        )
        numbers = {
            field: parse_uint(record[field], f"{label}.{field}")
            for field in numeric_names
        }
        if (
            numbers["public_blobs"] != 0
            or numbers["pending_sources"] != 1
            or numbers["carrier_count"] != 2
            or numbers["progressed_carriers"] != 1
            or numbers["carrier_prefixes"] != numbers["progressed_carriers"]
            or numbers["prefix_bytes"] == 0
            or numbers["prefix_bytes"] != numbers["prefix_len"]
            or numbers["prefix_carrier_index"] != numbers["next_carrier_index"]
            or record["prefix_object_id"] != record["next_object_id"]
            or numbers["prefix_len"] != numbers["next_offset"]
            or numbers["prefix_len"] >= numbers["prefix_total_len"]
            or numbers["remaining_bytes"] == 0
            or numbers["remaining_ranges"] == 0
            or numbers["prefix_bytes"] + numbers["remaining_bytes"] != numbers["total_carrier_bytes"]
            or numbers["next_end"] <= numbers["next_offset"]
            or numbers["next_end"] > numbers["prefix_total_len"]
            or numbers["next_end"] - numbers["next_offset"] > 16 * 1024
            or numbers["network_staging_bytes"] == 0
            or numbers["committed_chunks"] > 2
            or numbers["committed_file_bytes"] > numbers["reserved_file_bytes"]
            or numbers["reserved_file_bytes"] > COMMITTED_CIPHERTEXT_BYTES
        ):
            fail(f"{label} does not describe one bounded incomplete durable prefix")
        return record, numbers

    partial_progress, partial_numbers = validate_progress(41, "partial_from_publisher")
    reopen_progress, reopen_numbers = validate_progress(47, "partial_receiver_reopen")
    resume_progress, resume_numbers = validate_progress(56, "resume_from_replica")
    source_transfer_id = partial_progress["source_transfer_id"]
    if source_transfer_id == blob_id:
        fail("Blob transfer identity aliases the application Blob identity")
    if {partial_progress["source_transfer_id"], reopen_progress["source_transfer_id"], resume_progress["source_transfer_id"]} != {source_transfer_id}:
        fail("pending progress records cross Blob transfer identities")
    if partial_progress != {
        **reopen_progress,
        "phase": "partial_from_publisher",
    }:
        fail("pending Blob progress changed across peerless reopen")
    partial_shutdown = shutdown_numbers["partial_from_publisher:receiver"]
    reopen_shutdown = shutdown_numbers["partial_receiver_reopen:receiver"]
    resume_shutdown = shutdown_numbers["resume_from_replica:receiver"]
    for progress_numbers, shutdown in (
        (partial_numbers, partial_shutdown),
        (reopen_numbers, reopen_shutdown),
        (resume_numbers, resume_shutdown),
    ):
        for progress_field, shutdown_field in (
            ("public_blobs", "blobs"),
            ("pending_sources", "pending_blobs"),
            ("carrier_prefixes", "blob_carrier_prefixes"),
            ("network_staging_bytes", "blob_network_staging_bytes"),
            ("committed_chunks", "blob_committed_chunks"),
            ("committed_file_bytes", "blob_committed_file_bytes"),
            ("reserved_file_bytes", "blob_reserved_file_bytes"),
        ):
            if progress_numbers[progress_field] != shutdown[shutdown_field]:
                fail(f"PROGRESS.{progress_field} differs from exact SHUTDOWN.{shutdown_field}")
    if partial_numbers["prefix_bytes"] != partial_shutdown["blob_bytes_fetched"]:
        fail("partial durable prefix differs from newly accepted partial bytes")
    if (
        resume_numbers["carrier_count"] != reopen_numbers["carrier_count"]
        or resume_numbers["total_carrier_bytes"] != reopen_numbers["total_carrier_bytes"]
        or resume_progress["prefix_object_id"] != reopen_progress["prefix_object_id"]
        or resume_numbers["prefix_carrier_index"] != reopen_numbers["prefix_carrier_index"]
        or resume_numbers["prefix_total_len"] != reopen_numbers["prefix_total_len"]
        or resume_numbers["prefix_bytes"] != reopen_numbers["prefix_bytes"] + resume_shutdown["blob_bytes_fetched"]
        or reopen_numbers["remaining_bytes"] != resume_numbers["remaining_bytes"] + resume_shutdown["blob_bytes_fetched"]
        or reopen_numbers["remaining_ranges"] != resume_numbers["remaining_ranges"] + resume_shutdown["blob_ranges_fetched"]
        or resume_progress["staging_sha256"] == reopen_progress["staging_sha256"]
        or reopen_numbers["next_end"] - reopen_numbers["next_offset"] != resume_shutdown["blob_bytes_fetched"]
    ):
        fail("different peer did not advance the exact inspected durable complement")
    seed_receiver = shutdown_numbers["seed_replica:replica"]
    if partial_numbers["total_carrier_bytes"] != seed_receiver["blob_bytes_fetched"]:
        fail("pending carrier total differs from the completed seed transfer")

    require_fixed(
        records[32],
        {
            "phase": "seed_replica",
            "source": "publisher",
            "replica": "replica",
            "status": "completed",
            "data_fetched": str(seed_receiver["data_fetched"]),
            "blob_ranges_fetched": str(seed_receiver["blob_ranges_fetched"]),
            "blob_bytes_fetched": str(seed_receiver["blob_bytes_fetched"]),
            "public_blobs": str(seed_receiver["blobs"]),
        },
        "SEED",
    )
    require_fixed(
        records[48],
        {
            "phase": "partial_receiver_reopen",
            "participant": "receiver",
            "source_transfer_id": source_transfer_id,
            "staging_before_sha256": partial_progress["staging_sha256"],
            "staging_after_sha256": reopen_progress["staging_sha256"],
            "prefix_before": partial_progress["prefix_bytes"],
            "prefix_after": reopen_progress["prefix_bytes"],
            "prefix_object_id": reopen_progress["prefix_object_id"],
            "prefix_total_len": reopen_progress["prefix_total_len"],
            "exact_match": "true",
            "public": "false",
        },
        "PERSISTENCE",
    )
    require_fixed(
        records[57],
        {
            "phase": "resume_from_replica",
            "source": "replica",
            "receiver": "receiver",
            "original_source": "publisher",
            "source_transfer_id": source_transfer_id,
            "different_peer": "true",
            "source_refetched": "false",
            "exact_complement": "true",
            "contacts": str(resume_shutdown["contacts"]),
            "data_fetched": str(resume_shutdown["data_fetched"]),
            "blob_ranges_fetched": str(resume_shutdown["blob_ranges_fetched"]),
            "blob_bytes_fetched": str(resume_shutdown["blob_bytes_fetched"]),
            "prefix_before": reopen_progress["prefix_bytes"],
            "prefix_after": resume_progress["prefix_bytes"],
            "prefix_object_id": resume_progress["prefix_object_id"],
            "prefix_total_len": resume_progress["prefix_total_len"],
            "remaining_before": reopen_progress["remaining_bytes"],
            "remaining_after": resume_progress["remaining_bytes"],
            "public": "false",
        },
        "RESUME",
    )
    finish_receiver = shutdown_numbers["finish_from_replica:receiver"]
    reconstructed_bytes = (
        partial_shutdown["blob_bytes_fetched"]
        + resume_shutdown["blob_bytes_fetched"]
        + finish_receiver["blob_bytes_fetched"]
    )
    if (
        finish_receiver["blob_bytes_fetched"] != resume_numbers["remaining_bytes"]
        or finish_receiver["blob_ranges_fetched"] != resume_numbers["remaining_ranges"]
        or reconstructed_bytes != seed_receiver["blob_bytes_fetched"]
    ):
        fail("finish phase does not reconstruct the exact seeded transfer bytes and ranges")
    require_fixed(
        records[68],
        {
            "phase": "finish_from_replica",
            "source": "replica",
            "receiver": "receiver",
            "source_refetched": "false",
            "data_fetched": str(finish_receiver["data_fetched"]),
            "blob_ranges_fetched": str(finish_receiver["blob_ranges_fetched"]),
            "blob_bytes_fetched": str(finish_receiver["blob_bytes_fetched"]),
            "reconstructed_transfer_bytes": str(reconstructed_bytes),
            "seed_transfer_bytes": str(seed_receiver["blob_bytes_fetched"]),
            "promoted": "true",
        },
        "FINISH",
    )
    completed = records[69]
    require_fixed(
        completed,
        {
            "phase": "finish_from_replica",
            "participant": "receiver",
            "source_transfer_id": source_transfer_id,
            "id": blob_id,
            "public_blobs": "1",
            "pending_sources": "0",
            "carrier_prefixes": "0",
            "network_staging_bytes": "0",
            "public": "true",
        },
        "COMPLETED_PROGRESS",
    )

    for index, participant in zip((77, 78, 79), PARTICIPANTS, strict=True):
        require_fixed(
            records[index],
            {"participant": participant, "status": "reacquired"},
            f"BIND_REACQUIRED {participant}",
        )
    require_fixed(
        records[80],
        {
            "status": "pass",
            "secret_values_emitted": "false",
            "payload_representation": "sha256_only",
            "records": "81",
            "phases": "7",
            "actor_lifetimes": "11",
            "maximum_concurrent_actors": "2",
            "graceful_shutdowns": "11",
            "retained_handles": "11",
            "closed_handles": "11",
            "bind_reacquisitions": "3",
            "source_files_removed": "2",
            "source_removed": "true",
        },
        "RESULT",
    )

    connected_contacts = sum(
        shutdown_numbers[f"{phase}:{participant}"]["contacts"]
        for phase, participant in (
            ("seed_replica", "publisher"),
            ("seed_replica", "replica"),
            ("partial_from_publisher", "publisher"),
            ("partial_from_publisher", "receiver"),
            ("resume_from_replica", "replica"),
            ("resume_from_replica", "receiver"),
            ("finish_from_replica", "replica"),
            ("finish_from_replica", "receiver"),
        )
    )
    sensitive_progress = {
        source_transfer_id,
        *(record["staging_sha256"] for record in (partial_progress, reopen_progress, resume_progress)),
        *(record["prefix_object_id"] for record in (partial_progress, reopen_progress, resume_progress)),
        *(record["next_object_id"] for record in (partial_progress, reopen_progress, resume_progress)),
    }
    return {
        "records": TRANSCRIPT_RECORDS,
        "bytes": len(data),
        "sha256": sha256_bytes(data),
        "participants": 3,
        "phases": 7,
        "actor_lifetimes": 11,
        "maximum_concurrent_actors": 2,
        "connected_contacts": connected_contacts,
        "blob_publications": 1,
        "publication_retries": 1,
        "publication_conflicts": 1,
        "page_reads": 8,
        "whole_reads": 4,
        "unavailable_reads": 2,
        "shutdowns": 11,
        "closed_handles": 11,
        "bind_reacquisitions": 3,
        "source_files_removed": 2,
        "source_removed": True,
        "seed_transfer_bytes": seed_receiver["blob_bytes_fetched"],
        "partial_bytes": partial_shutdown["blob_bytes_fetched"],
        "resume_bytes": resume_shutdown["blob_bytes_fetched"],
        "finish_bytes": finish_receiver["blob_bytes_fetched"],
        "partial_prefix_bytes": partial_numbers["prefix_bytes"],
        "resume_prefix_bytes": resume_numbers["prefix_bytes"],
        "_participants": participants,
        "_peer_bindings": peer_bindings,
        "_shutdowns": shutdowns,
        "_shutdown_numbers": shutdown_numbers,
        "_progress": {
            "partial": partial_progress,
            "reopen": reopen_progress,
            "resume": resume_progress,
            "completed": completed,
        },
        "_application_ids": sorted({blob_id, *sensitive_progress}),
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
        if line.startswith("LIVE_BLOB\t")
    )
    if extracted != transcript:
        fail("transcript is not the exact ordered LIVE_BLOB extraction from stdout")

    participants: dict[str, dict[str, str]] = transcript_facts["_participants"]
    peer_bindings: dict[tuple[str, str], dict[str, str]] = transcript_facts["_peer_bindings"]
    shutdowns: dict[str, dict[str, str]] = transcript_facts["_shutdowns"]
    by_carrier = {record["carrier_id"]: name for name, record in participants.items()}
    by_mission = {record["mission_id"]: name for name, record in participants.items()}
    ordered_phases = (
        "peerless_publish",
        "seed_replica",
        "partial_from_publisher",
        "partial_receiver_reopen",
        "resume_from_replica",
        "finish_from_replica",
        "final_receiver_reopen",
    )
    phase_actors = {
        "peerless_publish": ("publisher",),
        "seed_replica": ("publisher", "replica"),
        "partial_from_publisher": ("publisher", "receiver"),
        "partial_receiver_reopen": ("receiver",),
        "resume_from_replica": ("replica", "receiver"),
        "finish_from_replica": ("replica", "receiver"),
        "final_receiver_reopen": ("receiver",),
    }
    phase_order = {
        "publisher": ("peerless_publish", "seed_replica", "partial_from_publisher"),
        "replica": ("seed_replica", "resume_from_replica", "finish_from_replica"),
        "receiver": (
            "partial_from_publisher",
            "partial_receiver_reopen",
            "resume_from_replica",
            "finish_from_replica",
            "final_receiver_reopen",
        ),
    }
    connected_phases = {
        phase for phase, actors in phase_actors.items() if len(actors) == 2
    }
    ready_count = {participant: 0 for participant in participants}
    stop_count = {participant: 0 for participant in participants}
    active: dict[str, str] = {}
    finished: set[tuple[str, str]] = set()
    contact_count: dict[tuple[str, str], int] = {}
    aggregate_fields = {
        **CONTACT_DATA_FIELDS,
        **{field: field for field in CONTACT_BLOB_FIELDS},
    }
    contact_totals: dict[tuple[str, str], dict[str, int]] = {}
    phase_contact_totals: dict[str, dict[str, dict[str, int]]] = {}
    connected_socket_by_participant: dict[str, str] = {}
    pids: set[int] = set()
    sockets: set[str] = set()
    ports: set[int] = set()
    ready_records = 0
    contact_records = 0
    stop_records = 0

    contact_numeric_fields = (
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
        "carrier_path_transitions",
    )

    for line_number, line in enumerate(lines, start=1):
        label = f"captured stdout line {line_number}"
        if line.startswith("LIVE_BLOB\t"):
            continue
        if line.startswith("READY "):
            record = parse_terminal_record(line, "READY", READY_KEYS, label)
            carrier_participant = by_carrier.get(record["carrier_id"])
            mission_participant = by_mission.get(record["mission_id"])
            if carrier_participant is None or carrier_participant != mission_participant:
                fail(f"{label} does not bind one transcript participant")
            participant = carrier_participant
            if participant in active or ready_count[participant] >= len(phase_order[participant]):
                fail(f"{label} starts an overlapping or extra participant lifetime")
            phase = phase_order[participant][ready_count[participant]]
            phase_index = ordered_phases.index(phase)
            for prior in ordered_phases[:phase_index]:
                if any((prior, actor) not in finished for actor in phase_actors[prior]):
                    fail(f"{label} starts {phase} before {prior} completed")
            if any(active_phase != phase for active_phase in active.values()):
                fail(f"{label} overlaps another acceptance phase")
            if participant not in phase_actors[phase]:
                fail(f"{label} participant is not admitted in {phase}")
            expected = participants[participant]
            require_fixed(
                record,
                {
                    "selected": "true",
                    "carrier_id": expected["carrier_id"],
                    "mission_id": expected["mission_id"],
                    "mission_authority": expected["mission_authority"],
                    "state": encoded_path(root / "participants" / participant / "state"),
                    "peers": "1" if phase in connected_phases else "0",
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
            socket = record["sockets"]
            sockets.add(socket)
            ports.add(int(socket_match.group(1)))
            if phase in connected_phases:
                prior_socket = connected_socket_by_participant.get(participant)
                if prior_socket is None:
                    if socket in connected_socket_by_participant.values():
                        fail(f"{label}.sockets aliases another connected participant bind")
                    connected_socket_by_participant[participant] = socket
                elif socket != prior_socket:
                    fail(f"{label}.sockets changed across connected actor lifetimes")
            active[participant] = phase
            contact_count[(phase, participant)] = 0
            contact_totals[(phase, participant)] = {
                transcript_field: 0 for transcript_field in aggregate_fields
            }
            ready_count[participant] += 1
            ready_records += 1
            continue

        if line.startswith("CONTACT "):
            record = parse_terminal_record(line, "CONTACT", CONTACT_KEYS, label)
            remote_by_carrier = by_carrier.get(record["carrier_peer"])
            remote_by_mission = by_mission.get(record["mission_peer"])
            if remote_by_carrier is None or remote_by_carrier != remote_by_mission:
                fail(f"{label} does not bind one expected peer")
            remote = remote_by_carrier
            candidates = [
                local
                for local, phase in active.items()
                if local != remote
                and active.get(remote) == phase
                and phase in connected_phases
                and set((local, remote)) == set(phase_actors[phase])
            ]
            if len(candidates) != 1:
                fail(f"{label} occurs outside one exact active paired phase")
            local = candidates[0]
            phase = active[local]
            if (local, remote) not in peer_bindings:
                fail(f"{label} uses an unbound directed peer edge")
            require_fixed(
                record,
                {
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
            numeric = {
                field: parse_uint(
                    record[field], f"{label}.{field}", positive=field == "rounds"
                )
                for field in contact_numeric_fields
            }
            for field in CONTACT_EXCLUDED_ZERO_FIELDS:
                if numeric[field] != 0:
                    fail(f"{label}.{field} is a nonzero excluded counter")
            expected_status = (
                "partial"
                if numeric["mutable_remaining"] or numeric["blob_remaining"]
                else "pass"
            )
            if record["status"] != expected_status:
                fail(f"{label}.status differs from the exact remaining-work state")
            for field in (
                "handshake_frames",
                "handshake_bytes",
                "protected_frames",
                "protected_bytes",
            ):
                if numeric[field] == 0:
                    fail(f"{label} has no authenticated or protected protocol traffic")
            lifetime = (phase, local)
            for transcript_field, contact_field in aggregate_fields.items():
                contact_totals[lifetime][transcript_field] += numeric[contact_field]
            contact_count[lifetime] += 1
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
            if phase is None or phase != phase_order[participant][stop_count[participant]]:
                fail(f"{label} closes an absent or misordered participant lifetime")
            transcript_shutdown = shutdowns[f"{phase}:{participant}"]
            require_fixed(
                record,
                {
                    "lifecycle": "complete",
                    "sync_status": (
                        "contacts_observed"
                        if phase in connected_phases
                        else "no_successful_contact"
                    ),
                    "carrier_id": participants[participant]["carrier_id"],
                    "mission_id": participants[participant]["mission_id"],
                    "path_observation": "not-authorization",
                    "mission_auth": "hybrid-pq",
                    "provisioning": "unprotected-reference",
                    "semantics": "source-authenticated-event",
                    "reconciliation_classes": "event,state,record,blob-v5",
                    "controls_semantics": "source-authenticated-flash",
                },
                label,
            )
            transcript_to_stop = {
                "contacts": "contacts",
                "contact_errors": "contact_errors",
                "direct_contacts": "direct_contacts",
                "relay_contacts": "relay_contacts",
                "unknown_path_contacts": "unknown_path_contacts",
                "carrier_path_transitions": "carrier_path_transitions",
                "carrier_path_transition_saturations": "carrier_path_transition_saturations",
                "events": "events",
                "event_acceptance_markers": "event_acceptance_markers",
                "route_cached_events": "route_cached_events",
                "controls": "controls",
                "applied_controls": "applied_controls",
                "pending_controls": "pending_controls",
                "control_highwater": "control_highwater",
                "blob_ranges_fetched": "blob_ranges_fetched",
                "blob_bytes_fetched": "blob_bytes_fetched",
                "blob_remaining": "blob_remaining",
                "blob_deferred": "blob_deferred",
                "blobs": "blobs",
                "blob_acceptance_markers": "blob_acceptance_markers",
                "blob_last_acceptance_marker": "blob_last_acceptance_marker",
                "blob_sealed_bytes": "blob_sealed_bytes",
                "blob_operations": "blob_operations",
                "blob_operation_bytes": "blob_operation_bytes",
                "blob_variants": "blob_variants",
                "blob_finalized_variants": "blob_finalized_variants",
                "blob_committed_chunks": "blob_committed_chunks",
                "blob_committed_file_bytes": "blob_committed_file_bytes",
                "blob_reserved_file_bytes": "blob_reserved_file_bytes",
                "pending_blobs": "pending_blobs",
                "blob_carrier_prefixes": "blob_carrier_prefixes",
                "blob_carrier_fetch_cursors": "blob_carrier_fetch_cursors",
                "blob_network_staging_bytes": "blob_network_staging_bytes",
            }
            for transcript_field, stop_field in transcript_to_stop.items():
                parse_uint(record[stop_field], f"{label}.{stop_field}")
                if record[stop_field] != transcript_shutdown[transcript_field]:
                    fail(f"{label}.{stop_field} differs from the exact SHUTDOWN cross-link")
            lifetime = (phase, participant)
            expected_contacts = parse_uint(
                transcript_shutdown["contacts"], f"{label}.contacts"
            )
            if contact_count[lifetime] != expected_contacts:
                fail(f"{label} contact count differs from parsed CONTACT records")
            for transcript_field in aggregate_fields:
                expected = parse_uint(
                    transcript_shutdown[transcript_field],
                    f"SHUTDOWN {phase} {participant}.{transcript_field}",
                )
                if contact_totals[lifetime][transcript_field] != expected:
                    fail(
                        f"{label} CONTACT aggregate differs from SHUTDOWN.{transcript_field}"
                    )
            phase_contact_totals.setdefault(phase, {})[participant] = dict(
                contact_totals[lifetime]
            )
            del active[participant]
            finished.add(lifetime)
            stop_count[participant] += 1
            stop_records += 1
            continue

        fail(f"{label} belongs to an unadmitted terminal record family")

    if active:
        fail("captured stdout ends with active actor lifetimes")
    for participant in PARTICIPANTS:
        if (
            ready_count[participant] != len(phase_order[participant])
            or stop_count[participant] != len(phase_order[participant])
        ):
            fail(f"captured stdout omits or adds a {participant} actor lifetime")
    if ready_records != 11 or stop_records != 11:
        fail("captured stdout does not contain exactly eleven READY and STOP records")
    if len(connected_socket_by_participant) != 3 or len(set(connected_socket_by_participant.values())) != 3:
        fail("captured stdout does not bind three stable distinct connected sockets")
    if len(pids) != 1:
        fail("captured stdout does not bind all actor receipts to one producer process")
    if contact_records != transcript_facts["connected_contacts"] or contact_records < 8:
        fail("captured stdout CONTACT records differ from exact SHUTDOWN accounting")
    for phase in connected_phases:
        first, second = phase_actors[phase]
        first_contacts = parse_uint(shutdowns[f"{phase}:{first}"]["contacts"], f"{phase} contacts")
        second_contacts = parse_uint(shutdowns[f"{phase}:{second}"]["contacts"], f"{phase} contacts")
        if first_contacts != second_contacts:
            fail(f"{phase} CONTACT records are not paired")
        if phase in {"partial_from_publisher", "resume_from_replica"} and first_contacts != 1:
            fail(f"{phase} does not contain exactly one reciprocal CONTACT pair")

    reconciliation: dict[str, Any] = {}
    for phase in (
        "seed_replica",
        "partial_from_publisher",
        "resume_from_replica",
        "finish_from_replica",
    ):
        roles: dict[str, Any] = {}
        for participant in phase_actors[phase]:
            shutdown = transcript_facts["_shutdown_numbers"][f"{phase}:{participant}"]
            roles[participant] = {
                "contacts": shutdown["contacts"],
                "data_offered": shutdown["data_offered"],
                "data_fetched": shutdown["data_fetched"],
                "data_inserted": shutdown["data_inserted"],
                "blob_ranges_fetched": shutdown["blob_ranges_fetched"],
                "blob_bytes_fetched": shutdown["blob_bytes_fetched"],
                "blob_remaining": shutdown["blob_remaining"],
            }
        reconciliation[phase] = roles
    return {
        "lines": len(lines),
        "bytes": len(stdout),
        "sha256": sha256_bytes(stdout),
        "ready_records": ready_records,
        "contact_records": contact_records,
        "stop_records": stop_records,
        "processes": 1,
        "reconciliation": {
            "phases": reconciliation,
            "partial_and_resume_contact_pairs": "exactly-one-each",
            "contact_shutdown_data_and_blob_aggregation": "exact",
            "direct_only": True,
            "terminal_event_state_record_control_counts": "all-zero",
        },
        "identifiers_paths_ports_pids": "parsed-cross-bound-excluded",
        "_sensitive_values": sorted(
            {
                *(
                    record[field]
                    for record in participants.values()
                    for field in ("carrier_id", "mission_id", "mission_authority")
                ),
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
    expected_binary = os.fspath(root / "binary" / "aster-live-blob-acceptance")
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
            path="binary/aster-live-blob-acceptance",
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
            "binary/aster-live-blob-acceptance",
            "copied release executable",
            BINARY_MAX_BYTES,
        )
        public_metadata = {
            "run.json": run_metadata,
            "stdout.log": stdout_metadata,
            "stderr.log": stderr_metadata,
            "transcript.tsv": transcript_metadata,
            "binary/aster-live-blob-acceptance": binary_metadata,
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
        for participant, phases in {
            "publisher": (
                "peerless_publish",
                "seed_replica",
                "partial_from_publisher",
            ),
            "replica": (
                "seed_replica",
                "resume_from_replica",
                "finish_from_replica",
            ),
            "receiver": ("finish_from_replica", "final_receiver_reopen"),
        }.items():
            expected_total = inventory["chunk_totals"][participant]
            for phase in phases:
                shutdown_total = parse_uint(
                    transcript_facts["_shutdowns"][f"{phase}:{participant}"][
                        "blob_committed_file_bytes"
                    ],
                    f"SHUTDOWN {phase} {participant}.blob_committed_file_bytes",
                )
                if shutdown_total != expected_total:
                    fail(
                        f"{participant} depot ciphertext metadata does not cross-bind "
                        f"SHUTDOWN {phase} committed bytes"
                    )
        terminal_facts = validate_terminal_stdout(stdout, transcript, root, transcript_facts)
        terminal_facts["_sensitive_values"].extend(inventory["variants"].values())
        terminal_facts["_sensitive_values"] = sorted(
            set(terminal_facts["_sensitive_values"])
        )
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
            "binary/aster-live-blob-acceptance": read_public_file(
                root_descriptor,
                "binary/aster-live-blob-acceptance",
                "terminal copied release executable",
                BINARY_MAX_BYTES,
            )[0],
        }
        initial_public = {
            "run.json": run_data,
            "stdout.log": stdout,
            "stderr.log": stderr,
            "transcript.tsv": transcript,
            "binary/aster-live-blob-acceptance": binary,
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
                "directories": len(EXPECTED_BASE_DIRECTORIES) + 3,
                "files": len(EXPECTED_BASE_FILES) + 6,
                "participant_directories": 3,
                "mission_artifacts": 3,
                "identity_keys": 3,
                "mesh_databases": 3,
                "depot_owner_markers": 3,
                "blob_variants": 3,
                "ciphertext_chunks": 6,
                "chunks_per_participant": 2,
                "ciphertext_bytes_per_participant": COMMITTED_CIPHERTEXT_BYTES,
                "secret_and_ciphertext_contents": "metadata-only-not-opened-read-or-hashed",
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
    shutdowns = transcript["_shutdown_numbers"]
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
    seed = shutdowns["seed_replica:replica"]
    partial = shutdowns["partial_from_publisher:receiver"]
    resume = shutdowns["resume_from_replica:receiver"]
    finish = shutdowns["finish_from_replica:receiver"]
    return {
        "schema": SCHEMA,
        "status": "pass",
        "claim": CLAIM,
        "supersedes": {
            "schema": "aster-selected-live-blob-receipt/v1",
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
            "argv_redacted": [
                "<raw-root>/binary/aster-live-blob-acceptance",
                "<raw-root>",
            ],
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
            "participants": 3,
            "phases": 7,
            "actor_lifetimes": 11,
            "maximum_concurrent_actors": 2,
            "distinct_carrier_ids": 3,
            "distinct_mission_ids": 3,
            "common_disjoint_mission_authority": True,
            "directed_expected_peer_bindings": 6,
            "complete_reciprocal_peer_binding_graph": "verified",
            "live_handle_identity_binding": "verified",
            "runtime_ready_stop_identity_binding": "verified",
            "phase_barriers": "verified-exact",
            "blob": {
                "publications": transcript["blob_publications"],
                "payload": {
                    "bytes": PAYLOAD_LEN,
                    "sha256": PAYLOAD_SHA256,
                    "media_type": MEDIA_TYPE,
                    "schema_id_sha256": SCHEMA_ID_SHA256,
                    "priority": "priority",
                    "counter": 1,
                    "acceptance_marker": 1,
                },
                "pages": [
                    {
                        "index": page[0],
                        "offset": page[1],
                        "bytes": page[2],
                        "next_offset": page[3],
                        "complete": page[4] == "true",
                        "sha256": page[5],
                    }
                    for page in PAGE_FACTS
                ],
                "page_limit": PAGE_LIMIT,
                "exact_page_reads": transcript["page_reads"],
                "whole_reads": transcript["whole_reads"],
                "typed_unavailable_reads": transcript["unavailable_reads"],
                "read_phases": [
                    "peerless_publish:publisher",
                    "seed_replica:replica",
                    "finish_from_replica:receiver",
                    "final_receiver_reopen:receiver",
                ],
                "unavailable_read_phases": [
                    "partial_from_publisher:receiver",
                    "partial_receiver_reopen:receiver",
                ],
                "exact_noninserting_retries": transcript["publication_retries"],
                "changed_payload_conflicts": transcript["publication_conflicts"],
                "conflict_preserves_publication": True,
                "source_files_removed_and_parent_synced": transcript[
                    "source_files_removed"
                ],
            },
            "interrupted_resume": {
                "seed_replica": {
                    "source": "publisher",
                    "receiver": "replica",
                    "data_fetched": seed["data_fetched"],
                    "ranges": seed["blob_ranges_fetched"],
                    "bytes": seed["blob_bytes_fetched"],
                    "completed": True,
                },
                "partial_from_publisher": {
                    "contacts": partial["contacts"],
                    "source": "publisher",
                    "receiver": "receiver",
                    "data_fetched": partial["data_fetched"],
                    "ranges": partial["blob_ranges_fetched"],
                    "bytes": partial["blob_bytes_fetched"],
                    "prefix_bytes": transcript["partial_prefix_bytes"],
                    "public": False,
                },
                "partial_receiver_reopen": {
                    "contacts": 0,
                    "prefix_unchanged": True,
                    "public": False,
                },
                "resume_from_replica": {
                    "contacts": resume["contacts"],
                    "source": "replica",
                    "receiver": "receiver",
                    "different_peer": True,
                    "source_refetched": False,
                    "data_fetched": resume["data_fetched"],
                    "ranges": resume["blob_ranges_fetched"],
                    "bytes": resume["blob_bytes_fetched"],
                    "prefix_before": transcript["partial_prefix_bytes"],
                    "prefix_after": transcript["resume_prefix_bytes"],
                    "exact_complement": True,
                    "public": False,
                },
                "finish_from_replica": {
                    "source_refetched": False,
                    "data_fetched": finish["data_fetched"],
                    "ranges": finish["blob_ranges_fetched"],
                    "bytes": finish["blob_bytes_fetched"],
                    "reconstructed_bytes": (
                        transcript["partial_bytes"]
                        + transcript["resume_bytes"]
                        + transcript["finish_bytes"]
                    ),
                    "seed_bytes": transcript["seed_transfer_bytes"],
                    "promoted": True,
                },
                "progress_persistence": "typed-store-inspection-and-exact-contact-accounting",
            },
            "connected_path": "positive-direct-only-zero-errors",
            "connected_contact_records": transcript["connected_contacts"],
            "connected_reconciliation": terminal["reconciliation"],
            "durable_shape": {
                "publications": 1,
                "acceptance_markers": 1,
                "last_acceptance_marker": 1,
                "variants": 1,
                "finalized_variants": 1,
                "committed_chunks": 2,
                "committed_file_bytes": COMMITTED_CIPHERTEXT_BYTES,
                "reserved_file_bytes": COMMITTED_CIPHERTEXT_BYTES,
            },
            "peerless_phase_contacts": "exact-zero",
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
        print("selected live Blob receipt validation failed", file=sys.stderr)
        raise SystemExit(1) from error


if __name__ == "__main__":
    main()
