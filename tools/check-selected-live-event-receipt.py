#!/usr/bin/env python3
# Copyright 2026 Defense Unicorns, Inc.
# SPDX-License-Identifier: Apache-2.0
"""Project or validate one retained selected live Event acceptance receipt.

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


SCHEMA = "aster-selected-live-event-receipt/v2"
RAW_SCHEMA = "aster-selected-live-event-raw/v2"
TRANSCRIPT_SCHEMA = "aster-selected-live-event-transcript/v2"
CLAIM = (
    "selected-live-event-one-host-direct-iroh-priority-withheld-authenticated-gap-"
    "forced-receiver-process-termination-durable-redelivery-gap-closure-acceptance"
)
RECEIPT_NAME = "selected-live-event-receipt.json"
RECEIPT_MAX_BYTES = 16 * 1024
RUN_JSON_MAX_BYTES = 64 * 1024
TRANSCRIPT_MAX_BYTES = 64 * 1024
STDOUT_MAX_BYTES = 8 * 1024 * 1024
STDERR_MAX_BYTES = 16 * 1024
BINARY_MAX_BYTES = 128 * 1024 * 1024
MISSION_MAX_BYTES = 1024 * 1024
STORE_MAX_BYTES = 1024 * 1024 * 1024
IDENTITY_BYTES = 32
TRANSCRIPT_RECORDS = 79
RUN_TIMEOUT_SECONDS = 180

HEX_32 = re.compile(r"[0-9a-f]{64}\Z")
GIT_OBJECT = re.compile(r"[0-9a-f]{40}\Z")
RUN_ID = re.compile(r"[0-9a-f]{16}\Z")
FIELD_NAME = re.compile(r"[a-z][a-z0-9_]*\Z")
SIGNER_FINGERPRINT = re.compile(
    r"(?:[0-9A-F]{40,64}|SHA256:[A-Za-z0-9+/]{43})\Z"
)

PRODUCER_PATH = "crates/aster-node/examples/live_event_acceptance.rs"
RUNNER_PATH = "tools/run-selected-live-event.py"
CHECKER_PATH = "tools/check-selected-live-event-receipt.py"
TEST_PATH = "tools/test-selected-live-event-receipt.py"
BINARY_NAME = "aster-live-event-acceptance"
PARTICIPANTS = ("publisher", "receiver")
ADMITTED_SOURCE_PATHS = tuple(
    sorted(
        {
            "Cargo.lock",
            "Cargo.toml",
            "mise.toml",
            "crates/aster-core/Cargo.toml",
            "crates/aster-core/src/custody.rs",
            "crates/aster-core/src/crypto/reference.rs",
            "crates/aster-core/src/lib.rs",
            "crates/aster-core/src/source_event.rs",
            "crates/aster-node/Cargo.toml",
            "crates/aster-node/examples/support/numbered.rs",
            "tools/historical/check-selected-live-event-receipt.py",
            "tools/historical/check-selected-linux-event-custody-receipt.py",

            "crates/aster-node/src/application.rs",
            "crates/aster-node/src/frame.rs",
            "crates/aster-node/src/identity.rs",
            "crates/aster-node/src/lib.rs",
            "crates/aster-node/src/mission.rs",
            "crates/aster-node/src/runtime.rs",
            "crates/aster-redb-store/Cargo.toml",
            "crates/aster-redb-store/src/custody.rs",
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
    "live_event_acceptance",
]

EXPECTED_DIRECTORIES = {
    "",
    "binary",
    "participants",
    "participants/publisher",
    "participants/publisher/state",
    "participants/receiver",
    "participants/receiver/state",
}
EXPECTED_FILES = {
    "run.json": 0o600,
    "stdout.log": 0o600,
    "stderr.log": 0o600,
    "transcript.tsv": 0o600,
    f"binary/{BINARY_NAME}": 0o700,
    "participants/publisher/mission.bundle": 0o600,
    "participants/publisher/state/identity.key": 0o600,
    "participants/publisher/state/mesh.redb": 0o600,
    "participants/receiver/mission.bundle": 0o600,
    "participants/receiver/state/identity.key": 0o600,
    "participants/receiver/state/mesh.redb": 0o600,
}
EXPECTED_FILES["participants/publisher/state/live-acceptance-publication.redb"] = 0o600
SECRET_FILES = {
    "participants/publisher/mission.bundle",
    "participants/publisher/state/identity.key",
    "participants/publisher/state/mesh.redb",
    "participants/receiver/mission.bundle",
    "participants/receiver/state/identity.key",
    "participants/receiver/state/mesh.redb",
}

SECRET_FILES.add("participants/publisher/state/live-acceptance-publication.redb")

RUN_KEYS = (
    "schema", "claim", "participants", "actor_lifetimes",
    "maximum_concurrent_actors", "topic", "beta_topic", "scope",
    "stream_events", "authorized_unsubscribed_events", "publication_model",
)
PARTICIPANT_KEYS = (
    "participant", "carrier_id", "mission_id", "mission_authority", "provisioning",
)
PEER_BINDING_KEYS = (
    "local", "remote", "local_carrier", "local_mission", "remote_carrier",
    "remote_mission", "mission_authenticated",
)
PHASE_KEYS = ("index", "phase", "actors", "outcome")
HANDLE_KEYS = ("phase", "participant", "event_identity", "event_authority")
EVENT_KEYS = (
    "phase", "participant", "stream", "id", "publisher", "publisher_counter",
    "event_sequence", "priority", "ttl", "acceptance_marker", "inserted",
    "payload_sha256",
)
RETRY_KEYS = (
    "phase", "participant", "id", "publisher", "publisher_counter",
    "event_sequence", "inserted", "exact_match",
)
CONFLICT_KEYS = (
    "phase", "participant", "original_id", "original_payload_sha256",
    "changed_payload_sha256", "error_kind", "operation", "sanitized",
    "publication_preserved",
)
QUERY_KEYS = (
    "phase", "participant", "stream", "items", "scanned_through", "has_more", "limit",
)
STATUS_KEYS = (
    "phase", "participant", "sync", "authenticated_contacts",
    "failed_contact_attempts", "peers", "peer", "peer_contacts",
    "peer_authorization", "peer_last_contact",
)
CHILD_STATUS_KEYS = (
    "phase", "participant", "observation", "sync", "authenticated_contacts",
    "failed_contact_attempts", "peers", "peer", "peer_contacts",
    "peer_authorization", "peer_last_contact",
)
SUBSCRIPTION_KEYS = (
    "phase", "participant", "stream", "id", "inserted", "durable",
    "include_descendant_scopes",
)
GAP_KEYS = (
    "phase", "participant", "stream", "disposition", "start_sequence",
    "end_sequence", "scanned_through_sequence", "has_more", "authenticated",
)
DELIVERY_KEYS = (
    "phase", "participant", "stream", "id", "event_sequence", "priority",
    "attempt", "payload_sha256",
)
ACK_KEYS = ("phase", "participant", "id", "disposition")
EMPTY_POLL_KEYS = (
    "phase", "participant", "observation", "deliveries", "has_more",
    "delivery_limit", "scan_limit",
)
TERMINATION_KEYS = (
    "phase", "participant", "mechanism", "after_flushed_poll", "graceful",
    "stop_record_expected", "acknowledged",
)
UNSUBSCRIBE_KEYS = (
    "phase", "participant", "stream", "subscription_id", "disposition",
)
RECEIPT_COUNTER_KEYS = (
    "contacts", "contact_errors", "direct_contacts", "relay_contacts",
    "unknown_path_contacts", "carrier_path_transitions",
    "carrier_path_transition_saturations", "items", "acceptance_markers", "events",
    "event_acceptance_markers", "route_cached_events", "controls", "applied_controls",
    "pending_controls", "control_highwater", "data_offered", "data_fetched",
    "data_inserted", "data_duplicates", "data_remaining", "mutable_remaining",
    "deferred_mutable_lanes", "blob_ranges_fetched", "blob_bytes_fetched",
    "blob_remaining", "blob_deferred", "blobs", "blob_acceptance_markers",
    "blob_last_acceptance_marker", "blob_sealed_bytes", "blob_operations",
    "blob_operation_bytes", "blob_variants", "blob_finalized_variants",
    "blob_committed_chunks", "blob_committed_file_bytes", "blob_reserved_file_bytes",
    "pending_blobs", "blob_carrier_prefixes", "blob_carrier_fetch_cursors",
    "blob_network_staging_bytes",
)
SHUTDOWN_KEYS = ("phase", "participant", *RECEIPT_COUNTER_KEYS)
CLOSED_HANDLE_KEYS = ("phase", "participant", "error_kind", "operation")
BIND_KEYS = ("participant", "status")
RESULT_KEYS = (
    "status", "records", "phases", "actor_lifetimes", "maximum_concurrent_actors",
    "graceful_shutdowns", "forced_process_terminations", "retained_handles",
    "closed_handles", "bind_reacquisitions", "secret_values_emitted",
    "payload_representation", "physical_network_claimed", "global_convergence_claimed",
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
    "opaque_items",
    "opaque_acceptance_markers",
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
    ("RUN", RUN_KEYS), ("PARTICIPANT", PARTICIPANT_KEYS),
    ("PARTICIPANT", PARTICIPANT_KEYS), ("PEER_BINDING", PEER_BINDING_KEYS),
    ("PEER_BINDING", PEER_BINDING_KEYS), ("PHASE", PHASE_KEYS),
    ("HANDLE", HANDLE_KEYS), ("EVENT", EVENT_KEYS), ("EVENT_RETRY", RETRY_KEYS),
    ("OPERATION_CONFLICT", CONFLICT_KEYS), ("EVENT", EVENT_KEYS),
    ("EVENT", EVENT_KEYS), ("EVENT", EVENT_KEYS), ("QUERY", QUERY_KEYS),
    ("QUERY", QUERY_KEYS), ("STATUS", STATUS_KEYS), ("SHUTDOWN", SHUTDOWN_KEYS),
    ("CLOSED_HANDLE", CLOSED_HANDLE_KEYS), ("PHASE", PHASE_KEYS),
    ("HANDLE", HANDLE_KEYS), ("HANDLE", HANDLE_KEYS),
    ("SUBSCRIPTION", SUBSCRIPTION_KEYS), ("STATUS", CHILD_STATUS_KEYS),
    ("STATUS", STATUS_KEYS), ("GAP", GAP_KEYS), ("DELIVERY", DELIVERY_KEYS),
    ("DELIVERY", DELIVERY_KEYS), ("PROCESS_TERMINATION", TERMINATION_KEYS),
    ("SHUTDOWN", SHUTDOWN_KEYS), ("CLOSED_HANDLE", CLOSED_HANDLE_KEYS),
    ("PHASE", PHASE_KEYS), ("HANDLE", HANDLE_KEYS),
    ("SUBSCRIPTION", SUBSCRIPTION_KEYS), ("STATUS", CHILD_STATUS_KEYS),
    ("GAP", GAP_KEYS), ("DELIVERY", DELIVERY_KEYS), ("DELIVERY", DELIVERY_KEYS),
    ("ACKNOWLEDGEMENT", ACK_KEYS), ("REACKNOWLEDGEMENT", ACK_KEYS),
    ("ACKNOWLEDGEMENT", ACK_KEYS), ("REACKNOWLEDGEMENT", ACK_KEYS),
    ("EMPTY_POLL", EMPTY_POLL_KEYS), ("SHUTDOWN", SHUTDOWN_KEYS),
    ("CLOSED_HANDLE", CLOSED_HANDLE_KEYS), ("PHASE", PHASE_KEYS),
    ("HANDLE", HANDLE_KEYS), ("HANDLE", HANDLE_KEYS),
    ("SUBSCRIPTION", SUBSCRIPTION_KEYS), ("EMPTY_POLL", EMPTY_POLL_KEYS),
    ("STATUS", STATUS_KEYS), ("STATUS", STATUS_KEYS), ("GAP", GAP_KEYS),
    ("DELIVERY", DELIVERY_KEYS), ("ACKNOWLEDGEMENT", ACK_KEYS),
    ("REACKNOWLEDGEMENT", ACK_KEYS), ("EMPTY_POLL", EMPTY_POLL_KEYS),
    ("QUERY", QUERY_KEYS), ("QUERY", QUERY_KEYS),
    ("SUBSCRIPTION", SUBSCRIPTION_KEYS), ("STATUS", STATUS_KEYS),
    ("UNSUBSCRIBE", UNSUBSCRIBE_KEYS), ("REUNSUBSCRIBE", UNSUBSCRIBE_KEYS),
    ("SHUTDOWN", SHUTDOWN_KEYS), ("SHUTDOWN", SHUTDOWN_KEYS),
    ("CLOSED_HANDLE", CLOSED_HANDLE_KEYS), ("CLOSED_HANDLE", CLOSED_HANDLE_KEYS),
    ("PHASE", PHASE_KEYS), ("HANDLE", HANDLE_KEYS),
    ("SUBSCRIPTION", SUBSCRIPTION_KEYS), ("STATUS", STATUS_KEYS),
    ("GAP", GAP_KEYS), ("EMPTY_POLL", EMPTY_POLL_KEYS), ("QUERY", QUERY_KEYS),
    ("QUERY", QUERY_KEYS), ("SHUTDOWN", SHUTDOWN_KEYS),
    ("CLOSED_HANDLE", CLOSED_HANDLE_KEYS), ("BIND_REACQUIRED", BIND_KEYS),
    ("BIND_REACQUIRED", BIND_KEYS), ("RESULT", RESULT_KEYS),
)

PAYLOAD_HASHES = {
    "first": "5bd118b5a1484f6c6d0c8cad0edc2dd040a678ebe1a63933ab4f18e9843bb9cc",
    "second": "cdecd7321784c956b0b03ec4a6e5dfbcf992ad350c830b2e5dc97568689a29ed",
    "third": "5c5da7717ebf03b70dddd6dbd22c181b3b962156f54ec2f6838d6c824e641ab6",
    "beta": "87dd6d2c288ae22d51d652e271e2e624bbe4f75a68bf92c3ac45fe5c8885451e",
    "changed_first": "057ce67a6cd72df1450395a1815e22e7f51e8cc9e8622c55832c892ab7280b9d",
}

LIMITATIONS = [
    "operator-attested-source-binary-execution-link-not-cryptographically-proven",
    "selected-admitted-source-list-is-not-a-complete-reproducible-build-closure",
    "one-host-loopback-same-implementation-observation",
    "participant-secret-artifacts-validated-by-metadata-only",
    "event-observation-and-publication-order-are-producer-attested",
    "awaiting-status-observation-has-zero-failed-contact-attempts",
    "policy-change-has-no-fresh-post-change-contact-or-completion-observation",
    "authorized-beta-event-is-withheld-but-not-delivered-or-acknowledged",
    "priority-withheld-data-is-outside-negotiated-work-and-does-not-produce-work-remained",
    "restart-observes-one-immediate-peerless-reopen-not-indefinite-retention",
]
NONCLAIMS = [
    "distinct-physical-hosts",
    "nat-or-internet-path",
    "controlled-or-public-relay",
    "btle-carrier",
    "independent-implementation-interoperability",
    "scale-beyond-two-participants",
    "resource-thresholds-or-long-duration-soak",
    "state-record-or-blob-live-application-acceptance",
    "reproducible-build-or-cryptographic-source-to-execution-provenance",
    "positive-failed-contact-attempt-status-propagation",
    "post-policy-change-fresh-contact-completion-or-beta-delivery",
    "work-remained-status-for-priority-policy-withheld-data",
    "indefinite-event-retention-compaction-or-garbage-collection",
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

    for participant in PARTICIPANTS:
        mission = observed_files[f"participants/{participant}/mission.bundle"]
        identity = observed_files[f"participants/{participant}/state/identity.key"]
        store = observed_files[f"participants/{participant}/state/mesh.redb"]
        if not 0 < mission.st_size <= MISSION_MAX_BYTES:
            fail(f"{participant} mission artifact violates its metadata-only size bound")
        if identity.st_size != IDENTITY_BYTES:
            fail(f"{participant} identity artifact has the wrong metadata-only byte count")
        if not 0 < store.st_size <= STORE_MAX_BYTES:
            fail(f"{participant} state artifact violates its metadata-only size bound")
    journal = observed_files["participants/publisher/state/live-acceptance-publication.redb"]
    if not 0 < journal.st_size <= STORE_MAX_BYTES:
        fail("publication journal violates its metadata-only size bound")
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
    if len(parts) != len(expected_keys) + 2 or parts[:2] != ["LIVE_EVENT", expected_type]:
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
    if len(EXPECTED_SEQUENCE) != TRANSCRIPT_RECORDS:
        raise AssertionError("checker transcript sequence length is inconsistent")
    records = [
        parse_record(lines[index], kind, keys, index)
        for index, (kind, keys) in enumerate(EXPECTED_SEQUENCE)
    ]

    require_fixed(
        records[0],
        {
            "schema": TRANSCRIPT_SCHEMA,
            "publication_model": "numbered-v1",
            "claim": CLAIM,
            "participants": "2",
            "actor_lifetimes": "7",
            "maximum_concurrent_actors": "2",
            "topic": "opaque",
            "beta_topic": "opaque.beta",
            "scope": "test/runtime-contact",
            "stream_events": "3",
            "authorized_unsubscribed_events": "1",
        },
        "RUN",
    )

    participants: dict[str, dict[str, str]] = {}
    for index, name in ((1, "publisher"), (2, "receiver")):
        record = records[index]
        require_fixed(
            record,
            {"participant": name, "provisioning": "independent_reference_bundle"},
            f"PARTICIPANT {name}",
        )
        for key in ("carrier_id", "mission_id", "mission_authority"):
            require_id(record[key], f"PARTICIPANT {name}.{key}")
        participants[name] = record
    publisher = participants["publisher"]
    receiver = participants["receiver"]
    if publisher["mission_authority"] != receiver["mission_authority"]:
        fail("participants do not share exactly one mission authority")
    domains = {
        publisher["carrier_id"],
        receiver["carrier_id"],
        publisher["mission_id"],
        receiver["mission_id"],
        publisher["mission_authority"],
    }
    if len(domains) != 5 or publisher["carrier_id"] >= receiver["carrier_id"]:
        fail("participant identity domains or deterministic initiation ordering differ")

    for index, local, remote in (
        (3, "publisher", "receiver"),
        (4, "receiver", "publisher"),
    ):
        record = records[index]
        require_fixed(
            record,
            {
                "local": local,
                "remote": remote,
                "local_carrier": participants[local]["carrier_id"],
                "local_mission": participants[local]["mission_id"],
                "remote_carrier": participants[remote]["carrier_id"],
                "remote_mission": participants[remote]["mission_id"],
                "mission_authenticated": "true",
            },
            f"PEER_BINDING {local}",
        )

    phases = (
        (5, "1", "peerless_publish", "publisher", "published"),
        (18, "2", "threshold_delivery", "publisher+receiver", "receiver-force-terminated"),
        (30, "3", "peerless_redelivery", "receiver", "acknowledged"),
        (44, "4", "normal_gap_closure", "publisher+receiver", "gap-closed"),
        (66, "5", "final_peerless_reopen", "receiver", "durable-empty"),
    )
    for index, number, phase, actors, outcome in phases:
        require_fixed(
            records[index],
            {"index": number, "phase": phase, "actors": actors, "outcome": outcome},
            f"PHASE {number}",
        )

    handle_expectations = (
        (6, "peerless_publish", "publisher"),
        (19, "threshold_delivery", "publisher"),
        (20, "threshold_delivery", "receiver"),
        (31, "peerless_redelivery", "receiver"),
        (45, "normal_gap_closure", "receiver"),
        (46, "normal_gap_closure", "publisher"),
        (67, "final_peerless_reopen", "receiver"),
    )
    for index, phase, participant in handle_expectations:
        require_fixed(
            records[index],
            {
                "phase": phase,
                "participant": participant,
                "event_identity": participants[participant]["mission_id"],
                "event_authority": participants[participant]["mission_authority"],
            },
            f"HANDLE {phase}/{participant}",
        )

    event_expectations = (
        (7, "alpha", 1, 1, "priority", "first"),
        (10, "alpha", 2, 2, "routine", "second"),
        (11, "alpha", 3, 3, "flash", "third"),
        (12, "beta", 4, 1, "priority", "beta"),
    )
    events: dict[str, dict[str, str]] = {}
    for index, stream, counter, sequence, priority, name in event_expectations:
        record = records[index]
        require_fixed(
            record,
            {
                "phase": "peerless_publish",
                "participant": "publisher",
                "stream": stream,
                "publisher": publisher["mission_id"],
                "publisher_counter": str(counter),
                "event_sequence": str(sequence),
                "priority": priority,
                "ttl": "durable",
                "acceptance_marker": str(counter),
                "inserted": "true",
                "payload_sha256": PAYLOAD_HASHES[name],
            },
            f"EVENT {name}",
        )
        require_id(record["id"], f"EVENT {name}.id")
        events[name] = record
    if len({record["id"] for record in events.values()}) != 4:
        fail("published Event identifiers are not pairwise distinct")

    retry = records[8]
    require_fixed(
        retry,
        {
            "phase": "peerless_publish",
            "participant": "publisher",
            "id": events["first"]["id"],
            "publisher": publisher["mission_id"],
            "publisher_counter": "1",
            "event_sequence": "1",
            "inserted": "false",
            "exact_match": "true",
        },
        "EVENT_RETRY",
    )
    require_fixed(
        records[9],
        {
            "phase": "peerless_publish",
            "participant": "publisher",
            "original_id": events["first"]["id"],
            "original_payload_sha256": PAYLOAD_HASHES["first"],
            "changed_payload_sha256": PAYLOAD_HASHES["changed_first"],
            "error_kind": "conflict",
            "operation": "publish_numbered",
            "sanitized": "true",
            "publication_preserved": "true",
        },
        "OPERATION_CONFLICT",
    )

    query_expectations = (
        (13, "peerless_publish", "publisher", "alpha", 3, 4),
        (14, "peerless_publish", "publisher", "beta", 1, 4),
        (56, "normal_gap_closure", "receiver", "alpha", 3, 3),
        (57, "normal_gap_closure", "receiver", "beta", 0, 3),
        (72, "final_peerless_reopen", "receiver", "alpha", 3, 3),
        (73, "final_peerless_reopen", "receiver", "beta", 0, 3),
    )
    for index, phase, participant, stream, items, scanned in query_expectations:
        require_fixed(
            records[index],
            {
                "phase": phase,
                "participant": participant,
                "stream": stream,
                "items": str(items),
                "scanned_through": str(scanned),
                "has_more": "false",
                "limit": "8",
            },
            f"QUERY {phase}/{stream}",
        )

    def require_status(
        index: int,
        phase: str,
        participant: str,
        sync: str,
        contacts: int,
        failures: int,
        peer: str | None,
        peer_last_contact: str | None,
        observation: str | None = None,
    ) -> None:
        expected = {
            "phase": phase,
            "participant": participant,
            "sync": sync,
            "authenticated_contacts": str(contacts),
            "failed_contact_attempts": str(failures),
            "peers": "0" if peer is None else "1",
            "peer": "none" if peer is None else participants[peer]["mission_id"],
            "peer_contacts": "0" if peer is None else "1",
            "peer_authorization": "none" if peer is None else "active",
            "peer_last_contact": "none" if peer_last_contact is None else peer_last_contact,
        }
        if observation is not None:
            expected["observation"] = observation
        require_fixed(records[index], expected, f"STATUS {phase}/{participant}")

    require_status(15, "peerless_publish", "publisher", "offline", 0, 0, None, None)
    require_status(
        22, "threshold_delivery", "receiver", "awaiting_authenticated_contact",
        0, 0, None, None, "before_publisher_start",
    )
    require_status(
        23, "threshold_delivery", "publisher", "last_contact_complete", 1, 0,
        "receiver", "complete_for_last_negotiated_contact",
    )
    require_status(
        33, "peerless_redelivery", "receiver", "offline", 0, 0,
        None, None, "peerless_reopen",
    )
    require_status(
        49, "normal_gap_closure", "receiver", "awaiting_authenticated_contact",
        0, 0, None, None,
    )
    require_status(
        50, "normal_gap_closure", "receiver", "last_contact_complete", 1, 0,
        "publisher", "complete_for_last_negotiated_contact",
    )
    require_status(
        59, "normal_gap_closure", "receiver", "policy_changed_since_contact", 1, 0,
        "publisher", "policy_changed_since_contact",
    )
    require_status(
        69, "final_peerless_reopen", "receiver", "offline", 0, 0, None, None,
    )

    subscriptions: dict[str, str] = {}
    for index, phase, stream, inserted, name in (
        (21, "threshold_delivery", "alpha", "true", "alpha_initial"),
        (32, "peerless_redelivery", "alpha", "false", "alpha_redelivery"),
        (47, "normal_gap_closure", "alpha", "false", "alpha_normal"),
        (58, "normal_gap_closure", "beta", "true", "beta"),
        (68, "final_peerless_reopen", "alpha", "false", "alpha_final"),
    ):
        record = records[index]
        require_fixed(
            record,
            {
                "phase": phase,
                "participant": "receiver",
                "stream": stream,
                "inserted": inserted,
                "durable": "true",
                "include_descendant_scopes": "false",
            },
            f"SUBSCRIPTION {phase}/{stream}",
        )
        require_id(record["id"], f"SUBSCRIPTION {phase}/{stream}.id")
        subscriptions[name] = record["id"]
    alpha_id = subscriptions["alpha_initial"]
    if any(
        subscriptions[name] != alpha_id
        for name in ("alpha_redelivery", "alpha_normal", "alpha_final")
    ) or subscriptions["beta"] == alpha_id:
        fail("durable subscription replay or beta subscription identity differs")

    for index, phase, disposition, start, end in (
        (24, "threshold_delivery", "open", 2, 3),
        (34, "peerless_redelivery", "open", 2, 3),
        (51, "normal_gap_closure", "closed", 0, 0),
        (70, "final_peerless_reopen", "closed", 0, 0),
    ):
        require_fixed(
            records[index],
            {
                "phase": phase,
                "participant": "receiver",
                "stream": "alpha",
                "disposition": disposition,
                "start_sequence": str(start),
                "end_sequence": str(end),
                "scanned_through_sequence": "3",
                "has_more": "false",
                "authenticated": "true",
            },
            f"GAP {phase}",
        )

    delivery_expectations = (
        (25, "threshold_delivery", "first", 1),
        (26, "threshold_delivery", "third", 1),
        (35, "peerless_redelivery", "first", 2),
        (36, "peerless_redelivery", "third", 2),
        (52, "normal_gap_closure", "second", 1),
    )
    for index, phase, name, attempt in delivery_expectations:
        event = events[name]
        require_fixed(
            records[index],
            {
                "phase": phase,
                "participant": "receiver",
                "stream": "alpha",
                "id": event["id"],
                "event_sequence": event["event_sequence"],
                "priority": event["priority"],
                "attempt": str(attempt),
                "payload_sha256": event["payload_sha256"],
            },
            f"DELIVERY {phase}/{name}",
        )

    for index, event_name, disposition in (
        (37, "first", "acknowledged"),
        (38, "first", "already_acknowledged"),
        (39, "third", "acknowledged"),
        (40, "third", "already_acknowledged"),
        (53, "second", "acknowledged"),
        (54, "second", "already_acknowledged"),
    ):
        require_fixed(
            records[index],
            {
                "phase": "peerless_redelivery" if index < 41 else "normal_gap_closure",
                "participant": "receiver",
                "id": events[event_name]["id"],
                "disposition": disposition,
            },
            f"ACK {event_name}/{disposition}",
        )

    for index, phase, observation in (
        (41, "peerless_redelivery", "after_acknowledgement"),
        (48, "normal_gap_closure", "before_normal_contact"),
        (55, "normal_gap_closure", "after_gap_acknowledgement"),
        (71, "final_peerless_reopen", "final_reopen"),
    ):
        require_fixed(
            records[index],
            {
                "phase": phase,
                "participant": "receiver",
                "observation": observation,
                "deliveries": "0",
                "has_more": "false",
                "delivery_limit": "8",
                "scan_limit": "8",
            },
            f"EMPTY_POLL {phase}/{observation}",
        )

    require_fixed(
        records[27],
        {
            "phase": "threshold_delivery",
            "participant": "receiver",
            "mechanism": "parent_child_kill",
            "after_flushed_poll": "true",
            "graceful": "false",
            "stop_record_expected": "false",
            "acknowledged": "false",
        },
        "PROCESS_TERMINATION",
    )
    require_fixed(
        records[60],
        {
            "phase": "normal_gap_closure",
            "participant": "receiver",
            "stream": "beta",
            "subscription_id": subscriptions["beta"],
            "disposition": "removed",
        },
        "UNSUBSCRIBE",
    )
    require_fixed(
        records[61],
        {
            "phase": "normal_gap_closure",
            "participant": "receiver",
            "stream": "beta",
            "subscription_id": subscriptions["beta"],
            "disposition": "already_absent",
        },
        "REUNSUBSCRIBE",
    )

    shutdown_expectations = (
        (16, "peerless_publish", "publisher", 0, 4),
        (28, "threshold_delivery", "publisher", 1, 4),
        (42, "peerless_redelivery", "receiver", 0, 2),
        (62, "normal_gap_closure", "publisher", 1, 4),
        (63, "normal_gap_closure", "receiver", 1, 3),
        (74, "final_peerless_reopen", "receiver", 0, 3),
    )
    shutdown_contacts: dict[str, dict[str, int]] = {}
    shutdown_counters: dict[str, dict[str, dict[str, int]]] = {}
    for index, phase, participant, contacts, events_count in shutdown_expectations:
        record = records[index]
        require_fixed(record, {"phase": phase, "participant": participant}, f"SHUTDOWN {phase}/{participant}")
        numeric = {
            key: parse_uint(record[key], f"SHUTDOWN {phase}/{participant}.{key}")
            for key in RECEIPT_COUNTER_KEYS
        }
        if (
            numeric["contacts"] != contacts
            or numeric["direct_contacts"] != contacts
            or numeric["contact_errors"] != 0
            or numeric["relay_contacts"] != 0
            or numeric["unknown_path_contacts"] != 0
            or numeric["carrier_path_transitions"] != 0
            or numeric["carrier_path_transition_saturations"] != 0
            or numeric["events"] != events_count
            or numeric["event_acceptance_markers"] != events_count
        ):
            fail(f"SHUTDOWN {phase}/{participant} contact or Event inventory differs")
        zero_fields = (
            "items", "acceptance_markers", "route_cached_events", "controls",
            "applied_controls", "pending_controls", "control_highwater",
            "data_duplicates", "mutable_remaining", "deferred_mutable_lanes",
            "blob_ranges_fetched", "blob_bytes_fetched", "blob_remaining",
            "blob_deferred", "blobs", "blob_acceptance_markers",
            "blob_last_acceptance_marker", "blob_sealed_bytes", "blob_operations",
            "blob_operation_bytes", "blob_variants", "blob_finalized_variants",
            "blob_committed_chunks", "blob_committed_file_bytes",
            "blob_reserved_file_bytes", "pending_blobs", "blob_carrier_prefixes",
            "blob_carrier_fetch_cursors", "blob_network_staging_bytes",
        )
        if any(numeric[key] != 0 for key in zero_fields):
            fail(f"SHUTDOWN {phase}/{participant} contains excluded class activity")
        if contacts == 0 and any(
            numeric[key] != 0
            for key in ("data_offered", "data_fetched", "data_inserted", "data_remaining")
        ):
            fail(f"peerless SHUTDOWN {phase}/{participant} contains contact data activity")
        shutdown_contacts.setdefault(phase, {})[participant] = contacts
        shutdown_counters.setdefault(phase, {})[participant] = numeric

    for index, phase, participant in (
        (17, "peerless_publish", "publisher"),
        (29, "threshold_delivery", "publisher"),
        (43, "peerless_redelivery", "receiver"),
        (64, "normal_gap_closure", "publisher"),
        (65, "normal_gap_closure", "receiver"),
        (75, "final_peerless_reopen", "receiver"),
    ):
        require_fixed(
            records[index],
            {
                "phase": phase,
                "participant": participant,
                "error_kind": "state_unavailable",
                "operation": "status",
            },
            f"CLOSED_HANDLE {phase}/{participant}",
        )
    require_fixed(records[76], {"participant": "publisher", "status": "reacquired"}, "BIND publisher")
    require_fixed(records[77], {"participant": "receiver", "status": "reacquired"}, "BIND receiver")
    require_fixed(
        records[78],
        {
            "status": "pass",
            "records": "79",
            "phases": "5",
            "actor_lifetimes": "7",
            "maximum_concurrent_actors": "2",
            "graceful_shutdowns": "6",
            "forced_process_terminations": "1",
            "retained_handles": "6",
            "closed_handles": "6",
            "bind_reacquisitions": "2",
            "secret_values_emitted": "false",
            "payload_representation": "sha256_only",
            "physical_network_claimed": "false",
            "global_convergence_claimed": "false",
        },
        "RESULT",
    )

    sensitive = {
        *(record[key] for record in participants.values() for key in ("carrier_id", "mission_id", "mission_authority")),
        *(event["id"] for event in events.values()),
        *subscriptions.values(),
    }
    return {
        "records": len(records),
        "bytes": len(data),
        "sha256": sha256_bytes(data),
        "phases": 5,
        "actor_lifetimes": 7,
        "maximum_concurrent_actors": 2,
        "events_published": 4,
        "alpha_events": 3,
        "authorized_unsubscribed_events": 1,
        "publication_retries": 1,
        "changed_intent_rejections": 1,
        "deliveries": 5,
        "acknowledgements": 3,
        "idempotent_reacknowledgements": 3,
        "empty_polls": 4,
        "queries": 6,
        "shutdowns": 6,
        "forced_process_terminations": 1,
        "closed_handles": 6,
        "bind_reacquisitions": 2,
        "_participants": participants,
        "_shutdown_contacts": shutdown_contacts,
        "_shutdown_counters": shutdown_counters,
        "_events": events,
        "_subscriptions": subscriptions,
        "_application_ids": sorted(sensitive),
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
        if line.startswith("LIVE_EVENT\t")
    )
    if extracted != transcript:
        fail("transcript is not the exact ordered LIVE_EVENT extraction from stdout")

    participants: dict[str, dict[str, str]] = transcript_facts["_participants"]
    by_carrier = {record["carrier_id"]: name for name, record in participants.items()}
    by_mission = {record["mission_id"]: name for name, record in participants.items()}
    lifetime_order = {
        "publisher": ("peerless_publish", "threshold_delivery", "normal_gap_closure"),
        "receiver": (
            "threshold_delivery",
            "peerless_redelivery",
            "normal_gap_closure",
            "final_peerless_reopen",
        ),
    }
    ready_count = {participant: 0 for participant in participants}
    stop_count = {participant: 0 for participant in participants}
    active: dict[str, str] = {}
    contact_count = {participant: 0 for participant in participants}
    contact_counters: dict[tuple[str, str], dict[str, int]] = {}
    pids: set[int] = set()
    lifetime_pids: dict[tuple[str, str], int] = {}
    sockets: set[str] = set()
    ports: set[int] = set()
    connected_sockets: dict[str, str] = {}
    child_records: dict[str, dict[str, str]] = {}
    ready_records = 0
    contact_records = 0
    stop_records = 0
    contact_totals = {
        key: 0
        for key in (
            "offered", "fetched", "inserted", "duplicates", "remaining",
            "deferred_event_lanes",
        )
    }
    receiver_peerless_redelivery_stopped = False

    def parse_child(line: str, label: str) -> tuple[str, dict[str, str]]:
        parts = line.split("\t")
        if len(parts) < 3 or parts[0] != "LIVE_EVENT_CHILD" or not parts[1]:
            fail(f"{label} has malformed child coordination framing")
        record: dict[str, str] = {}
        for token in parts[2:]:
            key, separator, value = token.partition("=")
            if (
                separator != "="
                or FIELD_NAME.fullmatch(key) is None
                or not value
                or key in record
                or not value.isascii()
                or any(ord(character) < 0x21 or ord(character) > 0x7E for character in value)
            ):
                fail(f"{label} has a malformed child coordination field")
            record[key] = value
        return parts[1], record

    transcript_started = False
    for line_number, line in enumerate(lines, start=1):
        label = f"captured stdout line {line_number}"
        if line.startswith("LIVE_EVENT\t"):
            transcript_started = True
            continue
        if transcript_started:
            fail(f"{label} appears after the public transcript began")
        if line.startswith("LIVE_EVENT_CHILD\t"):
            kind, record = parse_child(line, label)
            if kind not in {"AWAITING", "ATTEMPT1_READY", "ATTEMPT2_DONE"} or kind in child_records:
                fail(f"{label} has an unexpected or duplicate child coordination kind")
            if kind == "AWAITING":
                if (
                    active.get("receiver") != "threshold_delivery"
                    or ready_count["publisher"] != 1
                    or stop_count["publisher"] != 1
                    or "publisher" in active
                    or contact_records != 0
                ):
                    fail(
                        f"{label} is not inside the receiver threshold lifetime "
                        "before threshold publisher readiness and contact"
                    )
            elif kind == "ATTEMPT2_DONE" and not receiver_peerless_redelivery_stopped:
                fail(f"{label} precedes the receiver peerless-redelivery STOP")
            child_records[kind] = record
            if kind == "ATTEMPT1_READY":
                if (
                    active.get("receiver") != "threshold_delivery"
                    or active.get("publisher") != "threshold_delivery"
                    or contact_count["publisher"] != 1
                    or contact_count["receiver"] != 1
                ):
                    fail(
                        f"{label} is not after the threshold contact inside the "
                        "force-terminated receiver lifetime"
                    )
                # This flushed child witness is the last stdout evidence before
                # the parent kills the receiver. Close that forced lifetime here;
                # a receiver STOP would therefore remain inadmissible.
                del active["receiver"]
                contact_count["receiver"] = 0
            continue
        if line.startswith("READY "):
            record = parse_terminal_record(line, "READY", READY_KEYS, label)
            carrier_participant = by_carrier.get(record["carrier_id"])
            mission_participant = by_mission.get(record["mission_id"])
            if carrier_participant is None or carrier_participant != mission_participant:
                fail(f"{label} does not bind one transcript participant")
            participant = carrier_participant
            ordinal = ready_count[participant]
            if ordinal >= len(lifetime_order[participant]) or participant in active:
                fail(f"{label} starts an overlapping or extra participant lifetime")
            phase = lifetime_order[participant][ordinal]
            peers = "0" if phase in {"peerless_publish", "peerless_redelivery", "final_peerless_reopen"} else "1"
            require_fixed(
                record,
                {
                    "selected": "true",
                    "carrier_id": participants[participant]["carrier_id"],
                    "mission_id": participants[participant]["mission_id"],
                    "mission_authority": participants[participant]["mission_authority"],
                    "state": encoded_path(root / "participants" / participant / "state"),
                    "peers": peers,
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
            socket_match = LOOPBACK_SOCKET.fullmatch(record["sockets"])
            if socket_match is None or int(socket_match.group(1)) > 65535:
                fail(f"{label}.sockets is not one bounded loopback socket")
            if peers == "1":
                prior = connected_sockets.get(participant)
                if prior is not None and prior != record["sockets"]:
                    fail(f"{label}.sockets does not preserve the participant connected bind")
                connected_sockets[participant] = record["sockets"]
            pids.add(pid)
            lifetime_pids[(participant, phase)] = pid
            sockets.add(record["sockets"])
            ports.add(int(socket_match.group(1)))
            ready_count[participant] += 1
            active[participant] = phase
            ready_records += 1
            continue
        if line.startswith("CONTACT "):
            record = parse_terminal_record(line, "CONTACT", CONTACT_KEYS, label)
            remote_carrier = by_carrier.get(record["carrier_peer"])
            remote_mission = by_mission.get(record["mission_peer"])
            if remote_carrier is None or remote_carrier != remote_mission:
                fail(f"{label} does not bind one reciprocal transcript peer")
            remote = remote_carrier
            local = "receiver" if remote == "publisher" else "publisher"
            local_phase = active.get(local)
            if local_phase not in {"threshold_delivery", "normal_gap_closure"}:
                fail(f"{label} occurs outside an active connected lifetime")
            if active.get(remote) != local_phase:
                fail(f"{label} does not bind two active peers in the same connected phase")
            expected_direction = (
                "out"
                if participants[local]["carrier_id"] < participants[remote]["carrier_id"]
                else "in"
            )
            require_fixed(
                record,
                {
                    "direction": expected_direction,
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
            numeric_fields = CONTACT_KEYS[3:26] + CONTACT_KEYS[27:28]
            numeric = {
                key: parse_uint(record[key], f"{label}.{key}", positive=key == "rounds")
                for key in numeric_fields
            }
            for key in CONTACT_EXCLUDED_ZERO_FIELDS:
                if numeric[key] != 0:
                    fail(f"{label}.{key} is nonzero outside selected Event activity")
            if numeric["duplicates"] != 0:
                fail(f"{label}.duplicates is nonzero")
            lifetime_counters = contact_counters.setdefault(
                (local, local_phase),
                {
                    "offered": 0,
                    "fetched": 0,
                    "inserted": 0,
                    "duplicates": 0,
                    "remaining": 0,
                    "deferred_event_lanes": 0,
                },
            )
            for key in lifetime_counters:
                lifetime_counters[key] += numeric[key]
            for key in contact_totals:
                contact_totals[key] += numeric[key]
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
            if phase is None:
                fail(f"{label} closes an absent participant lifetime")
            expected = transcript_facts["_shutdown_counters"].get(phase, {}).get(participant)
            if expected is None:
                fail(f"{label} has no public graceful-shutdown counterpart")
            require_fixed(
                record,
                {
                    "lifecycle": "complete",
                    "sync_status": "contacts_observed" if expected["contacts"] else "no_successful_contact",
                    "carrier_id": participants[participant]["carrier_id"],
                    "mission_id": participants[participant]["mission_id"],
                    "contacts": str(expected["contacts"]),
                    "contact_errors": "0",
                    "direct_contacts": str(expected["direct_contacts"]),
                    "relay_contacts": "0",
                    "unknown_path_contacts": "0",
                    "carrier_path_transitions": "0",
                    "carrier_path_transition_saturations": "0",
                    "path_observation": "not-authorization",
                    "opaque_items": str(expected["items"]),
                    "opaque_acceptance_markers": str(expected["acceptance_markers"]),
                    "events": str(expected["events"]),
                    "event_acceptance_markers": str(expected["event_acceptance_markers"]),
                    "route_cached_events": str(expected["route_cached_events"]),
                    "controls": str(expected["controls"]),
                    "applied_controls": str(expected["applied_controls"]),
                    "pending_controls": str(expected["pending_controls"]),
                    "control_highwater": str(expected["control_highwater"]),
                    "mission_auth": "hybrid-pq",
                    "provisioning": "unprotected-reference",
                    "semantics": "source-authenticated-event",
                    "reconciliation_classes": "event,state,record,blob-v5",
                    "controls_semantics": "source-authenticated-flash",
                },
                label,
            )
            for key in STOP_NUMERIC_FIELDS:
                parse_uint(record[key], f"{label}.{key}")
            for key in STOP_EXCLUDED_ZERO_FIELDS:
                if record[key] != "0":
                    fail(f"{label}.{key} is nonzero outside selected Event activity")
            if contact_count[participant] != expected["contacts"]:
                fail(f"{label} CONTACT records differ from graceful shutdown accounting")
            observed_contact_counters = contact_counters.get(
                (participant, phase),
                {
                    "offered": 0,
                    "fetched": 0,
                    "inserted": 0,
                    "duplicates": 0,
                    "remaining": 0,
                    "deferred_event_lanes": 0,
                },
            )
            for contact_key, shutdown_key in (
                ("offered", "data_offered"),
                ("fetched", "data_fetched"),
                ("inserted", "data_inserted"),
                ("duplicates", "data_duplicates"),
                ("remaining", "data_remaining"),
            ):
                if observed_contact_counters[contact_key] != expected[shutdown_key]:
                    fail(
                        f"{label}.{contact_key} differs from public graceful "
                        "shutdown accounting"
                    )
            if observed_contact_counters["deferred_event_lanes"] != 0:
                fail(f"{label}.deferred_event_lanes is nonzero for a complete contact")
            del active[participant]
            contact_count[participant] = 0
            stop_count[participant] += 1
            stop_records += 1
            if participant == "receiver" and phase == "peerless_redelivery":
                receiver_peerless_redelivery_stopped = True
            continue
        fail(f"{label} belongs to an unadmitted terminal record family")

    if set(child_records) != {"AWAITING", "ATTEMPT1_READY", "ATTEMPT2_DONE"}:
        fail("captured stdout does not contain exactly the three child coordination records")
    awaiting_keys = {
        "participant", "identity", "subscription_id", "subscription_inserted", "sync",
        "authenticated_contacts", "failed_contact_attempts", "peers",
    }
    attempt_one_keys = {
        "participant", "subscription_id", "sync", "authenticated_contacts",
        "failed_contact_attempts", "peer", "peer_contacts", "peer_authorization",
        "peer_last_contact", "gap_start", "gap_end", "gap_scanned_through",
        "gap_has_more", "first_id", "first_sequence", "first_priority",
        "first_attempt", "first_payload_sha256", "third_id", "third_sequence",
        "third_priority", "third_attempt", "third_payload_sha256", "acknowledged",
    }
    attempt_two_keys = {
        "participant", "publisher", "subscription_id", "subscription_inserted", "sync",
        "authenticated_contacts", "failed_contact_attempts", "peers", "gap_start",
        "gap_end", "gap_scanned_through", "gap_has_more", "first_id",
        "first_sequence", "first_priority", "first_attempt", "first_payload_sha256",
        "first_ack", "first_reack", "third_id", "third_sequence", "third_priority",
        "third_attempt", "third_payload_sha256", "third_ack", "third_reack",
        "empty_deliveries", "empty_has_more", "closed_kind", "closed_operation",
        *(f"shutdown_{key}" for key in RECEIPT_COUNTER_KEYS),
    }
    for kind, expected_keys in (
        ("AWAITING", awaiting_keys),
        ("ATTEMPT1_READY", attempt_one_keys),
        ("ATTEMPT2_DONE", attempt_two_keys),
    ):
        if set(child_records[kind]) != expected_keys:
            fail(f"LIVE_EVENT_CHILD {kind} has missing or extra fields")
    require_fixed(
        child_records["AWAITING"],
        {
            "participant": "receiver",
            "identity": participants["receiver"]["mission_id"],
            "subscription_id": transcript_facts["_subscriptions"]["alpha_initial"],
            "subscription_inserted": "true",
            "sync": "awaiting_authenticated_contact",
            "authenticated_contacts": "0",
            "failed_contact_attempts": "0",
            "peers": "0",
        },
        "LIVE_EVENT_CHILD AWAITING",
    )
    attempt_one = child_records["ATTEMPT1_READY"]
    require_fixed(
        attempt_one,
        {
            "participant": "receiver",
            "subscription_id": transcript_facts["_subscriptions"]["alpha_initial"],
            "sync": "last_contact_complete",
            "authenticated_contacts": "1",
            "failed_contact_attempts": "0",
            "peer": participants["publisher"]["mission_id"],
            "peer_contacts": "1",
            "peer_authorization": "active",
            "peer_last_contact": "complete_for_last_negotiated_contact",
            "gap_start": "2",
            "gap_end": "3",
            "gap_scanned_through": "3",
            "gap_has_more": "false",
            "first_id": transcript_facts["_events"]["first"]["id"],
            "first_sequence": "1",
            "first_priority": "priority",
            "first_attempt": "1",
            "first_payload_sha256": PAYLOAD_HASHES["first"],
            "third_id": transcript_facts["_events"]["third"]["id"],
            "third_sequence": "3",
            "third_priority": "flash",
            "third_attempt": "1",
            "third_payload_sha256": PAYLOAD_HASHES["third"],
            "acknowledged": "false",
        },
        "LIVE_EVENT_CHILD ATTEMPT1_READY",
    )
    attempt_two = child_records["ATTEMPT2_DONE"]
    redelivery_shutdown = transcript_facts["_shutdown_counters"]["peerless_redelivery"]["receiver"]
    for key, value in redelivery_shutdown.items():
        if attempt_two[f"shutdown_{key}"] != str(value):
            fail(f"LIVE_EVENT_CHILD ATTEMPT2_DONE.shutdown_{key} differs from public shutdown")
    require_fixed(
        attempt_two,
        {
            "participant": "receiver",
            "publisher": participants["publisher"]["mission_id"],
            "subscription_id": transcript_facts["_subscriptions"]["alpha_initial"],
            "subscription_inserted": "false",
            "sync": "offline",
            "authenticated_contacts": "0",
            "failed_contact_attempts": "0",
            "peers": "0",
            "gap_start": "2",
            "gap_end": "3",
            "gap_scanned_through": "3",
            "gap_has_more": "false",
            "first_id": transcript_facts["_events"]["first"]["id"],
            "first_sequence": "1",
            "first_priority": "priority",
            "first_attempt": "2",
            "first_payload_sha256": PAYLOAD_HASHES["first"],
            "first_ack": "acknowledged",
            "first_reack": "already_acknowledged",
            "third_id": transcript_facts["_events"]["third"]["id"],
            "third_sequence": "3",
            "third_priority": "flash",
            "third_attempt": "2",
            "third_payload_sha256": PAYLOAD_HASHES["third"],
            "third_ack": "acknowledged",
            "third_reack": "already_acknowledged",
            "empty_deliveries": "0",
            "empty_has_more": "false",
            "shutdown_contacts": "0",
            "shutdown_contact_errors": "0",
            "shutdown_direct_contacts": "0",
            "shutdown_relay_contacts": "0",
            "shutdown_unknown_path_contacts": "0",
            "shutdown_events": "2",
            "shutdown_event_acceptance_markers": "2",
            "closed_kind": "state_unavailable",
            "closed_operation": "status",
        },
        "LIVE_EVENT_CHILD ATTEMPT2_DONE",
    )
    if any(value != len(lifetime_order[name]) for name, value in ready_count.items()):
        fail("captured stdout does not contain exactly seven actor READY records")
    if active or ready_records != 7 or stop_records != 6:
        fail("captured stdout does not close exactly six graceful and one forced lifetime")
    if contact_records != 4 or any(value != 0 for value in contact_count.values()):
        fail("captured stdout does not contain exactly four per-participant CONTACT receipts")
    if (
        contact_totals["offered"] != 3
        or contact_totals["fetched"] != 3
        or contact_totals["inserted"] != 3
        or contact_totals["duplicates"] != 0
        or contact_totals["remaining"] != 0
        or contact_totals["deferred_event_lanes"] != 0
    ):
        fail("captured stdout does not prove the exact three-Event direct transfer aggregate")
    parent_lifetimes = (
        ("publisher", "peerless_publish"),
        ("publisher", "threshold_delivery"),
        ("publisher", "normal_gap_closure"),
        ("receiver", "normal_gap_closure"),
        ("receiver", "final_peerless_reopen"),
    )
    parent_pids = {lifetime_pids[lifetime] for lifetime in parent_lifetimes}
    child_pids = {
        lifetime_pids[("receiver", "threshold_delivery")],
        lifetime_pids[("receiver", "peerless_redelivery")],
    }
    if (
        len(parent_pids) != 1
        or len(child_pids) != 2
        or not parent_pids.isdisjoint(child_pids)
        or pids != parent_pids | child_pids
        or len(connected_sockets) != 2
        or len(set(connected_sockets.values())) != 2
    ):
        fail("captured stdout does not bind one parent and two child processes to two connected sockets")

    sensitive = {
        *(record[key] for record in participants.values() for key in ("carrier_id", "mission_id", "mission_authority")),
        *transcript_facts["_application_ids"],
        *sockets,
        encoded_path(root),
    }
    return {
        "lines": len(lines),
        "bytes": len(stdout),
        "sha256": sha256_bytes(stdout),
        "ready_records": ready_records,
        "contact_records": contact_records,
        "stop_records": stop_records,
        "child_coordination_records": 3,
        "processes": 3,
        "reconciliation": {
            "event_transfer": {
                "offered": contact_totals["offered"],
                "fetched": contact_totals["fetched"],
                "inserted": contact_totals["inserted"],
                "duplicates": contact_totals["duplicates"],
            },
            "direct_only": True,
            "control_activity": "all-zero",
            "mutable_activity": "all-zero",
            "blob_activity": "all-zero",
            "contact_stop_aggregation": "exact",
        },
        "identifiers_paths_ports_pids": "parsed-cross-bound-excluded",
        "_sensitive_values": sorted(sensitive),
        "_sensitive_pids": sorted(pids),
        "_sensitive_ports": sorted(ports),
    }



def validate_publication_diagnostics(data: bytes, *, inserted: int, retries: int, failures: int) -> None:
    keys = ("group_sequence", "collected", "cohorts", "custody_writer_commits", "event_writer_commits",
            "total_writer_commits", "accepted_new", "exact_retries", "failures", "max_cohort_size", "singleton_fallbacks")
    if len(data) > STDERR_MAX_BYTES or not data.endswith(b"\n"):
        fail("publication diagnostics are missing or exceed their bound")
    totals = [0, 0, 0]
    try:
        lines = data.decode("ascii", errors="strict").splitlines()
    except UnicodeError:
        fail("publication diagnostics are not canonical ASCII")
    if len(lines) != inserted + retries + failures:
        fail("publication diagnostic count differs from the sequential producer")
    for sequence, line in enumerate(lines, 1):
        fields = line.split(" ")
        if fields[0] != "event_publication_group" or len(fields) != len(keys) + 1:
            fail("stderr contains an unclassified diagnostic")
        values = {}
        for key, field in zip(keys, fields[1:]):
            name, separator, value = field.partition("=")
            if name != key or separator != "=" or re.fullmatch(r"0|[1-9][0-9]{0,19}", value) is None or int(value) >= 2**64:
                fail("publication diagnostic field is noncanonical")
            values[key] = int(value)
        if (values["group_sequence"] != sequence or values["collected"] != 1 or values["cohorts"] != 1
                or values["max_cohort_size"] != 1 or values["singleton_fallbacks"] != 1
                or values["total_writer_commits"] != values["custody_writer_commits"] + values["event_writer_commits"]
                or values["accepted_new"] + values["exact_retries"] + values["failures"] != 1
                or (values["accepted_new"] and not values["event_writer_commits"])):
            fail("publication diagnostic accounting differs from its admitted outcome")
        for index, key in enumerate(("accepted_new", "exact_retries", "failures")):
            totals[index] += values[key]
    if totals != [inserted, retries, failures]:
        fail("publication diagnostic outcomes differ from the producer scenario")


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


def validate_inventory_document(
    value: Any,
    observed: dict[str, dict[str, os.stat_result]],
) -> None:
    inventory = exact_object(
        value,
        ("directories", "public", "participant_secret"),
        "run.inventory",
    )
    directories = exact_array(
        inventory["directories"],
        "run.inventory.directories",
        length=len(EXPECTED_DIRECTORIES),
    )
    expected_directories = sorted(EXPECTED_DIRECTORIES)
    for index, relative in enumerate(expected_directories):
        label = f"run.inventory.directories[{index}]"
        record = exact_object(directories[index], ("path", "mode", "owner"), label)
        metadata = observed["directories"][relative]
        exact_string(record["path"], f"{label}.path", expected=relative or ".")
        exact_uint(record["mode"], f"{label}.mode", expected=0o700)
        exact_uint(record["owner"], f"{label}.owner", expected=metadata.st_uid)

    def validate_files(kind: str, expected_paths: Sequence[str]) -> None:
        records = exact_array(
            inventory[kind],
            f"run.inventory.{kind}",
            length=len(expected_paths),
        )
        for index, relative in enumerate(expected_paths):
            label = f"run.inventory.{kind}[{index}]"
            record = exact_object(
                records[index],
                ("path", "bytes", "mode", "hard_links", "owner"),
                label,
            )
            metadata = observed["files"][relative]
            exact_string(record["path"], f"{label}.path", expected=relative)
            exact_uint(record["bytes"], f"{label}.bytes", expected=metadata.st_size)
            exact_uint(
                record["mode"],
                f"{label}.mode",
                expected=EXPECTED_FILES[relative],
            )
            exact_uint(record["hard_links"], f"{label}.hard_links", expected=1)
            exact_uint(record["owner"], f"{label}.owner", expected=metadata.st_uid)

    public_paths = tuple(
        sorted(
            relative
            for relative in EXPECTED_FILES
            if relative not in SECRET_FILES and relative != "run.json"
        )
    )
    validate_files("public", public_paths)
    validate_files("participant_secret", tuple(sorted(SECRET_FILES)))


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
    inventory: dict[str, dict[str, os.stat_result]],
    source_authority: dict[str, Any],
    binary: bytes,
    stdout: bytes,
    stderr: bytes,
    transcript: bytes,
) -> dict[str, Any]:
    exact_object(
        document,
        (
            "schema",
            "claim",
            "run_id",
            "source",
            "commands",
            "execution",
            "artifacts",
            "inventory",
            "tools",
        ),
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
    expected_binary = os.fspath(root / "binary" / BINARY_NAME)
    if run_argv != [expected_binary, os.fspath(root)]:
        fail("run.commands.run_argv does not bind the copied executable and exact raw root")

    execution = exact_object(
        document["execution"],
        (
            "exit_code",
            "timeout_seconds",
            "worktree_clean_at_run",
            "source_binary_execution_link",
        ),
        "run.execution",
    )
    exact_uint(execution["exit_code"], "run.execution.exit_code", expected=0)
    exact_uint(
        execution["timeout_seconds"],
        "run.execution.timeout_seconds",
        expected=RUN_TIMEOUT_SECONDS,
    )
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
            path=f"binary/{BINARY_NAME}",
            data=binary,
        ),
        "stdout": validate_artifact_record(artifacts["stdout"], "run.artifacts.stdout", path="stdout.log", data=stdout),
        "stderr": validate_artifact_record(artifacts["stderr"], "run.artifacts.stderr", path="stderr.log", data=stderr),
        "transcript": validate_artifact_record(
            artifacts["transcript"], "run.artifacts.transcript", path="transcript.tsv", data=transcript
        ),
    }

    validate_inventory_document(document["inventory"], inventory)

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
            f"binary/{BINARY_NAME}",
            "copied release executable",
            BINARY_MAX_BYTES,
        )
        public_metadata = {
            "run.json": run_metadata,
            "stdout.log": stdout_metadata,
            "stderr.log": stderr_metadata,
            "transcript.tsv": transcript_metadata,
            f"binary/{BINARY_NAME}": binary_metadata,
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
        validate_publication_diagnostics(stderr, inserted=3, retries=1, failures=1)
        transcript_facts = validate_transcript(transcript)
        terminal_facts = validate_terminal_stdout(stdout, transcript, root, transcript_facts)
        document = load_canonical_json(run_data, "run metadata", RUN_JSON_MAX_BYTES)
        run_facts = validate_run_document(
            document,
            root,
            inventory,
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
            f"binary/{BINARY_NAME}": read_public_file(
                root_descriptor,
                f"binary/{BINARY_NAME}",
                "terminal copied release executable",
                BINARY_MAX_BYTES,
            )[0],
        }
        initial_public = {
            "run.json": run_data,
            "stdout.log": stdout,
            "stderr.log": stderr,
            "transcript.tsv": transcript,
            f"binary/{BINARY_NAME}": binary,
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
                "participant_directories": len(PARTICIPANTS),
                "mission_artifacts": len(PARTICIPANTS),
                "identity_artifacts": len(PARTICIPANTS),
                "store_artifacts": len(PARTICIPANTS),
                "publication_journal_artifacts": 1,
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
            "PYTHONHOME",
            "PYTHONPATH",
        } or any(
            key.startswith(prefix)
            for prefix in ("GIT_CONFIG_KEY_", "GIT_CONFIG_VALUE_", "DYLD_", "LD_")
        ):
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
            "LC_ALL": "C",
            "LANG": "C",
            "PATH": os.confstr("CS_PATH") or "/bin:/usr/bin",
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
    return {
        "schema": SCHEMA,
        "status": "pass",
        "claim": CLAIM,
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
            "argv_redacted": ["<raw-root>/binary/aster-live-event-acceptance", "<raw-root>"],
            "exact_argv_sha256": sha256_bytes(canonical_json_bytes(run["run_argv"])),
            "exit_code": 0,
            "timeout_seconds": RUN_TIMEOUT_SECONDS,
            "processes": terminal["processes"],
            "stdout": {
                "bytes": run["artifacts"]["stdout"]["bytes"],
                "sha256": run["artifacts"]["stdout"]["sha256"],
                "lines": terminal["lines"],
                "ready_records": terminal["ready_records"],
                "contact_records": terminal["contact_records"],
                "stop_records": terminal["stop_records"],
                "child_coordination_records": terminal["child_coordination_records"],
                "identifiers_paths_ports_pids": terminal["identifiers_paths_ports_pids"],
            },
            "stderr": {
                "bytes": run["artifacts"]["stderr"]["bytes"],
                "sha256": run["artifacts"]["stderr"]["sha256"],
                "classification": "exact-bounded-numbered-publication-diagnostics",
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
            "actor_lifetimes": transcript["actor_lifetimes"],
            "maximum_concurrent_actors": transcript["maximum_concurrent_actors"],
            "graceful_shutdowns": transcript["shutdowns"],
            "forced_process_terminations": transcript["forced_process_terminations"],
            "distinct_carrier_ids": 2,
            "distinct_mission_ids": 2,
            "common_disjoint_mission_authority": True,
            "reciprocal_cross_peer_binding": "carrier-and-mission-verified",
            "live_handle_identity_authority_binding": "verified",
            "runtime_ready_contact_stop_identity_binding": "verified",
            "connected_path": "positive-direct-only-zero-errors",
            "connected_reconciliation": terminal["reconciliation"],
            "event": {
                "publications": transcript["events_published"],
                "alpha_publications": transcript["alpha_events"],
                "authorized_unsubscribed_beta_publications": transcript[
                    "authorized_unsubscribed_events"
                ],
                "durability": "all-durable",
                "payload_representation": "sha256-only",
                "exact_noninserting_publication_retries": transcript[
                    "publication_retries"
                ],
                "changed_intent_rejections_preserving_publication": transcript[
                    "changed_intent_rejections"
                ],
                "peerless_initial_queries": {
                "alpha_items": 3,
                "beta_items": 1,
                "acceptance_markers": 4,
                },
            },
            "status": {
                "offline_observations": 3,
                "awaiting_authenticated_contact_observations": 2,
                "awaiting_failed_contact_attempts": 0,
                "work_remained_observations": 0,
                "last_contact_complete_transcript_observations": 2,
                "last_contact_complete_child_coordination_observations": 1,
                "policy_changed_since_contact_observations": 1,
                "peer_authorization": "active",
                "per_peer_contact_count": 1,
            },
            "priority_threshold_contact": {
                "authenticated_direct_contact": True,
                "status": "last_contact_complete-for-negotiated-priority-policy",
                "delivered_alpha_sequences": [1, 3],
                "delivered_priorities": ["priority", "flash"],
                "delivery_attempt": 1,
                "withheld_alpha_sequence": 2,
                "withheld_alpha_priority": "routine",
                "authorized_unsubscribed_beta_withheld": True,
                "authenticated_gap": [2, 3],
            },
            "forced_receiver_termination": {
                "mechanism": "parent-child-kill",
                "after_flushed_durable_poll": True,
                "graceful": False,
                "stop_record_expected": False,
                "pretermination_acknowledged": False,
            },
            "fresh_process_redelivery": {
                "delivery_attempt": 2,
                "same_event_identifiers": True,
                "alpha_sequences": [1, 3],
                "acknowledgements": 2,
                "idempotent_reacknowledgements": 2,
                "empty_poll_after_acknowledgement": True,
                "durable_subscription_replayed": True,
            },
            "normal_gap_closure": {
                "precontact_empty_poll": True,
                "fresh_contact_status": "last_contact_complete",
                "gap_before_closure": [2, 3],
                "gap_after_contact": "closed-through-3",
                "delivered_alpha_sequence": 2,
                "delivery_attempt": 1,
                "acknowledged": True,
                "idempotent_reacknowledgement": True,
                "alpha_query_items": 3,
                "authorized_beta_query_items": 0,
                "beta_subscription_inserted": True,
                "post_selector_change_status": "policy_changed_since_contact",
                "beta_subscription_removal": "removed-then-already-absent",
                "post_policy_fresh_contact": "not-observed",
                "beta_delivery": "not-observed",
            },
            "final_peerless_reopen": {
                "alpha_subscription_replayed": True,
                "status": "offline",
                "gap": "closed-through-3",
                "empty_poll": True,
                "alpha_query_items": 3,
                "beta_query_items": 0,
                "closed_retained_handle": True,
            },
            "deliveries": transcript["deliveries"],
            "acknowledgements": transcript["acknowledgements"],
            "idempotent_reacknowledgements": transcript[
                "idempotent_reacknowledgements"
            ],
            "empty_polls": transcript["empty_polls"],
            "queries": transcript["queries"],
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


def render_receipt(
    document: dict[str, Any],
    *,
    forbidden_values: Iterable[str] = (),
    forbidden_pids: Iterable[int] = (),
    forbidden_ports: Iterable[int] = (),
) -> bytes:
    # Retain these inputs for call-site compatibility and audit extraction, but
    # do not compare ephemeral PID/port numbers with arbitrary receipt scalars:
    # legitimate byte and count fields may have the same numeric value. The
    # fixed projection plus the explicit field/socket/path checks below exclude
    # the runtime coordinates themselves.
    del forbidden_pids, forbidden_ports
    encoded = canonical_json_bytes(document)
    if len(encoded) > RECEIPT_MAX_BYTES:
        fail("sanitized receipt exceeds the 16 KiB output cap")
    forbidden = (
        b"/private/", b"/Users/", b"127.0.0.1:",
        b'"pid"', b'"port"',
    )
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
    parser.add_argument("--historical-v1", action="store_true", help="verify or project the unchanged historical v1 format")
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
    selected_arguments = list(sys.argv[1:] if arguments is None else arguments)
    if "--historical-v1" in selected_arguments:
        import importlib.util
        selected_arguments.remove("--historical-v1")
        path = Path(__file__).parent / "historical" / Path(__file__).name
        spec = importlib.util.spec_from_file_location("aster_historical_receipt", path)
        if spec is None or spec.loader is None:
            raise RuntimeError("historical receipt validator unavailable")
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        module.main(selected_arguments)
        return
    options = parse_args(selected_arguments)
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
        print(f"selected live Event receipt validation failed: {error}", file=sys.stderr)
        raise SystemExit(1) from error


if __name__ == "__main__":
    main()
