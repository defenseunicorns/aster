#!/usr/bin/env python3
# Copyright 2026 Defense Unicorns, Inc.
# SPDX-License-Identifier: Apache-2.0
"""Project or validate one retained peerless Blob-subscription receipt.

The raw root is one owner-only, exact-inventory acceptance artifact.  Public
runtime output and the selected transcript are validated semantically.  The
mission bundle, identity key, redb store, Blob-depot owner marker, and encrypted
chunk are inspected by metadata only and are never opened, read, or hashed.

The exact delegated-support bytes loaded by this checker are cross-checked
against the signed admitted source before evidence is accepted.  As with any
in-checkout verifier, the top-level checker, its delegated support, and the
Python environment remain trusted at launch.
"""

from __future__ import annotations

import argparse
from dataclasses import dataclass
import hashlib
import os
from pathlib import Path, PurePosixPath
import re
import stat
import sys
import types
from typing import Any, Iterable


def _read_source_without_bytecode(path: Path) -> bytes:
    before = path.lstat()
    if (
        not stat.S_ISREG(before.st_mode)
        or stat.S_ISLNK(before.st_mode)
        or before.st_nlink != 1
        or not 0 < before.st_size <= 4 * 1024 * 1024
    ):
        raise RuntimeError(f"unsafe checker support source {path}")
    descriptor = os.open(
        path,
        os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0),
    )
    try:
        opened = os.fstat(descriptor)
        if (opened.st_dev, opened.st_ino, opened.st_size) != (
            before.st_dev,
            before.st_ino,
            before.st_size,
        ):
            raise RuntimeError(f"checker support changed while opening {path}")
        chunks: list[bytes] = []
        remaining = opened.st_size
        while remaining:
            chunk = os.read(descriptor, min(64 * 1024, remaining))
            if not chunk:
                raise RuntimeError(f"checker support truncated while reading {path}")
            chunks.append(chunk)
            remaining -= len(chunk)
        if os.read(descriptor, 1):
            raise RuntimeError(f"checker support grew while reading {path}")
        final = os.fstat(descriptor)
        terminal = path.lstat()
        if (final.st_dev, final.st_ino, final.st_size) != (
            opened.st_dev,
            opened.st_ino,
            opened.st_size,
        ) or (terminal.st_dev, terminal.st_ino, terminal.st_size) != (
            before.st_dev,
            before.st_ino,
            before.st_size,
        ):
            raise RuntimeError(f"checker support changed while reading {path}")
        return b"".join(chunks)
    finally:
        os.close(descriptor)


def _load_support(filename: str, module_name: str) -> types.ModuleType:
    path = Path(__file__).with_name(filename)
    source = _read_source_without_bytecode(path)
    module = types.ModuleType(module_name)
    module.__file__ = os.fspath(path)
    module.__package__ = ""
    module.__loaded_source_sha256__ = hashlib.sha256(source).hexdigest()
    sys.modules[module_name] = module
    try:
        code = compile(source, os.fspath(path), "exec", dont_inherit=True, optimize=0)
        exec(code, module.__dict__)
    except BaseException:
        sys.modules.pop(module_name, None)
        raise
    return module


RUNNER = _load_support(
    "run-selected-live-blob-subscription.py",
    "selected_live_blob_subscription_runner_contract",
)
SUPPORT = _load_support(
    "check-selected-live-event-receipt.py",
    "selected_live_blob_subscription_checker_support",
)

SCHEMA = "aster-selected-live-blob-subscription-receipt/v1"
RAW_SCHEMA = RUNNER.RAW_SCHEMA
TRANSCRIPT_SCHEMA = "aster-selected-live-blob-subscription-transcript/v1"
CLAIM = RUNNER.CLAIM
RECEIPT_NAME = "selected-live-blob-subscription-receipt.json"
RECEIPT_MAX_BYTES = 16 * 1024
TRANSCRIPT_RECORDS = RUNNER.TRANSCRIPT_RECORDS
RUN_TIMEOUT_SECONDS = RUNNER.RUN_TIMEOUT_SECONDS
BINARY_NAME = RUNNER.BINARY_NAME
PARTICIPANTS = RUNNER.PARTICIPANTS
ADMITTED_SOURCE_PATHS = RUNNER.ADMITTED_PATHS
TOOL_PATHS = RUNNER.TOOL_PATHS
EXPECTED_BUILD_ARGV = RUNNER.BUILD_ARGV
RUNNER_PATH = RUNNER.RUNNER_PATH
CHECKER_PATH = RUNNER.CHECKER_PATH
RUNNER_SUPPORT_PATH = RUNNER.RUNNER_SUPPORT_PATH
CHECKER_SUPPORT_PATH = RUNNER.CHECKER_SUPPORT_PATH

TRANSCRIPT_PREFIX = "LIVE_BLOB_SUBSCRIPTION"
CHILD_PREFIX = "LIVE_BLOB_SUBSCRIPTION_CHILD"
HEX_32 = re.compile(r"[0-9a-f]{64}\Z")
FIELD_NAME = re.compile(r"[a-z][a-z0-9_]*\Z")
LOOPBACK_SOCKET = re.compile(r"127[.]0[.]0[.]1:([1-9][0-9]{0,4})\Z")
VARIANT_DIRECTORY = re.compile(r"[0-9a-f]{64}\Z")
CHUNK_FILE = "00000000000000000000.chunk"

TOPIC = "opaque"
OTHER_TOPIC = "opaque.beta"
ROOT_SCOPE = "test/runtime-contact"
DESCENDANT_SCOPE = "test/runtime-contact/withheld"
MEDIA_TYPE = "application/x-aster-live-blob-subscription-acceptance"
SCHEMA_SHA256 = hashlib.sha256(b"acceptance/live-blob-subscription-v1").hexdigest()
PAYLOAD = b"shared immutable Blob delivery payload"
PAYLOAD_SHA256 = hashlib.sha256(PAYLOAD).hexdigest()
PAYLOAD_BYTES = len(PAYLOAD)
SEALED_SOURCE_BYTES = 22_022
TOKEN_BYTES = 57
DELIVERY_LIMIT = 1
SCAN_LIMIT = 16
OWNER_MARKER_BYTES = 72
CHUNK_FILE_OVERHEAD = 169
COMMITTED_CIPHERTEXT_BYTES = PAYLOAD_BYTES + CHUNK_FILE_OVERHEAD


def _words(value: str) -> tuple[str, ...]:
    return tuple(value.split())


RUN_KEYS = _words(
    """schema claim participants processes actor_lifetimes
    maximum_concurrent_processes maximum_concurrent_actors phases topic root_scope
    delivery_limit scan_limit token_bytes"""
)
PARTICIPANT_KEYS = _words(
    "participant carrier_id mission_id mission_authority provisioning"
)
PHASE_KEYS = _words("phase name actors outcome")
SUBSCRIPTION_KEYS = _words(
    "phase participant id inserted topic scope include_descendant_scopes"
)
SUBSCRIPTION_CONFLICT_KEYS = _words(
    "phase participant kind operation changed_descendants rejected"
)
PUBLICATION_KEYS = _words(
    """phase participant label blob_id publisher counter topic scope priority total_len
    media_type schema_sha256 payload_sha256 acceptance_marker inserted"""
)
STATUS_KEYS = _words(
    """phase participant subscriptions pending_deliveries
    acknowledged_deliveries delivery_cursors selector_generation"""
)
RECEIPT_KEYS = _words(
    """phase participant contacts contact_errors direct_contacts relay_contacts
    unknown_path_contacts data_offered data_fetched data_inserted data_duplicates
    data_remaining mutable_remaining deferred_mutable_lanes blob_ranges_fetched
    blob_bytes_fetched blob_remaining blob_deferred blobs blob_acceptance_markers
    blob_last_acceptance_marker blob_operations blob_variants
    blob_finalized_variants blob_committed_chunks blob_committed_file_bytes
    blob_reserved_file_bytes pending_blobs blob_carrier_prefixes
    blob_network_staging_bytes events controls"""
)
DELIVERY_KEYS = _words(
    """phase participant label subscription_id publication_id blob_id publisher
    counter topic scope priority total_len media_type schema_sha256
    acceptance_marker attempt token_sha256 delivery_limit scan_limit has_more
    metadata_only acknowledged"""
)
TERMINATION_KEYS = _words(
    """phase participant mechanism signal distinct_process after_flushed_poll
    graceful stop_record_observed acknowledged token_persisted token_artifact_mode
    token_artifact_fsynced"""
)
TOKEN_CHECK_KEYS = _words(
    """phase label token_bytes attempt_tokens_distinct previous_token_restored
    malformed_token_rejected wrong_publication_token_rejected
    token_artifact_removed"""
)
ACK_KEYS = _words(
    """phase participant label publication_id ack reack ack_token_attempt
    reack_token_attempt"""
)
EMPTY_POLL_KEYS = _words("phase participant label deliveries has_more")
INSPECTION_KEYS = _words(
    """participant blob_publications blob_acceptance_markers blob_operations
    blob_variants blob_finalized_variants blob_committed_chunks
    blob_committed_file_bytes blob_reserved_file_bytes subscriptions
    pending_deliveries acknowledged_deliveries delivery_cursors
    selector_generation other_namespaces_empty pending_blobs carrier_prefixes
    network_staging_bytes"""
)
CLOSED_HANDLE_KEYS = _words("phase participant operation kind")
BIND_KEYS = _words("participant reacquired")
RESULT_KEYS = _words(
    """status records phases participants processes actor_lifetimes
    maximum_concurrent_processes maximum_concurrent_actors graceful_shutdowns
    forced_process_terminations blob_publications matching_publications
    withheld_publications unique_deliveries delivery_attempts polls
    acknowledgements reacknowledgements subscription_insertions
    subscription_replays token_binding_checks empty_polls status_observations
    bind_reacquisitions payload_representation token_representation
    opaque_tokens_emitted secret_values_emitted network_contact_claimed
    peer_status_claimed selector_withholding_claimed
    network_interest_separation_claimed long_retention_claimed"""
)

EXPECTED_SEQUENCE: tuple[tuple[str, tuple[str, ...]], ...] = (
    ("RUN", RUN_KEYS),
    ("PARTICIPANT", PARTICIPANT_KEYS),
    ("PHASE", PHASE_KEYS),
    ("SUBSCRIPTION", SUBSCRIPTION_KEYS),
    ("SUBSCRIPTION", SUBSCRIPTION_KEYS),
    ("SUBSCRIPTION_CONFLICT", SUBSCRIPTION_CONFLICT_KEYS),
    ("PUBLICATION", PUBLICATION_KEYS),
    ("PUBLICATION", PUBLICATION_KEYS),
    ("STATUS", STATUS_KEYS),
    ("RECEIPT", RECEIPT_KEYS),
    ("PHASE", PHASE_KEYS),
    ("SUBSCRIPTION", SUBSCRIPTION_KEYS),
    ("DELIVERY", DELIVERY_KEYS),
    ("STATUS", STATUS_KEYS),
    ("PROCESS_TERMINATION", TERMINATION_KEYS),
    ("PHASE", PHASE_KEYS),
    ("SUBSCRIPTION", SUBSCRIPTION_KEYS),
    ("DELIVERY", DELIVERY_KEYS),
    ("TOKEN_CHECKS", TOKEN_CHECK_KEYS),
    ("ACKNOWLEDGEMENT", ACK_KEYS),
    ("DELIVERY", DELIVERY_KEYS),
    ("TOKEN_CHECKS", TOKEN_CHECK_KEYS),
    ("ACKNOWLEDGEMENT", ACK_KEYS),
    ("EMPTY_POLL", EMPTY_POLL_KEYS),
    ("STATUS", STATUS_KEYS),
    ("RECEIPT", RECEIPT_KEYS),
    ("PHASE", PHASE_KEYS),
    ("SUBSCRIPTION", SUBSCRIPTION_KEYS),
    ("EMPTY_POLL", EMPTY_POLL_KEYS),
    ("STATUS", STATUS_KEYS),
    ("RECEIPT", RECEIPT_KEYS),
    ("INSPECTION", INSPECTION_KEYS),
    ("CLOSED_HANDLE", CLOSED_HANDLE_KEYS),
    ("BIND", BIND_KEYS),
    ("RESULT", RESULT_KEYS),
)

PHASES = (
    (1, "initial_peerless", "parent", "published-and-durable"),
    (2, "forced_delivery_attempt", "attempt-one-child", "force-terminated"),
    (3, "peerless_redelivery", "attempt-two-child", "acknowledged-and-empty"),
    (4, "final_peerless_reopen", "parent", "durable-empty"),
)

LIMITATIONS = [
    "operator-attested-source-binary-execution-link-not-cryptographically-proven",
    "selected-admitted-source-list-is-not-a-complete-reproducible-build-closure",
    "one-host-peerless-same-implementation-observation",
    "participant-secret-and-ciphertext-artifacts-validated-by-metadata-only",
    "blob-publication-order-store-inspection-and-fsync-timing-are-producer-attested",
    "forced-sigkill-is-not-power-loss-or-filesystem-crash-recovery",
    "restart-observes-one-immediate-peerless-reopen-not-long-retention-compaction-or-garbage-collection",
]
NONCLAIMS = [
    "network-contact-transfer-synchronization-convergence-or-peer-status",
    "distinct-physical-hosts",
    "nat-internet-controlled-or-public-relay-path",
    "btle-carrier",
    "mixed-implementation-or-mixed-carrier-interoperability",
    "scale-beyond-one-participant",
    "resource-thresholds-or-long-duration-soak",
    "event-state-or-record-live-application-acceptance",
    "blob-plaintext-delivery-or-exact-publication-read",
    "selector-withholding-or-network-interest-separation",
    "policy-rekey-revocation-or-route-interest-mutation",
    "finite-ttl-retention-expiry-compaction-or-garbage-collection",
    "reproducible-build-or-cryptographic-source-to-execution-provenance",
    "release-acceptance-production-authorization-or-operational-readiness",
]

EXPECTED_BASE_DIRECTORIES = {
    "",
    "binary",
    "participants",
    "participants/node",
    "participants/node/state",
    "participants/node/state/blob-depot-v1",
}
EXPECTED_BASE_FILES = {
    "run.json": 0o600,
    "stdout.log": 0o600,
    "stderr.log": 0o600,
    "transcript.tsv": 0o600,
    f"binary/{BINARY_NAME}": 0o700,
    "participants/node/mission.bundle": 0o600,
    "participants/node/state/identity.key": 0o600,
    "participants/node/state/mesh.redb": 0o600,
    "participants/node/state/blob-depot-v1/.aster-store-owner-v1": 0o600,
}
BASE_SECRET_FILES = {
    "participants/node/mission.bundle",
    "participants/node/state/identity.key",
    "participants/node/state/mesh.redb",
    "participants/node/state/blob-depot-v1/.aster-store-owner-v1",
}


@dataclass(frozen=True)
class OutputDestination:
    path: Path
    parent_fd: int
    parent_identity: tuple[int, int, int, int]


ReceiptViolation = SUPPORT.ReceiptViolation
fail = SUPPORT.fail
sha256_bytes = SUPPORT.sha256_bytes
canonical_json_bytes = SUPPORT.canonical_json_bytes
parse_uint = SUPPORT.parse_uint
require_id = SUPPORT.require_id
require_fixed = SUPPORT.require_fixed
encoded_path = SUPPORT.encoded_path


def _configure_support() -> None:
    values = {
        "SCHEMA": SCHEMA,
        "RAW_SCHEMA": RAW_SCHEMA,
        "TRANSCRIPT_SCHEMA": TRANSCRIPT_SCHEMA,
        "CLAIM": CLAIM,
        "RECEIPT_NAME": RECEIPT_NAME,
        "RECEIPT_MAX_BYTES": RECEIPT_MAX_BYTES,
        "TRANSCRIPT_RECORDS": TRANSCRIPT_RECORDS,
        "RUN_TIMEOUT_SECONDS": RUN_TIMEOUT_SECONDS,
        "BINARY_NAME": BINARY_NAME,
        "PARTICIPANTS": PARTICIPANTS,
        "ADMITTED_SOURCE_PATHS": ADMITTED_SOURCE_PATHS,
        "TOOL_PATHS": TOOL_PATHS,
        "EXPECTED_BUILD_ARGV": EXPECTED_BUILD_ARGV,
        "LIMITATIONS": LIMITATIONS,
        "NONCLAIMS": NONCLAIMS,
    }
    for name, value in values.items():
        setattr(SUPPORT, name, value)
    SUPPORT.EXPECTED_DIRECTORIES = set(EXPECTED_BASE_DIRECTORIES)
    SUPPORT.EXPECTED_FILES = dict(EXPECTED_BASE_FILES)
    SUPPORT.SECRET_FILES = set(BASE_SECRET_FILES)


_configure_support()


def parse_record(
    line: str,
    expected_type: str,
    expected_keys: tuple[str, ...],
    index: int,
) -> dict[str, str]:
    parts = line.split("\t")
    label = f"transcript record {index + 1}"
    if (
        len(parts) != len(expected_keys) + 2
        or parts[:2] != [TRANSCRIPT_PREFIX, expected_type.lower()]
    ):
        fail(f"{label} has an unexpected type, delimiter, or field count")
    record: dict[str, str] = {}
    ordered: list[str] = []
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
            fail(f"{label} contains a malformed field")
        ordered.append(key)
        record[key] = value
    if tuple(ordered) != expected_keys:
        fail(f"{label} has missing, extra, or reordered fields")
    return record


def _require_digest(value: str, label: str) -> str:
    if HEX_32.fullmatch(value) is None:
        fail(f"{label} is not one canonical SHA-256 digest")
    return value


def _validate_status(
    record: dict[str, str], phase: str, counts: tuple[int, int, int, int, int]
) -> None:
    subscriptions, pending, acknowledgements, cursors, generation = counts
    require_fixed(
        record,
        {
            "phase": phase,
            "participant": "node",
            "subscriptions": str(subscriptions),
            "pending_deliveries": str(pending),
            "acknowledged_deliveries": str(acknowledgements),
            "delivery_cursors": str(cursors),
            "selector_generation": str(generation),
        },
        f"STATUS {phase}",
    )


def _validate_receipt(record: dict[str, str], phase: str) -> None:
    require_fixed(
        record,
        {
            "phase": phase,
            "participant": "node",
            "contacts": "0",
            "contact_errors": "0",
            "direct_contacts": "0",
            "relay_contacts": "0",
            "unknown_path_contacts": "0",
            "data_offered": "0",
            "data_fetched": "0",
            "data_inserted": "0",
            "data_duplicates": "0",
            "data_remaining": "0",
            "mutable_remaining": "0",
            "deferred_mutable_lanes": "0",
            "blob_ranges_fetched": "0",
            "blob_bytes_fetched": "0",
            "blob_remaining": "0",
            "blob_deferred": "0",
            "blobs": "2",
            "blob_acceptance_markers": "2",
            "blob_last_acceptance_marker": "2",
            "blob_operations": "2",
            "blob_variants": "1",
            "blob_finalized_variants": "1",
            "blob_committed_chunks": "1",
            "blob_committed_file_bytes": str(COMMITTED_CIPHERTEXT_BYTES),
            "blob_reserved_file_bytes": str(COMMITTED_CIPHERTEXT_BYTES),
            "pending_blobs": "0",
            "blob_carrier_prefixes": "0",
            "blob_network_staging_bytes": "0",
            "events": "0",
            "controls": "0",
        },
        f"RECEIPT {phase}",
    )


def validate_transcript(data: bytes) -> dict[str, Any]:
    if not data or len(data) > SUPPORT.TRANSCRIPT_MAX_BYTES or not data.endswith(b"\n"):
        fail("transcript is empty, truncated, or exceeds its byte cap")
    if b"\x00" in data or b"\r" in data:
        fail("transcript contains a forbidden control encoding")
    try:
        text = data.decode("ascii", errors="strict")
    except UnicodeDecodeError:
        fail("transcript is not canonical ASCII")
    lines = text.splitlines()
    if len(lines) != TRANSCRIPT_RECORDS or len(EXPECTED_SEQUENCE) != TRANSCRIPT_RECORDS:
        fail(f"transcript does not contain exactly {TRANSCRIPT_RECORDS} records")
    if any(not line or len(line.encode("ascii")) > 16 * 1024 for line in lines):
        fail("transcript contains an empty or overlong record")
    records = [
        parse_record(lines[index], kind, keys, index)
        for index, (kind, keys) in enumerate(EXPECTED_SEQUENCE)
    ]

    require_fixed(
        records[0],
        {
            "schema": TRANSCRIPT_SCHEMA,
            "claim": CLAIM,
            "participants": "1",
            "processes": "3",
            "actor_lifetimes": "4",
            "maximum_concurrent_processes": "2",
            "maximum_concurrent_actors": "1",
            "phases": "4",
            "topic": TOPIC,
            "root_scope": ROOT_SCOPE,
            "delivery_limit": str(DELIVERY_LIMIT),
            "scan_limit": str(SCAN_LIMIT),
            "token_bytes": str(TOKEN_BYTES),
        },
        "RUN",
    )

    participant = records[1]
    require_fixed(
        participant,
        {"participant": "node", "provisioning": "one-node-bundle"},
        "PARTICIPANT",
    )
    for key in ("carrier_id", "mission_id", "mission_authority"):
        require_id(participant[key], f"PARTICIPANT.{key}")
    if len({participant[key] for key in ("carrier_id", "mission_id", "mission_authority")}) != 3:
        fail("participant carrier, mission, and authority identity domains are not disjoint")

    for index, expected in zip((2, 10, 15, 26), PHASES, strict=True):
        number, name, actors, outcome = expected
        require_fixed(
            records[index],
            {
                "phase": str(number),
                "name": name,
                "actors": actors,
                "outcome": outcome,
            },
            f"PHASE {number}",
        )

    subscription_id = records[3]["id"]
    require_id(subscription_id, "SUBSCRIPTION.id")
    for ordinal, (index, phase) in enumerate(
        ((3, "initial_peerless"), (4, "initial_peerless"),
         (11, "forced_delivery_attempt"), (16, "peerless_redelivery"),
         (27, "final_peerless_reopen"))
    ):
        require_fixed(
            records[index],
            {
                "phase": phase,
                "participant": "node",
                "id": subscription_id,
                "inserted": "true" if ordinal == 0 else "false",
                "topic": TOPIC,
                "scope": ROOT_SCOPE,
                "include_descendant_scopes": "false",
            },
            f"SUBSCRIPTION {ordinal + 1}",
        )
    require_fixed(
        records[5],
        {
            "phase": "initial_peerless",
            "participant": "node",
            "kind": "conflict",
            "operation": "blob_subscribe",
            "changed_descendants": "true",
            "rejected": "true",
        },
        "SUBSCRIPTION_CONFLICT",
    )

    publication_specs = (
        (6, "matching-a", TOPIC, ROOT_SCOPE, "priority", 1),
        (7, "matching-b", TOPIC, ROOT_SCOPE, "immediate", 2),
    )
    publications: dict[str, dict[str, str]] = {}
    shared_blob_id = records[6]["blob_id"]
    require_id(shared_blob_id, "PUBLICATION matching-a.blob_id")
    for index, label, topic, scope, priority, counter in publication_specs:
        record = records[index]
        require_id(record["blob_id"], f"PUBLICATION {label}.blob_id")
        _require_digest(record["schema_sha256"], f"PUBLICATION {label}.schema_sha256")
        _require_digest(record["payload_sha256"], f"PUBLICATION {label}.payload_sha256")
        require_fixed(
            record,
            {
                "phase": "initial_peerless",
                "participant": "node",
                "label": label,
                "blob_id": shared_blob_id,
                "publisher": participant["mission_id"],
                "counter": str(counter),
                "topic": topic,
                "scope": scope,
                "priority": priority,
                "total_len": str(PAYLOAD_BYTES),
                "media_type": MEDIA_TYPE,
                "schema_sha256": SCHEMA_SHA256,
                "payload_sha256": PAYLOAD_SHA256,
                "acceptance_marker": str(counter),
                "inserted": "true",
            },
            f"PUBLICATION {label}",
        )
        publications[label] = record

    _validate_status(records[8], "initial_peerless", (1, 0, 0, 0, 1))
    _validate_receipt(records[9], "initial_peerless")
    _validate_status(records[13], "forced_delivery_attempt", (1, 1, 0, 1, 1))
    _validate_status(records[24], "peerless_redelivery", (1, 0, 2, 2, 1))
    _validate_receipt(records[25], "peerless_redelivery")
    _validate_status(records[29], "final_peerless_reopen", (1, 0, 2, 2, 1))
    _validate_receipt(records[30], "final_peerless_reopen")

    delivery_specs = (
        (12, "matching-a", "forced_delivery_attempt", "matching-a", 1, "true"),
        (17, "matching-a-retry", "peerless_redelivery", "matching-a", 2, "true"),
        (20, "matching-b", "peerless_redelivery", "matching-b", 1, "false"),
    )
    deliveries: dict[str, dict[str, str]] = {}
    for index, label, phase, publication_label, attempt, has_more in delivery_specs:
        record = records[index]
        publication = publications[publication_label]
        require_id(record["subscription_id"], f"DELIVERY {label}.subscription_id")
        require_id(record["publication_id"], f"DELIVERY {label}.publication_id")
        require_id(record["blob_id"], f"DELIVERY {label}.blob_id")
        _require_digest(record["token_sha256"], f"DELIVERY {label}.token_sha256")
        require_fixed(
            record,
            {
                "phase": phase,
                "participant": "node",
                "label": label,
                "subscription_id": subscription_id,
                "blob_id": shared_blob_id,
                "publisher": participant["mission_id"],
                "counter": publication["counter"],
                "topic": TOPIC,
                "scope": ROOT_SCOPE,
                "priority": publication["priority"],
                "total_len": str(PAYLOAD_BYTES),
                "media_type": MEDIA_TYPE,
                "schema_sha256": SCHEMA_SHA256,
                "acceptance_marker": publication["acceptance_marker"],
                "attempt": str(attempt),
                "delivery_limit": str(DELIVERY_LIMIT),
                "scan_limit": str(SCAN_LIMIT),
                "has_more": has_more,
                "metadata_only": "true",
                "acknowledged": "false",
            },
            f"DELIVERY {label}",
        )
        deliveries[label] = record

    attempt_one = deliveries["matching-a"]
    retry = deliveries["matching-a-retry"]
    matching_b = deliveries["matching-b"]
    if attempt_one["publication_id"] != retry["publication_id"]:
        fail("matching-a redelivery changed exact publication identity")
    if matching_b["publication_id"] == attempt_one["publication_id"]:
        fail("two source publications sharing one BlobId reused a publication identity")
    token_hashes = {
        attempt_one["token_sha256"],
        retry["token_sha256"],
        matching_b["token_sha256"],
    }
    if len(token_hashes) != 3:
        fail("delivery attempts did not use three distinct token commitments")

    require_fixed(
        records[14],
        {
            "phase": "forced_delivery_attempt",
            "participant": "node",
            "mechanism": "parent-child-kill",
            "signal": "sigkill",
            "distinct_process": "true",
            "after_flushed_poll": "true",
            "graceful": "false",
            "stop_record_observed": "false",
            "acknowledged": "false",
            "token_persisted": "true",
            "token_artifact_mode": "0600",
            "token_artifact_fsynced": "true",
        },
        "PROCESS_TERMINATION",
    )
    require_fixed(
        records[18],
        {
            "phase": "peerless_redelivery",
            "label": "retry",
            "token_bytes": str(TOKEN_BYTES),
            "attempt_tokens_distinct": "true",
            "previous_token_restored": "true",
            "malformed_token_rejected": "true",
            "wrong_publication_token_rejected": "false",
            "token_artifact_removed": "false",
        },
        "TOKEN_CHECKS retry",
    )
    require_fixed(
        records[21],
        {
            "phase": "peerless_redelivery",
            "label": "binding",
            "token_bytes": str(TOKEN_BYTES),
            "attempt_tokens_distinct": "true",
            "previous_token_restored": "true",
            "malformed_token_rejected": "true",
            "wrong_publication_token_rejected": "true",
            "token_artifact_removed": "true",
        },
        "TOKEN_CHECKS binding",
    )
    for index, label, delivery, ack_attempt, reack_attempt in (
        (19, "matching-a", retry, 1, 2),
        (22, "matching-b", matching_b, 1, 1),
    ):
        require_fixed(
            records[index],
            {
                "phase": "peerless_redelivery",
                "participant": "node",
                "label": label,
                "publication_id": delivery["publication_id"],
                "ack": "acknowledged",
                "reack": "already_acknowledged",
                "ack_token_attempt": str(ack_attempt),
                "reack_token_attempt": str(reack_attempt),
            },
            f"ACKNOWLEDGEMENT {label}",
        )

    for index, phase, label in (
        (23, "peerless_redelivery", "post-acknowledgement"),
        (28, "final_peerless_reopen", "durable-empty"),
    ):
        require_fixed(
            records[index],
            {
                "phase": phase,
                "participant": "node",
                "label": label,
                "deliveries": "0",
                "has_more": "false",
            },
            f"EMPTY_POLL {label}",
        )

    require_fixed(
        records[31],
        {
            "participant": "node",
            "blob_publications": "2",
            "blob_acceptance_markers": "2",
            "blob_operations": "2",
            "blob_variants": "1",
            "blob_finalized_variants": "1",
            "blob_committed_chunks": "1",
            "blob_committed_file_bytes": str(COMMITTED_CIPHERTEXT_BYTES),
            "blob_reserved_file_bytes": str(COMMITTED_CIPHERTEXT_BYTES),
            "subscriptions": "1",
            "pending_deliveries": "0",
            "acknowledged_deliveries": "2",
            "delivery_cursors": "2",
            "selector_generation": "1",
            "other_namespaces_empty": "true",
            "pending_blobs": "0",
            "carrier_prefixes": "0",
            "network_staging_bytes": "0",
        },
        "INSPECTION",
    )
    require_fixed(
        records[32],
        {
            "phase": "final_peerless_reopen",
            "participant": "node",
            "operation": "blob_delivery_status",
            "kind": "state_unavailable",
        },
        "CLOSED_HANDLE",
    )
    require_fixed(records[33], {"participant": "node", "reacquired": "true"}, "BIND")
    require_fixed(
        records[34],
        {
            "status": "pass",
            "records": "35",
            "phases": "4",
            "participants": "1",
            "processes": "3",
            "actor_lifetimes": "4",
            "maximum_concurrent_processes": "2",
            "maximum_concurrent_actors": "1",
            "graceful_shutdowns": "3",
            "forced_process_terminations": "1",
            "blob_publications": "2",
            "matching_publications": "2",
            "withheld_publications": "0",
            "unique_deliveries": "2",
            "delivery_attempts": "3",
            "polls": "5",
            "acknowledgements": "2",
            "reacknowledgements": "2",
            "subscription_insertions": "1",
            "subscription_replays": "4",
            "token_binding_checks": "2",
            "empty_polls": "2",
            "status_observations": "4",
            "bind_reacquisitions": "1",
            "payload_representation": "sha256-only",
            "token_representation": "sha256-only",
            "opaque_tokens_emitted": "false",
            "secret_values_emitted": "false",
            "network_contact_claimed": "false",
            "peer_status_claimed": "false",
            "selector_withholding_claimed": "false",
            "network_interest_separation_claimed": "false",
            "long_retention_claimed": "false",
        },
        "RESULT",
    )

    sensitive = {
        participant["carrier_id"], participant["mission_id"],
        participant["mission_authority"], subscription_id, shared_blob_id,
        attempt_one["publication_id"], matching_b["publication_id"], *token_hashes,
    }
    return {
        "records": 35,
        "bytes": len(data),
        "sha256": sha256_bytes(data),
        "participants": 1,
        "processes": 3,
        "actor_lifetimes": 4,
        "maximum_concurrent_processes": 2,
        "maximum_concurrent_actors": 1,
        "phases": 4,
        "graceful_shutdowns": 3,
        "forced_process_terminations": 1,
        "blob_publications": 2,
        "matching_publications": 2,
        "withheld_publications": 0,
        "unique_deliveries": 2,
        "delivery_attempts": 3,
        "polls": 5,
        "acknowledgements": 2,
        "reacknowledgements": 2,
        "subscription_insertions": 1,
        "subscription_replays": 4,
        "token_binding_checks": 2,
        "token_bytes": TOKEN_BYTES,
        "empty_polls": 2,
        "status_observations": 4,
        "bind_reacquisitions": 1,
        "delivery_limit": DELIVERY_LIMIT,
        "scan_limit": SCAN_LIMIT,
        "_participant": participant,
        "_subscription_id": subscription_id,
        "_publications": publications,
        "_shared_blob_id": shared_blob_id,
        "_attempt_one": attempt_one,
        "_retry": retry,
        "_matching_b": matching_b,
        "_token_hashes": sorted(token_hashes),
        "_application_ids": sorted(sensitive),
    }


ATTEMPT_ONE_CHILD_KEYS = _words(
    """participant identity subscription_id subscription_inserted publication_id
    blob_id publisher counter topic scope priority total_len media_type
    schema_sha256 acceptance_marker attempt token_sha256 delivery_limit scan_limit
    has_more metadata_only acknowledged token_persisted subscriptions
    pending_deliveries acknowledged_deliveries delivery_cursors
    selector_generation"""
)
ATTEMPT_TWO_CHILD_KEYS = _words(
    """participant identity subscription_id subscription_inserted
    retry_publication_id retry_blob_id retry_publisher retry_counter retry_topic
    retry_scope retry_priority retry_total_len retry_media_type
    retry_schema_sha256 retry_acceptance_marker retry_attempt retry_token_sha256
    previous_token_sha256 tokens_distinct previous_token_restored
    malformed_token_rejected first_ack first_reack first_ack_token_attempt
    first_reack_token_attempt second_publication_id second_blob_id
    second_publisher second_counter second_topic second_scope second_priority
    second_total_len second_media_type second_schema_sha256
    second_acceptance_marker second_attempt second_token_sha256 same_blob_id
    distinct_publications wrong_publication_token_rejected second_ack
    second_reack second_ack_token_attempt second_reack_token_attempt empty_poll
    token_artifact_removed subscriptions
    pending_deliveries acknowledged_deliveries delivery_cursors
    selector_generation closed_kind closed_operation shutdown_contacts
    shutdown_contact_errors shutdown_direct_contacts shutdown_relay_contacts
    shutdown_unknown_path_contacts shutdown_data_offered shutdown_data_fetched
    shutdown_data_inserted shutdown_data_duplicates shutdown_data_remaining
    shutdown_mutable_remaining shutdown_deferred_mutable_lanes
    shutdown_blob_ranges_fetched shutdown_blob_bytes_fetched
    shutdown_blob_remaining shutdown_blob_deferred shutdown_blobs
    shutdown_blob_acceptance_markers shutdown_blob_last_acceptance_marker
    shutdown_blob_operations shutdown_blob_variants
    shutdown_blob_finalized_variants shutdown_blob_committed_chunks
    shutdown_blob_committed_file_bytes shutdown_blob_reserved_file_bytes
    shutdown_pending_blobs shutdown_blob_carrier_prefixes
    shutdown_blob_network_staging_bytes shutdown_events
    shutdown_controls"""
)


def _parse_child_record(line: str, label: str) -> tuple[str, dict[str, str]]:
    parts = line.split("\t")
    if len(parts) < 3 or parts[0] != CHILD_PREFIX:
        fail(f"{label} has malformed child coordination framing")
    kind = parts[1]
    expected = {
        "ATTEMPT1_READY": ATTEMPT_ONE_CHILD_KEYS,
        "ATTEMPT2_DONE": ATTEMPT_TWO_CHILD_KEYS,
    }.get(kind)
    if expected is None or len(parts) != len(expected) + 2:
        fail(f"{label} has an unexpected child coordination kind or field count")
    record: dict[str, str] = {}
    ordered: list[str] = []
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
        ordered.append(key)
        record[key] = value
    if tuple(ordered) != expected:
        fail(f"{label} has reordered, missing, or extra child coordination fields")
    return kind, record


def _delivery_child_expected(
    delivery: dict[str, str], prefix: str = ""
) -> dict[str, str]:
    mapping = {
        "publication_id": delivery["publication_id"],
        "blob_id": delivery["blob_id"],
        "publisher": delivery["publisher"],
        "counter": delivery["counter"],
        "topic": delivery["topic"],
        "scope": delivery["scope"],
        "priority": delivery["priority"],
        "total_len": delivery["total_len"],
        "media_type": delivery["media_type"],
        "schema_sha256": delivery["schema_sha256"],
        "acceptance_marker": delivery["acceptance_marker"],
        "attempt": delivery["attempt"],
        "token_sha256": delivery["token_sha256"],
    }
    return {f"{prefix}{key}": value for key, value in mapping.items()}


def _validate_attempt_one_child(
    record: dict[str, str], transcript: dict[str, Any]
) -> None:
    require_fixed(
        record,
        {
            "participant": "node",
            "identity": transcript["_participant"]["mission_id"],
            "subscription_id": transcript["_subscription_id"],
            "subscription_inserted": "false",
            **_delivery_child_expected(transcript["_attempt_one"]),
            "delivery_limit": str(DELIVERY_LIMIT),
            "scan_limit": str(SCAN_LIMIT),
            "has_more": "true",
            "metadata_only": "true",
            "acknowledged": "false",
            "token_persisted": "true",
            "subscriptions": "1",
            "pending_deliveries": "1",
            "acknowledged_deliveries": "0",
            "delivery_cursors": "1",
            "selector_generation": "1",
        },
        "ATTEMPT1_READY",
    )


def _validate_attempt_two_child(
    record: dict[str, str], transcript: dict[str, Any]
) -> None:
    retry = transcript["_retry"]
    second = transcript["_matching_b"]
    require_fixed(
        record,
        {
            "participant": "node",
            "identity": transcript["_participant"]["mission_id"],
            "subscription_id": transcript["_subscription_id"],
            "subscription_inserted": "false",
            **_delivery_child_expected(retry, "retry_"),
            "previous_token_sha256": transcript["_attempt_one"]["token_sha256"],
            "tokens_distinct": "true",
            "previous_token_restored": "true",
            "malformed_token_rejected": "true",
            "first_ack": "acknowledged",
            "first_reack": "already_acknowledged",
            "first_ack_token_attempt": "1",
            "first_reack_token_attempt": "2",
            **_delivery_child_expected(second, "second_"),
            "same_blob_id": "true",
            "distinct_publications": "true",
            "wrong_publication_token_rejected": "true",
            "second_ack": "acknowledged",
            "second_reack": "already_acknowledged",
            "second_ack_token_attempt": "1",
            "second_reack_token_attempt": "1",
            "empty_poll": "true",
            "token_artifact_removed": "true",
            "subscriptions": "1",
            "pending_deliveries": "0",
            "acknowledged_deliveries": "2",
            "delivery_cursors": "2",
            "selector_generation": "1",
            "closed_kind": "state_unavailable",
            "closed_operation": "blob_delivery_status",
            "shutdown_contacts": "0",
            "shutdown_contact_errors": "0",
            "shutdown_direct_contacts": "0",
            "shutdown_relay_contacts": "0",
            "shutdown_unknown_path_contacts": "0",
            "shutdown_data_offered": "0",
            "shutdown_data_fetched": "0",
            "shutdown_data_inserted": "0",
            "shutdown_data_duplicates": "0",
            "shutdown_data_remaining": "0",
            "shutdown_mutable_remaining": "0",
            "shutdown_deferred_mutable_lanes": "0",
            "shutdown_blob_ranges_fetched": "0",
            "shutdown_blob_bytes_fetched": "0",
            "shutdown_blob_remaining": "0",
            "shutdown_blob_deferred": "0",
            "shutdown_blobs": "2",
            "shutdown_blob_acceptance_markers": "2",
            "shutdown_blob_last_acceptance_marker": "2",
            "shutdown_blob_operations": "2",
            "shutdown_blob_variants": "1",
            "shutdown_blob_finalized_variants": "1",
            "shutdown_blob_committed_chunks": "1",
            "shutdown_blob_committed_file_bytes": str(COMMITTED_CIPHERTEXT_BYTES),
            "shutdown_blob_reserved_file_bytes": str(COMMITTED_CIPHERTEXT_BYTES),
            "shutdown_pending_blobs": "0",
            "shutdown_blob_carrier_prefixes": "0",
            "shutdown_blob_network_staging_bytes": "0",
            "shutdown_events": "0",
            "shutdown_controls": "0",
        },
        "ATTEMPT2_DONE",
    )


def _validate_stop(
    record: dict[str, str], participant: dict[str, str], label: str
) -> dict[str, int]:
    require_fixed(
        record,
        {
            "lifecycle": "complete",
            "sync_status": "no_successful_contact",
            "carrier_id": participant["carrier_id"],
            "mission_id": participant["mission_id"],
            "path_observation": "not-authorization",
            "mission_auth": "hybrid-pq",
            "provisioning": "unprotected-reference",
            "semantics": "source-authenticated-event",
            "reconciliation_classes": "event,state,record,blob-v5",
            "controls_semantics": "source-authenticated-flash",
        },
        label,
    )
    numeric = {
        key: parse_uint(record[key], f"{label}.{key}")
        for key in SUPPORT.STOP_NUMERIC_FIELDS
    }
    exact = {
        "contacts": 0,
        "contact_errors": 0,
        "direct_contacts": 0,
        "relay_contacts": 0,
        "unknown_path_contacts": 0,
        "carrier_path_transitions": 0,
        "carrier_path_transition_saturations": 0,
        "events": 0,
        "event_acceptance_markers": 0,
        "route_cached_events": 0,
        "controls": 0,
        "applied_controls": 0,
        "pending_controls": 0,
        "control_highwater": 0,
        "blobs": 2,
        "blob_acceptance_markers": 2,
        "blob_last_acceptance_marker": 2,
        "blob_sealed_bytes": SEALED_SOURCE_BYTES,
        "blob_operations": 2,
        "blob_variants": 1,
        "blob_finalized_variants": 1,
        "blob_committed_chunks": 1,
        "blob_committed_file_bytes": COMMITTED_CIPHERTEXT_BYTES,
        "blob_reserved_file_bytes": COMMITTED_CIPHERTEXT_BYTES,
        "pending_blobs": 0,
        "blob_carrier_prefixes": 0,
        "blob_carrier_fetch_cursors": 0,
        "blob_network_staging_bytes": 0,
        "blob_ranges_fetched": 0,
        "blob_bytes_fetched": 0,
        "blob_remaining": 0,
        "blob_deferred": 0,
    }
    if any(numeric[key] != value for key, value in exact.items()):
        fail(f"{label} contains non-peerless or incorrect durable Blob counters")
    if numeric["blob_operation_bytes"] <= 0:
        fail(f"{label}.blob_operation_bytes is not positive")
    return numeric


def validate_terminal_stdout(
    stdout: bytes,
    transcript: bytes,
    root: Path,
    transcript_facts: dict[str, Any],
) -> dict[str, Any]:
    if not stdout or len(stdout) > SUPPORT.STDOUT_MAX_BYTES or not stdout.endswith(b"\n"):
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
        if line.startswith(f"{TRANSCRIPT_PREFIX}\t")
    )
    if extracted != transcript:
        fail("transcript is not the exact ordered Blob-subscription extraction from stdout")

    transcript_started = False
    for line_number, line in enumerate(lines, start=1):
        if line.startswith(f"{TRANSCRIPT_PREFIX}\t"):
            transcript_started = True
        elif transcript_started:
            fail(
                f"captured stdout line {line_number} appears after the public transcript began"
            )

    runtime = [line for line in lines if not line.startswith(f"{TRANSCRIPT_PREFIX}\t")]
    if len(runtime) != 9:
        fail("captured stdout does not contain exactly four READY, three STOP, and two child records")
    expected_kinds = (
        "READY", "STOP", "READY", "ATTEMPT1_READY", "READY", "STOP",
        "ATTEMPT2_DONE", "READY", "STOP",
    )
    observed_kinds: list[str] = []
    ready: list[dict[str, str]] = []
    stops: list[dict[str, str]] = []
    children: dict[str, dict[str, str]] = {}
    participant = transcript_facts["_participant"]
    for index, line in enumerate(runtime):
        label = f"captured stdout runtime line {index + 1}"
        if line.startswith("READY "):
            observed_kinds.append("READY")
            record = SUPPORT.parse_terminal_record(line, "READY", SUPPORT.READY_KEYS, label)
            require_fixed(
                record,
                {
                    "selected": "true",
                    "carrier_id": participant["carrier_id"],
                    "mission_id": participant["mission_id"],
                    "mission_authority": participant["mission_authority"],
                    "state": encoded_path(root / "participants/node/state"),
                    "peers": "0",
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
            parse_uint(record["pid"], f"{label}.pid", positive=True)
            socket = LOOPBACK_SOCKET.fullmatch(record["sockets"])
            if socket is None or int(socket.group(1)) > 65535:
                fail(f"{label}.sockets is not one bounded loopback socket")
            ready.append(record)
        elif line.startswith("STOP "):
            observed_kinds.append("STOP")
            record = SUPPORT.parse_terminal_record(line, "STOP", SUPPORT.STOP_KEYS, label)
            _validate_stop(record, participant, label)
            stops.append(record)
        elif line.startswith(f"{CHILD_PREFIX}\t"):
            kind, record = _parse_child_record(line, label)
            if kind in children:
                fail(f"{label} duplicates one child coordination record")
            observed_kinds.append(kind)
            children[kind] = record
        else:
            fail(f"{label} has an unexpected public terminal record")
    if tuple(observed_kinds) != expected_kinds:
        fail("runtime records do not prove the required graceful/SIGKILL lifetime order")
    if set(children) != {"ATTEMPT1_READY", "ATTEMPT2_DONE"}:
        fail("runtime output lacks exact child coordination records")
    _validate_attempt_one_child(children["ATTEMPT1_READY"], transcript_facts)
    _validate_attempt_two_child(children["ATTEMPT2_DONE"], transcript_facts)

    pids = [parse_uint(record["pid"], "READY.pid", positive=True) for record in ready]
    sockets = [record["sockets"] for record in ready]
    if pids[0] != pids[3] or len(set(pids[:3])) != 3:
        fail("READY records do not bind one parent plus two distinct child processes")
    if sockets[0] != sockets[3]:
        fail("READY records do not bind parent socket reacquisition")
    stop_numeric = [
        {key: parse_uint(record[key], f"STOP.{key}") for key in SUPPORT.STOP_NUMERIC_FIELDS}
        for record in stops
    ]
    if any(record != stop_numeric[0] for record in stop_numeric[1:]):
        fail("graceful lifetimes disagree on the exact durable peerless store receipt")

    sensitive = {
        *transcript_facts["_application_ids"],
        *(record["sockets"] for record in ready),
        *(record["token_sha256"] for record in children.values() if "token_sha256" in record),
        children["ATTEMPT2_DONE"]["retry_token_sha256"],
        children["ATTEMPT2_DONE"]["second_token_sha256"],
        children["ATTEMPT2_DONE"]["previous_token_sha256"],
    }
    return {
        "lines": len(lines),
        "ready_records": 4,
        "contact_records": 0,
        "stop_records": 3,
        "child_coordination_records": 2,
        "processes": 3,
        "actor_lifetimes": 4,
        "maximum_concurrent_actors": 1,
        "identifiers_paths_ports_pids_tokens": "parsed-cross-bound-excluded",
        "reconciliation": {
            "contacts": 0,
            "contact_errors": 0,
            "direct_contacts": 0,
            "data_offered": 0,
            "data_fetched": 0,
            "data_inserted": 0,
            "peerless_only": True,
            "event_state_record_control_activity": "all-zero",
            "blob_network_activity": "all-zero",
        },
        "_sensitive_values": sorted(sensitive),
        "_sensitive_pids": sorted(set(pids)),
        "_sensitive_ports": sorted({int(LOOPBACK_SOCKET.fullmatch(value).group(1)) for value in sockets}),
    }


_LAST_INVENTORY: dict[str, Any] | None = None


def validate_inventory(root_descriptor: int) -> dict[str, Any]:
    global _LAST_INVENTORY
    observed_directories: dict[str, os.stat_result] = {}
    observed_files: dict[str, os.stat_result] = {}
    identities: list[tuple[int, int]] = []
    variant: str | None = None
    depot = "participants/node/state/blob-depot-v1"

    def admitted_directory(relative: str) -> bool:
        nonlocal variant
        if relative in EXPECTED_BASE_DIRECTORIES:
            return True
        parent, separator, name = relative.rpartition("/")
        if separator and parent == depot and VARIANT_DIRECTORY.fullmatch(name) is not None:
            if variant is not None:
                fail("Blob depot contains more than one variant directory")
            variant = name
            return True
        return False

    def expected_file_mode(relative: str) -> int | None:
        fixed = EXPECTED_BASE_FILES.get(relative)
        if fixed is not None:
            return fixed
        path = PurePosixPath(relative)
        if (
            len(path.parts) == 6
            and path.parts[:4] == ("participants", "node", "state", "blob-depot-v1")
            and VARIANT_DIRECTORY.fullmatch(path.parts[4]) is not None
            and path.parts[5] == CHUNK_FILE
        ):
            return 0o600
        return None

    def walk(descriptor: int, relative: str) -> None:
        metadata = os.fstat(descriptor)
        SUPPORT._validate_directory(metadata, f"raw directory {relative or '.'}")
        observed_directories[relative] = metadata
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
                    child = os.open(name, SUPPORT.DIRECTORY_FLAGS, dir_fd=descriptor)
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
    if variant is None:
        fail("Blob depot does not contain one canonical variant directory")
    variant_directory = f"{depot}/{variant}"
    chunk_path = f"{variant_directory}/{CHUNK_FILE}"
    expected_directories = EXPECTED_BASE_DIRECTORIES | {variant_directory}
    expected_files = set(EXPECTED_BASE_FILES) | {chunk_path}
    if set(observed_directories) != expected_directories:
        fail("raw inventory has missing or extra directories")
    if set(observed_files) != expected_files:
        fail("raw inventory has missing or extra files")
    if len(identities) != len(set(identities)):
        fail("raw inventory contains aliased directory or file identities")

    mission = observed_files["participants/node/mission.bundle"]
    identity = observed_files["participants/node/state/identity.key"]
    store = observed_files["participants/node/state/mesh.redb"]
    owner_marker = observed_files[f"{depot}/.aster-store-owner-v1"]
    chunk = observed_files[chunk_path]
    if not 0 < mission.st_size <= SUPPORT.MISSION_MAX_BYTES:
        fail("mission artifact violates its metadata-only size bound")
    if identity.st_size != SUPPORT.IDENTITY_BYTES:
        fail("identity key has the wrong metadata-only byte count")
    if not 0 < store.st_size <= SUPPORT.STORE_MAX_BYTES:
        fail("mesh database violates its metadata-only size bound")
    if owner_marker.st_size != OWNER_MARKER_BYTES:
        fail("Blob depot owner marker has the wrong metadata-only byte count")
    if chunk.st_size != COMMITTED_CIPHERTEXT_BYTES:
        fail("Blob ciphertext chunk has the wrong metadata-only byte count")

    SUPPORT.EXPECTED_DIRECTORIES = set(expected_directories)
    SUPPORT.EXPECTED_FILES = {
        **EXPECTED_BASE_FILES,
        chunk_path: 0o600,
    }
    SUPPORT.SECRET_FILES = BASE_SECRET_FILES | {chunk_path}
    result = {
        "directories": observed_directories,
        "files": observed_files,
        "variants": {"node": variant},
        "chunk_totals": {"node": chunk.st_size},
    }
    _LAST_INVENTORY = result
    return result


SUPPORT.validate_inventory = validate_inventory
SUPPORT.validate_transcript = validate_transcript
SUPPORT.validate_terminal_stdout = validate_terminal_stdout


def validate_source(source: Path, raw_root: Path) -> dict[str, Any]:
    return SUPPORT.validate_source(source, raw_root)


def validate_loaded_support(source_authority: dict[str, Any]) -> None:
    loaded = {
        RUNNER_PATH: RUNNER.__loaded_source_sha256__,
        RUNNER_SUPPORT_PATH: RUNNER.SUPPORT.__loaded_source_sha256__,
        CHECKER_SUPPORT_PATH: SUPPORT.__loaded_source_sha256__,
    }
    for relative, digest in loaded.items():
        if source_authority["admitted"][relative]["sha256"] != digest:
            fail(f"loaded tooling bytes differ from signed source: {relative}")


def validate_raw_root(root: Path, source_authority: dict[str, Any]) -> dict[str, Any]:
    global _LAST_INVENTORY
    _LAST_INVENTORY = None
    evidence = SUPPORT.validate_raw_root(root, source_authority)
    inventory = _LAST_INVENTORY
    if inventory is None:
        fail("terminal dynamic Blob inventory was not retained by the validator")
    variant = inventory["variants"]["node"]
    evidence["terminal"]["_sensitive_values"] = sorted(
        set(evidence["terminal"]["_sensitive_values"]) | {variant}
    )
    evidence["retention"] = {
        "root_mode": "0700",
        "directories": len(SUPPORT.EXPECTED_DIRECTORIES),
        "files": len(SUPPORT.EXPECTED_FILES),
        "participant_directories": 1,
        "mission_artifacts": 1,
        "identity_keys": 1,
        "mesh_databases": 1,
        "depot_owner_markers": 1,
        "blob_variants": 1,
        "ciphertext_chunks": 1,
        "ciphertext_bytes": COMMITTED_CIPHERTEXT_BYTES,
        "secret_and_ciphertext_contents": "metadata-only-not-opened-read-or-hashed",
        "file_links": "all-one",
        "inventory_aliases": "none",
    }
    return evidence


def build_receipt(source: dict[str, Any], evidence: dict[str, Any]) -> dict[str, Any]:
    run = evidence["run"]
    transcript = evidence["transcript"]
    terminal = evidence["terminal"]
    binary = run["artifacts"]["binary"]
    admitted = [
        {
            "path": relative,
            "bytes": source["admitted"][relative]["bytes"],
            "sha256": source["admitted"][relative]["sha256"],
        }
        for relative in ADMITTED_SOURCE_PATHS
    ]
    tools = {
        role: {
            "bytes": source["admitted"][relative]["bytes"],
            "sha256": source["admitted"][relative]["sha256"],
        }
        for role, relative in TOOL_PATHS.items()
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
            "executable": {
                "bytes": binary["bytes"],
                "sha256": binary["sha256"],
            },
            "source_binary_execution_link": "operator-attested-not-cryptographically-proven",
        },
        "run": {
            "id": "excluded",
            "argv_redacted": [
                f"<raw-root>/binary/{BINARY_NAME}",
                "<raw-root>",
            ],
            "exact_argv_sha256": sha256_bytes(canonical_json_bytes(run["run_argv"])),
            "exit_code": 0,
            "timeout_seconds": RUN_TIMEOUT_SECONDS,
            "processes": transcript["processes"],
            "maximum_concurrent_processes": transcript["maximum_concurrent_processes"],
            "stdout": {
                "bytes": run["artifacts"]["stdout"]["bytes"],
                "sha256": run["artifacts"]["stdout"]["sha256"],
                "lines": terminal["lines"],
                "ready_records": terminal["ready_records"],
                "contact_records": 0,
                "stop_records": terminal["stop_records"],
                "child_coordination_records": terminal["child_coordination_records"],
                "runtime_coordinates_and_tokens": terminal["identifiers_paths_ports_pids_tokens"],
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
                "application_identifiers": "excluded",
                "payloads": "sha256-only",
                "opaque_tokens": "excluded-sha256-commitments-only",
            },
        },
        "acceptance": {
            "participants": 1,
            "processes": transcript["processes"],
            "actor_lifetimes": transcript["actor_lifetimes"],
            "maximum_concurrent_processes": transcript["maximum_concurrent_processes"],
            "maximum_concurrent_actors": transcript["maximum_concurrent_actors"],
            "graceful_shutdowns": transcript["graceful_shutdowns"],
            "forced_process_terminations": transcript["forced_process_terminations"],
            "identity_binding": {
                "distinct_carrier_mission_authority_domains": 3,
                "runtime_ready_stop": "cross-bound",
            },
            "transport": {
                "shape": "one-host-peerless",
                "contacts": 0,
                "peer_status": "not-observed-or-claimed",
                "reconciliation": terminal["reconciliation"],
            },
            "blob": {
                "publications": transcript["blob_publications"],
                "matching_publications": transcript["matching_publications"],
                "shared_blob_ids": 1,
                "payload_representation": "sha256-only",
                "metadata_only_delivery": True,
                "exact_publication_separation": True,
                "source_counters": [1, 2],
                "acceptance_markers": [1, 2],
            },
            "subscription": {
                "insertions": transcript["subscription_insertions"],
                "durable_replays": transcript["subscription_replays"],
                "polls": transcript["polls"],
                "unique_deliveries": transcript["unique_deliveries"],
                "delivery_attempts": transcript["delivery_attempts"],
                "acknowledgements": transcript["acknowledgements"],
                "idempotent_reacknowledgements": transcript["reacknowledgements"],
                "empty_polls": transcript["empty_polls"],
                "delivery_limit": transcript["delivery_limit"],
                "scan_limit": transcript["scan_limit"],
                "final_pending": 0,
                "final_acknowledged": 2,
                "final_cursors": 2,
                "final_generation": 1,
                "status_scope": "local-ledger-only",
            },
            "tokens": {
                "bytes": transcript["token_bytes"],
                "representation": "opaque-excluded-sha256-only",
                "retry_rotation": "distinct",
                "earlier_same-tenure-attempt_accepted": True,
                "latest_attempt_reacknowledged": True,
                "malformed_rejected": True,
                "wrong_publication_rejected": True,
                "handoff_artifact": "owner-only-fsynced-then-removed",
            },
            "forced_receiver_termination": {
                "mechanism": "parent-child-sigkill",
                "distinct_process": True,
                "after_flushed_poll": True,
                "graceful": False,
                "stop_record_observed": False,
                "pretermination_acknowledged": False,
            },
            "selector_conflicting_reuse": "rejected-without-selector-change",
            "final_peerless_reopen": {
                "subscription_replayed": True,
                "delivery_queue_empty": True,
                "local_status": "subscriptions-1-pending-0-acknowledged-2-cursors-2-generation-1",
            },
            "store_inspection": {
                "blob_publications": 2,
                "acceptance_markers": 2,
                "operations": 2,
                "variants": 1,
                "finalized_variants": 1,
                "committed_chunks": 1,
                "committed_ciphertext_bytes": COMMITTED_CIPHERTEXT_BYTES,
                "subscriptions": 1,
                "pending": 0,
                "acknowledged": 2,
                "cursors": 2,
                "generation": 1,
                "other_namespaces": "empty",
            },
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


def render_receipt(
    document: dict[str, Any],
    *,
    forbidden_values: Iterable[str] = (),
    forbidden_pids: Iterable[int] = (),
    forbidden_ports: Iterable[int] = (),
) -> bytes:
    return SUPPORT.render_receipt(
        document,
        forbidden_values=forbidden_values,
        forbidden_pids=forbidden_pids,
        forbidden_ports=forbidden_ports,
    )


def parse_args(arguments: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "receipt",
        nargs="?",
        default="-",
        help="existing receipt to validate byte-for-byte, or '-' to project",
    )
    parser.add_argument("--raw-root", required=True, type=Path)
    parser.add_argument("--source", required=True, type=Path)
    parser.add_argument(
        "--output",
        type=Path,
        help=f"exclusive projected output named {RECEIPT_NAME}",
    )
    options = parser.parse_args(arguments)
    if options.receipt != "-" and options.output is not None:
        parser.error("--output cannot be combined with an existing receipt")
    return options


def validate_output_destination(
    output: Path | None, raw_root: Path, source: Path
) -> OutputDestination | None:
    if output is None:
        return None
    absolute = Path(os.path.abspath(os.fspath(output)))
    if absolute.name != RECEIPT_NAME:
        fail(f"receipt output must use the exact filename {RECEIPT_NAME}")
    parent = absolute.parent
    if os.path.realpath(parent) != os.fspath(parent):
        fail("receipt output parent is symbolic or noncanonical")
    flags = (
        os.O_RDONLY
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_DIRECTORY", 0)
        | getattr(os, "O_NOFOLLOW", 0)
    )
    parent_fd: int | None = None
    try:
        parent_fd = os.open(parent, flags)
        metadata = os.fstat(parent_fd)
        terminal = os.lstat(parent)
    except OSError:
        if parent_fd is not None:
            os.close(parent_fd)
        fail("receipt output parent is unavailable or unsafe")
    identity = (
        metadata.st_dev,
        metadata.st_ino,
        metadata.st_uid,
        stat.S_IMODE(metadata.st_mode),
    )
    if (
        not stat.S_ISDIR(metadata.st_mode)
        or stat.S_ISLNK(metadata.st_mode)
        or metadata.st_uid != os.getuid()
        or stat.S_IMODE(metadata.st_mode) & 0o022
        or identity
        != (
            terminal.st_dev,
            terminal.st_ino,
            terminal.st_uid,
            stat.S_IMODE(terminal.st_mode),
        )
    ):
        os.close(parent_fd)
        fail("receipt output parent metadata is unsafe")
    for protected, label in ((raw_root, "raw root"), (source, "source checkout")):
        try:
            absolute.relative_to(protected)
        except ValueError:
            continue
        os.close(parent_fd)
        fail(f"receipt output must be outside the {label}")
    return OutputDestination(absolute, parent_fd, identity)


def write_projected_receipt(
    destination: OutputDestination | None, data: bytes
) -> None:
    if destination is None:
        SUPPORT.write_receipt(None, data)
        return

    def require_parent_identity() -> None:
        try:
            opened = os.fstat(destination.parent_fd)
            current = os.lstat(destination.path.parent)
        except OSError:
            fail("receipt output parent changed during validation")
        for observed in (opened, current):
            identity = (
                observed.st_dev,
                observed.st_ino,
                observed.st_uid,
                stat.S_IMODE(observed.st_mode),
            )
            if identity != destination.parent_identity:
                fail("receipt output parent changed during validation")

    require_parent_identity()
    flags = (
        os.O_WRONLY
        | os.O_CREAT
        | os.O_EXCL
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_NOFOLLOW", 0)
    )
    descriptor: int | None = None
    try:
        descriptor = os.open(
            RECEIPT_NAME, flags, 0o600, dir_fd=destination.parent_fd
        )
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
        os.fsync(destination.parent_fd)
        final_opened = os.fstat(descriptor)
        final_entry = os.stat(
            RECEIPT_NAME, dir_fd=destination.parent_fd, follow_symlinks=False
        )
        if (
            (final_opened.st_dev, final_opened.st_ino)
            != (created.st_dev, created.st_ino)
            or final_opened.st_size != len(data)
            or stat.S_IMODE(final_opened.st_mode) != 0o600
            or (final_entry.st_dev, final_entry.st_ino)
            != (final_opened.st_dev, final_opened.st_ino)
        ):
            fail("receipt output changed metadata or identity while writing")
        require_parent_identity()
    except FileExistsError:
        fail("receipt output already exists; refusing to overwrite it")
    except OSError:
        fail("receipt output could not be created safely")
    finally:
        if descriptor is not None:
            os.close(descriptor)


def main(arguments: list[str] | None = None) -> None:
    options = parse_args(arguments)
    output: OutputDestination | None = None
    try:
        raw_root = Path(os.path.abspath(os.fspath(options.raw_root)))
        source = Path(os.path.abspath(os.fspath(options.source)))
        output = validate_output_destination(options.output, raw_root, source)
        bindings = (
            (Path(__file__), CHECKER_PATH),
            (Path(RUNNER.__file__), RUNNER_PATH),
            (RUNNER.SUPPORT_PATH, RUNNER_SUPPORT_PATH),
            (Path(SUPPORT.__file__), CHECKER_SUPPORT_PATH),
        )
        for observed, relative in bindings:
            try:
                if not os.path.samefile(observed, source / relative):
                    fail(f"executed tooling is not bound to signed source: {relative}")
            except OSError:
                fail(f"executed tooling source binding is unavailable: {relative}")
        source_authority = validate_source(source, raw_root)
        validate_loaded_support(source_authority)
        evidence = validate_raw_root(raw_root, source_authority)
        terminal_authority = validate_source(source, raw_root)
        if terminal_authority != source_authority:
            fail("signed source authority changed during raw evidence validation")
        encoded = render_receipt(
            build_receipt(source_authority, evidence),
            forbidden_values=receipt_forbidden_values(evidence, raw_root, source),
            forbidden_pids=SUPPORT.receipt_forbidden_pids(evidence),
            forbidden_ports=SUPPORT.receipt_forbidden_ports(evidence),
        )
        if options.receipt == "-":
            write_projected_receipt(output, encoded)
        else:
            supplied = SUPPORT.read_supplied_receipt(Path(options.receipt))
            SUPPORT.validate_supplied_receipt(supplied, encoded)
    except ReceiptViolation as error:
        print(
            f"selected live Blob subscription receipt validation failed: {error}",
            file=sys.stderr,
        )
        raise SystemExit(1) from error
    finally:
        if output is not None:
            os.close(output.parent_fd)


if __name__ == "__main__":
    main()
