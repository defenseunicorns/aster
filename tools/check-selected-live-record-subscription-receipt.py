#!/usr/bin/env python3
# Copyright 2026 Defense Unicorns, Inc.
# SPDX-License-Identifier: Apache-2.0
"""Project or validate one retained selected live Record-subscription receipt.

The raw root is an owner-only, exact-inventory acceptance artifact. Public
runtime output and the selected transcript are validated semantically; mission
bundles, identity keys, and stores are inspected by metadata only. The compact
canonical receipt excludes runtime paths, PIDs, ports, opaque tokens, and
application identifiers while retaining hashes that bind the admitted source,
executable, raw transcript, and exact invocation.

The exact delegated-support bytes loaded by this checker are cross-checked
against the signed source authority before evidence is accepted.  As with any
in-checkout verifier, invoking this file assumes the top-level checker, all
delegated-support bytes it loads, and the Python environment are trusted at
launch.
"""

from __future__ import annotations

import argparse
from dataclasses import dataclass
import hashlib
import os
from pathlib import Path
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
        or before.st_size <= 0
        or before.st_size > 4 * 1024 * 1024
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
    "run-selected-live-record-subscription.py",
    "selected_live_record_subscription_runner_contract",
)
SUPPORT = _load_support(
    "check-selected-live-event-receipt.py",
    "selected_live_record_subscription_checker_support",
)

SCHEMA = "aster-selected-live-record-subscription-receipt/v1"
RAW_SCHEMA = RUNNER.RAW_SCHEMA
TRANSCRIPT_SCHEMA = "aster-selected-live-record-subscription-transcript/v1"
CLAIM = RUNNER.CLAIM
RECEIPT_NAME = "selected-live-record-subscription-receipt.json"
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


@dataclass(frozen=True)
class OutputDestination:
    path: Path
    parent_fd: int
    parent_identity: tuple[int, int, int, int]

HEX_32 = re.compile(r"[0-9a-f]{64}\Z")
FIELD_NAME = re.compile(r"[a-z][a-z0-9_]*\Z")
LOOPBACK_SOCKET = re.compile(r"127\.0\.0\.1:([1-9][0-9]{0,4})\Z")

PAYLOAD_HASHES = {
    "edit": hashlib.sha256(b"disconnected Record edit").hexdigest(),
    "tombstone": hashlib.sha256(b"").hexdigest(),
    "beta": hashlib.sha256(
        b"network-interested application-unsubscribed Record"
    ).hexdigest(),
    "gamma": hashlib.sha256(
        b"application-matched network-uninterested Record"
    ).hexdigest(),
    "resolution": hashlib.sha256(b"guarded Record resolution").hexdigest(),
}
KEY_HASHES = {
    "alpha": hashlib.sha256(b"acceptance/record/alpha-key").hexdigest(),
    "beta": hashlib.sha256(b"acceptance/record/beta-key").hexdigest(),
    "gamma": hashlib.sha256(b"acceptance/record/gamma-key").hexdigest(),
}
ALPHA_PROJECTION_KEY_HASH = hashlib.sha256(
    b"opaque\0test/runtime-contact\0acceptance/record/alpha-key"
).hexdigest()

RUN_KEYS = (
    "schema", "claim", "participants", "processes", "actor_lifetimes",
    "maximum_concurrent_processes", "maximum_concurrent_actors", "phases",
    "alpha_topic", "beta_topic", "root_scope", "gamma_scope",
    "application_descendants", "network_alpha_descendants",
    "network_beta_descendants",
)
PARTICIPANT_KEYS = (
    "participant", "carrier_id", "mission_id", "mission_authority", "provisioning",
)
PEER_BINDING_KEYS = (
    "participant", "expected_carrier_peer", "expected_mission_peer",
)
PHASE_KEYS = ("phase", "name", "actors", "outcome")
SUBSCRIPTION_KEYS = (
    "phase", "participant", "id", "inserted", "topic", "scope",
    "include_descendant_scopes",
)
PUBLICATION_KEYS = (
    "phase", "participant", "label", "id", "publisher", "counter", "priority",
    "payload_sha256", "tombstone", "inserted",
)
DELIVERY_KEYS = (
    "phase", "participant", "label", "subscription_id", "projection_id", "topic",
    "scope", "logical_key_sha256", "current_id", "current_payload_sha256",
    "current_tombstone", "current_disposition", "concurrent_ids",
    "conflict_siblings", "attempt", "token_sha256", "delivery_limit", "scan_limit",
    "has_more", "superseded_exposed", "resolution_guard_exposed", "acknowledged",
)
PROJECTION_KEYS = (
    "phase", "participant", "label", "topic", "scope", "logical_key_sha256",
    "current_id", "current_payload_sha256", "current_tombstone",
    "current_disposition", "concurrent_ids", "superseded_ids",
    "conflict_siblings", "guard_siblings",
)
SELECTOR_KEYS = (
    "phase", "label", "topic", "scope", "record_id", "network_interested",
    "application_matched", "receiver_retained", "delivered",
)
RECEIPT_KEYS = (
    "phase", "participant", "contacts", "contact_errors", "direct_contacts",
    "relay_contacts", "unknown_path_contacts", "data_offered", "data_fetched",
    "data_inserted", "data_duplicates", "data_remaining", "mutable_remaining",
    "deferred_mutable_lanes", "events", "blobs",
)
CHILD_DELIVERY_KEYS = (
    "phase", "participant", "projection_id", "projection_key_sha256", "siblings",
    "current_id", "concurrent_id", "attempt", "token_sha256",
    "previous_token_sha256", "delivery_limit", "scan_limit", "has_more",
    "superseded_exposed", "resolution_guard_exposed", "acknowledged",
)
TERMINATION_KEYS = (
    "phase", "participant", "mechanism", "termination_signal", "distinct_process",
    "after_flushed_poll", "graceful", "stop_record_expected",
    "stop_record_observed", "acknowledged", "token_persisted",
    "token_artifact_mode", "token_artifact_fsynced",
)
TOKEN_CHECK_KEYS = (
    "phase", "token_bytes", "attempt_tokens_distinct", "attempt_one_restored",
    "malformed_token_rejected", "wrong_subscription_token_rejected",
    "wrong_projection_token_rejected", "retired_singleton_token_rejected",
    "token_artifacts_removed",
)
TOKEN_CHECKS_KEYS = TOKEN_CHECK_KEYS
ACK_KEYS = (
    "phase", "participant", "projection", "projection_id", "ack", "reack",
    "ack_token_attempt", "reack_token_attempt", "old_projection_reack",
)
EMPTY_POLL_KEYS = ("phase", "participant", "label", "deliveries", "has_more")
RESOLUTION_KEYS = (
    "phase", "participant", "id", "publisher", "counter", "priority",
    "payload_sha256", "tombstone", "inserted", "retry_inserted", "retry_same",
    "guard_fresh_query", "guard_siblings",
)
INSPECTION_KEYS = (
    "participant", "record_rows", "record_acceptance_markers", "record_operations",
    "subscriptions", "pending_deliveries", "acknowledged_deliveries",
    "delivery_cursors", "selector_generation", "other_namespaces_empty",
)
BIND_KEYS = ("participant", "reacquired")
RESULT_KEYS = (
    "status", "records", "phases", "participants", "processes", "actor_lifetimes",
    "maximum_concurrent_processes", "maximum_concurrent_actors",
    "graceful_shutdowns", "forced_process_terminations", "record_publications",
    "network_record_insertions", "polls", "deliveries", "acknowledgements",
    "reacknowledgements", "subscription_insertions", "subscription_replays",
    "token_binding_checks", "empty_polls", "bind_reacquisitions",
    "query_only_superseded", "payload_representation", "token_representation",
    "opaque_tokens_emitted", "secret_values_emitted", "physical_network_claimed",
    "automatic_merge_claimed", "global_convergence_claimed", "long_retention_claimed",
)

ATTEMPT_ONE_CHILD_KEYS = (
    "participant", "identity", "subscription_id", "subscription_inserted",
    "projection_id", "projection_topic", "projection_scope",
    "projection_key_sha256", "edit_id", "tombstone_id", "current_id",
    "concurrent_id", "siblings", "attempt", "token_sha256", "delivery_limit",
    "scan_limit", "has_more", "superseded_exposed", "resolution_guard_exposed",
    "token_persisted", "singleton_projection_changed", "beta_id", "beta_present",
    "gamma_empty", "acknowledged",
)
ATTEMPT_TWO_CHILD_KEYS = (
    "participant", "identity", "subscription_id", "subscription_inserted",
    "projection_id", "projection_topic", "projection_scope",
    "projection_key_sha256", "edit_id", "tombstone_id", "current_id",
    "concurrent_id", "siblings", "attempt", "token_sha256", "delivery_limit",
    "scan_limit", "has_more", "superseded_exposed", "resolution_guard_exposed",
    "previous_token_sha256", "tokens_distinct", "previous_token_restored",
    "malformed_token_rejected", "wrong_subscription_token_rejected",
    "wrong_projection_token_rejected", "retired_singleton_token_rejected",
    "retired_singleton_token_sha256", "ack_token_attempt", "reack_token_attempt",
    "conflict_ack", "conflict_reack", "post_conflict_empty", "guard_fresh_query",
    "guard_siblings", "resolution_id", "resolution_publisher", "resolution_counter",
    "resolution_inserted", "resolution_retry_inserted", "resolution_retry_same",
    "successor_projection_id", "successor_attempt", "successor_token_sha256",
    "successor_ack", "successor_reack", "old_conflict_reack",
    "post_successor_empty", "superseded_ids", "beta_id", "beta_present",
    "gamma_empty", "token_artifacts_removed", "closed_kind", "closed_operation",
    "shutdown_contacts", "shutdown_contact_errors", "shutdown_direct_contacts",
    "shutdown_relay_contacts", "shutdown_unknown_path_contacts",
    "shutdown_events", "shutdown_blobs", "shutdown_data_offered",
    "shutdown_data_fetched", "shutdown_data_inserted", "shutdown_data_duplicates",
    "shutdown_data_remaining", "shutdown_mutable_remaining",
    "shutdown_deferred_mutable_lanes",
)

EXPECTED_SEQUENCE: tuple[tuple[str, tuple[str, ...]], ...] = (
    ("RUN", RUN_KEYS),
    ("PARTICIPANT", PARTICIPANT_KEYS),
    ("PARTICIPANT", PARTICIPANT_KEYS),
    ("PEER_BINDING", PEER_BINDING_KEYS),
    ("PEER_BINDING", PEER_BINDING_KEYS),
    ("PHASE", PHASE_KEYS),
    ("SUBSCRIPTION", SUBSCRIPTION_KEYS),
    ("SUBSCRIPTION", SUBSCRIPTION_KEYS),
    ("PUBLICATION", PUBLICATION_KEYS),
    ("PUBLICATION", PUBLICATION_KEYS),
    ("DELIVERY", DELIVERY_KEYS),
    ("PROJECTION", PROJECTION_KEYS),
    ("PROJECTION", PROJECTION_KEYS),
    ("RECEIPT", RECEIPT_KEYS),
    ("RECEIPT", RECEIPT_KEYS),
    ("PHASE", PHASE_KEYS),
    ("SUBSCRIPTION", SUBSCRIPTION_KEYS),
    ("PROJECTION", PROJECTION_KEYS),
    ("PROJECTION", PROJECTION_KEYS),
    ("PUBLICATION", PUBLICATION_KEYS),
    ("PUBLICATION", PUBLICATION_KEYS),
    ("SELECTOR", SELECTOR_KEYS),
    ("SELECTOR", SELECTOR_KEYS),
    ("RECEIPT", RECEIPT_KEYS),
    ("RECEIPT", RECEIPT_KEYS),
    ("PHASE", PHASE_KEYS),
    ("SUBSCRIPTION", SUBSCRIPTION_KEYS),
    ("CHILD_DELIVERY", CHILD_DELIVERY_KEYS),
    ("PROCESS_TERMINATION", TERMINATION_KEYS),
    ("PHASE", PHASE_KEYS),
    ("SUBSCRIPTION", SUBSCRIPTION_KEYS),
    ("CHILD_DELIVERY", CHILD_DELIVERY_KEYS),
    ("TOKEN_CHECKS", TOKEN_CHECK_KEYS),
    ("ACKNOWLEDGEMENT", ACK_KEYS),
    ("EMPTY_POLL", EMPTY_POLL_KEYS),
    ("RESOLUTION", RESOLUTION_KEYS),
    ("DELIVERY", DELIVERY_KEYS),
    ("ACKNOWLEDGEMENT", ACK_KEYS),
    ("EMPTY_POLL", EMPTY_POLL_KEYS),
    ("PROJECTION", PROJECTION_KEYS),
    ("RECEIPT", RECEIPT_KEYS),
    ("PHASE", PHASE_KEYS),
    ("SUBSCRIPTION", SUBSCRIPTION_KEYS),
    ("PROJECTION", PROJECTION_KEYS),
    ("SELECTOR", SELECTOR_KEYS),
    ("SELECTOR", SELECTOR_KEYS),
    ("EMPTY_POLL", EMPTY_POLL_KEYS),
    ("RECEIPT", RECEIPT_KEYS),
    ("INSPECTION", INSPECTION_KEYS),
    ("INSPECTION", INSPECTION_KEYS),
    ("BIND", BIND_KEYS),
    ("BIND", BIND_KEYS),
    ("RESULT", RESULT_KEYS),
)
FIELD_KEYS = {
    "run": RUN_KEYS,
    "participant": PARTICIPANT_KEYS,
    "peer_binding": PEER_BINDING_KEYS,
    "phase": PHASE_KEYS,
    "subscription": SUBSCRIPTION_KEYS,
    "publication": PUBLICATION_KEYS,
    "delivery": DELIVERY_KEYS,
    "projection": PROJECTION_KEYS,
    "selector": SELECTOR_KEYS,
    "receipt": RECEIPT_KEYS,
    "child_delivery": CHILD_DELIVERY_KEYS,
    "process_termination": TERMINATION_KEYS,
    "token_checks": TOKEN_CHECK_KEYS,
    "acknowledgement": ACK_KEYS,
    "empty_poll": EMPTY_POLL_KEYS,
    "resolution": RESOLUTION_KEYS,
    "inspection": INSPECTION_KEYS,
    "bind": BIND_KEYS,
    "result": RESULT_KEYS,
}

PHASES = (
    (1, "peerless_origins", "publisher+receiver", "unacknowledged-singleton"),
    (
        2,
        "direct_conflict_and_selectors",
        "publisher+receiver",
        "whole-conflict-and-withholding",
    ),
    (3, "forced_conflict_delivery", "receiver-child", "force-terminated"),
    (
        4,
        "peerless_redelivery_resolution",
        "receiver-child",
        "acknowledged-and-resolved",
    ),
    (5, "final_peerless_reopen", "receiver", "durable-resolved-empty"),
)

LIMITATIONS = [
    "operator-attested-source-binary-execution-link-not-cryptographically-proven",
    "selected-admitted-source-list-is-not-a-complete-reproducible-build-closure",
    "one-host-direct-loopback-same-implementation-observation",
    "participant-secret-artifacts-validated-by-metadata-only",
    "record-causal-observation-and-publication-order-are-producer-attested",
    "network-interest-and-application-subscription-are-separate-static-surfaces",
    "forced-sigkill-is-not-power-loss-or-filesystem-crash-recovery",
    "restart-observes-one-immediate-peerless-reopen-not-long-retention-compaction-or-garbage-collection",
]
NONCLAIMS = [
    "hidden-policy-lineage-disclosure-or-authorization-from-opaque-conflict-sibling-identifiers",
    "distinct-physical-hosts",
    "nat-or-internet-path",
    "controlled-or-public-relay",
    "btle-carrier",
    "mixed-implementation-or-mixed-carrier-interoperability",
    "scale-beyond-two-participants",
    "resource-thresholds-or-long-duration-soak",
    "event-state-or-blob-live-application-acceptance",
    "finite-ttl-retention-expiry-compaction-or-garbage-collection",
    "automatic-registered-policy-conflict-merge-or-resolution",
    "reproducible-build-or-cryptographic-source-to-execution-provenance",
    "release-acceptance-production-authorization-or-operational-readiness",
]

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
    SUPPORT.EXPECTED_DIRECTORIES = {
        "",
        "binary",
        "participants",
        "participants/publisher",
        "participants/publisher/state",
        "participants/receiver",
        "participants/receiver/state",
    }
    SUPPORT.EXPECTED_FILES = {
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
    SUPPORT.SECRET_FILES = {
        f"participants/{participant}/{relative}"
        for participant in PARTICIPANTS
        for relative in ("mission.bundle", "state/identity.key", "state/mesh.redb")
    }


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
        or parts[:2] != ["LIVE_RECORD_SUBSCRIPTION", expected_type.lower()]
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


def _validate_receipt_record(
    record: dict[str, str],
    *,
    phase: str,
    participant: str,
    connected: bool,
) -> dict[str, int]:
    require_fixed(
        record,
        {
            "phase": phase,
            "participant": participant,
            "events": "0",
            "blobs": "0",
        },
        f"RECEIPT {phase}/{participant}",
    )
    numeric = {
        key: parse_uint(record[key], f"RECEIPT {phase}/{participant}.{key}")
        for key in RECEIPT_KEYS[2:]
    }
    zero_fields = (
        "contact_errors",
        "relay_contacts",
        "unknown_path_contacts",
        "data_duplicates",
        "data_remaining",
        "mutable_remaining",
        "deferred_mutable_lanes",
        "events",
        "blobs",
    )
    if any(numeric[key] != 0 for key in zero_fields):
        fail(f"RECEIPT {phase}/{participant} contains excluded or incomplete activity")
    if connected:
        if numeric["contacts"] == 0 or numeric["direct_contacts"] != numeric["contacts"]:
            fail(f"RECEIPT {phase}/{participant} lacks exact positive direct contacts")
        if numeric["data_fetched"] != numeric["data_inserted"]:
            fail(f"RECEIPT {phase}/{participant} does not bind fetches to insertions")
    elif any(
        numeric[key] != 0
        for key in (
            "contacts",
            "direct_contacts",
            "data_offered",
            "data_fetched",
            "data_inserted",
        )
    ):
        fail(f"RECEIPT {phase}/{participant} contains peerless network activity")
    return numeric


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
            "participants": "2",
            "processes": "3",
            "actor_lifetimes": "7",
            "maximum_concurrent_processes": "2",
            "maximum_concurrent_actors": "2",
            "phases": "5",
            "alpha_topic": "opaque",
            "beta_topic": "opaque.beta",
            "root_scope": "test/runtime-contact",
            "gamma_scope": "test/runtime-contact/withheld",
            "application_descendants": "true",
            "network_alpha_descendants": "false",
            "network_beta_descendants": "false",
        },
        "RUN",
    )

    participants: dict[str, dict[str, str]] = {}
    for index, participant in ((1, "publisher"), (2, "receiver")):
        record = records[index]
        require_fixed(
            record,
            {
                "participant": participant,
                "provisioning": "independent-node-bundle",
            },
            f"PARTICIPANT {participant}",
        )
        for key in ("carrier_id", "mission_id", "mission_authority"):
            require_id(record[key], f"PARTICIPANT {participant}.{key}")
        participants[participant] = record
    identity_domains = {
        participants[name][key]
        for name in participants
        for key in ("carrier_id", "mission_id")
    }
    if len(identity_domains) != 4:
        fail("participant carrier and mission identity domains are not disjoint")
    authority = participants["publisher"]["mission_authority"]
    if (
        participants["receiver"]["mission_authority"] != authority
        or authority in identity_domains
    ):
        fail("participants do not bind one common disjoint mission authority")
    for index, local, remote in (
        (3, "publisher", "receiver"),
        (4, "receiver", "publisher"),
    ):
        require_fixed(
            records[index],
            {
                "participant": local,
                "expected_carrier_peer": participants[remote]["carrier_id"],
                "expected_mission_peer": participants[remote]["mission_id"],
            },
            f"PEER_BINDING {local}",
        )
    for index, expected in zip((5, 15, 25, 29, 41), PHASES, strict=True):
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

    subscription_id = records[6]["id"]
    require_id(subscription_id, "SUBSCRIPTION.id")
    subscription_phases = (
        "peerless_origins",
        "peerless_origins",
        "direct_conflict_and_selectors",
        "forced_conflict_delivery",
        "peerless_redelivery_resolution",
        "final_peerless_reopen",
    )
    for ordinal, (index, phase) in enumerate(
        zip((6, 7, 16, 26, 30, 42), subscription_phases, strict=True)
    ):
        require_fixed(
            records[index],
            {
                "phase": phase,
                "participant": "receiver",
                "id": subscription_id,
                "inserted": "true" if ordinal == 0 else "false",
                "topic": "opaque",
                "scope": "test/runtime-contact",
                "include_descendant_scopes": "true",
            },
            f"SUBSCRIPTION {ordinal + 1}",
        )

    publications: dict[str, dict[str, str]] = {}
    publication_specs = (
        (8, "edit", "peerless_origins", "publisher", "alpha-edit", 1, "false"),
        (
            9,
            "tombstone",
            "peerless_origins",
            "receiver",
            "alpha-tombstone",
            1,
            "true",
        ),
        (
            19,
            "beta",
            "direct_conflict_and_selectors",
            "publisher",
            "beta",
            2,
            "false",
        ),
        (
            20,
            "gamma",
            "direct_conflict_and_selectors",
            "publisher",
            "gamma",
            3,
            "false",
        ),
    )
    for index, name, phase, participant, label, counter, tombstone in publication_specs:
        record = records[index]
        require_id(record["id"], f"PUBLICATION {name}.id")
        require_fixed(
            record,
            {
                "phase": phase,
                "participant": participant,
                "label": label,
                "publisher": participants[participant]["mission_id"],
                "counter": str(counter),
                "priority": "priority",
                "payload_sha256": PAYLOAD_HASHES[name],
                "tombstone": tombstone,
                "inserted": "true",
            },
            f"PUBLICATION {name}",
        )
        publications[name] = record
    if len({record["id"] for record in publications.values()}) != 4:
        fail("origin and selector publication identities are not pairwise distinct")

    edit_id = publications["edit"]["id"]
    tombstone_id = publications["tombstone"]["id"]
    origin_ids = sorted((edit_id, tombstone_id))
    current_id = max(origin_ids)
    concurrent_id = min(origin_ids)
    origin_by_id = {
        edit_id: publications["edit"],
        tombstone_id: publications["tombstone"],
    }
    singleton = records[10]
    require_id(singleton["projection_id"], "DELIVERY singleton.projection_id")
    _require_digest(singleton["token_sha256"], "DELIVERY singleton.token_sha256")
    require_fixed(
        singleton,
        {
            "phase": "peerless_origins",
            "participant": "receiver",
            "label": "alpha-singleton",
            "subscription_id": subscription_id,
            "topic": "opaque",
            "scope": "test/runtime-contact",
            "logical_key_sha256": KEY_HASHES["alpha"],
            "current_id": tombstone_id,
            "current_payload_sha256": PAYLOAD_HASHES["tombstone"],
            "current_tombstone": "true",
            "current_disposition": "current",
            "concurrent_ids": "none",
            "conflict_siblings": "none",
            "attempt": "1",
            "delivery_limit": "1",
            "scan_limit": "16",
            "has_more": "false",
            "superseded_exposed": "false",
            "resolution_guard_exposed": "false",
            "acknowledged": "false",
        },
        "DELIVERY singleton",
    )
    for index, participant, name in (
        (11, "publisher", "edit"),
        (12, "receiver", "tombstone"),
    ):
        publication = publications[name]
        require_fixed(
            records[index],
            {
                "phase": "peerless_origins",
                "participant": participant,
                "label": f"alpha-{name}",
                "topic": "opaque",
                "scope": "test/runtime-contact",
                "logical_key_sha256": KEY_HASHES["alpha"],
                "current_id": publication["id"],
                "current_payload_sha256": publication["payload_sha256"],
                "current_tombstone": publication["tombstone"],
                "current_disposition": "current",
                "concurrent_ids": "none",
                "superseded_ids": "none",
                "conflict_siblings": "none",
                "guard_siblings": "none",
            },
            f"PROJECTION singleton/{participant}",
        )

    for index, participant in ((17, "publisher"), (18, "receiver")):
        current = origin_by_id[current_id]
        require_fixed(
            records[index],
            {
                "phase": "direct_conflict_and_selectors",
                "participant": participant,
                "label": "alpha-conflict",
                "topic": "opaque",
                "scope": "test/runtime-contact",
                "logical_key_sha256": KEY_HASHES["alpha"],
                "current_id": current_id,
                "current_payload_sha256": current["payload_sha256"],
                "current_tombstone": current["tombstone"],
                "current_disposition": "current",
                "concurrent_ids": concurrent_id,
                "superseded_ids": "none",
                "conflict_siblings": ",".join(origin_ids),
                "guard_siblings": ",".join(origin_ids),
            },
            f"PROJECTION conflict/{participant}",
        )
    for key in PROJECTION_KEYS:
        if key != "participant" and records[17][key] != records[18][key]:
            fail(f"connected conflict projections differ at {key}")

    selector_specs = (
        (
            21,
            "direct_conflict_and_selectors",
            "beta",
            "opaque.beta",
            "test/runtime-contact",
            "beta",
            "true",
            "false",
            "true",
        ),
        (
            22,
            "direct_conflict_and_selectors",
            "gamma",
            "opaque",
            "test/runtime-contact/withheld",
            "gamma",
            "false",
            "true",
            "false",
        ),
        (
            44,
            "final_peerless_reopen",
            "beta",
            "opaque.beta",
            "test/runtime-contact",
            "beta",
            "true",
            "false",
            "true",
        ),
        (
            45,
            "final_peerless_reopen",
            "gamma",
            "opaque",
            "test/runtime-contact/withheld",
            "gamma",
            "false",
            "true",
            "false",
        ),
    )
    for (
        index,
        phase,
        label,
        topic,
        scope,
        publication,
        network,
        application,
        retained,
    ) in selector_specs:
        require_fixed(
            records[index],
            {
                "phase": phase,
                "label": label,
                "topic": topic,
                "scope": scope,
                "record_id": publications[publication]["id"],
                "network_interested": network,
                "application_matched": application,
                "receiver_retained": retained,
                "delivered": "false",
            },
            f"SELECTOR {phase}/{label}",
        )

    receipt_records: dict[tuple[str, str], dict[str, int]] = {}
    for index, phase, participant, connected in (
        (13, "peerless_origins", "publisher", False),
        (14, "peerless_origins", "receiver", False),
        (23, "direct_conflict_and_selectors", "publisher", True),
        (24, "direct_conflict_and_selectors", "receiver", True),
        (40, "peerless_redelivery_resolution", "receiver", False),
        (47, "final_peerless_reopen", "receiver", False),
    ):
        receipt_records[(phase, participant)] = _validate_receipt_record(
            records[index],
            phase=phase,
            participant=participant,
            connected=connected,
        )
    publisher_direct = receipt_records[
        ("direct_conflict_and_selectors", "publisher")
    ]
    receiver_direct = receipt_records[
        ("direct_conflict_and_selectors", "receiver")
    ]
    for key in ("data_offered", "data_fetched", "data_inserted"):
        if publisher_direct[key] + receiver_direct[key] != 3:
            fail(f"direct Record reconciliation does not contain exactly three {key}")
    if (
        publisher_direct["data_offered"] != receiver_direct["data_fetched"]
        or receiver_direct["data_offered"] != publisher_direct["data_fetched"]
    ):
        fail("direct Record reconciliation is not reciprocal")

    conflict_one = records[27]
    conflict_two = records[31]
    for record, attempt, phase, prior, acknowledged in (
        (conflict_one, "1", "forced_conflict_delivery", "none", "false"),
        (
            conflict_two,
            "2",
            "peerless_redelivery_resolution",
            conflict_one["token_sha256"],
            "true",
        ),
    ):
        for key in ("projection_id", "projection_key_sha256", "token_sha256"):
            _require_digest(record[key], f"CHILD_DELIVERY attempt {attempt}.{key}")
        require_fixed(
            record,
            {
                "phase": phase,
                "participant": "receiver",
                "projection_key_sha256": ALPHA_PROJECTION_KEY_HASH,
                "siblings": ",".join(origin_ids),
                "current_id": current_id,
                "concurrent_id": concurrent_id,
                "attempt": attempt,
                "previous_token_sha256": prior,
                "delivery_limit": "1",
                "scan_limit": "16",
                "has_more": "false",
                "superseded_exposed": "false",
                "resolution_guard_exposed": "false",
                "acknowledged": acknowledged,
            },
            f"CHILD_DELIVERY attempt {attempt}",
        )
    for key in ("projection_id", "projection_key_sha256"):
        if conflict_one[key] != conflict_two[key]:
            fail(f"conflict redelivery changed {key}")
    if conflict_one["projection_id"] == singleton["projection_id"]:
        fail("conflict delivery reused the retired singleton projection identity")
    if conflict_one["token_sha256"] == conflict_two["token_sha256"]:
        fail("conflict redelivery reused the attempt-one token")
    require_fixed(
        records[28],
        {
            "phase": "forced_conflict_delivery",
            "participant": "receiver",
            "mechanism": "parent-child-kill",
            "termination_signal": "sigkill",
            "distinct_process": "true",
            "after_flushed_poll": "true",
            "graceful": "false",
            "stop_record_expected": "false",
            "stop_record_observed": "false",
            "acknowledged": "false",
            "token_persisted": "true",
            "token_artifact_mode": "0600",
            "token_artifact_fsynced": "true",
        },
        "PROCESS_TERMINATION",
    )
    require_fixed(
        records[32],
        {
            "phase": "peerless_redelivery_resolution",
            "token_bytes": "89",
            "attempt_tokens_distinct": "true",
            "attempt_one_restored": "true",
            "malformed_token_rejected": "true",
            "wrong_subscription_token_rejected": "true",
            "wrong_projection_token_rejected": "true",
            "retired_singleton_token_rejected": "true",
            "token_artifacts_removed": "true",
        },
        "TOKEN_CHECKS",
    )
    require_fixed(
        records[33],
        {
            "phase": "peerless_redelivery_resolution",
            "participant": "receiver",
            "projection": "conflict",
            "projection_id": conflict_one["projection_id"],
            "ack": "acknowledged",
            "reack": "already_acknowledged",
            "ack_token_attempt": "1",
            "reack_token_attempt": "2",
            "old_projection_reack": "not-applicable",
        },
        "ACKNOWLEDGEMENT conflict",
    )
    for index, label in (
        (34, "post-conflict-ack"),
        (38, "post-successor-ack"),
        (46, "durable-empty"),
    ):
        require_fixed(
            records[index],
            {
                "phase": (
                    "peerless_redelivery_resolution"
                    if index < 40
                    else "final_peerless_reopen"
                ),
                "participant": "receiver",
                "label": label,
                "deliveries": "0",
                "has_more": "false",
            },
            f"EMPTY_POLL {label}",
        )

    resolution = records[35]
    require_id(resolution["id"], "RESOLUTION.id")
    require_fixed(
        resolution,
        {
            "phase": "peerless_redelivery_resolution",
            "participant": "receiver",
            "publisher": participants["receiver"]["mission_id"],
            "counter": "2",
            "priority": "immediate",
            "payload_sha256": PAYLOAD_HASHES["resolution"],
            "tombstone": "false",
            "inserted": "true",
            "retry_inserted": "false",
            "retry_same": "true",
            "guard_fresh_query": "true",
            "guard_siblings": ",".join(origin_ids),
        },
        "RESOLUTION",
    )
    if resolution["id"] in {record["id"] for record in publications.values()}:
        fail("resolution identity repeats an earlier publication")
    publications["resolution"] = resolution
    successor = records[36]
    require_id(successor["projection_id"], "DELIVERY successor.projection_id")
    _require_digest(successor["token_sha256"], "DELIVERY successor.token_sha256")
    require_fixed(
        successor,
        {
            "phase": "peerless_redelivery_resolution",
            "participant": "receiver",
            "label": "resolved-successor",
            "subscription_id": subscription_id,
            "topic": "opaque",
            "scope": "test/runtime-contact",
            "logical_key_sha256": KEY_HASHES["alpha"],
            "current_id": resolution["id"],
            "current_payload_sha256": PAYLOAD_HASHES["resolution"],
            "current_tombstone": "false",
            "current_disposition": "current",
            "concurrent_ids": "none",
            "conflict_siblings": "none",
            "attempt": "1",
            "delivery_limit": "1",
            "scan_limit": "16",
            "has_more": "false",
            "superseded_exposed": "false",
            "resolution_guard_exposed": "false",
            "acknowledged": "true",
        },
        "DELIVERY successor",
    )
    if successor["projection_id"] in {
        singleton["projection_id"],
        conflict_one["projection_id"],
    }:
        fail("successor delivery reused an earlier projection identity")
    token_hashes = {
        singleton["token_sha256"],
        conflict_one["token_sha256"],
        conflict_two["token_sha256"],
        successor["token_sha256"],
    }
    if len(token_hashes) != 4:
        fail("delivery token commitments are not pairwise distinct")
    require_fixed(
        records[37],
        {
            "phase": "peerless_redelivery_resolution",
            "participant": "receiver",
            "projection": "successor",
            "projection_id": successor["projection_id"],
            "ack": "acknowledged",
            "reack": "already_acknowledged",
            "ack_token_attempt": "1",
            "reack_token_attempt": "1",
            "old_projection_reack": "already_acknowledged",
        },
        "ACKNOWLEDGEMENT successor",
    )
    for index, phase, label in (
        (39, "peerless_redelivery_resolution", "alpha-resolved-query"),
        (43, "final_peerless_reopen", "alpha-resolved"),
    ):
        require_fixed(
            records[index],
            {
                "phase": phase,
                "participant": "receiver",
                "label": label,
                "topic": "opaque",
                "scope": "test/runtime-contact",
                "logical_key_sha256": KEY_HASHES["alpha"],
                "current_id": resolution["id"],
                "current_payload_sha256": PAYLOAD_HASHES["resolution"],
                "current_tombstone": "false",
                "current_disposition": "current",
                "concurrent_ids": "none",
                "superseded_ids": ",".join(origin_ids),
                "conflict_siblings": "none",
                "guard_siblings": "none",
            },
            f"PROJECTION {label}",
        )

    inspections: dict[str, dict[str, str]] = {}
    for index, participant, expected in (
        (48, "publisher", (4, 4, 3, 0, 0, 0, 0, 0)),
        (49, "receiver", (4, 4, 2, 1, 0, 1, 1, 1)),
    ):
        record = records[index]
        require_fixed(
            record,
            {
                "participant": participant,
                "record_rows": str(expected[0]),
                "record_acceptance_markers": str(expected[1]),
                "record_operations": str(expected[2]),
                "subscriptions": str(expected[3]),
                "pending_deliveries": str(expected[4]),
                "acknowledged_deliveries": str(expected[5]),
                "delivery_cursors": str(expected[6]),
                "selector_generation": str(expected[7]),
                "other_namespaces_empty": "true",
            },
            f"INSPECTION {participant}",
        )
        inspections[participant] = record
    require_fixed(
        records[50],
        {"participant": "publisher", "reacquired": "true"},
        "BIND publisher",
    )
    require_fixed(
        records[51],
        {"participant": "receiver", "reacquired": "true"},
        "BIND receiver",
    )
    require_fixed(
        records[52],
        {
            "status": "pass",
            "records": "53",
            "phases": "5",
            "participants": "2",
            "processes": "3",
            "actor_lifetimes": "7",
            "maximum_concurrent_processes": "2",
            "maximum_concurrent_actors": "2",
            "graceful_shutdowns": "6",
            "forced_process_terminations": "1",
            "record_publications": "5",
            "network_record_insertions": "3",
            "polls": "7",
            "deliveries": "4",
            "acknowledgements": "2",
            "reacknowledgements": "3",
            "subscription_insertions": "1",
            "subscription_replays": "5",
            "token_binding_checks": "4",
            "empty_polls": "3",
            "bind_reacquisitions": "2",
            "query_only_superseded": "2",
            "payload_representation": "sha256-only",
            "token_representation": "sha256-only",
            "opaque_tokens_emitted": "false",
            "secret_values_emitted": "false",
            "physical_network_claimed": "false",
            "automatic_merge_claimed": "false",
            "global_convergence_claimed": "false",
            "long_retention_claimed": "false",
        },
        "RESULT",
    )

    application_ids = {
        *(
            record[key]
            for record in participants.values()
            for key in ("carrier_id", "mission_id", "mission_authority")
        ),
        subscription_id,
        *(record["id"] for record in publications.values()),
        singleton["projection_id"],
        conflict_one["projection_id"],
        successor["projection_id"],
        conflict_one["projection_key_sha256"],
        *token_hashes,
    }
    return {
        "records": len(records),
        "bytes": len(data),
        "sha256": sha256_bytes(data),
        "participants": 2,
        "processes": 3,
        "actor_lifetimes": 7,
        "maximum_concurrent_processes": 2,
        "maximum_concurrent_actors": 2,
        "phases": 5,
        "graceful_shutdowns": 6,
        "forced_process_terminations": 1,
        "record_publications": 5,
        "network_record_insertions": 3,
        "polls": 7,
        "deliveries": 4,
        "acknowledgements": 2,
        "reacknowledgements": 3,
        "subscription_insertions": 1,
        "subscription_replays": 5,
        "token_binding_checks": 4,
        "token_bytes": 89,
        "empty_polls": 3,
        "bind_reacquisitions": 2,
        "query_only_superseded": 2,
        "delivery_limit": 1,
        "scan_limit": 16,
        "superseded_exposed": False,
        "resolution_guard_exposed": False,
        "_participants": participants,
        "_subscription_id": subscription_id,
        "_publications": publications,
        "_origin_ids": origin_ids,
        "_singleton": singleton,
        "_conflict_one": conflict_one,
        "_conflict_two": conflict_two,
        "_successor": successor,
        "_receipts": receipt_records,
        "_inspections": inspections,
        "_application_ids": sorted(application_ids),
        "_token_hashes": sorted(token_hashes),
    }


def _parse_child_record(line: str, label: str) -> tuple[str, dict[str, str]]:
    parts = line.split("\t")
    if len(parts) < 3 or parts[0] != "LIVE_RECORD_SUBSCRIPTION_CHILD":
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
        if line.startswith("LIVE_RECORD_SUBSCRIPTION\t")
    )
    if extracted != transcript:
        fail("transcript is not the exact ordered Record-subscription extraction from stdout")

    participants = transcript_facts["_participants"]
    by_carrier = {record["carrier_id"]: name for name, record in participants.items()}
    by_mission = {record["mission_id"]: name for name, record in participants.items()}
    lifetime_order = {
        "publisher": ("peerless_origins", "direct_conflict_and_selectors"),
        "receiver": (
            "peerless_origins",
            "direct_conflict_and_selectors",
            "forced_conflict_delivery",
            "peerless_redelivery_resolution",
            "final_peerless_reopen",
        ),
    }
    expected_ready_sequence = [
        ("publisher", "peerless_origins"),
        ("receiver", "peerless_origins"),
        ("receiver", "direct_conflict_and_selectors"),
        ("publisher", "direct_conflict_and_selectors"),
        ("receiver", "forced_conflict_delivery"),
        ("receiver", "peerless_redelivery_resolution"),
        ("receiver", "final_peerless_reopen"),
    ]
    ready_count = {participant: 0 for participant in participants}
    stop_count = {participant: 0 for participant in participants}
    active: dict[str, str] = {}
    ready_sequence: list[tuple[str, str]] = []
    active_maximum = 0
    contact_count = {participant: 0 for participant in participants}
    contact_counters: dict[tuple[str, str], dict[str, int]] = {}
    lifetime_pids: dict[tuple[str, str], int] = {}
    pids: set[int] = set()
    sockets: set[str] = set()
    ports: set[int] = set()
    connected_sockets: dict[str, str] = {}
    child_records: dict[str, dict[str, str]] = {}
    ready_records = 0
    contact_records = 0
    stop_records = 0
    transcript_started = False
    attempt_two_stopped = False

    for line_number, line in enumerate(lines, start=1):
        label = f"captured stdout line {line_number}"
        if line.startswith("LIVE_RECORD_SUBSCRIPTION\t"):
            transcript_started = True
            continue
        if transcript_started:
            fail(f"{label} appears after the public transcript began")
        if line.startswith("LIVE_RECORD_SUBSCRIPTION_CHILD\t"):
            kind, record = _parse_child_record(line, label)
            if kind in child_records:
                fail(f"{label} duplicates one child coordination kind")
            if kind == "ATTEMPT1_READY":
                if active.get("receiver") != "forced_conflict_delivery":
                    fail(f"{label} is outside the force-terminated receiver lifetime")
                del active["receiver"]
                contact_count["receiver"] = 0
            elif not attempt_two_stopped or "receiver" in active:
                fail(f"{label} precedes the graceful redelivery STOP")
            child_records[kind] = record
            continue
        if line.startswith("READY "):
            record = SUPPORT.parse_terminal_record(
                line, "READY", SUPPORT.READY_KEYS, label
            )
            carrier_participant = by_carrier.get(record["carrier_id"])
            mission_participant = by_mission.get(record["mission_id"])
            if carrier_participant is None or carrier_participant != mission_participant:
                fail(f"{label} does not bind one transcript participant")
            participant = carrier_participant
            ordinal = ready_count[participant]
            if ordinal >= len(lifetime_order[participant]) or participant in active:
                fail(f"{label} starts an overlapping or extra participant lifetime")
            phase = lifetime_order[participant][ordinal]
            peers = "1" if phase == "direct_conflict_and_selectors" else "0"
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
                connected_sockets[participant] = record["sockets"]
            ready_count[participant] += 1
            active[participant] = phase
            ready_sequence.append((participant, phase))
            active_maximum = max(active_maximum, len(active))
            lifetime_pids[(participant, phase)] = pid
            pids.add(pid)
            sockets.add(record["sockets"])
            ports.add(int(socket_match.group(1)))
            ready_records += 1
            continue
        if line.startswith("CONTACT "):
            record = SUPPORT.parse_terminal_record(
                line, "CONTACT", SUPPORT.CONTACT_KEYS, label
            )
            remote_carrier = by_carrier.get(record["carrier_peer"])
            remote_mission = by_mission.get(record["mission_peer"])
            if remote_carrier is None or remote_carrier != remote_mission:
                fail(f"{label} does not bind one reciprocal transcript peer")
            remote = remote_carrier
            local = "receiver" if remote == "publisher" else "publisher"
            phase = active.get(local)
            if (
                phase != "direct_conflict_and_selectors"
                or active.get(remote) != phase
            ):
                fail(f"{label} occurs outside the only connected phase")
            expected_direction = (
                "out"
                if participants[local]["carrier_id"]
                < participants[remote]["carrier_id"]
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
            numeric_keys = SUPPORT.CONTACT_KEYS[3:26] + SUPPORT.CONTACT_KEYS[27:28]
            numeric = {
                key: parse_uint(
                    record[key],
                    f"{label}.{key}",
                    positive=key == "rounds",
                )
                for key in numeric_keys
            }
            for key in (
                "handshake_frames",
                "handshake_bytes",
                "protected_frames",
                "protected_bytes",
            ):
                if numeric[key] == 0:
                    fail(f"{label}.{key} does not prove protected authenticated contact")
            excluded = (
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
            if any(numeric[key] for key in excluded):
                fail(f"{label} contains excluded or incomplete reconciliation activity")
            totals = contact_counters.setdefault(
                (local, phase),
                {"offered": 0, "fetched": 0, "inserted": 0},
            )
            for key in totals:
                totals[key] += numeric[key]
            contact_count[local] += 1
            contact_records += 1
            continue
        if line.startswith("STOP "):
            record = SUPPORT.parse_terminal_record(
                line, "STOP", SUPPORT.STOP_KEYS, label
            )
            carrier_participant = by_carrier.get(record["carrier_id"])
            mission_participant = by_mission.get(record["mission_id"])
            if carrier_participant is None or carrier_participant != mission_participant:
                fail(f"{label} does not bind one transcript participant")
            participant = carrier_participant
            phase = active.get(participant)
            if phase is None:
                fail(f"{label} closes an absent participant lifetime")
            expected = transcript_facts["_receipts"].get((phase, participant))
            if expected is None:
                fail(f"{label} has no public graceful receipt counterpart")
            require_fixed(
                record,
                {
                    "lifecycle": "complete",
                    "sync_status": (
                        "contacts_observed"
                        if expected["contacts"]
                        else "no_successful_contact"
                    ),
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
                    "events": "0",
                    "event_acceptance_markers": "0",
                    "route_cached_events": "0",
                    "mission_auth": "hybrid-pq",
                    "provisioning": "unprotected-reference",
                    "semantics": "source-authenticated-event",
                    "reconciliation_classes": "event,state,record,blob-v5",
                    "controls_semantics": "source-authenticated-flash",
                },
                label,
            )
            for key in SUPPORT.STOP_NUMERIC_FIELDS:
                parse_uint(record[key], f"{label}.{key}")
            if any(record[key] != "0" for key in SUPPORT.STOP_EXCLUDED_ZERO_FIELDS):
                fail(f"{label} contains excluded Event, Blob, or control activity")
            if contact_count[participant] != expected["contacts"]:
                fail(f"{label} CONTACT count differs from public receipt accounting")
            observed = contact_counters.get(
                (participant, phase),
                {"offered": 0, "fetched": 0, "inserted": 0},
            )
            for contact_key, receipt_key in (
                ("offered", "data_offered"),
                ("fetched", "data_fetched"),
                ("inserted", "data_inserted"),
            ):
                if observed[contact_key] != expected[receipt_key]:
                    fail(f"{label}.{contact_key} differs from public receipt accounting")
            del active[participant]
            contact_count[participant] = 0
            stop_count[participant] += 1
            stop_records += 1
            if (
                participant == "receiver"
                and phase == "peerless_redelivery_resolution"
            ):
                attempt_two_stopped = True
            continue
        fail(f"{label} belongs to an unadmitted terminal record family")

    if set(child_records) != {"ATTEMPT1_READY", "ATTEMPT2_DONE"}:
        fail("captured stdout does not contain exactly two child coordination records")
    publications = transcript_facts["_publications"]
    origin_ids = transcript_facts["_origin_ids"]
    singleton = transcript_facts["_singleton"]
    conflict_one = transcript_facts["_conflict_one"]
    conflict_two = transcript_facts["_conflict_two"]
    successor = transcript_facts["_successor"]
    attempt_one = child_records["ATTEMPT1_READY"]
    require_fixed(
        attempt_one,
        {
            "participant": "receiver",
            "identity": participants["receiver"]["mission_id"],
            "subscription_id": transcript_facts["_subscription_id"],
            "subscription_inserted": "false",
            "projection_id": conflict_one["projection_id"],
            "projection_topic": "opaque",
            "projection_scope": "test/runtime-contact",
            "projection_key_sha256": conflict_one["projection_key_sha256"],
            "edit_id": publications["edit"]["id"],
            "tombstone_id": publications["tombstone"]["id"],
            "current_id": conflict_one["current_id"],
            "concurrent_id": conflict_one["concurrent_id"],
            "siblings": ",".join(origin_ids),
            "attempt": "1",
            "token_sha256": conflict_one["token_sha256"],
            "delivery_limit": "1",
            "scan_limit": "16",
            "has_more": "false",
            "superseded_exposed": "false",
            "resolution_guard_exposed": "false",
            "token_persisted": "true",
            "singleton_projection_changed": "true",
            "beta_id": publications["beta"]["id"],
            "beta_present": "true",
            "gamma_empty": "true",
            "acknowledged": "false",
        },
        "LIVE_RECORD_SUBSCRIPTION_CHILD ATTEMPT1_READY",
    )
    attempt_two = child_records["ATTEMPT2_DONE"]
    require_fixed(
        attempt_two,
        {
            "participant": "receiver",
            "identity": participants["receiver"]["mission_id"],
            "subscription_id": transcript_facts["_subscription_id"],
            "subscription_inserted": "false",
            "projection_id": conflict_two["projection_id"],
            "projection_topic": "opaque",
            "projection_scope": "test/runtime-contact",
            "projection_key_sha256": conflict_two["projection_key_sha256"],
            "edit_id": publications["edit"]["id"],
            "tombstone_id": publications["tombstone"]["id"],
            "current_id": conflict_two["current_id"],
            "concurrent_id": conflict_two["concurrent_id"],
            "siblings": ",".join(origin_ids),
            "attempt": "2",
            "token_sha256": conflict_two["token_sha256"],
            "delivery_limit": "1",
            "scan_limit": "16",
            "has_more": "false",
            "superseded_exposed": "false",
            "resolution_guard_exposed": "false",
            "previous_token_sha256": conflict_one["token_sha256"],
            "tokens_distinct": "true",
            "previous_token_restored": "true",
            "malformed_token_rejected": "true",
            "wrong_subscription_token_rejected": "true",
            "wrong_projection_token_rejected": "true",
            "retired_singleton_token_rejected": "true",
            "retired_singleton_token_sha256": singleton["token_sha256"],
            "ack_token_attempt": "1",
            "reack_token_attempt": "2",
            "conflict_ack": "acknowledged",
            "conflict_reack": "already_acknowledged",
            "post_conflict_empty": "true",
            "guard_fresh_query": "true",
            "guard_siblings": ",".join(origin_ids),
            "resolution_id": publications["resolution"]["id"],
            "resolution_publisher": participants["receiver"]["mission_id"],
            "resolution_counter": "2",
            "resolution_inserted": "true",
            "resolution_retry_inserted": "false",
            "resolution_retry_same": "true",
            "successor_projection_id": successor["projection_id"],
            "successor_attempt": "1",
            "successor_token_sha256": successor["token_sha256"],
            "successor_ack": "acknowledged",
            "successor_reack": "already_acknowledged",
            "old_conflict_reack": "already_acknowledged",
            "post_successor_empty": "true",
            "superseded_ids": ",".join(origin_ids),
            "beta_id": publications["beta"]["id"],
            "beta_present": "true",
            "gamma_empty": "true",
            "token_artifacts_removed": "true",
            "closed_kind": "state_unavailable",
            "closed_operation": "record_query",
        },
        "LIVE_RECORD_SUBSCRIPTION_CHILD ATTEMPT2_DONE",
    )
    child_receipt = transcript_facts["_receipts"][
        ("peerless_redelivery_resolution", "receiver")
    ]
    for key in (
        "contacts",
        "contact_errors",
        "direct_contacts",
        "relay_contacts",
        "unknown_path_contacts",
        "events",
        "blobs",
        "data_offered",
        "data_fetched",
        "data_inserted",
        "data_duplicates",
        "data_remaining",
        "mutable_remaining",
        "deferred_mutable_lanes",
    ):
        if attempt_two[f"shutdown_{key}"] != str(child_receipt[key]):
            fail(f"ATTEMPT2_DONE.shutdown_{key} differs from public receipt")

    if ready_sequence != expected_ready_sequence:
        fail("captured stdout actor lifetime order differs from the frozen sequence")
    if active or ready_records != 7 or stop_records != 6 or active_maximum != 2:
        fail("captured stdout does not prove six graceful and one forced actor lifetime")
    if any(contact_count.values()) or contact_records == 0:
        fail("captured stdout leaves incomplete or absent direct CONTACT evidence")
    parent_lifetimes = {
        ("publisher", "peerless_origins"),
        ("publisher", "direct_conflict_and_selectors"),
        ("receiver", "peerless_origins"),
        ("receiver", "direct_conflict_and_selectors"),
        ("receiver", "final_peerless_reopen"),
    }
    child_lifetimes = {
        ("receiver", "forced_conflict_delivery"),
        ("receiver", "peerless_redelivery_resolution"),
    }
    parent_pids = {lifetime_pids[lifetime] for lifetime in parent_lifetimes}
    child_pids = {lifetime_pids[lifetime] for lifetime in child_lifetimes}
    if (
        len(parent_pids) != 1
        or len(child_pids) != 2
        or not parent_pids.isdisjoint(child_pids)
        or pids != parent_pids | child_pids
        or len(connected_sockets) != 2
        or len(set(connected_sockets.values())) != 2
    ):
        fail("captured stdout does not bind one parent and two child processes")
    totals = {
        key: sum(values[key] for values in contact_counters.values())
        for key in ("offered", "fetched", "inserted")
    }
    if totals != {"offered": 3, "fetched": 3, "inserted": 3}:
        fail("captured CONTACT records do not prove the exact three Record transfers")

    sensitive = {
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
        "child_coordination_records": 2,
        "processes": 3,
        "maximum_concurrent_processes": 2,
        "reconciliation": {
            "record_transfer": {
                "offered": totals["offered"],
                "fetched": totals["fetched"],
                "inserted": totals["inserted"],
                "duplicates": 0,
            },
            "direct_only": True,
            "event_activity": "all-zero",
            "control_activity": "all-zero",
            "blob_activity": "all-zero",
            "contact_stop_aggregation": "exact",
        },
        "identifiers_paths_ports_pids_tokens": "parsed-cross-bound-excluded",
        "_sensitive_values": sorted(sensitive),
        "_sensitive_pids": sorted(pids),
        "_sensitive_ports": sorted(ports),
    }


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
    return SUPPORT.validate_raw_root(root, source_authority)


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
            "source_binary_execution_link": (
                "operator-attested-not-cryptographically-proven"
            ),
        },
        "run": {
            "id": "excluded",
            "argv_redacted": [
                "<raw-root>/binary/aster-live-record-subscription-acceptance",
                "<raw-root>",
            ],
            "exact_argv_sha256": sha256_bytes(
                canonical_json_bytes(run["run_argv"])
            ),
            "exit_code": 0,
            "timeout_seconds": RUN_TIMEOUT_SECONDS,
            "processes": transcript["processes"],
            "maximum_concurrent_processes": transcript[
                "maximum_concurrent_processes"
            ],
            "stdout": {
                "bytes": run["artifacts"]["stdout"]["bytes"],
                "sha256": run["artifacts"]["stdout"]["sha256"],
                "lines": terminal["lines"],
                "ready_records": terminal["ready_records"],
                "contact_records": terminal["contact_records"],
                "stop_records": terminal["stop_records"],
                "child_coordination_records": terminal[
                    "child_coordination_records"
                ],
                "runtime_coordinates_and_tokens": terminal[
                    "identifiers_paths_ports_pids_tokens"
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
                "application_identifiers": "excluded",
                "payloads": "sha256-only",
                "opaque_tokens": "excluded-sha256-commitments-only",
            },
        },
        "acceptance": {
            "participants": transcript["participants"],
            "processes": transcript["processes"],
            "actor_lifetimes": transcript["actor_lifetimes"],
            "maximum_concurrent_processes": transcript[
                "maximum_concurrent_processes"
            ],
            "maximum_concurrent_actors": transcript[
                "maximum_concurrent_actors"
            ],
            "graceful_shutdowns": transcript["graceful_shutdowns"],
            "forced_process_terminations": transcript[
                "forced_process_terminations"
            ],
            "identity_binding": {
                "distinct_carrier_ids": 2,
                "distinct_mission_ids": 2,
                "common_disjoint_mission_authority": True,
                "reciprocal_expected_peers": "carrier-and-mission",
                "runtime_ready_contact_stop": "cross-bound",
            },
            "transport": {
                "shape": "one-host-loopback",
                "connected_phase": "positive-direct-only-zero-errors",
                "reconciliation": terminal["reconciliation"],
            },
            "record": {
                "publications": transcript["record_publications"],
                "network_insertions": transcript["network_record_insertions"],
                "payload_representation": "sha256-only",
                "whole_conflict": {
                    "heads": 2,
                    "one_delivery_at_limit_one": True,
                    "delivery_limit": transcript["delivery_limit"],
                    "scan_limit": transcript["scan_limit"],
                    "superseded_plaintext_exposed": transcript[
                        "superseded_exposed"
                    ],
                    "resolution_guard_exposed_by_delivery": transcript[
                        "resolution_guard_exposed"
                    ],
                    "stable_projection_across_attempts": True,
                },
                "explicit_resolution": {
                    "fresh_query_guard": True,
                    "guard_siblings": 2,
                    "inserted_then_exact_noninserting_retry": True,
                    "automatic_merge": False,
                },
                "successor": {
                    "new_projection": True,
                    "delivery_attempt": 1,
                    "superseded_query_only": transcript[
                        "query_only_superseded"
                    ],
                },
            },
            "subscription": {
                "insertions": transcript["subscription_insertions"],
                "durable_replays": transcript["subscription_replays"],
                "polls": transcript["polls"],
                "deliveries": transcript["deliveries"],
                "acknowledgements": transcript["acknowledgements"],
                "idempotent_reacknowledgements": transcript[
                    "reacknowledgements"
                ],
                "empty_polls": transcript["empty_polls"],
                "whole_projection_not_split": True,
                "final_pending": 0,
                "final_acknowledged": 1,
                "final_cursors": 1,
                "final_generation": 1,
            },
            "tokens": {
                "bytes": transcript["token_bytes"],
                "representation": "opaque-excluded-sha256-only",
                "retry_rotation": "distinct",
                "attempt_one_restored_for_acknowledgement": True,
                "binding_rejections": transcript["token_binding_checks"],
                "malformed_rejected": True,
                "wrong_subscription_rejected": True,
                "wrong_projection_rejected": True,
                "retired_singleton_rejected": True,
                "handoff_artifacts": "owner-only-fsynced-then-removed",
            },
            "forced_receiver_termination": {
                "mechanism": "parent-child-sigkill",
                "distinct_process": True,
                "after_flushed-durable-poll": True,
                "graceful": False,
                "stop_record_expected": False,
                "pretermination_acknowledged": False,
            },
            "selectors": {
                "beta_network_interested_application_unmatched_retained": True,
                "gamma_application_matched_network_uninterested_withheld": True,
                "subscription_does_not_mutate_network_interest": True,
            },
            "final_peerless_reopen": {
                "subscription_replayed": True,
                "resolved_current": True,
                "superseded_query_only": 2,
                "beta_retained": True,
                "gamma_empty": True,
                "delivery_queue_empty": True,
            },
            "store_inspection": {
                "publisher": {
                    "record_rows": 4,
                    "acceptance_markers": 4,
                    "operations": 3,
                    "subscription_stats": "all-zero",
                },
                "receiver": {
                    "record_rows": 4,
                    "acceptance_markers": 4,
                    "operations": 2,
                    "subscriptions": 1,
                    "pending": 0,
                    "acknowledged": 1,
                    "cursors": 1,
                    "generation": 1,
                },
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
            f"selected live Record subscription receipt validation failed: {error}",
            file=sys.stderr,
        )
        raise SystemExit(1) from error
    finally:
        if output is not None:
            os.close(output.parent_fd)


if __name__ == "__main__":
    main()
