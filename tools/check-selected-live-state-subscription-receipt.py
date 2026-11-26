#!/usr/bin/env python3
# Copyright 2026 Defense Unicorns, Inc.
# SPDX-License-Identifier: Apache-2.0
"""Project or validate one retained selected live State-subscription receipt.

The raw root is an owner-only, exact-inventory acceptance artifact.  Public
runtime output and the selected transcript are validated semantically; mission
bundles, identity keys, and stores are inspected by metadata only.  The output
is a compact canonical receipt and intentionally excludes ephemeral process,
socket, path, identity, publication, subscription, and token values.
"""

from __future__ import annotations

import argparse
import hashlib
import os
from pathlib import Path
import re
import stat
import sys
import types
from typing import Any, Iterable, Sequence


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
    sys.modules[module_name] = module
    try:
        code = compile(source, os.fspath(path), "exec", dont_inherit=True, optimize=0)
        exec(code, module.__dict__)
    except BaseException:
        sys.modules.pop(module_name, None)
        raise
    return module


RUNNER = _load_support(
    "run-selected-live-state-subscription.py",
    "selected_live_state_subscription_runner_contract",
)
SUPPORT = _load_support(
    "check-selected-live-event-receipt.py",
    "selected_live_state_subscription_checker_support",
)

SCHEMA = "aster-selected-live-state-subscription-receipt/v1"
RAW_SCHEMA = RUNNER.RAW_SCHEMA
TRANSCRIPT_SCHEMA = "aster-selected-live-state-subscription-transcript/v1"
CLAIM = RUNNER.CLAIM
RECEIPT_NAME = "selected-live-state-subscription-receipt.json"
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

HEX_32 = re.compile(r"[0-9a-f]{64}\Z")
FIELD_NAME = re.compile(r"[a-z][a-z0-9_]*\Z")
LOOPBACK_SOCKET = re.compile(r"127\.0\.0\.1:([1-9][0-9]{0,4})\Z")

PAYLOAD_HASHES = {
    "left": hashlib.sha256(b"left State").hexdigest(),
    "right": hashlib.sha256(b"right State").hexdigest(),
    "successor": hashlib.sha256(b"joined State").hexdigest(),
    "beta": hashlib.sha256(
        b"network-interested application-unsubscribed State"
    ).hexdigest(),
    "gamma": hashlib.sha256(b"authorized network-uninterested State").hexdigest(),
    "tombstone": hashlib.sha256(b"").hexdigest(),
}

RUN_KEYS = (
    "schema",
    "claim",
    "participants",
    "processes",
    "actor_lifetimes",
    "maximum_concurrent_actors",
    "alpha_topic",
    "beta_topic",
    "gamma_topic",
    "scope",
)
PARTICIPANT_KEYS = (
    "participant",
    "carrier_id",
    "mission_id",
    "mission_authority",
    "provisioning",
)
PEER_BINDING_KEYS = (
    "local",
    "remote",
    "local_carrier",
    "local_mission",
    "remote_carrier",
    "remote_mission",
    "mission_authenticated",
)
PHASE_KEYS = ("index", "phase", "actors", "outcome")
SUBSCRIPTION_KEYS = (
    "phase",
    "participant",
    "stream",
    "id",
    "inserted",
    "durable",
    "include_descendant_scopes",
)
STATE_KEYS = (
    "phase",
    "participant",
    "stream",
    "id",
    "publisher",
    "publisher_counter",
    "priority",
    "acceptance_marker",
    "inserted",
    "tombstone",
    "payload_sha256",
)
DELIVERY_KEYS = (
    "phase",
    "participant",
    "stream",
    "id",
    "publisher",
    "publisher_counter",
    "attempt",
    "token_sha256",
    "disposition",
    "tombstone",
    "payload_sha256",
)
PROJECTION_KEYS = (
    "phase",
    "participant",
    "stream",
    "current_id",
    "current_publisher",
    "current_counter",
    "current_disposition",
    "current_tombstone",
    "current_payload_sha256",
    "recoverable_count",
    "recoverable_ids",
    "recoverable_dispositions",
    "recoverable_tombstones",
    "recoverable_payload_sha256",
)
SELECTOR_KEYS = (
    "phase",
    "stream",
    "id",
    "publisher_retained",
    "network_interested",
    "receiver_retained",
    "alpha_application_delivered",
)
ACK_KEYS = (
    "phase",
    "participant",
    "id",
    "token_sha256",
    "token_attempt",
    "disposition",
)
EMPTY_POLL_KEYS = (
    "phase",
    "participant",
    "deliveries",
    "has_more",
    "delivery_limit",
    "scan_limit",
)
TERMINATION_KEYS = (
    "phase",
    "participant",
    "mechanism",
    "termination_signal",
    "distinct_process",
    "after_flushed_poll",
    "graceful",
    "stop_record_expected",
    "stop_record_observed",
    "acknowledged",
    "token_persisted",
    "token_artifact_permissions",
    "token_representation",
)
SHUTDOWN_KEYS = (
    "phase",
    "participant",
    "contacts",
    "contact_errors",
    "direct_contacts",
    "relay_contacts",
    "unknown_path_contacts",
    "data_offered",
    "data_fetched",
    "data_inserted",
    "data_duplicates",
    "data_remaining",
    "mutable_remaining",
    "deferred_mutable_lanes",
    "excluded_class_counters",
)
STORE_INSPECTION_KEYS = (
    "participant",
    "states",
    "state_acceptance_markers",
    "state_operations",
    "subscriptions",
    "pending_deliveries",
    "acknowledged_deliveries",
    "delivery_cursors",
    "selector_generation",
    "event_record_blob_opaque_control",
)
BIND_KEYS = ("participant", "status")
RESULT_KEYS = (
    "status",
    "records",
    "phases",
    "participants",
    "processes",
    "actor_lifetimes",
    "maximum_concurrent_actors",
    "graceful_shutdowns",
    "forced_process_terminations",
    "closed_handles",
    "state_publications",
    "network_state_insertions",
    "deliveries",
    "acknowledgements",
    "reacknowledgements",
    "token_binding_checks",
    "malformed_token_rejected",
    "wrong_subscription_token_rejected",
    "wrong_state_token_rejected",
    "retired_token_rejected",
    "empty_polls",
    "subscription_insertions",
    "subscription_replays",
    "bind_reacquisitions",
    "payload_representation",
    "token_representation",
    "opaque_tokens_emitted",
    "secret_values_emitted",
    "physical_network_claimed",
    "global_convergence_claimed",
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
    ("STATE", STATE_KEYS),
    ("STATE", STATE_KEYS),
    ("DELIVERY", DELIVERY_KEYS),
    ("PROJECTION", PROJECTION_KEYS),
    ("PROJECTION", PROJECTION_KEYS),
    ("SHUTDOWN", SHUTDOWN_KEYS),
    ("SHUTDOWN", SHUTDOWN_KEYS),
    ("PHASE", PHASE_KEYS),
    ("SUBSCRIPTION", SUBSCRIPTION_KEYS),
    ("PROJECTION", PROJECTION_KEYS),
    ("PROJECTION", PROJECTION_KEYS),
    ("STATE", STATE_KEYS),
    ("PROJECTION", PROJECTION_KEYS),
    ("PROJECTION", PROJECTION_KEYS),
    ("STATE", STATE_KEYS),
    ("STATE", STATE_KEYS),
    ("SELECTOR", SELECTOR_KEYS),
    ("SELECTOR", SELECTOR_KEYS),
    ("SHUTDOWN", SHUTDOWN_KEYS),
    ("SHUTDOWN", SHUTDOWN_KEYS),
    ("PHASE", PHASE_KEYS),
    ("SUBSCRIPTION", SUBSCRIPTION_KEYS),
    ("PROJECTION", PROJECTION_KEYS),
    ("DELIVERY", DELIVERY_KEYS),
    ("PROCESS_TERMINATION", TERMINATION_KEYS),
    ("PHASE", PHASE_KEYS),
    ("SUBSCRIPTION", SUBSCRIPTION_KEYS),
    ("DELIVERY", DELIVERY_KEYS),
    ("ACKNOWLEDGEMENT", ACK_KEYS),
    ("REACKNOWLEDGEMENT", ACK_KEYS),
    ("EMPTY_POLL", EMPTY_POLL_KEYS),
    ("SHUTDOWN", SHUTDOWN_KEYS),
    ("PHASE", PHASE_KEYS),
    ("SUBSCRIPTION", SUBSCRIPTION_KEYS),
    ("STATE", STATE_KEYS),
    ("DELIVERY", DELIVERY_KEYS),
    ("ACKNOWLEDGEMENT", ACK_KEYS),
    ("REACKNOWLEDGEMENT", ACK_KEYS),
    ("EMPTY_POLL", EMPTY_POLL_KEYS),
    ("PROJECTION", PROJECTION_KEYS),
    ("SHUTDOWN", SHUTDOWN_KEYS),
    ("PHASE", PHASE_KEYS),
    ("SUBSCRIPTION", SUBSCRIPTION_KEYS),
    ("PROJECTION", PROJECTION_KEYS),
    ("PROJECTION", PROJECTION_KEYS),
    ("SELECTOR", SELECTOR_KEYS),
    ("SELECTOR", SELECTOR_KEYS),
    ("EMPTY_POLL", EMPTY_POLL_KEYS),
    ("SHUTDOWN", SHUTDOWN_KEYS),
    ("SHUTDOWN", SHUTDOWN_KEYS),
    ("PHASE", PHASE_KEYS),
    ("SUBSCRIPTION", SUBSCRIPTION_KEYS),
    ("PROJECTION", PROJECTION_KEYS),
    ("SELECTOR", SELECTOR_KEYS),
    ("SELECTOR", SELECTOR_KEYS),
    ("EMPTY_POLL", EMPTY_POLL_KEYS),
    ("SHUTDOWN", SHUTDOWN_KEYS),
    ("STORE_INSPECTION", STORE_INSPECTION_KEYS),
    ("STORE_INSPECTION", STORE_INSPECTION_KEYS),
    ("BIND", BIND_KEYS),
    ("BIND", BIND_KEYS),
    ("RESULT", RESULT_KEYS),
)

PHASES = (
    (1, "peerless_origins", "publisher+receiver", "unacknowledged-origin"),
    (
        2,
        "direct_convergence_and_successor",
        "publisher+receiver",
        "successor-and-selectors",
    ),
    (3, "forced_successor_delivery", "receiver-child", "force-terminated"),
    (4, "peerless_redelivery_ack", "receiver-child", "acknowledged"),
    (5, "peerless_tombstone", "receiver", "explicit-current-tombstone"),
    (
        6,
        "direct_tombstone_propagation",
        "publisher+receiver",
        "converged-empty",
    ),
    (7, "final_peerless_reopen", "receiver", "durable-empty"),
)

LIMITATIONS = [
    "operator-attested-source-binary-execution-link-not-cryptographically-proven",
    "selected-admitted-source-list-is-not-a-complete-reproducible-build-closure",
    "one-host-loopback-same-implementation-observation",
    "participant-secret-artifacts-validated-by-metadata-only",
    "state-causal-observation-and-publication-order-are-producer-attested",
    "network-interest-and-application-subscription-are-separate-static-surfaces",
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
    "event-record-or-blob-live-application-acceptance",
    "reproducible-build-or-cryptographic-source-to-execution-provenance",
    "dynamic-network-interest-mutation-through-state-subscriptions",
    "tombstone-retention-duration-compaction-or-garbage-collection",
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
        or parts[:2] != ["LIVE_STATE_SUBSCRIPTION", expected_type.lower()]
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


def _exact_projection(
    record: dict[str, str],
    *,
    phase: str,
    participant: str,
    stream: str,
    current: dict[str, str],
    recoverable: Sequence[dict[str, str]],
    recoverable_disposition: str,
) -> None:
    ordered = sorted(recoverable, key=lambda item: item["id"])
    require_fixed(
        record,
        {
            "phase": phase,
            "participant": participant,
            "stream": stream,
            "current_id": current["id"],
            "current_publisher": current["publisher"],
            "current_counter": current["publisher_counter"],
            "current_disposition": "current",
            "current_tombstone": current["tombstone"],
            "current_payload_sha256": current["payload_sha256"],
            "recoverable_count": str(len(ordered)),
            "recoverable_ids": "none"
            if not ordered
            else ",".join(item["id"] for item in ordered),
            "recoverable_dispositions": "none"
            if not ordered
            else ",".join(recoverable_disposition for _item in ordered),
            "recoverable_tombstones": "none"
            if not ordered
            else ",".join(item["tombstone"] for item in ordered),
            "recoverable_payload_sha256": "none"
            if not ordered
            else ",".join(item["payload_sha256"] for item in ordered),
        },
        f"PROJECTION {phase}/{participant}/{stream}",
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
    if len(lines) != TRANSCRIPT_RECORDS:
        fail(f"transcript does not contain exactly {TRANSCRIPT_RECORDS} records")
    if len(EXPECTED_SEQUENCE) != TRANSCRIPT_RECORDS:
        raise AssertionError("checker transcript sequence length is inconsistent")
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
            "actor_lifetimes": "10",
            "maximum_concurrent_actors": "2",
            "alpha_topic": "opaque",
            "beta_topic": "opaque.beta",
            "gamma_topic": "opaque.gamma",
            "scope": "test/runtime-contact",
        },
        "RUN",
    )

    participants: dict[str, dict[str, str]] = {}
    for index, name in ((1, "publisher"), (2, "receiver")):
        record = records[index]
        require_fixed(
            record,
            {
                "participant": name,
                "provisioning": "independent-reference-bundle",
            },
            f"PARTICIPANT {name}",
        )
        for key in ("carrier_id", "mission_id", "mission_authority"):
            require_id(record[key], f"PARTICIPANT {name}.{key}")
        participants[name] = record
    publisher = participants["publisher"]
    receiver = participants["receiver"]
    if publisher["mission_authority"] != receiver["mission_authority"]:
        fail("participants do not share exactly one mission authority")
    identity_domains = {
        publisher["carrier_id"],
        receiver["carrier_id"],
        publisher["mission_id"],
        receiver["mission_id"],
        publisher["mission_authority"],
    }
    if len(identity_domains) != 5 or publisher["carrier_id"] >= receiver["carrier_id"]:
        fail("participant identity domains or deterministic initiation ordering differ")
    for index, local, remote in (
        (3, "publisher", "receiver"),
        (4, "receiver", "publisher"),
    ):
        require_fixed(
            records[index],
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

    phase_indices = (5, 15, 28, 33, 40, 49, 58)
    for index, (number, phase, actors, outcome) in zip(
        phase_indices, PHASES, strict=True
    ):
        require_fixed(
            records[index],
            {
                "index": str(number),
                "phase": phase,
                "actors": actors,
                "outcome": outcome,
            },
            f"PHASE {number}",
        )

    subscription_indices = (6, 7, 16, 29, 34, 41, 50, 59)
    subscription_id = records[subscription_indices[0]]["id"]
    require_id(subscription_id, "State subscription identifier")
    for ordinal, index in enumerate(subscription_indices):
        phase = records[index]["phase"]
        require_fixed(
            records[index],
            {
                "phase": phase,
                "participant": "receiver",
                "stream": "alpha",
                "id": subscription_id,
                "inserted": "true" if ordinal == 0 else "false",
                "durable": "true",
                "include_descendant_scopes": "false",
            },
            f"SUBSCRIPTION {ordinal + 1}",
        )
    expected_subscription_phases = (
        "peerless_origins",
        "peerless_origins",
        "direct_convergence_and_successor",
        "forced_successor_delivery",
        "peerless_redelivery_ack",
        "peerless_tombstone",
        "direct_tombstone_propagation",
        "final_peerless_reopen",
    )
    observed_subscription_phases = tuple(
        records[index]["phase"] for index in subscription_indices
    )
    if observed_subscription_phases != expected_subscription_phases:
        fail("State subscription records do not follow the exact phase sequence")

    publication_specs = (
        (8, "left", "peerless_origins", "publisher", "alpha-left", 1, False),
        (9, "right", "peerless_origins", "receiver", "alpha-right", 1, False),
        (
            19,
            "successor",
            "direct_convergence_and_successor",
            "publisher",
            "alpha-successor",
            2,
            False,
        ),
        (
            22,
            "beta",
            "direct_convergence_and_successor",
            "publisher",
            "beta",
            3,
            False,
        ),
        (
            23,
            "gamma",
            "direct_convergence_and_successor",
            "publisher",
            "gamma",
            4,
            False,
        ),
        (
            42,
            "tombstone",
            "peerless_tombstone",
            "receiver",
            "alpha-tombstone",
            2,
            True,
        ),
    )
    states: dict[str, dict[str, str]] = {}
    seen_markers: dict[str, set[int]] = {name: set() for name in participants}
    for index, name, phase, participant, stream, counter, tombstone in publication_specs:
        record = records[index]
        require_id(record["id"], f"STATE {name}.id")
        require_id(record["publisher"], f"STATE {name}.publisher")
        require_fixed(
            record,
            {
                "phase": phase,
                "participant": participant,
                "stream": stream,
                "publisher": participants[participant]["mission_id"],
                "publisher_counter": str(counter),
                "priority": "priority",
                "inserted": "true",
                "tombstone": str(tombstone).lower(),
                "payload_sha256": PAYLOAD_HASHES[name],
            },
            f"STATE {name}",
        )
        marker = parse_uint(
            record["acceptance_marker"], f"STATE {name}.acceptance_marker", positive=True
        )
        if marker in seen_markers[participant]:
            fail(f"STATE {name}.acceptance_marker repeats in one publication domain")
        seen_markers[participant].add(marker)
        states[name] = record
    if len({record["id"] for record in states.values()}) != len(states):
        fail("State publication identities are not pairwise distinct")

    delivery_tokens: dict[str, str] = {}

    def exact_delivery(
        index: int,
        state_name: str,
        phase: str,
        stream: str,
        attempt: int,
    ) -> None:
        state = states[state_name]
        token_digest = require_id(
            records[index]["token_sha256"], f"DELIVERY {phase}.token_sha256"
        )
        delivery_tokens[phase] = token_digest
        require_fixed(
            records[index],
            {
                "phase": phase,
                "participant": "receiver",
                "stream": stream,
                "id": state["id"],
                "publisher": state["publisher"],
                "publisher_counter": state["publisher_counter"],
                "attempt": str(attempt),
                "token_sha256": token_digest,
                "disposition": "current",
                "tombstone": state["tombstone"],
                "payload_sha256": state["payload_sha256"],
            },
            f"DELIVERY {phase}",
        )

    exact_delivery(10, "right", "peerless_origins", "alpha-right", 1)
    exact_delivery(
        31,
        "successor",
        "forced_successor_delivery",
        "alpha-successor",
        1,
    )
    exact_delivery(
        35,
        "successor",
        "peerless_redelivery_ack",
        "alpha-successor",
        2,
    )
    exact_delivery(43, "tombstone", "peerless_tombstone", "alpha-tombstone", 1)
    if (
        delivery_tokens["forced_successor_delivery"]
        == delivery_tokens["peerless_redelivery_ack"]
    ):
        fail("fresh-process State redelivery reused its opaque token digest")

    _exact_projection(
        records[11],
        phase="peerless_origins",
        participant="publisher",
        stream="alpha",
        current=states["left"],
        recoverable=(),
        recoverable_disposition="superseded",
    )
    _exact_projection(
        records[12],
        phase="peerless_origins",
        participant="receiver",
        stream="alpha",
        current=states["right"],
        recoverable=(),
        recoverable_disposition="superseded",
    )
    origins = sorted((states["left"], states["right"]), key=lambda item: item["id"])
    concurrent_current = origins[1]
    concurrent_recoverable = (origins[0],)
    for index, participant in ((17, "publisher"), (18, "receiver")):
        _exact_projection(
            records[index],
            phase="direct_convergence_and_successor",
            participant=participant,
            stream="alpha-concurrent",
            current=concurrent_current,
            recoverable=concurrent_recoverable,
            recoverable_disposition="concurrent",
        )
    for index, participant in ((20, "publisher"), (21, "receiver")):
        _exact_projection(
            records[index],
            phase="direct_convergence_and_successor",
            participant=participant,
            stream="alpha-successor",
            current=states["successor"],
            recoverable=origins,
            recoverable_disposition="superseded",
        )
    _exact_projection(
        records[30],
        phase="forced_successor_delivery",
        participant="receiver",
        stream="alpha-successor-child-validated",
        current=states["successor"],
        recoverable=origins,
        recoverable_disposition="superseded",
    )
    tombstone_history = (states["left"], states["right"], states["successor"])
    for index, phase, participant in (
        (47, "peerless_tombstone", "receiver"),
        (51, "direct_tombstone_propagation", "publisher"),
        (52, "direct_tombstone_propagation", "receiver"),
        (60, "final_peerless_reopen", "receiver"),
    ):
        _exact_projection(
            records[index],
            phase=phase,
            participant=participant,
            stream="alpha-tombstone",
            current=states["tombstone"],
            recoverable=tombstone_history,
            recoverable_disposition="superseded",
        )

    for index, phase, stream, state_name, network, retained in (
        (24, "direct_convergence_and_successor", "beta", "beta", True, True),
        (25, "direct_convergence_and_successor", "gamma", "gamma", False, False),
        (53, "direct_tombstone_propagation", "beta", "beta", True, True),
        (54, "direct_tombstone_propagation", "gamma", "gamma", False, False),
        (61, "final_peerless_reopen", "beta", "beta", True, True),
        (62, "final_peerless_reopen", "gamma", "gamma", False, False),
    ):
        require_fixed(
            records[index],
            {
                "phase": phase,
                "stream": stream,
                "id": states[state_name]["id"],
                "publisher_retained": "true",
                "network_interested": str(network).lower(),
                "receiver_retained": str(retained).lower(),
                "alpha_application_delivered": "false",
            },
            f"SELECTOR {phase}/{stream}",
        )

    for index, phase, state_name, token_phase, token_attempt, disposition in (
        (
            36,
            "peerless_redelivery_ack",
            "successor",
            "forced_successor_delivery",
            1,
            "acknowledged",
        ),
        (
            37,
            "peerless_redelivery_ack",
            "successor",
            "peerless_redelivery_ack",
            2,
            "already_acknowledged",
        ),
        (
            44,
            "peerless_tombstone",
            "tombstone",
            "peerless_tombstone",
            1,
            "acknowledged",
        ),
        (
            45,
            "peerless_tombstone",
            "tombstone",
            "peerless_tombstone",
            1,
            "already_acknowledged",
        ),
    ):
        require_fixed(
            records[index],
            {
                "phase": phase,
                "participant": "receiver",
                "id": states[state_name]["id"],
                "token_sha256": delivery_tokens[token_phase],
                "token_attempt": str(token_attempt),
                "disposition": disposition,
            },
            f"acknowledgement {phase}/{disposition}",
        )
    for index, phase in (
        (38, "peerless_redelivery_ack"),
        (46, "peerless_tombstone"),
        (55, "direct_tombstone_propagation"),
        (63, "final_peerless_reopen"),
    ):
        require_fixed(
            records[index],
            {
                "phase": phase,
                "participant": "receiver",
                "deliveries": "0",
                "has_more": "false",
                "delivery_limit": "8",
                "scan_limit": "16",
            },
            f"EMPTY_POLL {phase}",
        )
    require_fixed(
        records[32],
        {
            "phase": "forced_successor_delivery",
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
            "token_artifact_permissions": "owner-only",
            "token_representation": "sha256-only",
        },
        "PROCESS_TERMINATION",
    )

    shutdown_specs = (
        (13, "peerless_origins", "publisher", False),
        (14, "peerless_origins", "receiver", False),
        (26, "direct_convergence_and_successor", "publisher", True),
        (27, "direct_convergence_and_successor", "receiver", True),
        (39, "peerless_redelivery_ack", "receiver", False),
        (48, "peerless_tombstone", "receiver", False),
        (56, "direct_tombstone_propagation", "publisher", True),
        (57, "direct_tombstone_propagation", "receiver", True),
        (64, "final_peerless_reopen", "receiver", False),
    )
    shutdowns: dict[str, dict[str, dict[str, int]]] = {}
    for index, phase, participant, connected in shutdown_specs:
        record = records[index]
        require_fixed(
            record,
            {
                "phase": phase,
                "participant": participant,
                "contact_errors": "0",
                "relay_contacts": "0",
                "unknown_path_contacts": "0",
                "data_duplicates": "0",
                "data_remaining": "0",
                "mutable_remaining": "0",
                "deferred_mutable_lanes": "0",
                "excluded_class_counters": "all-zero",
            },
            f"SHUTDOWN {phase}/{participant}",
        )
        numeric = {
            key: parse_uint(record[key], f"SHUTDOWN {phase}/{participant}.{key}")
            for key in SHUTDOWN_KEYS[2:-1]
        }
        if connected:
            if numeric["contacts"] == 0 or numeric["direct_contacts"] != numeric["contacts"]:
                fail(f"SHUTDOWN {phase}/{participant} does not prove positive direct contact")
        elif any(numeric[key] for key in numeric):
            fail(f"SHUTDOWN {phase}/{participant} contains peerless activity")
        shutdowns.setdefault(phase, {})[participant] = numeric
    for phase, expected_inserted in (
        ("direct_convergence_and_successor", 4),
        ("direct_tombstone_propagation", 1),
    ):
        pair = tuple(shutdowns[phase].values())
        for key in ("data_offered", "data_fetched", "data_inserted"):
            if sum(record[key] for record in pair) != expected_inserted:
                fail(f"SHUTDOWN {phase} does not prove exact State {key}")

    for index, participant, expected in (
        (
            65,
            "publisher",
            {
                "states": "6",
                "state_acceptance_markers": "6",
                "state_operations": "4",
                "subscriptions": "0",
                "pending_deliveries": "0",
                "acknowledged_deliveries": "0",
                "delivery_cursors": "0",
                "selector_generation": "0",
            },
        ),
        (
            66,
            "receiver",
            {
                "states": "5",
                "state_acceptance_markers": "5",
                "state_operations": "2",
                "subscriptions": "1",
                "pending_deliveries": "0",
                "acknowledged_deliveries": "1",
                "delivery_cursors": "3",
                "selector_generation": "1",
            },
        ),
    ):
        require_fixed(
            records[index],
            {
                "participant": participant,
                **expected,
                "event_record_blob_opaque_control": "all-zero",
            },
            f"STORE_INSPECTION {participant}",
        )
        for key in STORE_INSPECTION_KEYS[1:-1]:
            parse_uint(records[index][key], f"STORE_INSPECTION {participant}.{key}")
    for index, participant in ((67, "publisher"), (68, "receiver")):
        require_fixed(
            records[index],
            {"participant": participant, "status": "reacquired"},
            f"BIND {participant}",
        )
    require_fixed(
        records[69],
        {
            "status": "pass",
            "records": "70",
            "phases": "7",
            "participants": "2",
            "processes": "3",
            "actor_lifetimes": "10",
            "maximum_concurrent_actors": "2",
            "graceful_shutdowns": "9",
            "forced_process_terminations": "1",
            "closed_handles": "9",
            "state_publications": "6",
            "network_state_insertions": "5",
            "deliveries": "4",
            "acknowledgements": "2",
            "reacknowledgements": "2",
            "token_binding_checks": "8",
            "malformed_token_rejected": "true",
            "wrong_subscription_token_rejected": "true",
            "wrong_state_token_rejected": "true",
            "retired_token_rejected": "true",
            "empty_polls": "4",
            "subscription_insertions": "1",
            "subscription_replays": "7",
            "bind_reacquisitions": "2",
            "payload_representation": "sha256-only",
            "token_representation": "sha256-only",
            "opaque_tokens_emitted": "false",
            "secret_values_emitted": "false",
            "physical_network_claimed": "false",
            "global_convergence_claimed": "false",
        },
        "RESULT",
    )

    application_ids = {
        subscription_id,
        *(record["id"] for record in states.values()),
        *delivery_tokens.values(),
    }
    return {
        "records": len(records),
        "bytes": len(data),
        "sha256": sha256_bytes(data),
        "participants": 2,
        "processes": 3,
        "actor_lifetimes": 10,
        "maximum_concurrent_actors": 2,
        "phases": 7,
        "state_publications": 6,
        "network_state_insertions": 5,
        "deliveries": 4,
        "acknowledgements": 2,
        "idempotent_reacknowledgements": 2,
        "token_binding_checks": 8,
        "empty_polls": 4,
        "subscription_insertions": 1,
        "subscription_replays": 7,
        "forced_process_terminations": 1,
        "graceful_shutdowns": 9,
        "closed_handles": 9,
        "bind_reacquisitions": 2,
        "_participants": participants,
        "_subscription": subscription_id,
        "_states": states,
        "_delivery_tokens": delivery_tokens,
        "_shutdown_counters": shutdowns,
        "_application_ids": sorted(application_ids),
    }


ATTEMPT_ONE_CHILD_KEYS = (
    "participant",
    "identity",
    "subscription_id",
    "subscription_inserted",
    "successor_id",
    "successor_publisher",
    "successor_counter",
    "successor_attempt",
    "successor_token_sha256",
    "successor_token_persisted",
    "successor_payload_sha256",
    "successor_disposition",
    "successor_tombstone",
    "old_left_absent",
    "old_right_absent",
    "beta_absent",
    "gamma_query_empty",
    "acknowledged",
)
ATTEMPT_TWO_CHILD_KEYS = (
    "participant",
    "identity",
    "subscription_id",
    "subscription_inserted",
    "successor_id",
    "successor_publisher",
    "successor_counter",
    "successor_attempt",
    "successor_token_sha256",
    "previous_token_sha256",
    "tokens_distinct",
    "previous_token_restored",
    "malformed_token_rejected",
    "wrong_subscription_token_rejected",
    "wrong_state_token_rejected",
    "retired_token_rejected",
    "retired_token_sha256",
    "ack_token_attempt",
    "reack_token_attempt",
    "token_artifact_removed",
    "successor_payload_sha256",
    "successor_disposition",
    "successor_tombstone",
    "ack",
    "reack",
    "empty_deliveries",
    "empty_has_more",
    "closed_kind",
    "closed_operation",
    "shutdown_contacts",
    "shutdown_contact_errors",
    "shutdown_direct_contacts",
    "shutdown_relay_contacts",
    "shutdown_unknown_path_contacts",
    "shutdown_events",
    "shutdown_blobs",
    "shutdown_data_offered",
    "shutdown_data_fetched",
    "shutdown_data_inserted",
    "shutdown_data_duplicates",
    "shutdown_data_remaining",
    "shutdown_mutable_remaining",
    "shutdown_deferred_mutable_lanes",
)


def _parse_child_record(line: str, label: str) -> tuple[str, dict[str, str]]:
    parts = line.split("\t")
    if len(parts) < 3 or parts[0] != "LIVE_STATE_SUBSCRIPTION_CHILD":
        fail(f"{label} has malformed child coordination framing")
    kind = parts[1]
    expected = {
        "ATTEMPT1_READY": ATTEMPT_ONE_CHILD_KEYS,
        "ATTEMPT2_DONE": ATTEMPT_TWO_CHILD_KEYS,
    }.get(kind)
    if expected is None or len(parts) != len(expected) + 2:
        fail(f"{label} has an unexpected child coordination kind or field count")
    record: dict[str, str] = {}
    order: list[str] = []
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
        order.append(key)
        record[key] = value
    if tuple(order) != expected:
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
        if line.startswith("LIVE_STATE_SUBSCRIPTION\t")
    )
    if extracted != transcript:
        fail("transcript is not the exact ordered State-subscription extraction from stdout")

    participants = transcript_facts["_participants"]
    by_carrier = {record["carrier_id"]: name for name, record in participants.items()}
    by_mission = {record["mission_id"]: name for name, record in participants.items()}
    lifetime_order = {
        "publisher": (
            "peerless_origins",
            "direct_convergence_and_successor",
            "direct_tombstone_propagation",
        ),
        "receiver": (
            "peerless_origins",
            "direct_convergence_and_successor",
            "forced_successor_delivery",
            "peerless_redelivery_ack",
            "peerless_tombstone",
            "direct_tombstone_propagation",
            "final_peerless_reopen",
        ),
    }
    connected_phases = {
        "direct_convergence_and_successor",
        "direct_tombstone_propagation",
    }
    ready_count = {participant: 0 for participant in participants}
    stop_count = {participant: 0 for participant in participants}
    active: dict[str, str] = {}
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
        if line.startswith("LIVE_STATE_SUBSCRIPTION\t"):
            transcript_started = True
            continue
        if transcript_started:
            fail(f"{label} appears after the public transcript began")
        if line.startswith("LIVE_STATE_SUBSCRIPTION_CHILD\t"):
            kind, record = _parse_child_record(line, label)
            if kind in child_records:
                fail(f"{label} duplicates one child coordination kind")
            if kind == "ATTEMPT1_READY":
                if active.get("receiver") != "forced_successor_delivery":
                    fail(f"{label} is outside the force-terminated receiver lifetime")
                # This flushed record is the parent's kill boundary.  A STOP for
                # this lifetime is deliberately inadmissible.
                del active["receiver"]
                contact_count["receiver"] = 0
            elif not attempt_two_stopped:
                fail(f"{label} precedes the peerless redelivery STOP")
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
            peers = "1" if phase in connected_phases else "0"
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
            if phase in connected_phases:
                prior = connected_sockets.get(participant)
                if prior is not None and prior != record["sockets"]:
                    fail(f"{label}.sockets does not preserve the reserved connected bind")
                connected_sockets[participant] = record["sockets"]
            ready_count[participant] += 1
            active[participant] = phase
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
            if phase not in connected_phases or active.get(remote) != phase:
                fail(f"{label} occurs outside two active peers in one connected phase")
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
            numeric_keys = SUPPORT.CONTACT_KEYS[3:26] + SUPPORT.CONTACT_KEYS[27:28]
            numeric = {
                key: parse_uint(record[key], f"{label}.{key}", positive=key == "rounds")
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
                fail(f"{label} contains non-State or incomplete reconciliation activity")
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
            record = SUPPORT.parse_terminal_record(line, "STOP", SUPPORT.STOP_KEYS, label)
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
                    "sync_status": "contacts_observed"
                    if expected["contacts"]
                    else "no_successful_contact",
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
            if record["events"] != "0" or record["event_acceptance_markers"] != "0":
                fail(f"{label} contains excluded Event activity")
            if contact_count[participant] != expected["contacts"]:
                fail(f"{label} CONTACT count differs from shutdown accounting")
            observed = contact_counters.get(
                (participant, phase), {"offered": 0, "fetched": 0, "inserted": 0}
            )
            for contact_key, shutdown_key in (
                ("offered", "data_offered"),
                ("fetched", "data_fetched"),
                ("inserted", "data_inserted"),
            ):
                if observed[contact_key] != expected[shutdown_key]:
                    fail(f"{label}.{contact_key} differs from public shutdown accounting")
            del active[participant]
            contact_count[participant] = 0
            stop_count[participant] += 1
            stop_records += 1
            if participant == "receiver" and phase == "peerless_redelivery_ack":
                attempt_two_stopped = True
            continue
        fail(f"{label} belongs to an unadmitted terminal record family")

    if set(child_records) != {"ATTEMPT1_READY", "ATTEMPT2_DONE"}:
        fail("captured stdout does not contain exactly two child coordination records")
    states = transcript_facts["_states"]
    attempt_one = child_records["ATTEMPT1_READY"]
    require_fixed(
        attempt_one,
        {
            "participant": "receiver",
            "identity": participants["receiver"]["mission_id"],
            "subscription_id": transcript_facts["_subscription"],
            "subscription_inserted": "false",
            "successor_id": states["successor"]["id"],
            "successor_publisher": participants["publisher"]["mission_id"],
            "successor_counter": "2",
            "successor_attempt": "1",
            "successor_token_sha256": transcript_facts["_delivery_tokens"][
                "forced_successor_delivery"
            ],
            "successor_token_persisted": "true",
            "successor_payload_sha256": PAYLOAD_HASHES["successor"],
            "successor_disposition": "current",
            "successor_tombstone": "false",
            "old_left_absent": "true",
            "old_right_absent": "true",
            "beta_absent": "true",
            "gamma_query_empty": "true",
            "acknowledged": "false",
        },
        "LIVE_STATE_SUBSCRIPTION_CHILD ATTEMPT1_READY",
    )
    attempt_two = child_records["ATTEMPT2_DONE"]
    require_fixed(
        attempt_two,
        {
            "participant": "receiver",
            "identity": participants["receiver"]["mission_id"],
            "subscription_id": transcript_facts["_subscription"],
            "subscription_inserted": "false",
            "successor_id": states["successor"]["id"],
            "successor_publisher": participants["publisher"]["mission_id"],
            "successor_counter": "2",
            "successor_attempt": "2",
            "successor_token_sha256": transcript_facts["_delivery_tokens"][
                "peerless_redelivery_ack"
            ],
            "previous_token_sha256": transcript_facts["_delivery_tokens"][
                "forced_successor_delivery"
            ],
            "tokens_distinct": "true",
            "previous_token_restored": "true",
            "malformed_token_rejected": "true",
            "wrong_subscription_token_rejected": "true",
            "wrong_state_token_rejected": "true",
            "retired_token_rejected": "true",
            "retired_token_sha256": transcript_facts["_delivery_tokens"][
                "peerless_origins"
            ],
            "ack_token_attempt": "1",
            "reack_token_attempt": "2",
            "token_artifact_removed": "true",
            "successor_payload_sha256": PAYLOAD_HASHES["successor"],
            "successor_disposition": "current",
            "successor_tombstone": "false",
            "ack": "acknowledged",
            "reack": "already_acknowledged",
            "empty_deliveries": "0",
            "empty_has_more": "false",
            "closed_kind": "state_unavailable",
            "closed_operation": "state_query",
        },
        "LIVE_STATE_SUBSCRIPTION_CHILD ATTEMPT2_DONE",
    )
    redelivery_shutdown = transcript_facts["_shutdown_counters"][
        "peerless_redelivery_ack"
    ]["receiver"]
    for key in (
        "contacts",
        "contact_errors",
        "direct_contacts",
        "relay_contacts",
        "unknown_path_contacts",
        "data_offered",
        "data_fetched",
        "data_inserted",
        "data_duplicates",
        "data_remaining",
        "mutable_remaining",
        "deferred_mutable_lanes",
    ):
        if attempt_two[f"shutdown_{key}"] != str(redelivery_shutdown[key]):
            fail(f"ATTEMPT2_DONE.shutdown_{key} differs from public shutdown")
    for key in ("shutdown_events", "shutdown_blobs"):
        if attempt_two[key] != "0":
            fail(f"ATTEMPT2_DONE.{key} is nonzero")

    if any(ready_count[name] != len(lifetime_order[name]) for name in participants):
        fail("captured stdout does not contain exactly ten actor READY records")
    if active or ready_records != 10 or stop_records != 9 or active_maximum != 2:
        fail("captured stdout does not prove nine graceful and one forced actor lifetime")
    if any(contact_count.values()) or contact_records == 0:
        fail("captured stdout leaves incomplete or absent direct CONTACT evidence")
    parent_lifetimes = {
        *(('publisher', phase) for phase in lifetime_order["publisher"]),
        ("receiver", "peerless_origins"),
        ("receiver", "direct_convergence_and_successor"),
        ("receiver", "peerless_tombstone"),
        ("receiver", "direct_tombstone_propagation"),
        ("receiver", "final_peerless_reopen"),
    }
    child_lifetimes = {
        ("receiver", "forced_successor_delivery"),
        ("receiver", "peerless_redelivery_ack"),
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

    sensitive = {
        *(
            record[key]
            for record in participants.values()
            for key in ("carrier_id", "mission_id", "mission_authority")
        ),
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
        "reconciliation": {
            "state_transfer": {
                "offered": sum(values["offered"] for values in contact_counters.values()),
                "fetched": sum(values["fetched"] for values in contact_counters.values()),
                "inserted": sum(values["inserted"] for values in contact_counters.values()),
                "duplicates": 0,
            },
            "direct_only": True,
            "event_activity": "all-zero",
            "control_activity": "all-zero",
            "blob_activity": "all-zero",
            "contact_stop_aggregation": "exact",
        },
        "identifiers_paths_ports_pids": "parsed-cross-bound-excluded",
        "_sensitive_values": sorted(sensitive),
        "_sensitive_pids": sorted(pids),
        "_sensitive_ports": sorted(ports),
    }


# The support module's raw-root and signed-source validation is generic apart
# from these two semantic callbacks and the constants configured above.
SUPPORT.validate_transcript = validate_transcript
SUPPORT.validate_terminal_stdout = validate_terminal_stdout


def validate_source(source: Path, raw_root: Path) -> dict[str, Any]:
    return SUPPORT.validate_source(source, raw_root)


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
            "id": run["run_id"],
            "argv_redacted": [
                "<raw-root>/binary/aster-live-state-subscription-acceptance",
                "<raw-root>",
            ],
            "exact_argv_sha256": sha256_bytes(
                canonical_json_bytes(run["run_argv"])
            ),
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
                "child_coordination_records": terminal[
                    "child_coordination_records"
                ],
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
            "participants": transcript["participants"],
            "processes": transcript["processes"],
            "actor_lifetimes": transcript["actor_lifetimes"],
            "maximum_concurrent_actors": transcript["maximum_concurrent_actors"],
            "graceful_shutdowns": transcript["graceful_shutdowns"],
            "forced_process_terminations": transcript[
                "forced_process_terminations"
            ],
            "distinct_carrier_ids": 2,
            "distinct_mission_ids": 2,
            "common_disjoint_mission_authority": True,
            "reciprocal_cross_peer_binding": "carrier-and-mission-verified",
            "runtime_ready_contact_stop_identity_binding": "verified",
            "connected_path": "positive-direct-only-zero-errors",
            "connected_reconciliation": terminal["reconciliation"],
            "state": {
                "publications": transcript["state_publications"],
                "network_insertions": transcript["network_state_insertions"],
                "durability": "all-durable",
                "payload_representation": "sha256-only",
                "concurrent_origins": 2,
                "deterministic_current_reduction": True,
                "causal_successor": "current-with-two-superseded-origins",
                "tombstone": "explicit-current-with-three-superseded-ancestors",
                "final_store_statistics": "exact",
            },
            "subscription": {
                "insertions": transcript["subscription_insertions"],
                "durable_replays": transcript["subscription_replays"],
                "deliveries": transcript["deliveries"],
                "acknowledgements": transcript["acknowledgements"],
                "idempotent_reacknowledgements": transcript[
                    "idempotent_reacknowledgements"
                ],
                "empty_polls": transcript["empty_polls"],
                "acknowledged_ancestors_suppressed": True,
                "superseded_pending_origin_retired": True,
                "token_binding_checks": transcript["token_binding_checks"],
                "token_representation": "sha256-only",
                "opaque_tokens_emitted": False,
                "retry_token_rotation": "distinct",
                "malformed_token_rejected": True,
                "wrong_subscription_token_rejected": True,
                "wrong_state_token_rejected": True,
                "retired_origin_token_rejected": True,
                "attempt_one_token_valid_after_retry": True,
                "attempt_two_token_idempotent_reack": True,
                "handoff_artifact_removed": True,
            },
            "forced_receiver_termination": {
                "mechanism": "parent-child-kill",
                "termination_signal": "sigkill",
                "distinct_process": True,
                "after_flushed_durable_poll": True,
                "graceful": False,
                "stop_record_expected": False,
                "stop_record_observed": False,
                "pretermination_acknowledged": False,
                "token_artifact_permissions": "owner-only",
            },
            "fresh_process_redelivery": {
                "same_state_identity": True,
                "delivery_attempt": 2,
                "acknowledged": True,
                "idempotent_reacknowledgement": True,
                "empty_poll_after_acknowledgement": True,
                "durable_subscription_replayed": True,
            },
            "selector_separation": {
                "network_interested_application_unsubscribed_retained": True,
                "network_uninterested_authorized_withheld": True,
                "application_subscription_does_not_mutate_network_interest": True,
            },
            "final_peerless_reopen": {
                "subscription_replayed": True,
                "explicit_current_tombstone": True,
                "acknowledged_delivery_set_empty": True,
                "network_selector_outcomes_retained": True,
            },
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
    return SUPPORT.receipt_forbidden_values(evidence, raw_root, source)


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


def main(arguments: list[str] | None = None) -> None:
    options = parse_args(arguments)
    try:
        raw_root = Path(os.path.abspath(os.fspath(options.raw_root)))
        source = Path(os.path.abspath(os.fspath(options.source)))
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
            SUPPORT.write_receipt(options.output, encoded)
        else:
            supplied = SUPPORT.read_supplied_receipt(Path(options.receipt))
            SUPPORT.validate_supplied_receipt(supplied, encoded)
    except ReceiptViolation as error:
        print(
            f"selected live State subscription receipt validation failed: {error}",
            file=sys.stderr,
        )
        raise SystemExit(1) from error


if __name__ == "__main__":
    main()
