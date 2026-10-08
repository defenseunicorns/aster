#!/usr/bin/env python3
# Copyright 2026 Defense Unicorns, Inc.
# SPDX-License-Identifier: Apache-2.0
"""Project or verify a selected Linux Event-custody receipt.

Participant mission bundles, identity keys, and redb stores are validated only
by descriptor-relative metadata.  Their contents are never opened or hashed.
Runtime identifiers, event identifiers, sockets, process identifiers, and host
paths are cross-bound while validating raw evidence and omitted from the
canonical receipt.
"""

from __future__ import annotations

import argparse
import hashlib
import io
import importlib.util
import ipaddress
import json
import os
from pathlib import Path
import re
import stat
import sys
import tarfile
from types import ModuleType
from typing import Any, Iterable


SCHEMA = "aster-selected-linux-event-custody-receipt/v1"
RAW_SCHEMA = "aster-selected-linux-event-custody-raw/v1"
TRANSCRIPT_SCHEMA = "aster-linux-event-custody-transcript/v1"
CLAIM = "linux-boottime-finite-ttl-priority-quota-route-only-store-and-forward-receive-only-zero-disclosure"
RAW_CLAIM = "selected-linux-arm64-event-custody-ttl-quota-receive-only-acceptance"
RECEIPT_NAME = "selected-linux-event-custody-receipt.json"
IMAGE = "rust@sha256:0e2bcaef56d041a486784e54104a81aebe0da44bd03019bd70bc0401e42e4a97"
PLATFORM = "linux/arm64"
EXAMPLE_NAME = "linux_event_custody_acceptance"
BINARY_NAME = "aster-linux-event-custody-acceptance"
PARTICIPANTS = ("origin", "relay", "receiver")
TRANSCRIPT_RECORDS = 29
RUN_TIMEOUT_SECONDS = 300
RUNTIME_PIDS = 128
RUNTIME_MEMORY = 1024 * 1024 * 1024
RUNTIME_CPUS = 1_000_000_000
RECEIPT_MAX_BYTES = 16 * 1024
RUN_MAX_BYTES = 256 * 1024
STDOUT_MAX_BYTES = 8 * 1024 * 1024
STDERR_MAX_BYTES = 64 * 1024
TRANSCRIPT_MAX_BYTES = 256 * 1024
INSPECT_MAX_BYTES = 1024 * 1024
FACTS_MAX_BYTES = 16 * 1024
BINARY_MAX_BYTES = 128 * 1024 * 1024
MISSION_MAX_BYTES = 1024 * 1024
STORE_MAX_BYTES = 1024 * 1024 * 1024
IDENTITY_BYTES = 32

PRODUCER_PATH = "crates/aster-node/examples/linux_event_custody_acceptance.rs"
RUNNER_PATH = "tools/run-selected-linux-event-custody.py"
CHECKER_PATH = "tools/check-selected-linux-event-custody-receipt.py"
TEST_PATH = "tools/test-selected-linux-event-custody-receipt.py"
ADMITTED_SOURCE_PATHS = tuple(
    sorted(
        {
            "Cargo.lock", "Cargo.toml", "mise.toml",
            "crates/aster-core/Cargo.toml", "crates/aster-core/src/custody.rs",
            "crates/aster-core/src/crypto/reference.rs", "crates/aster-core/src/lib.rs",
            "crates/aster-core/src/source_event.rs", "crates/aster-iroh/Cargo.toml",
            "crates/aster-iroh/src/lib.rs", "crates/aster-node/Cargo.toml",
            "crates/aster-node/src/application.rs", "crates/aster-node/src/frame.rs",
            "crates/aster-node/src/identity.rs", "crates/aster-node/src/lib.rs",
            "crates/aster-node/src/mission.rs", "crates/aster-node/src/runtime.rs",
            "crates/aster-redb-store/Cargo.toml", "crates/aster-redb-store/src/custody.rs",
            "crates/aster-redb-store/src/lib.rs", PRODUCER_PATH, RUNNER_PATH, CHECKER_PATH,
            TEST_PATH, "tools/run-selected-live-event.py", "tools/check-selected-live-event-receipt.py",
        }
    )
)
TOOL_PATHS = {
    "producer": PRODUCER_PATH, "runner": RUNNER_PATH, "checker": CHECKER_PATH,
    "test": TEST_PATH, "live_runner_helper": "tools/run-selected-live-event.py",
    "live_checker_helper": "tools/check-selected-live-event-receipt.py",
}
BUILD_COMMAND = ["cargo", "build", "--release", "--locked", "-p", "aster-node", "--example", EXAMPLE_NAME]
RUNTIME_SCRIPT = (
    "umask 077; printf 'LINUX_CUSTODY_RUNTIME\\tschema=aster-linux-event-custody-runtime/v1\\n'; "
    "printf 'LINUX_CUSTODY_RUNTIME\\tkernel_sysname='; uname -s; "
    "printf 'LINUX_CUSTODY_RUNTIME\\tkernel_release='; uname -r; "
    "printf 'LINUX_CUSTODY_RUNTIME\\tkernel_version='; uname -v; "
    "printf 'LINUX_CUSTODY_RUNTIME\\tkernel_machine='; uname -m; "
    "printf 'LINUX_CUSTODY_RUNTIME\\tboot_id='; tr -d '\\n' </proc/sys/kernel/random/boot_id; printf '\\n'; "
    "printf 'LINUX_CUSTODY_RUNTIME\\tuptime='; tr -d '\\n' </proc/uptime; printf '\\n'; "
    "printf 'LINUX_CUSTODY_RUNTIME\\tclocksource='; tr -d '\\n' </sys/devices/system/clocksource/clocksource0/current_clocksource; printf '\\n'; "
    "exec \"$1\" \"$2\""
)

EXPECTED_DIRECTORIES = {
    "", "binary", "participants",
    *(f"participants/{participant}" for participant in PARTICIPANTS),
    *(f"participants/{participant}/state" for participant in PARTICIPANTS),
}
PUBLIC_FILES = {
    "run.json": 0o600, "stdout.log": 0o600, "stderr.log": 0o600,
    "transcript.tsv": 0o600, "runtime-facts.tsv": 0o600,
    "container-inspect.json": 0o600, f"binary/{BINARY_NAME}": 0o700,
}
SECRET_FILES = {
    f"participants/{participant}/{relative}": 0o600
    for participant in PARTICIPANTS
    for relative in ("mission.bundle", "state/identity.key", "state/mesh.redb")
}
HEX32 = re.compile(r"[0-9a-f]{64}\Z")
CONTAINER_ID = re.compile(r"[0-9a-f]{64}\Z")
BOOT_ID = re.compile(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\Z")
SOCKET = re.compile(r"127\.0\.0\.1:([1-9][0-9]{0,4})\Z")
FIELD = re.compile(r"[a-z][a-z0-9_]*\Z")

RECORD_KEYS = {
    "META": ("schema", "claim", "platform", "custody_clock", "participants", "contacts"),
    "PARTICIPANT": ("participant", "access", "carrier", "mission", "authority", "provisioning"),
    "SELECTOR": ("participant", "mode", "seeded_while", "topic", "scope", "inspection"),
    "QUOTA": ("participant", "phase", "scope", "max_items", "max_bytes", "exact_scope"),
    "EVENT": ("label", "id", "publisher", "sequence", "priority", "ttl_ms", "payload_sha256"),
    "EXPIRY": ("event", "phase", "offered", "origin_retirements", "origin_active_events"),
    "CONTACT": ("phase", "initiator", "initiator_policy", "responder", "responder_policy", "offered", "relay_fetched", "routine_withheld"),
    "STORE3": ("phase", "participant", "inspection"),
    "STORE5": ("phase", "participant", "inspection", "content_events", "route_cached"),
    "REOPEN_MAINTENANCE": (
        "participant", "expired", "expiry_runtime_quota_items", "expiry_items_after",
        "expiry_retirements_after", "pressure_execution", "pressure_demand_items",
        "pressure_demand_bytes", "pressure_demand_priority", "pressure_retired",
        "pressure_items_after", "retirements_after", "quota_items_after",
        "retirement_fence_persisted",
    ),
    "CONTACT2": ("phase", "initiator", "initiator_policy", "responder", "responder_policy", "offered", "receiver_fetched", "origin_runtime_active"),
    "DELIVERY": ("order", "event", "priority", "poll_attempt"),
    "ABSENCE": ("already_expired", "relay_expired", "quota_pressure", "below_floor", "receiver_query_count", "receiver_poll_count"),
    "RECEIVE_ONLY": ("participants", "initiated_contacts", "event_data_offered", "state_offered", "record_offered", "blob_offered", "control_offered"),
    "STORE4": ("phase", "participant", "inspection", "route_only"),
    "STORE4P": ("phase", "participant", "inspection", "pending_deliveries"),
    "NAMESPACE_ZERO": ("participants", "legacy", "state", "record", "blob", "control", "exact"),
    "SOCKET_FENCE": ("origin", "relay", "receiver", "origin_socket_held_during_second_contact", "all_reacquired_after_stop"),
    "RESULT": ("status", "records", "bounded", "payload_representation", "secret_values_emitted", "physical_network_claimed", "global_convergence_claimed"),
}
EXPECTED_SEQUENCE = (
    "META", "PARTICIPANT", "PARTICIPANT", "PARTICIPANT", "SELECTOR", "SELECTOR",
    "QUOTA", "QUOTA", *("EVENT" for _ in range(6)), "EXPIRY", "CONTACT", "STORE3",
    "STORE5", "REOPEN_MAINTENANCE", "CONTACT2", "DELIVERY", "DELIVERY", "ABSENCE",
    "RECEIVE_ONLY", "STORE4", "STORE4P", "NAMESPACE_ZERO", "SOCKET_FENCE", "RESULT",
)
EVENT_SPECS = (
    ("already_expired", 1, "flash", "500", b"expired before first authenticated contact"),
    ("relay_expiring", 2, "flash", "20000", b"expires while retained by route-only relay"),
    ("live_flash", 3, "flash", "durable", b"live flash custody event"),
    ("live_immediate", 4, "immediate", "durable", b"live immediate custody event"),
    ("live_priority", 5, "priority", "durable", b"priority event retired by quota pressure"),
    ("routine", 6, "routine", "durable", b"routine event withheld below sender floor"),
)
CHILD_CONTACT_KEYS = (
    "authenticated_contacts", "failed_contact_attempts", "receipt_contacts",
    "receipt_contact_errors", "receipt_events", "receipt_event_markers",
    "receipt_route_cached", "receipt_data_offered", "receipt_data_fetched",
    "receipt_data_inserted", "receipt_data_remaining", "receipt_mutable_remaining",
    "receipt_controls", "receipt_blobs",
)
CHILD_INSPECTION_KEYS = (
    "store_events", "store_route_cached", "store_subscriptions",
    "store_pending_deliveries", "store_custody_items", "store_custody_bytes",
    "store_retirements", "store_quotas", "store_states", "store_records",
    "store_blobs", "store_controls",
)
CHILD_SCHEMAS = {
    "PHASE1_READY": ("participant", "mode", "quota_items"),
    "PHASE2_RELAY_READY": ("participant", "mode", "quota_items"),
    "PHASE2_RECEIVER_READY": ("participant", "mode", "quota_items", "subscription"),
    "PHASE1_DONE": CHILD_CONTACT_KEYS + CHILD_INSPECTION_KEYS + ("participant", "route_query_items"),
    "PHASE2_RELAY_DONE": CHILD_CONTACT_KEYS + CHILD_INSPECTION_KEYS + ("participant", "route_query_items"),
    "PHASE2_RECEIVER_DONE": CHILD_CONTACT_KEYS + CHILD_INSPECTION_KEYS + (
        "participant", "subscription", "query_items", "poll_deliveries", "first_id",
        "first_priority", "first_attempt", "second_id", "second_priority", "second_attempt",
    ),
}


def load_base() -> ModuleType:
    path = Path(__file__).with_name("check-selected-live-event-receipt.py")
    spec = importlib.util.spec_from_file_location("aster_live_event_checker", path)
    if spec is None or spec.loader is None:
        raise RuntimeError("live Event checker unavailable")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


BASE = load_base()
ReceiptViolation = BASE.ReceiptViolation
fail = BASE.fail
sha256_bytes = BASE.sha256_bytes
canonical_json_bytes = BASE.canonical_json_bytes


def parse_record(line: str, expected: str, index: int) -> dict[str, str]:
    kind = "STORE" if expected.startswith("STORE") else "CONTACT" if expected == "CONTACT2" else expected
    parts = line.split("\t")
    keys = RECORD_KEYS[expected]
    if len(parts) != len(keys) + 2 or parts[:2] != ["LINUX_CUSTODY", kind]:
        fail(f"transcript record {index} is out of order or has the wrong arity")
    result: dict[str, str] = {}
    for offset, key in enumerate(keys, 2):
        field = parts[offset]
        if not field.startswith(f"{key}="):
            fail(f"transcript record {index} fields are not canonical")
        value = field[len(key) + 1:]
        if not value or any(ord(char) < 0x20 or ord(char) > 0x7e for char in value):
            fail(f"transcript record {index} contains a noncanonical value")
        result[key] = value
    return result


def uint(value: str, label: str) -> int:
    if re.fullmatch(r"0|[1-9][0-9]{0,19}", value) is None:
        fail(f"{label} is not one canonical counter")
    return int(value)


def require_fields(record: dict[str, str], expected: dict[str, str], label: str) -> None:
    if any(record.get(key) != value for key, value in expected.items()):
        fail(f"{label} differs from the selected custody contract")


def validate_transcript(data: bytes) -> dict[str, Any]:
    if not data.endswith(b"\n") or b"\r" in data or b"\x00" in data:
        fail("transcript is not canonical LF-terminated text")
    try:
        text = data.decode("ascii")
    except UnicodeDecodeError:
        fail("transcript is not canonical ASCII")
    lines = text[:-1].split("\n")
    if len(lines) != TRANSCRIPT_RECORDS:
        fail("transcript has the wrong exact record count")
    records = [parse_record(line, expected, index) for index, (line, expected) in enumerate(zip(lines, EXPECTED_SEQUENCE))]
    require_fields(records[0], {"schema": TRANSCRIPT_SCHEMA, "claim": CLAIM, "platform": "linux", "custody_clock": "clock_boottime_suspend_inclusive", "participants": "3", "contacts": "2"}, "META")

    actors = records[1:4]
    expected_access = {"origin": "member", "relay": "route_only", "receiver": "member"}
    if [actor["participant"] for actor in actors] != list(PARTICIPANTS):
        fail("participant actor set or order differs")
    identifiers: set[str] = set()
    authorities: set[str] = set()
    for actor in actors:
        require_fields(actor, {"access": expected_access[actor["participant"]], "provisioning": "independent_reference_bundle"}, "PARTICIPANT")
        for field in ("carrier", "mission", "authority"):
            if HEX32.fullmatch(actor[field]) is None:
                fail(f"participant {field} is not a canonical identifier")
        if actor["carrier"] == actor["mission"]:
            fail("participant carrier and mission identities overlap")
        identifiers.update((actor["carrier"], actor["mission"]))
        authorities.add(actor["authority"])
    if len(identifiers) != 6 or len(authorities) != 1 or next(iter(authorities)) in identifiers:
        fail("participant identity and authority domains are not exact and disjoint")

    seeded = "events:0,route:0,custody:0,retirements:0,quotas:1,selectors:1,pending:0,state:0,record:0,blob:0,control:0"
    for record, participant, mode in zip(records[4:6], ("relay", "receiver"), ("carry", "consume")):
        require_fields(record, {"participant": participant, "mode": mode, "seeded_while": "stopped", "topic": "opaque.custody", "scope": "test/linux-event-custody", "inspection": seeded}, "SELECTOR")
    for record, phase, items in zip(records[6:8], ("origin_to_relay", "relay_to_receiver"), ("4", "2")):
        require_fields(record, {"participant": "relay", "phase": phase, "scope": "test/linux-event-custody", "max_items": items, "max_bytes": "1048576", "exact_scope": "true"}, "QUOTA")

    events = records[8:14]
    event_ids: dict[str, str] = {}
    publisher = actors[0]["mission"]
    for record, (label, sequence, priority, ttl, payload) in zip(events, EVENT_SPECS):
        require_fields(record, {"label": label, "publisher": publisher, "sequence": str(sequence), "priority": priority, "ttl_ms": ttl, "payload_sha256": hashlib.sha256(payload).hexdigest()}, f"EVENT {label}")
        if HEX32.fullmatch(record["id"]) is None or record["id"] in event_ids.values() or record["id"] in identifiers or record["id"] in authorities:
            fail("Event identifiers are not canonical and disjoint")
        event_ids[label] = record["id"]

    require_fields(records[14], {"event": event_ids["already_expired"], "phase": "before_first_contact", "offered": "false", "origin_retirements": "1", "origin_active_events": "5"}, "EXPIRY")
    require_fields(records[15], {"phase": "origin_to_relay", "initiator": "origin", "initiator_policy": "at_least_priority", "responder": "relay", "responder_policy": "receive_only", "offered": "4", "relay_fetched": "4", "routine_withheld": event_ids["routine"]}, "first CONTACT")
    require_fields(records[16], {"phase": "after_origin_stop", "participant": "origin", "inspection": "events:5,route:0,custody:5,retirements:1,quotas:1,selectors:0,pending:0,state:0,record:0,blob:0,control:0"}, "origin STORE")
    require_fields(records[17], {"phase": "after_first_contact", "participant": "relay", "inspection": "events:0,route:4,custody:4,retirements:0,quotas:2,selectors:1,pending:0,state:0,record:0,blob:0,control:0", "content_events": "0", "route_cached": "4"}, "relay phase-one STORE")
    require_fields(records[18], {
        "participant": "relay", "expired": event_ids["relay_expiring"],
        "expiry_runtime_quota_items": "4", "expiry_items_after": "3",
        "expiry_retirements_after": "1", "pressure_execution": "stopped_store",
        "pressure_demand_items": "2", "pressure_demand_bytes": "0",
        "pressure_demand_priority": "flash", "pressure_retired": event_ids["live_priority"],
        "pressure_items_after": "2", "retirements_after": "2", "quota_items_after": "2",
        "retirement_fence_persisted": "true",
    }, "REOPEN_MAINTENANCE")
    require_fields(records[19], {"phase": "relay_to_receiver", "initiator": "relay", "initiator_policy": "normal", "responder": "receiver", "responder_policy": "receive_only", "offered": "2", "receiver_fetched": "2", "origin_runtime_active": "false"}, "second CONTACT")
    for record, order, label, priority in zip(records[20:22], ("1", "2"), ("live_flash", "live_immediate"), ("flash", "immediate")):
        require_fields(record, {"order": order, "event": event_ids[label], "priority": priority, "poll_attempt": "1"}, "DELIVERY")
    require_fields(records[22], {"already_expired": event_ids["already_expired"], "relay_expired": event_ids["relay_expiring"], "quota_pressure": event_ids["live_priority"], "below_floor": event_ids["routine"], "receiver_query_count": "2", "receiver_poll_count": "2"}, "ABSENCE")
    require_fields(records[23], {"participants": "relay,receiver", "initiated_contacts": "0", "event_data_offered": "0", "state_offered": "0", "record_offered": "0", "blob_offered": "0", "control_offered": "0"}, "RECEIVE_ONLY")
    require_fields(records[24], {"phase": "final", "participant": "relay", "inspection": "events:0,route:2,custody:2,retirements:2,quotas:2,selectors:1,pending:0,state:0,record:0,blob:0,control:0", "route_only": "true"}, "relay final STORE")
    require_fields(records[25], {"phase": "final", "participant": "receiver", "inspection": "events:2,route:0,custody:2,retirements:0,quotas:1,selectors:1,pending:2,state:0,record:0,blob:0,control:0", "pending_deliveries": "2"}, "receiver final STORE")
    require_fields(records[26], {"participants": "origin,relay,receiver", "legacy": "0", "state": "0", "record": "0", "blob": "0", "control": "0", "exact": "true"}, "NAMESPACE_ZERO")
    sockets = [records[27][participant] for participant in PARTICIPANTS]
    ports = []
    for socket in sockets:
        match = SOCKET.fullmatch(socket)
        if match is None or int(match.group(1)) > 65535:
            fail("SOCKET_FENCE has a noncanonical loopback socket")
        ports.append(int(match.group(1)))
    if len(set(sockets)) != 3:
        fail("SOCKET_FENCE reuses a participant socket")
    require_fields(records[27], {"origin_socket_held_during_second_contact": "true", "all_reacquired_after_stop": "true"}, "SOCKET_FENCE")
    require_fields(records[28], {"status": "pass", "records": str(TRANSCRIPT_RECORDS), "bounded": "true", "payload_representation": "sha256_only", "secret_values_emitted": "false", "physical_network_claimed": "false", "global_convergence_claimed": "false"}, "RESULT")
    return {
        "records": TRANSCRIPT_RECORDS, "bytes": len(data), "sha256": sha256_bytes(data),
        "event_ids": list(event_ids.values()), "identity_values": sorted(identifiers | authorities),
        "sockets": sockets, "ports": ports,
        "actor_ids": {
            actor["participant"]: {key: actor[key] for key in ("carrier", "mission", "authority")}
            for actor in actors
        },
    }


def validate_runtime_facts(data: bytes) -> dict[str, str]:
    try:
        text = data.decode("ascii")
    except UnicodeDecodeError:
        fail("runtime facts are not canonical ASCII")
    if not text.endswith("\n") or "\r" in text or "\x00" in text:
        fail("runtime facts are not canonical LF text")
    keys = ("schema", "kernel_sysname", "kernel_release", "kernel_version", "kernel_machine", "boot_id", "uptime", "clocksource")
    lines = text[:-1].split("\n")
    if len(lines) != len(keys):
        fail("runtime facts have the wrong exact field count")
    result: dict[str, str] = {}
    for line, key in zip(lines, keys):
        if not line.startswith(f"{key}="):
            fail("runtime facts are out of order")
        value = line[len(key) + 1:]
        if not value or any(ord(char) < 0x20 or ord(char) > 0x7e for char in value):
            fail("runtime facts contain a noncanonical value")
        result[key] = value
    if result["schema"] != "aster-linux-event-custody-runtime/v1" or result["kernel_sysname"] != "Linux" or result["kernel_machine"] not in {"aarch64", "arm64"}:
        fail("runtime facts differ from pinned Linux arm64 execution")
    if BOOT_ID.fullmatch(result["boot_id"]) is None or result["boot_id"] == "00000000-0000-0000-0000-000000000000":
        fail("runtime boot identity is not one validated kernel UUID")
    if re.fullmatch(r"[0-9]+(?:\.[0-9]+)? [0-9]+(?:\.[0-9]+)?", result["uptime"]) is None:
        fail("runtime uptime is not the exact two-clock kernel sample")
    if not re.fullmatch(r"[A-Za-z0-9_.+-]{1,64}", result["clocksource"]):
        fail("runtime clock source is noncanonical")
    return result


def validate_stdout(data: bytes, transcript: bytes, runtime_facts: bytes, transcript_facts: dict[str, Any] | None = None) -> dict[str, Any]:
    try:
        text = data.decode("ascii")
    except UnicodeDecodeError:
        fail("captured stdout is not canonical ASCII")
    if not text.endswith("\n") or "\r" in text or "\x00" in text:
        fail("captured stdout is not canonical LF text")
    selected: list[bytes] = []
    runtime: list[bytes] = []
    counts = {"READY": 0, "CONTACT": 0, "STOP": 0, "CHILD": 0}
    child_kinds: list[str] = []
    sensitive: set[str] = set()
    for index, raw in enumerate(data.splitlines(keepends=True)):
        if not raw.endswith(b"\n"):
            fail("captured stdout contains an unterminated line")
        line = raw[:-1].decode("ascii")
        if line.startswith("LINUX_CUSTODY\t"):
            selected.append(raw)
            continue
        if line.startswith("LINUX_CUSTODY_RUNTIME\t"):
            parts = line.split("\t")
            if len(parts) != 2 or "=" not in parts[1]:
                fail("runtime-fact stdout record is malformed")
            runtime.append((parts[1] + "\n").encode("ascii"))
            continue
        if line.startswith("LINUX_CUSTODY_CHILD\t"):
            parts = line.split("\t")
            schema = CHILD_SCHEMAS.get(parts[1] if len(parts) > 1 else "")
            if schema is None or len(parts) != len(schema) + 2:
                fail("child coordination stdout record is malformed")
            fields = [field.split("=", 1) for field in parts[2:]]
            if [field[0] for field in fields] != list(schema) or any(len(field) != 2 or not field[1] for field in fields):
                fail("child coordination stdout fields are noncanonical")
            counts["CHILD"] += 1
            child_kinds.append(parts[1])
            for key, value in fields:
                if key in {"subscription", "first_id", "second_id"}:
                    sensitive.add(value)
            continue
        prefix = next((prefix for prefix in ("READY", "CONTACT", "STOP") if line.startswith(prefix + " ")), None)
        if prefix is None:
            fail(f"captured stdout line {index} has an unapproved record type")
        keys = {"READY": BASE.READY_KEYS, "CONTACT": BASE.CONTACT_KEYS, "STOP": BASE.STOP_KEYS}[prefix]
        record = BASE.parse_terminal_record(line, prefix, keys, f"stdout line {index}")
        counts[prefix] += 1
        for key in ("pid", "carrier_id", "mission_id", "mission_authority", "carrier_peer", "mission_peer", "state", "sockets"):
            if key in record:
                sensitive.add(record[key])
    if b"".join(selected) != transcript or b"".join(runtime) != runtime_facts:
        fail("stdout selected records differ from retained exact extractions")
    if counts != {"READY": 6, "CONTACT": 4, "STOP": 6, "CHILD": 6}:
        fail("stdout runtime/child record counts differ from six exact actor lifetimes")
    if set(child_kinds) != set(CHILD_SCHEMAS) or len(child_kinds) != len(set(child_kinds)):
        fail("stdout child coordination kind set differs")
    if transcript_facts is not None:
        allowed = set(transcript_facts["identity_values"])
        for value in sensitive:
            if HEX32.fullmatch(value) and value not in allowed and value not in transcript_facts["event_ids"]:
                # Subscription IDs are intentionally not participant identities.
                if value not in {part.split("=", 1)[-1] for line in text.splitlines() if line.startswith("LINUX_CUSTODY_CHILD\t") for part in line.split("\t") if part.startswith("subscription=")}:
                    fail("terminal participant identifier is not bound to transcript actors")
    return {"counts": counts, "sensitive": sensitive}


def validate_stderr(data: bytes, transcript_facts: dict[str, Any]) -> dict[str, Any]:
    del transcript_facts
    if data:
        fail("captured stderr is nonempty and therefore not a passing run")
    return {"contacts": 0, "sensitive": set()}


def validate_inventory(root_descriptor: int) -> dict[str, dict[str, os.stat_result]]:
    directories: dict[str, os.stat_result] = {}
    files: dict[str, os.stat_result] = {}
    identities: set[tuple[int, int]] = set()
    directory_flags = os.O_RDONLY | os.O_DIRECTORY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)

    def walk(descriptor: int, relative: str) -> None:
        metadata = os.fstat(descriptor)
        if not stat.S_ISDIR(metadata.st_mode) or metadata.st_uid != os.getuid() or stat.S_IMODE(metadata.st_mode) != 0o700:
            fail(f"raw directory {relative or '.'} is not owner-only")
        identity = (metadata.st_dev, metadata.st_ino)
        if identity in identities:
            fail("raw inventory aliases a directory")
        identities.add(identity)
        directories[relative] = metadata
        for name in sorted(os.listdir(descriptor)):
            if not name or name in {".", ".."} or "/" in name or "\x00" in name:
                fail("raw inventory has a noncanonical entry name")
            child = f"{relative}/{name}" if relative else name
            before = os.stat(name, dir_fd=descriptor, follow_symlinks=False)
            if stat.S_ISDIR(before.st_mode):
                if child not in EXPECTED_DIRECTORIES:
                    fail(f"raw inventory has unexpected directory {child}")
                opened = os.open(name, directory_flags, dir_fd=descriptor)
                try:
                    after = os.fstat(opened)
                    if (before.st_dev, before.st_ino) != (after.st_dev, after.st_ino):
                        fail("raw directory changed during open")
                    walk(opened, child)
                finally:
                    os.close(opened)
            elif stat.S_ISREG(before.st_mode) and not stat.S_ISLNK(before.st_mode):
                expected_mode = PUBLIC_FILES.get(child, SECRET_FILES.get(child))
                if expected_mode is None:
                    fail(f"raw inventory has unexpected file {child}")
                if before.st_uid != os.getuid() or before.st_nlink != 1 or stat.S_IMODE(before.st_mode) != expected_mode:
                    fail(f"raw file {child} has unsafe metadata")
                identity = (before.st_dev, before.st_ino)
                if identity in identities:
                    fail("raw inventory aliases a file")
                identities.add(identity)
                files[child] = before
            else:
                fail("raw inventory contains a non-plain entry")

    walk(root_descriptor, "")
    if set(directories) != EXPECTED_DIRECTORIES or set(files) != set(PUBLIC_FILES) | set(SECRET_FILES):
        fail("raw inventory is missing or has extra entries")
    for participant in PARTICIPANTS:
        mission = files[f"participants/{participant}/mission.bundle"]
        identity = files[f"participants/{participant}/state/identity.key"]
        store = files[f"participants/{participant}/state/mesh.redb"]
        if not 0 < mission.st_size <= MISSION_MAX_BYTES or identity.st_size != IDENTITY_BYTES or not 0 < store.st_size <= STORE_MAX_BYTES:
            fail("participant secret artifact metadata differs from bounds")
    return {"directories": directories, "files": files}


def same_inventory(first: dict[str, dict[str, os.stat_result]], second: dict[str, dict[str, os.stat_result]]) -> None:
    for kind in ("directories", "files"):
        if set(first[kind]) != set(second[kind]):
            fail("raw inventory changed during validation")
        for path in first[kind]:
            one, two = first[kind][path], second[kind][path]
            witness_one = (one.st_dev, one.st_ino, one.st_mode, one.st_nlink, one.st_uid, one.st_gid, one.st_size, one.st_mtime_ns, one.st_ctime_ns)
            witness_two = (two.st_dev, two.st_ino, two.st_mode, two.st_nlink, two.st_uid, two.st_gid, two.st_size, two.st_mtime_ns, two.st_ctime_ns)
            if witness_one != witness_two:
                fail(f"raw inventory entry changed: {path}")


def read_public(root_descriptor: int, relative: str, maximum: int, *, empty: bool = False) -> tuple[bytes, os.stat_result]:
    data, metadata = BASE.read_public_file(root_descriptor, relative, relative, maximum)
    if not empty and not data:
        fail(f"{relative} is unexpectedly empty")
    return data, metadata


def validate_artifact(value: Any, *, path: str, data: bytes, label: str) -> None:
    record = BASE.exact_object(value, ("path", "bytes", "sha256"), label)
    if record["path"] != path or record["bytes"] != len(data) or record["sha256"] != sha256_bytes(data):
        fail(f"{label} differs from retained bytes")


def validate_container(
    document: dict[str, Any], *, run: dict[str, Any], raw_root: Path
) -> dict[str, Any]:
    host = document.get("HostConfig")
    config = document.get("Config")
    mounts = document.get("Mounts")
    if not isinstance(host, dict) or not isinstance(config, dict) or not isinstance(mounts, list):
        fail("container inspection lacks exact configuration")
    runtime = BASE.exact_object(
        run["runtime"],
        ("container_id", "image_id", "exit_code", "timeout_seconds", "uid", "gid", "platform", "network", "read_only_root", "cap_drop", "no_new_privileges", "pids_limit", "memory_bytes", "memory_swap_bytes", "nano_cpus", "raw_mount"),
        "run.runtime",
    )
    container_id = runtime["container_id"]
    if not isinstance(container_id, str) or CONTAINER_ID.fullmatch(container_id) is None or document.get("Id") != container_id:
        fail("container identifier is not internally bound")
    image_id = runtime["image_id"]
    if not isinstance(image_id, str) or re.fullmatch(r"sha256:[0-9a-f]{64}", image_id) is None or document.get("Image") != image_id:
        fail("container image identifier is not internally bound")
    uid, gid = runtime["uid"], runtime["gid"]
    if type(uid) is not int or type(gid) is not int or uid <= 0 or gid <= 0:
        fail("runtime user is not a non-root numeric owner")
    expected_runtime = {
        "exit_code": 0, "timeout_seconds": RUN_TIMEOUT_SECONDS, "platform": PLATFORM,
        "network": "none", "read_only_root": True, "cap_drop": ["ALL"],
        "no_new_privileges": True, "pids_limit": RUNTIME_PIDS,
        "memory_bytes": RUNTIME_MEMORY, "memory_swap_bytes": RUNTIME_MEMORY,
        "nano_cpus": RUNTIME_CPUS,
        "raw_mount": {"destination": "/evidence", "read_write": True, "owner_only": True},
    }
    if any(runtime[key] != value for key, value in expected_runtime.items()):
        fail("declared runtime hardening differs")
    for key, value in {
        "NetworkMode": "none", "ReadonlyRootfs": True, "PidsLimit": RUNTIME_PIDS,
        "Memory": RUNTIME_MEMORY, "MemorySwap": RUNTIME_MEMORY, "NanoCpus": RUNTIME_CPUS,
        "CgroupnsMode": "private", "Privileged": False,
    }.items():
        if host.get(key) != value:
            fail(f"container hardening differs at {key}")
    if host.get("CapDrop") != ["ALL"] or host.get("CapAdd") is not None or host.get("SecurityOpt") not in (["no-new-privileges"], ["no-new-privileges:true"]):
        fail("container capabilities or no-new-privileges differ")
    for key, expected in {
        "Devices": [], "DeviceRequests": None, "DeviceCgroupRules": None,
        "PortBindings": {}, "PublishAllPorts": False, "AutoRemove": False,
        "RestartPolicy": {"Name": "no", "MaximumRetryCount": 0},
        "PidMode": "", "IpcMode": "private", "UTSMode": "",
    }.items():
        if host.get(key) != expected:
            fail(f"container isolation differs at {key}")
    if config.get("User") != f"{uid}:{gid}" or config.get("Image") != IMAGE:
        fail("container user or pinned image reference differs")
    tmpfs = host.get("Tmpfs")
    if not isinstance(tmpfs, dict) or set(tmpfs) != {"/tmp"} or not {"rw", "nosuid", "nodev", "noexec", "size=33554432", f"uid={uid}", f"gid={gid}"}.issubset(set(str(tmpfs["/tmp"]).split(","))):
        fail("container tmpfs differs from its bounded exact contract")
    state = document.get("State")
    if not isinstance(state, dict) or any(state.get(key) != value for key, value in {"Status": "exited", "Running": False, "Paused": False, "Restarting": False, "OOMKilled": False, "Dead": False, "Pid": 0, "ExitCode": 0, "Error": ""}.items()):
        fail("container terminal state is not exact clean exit")
    network = document.get("NetworkSettings")
    if not isinstance(network, dict) or network.get("Ports") not in ({}, None) or set((network.get("Networks") or {})) not in ({"none"}, set()):
        fail("container network/port inspection differs from none")
    expected_command = ["/bin/sh", "-eu", "-c", RUNTIME_SCRIPT, "sh", f"/execution/{BINARY_NAME}", "/evidence"]
    if (config.get("Entrypoint") or []) + (config.get("Cmd") or []) != expected_command:
        fail("container executable argv differs")
    if len(mounts) != 2:
        fail("container mounts do not isolate execution and raw evidence")
    by_destination = {mount.get("Destination"): mount for mount in mounts if isinstance(mount, dict)}
    evidence = by_destination.get("/evidence")
    execution = by_destination.get("/execution")
    if set(by_destination) != {"/evidence", "/execution"} or evidence is None or execution is None:
        fail("container mount destinations differ")
    if evidence.get("Type") != "bind" or evidence.get("Source") != os.fspath(raw_root) or evidence.get("RW") is not True:
        fail("raw evidence mount differs")
    if execution.get("Type") != "bind" or execution.get("RW") is not False:
        fail("execution mount is not separate and read-only")
    return {"container_id": container_id, "image_id": image_id, "uid": uid, "gid": gid, "execution_source": execution.get("Source")}


def validate_source_record(value: Any, authority: dict[str, Any]) -> None:
    stored = BASE.exact_object(value, ("commit", "tree", "signature", "admitted"), "run.source")
    if stored["commit"] != authority["commit"] or stored["tree"] != authority["tree"] or stored["signature"] != authority["signature"]:
        fail("run source authority differs from independently verified source")
    admitted = BASE.exact_array(stored["admitted"], "run.source.admitted", length=len(ADMITTED_SOURCE_PATHS))
    for index, path in enumerate(ADMITTED_SOURCE_PATHS):
        expected = authority["admitted"][path]
        if admitted[index] != {"path": path, "bytes": expected["bytes"], "sha256": expected["sha256"]}:
            fail("run admitted source manifest differs from signed source")


def reconstruct_archive(source: Path, authority: dict[str, Any]) -> dict[str, Any]:
    git = BASE.system_executable("git")
    trusted_options = BASE.reviewer_signature_options(git)
    archive = BASE.run_git(
        source,
        ["archive", "--format=tar", authority["commit"]],
        "signed tree archive reconstruction",
        128 * 1024 * 1024,
        git=git,
        trusted_options=trusted_options,
    )
    files = 0
    byte_count = 0
    try:
        with tarfile.open(fileobj=io.BytesIO(archive), mode="r:") as package:
            members = package.getmembers()
            if not members or len(members) > 20000:
                fail("signed tree archive inventory is outside bounds")
            for member in members:
                if member.isfile():
                    files += 1
                    byte_count += member.size
                elif not member.isdir():
                    fail("signed tree archive contains a non-plain entry")
    except (tarfile.TarError, OSError):
        fail("signed tree archive cannot be reconstructed safely")
    return {"archive_sha256": sha256_bytes(archive), "files": files, "bytes": byte_count}


def validate_image(value: Any) -> dict[str, Any]:
    image = BASE.exact_object(value, ("reference", "platform", "id", "architecture", "os", "repo_digests", "config"), "run.image")
    if image["reference"] != IMAGE or image["platform"] != PLATFORM or image["architecture"] != "arm64" or image["os"] != "linux":
        fail("run image differs from the pinned Linux arm64 image")
    if not isinstance(image["id"], str) or re.fullmatch(r"sha256:[0-9a-f]{64}", image["id"]) is None:
        fail("run image config identifier is malformed")
    if not isinstance(image["repo_digests"], list) or IMAGE not in image["repo_digests"]:
        # Docker normally expands rust to docker.io/library/rust.  The exact
        # pinned reference itself may not appear in RepoDigests, so bind its
        # digest component instead.
        digest = IMAGE.split("@", 1)[1]
        if not isinstance(image["repo_digests"], list) or not any(isinstance(item, str) and item.endswith(f"@{digest}") for item in image["repo_digests"]):
            fail("run image repository digest does not bind the requested pin")
    config = image["config"]
    if not isinstance(config, dict) or set(config) != {"User", "Env", "Entrypoint", "Cmd", "WorkingDir", "Labels"}:
        fail("run image configuration inventory differs")
    return image


def validate_commands(value: Any, *, run: dict[str, Any], raw_root: Path, source: Path, execution_source: str) -> dict[str, Any]:
    commands = BASE.exact_object(value, ("build", "runtime_create", "runtime_start"), "run.commands")
    build = BASE.exact_array(commands["build"], "run.commands.build")
    create = BASE.exact_array(commands["runtime_create"], "run.commands.runtime_create")
    start = BASE.exact_array(commands["runtime_start"], "run.commands.runtime_start")
    if not build or not create or not start or not all(isinstance(item, str) for item in build + create + start):
        fail("container command argv contains non-string values")
    docker = build[0]
    if (
        create[0] != docker
        or start[0] != docker
        or not os.path.isabs(docker)
        or os.path.basename(docker) != "docker"
    ):
        fail("container commands do not bind one trusted Docker invocation")
    BASE.trusted_executable(os.path.realpath(docker), "Docker")
    build_network = run["build_network"]
    if build_network not in {"none", "allowed-by-explicit-operator-flag"}:
        fail("build network classification differs")
    network = "none" if build_network == "none" else "default"
    try:
        source_mount = build[build.index("--mount") + 1]
        second_mount_index = build.index("--mount", build.index("--mount") + 1)
        build_mount = build[second_mount_index + 1]
    except (ValueError, IndexError):
        fail("build argv lacks exact source and build mounts")
    if "dst=/source" not in source_mount or "readonly" not in source_mount or "dst=/build" not in build_mount or "readonly" in build_mount:
        fail("build source/build isolation differs")
    source_host = source_mount.split("src=", 1)[-1].split(",dst=", 1)[0]
    build_host = build_mount.split("src=", 1)[-1].split(",dst=", 1)[0]
    if source_host in {os.fspath(raw_root), build_host} or build_host == os.fspath(raw_root):
        fail("build source, build state, and raw evidence are not isolated")
    for live in (source_host, build_host, execution_source):
        live_path = Path(live)
        if live_path == source or source in live_path.parents:
            fail("container workspace is equal to or nested under the live signed checkout")
    execution_path = Path(execution_source)
    if execution_path == raw_root or raw_root in execution_path.parents or execution_path in raw_root.parents:
        fail("execution source is not isolated outside raw evidence")

    uid, gid = run["runtime"]["uid"], run["runtime"]["gid"]
    expected_build = [
        docker, "run", "--rm", "--pull=never", "--platform", PLATFORM,
        f"--network={network}", "--read-only", "--user", f"{uid}:{gid}",
        "--cap-drop=ALL", "--security-opt=no-new-privileges", "--pids-limit=512",
        "--memory=4g", "--memory-swap=4g", "--cpus=4", "--tmpfs",
        f"/tmp:rw,nosuid,nodev,noexec,size=268435456,uid={uid},gid={gid}",
        "--mount", source_mount, "--mount", build_mount,
        "--env", "CARGO_HOME=/build/cargo-home", "--env", "CARGO_TARGET_DIR=/build/target",
        "--env", "RUSTUP_TOOLCHAIN=1.97.1-aarch64-unknown-linux-gnu",
        "--env", "CARGO_INCREMENTAL=0", "--workdir", "/source", IMAGE, *BUILD_COMMAND,
    ]
    if build != expected_build:
        fail("isolated build argv has missing, extra, or reordered options")

    runtime = run["runtime"]
    run_id = run["run_id"]
    name = f"aster-linux-custody-{run_id}"
    expected_tail = [IMAGE, "/bin/sh", "-eu", "-c", RUNTIME_SCRIPT, "sh", f"/execution/{BINARY_NAME}", "/evidence"]
    expected_create = [
        docker, "create", "--name", name, "--pull=never", "--platform", PLATFORM,
        "--network=none", "--read-only", "--user", f"{uid}:{gid}",
        "--cap-drop=ALL", "--security-opt=no-new-privileges", "--cgroupns=private",
        f"--pids-limit={RUNTIME_PIDS}", f"--memory={RUNTIME_MEMORY}",
        f"--memory-swap={RUNTIME_MEMORY}", "--cpus=1", "--tmpfs",
        f"/tmp:rw,nosuid,nodev,noexec,size=33554432,uid={uid},gid={gid}",
        "--mount", f"type=bind,src={raw_root},dst=/evidence",
        "--mount", f"type=bind,src={execution_source},dst=/execution,readonly",
        *expected_tail,
    ]
    if create != expected_create:
        fail("runtime create argv has missing, extra, or reordered hardening")
    if [docker, "start", "--attach", run["runtime"]["container_id"]] != start:
        fail("runtime start argv differs")
    if f"type=bind,src={raw_root},dst=/evidence" not in create:
        fail("runtime argv does not bind the exact raw root")
    if f"type=bind,src={execution_source},dst=/execution,readonly" not in create:
        fail("runtime argv does not bind the exact read-only execution root")
    if f"{runtime['uid']}:{runtime['gid']}" not in create:
        fail("runtime argv does not bind its inspected user")
    return {"docker": docker, "build_network": build_network}


def validate_run_document(
    document: dict[str, Any], *, authority: dict[str, Any], raw_root: Path,
    source: Path, artifacts: dict[str, bytes], inspect_document: dict[str, Any]
) -> dict[str, Any]:
    keys = ("schema", "claim", "run_id", "source", "materialized_source", "image", "commands", "runtime", "artifacts", "build_network", "limitations")
    run = BASE.exact_object(document, keys, "run metadata")
    if run["schema"] != RAW_SCHEMA or run["claim"] != RAW_CLAIM:
        fail("run metadata schema or claim differs")
    if not isinstance(run["run_id"], str) or re.fullmatch(r"[0-9a-f]{16}", run["run_id"]) is None:
        fail("run identifier is noncanonical")
    validate_source_record(run["source"], authority)
    materialized = BASE.exact_object(run["materialized_source"], ("commit", "tree", "archive_sha256", "files", "bytes", "read_only"), "run.materialized_source")
    if materialized["commit"] != authority["commit"] or materialized["tree"] != authority["tree"] or materialized["read_only"] is not True:
        fail("materialized build source does not bind the signed tree")
    if not isinstance(materialized["archive_sha256"], str) or HEX32.fullmatch(materialized["archive_sha256"]) is None or type(materialized["files"]) is not int or materialized["files"] <= 0 or type(materialized["bytes"]) is not int or materialized["bytes"] <= 0:
        fail("materialized build source inventory is malformed")
    if {key: materialized[key] for key in ("archive_sha256", "files", "bytes")} != reconstruct_archive(source, authority):
        fail("materialized build source differs from independently reconstructed signed tree")
    image = validate_image(run["image"])
    container = validate_container(inspect_document, run=run, raw_root=raw_root)
    if container["image_id"] != image["id"]:
        fail("runtime container does not bind the inspected pinned image")
    command_facts = validate_commands(run["commands"], run=run, raw_root=raw_root, source=source, execution_source=container["execution_source"])
    artifact_values = BASE.exact_object(run["artifacts"], ("binary", "stdout", "stderr", "transcript", "runtime_facts", "container_inspect"), "run.artifacts")
    mapping = {
        "binary": f"binary/{BINARY_NAME}", "stdout": "stdout.log", "stderr": "stderr.log",
        "transcript": "transcript.tsv", "runtime_facts": "runtime-facts.tsv",
        "container_inspect": "container-inspect.json",
    }
    for role, path in mapping.items():
        validate_artifact(artifact_values[role], path=path, data=artifacts[path], label=f"run.artifacts.{role}")
    if artifacts["stderr.log"] != b"":
        fail("captured runtime stderr is not exact empty")
    limitations = BASE.exact_array(run["limitations"], "run.limitations", length=3)
    expected_network_limitation = "build-network-not-part-of-runtime" if run["build_network"] == "allowed-by-explicit-operator-flag" else "offline-build-cache-dependent"
    if limitations != [
        "operator-attested-source-binary-execution-link-not-reproducible-build",
        expected_network_limitation,
        "one-container-one-kernel-one-implementation-observation",
    ]:
        fail("run limitations differ")
    return {"run_id": run["run_id"], "image": image, "container": container, "commands": command_facts, "artifacts": artifact_values}


def validate_source(source: Path, raw_root: Path) -> dict[str, Any]:
    original = BASE.ADMITTED_SOURCE_PATHS
    try:
        BASE.ADMITTED_SOURCE_PATHS = ADMITTED_SOURCE_PATHS
        return BASE.validate_source(source, raw_root)
    finally:
        BASE.ADMITTED_SOURCE_PATHS = original


def validate_raw_root(raw_root: Path, source: Path, authority: dict[str, Any]) -> dict[str, Any]:
    root_descriptor, root_metadata = BASE.open_raw_root(raw_root)
    try:
        inventory = validate_inventory(root_descriptor)
        limits = {
            "run.json": RUN_MAX_BYTES, "stdout.log": STDOUT_MAX_BYTES,
            "stderr.log": STDERR_MAX_BYTES, "transcript.tsv": TRANSCRIPT_MAX_BYTES,
            "runtime-facts.tsv": FACTS_MAX_BYTES, "container-inspect.json": INSPECT_MAX_BYTES,
            f"binary/{BINARY_NAME}": BINARY_MAX_BYTES,
        }
        artifacts: dict[str, bytes] = {}
        for path, maximum in limits.items():
            artifacts[path] = read_public(root_descriptor, path, maximum, empty=path in {"stderr.log"})[0]
        document = BASE.load_canonical_json(artifacts["run.json"], "run metadata", RUN_MAX_BYTES)
        inspect_document = BASE.load_canonical_json(artifacts["container-inspect.json"], "container inspection", INSPECT_MAX_BYTES)
        transcript = validate_transcript(artifacts["transcript.tsv"])
        facts = validate_runtime_facts(artifacts["runtime-facts.tsv"])
        extracted = b"".join(line for line in artifacts["stdout.log"].splitlines(keepends=True) if line.startswith(b"LINUX_CUSTODY\t"))
        if extracted != artifacts["transcript.tsv"]:
            fail("transcript is not the exact ordered extraction from stdout")
        terminal_stdout = validate_stdout(artifacts["stdout.log"], artifacts["transcript.tsv"], artifacts["runtime-facts.tsv"], transcript)
        validate_stderr(artifacts["stderr.log"], transcript)
        run = validate_run_document(document, authority=authority, raw_root=raw_root, source=source, artifacts=artifacts, inspect_document=inspect_document)
        terminal = validate_inventory(root_descriptor)
        same_inventory(inventory, terminal)
        for path, maximum in limits.items():
            final_data, _metadata = read_public(root_descriptor, path, maximum, empty=path == "stderr.log")
            if final_data != artifacts[path]:
                fail(f"public artifact changed after semantic validation: {path}")
        final_root = os.fstat(root_descriptor)
        if (final_root.st_dev, final_root.st_ino) != (root_metadata.st_dev, root_metadata.st_ino):
            fail("raw root identity changed during validation")
        try:
            final_path = os.lstat(raw_root)
        except OSError:
            fail("raw root path vanished during terminal validation")
        if (final_path.st_dev, final_path.st_ino) != (final_root.st_dev, final_root.st_ino):
            fail("raw root path changed identity during validation")
        return {"run": run, "transcript": transcript, "facts": facts, "terminal": terminal_stdout, "retention": {"directories": len(EXPECTED_DIRECTORIES), "files": len(PUBLIC_FILES) + len(SECRET_FILES), "participants": 3, "mission_artifacts": 3, "identity_artifacts": 3, "store_artifacts": 3, "secret_contents": "metadata-only-not-opened-read-or-hashed"}}
    finally:
        os.close(root_descriptor)


def admitted_manifest(authority: dict[str, Any]) -> bytes:
    return canonical_json_bytes([
        {"path": path, **authority["admitted"][path]} for path in ADMITTED_SOURCE_PATHS
    ])


def build_receipt(authority: dict[str, Any], evidence: dict[str, Any]) -> dict[str, Any]:
    run, transcript, facts = evidence["run"], evidence["transcript"], evidence["facts"]
    tools = {
        role: {
            "bytes": authority["admitted"][path]["bytes"],
            "sha256": authority["admitted"][path]["sha256"],
        }
        for role, path in TOOL_PATHS.items()
    }
    return {
        "schema": SCHEMA,
        "status": "pass",
        "claim": CLAIM,
        "source": {
            "signed_clean_checkout": True,
            "signature_status": "good",
            "commit": authority["commit"],
            "tree": authority["tree"],
            "signature": authority["signature"],
            "admitted_files": len(ADMITTED_SOURCE_PATHS),
            "admitted_manifest_sha256": sha256_bytes(admitted_manifest(authority)),
        },
        "image": {
            "reference": IMAGE,
            "platform": PLATFORM,
            "architecture": "arm64",
            "os": "linux",
        },
        "build": {
            "profile": "release",
            "package": "aster-node",
            "example": EXAMPLE_NAME,
            "locked": True,
            "network": run["commands"]["build_network"],
            "source_mount": "immutable-materialized-signed-tree-read-only",
            "build_mount": "separate-temporary-owner-only",
            "raw_evidence_available": False,
            "executable": {
                "bytes": run["artifacts"]["binary"]["bytes"],
                "sha256": run["artifacts"]["binary"]["sha256"],
            },
        },
        "runtime": {
            "exit_code": 0,
            "timeout_seconds": RUN_TIMEOUT_SECONDS,
            "kernel": {
                "sysname": facts["kernel_sysname"],
                "release": facts["kernel_release"],
                "version": facts["kernel_version"],
                "machine": facts["kernel_machine"],
                "clocksource": facts["clocksource"],
                "custody_clock": "clock_boottime_suspend_inclusive",
            },
            "hardening": {
                "network": "none", "read_only_root": True, "non_root": True,
                "capabilities": "all-dropped", "no_new_privileges": True,
                "private_cgroup_namespace": True, "pids_limit": RUNTIME_PIDS,
                "memory_bytes": RUNTIME_MEMORY, "memory_swap_bytes": RUNTIME_MEMORY,
                "nano_cpus": RUNTIME_CPUS, "tmpfs": "bounded-owner-only-noexec",
            },
            "execution_mount": "separate-read-only-executable-copy",
            "raw_mount": "owner-only-read-write-evidence-only",
            "exact_create_argv_sha256": sha256_bytes(canonical_json_bytes(run["commands"])),
            "stdout": {
                "bytes": run["artifacts"]["stdout"]["bytes"],
                "sha256": run["artifacts"]["stdout"]["sha256"],
            },
            "stderr": {
                "bytes": 0, "sha256": run["artifacts"]["stderr"]["sha256"],
                "classification": "exact-empty",
            },
            "transcript": {
                "records": transcript["records"], "bytes": transcript["bytes"],
                "sha256": transcript["sha256"],
                "identifiers_pids_ports_paths": "validated-cross-bound-excluded",
                "payloads": "sha256-only",
            },
        },
        "acceptance": {
            "participants": 3,
            "actor_set": ["origin", "relay", "receiver"],
            "authenticated_contacts": 2,
            "finite_ttl": {
                "already_expired_before_first_contact": 1,
                "expired_on_relay_reopen": 1,
                "clock": "Linux CLOCK_BOOTTIME suspend-inclusive",
                "retirement_fence_persisted": True,
            },
            "priority_and_quota": {
                "initial_exact_scope_items": 4, "final_exact_scope_items": 2,
                "exact_scope_bytes": 1024 * 1024,
                "priority_pressure_retirements": 1,
                "below_floor_withheld": 1,
                "final_relay_route_items": 2,
            },
            "store_and_forward": {
                "route_only_relay_content_events": 0,
                "origin_runtime_active_during_second_contact": False,
                "receiver_events": 2,
                "deliveries": 2,
                "delivery_priorities": ["flash", "immediate"],
            },
            "receive_only": {
                "actors": ["relay", "receiver"], "initiated_contacts": 0,
                "event_data_offered": 0, "state_offered": 0, "record_offered": 0,
                "blob_offered": 0, "control_offered": 0,
            },
            "namespace_zero": ["legacy", "state", "record", "blob", "control"],
            "bounded": True,
        },
        "retention": evidence["retention"],
        "tools": tools,
        "limitations": [
            "operator-attested-source-binary-execution-link-not-reproducible-build",
            "one-container-one-kernel-one-implementation-observation",
            "loopback-direct-contacts-not-physical-network-evidence",
            "participant-secret-artifacts-validated-by-metadata-only",
            "no-global-convergence-or-production-authorization-claim",
        ],
    }


def sensitive_values(evidence: dict[str, Any], raw_root: Path, source: Path) -> set[str]:
    transcript, run = evidence["transcript"], evidence["run"]
    values = set(transcript["event_ids"] + transcript["identity_values"] + transcript["sockets"])
    values.update(
        (
            run["run_id"],
            run["container"]["container_id"],
            run["container"]["execution_source"],
            evidence["facts"]["boot_id"],
            os.fspath(raw_root),
            os.fspath(source),
        )
    )
    values.update(evidence.get("terminal", {}).get("sensitive", set()))
    # Numeric PIDs and bare port numbers are not meaningful as unkeyed JSON
    # substrings (PID 1 would match nearly every receipt counter). Their field
    # names and full loopback sockets are rejected separately by render_receipt.
    return {
        value
        for value in values
        if isinstance(value, str) and len(value.encode("utf-8")) >= 8
    }


def render_receipt(document: dict[str, Any], forbidden_values: Iterable[str] = ()) -> bytes:
    encoded = canonical_json_bytes(document)
    if len(encoded) > RECEIPT_MAX_BYTES:
        fail("canonical receipt exceeds its 16 KiB bound")
    for token in (b'"id"', b'"pid"', b'"port"', b'"path"', b"127.0.0.1:", b"/private/", b"/Users/"):
        if token in encoded:
            fail("canonical receipt contains a forbidden identifier, PID, port, or path field")
    for value in forbidden_values:
        try:
            raw = value.encode("ascii")
        except UnicodeEncodeError:
            continue
        if raw and raw in encoded:
            fail("canonical receipt contains a validated raw identifier, socket, or path")
    return encoded


def project(source: Path, raw_root: Path) -> bytes:
    authority = validate_source(source, raw_root)
    evidence = validate_raw_root(raw_root, source, authority)
    terminal = validate_source(source, raw_root)
    if terminal != authority:
        fail("signed source authority changed during evidence validation")
    return render_receipt(build_receipt(authority, evidence), sensitive_values(evidence, raw_root, source))


def parse_args(arguments: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("receipt", nargs="?", default="-", help="receipt to validate, or '-' to project")
    parser.add_argument("--raw-root", required=True, type=Path)
    parser.add_argument("--source", required=True, type=Path)
    parser.add_argument("--output", type=Path)
    options = parser.parse_args(arguments)
    if options.receipt != "-" and options.output is not None:
        parser.error("--output cannot accompany an existing receipt")
    return options


def main(arguments: list[str] | None = None) -> None:
    options = parse_args(arguments)
    try:
        source = Path(os.path.abspath(os.fspath(options.source)))
        raw_root = Path(os.path.abspath(os.fspath(options.raw_root)))
        encoded = project(source, raw_root)
        if options.receipt == "-":
            if options.output is None:
                sys.stdout.buffer.write(encoded)
            else:
                original = BASE.RECEIPT_NAME
                try:
                    BASE.RECEIPT_NAME = RECEIPT_NAME
                    BASE.write_receipt(options.output, encoded)
                finally:
                    BASE.RECEIPT_NAME = original
        else:
            supplied = BASE.read_supplied_receipt(Path(options.receipt))
            BASE.validate_supplied_receipt(supplied, encoded)
    except (ReceiptViolation, OSError, ValueError, UnicodeError, TypeError, KeyError, AttributeError, json.JSONDecodeError) as error:
        print(f"selected Linux Event custody receipt validation failed: {error}", file=sys.stderr)
        raise SystemExit(1) from error


if __name__ == "__main__":
    main()
