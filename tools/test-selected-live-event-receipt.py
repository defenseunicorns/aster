#!/usr/bin/env python3
# Copyright 2026 Defense Unicorns, Inc.
# SPDX-License-Identifier: Apache-2.0
"""Adversarial tests for the retained selected live Event receipt projector."""

from __future__ import annotations

import hashlib
import importlib.util
import json
import os
from pathlib import Path
import stat
import subprocess
import tempfile
import unittest
from unittest import mock


TEST_TEMP_PARENT = os.path.realpath(tempfile.gettempdir())


CHECKER_PATH = Path(__file__).with_name("check-selected-live-event-receipt.py")
CHECKER_SPEC = importlib.util.spec_from_file_location(
    "selected_live_event_receipt", CHECKER_PATH
)
if CHECKER_SPEC is None or CHECKER_SPEC.loader is None:
    raise RuntimeError(f"cannot load {CHECKER_PATH}")
CHECKER = importlib.util.module_from_spec(CHECKER_SPEC)
CHECKER_SPEC.loader.exec_module(CHECKER)

RUNNER_PATH = Path(__file__).with_name("run-selected-live-event.py")
RUNNER_SPEC = importlib.util.spec_from_file_location(
    "selected_live_event_runner", RUNNER_PATH
)
if RUNNER_SPEC is None or RUNNER_SPEC.loader is None:
    raise RuntimeError(f"cannot load {RUNNER_PATH}")
RUNNER = importlib.util.module_from_spec(RUNNER_SPEC)
RUNNER_SPEC.loader.exec_module(RUNNER)

ORACLE_RECEIPT_SCHEMA = "aster-selected-live-event-receipt/v2"
ORACLE_RAW_SCHEMA = "aster-selected-live-event-raw/v2"
ORACLE_TRANSCRIPT_SCHEMA = "aster-selected-live-event-transcript/v2"
ORACLE_CLAIM = (
    "selected-live-event-one-host-direct-iroh-priority-withheld-authenticated-gap-"
    "forced-receiver-process-termination-durable-redelivery-gap-closure-acceptance"
)
ORACLE_TRANSCRIPT_RECORDS = 79
ORACLE_BUILD_ARGV = (
    "cargo",
    "build",
    "--release",
    "--locked",
    "-p",
    "aster-node",
    "--example",
    "live_event_acceptance",
)
ORACLE_ADMITTED_PATHS = tuple(
    sorted(
        (
            "Cargo.lock",
            "Cargo.toml",
            "mise.toml",
            "crates/aster-core/Cargo.toml",
            "crates/aster-core/src/custody.rs",
            "crates/aster-core/src/crypto/reference.rs",
            "crates/aster-core/src/lib.rs",
            "crates/aster-core/src/source_event.rs",
            "crates/aster-node/Cargo.toml",
            "crates/aster-node/src/publication_journal.rs",
            "tools/historical/check-selected-live-event-receipt.py",
            "tools/historical/check-selected-linux-event-custody-receipt.py",

            "crates/aster-node/examples/live_event_acceptance.rs",
            "crates/aster-node/src/application.rs",
            "crates/aster-node/src/frame.rs",
            "crates/aster-node/src/identity.rs",
            "crates/aster-node/src/lib.rs",
            "crates/aster-node/src/mission.rs",
            "crates/aster-node/src/runtime.rs",
            "crates/aster-redb-store/Cargo.toml",
            "crates/aster-redb-store/src/custody.rs",
            "crates/aster-redb-store/src/lib.rs",
            "tools/check-selected-live-event-receipt.py",
            "tools/run-selected-live-event.py",
            "tools/test-selected-live-event-receipt.py",
        )
    )
)
ORACLE_PAYLOAD_HASHES = {
    "first": hashlib.sha256(b"priority event one").hexdigest(),
    "second": hashlib.sha256(b"routine event two").hexdigest(),
    "third": hashlib.sha256(b"flash event three").hexdigest(),
    "beta": hashlib.sha256(
        b"authorized but initially unsubscribed beta event"
    ).hexdigest(),
    "changed_first": hashlib.sha256(b"changed event one").hexdigest(),
}
ORACLE_LIMITATIONS = (
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
)
ORACLE_NONCLAIMS = (
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
)

RUN_KEYS = (
    "schema",
    "claim",
    "participants",
    "actor_lifetimes",
    "maximum_concurrent_actors",
    "topic",
    "beta_topic",
    "scope",
    "stream_events",
    "authorized_unsubscribed_events",
    "publication_model",
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
HANDLE_KEYS = ("phase", "participant", "event_identity", "event_authority")
EVENT_KEYS = (
    "phase",
    "participant",
    "stream",
    "id",
    "publisher",
    "publisher_counter",
    "event_sequence",
    "priority",
    "ttl",
    "acceptance_marker",
    "inserted",
    "payload_sha256",
)
EVENT_RETRY_KEYS = (
    "phase",
    "participant",
    "id",
    "publisher",
    "publisher_counter",
    "event_sequence",
    "inserted",
    "exact_match",
)
OPERATION_CONFLICT_KEYS = (
    "phase",
    "participant",
    "original_id",
    "original_payload_sha256",
    "changed_payload_sha256",
    "error_kind",
    "operation",
    "sanitized",
    "publication_preserved",
)
QUERY_KEYS = (
    "phase",
    "participant",
    "stream",
    "items",
    "scanned_through",
    "has_more",
    "limit",
)
STATUS_KEYS = (
    "phase",
    "participant",
    "sync",
    "authenticated_contacts",
    "failed_contact_attempts",
    "peers",
    "peer",
    "peer_contacts",
    "peer_authorization",
    "peer_last_contact",
)
CHILD_STATUS_KEYS = (
    "phase",
    "participant",
    "observation",
    "sync",
    "authenticated_contacts",
    "failed_contact_attempts",
    "peers",
    "peer",
    "peer_contacts",
    "peer_authorization",
    "peer_last_contact",
)
SUBSCRIPTION_KEYS = (
    "phase",
    "participant",
    "stream",
    "id",
    "inserted",
    "durable",
    "include_descendant_scopes",
)
GAP_KEYS = (
    "phase",
    "participant",
    "stream",
    "disposition",
    "start_sequence",
    "end_sequence",
    "scanned_through_sequence",
    "has_more",
    "authenticated",
)
DELIVERY_KEYS = (
    "phase",
    "participant",
    "stream",
    "id",
    "event_sequence",
    "priority",
    "attempt",
    "payload_sha256",
)
ACK_KEYS = ("phase", "participant", "id", "disposition")
EMPTY_POLL_KEYS = (
    "phase",
    "participant",
    "observation",
    "deliveries",
    "has_more",
    "delivery_limit",
    "scan_limit",
)
PROCESS_TERMINATION_KEYS = (
    "phase",
    "participant",
    "mechanism",
    "after_flushed_poll",
    "graceful",
    "stop_record_expected",
    "acknowledged",
)
UNSUBSCRIBE_KEYS = (
    "phase",
    "participant",
    "stream",
    "subscription_id",
    "disposition",
)
SHUTDOWN_COUNTER_KEYS = (
    "contacts",
    "contact_errors",
    "direct_contacts",
    "relay_contacts",
    "unknown_path_contacts",
    "carrier_path_transitions",
    "carrier_path_transition_saturations",
    "items",
    "acceptance_markers",
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
SHUTDOWN_KEYS = ("phase", "participant", *SHUTDOWN_COUNTER_KEYS)
CLOSED_HANDLE_KEYS = ("phase", "participant", "error_kind", "operation")
BIND_KEYS = ("participant", "status")
RESULT_KEYS = (
    "status",
    "records",
    "phases",
    "actor_lifetimes",
    "maximum_concurrent_actors",
    "graceful_shutdowns",
    "forced_process_terminations",
    "retained_handles",
    "closed_handles",
    "bind_reacquisitions",
    "secret_values_emitted",
    "payload_representation",
    "physical_network_claimed",
    "global_convergence_claimed",
)

ORACLE_SEQUENCE: tuple[tuple[str, tuple[str, ...]], ...] = (
    ("RUN", RUN_KEYS),
    ("PARTICIPANT", PARTICIPANT_KEYS),
    ("PARTICIPANT", PARTICIPANT_KEYS),
    ("PEER_BINDING", PEER_BINDING_KEYS),
    ("PEER_BINDING", PEER_BINDING_KEYS),
    ("PHASE", PHASE_KEYS),
    ("HANDLE", HANDLE_KEYS),
    ("EVENT", EVENT_KEYS),
    ("EVENT_RETRY", EVENT_RETRY_KEYS),
    ("OPERATION_CONFLICT", OPERATION_CONFLICT_KEYS),
    ("EVENT", EVENT_KEYS),
    ("EVENT", EVENT_KEYS),
    ("EVENT", EVENT_KEYS),
    ("QUERY", QUERY_KEYS),
    ("QUERY", QUERY_KEYS),
    ("STATUS", STATUS_KEYS),
    ("SHUTDOWN", SHUTDOWN_KEYS),
    ("CLOSED_HANDLE", CLOSED_HANDLE_KEYS),
    ("PHASE", PHASE_KEYS),
    ("HANDLE", HANDLE_KEYS),
    ("HANDLE", HANDLE_KEYS),
    ("SUBSCRIPTION", SUBSCRIPTION_KEYS),
    ("STATUS", CHILD_STATUS_KEYS),
    ("STATUS", STATUS_KEYS),
    ("GAP", GAP_KEYS),
    ("DELIVERY", DELIVERY_KEYS),
    ("DELIVERY", DELIVERY_KEYS),
    ("PROCESS_TERMINATION", PROCESS_TERMINATION_KEYS),
    ("SHUTDOWN", SHUTDOWN_KEYS),
    ("CLOSED_HANDLE", CLOSED_HANDLE_KEYS),
    ("PHASE", PHASE_KEYS),
    ("HANDLE", HANDLE_KEYS),
    ("SUBSCRIPTION", SUBSCRIPTION_KEYS),
    ("STATUS", CHILD_STATUS_KEYS),
    ("GAP", GAP_KEYS),
    ("DELIVERY", DELIVERY_KEYS),
    ("DELIVERY", DELIVERY_KEYS),
    ("ACKNOWLEDGEMENT", ACK_KEYS),
    ("REACKNOWLEDGEMENT", ACK_KEYS),
    ("ACKNOWLEDGEMENT", ACK_KEYS),
    ("REACKNOWLEDGEMENT", ACK_KEYS),
    ("EMPTY_POLL", EMPTY_POLL_KEYS),
    ("SHUTDOWN", SHUTDOWN_KEYS),
    ("CLOSED_HANDLE", CLOSED_HANDLE_KEYS),
    ("PHASE", PHASE_KEYS),
    ("HANDLE", HANDLE_KEYS),
    ("HANDLE", HANDLE_KEYS),
    ("SUBSCRIPTION", SUBSCRIPTION_KEYS),
    ("EMPTY_POLL", EMPTY_POLL_KEYS),
    ("STATUS", STATUS_KEYS),
    ("STATUS", STATUS_KEYS),
    ("GAP", GAP_KEYS),
    ("DELIVERY", DELIVERY_KEYS),
    ("ACKNOWLEDGEMENT", ACK_KEYS),
    ("REACKNOWLEDGEMENT", ACK_KEYS),
    ("EMPTY_POLL", EMPTY_POLL_KEYS),
    ("QUERY", QUERY_KEYS),
    ("QUERY", QUERY_KEYS),
    ("SUBSCRIPTION", SUBSCRIPTION_KEYS),
    ("STATUS", STATUS_KEYS),
    ("UNSUBSCRIBE", UNSUBSCRIBE_KEYS),
    ("REUNSUBSCRIBE", UNSUBSCRIBE_KEYS),
    ("SHUTDOWN", SHUTDOWN_KEYS),
    ("SHUTDOWN", SHUTDOWN_KEYS),
    ("CLOSED_HANDLE", CLOSED_HANDLE_KEYS),
    ("CLOSED_HANDLE", CLOSED_HANDLE_KEYS),
    ("PHASE", PHASE_KEYS),
    ("HANDLE", HANDLE_KEYS),
    ("SUBSCRIPTION", SUBSCRIPTION_KEYS),
    ("STATUS", STATUS_KEYS),
    ("GAP", GAP_KEYS),
    ("EMPTY_POLL", EMPTY_POLL_KEYS),
    ("QUERY", QUERY_KEYS),
    ("QUERY", QUERY_KEYS),
    ("SHUTDOWN", SHUTDOWN_KEYS),
    ("CLOSED_HANDLE", CLOSED_HANDLE_KEYS),
    ("BIND_REACQUIRED", BIND_KEYS),
    ("BIND_REACQUIRED", BIND_KEYS),
    ("RESULT", RESULT_KEYS),
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
AWAITING_CHILD_KEYS = (
    "participant",
    "identity",
    "subscription_id",
    "subscription_inserted",
    "sync",
    "authenticated_contacts",
    "failed_contact_attempts",
    "peers",
)
ATTEMPT1_CHILD_KEYS = (
    "participant",
    "subscription_id",
    "sync",
    "authenticated_contacts",
    "failed_contact_attempts",
    "peer",
    "peer_contacts",
    "peer_authorization",
    "peer_last_contact",
    "gap_start",
    "gap_end",
    "gap_scanned_through",
    "gap_has_more",
    "first_id",
    "first_sequence",
    "first_priority",
    "first_attempt",
    "first_payload_sha256",
    "third_id",
    "third_sequence",
    "third_priority",
    "third_attempt",
    "third_payload_sha256",
    "acknowledged",
)
ATTEMPT2_PREFIX_KEYS = (
    "participant",
    "publisher",
    "subscription_id",
    "subscription_inserted",
    "sync",
    "authenticated_contacts",
    "failed_contact_attempts",
    "peers",
    "gap_start",
    "gap_end",
    "gap_scanned_through",
    "gap_has_more",
    "first_id",
    "first_sequence",
    "first_priority",
    "first_attempt",
    "first_payload_sha256",
    "first_ack",
    "first_reack",
    "third_id",
    "third_sequence",
    "third_priority",
    "third_attempt",
    "third_payload_sha256",
    "third_ack",
    "third_reack",
    "empty_deliveries",
    "empty_has_more",
)
ATTEMPT2_CHILD_KEYS = (
    *ATTEMPT2_PREFIX_KEYS,
    *(f"shutdown_{key}" for key in SHUTDOWN_COUNTER_KEYS),
    "closed_kind",
    "closed_operation",
)


def identifier(label: str) -> str:
    return hashlib.sha256(label.encode("ascii")).hexdigest()


def tsv(record_type: str, keys: tuple[str, ...], values: dict[str, str]) -> str:
    if set(values) != set(keys):
        raise AssertionError(
            f"fixture {record_type} keys differ: "
            f"missing={set(keys) - set(values)!r} extra={set(values) - set(keys)!r}"
        )
    return "\t".join(
        ["LIVE_EVENT", record_type, *(f"{key}={values[key]}" for key in keys)]
    )


def terminal(prefix: str, keys: tuple[str, ...], values: dict[str, str]) -> str:
    if set(values) != set(keys):
        raise AssertionError(
            f"fixture {prefix} keys differ: "
            f"missing={set(keys) - set(values)!r} extra={set(values) - set(keys)!r}"
        )
    return " ".join([prefix, *(f"{key}={values[key]}" for key in keys)])


def child_tsv(kind: str, keys: tuple[str, ...], values: dict[str, str]) -> str:
    if set(values) != set(keys):
        raise AssertionError(
            f"fixture LIVE_EVENT_CHILD {kind} keys differ: "
            f"missing={set(keys) - set(values)!r} extra={set(values) - set(keys)!r}"
        )
    return "\t".join(
        ["LIVE_EVENT_CHILD", kind, *(f"{key}={values[key]}" for key in keys)]
    )


def publication_diagnostics() -> bytes:
    lines = []
    for sequence, (inserted, retry, failure) in enumerate(((1, 0, 0), (0, 1, 0), (0, 0, 1), (1, 0, 0), (1, 0, 0)), 1):
        lines.append(f"event_publication_group group_sequence={sequence} collected=1 cohorts=1 custody_writer_commits=1 event_writer_commits={inserted} total_writer_commits={1+inserted} accepted_new={inserted} exact_retries={retry} failures={failure} max_cohort_size=1 singleton_fallbacks=1\n")
    return "".join(lines).encode()


class Fixture:
    def __init__(self, parent: Path) -> None:
        self.parent = parent
        self.parent.chmod(0o700)
        self.root = parent / "raw"
        self.root.mkdir(mode=0o700)
        self.carriers = {"publisher": "1" * 64, "receiver": "2" * 64}
        self.missions = {"publisher": "3" * 64, "receiver": "4" * 64}
        self.authority = "5" * 64
        self.event_ids = {
            "first": identifier("event-first"),
            "second": identifier("event-second"),
            "third": identifier("event-third"),
            "beta": identifier("event-beta"),
        }
        self.subscription_ids = {
            "alpha": identifier("subscription-alpha"),
            "beta": identifier("subscription-beta"),
        }
        self.secret = b"S" * CHECKER.IDENTITY_BYTES
        self.binary = b"\x7fELFsynthetic-live-event-release\n"
        self.source = {
            "commit": "1" * 40,
            "tree": "2" * 40,
            "signature": {"status": "good", "fingerprint": "A" * 40},
            "admitted": {
                path: {
                    "bytes": len(f"synthetic:{path}\n".encode("ascii")),
                    "sha256": hashlib.sha256(
                        f"synthetic:{path}\n".encode("ascii")
                    ).hexdigest(),
                }
                for path in ORACLE_ADMITTED_PATHS
            },
        }
        self._create_inventory()
        self.transcript_lines = self._transcript_lines()
        self.runtime_lines = self._runtime_lines()
        self.run_document: dict[str, object] = {}
        self.refresh_public()

    def _mkdir(self, relative: str) -> None:
        path = self.root / relative
        path.mkdir(mode=0o700)
        path.chmod(0o700)

    def _write(self, relative: str, data: bytes, mode: int) -> None:
        path = self.root / relative
        path.write_bytes(data)
        path.chmod(mode)

    def _create_inventory(self) -> None:
        for relative in (
            "binary",
            "participants",
            "participants/publisher",
            "participants/publisher/state",
            "participants/receiver",
            "participants/receiver/state",
        ):
            self._mkdir(relative)
        self._write("binary/aster-live-event-acceptance", self.binary, 0o700)
        self._write("participants/publisher/state/live-acceptance-publication.redb", b"private journal fixture", 0o600)
        for participant in ("publisher", "receiver"):
            self._write(
                f"participants/{participant}/mission.bundle",
                f"mission-{participant}\n".encode("ascii"),
                0o600,
            )
            self._write(
                f"participants/{participant}/state/identity.key", self.secret, 0o600
            )
            self._write(
                f"participants/{participant}/state/mesh.redb",
                f"store-{participant}\n".encode("ascii"),
                0o600,
            )

    def participant(self, name: str) -> dict[str, str]:
        return {
            "participant": name,
            "carrier_id": self.carriers[name],
            "mission_id": self.missions[name],
            "mission_authority": self.authority,
            "provisioning": "independent_reference_bundle",
        }

    def peer_binding(self, local: str, remote: str) -> dict[str, str]:
        return {
            "local": local,
            "remote": remote,
            "local_carrier": self.carriers[local],
            "local_mission": self.missions[local],
            "remote_carrier": self.carriers[remote],
            "remote_mission": self.missions[remote],
            "mission_authenticated": "true",
        }

    @staticmethod
    def phase(index: int, phase: str, actors: str, outcome: str) -> dict[str, str]:
        return {
            "index": str(index),
            "phase": phase,
            "actors": actors,
            "outcome": outcome,
        }

    def handle(self, phase: str, participant: str) -> dict[str, str]:
        return {
            "phase": phase,
            "participant": participant,
            "event_identity": self.missions[participant],
            "event_authority": self.authority,
        }

    def event(
        self,
        name: str,
        stream: str,
        counter: int,
        sequence: int,
        priority: str,
    ) -> dict[str, str]:
        return {
            "phase": "peerless_publish",
            "participant": "publisher",
            "stream": stream,
            "id": self.event_ids[name],
            "publisher": self.missions["publisher"],
            "publisher_counter": str(counter),
            "event_sequence": str(sequence),
            "priority": priority,
            "ttl": "durable",
            "acceptance_marker": str(counter),
            "inserted": "true",
            "payload_sha256": ORACLE_PAYLOAD_HASHES[name],
        }

    def query(
        self, phase: str, participant: str, stream: str, items: int, scanned: int
    ) -> dict[str, str]:
        return {
            "phase": phase,
            "participant": participant,
            "stream": stream,
            "items": str(items),
            "scanned_through": str(scanned),
            "has_more": "false",
            "limit": "8",
        }

    def status(
        self,
        phase: str,
        participant: str,
        sync: str,
        *,
        peer: str | None = None,
        observation: str | None = None,
        peer_last_contact: str | None = None,
    ) -> tuple[tuple[str, ...], dict[str, str]]:
        connected = peer is not None
        values = {
            "phase": phase,
            "participant": participant,
            "sync": sync,
            "authenticated_contacts": "1" if connected else "0",
            "failed_contact_attempts": "0",
            "peers": "1" if connected else "0",
            "peer": self.missions[peer] if connected else "none",
            "peer_contacts": "1" if connected else "0",
            "peer_authorization": "active" if connected else "none",
            "peer_last_contact": peer_last_contact if connected else "none",
        }
        if observation is not None:
            values = {
                "phase": phase,
                "participant": participant,
                "observation": observation,
                **{key: value for key, value in values.items() if key not in {"phase", "participant"}},
            }
            return CHILD_STATUS_KEYS, values
        return STATUS_KEYS, values

    def subscription(
        self, phase: str, stream: str, inserted: bool
    ) -> dict[str, str]:
        return {
            "phase": phase,
            "participant": "receiver",
            "stream": stream,
            "id": self.subscription_ids[stream],
            "inserted": str(inserted).lower(),
            "durable": "true",
            "include_descendant_scopes": "false",
        }

    @staticmethod
    def gap(phase: str, disposition: str) -> dict[str, str]:
        open_gap = disposition == "open"
        return {
            "phase": phase,
            "participant": "receiver",
            "stream": "alpha",
            "disposition": disposition,
            "start_sequence": "2" if open_gap else "0",
            "end_sequence": "3" if open_gap else "0",
            "scanned_through_sequence": "3",
            "has_more": "false",
            "authenticated": "true",
        }

    def delivery(self, phase: str, name: str, attempt: int) -> dict[str, str]:
        metadata = {
            "first": (1, "priority"),
            "second": (2, "routine"),
            "third": (3, "flash"),
        }
        sequence, priority = metadata[name]
        return {
            "phase": phase,
            "participant": "receiver",
            "stream": "alpha",
            "id": self.event_ids[name],
            "event_sequence": str(sequence),
            "priority": priority,
            "attempt": str(attempt),
            "payload_sha256": ORACLE_PAYLOAD_HASHES[name],
        }

    def acknowledgement(
        self, phase: str, name: str, *, already: bool
    ) -> dict[str, str]:
        return {
            "phase": phase,
            "participant": "receiver",
            "id": self.event_ids[name],
            "disposition": "already_acknowledged" if already else "acknowledged",
        }

    @staticmethod
    def empty_poll(phase: str, observation: str) -> dict[str, str]:
        return {
            "phase": phase,
            "participant": "receiver",
            "observation": observation,
            "deliveries": "0",
            "has_more": "false",
            "delivery_limit": "8",
            "scan_limit": "8",
        }

    @staticmethod
    def shutdown(
        phase: str,
        participant: str,
        *,
        events: int,
        contacts: int,
        offered: int = 0,
        fetched: int = 0,
        inserted: int = 0,
        duplicates: int = 0,
        remaining: int = 0,
    ) -> dict[str, str]:
        values = {key: "0" for key in SHUTDOWN_COUNTER_KEYS}
        values.update(
            {
                "contacts": str(contacts),
                "direct_contacts": str(contacts),
                "events": str(events),
                "event_acceptance_markers": str(events),
                "data_offered": str(offered),
                "data_fetched": str(fetched),
                "data_inserted": str(inserted),
                "data_duplicates": str(duplicates),
                "data_remaining": str(remaining),
            }
        )
        return {"phase": phase, "participant": participant, **values}

    @staticmethod
    def closed_handle(phase: str, participant: str) -> dict[str, str]:
        return {
            "phase": phase,
            "participant": participant,
            "error_kind": "state_unavailable",
            "operation": "status",
        }

    def _transcript_lines(self) -> list[str]:
        records: list[str] = []

        def add(kind: str, keys: tuple[str, ...], values: dict[str, str]) -> None:
            records.append(tsv(kind, keys, values))

        add(
            "RUN",
            RUN_KEYS,
            {
                "schema": ORACLE_TRANSCRIPT_SCHEMA,
                "publication_model": "numbered-v1",
                "claim": ORACLE_CLAIM,
                "participants": "2",
                "actor_lifetimes": "7",
                "maximum_concurrent_actors": "2",
                "topic": "opaque",
                "beta_topic": "opaque.beta",
                "scope": "test/runtime-contact",
                "stream_events": "3",
                "authorized_unsubscribed_events": "1",
            },
        )
        for participant in ("publisher", "receiver"):
            add("PARTICIPANT", PARTICIPANT_KEYS, self.participant(participant))
        add(
            "PEER_BINDING",
            PEER_BINDING_KEYS,
            self.peer_binding("publisher", "receiver"),
        )
        add(
            "PEER_BINDING",
            PEER_BINDING_KEYS,
            self.peer_binding("receiver", "publisher"),
        )

        add("PHASE", PHASE_KEYS, self.phase(1, "peerless_publish", "publisher", "published"))
        add("HANDLE", HANDLE_KEYS, self.handle("peerless_publish", "publisher"))
        add("EVENT", EVENT_KEYS, self.event("first", "alpha", 1, 1, "priority"))
        add(
            "EVENT_RETRY",
            EVENT_RETRY_KEYS,
            {
                "phase": "peerless_publish",
                "participant": "publisher",
                "id": self.event_ids["first"],
                "publisher": self.missions["publisher"],
                "publisher_counter": "1",
                "event_sequence": "1",
                "inserted": "false",
                "exact_match": "true",
            },
        )
        add(
            "OPERATION_CONFLICT",
            OPERATION_CONFLICT_KEYS,
            {
                "phase": "peerless_publish",
                "participant": "publisher",
                "original_id": self.event_ids["first"],
                "original_payload_sha256": ORACLE_PAYLOAD_HASHES["first"],
                "changed_payload_sha256": ORACLE_PAYLOAD_HASHES["changed_first"],
                "error_kind": "conflict",
                "operation": "publish_numbered",
                "sanitized": "true",
                "publication_preserved": "true",
            },
        )
        add("EVENT", EVENT_KEYS, self.event("second", "alpha", 2, 2, "routine"))
        add("EVENT", EVENT_KEYS, self.event("third", "alpha", 3, 3, "flash"))
        add("EVENT", EVENT_KEYS, self.event("beta", "beta", 4, 1, "priority"))
        add("QUERY", QUERY_KEYS, self.query("peerless_publish", "publisher", "alpha", 3, 4))
        add("QUERY", QUERY_KEYS, self.query("peerless_publish", "publisher", "beta", 1, 4))
        keys, values = self.status("peerless_publish", "publisher", "offline")
        add("STATUS", keys, values)
        add(
            "SHUTDOWN",
            SHUTDOWN_KEYS,
            self.shutdown("peerless_publish", "publisher", events=4, contacts=0),
        )
        add("CLOSED_HANDLE", CLOSED_HANDLE_KEYS, self.closed_handle("peerless_publish", "publisher"))

        add(
            "PHASE",
            PHASE_KEYS,
            self.phase(
                2,
                "threshold_delivery",
                "publisher+receiver",
                "receiver-force-terminated",
            ),
        )
        add("HANDLE", HANDLE_KEYS, self.handle("threshold_delivery", "publisher"))
        add("HANDLE", HANDLE_KEYS, self.handle("threshold_delivery", "receiver"))
        add("SUBSCRIPTION", SUBSCRIPTION_KEYS, self.subscription("threshold_delivery", "alpha", True))
        keys, values = self.status(
            "threshold_delivery",
            "receiver",
            "awaiting_authenticated_contact",
            observation="before_publisher_start",
        )
        add("STATUS", keys, values)
        keys, values = self.status(
            "threshold_delivery",
            "publisher",
            "last_contact_complete",
            peer="receiver",
            peer_last_contact="complete_for_last_negotiated_contact",
        )
        add("STATUS", keys, values)
        add("GAP", GAP_KEYS, self.gap("threshold_delivery", "open"))
        add("DELIVERY", DELIVERY_KEYS, self.delivery("threshold_delivery", "first", 1))
        add("DELIVERY", DELIVERY_KEYS, self.delivery("threshold_delivery", "third", 1))
        add(
            "PROCESS_TERMINATION",
            PROCESS_TERMINATION_KEYS,
            {
                "phase": "threshold_delivery",
                "participant": "receiver",
                "mechanism": "parent_child_kill",
                "after_flushed_poll": "true",
                "graceful": "false",
                "stop_record_expected": "false",
                "acknowledged": "false",
            },
        )
        add(
            "SHUTDOWN",
            SHUTDOWN_KEYS,
            self.shutdown(
                "threshold_delivery",
                "publisher",
                events=4,
                contacts=1,
                offered=2,
            ),
        )
        add("CLOSED_HANDLE", CLOSED_HANDLE_KEYS, self.closed_handle("threshold_delivery", "publisher"))

        add("PHASE", PHASE_KEYS, self.phase(3, "peerless_redelivery", "receiver", "acknowledged"))
        add("HANDLE", HANDLE_KEYS, self.handle("peerless_redelivery", "receiver"))
        add("SUBSCRIPTION", SUBSCRIPTION_KEYS, self.subscription("peerless_redelivery", "alpha", False))
        keys, values = self.status(
            "peerless_redelivery", "receiver", "offline", observation="peerless_reopen"
        )
        add("STATUS", keys, values)
        add("GAP", GAP_KEYS, self.gap("peerless_redelivery", "open"))
        for name in ("first", "third"):
            add("DELIVERY", DELIVERY_KEYS, self.delivery("peerless_redelivery", name, 2))
        for kind, name, already in (
            ("ACKNOWLEDGEMENT", "first", False),
            ("REACKNOWLEDGEMENT", "first", True),
            ("ACKNOWLEDGEMENT", "third", False),
            ("REACKNOWLEDGEMENT", "third", True),
        ):
            add(kind, ACK_KEYS, self.acknowledgement("peerless_redelivery", name, already=already))
        add("EMPTY_POLL", EMPTY_POLL_KEYS, self.empty_poll("peerless_redelivery", "after_acknowledgement"))
        add(
            "SHUTDOWN",
            SHUTDOWN_KEYS,
            self.shutdown("peerless_redelivery", "receiver", events=2, contacts=0),
        )
        add("CLOSED_HANDLE", CLOSED_HANDLE_KEYS, self.closed_handle("peerless_redelivery", "receiver"))

        add(
            "PHASE",
            PHASE_KEYS,
            self.phase(4, "normal_gap_closure", "publisher+receiver", "gap-closed"),
        )
        add("HANDLE", HANDLE_KEYS, self.handle("normal_gap_closure", "receiver"))
        add("HANDLE", HANDLE_KEYS, self.handle("normal_gap_closure", "publisher"))
        add("SUBSCRIPTION", SUBSCRIPTION_KEYS, self.subscription("normal_gap_closure", "alpha", False))
        add("EMPTY_POLL", EMPTY_POLL_KEYS, self.empty_poll("normal_gap_closure", "before_normal_contact"))
        keys, values = self.status(
            "normal_gap_closure", "receiver", "awaiting_authenticated_contact"
        )
        add("STATUS", keys, values)
        keys, values = self.status(
            "normal_gap_closure",
            "receiver",
            "last_contact_complete",
            peer="publisher",
            peer_last_contact="complete_for_last_negotiated_contact",
        )
        add("STATUS", keys, values)
        add("GAP", GAP_KEYS, self.gap("normal_gap_closure", "closed"))
        add("DELIVERY", DELIVERY_KEYS, self.delivery("normal_gap_closure", "second", 1))
        add("ACKNOWLEDGEMENT", ACK_KEYS, self.acknowledgement("normal_gap_closure", "second", already=False))
        add("REACKNOWLEDGEMENT", ACK_KEYS, self.acknowledgement("normal_gap_closure", "second", already=True))
        add("EMPTY_POLL", EMPTY_POLL_KEYS, self.empty_poll("normal_gap_closure", "after_gap_acknowledgement"))
        add("QUERY", QUERY_KEYS, self.query("normal_gap_closure", "receiver", "alpha", 3, 3))
        add("QUERY", QUERY_KEYS, self.query("normal_gap_closure", "receiver", "beta", 0, 3))
        add("SUBSCRIPTION", SUBSCRIPTION_KEYS, self.subscription("normal_gap_closure", "beta", True))
        keys, values = self.status(
            "normal_gap_closure",
            "receiver",
            "policy_changed_since_contact",
            peer="publisher",
            peer_last_contact="policy_changed_since_contact",
        )
        add("STATUS", keys, values)
        add(
            "UNSUBSCRIBE",
            UNSUBSCRIBE_KEYS,
            {
                "phase": "normal_gap_closure",
                "participant": "receiver",
                "stream": "beta",
                "subscription_id": self.subscription_ids["beta"],
                "disposition": "removed",
            },
        )
        add(
            "REUNSUBSCRIBE",
            UNSUBSCRIBE_KEYS,
            {
                "phase": "normal_gap_closure",
                "participant": "receiver",
                "stream": "beta",
                "subscription_id": self.subscription_ids["beta"],
                "disposition": "already_absent",
            },
        )
        add(
            "SHUTDOWN",
            SHUTDOWN_KEYS,
            self.shutdown(
                "normal_gap_closure",
                "publisher",
                events=4,
                contacts=1,
                offered=1,
            ),
        )
        add(
            "SHUTDOWN",
            SHUTDOWN_KEYS,
            self.shutdown(
                "normal_gap_closure",
                "receiver",
                events=3,
                contacts=1,
                fetched=1,
                inserted=1,
            ),
        )
        for participant in ("publisher", "receiver"):
            add("CLOSED_HANDLE", CLOSED_HANDLE_KEYS, self.closed_handle("normal_gap_closure", participant))

        add(
            "PHASE",
            PHASE_KEYS,
            self.phase(5, "final_peerless_reopen", "receiver", "durable-empty"),
        )
        add("HANDLE", HANDLE_KEYS, self.handle("final_peerless_reopen", "receiver"))
        add("SUBSCRIPTION", SUBSCRIPTION_KEYS, self.subscription("final_peerless_reopen", "alpha", False))
        keys, values = self.status("final_peerless_reopen", "receiver", "offline")
        add("STATUS", keys, values)
        add("GAP", GAP_KEYS, self.gap("final_peerless_reopen", "closed"))
        add("EMPTY_POLL", EMPTY_POLL_KEYS, self.empty_poll("final_peerless_reopen", "final_reopen"))
        add("QUERY", QUERY_KEYS, self.query("final_peerless_reopen", "receiver", "alpha", 3, 3))
        add("QUERY", QUERY_KEYS, self.query("final_peerless_reopen", "receiver", "beta", 0, 3))
        add(
            "SHUTDOWN",
            SHUTDOWN_KEYS,
            self.shutdown("final_peerless_reopen", "receiver", events=3, contacts=0),
        )
        add("CLOSED_HANDLE", CLOSED_HANDLE_KEYS, self.closed_handle("final_peerless_reopen", "receiver"))
        for participant in ("publisher", "receiver"):
            add("BIND_REACQUIRED", BIND_KEYS, {"participant": participant, "status": "reacquired"})
        add(
            "RESULT",
            RESULT_KEYS,
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
        )
        if len(records) != ORACLE_TRANSCRIPT_RECORDS:
            raise AssertionError(f"fixture has {len(records)} transcript records")
        return records

    def ready(
        self,
        participant: str,
        *,
        pid: int,
        socket: str,
        peers: int,
    ) -> str:
        return terminal(
            "READY",
            READY_KEYS,
            {
                "selected": "true",
                "pid": str(pid),
                "carrier_id": self.carriers[participant],
                "mission_id": self.missions[participant],
                "mission_authority": self.authority,
                "sockets": socket,
                "state": CHECKER.encoded_path(
                    self.root / "participants" / participant / "state"
                ),
                "peers": str(peers),
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
        )

    def contact(
        self,
        local: str,
        remote: str,
        *,
        offered: int,
        fetched: int,
        inserted: int,
    ) -> str:
        numeric = {key: "0" for key in CONTACT_KEYS[3:26] + CONTACT_KEYS[27:28]}
        numeric.update(
            {
                "rounds": "1",
                "offered": str(offered),
                "fetched": str(fetched),
                "inserted": str(inserted),
                "handshake_frames": "2",
                "handshake_bytes": "128",
                "protected_frames": "2",
                "protected_bytes": "128",
            }
        )
        return terminal(
            "CONTACT",
            CONTACT_KEYS,
            {
                "direction": "out" if local == "publisher" else "in",
                "carrier_peer": self.carriers[remote],
                "mission_peer": self.missions[remote],
                **numeric,
                "carrier_path": "direct",
                "carrier_path_transitions_saturated": "false",
                "path_observation": "not-authorization",
                "mission_auth": "hybrid-pq",
                "semantics": "source-authenticated-event",
                "reconciliation_classes": "event,state,record,blob",
                "controls": "source-authenticated-flash",
                "content_admission": "capability-gated",
                "status": "pass",
            },
        )

    def stop(self, phase: str, participant: str, *, events: int, contacts: int) -> str:
        numeric = {key: "0" for key in STOP_KEYS[4:11] + STOP_KEYS[12:-5]}
        numeric.update(
            {
                "contacts": str(contacts),
                "direct_contacts": str(contacts),
                "events": str(events),
                "event_acceptance_markers": str(events),
            }
        )
        return terminal(
            "STOP",
            STOP_KEYS,
            {
                "lifecycle": "complete",
                "sync_status": (
                    "contacts_observed" if contacts else "no_successful_contact"
                ),
                "carrier_id": self.carriers[participant],
                "mission_id": self.missions[participant],
                **numeric,
                "path_observation": "not-authorization",
                "mission_auth": "hybrid-pq",
                "provisioning": "unprotected-reference",
                "semantics": "source-authenticated-event",
                "reconciliation_classes": "event,state,record,blob-v5",
                "controls_semantics": "source-authenticated-flash",
            },
        )

    def awaiting_child(self) -> str:
        return child_tsv(
            "AWAITING",
            AWAITING_CHILD_KEYS,
            {
                "participant": "receiver",
                "identity": self.missions["receiver"],
                "subscription_id": self.subscription_ids["alpha"],
                "subscription_inserted": "true",
                "sync": "awaiting_authenticated_contact",
                "authenticated_contacts": "0",
                "failed_contact_attempts": "0",
                "peers": "0",
            },
        )

    def attempt_one_child(self) -> str:
        return child_tsv(
            "ATTEMPT1_READY",
            ATTEMPT1_CHILD_KEYS,
            {
                "participant": "receiver",
                "subscription_id": self.subscription_ids["alpha"],
                "sync": "last_contact_complete",
                "authenticated_contacts": "1",
                "failed_contact_attempts": "0",
                "peer": self.missions["publisher"],
                "peer_contacts": "1",
                "peer_authorization": "active",
                "peer_last_contact": "complete_for_last_negotiated_contact",
                "gap_start": "2",
                "gap_end": "3",
                "gap_scanned_through": "3",
                "gap_has_more": "false",
                "first_id": self.event_ids["first"],
                "first_sequence": "1",
                "first_priority": "priority",
                "first_attempt": "1",
                "first_payload_sha256": ORACLE_PAYLOAD_HASHES["first"],
                "third_id": self.event_ids["third"],
                "third_sequence": "3",
                "third_priority": "flash",
                "third_attempt": "1",
                "third_payload_sha256": ORACLE_PAYLOAD_HASHES["third"],
                "acknowledged": "false",
            },
        )

    def attempt_two_child(self) -> str:
        shutdown = {f"shutdown_{key}": "0" for key in SHUTDOWN_COUNTER_KEYS}
        shutdown.update(
            {"shutdown_events": "2", "shutdown_event_acceptance_markers": "2"}
        )
        return child_tsv(
            "ATTEMPT2_DONE",
            ATTEMPT2_CHILD_KEYS,
            {
                "participant": "receiver",
                "publisher": self.missions["publisher"],
                "subscription_id": self.subscription_ids["alpha"],
                "subscription_inserted": "false",
                "sync": "offline",
                "authenticated_contacts": "0",
                "failed_contact_attempts": "0",
                "peers": "0",
                "gap_start": "2",
                "gap_end": "3",
                "gap_scanned_through": "3",
                "gap_has_more": "false",
                "first_id": self.event_ids["first"],
                "first_sequence": "1",
                "first_priority": "priority",
                "first_attempt": "2",
                "first_payload_sha256": ORACLE_PAYLOAD_HASHES["first"],
                "first_ack": "acknowledged",
                "first_reack": "already_acknowledged",
                "third_id": self.event_ids["third"],
                "third_sequence": "3",
                "third_priority": "flash",
                "third_attempt": "2",
                "third_payload_sha256": ORACLE_PAYLOAD_HASHES["third"],
                "third_ack": "acknowledged",
                "third_reack": "already_acknowledged",
                "empty_deliveries": "0",
                "empty_has_more": "false",
                **shutdown,
                "closed_kind": "state_unavailable",
                "closed_operation": "status",
            },
        )

    def _runtime_lines(self) -> list[str]:
        lines = [
            self.ready(
                "publisher", pid=4242, socket="127.0.0.1:40000", peers=0
            ),
            self.stop("peerless_publish", "publisher", events=4, contacts=0),
            self.ready(
                "receiver", pid=4243, socket="127.0.0.1:41001", peers=1
            ),
            self.awaiting_child(),
            self.ready(
                "publisher", pid=4242, socket="127.0.0.1:41000", peers=1
            ),
            self.contact(
                "publisher", "receiver", offered=2, fetched=0, inserted=0
            ),
            self.contact(
                "receiver", "publisher", offered=0, fetched=2, inserted=2
            ),
            self.attempt_one_child(),
            self.stop("threshold_delivery", "publisher", events=4, contacts=1),
            self.ready(
                "receiver", pid=4244, socket="127.0.0.1:40001", peers=0
            ),
            self.stop("peerless_redelivery", "receiver", events=2, contacts=0),
            self.attempt_two_child(),
            self.ready(
                "receiver", pid=4242, socket="127.0.0.1:41001", peers=1
            ),
            self.ready(
                "publisher", pid=4242, socket="127.0.0.1:41000", peers=1
            ),
            self.contact(
                "publisher", "receiver", offered=1, fetched=0, inserted=0
            ),
            self.contact(
                "receiver", "publisher", offered=0, fetched=1, inserted=1
            ),
            self.stop("normal_gap_closure", "publisher", events=4, contacts=1),
            self.stop("normal_gap_closure", "receiver", events=3, contacts=1),
            self.ready(
                "receiver", pid=4242, socket="127.0.0.1:40002", peers=0
            ),
            self.stop("final_peerless_reopen", "receiver", events=3, contacts=0),
        ]
        return lines

    @staticmethod
    def _artifact(relative: str, data: bytes) -> dict[str, object]:
        return {
            "path": relative,
            "bytes": len(data),
            "sha256": hashlib.sha256(data).hexdigest(),
        }

    def inventory_document(self) -> dict[str, object]:
        directories = []
        for relative in sorted(
            (
                "",
                "binary",
                "participants",
                "participants/publisher",
                "participants/publisher/state",
                "participants/receiver",
                "participants/receiver/state",
            )
        ):
            path = self.root if not relative else self.root / relative
            metadata = path.stat()
            directories.append(
                {"path": relative or ".", "mode": 0o700, "owner": metadata.st_uid}
            )

        def metadata(relative: str) -> dict[str, object]:
            observed = (self.root / relative).stat()
            return {
                "path": relative,
                "bytes": observed.st_size,
                "mode": stat.S_IMODE(observed.st_mode),
                "hard_links": observed.st_nlink,
                "owner": observed.st_uid,
            }

        public = tuple(
            sorted(
                (
                    "binary/aster-live-event-acceptance",
                    "stderr.log",
                    "stdout.log",
                    "transcript.tsv",
                )
            )
        )
        secret = tuple(
            sorted(
                f"participants/{participant}/{relative}"
                for participant in ("publisher", "receiver")
                for relative in (
                    "mission.bundle",
                    "state/identity.key",
                    "state/mesh.redb",
                )
            )
        )
        return {
            "directories": directories,
            "public": [metadata(relative) for relative in public],
            "participant_secret": [metadata(relative) for relative in sorted((*secret, "participants/publisher/state/live-acceptance-publication.redb"))],
        }

    def refresh_public(self) -> None:
        transcript = ("\n".join(self.transcript_lines) + "\n").encode("ascii")
        stdout = ("\n".join([*self.runtime_lines, *self.transcript_lines]) + "\n").encode(
            "ascii"
        )
        self._write("transcript.tsv", transcript, 0o600)
        self._write("stdout.log", stdout, 0o600)
        self._write("stderr.log", publication_diagnostics(), 0o600)
        admitted = [
            {"path": path, **self.source["admitted"][path]}
            for path in ORACLE_ADMITTED_PATHS
        ]
        tools = {
            role: {"path": path, **self.source["admitted"][path]}
            for role, path in CHECKER.TOOL_PATHS.items()
        }
        self.run_document = {
            "schema": ORACLE_RAW_SCHEMA,
            "claim": ORACLE_CLAIM,
            "run_id": hashlib.sha256(transcript).hexdigest()[:16],
            "source": {
                "commit": self.source["commit"],
                "tree": self.source["tree"],
                "signature": dict(self.source["signature"]),
                "admitted": admitted,
            },
            "commands": {
                "build_argv": list(ORACLE_BUILD_ARGV),
                "run_argv": [
                    os.fspath(
                        self.root / "binary" / "aster-live-event-acceptance"
                    ),
                    os.fspath(self.root),
                ],
            },
            "execution": {
                "exit_code": 0,
                "timeout_seconds": 180,
                "worktree_clean_at_run": True,
                "source_binary_execution_link": (
                    "operator-attested-not-cryptographically-proven"
                ),
            },
            "artifacts": {
                "binary": self._artifact(
                    "binary/aster-live-event-acceptance", self.binary
                ),
                "stdout": self._artifact("stdout.log", stdout),
                "stderr": self._artifact("stderr.log", publication_diagnostics()),
                "transcript": self._artifact("transcript.tsv", transcript),
            },
            "inventory": self.inventory_document(),
            "tools": tools,
        }
        self.write_run_document()

    def write_run_document(self) -> None:
        self._write(
            "run.json", CHECKER.canonical_json_bytes(self.run_document), 0o600
        )

    def mutate_transcript(self, index: int, key: str, value: str) -> None:
        parts = self.transcript_lines[index].split("\t")
        for position in range(2, len(parts)):
            if parts[position].startswith(f"{key}="):
                parts[position] = f"{key}={value}"
                break
        else:
            raise AssertionError(f"missing fixture field {key}")
        self.transcript_lines[index] = "\t".join(parts)
        self.refresh_public()

    def mutate_runtime(self, index: int, key: str, value: str) -> None:
        separator = "\t" if self.runtime_lines[index].startswith("LIVE_EVENT_CHILD") else " "
        parts = self.runtime_lines[index].split(separator)
        for position in range(2 if separator == "\t" else 1, len(parts)):
            if parts[position].startswith(f"{key}="):
                parts[position] = f"{key}={value}"
                break
        else:
            raise AssertionError(f"missing runtime fixture field {key}")
        self.runtime_lines[index] = separator.join(parts)
        self.refresh_public()

    def receipt(self) -> bytes:
        evidence = CHECKER.validate_raw_root(self.root, self.source)
        document = CHECKER.build_receipt(self.source, evidence)
        return CHECKER.render_receipt(
            document,
            forbidden_values=CHECKER.receipt_forbidden_values(
                evidence, self.root
            ),
            forbidden_pids=CHECKER.receipt_forbidden_pids(evidence),
            forbidden_ports=CHECKER.receipt_forbidden_ports(evidence),
        )


class SelectedLiveEventReceiptTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory(dir=TEST_TEMP_PARENT)
        self.fixture = Fixture(Path(self.temporary.name))

    def test_publication_diagnostics_reject_missing_extra_and_changed_accounting(self) -> None:
        valid = publication_diagnostics()
        CHECKER.validate_publication_diagnostics(valid, inserted=3, retries=1, failures=1)
        for invalid in (b"", valid + b"\xff\n", valid + b"secret=leaked\n", valid.replace(b"accepted_new=1", b"accepted_new=2", 1), valid.replace(b"group_sequence=2", b"group_sequence=1", 1), valid.replace(b"event_writer_commits=1", b"event_writer_commits=0", 1)):
            with self.assertRaises(CHECKER.ReceiptViolation):
                CHECKER.validate_publication_diagnostics(invalid, inserted=3, retries=1, failures=1)

    def test_historical_v1_transcript_stays_distinct_from_numbered_v2(self) -> None:
        path = Path(__file__).parent / "historical/check-selected-live-event-receipt.py"
        spec = importlib.util.spec_from_file_location("historical_live_event", path)
        self.assertIsNotNone(spec)
        historical = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(historical)
        lines = list(self.fixture.transcript_lines)
        fields = [field for field in lines[0].split("\t") if not field.startswith("publication_model=")]
        lines[0] = "\t".join(fields).replace(ORACLE_TRANSCRIPT_SCHEMA, historical.TRANSCRIPT_SCHEMA)
        data = ("\n".join(lines) + "\n").replace("operation=publish_numbered", "operation=publish").encode()
        historical.validate_transcript(data)
        with self.assertRaises(CHECKER.ReceiptViolation):
            CHECKER.validate_transcript(data)
        self.assertEqual(historical.SCHEMA, "aster-selected-live-event-receipt/v1")
        self.assertNotIn("participants/publisher/state/live-acceptance-publication.redb", historical.SECRET_FILES)

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def assert_rejected(self, pattern: str | None = None) -> None:
        context = (
            self.assertRaisesRegex(CHECKER.ReceiptViolation, pattern)
            if pattern is not None
            else self.assertRaises(CHECKER.ReceiptViolation)
        )
        with context:
            self.fixture.receipt()

    def assert_transcript_cases(
        self, cases: tuple[tuple[int, str, str], ...]
    ) -> None:
        for index, key, value in cases:
            with self.subTest(index=index, key=key, value=value):
                with tempfile.TemporaryDirectory(dir=TEST_TEMP_PARENT) as parent:
                    fixture = Fixture(Path(parent))
                    fixture.mutate_transcript(index, key, value)
                    with self.assertRaises(CHECKER.ReceiptViolation):
                        fixture.receipt()

    def assert_runtime_cases(
        self, cases: tuple[tuple[int, str, str], ...]
    ) -> None:
        for index, key, value in cases:
            with self.subTest(index=index, key=key, value=value):
                with tempfile.TemporaryDirectory(dir=TEST_TEMP_PARENT) as parent:
                    fixture = Fixture(Path(parent))
                    fixture.mutate_runtime(index, key, value)
                    with self.assertRaises(CHECKER.ReceiptViolation):
                        fixture.receipt()

    def test_independent_contract_oracles_match_all_three_tools(self) -> None:
        self.assertEqual(CHECKER.SCHEMA, ORACLE_RECEIPT_SCHEMA)
        self.assertEqual(CHECKER.RAW_SCHEMA, ORACLE_RAW_SCHEMA)
        self.assertEqual(CHECKER.TRANSCRIPT_SCHEMA, ORACLE_TRANSCRIPT_SCHEMA)
        self.assertEqual(CHECKER.CLAIM, ORACLE_CLAIM)
        self.assertEqual(CHECKER.TRANSCRIPT_RECORDS, ORACLE_TRANSCRIPT_RECORDS)
        self.assertEqual(RUNNER.RAW_SCHEMA, ORACLE_RAW_SCHEMA)
        self.assertEqual(RUNNER.CLAIM, ORACLE_CLAIM)
        self.assertEqual(RUNNER.TRANSCRIPT_RECORDS, ORACLE_TRANSCRIPT_RECORDS)
        self.assertEqual(tuple(CHECKER.EXPECTED_BUILD_ARGV), ORACLE_BUILD_ARGV)
        self.assertEqual(tuple(RUNNER.BUILD_ARGV), ORACLE_BUILD_ARGV)
        self.assertEqual(tuple(CHECKER.ADMITTED_SOURCE_PATHS), ORACLE_ADMITTED_PATHS)
        self.assertEqual(tuple(RUNNER.ADMITTED_PATHS), ORACLE_ADMITTED_PATHS)
        self.assertEqual(tuple(CHECKER.LIMITATIONS), ORACLE_LIMITATIONS)
        self.assertEqual(tuple(CHECKER.NONCLAIMS), ORACLE_NONCLAIMS)
        self.assertEqual(CHECKER.PAYLOAD_HASHES, ORACLE_PAYLOAD_HASHES)
        self.assertEqual(CHECKER.EXPECTED_SEQUENCE, ORACLE_SEQUENCE)

    def test_producer_literals_match_independent_contract(self) -> None:
        producer = (
            Path(__file__).parents[1]
            / "crates/aster-node/examples/live_event_acceptance.rs"
        ).read_text(encoding="utf-8")
        for literal in (
            ORACLE_TRANSCRIPT_SCHEMA,
            ORACLE_CLAIM,
            "const TRANSCRIPT_RECORDS: usize = 79;",
            'const TOPIC: &str = "opaque";',
            'const BETA_TOPIC: &str = "opaque.beta";',
            'const SCOPE: &str = "test/runtime-contact";',
            'const FIRST_PAYLOAD: &[u8] = b"priority event one";',
            'const SECOND_PAYLOAD: &[u8] = b"routine event two";',
            'const THIRD_PAYLOAD: &[u8] = b"flash event three";',
            "parent_child_kill",
            "policy_changed_since_contact",
        ):
            with self.subTest(literal=literal):
                self.assertIn(literal, producer)

    def test_runner_extracts_exact_ordered_79_record_transcript(self) -> None:
        stdout = self.fixture.root / "synthetic-stdout.log"
        expected = ("\n".join(self.fixture.transcript_lines) + "\n").encode("ascii")
        stdout.write_bytes(b"READY selected=true\n" + expected + b"ignored\n")
        self.assertEqual(RUNNER.extract_transcript(stdout), expected)
        stdout.write_bytes(b"noise\n" + b"\n".join(expected.splitlines()[:-1]) + b"\n")
        with self.assertRaises(RUNNER.RunnerFailure):
            RUNNER.extract_transcript(stdout)

    def test_valid_projection_is_deterministic_canonical_bounded_and_sanitized(self) -> None:
        first = self.fixture.receipt()
        second = self.fixture.receipt()
        self.assertEqual(first, second)
        self.assertLessEqual(len(first), CHECKER.RECEIPT_MAX_BYTES)
        document = json.loads(first)
        self.assertEqual(first, CHECKER.canonical_json_bytes(document))
        self.assertEqual(document["schema"], ORACLE_RECEIPT_SCHEMA)
        self.assertEqual(document["claim"], ORACLE_CLAIM)
        self.assertEqual(document["status"], "pass")
        self.assertEqual(document["run"]["transcript"]["records"], 79)
        self.assertEqual(document["run"]["stdout"]["ready_records"], 7)
        self.assertEqual(document["run"]["stdout"]["contact_records"], 4)
        self.assertEqual(document["run"]["stdout"]["stop_records"], 6)
        self.assertEqual(document["run"]["stdout"]["child_coordination_records"], 3)
        status = document["acceptance"]["status"]
        self.assertEqual(status["awaiting_failed_contact_attempts"], 0)
        self.assertEqual(status["work_remained_observations"], 0)
        self.assertEqual(status["last_contact_complete_transcript_observations"], 2)
        self.assertEqual(status["last_contact_complete_child_coordination_observations"], 1)
        self.assertEqual(status["policy_changed_since_contact_observations"], 1)
        encoded = first.decode("ascii")
        # Exact paths and identifiers are safe whole-document canaries. Short
        # PID and port digit strings are checked structurally below because
        # they may legitimately occur inside counts or cryptographic digests.
        for forbidden in (
            os.fspath(self.fixture.root),
            *self.fixture.carriers.values(),
            *self.fixture.missions.values(),
            self.fixture.authority,
            *self.fixture.event_ids.values(),
            *self.fixture.subscription_ids.values(),
        ):
            self.assertNotIn(forbidden, encoded)

    def test_transcript_record_count_order_and_framing_fail_closed(self) -> None:
        self.fixture.transcript_lines.pop()
        self.fixture.refresh_public()
        self.assert_rejected("exactly 79 records")

        with tempfile.TemporaryDirectory(dir=TEST_TEMP_PARENT) as parent:
            fixture = Fixture(Path(parent))
            fixture.transcript_lines[10], fixture.transcript_lines[11] = (
                fixture.transcript_lines[11],
                fixture.transcript_lines[10],
            )
            fixture.refresh_public()
            with self.assertRaises(CHECKER.ReceiptViolation):
                fixture.receipt()

        with tempfile.TemporaryDirectory(dir=TEST_TEMP_PARENT) as parent:
            fixture = Fixture(Path(parent))
            fixture.transcript_lines[7] = fixture.transcript_lines[7].replace(
                "LIVE_EVENT\tEVENT", "UNTRUSTED\tEVENT", 1
            )
            fixture.refresh_public()
            with self.assertRaises(CHECKER.ReceiptViolation):
                fixture.receipt()

    def test_transcript_field_order_missing_extra_and_duplicate_fail_closed(self) -> None:
        for mutation in ("reorder", "missing", "extra", "duplicate"):
            with self.subTest(mutation=mutation):
                with tempfile.TemporaryDirectory(dir=TEST_TEMP_PARENT) as parent:
                    fixture = Fixture(Path(parent))
                    parts = fixture.transcript_lines[7].split("\t")
                    if mutation == "reorder":
                        parts[2], parts[3] = parts[3], parts[2]
                    elif mutation == "missing":
                        parts.pop()
                    elif mutation == "extra":
                        parts.append("unexpected=true")
                    else:
                        parts.append(parts[-1])
                    fixture.transcript_lines[7] = "\t".join(parts)
                    fixture.refresh_public()
                    with self.assertRaises(CHECKER.ReceiptViolation):
                        fixture.receipt()

    def test_transcript_noncanonical_encodings_fail_before_projection(self) -> None:
        transcript = self.fixture.root / "transcript.tsv"
        stdout = self.fixture.root / "stdout.log"
        for suffix in (b"\x00", b"\r", "\N{SNOWMAN}".encode("utf-8")):
            with self.subTest(suffix=suffix):
                data = transcript.read_bytes()
                transcript.write_bytes(data[:-1] + suffix + b"\n")
                stdout.write_bytes(stdout.read_bytes() + suffix + b"\n")
                with self.assertRaises(CHECKER.ReceiptViolation):
                    CHECKER.validate_raw_root(self.fixture.root, self.fixture.source)
                transcript.write_bytes(data)
                self.fixture.refresh_public()

    def test_run_participant_phase_and_handle_mutations_fail_closed(self) -> None:
        self.assert_transcript_cases(
            (
                (0, "claim", "wrong-claim"),
                (0, "participants", "3"),
                (0, "actor_lifetimes", "6"),
                (0, "authorized_unsubscribed_events", "0"),
                (1, "provisioning", "shared"),
                (1, "mission_authority", "6" * 64),
                (1, "carrier_id", "f" * 64),
                (3, "remote_mission", "f" * 64),
                (4, "mission_authenticated", "false"),
                (5, "outcome", "partial"),
                (18, "actors", "receiver"),
                (6, "event_identity", self.fixture.missions["receiver"]),
                (20, "event_authority", "6" * 64),
            )
        )

    def test_publication_sequence_priority_hash_and_identity_mutations_fail_closed(self) -> None:
        self.assert_transcript_cases(
            (
                (7, "publisher", self.fixture.missions["receiver"]),
                (7, "publisher_counter", "2"),
                (7, "event_sequence", "2"),
                (7, "priority", "routine"),
                (7, "ttl", "1000"),
                (7, "acceptance_marker", "9"),
                (7, "inserted", "false"),
                (7, "payload_sha256", "0" * 64),
                (10, "event_sequence", "3"),
                (11, "priority", "priority"),
                (12, "stream", "alpha"),
                (12, "id", self.fixture.event_ids["first"]),
            )
        )

    def test_retry_and_changed_intent_conflict_are_exact_and_nonmutating(self) -> None:
        self.assert_transcript_cases(
            (
                (8, "id", self.fixture.event_ids["second"]),
                (8, "inserted", "true"),
                (8, "exact_match", "false"),
                (9, "original_id", self.fixture.event_ids["second"]),
                (9, "original_payload_sha256", "0" * 64),
                (9, "changed_payload_sha256", ORACLE_PAYLOAD_HASHES["first"]),
                (9, "error_kind", "internal"),
                (9, "operation", "query"),
                (9, "sanitized", "false"),
                (9, "publication_preserved", "false"),
            )
        )

    def test_query_and_authorized_unsubscribed_beta_evidence_fail_closed(self) -> None:
        self.assert_transcript_cases(
            (
                (13, "items", "2"),
                (13, "scanned_through", "3"),
                (14, "items", "0"),
                (14, "scanned_through", "3"),
                (56, "items", "2"),
                (57, "items", "1"),
                (57, "stream", "alpha"),
                (73, "items", "1"),
            )
        )

    def test_status_transitions_are_exact_without_positive_failure_claim(self) -> None:
        self.assert_transcript_cases(
            (
                (15, "sync", "awaiting_authenticated_contact"),
                (22, "failed_contact_attempts", "1"),
                (22, "peers", "1"),
                (23, "sync", "work_remained"),
                (23, "peer_last_contact", "work_remained"),
                (33, "sync", "last_contact_complete"),
                (49, "failed_contact_attempts", "1"),
                (50, "authenticated_contacts", "2"),
                (50, "peer_authorization", "revoked"),
                (59, "sync", "last_contact_complete"),
                (59, "peer_last_contact", "complete_for_last_negotiated_contact"),
                (69, "peers", "1"),
            )
        )

    def test_subscription_replay_beta_policy_and_removal_are_exact(self) -> None:
        self.assert_transcript_cases(
            (
                (21, "inserted", "false"),
                (21, "durable", "false"),
                (32, "id", identifier("different-subscription")),
                (32, "inserted", "true"),
                (47, "id", identifier("different-subscription")),
                (58, "id", self.fixture.subscription_ids["alpha"]),
                (58, "inserted", "false"),
                (60, "subscription_id", self.fixture.subscription_ids["alpha"]),
                (60, "disposition", "already_absent"),
                (61, "disposition", "removed"),
                (68, "id", identifier("different-subscription")),
            )
        )

    def test_gap_crash_redelivery_attempt_and_ack_evidence_fail_closed(self) -> None:
        self.assert_transcript_cases(
            (
                (24, "start_sequence", "1"),
                (24, "end_sequence", "2"),
                (24, "authenticated", "false"),
                (25, "attempt", "2"),
                (26, "id", self.fixture.event_ids["second"]),
                (27, "mechanism", "graceful-shutdown"),
                (27, "after_flushed_poll", "false"),
                (27, "graceful", "true"),
                (27, "stop_record_expected", "true"),
                (27, "acknowledged", "true"),
                (34, "disposition", "closed"),
                (35, "attempt", "1"),
                (36, "payload_sha256", ORACLE_PAYLOAD_HASHES["second"]),
                (37, "disposition", "already_acknowledged"),
                (38, "disposition", "acknowledged"),
                (39, "id", self.fixture.event_ids["first"]),
                (41, "deliveries", "1"),
                (51, "disposition", "open"),
                (52, "attempt", "2"),
                (53, "id", self.fixture.event_ids["first"]),
                (54, "disposition", "acknowledged"),
                (70, "start_sequence", "2"),
                (71, "deliveries", "1"),
            )
        )

    def test_shutdown_closed_handle_bind_and_result_cardinality_fail_closed(self) -> None:
        self.assert_transcript_cases(
            (
                (16, "events", "3"),
                (16, "contacts", "1"),
                (28, "direct_contacts", "0"),
                (28, "contact_errors", "1"),
                (28, "controls", "1"),
                (42, "events", "3"),
                (62, "relay_contacts", "1"),
                (63, "event_acceptance_markers", "2"),
                (74, "blob_bytes_fetched", "1"),
                (17, "operation", "query"),
                (43, "error_kind", "not_found"),
                (76, "status", "held"),
                (77, "participant", "publisher"),
                (78, "actor_lifetimes", "6"),
                (78, "forced_process_terminations", "0"),
                (78, "global_convergence_claimed", "true"),
            )
        )

    def test_ready_identity_path_peer_and_process_binding_fail_closed(self) -> None:
        self.assert_runtime_cases(
            (
                (0, "carrier_id", self.fixture.carriers["receiver"]),
                (0, "mission_id", self.fixture.missions["receiver"]),
                (0, "mission_authority", "6" * 64),
                (0, "state", "/private/tmp/elsewhere"),
                (0, "peers", "1"),
                (0, "application", "consume"),
                (0, "semantics", "opaque"),
                (2, "peers", "0"),
                (9, "pid", "4243"),
                (12, "pid", "4245"),
                (12, "sockets", "127.0.0.1:42001"),
                (13, "sockets", "0.0.0.0:41000"),
                (18, "peers", "1"),
            )
        )

    def test_ready_lifetime_cardinality_overlap_and_socket_reuse_fail_closed(self) -> None:
        self.fixture.runtime_lines.pop(18)
        self.fixture.refresh_public()
        self.assert_rejected()

        with tempfile.TemporaryDirectory(dir=TEST_TEMP_PARENT) as parent:
            fixture = Fixture(Path(parent))
            fixture.runtime_lines.insert(1, fixture.runtime_lines[0])
            fixture.refresh_public()
            with self.assertRaises(CHECKER.ReceiptViolation):
                fixture.receipt()

        with tempfile.TemporaryDirectory(dir=TEST_TEMP_PARENT) as parent:
            fixture = Fixture(Path(parent))
            fixture.runtime_lines[12] = fixture.runtime_lines[12].replace(
                "sockets=127.0.0.1:41001", "sockets=127.0.0.1:41000"
            )
            fixture.refresh_public()
            with self.assertRaises(CHECKER.ReceiptViolation):
                fixture.receipt()

        with tempfile.TemporaryDirectory(dir=TEST_TEMP_PARENT) as parent:
            fixture = Fixture(Path(parent))
            for index in (2, 12):
                fixture.runtime_lines[index] = fixture.runtime_lines[index].replace(
                    "sockets=127.0.0.1:41001", "sockets=127.0.0.1:41000"
                )
            fixture.refresh_public()
            with self.assertRaises(CHECKER.ReceiptViolation):
                fixture.receipt()

    def test_contact_direction_path_status_and_excluded_classes_fail_closed(self) -> None:
        self.assert_runtime_cases(
            (
                (5, "direction", "in"),
                (6, "direction", "out"),
                (5, "carrier_peer", self.fixture.carriers["publisher"]),
                (5, "mission_peer", self.fixture.missions["publisher"]),
                (5, "rounds", "0"),
                (5, "carrier_path", "relay"),
                (5, "status", "partial"),
                (5, "control_offered", "1"),
                (5, "mutable_remaining", "1"),
                (5, "blob_bytes_fetched", "1"),
                (5, "duplicates", "1"),
                (5, "carrier_path_transitions", "1"),
                (14, "content_admission", "unrestricted"),
            )
        )

    def test_contact_cardinality_and_exact_three_event_transfer_fail_closed(self) -> None:
        self.assert_runtime_cases(
            (
                (5, "offered", "1"),
                (6, "fetched", "1"),
                (6, "inserted", "1"),
                (14, "offered", "2"),
                (15, "fetched", "2"),
                (15, "inserted", "2"),
            )
        )
        with tempfile.TemporaryDirectory(dir=TEST_TEMP_PARENT) as parent:
            fixture = Fixture(Path(parent))
            fixture.runtime_lines.pop(14)
            fixture.refresh_public()
            with self.assertRaises(CHECKER.ReceiptViolation):
                fixture.receipt()
        with tempfile.TemporaryDirectory(dir=TEST_TEMP_PARENT) as parent:
            fixture = Fixture(Path(parent))
            fixture.runtime_lines.insert(16, fixture.runtime_lines[15])
            fixture.refresh_public()
            with self.assertRaises(CHECKER.ReceiptViolation):
                fixture.receipt()

    def test_contact_shutdown_data_accounting_is_exact_per_lifetime(self) -> None:
        self.assert_transcript_cases(
            (
                (16, "data_offered", "1"),
                (28, "data_offered", "0"),
                (28, "data_fetched", "1"),
                (28, "data_inserted", "1"),
                (28, "data_duplicates", "1"),
                (28, "data_remaining", "1"),
                (42, "data_fetched", "1"),
                (62, "data_offered", "0"),
                (63, "data_fetched", "0"),
                (63, "data_inserted", "0"),
                (74, "data_remaining", "1"),
            )
        )
        self.assert_runtime_cases(
            (
                (5, "remaining", "1"),
                (5, "deferred_event_lanes", "1"),
                (6, "remaining", "1"),
                (6, "deferred_event_lanes", "1"),
                (14, "remaining", "1"),
                (15, "deferred_event_lanes", "1"),
            )
        )

    def test_stop_cross_binding_and_excluded_class_activity_fail_closed(self) -> None:
        self.assert_runtime_cases(
            (
                (1, "events", "3"),
                (1, "sync_status", "contacts_observed"),
                (1, "opaque_items", "1"),
                (8, "contacts", "0"),
                (8, "direct_contacts", "0"),
                (8, "contact_errors", "1"),
                (8, "relay_contacts", "1"),
                (8, "events", "3"),
                (8, "controls", "1"),
                (10, "event_acceptance_markers", "1"),
                (16, "blob_operations", "1"),
                (17, "carrier_path_transitions", "1"),
                (19, "lifecycle", "partial"),
            )
        )

    def test_stop_cardinality_and_forced_receiver_absence_fail_closed(self) -> None:
        self.fixture.runtime_lines.pop(8)
        self.fixture.refresh_public()
        self.assert_rejected()

        with tempfile.TemporaryDirectory(dir=TEST_TEMP_PARENT) as parent:
            fixture = Fixture(Path(parent))
            fake_stop = fixture.stop(
                "threshold_delivery", "receiver", events=2, contacts=1
            )
            fixture.runtime_lines.insert(7, fake_stop)
            fixture.refresh_public()
            with self.assertRaises(CHECKER.ReceiptViolation):
                fixture.receipt()

    def test_child_awaiting_record_is_exact_zero_failure_and_bound(self) -> None:
        self.assert_runtime_cases(
            (
                (3, "identity", self.fixture.missions["publisher"]),
                (3, "subscription_id", self.fixture.subscription_ids["beta"]),
                (3, "subscription_inserted", "false"),
                (3, "sync", "offline"),
                (3, "authenticated_contacts", "1"),
                (3, "failed_contact_attempts", "1"),
                (3, "peers", "1"),
            )
        )
        parts = self.fixture.runtime_lines[3].split("\t")
        parts.append("extra=true")
        self.fixture.runtime_lines[3] = "\t".join(parts)
        self.fixture.refresh_public()
        self.assert_rejected("missing or extra fields")

    def test_child_attempt_one_binds_flushed_unacknowledged_first_attempt(self) -> None:
        self.assert_runtime_cases(
            (
                (7, "subscription_id", self.fixture.subscription_ids["beta"]),
                (7, "sync", "work_remained"),
                (7, "authenticated_contacts", "0"),
                (7, "failed_contact_attempts", "1"),
                (7, "peer", self.fixture.missions["receiver"]),
                (7, "peer_contacts", "2"),
                (7, "peer_authorization", "revoked"),
                (7, "peer_last_contact", "work_remained"),
                (7, "gap_start", "1"),
                (7, "gap_end", "2"),
                (7, "first_id", self.fixture.event_ids["second"]),
                (7, "first_attempt", "2"),
                (7, "third_attempt", "2"),
                (7, "third_payload_sha256", ORACLE_PAYLOAD_HASHES["second"]),
                (7, "acknowledged", "true"),
            )
        )

    def test_child_attempt_two_binds_fresh_process_attempts_acks_and_shutdown(self) -> None:
        self.assert_runtime_cases(
            (
                (11, "publisher", self.fixture.missions["receiver"]),
                (11, "subscription_inserted", "true"),
                (11, "sync", "last_contact_complete"),
                (11, "failed_contact_attempts", "1"),
                (11, "gap_start", "1"),
                (11, "first_id", self.fixture.event_ids["second"]),
                (11, "first_attempt", "1"),
                (11, "first_ack", "already_acknowledged"),
                (11, "first_reack", "acknowledged"),
                (11, "third_attempt", "1"),
                (11, "third_ack", "already_acknowledged"),
                (11, "empty_deliveries", "1"),
                (11, "shutdown_contacts", "1"),
                (11, "shutdown_events", "3"),
                (11, "shutdown_controls", "1"),
                (11, "closed_kind", "not_found"),
                (11, "closed_operation", "query"),
            )
        )

    def test_child_record_cardinality_order_and_kill_lifetime_fail_closed(self) -> None:
        self.fixture.runtime_lines.pop(7)
        self.fixture.refresh_public()
        self.assert_rejected()

        with tempfile.TemporaryDirectory(dir=TEST_TEMP_PARENT) as parent:
            fixture = Fixture(Path(parent))
            record = fixture.runtime_lines.pop(7)
            fixture.runtime_lines.insert(10, record)
            fixture.refresh_public()
            with self.assertRaises(CHECKER.ReceiptViolation):
                fixture.receipt()

        with tempfile.TemporaryDirectory(dir=TEST_TEMP_PARENT) as parent:
            fixture = Fixture(Path(parent))
            fixture.runtime_lines.insert(8, fixture.runtime_lines[7])
            fixture.refresh_public()
            with self.assertRaises(CHECKER.ReceiptViolation):
                fixture.receipt()

        for source_index, destination_index in ((3, 1), (3, 5), (11, 10)):
            with self.subTest(
                source_index=source_index, destination_index=destination_index
            ):
                with tempfile.TemporaryDirectory(dir=TEST_TEMP_PARENT) as parent:
                    fixture = Fixture(Path(parent))
                    record = fixture.runtime_lines.pop(source_index)
                    fixture.runtime_lines.insert(destination_index, record)
                    fixture.refresh_public()
                    with self.assertRaises(CHECKER.ReceiptViolation):
                        fixture.receipt()

    def test_unexpected_terminal_family_or_post_transcript_output_fails_closed(self) -> None:
        self.fixture.runtime_lines.insert(0, "DEBUG value=1")
        self.fixture.refresh_public()
        self.assert_rejected("unadmitted terminal record family")

        with tempfile.TemporaryDirectory(dir=TEST_TEMP_PARENT) as parent:
            fixture = Fixture(Path(parent))
            stdout = fixture.root / "stdout.log"
            stdout.write_bytes(stdout.read_bytes() + b"READY selected=true\n")
            fixture.run_document["artifacts"]["stdout"] = fixture._artifact(
                "stdout.log", stdout.read_bytes()
            )
            fixture.run_document["inventory"] = fixture.inventory_document()
            fixture.write_run_document()
            with self.assertRaisesRegex(
                CHECKER.ReceiptViolation, "after the public transcript began"
            ):
                fixture.receipt()

    def test_unexpected_inventory_file_directory_symlink_and_hardlink_fail_closed(self) -> None:
        (self.fixture.root / "unexpected").write_bytes(b"x")
        self.assert_rejected()

        with tempfile.TemporaryDirectory(dir=TEST_TEMP_PARENT) as parent:
            fixture = Fixture(Path(parent))
            (fixture.root / "unexpected-directory").mkdir(mode=0o700)
            with self.assertRaises(CHECKER.ReceiptViolation):
                fixture.receipt()

        with tempfile.TemporaryDirectory(dir=TEST_TEMP_PARENT) as parent:
            fixture = Fixture(Path(parent))
            binary = fixture.root / "binary/aster-live-event-acceptance"
            binary.unlink()
            binary.symlink_to(fixture.root / "stdout.log")
            with self.assertRaises(CHECKER.ReceiptViolation):
                fixture.receipt()

        with tempfile.TemporaryDirectory(dir=TEST_TEMP_PARENT) as parent:
            fixture = Fixture(Path(parent))
            second = fixture.root / "participants/receiver/state/mesh.redb"
            second.unlink()
            os.link(
                fixture.root / "participants/publisher/state/mesh.redb", second
            )
            with self.assertRaisesRegex(CHECKER.ReceiptViolation, "hard-link"):
                fixture.receipt()

    def test_root_directory_and_file_modes_and_owner_are_exact(self) -> None:
        self.fixture.root.chmod(0o755)
        self.assert_rejected("owner-only mode 0700")

        with tempfile.TemporaryDirectory(dir=TEST_TEMP_PARENT) as parent:
            fixture = Fixture(Path(parent))
            (fixture.root / "binary/aster-live-event-acceptance").chmod(0o600)
            with self.assertRaisesRegex(CHECKER.ReceiptViolation, "unexpected mode"):
                fixture.receipt()

        with tempfile.TemporaryDirectory(dir=TEST_TEMP_PARENT) as parent:
            fixture = Fixture(Path(parent))
            with (
                mock.patch.object(
                    CHECKER.os, "getuid", return_value=os.getuid() + 1
                ),
                self.assertRaisesRegex(CHECKER.ReceiptViolation, "not owned"),
            ):
                fixture.receipt()

    def test_secret_contents_are_metadata_only_and_do_not_change_receipt(self) -> None:
        first = self.fixture.receipt()
        identity = self.fixture.root / "participants/publisher/state/identity.key"
        identity.write_bytes(b"T" * CHECKER.IDENTITY_BYTES)
        mission = self.fixture.root / "participants/receiver/mission.bundle"
        mission.write_bytes(b"M" * mission.stat().st_size)
        store = self.fixture.root / "participants/publisher/state/mesh.redb"
        store.write_bytes(b"R" * store.stat().st_size)
        second = self.fixture.receipt()
        self.assertEqual(first, second)

    def test_checker_never_opens_secret_artifacts(self) -> None:
        original_open = os.open
        original_path_open = Path.open
        secret_names = {"mission.bundle", "identity.key", "mesh.redb", "live-acceptance-publication.redb"}
        secret_paths = {
            self.fixture.root / "participants" / participant / relative
            for participant in ("publisher", "receiver")
            for relative in (
                "mission.bundle",
                "state/identity.key",
                "state/mesh.redb",
            )
        }

        def guarded_open(path, flags, mode=0o777, *, dir_fd=None):
            if os.path.basename(os.fsdecode(path)) in secret_names:
                raise AssertionError(f"secret artifact was opened: {path}")
            if dir_fd is None:
                return original_open(path, flags, mode)
            return original_open(path, flags, mode, dir_fd=dir_fd)

        def guarded_path_open(path, *args, **kwargs):
            if path in secret_paths:
                raise AssertionError(
                    f"secret artifact was opened through pathlib: {path}"
                )
            return original_path_open(path, *args, **kwargs)

        with (
            mock.patch.object(CHECKER.os, "open", side_effect=guarded_open),
            mock.patch.object(Path, "open", new=guarded_path_open),
        ):
            self.fixture.receipt()

    def test_runner_inventory_is_metadata_only_and_has_no_secret_hashes(self) -> None:
        run_json = self.fixture.root / "run.json"
        held = self.fixture.parent / "held-run.json"
        run_json.rename(held)
        original_open = os.open
        secret_names = {"mission.bundle", "identity.key", "mesh.redb", "live-acceptance-publication.redb"}

        def guarded_open(path, flags, mode=0o777, *, dir_fd=None):
            if os.path.basename(os.fsdecode(path)) in secret_names:
                raise AssertionError(f"runner opened secret artifact: {path}")
            if dir_fd is None:
                return original_open(path, flags, mode)
            return original_open(path, flags, mode, dir_fd=dir_fd)

        try:
            with mock.patch.object(RUNNER.os, "open", side_effect=guarded_open):
                inventory, _witnesses = RUNNER.inspect_inventory(self.fixture.root)
        finally:
            held.rename(run_json)
        for record in inventory["participant_secret"]:
            self.assertEqual(
                set(record), {"path", "bytes", "mode", "hard_links", "owner"}
            )

    def test_secret_size_and_presence_are_fail_closed(self) -> None:
        identity = self.fixture.root / "participants/publisher/state/identity.key"
        identity.write_bytes(b"short")
        self.assert_rejected("identity artifact")

        with tempfile.TemporaryDirectory(dir=TEST_TEMP_PARENT) as parent:
            fixture = Fixture(Path(parent))
            (fixture.root / "participants/receiver/mission.bundle").write_bytes(b"")
            with self.assertRaisesRegex(CHECKER.ReceiptViolation, "mission artifact"):
                fixture.receipt()

        with tempfile.TemporaryDirectory(dir=TEST_TEMP_PARENT) as parent:
            fixture = Fixture(Path(parent))
            (fixture.root / "participants/receiver/state/mesh.redb").unlink()
            with self.assertRaises(CHECKER.ReceiptViolation):
                fixture.receipt()

    def test_public_file_mutation_during_validation_is_detected(self) -> None:
        original = CHECKER.validate_transcript

        def mutate(data: bytes):
            result = original(data)
            binary = self.fixture.root / "binary/aster-live-event-acceptance"
            before = binary.stat()
            binary.write_bytes(self.fixture.binary)
            binary.chmod(0o700)
            os.utime(
                binary,
                ns=(before.st_atime_ns, before.st_mtime_ns + 1_000_000_000),
            )
            return result

        with mock.patch.object(CHECKER, "validate_transcript", side_effect=mutate):
            self.assert_rejected("metadata changed during validation")

    def test_secret_replacement_during_validation_is_detected(self) -> None:
        original = CHECKER.validate_run_document

        def replace(*arguments, **keywords):
            result = original(*arguments, **keywords)
            identity = (
                self.fixture.root
                / "participants/receiver/state/identity.key"
            )
            identity.unlink()
            identity.write_bytes(self.fixture.secret)
            identity.chmod(0o600)
            return result

        with mock.patch.object(CHECKER, "validate_run_document", side_effect=replace):
            self.assert_rejected("metadata changed during validation")

    def test_run_document_artifact_source_tool_and_command_bindings_fail_closed(self) -> None:
        mutations = (
            ("binary hash", lambda d: d["artifacts"]["binary"].__setitem__("sha256", "0" * 64)),
            ("source tree", lambda d: d["source"].__setitem__("tree", "3" * 40)),
            (
                "signer",
                lambda d: d["source"]["signature"].__setitem__(
                    "fingerprint", "B" * 40
                ),
            ),
            ("tool hash", lambda d: d["tools"]["checker"].__setitem__("sha256", "0" * 64)),
            ("build argv", lambda d: d["commands"]["build_argv"].__setitem__(0, "rustc")),
            ("run argv", lambda d: d["commands"]["run_argv"].__setitem__(0, "/tmp/binary")),
            ("timeout", lambda d: d["execution"].__setitem__("timeout_seconds", 1)),
            (
                "execution link",
                lambda d: d["execution"].__setitem__(
                    "source_binary_execution_link", "proven"
                ),
            ),
        )
        for label, mutation in mutations:
            with self.subTest(label=label):
                with tempfile.TemporaryDirectory(dir=TEST_TEMP_PARENT) as parent:
                    fixture = Fixture(Path(parent))
                    mutation(fixture.run_document)
                    fixture.write_run_document()
                    with self.assertRaises(CHECKER.ReceiptViolation):
                        fixture.receipt()

    def test_run_inventory_document_is_exact_and_forbids_secret_hashes(self) -> None:
        self.fixture.run_document["inventory"]["participant_secret"][0][
            "sha256"
        ] = "0" * 64
        self.fixture.write_run_document()
        self.assert_rejected()

        with tempfile.TemporaryDirectory(dir=TEST_TEMP_PARENT) as parent:
            fixture = Fixture(Path(parent))
            fixture.run_document["inventory"]["directories"][0]["mode"] = 0o755
            fixture.write_run_document()
            with self.assertRaises(CHECKER.ReceiptViolation):
                fixture.receipt()

        with tempfile.TemporaryDirectory(dir=TEST_TEMP_PARENT) as parent:
            fixture = Fixture(Path(parent))
            fixture.run_document["inventory"]["public"][0]["hard_links"] = 2
            fixture.write_run_document()
            with self.assertRaises(CHECKER.ReceiptViolation):
                fixture.receipt()

    def test_run_document_canonicality_and_duplicate_fields_fail_closed(self) -> None:
        path = self.fixture.root / "run.json"
        document = json.loads(path.read_bytes())
        path.write_text(json.dumps(document, indent=2) + "\n", encoding="ascii")
        self.assert_rejected("compact canonical JSON")

        with tempfile.TemporaryDirectory(dir=TEST_TEMP_PARENT) as parent:
            fixture = Fixture(Path(parent))
            path = fixture.root / "run.json"
            data = path.read_bytes()
            path.write_bytes(
                data.replace(b'{"artifacts":', b'{"schema":"duplicate","artifacts":', 1)
            )
            path.chmod(0o600)
            with self.assertRaisesRegex(CHECKER.ReceiptViolation, "duplicate JSON field"):
                fixture.receipt()

    def test_signature_status_and_fingerprint_fail_closed(self) -> None:
        for malformed in (
            b"B\x00" + b"A" * 40 + b"\n",
            b"G\x00\n",
            b"G\x00" + b"a" * 40 + b"\n",
            b"G" + b"A" * 40 + b"\n",
        ):
            with self.subTest(malformed=malformed):
                with self.assertRaises(CHECKER.ReceiptViolation):
                    CHECKER.parse_signature_authority(malformed)

    def test_git_environment_injection_is_removed_and_options_are_frozen(self) -> None:
        captured: dict[str, object] = {}

        def fake_run(argv, **keywords):
            captured["argv"] = argv
            captured["env"] = keywords["env"]
            return subprocess.CompletedProcess(argv, 0, b"ok\n", b"")

        with (
            mock.patch.dict(
                os.environ,
                {
                    "GIT_DIR": "/hostile",
                    "GIT_CONFIG_GLOBAL": "/hostile/config",
                    "GIT_CONFIG_COUNT": "1",
                    "GIT_CONFIG_KEY_0": "gpg.ssh.program",
                    "GIT_CONFIG_VALUE_0": "/hostile/program",
                    "HOME": "/hostile/home",
                    "PATH": "/hostile/bin",
                    "GNUPGHOME": "/hostile/gnupg",
                },
            ),
            mock.patch.object(CHECKER.subprocess, "run", side_effect=fake_run),
        ):
            CHECKER.run_git(
                Path("/source"),
                ["rev-parse", "HEAD"],
                "test",
                git="/usr/bin/git",
                trusted_options=["-c", "gpg.format=ssh"],
            )
        environment = captured["env"]
        self.assertNotIn("GIT_DIR", environment)
        self.assertNotIn("GIT_CONFIG_COUNT", environment)
        self.assertNotIn("GNUPGHOME", environment)
        self.assertNotEqual(environment["HOME"], "/hostile/home")
        self.assertEqual(environment["GIT_CONFIG_GLOBAL"], os.devnull)
        argv = captured["argv"]
        self.assertEqual(
            argv[:4], ["/usr/bin/git", "--no-replace-objects", "-c", "gpg.format=ssh"]
        )
        self.assertIn("core.fsmonitor=false", argv)
        self.assertIn("core.hooksPath=/dev/null", argv)
        self.assertLess(argv.index("core.fsmonitor=false"), argv.index("-C"))
        self.assertEqual(environment["GIT_OPTIONAL_LOCKS"], "0")

    def test_receipt_limitations_nonclaims_and_bounded_nonobservations_are_exact(self) -> None:
        receipt = self.fixture.receipt()
        document = json.loads(receipt)
        self.assertEqual(tuple(document["limitations"]), ORACLE_LIMITATIONS)
        self.assertEqual(tuple(document["nonclaims"]), ORACLE_NONCLAIMS)
        closure = document["acceptance"]["normal_gap_closure"]
        self.assertEqual(closure["authorized_beta_query_items"], 0)
        self.assertEqual(closure["beta_delivery"], "not-observed")
        self.assertEqual(closure["post_policy_fresh_contact"], "not-observed")
        threshold = document["acceptance"]["priority_threshold_contact"]
        self.assertEqual(
            threshold["status"],
            "last_contact_complete-for-negotiated-priority-policy",
        )
        mutated = json.loads(receipt)
        mutated["limitations"][0] = "cryptographically-proven"
        with self.assertRaisesRegex(CHECKER.ReceiptViolation, "differs byte-for-byte"):
            CHECKER.validate_supplied_receipt(
                CHECKER.canonical_json_bytes(mutated), receipt
            )

    def test_supplied_receipt_rejects_mutation_noncanonicality_and_duplicates(self) -> None:
        expected = self.fixture.receipt()
        document = json.loads(expected)
        document["acceptance"]["deliveries"] = 6
        with self.assertRaisesRegex(CHECKER.ReceiptViolation, "differs byte-for-byte"):
            CHECKER.validate_supplied_receipt(
                CHECKER.canonical_json_bytes(document), expected
            )
        with self.assertRaisesRegex(CHECKER.ReceiptViolation, "compact canonical JSON"):
            CHECKER.validate_supplied_receipt(
                (json.dumps(json.loads(expected), indent=2) + "\n").encode("ascii"),
                expected,
            )
        duplicated = expected.replace(
            b'{"acceptance":', b'{"schema":"duplicate","acceptance":', 1
        )
        with self.assertRaisesRegex(CHECKER.ReceiptViolation, "duplicate JSON field"):
            CHECKER.validate_supplied_receipt(duplicated, expected)

    def test_supplied_receipt_modes_and_symlinks_fail_closed(self) -> None:
        supplied = self.fixture.parent / "supplied.json"
        receipt = self.fixture.receipt()
        supplied.write_bytes(receipt)
        for mode in (0o600, 0o644):
            with self.subTest(mode=oct(mode)):
                supplied.chmod(mode)
                self.assertEqual(CHECKER.read_supplied_receipt(supplied), receipt)
        for mode in (0o620, 0o602, 0o700, 0o611):
            with self.subTest(mode=oct(mode)):
                supplied.chmod(mode)
                with self.assertRaisesRegex(CHECKER.ReceiptViolation, "unsafe metadata"):
                    CHECKER.read_supplied_receipt(supplied)
        supplied.unlink()
        supplied.symlink_to(self.fixture.root / "run.json")
        with self.assertRaisesRegex(CHECKER.ReceiptViolation, "unsafe metadata"):
            CHECKER.read_supplied_receipt(supplied)

    def test_receipt_output_is_exclusive_exactly_named_and_owner_only(self) -> None:
        output = self.fixture.parent / CHECKER.RECEIPT_NAME
        output.write_bytes(b"preexisting\n")
        output.chmod(0o600)
        with self.assertRaisesRegex(CHECKER.ReceiptViolation, "already exists"):
            CHECKER.write_receipt(output, self.fixture.receipt())
        self.assertEqual(output.read_bytes(), b"preexisting\n")
        with self.assertRaisesRegex(CHECKER.ReceiptViolation, "exact filename"):
            CHECKER.write_receipt(
                self.fixture.parent / "wrong.json", self.fixture.receipt()
            )
        output.unlink()
        prior_umask = os.umask(0o777)
        try:
            CHECKER.write_receipt(output, self.fixture.receipt())
        finally:
            os.umask(prior_umask)
        self.assertEqual(stat.S_IMODE(output.stat().st_mode), 0o600)

    def test_receipt_output_and_supplied_path_replacement_races_are_detected(self) -> None:
        output = self.fixture.parent / CHECKER.RECEIPT_NAME
        replacement = self.fixture.parent / "replacement-output.json"
        replacement.write_bytes(b'{"status":"fail"}\n')
        replacement.chmod(0o600)
        original_fsync = os.fsync

        def replacing_fsync(descriptor: int) -> None:
            original_fsync(descriptor)
            os.replace(replacement, output)

        with (
            mock.patch.object(CHECKER.os, "fsync", side_effect=replacing_fsync),
            self.assertRaisesRegex(CHECKER.ReceiptViolation, "path identity"),
        ):
            CHECKER.write_receipt(output, self.fixture.receipt())

        supplied = self.fixture.parent / "supplied.json"
        replacement = self.fixture.parent / "replacement.json"
        supplied.write_bytes(self.fixture.receipt())
        supplied.chmod(0o600)
        replacement.write_bytes(b'{"status":"fail"}\n')
        replacement.chmod(0o600)
        original_read = os.read

        def replacing_read(descriptor: int, count: int) -> bytes:
            data = original_read(descriptor, count)
            os.replace(replacement, supplied)
            return data

        with (
            mock.patch.object(CHECKER.os, "read", side_effect=replacing_read),
            self.assertRaisesRegex(CHECKER.ReceiptViolation, "path identity"),
        ):
            CHECKER.read_supplied_receipt(supplied)

    def test_render_receipt_rejects_exact_identifiers_and_explicit_coordinate_leaks(self) -> None:
        evidence = CHECKER.validate_raw_root(self.fixture.root, self.fixture.source)
        document = CHECKER.build_receipt(self.fixture.source, evidence)
        document["build"]["executable"]["sha256"] = self.fixture.event_ids["first"]
        with self.assertRaisesRegex(CHECKER.ReceiptViolation, "parsed identifier"):
            CHECKER.render_receipt(
                document,
                forbidden_values=CHECKER.receipt_forbidden_values(
                    evidence, self.fixture.root
                ),
                forbidden_pids=CHECKER.receipt_forbidden_pids(evidence),
                forbidden_ports=CHECKER.receipt_forbidden_ports(evidence),
            )

        for label, key, value in (
            ("pid field", "pid", 4242),
            ("port field", "port", 41000),
            ("absolute path", "leak", "/private/tmp/raw"),
            ("loopback socket", "leak", "127.0.0.1:41000"),
        ):
            with self.subTest(label=label):
                document = CHECKER.build_receipt(self.fixture.source, evidence)
                document["explicit_leak"] = {key: value}
                with self.assertRaisesRegex(
                    CHECKER.ReceiptViolation,
                    "forbidden path, port, or process field",
                ):
                    CHECKER.render_receipt(
                        document,
                        forbidden_values=CHECKER.receipt_forbidden_values(
                            evidence, self.fixture.root
                        ),
                        forbidden_pids=CHECKER.receipt_forbidden_pids(evidence),
                        forbidden_ports=CHECKER.receipt_forbidden_ports(evidence),
                    )

    def test_legitimate_numeric_counts_equal_to_pid_or_port_do_not_false_reject(self) -> None:
        evidence = CHECKER.validate_raw_root(self.fixture.root, self.fixture.source)
        document = CHECKER.build_receipt(self.fixture.source, evidence)
        document["source"]["admitted"][0]["bytes"] = 4242
        document["build"]["executable"]["bytes"] = 41000
        encoded = CHECKER.render_receipt(
            document,
            forbidden_values=CHECKER.receipt_forbidden_values(
                evidence, self.fixture.root
            ),
            forbidden_pids=CHECKER.receipt_forbidden_pids(evidence),
            forbidden_ports=CHECKER.receipt_forbidden_ports(evidence),
        )
        projected = json.loads(encoded)
        self.assertEqual(projected["source"]["admitted"][0]["bytes"], 4242)
        self.assertEqual(projected["build"]["executable"]["bytes"], 41000)

    def test_numeric_substrings_in_hashes_do_not_false_reject(self) -> None:
        evidence = CHECKER.validate_raw_root(self.fixture.root, self.fixture.source)
        document = CHECKER.build_receipt(self.fixture.source, evidence)
        document["build"]["executable"]["sha256"] = "a" * 30 + "4242" + "b" * 30
        encoded = CHECKER.render_receipt(
            document,
            forbidden_values=CHECKER.receipt_forbidden_values(
                evidence, self.fixture.root
            ),
            forbidden_pids=CHECKER.receipt_forbidden_pids(evidence),
            forbidden_ports=CHECKER.receipt_forbidden_ports(evidence),
        )
        self.assertIn(b"4242", encoded)

    def test_non_ascii_source_path_is_percent_encoded_for_redaction(self) -> None:
        evidence = CHECKER.validate_raw_root(self.fixture.root, self.fixture.source)
        values = CHECKER.receipt_forbidden_values(
            evidence,
            self.fixture.root,
            Path("/private/tmp/source-caf\N{LATIN SMALL LETTER E WITH ACUTE}"),
        )
        self.assertTrue(all(value.isascii() for value in values))
        CHECKER.render_receipt(
            CHECKER.build_receipt(self.fixture.source, evidence),
            forbidden_values=values,
            forbidden_pids=CHECKER.receipt_forbidden_pids(evidence),
            forbidden_ports=CHECKER.receipt_forbidden_ports(evidence),
        )

    def test_receipt_output_cap_fails_closed(self) -> None:
        evidence = CHECKER.validate_raw_root(self.fixture.root, self.fixture.source)
        document = CHECKER.build_receipt(self.fixture.source, evidence)
        with mock.patch.object(CHECKER, "RECEIPT_MAX_BYTES", 32):
            with self.assertRaisesRegex(CHECKER.ReceiptViolation, "output cap"):
                CHECKER.render_receipt(document)

    def test_raw_root_inside_source_is_rejected_even_if_git_status_is_clean(self) -> None:
        source = self.fixture.parent / "source"
        source.mkdir(mode=0o700)

        def fake_git(_source, arguments, _label, *_args, **_kwargs):
            if arguments == ["rev-parse", "--show-toplevel"]:
                return os.fsencode(source) + b"\n"
            if arguments == ["rev-parse", "--verify", "HEAD"]:
                return b"1" * 40 + b"\n"
            if arguments[:3] == ["show", "-s", "--format=%T"]:
                return b"2" * 40 + b"\n"
            if arguments[:3] == ["show", "-s", "--format=%G?%x00%GF"]:
                return b"G\x00" + b"A" * 40 + b"\n"
            if arguments[0] == "status":
                return b""
            if arguments[0] == "verify-commit":
                return b""
            raise AssertionError(arguments)

        with (
            mock.patch.object(CHECKER, "system_executable", return_value="/usr/bin/git"),
            mock.patch.object(CHECKER, "reviewer_signature_options", return_value=[]),
            mock.patch.object(CHECKER, "run_git", side_effect=fake_git),
            self.assertRaisesRegex(
                CHECKER.ReceiptViolation, "outside the source checkout"
            ),
        ):
            CHECKER.validate_source(source, source / "ignored-raw")


if __name__ == "__main__":
    unittest.main()
