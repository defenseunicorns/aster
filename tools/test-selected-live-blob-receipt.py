#!/usr/bin/env python3
# Copyright 2026 Defense Unicorns, Inc.
# SPDX-License-Identifier: Apache-2.0
"""Independent-oracle adversarial tests for the selected live Blob receipt."""

from __future__ import annotations

import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import stat
import tempfile
import unittest
from unittest import mock


TEST_TEMP_PARENT = os.path.realpath(tempfile.gettempdir())


CHECKER_PATH = Path(__file__).with_name("check-selected-live-blob-receipt.py")
SPEC = importlib.util.spec_from_file_location("selected_live_blob_receipt", CHECKER_PATH)
if SPEC is None or SPEC.loader is None:
    raise RuntimeError(f"cannot load {CHECKER_PATH}")
CHECKER = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(CHECKER)

ORACLE_RECEIPT_SCHEMA = "aster-selected-live-blob-receipt/v2"
ORACLE_RAW_SCHEMA = "aster-selected-live-blob-raw/v2"
ORACLE_TRANSCRIPT_SCHEMA = "aster-selected-live-blob-transcript/v2"
ORACLE_CLAIM = (
    "selected-live-blob-one-host-direct-iroh-peerless-publish-seed-interrupt-"
    "reopen-different-peer-resume-read-restart-acceptance"
)
ORACLE_SUPERSEDED_SCHEMA = "aster-selected-live-blob-receipt/v1"
ORACLE_SUPERSEDED_SOURCE_COMMIT = "036d068a8d055154beeffe265ceea8cf97079fa6"
ORACLE_SUPERSEDED_RECEIPT_SHA256 = (
    "484eafe504d958881dc7b871fbf788f733d9c8814e02fc27253ece38e6169735"
)
ORACLE_BUILD_ARGV = (
    "cargo",
    "build",
    "--release",
    "--locked",
    "-p",
    "aster-node",
    "--example",
    "live_blob_acceptance",
)
ORACLE_ADMITTED_PATHS = tuple(
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
            "crates/aster-node/examples/live_blob_acceptance.rs",
            "tools/check-selected-live-blob-receipt.py",
            "tools/run-selected-live-blob.py",
            "tools/test-selected-live-blob-receipt.py",
        )
    )
)
ORACLE_LIMITATIONS = (
    "operator-attested-source-binary-execution-link-not-cryptographically-proven",
    "selected-admitted-source-list-is-not-a-complete-reproducible-build-closure",
    "one-host-loopback-same-implementation-observation",
    "participant-secret-and-ciphertext-artifacts-validated-by-metadata-only",
    "interruption-and-restart-are-graceful-same-process-actor-store-and-provider-reopen",
    (
        "intermediate-store-inspection-transcript-timing-and-source-removal-"
        "order-are-producer-attested"
    ),
)
ORACLE_NONCLAIMS = (
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
)

ORACLE_PAYLOAD_LEN = 96 * 1024
ORACLE_PAGE_LIMIT = 65_536
ORACLE_PAYLOAD_SHA256 = (
    "8609fd29a7c72634fe10beaab26ab44441a97abf85fa428cba0898c69e1ed524"
)
ORACLE_CHANGED_PAYLOAD_SHA256 = (
    "db24aedc940e3af4d8b49a44db5d486c3c6773213153e6f17e8d72151c196b82"
)
ORACLE_SCHEMA_ID_SHA256 = (
    "ff1499ba5c4448784c8b5f1137ddcc0dd85dad9e51204b9236b3759e6b9d8826"
)
ORACLE_MEDIA_TYPE = "application/x-aster-live-blob-acceptance"
ORACLE_PAGE_FACTS = (
    (
        0,
        0,
        65_536,
        65_536,
        "false",
        "1047ab624c89856e2a3c2dea5cea7a299c2d0ba0a9bcbf1cb951a6d54927239a",
    ),
    (
        1,
        65_536,
        32_768,
        98_304,
        "true",
        "256acbd5fca30ff42275d172630103a1f6f087426ead5881fe07e2a7fef2974f",
    ),
)
ORACLE_CHUNK_SIZES = (65_705, 32_937)
ORACLE_CHUNK_TOTAL = sum(ORACLE_CHUNK_SIZES)
ORACLE_TRANSFER_BYTES = 98_638
ORACLE_RANGE_BYTES = 16_384
ORACLE_PARTIAL_PREFIX = ORACLE_RANGE_BYTES
ORACLE_RESUME_PREFIX = 2 * ORACLE_RANGE_BYTES
ORACLE_FINISH_BYTES = ORACLE_TRANSFER_BYTES - ORACLE_RESUME_PREFIX
ORACLE_PARTIAL_RANGES_REMAINING = 7
ORACLE_RESUME_RANGES_REMAINING = 6
ORACLE_PREFIX_TOTAL_LEN = 65_703
ORACLE_PARTIAL_STAGING_BYTES = 28_071
ORACLE_RESUME_STAGING_BYTES = 44_455

ORACLE_RUN_KEYS = (
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
ORACLE_PARTICIPANT_KEYS = (
    "participant",
    "carrier_id",
    "mission_id",
    "mission_authority",
)
ORACLE_PEER_BINDING_KEYS = (
    "phase",
    "local",
    "remote",
    "local_carrier",
    "local_mission",
    "expected_carrier_peer",
    "expected_mission_peer",
)
ORACLE_PHASE_KEYS = (
    "sequence",
    "phase",
    "actors",
    "outcome",
)
ORACLE_HANDLE_KEYS = (
    "phase",
    "participant",
    "blob_identity",
    "blob_authority",
)
ORACLE_PUBLICATION_KEYS = (
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
ORACLE_RETRY_KEYS = (
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
ORACLE_CONFLICT_KEYS = (
    "phase",
    "participant",
    "original_id",
    "original_payload_sha256",
    "changed_payload_sha256",
    "error_kind",
    "operation",
    "publication_preserved",
)
ORACLE_PAGE_KEYS = (
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
ORACLE_READ_KEYS = (
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
ORACLE_SHUTDOWN_KEYS = (
    "phase",
    "participant",
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
ORACLE_CLOSED_HANDLE_KEYS = ("phase", "participant", "error_kind", "operation")
ORACLE_SOURCE_REMOVED_KEYS = (
    "source",
    "participant",
    "status",
    "bytes",
    "sha256",
)
ORACLE_READ_UNAVAILABLE_KEYS = (
    "phase",
    "participant",
    "error_kind",
    "operation",
    "public",
)
ORACLE_SEED_KEYS = (
    "phase",
    "source",
    "replica",
    "status",
    "data_fetched",
    "blob_ranges_fetched",
    "blob_bytes_fetched",
    "public_blobs",
)
ORACLE_PROGRESS_KEYS = (
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
ORACLE_PERSISTENCE_KEYS = (
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
ORACLE_RESUME_KEYS = (
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
ORACLE_FINISH_KEYS = (
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
ORACLE_COMPLETED_PROGRESS_KEYS = (
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
ORACLE_BIND_KEYS = ("participant", "status")
ORACLE_RESULT_KEYS = (
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
ORACLE_EXPECTED_SEQUENCE = (
    ("RUN", ORACLE_RUN_KEYS),
    ("PARTICIPANT", ORACLE_PARTICIPANT_KEYS),
    ("PARTICIPANT", ORACLE_PARTICIPANT_KEYS),
    ("PARTICIPANT", ORACLE_PARTICIPANT_KEYS),
    ("PEER_BINDING", ORACLE_PEER_BINDING_KEYS),
    ("PEER_BINDING", ORACLE_PEER_BINDING_KEYS),
    ("PEER_BINDING", ORACLE_PEER_BINDING_KEYS),
    ("PEER_BINDING", ORACLE_PEER_BINDING_KEYS),
    ("PEER_BINDING", ORACLE_PEER_BINDING_KEYS),
    ("PEER_BINDING", ORACLE_PEER_BINDING_KEYS),
    ("PHASE", ORACLE_PHASE_KEYS),
    ("HANDLE", ORACLE_HANDLE_KEYS),
    ("BLOB_PUBLICATION", ORACLE_PUBLICATION_KEYS),
    ("BLOB_RETRY", ORACLE_RETRY_KEYS),
    ("BLOB_CONFLICT", ORACLE_CONFLICT_KEYS),
    ("PAGE", ORACLE_PAGE_KEYS),
    ("PAGE", ORACLE_PAGE_KEYS),
    ("READ", ORACLE_READ_KEYS),
    ("SHUTDOWN", ORACLE_SHUTDOWN_KEYS),
    ("CLOSED_HANDLE", ORACLE_CLOSED_HANDLE_KEYS),
    ("SOURCE_REMOVED", ORACLE_SOURCE_REMOVED_KEYS),
    ("SOURCE_REMOVED", ORACLE_SOURCE_REMOVED_KEYS),
    ("PHASE", ORACLE_PHASE_KEYS),
    ("HANDLE", ORACLE_HANDLE_KEYS),
    ("HANDLE", ORACLE_HANDLE_KEYS),
    ("PAGE", ORACLE_PAGE_KEYS),
    ("PAGE", ORACLE_PAGE_KEYS),
    ("READ", ORACLE_READ_KEYS),
    ("SHUTDOWN", ORACLE_SHUTDOWN_KEYS),
    ("SHUTDOWN", ORACLE_SHUTDOWN_KEYS),
    ("CLOSED_HANDLE", ORACLE_CLOSED_HANDLE_KEYS),
    ("CLOSED_HANDLE", ORACLE_CLOSED_HANDLE_KEYS),
    ("SEED", ORACLE_SEED_KEYS),
    ("PHASE", ORACLE_PHASE_KEYS),
    ("HANDLE", ORACLE_HANDLE_KEYS),
    ("HANDLE", ORACLE_HANDLE_KEYS),
    ("READ_UNAVAILABLE", ORACLE_READ_UNAVAILABLE_KEYS),
    ("SHUTDOWN", ORACLE_SHUTDOWN_KEYS),
    ("SHUTDOWN", ORACLE_SHUTDOWN_KEYS),
    ("CLOSED_HANDLE", ORACLE_CLOSED_HANDLE_KEYS),
    ("CLOSED_HANDLE", ORACLE_CLOSED_HANDLE_KEYS),
    ("PROGRESS", ORACLE_PROGRESS_KEYS),
    ("PHASE", ORACLE_PHASE_KEYS),
    ("HANDLE", ORACLE_HANDLE_KEYS),
    ("READ_UNAVAILABLE", ORACLE_READ_UNAVAILABLE_KEYS),
    ("SHUTDOWN", ORACLE_SHUTDOWN_KEYS),
    ("CLOSED_HANDLE", ORACLE_CLOSED_HANDLE_KEYS),
    ("PROGRESS", ORACLE_PROGRESS_KEYS),
    ("PERSISTENCE", ORACLE_PERSISTENCE_KEYS),
    ("PHASE", ORACLE_PHASE_KEYS),
    ("HANDLE", ORACLE_HANDLE_KEYS),
    ("HANDLE", ORACLE_HANDLE_KEYS),
    ("SHUTDOWN", ORACLE_SHUTDOWN_KEYS),
    ("SHUTDOWN", ORACLE_SHUTDOWN_KEYS),
    ("CLOSED_HANDLE", ORACLE_CLOSED_HANDLE_KEYS),
    ("CLOSED_HANDLE", ORACLE_CLOSED_HANDLE_KEYS),
    ("PROGRESS", ORACLE_PROGRESS_KEYS),
    ("RESUME", ORACLE_RESUME_KEYS),
    ("PHASE", ORACLE_PHASE_KEYS),
    ("HANDLE", ORACLE_HANDLE_KEYS),
    ("HANDLE", ORACLE_HANDLE_KEYS),
    ("PAGE", ORACLE_PAGE_KEYS),
    ("PAGE", ORACLE_PAGE_KEYS),
    ("READ", ORACLE_READ_KEYS),
    ("SHUTDOWN", ORACLE_SHUTDOWN_KEYS),
    ("SHUTDOWN", ORACLE_SHUTDOWN_KEYS),
    ("CLOSED_HANDLE", ORACLE_CLOSED_HANDLE_KEYS),
    ("CLOSED_HANDLE", ORACLE_CLOSED_HANDLE_KEYS),
    ("FINISH", ORACLE_FINISH_KEYS),
    ("COMPLETED_PROGRESS", ORACLE_COMPLETED_PROGRESS_KEYS),
    ("PHASE", ORACLE_PHASE_KEYS),
    ("HANDLE", ORACLE_HANDLE_KEYS),
    ("PAGE", ORACLE_PAGE_KEYS),
    ("PAGE", ORACLE_PAGE_KEYS),
    ("READ", ORACLE_READ_KEYS),
    ("SHUTDOWN", ORACLE_SHUTDOWN_KEYS),
    ("CLOSED_HANDLE", ORACLE_CLOSED_HANDLE_KEYS),
    ("BIND_REACQUIRED", ORACLE_BIND_KEYS),
    ("BIND_REACQUIRED", ORACLE_BIND_KEYS),
    ("BIND_REACQUIRED", ORACLE_BIND_KEYS),
    ("RESULT", ORACLE_RESULT_KEYS),
)

ORACLE_READY_KEYS = (
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
ORACLE_CONTACT_KEYS = (
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
ORACLE_STOP_KEYS = (
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


def identifier(label: str) -> str:
    return hashlib.sha256(label.encode("ascii")).hexdigest()


def tsv(record_type: str, keys: tuple[str, ...], values: dict[str, str]) -> str:
    if set(values) != set(keys):
        raise AssertionError(f"fixture {record_type} keys differ")
    return "\t".join(
        ["LIVE_BLOB", record_type, *(f"{key}={values[key]}" for key in keys)]
    )


def terminal(prefix: str, keys: tuple[str, ...], values: dict[str, str]) -> str:
    if set(values) != set(keys):
        raise AssertionError(f"fixture {prefix} keys differ")
    return " ".join([prefix, *(f"{key}={values[key]}" for key in keys)])


PARTICIPANTS = ("publisher", "replica", "receiver")
CONNECTED_PHASES = (
    "seed_replica",
    "partial_from_publisher",
    "resume_from_replica",
    "finish_from_replica",
)
PHASE_ACTORS = {
    "peerless_publish": ("publisher",),
    "seed_replica": ("publisher", "replica"),
    "partial_from_publisher": ("publisher", "receiver"),
    "partial_receiver_reopen": ("receiver",),
    "resume_from_replica": ("replica", "receiver"),
    "finish_from_replica": ("replica", "receiver"),
    "final_receiver_reopen": ("receiver",),
}
PHASE_OUTCOMES = {
    "peerless_publish": "published-and-read",
    "seed_replica": "completed",
    "partial_from_publisher": "one-contact-interrupted",
    "partial_receiver_reopen": "pending-unchanged",
    "resume_from_replica": "one-contact-resumed",
    "finish_from_replica": "completed",
    "final_receiver_reopen": "completed-read",
}
PEER_BINDINGS = (
    ("seed_replica", "publisher", "replica"),
    ("seed_replica", "replica", "publisher"),
    ("partial_from_publisher", "publisher", "receiver"),
    ("partial_from_publisher", "receiver", "publisher"),
    ("resume_from_replica", "replica", "receiver"),
    ("resume_from_replica", "receiver", "replica"),
)


class Fixture:
    def __init__(self, parent: Path) -> None:
        self.parent = parent
        self.parent.chmod(0o700)
        self.root = parent / "raw"
        self.root.mkdir(mode=0o700)
        self.carriers = {
            participant: identifier(f"carrier-{participant}")
            for participant in PARTICIPANTS
        }
        self.missions = {
            participant: identifier(f"mission-{participant}")
            for participant in PARTICIPANTS
        }
        self.authority = identifier("mission-authority")
        self.blob_id = identifier("selected-blob")
        self.variant_id = identifier("selected-blob-variant")
        self.source_transfer_id = identifier("selected-blob-source-transfer")
        self.carrier_object_id = "02" + identifier("selected-blob-carrier-zero")
        self.partial_staging = identifier("partial-staging-fingerprint")
        self.resume_staging = identifier("resume-staging-fingerprint")
        self.binary = b"\x7fELFsynthetic-live-blob-release\n"
        self.secret = b"S" * 96
        self.phase_contacts = {
            "seed_replica": 8,
            "partial_from_publisher": 1,
            "resume_from_replica": 1,
            "finish_from_replica": 6,
        }
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
        self.runtime_positions: dict[tuple[str, str, str, int], int] = {}
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
        directories = ["binary", "participants"]
        for participant in PARTICIPANTS:
            directories.extend(
                (
                    f"participants/{participant}",
                    f"participants/{participant}/state",
                    f"participants/{participant}/state/blob-depot-v1",
                    f"participants/{participant}/state/blob-depot-v1/{self.variant_id}",
                )
            )
        for relative in directories:
            self._mkdir(relative)
        self._write("binary/aster-live-blob-acceptance", self.binary, 0o700)
        for participant in PARTICIPANTS:
            prefix = f"participants/{participant}"
            self._write(f"{prefix}/mission.bundle", b"M" * 128, 0o600)
            self._write(f"{prefix}/state/identity.key", self.secret, 0o600)
            self._write(f"{prefix}/state/mesh.redb", b"R" * 256, 0o600)
            depot = f"{prefix}/state/blob-depot-v1"
            self._write(f"{depot}/.aster-store-owner-v1", b"O" * 72, 0o600)
            for index, size in enumerate(ORACLE_CHUNK_SIZES):
                self._write(
                    f"{depot}/{self.variant_id}/{index:020}.chunk",
                    bytes([0xC0 + index]) * size,
                    0o600,
                )

    def participant(self, participant: str) -> dict[str, str]:
        return {
            "participant": participant,
            "carrier_id": self.carriers[participant],
            "mission_id": self.missions[participant],
            "mission_authority": self.authority,
        }

    def peer_binding(self, phase: str, local: str, remote: str) -> dict[str, str]:
        return {
            "phase": phase,
            "local": local,
            "remote": remote,
            "local_carrier": self.carriers[local],
            "local_mission": self.missions[local],
            "expected_carrier_peer": self.carriers[remote],
            "expected_mission_peer": self.missions[remote],
        }

    def phase(self, sequence: int, phase: str) -> dict[str, str]:
        return {
            "sequence": str(sequence),
            "phase": phase,
            "actors": "+".join(PHASE_ACTORS[phase]),
            "outcome": PHASE_OUTCOMES[phase],
        }

    def handle(self, phase: str, participant: str) -> dict[str, str]:
        return {
            "phase": phase,
            "participant": participant,
            "blob_identity": self.missions[participant],
            "blob_authority": self.authority,
        }

    def closed(self, phase: str, participant: str) -> dict[str, str]:
        return {
            "phase": phase,
            "participant": participant,
            "error_kind": "state_unavailable",
            "operation": "blob_read_page",
        }

    def unavailable(self, phase: str) -> dict[str, str]:
        return {
            "phase": phase,
            "participant": "receiver",
            "error_kind": "unauthorized_or_revoked",
            "operation": "blob_read_page",
            "public": "false",
        }

    def metadata(self) -> dict[str, str]:
        return {
            "id": self.blob_id,
            "publisher": self.missions["publisher"],
            "counter": "1",
            "priority": "priority",
            "total_len": str(ORACLE_PAYLOAD_LEN),
            "media_type": ORACLE_MEDIA_TYPE,
            "schema_id_sha256": ORACLE_SCHEMA_ID_SHA256,
            "acceptance_marker": "1",
        }

    def page(self, phase: str, participant: str, page_index: int) -> dict[str, str]:
        index, offset, length, next_offset, complete, page_hash = ORACLE_PAGE_FACTS[
            page_index
        ]
        return {
            "phase": phase,
            "participant": participant,
            "page_index": str(index),
            **self.metadata(),
            "offset": str(offset),
            "max_bytes": str(ORACLE_PAGE_LIMIT),
            "page_len": str(length),
            "next_offset": str(next_offset),
            "complete": complete,
            "page_sha256": page_hash,
        }

    def read(self, phase: str, participant: str) -> dict[str, str]:
        return {
            "phase": phase,
            "participant": participant,
            **self.metadata(),
            "pages": "2",
            "max_page_bytes": str(ORACLE_PAGE_LIMIT),
            "payload_sha256": ORACLE_PAYLOAD_SHA256,
        }

    def progress(self, phase: str) -> dict[str, str]:
        resumed = phase == "resume_from_replica"
        prefix = ORACLE_RESUME_PREFIX if resumed else ORACLE_PARTIAL_PREFIX
        staging = self.resume_staging if resumed else self.partial_staging
        staging_bytes = (
            ORACLE_RESUME_STAGING_BYTES
            if resumed
            else ORACLE_PARTIAL_STAGING_BYTES
        )
        remaining_ranges = (
            ORACLE_RESUME_RANGES_REMAINING
            if resumed
            else ORACLE_PARTIAL_RANGES_REMAINING
        )
        return {
            "phase": phase,
            "participant": "receiver",
            "source_transfer_id": self.source_transfer_id,
            "id": self.blob_id,
            "staging_sha256": staging,
            "public_blobs": "0",
            "pending_sources": "1",
            "carrier_count": "2",
            "progressed_carriers": "1",
            "carrier_prefixes": "1",
            "prefix_bytes": str(prefix),
            "prefix_object_id": self.carrier_object_id,
            "prefix_carrier_index": "0",
            "prefix_len": str(prefix),
            "prefix_total_len": str(ORACLE_PREFIX_TOTAL_LEN),
            "total_carrier_bytes": str(ORACLE_TRANSFER_BYTES),
            "remaining_bytes": str(ORACLE_TRANSFER_BYTES - prefix),
            "remaining_ranges": str(remaining_ranges),
            "next_object_id": self.carrier_object_id,
            "next_carrier_index": "0",
            "next_offset": str(prefix),
            "next_end": str(prefix + ORACLE_RANGE_BYTES),
            "network_staging_bytes": str(staging_bytes),
            "committed_chunks": "0",
            "committed_file_bytes": "0",
            "reserved_file_bytes": str(ORACLE_CHUNK_TOTAL),
            "public": "false",
        }

    def shutdown(self, phase: str, participant: str) -> dict[str, str]:
        values = {key: "0" for key in ORACLE_SHUTDOWN_KEYS}
        connected = phase in CONNECTED_PHASES
        contacts = self.phase_contacts.get(phase, 0)
        values.update(
            {
                "phase": phase,
                "participant": participant,
                "contacts": str(contacts if connected else 0),
                "direct_contacts": str(contacts if connected else 0),
            }
        )
        pending = participant == "receiver" and phase in {
            "partial_from_publisher",
            "partial_receiver_reopen",
            "resume_from_replica",
        }
        if pending:
            prefix = (
                ORACLE_RESUME_PREFIX
                if phase == "resume_from_replica"
                else ORACLE_PARTIAL_PREFIX
            )
            staging_bytes = (
                ORACLE_RESUME_STAGING_BYTES
                if phase == "resume_from_replica"
                else ORACLE_PARTIAL_STAGING_BYTES
            )
            values.update(
                {
                    "blob_variants": "1",
                    "blob_reserved_file_bytes": str(ORACLE_CHUNK_TOTAL),
                    "pending_blobs": "1",
                    "blob_carrier_prefixes": "1",
                    "blob_network_staging_bytes": str(staging_bytes),
                    "blob_carrier_fetch_cursors": (
                        "0" if phase == "partial_receiver_reopen" else "1"
                    ),
                }
            )
        else:
            values.update(
                {
                    "blobs": "1",
                    "blob_acceptance_markers": "1",
                    "blob_last_acceptance_marker": "1",
                    "blob_sealed_bytes": "11017",
                    "blob_operations": (
                        "1" if participant == "publisher" else "0"
                    ),
                    "blob_operation_bytes": (
                        "98" if participant == "publisher" else "0"
                    ),
                    "blob_variants": "1",
                    "blob_finalized_variants": "1",
                    "blob_committed_chunks": "2",
                    "blob_committed_file_bytes": str(ORACLE_CHUNK_TOTAL),
                    "blob_reserved_file_bytes": str(ORACLE_CHUNK_TOTAL),
                }
            )
        source, sink = PHASE_ACTORS[phase][0], PHASE_ACTORS[phase][-1]
        if connected and participant == source:
            offered = contacts + (1 if phase in {
                "seed_replica",
                "partial_from_publisher",
            } else 0)
            values["data_offered"] = str(offered)
        if connected and participant == sink:
            if phase in {"seed_replica", "partial_from_publisher"}:
                values["data_fetched"] = "1"
                values["data_inserted"] = "1"
            range_and_bytes = {
                "seed_replica": (8, ORACLE_TRANSFER_BYTES, 7),
                "partial_from_publisher": (
                    contacts,
                    ORACLE_RANGE_BYTES * contacts,
                    contacts,
                ),
                "resume_from_replica": (
                    contacts,
                    ORACLE_RANGE_BYTES * contacts,
                    contacts,
                ),
                "finish_from_replica": (6, ORACLE_FINISH_BYTES, 5),
            }[phase]
            values["blob_ranges_fetched"] = str(range_and_bytes[0])
            values["blob_bytes_fetched"] = str(range_and_bytes[1])
            values["blob_remaining"] = str(range_and_bytes[2])
            values["mutable_remaining"] = str(range_and_bytes[2])
        return values

    def _append_read(
        self, records: list[str], phase: str, participant: str
    ) -> None:
        records.extend(
            (
                tsv("PAGE", ORACLE_PAGE_KEYS, self.page(phase, participant, 0)),
                tsv("PAGE", ORACLE_PAGE_KEYS, self.page(phase, participant, 1)),
                tsv("READ", ORACLE_READ_KEYS, self.read(phase, participant)),
            )
        )

    def _append_shutdowns(
        self, records: list[str], phase: str, participants: tuple[str, ...]
    ) -> None:
        for participant in participants:
            records.append(
                tsv(
                    "SHUTDOWN",
                    ORACLE_SHUTDOWN_KEYS,
                    self.shutdown(phase, participant),
                )
            )
        for participant in participants:
            records.append(
                tsv(
                    "CLOSED_HANDLE",
                    ORACLE_CLOSED_HANDLE_KEYS,
                    self.closed(phase, participant),
                )
            )

    def _transcript_lines(self) -> list[str]:
        records = [
            tsv(
                "RUN",
                ORACLE_RUN_KEYS,
                {
                    "schema": ORACLE_TRANSCRIPT_SCHEMA,
                    "claim": ORACLE_CLAIM,
                    "participants": "3",
                    "actor_lifetimes": "11",
                    "maximum_concurrent_actors": "2",
                    "topic": "opaque",
                    "scope": "test/runtime-contact",
                    "payload_len": str(ORACLE_PAYLOAD_LEN),
                    "payload_sha256": ORACLE_PAYLOAD_SHA256,
                    "page_limit": str(ORACLE_PAGE_LIMIT),
                    "expected_pages": "2",
                },
            )
        ]
        records.extend(
            tsv("PARTICIPANT", ORACLE_PARTICIPANT_KEYS, self.participant(name))
            for name in PARTICIPANTS
        )
        records.extend(
            tsv(
                "PEER_BINDING",
                ORACLE_PEER_BINDING_KEYS,
                self.peer_binding(phase, local, remote),
            )
            for phase, local, remote in PEER_BINDINGS
        )

        records.append(tsv("PHASE", ORACLE_PHASE_KEYS, self.phase(1, "peerless_publish")))
        records.append(
            tsv(
                "HANDLE",
                ORACLE_HANDLE_KEYS,
                self.handle("peerless_publish", "publisher"),
            )
        )
        records.append(
            tsv(
                "BLOB_PUBLICATION",
                ORACLE_PUBLICATION_KEYS,
                {
                    "phase": "peerless_publish",
                    "participant": "publisher",
                    **self.metadata(),
                    "inserted": "true",
                    "payload_sha256": ORACLE_PAYLOAD_SHA256,
                },
            )
        )
        records.append(
            tsv(
                "BLOB_RETRY",
                ORACLE_RETRY_KEYS,
                {
                    "phase": "peerless_publish",
                    "participant": "publisher",
                    "original_id": self.blob_id,
                    "retry_id": self.blob_id,
                    **{
                        key: value
                        for key, value in self.metadata().items()
                        if key != "id"
                    },
                    "inserted": "false",
                    "exact_match": "true",
                },
            )
        )
        records.append(
            tsv(
                "BLOB_CONFLICT",
                ORACLE_CONFLICT_KEYS,
                {
                    "phase": "peerless_publish",
                    "participant": "publisher",
                    "original_id": self.blob_id,
                    "original_payload_sha256": ORACLE_PAYLOAD_SHA256,
                    "changed_payload_sha256": ORACLE_CHANGED_PAYLOAD_SHA256,
                    "error_kind": "conflict",
                    "operation": "blob_publish",
                    "publication_preserved": "true",
                },
            )
        )
        self._append_read(records, "peerless_publish", "publisher")
        self._append_shutdowns(records, "peerless_publish", ("publisher",))
        for source, digest in (
            ("original", ORACLE_PAYLOAD_SHA256),
            ("conflict-probe", ORACLE_CHANGED_PAYLOAD_SHA256),
        ):
            records.append(
                tsv(
                    "SOURCE_REMOVED",
                    ORACLE_SOURCE_REMOVED_KEYS,
                    {
                        "source": source,
                        "participant": "publisher",
                        "status": "removed-and-parent-synced",
                        "bytes": str(ORACLE_PAYLOAD_LEN),
                        "sha256": digest,
                    },
                )
            )

        records.append(tsv("PHASE", ORACLE_PHASE_KEYS, self.phase(2, "seed_replica")))
        for participant in PHASE_ACTORS["seed_replica"]:
            records.append(
                tsv(
                    "HANDLE",
                    ORACLE_HANDLE_KEYS,
                    self.handle("seed_replica", participant),
                )
            )
        self._append_read(records, "seed_replica", "replica")
        self._append_shutdowns(records, "seed_replica", PHASE_ACTORS["seed_replica"])
        seed_receiver = self.shutdown("seed_replica", "replica")
        records.append(
            tsv(
                "SEED",
                ORACLE_SEED_KEYS,
                {
                    "phase": "seed_replica",
                    "source": "publisher",
                    "replica": "replica",
                    "status": "completed",
                    "data_fetched": seed_receiver["data_fetched"],
                    "blob_ranges_fetched": seed_receiver["blob_ranges_fetched"],
                    "blob_bytes_fetched": seed_receiver["blob_bytes_fetched"],
                    "public_blobs": seed_receiver["blobs"],
                },
            )
        )

        records.append(tsv("PHASE", ORACLE_PHASE_KEYS, self.phase(3, "partial_from_publisher")))
        for participant in PHASE_ACTORS["partial_from_publisher"]:
            records.append(
                tsv(
                    "HANDLE",
                    ORACLE_HANDLE_KEYS,
                    self.handle("partial_from_publisher", participant),
                )
            )
        records.append(
            tsv(
                "READ_UNAVAILABLE",
                ORACLE_READ_UNAVAILABLE_KEYS,
                self.unavailable("partial_from_publisher"),
            )
        )
        self._append_shutdowns(
            records,
            "partial_from_publisher",
            PHASE_ACTORS["partial_from_publisher"],
        )
        records.append(
            tsv(
                "PROGRESS",
                ORACLE_PROGRESS_KEYS,
                self.progress("partial_from_publisher"),
            )
        )

        records.append(tsv("PHASE", ORACLE_PHASE_KEYS, self.phase(4, "partial_receiver_reopen")))
        records.append(
            tsv(
                "HANDLE",
                ORACLE_HANDLE_KEYS,
                self.handle("partial_receiver_reopen", "receiver"),
            )
        )
        records.append(
            tsv(
                "READ_UNAVAILABLE",
                ORACLE_READ_UNAVAILABLE_KEYS,
                self.unavailable("partial_receiver_reopen"),
            )
        )
        self._append_shutdowns(records, "partial_receiver_reopen", ("receiver",))
        records.append(
            tsv(
                "PROGRESS",
                ORACLE_PROGRESS_KEYS,
                self.progress("partial_receiver_reopen"),
            )
        )
        records.append(
            tsv(
                "PERSISTENCE",
                ORACLE_PERSISTENCE_KEYS,
                {
                    "phase": "partial_receiver_reopen",
                    "participant": "receiver",
                    "source_transfer_id": self.source_transfer_id,
                    "staging_before_sha256": self.partial_staging,
                    "staging_after_sha256": self.partial_staging,
                    "prefix_before": str(ORACLE_PARTIAL_PREFIX),
                    "prefix_after": str(ORACLE_PARTIAL_PREFIX),
                    "prefix_object_id": self.carrier_object_id,
                    "prefix_total_len": str(ORACLE_PREFIX_TOTAL_LEN),
                    "exact_match": "true",
                    "public": "false",
                },
            )
        )

        records.append(tsv("PHASE", ORACLE_PHASE_KEYS, self.phase(5, "resume_from_replica")))
        for participant in PHASE_ACTORS["resume_from_replica"]:
            records.append(
                tsv(
                    "HANDLE",
                    ORACLE_HANDLE_KEYS,
                    self.handle("resume_from_replica", participant),
                )
            )
        self._append_shutdowns(records, "resume_from_replica", PHASE_ACTORS["resume_from_replica"])
        records.append(tsv("PROGRESS", ORACLE_PROGRESS_KEYS, self.progress("resume_from_replica")))
        resume_receiver = self.shutdown("resume_from_replica", "receiver")
        records.append(
            tsv(
                "RESUME",
                ORACLE_RESUME_KEYS,
                {
                    "phase": "resume_from_replica",
                    "source": "replica",
                    "receiver": "receiver",
                    "original_source": "publisher",
                    "source_transfer_id": self.source_transfer_id,
                    "different_peer": "true",
                    "source_refetched": "false",
                    "exact_complement": "true",
                    "contacts": resume_receiver["contacts"],
                    "data_fetched": resume_receiver["data_fetched"],
                    "blob_ranges_fetched": resume_receiver["blob_ranges_fetched"],
                    "blob_bytes_fetched": resume_receiver["blob_bytes_fetched"],
                    "prefix_before": str(ORACLE_PARTIAL_PREFIX),
                    "prefix_after": str(ORACLE_RESUME_PREFIX),
                    "prefix_object_id": self.carrier_object_id,
                    "prefix_total_len": str(ORACLE_PREFIX_TOTAL_LEN),
                    "remaining_before": str(ORACLE_TRANSFER_BYTES - ORACLE_PARTIAL_PREFIX),
                    "remaining_after": str(ORACLE_TRANSFER_BYTES - ORACLE_RESUME_PREFIX),
                    "public": "false",
                },
            )
        )

        records.append(tsv("PHASE", ORACLE_PHASE_KEYS, self.phase(6, "finish_from_replica")))
        for participant in PHASE_ACTORS["finish_from_replica"]:
            records.append(
                tsv(
                    "HANDLE",
                    ORACLE_HANDLE_KEYS,
                    self.handle("finish_from_replica", participant),
                )
            )
        self._append_read(records, "finish_from_replica", "receiver")
        self._append_shutdowns(records, "finish_from_replica", PHASE_ACTORS["finish_from_replica"])
        finish_receiver = self.shutdown("finish_from_replica", "receiver")
        records.append(
            tsv(
                "FINISH",
                ORACLE_FINISH_KEYS,
                {
                    "phase": "finish_from_replica",
                    "source": "replica",
                    "receiver": "receiver",
                    "source_refetched": "false",
                    "data_fetched": finish_receiver["data_fetched"],
                    "blob_ranges_fetched": finish_receiver["blob_ranges_fetched"],
                    "blob_bytes_fetched": finish_receiver["blob_bytes_fetched"],
                    "reconstructed_transfer_bytes": str(ORACLE_TRANSFER_BYTES),
                    "seed_transfer_bytes": str(ORACLE_TRANSFER_BYTES),
                    "promoted": "true",
                },
            )
        )
        records.append(
            tsv(
                "COMPLETED_PROGRESS",
                ORACLE_COMPLETED_PROGRESS_KEYS,
                {
                    "phase": "finish_from_replica",
                    "participant": "receiver",
                    "source_transfer_id": self.source_transfer_id,
                    "id": self.blob_id,
                    "public_blobs": "1",
                    "pending_sources": "0",
                    "carrier_prefixes": "0",
                    "network_staging_bytes": "0",
                    "public": "true",
                },
            )
        )

        records.append(tsv("PHASE", ORACLE_PHASE_KEYS, self.phase(7, "final_receiver_reopen")))
        records.append(
            tsv(
                "HANDLE",
                ORACLE_HANDLE_KEYS,
                self.handle("final_receiver_reopen", "receiver"),
            )
        )
        self._append_read(records, "final_receiver_reopen", "receiver")
        self._append_shutdowns(records, "final_receiver_reopen", ("receiver",))
        records.extend(
            tsv(
                "BIND_REACQUIRED",
                ORACLE_BIND_KEYS,
                {"participant": participant, "status": "reacquired"},
            )
            for participant in PARTICIPANTS
        )
        records.append(
            tsv(
                "RESULT",
                ORACLE_RESULT_KEYS,
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
            )
        )
        if len(records) != 81:
            raise AssertionError(f"fixture transcript has {len(records)}, expected 81")
        return records

    def ready(self, participant: str, phase: str, port: int) -> str:
        return terminal(
            "READY",
            ORACLE_READY_KEYS,
            {
                "selected": "true",
                "pid": "4242",
                "carrier_id": self.carriers[participant],
                "mission_id": self.missions[participant],
                "mission_authority": self.authority,
                "sockets": f"127.0.0.1:{port}",
                "state": CHECKER.encoded_path(
                    self.root / "participants" / participant / "state"
                ),
                "peers": "1" if phase in CONNECTED_PHASES else "0",
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
        phase: str,
        local: str,
        remote: str,
        pair_index: int,
    ) -> str:
        numeric = {
            key: "0"
            for key in ORACLE_CONTACT_KEYS[3:26] + ORACLE_CONTACT_KEYS[27:28]
        }
        numeric.update(
            {
                "rounds": "1",
                "handshake_frames": "2",
                "handshake_bytes": "128",
                "protected_frames": "2",
                "protected_bytes": "128",
            }
        )
        source, sink = PHASE_ACTORS[phase][0], PHASE_ACTORS[phase][-1]
        if local == source:
            numeric["offered"] = (
                "2"
                if pair_index == 0
                and phase in {"seed_replica", "partial_from_publisher"}
                else "1"
            )
        if local == sink:
            if pair_index == 0 and phase in {
                "seed_replica",
                "partial_from_publisher",
            }:
                numeric["fetched"] = "1"
                numeric["inserted"] = "1"
            transfer_ranges = {
                "seed_replica": (
                    16_384,
                    16_384,
                    16_384,
                    16_384,
                    167,
                    16_384,
                    16_384,
                    167,
                ),
                "partial_from_publisher": (ORACLE_RANGE_BYTES,)
                * self.phase_contacts[phase],
                "resume_from_replica": (ORACLE_RANGE_BYTES,)
                * self.phase_contacts[phase],
                "finish_from_replica": (
                    16_384,
                    16_384,
                    167,
                    16_384,
                    16_384,
                    167,
                ),
            }[phase]
            if pair_index < len(transfer_ranges):
                remaining = (
                    1
                    if phase
                    in {"partial_from_publisher", "resume_from_replica"}
                    else int(pair_index + 1 < len(transfer_ranges))
                )
                numeric["mutable_remaining"] = str(remaining)
                numeric["blob_ranges_fetched"] = "1"
                numeric["blob_bytes_fetched"] = str(
                    transfer_ranges[pair_index]
                )
                numeric["blob_remaining"] = str(remaining)
        direction = (
            "out" if self.carriers[local] < self.carriers[remote] else "in"
        )
        return terminal(
            "CONTACT",
            ORACLE_CONTACT_KEYS,
            {
                "direction": direction,
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
                "status": (
                    "partial"
                    if numeric["mutable_remaining"] != "0"
                    or numeric["blob_remaining"] != "0"
                    else "pass"
                ),
            },
        )

    def stop(self, participant: str, phase: str) -> str:
        shutdown = self.shutdown(phase, participant)
        return terminal(
            "STOP",
            ORACLE_STOP_KEYS,
            {
                "lifecycle": "complete",
                "sync_status": (
                    "contacts_observed"
                    if phase in CONNECTED_PHASES
                    else "no_successful_contact"
                ),
                "carrier_id": self.carriers[participant],
                "mission_id": self.missions[participant],
                "contacts": shutdown["contacts"],
                "contact_errors": shutdown["contact_errors"],
                "direct_contacts": shutdown["direct_contacts"],
                "relay_contacts": shutdown["relay_contacts"],
                "unknown_path_contacts": shutdown["unknown_path_contacts"],
                "carrier_path_transitions": shutdown["carrier_path_transitions"],
                "carrier_path_transition_saturations": shutdown[
                    "carrier_path_transition_saturations"
                ],
                "path_observation": "not-authorization",
                "opaque_items": shutdown["items"],
                "opaque_acceptance_markers": shutdown["acceptance_markers"],
                "events": shutdown["events"],
                "event_acceptance_markers": shutdown["event_acceptance_markers"],
                "route_cached_events": shutdown["route_cached_events"],
                "controls": shutdown["controls"],
                "applied_controls": shutdown["applied_controls"],
                "pending_controls": shutdown["pending_controls"],
                "control_highwater": shutdown["control_highwater"],
                "blobs": shutdown["blobs"],
                "blob_acceptance_markers": shutdown["blob_acceptance_markers"],
                "blob_last_acceptance_marker": shutdown[
                    "blob_last_acceptance_marker"
                ],
                "blob_sealed_bytes": shutdown["blob_sealed_bytes"],
                "blob_operations": shutdown["blob_operations"],
                "blob_operation_bytes": shutdown["blob_operation_bytes"],
                "blob_variants": shutdown["blob_variants"],
                "blob_finalized_variants": shutdown["blob_finalized_variants"],
                "blob_committed_chunks": shutdown["blob_committed_chunks"],
                "blob_committed_file_bytes": shutdown[
                    "blob_committed_file_bytes"
                ],
                "blob_reserved_file_bytes": shutdown[
                    "blob_reserved_file_bytes"
                ],
                "pending_blobs": shutdown["pending_blobs"],
                "blob_carrier_prefixes": shutdown["blob_carrier_prefixes"],
                "blob_carrier_fetch_cursors": shutdown[
                    "blob_carrier_fetch_cursors"
                ],
                "blob_network_staging_bytes": shutdown[
                    "blob_network_staging_bytes"
                ],
                "blob_ranges_fetched": shutdown["blob_ranges_fetched"],
                "blob_bytes_fetched": shutdown["blob_bytes_fetched"],
                "blob_remaining": shutdown["blob_remaining"],
                "blob_deferred": shutdown["blob_deferred"],
                "mission_auth": "hybrid-pq",
                "provisioning": "unprotected-reference",
                "semantics": "source-authenticated-event",
                "reconciliation_classes": "event,state,record,blob-v5",
                "controls_semantics": "source-authenticated-flash",
            },
        )

    def _runtime_lines(self) -> list[str]:
        lines: list[str] = []
        positions: dict[tuple[str, str, str, int], int] = {}
        connected_ports = {
            "publisher": 40_000,
            "replica": 40_001,
            "receiver": 40_002,
        }
        peerless_port = 41_000

        def append(
            phase: str,
            kind: str,
            participant: str,
            record: str,
            occurrence: int = 0,
        ) -> None:
            positions[(phase, kind, participant, occurrence)] = len(lines)
            lines.append(record)

        for phase, actors in PHASE_ACTORS.items():
            for participant in actors:
                port = (
                    connected_ports[participant]
                    if phase in CONNECTED_PHASES
                    else peerless_port
                )
                append(
                    phase,
                    "READY",
                    participant,
                    self.ready(participant, phase, port),
                )
                if phase not in CONNECTED_PHASES:
                    peerless_port += 1
            if phase in CONNECTED_PHASES:
                source, sink = actors
                for pair_index in range(self.phase_contacts[phase]):
                    append(
                        phase,
                        "CONTACT",
                        source,
                        self.contact(phase, source, sink, pair_index),
                        pair_index,
                    )
                    append(
                        phase,
                        "CONTACT",
                        sink,
                        self.contact(phase, sink, source, pair_index),
                        pair_index,
                    )
            for participant in actors:
                append(
                    phase,
                    "STOP",
                    participant,
                    self.stop(participant, phase),
                )
        self.runtime_positions = positions
        return lines

    def set_phase_contact_pairs(self, phase: str, pairs: int) -> None:
        if phase not in CONNECTED_PHASES or pairs <= 0:
            raise AssertionError("fixture requires a connected phase and positive pairs")
        self.phase_contacts[phase] = pairs
        self.transcript_lines = self._transcript_lines()
        self.runtime_lines = self._runtime_lines()
        self.refresh_public()

    def runtime_index(
        self,
        phase: str,
        kind: str,
        participant: str,
        occurrence: int = 0,
    ) -> int:
        return self.runtime_positions[(phase, kind, participant, occurrence)]

    def record_index(
        self,
        record_type: str,
        *,
        phase: str | None = None,
        participant: str | None = None,
        occurrence: int = 0,
    ) -> int:
        matches: list[int] = []
        for index, line in enumerate(self.transcript_lines):
            parts = line.split("\t")
            if len(parts) < 2 or parts[1] != record_type:
                continue
            fields = dict(token.split("=", 1) for token in parts[2:])
            if phase is not None and fields.get("phase") != phase:
                continue
            if participant is not None and fields.get("participant") != participant:
                continue
            matches.append(index)
        try:
            return matches[occurrence]
        except IndexError as error:
            raise AssertionError(
                f"missing {record_type} fixture record {phase} {participant}"
            ) from error

    @staticmethod
    def _artifact(relative: str, data: bytes) -> dict[str, object]:
        return {
            "path": relative,
            "bytes": len(data),
            "sha256": hashlib.sha256(data).hexdigest(),
        }

    def refresh_public(self) -> None:
        transcript = ("\n".join(self.transcript_lines) + "\n").encode("ascii")
        stdout = (
            "\n".join([*self.runtime_lines, *self.transcript_lines]) + "\n"
        ).encode("ascii")
        self._write("transcript.tsv", transcript, 0o600)
        self._write("stdout.log", stdout, 0o600)
        self._write("stderr.log", b"", 0o600)
        admitted = [
            {"path": path, **self.source["admitted"][path]}
            for path in ORACLE_ADMITTED_PATHS
        ]
        tools = {
            role: {"path": path, **self.source["admitted"][path]}
            for role, path in {
                "producer": "crates/aster-node/examples/live_blob_acceptance.rs",
                "runner": "tools/run-selected-live-blob.py",
                "checker": "tools/check-selected-live-blob-receipt.py",
                "test": "tools/test-selected-live-blob-receipt.py",
            }.items()
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
                        self.root / "binary" / "aster-live-blob-acceptance"
                    ),
                    os.fspath(self.root),
                ],
            },
            "execution": {
                "exit_code": 0,
                "worktree_clean_at_run": True,
                "source_binary_execution_link": (
                    "operator-attested-not-cryptographically-proven"
                ),
            },
            "artifacts": {
                "binary": self._artifact(
                    "binary/aster-live-blob-acceptance", self.binary
                ),
                "stdout": self._artifact("stdout.log", stdout),
                "stderr": self._artifact("stderr.log", b""),
                "transcript": self._artifact("transcript.tsv", transcript),
            },
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
        parts = self.runtime_lines[index].split(" ")
        for position in range(1, len(parts)):
            field, separator, _old = parts[position].partition("=")
            if separator and field == key:
                parts[position] = f"{field}={value}"
                self.runtime_lines[index] = " ".join(parts)
                self.refresh_public()
                return
        raise AssertionError(f"missing runtime fixture field {key}")

    def evidence(self) -> dict[str, object]:
        return CHECKER.validate_raw_root(self.root, self.source)

    def receipt_document(self) -> tuple[dict[str, object], dict[str, object]]:
        evidence = self.evidence()
        return CHECKER.build_receipt(self.source, evidence), evidence

    def receipt(self) -> bytes:
        document, evidence = self.receipt_document()
        return CHECKER.render_receipt(
            document,
            forbidden_values=CHECKER.receipt_forbidden_values(evidence, self.root),
            forbidden_pids=CHECKER.receipt_forbidden_pids(evidence),
            forbidden_ports=CHECKER.receipt_forbidden_ports(evidence),
        )


class SelectedLiveBlobReceiptTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory(dir=TEST_TEMP_PARENT)
        self.fixture = Fixture(Path(self.temporary.name))

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def assert_rejected(self, pattern: str = ".+") -> None:
        with self.assertRaisesRegex(CHECKER.ReceiptViolation, pattern):
            self.fixture.receipt()


    def test_valid_projection_is_deterministic_bounded_and_sanitized(self) -> None:
        first = self.fixture.receipt()
        second = self.fixture.receipt()
        self.assertEqual(first, second)
        self.assertLessEqual(len(first), 16 * 1024)
        parsed = json.loads(first)
        self.assertEqual(parsed["schema"], ORACLE_RECEIPT_SCHEMA)
        self.assertEqual(parsed["claim"], ORACLE_CLAIM)
        self.assertEqual(parsed["status"], "pass")
        self.assertEqual(parsed["acceptance"]["participants"], 3)
        self.assertEqual(parsed["acceptance"]["actor_lifetimes"], 11)
        self.assertEqual(parsed["acceptance"]["phases"], 7)
        self.assertEqual(parsed["retention"]["identity_keys"], 3)
        self.assertEqual(parsed["retention"]["mesh_databases"], 3)
        self.assertEqual(parsed["retention"]["participant_directories"], 3)
        self.assertEqual(
            parsed["acceptance"]["connected_reconciliation"][
                "partial_and_resume_contact_pairs"
            ],
            "exactly-one-each",
        )
        self.assertEqual(tuple(parsed["limitations"]), ORACLE_LIMITATIONS)
        self.assertEqual(tuple(parsed["nonclaims"]), ORACLE_NONCLAIMS)
        # Exact paths and identifiers are safe whole-document canaries. The
        # short PID is checked as an exact scalar by render_receipt because its
        # digits may legitimately occur inside counts or cryptographic digests.
        for forbidden in (
            os.fsencode(self.fixture.root),
            self.fixture.carriers["publisher"].encode("ascii"),
            self.fixture.carriers["replica"].encode("ascii"),
            self.fixture.missions["receiver"].encode("ascii"),
            self.fixture.blob_id.encode("ascii"),
            self.fixture.source_transfer_id.encode("ascii"),
            self.fixture.partial_staging.encode("ascii"),
            self.fixture.variant_id.encode("ascii"),
            b"127.0.0.1",
            self.fixture.secret,
        ):
            self.assertNotIn(forbidden, first)

    def test_projection_supersedes_only_the_exact_v1_receipt(self) -> None:
        parsed = json.loads(self.fixture.receipt())
        self.assertEqual(
            parsed["supersedes"],
            {
                "schema": ORACLE_SUPERSEDED_SCHEMA,
                "source_commit": ORACLE_SUPERSEDED_SOURCE_COMMIT,
                "receipt_sha256": ORACLE_SUPERSEDED_RECEIPT_SHA256,
            },
        )
        receipt = self.fixture.receipt()
        mutated = json.loads(receipt)
        mutated["supersedes"]["receipt_sha256"] = "0" * 64
        with self.assertRaisesRegex(CHECKER.ReceiptViolation, "byte-for-byte"):
            CHECKER.validate_supplied_receipt(
                CHECKER.canonical_json_bytes(mutated), receipt
            )

    def test_supplied_receipt_replay_is_byte_exact(self) -> None:
        receipt = self.fixture.receipt()
        CHECKER.validate_supplied_receipt(receipt, receipt)
        supplied = self.fixture.parent / "supplied.json"
        supplied.write_bytes(receipt)
        for mode in (0o600, 0o644):
            supplied.chmod(mode)
            self.assertEqual(CHECKER.read_supplied_receipt(supplied), receipt)
        mutated = json.loads(receipt)
        mutated["status"] = "fail"
        with self.assertRaisesRegex(CHECKER.ReceiptViolation, "byte-for-byte"):
            CHECKER.validate_supplied_receipt(
                CHECKER.canonical_json_bytes(mutated), receipt
            )

    def test_every_record_type_and_key_order_is_exact(self) -> None:
        for index, ((record_type, keys), line) in enumerate(
            zip(ORACLE_EXPECTED_SEQUENCE, self.fixture.transcript_lines, strict=True)
        ):
            with self.subTest(index=index, record_type=record_type):
                parsed = CHECKER.parse_record(line, record_type, keys, index)
                self.assertEqual(tuple(parsed), keys)
                parts = line.split("\t")
                parts[2], parts[3] = parts[3], parts[2]
                with self.assertRaisesRegex(
                    CHECKER.ReceiptViolation, "reordered fields"
                ):
                    CHECKER.parse_record(
                        "\t".join(parts), record_type, keys, index
                    )

    def test_transcript_order_and_exact_81_record_count_fail_closed(self) -> None:
        self.fixture.transcript_lines.pop()
        self.fixture.refresh_public()
        self.assert_rejected("exactly 81 records")

    def test_v1_raw_and_transcript_schemas_are_rejected(self) -> None:
        with tempfile.TemporaryDirectory(dir=TEST_TEMP_PARENT) as temporary:
            fixture = Fixture(Path(temporary))
            fixture.run_document["schema"] = "aster-selected-live-blob-raw/v1"
            fixture.write_run_document()
            with self.assertRaisesRegex(CHECKER.ReceiptViolation, "run.schema"):
                fixture.receipt()
        with tempfile.TemporaryDirectory(dir=TEST_TEMP_PARENT) as temporary:
            fixture = Fixture(Path(temporary))
            fixture.mutate_transcript(
                0, "schema", "aster-selected-live-blob-transcript/v1"
            )
            with self.assertRaisesRegex(CHECKER.ReceiptViolation, "RUN.schema"):
                fixture.receipt()

    def test_participant_identity_domains_are_disjoint(self) -> None:
        replica = self.fixture.record_index(
            "PARTICIPANT", participant="replica"
        )
        self.fixture.mutate_transcript(
            replica, "mission_id", self.fixture.carriers["publisher"]
        )
        self.assert_rejected("identity domains overlap")

    def test_peer_binding_missing_duplicate_self_and_wrong_edges_fail_closed(self) -> None:
        cases = ("missing", "duplicate", "self", "wrong")
        for case in cases:
            with self.subTest(case=case):
                with tempfile.TemporaryDirectory(dir=TEST_TEMP_PARENT) as temporary:
                    fixture = Fixture(Path(temporary))
                    if case == "missing":
                        fixture.transcript_lines.pop(9)
                        fixture.refresh_public()
                    elif case == "duplicate":
                        fixture.transcript_lines[9] = fixture.transcript_lines[4]
                        fixture.refresh_public()
                    elif case == "self":
                        fixture.mutate_transcript(4, "remote", "publisher")
                    else:
                        fixture.mutate_transcript(
                            4,
                            "expected_carrier_peer",
                            fixture.carriers["receiver"],
                        )
                    with self.assertRaises(CHECKER.ReceiptViolation):
                        fixture.receipt()

    def test_phase_reorder_and_runtime_wrong_remote_fail_closed(self) -> None:
        with tempfile.TemporaryDirectory(dir=TEST_TEMP_PARENT) as temporary:
            fixture = Fixture(Path(temporary))
            fixture.transcript_lines[22], fixture.transcript_lines[33] = (
                fixture.transcript_lines[33],
                fixture.transcript_lines[22],
            )
            fixture.refresh_public()
            with self.assertRaisesRegex(CHECKER.ReceiptViolation, "PHASE"):
                fixture.receipt()
        with tempfile.TemporaryDirectory(dir=TEST_TEMP_PARENT) as temporary:
            fixture = Fixture(Path(temporary))
            index = fixture.runtime_index(
                "seed_replica", "CONTACT", "publisher"
            )
            fixture.mutate_runtime(
                index, "carrier_peer", fixture.carriers["receiver"]
            )
            fixture.mutate_runtime(
                index, "mission_peer", fixture.missions["receiver"]
            )
            with self.assertRaises(CHECKER.ReceiptViolation):
                fixture.receipt()

    def test_partial_phase_requires_exactly_one_reciprocal_contact_pair(self) -> None:
        self.fixture.set_phase_contact_pairs("partial_from_publisher", 2)
        self.assert_rejected("exact one-contact|exactly one")

    def test_partial_blob_cannot_be_accidentally_complete_or_public(self) -> None:
        index = self.fixture.record_index(
            "SHUTDOWN",
            phase="partial_from_publisher",
            participant="receiver",
        )
        self.fixture.mutate_transcript(index, "blobs", "1")
        self.assert_rejected("incomplete Blob")

    def test_partial_and_reopen_reads_are_typed_unavailable(self) -> None:
        index = self.fixture.record_index(
            "READ_UNAVAILABLE", phase="partial_from_publisher"
        )
        self.fixture.mutate_transcript(index, "public", "true")
        self.assert_rejected("READ_UNAVAILABLE")

    def test_peerless_reopen_rejects_progress_drift(self) -> None:
        index = self.fixture.record_index(
            "PROGRESS", phase="partial_receiver_reopen"
        )
        self.fixture.mutate_transcript(
            index, "staging_sha256", identifier("drifted-staging")
        )
        self.assert_rejected("changed across peerless reopen|PERSISTENCE")

    def test_peerless_reopen_rejects_any_contact(self) -> None:
        phase = "partial_receiver_reopen"
        stop_index = self.fixture.runtime_index(phase, "STOP", "receiver")
        contact = self.fixture.contact(
            "partial_from_publisher", "receiver", "publisher", 0
        )
        self.fixture.runtime_lines.insert(stop_index, contact)
        self.fixture.refresh_public()
        self.assert_rejected("outside one exact active paired phase")

    def test_resume_requires_replica_not_original_publisher(self) -> None:
        index = self.fixture.record_index("RESUME", phase="resume_from_replica")
        self.fixture.mutate_transcript(index, "source", "publisher")
        self.assert_rejected("RESUME.source")

    def test_resume_must_not_refetch_the_staged_blob_source(self) -> None:
        index = self.fixture.record_index("RESUME", phase="resume_from_replica")
        self.fixture.mutate_transcript(index, "source_refetched", "true")
        self.assert_rejected("RESUME.source_refetched")

    def test_resume_data_aggregate_must_prove_zero_source_fetch(self) -> None:
        index = self.fixture.record_index(
            "SHUTDOWN",
            phase="resume_from_replica",
            participant="receiver",
        )
        self.fixture.mutate_transcript(index, "data_fetched", "1")
        self.assert_rejected("receiving-side|aggregate")

    def test_resume_prefix_overlap_and_gap_fail_closed(self) -> None:
        cases = (
            str(ORACLE_PARTIAL_PREFIX),
            str(ORACLE_RESUME_PREFIX + 1),
        )
        for prefix_after in cases:
            with self.subTest(prefix_after=prefix_after):
                with tempfile.TemporaryDirectory(dir=TEST_TEMP_PARENT) as temporary:
                    fixture = Fixture(Path(temporary))
                    index = fixture.record_index(
                        "RESUME", phase="resume_from_replica"
                    )
                    fixture.mutate_transcript(
                        index, "prefix_after", prefix_after
                    )
                    with self.assertRaises(CHECKER.ReceiptViolation):
                        fixture.receipt()

    def test_resume_progress_requires_exact_range_advance(self) -> None:
        index = self.fixture.record_index(
            "PROGRESS", phase="resume_from_replica"
        )
        self.fixture.mutate_transcript(
            index, "remaining_ranges", str(ORACLE_RESUME_RANGES_REMAINING + 1)
        )
        self.assert_rejected("exact inspected durable complement")

    def test_typed_prefix_identity_index_length_and_total_are_cross_bound(self) -> None:
        cases = (
            ("prefix_object_id", "02" + identifier("wrong-prefix-object")),
            ("prefix_carrier_index", "1"),
            ("prefix_len", str(ORACLE_PARTIAL_PREFIX)),
            ("prefix_total_len", str(ORACLE_PREFIX_TOTAL_LEN + 1)),
        )
        for field, value in cases:
            with self.subTest(field=field):
                with tempfile.TemporaryDirectory(dir=TEST_TEMP_PARENT) as temporary:
                    fixture = Fixture(Path(temporary))
                    index = fixture.record_index(
                        "PROGRESS", phase="resume_from_replica"
                    )
                    fixture.mutate_transcript(index, field, value)
                    with self.assertRaises(CHECKER.ReceiptViolation):
                        fixture.receipt()

    def test_finish_byte_and_range_conservation_is_exact(self) -> None:
        index = self.fixture.record_index("FINISH", phase="finish_from_replica")
        self.fixture.mutate_transcript(
            index,
            "reconstructed_transfer_bytes",
            str(ORACLE_TRANSFER_BYTES + 1),
        )
        self.assert_rejected("FINISH.reconstructed_transfer_bytes")

    def test_finish_cannot_leave_pending_prefix_or_staging(self) -> None:
        cases = (
            ("pending_sources", "1"),
            ("carrier_prefixes", "1"),
            ("network_staging_bytes", "1"),
            ("public", "false"),
        )
        for field, value in cases:
            with self.subTest(field=field):
                with tempfile.TemporaryDirectory(dir=TEST_TEMP_PARENT) as temporary:
                    fixture = Fixture(Path(temporary))
                    index = fixture.record_index(
                        "COMPLETED_PROGRESS", phase="finish_from_replica"
                    )
                    fixture.mutate_transcript(index, field, value)
                    with self.assertRaises(CHECKER.ReceiptViolation):
                        fixture.receipt()

    def test_final_reopen_rejects_any_durable_blob_drift(self) -> None:
        index = self.fixture.record_index(
            "SHUTDOWN",
            phase="final_receiver_reopen",
            participant="receiver",
        )
        self.fixture.mutate_transcript(index, "blob_sealed_bytes", "513")
        self.assert_rejected("changed after final reopen|durable field")

    def test_all_four_complete_reads_are_bound_to_the_publication(self) -> None:
        phases = (
            ("peerless_publish", "publisher"),
            ("seed_replica", "replica"),
            ("finish_from_replica", "receiver"),
            ("final_receiver_reopen", "receiver"),
        )
        for phase, participant in phases:
            with self.subTest(phase=phase):
                with tempfile.TemporaryDirectory(dir=TEST_TEMP_PARENT) as temporary:
                    fixture = Fixture(Path(temporary))
                    index = fixture.record_index(
                        "READ", phase=phase, participant=participant
                    )
                    fixture.mutate_transcript(index, "payload_sha256", "0" * 64)
                    with self.assertRaisesRegex(CHECKER.ReceiptViolation, "READ"):
                        fixture.receipt()

    def test_page_gap_overlap_size_completion_and_hash_fail_closed(self) -> None:
        cases = (
            ("offset", "65535"),
            ("offset", "65537"),
            ("page_len", "32767"),
            ("next_offset", "98303"),
            ("complete", "false"),
            ("page_sha256", "0" * 64),
        )
        for key, value in cases:
            with self.subTest(key=key, value=value):
                with tempfile.TemporaryDirectory(dir=TEST_TEMP_PARENT) as temporary:
                    fixture = Fixture(Path(temporary))
                    page_indices = [
                        index
                        for index, line in enumerate(fixture.transcript_lines)
                        if line.startswith("LIVE_BLOB\tPAGE\t")
                        and "\tphase=final_receiver_reopen\t" in line
                        and "\tpage_index=1\t" in line
                    ]
                    fixture.mutate_transcript(page_indices[0], key, value)
                    with self.assertRaises(CHECKER.ReceiptViolation):
                        fixture.receipt()

    def test_runtime_contact_data_and_blob_aggregates_are_exact(self) -> None:
        index = self.fixture.runtime_index(
            "partial_from_publisher", "CONTACT", "receiver"
        )
        self.fixture.mutate_runtime(index, "fetched", "0")
        self.assert_rejected("CONTACT aggregate")

    def test_serving_side_data_offer_is_required_in_every_connected_phase(self) -> None:
        index = self.fixture.record_index(
            "SHUTDOWN",
            phase="resume_from_replica",
            participant="replica",
        )
        self.fixture.mutate_transcript(index, "data_offered", "0")
        self.assert_rejected("serving-side|aggregate")

    def test_runtime_ready_identity_path_phase_and_socket_are_bound(self) -> None:
        index = self.fixture.runtime_index(
            "resume_from_replica", "READY", "replica"
        )
        self.fixture.mutate_runtime(
            index, "mission_id", identifier("wrong-ready-mission")
        )
        self.assert_rejected("does not bind one transcript participant")

    def test_runtime_stable_connected_socket_is_enforced(self) -> None:
        index = self.fixture.runtime_index(
            "finish_from_replica", "READY", "receiver"
        )
        self.fixture.mutate_runtime(index, "sockets", "127.0.0.1:49999")
        self.assert_rejected("changed across connected actor lifetimes")

    def test_runtime_global_phase_barriers_fail_closed(self) -> None:
        current = self.fixture.runtime_index(
            "seed_replica", "READY", "publisher"
        )
        line = self.fixture.runtime_lines.pop(current)
        self.fixture.runtime_lines.insert(1, line)
        self.fixture.refresh_public()
        self.assert_rejected("before peerless_publish completed|overlap")

    def test_source_removal_binds_both_plaintext_files(self) -> None:
        conflict = self.fixture.record_index(
            "SOURCE_REMOVED", occurrence=1
        )
        self.fixture.mutate_transcript(
            conflict, "sha256", ORACLE_PAYLOAD_SHA256
        )
        self.assert_rejected("SOURCE_REMOVED conflict-probe")

    def test_replica_inventory_hardlink_alias_fails_closed(self) -> None:
        publisher = (
            self.fixture.root
            / "participants/publisher/state/blob-depot-v1"
            / self.fixture.variant_id
            / "00000000000000000000.chunk"
        )
        replica = (
            self.fixture.root
            / "participants/replica/state/blob-depot-v1"
            / self.fixture.variant_id
            / "00000000000000000000.chunk"
        )
        replica.unlink()
        os.link(publisher, replica)
        self.assert_rejected("hard-link|aliased")

    def test_replica_inventory_missing_file_and_directory_fail_closed(self) -> None:
        with tempfile.TemporaryDirectory(dir=TEST_TEMP_PARENT) as temporary:
            fixture = Fixture(Path(temporary))
            (
                fixture.root
                / "participants/replica/state/blob-depot-v1"
                / fixture.variant_id
                / "00000000000000000001.chunk"
            ).unlink()
            with self.assertRaisesRegex(
                CHECKER.ReceiptViolation, "missing or extra"
            ):
                fixture.receipt()
        with tempfile.TemporaryDirectory(dir=TEST_TEMP_PARENT) as temporary:
            fixture = Fixture(Path(temporary))
            variant = (
                fixture.root
                / "participants/replica/state/blob-depot-v1"
                / fixture.variant_id
            )
            for child in variant.iterdir():
                child.unlink()
            variant.rmdir()
            with self.assertRaises(CHECKER.ReceiptViolation):
                fixture.receipt()

    def test_replica_inventory_extra_variant_and_file_fail_closed(self) -> None:
        with tempfile.TemporaryDirectory(dir=TEST_TEMP_PARENT) as temporary:
            fixture = Fixture(Path(temporary))
            extra_variant = (
                fixture.root
                / "participants/replica/state/blob-depot-v1"
                / identifier("extra-replica-variant")
            )
            extra_variant.mkdir(mode=0o700)
            with self.assertRaisesRegex(
                CHECKER.ReceiptViolation,
                "missing or extra|canonical variant|more than one variant",
            ):
                fixture.receipt()
        extra = self.fixture.root / "participants/replica/state/unexpected"
        extra.write_bytes(b"unexpected\n")
        extra.chmod(0o600)
        self.assert_rejected("unexpected file|missing or extra")

    def test_inventory_mode_symlink_and_ciphertext_size_fail_closed(self) -> None:
        chunk = (
            self.fixture.root
            / "participants/replica/state/blob-depot-v1"
            / self.fixture.variant_id
            / "00000000000000000001.chunk"
        )
        chunk.chmod(0o644)
        self.assert_rejected("unexpected mode")

    def test_three_participant_secret_contents_do_not_affect_projection(self) -> None:
        first = self.fixture.receipt()
        private_files = [
            self.fixture.root / "participants/publisher/mission.bundle",
            self.fixture.root / "participants/replica/state/identity.key",
            self.fixture.root / "participants/receiver/state/mesh.redb",
            (
                self.fixture.root
                / "participants/replica/state/blob-depot-v1"
                / ".aster-store-owner-v1"
            ),
            (
                self.fixture.root
                / "participants/receiver/state/blob-depot-v1"
                / self.fixture.variant_id
                / "00000000000000000000.chunk"
            ),
        ]
        for value, path in enumerate(private_files, start=1):
            path.write_bytes(bytes([value]) * path.stat().st_size)
            path.chmod(0o600)
        self.assertEqual(first, self.fixture.receipt())

    def test_secret_and_ciphertext_files_are_never_opened(self) -> None:
        original_open = os.open
        private_names = {
            "mission.bundle",
            "identity.key",
            "mesh.redb",
            ".aster-store-owner-v1",
            "00000000000000000000.chunk",
            "00000000000000000001.chunk",
        }

        def guarded_open(path, flags, mode=0o777, *, dir_fd=None):
            if os.path.basename(os.fsdecode(path)) in private_names:
                raise AssertionError(f"private artifact was opened: {path}")
            if dir_fd is None:
                return original_open(path, flags, mode)
            return original_open(path, flags, mode, dir_fd=dir_fd)

        with mock.patch.object(CHECKER.os, "open", side_effect=guarded_open):
            self.fixture.receipt()

    def test_source_signature_tree_admitted_tool_and_artifacts_are_bound(self) -> None:
        self.fixture.run_document["source"]["tree"] = "3" * 40
        self.fixture.write_run_document()
        self.assert_rejected("source.tree")

    def test_build_and_run_argv_are_exact(self) -> None:
        self.fixture.run_document["commands"]["build_argv"][0] = "rustc"
        self.fixture.write_run_document()
        self.assert_rejected("release build invocation")

    def test_binary_and_stdout_artifact_hashes_are_bound(self) -> None:
        self.fixture.run_document["artifacts"]["stdout"]["bytes"] += 1
        self.fixture.write_run_document()
        self.assert_rejected("artifacts.stdout.bytes")

    def test_run_document_is_compact_canonical_duplicate_free_json(self) -> None:
        path = self.fixture.root / "run.json"
        document = json.loads(path.read_bytes())
        path.write_text(json.dumps(document, indent=2) + "\n", encoding="ascii")
        path.chmod(0o600)
        self.assert_rejected("compact canonical JSON")

    def test_identifier_path_port_pid_payload_and_progress_leakage_fail_closed(self) -> None:
        document, evidence = self.fixture.receipt_document()
        forbidden_values = CHECKER.receipt_forbidden_values(
            evidence, self.fixture.root
        )
        for value, pattern in (
            (self.fixture.blob_id, "parsed identifier"),
            (self.fixture.source_transfer_id, "parsed identifier"),
            (self.fixture.partial_staging, "parsed identifier"),
            (os.fspath(self.fixture.root), "path"),
            (4242, "process identifier"),
            (40000, "network port"),
        ):
            with self.subTest(value=value):
                mutated = dict(document)
                mutated["status"] = value
                with self.assertRaisesRegex(CHECKER.ReceiptViolation, pattern):
                    CHECKER.render_receipt(
                        mutated,
                        forbidden_values=forbidden_values,
                        forbidden_pids=CHECKER.receipt_forbidden_pids(evidence),
                        forbidden_ports=CHECKER.receipt_forbidden_ports(evidence),
                    )
        payload = "synthetic-plaintext-payload"
        mutated = dict(document)
        mutated["status"] = payload
        with self.assertRaisesRegex(CHECKER.ReceiptViolation, "parsed identifier"):
            CHECKER.render_receipt(
                mutated,
                forbidden_values=[*forbidden_values, payload],
                forbidden_pids=CHECKER.receipt_forbidden_pids(evidence),
                forbidden_ports=CHECKER.receipt_forbidden_ports(evidence),
            )

    def test_receipt_output_is_exclusive_collision_safe_and_owner_only(self) -> None:
        output = self.fixture.parent / CHECKER.RECEIPT_NAME
        output.write_bytes(b"preexisting\n")
        output.chmod(0o600)
        with self.assertRaisesRegex(CHECKER.ReceiptViolation, "already exists"):
            CHECKER.write_receipt(output, self.fixture.receipt())
        self.assertEqual(output.read_bytes(), b"preexisting\n")
        output.unlink()
        prior_umask = os.umask(0o777)
        try:
            CHECKER.write_receipt(output, self.fixture.receipt())
        finally:
            os.umask(prior_umask)
        self.assertEqual(stat.S_IMODE(output.stat().st_mode), 0o600)

    def test_cli_failure_is_generic_while_internal_detail_is_private(self) -> None:
        chunk = (
            self.fixture.root
            / "participants/replica/state/blob-depot-v1"
            / self.fixture.variant_id
            / "00000000000000000000.chunk"
        )
        chunk.chmod(0o644)
        with self.assertRaises(CHECKER.ReceiptViolation) as raised:
            self.fixture.receipt()
        internal_detail = str(raised.exception)
        self.assertIn(self.fixture.variant_id, internal_detail)
        chunk.chmod(0o600)

        private_detail = (
            f"{internal_detail}; raw={self.fixture.root}; "
            "sentinel=private-diagnostic-detail"
        )
        stderr = io.StringIO()
        with (
            mock.patch.object(
                CHECKER, "validate_source", return_value=self.fixture.source
            ),
            mock.patch.object(
                CHECKER,
                "validate_raw_root",
                side_effect=CHECKER.ReceiptViolation(private_detail),
            ),
            mock.patch.object(CHECKER.sys, "stderr", stderr),
            self.assertRaises(SystemExit) as exited,
        ):
            CHECKER.main(
                [
                    "--raw-root",
                    os.fspath(self.fixture.root),
                    "--source",
                    os.fspath(self.fixture.parent / "source"),
                ]
            )
        self.assertEqual(exited.exception.code, 1)
        self.assertEqual(
            stderr.getvalue(), "selected live Blob receipt validation failed\n"
        )
        self.assertNotIn(self.fixture.variant_id, stderr.getvalue())
        self.assertNotIn(os.fspath(self.fixture.root), stderr.getvalue())
        self.assertNotIn("private-diagnostic-detail", stderr.getvalue())


if __name__ == "__main__":
    unittest.main()
