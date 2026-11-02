#!/usr/bin/env python3
# Copyright 2026 Defense Unicorns, Inc.
# SPDX-License-Identifier: Apache-2.0
"""Adversarial tests for the selected live-State/Record receipt projector."""

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


CHECKER_PATH = Path(__file__).with_name("check-selected-live-mutable-receipt.py")
SPEC = importlib.util.spec_from_file_location("selected_live_mutable_receipt", CHECKER_PATH)
if SPEC is None or SPEC.loader is None:
    raise RuntimeError(f"cannot load {CHECKER_PATH}")
CHECKER = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(CHECKER)

RUNNER_PATH = Path(__file__).with_name("run-selected-live-mutable.py")
RUNNER_SPEC = importlib.util.spec_from_file_location("selected_live_mutable_runner", RUNNER_PATH)
if RUNNER_SPEC is None or RUNNER_SPEC.loader is None:
    raise RuntimeError(f"cannot load {RUNNER_PATH}")
RUNNER = importlib.util.module_from_spec(RUNNER_SPEC)
RUNNER_SPEC.loader.exec_module(RUNNER)

ORACLE_RECEIPT_SCHEMA = "aster-selected-live-mutable-receipt/v2"
ORACLE_RAW_SCHEMA = "aster-selected-live-mutable-raw/v2"
ORACLE_TRANSCRIPT_SCHEMA = "aster-selected-live-mutable-transcript/v2"
ORACLE_CLAIM = "selected-live-state-causal-successor-tombstone-record-one-host-direct-iroh-two-actor-acceptance"
ORACLE_TRANSCRIPT_RECORDS = 48
ORACLE_SUPERSEDED_SCHEMA = "aster-selected-live-mutable-receipt/v1"
ORACLE_SUPERSEDED_SOURCE_COMMIT = "2ccfba0d18bf8d8221ab11fb485b32fcf6270272"
ORACLE_SUPERSEDED_RECEIPT_SHA256 = (
    "299a3c3b8d1685deb5980ed091797f7d46119562b67c3d853b94d8552c83b67a"
)
ORACLE_TRANSCRIPT_KEY_SCHEMA_SHA256 = (
    "613dae481f5a71a1d87962ed6a9d251b4a7d5a5c59a030486e402f722bf0f72d"
)
ORACLE_TERMINAL_KEY_SCHEMA_SHA256 = (
    "6cce95bbb1024560db205339f0e70a2b75b8e3b93f9c43b548a23c49abfcb617"
)
ORACLE_NEW_STOP_BLOB_FIELDS = (
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
    "blob_carrier_prefixes",
    "blob_carrier_fetch_cursors",
    "blob_network_staging_bytes",
)
ORACLE_BUILD_ARGV = (
    "cargo",
    "build",
    "--release",
    "--locked",
    "-p",
    "aster-node",
    "--example",
    "live_mutable_acceptance",
)
ORACLE_ADMITTED_PATHS = tuple(
    sorted(
        (
            "Cargo.lock",
            "Cargo.toml",
            "mise.toml",
            "crates/aster-core/Cargo.toml",
            "crates/aster-core/src/causal.rs",
            "crates/aster-core/src/crypto/reference.rs",
            "crates/aster-core/src/lib.rs",
            "crates/aster-core/src/source_state.rs",
            "crates/aster-node/Cargo.toml",
            "crates/aster-node/examples/live_mutable_acceptance.rs",
            "crates/aster-node/src/application.rs",
            "crates/aster-node/src/application/record.rs",
            "crates/aster-node/src/application/state.rs",
            "crates/aster-node/src/lib.rs",
            "crates/aster-node/src/runtime.rs",
            "crates/aster-redb-store/Cargo.toml",
            "crates/aster-redb-store/src/lib.rs",
            "tools/check-selected-live-mutable-receipt.py",
            "tools/run-selected-live-mutable.py",
            "tools/test-selected-live-mutable-receipt.py",
        )
    )
)
ORACLE_PAYLOAD_HASHES = {
    ("state", "node-a"): "88df35f927914acd45fed9c4e539d53c56bc688683246afc8eb28c3520023089",
    ("state", "node-b"): "f42c4365b7ecd070de362a5faee30028c9051e64c1e149f67b3396f08584b5c3",
    ("record", "node-a"): "ea7e65181655ebe13372e8b1d740c2114675ce2d85ba511074158ef1b971e34d",
    ("record", "node-b"): "0572316ec50701364d0e721db4197d4c15667411949b9821ae72c52dd6003ba3",
    ("resolution", "node-a"): "4b631dc38a7dc95cf0d35bc24ff0cdf94bfa9e84aad297bcc1af81fa8970afb3",
    ("successor", "node-a"): "d1604822c53bec359621ef55529767e3e3a586634f8e0218d4a2eea3730e581c",
    ("tombstone", "node-b"): "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
}
ORACLE_LIMITATIONS = (
    "operator-attested-source-binary-execution-link-not-cryptographically-proven",
    "selected-admitted-source-list-is-not-a-complete-reproducible-build-closure",
    "one-host-loopback-same-implementation-observation",
    "participant-secret-artifacts-validated-by-metadata-only",
    "state-causal-observation-and-publication-order-are-producer-attested",
    "restart-observes-one-immediate-peerless-reopen-not-indefinite-tombstone-retention",
)
ORACLE_NONCLAIMS = (
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
)
ORACLE_RECORD_TYPES = (
    "RUN",
    "PARTICIPANT",
    "PARTICIPANT",
    "HANDLE",
    "HANDLE",
    "STATE_PUBLICATION",
    "STATE_PUBLICATION",
    "STATE_RETRY",
    "STATE_RETRY",
    "RECORD_PUBLICATION",
    "RECORD_PUBLICATION",
    "RECORD_RETRY",
    "RECORD_RETRY",
    "SHUTDOWN",
    "SHUTDOWN",
    "CLOSED_HANDLE",
    "CLOSED_HANDLE",
    "CLOSED_HANDLE",
    "CLOSED_HANDLE",
    "STATE_VIEW",
    "STATE_VIEW",
    "RECORD_CONFLICT",
    "RECORD_CONFLICT",
    "RECORD_REJECTION",
    "RECORD_RESOLUTION",
    "RECORD_RESOLUTION_RETRY",
    "RECORD_RESOLVED",
    "RECORD_RESOLVED",
    "STATE_SUCCESSOR_PUBLICATION",
    "STATE_SUCCESSOR_RETRY",
    "STATE_CAUSAL_VIEW",
    "STATE_CAUSAL_VIEW",
    "STATE_TOMBSTONE_PUBLICATION",
    "STATE_TOMBSTONE_RETRY",
    "STATE_CAUSAL_VIEW",
    "STATE_CAUSAL_VIEW",
    "SHUTDOWN",
    "SHUTDOWN",
    "STATE_CAUSAL_VIEW",
    "STATE_CAUSAL_VIEW",
    "RECORD_RESOLVED",
    "RECORD_RESOLVED",
    "RECORD_RESOLUTION_RETRY",
    "SHUTDOWN",
    "SHUTDOWN",
    "BIND_REACQUIRED",
    "BIND_REACQUIRED",
    "RESULT",
)


def identifier(label: str) -> str:
    return hashlib.sha256(label.encode("ascii")).hexdigest()


def tsv(record_type: str, keys: tuple[str, ...], values: dict[str, str]) -> str:
    if set(values) != set(keys):
        raise AssertionError(f"fixture {record_type} keys differ")
    return "\t".join(
        ["LIVE_MUTABLE", record_type, *(f"{key}={values[key]}" for key in keys)]
    )


def terminal(prefix: str, keys: tuple[str, ...], values: dict[str, str]) -> str:
    if set(values) != set(keys):
        raise AssertionError(f"fixture {prefix} keys differ")
    return " ".join([prefix, *(f"{key}={values[key]}" for key in keys)])


class Fixture:
    def __init__(self, parent: Path) -> None:
        self.parent = parent
        self.parent.chmod(0o700)
        self.root = parent / "raw"
        self.root.mkdir(mode=0o700)
        self.carriers = {
            "node-a": identifier("carrier-a"),
            "node-b": identifier("carrier-b"),
        }
        self.missions = {
            "node-a": identifier("mission-a"),
            "node-b": identifier("mission-b"),
        }
        self.authority = identifier("common-authority")
        self.state_ids = {
            "node-a": identifier("state-a"),
            "node-b": identifier("state-b"),
        }
        self.record_ids = {
            "node-a": identifier("record-a"),
            "node-b": identifier("record-b"),
        }
        self.resolution_id = identifier("record-resolution")
        self.successor_id = identifier("state-successor")
        self.tombstone_id = identifier("state-tombstone")
        self.secret = b"S" * CHECKER.IDENTITY_BYTES
        self.binary = b"\x7fELFsynthetic-live-mutable-release\n"
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
            "participants/node-a",
            "participants/node-a/state",
            "participants/node-b",
            "participants/node-b/state",
        ):
            self._mkdir(relative)
        self._write("binary/aster-live-mutable-acceptance", self.binary, 0o700)
        for participant in ("node-a", "node-b"):
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
        other = "node-b" if name == "node-a" else "node-a"
        return {
            "participant": name,
            "carrier_id": self.carriers[name],
            "mission_id": self.missions[name],
            "mission_authority": self.authority,
            "expected_carrier_peer": self.carriers[other],
            "expected_mission_peer": self.missions[other],
        }

    def publication(
        self, kind: str, participant: str, publication_id: str, counter: int
    ) -> dict[str, str]:
        return {
            "participant": participant,
            "id": publication_id,
            "publisher": self.missions[participant],
            "counter": str(counter),
            "payload_sha256": ORACLE_PAYLOAD_HASHES[(kind, participant)],
            "inserted": "true",
        }

    def item(self, kind: str, participant: str, publication_id: str, counter: int) -> dict[str, str]:
        return {
            "id": publication_id,
            "publisher": self.missions[participant],
            "counter": str(counter),
            "payload_sha256": ORACLE_PAYLOAD_HASHES[(kind, participant)],
        }

    @staticmethod
    def item_fields(prefix: str, item: dict[str, str]) -> dict[str, str]:
        return {f"{prefix}_{key}": value for key, value in item.items()}

    def state_view(self, phase: str, participant: str) -> dict[str, str]:
        current_id = max(self.state_ids.values())
        concurrent_id = min(self.state_ids.values())
        current_owner = next(name for name, value in self.state_ids.items() if value == current_id)
        concurrent_owner = next(
            name for name, value in self.state_ids.items() if value == concurrent_id
        )
        return {
            "phase": phase,
            "participant": participant,
            **self.item_fields(
                "current", self.item("state", current_owner, current_id, 1)
            ),
            "current_disposition": "current",
            "recoverable_count": "1",
            **self.item_fields(
                "concurrent", self.item("state", concurrent_owner, concurrent_id, 1)
            ),
            "concurrent_disposition": "concurrent",
        }

    def causal_publication(
        self,
        kind: str,
        participant: str,
        publication_id: str,
        counter: int,
        observed_heads: list[str],
        observed_versions: list[str],
        *,
        tombstone: bool,
    ) -> dict[str, str]:
        return {
            "participant": participant,
            "observed_heads": ",".join(observed_heads),
            "observed_versions": ",".join(observed_versions),
            "id": publication_id,
            "publisher": self.missions[participant],
            "counter": str(counter),
            "payload_sha256": ORACLE_PAYLOAD_HASHES[(kind, participant)],
            "tombstone": str(tombstone).lower(),
            "inserted": "true",
        }

    def state_version(
        self,
        kind: str,
        participant: str,
        publication_id: str,
        counter: int,
        *,
        tombstone: bool,
    ) -> dict[str, str]:
        return {
            **self.item(kind, participant, publication_id, counter),
            "tombstone": str(tombstone).lower(),
        }

    def causal_state_view(
        self,
        phase: str,
        participant: str,
        current: dict[str, str],
        superseded: list[dict[str, str]],
    ) -> dict[str, str]:
        ordered = sorted(superseded, key=lambda item: item["id"])
        return {
            "phase": phase,
            "participant": participant,
            **self.item_fields(
                "current",
                {
                    key: current[key]
                    for key in ("id", "publisher", "counter", "payload_sha256")
                },
            ),
            "current_disposition": "current",
            "current_tombstone": current["tombstone"],
            "superseded_count": str(len(ordered)),
            "superseded": ",".join(item["id"] for item in ordered),
            "superseded_publishers": ",".join(
                item["publisher"] for item in ordered
            ),
            "superseded_counters": ",".join(item["counter"] for item in ordered),
            "superseded_payload_sha256": ",".join(
                item["payload_sha256"] for item in ordered
            ),
            "superseded_dispositions": ",".join(
                "superseded" for _item in ordered
            ),
            "superseded_tombstones": ",".join(
                item["tombstone"] for item in ordered
            ),
        }

    def conflict(self, participant: str) -> dict[str, str]:
        current_id = max(self.record_ids.values())
        concurrent_id = min(self.record_ids.values())
        current_owner = next(name for name, value in self.record_ids.items() if value == current_id)
        concurrent_owner = next(
            name for name, value in self.record_ids.items() if value == concurrent_id
        )
        siblings = ",".join(sorted(self.record_ids.values()))
        return {
            "phase": "connected",
            "participant": participant,
            **self.item_fields(
                "current", self.item("record", current_owner, current_id, 2)
            ),
            "current_disposition": "current",
            **self.item_fields(
                "concurrent", self.item("record", concurrent_owner, concurrent_id, 2)
            ),
            "concurrent_disposition": "concurrent",
            "conflict": "true",
            "siblings": siblings,
            "guard_siblings": siblings,
        }

    def resolved(self, phase: str, participant: str) -> dict[str, str]:
        return {
            "phase": phase,
            "participant": participant,
            **self.item_fields(
                "current",
                {
                    "id": self.resolution_id,
                    "publisher": self.missions["node-a"],
                    "counter": "3",
                    "payload_sha256": ORACLE_PAYLOAD_HASHES[("resolution", "node-a")],
                },
            ),
            "current_disposition": "current",
            "conflict": "false",
            "superseded_count": "2",
            "superseded": ",".join(sorted(self.record_ids.values())),
            "superseded_dispositions": "superseded,superseded",
        }

    @staticmethod
    def shutdown(phase: str, participant: str) -> dict[str, str]:
        contacts = "1" if phase == "connected" else "0"
        return {
            "phase": phase,
            "participant": participant,
            "contacts": contacts,
            "direct_contacts": contacts,
            "relay_contacts": "0",
            "unknown_path_contacts": "0",
            "contact_errors": "0",
        }

    def _transcript_lines(self) -> list[str]:
        records: list[str] = []
        records.append(
            tsv(
                "RUN",
                CHECKER.RUN_KEYS,
                {
                    "schema": ORACLE_TRANSCRIPT_SCHEMA,
                    "claim": ORACLE_CLAIM,
                    "participants": "2",
                    "actor_lifetimes": "6",
                    "maximum_concurrent_actors": "2",
                    "topic": "opaque",
                    "scope": "test/runtime-contact",
                },
            )
        )
        for participant in ("node-a", "node-b"):
            records.append(
                tsv("PARTICIPANT", CHECKER.PARTICIPANT_KEYS, self.participant(participant))
            )
        for participant in ("node-a", "node-b"):
            records.append(
                tsv(
                    "HANDLE",
                    CHECKER.HANDLE_KEYS,
                    {
                        "participant": participant,
                        "state_identity": self.missions[participant],
                        "state_authority": self.authority,
                        "record_identity": self.missions[participant],
                        "record_authority": self.authority,
                    },
                )
            )
        for participant in ("node-a", "node-b"):
            records.append(
                tsv(
                    "STATE_PUBLICATION",
                    CHECKER.PUBLICATION_KEYS,
                    self.publication("state", participant, self.state_ids[participant], 1),
                )
            )
        for participant in ("node-a", "node-b"):
            records.append(
                tsv(
                    "STATE_RETRY",
                    CHECKER.RETRY_KEYS,
                    {
                        "participant": participant,
                        "original_id": self.state_ids[participant],
                        "retry_id": self.state_ids[participant],
                        "inserted": "false",
                    },
                )
            )
        for participant in ("node-a", "node-b"):
            records.append(
                tsv(
                    "RECORD_PUBLICATION",
                    CHECKER.PUBLICATION_KEYS,
                    self.publication("record", participant, self.record_ids[participant], 2),
                )
            )
        for participant in ("node-a", "node-b"):
            records.append(
                tsv(
                    "RECORD_RETRY",
                    CHECKER.RETRY_KEYS,
                    {
                        "participant": participant,
                        "original_id": self.record_ids[participant],
                        "retry_id": self.record_ids[participant],
                        "inserted": "false",
                    },
                )
            )
        for participant in ("node-a", "node-b"):
            records.append(
                tsv("SHUTDOWN", CHECKER.SHUTDOWN_KEYS, self.shutdown("peerless", participant))
            )
        for participant in ("node-a", "node-b"):
            for kind, operation in (("state", "state_query"), ("record", "record_query")):
                records.append(
                    tsv(
                        "CLOSED_HANDLE",
                        CHECKER.CLOSED_HANDLE_KEYS,
                        {
                            "participant": participant,
                            "kind": kind,
                            "error_kind": "state_unavailable",
                            "operation": operation,
                        },
                    )
                )
        for participant in ("node-a", "node-b"):
            records.append(
                tsv("STATE_VIEW", CHECKER.STATE_VIEW_KEYS, self.state_view("connected", participant))
            )
        for participant in ("node-a", "node-b"):
            records.append(
                tsv("RECORD_CONFLICT", CHECKER.RECORD_CONFLICT_KEYS, self.conflict(participant))
            )
        siblings = ",".join(sorted(self.record_ids.values()))
        records.append(
            tsv(
                "RECORD_REJECTION",
                CHECKER.RECORD_REJECTION_KEYS,
                {
                    "participant": "node-a",
                    "error_kind": "conflict",
                    "operation": "record_publish",
                    "before_siblings": siblings,
                    "after_siblings": siblings,
                    "after_conflict": "true",
                },
            )
        )
        records.append(
            tsv(
                "RECORD_RESOLUTION",
                CHECKER.RECORD_RESOLUTION_KEYS,
                {
                    "participant": "node-a",
                    "observed_siblings": siblings,
                    "id": self.resolution_id,
                    "publisher": self.missions["node-a"],
                    "counter": "3",
                    "payload_sha256": ORACLE_PAYLOAD_HASHES[("resolution", "node-a")],
                    "inserted": "true",
                },
            )
        )
        records.append(
            tsv(
                "RECORD_RESOLUTION_RETRY",
                CHECKER.RESOLUTION_RETRY_KEYS,
                {
                    "phase": "immediate",
                    "participant": "node-a",
                    "original_id": self.resolution_id,
                    "retry_id": self.resolution_id,
                    "inserted": "false",
                },
            )
        )
        for participant in ("node-a", "node-b"):
            records.append(
                tsv(
                    "RECORD_RESOLVED",
                    CHECKER.RECORD_RESOLVED_KEYS,
                    self.resolved("connected", participant),
                )
            )
        initial_state_versions = [
            self.state_version(
                "state",
                participant,
                self.state_ids[participant],
                1,
                tombstone=False,
            )
            for participant in ("node-a", "node-b")
        ]
        initial_state_ids = sorted(self.state_ids.values())
        successor = self.state_version(
            "successor", "node-a", self.successor_id, 4, tombstone=False
        )
        records.append(
            tsv(
                "STATE_SUCCESSOR_PUBLICATION",
                CHECKER.CAUSAL_PUBLICATION_KEYS,
                self.causal_publication(
                    "successor",
                    "node-a",
                    self.successor_id,
                    4,
                    initial_state_ids,
                    initial_state_ids,
                    tombstone=False,
                ),
            )
        )
        records.append(
            tsv(
                "STATE_SUCCESSOR_RETRY",
                CHECKER.RETRY_KEYS,
                {
                    "participant": "node-a",
                    "original_id": self.successor_id,
                    "retry_id": self.successor_id,
                    "inserted": "false",
                },
            )
        )
        for participant in ("node-a", "node-b"):
            records.append(
                tsv(
                    "STATE_CAUSAL_VIEW",
                    CHECKER.STATE_CAUSAL_VIEW_KEYS,
                    self.causal_state_view(
                        "successor", participant, successor, initial_state_versions
                    ),
                )
            )
        pre_tombstone_versions = [*initial_state_versions, successor]
        tombstone = self.state_version(
            "tombstone", "node-b", self.tombstone_id, 3, tombstone=True
        )
        records.append(
            tsv(
                "STATE_TOMBSTONE_PUBLICATION",
                CHECKER.CAUSAL_PUBLICATION_KEYS,
                self.causal_publication(
                    "tombstone",
                    "node-b",
                    self.tombstone_id,
                    3,
                    [self.successor_id],
                    sorted(item["id"] for item in pre_tombstone_versions),
                    tombstone=True,
                ),
            )
        )
        records.append(
            tsv(
                "STATE_TOMBSTONE_RETRY",
                CHECKER.RETRY_KEYS,
                {
                    "participant": "node-b",
                    "original_id": self.tombstone_id,
                    "retry_id": self.tombstone_id,
                    "inserted": "false",
                },
            )
        )
        for participant in ("node-a", "node-b"):
            records.append(
                tsv(
                    "STATE_CAUSAL_VIEW",
                    CHECKER.STATE_CAUSAL_VIEW_KEYS,
                    self.causal_state_view(
                        "tombstone", participant, tombstone, pre_tombstone_versions
                    ),
                )
            )
        for participant in ("node-a", "node-b"):
            records.append(
                tsv("SHUTDOWN", CHECKER.SHUTDOWN_KEYS, self.shutdown("connected", participant))
            )
        for participant in ("node-a", "node-b"):
            records.append(
                tsv(
                    "STATE_CAUSAL_VIEW",
                    CHECKER.STATE_CAUSAL_VIEW_KEYS,
                    self.causal_state_view(
                        "restart", participant, tombstone, pre_tombstone_versions
                    ),
                )
            )
        for participant in ("node-a", "node-b"):
            records.append(
                tsv(
                    "RECORD_RESOLVED",
                    CHECKER.RECORD_RESOLVED_KEYS,
                    self.resolved("restart", participant),
                )
            )
        records.append(
            tsv(
                "RECORD_RESOLUTION_RETRY",
                CHECKER.RESOLUTION_RETRY_KEYS,
                {
                    "phase": "post_restart",
                    "participant": "node-a",
                    "original_id": self.resolution_id,
                    "retry_id": self.resolution_id,
                    "inserted": "false",
                },
            )
        )
        for participant in ("node-a", "node-b"):
            records.append(
                tsv("SHUTDOWN", CHECKER.SHUTDOWN_KEYS, self.shutdown("restart", participant))
            )
        for participant in ("node-a", "node-b"):
            records.append(
                tsv(
                    "BIND_REACQUIRED",
                    CHECKER.BIND_KEYS,
                    {"participant": participant, "status": "reacquired"},
                )
            )
        records.append(
            tsv(
                "RESULT",
                CHECKER.RESULT_KEYS,
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
            )
        )
        if len(records) != CHECKER.TRANSCRIPT_RECORDS:
            raise AssertionError("fixture transcript record count differs")
        return records

    def ready(self, participant: str, phase_index: int) -> str:
        return terminal(
            "READY",
            CHECKER.READY_KEYS,
            {
                "selected": "true",
                "pid": "4242",
                "carrier_id": self.carriers[participant],
                "mission_id": self.missions[participant],
                "mission_authority": self.authority,
                "sockets": f"127.0.0.1:{40000 + phase_index * 10 + (participant == 'node-b')}",
                "state": CHECKER.encoded_path(self.root / "participants" / participant / "state"),
                "peers": "1" if phase_index == 1 else "0",
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

    def contact(self, local: str, remote: str, direction: str) -> str:
        numeric = {
            key: "0"
            for key in CHECKER.CONTACT_KEYS[3:26] + CHECKER.CONTACT_KEYS[27:28]
        }
        reconciliation = (
            {"offered": "4", "fetched": "3", "inserted": "3"}
            if local == "node-a"
            else {"offered": "3", "fetched": "4", "inserted": "4"}
        )
        numeric.update(
            {
                "rounds": "1",
                **reconciliation,
                "handshake_frames": "2",
                "handshake_bytes": "128",
                "protected_frames": "2",
                "protected_bytes": "128",
            }
        )
        return terminal(
            "CONTACT",
            CHECKER.CONTACT_KEYS,
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
                "status": "pass",
            },
        )

    def stop(self, participant: str, phase: str) -> str:
        contacts = "1" if phase == "connected" else "0"
        numeric = {key: "0" for key in CHECKER.STOP_NUMERIC_FIELDS}
        numeric.update({"contacts": contacts, "direct_contacts": contacts})
        return terminal(
            "STOP",
            CHECKER.STOP_KEYS,
            {
                "lifecycle": "complete",
                "sync_status": "contacts_observed" if phase == "connected" else "no_successful_contact",
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

    def _runtime_lines(self) -> list[str]:
        lines: list[str] = []
        for phase_index, phase in enumerate(("peerless", "connected", "restart")):
            lines.extend(self.ready(participant, phase_index) for participant in ("node-a", "node-b"))
            if phase == "connected":
                lower = min(("node-a", "node-b"), key=self.carriers.__getitem__)
                higher = "node-b" if lower == "node-a" else "node-a"
                lines.append(self.contact(lower, higher, "out"))
                lines.append(self.contact(higher, lower, "in"))
            lines.extend(self.stop(participant, phase) for participant in ("node-a", "node-b"))
        return lines

    def _artifact(self, relative: str, data: bytes) -> dict[str, object]:
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
                    os.fspath(self.root / "binary" / "aster-live-mutable-acceptance"),
                    os.fspath(self.root),
                ],
            },
            "execution": {
                "exit_code": 0,
                "worktree_clean_at_run": True,
                "source_binary_execution_link": "operator-attested-not-cryptographically-proven",
            },
            "artifacts": {
                "binary": self._artifact(
                    "binary/aster-live-mutable-acceptance", self.binary
                ),
                "stdout": self._artifact("stdout.log", stdout),
                "stderr": self._artifact("stderr.log", b""),
                "transcript": self._artifact("transcript.tsv", transcript),
            },
            "tools": tools,
        }
        self.write_run_document()

    def write_run_document(self) -> None:
        self._write("run.json", CHECKER.canonical_json_bytes(self.run_document), 0o600)

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
        self.mutate_runtime_fields(index, {key: value})

    def mutate_runtime_fields(self, index: int, values: dict[str, str]) -> None:
        parts = self.runtime_lines[index].split(" ")
        pending = set(values)
        for position in range(1, len(parts)):
            key, separator, _value = parts[position].partition("=")
            if separator and key in pending:
                parts[position] = f"{key}={values[key]}"
                pending.remove(key)
        if pending:
            raise AssertionError(f"missing runtime fixture fields {sorted(pending)}")
        self.runtime_lines[index] = " ".join(parts)
        self.refresh_public()

    def receipt(self) -> bytes:
        evidence = CHECKER.validate_raw_root(self.root, self.source)
        return CHECKER.render_receipt(
            CHECKER.build_receipt(self.source, evidence),
            forbidden_values=CHECKER.receipt_forbidden_values(evidence, self.root),
            forbidden_pids=CHECKER.receipt_forbidden_pids(evidence),
            forbidden_ports=CHECKER.receipt_forbidden_ports(evidence),
        )


class SelectedLiveMutableReceiptTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory(dir=TEST_TEMP_PARENT)
        self.fixture = Fixture(Path(self.temporary.name))

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def assert_rejected(self, pattern: str) -> None:
        with self.assertRaisesRegex(CHECKER.ReceiptViolation, pattern):
            self.fixture.receipt()

    def test_independent_contract_oracles_match_checker(self) -> None:
        self.assertEqual(CHECKER.SCHEMA, ORACLE_RECEIPT_SCHEMA)
        self.assertEqual(CHECKER.RAW_SCHEMA, ORACLE_RAW_SCHEMA)
        self.assertEqual(CHECKER.TRANSCRIPT_SCHEMA, ORACLE_TRANSCRIPT_SCHEMA)
        self.assertEqual(CHECKER.CLAIM, ORACLE_CLAIM)
        self.assertEqual(CHECKER.TRANSCRIPT_RECORDS, ORACLE_TRANSCRIPT_RECORDS)
        self.assertEqual(RUNNER.TRANSCRIPT_RECORDS, ORACLE_TRANSCRIPT_RECORDS)
        self.assertEqual(CHECKER.OLD_RECEIPT_SOURCE_COMMIT, ORACLE_SUPERSEDED_SOURCE_COMMIT)
        self.assertEqual(CHECKER.OLD_RECEIPT_SHA256, ORACLE_SUPERSEDED_RECEIPT_SHA256)
        self.assertEqual(tuple(CHECKER.EXPECTED_BUILD_ARGV), ORACLE_BUILD_ARGV)
        self.assertEqual(CHECKER.ADMITTED_SOURCE_PATHS, ORACLE_ADMITTED_PATHS)
        self.assertEqual(CHECKER.PAYLOAD_HASHES, ORACLE_PAYLOAD_HASHES)
        self.assertEqual(tuple(CHECKER.LIMITATIONS), ORACLE_LIMITATIONS)
        self.assertEqual(tuple(CHECKER.NONCLAIMS), ORACLE_NONCLAIMS)
        self.assertEqual(
            tuple(record_type for record_type, _keys in CHECKER.EXPECTED_SEQUENCE),
            ORACLE_RECORD_TYPES,
        )

        transcript_key_schema = "\n".join(
            record_type + "\0" + "\0".join(keys)
            for record_type, keys in CHECKER.EXPECTED_SEQUENCE
        ).encode("ascii")
        terminal_key_schema = "\n".join(
            record_type + "\0" + "\0".join(keys)
            for record_type, keys in (
                ("READY", CHECKER.READY_KEYS),
                ("CONTACT", CHECKER.CONTACT_KEYS),
                ("STOP", CHECKER.STOP_KEYS),
            )
        ).encode("ascii")
        self.assertEqual(
            hashlib.sha256(transcript_key_schema).hexdigest(),
            ORACLE_TRANSCRIPT_KEY_SCHEMA_SHA256,
        )
        self.assertEqual(
            hashlib.sha256(terminal_key_schema).hexdigest(),
            ORACLE_TERMINAL_KEY_SCHEMA_SHA256,
        )
        self.assertEqual(
            tuple(
                field
                for field in CHECKER.STOP_KEYS
                if field in ORACLE_NEW_STOP_BLOB_FIELDS
            ),
            ORACLE_NEW_STOP_BLOB_FIELDS,
        )
        self.assertTrue(
            set(ORACLE_NEW_STOP_BLOB_FIELDS).issubset(CHECKER.STOP_NUMERIC_FIELDS)
        )
        self.assertTrue(
            set(ORACLE_NEW_STOP_BLOB_FIELDS).issubset(
                CHECKER.STOP_EXCLUDED_ZERO_FIELDS
            )
        )
        self.assertEqual(
            CHECKER.RUN_KEYS,
            (
                "schema",
                "claim",
                "participants",
                "actor_lifetimes",
                "maximum_concurrent_actors",
                "topic",
                "scope",
            ),
        )
        self.assertEqual(
            CHECKER.RESULT_KEYS,
            (
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
            ),
        )

    def test_runner_extracts_the_exact_v2_transcript(self) -> None:
        expected = ("\n".join(self.fixture.transcript_lines) + "\n").encode("ascii")
        self.assertEqual(
            RUNNER.extract_transcript(self.fixture.root / "stdout.log"),
            expected,
        )

    def test_valid_projection_is_deterministic_bounded_and_sanitized(self) -> None:
        first = self.fixture.receipt()
        second = self.fixture.receipt()
        self.assertEqual(first, second)
        self.assertLessEqual(len(first), CHECKER.RECEIPT_MAX_BYTES)
        parsed = json.loads(first)
        self.assertEqual(parsed["schema"], CHECKER.SCHEMA)
        self.assertEqual(parsed["acceptance"]["graceful_shutdowns"], 6)
        self.assertEqual(parsed["acceptance"]["connected_path"], "positive-direct-only-zero-errors")
        self.assertEqual(
            parsed["acceptance"]["connected_reconciliation"],
            {
                "selected_item_transfer": {
                    "offered": 7,
                    "fetched": 7,
                    "inserted": 7,
                    "duplicates": 0,
                },
                "remaining": {"event": 0, "mutable": 0},
                "deferred_lanes": {"event": 0, "mutable": 0},
                "stop_event_inventory": "all-zero",
                "control_counters": "all-zero",
                "blob_counters": "all-zero",
                "contact_stop_aggregation": "exact",
            },
        )
        self.assertEqual(
            parsed["supersedes"],
            {
                "schema": ORACLE_SUPERSEDED_SCHEMA,
                "source_commit": ORACLE_SUPERSEDED_SOURCE_COMMIT,
                "receipt_sha256": ORACLE_SUPERSEDED_RECEIPT_SHA256,
            },
        )
        self.assertEqual(
            parsed["acceptance"]["state"],
            {
                "publications": 4,
                "initial_publications": 2,
                "initial_reducer": "max-id-current-other-concurrent",
                "initial_connected_views": 2,
                "causal_observed_head_and_version_sets": "exact",
                "successor": {
                    "publications": 1,
                    "publisher_role": "node-a",
                    "publisher_counter": 4,
                    "observed_heads": 2,
                    "observed_versions": 2,
                    "current_tombstone": False,
                    "superseded_predecessors": 2,
                    "network_views": 2,
                },
                "tombstone": {
                    "publications": 1,
                    "publisher_role": "node-b",
                    "publisher_counter": 3,
                    "empty_payload_sha256": ORACLE_PAYLOAD_HASHES[
                        ("tombstone", "node-b")
                    ],
                    "observed_heads": 1,
                    "observed_versions": 3,
                    "current_tombstone": True,
                    "superseded_predecessors": 3,
                    "network_views": 2,
                    "peerless_restart_views": 2,
                    "retention_scope": "one-immediate-peerless-restart-observation",
                },
                "causal_views": 6,
            },
        )
        self.assertNotIn(os.fsencode(self.fixture.root), first)
        self.assertNotIn(self.fixture.carriers["node-a"].encode("ascii"), first)
        self.assertNotIn(self.fixture.missions["node-a"].encode("ascii"), first)
        self.assertNotIn(self.fixture.secret, first)
        self.assertNotIn(b"127.0.0.1", first)
        self.assertFalse(CHECKER.contains_exact_scalar(parsed, {"4242"}, {4242}))

    def test_identity_and_authority_domain_mutations_fail_closed(self) -> None:
        self.fixture.mutate_transcript(2, "carrier_id", self.fixture.carriers["node-a"])
        self.assert_rejected("carrier.*distinct|domains overlap")

    def test_disjoint_authority_mutation_fails_closed(self) -> None:
        self.fixture.mutate_transcript(1, "mission_authority", self.fixture.missions["node-a"])
        self.fixture.mutate_transcript(2, "mission_authority", self.fixture.missions["node-a"])
        self.assert_rejected("authority overlaps")

    def test_reciprocal_peer_binding_mutation_fails_closed(self) -> None:
        self.fixture.mutate_transcript(1, "expected_mission_peer", self.fixture.missions["node-a"])
        self.assert_rejected("not reciprocal")

    def test_handle_binding_mutation_fails_closed(self) -> None:
        self.fixture.mutate_transcript(3, "state_identity", self.fixture.missions["node-b"])
        self.assert_rejected("HANDLE.*state_identity")

    def test_publication_publisher_and_counter_mutations_fail_closed(self) -> None:
        self.fixture.mutate_transcript(5, "publisher", self.fixture.missions["node-b"])
        self.assert_rejected("STATE_PUBLICATION.*publisher")

    def test_record_counter_must_follow_state_counter(self) -> None:
        self.fixture.mutate_transcript(9, "counter", "3")
        self.assert_rejected("RECORD_PUBLICATION.*counter")

    def test_fixed_payload_hash_mutation_fails_closed(self) -> None:
        self.fixture.mutate_transcript(6, "payload_sha256", "0" * 64)
        self.assert_rejected("STATE_PUBLICATION.*payload_sha256")

    def test_immediate_state_and_record_retry_mutations_fail_closed(self) -> None:
        self.fixture.mutate_transcript(7, "retry_id", identifier("wrong-state-retry"))
        self.assert_rejected("STATE_RETRY")

    def test_record_order_and_schema_mutations_fail_closed(self) -> None:
        self.fixture.transcript_lines[1], self.fixture.transcript_lines[2] = (
            self.fixture.transcript_lines[2],
            self.fixture.transcript_lines[1],
        )
        self.fixture.refresh_public()
        self.assert_rejected("PARTICIPANT node-a")

    def test_reordered_field_fails_closed(self) -> None:
        parts = self.fixture.transcript_lines[0].split("\t")
        parts[2], parts[3] = parts[3], parts[2]
        self.fixture.transcript_lines[0] = "\t".join(parts)
        self.fixture.refresh_public()
        self.assert_rejected("reordered fields")

    def test_extra_record_field_fails_closed(self) -> None:
        self.fixture.transcript_lines[0] += "\textra=value"
        self.fixture.refresh_public()
        self.assert_rejected("field count")

    def test_non_ascii_transcript_fails_before_projection(self) -> None:
        transcript = self.fixture.root / "transcript.tsv"
        transcript.write_bytes(transcript.read_bytes()[:-1] + b"\xff\n")
        self.assert_rejected("canonical ASCII")

    def test_stdout_byte_cap_fails_closed(self) -> None:
        stdout = self.fixture.root / "stdout.log"
        stdout.write_bytes(b"X" * (CHECKER.STDOUT_MAX_BYTES + 1))
        self.assert_rejected("byte cap")

    def test_state_reducer_requires_maximum_id_current(self) -> None:
        self.fixture.mutate_transcript(19, "current_id", min(self.fixture.state_ids.values()))
        self.assert_rejected("inconsistent current_id")

    def test_state_restart_view_is_independently_checked(self) -> None:
        self.fixture.mutate_transcript(39, "superseded_dispositions", "current,current,current")
        self.assert_rejected("STATE_CAUSAL_VIEW restart")

    def test_successor_must_observe_exact_sorted_initial_heads(self) -> None:
        self.fixture.mutate_transcript(28, "observed_heads", self.fixture.state_ids["node-a"])
        self.assert_rejected("STATE_SUCCESSOR_PUBLICATION.observed_heads")

    def test_successor_must_observe_exact_sorted_initial_versions(self) -> None:
        reversed_versions = ",".join(sorted(self.fixture.state_ids.values(), reverse=True))
        self.fixture.mutate_transcript(28, "observed_versions", reversed_versions)
        self.assert_rejected("STATE_SUCCESSOR_PUBLICATION.observed_versions")

    def test_successor_publisher_counter_and_payload_are_exact(self) -> None:
        self.fixture.mutate_transcript(28, "counter", "3")
        self.assert_rejected("STATE_SUCCESSOR_PUBLICATION.counter")

    def test_successor_publisher_is_node_a(self) -> None:
        self.fixture.mutate_transcript(28, "publisher", self.fixture.missions["node-b"])
        self.assert_rejected("STATE_SUCCESSOR_PUBLICATION.publisher")

    def test_successor_payload_hash_is_exact(self) -> None:
        self.fixture.mutate_transcript(28, "payload_sha256", "0" * 64)
        self.assert_rejected("STATE_SUCCESSOR_PUBLICATION.payload_sha256")

    def test_successor_publication_must_insert(self) -> None:
        self.fixture.mutate_transcript(28, "inserted", "false")
        self.assert_rejected("STATE_SUCCESSOR_PUBLICATION.inserted")

    def test_successor_is_not_a_tombstone(self) -> None:
        self.fixture.mutate_transcript(28, "tombstone", "true")
        self.assert_rejected("STATE_SUCCESSOR_PUBLICATION.tombstone")

    def test_successor_identity_must_not_overlap_any_prior_publication(self) -> None:
        self.fixture.mutate_transcript(28, "id", self.fixture.resolution_id)
        self.assert_rejected("successor identity overlaps")

    def test_successor_retry_is_exact_and_noninserting(self) -> None:
        self.fixture.mutate_transcript(29, "inserted", "true")
        self.assert_rejected("STATE_SUCCESSOR_RETRY")

    def test_successor_retry_preserves_the_successor_identity(self) -> None:
        self.fixture.mutate_transcript(29, "retry_id", identifier("other-successor"))
        self.assert_rejected("STATE_SUCCESSOR_RETRY")

    def test_successor_current_is_checked_on_both_network_peers(self) -> None:
        self.fixture.mutate_transcript(31, "current_id", self.fixture.state_ids["node-a"])
        self.assert_rejected("STATE_CAUSAL_VIEW successor node-b")

    def test_successor_view_requires_both_exact_superseded_versions(self) -> None:
        self.fixture.mutate_transcript(30, "superseded", self.fixture.state_ids["node-a"])
        self.assert_rejected("STATE_CAUSAL_VIEW successor node-a")

    def test_successor_view_requires_exact_current_metadata(self) -> None:
        self.fixture.mutate_transcript(30, "current_publisher", self.fixture.missions["node-b"])
        self.assert_rejected("STATE_CAUSAL_VIEW successor node-a")

    def test_successor_view_requires_current_disposition(self) -> None:
        self.fixture.mutate_transcript(30, "current_disposition", "superseded")
        self.assert_rejected("STATE_CAUSAL_VIEW successor node-a.current_disposition")

    def test_successor_view_requires_superseded_cardinality(self) -> None:
        self.fixture.mutate_transcript(30, "superseded_count", "1")
        self.assert_rejected("STATE_CAUSAL_VIEW successor node-a.superseded_count")

    def test_successor_view_binds_parallel_publisher_counter_and_payload_sets(self) -> None:
        self.fixture.mutate_transcript(
            30,
            "superseded_counters",
            "1,2",
        )
        self.assert_rejected("STATE_CAUSAL_VIEW successor node-a.superseded_counters")

    def test_successor_view_binds_superseded_publishers(self) -> None:
        duplicate = ",".join([self.fixture.missions["node-a"]] * 2)
        self.fixture.mutate_transcript(30, "superseded_publishers", duplicate)
        self.assert_rejected("STATE_CAUSAL_VIEW successor node-a.superseded_publishers")

    def test_successor_view_binds_superseded_payload_hashes(self) -> None:
        self.fixture.mutate_transcript(
            30, "superseded_payload_sha256", ",".join(["0" * 64] * 2)
        )
        self.assert_rejected("STATE_CAUSAL_VIEW successor node-a.superseded_payload_sha256")

    def test_successor_view_binds_current_and_superseded_tombstone_flags(self) -> None:
        self.fixture.mutate_transcript(30, "current_tombstone", "true")
        self.assert_rejected("STATE_CAUSAL_VIEW successor node-a.current_tombstone")

    def test_successor_predecessors_are_not_tombstones(self) -> None:
        self.fixture.mutate_transcript(30, "superseded_tombstones", "true,false")
        self.assert_rejected("STATE_CAUSAL_VIEW successor node-a.superseded_tombstones")

    def test_tombstone_must_observe_only_the_successor_head(self) -> None:
        self.fixture.mutate_transcript(32, "observed_heads", self.fixture.state_ids["node-a"])
        self.assert_rejected("STATE_TOMBSTONE_PUBLICATION.observed_heads")

    def test_tombstone_must_observe_all_three_prior_versions(self) -> None:
        self.fixture.mutate_transcript(32, "observed_versions", self.fixture.successor_id)
        self.assert_rejected("STATE_TOMBSTONE_PUBLICATION.observed_versions")

    def test_tombstone_publisher_and_counter_are_exact(self) -> None:
        self.fixture.mutate_transcript(32, "publisher", self.fixture.missions["node-a"])
        self.assert_rejected("STATE_TOMBSTONE_PUBLICATION.publisher")

    def test_tombstone_counter_follows_node_b_record_publication(self) -> None:
        self.fixture.mutate_transcript(32, "counter", "4")
        self.assert_rejected("STATE_TOMBSTONE_PUBLICATION.counter")

    def test_tombstone_uses_the_sha256_of_an_empty_payload(self) -> None:
        self.fixture.mutate_transcript(32, "payload_sha256", "0" * 64)
        self.assert_rejected("STATE_TOMBSTONE_PUBLICATION.payload_sha256")

    def test_tombstone_publication_flag_is_exact(self) -> None:
        self.fixture.mutate_transcript(32, "tombstone", "false")
        self.assert_rejected("STATE_TOMBSTONE_PUBLICATION.tombstone")

    def test_tombstone_publication_must_insert(self) -> None:
        self.fixture.mutate_transcript(32, "inserted", "false")
        self.assert_rejected("STATE_TOMBSTONE_PUBLICATION.inserted")

    def test_tombstone_identity_must_not_overlap_prior_versions(self) -> None:
        self.fixture.mutate_transcript(32, "id", self.fixture.resolution_id)
        self.assert_rejected("identity domains overlap")

    def test_tombstone_retry_is_exact_and_noninserting(self) -> None:
        self.fixture.mutate_transcript(33, "retry_id", identifier("wrong-tombstone-retry"))
        self.assert_rejected("STATE_TOMBSTONE_RETRY")

    def test_tombstone_retry_must_not_reinsert(self) -> None:
        self.fixture.mutate_transcript(33, "inserted", "true")
        self.assert_rejected("STATE_TOMBSTONE_RETRY")

    def test_tombstone_current_is_checked_on_both_network_peers(self) -> None:
        self.fixture.mutate_transcript(35, "current_tombstone", "false")
        self.assert_rejected("STATE_CAUSAL_VIEW tombstone node-b.current_tombstone")

    def test_tombstone_view_requires_all_three_superseded_versions(self) -> None:
        self.fixture.mutate_transcript(34, "superseded_count", "2")
        self.assert_rejected("STATE_CAUSAL_VIEW tombstone node-a.superseded_count")

    def test_tombstone_view_requires_exact_current_identity(self) -> None:
        self.fixture.mutate_transcript(34, "current_id", self.fixture.successor_id)
        self.assert_rejected("STATE_CAUSAL_VIEW tombstone node-a")

    def test_tombstone_view_binds_all_superseded_ids(self) -> None:
        self.fixture.mutate_transcript(34, "superseded", self.fixture.successor_id)
        self.assert_rejected("STATE_CAUSAL_VIEW tombstone node-a.superseded")

    def test_tombstone_view_binds_superseded_publishers(self) -> None:
        duplicate = ",".join([self.fixture.missions["node-a"]] * 3)
        self.fixture.mutate_transcript(34, "superseded_publishers", duplicate)
        self.assert_rejected("STATE_CAUSAL_VIEW tombstone node-a.superseded_publishers")

    def test_tombstone_view_binds_superseded_counters(self) -> None:
        self.fixture.mutate_transcript(34, "superseded_counters", "2,2,2")
        self.assert_rejected("STATE_CAUSAL_VIEW tombstone node-a.superseded_counters")

    def test_tombstone_view_binds_superseded_payload_hashes(self) -> None:
        self.fixture.mutate_transcript(
            34, "superseded_payload_sha256", ",".join(["0" * 64] * 3)
        )
        self.assert_rejected("STATE_CAUSAL_VIEW tombstone node-a.superseded_payload_sha256")

    def test_tombstone_view_requires_superseded_dispositions(self) -> None:
        self.fixture.mutate_transcript(
            34, "superseded_dispositions", "concurrent,superseded,superseded"
        )
        self.assert_rejected("STATE_CAUSAL_VIEW tombstone node-a.superseded_dispositions")

    def test_tombstone_view_requires_nontombstone_predecessor_flags(self) -> None:
        self.fixture.mutate_transcript(34, "superseded_tombstones", "false,true,false")
        self.assert_rejected("STATE_CAUSAL_VIEW tombstone node-a.superseded_tombstones")

    def test_restart_view_preserves_tombstone_identity_and_empty_payload_hash(self) -> None:
        self.fixture.mutate_transcript(38, "current_payload_sha256", "0" * 64)
        self.assert_rejected("STATE_CAUSAL_VIEW restart node-a")

    def test_restart_view_preserves_current_tombstone_flag(self) -> None:
        self.fixture.mutate_transcript(38, "current_tombstone", "false")
        self.assert_rejected("STATE_CAUSAL_VIEW restart node-a.current_tombstone")

    def test_restart_view_preserves_all_three_superseded_versions(self) -> None:
        self.fixture.mutate_transcript(38, "superseded_count", "2")
        self.assert_rejected("STATE_CAUSAL_VIEW restart node-a.superseded_count")

    def test_record_siblings_must_be_sorted_and_exact(self) -> None:
        reversed_siblings = ",".join(sorted(self.fixture.record_ids.values(), reverse=True))
        self.fixture.mutate_transcript(21, "siblings", reversed_siblings)
        self.assert_rejected("RECORD_CONFLICT")

    def test_record_current_arithmetic_is_checked(self) -> None:
        self.fixture.mutate_transcript(22, "current_counter", "1")
        self.assert_rejected("inconsistent current_counter")

    def test_ordinary_rejection_must_leave_conflict_unchanged(self) -> None:
        self.fixture.mutate_transcript(23, "after_siblings", self.fixture.record_ids["node-a"])
        self.assert_rejected("RECORD_REJECTION")

    def test_resolution_must_observe_both_siblings(self) -> None:
        self.fixture.mutate_transcript(24, "observed_siblings", self.fixture.record_ids["node-a"])
        self.assert_rejected("RECORD_RESOLUTION")

    def test_resolution_counter_and_immediate_retry_are_checked(self) -> None:
        self.fixture.mutate_transcript(24, "counter", "4")
        self.assert_rejected("RECORD_RESOLUTION.counter")

    def test_resolution_retry_must_be_noninserting_and_same_id(self) -> None:
        self.fixture.mutate_transcript(25, "inserted", "true")
        self.assert_rejected("RECORD_RESOLUTION_RETRY immediate")

    def test_resolved_projection_requires_exact_superseded_originals(self) -> None:
        self.fixture.mutate_transcript(27, "superseded", self.fixture.record_ids["node-a"])
        self.assert_rejected("RECORD_RESOLVED connected")

    def test_restart_projection_cannot_reintroduce_conflict(self) -> None:
        self.fixture.mutate_transcript(40, "conflict", "true")
        self.assert_rejected("RECORD_RESOLVED restart")

    def test_post_restart_retry_must_preserve_resolution_identity(self) -> None:
        self.fixture.mutate_transcript(42, "retry_id", identifier("wrong-restart-retry"))
        self.assert_rejected("post_restart")

    def test_peerless_and_restart_contacts_must_be_zero(self) -> None:
        self.fixture.mutate_transcript(13, "contacts", "1")
        self.assert_rejected("zero-contact")

    def test_connected_contacts_must_be_positive_direct_only(self) -> None:
        self.fixture.mutate_transcript(36, "direct_contacts", "0")
        self.assert_rejected("positive direct-only")

    def test_connected_contacts_must_be_equal_paired_sessions(self) -> None:
        self.fixture.mutate_transcript(37, "contacts", "2")
        self.fixture.mutate_transcript(37, "direct_contacts", "2")
        self.assert_rejected("equal paired sessions")

    def test_contact_errors_fail_closed(self) -> None:
        self.fixture.mutate_transcript(37, "contact_errors", "1")
        self.assert_rejected("contact errors")

    def test_runtime_ready_identity_must_cross_bind_transcript(self) -> None:
        self.fixture.mutate_runtime(0, "mission_id", identifier("wrong-ready-mission"))
        self.assert_rejected("does not bind one transcript participant")

    def test_runtime_concurrent_ready_sockets_must_be_distinct(self) -> None:
        self.fixture.mutate_runtime(5, "sockets", "127.0.0.1:40010")
        self.assert_rejected("aliases another concurrent actor bind")

    def test_runtime_contact_must_be_pass_and_direct(self) -> None:
        self.fixture.mutate_runtime(6, "carrier_path", "relay")
        self.assert_rejected("carrier_path")

    def test_runtime_contact_direction_must_match_carrier_initiation(self) -> None:
        first = self.fixture.runtime_lines[6]
        direction = "in" if "direction=out" in first else "out"
        self.fixture.mutate_runtime(6, "direction", direction)
        self.assert_rejected("deterministic carrier initiation")

    def test_runtime_contact_and_stop_path_transitions_are_exact_zero(self) -> None:
        self.fixture.mutate_runtime(6, "carrier_path_transitions", "1")
        self.assert_rejected("carrier_path_transitions")
        self.fixture.mutate_runtime(6, "carrier_path_transitions", "0")
        self.fixture.mutate_runtime(8, "carrier_path_transitions", "1")
        self.assert_rejected("carrier_path_transitions")

    def test_runtime_contact_count_must_equal_stop_and_transcript(self) -> None:
        del self.fixture.runtime_lines[6]
        self.fixture.refresh_public()
        self.assert_rejected("contact count|CONTACT records")

    def test_runtime_all_zero_reconciliation_cannot_claim_convergence(self) -> None:
        zero_transfer = {"offered": "0", "fetched": "0", "inserted": "0"}
        self.fixture.mutate_runtime_fields(6, zero_transfer)
        self.fixture.mutate_runtime_fields(7, zero_transfer)
        self.assert_rejected("reconciliation aggregate")

    def test_runtime_blob_activity_cannot_hide_behind_zero_stop_counters(self) -> None:
        self.fixture.mutate_runtime(6, "blob_bytes_fetched", "1")
        self.assert_rejected("nonzero excluded.*Blob counter")

    def test_new_stop_blob_lifecycle_fields_must_all_be_zero(self) -> None:
        for field in ORACLE_NEW_STOP_BLOB_FIELDS:
            with self.subTest(field=field):
                self.fixture.mutate_runtime(2, field, "1")
                self.assert_rejected(field)
                self.fixture.mutate_runtime(2, field, "0")

    def test_stop_blob_lifecycle_field_order_is_exact(self) -> None:
        parts = self.fixture.runtime_lines[2].split(" ")
        positions = {
            token.partition("=")[0]: index
            for index, token in enumerate(parts[1:], start=1)
        }
        first = positions["blob_acceptance_markers"]
        second = positions["blob_last_acceptance_marker"]
        parts[first], parts[second] = parts[second], parts[first]
        self.fixture.runtime_lines[2] = " ".join(parts)
        self.fixture.refresh_public()
        self.assert_rejected("reordered fields")

    def test_stop_blob_lifecycle_schema_rejects_a_missing_field(self) -> None:
        parts = self.fixture.runtime_lines[2].split(" ")
        parts = [
            token
            for token in parts
            if not token.startswith("blob_network_staging_bytes=")
        ]
        self.fixture.runtime_lines[2] = " ".join(parts)
        self.fixture.refresh_public()
        self.assert_rejected("field count")

    def test_runtime_control_activity_cannot_hide_behind_zero_stop_counters(self) -> None:
        self.fixture.mutate_runtime_fields(
            6,
            {
                "control_offered": "1",
                "control_fetched": "1",
                "control_retained": "1",
                "control_activated": "1",
            },
        )
        self.assert_rejected("nonzero excluded.*control")

    def test_runtime_event_excluded_lane_counters_are_exact_zero(self) -> None:
        self.fixture.mutate_runtime_fields(
            6, {"duplicates": "1", "remaining": "1", "deferred_event_lanes": "1"}
        )
        self.assert_rejected("nonzero excluded Event")

    def test_runtime_reconciliation_is_bound_to_publication_roles(self) -> None:
        first_is_node_a = "offered=4" in self.fixture.runtime_lines[6]
        node_a = {"offered": "4", "fetched": "3", "inserted": "3"}
        node_b = {"offered": "3", "fetched": "4", "inserted": "4"}
        self.fixture.mutate_runtime_fields(6, node_b if first_is_node_a else node_a)
        self.fixture.mutate_runtime_fields(7, node_a if first_is_node_a else node_b)
        self.assert_rejected("publication and resolution arithmetic")

    def test_unexpected_stdout_family_fails_closed(self) -> None:
        self.fixture.runtime_lines.insert(0, "DEBUG status=pass")
        self.fixture.refresh_public()
        self.assert_rejected("unadmitted terminal record family")

    def test_six_shutdowns_four_handles_and_two_reacquisitions_are_exact(self) -> None:
        self.fixture.mutate_transcript(47, "graceful_shutdowns", "5")
        self.assert_rejected("RESULT.graceful_shutdowns")

    def test_closed_handle_operation_is_exact(self) -> None:
        self.fixture.mutate_transcript(16, "operation", "record_resolve")
        self.assert_rejected("CLOSED_HANDLE")

    def test_bind_reacquisition_is_exact(self) -> None:
        self.fixture.mutate_transcript(46, "status", "failed")
        self.assert_rejected("BIND_REACQUIRED")

    def test_unexpected_file_and_directory_fail_closed(self) -> None:
        extra = self.fixture.root / "unexpected"
        extra.write_text("unexpected\n", encoding="ascii")
        extra.chmod(0o600)
        self.assert_rejected("unexpected file")

    def test_symlink_and_hardlink_aliases_fail_closed(self) -> None:
        transcript = self.fixture.root / "transcript.tsv"
        transcript.unlink()
        os.symlink(self.fixture.root / "stdout.log", transcript)
        self.assert_rejected("unsafe type|missing or extra files")

    def test_hardlinked_secret_artifact_fails_closed(self) -> None:
        second = self.fixture.root / "participants/node-b/state/mesh.redb"
        second.unlink()
        os.link(self.fixture.root / "participants/node-a/state/mesh.redb", second)
        self.assert_rejected("hard-link")

    def test_root_directory_and_file_modes_are_exact(self) -> None:
        self.fixture.root.chmod(0o755)
        self.assert_rejected("owner-only mode 0700")

    def test_binary_mode_is_exact(self) -> None:
        (self.fixture.root / "binary/aster-live-mutable-acceptance").chmod(0o600)
        self.assert_rejected("unexpected mode")

    def test_wrong_owner_is_rejected(self) -> None:
        with mock.patch.object(CHECKER.os, "getuid", return_value=os.getuid() + 1):
            self.assert_rejected("not owned")

    def test_secret_contents_are_never_read_or_hashed(self) -> None:
        first = self.fixture.receipt()
        (self.fixture.root / "participants/node-a/state/identity.key").write_bytes(
            b"T" * CHECKER.IDENTITY_BYTES
        )
        mission = self.fixture.root / "participants/node-b/mission.bundle"
        mission.write_bytes(b"M" * mission.stat().st_size)
        store = self.fixture.root / "participants/node-a/state/mesh.redb"
        store.write_bytes(b"R" * store.stat().st_size)
        second = self.fixture.receipt()
        self.assertEqual(first, second)

    def test_secret_artifacts_are_never_opened(self) -> None:
        original_open = os.open
        original_path_open = Path.open
        secret_names = {"mission.bundle", "identity.key", "mesh.redb"}
        secret_paths = {
            self.fixture.root / "participants" / participant / relative
            for participant in ("node-a", "node-b")
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
                raise AssertionError(f"secret artifact was opened through pathlib: {path}")
            return original_path_open(path, *args, **kwargs)

        with (
            mock.patch.object(CHECKER.os, "open", side_effect=guarded_open),
            mock.patch.object(Path, "open", new=guarded_path_open),
        ):
            self.fixture.receipt()

    def test_missing_or_oversized_secret_metadata_fails_closed(self) -> None:
        identity = self.fixture.root / "participants/node-a/state/identity.key"
        identity.write_bytes(b"short")
        self.assert_rejected("identity artifact")

    def test_public_file_mutation_during_validation_is_detected(self) -> None:
        original = CHECKER.validate_transcript

        def mutate(data: bytes):
            result = original(data)
            binary = self.fixture.root / "binary/aster-live-mutable-acceptance"
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
            identity = self.fixture.root / "participants/node-b/state/identity.key"
            identity.unlink()
            identity.write_bytes(self.fixture.secret)
            identity.chmod(0o600)
            return result

        with mock.patch.object(CHECKER, "validate_run_document", side_effect=replace):
            self.assert_rejected("metadata changed during validation")

    def test_binary_and_artifact_hash_mutations_fail_closed(self) -> None:
        self.fixture.run_document["artifacts"]["binary"]["sha256"] = "0" * 64
        self.fixture.write_run_document()
        self.assert_rejected("artifacts.binary.sha256")

    def test_source_commit_tree_and_admitted_hashes_are_bound(self) -> None:
        self.fixture.run_document["source"]["tree"] = "3" * 40
        self.fixture.write_run_document()
        self.assert_rejected("source.tree")

    def test_source_signer_fingerprint_is_bound(self) -> None:
        self.fixture.run_document["source"]["signature"]["fingerprint"] = "B" * 40
        self.fixture.write_run_document()
        self.assert_rejected("signature.fingerprint")

    def test_tool_hash_must_equal_admitted_source_hash(self) -> None:
        self.fixture.run_document["tools"]["checker"]["sha256"] = "0" * 64
        self.fixture.write_run_document()
        self.assert_rejected("tools.checker")

    def test_build_and_run_argv_are_exact(self) -> None:
        self.fixture.run_document["commands"]["build_argv"][0] = "rustc"
        self.fixture.write_run_document()
        self.assert_rejected("release build invocation")

    def test_operator_attested_limitation_is_exact(self) -> None:
        self.fixture.run_document["execution"]["source_binary_execution_link"] = "proven"
        self.fixture.write_run_document()
        self.assert_rejected("source_binary_execution_link")

    def test_run_document_is_canonical_exclusive_json(self) -> None:
        path = self.fixture.root / "run.json"
        document = json.loads(path.read_bytes())
        path.write_text(json.dumps(document, indent=2) + "\n", encoding="ascii")
        self.assert_rejected("compact canonical JSON")

    def test_duplicate_run_json_field_fails_closed(self) -> None:
        path = self.fixture.root / "run.json"
        data = path.read_bytes()
        path.write_bytes(data.replace(b'{"artifacts":', b'{"schema":"duplicate","artifacts":', 1))
        path.chmod(0o600)
        self.assert_rejected("duplicate JSON field")

    def test_receipt_limitations_and_nonclaims_are_byte_exact(self) -> None:
        expected = self.fixture.receipt()
        mutated = json.loads(expected)
        mutated["limitations"][0] = "cryptographically-proven"
        with self.assertRaisesRegex(CHECKER.ReceiptViolation, "differs byte-for-byte"):
            CHECKER.validate_supplied_receipt(CHECKER.canonical_json_bytes(mutated), expected)

    def test_identifier_collision_in_projected_hash_field_fails_closed(self) -> None:
        evidence = CHECKER.validate_raw_root(self.fixture.root, self.fixture.source)
        document = CHECKER.build_receipt(self.fixture.source, evidence)
        document["build"]["executable"]["sha256"] = self.fixture.carriers["node-a"]
        with self.assertRaisesRegex(CHECKER.ReceiptViolation, "parsed identifier"):
            CHECKER.render_receipt(
                document,
                forbidden_values=CHECKER.receipt_forbidden_values(
                    evidence, self.fixture.root
                ),
                forbidden_pids=CHECKER.receipt_forbidden_pids(evidence),
                forbidden_ports=CHECKER.receipt_forbidden_ports(evidence),
            )

    def test_application_id_collision_in_projected_hash_fails_closed(self) -> None:
        evidence = CHECKER.validate_raw_root(self.fixture.root, self.fixture.source)
        document = CHECKER.build_receipt(self.fixture.source, evidence)
        document["build"]["executable"]["sha256"] = self.fixture.resolution_id
        with self.assertRaisesRegex(CHECKER.ReceiptViolation, "parsed identifier"):
            CHECKER.render_receipt(
                document,
                forbidden_values=CHECKER.receipt_forbidden_values(
                    evidence, self.fixture.root
                ),
                forbidden_pids=CHECKER.receipt_forbidden_pids(evidence),
                forbidden_ports=CHECKER.receipt_forbidden_ports(evidence),
            )

    def test_pid_digits_inside_hash_do_not_false_reject(self) -> None:
        evidence = CHECKER.validate_raw_root(self.fixture.root, self.fixture.source)
        document = CHECKER.build_receipt(self.fixture.source, evidence)
        document["build"]["executable"]["sha256"] = "a" * 30 + "4242" + "b" * 30
        encoded = CHECKER.render_receipt(
            document,
            forbidden_values=CHECKER.receipt_forbidden_values(evidence, self.fixture.root),
            forbidden_pids=CHECKER.receipt_forbidden_pids(evidence),
            forbidden_ports=CHECKER.receipt_forbidden_ports(evidence),
        )
        self.assertIn(b"4242", encoded)

    def test_exact_pid_scalar_is_rejected(self) -> None:
        evidence = CHECKER.validate_raw_root(self.fixture.root, self.fixture.source)
        document = CHECKER.build_receipt(self.fixture.source, evidence)
        document["acceptance"]["participants"] = 4242
        with self.assertRaisesRegex(CHECKER.ReceiptViolation, "process identifier scalar"):
            CHECKER.render_receipt(
                document,
                forbidden_values=CHECKER.receipt_forbidden_values(evidence, self.fixture.root),
                forbidden_pids=CHECKER.receipt_forbidden_pids(evidence),
                forbidden_ports=CHECKER.receipt_forbidden_ports(evidence),
            )

    def test_exact_port_scalar_is_rejected_without_substring_false_positive(self) -> None:
        evidence = CHECKER.validate_raw_root(self.fixture.root, self.fixture.source)
        ports = CHECKER.receipt_forbidden_ports(evidence)
        document = CHECKER.build_receipt(self.fixture.source, evidence)
        document["acceptance"]["participants"] = ports[0]
        with self.assertRaisesRegex(CHECKER.ReceiptViolation, "network port scalar"):
            CHECKER.render_receipt(
                document,
                forbidden_values=CHECKER.receipt_forbidden_values(
                    evidence, self.fixture.root
                ),
                forbidden_pids=CHECKER.receipt_forbidden_pids(evidence),
                forbidden_ports=ports,
            )
        document["acceptance"]["participants"] = 2
        document["build"]["executable"]["sha256"] = (
            "a" * 20 + str(ports[0]) + "b" * (44 - len(str(ports[0])))
        )
        CHECKER.render_receipt(
            document,
            forbidden_values=CHECKER.receipt_forbidden_values(
                evidence, self.fixture.root
            ),
            forbidden_pids=CHECKER.receipt_forbidden_pids(evidence),
            forbidden_ports=ports,
        )

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

    def test_receipt_output_is_exclusive_and_named_exactly(self) -> None:
        output = self.fixture.parent / CHECKER.RECEIPT_NAME
        output.write_bytes(b"preexisting\n")
        output.chmod(0o600)
        with self.assertRaisesRegex(CHECKER.ReceiptViolation, "already exists"):
            CHECKER.write_receipt(output, self.fixture.receipt())
        self.assertEqual(output.read_bytes(), b"preexisting\n")
        with self.assertRaisesRegex(CHECKER.ReceiptViolation, "exact filename"):
            CHECKER.write_receipt(self.fixture.parent / "wrong.json", self.fixture.receipt())

    def test_receipt_output_mode_is_exact_under_hostile_umask(self) -> None:
        output = self.fixture.parent / CHECKER.RECEIPT_NAME
        prior_umask = os.umask(0o777)
        try:
            CHECKER.write_receipt(output, self.fixture.receipt())
        finally:
            os.umask(prior_umask)
        self.assertEqual(stat.S_IMODE(output.stat().st_mode), 0o600)

    def test_supplied_receipt_accepts_private_and_checked_in_public_modes(self) -> None:
        supplied = self.fixture.parent / "supplied.json"
        receipt = self.fixture.receipt()
        supplied.write_bytes(receipt)
        for mode in (0o600, 0o644):
            with self.subTest(mode=oct(mode)):
                supplied.chmod(mode)
                self.assertEqual(CHECKER.read_supplied_receipt(supplied), receipt)

    def test_supplied_receipt_rejects_writable_or_executable_public_modes(self) -> None:
        supplied = self.fixture.parent / "supplied.json"
        supplied.write_bytes(self.fixture.receipt())
        for mode in (0o620, 0o602, 0o700, 0o611):
            with self.subTest(mode=oct(mode)):
                supplied.chmod(mode)
                with self.assertRaisesRegex(
                    CHECKER.ReceiptViolation, "unsafe metadata"
                ):
                    CHECKER.read_supplied_receipt(supplied)

    def test_receipt_output_path_replacement_during_write_is_detected(self) -> None:
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

    def test_supplied_receipt_path_replacement_during_read_is_detected(self) -> None:
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

    def test_raw_root_inside_source_is_rejected_even_if_status_is_clean(self) -> None:
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
            self.assertRaisesRegex(CHECKER.ReceiptViolation, "outside the source checkout"),
        ):
            CHECKER.validate_source(source, source / "ignored-raw")

    def test_signature_status_and_fingerprint_fail_closed(self) -> None:
        for malformed in (b"B\x00" + b"A" * 40 + b"\n", b"G\x00\n"):
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
        self.assertEqual(argv[:4], ["/usr/bin/git", "--no-replace-objects", "-c", "gpg.format=ssh"])
        self.assertIn("core.fsmonitor=false", argv)
        self.assertIn("core.hooksPath=/dev/null", argv)
        self.assertLess(argv.index("core.fsmonitor=false"), argv.index("-C"))
        self.assertEqual(environment["GIT_OPTIONAL_LOCKS"], "0")


if __name__ == "__main__":
    unittest.main()
