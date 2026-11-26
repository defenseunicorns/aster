#!/usr/bin/env python3
# Copyright 2026 Defense Unicorns, Inc.
# SPDX-License-Identifier: Apache-2.0
"""Falsification tests for the selected N=32 retained-run validator."""

from __future__ import annotations

import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import tempfile
import unittest
from unittest import mock


CHECKER_PATH = Path(__file__).with_name("check-selected-n32-receipt.py")
SPEC = importlib.util.spec_from_file_location("selected_n32_receipt", CHECKER_PATH)
if SPEC is None or SPEC.loader is None:
    raise RuntimeError(f"cannot load {CHECKER_PATH}")
CHECKER = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(CHECKER)


def identifier(label: str) -> str:
    return hashlib.sha256(label.encode("ascii")).hexdigest()


def line(prefix: str, keys: tuple[str, ...], values: dict[str, str]) -> str:
    if set(keys) != set(values):
        missing = set(keys) - set(values)
        extra = set(values) - set(keys)
        raise AssertionError(f"fixture fields differ: missing={missing} extra={extra}")
    return f"{prefix} " + " ".join(f"{key}={values[key]}" for key in keys)


class Fixture:
    def __init__(self, parent: Path) -> None:
        self.parent = parent
        self.root = parent / "run"
        self.logs = self.root / "logs"
        self.stdout = parent / "demo.stdout"
        self.stderr = parent / "demo.stderr"
        self.binary = parent / "aster"
        self.binary_data = b"synthetic selected N=32 executable\n"
        self.binary_sha256 = hashlib.sha256(self.binary_data).hexdigest()
        self.ping_transfer = identifier("ping-transfer")
        self.ping_semantic = identifier("ping-semantic")
        self.pong_transfer = identifier("pong-transfer")
        self.pong_semantic = identifier("pong-semantic")
        self.authority = identifier("mission-authority")
        self.secret = b"S" * CHECKER.IDENTITY_BYTES
        self.source = {
            "commit": "1" * 40,
            "tree": "2" * 40,
            "commit_signature": "verified",
            "checkout_head": "exact",
            "worktree": "not-validator-derived",
            "cargo_lock_sha256": "3" * 64,
            "requirements_sha256": "4" * 64,
        }
        self.root.mkdir()
        self.logs.mkdir()
        for node in range(CHECKER.NODE_COUNT):
            state = self.root / f"node-{node}"
            state.mkdir()
            artifacts = {
                "identity.key": self.secret,
                "mesh.redb": f"synthetic-store-{node}\n".encode("ascii"),
                "mission.unprotected-reference.bundle": (
                    f"synthetic-mission-{node}\n".encode("ascii")
                ),
            }
            for name, content in artifacts.items():
                retained = state / name
                retained.write_bytes(content)
                retained.chmod(0o600)
        self.binary.write_bytes(self.binary_data)
        self.binary.chmod(0o700)
        self.stderr.write_bytes(b"")
        self.stdout.write_text(self.outer_stdout(), encoding="utf-8")
        self.write_child_logs()

    @staticmethod
    def carrier(node: int) -> str:
        return identifier(f"carrier-{node}")

    @staticmethod
    def mission(node: int) -> str:
        return identifier(f"mission-{node}")

    @staticmethod
    def socket(node: int) -> str:
        return f"127.0.0.1:{40_000 + node}"

    def outer_stdout(self) -> str:
        output = [
            line(
                "SUBSCRIPTIONS",
                CHECKER.SUBSCRIPTION_KEYS,
                {
                    "status": "seeded",
                    "consume": "2",
                    "carry": "30",
                    "selectors": "32",
                    "interest_exchange": "mission-protected",
                    "lanes": "receiver-directed",
                },
            )
        ]
        phases = CHECKER.expected_phases()
        for phase in phases[:33]:
            edges = "not-applicable" if phase["kind"] == "publish" else "verified"
            output.append(
                line(
                    "PHASE",
                    CHECKER.PHASE_KEYS,
                    {
                        "status": "pass",
                        "name": phase["name"],
                        "processes": str(len(phase["nodes"])),
                        "carrier_authenticated_edges": edges,
                        "mission_authenticated_edges": edges,
                        "provisioning": "unprotected-reference",
                    },
                )
            )
        output.append(
            line(
                "PING",
                CHECKER.PING_KEYS,
                {
                    "status": "received",
                    "emitted_by": "origin-process",
                    "producer_state": "node-0",
                    "destination_state": "node-31",
                    "transfer_id": self.ping_transfer,
                    "semantic_id": self.ping_semantic,
                    "producer_process_absent": "true",
                    "source_authenticated": "true",
                    "ttl": "none",
                },
            )
        )
        for phase in phases[33:64]:
            output.append(
                line(
                    "PHASE",
                    CHECKER.PHASE_KEYS,
                    {
                        "status": "pass",
                        "name": phase["name"],
                        "processes": "2",
                        "carrier_authenticated_edges": "verified",
                        "mission_authenticated_edges": "verified",
                        "provisioning": "unprotected-reference",
                    },
                )
            )
        output.extend(
            [
                line(
                    "RELAY",
                    CHECKER.RELAY_KEYS,
                    {
                        "status": "pass",
                        "intermediates": "30",
                        "exact_forward": "true",
                        "content_access": "denied",
                        "semantic_acceptance": "none",
                    },
                ),
                line(
                    "PONG",
                    CHECKER.PONG_KEYS,
                    {
                        "status": "received",
                        "emitted_by": "destination-process",
                        "producer_state": "node-31",
                        "destination_state": "node-0",
                        "correlation_semantic_id": self.ping_semantic,
                        "transfer_id": self.pong_transfer,
                        "semantic_id": self.pong_semantic,
                        "source_authenticated": "true",
                        "causal_observation": "verified",
                        "ttl": "none",
                    },
                ),
                line(
                    "PHASE",
                    CHECKER.PHASE_KEYS,
                    {
                        "status": "pass",
                        "name": "noop",
                        "processes": "32",
                        "carrier_authenticated_edges": "verified",
                        "mission_authenticated_edges": "verified",
                        "provisioning": "unprotected-reference",
                    },
                ),
                line(
                    "DEMO_RESULT",
                    CHECKER.RESULT_KEYS,
                    {
                        "status": "pass",
                        "scenario": "ping-pong",
                        "nodes": "32",
                        "processes": "158",
                        "contacts": "real-iroh",
                        "mission_auth": "hybrid-pq",
                        "provisioning": "unprotected-reference",
                        "stores": "independent-redb",
                        "reconciliation": "negentropy",
                        "producer_process_absent": "true",
                        "restarts": "pass",
                        "atomic_reaction": "pass",
                        "equal_inventory_noop": "pass",
                        "transfers_each": "2",
                        "semantics": "source-authenticated-event",
                        "emitted_by": "running-node-processes",
                        "payload_blind_relays": "pass",
                        "ttl": "durable-none",
                        "root": CHECKER.receipt_path(self.root),
                    },
                ),
            ]
        )
        if len(output) != 70:
            raise AssertionError("synthetic outer receipt has the wrong line count")
        return "\n".join(output) + "\n"

    def ready(self, spec: dict[str, object], pid: int) -> str:
        node = int(spec["node"])
        peers = 0
        if spec["kind"] == "transfer":
            peers = 1
        elif spec["kind"] == "noop":
            peers = 1 if node in {0, CHECKER.NODE_COUNT - 1} else 2
        application = "relay"
        if spec["name"] == "ping-publish" or (spec["name"] == "noop" and node == 0):
            application = "ping-emitter"
        elif spec["name"] == "pong-publish" or (
            spec["name"] == "noop" and node == CHECKER.NODE_COUNT - 1
        ):
            application = "pong-responder"
        return line(
            "READY",
            CHECKER.READY_KEYS,
            {
                "selected": "true",
                "pid": str(pid),
                "carrier_id": self.carrier(node),
                "mission_id": self.mission(node),
                "mission_authority": self.authority,
                "sockets": self.socket(node),
                "state": CHECKER.receipt_path(self.root / f"node-{node}"),
                "peers": str(peers),
                "application": application,
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
        node: int,
        peer: int,
        *,
        offered: int = 0,
        fetched: int = 0,
        inserted: int = 0,
    ) -> str:
        direction = "out" if self.carrier(node) < self.carrier(peer) else "in"
        return line(
            "CONTACT",
            CHECKER.CONTACT_KEYS,
            {
                "direction": direction,
                "carrier_peer": self.carrier(peer),
                "mission_peer": self.mission(peer),
                "rounds": "18",
                "control_offered": "0",
                "control_fetched": "0",
                "control_retained": "0",
                "control_duplicates": "0",
                "control_activated": "0",
                "control_remaining": "0",
                "offered": str(offered),
                "fetched": str(fetched),
                "inserted": str(inserted),
                "duplicates": "0",
                "remaining": "0",
                "deferred_event_lanes": "0",
                "mutable_remaining": "0",
                "deferred_mutable_lanes": "0",
                "blob_ranges_fetched": "0",
                "blob_bytes_fetched": "0",
                "blob_remaining": "0",
                "blob_deferred": "0",
                "handshake_frames": "4",
                "handshake_bytes": "22874",
                "protected_frames": "100",
                "protected_bytes": "6941",
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
        )

    def application(self, spec: dict[str, object]) -> str | None:
        name = str(spec["name"])
        node = int(spec["node"])
        status: str | None = None
        kind: str | None = None
        if name == "ping-publish":
            status, kind = "emitted", "ping"
        elif name == "pong-publish":
            status, kind = "emitted", "pong"
        elif name == "noop" and node == 0:
            status, kind = "existing", "ping"
        elif name == "noop" and node == CHECKER.NODE_COUNT - 1:
            status, kind = "existing", "pong"
        if status is None or kind is None:
            return None
        if kind == "ping":
            return line(
                "APPLICATION",
                CHECKER.PING_APPLICATION_KEYS,
                {
                    "status": status,
                    "kind": kind,
                    "transfer_id": self.ping_transfer,
                    "semantic_id": self.ping_semantic,
                    "publisher": self.mission(0),
                    "source_authenticated": "true",
                    "ttl": "none",
                },
            )
        return line(
            "APPLICATION",
            CHECKER.PONG_APPLICATION_KEYS,
            {
                "status": status,
                "kind": kind,
                "transfer_id": self.pong_transfer,
                "semantic_id": self.pong_semantic,
                "publisher": self.mission(CHECKER.NODE_COUNT - 1),
                "correlation_semantic_id": self.ping_semantic,
                "ping_publisher": self.mission(0),
                "source_authenticated": "true",
                "causal_observation": "verified",
                "ttl": "none",
            },
        )

    def stop(self, spec: dict[str, object], contacts: int) -> str:
        node = int(spec["node"])
        noop = spec["kind"] == "noop"
        endpoint = node in {0, CHECKER.NODE_COUNT - 1}
        events = 2 if noop and endpoint else 0
        markers = events
        cached = 2 if noop and not endpoint else 0
        return line(
            "STOP",
            CHECKER.STOP_KEYS,
            {
                "lifecycle": "complete",
                "sync_status": "contacts_observed" if contacts else "no_successful_contact",
                "carrier_id": self.carrier(node),
                "mission_id": self.mission(node),
                "contacts": str(contacts),
                "contact_errors": "0",
                "direct_contacts": str(contacts),
                "relay_contacts": "0",
                "unknown_path_contacts": "0",
                "carrier_path_transitions": "0",
                "carrier_path_transition_saturations": "0",
                "path_observation": "not-authorization",
                "events": str(events),
                "event_acceptance_markers": str(markers),
                "route_cached_events": str(cached),
                "controls": "0",
                "applied_controls": "0",
                "pending_controls": "0",
                "control_highwater": "0",
                "blobs": "0",
                "pending_blobs": "0",
                "blob_ranges_fetched": "0",
                "blob_bytes_fetched": "0",
                "blob_remaining": "0",
                "blob_deferred": "0",
                "mission_auth": "hybrid-pq",
                "provisioning": "unprotected-reference",
                "semantics": "source-authenticated-event",
                "reconciliation_classes": "event,state,record,blob-v5",
                "controls_semantics": "source-authenticated-flash",
            },
        )

    def write_child_logs(self) -> None:
        for execution, (name, spec) in enumerate(CHECKER.expected_log_specs().items()):
            node = int(spec["node"])
            records = [self.ready(spec, 10_000 + execution)]
            application = self.application(spec)
            if application is not None:
                records.append(application)
            contacts: list[str] = []
            if spec["kind"] == "transfer":
                peer = int(spec["destination"] if node == spec["source"] else spec["source"])
                contacts.append(
                    self.contact(
                        node,
                        peer,
                        offered=1 if node == spec["source"] else 0,
                        fetched=1 if node == spec["destination"] else 0,
                        inserted=1 if node == spec["destination"] else 0,
                    )
                )
            elif spec["kind"] == "noop":
                for peer in (node - 1, node + 1):
                    if 0 <= peer < CHECKER.NODE_COUNT:
                        contacts.append(self.contact(node, peer))
            records.extend(contacts)
            records.append(self.stop(spec, len(contacts)))
            (self.logs / name).write_text("\n".join(records) + "\n", encoding="utf-8")
            (self.logs / name.removesuffix(".log")).with_suffix(".err").write_bytes(b"")

    def operator(self) -> dict[str, object]:
        return {
            "kind": "operator-recorded-provenance",
            "build_command": CHECKER.EXPECTED_BUILD_COMMAND,
            "run_argv_redacted": (
                "/usr/bin/time -l target/release/aster demo --nodes 32 --root <run-root>"
            ),
            "run_argv_sha256": identifier("fixture-run-argv"),
            "redirections": {"stdout": "demo.stdout", "stderr": "demo.stderr"},
            "wrapper_exit_code": 0,
            "host_os": "Darwin",
            "host_arch": "arm64",
            "rustc_version": CHECKER.EXPECTED_RUSTC_VERSION,
            "rustc_commit": CHECKER.EXPECTED_RUSTC_COMMIT,
            "build_target": CHECKER.EXPECTED_BUILD_TARGET,
            "worktree_clean_at_build_and_run": True,
            "cryptographic_source_binary_execution_link": "not-proven",
        }

    def receipt(self) -> bytes:
        binary = CHECKER.validate_binary(
            self.binary, self.binary_sha256, len(self.binary_data)
        )
        run, _ = CHECKER.validate_run_root(self.root, self.stdout, self.stderr)
        return CHECKER.render_receipt(
            CHECKER.build_receipt(self.source, binary, run, self.operator())
        )


class SelectedN32ReceiptTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary_directory = tempfile.TemporaryDirectory()
        self.fixture = Fixture(Path(self.temporary_directory.name))

    def tearDown(self) -> None:
        self.temporary_directory.cleanup()

    def test_minimum_valid_fixture_is_deterministic_and_bounded(self) -> None:
        first = self.fixture.receipt()
        second = self.fixture.receipt()
        self.assertEqual(first, second)
        self.assertLessEqual(len(first), CHECKER.RECEIPT_MAX_BYTES)
        parsed = json.loads(first)
        self.assertEqual(parsed["scenario"]["nodes"], 32)
        self.assertEqual(parsed["scenario"]["phases"], 65)
        self.assertEqual(parsed["scenario"]["processes"], 158)
        self.assertEqual(parsed["scenario"]["distinct_process_ids"], 158)
        self.assertEqual(parsed["scenario"]["noop_distinct_process_ids"], 32)
        self.assertEqual(parsed["evidence"]["children"]["stderr_bytes"], 0)
        self.assertEqual(parsed["evidence"]["children"]["noop_authenticated_edges"], 31)

    def test_truncated_child_log_fails_closed(self) -> None:
        retained = self.fixture.logs / "noop-node-0.log"
        retained.write_bytes(retained.read_bytes()[:-1])
        with self.assertRaisesRegex(CHECKER.ReceiptViolation, "truncated"):
            self.fixture.receipt()

    def test_missing_child_artifact_fails_closed(self) -> None:
        (self.fixture.logs / "noop-node-0.err").unlink()
        with self.assertRaisesRegex(CHECKER.ReceiptViolation, "missing"):
            self.fixture.receipt()

    def test_unexpected_duplicate_equivalent_artifact_fails_closed(self) -> None:
        (self.fixture.logs / "noop-node-0-copy.log").write_bytes(b"")
        with self.assertRaisesRegex(CHECKER.ReceiptViolation, "unexpected artifact"):
            self.fixture.receipt()

    def test_duplicate_or_wrong_phase_fails_closed(self) -> None:
        text = self.fixture.stdout.read_text(encoding="utf-8")
        text = text.replace(
            "name=ping-forward-0-to-1",
            "name=ping-publish",
            1,
        )
        self.fixture.stdout.write_text(text, encoding="utf-8")
        with self.assertRaisesRegex(CHECKER.ReceiptViolation, "unexpected name"):
            self.fixture.receipt()

    def test_wrong_noop_process_count_fails_closed(self) -> None:
        text = self.fixture.stdout.read_text(encoding="utf-8")
        text = text.replace(
            "name=noop processes=32",
            "name=noop processes=31",
            1,
        )
        self.fixture.stdout.write_text(text, encoding="utf-8")
        with self.assertRaisesRegex(CHECKER.ReceiptViolation, "unexpected processes"):
            self.fixture.receipt()

    def test_duplicate_noop_process_identifier_fails_closed(self) -> None:
        first = self.fixture.logs / "noop-node-0.log"
        second = self.fixture.logs / "noop-node-1.log"
        first_pid = first.read_text(encoding="utf-8").splitlines()[0].split(" pid=")[1].split(" ")[0]
        text = second.read_text(encoding="utf-8")
        text = re.sub(r" pid=[0-9]+ ", f" pid={first_pid} ", text, count=1)
        second.write_text(text, encoding="utf-8")
        with self.assertRaisesRegex(CHECKER.ReceiptViolation, "32 distinct"):
            self.fixture.receipt()

    def test_zero_process_identifier_fails_closed(self) -> None:
        retained = self.fixture.logs / "noop-node-0.log"
        text = retained.read_text(encoding="utf-8")
        text = re.sub(r" pid=[0-9]+ ", " pid=0 ", text, count=1)
        retained.write_text(text, encoding="utf-8")
        with self.assertRaisesRegex(CHECKER.ReceiptViolation, "positive process"):
            self.fixture.receipt()

    def test_duplicate_cross_phase_process_identifier_fails_closed(self) -> None:
        first = self.fixture.logs / "ping-forward-0-to-1-node-0.log"
        second = self.fixture.logs / "pong-return-1-to-0-node-0.log"
        first_pid = first.read_text(encoding="utf-8").splitlines()[0].split(" pid=")[1].split(" ")[0]
        text = second.read_text(encoding="utf-8")
        text = re.sub(r" pid=[0-9]+ ", f" pid={first_pid} ", text, count=1)
        second.write_text(text, encoding="utf-8")
        with self.assertRaisesRegex(CHECKER.ReceiptViolation, "158 distinct"):
            self.fixture.receipt()

    def test_wrong_binary_hash_fails_closed(self) -> None:
        with self.assertRaisesRegex(CHECKER.ReceiptViolation, "SHA-256"):
            CHECKER.validate_binary(
                self.fixture.binary,
                "0" * 64,
                len(self.fixture.binary_data),
            )

    def test_wrong_safe_transcript_manifest_hash_fails_closed(self) -> None:
        with self.assertRaisesRegex(CHECKER.ReceiptViolation, "transcript manifest"):
            CHECKER.validate_run_root(
                self.fixture.root,
                self.fixture.stdout,
                self.fixture.stderr,
                "0" * 64,
            )

    def test_outer_evidence_cap_fails_before_parsing(self) -> None:
        self.fixture.stdout.write_bytes(b"x" * (CHECKER.STDOUT_MAX_BYTES + 1))
        with self.assertRaisesRegex(CHECKER.ReceiptViolation, "byte cap"):
            self.fixture.receipt()

    def test_nonempty_child_stderr_is_unclassified_and_fails(self) -> None:
        (self.fixture.logs / "noop-node-0.err").write_text(
            "unexpected diagnostic\n", encoding="utf-8"
        )
        with self.assertRaisesRegex(CHECKER.ReceiptViolation, "unclassified"):
            self.fixture.receipt()

    def test_nonzero_noop_counter_fails_closed(self) -> None:
        retained = self.fixture.logs / "noop-node-0.log"
        text = retained.read_text(encoding="utf-8").replace(
            " offered=0 fetched=0 inserted=0 duplicates=0 ",
            " offered=1 fetched=0 inserted=0 duplicates=0 ",
            1,
        )
        retained.write_text(text, encoding="utf-8")
        with self.assertRaisesRegex(CHECKER.ReceiptViolation, "nonzero equal-inventory"):
            self.fixture.receipt()

    def test_secret_bearing_symlink_cannot_substitute_for_evidence(self) -> None:
        retained = self.fixture.logs / "noop-node-0.err"
        retained.unlink()
        os.symlink(self.fixture.root / "node-0" / "identity.key", retained)
        with self.assertRaisesRegex(CHECKER.ReceiptViolation, "plain regular file"):
            self.fixture.receipt()

    def test_secret_state_is_neither_read_nor_bound_into_receipt_hashes(self) -> None:
        first = self.fixture.receipt()
        self.assertNotIn(self.fixture.secret.rstrip(), first)
        self.assertNotIn(os.fsencode(self.fixture.root), first)
        self.assertNotIn(self.fixture.carrier(0).encode("ascii"), first)
        (self.fixture.root / "node-0" / "identity.key").write_bytes(
            b"T" * CHECKER.IDENTITY_BYTES
        )
        second = self.fixture.receipt()
        self.assertEqual(first, second)

    def test_missing_state_artifact_fails_closed(self) -> None:
        (self.fixture.root / "node-0" / "mesh.redb").unlink()
        with self.assertRaisesRegex(CHECKER.ReceiptViolation, "three expected"):
            self.fixture.receipt()

    def test_extra_state_artifact_fails_closed(self) -> None:
        extra = self.fixture.root / "node-0" / "unexpected.secret"
        extra.write_bytes(b"unexpected\n")
        extra.chmod(0o600)
        with self.assertRaisesRegex(CHECKER.ReceiptViolation, "three expected"):
            self.fixture.receipt()

    def test_hard_linked_state_artifact_fails_closed(self) -> None:
        target = self.fixture.root / "node-0" / "mesh.redb"
        linked = self.fixture.root / "node-1" / "mesh.redb"
        linked.unlink()
        os.link(target, linked)
        with self.assertRaisesRegex(CHECKER.ReceiptViolation, "hard-link"):
            self.fixture.receipt()

    def test_overpermissive_state_artifact_fails_closed(self) -> None:
        retained = self.fixture.root / "node-0" / "identity.key"
        retained.chmod(0o644)
        with self.assertRaisesRegex(CHECKER.ReceiptViolation, "broader than 0600"):
            self.fixture.receipt()

    def test_overpermissive_retained_parent_fails_closed(self) -> None:
        self.fixture.parent.chmod(0o755)
        with self.assertRaisesRegex(CHECKER.ReceiptViolation, "exact mode 0700"):
            self.fixture.receipt()

    @unittest.skipUnless(hasattr(os, "getuid"), "requires a Unix user identifier")
    def test_wrong_retained_parent_owner_fails_closed(self) -> None:
        with mock.patch.object(CHECKER.os, "getuid", return_value=os.getuid() + 1):
            with self.assertRaisesRegex(CHECKER.ReceiptViolation, "not owned"):
                self.fixture.receipt()

    def test_receipt_output_cap_fails_closed(self) -> None:
        binary = CHECKER.validate_binary(
            self.fixture.binary,
            self.fixture.binary_sha256,
            len(self.fixture.binary_data),
        )
        run, _ = CHECKER.validate_run_root(
            self.fixture.root, self.fixture.stdout, self.fixture.stderr
        )
        receipt = CHECKER.build_receipt(
            self.fixture.source, binary, run, self.fixture.operator()
        )
        with mock.patch.object(CHECKER, "RECEIPT_MAX_BYTES", 32):
            with self.assertRaisesRegex(CHECKER.ReceiptViolation, "output cap"):
                CHECKER.render_receipt(receipt)

    def test_receipt_output_is_exclusive_and_never_overwritten(self) -> None:
        output = self.fixture.parent / "receipt.json"
        output.write_bytes(b"preexisting\n")
        with self.assertRaisesRegex(CHECKER.ReceiptViolation, "already exists"):
            CHECKER.write_receipt(output, self.fixture.receipt())
        self.assertEqual(output.read_bytes(), b"preexisting\n")

    def test_unknown_outer_stderr_classification_fails_closed(self) -> None:
        self.fixture.stderr.write_text("warning: not time output\n", encoding="utf-8")
        with self.assertRaisesRegex(CHECKER.ReceiptViolation, "bounded classification"):
            self.fixture.receipt()

    def test_nonzero_operator_wrapper_exit_fails_closed(self) -> None:
        with self.assertRaisesRegex(CHECKER.ReceiptViolation, "nonzero"):
            CHECKER.validate_operator_attestation(
                CHECKER.EXPECTED_BUILD_COMMAND,
                (
                    "/usr/bin/time -l target/release/aster demo --nodes 32 --root "
                    f"{CHECKER.receipt_path(self.fixture.root)}"
                ),
                1,
                CHECKER.EXPECTED_HOST_OS,
                CHECKER.EXPECTED_HOST_ARCH,
                CHECKER.EXPECTED_RUSTC_VERSION,
                CHECKER.EXPECTED_RUSTC_COMMIT,
                CHECKER.EXPECTED_BUILD_TARGET,
                True,
                self.fixture.root,
            )

    def test_missing_clean_worktree_attestation_fails_closed(self) -> None:
        with (
            mock.patch.object(
                CHECKER.platform, "system", return_value=CHECKER.EXPECTED_HOST_OS
            ),
            mock.patch.object(
                CHECKER.platform, "machine", return_value=CHECKER.EXPECTED_HOST_ARCH
            ),
            self.assertRaisesRegex(CHECKER.ReceiptViolation, "clean worktree"),
        ):
            CHECKER.validate_operator_attestation(
                CHECKER.EXPECTED_BUILD_COMMAND,
                (
                    "/usr/bin/time -l target/release/aster demo --nodes 32 --root "
                    f"{CHECKER.receipt_path(self.fixture.root)}"
                ),
                0,
                CHECKER.EXPECTED_HOST_OS,
                CHECKER.EXPECTED_HOST_ARCH,
                CHECKER.EXPECTED_RUSTC_VERSION,
                CHECKER.EXPECTED_RUSTC_COMMIT,
                CHECKER.EXPECTED_BUILD_TARGET,
                False,
                self.fixture.root,
            )


if __name__ == "__main__":
    unittest.main()
