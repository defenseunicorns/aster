#!/usr/bin/env python3
# Copyright 2026 Defense Unicorns, Inc.
# SPDX-License-Identifier: Apache-2.0
"""Adversarial tests for the Linux Event MVP qualification validator."""

from __future__ import annotations

import json
import copy
import hashlib
import os
from pathlib import Path
import stat
import tempfile
import unittest
from io import BytesIO
from unittest import mock

import linux_event_mvp_qualification.io as qualification_io
import linux_event_mvp_qualification.validator as qualification_validator

from linux_event_mvp_qualification.io import (
    CanonicalJsonError,
    SafeInputError,
    SafeRoot,
    canonical_json_bytes,
    load_canonical_json,
)
from linux_event_mvp_qualification.schema import (
    BODY_SCHEMA_ID,
    CANONICALIZATION_ID,
    REPORT_SCHEMA_ID,
    SCHEMA_PATH,
    PROFILE_DIGEST,
    load_machine_schema,
    machine_schema_digest,
)
from linux_event_mvp_qualification.bindings import populate_binding_chain
from linux_event_mvp_qualification.validator import BundleInputs, validate_bundle
from linux_event_mvp_qualification.cli import main as cli_main


class CanonicalJsonTests(unittest.TestCase):
    def test_serialization_is_sorted_compact_ascii_and_lf_terminated(self) -> None:
        self.assertEqual(
            canonical_json_bytes({"b": 1, "a": "é"}),
            b'{"a":"\\u00e9","b":1}\n',
        )

    def test_loader_rejects_duplicate_keys_and_noncanonical_bytes(self) -> None:
        for raw in (
            b'{"a":1,"a":2}\n',
            b'{"b":1,"a":2}\n',
            b'{"a": 1}\n',
            b'{"a":1}',
            b'{"a":NaN}\n',
        ):
            with self.subTest(raw=raw), self.assertRaises(CanonicalJsonError):
                load_canonical_json(raw, label="fixture", maximum=1024)

    def test_loader_accepts_only_an_object(self) -> None:
        with self.assertRaises(CanonicalJsonError):
            load_canonical_json(b"[]\n", label="fixture", maximum=1024)


class MachineSchemaTests(unittest.TestCase):
    def test_committed_schema_is_canonical_and_exposes_all_document_types(self) -> None:
        raw = SCHEMA_PATH.read_bytes()
        document = load_machine_schema()
        self.assertEqual(canonical_json_bytes(document), raw)
        self.assertEqual(document["$id"], BODY_SCHEMA_ID)
        self.assertEqual(document["x-canonicalization"], CANONICALIZATION_ID)
        self.assertEqual(document["x-report-schema"], REPORT_SCHEMA_ID)
        self.assertEqual(
            set(document["$defs"]),
            {"approval", "candidate_body", "receipt_index", "release_decision"},
        )
        self.assertRegex(machine_schema_digest(), r"\Asha256:[0-9a-f]{64}\Z")
        profile_path = (
            SCHEMA_PATH.parent.parent / "linux-event-mvp-evaluation-profile-v0.1.md"
        )
        self.assertEqual(
            PROFILE_DIGEST,
            f"sha256:{hashlib.sha256(profile_path.read_bytes()).hexdigest()}",
        )

    def test_every_nested_object_and_array_has_an_exact_schema(self) -> None:
        """Break caught: published schema accepts fields the validator rejects."""

        def assert_exact(node: object, path: str) -> None:
            if not isinstance(node, dict):
                return
            if node.get("type") == "object" and "oneOf" not in node:
                self.assertIs(
                    node.get("additionalProperties"),
                    False,
                    f"open object schema at {path}",
                )
                self.assertIsInstance(
                    node.get("properties"), dict, f"missing properties at {path}"
                )
            if node.get("type") == "array":
                self.assertIn("items", node, f"unconstrained array at {path}")
            for keyword in ("properties", "$defs"):
                children = node.get(keyword, {})
                if isinstance(children, dict):
                    for name, child in children.items():
                        assert_exact(child, f"{path}.{name}")
            if "items" in node:
                assert_exact(node["items"], f"{path}[]")
            for keyword in ("allOf", "anyOf", "oneOf"):
                children = node.get(keyword, [])
                if isinstance(children, list):
                    for index, child in enumerate(children):
                        assert_exact(child, f"{path}.{keyword}[{index}]")

        assert_exact(load_machine_schema(), "$")


class SafeRootTests(unittest.TestCase):
    def setUp(self) -> None:
        self.parent = tempfile.TemporaryDirectory()
        self.root = Path(self.parent.name) / "bundle"
        self.root.mkdir(mode=0o700)
        (self.root / "nested").mkdir(mode=0o700)
        self.payload = canonical_json_bytes({"schema": "fixture/v1"})
        (self.root / "nested" / "receipt.json").write_bytes(self.payload)

    def tearDown(self) -> None:
        self.parent.cleanup()

    def test_reads_regular_file_relative_to_retained_root(self) -> None:
        with SafeRoot(self.root) as root:
            result = root.read_file("nested/receipt.json", maximum=1024)
        self.assertEqual(result.data, self.payload)
        self.assertEqual(result.size, len(self.payload))
        self.assertRegex(result.digest, r"\Asha256:[0-9a-f]{64}\Z")

    def test_rejects_absolute_parent_empty_and_dot_components(self) -> None:
        for path in (
            "/etc/passwd",
            "../receipt.json",
            "nested/../receipt.json",
            "nested//receipt.json",
            "nested/./receipt.json",
            "",
        ):
            with self.subTest(path=path), SafeRoot(self.root) as root:
                with self.assertRaises(SafeInputError):
                    root.read_file(path, maximum=1024)

    def test_rejects_symlinks_and_non_regular_files(self) -> None:
        os.symlink("nested/receipt.json", self.root / "link.json")
        os.mkfifo(self.root / "fifo")
        for path in ("link.json", "fifo", "nested"):
            with self.subTest(path=path), SafeRoot(self.root) as root:
                with self.assertRaises(SafeInputError):
                    root.read_file(path, maximum=1024)

    def test_rejects_oversize_file(self) -> None:
        with SafeRoot(self.root) as root, self.assertRaises(SafeInputError):
            root.read_file("nested/receipt.json", maximum=len(self.payload) - 1)

    def test_rejects_file_identity_change_during_read(self) -> None:
        original = qualification_io._same_identity
        regular_comparisons = 0

        def changes_after_open(left, right):
            nonlocal regular_comparisons
            if stat.S_ISREG(left.st_mode):
                regular_comparisons += 1
                return regular_comparisons == 1
            return original(left, right)

        with (
            mock.patch.object(qualification_io, "_same_identity", side_effect=changes_after_open),
            SafeRoot(self.root) as root,
            self.assertRaises(SafeInputError),
        ):
            root.read_file("nested/receipt.json", maximum=1024)


def digest_bytes(data: bytes) -> str:
    return f"sha256:{hashlib.sha256(data).hexdigest()}"


def digest_label(label: str) -> str:
    return digest_bytes(label.encode("ascii"))


def result(receipt_id: str = "evidence") -> dict[str, object]:
    return {"status": "pass", "receipt_id": receipt_id}


def valid_body(index_bytes: bytes) -> dict[str, object]:
    d = digest_label
    nodes = []
    for alias in ("cm4-a", "cm4-b"):
        nodes.append(
            {
                "alias": alias,
                "device_commitment": d(f"{alias}-device"),
                "physical": True,
                "model": "Compute Module 4 Rev 1.1",
                "architecture": "aarch64",
                "image_reference": "2026-06-18",
                "os": "Debian 13 trixie",
                "kernel": "6.18.39+rpt-rpi-v8",
                "systemd": "257.13-1~deb13u1",
                "filesystem": "ext4",
                "nominal_memory_bytes": 1024 * 1024 * 1024,
                "kernel_visible_memory_bytes": 949_702_656,
                "initial_state_free_bytes": 256 * 1024 * 1024,
                "peer_role": "event-participant",
                "artifact_digest": d("complete-artifact-set"),
            }
        )
    workloads = [
        {
            "label": "api_boundary",
            "nodes": ["cm4-a", "cm4-b"],
            "payload_bytes": [0, 4096, 65536],
            "publisher_assignments": ["cm4-a", "cm4-a", "cm4-a"],
            "events_per_node": [3, 0],
            "total_events": 3,
            "rate_per_hour_per_node": 0,
            "duration_seconds": 0,
            "distinct_operations_per_node": [3, 0],
            "exact_retries_per_node": [0, 0],
            "result": result(),
        },
        {
            "label": "two_node_topology",
            "nodes": ["cm4-a", "cm4-b"],
            "payload_bytes": [4096],
            "publisher_assignments": ["cm4-a"],
            "events_per_node": [10, 0],
            "total_events": 10,
            "rate_per_hour_per_node": 3600,
            "duration_seconds": 10,
            "distinct_operations_per_node": [10, 0],
            "exact_retries_per_node": [0, 0],
            "result": result(),
        },
        {
            "label": "offline_soak",
            "nodes": ["cm4-a", "cm4-b"],
            "payload_bytes": [4096],
            "publisher_assignments": ["cm4-a", "cm4-b"],
            "events_per_node": [240, 240],
            "total_events": 480,
            "rate_per_hour_per_node": 10,
            "duration_seconds": 86_400,
            "convergence_seconds": 86_400,
            "distinct_operations_per_node": [240, 240],
            "exact_retries_per_node": [0, 0],
            "result": result(),
        },
        {
            "label": "capacity_warning_probe",
            "nodes": ["cm4-a", "cm4-b"],
            "payload_bytes": [4096],
            "publisher_assignments": ["cm4-a"],
            "events_per_node": [512, 0],
            "total_events": 512,
            "rate_per_hour_per_node": 0,
            "duration_seconds": 0,
            "distinct_operations_per_node": [512, 0],
            "exact_retries_per_node": [1, 0],
            "retry_ledger_growth_per_node": [0, 0],
            "warning_operation_per_node": [512, 0],
            "result": result(),
        },
    ]
    resource_values = {
        "executable_bytes": (16 * 1024 * 1024, "bytes"),
        "steady_rss_bytes": (64 * 1024 * 1024, "bytes"),
        "peak_rss_bytes": (128 * 1024 * 1024, "bytes"),
        "idle_cpu_basis_points": (500, "basis-points-of-one-core"),
        "readiness_milliseconds": (10_000, "milliseconds"),
        "graceful_stop_milliseconds": (30_000, "milliseconds"),
        "initial_state_free_bytes": (256 * 1024 * 1024, "bytes"),
        "state_growth_bytes": (1, "bytes"),
        "final_state_free_bytes": (256 * 1024 * 1024, "bytes"),
        "logical_items": (480, "items"),
        "logical_bytes": (480 * 4096, "bytes"),
        "operation_records": (1024, "records"),
        "energy_millijoules": (1, "millijoules"),
    }
    resources = []
    for alias in ("cm4-a", "cm4-b"):
        for measurement, (value, unit) in resource_values.items():
            resources.append(
                {
                    "node": alias,
                    "measurement": measurement,
                    "value": value,
                    "unit": unit,
                    "procedure_digest": d(f"measure-{measurement}"),
                    "scenario_id": "offline_soak",
                    "start_state_digest": d(f"{alias}-{measurement}-start"),
                    "end_state_digest": d(f"{alias}-{measurement}-end"),
                    "result": result(),
                }
            )
    body: dict[str, object] = {
        "schema": {
            "id": "aster-linux-event-mvp-candidate-body/v0.1",
            "version": "0.1",
            "digest": machine_schema_digest(),
            "canonicalization": CANONICALIZATION_ID,
        },
        "candidate": {
            "id": "synthetic-candidate-not-evidence",
            "revision": 1,
            "checkpoint_date": "2026-09-13",
            "reviewed_at": "2026-09-13T08:00:00Z",
            "claim": "time-bounded non-production Linux Event v0.1 evaluation",
            "non_claims": ["not production qualification", "not signature verification"],
        },
        "source": {
            "commit": "a" * 40,
            "dependency_lock": {
                "format": "cargo-lock-v4",
                "version": "4",
                "path": "Cargo.lock",
                "size": 1,
                "digest": d("lock"),
            },
            "toolchain": {"versions": ["rustc 1.97.1", "go 1.26.7"], "digest": d("toolchain")},
            "configuration": {
                "schema": "aster-agent-config/v1",
                "version": "1",
                "reference": "receipts/config.json",
                "size": 1,
                "digest": d("config"),
            },
            "harness": {
                "source_commit": "b" * 40,
                "version": "1",
                "configuration_digest": d("harness-config"),
            },
        },
        "bindings": {
            "root": d("unset-root"),
            "g2": d("unset-g2"),
            "g3": d("unset-g3"),
            "g4": d("unset-g4"),
            "g5": d("unset-g5"),
            "global_g3": f"produced:{d('g3-attempt')}",
            "complete_artifact_set": d("complete-artifact-set"),
            "scenario_set": d("scenario-set"),
            "device_peer": d("device-peer-binding"),
            "network_conditions": d("network-conditions"),
        },
        "artifact": {
            "architecture": "aarch64",
            "package_architecture": "arm64",
            "package_name": "aster-agent_0.1.0_arm64.deb",
            "produced_at": "2026-09-13T07:30:00Z",
            "package_size": 1,
            "executable_size": 16 * 1024 * 1024,
            "executable_digest": d("executable"),
            "authentication": {"method": "detached-signature", "result": result()},
            "outputs": {
                name: f"produced:{d(name)}"
                for name in (
                    "arm64_package",
                    "package_authentication",
                    "package_manifest",
                    "sbom",
                    "notices",
                    "provenance",
                    "dependency_graph",
                    "complete_artifact_set_manifest",
                )
            },
            "procedures": {
                name: {"version": "1", "digest": d(f"procedure-{name}")}
                for name in ("install_start_health", "restart_upgrade_rollback", "uninstall_state_preservation")
            },
        },
        "prerequisites": {
            "profile_digest": PROFILE_DIGEST,
            "d06": {
                "design_digest": "sha256:30c5dfe71a203fcdd69dd330f9b5c68eeaee5032b624ee41912aa4723a9f853f",
                "amendment_digest": "sha256:549ea3fd5bdfd62c01bab5a8f1adac4b84a2710ab406ea006119c9048e28d4cd",
                "provider_contract": "aster-systemd-credential-store/v2",
            },
            "e01": [
                {"role": role, "disposition": "approve", "produced_at": "2026-09-13T07:00:00Z", "receipt_id": "evidence"}
                for role in ("security", "deployment")
            ],
            "d15": {
                "proposal_digest": "sha256:a6fe15f39fb553f87bc1224fe7f266e7c906d451d8140402d3bc1620011bfa53",
                "approval_digest": "sha256:4edda9457c78d0c1d177590c1583691071e708ccbbace078cc15a82dd9bcac85",
                "roles": ["dependency-license", "legal-compliance", "release"],
                "evaluation_only": True,
                "production_requirement_open": True,
            },
        },
        "provider": {
            "name": "aster-systemd-credential-store",
            "version": "2",
            "source_commit": "a" * 40,
            "architecture": "aarch64",
            "contract_digest": d("provider-contract"),
            "trust_boundary_digest": d("provider-trust-boundary"),
            "administration_artifact_digest": d("credential-admin"),
            "lifecycle": {
                name: result()
                for name in ("install", "startup_load", "bearer_rotation", "provider_rotation", "backup_recovery", "revoke_rekey", "logical_destroy")
            },
        },
        "mission": {
            "authority_commitment": d("mission-authority"),
            "offline_root_digest": d("mission-root"),
            "delegated_signer_digest": d("mission-signer"),
            "delegation_digest": d("delegation"),
            "roster_digest": d("roster"),
            "roster_count": 2,
            "scope_commitment": d("scope"),
            "topic_commitment": d("topic"),
            "semantic_protocol": 6,
            "security_profile": "0x0001",
            "hybrid_suite": "0x0001",
            "unordered_profile_ids": True,
            "no_fallback": True,
            "policy_digest": d("policy"),
            "policy_generation": 1,
            "relay_authority_separate": True,
        },
        "relay": {
            "mode": "direct_only",
            "direct_enabled": True,
            "statement": "relay not used",
            "statement_digest": d("relay-not-used"),
            "receipt_id": "evidence",
        },
        "inventory": {
            "digest": d("inventory"),
            "binding_record_digest": d("device-peer-binding-record"),
            "nodes": nodes,
        },
        "configuration": {
            "discovery": "off",
            "direct_ip": True,
            "manual_peers_per_node": [1, 1],
            "storage_max_items": 10_000,
            "storage_max_payload_bytes": 67_108_864,
            "operations_max_records": 1_000_000,
            "operations_max_logical_bytes": 201_326_592,
            "operations_emergency_reserve": 10_000,
            "operations_active_alias_limit": 64,
            "application_max_connections": 1,
            "max_in_flight_operations": 8,
            "emission_modes": ["normal", "receive_only"],
            "local_clients_per_node": 1,
            "query_page": 16,
            "gap_page": 16,
            "delivery_page": 16,
            "delivery_scan": 128,
            "gap_scan": 128,
            "unacknowledged_deliveries": 256,
            "payload_min_bytes": 0,
            "payload_max_bytes": 65_536,
            "operation_key_min_bytes": 1,
            "operation_key_max_bytes": 256,
            "operation_profile_warning": 512,
            "operation_profile_stop": 1024,
            "mission_publish_seconds": 86_400,
            "mission_convergence_max_seconds": 86_400,
            "focused_test_procedure_digests": [d("focused-tests")],
        },
        "workloads": workloads,
        "acceptance_conditions": [
            {"condition": number, "result": result()} for number in range(1, 14)
        ],
        "resources": resources,
        "evidence": {
            "profile_qualification_index_digest": d("profile-evidence"),
            "component_disposition": "not cited",
            "isolated_engineering_disposition": "not cited",
            "generated_client_contract_receipt_id": "evidence",
            "independent_server_disposition": "not cited",
            "retirement_behavior_class": "component",
            "configured_cap_saturation_class": "isolated-engineering",
        },
        "receipt_index": {
            "reference": "receipt-index.json",
            "size": len(index_bytes),
            "media_type": "application/json",
            "digest": digest_bytes(index_bytes),
        },
        "gates": [],
    }
    gates = []
    for number in range(1, 6):
        gate: dict[str, object] = {
            "gate": f"G{number}",
            "status": "pass",
            "binding": d(f"unset-gate-{number}"),
            "exit_digest": d(f"g{number}-exit"),
            "receipt_id": "evidence",
            "reviewed_at": f"2026-09-13T0{number}:00:00Z",
        }
        if number > 1:
            gate["predecessor_exit_digest"] = d(f"g{number - 1}-exit")
        gates.append(gate)
    body["gates"] = gates
    populate_binding_chain(body)
    return body


def write_valid_bundle(root: Path) -> BundleInputs:
    (root / "receipts").mkdir()
    evidence_bytes = canonical_json_bytes({"schema": "synthetic-evidence-not-qualification/v1"})
    (root / "receipts" / "evidence.json").write_bytes(evidence_bytes)
    index = {
        "schema": "aster-linux-event-mvp-receipt-index/v0.1",
        "candidate_id": "synthetic-candidate-not-evidence",
        "entries": [
            {
                "id": "evidence",
                "root": "bundle",
                "reference": "receipts/evidence.json",
                "size": len(evidence_bytes),
                "media_type": "application/json",
                "digest": digest_bytes(evidence_bytes),
                "producer_id": "synthetic-producer",
                "producer_role": "integration",
                "producer_tool_digest": digest_label("producer-tool"),
                "produced_at": "2026-09-13T00:00:00Z",
                "evidence_type": "profile-qualification",
                "environment_class": "physical-device",
                "environment_digest": digest_label("environment"),
                "claim_digest": digest_label("bounded-claim"),
                "non_claims": ["not production qualification"],
                "verification_procedure_digest": digest_label("verify"),
                "verification_result": "pass",
                "controlled_storage_dependency": False,
            }
        ],
    }
    index_bytes = canonical_json_bytes(index)
    (root / "receipt-index.json").write_bytes(index_bytes)
    body = valid_body(index_bytes)
    body_bytes = canonical_json_bytes(body)
    (root / "candidate-body.json").write_bytes(body_bytes)
    body_digest = digest_bytes(body_bytes)
    approval_paths = []
    approval_digests = []
    roles = (
        "profile-product",
        "security",
        "deployment-os-artifact",
        "integration-device-physical-carrier",
        "event-service-api-runtime",
        "deterministic-gate",
        "dependency-license",
        "legal-compliance",
    )
    for offset, role in enumerate(roles):
        approval = {
            "schema": "aster-linux-event-mvp-candidate-approval/v0.1",
            "role": role,
            "reviewer_id": f"synthetic-{role}",
            "disposition": "approve",
            "produced_at": f"2026-09-13T{10 + offset:02d}:00:00Z",
            "body_digest": body_digest,
            "candidate_id": "synthetic-candidate-not-evidence",
            "schema_digest": machine_schema_digest(),
            "g3_binding": body["bindings"]["global_g3"],
            "signature": {
                "scheme": "reference-only-not-verified",
                "signer_id": f"synthetic-{role}",
                "trust_store_digest": digest_label(f"trust-{role}"),
                "receipt_id": "evidence",
            },
        }
        raw = canonical_json_bytes(approval)
        path = f"approvals/{offset:02d}-{role}.json"
        (root / "approvals").mkdir(exist_ok=True)
        (root / path).write_bytes(raw)
        approval_paths.append(path)
        approval_digests.append(digest_bytes(raw))
    decision = {
        "schema": "aster-linux-event-mvp-release-decision/v0.1",
        "outcome": "issue",
        "reason_digest": digest_label("synthetic-reason"),
        "role_blockers": {},
        "produced_at": "2026-09-13T20:00:00Z",
        "body_digest": body_digest,
        "approval_digests": sorted(approval_digests),
        "candidate_id": "synthetic-candidate-not-evidence",
        "schema_digest": machine_schema_digest(),
        "g3_binding": body["bindings"]["global_g3"],
        "signature": {
            "scheme": "reference-only-not-verified",
            "signer_id": "synthetic-release",
            "trust_store_digest": digest_label("trust-release"),
            "receipt_id": "evidence",
        },
    }
    (root / "release-decision.json").write_bytes(canonical_json_bytes(decision))
    return BundleInputs(
        bundle_root=root,
        body="candidate-body.json",
        index="receipt-index.json",
        approvals=tuple(approval_paths),
        decision="release-decision.json",
        artifact_root=None,
    )


def rebind_bundle(root: Path, inputs: BundleInputs) -> None:
    index_bytes = (root / inputs.index).read_bytes()
    body = json.loads((root / inputs.body).read_bytes())
    body["receipt_index"] = {
        "reference": inputs.index,
        "size": len(index_bytes),
        "media_type": "application/json",
        "digest": digest_bytes(index_bytes),
    }
    populate_binding_chain(body)
    body_bytes = canonical_json_bytes(body)
    (root / inputs.body).write_bytes(body_bytes)
    body_digest = digest_bytes(body_bytes)
    approval_digests = []
    for path in inputs.approvals:
        approval = json.loads((root / path).read_bytes())
        approval["body_digest"] = body_digest
        approval["g3_binding"] = body["bindings"]["global_g3"]
        raw = canonical_json_bytes(approval)
        (root / path).write_bytes(raw)
        approval_digests.append(digest_bytes(raw))
    decision = json.loads((root / inputs.decision).read_bytes())
    decision["body_digest"] = body_digest
    decision["g3_binding"] = body["bindings"]["global_g3"]
    decision["approval_digests"] = sorted(approval_digests)
    (root / inputs.decision).write_bytes(canonical_json_bytes(decision))


class CompleteBundleTests(unittest.TestCase):
    def mutate_body(self, root: Path, inputs: BundleInputs, mutate) -> None:
        body = json.loads((root / inputs.body).read_bytes())
        mutate(body)
        (root / inputs.body).write_bytes(canonical_json_bytes(body))

    def test_complete_synthetic_bundle_is_structurally_conformant(self) -> None:
        with tempfile.TemporaryDirectory() as parent:
            inputs = write_valid_bundle(Path(parent))
            report = validate_bundle(inputs)
        self.assertEqual(report.disposition, "conformant")
        self.assertEqual(report.findings, ())
        self.assertEqual(
            report.non_claim,
            "structural/profile validation only; not qualification or signature verification",
        )
        self.assertEqual(report.to_dict()["validator_schema"], REPORT_SCHEMA_ID)
        self.assertEqual(
            report.to_dict()["signature_authenticity"], "not-assessed"
        )
        self.assertEqual(
            report.to_dict()["signature_reference_status"],
            "signature-reference-present",
        )
        self.assertEqual(
            report.to_dict()["candidate_id_uniqueness"],
            "global candidate-ID uniqueness not assessed",
        )
        self.assertEqual(report.to_bytes(), report.to_bytes())

    def test_source_mutation_breaks_binding_chain(self) -> None:
        with tempfile.TemporaryDirectory() as parent:
            root = Path(parent)
            inputs = write_valid_bundle(root)
            self.mutate_body(root, inputs, lambda body: body["source"].__setitem__("commit", "c" * 40))
            report = validate_bundle(inputs)
        self.assertEqual(report.disposition, "nonconformant")
        self.assertIn("QVB001", tuple(item.code for item in report.findings))
        finding = report.to_dict()["findings"][0]
        self.assertEqual(set(finding), {"code", "field_path", "message", "severity", "source"})
        binding_finding = next(item for item in report.to_dict()["findings"] if item["code"] == "QVB001")
        self.assertEqual(binding_finding["field_path"], "$.bindings.g2")
        finding_keys = [(item.code, item.field_path) for item in report.findings]
        self.assertEqual(len(finding_keys), len(set(finding_keys)))

    def test_candidate_profile_digest_must_match_selected_profile_bytes(self) -> None:
        """Break caught: root binding substitutes the machine-schema digest."""

        with tempfile.TemporaryDirectory() as parent:
            root = Path(parent)
            inputs = write_valid_bundle(root)
            self.mutate_body(
                root,
                inputs,
                lambda body: body["prerequisites"].__setitem__(
                    "profile_digest", "sha256:" + "f" * 64
                ),
            )
            rebind_bundle(root, inputs)
            report = validate_bundle(inputs)
        self.assertEqual(report.disposition, "nonconformant")
        self.assertIn("QVB002", tuple(item.code for item in report.findings))

    def test_unknown_nested_field_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as parent:
            root = Path(parent)
            inputs = write_valid_bundle(root)
            self.mutate_body(root, inputs, lambda body: body["configuration"].__setitem__("max_connections_per_client", 1))
            report = validate_bundle(inputs)
        self.assertIn("QVR002", tuple(item.code for item in report.findings))

    def test_unknown_spare_inventory_shape_is_rejected(self) -> None:
        """Break caught: optional spare inventory bypasses the field allowlist."""

        with tempfile.TemporaryDirectory() as parent:
            root = Path(parent)
            inputs = write_valid_bundle(root)
            self.mutate_body(
                root,
                inputs,
                lambda body: body["inventory"].__setitem__(
                    "spare", {"raw_device_identity": "must-not-be-accepted"}
                ),
            )
            report = validate_bundle(inputs)
        self.assertIn("QVR002", tuple(item.code for item in report.findings))

    def test_wrong_nested_types_are_rejected_without_operational_failure(self) -> None:
        mutations = (
            ("body", lambda body: body.__setitem__("bindings", [])),
            ("approval", lambda approval: approval.__setitem__("signature", [])),
        )
        for target, mutate in mutations:
            with self.subTest(target=target), tempfile.TemporaryDirectory() as parent:
                root = Path(parent)
                inputs = write_valid_bundle(root)
                path = inputs.body if target == "body" else inputs.approvals[0]
                document = json.loads((root / path).read_bytes())
                mutate(document)
                (root / path).write_bytes(canonical_json_bytes(document))
                report = validate_bundle(inputs)
            self.assertEqual(report.disposition, "nonconformant")
            self.assertTrue(any(item.code.startswith("QVR") for item in report.findings))

    def test_null_placeholder_negative_and_boolean_integer_are_rejected(self) -> None:
        mutations = (
            (lambda body: body["candidate"].__setitem__("revision", None), "QVR003"),
            (lambda body: body["provider"].__setitem__("name", "pending"), "QVR003"),
            (lambda body: body["candidate"].__setitem__("revision", -1), "QVR005"),
            (lambda body: body["candidate"].__setitem__("revision", True), "QVR005"),
            (lambda body: body["candidate"].__setitem__("reviewed_at", "2026-99-99T99:99:99Z"), "QVR005"),
        )
        for mutate, expected in mutations:
            with self.subTest(expected=expected), tempfile.TemporaryDirectory() as parent:
                root = Path(parent)
                inputs = write_valid_bundle(root)
                self.mutate_body(root, inputs, mutate)
                report = validate_bundle(inputs)
            self.assertIn(expected, tuple(item.code for item in report.findings))

    def test_missing_indexed_evidence_is_indeterminate(self) -> None:
        with tempfile.TemporaryDirectory() as parent:
            root = Path(parent)
            inputs = write_valid_bundle(root)
            (root / "receipts" / "evidence.json").unlink()
            report = validate_bundle(inputs)
        self.assertEqual(report.disposition, "indeterminate")
        self.assertEqual(tuple(item.code for item in report.findings), ("QVB010",))

    def test_approval_count_limit_is_enforced_before_detached_reads(self) -> None:
        with tempfile.TemporaryDirectory() as parent:
            original = write_valid_bundle(Path(parent))
            inputs = BundleInputs(
                bundle_root=original.bundle_root,
                body=original.body,
                index=original.index,
                approvals=tuple("must-not-be-read.json" for _ in range(65)),
                decision=original.decision,
                artifact_root=original.artifact_root,
            )
            report = validate_bundle(inputs)
        self.assertEqual(report.disposition, "nonconformant")
        self.assertEqual(tuple(item.code for item in report.findings), ("QVS006",))

    def test_actual_referenced_bytes_enforce_aggregate_limit(self) -> None:
        with tempfile.TemporaryDirectory() as parent:
            root = Path(parent)
            inputs = write_valid_bundle(root)
            index = json.loads((root / inputs.index).read_bytes())
            index["entries"][0]["size"] = 0
            (root / inputs.index).write_bytes(canonical_json_bytes(index))
            rebind_bundle(root, inputs)
            with mock.patch.object(
                qualification_validator, "TOTAL_REFERENCED_MAX_BYTES", 1
            ):
                report = validate_bundle(inputs)
        self.assertIn("QVR006", tuple(item.code for item in report.findings))

    def test_workload_resource_approval_and_decision_mutations_are_rejected(self) -> None:
        mutations = (
            ("body", lambda body: body["workloads"][2].__setitem__("events_per_node", [239, 240]), "QVW004"),
            ("body", lambda body: body["resources"][1].__setitem__("value", 64 * 1024 * 1024 + 1), "QVW009"),
            ("approval", lambda approval: approval.__setitem__("candidate_id", "another-synthetic-candidate"), "QVS004"),
            ("decision", lambda decision: decision.__setitem__("approval_digests", list(reversed(decision["approval_digests"]))), "QVS006"),
        )
        for target, mutate, expected in mutations:
            with self.subTest(target=target, expected=expected), tempfile.TemporaryDirectory() as parent:
                root = Path(parent)
                inputs = write_valid_bundle(root)
                path = inputs.body if target == "body" else inputs.approvals[0] if target == "approval" else inputs.decision
                document = json.loads((root / path).read_bytes())
                mutate(document)
                (root / path).write_bytes(canonical_json_bytes(document))
                report = validate_bundle(inputs)
            self.assertEqual(report.disposition, "nonconformant")
            self.assertIn(expected, tuple(item.code for item in report.findings))
            if expected.startswith("QVS"):
                self.assertEqual(
                    report.to_dict()["signature_reference_status"],
                    "signature-reference-binding-invalid",
                )

    def test_every_workload_row_enforces_its_complete_profile_shape(self) -> None:
        mutations = (
            (lambda body: body["workloads"][0].__setitem__("nodes", ["cm4-b", "cm4-a"]), "QVW002"),
            (lambda body: body["workloads"][1].__setitem__("duration_seconds", 9), "QVW003"),
            (lambda body: body["workloads"][2].__setitem__("total_events", 479), "QVW004"),
            (lambda body: body["workloads"][3].__setitem__("payload_bytes", [0]), "QVW005"),
        )
        for mutate, expected in mutations:
            with self.subTest(expected=expected), tempfile.TemporaryDirectory() as parent:
                root = Path(parent)
                inputs = write_valid_bundle(root)
                self.mutate_body(root, inputs, mutate)
                report = validate_bundle(inputs)
            self.assertIn(expected, tuple(item.code for item in report.findings))

    def test_resource_values_require_exact_integer_type_and_unit(self) -> None:
        mutations = (
            lambda body: body["resources"][0].__setitem__("value", True),
            lambda body: body["resources"][0].__setitem__("unit", "kilobytes"),
        )
        for mutate in mutations:
            with self.subTest(mutate=mutate), tempfile.TemporaryDirectory() as parent:
                root = Path(parent)
                inputs = write_valid_bundle(root)
                self.mutate_body(root, inputs, mutate)
                report = validate_bundle(inputs)
            self.assertIn("QVW009", tuple(item.code for item in report.findings))

    def test_issue_requires_approvals_and_exact_signature_reference_metadata(self) -> None:
        mutations = (
            ("approval", lambda record: record.__setitem__("disposition", "refuse"), "QVS006"),
            (
                "approval",
                lambda record: record["signature"].__setitem__("scheme", "claimed-verified"),
                "QVS004",
            ),
            (
                "decision",
                lambda record: record["signature"].__setitem__("scheme", "claimed-verified"),
                "QVS006",
            ),
            (
                "decision",
                lambda record: record.__setitem__("produced_at", "2026-09-13T09:00:00Z"),
                "QVS006",
            ),
        )
        for target, mutate, expected in mutations:
            with self.subTest(target=target, expected=expected), tempfile.TemporaryDirectory() as parent:
                root = Path(parent)
                inputs = write_valid_bundle(root)
                path = inputs.approvals[0] if target == "approval" else inputs.decision
                record = json.loads((root / path).read_bytes())
                mutate(record)
                (root / path).write_bytes(canonical_json_bytes(record))
                if target == "approval":
                    decision = json.loads((root / inputs.decision).read_bytes())
                    decision["approval_digests"] = sorted(
                        digest_bytes((root / approval).read_bytes())
                        for approval in inputs.approvals
                    )
                    (root / inputs.decision).write_bytes(canonical_json_bytes(decision))
                report = validate_bundle(inputs)
            self.assertIn(expected, tuple(item.code for item in report.findings))

    def test_noncanonical_digest_in_detached_decision_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as parent:
            root = Path(parent)
            inputs = write_valid_bundle(root)
            decision = json.loads((root / inputs.decision).read_bytes())
            decision["reason_digest"] = "sha256:" + "A" * 64
            (root / inputs.decision).write_bytes(canonical_json_bytes(decision))
            report = validate_bundle(inputs)
        self.assertIn("QVR004", tuple(item.code for item in report.findings))

    def test_capacity_probe_rejects_two_publisher_reinterpretation(self) -> None:
        with tempfile.TemporaryDirectory() as parent:
            root = Path(parent)
            inputs = write_valid_bundle(root)
            def mutate(body):
                probe = body["workloads"][3]
                probe["publisher_assignments"] = ["cm4-a", "cm4-b"]
                probe["events_per_node"] = [512, 512]
                probe["total_events"] = 1024
                probe["distinct_operations_per_node"] = [512, 512]
                probe["exact_retries_per_node"] = [1, 1]
                probe["warning_operation_per_node"] = [512, 512]
            self.mutate_body(root, inputs, mutate)
            report = validate_bundle(inputs)
        self.assertIn("QVW005", tuple(item.code for item in report.findings))

    def test_manual_peer_counts_accept_zero_through_nineteen_only(self) -> None:
        with tempfile.TemporaryDirectory() as parent:
            root = Path(parent)
            inputs = write_valid_bundle(root)
            body = json.loads((root / inputs.body).read_bytes())
            body["configuration"]["manual_peers_per_node"] = [0, 19]
            populate_binding_chain(body)
            (root / inputs.body).write_bytes(canonical_json_bytes(body))
            rebind_bundle(root, inputs)
            self.assertEqual(validate_bundle(inputs).disposition, "conformant")

            body = json.loads((root / inputs.body).read_bytes())
            body["configuration"]["manual_peers_per_node"] = [20, 0]
            populate_binding_chain(body)
            (root / inputs.body).write_bytes(canonical_json_bytes(body))
            rebind_bundle(root, inputs)
            report = validate_bundle(inputs)
        self.assertIn("QVP005", tuple(item.code for item in report.findings))

    def test_issue_rejects_failed_gate_and_unindexed_result_reference(self) -> None:
        mutations = (
            (lambda body: body["gates"][3].__setitem__("status", "fail"), "QVG006"),
            (lambda body: body["provider"]["lifecycle"]["startup_load"].__setitem__("receipt_id", "absent"), "QVG001"),
        )
        for mutate, expected in mutations:
            with self.subTest(expected=expected), tempfile.TemporaryDirectory() as parent:
                root = Path(parent)
                inputs = write_valid_bundle(root)
                self.mutate_body(root, inputs, mutate)
                report = validate_bundle(inputs)
            self.assertIn(expected, tuple(item.code for item in report.findings))

    def test_profile_identity_platform_provider_and_capacity_deviations(self) -> None:
        mutations = (
            (lambda body: body["inventory"]["nodes"][0].__setitem__("model", "Compute Module 5"), "QVP002"),
            (lambda body: body["inventory"]["nodes"][0].__setitem__("nominal_memory_bytes", 1024 * 1024 * 1024 - 1), "QVP002"),
            (lambda body: body["configuration"].__setitem__("operation_profile_warning", 513), "QVP009"),
            (lambda body: body["artifact"].__setitem__("executable_size", 16 * 1024 * 1024 + 1), "QVB008"),
            (lambda body: body["prerequisites"]["d06"].__setitem__("provider_contract", "aster-systemd-credential-store/v1"), "QVS002"),
            (lambda body: body["prerequisites"]["d15"].__setitem__("evaluation_only", False), "QVS003"),
            (lambda body: body["mission"].__setitem__("semantic_protocol", 5), "QVP011"),
            (lambda body: body["relay"].__setitem__("statement", "relay maybe used"), "QVP007"),
        )
        for mutate, expected in mutations:
            with self.subTest(expected=expected), tempfile.TemporaryDirectory() as parent:
                root = Path(parent)
                inputs = write_valid_bundle(root)
                self.mutate_body(root, inputs, mutate)
                report = validate_bundle(inputs)
            self.assertIn(expected, tuple(item.code for item in report.findings))

    def test_report_does_not_copy_candidate_or_receipt_values(self) -> None:
        with tempfile.TemporaryDirectory() as parent:
            inputs = write_valid_bundle(Path(parent))
            report_bytes = validate_bundle(inputs).to_bytes()
        self.assertNotIn(b"synthetic-candidate-not-evidence", report_bytes)
        self.assertNotIn(b"synthetic-producer", report_bytes)
        self.assertNotIn(b"receipts/evidence.json", report_bytes)

    def test_failed_workload_can_be_preserved_by_structurally_conformant_defer(self) -> None:
        with tempfile.TemporaryDirectory() as parent:
            root = Path(parent)
            inputs = write_valid_bundle(root)
            body = json.loads((root / inputs.body).read_bytes())
            body["workloads"][2]["result"]["status"] = "fail"
            body["gates"][4]["status"] = "fail"
            populate_binding_chain(body)
            body_bytes = canonical_json_bytes(body)
            (root / inputs.body).write_bytes(body_bytes)
            body_digest = digest_bytes(body_bytes)
            approval_digests = []
            for path in inputs.approvals:
                approval = json.loads((root / path).read_bytes())
                approval["body_digest"] = body_digest
                approval["g3_binding"] = body["bindings"]["global_g3"]
                raw = canonical_json_bytes(approval)
                (root / path).write_bytes(raw)
                approval_digests.append(digest_bytes(raw))
            decision = json.loads((root / inputs.decision).read_bytes())
            decision["outcome"] = "defer"
            decision["body_digest"] = body_digest
            decision["approval_digests"] = sorted(approval_digests)
            (root / inputs.decision).write_bytes(canonical_json_bytes(decision))
            report = validate_bundle(inputs)
        self.assertEqual(report.disposition, "conformant")
        self.assertEqual(report.findings, ())

    def test_defer_preserves_typed_blocker_for_unreached_final_role(self) -> None:
        with tempfile.TemporaryDirectory() as parent:
            root = Path(parent)
            original = write_valid_bundle(root)
            body = json.loads((root / original.body).read_bytes())
            body["workloads"][2]["result"]["status"] = "fail"
            body["gates"][4]["status"] = "fail"
            populate_binding_chain(body)
            (root / original.body).write_bytes(canonical_json_bytes(body))
            rebind_bundle(root, original)
            inputs = BundleInputs(
                bundle_root=original.bundle_root,
                body=original.body,
                index=original.index,
                approvals=original.approvals[:-1],
                decision=original.decision,
                artifact_root=None,
            )
            decision = json.loads((root / inputs.decision).read_bytes())
            decision["outcome"] = "defer"
            decision["approval_digests"] = sorted(
                digest_bytes((root / path).read_bytes()) for path in inputs.approvals
            )
            decision["role_blockers"] = {
                "legal-compliance": f"not-run:blocked-at-G5:{body['gates'][4]['exit_digest']}"
            }
            (root / inputs.decision).write_bytes(canonical_json_bytes(decision))
            self.assertEqual(validate_bundle(inputs).disposition, "conformant")

            decision["role_blockers"]["legal-compliance"] = (
                f"not-run:blocked-at-G5:{digest_label('unrelated-failure')}"
            )
            (root / inputs.decision).write_bytes(canonical_json_bytes(decision))
            report = validate_bundle(inputs)
        self.assertIn("QVG004", tuple(item.code for item in report.findings))

    def test_validation_has_no_network_subprocess_or_write_side_effects(self) -> None:
        with tempfile.TemporaryDirectory() as parent:
            inputs = write_valid_bundle(Path(parent))
            real_open = os.open

            def read_only_open(path, flags, *args, **kwargs):
                forbidden = os.O_WRONLY | os.O_RDWR | os.O_CREAT | os.O_TRUNC | os.O_APPEND
                if flags & forbidden:
                    raise AssertionError("validator attempted a filesystem write")
                return real_open(path, flags, *args, **kwargs)

            with (
                mock.patch("os.open", side_effect=read_only_open),
                mock.patch("os.mkdir", side_effect=AssertionError("mkdir side effect")),
                mock.patch("os.unlink", side_effect=AssertionError("unlink side effect")),
                mock.patch("os.rename", side_effect=AssertionError("rename side effect")),
                mock.patch("socket.socket", side_effect=AssertionError("network side effect")),
                mock.patch("subprocess.Popen", side_effect=AssertionError("subprocess side effect")),
            ):
                report = validate_bundle(inputs)
        self.assertEqual(report.disposition, "conformant")

    def test_explicit_artifact_root_remains_open_for_indexed_reads(self) -> None:
        with tempfile.TemporaryDirectory() as parent:
            root = Path(parent)
            inputs = write_valid_bundle(root)
            index = json.loads((root / inputs.index).read_bytes())
            index["entries"][0]["root"] = "artifact"
            (root / inputs.index).write_bytes(canonical_json_bytes(index))
            inputs = BundleInputs(
                bundle_root=inputs.bundle_root,
                body=inputs.body,
                index=inputs.index,
                approvals=inputs.approvals,
                decision=inputs.decision,
                artifact_root=root,
            )
            rebind_bundle(root, inputs)
            report = validate_bundle(inputs)
        self.assertEqual(report.disposition, "conformant")

    def test_one_customer_controlled_pinned_relay_is_valid_alternative(self) -> None:
        with tempfile.TemporaryDirectory() as parent:
            root = Path(parent)
            inputs = write_valid_bundle(root)
            body = json.loads((root / inputs.body).read_bytes())
            body["relay"] = {
                "mode": "direct_plus_one_pinned_relay",
                "direct_enabled": True,
                "relay_id_commitment": digest_label("relay-id"),
                "customer_controlled": True,
                "preference": "direct_preferred",
                "der_trust_root_digests": [digest_label("relay-root")],
                "configuration_digest": digest_label("relay-config"),
                "placement_digest": digest_label("relay-placement"),
                "loss_recovery_receipt_id": "evidence",
            }
            populate_binding_chain(body)
            (root / inputs.body).write_bytes(canonical_json_bytes(body))
            rebind_bundle(root, inputs)
            report = validate_bundle(inputs)
        self.assertEqual(report.disposition, "conformant")


class CliTests(unittest.TestCase):
    def arguments(self, inputs: BundleInputs) -> list[str]:
        args = [
            "--bundle-root", os.fspath(inputs.bundle_root),
            "--body", inputs.body,
            "--index", inputs.index,
        ]
        for approval in inputs.approvals:
            args.extend(("--approval", approval))
        args.extend(("--decision", inputs.decision))
        return args

    def test_public_exit_codes_and_single_sanitized_report(self) -> None:
        with tempfile.TemporaryDirectory() as parent:
            root = Path(parent)
            inputs = write_valid_bundle(root)
            output = BytesIO()
            self.assertEqual(cli_main(self.arguments(inputs), stdout=output), 0)
            report = json.loads(output.getvalue())
            self.assertEqual(report["disposition"], "conformant")

            (root / "receipts" / "evidence.json").unlink()
            self.assertEqual(cli_main(self.arguments(inputs), stdout=BytesIO()), 3)

        with tempfile.TemporaryDirectory() as parent:
            root = Path(parent)
            inputs = write_valid_bundle(root)
            body = json.loads((root / inputs.body).read_bytes())
            body["configuration"]["query_page"] = 17
            (root / inputs.body).write_bytes(canonical_json_bytes(body))
            self.assertEqual(cli_main(self.arguments(inputs), stdout=BytesIO()), 2)

    def test_unexpected_operational_fault_is_exit_70(self) -> None:
        output = BytesIO()
        with mock.patch(
            "linux_event_mvp_qualification.cli.validate_bundle",
            side_effect=RuntimeError("sensitive internal detail"),
        ):
            exit_code = cli_main(
                ["--bundle-root", "/unused", "--body", "body", "--index", "index", "--decision", "decision"],
                stdout=output,
            )
        self.assertEqual(exit_code, 70)
        self.assertNotIn(b"sensitive internal detail", output.getvalue())


if __name__ == "__main__":
    unittest.main()
