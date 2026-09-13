# Copyright 2026 Defense Unicorns, Inc.
# SPDX-License-Identifier: Apache-2.0
"""Read-only Linux Event MVP qualification bundle validator."""

from __future__ import annotations

from contextlib import ExitStack
from dataclasses import dataclass
from datetime import datetime
import re
from pathlib import Path
from typing import Any

from .bindings import expected_binding_chain
from .io import CanonicalJsonError, SafeInputError, SafeRoot, load_canonical_json
from .model import Finding, ValidationReport, build_report
from .schema import (
    APPROVAL_SCHEMA,
    BODY_DOCUMENT_SCHEMA,
    CANONICALIZATION_ID,
    DECISION_SCHEMA,
    INDEX_SCHEMA,
    machine_schema_digest,
)


BODY_MAX_BYTES = 4 * 1024 * 1024
INDEX_MAX_BYTES = 8 * 1024 * 1024
DETACHED_MAX_BYTES = 256 * 1024
ARTIFACT_MAX_BYTES = 128 * 1024 * 1024
TOTAL_REFERENCED_MAX_BYTES = 512 * 1024 * 1024
MAX_INDEX_ENTRIES = 4096
MAX_APPROVALS = 64
DIGEST = re.compile(r"sha256:[0-9a-f]{64}\Z")
COMMIT = re.compile(r"[0-9a-f]{40}\Z")
UTC = re.compile(r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z\Z")
PRODUCED = re.compile(r"produced:sha256:[0-9a-f]{64}\Z")
CODE_PATHS = {
    "QVB001": "$.bindings.g2",
    "QVB002": "$.bindings.root",
    "QVB003": "$.bindings.global_g3",
    "QVB004": "$.bindings.global_g3",
    "QVB005": "$.artifact.outputs",
    "QVB008": "$.artifact",
    "QVB010": "$.receipt_index",
    "QVB011": "$.candidate.id",
    "QVB012": "$.receipt_index",
    "QVP001": "$.inventory.nodes",
    "QVP002": "$.inventory.nodes",
    "QVP005": "$.configuration.manual_peers_per_node",
    "QVP007": "$.relay",
    "QVP009": "$.configuration",
    "QVP011": "$.mission",
    "QVG001": "$.results",
    "QVG004": "$.release_decision.role_blockers",
    "QVG005": "$.gates",
    "QVG006": "$.gates",
    "QVG015": "$.bindings",
    "QVG016": "$.receipt_index.entries",
    "QVS002": "$.prerequisites.e01",
    "QVS003": "$.prerequisites.d15",
    "QVS004": "$.approvals",
    "QVS006": "$.release_decision",
    "QVS012": "$.prerequisites.e01",
    "QVW001": "$.workloads",
    "QVW002": "$.workloads.api_boundary",
    "QVW003": "$.workloads.two_node_topology",
    "QVW004": "$.workloads.offline_soak",
    "QVW005": "$.workloads.capacity_warning_probe",
    "QVW009": "$.resources",
}


@dataclass(frozen=True)
class BundleInputs:
    bundle_root: Path
    body: str
    index: str
    approvals: tuple[str, ...]
    decision: str
    artifact_root: Path | None


def _finding(code: str, message: str, *, unresolved: bool = False) -> Finding:
    return Finding(
        code=code,
        message=message,
        field_path=CODE_PATHS.get(code, "$"),
        unresolved=unresolved,
    )


def _is_utc(value: Any) -> bool:
    if not isinstance(value, str) or UTC.fullmatch(value) is None:
        return False
    try:
        datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ")
    except ValueError:
        return False
    return True


def _keys(
    value: Any,
    expected: set[str],
    findings: list[Finding],
    code: str,
) -> bool:
    if not isinstance(value, dict) or set(value) != expected:
        findings.append(_finding(code, "document shape does not match the frozen schema"))
        return False
    return True


def _same_json_type_and_value(actual: Any, expected: Any) -> bool:
    if type(actual) is not type(expected):
        return False
    if isinstance(expected, list):
        return len(actual) == len(expected) and all(
            _same_json_type_and_value(left, right)
            for left, right in zip(actual, expected)
        )
    return actual == expected


def _validate_scalar_completion(value: Any, findings: list[Finding]) -> None:
    incomplete = False
    invalid_number = False

    def visit(item: Any) -> None:
        nonlocal incomplete, invalid_number
        if item is None or (
            isinstance(item, str)
            and item in ("", "unknown", "pending", "scheduled", "warning")
        ):
            incomplete = True
        elif isinstance(item, int) and not isinstance(item, bool) and item < 0:
            invalid_number = True
        elif isinstance(item, dict):
            for child in item.values():
                visit(child)
        elif isinstance(item, list):
            for child in item:
                visit(child)

    visit(value)
    if incomplete:
        findings.append(_finding("QVR003", "a required value is null, empty, or a placeholder"))
    if invalid_number:
        findings.append(_finding("QVR005", "a numeric value is outside the nonnegative integer grammar"))


def _validate_digest_grammar(value: Any, findings: list[Finding]) -> None:
    invalid = False

    def valid_digest(item: Any) -> bool:
        return isinstance(item, str) and DIGEST.fullmatch(item) is not None

    def visit(item: Any) -> None:
        nonlocal invalid
        if isinstance(item, dict):
            for key, child in item.items():
                if key == "approval_digests":
                    if not isinstance(child, list) or any(
                        not valid_digest(entry) for entry in child
                    ):
                        invalid = True
                elif key == "digest" or key.endswith("_digest") or key.endswith("_commitment"):
                    if not valid_digest(child):
                        invalid = True
                else:
                    visit(child)
        elif isinstance(item, list):
            for child in item:
                visit(child)

    visit(value)
    if isinstance(value, dict):
        bindings = value.get("bindings")
        if isinstance(bindings, dict):
            for key in ("root", "g2", "g3", "g4", "g5", "complete_artifact_set", "scenario_set", "device_peer", "network_conditions"):
                if not valid_digest(bindings.get(key)):
                    invalid = True
    if invalid:
        findings.append(_finding("QVR004", "an immutable digest or commitment is noncanonical"))


def _receipt_ids(index: dict[str, Any], findings: list[Finding]) -> dict[str, dict[str, Any]]:
    entries = index.get("entries")
    if not isinstance(entries, list) or not 1 <= len(entries) <= MAX_INDEX_ENTRIES:
        findings.append(_finding("QVR005", "receipt index count is outside the frozen limit"))
        return {}
    result: dict[str, dict[str, Any]] = {}
    references: set[tuple[str, str]] = set()
    digests: set[str] = set()
    for entry in entries:
        if not isinstance(entry, dict) or not isinstance(entry.get("id"), str):
            findings.append(_finding("QVG016", "receipt index entry shape is invalid"))
            continue
        identity = entry["id"]
        reference_key = (entry.get("root"), entry.get("reference"))
        digest = entry.get("digest")
        if identity in result or reference_key in references or digest in digests:
            findings.append(_finding("QVR001", "receipt index contains a duplicate identity or binding"))
            continue
        result[identity] = entry
        references.add(reference_key)
        digests.add(digest)
        if (
            not _is_utc(entry.get("produced_at"))
            or entry.get("evidence_type")
            not in {
                "profile-qualification",
                "component",
                "isolated-engineering",
                "generated-client-contract",
                "independent-server",
            }
            or entry.get("environment_class")
            not in {
                "same-host-software",
                "virtual-machine",
                "network-namespace",
                "physical-device",
            }
            or not isinstance(entry.get("non_claims"), list)
            or not entry["non_claims"]
            or entry.get("verification_result") not in ("pass", "fail")
        ):
            findings.append(_finding("QVG016", "receipt provenance metadata is incomplete"))
    return result


def _validate_body_shapes(body: dict[str, Any], findings: list[Finding]) -> None:
    _keys(body.get("schema"), {"id", "version", "digest", "canonicalization"}, findings, "QVR002")
    _keys(body.get("candidate"), {"id", "revision", "checkpoint_date", "reviewed_at", "claim", "non_claims"}, findings, "QVR002")
    source = body.get("source")
    if _keys(source, {"commit", "dependency_lock", "toolchain", "configuration", "harness"}, findings, "QVR002"):
        _keys(source["dependency_lock"], {"format", "version", "path", "size", "digest"}, findings, "QVR002")
        _keys(source["toolchain"], {"versions", "digest"}, findings, "QVR002")
        _keys(source["configuration"], {"schema", "version", "reference", "size", "digest"}, findings, "QVR002")
        _keys(source["harness"], {"source_commit", "version", "configuration_digest"}, findings, "QVR002")
    _keys(body.get("bindings"), {"root", "g2", "g3", "g4", "g5", "global_g3", "complete_artifact_set", "scenario_set", "device_peer", "network_conditions"}, findings, "QVR002")
    artifact = body.get("artifact")
    if _keys(artifact, {"architecture", "package_architecture", "package_name", "package_size", "produced_at", "executable_size", "executable_digest", "authentication", "outputs", "procedures"}, findings, "QVR002"):
        _keys(artifact["authentication"], {"method", "result"}, findings, "QVR002")
        _keys(artifact["outputs"], {"arm64_package", "package_authentication", "package_manifest", "sbom", "notices", "provenance", "dependency_graph", "complete_artifact_set_manifest"}, findings, "QVR002")
        if isinstance(artifact["procedures"], dict):
            _keys(artifact["procedures"], {"install_start_health", "restart_upgrade_rollback", "uninstall_state_preservation"}, findings, "QVR002")
            for procedure in artifact["procedures"].values():
                _keys(procedure, {"version", "digest"}, findings, "QVR002")
    prerequisites = body.get("prerequisites")
    if _keys(prerequisites, {"d06", "e01", "d15"}, findings, "QVR002"):
        _keys(prerequisites["d06"], {"design_digest", "amendment_digest", "provider_contract"}, findings, "QVR002")
        _keys(prerequisites["d15"], {"proposal_digest", "approval_digest", "roles", "evaluation_only", "production_requirement_open"}, findings, "QVR002")
        if isinstance(prerequisites["e01"], list):
            for approval in prerequisites["e01"]:
                _keys(approval, {"role", "disposition", "produced_at", "receipt_id"}, findings, "QVR002")
    provider = body.get("provider")
    if _keys(provider, {"name", "version", "source_commit", "architecture", "contract_digest", "trust_boundary_digest", "administration_artifact_digest", "lifecycle"}, findings, "QVR002"):
        _keys(provider["lifecycle"], {"install", "startup_load", "bearer_rotation", "provider_rotation", "backup_recovery", "revoke_rekey", "logical_destroy"}, findings, "QVR002")
    _keys(body.get("mission"), {"authority_commitment", "offline_root_digest", "delegated_signer_digest", "delegation_digest", "roster_digest", "roster_count", "scope_commitment", "topic_commitment", "semantic_protocol", "security_profile", "hybrid_suite", "unordered_profile_ids", "no_fallback", "policy_digest", "policy_generation", "relay_authority_separate"}, findings, "QVR002")
    relay = body.get("relay")
    relay_keys = (
        {"mode", "direct_enabled", "statement", "statement_digest", "receipt_id"}
        if isinstance(relay, dict) and relay.get("mode") == "direct_only"
        else {"mode", "direct_enabled", "relay_id_commitment", "customer_controlled", "preference", "der_trust_root_digests", "configuration_digest", "placement_digest", "loss_recovery_receipt_id"}
    )
    _keys(relay, relay_keys, findings, "QVR002")
    inventory = body.get("inventory")
    inventory_valid = isinstance(inventory, dict) and set(inventory) in (
        {"digest", "binding_record_digest", "nodes"},
        {"digest", "binding_record_digest", "nodes", "spare"},
    )
    if not inventory_valid:
        findings.append(_finding("QVR002", "document shape does not match the frozen schema"))
    if inventory_valid and isinstance(inventory["nodes"], list):
        node_keys = {"alias", "device_commitment", "physical", "model", "architecture", "image_reference", "os", "kernel", "systemd", "filesystem", "nominal_memory_bytes", "kernel_visible_memory_bytes", "initial_state_free_bytes", "peer_role", "artifact_digest"}
        for node in inventory["nodes"]:
            _keys(node, node_keys, findings, "QVR002")
    _keys(body.get("configuration"), {"discovery", "direct_ip", "manual_peers_per_node", "storage_max_items", "storage_max_payload_bytes", "operations_max_records", "operations_max_logical_bytes", "operations_emergency_reserve", "operations_active_alias_limit", "application_max_connections", "max_in_flight_operations", "emission_modes", "local_clients_per_node", "query_page", "gap_page", "delivery_page", "delivery_scan", "gap_scan", "unacknowledged_deliveries", "payload_min_bytes", "payload_max_bytes", "operation_key_min_bytes", "operation_key_max_bytes", "operation_profile_warning", "operation_profile_stop", "mission_publish_seconds", "mission_convergence_max_seconds", "focused_test_procedure_digests"}, findings, "QVR002")
    workload_base = {"label", "nodes", "payload_bytes", "publisher_assignments", "events_per_node", "total_events", "rate_per_hour_per_node", "duration_seconds", "distinct_operations_per_node", "exact_retries_per_node", "result"}
    for workload in body.get("workloads", ()) if isinstance(body.get("workloads"), list) else ():
        extras = set()
        if workload.get("label") == "offline_soak":
            extras.add("convergence_seconds")
        if workload.get("label") == "capacity_warning_probe":
            extras.update(("retry_ledger_growth_per_node", "warning_operation_per_node"))
        _keys(workload, workload_base | extras, findings, "QVR002")
    for condition in body.get("acceptance_conditions", ()) if isinstance(body.get("acceptance_conditions"), list) else ():
        _keys(condition, {"condition", "result"}, findings, "QVR002")
    resource_keys = {"node", "measurement", "value", "unit", "procedure_digest", "scenario_id", "start_state_digest", "end_state_digest", "result"}
    for resource in body.get("resources", ()) if isinstance(body.get("resources"), list) else ():
        _keys(resource, resource_keys, findings, "QVR002")
    _keys(body.get("evidence"), {"profile_qualification_index_digest", "component_disposition", "isolated_engineering_disposition", "generated_client_contract_receipt_id", "independent_server_disposition", "retirement_behavior_class", "configured_cap_saturation_class"}, findings, "QVR002")
    _keys(body.get("receipt_index"), {"reference", "size", "media_type", "digest"}, findings, "QVR002")
    for gate in body.get("gates", ()) if isinstance(body.get("gates"), list) else ():
        expected = {"gate", "status", "binding", "exit_digest", "receipt_id", "reviewed_at"}
        if gate.get("gate") != "G1":
            expected.add("predecessor_exit_digest")
        _keys(gate, expected, findings, "QVR002")
    results: list[Any] = []
    if isinstance(artifact, dict) and isinstance(artifact.get("authentication"), dict):
        results.append(artifact["authentication"].get("result"))
    if isinstance(provider, dict) and isinstance(provider.get("lifecycle"), dict):
        results.extend(provider["lifecycle"].values())
    results.extend(item.get("result") for item in body.get("workloads", ()) if isinstance(item, dict))
    results.extend(item.get("result") for item in body.get("acceptance_conditions", ()) if isinstance(item, dict))
    results.extend(item.get("result") for item in body.get("resources", ()) if isinstance(item, dict))
    for result in results:
        _keys(result, {"status", "receipt_id"}, findings, "QVR002")


def _validate_index_shapes(index: dict[str, Any], findings: list[Finding]) -> None:
    entry_keys = {"id", "root", "reference", "size", "media_type", "digest", "producer_id", "producer_role", "producer_tool_digest", "produced_at", "evidence_type", "environment_class", "environment_digest", "claim_digest", "non_claims", "verification_procedure_digest", "verification_result", "controlled_storage_dependency"}
    for entry in index.get("entries", ()) if isinstance(index.get("entries"), list) else ():
        _keys(entry, entry_keys, findings, "QVR002")


def _validate_detached_shapes(records: list[dict[str, Any]], decision: dict[str, Any], findings: list[Finding]) -> None:
    approval_keys = {"schema", "role", "reviewer_id", "disposition", "produced_at", "body_digest", "candidate_id", "schema_digest", "g3_binding", "signature"}
    decision_keys = {"schema", "outcome", "reason_digest", "role_blockers", "produced_at", "body_digest", "approval_digests", "candidate_id", "schema_digest", "g3_binding", "signature"}
    signature_keys = {"scheme", "signer_id", "trust_store_digest", "receipt_id"}
    for record in records:
        if _keys(record, approval_keys, findings, "QVR002"):
            _keys(record["signature"], signature_keys, findings, "QVR002")
    if _keys(decision, decision_keys, findings, "QVR002"):
        _keys(decision["signature"], signature_keys, findings, "QVR002")


def _validate_referenced_bytes(
    entries: dict[str, dict[str, Any]],
    bundle: SafeRoot,
    artifact: SafeRoot | None,
    findings: list[Finding],
) -> None:
    declared_total = 0
    actual_total = 0
    for entry in entries.values():
        declared_size = entry.get("size")
        root_name = entry.get("root")
        reference = entry.get("reference")
        digest = entry.get("digest")
        if (
            not isinstance(declared_size, int)
            or isinstance(declared_size, bool)
            or declared_size < 0
            or not isinstance(reference, str)
            or not isinstance(digest, str)
            or DIGEST.fullmatch(digest) is None
            or root_name not in ("bundle", "artifact")
        ):
            findings.append(_finding("QVG016", "receipt index metadata is malformed"))
            continue
        declared_total += declared_size
        if declared_total > TOTAL_REFERENCED_MAX_BYTES:
            findings.append(_finding("QVR006", "aggregate referenced bytes exceed the frozen limit"))
            return
        selected = bundle if root_name == "bundle" else artifact
        if selected is None:
            findings.append(_finding("QVB010", "required artifact root is unavailable", unresolved=True))
            continue
        try:
            read = selected.read_file(reference, maximum=ARTIFACT_MAX_BYTES)
        except SafeInputError as exc:
            missing = "unavailable" in str(exc)
            findings.append(
                _finding(
                    "QVB010" if missing else "QVR006",
                    "required referenced bytes are unavailable" if missing else "referenced bytes are unsafe",
                    unresolved=missing,
                )
            )
            continue
        actual_total += read.size
        if actual_total > TOTAL_REFERENCED_MAX_BYTES:
            findings.append(_finding("QVR006", "aggregate referenced bytes exceed the frozen limit"))
            return
        if read.size != declared_size or read.digest != digest:
            findings.append(_finding("QVB010", "referenced byte size or digest does not match"))


def _validate_bindings(body: dict[str, Any], findings: list[Finding], checked: set[str]) -> None:
    try:
        expected = expected_binding_chain(body)
    except (KeyError, TypeError, ValueError):
        findings.append(_finding("QVG015", "candidate binding inputs are incomplete"))
        return
    supplied = body.get("bindings", {})
    codes = {"root": "QVB002", "g2": "QVB001", "g3": "QVG015", "g4": "QVG015", "g5": "QVG015"}
    for name, value in expected.items():
        if supplied.get(name) != value:
            findings.append(_finding(codes[name], "candidate binding chain does not verify"))
        else:
            checked.add(name)
    gates = {item.get("gate"): item for item in body.get("gates", []) if isinstance(item, dict)}
    for number, name in enumerate(("root", "g2", "g3", "g4", "g5"), 1):
        gate = gates.get(f"G{number}")
        if gate is None or gate.get("binding") != expected[name]:
            findings.append(_finding("QVG015", "gate receipt binds a different candidate key"))


def _results(body: dict[str, Any]) -> list[dict[str, Any]]:
    values: list[Any] = []
    artifact = body.get("artifact", {})
    if isinstance(artifact, dict) and isinstance(artifact.get("authentication"), dict):
        values.append(artifact["authentication"].get("result"))
    provider = body.get("provider", {})
    if isinstance(provider, dict) and isinstance(provider.get("lifecycle"), dict):
        values.extend(provider["lifecycle"].values())
    for group in ("workloads", "acceptance_conditions", "resources"):
        values.extend(item.get("result") for item in body.get(group, ()) if isinstance(item, dict))
    return [value for value in values if isinstance(value, dict)]


def _validate_gates_and_result_references(
    body: dict[str, Any],
    outcome: Any,
    receipt_ids: set[str],
    findings: list[Finding],
) -> None:
    gates = body.get("gates")
    if not isinstance(gates, list) or [item.get("gate") for item in gates if isinstance(item, dict)] != ["G1", "G2", "G3", "G4", "G5"]:
        findings.append(_finding("QVG006", "gate chain is incomplete or unordered"))
        return
    failed = False
    for offset, gate in enumerate(gates):
        status = gate.get("status")
        if status not in ("pass", "fail"):
            findings.append(_finding("QVG001", "gate status is not an executed result"))
        if outcome == "issue" and status != "pass":
            findings.append(_finding("QVG006", "issue requires every predecessor gate to pass"))
        if failed and status == "pass":
            findings.append(_finding("QVG005", "a downstream gate executed after a blocking failure"))
        failed = failed or status == "fail"
        if gate.get("receipt_id") not in receipt_ids:
            findings.append(_finding("QVG001", "a result references an unindexed receipt"))
        if not isinstance(gate.get("exit_digest"), str) or DIGEST.fullmatch(gate["exit_digest"]) is None:
            findings.append(_finding("QVR004", "gate exit digest is malformed"))
        if not _is_utc(gate.get("reviewed_at")):
            findings.append(_finding("QVR005", "gate review time is malformed"))
        if offset > 0 and gate.get("predecessor_exit_digest") != gates[offset - 1].get("exit_digest"):
            findings.append(_finding("QVG015", "gate predecessor exit digest does not verify"))
    for result in _results(body):
        if result.get("receipt_id") not in receipt_ids:
            findings.append(_finding("QVG001", "a result references an unindexed receipt"))
        if result.get("status") not in ("pass", "fail"):
            findings.append(_finding("QVG001", "an executed result has an invalid status"))
        if outcome == "issue" and result.get("status") != "pass":
            findings.append(_finding("QVG006", "issue contains a failing required result"))
    relay = body.get("relay", {})
    relay_receipt = (
        relay.get("receipt_id")
        if relay.get("mode") == "direct_only"
        else relay.get("loss_recovery_receipt_id")
    )
    if relay_receipt not in receipt_ids:
        findings.append(_finding("QVG001", "relay disposition references an unindexed receipt"))


def _validate_profile(body: dict[str, Any], outcome: Any, findings: list[Finding]) -> None:
    schema = body.get("schema", {})
    if schema != {
        "id": BODY_DOCUMENT_SCHEMA,
        "version": "0.1",
        "digest": machine_schema_digest(),
        "canonicalization": CANONICALIZATION_ID,
    }:
        findings.append(_finding("QVR002", "candidate schema identity is not the frozen v0.1 schema"))
    candidate = body.get("candidate", {})
    if candidate.get("checkpoint_date") != "2026-09-13":
        findings.append(_finding("QVR003", "candidate identity or checkpoint is invalid"))
    revision = candidate.get("revision")
    if (
        not isinstance(revision, int)
        or isinstance(revision, bool)
        or revision < 0
    ):
        findings.append(_finding("QVR005", "candidate revision is not a nonnegative integer"))
    if not _is_utc(candidate.get("reviewed_at")):
        findings.append(_finding("QVR005", "candidate review time is not RFC 3339 UTC"))
    source = body.get("source", {})
    if not isinstance(source.get("commit"), str) or COMMIT.fullmatch(source["commit"]) is None:
        findings.append(_finding("QVR004", "source commit is not a full lowercase Git object ID"))
    configuration = body.get("configuration", {})
    expected_configuration = {
        "discovery": "off",
        "direct_ip": True,
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
    }
    if any(
        not _same_json_type_and_value(configuration.get(key), value)
        for key, value in expected_configuration.items()
    ):
        findings.append(_finding("QVP009", "effective configuration deviates from profile v0.1"))
    peer_counts = configuration.get("manual_peers_per_node")
    if (
        not isinstance(peer_counts, list)
        or len(peer_counts) != 2
        or any(
            not isinstance(count, int)
            or isinstance(count, bool)
            or not 0 <= count <= 19
            for count in peer_counts
        )
    ):
        findings.append(_finding("QVP005", "manual peer count is outside the v0.1 bound"))
    artifact = body.get("artifact", {})
    if artifact.get("architecture") != "aarch64" or artifact.get("package_architecture") != "arm64":
        findings.append(_finding("QVB008", "artifact architecture is outside the v0.1 target"))
    if (
        not isinstance(artifact.get("package_size"), int)
        or isinstance(artifact.get("package_size"), bool)
        or artifact.get("package_size", 0) < 1
        or not isinstance(artifact.get("executable_size"), int)
        or isinstance(artifact.get("executable_size"), bool)
        or not 0 < artifact.get("executable_size", 0) <= 16 * 1024 * 1024
    ):
        findings.append(_finding("QVB008", "artifact size or provider-composed executable bound is invalid"))
    if not _is_utc(artifact.get("produced_at")):
        findings.append(_finding("QVR005", "artifact production time is not RFC 3339 UTC"))
    outputs = artifact.get("outputs", {})
    required_outputs = {
        "arm64_package", "package_authentication", "package_manifest", "sbom", "notices",
        "provenance", "dependency_graph", "complete_artifact_set_manifest",
    }
    if set(outputs) != required_outputs or any(not isinstance(value, str) or PRODUCED.fullmatch(value) is None for value in outputs.values()):
        findings.append(_finding("QVB005", "G3 output manifest is incomplete for issue"))
    bindings = body.get("bindings", {})
    if not isinstance(bindings.get("global_g3"), str) or PRODUCED.fullmatch(bindings["global_g3"]) is None:
        findings.append(_finding("QVB004", "global G3 binding is not a produced attempt manifest"))
    d06 = body.get("prerequisites", {}).get("d06", {})
    if d06 != {
        "design_digest": "sha256:30c5dfe71a203fcdd69dd330f9b5c68eeaee5032b624ee41912aa4723a9f853f",
        "amendment_digest": "sha256:549ea3fd5bdfd62c01bab5a8f1adac4b84a2710ab406ea006119c9048e28d4cd",
        "provider_contract": "aster-systemd-credential-store/v2",
    }:
        findings.append(_finding("QVS002", "D06 prerequisite binding does not match the approved design"))
    e01 = body.get("prerequisites", {}).get("e01", [])
    if (
        not isinstance(e01, list)
        or [record.get("role") for record in e01 if isinstance(record, dict)] != ["security", "deployment"]
        or any(record.get("disposition") != "approve" for record in e01 if isinstance(record, dict))
        or any(not _is_utc(record.get("produced_at")) for record in e01 if isinstance(record, dict))
        or any(record.get("produced_at", "") > artifact.get("produced_at", "") for record in e01 if isinstance(record, dict))
    ):
        findings.append(_finding("QVS012", "E01 approval references do not precede the G3 artifact"))
    d15 = body.get("prerequisites", {}).get("d15", {})
    if (
        d15.get("proposal_digest") != "sha256:a6fe15f39fb553f87bc1224fe7f266e7c906d451d8140402d3bc1620011bfa53"
        or d15.get("approval_digest") != "sha256:4edda9457c78d0c1d177590c1583691071e708ccbbace078cc15a82dd9bcac85"
        or d15.get("roles") != ["dependency-license", "legal-compliance", "release"]
        or d15.get("evaluation_only") is not True
        or d15.get("production_requirement_open") is not True
    ):
        findings.append(_finding("QVS003", "D15 prerequisite binding or evaluation-only boundary is invalid"))
    mission = body.get("mission", {})
    if any(
        (
            mission.get("semantic_protocol") != 6,
            mission.get("security_profile") != "0x0001",
            mission.get("hybrid_suite") != "0x0001",
            mission.get("unordered_profile_ids") is not True,
            mission.get("no_fallback") is not True,
            mission.get("relay_authority_separate") is not True,
            mission.get("roster_count") != 2,
        )
    ):
        findings.append(_finding("QVP011", "mission policy identity deviates from profile v0.1"))
    provider = body.get("provider", {})
    if any(
        (
            provider.get("name") != "aster-systemd-credential-store",
            provider.get("version") != "2",
            provider.get("source_commit") != source.get("commit"),
            provider.get("architecture") != "aarch64",
        )
    ):
        findings.append(_finding("QVB002", "provider identity drifts from the selected candidate"))
    relay = body.get("relay", {})
    relay_mode = relay.get("mode")
    invalid_relay = relay.get("direct_enabled") is not True
    if relay_mode == "direct_only":
        invalid_relay = invalid_relay or relay.get("statement") != "relay not used"
    elif relay_mode == "direct_plus_one_pinned_relay":
        roots = relay.get("der_trust_root_digests")
        invalid_relay = invalid_relay or any(
            (
                relay.get("customer_controlled") is not True,
                relay.get("preference") != "direct_preferred",
                not isinstance(roots, list),
                isinstance(roots, list) and len(roots) < 1,
                isinstance(roots, list) and any(not isinstance(item, str) or DIGEST.fullmatch(item) is None for item in roots),
            )
        )
    else:
        invalid_relay = True
    if invalid_relay:
        findings.append(_finding("QVP007", "relay disposition is not one approved v0.1 branch"))
    nodes = body.get("inventory", {}).get("nodes", [])
    if len(nodes) != 2 or [node.get("alias") for node in nodes] != ["cm4-a", "cm4-b"]:
        findings.append(_finding("QVP001", "inventory does not contain the two ordered mandatory nodes"))
    else:
        commitments: set[Any] = set()
        for node in nodes:
            if any(
                (
                    node.get("physical") is not True,
                    node.get("model") != "Compute Module 4 Rev 1.1",
                    node.get("architecture") != "aarch64",
                    node.get("image_reference") != "2026-06-18",
                    node.get("os") != "Debian 13 trixie",
                    node.get("kernel") != "6.18.39+rpt-rpi-v8",
                    node.get("systemd") != "257.13-1~deb13u1",
                    node.get("filesystem") != "ext4",
                    node.get("nominal_memory_bytes", 0) < 1024 * 1024 * 1024,
                    node.get("initial_state_free_bytes", 0) < 256 * 1024 * 1024,
                    node.get("artifact_digest") != bindings.get("complete_artifact_set"),
                )
            ):
                findings.append(_finding("QVP002", "mandatory physical node facts deviate from v0.1"))
                break
            commitments.add(node.get("device_commitment"))
        if len(commitments) != 2:
            findings.append(_finding("QVP003", "mandatory node commitments are not distinct"))
    _validate_workloads(body.get("workloads"), outcome, findings)
    _validate_acceptance(body.get("acceptance_conditions"), outcome, findings)
    _validate_resources(body.get("resources"), outcome, findings)


def _validate_workloads(value: Any, outcome: Any, findings: list[Finding]) -> None:
    if not isinstance(value, list) or [item.get("label") for item in value if isinstance(item, dict)] != [
        "api_boundary", "two_node_topology", "offline_soak", "capacity_warning_probe"
    ]:
        findings.append(_finding("QVW001", "workload rows or ordering do not match v0.1"))
        return
    api, topology, soak, capacity = value
    expected_api = {
        "nodes": ["cm4-a", "cm4-b"],
        "payload_bytes": [0, 4096, 65536],
        "publisher_assignments": ["cm4-a", "cm4-a", "cm4-a"],
        "events_per_node": [3, 0],
        "total_events": 3,
        "rate_per_hour_per_node": 0,
        "duration_seconds": 0,
        "distinct_operations_per_node": [3, 0],
        "exact_retries_per_node": [0, 0],
    }
    if any(
        not _same_json_type_and_value(api.get(key), expected)
        for key, expected in expected_api.items()
    ):
        findings.append(_finding("QVW002", "API-boundary workload deviates from v0.1"))
    expected_topology = {
        "nodes": ["cm4-a", "cm4-b"],
        "payload_bytes": [4096],
        "publisher_assignments": ["cm4-a"],
        "events_per_node": [10, 0],
        "total_events": 10,
        "rate_per_hour_per_node": 3600,
        "duration_seconds": 10,
        "distinct_operations_per_node": [10, 0],
        "exact_retries_per_node": [0, 0],
    }
    if any(
        not _same_json_type_and_value(topology.get(key), expected)
        for key, expected in expected_topology.items()
    ):
        findings.append(_finding("QVW003", "two-node topology workload deviates from v0.1"))
    expected_soak = {
        "nodes": ["cm4-a", "cm4-b"],
        "payload_bytes": [4096],
        "publisher_assignments": ["cm4-a", "cm4-b"],
        "events_per_node": [240, 240],
        "total_events": 480,
        "rate_per_hour_per_node": 10,
        "duration_seconds": 86_400,
        "distinct_operations_per_node": [240, 240],
        "exact_retries_per_node": [0, 0],
    }
    convergence = soak.get("convergence_seconds")
    if any(
        not _same_json_type_and_value(soak.get(key), expected)
        for key, expected in expected_soak.items()
    ) or (
        not isinstance(convergence, int)
        or isinstance(convergence, bool)
        or not 0 <= convergence <= 86_400
    ):
        findings.append(_finding("QVW004", "offline-soak workload deviates from v0.1"))
    expected_capacity = {
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
    }
    if any(
        not _same_json_type_and_value(capacity.get(key), expected)
        for key, expected in expected_capacity.items()
    ):
        findings.append(_finding("QVW005", "capacity-warning workload deviates from v0.1"))
    statuses = [item.get("result", {}).get("status") for item in value]
    if any(status not in ("pass", "fail") for status in statuses) or (
        outcome == "issue" and any(status != "pass" for status in statuses)
    ):
        findings.append(_finding("QVW006", "one or more required workloads did not pass"))


def _validate_acceptance(value: Any, outcome: Any, findings: list[Finding]) -> None:
    if not isinstance(value, list) or [item.get("condition") for item in value if isinstance(item, dict)] != list(range(1, 14)):
        findings.append(_finding("QVG010", "acceptance conditions are incomplete or unordered"))
    elif any(item.get("result", {}).get("status") not in ("pass", "fail") for item in value) or (
        outcome == "issue" and any(item.get("result", {}).get("status") != "pass" for item in value)
    ):
        findings.append(_finding("QVG011", "one or more acceptance conditions did not pass"))


def _validate_resources(value: Any, outcome: Any, findings: list[Finding]) -> None:
    thresholds = {
        "executable_bytes": 16 * 1024 * 1024,
        "steady_rss_bytes": 64 * 1024 * 1024,
        "peak_rss_bytes": 128 * 1024 * 1024,
        "idle_cpu_basis_points": 500,
        "readiness_milliseconds": 10_000,
        "graceful_stop_milliseconds": 30_000,
    }
    required = set(thresholds) | {
        "initial_state_free_bytes", "state_growth_bytes", "final_state_free_bytes",
        "logical_items", "logical_bytes", "operation_records", "energy_millijoules",
    }
    units = {
        "executable_bytes": "bytes",
        "steady_rss_bytes": "bytes",
        "peak_rss_bytes": "bytes",
        "idle_cpu_basis_points": "basis-points-of-one-core",
        "readiness_milliseconds": "milliseconds",
        "graceful_stop_milliseconds": "milliseconds",
        "initial_state_free_bytes": "bytes",
        "state_growth_bytes": "bytes",
        "final_state_free_bytes": "bytes",
        "logical_items": "items",
        "logical_bytes": "bytes",
        "operation_records": "records",
        "energy_millijoules": "millijoules",
    }
    if not isinstance(value, list):
        findings.append(_finding("QVW009", "resource measurements are absent"))
        return
    for node in ("cm4-a", "cm4-b"):
        records = {item.get("measurement"): item for item in value if isinstance(item, dict) and item.get("node") == node}
        if set(records) != required:
            findings.append(_finding("QVW009", "resource measurement set is incomplete"))
            continue
        if any(
            not isinstance(record.get("value"), int)
            or isinstance(record.get("value"), bool)
            or record["value"] < 0
            or record.get("unit") != units[name]
            for name, record in records.items()
        ):
            findings.append(_finding("QVW009", "resource value type or unit is invalid"))
            continue
        exceeded = [
            name
            for name, limit in thresholds.items()
            if records[name].get("value", limit + 1) > limit
        ]
        if outcome == "issue" and exceeded:
            findings.append(_finding("QVW009", "a resource threshold is exceeded"))
        if any(
            records[name].get("result", {}).get("status")
            != ("fail" if name in exceeded else "pass")
            for name in thresholds
        ):
            findings.append(_finding("QVG001", "resource result disagrees with measured threshold"))
        if records["initial_state_free_bytes"].get("value", 0) < 256 * 1024 * 1024:
            findings.append(_finding("QVW009", "initial state free space is below v0.1"))


def _validate_approvals(
    body: dict[str, Any],
    body_digest: str,
    approvals: list[tuple[dict[str, Any], str]],
    decision: dict[str, Any],
    receipt_ids: set[str],
    findings: list[Finding],
) -> None:
    required_roles = {
        "profile-product", "security", "deployment-os-artifact",
        "integration-device-physical-carrier", "event-service-api-runtime",
        "deterministic-gate", "dependency-license", "legal-compliance",
    }
    outcome = decision.get("outcome")
    roles = [record.get("role") for record, _digest in approvals]
    role_blockers = decision.get("role_blockers")
    if not isinstance(role_blockers, dict):
        role_blockers = {}
        findings.append(_finding("QVS006", "detached final approval blocker set is invalid"))
    represented_roles = set(roles) | set(role_blockers)
    if (
        len(approvals) > MAX_APPROVALS
        or represented_roles != required_roles
        or set(roles) & set(role_blockers)
        or len(roles) != len(set(roles))
        or (
            outcome == "issue"
            and (
                set(roles) != required_roles
                or role_blockers
                or any(
                    record.get("disposition") != "approve"
                    for record, _digest in approvals
                )
            )
        )
    ):
        findings.append(_finding("QVS006", "detached final approval role set is invalid"))
    blocker_pattern = re.compile(
        r"not-run:blocked-at-(G[1-6]):(sha256:[0-9a-f]{64})\Z"
    )
    failed_gates = {
        gate.get("gate"): gate.get("exit_digest")
        for gate in body.get("gates", ())
        if isinstance(gate, dict) and gate.get("status") == "fail"
    }
    for value in role_blockers.values():
        match = blocker_pattern.fullmatch(value) if isinstance(value, str) else None
        if match is None:
            findings.append(_finding("QVG003", "detached final role blocker is malformed"))
        elif failed_gates.get(match.group(1)) != match.group(2):
            findings.append(_finding("QVG004", "detached final role blocker does not bind the blocking gate"))
    candidate_id = body.get("candidate", {}).get("id")
    schema_digest = machine_schema_digest()
    g3_binding = body.get("bindings", {}).get("global_g3")
    for record, _digest in approvals:
        signature = record.get("signature", {})
        if (
            record.get("schema") != APPROVAL_SCHEMA
            or record.get("disposition") not in ("approve", "refuse")
            or record.get("body_digest") != body_digest
            or record.get("candidate_id") != candidate_id
            or record.get("schema_digest") != schema_digest
            or record.get("g3_binding") != g3_binding
            or not _is_utc(record.get("produced_at"))
            or not isinstance(record.get("reviewer_id"), str)
            or not record.get("reviewer_id")
            or not isinstance(signature, dict)
            or signature.get("scheme") != "reference-only-not-verified"
            or signature.get("signer_id") != record.get("reviewer_id")
            or signature.get("receipt_id") not in receipt_ids
        ):
            findings.append(_finding("QVS004", "detached approval binding is invalid"))
    approval_digests = sorted(digest for _record, digest in approvals)
    decision_signature = decision.get("signature")
    if (
        decision.get("schema") != DECISION_SCHEMA
        or outcome not in ("issue", "refuse", "defer")
        or decision.get("body_digest") != body_digest
        or decision.get("approval_digests") != approval_digests
        or decision.get("candidate_id") != candidate_id
        or decision.get("schema_digest") != schema_digest
        or decision.get("g3_binding") != g3_binding
        or not _is_utc(decision.get("produced_at"))
        or any(
            record.get("produced_at", "") > decision.get("produced_at", "")
            for record, _digest in approvals
        )
        or not isinstance(decision.get("reason_digest"), str)
        or DIGEST.fullmatch(decision["reason_digest"]) is None
        or not isinstance(decision_signature, dict)
        or decision_signature.get("scheme") != "reference-only-not-verified"
        or not isinstance(decision_signature.get("signer_id"), str)
        or not decision_signature.get("signer_id")
        or decision_signature.get("receipt_id") not in receipt_ids
    ):
        findings.append(_finding("QVS006", "release decision binding is invalid"))


def validate_bundle(inputs: BundleInputs) -> ValidationReport:
    findings: list[Finding] = []
    checked: set[str] = set()
    schema_digest = machine_schema_digest()
    body_digest: str | None = None
    index_digest: str | None = None
    if len(inputs.approvals) > MAX_APPROVALS:
        findings.append(_finding("QVS006", "approval count exceeds the frozen limit"))
        return build_report(
            findings,
            checked_bindings=checked,
            body_digest=body_digest,
            index_digest=index_digest,
            schema_digest=schema_digest,
        )
    try:
        with ExitStack() as stack:
            bundle = stack.enter_context(SafeRoot(inputs.bundle_root))
            artifact = (
                stack.enter_context(SafeRoot(inputs.artifact_root))
                if inputs.artifact_root is not None
                else None
            )
            try:
                body_read = bundle.read_file(inputs.body, maximum=BODY_MAX_BYTES)
                index_read = bundle.read_file(inputs.index, maximum=INDEX_MAX_BYTES)
                body_digest = body_read.digest
                index_digest = index_read.digest
                body = load_canonical_json(body_read.data, label="candidate body", maximum=BODY_MAX_BYTES)
                index = load_canonical_json(index_read.data, label="receipt index", maximum=INDEX_MAX_BYTES)
                approval_records: list[tuple[dict[str, Any], str]] = []
                for path in inputs.approvals:
                    read = bundle.read_file(path, maximum=DETACHED_MAX_BYTES)
                    approval_records.append((load_canonical_json(read.data, label="approval", maximum=DETACHED_MAX_BYTES), read.digest))
                decision_read = bundle.read_file(inputs.decision, maximum=DETACHED_MAX_BYTES)
                decision = load_canonical_json(decision_read.data, label="release decision", maximum=DETACHED_MAX_BYTES)
            except SafeInputError as exc:
                missing = "unavailable" in str(exc)
                findings.append(_finding("QVB010" if missing else "QVR006", "required bundle input is unavailable" if missing else "required bundle input is unsafe", unresolved=missing))
                return build_report(findings, checked_bindings=checked, body_digest=body_digest, index_digest=index_digest, schema_digest=schema_digest)
            except CanonicalJsonError:
                findings.append(_finding("QVR001", "required bundle input is not canonical JSON"))
                return build_report(findings, checked_bindings=checked, body_digest=body_digest, index_digest=index_digest, schema_digest=schema_digest)
            try:
                body_keys = {"schema", "candidate", "source", "bindings", "artifact", "prerequisites", "provider", "mission", "relay", "inventory", "configuration", "workloads", "acceptance_conditions", "resources", "evidence", "receipt_index", "gates"}
                _keys(body, body_keys, findings, "QVR002")
                _keys(index, {"schema", "candidate_id", "entries"}, findings, "QVR002")
                _validate_scalar_completion(body, findings)
                _validate_scalar_completion(index, findings)
                _validate_scalar_completion([record for record, _digest in approval_records], findings)
                _validate_scalar_completion(decision, findings)
                _validate_digest_grammar(body, findings)
                _validate_digest_grammar(index, findings)
                _validate_digest_grammar([record for record, _digest in approval_records], findings)
                _validate_digest_grammar(decision, findings)
                _validate_body_shapes(body, findings)
                _validate_index_shapes(index, findings)
                _validate_detached_shapes([record for record, _digest in approval_records], decision, findings)
                if index.get("schema") != INDEX_SCHEMA or index.get("candidate_id") != body.get("candidate", {}).get("id"):
                    findings.append(_finding("QVB011", "receipt index candidate or schema binding is invalid"))
                index_binding = body.get("receipt_index", {})
                if index_binding != {"reference": inputs.index, "size": index_read.size, "media_type": "application/json", "digest": index_read.digest}:
                    findings.append(_finding("QVB012", "candidate body receipt-index binding is invalid"))
                entries = _receipt_ids(index, findings)
                _validate_referenced_bytes(entries, bundle, artifact, findings)
                _validate_profile(body, decision.get("outcome"), findings)
                _validate_bindings(body, findings, checked)
                _validate_gates_and_result_references(
                    body, decision.get("outcome"), set(entries), findings
                )
                _validate_approvals(body, body_read.digest, approval_records, decision, set(entries), findings)
            except (AttributeError, KeyError, TypeError, ValueError):
                findings.append(_finding("QVR003", "typed document structure is invalid"))
    except SafeInputError:
        findings.append(_finding("QVR006", "declared bundle or artifact root is unsafe"))
    return build_report(
        findings,
        checked_bindings=checked,
        body_digest=body_digest,
        index_digest=index_digest,
        schema_digest=schema_digest,
    )
