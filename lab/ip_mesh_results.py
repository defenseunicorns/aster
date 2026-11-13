#!/usr/bin/env python3
"""Validate and summarize one or more IP-mesh experiment evidence roots.

The command writes a deterministic JSON document to stdout.  It treats the
experiment receipts as evidence: duplicate JSON keys, unknown schemas,
inconsistent summaries, and missing or extra trial directories are errors.
Optional metrics from older receipt generations remain visible as unavailable
observations instead of being silently dropped.
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import math
import os
from pathlib import Path, PurePath
import re
import shlex
import stat
import sys
import tempfile
from types import SimpleNamespace
from typing import Any, Iterable, Sequence

try:
    import gate_h_faults as gate_h_fault_contract
except ModuleNotFoundError:  # Imported as ``lab.ip_mesh_results`` in tests.
    from lab import gate_h_faults as gate_h_fault_contract

try:
    import ip_mesh_experiment as gate_h_experiment_contract
except ModuleNotFoundError:  # Imported as ``lab.ip_mesh_results`` in tests.
    from lab import ip_mesh_experiment as gate_h_experiment_contract

try:
    import gate_h_signature
except ModuleNotFoundError:  # Imported as ``lab.ip_mesh_results`` in tests.
    from lab import gate_h_signature

try:
    import gate_h_source
except ModuleNotFoundError:  # Imported as ``lab.ip_mesh_results`` in tests.
    from lab import gate_h_source


_RESULTS_REPOSITORY_VALUE = os.environ.get("ASTER_GATE_H_REPOSITORY_WORKSPACE")
REPOSITORY_WORKSPACE = (
    Path(_RESULTS_REPOSITORY_VALUE).resolve()
    if isinstance(_RESULTS_REPOSITORY_VALUE, str)
    and Path(_RESULTS_REPOSITORY_VALUE).is_absolute()
    else gate_h_fault_contract.WORKSPACE
)


EXPERIMENT_SCHEMA = "aster-ip-mesh-phase-a/v1"
RESULTS_SCHEMA = "aster-ip-mesh-results/v1"
EVIDENCE_INDEX_SCHEMA = "aster-ip-mesh-evidence-index/v1"
GATE_H_FAULT_SCHEMA = gate_h_fault_contract.SCHEMA
GATE_H_FAULT_MAX_TIMEOUT_SECONDS = gate_h_fault_contract.MAX_TIMEOUT_SECONDS
GATE_H_BINARY_PROVENANCE_SCHEMA = "aster-gate-h-binary-provenance/v1"
GATE_H_CLEANUP_SCHEMA = "aster-gate-h-cleanup/v1"
GATE_H_RESOURCE_CLEANUP_SCHEMA = "aster-gate-h-resource-cleanup/v1"
GATE_H_HOST_EXECUTION_SCHEMA = "aster-gate-h-host-execution/v1"
GATE_H_HOST_EXECUTION_FINAL_SCHEMA = "aster-gate-h-host-execution-final/v1"
GATE_H_SIGNATURE_FINAL_SCHEMA = "aster-gate-h-signature-final/v1"
GATE_H_EXPORT_EXECUTION_SCHEMA = "aster-gate-h-export-execution/v1"
SURVEY_BASELINE = "56ea19d89e537a351ceded446c2d38f5313d118b"
PROPOSAL_0004_BASELINE = "26c24a65c125406ed59493e5fc82a31bebb16d02"
REQUIREMENTS_SHA256 = "e88bcc6c717a5175a460205fdc084aaa2e1f020a142a84087f9881677da02987"
ARMS = ("native", "iroh", "libp2p")
SCENARIOS = (
    "primary",
    "gate-h",
    "discovery-disabled",
    "manual",
    "receive-only",
    "idle",
    "multi-peer",
    "live-relay",
)
NODE_SCHEMAS = {
    "native": {
        "aster-lab-native-mesh-node/v1",
        "aster-lab-native-mesh-node/v2",
    },
    "iroh": {
        "aster-lab-iroh-mesh-node/v1",
        "aster-lab-iroh-mesh-node/v2",
    },
    "libp2p": {
        "aster-lab-libp2p-mesh-node/v1",
        "aster-lab-libp2p-mesh-node/v2",
        "aster-lab-libp2p-mesh-node/v3",
    },
}
RECEIPT_ROLES = {
    "primary": ("ab_a", "ab_b", "bc_b", "bc_c", "dup_a", "dup_b"),
    "gate-h": ("a", "b_pre", "b_post", "c"),
    "discovery-disabled": ("a", "b"),
    "manual": ("a", "b"),
    "receive-only": ("a", "b"),
    "idle": ("a",),
    "multi-peer": ("a", "b", "c"),
    "live-relay": ("a", "b", "c"),
}
HEX_64 = re.compile(r"^[0-9a-f]{64}$")
HEX_40 = re.compile(r"^[0-9a-f]{40}$")
GATE_H_RESULTS_RELATIVE_PATH = "lab/ip_mesh_results.py"
GATE_H_RESULTS_MODULES = {
    "gate_h_faults": "lab/gate_h_faults.py",
    "gate_h_signature": "lab/gate_h_signature.py",
    "gate_h_source": "lab/gate_h_source.py",
    "ip_mesh_experiment": "lab/ip_mesh_experiment.py",
}
IROH_PRE_INCOMING_BLOCKER = (
    "iroh-1.0.3-noq-pre-incoming-defaults-max-65536-total-buffer-100-mib"
)
NATIVE_SHARED_NODE_SCHEMA = "aster-lab-native-mesh-node/v2"
LIBP2P_SHARED_NODE_SCHEMA = "aster-lab-libp2p-mesh-node/v3"
GATE_H_NODE_BUFFER_BYTES = 8 * 1024 * 1024
GATE_H_IMAGE_BINARY_PATH = "/usr/local/bin/aster-lab"
NODE_RESOURCE_FIELDS = (
    "candidates",
    "pending_connections",
    "pre_authentication_contacts",
    "admitted_contacts",
    "streams",
    "tasks",
    "frames",
    "inbound_bytes",
    "outbound_bytes",
    "descriptors",
    "relay_reservations",
)
NATIVE_SHARED_NODE_CONSTRUCTION_FIELDS = (
    "sqlite_node_open_count",
    "blob_authority_open_count",
    "semantic_backend_construction_count",
    "process_authority_construction_count",
)
NATIVE_PROTOCOL_COUNTER_FIELDS = (
    "aster_frames_received",
    "aster_frames_sent",
    "aster_bytes_received",
    "aster_bytes_sent",
    "carrier_control_frames_received",
    "carrier_control_frames_sent",
    "carrier_control_bytes_received",
    "carrier_control_bytes_sent",
    "authorization_generation_checks",
    "authorization_generation_mismatches",
    "authorization_generation_unavailable",
)
GATE_H_FAULT_CASES = gate_h_fault_contract.EXPECTED_CASES
GATE_H_NATIVE_RESOURCE_LIMITS = {
    "candidates": 8,
    "pending_connections": 2,
    "pre_authentication_contacts": 2,
    "admitted_contacts": 2,
    "streams": 2,
    "tasks": 3,
    "frames": 8_192,
    "inbound_bytes": GATE_H_NODE_BUFFER_BYTES,
    "outbound_bytes": GATE_H_NODE_BUFFER_BYTES,
    "descriptors": 1,
    "relay_reservations": 0,
}
GATE_H_NATIVE_PROVIDER_BASE = {
    "tasks": 1,
    "frames": 5_632,
    "inbound_bytes": 65_507,
    "descriptors": 1,
}
GATE_H_NATIVE_ADMITTED_CONTACT = {
    "admitted_contacts": 1,
    "streams": 1,
    "tasks": 1,
    "frames": 593,
    "inbound_bytes": 2 * 1_024 * 1_024,
    "outbound_bytes": 1_024 * 1_024,
}
GATE_H_CLEAN_ZERO_COUNTERS = (
    "contact_failures",
    "duplicate_contacts",
    "candidates_rejected_capacity",
    "node_resource_rejected_claims",
)

METRIC_UNITS = {
    "trial_elapsed_ms": "ms",
    "node_elapsed_ms": "ms",
    "first_candidate_ms": "ms-from-process-launch",
    "first_authenticated_ms": "ms-from-process-launch",
    "durable_item_first_observed_ms": "ms-from-process-launch",
    "durable_item_newly_observed_ms": "ms-from-process-launch",
    "cpu_usage_usec": "microseconds",
    "network_bytes": "bytes-rx-plus-tx",
    "memory_current_bytes": "bytes",
    "memory_peak_bytes": "bytes",
    "application_payload_throughput_bps": "payload-bits-per-second-from-process-launch",
    "network_amplification_bytes_per_payload_byte": "network-bytes-per-payload-byte",
    "frames_received": "frames",
    "frames_sent": "frames",
    "frames_total": "frames",
    "bytes_received": "aster-frame-bytes",
    "bytes_sent": "aster-frame-bytes",
    "bytes_total": "aster-frame-bytes",
    "pump_calls": "calls",
    "contact_failures": "contacts",
    "duplicate_contacts": "contacts",
    "duplicate_connections": "connections",
    "active_contact_high_water": "contacts",
    "admitted_contact_high_water": "semantically-admitted-contacts",
    "candidates_discovered": "candidates",
    "discovery_announcements": "announcements",
    "idle_cpu_usage_usec_total": "microseconds",
    "idle_cpu_usage_usec_settling": "microseconds",
    "idle_cpu_usage_usec_settled": "microseconds",
    "idle_cpu_percent_of_one_core_total": "percent",
    "idle_cpu_percent_of_one_core_settled": "percent",
    "idle_settled_network_bytes": "bytes-rx-plus-tx",
    "idle_settled_network_bytes_per_minute": "bytes-rx-plus-tx-per-minute",
    "idle_memory_current_after_settle_bytes": "bytes",
    "idle_memory_peak_bytes": "bytes",
    "live_bc_prerequisite_ms": "ms-before-a-launch",
    "live_c_item_observed_ms": "ms-from-c-process-launch",
    "receive_only_b_item_observed_ms": "ms-from-b-process-launch",
    "gate_h_pre_admitted_ms": "ms-from-pre-phase-process-launch",
    "gate_h_b_custody_observed_ms": "ms-after-pre-phase-admission",
    "gate_h_post_admitted_ms": "ms-from-post-phase-process-launch",
    "gate_h_c_item_observed_ms": "ms-after-post-phase-admission",
    "aster_frames_received": "aster-protocol-frames",
    "aster_frames_sent": "aster-protocol-frames",
    "aster_bytes_received": "aster-protocol-bytes",
    "aster_bytes_sent": "aster-protocol-bytes",
    "carrier_control_frames_received": "carrier-control-frames",
    "carrier_control_frames_sent": "carrier-control-frames",
    "carrier_control_bytes_received": "carrier-control-bytes",
    "carrier_control_bytes_sent": "carrier-control-bytes",
    "authorization_generation_checks": "checks",
    "authorization_generation_mismatches": "mismatches",
    "authorization_generation_unavailable": "unavailable-checks",
    "node_resource_rejected_claims": "aggregate-resource-claim-rejections",
    **{
        f"node_resource_rejections_{field}": "resource-claim-rejections"
        for field in NODE_RESOURCE_FIELDS
    },
    **{
        f"node_resource_high_water_{field}": field.replace("_", "-")
        for field in NODE_RESOURCE_FIELDS
    },
}


class ResultsError(RuntimeError):
    """A fail-closed evidence validation error."""


def _pairs_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    value: dict[str, Any] = {}
    for key, item in pairs:
        if key in value:
            raise ResultsError(f"duplicate JSON object key: {key}")
        value[key] = item
    return value


def _reject_constant(value: str) -> None:
    raise ResultsError(f"non-finite JSON number: {value}")


def read_object(path: Path) -> dict[str, Any]:
    if not path.is_file():
        raise ResultsError(f"missing evidence file: {path}")
    try:
        value = json.loads(
            path.read_text(encoding="utf-8"),
            object_pairs_hook=_pairs_object,
            parse_constant=_reject_constant,
        )
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise ResultsError(f"invalid JSON evidence file {path}: {error}") from error
    if not isinstance(value, dict):
        raise ResultsError(f"evidence file is not a JSON object: {path}")
    return value


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def canonical_sha256(value: Any) -> str:
    return hashlib.sha256(
        json.dumps(
            value, sort_keys=True, separators=(",", ":"), ensure_ascii=True
        ).encode("utf-8")
    ).hexdigest()


def calculate_evidence_entries(root: Path) -> tuple[list[dict[str, Any]], str]:
    entries: list[dict[str, Any]] = []
    aggregate = hashlib.sha256()
    for path in sorted(root.rglob("*"), key=lambda item: item.relative_to(root).as_posix()):
        if path.name == "evidence-index.json":
            continue
        if path.is_symlink():
            raise ResultsError(f"evidence tree contains a symlink: {path}")
        if not path.is_file():
            continue
        relative = path.relative_to(root).as_posix()
        size = path.stat().st_size
        digest = sha256_file(path)
        aggregate.update(relative.encode("utf-8"))
        aggregate.update(b"\0")
        aggregate.update(str(size).encode("ascii"))
        aggregate.update(b"\0")
        aggregate.update(digest.encode("ascii"))
        aggregate.update(b"\n")
        entries.append({"path": relative, "size": size, "sha256": digest})
    return entries, aggregate.hexdigest()


def verify_evidence_index(root: Path) -> dict[str, Any]:
    index_path = root / "evidence-index.json"
    index = read_object(index_path)
    validate_schema(index, EVIDENCE_INDEX_SCHEMA, str(index_path))
    entries, aggregate = calculate_evidence_entries(root)
    if index.get("entries") != entries:
        raise ResultsError(f"{index_path} does not match the retained evidence files")
    if index.get("entry_count") != len(entries):
        raise ResultsError(f"{index_path}.entry_count differs from its entries")
    if index.get("aggregate_sha256") != aggregate:
        raise ResultsError(f"{index_path}.aggregate_sha256 differs")
    return {
        "index_sha256": sha256_file(index_path),
        "aggregate_sha256": aggregate,
        "entry_count": len(entries),
    }


def require_string(value: dict[str, Any], field: str, context: str) -> str:
    item = value.get(field)
    if not isinstance(item, str) or not item:
        raise ResultsError(f"{context}.{field} must be a nonempty string")
    return item


def require_bool(value: dict[str, Any], field: str, context: str) -> bool:
    item = value.get(field)
    if not isinstance(item, bool):
        raise ResultsError(f"{context}.{field} must be a boolean")
    return item


def require_int(value: dict[str, Any], field: str, context: str) -> int:
    item = value.get(field)
    if isinstance(item, bool) or not isinstance(item, int) or item < 0:
        raise ResultsError(f"{context}.{field} must be a nonnegative integer")
    return item


def number_or_none(
    value: dict[str, Any], field: str, context: str, *, required: bool = False
) -> int | float | None:
    if field not in value:
        if required:
            raise ResultsError(f"{context}.{field} is missing")
        return None
    item = value[field]
    if item is None:
        return None
    if isinstance(item, bool) or not isinstance(item, (int, float)):
        raise ResultsError(f"{context}.{field} must be a nonnegative number or null")
    if not math.isfinite(item) or item < 0:
        raise ResultsError(f"{context}.{field} must be finite and nonnegative")
    return item


def require_number(value: dict[str, Any], field: str, context: str) -> int | float:
    item = number_or_none(value, field, context, required=True)
    if item is None:
        raise ResultsError(f"{context}.{field} cannot be null")
    return item


def _nearest_rank(values: list[int | float], fraction: float) -> int | float:
    rank = max(1, math.ceil(fraction * len(values)))
    return values[rank - 1]


def distribution(
    observations: Sequence[int | float | None], unit: str
) -> dict[str, int | float | str | None]:
    values = sorted(value for value in observations if value is not None)
    result: dict[str, int | float | str | None] = {
        "unit": unit,
        "observations": len(observations),
        "sample_count": len(values),
        "unavailable_count": len(observations) - len(values),
    }
    if not values:
        result.update(
            {
                "min": None,
                "p50": None,
                "p95": None,
                "max": None,
                "mean": None,
                "sum": None,
            }
        )
        return result
    result.update(
        {
            "min": values[0],
            "p50": _nearest_rank(values, 0.50),
            "p95": _nearest_rank(values, 0.95),
            "max": values[-1],
            "mean": sum(values) / len(values),
            "sum": sum(values),
        }
    )
    return result


class Samples:
    def __init__(self) -> None:
        self.values: dict[str, list[int | float | None]] = {
            name: [] for name in METRIC_UNITS
        }

    def add(self, name: str, value: int | float | None) -> None:
        self.values[name].append(value)

    def result(self) -> dict[str, dict[str, int | float | str | None]]:
        return {
            name: distribution(self.values[name], unit)
            for name, unit in METRIC_UNITS.items()
        }


def scenario_of(value: dict[str, Any]) -> str:
    scenario = value.get("scenario", "primary")
    if scenario not in SCENARIOS:
        raise ResultsError(f"unknown experiment scenario: {scenario!r}")
    return scenario


def validate_provider_profile(
    receipt: dict[str, Any],
    *,
    arm: str,
    discovery_source: str | None,
    context: str,
    provider_binary_sha256: str | None = None,
) -> None:
    """Revalidate the exact provider/discovery build represented by a receipt."""
    if arm == "native":
        if provider_binary_sha256 is not None:
            raise ResultsError(f"{context} native evidence selected a provider binary")
        if discovery_source is not None:
            raise ResultsError(f"{context} native evidence selected a provider source")
        if receipt.get("schema") == NATIVE_SHARED_NODE_SCHEMA:
            validate_native_shared_node_profile(receipt, context=context)
        return
    if discovery_source not in ("aster-protected", "provider-mdns"):
        raise ResultsError(f"{context} has no exact provider discovery source")

    if arm == "iroh":
        if provider_binary_sha256 is not None:
            raise ResultsError(f"{context} Iroh evidence selected a provider binary")
        if receipt.get("schema") != "aster-lab-iroh-mesh-node/v2":
            raise ResultsError(f"{context} is not an Iroh v2 profile receipt")
        expected = {
            "candidate_source": discovery_source,
            "public_defaults": False,
            "pre_incoming_boundedness_blocker": IROH_PRE_INCOMING_BLOCKER,
            "phase1_scale_eligible": False,
        }
        if not isinstance(receipt.get("path_events_integrated"), bool):
            raise ResultsError(f"{context}.path_events_integrated must be boolean")
        if discovery_source == "aster-protected":
            expected.update(
                {
                    "iroh_mdns": False,
                    "iroh_mdns_compiled": False,
                    "discovery_announcement_count_observable": True,
                    "mdns_boundedness_blocker": None,
                    "requirements_eligible_discovery": True,
                }
            )
        else:
            expected.update(
                {
                    "iroh_mdns": True,
                    "iroh_mdns_compiled": True,
                    "discovery_announcement_count_observable": False,
                    "mdns_boundedness_blocker": (
                        "uncapped-pre-host-iroh-mdns-address-cache-and-callback-tasks"
                    ),
                    "requirements_eligible_discovery": False,
                }
            )
    elif arm == "libp2p":
        schema = receipt.get("schema")
        if schema not in (
            "aster-lab-libp2p-mesh-node/v2",
            LIBP2P_SHARED_NODE_SCHEMA,
        ):
            raise ResultsError(f"{context} is not a supported libp2p profile receipt")
        if provider_binary_sha256 is not None and schema != LIBP2P_SHARED_NODE_SCHEMA:
            raise ResultsError(
                f"{context} corrected libp2p evidence is not a v3 profile receipt"
            )
        if schema == LIBP2P_SHARED_NODE_SCHEMA:
            receipt_provider_sha256 = receipt.get("provider_binary_sha256")
            if (
                not isinstance(receipt_provider_sha256, str)
                or not HEX_64.fullmatch(receipt_provider_sha256)
            ):
                raise ResultsError(
                    f"{context}.provider_binary_sha256 is malformed or absent"
                )
            if (
                provider_binary_sha256 is not None
                and receipt_provider_sha256 != provider_binary_sha256
            ):
                raise ResultsError(
                    f"{context}.provider_binary_sha256 differs from the frozen provider"
                )
        expected = {"candidate_source": discovery_source}
        if discovery_source == "aster-protected":
            expected.update(
                {
                    "bounded_candidate_source": True,
                    "protected_source_compiled_without_mdns": True,
                    "libp2p_mdns": False,
                    "libp2p_mdns_enabled": False,
                    "mdns_rustsec_blocker": None,
                    "provider_mdns_announcement_count_observable": False,
                }
            )
        else:
            expected.update(
                {
                    "bounded_candidate_source": False,
                    "protected_source_compiled_without_mdns": False,
                    "libp2p_mdns": True,
                    "libp2p_mdns_enabled": True,
                    "mdns_rustsec_blocker": "RUSTSEC-2026-0119",
                    "provider_mdns_announcement_count_observable": False,
                }
            )
    else:
        raise ResultsError(f"{context} has unknown provider arm {arm!r}")

    for field, expected_value in expected.items():
        actual = receipt.get(field)
        if isinstance(expected_value, bool) or expected_value is None:
            matches = actual is expected_value
        else:
            matches = type(actual) is type(expected_value) and actual == expected_value
        if not matches:
            raise ResultsError(
                f"{context}.{field} does not prove {arm}/{discovery_source}"
            )


def _strict_nonnegative_integer(value: Any, *, field: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise ResultsError(f"{field} must be a nonnegative integer")
    return value


def _native_resource_object(
    receipt: dict[str, Any], field: str, *, context: str
) -> dict[str, int]:
    value = receipt.get(field)
    if not isinstance(value, dict):
        raise ResultsError(f"{context}.{field} must be an object")
    if set(value) != set(NODE_RESOURCE_FIELDS):
        raise ResultsError(f"{context}.{field} has the wrong resource fields")
    return {
        name: _strict_nonnegative_integer(
            value[name], field=f"{context}.{field}.{name}"
        )
        for name in NODE_RESOURCE_FIELDS
    }


def validate_native_shared_node_profile(
    receipt: dict[str, Any], *, context: str
) -> None:
    if receipt.get("durable_authority_open_count") != 1:
        raise ResultsError(f"{context} does not prove one durable authority open")
    if receipt.get("frame_counter_scope") != "aster_protocol":
        raise ResultsError(f"{context}.frame_counter_scope does not identify Aster")
    counters = {
        field: _strict_nonnegative_integer(
            receipt.get(field), field=f"{context}.{field}"
        )
        for field in NATIVE_PROTOCOL_COUNTER_FIELDS
    }
    legacy_frames_received = _strict_nonnegative_integer(
        receipt.get("frames_received"), field=f"{context}.frames_received"
    )
    legacy_frames_sent = _strict_nonnegative_integer(
        receipt.get("frames_sent"), field=f"{context}.frames_sent"
    )
    if (
        legacy_frames_received != counters["aster_frames_received"]
        or legacy_frames_sent != counters["aster_frames_sent"]
    ):
        raise ResultsError(f"{context} legacy frame aliases differ from Aster frames")
    checks = counters["authorization_generation_checks"]
    if checks == 0:
        raise ResultsError(f"{context} performed no authorization generation checks")
    if (
        counters["authorization_generation_mismatches"]
        + counters["authorization_generation_unavailable"]
        > checks
    ):
        raise ResultsError(
            f"{context} authorization generation outcomes exceed checks"
        )
    for field in NATIVE_SHARED_NODE_CONSTRUCTION_FIELDS:
        if receipt.get(field) != 1:
            raise ResultsError(f"{context}.{field} does not equal one")
    admitted = receipt.get("admitted_peers")
    if (
        not isinstance(admitted, list)
        or any(not isinstance(peer, str) or not HEX_64.fullmatch(peer) for peer in admitted)
        or len(admitted) != len(set(admitted))
    ):
        raise ResultsError(f"{context}.admitted_peers is malformed")
    limits = _native_resource_object(receipt, "node_resource_limits", context=context)
    current = _native_resource_object(receipt, "node_resource_current", context=context)
    high_water = _native_resource_object(
        receipt, "node_resource_high_water", context=context
    )
    for field in NODE_RESOURCE_FIELDS:
        if current[field] > high_water[field] or high_water[field] > limits[field]:
            raise ResultsError(
                f"{context} node resource ordering is invalid for {field}"
            )
    for field in NODE_RESOURCE_FIELDS[:-1]:
        if limits[field] == 0:
            raise ResultsError(f"{context} node resource limit is zero for {field}")
    if limits["relay_reservations"] != 0:
        raise ResultsError(f"{context} native control reserves a connectivity relay")
    if (
        limits["inbound_bytes"] != GATE_H_NODE_BUFFER_BYTES
        or limits["outbound_bytes"] != GATE_H_NODE_BUFFER_BYTES
    ):
        raise ResultsError(f"{context} has the wrong Gate-H aggregate byte ceilings")
    _strict_nonnegative_integer(
        receipt.get("node_resource_rejected_claims"),
        field=f"{context}.node_resource_rejected_claims",
    )
    rejections = _native_resource_object(
        receipt, "node_resource_rejections", context=context
    )
    if sum(rejections.values()) != receipt["node_resource_rejected_claims"]:
        raise ResultsError(
            f"{context} aggregate resource rejections differ from per-category counts"
        )


def validate_gate_h_native_receipt(
    receipt: dict[str, Any], *, context: str, expected_item_id: str
) -> None:
    """Require the exact clean native accounting contract for Gate H."""

    if receipt.get("schema") != NATIVE_SHARED_NODE_SCHEMA:
        raise ResultsError(f"{context} does not use the required native v2 schema")
    validate_native_shared_node_profile(receipt, context=context)
    limits = _native_resource_object(receipt, "node_resource_limits", context=context)
    if limits != GATE_H_NATIVE_RESOURCE_LIMITS:
        raise ResultsError(f"{context} has the wrong exact native resource limits")
    current = _native_resource_object(receipt, "node_resource_current", context=context)
    high_water = _native_resource_object(
        receipt, "node_resource_high_water", context=context
    )
    for field, floor in GATE_H_NATIVE_PROVIDER_BASE.items():
        if current[field] < floor:
            raise ResultsError(
                f"{context} does not retain the native provider base lease for {field}"
            )

    admitted_high_water = _strict_nonnegative_integer(
        receipt.get("admitted_contact_high_water"),
        field=f"{context}.admitted_contact_high_water",
    )
    for field in NODE_RESOURCE_FIELDS:
        floor = GATE_H_NATIVE_PROVIDER_BASE.get(field, 0) + (
            admitted_high_water * GATE_H_NATIVE_ADMITTED_CONTACT.get(field, 0)
        )
        if high_water[field] < floor:
            raise ResultsError(
                f"{context} resource high-water omits admitted-contact {field}"
            )

    for field in GATE_H_CLEAN_ZERO_COUNTERS:
        if (
            _strict_nonnegative_integer(
                receipt.get(field), field=f"{context}.{field}"
            )
            != 0
        ):
            raise ResultsError(f"{context} is not clean: {field} is nonzero")
    unauthorized = receipt.get("unauthorized_peers")
    if not isinstance(unauthorized, list) or unauthorized:
        raise ResultsError(f"{context} is not clean: unauthorized peers were retained")
    rejections = _native_resource_object(
        receipt, "node_resource_rejections", context=context
    )
    if any(rejections.values()):
        raise ResultsError(f"{context} is not clean: resource rejection is nonzero")
    if not HEX_64.fullmatch(expected_item_id):
        raise ResultsError(f"{context} expected ItemID is malformed")
    if receipt.get("durable_item_probe_id") != expected_item_id:
        raise ResultsError(f"{context} observed the wrong durable ItemID")
    if receipt.get("durable_item_present") is not True:
        raise ResultsError(f"{context} did not observe the exact durable ItemID")


def validate_gate_h_durable_item_observations(
    value: Any, *, expected_item_id: str, context: str
) -> None:
    """Validate the retained exact live custody/absence observations."""

    expected_roles = {"b_custody", "c_at_b_custody", "c_pre_restart"}
    if not isinstance(value, dict) or set(value) != expected_roles:
        raise ResultsError(f"{context} has the wrong durable observation phases")
    elapsed: dict[str, int] = {}
    for phase in sorted(expected_roles):
        observation = value.get(phase)
        if not isinstance(observation, dict) or set(observation) != {
            "item_id",
            "present",
            "elapsed_ms",
        }:
            raise ResultsError(f"{context}.{phase} has the wrong exact fields")
        if observation.get("item_id") != expected_item_id:
            raise ResultsError(f"{context}.{phase} observed the wrong durable ItemID")
        expected_present = phase == "b_custody"
        if observation.get("present") is not expected_present:
            raise ResultsError(f"{context}.{phase} has the wrong presence result")
        elapsed[phase] = _strict_nonnegative_integer(
            observation.get("elapsed_ms"), field=f"{context}.{phase}.elapsed_ms"
        )
    if elapsed["c_pre_restart"] <= elapsed["c_at_b_custody"]:
        raise ResultsError(f"{context} does not prove a fresh C absence observation")


def provider_profile_evidence(receipt: dict[str, Any], arm: str) -> dict[str, Any]:
    if arm == "native":
        return {
            "candidate_source": "aster-protected",
            "shared_node_profile": receipt.get("schema")
            == NATIVE_SHARED_NODE_SCHEMA,
            "durable_authority_open_count": receipt.get(
                "durable_authority_open_count"
            ),
            **{
                field: receipt.get(field)
                for field in NATIVE_SHARED_NODE_CONSTRUCTION_FIELDS
            },
            "node_resource_limits": receipt.get("node_resource_limits"),
            "node_resource_rejections": receipt.get("node_resource_rejections"),
        }
    if arm == "iroh":
        fields = (
            "candidate_source",
            "iroh_mdns",
            "iroh_mdns_compiled",
            "discovery_announcement_count_observable",
            "mdns_boundedness_blocker",
            "requirements_eligible_discovery",
            "pre_incoming_boundedness_blocker",
            "phase1_scale_eligible",
            "public_defaults",
            "path_events_integrated",
        )
    else:
        fields = (
            "candidate_source",
            "bounded_candidate_source",
            "protected_source_compiled_without_mdns",
            "libp2p_mdns",
            "libp2p_mdns_enabled",
            "mdns_rustsec_blocker",
            "provider_mdns_announcement_count_observable",
        )
    return {field: receipt.get(field) for field in fields}


def validate_source_freeze(manifest: dict[str, Any]) -> dict[str, Any]:
    freeze = manifest.get("source_freeze")
    if not isinstance(freeze, dict):
        raise ResultsError("manifest.source_freeze must be an object")
    if freeze.get("survey_baseline") != SURVEY_BASELINE:
        raise ResultsError("manifest source freeze has the wrong survey baseline")
    commit = freeze.get("candidate_commit")
    if not isinstance(commit, str) or not HEX_40.fullmatch(commit):
        raise ResultsError("manifest source freeze has no exact candidate commit")
    tree = freeze.get("candidate_tree")
    if tree is not None and (
        not isinstance(tree, str) or not HEX_40.fullmatch(tree)
    ):
        raise ResultsError("manifest source freeze has no exact candidate tree")
    if freeze.get("worktree_clean") is not True or freeze.get("worktree_status") != []:
        raise ResultsError("manifest source freeze is not a clean worktree")
    if freeze.get("requirements_sha256") != REQUIREMENTS_SHA256:
        raise ResultsError("manifest source freeze has the wrong requirements digest")
    build_command = freeze.get("build_command")
    if not isinstance(build_command, str) or not build_command.strip():
        raise ResultsError("manifest source freeze has no exact build command")
    image = manifest.get("image_content")
    if not isinstance(image, dict):
        raise ResultsError("manifest.image_content must be an object")
    image_id = image.get("id")
    if (
        not isinstance(image_id, str)
        or not image_id.startswith("sha256:")
        or not HEX_64.fullmatch(image_id.removeprefix("sha256:"))
    ):
        raise ResultsError("manifest image has no content-addressed ID")
    repo_digests = image.get("repo_digests")
    if not isinstance(repo_digests, list) or any(
        not isinstance(item, str) for item in repo_digests
    ):
        raise ResultsError("manifest image repo digests are malformed")
    return {
        "candidate_commit": commit,
        "candidate_tree": tree,
        "build_command": build_command,
        "image_id": image_id,
        "repo_digests": repo_digests,
        "requirements_sha256": REQUIREMENTS_SHA256,
        "requirements_git_blob": freeze.get("requirements_git_blob"),
        "requirements_size_bytes": freeze.get("requirements_size_bytes"),
        "proposal_0004_baseline": freeze.get("proposal_0004_baseline"),
        "experiment_proposal": freeze.get("experiment_proposal"),
        "signature_status": freeze.get("signature_status"),
        "signature_signer": freeze.get("signature_signer"),
        "signature_fingerprint": freeze.get("signature_fingerprint"),
        "signature_verification": freeze.get("signature_verification"),
        "signature_trust_sha256": freeze.get("signature_trust_sha256"),
        "git_commands": freeze.get("git_commands"),
        "git_binary": freeze.get("git_binary"),
        "host_environment_sha256": freeze.get("host_environment_sha256"),
    }


def gate_h_build_argv(image: str) -> list[str]:
    if not isinstance(image, str) or not image or any(character.isspace() for character in image):
        raise ResultsError("Gate-H manifest image must be a nonempty token")
    return [
        "docker",
        "build",
        "--pull=false",
        "--build-arg",
        "LAB_ASTER_FEATURES=aster-lab/gate-h",
        "--build-arg",
        "LAB_ASTER_BINARY=aster-gate-h",
        "--tag",
        image,
        "--file",
        "lab/Dockerfile",
        ".",
    ]


def read_command_records(root: Path) -> dict[int, dict[str, Any]]:
    path = root / "commands.jsonl"
    if not path.is_file():
        raise ResultsError("Gate-H evidence has no retained command log")
    records: dict[int, dict[str, Any]] = {}
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except (OSError, UnicodeError) as error:
        raise ResultsError(f"cannot read Gate-H command log: {error}") from error
    for line_number, line in enumerate(lines, start=1):
        try:
            record = json.loads(
                line,
                object_pairs_hook=_pairs_object,
                parse_constant=_reject_constant,
            )
        except (json.JSONDecodeError, ResultsError) as error:
            raise ResultsError(
                f"invalid Gate-H command record at line {line_number}: {error}"
            ) from error
        if not isinstance(record, dict):
            raise ResultsError(f"Gate-H command record {line_number} is not an object")
        sequence = require_int(record, "sequence", f"commands.jsonl:{line_number}")
        if sequence == 0 or sequence in records:
            raise ResultsError("Gate-H command log has a zero or duplicate sequence")
        records[sequence] = record
    return records


def _validate_gate_h_buildx_state_cleanup(
    value: Any, *, root: Path
) -> dict[str, Any]:
    """Recompute the bounded buildx-state inventory retained before cleanup."""

    state_path = (root / "docker-config/buildx").resolve()
    if (
        not isinstance(value, dict)
        or set(value)
        != {"path", "present_before", "inventory", "removed", "errors", "passed"}
        or value.get("path") != str(state_path)
        or value.get("present_before") is not True
        or value.get("removed") is not True
        or value.get("errors") != []
        or value.get("passed") is not True
    ):
        raise ResultsError("Gate-H Docker buildx state cleanup did not pass")
    inventory = value.get("inventory")
    if (
        not isinstance(inventory, dict)
        or set(inventory)
        != {
            "path",
            "entry_count",
            "total_file_bytes",
            "entries",
            "entries_sha256",
        }
        or inventory.get("path") != str(state_path)
    ):
        raise ResultsError("Gate-H Docker buildx state inventory is malformed")
    entries = inventory.get("entries")
    if (
        not isinstance(entries, list)
        or len(entries) != inventory.get("entry_count")
        or len(entries)
        > gate_h_experiment_contract.GATE_H_DOCKER_BUILDX_STATE_MAX_ENTRIES
        or inventory.get("entries_sha256") != canonical_sha256(entries)
    ):
        raise ResultsError("Gate-H Docker buildx state entry inventory differs")

    directories: dict[str, dict[str, Any]] = {}
    files: dict[str, tuple[dict[str, Any], bytes]] = {}
    total_bytes = 0
    last_path: str | None = None
    for entry in entries:
        if not isinstance(entry, dict) or not isinstance(entry.get("path"), str):
            raise ResultsError("Gate-H Docker buildx state entry is malformed")
        relative = entry["path"]
        if last_path is not None and relative <= last_path:
            raise ResultsError("Gate-H Docker buildx state entries are not canonical")
        last_path = relative
        if entry.get("kind") == "directory":
            if set(entry) != {"path", "kind", "mode"} or entry.get("mode") != "0700":
                raise ResultsError("Gate-H Docker buildx directory receipt differs")
            directories[relative] = entry
            continue
        if entry.get("kind") != "file" or set(entry) != {
            "path",
            "kind",
            "mode",
            "size_bytes",
            "sha256",
            "content_base64",
        }:
            raise ResultsError("Gate-H Docker buildx file receipt differs")
        size = require_int(entry, "size_bytes", "Docker buildx state file")
        if size > gate_h_experiment_contract.GATE_H_DOCKER_BUILDX_STATE_MAX_FILE_BYTES:
            raise ResultsError("Gate-H Docker buildx state file exceeds its bound")
        try:
            data = base64.b64decode(entry["content_base64"], validate=True)
        except (KeyError, ValueError) as error:
            raise ResultsError("Gate-H Docker buildx state base64 is invalid") from error
        if (
            len(data) != size
            or hashlib.sha256(data).hexdigest() != entry.get("sha256")
            or not HEX_64.fullmatch(str(entry.get("sha256")))
        ):
            raise ResultsError("Gate-H Docker buildx state file digest differs")
        total_bytes += size
        files[relative] = (entry, data)
    if (
        set(directories)
        != {
            ".",
            "activity",
            "defaults",
            "instances",
            "refs",
            "refs/default",
            "refs/default/default",
        }
        or total_bytes != inventory.get("total_file_bytes")
        or total_bytes
        > gate_h_experiment_contract.GATE_H_DOCKER_BUILDX_STATE_MAX_TOTAL_BYTES
    ):
        raise ResultsError("Gate-H Docker buildx state bounds or layout differ")
    fixed_files = {".lock", ".buildNodeID", "activity/default"}
    if not fixed_files.issubset(files):
        raise ResultsError("Gate-H Docker buildx fixed state is incomplete")
    dynamic_refs = sorted(set(files) - fixed_files)
    if (
        len(dynamic_refs) != 1
        or not dynamic_refs[0].startswith("refs/default/default/")
        or gate_h_experiment_contract.GATE_H_DOCKER_BUILDX_REF.fullmatch(
            dynamic_refs[0].rsplit("/", 1)[1]
        )
        is None
        or files[".lock"][0].get("mode") != "0600"
        or files[".lock"][1] != b""
        or files[".buildNodeID"][0].get("mode") != "0600"
        or re.fullmatch(rb"[a-z0-9]{16}", files[".buildNodeID"][1]) is None
        or files["activity/default"][0].get("mode") != "0600"
        or re.fullmatch(
            rb"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z",
            files["activity/default"][1],
        )
        is None
        or files[dynamic_refs[0]][0].get("mode") != "0644"
    ):
        raise ResultsError("Gate-H Docker buildx fixed state differs")
    try:
        ref = json.loads(files[dynamic_refs[0]][1])
    except json.JSONDecodeError as error:
        raise ResultsError("Gate-H Docker buildx ref is not JSON") from error
    signed_source = str((root / "gate-h-signed-source").resolve())
    if ref != {
        "Target": "default",
        "LocalPath": signed_source,
        "DockerfilePath": f"{signed_source}/lab/Dockerfile",
    }:
        raise ResultsError("Gate-H Docker buildx ref does not bind signed source")
    return value


def validate_gate_h_host_execution(
    root: Path, manifest: dict[str, Any]
) -> dict[str, Any]:
    """Revalidate the hermetic controller, tools, endpoint, and child environment."""

    value = manifest.get("host_execution")
    expected_keys = {
        "schema",
        "controller_argv",
        "controller_environment",
        "environment",
        "environment_sha256",
        "tools",
        "docker_endpoint",
        "docker_config",
    }
    if not isinstance(value, dict) or set(value) != expected_keys:
        raise ResultsError("Gate-H manifest has no exact host-execution receipt")
    if value.get("schema") != GATE_H_HOST_EXECUTION_SCHEMA:
        raise ResultsError("Gate-H host execution has the wrong schema")
    environment = value.get("environment")
    if (
        not isinstance(environment, dict)
        or set(environment)
        != gate_h_experiment_contract.GATE_H_HOST_ENVIRONMENT_KEYS
        or any(not isinstance(item, str) or not item for item in environment.values())
        or value.get("controller_environment") != environment
        or value.get("environment_sha256") != canonical_sha256(environment)
    ):
        raise ResultsError("Gate-H host environment is not exact and allowlisted")
    expected_environment_values = {
        "ASTER_GATE_H_HERMETIC": "1",
        "ASTER_GATE_H_REPOSITORY_WORKSPACE": require_string(
            manifest.get("signed_source", {}), "workspace", "signed source"
        ),
        "ASTER_GATE_H_SIGNED_CONTROLLER": str(
            (root / "gate-h-signed-source/lab/ip_mesh_experiment.py").resolve()
        ),
        "BUILDKIT_PROGRESS": "plain",
        "DOCKER_BUILDKIT": "1",
        "DOCKER_CLI_HINTS": "false",
        "DOCKER_CONFIG": str((root / "docker-config").resolve()),
        "LANG": "C",
        "LC_ALL": "C",
        "PATH": gate_h_experiment_contract.GATE_H_HOST_PATH,
        "PYTHONCOERCECLOCALE": "0",
        "PYTHONDONTWRITEBYTECODE": "1",
        "PYTHONHASHSEED": "0",
        "PYTHONNOUSERSITE": "1",
        "PYTHONSAFEPATH": "1",
        "PYTHONUTF8": "1",
        "TMPDIR": str((root / "host-tmp").resolve()),
        "__CF_USER_TEXT_ENCODING": f"0x{os.getuid():X}:0x0:0x0",
    }
    if any(environment.get(key) != item for key, item in expected_environment_values.items()):
        raise ResultsError("Gate-H host environment has unexpected fixed values")
    if not PurePath(require_string(environment, "HOME", "host environment")).is_absolute():
        raise ResultsError("Gate-H host HOME is not absolute")
    docker_host = require_string(environment, "DOCKER_HOST", "host environment")
    if not docker_host.startswith("unix://"):
        raise ResultsError("Gate-H Docker endpoint is not an explicit Unix socket")
    socket_path = Path(docker_host.removeprefix("unix://"))
    if not socket_path.is_absolute():
        raise ResultsError("Gate-H Docker endpoint socket path is not absolute")

    tools = value.get("tools")
    if not isinstance(tools, dict) or set(tools) != {
        "python",
        "docker",
        "docker_buildx",
        "git",
    }:
        raise ResultsError("Gate-H host tool binding is incomplete")
    records = read_command_records(root)
    version_argv = {
        "python": [tools["python"]["invocation_path"], "--version"],
        "git": [
            tools["git"]["invocation_path"],
            "version",
            "--build-options",
        ],
        "docker": [
            tools["docker"]["invocation_path"],
            "version",
            "--format",
            "{{json .}}",
        ],
        "docker_buildx": [
            tools["docker"]["invocation_path"],
            "buildx",
            "version",
        ],
    }
    for name, binding in tools.items():
        expected_binding_keys = {
            "requested_path",
            "invocation_path",
            "path",
            "size_bytes",
            "sha256",
            "version",
        }
        if name == "docker":
            expected_binding_keys.add("socket_path")
        if not isinstance(binding, dict) or set(binding) != expected_binding_keys:
            raise ResultsError(f"Gate-H {name} tool binding is malformed")
        requested = Path(require_string(binding, "requested_path", f"{name} tool"))
        invocation = Path(
            require_string(binding, "invocation_path", f"{name} tool")
        )
        tool_path = Path(require_string(binding, "path", f"{name} tool"))
        size = require_int(binding, "size_bytes", f"{name} tool")
        digest = require_string(binding, "sha256", f"{name} tool")
        try:
            if (
                not requested.is_absolute()
                or not invocation.is_absolute()
                or requested.resolve(strict=True) != tool_path
                or invocation.resolve(strict=True) != tool_path
                or tool_path.is_symlink()
                or not tool_path.is_file()
                or not os.access(tool_path, os.X_OK)
                or tool_path.stat().st_size != size
                or sha256_file(tool_path) != digest
            ):
                raise ResultsError(f"Gate-H {name} executable binding differs")
        except OSError as error:
            raise ResultsError(f"Gate-H {name} executable is unavailable") from error
        if not HEX_64.fullmatch(digest):
            raise ResultsError(f"Gate-H {name} executable digest is malformed")
        version = binding.get("version")
        expected_version_keys = {
            "argv",
            "command_sequence",
            "started_utc",
            "completed_utc",
            "duration_ms",
            "returncode",
            "stdout",
            "stderr",
        }
        expected_argv = version_argv[name]
        if (
            not isinstance(version, dict)
            or set(version) != expected_version_keys
            or version.get("argv") != expected_argv
            or require_int(version, "returncode", f"{name} version") != 0
            or not isinstance(version.get("started_utc"), str)
            or not version["started_utc"].strip()
            or not isinstance(version.get("completed_utc"), str)
            or not version["completed_utc"].strip()
            or not isinstance(version.get("stdout"), str)
            or not isinstance(version.get("stderr"), str)
            or not (version["stdout"].strip() or version["stderr"].strip())
        ):
            raise ResultsError(f"Gate-H {name} version receipt is malformed")
        sequence = require_int(version, "command_sequence", f"{name} version")
        record = records.get(sequence)
        if (
            record is None
            or record.get("argv") != expected_argv
            or record.get("returncode") != 0
            or record.get("stdout") != version["stdout"]
            or record.get("stderr") != version["stderr"]
            or record.get("environment_sha256") != value["environment_sha256"]
        ):
            raise ResultsError(
                f"Gate-H {name} version command log is not hash-bound"
            )

    controller_argv = value.get("controller_argv")
    if (
        not isinstance(controller_argv, list)
        or len(controller_argv) < 6
        or controller_argv[0] != tools["python"]["invocation_path"]
        or controller_argv[1:5]
        != list(gate_h_experiment_contract.GATE_H_PYTHON_FLAGS)
        or controller_argv[5]
        != str((root / "gate-h-signed-source/lab/ip_mesh_experiment.py").resolve())
        or any(not isinstance(argument, str) for argument in controller_argv)
    ):
        raise ResultsError("Gate-H controller argv is not bound to exact Python")
    endpoint = value.get("docker_endpoint")
    docker_version = tools["docker"]["version"]
    try:
        parsed_docker_version = json.loads(docker_version["stdout"])
    except json.JSONDecodeError as error:
        raise ResultsError("Gate-H Docker client/server receipt is not JSON") from error
    if (
        not isinstance(endpoint, dict)
        or endpoint
        != {
            "strategy": "explicit-unix-socket",
            "host": docker_host,
            "socket_path": str(socket_path),
            "version": parsed_docker_version,
        }
        or not isinstance(parsed_docker_version, dict)
        or not isinstance(parsed_docker_version.get("Client"), dict)
        or not isinstance(parsed_docker_version.get("Server"), dict)
        or tools["docker"].get("socket_path") != str(socket_path)
    ):
        raise ResultsError("Gate-H Docker client/server endpoint receipt differs")
    docker_config = value.get("docker_config")
    docker_config_path = root / "docker-config"
    buildx = tools["docker_buildx"]
    buildx_target = buildx["invocation_path"]
    buildx_plugin_path = (
        docker_config_path
        / gate_h_experiment_contract.GATE_H_DOCKER_BUILDX_PLUGIN_RELATIVE_PATH
    )
    expected_buildx_plugin = {
        "directory_path": str((docker_config_path / "cli-plugins").resolve()),
        "path": str(buildx_plugin_path.resolve()),
        "target": buildx_target,
        "symlink_size_bytes": len(os.fsencode(buildx_target)),
        "symlink_sha256": hashlib.sha256(os.fsencode(buildx_target)).hexdigest(),
        "resolved_path": buildx["path"],
        "executable_size_bytes": buildx["size_bytes"],
        "executable_sha256": buildx["sha256"],
        "installed": True,
    }
    if (
        docker_config
        != {
            "path": str(docker_config_path.resolve()),
            "created_fresh": True,
            "initial_entries": [],
            "buildx_plugin": expected_buildx_plugin,
        }
        or not docker_config_path.is_dir()
        or any(docker_config_path.iterdir())
    ):
        raise ResultsError("Gate-H Docker config is not retained empty")
    temporary = root / "host-tmp"
    if not temporary.is_dir():
        raise ResultsError("Gate-H host temporary directory is absent")

    for sequence, record in records.items():
        if record.get("environment_sha256") != value["environment_sha256"]:
            raise ResultsError(
                f"Gate-H command {sequence} is not bound to the host environment"
            )
        argv = record.get("argv")
        if not isinstance(argv, list) or not argv or not PurePath(argv[0]).is_absolute():
            raise ResultsError(f"Gate-H command {sequence} has no absolute executable")

    final_path = root / "gate-h-host-execution-final.json"
    final = read_object(final_path)
    cleanup_value = final.get("docker_buildx_cleanup")
    state_cleanup = _validate_gate_h_buildx_state_cleanup(
        cleanup_value.get("state_cleanup") if isinstance(cleanup_value, dict) else None,
        root=root,
    )
    expected_buildx_cleanup = {
        "plugin_path": str(buildx_plugin_path.resolve()),
        "expected_target": buildx_target,
        "plugin_present_before": True,
        "observed_target": buildx_target,
        "plugin_was_installed": True,
        "plugin_removed": True,
        "directory_path": str((docker_config_path / "cli-plugins").resolve()),
        "directory_removed": True,
        "state_cleanup": state_cleanup,
        "errors": [],
        "docker_config_entries": [],
        "passed": True,
    }
    if final != {
        "schema": GATE_H_HOST_EXECUTION_FINAL_SCHEMA,
        "completed_utc": final.get("completed_utc"),
        "environment_sha256": value["environment_sha256"],
        "docker_buildx_cleanup": expected_buildx_cleanup,
        "docker_config_entries": [],
        "owned_processes": 0,
        "registered_docker_resources": 0,
        "passed": True,
    } or not isinstance(final.get("completed_utc"), str) or not final["completed_utc"].strip():
        raise ResultsError("Gate-H final host-execution receipt did not pass")
    return {
        "environment_sha256": value["environment_sha256"],
        "tools": {
            name: {
                "path": binding["path"],
                "invocation_path": binding["invocation_path"],
                "sha256": binding["sha256"],
                "version_command_sequence": binding["version"]["command_sequence"],
            }
            for name, binding in tools.items()
        },
        "docker_host": docker_host,
        "final_sha256": sha256_file(final_path),
    }


def _validate_retained_source_freeze_git_commands(
    commands: Any,
    *,
    commit: str,
    tree: str,
    requirements_blob: str,
    requirements_size: int,
    trust: dict[str, Any],
) -> None:
    expected = (
        (
            "source-freeze:head",
            ["rev-parse", "HEAD"],
            commit.encode("utf-8"),
        ),
        (
            "candidate-tree",
            ["rev-parse", f"{commit}^{{tree}}"],
            tree.encode("utf-8"),
        ),
        (
            "source-freeze:status",
            ["status", "--porcelain=v1", "--untracked-files=all"],
            b"",
        ),
        (
            "candidate-blob-id:data-mesh-requirements.md",
            ["rev-parse", f"{commit}:data-mesh-requirements.md"],
            requirements_blob.encode("utf-8"),
        ),
        (
            "candidate-blob:data-mesh-requirements.md",
            ["cat-file", "blob", f"{commit}:data-mesh-requirements.md"],
            None,
        ),
    )
    if not isinstance(commands, list) or len(commands) != len(expected):
        raise ResultsError("Gate-H source freeze has no exact Git command receipts")
    try:
        for command, (context, arguments, expected_stdout) in zip(
            commands, expected, strict=True
        ):
            stdout, _stderr = gate_h_signature._validate_successful_command(
                command,
                argv=gate_h_signature.git_argv(trust, arguments),
                environment=trust["git_environment"],
                workspace=REPOSITORY_WORKSPACE,
                context=context,
            )
            if expected_stdout is None:
                if (
                    len(stdout) != requirements_size
                    or hashlib.sha256(stdout).hexdigest() != REQUIREMENTS_SHA256
                ):
                    raise gate_h_signature.SignatureTrustError(
                        f"{context} output differs"
                    )
            elif stdout.rstrip(b"\r\n") != expected_stdout:
                raise gate_h_signature.SignatureTrustError(
                    f"{context} output differs"
                )
    except gate_h_signature.SignatureTrustError as error:
        raise ResultsError(f"Gate-H source-freeze Git evidence is invalid: {error}") from error


def validate_gate_h_signature_evidence(
    root: Path,
    manifest: dict[str, Any],
    *,
    candidate_commit: str,
    source_freeze: dict[str, Any],
) -> dict[str, Any]:
    """Validate the caller-selected signer anchor and reverify the commit post-hoc."""

    trust = manifest.get("signature_trust")
    anchor = manifest.get("signature_anchor")
    verification = manifest.get("signature_verification")
    request = manifest.get("signature_request")
    base_environment = manifest["host_execution"]["environment"]
    if not isinstance(trust, dict):
        raise ResultsError("Gate-H manifest has no live signature trust receipt")
    if not isinstance(request, dict) or set(request) != {
        "git",
        "ssh_keygen",
        "ssh",
        "allowed_signers",
        "principal",
    }:
        raise ResultsError("Gate-H manifest has no exact signature request")
    if any(
        not isinstance(request[field], str) or not request[field]
        for field in request
    ):
        raise ResultsError("Gate-H signature request contains an empty value")
    for field in ("git", "ssh_keygen", "ssh", "allowed_signers"):
        if not PurePath(request[field]).is_absolute():
            raise ResultsError(f"Gate-H signature request {field} is not absolute")
    if gate_h_signature.SAFE_PRINCIPAL.fullmatch(request["principal"]) is None:
        raise ResultsError("Gate-H signature request principal is unsafe")
    try:
        allowed_value = gate_h_signature.validate_signature_trust_receipt(
            trust,
            workspace=REPOSITORY_WORKSPACE,
            expected_principal=request["principal"],
            verify_tool_files=True,
            verify_frozen_file=False,
        )
        gate_h_signature.validate_signature_anchor_receipt(
            anchor,
            trust,
            workspace=REPOSITORY_WORKSPACE,
            base_environment=base_environment,
        )
        gate_h_signature.validate_signature_verification_receipt(
            verification,
            candidate_commit,
            trust,
            workspace=REPOSITORY_WORKSPACE,
            base_environment=base_environment,
        )
    except gate_h_signature.SignatureTrustError as error:
        raise ResultsError(f"Gate-H live signature evidence is invalid: {error}") from error

    tools = trust["tools"]
    anchor_allowed = anchor["allowed_signers"]
    host_git = manifest["host_execution"]["tools"]["git"]
    expected_git_identity = {
        "invocation": host_git["invocation_path"],
        "path": host_git["path"],
        "size_bytes": host_git["size_bytes"],
        "sha256": host_git["sha256"],
    }
    actual_git_identity = {
        key: tools["git"][key] for key in expected_git_identity
    }
    if (
        actual_git_identity != expected_git_identity
        or request["git"] != tools["git"]["invocation"]
        or request["ssh_keygen"] != tools["ssh-keygen"]["invocation"]
        or request["ssh"] != tools["ssh"]["invocation"]
        or request["allowed_signers"] != anchor_allowed["invocation"]
        or request["principal"] != trust["principal"]
        or trust["git_environment"]
        != gate_h_signature.git_environment(base_environment)
    ):
        raise ResultsError(
            "Gate-H signature request, tools, or host Git environment differ"
        )
    trust_sha256 = canonical_sha256(trust)
    if (
        source_freeze.get("signature_trust_sha256") != trust_sha256
        or source_freeze.get("signature_verification") != verification
        or source_freeze.get("signature_status") != verification["status"]
        or source_freeze.get("signature_signer") != verification["principal"]
        or source_freeze.get("signature_fingerprint")
        != verification["fingerprint"]
    ):
        raise ResultsError("Gate-H source freeze differs from its signature trust")
    if (
        not isinstance(source_freeze.get("requirements_git_blob"), str)
        or HEX_40.fullmatch(source_freeze["requirements_git_blob"]) is None
        or isinstance(source_freeze.get("requirements_size_bytes"), bool)
        or not isinstance(source_freeze.get("requirements_size_bytes"), int)
        or source_freeze["requirements_size_bytes"] <= 0
    ):
        raise ResultsError("Gate-H signed requirements source binding is malformed")
    _validate_retained_source_freeze_git_commands(
        source_freeze.get("git_commands"),
        commit=candidate_commit,
        tree=source_freeze["candidate_tree"],
        requirements_blob=source_freeze["requirements_git_blob"],
        requirements_size=source_freeze["requirements_size_bytes"],
        trust=trust,
    )

    retained_signers = root / "gate-h-allowed-signers"
    try:
        retained_metadata = retained_signers.stat()
        retained_value = retained_signers.read_bytes()
    except OSError as error:
        raise ResultsError("Gate-H retained allowed-signers is unavailable") from error
    if (
        retained_signers.is_symlink()
        or not retained_signers.is_file()
        or retained_metadata.st_mode & 0o777 != 0o400
        or retained_value != allowed_value
    ):
        raise ResultsError("Gate-H retained allowed-signers bytes or mode differ")

    final_path = root / "gate-h-signature-final.json"
    final = read_object(final_path)
    expected_final_tools = {
        name: {
            "path": binding["path"],
            "size_bytes": binding["size_bytes"],
            "sha256": binding["sha256"],
        }
        for name, binding in sorted(tools.items())
    }
    frozen_final = final.get("frozen_allowed_signers")
    if (
        set(final)
        != {
            "schema",
            "completed_utc",
            "principal",
            "signature_trust_sha256",
            "frozen_allowed_signers",
            "tools",
            "passed",
        }
        or final.get("schema") != GATE_H_SIGNATURE_FINAL_SCHEMA
        or not isinstance(final.get("completed_utc"), str)
        or not final["completed_utc"].strip()
        or final.get("principal") != trust["principal"]
        or final.get("signature_trust_sha256") != trust_sha256
        or not isinstance(frozen_final, dict)
        or set(frozen_final) != {"path", "size_bytes", "sha256"}
        or PurePath(frozen_final.get("path", "")).name
        != "gate-h-allowed-signers"
        or frozen_final.get("size_bytes") != len(allowed_value)
        or frozen_final.get("sha256") != hashlib.sha256(allowed_value).hexdigest()
        or final.get("tools") != expected_final_tools
        or final.get("passed") is not True
    ):
        raise ResultsError("Gate-H final signature-trust receipt differs")

    try:
        with tempfile.TemporaryDirectory(
            prefix="aster-gate-h-signature-posthoc-"
        ) as temporary:
            rebound = gate_h_signature.rebind_signature_trust(
                trust,
                workspace=REPOSITORY_WORKSPACE,
                frozen_directory=Path(temporary).resolve(),
                expected_principal=request["principal"],
            )
            posthoc = gate_h_signature.verify_commit(
                candidate_commit,
                rebound,
                workspace=REPOSITORY_WORKSPACE,
                base_environment=base_environment,
                run_command=gate_h_experiment_contract.run_gate_h_signature_command,
            )
    except gate_h_signature.SignatureTrustError as error:
        raise ResultsError(f"Gate-H post-hoc signature verification failed: {error}") from error
    for field in ("commit", "status", "principal", "fingerprint", "passed"):
        if posthoc.get(field) != verification.get(field):
            raise ResultsError(
                f"Gate-H post-hoc signature {field} differs from live evidence"
            )
    return {
        "principal": trust["principal"],
        "fingerprint": verification["fingerprint"],
        "trust_sha256": trust_sha256,
        "anchor_sha256": canonical_sha256(anchor),
        "verification_sha256": canonical_sha256(verification),
        "final_sha256": sha256_file(final_path),
    }


def validate_gate_h_signed_source_evidence(
    root: Path,
    manifest: dict[str, Any],
    *,
    source_freeze: dict[str, Any],
) -> dict[str, Any]:
    """Revalidate and independently rematerialize the Docker build source."""

    receipt = manifest.get("signed_source")
    trust = manifest.get("signature_trust")
    expected_sha256 = manifest.get("signed_source_sha256")
    if (
        not isinstance(receipt, dict)
        or not isinstance(trust, dict)
        or not isinstance(expected_sha256, str)
        or HEX_64.fullmatch(expected_sha256) is None
        or gate_h_source.canonical_sha256(receipt) != expected_sha256
        or receipt.get("commit") != source_freeze["candidate_commit"]
        or receipt.get("tree") != source_freeze["candidate_tree"]
        or receipt.get("signature_trust_sha256")
        != source_freeze["signature_trust_sha256"]
    ):
        raise ResultsError("Gate-H signed source identity differs")
    archive_path = root / "gate-h-signed-source.tar"
    export_root = root / "gate-h-signed-source"
    if (
        receipt.get("archive", {}).get("path") != str(archive_path.resolve())
        or receipt.get("export", {}).get("path") != str(export_root.resolve())
    ):
        raise ResultsError("Gate-H signed source retained paths differ")
    try:
        validated_root = gate_h_source.validate_signed_tree_receipt(
            receipt,
            workspace=REPOSITORY_WORKSPACE,
            trust=trust,
            verify_archive_file=True,
            verify_export=True,
        )
        with tempfile.TemporaryDirectory(
            prefix="aster-gate-h-source-posthoc-"
        ) as temporary:
            rebound = gate_h_source.rematerialize_signed_tree(
                receipt,
                workspace=REPOSITORY_WORKSPACE,
                trust=trust,
                archive_path=archive_path.resolve(),
                export_root=(Path(temporary) / "source").resolve(),
            )
            gate_h_source.validate_signed_tree_receipt(
                rebound,
                workspace=REPOSITORY_WORKSPACE,
                trust=trust,
                verify_archive_file=True,
                verify_export=True,
            )
    except gate_h_source.SignedSourceError as error:
        raise ResultsError(f"Gate-H signed source evidence is invalid: {error}") from error
    return {
        "sha256": expected_sha256,
        "archive_sha256": receipt["archive"]["sha256"],
        "tree": receipt["tree"],
        "file_count": receipt["export"]["file_count"],
        "build_context": str(validated_root),
    }


def _validate_export_python_binding(
    value: Any,
    *,
    relative_path: str,
    code_root: Path,
    signed_files: dict[str, dict[str, Any]],
    materialized: bool,
) -> None:
    expected_keys = {
        "raw_path",
        "path",
        "relative_path",
        "mode",
        "filesystem_mode",
        "size_bytes",
        "sha256",
        "cached_path",
        "cached_path_absent",
    }
    source = signed_files.get(relative_path)
    expected_path = (code_root / relative_path).resolve()
    expected_mode = (
        "0555" if source and source.get("mode") == "100755" else "0444"
    )
    if not materialized:
        expected_mode = (
            "0755" if source and source.get("mode") == "100755" else "0644"
        )
    if (
        not isinstance(value, dict)
        or set(value) != expected_keys
        or not isinstance(source, dict)
        or value.get("relative_path") != relative_path
        or value.get("raw_path") != str(expected_path)
        or value.get("path") != str(expected_path)
        or value.get("mode") != source.get("mode")
        or value.get("filesystem_mode") != expected_mode
        or value.get("size_bytes") != source.get("size_bytes")
        or value.get("sha256") != source.get("sha256")
        or not isinstance(value.get("cached_path_absent"), bool)
    ):
        raise ResultsError(f"Gate-H exported Python binding differs: {relative_path}")


def _path_is_equal_to_or_beneath(path: Path, root: Path) -> bool:
    resolved_path = path.resolve()
    resolved_root = root.resolve()
    return resolved_path == resolved_root or resolved_root in resolved_path.parents


def validate_gate_h_export_execution(
    root: Path,
    manifest: dict[str, Any],
    *,
    signed_source: dict[str, Any],
) -> dict[str, Any]:
    """Require the privileged controller to be the signed exported Python code."""

    value = manifest.get("export_execution")
    expected_keys = {
        "schema",
        "sentinel_sha256",
        "repository_workspace",
        "code_root",
        "python",
        "argv",
        "environment",
        "handoff",
        "runner",
        "modules",
        "bootstrap_modules",
        "signature_anchor",
        "sys_path",
        "bytecode",
        "modules_after",
        "passed",
    }
    if (
        not isinstance(value, dict)
        or set(value) != expected_keys
        or value.get("schema") != GATE_H_EXPORT_EXECUTION_SCHEMA
        or not isinstance(value.get("sentinel_sha256"), str)
        or HEX_64.fullmatch(value["sentinel_sha256"]) is None
        or value.get("passed") is not False
        or value.get("modules_after") is not None
    ):
        raise ResultsError("Gate-H manifest has no exact export execution receipt")
    receipt = manifest["signed_source"]
    export_root = (root / "gate-h-signed-source").resolve()
    signed_files = {
        binding["path"]: binding
        for binding in receipt.get("files", [])
        if isinstance(binding, dict) and isinstance(binding.get("path"), str)
    }
    host = manifest["host_execution"]
    host_python = host["tools"]["python"]
    expected_python = {
        "invocation": host_python["invocation_path"],
        "path": host_python["path"],
        "size_bytes": host_python["size_bytes"],
        "sha256": host_python["sha256"],
    }
    expected_flags = {
        "dont_write_bytecode": 1,
        "ignore_environment": 1,
        "no_site": 1,
        "no_user_site": 1,
    }
    if (
        value.get("python") != expected_python
        or value.get("environment") != host.get("environment")
        or value.get("repository_workspace") != receipt.get("workspace")
        or value.get("code_root") != str(export_root)
        or value.get("argv") != host.get("controller_argv")
        or value.get("bytecode")
        != {
            "flags": expected_flags,
            "pycache_or_pyc_before": [],
            "pycache_or_pyc_after": None,
        }
        or value.get("signature_anchor") != manifest.get("signature_anchor")
    ):
        raise ResultsError("Gate-H exported controller provenance differs")
    _validate_export_python_binding(
        value.get("runner"),
        relative_path="lab/ip_mesh_experiment.py",
        code_root=export_root,
        signed_files=signed_files,
        materialized=True,
    )
    modules = value.get("modules")
    if (
        not isinstance(modules, dict)
        or set(modules) != set(gate_h_experiment_contract.GATE_H_EXPORT_MODULES)
    ):
        raise ResultsError("Gate-H exported module inventory differs")
    for name, relative_path in gate_h_experiment_contract.GATE_H_EXPORT_MODULES.items():
        _validate_export_python_binding(
            modules[name],
            relative_path=relative_path,
            code_root=export_root,
            signed_files=signed_files,
            materialized=True,
        )
    bootstrap_modules = value.get("bootstrap_modules")
    bootstrap_paths = {
        "ip_mesh_experiment": "lab/ip_mesh_experiment.py",
        **gate_h_experiment_contract.GATE_H_EXPORT_MODULES,
    }
    if not isinstance(bootstrap_modules, dict) or set(
        bootstrap_modules
    ) != set(bootstrap_paths):
        raise ResultsError("Gate-H bootstrap module inventory differs")
    for name, relative_path in bootstrap_paths.items():
        _validate_export_python_binding(
            bootstrap_modules[name],
            relative_path=relative_path,
            code_root=Path(receipt["workspace"]),
            signed_files=signed_files,
            materialized=False,
        )
    sys_path = value.get("sys_path")
    if (
        not isinstance(sys_path, list)
        or not sys_path
        or sys_path[0] != str((export_root / "lab").resolve())
        or any(not isinstance(item, str) for item in sys_path)
        or any(
            item
            and not _path_is_equal_to_or_beneath(Path(item), export_root)
            and _path_is_equal_to_or_beneath(
                Path(item), Path(receipt["workspace"])
            )
            for item in sys_path
        )
    ):
        raise ResultsError("Gate-H exported controller import path differs")
    handoff_binding = value.get("handoff")
    handoff = root / "gate-h-export-handoff.json"
    if (
        not isinstance(handoff_binding, dict)
        or set(handoff_binding)
        != {"path", "size_bytes", "sha256", "payload_sha256"}
        or handoff_binding.get("path") != str(handoff.resolve())
        or not handoff.is_file()
        or handoff.is_symlink()
        or handoff.stat().st_size != handoff_binding.get("size_bytes")
        or sha256_file(handoff) != handoff_binding.get("sha256")
    ):
        raise ResultsError("Gate-H exported controller handoff differs")
    final_path = root / "gate-h-export-execution-final.json"
    final = read_object(final_path)
    expected_after = json.loads(json.dumps(value))
    expected_after["modules_after"] = expected_after["modules"]
    expected_after["bytecode"]["pycache_or_pyc_after"] = []
    expected_after["passed"] = True
    if (
        final
        != {
            "schema": GATE_H_EXPORT_EXECUTION_SCHEMA,
            "completed_utc": final.get("completed_utc"),
            "before_sha256": canonical_sha256(value),
            "before": value,
            "after": expected_after,
            "passed": True,
        }
        or not isinstance(final.get("completed_utc"), str)
        or not final["completed_utc"].strip()
    ):
        raise ResultsError("Gate-H final export execution receipt did not pass")
    return {
        "sha256": canonical_sha256(value),
        "final_sha256": sha256_file(final_path),
        "code_root": str(export_root),
    }


def validate_gate_h_resource_cleanup(
    root: Path,
    manifest: dict[str, Any],
    *,
    run_id: str,
    docker_binary: str,
) -> dict[str, Any]:
    """Bind every ephemeral Gate-H container to a named no-remain receipt."""

    path = root / "gate-h-resource-cleanup.jsonl"
    if not path.is_file():
        raise ResultsError("Gate-H evidence has no resource-cleanup log")
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except (OSError, UnicodeError) as error:
        raise ResultsError(f"cannot read Gate-H resource-cleanup log: {error}") from error
    receipts: list[dict[str, Any]] = []
    for line_number, line in enumerate(lines, start=1):
        try:
            value = json.loads(
                line,
                object_pairs_hook=_pairs_object,
                parse_constant=_reject_constant,
            )
        except (json.JSONDecodeError, ResultsError) as error:
            raise ResultsError(
                f"invalid Gate-H resource-cleanup record at line {line_number}: {error}"
            ) from error
        if not isinstance(value, dict):
            raise ResultsError(
                f"Gate-H resource-cleanup record {line_number} is not an object"
            )
        receipts.append(value)

    expected: dict[str, dict[str, Any]] = {
        f"aster-mesh-{run_id}-t00-build-extract": {
            "reason": "gate-h-binary-extraction",
            "owner": "gate-h-binary-extraction",
            "registration_sequence": 1,
            "remaining": 0,
            "offline_command": None,
        }
    }
    registration_sequence = 1
    seed = require_int(manifest, "seed", "manifest")
    payload_bytes = require_int(manifest, "payload_bytes", "manifest")
    image = require_string(manifest, "image", "manifest")
    binary = root / "candidate-aster-lab"
    for trial in range(1, 11):
        registration_sequence += 5
        for role, command in (
            (
                "prepare",
                [
                    "mesh-prepare",
                    "--root",
                    "/lab/run",
                    "--seed",
                    str(seed + trial),
                    "--payload-bytes",
                    str(payload_bytes),
                ],
            ),
            (
                "custody",
                [
                    "mesh-verify-relay",
                    "--root",
                    "/lab/run",
                    "--invocation",
                    f"t{trial:02d}_gate_pre",
                ],
            ),
            (
                "delivery",
                [
                    "mesh-consume",
                    "--root",
                    "/lab/run",
                    "--invocation",
                    f"t{trial:02d}_gate_post",
                ],
            ),
        ):
            registration_sequence += 1
            name = f"aster-mesh-{run_id}-t{trial:02d}-offline-{role}"
            expected[name] = {
                "reason": f"offline:{command[0]}",
                "owner": f"offline:{command[0]}",
                "registration_sequence": registration_sequence,
                "remaining": 5,
                "offline_command": command,
                "trial": trial,
                "image": image,
                "binary": binary,
            }

    if len(receipts) != len(expected):
        raise ResultsError(
            "Gate-H resource-cleanup log does not contain extraction plus 30 offline receipts"
        )
    records = read_command_records(root)
    records_by_argv: dict[tuple[str, ...], list[dict[str, Any]]] = {}
    for record in records.values():
        argv = record.get("argv")
        if isinstance(argv, list) and all(isinstance(item, str) for item in argv):
            records_by_argv.setdefault(tuple(argv), []).append(record)

    seen: set[str] = set()
    for line_number, receipt in enumerate(receipts, start=1):
        if receipt.get("schema") != GATE_H_RESOURCE_CLEANUP_SCHEMA:
            raise ResultsError(
                f"Gate-H resource-cleanup record {line_number} has the wrong schema"
            )
        if (
            receipt.get("passed") is not True
            or receipt.get("deferred_signals") != []
            or not isinstance(receipt.get("completed_utc"), str)
            or not receipt["completed_utc"].strip()
        ):
            raise ResultsError(
                f"Gate-H resource-cleanup record {line_number} did not pass cleanly"
            )
        resources = receipt.get("resources")
        if not isinstance(resources, list) or len(resources) != 1:
            raise ResultsError(
                f"Gate-H resource-cleanup record {line_number} is not one exact resource"
            )
        resource = resources[0]
        if not isinstance(resource, dict):
            raise ResultsError(
                f"Gate-H resource-cleanup record {line_number} resource is malformed"
            )
        name = resource.get("name")
        binding = expected.get(name) if isinstance(name, str) else None
        if binding is None or name in seen:
            raise ResultsError("Gate-H resource-cleanup name is unexpected or duplicated")
        seen.add(name)
        if (
            resource.get("kind") != "container"
            or resource.get("owner") != binding["owner"]
            or resource.get("registration_sequence")
            != binding["registration_sequence"]
            or resource.get("settled") is not True
            or receipt.get("reason") != binding["reason"]
            or receipt.get("remaining_registered_resources")
            != binding["remaining"]
        ):
            raise ResultsError(f"Gate-H resource-cleanup binding differs for {name}")
        attempts = resource.get("remove_attempts")
        remove_argv = [docker_binary, "rm", "--force", name]
        if (
            not isinstance(attempts, list)
            or len(attempts) != 1
            or not isinstance(attempts[0], dict)
            or attempts[0].get("argv") != remove_argv
            or isinstance(attempts[0].get("returncode"), bool)
            or not isinstance(attempts[0].get("returncode"), int)
        ):
            raise ResultsError(f"Gate-H resource-cleanup removal differs for {name}")
        remove_returncode = attempts[0]["returncode"]
        if len(records_by_argv.get(tuple(remove_argv), [])) != 1 or records_by_argv[
            tuple(remove_argv)
        ][0].get("returncode") != remove_returncode:
            raise ResultsError(
                f"Gate-H resource-cleanup removal is not command-bound for {name}"
            )
        absence = resource.get("absence_check")
        if remove_returncode == 0:
            if absence is not None:
                raise ResultsError(
                    f"Gate-H resource-cleanup has a redundant absence check for {name}"
                )
        else:
            enumerate_argv = [
                docker_binary,
                "container",
                "ls",
                "--all",
                "--filter",
                f"name=^/{name}$",
                "--format",
                "{{.Names}}",
            ]
            if (
                not isinstance(absence, dict)
                or absence.get("argv") != enumerate_argv
                or absence.get("returncode") != 0
                or absence.get("retained_names") != []
                or len(records_by_argv.get(tuple(enumerate_argv), [])) != 1
                or records_by_argv[tuple(enumerate_argv)][0].get("returncode") != 0
                or records_by_argv[tuple(enumerate_argv)][0].get("stdout", "").strip()
            ):
                raise ResultsError(
                    f"Gate-H resource-cleanup absence proof differs for {name}"
                )

        offline_command = binding["offline_command"]
        if offline_command is not None:
            trial_root = root / f"trial-{binding['trial']:02d}"
            run_argv = [
                docker_binary,
                "run",
                "--rm",
                "--name",
                name,
                "--pull=never",
                "--network",
                "none",
                "--read-only",
                "--tmpfs",
                "/tmp:rw,noexec,nosuid,nodev,size=64m",
                "--cap-drop",
                "ALL",
                "--security-opt",
                "no-new-privileges",
                "--mount",
                f"type=bind,src={binary.resolve()},dst=/experiment/aster-lab,readonly",
                "--mount",
                f"type=bind,src={trial_root.resolve()},dst=/lab/run",
                "--entrypoint",
                "/experiment/aster-lab",
                image,
                *offline_command,
            ]
            matches = records_by_argv.get(tuple(run_argv), [])
            if len(matches) != 1 or matches[0].get("returncode") != 0:
                raise ResultsError(
                    f"Gate-H named offline invocation is absent or duplicated for {name}"
                )
    if seen != set(expected):
        raise ResultsError("Gate-H resource-cleanup log is not a complete name bijection")
    return {"sha256": sha256_file(path), "receipt_count": len(receipts)}


def validate_gate_h_binary_provenance(
    root: Path,
    manifest: dict[str, Any],
    *,
    candidate_commit: str,
    binary_sha256: str,
    host_execution: dict[str, Any],
    signed_source: dict[str, Any],
) -> dict[str, Any]:
    metadata = manifest.get("gate_h_binary_provenance")
    if not isinstance(metadata, dict):
        raise ResultsError("Gate-H manifest has no binary provenance receipt")
    if metadata.get("path") != "gate-h-binary-provenance.json":
        raise ResultsError("Gate-H manifest has an unexpected binary provenance path")
    expected_receipt_sha = metadata.get("sha256")
    if not isinstance(expected_receipt_sha, str) or not HEX_64.fullmatch(
        expected_receipt_sha
    ):
        raise ResultsError("Gate-H manifest has no binary provenance digest")
    receipt_path = root / "gate-h-binary-provenance.json"
    if not receipt_path.is_file() or sha256_file(receipt_path) != expected_receipt_sha:
        raise ResultsError("Gate-H binary provenance differs from its manifest digest")
    receipt = read_object(receipt_path)
    validate_schema(
        receipt, GATE_H_BINARY_PROVENANCE_SCHEMA, str(receipt_path)
    )
    if receipt.get("candidate_commit") != candidate_commit:
        raise ResultsError("Gate-H binary provenance names the wrong candidate commit")
    image = require_string(manifest, "image", "manifest")
    expected_build_argv = gate_h_build_argv(image)
    docker_binary = host_execution["tools"]["docker"]["invocation_path"]
    expected_executed_build_argv = [docker_binary, *expected_build_argv[1:]]
    expected_build_command = shlex.join(expected_build_argv)
    if (
        receipt.get("build_argv") != expected_build_argv
        or receipt.get("build_command") != expected_build_command
        or manifest["source_freeze"].get("build_command") != expected_build_command
    ):
        raise ResultsError("Gate-H source build command is not the exact allowlisted command")
    build_cwd = require_string(receipt, "build_cwd", str(receipt_path))
    if (
        not PurePath(build_cwd).is_absolute()
        or build_cwd != signed_source["build_context"]
        or receipt.get("signed_source_sha256") != signed_source["sha256"]
        or metadata.get("signed_source_sha256") != signed_source["sha256"]
    ):
        raise ResultsError("Gate-H build is not bound to the signed source context")
    if receipt.get("image") != image or receipt.get("image_content") != manifest.get(
        "image_content"
    ):
        raise ResultsError("Gate-H binary provenance differs from the built image")
    if receipt.get("image_binary_path") != GATE_H_IMAGE_BINARY_PATH:
        raise ResultsError("Gate-H provenance extracted the wrong image binary")
    if receipt.get("extracted_binary_file") != "gate-h-image-aster-lab":
        raise ResultsError("Gate-H provenance retained an unexpected extracted file")
    if any(
        digest != binary_sha256
        for digest in (
            metadata.get("binary_sha256"),
            receipt.get("supplied_binary_sha256"),
            receipt.get("image_binary_sha256"),
        )
    ):
        raise ResultsError("Gate-H built, supplied, and frozen binary digests differ")
    extracted_binary = root / "gate-h-image-aster-lab"
    if not extracted_binary.is_file() or sha256_file(extracted_binary) != binary_sha256:
        raise ResultsError("Gate-H retained image binary differs from the frozen candidate")

    extraction = receipt.get("extraction")
    if not isinstance(extraction, dict):
        raise ResultsError("Gate-H binary provenance has no extraction receipt")
    container = require_string(extraction, "container", "Gate-H extraction")
    if not re.fullmatch(r"aster-mesh-[a-z0-9]{8}-t00-build-extract", container):
        raise ResultsError("Gate-H extraction used an unexpected container name")
    sequences = {
        field: require_int(extraction, field, "Gate-H extraction")
        for field in ("create_sequence", "copy_sequence", "cleanup_sequence")
    }
    if len(set(sequences.values())) != len(sequences) or any(
        sequence == 0 for sequence in sequences.values()
    ):
        raise ResultsError("Gate-H extraction command sequences are invalid")
    if require_int(extraction, "cleanup_returncode", "Gate-H extraction") != 0:
        raise ResultsError("Gate-H extraction container cleanup failed")
    build_sequence = require_int(receipt, "build_command_sequence", str(receipt_path))
    if build_sequence == 0:
        raise ResultsError("Gate-H build command sequence is zero")
    records = read_command_records(root)
    expected_commands = {
        build_sequence: (expected_executed_build_argv, build_cwd),
        sequences["create_sequence"]: (
            [docker_binary, "create", "--name", container, image],
            None,
        ),
        sequences["cleanup_sequence"]: (
            [docker_binary, "rm", "--force", container],
            None,
        ),
    }
    for sequence, (argv, cwd) in expected_commands.items():
        record = records.get(sequence)
        if (
            record is None
            or record.get("argv") != argv
            or record.get("returncode") != 0
            or (cwd is not None and record.get("cwd") != cwd)
        ):
            raise ResultsError("Gate-H provenance command log differs from its receipt")
    copy_record = records.get(sequences["copy_sequence"])
    if (
        copy_record is None
        or copy_record.get("returncode") != 0
        or copy_record.get("argv", [])[:3]
        != [docker_binary, "cp", f"{container}:{GATE_H_IMAGE_BINARY_PATH}"]
        or PurePath(copy_record["argv"][-1]).name != "gate-h-image-aster-lab"
    ):
        raise ResultsError("Gate-H image extraction command is not exact")
    return {
        "sha256": expected_receipt_sha,
        "binary_sha256": binary_sha256,
        "build_argv": expected_build_argv,
        "image_binary_path": GATE_H_IMAGE_BINARY_PATH,
    }


def validate_gate_h_fault_evidence(
    root: Path,
    manifest: dict[str, Any],
    *,
    candidate_commit: str,
    binary_sha256: str,
    binary_size: int,
    source_freeze: dict[str, Any],
    host_execution: dict[str, Any],
) -> dict[str, Any]:
    metadata = manifest.get("gate_h_fault_receipt")
    if not isinstance(metadata, dict):
        raise ResultsError("Gate-H manifest has no deterministic fault receipt")
    if metadata.get("path") != "gate-h-fault-receipt.json":
        raise ResultsError("Gate-H manifest has an unexpected fault receipt path")
    expected_sha256 = metadata.get("sha256")
    if not isinstance(expected_sha256, str) or not HEX_64.fullmatch(expected_sha256):
        raise ResultsError("Gate-H manifest has no exact fault receipt digest")
    path = root / "gate-h-fault-receipt.json"
    if not path.is_file() or sha256_file(path) != expected_sha256:
        raise ResultsError("Gate-H fault receipt differs from its manifest digest")
    value = read_object(path)
    timeout_seconds = require_int(
        value, "timeout_seconds_per_command", "Gate-H fault receipt"
    )
    if timeout_seconds < 1 or timeout_seconds > GATE_H_FAULT_MAX_TIMEOUT_SECONDS:
        raise ResultsError("Gate-H fault receipt has an invalid command timeout")

    def exact_returncode(item: Any, field: str, context: str) -> int:
        if not isinstance(item, dict):
            raise ResultsError(f"{context} is not an object")
        returncode = item.get(field)
        if isinstance(returncode, bool) or not isinstance(returncode, int):
            raise ResultsError(f"{context}.{field} is not a non-boolean integer")
        return returncode

    build_block = value.get("test_executable_build")
    build_receipts = (
        build_block.get("builds") if isinstance(build_block, dict) else None
    )
    if not isinstance(build_receipts, dict):
        raise ResultsError("Gate-H fault receipt has no executable build receipts")
    for package, build_receipt in build_receipts.items():
        if exact_returncode(
            build_receipt, "returncode", f"Gate-H {package} build"
        ) != 0:
            raise ResultsError(f"Gate-H {package} build returncode is not zero")
    fault_commands = value.get("commands")
    if not isinstance(fault_commands, list):
        raise ResultsError("Gate-H fault receipt has no command receipts")
    for index, command in enumerate(fault_commands):
        if exact_returncode(
            command, "returncode", f"Gate-H fault command {index}"
        ) != 0:
            raise ResultsError(f"Gate-H fault command {index} returncode is not zero")
    static_checks = value.get("static_checks")
    if not isinstance(static_checks, dict):
        raise ResultsError("Gate-H fault receipt has no static-check receipts")
    for name, check in static_checks.items():
        returncode = exact_returncode(check, "returncode", f"Gate-H static {name}")
        expected_returncode = exact_returncode(
            check, "expected_returncode", f"Gate-H static {name}"
        )
        if returncode != expected_returncode:
            raise ResultsError(f"Gate-H static {name} returncode differs")

    live_trust = manifest.get("signature_trust")
    request_record = manifest.get("signature_request")
    fault_trust = value.get("signature_trust")
    fault_verification = value.get("signature_verification")
    execution_provenance = value.get("execution_provenance")
    fault_environment = (
        execution_provenance.get("environment")
        if isinstance(execution_provenance, dict)
        else None
    )
    if (
        not isinstance(live_trust, dict)
        or not isinstance(request_record, dict)
        or not isinstance(fault_trust, dict)
        or not isinstance(fault_environment, dict)
    ):
        raise ResultsError("Gate-H fault signature trust evidence is incomplete")
    expected_metadata_keys = {
        "path",
        "sha256",
        "cases",
        "candidate_binary_sha256",
        "signature_anchor",
        "validation_git_commands",
    }
    if set(metadata) != expected_metadata_keys:
        raise ResultsError("Gate-H fault manifest metadata keys differ")
    try:
        gate_h_experiment_contract._validate_gate_h_execution_provenance(
            execution_provenance,
            verify_signed_source_files=False,
        )
        gate_h_signature.validate_signature_trust_receipt(
            fault_trust,
            workspace=REPOSITORY_WORKSPACE,
            expected_principal=request_record["principal"],
            verify_tool_files=True,
            verify_frozen_file=False,
        )
        gate_h_signature.validate_signature_verification_receipt(
            fault_verification,
            candidate_commit,
            fault_trust,
            workspace=REPOSITORY_WORKSPACE,
            base_environment=fault_environment,
        )
        gate_h_signature.validate_signature_anchor_receipt(
            metadata["signature_anchor"],
            fault_trust,
            workspace=REPOSITORY_WORKSPACE,
            base_environment=manifest["host_execution"]["environment"],
        )
        with tempfile.TemporaryDirectory(
            prefix="aster-gate-h-fault-signature-posthoc-"
        ) as temporary:
            rebound = gate_h_signature.rebind_signature_trust(
                live_trust,
                workspace=REPOSITORY_WORKSPACE,
                frozen_directory=Path(temporary).resolve(),
                expected_principal=request_record["principal"],
            )
            posthoc_request = gate_h_signature.SignatureRequest(
                git=Path(request_record["git"]),
                ssh_keygen=Path(request_record["ssh_keygen"]),
                ssh=Path(request_record["ssh"]),
                allowed_signers=Path(
                    rebound["allowed_signers"]["frozen_path"]
                ),
                principal=request_record["principal"],
            )
            gate_h_experiment_contract.validate_gate_h_fault_receipt(
                path,
                expected_commit=candidate_commit,
                expected_binary_sha256=binary_sha256,
                expected_binary_size=binary_size,
                expected_signature_status=source_freeze["signature_status"],
                expected_signature_signer=source_freeze["signature_signer"],
                expected_signature_fingerprint=source_freeze[
                    "signature_fingerprint"
                ],
                git_binary=host_execution["tools"]["git"]["invocation_path"],
                environment=manifest["host_execution"]["environment"],
                signature_trust=rebound,
                signature_request=posthoc_request,
                signed_source=manifest["signed_source"],
                verify_fault_signed_source_files=False,
            )
    except (
        gate_h_experiment_contract.ExperimentError,
        gate_h_signature.SignatureTrustError,
    ) as error:
        raise ResultsError(f"Gate-H deterministic fault receipt is invalid: {error}") from error

    validation_commands = metadata["validation_git_commands"]
    expected_commands: list[tuple[str, list[str], bytes, dict[str, Any] | None]] = [
        (
            "candidate-tree",
            ["rev-parse", f"{candidate_commit}^{{tree}}"],
            value["candidate_tree"].encode("utf-8"),
            None,
        )
    ]
    for binding in value["source_files"]:
        relative = binding["path"]
        expected_commands.extend(
            (
                (
                    f"candidate-blob-id:{relative}",
                    ["rev-parse", f"{candidate_commit}:{relative}"],
                    binding["git_blob"].encode("utf-8"),
                    None,
                ),
                (
                    f"candidate-blob:{relative}",
                    ["cat-file", "blob", f"{candidate_commit}:{relative}"],
                    b"",
                    binding,
                ),
            )
        )
    if not isinstance(validation_commands, list) or len(validation_commands) != len(
        expected_commands
    ):
        raise ResultsError("Gate-H fault validation Git command count differs")
    try:
        for command, (context, arguments, expected_stdout, source_binding) in zip(
            validation_commands, expected_commands, strict=True
        ):
            stdout, _stderr = gate_h_signature._validate_successful_command(
                command,
                argv=gate_h_signature.git_argv(live_trust, arguments),
                environment=live_trust["git_environment"],
                workspace=REPOSITORY_WORKSPACE,
                context=context,
            )
            if source_binding is None:
                if stdout.rstrip(b"\r\n") != expected_stdout:
                    raise gate_h_signature.SignatureTrustError(
                        f"{context} output differs"
                    )
            elif (
                len(stdout) != source_binding["size_bytes"]
                or hashlib.sha256(stdout).hexdigest() != source_binding["sha256"]
            ):
                raise gate_h_signature.SignatureTrustError(
                    f"{context} source bytes differ"
                )
    except gate_h_signature.SignatureTrustError as error:
        raise ResultsError(
            f"Gate-H retained fault-validation Git command is invalid: {error}"
        ) from error
    for field in (
        "signature_status",
        "signature_signer",
        "signature_fingerprint",
    ):
        if value.get(field) != source_freeze.get(field):
            raise ResultsError(f"Gate-H fault receipt {field} differs from source freeze")
    cases = value.get("cases")
    if (
        not isinstance(cases, dict)
        or set(cases) != GATE_H_FAULT_CASES
        or any(case is not True for case in cases.values())
    ):
        raise ResultsError("Gate-H fault receipt does not pass every mandatory case")
    if metadata.get("cases") != cases:
        raise ResultsError("Gate-H manifest cases differ from the fault receipt")
    if metadata.get("candidate_binary_sha256") != binary_sha256:
        raise ResultsError("Gate-H manifest fault receipt names the wrong binary digest")
    commands = value["commands"]
    return {
        "sha256": expected_sha256,
        "cases": cases,
        "command_count": len(commands),
        "static_check_count": len(value["static_checks"]),
        "test_executable_count": len(
            value["test_executable_build"]["executables"]
        ),
    }


def validate_schema(value: dict[str, Any], expected: str, context: str) -> None:
    if value.get("schema") != expected:
        raise ResultsError(
            f"{context}.schema differs: expected {expected!r}, got {value.get('schema')!r}"
        )


def trial_receipts(
    result: dict[str, Any], scenario: str, context: str
) -> list[tuple[str, dict[str, Any]]]:
    if scenario == "idle":
        receipt = result.get("receipt")
        if not isinstance(receipt, dict):
            raise ResultsError(f"{context}.receipt must be an object")
        return [("a", receipt)]
    field = "node_receipts" if scenario == "primary" else "receipts"
    receipts = result.get(field)
    if not isinstance(receipts, dict):
        raise ResultsError(f"{context}.{field} must be an object")
    expected = set(RECEIPT_ROLES[scenario])
    if set(receipts) != expected:
        raise ResultsError(
            f"{context}.{field} roles differ: expected {sorted(expected)}, got {sorted(receipts)}"
        )
    ordered = []
    for role in RECEIPT_ROLES[scenario]:
        receipt = receipts[role]
        if not isinstance(receipt, dict):
            raise ResultsError(f"{context}.{field}.{role} must be an object")
        ordered.append((role, receipt))
    return ordered


def collect_receipt(
    receipt: dict[str, Any],
    arm: str,
    context: str,
    samples: Samples,
    payload_bytes: int,
    discovery_source: str | None,
    provider_binary_sha256: str | None = None,
) -> bool:
    schema = require_string(receipt, "schema", context)
    if schema not in NODE_SCHEMAS[arm]:
        raise ResultsError(f"{context}.schema is not recognized for {arm}: {schema!r}")
    validate_provider_profile(
        receipt,
        arm=arm,
        discovery_source=discovery_source,
        context=context,
        provider_binary_sha256=provider_binary_sha256,
    )

    samples.add("node_elapsed_ms", require_number(receipt, "elapsed_ms", context))
    samples.add(
        "first_candidate_ms", number_or_none(receipt, "first_candidate_ms", context)
    )
    samples.add(
        "first_authenticated_ms",
        number_or_none(receipt, "first_authenticated_ms", context),
    )

    common = (
        "frames_received",
        "frames_sent",
        "pump_calls",
        "contact_failures",
        "duplicate_contacts",
        "active_contact_high_water",
        "admitted_contact_high_water",
        "candidates_discovered",
    )
    metrics = {field: require_number(receipt, field, context) for field in common}
    for field in common:
        samples.add(field, metrics[field])
    samples.add("frames_total", metrics["frames_received"] + metrics["frames_sent"])

    if schema == NATIVE_SHARED_NODE_SCHEMA:
        for field in NATIVE_PROTOCOL_COUNTER_FIELDS:
            samples.add(field, receipt[field])
        received = receipt["aster_bytes_received"]
        sent = receipt["aster_bytes_sent"]
    else:
        for field in NATIVE_PROTOCOL_COUNTER_FIELDS:
            samples.add(field, None)
    if schema.startswith(("aster-lab-iroh-", "aster-lab-libp2p-")):
        received = require_number(receipt, "bytes_received", context)
        sent = require_number(receipt, "bytes_sent", context)
    elif schema != NATIVE_SHARED_NODE_SCHEMA:
        received = number_or_none(receipt, "bytes_received", context)
        sent = number_or_none(receipt, "bytes_sent", context)
        if (received is None) != (sent is None):
            raise ResultsError(f"{context} must provide both byte counters or neither")
    samples.add("bytes_received", received)
    samples.add("bytes_sent", sent)
    samples.add("bytes_total", None if received is None or sent is None else received + sent)
    samples.add(
        "duplicate_connections",
        number_or_none(receipt, "duplicate_connections", context),
    )
    provider_mdns_announcements_unobservable = (
        arm in ("iroh", "libp2p")
        and receipt.get("candidate_source") == "provider-mdns"
    )
    samples.add(
        "discovery_announcements",
        None
        if provider_mdns_announcements_unobservable
        else number_or_none(receipt, "discovery_announcements", context),
    )
    if schema == NATIVE_SHARED_NODE_SCHEMA:
        high_water = receipt["node_resource_high_water"]
        rejections = receipt["node_resource_rejections"]
        samples.add(
            "node_resource_rejected_claims",
            require_number(receipt, "node_resource_rejected_claims", context),
        )
        for field in NODE_RESOURCE_FIELDS:
            samples.add(f"node_resource_high_water_{field}", high_water[field])
            samples.add(f"node_resource_rejections_{field}", rejections[field])
    else:
        samples.add("node_resource_rejected_claims", None)
        for field in NODE_RESOURCE_FIELDS:
            samples.add(f"node_resource_high_water_{field}", None)
            samples.add(f"node_resource_rejections_{field}", None)

    resources = receipt.get("experiment_resources")
    if resources is None:
        for field in (
            "cpu_usage_usec",
            "network_bytes",
            "memory_current_bytes",
            "memory_peak_bytes",
        ):
            samples.add(field, None)
        samples.add("application_payload_throughput_bps", None)
        samples.add("network_amplification_bytes_per_payload_byte", None)
        samples.add("durable_item_first_observed_ms", None)
        return False
    if not isinstance(resources, dict):
        raise ResultsError(f"{context}.experiment_resources must be an object")
    if resources.get("memory_current_sample_phase") != (
        "exact-item-observation-before-process-wait"
    ):
        raise ResultsError(
            f"{context}.experiment_resources does not identify a live memory sample"
        )
    if require_bool(
        resources,
        "memory_current_candidate_running",
        f"{context}.experiment_resources",
    ) is not True:
        raise ResultsError(f"{context}.experiment_resources sampled memory post-exit")
    resource_metrics: dict[str, int | float] = {}
    for field in (
        "cpu_usage_usec",
        "network_bytes",
        "memory_current_bytes",
        "memory_peak_bytes",
    ):
        resource_metrics[field] = require_number(
            resources, field, f"{context}.experiment_resources"
        )
        samples.add(field, resource_metrics[field])

    durable_context = f"{context}.experiment_resources"
    if "durable_item_present_before_contact" not in resources:
        samples.add("application_payload_throughput_bps", None)
        samples.add("network_amplification_bytes_per_payload_byte", None)
        samples.add("durable_item_first_observed_ms", None)
        return False
    present_before = require_bool(resources, "durable_item_present_before_contact", durable_context)
    observed = number_or_none(
        resources,
        "durable_item_first_observed_ms_from_process_launch",
        durable_context,
        required=True,
    )
    expected_scope = "read-only exact ItemID row; 10 ms controller polling"
    if resources.get("durable_probe_scope") != expected_scope:
        raise ResultsError(
            f"{durable_context}.durable_probe_scope does not establish the exact ItemID probe"
        )
    samples.add("durable_item_first_observed_ms", observed)
    if not present_before:
        if observed is None:
            raise ResultsError(
                f"{durable_context} never observed the exact ItemID after contact"
            )
        samples.add("durable_item_newly_observed_ms", observed)
        samples.add(
            "application_payload_throughput_bps",
            None if observed in (None, 0) else payload_bytes * 8_000 / observed,
        )
        samples.add(
            "network_amplification_bytes_per_payload_byte",
            resource_metrics["network_bytes"] / payload_bytes,
        )
        return True
    if observed != 0:
        raise ResultsError(
            f"{durable_context} preexisting ItemID must be recorded at zero milliseconds"
        )
    samples.add("application_payload_throughput_bps", None)
    samples.add("network_amplification_bytes_per_payload_byte", None)
    return False


def collect_idle(result: dict[str, Any], context: str, samples: Samples) -> None:
    duration = require_int(result, "duration_ms", context)
    settle = require_int(result, "settle_ms", context)
    if duration <= settle:
        raise ResultsError(f"{context} idle duration must exceed settle time")
    total = require_int(result, "cpu_usage_usec_total", context)
    settling = require_int(result, "cpu_usage_usec_settling", context)
    if settling > total:
        raise ResultsError(f"{context} settling CPU exceeds total CPU")
    settled = total - settling
    settled_wall_ms = duration - settle
    samples.add("idle_cpu_usage_usec_total", total)
    samples.add("idle_cpu_usage_usec_settling", settling)
    samples.add("idle_cpu_usage_usec_settled", settled)
    samples.add(
        "idle_cpu_percent_of_one_core_total",
        require_number(result, "cpu_percent_of_one_core_total", context),
    )
    samples.add(
        "idle_cpu_percent_of_one_core_settled",
        settled / (settled_wall_ms * 10.0),
    )
    samples.add(
        "idle_settled_network_bytes",
        require_number(result, "settled_network_bytes", context),
    )
    samples.add(
        "idle_settled_network_bytes_per_minute",
        require_number(result, "settled_network_bytes_per_minute", context),
    )
    samples.add(
        "idle_memory_current_after_settle_bytes",
        require_number(result, "memory_current_after_settle_bytes", context),
    )
    samples.add("idle_memory_peak_bytes", require_number(result, "memory_peak_bytes", context))


def result_suffixes(value: Any, context: str) -> list[tuple[str, str]]:
    if not isinstance(value, list):
        raise ResultsError(f"{context}.results must be an array")
    suffixes: list[tuple[str, str]] = []
    for index, item in enumerate(value, start=1):
        if not isinstance(item, str):
            raise ResultsError(f"{context}.results[{index - 1}] must be a string")
        parts = PurePath(item).parts
        if len(parts) < 2:
            raise ResultsError(f"{context}.results[{index - 1}] has no trial/result suffix")
        suffixes.append((parts[-2], parts[-1]))
    return suffixes


def require_identity_map(
    result: dict[str, Any], roles: Sequence[str], context: str
) -> dict[str, str]:
    value = result.get("identities")
    if not isinstance(value, dict) or set(value) != set(roles):
        raise ResultsError(
            f"{context}.identities must contain exactly {sorted(roles)}"
        )
    identities: dict[str, str] = {}
    for role in roles:
        identity = value.get(role)
        if not isinstance(identity, str) or not HEX_64.fullmatch(identity):
            raise ResultsError(f"{context}.identities.{role} is not a NodeID")
        identities[role] = identity
    if len(set(identities.values())) != len(identities):
        raise ResultsError(f"{context}.identities are not distinct")
    return identities


def require_exact_peer_receipt(
    receipt: dict[str, Any],
    *,
    identity: str,
    expected_peers: set[str],
    arm: str,
    context: str,
) -> None:
    if receipt.get("identity") != identity:
        raise ResultsError(f"{context}.identity differs from the retained identity map")
    for field in ("authenticated_peers", "unauthorized_peers"):
        value = receipt.get(field)
        if not isinstance(value, list) or any(not isinstance(item, str) for item in value):
            raise ResultsError(f"{context}.{field} must be a string array")
        if len(value) != len(set(value)):
            raise ResultsError(f"{context}.{field} contains duplicates")
    authenticated = receipt["authenticated_peers"]
    if set(authenticated) != expected_peers or len(authenticated) != len(expected_peers):
        raise ResultsError(f"{context} did not authenticate exactly the expected peers")
    if receipt["unauthorized_peers"]:
        raise ResultsError(f"{context} retained an unauthorized peer")
    if arm in ("iroh", "libp2p") or receipt.get("schema") == NATIVE_SHARED_NODE_SCHEMA:
        admitted = receipt.get("admitted_peers")
        if (
            not isinstance(admitted, list)
            or any(not isinstance(item, str) for item in admitted)
            or len(admitted) != len(expected_peers)
            or set(admitted) != expected_peers
        ):
            raise ResultsError(f"{context} did not admit exactly the expected peers")


def require_custody(value: Any, context: str) -> None:
    if not isinstance(value, dict):
        raise ResultsError(f"{context} must be an object")
    for field in (
        "exact_envelope",
        "application_unreadable",
        "payload_absent_at_rest",
        "payload_digest_absent_at_rest",
    ):
        if require_bool(value, field, context) is not True:
            raise ResultsError(f"{context}.{field} did not pass")


def require_delivery(value: Any, context: str) -> None:
    if not isinstance(value, dict):
        raise ResultsError(f"{context} must be an object")
    for field in ("same_item", "same_envelope", "application_acknowledged"):
        if require_bool(value, field, context) is not True:
            raise ResultsError(f"{context}.{field} did not pass")
    for field in ("immediate_post_ack_deliveries", "post_restart_deliveries"):
        if require_int(value, field, context) != 0:
            raise ResultsError(f"{context}.{field} is not zero")


def require_contact_ids(value: Any, context: str) -> list[int]:
    if (
        not isinstance(value, list)
        or any(
            isinstance(contact, bool) or not isinstance(contact, int) or contact < 0
            for contact in value
        )
        or value != sorted(set(value))
    ):
        raise ResultsError(f"{context} must be sorted unique nonnegative integers")
    return value


def validate_gate_h_cleanup(
    trial_root: Path, *, trial: int, run_id: str, docker_binary: str
) -> dict[str, Any]:
    path = trial_root / "cleanup.json"
    receipt = read_object(path)
    validate_schema(receipt, GATE_H_CLEANUP_SCHEMA, str(path))
    if require_int(receipt, "trial", str(path)) != trial:
        raise ResultsError(f"{path}.trial differs from its directory")
    if require_bool(receipt, "passed", str(path)) is not True:
        raise ResultsError(f"{path} records failed Gate-H cleanup")
    if receipt.get("primary_error") is not None:
        raise ResultsError(f"{path} retains a primary trial failure")
    commands = receipt.get("commands")
    if not isinstance(commands, list) or len(commands) != 5:
        raise ResultsError(f"{path} does not contain the exact five cleanup commands")
    prefix = f"aster-mesh-{run_id}-t{trial:02d}"
    expected = [
        [docker_binary, "rm", "--force", f"{prefix}-gate-a"],
        [docker_binary, "rm", "--force", f"{prefix}-gate-b"],
        [docker_binary, "rm", "--force", f"{prefix}-gate-c"],
        [docker_binary, "network", "rm", f"{prefix}-live-ab"],
        [docker_binary, "network", "rm", f"{prefix}-live-bc"],
    ]
    for index, (command, expected_argv) in enumerate(zip(commands, expected, strict=True)):
        if (
            not isinstance(command, dict)
            or command.get("argv") != expected_argv
            or command.get("returncode") != 0
            or "error" in command
        ):
            raise ResultsError(f"{path} cleanup command {index} is not exact and successful")
    return {"sha256": sha256_file(path), "command_count": len(commands)}


GATE_H_PROCESS_FILE = re.compile(
    r"^process-([0-9]{5})\.(command\.json|result\.json|stdout\.log|stderr\.log)$"
)
GATE_H_PROCESS_SUFFIXES = frozenset(
    {"command.json", "result.json", "stdout.log", "stderr.log"}
)
GATE_H_PROCESS_COMMAND_KEYS = frozenset(
    {"sequence", "utc", "argv", "environment_sha256"}
)
GATE_H_PROCESS_RESULT_KEYS = frozenset(
    {"returncode", "completed_utc", "timed_out"}
)


def read_gate_h_process_quartets(
    root: Path, *, trials: int, environment_sha256: str
) -> dict[int, dict[str, Any]]:
    """Read the complete, exact process-launch evidence set for Gate H."""

    grouped: dict[int, dict[str, Path]] = {}
    try:
        process_entries = sorted(
            (path for path in root.rglob("process-*") if path.name.startswith("process-")),
            key=lambda path: path.relative_to(root).as_posix(),
        )
    except OSError as error:
        raise ResultsError(f"cannot enumerate Gate-H process evidence: {error}") from error
    for path in process_entries:
        if path.parent != root:
            raise ResultsError(f"Gate-H process evidence is outside the run root: {path}")
        match = GATE_H_PROCESS_FILE.fullmatch(path.name)
        if match is None:
            raise ResultsError(f"unexpected Gate-H process evidence file: {path}")
        if path.is_symlink() or not path.is_file():
            raise ResultsError(f"Gate-H process evidence is not a regular file: {path}")
        sequence = int(match.group(1))
        if sequence == 0:
            raise ResultsError("Gate-H process evidence has a zero sequence")
        suffix = match.group(2)
        sequence_files = grouped.setdefault(sequence, {})
        if suffix in sequence_files:  # pragma: no cover - distinct paths cannot alias.
            raise ResultsError(f"duplicate Gate-H process evidence for sequence {sequence}")
        sequence_files[suffix] = path

    expected_quartets = trials * 4
    if len(grouped) != expected_quartets:
        raise ResultsError(
            f"Gate-H must retain exactly {expected_quartets} process quartets "
            f"for {trials} trials; found {len(grouped)}"
        )
    synchronous_sequences = set(read_command_records(root))
    overlapping_sequences = synchronous_sequences & set(grouped)
    if overlapping_sequences:
        raise ResultsError(
            "Gate-H process and synchronous command evidence reuse global sequences: "
            + ",".join(str(sequence) for sequence in sorted(overlapping_sequences))
        )

    quartets: dict[int, dict[str, Any]] = {}
    for sequence, paths in sorted(grouped.items()):
        if set(paths) != GATE_H_PROCESS_SUFFIXES:
            raise ResultsError(
                f"Gate-H process sequence {sequence} is an incomplete or extra quartet"
            )
        command_path = paths["command.json"]
        command = read_object(command_path)
        if set(command) != GATE_H_PROCESS_COMMAND_KEYS:
            raise ResultsError(f"{command_path} does not have the exact command keys")
        if require_int(command, "sequence", str(command_path)) != sequence:
            raise ResultsError(f"{command_path} filename sequence differs from its payload")
        if command.get("environment_sha256") != environment_sha256:
            raise ResultsError(
                f"{command_path} is not bound to the exact host environment"
            )
        utc = command.get("utc")
        if not isinstance(utc, str) or not utc.strip():
            raise ResultsError(f"{command_path}.utc must be a nonempty string")
        argv = command.get("argv")
        if (
            not isinstance(argv, list)
            or not argv
            or any(not isinstance(argument, str) for argument in argv)
        ):
            raise ResultsError(f"{command_path}.argv must be a nonempty string list")

        result_path = paths["result.json"]
        result = read_object(result_path)
        if set(result) != GATE_H_PROCESS_RESULT_KEYS:
            raise ResultsError(f"{result_path} does not have the exact result keys")
        returncode = result.get("returncode")
        if isinstance(returncode, bool) or not isinstance(returncode, int) or returncode != 0:
            raise ResultsError(f"{result_path}.returncode is not exactly zero")
        if result.get("timed_out") is not False:
            raise ResultsError(f"{result_path}.timed_out is not exactly false")
        completed_utc = result.get("completed_utc")
        if not isinstance(completed_utc, str) or not completed_utc.strip():
            raise ResultsError(f"{result_path}.completed_utc must be a nonempty string")

        quartets[sequence] = {
            "sequence": sequence,
            "argv": argv,
            "returncode": returncode,
            "command_path": command_path,
            "result_path": result_path,
            "stdout_path": paths["stdout.log"],
            "stderr_path": paths["stderr.log"],
        }
    return quartets


def expected_gate_h_process_commands(
    *,
    trial: int,
    run_id: str,
    duration_ms: int,
    identities: dict[str, str],
    item_id: str,
    docker_binary: str = "docker",
) -> dict[str, list[str]]:
    """Reconstruct the four native commands from the experiment contract."""

    args = SimpleNamespace(arm="native", duration_ms=duration_ms)
    durations = gate_h_experiment_contract.gate_h_process_durations(duration_ms)
    subnet_ab, _, broadcast_ab = gate_h_experiment_contract.network_spec(
        "native", trial, "live-ab"
    )
    subnet_bc, _, broadcast_bc = gate_h_experiment_contract.network_spec(
        "native", trial, "live-bc"
    )
    ab_second, ab_third = subnet_ab.split(".")[1:3]
    bc_second, bc_third = subnet_bc.split(".")[1:3]
    addresses = {
        "a": f"10.{ab_second}.{ab_third}.10",
        "b_ab": f"10.{ab_second}.{ab_third}.11",
        "b_bc": f"10.{bc_second}.{bc_third}.10",
        "c": f"10.{bc_second}.{bc_third}.11",
    }
    containers = {
        role: gate_h_experiment_contract.resource_name(
            run_id, trial, "gate", role
        )
        for role in ("a", "b", "c")
    }
    pre_invocation = f"t{trial:02d}_gate_pre"
    post_invocation = f"t{trial:02d}_gate_post"
    try:
        commands = {
            "b_pre": gate_h_experiment_contract.node_exec_command(
                args=args,
                container=containers["b"],
                invocation=pre_invocation,
                expected_peer=f"{identities['a']},{identities['c']}",
                broadcast=broadcast_ab,
                discovery_enabled=False,
                emission_mode=gate_h_experiment_contract.GATE_H_FLASH_ONLY_EMISSION_MODE,
                manual_peers=gate_h_experiment_contract.gate_h_relay_manual_peers(
                    identities, addresses
                ),
                duration_ms=durations["b_pre"],
                gate_h_control=gate_h_experiment_contract.GATE_H_CONTROL_PATH,
                gate_h_stale_target_peer=identities["c"],
                durable_item_probe=item_id,
            ),
            "c_continuous": gate_h_experiment_contract.node_exec_command(
                args=args,
                container=containers["c"],
                invocation=pre_invocation,
                expected_peer=identities["b"],
                broadcast=broadcast_bc,
                discovery_enabled=False,
                manual_peers=f"{identities['b']}@{addresses['b_bc']}:47101",
                duration_ms=durations["c_continuous"],
                durable_item_probe=item_id,
            ),
            "a_pre": gate_h_experiment_contract.node_exec_command(
                args=args,
                container=containers["a"],
                invocation=pre_invocation,
                expected_peer=identities["b"],
                broadcast=broadcast_ab,
                discovery_enabled=False,
                manual_peers=f"{identities['b']}@{addresses['b_ab']}:47101",
                duration_ms=durations["a_pre"],
                durable_item_probe=item_id,
            ),
            "b_post": gate_h_experiment_contract.node_exec_command(
                args=args,
                container=containers["b"],
                invocation=post_invocation,
                expected_peer=identities["c"],
                broadcast=broadcast_bc,
                discovery_enabled=False,
                manual_peers=f"{identities['c']}@{addresses['c']}:47101",
                duration_ms=durations["b_post"],
                durable_item_probe=item_id,
            ),
        }
        for command in commands.values():
            command[0] = docker_binary
        return commands
    except gate_h_experiment_contract.ExperimentError as error:
        raise ResultsError(
            f"cannot reconstruct Gate-H trial {trial} process commands: {error}"
        ) from error


def validate_gate_h_process_launches(
    *,
    trial: int,
    run_id: str,
    duration_ms: int,
    identities: dict[str, str],
    item_id: str,
    result: dict[str, Any],
    quartets: dict[int, dict[str, Any]],
    claimed_sequences: set[int],
    docker_binary: str,
) -> dict[str, Any]:
    """Prove one trial has a one-to-one mapping to its four launched nodes."""

    expected = expected_gate_h_process_commands(
        trial=trial,
        run_id=run_id,
        duration_ms=duration_ms,
        identities=identities,
        item_id=item_id,
        docker_binary=docker_binary,
    )
    matched: dict[str, dict[str, Any]] = {}
    for role, expected_argv in expected.items():
        candidates = [
            quartet
            for sequence, quartet in quartets.items()
            if sequence not in claimed_sequences and quartet["argv"] == expected_argv
        ]
        if len(candidates) != 1:
            raise ResultsError(
                f"Gate-H trial {trial} has {len(candidates)} exact {role} process commands"
            )
        matched[role] = candidates[0]
    sequences = [matched[role]["sequence"] for role in expected]
    if sequences != sorted(sequences):
        raise ResultsError(
            f"Gate-H trial {trial} process launch order is not B-pre, C, A, B-post"
        )
    if len(set(sequences)) != 4:
        raise ResultsError(f"Gate-H trial {trial} process command mapping is not bijective")
    claimed_sequences.update(sequences)

    observed_pre = {
        "a": matched["a_pre"]["returncode"],
        "b": matched["b_pre"]["returncode"],
    }
    observed_post = {
        "b": matched["b_post"]["returncode"],
        "c": matched["c_continuous"]["returncode"],
    }
    if result.get("pre_process_returncodes") != observed_pre:
        raise ResultsError(
            f"Gate-H trial {trial} pre-process returncodes do not reconcile "
            "with retained launch results"
        )
    if result.get("post_process_returncodes") != observed_post:
        raise ResultsError(
            f"Gate-H trial {trial} post-process returncodes do not reconcile "
            "with retained launch results"
        )

    return {
        "trial": trial,
        "sequences": {role: matched[role]["sequence"] for role in expected},
        "commands": {
            role: {
                "path": matched[role]["command_path"].name,
                "sha256": sha256_file(matched[role]["command_path"]),
            }
            for role in expected
        },
    }


def summarize_root(root: Path) -> dict[str, Any]:
    root = root.resolve()
    if not root.is_dir():
        raise ResultsError(f"experiment root is not a directory: {root}")
    manifest = read_object(root / "manifest.json")
    summary = read_object(root / "summary.json")
    validate_schema(manifest, EXPERIMENT_SCHEMA, f"{root}/manifest.json")
    validate_schema(summary, EXPERIMENT_SCHEMA, f"{root}/summary.json")
    freeze_evidence = validate_source_freeze(manifest)

    arm = require_string(manifest, "arm", "manifest")
    if arm not in ARMS:
        raise ResultsError(f"manifest.arm is unknown: {arm!r}")
    discovery_source = manifest.get("discovery_source")
    corrected_retest = freeze_evidence.get("experiment_proposal") == "0004"
    if arm == "native":
        if discovery_source is not None:
            raise ResultsError("manifest.discovery_source must be null for native")
    elif discovery_source not in ("aster-protected", "provider-mdns"):
        raise ResultsError(
            "manifest.discovery_source must select a provider discovery profile"
        )
    scenario = scenario_of(manifest)
    trials = require_int(manifest, "trials", "manifest")
    if trials < 1 or trials > 30:
        raise ResultsError("manifest.trials must be in 1..30")
    if manifest.get("execute") is not True:
        raise ResultsError("manifest.execute must be true for aggregatable evidence")
    payload_bytes = require_int(manifest, "payload_bytes", "manifest")
    if payload_bytes < 64 or payload_bytes > 1_048_576:
        raise ResultsError("manifest.payload_bytes must be in 64..1048576")
    if scenario == "gate-h" and trials != 10:
        raise ResultsError("Gate-H evidence must contain exactly ten trials")
    if scenario == "gate-h" and payload_bytes != 1_048_576:
        raise ResultsError("Gate-H evidence must use the exact 1048576-byte payload")
    if scenario == "gate-h" and arm != "native":
        raise ResultsError("Gate-H launch evidence must use the native arm")
    gate_h_duration_ms: int | None = None
    gate_h_run_id: str | None = None
    if scenario == "gate-h":
        gate_h_duration_ms = require_int(manifest, "duration_ms", "manifest")
        if gate_h_duration_ms < 6_000 or gate_h_duration_ms > 60_000:
            raise ResultsError("Gate-H duration_ms must be in 6000..60000")
        gate_h_run_id = require_string(manifest, "run_id", "manifest")
        if not re.fullmatch(r"[0-9a-f]{8}", gate_h_run_id):
            raise ResultsError("Gate-H manifest.run_id is not eight lowercase hex digits")
    if corrected_retest and (
        freeze_evidence["proposal_0004_baseline"] != PROPOSAL_0004_BASELINE
        or freeze_evidence["signature_status"] != "G"
        or not isinstance(freeze_evidence["signature_signer"], str)
        or not freeze_evidence["signature_signer"].strip()
        or not isinstance(freeze_evidence["signature_fingerprint"], str)
        or not freeze_evidence["signature_fingerprint"].strip()
    ):
        raise ResultsError("source freeze is not a signed Proposal-0004 checkpoint")
    if scenario == "gate-h" and not corrected_retest:
        raise ResultsError("Gate-H source freeze is not a Proposal-0004 checkpoint")
    if scenario != "gate-h" and manifest.get("gate_h_fault_receipt") is not None:
        raise ResultsError("non-Gate-H manifest unexpectedly retains a fault receipt")
    gate_h_host_execution = (
        validate_gate_h_host_execution(root, manifest)
        if scenario == "gate-h"
        else None
    )
    if scenario == "gate-h":
        assert gate_h_host_execution is not None
        if (
            freeze_evidence.get("git_binary")
            != gate_h_host_execution["tools"]["git"]["invocation_path"]
            or freeze_evidence.get("host_environment_sha256")
            != gate_h_host_execution["environment_sha256"]
        ):
            raise ResultsError(
                "Gate-H source freeze is not bound to the exact Git environment"
            )
        gate_h_signature_evidence = validate_gate_h_signature_evidence(
            root,
            manifest,
            candidate_commit=freeze_evidence["candidate_commit"],
            source_freeze=freeze_evidence,
        )
        gate_h_signed_source = validate_gate_h_signed_source_evidence(
            root,
            manifest,
            source_freeze=freeze_evidence,
        )
        gate_h_export_execution = validate_gate_h_export_execution(
            root,
            manifest,
            signed_source=gate_h_signed_source,
        )
    elif manifest.get("host_execution") is not None:
        raise ResultsError("non-Gate-H manifest unexpectedly retains host execution")
    else:
        gate_h_signature_evidence = None
        gate_h_signed_source = None
        gate_h_export_execution = None
        if any(
            manifest.get(field) is not None
            for field in (
                "signature_request",
                "signature_trust",
                "signature_anchor",
                "signature_verification",
                "signed_source",
                "signed_source_sha256",
                "export_execution",
            )
        ):
            raise ResultsError(
                "non-Gate-H manifest unexpectedly retains signature trust"
            )
    gate_h_resource_cleanup = (
        validate_gate_h_resource_cleanup(
            root,
            manifest,
            run_id=gate_h_run_id,
            docker_binary=gate_h_host_execution["tools"]["docker"][
                "invocation_path"
            ],
        )
        if scenario == "gate-h"
        and gate_h_run_id is not None
        and gate_h_host_execution is not None
        else None
    )

    binary_sha256 = require_string(manifest, "binary_sha256", "manifest")
    if not HEX_64.fullmatch(binary_sha256):
        raise ResultsError("manifest.binary_sha256 must be 64 lowercase hexadecimal digits")
    frozen_binary = root / "candidate-aster-lab"
    if not frozen_binary.is_file() or sha256_file(frozen_binary) != binary_sha256:
        raise ResultsError("manifest.binary_sha256 differs from the frozen candidate")
    gate_h_fault_evidence = (
        validate_gate_h_fault_evidence(
            root,
            manifest,
            candidate_commit=freeze_evidence["candidate_commit"],
            binary_sha256=binary_sha256,
            binary_size=frozen_binary.stat().st_size,
            source_freeze=freeze_evidence,
            host_execution=gate_h_host_execution,
        )
        if scenario == "gate-h"
        else None
    )
    gate_h_binary_provenance = (
        validate_gate_h_binary_provenance(
            root,
            manifest,
            candidate_commit=freeze_evidence["candidate_commit"],
            binary_sha256=binary_sha256,
            host_execution=gate_h_host_execution,
            signed_source=gate_h_signed_source,
        )
        if scenario == "gate-h"
        else None
    )
    if scenario != "gate-h" and manifest.get("gate_h_binary_provenance") is not None:
        raise ResultsError("non-Gate-H manifest unexpectedly retains binary provenance")
    provider_binary_sha256: str | None = None
    if arm == "libp2p" and corrected_retest:
        provider_binary_sha256 = require_string(
            manifest, "provider_binary_sha256", "manifest"
        )
        if not HEX_64.fullmatch(provider_binary_sha256):
            raise ResultsError("manifest.provider_binary_sha256 is malformed")
        provider_source = require_string(manifest, "provider_source_binary", "manifest")
        if not provider_source.strip():
            raise ResultsError("manifest.provider_source_binary is empty")
        provider_build = require_string(manifest, "provider_build_command", "manifest")
        if not provider_build.strip():
            raise ResultsError("manifest.provider_build_command is empty")
        frozen_provider = root / "candidate-aster-libp2p-node"
        provider_path = require_string(manifest, "provider_binary", "manifest")
        if PurePath(provider_path).name != frozen_provider.name:
            raise ResultsError(
                "manifest.provider_binary does not name the frozen provider"
            )
        if (
            not frozen_provider.is_file()
            or sha256_file(frozen_provider) != provider_binary_sha256
        ):
            raise ResultsError(
                "manifest.provider_binary_sha256 differs from the frozen provider"
            )
    elif any(
        manifest.get(field) is not None
        for field in (
            "provider_source_binary",
            "provider_binary",
            "provider_binary_sha256",
            "provider_build_command",
        )
    ):
        raise ResultsError(
            "non-corrected-provider evidence has unexpected provider binary fields"
        )

    if summary.get("arm") != arm or scenario_of(summary) != scenario:
        raise ResultsError("summary arm/scenario differs from manifest")
    if require_int(summary, "requested_trials", "summary") != trials:
        raise ResultsError("summary requested_trials differs from manifest")

    expected_names = [f"trial-{index:02d}" for index in range(1, trials + 1)]
    actual_names = sorted(
        path.name for path in root.iterdir() if path.name.startswith("trial-")
    )
    if actual_names != expected_names:
        raise ResultsError(
            f"trial directories differ in {root}: expected {expected_names}, got {actual_names}"
        )
    expected_suffixes = [(name, "result.json") for name in expected_names]
    if result_suffixes(summary.get("results"), "summary") != expected_suffixes:
        raise ResultsError("summary.results does not name the exact ordered trial result set")

    gate_h_process_quartets = (
        read_gate_h_process_quartets(
            root,
            trials=trials,
            environment_sha256=gate_h_host_execution["environment_sha256"],
        )
        if scenario == "gate-h"
        else {}
    )
    gate_h_claimed_process_sequences: set[int] = set()
    samples = Samples()
    passed = 0
    node_receipts = 0
    absent_before_contact = 0
    node_schemas: set[str] = set()
    retained_provider_profile: dict[str, Any] | None = None
    gate_h_cleanups: list[dict[str, Any]] = []
    gate_h_process_launches: list[dict[str, Any]] = []
    for index, name in enumerate(expected_names, start=1):
        context = f"{root}/{name}/result.json"
        result = read_object(root / name / "result.json")
        validate_schema(result, EXPERIMENT_SCHEMA, context)
        if result.get("arm") != arm or scenario_of(result) != scenario:
            raise ResultsError(f"{context} arm/scenario differs from manifest")
        if require_int(result, "trial", context) != index:
            raise ResultsError(f"{context} trial number differs from its directory")
        if require_bool(result, "passed", context):
            passed += 1
        if scenario == "gate-h":
            assert gate_h_run_id is not None
            gate_h_cleanups.append(
                validate_gate_h_cleanup(
                    root / name,
                    trial=index,
                    run_id=gate_h_run_id,
                    docker_binary=gate_h_host_execution["tools"]["docker"][
                        "invocation_path"
                    ],
                )
            )
        samples.add("trial_elapsed_ms", require_number(result, "elapsed_ms", context))
        receipts = trial_receipts(result, scenario, context)
        gate_h_item_id = (
            require_string(result, "item_id", context)
            if scenario == "gate-h"
            else None
        )
        receipt_by_role = dict(receipts)
        node_receipts += len(receipts)
        for role, receipt in receipts:
            receipt_context = f"{context}:{role}"
            receipt_schema = require_string(receipt, "schema", receipt_context)
            node_schemas.add(receipt_schema)
            if scenario == "gate-h":
                assert gate_h_item_id is not None
                validate_gate_h_native_receipt(
                    receipt,
                    context=receipt_context,
                    expected_item_id=gate_h_item_id,
                )
            if collect_receipt(
                receipt,
                arm,
                receipt_context,
                samples,
                payload_bytes,
                discovery_source,
                provider_binary_sha256,
            ):
                absent_before_contact += 1
            profile = provider_profile_evidence(receipt, arm)
            if retained_provider_profile is None:
                retained_provider_profile = profile
            elif retained_provider_profile != profile:
                raise ResultsError(
                    f"{receipt_context} provider profile differs within one run"
                )
        if scenario == "idle":
            collect_idle(result, context, samples)
        if scenario == "gate-h":
            identities = require_identity_map(result, ("a", "b", "c"), context)
            assert gate_h_run_id is not None
            assert gate_h_duration_ms is not None
            gate_h_process_launches.append(
                validate_gate_h_process_launches(
                    trial=index,
                    run_id=gate_h_run_id,
                    duration_ms=gate_h_duration_ms,
                    identities=identities,
                    item_id=gate_h_item_id,
                    result=result,
                    quartets=gate_h_process_quartets,
                    claimed_sequences=gate_h_claimed_process_sequences,
                    docker_binary=gate_h_host_execution["tools"]["docker"][
                        "invocation_path"
                    ],
                )
            )
            if result.get("b_pre_emission_mode") != (
                gate_h_experiment_contract.GATE_H_FLASH_ONLY_EMISSION_MODE
            ):
                raise ResultsError(
                    f"{context} does not bind B-pre to exact Flash-only emission"
                )
            for field in ("item_id", "envelope_id"):
                value = require_string(result, field, context)
                if not HEX_64.fullmatch(value):
                    raise ResultsError(f"{context}.{field} is not a 32-byte hex ID")
            expected_receipts = {
                "a": (identities["a"], {identities["b"]}),
                "b_pre": (identities["b"], {identities["a"], identities["c"]}),
                "b_post": (identities["b"], {identities["c"]}),
                "c": (identities["c"], {identities["b"]}),
            }
            for role, (identity, peers) in expected_receipts.items():
                require_exact_peer_receipt(
                    receipt_by_role[role],
                    identity=identity,
                    expected_peers=peers,
                    arm=arm,
                    context=f"{context}:{role}",
                )
            try:
                authorization_control = (
                    gate_h_experiment_contract.prepared_gate_h_authorization_control(
                        result.get("authorization_control"), root / name, identities
                    )
                )
                live_control = gate_h_experiment_contract.validate_gate_h_live_control_evidence(
                    control=authorization_control,
                    identities=identities,
                    receipts=receipt_by_role,
                    b_events=gate_h_experiment_contract.read_event_log(
                        root
                        / name
                        / "b"
                        / f"native-mesh-t{index:02d}_gate_pre-events.jsonl"
                    ),
                    c_events=gate_h_experiment_contract.read_event_log(
                        root
                        / name
                        / "c"
                        / f"native-mesh-t{index:02d}_gate_pre-events.jsonl"
                    ),
                )
            except (
                gate_h_experiment_contract.ExperimentError,
                OSError,
                TypeError,
                UnicodeError,
                ValueError,
            ) as error:
                raise ResultsError(
                    f"{context} Gate-H live control is invalid: {error}"
                ) from error
            if result.get("live_control") != live_control:
                raise ResultsError(
                    f"{context}.live_control differs from its receipts and event logs"
                )
            if require_int(
                result, "b_pre_restart_admitted_contact_high_water", context
            ) < 2:
                raise ResultsError(
                    f"{context} did not retain two admitted B contacts before restart"
                )
            process_durations = result.get("process_durations_ms")
            expected_process_durations = {
                "a_pre": gate_h_duration_ms,
                "b_pre": gate_h_duration_ms,
                "c_continuous": gate_h_duration_ms * 2 + 5_000,
                "b_post": gate_h_duration_ms,
            }
            if process_durations != expected_process_durations:
                raise ResultsError(
                    f"{context}.process_durations_ms does not prove the bounded "
                    "continuous-C schedule"
                )
            baseline_contacts = require_contact_ids(
                result.get("c_pre_restart_admitted_contact_ids_for_b"),
                f"{context}.c_pre_restart_admitted_contact_ids_for_b",
            )
            new_contacts = require_contact_ids(
                result.get("c_post_restart_new_admitted_contact_ids_for_b"),
                f"{context}.c_post_restart_new_admitted_contact_ids_for_b",
            )
            final_contacts = require_contact_ids(
                result.get("c_final_admitted_contact_ids_for_b"),
                f"{context}.c_final_admitted_contact_ids_for_b",
            )
            if (
                not baseline_contacts
                or not new_contacts
                or set(baseline_contacts) - set(final_contacts)
                or set(new_contacts) != set(final_contacts) - set(baseline_contacts)
            ):
                raise ResultsError(
                    f"{context} did not prove C admitted a fresh B contact after restart"
                )
            if require_int(
                result, "c_distinct_admitted_contacts_for_b", context
            ) != len(final_contacts):
                raise ResultsError(
                    f"{context}.c_distinct_admitted_contacts_for_b differs from IDs"
                )
            for field in (
                "c_item_absent_before_b_restart",
                "publisher_offline_during_post_restart_delivery",
                "fresh_process_authentication_after_restart",
                "internal_only_segmented_networks",
            ):
                if require_bool(result, field, context) is not True:
                    raise ResultsError(f"{context}.{field} is not true")
            validate_gate_h_durable_item_observations(
                result.get("durable_item_observations"),
                expected_item_id=gate_h_item_id,
                context=f"{context}.durable_item_observations",
            )
            for field, roles in (
                ("pre_process_returncodes", ("a", "b")),
                ("post_process_returncodes", ("b", "c")),
            ):
                returncodes = result.get(field)
                if not isinstance(returncodes, dict) or set(returncodes) != set(roles):
                    raise ResultsError(f"{context}.{field} has the wrong process roles")
                if any(
                    isinstance(returncode, bool)
                    or not isinstance(returncode, int)
                    or returncode != 0
                    for returncode in returncodes.values()
                ):
                    raise ResultsError(f"{context}.{field} contains a nonzero exit")
            require_custody(result.get("custody"), f"{context}.custody")
            require_delivery(result.get("delivery"), f"{context}.delivery")
            samples.add(
                "gate_h_pre_admitted_ms",
                require_number(result, "pre_restart_all_three_admitted_ms", context),
            )
            samples.add(
                "gate_h_b_custody_observed_ms",
                require_number(result, "b_pre_restart_custody_observed_ms", context),
            )
            samples.add(
                "gate_h_post_admitted_ms",
                require_number(result, "post_restart_bc_admitted_ms", context),
            )
            samples.add(
                "gate_h_c_item_observed_ms",
                require_number(result, "c_post_restart_item_observed_ms", context),
            )
        if scenario == "live-relay":
            identities = require_identity_map(result, ("a", "b", "c"), context)
            for field in ("item_id", "envelope_id"):
                value = require_string(result, field, context)
                if not HEX_64.fullmatch(value):
                    raise ResultsError(f"{context}.{field} is not a 32-byte hex ID")
            require_exact_peer_receipt(
                receipt_by_role["a"],
                identity=identities["a"],
                expected_peers={identities["b"]},
                arm=arm,
                context=f"{context}:a",
            )
            require_exact_peer_receipt(
                receipt_by_role["b"],
                identity=identities["b"],
                expected_peers={identities["a"], identities["c"]},
                arm=arm,
                context=f"{context}:b",
            )
            require_exact_peer_receipt(
                receipt_by_role["c"],
                identity=identities["c"],
                expected_peers={identities["b"]},
                arm=arm,
                context=f"{context}:c",
            )
            if require_bool(
                result, "bc_authenticated_before_a_started", context
            ) is not True:
                raise ResultsError(f"{context} did not establish B/C before A")
            if require_bool(
                result, "all_nodes_running_when_c_observed", context
            ) is not True:
                raise ResultsError(
                    f"{context} did not observe C while all node processes were live"
                )
            if require_int(result, "a_c_contact_count", context) != 0:
                raise ResultsError(f"{context} contains an A/C contact")
            if require_bool(
                result, "internal_only_segmented_networks", context
            ) is not True:
                raise ResultsError(f"{context} did not retain two internal segments")
            if require_int(
                result, "relay_admitted_contact_high_water", context
            ) < 2:
                raise ResultsError(
                    f"{context} did not retain two admitted relay contacts"
                )
            if require_bool(
                result, "b_commit_fanout_observed_before_c_verification", context
            ) is not True:
                raise ResultsError(f"{context} has no retained B commit fan-out proof")
            fanout = result.get("b_commit_fanout")
            if not isinstance(fanout, dict):
                raise ResultsError(f"{context}.b_commit_fanout must be an object")
            require_int(fanout, "contact", f"{context}.b_commit_fanout")
            if require_int(
                fanout, "contacts_planned", f"{context}.b_commit_fanout"
            ) < 1:
                raise ResultsError(
                    f"{context}.b_commit_fanout planned no target contact"
                )
            fanout_count_fields = (
                "contacts_queued",
                "contacts_notified",
            )
            present_fanout_count_fields = [
                field for field in fanout_count_fields if field in fanout
            ]
            if len(present_fanout_count_fields) != 1:
                raise ResultsError(
                    f"{context}.b_commit_fanout must contain exactly one queued/notified count"
                )
            queued_field = present_fanout_count_fields[0]
            if require_int(
                fanout, queued_field, f"{context}.b_commit_fanout"
            ) < 1:
                raise ResultsError(
                    f"{context}.b_commit_fanout did not queue another contact"
                )
            source_peer = require_string(
                fanout, "source_peer", f"{context}.b_commit_fanout"
            )
            if source_peer != identities["a"]:
                raise ResultsError(
                    f"{context}.b_commit_fanout is not bound to publisher A"
                )
            require_custody(result.get("custody"), f"{context}.custody")
            require_delivery(result.get("delivery"), f"{context}.delivery")
            samples.add(
                "live_bc_prerequisite_ms",
                require_number(result, "bc_prerequisite_ms", context),
            )
            samples.add(
                "live_c_item_observed_ms",
                require_number(
                    result, "c_item_observed_ms_from_process_launch", context
                ),
            )
        if scenario == "receive-only":
            identities = require_identity_map(result, ("a", "b"), context)
            item_id = require_string(result, "item_id", context)
            if not HEX_64.fullmatch(item_id):
                raise ResultsError(f"{context}.item_id is not a 32-byte hex ID")
            require_exact_peer_receipt(
                receipt_by_role["a"],
                identity=identities["a"],
                expected_peers={identities["b"]},
                arm=arm,
                context=f"{context}:a",
            )
            require_exact_peer_receipt(
                receipt_by_role["b"],
                identity=identities["b"],
                expected_peers={identities["a"]},
                arm=arm,
                context=f"{context}:b",
            )
            if require_bool(
                result, "all_nodes_running_when_b_observed", context
            ) is not True:
                raise ResultsError(
                    f"{context} did not observe B while both node processes were live"
                )
            if require_bool(
                result, "receive_only_control_bytes_allowed", context
            ) is not True:
                raise ResultsError(
                    f"{context} misstates the receive-only control-byte contract"
                )
            if require_int(result, "discovery_announcements", context) != 0:
                raise ResultsError(f"{context} emitted discovery in receive-only lane")
            require_custody(result.get("custody"), f"{context}.custody")
            samples.add(
                "receive_only_b_item_observed_ms",
                require_number(
                    result, "b_item_observed_ms_from_process_launch", context
                ),
            )

    if require_int(summary, "passed_trials", "summary") != passed:
        raise ResultsError("summary passed_trials differs from trial receipts")
    all_passed = passed == trials
    if require_bool(summary, "all_passed", "summary") != all_passed:
        raise ResultsError("summary all_passed differs from trial receipts")
    if scenario == "gate-h" and (passed != 10 or not all_passed):
        raise ResultsError("Gate-H evidence is not a 10/10 clean cohort")
    if scenario == "gate-h" and node_schemas != {NATIVE_SHARED_NODE_SCHEMA}:
        raise ResultsError("Gate-H evidence must use only native v2 receipts")
    if arm == "libp2p" and corrected_retest and node_schemas != {
        "aster-lab-libp2p-mesh-node/v3"
    }:
        raise ResultsError(
            "corrected libp2p evidence must use only the shared-node v3 receipt"
        )

    if scenario == "gate-h" and gate_h_claimed_process_sequences != set(
        gate_h_process_quartets
    ):
        raise ResultsError("Gate-H process evidence contains unmatched launch quartets")
    index_evidence = verify_evidence_index(root)
    return {
        "root": str(root),
        "arm": arm,
        "scenario": scenario,
        "discovery_source": discovery_source,
        "payload_bytes": payload_bytes,
        "binary_sha256": binary_sha256,
        "provider_binary_sha256": provider_binary_sha256,
        "source_freeze": freeze_evidence,
        "gate_h_host_execution": gate_h_host_execution,
        "gate_h_signature_evidence": gate_h_signature_evidence,
        "gate_h_signed_source": gate_h_signed_source,
        "gate_h_export_execution": gate_h_export_execution,
        "gate_h_resource_cleanup": gate_h_resource_cleanup,
        "gate_h_binary_provenance": gate_h_binary_provenance,
        "gate_h_fault_evidence": gate_h_fault_evidence,
        "gate_h_cleanup_receipts": gate_h_cleanups,
        "gate_h_process_launches": gate_h_process_launches,
        "provider_profile": retained_provider_profile,
        "evidence_index": index_evidence,
        "requested_trials": trials,
        "passed_trials": passed,
        "failed_trials": trials - passed,
        "all_passed": all_passed,
        "sample_scopes": {
            "trial_results": trials,
            "node_receipts": node_receipts,
            "durable_item_absent_before_contact_receipts": absent_before_contact,
        },
        "node_receipt_schemas": sorted(node_schemas),
        "distributions": samples.result(),
    }


def aggregate(roots: Iterable[Path]) -> dict[str, Any]:
    resolved = [root.resolve() for root in roots]
    if not resolved:
        raise ResultsError("at least one experiment root is required")
    if len(set(resolved)) != len(resolved):
        raise ResultsError("experiment roots must be unique")
    runs = [summarize_root(root) for root in resolved]
    requested = sum(run["requested_trials"] for run in runs)
    passed = sum(run["passed_trials"] for run in runs)
    return {
        "schema": RESULTS_SCHEMA,
        "quantile_method": "nearest-rank",
        "run_count": len(runs),
        "requested_trials": requested,
        "passed_trials": passed,
        "failed_trials": requested - passed,
        "all_passed": all(run["all_passed"] for run in runs),
        "runs": runs,
    }


def _raw_gate_h_manifest(root: Path) -> dict[str, Any]:
    try:
        value = json.loads((root.resolve() / "manifest.json").read_text("utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise ResultsError(f"cannot read post-hoc bootstrap manifest: {root}") from error
    if not isinstance(value, dict):
        raise ResultsError("post-hoc bootstrap manifest is not an object")
    return value


def _gate_h_posthoc_roots(roots: Sequence[Path]) -> list[tuple[Path, dict[str, Any]]]:
    values = []
    for root in roots:
        manifest = _raw_gate_h_manifest(root)
        if manifest.get("scenario") == "gate-h":
            values.append((root.resolve(), manifest))
    return values


def ensure_gate_h_results_export(
    args: argparse.Namespace, raw_argv: Sequence[str]
) -> tuple[Path, dict[str, Any]] | None:
    """Replace the mutable post-hoc bootstrap with the signed results program."""

    gate_h_roots = _gate_h_posthoc_roots(args.roots)
    if not gate_h_roots:
        return None
    selected_root, selected_manifest = gate_h_roots[0]
    signed_source = selected_manifest.get("signed_source")
    if not isinstance(signed_source, dict):
        raise ResultsError("Gate-H post-hoc bootstrap has no signed source")
    export = signed_source.get("export")
    workspace = signed_source.get("workspace")
    if (
        not isinstance(export, dict)
        or not isinstance(export.get("path"), str)
        or not Path(export["path"]).is_absolute()
        or not isinstance(workspace, str)
        or not Path(workspace).is_absolute()
    ):
        raise ResultsError("Gate-H post-hoc bootstrap paths are malformed")
    export_root = Path(export["path"]).resolve()
    expected = (export_root / GATE_H_RESULTS_RELATIVE_PATH).resolve()
    current = Path(__file__).resolve()
    if os.environ.get("ASTER_GATE_H_RESULTS_EXPORT") != "1":
        if not expected.is_file() or expected.is_symlink():
            raise ResultsError("Gate-H exported results controller is unavailable")
        files = {
            item.get("path"): item
            for item in signed_source.get("files", [])
            if isinstance(item, dict)
        }
        binding = files.get(GATE_H_RESULTS_RELATIVE_PATH)
        if (
            not isinstance(binding, dict)
            or expected.stat().st_size != binding.get("size_bytes")
            or sha256_file(expected) != binding.get("sha256")
        ):
            raise ResultsError("Gate-H exported results controller differs")
        environment = dict(os.environ)
        environment["ASTER_GATE_H_RESULTS_EXPORT"] = "1"
        environment["ASTER_GATE_H_REPOSITORY_WORKSPACE"] = workspace
        environment["ASTER_GATE_H_SIGNED_CONTROLLER"] = str(expected)
        python = str(Path(sys.executable).resolve())
        os.execve(
            python,
            [
                python,
                *gate_h_experiment_contract.GATE_H_PYTHON_FLAGS,
                str(expected),
                *raw_argv,
            ],
            environment,
        )
        raise AssertionError("post-hoc signed re-exec returned")  # pragma: no cover
    if current != expected:
        raise ResultsError("Gate-H post-hoc sentinel does not name signed code")
    for _root, manifest in gate_h_roots:
        candidate = manifest.get("signed_source", {})
        files = {
            item.get("path"): item
            for item in candidate.get("files", [])
            if isinstance(item, dict)
        }
        selected_files = {
            item.get("path"): item
            for item in signed_source.get("files", [])
            if isinstance(item, dict)
        }
        for relative in (GATE_H_RESULTS_RELATIVE_PATH, *GATE_H_RESULTS_MODULES.values()):
            if files.get(relative) != selected_files.get(relative):
                raise ResultsError(
                    "Gate-H cohorts require one exact post-hoc code identity"
                )
    return selected_root, selected_manifest


def gate_h_results_execution_snapshot(
    root: Path, manifest: dict[str, Any], raw_argv: Sequence[str]
) -> dict[str, Any]:
    signed_source = manifest["signed_source"]
    export_root = Path(signed_source["export"]["path"]).resolve()
    signed_files = {
        item["path"]: item
        for item in signed_source["files"]
        if isinstance(item, dict) and isinstance(item.get("path"), str)
    }

    def loaded_binding(name: str, relative_path: str, raw_file: str) -> dict[str, Any]:
        path = Path(raw_file)
        resolved = path.resolve(strict=True)
        source = signed_files.get(relative_path)
        expected = (export_root / relative_path).resolve(strict=True)
        file_stat = path.lstat()
        if not isinstance(source, dict):
            raise ResultsError(f"Gate-H signed post-hoc source is absent: {name}")
        expected_mode = 0o555 if source.get("mode") == "100755" else 0o444
        if (
            resolved != expected
            or path.is_symlink()
            or not stat.S_ISREG(file_stat.st_mode)
            or stat.S_IMODE(file_stat.st_mode) != expected_mode
            or file_stat.st_size != source.get("size_bytes")
            or sha256_file(resolved) != source.get("sha256")
        ):
            raise ResultsError(f"Gate-H loaded post-hoc module differs: {name}")
        return {
            "name": name,
            "relative_path": relative_path,
            "raw_file": raw_file,
            "path": str(resolved),
            "mode": stat.S_IMODE(file_stat.st_mode),
            "size_bytes": file_stat.st_size,
            "sha256": source["sha256"],
            "git_mode": source["mode"],
            "git_blob": source["git_blob"],
        }

    bytecode = sorted(
        path.relative_to(export_root).as_posix()
        for path in export_root.rglob("*")
        if path.name == "__pycache__"
        or (path.is_file() and path.suffix in (".pyc", ".pyo"))
    )
    if bytecode or sys.dont_write_bytecode is not True:
        raise ResultsError("Gate-H post-hoc execution admits Python bytecode")
    runner = loaded_binding(
        "ip_mesh_results", GATE_H_RESULTS_RELATIVE_PATH, __file__
    )
    modules = []
    for name, relative_path in GATE_H_RESULTS_MODULES.items():
        module = sys.modules.get(name)
        raw_file = getattr(module, "__file__", None)
        if not isinstance(raw_file, str):
            raise ResultsError(f"Gate-H post-hoc module is not loaded: {name}")
        cached = getattr(module, "__cached__", None)
        if isinstance(cached, str) and Path(cached).exists():
            raise ResultsError(f"Gate-H post-hoc module used bytecode: {name}")
        modules.append(loaded_binding(name, relative_path, raw_file))
    host_python = manifest["host_execution"]["tools"]["python"]
    python = Path(sys.executable).resolve()
    if (
        python != Path(host_python["path"])
        or python.stat().st_size != host_python["size_bytes"]
        or sha256_file(python) != host_python["sha256"]
    ):
        raise ResultsError("Gate-H post-hoc Python differs from the live toolchain")
    sys_path = [str(item) for item in sys.path]
    if not sys_path or sys_path[0] != str((export_root / "lab").resolve()):
        raise ResultsError("Gate-H post-hoc import root differs")
    repository = Path(signed_source["workspace"])
    if any(
        item
        and not _path_is_equal_to_or_beneath(Path(item), export_root)
        and _path_is_equal_to_or_beneath(Path(item), repository)
        for item in sys_path
    ):
        raise ResultsError("Gate-H post-hoc import path admits mutable worktree code")
    return {
        "schema": GATE_H_EXPORT_EXECUTION_SCHEMA,
        "python": {
            "path": str(python),
            "size_bytes": python.stat().st_size,
            "sha256": sha256_file(python),
        },
        "argv": [
            str(python),
            *gate_h_experiment_contract.GATE_H_PYTHON_FLAGS,
            runner["path"],
            *raw_argv,
        ],
        "repo_workspace": signed_source["workspace"],
        "code_root": str(export_root),
        "runner": runner,
        "modules": modules,
        "sys_path": sys_path,
        "bytecode": {"dont_write_bytecode": True, "paths": bytecode},
        "passed": True,
    }


def parser() -> argparse.ArgumentParser:
    value = argparse.ArgumentParser(description=__doc__)
    value.add_argument("roots", type=Path, nargs="+")
    value.add_argument("--compact", action="store_true", help="emit one-line JSON")
    return value


def main(argv: Sequence[str] | None = None) -> int:
    raw_argv = list(sys.argv[1:] if argv is None else argv)
    args = parser().parse_args(raw_argv)
    try:
        selected = ensure_gate_h_results_export(args, raw_argv)
        posthoc_before = (
            None
            if selected is None
            else gate_h_results_execution_snapshot(
                selected[0], selected[1], raw_argv
            )
        )
        result = aggregate(args.roots)
        if selected is not None:
            posthoc_after = gate_h_results_execution_snapshot(
                selected[0], selected[1], raw_argv
            )
            if posthoc_after != posthoc_before:
                raise ResultsError("Gate-H post-hoc code changed while validating")
            result["posthoc_execution"] = {
                "schema": GATE_H_EXPORT_EXECUTION_SCHEMA,
                "before": posthoc_before,
                "after": posthoc_after,
                "passed": True,
            }
    except (OSError, ResultsError) as error:
        print(f"ip-mesh results: {error}", file=sys.stderr)
        return 2
    json.dump(result, sys.stdout, indent=None if args.compact else 2, sort_keys=True)
    sys.stdout.write("\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
