# Copyright 2026 Defense Unicorns, Inc.
# SPDX-License-Identifier: Apache-2.0
"""Monotonic G1-G5 candidate binding-chain construction."""

from __future__ import annotations

import hashlib
from typing import Any

from .io import canonical_json_bytes


def _digest(label: str, value: Any) -> str:
    raw = canonical_json_bytes({"binding": label, "value": value})
    return f"sha256:{hashlib.sha256(raw).hexdigest()}"


def _gates(body: dict[str, Any]) -> dict[str, dict[str, Any]]:
    return {gate["gate"]: gate for gate in body["gates"]}


def expected_binding_chain(body: dict[str, Any]) -> dict[str, str]:
    gates = _gates(body)
    schema = body["schema"]
    candidate = body["candidate"]
    configuration = body["configuration"]
    root = _digest(
        "root",
        {
            "candidate_id": candidate["id"],
            "candidate_revision": candidate["revision"],
            "schema_version": schema["version"],
            "schema_digest": schema["digest"],
            "profile_id": "aster-linux-event-mvp-evaluation-v0.1",
            "profile_version": "0.1",
            "profile_digest": body["prerequisites"]["profile_digest"],
            "g1_contracts": {
                "emission_modes": configuration["emission_modes"],
                "operation_profile_warning": configuration["operation_profile_warning"],
                "operation_profile_stop": configuration["operation_profile_stop"],
            },
        },
    )
    g2 = _digest(
        "G2",
        {
            "predecessor": root,
            "g1_exit_digest": gates["G1"]["exit_digest"],
            "source": body["source"],
        },
    )
    g3 = _digest(
        "G3",
        {
            "predecessor": g2,
            "g2_exit_digest": gates["G2"]["exit_digest"],
            "global_g3": body["bindings"]["global_g3"],
            "outputs": body["artifact"]["outputs"],
            "complete_artifact_set": body["bindings"]["complete_artifact_set"],
            "provider": body["provider"],
        },
    )
    g4 = _digest(
        "G4",
        {
            "predecessor": g3,
            "g3_exit_digest": gates["G3"]["exit_digest"],
            "inventory_digest": body["inventory"]["digest"],
            "inventory_binding": body["inventory"]["binding_record_digest"],
            "device_peer": body["bindings"]["device_peer"],
            "network_conditions": body["bindings"]["network_conditions"],
            "relay": body["relay"],
            "scenario_set": body["bindings"]["scenario_set"],
            "focused_test_procedures": configuration["focused_test_procedure_digests"],
        },
    )
    workload_identities = [
        _digest("workload", workload) for workload in body["workloads"]
    ]
    g5 = _digest(
        "G5",
        {
            "predecessor": g4,
            "g4_exit_digest": gates["G4"]["exit_digest"],
            "workload_identities": workload_identities,
        },
    )
    return {"root": root, "g2": g2, "g3": g3, "g4": g4, "g5": g5}


def populate_binding_chain(body: dict[str, Any]) -> None:
    expected = expected_binding_chain(body)
    body["bindings"].update(expected)
    gates = _gates(body)
    gates["G1"]["binding"] = expected["root"]
    for number in range(2, 6):
        gates[f"G{number}"]["binding"] = expected[f"g{number}"]
