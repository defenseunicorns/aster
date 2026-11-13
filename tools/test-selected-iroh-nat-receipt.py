#!/usr/bin/env python3
# Copyright 2026 Defense Unicorns, Inc.
# SPDX-License-Identifier: Apache-2.0
"""Adversarial tests for the sanitized selected-Iroh NAT receipt schema."""

from __future__ import annotations

import copy
import contextlib
import base64
import hashlib
import importlib.util
import json
import io
import os
from pathlib import Path
import shlex
import tempfile
from typing import Callable
import unittest
from unittest import mock


CHECKER_PATH = Path(__file__).with_name("check-selected-iroh-nat-receipt.py")
SPEC = importlib.util.spec_from_file_location("selected_iroh_nat_receipt", CHECKER_PATH)
if SPEC is None or SPEC.loader is None:
    raise RuntimeError(f"cannot load {CHECKER_PATH}")
CHECKER = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(CHECKER)


def digest(label: str) -> str:
    return hashlib.sha256(label.encode("ascii")).hexdigest()


def git_tree_fixture(
    object_ids: dict[str, str],
) -> tuple[str, dict[str, bytes], dict[str, str]]:
    """Build canonical raw Git tree objects for mocked immutable-source tests."""
    root: dict[str, object] = {}
    for relative, object_id in object_ids.items():
        parts = relative.split("/")
        node = root
        for part in parts[:-1]:
            child = node.setdefault(part, {})
            if not isinstance(child, dict):
                raise AssertionError("Git fixture path collides with a blob")
            node = child
        if parts[-1] in node:
            raise AssertionError("Git fixture repeats a path")
        node[parts[-1]] = ("100644", object_id)
    objects: dict[str, bytes] = {}
    path_ids: dict[str, str] = {}

    def build(node: dict[str, object], prefix: str) -> str:
        entries: list[tuple[bytes, bytes, str]] = []
        for name, value in node.items():
            name_bytes = name.encode("utf-8")
            if isinstance(value, dict):
                child_path = f"{prefix}/{name}" if prefix else name
                child_id = build(value, child_path)
                entries.append((name_bytes + b"/", b"40000", child_id))
            else:
                mode, child_id = value
                entries.append((name_bytes + b"\0", mode.encode("ascii"), child_id))
        content = b"".join(
            mode + b" " + sort_key[:-1] + b"\0" + bytes.fromhex(child_id)
            for sort_key, mode, child_id in sorted(entries, key=lambda item: item[0])
        )
        object_id = hashlib.sha1(
            f"tree {len(content)}\0".encode("ascii") + content
        ).hexdigest()
        objects[object_id] = content
        path_ids[prefix] = object_id
        return object_id

    root_id = build(root, "")
    return root_id, objects, path_ids


def fixture_canary(profile: str) -> bytes:
    """Return one deterministic 32-byte test-only stand-in for the fresh canary."""
    return hashlib.sha256(f"fixture-canary:{profile}".encode("ascii")).digest()


def artifact_content(scope: str, role: str, size: int) -> bytes:
    seed = hashlib.sha256(f"artifact:{scope}:{role}".encode("ascii")).digest()
    return (seed * ((size + len(seed) - 1) // len(seed)))[:size]


TEST_CERTIFICATE_DER = {
    # Produced by the exact rcgen 0.14.9 `relay-material` implementation.  Only
    # these public certificates are retained; its temporary PKCS#8 key was
    # destroyed with `relay-material-destroy` immediately after capture.
    "ca": base64.b64decode(
        "MIIBnzCCAUWgAwIBAgIUZ4/FHmqzTge8lp/22XmNNS6QzF0wCgYIKoZIzj0EAwIwKzEpMCcGA1UEAwwgQXN0ZXIgc2VsZWN0ZWQgTkFUIGxhYm9yYXRvcnkgQ0EwIBcNNzUwMTAxMDAwMDAwWhgPNDA5NjAxMDEwMDAwMDBaMCsxKTAnBgNVBAMMIEFzdGVyIHNlbGVjdGVkIE5BVCBsYWJvcmF0b3J5IENBMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEf4NBelvaDhd3EndYdQhlEc1351/+AXjcJPYncQZT3gBmLR+Jab3ME8ICcAuzUZfaWrNFao8hVwz2pv9hLM0V56NFMEMwDgYDVR0PAQH/BAQDAgGGMB0GA1UdDgQWBBQPX1FtX6YiKaU1l43MlynlY3l2MDASBgNVHRMBAf8ECDAGAQH/AgEAMAoGCCqGSM49BAMCA0gAMEUCIEH1v6f+xZep6L83J1i6AYHPmLIK78mlkU1lfcZRvNnFAiEAlndtksjR9TyjilRmGJV7JrmyPu1MP6Qa8Pl6b10oWrA="
    ),
    "server": base64.b64decode(
        "MIIBtjCCAVugAwIBAgIUBnhIDBYY9k32JHqz8V9n+GZvDs4wCgYIKoZIzj0EAwIwKzEpMCcGA1UEAwwgQXN0ZXIgc2VsZWN0ZWQgTkFUIGxhYm9yYXRvcnkgQ0EwIBcNNzUwMTAxMDAwMDAwWhgPNDA5NjAxMDEwMDAwMDBaMBsxGTAXBgNVBAMMEHJlbGF5LmFzdGVyLnRlc3QwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAASOy+t25fFeBa4o7uPzXVL4woKGIPCVolr4nVNIrRwqkXvgzs+M95JW6Vmfqa258S00MfkvzHakHLeRWSW7r4Tbo2swaTAfBgNVHSMEGDAWgBQPX1FtX6YiKaU1l43MlynlY3l2MDAhBgNVHREEGjAYghByZWxheS5hc3Rlci50ZXN0hwQK+gAUMA4GA1UdDwEB/wQEAwIHgDATBgNVHSUEDDAKBggrBgEFBQcDATAKBggqhkjOPQQDAgNJADBGAiEA1zXaAaNP7HA70iDfUbzvqDu6uE+8P1QkOO4cS+gJirkCIQDoRrLyQf/SLxoUe3vsFFYZDpcCf9kvG/NtTKtJZNk2MA=="
    ),
}


def test_certificate_der(role: str) -> bytes:
    return TEST_CERTIFICATE_DER[role]


def build_artifacts() -> list[dict[str, object]]:
    return [
        {
            "role": role,
            "name": {
                "aster-cli": "aster",
                "event-helper": "aster-selected-nat",
                "relay-helper": "aster-selected-relay",
            }[role],
            "bytes": 1_000_000 + index,
            "sha256": digest(f"build-{role}"),
        }
        for index, role in enumerate(CHECKER.BUILD_ROLES)
    ]


def endpoints(cell: str) -> list[dict[str, object]]:
    return [
        {
            "role": role,
            "carrier_id": digest(f"{cell}-{role}-carrier"),
            "mission_id": digest(f"{cell}-{role}-mission"),
            "fresh": True,
        }
        for role in CHECKER.ENDPOINT_ROLES
    ]


def nft(cell: str) -> dict[str, object]:
    names = (
        CHECKER.CONE_NFT_NAMES
        if cell == "cone-direct"
        else CHECKER.RESTRICTIVE_NFT_NAMES
    )
    counters = []
    for router in ("nat-a", "nat-b"):
        if cell == "cone-direct":
            outbound = 2 if router == "nat-a" else 4
            inbound = 4 if router == "nat-a" else 2
            packet_counts = {
                "aster_cone_dnat": 0 if router == "nat-a" else 1,
                "aster_cone_snat": 1 if router == "nat-a" else 0,
                "aster_cone_forward_in": inbound,
                "aster_cone_forward_out": outbound,
            }
        else:
            packet_counts = {
                "aster_restrict_direct_drop": 1 if router == "nat-a" else 0,
                "aster_restrict_relay_https": 3,
                "aster_restrict_relay_http": 0,
                "aster_restrict_established": 6,
            }
        for name in names:
            delta_packets = packet_counts[name]
            delta_bytes = delta_packets * 128
            counters.append(
                {
                    "router": router,
                    "name": name,
                    "before_packets": 0,
                    "after_packets": delta_packets,
                    "delta_packets": delta_packets,
                    "before_bytes": 0,
                    "after_bytes": delta_bytes,
                    "delta_bytes": delta_bytes,
                }
            )
    return {"namespace": "nat-a,nat-b", "counters": counters}


def set_nft_counter_packets(
    receipt_cell: dict[str, object], router: str, name: str, packets: int
) -> None:
    counter = next(
        value
        for value in receipt_cell["nft"]["counters"]
        if value["router"] == router and value["name"] == name
    )
    byte_count = packets * 128
    counter.update(
        {
            "after_packets": packets,
            "delta_packets": packets,
            "after_bytes": byte_count,
            "delta_bytes": byte_count,
        }
    )


def pcap_tuple_records(cell: str, role: str, packets: int) -> list[dict[str, object]]:
    if cell == "cone-direct":
        own = "10.250.0.11" if role == "nat-a" else "10.250.0.12"
        peer = "10.250.0.12" if role == "nat-a" else "10.250.0.11"
        values = (
            (min(own, peer), max(own, peer), 44000, 44000, "udp", packets // 3),
            (max(own, peer), min(own, peer), 44000, 44000, "udp", packets - packets // 3),
        )
    else:
        own = "10.250.0.11" if role == "nat-a" else "10.250.0.12"
        source_port = 49152 if role == "nat-a" else 49153
        values = (
            (own, "10.250.0.20", source_port, 8443, "tcp", packets // 3),
            ("10.250.0.20", own, 8443, source_port, "tcp", packets - packets // 3),
        )
    return [
        {
            "source": source,
            "destination": destination,
            "source_port": source_port,
            "destination_port": destination_port,
            "protocol": protocol,
            "packets": count,
        }
        for source, destination, source_port, destination_port, protocol, count in values
    ]


def pcap_capture_bytes(cell: str, role: str, packets: int) -> bytes:
    records = pcap_tuple_records(cell, role, packets)
    global_header = (
        bytes.fromhex("d4c3b2a1")
        + (2).to_bytes(2, "little")
        + (4).to_bytes(2, "little")
        + (0).to_bytes(4, "little", signed=True)
        + (0).to_bytes(4, "little")
        + (262_144).to_bytes(4, "little")
        + (1).to_bytes(4, "little")
    )
    output = bytearray(global_header)
    packet_index = 0
    for record in records:
        source = bytes(int(part) for part in str(record["source"]).split("."))
        destination = bytes(
            int(part) for part in str(record["destination"]).split(".")
        )
        protocol = str(record["protocol"])
        if protocol == "udp":
            transport = (
                int(record["source_port"]).to_bytes(2, "big")
                + int(record["destination_port"]).to_bytes(2, "big")
                + (8).to_bytes(2, "big")
                + b"\x00\x00"
            )
            protocol_number = 17
        else:
            transport = (
                int(record["source_port"]).to_bytes(2, "big")
                + int(record["destination_port"]).to_bytes(2, "big")
                + b"\x00" * 8
                + b"\x50\x10"
                + b"\x10\x00"
                + b"\x00" * 4
            )
            protocol_number = 6
        ipv4 = (
            b"\x45\x00"
            + (20 + len(transport)).to_bytes(2, "big")
            + packet_index.to_bytes(2, "big")
            + b"\x00\x00\x40"
            + bytes([protocol_number])
            + b"\x00\x00"
            + source
            + destination
        )
        frame = b"\x02" * 6 + b"\x04" * 6 + b"\x08\x00" + ipv4 + transport
        for _ in range(int(record["packets"])):
            output.extend(packet_index.to_bytes(4, "little"))
            output.extend((0).to_bytes(4, "little"))
            output.extend(len(frame).to_bytes(4, "little"))
            output.extend(len(frame).to_bytes(4, "little"))
            output.extend(frame)
            packet_index += 1
    return bytes(output)


def pcap(cell: str) -> dict[str, object]:
    captures = []
    for role in CHECKER.PCAP_ROLES:
        manifest_role = f"{role}-pcap"
        packet_count = 6 if cell == "cone-direct" else 9
        content = pcap_capture_bytes(
            cell, role.removesuffix("-wan"), packet_count
        )
        captures.append(
            {
                "role": role,
                "bytes": len(content),
                "packets": packet_count,
                "dropped_packets": 0,
                "sha256": hashlib.sha256(content).hexdigest(),
                "manifest_role": manifest_role,
            }
        )
    summary_role = "pcap-tuple-summary"
    summary_size = 100 + len(summary_role)
    return {
        "captures": captures,
        "tuple_summary_sha256": hashlib.sha256(
            artifact_content(cell, summary_role, summary_size)
        ).hexdigest(),
        "tuple_proof": {
            "direct_cross_nat_packets": 12 if cell == "cone-direct" else 0,
            "direct_probe_packets": 12 if cell == "cone-direct" else 0,
            "controlled_relay_https_packets": 0 if cell == "cone-direct" else 18,
            "controlled_relay_http_packets": 0,
            "unexpected_public_relay_packets": 0,
            "unexpected_hosted_discovery_packets": 0,
        },
    }


def relay(
    cell: str, cell_endpoints: list[dict[str, object]]
) -> dict[str, object]:
    if cell == "cone-direct":
        return {
            "mode": "disabled",
            "origin": "none",
            "tls_mode": "not-applicable",
            "server_trust_claim": "not-applicable",
            "client_trust_mode": "not-applicable",
            "root_fingerprint_sha256": "not-applicable",
            "allowlist_mode": "not-applicable",
            "allowlist_count": 0,
            "allowlist_sha256": "not-applicable",
            "key_cache_capacity": 0,
            "client_rx_bytes_per_second": 0,
            "client_rx_max_burst_bytes": 0,
            "max_admitted_connections": 0,
            "pre_auth_connection_cap": "not-applicable",
            "observed_active_sessions_peak": 0,
            "accepted_sessions": 0,
            "rejected_sessions": 0,
            "secrets_logged": False,
        }
    return {
        "mode": "controlled",
        "origin": "https://relay.aster.test:8443",
        "tls_mode": "manual-der-certificate",
        "server_trust_claim": "none",
        "client_trust_mode": "explicit-der-root-pin",
        "root_fingerprint_sha256": digest("relay-root"),
        "allowlist_mode": "exact-cli-identities",
        "allowlist_count": 2,
        "allowlist_sha256": hashlib.sha256(
            (
                "\n".join(
                    sorted(str(endpoint["carrier_id"]) for endpoint in cell_endpoints)
                )
                + "\n"
            ).encode("ascii")
        ).hexdigest(),
        "key_cache_capacity": 256,
        "client_rx_bytes_per_second": 1_048_576,
        "client_rx_max_burst_bytes": 1_048_576,
        "max_admitted_connections": 8,
        "pre_auth_connection_cap": "not-enforced",
        "observed_active_sessions_peak": 2,
        "accepted_sessions": 2,
        "rejected_sessions": 0,
        "secrets_logged": False,
    }


def cell(name: str) -> dict[str, object]:
    selected = "Direct" if name == "cone-direct" else "Relay"
    relay_origin = (
        "none" if name == "cone-direct" else "https://relay.aster.test:8443"
    )
    cell_endpoints = endpoints(name)
    canary_sha256 = hashlib.sha256(fixture_canary(name)).hexdigest()
    return {
        "name": name,
        "status": "pass",
        "nat_profile": "cone" if name == "cone-direct" else "restrictive",
        "topology": {
            "sender_bind": "10.250.1.10:44000",
            "receiver_bind": "10.250.2.10:44000",
            "nat_a_external": "10.250.0.11:44000",
            "nat_b_external": "10.250.0.12:44000",
            "sender_default_gateway": "10.250.1.1",
            "receiver_default_gateway": "10.250.2.1",
            "relay_origin": relay_origin,
        },
        "infrastructure": {
            "controlled_relay": name == "restrictive-relay",
            "hosted_discovery": False,
            "public_relay": False,
            "default_relay": False,
            "public_relay_fallback": False,
            "port_mapper": False,
        },
        "endpoints": cell_endpoints,
        "event": {
            "event_id": digest(f"{name}-event"),
            "publisher": cell_endpoints[0]["mission_id"],
            "payload_sha256": canary_sha256,
            "sealed_sha256": "not-exposed-by-production-api",
            "canary_sha256": canary_sha256,
            "payload_bytes": 32,
            "source_sequence": 1,
            "source_inserted": True,
            "destination_deliveries": 1,
            "destination_attempt": 1,
            "acknowledged": True,
            "empty_after_ack": True,
            "replay_ack": "noop",
            "replay_subscription": "noop",
            "exact_query": True,
            "exact_event_id_match": True,
        },
        "reconciliation": {
            "status": "pass",
            "contacts": 4,
            "offered": 0,
            "fetched": 0,
            "inserted": 0,
            "duplicates": 0,
            "remaining": 0,
            "deferred_event_lanes": 0,
            "control_offered": 0,
            "control_fetched": 0,
            "control_retained": 0,
            "control_duplicates": 0,
            "control_activated": 0,
            "control_remaining": 0,
            "mutable_remaining": 0,
            "deferred_mutable_lanes": 0,
            "blob_ranges_fetched": 0,
            "blob_bytes_fetched": 0,
            "blob_remaining": 0,
            "blob_deferred": 0,
        },
        "path": {
            "witnesses": [
                {
                    "role": role,
                    "selected": selected,
                    "transition_count": 1 if name == "cone-direct" else 0,
                    "transitions_saturated": False,
                }
                for role in CHECKER.ENDPOINT_ROLES
            ]
        },
        "nft": nft(name),
        "pcap": pcap(name),
        "relay": relay(name, cell_endpoints),
        "canary_scan": {
            "classes": list(CHECKER.CANARY_CLASSES),
            "scan_targets": ["finalized-public-artifacts", "wan-pcaps"],
            "positive_control": {
                "status": "pass",
                "expected_matches": 3,
                "observed_matches": 3,
                "class_match_counts": {
                    representation: 1
                    for representation in CHECKER.CANARY_CLASSES
                },
            },
            "chronology": list(CHECKER.CANARY_CHRONOLOGY),
            "artifacts_scanned": 11 if name == "cone-direct" else 15,
            "class_match_counts": {
                representation: 0 for representation in CHECKER.CANARY_CLASSES
            },
            "match_count": 0,
        },
        "cleanup": {
            "status": "pass",
            "canary_control_file_disposition": "destroyed-and-unlinked",
            "canary_control_file_previous_bytes": 32,
            "relay_private_key_file_disposition": (
                "not-created"
                if name == "cone-direct"
                else "destroyed-and-unlinked"
            ),
            "canary_control_file_absent_after_cleanup": True,
            "relay_private_key_file_absent_after_cleanup": True,
            "assurance": "bounded-software",
            "physical_sanitization": "not-claimed",
            "containers_remaining": 0,
            "networks_remaining": 0,
            "namespaces_remaining": 0,
        },
    }


def manifest_entry(
    scope: str,
    role: str,
    path: str,
    cells: dict[str, dict[str, object]],
) -> dict[str, object]:
    sensitivity = "public-metadata"
    retention = "retained-sanitized"
    size = 100 + len(role)
    if role.endswith("-log") or role in {"events", "prepare-log"}:
        sensitivity = "sanitized-log"
    if role.endswith("-pcap"):
        sensitivity = "restricted-pcap"
        retention = "external-restricted"
        capture = next(
            capture
            for capture in cells[scope]["pcap"]["captures"]
            if capture["manifest_role"] == role
        )
        size = int(capture["bytes"])
        content = pcap_capture_bytes(
            scope, str(capture["role"]).removesuffix("-wan"), int(capture["packets"])
        )
    elif role in {"relay-ca-der", "relay-cert-der"}:
        sensitivity = "public-certificate"
        retention = "retained-public"
        content = test_certificate_der(
            "ca" if role == "relay-ca-der" else "server"
        )
        size = len(content)
    else:
        content = artifact_content(scope, role, size)
    entry_digest = hashlib.sha256(content).hexdigest()
    return {
        "cell": scope,
        "role": role,
        "path": path,
        "type": "regular",
        "nlink": 1,
        "bytes": size,
        "sha256": entry_digest,
        "mode": "0600",
        "owner": "current-runner",
        "sensitivity": sensitivity,
        "retention": retention,
    }


def raw_manifest(cells: list[dict[str, object]]) -> dict[str, object]:
    by_name = {str(value["name"]): value for value in cells}
    expected_paths = CHECKER.manifest_expected_paths()
    entries = [
        manifest_entry(scope, role, path, by_name)
        for scope, roles in expected_paths.items()
        for role, path in roles.items()
    ]
    entries.sort(key=lambda entry: str(entry["path"]))
    manifest = b"".join(
        f"{entry['sha256']}  {entry['path']}\n".encode("ascii") for entry in entries
    )
    return {
        "format": "sha256-two-space-relative-v1",
        "root_type": "directory",
        "root_mode": "0700",
        "root_owner": "current-runner",
        "entries": entries,
        "records": len(entries),
        "manifest_bytes": len(manifest),
        "artifact_bytes": sum(int(entry["bytes"]) for entry in entries),
        "sha256": hashlib.sha256(manifest).hexdigest(),
        "secret_artifacts": (
            "excluded-from-curated-manifest-retained-external-restricted"
        ),
        "pcap_contents": "external-restricted-not-embedded",
    }


def raw_json(value: object) -> bytes:
    return (json.dumps(value, indent=2, sort_keys=True) + "\n").encode("utf-8")


def raw_nft_evidence(
    receipt_cell: dict[str, object], router: str
) -> dict[str, dict[str, dict[str, int]]]:
    counters = {
        str(counter["name"]): counter
        for counter in receipt_cell["nft"]["counters"]
        if counter["router"] == router
    }
    return {
        phase: {
            name: {
                "packets": int(counter[f"{phase}_packets"]),
                "bytes": int(counter[f"{phase}_bytes"]),
            }
            for name, counter in counters.items()
        }
        for phase in ("before", "after", "delta")
    }


def raw_command_stderr_content(
    profile: str, index: int, *, packet_count: int | None = None
) -> bytes:
    if index in {0, 1}:
        return b""
    if packet_count is None:
        packet_count = 6 if profile == "cone-direct" else 9
    return (
        f"{packet_count} packets captured\n"
        f"{packet_count} packets received by filter\n"
        f"0 packets dropped by kernel\n"
    ).encode("ascii")


def raw_pcap_summary(receipt_cell: dict[str, object]) -> dict[str, object]:
    profile = str(receipt_cell["name"])
    proof = receipt_cell["pcap"]["tuple_proof"]
    routers: dict[str, object] = {}
    router_proof: dict[str, object] = {}
    for index, router in enumerate(("nat-a", "nat-b")):
        capture = receipt_cell["pcap"]["captures"][index]
        if profile == "cone-direct":
            packets = int(proof["direct_cross_nat_packets"]) // 2
            tuples = pcap_tuple_records(profile, router, packets)
            direct_packets = packets
            relay_packets = 0
        else:
            packets = int(proof["controlled_relay_https_packets"]) // 2
            tuples = pcap_tuple_records(profile, router, packets)
            direct_packets = 0
            relay_packets = packets
        routers[router] = {
            "bytes": capture["bytes"],
            "packets": capture["packets"],
            "sha256": capture["sha256"],
            "drop_count": capture["dropped_packets"],
            "path": f"outputs/{router}/{router}-wan.pcap",
            "role": router,
            "tuples": tuples,
            "tcpdump_stderr": f"command-{100 + index:04d}.stderr",
            "tcpdump_stderr_sha256": hashlib.sha256(
                raw_command_stderr_content(profile, 2 + index)
            ).hexdigest(),
        }
        router_proof[router] = {
            "direct_udp_packets": direct_packets,
            "relay_https_tcp_packets": relay_packets,
            "relay_http_tcp_packets": 0,
        }
    return {
        "schema": CHECKER.RAW_CONTROLLER_SCHEMA,
        "profile": profile,
        "routers": routers,
        "proof": router_proof,
    }


def raw_canary_scan(
    receipt_cell: dict[str, object],
    contents: dict[str, bytes],
    entry_by_role: dict[tuple[str, str], dict[str, object]],
) -> dict[str, object]:
    receipt = receipt_cell["canary_scan"]
    zero_counts = copy.deepcopy(receipt["class_match_counts"])
    profile = str(receipt_cell["name"])
    canary = fixture_canary(profile)
    needles = {
        "raw-bytes": canary,
        "lowercase-hex": canary.hex().encode("ascii"),
        "base64-standard": base64.b64encode(canary),
    }
    positive_bytes = (
        b"\x00ASTER-RAW\x00"
        + canary
        + b"\x00ASTER-HEX\x00"
        + needles["lowercase-hex"]
        + b"\x00ASTER-B64\x00"
        + needles["base64-standard"]
        + b"\x00ASTER-END\x00"
    )

    def retained_file(role: str) -> dict[str, object]:
        entry = entry_by_role[(profile, role)]
        content = contents[str(entry["path"])]
        prefix = f"cells/{profile}/"
        path = str(entry["path"])
        if not path.startswith(prefix):
            raise AssertionError("cell scan artifact is outside its cell")
        return {
            "path": path[len(prefix) :],
            "bytes": len(content),
            "sha256": hashlib.sha256(content).hexdigest(),
            "matches": copy.deepcopy(zero_counts),
        }

    pcap_files = [retained_file(f"{router}-wan-pcap") for router in ("nat-a", "nat-b")]
    retained_logs = {
        role: retained_file(role)
        for role in (
            "prepare-log",
            "publish-log",
            "verify-log",
            "node-a-log",
            "node-b-log",
            *(
                ("relay-log", "relay-material-log")
                if profile == "restrictive-relay"
                else ()
            ),
        )
    }
    certificate_files = (
        [retained_file(role) for role in ("relay-ca-der", "relay-cert-der")]
        if profile == "restrictive-relay"
        else []
    )
    command_stderr = []
    for path, content in (
        ("command-0201.stderr", raw_command_stderr_content(profile, 0)),
        ("command-0200.stderr", raw_command_stderr_content(profile, 1)),
        ("command-0100.stderr", raw_command_stderr_content(profile, 2)),
        ("command-0101.stderr", raw_command_stderr_content(profile, 3)),
    ):
        contents[f"cells/{profile}/{path}"] = content
        command_stderr.append(
            {
                "path": path,
                "bytes": len(content),
                "sha256": hashlib.sha256(content).hexdigest(),
                "matches": copy.deepcopy(zero_counts),
            }
        )
    log_files = [
        retained_logs["prepare-log"],
        retained_logs["publish-log"],
        retained_logs["verify-log"],
        retained_logs["node-a-log"],
        command_stderr[0],
        retained_logs["node-b-log"],
        command_stderr[1],
    ]
    if profile == "restrictive-relay":
        log_files.extend(
            [retained_logs["relay-log"], retained_logs["relay-material-log"]]
        )
    log_files.extend(command_stderr[2:])
    return {
        "schema": CHECKER.RAW_CONTROLLER_SCHEMA,
        "algorithm": "exact-byte-sequence/v1",
        "canary_bytes": 32,
        "canary_sha256": hashlib.sha256(canary).hexdigest(),
        "representations": [
            {
                "name": representation,
                "bytes": len(needles[representation]),
                "needle_sha256": hashlib.sha256(
                    needles[representation]
                ).hexdigest(),
                "positive_control_expected": 1,
                "positive_control_observed": 1,
            }
            for representation in CHECKER.CANARY_CLASSES
        ],
        "positive_control": {
            "path_class": "private-ephemeral",
            "bytes": len(positive_bytes),
            "expected": 3,
            "observed": 3,
            "class_match_counts": {
                representation: 1 for representation in CHECKER.CANARY_CLASSES
            },
            "pass": True,
        },
        "classes": list(CHECKER.CANARY_CLASSES),
        "artifact_classes": [
            {
                "class": artifact_class,
                "matches": copy.deepcopy(zero_counts),
                "total_matches": 0,
                "files": (
                    pcap_files
                    if artifact_class == "pcap"
                    else log_files
                    if artifact_class == "log"
                    else certificate_files
                ),
            }
            for artifact_class in ("pcap", "log", "public-certificate")
        ],
        "class_match_counts": zero_counts,
        "chronology": list(CHECKER.CANARY_CHRONOLOGY),
        "matches": 0,
        "status": "pass",
    }


def receipt_line(prefix: str, fields: dict[str, object]) -> str:
    return prefix + " " + " ".join(f"{key}={value}" for key, value in fields.items())


def raw_container_config(
    *,
    image_id: str,
    user: str,
    entrypoint: str,
    memory: int,
    pids: int,
    network: str,
    cap_add: list[str],
    sysctls: dict[str, str],
    extra_hosts: list[str],
    mounts: dict[str, tuple[str, bool]],
    network_addresses: dict[str, str],
    run_id: str,
    role: str,
    input_manifest_sha256: str,
    command: list[str],
) -> dict[str, object]:
    return {
        "Id": digest(f"container-{network}-{entrypoint}-{user}"),
        "Image": image_id,
        "HostConfig": {
            "Privileged": False,
            "Init": True,
            "ReadonlyRootfs": True,
            "Memory": memory,
            "MemorySwap": memory,
            "PidsLimit": pids,
            "NanoCpus": (
                1_000_000_000
                if memory >= 512 * 1024 * 1024
                else 250_000_000
                if memory <= 64 * 1024 * 1024
                else 500_000_000
            ),
            "NetworkMode": network,
            "CgroupnsMode": "private",
            "CapDrop": ["ALL"],
            "CapAdd": sorted(f"CAP_{capability}" for capability in cap_add) or None,
            "SecurityOpt": ["no-new-privileges:true"],
            "Devices": [],
            "DeviceRequests": None,
            "DeviceCgroupRules": None,
            "PidMode": "",
            "IpcMode": "private",
            "UTSMode": "",
            "UsernsMode": "",
            "PortBindings": {},
            "PublishAllPorts": False,
            "AutoRemove": False,
            "RestartPolicy": {"Name": "no", "MaximumRetryCount": 0},
            "Links": None,
            "VolumesFrom": None,
            "Ulimits": [{"Name": "nofile", "Hard": 65_536, "Soft": 65_536}],
            "Tmpfs": {
                "/tmp": "rw,noexec,nosuid,nodev,size=32m",
                "/run": "rw,noexec,nosuid,nodev,size=8m",
            },
            "Sysctls": sysctls,
            "ExtraHosts": extra_hosts,
        },
        "Config": {
            "User": user,
            "Entrypoint": [entrypoint],
            "Cmd": command,
            "Env": list(CHECKER.SELECTED_NAT_IMAGE_ENVIRONMENT),
            "ExposedPorts": None,
            "Volumes": None,
            "Labels": {
                **CHECKER.PINNED_BASE_IMAGE_LABELS,
                CHECKER.MANAGED_LABEL: "true",
                CHECKER.IMAGE_SCHEMA_LABEL: CHECKER.SELECTED_NAT_IMAGE_SCHEMA,
                CHECKER.IMAGE_INPUT_LABEL: input_manifest_sha256,
                CHECKER.IMAGE_BASE_LABEL: CHECKER.LAB_BASE_IMAGE,
                CHECKER.RUN_LABEL: run_id,
                CHECKER.ROLE_LABEL: role,
            },
        },
        "Mounts": [
            {
                "Type": "bind",
                "Source": source,
                "Destination": destination,
                "RW": read_write,
            }
            for destination, (source, read_write) in mounts.items()
        ],
        "NetworkSettings": {
            "Networks": {
                name: {"IPAddress": address}
                for name, address in network_addresses.items()
            }
        },
    }


def raw_nft_program(profile: str, router: str) -> str:
    lan_if = "eth0"
    wan_if = "eth1"
    if router == "nat-a":
        lan_subnet = "10.250.1.0/24"
        node_ip = "10.250.1.10"
        external_ip = "10.250.0.11"
        peer_external_ip = "10.250.0.12"
    else:
        lan_subnet = "10.250.2.0/24"
        node_ip = "10.250.2.10"
        external_ip = "10.250.0.12"
        peer_external_ip = "10.250.0.11"
    if profile == "cone-direct":
        return f'''flush ruleset
table inet aster_selected_filter {{
    counter aster_cone_forward_out {{}}
    counter aster_cone_forward_in {{}}
    chain forward {{
        type filter hook forward priority filter; policy drop;
        iifname "{lan_if}" oifname "{wan_if}" ip saddr {node_ip} ip daddr {peer_external_ip} udp sport 44000 udp dport 44000 counter name aster_cone_forward_out accept
        iifname "{wan_if}" oifname "{lan_if}" ip daddr {node_ip} udp dport 44000 counter name aster_cone_forward_in accept
        ct state established,related accept
    }}
}}
table ip aster_selected_nat {{
    counter aster_cone_dnat {{}}
    counter aster_cone_snat {{}}
    chain prerouting {{
        type nat hook prerouting priority dstnat;
        iifname "{wan_if}" ip daddr {external_ip} udp dport 44000 counter name aster_cone_dnat dnat to {node_ip}:44000
    }}
    chain postrouting {{
        type nat hook postrouting priority srcnat;
        oifname "{wan_if}" ip saddr {node_ip} udp sport 44000 counter name aster_cone_snat snat to {external_ip}:44000
    }}
}}
'''
    return f'''flush ruleset
table inet aster_selected_filter {{
    counter aster_restrict_direct_drop {{}}
    counter aster_restrict_relay_https {{}}
    counter aster_restrict_relay_http {{}}
    counter aster_restrict_established {{}}
    chain forward {{
        type filter hook forward priority filter; policy drop;
        iifname "{lan_if}" oifname "{wan_if}" ip saddr {node_ip} ip daddr {peer_external_ip} udp dport 44000 counter name aster_restrict_direct_drop drop
        iifname "{lan_if}" oifname "{wan_if}" ip saddr {node_ip} ip daddr 10.250.0.20 tcp dport 8443 counter name aster_restrict_relay_https accept
        iifname "{lan_if}" oifname "{wan_if}" ip saddr {node_ip} ip daddr 10.250.0.20 tcp dport 8080 counter name aster_restrict_relay_http accept
        iifname "{wan_if}" oifname "{lan_if}" ct state established,related counter name aster_restrict_established accept
    }}
}}
table ip aster_selected_nat {{
    chain postrouting {{
        type nat hook postrouting priority srcnat;
        oifname "{wan_if}" ip saddr {lan_subnet} masquerade
    }}
}}
'''


def raw_network_config(profile: str, role: str, run_id: str) -> dict[str, object]:
    fixed = {
        "lan-a": (
            "aster-lab-lan-a",
            "10.250.1.0/24",
            "10.250.1.254",
            {"aster-lab-node-a": "10.250.1.10/24", "aster-lab-nat-a": "10.250.1.1/24"},
        ),
        "wan": (
            "aster-lab-wan",
            "10.250.0.0/24",
            "10.250.0.254",
            {
                "aster-lab-nat-a": "10.250.0.11/24",
                "aster-lab-nat-b": "10.250.0.12/24",
                **(
                    {"aster-lab-infra": "10.250.0.20/24"}
                    if profile == "restrictive-relay"
                    else {}
                ),
            },
        ),
        "lan-b": (
            "aster-lab-lan-b",
            "10.250.2.0/24",
            "10.250.2.254",
            {"aster-lab-node-b": "10.250.2.10/24", "aster-lab-nat-b": "10.250.2.1/24"},
        ),
    }
    name, subnet, gateway, members = fixed[role]
    return {
        "Name": name,
        "Driver": "bridge",
        "Internal": True,
        "Attachable": False,
        "Ingress": False,
        "Labels": {
            CHECKER.MANAGED_LABEL: "true",
            CHECKER.RUN_LABEL: run_id,
            CHECKER.ROLE_LABEL: role,
        },
        "IPAM": {"Driver": "default", "Config": [{"Subnet": subnet, "Gateway": gateway}]},
        "Containers": {
            digest(f"{profile}-{member}"): {
                "Name": member,
                "IPv4Address": address,
            }
            for member, address in members.items()
        },
    }


def semantic_raw_artifacts(
    root: Path,
    document: dict[str, object],
    *,
    mission_authorities: dict[str, str] | None = None,
    ready_authorities: dict[tuple[str, str], str] | None = None,
) -> dict[str, bytes]:
    root = root.resolve()
    build_arguments = shlex.split(document["build"]["command"])
    evidence_root = Path(build_arguments[-1]).parent
    entries = document["raw_manifest"]["entries"]
    entry_by_role = {
        (str(entry["cell"]), str(entry["role"])): entry for entry in entries
    }
    contents = {
        str(entry["path"]): artifact_content(
            str(entry["cell"]), str(entry["role"]), int(entry["bytes"])
        )
        for entry in entries
    }
    for entry in entries:
        role = str(entry["role"])
        if role in {"relay-ca-der", "relay-cert-der"}:
            contents[str(entry["path"])] = test_certificate_der(
                "ca" if role == "relay-ca-der" else "server"
            )

    def put_bytes(scope: str, role: str, content: bytes) -> bytes:
        entry = entry_by_role[(scope, role)]
        contents[str(entry["path"])] = content
        return content

    def put(scope: str, role: str, value: object) -> bytes:
        return put_bytes(scope, role, raw_json(value))

    source = {
        "schema": CHECKER.RAW_CONTROLLER_SCHEMA,
        "commit": document["source"]["commit"],
        "tree": document["source"]["tree"],
        "tracked_and_untracked_nonignored_clean": True,
        "commit_signature_verified": True,
        "cargo_toml_sha256": digest("Cargo.toml"),
        "cargo_lock_sha256": document["source"]["cargo_lock_sha256"],
        "requirements_sha256": document["source"]["requirements_sha256"],
        "dockerfile_sha256": document["build"]["container"][
            "dockerfile_sha256"
        ],
        "build_input_manifest_sha256": document["build"]["container"][
            "input_manifest_sha256"
        ],
    }
    build_environment = {
        "schema": CHECKER.RAW_CONTROLLER_SCHEMA,
        "physical_hosts": document["environment"]["physical_hosts"],
        "isolation": document["environment"]["isolation"],
        "host_os": document["environment"]["host_os"],
        "host_arch": document["environment"]["host_arch"],
        "kernel": document["environment"]["kernel"],
        "docker_version": document["environment"]["docker_version"],
        "orbstack_version": document["environment"]["orbstack_version"],
        "build_network": CHECKER.LIMITATIONS["build_network"],
    }
    build = {
        "schema": CHECKER.RAW_CONTROLLER_SCHEMA,
        "arguments": shlex.split(document["build"]["command"]),
        "command": document["build"]["command"],
        "network": "default",
        "no_cache": True,
        "pull": False,
        "input_manifest_sha256": document["build"]["container"][
            "input_manifest_sha256"
        ],
        "dockerfile_sha256": document["build"]["container"][
            "dockerfile_sha256"
        ],
        "build_run_id": document["build"]["container"]["build_run_id"],
        "status": "pass",
        "image_id": document["build"]["container"]["image_id"],
        "image_config_digest": document["build"]["container"][
            "image_config_digest"
        ],
        "runtime_packages": 6,
        "runtime_package_inventory_sha256": digest("runtime-package-inventory"),
        "environment": build_environment,
    }
    controller = {
        "schema": CHECKER.RAW_CONTROLLER_SCHEMA,
        "created_utc": "2026-08-26T00:00:00Z",
        "run_id": document["build"]["container"]["build_run_id"],
        "label": "selected-iroh-nat",
        "workspace": "/workspace/aster",
        "evidence_dir": str(evidence_root),
        "image": CHECKER.SELECTED_NAT_IMAGE,
        "resources": [],
    }
    put("global", "suite-controller", controller)
    put("global", "suite-source-identity", source)
    put("global", "suite-build-identity", build)

    inventory = [
        {
            **copy.deepcopy(record),
            "path": f"/usr/local/bin/{record['name']}",
        }
        for record in document["build"]["artifacts"]
    ]
    image = {
        "id": document["build"]["container"]["image_id"],
        "repo_digests": [
            f"{CHECKER.SELECTED_NAT_LOCAL_REPOSITORY}@"
            f"{document['build']['container']['image_id']}"
        ],
        "labels": {
            **CHECKER.PINNED_BASE_IMAGE_LABELS,
            CHECKER.MANAGED_LABEL: "true",
            CHECKER.RUN_LABEL: document["build"]["container"]["build_run_id"],
            CHECKER.IMAGE_SCHEMA_LABEL: CHECKER.SELECTED_NAT_IMAGE_SCHEMA,
            CHECKER.IMAGE_INPUT_LABEL: document["build"]["container"][
                "input_manifest_sha256"
            ],
            CHECKER.IMAGE_BASE_LABEL: CHECKER.LAB_BASE_IMAGE,
        },
        "architecture": "arm64",
        "env": list(CHECKER.SELECTED_NAT_IMAGE_ENVIRONMENT),
    }
    cell_summaries = []
    for cell_index, receipt_cell in enumerate(document["cells"]):
        profile = str(receipt_cell["name"])
        run_id = f"{cell_index + 1:016x}"
        cell_root = evidence_root / "cells" / profile
        resource_roles = [
            ("network", "aster-lab-lan-a", "lan-a"),
            ("network", "aster-lab-wan", "wan"),
            ("network", "aster-lab-lan-b", "lan-b"),
            *[
                ("container", f"aster-lab-{role}", role)
                for role in (
                    "provision",
                    "node-a",
                    "nat-a",
                    "route-a",
                    "nat-b",
                    "node-b",
                    "route-b",
                )
            ],
        ]
        if profile == "restrictive-relay":
            resource_roles.append(("container", "aster-lab-infra", "infra"))
        cell_controller = {
            "schema": CHECKER.RAW_CONTROLLER_SCHEMA,
            "created_utc": "2026-08-26T00:00:01Z",
            "run_id": run_id,
            "label": profile,
            "workspace": "/workspace/aster",
            "evidence_dir": str(cell_root),
            "image": CHECKER.SELECTED_NAT_IMAGE,
            "resources": [
                {"kind": kind, "name": name, "role": role}
                for kind, name, role in resource_roles
            ],
        }
        put(profile, "controller-receipt", cell_controller)
        put(
            profile,
            "scenario-receipt",
            {
                "schema": CHECKER.RAW_CONTROLLER_SCHEMA,
                "operation": profile,
                "scenario": "selected-iroh-nat-acceptance",
                "profile": profile,
                "scope": f"lab/selected-iroh-nat/{profile}",
                "topic": "lab.selected-iroh-nat",
                "duration_seconds": 30,
                "physical_hosts": 1,
                "namespace_isolation": True,
                "infrastructure_free": profile == "cone-direct",
                "controlled_relay": profile == "restrictive-relay",
                "physical_nat_claim": False,
                "public_internet": False,
            },
        )
        event_lines = []
        for event_index, event in enumerate(
            CHECKER.selected_nat_expected_events(profile, run_id)
        ):
            event_lines.append(
                json.dumps(
                    {
                        **event,
                        "utc": f"2026-08-26T00:00:{event_index:02d}Z",
                    },
                    sort_keys=True,
                    separators=(",", ":"),
                )
            )
        put_bytes(
            profile,
            "events",
            ("\n".join(event_lines) + "\n").encode("ascii"),
        )
        put(profile, "source-identity", source)
        put(profile, "build-identity", inventory)
        put(profile, "image-identity", image)

        scope = f"lab/selected-iroh-nat/{profile}"
        topic = "lab.selected-iroh-nat"
        mission_authority = (mission_authorities or {}).get(
            profile, digest(f"{profile}-mission-authority")
        )
        manifest_nodes = {
            node: {
                "name": node,
                "mission_id": receipt_cell["endpoints"][identity_index][
                    "mission_id"
                ],
                "carrier_id": receipt_cell["endpoints"][identity_index][
                    "carrier_id"
                ],
                "subscription_id": digest(f"{profile}-{node}-subscription"),
            }
            for identity_index, node in enumerate(("a", "b"))
        }
        manifest_text = (
            f"ASTER_SELECTED_NAT_MANIFEST\tversion=2\tscope={scope}\ttopic={topic}"
            f"\tmission_authority={mission_authority}"
            f"\tcanary_sha256={receipt_cell['event']['canary_sha256']}\tnodes=2\n"
            "name\tmission_id\tcarrier_id\tsubscription_id\n"
            + "\n".join(
                "\t".join(
                    (
                        node,
                        manifest_nodes[node]["mission_id"],
                        manifest_nodes[node]["carrier_id"],
                        manifest_nodes[node]["subscription_id"],
                    )
                )
                for node in ("a", "b")
            )
            + "\n"
        ).encode("utf-8")
        put_bytes(profile, "prepare-manifest", manifest_text)
        prepare_digest = hashlib.sha256(manifest_text).hexdigest()
        prepare_lines = [
            receipt_line(
                "SELECTED_NAT_PREPARE",
                {
                    "status": "pass",
                    "version": 2,
                    "nodes": 2,
                    "scope": scope,
                    "topic": topic,
                    "manifest": "/output/manifest.tsv",
                    "mission_authority": mission_authority,
                    "mission_authority_shared": "true",
                    "mission_authority_disjoint": "true",
                    "mission_ids_distinct": "true",
                    "carrier_ids_distinct": "true",
                    "mission_carrier_disjoint": "true",
                    "subscriptions": 2,
                    "pre_inventory_events": 0,
                    "canary_sha256": receipt_cell["event"]["canary_sha256"],
                    "canary_bytes": 32,
                    "canary": "redacted",
                },
            ),
            *[
                receipt_line(
                    "SELECTED_NAT_NODE",
                    {
                        "name": node,
                        "mission_id": manifest_nodes[node]["mission_id"],
                        "carrier_id": manifest_nodes[node]["carrier_id"],
                    },
                )
                for node in ("a", "b")
            ],
        ]
        put_bytes(
            profile, "prepare-log", ("\n".join(prepare_lines) + "\n").encode("utf-8")
        )

        selected = "Direct" if profile == "cone-direct" else "Relay"
        node_results = {}
        for node_index, node_role in enumerate(("node-a", "node-b")):
            short_name = "a" if node_role == "node-a" else "b"
            peer_name = "b" if short_name == "a" else "a"
            transition_count = receipt_cell["path"]["witnesses"][node_index][
                "transition_count"
            ]
            ready = {
                "selected": "true",
                "pid": str(1000 + node_index),
                "carrier_id": manifest_nodes[short_name]["carrier_id"],
                "mission_id": manifest_nodes[short_name]["mission_id"],
                "mission_authority": (ready_authorities or {}).get(
                    (profile, node_role), mission_authority
                ),
                "sockets": (
                    "10.250.1.10:44000" if node_role == "node-a" else "10.250.2.10:44000"
                ),
                "state": f"/output/{node_role}",
                "peers": "1",
                "application": "relay",
                "carrier_route": (
                    "direct" if profile == "cone-direct" else "direct-plus-controlled-relay"
                ),
                "controlled_relay_url": (
                    "none"
                    if profile == "cone-direct"
                    else "https://relay.aster.test:8443/"
                ),
                "controlled_relay_trust": (
                    "none" if profile == "cone-direct" else "explicit-der-roots"
                ),
                "controlled_relay_readiness": (
                    "not-applicable" if profile == "cone-direct" else "deferred"
                ),
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
            }
            final_contact = {
                "direction": "out" if node_role == "node-a" else "in",
                "carrier_peer": manifest_nodes[peer_name]["carrier_id"],
                "mission_peer": manifest_nodes[peer_name]["mission_id"],
                "rounds": "18",
                **{
                    field: str(receipt_cell["reconciliation"][field])
                    for field in sorted(CHECKER.RECONCILIATION_KEYS)
                    if field not in {"status", "contacts"}
                },
                "handshake_frames": "4",
                "handshake_bytes": "22874",
                "protected_frames": "100",
                "protected_bytes": "6941",
                "carrier_path": "direct" if profile == "cone-direct" else "relay",
                "carrier_path_transitions": "0",
                "carrier_path_transitions_saturated": "false",
                "path_observation": "not-authorization",
                "mission_auth": "hybrid-pq",
                "semantics": "source-authenticated-event",
                "reconciliation_classes": "event,state,record,blob",
                "controls": "source-authenticated-flash",
                "content_admission": "capability-gated",
                "status": "pass",
            }
            transfer_contact = dict(final_contact)
            transfer_contact["carrier_path_transitions"] = str(transition_count)
            if node_role == "node-a":
                transfer_contact["offered"] = "1"
            else:
                transfer_contact["fetched"] = "1"
                transfer_contact["inserted"] = "1"
            contacts = [transfer_contact, final_contact]
            stop = {
                "lifecycle": "complete",
                "sync_status": "contacts_observed",
                "carrier_id": manifest_nodes[short_name]["carrier_id"],
                "mission_id": manifest_nodes[short_name]["mission_id"],
                "contacts": "2",
                "contact_errors": "0",
                "direct_contacts": "2" if profile == "cone-direct" else "0",
                "relay_contacts": "0" if profile == "cone-direct" else "2",
                "unknown_path_contacts": "0",
                "carrier_path_transitions": str(transition_count),
                "carrier_path_transition_saturations": "0",
                "path_observation": "not-authorization",
                "opaque_items": "0",
                "opaque_acceptance_markers": "0",
                "events": "1",
                "event_acceptance_markers": "1",
                "route_cached_events": "0",
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
            }
            result = {
                "ready": ready,
                "stop": stop,
                "contacts": contacts,
                "path": selected,
                "saturated": False,
                "transition_count": transition_count,
                "final_noop": {
                    field: receipt_cell["reconciliation"][field]
                    for field in CHECKER.RECONCILIATION_KEYS
                    if field not in {"status", "contacts"}
                },
            }
            node_results[node_role] = result
            put(profile, f"{node_role}-result", result)
            transcript = (
                "ASTER_SELECTED_NAT_TRANSCRIPT version=1 stream=stdout\n"
                + receipt_line("READY", ready)
                + "\n"
                + "\n".join(receipt_line("CONTACT", contact) for contact in contacts)
                + "\n"
                + receipt_line("STOP", stop)
                + "\nASTER_SELECTED_NAT_TRANSCRIPT version=1 stream=stderr\n"
            ).encode("utf-8")
            put_bytes(profile, f"{node_role}-log", transcript)

        runtime_privileges = {
            node_role: {
                "uid": os.getuid(),
                "gid": os.getgid(),
                "no_new_privs": True,
                "cap_inheritable": 0,
                "cap_permitted": 0,
                "cap_effective": 0,
                "cap_bounding": 0,
                "cap_ambient": 0,
            }
            for node_role in ("node-a", "node-b")
        }
        for node_role in ("node-a", "node-b"):
            put(
                profile,
                f"{node_role}-runtime-privilege",
                runtime_privileges[node_role],
            )
            network = "aster-lab-lan-a" if node_role == "node-a" else "aster-lab-lan-b"
            address = "10.250.1.10" if node_role == "node-a" else "10.250.2.10"
            node_mounts = {
                f"/output/{node_role}": (
                    str(cell_root / "outputs" / "provision" / node_role),
                    True,
                ),
                "/run/secrets/node.bundle": (
                    str(
                        cell_root
                        / "outputs"
                        / "provision"
                        / "private"
                        / f"{node_role}.bundle"
                    ),
                    True,
                ),
            }
            if profile == "restrictive-relay":
                node_mounts["/run/relay/ca.der"] = (
                    str(cell_root / "outputs" / "provision" / "relay" / "ca.der"),
                    False,
                )
            put(
                profile,
                f"{node_role}-config",
                raw_container_config(
                    image_id=document["build"]["container"]["image_id"],
                    user=f"{os.getuid()}:{os.getgid()}",
                    entrypoint="/usr/bin/sleep",
                    memory=1024 * 1024 * 1024,
                    pids=256,
                    network=network,
                    cap_add=[],
                    sysctls={},
                    extra_hosts=(
                        ["relay.aster.test:10.250.0.20"]
                        if profile == "restrictive-relay"
                        else []
                    ),
                    mounts=node_mounts,
                    network_addresses={network: address},
                    run_id=run_id,
                    role=node_role,
                    input_manifest_sha256=document["build"]["container"][
                        "input_manifest_sha256"
                    ],
                    command=["infinity"],
                ),
            )

        route_receipts = [
            {
                "role": route_role,
                "name": f"aster-lab-{route_role}",
                "exit_code": 0,
                "exited": True,
                "removed": True,
                "log": f"reap-aster-lab-{route_role}-command-{90 + index:04d}.log",
                "log_sha256": hashlib.sha256(b"").hexdigest(),
                "node": node_role,
                "gateway": gateway,
                "route": {
                    "dev": "eth0",
                    "dst": "default",
                    "flags": [],
                    "gateway": gateway,
                },
            }
            for index, (route_role, node_role, gateway) in enumerate((
                ("route-a", "node-a", "10.250.1.1"),
                ("route-b", "node-b", "10.250.2.1"),
            ))
        ]
        put(profile, "route-init-removal", route_receipts)

        canary_destroy = {
            "status": "pass",
            "version": "2",
            "publication_journals_destroyed": "2",
            "artifact_destroyed": "true",
            "global_secret_destruction": "false",
            "target": "private/canary.bin",
            "previous_bytes": "32",
            "previous_mode": "0600",
            "owner_uid": str(os.getuid()),
            "overwrite": "zero",
            "sync": "file+directory",
            "unlinked": "true",
            "assurance": "bounded-software",
            "physical_sanitization": "not-claimed",
        }
        relay_destroy = (
            {
                **{key: value for key, value in canary_destroy.items() if key != "publication_journals_destroyed"},
                "version": "1",
                "target": "private/server.key.pkcs8.der",
                "previous_bytes": "128",
            }
            if profile == "restrictive-relay"
            else None
        )
        put_bytes(
            profile,
            "canary-destroy-log",
            (receipt_line("SELECTED_NAT_CANARY_DESTROY", canary_destroy) + "\n").encode(
                "utf-8"
            ),
        )
        cleanup = {
            "schema": CHECKER.RAW_CONTROLLER_SCHEMA,
            "status": "pass",
            "raw_canary_control_file": canary_destroy,
            "relay_private_key_file": relay_destroy,
            **{
                field: receipt_cell["cleanup"][field]
                for field in (
                    "canary_control_file_disposition",
                    "canary_control_file_previous_bytes",
                    "canary_control_file_absent_after_cleanup",
                    "relay_private_key_file_disposition",
                    "relay_private_key_file_absent_after_cleanup",
                    "assurance",
                    "physical_sanitization",
                )
            },
            "encrypted_event_state_retained": True,
            "mission_credentials_retained_external_restricted": True,
            "global_secret_destruction": False,
        }
        put(profile, "secret-cleanup-receipt", cleanup)
        if relay_destroy is not None:
            put_bytes(
                profile,
                "relay-material-destroy-log",
                (
                    receipt_line(
                        "SELECTED_NAT_RELAY_MATERIAL_DESTROY", relay_destroy
                    )
                    + "\n"
                ).encode("utf-8"),
            )

        for capture in receipt_cell["pcap"]["captures"]:
            capture_content = pcap_capture_bytes(
                profile,
                str(capture["role"]).removesuffix("-wan"),
                int(capture["packets"]),
            )
            self_hash = hashlib.sha256(capture_content).hexdigest()
            if (
                len(capture_content) != capture["bytes"]
                or self_hash != capture["sha256"]
            ):
                raise AssertionError("source-shaped pcap fixture metadata differs")
            put_bytes(profile, str(capture["manifest_role"]), capture_content)
        pcap_summary = raw_pcap_summary(receipt_cell)
        pcap_content = put(profile, "pcap-tuple-summary", pcap_summary)
        receipt_cell["pcap"]["tuple_summary_sha256"] = hashlib.sha256(
            pcap_content
        ).hexdigest()

        nft_evidence = {
            router: raw_nft_evidence(receipt_cell, router)
            for router in ("nat-a", "nat-b")
        }
        for router in ("nat-a", "nat-b"):
            for phase in ("before", "after"):
                put(
                    profile,
                    f"{router}-nft-{phase}",
                    {
                        "schema": CHECKER.RAW_CONTROLLER_SCHEMA,
                        "profile": profile,
                        "role": router,
                        "phase": phase,
                        "counters": nft_evidence[router][phase],
                        "ruleset_sha256": digest(
                            f"{profile}-{router}-{phase}-ruleset"
                        ),
                    },
                )

        event = receipt_cell["event"]
        publish = {
            "status": "pass",
            "version": "2",
            "publication_model": "numbered-v1",
            "node": "a",
            "event_id": event["event_id"],
            "publisher": event["publisher"],
            "sequence": "1",
            "inserted": "true",
            "replay_publish": "noop",
            "pre_inventory_events": "0",
            "post_inventory_events": "1",
            "canary_sha256": event["canary_sha256"],
            "payload_sha256": event["payload_sha256"],
            "payload_bytes": "32",
            "sealed_sha256": event["sealed_sha256"],
            "exact_query": "true",
        }
        verify = {
            "status": "pass",
            "version": "1",
            "node": "b",
            "event_id": event["event_id"],
            "publisher": event["publisher"],
            "pre_inventory_events": "0",
            "post_inventory_events": "1",
            "canary_sha256": event["canary_sha256"],
            "payload_sha256": event["payload_sha256"],
            "payload_bytes": "32",
            "sealed_sha256": event["sealed_sha256"],
            "deliveries": "1",
            "attempt": "1",
            "acknowledged": "true",
            "empty_after_ack": "true",
            "replay_ack": "noop",
            "replay_subscription": "noop",
            "exact_query": "true",
        }
        put_bytes(
            profile,
            "publish-log",
            (receipt_line("SELECTED_NAT_PUBLISH", publish) + "\n").encode("utf-8"),
        )
        put_bytes(
            profile,
            "verify-log",
            (receipt_line("SELECTED_NAT_VERIFY", verify) + "\n").encode("utf-8"),
        )
        raw_event = {
            "publish": publish,
            "verify": verify,
            "transfer_insertions": 1,
            "transfer_fetches": 1,
            "sealed_sha256": "not-exposed-by-production-api",
        }
        if profile == "cone-direct":
            relay_evidence = {
                "schema": CHECKER.RAW_CONTROLLER_SCHEMA,
                "profile": profile,
                "relay_container": False,
                "relay_configuration": False,
                "legacy_ports_4476_4477": False,
                "hosted_discovery": False,
                "public_relay_fallback": False,
                "status": "pass",
            }
            put(profile, "relay-disabled-receipt", relay_evidence)
            raw_relay = None
            relay_privilege = None
        else:
            relay = receipt_cell["relay"]
            ca_entry = entry_by_role[(profile, "relay-ca-der")]
            certificate_entry = entry_by_role[(profile, "relay-cert-der")]
            relay["root_fingerprint_sha256"] = hashlib.sha256(
                contents[str(ca_entry["path"])]
            ).hexdigest()
            certificate_sha256 = hashlib.sha256(
                contents[str(certificate_entry["path"])]
            ).hexdigest()
            relay_material = {
                "status": "pass",
                "version": "1",
                "dns_name": "relay.aster.test",
                "ip_address": "10.250.0.20",
                "san": "dns+ip",
                "ca_sha256": relay["root_fingerprint_sha256"],
                "certificate_sha256": certificate_sha256,
                "certificate_format": "der",
                "private_key_format": "pkcs8-der",
                "private_key": "redacted",
                "key_mode": "0600",
            }
            put_bytes(
                profile,
                "relay-material-log",
                (
                    receipt_line("SELECTED_NAT_RELAY_MATERIAL", relay_material)
                    + "\n"
                ).encode("utf-8"),
            )
            relay_evidence = {
                "schema": CHECKER.RAW_CONTROLLER_SCHEMA,
                "origin": "https://relay.aster.test:8443/",
                "address": "10.250.0.20",
                "https_port": 8443,
                "http_port": 8080,
                "tls_mode": relay["tls_mode"],
                "server_trust_claim": relay["server_trust_claim"],
                "client_trust_mode": relay["client_trust_mode"],
                "root_fingerprint_sha256": relay["root_fingerprint_sha256"],
                "certificate_sha256": certificate_sha256,
                "allowlist": sorted(
                    endpoint["carrier_id"] for endpoint in receipt_cell["endpoints"]
                ),
                "max_admitted_connections": relay["max_admitted_connections"],
                "pre_auth_connection_cap": relay["pre_auth_connection_cap"],
                "client_rx_bytes_per_second": relay["client_rx_bytes_per_second"],
                "client_rx_max_burst_bytes": relay["client_rx_max_burst_bytes"],
                "key_cache_capacity": relay["key_cache_capacity"],
                "public_relay_fallback": False,
                "hosted_discovery": False,
                "port_mapper": False,
            }
            put(profile, "relay-config", relay_evidence)
            relay_ready = {
                "status": "ready",
                "version": "1",
                "https": "0.0.0.0:8443",
                "http": "0.0.0.0:8080",
                "tls": relay["tls_mode"],
                "server_trust_claim": relay["server_trust_claim"],
                "allowlist": relay["allowlist_mode"],
                "allowlist_count": "2",
                "max_admitted_connections": str(relay["max_admitted_connections"]),
                "pre_auth_connection_cap": relay["pre_auth_connection_cap"],
                "client_rx_bytes_per_second": str(
                    relay["client_rx_bytes_per_second"]
                ),
                "client_rx_max_burst_bytes": str(
                    relay["client_rx_max_burst_bytes"]
                ),
                "key_cache_capacity": str(relay["key_cache_capacity"]),
                "secrets_logged": "false",
                "public_relay_fallback": "false",
                "hosted_discovery": "false",
                "port_mapper": "false",
            }
            relay_stop = {
                "status": "pass",
                "version": "1",
                "accepted_connections": str(relay["accepted_sessions"]),
                "denied_connections": str(relay["rejected_sessions"]),
                "active_connections": "0",
                "peak_active_connections": str(
                    relay["observed_active_sessions_peak"]
                ),
                "sessions": str(relay["accepted_sessions"]),
                "bytes_up": "4096",
                "bytes_down": "8192",
                "max_admitted_connections": str(relay["max_admitted_connections"]),
                "pre_auth_connection_cap": relay["pre_auth_connection_cap"],
                "client_rx_bytes_per_second": str(
                    relay["client_rx_bytes_per_second"]
                ),
                "client_rx_max_burst_bytes": str(
                    relay["client_rx_max_burst_bytes"]
                ),
                "key_cache_capacity": str(relay["key_cache_capacity"]),
                "allowlist": relay["allowlist_mode"],
                "allowlist_count": "2",
                "server_trust_claim": relay["server_trust_claim"],
                "graceful": "true",
            }
            put_bytes(
                profile,
                "relay-log",
                (
                    receipt_line("SELECTED_NAT_RELAY_READY", relay_ready)
                    + "\n"
                    + receipt_line("SELECTED_NAT_RELAY_STOP", relay_stop)
                    + "\n"
                ).encode("utf-8"),
            )
            raw_relay = {
                "ready": relay_ready,
                "stop": relay_stop,
            }
            relay_privilege = {
                "uid": os.getuid(),
                "gid": os.getgid(),
                "no_new_privs": True,
                "cap_inheritable": 0,
                "cap_permitted": 0,
                "cap_effective": 0,
                "cap_bounding": 0,
                "cap_ambient": 0,
            }
            put(profile, "relay-runtime-privilege", relay_privilege)
            relay_command = [
                "--https-bind",
                "0.0.0.0:8443",
                "--http-bind",
                "0.0.0.0:8080",
                "--certificate-der",
                "/run/relay/server.cert.der",
                "--private-key-pkcs8-der",
                "/run/relay/server.key.pkcs8.der",
            ]
            for carrier_id in sorted(
                endpoint["carrier_id"] for endpoint in receipt_cell["endpoints"]
            ):
                relay_command.extend(["--allow-carrier", str(carrier_id)])
            relay_command.extend(
                [
                    "--max-admitted-connections",
                    "8",
                    "--client-rx-bytes-per-second",
                    "1048576",
                    "--client-rx-max-burst-bytes",
                    "1048576",
                    "--key-cache-capacity",
                    "256",
                ]
            )
            put(
                profile,
                "relay-runtime-config",
                raw_container_config(
                    image_id=document["build"]["container"]["image_id"],
                    user=f"{os.getuid()}:{os.getgid()}",
                    entrypoint="/usr/local/bin/aster-selected-relay",
                    memory=512 * 1024 * 1024,
                    pids=256,
                    network="aster-lab-wan",
                    cap_add=[],
                    sysctls={},
                    extra_hosts=[],
                    mounts={
                        "/output": (str(cell_root / "outputs" / "infra"), True),
                        "/run/relay/server.cert.der": (
                            str(
                                cell_root
                                / "outputs"
                                / "provision"
                                / "relay"
                                / "server.cert.der"
                            ),
                            False,
                        ),
                        "/run/relay/server.key.pkcs8.der": (
                            str(
                                cell_root
                                / "outputs"
                                / "provision"
                                / "relay"
                                / "private"
                                / "server.key.pkcs8.der"
                            ),
                            False,
                        ),
                    },
                    network_addresses={"aster-lab-wan": "10.250.0.20"},
                    run_id=run_id,
                    role="infra",
                    input_manifest_sha256=document["build"]["container"][
                        "input_manifest_sha256"
                    ],
                    command=relay_command,
                ),
            )

        runtime_routers = []
        for router in ("nat-a", "nat-b"):
            lan_network = "aster-lab-lan-a" if router == "nat-a" else "aster-lab-lan-b"
            lan_address = "10.250.1.1" if router == "nat-a" else "10.250.2.1"
            wan_address = "10.250.0.11" if router == "nat-a" else "10.250.0.12"
            node_ip = "10.250.1.10" if router == "nat-a" else "10.250.2.10"
            peer_external = "10.250.0.12" if router == "nat-a" else "10.250.0.11"
            put(
                profile,
                f"{router}-config",
                raw_container_config(
                    image_id=document["build"]["container"]["image_id"],
                    user="",
                    entrypoint="/usr/bin/sleep",
                    memory=256 * 1024 * 1024,
                    pids=64,
                    network=lan_network,
                    cap_add=["NET_ADMIN", "NET_RAW", "SETUID", "SETGID"],
                    sysctls={"net.ipv4.ip_forward": "1"},
                    extra_hosts=[],
                    mounts={
                        "/output": (str(cell_root / "outputs" / router), True)
                    },
                    network_addresses={
                        lan_network: lan_address,
                        "aster-lab-wan": wan_address,
                    },
                    run_id=run_id,
                    role=router,
                    input_manifest_sha256=document["build"]["container"][
                        "input_manifest_sha256"
                    ],
                    command=["infinity"],
                ),
            )
            nft_program = raw_nft_program(profile, router)
            put_bytes(profile, f"{router}-nft-program", nft_program.encode("utf-8"))
            runtime_routers.append(
                {
                    "role": router,
                    "container": f"aster-lab-{router}",
                    "lan_interface": "eth0",
                    "wan_interface": "eth1",
                    "lan_address": lan_address,
                    "wan_address": wan_address,
                    "node_ip": node_ip,
                    "peer_external_ip": peer_external,
                    "capture_relative_path": f"outputs/{router}/{router}-wan.pcap",
                }
            )

        for provision_role in ("provision-prepare-config", "provision-verify-config"):
            put(
                profile,
                provision_role,
                raw_container_config(
                    image_id=document["build"]["container"]["image_id"],
                    user=f"{os.getuid()}:{os.getgid()}",
                    entrypoint="/usr/bin/sleep",
                    memory=512 * 1024 * 1024,
                    pids=128,
                    network="none",
                    cap_add=[],
                    sysctls={},
                    extra_hosts=[],
                    mounts={
                        "/output": (
                            str(cell_root / "outputs" / "provision"),
                            True,
                        )
                    },
                    network_addresses={"none": ""},
                    run_id=run_id,
                    role="provision",
                    input_manifest_sha256=document["build"]["container"][
                        "input_manifest_sha256"
                    ],
                    command=["infinity"],
                ),
            )
        for route_role, node_role in (("route-a", "node-a"), ("route-b", "node-b")):
            put(
                profile,
                f"{route_role}-config",
                raw_container_config(
                    image_id=document["build"]["container"]["image_id"],
                    user="",
                    entrypoint="/usr/sbin/ip",
                    memory=64 * 1024 * 1024,
                    pids=32,
                    network=f"container:aster-lab-{node_role}",
                    cap_add=["NET_ADMIN"],
                    sysctls={},
                    extra_hosts=[],
                    mounts={},
                    network_addresses={},
                    run_id=run_id,
                    role=route_role,
                    input_manifest_sha256=document["build"]["container"][
                        "input_manifest_sha256"
                    ],
                    command=[
                        "route",
                        "replace",
                        "default",
                        "via",
                        "10.250.1.1" if route_role == "route-a" else "10.250.2.1",
                    ],
                ),
            )

        network_receipts = {}
        for network_role in ("lan-a", "wan", "lan-b"):
            network_config = raw_network_config(profile, network_role, run_id)
            network_content = put(
                profile, f"{network_role}-network-config", network_config
            )
            ipam = network_config["IPAM"]["Config"][0]
            members = {
                member["Name"]: member["IPv4Address"]
                for member in network_config["Containers"].values()
            }
            network_receipts[network_role] = {
                "role": network_role,
                "name": network_config["Name"],
                "path": f"{network_config['Name']}-network.json",
                "sha256": hashlib.sha256(network_content).hexdigest(),
                "internal": True,
                "subnet": ipam["Subnet"],
                "gateway": ipam["Gateway"],
                "members": members,
            }

        runtime = {
            "schema": CHECKER.RAW_CONTROLLER_SCHEMA,
            "run_id": run_id,
            "profile": profile,
            "source": source,
            "image": CHECKER.SELECTED_NAT_IMAGE,
            "image_id": document["build"]["container"]["image_id"],
            "binary_inventory": inventory,
            "scope": scope,
            "topic": topic,
            "mission_authority": mission_authority,
            "nodes": manifest_nodes,
            "routers": runtime_routers,
            "route_initializers_removed": True,
            "networks": network_receipts,
            "node_privileges": runtime_privileges,
            "relay": None if profile == "cone-direct" else relay_evidence,
            "relay_privilege": relay_privilege,
            "legacy_ports_4476_4477": False,
        }
        put(profile, "nat-runtime", runtime)
        put(
            profile,
            "cleanup-log",
            {
                "schema": CHECKER.RAW_CONTROLLER_SCHEMA,
                "run_id": run_id,
                "resources": 10 if profile == "cone-direct" else 11,
                "all_owned_resources_removed": True,
                "status": "pass",
            },
        )

        scan = raw_canary_scan(receipt_cell, contents, entry_by_role)
        put(profile, "canary-scan", scan)

        finalization = {
            "schema": CHECKER.RAW_CONTROLLER_SCHEMA,
            "run_id": run_id,
            "profile": profile,
            "status": "pass",
            "manifest_sha256": prepare_digest,
            "event": raw_event,
            "nodes": node_results,
            "nft": nft_evidence,
            "pcap": pcap_summary["routers"],
            "tuple_proof": pcap_summary["proof"],
            "relay": raw_relay,
            "canary_scan": scan,
            "secret_cleanup": cleanup,
            "restricted_state_containment": {
                "schema": CHECKER.RAW_CONTROLLER_SCHEMA,
                "mission_bundle_files": 2,
                "state_files": 2,
                "retained_files": 4,
                "retained_bytes": 4096,
                "owner": "current-runner",
                "file_mode": "0600",
                "directory_mode": "0700",
                "sanitized_manifest": "excluded-external-restricted",
                "encrypted_event_state_retained": True,
                "mission_credentials_retained": True,
                "status": "pass",
            },
            "legacy_ports_4476_4477": False,
            "limitations": list(CHECKER.RAW_CELL_LIMITATIONS),
        }
        finalization_content = put(profile, "nat-finalization", finalization)
        cell_summaries.append(
            {
                "profile": profile,
                "status": "pass",
                "run_id": run_id,
                "path": f"cells/{profile}",
                "source_commit": document["source"]["commit"],
                "source_tree": document["source"]["tree"],
                "image_id": document["build"]["container"]["image_id"],
                "manifest_sha256": prepare_digest,
                "finalization_sha256": hashlib.sha256(
                    finalization_content
                ).hexdigest(),
                "identities": {
                    node: {
                        "carrier_id": receipt_cell["endpoints"][identity_index][
                            "carrier_id"
                        ],
                        "mission_id": receipt_cell["endpoints"][identity_index][
                            "mission_id"
                        ],
                    }
                    for identity_index, node in enumerate(("a", "b"))
                },
            }
        )

    suite_summary = {
        "schema": CHECKER.RAW_CONTROLLER_SCHEMA,
        "status": "pass",
        "profile": "all",
        "cells": cell_summaries,
        "source_commit": document["source"]["commit"],
        "source_tree": document["source"]["tree"],
        "source_identity": source,
        "build_identity": build,
        "image_id": document["build"]["container"]["image_id"],
        "build_input_manifest_sha256": document["build"]["container"][
            "input_manifest_sha256"
        ],
        "build_command_sha256": hashlib.sha256(
            document["build"]["command"].encode("utf-8")
        ).hexdigest(),
        "physical_hosts": 1,
        "namespace_isolation": True,
        "all_resources_removed": True,
        "retained_claim_eligible": True,
    }
    put("global", "suite-summary", suite_summary)

    for entry in entries:
        content = contents[str(entry["path"])]
        entry["bytes"] = len(content)
        entry["sha256"] = hashlib.sha256(content).hexdigest()
    manifest = b"".join(
        f"{entry['sha256']}  {entry['path']}\n".encode("ascii")
        for entry in entries
    )
    raw = document["raw_manifest"]
    raw["records"] = len(entries)
    raw["manifest_bytes"] = len(manifest)
    raw["artifact_bytes"] = sum(int(entry["bytes"]) for entry in entries)
    raw["sha256"] = hashlib.sha256(manifest).hexdigest()
    return contents


def materialize_raw_root(
    root: Path,
    document: dict[str, object],
    *,
    mission_authorities: dict[str, str] | None = None,
    ready_authorities: dict[tuple[str, str], str] | None = None,
) -> None:
    root = root.resolve()
    root.chmod(0o700)
    contents = semantic_raw_artifacts(
        root,
        document,
        mission_authorities=mission_authorities,
        ready_authorities=ready_authorities,
    )
    for relative, content in contents.items():
        path = root / relative
        path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        path.write_bytes(content)
        path.chmod(0o600)
    for profile in CHECKER.CELL_NAMES:
        provision = root / "cells" / profile / "outputs" / "provision"
        restricted_files = {
            provision / "private" / "node-a.bundle": b"a" * 1024,
            provision / "private" / "node-b.bundle": b"b" * 1024,
            provision / "node-a" / "store.redb": b"c" * 1024,
            provision / "node-b" / "store.redb": b"d" * 1024,
        }
        for path, content in restricted_files.items():
            path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
            path.parent.chmod(0o700)
            path.write_bytes(content)
            path.chmod(0o600)
        if profile == "restrictive-relay":
            relay_private = provision / "relay" / "private"
            relay_private.mkdir(mode=0o700, parents=True, exist_ok=True)
            relay_private.chmod(0o700)
    for directory, _names, _files in os.walk(root):
        Path(directory).chmod(0o700)


def refresh_manifest_entry(
    document: dict[str, object], relative_path: str, content: bytes
) -> None:
    entries = document["raw_manifest"]["entries"]
    entry = next(value for value in entries if value["path"] == relative_path)
    entry["bytes"] = len(content)
    entry["sha256"] = hashlib.sha256(content).hexdigest()
    manifest = b"".join(
        f"{value['sha256']}  {value['path']}\n".encode("ascii")
        for value in entries
    )
    raw = document["raw_manifest"]
    raw["manifest_bytes"] = len(manifest)
    raw["artifact_bytes"] = sum(int(value["bytes"]) for value in entries)
    raw["sha256"] = hashlib.sha256(manifest).hexdigest()


def baseline() -> dict[str, object]:
    cells = [cell(name) for name in CHECKER.CELL_NAMES]
    input_manifest_sha256 = digest("container-inputs")
    base_image = CHECKER.LAB_BASE_IMAGE
    build_run_id = "a1b2c3d4e5f60718"
    sealed_context = "/private/tmp/aster-selected-nat/build-context"
    container = {
        "reference": CHECKER.SELECTED_NAT_IMAGE,
        "dockerfile_sha256": digest("Dockerfile"),
        "input_manifest_sha256": input_manifest_sha256,
        "base_image": base_image,
        "build_run_id": build_run_id,
        "image_id": f"sha256:{digest('image-id')}",
        "image_config_digest": f"sha256:{digest('image-id')}",
    }
    build_arguments = [
        "docker",
        "build",
        "--pull=false",
        "--network=default",
        "--no-cache",
        "--load",
        "--progress=plain",
        "--file",
        f"{sealed_context}/lab/Dockerfile.selected-nat",
        "--tag",
        CHECKER.SELECTED_NAT_IMAGE,
        "--label",
        f"{CHECKER.MANAGED_LABEL}=true",
        "--label",
        f"{CHECKER.RUN_LABEL}={build_run_id}",
        "--label",
        f"{CHECKER.IMAGE_SCHEMA_LABEL}={CHECKER.SELECTED_NAT_IMAGE_SCHEMA}",
        "--label",
        f"{CHECKER.IMAGE_INPUT_LABEL}={input_manifest_sha256}",
        "--label",
        f"{CHECKER.IMAGE_BASE_LABEL}={base_image}",
        "--build-arg",
        f"LAB_BASE_IMAGE={base_image}",
        "--iidfile",
        "/private/tmp/aster-selected-nat/image-id.txt",
        "--metadata-file",
        "/private/tmp/aster-selected-nat/build-metadata.json",
        sealed_context,
    ]
    return {
        "schema": CHECKER.SCHEMA,
        "status": "pass",
        "claim": CHECKER.CLAIM,
        "source": {
            "commit": "1" * 40,
            "tree": "2" * 40,
            "signature": "verified",
            "cargo_lock_sha256": digest("Cargo.lock"),
            "requirements_sha256": digest("requirements"),
            "worktree": "clean-tracked-and-untracked-nonignored",
        },
        "build": {
            "command": shlex.join(build_arguments),
            "target": "aarch64-unknown-linux-gnu",
            "artifacts": build_artifacts(),
            "container": container,
        },
        "environment": {
            "physical_hosts": 1,
            "isolation": "docker-linux-network-namespaces",
            "host_os": "Darwin",
            "host_arch": "arm64",
            "kernel": "Linux-6.12.0-orbstack",
            "docker_version": "28.3.3",
            "orbstack_version": "2.4.0",
            "orchestrator_exit_code": 0,
            "cleanup": "pass",
            "clock_assurance": "filesystem-metadata-not-independent",
        },
        "cells": cells,
        "raw_manifest": raw_manifest(cells),
        "limitations": copy.deepcopy(CHECKER.LIMITATIONS),
    }


def canonical(document: dict[str, object]) -> bytes:
    return (
        json.dumps(document, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
        + "\n"
    ).encode("ascii")


class SelectedIrohNatReceiptTests(unittest.TestCase):
    def test_minimum_canonical_receipt_passes(self) -> None:
        document = baseline()
        CHECKER.validate_receipt(document)
        self.assertEqual(document["raw_manifest"]["records"], 99)
        encoded = canonical(document)
        self.assertLess(len(encoded), CHECKER.RECEIPT_MAX_BYTES)
        self.assertNotIn(b"identity.key", encoded)
        self.assertNotIn(b"mesh.redb", encoded)
        self.assertNotIn(b"mission.unprotected", encoded)
        self.assertNotIn(b'"mission_authority"', encoded)
        self.assertNotIn(b"pcapng", encoded)

    def test_raw_command_chronology_rejects_route_capture_and_node_mutations(self) -> None:
        routes = {"route-a": 90, "route-b": 91}
        stderr = {"nat-a": 100, "nat-b": 101, "node-b": 200, "node-a": 201}
        CHECKER.validate_raw_command_chronology(routes, stderr, "chronology")
        mutations = (
            ({"route-a": 300, "route-b": 301}, stderr),
            ({"route-a": 91, "route-b": 90}, stderr),
            (routes, {**stderr, "nat-a": 101, "nat-b": 100}),
            (routes, {**stderr, "node-a": 202}),
        )
        for route_values, stderr_values in mutations:
            with self.subTest(
                routes=route_values, stderr=stderr_values
            ), self.assertRaises(CHECKER.ReceiptViolation):
                CHECKER.validate_raw_command_chronology(
                    route_values, stderr_values, "chronology"
                )

    def test_adversarial_mutation_corpus_fails_closed(self) -> None:
        def remove_restrictive_drop(value: dict[str, object]) -> None:
            counter = value["cells"][1]["nft"]["counters"][0]
            counter["after_packets"] = counter["before_packets"]
            counter["delta_packets"] = 0
            counter["after_bytes"] = counter["before_bytes"]
            counter["delta_bytes"] = 0

        mutations: list[tuple[str, Callable[[dict[str, object]], None]]] = [
            ("extra-top-key", lambda value: value.update({"unexpected": True})),
            ("wrong-schema", lambda value: value.__setitem__("schema", "v0")),
            ("bad-source-hash", lambda value: value["source"].__setitem__("commit", "0")),
            ("dirty-source", lambda value: value["source"].__setitem__("worktree", "dirty")),
            (
                "physical-hosts",
                lambda value: value["environment"].__setitem__("physical_hosts", 2),
            ),
            (
                "bool-as-integer",
                lambda value: value["environment"].__setitem__(
                    "physical_hosts", True
                ),
            ),
            (
                "mutable-image",
                lambda value: value["build"]["container"].__setitem__(
                    "reference", "aster:latest"
                ),
            ),
            (
                "false-offline-build",
                lambda value: value["build"].__setitem__(
                    "command",
                    value["build"]["command"].replace(
                        "--network=default --no-cache", "--network=none"
                    ),
                ),
            ),
            (
                "image-config-mismatch",
                lambda value: value["build"]["container"].__setitem__(
                    "image_config_digest", f"sha256:{digest('different-image')}"
                ),
            ),
            ("missing-helper", lambda value: value["build"]["artifacts"].pop()),
            ("wrong-cell-order", lambda value: value["cells"].reverse()),
            (
                "wrong-fixed-topology",
                lambda value: value["cells"][0]["topology"].__setitem__(
                    "sender_bind", "10.250.1.11:44000"
                ),
            ),
            (
                "duplicate-carrier",
                lambda value: value["cells"][1]["endpoints"][0].__setitem__(
                    "carrier_id", value["cells"][0]["endpoints"][0]["carrier_id"]
                ),
            ),
            (
                "publisher-mismatch",
                lambda value: value["cells"][0]["event"].__setitem__(
                    "publisher", digest("not-sender")
                ),
            ),
            (
                "fabricated-sealed-hash",
                lambda value: value["cells"][0]["event"].__setitem__(
                    "sealed_sha256", digest("fabricated")
                ),
            ),
            (
                "payload-not-canary",
                lambda value: value["cells"][0]["event"].__setitem__(
                    "payload_sha256", digest("not-canary")
                ),
            ),
            (
                "delivery-count",
                lambda value: value["cells"][0]["event"].__setitem__(
                    "destination_deliveries", 2
                ),
            ),
            (
                "nonzero-noop",
                lambda value: value["cells"][0]["reconciliation"].__setitem__(
                    "inserted", 1
                ),
            ),
            (
                "wrong-path",
                lambda value: value["cells"][0]["path"]["witnesses"][0].__setitem__(
                    "selected", "Relay"
                ),
            ),
            (
                "saturated-path",
                lambda value: value["cells"][1]["path"]["witnesses"][1].__setitem__(
                    "transitions_saturated", True
                ),
            ),
            (
                "hosted-discovery",
                lambda value: value["cells"][0]["infrastructure"].__setitem__(
                    "hosted_discovery", True
                ),
            ),
            (
                "wrong-nft-name",
                lambda value: value["cells"][0]["nft"]["counters"][0].__setitem__(
                    "name", "wrong"
                ),
            ),
            (
                "wrong-nft-delta",
                lambda value: value["cells"][0]["nft"]["counters"][0].__setitem__(
                    "delta_packets", 99
                ),
            ),
            (
                "nft-byte-floor",
                lambda value: value["cells"][0]["nft"]["counters"][0].update(
                    {"after_packets": 100, "delta_packets": 100,
                     "after_bytes": 1, "delta_bytes": 1}
                ),
            ),
            ("no-aggregate-direct-drop", remove_restrictive_drop),
            (
                "pcap-drop",
                lambda value: value["cells"][0]["pcap"]["captures"][0].__setitem__(
                    "dropped_packets", 1
                ),
            ),
            (
                "missing-direct-tuple",
                lambda value: value["cells"][0]["pcap"]["tuple_proof"].__setitem__(
                    "direct_cross_nat_packets", 0
                ),
            ),
            (
                "relay-trust",
                lambda value: value["cells"][1]["relay"].__setitem__(
                    "client_trust_mode", "system-roots"
                ),
            ),
            (
                "relay-session-bound",
                lambda value: value["cells"][1]["relay"].__setitem__(
                    "observed_active_sessions_peak", 9
                ),
            ),
            (
                "relay-allowlist-hash",
                lambda value: value["cells"][1]["relay"].__setitem__(
                    "allowlist_sha256", digest("forged-allowlist")
                ),
            ),
            (
                "relay-key-cache",
                lambda value: value["cells"][1]["relay"].__setitem__(
                    "key_cache_capacity", 255
                ),
            ),
            (
                "relay-rate",
                lambda value: value["cells"][1]["relay"].__setitem__(
                    "client_rx_bytes_per_second", 2_097_152
                ),
            ),
            (
                "relay-pre-auth-overclaim",
                lambda value: value["cells"][1]["relay"].__setitem__(
                    "pre_auth_connection_cap", "enforced"
                ),
            ),
            (
                "relay-secret-log",
                lambda value: value["cells"][1]["relay"].__setitem__(
                    "secrets_logged", True
                ),
            ),
            (
                "canary-positive-control",
                lambda value: value["cells"][0]["canary_scan"]["positive_control"].__setitem__(
                    "observed_matches", 0
                ),
            ),
            (
                "canary-match",
                lambda value: value["cells"][1]["canary_scan"].__setitem__(
                    "match_count", 1
                ),
            ),
            (
                "canary-class-match",
                lambda value: value["cells"][0]["canary_scan"][
                    "class_match_counts"
                ].__setitem__("lowercase-hex", 1),
            ),
            (
                "canary-chronology",
                lambda value: value["cells"][0]["canary_scan"][
                    "chronology"
                ].reverse(),
            ),
            (
                "control-file-still-present",
                lambda value: value["cells"][0]["cleanup"].__setitem__(
                    "canary_control_file_absent_after_cleanup", False
                ),
            ),
            (
                "manifest-mode",
                lambda value: value["raw_manifest"]["entries"][0].__setitem__(
                    "mode", "0644"
                ),
            ),
            (
                "manifest-owner",
                lambda value: value["raw_manifest"]["entries"][0].__setitem__(
                    "owner", "root"
                ),
            ),
            (
                "secret-manifest-path",
                lambda value: value["raw_manifest"]["entries"][0].__setitem__(
                    "path", "global/identity.key"
                ),
            ),
            (
                "private-canary-disguised-role",
                lambda value: value["raw_manifest"]["entries"][0].__setitem__(
                    "path", "private/canary.bin"
                ),
            ),
            (
                "manifest-hash",
                lambda value: value["raw_manifest"].__setitem__("sha256", "0" * 64),
            ),
            (
                "impossible-pcap-size",
                lambda value: value["cells"][0]["pcap"]["captures"][0].__setitem__(
                    "bytes", 100
                ),
            ),
            (
                "physical-claim",
                lambda value: value["limitations"].__setitem__("physical_nat", "pass"),
            ),
            (
                "limitation-bool-confusion",
                lambda value: value["limitations"].__setitem__("physical_hosts", True),
            ),
        ]
        for name, mutate in mutations:
            with self.subTest(name=name):
                document = baseline()
                mutate(document)
                with self.assertRaises(CHECKER.ReceiptViolation):
                    CHECKER.validate_receipt(document)

    def test_pcap_manifest_metadata_mismatch_fails(self) -> None:
        document = baseline()
        capture = document["cells"][0]["pcap"]["captures"][0]
        capture["bytes"] += 1
        with self.assertRaisesRegex(CHECKER.ReceiptViolation, "packet capture metadata"):
            CHECKER.validate_receipt(document)

    def test_public_cone_nft_requires_opposite_one_sided_nat_hooks(self) -> None:
        mutations = {
            "both-hooks-positive": (
                ("nat-a", "aster_cone_dnat", 1),
                ("nat-b", "aster_cone_dnat", 0),
            ),
            "both-zero": (
                ("nat-a", "aster_cone_snat", 0),
                ("nat-b", "aster_cone_dnat", 0),
            ),
            "inactive-nonzero": (("nat-a", "aster_cone_dnat", 1),),
            "higher-carrier-router-snat": (
                ("nat-a", "aster_cone_snat", 0),
                ("nat-a", "aster_cone_dnat", 1),
                ("nat-b", "aster_cone_dnat", 0),
                ("nat-b", "aster_cone_snat", 1),
            ),
            "missing-forward-direction": (
                ("nat-b", "aster_cone_forward_out", 0),
            ),
        }
        for name, changes in mutations.items():
            with self.subTest(name=name):
                document = baseline()
                receipt_cell = document["cells"][0]
                for router, counter_name, packets in changes:
                    set_nft_counter_packets(
                        receipt_cell, router, counter_name, packets
                    )
                with self.assertRaises(CHECKER.ReceiptViolation):
                    CHECKER.validate_receipt(document)

    def test_raw_cone_nft_hooks_follow_the_contact_derived_initiator(self) -> None:
        receipt_cell = baseline()["cells"][0]
        summary = raw_pcap_summary(receipt_cell)

        def finalization_for(cell: dict[str, object]) -> dict[str, object]:
            return {
                "nft": {
                    router: raw_nft_evidence(cell, router)
                    for router in ("nat-a", "nat-b")
                }
            }

        CHECKER.validate_raw_nft_pcap_binding(
            summary,
            finalization_for(receipt_cell),
            receipt_cell,
            "canonical.nft",
            cone_initiator_router="nat-a",
        )

        swapped = copy.deepcopy(receipt_cell)
        set_nft_counter_packets(swapped, "nat-a", "aster_cone_snat", 0)
        set_nft_counter_packets(swapped, "nat-a", "aster_cone_dnat", 1)
        set_nft_counter_packets(swapped, "nat-b", "aster_cone_dnat", 0)
        set_nft_counter_packets(swapped, "nat-b", "aster_cone_snat", 1)
        with self.assertRaisesRegex(
            CHECKER.ReceiptViolation, "lower-carrier-ID router"
        ):
            CHECKER.validate_nft(
                swapped["nft"],
                "cone-direct",
                cone_initiator_router="nat-a",
            )
        with self.assertRaisesRegex(CHECKER.ReceiptViolation, "CONTACT-matched"):
            CHECKER.validate_raw_nft_pcap_binding(
                summary,
                finalization_for(swapped),
                swapped,
                "swapped.nft",
                cone_initiator_router="nat-a",
            )

        inactive = copy.deepcopy(receipt_cell)
        set_nft_counter_packets(inactive, "nat-a", "aster_cone_dnat", 1)
        with self.assertRaisesRegex(CHECKER.ReceiptViolation, "opposite CONTACT"):
            CHECKER.validate_raw_nft_pcap_binding(
                summary,
                finalization_for(inactive),
                inactive,
                "inactive.nft",
                cone_initiator_router="nat-a",
            )

    def test_raw_cone_contact_directions_require_one_paired_initiator(self) -> None:
        outbound = [{"direction": "out"}, {"direction": "out"}]
        inbound = [{"direction": "in"}, {"direction": "in"}]
        node_a_lower = {"node-a": "1" * 64, "node-b": "f" * 64}
        node_b_lower = {"node-a": "f" * 64, "node-b": "1" * 64}
        self.assertEqual(
            CHECKER.raw_cone_initiator_router(
                {"node-a": outbound, "node-b": inbound},
                node_a_lower,
                "contacts",
            ),
            "nat-a",
        )
        self.assertEqual(
            CHECKER.raw_cone_initiator_router(
                {"node-a": inbound, "node-b": outbound},
                node_b_lower,
                "contacts",
            ),
            "nat-b",
        )
        mutations = {
            "mixed-direction": {
                "node-a": [{"direction": "out"}, {"direction": "in"}],
                "node-b": inbound,
            },
            "empty-responder": {
                "node-a": outbound,
                "node-b": [],
            },
            "both-out": {"node-a": outbound, "node-b": outbound},
        }
        for name, contacts in mutations.items():
            with self.subTest(name=name), self.assertRaises(
                CHECKER.ReceiptViolation
            ):
                CHECKER.raw_cone_initiator_router(
                    contacts, node_a_lower, "contacts"
                )
        with self.assertRaisesRegex(
            CHECKER.ReceiptViolation, "lower carrier identity"
        ):
            CHECKER.raw_cone_initiator_router(
                {"node-a": inbound, "node-b": outbound},
                node_a_lower,
                "contacts",
            )

    def test_raw_pcap_rejects_unexpected_wan_tuple(self) -> None:
        receipt_cell = baseline()["cells"][0]
        summary = raw_pcap_summary(receipt_cell)
        metadata_mutations = {
            "missing-role": lambda value: value["routers"]["nat-a"].pop("role"),
            "wrong-role": lambda value: value["routers"]["nat-a"].__setitem__(
                "role", "nat-b"
            ),
            "missing-path": lambda value: value["routers"]["nat-a"].pop("path"),
            "wrong-path": lambda value: value["routers"]["nat-a"].__setitem__(
                "path", "outputs/nat-b/nat-b-wan.pcap"
            ),
            "unexpected-field": lambda value: value["routers"]["nat-a"].__setitem__(
                "unexpected_private_material", "redacted"
            ),
        }
        for name, mutate in metadata_mutations.items():
            with self.subTest(name=name):
                mutated = raw_pcap_summary(receipt_cell)
                mutate(mutated)
                mutated_finalization = {
                    "pcap": copy.deepcopy(mutated["routers"]),
                    "tuple_proof": copy.deepcopy(mutated["proof"]),
                }
                with self.assertRaises(CHECKER.ReceiptViolation):
                    CHECKER.validate_raw_pcap_summary(
                        mutated,
                        mutated_finalization,
                        receipt_cell,
                        f"{name}.pcap",
                    )
        summary["routers"]["nat-a"]["tuples"][0]["destination"] = "10.250.0.99"
        finalization = {
            "pcap": summary["routers"],
            "tuple_proof": summary["proof"],
        }
        with self.assertRaisesRegex(CHECKER.ReceiptViolation, "tuple allowlist"):
            CHECKER.validate_raw_pcap_summary(
                summary, finalization, receipt_cell, "mutated.pcap"
            )

        missing = raw_pcap_summary(receipt_cell)
        missing["routers"]["nat-a"]["tuples"] = []
        missing_finalization = {
            "pcap": missing["routers"],
            "tuple_proof": missing["proof"],
        }
        with self.assertRaisesRegex(CHECKER.ReceiptViolation, "accounting is not lossless"):
            CHECKER.validate_raw_pcap_summary(
                missing, missing_finalization, receipt_cell, "missing.pcap"
            )

        restrictive_cell = baseline()["cells"][1]
        wrong_server_port = raw_pcap_summary(restrictive_cell)
        first = wrong_server_port["routers"]["nat-a"]["tuples"][0]
        first["source_port"] = 8443
        first["destination_port"] = 49152
        wrong_finalization = {
            "pcap": wrong_server_port["routers"],
            "tuple_proof": wrong_server_port["proof"],
        }
        with self.assertRaisesRegex(CHECKER.ReceiptViolation, "tuple allowlist"):
            CHECKER.validate_raw_pcap_summary(
                wrong_server_port,
                wrong_finalization,
                restrictive_cell,
                "wrong-server-port.pcap",
            )

    def test_tcpdump_terminal_receipts_are_exact_complete_and_role_bound(self) -> None:
        for profile, packets in (("cone-direct", 6), ("restrictive-relay", 9)):
            with self.subTest(profile=profile):
                content = raw_command_stderr_content(profile, 2)
                self.assertEqual(
                    content,
                    (
                        f"{packets} packets captured\n"
                        f"{packets} packets received by filter\n"
                        "0 packets dropped by kernel\n"
                    ).encode("ascii"),
                )
                CHECKER.validate_tcpdump_terminal_receipt(
                    (
                        "tcpdump: listening on eth1, link-type EN10MB "
                        "(Ethernet), snapshot length 262144 bytes\n"
                    )
                    + content.decode("ascii"),
                    f"fixture.{profile}",
                    expected_packets=packets,
                )

        mutations = {
            "counter-mismatch": (
                b"5 packets captured\n"
                b"6 packets received by filter\n"
                b"0 packets dropped by kernel\n"
            ),
            "kernel-drop": (
                b"6 packets captured\n"
                b"6 packets received by filter\n"
                b"1 packets dropped by kernel\n"
            ),
            "receipt-count-mismatch": (
                b"5 packets captured\n"
                b"5 packets received by filter\n"
                b"0 packets dropped by kernel\n"
            ),
            "missing": (
                b"6 packets captured\n"
                b"0 packets dropped by kernel\n"
            ),
            "duplicate": (
                b"6 packets captured\n"
                b"6 packets captured\n"
                b"6 packets received by filter\n"
                b"0 packets dropped by kernel\n"
            ),
            "noncanonical": (
                b"06 packets captured\n"
                b"6 packets received by filter\n"
                b"0 packets dropped by kernel\n"
            ),
        }
        for name, content in mutations.items():
            with self.subTest(name=name), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary).resolve()
                document = baseline()
                materialize_raw_root(root, document)
                profile = "cone-direct"
                relative = f"cells/{profile}/command-0100.stderr"
                path = root / relative
                path.write_bytes(content)
                path.chmod(0o600)
                digest_value = hashlib.sha256(content).hexdigest()
                scan = json.loads(
                    (root / f"cells/{profile}/canary-scan.json").read_text(
                        encoding="utf-8"
                    )
                )
                scan_file = next(
                    value
                    for value in scan["artifact_classes"][1]["files"]
                    if value["path"] == "command-0100.stderr"
                )
                scan_file["bytes"] = len(content)
                scan_file["sha256"] = digest_value
                finalization = json.loads(
                    (
                        root
                        / f"cells/{profile}/selected-nat-finalization.json"
                    ).read_text(encoding="utf-8")
                )
                finalization["pcap"]["nat-a"][
                    "tcpdump_stderr_sha256"
                ] = digest_value
                root_descriptor, _opened = CHECKER.open_raw_root(root)
                try:
                    with self.assertRaisesRegex(
                        CHECKER.ReceiptViolation, "tcpdump"
                    ):
                        CHECKER.validate_raw_canary_scan(
                            root_descriptor,
                            scan,
                            document["cells"][0],
                            f"mutated.{name}",
                            CHECKER.manifest_entries_by_role(document),
                            finalization,
                            {"route-a": 90, "route-b": 91},
                        )
                finally:
                    os.close(root_descriptor)

    def test_nft_packet_counters_are_directionally_bound_to_pcap(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            document = baseline()
            materialize_raw_root(root, document)
            profile = "cone-direct"
            finalization_path = root / "cells" / profile / "selected-nat-finalization.json"
            snapshot_path = root / "cells" / profile / "nat-a-nft-after.json"
            finalization = json.loads(finalization_path.read_text(encoding="utf-8"))
            snapshot = json.loads(snapshot_path.read_text(encoding="utf-8"))
            for authority in (
                finalization["nft"]["nat-a"]["after"]["aster_cone_forward_out"],
                finalization["nft"]["nat-a"]["delta"]["aster_cone_forward_out"],
                snapshot["counters"]["aster_cone_forward_out"],
            ):
                authority["packets"] = 3
                authority["bytes"] = 384
            counter = next(
                value
                for value in document["cells"][0]["nft"]["counters"]
                if value["router"] == "nat-a"
                and value["name"] == "aster_cone_forward_out"
            )
            counter.update(
                {
                    "after_packets": 3,
                    "delta_packets": 3,
                    "after_bytes": 384,
                    "delta_bytes": 384,
                }
            )
            finalization_content = raw_json(finalization)
            snapshot_content = raw_json(snapshot)
            finalization_path.write_bytes(finalization_content)
            snapshot_path.write_bytes(snapshot_content)
            finalization_path.chmod(0o600)
            snapshot_path.chmod(0o600)
            refresh_manifest_entry(
                document,
                f"cells/{profile}/selected-nat-finalization.json",
                finalization_content,
            )
            refresh_manifest_entry(
                document,
                f"cells/{profile}/nat-a-nft-after.json",
                snapshot_content,
            )
            suite_path = root / "selected-nat-suite.json"
            suite = json.loads(suite_path.read_text(encoding="utf-8"))
            suite["cells"][0]["finalization_sha256"] = hashlib.sha256(
                finalization_content
            ).hexdigest()
            suite_content = raw_json(suite)
            suite_path.write_bytes(suite_content)
            suite_path.chmod(0o600)
            refresh_manifest_entry(document, "selected-nat-suite.json", suite_content)
            CHECKER.validate_receipt(document)
            with self.assertRaisesRegex(CHECKER.ReceiptViolation, "packet/pcap"):
                CHECKER.verify_raw_root(root, document)

    def test_pcap_cap_accepts_128_mib_and_rejects_one_byte_more(self) -> None:
        for size, accepted in (
            (CHECKER.MAX_PCAP_BYTES, True),
            (CHECKER.MAX_PCAP_BYTES + 1, False),
        ):
            with self.subTest(size=size):
                document = baseline()
                capture = document["cells"][0]["pcap"]["captures"][0]
                capture["bytes"] = size
                entry = next(
                    item
                    for item in document["raw_manifest"]["entries"]
                    if item["cell"] == "cone-direct"
                    and item["role"] == "nat-a-wan-pcap"
                )
                entry["bytes"] = size
                document["raw_manifest"]["artifact_bytes"] = sum(
                    int(item["bytes"])
                    for item in document["raw_manifest"]["entries"]
                )
                if accepted:
                    CHECKER.validate_receipt(document)
                else:
                    with self.assertRaises(CHECKER.ReceiptViolation):
                        CHECKER.validate_receipt(document)

    def test_public_relay_certificates_are_exact_valid_x509_authorities(self) -> None:
        ca = CHECKER.validate_x509_der(
            test_certificate_der("ca"), role="ca", label="fixture.ca"
        )
        server = CHECKER.validate_x509_der(
            test_certificate_der("server"), role="server", label="fixture.server"
        )
        CHECKER.verify_p256_signature(
            ca["public_key"], ca["tbs"], ca["signature"], "fixture CA"
        )
        CHECKER.verify_p256_signature(
            ca["public_key"], server["tbs"], server["signature"], "fixture server"
        )
        malformed = (
            test_certificate_der("server").replace(
                b"relay.aster.test", b"xelay.aster.test", 1
            ),
            test_certificate_der("server") + b"\x00",
            bytes.fromhex("3010020100300506032b6570030400010203"),
        )
        for index, content in enumerate(malformed):
            with self.subTest(index=index), self.assertRaises(CHECKER.ReceiptViolation):
                CHECKER.validate_x509_der(
                    content, role="server", label=f"malformed.server.{index}"
                )

    def test_rcgen_serial_canonicalization_strips_masked_leading_zero(self) -> None:
        public_point = next(
            value.to_bytes(4, "big")
            for value in range(100_000)
            if hashlib.sha256(value.to_bytes(4, "big")).digest()[0] & 0x7F == 0
        )
        raw = bytearray(hashlib.sha256(public_point).digest()[:20])
        raw[0] &= 0x7F
        expected = bytes(raw).lstrip(b"\x00") or b"\x00"
        self.assertLess(len(expected), 20)
        self.assertEqual(CHECKER.rcgen_serial_bytes(public_point), expected)

    def test_duplicate_json_key_fails_before_schema_validation(self) -> None:
        encoded = canonical(baseline())
        duplicate = encoded.replace(
            b'"status":"pass"',
            b'"status":"pass","status":"pass"',
            1,
        )
        with tempfile.TemporaryDirectory() as temporary:
            retained = Path(temporary) / "receipt.json"
            retained.write_bytes(duplicate)
            with self.assertRaisesRegex(CHECKER.ReceiptViolation, "duplicate"):
                CHECKER.load_receipt(retained)

    def test_noncanonical_json_fails(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            retained = Path(temporary) / "receipt.json"
            retained.write_text(json.dumps(baseline(), indent=2) + "\n", encoding="utf-8")
            with self.assertRaisesRegex(CHECKER.ReceiptViolation, "canonical JSON"):
                CHECKER.load_receipt(retained)

    def test_receipt_byte_cap_fails_before_json_parsing(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            retained = Path(temporary) / "receipt.json"
            retained.write_bytes(b"x" * (CHECKER.RECEIPT_MAX_BYTES + 1))
            with self.assertRaisesRegex(CHECKER.ReceiptViolation, "byte cap"):
                CHECKER.load_receipt(retained)

    def test_plain_canonical_file_loads_and_validates(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            retained = Path(temporary) / "receipt.json"
            retained.write_bytes(canonical(baseline()))
            document = CHECKER.load_receipt(retained)
            CHECKER.validate_receipt(document)

    def test_raw_root_replay_and_adversarial_filesystem_mutations(self) -> None:
        def corrupt(path: Path, root: Path) -> None:
            content = path.read_bytes()
            path.write_bytes(bytes([content[0] ^ 1]) + content[1:])

        def truncate(path: Path, root: Path) -> None:
            path.write_bytes(path.read_bytes()[:-1])

        def remove(path: Path, root: Path) -> None:
            path.unlink()

        def overpermissive(path: Path, root: Path) -> None:
            path.chmod(0o644)

        def hard_link(path: Path, root: Path) -> None:
            os.link(path, root / "unexpected-hard-link")

        def symbolic_link(path: Path, root: Path) -> None:
            target = root / "selected-nat-suite.json"
            path.unlink()
            path.symlink_to(target)

        def retained_canary(path: Path, root: Path) -> None:
            target = (
                root
                / "cells/cone-direct/outputs/provision/private/canary.bin"
            )
            target.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
            target.write_bytes(b"x" * 32)
            target.chmod(0o600)

        def retained_relay_key(path: Path, root: Path) -> None:
            target = (
                root
                / "cells/restrictive-relay/outputs/provision/relay/private"
                / "server.key.pkcs8.der"
            )
            target.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
            target.write_bytes(b"x" * 64)
            target.chmod(0o600)

        def retained_cone_relay_key(path: Path, root: Path) -> None:
            target = (
                root
                / "cells/cone-direct/outputs/provision/relay/private"
                / "server.key.pkcs8.der"
            )
            target.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
            target.write_bytes(b"x" * 64)
            target.chmod(0o600)

        def unsafe_parent_mode(path: Path, root: Path) -> None:
            (root / "cells/cone-direct").chmod(0o777)

        def symbolic_parent(path: Path, root: Path) -> None:
            parent = root / "cells/cone-direct/outputs/nat-a"
            replacement = parent.with_name("nat-a-real")
            parent.rename(replacement)
            parent.symlink_to(replacement.name, target_is_directory=True)

        def unsafe_root_mode(path: Path, root: Path) -> None:
            root.chmod(0o755)

        for name, mutate in (
            ("corrupt", corrupt),
            ("truncate", truncate),
            ("missing", remove),
            ("mode", overpermissive),
            ("hard-link", hard_link),
            ("symbolic-link", symbolic_link),
            ("retained-canary", retained_canary),
            ("retained-relay-key", retained_relay_key),
            ("retained-cone-relay-key", retained_cone_relay_key),
            ("unsafe-parent-mode", unsafe_parent_mode),
            ("symbolic-parent", symbolic_parent),
            ("unsafe-root-mode", unsafe_root_mode),
        ):
            with self.subTest(name=name), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary).resolve()
                document = baseline()
                materialize_raw_root(root, document)
                CHECKER.validate_receipt(document)
                CHECKER.verify_raw_root(root, document)
                first = root / document["raw_manifest"]["entries"][0]["path"]
                mutate(first, root)
                with self.assertRaises(CHECKER.ReceiptViolation):
                    CHECKER.verify_raw_root(root, document)

    def test_mission_authority_adversarial_matrix_fails_closed(self) -> None:
        for mode in (
            "manifest-missing",
            "manifest-malformed",
            "manifest-uppercase",
            "manifest-duplicate-field",
            "manifest-v1",
            "manifest-endpoint-domain-collision",
            "prepare-mismatch",
            "prepare-shared-false",
            "prepare-disjoint-false",
            "both-ready-coherent-mismatch",
            "one-node-divergence",
            "cross-cell-reuse",
        ):
            with self.subTest(mode=mode), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary).resolve()
                document = baseline()
                mission_authorities: dict[str, str] | None = None
                ready_authorities: dict[tuple[str, str], str] | None = None
                artifact_mutation: tuple[str, str, bytes, bytes] | None = None
                authority = digest("cone-direct-mission-authority")
                authority_field = b"\tmission_authority=" + authority.encode("ascii")
                if mode == "manifest-missing":
                    artifact_mutation = (
                        "cone-direct",
                        "prepare-manifest",
                        authority_field,
                        b"",
                    )
                elif mode == "manifest-malformed":
                    artifact_mutation = (
                        "cone-direct",
                        "prepare-manifest",
                        authority.encode("ascii"),
                        b"z" * 64,
                    )
                elif mode == "manifest-uppercase":
                    artifact_mutation = (
                        "cone-direct",
                        "prepare-manifest",
                        authority.encode("ascii"),
                        authority.upper().encode("ascii"),
                    )
                elif mode == "manifest-duplicate-field":
                    artifact_mutation = (
                        "cone-direct",
                        "prepare-manifest",
                        authority_field,
                        authority_field + authority_field,
                    )
                elif mode == "manifest-v1":
                    artifact_mutation = (
                        "cone-direct",
                        "prepare-manifest",
                        b"ASTER_SELECTED_NAT_MANIFEST\tversion=2\t",
                        b"ASTER_SELECTED_NAT_MANIFEST\tversion=1\t",
                    )
                elif mode == "manifest-endpoint-domain-collision":
                    mission_authorities = {
                        "cone-direct": str(
                            document["cells"][0]["endpoints"][0]["mission_id"]
                        )
                    }
                elif mode == "prepare-mismatch":
                    artifact_mutation = (
                        "cone-direct",
                        "prepare-log",
                        authority.encode("ascii"),
                        digest("forged-prepare-mission-authority").encode("ascii"),
                    )
                elif mode == "prepare-shared-false":
                    artifact_mutation = (
                        "cone-direct",
                        "prepare-log",
                        b"mission_authority_shared=true",
                        b"mission_authority_shared=false",
                    )
                elif mode == "prepare-disjoint-false":
                    artifact_mutation = (
                        "cone-direct",
                        "prepare-log",
                        b"mission_authority_disjoint=true",
                        b"mission_authority_disjoint=false",
                    )
                elif mode == "both-ready-coherent-mismatch":
                    live = digest("forged-cone-live-mission-authority")
                    ready_authorities = {
                        ("cone-direct", role): live
                        for role in ("node-a", "node-b")
                    }
                elif mode == "one-node-divergence":
                    ready_authorities = {
                        ("cone-direct", "node-a"): digest(
                            "forged-cone-node-a-mission-authority"
                        )
                    }
                elif mode == "cross-cell-reuse":
                    shared = digest("forged-shared-mission-authority")
                    mission_authorities = {
                        profile: shared for profile in CHECKER.CELL_NAMES
                    }
                materialize_raw_root(
                    root,
                    document,
                    mission_authorities=mission_authorities,
                    ready_authorities=ready_authorities,
                )
                if artifact_mutation is not None:
                    profile, role, old, new = artifact_mutation
                    entry = next(
                        value
                        for value in document["raw_manifest"]["entries"]
                        if value["cell"] == profile and value["role"] == role
                    )
                    path = root / str(entry["path"])
                    content = path.read_bytes()
                    if content.count(old) != 1:
                        raise AssertionError(
                            f"authority fixture lacks exact {mode} mutation target"
                        )
                    changed = content.replace(old, new)
                    path.write_bytes(changed)
                    path.chmod(0o600)
                    refresh_manifest_entry(document, str(entry["path"]), changed)
                CHECKER.validate_receipt(document)
                with self.assertRaises(CHECKER.ReceiptViolation):
                    CHECKER.verify_raw_root(root, document)

    def test_clean_node_stderr_is_empty_and_diagnostics_fail(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            document = baseline()
            materialize_raw_root(root, document)
            CHECKER.validate_receipt(document)
            CHECKER.verify_raw_root(root, document)
            for sequence in (200, 201):
                path = root / f"cells/cone-direct/command-{sequence:04d}.stderr"
                self.assertEqual(path.read_bytes(), b"")
                self.assertEqual(path.stat().st_mode & 0o777, 0o600)
            diagnostic = root / "cells/cone-direct/command-0201.stderr"
            diagnostic.write_bytes(b"CONTACT direction=out status=error\n")
            diagnostic.chmod(0o600)
            with self.assertRaises(CHECKER.ReceiptViolation):
                CHECKER.verify_raw_root(root, document)

    def test_restricted_state_metadata_mutations_fail_closed(self) -> None:
        def missing(root: Path) -> None:
            (root / "cells/cone-direct/outputs/provision/private/node-a.bundle").unlink()

        def mode(root: Path) -> None:
            (root / "cells/cone-direct/outputs/provision/node-a/store.redb").chmod(
                0o644
            )

        def hard_link(root: Path) -> None:
            source = root / "cells/cone-direct/outputs/provision/private/node-a.bundle"
            os.link(source, source.with_name("unexpected.bundle"))

        def symbolic(root: Path) -> None:
            source = root / "cells/cone-direct/outputs/provision/node-a/store.redb"
            source.unlink()
            source.symlink_to("../node-b/store.redb")

        def extra_state(root: Path) -> None:
            target = root / "cells/cone-direct/outputs/provision/node-a/extra.redb"
            target.write_bytes(b"x")
            target.chmod(0o600)

        for name, mutate in (
            ("missing", missing),
            ("mode", mode),
            ("hard-link", hard_link),
            ("symbolic", symbolic),
            ("count", extra_state),
        ):
            with self.subTest(name=name), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary).resolve()
                document = baseline()
                materialize_raw_root(root, document)
                mutate(root)
                with self.assertRaises(CHECKER.ReceiptViolation):
                    CHECKER.verify_raw_root(root, document)

    def test_manifest_to_semantic_read_races_fail_closed(self) -> None:
        original = CHECKER.validate_raw_semantics
        for mode in ("in-place", "replacement"):
            with self.subTest(mode=mode), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary).resolve()
                document = baseline()
                materialize_raw_root(root, document)
                summary = root / "selected-nat-suite.json"

                def mutate_then_validate(
                    root_descriptor: int,
                    checked_root: Path,
                    checked_document: dict[str, object],
                    **kwargs: object,
                ) -> object:
                    original_bytes = summary.read_bytes()
                    changed = original_bytes.replace(
                        b'"status": "pass"', b'"status": "fail"', 1
                    )
                    self.assertEqual(len(changed), len(original_bytes))
                    if mode == "in-place":
                        with summary.open("r+b") as stream:
                            stream.seek(0)
                            stream.write(changed)
                            stream.flush()
                            os.fsync(stream.fileno())
                    else:
                        replacement = root / "summary-replacement"
                        replacement.write_bytes(changed)
                        replacement.chmod(0o600)
                        os.replace(replacement, summary)
                    return original(
                        root_descriptor, checked_root, checked_document, **kwargs
                    )

                with mock.patch.object(
                    CHECKER, "validate_raw_semantics", side_effect=mutate_then_validate
                ):
                    with self.assertRaises(CHECKER.ReceiptViolation):
                        CHECKER.verify_raw_root(root, document)

    def test_final_opaque_evidence_reverification_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            document = baseline()
            materialize_raw_root(root, document)
            original = CHECKER.validate_raw_semantics
            ca_path = (
                root
                / "cells"
                / "restrictive-relay"
                / "outputs"
                / "provision"
                / "relay"
                / "ca.der"
            )

            def validate_then_mutate(
                root_descriptor: int,
                checked_root: Path,
                checked_document: dict[str, object],
                **kwargs: object,
            ) -> object:
                authorities = original(
                    root_descriptor, checked_root, checked_document, **kwargs
                )
                content = bytearray(ca_path.read_bytes())
                content[0] ^= 0x01
                ca_path.write_bytes(content)
                ca_path.chmod(0o600)
                return authorities

            with mock.patch.object(
                CHECKER, "validate_raw_semantics", side_effect=validate_then_mutate
            ):
                with self.assertRaises(CHECKER.ReceiptViolation):
                    CHECKER.verify_raw_root(root, document)

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            document = baseline()
            materialize_raw_root(root, document)
            capture = root / "cells/cone-direct/command-0100.stderr"
            self.assertGreater(capture.stat().st_size, 0)
            capture.write_bytes(b"")
            capture.chmod(0o600)
            with self.assertRaises(CHECKER.ReceiptViolation):
                CHECKER.verify_raw_root(root, document)

    def test_terminal_tcpdump_receipt_is_reparsed_after_semantics(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            document = baseline()
            materialize_raw_root(root, document)
            original = CHECKER.validate_raw_semantics
            relative = "cells/cone-direct/command-0100.stderr"
            target = root / relative
            noncanonical = (
                b"06 packets captured\n"
                b"6 packets received by filter\n"
                b"0 packets dropped by kernel\n"
            )

            def validate_then_mutate(
                root_descriptor: int,
                checked_root: Path,
                checked_document: dict[str, object],
                **kwargs: object,
            ) -> object:
                stderr_authorities, containments = original(
                    root_descriptor, checked_root, checked_document, **kwargs
                )
                target.write_bytes(noncanonical)
                target.chmod(0o600)
                authority = stderr_authorities[relative]
                authority["bytes"] = len(noncanonical)
                authority["sha256"] = hashlib.sha256(noncanonical).hexdigest()
                return stderr_authorities, containments

            with mock.patch.object(
                CHECKER, "validate_raw_semantics", side_effect=validate_then_mutate
            ):
                with self.assertRaisesRegex(CHECKER.ReceiptViolation, "tcpdump"):
                    CHECKER.verify_raw_root(root, document)

    def test_terminal_unretained_and_cleanup_rechecks_fail_closed(self) -> None:
        for mode in ("node-stderr", "capture-stderr", "canary", "relay-key"):
            with self.subTest(mode=mode), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary).resolve()
                document = baseline()
                materialize_raw_root(root, document)
                original = CHECKER.validate_raw_semantics

                def validate_then_mutate(
                    root_descriptor: int,
                    checked_root: Path,
                    checked_document: dict[str, object],
                    **kwargs: object,
                ) -> object:
                    authorities = original(
                        root_descriptor, checked_root, checked_document, **kwargs
                    )
                    if mode == "node-stderr":
                        target = root / "cells/cone-direct/command-0201.stderr"
                        target.write_bytes(b"diagnostic=post-semantic\n")
                    elif mode == "capture-stderr":
                        target = root / "cells/cone-direct/command-0100.stderr"
                        target.write_bytes(b"1 packets dropped by kernel\n")
                    elif mode == "canary":
                        target = (
                            root
                            / "cells/cone-direct/outputs/provision/private/canary.bin"
                        )
                        target.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
                        target.write_bytes(b"x" * 32)
                    else:
                        target = (
                            root
                            / "cells/restrictive-relay/outputs/provision/relay/private"
                            / "server.key.pkcs8.der"
                        )
                        target.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
                        target.write_bytes(b"x" * 64)
                    target.chmod(0o600)
                    return authorities

                with mock.patch.object(
                    CHECKER,
                    "validate_raw_semantics",
                    side_effect=validate_then_mutate,
                ):
                    with self.assertRaises(CHECKER.ReceiptViolation):
                        CHECKER.verify_raw_root(root, document)

    def test_cli_requires_and_replays_raw_root(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            document = baseline()
            materialize_raw_root(root, document)
            receipt = root / "selected-iroh-nat-receipt.json"
            receipt.write_bytes(canonical(document))
            receipt.chmod(0o600)
            output = io.StringIO()
            source_authority = {
                "commit": document["source"]["commit"],
                "tree": document["source"]["tree"],
                "cargo_toml_sha256": digest("Cargo.toml"),
                "cargo_lock_sha256": document["source"]["cargo_lock_sha256"],
                "requirements_sha256": document["source"]["requirements_sha256"],
                "dockerfile_sha256": document["build"]["container"][
                    "dockerfile_sha256"
                ],
                "build_input_manifest_sha256": document["build"]["container"][
                    "input_manifest_sha256"
                ],
            }
            with contextlib.redirect_stdout(output), mock.patch.object(
                CHECKER, "verify_source_checkout", return_value=source_authority
            ):
                CHECKER.main(
                    [
                        "--raw-root",
                        str(root),
                        "--source",
                        "/workspace/aster",
                        str(receipt),
                    ]
                )
            self.assertIn("receipt passed", output.getvalue())

    def test_independent_source_reconstruction_binds_immutable_objects(self) -> None:
        document = baseline()
        contents = {
            ".dockerignore": CHECKER.EXPECTED_DOCKERIGNORE.encode("utf-8"),
            "Cargo.toml": b"[workspace]\nmembers=[]\n",
            "Cargo.lock": b"version = 4\n",
            "LICENSE": b"test license\n",
            "lab/Dockerfile": b"FROM scratch\n",
            "lab/Dockerfile.selected-nat": b"FROM scratch\n",
            "lab/Dockerfile.dockerignore": CHECKER.EXPECTED_DOCKERIGNORE.encode(
                "utf-8"
            ),
            "lab/debian.sources": b"Types: deb\n",
            "data-mesh-requirements.md": b"# requirements\n",
        }
        object_ids = {
            path: hashlib.sha1(
                f"blob {len(content)}\0".encode("ascii") + content
            ).hexdigest()
            for path, content in contents.items()
        }
        tree, tree_objects, tree_paths = git_tree_fixture(object_ids)
        commit_content = (
            f"tree {tree}\nauthor Fixture <fixture@example.test> 0 +0000\n"
            "committer Fixture <fixture@example.test> 0 +0000\n"
            "gpgsig -----BEGIN SSH SIGNATURE-----\n fixture\n"
            " -----END SSH SIGNATURE-----\n\nfixture\n"
        ).encode("ascii")
        commit = hashlib.sha1(
            f"commit {len(commit_content)}\0".encode("ascii") + commit_content
        ).hexdigest()
        build_paths = sorted(set(contents) - {"data-mesh-requirements.md"})
        input_document = {
            "dockerignore_sha256": hashlib.sha256(
                CHECKER.EXPECTED_DOCKERIGNORE.encode("utf-8")
            ).hexdigest(),
            "files": [
                {
                    "path": path,
                    "bytes": len(contents[path]),
                    "sha256": hashlib.sha256(contents[path]).hexdigest(),
                }
                for path in build_paths
            ],
        }
        input_digest = hashlib.sha256(
            json.dumps(input_document, sort_keys=True, separators=(",", ":")).encode(
                "utf-8"
            )
        ).hexdigest()
        document["source"].update(
            {
                "commit": commit,
                "tree": tree,
                "cargo_lock_sha256": hashlib.sha256(contents["Cargo.lock"]).hexdigest(),
                "requirements_sha256": hashlib.sha256(
                    contents["data-mesh-requirements.md"]
                ).hexdigest(),
            }
        )
        document["build"]["container"].update(
            {
                "dockerfile_sha256": hashlib.sha256(
                    contents["lab/Dockerfile.selected-nat"]
                ).hexdigest(),
                "input_manifest_sha256": input_digest,
            }
        )
        by_object = {object_ids[path]: content for path, content in contents.items()}

        def source_git(
            _git: str,
            _source: Path,
            arguments: list[str],
            _label: str,
            **_kwargs: object,
        ) -> bytes:
            if arguments[:2] == ["cat-file", "commit"]:
                return commit_content
            if arguments[:1] == ["verify-commit"]:
                return b""
            if arguments[:2] == ["cat-file", "tree"]:
                return tree_objects[arguments[2]]
            if arguments[:2] == ["cat-file", "-s"]:
                return str(len(by_object[arguments[2]])).encode("ascii") + b"\n"
            if arguments[:2] == ["cat-file", "blob"]:
                return by_object[arguments[2]]
            raise AssertionError(f"unexpected Git plumbing call: {arguments!r}")

        with tempfile.TemporaryDirectory() as temporary, mock.patch.object(
            CHECKER.shutil, "which", return_value="/usr/bin/git"
        ), mock.patch.object(
            CHECKER,
            "reviewer_signature_options",
            return_value=["-c", "gpg.format=ssh"],
        ), mock.patch.object(
            CHECKER, "run_source_git", side_effect=source_git
        ) as source_git_mock:
            authority = CHECKER.verify_source_checkout(Path(temporary).resolve(), document)
            self.assertEqual(authority["commit"], commit)
            self.assertEqual(authority["build_input_manifest_sha256"], input_digest)

            forged = copy.deepcopy(document)
            forged["source"]["commit"] = "0" * 40
            with self.assertRaises(CHECKER.ReceiptViolation):
                CHECKER.verify_source_checkout(Path(temporary).resolve(), forged)

            intermediate = tree_paths["lab"]

            def substituted_tree(
                git: str,
                source: Path,
                arguments: list[str],
                label: str,
                **kwargs: object,
            ) -> bytes:
                if arguments == ["cat-file", "tree", intermediate]:
                    return tree_objects[intermediate] + b"x"
                return source_git(git, source, arguments, label, **kwargs)

            source_git_mock.side_effect = substituted_tree
            with self.assertRaisesRegex(
                CHECKER.ReceiptViolation, "immutable descendant tree"
            ):
                CHECKER.verify_source_checkout(Path(temporary).resolve(), document)
            source_git_mock.side_effect = source_git

            forged = copy.deepcopy(document)
            forged["build"]["container"]["input_manifest_sha256"] = digest(
                "coherently-forged-input-manifest"
            )
            with self.assertRaises(CHECKER.ReceiptViolation):
                CHECKER.verify_source_checkout(Path(temporary).resolve(), forged)

    def test_source_git_disables_replacements_and_untrusted_global_config(self) -> None:
        completed = mock.Mock(returncode=0, stdout=b"ok", stderr=b"")
        injected = {
            "GIT_DIR": "/attacker/git-dir",
            "GIT_WORK_TREE": "/attacker/work-tree",
            "GIT_COMMON_DIR": "/attacker/common",
            "GIT_OBJECT_DIRECTORY": "/attacker/objects",
            "GIT_ALTERNATE_OBJECT_DIRECTORIES": "/attacker/alternate",
            "GIT_INDEX_FILE": "/attacker/index",
            "GIT_NAMESPACE": "attacker",
            "GIT_CONFIG_PARAMETERS": "'gpg.ssh.program'='/attacker/verifier'",
            "GIT_CONFIG_COUNT": "1",
            "GIT_CONFIG_KEY_0": "gpg.ssh.program",
            "GIT_CONFIG_VALUE_0": "/attacker/verifier",
        }
        with mock.patch.dict(CHECKER.os.environ, injected), mock.patch.object(
            CHECKER.subprocess, "run", return_value=completed
        ) as run:
            output = CHECKER.run_source_git(
                "/usr/bin/git",
                Path("/private/tmp/source"),
                ["cat-file", "commit", "a" * 40],
                "replacement-resistant commit",
                trusted_options=["-c", "gpg.format=ssh"],
            )
        self.assertEqual(output, b"ok")
        command = run.call_args.args[0]
        environment = run.call_args.kwargs["env"]
        self.assertIn("--no-replace-objects", command)
        self.assertEqual(environment["GIT_NO_REPLACE_OBJECTS"], "1")
        self.assertEqual(environment["GIT_CONFIG_NOSYSTEM"], "1")
        self.assertEqual(environment["GIT_CONFIG_GLOBAL"], os.devnull)
        for variable in (
            "GIT_DIR",
            "GIT_WORK_TREE",
            "GIT_COMMON_DIR",
            "GIT_OBJECT_DIRECTORY",
            "GIT_ALTERNATE_OBJECT_DIRECTORIES",
            "GIT_INDEX_FILE",
            "GIT_NAMESPACE",
            "GIT_CONFIG_PARAMETERS",
            "GIT_CONFIG_COUNT",
        ):
            self.assertNotIn(variable, environment)

    def test_independent_source_review_caps_committed_input_count(self) -> None:
        document = baseline()
        object_ids = {
            f"crates/cap/file-{index:04d}": "1" * 40
            for index in range(CHECKER.MAX_COMMITTED_INPUTS + 1)
        }
        tree, tree_objects, _tree_paths = git_tree_fixture(object_ids)
        commit_content = (
            f"tree {tree}\nauthor Fixture <fixture@example.test> 0 +0000\n"
            "committer Fixture <fixture@example.test> 0 +0000\n"
            "gpgsig -----BEGIN SSH SIGNATURE-----\n fixture\n"
            " -----END SSH SIGNATURE-----\n\nfixture\n"
        ).encode("ascii")
        commit = hashlib.sha1(
            f"commit {len(commit_content)}\0".encode("ascii") + commit_content
        ).hexdigest()
        document["source"]["commit"] = commit
        document["source"]["tree"] = tree
        def source_git(
            _git: str,
            _source: Path,
            arguments: list[str],
            _label: str,
            **_kwargs: object,
        ) -> bytes:
            if arguments[:2] == ["cat-file", "commit"]:
                return commit_content
            if arguments[:1] == ["verify-commit"]:
                return b""
            if arguments[:2] == ["cat-file", "tree"]:
                return tree_objects[arguments[2]]
            raise AssertionError("blob subprocess work began before the input-count cap")

        with tempfile.TemporaryDirectory() as temporary, mock.patch.object(
            CHECKER.shutil, "which", return_value="/usr/bin/git"
        ), mock.patch.object(
            CHECKER,
            "reviewer_signature_options",
            return_value=["-c", "gpg.format=ssh"],
        ), mock.patch.object(CHECKER, "run_source_git", side_effect=source_git):
            with self.assertRaisesRegex(CHECKER.ReceiptViolation, "count exceeds"):
                CHECKER.verify_source_checkout(Path(temporary).resolve(), document)

    def test_openpgp_signature_program_is_pinned_at_command_precedence(self) -> None:
        completed = mock.Mock(returncode=0, stdout=b"openpgp\n", stderr=b"")
        with tempfile.TemporaryDirectory() as temporary:
            reviewer_home = Path(temporary).resolve()
            global_config = reviewer_home / ".gitconfig"
            global_config.write_text("[gpg]\n\tformat = openpgp\n", encoding="utf-8")
            global_config.chmod(0o600)
            with mock.patch.object(
                CHECKER.Path, "home", return_value=reviewer_home
            ), mock.patch.object(
                CHECKER.subprocess, "run", return_value=completed
            ), mock.patch.object(
                CHECKER.shutil, "which", return_value="/usr/bin/gpg"
            ):
                options = CHECKER.reviewer_signature_options("/usr/bin/git")
        self.assertIn("gpg.format=openpgp", options)
        self.assertIn("gpg.program=/usr/bin/gpg", options)
        self.assertIn("gpg.openpgp.program=/usr/bin/gpg", options)
        self.assertIn("gpg.minTrustLevel=fully", options)

    def test_receipt_provenance_falsifications_fail_raw_replay(self) -> None:
        def mutate_input(value: dict[str, object]) -> None:
            old = value["build"]["container"]["input_manifest_sha256"]
            new = digest("forged-input-manifest")
            value["build"]["container"]["input_manifest_sha256"] = new
            value["build"]["command"] = value["build"]["command"].replace(old, new)

        def mutate_image(value: dict[str, object]) -> None:
            forged = f"sha256:{digest('forged-image')}"
            value["build"]["container"]["image_id"] = forged
            value["build"]["container"]["image_config_digest"] = forged

        def mutate_command(value: dict[str, object]) -> None:
            value["build"]["command"] = value["build"]["command"].replace(
                "/private/tmp/aster-selected-nat",
                "/private/tmp/forged-selected-nat",
            )

        def mutate_event(value: dict[str, object]) -> None:
            forged = digest("forged-cone-canary")
            value["cells"][0]["event"]["payload_sha256"] = forged
            value["cells"][0]["event"]["canary_sha256"] = forged

        def mutate_tuple(value: dict[str, object]) -> None:
            proof = value["cells"][0]["pcap"]["tuple_proof"]
            proof["direct_cross_nat_packets"] = 10
            proof["direct_probe_packets"] = 10

        def mutate_nft(value: dict[str, object]) -> None:
            counter = next(
                candidate
                for candidate in value["cells"][0]["nft"]["counters"]
                if candidate["router"] == "nat-a"
                and candidate["name"] == "aster_cone_snat"
            )
            counter["after_packets"] += 1
            counter["delta_packets"] += 1
            counter["after_bytes"] += 128
            counter["delta_bytes"] += 128

        mutations: list[tuple[str, Callable[[dict[str, object]], None]]] = [
            ("commit", lambda value: value["source"].__setitem__("commit", "3" * 40)),
            ("tree", lambda value: value["source"].__setitem__("tree", "4" * 40)),
            (
                "cargo-lock",
                lambda value: value["source"].__setitem__(
                    "cargo_lock_sha256", digest("forged-lock")
                ),
            ),
            (
                "requirements",
                lambda value: value["source"].__setitem__(
                    "requirements_sha256", digest("forged-requirements")
                ),
            ),
            (
                "dockerfile",
                lambda value: value["build"]["container"].__setitem__(
                    "dockerfile_sha256", digest("forged-dockerfile")
                ),
            ),
            ("build-input", mutate_input),
            ("build-command", mutate_command),
            (
                "artifact",
                lambda value: value["build"]["artifacts"][0].__setitem__(
                    "sha256", digest("forged-aster")
                ),
            ),
            ("image", mutate_image),
            (
                "kernel",
                lambda value: value["environment"].__setitem__(
                    "kernel", "Linux-6.12.99-orbstack"
                ),
            ),
            (
                "docker-version",
                lambda value: value["environment"].__setitem__(
                    "docker_version", "28.3.4"
                ),
            ),
            ("event-canary", mutate_event),
            ("pcap-tuples", mutate_tuple),
            ("nft-counter", mutate_nft),
            (
                "relay-sessions",
                lambda value: value["cells"][1]["relay"].__setitem__(
                    "accepted_sessions", 3
                ),
            ),
        ]
        for name, mutate in mutations:
            with self.subTest(name=name), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary).resolve()
                document = baseline()
                materialize_raw_root(root, document)
                CHECKER.validate_receipt(document)
                CHECKER.verify_raw_root(root, document)
                mutate(document)
                CHECKER.validate_receipt(document)
                with self.assertRaises(CHECKER.ReceiptViolation):
                    CHECKER.verify_raw_root(root, document)

    def test_duplicate_key_in_curated_summary_fails_after_hash_refresh(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            document = baseline()
            materialize_raw_root(root, document)
            summary = root / "selected-nat-suite.json"
            content = summary.read_bytes().replace(
                b'  "status": "pass"\n}',
                b'  "status": "pass",\n  "status": "pass"\n}',
                1,
            )
            self.assertNotEqual(content, summary.read_bytes())
            summary.write_bytes(content)
            summary.chmod(0o600)
            refresh_manifest_entry(document, "selected-nat-suite.json", content)
            CHECKER.validate_receipt(document)
            with self.assertRaisesRegex(CHECKER.ReceiptViolation, "duplicate"):
                CHECKER.verify_raw_root(root, document)

    def test_semantic_summary_mutation_fails_after_hash_refresh(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            document = baseline()
            materialize_raw_root(root, document)
            summary_path = root / "selected-nat-suite.json"
            summary = json.loads(summary_path.read_text(encoding="utf-8"))
            summary["build_identity"]["environment"]["kernel"] = (
                "Linux-6.12.99-orbstack"
            )
            content = raw_json(summary)
            summary_path.write_bytes(content)
            summary_path.chmod(0o600)
            refresh_manifest_entry(document, "selected-nat-suite.json", content)
            CHECKER.validate_receipt(document)
            with self.assertRaises(CHECKER.ReceiptViolation):
                CHECKER.verify_raw_root(root, document)

    def test_controlled_summary_extra_fields_fail_after_hash_refresh(self) -> None:
        mutations = (
            lambda value: value.__setitem__(
                "unexpected_private_material", "redacted"
            ),
            lambda value: value["cells"][0].__setitem__(
                "unexpected_private_material", "redacted"
            ),
            lambda value: value["build_identity"]["environment"].__setitem__(
                "unexpected_private_material", "redacted"
            ),
        )
        for index, mutate in enumerate(mutations):
            with self.subTest(index=index), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary).resolve()
                document = baseline()
                materialize_raw_root(root, document)
                summary_path = root / "selected-nat-suite.json"
                summary = json.loads(summary_path.read_text(encoding="utf-8"))
                mutate(summary)
                content = raw_json(summary)
                summary_path.write_bytes(content)
                summary_path.chmod(0o600)
                refresh_manifest_entry(document, "selected-nat-suite.json", content)
                CHECKER.validate_receipt(document)
                with self.assertRaises(CHECKER.ReceiptViolation):
                    CHECKER.verify_raw_root(root, document)

    def test_curated_authority_mutations_fail_after_hash_refresh(self) -> None:
        def mutate_json(
            transform: Callable[[dict[str, object]], None]
        ) -> Callable[[bytes], bytes]:
            def apply(content: bytes) -> bytes:
                value = json.loads(content.decode("utf-8"))
                transform(value)
                return raw_json(value)

            return apply

        def replace(old: bytes, new: bytes) -> Callable[[bytes], bytes]:
            def apply(content: bytes) -> bytes:
                changed = content.replace(old, new, 1)
                if changed == content:
                    raise AssertionError(f"fixture lacks mutation token {old!r}")
                return changed

            return apply

        def reverse_receipt_lines(content: bytes) -> bytes:
            lines = content.removesuffix(b"\n").split(b"\n")
            return b"\n".join(reversed(lines)) + b"\n"

        def append_diagnostic_line(content: bytes) -> bytes:
            return content + b"DIAGNOSTIC unexpected=true\n"

        def reorder_prepare_lines(content: bytes) -> bytes:
            lines = content.removesuffix(b"\n").split(b"\n")
            if len(lines) != 3:
                raise AssertionError("fixture prepare log lacks three lines")
            return b"\n".join([lines[1], lines[0], lines[2]]) + b"\n"

        def reorder_prepare_manifest_rows(content: bytes) -> bytes:
            lines = content.removesuffix(b"\n").split(b"\n")
            if len(lines) != 4:
                raise AssertionError("fixture prepare manifest lacks four lines")
            return b"\n".join([lines[0], lines[1], lines[3], lines[2]]) + b"\n"

        def mutate_event_field(content: bytes) -> bytes:
            records = [json.loads(line) for line in content.splitlines()]
            records[0]["unexpected_private_material"] = "redacted"
            return (
                "\n".join(
                    json.dumps(record, sort_keys=True, separators=(",", ":"))
                    for record in records
                )
                + "\n"
            ).encode("ascii")

        def swap_node_stderr_scan_rows(content: bytes) -> bytes:
            value = json.loads(content.decode("utf-8"))
            files = value["artifact_classes"][1]["files"]
            files[4], files[6] = files[6], files[4]
            return raw_json(value)

        def reorder_events(content: bytes) -> bytes:
            lines = content.removesuffix(b"\n").split(b"\n")
            lines[0], lines[1] = lines[1], lines[0]
            return b"\n".join(lines) + b"\n"

        def mutate_mount_source(
            destination: str, old_suffix: str, new_suffix: str
        ) -> Callable[[bytes], bytes]:
            def transform(value: dict[str, object]) -> None:
                mounts = value["Mounts"]
                mount = next(
                    item for item in mounts if item["Destination"] == destination
                )
                source = str(mount["Source"])
                if not source.endswith(old_suffix):
                    raise AssertionError("fixture mount source suffix differs")
                mount["Source"] = source[: -len(old_suffix)] + new_suffix

            return mutate_json(transform)

        def mutate_mount_read_write(
            destination: str, read_write: bool
        ) -> Callable[[bytes], bytes]:
            def transform(value: dict[str, object]) -> None:
                mounts = value["Mounts"]
                mount = next(
                    item for item in mounts if item["Destination"] == destination
                )
                mount["RW"] = read_write

            return mutate_json(transform)

        def mutate_mount_destination(
            old_destination: str, new_destination: str
        ) -> Callable[[bytes], bytes]:
            def transform(value: dict[str, object]) -> None:
                mounts = value["Mounts"]
                mount = next(
                    item
                    for item in mounts
                    if item["Destination"] == old_destination
                )
                mount["Destination"] = new_destination

            return mutate_json(transform)

        def replace_exact_bytes(old: bytes, new: bytes) -> Callable[[bytes], bytes]:
            def transform(content: bytes) -> bytes:
                if content.count(old) != 1:
                    raise AssertionError("fixture replacement target is not exact")
                return content.replace(old, new)

            return transform

        def mutate_node_transcript(mode: str) -> Callable[[bytes], bytes]:
            def apply(content: bytes) -> bytes:
                text = content.decode("utf-8")
                stdout_marker = "ASTER_SELECTED_NAT_TRANSCRIPT version=1 stream=stdout\n"
                stderr_marker = "ASTER_SELECTED_NAT_TRANSCRIPT version=1 stream=stderr\n"
                if not text.startswith(stdout_marker) or text.count(stderr_marker) != 1:
                    raise AssertionError("fixture lacks canonical node transcript")
                stdout, stderr = text[len(stdout_marker) :].split(stderr_marker, 1)
                lines = stdout.splitlines()
                if len(lines) < 4 or stderr:
                    raise AssertionError("fixture lacks source-shaped clean node streams")
                ready, contacts, stop = lines[0], lines[1:-1], lines[-1]
                if mode == "contact-to-stderr":
                    lines, stderr = [ready, *contacts[:-1], stop], contacts[-1] + "\n"
                elif mode == "diagnostic-stderr":
                    stderr = "diagnostic=unexpected\n"
                elif mode == "missing-ready":
                    lines = [*contacts, stop]
                elif mode == "reordered":
                    lines = [stop, *contacts, ready]
                elif mode == "duplicate-ready":
                    lines = [ready, ready, *contacts, stop]
                elif mode == "duplicate-stop":
                    lines = [ready, *contacts, stop, stop]
                elif mode == "contact-error":
                    lines = [
                        ready,
                        contacts[0].replace("status=pass", "status=error"),
                        *contacts[1:],
                        stop,
                    ]
                elif mode == "stdout-extra":
                    lines = [ready, "DIAGNOSTIC unexpected=true", *contacts, stop]
                elif mode == "ready-extra-field":
                    lines = [
                        ready + " unexpected_private_material=redacted",
                        *contacts,
                        stop,
                    ]
                elif mode == "ready-extra-socket":
                    lines = [
                        ready.replace(
                            "sockets=10.250.1.10:44000",
                            "sockets=10.250.1.10:44000,203.0.113.9:53",
                        ),
                        *contacts,
                        stop,
                    ]
                elif mode == "ready-state-rebased":
                    lines = [
                        ready.replace("state=/output/node-a", "state=/output"),
                        *contacts,
                        stop,
                    ]
                elif mode == "handshake-frame-count":
                    lines = [
                        ready,
                        contacts[0].replace(
                            "handshake_frames=4", "handshake_frames=5"
                        ),
                        *contacts[1:],
                        stop,
                    ]
                elif mode == "protected-frame-parity":
                    lines = [
                        ready,
                        contacts[0].replace(
                            "protected_frames=100", "protected_frames=99"
                        ),
                        *contacts[1:],
                        stop,
                    ]
                elif mode == "round-frame-bound":
                    lines = [
                        ready,
                        contacts[0].replace("rounds=18", "rounds=51"),
                        *contacts[1:],
                        stop,
                    ]
                elif mode == "transfer-wrong-role":
                    transferred = contacts[0].replace("offered=1", "offered=0")
                    transferred = transferred.replace("fetched=0", "fetched=1")
                    transferred = transferred.replace("inserted=0", "inserted=1")
                    lines = [ready, transferred, *contacts[1:], stop]
                elif mode == "transfer-only":
                    single_stop = stop.replace(" contacts=2 ", " contacts=1 ")
                    single_stop = single_stop.replace(
                        " direct_contacts=2 ", " direct_contacts=1 "
                    )
                    lines = [ready, contacts[0], single_stop]
                elif mode == "stop-contact-errors":
                    lines = [
                        ready,
                        *contacts,
                        stop.replace(" contact_errors=0 ", " contact_errors=1 "),
                    ]
                elif mode == "stop-transition-mismatch":
                    lines = [
                        ready,
                        *contacts,
                        stop.replace(
                            "carrier_path_transitions=1",
                            "carrier_path_transitions=2",
                        ),
                    ]
                elif mode == "stop-transition-omitted":
                    lines = [
                        ready,
                        *contacts,
                        stop.replace(" carrier_path_transitions=1", ""),
                    ]
                else:
                    raise AssertionError(f"unknown transcript mutation {mode}")
                return (
                    stdout_marker + "\n".join(lines) + "\n" + stderr_marker + stderr
                ).encode("utf-8")

            return apply

        cases: list[tuple[str, str, str, Callable[[bytes], bytes]]] = [
            (
                "controller-resource-order",
                "cone-direct",
                "controller-receipt",
                mutate_json(
                    lambda value: value["resources"].__setitem__(
                        slice(0, 2), list(reversed(value["resources"][:2]))
                    )
                ),
            ),
            (
                "scenario-public-internet",
                "cone-direct",
                "scenario-receipt",
                mutate_json(
                    lambda value: value.__setitem__("public_internet", True)
                ),
            ),
            (
                "scenario-unexpected-field",
                "cone-direct",
                "scenario-receipt",
                mutate_json(
                    lambda value: value.__setitem__(
                        "unexpected_private_material", "redacted"
                    )
                ),
            ),
            (
                "events-unexpected-field",
                "cone-direct",
                "events",
                mutate_event_field,
            ),
            (
                "events-reordered",
                "cone-direct",
                "events",
                reorder_events,
            ),
            (
                "events-extra-line",
                "cone-direct",
                "events",
                lambda content: content + content.splitlines(keepends=True)[-1],
            ),
            (
                "node-root-user",
                "cone-direct",
                "node-a-config",
                mutate_json(lambda value: value["Config"].__setitem__("User", "0:0")),
            ),
            (
                "node-privileged",
                "cone-direct",
                "node-a-config",
                mutate_json(
                    lambda value: value["HostConfig"].__setitem__("Privileged", True)
                ),
            ),
            (
                "node-disabled-no-new-privileges",
                "cone-direct",
                "node-a-config",
                mutate_json(
                    lambda value: value["HostConfig"].__setitem__(
                        "SecurityOpt", ["no-new-privileges:false"]
                    )
                ),
            ),
            (
                "node-extra-security-option",
                "cone-direct",
                "node-a-config",
                mutate_json(
                    lambda value: value["HostConfig"]["SecurityOpt"].append(
                        "seccomp=unconfined"
                    )
                ),
            ),
            (
                "node-init-disabled",
                "cone-direct",
                "node-a-config",
                mutate_json(
                    lambda value: value["HostConfig"].__setitem__("Init", False)
                ),
            ),
            (
                "node-host-device",
                "cone-direct",
                "node-a-config",
                mutate_json(
                    lambda value: value["HostConfig"]["Devices"].append(
                        {
                            "PathOnHost": "/dev/null",
                            "PathInContainer": "/dev/escape",
                            "CgroupPermissions": "rwm",
                        }
                    )
                ),
            ),
            (
                "node-host-pid-namespace",
                "cone-direct",
                "node-a-config",
                mutate_json(
                    lambda value: value["HostConfig"].__setitem__(
                        "PidMode", "host"
                    )
                ),
            ),
            (
                "node-nofile-weakened",
                "cone-direct",
                "node-a-config",
                mutate_json(
                    lambda value: value["HostConfig"].__setitem__("Ulimits", [])
                ),
            ),
            (
                "node-executable-tmpfs",
                "cone-direct",
                "node-a-config",
                mutate_json(
                    lambda value: value["HostConfig"]["Tmpfs"].__setitem__(
                        "/tmp", "rw,nosuid,nodev,size=32m"
                    )
                ),
            ),
            (
                "node-missing-image-label",
                "cone-direct",
                "node-a-config",
                mutate_json(
                    lambda value: value["Config"]["Labels"].pop(
                        CHECKER.IMAGE_INPUT_LABEL
                    )
                ),
            ),
            (
                "node-mutated-image-label",
                "cone-direct",
                "node-a-config",
                mutate_json(
                    lambda value: value["Config"]["Labels"].__setitem__(
                        CHECKER.IMAGE_BASE_LABEL, "rust@sha256:" + "0" * 64
                    )
                ),
            ),
            (
                "node-missing-base-source-label",
                "cone-direct",
                "node-a-config",
                mutate_json(
                    lambda value: value["Config"]["Labels"].pop(
                        CHECKER.BASE_IMAGE_SOURCE_LABEL
                    )
                ),
            ),
            (
                "node-mutated-base-source-label",
                "cone-direct",
                "node-a-config",
                mutate_json(
                    lambda value: value["Config"]["Labels"].__setitem__(
                        CHECKER.BASE_IMAGE_SOURCE_LABEL,
                        "https://invalid.example/base",
                    )
                ),
            ),
            (
                "node-extra-label",
                "cone-direct",
                "node-a-config",
                mutate_json(
                    lambda value: value["Config"]["Labels"].__setitem__(
                        "unexpected.private.material", "redacted"
                    )
                ),
            ),
            (
                "node-secret-shaped-extra-env",
                "cone-direct",
                "node-a-config",
                mutate_json(
                    lambda value: value["Config"]["Env"].append(
                        "CANARY=" + "ab" * 32
                    )
                ),
            ),
            (
                "image-unexpected-env",
                "cone-direct",
                "image-identity",
                mutate_json(
                    lambda value: value["env"].append("KEY=public-looking-value")
                ),
            ),
            (
                "image-missing-base-source-label",
                "cone-direct",
                "image-identity",
                mutate_json(
                    lambda value: value["labels"].pop(
                        CHECKER.BASE_IMAGE_SOURCE_LABEL
                    )
                ),
            ),
            (
                "image-mutated-base-source-label",
                "cone-direct",
                "image-identity",
                mutate_json(
                    lambda value: value["labels"].__setitem__(
                        CHECKER.BASE_IMAGE_SOURCE_LABEL,
                        "https://invalid.example/base",
                    )
                ),
            ),
            (
                "image-unexpected-label",
                "cone-direct",
                "image-identity",
                mutate_json(
                    lambda value: value["labels"].__setitem__(
                        "unexpected.private.material", "redacted"
                    )
                ),
            ),
            (
                "image-foreign-repository-digest",
                "cone-direct",
                "image-identity",
                mutate_json(
                    lambda value: value.__setitem__(
                        "repo_digests", ["foreign@sha256:" + "0" * 64]
                    )
                ),
            ),
            (
                "node-extra-network-attachment",
                "cone-direct",
                "node-a-config",
                mutate_json(
                    lambda value: value["NetworkSettings"]["Networks"].__setitem__(
                        "bridge", {"IPAddress": "172.17.0.2"}
                    )
                ),
            ),
            (
                "node-output-source-swapped",
                "cone-direct",
                "node-a-config",
                mutate_mount_source(
                    "/output/node-a",
                    "/outputs/provision/node-a",
                    "/outputs/provision/node-b",
                ),
            ),
            (
                "node-state-destination-rebased",
                "cone-direct",
                "node-a-config",
                mutate_mount_destination("/output/node-a", "/output"),
            ),
            (
                "node-state-destination-swapped",
                "cone-direct",
                "node-a-config",
                mutate_mount_destination("/output/node-a", "/output/node-b"),
            ),
            (
                "node-ready-state-swapped",
                "cone-direct",
                "node-a-log",
                replace_exact_bytes(b"state=/output/node-a", b"state=/output/node-b"),
            ),
            (
                "node-b-ready-state-rebased",
                "cone-direct",
                "node-b-log",
                replace_exact_bytes(b"state=/output/node-b", b"state=/output"),
            ),
            (
                "node-bundle-source-swapped",
                "cone-direct",
                "node-a-config",
                mutate_mount_source(
                    "/run/secrets/node.bundle",
                    "/outputs/provision/private/node-a.bundle",
                    "/outputs/provision/private/node-b.bundle",
                ),
            ),
            (
                "node-bundle-read-only",
                "cone-direct",
                "node-a-config",
                mutate_mount_read_write("/run/secrets/node.bundle", False),
            ),
            (
                "node-effective-capability",
                "cone-direct",
                "node-a-runtime-privilege",
                mutate_json(lambda value: value.__setitem__("cap_effective", 1)),
            ),
            (
                "node-unexpected-cap-add",
                "cone-direct",
                "node-a-config",
                mutate_json(
                    lambda value: value["HostConfig"].__setitem__(
                        "CapAdd", ["CAP_NET_ADMIN"]
                    )
                ),
            ),
            (
                "node-missing-cap-add-field",
                "cone-direct",
                "node-a-config",
                mutate_json(lambda value: value["HostConfig"].pop("CapAdd")),
            ),
            (
                "node-duplicate-cap-drop",
                "cone-direct",
                "node-a-config",
                mutate_json(
                    lambda value: value["HostConfig"]["CapDrop"].append("ALL")
                ),
            ),
            (
                "router-capability",
                "cone-direct",
                "nat-a-config",
                mutate_json(lambda value: value["HostConfig"].__setitem__("CapAdd", [])),
            ),
            (
                "router-capability-order",
                "cone-direct",
                "nat-a-config",
                mutate_json(
                    lambda value: value["HostConfig"]["CapAdd"].reverse()
                ),
            ),
            (
                "router-capability-unprefixed",
                "cone-direct",
                "nat-a-config",
                mutate_json(
                    lambda value: value["HostConfig"].__setitem__(
                        "CapAdd", ["NET_ADMIN", "NET_RAW", "SETUID", "SETGID"]
                    )
                ),
            ),
            (
                "router-capability-extra",
                "cone-direct",
                "nat-a-config",
                mutate_json(
                    lambda value: value["HostConfig"]["CapAdd"].append(
                        "CAP_SYS_ADMIN"
                    )
                ),
            ),
            (
                "router-output-source-swapped",
                "cone-direct",
                "nat-a-config",
                mutate_mount_source(
                    "/output", "/outputs/nat-a", "/outputs/nat-b"
                ),
            ),
            (
                "route-network-target",
                "cone-direct",
                "route-a-config",
                mutate_json(
                    lambda value: value["HostConfig"].__setitem__(
                        "NetworkMode", "bridge"
                    )
                ),
            ),
            (
                "route-unexpected-network-attachment",
                "cone-direct",
                "route-a-config",
                mutate_json(
                    lambda value: value["NetworkSettings"]["Networks"].__setitem__(
                        "bridge", {"IPAddress": "172.17.0.2"}
                    )
                ),
            ),
            (
                "route-duplicate-cap-add",
                "cone-direct",
                "route-a-config",
                mutate_json(
                    lambda value: value["HostConfig"]["CapAdd"].append(
                        "CAP_NET_ADMIN"
                    )
                ),
            ),
            (
                "route-unprefixed-cap-add",
                "cone-direct",
                "route-a-config",
                mutate_json(
                    lambda value: value["HostConfig"].__setitem__(
                        "CapAdd", ["NET_ADMIN"]
                    )
                ),
            ),
            (
                "route-nonzero-exit",
                "cone-direct",
                "route-init-removal",
                mutate_json(lambda value: value[0].__setitem__("exit_code", 1)),
            ),
            (
                "route-unexpected-field",
                "cone-direct",
                "route-init-removal",
                mutate_json(
                    lambda value: value[0].__setitem__(
                        "unexpected_private_material", "redacted"
                    )
                ),
            ),
            (
                "route-missing-dev",
                "cone-direct",
                "route-init-removal",
                mutate_json(lambda value: value[0]["route"].pop("dev")),
            ),
            (
                "route-wrong-dev",
                "cone-direct",
                "route-init-removal",
                mutate_json(
                    lambda value: value[0]["route"].__setitem__("dev", "eth1")
                ),
            ),
            (
                "route-missing-flags",
                "cone-direct",
                "route-init-removal",
                mutate_json(lambda value: value[0]["route"].pop("flags")),
            ),
            (
                "route-nonempty-flags",
                "cone-direct",
                "route-init-removal",
                mutate_json(
                    lambda value: value[0]["route"].__setitem__(
                        "flags", ["onlink"]
                    )
                ),
            ),
            (
                "route-flags-wrong-type",
                "cone-direct",
                "route-init-removal",
                mutate_json(
                    lambda value: value[0]["route"].__setitem__("flags", {})
                ),
            ),
            (
                "route-nested-unexpected-field",
                "cone-direct",
                "route-init-removal",
                mutate_json(
                    lambda value: value[0]["route"].__setitem__(
                        "unexpected_private_material", "redacted"
                    )
                ),
            ),
            (
                "route-log-name",
                "cone-direct",
                "route-init-removal",
                mutate_json(
                    lambda value: value[0].__setitem__(
                        "log", "reap-aster-lab-route-a.log"
                    )
                ),
            ),
            (
                "route-log-after-capture-start",
                "cone-direct",
                "route-init-removal",
                mutate_json(
                    lambda value: value[1].__setitem__(
                        "log", "reap-aster-lab-route-b-command-0150.log"
                    )
                ),
            ),
            (
                "route-log-order-swapped",
                "cone-direct",
                "route-init-removal",
                mutate_json(
                    lambda value: value[0].__setitem__(
                        "log", "reap-aster-lab-route-a-command-0092.log"
                    )
                ),
            ),
            (
                "route-log-nonempty-hash",
                "cone-direct",
                "route-init-removal",
                mutate_json(
                    lambda value: value[0].__setitem__(
                        "log_sha256", digest("nonempty-route-log")
                    )
                ),
            ),
            (
                "provisioner-network",
                "cone-direct",
                "provision-prepare-config",
                mutate_json(
                    lambda value: value["HostConfig"].__setitem__(
                        "NetworkMode", "default"
                    )
                ),
            ),
            (
                "provisioner-empty-cap-add",
                "cone-direct",
                "provision-prepare-config",
                mutate_json(
                    lambda value: value["HostConfig"].__setitem__("CapAdd", [])
                ),
            ),
            (
                "provisioner-missing-cap-add-field",
                "cone-direct",
                "provision-prepare-config",
                mutate_json(lambda value: value["HostConfig"].pop("CapAdd")),
            ),
            (
                "provisioner-unexpected-cap-add",
                "cone-direct",
                "provision-prepare-config",
                mutate_json(
                    lambda value: value["HostConfig"].__setitem__(
                        "CapAdd", ["CAP_NET_ADMIN"]
                    )
                ),
            ),
            (
                "provisioner-missing-none-attachment",
                "cone-direct",
                "provision-prepare-config",
                mutate_json(
                    lambda value: value["NetworkSettings"]["Networks"].pop("none")
                ),
            ),
            (
                "provisioner-extra-network-attachment",
                "cone-direct",
                "provision-prepare-config",
                mutate_json(
                    lambda value: value["NetworkSettings"]["Networks"].__setitem__(
                        "bridge", {"IPAddress": "172.17.0.2"}
                    )
                ),
            ),
            (
                "provisioner-output-source-swapped",
                "cone-direct",
                "provision-prepare-config",
                mutate_mount_source(
                    "/output", "/outputs/provision", "/outputs/nat-a"
                ),
            ),
            (
                "external-network",
                "cone-direct",
                "wan-network-config",
                mutate_json(lambda value: value.__setitem__("Internal", False)),
            ),
            (
                "nft-policy",
                "cone-direct",
                "nat-a-nft-program",
                replace(b"policy drop;", b"policy accept;"),
            ),
            (
                "node-transcript-path",
                "cone-direct",
                "node-a-log",
                replace(b"carrier_path=direct", b"carrier_path=relay"),
            ),
            *[
                (
                    f"node-transcript-{mode}",
                    "cone-direct",
                    "node-a-log",
                    mutate_node_transcript(mode),
                )
                for mode in (
                    "contact-to-stderr",
                    "diagnostic-stderr",
                    "missing-ready",
                    "reordered",
                    "duplicate-ready",
                    "duplicate-stop",
                    "contact-error",
                    "stdout-extra",
                    "ready-extra-field",
                    "ready-extra-socket",
                    "ready-state-rebased",
                    "handshake-frame-count",
                    "protected-frame-parity",
                    "round-frame-bound",
                    "transfer-wrong-role",
                    "transfer-only",
                    "stop-contact-errors",
                    "stop-transition-mismatch",
                    "stop-transition-omitted",
                )
            ],
            (
                "publish-event",
                "cone-direct",
                "publish-log",
                replace(
                    digest("cone-direct-event").encode("ascii"),
                    digest("forged-event-authority").encode("ascii"),
                ),
            ),
            (
                "prepare-reordered-prefixes",
                "cone-direct",
                "prepare-log",
                reorder_prepare_lines,
            ),
            (
                "prepare-mission-authority-mismatch",
                "cone-direct",
                "prepare-log",
                replace(
                    digest("cone-direct-mission-authority").encode("ascii"),
                    digest("forged-prepare-mission-authority").encode("ascii"),
                ),
            ),
            (
                "manifest-mission-authority-mismatch",
                "cone-direct",
                "prepare-manifest",
                replace(
                    digest("cone-direct-mission-authority").encode("ascii"),
                    digest("forged-manifest-mission-authority").encode("ascii"),
                ),
            ),
            (
                "prepare-manifest-row-order",
                "cone-direct",
                "prepare-manifest",
                reorder_prepare_manifest_rows,
            ),
            (
                "canary-scan-class",
                "cone-direct",
                "canary-scan",
                mutate_json(
                    lambda value: value["representations"][1].__setitem__(
                        "positive_control_observed", 0
                    )
                ),
            ),
            (
                "canary-scan-unexpected-field",
                "cone-direct",
                "canary-scan",
                mutate_json(
                    lambda value: value["positive_control"].__setitem__(
                        "unexpected_private_material", "redacted"
                    )
                ),
            ),
            (
                "canary-scan-node-stderr-role-swap",
                "cone-direct",
                "canary-scan",
                swap_node_stderr_scan_rows,
            ),
            (
                "runtime-unexpected-field",
                "cone-direct",
                "nat-runtime",
                mutate_json(
                    lambda value: value.__setitem__(
                        "unexpected_private_material", "redacted"
                    )
                ),
            ),
            (
                "runtime-mission-authority-mismatch",
                "cone-direct",
                "nat-runtime",
                mutate_json(
                    lambda value: value.__setitem__(
                        "mission_authority",
                        digest("forged-runtime-mission-authority"),
                    )
                ),
            ),
            (
                "node-result-unexpected-field",
                "cone-direct",
                "node-a-result",
                mutate_json(
                    lambda value: value.__setitem__(
                        "unexpected_private_material", "redacted"
                    )
                ),
            ),
            (
                "finalization-unexpected-field",
                "cone-direct",
                "nat-finalization",
                mutate_json(
                    lambda value: value.__setitem__(
                        "unexpected_private_material", "redacted"
                    )
                ),
            ),
            (
                "containment-impossible-file-arithmetic",
                "cone-direct",
                "nat-finalization",
                mutate_json(
                    lambda value: value["restricted_state_containment"].update(
                        {"state_files": 5, "retained_files": 4}
                    )
                ),
            ),
            (
                "pcap-tuple-unexpected-field",
                "cone-direct",
                "pcap-tuple-summary",
                mutate_json(
                    lambda value: value["routers"]["nat-a"]["tuples"][0].__setitem__(
                        "unexpected_private_material", "redacted"
                    )
                ),
            ),
            (
                "nft-snapshot-unexpected-field",
                "cone-direct",
                "nat-a-nft-before",
                mutate_json(
                    lambda value: value.__setitem__(
                        "unexpected_private_material", "redacted"
                    )
                ),
            ),
            (
                "cleanup-unexpected-field",
                "cone-direct",
                "secret-cleanup-receipt",
                mutate_json(
                    lambda value: value.__setitem__(
                        "unexpected_private_material", "redacted"
                    )
                ),
            ),
            (
                "destroy-global-overclaim",
                "cone-direct",
                "canary-destroy-log",
                replace(b"global_secret_destruction=false", b"global_secret_destruction=true"),
            ),
            (
                "relay-runtime-capability",
                "restrictive-relay",
                "relay-runtime-config",
                mutate_json(
                    lambda value: value["HostConfig"].__setitem__(
                        "CapAdd", ["CAP_NET_ADMIN"]
                    )
                ),
            ),
            (
                "relay-missing-cap-add-field",
                "restrictive-relay",
                "relay-runtime-config",
                mutate_json(lambda value: value["HostConfig"].pop("CapAdd")),
            ),
            (
                "relay-duplicate-cap-drop",
                "restrictive-relay",
                "relay-runtime-config",
                mutate_json(
                    lambda value: value["HostConfig"]["CapDrop"].append("ALL")
                ),
            ),
            (
                "relay-ca-source-swapped",
                "restrictive-relay",
                "node-a-config",
                mutate_mount_source(
                    "/run/relay/ca.der",
                    "/outputs/provision/relay/ca.der",
                    "/outputs/provision/relay/server.cert.der",
                ),
            ),
            (
                "relay-ca-writable",
                "restrictive-relay",
                "node-a-config",
                mutate_mount_read_write("/run/relay/ca.der", True),
            ),
            (
                "relay-certificate-source-swapped",
                "restrictive-relay",
                "relay-runtime-config",
                mutate_mount_source(
                    "/run/relay/server.cert.der",
                    "/outputs/provision/relay/server.cert.der",
                    "/outputs/provision/relay/ca.der",
                ),
            ),
            (
                "relay-key-source-swapped",
                "restrictive-relay",
                "relay-runtime-config",
                mutate_mount_source(
                    "/run/relay/server.key.pkcs8.der",
                    "/outputs/provision/relay/private/server.key.pkcs8.der",
                    "/outputs/provision/relay/server.cert.der",
                ),
            ),
            (
                "relay-session-bound",
                "restrictive-relay",
                "relay-log",
                replace(b"max_admitted_connections=8", b"max_admitted_connections=9"),
            ),
            (
                "relay-reversed-lifecycle",
                "restrictive-relay",
                "relay-log",
                reverse_receipt_lines,
            ),
            (
                "relay-extra-line",
                "restrictive-relay",
                "relay-log",
                append_diagnostic_line,
            ),
            (
                "relay-material-extra-line",
                "restrictive-relay",
                "relay-material-log",
                append_diagnostic_line,
            ),
            (
                "relay-material-root",
                "restrictive-relay",
                "relay-material-log",
                replace(
                    b"ca_sha256=" + hashlib.sha256(
                        test_certificate_der("ca")
                    ).hexdigest().encode("ascii"),
                    b"ca_sha256=" + digest("forged-relay-ca").encode("ascii"),
                ),
            ),
            (
                "relay-key-destroy-oversized",
                "restrictive-relay",
                "relay-material-destroy-log",
                replace(b"previous_bytes=128", b"previous_bytes=16385"),
            ),
        ]
        for name, scope, role, mutate in cases:
            with self.subTest(name=name), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary).resolve()
                document = baseline()
                materialize_raw_root(root, document)
                entry = next(
                    value
                    for value in document["raw_manifest"]["entries"]
                    if value["cell"] == scope and value["role"] == role
                )
                path = root / entry["path"]
                changed = mutate(path.read_bytes())
                path.write_bytes(changed)
                path.chmod(0o600)
                refresh_manifest_entry(document, str(entry["path"]), changed)
                if role == "nat-finalization":
                    summary_path = root / "selected-nat-suite.json"
                    summary = json.loads(summary_path.read_text(encoding="utf-8"))
                    summary_cell = next(
                        value for value in summary["cells"] if value["profile"] == scope
                    )
                    summary_cell["finalization_sha256"] = hashlib.sha256(
                        changed
                    ).hexdigest()
                    summary_content = raw_json(summary)
                    summary_path.write_bytes(summary_content)
                    summary_path.chmod(0o600)
                    refresh_manifest_entry(
                        document, "selected-nat-suite.json", summary_content
                    )
                if role == "pcap-tuple-summary":
                    receipt_cell = next(
                        cell for cell in document["cells"] if cell["name"] == scope
                    )
                    receipt_cell["pcap"]["tuple_summary_sha256"] = hashlib.sha256(
                        changed
                    ).hexdigest()
                CHECKER.validate_receipt(document)
                with self.assertRaises(CHECKER.ReceiptViolation):
                    CHECKER.verify_raw_root(root, document)

    def test_symbolic_raw_root_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            parent = Path(temporary).resolve()
            root = parent / "real-root"
            root.mkdir(mode=0o700)
            document = baseline()
            materialize_raw_root(root, document)
            alias = parent / "alias-root"
            alias.symlink_to(root, target_is_directory=True)
            with self.assertRaises(CHECKER.ReceiptViolation):
                CHECKER.verify_raw_root(alias, document)

    def test_pcap_tuple_sequence_must_be_positive_sorted_and_unique(self) -> None:
        for mode in ("zero", "duplicate", "reordered"):
            with self.subTest(mode=mode), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary).resolve()
                document = baseline()
                materialize_raw_root(root, document)
                profile = "cone-direct"
                summary_path = root / "cells" / profile / "pcap-tuple-summary.json"
                finalization_path = (
                    root / "cells" / profile / "selected-nat-finalization.json"
                )
                summary = json.loads(summary_path.read_text(encoding="utf-8"))
                tuples = summary["routers"]["nat-a"]["tuples"]
                if mode == "zero":
                    moved = tuples[0]["packets"]
                    tuples[0]["packets"] = 0
                    tuples[1]["packets"] += moved
                elif mode == "duplicate":
                    duplicate = dict(tuples[0])
                    tuples[0]["packets"] -= 1
                    duplicate["packets"] = 1
                    tuples.insert(1, duplicate)
                else:
                    tuples.reverse()
                finalization = json.loads(
                    finalization_path.read_text(encoding="utf-8")
                )
                finalization["pcap"] = summary["routers"]
                summary_content = raw_json(summary)
                finalization_content = raw_json(finalization)
                summary_path.write_bytes(summary_content)
                summary_path.chmod(0o600)
                finalization_path.write_bytes(finalization_content)
                finalization_path.chmod(0o600)
                refresh_manifest_entry(
                    document,
                    f"cells/{profile}/pcap-tuple-summary.json",
                    summary_content,
                )
                refresh_manifest_entry(
                    document,
                    f"cells/{profile}/selected-nat-finalization.json",
                    finalization_content,
                )
                receipt_cell = next(
                    cell for cell in document["cells"] if cell["name"] == profile
                )
                receipt_cell["pcap"]["tuple_summary_sha256"] = hashlib.sha256(
                    summary_content
                ).hexdigest()
                suite_path = root / "selected-nat-suite.json"
                suite = json.loads(suite_path.read_text(encoding="utf-8"))
                suite_cell = next(
                    cell for cell in suite["cells"] if cell["profile"] == profile
                )
                suite_cell["finalization_sha256"] = hashlib.sha256(
                    finalization_content
                ).hexdigest()
                suite_content = raw_json(suite)
                suite_path.write_bytes(suite_content)
                suite_path.chmod(0o600)
                refresh_manifest_entry(
                    document, "selected-nat-suite.json", suite_content
                )
                CHECKER.validate_receipt(document)
                with self.assertRaises(CHECKER.ReceiptViolation):
                    CHECKER.verify_raw_root(root, document)

    def test_symlink_receipt_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            target = root / "target.json"
            target.write_bytes(canonical(baseline()))
            retained = root / "receipt.json"
            os.symlink(target, retained)
            with self.assertRaisesRegex(CHECKER.ReceiptViolation, "plain regular"):
                CHECKER.load_receipt(retained)


if __name__ == "__main__":
    unittest.main()
