#!/usr/bin/env python3
# Copyright 2026 Defense Unicorns, Inc.
# SPDX-License-Identifier: Apache-2.0
"""Validate one sanitized selected-Iroh, two-cell NAT acceptance receipt.

The schema is deliberately exclusive and bounded.  It accepts only the one-host
Linux-network-namespace cone/direct and restrictive/controlled-relay experiment.
Raw replay parses only bounded Ethernet/IPv4/TCP/UDP tuple metadata from curated
packet captures and never embeds or emits packet payload contents.  It never
reads stores, mission bundles, identity keys, payloads, or canaries; those
remain outside the sanitized receipt.
"""

from __future__ import annotations

import argparse
import hashlib
import ipaddress
import json
import os
from pathlib import Path, PurePosixPath
import re
import shlex
import shutil
import stat
import subprocess
import sys
from typing import Any, Callable, Sequence
from urllib.parse import urlsplit


SCHEMA = "aster-selected-iroh-nat-receipt/v1"
CLAIM = "selected-iroh-one-host-namespace-nat-two-cell-acceptance"
RECEIPT_MAX_BYTES = 128 * 1024
MAX_BINARY_BYTES = 256 * 1024 * 1024
MAX_ARTIFACT_BYTES = 1024 * 1024 * 1024
MAX_PCAP_BYTES = 128 * 1024 * 1024
MAX_MANIFEST_ARTIFACT_BYTES = 8 * 1024 * 1024 * 1024
MAX_MANIFEST_RECORDS = 128
MAX_COUNTER = (1 << 63) - 1
MAX_TRANSITIONS = 1024
MAX_SESSIONS = 1024
MAX_COMMITTED_INPUTS = 1024
MAX_GIT_TREE_OBJECTS = 4096
MAX_GIT_TREE_ENTRIES = 16384
MAX_GIT_TREE_BYTES = 64 * 1024 * 1024
MAX_GIT_TREE_DEPTH = 64
MAX_GIT_TREE_PATH_BYTES = 16 * 1024 * 1024

HEX_32 = re.compile(r"[0-9a-f]{64}\Z")
GIT_OBJECT = re.compile(r"[0-9a-f]{40}\Z")
SAFE_NAME = re.compile(r"[a-z0-9][a-z0-9._-]{0,95}\Z")
SAFE_VERSION = re.compile(r"[0-9A-Za-z][0-9A-Za-z.+_-]{0,63}\Z")
IMAGE_REFERENCE = re.compile(r"[a-z0-9][a-z0-9./:_-]{0,191}\Z")
SHA256_REFERENCE = re.compile(r"sha256:[0-9a-f]{64}\Z")
PINNED_IMAGE_REFERENCE = re.compile(
    r"[a-z0-9][a-z0-9./:_-]{0,127}@sha256:[0-9a-f]{64}\Z"
)
RUN_ID = re.compile(r"[0-9a-f]{16}\Z")
UTC_TIMESTAMP = re.compile(
    r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}"
    r"(?:\.[0-9]{1,6})?Z\Z"
)

SELECTED_NAT_IMAGE = "aster-lab:selected-nat"
SELECTED_NAT_IMAGE_SCHEMA = "aster-selected-nat-image/v1"
LAB_BASE_IMAGE = (
    "rust@sha256:0e2bcaef56d041a486784e54104a81aebe0da44bd03019bd70bc0401e42e4a97"
)
BASE_IMAGE_SOURCE_LABEL = "org.opencontainers.image.source"
BASE_IMAGE_SOURCE = "https://github.com/rust-lang/docker-rust"
PINNED_BASE_IMAGE_LABELS = {BASE_IMAGE_SOURCE_LABEL: BASE_IMAGE_SOURCE}
SELECTED_NAT_LOCAL_REPOSITORY = "aster-lab"
SELECTED_NAT_IMAGE_ENVIRONMENT = [
    "PATH=/usr/local/cargo/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
    "RUSTUP_HOME=/usr/local/rustup",
    "CARGO_HOME=/usr/local/cargo",
    "RUST_VERSION=1.97.1",
]
EXPECTED_DOCKERIGNORE = """**
!Cargo.toml
!Cargo.lock
!LICENSE
!crates/
!crates/**
!third-party/
!third-party/**
!lab/
!lab/Dockerfile
!lab/Dockerfile.selected-nat
!lab/Dockerfile.dockerignore
!lab/debian.sources
"""
RAW_CONTROLLER_SCHEMA = "aster-lab-controller/v1"
MANAGED_LABEL = "com.defenseunicorns.aster-lab.managed"
RUN_LABEL = "com.defenseunicorns.aster-lab.run-id"
IMAGE_SCHEMA_LABEL = "com.defenseunicorns.aster-lab.image-schema"
IMAGE_INPUT_LABEL = "com.defenseunicorns.aster-lab.build-input-sha256"
IMAGE_BASE_LABEL = "com.defenseunicorns.aster-lab.base-image"
ROLE_LABEL = "com.defenseunicorns.aster-lab.role"

TOP_KEYS = {
    "schema",
    "status",
    "claim",
    "source",
    "build",
    "environment",
    "cells",
    "raw_manifest",
    "limitations",
}
SOURCE_KEYS = {
    "commit",
    "tree",
    "signature",
    "cargo_lock_sha256",
    "requirements_sha256",
    "worktree",
}
BUILD_KEYS = {"command", "target", "artifacts", "container"}
BUILD_ARTIFACT_KEYS = {"role", "name", "bytes", "sha256"}
CONTAINER_KEYS = {
    "reference",
    "dockerfile_sha256",
    "input_manifest_sha256",
    "base_image",
    "build_run_id",
    "image_id",
    "image_config_digest",
}
ENVIRONMENT_KEYS = {
    "physical_hosts",
    "isolation",
    "host_os",
    "host_arch",
    "kernel",
    "docker_version",
    "orbstack_version",
    "orchestrator_exit_code",
    "cleanup",
    "clock_assurance",
}
CELL_KEYS = {
    "name",
    "status",
    "nat_profile",
    "topology",
    "infrastructure",
    "endpoints",
    "event",
    "reconciliation",
    "path",
    "nft",
    "pcap",
    "relay",
    "canary_scan",
    "cleanup",
}
TOPOLOGY_KEYS = {
    "sender_bind",
    "receiver_bind",
    "nat_a_external",
    "nat_b_external",
    "sender_default_gateway",
    "receiver_default_gateway",
    "relay_origin",
}
INFRASTRUCTURE_KEYS = {
    "controlled_relay",
    "hosted_discovery",
    "public_relay",
    "default_relay",
    "public_relay_fallback",
    "port_mapper",
}
ENDPOINT_KEYS = {"role", "carrier_id", "mission_id", "fresh"}
EVENT_KEYS = {
    "event_id",
    "publisher",
    "payload_sha256",
    "sealed_sha256",
    "canary_sha256",
    "payload_bytes",
    "source_sequence",
    "source_inserted",
    "destination_deliveries",
    "destination_attempt",
    "acknowledged",
    "empty_after_ack",
    "replay_ack",
    "replay_subscription",
    "exact_query",
    "exact_event_id_match",
}
RECONCILIATION_KEYS = {
    "status",
    "contacts",
    "offered",
    "fetched",
    "inserted",
    "duplicates",
    "remaining",
    "deferred_event_lanes",
    "control_offered",
    "control_fetched",
    "control_retained",
    "control_duplicates",
    "control_activated",
    "control_remaining",
    "mutable_remaining",
    "deferred_mutable_lanes",
    "blob_ranges_fetched",
    "blob_bytes_fetched",
    "blob_remaining",
    "blob_deferred",
}
RAW_NODE_READY_KEYS = {
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
}
RAW_NODE_CONTACT_KEYS = {
    "direction",
    "carrier_peer",
    "mission_peer",
    "rounds",
    *(RECONCILIATION_KEYS - {"status", "contacts"}),
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
}
RAW_NODE_STOP_KEYS = {
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
    "pending_blobs",
    "blob_ranges_fetched",
    "blob_bytes_fetched",
    "blob_remaining",
    "blob_deferred",
    "mission_auth",
    "provisioning",
    "semantics",
    "reconciliation_classes",
    "controls_semantics",
}
PATH_KEYS = {"witnesses"}
PATH_WITNESS_KEYS = {
    "role",
    "selected",
    "transition_count",
    "transitions_saturated",
}
NFT_KEYS = {"namespace", "counters"}
NFT_COUNTER_KEYS = {
    "router",
    "name",
    "before_packets",
    "after_packets",
    "delta_packets",
    "before_bytes",
    "after_bytes",
    "delta_bytes",
}
PCAP_KEYS = {"captures", "tuple_summary_sha256", "tuple_proof"}
PCAP_CAPTURE_KEYS = {
    "role",
    "bytes",
    "packets",
    "dropped_packets",
    "sha256",
    "manifest_role",
}
PCAP_TUPLE_KEYS = {
    "direct_cross_nat_packets",
    "direct_probe_packets",
    "controlled_relay_https_packets",
    "controlled_relay_http_packets",
    "unexpected_public_relay_packets",
    "unexpected_hosted_discovery_packets",
}
RELAY_KEYS = {
    "mode",
    "origin",
    "tls_mode",
    "server_trust_claim",
    "client_trust_mode",
    "root_fingerprint_sha256",
    "allowlist_mode",
    "allowlist_count",
    "allowlist_sha256",
    "key_cache_capacity",
    "client_rx_bytes_per_second",
    "client_rx_max_burst_bytes",
    "max_admitted_connections",
    "pre_auth_connection_cap",
    "observed_active_sessions_peak",
    "accepted_sessions",
    "rejected_sessions",
    "secrets_logged",
}
CANARY_KEYS = {
    "classes",
    "scan_targets",
    "positive_control",
    "chronology",
    "artifacts_scanned",
    "class_match_counts",
    "match_count",
}
POSITIVE_CONTROL_KEYS = {
    "status",
    "expected_matches",
    "observed_matches",
    "class_match_counts",
}
CLEANUP_KEYS = {
    "status",
    "canary_control_file_disposition",
    "canary_control_file_previous_bytes",
    "relay_private_key_file_disposition",
    "canary_control_file_absent_after_cleanup",
    "relay_private_key_file_absent_after_cleanup",
    "assurance",
    "physical_sanitization",
    "containers_remaining",
    "networks_remaining",
    "namespaces_remaining",
}
MANIFEST_KEYS = {
    "format",
    "root_type",
    "root_mode",
    "root_owner",
    "entries",
    "records",
    "manifest_bytes",
    "artifact_bytes",
    "sha256",
    "secret_artifacts",
    "pcap_contents",
}
MANIFEST_ENTRY_KEYS = {
    "cell",
    "role",
    "path",
    "type",
    "nlink",
    "bytes",
    "sha256",
    "mode",
    "owner",
    "sensitivity",
    "retention",
}

BUILD_ROLES = ("aster-cli", "event-helper", "relay-helper")
BUILD_NAMES = ("aster", "aster-selected-nat", "aster-selected-relay")
CELL_NAMES = ("cone-direct", "restrictive-relay")
ENDPOINT_ROLES = ("sender", "receiver")
PCAP_ROLES = ("nat-a-wan", "nat-b-wan")
CANARY_CLASSES = ("raw-bytes", "lowercase-hex", "base64-standard")
CANARY_CHRONOLOGY = (
    "positive-control-observed-before-retained-scan",
    "captures-and-logs-finalized-before-retained-scan",
    "retained-artifact-scan-zero-before-destruction",
    "standalone-control-file-overwritten-unlinked-and-absent-after-scan",
)
RAW_CELL_LIMITATIONS = (
    "one physical host with Docker namespace isolation",
    "software/static NAT only; no physical NAT hardware or public Internet",
    "no direct-first fallback chronology claim",
    "no exclusive laboratory network or whole-listener pre-auth connection-cap claim",
    "no BTLE, independent implementation, or resource-threshold claim",
    "filesystem timestamps are not an independent clock",
)

TOPOLOGY = {
    "cone-direct": {
        "sender_bind": "10.250.1.10:44000",
        "receiver_bind": "10.250.2.10:44000",
        "nat_a_external": "10.250.0.11:44000",
        "nat_b_external": "10.250.0.12:44000",
        "sender_default_gateway": "10.250.1.1",
        "receiver_default_gateway": "10.250.2.1",
        "relay_origin": "none",
    },
    "restrictive-relay": {
        "sender_bind": "10.250.1.10:44000",
        "receiver_bind": "10.250.2.10:44000",
        "nat_a_external": "10.250.0.11:44000",
        "nat_b_external": "10.250.0.12:44000",
        "sender_default_gateway": "10.250.1.1",
        "receiver_default_gateway": "10.250.2.1",
        "relay_origin": "https://relay.aster.test:8443",
    },
}

CONE_NFT_NAMES = (
    "aster_cone_dnat",
    "aster_cone_snat",
    "aster_cone_forward_in",
    "aster_cone_forward_out",
)
RESTRICTIVE_NFT_NAMES = (
    "aster_restrict_direct_drop",
    "aster_restrict_relay_https",
    "aster_restrict_relay_http",
    "aster_restrict_established",
)

GLOBAL_MANIFEST_PATHS = {
    "suite-controller": "controller.json",
    "suite-summary": "selected-nat-suite.json",
    "suite-source-identity": "source-identity.json",
    "suite-build-identity": "selected-build.json",
}
COMMON_CELL_MANIFEST_PATHS = {
    "controller-receipt": "controller.json",
    "scenario-receipt": "scenario-request.json",
    "source-identity": "source-identity.json",
    "build-identity": "binary-inventory.json",
    "image-identity": "image-identity.json",
    "prepare-manifest": "outputs/provision/manifest.tsv",
    "prepare-log": "prepare.log",
    "provision-prepare-config": "aster-lab-provision-configuration.json",
    "provision-verify-config": "aster-lab-provision-verifier-configuration.json",
    "publish-log": "publish.log",
    "verify-log": "verify.log",
    "node-a-result": "node-a-result.json",
    "node-a-log": "node-a.log",
    "node-b-result": "node-b-result.json",
    "node-b-log": "node-b.log",
    "nat-runtime": "selected-nat-runtime.json",
    "nat-finalization": "selected-nat-finalization.json",
    "nat-a-nft-program": "nat-a.nft",
    "nat-b-nft-program": "nat-b.nft",
    "nat-a-config": "aster-lab-nat-a-configuration.json",
    "nat-b-config": "aster-lab-nat-b-configuration.json",
    "nat-a-nft-before": "nat-a-nft-before.json",
    "nat-a-nft-after": "nat-a-nft-after.json",
    "nat-b-nft-before": "nat-b-nft-before.json",
    "nat-b-nft-after": "nat-b-nft-after.json",
    "nat-a-wan-pcap": "outputs/nat-a/nat-a-wan.pcap",
    "nat-b-wan-pcap": "outputs/nat-b/nat-b-wan.pcap",
    "pcap-tuple-summary": "pcap-tuple-summary.json",
    "route-init-removal": "route-init-removal.json",
    "route-a-config": "aster-lab-route-a-configuration.json",
    "route-b-config": "aster-lab-route-b-configuration.json",
    "lan-a-network-config": "aster-lab-lan-a-network.json",
    "wan-network-config": "aster-lab-wan-network.json",
    "lan-b-network-config": "aster-lab-lan-b-network.json",
    "node-a-config": "aster-lab-node-a-configuration.json",
    "node-b-config": "aster-lab-node-b-configuration.json",
    "node-a-runtime-privilege": "node-a-runtime-privilege.json",
    "node-b-runtime-privilege": "node-b-runtime-privilege.json",
    "cleanup-log": "cleanup-summary.json",
    "events": "events.jsonl",
    "canary-scan": "canary-scan.json",
    "canary-destroy-log": "canary-destroy.log",
    "secret-cleanup-receipt": "secret-cleanup.json",
}
CELL_EXTRA_MANIFEST_PATHS = {
    "cone-direct": {"relay-disabled-receipt": "relay-disabled.json"},
    "restrictive-relay": {
        "relay-log": "relay.log",
        "relay-ca-der": "outputs/provision/relay/ca.der",
        "relay-cert-der": "outputs/provision/relay/server.cert.der",
        "relay-material-log": "relay-material.log",
        "relay-material-destroy-log": "relay-material-destroy.log",
        "relay-config": "relay-config.json",
        "relay-runtime-config": "aster-lab-infra-configuration.json",
        "relay-runtime-privilege": "infra-runtime-privilege.json",
    },
}

LIMITATIONS = {
    "claim_scope": "observed-bounded-selected-iroh-carrier",
    "physical_hosts": 1,
    "topology": "linux-network-namespaces-on-one-host",
    "namespace_nat": "observed-bounded",
    "physical_nat": "not-claimed",
    "nat_hardware": "not-claimed",
    "public_internet": "not-claimed",
    "physical_path": "not-claimed",
    "relay_fallback_chronology": "not-claimed",
    "btle": "not-claimed",
    "independent_implementation": "not-claimed",
    "resource_thresholds": "not-claimed",
    "clock_assurance": "filesystem-metadata-not-independent",
    "sealed_representation_hash": "not-exposed-by-production-api",
    "hosted_or_public_relay": "not-used",
    "port_mapping": "disabled-not-used",
    "path_witness": "selected-final-path-not-route-authorization",
    "control_file_destruction": (
        "bounded-software-only-standalone-control-files-physical-sanitization-not-claimed"
    ),
    "encrypted_event_state_and_credentials": (
        "retained-external-restricted-not-sanitized-by-control-file-cleanup"
    ),
    "registry_image_digest": "not-claimed-local-image-id-only",
    "build_network": "explicit-default-network-no-cache-not-hermetic",
    "relay_pre_auth_connection_cap": "not-enforced",
    "lab_network_exclusivity": "not-claimed",
}

FORBIDDEN_MANIFEST_PATH_PARTS = (
    "identity.key",
    "mesh.redb",
    "mission.unprotected",
    "private-key",
    "private_key",
    "canary.bin",
    "canary.raw",
    "relay-key",
    "relay_key",
    ".key",
    ".pem",
    ".p12",
    ".pfx",
    ".bundle",
    ".redb",
    "/private/",
    "secret",
    "credential",
)


class ReceiptViolation(ValueError):
    """The receipt is malformed, incomplete, unsafe, or outside the claim."""


class DuplicateKey(ReceiptViolation):
    """JSON object member names were not unique."""


def fail(message: str) -> None:
    raise ReceiptViolation(message)


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def exact_object(value: Any, keys: set[str], label: str) -> dict[str, Any]:
    if type(value) is not dict:
        fail(f"{label} is not an object")
    if set(value) != keys:
        fail(f"{label} has missing or unexpected keys")
    return value


def exact_array(value: Any, length: int | None, label: str) -> list[Any]:
    if type(value) is not list:
        fail(f"{label} is not an array")
    if length is not None and len(value) != length:
        fail(f"{label} has an unexpected element count")
    return value


def exact_string(
    value: Any,
    label: str,
    *,
    expected: str | None = None,
    pattern: re.Pattern[str] | None = None,
    maximum: int = 256,
) -> str:
    if type(value) is not str or not value or len(value) > maximum:
        fail(f"{label} is not a bounded nonempty string")
    if not value.isascii() or any(
        not 0x20 <= ord(character) <= 0x7E for character in value
    ):
        fail(f"{label} is not canonical printable ASCII")
    if expected is not None and value != expected:
        fail(f"{label} has an unexpected value")
    if pattern is not None and pattern.fullmatch(value) is None:
        fail(f"{label} has a malformed value")
    return value


def exact_bool(value: Any, label: str, expected: bool | None = None) -> bool:
    if type(value) is not bool:
        fail(f"{label} is not a Boolean")
    if expected is not None and value is not expected:
        fail(f"{label} has an unexpected Boolean value")
    return value


def bounded_int(
    value: Any,
    label: str,
    *,
    minimum: int = 0,
    maximum: int = MAX_COUNTER,
    expected: int | None = None,
) -> int:
    if type(value) is not int:
        fail(f"{label} is not an integer")
    if value < minimum or value > maximum:
        fail(f"{label} is outside its bound")
    if expected is not None and value != expected:
        fail(f"{label} has an unexpected value")
    return value


def hex_32(value: Any, label: str) -> str:
    return exact_string(value, label, pattern=HEX_32, maximum=64)


def git_object(value: Any, label: str) -> str:
    return exact_string(value, label, pattern=GIT_OBJECT, maximum=40)


def duplicate_safe_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    output: dict[str, Any] = {}
    for key, value in pairs:
        if key in output:
            raise DuplicateKey("receipt JSON contains a duplicate object key")
        output[key] = value
    return output


def reject_json_constant(value: str) -> None:
    raise ReceiptViolation("receipt JSON contains a non-finite numeric constant")


def load_receipt(path: Path) -> dict[str, Any]:
    try:
        metadata = os.lstat(path)
    except OSError:
        fail("receipt file is missing or unreadable")
    if not stat.S_ISREG(metadata.st_mode) or stat.S_ISLNK(metadata.st_mode):
        fail("receipt file is not a plain regular file")
    if metadata.st_nlink != 1:
        fail("receipt file has an unsafe hard-link count")
    if metadata.st_size <= 0 or metadata.st_size > RECEIPT_MAX_BYTES:
        fail("receipt file is empty or exceeds its byte cap")
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags)
    except OSError:
        fail("receipt file could not be opened without following links")
    try:
        opened = os.fstat(descriptor)
        if (metadata.st_dev, metadata.st_ino) != (opened.st_dev, opened.st_ino):
            fail("receipt file changed identity while being opened")
        data = b""
        while len(data) <= RECEIPT_MAX_BYTES:
            chunk = os.read(descriptor, min(64 * 1024, RECEIPT_MAX_BYTES + 1 - len(data)))
            if not chunk:
                break
            data += chunk
    finally:
        os.close(descriptor)
    if len(data) != metadata.st_size or len(data) > RECEIPT_MAX_BYTES:
        fail("receipt file changed size or exceeded its byte cap")
    if b"\x00" in data or b"\r" in data or not data.endswith(b"\n"):
        fail("receipt file is truncated or has a forbidden control encoding")
    try:
        text = data.decode("utf-8", errors="strict")
        document = json.loads(
            text,
            object_pairs_hook=duplicate_safe_object,
            parse_constant=reject_json_constant,
        )
    except (UnicodeDecodeError, json.JSONDecodeError):
        fail("receipt file is not canonical UTF-8 JSON")
    if type(document) is not dict:
        fail("receipt root is not an object")
    canonical = (
        json.dumps(document, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
        + "\n"
    ).encode("ascii")
    if canonical != data:
        fail("receipt file is not deterministic canonical JSON")
    return document


def validate_source(value: Any) -> None:
    source = exact_object(value, SOURCE_KEYS, "source")
    git_object(source["commit"], "source.commit")
    git_object(source["tree"], "source.tree")
    exact_string(source["signature"], "source.signature", expected="verified")
    hex_32(source["cargo_lock_sha256"], "source.cargo_lock_sha256")
    hex_32(source["requirements_sha256"], "source.requirements_sha256")
    exact_string(
        source["worktree"],
        "source.worktree",
        expected="clean-tracked-and-untracked-nonignored",
    )


def canonical_absolute_path(value: str, label: str) -> PurePosixPath:
    path = PurePosixPath(value)
    if not value.startswith("/") or str(path) != value or ".." in path.parts:
        fail(f"{label} is not a canonical absolute path")
    return path


def validate_build_command(
    value: Any, container: dict[str, Any]
) -> PurePosixPath:
    command = exact_string(value, "build.command", maximum=2048)
    if any(ord(character) < 0x20 for character in command):
        fail("build.command contains a control character")
    if any(token in command for token in (";", "&&", "||", "`", "$(")):
        fail("build.command contains shell control syntax")
    try:
        arguments = shlex.split(command, posix=True)
    except ValueError:
        fail("build.command is not a canonical argv rendering")
    if shlex.join(arguments) != command:
        fail("build.command is not the canonical shell-escaped argv rendering")
    prefix = [
        "docker",
        "build",
        "--pull=false",
        "--network=default",
        "--no-cache",
        "--load",
        "--progress=plain",
    ]
    if arguments[: len(prefix)] != prefix:
        fail("build.command is not the exact selected-NAT Docker build")
    index = len(prefix)

    def pair(flag: str) -> str:
        nonlocal index
        if arguments[index : index + 1] != [flag] or index + 1 >= len(arguments):
            fail(f"build.command omits or reorders {flag}")
        result = arguments[index + 1]
        index += 2
        return result

    dockerfile = canonical_absolute_path(pair("--file"), "build.command Dockerfile")
    if dockerfile.parts[-2:] != ("lab", "Dockerfile.selected-nat"):
        fail("build.command does not select lab/Dockerfile.selected-nat")
    sealed_context = dockerfile.parents[1]
    if sealed_context.name != "build-context":
        fail("build.command does not use the sealed build-context directory")
    if pair("--tag") != container["reference"]:
        fail("build.command tag differs from build.container.reference")
    expected_labels = (
        f"{MANAGED_LABEL}=true",
        f"{RUN_LABEL}={container['build_run_id']}",
        f"{IMAGE_SCHEMA_LABEL}={SELECTED_NAT_IMAGE_SCHEMA}",
        f"{IMAGE_INPUT_LABEL}={container['input_manifest_sha256']}",
        f"{IMAGE_BASE_LABEL}={container['base_image']}",
    )
    for expected_label in expected_labels:
        if pair("--label") != expected_label:
            fail("build.command contains a missing, reordered, or false image label")
    if pair("--build-arg") != f"LAB_BASE_IMAGE={container['base_image']}":
        fail("build.command base-image argument differs from its bound image")
    iidfile = canonical_absolute_path(pair("--iidfile"), "build.command iidfile")
    metadata = canonical_absolute_path(
        pair("--metadata-file"), "build.command metadata file"
    )
    if iidfile.name != "image-id.txt" or metadata.name != "build-metadata.json":
        fail("build.command output receipt names are not exact")
    if iidfile.parent != metadata.parent:
        fail("build.command output receipts do not share one run directory")
    if iidfile.parent != sealed_context.parent:
        fail("build.command output receipts are outside the sealed build run")
    if index != len(arguments) - 1:
        fail("build.command contains an unexpected flag or argument")
    context = canonical_absolute_path(arguments[index], "build.command context")
    if context != sealed_context:
        fail("build.command context differs from its selected Dockerfile root")
    return sealed_context.parent


def validate_build(value: Any) -> None:
    build = exact_object(value, BUILD_KEYS, "build")
    exact_string(
        build["target"],
        "build.target",
        expected="aarch64-unknown-linux-gnu",
    )
    artifacts = exact_array(build["artifacts"], len(BUILD_ROLES), "build.artifacts")
    names: set[str] = set()
    for index, expected_role in enumerate(BUILD_ROLES):
        artifact = exact_object(
            artifacts[index], BUILD_ARTIFACT_KEYS, f"build.artifacts[{index}]"
        )
        exact_string(
            artifact["role"],
            f"build.artifacts[{index}].role",
            expected=expected_role,
        )
        name = exact_string(
            artifact["name"],
            f"build.artifacts[{index}].name",
            pattern=SAFE_NAME,
        )
        if name != BUILD_NAMES[index]:
            fail(f"build.artifacts[{index}].name is not the exact selected executable")
        if name in names:
            fail("build artifacts contain a duplicate executable name")
        names.add(name)
        bounded_int(
            artifact["bytes"],
            f"build.artifacts[{index}].bytes",
            minimum=1,
            maximum=MAX_BINARY_BYTES,
        )
        hex_32(artifact["sha256"], f"build.artifacts[{index}].sha256")

    container = exact_object(build["container"], CONTAINER_KEYS, "build.container")
    reference = exact_string(
        container["reference"],
        "build.container.reference",
        pattern=IMAGE_REFERENCE,
        maximum=192,
    )
    if reference != SELECTED_NAT_IMAGE:
        fail("build.container.reference is not the exact selected-NAT local tag")
    hex_32(container["dockerfile_sha256"], "build.container.dockerfile_sha256")
    hex_32(
        container["input_manifest_sha256"],
        "build.container.input_manifest_sha256",
    )
    exact_string(
        container["base_image"],
        "build.container.base_image",
        expected=LAB_BASE_IMAGE,
        maximum=200,
    )
    exact_string(
        container["build_run_id"],
        "build.container.build_run_id",
        pattern=RUN_ID,
        maximum=16,
    )
    exact_string(
        container["image_id"],
        "build.container.image_id",
        pattern=SHA256_REFERENCE,
        maximum=71,
    )
    exact_string(
        container["image_config_digest"],
        "build.container.image_config_digest",
        pattern=SHA256_REFERENCE,
        maximum=71,
    )
    if container["image_id"] != container["image_config_digest"]:
        fail("build.container local image ID differs from its OCI config digest")
    validate_build_command(build["command"], container)


def validate_environment(value: Any) -> None:
    environment = exact_object(value, ENVIRONMENT_KEYS, "environment")
    bounded_int(environment["physical_hosts"], "environment.physical_hosts", expected=1)
    exact_string(
        environment["isolation"],
        "environment.isolation",
        expected="docker-linux-network-namespaces",
    )
    exact_string(environment["host_os"], "environment.host_os", expected="Darwin")
    exact_string(environment["host_arch"], "environment.host_arch", expected="arm64")
    exact_string(environment["kernel"], "environment.kernel", maximum=128)
    exact_string(
        environment["docker_version"],
        "environment.docker_version",
        pattern=SAFE_VERSION,
    )
    exact_string(
        environment["orbstack_version"],
        "environment.orbstack_version",
        pattern=SAFE_VERSION,
    )
    bounded_int(
        environment["orchestrator_exit_code"],
        "environment.orchestrator_exit_code",
        expected=0,
    )
    exact_string(environment["cleanup"], "environment.cleanup", expected="pass")
    exact_string(
        environment["clock_assurance"],
        "environment.clock_assurance",
        expected="filesystem-metadata-not-independent",
    )


def parse_private_ipv4(value: Any, label: str) -> ipaddress.IPv4Address:
    text = exact_string(value, label, maximum=15)
    try:
        address = ipaddress.ip_address(text)
    except ValueError:
        fail(f"{label} is not an IP address")
    if type(address) is not ipaddress.IPv4Address or not address.is_private:
        fail(f"{label} is not one private IPv4 address")
    if address.is_unspecified or address.is_loopback or address.is_multicast:
        fail(f"{label} is not a usable private IPv4 address")
    if str(address) != text:
        fail(f"{label} is not canonical")
    return address


def parse_socket(value: Any, label: str) -> tuple[ipaddress.IPv4Address, int]:
    text = exact_string(value, label, maximum=22)
    host, separator, port_text = text.rpartition(":")
    if separator != ":" or not port_text.isdigit():
        fail(f"{label} is not a canonical IPv4 socket")
    address = parse_private_ipv4(host, f"{label}.address")
    if len(port_text) > 1 and port_text.startswith("0"):
        fail(f"{label} has a non-canonical port")
    port = int(port_text)
    if not 1 <= port <= 65535:
        fail(f"{label} has an out-of-range port")
    return address, port


def parse_relay_origin(value: Any, label: str) -> str:
    origin = exact_string(value, label, maximum=128)
    try:
        parsed = urlsplit(origin)
        port = parsed.port
    except ValueError:
        fail(f"{label} is not a canonical HTTPS origin")
    if (
        parsed.scheme != "https"
        or parsed.username is not None
        or parsed.password is not None
        or parsed.hostname is None
        or port is None
        or parsed.path not in {"", "/"}
        or parsed.query
        or parsed.fragment
    ):
        fail(f"{label} is not a canonical HTTPS origin")
    try:
        address = ipaddress.ip_address(parsed.hostname)
    except ValueError:
        if SAFE_NAME.fullmatch(parsed.hostname) is None:
            fail(f"{label} has a malformed host")
    else:
        if type(address) is not ipaddress.IPv4Address or not address.is_private:
            fail(f"{label} does not use a private experiment address")
    return origin


def validate_topology(value: Any, cell: str) -> dict[str, str]:
    topology = exact_object(value, TOPOLOGY_KEYS, f"cells.{cell}.topology")
    for field, expected in TOPOLOGY[cell].items():
        exact_string(
            topology[field],
            f"cells.{cell}.topology.{field}",
            expected=expected,
        )
    return topology


def validate_infrastructure(value: Any, cell: str) -> None:
    infrastructure = exact_object(
        value, INFRASTRUCTURE_KEYS, f"cells.{cell}.infrastructure"
    )
    exact_bool(
        infrastructure["controlled_relay"],
        f"cells.{cell}.infrastructure.controlled_relay",
        expected=cell == "restrictive-relay",
    )
    for field in (
        "hosted_discovery",
        "public_relay",
        "default_relay",
        "public_relay_fallback",
        "port_mapper",
    ):
        exact_bool(
            infrastructure[field],
            f"cells.{cell}.infrastructure.{field}",
            expected=False,
        )


def validate_endpoints(value: Any, cell: str) -> list[dict[str, Any]]:
    endpoints = exact_array(value, 2, f"cells.{cell}.endpoints")
    for index, role in enumerate(ENDPOINT_ROLES):
        endpoint = exact_object(
            endpoints[index], ENDPOINT_KEYS, f"cells.{cell}.endpoints[{index}]"
        )
        exact_string(
            endpoint["role"],
            f"cells.{cell}.endpoints[{index}].role",
            expected=role,
        )
        hex_32(endpoint["carrier_id"], f"cells.{cell}.endpoints[{index}].carrier_id")
        hex_32(endpoint["mission_id"], f"cells.{cell}.endpoints[{index}].mission_id")
        exact_bool(
            endpoint["fresh"], f"cells.{cell}.endpoints[{index}].fresh", expected=True
        )
    if endpoints[0]["carrier_id"] == endpoints[1]["carrier_id"]:
        fail(f"cells.{cell}.endpoints carrier identities are not distinct")
    if endpoints[0]["mission_id"] == endpoints[1]["mission_id"]:
        fail(f"cells.{cell}.endpoints mission identities are not distinct")
    return endpoints


def validate_event(value: Any, cell: str, endpoints: list[dict[str, Any]]) -> dict[str, Any]:
    event = exact_object(value, EVENT_KEYS, f"cells.{cell}.event")
    hex_32(event["event_id"], f"cells.{cell}.event.event_id")
    publisher = hex_32(event["publisher"], f"cells.{cell}.event.publisher")
    if publisher != endpoints[0]["mission_id"]:
        fail(f"cells.{cell}.event publisher is not the sender mission identity")
    payload_sha256 = hex_32(
        event["payload_sha256"], f"cells.{cell}.event.payload_sha256"
    )
    exact_string(
        event["sealed_sha256"],
        f"cells.{cell}.event.sealed_sha256",
        expected="not-exposed-by-production-api",
    )
    canary_sha256 = hex_32(
        event["canary_sha256"], f"cells.{cell}.event.canary_sha256"
    )
    if payload_sha256 != canary_sha256:
        fail(f"cells.{cell}.event payload is not the exact fresh canary")
    bounded_int(event["payload_bytes"], f"cells.{cell}.event.payload_bytes", expected=32)
    bounded_int(event["source_sequence"], f"cells.{cell}.event.source_sequence", expected=1)
    exact_bool(
        event["source_inserted"], f"cells.{cell}.event.source_inserted", expected=True
    )
    bounded_int(
        event["destination_deliveries"],
        f"cells.{cell}.event.destination_deliveries",
        expected=1,
    )
    bounded_int(
        event["destination_attempt"],
        f"cells.{cell}.event.destination_attempt",
        expected=1,
    )
    for field in (
        "acknowledged",
        "empty_after_ack",
        "exact_query",
        "exact_event_id_match",
    ):
        exact_bool(event[field], f"cells.{cell}.event.{field}", expected=True)
    exact_string(event["replay_ack"], f"cells.{cell}.event.replay_ack", expected="noop")
    exact_string(
        event["replay_subscription"],
        f"cells.{cell}.event.replay_subscription",
        expected="noop",
    )
    return event


def validate_reconciliation(value: Any, cell: str) -> None:
    receipt = exact_object(value, RECONCILIATION_KEYS, f"cells.{cell}.reconciliation")
    exact_string(receipt["status"], f"cells.{cell}.reconciliation.status", expected="pass")
    bounded_int(
        receipt["contacts"],
        f"cells.{cell}.reconciliation.contacts",
        minimum=1,
        maximum=MAX_SESSIONS,
    )
    for field in RECONCILIATION_KEYS - {"status", "contacts"}:
        bounded_int(
            receipt[field],
            f"cells.{cell}.reconciliation.{field}",
            expected=0,
        )


def validate_path(value: Any, cell: str) -> None:
    path = exact_object(value, PATH_KEYS, f"cells.{cell}.path")
    witnesses = exact_array(path["witnesses"], 2, f"cells.{cell}.path.witnesses")
    expected_selected = "Direct" if cell == "cone-direct" else "Relay"
    for index, role in enumerate(ENDPOINT_ROLES):
        witness = exact_object(
            witnesses[index],
            PATH_WITNESS_KEYS,
            f"cells.{cell}.path.witnesses[{index}]",
        )
        exact_string(
            witness["role"],
            f"cells.{cell}.path.witnesses[{index}].role",
            expected=role,
        )
        exact_string(
            witness["selected"],
            f"cells.{cell}.path.witnesses[{index}].selected",
            expected=expected_selected,
        )
        bounded_int(
            witness["transition_count"],
            f"cells.{cell}.path.witnesses[{index}].transition_count",
            maximum=MAX_TRANSITIONS,
        )
        exact_bool(
            witness["transitions_saturated"],
            f"cells.{cell}.path.witnesses[{index}].transitions_saturated",
            expected=False,
        )


def validate_nft(
    value: Any, cell: str, *, cone_initiator_router: str | None = None
) -> None:
    nft = exact_object(value, NFT_KEYS, f"cells.{cell}.nft")
    exact_string(nft["namespace"], f"cells.{cell}.nft.namespace", expected="nat-a,nat-b")
    names = CONE_NFT_NAMES if cell == "cone-direct" else RESTRICTIVE_NFT_NAMES
    counters = exact_array(nft["counters"], len(names) * 2, f"cells.{cell}.nft.counters")
    expected_pairs = [(router, name) for router in ("nat-a", "nat-b") for name in names]
    deltas: dict[tuple[str, str], tuple[int, int]] = {}
    for index, (router, name) in enumerate(expected_pairs):
        counter = exact_object(
            counters[index], NFT_COUNTER_KEYS, f"cells.{cell}.nft.counters[{index}]"
        )
        exact_string(
            counter["router"],
            f"cells.{cell}.nft.counters[{index}].router",
            expected=router,
        )
        exact_string(
            counter["name"],
            f"cells.{cell}.nft.counters[{index}].name",
            expected=name,
        )
        values = {
            field: bounded_int(
                counter[field], f"cells.{cell}.nft.counters[{index}].{field}"
            )
            for field in NFT_COUNTER_KEYS - {"router", "name"}
        }
        if values["after_packets"] - values["before_packets"] != values["delta_packets"]:
            fail(f"cells.{cell}.nft.counters[{index}] packet delta is inconsistent")
        if values["after_bytes"] - values["before_bytes"] != values["delta_bytes"]:
            fail(f"cells.{cell}.nft.counters[{index}] byte delta is inconsistent")
        if (values["delta_packets"] == 0) != (values["delta_bytes"] == 0):
            fail(f"cells.{cell}.nft.counters[{index}] packet/byte activity disagrees")
        if values["before_packets"] != 0 or values["before_bytes"] != 0:
            fail(f"cells.{cell}.nft.counters[{index}] fresh counter baseline is nonzero")
        protocol_minimum = (
            28
            if cell == "cone-direct" or name == "aster_restrict_direct_drop"
            else 40
        )
        for prefix in ("after", "delta"):
            if values[f"{prefix}_bytes"] < (
                values[f"{prefix}_packets"] * protocol_minimum
            ):
                fail(
                    f"cells.{cell}.nft.counters[{index}] byte count is below "
                    "its protocol header floor"
                )
        deltas[(router, name)] = (values["delta_packets"], values["delta_bytes"])

    if cell == "cone-direct":
        if cone_initiator_router not in {"nat-a", "nat-b"}:
            fail("cone-direct nft evidence lacks its identity-bound initiator router")
        for router in ("nat-a", "nat-b"):
            for name in ("aster_cone_forward_in", "aster_cone_forward_out"):
                packets, bytes_value = deltas[(router, name)]
                if packets <= 0 or bytes_value <= 0:
                    fail(
                        f"cells.{cell}.nft {router}/{name} required delta is not positive"
                    )
        snat_routers = {
            router
            for router in ("nat-a", "nat-b")
            if deltas[(router, "aster_cone_snat")] != (0, 0)
        }
        dnat_routers = {
            router
            for router in ("nat-a", "nat-b")
            if deltas[(router, "aster_cone_dnat")] != (0, 0)
        }
        if len(snat_routers) != 1 or len(dnat_routers) != 1:
            fail(
                "cone-direct nft evidence does not contain exactly one active "
                "SNAT and one active DNAT hook"
            )
        if snat_routers == dnat_routers:
            fail("cone-direct nft SNAT and DNAT hooks are not on opposite routers")
        if snat_routers != {cone_initiator_router}:
            fail("cone-direct nft SNAT hook is not on the lower-carrier-ID router")
        expected_responder = "nat-b" if cone_initiator_router == "nat-a" else "nat-a"
        if dnat_routers != {expected_responder}:
            fail("cone-direct nft DNAT hook is not on the higher-carrier-ID router")
        return

    for router in ("nat-a", "nat-b"):
        for name in ("aster_restrict_relay_https", "aster_restrict_established"):
            packets, bytes_value = deltas[(router, name)]
            if packets <= 0 or bytes_value <= 0:
                fail(f"cells.{cell}.nft {router}/{name} required delta is not positive")
        packets, bytes_value = deltas[(router, "aster_restrict_relay_http")]
        if packets != 0 or bytes_value != 0:
            fail(f"cells.{cell}.nft {router} unexpectedly observed relay HTTP")
    drop_deltas = [
        deltas[(router, "aster_restrict_direct_drop")]
        for router in ("nat-a", "nat-b")
    ]
    if sum(value[0] for value in drop_deltas) <= 0 or sum(
        value[1] for value in drop_deltas
    ) <= 0:
        fail("restrictive-relay nft evidence lacks an aggregate direct drop")


def validate_pcap(value: Any, cell: str) -> dict[str, Any]:
    pcap = exact_object(value, PCAP_KEYS, f"cells.{cell}.pcap")
    captures = exact_array(pcap["captures"], 2, f"cells.{cell}.pcap.captures")
    captured_packets = 0
    for index, role in enumerate(PCAP_ROLES):
        capture = exact_object(
            captures[index], PCAP_CAPTURE_KEYS, f"cells.{cell}.pcap.captures[{index}]"
        )
        exact_string(
            capture["role"],
            f"cells.{cell}.pcap.captures[{index}].role",
            expected=role,
        )
        capture_bytes = bounded_int(
            capture["bytes"],
            f"cells.{cell}.pcap.captures[{index}].bytes",
            minimum=24,
            maximum=MAX_PCAP_BYTES,
        )
        packet_count = bounded_int(
            capture["packets"],
            f"cells.{cell}.pcap.captures[{index}].packets",
            minimum=1,
        )
        captured_packets += packet_count
        if capture_bytes < 24 + 16 * packet_count:
            fail(f"cells.{cell}.pcap.captures[{index}] is too small for its records")
        bounded_int(
            capture["dropped_packets"],
            f"cells.{cell}.pcap.captures[{index}].dropped_packets",
            expected=0,
        )
        hex_32(capture["sha256"], f"cells.{cell}.pcap.captures[{index}].sha256")
        exact_string(
            capture["manifest_role"],
            f"cells.{cell}.pcap.captures[{index}].manifest_role",
            expected=f"{role}-pcap",
        )
    hex_32(pcap["tuple_summary_sha256"], f"cells.{cell}.pcap.tuple_summary_sha256")
    proof = exact_object(
        pcap["tuple_proof"], PCAP_TUPLE_KEYS, f"cells.{cell}.pcap.tuple_proof"
    )
    values = {
        field: bounded_int(proof[field], f"cells.{cell}.pcap.tuple_proof.{field}")
        for field in PCAP_TUPLE_KEYS
    }
    if any(value > captured_packets for value in values.values()):
        fail(f"cells.{cell}.pcap tuple proof exceeds captured packet counts")
    if values["unexpected_public_relay_packets"] != 0:
        fail(f"cells.{cell}.pcap observed unexpected public relay traffic")
    if values["unexpected_hosted_discovery_packets"] != 0:
        fail(f"cells.{cell}.pcap observed unexpected hosted discovery traffic")
    if cell == "cone-direct":
        if values["direct_probe_packets"] <= 0:
            fail("cone-direct pcap tuple proof lacks direct probes")
        if values["direct_cross_nat_packets"] <= 0:
            fail("cone-direct pcap lacks a successful cross-NAT direct tuple")
        if values["direct_cross_nat_packets"] != values["direct_probe_packets"]:
            fail("cone-direct pcap direct tuple and probe counts differ")
        if values["controlled_relay_https_packets"] != 0:
            fail("cone-direct pcap unexpectedly contains controlled-relay HTTPS")
        if values["controlled_relay_http_packets"] != 0:
            fail("cone-direct pcap unexpectedly contains controlled-relay HTTP")
    else:
        if values["direct_probe_packets"] != 0:
            fail("restrictive-relay WAN pcap unexpectedly contains a direct probe")
        if values["direct_cross_nat_packets"] != 0:
            fail("restrictive-relay pcap unexpectedly contains a direct cross-NAT tuple")
        if values["controlled_relay_https_packets"] <= 0:
            fail("restrictive-relay pcap lacks controlled-relay HTTPS")
        if values["controlled_relay_http_packets"] != 0:
            fail("restrictive-relay pcap unexpectedly contains relay HTTP")
    return pcap


def validate_relay(
    value: Any,
    cell: str,
    relay_origin: str,
    endpoints: list[dict[str, Any]],
) -> None:
    relay = exact_object(value, RELAY_KEYS, f"cells.{cell}.relay")
    exact_bool(relay["secrets_logged"], f"cells.{cell}.relay.secrets_logged", expected=False)
    numeric_fields = (
        "allowlist_count",
        "key_cache_capacity",
        "client_rx_bytes_per_second",
        "client_rx_max_burst_bytes",
        "max_admitted_connections",
        "observed_active_sessions_peak",
        "accepted_sessions",
        "rejected_sessions",
    )
    if cell == "cone-direct":
        for field, expected in (
            ("mode", "disabled"),
            ("origin", "none"),
            ("tls_mode", "not-applicable"),
            ("server_trust_claim", "not-applicable"),
            ("client_trust_mode", "not-applicable"),
            ("root_fingerprint_sha256", "not-applicable"),
            ("allowlist_mode", "not-applicable"),
            ("allowlist_sha256", "not-applicable"),
            ("pre_auth_connection_cap", "not-applicable"),
        ):
            exact_string(relay[field], f"cells.{cell}.relay.{field}", expected=expected)
        for field in numeric_fields:
            bounded_int(relay[field], f"cells.{cell}.relay.{field}", expected=0)
        return

    exact_string(relay["mode"], f"cells.{cell}.relay.mode", expected="controlled")
    origin = parse_relay_origin(relay["origin"], f"cells.{cell}.relay.origin")
    if origin != relay_origin:
        fail("restrictive-relay topology and relay origins differ")
    exact_string(
        relay["tls_mode"],
        f"cells.{cell}.relay.tls_mode",
        expected="manual-der-certificate",
    )
    exact_string(
        relay["server_trust_claim"],
        f"cells.{cell}.relay.server_trust_claim",
        expected="none",
    )
    exact_string(
        relay["client_trust_mode"],
        f"cells.{cell}.relay.client_trust_mode",
        expected="explicit-der-root-pin",
    )
    hex_32(
        relay["root_fingerprint_sha256"],
        f"cells.{cell}.relay.root_fingerprint_sha256",
    )
    exact_string(
        relay["allowlist_mode"],
        f"cells.{cell}.relay.allowlist_mode",
        expected="exact-cli-identities",
    )
    allowlist_sha256 = hex_32(
        relay["allowlist_sha256"], f"cells.{cell}.relay.allowlist_sha256"
    )
    expected_allowlist = sha256_bytes(
        ("\n".join(sorted(endpoint["carrier_id"] for endpoint in endpoints)) + "\n").encode(
            "ascii"
        )
    )
    if allowlist_sha256 != expected_allowlist:
        fail("restrictive-relay allowlist hash differs from its exact carrier IDs")
    bounded_int(
        relay["allowlist_count"], f"cells.{cell}.relay.allowlist_count", expected=2
    )
    bounded_int(
        relay["key_cache_capacity"],
        f"cells.{cell}.relay.key_cache_capacity",
        expected=256,
    )
    bounded_int(
        relay["client_rx_bytes_per_second"],
        f"cells.{cell}.relay.client_rx_bytes_per_second",
        expected=1_048_576,
    )
    bounded_int(
        relay["client_rx_max_burst_bytes"],
        f"cells.{cell}.relay.client_rx_max_burst_bytes",
        expected=1_048_576,
    )
    maximum = bounded_int(
        relay["max_admitted_connections"],
        f"cells.{cell}.relay.max_admitted_connections",
        expected=8,
    )
    exact_string(
        relay["pre_auth_connection_cap"],
        f"cells.{cell}.relay.pre_auth_connection_cap",
        expected="not-enforced",
    )
    peak = bounded_int(
        relay["observed_active_sessions_peak"],
        f"cells.{cell}.relay.observed_active_sessions_peak",
        minimum=1,
        maximum=maximum,
    )
    accepted = bounded_int(
        relay["accepted_sessions"],
        f"cells.{cell}.relay.accepted_sessions",
        minimum=1,
        maximum=MAX_COUNTER,
    )
    if accepted < peak:
        fail("restrictive-relay accepted fewer sessions than its observed peak")
    bounded_int(
        relay["rejected_sessions"],
        f"cells.{cell}.relay.rejected_sessions",
        expected=0,
    )


def validate_canary(value: Any, cell: str) -> None:
    scan = exact_object(value, CANARY_KEYS, f"cells.{cell}.canary_scan")
    classes = exact_array(
        scan["classes"], len(CANARY_CLASSES), f"cells.{cell}.canary_scan.classes"
    )
    if tuple(classes) != CANARY_CLASSES:
        fail(f"cells.{cell}.canary_scan classes are incomplete or reordered")
    expected_targets = ["finalized-public-artifacts", "wan-pcaps"]
    targets = exact_array(
        scan["scan_targets"], len(expected_targets), f"cells.{cell}.canary_scan.scan_targets"
    )
    if targets != expected_targets:
        fail(f"cells.{cell}.canary_scan targets are incomplete or reordered")
    positive = exact_object(
        scan["positive_control"],
        POSITIVE_CONTROL_KEYS,
        f"cells.{cell}.canary_scan.positive_control",
    )
    exact_string(
        positive["status"],
        f"cells.{cell}.canary_scan.positive_control.status",
        expected="pass",
    )
    expected = bounded_int(
        positive["expected_matches"],
        f"cells.{cell}.canary_scan.positive_control.expected_matches",
        expected=len(CANARY_CLASSES),
    )
    observed = bounded_int(
        positive["observed_matches"],
        f"cells.{cell}.canary_scan.positive_control.observed_matches",
        expected=len(CANARY_CLASSES),
    )
    positive_class_counts = exact_object(
        positive["class_match_counts"],
        set(CANARY_CLASSES),
        f"cells.{cell}.canary_scan.positive_control.class_match_counts",
    )
    for representation in CANARY_CLASSES:
        bounded_int(
            positive_class_counts[representation],
            (
                f"cells.{cell}.canary_scan.positive_control."
                f"class_match_counts.{representation}"
            ),
            expected=1,
        )
    if expected != observed:
        fail(f"cells.{cell}.canary_scan positive control did not detect every canary")
    chronology = exact_array(
        scan["chronology"],
        len(CANARY_CHRONOLOGY),
        f"cells.{cell}.canary_scan.chronology",
    )
    if tuple(chronology) != CANARY_CHRONOLOGY:
        fail(f"cells.{cell}.canary_scan chronology is incomplete or reordered")
    bounded_int(
        scan["artifacts_scanned"],
        f"cells.{cell}.canary_scan.artifacts_scanned",
        expected=11 if cell == "cone-direct" else 15,
    )
    class_match_counts = exact_object(
        scan["class_match_counts"],
        set(CANARY_CLASSES),
        f"cells.{cell}.canary_scan.class_match_counts",
    )
    for representation in CANARY_CLASSES:
        bounded_int(
            class_match_counts[representation],
            f"cells.{cell}.canary_scan.class_match_counts.{representation}",
            expected=0,
        )
    bounded_int(
        scan["match_count"], f"cells.{cell}.canary_scan.match_count", expected=0
    )


def validate_cleanup(value: Any, label: str, cell: str) -> None:
    cleanup = exact_object(value, CLEANUP_KEYS, label)
    exact_string(cleanup["status"], f"{label}.status", expected="pass")
    exact_string(
        cleanup["canary_control_file_disposition"],
        f"{label}.canary_control_file_disposition",
        expected="destroyed-and-unlinked",
    )
    bounded_int(
        cleanup["canary_control_file_previous_bytes"],
        f"{label}.canary_control_file_previous_bytes",
        expected=32,
    )
    exact_string(
        cleanup["relay_private_key_file_disposition"],
        f"{label}.relay_private_key_file_disposition",
        expected=(
            "not-created" if cell == "cone-direct" else "destroyed-and-unlinked"
        ),
    )
    exact_bool(
        cleanup["canary_control_file_absent_after_cleanup"],
        f"{label}.canary_control_file_absent_after_cleanup",
        expected=True,
    )
    exact_bool(
        cleanup["relay_private_key_file_absent_after_cleanup"],
        f"{label}.relay_private_key_file_absent_after_cleanup",
        expected=True,
    )
    exact_string(
        cleanup["assurance"],
        f"{label}.assurance",
        expected="bounded-software",
    )
    exact_string(
        cleanup["physical_sanitization"],
        f"{label}.physical_sanitization",
        expected="not-claimed",
    )
    for field in ("containers_remaining", "networks_remaining", "namespaces_remaining"):
        bounded_int(cleanup[field], f"{label}.{field}", expected=0)


def validate_cell(value: Any, expected_name: str) -> dict[str, Any]:
    cell = exact_object(value, CELL_KEYS, f"cells.{expected_name}")
    exact_string(cell["name"], f"cells.{expected_name}.name", expected=expected_name)
    exact_string(cell["status"], f"cells.{expected_name}.status", expected="pass")
    exact_string(
        cell["nat_profile"],
        f"cells.{expected_name}.nat_profile",
        expected="cone" if expected_name == "cone-direct" else "restrictive",
    )
    topology = validate_topology(cell["topology"], expected_name)
    validate_infrastructure(cell["infrastructure"], expected_name)
    endpoints = validate_endpoints(cell["endpoints"], expected_name)
    event = validate_event(cell["event"], expected_name, endpoints)
    validate_reconciliation(cell["reconciliation"], expected_name)
    validate_path(cell["path"], expected_name)
    cone_initiator_router = None
    if expected_name == "cone-direct":
        cone_initiator_router = (
            "nat-a"
            if endpoints[0]["carrier_id"] < endpoints[1]["carrier_id"]
            else "nat-b"
        )
    validate_nft(
        cell["nft"],
        expected_name,
        cone_initiator_router=cone_initiator_router,
    )
    pcap = validate_pcap(cell["pcap"], expected_name)
    validate_relay(
        cell["relay"], expected_name, topology["relay_origin"], endpoints
    )
    validate_canary(cell["canary_scan"], expected_name)
    validate_cleanup(cell["cleanup"], f"cells.{expected_name}.cleanup", expected_name)
    return {"raw": cell, "endpoints": endpoints, "event": event, "pcap": pcap}


def validate_manifest_path(value: Any, label: str) -> str:
    text = exact_string(value, label, maximum=192)
    if "\\" in text or text.startswith("/") or "//" in text:
        fail(f"{label} is not a canonical relative path")
    candidate = PurePosixPath(text)
    if any(part in {"", ".", ".."} for part in candidate.parts):
        fail(f"{label} is not a canonical relative path")
    if any(part.lower() == "private" for part in candidate.parts):
        fail(f"{label} names a forbidden private artifact directory")
    lowered = text.lower()
    inspected = lowered.replace("secret-cleanup.json", "")
    if any(forbidden in inspected for forbidden in FORBIDDEN_MANIFEST_PATH_PARTS):
        fail(f"{label} names a forbidden secret-bearing artifact")
    return text


def manifest_role_sets() -> dict[str, set[str]]:
    return {
        "global": set(GLOBAL_MANIFEST_PATHS),
        **{
            cell: set(COMMON_CELL_MANIFEST_PATHS)
            | set(CELL_EXTRA_MANIFEST_PATHS[cell])
            for cell in CELL_NAMES
        },
    }


def manifest_expected_paths() -> dict[str, dict[str, str]]:
    return {
        "global": dict(GLOBAL_MANIFEST_PATHS),
        **{
            cell: {
                **{
                    role: f"cells/{cell}/{relative}"
                    for role, relative in COMMON_CELL_MANIFEST_PATHS.items()
                },
                **{
                    role: f"cells/{cell}/{relative}"
                    for role, relative in CELL_EXTRA_MANIFEST_PATHS[cell].items()
                },
            }
            for cell in CELL_NAMES
        },
    }


def validate_manifest(value: Any, cells: dict[str, dict[str, Any]]) -> None:
    manifest = exact_object(value, MANIFEST_KEYS, "raw_manifest")
    exact_string(
        manifest["format"],
        "raw_manifest.format",
        expected="sha256-two-space-relative-v1",
    )
    exact_string(manifest["root_type"], "raw_manifest.root_type", expected="directory")
    exact_string(manifest["root_mode"], "raw_manifest.root_mode", expected="0700")
    exact_string(
        manifest["root_owner"], "raw_manifest.root_owner", expected="current-runner"
    )
    entries = exact_array(manifest["entries"], None, "raw_manifest.entries")
    if not entries or len(entries) > MAX_MANIFEST_RECORDS:
        fail("raw_manifest.entries is empty or exceeds its record cap")
    expected_roles = manifest_role_sets()
    expected_paths = manifest_expected_paths()
    seen_roles: dict[str, set[str]] = {scope: set() for scope in expected_roles}
    seen_paths: set[str] = set()
    normalized: list[tuple[str, str]] = []
    artifact_bytes = 0
    entry_by_role: dict[tuple[str, str], dict[str, Any]] = {}
    for index, raw_entry in enumerate(entries):
        label = f"raw_manifest.entries[{index}]"
        entry = exact_object(raw_entry, MANIFEST_ENTRY_KEYS, label)
        scope = exact_string(entry["cell"], f"{label}.cell", maximum=24)
        if scope not in expected_roles:
            fail(f"{label}.cell is outside the two cells and global scope")
        role = exact_string(entry["role"], f"{label}.role", pattern=SAFE_NAME)
        if role not in expected_roles[scope] or role in seen_roles[scope]:
            fail(f"{label}.role is missing, duplicated, or unexpected for its scope")
        seen_roles[scope].add(role)
        path = validate_manifest_path(entry["path"], f"{label}.path")
        if path != expected_paths[scope][role]:
            fail(f"{label}.path differs from the exact curated artifact path")
        if path in seen_paths:
            fail(f"{label}.path duplicates another artifact")
        seen_paths.add(path)
        exact_string(entry["type"], f"{label}.type", expected="regular")
        bounded_int(entry["nlink"], f"{label}.nlink", expected=1)
        size = bounded_int(
            entry["bytes"],
            f"{label}.bytes",
            minimum=1,
            maximum=MAX_ARTIFACT_BYTES,
        )
        digest = hex_32(entry["sha256"], f"{label}.sha256")
        exact_string(entry["mode"], f"{label}.mode", expected="0600")
        exact_string(entry["owner"], f"{label}.owner", expected="current-runner")
        sensitivity = exact_string(entry["sensitivity"], f"{label}.sensitivity")
        retention = exact_string(entry["retention"], f"{label}.retention")
        if role.endswith("-pcap"):
            if size < 24:
                fail(f"{label}.bytes is too small for a packet capture")
            if size > MAX_PCAP_BYTES:
                fail(f"{label}.bytes exceeds the packet-capture cap")
            if sensitivity != "restricted-pcap" or retention != "external-restricted":
                fail(f"{label} does not classify raw packet capture retention exactly")
        elif role in {"relay-ca-der", "relay-cert-der"}:
            if size <= 0:
                fail(f"{label}.bytes is empty for the public certificate")
            if sensitivity != "public-certificate" or retention != "retained-public":
                fail(f"{label} does not classify the public relay certificate exactly")
        else:
            if sensitivity not in {"public-metadata", "sanitized-log"}:
                fail(f"{label}.sensitivity is not a permitted sanitized class")
            if retention != "retained-sanitized":
                fail(f"{label}.retention is not the sanitized retention class")
        artifact_bytes += size
        normalized.append((path, digest))
        entry_by_role[(scope, role)] = entry

    if seen_roles != expected_roles:
        fail("raw_manifest does not contain the exact mandatory artifact role set")
    if [path for path, _ in normalized] != sorted(seen_paths):
        fail("raw_manifest entries are not ordered by canonical relative path")
    manifest_lines = b"".join(
        f"{digest}  {path}\n".encode("ascii") for path, digest in normalized
    )
    bounded_int(manifest["records"], "raw_manifest.records", expected=len(entries))
    bounded_int(
        manifest["manifest_bytes"],
        "raw_manifest.manifest_bytes",
        expected=len(manifest_lines),
    )
    bounded_int(
        manifest["artifact_bytes"],
        "raw_manifest.artifact_bytes",
        maximum=MAX_MANIFEST_ARTIFACT_BYTES,
        expected=artifact_bytes,
    )
    digest = hex_32(manifest["sha256"], "raw_manifest.sha256")
    if digest != sha256_bytes(manifest_lines):
        fail("raw_manifest.sha256 does not bind the canonical manifest")
    exact_string(
        manifest["secret_artifacts"],
        "raw_manifest.secret_artifacts",
        expected="excluded-from-curated-manifest-retained-external-restricted",
    )
    exact_string(
        manifest["pcap_contents"],
        "raw_manifest.pcap_contents",
        expected="external-restricted-not-embedded",
    )

    for cell in CELL_NAMES:
        captures = cells[cell]["pcap"]["captures"]
        for capture in captures:
            entry = entry_by_role[(cell, capture["manifest_role"])]
            if entry["bytes"] != capture["bytes"] or entry["sha256"] != capture["sha256"]:
                fail(f"raw_manifest packet capture metadata differs from cells.{cell}.pcap")
        summary = entry_by_role[(cell, "pcap-tuple-summary")]
        if summary["sha256"] != cells[cell]["pcap"]["tuple_summary_sha256"]:
            fail(f"raw_manifest tuple summary differs from cells.{cell}.pcap")


DIRECTORY_OPEN_FLAGS = (
    os.O_RDONLY
    | getattr(os, "O_CLOEXEC", 0)
    | getattr(os, "O_DIRECTORY", 0)
    | getattr(os, "O_NOFOLLOW", 0)
)
FILE_OPEN_FLAGS = (
    os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
)


def validate_open_directory(metadata: os.stat_result, label: str, *, root: bool) -> None:
    if not stat.S_ISDIR(metadata.st_mode):
        fail(f"{label} is not one directory")
    if metadata.st_uid != os.getuid():
        fail(f"{label} is not owned by the current runner")
    mode = stat.S_IMODE(metadata.st_mode)
    if (root and mode != 0o700) or (not root and mode & 0o022):
        fail(f"{label} has an unsafe mode")


def open_raw_root(root: Path) -> tuple[int, os.stat_result]:
    root_text = os.fspath(root)
    candidate = PurePosixPath(root_text)
    if not root_text.startswith("/") or str(candidate) != root_text:
        fail("raw root is not a canonical absolute path")
    try:
        descriptor = os.open("/", DIRECTORY_OPEN_FLAGS)
    except OSError:
        fail("raw root filesystem anchor could not be opened")
    try:
        for index, part in enumerate(candidate.parts[1:]):
            label = "raw root" if index == len(candidate.parts[1:]) - 1 else "raw root parent"
            try:
                before = os.stat(part, dir_fd=descriptor, follow_symlinks=False)
                following = os.open(part, DIRECTORY_OPEN_FLAGS, dir_fd=descriptor)
            except OSError:
                fail(f"{label} could not be opened as a non-symbolic directory")
            opened = os.fstat(following)
            if (before.st_dev, before.st_ino) != (opened.st_dev, opened.st_ino):
                os.close(following)
                fail(f"{label} changed identity while opening")
            os.close(descriptor)
            descriptor = following
        opened = os.fstat(descriptor)
        validate_open_directory(opened, "raw root", root=True)
        try:
            path_metadata = os.lstat(root)
        except OSError:
            fail("raw root path vanished while opening")
        if (path_metadata.st_dev, path_metadata.st_ino) != (
            opened.st_dev,
            opened.st_ino,
        ):
            fail("raw root path changed identity while opening")
        return descriptor, opened
    except BaseException:
        try:
            os.close(descriptor)
        except OSError:
            pass
        raise


def open_raw_parent(
    root_descriptor: int,
    relative: str,
    label: str,
    *,
    missing_ok: bool = False,
) -> tuple[int | None, str]:
    parts = PurePosixPath(relative).parts
    if not parts or any(part in {"", ".", ".."} for part in parts):
        fail(f"{label} is not a canonical raw-root path")
    current = os.dup(root_descriptor)
    try:
        for part in parts[:-1]:
            try:
                following = os.open(part, DIRECTORY_OPEN_FLAGS, dir_fd=current)
            except FileNotFoundError:
                if missing_ok:
                    os.close(current)
                    return None, parts[-1]
                fail(f"{label} has a missing parent directory")
            except OSError:
                fail(f"{label} has an unsafe parent directory")
            os.close(current)
            current = following
            validate_open_directory(os.fstat(current), f"{label} parent", root=False)
        return current, parts[-1]
    except BaseException:
        try:
            os.close(current)
        except OSError:
            pass
        raise


def validate_open_regular(
    metadata: os.stat_result,
    label: str,
    *,
    expected_size: int | None = None,
) -> None:
    if not stat.S_ISREG(metadata.st_mode):
        fail(f"{label} is not one plain regular file")
    if metadata.st_nlink != 1 or metadata.st_uid != os.getuid():
        fail(f"{label} has an unsafe link count or owner")
    if stat.S_IMODE(metadata.st_mode) != 0o600:
        fail(f"{label} is not mode 0600")
    if expected_size is not None and metadata.st_size != expected_size:
        fail(f"{label} byte count differs")


def recheck_open_regular(
    parent_descriptor: int,
    name: str,
    descriptor: int,
    opened: os.stat_result,
    label: str,
    expected_size: int,
) -> None:
    final = os.fstat(descriptor)
    try:
        path_final = os.stat(name, dir_fd=parent_descriptor, follow_symlinks=False)
    except OSError:
        fail(f"{label} path vanished during inspection")
    for metadata in (final, path_final):
        validate_open_regular(metadata, label, expected_size=expected_size)
        if (metadata.st_dev, metadata.st_ino) != (opened.st_dev, opened.st_ino):
            fail(f"{label} changed identity during inspection")


def verify_raw_entry(root_descriptor: int, entry: dict[str, Any], index: int) -> None:
    label = f"raw_manifest.entries[{index}] curated artifact"
    parent, name = open_raw_parent(root_descriptor, entry["path"], label)
    if parent is None:
        fail(f"{label} parent unexpectedly disappeared")
    try:
        try:
            descriptor = os.open(name, FILE_OPEN_FLAGS, dir_fd=parent)
        except OSError:
            fail(f"{label} could not be opened safely")
        try:
            opened = os.fstat(descriptor)
            validate_open_regular(opened, label, expected_size=entry["bytes"])
            digest = hashlib.sha256()
            observed_bytes = 0
            while True:
                chunk = os.read(descriptor, 1024 * 1024)
                if not chunk:
                    break
                observed_bytes += len(chunk)
                if observed_bytes > entry["bytes"]:
                    fail(f"{label} grew while hashing")
                digest.update(chunk)
            if observed_bytes != entry["bytes"] or digest.hexdigest() != entry["sha256"]:
                fail(f"{label} size or SHA-256 differs")
            recheck_open_regular(
                parent, name, descriptor, opened, label, entry["bytes"]
            )
        except OSError:
            fail(f"{label} could not be hashed safely")
        finally:
            os.close(descriptor)
    finally:
        os.close(parent)


def read_raw_scanned_file(
    root_descriptor: int,
    relative: str,
    label: str,
    *,
    expected_size: int,
    expected_sha256: str,
    maximum: int = 16 * 1024 * 1024,
) -> bytes:
    if expected_size < 0 or expected_size > maximum:
        fail(f"{label} is outside its scan byte cap")
    parent, name = open_raw_parent(root_descriptor, relative, label)
    if parent is None:
        fail(f"{label} parent unexpectedly disappeared")
    try:
        try:
            descriptor = os.open(name, FILE_OPEN_FLAGS, dir_fd=parent)
        except OSError:
            fail(f"{label} could not be opened safely")
        try:
            opened = os.fstat(descriptor)
            validate_open_regular(opened, label, expected_size=expected_size)
            chunks: list[bytes] = []
            observed = 0
            digest = hashlib.sha256()
            while observed <= maximum:
                chunk = os.read(descriptor, min(64 * 1024, maximum + 1 - observed))
                if not chunk:
                    break
                observed += len(chunk)
                chunks.append(chunk)
                digest.update(chunk)
            if (
                observed != expected_size
                or observed > maximum
                or digest.hexdigest() != expected_sha256
            ):
                fail(f"{label} size or SHA-256 differs")
            recheck_open_regular(
                parent, name, descriptor, opened, label, expected_size
            )
        except OSError:
            fail(f"{label} could not be read safely")
        finally:
            os.close(descriptor)
    finally:
        os.close(parent)
    return b"".join(chunks)


def verify_absent_raw_path(
    root_descriptor: int, relative: str, label: str
) -> None:
    parent, name = open_raw_parent(
        root_descriptor, relative, label, missing_ok=True
    )
    if parent is None:
        return
    try:
        try:
            os.stat(name, dir_fd=parent, follow_symlinks=False)
        except FileNotFoundError:
            return
        except OSError:
            fail(f"{label} absence could not be inspected")
        fail(f"{label} is still present after bounded cleanup")
    finally:
        os.close(parent)


def open_raw_restricted_directory(
    root_descriptor: int, relative: str, label: str
) -> int:
    parent, name = open_raw_parent(root_descriptor, relative, label)
    if parent is None:
        fail(f"{label} parent unexpectedly disappeared")
    descriptor: int | None = None
    try:
        before = os.stat(name, dir_fd=parent, follow_symlinks=False)
        descriptor = os.open(name, DIRECTORY_OPEN_FLAGS, dir_fd=parent)
        opened = os.fstat(descriptor)
    except OSError:
        if descriptor is not None:
            os.close(descriptor)
        os.close(parent)
        fail(f"{label} is not a safe retained restricted directory")
    if (
        not stat.S_ISDIR(opened.st_mode)
        or opened.st_uid != os.getuid()
        or stat.S_IMODE(opened.st_mode) != 0o700
        or (before.st_dev, before.st_ino) != (opened.st_dev, opened.st_ino)
    ):
        os.close(descriptor)
        os.close(parent)
        fail(f"{label} retained restricted directory metadata differs")
    try:
        final_path = os.stat(name, dir_fd=parent, follow_symlinks=False)
    except OSError:
        os.close(descriptor)
        os.close(parent)
        fail(f"{label} retained restricted directory path vanished")
    os.close(parent)
    if (
        not stat.S_ISDIR(final_path.st_mode)
        or final_path.st_uid != os.getuid()
        or stat.S_IMODE(final_path.st_mode) != 0o700
        or (final_path.st_dev, final_path.st_ino) != (opened.st_dev, opened.st_ino)
    ):
        os.close(descriptor)
        fail(f"{label} retained restricted directory path changed")
    return descriptor


def recheck_raw_restricted_directory(
    root_descriptor: int,
    relative: str,
    descriptor: int,
    opened: os.stat_result,
    label: str,
) -> None:
    final = os.fstat(descriptor)
    parent, name = open_raw_parent(root_descriptor, relative, label)
    if parent is None:
        fail(f"{label} parent unexpectedly disappeared")
    try:
        try:
            path_final = os.stat(name, dir_fd=parent, follow_symlinks=False)
        except OSError:
            fail(f"{label} path vanished during metadata inspection")
    finally:
        os.close(parent)
    for metadata in (final, path_final):
        if (
            not stat.S_ISDIR(metadata.st_mode)
            or metadata.st_uid != os.getuid()
            or stat.S_IMODE(metadata.st_mode) != 0o700
            or (metadata.st_dev, metadata.st_ino)
            != (opened.st_dev, opened.st_ino)
        ):
            fail(f"{label} changed during metadata inspection")


def inspect_raw_restricted_regular(
    parent_descriptor: int,
    name: str,
    before: os.stat_result,
    label: str,
    *,
    require_nonempty: bool,
) -> int:
    try:
        descriptor = os.open(name, FILE_OPEN_FLAGS, dir_fd=parent_descriptor)
    except OSError:
        fail(f"{label} could not be opened safely")
    try:
        opened = os.fstat(descriptor)
        validate_open_regular(opened, label)
        if (opened.st_dev, opened.st_ino) != (before.st_dev, before.st_ino):
            fail(f"{label} changed identity while opening")
        if opened.st_size > 512 * 1024 * 1024 or (
            require_nonempty and opened.st_size <= 0
        ):
            fail(f"{label} size differs")
        recheck_open_regular(
            parent_descriptor,
            name,
            descriptor,
            opened,
            label,
            opened.st_size,
        )
        return opened.st_size
    except OSError:
        fail(f"{label} could not be inspected safely")
    finally:
        os.close(descriptor)


def walk_raw_restricted_state(
    descriptor: int,
    label: str,
    *,
    maximum_files: int = 4_094,
    depth: int = 0,
    budget: dict[str, int] | None = None,
) -> tuple[int, int]:
    if budget is None:
        budget = {"directories": 0, "entries": 0}
    if depth > 32:
        fail(f"{label} exceeds the retained-state depth bound")
    budget["directories"] += 1
    if budget["directories"] > 4_096:
        fail(f"{label} exceeds the retained-state directory bound")
    files = 0
    total_bytes = 0
    try:
        names = sorted(os.listdir(descriptor))
    except OSError:
        fail(f"{label} could not be enumerated safely")
    if len(names) > 4_096:
        fail(f"{label} contains too many directory entries")
    budget["entries"] += len(names)
    if budget["entries"] > 8_192:
        fail(f"{label} exceeds the retained-state total entry bound")
    for name in names:
        if not name or name in {".", ".."} or "/" in name or "\x00" in name:
            fail(f"{label} contains a noncanonical entry name")
        try:
            metadata = os.stat(name, dir_fd=descriptor, follow_symlinks=False)
        except OSError:
            fail(f"{label}/{name} could not be inspected safely")
        child_label = f"{label}/{name}"
        if stat.S_ISDIR(metadata.st_mode):
            if metadata.st_uid != os.getuid() or stat.S_IMODE(metadata.st_mode) != 0o700:
                fail(f"{child_label} directory metadata differs")
            try:
                child = os.open(name, DIRECTORY_OPEN_FLAGS, dir_fd=descriptor)
            except OSError:
                fail(f"{child_label} could not be opened safely")
            try:
                opened = os.fstat(child)
                if (opened.st_dev, opened.st_ino) != (metadata.st_dev, metadata.st_ino):
                    fail(f"{child_label} changed identity while opening")
                if (
                    not stat.S_ISDIR(opened.st_mode)
                    or opened.st_uid != os.getuid()
                    or stat.S_IMODE(opened.st_mode) != 0o700
                ):
                    fail(f"{child_label} opened directory metadata differs")
                child_files, child_bytes = walk_raw_restricted_state(
                    child,
                    child_label,
                    maximum_files=maximum_files - files,
                    depth=depth + 1,
                    budget=budget,
                )
                final = os.fstat(child)
                path_final = os.stat(
                    name, dir_fd=descriptor, follow_symlinks=False
                )
                for observed in (final, path_final):
                    if (
                        not stat.S_ISDIR(observed.st_mode)
                        or observed.st_uid != os.getuid()
                        or stat.S_IMODE(observed.st_mode) != 0o700
                        or (observed.st_dev, observed.st_ino)
                        != (opened.st_dev, opened.st_ino)
                    ):
                        fail(f"{child_label} changed during enumeration")
            finally:
                os.close(child)
            files += child_files
            total_bytes += child_bytes
        elif stat.S_ISREG(metadata.st_mode):
            observed_size = inspect_raw_restricted_regular(
                descriptor,
                name,
                metadata,
                child_label,
                require_nonempty=False,
            )
            files += 1
            total_bytes += observed_size
        else:
            fail(f"{child_label} is a special or symbolic retained entry")
        if files > maximum_files or total_bytes > 1024 * 1024 * 1024:
            fail(f"{label} retained state exceeds its fixed bounds")
    try:
        final_names = sorted(os.listdir(descriptor))
    except OSError:
        fail(f"{label} could not be re-enumerated safely")
    if final_names != names:
        fail(f"{label} entries changed during metadata inspection")
    return files, total_bytes


def validate_raw_restricted_state(
    root_descriptor: int,
    profile: str,
    containment: dict[str, Any],
) -> None:
    base = f"cells/{profile}/outputs/provision"
    traversal_budget = {"directories": 1, "entries": 2}
    private = open_raw_restricted_directory(
        root_descriptor, f"{base}/private", f"cells.{profile}.private"
    )
    private_opened = os.fstat(private)
    bundle_bytes = 0
    try:
        names = sorted(os.listdir(private))
        if names != ["node-a.bundle", "node-b.bundle"]:
            fail(f"cells.{profile}.private entries differ")
        for name in names:
            metadata = os.stat(name, dir_fd=private, follow_symlinks=False)
            bundle_bytes += inspect_raw_restricted_regular(
                private,
                name,
                metadata,
                f"cells.{profile}.private/{name}",
                require_nonempty=True,
            )
        if sorted(os.listdir(private)) != names:
            fail(f"cells.{profile}.private entries changed during inspection")
    except OSError:
        fail(f"cells.{profile}.private could not be enumerated safely")
    finally:
        recheck_raw_restricted_directory(
            root_descriptor,
            f"{base}/private",
            private,
            private_opened,
            f"cells.{profile}.private",
        )
        os.close(private)
    state_files = 0
    state_bytes = 0
    for node in ("node-a", "node-b"):
        state = open_raw_restricted_directory(
            root_descriptor, f"{base}/{node}", f"cells.{profile}.{node} state"
        )
        state_opened = os.fstat(state)
        try:
            files, observed_bytes = walk_raw_restricted_state(
                state,
                f"cells.{profile}.{node} state",
                maximum_files=4_094 - state_files,
                budget=traversal_budget,
            )
        finally:
            recheck_raw_restricted_directory(
                root_descriptor,
                f"{base}/{node}",
                state,
                state_opened,
                f"cells.{profile}.{node} state",
            )
            os.close(state)
        state_files += files
        state_bytes += observed_bytes
    if profile == "restrictive-relay":
        traversal_budget["directories"] += 1
        if traversal_budget["directories"] > 4_096:
            fail(f"cells.{profile} exceeds the retained-state directory bound")
        relay_private = open_raw_restricted_directory(
            root_descriptor,
            f"{base}/relay/private",
            f"cells.{profile}.relay private",
        )
        relay_private_opened = os.fstat(relay_private)
        try:
            initial_relay_names = sorted(os.listdir(relay_private))
            if initial_relay_names:
                fail(f"cells.{profile}.relay private is not empty after cleanup")
            if sorted(os.listdir(relay_private)) != initial_relay_names:
                fail(f"cells.{profile}.relay private changed during inspection")
        finally:
            recheck_raw_restricted_directory(
                root_descriptor,
                f"{base}/relay/private",
                relay_private,
                relay_private_opened,
                f"cells.{profile}.relay private",
            )
            os.close(relay_private)
    raw_equal(state_files, containment["state_files"], f"cells.{profile}.state_files")
    raw_equal(
        state_files + 2,
        containment["retained_files"],
        f"cells.{profile}.retained_files",
    )
    raw_equal(
        state_bytes + bundle_bytes,
        containment["retained_bytes"],
        f"cells.{profile}.retained_bytes",
    )


def load_raw_json(
    root_descriptor: int,
    relative: str,
    label: str,
    *,
    entries: dict[tuple[str, str], dict[str, Any]],
    maximum: int = 8 * 1024 * 1024,
) -> Any:
    manifest_entry = manifest_entry_for_path(entries, relative, label)
    expected_size = manifest_entry["bytes"]
    expected_sha256 = manifest_entry["sha256"]
    if expected_size <= 0 or expected_size > maximum:
        fail(f"{label} manifest size is outside its JSON byte cap")
    parent, name = open_raw_parent(root_descriptor, relative, label)
    if parent is None:
        fail(f"{label} parent unexpectedly disappeared")
    try:
        try:
            descriptor = os.open(name, FILE_OPEN_FLAGS, dir_fd=parent)
        except OSError:
            fail(f"{label} could not be opened safely")
        try:
            opened = os.fstat(descriptor)
            validate_open_regular(opened, label, expected_size=expected_size)
            data = b""
            digest = hashlib.sha256()
            while len(data) <= maximum:
                chunk = os.read(descriptor, min(64 * 1024, maximum + 1 - len(data)))
                if not chunk:
                    break
                data += chunk
                digest.update(chunk)
            if (
                len(data) != expected_size
                or len(data) > maximum
                or digest.hexdigest() != expected_sha256
            ):
                fail(f"{label} differs from its curated manifest authority")
            recheck_open_regular(
                parent, name, descriptor, opened, label, expected_size
            )
        except OSError:
            fail(f"{label} could not be read safely")
        finally:
            os.close(descriptor)
    finally:
        os.close(parent)
    if b"\x00" in data or b"\r" in data or not data.endswith(b"\n"):
        fail(f"{label} has a forbidden or truncated encoding")
    try:
        value = json.loads(
            data.decode("utf-8", errors="strict"),
            object_pairs_hook=duplicate_safe_object,
            parse_constant=reject_json_constant,
        )
    except (UnicodeDecodeError, json.JSONDecodeError):
        fail(f"{label} is not duplicate-safe UTF-8 JSON")
    canonical = (json.dumps(value, indent=2, sort_keys=True) + "\n").encode("utf-8")
    if canonical != data:
        fail(f"{label} is not canonical sorted controller JSON")
    return value


def load_raw_text(
    root_descriptor: int,
    relative: str,
    label: str,
    *,
    entries: dict[tuple[str, str], dict[str, Any]],
    maximum: int = 16 * 1024 * 1024,
) -> str:
    manifest_entry = manifest_entry_for_path(entries, relative, label)
    expected_size = manifest_entry["bytes"]
    expected_sha256 = manifest_entry["sha256"]
    if expected_size <= 0 or expected_size > maximum:
        fail(f"{label} manifest size is outside its text byte cap")
    parent, name = open_raw_parent(root_descriptor, relative, label)
    if parent is None:
        fail(f"{label} parent unexpectedly disappeared")
    try:
        try:
            descriptor = os.open(name, FILE_OPEN_FLAGS, dir_fd=parent)
        except OSError:
            fail(f"{label} could not be opened safely")
        try:
            opened = os.fstat(descriptor)
            validate_open_regular(opened, label, expected_size=expected_size)
            chunks: list[bytes] = []
            observed = 0
            digest = hashlib.sha256()
            while observed <= maximum:
                chunk = os.read(descriptor, min(64 * 1024, maximum + 1 - observed))
                if not chunk:
                    break
                chunks.append(chunk)
                observed += len(chunk)
                digest.update(chunk)
            if (
                observed != expected_size
                or observed > maximum
                or digest.hexdigest() != expected_sha256
            ):
                fail(f"{label} differs from its curated manifest authority")
            recheck_open_regular(
                parent, name, descriptor, opened, label, expected_size
            )
        except OSError:
            fail(f"{label} could not be read safely")
        finally:
            os.close(descriptor)
    finally:
        os.close(parent)
    data = b"".join(chunks)
    if b"\x00" in data or b"\r" in data or not data.endswith(b"\n"):
        fail(f"{label} has a forbidden or truncated text encoding")
    try:
        return data.decode("utf-8", errors="strict")
    except UnicodeDecodeError:
        fail(f"{label} is not UTF-8 text")


def parse_raw_receipt_line(line: str, prefix: str, label: str) -> dict[str, str]:
    if not line.startswith(f"{prefix} "):
        fail(f"{label} does not start with {prefix}")
    try:
        tokens = shlex.split(line, posix=True)
    except ValueError:
        fail(f"{label} contains malformed shell quoting")
    if not tokens or tokens[0] != prefix:
        fail(f"{label} has an unexpected receipt prefix")
    fields: dict[str, str] = {}
    for token in tokens[1:]:
        if "=" not in token:
            fail(f"{label} contains an unkeyed token")
        key, value = token.split("=", 1)
        if not re.fullmatch(r"[a-z][a-z0-9_]*", key) or not value or key in fields:
            fail(f"{label} contains a malformed or duplicate field")
        fields[key] = value
    return fields


def exact_raw_receipt(text: str, prefix: str, label: str) -> dict[str, str]:
    matches = [
        parse_raw_receipt_line(line, prefix, label)
        for line in text.splitlines()
        if line.startswith(f"{prefix} ")
    ]
    if len(matches) != 1:
        fail(f"{label} does not contain exactly one {prefix} receipt")
    return matches[0]


def validate_raw_receipt_sequence(
    text: str, prefixes: Sequence[str], label: str
) -> list[str]:
    lines = text.splitlines()
    if (
        not prefixes
        or len(lines) != len(prefixes)
        or text != "\n".join(lines) + "\n"
        or any(
            not line.startswith(f"{prefix} ")
            for line, prefix in zip(lines, prefixes, strict=True)
        )
    ):
        fail(f"{label} differs from its exact receipt prefix sequence")
    return lines


def raw_receipt_nonnegative(
    fields: dict[str, str], name: str, label: str
) -> int:
    return raw_nonnegative(fields.get(name), f"{label}.{name}")


def raw_object(value: Any, label: str) -> dict[str, Any]:
    if type(value) is not dict:
        fail(f"{label} is not an object")
    return value


def raw_exact_object(
    value: Any, keys: set[str] | frozenset[str], label: str
) -> dict[str, Any]:
    result = raw_object(value, label)
    if set(result) != set(keys):
        fail(f"{label} has missing or unexpected fields")
    return result


def raw_array(value: Any, label: str, *, length: int | None = None) -> list[Any]:
    if type(value) is not list or (length is not None and len(value) != length):
        fail(f"{label} is not an array with the required length")
    return value


def raw_equal(value: Any, expected: Any, label: str) -> None:
    if type(value) is not type(expected) or value != expected:
        fail(f"{label} differs from the sanitized receipt or fixed experiment")


def raw_nonnegative(value: Any, label: str) -> int:
    if type(value) is int and 0 <= value <= MAX_COUNTER:
        return value
    if type(value) is str and re.fullmatch(r"0|[1-9][0-9]{0,18}", value):
        parsed = int(value)
        if parsed <= MAX_COUNTER:
            return parsed
    fail(f"{label} is not a bounded nonnegative integer")


def raw_boolean(value: Any, label: str) -> bool:
    if type(value) is bool:
        return value
    if value in {"true", "false"}:
        return value == "true"
    fail(f"{label} is not a Boolean")


def manifest_entries_by_role(document: dict[str, Any]) -> dict[tuple[str, str], dict[str, Any]]:
    return {
        (entry["cell"], entry["role"]): entry
        for entry in document["raw_manifest"]["entries"]
    }


def manifest_entry_for_path(
    entries: dict[tuple[str, str], dict[str, Any]], relative: str, label: str
) -> dict[str, Any]:
    matches = [entry for entry in entries.values() if entry.get("path") == relative]
    if len(matches) != 1:
        fail(f"{label} has no unique curated manifest authority")
    return matches[0]


def validate_raw_source_identity(
    value: Any, document: dict[str, Any], label: str
) -> dict[str, Any]:
    source = raw_object(value, label)
    if set(source) != {
        "schema",
        "commit",
        "tree",
        "tracked_and_untracked_nonignored_clean",
        "commit_signature_verified",
        "cargo_toml_sha256",
        "cargo_lock_sha256",
        "requirements_sha256",
        "dockerfile_sha256",
        "build_input_manifest_sha256",
    }:
        fail(f"{label} has missing or unexpected source identity fields")
    receipt_source = document["source"]
    receipt_container = document["build"]["container"]
    raw_equal(source.get("schema"), RAW_CONTROLLER_SCHEMA, f"{label}.schema")
    for field in ("commit", "tree", "cargo_lock_sha256", "requirements_sha256"):
        raw_equal(source.get(field), receipt_source[field], f"{label}.{field}")
    raw_equal(
        source.get("tracked_and_untracked_nonignored_clean"),
        True,
        f"{label}.worktree",
    )
    raw_equal(
        source.get("commit_signature_verified"), True, f"{label}.signature"
    )
    hex_32(source.get("cargo_toml_sha256"), f"{label}.cargo_toml_sha256")
    raw_equal(
        source.get("dockerfile_sha256"),
        receipt_container["dockerfile_sha256"],
        f"{label}.dockerfile_sha256",
    )
    raw_equal(
        source.get("build_input_manifest_sha256"),
        receipt_container["input_manifest_sha256"],
        f"{label}.build_input_manifest_sha256",
    )
    return source


def validate_raw_build_identity(
    value: Any, document: dict[str, Any], label: str
) -> dict[str, Any]:
    build = raw_exact_object(
        value,
        {
            "schema",
            "arguments",
            "command",
            "network",
            "no_cache",
            "pull",
            "input_manifest_sha256",
            "dockerfile_sha256",
            "build_run_id",
            "status",
            "image_id",
            "image_config_digest",
            "runtime_packages",
            "runtime_package_inventory_sha256",
            "environment",
        },
        label,
    )
    receipt_build = document["build"]
    container = receipt_build["container"]
    raw_equal(build.get("schema"), RAW_CONTROLLER_SCHEMA, f"{label}.schema")
    raw_equal(build.get("status"), "pass", f"{label}.status")
    raw_equal(build.get("command"), receipt_build["command"], f"{label}.command")
    raw_equal(
        build.get("arguments"),
        shlex.split(receipt_build["command"], posix=True),
        f"{label}.arguments",
    )
    raw_equal(build.get("network"), "default", f"{label}.network")
    raw_equal(build.get("no_cache"), True, f"{label}.no_cache")
    raw_equal(build.get("pull"), False, f"{label}.pull")
    for field in (
        "input_manifest_sha256",
        "dockerfile_sha256",
        "build_run_id",
        "image_id",
        "image_config_digest",
    ):
        raw_equal(build.get(field), container[field], f"{label}.{field}")
    environment = raw_exact_object(
        build.get("environment"),
        {
            "schema",
            "physical_hosts",
            "isolation",
            "host_os",
            "host_arch",
            "kernel",
            "docker_version",
            "orbstack_version",
            "build_network",
        },
        f"{label}.environment",
    )
    raw_equal(environment.get("schema"), RAW_CONTROLLER_SCHEMA, f"{label}.environment.schema")
    raw_equal(build.get("runtime_packages"), 6, f"{label}.runtime_packages")
    hex_32(
        build.get("runtime_package_inventory_sha256"),
        f"{label}.runtime_package_inventory_sha256",
    )
    receipt_environment = document["environment"]
    for field in (
        "physical_hosts",
        "isolation",
        "host_os",
        "host_arch",
        "kernel",
        "docker_version",
        "orbstack_version",
    ):
        raw_equal(
            environment.get(field),
            receipt_environment[field],
            f"{label}.environment.{field}",
        )
    raw_equal(
        environment.get("build_network"),
        LIMITATIONS["build_network"],
        f"{label}.environment.build_network",
    )
    return build


def validate_raw_controller(
    value: Any,
    *,
    label: str,
    run_id: str,
    run_label: str,
    evidence_dir: str,
    require_empty_resources: bool,
    expected_workspace: str | None = None,
) -> dict[str, Any]:
    controller = raw_exact_object(
        value,
        {
            "schema",
            "created_utc",
            "run_id",
            "label",
            "workspace",
            "evidence_dir",
            "image",
            "resources",
        },
        label,
    )
    raw_equal(controller.get("schema"), RAW_CONTROLLER_SCHEMA, f"{label}.schema")
    raw_equal(controller.get("run_id"), run_id, f"{label}.run_id")
    raw_equal(controller.get("label"), run_label, f"{label}.label")
    raw_equal(controller.get("evidence_dir"), evidence_dir, f"{label}.evidence_dir")
    raw_equal(controller.get("image"), SELECTED_NAT_IMAGE, f"{label}.image")
    exact_string(
        controller.get("created_utc"),
        f"{label}.created_utc",
        maximum=64,
        pattern=UTC_TIMESTAMP,
    )
    workspace = str(
        canonical_absolute_path(
            exact_string(
                controller.get("workspace"), f"{label}.workspace", maximum=512
            ),
            f"{label}.workspace",
        )
    )
    if expected_workspace is not None:
        raw_equal(workspace, expected_workspace, f"{label}.workspace suite binding")
    resources = raw_array(controller.get("resources"), f"{label}.resources")
    if require_empty_resources and resources:
        fail(f"{label}.resources is not empty for the suite controller")
    if not require_empty_resources and not resources:
        fail(f"{label}.resources is empty for a cell controller")
    return controller


def validate_raw_binary_inventory(
    value: Any, document: dict[str, Any], label: str
) -> list[Any]:
    inventory = raw_array(value, label, length=len(BUILD_ROLES))
    expected_paths = (
        "/usr/local/bin/aster",
        "/usr/local/bin/aster-selected-nat",
        "/usr/local/bin/aster-selected-relay",
    )
    for index, role in enumerate(BUILD_ROLES):
        record = raw_exact_object(
            inventory[index],
            {"role", "name", "path", "bytes", "sha256"},
            f"{label}[{index}]",
        )
        receipt_record = document["build"]["artifacts"][index]
        for field in ("role", "name", "bytes", "sha256"):
            raw_equal(
                record.get(field), receipt_record[field], f"{label}[{index}].{field}"
            )
        raw_equal(record.get("role"), role, f"{label}[{index}].role")
        raw_equal(record.get("path"), expected_paths[index], f"{label}[{index}].path")
    return inventory


def validate_raw_image_identity(
    value: Any, document: dict[str, Any], label: str
) -> dict[str, Any]:
    image = raw_exact_object(
        value, {"id", "repo_digests", "labels", "architecture", "env"}, label
    )
    container = document["build"]["container"]
    raw_equal(image.get("id"), container["image_id"], f"{label}.id")
    raw_equal(image.get("architecture"), "arm64", f"{label}.architecture")
    labels = raw_object(image.get("labels"), f"{label}.labels")
    expected_labels = {
        **PINNED_BASE_IMAGE_LABELS,
        MANAGED_LABEL: "true",
        RUN_LABEL: container["build_run_id"],
        IMAGE_SCHEMA_LABEL: SELECTED_NAT_IMAGE_SCHEMA,
        IMAGE_INPUT_LABEL: container["input_manifest_sha256"],
        IMAGE_BASE_LABEL: LAB_BASE_IMAGE,
    }
    raw_equal(labels, expected_labels, f"{label}.labels")
    raw_equal(
        image.get("repo_digests"),
        [f"{SELECTED_NAT_LOCAL_REPOSITORY}@{container['image_id']}"],
        f"{label}.repo_digests",
    )
    environment = raw_array(image.get("env"), f"{label}.env")
    raw_equal(
        environment,
        SELECTED_NAT_IMAGE_ENVIRONMENT,
        f"{label}.env pinned base-image environment",
    )
    return image


def validate_raw_prepare_evidence(
    root_descriptor: int,
    profile: str,
    receipt_cell: dict[str, Any],
    entries: dict[tuple[str, str], dict[str, Any]],
) -> tuple[dict[str, dict[str, str]], str]:
    label = f"cells.{profile}.prepare"
    scope = f"lab/selected-iroh-nat/{profile}"
    topic = "lab.selected-iroh-nat"
    manifest_text = load_raw_text(
        root_descriptor,
        f"cells/{profile}/outputs/provision/manifest.tsv",
        f"{label}.manifest",
        entries=entries,
        maximum=64 * 1024,
    )
    lines = manifest_text.splitlines()
    header_prefix = (
        f"ASTER_SELECTED_NAT_MANIFEST\tversion=2\tscope={scope}\ttopic={topic}"
        "\tmission_authority="
    )
    header_suffix = (
        f"\tcanary_sha256={receipt_cell['event']['canary_sha256']}\tnodes=2"
    )
    if (
        len(lines) != 4
        or not lines[0].startswith(header_prefix)
        or not lines[0].endswith(header_suffix)
    ):
        fail(f"{label}.manifest header or row count differs")
    mission_authority = hex_32(
        lines[0][len(header_prefix) : -len(header_suffix)],
        f"{label}.manifest.mission_authority",
    )
    if lines[1] != "name\tmission_id\tcarrier_id\tsubscription_id":
        fail(f"{label}.manifest columns differ")
    nodes: dict[str, dict[str, str]] = {}
    subscriptions: set[str] = set()
    for index, (expected_name, line) in enumerate(zip(("a", "b"), lines[2:])):
        fields = line.split("\t")
        if len(fields) != 4 or fields[0] != expected_name or fields[0] in nodes:
            fail(f"{label}.manifest node row {index} is malformed or duplicated")
        name, mission_id, carrier_id, subscription_id = fields
        hex_32(mission_id, f"{label}.manifest.{name}.mission_id")
        hex_32(carrier_id, f"{label}.manifest.{name}.carrier_id")
        hex_32(subscription_id, f"{label}.manifest.{name}.subscription_id")
        endpoint = receipt_cell["endpoints"][0 if name == "a" else 1]
        raw_equal(mission_id, endpoint["mission_id"], f"{label}.{name}.mission_id")
        raw_equal(carrier_id, endpoint["carrier_id"], f"{label}.{name}.carrier_id")
        subscriptions.add(subscription_id)
        nodes[name] = {
            "name": name,
            "mission_id": mission_id,
            "carrier_id": carrier_id,
            "subscription_id": subscription_id,
        }
    if set(nodes) != {"a", "b"} or len(subscriptions) != 2:
        fail(f"{label}.manifest lacks two distinct node subscriptions")
    public_endpoint_ids = {
        endpoint[field]
        for endpoint in receipt_cell["endpoints"]
        for field in ("mission_id", "carrier_id")
    }
    if mission_authority in public_endpoint_ids:
        fail(f"{label}.manifest mission authority overlaps an endpoint identity")

    prepare_text = load_raw_text(
        root_descriptor,
        f"cells/{profile}/prepare.log",
        f"{label}.log",
        entries=entries,
        maximum=64 * 1024,
    )
    nonempty = validate_raw_receipt_sequence(
        prepare_text,
        ["SELECTED_NAT_PREPARE", "SELECTED_NAT_NODE", "SELECTED_NAT_NODE"],
        f"{label}.log",
    )
    prepare = exact_raw_receipt(prepare_text, "SELECTED_NAT_PREPARE", f"{label}.log")
    expected_prepare_keys = {
        "status",
        "version",
        "nodes",
        "scope",
        "topic",
        "manifest",
        "mission_authority",
        "mission_authority_shared",
        "mission_authority_disjoint",
        "mission_ids_distinct",
        "carrier_ids_distinct",
        "mission_carrier_disjoint",
        "subscriptions",
        "pre_inventory_events",
        "canary_sha256",
        "canary_bytes",
        "canary",
    }
    if set(prepare) != expected_prepare_keys:
        fail(f"{label}.log has missing or unexpected prepare fields")
    for field, expected in (
        ("status", "pass"),
        ("version", "2"),
        ("nodes", "2"),
        ("scope", scope),
        ("topic", topic),
        ("manifest", "/output/manifest.tsv"),
        ("mission_authority", mission_authority),
        ("mission_authority_shared", "true"),
        ("mission_authority_disjoint", "true"),
        ("mission_ids_distinct", "true"),
        ("carrier_ids_distinct", "true"),
        ("mission_carrier_disjoint", "true"),
        ("subscriptions", "2"),
        ("pre_inventory_events", "0"),
        ("canary_sha256", receipt_cell["event"]["canary_sha256"]),
        ("canary_bytes", "32"),
        ("canary", "redacted"),
    ):
        raw_equal(prepare.get(field), expected, f"{label}.log.{field}")
    logged_nodes: dict[str, dict[str, str]] = {}
    for line in nonempty:
        if not line.startswith("SELECTED_NAT_NODE "):
            continue
        node = parse_raw_receipt_line(line, "SELECTED_NAT_NODE", f"{label}.log.node")
        if set(node) != {"name", "mission_id", "carrier_id"}:
            fail(f"{label}.log has missing or unexpected node fields")
        name = node.get("name")
        if name not in {"a", "b"} or name in logged_nodes:
            fail(f"{label}.log has a malformed or duplicate node")
        for field in ("mission_id", "carrier_id"):
            raw_equal(node.get(field), nodes[name][field], f"{label}.log.{name}.{field}")
        logged_nodes[name] = node
    if set(logged_nodes) != {"a", "b"}:
        fail(f"{label}.log omits a node identity")
    if [
        parse_raw_receipt_line(line, "SELECTED_NAT_NODE", f"{label}.log.node").get(
            "name"
        )
        for line in nonempty[1:]
    ] != ["a", "b"]:
        fail(f"{label}.log node identity order differs")
    return nodes, mission_authority


def validate_raw_event_logs(
    root_descriptor: int,
    profile: str,
    receipt_cell: dict[str, Any],
    finalization: dict[str, Any],
    entries: dict[tuple[str, str], dict[str, Any]],
) -> None:
    label = f"cells.{profile}.event"
    event = receipt_cell["event"]
    publish_text = load_raw_text(
        root_descriptor,
        f"cells/{profile}/publish.log",
        f"{label}.publish_log",
        entries=entries,
        maximum=64 * 1024,
    )
    verify_text = load_raw_text(
        root_descriptor,
        f"cells/{profile}/verify.log",
        f"{label}.verify_log",
        entries=entries,
        maximum=64 * 1024,
    )
    validate_raw_receipt_sequence(
        publish_text, ["SELECTED_NAT_PUBLISH"], f"{label}.publish_log"
    )
    validate_raw_receipt_sequence(
        verify_text, ["SELECTED_NAT_VERIFY"], f"{label}.verify_log"
    )
    publish = exact_raw_receipt(
        publish_text, "SELECTED_NAT_PUBLISH", f"{label}.publish_log"
    )
    verify = exact_raw_receipt(
        verify_text, "SELECTED_NAT_VERIFY", f"{label}.verify_log"
    )
    publish_expected = {
        "status": "pass",
        "version": "1",
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
        "sealed_sha256": "not-exposed-by-production-api",
        "exact_query": "true",
    }
    verify_expected = {
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
        "sealed_sha256": "not-exposed-by-production-api",
        "deliveries": "1",
        "attempt": "1",
        "acknowledged": "true",
        "empty_after_ack": "true",
        "replay_ack": "noop",
        "replay_subscription": "noop",
        "exact_query": "true",
    }
    raw_equal(publish, publish_expected, f"{label}.publish_log fields")
    raw_equal(verify, verify_expected, f"{label}.verify_log fields")
    raw_event = raw_object(finalization.get("event"), f"{label}.finalization")
    raw_equal(raw_event.get("publish"), publish, f"{label}.finalization.publish")
    raw_equal(raw_event.get("verify"), verify, f"{label}.finalization.verify")


def validate_raw_privilege(value: Any, label: str) -> tuple[int, int]:
    privilege = raw_object(value, label)
    expected_keys = {
        "uid",
        "gid",
        "no_new_privs",
        "cap_inheritable",
        "cap_permitted",
        "cap_effective",
        "cap_bounding",
        "cap_ambient",
    }
    if set(privilege) != expected_keys:
        fail(f"{label} has missing or unexpected privilege fields")
    uid = raw_nonnegative(privilege.get("uid"), f"{label}.uid")
    gid = raw_nonnegative(privilege.get("gid"), f"{label}.gid")
    if uid == 0 or gid == 0:
        fail(f"{label} records a root workload identity")
    raw_equal(privilege.get("no_new_privs"), True, f"{label}.no_new_privs")
    for field in (
        "cap_inheritable",
        "cap_permitted",
        "cap_effective",
        "cap_bounding",
        "cap_ambient",
    ):
        raw_equal(privilege.get(field), 0, f"{label}.{field}")
    return uid, gid


def validate_raw_bind_mounts(
    value: Any,
    expected: dict[str, tuple[str, bool]],
    label: str,
) -> None:
    observed: dict[str, tuple[str, bool]] = {}
    for index, raw_mount in enumerate(raw_array(value, label)):
        mount_label = f"{label}[{index}]"
        mount = raw_object(raw_mount, mount_label)
        raw_equal(mount.get("Type"), "bind", f"{mount_label}.Type")
        source = exact_string(
            mount.get("Source"), f"{mount_label}.Source", maximum=4096
        )
        destination = exact_string(
            mount.get("Destination"),
            f"{mount_label}.Destination",
            maximum=256,
        )
        if (
            not source.startswith("/")
            or PurePosixPath(source).as_posix() != source
            or ".." in PurePosixPath(source).parts
            or destination in observed
        ):
            fail(f"{mount_label} has a noncanonical or duplicate bind path")
        observed[destination] = (
            source,
            raw_boolean(mount.get("RW"), f"{mount_label}.RW"),
        )
    raw_equal(observed, expected, label)


def validate_raw_security_opt(value: Any, label: str) -> None:
    security = raw_array(value, label, length=1)
    option = exact_string(security[0], f"{label}[0]", maximum=64)
    if option not in {"no-new-privileges", "no-new-privileges:true"}:
        fail(f"{label} is not the exact enabled no-new-privileges option")


def validate_raw_container_tmpfs(host: dict[str, Any], label: str) -> None:
    raw_equal(host.get("Init"), True, f"{label}.HostConfig.Init")
    raw_equal(
        host.get("Ulimits"),
        [{"Name": "nofile", "Hard": 65_536, "Soft": 65_536}],
        f"{label}.HostConfig.Ulimits",
    )
    tmpfs = raw_exact_object(
        host.get("Tmpfs"), {"/tmp", "/run"}, f"{label}.HostConfig.Tmpfs"
    )
    for destination, expected_size in (
        ("/tmp", 32 * 1024 * 1024),
        ("/run", 8 * 1024 * 1024),
    ):
        value = exact_string(
            tmpfs[destination], f"{label}.HostConfig.Tmpfs.{destination}", maximum=128
        )
        options = value.split(",")
        sizes = [item for item in options if item.startswith("size=")]
        flags = {item for item in options if not item.startswith("size=")}
        if (
            len(options) != len(set(options))
            or flags != {"rw", "nosuid", "nodev", "noexec"}
            or len(sizes) != 1
        ):
            fail(f"{label}.HostConfig.Tmpfs.{destination} differs")
        size = sizes[0].split("=", 1)[1].lower()
        match = re.fullmatch(r"([1-9][0-9]*)([kmgt]?)(?:b)?", size)
        if match is None:
            fail(f"{label}.HostConfig.Tmpfs.{destination} size is malformed")
        multiplier = 1024 ** {"": 0, "k": 1, "m": 2, "g": 3, "t": 4}[
            match.group(2)
        ]
        if int(match.group(1)) * multiplier != expected_size:
            fail(f"{label}.HostConfig.Tmpfs.{destination} size differs")


def validate_raw_container_host_isolation(
    host: dict[str, Any], config: dict[str, Any], label: str
) -> None:
    expected = {
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
    }
    for field, expected_value in expected.items():
        raw_equal(
            host.get(field), expected_value, f"{label}.HostConfig.{field}"
        )
    raw_equal(config.get("ExposedPorts"), None, f"{label}.Config.ExposedPorts")
    raw_equal(config.get("Volumes"), None, f"{label}.Config.Volumes")


def validate_raw_container_labels(
    config: dict[str, Any],
    *,
    run_id: str,
    role: str,
    input_manifest_sha256: str,
    image_environment: list[str],
    label: str,
) -> None:
    raw_equal(
        config.get("Labels"),
        {
            **PINNED_BASE_IMAGE_LABELS,
            MANAGED_LABEL: "true",
            IMAGE_SCHEMA_LABEL: SELECTED_NAT_IMAGE_SCHEMA,
            IMAGE_INPUT_LABEL: input_manifest_sha256,
            IMAGE_BASE_LABEL: LAB_BASE_IMAGE,
            RUN_LABEL: run_id,
            ROLE_LABEL: role,
        },
        f"{label}.Config.Labels",
    )
    raw_equal(
        config.get("Env"), image_environment, f"{label}.Config.Env image binding"
    )


def validate_raw_node_config(
    value: Any,
    *,
    profile: str,
    node_role: str,
    image_id: str,
    uid: int,
    gid: int,
    evidence_dir: str,
    run_id: str,
    input_manifest_sha256: str,
    image_environment: list[str],
    label: str,
) -> str:
    config_receipt = raw_object(value, label)
    container_id = hex_32(config_receipt.get("Id"), f"{label}.Id")
    raw_equal(config_receipt.get("Image"), image_id, f"{label}.Image")
    host = raw_object(config_receipt.get("HostConfig"), f"{label}.HostConfig")
    config = raw_object(config_receipt.get("Config"), f"{label}.Config")
    mounts = raw_array(config_receipt.get("Mounts"), f"{label}.Mounts")
    for field, expected in (
        ("Privileged", False),
        ("ReadonlyRootfs", True),
        ("Memory", 1024 * 1024 * 1024),
        ("MemorySwap", 1024 * 1024 * 1024),
        ("PidsLimit", 256),
        ("NanoCpus", 1_000_000_000),
        ("CgroupnsMode", "private"),
    ):
        raw_equal(host.get(field), expected, f"{label}.HostConfig.{field}")
    expected_network = "aster-lab-lan-a" if node_role == "node-a" else "aster-lab-lan-b"
    raw_equal(host.get("NetworkMode"), expected_network, f"{label}.HostConfig.NetworkMode")
    raw_equal(
        raw_array(host.get("CapDrop"), f"{label}.HostConfig.CapDrop"),
        ["ALL"],
        f"{label}.HostConfig.CapDrop",
    )
    if "CapAdd" not in host:
        fail(f"{label}.HostConfig.CapAdd is missing")
    raw_equal(host["CapAdd"], None, f"{label}.HostConfig.CapAdd")
    validate_raw_security_opt(
        host.get("SecurityOpt"), f"{label}.HostConfig.SecurityOpt"
    )
    validate_raw_container_tmpfs(host, label)
    validate_raw_container_host_isolation(host, config, label)
    raw_equal(host.get("Sysctls") or {}, {}, f"{label}.HostConfig.Sysctls")
    expected_hosts = (
        ["relay.aster.test:10.250.0.20"] if profile == "restrictive-relay" else []
    )
    raw_equal(host.get("ExtraHosts") or [], expected_hosts, f"{label}.HostConfig.ExtraHosts")
    raw_equal(config.get("User"), f"{uid}:{gid}", f"{label}.Config.User")
    raw_equal(config.get("Entrypoint"), ["/usr/bin/sleep"], f"{label}.Config.Entrypoint")
    raw_equal(config.get("Cmd"), ["infinity"], f"{label}.Config.Cmd")
    validate_raw_container_labels(
        config,
        run_id=run_id,
        role=node_role,
        input_manifest_sha256=input_manifest_sha256,
        image_environment=image_environment,
        label=label,
    )
    node_state_path = f"/output/{node_role}"
    expected_mounts = {
        node_state_path: (f"{evidence_dir}/outputs/provision/{node_role}", True),
        "/run/secrets/node.bundle": (
            f"{evidence_dir}/outputs/provision/private/{node_role}.bundle",
            True,
        ),
    }
    if profile == "restrictive-relay":
        expected_mounts["/run/relay/ca.der"] = (
            f"{evidence_dir}/outputs/provision/relay/ca.der",
            False,
        )
    validate_raw_bind_mounts(mounts, expected_mounts, f"{label}.bind mounts")
    networks = raw_object(
        raw_object(
            config_receipt.get("NetworkSettings"), f"{label}.NetworkSettings"
        ).get("Networks"),
        f"{label}.NetworkSettings.Networks",
    )
    expected_address = "10.250.1.10" if node_role == "node-a" else "10.250.2.10"
    if set(networks) != {expected_network}:
        fail(f"{label} has an unexpected node network attachment")
    raw_equal(
        raw_object(networks[expected_network], f"{label}.Networks.primary").get(
            "IPAddress"
        ),
        expected_address,
        f"{label}.Networks.primary.IPAddress",
    )
    return container_id


def validate_raw_router_config(
    value: Any,
    *,
    router: str,
    image_id: str,
    evidence_dir: str,
    run_id: str,
    input_manifest_sha256: str,
    image_environment: list[str],
    label: str,
) -> None:
    receipt = raw_object(value, label)
    raw_equal(receipt.get("Image"), image_id, f"{label}.Image")
    host = raw_object(receipt.get("HostConfig"), f"{label}.HostConfig")
    config = raw_object(receipt.get("Config"), f"{label}.Config")
    for field, expected in (
        ("Privileged", False),
        ("ReadonlyRootfs", True),
        ("Memory", 256 * 1024 * 1024),
        ("MemorySwap", 256 * 1024 * 1024),
        ("PidsLimit", 64),
        ("NanoCpus", 500_000_000),
        ("CgroupnsMode", "private"),
        ("NetworkMode", "aster-lab-lan-a" if router == "nat-a" else "aster-lab-lan-b"),
    ):
        raw_equal(host.get(field), expected, f"{label}.HostConfig.{field}")
    raw_equal(
        raw_array(host.get("CapDrop"), f"{label}.HostConfig.CapDrop"),
        ["ALL"],
        f"{label}.HostConfig.CapDrop",
    )
    raw_equal(
        raw_array(host.get("CapAdd"), f"{label}.HostConfig.CapAdd"),
        ["CAP_NET_ADMIN", "CAP_NET_RAW", "CAP_SETGID", "CAP_SETUID"],
        f"{label}.HostConfig.CapAdd",
    )
    validate_raw_security_opt(
        host.get("SecurityOpt"), f"{label}.HostConfig.SecurityOpt"
    )
    validate_raw_container_tmpfs(host, label)
    validate_raw_container_host_isolation(host, config, label)
    raw_equal(
        host.get("Sysctls"),
        {"net.ipv4.ip_forward": "1"},
        f"{label}.HostConfig.Sysctls",
    )
    raw_equal(host.get("ExtraHosts") or [], [], f"{label}.HostConfig.ExtraHosts")
    raw_equal(config.get("User"), "", f"{label}.Config.User")
    raw_equal(config.get("Entrypoint"), ["/usr/bin/sleep"], f"{label}.Config.Entrypoint")
    raw_equal(config.get("Cmd"), ["infinity"], f"{label}.Config.Cmd")
    validate_raw_container_labels(
        config,
        run_id=run_id,
        role=router,
        input_manifest_sha256=input_manifest_sha256,
        image_environment=image_environment,
        label=label,
    )
    validate_raw_bind_mounts(
        receipt.get("Mounts"),
        {"/output": (f"{evidence_dir}/outputs/{router}", True)},
        f"{label}.bind mounts",
    )
    networks = raw_object(
        raw_object(receipt.get("NetworkSettings"), f"{label}.NetworkSettings").get("Networks"),
        f"{label}.NetworkSettings.Networks",
    )
    expected_addresses = {
        "aster-lab-lan-a" if router == "nat-a" else "aster-lab-lan-b":
        "10.250.1.1" if router == "nat-a" else "10.250.2.1",
        "aster-lab-wan": "10.250.0.11" if router == "nat-a" else "10.250.0.12",
    }
    observed_addresses = {
        name: raw_object(network, f"{label}.Networks.{name}").get("IPAddress")
        for name, network in networks.items()
    }
    raw_equal(observed_addresses, expected_addresses, f"{label}.network attachments")


def validate_raw_relay_runtime_config(
    value: Any,
    *,
    image_id: str,
    uid: int,
    gid: int,
    evidence_dir: str,
    run_id: str,
    input_manifest_sha256: str,
    image_environment: list[str],
    carrier_ids: list[str],
    label: str,
) -> None:
    receipt = raw_object(value, label)
    raw_equal(receipt.get("Image"), image_id, f"{label}.Image")
    host = raw_object(receipt.get("HostConfig"), f"{label}.HostConfig")
    config = raw_object(receipt.get("Config"), f"{label}.Config")
    for field, expected in (
        ("Privileged", False),
        ("ReadonlyRootfs", True),
        ("Memory", 512 * 1024 * 1024),
        ("MemorySwap", 512 * 1024 * 1024),
        ("PidsLimit", 256),
        ("NanoCpus", 1_000_000_000),
        ("CgroupnsMode", "private"),
        ("NetworkMode", "aster-lab-wan"),
    ):
        raw_equal(host.get(field), expected, f"{label}.HostConfig.{field}")
    raw_equal(
        raw_array(host.get("CapDrop"), f"{label}.HostConfig.CapDrop"),
        ["ALL"],
        f"{label}.HostConfig.CapDrop",
    )
    if "CapAdd" not in host:
        fail(f"{label}.HostConfig.CapAdd is missing")
    raw_equal(host["CapAdd"], None, f"{label}.HostConfig.CapAdd")
    validate_raw_security_opt(
        host.get("SecurityOpt"), f"{label}.HostConfig.SecurityOpt"
    )
    validate_raw_container_tmpfs(host, label)
    validate_raw_container_host_isolation(host, config, label)
    raw_equal(host.get("Sysctls") or {}, {}, f"{label}.HostConfig.Sysctls")
    raw_equal(host.get("ExtraHosts") or [], [], f"{label}.HostConfig.ExtraHosts")
    raw_equal(config.get("User"), f"{uid}:{gid}", f"{label}.Config.User")
    raw_equal(
        config.get("Entrypoint"),
        ["/usr/local/bin/aster-selected-relay"],
        f"{label}.Config.Entrypoint",
    )
    expected_command = [
        "--https-bind",
        "0.0.0.0:8443",
        "--http-bind",
        "0.0.0.0:8080",
        "--certificate-der",
        "/run/relay/server.cert.der",
        "--private-key-pkcs8-der",
        "/run/relay/server.key.pkcs8.der",
    ]
    for carrier_id in sorted(carrier_ids):
        expected_command.extend(["--allow-carrier", carrier_id])
    expected_command.extend(
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
    raw_equal(config.get("Cmd"), expected_command, f"{label}.Config.Cmd")
    validate_raw_container_labels(
        config,
        run_id=run_id,
        role="infra",
        input_manifest_sha256=input_manifest_sha256,
        image_environment=image_environment,
        label=label,
    )
    validate_raw_bind_mounts(
        receipt.get("Mounts"),
        {
            "/output": (f"{evidence_dir}/outputs/infra", True),
            "/run/relay/server.cert.der": (
                f"{evidence_dir}/outputs/provision/relay/server.cert.der",
                False,
            ),
            "/run/relay/server.key.pkcs8.der": (
                f"{evidence_dir}/outputs/provision/relay/private/server.key.pkcs8.der",
                False,
            ),
        },
        f"{label}.bind mounts",
    )
    networks = raw_object(
        raw_object(receipt.get("NetworkSettings"), f"{label}.NetworkSettings").get("Networks"),
        f"{label}.NetworkSettings.Networks",
    )
    if set(networks) != {"aster-lab-wan"}:
        fail(f"{label} has an unexpected network attachment")
    raw_equal(
        raw_object(networks["aster-lab-wan"], f"{label}.Networks.wan").get("IPAddress"),
        "10.250.0.20",
        f"{label}.Networks.wan.IPAddress",
    )


def validate_raw_ephemeral_config(
    value: Any,
    *,
    role: str,
    image_id: str,
    node_container_id: str | None,
    evidence_dir: str,
    run_id: str,
    input_manifest_sha256: str,
    image_environment: list[str],
    label: str,
) -> None:
    receipt = raw_object(value, label)
    raw_equal(receipt.get("Image"), image_id, f"{label}.Image")
    host = raw_object(receipt.get("HostConfig"), f"{label}.HostConfig")
    config = raw_object(receipt.get("Config"), f"{label}.Config")
    provision = role.startswith("provision-")
    route_a = role == "route-a"
    for field, expected in (
        ("Privileged", False),
        ("ReadonlyRootfs", True),
        ("Memory", (512 if provision else 64) * 1024 * 1024),
        ("MemorySwap", (512 if provision else 64) * 1024 * 1024),
        ("PidsLimit", 128 if provision else 32),
        ("NanoCpus", 1_000_000_000 if provision else 250_000_000),
        ("CgroupnsMode", "private"),
    ):
        raw_equal(host.get(field), expected, f"{label}.HostConfig.{field}")
    network_mode = host.get("NetworkMode")
    if provision:
        raw_equal(network_mode, "none", f"{label}.HostConfig.NetworkMode")
    else:
        node_name = "node-a" if route_a else "node-b"
        allowed_modes = {f"container:aster-lab-{node_name}"}
        if node_container_id is not None:
            allowed_modes.add(f"container:{node_container_id}")
        if network_mode not in allowed_modes:
            fail(f"{label}.HostConfig.NetworkMode is not its exact node namespace")
    networks = raw_object(
        raw_object(
            receipt.get("NetworkSettings"), f"{label}.NetworkSettings"
        ).get("Networks"),
        f"{label}.NetworkSettings.Networks",
    )
    observed_addresses = {
        network_name: raw_object(
            network, f"{label}.NetworkSettings.Networks.{network_name}"
        ).get("IPAddress")
        for network_name, network in networks.items()
    }
    raw_equal(
        observed_addresses,
        {"none": ""} if provision else {},
        f"{label}.NetworkSettings addresses",
    )
    raw_equal(
        raw_array(host.get("CapDrop"), f"{label}.HostConfig.CapDrop"),
        ["ALL"],
        f"{label}.HostConfig.CapDrop",
    )
    if provision:
        if "CapAdd" not in host:
            fail(f"{label}.HostConfig.CapAdd is missing")
        raw_equal(host["CapAdd"], None, f"{label}.HostConfig.CapAdd")
    else:
        raw_equal(
            raw_array(host.get("CapAdd"), f"{label}.HostConfig.CapAdd"),
            ["CAP_NET_ADMIN"],
            f"{label}.HostConfig.CapAdd",
        )
    validate_raw_security_opt(
        host.get("SecurityOpt"), f"{label}.HostConfig.SecurityOpt"
    )
    validate_raw_container_tmpfs(host, label)
    validate_raw_container_host_isolation(host, config, label)
    raw_equal(host.get("Sysctls") or {}, {}, f"{label}.HostConfig.Sysctls")
    raw_equal(host.get("ExtraHosts") or [], [], f"{label}.HostConfig.ExtraHosts")
    expected_user = f"{os.getuid()}:{os.getgid()}" if provision else ""
    raw_equal(config.get("User"), expected_user, f"{label}.Config.User")
    raw_equal(
        config.get("Entrypoint"),
        ["/usr/bin/sleep" if provision else "/usr/sbin/ip"],
        f"{label}.Config.Entrypoint",
    )
    command = (
        ["infinity"]
        if provision
        else ["route", "replace", "default", "via", "10.250.1.1" if route_a else "10.250.2.1"]
    )
    raw_equal(config.get("Cmd"), command, f"{label}.Config.Cmd")
    validate_raw_container_labels(
        config,
        run_id=run_id,
        role="provision" if provision else role,
        input_manifest_sha256=input_manifest_sha256,
        image_environment=image_environment,
        label=label,
    )
    validate_raw_bind_mounts(
        receipt.get("Mounts"),
        (
            {"/output": (f"{evidence_dir}/outputs/provision", True)}
            if provision
            else {}
        ),
        f"{label}.bind mounts",
    )


def validate_raw_network_config(
    value: Any,
    *,
    profile: str,
    role: str,
    run_id: str,
    manifest_sha256: str,
    label: str,
) -> dict[str, Any]:
    network = raw_object(value, label)
    fixed = {
        "lan-a": (
            "aster-lab-lan-a",
            "10.250.1.0/24",
            "10.250.1.254",
            {
                "aster-lab-node-a": "10.250.1.10/24",
                "aster-lab-nat-a": "10.250.1.1/24",
            },
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
            {
                "aster-lab-node-b": "10.250.2.10/24",
                "aster-lab-nat-b": "10.250.2.1/24",
            },
        ),
    }
    name, subnet, gateway, expected_members = fixed[role]
    for field, expected in (
        ("Name", name),
        ("Driver", "bridge"),
        ("Internal", True),
        ("Attachable", False),
        ("Ingress", False),
    ):
        raw_equal(network.get(field), expected, f"{label}.{field}")
    raw_equal(
        network.get("Labels"),
        {MANAGED_LABEL: "true", RUN_LABEL: run_id, ROLE_LABEL: role},
        f"{label}.Labels",
    )
    ipam = raw_object(network.get("IPAM"), f"{label}.IPAM")
    raw_equal(ipam.get("Driver"), "default", f"{label}.IPAM.Driver")
    configuration = raw_array(ipam.get("Config"), f"{label}.IPAM.Config", length=1)
    ipam_record = raw_object(configuration[0], f"{label}.IPAM.Config[0]")
    raw_equal(ipam_record.get("Subnet"), subnet, f"{label}.IPAM.Subnet")
    raw_equal(ipam_record.get("Gateway"), gateway, f"{label}.IPAM.Gateway")
    containers = raw_object(network.get("Containers"), f"{label}.Containers")
    observed_members: dict[str, str] = {}
    for key, raw_member in containers.items():
        exact_string(key, f"{label}.Containers key", maximum=128)
        member = raw_object(raw_member, f"{label}.Containers.{key}")
        member_name = exact_string(
            member.get("Name"), f"{label}.Containers.{key}.Name", pattern=SAFE_NAME
        )
        if member_name in observed_members:
            fail(f"{label} contains a duplicate member name")
        observed_members[member_name] = exact_string(
            member.get("IPv4Address"),
            f"{label}.Containers.{key}.IPv4Address",
            maximum=64,
        )
    raw_equal(observed_members, expected_members, f"{label}.members")
    return {
        "role": role,
        "name": name,
        "path": f"{name}-network.json",
        "sha256": manifest_sha256,
        "internal": True,
        "subnet": subnet,
        "gateway": gateway,
        "members": observed_members,
    }


def validate_raw_route_initializers(
    value: Any, profile: str, label: str
) -> dict[str, int]:
    receipts = raw_array(value, label, length=2)
    sequences: dict[str, int] = {}
    for index, (route_role, node_role, gateway) in enumerate(
        (
            ("route-a", "node-a", "10.250.1.1"),
            ("route-b", "node-b", "10.250.2.1"),
        )
    ):
        receipt = raw_exact_object(
            receipts[index],
            {
                "role",
                "name",
                "exit_code",
                "exited",
                "removed",
                "log",
                "log_sha256",
                "node",
                "gateway",
                "route",
            },
            f"{label}[{index}]",
        )
        for field, expected in (
            ("role", route_role),
            ("name", f"aster-lab-{route_role}"),
            ("exit_code", 0),
            ("exited", True),
            ("removed", True),
            ("node", node_role),
            ("gateway", gateway),
        ):
            raw_equal(receipt.get(field), expected, f"{label}[{index}].{field}")
        route = raw_exact_object(
            receipt.get("route"),
            {"dev", "dst", "flags", "gateway"},
            f"{label}[{index}].route",
        )
        raw_equal(route.get("dev"), "eth0", f"{label}[{index}].route.dev")
        raw_equal(route.get("dst"), "default", f"{label}[{index}].route.dst")
        raw_equal(route.get("flags"), [], f"{label}[{index}].route.flags")
        raw_equal(route.get("gateway"), gateway, f"{label}[{index}].route.gateway")
        log_name = exact_string(
            receipt.get("log"),
            f"{label}[{index}].log",
            pattern=re.compile(
                rf"reap-aster-lab-{re.escape(route_role)}-command-[0-9]{{4,}}\.log\Z"
            ),
        )
        matched = re.fullmatch(
            rf"reap-aster-lab-{re.escape(route_role)}-command-([0-9]{{4,}})\.log",
            log_name,
        )
        if matched is None:
            fail(f"{label}[{index}].log lacks its command sequence")
        sequence = int(matched.group(1))
        if sequence <= 0 or sequence > 9_999_999:
            fail(f"{label}[{index}].log command sequence exceeds its bound")
        sequences[route_role] = sequence
        raw_equal(
            receipt.get("log_sha256"),
            hashlib.sha256(b"").hexdigest(),
            f"{label}[{index}].log_sha256",
        )
    if sequences["route-a"] >= sequences["route-b"]:
        fail(f"{label} command order differs")
    return sequences


def validate_raw_command_chronology(
    route_sequences: dict[str, int],
    stderr_sequences: dict[str, int],
    label: str,
) -> None:
    if set(route_sequences) != {"route-a", "route-b"} or set(stderr_sequences) != {
        "nat-a",
        "nat-b",
        "node-a",
        "node-b",
    }:
        fail(f"{label} authorities differ")
    if not (
        route_sequences["route-a"]
        < route_sequences["route-b"]
        < stderr_sequences["nat-a"]
        < stderr_sequences["nat-b"]
        < stderr_sequences["node-b"]
        < stderr_sequences["node-a"]
        and stderr_sequences["node-a"] == stderr_sequences["node-b"] + 1
    ):
        fail(f"{label} differs from exact production order")


def validate_tcpdump_terminal_receipt(
    text: str, label: str, *, expected_packets: int
) -> None:
    """Require tcpdump's canonical, complete terminal packet accounting."""
    bounded_int(expected_packets, f"{label}.expected_packets")
    if "\r" in text or not text.endswith("\n"):
        fail(f"{label} has noncanonical tcpdump terminal receipt lines")
    lines = text.splitlines()
    patterns = (
        ("captured", re.compile(r"(0|[1-9][0-9]{0,18}) packets captured\Z")),
        (
            "received",
            re.compile(r"(0|[1-9][0-9]{0,18}) packets received by filter\Z"),
        ),
        (
            "dropped",
            re.compile(r"(0|[1-9][0-9]{0,18}) packets dropped by kernel\Z"),
        ),
    )
    observed: dict[str, int] = {}
    positions: list[int] = []
    for name, pattern in patterns:
        matches = [
            (index, match)
            for index, line in enumerate(lines)
            if (match := pattern.fullmatch(line)) is not None
        ]
        if len(matches) != 1:
            fail(f"{label} lacks exactly one canonical tcpdump {name} counter")
        index, match = matches[0]
        value = int(match.group(1))
        if value > MAX_COUNTER:
            fail(f"{label} tcpdump {name} counter exceeds its bound")
        observed[name] = value
        positions.append(index)
    if positions != list(range(len(lines) - 3, len(lines))):
        fail(f"{label} has noncanonical tcpdump terminal receipt ordering")
    if any("packets" in line for line in lines[:-3]):
        fail(f"{label} has duplicate or noncanonical tcpdump counter lines")
    if (
        observed["captured"] != expected_packets
        or observed["received"] != expected_packets
        or observed["dropped"] != 0
    ):
        fail(f"{label} tcpdump terminal counters differ from its canonical pcap")


def validate_raw_planned_resources(value: Any, profile: str, label: str) -> None:
    resources = raw_array(value, label, length=10 if profile == "cone-direct" else 11)
    observed = []
    for index, raw_resource in enumerate(resources):
        resource = raw_object(raw_resource, f"{label}[{index}]")
        if set(resource) != {"kind", "name", "role"}:
            fail(f"{label}[{index}] has an unexpected resource shape")
        observed.append((resource.get("kind"), resource.get("name"), resource.get("role")))
    expected = [
        ("network", "aster-lab-lan-a", "lan-a"),
        ("network", "aster-lab-wan", "wan"),
        ("network", "aster-lab-lan-b", "lan-b"),
        *[
            ("container", f"aster-lab-{role}", role)
            for role in ("provision", "node-a", "nat-a", "route-a", "nat-b", "node-b", "route-b")
        ],
    ]
    if profile == "restrictive-relay":
        expected.append(("container", "aster-lab-infra", "infra"))
    if observed != expected:
        fail(f"{label} differs from the exact selected NAT resource plan")


def validate_raw_scenario_request(
    value: Any, profile: str, receipt_cell: dict[str, Any], label: str
) -> None:
    scenario = raw_exact_object(
        value,
        {
            "schema",
            "operation",
            "scenario",
            "profile",
            "scope",
            "topic",
            "duration_seconds",
            "physical_hosts",
            "namespace_isolation",
            "infrastructure_free",
            "controlled_relay",
            "physical_nat_claim",
            "public_internet",
        },
        label,
    )
    controlled_relay = profile == "restrictive-relay"
    expected = {
        "schema": RAW_CONTROLLER_SCHEMA,
        "operation": profile,
        "scenario": "selected-iroh-nat-acceptance",
        "profile": profile,
        "scope": f"lab/selected-iroh-nat/{profile}",
        "topic": "lab.selected-iroh-nat",
        "duration_seconds": 30,
        "physical_hosts": 1,
        "namespace_isolation": True,
        "infrastructure_free": not controlled_relay,
        "controlled_relay": controlled_relay,
        "physical_nat_claim": False,
        "public_internet": False,
    }
    raw_equal(scenario, expected, label)
    raw_equal(
        scenario["controlled_relay"],
        receipt_cell["infrastructure"]["controlled_relay"],
        f"{label}.controlled_relay",
    )


def selected_nat_expected_events(profile: str, run_id: str) -> list[dict[str, Any]]:
    def event(event_name: str, **fields: Any) -> dict[str, Any]:
        return {
            "schema": RAW_CONTROLLER_SCHEMA,
            "run_id": run_id,
            "profile": profile,
            "event": event_name,
            **fields,
        }

    def resource(name: str, kind: str, role: str) -> dict[str, Any]:
        return event("resource-removed", kind=kind, name=name, role=role)

    expected = [
        resource("aster-lab-provision", "container", "provision"),
        event(
            "resource-created",
            kind="network",
            name="aster-lab-lan-a",
            role="lan-a",
        ),
        event(
            "resource-created",
            kind="network",
            name="aster-lab-wan",
            role="wan",
        ),
        event(
            "resource-created",
            kind="network",
            name="aster-lab-lan-b",
            role="lan-b",
        ),
        resource("aster-lab-route-a", "container", "route-a"),
        resource("aster-lab-route-b", "container", "route-b"),
        resource("aster-lab-provision", "container", "provision"),
        event("selected-nat-cell-verified", status="pass"),
        event(
            "cleanup-absent",
            kind="container",
            name="aster-lab-provision",
            role="provision",
        ),
        resource("aster-lab-node-a", "container", "node-a"),
        resource("aster-lab-nat-a", "container", "nat-a"),
        event(
            "cleanup-absent",
            kind="container",
            name="aster-lab-route-a",
            role="route-a",
        ),
        resource("aster-lab-nat-b", "container", "nat-b"),
        resource("aster-lab-node-b", "container", "node-b"),
        event(
            "cleanup-absent",
            kind="container",
            name="aster-lab-route-b",
            role="route-b",
        ),
    ]
    if profile == "restrictive-relay":
        expected.append(resource("aster-lab-infra", "container", "infra"))
    expected.extend(
        [
            resource("aster-lab-lan-a", "network", "lan-a"),
            resource("aster-lab-wan", "network", "wan"),
            resource("aster-lab-lan-b", "network", "lan-b"),
            event(
                "selected-nat-cleanup-verified",
                resources=10 if profile == "cone-direct" else 11,
                status="pass",
            ),
        ]
    )
    return expected


def validate_raw_events(value: str, profile: str, run_id: str, label: str) -> None:
    if not value.endswith("\n") or "\r" in value or "\x00" in value:
        fail(f"{label} has a forbidden or truncated encoding")
    lines = value.splitlines()
    expected = selected_nat_expected_events(profile, run_id)
    if len(lines) != len(expected) or any(not line for line in lines):
        fail(f"{label} does not contain the exact selected NAT lifecycle")
    for index, (line, expected_record) in enumerate(zip(lines, expected)):
        item_label = f"{label}[{index}]"
        try:
            record = json.loads(
                line,
                object_pairs_hook=duplicate_safe_object,
                parse_constant=reject_json_constant,
            )
        except (json.JSONDecodeError, DuplicateKey):
            fail(f"{item_label} is not duplicate-safe JSON")
        if type(record) is not dict:
            fail(f"{item_label} is not an object")
        canonical = json.dumps(
            record, sort_keys=True, separators=(",", ":"), ensure_ascii=True
        )
        if canonical != line:
            fail(f"{item_label} is not canonical JSON Lines")
        exact = raw_exact_object(
            record, set(expected_record) | {"utc"}, item_label
        )
        exact_string(exact.get("utc"), f"{item_label}.utc", pattern=UTC_TIMESTAMP)
        without_utc = {key: value for key, value in exact.items() if key != "utc"}
        raw_equal(without_utc, expected_record, item_label)


def validate_raw_event(
    finalization: dict[str, Any],
    receipt_cell: dict[str, Any],
    transfer_counts: dict[str, int],
    label: str,
) -> None:
    raw_event = raw_exact_object(
        finalization.get("event"),
        {
            "publish",
            "verify",
            "transfer_insertions",
            "transfer_fetches",
            "sealed_sha256",
        },
        f"{label}.event",
    )
    publish = raw_object(raw_event.get("publish"), f"{label}.event.publish")
    verify = raw_object(raw_event.get("verify"), f"{label}.event.verify")
    receipt = receipt_cell["event"]
    for field in (
        "event_id",
        "publisher",
        "payload_sha256",
        "sealed_sha256",
        "canary_sha256",
    ):
        raw_equal(publish.get(field), receipt[field], f"{label}.event.publish.{field}")
    raw_equal(verify.get("event_id"), receipt["event_id"], f"{label}.event.verify.event_id")
    raw_equal(
        verify.get("publisher"), receipt["publisher"], f"{label}.event.verify.publisher"
    )
    raw_equal(
        verify.get("canary_sha256"),
        receipt["canary_sha256"],
        f"{label}.event.verify.canary_sha256",
    )
    raw_equal(
        verify.get("payload_sha256"),
        receipt["payload_sha256"],
        f"{label}.event.verify.payload_sha256",
    )
    for raw_name, receipt_name in (
        ("payload_bytes", "payload_bytes"),
        ("sequence", "source_sequence"),
    ):
        raw_equal(
            raw_nonnegative(publish.get(raw_name), f"{label}.event.publish.{raw_name}"),
            receipt[receipt_name],
            f"{label}.event.publish.{raw_name}",
        )
    for raw_name, receipt_name in (
        ("deliveries", "destination_deliveries"),
        ("attempt", "destination_attempt"),
    ):
        raw_equal(
            raw_nonnegative(verify.get(raw_name), f"{label}.event.verify.{raw_name}"),
            receipt[receipt_name],
            f"{label}.event.verify.{raw_name}",
        )
    raw_equal(
        raw_boolean(publish.get("inserted"), f"{label}.event.publish.inserted"),
        receipt["source_inserted"],
        f"{label}.event.publish.inserted",
    )
    for field in ("acknowledged", "empty_after_ack", "exact_query"):
        raw_equal(
            raw_boolean(verify.get(field), f"{label}.event.verify.{field}"),
            receipt[field],
            f"{label}.event.verify.{field}",
        )
    raw_equal(
        raw_boolean(publish.get("exact_query"), f"{label}.event.publish.exact_query"),
        True,
        f"{label}.event.publish.exact_query",
    )
    for field in ("replay_ack", "replay_subscription"):
        raw_equal(verify.get(field), receipt[field], f"{label}.event.verify.{field}")
    raw_equal(transfer_counts, {"inserted": 1, "fetched": 1}, f"{label}.event transfers")
    raw_equal(
        raw_event.get("transfer_insertions"),
        transfer_counts["inserted"],
        f"{label}.event.insertions",
    )
    raw_equal(
        raw_event.get("transfer_fetches"),
        transfer_counts["fetched"],
        f"{label}.event.fetches",
    )
    raw_equal(
        raw_event.get("sealed_sha256"),
        "not-exposed-by-production-api",
        f"{label}.event.sealed_sha256",
    )


def validate_raw_node_transcript(
    text: str,
    *,
    profile: str,
    node_role: str,
    mission_authority: str,
    identity: dict[str, str],
    peer: dict[str, str],
    result: dict[str, Any],
    receipt_cell: dict[str, Any],
    label: str,
) -> list[dict[str, str]]:
    stdout_marker = "ASTER_SELECTED_NAT_TRANSCRIPT version=1 stream=stdout\n"
    stderr_marker = "ASTER_SELECTED_NAT_TRANSCRIPT version=1 stream=stderr\n"
    if not text.startswith(stdout_marker) or text.count(stderr_marker) != 1:
        fail(f"{label} lacks the exact stdout/stderr transcript delimiters")
    stdout, stderr = text[len(stdout_marker) :].split(stderr_marker, 1)
    stdout_lines = stdout.splitlines()
    if (
        len(stdout_lines) < 3
        or not stdout.endswith("\n")
        or not stdout_lines[0].startswith("READY ")
        or not stdout_lines[-1].startswith("STOP ")
        or any(
            not line.startswith("CONTACT ") or not line.endswith("status=pass")
            for line in stdout_lines[1:-1]
        )
    ):
        fail(f"{label} does not contain canonical READY/CONTACT+/STOP stdout")
    if stderr != "":
        fail(f"{label} contains unexpected node stderr")
    ready = exact_raw_receipt(stdout, "READY", label)
    stop = exact_raw_receipt(stdout, "STOP", label)
    contacts = [
        parse_raw_receipt_line(line, "CONTACT", f"{label}.CONTACT")
        for line in stdout_lines[1:-1]
    ]
    if set(ready) != RAW_NODE_READY_KEYS:
        fail(f"{label}.READY has missing or unexpected fields")
    if set(stop) != RAW_NODE_STOP_KEYS:
        fail(f"{label}.STOP has missing or unexpected fields")
    if any(set(contact) != RAW_NODE_CONTACT_KEYS for contact in contacts):
        fail(f"{label}.CONTACT has missing or unexpected fields")
    expected_route = "direct" if profile == "cone-direct" else "direct-plus-controlled-relay"
    expected_path = "direct" if profile == "cone-direct" else "relay"
    expected_readiness = "not-applicable" if profile == "cone-direct" else "deferred"
    expected_relay_url = "none" if profile == "cone-direct" else "https://relay.aster.test:8443/"
    expected_relay_trust = "none" if profile == "cone-direct" else "explicit-der-roots"
    expected_bind = "10.250.1.10:44000" if node_role == "node-a" else "10.250.2.10:44000"
    for field, expected in (
        ("selected", "true"),
        ("carrier_id", identity["carrier_id"]),
        ("mission_id", identity["mission_id"]),
        ("mission_authority", mission_authority),
        ("state", f"/output/{node_role}"),
        ("peers", "1"),
        ("application", "relay"),
        ("carrier_route", expected_route),
        ("controlled_relay_url", expected_relay_url),
        ("controlled_relay_trust", expected_relay_trust),
        ("controlled_relay_readiness", expected_readiness),
        ("public_relay_fallback", "false"),
        ("hosted_discovery", "false"),
        ("nat_traversal", "not-claimed"),
        ("path_observation", "not-authorization"),
        ("mission_auth", "hybrid-pq"),
        ("provisioning", "unprotected-reference"),
        ("semantics", "source-authenticated-event"),
        ("reconciliation_classes", "event,state,record,blob-v5-opt-in"),
        ("controls", "source-authenticated-flash"),
        ("commit_before_activate", "true"),
        ("content_admission", "capability-gated"),
    ):
        raw_equal(ready.get(field), expected, f"{label}.READY.{field}")
    if raw_receipt_nonnegative(ready, "pid", f"{label}.READY") <= 0:
        fail(f"{label}.READY.pid is not positive")
    sockets = exact_string(ready.get("sockets"), f"{label}.READY.sockets", maximum=1024)
    raw_equal(sockets, expected_bind, f"{label}.READY exact private bind socket")
    transition_total = 0
    for index, contact in enumerate(contacts):
        contact_label = f"{label}.CONTACT[{index}]"
        for field, expected in (
            ("carrier_peer", peer["carrier_id"]),
            ("mission_peer", peer["mission_id"]),
            ("carrier_path", expected_path),
            ("carrier_path_transitions_saturated", "false"),
            ("path_observation", "not-authorization"),
            ("mission_auth", "hybrid-pq"),
            ("semantics", "source-authenticated-event"),
            ("reconciliation_classes", "event,state,record,blob"),
            ("controls", "source-authenticated-flash"),
            ("content_admission", "capability-gated"),
            ("status", "pass"),
        ):
            raw_equal(contact.get(field), expected, f"{contact_label}.{field}")
        if contact.get("direction") not in {"in", "out"}:
            fail(f"{contact_label}.direction is not a selected transport direction")
        rounds = raw_receipt_nonnegative(contact, "rounds", contact_label)
        handshake_frames = raw_receipt_nonnegative(
            contact, "handshake_frames", contact_label
        )
        handshake_bytes = raw_receipt_nonnegative(
            contact, "handshake_bytes", contact_label
        )
        protected_frames = raw_receipt_nonnegative(
            contact, "protected_frames", contact_label
        )
        protected_bytes = raw_receipt_nonnegative(
            contact, "protected_bytes", contact_label
        )
        if (
            not 1 <= rounds <= 4_096
            or min(
                handshake_frames,
                handshake_bytes,
                protected_frames,
                protected_bytes,
            )
            <= 0
            or handshake_frames != 4
            or protected_frames % 2 != 0
            or 2 * rounds > protected_frames
            or handshake_frames + protected_frames > 8_192
            or handshake_bytes + protected_bytes > 64 * 1024 * 1024
            or handshake_bytes < handshake_frames
            or protected_bytes < protected_frames
        ):
            fail(f"{contact_label} transport accounting differs from runtime bounds")
        transitions = raw_receipt_nonnegative(
            contact, "carrier_path_transitions", contact_label
        )
        if transitions > MAX_TRANSITIONS:
            fail(f"{contact_label} exceeds the path transition bound")
        transition_total += transitions
        if transition_total > MAX_TRANSITIONS:
            fail(f"{label} exceeds the aggregate path transition bound")
    transfer_fields = RECONCILIATION_KEYS - {"status", "contacts"}
    expected_transfer = {
        field: (
            1
            if (node_role == "node-a" and field == "offered")
            or (node_role == "node-b" and field in {"fetched", "inserted"})
            else 0
        )
        for field in transfer_fields
    }
    observed_transfers = 0
    for index, contact in enumerate(contacts):
        observed = {
            field: raw_receipt_nonnegative(
                contact, field, f"{label}.CONTACT[{index}]"
            )
            for field in transfer_fields
        }
        if observed == expected_transfer:
            observed_transfers += 1
        elif any(observed.values()):
            fail(f"{label}.CONTACT[{index}] has an unexpected Event transfer shape")
    if observed_transfers != 1 or {
        field: raw_receipt_nonnegative(
            contacts[-1], field, f"{label}.final_CONTACT"
        )
        for field in transfer_fields
    } != {field: 0 for field in transfer_fields}:
        fail(f"{label} lacks one exact role-bound transfer before its final no-op")
    final_contact = contacts[-1]
    for field in RECONCILIATION_KEYS - {"status", "contacts"}:
        raw_equal(
            raw_receipt_nonnegative(final_contact, field, f"{label}.final_CONTACT"),
            receipt_cell["reconciliation"][field],
            f"{label}.final_CONTACT.{field}",
        )
    for field, expected in (
        ("lifecycle", "complete"),
        ("sync_status", "contacts_observed"),
        ("carrier_id", identity["carrier_id"]),
        ("mission_id", identity["mission_id"]),
        ("path_observation", "not-authorization"),
        ("mission_auth", "hybrid-pq"),
        ("provisioning", "unprotected-reference"),
        ("semantics", "source-authenticated-event"),
        ("reconciliation_classes", "event,state,record,blob-v5"),
        ("controls_semantics", "source-authenticated-flash"),
    ):
        raw_equal(stop.get(field), expected, f"{label}.STOP.{field}")
    raw_equal(
        raw_receipt_nonnegative(stop, "contacts", f"{label}.STOP"),
        len(contacts),
        f"{label}.STOP.contacts",
    )
    for field in (
        "contact_errors",
        "unknown_path_contacts",
        "carrier_path_transition_saturations",
    ):
        raw_equal(
            raw_receipt_nonnegative(stop, field, f"{label}.STOP"),
            0,
            f"{label}.STOP.{field}",
        )
    total = len(contacts)
    direct = raw_receipt_nonnegative(stop, "direct_contacts", f"{label}.STOP")
    relay = raw_receipt_nonnegative(stop, "relay_contacts", f"{label}.STOP")
    raw_equal(
        (direct, relay),
        (total, 0) if profile == "cone-direct" else (0, total),
        f"{label}.STOP path counts",
    )
    terminal_inventory = {
        "opaque_items": 0,
        "opaque_acceptance_markers": 0,
        "events": 1,
        "event_acceptance_markers": 1,
        "route_cached_events": 0,
        "controls": 0,
        "applied_controls": 0,
        "pending_controls": 0,
        "control_highwater": 0,
        "blobs": 0,
        "pending_blobs": 0,
        "blob_ranges_fetched": 0,
        "blob_bytes_fetched": 0,
        "blob_remaining": 0,
        "blob_deferred": 0,
    }
    for field, expected in terminal_inventory.items():
        raw_equal(
            raw_receipt_nonnegative(stop, field, f"{label}.STOP"),
            expected,
            f"{label}.STOP.{field}",
        )
    stop_transitions = raw_receipt_nonnegative(
        stop, "carrier_path_transitions", f"{label}.STOP"
    )
    raw_equal(
        stop_transitions,
        transition_total,
        f"{label}.STOP carrier_path_transitions CONTACT sum",
    )
    raw_equal(
        stop_transitions,
        raw_nonnegative(result.get("transition_count"), f"{label}.result.transition_count"),
        f"{label}.STOP.carrier_path_transitions",
    )
    raw_equal(result.get("ready"), ready, f"{label}.result.ready")
    raw_equal(result.get("contacts"), contacts, f"{label}.result.contacts")
    raw_equal(result.get("stop"), stop, f"{label}.result.stop")
    return contacts


def validate_raw_relay_log(
    text: str,
    finalization: dict[str, Any],
    receipt_cell: dict[str, Any],
    label: str,
) -> None:
    validate_raw_receipt_sequence(
        text,
        ["SELECTED_NAT_RELAY_READY", "SELECTED_NAT_RELAY_STOP"],
        label,
    )
    ready = exact_raw_receipt(text, "SELECTED_NAT_RELAY_READY", label)
    stop = exact_raw_receipt(text, "SELECTED_NAT_RELAY_STOP", label)
    if set(ready) != {
        "status",
        "version",
        "https",
        "http",
        "tls",
        "server_trust_claim",
        "allowlist",
        "allowlist_count",
        "max_admitted_connections",
        "pre_auth_connection_cap",
        "client_rx_bytes_per_second",
        "client_rx_max_burst_bytes",
        "key_cache_capacity",
        "secrets_logged",
        "public_relay_fallback",
        "hosted_discovery",
        "port_mapper",
    }:
        fail(f"{label}.READY has missing or unexpected fields")
    if set(stop) != {
        "status",
        "version",
        "accepted_connections",
        "denied_connections",
        "active_connections",
        "peak_active_connections",
        "sessions",
        "bytes_up",
        "bytes_down",
        "max_admitted_connections",
        "pre_auth_connection_cap",
        "client_rx_bytes_per_second",
        "client_rx_max_burst_bytes",
        "key_cache_capacity",
        "allowlist",
        "allowlist_count",
        "server_trust_claim",
        "graceful",
    }:
        fail(f"{label}.STOP has missing or unexpected fields")
    relay = receipt_cell["relay"]
    for field, expected in (
        ("status", "ready"),
        ("version", "1"),
        ("https", "0.0.0.0:8443"),
        ("http", "0.0.0.0:8080"),
        ("tls", relay["tls_mode"]),
        ("server_trust_claim", relay["server_trust_claim"]),
        ("allowlist", relay["allowlist_mode"]),
        ("allowlist_count", "2"),
        ("pre_auth_connection_cap", relay["pre_auth_connection_cap"]),
        ("secrets_logged", "false"),
        ("public_relay_fallback", "false"),
        ("hosted_discovery", "false"),
        ("port_mapper", "false"),
    ):
        raw_equal(ready.get(field), expected, f"{label}.READY.{field}")
    for field, expected in (
        ("status", "pass"),
        ("version", "1"),
        ("allowlist", relay["allowlist_mode"]),
        ("allowlist_count", "2"),
        ("server_trust_claim", relay["server_trust_claim"]),
        ("pre_auth_connection_cap", relay["pre_auth_connection_cap"]),
        ("graceful", "true"),
    ):
        raw_equal(stop.get(field), expected, f"{label}.STOP.{field}")
    for raw_name, receipt_name in (
        ("max_admitted_connections", "max_admitted_connections"),
        ("client_rx_bytes_per_second", "client_rx_bytes_per_second"),
        ("client_rx_max_burst_bytes", "client_rx_max_burst_bytes"),
        ("key_cache_capacity", "key_cache_capacity"),
    ):
        for marker, fields in (("READY", ready), ("STOP", stop)):
            raw_equal(
                raw_receipt_nonnegative(fields, raw_name, f"{label}.{marker}"),
                relay[receipt_name],
                f"{label}.{marker}.{raw_name}",
            )
    for raw_name, expected in (
        ("accepted_connections", relay["accepted_sessions"]),
        ("sessions", relay["accepted_sessions"]),
        ("denied_connections", relay["rejected_sessions"]),
        ("peak_active_connections", relay["observed_active_sessions_peak"]),
        ("active_connections", 0),
    ):
        raw_equal(
            raw_receipt_nonnegative(stop, raw_name, f"{label}.STOP"),
            expected,
            f"{label}.STOP.{raw_name}",
        )
    for field in ("bytes_up", "bytes_down"):
        if raw_receipt_nonnegative(stop, field, f"{label}.STOP") <= 0:
            fail(f"{label}.STOP.{field} did not observe bidirectional relay bytes")
    raw_relay = raw_exact_object(
        finalization.get("relay"), {"ready", "stop"}, f"{label}.finalization"
    )
    raw_equal(raw_relay.get("ready"), ready, f"{label}.finalization.ready")
    raw_equal(raw_relay.get("stop"), stop, f"{label}.finalization.stop")


def validate_raw_canary_scan(
    root_descriptor: int,
    scan: Any,
    receipt_cell: dict[str, Any],
    label: str,
    entries: dict[tuple[str, str], dict[str, Any]],
    finalization: dict[str, Any],
    route_sequences: dict[str, int],
) -> dict[str, dict[str, Any]]:
    raw_scan = raw_exact_object(
        scan,
        {
            "schema",
            "algorithm",
            "canary_bytes",
            "canary_sha256",
            "representations",
            "positive_control",
            "classes",
            "artifact_classes",
            "class_match_counts",
            "chronology",
            "matches",
            "status",
        },
        label,
    )
    receipt = receipt_cell["canary_scan"]
    raw_equal(raw_scan.get("schema"), RAW_CONTROLLER_SCHEMA, f"{label}.schema")
    raw_equal(raw_scan.get("status"), "pass", f"{label}.status")
    raw_equal(raw_scan.get("algorithm"), "exact-byte-sequence/v1", f"{label}.algorithm")
    raw_equal(raw_scan.get("canary_bytes"), 32, f"{label}.canary_bytes")
    raw_equal(
        raw_scan.get("canary_sha256"), receipt_cell["event"]["canary_sha256"],
        f"{label}.canary_sha256",
    )
    for field in ("classes", "chronology", "class_match_counts"):
        raw_equal(raw_scan.get(field), receipt[field], f"{label}.{field}")
    raw_equal(raw_scan.get("matches"), receipt["match_count"], f"{label}.matches")
    positive = raw_exact_object(
        raw_scan.get("positive_control"),
        {"path_class", "bytes", "expected", "observed", "class_match_counts", "pass"},
        f"{label}.positive_control",
    )
    raw_equal(
        positive.get("path_class"),
        "private-ephemeral",
        f"{label}.positive_control.path_class",
    )
    raw_equal(positive.get("bytes"), 184, f"{label}.positive_control.bytes")
    receipt_positive = receipt["positive_control"]
    for raw_name, receipt_name in (
        ("expected", "expected_matches"),
        ("observed", "observed_matches"),
        ("class_match_counts", "class_match_counts"),
    ):
        raw_equal(
            positive.get(raw_name),
            receipt_positive[receipt_name],
            f"{label}.positive_control.{raw_name}",
        )
    raw_equal(positive.get("pass"), True, f"{label}.positive_control.pass")
    representations = raw_array(
        raw_scan.get("representations"), f"{label}.representations", length=3
    )
    for index, representation in enumerate(CANARY_CLASSES):
        record = raw_exact_object(
            representations[index],
            {
                "name",
                "bytes",
                "needle_sha256",
                "positive_control_expected",
                "positive_control_observed",
            },
            f"{label}.representations[{index}]",
        )
        raw_equal(record.get("name"), representation, f"{label}.representations[{index}].name")
        raw_equal(
            record.get("positive_control_expected"),
            1,
            f"{label}.representations[{index}].expected",
        )
        raw_equal(
            record.get("positive_control_observed"),
            1,
            f"{label}.representations[{index}].observed",
        )
        expected_bytes = (32, 64, 44)[index]
        bounded_int(
            record.get("bytes"),
            f"{label}.representations[{index}].bytes",
            expected=expected_bytes,
        )
        needle_sha256 = hex_32(
            record.get("needle_sha256"),
            f"{label}.representations[{index}].needle_sha256",
        )
        if representation == "raw-bytes":
            raw_equal(
                needle_sha256,
                receipt_cell["event"]["canary_sha256"],
                f"{label}.representations[{index}].needle_sha256",
            )
    artifact_classes = raw_array(
        raw_scan.get("artifact_classes"), f"{label}.artifact_classes", length=3
    )
    scanned = 0
    profile = receipt_cell["name"]
    expected_pcap = [
        (
            str(entries[(profile, f"{router}-wan-pcap")]["path"]).removeprefix(
                f"cells/{profile}/"
            ),
            entries[(profile, f"{router}-wan-pcap")],
            "retained",
        )
        for router in ("nat-a", "nat-b")
    ]
    expected_log_roles = [
        "prepare-log",
        "publish-log",
        "verify-log",
        "node-a-log",
        "node-b-log",
    ]
    if profile == "restrictive-relay":
        expected_log_roles.extend(("relay-log", "relay-material-log"))
    retained_logs = {
        role: (
            str(entries[(profile, role)]["path"]).removeprefix(f"cells/{profile}/"),
            entries[(profile, role)],
            "retained",
        )
        for role in expected_log_roles
    }
    expected_certificates = (
        [
            (
                str(entries[(profile, role)]["path"]).removeprefix(
                    f"cells/{profile}/"
                ),
                entries[(profile, role)],
                "retained",
            )
            for role in ("relay-ca-der", "relay-cert-der")
        ]
        if profile == "restrictive-relay"
        else []
    )
    pcap_authority = raw_object(finalization.get("pcap"), f"{label}.pcap_authority")
    capture_stderr: dict[str, dict[str, Any]] = {}
    capture_paths: dict[str, str] = {}
    for index, router in enumerate(("nat-a", "nat-b")):
        capture = raw_object(
            pcap_authority.get(router), f"{label}.pcap_authority.{router}"
        )
        receipt_capture = receipt_cell["pcap"]["captures"][index]
        raw_equal(
            receipt_capture["role"],
            f"{router}-wan",
            f"{label}.receipt_pcap.{router}.role",
        )
        expected_packets = bounded_int(
            receipt_capture["packets"],
            f"{label}.receipt_pcap.{router}.packets",
            minimum=1,
        )
        stderr_path = exact_string(
            capture.get("tcpdump_stderr"),
            f"{label}.pcap_authority.{router}.tcpdump_stderr",
            maximum=64,
        )
        if re.fullmatch(r"command-[0-9]{4,}\.stderr", stderr_path) is None:
            fail(f"{label}.pcap_authority.{router} has a malformed stderr path")
        stderr_sha256 = hex_32(
            capture.get("tcpdump_stderr_sha256"),
            f"{label}.pcap_authority.{router}.tcpdump_stderr_sha256",
        )
        if stderr_path in capture_stderr:
            fail(f"{label}.pcap_authority repeats a capture stderr path")
        capture_stderr[stderr_path] = {
            "router": router,
            "sha256": stderr_sha256,
            "packets": expected_packets,
        }
        capture_paths[router] = stderr_path
    expected_log_sequence = [
        retained_logs["prepare-log"],
        retained_logs["publish-log"],
        retained_logs["verify-log"],
        retained_logs["node-a-log"],
        (None, None, "node-a-stderr"),
        retained_logs["node-b-log"],
        (None, None, "node-b-stderr"),
    ]
    if profile == "restrictive-relay":
        expected_log_sequence.extend(
            (retained_logs[role] for role in ("relay-log", "relay-material-log"))
        )
    expected_log_sequence.extend(
        (capture_paths[router], None, f"{router}-capture-stderr")
        for router in ("nat-a", "nat-b")
    )
    expected_sequences = {
        "pcap": expected_pcap,
        "log": expected_log_sequence,
        "public-certificate": expected_certificates,
    }
    unretained: dict[str, tuple[int, str]] = {}
    node_stderr_roles: dict[str, str] = {}
    for index, expected_class in enumerate(("pcap", "log", "public-certificate")):
        record = raw_exact_object(
            artifact_classes[index],
            {"class", "matches", "total_matches", "files"},
            f"{label}.artifact_classes[{index}]",
        )
        raw_equal(record.get("class"), expected_class, f"{label}.artifact_classes[{index}].class")
        raw_equal(record.get("total_matches"), 0, f"{label}.artifact_classes[{index}].matches")
        raw_equal(record.get("matches"), receipt["class_match_counts"], f"{label}.artifact_classes[{index}].class_matches")
        files = raw_array(
            record.get("files"), f"{label}.artifact_classes[{index}].files"
        )
        expected_sequence = expected_sequences[expected_class]
        if len(files) != len(expected_sequence):
            fail(f"{label}.{expected_class} scan sequence length differs")
        scanned += len(files)
        observed_paths: set[str] = set()
        for file_index, (raw_file, expected_file) in enumerate(
            zip(files, expected_sequence)
        ):
            file_label = f"{label}.artifact_classes[{index}].files[{file_index}]"
            file_record = raw_object(raw_file, file_label)
            if set(file_record) != {"path", "bytes", "sha256", "matches"}:
                fail(f"{file_label} has missing or unexpected scan metadata")
            path = exact_string(file_record.get("path"), f"{file_label}.path", maximum=192)
            if path in observed_paths:
                fail(f"{file_label}.path is duplicated")
            observed_paths.add(path)
            raw_equal(file_record.get("matches"), receipt["class_match_counts"], f"{file_label}.matches")
            size = raw_nonnegative(file_record.get("bytes"), f"{file_label}.bytes")
            digest = hex_32(file_record.get("sha256"), f"{file_label}.sha256")
            expected_path, retained, expected_kind = expected_file
            if retained is not None:
                raw_equal(path, expected_path, f"{file_label}.path")
                raw_equal(size, retained["bytes"], f"{file_label}.bytes")
                raw_equal(digest, retained["sha256"], f"{file_label}.sha256")
            elif expected_kind in {"node-a-stderr", "node-b-stderr"}:
                if (
                    re.fullmatch(r"command-[0-9]{4,}\.stderr", path) is None
                    or size != 0
                    or digest != hashlib.sha256(b"").hexdigest()
                    or path in unretained
                ):
                    fail(f"{file_label} is outside the bounded stderr class")
                unretained[path] = (size, digest)
                node_stderr_roles[expected_kind.removesuffix("-stderr")] = path
            elif expected_kind in {"nat-a-capture-stderr", "nat-b-capture-stderr"}:
                raw_equal(path, expected_path, f"{file_label}.path")
                if size <= 0 or size > 16 * 1024 * 1024 or path in unretained:
                    fail(f"{file_label} is outside the bounded capture stderr class")
                raw_equal(
                    digest,
                    capture_stderr[path]["sha256"],
                    f"{file_label}.sha256",
                )
                unretained[path] = (size, digest)
            else:
                fail(f"{file_label} is not an exact retained scan target")
    if set(node_stderr_roles) != {"node-a", "node-b"}:
        fail(f"{label}.log scan lacks role-bound node stderrs")
    stderr_sequences = {
        name: int(path.removeprefix("command-").removesuffix(".stderr"))
        for name, path in {
            **node_stderr_roles,
            **capture_paths,
        }.items()
    }
    if any(value <= 0 or value > 9_999_999 for value in stderr_sequences.values()):
        fail(f"{label}.log scan command sequence exceeds its bound")
    validate_raw_command_chronology(
        route_sequences,
        stderr_sequences,
        f"{label}.log scan command ordering",
    )
    if set(capture_stderr) - set(unretained):
        fail(f"{label}.log scan omits a tcpdump stderr authority")
    node_stderr = set(unretained) - set(capture_stderr)
    if len(node_stderr) != 2:
        fail(f"{label}.log scan lacks the two clean node stderr files")
    profile = receipt_cell["name"]
    stderr_authorities: dict[str, dict[str, Any]] = {}
    for path, (size, digest) in unretained.items():
        data = read_raw_scanned_file(
            root_descriptor,
            f"cells/{profile}/{path}",
            f"{label}.{path}",
            expected_size=size,
            expected_sha256=digest,
        )
        if path in node_stderr:
            if size != 0 or data != b"":
                fail(f"{label}.{path} is not an empty clean node stderr")
            stderr_authorities[f"cells/{profile}/{path}"] = {
                "bytes": size,
                "sha256": digest,
                "kind": "node-clean-empty",
            }
            continue
        capture_authority = capture_stderr[path]
        if size <= 0 or digest != capture_authority["sha256"]:
            fail(f"{label}.{path} differs from its tcpdump stderr authority")
        try:
            text = data.decode("utf-8", errors="strict")
        except UnicodeDecodeError:
            fail(f"{label}.{path} is not UTF-8 tcpdump stderr")
        validate_tcpdump_terminal_receipt(
            text,
            f"{label}.{path}",
            expected_packets=capture_authority["packets"],
        )
        relative = f"cells/{profile}/{path}"
        stderr_authorities[relative] = {
            "bytes": size,
            "sha256": digest,
            "kind": "tcpdump-terminal-complete",
            "path": relative,
            "profile": profile,
            "router": capture_authority["router"],
            "packets": capture_authority["packets"],
        }
    raw_equal(scanned, receipt["artifacts_scanned"], f"{label}.artifacts_scanned")
    if len(stderr_authorities) != 4:
        fail(f"{label} lacks four exact command stderr authorities")
    return stderr_authorities


def reverify_raw_command_stderr(
    root_descriptor: int, authorities: dict[str, dict[str, Any]]
) -> None:
    if len(authorities) != 8:
        fail("raw terminal command stderr authority count differs")
    capture_roles: set[tuple[str, str]] = set()
    for relative, authority in sorted(authorities.items()):
        data = read_raw_scanned_file(
            root_descriptor,
            relative,
            f"terminal {relative}",
            expected_size=authority["bytes"],
            expected_sha256=authority["sha256"],
        )
        if authority["kind"] == "node-clean-empty":
            if set(authority) != {"bytes", "sha256", "kind"}:
                fail(f"terminal {relative} has malformed node stderr authority")
            if data != b"":
                fail(f"terminal {relative} is not an exact empty node stderr")
            continue
        if set(authority) != {
            "bytes",
            "sha256",
            "kind",
            "path",
            "profile",
            "router",
            "packets",
        }:
            fail(f"terminal {relative} has malformed tcpdump stderr authority")
        if (
            authority["kind"] != "tcpdump-terminal-complete"
            or authority["path"] != relative
            or authority["profile"] not in CELL_NAMES
            or authority["router"] not in {"nat-a", "nat-b"}
            or re.fullmatch(
                rf"cells/{re.escape(authority['profile'])}/command-[0-9]{{4,}}\.stderr",
                relative,
            )
            is None
            or not data
        ):
            fail(f"terminal {relative} has an unknown stderr authority class")
        capture_role = (authority["profile"], authority["router"])
        if capture_role in capture_roles:
            fail(f"terminal {relative} repeats a tcpdump role authority")
        capture_roles.add(capture_role)
        try:
            text = data.decode("utf-8", errors="strict")
        except UnicodeDecodeError:
            fail(f"terminal {relative} is not UTF-8 tcpdump stderr")
        validate_tcpdump_terminal_receipt(
            text,
            f"terminal {relative}",
            expected_packets=authority["packets"],
        )
    if capture_roles != {
        (profile, router)
        for profile in CELL_NAMES
        for router in ("nat-a", "nat-b")
    }:
        fail("raw terminal tcpdump role authorities differ")


def verify_raw_tree_inventory(
    root_descriptor: int,
    document: dict[str, Any],
    entries: dict[tuple[str, str], dict[str, Any]],
    stderr_authorities: dict[str, dict[str, Any]],
) -> None:
    """Reject every path outside the exact retained evidence/state inventory."""
    exact_files = {str(entry["path"]) for entry in entries.values()}
    exact_files.update(stderr_authorities)
    receipt_relative = "selected-iroh-nat-receipt.json"
    restricted_files = {
        f"cells/{profile}/outputs/provision/private/{name}.bundle"
        for profile in CELL_NAMES
        for name in ("node-a", "node-b")
    }
    opaque_roots = {
        f"cells/{profile}/outputs/provision/{node}"
        for profile in CELL_NAMES
        for node in ("node-a", "node-b")
    }
    relay_private = "cells/restrictive-relay/outputs/provision/relay/private"
    exact_directories = {"", *opaque_roots, relay_private}
    for relative in exact_files | restricted_files | opaque_roots | {relay_private}:
        path = PurePosixPath(relative)
        for parent in path.parents:
            if str(parent) != ".":
                exact_directories.add(str(parent))

    canonical_receipt = (
        json.dumps(document, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
        + "\n"
    ).encode("ascii")

    def inside_opaque(relative: str) -> bool:
        return any(
            relative == root or relative.startswith(root + "/")
            for root in opaque_roots
        )

    def walk(descriptor: int, relative_directory: str) -> None:
        try:
            names = sorted(os.listdir(descriptor))
        except OSError:
            fail(f"raw inventory {relative_directory or '.'} could not be enumerated")
        if len(names) > 8_192:
            fail(f"raw inventory {relative_directory or '.'} has too many entries")
        for name in names:
            if not name or name in {".", ".."} or "/" in name or "\x00" in name:
                fail("raw inventory contains a noncanonical entry name")
            relative = f"{relative_directory}/{name}" if relative_directory else name
            try:
                before = os.stat(name, dir_fd=descriptor, follow_symlinks=False)
            except OSError:
                fail(f"raw inventory {relative} could not be inspected")
            if stat.S_ISDIR(before.st_mode):
                if relative not in exact_directories and not inside_opaque(relative):
                    fail(f"raw inventory contains unexpected directory {relative}")
                if before.st_uid != os.getuid() or stat.S_IMODE(before.st_mode) != 0o700:
                    fail(f"raw inventory directory metadata differs: {relative}")
                try:
                    child = os.open(name, DIRECTORY_OPEN_FLAGS, dir_fd=descriptor)
                except OSError:
                    fail(f"raw inventory directory could not be opened: {relative}")
                try:
                    opened = os.fstat(child)
                    if (opened.st_dev, opened.st_ino) != (before.st_dev, before.st_ino):
                        fail(f"raw inventory directory changed while opening: {relative}")
                    walk(child, relative)
                    final = os.fstat(child)
                    path_final = os.stat(name, dir_fd=descriptor, follow_symlinks=False)
                    for observed in (final, path_final):
                        if (
                            not stat.S_ISDIR(observed.st_mode)
                            or observed.st_uid != os.getuid()
                            or stat.S_IMODE(observed.st_mode) != 0o700
                            or (observed.st_dev, observed.st_ino)
                            != (opened.st_dev, opened.st_ino)
                        ):
                            fail(f"raw inventory directory changed: {relative}")
                finally:
                    os.close(child)
                continue
            if not stat.S_ISREG(before.st_mode):
                fail(f"raw inventory contains a symbolic or special entry: {relative}")
            allowed = (
                relative in exact_files
                or relative in restricted_files
                or inside_opaque(relative)
                or relative == receipt_relative
            )
            if not allowed:
                fail(f"raw inventory contains unexpected file {relative}")
            if (
                before.st_uid != os.getuid()
                or stat.S_IMODE(before.st_mode) != 0o600
                or before.st_nlink != 1
            ):
                fail(f"raw inventory file metadata differs: {relative}")
            if relative == receipt_relative:
                data = read_raw_scanned_file(
                    root_descriptor,
                    relative,
                    "raw inventory canonical receipt",
                    expected_size=len(canonical_receipt),
                    expected_sha256=hashlib.sha256(canonical_receipt).hexdigest(),
                    maximum=RECEIPT_MAX_BYTES,
                )
                if data != canonical_receipt:
                    fail("raw inventory receipt bytes differ from the accepted document")
        try:
            final_names = sorted(os.listdir(descriptor))
        except OSError:
            fail(f"raw inventory {relative_directory or '.'} could not be re-enumerated")
        if final_names != names:
            fail(f"raw inventory {relative_directory or '.'} changed during inspection")

    walk(root_descriptor, "")


def parse_raw_pcap_bytes(data: bytes, label: str) -> dict[str, Any]:
    if len(data) < 24 or len(data) > MAX_PCAP_BYTES:
        fail(f"{label} is outside the exact pcap byte bound")
    endian_by_magic = {
        bytes.fromhex("d4c3b2a1"): "little",
        bytes.fromhex("a1b2c3d4"): "big",
        bytes.fromhex("4d3cb2a1"): "little",
        bytes.fromhex("a1b23c4d"): "big",
    }
    endian = endian_by_magic.get(data[:4])
    if endian is None or int.from_bytes(data[20:24], endian) != 1:
        fail(f"{label} is not an Ethernet pcap")
    offset = 24
    packets = 0
    tuples: dict[tuple[str, str, int, int, str], int] = {}
    while offset < len(data):
        if len(data) - offset < 16:
            fail(f"{label} has a truncated record header")
        included = int.from_bytes(data[offset + 8 : offset + 12], endian)
        original = int.from_bytes(data[offset + 12 : offset + 16], endian)
        offset += 16
        if included > original or included > 262_144 or offset + included > len(data):
            fail(f"{label} has an invalid record length")
        frame = data[offset : offset + included]
        offset += included
        packets += 1
        if len(frame) < 14:
            continue
        network_offset = 14
        ether_type = int.from_bytes(frame[12:14], "big")
        if ether_type == 0x8100 and len(frame) >= 18:
            ether_type = int.from_bytes(frame[16:18], "big")
            network_offset = 18
        if ether_type != 0x0800 or len(frame) < network_offset + 20:
            continue
        version_ihl = frame[network_offset]
        if version_ihl >> 4 != 4:
            continue
        ihl = (version_ihl & 0x0F) * 4
        if ihl < 20 or len(frame) < network_offset + ihl + 4:
            continue
        protocol = {6: "tcp", 17: "udp"}.get(frame[network_offset + 9])
        if protocol is None:
            continue
        source = str(
            ipaddress.ip_address(frame[network_offset + 12 : network_offset + 16])
        )
        destination = str(
            ipaddress.ip_address(frame[network_offset + 16 : network_offset + 20])
        )
        transport = network_offset + ihl
        source_port = int.from_bytes(frame[transport : transport + 2], "big")
        destination_port = int.from_bytes(frame[transport + 2 : transport + 4], "big")
        key = (source, destination, source_port, destination_port, protocol)
        tuples[key] = tuples.get(key, 0) + 1
    if offset != len(data) or packets == 0:
        fail(f"{label} is empty or structurally incomplete")
    return {
        "bytes": len(data),
        "packets": packets,
        "sha256": sha256_bytes(data),
        "tuples": [
            {
                "source": key[0],
                "destination": key[1],
                "source_port": key[2],
                "destination_port": key[3],
                "protocol": key[4],
                "packets": count,
            }
            for key, count in sorted(tuples.items())
        ],
    }


def read_der_tlv(
    data: bytes, offset: int, limit: int, label: str
) -> tuple[int, int, int, int]:
    if offset >= limit or limit > len(data):
        fail(f"{label} is truncated")
    tag = data[offset]
    if tag & 0x1F == 0x1F or offset + 1 >= limit:
        fail(f"{label} uses an unsupported or truncated DER tag")
    first_length = data[offset + 1]
    cursor = offset + 2
    if first_length < 0x80:
        length = first_length
    else:
        count = first_length & 0x7F
        if count == 0 or count > 4 or cursor + count > limit:
            fail(f"{label} has an invalid DER length")
        encoded = data[cursor : cursor + count]
        if encoded[0] == 0:
            fail(f"{label} has a nonminimal DER length")
        length = int.from_bytes(encoded, "big")
        if length < 0x80:
            fail(f"{label} has a nonminimal long DER length")
        cursor += count
    end = cursor + length
    if end > limit:
        fail(f"{label} extends beyond its DER container")
    return tag, cursor, end, end


def der_children(
    data: bytes, start: int, end: int, label: str
) -> list[tuple[int, int, int, int, int]]:
    children = []
    offset = start
    while offset < end:
        tag, content_start, content_end, next_offset = read_der_tlv(
            data, offset, end, f"{label}[{len(children)}]"
        )
        children.append((tag, offset, content_start, content_end, next_offset))
        offset = next_offset
    if offset != end:
        fail(f"{label} does not consume its exact DER container")
    return children


ECDSA_SHA256_OID = bytes.fromhex("2a8648ce3d040302")
EC_PUBLIC_KEY_OID = bytes.fromhex("2a8648ce3d0201")
P256_OID = bytes.fromhex("2a8648ce3d030107")
P256_P = 0xFFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF
P256_A = P256_P - 3
P256_B = 0x5AC635D8AA3A93E7B3EBBD55769886BC651D06B0CC53B0F63BCE3C3E27D2604B
P256_N = 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551
P256_G = (
    0x6B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296,
    0x4FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F5,
)


def validate_der_algorithm(
    data: bytes, record: tuple[int, int, int, int, int], label: str
) -> bytes:
    tag, _raw_start, content_start, content_end, _next = record
    if tag != 0x30:
        fail(f"{label} is not an AlgorithmIdentifier sequence")
    children = der_children(data, content_start, content_end, label)
    if len(children) != 1 or children[0][0] != 0x06:
        fail(f"{label} has an invalid algorithm identifier")
    oid = data[children[0][2] : children[0][3]]
    if not oid or oid[-1] & 0x80:
        fail(f"{label} has a malformed algorithm OID")
    return oid


def validate_der_name(
    data: bytes,
    record: tuple[int, int, int, int, int],
    expected_common_name: bytes,
    label: str,
) -> bytes:
    if record[0] != 0x30:
        fail(f"{label} is not an X.509 Name")
    rdns = der_children(data, record[2], record[3], label)
    if len(rdns) != 1 or rdns[0][0] != 0x31:
        fail(f"{label} differs from the exact single-CN name")
    attributes = der_children(data, rdns[0][2], rdns[0][3], label)
    if len(attributes) != 1 or attributes[0][0] != 0x30:
        fail(f"{label} differs from the exact single-CN name")
    fields = der_children(data, attributes[0][2], attributes[0][3], label)
    if (
        len(fields) != 2
        or fields[0][0] != 0x06
        or data[fields[0][2] : fields[0][3]] != bytes.fromhex("550403")
        or fields[1][0] != 0x0C
        or data[fields[1][2] : fields[1][3]] != expected_common_name
    ):
        fail(f"{label} differs from the exact UTF8 common name")
    return data[record[1] : record[4]]


def validate_der_validity(
    data: bytes, record: tuple[int, int, int, int, int], label: str
) -> None:
    if record[0] != 0x30:
        fail(f"{label} is not a Validity sequence")
    fields = der_children(data, record[2], record[3], label)
    if (
        len(fields) != 2
        or fields[0][0] != 0x17
        or data[fields[0][2] : fields[0][3]] != b"750101000000Z"
        or fields[1][0] != 0x18
        or data[fields[1][2] : fields[1][3]] != b"40960101000000Z"
    ):
        fail(f"{label} differs from the fixed rcgen validity interval")


def validate_der_spki(
    data: bytes, record: tuple[int, int, int, int, int], label: str
) -> tuple[tuple[int, int], bytes, bytes]:
    if record[0] != 0x30:
        fail(f"{label} is not SubjectPublicKeyInfo")
    fields = der_children(data, record[2], record[3], label)
    if len(fields) != 2 or fields[0][0] != 0x30 or fields[1][0] != 0x03:
        fail(f"{label} has an invalid SubjectPublicKeyInfo shape")
    algorithm = der_children(data, fields[0][2], fields[0][3], f"{label}.algorithm")
    if (
        len(algorithm) != 2
        or [item[0] for item in algorithm] != [0x06, 0x06]
        or data[algorithm[0][2] : algorithm[0][3]] != EC_PUBLIC_KEY_OID
        or data[algorithm[1][2] : algorithm[1][3]] != P256_OID
    ):
        fail(f"{label} is not the exact P-256 SubjectPublicKeyInfo")
    encoded = data[fields[1][2] : fields[1][3]]
    if len(encoded) != 66 or encoded[:2] != b"\x00\x04":
        fail(f"{label} is not one uncompressed byte-aligned P-256 point")
    point = (int.from_bytes(encoded[2:34], "big"), int.from_bytes(encoded[34:], "big"))
    if not (0 <= point[0] < P256_P and 0 <= point[1] < P256_P) or (
        point[1] * point[1] - (point[0] ** 3 + P256_A * point[0] + P256_B)
    ) % P256_P:
        fail(f"{label} public point is not on P-256")
    return point, encoded[1:], data[record[1] : record[4]]


def p256_add(
    left: tuple[int, int] | None, right: tuple[int, int] | None
) -> tuple[int, int] | None:
    if left is None:
        return right
    if right is None:
        return left
    x1, y1 = left
    x2, y2 = right
    if x1 == x2 and (y1 + y2) % P256_P == 0:
        return None
    if left == right:
        slope = ((3 * x1 * x1 + P256_A) * pow(2 * y1, -1, P256_P)) % P256_P
    else:
        slope = ((y2 - y1) * pow(x2 - x1, -1, P256_P)) % P256_P
    x3 = (slope * slope - x1 - x2) % P256_P
    return x3, (slope * (x1 - x3) - y1) % P256_P


def p256_multiply(scalar: int, point: tuple[int, int]) -> tuple[int, int] | None:
    result = None
    addend: tuple[int, int] | None = point
    while scalar:
        if scalar & 1:
            result = p256_add(result, addend)
        addend = p256_add(addend, addend)
        scalar >>= 1
    return result


def der_positive_integer(
    data: bytes, record: tuple[int, int, int, int, int], label: str
) -> int:
    if record[0] != 0x02:
        fail(f"{label} is not a DER INTEGER")
    encoded = data[record[2] : record[3]]
    if (
        not encoded
        or encoded[0] & 0x80
        or (len(encoded) > 1 and encoded[0] == 0 and not encoded[1] & 0x80)
    ):
        fail(f"{label} is not a canonical positive DER INTEGER")
    return int.from_bytes(encoded, "big")


def verify_p256_signature(
    public_key: tuple[int, int], signed: bytes, signature: bytes, label: str
) -> None:
    outer = read_der_tlv(signature, 0, len(signature), label)
    if outer[0] != 0x30 or outer[3] != len(signature):
        fail(f"{label} is not one DER ECDSA signature")
    values = der_children(signature, outer[1], outer[2], label)
    if len(values) != 2:
        fail(f"{label} does not contain exactly r and s")
    r = der_positive_integer(signature, values[0], f"{label}.r")
    s = der_positive_integer(signature, values[1], f"{label}.s")
    if not (1 <= r < P256_N and 1 <= s < P256_N):
        fail(f"{label} scalar lies outside P-256")
    inverse = pow(s, -1, P256_N)
    digest_value = int.from_bytes(hashlib.sha256(signed).digest(), "big")
    candidate = p256_add(
        p256_multiply((digest_value * inverse) % P256_N, P256_G),
        p256_multiply((r * inverse) % P256_N, public_key),
    )
    if candidate is None or candidate[0] % P256_N != r:
        fail(f"{label} does not verify under the retained CA authority")


def validate_der_extensions(
    data: bytes,
    record: tuple[int, int, int, int, int],
    *,
    role: str,
    label: str,
) -> dict[str, bytes]:
    if record[0] != 0xA3:
        fail(f"{label} is not the X.509 extensions field")
    wrapped = der_children(data, record[2], record[3], label)
    if len(wrapped) != 1 or wrapped[0][0] != 0x30:
        fail(f"{label} does not contain one Extensions sequence")
    extensions = der_children(data, wrapped[0][2], wrapped[0][3], label)
    values: dict[bytes, tuple[bool, bytes]] = {}
    order: list[bytes] = []
    for index, extension in enumerate(extensions):
        extension_label = f"{label}.extension[{index}]"
        if extension[0] != 0x30:
            fail(f"{extension_label} is not a sequence")
        fields = der_children(data, extension[2], extension[3], extension_label)
        if len(fields) not in {2, 3} or fields[0][0] != 0x06:
            fail(f"{extension_label} has an invalid shape")
        value_index = 1
        critical = False
        if len(fields) == 3:
            if fields[1][0] != 0x01 or fields[1][3] - fields[1][2] != 1:
                fail(f"{extension_label} has a malformed critical flag")
            if data[fields[1][2] : fields[1][3]] != b"\xff":
                fail(f"{extension_label} has a noncanonical or false critical flag")
            critical = True
            value_index = 2
        if fields[value_index][0] != 0x04:
            fail(f"{extension_label} has no DER OCTET STRING value")
        oid = data[fields[0][2] : fields[0][3]]
        if oid in values:
            fail(f"{extension_label} repeats an extension OID")
        values[oid] = (critical, data[fields[value_index][2] : fields[value_index][3]])
        order.append(oid)
    expected_order = (
        [bytes.fromhex(value) for value in ("551d0f", "551d0e", "551d13")]
        if role == "ca"
        else [bytes.fromhex(value) for value in ("551d23", "551d11", "551d0f", "551d25")]
    )
    if order != expected_order:
        fail(f"{label} extension set/order differs from exact rcgen output")
    basic_record = values.get(bytes.fromhex("551d13"))
    basic_constraints = None if basic_record is None else basic_record[1]
    is_ca = False
    if basic_constraints is not None:
        tag, start, end, next_offset = read_der_tlv(
            basic_constraints, 0, len(basic_constraints), f"{label}.BasicConstraints"
        )
        if tag != 0x30 or next_offset != len(basic_constraints):
            fail(f"{label}.BasicConstraints is not one DER sequence")
        basic_fields = der_children(
            basic_constraints, start, end, f"{label}.BasicConstraints"
        )
        if basic_fields:
            first = basic_fields[0]
            if first[0] != 0x01 or first[3] - first[2] != 1:
                fail(f"{label}.BasicConstraints CA flag is malformed")
            encoded = basic_constraints[first[2] : first[3]]
            if encoded not in {b"\x00", b"\xff"}:
                fail(f"{label}.BasicConstraints CA flag is not canonical DER")
            is_ca = encoded == b"\xff"
    if role == "ca" and (basic_constraints is None or not is_ca):
        fail(f"{label} CA certificate omits BasicConstraints CA=true")
    if role == "server" and is_ca:
        fail(f"{label} server certificate asserts BasicConstraints CA=true")
    if role == "ca":
        if values[bytes.fromhex("551d13")][0] is not True or basic_constraints != bytes.fromhex(
            "30060101ff020100"
        ):
            fail(f"{label}.BasicConstraints differs from CA=true,pathLen=0 critical")
        if values[bytes.fromhex("551d0f")] != (
            True,
            bytes.fromhex("03020186"),
        ):
            fail(f"{label}.KeyUsage differs from the exact CA critical uses")
        ski_critical, ski = values[bytes.fromhex("551d0e")]
        if ski_critical or len(ski) != 22 or ski[:2] != b"\x04\x14":
            fail(f"{label}.SubjectKeyIdentifier differs from rcgen SHA-256 form")
        return {"subject_key_identifier": ski[2:]}
    if values[bytes.fromhex("551d0f")] != (
        True,
        bytes.fromhex("03020780"),
    ):
        fail(f"{label}.KeyUsage differs from critical digitalSignature")
    if values[bytes.fromhex("551d25")] != (
        False,
        bytes.fromhex("300a06082b06010505070301"),
    ):
        fail(f"{label}.ExtendedKeyUsage differs from serverAuth")
    aki_critical, aki = values[bytes.fromhex("551d23")]
    if aki_critical or len(aki) != 24 or aki[:4] != b"\x30\x16\x80\x14":
        fail(f"{label}.AuthorityKeyIdentifier differs from rcgen key-id form")
    san_record = values.get(bytes.fromhex("551d11"))
    san = None if san_record is None else san_record[1]
    if san is None:
        fail(f"{label} server certificate omits SubjectAltName")
    tag, start, end, next_offset = read_der_tlv(
        san, 0, len(san), f"{label}.SubjectAltName"
    )
    if tag != 0x30 or next_offset != len(san):
        fail(f"{label}.SubjectAltName is not one DER sequence")
    names = der_children(san, start, end, f"{label}.SubjectAltName")
    observed_dns = [san[item[2] : item[3]] for item in names if item[0] == 0x82]
    observed_ips = [san[item[2] : item[3]] for item in names if item[0] == 0x87]
    if (
        len(names) != 2
        or observed_dns != [b"relay.aster.test"]
        or observed_ips != [bytes((10, 250, 0, 20))]
    ):
        fail(f"{label}.SubjectAltName differs from the exact relay DNS/IP")
    if san_record[0]:
        fail(f"{label}.SubjectAltName is unexpectedly critical")
    return {"authority_key_identifier": aki[4:]}


def rcgen_serial_bytes(public_point: bytes) -> bytes:
    expected = bytearray(hashlib.sha256(public_point).digest()[:20])
    expected[0] &= 0x7F
    return bytes(expected).lstrip(b"\x00") or b"\x00"


def validate_x509_der(data: bytes, *, role: str, label: str) -> dict[str, Any]:
    if not data or len(data) > 1024 * 1024:
        fail(f"{label} is empty or exceeds the certificate byte cap")
    outer = read_der_tlv(data, 0, len(data), label)
    if outer[0] != 0x30 or outer[3] != len(data):
        fail(f"{label} is not one exact DER Certificate sequence")
    certificate = der_children(data, outer[1], outer[2], label)
    if [item[0] for item in certificate] != [0x30, 0x30, 0x03]:
        fail(f"{label} does not have the X.509 Certificate shape")
    tbs, algorithm, signature = certificate
    if validate_der_algorithm(data, algorithm, f"{label}.signatureAlgorithm") != ECDSA_SHA256_OID:
        fail(f"{label}.signatureAlgorithm is not ECDSA P-256/SHA-256")
    if signature[3] - signature[2] < 2 or data[signature[2]] != 0:
        fail(f"{label}.signatureValue is not a canonical byte-aligned BIT STRING")
    tbs_fields = der_children(data, tbs[2], tbs[3], f"{label}.TBSCertificate")
    if not tbs_fields or tbs_fields[0][0] != 0xA0:
        fail(f"{label}.version omits the mandatory rcgen v3 field")
    version = der_children(
        data, tbs_fields[0][2], tbs_fields[0][3], f"{label}.version"
    )
    if (
        len(version) != 1
        or version[0][0] != 0x02
        or data[version[0][2] : version[0][3]] != b"\x02"
    ):
        fail(f"{label}.version is not exact X.509 v3")
    index = 1
    if len(tbs_fields) < index + 7:
        fail(f"{label}.TBSCertificate omits mandatory fields")
    serial, tbs_algorithm, issuer, validity, subject, spki = tbs_fields[
        index : index + 6
    ]
    if serial[0] != 0x02 or not (1 <= serial[3] - serial[2] <= 20):
        fail(f"{label}.serialNumber is malformed")
    der_positive_integer(data, serial, f"{label}.serialNumber")
    if validate_der_algorithm(data, tbs_algorithm, f"{label}.tbs.signature") != ECDSA_SHA256_OID:
        fail(f"{label}.tbs.signature is not ECDSA P-256/SHA-256")
    if data[tbs_algorithm[1] : tbs_algorithm[4]] != data[algorithm[1] : algorithm[4]]:
        fail(f"{label} inner and outer signature algorithms differ")
    if [issuer[0], validity[0], subject[0], spki[0]] != [0x30, 0x30, 0x30, 0x30]:
        fail(f"{label}.TBSCertificate mandatory sequence shape differs")
    expected_subject = (
        b"Aster selected NAT laboratory CA" if role == "ca" else b"relay.aster.test"
    )
    issuer_raw = validate_der_name(
        data,
        issuer,
        b"Aster selected NAT laboratory CA",
        f"{label}.issuer",
    )
    subject_raw = validate_der_name(
        data, subject, expected_subject, f"{label}.subject"
    )
    if (role == "ca" and issuer_raw != subject_raw) or (
        role == "server" and issuer_raw == subject_raw
    ):
        fail(f"{label} issuer/subject relationship differs from its role")
    validate_der_validity(data, validity, f"{label}.validity")
    public_key, public_point, spki_der = validate_der_spki(
        data, spki, f"{label}.subjectPublicKeyInfo"
    )
    canonical_serial = rcgen_serial_bytes(public_point)
    if data[serial[2] : serial[3]] != canonical_serial:
        fail(f"{label}.serialNumber differs from rcgen public-key derivation")
    extension_records = tbs_fields[index + 6 :]
    if len(extension_records) != 1 or extension_records[0][0] != 0xA3:
        fail(f"{label} does not contain exactly one extensions field")
    extension_authority = validate_der_extensions(
        data, extension_records[0], role=role, label=f"{label}.extensions"
    )
    if role == "ca" and extension_authority["subject_key_identifier"] != hashlib.sha256(
        spki_der
    ).digest()[:20]:
        fail(f"{label}.SubjectKeyIdentifier differs from rcgen SPKI derivation")
    return {
        "tbs": data[tbs[1] : tbs[4]],
        "signature": data[signature[2] + 1 : signature[3]],
        "public_key": public_key,
        "issuer": issuer_raw,
        "subject": subject_raw,
        **extension_authority,
    }


def validate_raw_relay_certificates(
    root_descriptor: int,
    entries: dict[tuple[str, str], dict[str, Any]],
    relay_config: dict[str, Any],
) -> None:
    certificates: dict[str, dict[str, Any]] = {}
    for role, filename, certificate_role, fingerprint_field in (
        ("relay-ca-der", "ca.der", "ca", "root_fingerprint_sha256"),
        ("relay-cert-der", "server.cert.der", "server", "certificate_sha256"),
    ):
        entry = entries[("restrictive-relay", role)]
        data = read_raw_scanned_file(
            root_descriptor,
            f"cells/restrictive-relay/outputs/provision/relay/{filename}",
            f"cells.restrictive-relay.{role}",
            expected_size=entry["bytes"],
            expected_sha256=entry["sha256"],
            maximum=1024 * 1024,
        )
        certificates[certificate_role] = validate_x509_der(
            data,
            role=certificate_role,
            label=f"cells.restrictive-relay.{role}",
        )
        raw_equal(
            hashlib.sha256(data).hexdigest(),
            relay_config[fingerprint_field],
            f"cells.restrictive-relay.{role} fingerprint",
        )
    ca = certificates["ca"]
    server = certificates["server"]
    raw_equal(server["issuer"], ca["subject"], "relay server/CA issuer binding")
    raw_equal(
        server["authority_key_identifier"],
        ca["subject_key_identifier"],
        "relay server authority/CA subject key identifier binding",
    )
    verify_p256_signature(ca["public_key"], ca["tbs"], ca["signature"], "relay CA signature")
    verify_p256_signature(
        ca["public_key"],
        server["tbs"],
        server["signature"],
        "relay server certificate signature",
    )


def validate_raw_pcap_summary(
    summary: Any,
    finalization: dict[str, Any],
    receipt_cell: dict[str, Any],
    label: str,
    *,
    root_descriptor: int | None = None,
    entries: dict[tuple[str, str], dict[str, Any]] | None = None,
) -> None:
    raw_summary = raw_exact_object(
        summary, {"schema", "profile", "routers", "proof"}, label
    )
    raw_equal(raw_summary.get("schema"), RAW_CONTROLLER_SCHEMA, f"{label}.schema")
    raw_equal(raw_summary.get("profile"), receipt_cell["name"], f"{label}.profile")
    routers = raw_exact_object(
        raw_summary.get("routers"), {"nat-a", "nat-b"}, f"{label}.routers"
    )
    proof = raw_exact_object(
        raw_summary.get("proof"), {"nat-a", "nat-b"}, f"{label}.proof"
    )
    raw_equal(routers, finalization.get("pcap"), f"{label}.routers")
    raw_equal(proof, finalization.get("tuple_proof"), f"{label}.proof")
    aggregated = {
        "direct_cross_nat_packets": 0,
        "direct_probe_packets": 0,
        "controlled_relay_https_packets": 0,
        "controlled_relay_http_packets": 0,
        "unexpected_public_relay_packets": 0,
        "unexpected_hosted_discovery_packets": 0,
    }
    for index, router in enumerate(("nat-a", "nat-b")):
        capture = raw_exact_object(
            routers.get(router),
            {
                "bytes",
                "packets",
                "sha256",
                "drop_count",
                "path",
                "role",
                "tuples",
                "tcpdump_stderr",
                "tcpdump_stderr_sha256",
            },
            f"{label}.routers.{router}",
        )
        raw_equal(capture.get("role"), router, f"{label}.routers.{router}.role")
        raw_equal(
            capture.get("path"),
            f"outputs/{router}/{router}-wan.pcap",
            f"{label}.routers.{router}.path",
        )
        receipt_capture = receipt_cell["pcap"]["captures"][index]
        raw_equal(
            receipt_capture.get("role"),
            f"{router}-wan",
            f"{label}.routers.{router} public role",
        )
        for raw_name, receipt_name in (
            ("bytes", "bytes"),
            ("packets", "packets"),
            ("sha256", "sha256"),
            ("drop_count", "dropped_packets"),
        ):
            raw_equal(
                capture.get(raw_name),
                receipt_capture[receipt_name],
                f"{label}.routers.{router}.{raw_name}",
            )
        if (root_descriptor is None) != (entries is None):
            fail(f"{label} pcap replay authority is incomplete")
        if root_descriptor is not None and entries is not None:
            relative = (
                f"cells/{receipt_cell['name']}/outputs/{router}/{router}-wan.pcap"
            )
            manifest_entry = entries[(receipt_cell["name"], f"{router}-wan-pcap")]
            pcap_data = read_raw_scanned_file(
                root_descriptor,
                relative,
                f"{label}.routers.{router}.pcap",
                expected_size=manifest_entry["bytes"],
                expected_sha256=manifest_entry["sha256"],
                maximum=MAX_PCAP_BYTES,
            )
            parsed_capture = parse_raw_pcap_bytes(
                pcap_data, f"{label}.routers.{router}.pcap"
            )
            raw_equal(
                parsed_capture,
                {
                    "bytes": capture["bytes"],
                    "packets": capture["packets"],
                    "sha256": capture["sha256"],
                    "tuples": capture["tuples"],
                },
                f"{label}.routers.{router} pcap-derived tuple inventory",
            )
        tuples = raw_array(capture.get("tuples"), f"{label}.routers.{router}.tuples")
        observed_direct = 0
        observed_https = 0
        observed_http = 0
        tuple_packets = 0
        previous_tuple_key: tuple[str, str, int, int, str] | None = None
        own_external = "10.250.0.11" if router == "nat-a" else "10.250.0.12"
        for tuple_index, raw_record in enumerate(tuples):
            tuple_label = f"{label}.routers.{router}.tuples[{tuple_index}]"
            record = raw_exact_object(
                raw_record,
                {
                    "protocol",
                    "source",
                    "destination",
                    "source_port",
                    "destination_port",
                    "packets",
                },
                tuple_label,
            )
            protocol = exact_string(
                record.get("protocol"), f"{tuple_label}.protocol", maximum=8
            )
            source = exact_string(
                record.get("source"), f"{tuple_label}.source", maximum=64
            )
            destination = exact_string(
                record.get("destination"), f"{tuple_label}.destination", maximum=64
            )
            try:
                ipaddress.ip_address(source)
                ipaddress.ip_address(destination)
            except ValueError:
                fail(f"{tuple_label} contains a malformed IP address")
            source_port = raw_nonnegative(
                record.get("source_port"), f"{tuple_label}.source_port"
            )
            destination_port = raw_nonnegative(
                record.get("destination_port"), f"{tuple_label}.destination_port"
            )
            if source_port > 65535 or destination_port > 65535:
                fail(f"{tuple_label} contains an invalid transport port")
            packets = raw_nonnegative(record.get("packets"), f"{tuple_label}.packets")
            if packets < 1:
                fail(f"{tuple_label}.packets is not strictly positive")
            tuple_key = (
                source,
                destination,
                source_port,
                destination_port,
                protocol,
            )
            if previous_tuple_key is not None and tuple_key <= previous_tuple_key:
                fail(
                    f"{label}.routers.{router}.tuples is not the canonical sorted unique sequence"
                )
            previous_tuple_key = tuple_key
            tuple_packets += packets
            address_pair = {source, destination}
            is_direct = (
                protocol == "udp"
                and address_pair == {"10.250.0.11", "10.250.0.12"}
                and source_port == 44000
                and destination_port == 44000
            )
            is_https = (
                protocol == "tcp"
                and address_pair == {own_external, "10.250.0.20"}
                and (
                    (source == "10.250.0.20" and source_port == 8443)
                    or (destination == "10.250.0.20" and destination_port == 8443)
                )
            )
            is_http = (
                protocol == "tcp"
                and address_pair == {own_external, "10.250.0.20"}
                and (
                    (source == "10.250.0.20" and source_port == 8080)
                    or (destination == "10.250.0.20" and destination_port == 8080)
                )
            )
            if receipt_cell["name"] == "cone-direct":
                if not is_direct:
                    fail(f"{tuple_label} is outside the exact cone WAN tuple allowlist")
                observed_direct += packets
            elif not is_https:
                fail(f"{tuple_label} is outside the exact restrictive WAN tuple allowlist")
            if is_https:
                observed_https += packets
            if is_http:
                observed_http += packets
        if tuple_packets != receipt_capture["packets"]:
            fail(f"{label}.routers.{router} tuple packet accounting is not lossless")
        router_proof = raw_exact_object(
            proof.get(router),
            {
                "direct_udp_packets",
                "relay_https_tcp_packets",
                "relay_http_tcp_packets",
            },
            f"{label}.proof.{router}",
        )
        direct = raw_nonnegative(
            router_proof.get("direct_udp_packets"), f"{label}.proof.{router}.direct"
        )
        https = raw_nonnegative(
            router_proof.get("relay_https_tcp_packets"), f"{label}.proof.{router}.https"
        )
        http = raw_nonnegative(
            router_proof.get("relay_http_tcp_packets"), f"{label}.proof.{router}.http"
        )
        raw_equal(observed_direct, direct, f"{label}.proof.{router}.direct tuples")
        raw_equal(observed_https, https, f"{label}.proof.{router}.https tuples")
        raw_equal(observed_http, http, f"{label}.proof.{router}.http tuples")
        aggregated["direct_cross_nat_packets"] += direct
        aggregated["direct_probe_packets"] += direct
        aggregated["controlled_relay_https_packets"] += https
        aggregated["controlled_relay_http_packets"] += http
    if receipt_cell["name"] == "restrictive-relay":
        aggregated["direct_cross_nat_packets"] = 0
        aggregated["direct_probe_packets"] = 0
    raw_equal(
        aggregated,
        receipt_cell["pcap"]["tuple_proof"],
        f"{label} aggregate tuple proof",
    )


def validate_raw_nft(
    snapshots: dict[tuple[str, str], Any],
    finalization: dict[str, Any],
    receipt_cell: dict[str, Any],
    label: str,
) -> None:
    receipt_counters = {
        (counter["router"], counter["name"]): counter
        for counter in receipt_cell["nft"]["counters"]
    }
    final_nft = raw_exact_object(
        finalization.get("nft"), {"nat-a", "nat-b"}, f"{label}.finalization"
    )
    for router in ("nat-a", "nat-b"):
        router_final = raw_exact_object(
            final_nft.get(router),
            {"before", "after", "delta"},
            f"{label}.{router}",
        )
        expected_names = {
            name for observed_router, name in receipt_counters if observed_router == router
        }
        ruleset_hashes: list[str] = []
        for phase in ("before", "after"):
            snapshot = raw_exact_object(
                snapshots[(router, phase)],
                {"schema", "profile", "role", "phase", "counters", "ruleset_sha256"},
                f"{label}.{router}.{phase}",
            )
            raw_equal(snapshot.get("schema"), RAW_CONTROLLER_SCHEMA, f"{label}.{router}.{phase}.schema")
            raw_equal(snapshot.get("profile"), receipt_cell["name"], f"{label}.{router}.{phase}.profile")
            raw_equal(snapshot.get("role"), router, f"{label}.{router}.{phase}.role")
            raw_equal(snapshot.get("phase"), phase, f"{label}.{router}.{phase}.phase")
            raw_equal(snapshot.get("counters"), router_final.get(phase), f"{label}.{router}.{phase}.counters")
            ruleset_hashes.append(
                hex_32(
                    snapshot.get("ruleset_sha256"),
                    f"{label}.{router}.{phase}.ruleset_sha256",
                )
            )
        before = raw_object(router_final.get("before"), f"{label}.{router}.before")
        after = raw_object(router_final.get("after"), f"{label}.{router}.after")
        delta = raw_object(router_final.get("delta"), f"{label}.{router}.delta")
        if set(before) != expected_names or set(after) != expected_names or set(delta) != expected_names:
            fail(f"{label}.{router} does not contain the exact named nft counter set")
        if ruleset_hashes[0] == ruleset_hashes[1] and any(
            raw_object(delta[name], f"{label}.{router}.delta.{name}").get("packets")
            for name in expected_names
        ):
            fail(f"{label}.{router} before/after ruleset hashes do not bind changed counters")
        for name in before:
            counter = receipt_counters.get((router, name))
            if counter is None:
                fail(f"{label}.{router} contains an unexpected nft counter")
            for source, prefix in ((before[name], "before"), (after[name], "after"), (delta[name], "delta")):
                values = raw_exact_object(
                    source,
                    {"packets", "bytes"},
                    f"{label}.{router}.{prefix}.{name}",
                )
                raw_equal(values.get("packets"), counter[f"{prefix}_packets"], f"{label}.{router}.{name}.{prefix}_packets")
                raw_equal(values.get("bytes"), counter[f"{prefix}_bytes"], f"{label}.{router}.{name}.{prefix}_bytes")
            if (
                raw_object(before[name], f"{label}.{router}.before.{name}").get("packets")
                != 0
                or raw_object(before[name], f"{label}.{router}.before.{name}").get("bytes")
                != 0
            ):
                fail(f"{label}.{router}.{name} fresh counter baseline is nonzero")


def validate_raw_nft_pcap_binding(
    summary: Any,
    finalization: dict[str, Any],
    receipt_cell: dict[str, Any],
    label: str,
    *,
    cone_initiator_router: str | None = None,
) -> None:
    routers = raw_object(raw_object(summary, label).get("routers"), f"{label}.routers")
    final_nft = raw_object(finalization.get("nft"), f"{label}.nft")
    profile = receipt_cell["name"]
    if profile == "cone-direct" and cone_initiator_router not in {"nat-a", "nat-b"}:
        fail(f"{label} lacks the cone CONTACT-derived initiator router")
    for router in ("nat-a", "nat-b"):
        own_external = "10.250.0.11" if router == "nat-a" else "10.250.0.12"
        tuples = raw_array(
            raw_object(routers.get(router), f"{label}.{router}").get("tuples"),
            f"{label}.{router}.tuples",
        )
        outbound = sum(
            raw_nonnegative(
                raw_object(record, f"{label}.{router}.tuple").get("packets"),
                f"{label}.{router}.tuple.packets",
            )
            for record in tuples
            if raw_object(record, f"{label}.{router}.tuple").get("source")
            == own_external
        )
        inbound = sum(
            raw_nonnegative(
                raw_object(record, f"{label}.{router}.tuple").get("packets"),
                f"{label}.{router}.tuple.packets",
            )
            for record in tuples
            if raw_object(record, f"{label}.{router}.tuple").get("destination")
            == own_external
        )
        delta = raw_object(
            raw_object(final_nft.get(router), f"{label}.nft.{router}").get("delta"),
            f"{label}.nft.{router}.delta",
        )
        expected = (
            {
                "aster_cone_forward_out": outbound,
                "aster_cone_forward_in": inbound,
            }
            if profile == "cone-direct"
            else {
                "aster_restrict_relay_https": outbound,
                "aster_restrict_established": inbound,
            }
        )
        for counter_name, packet_count in expected.items():
            counter = raw_object(
                delta.get(counter_name),
                f"{label}.nft.{router}.delta.{counter_name}",
            )
            raw_equal(
                raw_nonnegative(
                    counter.get("packets"),
                    f"{label}.nft.{router}.delta.{counter_name}.packets",
                ),
                packet_count,
                f"{label}.{router}.{counter_name} packet/pcap binding",
            )
        if profile == "cone-direct":
            active_counter = (
                "aster_cone_snat"
                if router == cone_initiator_router
                else "aster_cone_dnat"
            )
            inactive_counter = (
                "aster_cone_dnat"
                if router == cone_initiator_router
                else "aster_cone_snat"
            )
            active_direction_packets = (
                outbound if active_counter == "aster_cone_snat" else inbound
            )
            active = raw_exact_object(
                delta.get(active_counter),
                {"packets", "bytes"},
                f"{label}.nft.{router}.delta.{active_counter}",
            )
            active_packets = raw_nonnegative(
                active.get("packets"),
                f"{label}.nft.{router}.delta.{active_counter}.packets",
            )
            active_bytes = raw_nonnegative(
                active.get("bytes"),
                f"{label}.nft.{router}.delta.{active_counter}.bytes",
            )
            if not 1 <= active_packets <= active_direction_packets or active_bytes <= 0:
                fail(
                    f"{label}.{router}.{active_counter} is not bounded by its "
                    "CONTACT-matched WAN direction"
                )
            inactive = raw_exact_object(
                delta.get(inactive_counter),
                {"packets", "bytes"},
                f"{label}.nft.{router}.delta.{inactive_counter}",
            )
            if (
                raw_nonnegative(
                    inactive.get("packets"),
                    f"{label}.nft.{router}.delta.{inactive_counter}.packets",
                )
                != 0
                or raw_nonnegative(
                    inactive.get("bytes"),
                    f"{label}.nft.{router}.delta.{inactive_counter}.bytes",
                )
                != 0
            ):
                fail(
                    f"{label}.{router}.{inactive_counter} is active despite the "
                    "opposite CONTACT direction"
                )


def expected_raw_nft_program(
    profile: str, router: str, lan_if: str, wan_if: str
) -> str:
    if router == "nat-a":
        lan_subnet = "10.250.1.0/24"
        node_ip = "10.250.1.10"
        external_ip = "10.250.0.11"
        peer_external = "10.250.0.12"
    else:
        lan_subnet = "10.250.2.0/24"
        node_ip = "10.250.2.10"
        external_ip = "10.250.0.12"
        peer_external = "10.250.0.11"
    if profile == "cone-direct":
        return f'''flush ruleset
table inet aster_selected_filter {{
    counter aster_cone_forward_out {{}}
    counter aster_cone_forward_in {{}}
    chain forward {{
        type filter hook forward priority filter; policy drop;
        iifname "{lan_if}" oifname "{wan_if}" ip saddr {node_ip} ip daddr {peer_external} udp sport 44000 udp dport 44000 counter name aster_cone_forward_out accept
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
        iifname "{lan_if}" oifname "{wan_if}" ip saddr {node_ip} ip daddr {peer_external} udp dport 44000 counter name aster_restrict_direct_drop drop
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


def validate_raw_nft_programs(
    root_descriptor: int,
    profile: str,
    runtime: dict[str, Any],
    label: str,
    entries: dict[tuple[str, str], dict[str, Any]],
) -> None:
    routers = raw_array(runtime.get("routers"), f"{label}.runtime.routers", length=2)
    for index, router in enumerate(("nat-a", "nat-b")):
        runtime_router = raw_object(routers[index], f"{label}.runtime.routers[{index}]")
        lan_if = exact_string(
            runtime_router.get("lan_interface"),
            f"{label}.runtime.routers[{index}].lan_interface",
            pattern=SAFE_NAME,
            maximum=32,
        )
        wan_if = exact_string(
            runtime_router.get("wan_interface"),
            f"{label}.runtime.routers[{index}].wan_interface",
            pattern=SAFE_NAME,
            maximum=32,
        )
        if lan_if == wan_if:
            fail(f"{label}.runtime.routers[{index}] reuses one interface")
        observed = load_raw_text(
            root_descriptor,
            f"cells/{profile}/{router}.nft",
            f"{label}.{router}.program",
            entries=entries,
            maximum=64 * 1024,
        )
        raw_equal(
            observed,
            expected_raw_nft_program(profile, router, lan_if, wan_if),
            f"{label}.{router}.program",
        )


def validate_raw_relay_config(
    value: Any,
    receipt_cell: dict[str, Any],
    label: str,
    entries: dict[tuple[str, str], dict[str, Any]],
) -> None:
    relay = receipt_cell["relay"]
    if receipt_cell["name"] == "cone-direct":
        disabled = raw_exact_object(
            value,
            {
                "schema",
                "profile",
                "relay_container",
                "relay_configuration",
                "legacy_ports_4476_4477",
                "hosted_discovery",
                "public_relay_fallback",
                "status",
            },
            label,
        )
        for field, expected in (
            ("schema", RAW_CONTROLLER_SCHEMA),
            ("profile", "cone-direct"),
            ("relay_container", False),
            ("relay_configuration", False),
            ("legacy_ports_4476_4477", False),
            ("hosted_discovery", False),
            ("public_relay_fallback", False),
            ("status", "pass"),
        ):
            raw_equal(disabled.get(field), expected, f"{label}.{field}")
        return
    config = raw_exact_object(
        value,
        {
            "schema",
            "origin",
            "address",
            "https_port",
            "http_port",
            "tls_mode",
            "server_trust_claim",
            "client_trust_mode",
            "root_fingerprint_sha256",
            "certificate_sha256",
            "allowlist",
            "max_admitted_connections",
            "pre_auth_connection_cap",
            "client_rx_bytes_per_second",
            "client_rx_max_burst_bytes",
            "key_cache_capacity",
            "public_relay_fallback",
            "hosted_discovery",
            "port_mapper",
        },
        label,
    )
    carriers = sorted(endpoint["carrier_id"] for endpoint in receipt_cell["endpoints"])
    for field, expected in (
        ("schema", RAW_CONTROLLER_SCHEMA),
        ("origin", "https://relay.aster.test:8443/"),
        ("address", "10.250.0.20"),
        ("https_port", 8443),
        ("http_port", 8080),
        ("tls_mode", relay["tls_mode"]),
        ("server_trust_claim", relay["server_trust_claim"]),
        ("client_trust_mode", relay["client_trust_mode"]),
        ("root_fingerprint_sha256", relay["root_fingerprint_sha256"]),
        ("allowlist", carriers),
        ("max_admitted_connections", relay["max_admitted_connections"]),
        ("pre_auth_connection_cap", relay["pre_auth_connection_cap"]),
        ("client_rx_bytes_per_second", relay["client_rx_bytes_per_second"]),
        ("client_rx_max_burst_bytes", relay["client_rx_max_burst_bytes"]),
        ("key_cache_capacity", relay["key_cache_capacity"]),
        ("public_relay_fallback", False),
        ("hosted_discovery", False),
        ("port_mapper", False),
    ):
        raw_equal(config.get(field), expected, f"{label}.{field}")
    raw_equal(
        config.get("root_fingerprint_sha256"),
        entries[("restrictive-relay", "relay-ca-der")]["sha256"],
        f"{label}.root_fingerprint_sha256 manifest binding",
    )
    raw_equal(
        config.get("certificate_sha256"),
        entries[("restrictive-relay", "relay-cert-der")]["sha256"],
        f"{label}.certificate_sha256 manifest binding",
    )


def validate_raw_runtime(
    value: Any,
    *,
    profile: str,
    run_id: str,
    suite_source: dict[str, Any],
    inventory: list[Any],
    image_id: str,
    mission_authority: str,
    manifest_nodes: dict[str, dict[str, str]],
    privileges: dict[str, dict[str, Any]],
    networks: dict[str, dict[str, Any]],
    relay_config: Any,
    relay_privilege: Any,
    label: str,
) -> None:
    runtime = raw_exact_object(
        value,
        {
            "schema",
            "run_id",
            "profile",
            "source",
            "image",
            "image_id",
            "binary_inventory",
            "scope",
            "topic",
            "mission_authority",
            "nodes",
            "routers",
            "route_initializers_removed",
            "networks",
            "node_privileges",
            "relay",
            "relay_privilege",
            "legacy_ports_4476_4477",
        },
        label,
    )
    for field, expected in (
        ("schema", RAW_CONTROLLER_SCHEMA),
        ("run_id", run_id),
        ("profile", profile),
        ("source", suite_source),
        ("image", SELECTED_NAT_IMAGE),
        ("image_id", image_id),
        ("binary_inventory", inventory),
        ("scope", f"lab/selected-iroh-nat/{profile}"),
        ("topic", "lab.selected-iroh-nat"),
        ("mission_authority", mission_authority),
        ("nodes", manifest_nodes),
        ("route_initializers_removed", True),
        ("networks", networks),
        ("node_privileges", privileges),
        ("relay", relay_config),
        ("relay_privilege", relay_privilege),
        ("legacy_ports_4476_4477", False),
    ):
        raw_equal(runtime.get(field), expected, f"{label}.{field}")
    routers = raw_array(runtime.get("routers"), f"{label}.routers", length=2)
    expected_routers = (
        {
            "role": "nat-a",
            "container": "aster-lab-nat-a",
            "lan_address": "10.250.1.1",
            "wan_address": "10.250.0.11",
            "node_ip": "10.250.1.10",
            "peer_external_ip": "10.250.0.12",
            "capture_relative_path": "outputs/nat-a/nat-a-wan.pcap",
        },
        {
            "role": "nat-b",
            "container": "aster-lab-nat-b",
            "lan_address": "10.250.2.1",
            "wan_address": "10.250.0.12",
            "node_ip": "10.250.2.10",
            "peer_external_ip": "10.250.0.11",
            "capture_relative_path": "outputs/nat-b/nat-b-wan.pcap",
        },
    )
    for index, expected in enumerate(expected_routers):
        router = raw_exact_object(
            routers[index],
            {
                *expected.keys(),
                "lan_interface",
                "wan_interface",
            },
            f"{label}.routers[{index}]",
        )
        for field, expected_value in expected.items():
            raw_equal(
                router.get(field), expected_value, f"{label}.routers[{index}].{field}"
            )
        for interface_field in ("lan_interface", "wan_interface"):
            exact_string(
                router.get(interface_field),
                f"{label}.routers[{index}].{interface_field}",
                pattern=SAFE_NAME,
                maximum=32,
            )


def validate_raw_cleanup_summary(
    value: Any,
    *,
    profile: str,
    run_id: str,
    receipt_cell: dict[str, Any],
    label: str,
) -> None:
    cleanup = raw_exact_object(
        value,
        {
            "schema",
            "run_id",
            "resources",
            "all_owned_resources_removed",
            "status",
        },
        label,
    )
    for field, expected in (
        ("schema", RAW_CONTROLLER_SCHEMA),
        ("run_id", run_id),
        ("resources", 10 if profile == "cone-direct" else 11),
        ("all_owned_resources_removed", True),
        ("status", "pass"),
    ):
        raw_equal(cleanup.get(field), expected, f"{label}.{field}")
    for field in ("containers_remaining", "networks_remaining", "namespaces_remaining"):
        raw_equal(
            receipt_cell["cleanup"][field], 0, f"{label}.receipt_cleanup.{field}"
        )


def validate_raw_cleanup(
    value: Any, receipt_cell: dict[str, Any], label: str
) -> None:
    cleanup = raw_exact_object(
        value,
        {
            "schema",
            "raw_canary_control_file",
            "relay_private_key_file",
            "canary_control_file_disposition",
            "canary_control_file_previous_bytes",
            "canary_control_file_absent_after_cleanup",
            "relay_private_key_file_disposition",
            "relay_private_key_file_absent_after_cleanup",
            "assurance",
            "encrypted_event_state_retained",
            "mission_credentials_retained_external_restricted",
            "global_secret_destruction",
            "physical_sanitization",
            "status",
        },
        label,
    )
    receipt = receipt_cell["cleanup"]
    raw_equal(cleanup.get("schema"), RAW_CONTROLLER_SCHEMA, f"{label}.schema")
    raw_equal(cleanup.get("status"), "pass", f"{label}.status")
    for field in (
        "canary_control_file_disposition",
        "canary_control_file_previous_bytes",
        "canary_control_file_absent_after_cleanup",
        "relay_private_key_file_disposition",
        "relay_private_key_file_absent_after_cleanup",
        "assurance",
        "physical_sanitization",
    ):
        raw_equal(cleanup.get(field), receipt[field], f"{label}.{field}")
    raw_equal(
        cleanup.get("encrypted_event_state_retained"),
        True,
        f"{label}.encrypted_event_state_retained",
    )
    raw_equal(
        cleanup.get("mission_credentials_retained_external_restricted"),
        True,
        f"{label}.mission_credentials_retained_external_restricted",
    )
    raw_equal(
        cleanup.get("global_secret_destruction"),
        False,
        f"{label}.global_secret_destruction",
    )


def validate_raw_destroy_marker(
    fields: dict[str, str],
    *,
    target: str,
    expected_bytes: int | None,
    label: str,
) -> None:
    expected_keys = {
        "status",
        "version",
        "artifact_destroyed",
        "global_secret_destruction",
        "target",
        "previous_bytes",
        "previous_mode",
        "owner_uid",
        "overwrite",
        "sync",
        "unlinked",
        "assurance",
        "physical_sanitization",
    }
    if set(fields) != expected_keys:
        fail(f"{label} has missing or unexpected destruction fields")
    for field, expected in (
        ("status", "pass"),
        ("version", "1"),
        ("artifact_destroyed", "true"),
        ("global_secret_destruction", "false"),
        ("target", target),
        ("previous_mode", "0600"),
        ("owner_uid", str(os.getuid())),
        ("overwrite", "zero"),
        ("sync", "file+directory"),
        ("unlinked", "true"),
        ("assurance", "bounded-software"),
        ("physical_sanitization", "not-claimed"),
    ):
        raw_equal(fields.get(field), expected, f"{label}.{field}")
    previous = raw_receipt_nonnegative(fields, "previous_bytes", label)
    if (
        previous <= 0
        or (expected_bytes is not None and previous != expected_bytes)
        or (expected_bytes is None and previous > 16_384)
    ):
        fail(f"{label}.previous_bytes differs")


def validate_raw_cleanup_authorities(
    root_descriptor: int,
    *,
    profile: str,
    cleanup: dict[str, Any],
    entries: dict[tuple[str, str], dict[str, Any]],
    label: str,
) -> None:
    canary_text = load_raw_text(
        root_descriptor,
        f"cells/{profile}/canary-destroy.log",
        f"{label}.canary_destroy_log",
        entries=entries,
        maximum=64 * 1024,
    )
    validate_raw_receipt_sequence(
        canary_text,
        ["SELECTED_NAT_CANARY_DESTROY"],
        f"{label}.canary_destroy_log",
    )
    canary = exact_raw_receipt(
        canary_text, "SELECTED_NAT_CANARY_DESTROY", f"{label}.canary_destroy_log"
    )
    validate_raw_destroy_marker(
        canary,
        target="private/canary.bin",
        expected_bytes=32,
        label=f"{label}.canary_destroy_log",
    )
    raw_equal(
        cleanup.get("raw_canary_control_file"),
        canary,
        f"{label}.raw_canary_control_file",
    )
    if profile == "cone-direct":
        raw_equal(
            cleanup.get("relay_private_key_file"),
            None,
            f"{label}.relay_private_key_file",
        )
        return
    material_text = load_raw_text(
        root_descriptor,
        f"cells/{profile}/relay-material.log",
        f"{label}.relay_material_log",
        entries=entries,
        maximum=64 * 1024,
    )
    validate_raw_receipt_sequence(
        material_text,
        ["SELECTED_NAT_RELAY_MATERIAL"],
        f"{label}.relay_material_log",
    )
    material = exact_raw_receipt(
        material_text,
        "SELECTED_NAT_RELAY_MATERIAL",
        f"{label}.relay_material_log",
    )
    expected_material = {
        "status": "pass",
        "version": "1",
        "dns_name": "relay.aster.test",
        "ip_address": "10.250.0.20",
        "san": "dns+ip",
        "ca_sha256": entries[(profile, "relay-ca-der")]["sha256"],
        "certificate_sha256": entries[(profile, "relay-cert-der")]["sha256"],
        "certificate_format": "der",
        "private_key_format": "pkcs8-der",
        "private_key": "redacted",
        "key_mode": "0600",
    }
    raw_equal(material, expected_material, f"{label}.relay_material_log fields")
    destroy_text = load_raw_text(
        root_descriptor,
        f"cells/{profile}/relay-material-destroy.log",
        f"{label}.relay_destroy_log",
        entries=entries,
        maximum=64 * 1024,
    )
    validate_raw_receipt_sequence(
        destroy_text,
        ["SELECTED_NAT_RELAY_MATERIAL_DESTROY"],
        f"{label}.relay_destroy_log",
    )
    destroy = exact_raw_receipt(
        destroy_text,
        "SELECTED_NAT_RELAY_MATERIAL_DESTROY",
        f"{label}.relay_destroy_log",
    )
    validate_raw_destroy_marker(
        destroy,
        target="private/server.key.pkcs8.der",
        expected_bytes=None,
        label=f"{label}.relay_destroy_log",
    )
    raw_equal(
        cleanup.get("relay_private_key_file"),
        destroy,
        f"{label}.relay_private_key_file",
    )


def raw_cone_initiator_router(
    contacts_by_node: dict[str, list[dict[str, str]]],
    carrier_ids: dict[str, str],
    label: str,
) -> str:
    if set(contacts_by_node) != {"node-a", "node-b"}:
        fail(f"{label} lacks the exact cone node CONTACT domains")
    if not contacts_by_node["node-a"] or not contacts_by_node["node-b"]:
        fail(f"{label} cone CONTACT direction evidence is empty")
    if set(carrier_ids) != {"node-a", "node-b"}:
        fail(f"{label} lacks the exact cone carrier identity domains")
    validated_carriers = {
        role: hex_32(carrier_ids[role], f"{label}.{role}.carrier_id")
        for role in ("node-a", "node-b")
    }
    if validated_carriers["node-a"] == validated_carriers["node-b"]:
        fail(f"{label} cone carrier identities are not distinct")
    expected_router = (
        "nat-a"
        if validated_carriers["node-a"] < validated_carriers["node-b"]
        else "nat-b"
    )
    directions = {
        node_role: [contact.get("direction") for contact in contacts]
        for node_role, contacts in contacts_by_node.items()
    }
    if all(direction == "out" for direction in directions["node-a"]) and all(
        direction == "in" for direction in directions["node-b"]
    ):
        observed_router = "nat-a"
    elif all(direction == "in" for direction in directions["node-a"]) and all(
        direction == "out" for direction in directions["node-b"]
    ):
        observed_router = "nat-b"
    else:
        fail(f"{label} does not prove one exact all-out/all-in cone initiator pattern")
    if observed_router != expected_router:
        fail(f"{label} initiator is not the lower carrier identity")
    return observed_router


def validate_raw_node_results(
    root_descriptor: int,
    profile: str,
    finalization: dict[str, Any],
    receipt_cell: dict[str, Any],
    mission_authority: str,
    manifest_nodes: dict[str, dict[str, str]],
    entries: dict[tuple[str, str], dict[str, Any]],
) -> tuple[dict[str, int], str | None]:
    nodes = raw_exact_object(
        finalization.get("nodes"),
        {"node-a", "node-b"},
        f"cells.{profile}.finalization.nodes",
    )
    contacts = 0
    transfer_counts = {"inserted": 0, "fetched": 0}
    contacts_by_node: dict[str, list[dict[str, str]]] = {}
    for index, node_role in enumerate(("node-a", "node-b")):
        label = f"cells.{profile}.{node_role}-result"
        result = load_raw_json(
            root_descriptor,
            f"cells/{profile}/{node_role}-result.json",
            label,
            entries=entries,
        )
        raw_equal(result, nodes.get(node_role), label)
        result_object = raw_exact_object(
            result,
            {
                "ready",
                "stop",
                "contacts",
                "path",
                "saturated",
                "transition_count",
                "final_noop",
            },
            label,
        )
        witness = receipt_cell["path"]["witnesses"][index]
        raw_equal(result_object.get("path"), witness["selected"], f"{label}.path")
        raw_equal(result_object.get("saturated"), False, f"{label}.saturated")
        raw_equal(
            raw_nonnegative(result_object.get("transition_count"), f"{label}.transition_count"),
            witness["transition_count"],
            f"{label}.transition_count",
        )
        final_noop = raw_exact_object(
            result_object.get("final_noop"),
            RECONCILIATION_KEYS - {"status", "contacts"},
            f"{label}.final_noop",
        )
        for field in RECONCILIATION_KEYS - {"status", "contacts"}:
            raw_equal(
                raw_nonnegative(final_noop.get(field), f"{label}.final_noop.{field}"),
                receipt_cell["reconciliation"][field],
                f"{label}.final_noop.{field}",
            )
        stop = raw_object(result_object.get("stop"), f"{label}.stop")
        contacts += raw_nonnegative(stop.get("contacts"), f"{label}.stop.contacts")
        short_name = "a" if node_role == "node-a" else "b"
        peer_name = "b" if short_name == "a" else "a"
        transcript_contacts = validate_raw_node_transcript(
            load_raw_text(
                root_descriptor,
                f"cells/{profile}/{node_role}.log",
                f"{label}.transcript",
                entries=entries,
            ),
            profile=profile,
            node_role=node_role,
            mission_authority=mission_authority,
            identity=manifest_nodes[short_name],
            peer=manifest_nodes[peer_name],
            result=result_object,
            receipt_cell=receipt_cell,
            label=f"{label}.transcript",
        )
        contacts_by_node[node_role] = transcript_contacts
        for contact in transcript_contacts:
            for field in transfer_counts:
                transfer_counts[field] += raw_receipt_nonnegative(
                    contact, field, f"{label}.transcript.CONTACT.{field}"
                )
    raw_equal(
        contacts,
        receipt_cell["reconciliation"]["contacts"],
        f"cells.{profile}.contacts",
    )
    raw_equal(
        transfer_counts,
        {"inserted": 1, "fetched": 1},
        f"cells.{profile}.CONTACT Event transfers",
    )
    initiator_router = (
        raw_cone_initiator_router(
            contacts_by_node,
            {
                "node-a": manifest_nodes["a"]["carrier_id"],
                "node-b": manifest_nodes["b"]["carrier_id"],
            },
            f"cells.{profile}.CONTACT",
        )
        if profile == "cone-direct"
        else None
    )
    return transfer_counts, initiator_router


def validate_raw_cell_semantics(
    root_descriptor: int,
    suite_evidence_dir: str,
    suite_workspace: str,
    profile: str,
    cell_summary_value: Any,
    document: dict[str, Any],
    suite_source: dict[str, Any],
    entries: dict[tuple[str, str], dict[str, Any]],
) -> tuple[
    list[Any], dict[str, Any], dict[str, dict[str, Any]], dict[str, Any], str
]:
    label = f"cells.{profile}"
    evidence_dir = f"{suite_evidence_dir}/cells/{profile}"
    cell_summary = raw_exact_object(
        cell_summary_value,
        {
            "profile",
            "status",
            "run_id",
            "path",
            "source_commit",
            "source_tree",
            "image_id",
            "manifest_sha256",
            "finalization_sha256",
            "identities",
        },
        f"{label}.suite_summary",
    )
    receipt_cell = next(cell for cell in document["cells"] if cell["name"] == profile)
    for field, expected in (
        ("profile", profile),
        ("status", "pass"),
        ("path", f"cells/{profile}"),
        ("source_commit", document["source"]["commit"]),
        ("source_tree", document["source"]["tree"]),
        ("image_id", document["build"]["container"]["image_id"]),
    ):
        raw_equal(cell_summary.get(field), expected, f"{label}.suite_summary.{field}")
    run_id = exact_string(
        cell_summary.get("run_id"), f"{label}.suite_summary.run_id", pattern=RUN_ID
    )
    raw_equal(
        cell_summary.get("manifest_sha256"),
        entries[(profile, "prepare-manifest")]["sha256"],
        f"{label}.suite_summary.manifest_sha256",
    )
    raw_equal(
        cell_summary.get("finalization_sha256"),
        entries[(profile, "nat-finalization")]["sha256"],
        f"{label}.suite_summary.finalization_sha256",
    )
    identities = raw_object(
        cell_summary.get("identities"), f"{label}.suite_summary.identities"
    )
    if set(identities) != {"a", "b"}:
        fail(f"{label}.suite_summary identities differ")
    for index, node in enumerate(("a", "b")):
        identity = raw_exact_object(
            identities[node],
            {"carrier_id", "mission_id"},
            f"{label}.identities.{node}",
        )
        for field in ("carrier_id", "mission_id"):
            raw_equal(
                identity.get(field),
                receipt_cell["endpoints"][index][field],
                f"{label}.identities.{node}.{field}",
            )

    controller = load_raw_json(
        root_descriptor,
        f"cells/{profile}/controller.json",
        f"{label}.controller",
        entries=entries,
    )
    validate_raw_controller(
        controller,
        label=f"{label}.controller",
        run_id=run_id,
        run_label=profile,
        evidence_dir=evidence_dir,
        require_empty_resources=False,
        expected_workspace=suite_workspace,
    )
    validate_raw_planned_resources(
        raw_object(controller, f"{label}.controller").get("resources"),
        profile,
        f"{label}.controller.resources",
    )
    validate_raw_scenario_request(
        load_raw_json(
            root_descriptor,
            f"cells/{profile}/scenario-request.json",
            f"{label}.scenario",
            entries=entries,
        ),
        profile,
        receipt_cell,
        f"{label}.scenario",
    )
    validate_raw_events(
        load_raw_text(
            root_descriptor,
            f"cells/{profile}/events.jsonl",
            f"{label}.events",
            entries=entries,
            maximum=64 * 1024,
        ),
        profile,
        run_id,
        f"{label}.events",
    )
    source = load_raw_json(
        root_descriptor,
        f"cells/{profile}/source-identity.json",
        f"{label}.source",
        entries=entries,
    )
    raw_equal(source, suite_source, f"{label}.source")
    validate_raw_source_identity(source, document, f"{label}.source")
    image = validate_raw_image_identity(
        load_raw_json(
            root_descriptor,
            f"cells/{profile}/image-identity.json",
            f"{label}.image",
            entries=entries,
        ),
        document,
        f"{label}.image",
    )
    inventory = validate_raw_binary_inventory(
        load_raw_json(
            root_descriptor,
            f"cells/{profile}/binary-inventory.json",
            f"{label}.binary_inventory",
            entries=entries,
        ),
        document,
        f"{label}.binary_inventory",
    )
    manifest_nodes, mission_authority = validate_raw_prepare_evidence(
        root_descriptor, profile, receipt_cell, entries
    )
    privileges: dict[str, dict[str, Any]] = {}
    node_container_ids: dict[str, str] = {}
    for node_role in ("node-a", "node-b"):
        privilege = raw_object(
            load_raw_json(
                root_descriptor,
                f"cells/{profile}/{node_role}-runtime-privilege.json",
                f"{label}.{node_role}.privilege",
                entries=entries,
            ),
            f"{label}.{node_role}.privilege",
        )
        uid, gid = validate_raw_privilege(
            privilege, f"{label}.{node_role}.privilege"
        )
        privileges[node_role] = privilege
        node_container_ids[node_role] = validate_raw_node_config(
            load_raw_json(
                root_descriptor,
                f"cells/{profile}/aster-lab-{node_role}-configuration.json",
                f"{label}.{node_role}.config",
                entries=entries,
            ),
            profile=profile,
            node_role=node_role,
            image_id=document["build"]["container"]["image_id"],
            uid=uid,
            gid=gid,
            evidence_dir=evidence_dir,
            run_id=run_id,
            input_manifest_sha256=document["build"]["container"][
                "input_manifest_sha256"
            ],
            image_environment=image["env"],
            label=f"{label}.{node_role}.config",
        )
    route_sequences = validate_raw_route_initializers(
        load_raw_json(
            root_descriptor,
            f"cells/{profile}/route-init-removal.json",
            f"{label}.route_initializers",
            entries=entries,
        ),
        profile,
        f"{label}.route_initializers",
    )
    for ephemeral_role in (
        "provision-prepare",
        "provision-verify",
        "route-a",
        "route-b",
    ):
        filename = {
            "provision-prepare": "aster-lab-provision-configuration.json",
            "provision-verify": "aster-lab-provision-verifier-configuration.json",
            "route-a": "aster-lab-route-a-configuration.json",
            "route-b": "aster-lab-route-b-configuration.json",
        }[ephemeral_role]
        validate_raw_ephemeral_config(
            load_raw_json(
                root_descriptor,
                f"cells/{profile}/{filename}",
                f"{label}.{ephemeral_role}.config",
                entries=entries,
            ),
            role=ephemeral_role,
            image_id=document["build"]["container"]["image_id"],
            node_container_id=(
                node_container_ids["node-a"]
                if ephemeral_role == "route-a"
                else node_container_ids["node-b"]
                if ephemeral_role == "route-b"
                else None
            ),
            evidence_dir=evidence_dir,
            run_id=run_id,
            input_manifest_sha256=document["build"]["container"][
                "input_manifest_sha256"
            ],
            image_environment=image["env"],
            label=f"{label}.{ephemeral_role}.config",
        )
    for router in ("nat-a", "nat-b"):
        validate_raw_router_config(
            load_raw_json(
                root_descriptor,
                f"cells/{profile}/aster-lab-{router}-configuration.json",
                f"{label}.{router}.config",
                entries=entries,
            ),
            router=router,
            image_id=document["build"]["container"]["image_id"],
            evidence_dir=evidence_dir,
            run_id=run_id,
            input_manifest_sha256=document["build"]["container"][
                "input_manifest_sha256"
            ],
            image_environment=image["env"],
            label=f"{label}.{router}.config",
        )
    networks = {
        role: validate_raw_network_config(
            load_raw_json(
                root_descriptor,
                f"cells/{profile}/aster-lab-{role}-network.json",
                f"{label}.networks.{role}",
                entries=entries,
            ),
            profile=profile,
            role=role,
            run_id=run_id,
            manifest_sha256=entries[(profile, f"{role}-network-config")]["sha256"],
            label=f"{label}.networks.{role}",
        )
        for role in ("lan-a", "wan", "lan-b")
    }
    relay_relative = "relay-disabled.json" if profile == "cone-direct" else "relay-config.json"
    relay_evidence = load_raw_json(
        root_descriptor,
        f"cells/{profile}/{relay_relative}",
        f"{label}.relay",
        entries=entries,
    )
    validate_raw_relay_config(
        relay_evidence, receipt_cell, f"{label}.relay", entries
    )
    if profile == "restrictive-relay":
        validate_raw_relay_certificates(
            root_descriptor,
            entries,
            raw_object(relay_evidence, f"{label}.relay"),
        )
    relay_privilege = None
    if profile == "restrictive-relay":
        relay_privilege = raw_object(
            load_raw_json(
                root_descriptor,
                f"cells/{profile}/infra-runtime-privilege.json",
                f"{label}.relay_runtime_privilege",
                entries=entries,
            ),
            f"{label}.relay_runtime_privilege",
        )
        relay_uid, relay_gid = validate_raw_privilege(
            relay_privilege, f"{label}.relay_runtime_privilege"
        )
        validate_raw_relay_runtime_config(
            load_raw_json(
                root_descriptor,
                f"cells/{profile}/aster-lab-infra-configuration.json",
                f"{label}.relay_runtime_config",
                entries=entries,
            ),
            image_id=document["build"]["container"]["image_id"],
            uid=relay_uid,
            gid=relay_gid,
            evidence_dir=evidence_dir,
            run_id=run_id,
            input_manifest_sha256=document["build"]["container"][
                "input_manifest_sha256"
            ],
            image_environment=image["env"],
            carrier_ids=[
                endpoint["carrier_id"] for endpoint in receipt_cell["endpoints"]
            ],
            label=f"{label}.relay_runtime_config",
        )
    runtime = raw_object(
        load_raw_json(
            root_descriptor,
            f"cells/{profile}/selected-nat-runtime.json",
            f"{label}.runtime",
            entries=entries,
        ),
        f"{label}.runtime",
    )
    validate_raw_runtime(
        runtime,
        profile=profile,
        run_id=run_id,
        suite_source=suite_source,
        inventory=inventory,
        image_id=document["build"]["container"]["image_id"],
        mission_authority=mission_authority,
        manifest_nodes=manifest_nodes,
        privileges=privileges,
        networks=networks,
        relay_config=None if profile == "cone-direct" else relay_evidence,
        relay_privilege=relay_privilege,
        label=f"{label}.runtime",
    )
    validate_raw_nft_programs(
        root_descriptor, profile, runtime, f"{label}.nft", entries
    )
    finalization = raw_object(
        load_raw_json(
            root_descriptor,
            f"cells/{profile}/selected-nat-finalization.json",
            f"{label}.finalization",
            entries=entries,
        ),
        f"{label}.finalization",
    )
    if set(finalization) != {
        "schema",
        "run_id",
        "profile",
        "status",
        "manifest_sha256",
        "event",
        "nodes",
        "nft",
        "pcap",
        "tuple_proof",
        "relay",
        "canary_scan",
        "secret_cleanup",
        "restricted_state_containment",
        "legacy_ports_4476_4477",
        "limitations",
    }:
        fail(f"{label}.finalization has missing or unexpected fields")
    for field, expected in (
        ("schema", RAW_CONTROLLER_SCHEMA),
        ("profile", profile),
        ("run_id", run_id),
        ("status", "pass"),
        ("legacy_ports_4476_4477", False),
    ):
        raw_equal(finalization.get(field), expected, f"{label}.finalization.{field}")
    raw_equal(
        finalization.get("manifest_sha256"),
        entries[(profile, "prepare-manifest")]["sha256"],
        f"{label}.finalization.manifest_sha256",
    )
    raw_equal(
        finalization.get("limitations"),
        list(RAW_CELL_LIMITATIONS),
        f"{label}.finalization.limitations",
    )
    containment = raw_exact_object(
        finalization.get("restricted_state_containment"),
        {
            "schema",
            "mission_bundle_files",
            "state_files",
            "retained_files",
            "retained_bytes",
            "owner",
            "file_mode",
            "directory_mode",
            "sanitized_manifest",
            "encrypted_event_state_retained",
            "mission_credentials_retained",
            "status",
        },
        f"{label}.finalization.restricted_state_containment",
    )
    for field, expected in (
        ("schema", RAW_CONTROLLER_SCHEMA),
        ("mission_bundle_files", 2),
        ("owner", "current-runner"),
        ("file_mode", "0600"),
        ("directory_mode", "0700"),
        ("sanitized_manifest", "excluded-external-restricted"),
        ("encrypted_event_state_retained", True),
        ("mission_credentials_retained", True),
        ("status", "pass"),
    ):
        raw_equal(containment.get(field), expected, f"{label}.containment.{field}")
    state_files = raw_nonnegative(
        containment.get("state_files"), f"{label}.containment.state_files"
    )
    retained_files = raw_nonnegative(
        containment.get("retained_files"), f"{label}.containment.retained_files"
    )
    retained_bytes = raw_nonnegative(
        containment.get("retained_bytes"), f"{label}.containment.retained_bytes"
    )
    if state_files < 2 or state_files > 4_094:
        fail(f"{label}.containment.state_files is outside its exact bound")
    if retained_files != state_files + 2 or retained_files > 4_096:
        fail(f"{label}.containment retained/state file arithmetic differs")
    if retained_bytes < 1 or retained_bytes > 1024 * 1024 * 1024:
        fail(f"{label}.containment.retained_bytes is outside its exact bound")
    validate_raw_restricted_state(root_descriptor, profile, containment)
    transfer_counts, cone_initiator_router = validate_raw_node_results(
        root_descriptor,
        profile,
        finalization,
        receipt_cell,
        mission_authority,
        manifest_nodes,
        entries,
    )
    validate_raw_event(
        finalization, receipt_cell, transfer_counts, f"{label}.finalization"
    )
    validate_raw_event_logs(
        root_descriptor, profile, receipt_cell, finalization, entries
    )

    scan = load_raw_json(
        root_descriptor,
        f"cells/{profile}/canary-scan.json",
        f"{label}.canary_scan",
        entries=entries,
    )
    raw_equal(scan, finalization.get("canary_scan"), f"{label}.canary_scan")
    stderr_authorities = validate_raw_canary_scan(
        root_descriptor,
        scan,
        receipt_cell,
        f"{label}.canary_scan",
        entries,
        finalization,
        route_sequences,
    )
    cleanup = load_raw_json(
        root_descriptor,
        f"cells/{profile}/secret-cleanup.json",
        f"{label}.cleanup",
        entries=entries,
    )
    raw_equal(cleanup, finalization.get("secret_cleanup"), f"{label}.cleanup")
    validate_raw_cleanup(cleanup, receipt_cell, f"{label}.cleanup")
    validate_raw_cleanup_authorities(
        root_descriptor,
        profile=profile,
        cleanup=raw_object(cleanup, f"{label}.cleanup"),
        entries=entries,
        label=f"{label}.cleanup",
    )
    pcap_summary = load_raw_json(
        root_descriptor,
        f"cells/{profile}/pcap-tuple-summary.json",
        f"{label}.pcap_summary",
        entries=entries,
    )
    validate_raw_pcap_summary(
        pcap_summary,
        finalization,
        receipt_cell,
        f"{label}.pcap_summary",
        root_descriptor=root_descriptor,
        entries=entries,
    )
    nft_snapshots = {
        (router, phase): load_raw_json(
            root_descriptor,
            f"cells/{profile}/{router}-nft-{phase}.json",
            f"{label}.nft.{router}.{phase}",
            entries=entries,
        )
        for router in ("nat-a", "nat-b")
        for phase in ("before", "after")
    }
    validate_raw_nft(nft_snapshots, finalization, receipt_cell, f"{label}.nft")
    validate_raw_nft_pcap_binding(
        pcap_summary,
        finalization,
        receipt_cell,
        f"{label}.nft_pcap",
        cone_initiator_router=cone_initiator_router,
    )
    if profile == "restrictive-relay":
        validate_raw_relay_log(
            load_raw_text(
                root_descriptor,
                f"cells/{profile}/relay.log",
                f"{label}.relay_log",
                entries=entries,
            ),
            finalization,
            receipt_cell,
            f"{label}.relay_log",
        )
    validate_raw_cleanup_summary(
        load_raw_json(
            root_descriptor,
            f"cells/{profile}/cleanup-summary.json",
            f"{label}.cleanup_summary",
            entries=entries,
        ),
        profile=profile,
        run_id=run_id,
        receipt_cell=receipt_cell,
        label=f"{label}.cleanup_summary",
    )
    return inventory, image, stderr_authorities, containment, mission_authority


def validate_raw_semantics(
    root_descriptor: int,
    root: Path,
    document: dict[str, Any],
    *,
    source_authority: dict[str, str] | None = None,
) -> tuple[dict[str, dict[str, Any]], dict[str, dict[str, Any]]]:
    root_text = os.path.abspath(os.fspath(root))
    if os.path.realpath(root_text) != root_text:
        fail("raw root path contains a symbolic or noncanonical component")
    entries = manifest_entries_by_role(document)
    summary = raw_exact_object(
        load_raw_json(
            root_descriptor,
            "selected-nat-suite.json",
            "selected NAT suite summary",
            entries=entries,
        ),
        {
            "schema",
            "status",
            "profile",
            "cells",
            "source_commit",
            "source_tree",
            "source_identity",
            "build_identity",
            "image_id",
            "build_input_manifest_sha256",
            "build_command_sha256",
            "physical_hosts",
            "namespace_isolation",
            "all_resources_removed",
            "retained_claim_eligible",
        },
        "selected NAT suite summary",
    )
    for field, expected in (
        ("schema", RAW_CONTROLLER_SCHEMA),
        ("status", "pass"),
        ("profile", "all"),
        ("physical_hosts", 1),
        ("namespace_isolation", True),
        ("all_resources_removed", True),
        ("retained_claim_eligible", True),
    ):
        raw_equal(summary.get(field), expected, f"selected NAT suite summary.{field}")
    source = validate_raw_source_identity(
        summary.get("source_identity"), document, "selected NAT suite source"
    )
    raw_equal(
        load_raw_json(
            root_descriptor,
            "source-identity.json",
            "selected NAT retained suite source",
            entries=entries,
        ),
        source,
        "selected NAT retained suite source",
    )
    if source_authority is not None:
        for field in (
            "commit",
            "tree",
            "cargo_toml_sha256",
            "cargo_lock_sha256",
            "requirements_sha256",
            "dockerfile_sha256",
            "build_input_manifest_sha256",
        ):
            raw_equal(
                source.get(field),
                source_authority[field],
                f"selected NAT suite source reviewer binding {field}",
            )
    build = validate_raw_build_identity(
        summary.get("build_identity"), document, "selected NAT suite build"
    )
    raw_equal(
        load_raw_json(
            root_descriptor,
            "selected-build.json",
            "selected NAT retained suite build",
            entries=entries,
        ),
        build,
        "selected NAT retained suite build",
    )
    raw_equal(summary.get("source_commit"), source["commit"], "suite source_commit")
    raw_equal(summary.get("source_tree"), source["tree"], "suite source_tree")
    raw_equal(summary.get("image_id"), build["image_id"], "suite image_id")
    raw_equal(
        summary.get("build_input_manifest_sha256"),
        build["input_manifest_sha256"],
        "suite build_input_manifest_sha256",
    )
    raw_equal(
        summary.get("build_command_sha256"),
        sha256_bytes(build["command"].encode("utf-8")),
        "suite build_command_sha256",
    )
    run_id = document["build"]["container"]["build_run_id"]
    suite_controller = load_raw_json(
        root_descriptor,
        "controller.json",
        "suite controller",
        entries=entries,
    )
    suite_controller_object = raw_object(suite_controller, "suite controller")
    suite_evidence_dir = str(
        canonical_absolute_path(
            exact_string(
                suite_controller_object.get("evidence_dir"),
                "suite controller.evidence_dir",
                maximum=4096,
            ),
            "suite controller.evidence_dir",
        )
    )
    validated_suite_controller = validate_raw_controller(
        suite_controller,
        label="suite controller",
        run_id=run_id,
        run_label="selected-iroh-nat",
        evidence_dir=suite_evidence_dir,
        require_empty_resources=True,
    )
    suite_workspace = str(validated_suite_controller["workspace"])
    build_root = validate_build_command(
        document["build"]["command"], document["build"]["container"]
    )
    raw_equal(
        str(build_root),
        suite_evidence_dir,
        "build command/suite evidence directory binding",
    )
    cells = raw_array(summary.get("cells"), "selected NAT suite cells", length=2)
    inventories = []
    images = []
    mission_authorities: list[str] = []
    stderr_authorities: dict[str, dict[str, Any]] = {}
    containments: dict[str, dict[str, Any]] = {}
    for index, profile in enumerate(CELL_NAMES):
        inventory, image, cell_stderr, containment, mission_authority = (
            validate_raw_cell_semantics(
                root_descriptor,
                suite_evidence_dir,
                suite_workspace,
                profile,
                cells[index],
                document,
                source,
                entries,
            )
        )
        inventories.append(inventory)
        images.append(image)
        mission_authorities.append(mission_authority)
        if set(stderr_authorities).intersection(cell_stderr):
            fail("raw command stderr authorities overlap across cells")
        stderr_authorities.update(cell_stderr)
        containments[profile] = containment
    raw_equal(inventories[0], inventories[1], "cell binary inventories")
    raw_equal(images[0], images[1], "cell image identities")
    if len(set(mission_authorities)) != len(CELL_NAMES):
        fail("selected NAT cell mission authorities are not fresh and distinct")
    public_endpoint_ids = {
        endpoint[field]
        for cell in document["cells"]
        for endpoint in cell["endpoints"]
        for field in ("mission_id", "carrier_id")
    }
    if set(mission_authorities) & public_endpoint_ids:
        fail("selected NAT mission authority and endpoint identity domains overlap")
    return stderr_authorities, containments


def verify_raw_root(
    root: Path,
    document: dict[str, Any],
    *,
    source_authority: dict[str, str] | None = None,
) -> None:
    manifest = exact_object(document["raw_manifest"], MANIFEST_KEYS, "raw_manifest")
    root_descriptor, opened_root = open_raw_root(root)
    try:
        entries = exact_array(manifest["entries"], None, "raw_manifest.entries")
        for index, entry in enumerate(entries):
            verify_raw_entry(root_descriptor, entry, index)
        for cell in CELL_NAMES:
            verify_absent_raw_path(
                root_descriptor,
                f"cells/{cell}/outputs/provision/private/canary.bin",
                f"cells.{cell} standalone canary control file",
            )
            verify_absent_raw_path(
                root_descriptor,
                (
                    f"cells/{cell}/outputs/provision/relay/private/"
                    "server.key.pkcs8.der"
                ),
                f"cells.{cell} standalone relay private key file",
            )
        stderr_authorities, containments = validate_raw_semantics(
            root_descriptor,
            root,
            document,
            source_authority=source_authority,
        )
        # Reverify the complete retained evidence set at the acceptance boundary.
        # Semantic readers above bind their parse to the manifest bytes on the
        # same descriptor; this final pass also covers opaque DER/pcap evidence.
        for index, entry in enumerate(entries):
            verify_raw_entry(root_descriptor, entry, index)
        reverify_raw_command_stderr(root_descriptor, stderr_authorities)
        for profile, containment in containments.items():
            validate_raw_restricted_state(root_descriptor, profile, containment)
        for cell in CELL_NAMES:
            verify_absent_raw_path(
                root_descriptor,
                f"cells/{cell}/outputs/provision/private/canary.bin",
                f"terminal cells.{cell} standalone canary control file",
            )
            verify_absent_raw_path(
                root_descriptor,
                (
                    f"cells/{cell}/outputs/provision/relay/private/"
                    "server.key.pkcs8.der"
                ),
                f"terminal cells.{cell} standalone relay private key file",
            )
        verify_raw_tree_inventory(
            root_descriptor,
            document,
            manifest_entries_by_role(document),
            stderr_authorities,
        )
        final_root = os.fstat(root_descriptor)
        validate_open_directory(final_root, "raw root", root=True)
        if (final_root.st_dev, final_root.st_ino) != (
            opened_root.st_dev,
            opened_root.st_ino,
        ):
            fail("raw root changed identity during inspection")
        try:
            path_final = os.lstat(root)
        except OSError:
            fail("raw root path vanished during inspection")
        validate_open_directory(path_final, "raw root", root=True)
        if (path_final.st_dev, path_final.st_ino) != (
            final_root.st_dev,
            final_root.st_ino,
        ):
            fail("raw root path changed identity during inspection")
    finally:
        os.close(root_descriptor)


def validate_limitations(value: Any) -> None:
    limitations = exact_object(value, set(LIMITATIONS), "limitations")
    for field, expected in LIMITATIONS.items():
        observed = limitations[field]
        if type(observed) is not type(expected) or observed != expected:
            fail("limitations differ from the mandatory bounded claim and nonclaims")


def validate_receipt(document: dict[str, Any]) -> None:
    receipt = exact_object(document, TOP_KEYS, "receipt")
    exact_string(receipt["schema"], "schema", expected=SCHEMA)
    exact_string(receipt["status"], "status", expected="pass")
    exact_string(receipt["claim"], "claim", expected=CLAIM)
    validate_source(receipt["source"])
    validate_build(receipt["build"])
    validate_environment(receipt["environment"])
    raw_cells = exact_array(receipt["cells"], len(CELL_NAMES), "cells")
    cells = {
        name: validate_cell(raw_cells[index], name)
        for index, name in enumerate(CELL_NAMES)
    }

    carriers = [
        endpoint["carrier_id"]
        for cell in cells.values()
        for endpoint in cell["endpoints"]
    ]
    missions = [
        endpoint["mission_id"]
        for cell in cells.values()
        for endpoint in cell["endpoints"]
    ]
    if len(set(carriers)) != 4 or len(set(missions)) != 4:
        fail("cell endpoint carrier and mission identities are not globally fresh")
    if set(carriers) & set(missions):
        fail("carrier and mission identity domains are not disjoint")
    for field in ("event_id", "payload_sha256", "canary_sha256"):
        if len({cell["event"][field] for cell in cells.values()}) != 2:
            fail(f"cell Event {field} values are not fresh and distinct")

    validate_manifest(receipt["raw_manifest"], cells)
    validate_limitations(receipt["limitations"])


def run_source_git(
    git: str,
    source: Path,
    arguments: Sequence[str],
    label: str,
    *,
    maximum: int = 16 * 1024 * 1024,
    trusted_options: Sequence[str] = (),
) -> bytes:
    environment = os.environ.copy()
    for key in list(environment):
        if key in {
            "GIT_DIR",
            "GIT_WORK_TREE",
            "GIT_COMMON_DIR",
            "GIT_OBJECT_DIRECTORY",
            "GIT_ALTERNATE_OBJECT_DIRECTORIES",
            "GIT_INDEX_FILE",
            "GIT_NAMESPACE",
            "GIT_CONFIG_PARAMETERS",
            "GIT_CONFIG_SYSTEM",
        } or key.startswith("GIT_CONFIG_KEY_") or key.startswith("GIT_CONFIG_VALUE_"):
            environment.pop(key, None)
    environment.pop("GIT_CONFIG_COUNT", None)
    environment.update(
        {
            "GIT_NO_REPLACE_OBJECTS": "1",
            "GIT_CONFIG_NOSYSTEM": "1",
            "GIT_CONFIG_GLOBAL": os.devnull,
        }
    )
    try:
        result = subprocess.run(
            [
                git,
                "--no-replace-objects",
                *trusted_options,
                "-C",
                str(source),
                *arguments,
            ],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env=environment,
            shell=False,
            check=False,
            timeout=60,
        )
    except (OSError, subprocess.TimeoutExpired) as error:
        fail(f"reviewer source {label} could not complete: {error}")
    if len(result.stdout) > maximum or len(result.stderr) > 1024 * 1024:
        fail(f"reviewer source {label} output exceeds its bound")
    if result.returncode != 0:
        fail(f"reviewer source {label} failed")
    return result.stdout


def reviewer_signature_options(git: str) -> list[str]:
    """Freeze the reviewer's global trust roots as command-line Git config."""
    environment = os.environ.copy()
    for key in list(environment):
        if key in {
            "GIT_DIR",
            "GIT_WORK_TREE",
            "GIT_COMMON_DIR",
            "GIT_OBJECT_DIRECTORY",
            "GIT_ALTERNATE_OBJECT_DIRECTORIES",
            "GIT_INDEX_FILE",
            "GIT_NAMESPACE",
            "GIT_CONFIG_PARAMETERS",
            "GIT_CONFIG_SYSTEM",
            "GIT_CONFIG_GLOBAL",
        } or key.startswith("GIT_CONFIG_KEY_") or key.startswith("GIT_CONFIG_VALUE_"):
            environment.pop(key, None)
    environment.pop("GIT_CONFIG_COUNT", None)
    reviewer_global = os.path.abspath(os.fspath(Path.home() / ".gitconfig"))
    if os.path.realpath(reviewer_global) != reviewer_global:
        fail("reviewer global Git configuration is symbolic or noncanonical")
    try:
        global_metadata = os.lstat(reviewer_global)
    except OSError:
        fail("reviewer global Git configuration is unavailable")
    if (
        not stat.S_ISREG(global_metadata.st_mode)
        or stat.S_ISLNK(global_metadata.st_mode)
        or global_metadata.st_uid != os.getuid()
        or global_metadata.st_nlink != 1
        or global_metadata.st_size > 1024 * 1024
        or stat.S_IMODE(global_metadata.st_mode) & 0o022
    ):
        fail("reviewer global Git configuration metadata is unsafe")
    environment.update(
        {
            "GIT_NO_REPLACE_OBJECTS": "1",
            "GIT_CONFIG_NOSYSTEM": "1",
            "GIT_CONFIG_GLOBAL": reviewer_global,
        }
    )

    def global_value(arguments: Sequence[str], label: str) -> str:
        try:
            result = subprocess.run(
                [git, "config", "--global", *arguments],
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                env=environment,
                shell=False,
                check=False,
                timeout=10,
            )
        except (OSError, subprocess.TimeoutExpired) as error:
            fail(f"reviewer signature {label} could not be read: {error}")
        if result.returncode != 0 or len(result.stdout) > 4096 or result.stderr:
            fail(f"reviewer signature {label} is unavailable")
        try:
            value = result.stdout.decode("utf-8", errors="strict").strip()
        except UnicodeDecodeError:
            fail(f"reviewer signature {label} is not UTF-8")
        if not value or "\n" in value or "\x00" in value:
            fail(f"reviewer signature {label} is malformed")
        return value

    signature_format = global_value(["--get", "gpg.format"], "format")
    if signature_format == "ssh":
        allowed = global_value(
            ["--path", "--get", "gpg.ssh.allowedSignersFile"],
            "allowed signers",
        )
        allowed_path = os.path.abspath(os.path.expanduser(allowed))
        if os.path.realpath(allowed_path) != allowed_path:
            fail("reviewer SSH allowed-signers path is symbolic or noncanonical")
        try:
            allowed_metadata = os.lstat(allowed_path)
        except OSError:
            fail("reviewer SSH allowed-signers file is unavailable")
        if (
            not stat.S_ISREG(allowed_metadata.st_mode)
            or stat.S_ISLNK(allowed_metadata.st_mode)
            or allowed_metadata.st_uid != os.getuid()
            or allowed_metadata.st_nlink != 1
            or allowed_metadata.st_size <= 0
            or allowed_metadata.st_size > 1024 * 1024
            or stat.S_IMODE(allowed_metadata.st_mode) & 0o022
        ):
            fail("reviewer SSH allowed-signers file metadata is unsafe")
        ssh_keygen = shutil.which("ssh-keygen")
        if ssh_keygen is None or not os.path.isabs(ssh_keygen):
            fail("reviewer ssh-keygen executable is unavailable")
        return [
            "-c",
            "gpg.format=ssh",
            "-c",
            f"gpg.ssh.allowedSignersFile={allowed_path}",
            "-c",
            f"gpg.ssh.program={ssh_keygen}",
            "-c",
            "gpg.minTrustLevel=fully",
        ]
    if signature_format == "openpgp":
        gpg = shutil.which("gpg")
        if gpg is None or not os.path.isabs(gpg):
            fail("reviewer gpg executable is unavailable")
        return [
            "-c",
            "gpg.format=openpgp",
            "-c",
            f"gpg.program={gpg}",
            "-c",
            f"gpg.openpgp.program={gpg}",
            "-c",
            "gpg.minTrustLevel=fully",
        ]
    fail("reviewer signature format is unsupported")


def reconstruct_verified_git_tree(
    git: str,
    source: Path,
    root_tree: str,
    *,
    trusted_options: Sequence[str],
) -> dict[str, tuple[str, str]]:
    """Derive every regular leaf from independently hashed canonical tree objects."""
    cache: dict[str, list[tuple[str, bytes, str]]] = {}
    active: set[str] = set()
    files: dict[str, tuple[str, str]] = {}
    budget = {
        "objects": 0,
        "entries": 0,
        "expanded_entries": 0,
        "bytes": 0,
        "path_bytes": 0,
    }

    def parse_tree_object(object_id: str) -> list[tuple[str, bytes, str]]:
        if object_id in cache:
            return cache[object_id]
        if not GIT_OBJECT.fullmatch(object_id):
            fail("reviewer source tree contains a malformed object identifier")
        content = run_source_git(
            git,
            source,
            ["cat-file", "tree", object_id],
            f"tree object {object_id}",
            maximum=MAX_GIT_TREE_BYTES,
            trusted_options=trusted_options,
        )
        identity = hashlib.sha1(
            f"tree {len(content)}\0".encode("ascii") + content
        ).hexdigest()
        raw_equal(identity, object_id, "reviewer source immutable descendant tree")
        budget["objects"] += 1
        budget["bytes"] += len(content)
        if (
            budget["objects"] > MAX_GIT_TREE_OBJECTS
            or budget["bytes"] > MAX_GIT_TREE_BYTES
        ):
            fail("reviewer source tree-object authority exceeds its bound")
        entries: list[tuple[str, bytes, str]] = []
        names: set[bytes] = set()
        previous_key: bytes | None = None
        offset = 0
        while offset < len(content):
            space = content.find(b" ", offset)
            terminator = content.find(b"\0", space + 1 if space >= 0 else offset)
            if space <= offset or terminator <= space + 1 or terminator + 21 > len(content):
                fail("reviewer source tree object has a malformed entry")
            mode_bytes = content[offset:space]
            name_bytes = content[space + 1 : terminator]
            raw_object_id = content[terminator + 1 : terminator + 21]
            offset = terminator + 21
            if mode_bytes == b"40000":
                mode = "40000"
                tree_entry = True
            elif mode_bytes in {b"100644", b"100755"}:
                mode = mode_bytes.decode("ascii")
                tree_entry = False
            else:
                fail("reviewer source tree contains a non-regular or non-tree entry")
            if (
                not name_bytes
                or len(name_bytes) > 255
                or name_bytes in {b".", b".."}
                or b"/" in name_bytes
                or b"\\" in name_bytes
                or any(value in name_bytes for value in (b"\r", b"\n", b"\t"))
            ):
                fail("reviewer source tree contains a noncanonical entry name")
            try:
                name_bytes.decode("utf-8", errors="strict")
            except UnicodeDecodeError:
                fail("reviewer source tree contains a non-UTF-8 entry name")
            if name_bytes in names:
                fail("reviewer source tree contains a duplicate entry name")
            names.add(name_bytes)
            sort_key = name_bytes + (b"/" if tree_entry else b"\0")
            if previous_key is not None and sort_key <= previous_key:
                fail("reviewer source tree entries are not canonically ordered")
            previous_key = sort_key
            entries.append((mode, name_bytes, raw_object_id.hex()))
            budget["entries"] += 1
            if budget["entries"] > MAX_GIT_TREE_ENTRIES:
                fail("reviewer source tree entry count exceeds its bound")
        cache[object_id] = entries
        return entries

    def walk(prefix: str, object_id: str, depth: int) -> None:
        if depth > MAX_GIT_TREE_DEPTH:
            fail("reviewer source tree depth exceeds its bound")
        if object_id in active:
            fail("reviewer source tree contains an object cycle")
        active.add(object_id)
        try:
            for mode, raw_name, child_id in parse_tree_object(object_id):
                budget["expanded_entries"] += 1
                if budget["expanded_entries"] > MAX_GIT_TREE_ENTRIES:
                    fail("reviewer source expanded tree entries exceed their bound")
                name = raw_name.decode("utf-8")
                relative = f"{prefix}/{name}" if prefix else name
                encoded_path = relative.encode("utf-8")
                if len(encoded_path) > 4096:
                    fail("reviewer source tree path exceeds its bound")
                budget["path_bytes"] += len(encoded_path)
                if budget["path_bytes"] > MAX_GIT_TREE_PATH_BYTES:
                    fail("reviewer source tree paths exceed their aggregate bound")
                if mode == "40000":
                    walk(relative, child_id, depth + 1)
                else:
                    if relative in files:
                        fail("reviewer source tree contains a repeated path")
                    files[relative] = (mode, child_id)
        finally:
            active.remove(object_id)

    walk("", root_tree, 0)
    return files


def verify_source_checkout(source: Path, document: dict[str, Any]) -> dict[str, str]:
    """Reconstruct the sealed input authority from one immutable signed commit."""
    source_text = os.path.abspath(os.fspath(source))
    if os.path.realpath(source_text) != source_text:
        fail("reviewer source path is symbolic or noncanonical")
    try:
        metadata = os.lstat(source_text)
    except OSError:
        fail("reviewer source checkout is unavailable")
    if not stat.S_ISDIR(metadata.st_mode) or stat.S_ISLNK(metadata.st_mode):
        fail("reviewer source checkout is not a plain directory")
    git = shutil.which("git")
    if git is None:
        fail("git is required for independent source review")
    source_path = Path(source_text)
    trusted_options = reviewer_signature_options(git)
    commit = exact_string(document["source"]["commit"], "reviewer source commit", pattern=GIT_OBJECT)
    commit_content = run_source_git(
        git,
        source_path,
        ["cat-file", "commit", commit],
        "commit object",
        trusted_options=trusted_options,
    )
    commit_identity = hashlib.sha1(
        f"commit {len(commit_content)}\0".encode("ascii") + commit_content
    ).hexdigest()
    raw_equal(commit_identity, commit, "reviewer source immutable commit object")
    signature_format = next(
        (
            option.removeprefix("gpg.format=")
            for option in trusted_options
            if option.startswith("gpg.format=")
        ),
        None,
    )
    signature_marker = {
        "ssh": b"gpgsig -----BEGIN SSH SIGNATURE-----\n",
        "openpgp": b"gpgsig -----BEGIN PGP SIGNATURE-----\n",
    }.get(signature_format)
    if signature_marker is None or commit_content.count(signature_marker) != 1:
        fail("reviewer source commit signature format differs from trusted authority")
    tree_match = re.match(rb"tree ([0-9a-f]{40})\n", commit_content)
    if tree_match is None:
        fail("reviewer source commit omits its exact tree header")
    tree = tree_match.group(1).decode("ascii")
    raw_equal(tree, document["source"]["tree"], "reviewer source commit tree")
    run_source_git(
        git,
        source_path,
        ["verify-commit", commit],
        "commit signature",
        trusted_options=trusted_options,
    )
    all_committed = reconstruct_verified_git_tree(
        git,
        source_path,
        tree,
        trusted_options=trusted_options,
    )
    fixed_build = {
        ".dockerignore",
        "Cargo.toml",
        "Cargo.lock",
        "LICENSE",
        "lab/Dockerfile",
        "lab/Dockerfile.selected-nat",
        "lab/Dockerfile.dockerignore",
        "lab/debian.sources",
    }
    requirements_path = "data-mesh-requirements.md"
    admitted_paths = {
        relative
        for relative in all_committed
        if relative in fixed_build
        or relative.startswith("crates/")
        or relative.startswith("third-party/")
        or relative == requirements_path
    }
    committed = {relative: all_committed[relative] for relative in admitted_paths}
    committed_path_bytes = sum(len(relative.encode("utf-8")) for relative in committed)
    if committed_path_bytes > 1024 * 1024:
        fail("reviewer source committed input paths exceed their byte bound")
    if len(committed) > MAX_COMMITTED_INPUTS:
        fail("reviewer source committed input count exceeds its bound")
    build_paths = admitted_paths - {requirements_path}
    expected_all = build_paths | {requirements_path}
    if fixed_build - build_paths or set(committed) != expected_all:
        fail("reviewer source commit admitted input set differs")
    total = 0
    contents: dict[str, bytes] = {}
    for relative in sorted(expected_all):
        _mode, object_id = committed[relative]
        size_text = run_source_git(
            git,
            source_path,
            ["cat-file", "-s", object_id],
            f"blob size {relative}",
            maximum=64,
            trusted_options=trusted_options,
        ).decode("ascii", errors="strict").strip()
        if not re.fullmatch(r"[0-9]+", size_text):
            fail(f"reviewer source blob size is malformed: {relative}")
        size = int(size_text)
        total += size
        if size > 256 * 1024 * 1024 or total > 1024 * 1024 * 1024:
            fail("reviewer source admitted blobs exceed the byte bound")
        content = run_source_git(
            git,
            source_path,
            ["cat-file", "blob", object_id],
            f"blob {relative}",
            maximum=size,
            trusted_options=trusted_options,
        )
        if len(content) != size:
            fail(f"reviewer source blob size changed: {relative}")
        git_blob = hashlib.sha1(
            f"blob {len(content)}\0".encode("ascii") + content
        ).hexdigest()
        raw_equal(git_blob, object_id, f"reviewer source blob identity {relative}")
        contents[relative] = content
    if contents[".dockerignore"] != EXPECTED_DOCKERIGNORE.encode("utf-8") or contents[
        "lab/Dockerfile.dockerignore"
    ] != EXPECTED_DOCKERIGNORE.encode("utf-8"):
        fail("reviewer source deny-all Docker ignore policy differs")
    input_records = [
        {
            "path": relative,
            "bytes": len(contents[relative]),
            "sha256": hashlib.sha256(contents[relative]).hexdigest(),
        }
        for relative in sorted(build_paths)
    ]
    input_document = {
        "dockerignore_sha256": hashlib.sha256(
            EXPECTED_DOCKERIGNORE.encode("utf-8")
        ).hexdigest(),
        "files": input_records,
    }
    input_digest = hashlib.sha256(
        json.dumps(input_document, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()
    authority = {
        "commit": commit,
        "tree": tree,
        "cargo_toml_sha256": hashlib.sha256(contents["Cargo.toml"]).hexdigest(),
        "cargo_lock_sha256": hashlib.sha256(contents["Cargo.lock"]).hexdigest(),
        "requirements_sha256": hashlib.sha256(contents[requirements_path]).hexdigest(),
        "dockerfile_sha256": hashlib.sha256(
            contents["lab/Dockerfile.selected-nat"]
        ).hexdigest(),
        "build_input_manifest_sha256": input_digest,
    }
    for field in ("commit", "tree", "cargo_lock_sha256", "requirements_sha256"):
        raw_equal(authority[field], document["source"][field], f"reviewer source {field}")
    raw_equal(
        authority["dockerfile_sha256"],
        document["build"]["container"]["dockerfile_sha256"],
        "reviewer source selected Dockerfile",
    )
    raw_equal(
        authority["build_input_manifest_sha256"],
        document["build"]["container"]["input_manifest_sha256"],
        "reviewer source admitted input manifest",
    )
    return authority


def parse_args(arguments: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--raw-root",
        required=True,
        type=Path,
        help="completed suite root containing every curated raw artifact",
    )
    parser.add_argument(
        "--source",
        required=True,
        type=Path,
        help="checkout containing the exact signed source commit and Git objects",
    )
    parser.add_argument("receipt", type=Path, help="canonical sanitized NAT receipt JSON")
    return parser.parse_args(arguments)


def main(arguments: list[str] | None = None) -> None:
    options = parse_args(arguments)
    try:
        document = load_receipt(options.receipt)
        validate_receipt(document)
        source_authority = verify_source_checkout(options.source, document)
        verify_raw_root(options.raw_root, document, source_authority=source_authority)
    except ReceiptViolation as error:
        print(f"selected Iroh NAT receipt validation failed: {error}", file=sys.stderr)
        raise SystemExit(1) from error
    print(
        "selected Iroh NAT receipt passed: schema="
        f"{SCHEMA} cells=cone-direct,restrictive-relay physical-hosts=1"
    )


if __name__ == "__main__":
    main()
