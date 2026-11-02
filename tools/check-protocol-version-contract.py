#!/usr/bin/env python3
# Copyright 2026 Defense Unicorns, Inc.
# SPDX-License-Identifier: Apache-2.0
"""Keep the implemented and normative semantic-version registries aligned."""

from __future__ import annotations

from pathlib import Path
import ast
import json
import re
import subprocess
import sys


ROOT = Path(__file__).resolve().parents[1]
VERSIONS = tuple(range(1, 10))
DEFAULT_OFFER = tuple(reversed(VERSIONS))
PROTOCOL_ROWS = {
    1: ("—", "stable Event and Blob-chunk transfer"),
    2: ("v1", "compact batch and bridge objects"),
    3: ("v2", "session custody record"),
    4: ("v3", "State and Record reconciliation"),
    5: ("v4", "historical direct Blob frame allocation"),
    6: ("v5 ordinary lanes byte-for-byte", "Event bridge transfer"),
    7: (
        "v6 byte-for-byte",
        "per-lane profiles, receipt-free Event pages, and durable Blob range streams",
    ),
    8: (
        "v7 byte-for-byte except the lane AAD domain and Blob custody fields",
        "authenticated finite Blob custody over `BlobRangesStreamV1`",
    ),
    9: (
        "v8 fixed lanes byte-for-byte except the Blob transfer profile and Blob chunk kind",
        "independently authenticated Blob streams over `BlobStreamV1`",
    ),
}
CDDL_ALIASES = {
    1: "1 / 2",
    2: "semantic-v1-object-kind / 3 / 4 / 5",
    3: "semantic-v2-object-kind",
    4: "semantic-v3-object-kind",
    5: "semantic-v4-object-kind",
    6: "semantic-v5-object-kind",
    7: "semantic-v6-object-kind",
    8: "semantic-v7-object-kind",
    9: "1 / 3 / 4 / 5",
}
PROTOCOL_DEFAULT_OFFER_PATTERNS = (
    r"default semantic offer is\s*`\[([^\]]+)\]`",
    r"default\s+descending\s+offer\s+is\s*`\[([^\]]+)\]`",
    r"default initiator offers\s+semantic versions\s*`\[([^\]]+)\]`",
)
PROFILE4_LIMITS = (67_108_864, 1_024, 1_048_576)
PROFILE5_LIMIT_NAMES = (
    "MAX_SELECTED_BLOB_STREAM_BYTES",
    "MAX_STREAM_AUTHENTICATED_OPEN_BYTES",
    "BLOB_STREAM_SEGMENT_BYTES",
    "BLOB_STREAM_SEGMENT_ENCODED_OVERHEAD_BYTES",
    "PROFILE5_PACK_RECORD_PREFIX_BYTES",
    "PROFILE5_PACK_SEGMENT_RECORD_BYTES",
    "PROFILE5_PACK_TRANSPORT_FRAME_BYTES",
    "PROFILE5_MAX_PACK_SEGMENTS",
    "PROFILE5_MAX_PACK_WIRE_BYTES",
    "MAX_STREAM_CHECKPOINT_BATCH_BYTES",
    "DEFAULT_MAX_EXCHANGE_BYTES",
)
PROFILE5_PIPELINE = (
    "PLAN -> OPEN -> SOURCE -> ACCEPT -> ASTRBS02 pack DATA -> CHECKPOINT -> FINISH -> RESULT -> ACK"
)
PROFILE5_EMPTY_PIPELINE = (
    "OPEN -> SOURCE -> ACCEPT -> FINISH(final_offset=0) -> RESULT -> ACK, "
    "with no DATA or CHECKPOINT"
)
PROFILE5_RECORDS = {
    "OPEN": (0xD6, ["class", "direction", "semantic_version", "profile_id", "session_transcript", "exchange_id", "transfer_id", "source_transfer_id", "publication_id", "variant_id", "total_len", "attempt_nonce", "checkpoint_generation", "custody_present", "custody_digest", "source_len", "source_digest"]),
    "SOURCE": (0xDD, ["attempt", "source_offset", "source_total_len", "source_chunk_len", "source_chunk"]),
    "ACCEPT": (0xD7, ["attempt", "durable_offset", "checkpoint_generation", "absolute_receive_limit", "max_extent_bytes", "checkpoint_batch_bytes"]),
    "DATA": (0xD8, ["attempt", "offset", "extent_len", "astrbs02_record"]),
    "CHECKPOINT": (0xD9, ["attempt", "durable_offset", "checkpoint_generation", "absolute_receive_limit"]),
    "FINISH": (0xDA, ["attempt", "final_offset", "commitment_len", "semantic_commitment"]),
    "RESULT": (0xDB, ["attempt", "final_offset", "result_code", "result_digest"]),
    "ACK": (0xDC, ["attempt", "result_digest"]),
}
PROFILE5_FIELDS = {
    "OPEN": [["class", "u8-enum:1"], ["direction", "u8-enum:1,2"], ["semantic_version", "u16=9"], ["profile_id", "u16=5"], ["session_transcript", "bytes32"], ["exchange_id", "u64"], ["transfer_id", "bytes32"], ["source_transfer_id", "bytes32"], ["publication_id", "bytes32"], ["variant_id", "bytes32"], ["total_len", "u64-native-pack-wire<=8591032320"], ["attempt_nonce", "bytes32-nonzero"], ["checkpoint_generation", "u64"], ["custody_present", "u8-enum:0,1"], ["custody_digest", "bytes32-if-present"], ["source_len", "u32:1..401902"], ["source_digest", "bytes32"]],
    "SOURCE": [["attempt", "attempt_fields"], ["source_offset", "u32"], ["source_total_len", "u32:1..401902"], ["source_chunk_len", "u32:1..1048576"], ["source_chunk", "bytes[source_chunk_len]"]],
    "ACCEPT": [["attempt", "attempt_fields"], ["durable_offset", "u64"], ["checkpoint_generation", "u64"], ["absolute_receive_limit", "u64>=durable_offset"], ["max_extent_bytes", "u32:1..1048710"], ["checkpoint_batch_bytes", "u32:1..134217728"]],
    "DATA": [["attempt", "attempt_fields"], ["offset", "u64"], ["extent_len", "u32:1..1048710"], ["astrbs02_record", "bytes[extent_len],length-prefixed-ASTRBS02"]],
    "CHECKPOINT": [["attempt", "attempt_fields"], ["durable_offset", "u64"], ["checkpoint_generation", "u64"], ["absolute_receive_limit", "u64>=durable_offset"]],
    "FINISH": [["attempt", "attempt_fields"], ["final_offset", "u64"], ["commitment_len", "u32:1..65536"], ["semantic_commitment", "bytes[commitment_len]"]],
    "RESULT": [["attempt", "attempt_fields"], ["final_offset", "u64"], ["result_code", "u8-enum:1,2,3,4,5,6"], ["result_digest", "bytes32"]],
    "ACK": [["attempt", "attempt_fields"], ["result_digest", "bytes32"]],
}
PROFILE5_RUST_ORDER = {
    "OPEN": ["o.push(0xd6)", "x.class as u8", "x.direction as u8", "9u16.to_be_bytes()", "5u16.to_be_bytes()", "x.session_transcript", "x.exchange_id", "x.transfer_id", "x.source_transfer_id", "x.publication_id", "x.variant_id", "x.total_len", "x.attempt_nonce", "x.checkpoint_generation", "match x.custody_digest", "x.source_len", "x.source_digest"],
    "SOURCE": ["o.push(0xdd)", "put_attempt", "x.offset", "x.total_len", "x.bytes.len()", "o.extend(&x.bytes)"],
    "ACCEPT": ["o.push(0xd7)", "put_attempt", "x.durable_offset", "x.checkpoint_generation", "x.absolute_receive_limit", "x.max_extent_bytes", "x.checkpoint_batch_bytes"],
    "DATA": ["o.push(0xd8)", "put_attempt", "x.offset", "l.to_be_bytes()", "o.extend(&x.bytes)"],
    "CHECKPOINT": ["o.push(0xd9)", "put_attempt", "x.durable_offset", "x.checkpoint_generation", "x.absolute_receive_limit"],
    "FINISH": ["o.push(0xda)", "put_attempt", "x.final_offset", "x.semantic_commitment.len()", "o.extend(&x.semantic_commitment)"],
    "RESULT": ["o.push(0xdb)", "put_attempt", "x.final_offset", "x.code as u8", "x.result_digest"],
    "ACK": ["o.push(0xdc)", "put_attempt", "x.result_digest"],
}
PROFILE5_ATTEMPT_FIELDS = [["transfer_id", "bytes32"], ["attempt_nonce", "bytes32-nonzero"], ["sequence", "u64"]]
PROFILE5_PACK_FIELDS = [["record_len", "u32:1..1048706"], ["record", "bytes[record_len],valid-ASTRBS02"]]
PROFILE5_COMPOSITE_FIELDS = [["protected_header_len", "u32:1..2048"], ["protected_header", "bytes[protected_header_len],protected-ASTRFR01-DATA-header"], ["length_prefixed_astrbs02_record", "bytes[record_len+4]"]]
PROFILE5_FLOWS = {
    "nonempty": ["PLAN", "OPEN", "SOURCE", "ACCEPT", "DATA", "CHECKPOINT", "FINISH", "RESULT", "ACK"],
    "empty": ["PLAN", "OPEN", "SOURCE", "ACCEPT", "FINISH", "RESULT", "ACK"],
}
PROFILE5_RUST_DECODE_ORDER = {
    "OPEN": ["StreamClass::decode(r.u8()?)", "StreamDirection::decode(r.u8()?)", "r.u16() != Ok(9)", "r.u16() != Ok(5)", "let session_transcript = r.array()?", "let exchange_id = r.u64()?", "let transfer_id = r.array()?", "let source_transfer_id = r.array()?", "let publication_id = r.array()?", "let variant_id = r.array()?", "let total_len = r.u64()?", "validate_profile5_wire_len(total_len)?", "let attempt_nonce = r.array()?", "let checkpoint_generation = r.u64()?", "let custody_digest = match r.u8()?", "let source_len = r.u32()?", "let source_digest = r.array()?"],
    "SOURCE": ["let (transfer_id, attempt_nonce, sequence) = r.attempt()?", "let offset = r.u32()?", "let total_len = r.u32()?", "let chunk_len = usize::try_from(r.u32()?)", "bytes: r.take(chunk_len)?.to_vec()"],
    "ACCEPT": ["let (transfer_id, attempt_nonce, sequence) = r.attempt()?", "durable_offset: r.u64()?", "checkpoint_generation: r.u64()?", "absolute_receive_limit: r.u64()?", "max_extent_bytes: r.u32()?", "checkpoint_batch_bytes: r.u32()?"],
    "DATA": ["let (transfer_id, attempt_nonce, sequence) = r.attempt()?", "let offset = r.u64()?", "let extent_len = r.u32()?", "extent(extent_len)?"],
    "CHECKPOINT": ["let (transfer_id, attempt_nonce, sequence) = r.attempt()?", "durable_offset: r.u64()?", "checkpoint_generation: r.u64()?", "absolute_receive_limit: r.u64()?"],
    "FINISH": ["let (transfer_id, attempt_nonce, sequence) = r.attempt()?", "let final_offset = r.u64()?", "let commitment_len = usize::try_from(r.u32()?)", "semantic_commitment: r.take(commitment_len)?.to_vec()"],
    "RESULT": ["let (transfer_id, attempt_nonce, sequence) = r.attempt()?", "final_offset: r.u64()?", "code: StreamResultCode::decode(r.u8()?)?", "result_digest: r.array()?"],
    "ACK": ["let (transfer_id, attempt_nonce, sequence) = r.attempt()?", "result_digest: r.array()?"],
}


class ContractViolation(ValueError):
    """A normative semantic-version declaration drifted from implementation."""


def fail(message: str) -> None:
    raise ContractViolation(message)


def require_version_sequence(
    text: str, pattern: str, expected: tuple[int, ...], label: str
) -> None:
    matches = re.findall(pattern, text, re.DOTALL)
    if len(matches) != 1:
        fail(f"{label} declaration must occur exactly once; found {len(matches)}")
    actual = tuple(int(version) for version in re.findall(r"\d+", matches[0]))
    if actual != expected:
        fail(f"{label} must be {expected}; found {actual}")


def require_once(text: str, declaration: str, label: str) -> None:
    count = text.count(declaration)
    if count != 1:
        fail(f"{label} declaration must occur exactly once; found {count}")


BLOB_PUBLIC_API_FIELDS = {
    "local_publish_waits_for_peer": False,
    "rust_agent_asterctl_publish_read": "implemented",
    "blob_status_scope": "receiver_local_durable_state",
    "blob_status_reports_remote_delivery_peer_or_convergence": False,
    "cli_download_resume": "post_merge",
}

BLOB_DOCUMENTATION_CAPABILITIES = {
    surface: {
        "schema": 1,
        "surface": surface,
        "semantic_v7_v8_profile": "4:BlobRangesStreamV1",
        "semantic_v9_profile": "5:BlobStreamV1",
        "map_unit": "1048576-byte native plaintext segment",
        "record": "ASTRBS02, at most 1048706 bytes",
        "data_body": "4-byte length prefix plus one ASTRBS02 record, at most 1048710 bytes",
    }
    for surface in ("node_api", "transports", "recipes")
}
BLOB_DOCUMENTATION_CAPABILITIES.update(
    {
        "runbook": {
            "schema": 1,
            "surface": "runbook",
            "settlement_order": [
                "authenticated_finish_and_content_verification",
                "canonical_apply_promotion",
                "result",
                "result_ack_or_eof_attempt_settlement",
            ],
            "available_before_attempt_settlement": True,
            "durable_resume_authority": [
                "lifecycle_owned_provisional_source_or_upload_state",
                "native_pack_checkpoint_journal",
            ],
            "attempt_settlement_owns_durable_resume": False,
            "sender_hard_deadline_basis": "exact_native_pack_wire_length",
            "receiver_initial_hard_deadline_basis": "profile_wire_ceiling_before_authenticated_open",
            "contact_no_progress_timeout_seconds": 30,
            "contact_progress_signal": "completed_authenticated_profile5_operation",
            "authenticated_progress_timeout_seconds": 120,
            "plaintext_segment_bytes": 1_048_576,
            "encoded_record_max_bytes": 1_048_706,
            "length_prefixed_data_max_bytes": 1_048_710,
            "checkpoint_batch_max_bytes": 134_217_728,
            "capacity_authority": "configured_blob_depot_limits",
        },
        "performance": {
            "schema": 1,
            "surface": "performance",
            "historical_2026_10_20_format": "ASTRBS02_1MiB_semantic_segments",
            "historical_2026_10_20_supports_architecture": True,
            "historical_2026_10_20_qualifies_current_commit": False,
            "current_map_unit": "1048576-byte native plaintext segment",
            "current_record": "ASTRBS02, at most 1048706 bytes",
            "current_data_body": "length-prefixed record, at most 1048710 bytes",
            "current_cm4_qualification": "pending_task_13",
        },
        "requirements_status": {
            "schema": 1,
            "surface": "requirements_status",
            "default_semantic_offer": [9, 8, 7, 6, 5, 4, 3, 2, 1],
            "semantic_v7_v8_profile": "4:BlobRangesStreamV1",
            "semantic_v9_profile": "5:BlobStreamV1",
            "current_blob_network": "semantic_v9_profile5_with_v7_v8_compatibility",
        },
    }
)
for _surface in (
    "readme",
    "agent_readme",
    "asterctl_readme",
    "selected_blob_api",
    "operator_guide",
    "capability_roadmap",
):
    BLOB_DOCUMENTATION_CAPABILITIES[_surface] = {
        "schema": 1,
        "surface": _surface,
        **BLOB_PUBLIC_API_FIELDS,
    }
BLOB_DOCUMENTATION_CAPABILITIES.update(
    {
        "blob_publish_man": {
            "schema": 1,
            "surface": "blob_publish_man",
            "local_publish_waits_for_peer": False,
            "capacity_authority": "configured_blob_depot_limits",
        },
        "blob_read_man": {
            "schema": 1,
            "surface": "blob_read_man",
            "cli_download_resume": "post_merge",
            "node_to_node_receiver_checkpoint_resume": "implemented",
        },
        "blob_status_man": {
            "schema": 1,
            "surface": "blob_status_man",
            "blob_status_scope": "receiver_local_durable_state",
            "blob_status_reports_remote_delivery_peer_or_convergence": False,
        },
    }
)

REQUIREMENTS_CURRENT_SECTION_NAMES = (
    "selected-lane-summary",
    "current-selected-blob-evidence",
    "running-node-selected-blobs",
    "live-selected-blob",
    "current-automation",
    "selected-blob-network",
    "production-blob-network",
    "production-blob-read",
    "production-blob-lifecycle",
)
_REQUIREMENTS_CURRENT_TEXT = (
    "Current Blob transfer uses semantic v9 profile 5 with lifecycle-owned provisional "
    "source or upload state plus the native pack checkpoint journal as durable resume "
    "authority, and native 1-MiB ASTRBS02 pack records bounded at 8 GiB and 8,192 "
    "segments. Atomic promotion precedes RESULT; RESULT_ACK or EOF settles only the "
    "attempt and owns no durable resume state. Semantic v7/v8 profile 4 remains "
    "compatibility-only at 64 MiB and 1,024 chunks."
)

_CAPABILITY_BLOCK = re.compile(
    r"<!-- ASTER-BLOB-CAPABILITY:BEGIN -->\s*"
    r"```json\s*(.*?)\s*```\s*"
    r"<!-- ASTER-BLOB-CAPABILITY:RENDERED -->\s*"
    r"(.*?)\s*"
    r"<!-- ASTER-BLOB-CAPABILITY:END -->",
    re.DOTALL,
)

_JSON_FENCE = re.compile(r"```json\s*(.*?)\s*```", re.DOTALL | re.IGNORECASE)
_CODE_FENCE = re.compile(r"```.*?```", re.DOTALL)
_CAPABILITY_MARKER = re.compile(r"ASTER-BLOB-CAPABILITY:(?:BEGIN|RENDERED|END)", re.IGNORECASE)
_LEGACY_BLOCK = re.compile(
    r"<!-- ASTER-BLOB-LEGACY:BEGIN -->.*?<!-- ASTER-BLOB-LEGACY:END -->",
    re.DOTALL,
)
_REQUIREMENTS_CURRENT_BLOCK = re.compile(
    r"<!-- ASTER-BLOB-CURRENT:([a-z0-9-]+):BEGIN -->\s*(.*?)\s*"
    r"<!-- ASTER-BLOB-CURRENT:\1:END -->",
    re.DOTALL,
)
_REQUIREMENTS_CURRENT_MARKER = re.compile(
    r"<!--\s*ASTER(?:[-_\s]+)BLOB(?:[-_\s]+)CURRENT\s*:\s*[^:>]+?\s*:\s*"
    r"(?:BEGIN|END)\s*-->",
    re.IGNORECASE,
)
_REQUIREMENTS_CANONICAL_CURRENT_MARKER = re.compile(
    r"<!-- ASTER-BLOB-CURRENT:[a-z0-9-]+:(?:BEGIN|END) -->"
)


def render_blob_documentation_capability(surface: str) -> str:
    """Render the sole human-readable current claim from the typed record."""
    value = BLOB_DOCUMENTATION_CAPABILITIES[surface]
    if surface in {"node_api", "transports", "recipes"}:
        return (
            "Semantic v7/v8 selects profile 4 BlobRangesStreamV1; semantic v9 "
            "selects profile 5 BlobStreamV1. Profile 5 maps 1,048,576-byte plaintext "
            "segments into append-only ASTRBS02 records of at most 1,048,706 bytes "
            "and sends one complete length-prefixed record per DATA body, at most "
            "1,048,710 bytes, without repacking or re-encryption."
        )
    if surface == "runbook":
        return (
            "The receiver verifies authenticated FINISH and content, atomically "
            "promotes the native pack before sending RESULT. RESULT_ACK or EOF settles "
            "only the transport attempt and does not own durable resume state. AVAILABLE "
            "may precede attempt settlement. Durable resume authority is lifecycle-owned "
            "provisional source or upload state plus the native pack checkpoint journal. "
            "The sender hard deadline uses exact "
            "native-pack wire length; before authenticated OPEN, the receiver uses the "
            "profile wire ceiling. A contact with no completed authenticated Profile-5 "
            "operation expires after 30 seconds; each such operation refreshes that outer "
            "watchdog. An individual authenticated Profile-5 operation times out after "
            "120 seconds of inactivity, and the size-derived hard attempt bound remains "
            "absolute. "
            "The 1,048,576-byte plaintext segment, 1,048,706-byte ASTRBS02 record "
            "ceiling, 1,048,710-byte length-prefixed DATA body ceiling, and "
            "134,217,728-byte checkpoint ceiling are distinct. "
            "Provisional upload state, lifecycle-owned provisional source state, native "
            "pack checkpoint journals, and completed native packs share configured Blob "
            "depot limits."
        )
    if surface == "performance":
        return (
            "The 2026-10-20 ASTRBS02 measurements validate the native-pack architecture "
            "but not the current commit. Current qualification must measure 1,048,576-byte "
            "plaintext segments, ASTRBS02 records of at most 1,048,706 bytes, and "
            "length-prefixed DATA bodies of at most 1,048,710 bytes; three-CM4 "
            "qualification remains Task 13 work."
        )
    if surface == "requirements_status":
        return (
            "The current default semantic offer is [9, 8, 7, 6, 5, 4, 3, 2, 1]. "
            "Semantic v9 selects profile 5 BlobStreamV1; semantic v7/v8 retain "
            "compatibility profile 4 BlobRangesStreamV1."
        )
    if surface == "blob_publish_man":
        return (
            "Publication commits to the local canonical Blob authority without waiting "
            "for a peer, and all Blob states share configured depot limits."
        )
    if surface == "blob_read_man":
        return (
            "Interrupted CLI downloads restart at byte zero; node-to-node profile-5 "
            "receiver-checkpoint resume is implemented independently."
        )
    if surface == "blob_status_man":
        return (
            "blob-status reports receiver-local durable state, not remote delivery, "
            "peer status, or convergence."
        )
    if all(value.get(key) == expected for key, expected in BLOB_PUBLIC_API_FIELDS.items()):
        return (
            "Local Blob publication commits without waiting for a peer. Rust, the "
            "native-gRPC agent, and asterctl implement bounded Blob publication and "
            "authenticated reads. blob-status reports receiver-local durable state, "
            "not remote delivery, peer status, or convergence. CLI download resume is "
            "post-merge work; an interrupted download restarts at byte zero."
        )
    raise AssertionError(f"no Blob capability renderer for {surface}")


def blob_documentation_capability_block(surface: str) -> str:
    payload = json.dumps(BLOB_DOCUMENTATION_CAPABILITIES[surface], indent=2)
    return (
        "<!-- ASTER-BLOB-CAPABILITY:BEGIN -->\n"
        "```json\n"
        f"{payload}\n"
        "```\n"
        "<!-- ASTER-BLOB-CAPABILITY:RENDERED -->\n"
        f"{render_blob_documentation_capability(surface)}\n"
        "<!-- ASTER-BLOB-CAPABILITY:END -->"
    )


def render_requirements_current_section(name: str) -> str:
    if name not in REQUIREMENTS_CURRENT_SECTION_NAMES:
        raise KeyError(name)
    return (
        f"<!-- ASTER-BLOB-CURRENT:{name}:BEGIN -->\n"
        f"{_REQUIREMENTS_CURRENT_TEXT}\n"
        f"<!-- ASTER-BLOB-CURRENT:{name}:END -->\n"
    )


def _documentation_sentences(text: str) -> list[set[str]]:
    """Return normalized topic tokens; relations and negation are not interpreted."""
    text = _CODE_FENCE.sub("", text)
    return [
        set(
            re.findall(
                r"[a-z0-9]+",
                re.sub(r"\bblob[ -]status\b", "blobstatus", sentence.lower()).replace("-", " "),
            )
        )
        for sentence in re.split(r"(?<=[.!?])\s+|\n{2,}|\n(?=\|)", text)
        if sentence.strip()
    ]


def _documentation_sentence_text(text: str) -> list[tuple[str, set[str]]]:
    """Return normalized sentence text and tokens for relation-aware checks."""
    text = _CODE_FENCE.sub("", text)
    sentences = []
    for sentence in re.split(r"(?<=[.!?])\s+|\n{2,}|\n(?=\|)", text):
        normalized = " ".join(sentence.lower().replace("-", " ").split())
        if not normalized:
            continue
        normalized = re.sub(r"\bblob\s+status\b", "blobstatus", normalized)
        sentences.append((normalized, set(re.findall(r"[a-z0-9]+", normalized))))
    return sentences


def _contains_any(words: set[str], prefixes: tuple[str, ...]) -> bool:
    return any(any(word.startswith(prefix) for prefix in prefixes) for word in words)


def _strip_legacy_blocks(surface: str, text: str) -> str:
    begins = text.count("<!-- ASTER-BLOB-LEGACY:BEGIN -->")
    ends = text.count("<!-- ASTER-BLOB-LEGACY:END -->")
    matches = list(_LEGACY_BLOCK.finditer(text))
    if begins != ends or begins != len(matches):
        fail(f"Blob documentation {surface} has malformed legacy delimiters")
    return _LEGACY_BLOCK.sub("", text)


def _reject_capability_shaped_json(surface: str, text: str) -> None:
    governed_keys = {
        key
        for value in BLOB_DOCUMENTATION_CAPABILITIES.values()
        for key in value
        if key not in {"schema", "surface"}
    }
    def contains_governed_key(value: object) -> bool:
        if isinstance(value, dict):
            return bool(governed_keys.intersection(value)) or any(
                contains_governed_key(child) for child in value.values()
            )
        if isinstance(value, list):
            return any(contains_governed_key(child) for child in value)
        return False

    for match in _JSON_FENCE.finditer(text):
        try:
            value = json.loads(match.group(1))
        except json.JSONDecodeError:
            continue
        if contains_governed_key(value):
            fail(f"Blob documentation {surface} has an extra capability-shaped JSON block")


def _validate_requirements_current_sections(text: str) -> str:
    candidate_markers = _REQUIREMENTS_CURRENT_MARKER.findall(text)
    canonical_markers = _REQUIREMENTS_CANONICAL_CURRENT_MARKER.findall(text)
    expected_marker_count = 2 * len(REQUIREMENTS_CURRENT_SECTION_NAMES)
    if (
        len(candidate_markers) != expected_marker_count
        or len(canonical_markers) != expected_marker_count
        or candidate_markers != canonical_markers
    ):
        fail(
            "Blob documentation requirements_status current section set differs: "
            "current section marker set differs"
        )
    matches = list(_REQUIREMENTS_CURRENT_BLOCK.finditer(text))
    names = [match.group(1) for match in matches]
    if sorted(names) != sorted(REQUIREMENTS_CURRENT_SECTION_NAMES):
        fail("Blob documentation requirements_status current section set differs")
    for match in matches:
        name = match.group(1)
        if " ".join(match.group(2).split()) != " ".join(_REQUIREMENTS_CURRENT_TEXT.split()):
            fail(f"Blob documentation requirements_status {name} current section differs")
    return _REQUIREMENTS_CURRENT_BLOCK.sub("", text)


def _unstructured_capability_text(surface: str, text: str) -> str:
    if surface == "node_api":
        text = re.sub(r"(?m)^//! ?", "", text)
    if surface in {"blob_publish_man", "blob_read_man", "blob_status_man"}:
        text = re.sub(r'(?m)^\.\\" ?', "", text)
    markers = list(_CAPABILITY_MARKER.finditer(text))
    matches = list(_CAPABILITY_BLOCK.finditer(text))
    if len(markers) != 3 or len(matches) != 1:
        fail(
            f"Blob documentation {surface} must contain exactly one structured capability block"
        )
    try:
        actual = json.loads(matches[0].group(1))
    except json.JSONDecodeError as error:
        fail(f"Blob documentation {surface} capability JSON is malformed: {error.msg}")
    expected = BLOB_DOCUMENTATION_CAPABILITIES[surface]
    if actual != expected:
        fail(f"Blob documentation {surface} capability fields differ from the contract")
    rendered = " ".join(matches[0].group(2).split())
    expected_rendered = " ".join(render_blob_documentation_capability(surface).split())
    if rendered != expected_rendered:
        fail(f"Blob documentation {surface} rendered capability differs from the contract")
    remainder = text[: matches[0].start()] + text[matches[0].end() :]
    _reject_capability_shaped_json(surface, remainder)
    return _strip_legacy_blocks(surface, remainder)


def validate_blob_documentation_contract(documents: dict[str, str]) -> None:
    """Validate one typed authority per surface and reject competing prose claims."""
    if set(documents) != set(BLOB_DOCUMENTATION_CAPABILITIES):
        fail("Blob documentation surfaces differ from the structured contract")
    prose = {
        surface: _unstructured_capability_text(surface, documents[surface])
        for surface in BLOB_DOCUMENTATION_CAPABILITIES
    }
    prose["requirements_status"] = _validate_requirements_current_sections(
        prose["requirements_status"]
    )

    for surface in ("node_api", "transports", "recipes"):
        for words in _documentation_sentences(prose[surface]):
            if (
                {"1", "mib"} <= words
                and _contains_any(words, ("segment",))
                and _contains_any(words, ("authenticat", "tag"))
            ):
                fail(f"Blob documentation {surface} contradiction is present")

    for normalized, words in _documentation_sentence_text(prose["runbook"]):
        result_before_promotion = re.search(
            r"\b(?:result|ack)\b.{0,80}\b(?:before|prior to)\b.{0,80}\bpromotion\b",
            normalized,
        )
        promotion_after_result = re.search(
            r"\bpromotion\b.{0,40}\b(?:follows|after)\b.{0,40}\b(?:result|ack)\b",
            normalized,
        )
        if result_before_promotion or promotion_after_result:
            fail("Blob documentation receiver settlement contradiction is present")
        if (
            "receipt" in words
            and bool(words & {"durable", "resume", "checkpoint", "authority", "key"})
        ):
            fail("Blob documentation durable resume authority contradiction is present")
        attempt_subject = r"(?:result_?ack|result\s+ack|eof)"
        settlement_owns_resume = re.search(
            rf"\b{attempt_subject}\b.{{0,80}}\bowns?\b\s+(?!no\b).{{0,40}}\bresume\b",
            normalized,
        )
        settlement_is_resume_authority = re.search(
            rf"\b{attempt_subject}\b.{{0,80}}\bis\b\s+(?:the\s+)?(?:durable\s+)?resume\s+authority\b",
            normalized,
        )
        if settlement_owns_resume or settlement_is_resume_authority:
            fail("Blob documentation attempt settlement authority contradiction is present")
        if (
            bool(words & {"receiver", "receiving", "incoming"})
            and "exact" in words
            and "deadline" in words
        ):
            fail("Blob documentation receiver timeout contradiction is present")

    for words in _documentation_sentences(prose["performance"]):
        if (
            bool(words & {"legacy", "cm4", "2026"})
            and "current" in words
            and bool(words & {"abx1", "batching", "candidate"})
        ):
            fail("Blob documentation legacy performance contradiction is present")

    public_surfaces = (
        "readme",
        "agent_readme",
        "asterctl_readme",
        "selected_blob_api",
        "operator_guide",
        "capability_roadmap",
    )
    for surface in public_surfaces:
        for words in _documentation_sentences(prose[surface]):
            governed = (
                (
                    {"local", "peer"} <= words
                    and not bool(words & {"event", "state", "record"})
                    and _contains_any(words, ("publish", "publicat"))
                )
                or ("blobstatus" in words and bool(words & {"remote", "peer", "convergence"}))
                or ({"cli", "download", "resume"} <= words)
                or (
                    {"blob", "rust", "agent", "asterctl"} <= words
                    and _contains_any(words, ("publish", "publicat", "read"))
                )
            )
            if governed:
                fail(f"Blob documentation {surface} governed claim is outside its capability block")

    for words in _documentation_sentences(prose["blob_publish_man"]):
        if "peer" in words and _contains_any(words, ("publish", "publicat")):
            fail(
                "Blob documentation blob_publish_man governed claim is outside "
                "its capability block"
            )

    for words in _documentation_sentences(prose["blob_read_man"]):
        read_resume_topic = _contains_any(words, ("resume",)) and (
            _contains_any(words, ("download",))
            or {"asterctl", "blob", "read"} <= words
        )
        if read_resume_topic:
            fail(
                "Blob documentation blob_read_man governed claim is outside "
                "its capability block"
            )

    for words in _documentation_sentences(prose["blob_status_man"]):
        if "blobstatus" in words and bool(
            words & {"remote", "peer", "delivery", "convergence"}
        ):
            fail(
                "Blob documentation blob_status_man governed claim is outside "
                "its capability block"
            )

    stale_current_requirements = (
        "current selected offer is `[8, 7, 6, 5, 4, 3, 2, 1]`",
        "selected handshake default/highest semantic version is 8",
        "selected Blob carrier IO requires v7/v8 profile 4",
        "Blob carrier transfer requires semantic v7/v8 profile 4",
        "enter current carrier IO only through the v7/v8 profile-4 stream",
    )
    requirements = prose["requirements_status"]
    stale_current_blob_evidence = (
        "Current v7/v8 profile-4 streaming, semantic-v8 finite custody, bounded "
        "pressure, and GC remain current-code evidence only."
    )
    if stale_current_blob_evidence.lower() in " ".join(requirements.split()).lower():
        fail("Blob documentation requirements_status retains stale selected Blob mechanism")
    for stale in stale_current_requirements:
        if stale.lower() in requirements.lower():
            fail("Blob documentation requirements_status retains stale current-v8 wording")
    for _, words in _documentation_sentence_text(requirements):
        stale_running_node = (
            {"runningnode", "selected", "blobs"} <= words
            and (
                (
                    {"64", "mib", "1024"} <= words
                    and bool(words & {"chunk", "chunks"})
                )
                or ({"capacity", "one", "worker"} <= words)
            )
        )
        stale_profile5_mechanism = (
            {"semantic", "v5"} <= words
            and bool(words & {"stages", "persists", "resumes", "withholds"})
            and ({"16", "kib"} <= words or "prefixes" in words)
        )
        if stale_running_node or stale_profile5_mechanism:
            fail("Blob documentation requirements_status retains stale selected Blob mechanism")


def parse_numeric_declaration(text: str, label: str) -> tuple[int, ...]:
    match = re.search(rf"^{re.escape(label)}:\s*([^\n]+)$", text, re.MULTILINE)
    if match is None:
        fail(f"{label} declaration is missing")
    body = re.sub(r"[A-Za-z_]+\d+[A-Za-z_]*", "", match.group(1))
    return tuple(int(value.replace(",", "")) for value in re.findall(r"\d[\d,]*", body))


def parse_profile_contract(protocol: str) -> None:
    require_once(
        protocol,
        "Blob profile registry: semantic v7/v8 select profile 4; semantic v9 selects profile 5.",
        "Blob profile registry",
    )
    if parse_numeric_declaration(protocol, "Profile 4 limits") != PROFILE4_LIMITS:
        fail("profile 4 limits differ from the executable compatibility bounds")
    expected_profile5 = (
        8_589_934_592,
        8_192,
        16_777_216,
    )
    if parse_numeric_declaration(protocol, "Profile 5 limits") != expected_profile5:
        fail("profile 5 limits differ from the executable streaming bounds")
    expected_sizes = (1_048_576, 1_048_706, 1_048_710, 134_217_728, 2_097_152)
    if parse_numeric_declaration(protocol, "Profile 5 size classes") != expected_sizes:
        fail("profile 5 limits must distinguish segment, record, DATA body, checkpoint, and frame sizes")
    require_once(protocol, f"Profile 5 order: {PROFILE5_PIPELINE}.", "profile 5 grammar")
    require_once(
        protocol,
        f"Profile 5 exact empty transfer: {PROFILE5_EMPTY_PIPELINE}.",
        "profile 5 grammar",
    )


def parse_implementation(core: str) -> None:
    declarations = re.findall(
        r"^pub\(crate\) const SEMANTIC_PROTOCOL_V(\d+): u16 = (\d+);$",
        core,
        re.MULTILINE,
    )
    actual_versions = tuple(sorted(int(name) for name, _ in declarations))
    expected_versions = VERSIONS
    mismatched = [
        int(name) for name, value in declarations if int(name) != int(value)
    ]
    if actual_versions != expected_versions or mismatched:
        missing = tuple(sorted(set(expected_versions) - set(actual_versions)))
        extra = tuple(sorted(set(actual_versions) - set(expected_versions)))
        fail(
            "implementation versions must be exactly 1 through 9 with matching values; "
            f"missing {missing}, extra {extra}, mismatched {tuple(mismatched)}"
        )

    offer_match = re.search(
        r"SUPPORTED_SEMANTIC_PROTOCOL_VERSIONS:\s*&\[u16\]\s*=\s*&\[(.*?)\];",
        core,
        re.DOTALL,
    )
    if offer_match is None:
        fail("implementation default offer declaration is missing")
    offer = tuple(
        int(version)
        for version in re.findall(r"SEMANTIC_PROTOCOL_V(\d+)", offer_match.group(1))
    )
    if offer != DEFAULT_OFFER:
        fail(f"implementation default offer must be {DEFAULT_OFFER}; found {offer}")


def parse_protocol(protocol: str) -> None:
    require_version_sequence(
        protocol,
        r"default and\s+highest-supported semantic-version surfaces report\s+(`\d+`)",
        (DEFAULT_OFFER[0],),
        "protocol highest-supported version",
    )
    for pattern in PROTOCOL_DEFAULT_OFFER_PATTERNS:
        require_version_sequence(
            protocol, pattern, DEFAULT_OFFER, "protocol default offer"
        )
    require_version_sequence(
        protocol,
        r"current handshake negotiates\s+semantic versions\s+(.+?)\s+and the complete suite",
        DEFAULT_OFFER,
        "protocol negotiated versions",
    )

    rows = {
        int(version): (inheritance.strip(), mechanics.strip())
        for version, inheritance, mechanics in re.findall(
            r"^\| `(\d+)` \| ([^|]+) \| ([^|]+) \|$",
            protocol,
            re.MULTILINE,
        )
    }
    actual_versions = tuple(sorted(rows))
    if actual_versions != VERSIONS:
        missing = tuple(sorted(set(VERSIONS) - set(actual_versions)))
        extra = tuple(sorted(set(actual_versions) - set(VERSIONS)))
        fail(
            "protocol registry must contain exactly semantic versions 1 through 9; "
            f"missing {missing}, extra {extra}"
        )
    if rows[6][0] != PROTOCOL_ROWS[6][0]:
        fail(
            "protocol v6 inheritance must preserve v5 ordinary lanes byte-for-byte; "
            f"found {rows[6][0]!r}"
        )
    if rows[7][0] != PROTOCOL_ROWS[7][0]:
        fail(
            "protocol v7 inheritance must preserve v6 byte-for-byte; "
            f"found {rows[7][0]!r}"
        )
    if rows[8][0] != PROTOCOL_ROWS[8][0]:
        fail(
            "protocol v8 inheritance must preserve v7 bytes except the lane AAD domain and Blob custody fields; "
            f"found {rows[8][0]!r}"
        )
    if rows[9][0] != PROTOCOL_ROWS[9][0]:
        fail(
            "protocol v9 inheritance must preserve v8 fixed lanes while replacing the Blob profile and legacy chunk kind; "
            f"found {rows[9][0]!r}"
        )
    if rows != PROTOCOL_ROWS:
        fail(f"protocol registry semantics drifted; found {rows!r}")
    parse_profile_contract(protocol)


def parse_envelope(envelope: str) -> None:
    require_version_sequence(
        envelope,
        r"(?m)^- Negotiated semantic versions:\s+default/highest\s+([^\n]+)$",
        DEFAULT_OFFER,
        "envelope version summary",
    )
    require_version_sequence(
        envelope,
        r"default semantic-version list is\s*`\[([^\]]+)\]`",
        DEFAULT_OFFER,
        "envelope default offer",
    )

    match = re.search(
        r"^selected_semantic_version\s+u16\s*=\s*([^\n]+)$",
        envelope,
        re.MULTILINE,
    )
    if match is None:
        fail("envelope selection registry is missing")
    selected = tuple(int(version) for version in re.findall(r"\d+", match.group(1)))
    if selected != VERSIONS:
        fail(f"envelope selection registry must be {VERSIONS}; found {selected}")


def parse_cddl(cddl: str) -> None:
    aliases = {
        int(version): expression.strip()
        for version, expression in re.findall(
            r"^semantic-v(\d+)-object-kind\s*=\s*([^\n]+)$",
            cddl,
            re.MULTILINE,
        )
    }
    actual_versions = tuple(sorted(aliases))
    if actual_versions != VERSIONS:
        missing = tuple(sorted(set(VERSIONS) - set(actual_versions)))
        extra = tuple(sorted(set(actual_versions) - set(VERSIONS)))
        fail(
            "CDDL object-kind aliases must cover exactly semantic versions 1 through 9; "
            f"missing {missing}, extra {extra}"
        )
    if aliases[6] != CDDL_ALIASES[6]:
        fail(
            "CDDL v6 inheritance must reuse the semantic-v5 object-kind registry; "
            f"found {aliases[6]!r}"
        )
    if aliases[7] != CDDL_ALIASES[7]:
        fail(
            "CDDL v7 inheritance must reuse the semantic-v6 object-kind registry; "
            f"found {aliases[7]!r}"
        )
    if aliases[8] != CDDL_ALIASES[8]:
        fail(
            "CDDL v8 inheritance must reuse the semantic-v7 object-kind registry; "
            f"found {aliases[8]!r}"
        )
    if aliases[9] != CDDL_ALIASES[9]:
        fail(
            "CDDL v9 object kinds must exclude the legacy Blob chunk kind; "
            f"found {aliases[9]!r}"
        )
    if aliases != CDDL_ALIASES:
        fail(f"CDDL object-kind registry drifted; found {aliases!r}")
    for declaration in (
        "stream-profile-v5 = stream-open-v1 / stream-source-v1 / stream-accept-v1 / stream-data-v1 / stream-checkpoint-v1 / stream-finish-v1 / stream-result-v1 / stream-result-ack-v1",
        'stream-data-v1 = "ASM\\x01\\xd8" attempt-tuple offset-u64 record-len-u32 astrbs02-record',
        'astrbs02-record = "ASTRBS02" authenticated-segment-header ciphertext-and-tag',
    ):
        require_once(cddl, declaration, "CDDL profile 5 grammar")


def rust_numeric_constants(*sources: str) -> dict[str, int]:
    declarations: dict[str, str] = {}
    for source in sources:
        for name, expression in re.findall(
            r"(?ms)^(?:pub(?:\([^)]*\))?\s+)?const\s+([A-Z][A-Z0-9_]*)\s*(?::[^=]+)?=\s*(.*?);",
            source,
        ):
            declarations.setdefault(name, re.sub(r"//.*", "", expression).strip())
    resolved: dict[str, int] = {}

    def resolve(name: str, stack: tuple[str, ...] = ()) -> int:
        if name in resolved:
            return resolved[name]
        if name in stack or name not in declarations:
            fail(f"executable numeric constant {name} cannot be resolved")
        expression = re.sub(r"\bas\s+(?:u|i|usize)[0-9]*\b", "", declarations[name])
        expression = re.sub(r"\b[a-z_][a-z0-9_]*::", "", expression)
        expression = re.sub(r"(?<=\d)_(?=\d)", "", expression)
        expression = re.sub(r"(?<=\d)(?:u|i)(?:8|16|32|64|128|size)\b", "", expression)
        for dependency in sorted(set(re.findall(r"\b[A-Z][A-Z0-9_]*\b", expression)), key=len, reverse=True):
            expression = re.sub(rf"\b{dependency}\b", str(resolve(dependency, stack + (name,))), expression)
        expression = re.sub(r"\s+", " ", expression).strip()
        try:
            node = ast.parse(expression, mode="eval")
        except SyntaxError as error:
            fail(f"executable numeric constant {name} is not a supported expression: {error}")

        def calculate(value: ast.AST) -> int:
            if isinstance(value, ast.Expression):
                return calculate(value.body)
            if isinstance(value, ast.Constant) and isinstance(value.value, int):
                return value.value
            if isinstance(value, ast.BinOp) and isinstance(value.op, (ast.Add, ast.Sub, ast.Mult, ast.Div, ast.FloorDiv)):
                left, right = calculate(value.left), calculate(value.right)
                if isinstance(value.op, ast.Add):
                    return left + right
                if isinstance(value.op, ast.Sub):
                    return left - right
                if isinstance(value.op, ast.Mult):
                    return left * right
                return left // right
            fail(f"executable numeric constant {name} uses an unsupported expression")
        resolved[name] = calculate(node)
        return resolved[name]

    for name in PROFILE5_LIMIT_NAMES:
        resolve(name)
    return resolved


def validate_executable_profile_contract(
    profile: str,
    application_blob: str,
    core_blob: str,
    core_model: str,
    core_bridge: str,
    core_blob_stream: str,
    stream_transfer: str,
    iroh: str,
    blob_runtime: str,
) -> None:
    values = rust_numeric_constants(
        application_blob,
        core_blob,
        core_model,
        core_bridge,
        core_blob_stream,
        stream_transfer,
        iroh,
    )
    expected = {
        "MAX_SELECTED_BLOB_STREAM_BYTES": 8_589_934_592,
        "MAX_STREAM_AUTHENTICATED_OPEN_BYTES": 401_902,
        "BLOB_STREAM_SEGMENT_BYTES": 1_048_576,
        "BLOB_STREAM_SEGMENT_ENCODED_OVERHEAD_BYTES": 130,
        "PROFILE5_PACK_RECORD_PREFIX_BYTES": 4,
        "PROFILE5_PACK_SEGMENT_RECORD_BYTES": 1_048_706,
        "PROFILE5_PACK_TRANSPORT_FRAME_BYTES": 1_048_710,
        "PROFILE5_MAX_PACK_SEGMENTS": 8_192,
        "PROFILE5_MAX_PACK_WIRE_BYTES": 8_591_032_320,
        "MAX_STREAM_CHECKPOINT_BATCH_BYTES": 134_217_728,
        "DEFAULT_MAX_EXCHANGE_BYTES": 2_097_152,
    }
    if {name: values[name] for name in expected} != expected:
        fail(f"executable profile 5 limits drifted; found {values!r}")
    required_profile_fragments = (
        "BlobRangesStreamV1 = 4",
        "BlobStreamV1 = 5",
        "SEMANTIC_PROTOCOL_V7 | SEMANTIC_PROTOCOL_V8 => Ok(Self::current())",
        "SEMANTIC_PROTOCOL_V9 => Ok(Self::stream_v9())",
        "vec![TransferProfileId::BlobRangesStreamV1 as u16]",
        "vec![TransferProfileId::BlobStreamV1 as u16]",
    )
    if any(fragment not in profile for fragment in required_profile_fragments):
        fail("executable Blob profile registry must bind v7/v8 to profile 4 and v9 to profile 5")
    required_extent_fragments = (
        "MAX_STREAM_EXTENT_BYTES: usize = PROFILE5_PACK_TRANSPORT_FRAME_BYTES",
        "profile5_attempt_bounds_for_extents",
        "8 + MAX_PROTECTED_STREAM_DATA_HEADER_BYTES as u64 + 192",
        "PROFILE5_PACK_TRANSPORT_FRAME_BYTES as u64",
    )
    if any(fragment not in stream_transfer for fragment in required_extent_fragments):
        fail("production DATA admission and attempt bounds must use native pack limits")
    if "let profile_ceiling = blob_pack_wire_len(aster_mesh::MAX_BLOB_STREAM_BYTES)" not in blob_runtime:
        fail("profile 5 receiver ceiling must use the exact native pack wire shape")


def require_source_fragments(label: str, source: str, fragments: tuple[str, ...]) -> None:
    for fragment in fragments:
        if re.sub(r"\s+", " ", fragment) not in source:
            fail(f"executable profile 5 {label} differs at {fragment}")


def decode_transcript_seed(path: Path) -> tuple[bool, list[str]]:
    payload = path.read_bytes()
    if not payload.startswith(b"AST1") or len(payload) < 6 or payload[4] not in (0, 1):
        fail(f"profile 5 transcript seed {path.name} framing differs")
    count, offset = payload[5], 6
    names_by_tag = {tag: name for name, (tag, _) in PROFILE5_RECORDS.items()}
    steps = []
    for _ in range(count):
        if offset + 4 > len(payload):
            fail(f"profile 5 transcript seed {path.name} is truncated")
        length = int.from_bytes(payload[offset:offset + 4], "big")
        offset += 4
        frame = payload[offset:offset + length]
        offset += length
        if len(frame) != length or len(frame) < 5 or frame[:4] != b"ASM\x01":
            fail(f"profile 5 transcript seed {path.name} frame differs")
        name = names_by_tag.get(frame[4])
        if name is None:
            fail(f"profile 5 transcript seed {path.name} tag differs")
        steps.append(name)
    if offset != len(payload):
        fail(f"profile 5 transcript seed {path.name} has trailing bytes")
    return payload[4] == 1, steps


def validate_profile5_schema(
    schema: dict,
    stream_transfer: str,
    blob_runtime: str | None = None,
    root: Path = ROOT,
) -> None:
    if blob_runtime is None:
        blob_runtime = (root / "crates/aster-node/src/runtime/blob_stream.rs").read_text()
    compact_stream = re.sub(r"\s+", " ", stream_transfer)
    compact_blob_runtime = re.sub(r"\s+", " ", blob_runtime)
    if (
        schema.get("format") != "aster-profile5-fixed-binary-v1"
        or schema.get("magic") != "41534d01"
        or schema.get("semantic_version") != 9
        or schema.get("profile_id") != 5
        or schema.get("byte_order") != "big-endian"
    ):
        fail("profile 5 schema identity differs")
    records = schema.get("records")
    if not isinstance(records, list) or len(records) != len(PROFILE5_RECORDS):
        fail("profile 5 schema record set differs")
    encoder_arms = {}
    decoder_arms = {}
    for record in records:
        name = record.get("name")
        if name not in PROFILE5_RECORDS:
            fail("profile 5 schema record name differs")
        tag, fields = PROFILE5_RECORDS[name]
        if record.get("tag") != tag or record.get("fields") != PROFILE5_FIELDS[name]:
            fail(f"profile 5 schema {name} tag or field order differs")
        rust_name = "ResultAck" if name == "ACK" else name.title()
        marker = f"Self::{rust_name}(x) =>"
        encoder = stream_transfer.find("pub(crate) fn encode_for_context")
        start = stream_transfer.find(marker, encoder)
        if start < 0:
            fail(f"executable profile 5 encoder lacks {name}")
        end = stream_transfer.find("\n            Self::", start + len(marker))
        arm = re.sub(r"\s+", " ", stream_transfer[start:end if end >= 0 else None])
        encoder_arms[name] = arm
        if f"o.push(0x{tag:02x})" not in arm:
            fail(f"executable profile 5 {name} tag differs")
        cursor = -1
        for token in PROFILE5_RUST_ORDER[name]:
            token = re.sub(r"\s+", " ", token)
            position = arm.find(token, cursor + 1)
            if position < 0:
                fail(f"executable profile 5 {name} field order differs at {token}")
            cursor = position
        if name == "DATA":
            data_impl = stream_transfer.find("impl StreamDataHeaderV1")
            decoder_start = stream_transfer.find(
                "pub(crate) fn decode_for_context", data_impl
            )
            decode_body = stream_transfer.find(
                "pub(crate) fn decode_body", decoder_start
            )
            decoder_end = stream_transfer.find("impl StreamDataV1", decode_body)
            decoder_source = (
                stream_transfer[decoder_start:decode_body]
                + stream_transfer[decode_body:decoder_end]
            )
        else:
            decoder = stream_transfer.find("pub(crate) fn decode_for_context", encoder)
            tag_marker = f"0x{tag:02x} =>"
            decoder_start = stream_transfer.find(tag_marker, decoder)
            decoder_end = stream_transfer.find("\n            0x", decoder_start + len(tag_marker))
            decoder_source = stream_transfer[decoder_start:decoder_end if decoder_end >= 0 else None]
        if decoder_start < 0:
            fail(f"executable profile 5 decoder lacks {name}")
        decoder_arm = re.sub(r"\s+", " ", decoder_source)
        decoder_arms[name] = decoder_arm
        cursor = -1
        for token in PROFILE5_RUST_DECODE_ORDER[name]:
            token = re.sub(r"\s+", " ", token)
            position = decoder_arm.find(token, cursor + 1)
            if position < 0:
                fail(f"executable profile 5 {name} decoder field order differs at {token}")
            cursor = position
    encoder_validators = {
        "OPEN": (
            "nonce(&x.attempt_nonce)?",
            "validate_profile5_wire_len(x.total_len)?",
            "x.source_len == 0",
            "length > MAX_STREAM_AUTHENTICATED_OPEN_BYTES",
            "match x.custody_digest",
            "None => o.push(0)",
            "Some(d) => { o.push(1)",
        ),
        "SOURCE": ("nonce(&x.attempt_nonce)?", "x.bytes.is_empty()", "x.bytes.len() > PROFILE5_SOURCE_CHUNK_BYTES", "x.total_len == 0", "length > MAX_STREAM_AUTHENTICATED_OPEN_BYTES", "x.offset .checked_add", "end > x.total_len"),
        "ACCEPT": ("nonce(&x.attempt_nonce)?", "extent(x.max_extent_bytes)?", "x.absolute_receive_limit < x.durable_offset", "x.checkpoint_batch_bytes == 0", "x.checkpoint_batch_bytes > MAX_STREAM_CHECKPOINT_BATCH_BYTES"),
        "DATA": ("nonce(&x.attempt_nonce)?", "u32::try_from(x.bytes.len())", "extent(l)?", "x.offset .checked_add"),
        "CHECKPOINT": ("nonce(&x.attempt_nonce)?", "x.absolute_receive_limit < x.durable_offset"),
        "FINISH": ("nonce(&x.attempt_nonce)?", "validate_semantic_commitment(&x.semantic_commitment)?", "u32::try_from(x.semantic_commitment.len())"),
        "RESULT": ("nonce(&x.attempt_nonce)?", "o.push(x.code as u8)"),
        "ACK": ("nonce(&x.attempt_nonce)?",),
    }
    decoder_validators = {
        "OPEN": ("StreamClass::decode(r.u8()?)?", "StreamDirection::decode(r.u8()?)?", "r.u16() != Ok(9)", "r.u16() != Ok(5)", "validate_profile5_wire_len(total_len)?", "nonce(&attempt_nonce)?", "0 => None", "1 => Some(r.array()?)", "source_len == 0", "length > MAX_STREAM_AUTHENTICATED_OPEN_BYTES"),
        "SOURCE": ("r.attempt()?", "chunk_len == 0", "chunk_len > PROFILE5_SOURCE_CHUNK_BYTES", "total_len == 0", "length > MAX_STREAM_AUTHENTICATED_OPEN_BYTES", "offset .checked_add", "end > total_len", "r.take(chunk_len)?"),
        "ACCEPT": ("r.attempt()?", "extent(x.max_extent_bytes)?", "x.absolute_receive_limit < x.durable_offset", "x.checkpoint_batch_bytes == 0", "x.checkpoint_batch_bytes > MAX_STREAM_CHECKPOINT_BATCH_BYTES"),
        "DATA": ("r.attempt()?", "extent(extent_len)?", "offset .checked_add", "b.len() != self.extent_len as usize"),
        "CHECKPOINT": ("r.attempt()?", "x.absolute_receive_limit < x.durable_offset"),
        "FINISH": ("r.attempt()?", "commitment_len == 0", "commitment_len > MAX_STREAM_SEMANTIC_COMMITMENT_BYTES", "r.take(commitment_len)?"),
        "RESULT": ("r.attempt()?", "StreamResultCode::decode(r.u8()?)?"),
        "ACK": ("r.attempt()?",),
    }
    for name in PROFILE5_RECORDS:
        require_source_fragments(f"{name} encoder validator", encoder_arms[name], encoder_validators[name])
        require_source_fragments(f"{name} decoder validator", decoder_arms[name], decoder_validators[name])
    require_source_fragments("enum wire mappings", compact_stream, (
        "pub(crate) enum StreamClass { Blob = 1, }",
        "(v == 1) .then_some(Self::Blob)",
        "pub(crate) enum StreamDirection { ToSessionInitiator = 1, ToSessionResponder = 2, }",
        "1 => Ok(Self::ToSessionInitiator), 2 => Ok(Self::ToSessionResponder)",
        "pub(crate) enum StreamResultCode { Promoted = 1, AlreadyPresent = 2, DeferredCapacity = 3, RetiredExpired = 4, RejectedPolicy = 5, IntegrityFailure = 6, }",
        "1 => Ok(Self::Promoted), 2 => Ok(Self::AlreadyPresent), 3 => Ok(Self::DeferredCapacity), 4 => Ok(Self::RetiredExpired), 5 => Ok(Self::RejectedPolicy), 6 => Ok(Self::IntegrityFailure)",
    ))
    require_source_fragments("shared validators", compact_stream, (
        "fn nonce(v: &[u8; 32]) -> Result<(), StreamError> { if v.iter().all(|b| *b == 0)",
        "fn extent(v: u32) -> Result<(), StreamError> { if v == 0 || v as usize > MAX_STREAM_EXTENT_BYTES",
        "validate_semantic_commitment_with_max(bytes, MAX_STREAM_SEMANTIC_COMMITMENT_BYTES)",
        "if max_bytes == 0 || bytes.is_empty() || bytes.len() > max_bytes",
        "if bytes <= PROFILE5_MAX_PACK_WIRE_BYTES",
        "if self.o == self.b.len()",
    ))
    if compact_stream.count("if max_bytes == 0 || bytes.is_empty() || bytes.len() > max_bytes") != 2:
        fail("executable profile 5 bounded byte validators differ")
    if schema.get("attempt_fields") != PROFILE5_ATTEMPT_FIELDS:
        fail("profile 5 nested attempt tuple differs")
    source_object = schema.get("source_object", {})
    semantic_publication = source_object.get("semantic_publication", {})
    physical_source = source_object.get("physical_source", {})
    source_identity = source_object.get("identity", {})
    if (
        source_object.get("magic") != "4153545250533032"
        or source_object.get("format_version") != 2
        or source_object.get("max_encoded_bytes") != 401_902
        or semantic_publication.get("magic") != "4153545242503032"
        or semantic_publication.get("format_version") != 2
        or semantic_publication.get("authenticated") is not True
        or physical_source.get("magic") != "4153545250503032"
        or physical_source.get("format_version") != 2
        or source_identity.get("transfer_id") != "sha256(ASTRPS02)"
        or source_identity.get("publication_id")
        != "sha256(authenticated-ASTRBP02)"
        or source_identity.get("finish")
        != "byte-equal-authenticated-physical-commitment"
    ):
        fail("profile 5 ASTRPS02 source schema differs")
    core_blob_stream = (root / "crates/aster-core/src/blob_stream.rs").read_text()
    require_source_fragments("ASTRPS02 core format", core_blob_stream, (
        'BLOB_STREAM_PUBLICATION_MAGIC: &[u8; 8] = b"ASTRBP02"',
        'BLOB_STREAM_PHYSICAL_SOURCE_MAGIC: &[u8; 8] = b"ASTRPP02"',
        'BLOB_STREAM_PUBLICATION_SOURCE_MAGIC: &[u8; 8] = b"ASTRPS02"',
        "pub const MAX_BLOB_STREAM_PUBLICATION_SOURCE_BYTES: usize",
        "MAX_AUTHENTICATED_BLOB_STREAM_PUBLICATION_BYTES",
        "MAX_AUTHENTICATED_BLOB_STREAM_OPEN_BYTES",
        "MAX_AUTHENTICATED_BLOB_STREAM_COMMITMENT_BYTES",
    ))
    for start_marker, end_marker, tokens in (
        ("fn put_attempt", "impl StreamFrame", ["o.extend_from_slice(id)", "o.extend_from_slice(n)", "s.to_be_bytes()"]),
        ("fn attempt(&mut self)", "fn finish(self)", ["let id = self.array()?", "let n = self.array()?", "nonce(&n)?", "Ok((id, n, self.u64()?))"]),
    ):
        start = compact_stream.find(start_marker)
        end = compact_stream.find(end_marker, start)
        cursor = start
        if start < 0 or end < 0:
            fail("executable profile 5 nested attempt tuple differs")
        for token in tokens:
            position = compact_stream.find(token, cursor, end)
            if position < 0:
                fail("executable profile 5 nested attempt tuple differs")
            cursor = position
    native_pack = schema.get("native_pack_record", {})
    if (
        native_pack.get("magic") != "4153545242533032"
        or native_pack.get("max_encoded_bytes") != 1_048_710
    ):
        fail("profile 5 native pack schema differs")
    if native_pack.get("fields") != PROFILE5_PACK_FIELDS:
        fail("profile 5 native pack fields or bounds differ")
    require_source_fragments("native pack constants", compact_stream, (
        "PROFILE5_PACK_SEGMENT_RECORD_BYTES",
        "PROFILE5_PACK_TRANSPORT_FRAME_BYTES",
    ))
    require_source_fragments("native pack parser", compact_blob_runtime, (
        "if encoded_len == 0",
        "encoded_len > aster_mesh::BLOB_STREAM_SEGMENT_BYTES + aster_mesh::BLOB_STREAM_SEGMENT_ENCODED_OVERHEAD_BYTES",
        "let record_len = encoded_len .checked_add(4)",
        ".open_encoded(&record[4..])",
    ))
    composite = schema.get("composite", {})
    if composite.get("magic") != "41534431" or composite.get("max_encoded_bytes") != 1_050_766:
        fail("profile 5 ASD1 composite schema differs")
    if composite.get("fields") != PROFILE5_COMPOSITE_FIELDS:
        fail("profile 5 ASD1 fields or bounds differ")
    composite_start = compact_stream.find("const COMPOSITE_DATA_MAGIC")
    composite_end = compact_stream.find("fn decode_data", composite_start)
    composite_source = compact_stream[composite_start:composite_end]
    for fragment in (
        'COMPOSITE_DATA_MAGIC: &[u8; 4] = b"ASD1"',
        "protected_header.is_empty()",
        "protected_header.len() > MAX_PROTECTED_STREAM_DATA_HEADER_BYTES",
        "u32::try_from(protected_header.len())", "output.extend_from_slice(protected_header)",
        "&bytes[..4] != COMPOSITE_DATA_MAGIC", "bytes[4..8]", "protected_len == 0",
        "protected_len > MAX_PROTECTED_STREAM_DATA_HEADER_BYTES", "&bytes[8..body_offset]",
        "&bytes[body_offset..]",
    ):
        if fragment not in composite_source:
            fail(f"executable profile 5 ASD1 validator differs at {fragment}")
    if schema.get("flow") != PROFILE5_FLOWS:
        fail("profile 5 empty or nonempty flow differs")
    seed_root = root / "fuzz/corpus/stream_transfer_decode"
    expected_seed_flows = {
        "profile5-transcript-nonempty.bin": schema["flow"]["nonempty"][1:],
        "profile5-transcript-empty.bin": schema["flow"]["empty"][1:],
    }
    for seed_name, expected_steps in expected_seed_flows.items():
        accepted, steps = decode_transcript_seed(seed_root / seed_name)
        if not accepted or steps != expected_steps:
            fail(f"profile 5 {seed_name} flow differs from schema")
    rejected = [
        decode_transcript_seed(path)[0]
        for path in seed_root.glob("profile5-transcript-reject-*.bin")
    ]
    if len(rejected) != 4 or any(rejected):
        fail("profile 5 rejected transcript branch corpus differs")
    require_source_fragments("flow state model", compact_stream, (
        "phase = Phase::Data", "phase = Phase::Finished", "phase = Phase::Result",
        "phase = Phase::Terminal", "phase == Phase::Terminal",
        "drive_fuzz_transcript(&frames), model_fuzz_transcript(&frames)",
        "model_fuzz_transcript(&frames), expected",
        "drive_fuzz_transcript(&frames), expected",
        "sender.accept(value.clone())", "receiver.data(value)",
        "sender.checkpoint(value.clone())", "receiver.finish(value.clone())",
        "sender.result(value.clone())", "receiver.result_ack(",
    ))
    if stream_transfer.count("validate_profile5_wire_len(x.total_len)?") != 1 or stream_transfer.count("validate_profile5_wire_len(total_len)?") != 1:
        fail("profile 5 OPEN encoder/decoder wire bound differs")
    if "bytes <= PROFILE5_MAX_PACK_WIRE_BYTES" not in stream_transfer:
        fail("profile 5 OPEN native pack wire bound differs")
    result = next(record for record in records if record["name"] == "RESULT")
    if dict(result["fields"])["result_code"] != "u8-enum:1,2,3,4,5,6":
        fail("profile 5 result-code enum differs")


def validate_profile5_oracle(root: Path = ROOT) -> None:
    result = subprocess.run(
        [sys.executable, str(root / "conformance/blob_stream_oracle.py")],
        cwd=root, capture_output=True, text=True,
    )
    if result.returncode != 0:
        fail(f"profile 5 oracle/vectors drifted: {result.stderr.strip() or result.stdout.strip()}")


def validate_profile5_runtime_flow(root: Path = ROOT) -> None:
    result = subprocess.run(
        [
            "cargo", "test", "-p", "aster-node", "--features", "fuzzing",
            "transcript_seed_expectations_match_model_and_production_states", "--", "--nocapture",
        ],
        cwd=root, capture_output=True, text=True,
    )
    if result.returncode != 0:
        fail(
            "profile 5 production transcript conformance failed: "
            + (result.stderr.strip() or result.stdout.strip())
        )


def validate_contract_texts(
    core: str, protocol: str, envelope: str, cddl: str
) -> None:
    parse_implementation(core)
    parse_protocol(protocol)
    parse_envelope(envelope)
    parse_cddl(cddl)


def main() -> int:
    try:
        validate_contract_texts(
            (ROOT / "crates/aster-core/src/crypto.rs").read_text(),
            (ROOT / "docs/protocol.md").read_text(),
            (ROOT / "docs/envelope.md").read_text(),
            (ROOT / "docs/wire.cddl").read_text(),
        )
        validate_executable_profile_contract(
            (ROOT / "crates/aster-core/src/transfer_profile.rs").read_text(),
            (ROOT / "crates/aster-node/src/application/blob.rs").read_text(),
            (ROOT / "crates/aster-core/src/blob.rs").read_text(),
            (ROOT / "crates/aster-core/src/model.rs").read_text(),
            (ROOT / "crates/aster-core/src/bridge.rs").read_text(),
            (ROOT / "crates/aster-core/src/blob_stream.rs").read_text(),
            (ROOT / "crates/aster-node/src/stream_transfer.rs").read_text(),
            (ROOT / "crates/aster-iroh/src/lib.rs").read_text(),
            (ROOT / "crates/aster-node/src/runtime/blob_stream.rs").read_text(),
        )
        validate_profile5_schema(
            json.loads((ROOT / "conformance/profile5-wire-schema.json").read_text()),
            (ROOT / "crates/aster-node/src/stream_transfer.rs").read_text(),
            (ROOT / "crates/aster-node/src/runtime/blob_stream.rs").read_text(),
        )
        validate_profile5_oracle()
        validate_profile5_runtime_flow()
        validate_blob_documentation_contract(
            {
                "runbook": (
                    ROOT / "docs/validation/blob-streaming-engineering-runbook.md"
                ).read_text(),
                "readme": (ROOT / "README.md").read_text(),
                "agent_readme": (
                    ROOT / "crates/aster-agent/README.md"
                ).read_text(),
                "asterctl_readme": (
                    ROOT / "crates/asterctl/README.md"
                ).read_text(),
                "selected_blob_api": (
                    ROOT / "docs/quickstart/selected-blob-api.md"
                ).read_text(),
                "operator_guide": (ROOT / "docs/operator-guide.md").read_text(),
                "capability_roadmap": (
                    ROOT / "docs/validation/capability-roadmap.md"
                ).read_text(),
                "node_api": (ROOT / "crates/aster-node/src/lib.rs").read_text(),
                "transports": (ROOT / "docs/transports.md").read_text(),
                "recipes": (ROOT / "docs/application-recipes.md").read_text(),
                "performance": (
                    ROOT / "docs/validation/blob-streaming-performance.md"
                ).read_text(),
                "requirements_status": (
                    ROOT / "docs/validation/requirements-status.md"
                ).read_text(),
                "blob_publish_man": (
                    ROOT / "crates/asterctl/asterctl-blob-publish.1"
                ).read_text(),
                "blob_read_man": (
                    ROOT / "crates/asterctl/asterctl-blob-read.1"
                ).read_text(),
                "blob_status_man": (
                    ROOT / "crates/asterctl/asterctl-blob-status.1"
                ).read_text(),
            }
        )
    except (ContractViolation, OSError) as error:
        print(f"protocol version contract check failed: {error}", file=sys.stderr)
        return 1
    print("protocol version contract check passed: semantic versions 1 through 9 align")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
