# Copyright 2026 Defense Unicorns, Inc.
# SPDX-License-Identifier: Apache-2.0
"""Deterministic sanitized validation result model."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from .io import canonical_json_bytes
from .schema import REPORT_SCHEMA_ID


NON_CLAIM = "structural/profile validation only; not qualification or signature verification"


@dataclass(frozen=True, order=True)
class Finding:
    code: str
    message: str
    field_path: str = "$"
    source: str = "linux-event-mvp-qualification-receipt-validator-spec.md#8"
    unresolved: bool = False

    def to_dict(self) -> dict[str, Any]:
        return {
            "code": self.code,
            "field_path": self.field_path,
            "message": self.message,
            "severity": "unresolved" if self.unresolved else "error",
            "source": self.source,
        }


@dataclass(frozen=True)
class ValidationReport:
    disposition: str
    findings: tuple[Finding, ...]
    checked_bindings: tuple[str, ...]
    body_digest: str | None
    index_digest: str | None
    schema_digest: str
    non_claim: str = NON_CLAIM

    def to_dict(self) -> dict[str, Any]:
        signature_reference_status = (
            "signature-reference-binding-invalid"
            if any(finding.code.startswith("QVS") for finding in self.findings)
            else "signature-reference-present"
        )
        return {
            "body_digest": self.body_digest,
            "candidate_id_uniqueness": "global candidate-ID uniqueness not assessed",
            "checked_bindings": list(self.checked_bindings),
            "disposition": self.disposition,
            "findings": [finding.to_dict() for finding in self.findings],
            "index_digest": self.index_digest,
            "non_claim": self.non_claim,
            "schema_digest": self.schema_digest,
            "signature_authenticity": "not-assessed",
            "signature_reference_status": signature_reference_status,
            "validator_schema": REPORT_SCHEMA_ID,
            "validator_source_identity": "tools/check-linux-event-mvp-qualification.py@v0.1",
        }

    def to_bytes(self) -> bytes:
        return canonical_json_bytes(self.to_dict())


def build_report(
    findings: list[Finding],
    *,
    checked_bindings: set[str],
    body_digest: str | None,
    index_digest: str | None,
    schema_digest: str,
) -> ValidationReport:
    by_location: dict[tuple[str, str], Finding] = {}
    for finding in sorted(
        findings,
        key=lambda item: (
            item.unresolved,
            item.code,
            item.field_path,
            item.message,
            item.source,
        ),
    ):
        by_location.setdefault((finding.code, finding.field_path), finding)
    ordered = tuple(
        sorted(
            by_location.values(),
            key=lambda item: (item.unresolved, item.code, item.field_path),
        )
    )
    if any(not item.unresolved for item in ordered):
        disposition = "nonconformant"
    elif ordered:
        disposition = "indeterminate"
    else:
        disposition = "conformant"
    return ValidationReport(
        disposition=disposition,
        findings=ordered,
        checked_bindings=tuple(sorted(checked_bindings)),
        body_digest=body_digest,
        index_digest=index_digest,
        schema_digest=schema_digest,
    )
