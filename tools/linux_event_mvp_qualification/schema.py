# Copyright 2026 Defense Unicorns, Inc.
# SPDX-License-Identifier: Apache-2.0
"""Frozen schema identity and exact object-shape helpers."""

from __future__ import annotations

import hashlib
from pathlib import Path
from typing import Any

from .io import load_canonical_json


BODY_SCHEMA_ID = "aster-linux-event-mvp-qualification-machine-schema/v0.1"
BODY_DOCUMENT_SCHEMA = "aster-linux-event-mvp-candidate-body/v0.1"
INDEX_SCHEMA = "aster-linux-event-mvp-receipt-index/v0.1"
APPROVAL_SCHEMA = "aster-linux-event-mvp-candidate-approval/v0.1"
DECISION_SCHEMA = "aster-linux-event-mvp-release-decision/v0.1"
REPORT_SCHEMA_ID = "aster-linux-event-mvp-qualification-validation-report/v0.1"
CANONICALIZATION_ID = "aster-canonical-json-integer-v1"

SCHEMA_PATH = (
    Path(__file__).resolve().parents[2]
    / "docs"
    / "implementation"
    / "schemas"
    / "linux-event-mvp-qualification-v0.1.json"
)
SCHEMA_MAX_BYTES = 1024 * 1024


def load_machine_schema() -> dict[str, Any]:
    return load_canonical_json(
        SCHEMA_PATH.read_bytes(), label="machine schema", maximum=SCHEMA_MAX_BYTES
    )


def machine_schema_digest() -> str:
    return f"sha256:{hashlib.sha256(SCHEMA_PATH.read_bytes()).hexdigest()}"
