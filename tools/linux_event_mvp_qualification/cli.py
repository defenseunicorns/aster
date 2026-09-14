# Copyright 2026 Defense Unicorns, Inc.
# SPDX-License-Identifier: Apache-2.0
"""Public command-line contract for qualification bundle validation."""

from __future__ import annotations

import argparse
from pathlib import Path
import sys
from typing import BinaryIO, Sequence

from .io import canonical_json_bytes
from .validator import BundleInputs, validate_bundle


EXIT_CODES = {"conformant": 0, "nonconformant": 2, "indeterminate": 3}


def parser() -> argparse.ArgumentParser:
    result = argparse.ArgumentParser(
        description="Validate one local Linux Event MVP qualification receipt bundle",
    )
    result.add_argument("--bundle-root", required=True, type=Path)
    result.add_argument("--artifact-root", type=Path)
    result.add_argument("--body", required=True)
    result.add_argument("--index", required=True)
    result.add_argument("--approval", action="append", default=[])
    result.add_argument("--decision", required=True)
    return result


def main(argv: Sequence[str] | None = None, *, stdout: BinaryIO | None = None) -> int:
    destination = stdout if stdout is not None else sys.stdout.buffer
    arguments = parser().parse_args(argv)
    inputs = BundleInputs(
        bundle_root=arguments.bundle_root,
        artifact_root=arguments.artifact_root,
        body=arguments.body,
        index=arguments.index,
        approvals=tuple(arguments.approval),
        decision=arguments.decision,
    )
    try:
        report = validate_bundle(inputs)
        destination.write(report.to_bytes())
        return EXIT_CODES[report.disposition]
    except Exception:  # Fail closed at the public process boundary.
        destination.write(
            canonical_json_bytes({"error": "validator operational failure"})
        )
        return 70
