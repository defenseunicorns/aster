#!/usr/bin/env python3
# Copyright 2026 Defense Unicorns, Inc.
# SPDX-License-Identifier: Apache-2.0
"""Focused regressions for adopter-facing Blob requirement claims."""

from __future__ import annotations

import importlib.util
import json
from pathlib import Path
import unittest


CHECKER_PATH = Path(__file__).with_name("check-implementation-requirements.py")
SPEC = importlib.util.spec_from_file_location("implementation_requirements", CHECKER_PATH)
if SPEC is None or SPEC.loader is None:
    raise RuntimeError(f"cannot load {CHECKER_PATH}")
CHECKER = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(CHECKER)


class BlobCapabilityDocumentationTests(unittest.TestCase):
    def test_profile5_retired_api_guard_covers_public_core_and_store_surfaces(self) -> None:
        retired = (
            "Profile5CanonicalCheckpoint",
            "Profile5CanonicalWireShape",
            "profile5_canonical_wire_shape",
            "PROFILE5_CANONICAL_",
            "BlobProfile5Receipt",
            "reserve_profile5_receipt",
            "checkpoint_profile5_receipt",
            "resume_profile5_receipt",
            "complete_profile5_receipt",
            "begin_profile5_sender_carrier",
            "begin_profile5_sender_read",
            "read_profile5_sender_carrier",
            "commit_verified_profile5_batch_with_policy",
            "apply_verified_profile5_blob_with_policy",
        )
        for token in retired:
            with self.subTest(token=token), self.assertRaisesRegex(
                ValueError, "legacy carrier concepts remain active"
            ):
                CHECKER.validate_profile5_native_pack_path(
                    active_sources={"retirement-regression.rs": token},
                    active_documentation={},
                )

    def test_profile5_native_pack_guard_covers_stream_transfer_and_active_docs(self) -> None:
        root = CHECKER_PATH.parents[1]
        stream_path = "crates/aster-node/src/stream_transfer.rs"
        docs_path = "docs/transports.md"
        stream = (root / stream_path).read_text()
        docs = (root / docs_path).read_text()

        CHECKER.validate_profile5_native_pack_path(
            active_sources={stream_path: stream},
            active_documentation={docs_path: docs},
        )
        for token in ("ABX1", "ASTRBT01"):
            with self.subTest(surface="stream_transfer", token=token), self.assertRaisesRegex(
                ValueError, "legacy carrier concepts remain active"
            ):
                CHECKER.validate_profile5_native_pack_path(
                    active_sources={stream_path: stream + f'\nconst REGRESSION: &str = "{token}";\n'},
                    active_documentation={docs_path: docs},
                )
            with self.subTest(surface="active_v9_docs", token=token), self.assertRaisesRegex(
                ValueError, "legacy carrier concepts remain active"
            ):
                CHECKER.validate_profile5_native_pack_path(
                    active_sources={stream_path: stream},
                    active_documentation={
                        docs_path: docs
                        + f"\nSemantic-v9 Profile-5 DATA actively carries {token} records.\n"
                    },
                )

        CHECKER.validate_profile5_native_pack_path(
            active_sources={stream_path: stream},
            active_documentation={
                docs_path: docs
                + "\nHistorical semantic-v7/v8 profile-4 used ASTRBT01 and ABX1.\n"
            },
        )
        with self.assertRaisesRegex(ValueError, "legacy carrier concepts remain active"):
            CHECKER.validate_profile5_native_pack_path(
                active_sources={stream_path: stream},
                active_documentation={
                    docs_path: docs
                    + "\nHistorical Profile-4 used ASTRBT01. "
                    "Semantic-v9 Profile-5 actively carries ABX1.\n"
                },
            )
        for mixed_clause in (
            "Historical Profile-4 used ASTRBT01, while semantic-v9 Profile-5 actively carries ABX1.",
            "Unlike legacy ASTRBT01, semantic-v9 Profile-5 actively carries ABX1.",
        ):
            with self.subTest(mixed_clause=mixed_clause), self.assertRaisesRegex(
                ValueError, "legacy carrier concepts remain active"
            ):
                CHECKER.validate_profile5_native_pack_path(
                    active_sources={stream_path: stream},
                    active_documentation={docs_path: docs + "\n" + mixed_clause + "\n"},
                )

    def test_current_capability_boundary_is_required(self) -> None:
        payload = {
            "schema": 1,
            "surface": "capability_roadmap",
            "local_publish_waits_for_peer": False,
            "rust_agent_asterctl_publish_read": "implemented",
            "blob_status_scope": "receiver_local_durable_state",
            "blob_status_reports_remote_delivery_peer_or_convergence": False,
            "cli_download_resume": "post_merge",
        }
        text = f"""<!-- ASTER-BLOB-CAPABILITY:BEGIN -->
```json
{json.dumps(payload, indent=2)}
```
<!-- ASTER-BLOB-CAPABILITY:RENDERED -->
Local Blob publication commits without waiting for a peer. Rust, the native-gRPC agent, and asterctl implement bounded Blob publication and authenticated reads. blob-status reports receiver-local durable state, not remote delivery, peer status, or convergence. CLI download resume is post-merge work; an interrupted download restarts at byte zero.
<!-- ASTER-BLOB-CAPABILITY:END -->
BLE is not implemented. Three-CM4 validation of this candidate has not yet run.
"""
        CHECKER.validate_blob_capability_documentation(text)
        mutations = (
            ("typed capability", '"cli_download_resume": "post_merge"', '"cli_download_resume": "implemented"'),
            ("rendered capability", "commits without waiting", "waits before committing"),
            ("BLE boundary", "BLE is not implemented", "BLE is implemented"),
            ("CM4 evidence boundary", "has not yet run", "passed"),
        )
        for label, old, new in mutations:
            with self.subTest(label=label), self.assertRaisesRegex(
                ValueError, label
            ):
                CHECKER.validate_blob_capability_documentation(
                    text.replace(old, new, 1)
                )

    def test_requirements_totals_are_rendered_from_trace(self) -> None:
        rows = [
            {"id": "DM-1-01", "selected_status": "implemented-uncredited"},
            {"id": "DM-1-02", "selected_status": "observed-bounded"},
            {"id": "DM-2-01", "selected_status": "open"},
        ]
        rendered = CHECKER.render_requirements_totals(rows, 2)
        CHECKER.validate_requirements_totals(rendered, rows, 2)

        for label, damaged in (
            ("totals", rendered.replace("implemented-uncredited=1", "implemented-uncredited=2")),
            ("mapping", rendered.replace("exact-selected-mappings=2", "exact-selected-mappings=1")),
            ("family", rendered.replace("DM-1 | 1 | 1 | 0 | 2", "DM-1 | 0 | 1 | 1 | 2")),
        ):
            with self.subTest(label=label), self.assertRaisesRegex(ValueError, label):
                CHECKER.validate_requirements_totals(damaged, rows, 2)

    def test_duplicate_current_totals_are_rejected(self) -> None:
        rows = [{"id": "DM-1-01", "selected_status": "open"}]
        rendered = CHECKER.render_requirements_totals(rows, 0)
        with self.assertRaisesRegex(ValueError, "exactly one"):
            CHECKER.validate_requirements_totals(rendered + rendered, rows, 0)


if __name__ == "__main__":
    unittest.main()
