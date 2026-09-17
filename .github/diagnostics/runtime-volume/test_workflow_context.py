# Copyright 2026 Defense Unicorns, Inc.
# SPDX-License-Identifier: Apache-2.0
"""Workflow contracts for the manual runtime-volume harness."""
from pathlib import Path
import unittest


WORKFLOW = Path(__file__).parents[2] / "workflows/diagnostic-runtime-volume.yml"
CI_WORKFLOW = Path(__file__).parents[2] / "workflows/ci.yml"


class WorkflowContext(unittest.TestCase):
    def setUp(self):
        self.text = WORKFLOW.read_text()
        self.ci_text = CI_WORKFLOW.read_text()

    def test_feature_branch_bootstrap_is_manual_only(self):
        guard = (
            "github.event_name == 'workflow_dispatch' && "
            "github.ref == 'refs/heads/ci-runtime-volume-diagnostic'"
        )
        caller = self.ci_text.split("  runtime-volume-diagnostic:\n", 1)[1].split("\n  required:\n", 1)[0]
        required = self.ci_text.split("\n  required:\n", 1)[1]
        self.assertIn(guard, caller)
        self.assertIn("name: Run manual runtime-volume diagnostic", caller)
        self.assertIn("uses: ./.github/workflows/diagnostic-runtime-volume.yml", caller)
        self.assertNotIn("runtime-volume-diagnostic", required)
        self.assertEqual(
            self.ci_text.count("uses: ./.github/workflows/diagnostic-runtime-volume.yml"),
            1,
        )

    def test_standalone_workflow_has_only_manual_entrypoints(self):
        triggers = self.text.split("on:\n", 1)[1].split("\npermissions:\n", 1)[0]
        self.assertIn("workflow_call:", triggers)
        self.assertIn("workflow_dispatch:", triggers)
        for automatic in ("push:", "pull_request:", "merge_group:", "schedule:", "workflow_run:"):
            with self.subTest(automatic=automatic):
                self.assertNotIn(automatic, triggers)

    def test_standalone_workflow_uses_dispatched_sha_without_historical_installer_inputs(self):
        self.assertIn("ref: ${{ github.sha }}", self.text)
        self.assertIn("EXPECTED_SOURCE_SHA: ${{ github.sha }}", self.text)
        self.assertNotIn("14d795390a84d425681d7d40ee4c0e1072be0fb9", self.text)
        self.assertNotIn("reviewed_rustup_sha256", self.text)
        self.assertNotIn("source_admission_receipt_sha256", self.text)
        self.assertNotIn("installer.py", self.text)

    def test_contracts_run_before_the_instrumented_test(self):
        contracts = self.text.index("Validate diagnostic contracts")
        execute = self.text.index("Execute the single instrumented test")
        upload = self.text.index("Retain only sanitized bounded diagnostic evidence")
        self.assertLess(contracts, execute)
        self.assertLess(execute, upload)


if __name__ == "__main__":
    unittest.main()
