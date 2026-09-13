# Copyright 2026 Defense Unicorns, Inc.
# SPDX-License-Identifier: Apache-2.0
"""CLI regressions only; these do not execute Docker's context matcher."""
import os
from pathlib import Path
import subprocess
import sys
import unittest

PROBE = Path(__file__).with_name("probe_delivery_docker_context.py")


class DockerContextProbeCliTests(unittest.TestCase):
    def test_help_does_not_require_docker(self):
        result = subprocess.run(
            [sys.executable, str(PROBE), "--help"],
            capture_output=True, text=True, check=False, timeout=10,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("--execute", result.stdout)

    def test_missing_docker_is_explicitly_not_run(self):
        result = subprocess.run(
            [sys.executable, str(PROBE), "--execute"],
            env={**os.environ, "PATH": ""},
            capture_output=True, text=True, check=False, timeout=10,
        )
        self.assertEqual(result.returncode, 77, result.stderr)
        self.assertIn("NOT RUN: Docker CLI unavailable", result.stdout)
        self.assertNotIn("PASS", result.stdout)


if __name__ == "__main__":
    unittest.main()
