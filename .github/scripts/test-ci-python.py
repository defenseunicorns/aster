#!/usr/bin/env python3
"""Fail-closed regression tests for the CI interpreter preflight."""
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

PREFLIGHT = Path(__file__).with_name("check-ci-python.py")


class PreflightTests(unittest.TestCase):
    def test_missing_selection_fails_closed(self):
        env = dict(os.environ)
        env.pop("MISE_PYTHON_VERSION", None)
        result = subprocess.run(
            [sys.executable, str(PREFLIGHT)], env=env,
            capture_output=True, text=True, timeout=15,
        )
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("CI Python preflight failed: missing absolute mise Python path", result.stderr)
        self.assertNotIn("CI Python preflight passed", result.stdout)

    def test_wrong_interpreter_fails_closed(self):
        with tempfile.TemporaryDirectory() as directory:
            prefix = Path(directory)
            (prefix / "bin").mkdir()
            # A real, different executable target, never executed by the probe.
            (prefix / "bin/python3").write_text("not the selected interpreter")
            result = subprocess.run(
                [sys.executable, str(PREFLIGHT)],
                env={**os.environ, "MISE_PYTHON_VERSION": f"path:{prefix}"},
                capture_output=True, text=True, timeout=15,
            )
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("interpreter does not match the mise Python path", result.stderr)
        self.assertNotIn("CI Python preflight passed", result.stdout)

    def test_actual_interpreter_capability(self):
        with tempfile.TemporaryDirectory() as directory:
            prefix = Path(directory)
            (prefix / "bin").mkdir()
            (prefix / "bin/python3").symlink_to(sys.executable)
            result = subprocess.run(
                [sys.executable, str(PREFLIGHT)],
                env={**os.environ, "MISE_PYTHON_VERSION": f"path:{prefix}"},
                capture_output=True, text=True, timeout=15,
            )
        if sys.platform == "linux" and sys.version_info[:3] == (3, 13, 7) and hasattr(os, "POSIX_SPAWN_CLOSEFROM"):
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertIn("CI Python preflight passed", result.stdout)
        else:
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("CI Python preflight failed:", result.stderr)
            self.assertNotIn("CI Python preflight passed", result.stdout)


if __name__ == "__main__":
    unittest.main()
