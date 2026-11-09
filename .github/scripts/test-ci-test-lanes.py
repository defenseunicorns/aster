#!/usr/bin/env python3
"""Runtime regression tests for the macOS compatibility runner."""

import os
from pathlib import Path
import subprocess
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[2]
MACOS_COMPATIBILITY = ROOT / "tools/test-macos-compatibility.sh"


class RequiredMacosLaneTests(unittest.TestCase):
    def test_compatibility_runner_rejects_non_macos_hosts_before_cargo(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "uname").write_text("#!/bin/sh\nprintf 'Linux\\n'\n")
            (root / "uname").chmod(0o700)
            cargo_log = root / "cargo-log"
            (root / "cargo").write_text(
                "#!/bin/sh\nprintf '%s\\n' \"$*\" >> \"$CARGO_LOG\"\n"
            )
            (root / "cargo").chmod(0o700)
            result = subprocess.run(
                ["sh", str(MACOS_COMPATIBILITY)],
                cwd=ROOT,
                env={
                    **os.environ,
                    "PATH": directory + os.pathsep + os.environ["PATH"],
                    "CARGO_LOG": str(cargo_log),
                },
                capture_output=True,
                text=True,
                timeout=15,
            )

        self.assertNotEqual(result.returncode, 0)
        self.assertIn("requires macOS", result.stderr)
        self.assertFalse(cargo_log.exists(), "non-macOS host invoked Cargo")

    def test_compatibility_runner_compiles_workspace_and_selects_contracts(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "uname").write_text("#!/bin/sh\nprintf 'Darwin\\n'\n")
            (root / "uname").chmod(0o700)
            cargo_log = root / "cargo-log"
            (root / "cargo").write_text(
                "#!/bin/sh\n"
                "printf '%s|%s\\n' \"${CARGO_TARGET_DIR:-unset}\" "
                "\"$*\" >> \"$CARGO_LOG\"\n"
            )
            (root / "cargo").chmod(0o700)
            result = subprocess.run(
                ["sh", str(MACOS_COMPATIBILITY)],
                cwd=ROOT,
                env={
                    **os.environ,
                    "PATH": directory + os.pathsep + os.environ["PATH"],
                    "CARGO_LOG": str(cargo_log),
                },
                capture_output=True,
                text=True,
                timeout=15,
            )
            commands = cargo_log.read_text().splitlines()

        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(len(commands), 4)
        target_roots = [command.split("|", 1)[0] for command in commands]
        arguments = [command.split("|", 1)[1] for command in commands]
        self.assertTrue(target_roots[0].endswith("/systemd-workspace"))
        self.assertTrue(target_roots[1].endswith("/compose-package"))
        self.assertEqual(target_roots[2:], target_roots[:2])
        self.assertIn(
            "--workspace --all-features --exclude aster-compose-credentials",
            arguments[0],
        )
        self.assertIn("-p aster-compose-credentials --all-features", arguments[1])
        self.assertTrue(all("--no-run" in command for command in arguments[:2]))
        self.assertNotIn("--no-run", arguments[2])
        self.assertNotIn("--no-run", arguments[3])
        self.assertTrue(all("platform_compat_" in command for command in arguments[2:]))
        self.assertIn(
            "--workspace --all-features --exclude aster-compose-credentials",
            arguments[2],
        )
        self.assertIn("-p aster-compose-credentials --all-features", arguments[3])


if __name__ == "__main__":
    unittest.main()
