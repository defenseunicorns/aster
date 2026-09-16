# Copyright 2026 Defense Unicorns, Inc.
# SPDX-License-Identifier: Apache-2.0
"""Exercise platform selection without compiling or executing fuzz targets."""

import os
from pathlib import Path
import subprocess
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
PORTABLE = [
    "wire_decode", "fragment_decode", "envelope_inspect",
    "selected_frame_decode", "selected_negentropy", "classical_profile_decode",
    "systemd_credential_decode",
]
LINUX_ONLY = ["systemd_admin_record_decode", "systemd_backup_decode"]


class FuzzSmokeTests(unittest.TestCase):
    def run_smoke(self, platform, fail_target=""):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            log = root / "calls"
            for name, script in {
                "uname": '#!/bin/sh\nprintf "%s\\n" "$TEST_PLATFORM"\n',
                "cargo": (
                    '#!/bin/sh\nprintf "%s\\n" "$6" >> "$TEST_CALLS"\n'
                    '[ "$6" != "$TEST_FAIL_TARGET" ] || exit 23\n'
                ),
            }.items():
                path = root / name
                path.write_text(script)
                path.chmod(0o700)
            result = subprocess.run(
                ["sh", str(ROOT / "tools/run-fuzz-smoke.sh")],
                env={
                    **os.environ, "PATH": f"{root}:{os.environ['PATH']}",
                    "TMPDIR": str(root), "TEST_PLATFORM": platform,
                    "TEST_CALLS": str(log), "TEST_FAIL_TARGET": fail_target,
                },
                capture_output=True, text=True, timeout=30,
            )
            self.assertFalse(list(root.glob("aster-fuzz-smoke.*")))
            return result, log.read_text().splitlines()

    def test_linux_runs_all_nine_targets(self):
        result, calls = self.run_smoke("Linux")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(calls, PORTABLE + LINUX_ONLY)
        self.assertNotIn("SKIP", result.stdout)

    def test_macos_runs_portable_targets_and_reports_skips(self):
        result, calls = self.run_smoke("Darwin")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(calls, PORTABLE)
        for target in LINUX_ONLY:
            self.assertIn(f"SKIP {target}: requires Linux", result.stdout)

    def test_target_failure_stops_campaigns_and_is_not_a_skip(self):
        for platform, target, expected in (
            ("Darwin", "fragment_decode", PORTABLE[:2]),
            ("Linux", "systemd_admin_record_decode", PORTABLE + LINUX_ONLY[:1]),
        ):
            with self.subTest(platform=platform):
                result, calls = self.run_smoke(platform, target)
                self.assertEqual(result.returncode, 23)
                self.assertEqual(calls, expected)
                self.assertNotIn("SKIP", result.stdout)


if __name__ == "__main__":
    unittest.main()
