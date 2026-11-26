from __future__ import annotations

import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import time
import unittest
from unittest.mock import patch
import warnings

from aster_quickstart.terminal import open_terminal
from aster_quickstart.transcript import TranscriptJournal


class TerminalTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)

    def executable(self, name: str, body: str) -> Path:
        path = self.root / name
        path.write_text(f"#!{sys.executable}\n" + body)
        path.chmod(0o700)
        return path

    def wait_for(self, path: Path) -> None:
        deadline = time.monotonic() + 1
        while time.monotonic() < deadline:
            if path.exists():
                return
            time.sleep(0.01)
        self.fail(f"terminal test process did not create {path}")

    def test_missing_or_unstartable_terminal_falls_back_quickly(self):
        self.assertFalse(
            open_terminal(["observer", "--role", "publisher"], Path("/definitely/missing"))
        )
        with patch("aster_quickstart.terminal.subprocess.Popen", side_effect=OSError):
            self.assertFalse(
                open_terminal(
                    ["observer", "--role", "publisher"],
                    Path("/usr/bin/x-terminal-emulator"),
                )
            )

    def test_launch_uses_only_the_verified_exact_vector_without_a_shell(self):
        with patch("aster_quickstart.terminal.subprocess.Popen") as popen:
            self.assertTrue(
                open_terminal(
                    ["observer", "--role", "publisher", "value; touch bad"],
                    Path("/usr/bin/x-terminal-emulator"),
                )
            )

        popen.assert_called_once_with(
            [
                "/usr/bin/x-terminal-emulator",
                "-e",
                "observer",
                "--role",
                "publisher",
                "value; touch bad",
            ],
            close_fds=True,
            cwd=os.getcwd(),
            start_new_session=True,
        )

    def test_launch_records_the_real_terminal_emulator_spawn_without_owning_its_output(self):
        terminal = self.executable(
            "terminal",
            """import json, os, pathlib, sys, time
path = pathlib.Path(sys.argv[-1])
path.write_text(json.dumps({"argv": sys.argv[1:], "cwd": os.getcwd()}))
time.sleep(0.05)
""",
        )
        observed = self.root / "terminal.json"
        transcript = TranscriptJournal()
        with warnings.catch_warnings():
            warnings.simplefilter("ignore", ResourceWarning)
            self.assertTrue(
                open_terminal(
                    ["observer", "--role", "publisher", str(observed)],
                    terminal,
                    transcript=transcript,
                    transcript_step="publisher",
                )
            )
        self.wait_for(observed)
        time.sleep(0.1)

        [entry] = transcript.snapshot()
        self.assertEqual(
            json.loads(observed.read_text()),
            {
                "argv": ["-e", "observer", "--role", "publisher", str(observed)],
                "cwd": os.getcwd(),
            },
        )
        self.assertEqual(entry["step"], "publisher")
        self.assertEqual(
            entry["command"],
            f"{terminal} -e observer --role publisher {observed}",
        )
        self.assertEqual(entry["cwd"], os.getcwd())
        self.assertEqual(entry["outcome"], "spawned")
        self.assertEqual(entry["stdout"], "")
        self.assertEqual(entry["stderr"], "")
        self.assertIsNone(entry["returncode"])

    def test_real_terminal_spawn_failure_finalizes_the_entry(self):
        terminal = self.root / "unstartable-terminal"
        terminal.write_text("#!/definitely/missing-interpreter\n")
        terminal.chmod(0o700)
        transcript = TranscriptJournal()

        self.assertFalse(
            open_terminal(
                ["observer", "--role", "receiver"],
                terminal,
                transcript=transcript,
                transcript_step="receiver",
            )
        )

        [entry] = transcript.snapshot()
        self.assertEqual(entry["step"], "receiver")
        self.assertEqual(entry["outcome"], "spawn failed")
        self.assertIsNone(entry["returncode"])

    def test_missing_terminal_records_a_visible_failed_entry(self):
        transcript = TranscriptJournal()

        self.assertFalse(
            open_terminal(
                ["observer", "--role", "publisher"],
                Path("/definitely/missing"),
                transcript=transcript,
                transcript_step="publisher",
            )
        )

        [entry] = transcript.snapshot()
        self.assertEqual(entry["outcome"], "launch failed")
        self.assertEqual(entry["status"], "failed")
        self.assertEqual(entry["cwd"], os.getcwd())

    def test_invalid_observer_vector_is_rejected_without_starting_a_process(self):
        for argv in ([], [""], ["observer", "bad\x00value"], ["observer", 7]):
            with self.subTest(argv=argv), patch(
                "aster_quickstart.terminal.subprocess.Popen"
            ) as popen:
                self.assertFalse(open_terminal(argv, Path("/usr/bin/x-terminal-emulator")))
                popen.assert_not_called()


if __name__ == "__main__":
    unittest.main()
