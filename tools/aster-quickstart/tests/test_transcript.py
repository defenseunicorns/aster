from __future__ import annotations

import json
import shlex
import threading
import time
import unittest

from aster_quickstart.transcript import TranscriptJournal


class TranscriptJournalTests(unittest.TestCase):
    def test_command_copy_uses_exact_shell_quoted_argv_and_ids_are_monotonic(self):
        journal = TranscriptJournal()

        first = journal.start_command(
            "publisher", ["asterctl", "publish", "two words", "quote'"], cwd="/work"
        )
        second = journal.start_command("receiver", ["asterctl", "query"], cwd="/work")
        first.finish(0, outcome="ok")

        entries = journal.snapshot()
        self.assertEqual([entry["id"] for entry in entries], [1, 2])
        self.assertEqual(entries[0]["command"], "asterctl publish 'two words' 'quote'\"'\"''")
        self.assertEqual(entries[0]["outcome"], "ok")
        self.assertEqual(entries[0]["returncode"], 0)
        self.assertTrue(entries[0]["replayable"])

    def test_registered_secrets_and_sensitive_options_are_redacted_before_retention(self):
        journal = TranscriptJournal()
        journal.register_secret("registered-secret")
        handle = journal.start_command(
            "authentication",
            [
                "aster-agent",
                "--token",
                "option-secret",
                "--password=second-secret",
                "registered-secret",
            ],
            cwd="/work",
            stdin=b"registered-secret",
            sensitive_values=("option-secret",),
        )
        handle.update(
            stdout=b"registered-secret option-secret second-secret",
            stderr=b"registered-secret",
        )

        entry = journal.snapshot()[0]
        displayed = json.dumps(entry)
        self.assertNotIn("registered-secret", displayed)
        self.assertNotIn("option-secret", displayed)
        self.assertNotIn("second-secret", displayed)
        self.assertEqual(
            entry["command"],
            "aster-agent --token '<redacted:argument>' '--password=<redacted:argument>' '<redacted:argument>'",
        )
        self.assertEqual(entry["stdin"], "<redacted:secret>")
        self.assertEqual(entry["stdout"], "<redacted:secret> <redacted:secret> <redacted:secret>")
        self.assertEqual(entry["stderr"], "<redacted:secret>")
        self.assertFalse(entry["replayable"])

    def test_authorization_header_argv_is_redacted_and_non_replayable(self):
        raw_secret = "RAW-'TOKEN"
        header = f"Authorization: Bearer {raw_secret}"
        forms = (
            ["curl", "-H", header],
            ["curl", f"-H{header}"],
            ["curl", f"--header={header}"],
            ["curl", "--header", header],
        )

        for argv in forms:
            with self.subTest(argv=argv):
                journal = TranscriptJournal()
                handle = journal.start_command("authentication", argv, cwd="/work")
                journal.register_secret("later-secret")

                entry = journal.snapshot()[0]
                self.assertNotIn(raw_secret, json.dumps(entry))
                self.assertNotIn(raw_secret, handle._entry.argv)
                self.assertIn("<redacted:argument>", entry["command"])
                self.assertFalse(entry["replayable"])
                self.assertNotIn(b"<redacted:argument>", journal._secrets)

    def test_registering_a_late_generated_secret_scrubs_existing_retained_output(self):
        journal = TranscriptJournal()
        handle = journal.start_command("authentication", ["aster-agent"], cwd="/work")
        handle.update(stdout=b"late-generated-secret")

        journal.register_secret("late-generated-secret")

        entry = journal.snapshot()[0]
        self.assertNotIn("late-generated-secret", json.dumps(entry))
        self.assertEqual(entry["stdout"], "<redacted:secret>")

    def test_late_secret_registration_regenerates_shell_quoted_command_and_finish_outcome(self):
        journal = TranscriptJournal()
        handle = journal.start_command(
            "authentication", ["aster-agent", "late'secret"], cwd="/work"
        )
        journal.register_secret("late'secret")
        handle.finish(1, outcome="failed: late'secret")

        entry = journal.snapshot()[0]
        self.assertNotIn("late'secret", json.dumps(entry))
        self.assertEqual(entry["command"], "aster-agent '<redacted:argument>'")
        self.assertEqual(entry["outcome"], "failed: <redacted:secret>")
        self.assertFalse(entry["replayable"])
        self.assertEqual(handle._entry.argv, ["aster-agent", "<redacted:argument>"])

    def test_sanitizing_historical_snapshot_uses_current_structured_argv(self):
        journal = TranscriptJournal()
        secret = "late'secret $(still-data)"
        journal.start_command(
            "authentication", ["aster-agent", secret, "safe"], cwd="/work"
        )
        historical = journal.snapshot()

        journal.register_secret(secret)

        [sanitized] = journal.sanitize_snapshot(historical)
        self.assertNotIn(secret, json.dumps(sanitized))
        self.assertNotIn(secret, shlex.split(sanitized["command"]))
        self.assertEqual(
            shlex.split(sanitized["command"]),
            ["aster-agent", "<redacted:argument>", "safe"],
        )
        self.assertFalse(sanitized["replayable"])

    def test_sanitizing_evicted_historical_command_recovers_its_structured_argv(self):
        journal = TranscriptJournal(max_entries=1)
        secret = "late'secret $(still-data)"
        journal.start_command(
            "authentication", ["aster-agent", secret, "safe"], cwd="/work"
        )
        historical = journal.snapshot()
        journal.record_internal(
            "workspace", "ready", outcome="succeeded", detail="done", duration_ms=0
        )

        journal.register_secret(secret)

        [sanitized] = journal.sanitize_snapshot(historical)
        self.assertNotIn(secret, json.dumps(sanitized))
        self.assertEqual(
            shlex.split(sanitized["command"]),
            ["aster-agent", "<redacted:argument>", "safe"],
        )
        self.assertFalse(sanitized["replayable"])

    def test_late_secret_scrub_redacts_overlap_between_retained_and_pending_output(self):
        journal = TranscriptJournal()
        journal.register_secret(b"abcde")
        handle = journal.start_command("authentication", ["aster-agent"], cwd="/work")
        handle.update(stdout=b"prefixabc")

        journal.register_secret(b"prefixabc")
        handle.finish(0, outcome="succeeded")

        [entry] = journal.snapshot()
        self.assertEqual(entry["stdout"], "<redacted:secret>")
        self.assertNotIn("prefixabc", json.dumps(entry))

    def test_registered_secret_is_redacted_from_internal_display_fields(self):
        journal = TranscriptJournal()
        journal.register_secret("internal-secret")

        journal.record_internal(
            "workspace",
            "Create internal-secret workspace",
            outcome="ok",
            detail="internal-secret removed",
            duration_ms=0,
        )

        entry = journal.snapshot()[0]
        self.assertNotIn("internal-secret", json.dumps(entry))
        self.assertEqual(entry["title"], "Create <redacted:secret> workspace")
        self.assertEqual(entry["detail"], "<redacted:secret> removed")

    def test_streams_remain_separate_and_non_utf8_bytes_use_replacement(self):
        journal = TranscriptJournal()
        handle = journal.start_command(
            "event", ["asterctl", "publish"], cwd="/work", stdin=b"input"
        )
        handle.update(stdout=b"out\xff", stderr=b"err\xfe")

        entry = journal.snapshot()[0]
        self.assertEqual(entry["stdin"], "input")
        self.assertEqual(entry["stdout"], "out\ufffd")
        self.assertEqual(entry["stderr"], "err\ufffd")

    def test_default_stream_bound_keeps_65536_bytes_and_marks_truncation(self):
        journal = TranscriptJournal()
        handle = journal.start_command("event", ["asterctl", "publish"], cwd="/work")
        handle.update(stdout=(b"x" * 65_536) + b"overflow")

        stdout = journal.snapshot()[0]["stdout"]
        self.assertTrue(stdout.startswith("x" * 65_536))
        self.assertEqual(stdout[65_536:], "\n<truncated: 65536 bytes retained>")

    def test_stdin_uses_the_same_65536_byte_bound_and_truncation_marker(self):
        journal = TranscriptJournal()
        journal.start_command(
            "event",
            ["asterctl", "publish"],
            cwd="/work",
            stdin=(b"i" * 65_536) + b"overflow",
        )

        stdin = journal.snapshot()[0]["stdin"]
        self.assertTrue(stdin.startswith("i" * 65_536))
        self.assertEqual(stdin[65_536:], "\n<truncated: 65536 bytes retained>")

    def test_late_stdin_redaction_expansion_preserves_the_configured_byte_bound(self):
        journal = TranscriptJournal(max_stream_bytes=32)
        journal.start_command(
            "event", ["asterctl", "publish"], cwd="/work", stdin=b"x" * 32
        )

        journal.register_secret(b"x")

        stdin = journal.snapshot()[0]["stdin"]
        retained, marker = stdin.split("\n", 1)
        self.assertNotIn("x", retained)
        self.assertLessEqual(len(retained.encode()), 32)
        self.assertEqual(marker, "<truncated: 32 bytes retained>")

    def test_journal_evicts_oldest_entries_without_reusing_identifiers(self):
        journal = TranscriptJournal(max_entries=128)

        for number in range(129):
            journal.record_internal(
                "workspace", f"operation {number}", outcome="ok", detail="completed", duration_ms=0
            )

        entries = journal.snapshot()
        self.assertEqual(len(entries), 128)
        self.assertEqual(entries[0]["id"], 2)
        self.assertEqual(entries[-1]["id"], 129)

    def test_total_serialized_snapshot_budget_evicts_old_evidence(self):
        budget = 300_000
        journal = TranscriptJournal(
            max_entries=128,
            max_stream_bytes=65_536,
            max_total_bytes=budget,
        )

        for number in range(8):
            handle = journal.start_command(
                "event",
                ["asterctl", "publish", str(number)],
                cwd="/work",
                stdin=b"i" * 65_536,
            )
            handle.update(stdout=b"o" * 65_536, stderr=b"e" * 65_536)
            handle.finish(0, outcome="succeeded")

        snapshot = journal.snapshot()
        encoded = json.dumps(snapshot, ensure_ascii=False, separators=(",", ":")).encode()
        self.assertLessEqual(len(encoded), budget)
        self.assertEqual(snapshot[-1]["id"], 8)
        self.assertLess(len(snapshot), 8)

    def test_released_secret_remains_redacted_from_later_output_and_keeps_registry_slot(self):
        journal = TranscriptJournal(max_secrets=2)
        journal.register_secret("first-secret")
        journal.register_secret("second-secret")

        with self.assertRaisesRegex(ValueError, "secret registry is full"):
            journal.register_secret("third-secret")

        journal.release_secret("first-secret")
        with self.assertRaisesRegex(ValueError, "secret registry is full"):
            journal.register_secret("third-secret")

        handle = journal.start_command("authentication", ["aster-agent"], cwd="/work")
        handle.update(stdout=b"first-secret")
        handle.finish(0, outcome="succeeded")

        [entry] = journal.snapshot()
        self.assertNotIn("first-secret", json.dumps(entry))
        self.assertEqual(entry["stdout"], "<redacted:secret>")

    def test_snapshots_are_deep_copied_json_safe_views(self):
        journal = TranscriptJournal()
        handle = journal.start_command("event", ["asterctl", "publish"], cwd="/work")
        handle.update(stdout=b"original")

        snapshot = journal.snapshot()
        json.dumps(snapshot)
        snapshot[0]["stdout"] = "tampered"
        snapshot.append({"id": 999})

        current = journal.snapshot()
        self.assertEqual(len(current), 1)
        self.assertEqual(current[0]["stdout"], "original")

    def test_observer_can_snapshot_from_another_thread_without_waiting_for_journal_lock(self):
        journal = TranscriptJournal()
        observed_snapshot = threading.Event()
        failures: list[BaseException] = []

        def observer() -> None:
            def take_snapshot() -> None:
                try:
                    journal.snapshot()
                except BaseException as error:  # pragma: no cover - asserted below
                    failures.append(error)
                finally:
                    observed_snapshot.set()

            thread = threading.Thread(target=take_snapshot)
            thread.start()
            self.assertTrue(observed_snapshot.wait(timeout=0.5))
            thread.join(timeout=0.5)

        journal.set_observer(observer)
        journal.start_command("publisher", ["aster-agent"], cwd="/work")

        self.assertEqual(failures, [])

    def test_stream_updates_notify_at_most_ten_times_per_second_but_start_and_finish_are_immediate(self):
        journal = TranscriptJournal(update_interval=0.1)
        notifications: list[str] = []
        journal.set_observer(lambda: notifications.append("changed"))

        handle = journal.start_command("publisher", ["aster-agent"], cwd="/work")
        handle.update(stdout=b"first")
        handle.update(stdout=b"second")
        self.assertEqual(len(notifications), 2)

        time.sleep(0.11)
        handle.update(stdout=b"third")
        self.assertEqual(len(notifications), 3)

        handle.finish(0, outcome="ok")
        self.assertEqual(len(notifications), 4)

    def test_lone_early_output_chunk_is_published_without_finish_or_second_update(self):
        journal = TranscriptJournal(update_interval=0.1)
        observed: list[str] = []
        journal.set_observer(
            lambda: observed.append(journal.snapshot()[0]["stdout"] or "")
        )
        handle = journal.start_command("publisher", ["aster-agent"], cwd="/work")

        handle.update(stdout=b"ready")

        self.assertEqual(observed, ["", "ready"])

    def test_semantic_status_does_not_treat_intentional_sigkill_as_failure(self):
        journal = TranscriptJournal()
        stopped = journal.start_command("publisher", ["aster-agent"], cwd="/work")
        stopped.finish(-9, outcome="stopped")
        failed = journal.start_command("receiver", ["aster-agent"], cwd="/work")
        failed.finish(1, outcome="failed")

        entries = journal.snapshot()
        self.assertEqual(entries[0]["status"], "stopped")
        self.assertEqual(entries[1]["status"], "failed")

    def test_retained_output_ownership_is_a_semantic_failure(self):
        for outcome in ("output pipe retained", "process group retained"):
            with self.subTest(outcome=outcome):
                journal = TranscriptJournal()
                handle = journal.start_command("event", ["asterctl", "publish"], cwd="/work")

                handle.finish(0, outcome=outcome)

                [entry] = journal.snapshot()
                self.assertEqual(entry["status"], "failed")

    def test_update_intervals_below_ten_hertz_are_rejected(self):
        with self.assertRaises(ValueError):
            TranscriptJournal(update_interval=0.01)

    def test_internal_operations_have_no_fake_command(self):
        journal = TranscriptJournal()
        journal.record_internal(
            "cleanup", "Remove temporary workspace", outcome="ok", detail="completed", duration_ms=12
        )

        entry = journal.snapshot()[0]
        self.assertEqual(entry["kind"], "internal")
        self.assertEqual(entry["title"], "Remove temporary workspace")
        self.assertEqual(entry["detail"], "completed")
        self.assertEqual(entry["duration_ms"], 12)
        self.assertIsNone(entry["command"])
        self.assertIsNone(entry["cwd"])
        self.assertIsNone(entry["stdin"])
        self.assertIsNone(entry["stdout"])
        self.assertIsNone(entry["stderr"])
        self.assertIsNone(entry["returncode"])
        self.assertIsNone(entry["replayable"])


if __name__ == "__main__":
    unittest.main()
