from __future__ import annotations

from datetime import datetime, timezone
import threading
import time
import unittest

from aster_quickstart.records import RecordJournal, parse_detail, render_record


class RecordJournalTests(unittest.TestCase):
    def test_records_are_monotonic_bounded_and_report_history_gap(self):
        journal = RecordJournal(limit=2, clock=lambda: datetime(2026, 1, 1, tzinfo=timezone.utc))

        first = journal.emit(action="start", node="publisher", outcome="ok", message="started")
        second = journal.emit(action="ready", node="publisher", outcome="ok", message="ready")
        third = journal.emit(action="stop", node="publisher", outcome="ok", message="stopped")

        self.assertEqual([first.sequence, second.sequence, third.sequence], [1, 2, 3])
        records = journal.records_after(0, timeout=0)
        self.assertEqual([record.sequence for record in records], [1, 2, 3])
        self.assertEqual(records[0].action, "history-gap")
        self.assertEqual(records[0].outcome, "truncated")
        self.assertIn("sequence 2", records[0].message)
        self.assertTrue(render_record(records[0], "compact").startswith("[history-gap]"))

    def test_detail_levels_filter_one_canonical_record(self):
        journal = RecordJournal(clock=lambda: datetime(2026, 1, 1, tzinfo=timezone.utc))
        record = journal.emit(
            action="publish",
            node="publisher",
            outcome="ok",
            message="Event committed",
            explanation="The publisher committed the Event; send another when ready.",
            debug={"event_id": "a" * 64, "pid": 42, "log_name": "quickstart-log"},
        )

        compact = render_record(record, "compact")
        guided = render_record(record, "guided")
        debug = render_record(record, "debug")
        self.assertEqual(compact, "[publish] publisher ok: Event committed")
        self.assertIn(compact, guided)
        self.assertIn(record.explanation, guided)
        self.assertNotIn("a" * 64, guided)
        self.assertIn(record.explanation, debug)
        self.assertIn("event_id=" + ("a" * 64), debug)
        self.assertIn("pid=42", debug)
        self.assertNotIn("event_id=" + ("a" * 64), compact)
        self.assertEqual(parse_detail(" GUIDED "), "guided")
        with self.assertRaises(ValueError):
            parse_detail("verbose")

    def test_emit_rejects_unbounded_or_secret_shaped_fields(self):
        journal = RecordJournal()
        with self.assertRaises(ValueError):
            journal.emit(action="start", node="publisher", outcome="ok", message="x" * 1000)
        with self.assertRaises(ValueError):
            journal.emit(
                action="start",
                node="publisher",
                outcome="ok",
                message="started",
                debug={"client_token": "not-for-display"},
            )
        with self.assertRaises(ValueError):
            journal.emit(
                action="start",
                node="publisher",
                outcome="ok",
                message="password=not-for-display",
            )
        with self.assertRaises(TypeError):
            journal.emit(
                action="start",
                node="publisher",
                outcome="ok",
                message="started",
                debug={"values": {"nested": "no"}},
            )

        for key in ("apiToken", "privateKey", "auth.token"):
            with self.subTest(key=key), self.assertRaises(ValueError):
                journal.emit(
                    action="start",
                    node="publisher",
                    outcome="ok",
                    message="started",
                    debug={key: "credential contents"},
                )
        with self.assertRaises(ValueError):
            journal.emit(
                action="start",
                node="publisher",
                outcome="ok",
                message="started",
                debug={"key_material": "MIIEvQIBADANBgkqhkiG9w0BAQEFAASCQKBgQ"},
            )
        with self.assertRaises(ValueError):
            journal.emit(
                action="start",
                node="publisher",
                outcome="ok",
                message="stdout: child process emitted raw output",
            )
        for field in ("action", "node", "outcome", "message", "explanation"):
            with self.subTest(field=field), self.assertRaises(ValueError):
                values = {
                    "action": "start",
                    "node": "publisher",
                    "outcome": "ok",
                    "message": "started",
                    "explanation": "ready",
                }
                values[field] = (
                    "/tmp/unvalidated/workspace"
                    if field in {"message", "explanation"}
                    else "/tmp/unvalidated/workspace"
                )
                journal.emit(**values)
        with self.assertRaises(ValueError):
            journal.emit(
                action="start",
                node="publisher",
                outcome="ok",
                message="started",
                debug={"path": "/tmp/unvalidated/workspace"},
            )
        for path in ("/", ".", ".."):
            for field in ("action", "node", "outcome", "message", "explanation"):
                with self.subTest(path=path, field=field), self.assertRaises(ValueError):
                    values = {
                        "action": "start",
                        "node": "publisher",
                        "outcome": "ok",
                        "message": "started",
                        "explanation": "ready",
                    }
                    values[field] = path
                    journal.emit(**values)

    def test_debug_contract_accepts_only_bounded_operational_facts(self):
        journal = RecordJournal()
        record = journal.emit(
            action="cleanup",
            node=None,
            outcome="cleaned",
            message="cleaned up",
            debug={
                "operation": "cleanup",
                "event_id": "f" * 64,
                "payload_bytes": 4096,
                "pid": 1,
                "port": 65535,
                "owned_processes": 0,
                "port_reserved": True,
                "socket_closed": True,
                "workspace_removed": True,
                "descriptor_removed": True,
            },
        )
        self.assertEqual(record.debug["event_id"], "f" * 64)
        for key, value in (
            ("event_id", "event-1"),
            ("payload_bytes", 4097),
            ("pid", 0),
            ("port", 65536),
            ("owned_processes", 9),
        ):
            with self.subTest(key=key), self.assertRaises((TypeError, ValueError)):
                journal.emit(
                    action="start",
                    node="publisher",
                    outcome="ok",
                    message="started",
                    debug={key: value},
                )

        class LyingMapping(dict):
            def __len__(self):
                return 0

        too_many = LyingMapping({f"field_{index}": index for index in range(33)})
        with self.assertRaises(ValueError):
            journal.emit(
                action="start",
                node="publisher",
                outcome="ok",
                message="started",
                debug=too_many,
            )

    def test_debug_contract_admits_only_allowlisted_commands_and_confined_paths(self):
        journal = RecordJournal()

        record = journal.emit(
            action="start",
            node="publisher",
            outcome="running",
            message="running",
            debug={
                "command": "aster-agent",
                "confined_path": "logs/node-0/run-17",
            },
        )

        self.assertEqual(record.debug["command"], "aster-agent")
        self.assertEqual(record.debug["confined_path"], "logs/node-0/run-17")
        rendered = render_record(record, "debug")
        self.assertIn("command=aster-agent", rendered)
        self.assertIn("confined_path=logs/node-0/run-17", rendered)
        for key, value in (
            ("command", "sh -c arbitrary"),
            ("command", "aster-agent --token secret"),
            ("confined_path", "/tmp/session/logs/node-0/run-17"),
            ("confined_path", "../logs/node-0/run-17"),
            ("confined_path", "node-0/playground.client.token"),
            ("confined_path", "logs/node-2/run-17"),
        ):
            with self.subTest(key=key, value=value), self.assertRaises(ValueError):
                journal.emit(
                    action="start",
                    node="publisher",
                    outcome="running",
                    message="running",
                    debug={key: value},
                )

    def test_waiter_receives_new_record_without_exposing_mutable_history(self):
        journal = RecordJournal(clock=lambda: datetime(2026, 1, 1, tzinfo=timezone.utc))
        received: list[list] = []

        def wait_for_record():
            received.append(journal.records_after(0, timeout=1))

        waiter = threading.Thread(target=wait_for_record)
        waiter.start()
        time.sleep(0.02)
        source_debug = {"pid": 42}
        emitted = journal.emit(
            action="start",
            node="publisher",
            outcome="ok",
            message="started",
            debug=source_debug,
        )
        source_debug["pid"] = 99
        waiter.join(timeout=1)

        self.assertFalse(waiter.is_alive())
        self.assertEqual(received[0][0], emitted)
        self.assertEqual(received[0][0].debug["pid"], 42)
        with self.assertRaises(TypeError):
            received[0][0].debug["pid"] = 7
        received[0].clear()
        self.assertEqual(journal.records_after(0, timeout=0)[0].debug["pid"], 42)

    def test_closed_display_copy_policy_rejects_arbitrary_child_text(self):
        journal = RecordJournal()
        for field in ("message", "explanation"):
            with self.subTest(field=field), self.assertRaises(ValueError):
                values = {
                    "action": "start",
                    "node": "publisher",
                    "outcome": "ok",
                    "message": "started",
                    "explanation": "ready",
                }
                values[field] = "arbitrary child output"
                journal.emit(**values)

        record = journal.emit(
            action="start",
            node="publisher",
            outcome="ok",
            message="Intentional UI copy",
            explanation="The node is ready for the next action.",
        )
        self.assertEqual(record.message, "Intentional UI copy")
        self.assertEqual(record.explanation, "The node is ready for the next action.")

        with self.assertRaises(ValueError):
            journal.emit(
                action="start",
                node="publisher",
                outcome="ok",
                message="started",
                debug={"event_id": "opaque child line with no marker"},
            )

    def test_closed_structured_fields_reject_arbitrary_text_and_allow_quickstart_facts(self):
        journal = RecordJournal()
        for field in ("action", "node", "outcome"):
            with self.subTest(field=field), self.assertRaises(ValueError):
                values = {
                    "action": "start",
                    "node": "publisher",
                    "outcome": "ok",
                    "message": "started",
                }
                values[field] = "markerless arbitrary child text"
                journal.emit(**values)

        for action, node, outcome in (
            ("initialize", None, "initialized"),
            ("start", "publisher", "started"),
            ("start", "receiver", "running"),
            ("authenticate", None, "authenticated"),
            ("publish", "publisher", "committed"),
            ("receive", "receiver", "received"),
            ("transport", None, "unavailable"),
            ("restore", None, "restored"),
            ("cleanup", None, "cleaned"),
            ("error", None, "failed"),
        ):
            with self.subTest(action=action, node=node, outcome=outcome):
                record = journal.emit(
                    action=action,
                    node=node,
                    outcome=outcome,
                    message="started",
                )
                self.assertEqual((record.action, record.node, record.outcome), (action, node, outcome))

    def test_debug_value_types_match_their_allowlisted_categories(self):
        journal = RecordJournal()

        for debug in (
            {"pid": True},
            {"port": False},
            {"durable": 1},
            {"observed": 0.0},
        ):
            with self.subTest(debug=debug), self.assertRaises(TypeError):
                journal.emit(
                    action="start",
                    node="publisher",
                    outcome="ok",
                    message="started",
                    debug=debug,
                )
        with self.assertRaises(ValueError):
            journal.emit(
                action="start",
                node="publisher",
                outcome="ok",
                message="started",
                debug={"unknown": None},
            )


if __name__ == "__main__":
    unittest.main()
