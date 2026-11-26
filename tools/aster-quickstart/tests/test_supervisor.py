from __future__ import annotations

from copy import deepcopy
import json
import shlex
import threading
import time
import unittest

from aster_quickstart.records import RecordJournal, render_record
from aster_quickstart.aster_session import RecoverableOfflinePublishError
from aster_quickstart.supervisor import (
    EventValidationError,
    QuickstartSupervisor,
    REVISION_HISTORY_BYTES_LIMIT,
    SupervisorBusyError,
    SupervisorStateError,
)
from aster_quickstart.transcript import TranscriptJournal


class FakeSession:
    EVENT_ID = "a" * 64
    OFFLINE_EVENT_ID = "b" * 64

    def __init__(
        self,
        *,
        start_started: threading.Event | None = None,
        start_release: threading.Event | None = None,
    ) -> None:
        self.start_started = start_started
        self.start_release = start_release
        self.initialize_calls = 0
        self.start_calls: list[str] = []
        self.stop_calls: list[str] = []
        self.authenticate_calls = 0
        self.publish_calls: list[str] = []
        self.offline_calls: list[str] = []
        self.close_calls = 0
        self.fail_start = False
        self.fail_authenticate = False
        self.fail_publish = False
        self.fail_close = False

    def initialize(self):
        self.initialize_calls += 1
        return {
            "status": "initialized",
            "nodes": {
                "publisher": {"identity_fingerprint": "a" * 64},
                "receiver": {"identity_fingerprint": "b" * 64},
            },
        }

    def start_node(self, role):
        self.start_calls.append(role)
        if self.start_started is not None:
            self.start_started.set()
        if self.start_release is not None:
            self.start_release.wait(timeout=2)
        if self.fail_start:
            raise RuntimeError("token=/owner-only/credential")
        return {"role": role, "state": "running"}

    def stop_node(self, role):
        self.stop_calls.append(role)
        return {"role": role, "state": "stopped"}

    def authenticate(self, progress=None):
        self.authenticate_calls += 1
        if progress is not None:
            progress({"status": "authenticating"})
        if self.fail_authenticate:
            raise RuntimeError("private-key=/owner-only/credential")
        return {"status": "authenticated", "challenge": "verified"}

    def publish_with_progress(self, text, progress):
        self.publish_calls.append(text)
        if self.fail_publish:
            raise RuntimeError("bearer secret")
        result = self.receipt(self.EVENT_ID, text)
        progress({"commit": result["commit"]})
        return result

    def offline_publish(self, text, progress=None):
        self.offline_calls.append(text)
        result = self.receipt(self.OFFLINE_EVENT_ID, text)
        if progress is not None:
            progress({"availability": "unavailable"})
            progress({"commit": result["commit"]})
            progress({"availability": "available"})
            progress({"receipt": result["receipt"]})
        return result

    def close(self):
        self.close_calls += 1
        if self.fail_close:
            raise RuntimeError("credential=/owner-only/credential")

    @staticmethod
    def receipt(event_id, text):
        return {
            "commit": {
                "event_id": event_id,
                "text": text,
                "status": "committed",
                "durable": True,
                "node": "atlas",
            },
            "receipt": {
                "event_id": event_id,
                "text": text,
                "status": "received",
                "observed": True,
                "node": "beacon",
            },
        }


class TerminalFailureSession(FakeSession):
    """Models an AsterSession that completed terminal cleanup before raising."""

    def __init__(self):
        super().__init__()
        self.unusable = False
        self.fail_terminal_publish = False
        self.fail_terminal_offline = False

    def start_node(self, role):
        self.start_calls.append(role)
        if self.unusable:
            raise RuntimeError("the Aster session is closed")
        return {"role": role, "state": "running"}

    def authenticate(self, progress=None):
        self.authenticate_calls += 1
        if self.unusable:
            raise RuntimeError("the Aster session is closed")
        if progress is not None:
            progress({"status": "authenticating"})
        return {"status": "authenticated", "challenge": "verified"}

    def publish_with_progress(self, text, progress):
        self.publish_calls.append(text)
        if self.fail_terminal_publish:
            self.unusable = True
            raise RuntimeError("the Aster session cleaned up after publication failure")
        result = self.receipt(self.EVENT_ID, text)
        progress({"commit": result["commit"]})
        return result

    def offline_publish(self, text, progress=None):
        self.offline_calls.append(text)
        if self.fail_terminal_offline:
            self.unusable = True
            raise RuntimeError("the Aster session cleaned up after restoration failure")
        return super().offline_publish(text, progress)


class RecoverableOfflineFailureSession(FakeSession):
    """Models the typed session contract after peers have been restored."""

    def offline_publish(self, text, progress=None):
        self.offline_calls.append(text)
        result = self.receipt(self.OFFLINE_EVENT_ID, text)
        if progress is not None:
            progress({"availability": "unavailable"})
            progress({"commit": result["commit"]})
            progress({"availability": "available"})
        raise RecoverableOfflinePublishError("offline experiment failed after contacts were restored")


class EvidenceSession(FakeSession):
    def start_node(self, role):
        receipt = super().start_node(role)
        index = 0 if role == "publisher" else 1
        receipt.update({
            "pid": 500 + index,
            "port": 41_000 + index,
            "command": "aster-agent",
            "confined_path": f"logs/node-{index}/run-{index + 1}",
        })
        return receipt


class QuickstartSupervisorTests(unittest.TestCase):
    def make_supervisor(self, session=None, *, transcript=None):
        session = session or FakeSession()
        records = RecordJournal()
        shutdown_requested = threading.Event()
        return (
            QuickstartSupervisor(session, records, shutdown_requested, transcript=transcript),
            session,
            records,
            shutdown_requested,
        )

    def test_transcript_snapshot_is_seeded_and_observer_revisions_are_ordered(self):
        transcript = TranscriptJournal()
        transcript.record_internal(
            "setup", "Acquire workspace", outcome="succeeded", detail="ready", duration_ms=4
        )
        supervisor, _, _, _ = self.make_supervisor(transcript=transcript)

        seeded = supervisor.snapshot()
        self.assertEqual(seeded["transcript"][0]["title"], "Acquire workspace")
        initial_revision = seeded["revision"]

        transcript.record_internal(
            "publisher", "Start publisher", outcome="running", detail="listening", duration_ms=8
        )

        updates = supervisor.snapshots_after(initial_revision, timeout=0)
        self.assertEqual([state["revision"] for state in updates], sorted(state["revision"] for state in updates))
        self.assertEqual(updates[-1]["transcript"][-1]["title"], "Start publisher")

    def test_transcript_is_immutable_redacted_public_state_and_detaches_after_cleanup(self):
        transcript = TranscriptJournal()
        transcript.register_secret("browser-only-secret")
        command = transcript.start_command(
            "event", ["asterctl", "publish", "browser-only-secret"], cwd="/tmp/work"
        )
        command.update(stdout=b"browser-only-secret")
        command.finish(0, outcome="succeeded")
        supervisor, _, _, _ = self.make_supervisor(transcript=transcript)

        public = supervisor.snapshot()
        encoded = repr(public)
        self.assertNotIn("browser-only-secret", encoded)
        self.assertNotIn("_entries", encoded)
        self.assertIsNot(public["transcript"], transcript.snapshot())

        supervisor.cleanup()
        cleaned = supervisor.snapshot()
        cleaned_revision = cleaned["revision"]
        transcript.record_internal(
            "cleanup", "Late mutation", outcome="failed", detail="must stay private", duration_ms=0
        )

        self.assertEqual(supervisor.snapshot()["revision"], cleaned_revision)
        self.assertNotIn("Late mutation", repr(supervisor.snapshot()))

    def test_transcript_observer_cannot_miss_a_mutation_during_initial_snapshot(self):
        class SnapshotGateJournal(TranscriptJournal):
            def __init__(self):
                super().__init__()
                self.snapshot_taken = threading.Event()
                self.release_snapshot = threading.Event()
                self.block_next_snapshot = False

            def snapshot(self):
                value = super().snapshot()
                if self.block_next_snapshot:
                    self.block_next_snapshot = False
                    self.snapshot_taken.set()
                    self.release_snapshot.wait(timeout=1)
                return value

        transcript = SnapshotGateJournal()
        transcript.record_internal(
            "setup", "A", outcome="succeeded", detail="first", duration_ms=1
        )
        transcript.block_next_snapshot = True
        created: list[QuickstartSupervisor] = []
        creator = threading.Thread(
            target=lambda: created.append(
                QuickstartSupervisor(FakeSession(), RecordJournal(), threading.Event(), transcript=transcript)
            )
        )
        creator.start()
        self.assertTrue(transcript.snapshot_taken.wait(timeout=1))

        mutation = threading.Thread(
            target=lambda: transcript.record_internal(
                "setup", "B", outcome="succeeded", detail="second", duration_ms=1
            )
        )
        mutation.start()
        transcript.release_snapshot.set()
        creator.join(timeout=1)
        mutation.join(timeout=1)

        self.assertFalse(creator.is_alive())
        self.assertFalse(mutation.is_alive())
        self.assertEqual(
            [entry["title"] for entry in created[0].snapshot()["transcript"]],
            ["A", "B"],
        )

    def test_concurrent_transcript_callbacks_cannot_regress_authoritative_snapshot(self):
        class ScheduledSnapshotJournal(TranscriptJournal):
            def __init__(self):
                super().__init__()
                self.snapshots: list[list[dict[str, object]]] = []
                self.schedule: list[int] = []
                self.first_snapshot_taken = threading.Event()
                self.release_first_snapshot = threading.Event()
                self._schedule_lock = threading.Lock()

            def snapshot(self):
                with self._schedule_lock:
                    index = self.schedule.pop(0) if self.schedule else None
                if index is None:
                    return super().snapshot()
                value = deepcopy(self.snapshots[index])
                if index == 0:
                    self.first_snapshot_taken.set()
                    self.release_first_snapshot.wait(timeout=1)
                return value

        transcript = ScheduledSnapshotJournal()
        supervisor, _, _, _ = self.make_supervisor(transcript=transcript)
        transcript.set_observer(None)
        transcript.record_internal("setup", "A", outcome="succeeded", detail="first", duration_ms=1)
        first = transcript.snapshot()
        transcript.record_internal("setup", "B", outcome="succeeded", detail="second", duration_ms=1)
        second = transcript.snapshot()
        transcript.snapshots = [first, second]
        transcript.schedule = [0, 1]

        first_callback = threading.Thread(target=supervisor._on_transcript_changed)
        first_callback.start()
        self.assertTrue(transcript.first_snapshot_taken.wait(timeout=1))
        second_callback = threading.Thread(target=supervisor._on_transcript_changed)
        second_callback.start()
        transcript.release_first_snapshot.set()
        first_callback.join(timeout=1)
        second_callback.join(timeout=1)

        self.assertFalse(first_callback.is_alive())
        self.assertFalse(second_callback.is_alive())
        self.assertEqual(
            [entry["title"] for entry in supervisor.snapshot()["transcript"]],
            ["A", "B"],
        )

    def test_late_transcript_redaction_sanitizes_current_and_retained_revisions(self):
        transcript = TranscriptJournal()
        supervisor, _, _, _ = self.make_supervisor(transcript=transcript)
        secret = "late'secret $(still-data)"
        handle = transcript.start_command(
            "event", ["asterctl", "publish", secret], cwd="/tmp/quickstart"
        )
        command_identifier = supervisor.snapshot()["transcript"][0]["id"]
        handle.update(stdout=secret.encode())
        handle.finish(0, outcome="succeeded")
        before_redaction = supervisor.snapshot()["revision"]

        transcript.register_secret(secret)

        states = supervisor.snapshots_after(0, timeout=0)
        self.assertGreater(supervisor.snapshot()["revision"], before_redaction)
        self.assertTrue(states)
        self.assertTrue(all(secret not in repr(state) for state in states))
        retained_command_versions = [
            entry
            for state in states
            for entry in state["transcript"]
            if entry["id"] == command_identifier
        ]
        self.assertTrue(retained_command_versions)
        self.assertTrue(all(entry["replayable"] is False for entry in retained_command_versions))
        self.assertTrue(
            all(secret not in shlex.split(entry["command"]) for entry in retained_command_versions)
        )
        revision = supervisor.snapshot()["revision"]
        transcript.register_secret("not-present")
        self.assertEqual(supervisor.snapshot()["revision"], revision)

    def test_late_secret_redacts_evicted_retained_revisions_without_a_noop_revision(self):
        transcript = TranscriptJournal(max_entries=1)
        supervisor, _, _, _ = self.make_supervisor(transcript=transcript)
        secret = "evicted-secret"
        handle = transcript.start_command(
            "event", ["asterctl", "publish", secret], cwd="/tmp/quickstart"
        )
        handle.update(stdout=secret.encode())
        handle.finish(0, outcome="succeeded")
        transcript.record_internal("setup", "safe", outcome="succeeded", detail="safe", duration_ms=0)
        revision = supervisor.snapshot()["revision"]

        transcript.register_secret(secret)

        self.assertEqual(supervisor.snapshot()["revision"], revision)
        states = supervisor.snapshots_after(0, timeout=0)
        self.assertTrue(states)
        self.assertTrue(all(secret not in repr(state) for state in states))

    def test_revision_history_has_a_strict_serialized_budget_and_resyncs_after_eviction(self):
        transcript = TranscriptJournal(max_total_bytes=100_000)
        supervisor, _, _, _ = self.make_supervisor(transcript=transcript)
        original_revision = supervisor.snapshot()["revision"]

        for number in range(80):
            transcript.record_internal(
                "setup",
                f"operation {number}",
                outcome="succeeded",
                detail="x" * 25_000,
                duration_ms=number,
            )

        retained_bytes = sum(
            len(json.dumps(state, ensure_ascii=False, separators=(",", ":")).encode())
            for state in supervisor._revision_history
        )
        self.assertLessEqual(retained_bytes, REVISION_HISTORY_BYTES_LIMIT)
        [resync] = supervisor.snapshots_after(original_revision, timeout=0)
        self.assertEqual(resync["stream"]["mode"], "full_resync")
        self.assertEqual(resync["revision"], supervisor.snapshot()["revision"])

    def test_oversized_current_state_resyncs_even_when_no_revision_can_be_retained(self):
        transcript = TranscriptJournal(max_total_bytes=4_000_000)
        supervisor, _, _, _ = self.make_supervisor(transcript=transcript)
        revision = supervisor.snapshot()["revision"]

        transcript.record_internal(
            "setup",
            "oversized operation",
            outcome="succeeded",
            detail="x" * (REVISION_HISTORY_BYTES_LIMIT + 1),
            duration_ms=0,
        )

        self.assertEqual(list(supervisor._revision_history), [])
        [resync] = supervisor.snapshots_after(revision, timeout=0)
        self.assertEqual(resync["stream"]["mode"], "full_resync")
        self.assertEqual(resync["revision"], supervisor.snapshot()["revision"])

    def test_ordinary_transcript_updates_preserve_retained_revision_chronology(self):
        transcript = TranscriptJournal()
        supervisor, _, _, _ = self.make_supervisor(transcript=transcript)
        initial_revision = supervisor.snapshot()["revision"]

        transcript.record_internal(
            "setup", "A", outcome="succeeded", detail="first", duration_ms=1
        )
        transcript.record_internal(
            "setup", "B", outcome="succeeded", detail="second", duration_ms=1
        )

        states = supervisor.snapshots_after(initial_revision, timeout=0)

        self.assertEqual(
            [
                [entry["title"] for entry in state["transcript"]]
                for state in states
            ],
            [["A"], ["A", "B"]],
        )

    def start_both(self, supervisor):
        supervisor.start_node("publisher")
        supervisor.start_node("receiver")

    def authenticate(self, supervisor):
        self.start_both(supervisor)
        supervisor.authenticate()

    def test_initialization_exposes_stopped_nodes_and_derived_start_actions(self):
        supervisor, session, records, shutdown_requested = self.make_supervisor()

        state = supervisor.snapshot()

        self.assertEqual(session.initialize_calls, 1)
        self.assertEqual(state["nodes"]["publisher"]["state"], "stopped")
        self.assertEqual(state["nodes"]["receiver"]["state"], "stopped")
        self.assertEqual(state["nodes"]["publisher"]["identity_fingerprint"], "a" * 64)
        self.assertEqual(state["nodes"]["receiver"]["identity_fingerprint"], "b" * 64)
        self.assertEqual(state["authentication"]["state"], "unauthenticated")
        self.assertEqual(
            state["available_actions"],
            ["start_publisher", "start_receiver", "cleanup"],
        )
        self.assertFalse(shutdown_requested.is_set())
        self.assertEqual(
            [(record.action, record.outcome) for record in records.records_after(0, timeout=0)],
            [("initialize", "initialized")],
        )

    def test_start_record_preserves_validated_command_and_confined_path_evidence(self):
        supervisor, _, records, _ = self.make_supervisor(EvidenceSession())

        supervisor.start_node("publisher")

        record = next(
            item
            for item in records.records_after(0, timeout=0)
            if item.action == "ready" and item.outcome == "running"
        )
        self.assertEqual(record.action, "ready")
        self.assertEqual(record.outcome, "running")
        self.assertEqual(record.debug["command"], "aster-agent")
        self.assertEqual(record.debug["confined_path"], "logs/node-0/run-1")
        self.assertIn("command=aster-agent", render_record(record, "debug"))
        self.assertNotIn("confined_path", render_record(record, "guided"))

    def test_nodes_start_stop_independently_and_stop_invalidates_authentication(self):
        supervisor, session, records, _ = self.make_supervisor()

        supervisor.start_node("publisher")
        with self.assertRaises(SupervisorStateError):
            supervisor.authenticate()
        supervisor.start_node("receiver")
        supervisor.authenticate()
        authenticated = supervisor.snapshot()
        self.assertEqual(authenticated["authentication"]["state"], "authenticated")
        self.assertIn("publish_event", authenticated["available_actions"])

        supervisor.stop_node("publisher")
        stopped = supervisor.snapshot()

        self.assertEqual(session.start_calls, ["publisher", "receiver"])
        self.assertEqual(session.stop_calls, ["publisher"])
        self.assertEqual(stopped["nodes"]["publisher"]["state"], "stopped")
        self.assertEqual(stopped["nodes"]["receiver"]["state"], "running")
        self.assertEqual(stopped["authentication"]["state"], "unauthenticated")
        self.assertNotIn("publish_event", stopped["available_actions"])
        self.assertIn("start_publisher", stopped["available_actions"])
        self.assertEqual(
            [record.action for record in records.records_after(0, timeout=0)],
            ["initialize", "start", "ready", "start", "ready", "authenticate", "authenticate", "stop", "stop"],
        )

    def test_authentication_waits_for_real_progress_and_exact_success_receipt(self):
        supervisor, session, records, _ = self.make_supervisor()
        self.start_both(supervisor)
        start_revision = supervisor.snapshot()["revision"]

        supervisor.authenticate()

        updates = supervisor.snapshots_after(start_revision, timeout=0)
        authenticating = next(state for state in updates if state["authentication"]["state"] == "authenticating")
        authenticated = supervisor.snapshot()
        self.assertLess(authenticating["revision"], authenticated["revision"])
        self.assertEqual(session.authenticate_calls, 1)
        self.assertEqual(authenticated["authentication"], {"state": "authenticated", "verification": "verified"})
        self.assertIn("publish_event", authenticated["available_actions"])
        self.assertEqual(
            [(record.action, record.outcome) for record in records.records_after(0, timeout=0)][-2:],
            [("authenticate", "ok"), ("authenticate", "authenticated")],
        )

    def test_authentication_exposes_truthful_pair_restart_until_verified(self):
        entered = threading.Event()
        release = threading.Event()

        class RestartingSession(FakeSession):
            def authenticate(self, progress=None):
                self.authenticate_calls += 1
                if progress is not None:
                    progress({"status": "authenticating"})
                entered.set()
                release.wait(timeout=1)
                return {"status": "authenticated", "challenge": "verified"}

        supervisor, _, _, _ = self.make_supervisor(RestartingSession())
        self.start_both(supervisor)
        worker = threading.Thread(target=supervisor.authenticate)
        worker.start()
        self.assertTrue(entered.wait(timeout=1))

        restarting = supervisor.snapshot()
        self.assertEqual(
            restarting["pair_transition"],
            {"state": "restarting_for_authentication"},
        )
        self.assertEqual(restarting["authentication"]["state"], "authenticating")

        release.set()
        worker.join(timeout=1)
        self.assertFalse(worker.is_alive())
        self.assertIsNone(supervisor.snapshot()["pair_transition"])

    def test_actual_supervisor_records_explain_guided_next_actions(self):
        supervisor, session, records, _ = self.make_supervisor()
        supervisor.start_node("publisher")
        supervisor.start_node("receiver")
        supervisor.authenticate()
        supervisor.stop_node("publisher")
        supervisor.cleanup()

        emitted = records.records_after(0, timeout=0)
        guided_actions = {
            "initialize", "start", "ready", "stop", "authenticate", "cleanup"
        }
        guided = [record for record in emitted if record.action in guided_actions]
        self.assertTrue(guided)
        self.assertTrue(all(record.explanation for record in guided))
        rendered = "\n".join(render_record(record, "guided") for record in guided)
        self.assertIn("Start the publisher and receiver", rendered)
        self.assertIn("Authentication verified", rendered)
        self.assertIn("disposable data", rendered)
        self.assertNotIn("credential", rendered.casefold())

        failing = FakeSession()
        failing.fail_start = True
        failed_supervisor, _, failed_records, _ = self.make_supervisor(failing)
        with self.assertRaises(RuntimeError):
            failed_supervisor.start_node("publisher")
        error_record = failed_records.records_after(0, timeout=0)[-1]
        self.assertEqual(error_record.action, "error")
        self.assertIsNotNone(error_record.explanation)

    def test_publication_emits_commit_snapshot_before_receipt_and_requires_exact_evidence(self):
        commit_reported = threading.Event()
        receipt_release = threading.Event()

        class PublishingSession(FakeSession):
            def publish_with_progress(self, text, progress):
                self.publish_calls.append(text)
                result = self.receipt(self.EVENT_ID, text)
                progress({"commit": result["commit"]})
                commit_reported.set()
                receipt_release.wait(timeout=2)
                return result

        supervisor, _, records, _ = self.make_supervisor(PublishingSession())
        self.authenticate(supervisor)
        ready_revision = supervisor.snapshot()["revision"]
        result = []
        worker = threading.Thread(target=lambda: result.append(supervisor.publish_event("hello")))

        worker.start()
        self.assertTrue(commit_reported.wait(timeout=1))
        committed = supervisor.snapshot()
        self.assertEqual(committed["operation"], "publishing")
        self.assertEqual(committed["commit"]["event_id"], FakeSession.EVENT_ID)
        self.assertIsNone(committed["receipt"])

        receipt_release.set()
        worker.join(timeout=2)
        self.assertFalse(worker.is_alive())
        delivered = supervisor.snapshot()
        updates = supervisor.snapshots_after(ready_revision, timeout=0)
        commit_only = next(state for state in updates if state["commit"] is not None and state["receipt"] is None)
        self.assertGreater(delivered["revision"], commit_only["revision"])
        self.assertEqual(delivered["receipt"]["event_id"], FakeSession.EVENT_ID)
        self.assertEqual(result[0]["receipt"]["event_id"], FakeSession.EVENT_ID)
        publication_records = records.records_after(0, timeout=0)[-3:]
        self.assertEqual([record.action for record in publication_records], ["publish", "commit", "receive"])
        for record, flag in zip(publication_records[1:], ("durable", "observed")):
            self.assertEqual(record.debug["event_id"], FakeSession.EVENT_ID)
            self.assertEqual(record.debug["payload_bytes"], 5)
            self.assertIs(record.debug[flag], True)

    def test_event_validation_uses_the_existing_empty_and_4096_byte_limits(self):
        supervisor, session, _, _ = self.make_supervisor()
        self.authenticate(supervisor)
        exact = "é" * 2048

        supervisor.publish_event(exact)
        with self.assertRaises(EventValidationError):
            supervisor.publish_event("")
        with self.assertRaises(EventValidationError):
            supervisor.publish_event("é" * 2049)
        with self.assertRaises(EventValidationError):
            supervisor.publish_event(7)

        self.assertEqual(session.publish_calls, [exact])

    def test_offline_experiment_requires_a_delivery_and_preserves_first_delivery(self):
        supervisor, session, records, _ = self.make_supervisor()
        self.authenticate(supervisor)

        with self.assertRaises(SupervisorStateError):
            supervisor.run_offline_experiment("too soon")
        supervisor.publish_event("first")
        first = supervisor.snapshot()["first_delivery"]
        supervisor.publish_event("second")
        supervisor.run_offline_experiment("offline")
        completed = supervisor.snapshot()

        self.assertEqual(session.offline_calls, ["offline"])
        self.assertEqual(completed["first_delivery"], first)
        self.assertEqual(completed["message"], "second")
        self.assertEqual(completed["experiment"]["availability"], "available")
        self.assertEqual(completed["experiment"]["receipt"]["event_id"], FakeSession.OFFLINE_EVENT_ID)
        actions = [record.action for record in records.records_after(0, timeout=0)]
        self.assertIn("transport", actions)
        self.assertIn("restore", actions)

    def test_only_one_nonblocking_mutation_runs_at_a_time(self):
        started = threading.Event()
        release = threading.Event()
        supervisor, session, _, _ = self.make_supervisor(FakeSession(start_started=started, start_release=release))

        worker = threading.Thread(target=lambda: supervisor.start_node("publisher"))
        worker.start()
        self.assertTrue(started.wait(timeout=1))
        self.assertEqual(supervisor.snapshot()["nodes"]["publisher"]["state"], "starting")
        with self.assertRaises(SupervisorBusyError):
            supervisor.start_node("receiver")
        self.assertEqual(session.start_calls, ["publisher"])

        release.set()
        worker.join(timeout=2)
        self.assertFalse(worker.is_alive())

    def test_rejects_noop_start_and_stop_without_session_call_revision_or_success_record(self):
        supervisor, session, records, _ = self.make_supervisor()
        supervisor.start_node("publisher")
        running_revision = supervisor.snapshot()["revision"]
        running_records = records.records_after(0, timeout=0)

        with self.assertRaises(SupervisorStateError):
            supervisor.start_node("publisher")

        self.assertEqual(session.start_calls, ["publisher"])
        self.assertEqual(supervisor.snapshot()["revision"], running_revision)
        self.assertEqual(records.records_after(0, timeout=0), running_records)

        supervisor.stop_node("publisher")
        stopped_revision = supervisor.snapshot()["revision"]
        stopped_records = records.records_after(0, timeout=0)

        with self.assertRaises(SupervisorStateError):
            supervisor.stop_node("publisher")

        self.assertEqual(session.stop_calls, ["publisher"])
        self.assertEqual(supervisor.snapshot()["revision"], stopped_revision)
        self.assertEqual(records.records_after(0, timeout=0), stopped_records)

    def test_terminal_publish_and_offline_failures_leave_only_retryable_cleanup(self):
        for operation in ("publish", "offline"):
            with self.subTest(operation=operation):
                session = TerminalFailureSession()
                supervisor, session, _, shutdown_requested = self.make_supervisor(session)
                self.authenticate(supervisor)
                if operation == "offline":
                    supervisor.publish_event("first")
                    session.fail_terminal_offline = True
                    invoke = lambda: supervisor.run_offline_experiment("offline")
                else:
                    session.fail_terminal_publish = True
                    invoke = lambda: supervisor.publish_event("message")

                with self.assertRaisesRegex(RuntimeError, "^The quickstart operation failed\\.$"):
                    invoke()

                failed = supervisor.snapshot()
                self.assertFalse(failed["initialized"])
                self.assertEqual(
                    {failed["nodes"][role]["state"] for role in ("publisher", "receiver")},
                    {"failed"},
                )
                self.assertEqual(failed["authentication"], {"state": "unauthenticated"})
                self.assertEqual(failed["available_actions"], ["cleanup"])
                self.assertFalse(shutdown_requested.is_set())
                start_calls = list(session.start_calls)
                authenticate_calls = session.authenticate_calls
                publish_calls = list(session.publish_calls)
                offline_calls = list(session.offline_calls)

                for retry in (
                    lambda: supervisor.start_node("publisher"),
                    supervisor.authenticate,
                    lambda: supervisor.publish_event("again"),
                    lambda: supervisor.run_offline_experiment("again"),
                ):
                    with self.assertRaises(SupervisorStateError):
                        retry()

                self.assertEqual(session.start_calls, start_calls)
                self.assertEqual(session.authenticate_calls, authenticate_calls)
                self.assertEqual(session.publish_calls, publish_calls)
                self.assertEqual(session.offline_calls, offline_calls)
                supervisor.cleanup()
                self.assertTrue(shutdown_requested.is_set())
                self.assertEqual(session.close_calls, 1)

    def test_recoverable_offline_failure_preserves_the_live_authenticated_scenario(self):
        supervisor, session, records, shutdown_requested = self.make_supervisor(RecoverableOfflineFailureSession())
        self.authenticate(supervisor)
        supervisor.publish_event("first")
        before = supervisor.snapshot()
        revision = before["revision"]

        with self.assertRaisesRegex(RuntimeError, "^The quickstart operation failed\\.$"):
            supervisor.run_offline_experiment("offline")

        recovered = supervisor.snapshot()
        self.assertTrue(recovered["initialized"])
        self.assertEqual(
            {recovered["nodes"][role]["state"] for role in ("publisher", "receiver")},
            {"running"},
        )
        self.assertEqual(recovered["authentication"], {"state": "authenticated", "verification": "verified"})
        self.assertEqual(recovered["first_delivery"], before["first_delivery"])
        self.assertEqual(recovered["message"], "first")
        self.assertEqual(recovered["experiment"], None)
        self.assertEqual(recovered["error"], {"code": "operation_failed", "message": "The quickstart operation failed."})
        self.assertEqual(
            recovered["available_actions"],
            ["stop_publisher", "stop_receiver", "publish_event", "offline_experiment", "cleanup"],
        )
        self.assertFalse(shutdown_requested.is_set())
        self.assertEqual(session.offline_calls, ["offline"])
        self.assertEqual(records.records_after(0, timeout=0)[-1].action, "error")
        self.assertGreater(recovered["revision"], revision)

        supervisor.publish_event("recovered")
        self.assertEqual(supervisor.snapshot()["message"], "recovered")
        self.assertEqual(session.publish_calls, ["first", "recovered"])

    def test_rejects_non_production_event_ids_before_they_enter_snapshots(self):
        invalid_ids = (
            "token=secret-value",
            "/tmp/owner-only-event",
            "a" * 63 + "\x00",
            "A" * 64,
            "a" * 63,
            "a" * 65,
        )

        for field in ("commit", "receipt"):
            for event_id in invalid_ids:
                with self.subTest(field=field, event_id=repr(event_id)):
                    class InvalidEvidenceSession(FakeSession):
                        def publish_with_progress(self, text, progress):
                            self.publish_calls.append(text)
                            result = self.receipt(self.EVENT_ID, text)
                            if field == "commit":
                                result["commit"]["event_id"] = event_id
                                progress({"commit": result["commit"]})
                            else:
                                progress({"commit": result["commit"]})
                                result["receipt"]["event_id"] = event_id
                            return result

                    supervisor, _, _, _ = self.make_supervisor(InvalidEvidenceSession())
                    self.authenticate(supervisor)

                    with self.assertRaisesRegex(RuntimeError, "^The quickstart operation failed\\.$"):
                        supervisor.publish_event("hello")

                    failed = supervisor.snapshot()
                    self.assertNotIn(event_id, repr(failed))
                    self.assertEqual(failed["available_actions"], ["cleanup"])

    def test_failures_are_generic_recorded_and_never_claim_a_running_node(self):
        session = FakeSession()
        session.fail_start = True
        supervisor, _, records, _ = self.make_supervisor(session)

        with self.assertRaisesRegex(RuntimeError, "^The quickstart operation failed\\.$"):
            supervisor.start_node("publisher")

        failed = supervisor.snapshot()
        self.assertEqual(failed["nodes"]["publisher"]["state"], "failed")
        self.assertEqual(failed["failed_stage"], "publisher")
        self.assertEqual(failed["error"], {"code": "operation_failed", "message": "The quickstart operation failed."})
        self.assertNotIn("credential", repr(failed))
        self.assertEqual(records.records_after(0, timeout=0)[-1].action, "error")
        self.assertEqual(records.records_after(0, timeout=0)[-1].outcome, "failed")

    def test_authentication_failure_preserves_its_stage_without_rewriting_retry_state(self):
        session = FakeSession()
        supervisor, _, _, _ = self.make_supervisor(session)
        self.start_both(supervisor)
        session.fail_authenticate = True

        with self.assertRaisesRegex(RuntimeError, "^The quickstart operation failed\\.$"):
            supervisor.authenticate()

        failed = supervisor.snapshot()
        self.assertEqual(failed["failed_stage"], "authentication")
        self.assertEqual(
            {role: failed["nodes"][role]["state"] for role in ("publisher", "receiver")},
            {"publisher": "failed", "receiver": "failed"},
        )
        self.assertEqual(
            failed["available_actions"],
            ["start_publisher", "start_receiver", "cleanup"],
        )
        self.assertNotIn("credential", repr(failed).casefold())

        session.fail_authenticate = False
        supervisor.start_node("publisher")
        retried = supervisor.snapshot()
        self.assertIsNone(retried["failed_stage"])
        self.assertEqual(retried["nodes"]["publisher"]["state"], "running")
        self.assertEqual(retried["available_actions"], ["stop_publisher", "start_receiver", "cleanup"])

    def test_cleanup_retries_and_only_requests_launcher_shutdown_after_success(self):
        supervisor, session, records, shutdown_requested = self.make_supervisor()
        self.start_both(supervisor)
        session.fail_close = True

        with self.assertRaisesRegex(RuntimeError, "^The quickstart cleanup failed\\.$"):
            supervisor.cleanup()
        self.assertFalse(shutdown_requested.is_set())
        self.assertEqual(supervisor.snapshot()["cleanup"], "failed")
        self.assertEqual(supervisor.snapshot()["available_actions"], ["cleanup"])

        session.fail_close = False
        supervisor.close()
        cleaned = supervisor.snapshot()
        self.assertTrue(shutdown_requested.is_set())
        self.assertEqual(cleaned["cleanup"], "cleaned")
        self.assertEqual(cleaned["nodes"]["publisher"]["state"], "stopped")
        self.assertEqual(cleaned["available_actions"], [])
        self.assertEqual(session.close_calls, 2)
        self.assertEqual(
            [record.action for record in records.records_after(0, timeout=0)][-4:],
            ["cleanup", "error", "cleanup", "cleanup"],
        )

    def test_blocking_shutdown_waits_for_active_start_stop_authenticate_and_publish(self):
        for operation in ("start", "stop", "authenticate", "publish"):
            with self.subTest(operation=operation):
                entered = threading.Event()
                release = threading.Event()

                class BlockingSession(FakeSession):
                    block = False

                    def _wait(self):
                        if self.block:
                            entered.set()
                            release.wait(timeout=1)

                    def start_node(self, role):
                        self.start_calls.append(role)
                        self._wait()
                        return {"role": role, "state": "running"}

                    def stop_node(self, role):
                        self.stop_calls.append(role)
                        self._wait()
                        return {"role": role, "state": "stopped"}

                    def authenticate(self, progress=None):
                        self.authenticate_calls += 1
                        if progress is not None:
                            progress({"status": "authenticating"})
                        self._wait()
                        return {"status": "authenticated", "challenge": "verified"}

                    def publish_with_progress(self, text, progress):
                        self.publish_calls.append(text)
                        result = self.receipt(self.EVENT_ID, text)
                        progress({"commit": result["commit"]})
                        self._wait()
                        return result

                session = BlockingSession()
                supervisor, session, _, shutdown_requested = self.make_supervisor(session)
                if operation in {"stop", "authenticate", "publish"}:
                    self.start_both(supervisor)
                if operation == "publish":
                    supervisor.authenticate()
                session.block = True
                invoke = {
                    "start": lambda: supervisor.start_node("publisher"),
                    "stop": lambda: supervisor.stop_node("publisher"),
                    "authenticate": supervisor.authenticate,
                    "publish": lambda: supervisor.publish_event("hello"),
                }[operation]
                action = threading.Thread(target=invoke)
                action.start()
                self.assertTrue(entered.wait(timeout=1))

                shutdown = threading.Thread(target=supervisor.shutdown)
                shutdown.start()
                self.assertTrue(shutdown_requested.wait(timeout=1))
                self.assertTrue(shutdown.is_alive())
                release.set()
                action.join(timeout=1)
                shutdown.join(timeout=1)

                self.assertFalse(action.is_alive())
                self.assertFalse(shutdown.is_alive())
                self.assertGreaterEqual(session.close_calls, 1)
                self.assertEqual(supervisor.snapshot()["cleanup"], "cleaned")

    def test_revision_history_gap_returns_explicit_full_resync(self):
        supervisor, _, _, _ = self.make_supervisor()
        old_revision = supervisor.snapshot()["revision"]
        for _ in range(20):
            supervisor.start_node("publisher")
            supervisor.stop_node("publisher")

        updates = supervisor.snapshots_after(old_revision, timeout=0)

        self.assertEqual(len(updates), 1)
        self.assertEqual(updates[0]["stream"]["mode"], "full_resync")
        self.assertEqual(updates[0]["stream"]["after_revision"], old_revision)
        self.assertEqual(updates[0]["revision"], supervisor.snapshot()["revision"])

    def test_snapshots_are_ordered_waitable_and_caller_independent(self):
        supervisor, _, _, _ = self.make_supervisor()
        revision = supervisor.snapshot()["revision"]
        received = []

        waiter = threading.Thread(target=lambda: received.extend(supervisor.snapshots_after(revision, timeout=1)))
        waiter.start()
        time.sleep(0.02)
        supervisor.start_node("publisher")
        waiter.join(timeout=1)

        self.assertFalse(waiter.is_alive())
        self.assertEqual([state["revision"] for state in received], sorted(state["revision"] for state in received))
        received[0]["nodes"]["publisher"]["state"] = "tampered"
        self.assertNotEqual(supervisor.snapshots_after(revision, timeout=0)[0]["nodes"]["publisher"]["state"], "tampered")


if __name__ == "__main__":
    unittest.main()
