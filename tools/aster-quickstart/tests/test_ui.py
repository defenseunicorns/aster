from __future__ import annotations

from html.parser import HTMLParser
import json
import os
from pathlib import Path
import shutil
import subprocess
import unittest


class WorkbenchParser(HTMLParser):
    def __init__(self):
        super().__init__()
        self.ids: set[str] = set()
        self.buttons: dict[str, dict[str, str | None]] = {}
        self.landmarks: list[tuple[str, str | None]] = []

    def handle_starttag(self, tag, attrs):
        values = dict(attrs)
        if "id" in values:
            self.ids.add(values["id"])
        if tag == "button" and "id" in values:
            self.buttons[values["id"]] = values
        if tag in {"main", "section", "article", "nav"}:
            self.landmarks.append((tag, values.get("aria-label") or values.get("aria-labelledby")))


class BrowserBehaviorTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.node = os.environ.get("ASTER_QUICKSTART_NODE") or shutil.which("node")
        if cls.node is None:
            raise unittest.SkipTest("node is required for the browser behavior test")
        cls.root = Path(__file__).resolve().parents[1]

    def run_scenario(self, mode):
        completed = subprocess.run(
            [
                self.node,
                str(self.root / "tests" / "ui_behavior.js"),
                str(self.root / "aster_quickstart" / "static" / "app.js"),
                mode,
            ],
            check=True,
            capture_output=True,
            text=True,
            timeout=3,
        )
        return json.loads(completed.stdout)

    def test_page_has_two_operational_nodes_and_keyboard_native_controls(self):
        parser = WorkbenchParser()
        parser.feed((self.root / "aster_quickstart" / "static" / "index.html").read_text())
        required = {
            "publisher-card", "publisher-start", "publisher-stop", "publisher-terminal",
            "publisher-output", "receiver-card", "receiver-start", "receiver-stop",
            "receiver-terminal", "receiver-output", "authenticate", "event-form",
            "event-text", "send-event", "detail-level", "offline-experiment",
            "technical-evidence", "cleanup", "workspace-progress-state",
            "publisher-progress-state", "receiver-progress-state", "auth-progress-state",
            "event-progress-state",
            "publisher-copy-command", "receiver-copy-command",
            "publisher-copy-feedback", "receiver-copy-feedback",
            "publisher-fallback-note", "receiver-fallback-note",
            "execution-transcript",
            "session-signal",
        }
        self.assertEqual(required - parser.ids, set())
        self.assertTrue(all(button.get("type") == "button" for name, button in parser.buttons.items() if name != "send-event"))
        self.assertEqual(parser.buttons["send-event"].get("type"), "submit")
        self.assertIn(("section", "Publisher and receiver nodes"), parser.landmarks)
        markup = (self.root / "aster_quickstart" / "static" / "index.html").read_text()
        self.assertIn("commands and internal operations", markup)

    def test_node_regions_and_controls_have_distinct_accessible_names(self):
        parser = WorkbenchParser()
        parser.feed((self.root / "aster_quickstart" / "static" / "index.html").read_text())

        self.assertIn(("article", "publisher-title"), parser.landmarks)
        self.assertIn(("article", "receiver-title"), parser.landmarks)
        self.assertEqual(parser.buttons["publisher-start"].get("aria-label"), "Start Publisher")
        self.assertEqual(parser.buttons["publisher-stop"].get("aria-label"), "Stop Publisher")
        self.assertEqual(parser.buttons["publisher-terminal"].get("aria-label"), "Open Publisher terminal")
        self.assertEqual(parser.buttons["publisher-copy-command"].get("aria-label"), "Copy Publisher observer command")
        self.assertEqual(parser.buttons["receiver-start"].get("aria-label"), "Start Receiver")
        self.assertEqual(parser.buttons["receiver-stop"].get("aria-label"), "Stop Receiver")
        self.assertEqual(parser.buttons["receiver-terminal"].get("aria-label"), "Open Receiver terminal")
        self.assertEqual(parser.buttons["receiver-copy-command"].get("aria-label"), "Copy Receiver observer command")

    def test_per_node_actions_and_authentication_follow_authoritative_actions(self):
        result = self.run_scenario("lifecycle")
        self.assertEqual(result["initialDisabled"], {
            "publisherStart": False,
            "publisherStop": True,
            "receiverStart": False,
            "authenticate": True,
            "send": True,
        })
        self.assertEqual(result["postPath"], "/api/nodes/publisher/start?token=test-token")
        self.assertEqual(result["afterPublisher"]["publisherState"], "running")
        self.assertFalse(result["afterPublisher"]["receiverStartDisabled"])

    def test_commit_renders_before_receipt_and_enables_experiment_only_after_delivery(self):
        result = self.run_scenario("progress")
        self.assertEqual(result["commit"], "committed · " + ("a" * 64))
        self.assertEqual(result["receiptBefore"], "Waiting for receiver…")
        self.assertTrue(result["offlineBefore"])
        self.assertEqual(result["receiptAfter"], "received · " + ("a" * 64))
        self.assertFalse(result["offlineAfter"])

    def test_fast_post_response_preserves_commit_across_two_frame_callbacks(self):
        result = self.run_scenario("fast-post")
        expected = {
            "commit": "committed · " + ("a" * 64),
            "receipt": "Waiting for receiver…",
        }
        self.assertEqual(result["frameSnapshots"], [expected, expected])
        self.assertEqual(result["finalCommit"], "committed · " + ("a" * 64))
        self.assertEqual(result["finalReceipt"], "received · " + ("a" * 64))

    def test_lagging_sse_receipt_is_deferred_during_commit_presentation(self):
        result = self.run_scenario("fast-post-sse")

        self.assertEqual(result["receiptAfterLaggingSse"], "Waiting for receiver…")
        self.assertEqual(result["finalCommit"], "committed · " + ("a" * 64))
        self.assertEqual(result["finalReceipt"], "received · " + ("a" * 64))

    def test_resync_required_sse_payload_refreshes_without_becoming_authoritative(self):
        result = self.run_scenario("resync-required")

        self.assertEqual(result["fetches"], 1)
        self.assertEqual(result["publisherState"], "running")

    def test_consecutive_resync_required_controls_share_one_refresh(self):
        result = self.run_scenario("consecutive-resync-required")

        self.assertEqual(result["fetches"], 1)
        self.assertEqual(result["publisherState"], "running")

    def test_detail_selector_filters_existing_records_locally(self):
        result = self.run_scenario("detail")
        self.assertNotIn("The node is ready", result["compact"])
        self.assertIn("The node is ready", result["guided"])
        self.assertIn("state=running", result["debug"])
        self.assertEqual(result["fetchesAfterDetailChanges"], 0)

    def test_terminal_fallback_and_cleanup_are_explicit(self):
        terminal = self.run_scenario("terminal")
        self.assertIn("aster_quickstart.attach", terminal["fallback"])
        self.assertFalse(terminal["fallbackHidden"])
        self.assertEqual(terminal["copiedText"], terminal["fallback"])
        self.assertEqual(terminal["copyLabel"], "Copied")
        self.assertEqual(terminal["postPath"], "/api/terminal/publisher?token=test-token")

        cancelled = self.run_scenario("cleanup-cancel")
        accepted = self.run_scenario("cleanup-accept")
        self.assertEqual(cancelled["confirmCalls"], 1)
        self.assertFalse(cancelled["postSeen"])
        self.assertEqual(accepted["postPath"], "/api/cleanup?token=test-token")
        self.assertEqual(accepted["status"], "Cleanup complete. You can close this page.")

    def test_terminal_copy_without_clipboard_selects_command_and_reports_context(self):
        terminal = self.run_scenario("terminal-no-clipboard")

        self.assertIsNone(terminal["copiedText"])
        self.assertEqual(terminal["selectedText"], terminal["fallback"])
        self.assertEqual(
            terminal["copyFeedback"],
            "Publisher observer command selected. Use your copy shortcut to copy it.",
        )

    def test_progress_is_textual_current_and_pair_restart_supersedes_node_pills(self):
        result = self.run_scenario("progress-accessibility")
        self.assertEqual(result["initial"], {
            "workspace": "Complete",
            "publisher": "Current",
            "publisherCurrent": "step",
        })
        self.assertEqual(result["authenticating"]["publisherPill"], "restarting · pair authentication")
        self.assertEqual(result["authenticating"]["receiverPill"], "restarting · pair authentication")
        self.assertEqual(result["authenticating"]["authText"], "Current")
        self.assertEqual(result["complete"]["eventText"], "Complete")
        self.assertIsNone(result["complete"]["eventCurrent"])

    def test_observer_controls_stay_disabled_after_cleanup_begins_and_retry_remains(self):
        result = self.run_scenario("cleanup-observer-controls")

        self.assertEqual(result["cleaning"], {"terminal": True, "copy": True})
        self.assertEqual(
            result["failed"],
            {"terminal": True, "copy": True, "cleanup": False},
        )

        pending = self.run_scenario("cleanup-pending")
        self.assertEqual(pending, {"terminal": True, "copy": True})

    def test_session_signal_tracks_ready_failed_and_cleaned_states(self):
        result = self.run_scenario("signal-states")

        self.assertEqual(result["ready"], {"good": True, "failed": False})
        self.assertEqual(result["failed"], {"good": False, "failed": True})
        self.assertEqual(result["cleaned"], {"inactive": True, "good": False})

    def test_publisher_start_failure_marks_only_publisher_and_has_no_current_stage(self):
        result = self.run_scenario("publisher-failure")
        self.assertEqual(result["progress"], {
            "workspace": "Complete",
            "publisher": "Failed",
            "receiver": "Pending",
            "authentication": "Pending",
            "event": "Pending",
        })
        self.assertEqual(result["publisherPill"], "failed")
        self.assertEqual(result["currentStages"], [])

    def test_authentication_failure_preserves_completed_nodes_and_marks_authentication(self):
        result = self.run_scenario("authentication-failure")
        self.assertEqual(result["progress"], {
            "workspace": "Complete",
            "publisher": "Complete",
            "receiver": "Complete",
            "authentication": "Failed",
            "event": "Pending",
        })
        self.assertEqual(result["nodePills"], {"publisher": "failed", "receiver": "failed"})
        self.assertEqual(result["currentStages"], [])

    def test_stale_post_state_cannot_overwrite_newer_sse_state(self):
        result = self.run_scenario("stale-post")
        self.assertEqual(result["publisherState"], "running")
        self.assertEqual(result["receiverState"], "running")
        self.assertEqual(result["authState"], "unauthenticated")
        self.assertEqual(result["status"], "Both nodes are running. Authenticate them.")

if __name__ == "__main__":
    unittest.main()
