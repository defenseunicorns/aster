from __future__ import annotations

import base64
from collections import deque
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import os
from pathlib import Path
import signal
import shlex
import sys
import tempfile
import threading
import time
import unittest
from unittest.mock import patch

from aster_quickstart.connect import ConnectError, ConnectJsonClient, NumberedPublisher
from aster_quickstart.transcript import TranscriptJournal


EVENT_ID = b"e" * 32
PAYLOAD = b"hello"


class _RpcServer(ThreadingHTTPServer):
    def __init__(self, responses):
        super().__init__(("127.0.0.1", 0), _RpcHandler)
        self.responses = deque(responses)
        self.requests = []


class _RpcHandler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def do_POST(self):
        body = self.rfile.read(int(self.headers.get("Content-Length", "0")))
        self.server.requests.append((self.path, self.headers.get("Authorization"), json.loads(body)))
        response = self.server.responses.popleft()
        status, payload = response[:2]
        if len(response) == 3:
            time.sleep(response[2])
        payload = payload if isinstance(payload, bytes) else json.dumps(payload).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        try:
            self.wfile.write(payload)
        except BrokenPipeError:
            pass

    def log_message(self, format, *args):
        pass


class _TrickleHandler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def do_POST(self):
        self.rfile.read(int(self.headers.get("Content-Length", "0")))
        payload = json.dumps(
            {"events": [], "scannedThrough": "0", "hasMore": False}
        ).encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        try:
            for byte in payload:
                self.wfile.write(bytes([byte]))
                self.wfile.flush()
                time.sleep(0.015)
        except (BrokenPipeError, ConnectionResetError):
            pass

    def log_message(self, format, *args):
        pass


class ConnectJsonClientTests(unittest.TestCase):
    def start_server(self, responses):
        server = _RpcServer(responses)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        self.addCleanup(server.server_close)
        self.addCleanup(server.shutdown)
        self.addCleanup(thread.join, 2)
        return server

    def test_requires_an_explicit_literal_loopback_http_url(self):
        for url in (
            "http://localhost:1234",
            "http://192.0.2.1:1234",
            "https://127.0.0.1:1234",
            "http://user@127.0.0.1:1234",
            "http://127.0.0.1",
            "http://127.0.0.1:1234/?query=yes",
            "http://127.0.0.1:1234/#fragment",
        ):
            with self.subTest(url=url), self.assertRaises(ConnectError):
                ConnectJsonClient(url, "token")

        client = ConnectJsonClient("http://127.0.0.1:1234/application", "token")
        self.assertEqual((client.host, client.port, client.base_path), ("127.0.0.1", 1234, "/application"))

    def test_response_is_bounded_before_json_is_accepted(self):
        server = self.start_server([(200, b"{" + b" " * (2 * 1024 * 1024) + b"}")])
        client = ConnectJsonClient(f"http://127.0.0.1:{server.server_port}", "token")

        with self.assertRaisesRegex(ConnectError, "bound"):
            client.call("GetStatus", {})

    def test_malformed_json_and_non_object_responses_fail_closed(self):
        server = self.start_server([(200, b"not-json"), (200, ["not", "an", "object"])])
        client = ConnectJsonClient(f"http://127.0.0.1:{server.server_port}", "token")

        with self.assertRaisesRegex(ConnectError, "malformed"):
            client.call("GetStatus", {})
        with self.assertRaisesRegex(ConnectError, "object"):
            client.call("GetStatus", {})

    def test_query_events_requires_pagination_progress(self):
        server = self.start_server([
            (200, {"events": [], "scannedThrough": "0", "hasMore": True}),
        ])
        client = ConnectJsonClient(f"http://127.0.0.1:{server.server_port}", "token")

        with self.assertRaisesRegex(ConnectError, "progress"):
            client.query_events(0)

    def test_query_events_advances_the_marker_and_uses_exact_contract(self):
        event = {
            "id": base64.b64encode(EVENT_ID).decode("ascii"),
            "payload": base64.b64encode(PAYLOAD).decode("ascii"),
            "topic": "mesh.messages",
            "scope": "demo/playground",
            "publisher": base64.b64encode(b"p" * 32).decode("ascii"),
            "eventSequence": "1",
        }
        server = self.start_server([
            (200, {"events": [], "scannedThrough": "4", "hasMore": True}),
            (200, {"events": [event], "scannedThrough": "5", "hasMore": False}),
        ])
        client = ConnectJsonClient(f"http://127.0.0.1:{server.server_port}/rpc", "secret", timeout=1)

        events, marker = client.query_events(0)

        self.assertEqual((events, marker), ([event], 5))
        self.assertEqual([request[2]["afterAcceptanceMarker"] for request in server.requests], ["0", "4"])
        self.assertTrue(all(request[0].endswith("/QueryEvents") for request in server.requests))
        self.assertTrue(all(request[1] == "Bearer secret" for request in server.requests))

    def test_query_events_timeout_bounds_the_whole_paginated_scan(self):
        server = self.start_server([
            (200, {"events": [{"page": page}], "scannedThrough": str(page + 1), "hasMore": True}, 0.06)
            for page in range(9)
        ])
        client = ConnectJsonClient(f"http://127.0.0.1:{server.server_port}", "token", timeout=0.12)

        started = time.monotonic()
        with self.assertRaises(ConnectError):
            client.query_events(0)
        self.assertLess(time.monotonic() - started, 0.30)

    def test_absolute_deadline_stops_a_response_that_trickles_without_stalling(self):
        server = ThreadingHTTPServer(("127.0.0.1", 0), _TrickleHandler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()

        def stop_server():
            server.shutdown()
            server.server_close()
            thread.join(timeout=2)

        self.addCleanup(stop_server)
        client = ConnectJsonClient(
            f"http://127.0.0.1:{server.server_port}", "token", timeout=0.12
        )

        started = time.monotonic()
        with self.assertRaises(ConnectError):
            client.query_events(0)
        self.assertLess(time.monotonic() - started, 0.30)

    def test_exact_event_rejects_the_expected_identifier_with_wrong_data(self):
        wrong = {
            "id": base64.b64encode(EVENT_ID).decode("ascii"),
            "payload": base64.b64encode(b"different").decode("ascii"),
            "topic": "mesh.messages",
            "scope": "demo/playground",
        }
        server = self.start_server([
            (200, {"events": [wrong], "scannedThrough": "1", "hasMore": False}),
        ])
        client = ConnectJsonClient(f"http://127.0.0.1:{server.server_port}", "token")

        with self.assertRaisesRegex(ConnectError, "different payload"):
            client.query_exact_event(EVENT_ID, PAYLOAD, 0)


class NumberedPublisherProcessTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)

    def executable(self, name, body):
        path = self.root / name
        path.write_text(f"#!{sys.executable}\n" + body)
        path.chmod(0o700)
        return path

    @staticmethod
    def kill_if_alive(pid):
        try:
            os.kill(pid, signal.SIGKILL)
        except ProcessLookupError:
            pass

    def assert_not_live(self, pid):
        deadline = time.monotonic() + 2
        while time.monotonic() < deadline:
            try:
                state = Path(f"/proc/{pid}/stat").read_text().split()[2]
            except (FileNotFoundError, IndexError, OSError):
                return
            if state == "Z":
                return
            time.sleep(0.02)
        self.fail(f"numbered publisher descendant remains alive: {pid}")

    def test_stderr_is_bounded_while_the_command_runs(self):
        ctl = self.executable(
            "noisy-ctl",
            "import os\nos.write(2, b'x' * (2 * 1024 * 1024 + 1))\n",
        )
        transcript = TranscriptJournal()
        publisher = NumberedPublisher(
            ctl,
            self.root / "journal",
            "client",
            timeout=0.2,
            transcript=transcript,
        )

        with self.assertRaisesRegex(ConnectError, "bound"):
            publisher.initialize()
        [entry] = transcript.snapshot()
        self.assertEqual(entry["outcome"], "output overflow")

    def test_initialize_records_exact_command_boundary(self):
        ctl = self.executable("successful-ctl", "print('initialized')\n")
        transcript = TranscriptJournal()
        publisher = NumberedPublisher(
            ctl,
            self.root / "journal",
            "client",
            timeout=0.2,
            transcript=transcript,
            transcript_step="setup",
        )

        publisher.initialize()

        [entry] = transcript.snapshot()
        self.assertEqual(entry["step"], "setup")
        self.assertIn("publication-init", entry["command"])
        self.assertEqual(entry["stdin"], None)
        self.assertEqual(entry["stdout"], "initialized\n")
        self.assertEqual(entry["stderr"], "")
        self.assertEqual(entry["outcome"], "succeeded")
        self.assertEqual(entry["returncode"], 0)

    def test_every_numbered_command_records_its_own_step_and_streams(self):
        ctl = self.executable(
            "all-actions-ctl",
            """import base64, json, sys
actions = {"publication-init", "subscribe", "publish", "publication-ack"}
action = next(item for item in sys.argv if item in actions)
if action == "subscribe":
    print(json.dumps({"subscriptionId": base64.b64encode(b"s" * 32).decode()}))
elif action == "publish":
    print(json.dumps({"result": {"receipt": {"eventId": base64.b64encode(b"e" * 32).decode()}, "operationSequence": "1"}, "inserted": True}))
else:
    print(action)
""",
        )
        transcript = TranscriptJournal()
        publisher = NumberedPublisher(ctl, self.root / "journal", "client", timeout=0.2, transcript=transcript)

        publisher.initialize()
        publisher.connect("http://127.0.0.1:1234", self.root / "client.token")
        publisher.create_subscription(b"subscription", transcript_step="authentication")
        publication = publisher.publish(b"event", b"payload", transcript_step="event")
        publisher.acknowledge(publication, transcript_step="event")

        entries = transcript.snapshot()
        self.assertEqual(len(entries), 4)
        self.assertEqual(
            [(entry["step"], entry["stdin"], entry["outcome"], entry["returncode"]) for entry in entries],
            [
                ("setup", None, "succeeded", 0),
                ("authentication", None, "succeeded", 0),
                ("event", "payload", "succeeded", 0),
                ("event", None, "succeeded", 0),
            ],
        )
        subscription_id = base64.b64encode(b"s" * 32).decode()
        event_id = base64.b64encode(b"e" * 32).decode()
        self.assertEqual(
            [(entry["stdout"], entry["stderr"]) for entry in entries],
            [
                ("publication-init\n", ""),
                (json.dumps({"subscriptionId": subscription_id}) + "\n", ""),
                (
                    json.dumps({
                        "result": {
                            "receipt": {"eventId": event_id},
                            "operationSequence": "1",
                        },
                        "inserted": True,
                    }) + "\n",
                    "",
                ),
                ("publication-ack\n", ""),
            ],
        )
        expected_commands = (
            [str(ctl), "publication-init", "--journal", str(self.root / "journal"), "--client-id", "client"],
            [str(ctl), "--token-file", str(self.root / "client.token"), "--host", "127.0.0.1", "--port", "1234", "--timeout", "1", "--json", "subscribe", "--journal", str(self.root / "journal"), "--client-id", "client", "--operation-key", "subscription", "--scope", "demo/playground", "mesh.messages"],
            [str(ctl), "--token-file", str(self.root / "client.token"), "--host", "127.0.0.1", "--port", "1234", "--timeout", "1", "--json", "publish", "--journal", str(self.root / "journal"), "--client-id", "client", "--topic", "mesh.messages", "--scope", "demo/playground", "--logical-key", "event"],
            [str(ctl), "--token-file", str(self.root / "client.token"), "--host", "127.0.0.1", "--port", "1234", "--timeout", "1", "--json", "publication-ack", "--journal", str(self.root / "journal"), "--client-id", "client", "--sequence", "1"],
        )
        for entry, expected in zip(entries, expected_commands):
            self.assertEqual(entry["command"], shlex.join(expected))
            self.assertEqual(entry["cwd"], os.getcwd())
            self.assertIsInstance(entry["duration_ms"], int)

    def test_spawn_failure_finalizes_one_command_entry(self):
        transcript = TranscriptJournal()
        publisher = NumberedPublisher(self.root / "missing-ctl", self.root / "journal", "client", transcript=transcript)

        with self.assertRaises(ConnectError):
            publisher.initialize()

        [entry] = transcript.snapshot()
        self.assertEqual((entry["outcome"], entry["returncode"]), ("spawn failed", None))
        self.assertIsInstance(entry["duration_ms"], int)

    def test_nonzero_exit_finalizes_one_command_entry(self):
        ctl = self.executable("failing-ctl", "import sys\nsys.exit(7)\n")
        transcript = TranscriptJournal()
        publisher = NumberedPublisher(ctl, self.root / "journal", "client", transcript=transcript)

        with self.assertRaises(ConnectError):
            publisher.initialize()

        [entry] = transcript.snapshot()
        self.assertEqual((entry["outcome"], entry["returncode"]), ("failed", 7))
        self.assertIsInstance(entry["duration_ms"], int)

    def test_cancellation_finalizes_one_command_entry(self):
        ctl = self.executable("stalled-ctl", "import time\ntime.sleep(60)\n")
        cancelled = threading.Event()
        cancelled.set()
        transcript = TranscriptJournal()
        publisher = NumberedPublisher(
            ctl,
            self.root / "journal",
            "client",
            cancel_event=cancelled,
            transcript=transcript,
        )

        with self.assertRaisesRegex(ConnectError, "cancelled"):
            publisher.initialize()

        [entry] = transcript.snapshot()
        self.assertEqual(entry["outcome"], "cancelled")
        self.assertIsInstance(entry["duration_ms"], int)

    def test_retained_output_pipe_finalizes_one_command_entry(self):
        ctl = self.executable(
            "retained-pipe-ctl",
            """import pathlib, subprocess, sys
child = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(60)"])
pathlib.Path(sys.argv[sys.argv.index("--journal") + 1]).with_suffix(".pid").write_text(str(child.pid))
""",
        )
        transcript = TranscriptJournal()
        journal = self.root / "journal"
        publisher = NumberedPublisher(ctl, journal, "client", timeout=0.2, transcript=transcript)

        with self.assertRaises(ConnectError):
            publisher.initialize()

        descendant = int(journal.with_suffix(".pid").read_text())
        self.addCleanup(self.kill_if_alive, descendant)
        [entry] = transcript.snapshot()
        self.assertEqual(entry["outcome"], "output pipe retained")
        self.assertIsInstance(entry["duration_ms"], int)

    def test_timeout_reaps_the_numbered_command_process_group(self):
        ctl = self.executable(
            "stalled-ctl",
            """import pathlib, signal, subprocess, sys, time
child = subprocess.Popen([sys.executable, '-c', 'import signal,time; signal.signal(signal.SIGINT, signal.SIG_IGN); signal.signal(signal.SIGTERM, signal.SIG_IGN); time.sleep(60)'])
pathlib.Path(sys.argv[sys.argv.index('--journal') + 1]).with_suffix('.pid').write_text(str(child.pid))
time.sleep(60)
""",
        )
        journal = self.root / "journal"
        transcript = TranscriptJournal()
        publisher = NumberedPublisher(ctl, journal, "client", timeout=0.05, transcript=transcript)

        with self.assertRaises(ConnectError):
            publisher.initialize()
        descendant = int(journal.with_suffix(".pid").read_text())
        self.addCleanup(self.kill_if_alive, descendant)
        self.assert_not_live(descendant)
        [entry] = transcript.snapshot()
        self.assertEqual(entry["outcome"], "timed out")
        self.assertIsInstance(entry["duration_ms"], int)

    def test_exited_leader_with_unpinned_descendant_fails_closed_without_group_signal(self):
        ctl = self.executable(
            "successful-leader",
            """import pathlib, signal, subprocess, sys
child = subprocess.Popen(
    [sys.executable, '-c', 'import signal,time; signal.signal(signal.SIGINT, signal.SIG_IGN); signal.signal(signal.SIGTERM, signal.SIG_IGN); time.sleep(60)'],
    stdin=subprocess.DEVNULL,
    stdout=subprocess.DEVNULL,
    stderr=subprocess.DEVNULL,
)
journal = pathlib.Path(sys.argv[sys.argv.index('--journal') + 1])
journal.with_suffix('.pid').write_text(str(child.pid))
print('not-json')
""",
        )
        journal = self.root / "journal"
        transcript = TranscriptJournal()
        publisher = NumberedPublisher(ctl, journal, "client", timeout=0.1, transcript=transcript)
        publisher.connect("http://127.0.0.1:1234", self.root / "token")

        with self.assertRaises(ConnectError):
            publisher.create_subscription(b"operation")

        descendant = int(journal.with_suffix(".pid").read_text())
        self.addCleanup(self.kill_if_alive, descendant)
        os.kill(descendant, 0)
        [entry] = transcript.snapshot()
        self.assertEqual(entry["outcome"], "process group retained")
        self.assertIsInstance(entry["duration_ms"], int)

    def test_uncertain_pre_identity_command_does_not_clear_its_pending_marker(self):
        ctl = self.executable(
            "uncertain-ctl",
            """import pathlib, subprocess, sys, time
child = subprocess.Popen(
    [sys.executable, '-c', 'import time; time.sleep(60)'],
    stdin=subprocess.DEVNULL,
    stdout=subprocess.DEVNULL,
    stderr=subprocess.DEVNULL,
)
journal = pathlib.Path(sys.argv[sys.argv.index('--journal') + 1])
journal.with_suffix('.pid').write_text(str(child.pid))
time.sleep(60)
""",
        )
        journal = self.root / "journal"
        pending = []
        gone = []
        transcript = TranscriptJournal()
        publisher = NumberedPublisher(
            ctl,
            journal,
            "client",
            timeout=0.1,
            before_spawn=pending.append,
            after_gone=gone.append,
            transcript=transcript,
        )
        publisher.connect("http://127.0.0.1:1234", self.root / "token")

        def lose_identity(pid):
            deadline = time.monotonic() + 0.5
            while not journal.with_suffix(".pid").exists() and time.monotonic() < deadline:
                time.sleep(0.005)
            raise ProcessLookupError(pid)

        with patch("aster_quickstart.connect.OwnedProcessGroup.capture", side_effect=lose_identity):
            with self.assertRaises(ConnectError):
                publisher.create_subscription(b"operation")

        self.assertEqual(pending, ["asterctl-subscribe"])
        self.assertEqual(gone, [])
        descendant = int(journal.with_suffix(".pid").read_text())
        self.addCleanup(self.kill_if_alive, descendant)
        os.kill(descendant, 0)
        [entry] = transcript.snapshot()
        self.assertEqual(entry["outcome"], "identity failed")
        self.assertIsInstance(entry["duration_ms"], int)


if __name__ == "__main__":
    unittest.main()
