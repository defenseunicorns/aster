from __future__ import annotations

import http.client
import json
from pathlib import Path
import socket
import struct
import threading
import time
import unittest
from unittest.mock import patch
from urllib.parse import urlsplit

from aster_quickstart.records import RecordJournal
from aster_quickstart.supervisor import QuickstartSupervisor
from aster_quickstart.transcript import TranscriptJournal
from aster_quickstart.web import (
    MAX_ACTIVE_HTTP_HANDLERS,
    SSE_CATCHUP_BYTES_LIMIT,
    QuickstartServer,
)


class FakeSession:
    EVENT_ID = "a" * 64
    OFFLINE_ID = "b" * 64

    def __init__(self) -> None:
        self.start_calls: list[str] = []
        self.stop_calls: list[str] = []
        self.publish_calls: list[str] = []
        self.closed = False
        self.start_entered: threading.Event | None = None
        self.start_release: threading.Event | None = None
        self.commit_entered: threading.Event | None = None
        self.receipt_release: threading.Event | None = None
        self.fail_publish = False
        self.close_entered: threading.Event | None = None
        self.close_release: threading.Event | None = None
        self.close_failures = 0

    def initialize(self):
        return {
            "status": "initialized",
            "nodes": {
                "publisher": {"identity_fingerprint": "1" * 64},
                "receiver": {"identity_fingerprint": "2" * 64},
            },
        }

    def start_node(self, role):
        self.start_calls.append(role)
        if self.start_entered is not None:
            self.start_entered.set()
        if self.start_release is not None:
            self.start_release.wait(timeout=1)
        return {"role": role, "state": "running"}

    def stop_node(self, role):
        self.stop_calls.append(role)
        return {"role": role, "state": "stopped"}

    def authenticate(self, progress):
        progress({"status": "authenticating"})
        return {"status": "authenticated", "challenge": "verified"}

    @classmethod
    def receipt(cls, event_id, text):
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

    def publish_with_progress(self, text, progress):
        self.publish_calls.append(text)
        if self.fail_publish:
            raise RuntimeError("secret credential=/owner-only")
        result = self.receipt(self.EVENT_ID, text)
        progress({"commit": result["commit"]})
        if self.commit_entered is not None:
            self.commit_entered.set()
        if self.receipt_release is not None:
            self.receipt_release.wait(timeout=1)
        return result

    def offline_publish(self, text, progress):
        result = self.receipt(self.OFFLINE_ID, text)
        progress({"availability": "unavailable"})
        progress({"commit": result["commit"]})
        progress({"availability": "available"})
        progress({"receipt": result["receipt"]})
        return result

    def close(self):
        if self.close_entered is not None:
            self.close_entered.set()
        if self.close_release is not None:
            self.close_release.wait(timeout=1)
        if self.close_failures:
            self.close_failures -= 1
            raise RuntimeError("cleanup failed")
        self.closed = True


class FakeAttach:
    def command(self, role, detail):
        class Command:
            argv = (
                "/usr/bin/python3", "-m", "aster_quickstart.attach",
                "--role", role, "--detail", detail,
            )
            cwd = Path("/opt/aster quickstart")

        return Command()


class QuickstartServerTests(unittest.TestCase):
    token = "token-for-browser-session"

    def setUp(self):
        self.session = FakeSession()
        self.records = RecordJournal()
        self.shutdown = threading.Event()
        self.transcript = TranscriptJournal()
        self.transcript.record_internal(
            "setup", "Acquire workspace", outcome="succeeded", detail="ready", duration_ms=1
        )
        self.supervisor = QuickstartSupervisor(
            self.session, self.records, self.shutdown, transcript=self.transcript
        )
        self.opened: list[list[str]] = []
        self.terminal_roles: list[str] = []
        self.terminal_result = False
        self.server = QuickstartServer(
            self.supervisor,
            self.token,
            records=self.records,
            attach=FakeAttach(),
            terminal_open=self.open_terminal,
        )
        self.url = self.server.start()
        parsed = urlsplit(self.url)
        self.port = parsed.port
        self.host = parsed.netloc

    def tearDown(self):
        self.server.close()

    def open_terminal(self, command, role):
        self.opened.append({"argv": list(command.argv), "cwd": str(command.cwd)})
        self.terminal_roles.append(role)
        return self.terminal_result

    def request(self, method, path, *, body=None, headers=None):
        connection = http.client.HTTPConnection("127.0.0.1", self.port, timeout=2)
        request_headers = {"Host": self.host}
        if method == "POST":
            request_headers["Origin"] = f"http://{self.host}"
        request_headers.update(headers or {})
        connection.request(method, path, body=body, headers=request_headers)
        response = connection.getresponse()
        data = response.read()
        result = response.status, dict(response.getheaders()), data
        connection.close()
        return result

    def path(self, route):
        return f"{route}?token={self.token}"

    def json_request(self, route, body):
        return self.request(
            "POST",
            self.path(route),
            body=json.dumps(body).encode(),
            headers={
                "Content-Type": "application/json",
                "Origin": f"http://{self.host}",
            },
        )

    def raw_request(self, request):
        client = socket.create_connection(("127.0.0.1", self.port), timeout=1)
        try:
            client.sendall(request)
            client.shutdown(socket.SHUT_WR)
            response = bytearray()
            while True:
                chunk = client.recv(4096)
                if not chunk:
                    break
                response.extend(chunk)
            return bytes(response)
        finally:
            client.close()

    @staticmethod
    def decode(result):
        return result[0], json.loads(result[2])

    def assert_peer_terminated(self, client: socket.socket) -> None:
        try:
            received = client.recv(4096)
        except ConnectionResetError:
            return
        self.assertEqual(received, b"")

    def start_and_authenticate(self):
        self.assertEqual(self.json_request("/api/nodes/publisher/start", {})[0], 200)
        self.assertEqual(self.json_request("/api/nodes/receiver/start", {})[0], 200)
        self.assertEqual(self.json_request("/api/authenticate", {})[0], 200)

    def test_server_is_private_tokenized_and_keeps_security_headers(self):
        self.assertEqual(urlsplit(self.url).hostname, "127.0.0.1")
        self.assertEqual(urlsplit(self.url).query, f"token={self.token}")
        with self.assertRaises(ValueError):
            QuickstartServer(self.supervisor, self.token, host="0.0.0.0")

        for path, host in (
            ("/api/state", self.host),
            ("/api/state?token=wrong", self.host),
            (self.path("/api/state"), "localhost"),
            (f"/api/state?token={self.token}&extra=1", self.host),
        ):
            status, _, _ = self.request("GET", path, headers={"Host": host})
            self.assertEqual(status, 403)

        status, headers, body = self.request("GET", self.path("/"))
        self.assertEqual(status, 200)
        self.assertIn(b"publisher-start", body)
        self.assertIn(b"receiver-start", body)
        self.assertNotIn(b"__TOKEN__", body)
        self.assertEqual(headers["Cache-Control"], "no-store")
        self.assertEqual(headers["X-Frame-Options"], "DENY")
        self.assertIn("default-src 'self'", headers["Content-Security-Policy"])

    def test_public_transcript_state_is_redacted_revisioned_and_detaches_after_cleanup(self):
        self.transcript.register_secret("browser-private-secret")
        command = self.transcript.start_command(
            "event", ["asterctl", "publish", "browser-private-secret"], cwd="/tmp/quickstart"
        )
        command.update(stdout=b"browser-private-secret")
        command.finish(0, outcome="succeeded")

        status, initial = self.decode(self.request("GET", self.path("/api/state")))
        self.assertEqual(status, 200)
        self.assertEqual(initial["transcript"][-1]["command"], "asterctl publish '<redacted:argument>'")
        self.assertNotIn("browser-private-secret", repr(initial))
        revision = initial["revision"]

        self.transcript.record_internal(
            "publisher", "Start publisher", outcome="running", detail="listening", duration_ms=2
        )
        status, updated = self.decode(self.request("GET", self.path("/api/state")))
        self.assertEqual(status, 200)
        self.assertGreater(updated["revision"], revision)
        self.assertEqual(updated["transcript"][-1]["title"], "Start publisher")

        self.supervisor.cleanup()
        cleaned = self.supervisor.snapshot()["revision"]
        self.transcript.record_internal(
            "cleanup", "Late journal mutation", outcome="failed", detail="private", duration_ms=0
        )
        status, final = self.decode(self.request("GET", self.path("/api/state")))
        self.assertEqual((status, final["revision"]), (200, cleaned))
        self.assertNotIn("Late journal mutation", repr(final))

    def test_start_failure_releases_the_bound_server(self):
        self.server.close()
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as reservation:
            reservation.bind(("127.0.0.1", 0))
            port = reservation.getsockname()[1]
        failed = QuickstartServer(self.supervisor, self.token, port=port)
        with patch("aster_quickstart.web.threading.Thread.start", side_effect=RuntimeError("thread unavailable")):
            with self.assertRaisesRegex(RuntimeError, "thread unavailable"):
                failed.start()
        failed.close()
        replacement = QuickstartServer(self.supervisor, self.token, port=port)
        replacement.start()
        replacement.close()

    def test_operational_routes_drive_authoritative_per_node_state(self):
        status, initial = self.decode(self.request("GET", self.path("/api/state")))
        self.assertEqual(status, 200)
        self.assertEqual(initial["nodes"]["publisher"]["state"], "stopped")
        self.assertEqual(initial["nodes"]["receiver"]["state"], "stopped")
        self.assertEqual(initial["available_actions"], ["start_publisher", "start_receiver", "cleanup"])
        self.assertEqual(initial["records"][0]["action"], "initialize")
        rendered = initial["records"][0]["rendered"]
        self.assertEqual(rendered["compact"], "[initialize] initialized: ready")
        self.assertIn("Start the publisher", rendered["guided"])
        self.assertIn("operation=initialize", rendered["debug"])

        status, publisher = self.decode(self.json_request("/api/nodes/publisher/start", {}))
        self.assertEqual(status, 200)
        self.assertEqual(publisher["nodes"]["publisher"]["state"], "running")
        self.assertNotIn("authenticate", publisher["available_actions"])
        status, duplicate = self.decode(self.json_request("/api/nodes/publisher/start", {}))
        self.assertEqual((status, duplicate["error"]["code"]), (409, "unavailable"))

        status, both = self.decode(self.json_request("/api/nodes/receiver/start", {}))
        self.assertEqual(status, 200)
        self.assertIn("authenticate", both["available_actions"])
        status, authenticated = self.decode(self.json_request("/api/authenticate", {}))
        self.assertEqual(status, 200)
        self.assertEqual(authenticated["authentication"]["state"], "authenticated")
        self.assertIn("publish_event", authenticated["available_actions"])

        status, delivered = self.decode(self.json_request("/api/events", {"text": "Hello from publisher"}))
        self.assertEqual(status, 200)
        self.assertEqual(delivered["commit"]["status"], "committed")
        self.assertEqual(delivered["receipt"]["status"], "received")
        self.assertIn("offline_experiment", delivered["available_actions"])

        status, stopped = self.decode(self.json_request("/api/nodes/receiver/stop", {}))
        self.assertEqual(status, 200)
        self.assertEqual(stopped["nodes"]["receiver"]["state"], "stopped")
        self.assertEqual(stopped["authentication"]["state"], "unauthenticated")

    def test_action_schemas_and_event_body_are_exact_and_bounded(self):
        status, payload = self.decode(self.json_request("/api/nodes/publisher/start", {"extra": True}))
        self.assertEqual((status, payload["error"]["code"]), (400, "invalid_request"))
        status, _, _ = self.request("POST", self.path("/api/events"), body=b'{"text":"hello"}')
        self.assertEqual(status, 415)
        status, payload = self.decode(
            self.request(
                "POST",
                self.path("/api/events"),
                body=b"x" * 24_641,
                headers={"Content-Type": "application/json"},
            )
        )
        self.assertEqual((status, payload["error"]["code"]), (413, "request_too_large"))
        self.start_and_authenticate()
        status, payload = self.decode(self.request(
            "POST",
            self.path("/api/events"),
            body=json.dumps({"text": "é" * 2049}, ensure_ascii=False).encode(),
            headers={"Content-Type": "application/json"},
        ))
        self.assertEqual((status, payload["error"]["code"]), (400, "invalid_event"))
        self.assertEqual(self.session.publish_calls, [])

    def test_escaped_4096_byte_event_is_valid_and_lone_surrogate_is_invalid_event(self):
        self.start_and_authenticate()
        boundary = '"\\' * 2048
        body = json.dumps({"text": boundary}).encode()
        self.assertGreater(len(body), 8192)

        status, payload = self.decode(self.request(
            "POST",
            self.path("/api/events"),
            body=body,
            headers={"Content-Type": "application/json"},
        ))
        self.assertEqual(status, 200)
        self.assertEqual(payload["receipt"]["text"], boundary)

        status, payload = self.decode(self.request(
            "POST",
            self.path("/api/events"),
            body=b'{"text":"\\ud800"}',
            headers={"Content-Type": "application/json"},
        ))
        self.assertEqual((status, payload["error"]["code"]), (400, "invalid_event"))

    def test_terminal_route_uses_vector_and_returns_copyable_fallback(self):
        status, payload = self.decode(
            self.json_request("/api/terminal/publisher", {"detail": "debug"})
        )
        self.assertEqual(status, 200)
        self.assertFalse(payload["terminal"]["opened"])
        self.assertIn("aster_quickstart.attach", payload["terminal"]["attach_command"])
        self.assertEqual(
            payload["terminal"],
            {
                "opened": False,
                "argv": [
                    "/usr/bin/python3", "-m", "aster_quickstart.attach",
                    "--role", "publisher", "--detail", "debug",
                ],
                "cwd": "/opt/aster quickstart",
                "attach_command": "cd -- '/opt/aster quickstart' && /usr/bin/python3 -m aster_quickstart.attach --role publisher --detail debug",
            },
        )
        self.assertEqual(self.opened, [{
            "argv": [
                "/usr/bin/python3", "-m", "aster_quickstart.attach",
                "--role", "publisher", "--detail", "debug",
            ],
            "cwd": "/opt/aster quickstart",
        }])
        self.assertEqual(self.terminal_roles, ["publisher"])
        status, payload = self.decode(
            self.json_request("/api/terminal/receiver", {"detail": "verbose"})
        )
        self.assertEqual((status, payload["error"]["code"]), (400, "invalid_request"))

    def test_raw_http_rejects_ambiguous_framing_origin_and_duplicate_host(self):
        route = self.path("/api/nodes/publisher/start")
        common = (
            f"POST {route} HTTP/1.1\r\n"
            f"Host: {self.host}\r\n"
            f"Origin: http://{self.host}\r\n"
            "Content-Type: application/json\r\n"
        )
        cases = (
            common + "Content-Length: 2\r\nContent-Length: 2\r\n\r\n{}",
            common + "Content-Type: application/json\r\nContent-Length: 2\r\n\r\n{}",
            common + "Transfer-Encoding: chunked\r\n\r\n0\r\n\r\n",
            common.replace(
                f"Origin: http://{self.host}\r\n",
                "Origin: http://attacker.invalid\r\n",
            ) + "Content-Length: 2\r\n\r\n{}",
            common.replace(
                f"Host: {self.host}\r\n",
                f"Host: {self.host}\r\nHost: {self.host}\r\n",
            ) + "Content-Length: 2\r\n\r\n{}",
        )
        for request in cases:
            with self.subTest(request=request.split("\r\n")[1:4]):
                response = self.raw_request(request.encode("ascii"))
                self.assertRegex(response, rb"HTTP/1\.1 (400|403|411|415) ")
        self.assertEqual(self.session.start_calls, [])

    def test_partial_header_and_body_are_closed_on_absolute_deadlines(self):
        clients = []
        try:
            header = socket.create_connection(("127.0.0.1", self.port), timeout=1)
            clients.append(header)
            header.sendall(b"GET /api/state HTTP/1.1\r\n")
            body = socket.create_connection(("127.0.0.1", self.port), timeout=1)
            clients.append(body)
            body.sendall(
                (
                    f"POST {self.path('/api/nodes/publisher/start')} HTTP/1.1\r\n"
                    f"Host: {self.host}\r\n"
                    f"Origin: http://{self.host}\r\n"
                    "Content-Type: application/json\r\n"
                    "Content-Length: 20\r\n\r\n{"
                ).encode("ascii")
            )
            deadline = time.monotonic() + 1.0
            for client in clients:
                client.settimeout(max(0.01, deadline - time.monotonic()))
                self.assert_peer_terminated(client)
            self.assertEqual(self.request("GET", self.path("/api/state"))[0], 200)
        finally:
            for client in clients:
                client.close()

    def test_close_terminates_a_pre_auth_partial_connection(self):
        with socket.create_connection(("127.0.0.1", self.port), timeout=1) as client:
            client.sendall(b"GET / HTTP/1.1\r\n")
            started = time.monotonic()
            self.server.close()
            self.assertLess(time.monotonic() - started, 1.0)
            client.settimeout(0.2)
            self.assert_peer_terminated(client)

    def test_pre_auth_handler_count_is_bounded_and_excess_connections_close(self):
        clients = []
        try:
            for _ in range(MAX_ACTIVE_HTTP_HANDLERS + 4):
                client = socket.create_connection(("127.0.0.1", self.port), timeout=1)
                client.sendall(b"GET / HTTP/1.1\r\n")
                clients.append(client)
            deadline = time.monotonic() + 0.2
            while self.server._httpd._active_handlers < MAX_ACTIVE_HTTP_HANDLERS:
                self.assertLess(time.monotonic(), deadline)
                time.sleep(0.005)
            self.assertEqual(self.server._httpd._active_handlers, MAX_ACTIVE_HTTP_HANDLERS)
            closed = 0
            for client in clients:
                client.settimeout(0.05)
                try:
                    closed += client.recv(1) == b""
                except TimeoutError:
                    pass
            self.assertGreaterEqual(closed, 4)
        finally:
            for client in clients:
                client.close()

    def test_stalled_sse_writer_is_evicted_by_the_response_deadline(self):
        entered = threading.Event()

        def oversized_event(handler, _state):
            entered.set()
            handler.connection.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, 4096)
            handler._write_bytes(b"x" * (2 * 1024 * 1024))

        client = socket.create_connection(("127.0.0.1", self.port), timeout=1)
        try:
            with patch(
                "aster_quickstart.web._QuickstartRequestHandler._send_state_event",
                new=oversized_event,
            ):
                client.sendall(
                    (
                        f"GET {self.path('/api/events')} HTTP/1.1\r\n"
                        f"Host: {self.host}\r\n\r\n"
                    ).encode("ascii")
                )
                self.assertTrue(entered.wait(0.5))
                deadline = time.monotonic() + 1
                while self.server._httpd._active_handlers:
                    self.assertLess(time.monotonic(), deadline)
                    time.sleep(0.01)
        finally:
            client.close()

    def test_terminal_launches_are_serialized_and_rate_limited(self):
        entered = threading.Event()
        release = threading.Event()

        def blocking_open(command, role):
            self.opened.append(list(command))
            entered.set()
            release.wait(timeout=1)
            return False

        self.server._httpd.terminal_open = blocking_open
        first = []
        second = []
        first_worker = threading.Thread(
            target=lambda: first.append(
                self.json_request("/api/terminal/publisher", {"detail": "guided"})
            )
        )
        second_worker = threading.Thread(
            target=lambda: second.append(
                self.json_request("/api/terminal/receiver", {"detail": "guided"})
            )
        )
        first_worker.start()
        self.assertTrue(entered.wait(timeout=1))
        second_worker.start()
        release.set()
        first_worker.join(timeout=1)
        second_worker.join(timeout=1)

        self.assertEqual(first[0][0], 200)
        status, payload = self.decode(second[0])
        self.assertEqual((status, payload["error"]["code"]), (409, "busy"))
        self.assertEqual(len(self.opened), 1)

    def test_cleanup_waits_for_inflight_terminal_launch_and_rejects_new_ones(self):
        terminal_entered = threading.Event()
        terminal_release = threading.Event()

        def blocking_open(command, role):
            self.opened.append(list(command))
            terminal_entered.set()
            terminal_release.wait(timeout=1)
            return False

        self.server._httpd.terminal_open = blocking_open
        terminal = []
        terminal_worker = threading.Thread(
            target=lambda: terminal.append(
                self.json_request("/api/terminal/publisher", {"detail": "guided"})
            )
        )
        terminal_worker.start()
        self.assertTrue(terminal_entered.wait(timeout=1))

        self.session.close_entered = threading.Event()
        self.session.close_release = threading.Event()
        cleanup = []
        cleanup_worker = threading.Thread(
            target=lambda: cleanup.append(
                self.json_request("/api/cleanup", {"confirm": True})
            )
        )
        cleanup_worker.start()
        self.assertFalse(self.session.close_entered.wait(timeout=0.05))
        status, payload = self.decode(
            self.json_request("/api/terminal/receiver", {"detail": "guided"})
        )
        self.assertEqual((status, payload["error"]["code"]), (409, "unavailable"))
        terminal_release.set()
        terminal_worker.join(timeout=1)
        self.assertTrue(self.session.close_entered.wait(timeout=1))
        self.session.close_release.set()
        cleanup_worker.join(timeout=1)
        self.assertEqual(terminal[0][0], 200)

    def test_busy_and_unavailable_errors_are_distinct_and_sanitized(self):
        entered = threading.Event()
        release = threading.Event()
        self.session.start_entered = entered
        self.session.start_release = release
        response = []
        worker = threading.Thread(
            target=lambda: response.append(self.json_request("/api/nodes/publisher/start", {}))
        )
        worker.start()
        self.assertTrue(entered.wait(timeout=1))
        status, payload = self.decode(self.json_request("/api/nodes/receiver/start", {}))
        self.assertEqual((status, payload["error"]["code"]), (409, "busy"))
        release.set()
        worker.join(timeout=1)
        self.assertFalse(worker.is_alive())

        status, payload = self.decode(self.json_request("/api/events", {"text": "too soon"}))
        self.assertEqual((status, payload["error"]["code"]), (409, "unavailable"))

    def test_sse_preserves_commit_before_receipt_revisions(self):
        self.start_and_authenticate()
        self.session.commit_entered = threading.Event()
        self.session.receipt_release = threading.Event()
        connection = http.client.HTTPConnection("127.0.0.1", self.port, timeout=2)
        connection.request("GET", self.path("/api/events"), headers={"Host": self.host})
        response = connection.getresponse()
        initial = self._read_sse_state(response)

        mutation = []
        worker = threading.Thread(
            target=lambda: mutation.append(self.json_request("/api/events", {"text": "ordered"}))
        )
        worker.start()
        self.assertTrue(self.session.commit_entered.wait(timeout=1))
        committed = self._read_sse_until(response, lambda state: state["commit"] is not None)
        self.assertGreater(committed["revision"], initial["revision"])
        self.assertIsNone(committed["receipt"])
        self.session.receipt_release.set()
        delivered = self._read_sse_until(response, lambda state: state["receipt"] is not None)
        worker.join(timeout=1)
        self.assertGreater(delivered["revision"], committed["revision"])
        self.assertEqual(mutation[0][0], 200)
        connection.close()

    def test_sse_catchup_uses_one_bounded_full_resync_for_large_revision_history(self):
        transcript = TranscriptJournal(max_entries=1, max_total_bytes=100_000)
        supervisor = QuickstartSupervisor(
            FakeSession(), RecordJournal(), threading.Event(), transcript=transcript
        )
        revision = supervisor.snapshot()["revision"]
        for number in range(64):
            transcript.record_internal(
                "setup",
                f"operation {number}",
                outcome="succeeded",
                detail="x" * 25_000,
                duration_ms=number,
            )

        updates = supervisor.snapshots_after(revision, timeout=0)
        public = self.server._httpd.bounded_public_updates(updates, revision)
        encoded = sum(
            len(b"event: state\ndata: ")
            + len(json.dumps(state, ensure_ascii=False, separators=(",", ":")).encode())
            + len(b"\n\n")
            for state in public
        )

        self.assertEqual(len(public), 1)
        self.assertEqual(public[0]["stream"]["mode"], "full_resync")
        self.assertEqual(public[0]["stream"]["reason"], "payload_budget")
        self.assertLessEqual(encoded, SSE_CATCHUP_BYTES_LIMIT)
        self.assertEqual(public[0]["revision"], supervisor.snapshot()["revision"])

    def test_sse_resync_explicitly_reports_records_omitted_for_its_payload_budget(self):
        records = RecordJournal(limit=1_024)
        self.server._httpd.records = records
        for _ in range(1_024):
            records.emit(
                action="error",
                node=None,
                outcome="failed",
                message="The action failed safely; clean up or retry an available action.",
                explanation="Some earlier records have expired from the bounded history.",
            )
        state = self.supervisor.snapshot()
        state["record_sequence"] = records.latest_sequence()

        with patch("aster_quickstart.web.SSE_CATCHUP_BYTES_LIMIT", 2_000):
            [resync] = self.server._httpd.bounded_public_updates([state], 0)
            encoded = (
                b"event: state\\ndata: "
                + json.dumps(resync, ensure_ascii=False, separators=(",", ":")).encode()
                + b"\\n\\n"
            )

        self.assertEqual(resync["stream"]["mode"], "full_resync")
        self.assertFalse(resync["stream"]["records_complete"])
        self.assertGreater(resync["stream"]["records_omitted"], 0)
        self.assertEqual(
            resync["stream"]["records_omitted"] + len(resync["records"]),
            records.latest_sequence(),
        )
        self.assertLessEqual(len(encoded), 2_000)

    def test_sse_historical_watermark_discloses_records_expired_by_journal_rollover(self):
        records = RecordJournal(limit=2)
        self.server._httpd.records = records
        for _ in range(4):
            records.emit(
                action="error",
                node=None,
                outcome="failed",
                message="The action failed safely; clean up or retry an available action.",
            )
        state = self.supervisor.snapshot()
        state["record_sequence"] = 1

        [public] = self.server._httpd.bounded_public_updates([state], 0)

        self.assertEqual(public["records"], [])
        self.assertFalse(public["stream"]["records_complete"])
        self.assertEqual(public["stream"]["records_omitted"], 1)

    def test_sse_budget_trim_counts_each_expired_record_represented_by_history_gap(self):
        records = RecordJournal(limit=2)
        self.server._httpd.records = records
        for _ in range(5):
            records.emit(
                action="error",
                node=None,
                outcome="failed",
                message="The action failed safely; clean up or retry an available action.",
                explanation="Some earlier records have expired from the bounded history.",
            )
        state = self.supervisor.snapshot()
        state["record_sequence"] = records.latest_sequence()
        source = records.records_after(0, timeout=0)

        with patch("aster_quickstart.web.SSE_CATCHUP_BYTES_LIMIT", 1_500):
            [resync] = self.server._httpd.bounded_public_updates([state], 0)

        retained_real_records = [
            record for record in resync["records"] if record["action"] != "history-gap"
        ]
        self.assertEqual(resync["stream"]["mode"], "full_resync")
        self.assertFalse(resync["stream"]["records_complete"])
        self.assertLess(len(resync["records"]), len(source))
        self.assertEqual(
            resync["stream"]["records_omitted"],
            state["record_sequence"] - len(retained_real_records),
        )

    def test_sse_resync_required_replaces_oversized_record_free_authoritative_state(self):
        transcript = TranscriptJournal(
            max_entries=1,
            max_total_bytes=SSE_CATCHUP_BYTES_LIMIT + 8_192,
        )
        supervisor = QuickstartSupervisor(
            FakeSession(), RecordJournal(), threading.Event(), transcript=transcript
        )
        revision = supervisor.snapshot()["revision"]
        transcript.record_internal(
            "setup",
            "Acquire workspace",
            outcome="succeeded",
            detail="x" * SSE_CATCHUP_BYTES_LIMIT,
            duration_ms=1,
        )
        [oversized] = supervisor.snapshots_after(revision, timeout=0)

        [control] = self.server._httpd.bounded_public_updates([oversized], revision)
        encoded = json.dumps(control, ensure_ascii=False, separators=(",", ":")).encode()

        self.assertEqual(control, {
            "revision": oversized["revision"],
            "stream": {"mode": "resync_required", "reason": "payload_budget"},
        })
        self.assertLessEqual(len(encoded), SSE_CATCHUP_BYTES_LIMIT)

    def test_fast_publication_sse_commit_snapshot_never_contains_later_receive_record(self):
        self.start_and_authenticate()
        connection = http.client.HTTPConnection("127.0.0.1", self.port, timeout=2)
        connection.request("GET", self.path("/api/events"), headers={"Host": self.host})
        response = connection.getresponse()
        self._read_sse_state(response)

        self.assertEqual(self.json_request("/api/events", {"text": "fast"})[0], 200)
        commit_only = None
        delivered = None
        while delivered is None:
            state = self._read_sse_state(response)
            if state["commit"] is not None and state["receipt"] is None:
                commit_only = state
            if state["receipt"] is not None:
                delivered = state

        self.assertIsNotNone(commit_only)
        self.assertNotIn("receive", [record["action"] for record in commit_only["records"]])
        self.assertLess(commit_only["record_sequence"], delivered["record_sequence"])
        connection.close()

    def test_sse_gap_is_a_full_resync_and_server_close_ends_live_stream(self):
        original = self.supervisor.snapshots_after
        waiting = threading.Event()
        release = threading.Event()
        first = True

        def gated(revision, timeout):
            nonlocal first
            if first:
                first = False
                waiting.set()
                release.wait(timeout=1)
            return original(revision, timeout)

        self.supervisor.snapshots_after = gated
        connection = http.client.HTTPConnection("127.0.0.1", self.port, timeout=2)
        connection.request("GET", self.path("/api/events"), headers={"Host": self.host})
        response = connection.getresponse()
        initial = self._read_sse_state(response)
        self.assertTrue(waiting.wait(timeout=1))
        for _ in range(20):
            self.supervisor.start_node("publisher")
            self.supervisor.stop_node("publisher")
        release.set()

        resync = self._read_sse_state(response)
        self.assertEqual(resync["stream"]["mode"], "full_resync")
        self.assertEqual(resync["stream"]["after_revision"], initial["revision"])

        closer = threading.Thread(target=self.server.close)
        closer.start()
        closer.join(timeout=1)
        self.assertFalse(closer.is_alive())
        try:
            self.assertEqual(response.fp.readline(), b"")
        except (ConnectionError, OSError):
            pass
        connection.close()

    def test_sse_client_count_is_bounded(self):
        streams = []
        try:
            for _ in range(4):
                connection = http.client.HTTPConnection("127.0.0.1", self.port, timeout=2)
                connection.request("GET", self.path("/api/events"), headers={"Host": self.host})
                response = connection.getresponse()
                self.assertEqual(response.status, 200)
                self._read_sse_state(response)
                streams.append((connection, response))
            rejected = self.request("GET", self.path("/api/events"))
            self.assertEqual(rejected[0], 503)
            self.assertEqual(json.loads(rejected[2])["error"]["code"], "busy")
        finally:
            for connection, _ in streams:
                connection.close()

    def test_operation_errors_never_return_raw_failure_text(self):
        self.start_and_authenticate()
        self.session.fail_publish = True
        status, payload = self.decode(self.json_request("/api/events", {"text": "hello"}))
        self.assertEqual(status, 500)
        self.assertEqual(payload["error"], {
            "code": "operation_failed", "message": "The quickstart operation failed."
        })
        self.assertNotIn("credential", json.dumps(payload))

    def test_cleanup_confirmation_returns_final_state_before_shutdown_signal(self):
        status, payload = self.decode(self.json_request("/api/cleanup", {"confirm": False}))
        self.assertEqual((status, payload["error"]["code"]), (400, "invalid_request"))
        self.assertFalse(self.shutdown.is_set())

        status, payload = self.decode(self.json_request("/api/cleanup", {"confirm": True}))
        self.assertEqual(status, 200)
        self.assertEqual(payload["cleanup"], "cleaned")
        self.assertEqual(payload["records"][-1]["action"], "cleanup")
        self.assertTrue(self.shutdown.is_set())
        self.assertEqual(self.server.wait_for_cleanup_response(timeout=1), "sent")

    def test_failed_cleanup_keeps_terminals_disabled_and_can_be_retried(self):
        self.session.close_failures = 1
        status, failed = self.decode(self.json_request("/api/cleanup", {"confirm": True}))
        self.assertEqual((status, failed["error"]["code"]), (500, "operation_failed"))
        status, unavailable = self.decode(
            self.json_request("/api/terminal/publisher", {"detail": "guided"})
        )
        self.assertEqual((status, unavailable["error"]["code"]), (409, "unavailable"))
        status, cleaned = self.decode(self.json_request("/api/cleanup", {"confirm": True}))
        self.assertEqual((status, cleaned["cleanup"]), (200, "cleaned"))

    def test_cleanup_response_disconnect_is_reported_without_blocking_cleanup(self):
        self.session.close_entered = threading.Event()
        self.session.close_release = threading.Event()
        client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        client.connect(("127.0.0.1", self.port))
        body = b'{"confirm":true}'
        request = (
            f"POST {self.path('/api/cleanup')} HTTP/1.1\r\n"
            f"Host: {self.host}\r\n"
            f"Origin: http://{self.host}\r\n"
            "Content-Type: application/json\r\n"
            f"Content-Length: {len(body)}\r\n\r\n"
        ).encode() + body
        client.sendall(request)
        self.assertTrue(self.session.close_entered.wait(timeout=1))
        client.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, struct.pack("ii", 1, 0))
        client.close()
        self.session.close_release.set()

        self.assertEqual(self.server.wait_for_cleanup_response(timeout=1), "disconnected")
        self.assertTrue(self.session.closed)

    @staticmethod
    def _read_sse_state(response):
        if response.fp.readline() != b"event: state\n":
            raise AssertionError("missing state event")
        line = response.fp.readline()
        response.fp.readline()
        return json.loads(line.removeprefix(b"data: "))

    def _read_sse_until(self, response, predicate):
        deadline = time.monotonic() + 1
        while time.monotonic() < deadline:
            state = self._read_sse_state(response)
            if predicate(state):
                return state
        self.fail("expected SSE state was not observed")


if __name__ == "__main__":
    unittest.main()
