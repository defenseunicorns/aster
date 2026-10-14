#!/usr/bin/env python3
# Copyright 2026 Defense Unicorns, Inc.
# SPDX-License-Identifier: Apache-2.0
"""Focused tests for the bounded local Aster Event playground."""

from __future__ import annotations

import base64
import hashlib
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import importlib.util
import io
import json
import os
from pathlib import Path
import signal
import socket
import subprocess
import sys
import tempfile
import threading
import time
import types
import unittest
from unittest import mock
from urllib.parse import quote


MODULE_PATH = Path(__file__).with_name("aster_mesh_playground.py")
SPEC = importlib.util.spec_from_file_location("aster_mesh_playground_under_test", MODULE_PATH)
assert SPEC is not None and SPEC.loader is not None
playground = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = playground
SPEC.loader.exec_module(playground)


def identity(index: int, offset: int = 0) -> str:
    return ("%064x" % (index + 1 + offset))[-64:]


def initializer_bytes(root: Path, nodes: int) -> bytes:
    lines = [
        "PLAYGROUND_INIT status=pass nodes=%d scope=%s topic=%s epoch=1 provisioning=unprotected-reference root=%s"
        % (nodes, playground.SCOPE, playground.TOPIC, quote(str(root), safe="/"))
    ]
    for index in range(nodes):
        lines.append(
            "PLAYGROUND_NODE index=%d carrier_id=%s mission_id=%s"
            % (index, identity(index), identity(index, 100))
        )
    return ("\n".join(lines) + "\n").encode("utf-8")


def initialized_root(parent: Path, nodes: int) -> playground.InitResult:
    root = parent / "mesh"
    root.mkdir(mode=0o700)
    items = []
    for index in range(nodes):
        state = root / ("node-%d" % index)
        state.mkdir(mode=0o700)
        mission = state / "mission.unprotected-reference.bundle"
        mission.write_bytes(b"disposable-reference-%d" % index)
        os.chmod(mission, 0o600)
        items.append(playground.InitNode(index, identity(index), identity(index, 100)))
    return playground.InitResult(root, tuple(items))


class InitializerParsingTests(unittest.TestCase):
    def test_hello_roster_names_are_fixed_unique_and_cover_the_node_bound(self) -> None:
        self.assertEqual(len(playground.HELLO_NODE_NAMES), playground.MAX_NODES)
        self.assertEqual(len(set(playground.HELLO_NODE_NAMES)), playground.MAX_NODES)
        self.assertEqual(playground.HELLO_NODE_NAMES[:3], ("atlas", "beacon", "cove"))
        for name in playground.HELLO_NODE_NAMES:
            self.assertRegex(name, r"^[a-z]{3,12}$")

    def test_exact_initializer_contract_is_accepted(self) -> None:
        root = Path("/tmp/playground root/mesh")
        result = playground.parse_initializer_output(initializer_bytes(root, 3), root, 3)
        self.assertEqual(result.root, root)
        self.assertEqual([node.index for node in result.nodes], [0, 1, 2])
        self.assertEqual(result.nodes[2].mission_id, identity(2, 100))

    def test_duplicate_or_unknown_initializer_records_fail_closed(self) -> None:
        root = Path("/tmp/playground/mesh")
        valid = initializer_bytes(root, 2).decode("utf-8").splitlines()
        duplicate = "\n".join([valid[0], valid[1], valid[1]]) + "\n"
        with self.assertRaisesRegex(playground.PlaygroundError, "indexes"):
            playground.parse_initializer_output(duplicate.encode("utf-8"), root, 2)
        unknown = "\n".join([valid[0], valid[1], "NOPE status=pass"]) + "\n"
        with self.assertRaisesRegex(playground.PlaygroundError, "unknown"):
            playground.parse_initializer_output(unknown.encode("utf-8"), root, 2)

    def test_initializer_rejects_broadened_topic_or_node_range(self) -> None:
        root = Path("/tmp/playground/mesh")
        bad = initializer_bytes(root, 2).replace(b"topic=mesh.messages", b"topic=other")
        with self.assertRaisesRegex(playground.PlaygroundError, "topic or scope"):
            playground.parse_initializer_output(bad, root, 2)
        with self.assertRaisesRegex(playground.PlaygroundError, "2..=32"):
            playground.Topology(33)

    def test_initializer_output_is_drained_but_retained_only_to_a_fixed_cap(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            parent = Path(temporary)
            executable = parent / "noisy-initializer"
            executable.write_text(
                "#!%s\nimport os\nos.write(1, b'x' * %d)\n"
                % (sys.executable, playground.MAX_INITIALIZER_STDOUT_BYTES + 8192),
                encoding="utf-8",
            )
            os.chmod(executable, 0o700)
            with self.assertRaisesRegex(playground.PlaygroundError, "stdout exceeds"):
                playground.run_initializer(executable, parent / "mesh", 2, 5)


class TopologyTests(unittest.TestCase):
    def test_line_neighbors_and_isolation_are_exact(self) -> None:
        topology = playground.Topology(5)
        self.assertEqual(topology.neighbors(0), {1})
        self.assertEqual(topology.neighbors(2), {1, 3})
        self.assertEqual(topology.neighbors(4), {3})
        self.assertEqual(topology.isolate(2), {1, 2, 3})
        self.assertEqual(topology.neighbors(2), set())
        self.assertEqual(topology.neighbors(1), {0})
        self.assertFalse(topology.edge_enabled(1, 2))
        self.assertEqual(topology.rejoin(2), {1, 2, 3})
        self.assertEqual(topology.neighbors(2), {1, 3})

    def test_overlapping_isolations_do_not_restore_an_isolated_neighbor(self) -> None:
        topology = playground.Topology(4)
        topology.isolate(1)
        topology.isolate(2)
        topology.rejoin(1)
        self.assertEqual(topology.neighbors(1), {0})
        self.assertEqual(topology.neighbors(2), set())


class RenderingTests(unittest.TestCase):
    def snapshot(self) -> dict:
        return {
            "root": "/tmp/example",
            "isolated": [1],
            "nodes": [
                {"index": 0, "status": "ready", "seen": 1, "neighbors": []},
                {"index": 1, "status": "ready", "seen": 1, "neighbors": []},
                {"index": 2, "status": "failed", "seen": 0, "neighbors": []},
            ],
            "events": [
                {
                    "alias": "m1",
                    "publisherNode": 0,
                    "text": "hello\x1b[31m\nworld",
                    "seen": [0, 1],
                }
            ],
        }

    def test_narrow_ascii_dashboard_is_bounded_and_control_safe(self) -> None:
        lines = playground.render_dashboard(self.snapshot(), 38, 10, False)
        self.assertLessEqual(len(lines), 10)
        self.assertTrue(all(len(line) <= 38 for line in lines))
        self.assertTrue(all("\x1b" not in line and "\n" not in line for line in lines))
        for line in lines:
            line.encode("ascii")
        self.assertTrue(any("Commands:" in line for line in lines))

    def test_field_notes_dashboard_names_route_provenance_and_evidence_boundary(self) -> None:
        snapshot = {
            "experience": "hello",
            "networkProvenance": "nearby",
            "nearbyWindowSeconds": 10,
            "selectedNode": 1,
            "isolated": [],
            "nodes": [
                {
                    "index": 0,
                    "name": "atlas",
                    "activated": True,
                    "status": "ready",
                    "authenticatedNeighbors": [1],
                },
                {
                    "index": 1,
                    "name": "beacon",
                    "activated": True,
                    "status": "ready",
                    "authenticatedNeighbors": [0],
                },
                {
                    "index": 2,
                    "name": "cove",
                    "activated": False,
                    "status": "available",
                    "authenticatedNeighbors": [],
                },
            ],
            "events": [],
        }
        lines = playground.render_dashboard(snapshot, 100, 20, True)
        rendered = "\n".join(lines)
        self.assertIn("ASTER FIELD NOTES", rendered)
        self.assertIn("atlas", rendered)
        self.assertIn("beacon*", rendered)
        self.assertIn("cove", rendered)
        self.assertIn("ROUTE nearby", rendered)
        self.assertIn("no fallback", rendered)
        self.assertIn("not discovery metadata", rendered)
        self.assertIn("exact QueryEvents", rendered)
        self.assertIn("● atlas ─── ● beacon* ··· ○ cove", rendered)

    def test_raw_and_plain_views_never_emit_live_terminal_controls(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "logs").mkdir()
            raw_out = io.StringIO()
            raw = playground.EventSink(root, "raw", raw_out, io.StringIO())
            raw.emit("info", text="bad\x1b[2J\nvalue")
            raw.close()
            self.assertNotIn("\x1b", raw_out.getvalue())
            self.assertIn("\\u001b", raw_out.getvalue())

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "logs").mkdir()
            plain_out = io.StringIO()
            plain = playground.EventSink(root, "plain", plain_out, io.StringIO())
            plain.emit("info", text="bad\x1b[2J\nvalue")
            plain.close()
            self.assertNotIn("\x1b", plain_out.getvalue())
            self.assertIn("bad?[2J value", plain_out.getvalue())

    def test_controller_journal_is_rotated_to_the_same_retained_cap(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            sink = playground.EventSink(root, "tui", io.StringIO(), io.StringIO())
            for number in range(5000):
                sink.emit("info", text=("record-%d-" % number) + "x" * 230)
            sink.close()
            segments = list((root / "logs").glob("controller.jsonl*"))
            self.assertLessEqual(len(segments), playground.CHILD_LOG_SEGMENTS)
            self.assertLessEqual(
                sum(path.stat().st_size for path in segments),
                playground.CHILD_LOG_SEGMENT_BYTES * playground.CHILD_LOG_SEGMENTS,
            )
            for path in segments:
                for line in path.read_text(encoding="utf-8").splitlines():
                    self.assertIsInstance(json.loads(line), dict)

    def test_tui_wide_input_accepts_unicode_and_preserves_byte_bound(self) -> None:
        exact = "x" * (playground.MAX_COMMAND_LINE_CHARACTERS - 4)
        self.assertEqual(playground.tui_append_character(exact, "🙂"), exact + "🙂")
        self.assertEqual(playground.tui_append_character(exact + "x", "🙂"), exact + "x")

        temporary = tempfile.TemporaryDirectory()
        init = initialized_root(Path(temporary.name), 2)
        network = FakeNetwork(init)
        sink = playground.EventSink(init.root, "tui", io.StringIO(), io.StringIO())
        controller = playground.PlaygroundController(
            init,
            Path("/fake/aster-agent"),
            sink,
            startup_timeout=1,
            poll_seconds=0.01,
            process_factory=network.process_factory,
            client_factory=network.client_factory,
            publisher_factory=network.publisher_factory,
            port_reservations=[FakeReservation(19800 + index) for index in range(2)],
        )
        controller.start()

        class FakeCursesError(Exception):
            pass

        class FakeScreen:
            def __init__(self):
                self.keys = (
                    list("send 0 héx")
                    + [263]
                    + list("llo")
                    + [343]
                    + list("q")
                    + [343]
                )

            def keypad(self, _enabled):
                return None

            def timeout(self, _milliseconds):
                return None

            def getmaxyx(self):
                return (24, 100)

            def erase(self):
                return None

            def addnstr(self, *_arguments):
                return None

            def move(self, *_arguments):
                return None

            def refresh(self):
                return None

            def get_wch(self):
                if not self.keys:
                    raise FakeCursesError()
                return self.keys.pop(0)

        screen = FakeScreen()
        fake_curses = types.SimpleNamespace(
            error=FakeCursesError,
            KEY_BACKSPACE=263,
            KEY_ENTER=343,
            curs_set=lambda _visibility: None,
            wrapper=lambda application: application(screen),
        )
        try:
            processor = playground.CommandProcessor(controller)
            with mock.patch.dict(sys.modules, {"curses": fake_curses}):
                playground.run_tui(processor, controller)
            record = controller.resolve_alias("m1")
            self.assertEqual(record.payload, "héllo".encode("utf-8"))
        finally:
            controller.close()
            sink.close()
            temporary.cleanup()


class RpcFixture:
    def __init__(self) -> None:
        event_one = self.event(1, b"one")
        event_two = self.event(2, b"two")
        fixture = self

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, _format: str, *_arguments: object) -> None:
                return

            def do_POST(self) -> None:
                length = int(self.headers.get("Content-Length", "0"))
                body = self.rfile.read(length)
                fixture.requests.append((self.path, dict(self.headers), json.loads(body)))
                if self.headers.get("Authorization") != "Bearer exact-token-value-000000000000":
                    response = {"code": "unauthenticated", "message": "no"}
                    encoded = json.dumps(response).encode("utf-8")
                    self.send_response(401)
                    self.send_header("Content-Type", "application/json")
                    self.send_header("Content-Length", str(len(encoded)))
                    self.end_headers()
                    self.wfile.write(encoded)
                    return
                method = self.path.rsplit("/", 1)[-1]
                if method == "GetStatus" and fixture.redirect:
                    self.send_response(302)
                    self.send_header("Location", "http://192.0.2.1/bearer-leak")
                    self.send_header("Content-Length", "0")
                    self.end_headers()
                    return
                if method == "GetStatus":
                    response = {
                        "sync": "SYNC_STATUS_LAST_CONTACT_COMPLETE",
                        "authenticatedContacts": "4",
                        "failedContactAttempts": "1",
                        "peers": [],
                    }
                elif method == "CreateEventSubscription":
                    response = {"subscriptionId": base64.b64encode(b"s" * 32).decode("ascii"), "inserted": True}
                elif method == "QueryEvents":
                    marker = int(fixture.requests[-1][2].get("afterAcceptanceMarker", "0"))
                    if marker == 0:
                        response = {"events": [event_one], "scannedThrough": "1", "hasMore": True}
                    else:
                        response = {"events": [event_two], "scannedThrough": "2", "hasMore": False}
                else:
                    response = {"code": "not_found"}
                encoded = json.dumps(response).encode("utf-8")
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(encoded)))
                self.end_headers()
                self.wfile.write(encoded)

        self.requests = []
        self.redirect = False
        self.server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()

    @staticmethod
    def event(number: int, payload: bytes) -> dict:
        return {
            "id": base64.b64encode(bytes([number]) * 32).decode("ascii"),
            "publisher": base64.b64encode(bytes([9]) * 32).decode("ascii"),
            "publisherCounter": str(number),
            "eventSequence": str(number),
            "topic": playground.TOPIC,
            "scope": playground.SCOPE,
            "priority": "PRIORITY_ROUTINE",
            "logicalKey": base64.b64encode(b"key").decode("ascii"),
            "payload": base64.b64encode(payload).decode("ascii"),
            "tombstone": False,
            "acceptanceMarker": str(number),
        }

    @property
    def url(self) -> str:
        return "http://127.0.0.1:%d" % self.server.server_address[1]

    def close(self) -> None:
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=2)


class RpcTests(unittest.TestCase):
    def test_stdlib_connect_json_auth_and_pagination(self) -> None:
        fixture = RpcFixture()
        try:
            client = playground.ConnectJsonClient(fixture.url, "exact-token-value-000000000000")
            status = client.get_status()
            self.assertEqual(status["authenticatedContacts"], "4")
            subscription = client.create_subscription(b"operation")
            self.assertEqual(len(playground.decode_b64(subscription["subscriptionId"], "id")), 32)
            events, marker = client.query_events(0)
            self.assertEqual(marker, 2)
            self.assertEqual([base64.b64decode(event["payload"]) for event in events], [b"one", b"two"])
            self.assertEqual(len([request for request in fixture.requests if request[0].endswith("QueryEvents")]), 2)
            self.assertTrue(
                all(request[1].get("Content-Type") == "application/json" for request in fixture.requests)
            )
        finally:
            fixture.close()

    def test_bad_bearer_is_a_sanitized_rpc_failure(self) -> None:
        fixture = RpcFixture()
        try:
            client = playground.ConnectJsonClient(fixture.url, "wrong-token-value-0000000000000")
            with self.assertRaisesRegex(playground.RpcError, "HTTP 401"):
                client.get_status()
        finally:
            fixture.close()

    def test_proxy_environment_cannot_receive_loopback_bearer_or_payload(self) -> None:
        fixture = RpcFixture()
        try:
            proxy_environment = {
                "HTTP_PROXY": "http://192.0.2.1:9",
                "HTTPS_PROXY": "http://192.0.2.1:9",
                "ALL_PROXY": "http://192.0.2.1:9",
                "NO_PROXY": "",
                "http_proxy": "http://192.0.2.1:9",
                "https_proxy": "http://192.0.2.1:9",
                "all_proxy": "http://192.0.2.1:9",
                "no_proxy": "",
            }
            with mock.patch.dict(os.environ, proxy_environment, clear=False):
                client = playground.ConnectJsonClient(
                    fixture.url,
                    "exact-token-value-000000000000",
                )
                self.assertEqual(client.get_status()["authenticatedContacts"], "4")
            self.assertEqual(len(fixture.requests), 1)
            self.assertEqual(
                fixture.requests[0][1].get("Authorization"),
                "Bearer exact-token-value-000000000000",
            )
        finally:
            fixture.close()

    def test_loopback_redirect_is_rejected_without_forwarding_authorization(self) -> None:
        fixture = RpcFixture()
        fixture.redirect = True
        try:
            client = playground.ConnectJsonClient(fixture.url, "exact-token-value-000000000000")
            with self.assertRaisesRegex(playground.RpcError, "HTTP 302"):
                client.get_status()
            self.assertEqual(len(fixture.requests), 1)
        finally:
            fixture.close()


class ManagedProcessTests(unittest.TestCase):
    def test_ready_process_is_stopped_and_logs_are_drained(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            code = (
                "import signal,sys,time;"
                "signal.signal(signal.SIGINT,lambda *_:sys.exit(0));"
                "print('AGENT status=ready listen=http://127.0.0.1:4567',flush=True);"
                "print('diagnostic',file=sys.stderr,flush=True);"
                "time.sleep(60)"
            )
            process = playground.ManagedProcess(
                [sys.executable, "-c", code],
                root / "stdout",
                root / "stderr",
            )
            self.assertEqual(process.wait_ready(3), "http://127.0.0.1:4567")
            self.assertEqual(process.stop(2), 0)
            self.assertIsNotNone(process.poll())
            self.assertIn(b"AGENT status=ready", (root / "stdout").read_bytes())
            self.assertIn(b"diagnostic", (root / "stderr").read_bytes())

    def test_process_failure_before_ready_is_reported_and_reaped(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            process = playground.ManagedProcess(
                [sys.executable, "-c", "import sys;print('broken',file=sys.stderr);sys.exit(7)"],
                root / "stdout",
                root / "stderr",
            )
            with self.assertRaisesRegex(playground.PlaygroundError, "status 7"):
                process.wait_ready(3)
            self.assertEqual(process.stop(1), 7)

    def test_oversized_unterminated_line_is_bounded_without_false_readiness(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            code = (
                "import os,signal,sys,time;"
                "signal.signal(signal.SIGINT,lambda *_:sys.exit(0));"
                "os.write(1,b'x'*%d+b'AGENT status=ready listen=http://127.0.0.1:9999\\n');"
                "os.write(1,b'AGENT status=ready listen=http://127.0.0.1:4567\\n');"
                "time.sleep(60)"
            ) % (playground.MAX_PARSED_LINE_BYTES + 1024)
            process = playground.ManagedProcess(
                [sys.executable, "-c", code],
                root / "stdout",
                root / "stderr",
            )
            self.assertEqual(process.wait_ready(3), "http://127.0.0.1:4567")
            self.assertEqual(process.stop(2), 0)
            logged = (root / "stdout").read_bytes()
            self.assertIn(b"127.0.0.1:9999", logged)
            self.assertTrue(logged.endswith(b"127.0.0.1:4567\n"))

    def test_child_output_rotates_with_an_enforced_retained_cap(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            byte_count = (
                playground.CHILD_LOG_SEGMENT_BYTES * playground.CHILD_LOG_SEGMENTS
                + playground.MAX_PARSED_LINE_BYTES
            )
            code = (
                "import os,signal,sys,time;"
                "signal.signal(signal.SIGINT,lambda *_:sys.exit(0));"
                "os.write(1,b'z'*%d+b'\\n');"
                "os.write(1,b'AGENT status=ready listen=http://127.0.0.1:4567\\n');"
                "time.sleep(60)"
            ) % byte_count
            process = playground.ManagedProcess(
                [sys.executable, "-c", code],
                root / "stdout",
                root / "stderr",
            )
            self.assertEqual(process.wait_ready(5), "http://127.0.0.1:4567")
            self.assertEqual(process.stop(2), 0)
            segments = list(root.glob("stdout*"))
            self.assertLessEqual(len(segments), playground.CHILD_LOG_SEGMENTS)
            self.assertLessEqual(
                sum(path.stat().st_size for path in segments),
                playground.CHILD_LOG_SEGMENT_BYTES * playground.CHILD_LOG_SEGMENTS,
            )
            self.assertIn(b"127.0.0.1:4567", (root / "stdout").read_bytes())

    @unittest.skipUnless(os.name == "posix", "process-group sweep is POSIX-specific")
    def test_cleanup_kills_resistant_descendant_after_group_leader_exits(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            descendant = (
                "import signal,time;"
                "signal.signal(signal.SIGINT,signal.SIG_IGN);"
                "signal.signal(signal.SIGTERM,signal.SIG_IGN);"
                "time.sleep(60)"
            )
            code = (
                "import signal,subprocess,sys,time;"
                "child=subprocess.Popen([sys.executable,'-c',%r]);"
                "signal.signal(signal.SIGINT,lambda *_:sys.exit(0));"
                "print('CHILD pid=%%d'%%child.pid,flush=True);"
                "print('AGENT status=ready listen=http://127.0.0.1:4567',flush=True);"
                "time.sleep(60)"
            ) % descendant
            process = playground.ManagedProcess(
                [sys.executable, "-c", code],
                root / "stdout",
                root / "stderr",
            )
            descendant_pid = None
            try:
                self.assertEqual(process.wait_ready(3), "http://127.0.0.1:4567")
                for line in (root / "stdout").read_text(encoding="utf-8").splitlines():
                    if line.startswith("CHILD pid="):
                        descendant_pid = int(line.split("=", 1)[1])
                self.assertIsNotNone(descendant_pid)
                self.assertEqual(process.stop(0.2), 0)
                with self.assertRaises(ProcessLookupError):
                    os.kill(descendant_pid, 0)
            finally:
                if process.poll() is None:
                    process.force_stop()
                if descendant_pid is not None:
                    try:
                        os.kill(descendant_pid, signal.SIGKILL)
                    except ProcessLookupError:
                        pass


class FakeProcess:
    next_pid = 50000

    def __init__(self, command, stdout_path, stderr_path) -> None:
        self.command = list(command)
        self.stdout_path = stdout_path
        self.stderr_path = stderr_path
        stdout_path.parent.mkdir(parents=True, exist_ok=True)
        stdout_path.write_bytes(b"")
        stderr_path.write_bytes(b"")
        FakeProcess.next_pid += 1
        self.pid = FakeProcess.next_pid
        self.index = int(stdout_path.parent.name.split("-")[-1])
        self.ready_url = "http://127.0.0.1:%d" % (18000 + self.index)
        self.returncode = None
        self.stopped = False

    def wait_ready(self, _timeout: float) -> str:
        return self.ready_url

    def poll(self):
        return self.returncode

    def stop(self, _graceful_seconds: float = 4.0) -> int:
        self.stopped = True
        self.returncode = 0
        return 0

    def force_stop(self) -> int:
        self.stopped = True
        self.returncode = -signal.SIGKILL
        return self.returncode

    def close_streams(self) -> None:
        return


class FakeReservation:
    def __init__(self, port: int) -> None:
        self.port = port
        self.closed = False

    def getsockname(self):
        return ("127.0.0.1", self.port)

    def close(self) -> None:
        self.closed = True


class FakeNetwork:
    def __init__(self, init: playground.InitResult) -> None:
        self.init = init
        self.events = []
        self.commands = []
        self.processes = []
        self.publication_results = {}
        self.publication_frontiers = {}

    def process_factory(self, command, stdout_path, stderr_path):
        process = FakeProcess(command, stdout_path, stderr_path)
        self.commands.append(list(command))
        self.processes.append(process)
        return process

    def client_factory(self, url: str, _token: str):
        index = int(url.rsplit(":", 1)[-1]) - 18000
        return FakeClient(self, index)

    def publisher_factory(self, cli, journal, client_id):
        index = int(client_id.split("/")[1].split("-")[1])
        return FakePublisher(self, index, journal)


class FakePublisher:
    def __init__(self, network, index, journal):
        self.network, self.index, self.journal = network, index, journal
        self.pending = None
        self.next_sequence = 1

    def initialize(self):
        with self.journal.open("xb") as stream:
            stream.write(b"test publication journal")

    def connect(self, url, token_path):
        self.client = FakeClient(self.network, self.index)

    def recover(self, apply):
        if self.pending is not None:
            sequence, logical_key, payload = self.pending
            response = self._send(sequence, logical_key, payload)
            apply({"payload": base64.b64encode(payload).decode("ascii")}, response["result"], True, None)
            self.network.publication_results.pop((self.index, sequence))
            self.pending = None

    def _send(self, sequence, logical_key, payload):
        return self.client.publish_numbered(sequence, logical_key, payload)

    def publish(self, logical_key, payload, apply):
        if not self.journal.exists():
            raise playground.RpcError("publication journal is missing")
        self.recover(apply)
        sequence = self.next_sequence
        self.next_sequence += 1
        self.pending = (sequence, logical_key, payload)
        response = self._send(sequence, logical_key, payload)
        alias = apply({"payload": base64.b64encode(payload).decode("ascii")}, response["result"], False, response["inserted"])
        self.network.publication_results.pop((self.index, sequence))
        self.pending = None
        return alias


class FakeClient:
    def __init__(self, network: FakeNetwork, index: int) -> None:
        self.network = network
        self.index = index

    def create_subscription(self, _operation_key: bytes) -> dict:
        return {"subscriptionId": base64.b64encode(bytes([self.index + 1]) * 32).decode("ascii")}

    def get_status(self) -> dict:
        return {
            "sync": "SYNC_STATUS_LAST_CONTACT_COMPLETE",
            "authenticatedContacts": "2",
            "failedContactAttempts": "0",
            "peers": [],
        }

    def publish_numbered(self, sequence: int, logical_key: bytes, payload: bytes) -> dict:
        identity = (self.index, sequence)
        retained = self.network.publication_results.get(identity)
        if retained is not None:
            intent, result = retained
            if intent != (logical_key, payload):
                raise playground.RpcError("conflicting numbered intent")
            return {"result": result, "inserted": False}
        if sequence != self.network.publication_frontiers.get(self.index, 0) + 1:
            raise playground.RpcError("numbered sequence gap or retired sequence")
        event_id = hashlib.sha256(bytes([self.index]) + payload + bytes([len(self.network.events)])).digest()
        event = {
            "id": base64.b64encode(event_id).decode("ascii"),
            "publisher": base64.b64encode(bytes.fromhex(self.network.init.nodes[self.index].mission_id)).decode("ascii"),
            "eventSequence": str(len(self.network.events) + 1),
            "topic": playground.TOPIC,
            "scope": playground.SCOPE,
            "payload": base64.b64encode(payload).decode("ascii"),
        }
        self.network.events.append(event)
        result = {"operationSequence": str(sequence), "receipt": {"eventId": event["id"], "transferId": event["id"], "acceptanceMarker": str(len(self.network.events))}, "content": "COMMITTED_CONTENT_STATUS_AVAILABLE"}
        self.network.publication_frontiers[self.index] = sequence
        self.network.publication_results[identity] = ((logical_key, payload), result)
        return {"result": result, "inserted": True}

    def query_events(self, after_marker: int):
        return list(self.network.events[after_marker:]), len(self.network.events)


class ControllerAndScriptTests(unittest.TestCase):
    def make_controller(
        self,
        nodes: int = 3,
        *,
        hello: bool = False,
        network_provenance: str = "direct",
    ):
        temporary = tempfile.TemporaryDirectory()
        init = initialized_root(Path(temporary.name), nodes)
        network = FakeNetwork(init)
        output = io.StringIO()
        sink = playground.EventSink(init.root, "plain", output, io.StringIO())
        controller = playground.PlaygroundController(
            init,
            Path("/fake/aster-agent"),
            sink,
            startup_timeout=1,
            poll_seconds=0.01,
            process_factory=network.process_factory,
            client_factory=network.client_factory,
            publisher_factory=network.publisher_factory,
            port_reservations=[FakeReservation(19000 + index) for index in range(nodes)],
            hello=hello,
            network_provenance=network_provenance,
        )
        controller.start()
        return temporary, network, output, sink, controller

    def test_real_process_shape_and_reconfiguration_commands_retain_model(self) -> None:
        temporary, network, _output, sink, controller = self.make_controller()
        try:
            initial = network.commands[:3]
            peer_counts = [command.count("--peer") for command in initial]
            self.assertEqual(peer_counts, [1, 2, 1])
            initial_pids = [node.pid for node in controller.nodes]
            controller.isolate(1)
            self.assertEqual(controller.topology.neighbors(1), set())
            isolated = network.commands[-3:]
            self.assertEqual([command.count("--peer") for command in isolated], [0, 0, 0])
            self.assertNotEqual([node.pid for node in controller.nodes], initial_pids)
            controller.rejoin(1)
            self.assertEqual(controller.topology.neighbors(1), {0, 2})
            controller.stop_node(2)
            self.assertEqual(controller.nodes[2].status, "stopped")
            controller.start_node(2)
            self.assertEqual(controller.nodes[2].status, "ready")
        finally:
            controller.close()
            sink.close()
            self.assertTrue(all(process.stopped for process in network.processes))
            temporary.cleanup()

    def test_invitation_hello_stages_named_nodes_and_human_commands(self) -> None:
        temporary, network, output, sink, controller = self.make_controller(
            hello=True,
            network_provenance="invitation",
        )
        try:
            self.assertEqual(network.commands, [])
            self.assertEqual(
                [(node.name, node.activated, node.status) for node in controller.nodes],
                [
                    ("atlas", False, "available"),
                    ("beacon", False, "available"),
                    ("cove", False, "available"),
                ],
            )
            processor = playground.CommandProcessor(controller)
            with self.assertRaisesRegex(playground.PlaygroundError, "add or use"):
                processor.execute("note written before anyone exists")

            processor.execute("add atlas")
            self.assertEqual(controller.selected_index, 0)
            self.assertEqual(len(network.commands), 1)
            self.assertIn("--peer", network.commands[0])
            self.assertNotIn("--nearby-peer", network.commands[0])
            self.assertEqual(
                network.commands[0][network.commands[0].index("--sync-ms") + 1],
                str(playground.HELLO_SYNC_MILLISECONDS),
            )
            processor.execute("note written before anyone else exists")
            processor.execute("add beacon")
            self.assertEqual(len(network.commands), 2)
            processor.execute("use atlas")
            processor.execute("sleep atlas")
            self.assertEqual(controller.nodes[0].status, "stopped")
            processor.execute("wake atlas")
            self.assertEqual(controller.nodes[0].status, "ready")
            processor.execute("wait-seen last atlas,beacon 2")
            self.assertEqual(controller.resolve_alias("last").seen, {0, 1})
            self.assertIn("ROUTE invitation", output.getvalue())
            self.assertIn("fallback=none", output.getvalue())
            self.assertIn("published-by=atlas", output.getvalue())
        finally:
            controller.close()
            sink.close()
            temporary.cleanup()

    def test_nearby_hello_uses_only_bounded_identity_hints_and_reopens_windows(self) -> None:
        temporary, network, output, sink, controller = self.make_controller(
            hello=True,
            network_provenance="nearby",
        )
        try:
            processor = playground.CommandProcessor(controller)
            processor.execute("add atlas")
            self.assertEqual(len(network.commands), 1)
            processor.execute("note cache this note")
            processor.execute("add beacon")
            self.assertEqual(
                len(network.commands),
                3,
                "adding beacon restarts atlas so both ten-second windows overlap",
            )
            processor.execute("add cove")
            self.assertEqual(
                len(network.commands),
                6,
                "the activated three-node roster receives one overlapping nearby window",
            )

            for command in network.commands:
                self.assertNotIn("--peer", command)
                self.assertIn("--nearby-peer", command)
                self.assertEqual(
                    command[command.index("--sync-ms") + 1],
                    str(playground.HELLO_SYNC_MILLISECONDS),
                )
                self.assertEqual(
                    command[command.index("--nearby-window") + 1],
                    str(playground.HELLO_NEARBY_WINDOW_SECONDS),
                )
                for offset, value in enumerate(command):
                    if value == "--nearby-peer":
                        hint = command[offset + 1]
                        carrier, mission = hint.split("=", 1)
                        self.assertRegex(carrier, r"^[0-9a-f]{64}$")
                        self.assertRegex(mission, r"^[0-9a-f]{64}$")
                        self.assertNotIn("127.0.0.1", hint)
            self.assertEqual(controller.network_provenance, "nearby")
            self.assertIn("ROUTE nearby window=10s fallback=none", output.getvalue())
        finally:
            controller.close()
            sink.close()
            temporary.cleanup()

    def test_scripted_send_exact_presence_wait_and_restart(self) -> None:
        temporary, _network, output, sink, controller = self.make_controller()
        try:
            processor = playground.CommandProcessor(controller)
            script = io.StringIO(
                "send 0 hello from node zero\n"
                "wait-seen last 0,1,2 2\n"
                "stop 0\n"
                "start 0\n"
                "status\n"
                "quit\n"
            )
            self.assertTrue(playground.run_script(processor, script, sink))
            record = controller.resolve_alias("last")
            self.assertEqual(record.payload, b"hello from node zero")
            self.assertEqual(record.seen, {0, 1, 2})
            self.assertIn("exact-event=true", output.getvalue())
            self.assertIn("WAIT m1 status=pass", output.getvalue())
        finally:
            controller.close()
            sink.close()
            temporary.cleanup()

    def test_command_parser_rejects_unsafe_or_incomplete_requests(self) -> None:
        temporary, _network, _output, sink, controller = self.make_controller(2)
        try:
            processor = playground.CommandProcessor(controller)
            with self.assertRaisesRegex(playground.PlaygroundError, "usage"):
                processor.execute("send 0")
            with self.assertRaisesRegex(playground.PlaygroundError, "unknown command"):
                processor.execute("destroy everything")
            with self.assertRaisesRegex(playground.PlaygroundError, "within"):
                processor.execute("isolate 7")
            with self.assertRaisesRegex(playground.PlaygroundError, "4096-byte"):
                processor.execute("send 0 " + "x" * 4097)
            for value in ("nan", "inf", "3601"):
                with self.assertRaisesRegex(playground.PlaygroundError, "finite"):
                    processor.execute("wait-all " + value)
        finally:
            controller.close()
            sink.close()
            temporary.cleanup()

    def test_uncertain_publish_recovers_the_original_sequence_before_allocating_new_work(self) -> None:
        temporary, network, _output, sink, controller = self.make_controller(2)
        try:
            publisher = controller.nodes[0].publisher
            calls = []
            original_send = publisher._send

            def lose_first_reply(sequence, logical_key, payload):
                calls.append((sequence, logical_key, payload))
                response = original_send(sequence, logical_key, payload)
                if len(calls) == 1:
                    raise playground.RpcError("uncertain local reply after commit")
                return response

            publisher._send = lose_first_reply
            with self.assertRaisesRegex(playground.RpcError, "uncertain"):
                controller.send(0, "first attempt")
            self.assertIsNotNone(publisher.pending)
            controller.stop_node(0)
            controller.start_node(0)
            self.assertIsNone(publisher.pending, "node replacement recovers the original publication")
            self.assertEqual(len(network.events), 1)
            alias = controller.send(0, "second attempt")
            self.assertEqual(alias, "m2")
            self.assertEqual(len(calls), 3)
            self.assertEqual(calls[0], calls[1], "recovery must replay the original sequence and complete intent")
            self.assertEqual(calls[2][0], 2)
            self.assertEqual(len(network.events), 2, "lost receipt must not duplicate the first Event")
            self.assertIsNone(publisher.pending)
            self.assertEqual(network.publication_results, {}, "results are acknowledged after application")
            controller._operation_counter = playground.MAX_TRACKED_MESSAGES
            with self.assertRaisesRegex(playground.PlaygroundError, "attempt limit"):
                controller.send(0, "one too many")
        finally:
            controller.close()
            sink.close()
            temporary.cleanup()

    def test_lifecycle_progress_and_status_are_visible_to_the_tui_model(self) -> None:
        temporary, _network, _output, sink, controller = self.make_controller()
        try:
            transitions = []
            controller.progress_callback = lambda: transitions.append(
                tuple(node.status for node in controller.nodes)
            )
            controller.isolate(1)
            flattened = {status for transition in transitions for status in transition}
            self.assertTrue({"reconfiguring", "stopped", "starting", "ready"} <= flattened)
            processor = playground.CommandProcessor(controller)
            processor.execute("status 1")
            self.assertIn("n1 ready", processor.last_notice)
            self.assertIn("contacts=", processor.last_notice)
            self.assertIn("pid=", processor.last_notice)
            controller.nodes[1].observer = "error"
            controller.nodes[1].observer_error = "stale"
            controller.stop_node(1)
            controller.start_node(1)
            self.assertEqual(controller.nodes[1].observer, "pending")
            self.assertEqual(controller.nodes[1].observer_error, "")
        finally:
            controller.progress_callback = None
            controller.close()
            sink.close()
            temporary.cleanup()

    def test_close_reconciles_dead_child_and_attempts_every_process(self) -> None:
        temporary, network, _output, sink, controller = self.make_controller(3)
        try:
            network.processes[0].returncode = 9
            bad = network.processes[2]

            def fail_stop(_graceful_seconds=4.0):
                raise OSError("synthetic stop failure")

            bad.stop = fail_stop
            with self.assertRaisesRegex(playground.PlaygroundError, "n2"):
                controller.close()
            self.assertTrue(controller.had_process_failure)
            self.assertTrue(all(process.stopped for process in network.processes))
        finally:
            controller.close()
            sink.close()
            temporary.cleanup()

    def test_failed_close_retains_handle_and_later_close_retries(self) -> None:
        temporary, network, _output, sink, controller = self.make_controller(2)
        bad = network.processes[1]

        def fail_cleanup(*_arguments):
            raise OSError("synthetic persistent cleanup failure")

        bad.stop = fail_cleanup
        bad.force_stop = fail_cleanup
        try:
            with self.assertRaises(playground.PlaygroundError):
                controller.close()
            self.assertIs(controller.nodes[1].process, bad)
            self.assertFalse(controller._closed)
            bad.stop = FakeProcess.stop.__get__(bad, FakeProcess)
            bad.force_stop = FakeProcess.force_stop.__get__(bad, FakeProcess)
            controller.close()
            self.assertTrue(controller._closed)
            self.assertTrue(bad.stopped)
        finally:
            if not controller._closed:
                bad.stop = FakeProcess.stop.__get__(bad, FakeProcess)
                bad.force_stop = FakeProcess.force_stop.__get__(bad, FakeProcess)
                controller.close()
            sink.close()
            temporary.cleanup()

    def test_poll_retains_handle_when_descendant_sweep_fails(self) -> None:
        temporary, network, _output, sink, controller = self.make_controller(2)
        process = network.processes[0]
        process.returncode = 9

        def fail_force():
            raise OSError("synthetic descendant sweep failure")

        process.force_stop = fail_force
        try:
            controller.poll_once()
            self.assertIs(controller.nodes[0].process, process)
            self.assertEqual(controller.nodes[0].status, "failed")
            self.assertIn("descendant cleanup failed", controller.nodes[0].error)
        finally:
            process.force_stop = FakeProcess.force_stop.__get__(process, FakeProcess)
            controller.close()
            sink.close()
            temporary.cleanup()

    def test_startup_keyboard_interrupt_is_not_wrapped_as_status_one(self) -> None:
        temporary = tempfile.TemporaryDirectory()
        init = initialized_root(Path(temporary.name), 2)
        network = FakeNetwork(init)
        sink = playground.EventSink(init.root, "plain", io.StringIO(), io.StringIO())

        def process_factory(command, stdout_path, stderr_path):
            process = network.process_factory(command, stdout_path, stderr_path)
            if len(network.processes) == 1:
                def interrupt(_timeout):
                    raise KeyboardInterrupt
                process.wait_ready = interrupt
            return process

        controller = playground.PlaygroundController(
            init,
            Path("/fake/aster-agent"),
            sink,
            startup_timeout=1,
            poll_seconds=60,
            process_factory=process_factory,
            client_factory=network.client_factory,
            publisher_factory=network.publisher_factory,
            port_reservations=[FakeReservation(19500 + index) for index in range(2)],
        )
        try:
            with self.assertRaises(KeyboardInterrupt):
                controller.start()
            self.assertFalse(controller.had_process_failure)
            self.assertTrue(all(process.stopped for process in network.processes))
        finally:
            controller.close()
            sink.close()
            temporary.cleanup()

    def test_unexpected_process_exit_is_retained_as_a_controller_failure(self) -> None:
        temporary, network, _output, sink, controller = self.make_controller(2)
        try:
            network.processes[0].returncode = 9
            controller.poll_once()
            self.assertTrue(controller.had_process_failure)
            self.assertTrue(network.processes[0].stopped)
            self.assertEqual(controller.nodes[0].status, "failed")
            self.assertIn("status 9", controller.nodes[0].error)
        finally:
            controller.close()
            sink.close()
            temporary.cleanup()

    def test_startup_cleanup_failure_retains_process_handle_for_close_retry(self) -> None:
        temporary = tempfile.TemporaryDirectory()
        init = initialized_root(Path(temporary.name), 2)
        network = FakeNetwork(init)
        sink = playground.EventSink(init.root, "plain", io.StringIO(), io.StringIO())

        def process_factory(command, stdout_path, stderr_path):
            process = network.process_factory(command, stdout_path, stderr_path)
            if len(network.processes) == 1:
                def fail_ready(_timeout):
                    raise playground.PlaygroundError("synthetic readiness failure")
                def fail_cleanup(*_arguments):
                    raise OSError("synthetic cleanup failure")
                process.wait_ready = fail_ready
                process.stop = fail_cleanup
                process.force_stop = fail_cleanup
            return process

        controller = playground.PlaygroundController(
            init,
            Path("/fake/aster-agent"),
            sink,
            startup_timeout=1,
            poll_seconds=60,
            process_factory=process_factory,
            client_factory=network.client_factory,
            publisher_factory=network.publisher_factory,
            port_reservations=[FakeReservation(19600 + index) for index in range(2)],
        )
        try:
            with self.assertRaises(playground.PlaygroundError):
                controller.start()
            failed = network.processes[0]
            self.assertIs(controller.nodes[0].process, failed)
            self.assertEqual(controller.nodes[0].pid, failed.pid)
            failed.stop = FakeProcess.stop.__get__(failed, FakeProcess)
            failed.force_stop = FakeProcess.force_stop.__get__(failed, FakeProcess)
        finally:
            controller.close()
            sink.close()
            temporary.cleanup()

    def test_observer_failure_is_visible_and_slow_io_does_not_hold_model_lock(self) -> None:
        temporary, _network, output, sink, controller = self.make_controller(2)
        original = controller.nodes[0].client
        self.assertIsNotNone(original)

        class BrokenClient:
            def get_status(self):
                raise playground.RpcError("synthetic observer unavailable")

        try:
            controller.nodes[0].client = BrokenClient()
            controller.poll_once()
            snapshot = controller.snapshot()
            self.assertEqual(snapshot["nodes"][0]["observer"], "error")
            self.assertTrue(
                any("observer-error" in line for line in playground.render_dashboard(snapshot, 90, 20, False))
            )
            self.assertIn("OBSERVER n0 error=", output.getvalue())
            controller.status(0)
            self.assertIn("observer=error", output.getvalue())
            self.assertIn("contacts=", output.getvalue())

            entered = threading.Event()
            release = threading.Event()

            class SlowClient:
                def get_status(self):
                    entered.set()
                    release.wait(5)
                    return original.get_status()

                def query_events(self, marker):
                    return original.query_events(marker)

            controller.nodes[0].client = SlowClient()
            poll = threading.Thread(target=controller.poll_once)
            poll.start()
            self.assertTrue(entered.wait(1))
            started = time.monotonic()
            controller.snapshot()
            self.assertLess(time.monotonic() - started, 0.2)
            started = time.monotonic()
            controller.close()
            self.assertLess(time.monotonic() - started, 1.0)
            release.set()
            poll.join(timeout=2)
            self.assertFalse(poll.is_alive())
        finally:
            release.set() if "release" in locals() else None
            controller.close()
            sink.close()
            temporary.cleanup()

    def test_oversized_observed_event_is_fatal_and_does_not_advance_marker(self) -> None:
        temporary, _network, _output, sink, controller = self.make_controller(2)
        node = controller.nodes[0]
        original_client = node.client

        class OversizedClient:
            def get_status(self):
                return original_client.get_status()

            def query_events(self, _marker):
                event = RpcFixture.event(7, b"x" * (playground.MAX_MESSAGE_BYTES + 1))
                event["publisher"] = base64.b64encode(
                    bytes.fromhex(controller.nodes[0].init.mission_id)
                ).decode("ascii")
                return [event], 7

        try:
            node.client = OversizedClient()
            controller.poll_once()
            self.assertEqual(node.query_marker, 0)
            self.assertEqual(len(controller.events), 0)
            self.assertEqual(node.observer, "error")
            self.assertTrue(controller.had_fatal_failure)
        finally:
            controller.close()
            sink.close()
            temporary.cleanup()

    def test_wait_deadline_is_not_extended_by_a_stalled_observer(self) -> None:
        temporary, _network, _output, sink, controller = self.make_controller(2)
        original = controller.nodes[0].client
        entered = threading.Event()
        release = threading.Event()

        class SlowClient:
            def get_status(self):
                entered.set()
                release.wait(5)
                return original.get_status()

            def query_events(self, marker):
                return original.query_events(marker)

        try:
            controller.nodes[0].client = SlowClient()
            self.assertTrue(entered.wait(1))
            alias = controller.send(1, "deadline-bound")
            started = time.monotonic()
            with self.assertRaisesRegex(playground.PlaygroundError, "deadline"):
                controller.wait_seen(alias, [0], 0.2)
            self.assertLess(time.monotonic() - started, 0.5)
        finally:
            release.set()
            controller.close()
            sink.close()
            temporary.cleanup()

    def test_script_assert_unseen_uses_one_fresh_exact_query_view(self) -> None:
        temporary, _network, output, sink, controller = self.make_controller(3)
        controller._poll_stop.set()
        controller._poll_thread.join(timeout=1)
        original = controller.nodes[2].client
        queries = []

        class AbsentClient:
            def get_status(self):
                return original.get_status()

            def query_events(self, marker):
                queries.append(marker)
                return [], marker

        try:
            controller.nodes[2].client = AbsentClient()
            processor = playground.CommandProcessor(controller)
            script = io.StringIO(
                "send 0 snapshot-only\n"
                "assert-unseen m1 2\n"
                "quit\n"
            )
            self.assertTrue(playground.run_script(processor, script, sink))
            self.assertIn(0, queries)
            self.assertIn("ASSERT-UNSEEN m1 status=pass", output.getvalue())
            self.assertIn("snapshot-only=true", output.getvalue())

            controller.nodes[2].client = original
            with self.assertRaisesRegex(playground.PlaygroundError, "is present"):
                controller.assert_unseen("m1", [2])
        finally:
            controller.close()
            sink.close()
            temporary.cleanup()


class ArgumentAndModeTests(unittest.TestCase):
    def test_parser_exposes_stable_controller_contract(self) -> None:
        arguments = playground.build_parser().parse_args(
            [
                "--aster",
                "/tmp/aster",
                "--agent",
                "/tmp/aster-agent",
                "--nodes",
                "8",
                "--view",
                "raw",
                "--script",
                "-",
            ]
        )
        self.assertEqual(arguments.nodes, 8)
        self.assertEqual(arguments.view, "raw")
        self.assertEqual(arguments.script, "-")
        self.assertFalse(arguments.hello)
        self.assertIsNone(arguments.network)
        hello = playground.build_parser().parse_args(
            [
                "--aster",
                "/tmp/aster",
                "--agent",
                "/tmp/aster-agent",
                "--nodes",
                "3",
                "--hello",
                "--network",
                "nearby",
            ]
        )
        self.assertTrue(hello.hello)
        self.assertEqual(hello.network, "nearby")
        self.assertIn("assert-unseen MESSAGE NODE[,NODE...]", playground.HELP_TEXT)
        self.assertIn("add NAME", playground.HELLO_HELP_TEXT)
        smoke = MODULE_PATH.parent / "testdata" / "aster-mesh-playground-real.commands"
        self.assertIn("assert-unseen m1 2", smoke.read_text(encoding="utf-8"))

    def test_non_tty_auto_view_is_plain(self) -> None:
        original_stdin = sys.stdin
        original_stdout = sys.stdout
        try:
            sys.stdin = io.StringIO()
            sys.stdout = io.StringIO()
            self.assertEqual(playground.resolve_view("auto"), "plain")
        finally:
            sys.stdin = original_stdin
            sys.stdout = original_stdout

    def test_timeout_bounds_and_first_signal_exit_status(self) -> None:
        for value in (float("nan"), float("inf"), 0, 301):
            with self.assertRaisesRegex(playground.PlaygroundError, "finite"):
                playground.bounded_timeout(value, "startup timeout", 300)

        latch = playground.InterruptLatch((signal.SIGINT, signal.SIGTERM))
        with mock.patch.object(playground.signal, "signal") as install:
            with self.assertRaises(KeyboardInterrupt):
                latch(signal.SIGTERM, None)
            latch(signal.SIGINT, None)
        self.assertEqual(latch.signum, signal.SIGTERM)
        self.assertEqual(latch.exit_code, 128 + signal.SIGTERM)
        self.assertEqual(
            install.call_args_list,
            [
                mock.call(signal.SIGINT, signal.SIG_IGN),
                mock.call(signal.SIGTERM, signal.SIG_IGN),
            ],
        )

    def test_tui_startup_can_emit_plain_progress_before_switching_modes(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            output = io.StringIO()
            sink = playground.EventSink(root, "plain", output, io.StringIO())
            sink.emit("node", node=0, status="starting")
            sink.set_mode("tui")
            sink.emit("node", node=0, status="ready")
            sink.close()
            self.assertIn("NODE n0 starting", output.getvalue())
            self.assertNotIn("NODE n0 ready", output.getvalue())

    def test_bounded_command_reader_rejects_and_drains_one_oversized_line(self) -> None:
        source = io.StringIO(
            "x" * (playground.MAX_COMMAND_LINE_CHARACTERS + 50) + "\nstatus\n"
        )
        with self.assertRaisesRegex(playground.PlaygroundError, "command line exceeds"):
            playground.read_command_line(source)
        self.assertEqual(playground.read_command_line(source), "status\n")

    def test_wrapper_rejects_reserved_binary_arguments_before_build(self) -> None:
        wrapper = MODULE_PATH.with_name("aster-mesh-playground.sh")
        environment = dict(os.environ)
        environment.pop("ASTER_PLAYGROUND_ASTER_BIN", None)
        environment.pop("ASTER_PLAYGROUND_AGENT_BIN", None)
        result = subprocess.run(
            ["/bin/sh", str(wrapper), "--aster=/tmp/not-allowed", "--nodes", "2"],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env=environment,
            check=False,
        )
        self.assertEqual(result.returncode, 2)
        self.assertIn(b"wrapper-managed", result.stderr)

    def test_wrapper_rejects_one_sided_binary_override_before_build(self) -> None:
        wrapper = MODULE_PATH.with_name("aster-mesh-playground.sh")
        environment = dict(os.environ)
        environment["ASTER_PLAYGROUND_ASTER_BIN"] = "/tmp/one-sided"
        environment.pop("ASTER_PLAYGROUND_AGENT_BIN", None)
        result = subprocess.run(
            ["/bin/sh", str(wrapper), "--nodes", "2"],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env=environment,
            check=False,
        )
        self.assertEqual(result.returncode, 2)
        self.assertIn(b"must be set together", result.stderr)

    def test_hello_wrapper_requires_a_visible_noninteractive_route_choice(self) -> None:
        wrapper = MODULE_PATH.with_name("aster-hello.sh")
        environment = dict(os.environ)
        environment.pop("ASTER_HELLO_NETWORK", None)
        result = subprocess.run(
            ["/bin/sh", str(wrapper)],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env=environment,
            check=False,
        )
        self.assertEqual(result.returncode, 2)
        self.assertIn(b"requires a human network choice", result.stderr)
        self.assertIn(b"nearby", result.stderr)
        self.assertIn(b"invitation", result.stderr)

    def test_playground_wrapper_builds_the_discovery_enabled_agent(self) -> None:
        wrapper = MODULE_PATH.with_name("aster-mesh-playground.sh")
        text = wrapper.read_text(encoding="utf-8")
        self.assertIn("--features aster-agent/nearby-discovery", text)
        syntax = subprocess.run(
            ["/bin/sh", "-n", str(wrapper)],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
        )
        self.assertEqual(syntax.returncode, 0, syntax.stderr.decode("utf-8", errors="replace"))
        hello = MODULE_PATH.with_name("aster-hello.sh")
        syntax = subprocess.run(
            ["/bin/sh", "-n", str(hello)],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
        )
        self.assertEqual(syntax.returncode, 0, syntax.stderr.decode("utf-8", errors="replace"))


if __name__ == "__main__":
    unittest.main(verbosity=2)
