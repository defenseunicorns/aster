from __future__ import annotations

from datetime import datetime, timezone
from io import StringIO
import json
import os
from pathlib import Path
import socket
import stat
import sys
import tempfile
import threading
import time
import unittest
from unittest.mock import patch

from aster_quickstart.attach import AttachServer, follow_records
from aster_quickstart.records import RecordJournal


class AttachTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.parent = Path(self.temporary.name) / "run"
        self.parent.mkdir(mode=0o700)
        self.socket_path = self.parent / "observer.sock"
        self.records = RecordJournal(
            limit=8,
            clock=lambda: datetime(2026, 1, 1, tzinfo=timezone.utc),
        )
        self.server = AttachServer(self.socket_path, self.records, os.getuid())
        self.server.start()
        self.server.bind_runtime_owner(os.getpid())
        self.addCleanup(self.server.close)

    def _request(self, payload: bytes) -> bytes:
        client = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        client.settimeout(1)
        client.connect(str(self.socket_path))
        try:
            client.sendall(payload)
            client.shutdown(socket.SHUT_WR)
            try:
                return client.recv(4096)
            except ConnectionResetError:
                return b""
        finally:
            client.close()

    def test_socket_is_owner_only_and_command_is_an_exact_argument_vector(self):
        parent = self.parent.stat()
        endpoint = self.socket_path.lstat()
        self.assertTrue(stat.S_ISDIR(parent.st_mode))
        self.assertEqual(stat.S_IMODE(parent.st_mode), 0o700)
        self.assertEqual(parent.st_uid, os.getuid())
        self.assertTrue(stat.S_ISSOCK(endpoint.st_mode))
        self.assertEqual(stat.S_IMODE(endpoint.st_mode), 0o600)
        self.assertEqual(endpoint.st_uid, os.getuid())
        command = self.server.command("publisher", "guided")
        self.assertTrue(hasattr(command, "argv"), "observer command must represent argv explicitly")
        self.assertTrue(hasattr(command, "cwd"), "observer command must represent cwd explicitly")
        self.assertEqual(
            list(command.argv),
            [
                sys.executable,
                "-m",
                "aster_quickstart.attach",
                "--socket",
                str(self.socket_path),
                "--role",
                "publisher",
                "--detail",
                "guided",
                "--peer-pid",
                str(os.getpid()),
            ],
        )
        self.assertEqual(command.cwd, Path(__file__).resolve().parents[1])

    def test_client_rejects_socket_whose_peer_pid_is_not_the_validated_launcher(self):
        output = StringIO()

        result = follow_records(
            self.socket_path,
            "publisher",
            "compact",
            output,
            expected_peer_pid=os.getpid() + 1,
        )

        self.assertEqual(result, 1)
        self.assertEqual(output.getvalue(), "")

    def test_client_rejects_insecure_parent_and_symlinked_socket_before_connecting(self):
        self.server.close()
        self.parent.chmod(0o755)
        output = StringIO()
        self.assertEqual(
            follow_records(
                self.socket_path,
                "publisher",
                "compact",
                output,
                expected_peer_pid=os.getpid(),
            ),
            1,
        )
        self.assertEqual(output.getvalue(), "")

        self.parent.chmod(0o700)
        target = self.parent / "target"
        target.write_text("not a socket")
        self.socket_path.symlink_to(target)
        self.assertEqual(
            follow_records(
                self.socket_path,
                "publisher",
                "compact",
                output,
                expected_peer_pid=os.getpid(),
            ),
            1,
        )
        self.assertEqual(output.getvalue(), "")

    def test_server_rejects_peer_uid_that_does_not_match_owner(self):
        with patch("aster_quickstart.attach._peer_uid", return_value=os.getuid() + 1):
            payload = json.dumps(
                {"role": "publisher", "detail": "compact", "after_sequence": 0}
            ).encode() + b"\n"
            self.assertEqual(self._request(payload), b"")

    def test_request_grammar_is_exact_and_bounded(self):
        invalid = [
            b"{}\n",
            b'{"role":"publisher","detail":"compact","after_sequence":0,"extra":1}\n',
            b'{"role":"admin","detail":"compact","after_sequence":0}\n',
            b'{"role":"publisher","detail":"verbose","after_sequence":0}\n',
            b'{"role":"publisher","detail":" COMPACT ","after_sequence":0}\n',
            b'{"role":"publisher","detail":"COMPACT","after_sequence":0}\n',
            b'{"role":"publisher","detail":7,"after_sequence":0}\n',
            b'{"role":"publisher","detail":"compact","after_sequence":true}\n',
            b'{"role":"admin","role":"publisher","detail":"compact","after_sequence":0}\n',
            b"[1,2,3]\n",
            b"{" + (b"x" * 2048) + b"}\n",
        ]
        for payload in invalid:
            with self.subTest(payload=payload[:80]):
                self.assertEqual(self._request(payload), b"")

    def test_concurrent_clients_are_capped_before_another_handler_is_created(self):
        clients: list[socket.socket] = []
        try:
            for _ in range(4):
                client = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
                client.connect(str(self.socket_path))
                client.sendall(b"{")
                clients.append(client)
            time.sleep(0.05)

            rejected = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            rejected.settimeout(0.3)
            rejected.connect(str(self.socket_path))
            rejected.sendall(
                b'{"role":"publisher","detail":"compact","after_sequence":0}\n'
            )
            try:
                self.assertEqual(rejected.recv(1), b"")
            except ConnectionResetError:
                pass
            finally:
                rejected.close()
        finally:
            for client in clients:
                client.close()

    def test_request_deadline_is_absolute_even_when_bytes_keep_arriving(self):
        client = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        client.settimeout(0.25)
        client.connect(str(self.socket_path))
        try:
            client.sendall(b"{")
            for _ in range(3):
                time.sleep(0.35)
                try:
                    client.sendall(b" ")
                except (BrokenPipeError, ConnectionResetError):
                    break
            try:
                self.assertEqual(client.recv(1), b"")
            except ConnectionResetError:
                pass
        finally:
            client.close()

    def test_non_reading_observer_is_evicted_by_bounded_writes(self):
        self.server.close()
        records = RecordJournal(
            limit=1024,
            clock=lambda: datetime(2026, 1, 1, tzinfo=timezone.utc),
        )
        for _ in range(1024):
            records.emit(
                action="start",
                node="publisher",
                outcome="ok",
                message="started",
                debug={"event_id": "a" * 64},
            )
        self.server = AttachServer(self.socket_path, records, os.getuid())
        self.server.start()
        client = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        client.settimeout(0.5)
        client.connect(str(self.socket_path))
        client.sendall(
            b'{"role":"publisher","detail":"debug","after_sequence":0}\n'
        )
        try:
            time.sleep(0.3)
            received = bytearray()
            while True:
                chunk = client.recv(65536)
                if not chunk:
                    break
                received.extend(chunk)
            self.assertTrue(received)
        finally:
            client.close()
            self.server.close()

    def test_close_waits_for_all_tracked_handlers_to_exit(self):
        clients: list[socket.socket] = []
        for _ in range(4):
            client = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            client.connect(str(self.socket_path))
            client.sendall(b"{")
            clients.append(client)
        time.sleep(0.05)

        started = time.monotonic()
        self.server.close()
        elapsed = time.monotonic() - started
        for client in clients:
            client.close()

        self.assertLess(elapsed, 1)
        self.assertEqual(self.server._handlers, set())

    def test_closed_server_rejects_restart_without_recreating_the_socket(self):
        self.server.close()

        with self.assertRaisesRegex(RuntimeError, "closed"):
            self.server.start()

        self.assertFalse(self.socket_path.exists())

    def test_replays_history_follows_new_records_filters_role_and_shows_gap(self):
        self.server.close()
        self.records = RecordJournal(
            limit=2,
            clock=lambda: datetime(2026, 1, 1, tzinfo=timezone.utc),
        )
        self.records.emit(action="start", node="publisher", outcome="ok", message="started")
        self.records.emit(action="start", node="receiver", outcome="ok", message="started")
        self.records.emit(action="ready", node="publisher", outcome="running", message="running")
        self.server = AttachServer(self.socket_path, self.records, os.getuid())
        self.server.start()

        output = StringIO()
        result: list[int] = []
        follower = threading.Thread(
            target=lambda: result.append(
                follow_records(
                    self.socket_path,
                    "publisher",
                    "compact",
                    output,
                    expected_peer_pid=os.getpid(),
                )
            )
        )
        follower.start()
        deadline = time.monotonic() + 1
        while "[ready] publisher running: running" not in output.getvalue() and time.monotonic() < deadline:
            time.sleep(0.005)
        self.records.emit(action="ready", node="receiver", outcome="running", message="running")
        self.records.emit(action="stop", node="publisher", outcome="stopped", message="stopped")
        deadline = time.monotonic() + 1
        while "[stop] publisher stopped: stopped" not in output.getvalue() and time.monotonic() < deadline:
            time.sleep(0.005)
        self.server.close()
        follower.join(timeout=1)

        self.assertFalse(follower.is_alive())
        self.assertEqual(result, [0])
        rendered = output.getvalue()
        self.assertIn("[history-gap] truncated:", rendered)
        self.assertIn("[ready] publisher running: running", rendered)
        self.assertIn("[stop] publisher stopped: stopped", rendered)
        self.assertNotIn(" receiver ", rendered)

    def test_detaching_one_client_does_not_stop_journal_or_server(self):
        first = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        first.connect(str(self.socket_path))
        first.sendall(
            b'{"role":"publisher","detail":"compact","after_sequence":0}\n'
        )
        first.close()

        record = self.records.emit(
            action="start", node="publisher", outcome="ok", message="started"
        )
        self.assertEqual(record.sequence, 1)
        second = self._request(
            b'{"role":"publisher","detail":"compact","after_sequence":0}\n'
        )
        self.assertIn(b"[start] publisher ok: started", second)


if __name__ == "__main__":
    unittest.main()
