#!/usr/bin/env python3
"""Bounded real-process Event boundary regressions.

Run with ASTER_AGENT_FIXTURE pointing to the acceptance-test-provider binary.
This unprotected fixture is test-only and supplies no customer custody evidence.
"""

import base64
import http.client
import json
import os
from pathlib import Path
import signal
import select
import socket
import subprocess
import tempfile
import time
import unittest


class ProcessBoundaries(unittest.TestCase):
    def setUp(self):
        self.binary = os.environ["ASTER_AGENT_FIXTURE"]
        self.root = tempfile.TemporaryDirectory(prefix="aster-final-boundaries-")
        self.addCleanup(self.root.cleanup)
        subprocess.run([self.binary, "prepare", "--root", self.root.name],
                       check=True, capture_output=True, timeout=10)
        self.config_path = Path(self.root.name) / "agent.json"
        self.config = json.loads(self.config_path.read_text())
        self.config["mesh"]["peers"] = []
        self.config["limits"] = {"max_in_flight_requests": 1, "shutdown_grace_ms": 2000}
        self.config_path.write_text(json.dumps(self.config))
        self.token_path = Path(self.config["credentials"]["client_token_file"])
        self.token = self.token_path.read_text().strip()

    def start(self):
        process = subprocess.Popen([self.binary, "--config", str(self.config_path)],
                                   stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                   start_new_session=True)
        def cleanup():
            if process.poll() is None:
                os.killpg(process.pid, signal.SIGKILL)
            process.communicate(timeout=5)
        self.addCleanup(cleanup)
        self.wait_status("health", "/readyz", 200)
        return process

    def status(self, listener, path):
        conn = http.client.HTTPConnection(self.config[listener]["listen"], timeout=0.25)
        try:
            if listener == "application":
                conn.request("POST", path, b"{}", {
                    "Content-Type": "application/json", "Authorization": "Bearer " + self.token})
            else:
                conn.request("GET", path)
            response = conn.getresponse()
            response.read()
            return response.status
        finally:
            conn.close()

    def wait_status(self, listener, path, expected):
        deadline = time.monotonic() + 5
        while time.monotonic() < deadline:
            try:
                if self.status(listener, path) == expected:
                    return
            except (OSError, http.client.HTTPException):
                pass
            time.sleep(0.02)
        self.fail(f"{listener} did not reach status {expected}")

    def test_fifo_credentials_never_block_startup_or_check(self):
        # Break caught: open(O_RDONLY) hangs on a FIFO before regular-file checks.
        for kind in ("client_token_file", "mission_secret_ref_file"):
            path = Path(self.config["credentials"][kind])
            original = path.read_bytes()
            path.unlink()
            os.mkfifo(path, 0o600)
            try:
                for mode in ("--check-config", "--config"):
                    with self.subTest(kind=kind, mode=mode):
                        try:
                            result = subprocess.run([self.binary, mode, str(self.config_path)],
                                                    capture_output=True, timeout=2)
                        except subprocess.TimeoutExpired:
                            self.fail("FIFO credential blocked validation beyond two seconds")
                        self.assertNotEqual(result.returncode, 0)
                        self.assertNotIn(b"SECRET_", result.stdout + result.stderr)
            finally:
                path.unlink()
                path.write_bytes(original)
                path.chmod(0o600)

    def test_fifo_reload_keeps_authentication_and_handles_termination(self):
        # Break caught: synchronous SIGHUP FIFO open blocks supervisor signals.
        process = self.start()
        self.token_path.unlink()
        os.mkfifo(self.token_path, 0o600)
        process.send_signal(signal.SIGHUP)
        time.sleep(0.15)
        self.assertEqual(self.status("health", "/readyz"), 200)
        self.assertEqual(self.status("application", "/aster.application.v1alpha1.AsterApplicationService/GetStatus"), 200)
        process.send_signal(signal.SIGTERM)
        try:
            stdout, stderr = process.communicate(timeout=4)
        except subprocess.TimeoutExpired:
            self.fail("FIFO reload prevented bounded termination")
        self.assertEqual(process.returncode, 0)
        self.assertIn(b'"operation":"token_reload"', stdout + stderr)
        self.assertNotIn(b"SECRET_", stdout + stderr)

    def test_sigint_drains_a_headers_admitted_publish(self):
        # Break caught: node's independent ctrl_c handler closes Event admission
        # before the supervisor finishes the already-admitted request body.
        process = self.start()
        body = json.dumps({
            "operationKey": base64.b64encode(b"sigint-publication").decode(),
            "topic": "chat.events", "scope": "mission/team/alpha", "priority": "PRIORITY_IMMEDIATE",
            "logicalKey": base64.b64encode(b"sigint-message").decode(),
            "payload": base64.b64encode(b"accepted before SIGINT").decode(),
        }).encode()
        host, port = self.config["application"]["listen"].rsplit(":", 1)
        with socket.create_connection((host, int(port)), timeout=3) as connection:
            connection.sendall((
                "POST /aster.application.v1alpha1.AsterApplicationService/PublishEvent HTTP/1.1\r\n"
                "Host: localhost\r\nContent-Type: application/json\r\n"
                f"Authorization: Bearer {self.token}\r\nContent-Length: {len(body)}\r\n"
                "Expect: 100-continue\r\nConnection: close\r\n\r\n").encode())
            interim = b""
            while not interim.endswith(b"\r\n\r\n"):
                byte = connection.recv(1)
                self.assertTrue(byte, "connection closed before body admission")
                interim += byte
                self.assertLess(len(interim), 1024)
            self.assertTrue(interim.startswith(b"HTTP/1.1 100"), interim.decode())
            self.wait_status("application", "/aster.application.v1alpha1.AsterApplicationService/GetStatus", 429)
            process.send_signal(signal.SIGINT)
            self.wait_status("health", "/readyz", 503)
            # Give any competing node signal consumer time to expose the bug.
            time.sleep(0.15)
            connection.sendall(body)
            response = http.client.HTTPResponse(connection)
            response.begin()
            payload = response.read()
            self.assertEqual(response.status, 200, payload.decode())
            self.assertTrue(json.loads(payload)["inserted"])
        stdout, stderr = process.communicate(timeout=4)
        self.assertEqual(process.returncode, 0, stderr.decode())
        self.assertNotIn(b"SECRET_", stdout + stderr)

    @unittest.skipUnless(os.environ.get("ASTER_NODE_BINARY"), "set ASTER_NODE_BINARY for standalone signal compatibility")
    def test_standalone_node_still_stops_cleanly_on_sigint(self):
        process = subprocess.Popen([
            os.environ["ASTER_NODE_BINARY"], "node", "--state", self.config["state"]["directory"],
            "--bind", "127.0.0.1:0", "--application", "relay",
            "--mission-bundle-unprotected-reference", str(Path(self.root.name) / "SECRET_PATH_CANARY-mission-bundle"),
        ], stdout=subprocess.PIPE, stderr=subprocess.PIPE, start_new_session=True)
        def cleanup():
            if process.poll() is None:
                os.killpg(process.pid, signal.SIGKILL)
            process.communicate(timeout=5)
        self.addCleanup(cleanup)
        captured = b""
        deadline = time.monotonic() + 5
        while b"READY selected=true" not in captured and time.monotonic() < deadline:
            readable, _, _ = select.select([process.stdout], [], [], 0.1)
            if readable:
                chunk = os.read(process.stdout.fileno(), 4096)
                if not chunk:
                    break
                captured += chunk
                self.assertLess(len(captured), 65536)
        self.assertIn(b"READY selected=true", captured)
        process.send_signal(signal.SIGINT)
        stdout, stderr = process.communicate(timeout=5)
        self.assertEqual(process.returncode, 0, stderr.decode())
        self.assertIn(b"STOP", captured + stdout)


if __name__ == "__main__":
    unittest.main()
