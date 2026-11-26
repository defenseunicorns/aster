from __future__ import annotations

import http.client
from io import StringIO
import json
import os
from pathlib import Path
import shlex
import tempfile
import threading
import time
import unittest
from urllib.parse import urlsplit

from aster_quickstart.__main__ import CleanupRequest, QuickstartLauncher, discover_binaries
from aster_quickstart.runtime import RuntimeRegistry


@unittest.skipUnless(
    os.environ.get("ASTER_QUICKSTART_REAL") == "1",
    "set ASTER_QUICKSTART_REAL=1 to run",
)
class RealQuickstartTests(unittest.TestCase):
    def setUp(self):
        bin_dir = os.environ.get("ASTER_QUICKSTART_BIN_DIR")
        self.assertIsNotNone(
            bin_dir,
            "ASTER_QUICKSTART_BIN_DIR must identify the prebuilt binaries",
        )
        self.binaries = discover_binaries(Path(bin_dir))
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.runtime_dir = Path(self.temporary.name) / "runtime"
        self.pids: set[int] = set()
        self.stop = CleanupRequest()
        self.url_ready = threading.Event()
        self.url = ""
        self.output = StringIO()
        self.result: list[int] = []

        def capture_url(url):
            self.url = url
            self.url_ready.set()
            return True

        self.registry_paths = (
            self.runtime_dir / "runtime.lock",
            self.runtime_dir / "runtime.json",
        )
        registry = RuntimeRegistry(*self.registry_paths)
        self.launcher = QuickstartLauncher(
            self.binaries,
            no_open=False,
            browser_open=capture_url,
            output=self.output,
            runtime_registry=registry,
        )
        self.worker = threading.Thread(
            target=lambda: self.result.append(self.launcher.run(self.stop)),
        )
        self.worker.start()
        self.assertTrue(self.url_ready.wait(timeout=3), "quickstart URL was not opened")

    def tearDown(self):
        if self.worker.is_alive():
            self.stop.set()
            self.worker.join(timeout=5)

    def test_complete_operational_http_path_and_cleanup_evidence(self):
        initial = self.get_state()
        self.assertTrue(initial["initialized"])
        self.assertEqual(initial["nodes"]["publisher"]["state"], "stopped")
        self.assertEqual(initial["nodes"]["receiver"]["state"], "stopped")

        publisher = self.post("/api/nodes/publisher/start", {})
        self.capture_pids()
        self.assertEqual(publisher["nodes"]["publisher"]["state"], "running")

        receiver = self.post("/api/nodes/receiver/start", {})
        self.capture_pids()
        self.assertEqual(receiver["nodes"]["receiver"]["state"], "running")

        authenticated = self.post("/api/authenticate", {})
        self.capture_pids()
        self.assertEqual(authenticated["authentication"], {
            "state": "authenticated",
            "verification": "verified",
        })

        text = "One real Event from the operational quickstart."
        delivered = self.post("/api/events", {"text": text})
        self.assertEqual(delivered["commit"]["event_id"], delivered["receipt"]["event_id"])
        self.assertEqual(delivered["commit"]["text"], text)
        self.assertEqual(delivered["receipt"]["text"], text)
        self.assertEqual(delivered["commit"]["status"], "committed")
        self.assertEqual(delivered["receipt"]["status"], "received")

        stopped = self.post("/api/nodes/receiver/stop", {})
        self.capture_pids()
        self.assertEqual(stopped["nodes"]["receiver"]["state"], "stopped")
        self.assertEqual(stopped["authentication"]["state"], "unauthenticated")
        self.assertNotIn("publish_event", stopped["available_actions"])

        restarted = self.post("/api/nodes/receiver/start", {})
        self.capture_pids()
        self.assertEqual(restarted["nodes"]["receiver"]["state"], "running")
        self.assertIn("authenticate", restarted["available_actions"])
        reauthenticated = self.post("/api/authenticate", {})
        self.capture_pids()
        self.assertEqual(reauthenticated["authentication"]["state"], "authenticated")

        runtime = self.live_runtime()
        workspace = Path(runtime.workspace)
        socket_path = Path(runtime.socket_path)
        generated_secrets = [
            (workspace / "session" / f"node-{index}" / "playground.client.token").read_text()
            for index in range(2)
        ]
        cleaned = self.post("/api/cleanup", {"confirm": True})
        self.assertEqual(cleaned["cleanup"], "cleaned")
        self.assertEqual(cleaned["records"][-1]["action"], "cleanup")
        self.assertEqual(cleaned["records"][-1]["debug"], {
            "operation": "cleanup",
            "success": True,
            "owned_processes": 0,
            "socket_closed": True,
            "workspace_removed": True,
            "descriptor_removed": True,
        })
        self.assert_complete_safe_transcript(
            cleaned["transcript"],
            [urlsplit(self.url).query.removeprefix("token="), *generated_secrets],
        )
        self.worker.join(timeout=5)

        self.assertFalse(self.worker.is_alive(), "launcher cleanup did not finish promptly")
        self.assertEqual(self.result, [0])
        self.assert_no_live_pids(self.pids)
        self.assertFalse(workspace.exists())
        self.assertFalse(socket_path.exists())
        self.assertFalse((self.runtime_dir / "runtime.json").exists())
        self.assertFalse(
            any("transcript" in path.name.casefold() for path in self.runtime_dir.rglob("*")),
            "cleanup retained transcript evidence on disk",
        )
        rendered = self.output.getvalue()
        token = urlsplit(self.url).query.removeprefix("token=")
        self.assertFalse(token in rendered, "stdout exposed the bearer token")
        self.assertFalse("?token=" in rendered, "stdout exposed a tokenized URL")
        self.assertFalse(self.url in rendered, "stdout exposed the private browser URL")

    @unittest.skipUnless(
        os.environ.get("ASTER_QUICKSTART_REAL_OFFLINE") == "1",
        "set ASTER_QUICKSTART_REAL_OFFLINE=1 for the optional experiment",
    )
    def test_optional_offline_experiment_is_separate_from_first_run(self):
        self.post("/api/nodes/publisher/start", {})
        self.post("/api/nodes/receiver/start", {})
        self.post("/api/authenticate", {})
        first = self.post("/api/events", {"text": "First delivery."})
        self.assertEqual(first["receipt"]["status"], "received")

        offline = self.post(
            "/api/experiments/offline",
            {"text": "Committed while the transport was unavailable."},
            timeout=20,
        )
        self.capture_pids()
        self.assertEqual(
            offline["experiment"]["commit"]["event_id"],
            offline["experiment"]["receipt"]["event_id"],
        )
        self.assertEqual(offline["experiment"]["availability"], "available")
        self.post("/api/cleanup", {"confirm": True})
        self.worker.join(timeout=5)
        self.assertEqual(self.result, [0])
        self.assert_no_live_pids(self.pids)

    def capture_pids(self):
        self.pids.update(process.pid for process in self.live_runtime().owned_processes)

    def live_runtime(self):
        return RuntimeRegistry(*self.registry_paths).read_live()

    def assert_complete_safe_transcript(self, transcript, generated_secrets):
        commands = [entry for entry in transcript if entry["kind"] == "command"]
        by_step = {}
        for entry in commands:
            by_step.setdefault(entry["step"], []).append(self.command_action(entry["command"]))
            self.assertIn(entry["outcome"], {"succeeded", "stopped"})
            self.assertIsInstance(entry["returncode"], int)
            self.assertIsInstance(entry["duration_ms"], int)
            self.assertGreaterEqual(entry["duration_ms"], 0)
            self.assertTrue(entry["cwd"])
            self.assertEqual(shlex.join(shlex.split(entry["command"])), entry["command"])

        self.assertEqual(by_step, {
            "setup": ["playground-init", "publication-init", "publication-init"],
            "publisher": ["aster-agent"],
            "receiver": ["aster-agent", "aster-agent"],
            "authentication": [
                "aster-agent", "aster-agent", "subscribe", "subscribe", "publish",
                "publication-ack", "aster-agent", "aster-agent", "subscribe", "subscribe",
                "publish", "publication-ack",
            ],
            "event": ["publish", "publication-ack"],
        })
        cleanup = [entry for entry in transcript if entry["step"] == "cleanup"]
        self.assertGreaterEqual(len(cleanup), 2)
        self.assertTrue(all(
            entry["kind"] == "internal" and entry["outcome"] == "succeeded"
            for entry in cleanup
        ))
        serialized = json.dumps(transcript, sort_keys=True)
        for secret in generated_secrets:
            self.assertTrue(secret)
            self.assertNotIn(secret, serialized)

    def command_action(self, command):
        arguments = shlex.split(command)
        executable = Path(arguments[0]).name
        if executable == "aster":
            return arguments[1]
        if executable == "aster-agent":
            return executable
        self.assertEqual(executable, "asterctl")
        actions = {
            "publication-init", "subscribe", "publish", "publication-ack",
        }
        [action] = [argument for argument in arguments if argument in actions]
        return action

    def get_state(self):
        return self.request("GET", "/api/state")

    def post(self, route, body, *, timeout=12):
        return self.request("POST", route, body, timeout=timeout)

    def request(self, method, route, body=None, *, timeout=3):
        parsed = urlsplit(self.url)
        encoded = None if body is None else json.dumps(body).encode()
        connection = http.client.HTTPConnection(parsed.hostname, parsed.port, timeout=timeout)
        try:
            headers = {}
            if encoded is not None:
                headers = {
                    "Content-Type": "application/json",
                    "Origin": f"http://{parsed.netloc}",
                }
            connection.request(
                method,
                f"{route}?{parsed.query}",
                body=encoded,
                headers=headers,
            )
            response = connection.getresponse()
            payload = json.loads(response.read())
        finally:
            connection.close()
        self.assertEqual(response.status, 200, payload)
        return payload

    def assert_no_live_pids(self, pids):
        deadline = time.monotonic() + 2
        while time.monotonic() < deadline:
            live = []
            for pid in pids:
                try:
                    state = Path(f"/proc/{pid}/stat").read_text().split()[2]
                except (FileNotFoundError, IndexError, OSError):
                    continue
                if state != "Z":
                    live.append(pid)
            if not live:
                return
            time.sleep(0.02)
        self.fail(f"owned process IDs remain alive: {live}")


if __name__ == "__main__":
    unittest.main()
