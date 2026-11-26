from __future__ import annotations

import base64
import json
import os
from pathlib import Path
import signal
import shutil
import socket
import stat
import sys
import tempfile
import threading
import time
import unittest
from unittest.mock import patch

from aster_quickstart.aster_session import (
    AsterBinaries,
    AsterSession,
    AsterSessionError,
    MAX_CAPTURE_BYTES,
    RecoverableOfflinePublishError,
)
from aster_quickstart.transcript import TranscriptJournal


INITIALIZER = r'''#!{python}
import os
from pathlib import Path
import sys
from urllib.parse import quote

root = Path(sys.argv[sys.argv.index("--root") + 1])
mode_path = root.with_suffix(".mode")
mode = mode_path.read_text() if mode_path.exists() else "ready"
if mode == "root_escape":
    root.mkdir(mode=0o700)
    outside = root.parent / "outside"
    outside.mkdir(mode=0o755)
    (outside / "mission.unprotected-reference.bundle").write_bytes(b"outside")
    os.symlink(outside, root / "node-0", target_is_directory=True)
    (root / "node-1").mkdir()
    (root / "node-1" / "mission.unprotected-reference.bundle").write_bytes(b"node-1")
else:
    root.mkdir(mode=0o700)
    for index in range(2):
        state = root / ("node-%d" % index)
        state.mkdir()
        (state / "mission.unprotected-reference.bundle").write_bytes(("mission-%d" % index).encode())
(root / "initializer-argv.json").write_text(__import__("json").dumps(sys.argv[1:]))
print("PLAYGROUND_INIT status=pass nodes=2 scope=demo/playground topic=mesh.messages epoch=1 provisioning=unprotected-reference root=%s" % quote(str(root), safe="/"))
for index in range(2):
    print("PLAYGROUND_NODE index=%d carrier_id=%064x mission_id=%064x" % (index, index + 1, index + 101))
'''


AGENT = r'''#!{python}
import base64
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import os
from pathlib import Path
import signal
import socket
import subprocess
import sys
import threading
import time

state = Path(sys.argv[sys.argv.index("--state") + 1])
root = state.parent
index = int(state.name.split("-")[1])
mode_path = root.with_suffix(".mode")
mode = mode_path.read_text() if mode_path.exists() else "ready"
with (root / "agent-argv.jsonl").open("a") as output:
    output.write(json.dumps(sys.argv[1:]) + "\n")
with (root / "timeline.jsonl").open("a") as output:
    output.write(json.dumps({"step": "agent-start", "peer": "--peer" in sys.argv, "index": index, "pid": os.getpid()}) + "\n")
if mode == "early_descendant":
    child = subprocess.Popen([
        sys.executable,
        "-c",
        "import signal,time; signal.signal(signal.SIGINT, signal.SIG_IGN); signal.signal(signal.SIGTERM, signal.SIG_IGN); time.sleep(60)",
    ])
    root.with_suffix(".descendant-%d.pid" % index).write_text(str(child.pid))
    print("fixture leader exited", file=sys.stderr, flush=True)
    raise SystemExit(24)
if mode == "early" or (mode == "partial" and index == 1) or (mode == "offline_restore_failure" and "--peer" in sys.argv):
    print("fixture agent exited", file=sys.stderr, flush=True)
    raise SystemExit(23)
if mode == "timeout":
    time.sleep(60)
if mode == "noisy":
    os.write(2, b"x" * (2 * 1024 * 1024 + 1))
if mode == "malformed":
    print("AGENT status=ready listen=http://0.0.0.0:8181", flush=True)
    time.sleep(60)
if mode == "descendant":
    child = subprocess.Popen([
        sys.executable,
        "-c",
        "import signal,time; signal.signal(signal.SIGINT, signal.SIG_IGN); signal.signal(signal.SIGTERM, signal.SIG_IGN); time.sleep(60)",
    ])
    root.with_suffix(".descendant-%d.pid" % index).write_text(str(child.pid))

token = (state / "playground.client.token").read_text()

class Handler(BaseHTTPRequestHandler):
    def do_POST(self):
        length = int(self.headers.get("Content-Length", "0"))
        request = json.loads(self.rfile.read(length))
        if self.headers.get("Authorization") != "Bearer " + token:
            self.send_response(401)
            self.send_header("Content-Length", "0")
            self.end_headers()
            return
        events = []
        published = root / "published.json"
        request_mode = mode_path.read_text() if mode_path.exists() else mode
        receiver_silent = request_mode in {"receiver_silence", "offline_receiver_silence"} and index == 1
        if self.path.endswith("/QueryEvents") and published.exists() and not receiver_silent:
            events = [json.loads(published.read_text())]
            if request_mode == "wrong_payload" and index == 1:
                events[0]["payload"] = base64.b64encode(b"wrong").decode()
        if self.path.endswith("/QueryEvents") and request_mode == "malformed_query" and index == 1:
            response = {"events": "not-a-page", "scannedThrough": "0", "hasMore": False}
        elif self.path.endswith("/QueryEvents") and request_mode == "slow_pages" and index == 1:
            time.sleep(0.08)
            marker = int(request["afterAcceptanceMarker"])
            response = {"events": [{"unrelated": marker}], "scannedThrough": str(marker + 1), "hasMore": True}
        else:
            response = {"events": events, "scannedThrough": "1" if events else "0", "hasMore": False}
        if events and index == 1:
            with (root / "timeline.jsonl").open("a") as output:
                output.write(json.dumps({
                    "step": "observe",
                    "event_id": events[0]["id"],
                    "payload": events[0]["payload"],
                }) + "\n")
        payload = json.dumps(response).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def log_message(self, format, *args):
        pass

server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
mesh_host, mesh_port = sys.argv[sys.argv.index("--mesh-bind") + 1].rsplit(":", 1)
mesh_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
mesh_socket.bind((mesh_host, int(mesh_port)))
if mode == "readiness_grammar":
    print("AGENT status=starting status=ready listen=http://127.0.0.1:%d trailing" % server.server_port, flush=True)
elif mode == "production_readiness":
    print("AGENT status=ready listen=http://127.0.0.1:%d mesh_bind=127.0.0.1:43100 protocol=connect+grpc api=aster.application.v1alpha1 plaintext=loopback-only" % server.server_port, flush=True)
else:
    print("AGENT status=ready listen=http://127.0.0.1:%d" % server.server_port, flush=True)
if mode == "ready_overflow_descendant":
    child = subprocess.Popen([
        sys.executable,
        "-c",
        "import signal,time; signal.signal(signal.SIGINT, signal.SIG_IGN); signal.signal(signal.SIGTERM, signal.SIG_IGN); time.sleep(60)",
    ])
    root.with_suffix(".ready-overflow-descendant-%d.pid" % index).write_text(str(child.pid))

    def overflow_after_readiness():
        time.sleep(0.05)
        os.write(2, b"x" * (2 * 1024 * 1024 + 1))

    threading.Thread(target=overflow_after_readiness, daemon=True).start()
if mode == "ready_child_overflow":
    child = subprocess.Popen([
        sys.executable,
        "-c",
        "import os,signal,time; signal.signal(signal.SIGINT, signal.SIG_IGN); signal.signal(signal.SIGTERM, signal.SIG_IGN); time.sleep(0.1); os.write(2, b'x' * (2 * 1024 * 1024 + 1)); time.sleep(60)",
    ])
    root.with_suffix(".child-overflow-descendant-%d.pid" % index).write_text(str(child.pid))
server.serve_forever()
'''


CTL = r'''#!{python}
import base64
import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import time

actions = {"publication-init", "subscribe", "publish", "publication-ack"}
action = next(value for value in sys.argv[1:] if value in actions)
journal = Path(sys.argv[sys.argv.index("--journal") + 1])
root = journal.parent.parent
mode_path = root.with_suffix(".mode")
mode = mode_path.read_text() if mode_path.exists() else "ready"
with (root / "ctl-argv.jsonl").open("a") as output:
    output.write(json.dumps(sys.argv[1:]) + "\n")
with root.with_suffix(".ctl-argv.jsonl").open("a") as output:
    output.write(json.dumps(sys.argv[1:]) + "\n")
with (root / "timeline.jsonl").open("a") as output:
    output.write(json.dumps({"step": action}) + "\n")
if action == "publication-init":
    if mode == "auth_ctl_timeout":
        child = subprocess.Popen([
            sys.executable,
            "-c",
            "import signal,time; signal.signal(signal.SIGINT, signal.SIG_IGN); signal.signal(signal.SIGTERM, signal.SIG_IGN); time.sleep(60)",
        ])
        root.with_suffix(".auth-ctl-descendant.pid").write_text(str(child.pid))
        time.sleep(60)
    journal.touch()
elif action == "subscribe":
    print(json.dumps({"subscriptionId": base64.b64encode(b"s" * 32).decode()}))
elif action == "publish":
    if mode == "offline_publish_failure":
        raise SystemExit(29)
    if mode == "ctl_timeout_descendant":
        child = subprocess.Popen([
            sys.executable,
            "-c",
            "import signal,time; signal.signal(signal.SIGINT, signal.SIG_IGN); signal.signal(signal.SIGTERM, signal.SIG_IGN); time.sleep(60)",
        ])
        root.with_suffix(".ctl-descendant.pid").write_text(str(child.pid))
        time.sleep(60)
    if mode == "ctl_noisy":
        os.write(2, b"x" * (2 * 1024 * 1024 + 1))
    payload = sys.stdin.buffer.read()
    event_id = b"e" * 32
    event = {
        "id": base64.b64encode(event_id).decode(),
        "payload": base64.b64encode(payload).decode(),
        "topic": "mesh.messages",
        "scope": "demo/playground",
        "publisher": base64.b64encode(b"p" * 32).decode(),
        "eventSequence": "1",
    }
    (root / "published.json").write_text(json.dumps(event))
    print(json.dumps({
        "inserted": True,
        "result": {
            "operationSequence": "1",
            "receipt": {"eventId": base64.b64encode(b"r" * 32 if mode == "wrong_receipt" else event_id).decode()},
        },
    }))
'''


class AsterSessionTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.parent = Path(self.temporary.name)
        self.bin = self.parent / "bin"
        self.bin.mkdir()
        self.aster = self.write_executable("aster", INITIALIZER)
        self.agent = self.write_executable("aster-agent", AGENT)
        self.ctl = self.write_executable("asterctl", CTL)
        self.root = self.parent / "session"
        self.binaries = AsterBinaries(self.aster, self.agent, self.ctl)

    def write_executable(self, name, source):
        path = self.bin / name
        path.write_text(source.replace("{python}", sys.executable))
        path.chmod(0o700)
        return path

    def set_mode(self, mode):
        self.root.with_suffix(".mode").write_text(mode)

    def session(self, *, startup_timeout=0.8, rpc_timeout=0.5, transcript=None):
        session = AsterSession(
            self.binaries,
            self.root,
            startup_timeout=startup_timeout,
            rpc_timeout=rpc_timeout,
            transcript=transcript,
        )
        self.addCleanup(session.close)
        return session

    @staticmethod
    def start_authenticated(session):
        session.initialize()
        session.start_node("publisher")
        session.start_node("receiver")
        return session.authenticate()

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

    def wait_for_group_gone(self, process_group):
        deadline = time.monotonic() + 2
        while time.monotonic() < deadline:
            try:
                os.killpg(process_group, 0)
            except ProcessLookupError:
                return
            time.sleep(0.02)
        self.fail(f"process group remains after cleanup: {process_group}")

    @staticmethod
    def kill_if_alive(pid):
        try:
            os.kill(pid, signal.SIGKILL)
        except ProcessLookupError:
            pass

    def agent_commands(self):
        path = self.root / "agent-argv.jsonl"
        if not path.exists():
            return []
        return [json.loads(line) for line in path.read_text().splitlines()]

    def ctl_actions(self):
        actions = {"publication-init", "subscribe", "publish", "publication-ack"}
        path = self.root / "ctl-argv.jsonl"
        if not path.exists():
            return []
        return [
            next(item for item in command if item in actions)
            for command in (json.loads(line) for line in path.read_text().splitlines())
        ]

    def assert_mesh_port_reserved(self, command):
        mesh_bind = command[command.index("--mesh-bind") + 1]
        host, port = mesh_bind.rsplit(":", 1)
        probe = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            with self.assertRaises(OSError):
                probe.bind((host, int(port)))
        finally:
            probe.close()

    def assert_mesh_port_available(self, command):
        mesh_bind = command[command.index("--mesh-bind") + 1]
        host, port = mesh_bind.rsplit(":", 1)
        probe = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            probe.bind((host, int(port)))
        finally:
            probe.close()

    def assert_final_command(
        self,
        transcript,
        command_fragment,
        *,
        outcome,
        returncode,
        stdout,
        stderr,
    ):
        entries = [
            entry
            for entry in transcript.snapshot()
            if command_fragment in (entry["command"] or "")
        ]
        self.assertEqual(len(entries), 1)
        [entry] = entries
        self.assertEqual(entry["outcome"], outcome)
        self.assertEqual(entry["returncode"], returncode)
        self.assertEqual(entry["stdout"], stdout)
        self.assertEqual(entry["stderr"], stderr)
        self.assertIsInstance(entry["duration_ms"], int)
        self.assertNotEqual(entry["outcome"], "running")
        return entry

    def wait_for_final_command(self, transcript, command_fragment):
        deadline = time.monotonic() + 2
        while time.monotonic() < deadline:
            entries = [
                entry
                for entry in transcript.snapshot()
                if command_fragment in (entry["command"] or "")
            ]
            if len(entries) == 1 and entries[0]["outcome"] != "running":
                return entries[0]
            time.sleep(0.01)
        self.fail("overflowed agent command did not finalize")

    def test_initialize_creates_identity_without_starting_agents(self):
        session = self.session()

        initialized = session.initialize()

        self.assertEqual(
            initialized,
            {
                "status": "initialized",
                "nodes": {
                    "publisher": {"identity_fingerprint": f"{1:064x}"},
                    "receiver": {"identity_fingerprint": f"{2:064x}"},
                },
            },
        )
        self.assertEqual(session.owned_pids, ())
        self.assertEqual(self.agent_commands(), [])
        self.assertEqual(self.ctl_actions(), ["publication-init", "publication-init"])

    def test_initializer_spawn_failure_finalizes_one_command_entry(self):
        self.aster.write_text("#!/definitely/missing-interpreter\n")
        self.aster.chmod(0o700)
        transcript = TranscriptJournal()
        session = self.session(transcript=transcript)

        with self.assertRaisesRegex(AsterSessionError, "could not start"):
            session.initialize()

        self.assert_final_command(
            transcript,
            "playground-init",
            outcome="spawn failed",
            returncode=None,
            stdout="",
            stderr="",
        )

    def test_initialize_and_explicit_node_start_record_setup_and_node_commands(self):
        transcript = TranscriptJournal()
        session = AsterSession(
            self.binaries,
            self.root,
            startup_timeout=0.8,
            rpc_timeout=0.5,
            transcript=transcript,
        )
        self.addCleanup(session.close)

        session.initialize()
        session.start_node("publisher")

        entries = transcript.snapshot()
        initializer = next(entry for entry in entries if "playground-init" in (entry["command"] or ""))
        agent = next(entry for entry in entries if "aster-agent" in (entry["command"] or ""))
        self.assertEqual(initializer["step"], "setup")
        self.assertEqual(initializer["outcome"], "succeeded")
        self.assertEqual(agent["step"], "publisher")
        self.assertEqual(agent["outcome"], "running")
        self.assertIn("--client-token-file", agent["command"])
        self.assertNotIn(session._nodes[0].token, str(entries))

    def test_closing_a_running_node_finalizes_its_entry_once(self):
        transcript = TranscriptJournal()
        session = self.session(transcript=transcript)
        session.initialize()
        session.start_node("publisher")
        agent_stdout = (self.root / "logs" / "node-0" / "run-1" / "agent.stdout").read_text()
        session.close()

        entries = transcript.snapshot()
        agent_entries = [entry for entry in entries if "aster-agent" in (entry["command"] or "")]
        cleanup_entries = [entry for entry in entries if entry["step"] == "cleanup"]
        self.assertEqual(len(agent_entries), 1)
        self.assertEqual(agent_entries[0]["outcome"], "stopped")
        self.assertEqual(agent_entries[0]["returncode"], -signal.SIGKILL)
        self.assertEqual(
            agent_entries[0]["stdout"],
            agent_stdout,
        )
        self.assertEqual(agent_entries[0]["stderr"], "")
        self.assertIsInstance(agent_entries[0]["duration_ms"], int)
        self.assertNotEqual(agent_entries[0]["outcome"], "running")
        self.assertEqual(len(cleanup_entries), 1)
        self.assertEqual(cleanup_entries[0]["outcome"], "succeeded")

    def test_nodes_start_and_stop_independently_without_peers(self):
        session = self.session()
        session.initialize()

        publisher = session.start_node("publisher")
        self.assertEqual((publisher["role"], publisher["state"]), ("publisher", "running"))
        self.assertEqual(publisher["pid"], session.owned_pids[0])
        self.assertGreater(publisher["port"], 0)
        self.assertEqual(publisher["command"], "aster-agent")
        self.assertEqual(publisher["confined_path"], "logs/node-0/run-1")
        self.assertEqual(len(session.owned_pids), 1)
        self.assertNotIn("--peer", self.agent_commands()[0])

        stopped = session.stop_node("publisher")
        self.assertEqual((stopped["role"], stopped["state"]), ("publisher", "stopped"))
        self.assertGreater(stopped["port"], 0)
        self.assertEqual(session.owned_pids, ())

        receiver = session.start_node("receiver")
        self.assertEqual((receiver["role"], receiver["state"]), ("receiver", "running"))
        self.assertGreater(receiver["pid"], 0)
        self.assertGreater(receiver["port"], 0)
        self.assertEqual(len(session.owned_pids), 1)
        self.assertNotIn("--peer", self.agent_commands()[1])

    def test_uncertain_kernel_group_probe_retains_agent_ownership(self):
        session = self.session()
        session.initialize()
        session.start_node("publisher")
        owned = session.owned_pids
        real_killpg = os.killpg

        def uncertain_probe(group, signum):
            if signum == 0:
                raise PermissionError("group probe denied")
            return real_killpg(group, signum)

        with patch("aster_quickstart.linux_process.os.killpg", side_effect=uncertain_probe):
            with self.assertRaises(AsterSessionError):
                session.stop_node("publisher")

        self.assertEqual(session.owned_pids, owned)

    def test_reaped_leader_never_signals_a_reused_process_group(self):
        session = self.session()
        session.initialize()
        session.start_node("publisher")
        process = session._nodes[0].process
        self.assertIsNotNone(process)
        os.killpg(process.pid, signal.SIGKILL)
        process.process.wait(timeout=1)

        with (
            patch("aster_quickstart.linux_process.group_is_gone", return_value=False),
            patch("aster_quickstart.linux_process.os.killpg") as kill_group,
        ):
            with self.assertRaises(AsterSessionError):
                session.stop_node("publisher")

        kill_group.assert_not_called()

    def test_failed_exact_group_signal_resumes_the_pinned_leader(self):
        session = self.session()
        session.initialize()
        session.start_node("publisher")
        pid = session.owned_pids[0]
        real_killpg = os.killpg

        def fail_kill(group, signum):
            if signum == signal.SIGKILL:
                raise PermissionError("injected signal failure")
            return real_killpg(group, signum)

        with patch("aster_quickstart.linux_process.os.killpg", side_effect=fail_kill):
            with self.assertRaises(AsterSessionError):
                session.stop_node("publisher")

        deadline = time.monotonic() + 0.2
        state = "T"
        while state == "T" and time.monotonic() < deadline:
            state = Path(f"/proc/{pid}/stat").read_text().rsplit(")", 1)[1].split()[0]
            time.sleep(0.005)
        self.assertNotEqual(state, "T")
        self.assertEqual(session.owned_pids, (pid,))

    def test_owned_process_observer_tracks_exact_dedicated_agent_identities(self):
        session = self.session()
        inventories = []
        session.set_process_inventory_observer(
            lambda inventory, start_pending: inventories.append((inventory, start_pending))
        )
        self.assertEqual(inventories, [((), None)])
        session.initialize()

        session.start_node("publisher")
        publisher = inventories[-1][0][0]
        stat_fields = Path(f"/proc/{publisher.pid}/stat").read_text().rsplit(")", 1)[1].split()
        self.assertEqual(publisher.process_group, publisher.pid)
        self.assertEqual(publisher.process_group, int(stat_fields[2]))
        self.assertEqual(publisher.proc_start_time, int(stat_fields[19]))
        self.assertEqual(publisher.executable, str(Path(f"/proc/{publisher.pid}/exe").resolve()))

        session.start_node("receiver")
        self.assertEqual(len(inventories[-1][0]), 2)
        self.assertEqual({item.pid for item in inventories[-1][0]}, set(session.owned_pids))
        self.assertIsNone(inventories[-1][1])
        session.stop_node("publisher")
        self.assertEqual(len(inventories[-1][0]), 1)
        session.stop_node("receiver")
        self.assertEqual(inventories[-1], ((), None))

    def test_inventory_durably_brackets_playground_and_numbered_commands(self):
        session = self.session()
        inventories = []
        session.set_process_inventory_observer(
            lambda inventory, start_pending: inventories.append((inventory, start_pending))
        )

        session.initialize()

        pending = [marker for _inventory, marker in inventories if marker is not None]
        transient = [item for inventory, _marker in inventories for item in inventory]
        self.assertIn("playground-init", pending)
        self.assertTrue(any(marker.startswith("asterctl-") for marker in pending))
        self.assertTrue(any(Path(item.executable) == Path(sys.executable).resolve() for item in transient))
        self.assertTrue(all(item.pid == item.process_group for item in transient))
        self.assertEqual(inventories[-1], ((), None))

    def test_uncertain_pre_identity_spawn_keeps_the_durable_pending_marker(self):
        child_path = self.root.with_suffix(".capture-child.pid")
        initializer = self.write_executable(
            "uncertain-initializer",
            """#!{python}
import pathlib, subprocess, sys, time
root = pathlib.Path(sys.argv[sys.argv.index('--root') + 1])
root.mkdir(mode=0o700)
child = subprocess.Popen(
    [sys.executable, '-c', 'import time; time.sleep(60)'],
    stdin=subprocess.DEVNULL,
    stdout=subprocess.DEVNULL,
    stderr=subprocess.DEVNULL,
)
root.with_suffix('.capture-child.pid').write_text(str(child.pid))
time.sleep(60)
""",
        )
        session = AsterSession(
            AsterBinaries(initializer, self.agent, self.ctl),
            self.root,
            startup_timeout=0.8,
            rpc_timeout=0.5,
        )
        states = []
        session.set_process_inventory_observer(
            lambda inventory, start_pending: states.append((inventory, start_pending))
        )

        def lose_identity(pid):
            deadline = time.monotonic() + 0.5
            while not child_path.exists() and time.monotonic() < deadline:
                time.sleep(0.005)
            raise ProcessLookupError(pid)

        with patch("aster_quickstart.aster_session.OwnedProcessGroup.capture", side_effect=lose_identity):
            with self.assertRaises(AsterSessionError):
                session.initialize()

        self.assertEqual(states[-1], ((), "playground-init"))
        self.assertTrue(self.root.exists())
        child = int(child_path.read_text())
        self.addCleanup(self.kill_if_alive, child)
        os.kill(child, 0)

    def test_owned_process_observer_failure_cannot_leave_an_unrecorded_agent(self):
        session = self.session()
        reject_owned_process = False

        def reject_running(inventory, _start_pending):
            if reject_owned_process and inventory:
                raise OSError("registry unavailable")

        session.set_process_inventory_observer(reject_running)
        session.initialize()
        reject_owned_process = True

        with self.assertRaises(AsterSessionError):
            session.start_node("publisher")

        self.assertEqual(session.owned_pids, ())

    def test_agent_start_is_persisted_pending_before_spawn_and_cleared_on_spawn_failure(self):
        session = self.session()
        states = []
        session.set_process_inventory_observer(
            lambda inventory, start_pending: states.append((inventory, start_pending))
        )
        session.initialize()

        def fail_spawn(*_args, **_kwargs):
            self.assertEqual(states[-1][0], ())
            self.assertIsNotNone(states[-1][1])
            raise OSError("spawn failed")

        with patch("aster_quickstart.aster_session._BoundedProcess", side_effect=fail_spawn):
            with self.assertRaises(AsterSessionError):
                session.start_node("publisher")

        self.assertEqual(states[-1], ((), None))
        self.assertEqual(session.owned_pids, ())

    def test_pending_publication_failure_prevents_spawn_and_clears_local_token(self):
        session = self.session()
        states = []
        reject_pending = False

        def observe(inventory, start_pending):
            nonlocal reject_pending
            states.append((inventory, start_pending))
            if start_pending is not None and reject_pending:
                reject_pending = False
                raise OSError("pending state unavailable")

        session.set_process_inventory_observer(observe)
        session.initialize()
        reject_pending = True
        with patch(
            "aster_quickstart.aster_session._BoundedProcess",
            side_effect=AssertionError("spawn must not run"),
        ):
            with self.assertRaises(AsterSessionError):
                session.start_node("publisher")

        self.assertEqual(states[-1], ((), None))
        self.assertEqual(session.owned_pids, ())

    def test_stop_pre_reserves_the_next_mesh_port_without_an_unowned_gap(self):
        session = self.session()
        session.initialize()
        session.start_node("publisher")
        first_command = self.agent_commands()[0]
        process = session._nodes[0].process
        self.assertIsNotNone(process)
        original_stop = process.stop
        observed = []

        def inspect_reservation_before_process_exit():
            reservation = session._reservations[0]
            self.assertIsNotNone(reservation)
            port = reservation.getsockname()[1]
            probe = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            try:
                with self.assertRaises(OSError):
                    probe.bind(("127.0.0.1", port))
            finally:
                probe.close()
            observed.append(port)
            original_stop()

        self.assert_mesh_port_reserved(first_command)
        with patch.object(process, "stop", side_effect=inspect_reservation_before_process_exit):
            session.stop_node("publisher")
        self.assertEqual(observed, [session._nodes[0].mesh_port])

        session.start_node("publisher")
        restarted_command = self.agent_commands()[1]
        self.assertNotEqual(
            restarted_command[restarted_command.index("--mesh-bind") + 1],
            first_command[first_command.index("--mesh-bind") + 1],
        )
        self.assert_mesh_port_reserved(restarted_command)

    def test_authenticate_restarts_both_with_reciprocal_peers_and_exact_challenge(self):
        session = self.session()
        session.initialize()
        session.start_node("publisher")
        session.start_node("receiver")

        authenticated = session.authenticate()

        self.assertEqual(authenticated, {"status": "authenticated", "challenge": "verified"})
        commands = self.agent_commands()
        self.assertEqual(["--peer" in command for command in commands], [False, False, True, True])
        self.assertEqual(
            commands[2][commands[2].index("--peer") + 1],
            f"{2:064x}@{commands[3][commands[3].index('--mesh-bind') + 1]}={102:064x}",
        )
        self.assertEqual(
            commands[3][commands[3].index("--peer") + 1],
            f"{1:064x}@{commands[2][commands[2].index('--mesh-bind') + 1]}={101:064x}",
        )
        self.assertEqual(
            self.ctl_actions(),
            ["publication-init", "publication-init", "subscribe", "subscribe", "publish", "publication-ack"],
        )
        published = json.loads((self.root / "published.json").read_text())
        observed = [
            json.loads(line)
            for line in (self.root / "timeline.jsonl").read_text().splitlines()
            if json.loads(line)["step"] == "observe"
        ]
        self.assertEqual(len(observed), 1)
        self.assertEqual(observed[0]["event_id"], published["id"])
        self.assertEqual(observed[0]["payload"], published["payload"])
        timeline = [json.loads(line)["step"] for line in (self.root / "timeline.jsonl").read_text().splitlines()]
        self.assertLess(timeline.index("observe"), timeline.index("publication-ack"))

    def test_public_start_rejects_peer_configuration(self):
        session = self.session()
        session.initialize()

        with self.assertRaisesRegex(AsterSessionError, "controlled authentication"):
            session.start_node("publisher", authenticated=True)

        self.assertEqual(session.owned_pids, ())
        self.assertEqual(self.agent_commands(), [])

    def test_stopped_node_can_restart_and_pair_can_authenticate_again(self):
        session = self.session()
        session.initialize()
        session.start_node("publisher")
        session.start_node("receiver")
        session.authenticate()
        session.stop_node("publisher")
        session.start_node("publisher")

        authenticated = session.authenticate()

        self.assertEqual(authenticated, {"status": "authenticated", "challenge": "verified"})
        self.assertEqual(len(session.owned_pids), 2)
        self.assertEqual(
            ["--peer" in command for command in self.agent_commands()],
            [False, False, True, True, False, True, True],
        )

    def test_repeated_authentication_fails_closed_when_journal_secret_registry_is_full(self):
        transcript = TranscriptJournal(max_secrets=3)
        session = self.session(transcript=transcript)
        session.initialize()
        session.start_node("publisher")
        session.start_node("receiver")

        with (
            patch(
                "aster_quickstart.aster_session.secrets.token_bytes",
                side_effect=[b"a" * 32, b"b" * 32],
            ),
            patch(
                "aster_quickstart.aster_session.secrets.token_hex",
                side_effect=["1" * 32, "2" * 32],
            ),
        ):
            session.authenticate()
            session.stop_node("publisher")
            session.start_node("publisher")
            with self.assertRaisesRegex(AsterSessionError, "authentication failed"):
                session.authenticate()

        self.assertEqual(len(transcript._secrets), 3)
        encoded = json.dumps(transcript.snapshot())
        self.assertNotIn((b"a" * 32).decode(), encoded)
        self.assertNotIn((b"b" * 32).decode(), encoded)

    def test_dead_peerless_restart_requires_and_accepts_reauthentication(self):
        session = self.session()
        self.start_authenticated(session)
        publisher = session._nodes[0].process
        self.assertIsNotNone(publisher)
        os.kill(publisher.pid, signal.SIGKILL)
        publisher.process.wait(timeout=1)

        session.start_node("publisher")

        authenticated = session.authenticate()

        self.assertEqual(authenticated, {"status": "authenticated", "challenge": "verified"})
        self.assertEqual(len(session.owned_pids), 2)
        self.assertEqual(session.publish("hello")["receipt"]["text"], "hello")

    def test_authentication_with_one_missing_node_fails_closed(self):
        session = self.session()
        session.initialize()
        session.start_node("publisher")

        with self.assertRaisesRegex(AsterSessionError, "not running"):
            session.authenticate()

        self.assertEqual(session.owned_pids, ())
        with self.assertRaisesRegex(AsterSessionError, "not authenticated"):
            session.publish("hello")

    def test_authentication_dead_fast_path_fails_closed(self):
        session = self.session()
        self.start_authenticated(session)
        publisher = session._nodes[0].process
        self.assertIsNotNone(publisher)
        os.kill(publisher.pid, signal.SIGKILL)
        publisher.process.wait(timeout=1)

        with self.assertRaisesRegex(AsterSessionError, "not running"):
            session.authenticate()

        self.assertEqual(session.owned_pids, ())
        with self.assertRaisesRegex(AsterSessionError, "not authenticated"):
            session.publish("hello")

    def test_authentication_progress_failure_fails_closed(self):
        session = self.session()
        session.initialize()
        session.start_node("publisher")
        session.start_node("receiver")
        updates = []

        def raising_progress(update):
            updates.append(update)
            raise RuntimeError("observer failed")

        with self.assertRaisesRegex(AsterSessionError, "authentication failed"):
            session.authenticate(raising_progress)

        self.assertEqual(updates, [{"status": "authenticating"}])
        self.assertEqual(session.owned_pids, ())
        with self.assertRaisesRegex(AsterSessionError, "not authenticated"):
            session.publish("hello")

    def test_authentication_reentrant_progress_fails_closed(self):
        session = self.session()
        session.initialize()
        session.start_node("publisher")
        session.start_node("receiver")
        updates = []

        def stop_publisher(update):
            updates.append(update)
            session.stop_node("publisher")

        with self.assertRaisesRegex(AsterSessionError, "not running"):
            session.authenticate(stop_publisher)

        self.assertEqual(updates, [{"status": "authenticating"}])
        self.assertEqual(session.owned_pids, ())
        with self.assertRaisesRegex(AsterSessionError, "not authenticated"):
            session.publish("hello")

    def test_authentication_reentrant_close_releases_mesh_ports(self):
        session = self.session()
        session.initialize()
        session.start_node("publisher")
        session.start_node("receiver")
        commands = self.agent_commands()

        with self.assertRaisesRegex(AsterSessionError, "not running"):
            session.authenticate(lambda update: session.close())

        self.assertEqual(session.owned_pids, ())
        self.assertFalse(self.root.exists())
        for command in commands:
            self.assert_mesh_port_available(command)

    def test_failed_challenge_stops_both_and_never_authenticates(self):
        session = self.session(startup_timeout=0.2, rpc_timeout=0.1)
        session.initialize()
        session.start_node("publisher")
        session.start_node("receiver")
        self.set_mode("receiver_silence")

        with self.assertRaisesRegex(AsterSessionError, "delivery deadline"):
            session.authenticate()

        self.assertEqual(session.owned_pids, ())
        with self.assertRaisesRegex(AsterSessionError, "not authenticated"):
            session.publish("hello")
        self.assertNotIn("publication-ack", self.ctl_actions())

    def test_user_event_remains_first_visible_delivery_after_challenge(self):
        session = self.session()
        session.initialize()
        session.start_node("publisher")
        session.start_node("receiver")
        session.authenticate()

        result = session.publish("hello")

        self.assertEqual(
            result,
            {
                "commit": {
                    "event_id": (b"e" * 32).hex(),
                    "text": "hello",
                    "status": "committed",
                    "durable": True,
                    "node": "atlas",
                },
                "receipt": {
                    "event_id": (b"e" * 32).hex(),
                    "text": "hello",
                    "status": "received",
                    "observed": True,
                    "node": "beacon",
                },
            },
        )
        commands = [
            command for command in self.agent_commands()
            if "--peer" in command
        ]
        self.assertEqual(len(commands), 2)
        publish_commands = [
            json.loads(line)
            for line in (self.root / "ctl-argv.jsonl").read_text().splitlines()
            if "publish" in json.loads(line)
        ]
        self.assertEqual(len(publish_commands), 2)
        self.assertTrue(
            publish_commands[0][publish_commands[0].index("--logical-key") + 1].startswith(
                "quickstart-auth-challenge-"
            )
        )
        self.assertEqual(
            publish_commands[1][publish_commands[1].index("--logical-key") + 1],
            "quickstart-event-1",
        )
        observed = [
            json.loads(line)
            for line in (self.root / "timeline.jsonl").read_text().splitlines()
            if json.loads(line)["step"] == "observe"
        ]
        self.assertEqual(len(observed), 2)
        self.assertNotEqual(observed[0]["payload"], base64.b64encode(b"hello").decode())
        self.assertEqual(observed[1]["payload"], base64.b64encode(b"hello").decode())
        self.assertEqual(self.ctl_actions().count("publication-ack"), 2)

    def test_operational_sequence_starts_two_invited_nodes_and_observes_exact_event(self):
        session = self.session()

        authenticated = self.start_authenticated(session)
        result = session.publish("hello")

        self.assertEqual(authenticated, {"status": "authenticated", "challenge": "verified"})
        self.assertEqual(result, {
            "commit": {
                "event_id": (b"e" * 32).hex(),
                "text": "hello",
                "status": "committed",
                "durable": True,
                "node": "atlas",
            },
            "receipt": {
                "event_id": (b"e" * 32).hex(),
                "text": "hello",
                "status": "received",
                "observed": True,
                "node": "beacon",
            },
        })
        initializer_argv = json.loads((self.root / "initializer-argv.json").read_text())
        self.assertEqual(initializer_argv, ["playground-init", "--nodes", "2", "--root", str(self.root)])
        agent_commands = [json.loads(line) for line in (self.root / "agent-argv.jsonl").read_text().splitlines()]
        self.assertEqual(["--peer" in command for command in agent_commands], [False, False, True, True])
        self.assertTrue(all("@127.0.0.1:" in command[command.index("--peer") + 1] for command in agent_commands[2:]))
        ctl_commands = [json.loads(line) for line in (self.root / "ctl-argv.jsonl").read_text().splitlines()]
        self.assertEqual([next(item for item in command if item in {"publication-init", "subscribe", "publish", "publication-ack"}) for command in ctl_commands], [
            "publication-init", "publication-init", "subscribe", "subscribe", "publish", "publication-ack", "publish", "publication-ack",
        ])
        timeline = [json.loads(line)["step"] for line in (self.root / "timeline.jsonl").read_text().splitlines()]
        self.assertLess(timeline[-2:].index("observe"), timeline[-2:].index("publication-ack"))
        self.assertEqual(stat.S_IMODE(self.root.stat().st_mode), 0o700)
        for index in range(2):
            state = self.root / f"node-{index}"
            self.assertEqual(stat.S_IMODE(state.stat().st_mode), 0o700)
            self.assertEqual(stat.S_IMODE((state / "playground.client.token").stat().st_mode), 0o600)

    def test_publication_progress_reports_durable_commit_before_receiver_observation(self):
        session = self.session()
        self.start_authenticated(session)
        updates = []
        observation_visible_during_callback = []
        prior_observations = sum(
            json.loads(line)["step"] == "observe"
            for line in (self.root / "timeline.jsonl").read_text().splitlines()
        )

        def record(update):
            updates.append(update)
            timeline = [
                json.loads(line)["step"]
                for line in (self.root / "timeline.jsonl").read_text().splitlines()
            ]
            observation_visible_during_callback.append(timeline.count("observe") > prior_observations)

        result = session.publish_with_progress("hello", record)

        self.assertEqual(updates, [{"commit": result["commit"]}])
        self.assertEqual(observation_visible_during_callback, [False])
        self.assertEqual(result["receipt"]["event_id"], result["commit"]["event_id"])

    def test_agent_early_exit_fails_quickly_and_keeps_initialized_state_for_retry(self):
        self.set_mode("early")
        transcript = TranscriptJournal()
        session = self.session(transcript=transcript)

        started = time.monotonic()
        with self.assertRaisesRegex(AsterSessionError, "exited before readiness"):
            self.start_authenticated(session)
        self.assertLess(time.monotonic() - started, 1.5)
        self.assertEqual(session.owned_pids, ())
        self.assertTrue(self.root.is_dir())
        self.assert_final_command(
            transcript,
            "aster-agent",
            outcome="failed",
            returncode=23,
            stdout="",
            stderr="fixture agent exited\n",
        )
        session.close()
        self.assertFalse(self.root.exists())

    def test_early_exit_with_an_unpinned_descendant_fails_closed_without_group_signal(self):
        self.set_mode("early_descendant")
        session = self.session()

        with self.assertRaisesRegex(AsterSessionError, "startup and cleanup failed"):
            self.start_authenticated(session)
        descendant_paths = list(self.parent.glob("session.descendant-*.pid"))
        self.assertTrue(descendant_paths)
        descendant_pids = [int(path.read_text()) for path in descendant_paths]
        for pid in descendant_pids:
            self.addCleanup(self.kill_if_alive, pid)
        self.assertTrue(session.owned_pids)
        with self.assertRaisesRegex(AsterSessionError, "cleanup failed"):
            session.close()
        for pid in descendant_pids:
            self.kill_if_alive(pid)
        self.assert_no_live_pids(descendant_pids)
        session.close()

    def test_malformed_readiness_never_becomes_ready(self):
        self.set_mode("malformed")
        session = self.session(startup_timeout=0.2)

        with self.assertRaisesRegex(AsterSessionError, "startup deadline"):
            self.start_authenticated(session)
        self.assertEqual(session.owned_pids, ())

    def test_readiness_rejects_duplicate_fields_and_trailing_tokens(self):
        self.set_mode("readiness_grammar")
        session = self.session(startup_timeout=0.2)

        with self.assertRaisesRegex(AsterSessionError, "startup deadline"):
            self.start_authenticated(session)
        self.assertEqual(session.owned_pids, ())

    def test_readiness_accepts_required_fields_with_production_metadata(self):
        self.set_mode("production_readiness")
        session = self.session()

        authenticated = self.start_authenticated(session)

        self.assertEqual(authenticated, {"status": "authenticated", "challenge": "verified"})
        self.assertEqual(len(session.owned_pids), 2)

    def test_startup_silence_times_out_and_reaps_children(self):
        self.set_mode("timeout")
        transcript = TranscriptJournal()
        session = self.session(startup_timeout=0.2, transcript=transcript)

        with self.assertRaisesRegex(AsterSessionError, "startup deadline"):
            self.start_authenticated(session)
        self.assertEqual(session.owned_pids, ())
        self.assert_final_command(
            transcript,
            "aster-agent",
            outcome="timed out",
            returncode=-signal.SIGKILL,
            stdout="",
            stderr="",
        )

    def test_agent_output_overflow_finalizes_its_entry(self):
        self.set_mode("noisy")
        transcript = TranscriptJournal(max_stream_bytes=MAX_CAPTURE_BYTES)
        session = self.session(startup_timeout=0.8, transcript=transcript)

        with self.assertRaisesRegex(AsterSessionError, "output exceeds its bound"):
            session.initialize()
            session.start_node("publisher")

        self.assertEqual(session.owned_pids, ())
        agent_stdout = (self.root / "logs" / "node-0" / "run-1" / "agent.stdout").read_text()
        entry = self.assert_final_command(
            transcript,
            "aster-agent",
            outcome="output overflow",
            returncode=-signal.SIGKILL,
            stdout=agent_stdout,
            stderr="x" * MAX_CAPTURE_BYTES,
        )
        self.assertEqual(entry["step"], "publisher")

    def test_post_readiness_overflow_stops_the_owned_agent_group_without_cleanup(self):
        self.set_mode("ready_overflow_descendant")
        transcript = TranscriptJournal(max_stream_bytes=MAX_CAPTURE_BYTES)
        session = self.session(transcript=transcript)
        session.initialize()
        receipt = session.start_node("publisher")
        descendant_path = self.root.with_suffix(".ready-overflow-descendant-0.pid")
        deadline = time.monotonic() + 1
        while not descendant_path.exists() and time.monotonic() < deadline:
            time.sleep(0.01)
        self.assertTrue(descendant_path.exists())
        descendant = int(descendant_path.read_text())
        self.addCleanup(self.kill_if_alive, descendant)

        entry = self.wait_for_final_command(transcript, "aster-agent")

        self.assert_no_live_pids([receipt["pid"], descendant])
        self.assertEqual(entry["step"], "publisher")
        self.assertEqual(entry["outcome"], "output overflow")
        self.assertEqual(entry["returncode"], -signal.SIGKILL)
        self.assertEqual(
            entry["stdout"],
            (self.root / "logs" / "node-0" / "run-1" / "agent.stdout").read_text(),
        )
        self.assertEqual(entry["stderr"], "x" * MAX_CAPTURE_BYTES)
        self.assertEqual(
            len([entry for entry in transcript.snapshot() if "aster-agent" in (entry["command"] or "")]),
            1,
        )

    def test_overflowed_exited_leader_with_live_group_records_overflow(self):
        self.set_mode("ready_child_overflow")
        transcript = TranscriptJournal(max_stream_bytes=MAX_CAPTURE_BYTES)
        session = self.session(transcript=transcript)
        session.initialize()
        receipt = session.start_node("publisher")
        descendant_path = self.root.with_suffix(".child-overflow-descendant-0.pid")
        deadline = time.monotonic() + 1
        while not descendant_path.exists() and time.monotonic() < deadline:
            time.sleep(0.01)
        self.assertTrue(descendant_path.exists())
        descendant = int(descendant_path.read_text())
        self.addCleanup(self.kill_if_alive, descendant)
        os.kill(receipt["pid"], signal.SIGKILL)
        process = session._nodes[0].process
        self.assertIsNotNone(process)
        process.process.wait(timeout=1)
        entry = self.wait_for_final_command(transcript, "aster-agent")

        self.assertEqual(entry["step"], "publisher")
        self.assertEqual(entry["outcome"], "output overflow")
        self.assertEqual(entry["returncode"], -signal.SIGKILL)
        self.assertEqual(
            entry["stdout"],
            (self.root / "logs" / "node-0" / "run-1" / "agent.stdout").read_text(),
        )
        self.assertEqual(entry["stderr"], "x" * MAX_CAPTURE_BYTES)
        os.kill(descendant, 0)
        self.kill_if_alive(descendant)
        self.assert_no_live_pids([descendant])
        self.wait_for_group_gone(receipt["pid"])
        session.close()

    def test_operational_start_cancellation_stops_started_agents_promptly(self):
        self.set_mode("timeout")
        cancel = threading.Event()
        transcript = TranscriptJournal()
        session = AsterSession(
            self.binaries,
            self.root,
            startup_timeout=5,
            rpc_timeout=0.5,
            cancel_event=cancel,
            transcript=transcript,
        )
        errors = []
        worker = threading.Thread(target=lambda: self._capture_start_error(session, errors))
        worker.start()
        agent_argv = self.root / "agent-argv.jsonl"
        deadline = time.monotonic() + 1
        while not agent_argv.exists() and time.monotonic() < deadline:
            time.sleep(0.01)
        self.assertTrue(agent_argv.exists())

        started = time.monotonic()
        cancel.set()
        worker.join(timeout=1)

        self.assertFalse(worker.is_alive())
        self.assertLess(time.monotonic() - started, 0.8)
        self.assertEqual(len(errors), 1)
        self.assertIsInstance(errors[0], AsterSessionError)
        self.assertIn("cancelled", str(errors[0]))
        self.assertEqual(session.owned_pids, ())
        self.assert_final_command(
            transcript,
            "aster-agent",
            outcome="cancelled",
            returncode=-signal.SIGKILL,
            stdout="",
            stderr="",
        )

    def test_operational_start_cancellation_stops_numbered_command_promptly(self):
        self.set_mode("auth_ctl_timeout")
        cancel = threading.Event()
        session = AsterSession(
            self.binaries,
            self.root,
            startup_timeout=5,
            rpc_timeout=5,
            cancel_event=cancel,
        )
        errors = []
        worker = threading.Thread(target=lambda: self._capture_start_error(session, errors))
        worker.start()
        descendant_path = self.root.with_suffix(".auth-ctl-descendant.pid")
        deadline = time.monotonic() + 1
        while not descendant_path.exists() and time.monotonic() < deadline:
            time.sleep(0.01)
        self.assertTrue(descendant_path.exists())
        descendant = int(descendant_path.read_text())
        self.addCleanup(self.kill_if_alive, descendant)

        started = time.monotonic()
        cancel.set()
        worker.join(timeout=1)

        self.assertFalse(worker.is_alive())
        self.assertLess(time.monotonic() - started, 0.8)
        self.assertEqual(len(errors), 1)
        self.assertIn("cancelled", str(errors[0]))
        self.assert_no_live_pids([descendant])
        self.assertEqual(session.owned_pids, ())

    def _capture_start_error(self, session, errors):
        try:
            self.start_authenticated(session)
        except Exception as error:
            errors.append(error)

    @staticmethod
    def _capture_offline_error(session, errors):
        try:
            session.offline_publish("offline")
        except Exception as error:
            errors.append(error)

    def _wait_for_offline_restore(self):
        deadline = time.monotonic() + 1
        commands = []
        while time.monotonic() < deadline:
            commands = [json.loads(line) for line in (self.root / "agent-argv.jsonl").read_text().splitlines()]
            if len(commands) >= 8:
                break
            time.sleep(0.01)
        self.assertEqual(["--peer" in command for command in commands], [False, False, True, True, False, False, True, True])

    def test_second_node_start_failure_preserves_the_independent_running_node(self):
        self.set_mode("partial")
        session = self.session()

        with self.assertRaises(AsterSessionError):
            self.start_authenticated(session)
        first_node = session.owned_pids
        self.assertEqual(len(first_node), 1)
        session.close()
        self.assert_no_live_pids(first_node)

    def assert_publish_failure_reaps_session(self, mode, message_pattern=None, **timeouts):
        session = self.session(**timeouts)
        self.start_authenticated(session)
        action_count_before_publication = len(self.ctl_actions())
        self.set_mode(mode)
        leaders = session.owned_pids
        context = self.assertRaisesRegex(AsterSessionError, message_pattern) if message_pattern else self.assertRaises(AsterSessionError)
        with context:
            session.publish("hello")
        self.assertEqual(session.owned_pids, ())
        self.assert_no_live_pids(leaders)
        actions = [
            next(item for item in command if item in {"publication-init", "subscribe", "publish", "publication-ack"})
            for command in (
                json.loads(line)
                for line in self.root.with_suffix(".ctl-argv.jsonl").read_text().splitlines()
            )
        ][action_count_before_publication:]
        session.close()
        session.close()
        self.assertFalse(self.root.exists())
        return actions

    def test_receiver_silence_fails_closed_and_leaves_the_journal_unacknowledged(self):
        actions = self.assert_publish_failure_reaps_session(
            "receiver_silence",
            "delivery deadline",
            startup_timeout=0.2,
            rpc_timeout=0.1,
        )
        self.assertIn("publish", actions)
        self.assertNotIn("publication-ack", actions)

    def test_wrong_observed_payload_fails_closed(self):
        actions = self.assert_publish_failure_reaps_session("wrong_payload", "different payload")
        self.assertNotIn("publication-ack", actions)

    def test_wrong_publication_receipt_fails_closed_and_remains_recoverable(self):
        actions = self.assert_publish_failure_reaps_session(
            "wrong_receipt",
            "delivery deadline",
            startup_timeout=0.2,
            rpc_timeout=0.1,
        )
        self.assertNotIn("publication-ack", actions)

    def test_malformed_query_events_fails_closed(self):
        actions = self.assert_publish_failure_reaps_session("malformed_query", "malformed Event page")
        self.assertNotIn("publication-ack", actions)

    def test_numbered_publication_output_overflow_fails_closed(self):
        actions = self.assert_publish_failure_reaps_session("ctl_noisy", "bound", rpc_timeout=0.1)
        self.assertNotIn("publication-ack", actions)

    def test_numbered_publication_timeout_reaps_its_descendant_and_the_agents(self):
        session = self.session(rpc_timeout=0.05)
        self.start_authenticated(session)
        leaders = session.owned_pids
        self.set_mode("ctl_timeout_descendant")

        with self.assertRaises(AsterSessionError):
            session.publish("hello")

        descendant = int(self.root.with_suffix(".ctl-descendant.pid").read_text())
        self.addCleanup(self.kill_if_alive, descendant)
        self.assertEqual(session.owned_pids, ())
        self.assert_no_live_pids([*leaders, descendant])

    def test_delivery_deadline_bounds_multi_page_query_and_reaps_agents(self):
        session = self.session(startup_timeout=0.2, rpc_timeout=0.15)
        self.start_authenticated(session)
        self.set_mode("slow_pages")

        started = time.monotonic()
        with self.assertRaises(AsterSessionError):
            session.publish("hello")
        elapsed = time.monotonic() - started

        self.assertLess(elapsed, 0.55)
        self.assertEqual(session.owned_pids, ())

    def test_offline_publish_commits_without_contacts_then_restores_and_receives(self):
        session = self.session()
        self.start_authenticated(session)
        initial_pids = session.owned_pids
        progress = []

        result = session.offline_publish("offline", progress.append)

        commands = [json.loads(line) for line in (self.root / "agent-argv.jsonl").read_text().splitlines()]
        self.assertEqual(["--peer" in command for command in commands], [False, False, True, True, False, False, True, True])
        self.assertEqual(
            progress,
            [
                {"availability": "unavailable"},
                {"commit": result["commit"]},
                {"availability": "available"},
                {"receipt": result["receipt"]},
            ],
        )
        self.assertEqual(progress[1]["commit"]["event_id"], (b"e" * 32).hex())
        self.assertEqual(result["commit"]["event_id"], result["receipt"]["event_id"])
        timeline = [json.loads(line) for line in (self.root / "timeline.jsonl").read_text().splitlines()]
        publish_index = [index for index, item in enumerate(timeline) if item["step"] == "publish"][-1]
        peerless_start = max(
            index for index, item in enumerate(timeline[:publish_index])
            if item["step"] == "agent-start" and item["peer"] is False
        )
        restored_start = min(
            index for index, item in enumerate(timeline[publish_index + 1:], publish_index + 1)
            if item["step"] == "agent-start" and item["peer"] is True
        )
        observe_index = [index for index, item in enumerate(timeline) if item["step"] == "observe"][-1]
        self.assertLess(peerless_start, publish_index)
        self.assertLess(publish_index, restored_start)
        self.assertLess(restored_start, observe_index)
        self.assert_no_live_pids(initial_pids)

    def test_offline_publish_failure_restores_contacts_and_keeps_session_usable(self):
        session = self.session(startup_timeout=0.2, rpc_timeout=0.1)
        self.start_authenticated(session)
        initial_pids = session.owned_pids
        self.set_mode("offline_receiver_silence")

        with self.assertRaisesRegex(RecoverableOfflinePublishError, "delivery deadline"):
            session.offline_publish("offline")

        commands = [json.loads(line) for line in (self.root / "agent-argv.jsonl").read_text().splitlines()]
        self.assertEqual(["--peer" in command for command in commands], [False, False, True, True, False, False, True, True])
        self.assertEqual(len(session.owned_pids), 2)
        self.assert_no_live_pids(initial_pids)
        self.set_mode("ready")
        recovered = session.publish("recovered")
        self.assertEqual(recovered["receipt"]["text"], "recovered")

    def test_peerless_commit_failure_restores_contacts_before_returning(self):
        session = self.session()
        self.start_authenticated(session)
        initial_pids = session.owned_pids
        self.set_mode("offline_publish_failure")

        with self.assertRaisesRegex(RecoverableOfflinePublishError, "numbered publication command failed"):
            session.offline_publish("offline")

        commands = [json.loads(line) for line in (self.root / "agent-argv.jsonl").read_text().splitlines()]
        self.assertEqual(["--peer" in command for command in commands], [False, False, True, True, False, False, True, True])
        self.assertEqual(len(session.owned_pids), 2)
        self.assert_no_live_pids(initial_pids)

    def test_silent_receiver_cancellation_returns_promptly_and_reaps_every_generation(self):
        cancel = threading.Event()
        session = AsterSession(
            self.binaries,
            self.root,
            startup_timeout=1.2,
            rpc_timeout=0.1,
            cancel_event=cancel,
        )
        self.addCleanup(session.close)
        self.start_authenticated(session)
        self.set_mode("offline_receiver_silence")
        errors = []

        def run_experiment():
            try:
                session.offline_publish("offline")
            except Exception as error:
                errors.append(error)

        worker = threading.Thread(target=run_experiment)
        worker.start()
        deadline = time.monotonic() + 1
        commands = []
        while time.monotonic() < deadline:
            commands = [json.loads(line) for line in (self.root / "agent-argv.jsonl").read_text().splitlines()]
            if len(commands) >= 8:
                break
            time.sleep(0.01)
        self.assertEqual(["--peer" in command for command in commands], [False, False, True, True, False, False, True, True])
        timeline = [json.loads(line) for line in (self.root / "timeline.jsonl").read_text().splitlines()]
        all_agent_pids = [item["pid"] for item in timeline if item["step"] == "agent-start"]

        started = time.monotonic()
        cancel.set()
        worker.join(timeout=0.4)
        prompt = not worker.is_alive()
        if worker.is_alive():
            worker.join(timeout=2)
        owned_on_return = session.owned_pids

        self.assertTrue(prompt, "silent receiver ignored cancellation")
        self.assertLess(time.monotonic() - started, 0.8)
        self.assertEqual(len(errors), 1)
        self.assertIn("cancelled", str(errors[0]))
        self.assertEqual(owned_on_return, ())
        self.assert_no_live_pids(all_agent_pids)
        self.assertFalse(self.root.exists())

    def test_offline_restore_failure_finalizes_the_owned_root(self):
        """Catches an offline restoration failure that leaves raw session state behind."""
        session = self.session()
        self.start_authenticated(session)
        original_pids = session.owned_pids
        self.set_mode("offline_restore_failure")

        with self.assertRaisesRegex(AsterSessionError, "contacts could not be restored"):
            session.offline_publish("offline")

        self.assertEqual(session.owned_pids, ())
        self.assert_no_live_pids(original_pids)
        self.assertFalse(self.root.exists())

    def test_offline_restore_failure_chains_the_recovery_error(self):
        """Catches restoration failure reporting the original experiment error instead."""
        session = self.session()
        self.start_authenticated(session)
        original_restart = session._restart_nodes
        first_restore_error = AsterSessionError("first restoration failure")
        retry_restore_error = AsterSessionError("retry restoration failure")
        restoration_attempts = 0

        def restore_failure(*, with_contacts, **kwargs):
            nonlocal restoration_attempts
            if not with_contacts:
                return original_restart(with_contacts=with_contacts, **kwargs)
            restoration_attempts += 1
            if restoration_attempts == 1:
                raise first_restore_error
            raise retry_restore_error

        with patch.object(session, "_restart_nodes", side_effect=restore_failure):
            with self.assertRaisesRegex(AsterSessionError, "contacts could not be restored") as caught:
                session.offline_publish("offline")

        self.assertIs(caught.exception.__cause__, retry_restore_error)
        self.assertFalse(self.root.exists())

    def test_offline_restore_cleanup_process_failure_preserves_root_for_retry(self):
        """Catches terminal cleanup hiding a live owned process behind a synthetic success."""
        session = self.session()
        self.start_authenticated(session)
        original_restart = session._restart_nodes
        restore_error = AsterSessionError("injected restoration failure")
        stop_error = AsterSessionError("injected process stop failure")
        stop_patch = None
        stop_failed = False

        def restore_failure(*, with_contacts, **kwargs):
            if with_contacts:
                nonlocal stop_patch
                if stop_patch is None:
                    process = session._nodes[0].process
                    self.assertIsNotNone(process)
                    original_stop = process.stop

                    def stop_once():
                        nonlocal stop_failed
                        if not stop_failed:
                            stop_failed = True
                            raise stop_error
                        return original_stop()

                    stop_patch = patch.object(process, "stop", side_effect=stop_once)
                    stop_patch.start()
                raise restore_error
            return original_restart(with_contacts=with_contacts, **kwargs)

        with patch.object(session, "_restart_nodes", side_effect=restore_failure):
            with self.assertRaisesRegex(AsterSessionError, "cleanup failed") as caught:
                session.offline_publish("offline")

        self.assertIsNotNone(stop_patch)
        self.assertTrue(stop_failed)
        self.assertTrue(session.owned_pids)
        self.assertTrue(self.root.is_dir())
        try:
            self.assertIs(caught.exception.__cause__, stop_error)
        finally:
            stop_patch.stop()
        session.close()
        self.assertEqual(session.owned_pids, ())
        self.assertFalse(self.root.exists())

    def test_offline_restore_cleanup_root_deletion_failure_preserves_root_for_retry(self):
        """Catches terminal cleanup marking a failed root deletion as successfully closed."""
        session = self.session()
        self.start_authenticated(session)
        self.set_mode("offline_restore_failure")
        original_restart = session._restart_nodes

        def restore_failure(*, with_contacts, **kwargs):
            if with_contacts:
                raise AsterSessionError("injected restoration failure")
            return original_restart(with_contacts=with_contacts, **kwargs)

        deletion_error = OSError("injected deletion failure")
        with patch.object(session, "_restart_nodes", side_effect=restore_failure), patch(
            "aster_quickstart.aster_session.shutil.rmtree", side_effect=deletion_error
        ):
            with self.assertRaisesRegex(AsterSessionError, "cleanup failed") as caught:
                session.offline_publish("offline")

        self.assertIs(caught.exception.__cause__, deletion_error)
        self.assertEqual(session.owned_pids, ())
        self.assertTrue(self.root.is_dir())
        session.close()
        self.assertFalse(self.root.exists())

    def test_offline_cancellation_process_cleanup_failure_preserves_root_for_retry(self):
        """Catches cancellation cleanup losing an owned process before retry can stop it."""
        cancel = threading.Event()
        session = AsterSession(
            self.binaries,
            self.root,
            startup_timeout=1.2,
            rpc_timeout=0.1,
            cancel_event=cancel,
        )
        self.addCleanup(session.close)
        self.start_authenticated(session)
        self.set_mode("offline_receiver_silence")
        errors = []
        worker = threading.Thread(target=lambda: self._capture_offline_error(session, errors))
        worker.start()
        self._wait_for_offline_restore()
        process = session._nodes[0].process
        self.assertIsNotNone(process)
        stop_error = AsterSessionError("injected cancellation stop failure")
        original_stop = process.stop
        stop_failed = False

        def stop_once():
            nonlocal stop_failed
            if not stop_failed:
                stop_failed = True
                raise stop_error
            return original_stop()

        with patch.object(process, "stop", side_effect=stop_once):
            cancel.set()
            worker.join(timeout=1)

        self.assertFalse(worker.is_alive())
        self.assertEqual(len(errors), 1)
        self.assertEqual(str(errors[0]), "offline experiment cancellation cleanup failed")
        self.assertIs(errors[0].__cause__, stop_error)
        self.assertTrue(stop_failed)
        self.assertTrue(session.owned_pids)
        self.assertTrue(self.root.is_dir())
        session.close()
        self.assertEqual(session.owned_pids, ())
        self.assertFalse(self.root.exists())

    def test_offline_cancellation_root_deletion_failure_preserves_root_for_retry(self):
        """Catches cancellation cleanup hiding a confined root deletion failure."""
        cancel = threading.Event()
        session = AsterSession(
            self.binaries,
            self.root,
            startup_timeout=1.2,
            rpc_timeout=0.1,
            cancel_event=cancel,
        )
        self.addCleanup(session.close)
        self.start_authenticated(session)
        self.set_mode("offline_receiver_silence")
        errors = []
        worker = threading.Thread(target=lambda: self._capture_offline_error(session, errors))
        worker.start()
        self._wait_for_offline_restore()
        deletion_error = OSError("injected cancellation deletion failure")

        with patch("aster_quickstart.aster_session.shutil.rmtree", side_effect=deletion_error):
            cancel.set()
            worker.join(timeout=1)

        self.assertFalse(worker.is_alive())
        self.assertEqual(len(errors), 1)
        self.assertEqual(str(errors[0]), "offline experiment cancellation cleanup failed")
        self.assertIs(errors[0].__cause__, deletion_error)
        self.assertEqual(session.owned_pids, ())
        self.assertTrue(self.root.is_dir())
        session.close()
        self.assertFalse(self.root.exists())

    def test_repeated_experiments_keep_a_fixed_number_of_agent_log_generations(self):
        session = self.session()
        self.start_authenticated(session)

        for index in range(5):
            session.offline_publish(f"offline-{index}")

        for node_index in range(2):
            runs = sorted((self.root / "logs" / f"node-{node_index}").glob("run-*"))
            self.assertLessEqual(len(runs), 3)
            self.assertTrue(all(path.is_dir() and not path.is_symlink() for path in runs))

    def test_restart_log_symlink_cannot_redirect_files_outside_the_session(self):
        session = self.session()
        self.start_authenticated(session)
        node_logs = self.root / "logs" / "node-0"
        shutil.rmtree(node_logs)
        outside = self.parent / "outside-logs"
        outside.mkdir()
        sentinel = outside / "sentinel"
        sentinel.write_text("unchanged")
        node_logs.symlink_to(outside, target_is_directory=True)

        with self.assertRaises(AsterSessionError):
            session.offline_publish("offline")

        self.assertEqual(sentinel.read_text(), "unchanged")
        self.assertEqual([path.name for path in outside.iterdir()], ["sentinel"])
        self.assertEqual(session.owned_pids, ())

    def test_close_is_idempotent_and_kills_the_entire_process_groups(self):
        self.set_mode("descendant")
        session = self.session()
        self.start_authenticated(session)
        leader_pids = session.owned_pids
        descendant_paths = [self.root.with_suffix(f".descendant-{index}.pid") for index in range(2)]
        deadline = time.monotonic() + 1
        while not all(path.exists() for path in descendant_paths) and time.monotonic() < deadline:
            time.sleep(0.01)
        descendant_pids = [int(path.read_text()) for path in descendant_paths]

        session.close()
        session.close()

        self.assertEqual(session.owned_pids, ())
        self.assert_no_live_pids([*leader_pids, *descendant_pids])
        self.assertFalse(self.root.exists())

    def test_cleanup_failure_preserves_raw_session_root_for_diagnostics(self):
        session = self.session()
        self.start_authenticated(session)

        with patch("aster_quickstart.aster_session.shutil.rmtree", side_effect=OSError("disk failure")):
            with self.assertRaisesRegex(AsterSessionError, "cleanup failed"):
                session.close()

        self.assertTrue(self.root.is_dir())
        self.assertEqual(session.owned_pids, ())
        session.close()
        self.assertFalse(self.root.exists())

    def test_initializer_cannot_escape_the_owned_root_with_symlinked_state(self):
        self.set_mode("root_escape")
        session = self.session()

        with self.assertRaisesRegex(AsterSessionError, "contained"):
            self.start_authenticated(session)

        outside = self.parent / "outside"
        self.assertEqual(stat.S_IMODE(outside.stat().st_mode), 0o755)
        self.assertEqual((outside / "mission.unprotected-reference.bundle").read_bytes(), b"outside")
        self.assertEqual(session.owned_pids, ())

    def test_binary_validation_rejects_non_executable_and_aliases(self):
        self.ctl.chmod(0o600)
        with self.assertRaises(AsterSessionError):
            self.binaries.validate()
        self.ctl.chmod(0o700)
        with self.assertRaises(AsterSessionError):
            AsterBinaries(self.aster, self.aster, self.ctl).validate()


if __name__ == "__main__":
    unittest.main()
