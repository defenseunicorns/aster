from __future__ import annotations

from io import StringIO
import http.client
import json
import multiprocessing
import os
from pathlib import Path
import signal
import tempfile
import threading
import time
import unittest
from unittest.mock import patch
from urllib.parse import parse_qs, urlsplit

from aster_quickstart.__main__ import (
    CleanupRequest,
    QuickstartLauncher,
    _build_aster_session,
    discover_binaries,
    main,
)
from aster_quickstart.aster_session import AsterSessionError
from aster_quickstart.attach import AttachServer
from aster_quickstart.records import RecordJournal
from aster_quickstart.runtime import RuntimeRegistry, current_runtime_descriptor
from aster_quickstart.runtime import RuntimeActiveError, RuntimeDescriptor
from aster_quickstart.web import QuickstartServer
from aster_quickstart.transcript import TranscriptJournal


def _serve_registry_attach(runtime_dir_text, control):
    runtime_dir = Path(runtime_dir_text)
    workspace = runtime_dir / "session"
    workspace.mkdir(parents=True, mode=0o700)
    runtime_dir.chmod(0o700)
    socket_path = workspace / "attach.sock"
    records = RecordJournal()
    attach = AttachServer(socket_path, records, os.geteuid())
    registry = RuntimeRegistry(runtime_dir / "runtime.lock", runtime_dir / "runtime.json")
    try:
        registry.acquire()
        attach.start()
        registry.publish(current_runtime_descriptor(workspace, socket_path))
        records.emit(action="start", node="publisher", outcome="ok", message="started")
        control.send("ready")
        control.recv()
    finally:
        attach.close()
        registry.close(remove_descriptor=False)
        control.close()


class RecordingSession:
    def __init__(self, root: Path, *, fail_initialize: bool = False, close_failures: int = 0):
        self.root = root
        self.fail_initialize = fail_initialize
        self.initialized = False
        self.closed = False
        self.close_failures = close_failures
        self.inventory_observer = None

    def set_process_inventory_observer(self, observer):
        self.inventory_observer = observer
        observer((), None)

    def initialize(self):
        self.root.mkdir(mode=0o700)
        if self.fail_initialize:
            (self.root / "raw-secret.log").write_text("private credential")
            raise RuntimeError("private credential")
        self.initialized = True
        return {
            "status": "initialized",
            "nodes": {
                "publisher": {"identity_fingerprint": "1" * 64},
                "receiver": {"identity_fingerprint": "2" * 64},
            },
        }

    def close(self):
        RecordingServer.order.append("session-close")
        if self.close_failures:
            self.close_failures -= 1
            raise RuntimeError("bounded cleanup failure")
        self.closed = True


class RecordingAttach:
    instances = []
    close_failures = 0

    def __init__(self, path, records, owner_uid):
        self.path = path
        self.records = records
        self.owner_uid = owner_uid
        self.started = False
        self.closed = False
        type(self).instances.append(self)

    def start(self):
        self.path.touch(mode=0o600)
        self.started = True

    def bind_runtime_owner(self, pid):
        self.owner_pid = pid

    def close(self):
        RecordingServer.order.append("attach-close")
        if type(self).close_failures:
            type(self).close_failures -= 1
            raise RuntimeError("adapter close failed")
        self.closed = True
        self.path.unlink(missing_ok=True)

    def command(self, role, detail):
        return ["observer", role, detail]


class RecordingServer:
    instances = []
    order = []
    response_result = "sent"

    def __init__(self, supervisor, token, **adapters):
        self.supervisor = supervisor
        self.token = token
        self.adapters = adapters
        self.started = threading.Event()
        self.closed = False
        self.waited_for_cleanup = False
        self.browser_cleanup = False
        type(self).instances.append(self)

    def start(self):
        self.state_when_started = self.supervisor.snapshot()
        self.attach_started_when_started = RecordingAttach.instances[-1].started
        self.started.set()
        return f"http://127.0.0.1:43123/?token={self.token}"

    def wait_for_cleanup_response(self, timeout):
        type(self).order.append("response-" + type(self).response_result)
        self.waited_for_cleanup = True
        return type(self).response_result

    def browser_cleanup_requested(self):
        return self.browser_cleanup

    def close(self):
        type(self).order.append("server-close")
        self.closed = True


class LauncherTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.bin_dir = self.root / "bin"
        self.bin_dir.mkdir()
        for name in ("aster", "aster-agent", "asterctl"):
            path = self.bin_dir / name
            path.write_text("#!/bin/sh\nexit 0\n")
            path.chmod(0o700)
        RecordingAttach.instances.clear()
        RecordingAttach.close_failures = 0
        RecordingServer.instances.clear()
        RecordingServer.order.clear()
        RecordingServer.response_result = "sent"

    def launcher(self, **overrides):
        sessions = []

        def build_session(_binaries, root, _cancel):
            session = RecordingSession(
                root,
                fail_initialize=overrides.get("fail_initialize", False),
                close_failures=overrides.get("close_failures", 0),
            )
            sessions.append(session)
            return session

        output = overrides.get("output", StringIO())
        error = StringIO()
        runtime_dir = self.root / "runtime"
        runtime = RuntimeRegistry(runtime_dir / "runtime.lock", runtime_dir / "runtime.json")
        launcher = QuickstartLauncher(
            discover_binaries(self.bin_dir),
            no_open=overrides.get("no_open", True),
            detail=overrides.get("detail", "guided"),
            browser_open=overrides.get("browser_open", lambda _url: True),
            output=output,
            error=error,
            runtime_registry=overrides.get("runtime_registry", runtime),
            session_builder=build_session,
            attach_builder=RecordingAttach,
            server_builder=overrides.get("server_builder", RecordingServer),
            terminal_open=overrides.get("terminal_open", lambda _command: False),
        )
        return launcher, sessions, output, error

    def run_until_server_starts(self, launcher, *, browser_cleanup=False):
        stop = CleanupRequest()
        result = []
        worker = threading.Thread(target=lambda: result.append(launcher.run(stop)))
        worker.start()
        deadline = time.monotonic() + 2
        while not RecordingServer.instances and time.monotonic() < deadline:
            time.sleep(0.005)
        self.assertTrue(RecordingServer.instances)
        server = RecordingServer.instances[-1]
        self.assertTrue(server.started.wait(timeout=1))
        if browser_cleanup:
            server.browser_cleanup = True
            server.supervisor.cleanup()
        else:
            stop.set()
        worker.join(timeout=2)
        self.assertFalse(worker.is_alive())
        return result[0]

    @staticmethod
    def request_json(url, route, body):
        parsed = urlsplit(url)
        connection = http.client.HTTPConnection(parsed.hostname, parsed.port, timeout=1)
        encoded = json.dumps(body).encode()
        try:
            connection.request(
                "POST",
                f"{route}?{parsed.query}",
                body=encoded,
                headers={
                    "Content-Type": "application/json",
                    "Origin": f"http://{parsed.hostname}:{parsed.port}",
                },
            )
            response = connection.getresponse()
            return response.status, json.loads(response.read())
        finally:
            connection.close()

    def test_binary_discovery_requires_three_distinct_executables(self):
        binaries = discover_binaries(self.bin_dir)
        self.assertEqual(binaries.aster, (self.bin_dir / "aster").resolve())
        (self.bin_dir / "asterctl").unlink()
        with self.assertRaisesRegex(AsterSessionError, "asterctl binary is unavailable"):
            discover_binaries(self.bin_dir)

    def test_default_session_builder_injects_the_launcher_transcript(self):
        transcript = TranscriptJournal()
        session = _build_aster_session(
            discover_binaries(self.bin_dir),
            self.root / "session",
            CleanupRequest(),
            transcript=transcript,
        )
        self.addCleanup(session.close)

        self.assertIs(session.transcript, transcript)

    def test_launcher_composes_initialized_supervisor_attach_and_browser(self):
        opened = []
        launcher, sessions, output, error = self.launcher(
            no_open=False,
            browser_open=lambda url: opened.append(url),
        )

        self.assertEqual(self.run_until_server_starts(launcher), 0)

        self.assertEqual(len(sessions), 1)
        self.assertTrue(sessions[0].initialized)
        self.assertTrue(sessions[0].closed)
        server = RecordingServer.instances[0]
        self.assertTrue(server.state_when_started["initialized"])
        self.assertEqual(server.state_when_started["nodes"]["publisher"]["state"], "stopped")
        self.assertTrue(server.attach_started_when_started)
        self.assertIs(server.adapters["records"], RecordingAttach.instances[0].records)
        self.assertIs(server.adapters["attach"], RecordingAttach.instances[0])
        self.assertTrue(server.closed)
        self.assertTrue(RecordingAttach.instances[0].closed)
        self.assertEqual(len(opened), 1)
        token = parse_qs(urlsplit(opened[0]).query)["token"][0]
        self.assertGreaterEqual(len(token), 32)
        rendered = output.getvalue()
        self.assertFalse(token in rendered, "stdout exposed the bearer token")
        self.assertFalse("?token=" in rendered, "stdout exposed a tokenized URL")
        self.assertFalse(opened[0] in rendered, "stdout exposed the private browser URL")
        self.assertEqual(error.getvalue(), "")

    def test_custom_terminal_callback_keeps_its_one_argument_launcher_seam(self):
        opened = []
        launcher, _, _, _ = self.launcher(
            terminal_open=lambda command: opened.append(list(command)) or True,
        )

        self.assertEqual(self.run_until_server_starts(launcher), 0)

        callback = RecordingServer.instances[0].adapters["terminal_open"]
        self.assertTrue(callback(["observer", "publisher"], "publisher"))
        self.assertEqual(opened, [["observer", "publisher"]])

    def test_browser_cleanup_response_is_awaited_before_surfaces_close(self):
        launcher, sessions, _, error = self.launcher()

        self.assertEqual(self.run_until_server_starts(launcher, browser_cleanup=True), 0)

        server = RecordingServer.instances[0]
        self.assertTrue(server.waited_for_cleanup)
        self.assertTrue(server.closed)
        self.assertTrue(RecordingAttach.instances[0].closed)
        self.assertTrue(sessions[0].closed)
        self.assertLess(RecordingServer.order.index("attach-close"), RecordingServer.order.index("response-sent"))
        self.assertLess(RecordingServer.order.index("response-sent"), RecordingServer.order.index("server-close"))
        self.assertEqual(error.getvalue(), "")

    def test_cleanup_response_timeout_fails_explicitly_but_still_closes_all_ownership(self):
        RecordingServer.response_result = "timeout"
        launcher, sessions, _, error = self.launcher()

        self.assertEqual(self.run_until_server_starts(launcher, browser_cleanup=True), 1)

        server = RecordingServer.instances[0]
        self.assertTrue(server.waited_for_cleanup)
        self.assertTrue(sessions[0].closed)
        self.assertTrue(RecordingAttach.instances[0].closed)
        self.assertTrue(server.closed)
        self.assertLess(RecordingServer.order.index("attach-close"), RecordingServer.order.index("response-timeout"))
        self.assertEqual(error.getvalue().splitlines()[0], "Quickstart failed.")

    def test_no_open_never_uses_browser_integration(self):
        launcher, sessions, output, error = self.launcher(
            no_open=True,
            browser_open=lambda _url: self.fail("browser must not open"),
        )
        self.assertEqual(self.run_until_server_starts(launcher), 0)
        rendered = output.getvalue()
        self.assertTrue("Quickstart ready." in rendered, "stdout omitted readiness")
        self.assertFalse(
            RecordingServer.instances[0].token in rendered,
            "stdout exposed the bearer token",
        )
        self.assertFalse("?token=" in rendered, "stdout exposed a tokenized URL")
        self.assertFalse("Open:" in rendered, "stdout exposed a private URL")
        self.assertTrue(sessions[0].closed)
        self.assertEqual(error.getvalue(), "")

    def test_no_open_help_describes_headless_credential_free_operation(self):
        output = StringIO()

        with patch("aster_quickstart.__main__.sys.stdout", output):
            with self.assertRaisesRegex(SystemExit, "0"):
                main(["--help"])

        help_text = output.getvalue()
        normalized_help = " ".join(help_text.split())
        self.assertIn("headless", help_text)
        self.assertIn("do not open a browser", normalized_help)
        self.assertIn("or print its credentialed URL", normalized_help)

    def test_overlapping_launcher_is_rejected_before_constructing_resources(self):
        runtime_dir = self.root / "shared-runtime"
        first, first_sessions, _, first_error = self.launcher(
            runtime_registry=RuntimeRegistry(runtime_dir / "runtime.lock", runtime_dir / "runtime.json")
        )
        second, second_sessions, _, second_error = self.launcher(
            runtime_registry=RuntimeRegistry(runtime_dir / "runtime.lock", runtime_dir / "runtime.json")
        )
        stop = CleanupRequest()
        result = []
        worker = threading.Thread(target=lambda: result.append(first.run(stop)))
        worker.start()
        deadline = time.monotonic() + 2
        while not RecordingServer.instances and time.monotonic() < deadline:
            time.sleep(0.005)
        self.assertTrue(RecordingServer.instances)

        self.assertEqual(second.run(CleanupRequest()), 1)
        self.assertEqual(second_sessions, [])
        self.assertEqual(second_error.getvalue(), "Quickstart is already running.\n")
        stop.set()
        worker.join(timeout=2)
        self.assertEqual(result, [0])
        self.assertTrue(first_sessions[0].closed)
        self.assertEqual(first_error.getvalue(), "")

    def test_initialization_failure_never_exposes_raw_diagnostics(self):
        launcher, sessions, output, error = self.launcher(fail_initialize=True)
        self.assertEqual(launcher.run(CleanupRequest()), 1)
        self.assertEqual(RecordingServer.instances, [])
        self.assertEqual(len(RecordingAttach.instances), 1)
        self.assertTrue(RecordingAttach.instances[0].closed)
        self.assertTrue(sessions[0].closed)
        self.assertIn("[error] failed: failed", output.getvalue())
        self.assertNotIn("private credential", output.getvalue())
        self.assertNotIn("private credential", error.getvalue())
        summary = Path(error.getvalue().splitlines()[1].removeprefix("Summary: "))
        self.assertEqual(summary.read_text(), "Quickstart failed; raw session data was removed.\n")

    def test_committed_descriptor_fsync_failure_uses_managed_retry_cleanup(self):
        class CommitThenFailSyncRegistry(RuntimeRegistry):
            sync_failures = 1
            cleanup_pending_seen = False

            def _sync_parent(self):
                if self.sync_failures:
                    self.sync_failures -= 1
                    raise OSError("descriptor fsync failed")
                return super()._sync_parent()

            def mark_cleanup_pending(self, processes):
                self.cleanup_pending_seen = True
                return super().mark_cleanup_pending(processes)

        runtime_dir = self.root / "committed-publication-runtime"
        registry = CommitThenFailSyncRegistry(
            runtime_dir / "runtime.lock", runtime_dir / "runtime.json"
        )
        launcher, sessions, _, error = self.launcher(runtime_registry=registry)

        self.assertEqual(launcher.run(CleanupRequest()), 1)

        self.assertTrue(registry.cleanup_pending_seen)
        self.assertTrue(sessions[0].closed)
        self.assertFalse((runtime_dir / "runtime.json").exists())
        self.assertEqual(list(runtime_dir.glob("session-*")), [])
        self.assertEqual(error.getvalue().splitlines()[0], "Quickstart failed.")

    def test_server_start_failure_closes_attach_and_session(self):
        class FailingServer(RecordingServer):
            def start(self):
                self.started.set()
                raise RuntimeError("private bind detail")

        launcher, sessions, output, error = self.launcher(server_builder=FailingServer)
        self.assertEqual(launcher.run(CleanupRequest()), 1)
        self.assertTrue(sessions[0].closed)
        self.assertTrue(RecordingAttach.instances[0].closed)
        self.assertTrue(FailingServer.instances[-1].closed)
        self.assertIn("[initialize] initialized: ready", output.getvalue())
        self.assertIn("[cleanup] cleaned: cleaned up", output.getvalue())
        self.assertNotIn("private bind detail", error.getvalue())

    def test_sigint_uses_the_same_complete_cleanup_path(self):
        launcher, sessions, _, error = self.launcher()
        started = threading.Event()

        class NotifyingServer(RecordingServer):
            def start(self):
                url = super().start()
                started.set()
                return url

        launcher.server_builder = NotifyingServer

        def interrupt():
            self.assertTrue(started.wait(timeout=1))
            os.kill(os.getpid(), signal.SIGINT)

        sender = threading.Thread(target=interrupt)
        sender.start()
        code = main(
            ["--bin-dir", str(self.bin_dir), "--no-open", "--detail", "guided"],
            launcher_factory=lambda _binaries, _no_open, _detail: launcher,
        )
        sender.join(timeout=1)
        self.assertEqual(code, 0)
        self.assertTrue(sessions[0].closed)
        self.assertTrue(RecordingAttach.instances[0].closed)
        self.assertTrue(NotifyingServer.instances[-1].closed)
        self.assertEqual(error.getvalue(), "")

    def test_stdout_follows_canonical_records_at_the_selected_detail(self):
        launcher, sessions, output, error = self.launcher(detail="compact")

        self.assertEqual(self.run_until_server_starts(launcher), 0)

        rendered = output.getvalue()
        self.assertIn("[initialize] initialized: ready", rendered)
        self.assertIn("[cleanup] cleaned: cleaned up", rendered)
        self.assertNotIn("Start the publisher and receiver when ready.", rendered)
        self.assertTrue(sessions[0].closed)
        self.assertEqual(error.getvalue(), "")

    def test_stdout_record_failure_requests_cleanup_and_returns_failure(self):
        class FailingRecordOutput(StringIO):
            def write(self, value):
                if value.startswith("["):
                    raise OSError("output unavailable")
                return super().write(value)

        runtime_dir = self.root / "writer-runtime"
        output = FailingRecordOutput()
        launcher, sessions, _, error = self.launcher(
            output=output,
            runtime_registry=RuntimeRegistry(
                runtime_dir / "runtime.lock", runtime_dir / "runtime.json"
            ),
        )
        result = []
        stop = CleanupRequest()
        worker = threading.Thread(target=lambda: result.append(launcher.run(stop)))
        worker.start()
        worker.join(timeout=2)
        stopped_after_failure = not worker.is_alive()
        if worker.is_alive():
            stop.set()
            worker.join(timeout=2)

        self.assertTrue(stopped_after_failure)
        self.assertEqual(result, [1])
        self.assertTrue(sessions[0].closed)
        self.assertTrue(RecordingAttach.instances[0].closed)
        self.assertTrue(RecordingServer.instances[0].closed)
        self.assertFalse((runtime_dir / "runtime.json").exists())
        self.assertIn("Quickstart failed.", error.getvalue())
        self.assertNotIn("output unavailable", error.getvalue())

    def test_browser_launch_false_or_exception_fails_promptly_with_safe_retry(self):
        for outcome in ("false", "exception"):
            with self.subTest(outcome=outcome):
                opened = []

                def browser_open(url):
                    opened.append(url)
                    if outcome == "exception":
                        raise RuntimeError("desktop browser unavailable with token=private")
                    return False

                launcher, sessions, output, error = self.launcher(
                    no_open=False,
                    browser_open=browser_open,
                )
                stop = CleanupRequest()
                result = []
                worker = threading.Thread(target=lambda: result.append(launcher.run(stop)))
                worker.start()
                worker.join(timeout=2)
                if worker.is_alive():
                    stop.set()
                    worker.join(timeout=2)

                self.assertFalse(worker.is_alive(), "browser launch failure waited invisibly")
                self.assertEqual(result, [1])
                self.assertTrue(sessions[0].closed)
                self.assertTrue(RecordingAttach.instances[-1].closed)
                self.assertTrue(RecordingServer.instances[-1].closed)
                rendered = output.getvalue() + error.getvalue()
                self.assertIn(
                    "Configure a default browser, then run the quickstart again.",
                    rendered,
                )
                self.assertNotIn("Quickstart ready.", rendered)
                self.assertNotIn(opened[0], rendered)
                self.assertNotIn("?token=", rendered)
                self.assertNotIn("token=private", rendered)

    def test_cleanup_failure_keeps_private_surfaces_for_an_explicit_retry(self):
        launcher, sessions, _, error = self.launcher(close_failures=1)
        stop = CleanupRequest()
        result = []
        worker = threading.Thread(target=lambda: result.append(launcher.run(stop)))
        worker.start()
        deadline = time.monotonic() + 1
        while not RecordingServer.instances and time.monotonic() < deadline:
            time.sleep(0.005)
        server = RecordingServer.instances[-1]
        self.assertTrue(server.started.wait(timeout=1))

        stop.set()
        deadline = time.monotonic() + 1
        while server.supervisor.snapshot()["cleanup"] != "failed" and time.monotonic() < deadline:
            time.sleep(0.005)
        self.assertEqual(server.supervisor.snapshot()["cleanup"], "failed")
        self.assertTrue(worker.is_alive())
        self.assertFalse(server.closed)
        self.assertFalse(RecordingAttach.instances[-1].closed)
        self.assertTrue((self.root / "runtime" / "runtime.json").exists())

        server.supervisor.cleanup()
        worker.join(timeout=2)
        self.assertEqual(result, [0])
        self.assertTrue(sessions[0].closed)
        self.assertTrue(server.closed)
        self.assertTrue(RecordingAttach.instances[-1].closed)
        self.assertFalse((self.root / "runtime" / "runtime.json").exists())
        self.assertEqual(error.getvalue(), "")

    def test_browser_cleanup_reports_registry_failure_and_retries_over_same_http_surface(self):
        class FailWorkspaceOnce(RuntimeRegistry):
            failures = 1

            def delete_workspace(self):
                if self.failures:
                    self.failures -= 1
                    raise OSError("delete failed")
                return super().delete_workspace()

        runtime_dir = self.root / "browser-retry-runtime"
        registry = FailWorkspaceOnce(runtime_dir / "runtime.lock", runtime_dir / "runtime.json")
        opened = []
        launcher, sessions, output, error = self.launcher(
            no_open=False,
            browser_open=lambda private_url: opened.append(private_url),
            runtime_registry=registry,
            server_builder=QuickstartServer,
        )
        result = []
        worker = threading.Thread(target=lambda: result.append(launcher.run(CleanupRequest())))
        worker.start()
        deadline = time.monotonic() + 2
        while not opened and time.monotonic() < deadline:
            time.sleep(0.005)
        self.assertEqual(len(opened), 1)
        url = opened[0]
        token = parse_qs(urlsplit(url).query)["token"][0]
        rendered = output.getvalue()
        self.assertFalse(token in rendered, "stdout exposed the bearer token")
        self.assertFalse("?token=" in rendered, "stdout exposed a tokenized URL")
        self.assertFalse(url in rendered, "stdout exposed the private browser URL")

        status, failed = self.request_json(url, "/api/cleanup", {"confirm": True})

        self.assertEqual(status, 500)
        self.assertEqual(failed["error"]["code"], "operation_failed")
        state = self.request_json(url, "/api/cleanup", {"confirm": True})
        self.assertEqual(state[0], 200)
        self.assertEqual(state[1]["cleanup"], "cleaned")
        worker.join(timeout=2)
        self.assertFalse(worker.is_alive())
        self.assertEqual(result, [0])
        self.assertTrue(sessions[0].closed)
        self.assertFalse((runtime_dir / "runtime.json").exists())
        self.assertEqual(error.getvalue(), "")

    def test_adapter_close_failure_keeps_lock_descriptor_and_retryable_surfaces(self):
        RecordingAttach.close_failures = 1
        launcher, _, _, error = self.launcher()
        request = CleanupRequest()
        result = []
        worker = threading.Thread(target=lambda: result.append(launcher.run(request)))
        worker.start()
        self.assertTrue(self._wait_for_server().started.wait(timeout=1))

        request.set()
        descriptor_path = self.root / "runtime" / "runtime.json"
        deadline = time.monotonic() + 1
        while RecordingAttach.close_failures and time.monotonic() < deadline:
            time.sleep(0.005)
        self.assertTrue(worker.is_alive())
        self.assertEqual(__import__("json").loads(descriptor_path.read_text())["lifecycle"], "cleanup_pending")
        contender = RuntimeRegistry(self.root / "runtime" / "runtime.lock", descriptor_path)
        with self.assertRaises(RuntimeActiveError):
            contender.acquire()

        request.set()
        worker.join(timeout=2)
        self.assertEqual(result, [0])
        self.assertFalse(descriptor_path.exists())
        self.assertEqual(error.getvalue(), "")

    def test_workspace_delete_failure_remains_discoverable_and_retryable(self):
        class FailOnceRegistry(RuntimeRegistry):
            failures = 1

            def delete_workspace(self):
                if self.failures:
                    self.failures -= 1
                    raise OSError("delete failed")
                return super().delete_workspace()

        runtime_dir = self.root / "retry-runtime"
        registry = FailOnceRegistry(runtime_dir / "runtime.lock", runtime_dir / "runtime.json")
        launcher, _, _, error = self.launcher(runtime_registry=registry)
        request = CleanupRequest()
        result = []
        worker = threading.Thread(target=lambda: result.append(launcher.run(request)))
        worker.start()
        self.assertTrue(self._wait_for_server().started.wait(timeout=1))

        request.set()
        deadline = time.monotonic() + 1
        while registry.failures and time.monotonic() < deadline:
            time.sleep(0.005)
        self.assertTrue(worker.is_alive())
        self.assertTrue((runtime_dir / "runtime.json").exists())
        contender = RuntimeRegistry(runtime_dir / "runtime.lock", runtime_dir / "runtime.json")
        with self.assertRaises(RuntimeActiveError):
            contender.acquire()

        request.set()
        worker.join(timeout=2)
        self.assertEqual(result, [0])
        self.assertFalse((runtime_dir / "runtime.json").exists())
        self.assertEqual(error.getvalue(), "")

    def test_descriptor_remove_failure_after_workspace_delete_is_retryable(self):
        class FailRemoveOnceRegistry(RuntimeRegistry):
            failures = 1

            def remove_descriptor(self):
                if self.failures:
                    self.failures -= 1
                    raise OSError("descriptor remove failed")
                return super().remove_descriptor()

        runtime_dir = self.root / "remove-retry-runtime"
        registry = FailRemoveOnceRegistry(
            runtime_dir / "runtime.lock", runtime_dir / "runtime.json"
        )
        launcher, _, _, error = self.launcher(runtime_registry=registry)
        request = CleanupRequest()
        result = []
        worker = threading.Thread(target=lambda: result.append(launcher.run(request)))
        worker.start()
        self.assertTrue(self._wait_for_server().started.wait(timeout=1))

        request.set()
        deadline = time.monotonic() + 1
        while registry.failures and time.monotonic() < deadline:
            time.sleep(0.005)
        self.assertTrue(worker.is_alive())
        self.assertTrue((runtime_dir / "runtime.json").exists())

        request.set()
        worker.join(timeout=2)
        self.assertEqual(result, [0])
        self.assertFalse((runtime_dir / "runtime.json").exists())
        self.assertEqual(error.getvalue(), "")

    def test_every_descriptor_removal_phase_retries_without_restarting_cleanup(self):
        cases = (
            ("link", None),
            ("link-fsync", 1),
            ("canonical-unlink", None),
            ("canonical-fsync", 2),
            ("removal-unlink", None),
            ("removal-fsync", 3),
        )
        real_link = os.link
        real_unlink = os.unlink

        for fault, failing_sync in cases:
            with self.subTest(phase=fault):
                RecordingAttach.instances.clear()
                RecordingServer.instances.clear()
                runtime_dir = self.root / f"launcher-removal-{fault}"
                descriptor_path = runtime_dir / "runtime.json"
                removal_path = runtime_dir / "runtime.json.removing"
                fault_seen = threading.Event()

                class PhaseFaultRegistry(RuntimeRegistry):
                    in_remove = False
                    fault_injected = False
                    removal_syncs = 0
                    mark_calls = 0
                    workspace_calls = 0

                    def mark_cleanup_pending(self, processes):
                        self.mark_calls += 1
                        if self.mark_calls > 1:
                            return None
                        return super().mark_cleanup_pending(processes)

                    def delete_workspace(self):
                        self.workspace_calls += 1
                        if self.workspace_calls > 1:
                            return None
                        return super().delete_workspace()

                    def remove_descriptor(self):
                        self.in_remove = True
                        try:
                            return super().remove_descriptor()
                        finally:
                            self.in_remove = False

                    def _sync_parent(self):
                        if self.in_remove:
                            self.removal_syncs += 1
                            if (
                                not self.fault_injected
                                and failing_sync == self.removal_syncs
                            ):
                                self.fault_injected = True
                                fault_seen.set()
                                raise OSError(f"injected {fault}")
                        return super()._sync_parent()

                registry = PhaseFaultRegistry(
                    runtime_dir / "runtime.lock", descriptor_path
                )

                def injected_link(*args, **kwargs):
                    if (
                        registry.in_remove
                        and fault == "link"
                        and not registry.fault_injected
                    ):
                        registry.fault_injected = True
                        fault_seen.set()
                        raise OSError("injected link")
                    return real_link(*args, **kwargs)

                def injected_unlink(path, *args, **kwargs):
                    selected = (
                        fault == "canonical-unlink" and path == descriptor_path.name
                    ) or (
                        fault == "removal-unlink" and path == removal_path.name
                    )
                    if registry.in_remove and selected and not registry.fault_injected:
                        registry.fault_injected = True
                        fault_seen.set()
                        raise OSError(f"injected {fault}")
                    return real_unlink(path, *args, **kwargs)

                launcher, _, _, error = self.launcher(runtime_registry=registry)
                request = CleanupRequest()
                result = []
                with (
                    patch("aster_quickstart.runtime.os.link", side_effect=injected_link),
                    patch("aster_quickstart.runtime.os.unlink", side_effect=injected_unlink),
                ):
                    worker = threading.Thread(
                        target=lambda: result.append(launcher.run(request))
                    )
                    worker.start()
                    self.assertTrue(self._wait_for_server().started.wait(timeout=1))
                    request.set()
                    self.assertTrue(fault_seen.wait(timeout=1))
                    self.assertTrue(worker.is_alive())

                    contender = RuntimeRegistry(
                        runtime_dir / "runtime.lock", descriptor_path
                    )
                    with self.assertRaises(RuntimeActiveError):
                        contender.acquire()

                    request.set()
                    worker.join(timeout=2)

                self.assertFalse(worker.is_alive())
                self.assertEqual(result, [0])
                self.assertEqual(registry.mark_calls, 1)
                self.assertEqual(registry.workspace_calls, 1)
                self.assertFalse(descriptor_path.exists())
                self.assertFalse(removal_path.exists())
                self.assertEqual(error.getvalue(), "")

                contender = RuntimeRegistry(
                    runtime_dir / "runtime.lock", descriptor_path
                )
                contender.acquire()
                contender.close(remove_descriptor=False)

    def test_cleanup_request_arriving_during_failure_is_not_lost(self):
        request = CleanupRequest()

        class WakeDuringFailureRegistry(RuntimeRegistry):
            failures = 1

            def delete_workspace(self):
                if self.failures:
                    self.failures -= 1
                    request.set()
                    raise OSError("delete failed")
                return super().delete_workspace()

        runtime_dir = self.root / "wakeup-runtime"
        registry = WakeDuringFailureRegistry(runtime_dir / "runtime.lock", runtime_dir / "runtime.json")
        launcher, _, _, error = self.launcher(runtime_registry=registry)
        result = []
        worker = threading.Thread(target=lambda: result.append(launcher.run(request)))
        worker.start()
        self.assertTrue(self._wait_for_server().started.wait(timeout=1))

        request.set()
        worker.join(timeout=2)

        self.assertEqual(result, [0])
        self.assertFalse((runtime_dir / "runtime.json").exists())
        self.assertEqual(error.getvalue(), "")

    def _wait_for_server(self):
        deadline = time.monotonic() + 2
        while not RecordingServer.instances and time.monotonic() < deadline:
            time.sleep(0.005)
        self.assertTrue(RecordingServer.instances)
        return RecordingServer.instances[-1]

    def test_attach_mode_discovers_live_descriptor_and_only_follows_records(self):
        socket_path = self.root / "runtime" / "session" / "attach.sock"
        descriptor = RuntimeDescriptor(
            pid=123,
            proc_start_time=456,
            executable="/usr/bin/python3",
            process_group=123,
            workspace=str(socket_path.parent),
            socket_path=str(socket_path),
            workspace_device=1,
            workspace_inode=2,
            socket_device=1,
            socket_inode=3,
            lifecycle="active",
            owned_processes=(),
        )
        followed = []

        class ReadOnlyRegistry:
            def read_live(self):
                return descriptor

        code = main(
            ["attach", "publisher", "--detail", "DEBUG"],
            registry_factory=lambda: ReadOnlyRegistry(),
            attach_follow=lambda path, role, detail, output, expected_peer_pid: followed.append(
                (path, role, detail, output, expected_peer_pid)
            ) or 0,
        )

        self.assertEqual(code, 0)
        self.assertEqual(
            followed,
            [(socket_path, "publisher", "debug", os.sys.stdout, descriptor.pid)],
        )
        self.assertEqual(RecordingServer.instances, [])
        self.assertEqual(RecordingAttach.instances, [])

    def test_attach_mode_follows_a_real_registry_owner_process_and_unix_socket(self):
        runtime_dir = self.root / "real-attach-runtime"
        context = multiprocessing.get_context("fork")
        parent_control, child_control = context.Pipe()
        owner = context.Process(
            target=_serve_registry_attach,
            args=(str(runtime_dir), child_control),
        )
        owner.start()
        output = StringIO()
        result = []
        try:
            self.assertTrue(parent_control.poll(1), "registry owner did not become ready")
            self.assertEqual(parent_control.recv(), "ready")
            with patch("aster_quickstart.__main__.sys.stdout", output):
                worker = threading.Thread(
                    target=lambda: result.append(
                        main(
                            ["attach", "publisher", "--detail", "compact"],
                            registry_factory=lambda: RuntimeRegistry(
                                runtime_dir / "runtime.lock", runtime_dir / "runtime.json"
                            ),
                        )
                    )
                )
                worker.start()
                deadline = time.monotonic() + 1
                while "publisher ok: started" not in output.getvalue() and time.monotonic() < deadline:
                    time.sleep(0.005)
                parent_control.send("stop")
                worker.join(timeout=1)
            self.assertFalse(worker.is_alive())
            self.assertEqual(result, [0])
            self.assertIn("[start] publisher ok: started", output.getvalue())
        finally:
            if owner.is_alive():
                try:
                    parent_control.send("stop")
                except (BrokenPipeError, EOFError, OSError):
                    pass
            owner.join(timeout=1)
            if owner.is_alive():
                owner.terminate()
                owner.join(timeout=1)
            parent_control.close()
        self.assertEqual(owner.exitcode, 0)

    def test_run_mode_passes_normalized_detail_to_the_launcher(self):
        received = []

        class ImmediateLauncher:
            def run(self, _stop):
                return 0

        code = main(
            ["--bin-dir", str(self.bin_dir), "--detail", " COMPACT ", "--no-open"],
            launcher_factory=lambda binaries, no_open, detail: received.append(
                (binaries, no_open, detail)
            ) or ImmediateLauncher(),
        )

        self.assertEqual(code, 0)
        self.assertEqual(received[0][1:], (True, "compact"))

    def test_successful_cleanup_orders_final_record_adapters_descriptor_workspace_and_lock(self):
        order = RecordingServer.order
        runtime_dir = self.root / "ordered-runtime"

        class OrderedRegistry(RuntimeRegistry):
            def delete_workspace(self):
                order.append("workspace-delete")
                return super().delete_workspace()

            def remove_descriptor(self):
                order.append("descriptor-remove")
                return super().remove_descriptor()

            def close(self, *, remove_descriptor):
                try:
                    return super().close(remove_descriptor=remove_descriptor)
                finally:
                    order.append("lock-close")

        class OrderedOutput(StringIO):
            def write(self, value):
                if "[cleanup] cleaned: cleaned up" in value:
                    order.append("final-record")
                return super().write(value)

        runtime = OrderedRegistry(runtime_dir / "runtime.lock", runtime_dir / "runtime.json")
        launcher, _, _, error = self.launcher(
            runtime_registry=runtime,
            output=OrderedOutput(),
        )
        self.assertEqual(self.run_until_server_starts(launcher), 0)

        expected = [
            "attach-close",
            "workspace-delete",
            "descriptor-remove",
            "final-record",
            "server-close",
            "lock-close",
        ]
        positions = [order.index(item) for item in expected]
        self.assertEqual(positions, sorted(positions))
        self.assertEqual(error.getvalue(), "")


if __name__ == "__main__":
    unittest.main()
