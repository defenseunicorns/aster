#!/usr/bin/env python3
"""Contract tests for the bounded Aster agent process checker."""

from __future__ import annotations

import contextlib
import importlib.util
import inspect
import io
import json
import subprocess
import sys
import tempfile
import time
import unittest
from unittest import mock
from pathlib import Path


CHECKER_PATH = Path(__file__).with_name("check-aster-agent-process.py")


def load_checker():
    if not CHECKER_PATH.is_file():
        raise AssertionError("process checker is missing")
    spec = importlib.util.spec_from_file_location("check_aster_agent_process", CHECKER_PATH)
    if spec is None or spec.loader is None:
        raise AssertionError("process checker cannot be loaded")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def run_checker(*arguments: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, str(CHECKER_PATH), *arguments],
        check=False,
        capture_output=True,
        text=True,
        timeout=5,
    )


class ProcessCheckerContractTests(unittest.TestCase):
    def test_rejects_unbounded_or_missing_process_inputs(self) -> None:
        # Break caught: a zero timeout could turn deployment acceptance into an
        # unbounded wait, while argparse-first validation could hide that bug.
        result = run_checker("--timeout-seconds", "0")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("timeout must be within 1..=120", result.stderr)

        result = run_checker("--timeout-seconds", "121")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("timeout must be within 1..=120", result.stderr)

        result = run_checker("--timeout-seconds", "1")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("agent, config, and client paths are required", result.stderr)

        result = run_checker(
            "--agent",
            "/tmp/SECRET_AGENT_PATH",
            "--config",
            "/tmp/SECRET_CONFIG_PATH",
            "--client",
            "/tmp/SECRET_CLIENT_PATH",
        )
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("invalid process checker arguments", result.stderr)
        self.assertNotIn("SECRET_", result.stdout + result.stderr)

    def test_path_validation_never_echoes_a_rejected_input(self) -> None:
        # Break caught: including caller-controlled paths in validation errors
        # would disclose the configured state or credential boundary.
        canary = "/tmp/SECRET_PATH_CANARY-does-not-exist"
        result = run_checker(
            "--agent",
            canary,
            "--config",
            canary,
            "--client",
            canary,
            "--timeout-seconds",
            "1",
        )
        self.assertNotEqual(result.returncode, 0)
        self.assertNotIn(canary, result.stdout + result.stderr)
        self.assertIn("agent executable is unavailable", result.stderr)

    def test_input_contract_accepts_only_regular_executable_programs(self) -> None:
        # Break caught: directories and non-executable files could otherwise be
        # accepted and fail after orchestration has already created processes.
        checker = load_checker()
        with tempfile.TemporaryDirectory() as root:
            root_path = Path(root)
            program = root_path / "program"
            program.write_text("fixture", encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "agent executable is unavailable"):
                checker.require_executable(program, "agent")
            program.chmod(0o700)
            checker.require_executable(program, "agent")
            with self.assertRaisesRegex(ValueError, "config file is unavailable"):
                checker.require_regular_file(root_path, "config")

    def test_config_contract_requires_the_v1_string_peer_list(self) -> None:
        # Break caught: tuple(string) silently treats an invalid scalar peer as
        # a list of one-character peers, weakening the config/canary contract.
        checker = load_checker()
        with tempfile.TemporaryDirectory() as root:
            root_path = Path(root)
            token = root_path / "token"
            reference = root_path / "reference"
            token.write_bytes(b"x")
            reference.write_bytes(b"x")
            config = root_path / "agent.json"
            document = {
                "application": {"listen": "127.0.0.1:20001"},
                "health": {"listen": "127.0.0.1:20002"},
                "state": {"directory": str(root_path / "state")},
                "credentials": {
                    "client_token_file": str(token),
                    "mission_secret_ref_file": str(reference),
                },
                "mesh": {"peers": ["carrier@127.0.0.1:9=mission"]},
            }
            config.write_text(json.dumps(document), encoding="utf-8")
            self.assertEqual(
                checker.load_config_contract(config).peers,
                ("carrier@127.0.0.1:9=mission",),
            )

            document["mesh"]["peers"] = "carrier@127.0.0.1:9=mission"
            config.write_text(json.dumps(document), encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "config file is invalid"):
                checker.load_config_contract(config)

    def test_canary_scanner_rejects_each_combined_output_channel(self) -> None:
        # Break caught: scanning only the agent's standard output would miss a
        # disclosure on standard error or in a failed client invocation.
        checker = load_checker()
        canaries = [
            "SECRET_TOKEN_CANARY",
            "SECRET_PATH_CANARY",
            "SECRET_PAYLOAD_CANARY",
            "SECRET_TOPIC_CANARY",
            "SECRET_SCOPE_CANARY",
            "SECRET_PEER_CANARY",
        ]
        for canary in canaries:
            for channel in range(3):
                chunks = ["safe stdout", "safe stderr", "safe client error"]
                chunks[channel] = canary
                with self.subTest(canary=canary, channel=channel):
                    with self.assertRaisesRegex(ValueError, "canary exposed"):
                        checker.require_sanitized("\n".join(chunks), canaries)

    def test_canary_scanner_accepts_output_without_sensitive_values(self) -> None:
        # Break caught: an over-broad scanner could reject fixed lifecycle and
        # acceptance receipts that contain no configured values.
        checker = load_checker()
        checker.require_sanitized(
            "lifecycle=ready receipt=publish-recovered",
            ["SECRET_PATH_CANARY", "SECRET_PAYLOAD_CANARY"],
        )

    def test_peer_canaries_include_every_direct_component(self) -> None:
        # Break caught: scanning the full peer and socket suffix still misses
        # disclosure of the carrier identity that precedes `@`.
        checker = load_checker()
        self.assertEqual(
            checker._peer_canaries(
                "SECRET_CARRIER_ID@127.0.0.1:41999=SECRET_MISSION_ID"
            ),
            (
                "SECRET_CARRIER_ID@127.0.0.1:41999=SECRET_MISSION_ID",
                "SECRET_CARRIER_ID@127.0.0.1:41999",
                "SECRET_CARRIER_ID",
                "127.0.0.1:41999",
                "SECRET_MISSION_ID",
            ),
        )

    def test_failure_diagnostic_reports_counts_without_echoing_output(self) -> None:
        # Break caught: making a failed child observable by forwarding its raw
        # output could disclose the very canaries this checker protects.
        checker = load_checker()
        diagnostic = checker.sanitized_diagnostic(
            "client", 1, "SECRET_PAYLOAD_CANARY\n", "SECRET_PATH_CANARY\n"
        )
        self.assertEqual(
            diagnostic,
            "DIAGNOSTIC source=client exit_code=1 stdout_bytes=22 "
            "stderr_bytes=19 stdout_lines=1 stderr_lines=1",
        )
        self.assertNotIn("SECRET", diagnostic)

    def test_agent_diagnostic_reports_only_fixed_lifecycle_categories(self) -> None:
        # Break caught: raw lifecycle output can contain configured values, but
        # an exit failure must still distinguish clean, forced, and fatal paths.
        checker = load_checker()
        stdout = "\n".join(
            [
                '{"operation":"drain_start","reason":"terminating"}',
                '{"operation":"shutdown_result","reason":"forced"}',
                '{"operation":"SECRET","reason":"SECRET"}',
            ]
        )
        diagnostic = checker.sanitized_agent_diagnostic(
            "unary", 2, stdout, "SECRET_PATH_CANARY"
        )
        self.assertIn("phase=unary", diagnostic)
        self.assertIn("exit_code=2", diagnostic)
        self.assertIn("drain_start.terminating:1", diagnostic)
        self.assertIn("shutdown_result.forced:1", diagnostic)
        self.assertNotIn("SECRET", diagnostic)

    def test_managed_process_returns_the_exact_child_exit_status(self) -> None:
        # Break caught: dropping the wait result makes every successful client
        # invocation look like a nonzero failure to the process orchestrator.
        checker = load_checker()
        process = checker.ManagedProcess([sys.executable, "-c", "pass"])
        try:
            self.assertEqual(process.wait(1), 0)
        finally:
            process.cleanup(1)

    def test_wait_uses_one_deadline_when_descendant_retains_both_pipes(self) -> None:
        # Break caught: joining stdout and stderr readers with a fresh timeout
        # each can multiply the caller's process-wait bound.
        checker = load_checker()
        child_code = "import time; time.sleep(5)"
        leader_code = (
            "import subprocess, sys; "
            f"subprocess.Popen([sys.executable, '-c', {child_code!r}])"
        )
        process = checker.ManagedProcess([sys.executable, "-c", leader_code])
        started = time.monotonic()
        try:
            with self.assertRaisesRegex(
                checker.AcceptanceError, "process output drain exceeded the bound"
            ):
                process.wait(0.1)
            self.assertLess(time.monotonic() - started, 0.2)
        finally:
            process.cleanup(1)

    def test_cleanup_targets_the_process_group_after_the_leader_exits(self) -> None:
        # Break caught: a group leader may exit while descendants retain its
        # pipes; exact cleanup must still target the isolated process group.
        checker = load_checker()
        process = checker.ManagedProcess([sys.executable, "-c", "pass"])
        process.wait(1)
        with mock.patch.object(checker.os, "killpg") as kill_group:
            process.cleanup(1)
        kill_group.assert_called_once_with(process.process.pid, checker.signal.SIGKILL)

    def test_spawn_is_registered_before_pending_signal_delivery(self) -> None:
        # Break caught: an external signal between Popen and live-list append
        # could unwind cleanup while the new detached group was still unknown.
        checker = load_checker()
        registry = checker.ProcessRegistry()
        process = mock.Mock()
        mask_events = []

        def signal_mask(how, signals):
            mask_events.append(how)
            if how == checker.signal.SIG_SETMASK:
                self.assertIn(process, registry._processes)
                raise checker.CheckerInterrupted("pending checker signal")
            self.assertEqual(
                set(signals),
                {checker.signal.SIGTERM, checker.signal.SIGHUP, checker.signal.SIGINT},
            )
            return frozenset()

        with (
            mock.patch.object(checker, "ManagedProcess", return_value=process),
            mock.patch.object(
                checker.signal, "pthread_sigmask", side_effect=signal_mask
            ),
            self.assertRaisesRegex(checker.CheckerInterrupted, "pending checker signal"),
        ):
            registry.spawn(["packaged-agent"])

        registry.cleanup_all(1)
        process.cleanup.assert_called_once_with(1)
        self.assertEqual(
            mask_events, [checker.signal.SIG_BLOCK, checker.signal.SIG_SETMASK]
        )

    def test_all_checker_subprocesses_use_the_signal_safe_registry(self) -> None:
        # Break caught: routing only long-lived agents through the registry
        # leaves short-lived clients and config checks exposed to the same race.
        checker = load_checker()
        source = inspect.getsource(checker)
        self.assertEqual(source.count("ManagedProcess("), 1)

    def test_registered_child_does_not_retain_the_checker_signal_mask(self) -> None:
        # Break caught: masking the parent around Popen also masks the child;
        # the spawned process must unblock before exec so drain signals work.
        checker = load_checker()
        registry = checker.ProcessRegistry()
        process = registry.spawn(
            [sys.executable, "-c", "import time; time.sleep(5)"]
        )
        try:
            process.signal(checker.signal.SIGTERM)
            self.assertEqual(process.wait(1), -checker.signal.SIGTERM)
        finally:
            registry.cleanup_all(1)

    def test_active_client_exit_fails_early_with_fixed_phase_context(self) -> None:
        # Break caught: waiting only on stdout hides an already-exited client
        # for the full timeout and gives no clue whether unary or stream setup
        # failed. Diagnostics may expose only a whitelisted public code.
        checker = load_checker()
        with tempfile.TemporaryDirectory() as root:
            root_path = Path(root)
            client = root_path / "client"
            client.write_text(
                "#!/usr/bin/env python3\n"
                "import sys\n"
                "sys.stderr.write('SECRET\\n{\\\"status\\\":\\\"error\\\",'"
                "'\\\"code\\\":\\\"resourceexhausted\\\"}\\n')\n"
                "raise SystemExit(1)\n",
                encoding="utf-8",
            )
            client.chmod(0o700)
            token = root_path / "token"
            token.write_bytes(b"unused")
            diagnostics = io.StringIO()
            started = time.monotonic()
            with contextlib.redirect_stderr(diagnostics):
                with self.assertRaisesRegex(
                    checker.AcceptanceError,
                    "client phase unary exited before activity",
                ):
                    checker.start_active_client(
                        checker.ProcessRegistry(),
                        client,
                        "status",
                        "127.0.0.1:1",
                        token,
                        2,
                        {"repeat_until_error": True},
                    )
            self.assertLess(time.monotonic() - started, 1.5)
            diagnostic = diagnostics.getvalue()
            self.assertIn("phase=unary", diagnostic)
            self.assertIn("exit_code=1", diagnostic)
            self.assertIn("public_code=resourceexhausted", diagnostic)
            self.assertNotIn("SECRET", diagnostic)

    def test_active_marker_is_observed_while_the_client_remains_alive(self) -> None:
        # Break caught: BufferedReader.read(size) can wait for a full buffer or
        # EOF, hiding a flushed activity marker until the live client exits.
        checker = load_checker()
        with tempfile.TemporaryDirectory() as root:
            root_path = Path(root)
            client = root_path / "client"
            client.write_text(
                "#!/usr/bin/env python3\n"
                "import sys, time\n"
                "sys.stdin.read()\n"
                "sys.stdout.write('{\\\"status\\\":\\\"active\\\"}\\n')\n"
                "sys.stdout.flush()\n"
                "time.sleep(5)\n",
                encoding="utf-8",
            )
            client.chmod(0o700)
            token = root_path / "token"
            token.write_bytes(b"unused")
            started = time.monotonic()
            process = checker.start_active_client(
                checker.ProcessRegistry(),
                client,
                "stream",
                "127.0.0.1:1",
                token,
                1,
                {},
            )
            try:
                self.assertLess(time.monotonic() - started, 0.75)
                self.assertIsNone(process.process.poll())
            finally:
                process.cleanup(1)

    def test_process_pair_wait_observes_both_children_with_one_bound(self) -> None:
        # Break caught: drain orchestration must observe agent and client as a
        # pair instead of hiding one side behind a serial blocking wait.
        checker = load_checker()
        first = checker.ManagedProcess(
            [sys.executable, "-c", "import time; time.sleep(0.05)"]
        )
        second = checker.ManagedProcess(
            [sys.executable, "-c", "import time; time.sleep(0.1); raise SystemExit(3)"]
        )
        try:
            self.assertEqual(checker.wait_for_process_pair(first, second, 1), (0, 3))
        finally:
            first.cleanup(1)
            second.cleanup(1)

    def test_client_token_is_restored_exactly_after_failure(self) -> None:
        # Break caught: the reusable checker must not leave a caller-supplied
        # credential rotated, including when acceptance exits through failure.
        checker = load_checker()
        with tempfile.TemporaryDirectory() as root:
            token = Path(root) / "token"
            original = b"original-token-with-exact-newline\r\n"
            token.write_bytes(original)
            token.chmod(0o600)
            with self.assertRaisesRegex(RuntimeError, "simulated acceptance failure"):
                with checker.preserve_client_token(token) as preserved:
                    preserved.replace(checker.ROTATED_TOKEN + b"\n")
                    self.assertEqual(token.read_bytes(), checker.ROTATED_TOKEN + b"\n")
                    raise RuntimeError("simulated acceptance failure")
            self.assertEqual(token.read_bytes(), original)
            self.assertEqual(token.stat().st_mode & 0o777, 0o600)

            with checker.preserve_client_token(token) as preserved:
                preserved.replace(checker.ROTATED_TOKEN + b"\n")
            self.assertEqual(token.read_bytes(), original)
            self.assertEqual(token.stat().st_mode & 0o777, 0o600)

    def test_success_receipts_emit_only_after_token_restoration(self) -> None:
        # Break caught: emitting PASS inside the preservation context can claim
        # success before a failing credential restoration changes the exit.
        checker = load_checker()
        arguments = checker.Arguments(Path("agent"), Path("config"), Path("client"), 1)
        contract = checker.ConfigContract(
            "127.0.0.1:1",
            "127.0.0.1:2",
            Path("state"),
            Path("token"),
            Path("reference"),
            (),
        )

        @contextlib.contextmanager
        def successful_preservation(_path):
            yield object()

        output = io.StringIO()
        with (
            mock.patch.object(checker, "require_executable"),
            mock.patch.object(checker, "load_config_contract", return_value=contract),
            mock.patch.object(
                checker, "preserve_client_token", side_effect=successful_preservation
            ),
            mock.patch.object(
                checker,
                "run_acceptance_with_token",
                return_value=["readiness"],
            ),
            contextlib.redirect_stdout(output),
        ):
            checker.run_acceptance(arguments)
        self.assertIn("RECEIPT status=pass name=readiness", output.getvalue())

        @contextlib.contextmanager
        def failing_restoration(_path):
            yield object()
            raise checker.AcceptanceError("client token could not be replaced")

        output = io.StringIO()
        with (
            mock.patch.object(checker, "require_executable"),
            mock.patch.object(checker, "load_config_contract", return_value=contract),
            mock.patch.object(
                checker, "preserve_client_token", side_effect=failing_restoration
            ),
            mock.patch.object(
                checker,
                "run_acceptance_with_token",
                return_value=["readiness"],
            ),
            contextlib.redirect_stdout(output),
            self.assertRaisesRegex(
                checker.AcceptanceError, "client token could not be replaced"
            ),
        ):
            checker.run_acceptance(arguments)
        self.assertEqual(output.getvalue(), "")

    def test_readiness_probe_obeys_an_absolute_deadline(self) -> None:
        # Break caught: a peer that continually dribbles bytes can reset socket
        # inactivity timeouts and exceed the caller's wall-clock bound.
        checker = load_checker()

        class DribblingSocket:
            def __enter__(self):
                return self

            def __exit__(self, *_args):
                return False

            def setblocking(self, _blocking):
                pass

            def connect_ex(self, _address):
                return 0

            def getsockopt(self, *_args):
                return 0

            def send(self, data):
                return len(data)

            def recv(self, _size):
                return b"x"

        def slowly_ready(readers, writers, _exceptional, _timeout):
            time.sleep(0.005)
            return (readers, writers, [])

        started = time.monotonic()
        with (
            mock.patch.object(checker.socket, "socket", return_value=DribblingSocket()),
            mock.patch.object(checker.select, "select", side_effect=slowly_ready),
        ):
            self.assertFalse(
                checker._readiness_probe("127.0.0.1", 1, time.monotonic() + 0.03)
            )
        self.assertLess(time.monotonic() - started, 0.15)

    def test_active_client_outcomes_are_exact_for_each_drain_phase(self) -> None:
        # Break caught: an active marker followed by an arbitrary client failure
        # cannot establish the unary or streaming drain contract.
        checker = load_checker()
        self.assertTrue(
            checker.expected_drain_client_outcome(
                "unary",
                1,
                '{"status":"active","activity":"unary"}\n',
                '{"status":"error","code":"unavailable"}\n',
            )
        )
        self.assertTrue(
            checker.expected_drain_client_outcome(
                "stream",
                0,
                '{"status":"active","activity":"stream"}\n'
                '{"status":"ok","delivered":0}\n',
                "",
            )
        )
        for phase, code, stdout, stderr in [
            ("unary", 1, '{"status":"active"}\n', '{"code":"internal"}\n'),
            ("stream", 1, '{"status":"active"}\n', '{"code":"unavailable"}\n'),
            ("stream", 0, '{"status":"active"}\n{"status":"ok","delivered":1}\n', ""),
            ("stream", 0, '{"status":"active"}\n{"status":"ok","delivered":0}\n', '{"code":"internal"}\n'),
        ]:
            with self.subTest(phase=phase, code=code, stderr=stderr):
                self.assertFalse(
                    checker.expected_drain_client_outcome(phase, code, stdout, stderr)
                )

    def test_external_termination_becomes_one_cleanup_unwind(self) -> None:
        # Break caught: the checker must not die directly and strand children in
        # detached sessions; the first external signal initiates normal unwind.
        checker = load_checker()
        previous = checker.signal.getsignal(checker.signal.SIGTERM)
        with checker.termination_unwinds_cleanup():
            handler = checker.signal.getsignal(checker.signal.SIGTERM)
            with self.assertRaisesRegex(checker.CheckerInterrupted, "checker interrupted"):
                handler(checker.signal.SIGTERM, None)
            handler(checker.signal.SIGTERM, None)
        self.assertIs(checker.signal.getsignal(checker.signal.SIGTERM), previous)

    def test_negative_startup_checks_are_process_level_and_side_effect_free(self) -> None:
        # Break caught: in-process validation tests do not prove a packaged
        # agent rejects invalid/non-loopback config before state or listeners.
        checker = load_checker()
        with tempfile.TemporaryDirectory() as root:
            root_path = Path(root)
            agent = root_path / "agent"
            agent.write_text(
                "#!/bin/sh\n"
                "test \"$1\" = '--check-config' || exit 99\n"
                "echo 'PACKAGED_AGENT status=config-rejected' >&2\n"
                "exit 7\n",
                encoding="utf-8",
            )
            agent.chmod(0o700)
            config = root_path / "agent.json"
            config.write_text(
                json.dumps(
                    {
                        "schema_version": 1,
                        "state": {"directory": str(root_path / "state")},
                        "application": {"listen": "127.0.0.1:20001"},
                        "health": {"listen": "127.0.0.1:20002"},
                        "mesh": {"bind": "127.0.0.1:0", "peers": []},
                        "credentials": {
                            "client_token_file": str(root_path / "token"),
                            "mission_secret_ref_file": str(root_path / "reference"),
                            "mission_load_id": "11" * 32,
                        },
                        "storage": {
                            "max_items": 10_000,
                            "max_payload_bytes": 64 * 1024 * 1024,
                        },
                        "limits": {"shutdown_grace_ms": 10_000},
                    }
                ),
                encoding="utf-8",
            )
            contract = checker.ConfigContract(
                "127.0.0.1:20001",
                "127.0.0.1:20002",
                root_path / "state",
                root_path / "token",
                root_path / "reference",
                (),
            )
            @contextlib.contextmanager
            def guarded_addresses():
                yield checker.GuardedAddresses(
                    application="127.0.0.1:21001",
                    health="127.0.0.1:21002",
                    mesh="127.0.0.1:21003",
                )

            with mock.patch.object(
                checker,
                "guarded_loopback_addresses",
                side_effect=guarded_addresses,
            ):
                result = checker.run_negative_startup_checks(
                    checker.ProcessRegistry(), agent, config, contract, 1
                )
            self.assertEqual(
                result.receipts,
                (
                    "invalid-config-no-side-effects",
                    "non-loopback-application-refusal",
                    "non-loopback-health-refusal",
                ),
            )
            self.assertEqual(len(result.captures), 3)
            self.assertGreaterEqual(len(result.canaries), 4)

    def test_negative_check_rejects_transient_state_creation_and_removal(self) -> None:
        # Break caught: checking only final path absence allows a packaged
        # validator to create and then erase state before returning failure.
        checker = load_checker()
        with tempfile.TemporaryDirectory() as root:
            root_path = Path(root)
            agent = root_path / "agent"
            agent.write_text(
                "#!/usr/bin/env python3\n"
                "import json, pathlib, sys\n"
                "document = json.loads(pathlib.Path(sys.argv[2]).read_text())\n"
                "state = pathlib.Path(document['state']['directory'])\n"
                "state.mkdir()\n"
                "state.rmdir()\n"
                "sys.stderr.write('PACKAGED_AGENT status=config-rejected\\n')\n"
                "raise SystemExit(7)\n",
                encoding="utf-8",
            )
            agent.chmod(0o700)
            config = root_path / "agent.json"
            config.write_text(
                json.dumps(
                    {
                        "schema_version": 1,
                        "state": {"directory": str(root_path / "unused-state")},
                        "application": {"listen": "127.0.0.1:20001"},
                        "health": {"listen": "127.0.0.1:20002"},
                        "mesh": {"bind": "127.0.0.1:0", "peers": []},
                        "credentials": {
                            "client_token_file": str(root_path / "token"),
                            "mission_secret_ref_file": str(root_path / "reference"),
                            "mission_load_id": "11" * 32,
                        },
                        "storage": {
                            "max_items": 10_000,
                            "max_payload_bytes": 64 * 1024 * 1024,
                        },
                        "limits": {"shutdown_grace_ms": 10_000},
                    }
                ),
                encoding="utf-8",
            )
            contract = checker.ConfigContract(
                "127.0.0.1:20001",
                "127.0.0.1:20002",
                root_path / "unused-state",
                root_path / "token",
                root_path / "reference",
                (),
            )

            @contextlib.contextmanager
            def guarded_addresses():
                yield checker.GuardedAddresses(
                    application="127.0.0.1:21001",
                    health="127.0.0.1:21002",
                    mesh="127.0.0.1:21003",
                )

            with (
                mock.patch.object(
                    checker,
                    "guarded_loopback_addresses",
                    side_effect=guarded_addresses,
                ),
                self.assertRaisesRegex(
                    checker.AcceptanceError, "invalid configuration mutated state"
                ),
            ):
                checker.run_negative_startup_checks(
                    checker.ProcessRegistry(), agent, config, contract, 1
                )

    def test_exact_recovery_request_and_evidence_cover_every_event_field(self) -> None:
        # Break caught: matching only an Event ID cannot prove the recovered
        # durable value retained all of its caller-visible fields.
        checker = load_checker()
        request = checker._publish_request()
        receipt = {
            "event_id_hex": "01" * 32,
            "publisher_id_hex": "02" * 32,
            "publisher_counter": 3,
            "event_sequence": 4,
            "acceptance_marker": 5,
        }
        expected = checker._expected_recovered_event(receipt, request)
        self.assertEqual(
            expected,
            {
                "id_hex": "01" * 32,
                "publisher_hex": "02" * 32,
                "publisher_counter": 3,
                "event_sequence": 4,
                "topic": checker.CANARY_TOPIC,
                "scope": checker.CANARY_SCOPE,
                "priority": "immediate",
                "logical_key_hex": checker.CANARY_LOGICAL_KEY.hex(),
                "payload_hex": checker.CANARY_PAYLOAD.hex(),
                "tombstone": False,
                "acceptance_marker": 5,
            },
        )
        checker.require_exact_recovery_evidence(
            {"status": "ok", "exact_match": True, "count": 1, "has_more": False}
        )
        for key, value in (
            ("exact_match", False),
            ("count", 2),
            ("has_more", True),
        ):
            evidence = {
                "status": "ok",
                "exact_match": True,
                "count": 1,
                "has_more": False,
            }
            evidence[key] = value
            with self.subTest(key=key):
                with self.assertRaisesRegex(
                    checker.AcceptanceError, "recovered publication was not exact"
                ):
                    checker.require_exact_recovery_evidence(evidence)

    def test_operation_key_conflict_requires_exact_public_aborted_code(self) -> None:
        # Break caught: accepting any client error permits auth, capacity, or
        # transport failures to masquerade as operation-key conflict proof.
        checker = load_checker()
        checker.require_operation_key_conflict({"status": "error", "code": "aborted"})
        for code in ("internal", "unavailable", None):
            with self.subTest(code=code):
                with self.assertRaisesRegex(
                    checker.AcceptanceError, "operation-key conflict was not rejected"
                ):
                    checker.require_operation_key_conflict(
                        {"status": "error", "code": code}
                    )

    def test_smoke_trap_precedes_temporary_directory_creation(self) -> None:
        # Break caught: creating the root before installing the trap leaves a
        # signal window that can strand sensitive temporary fixture files.
        mise = CHECKER_PATH.parent.parent / "mise.toml"
        source = mise.read_text(encoding="utf-8")
        task = source[source.index("[tasks.agent-process-smoke]") :]
        empty = task.index('task_root=""')
        trap = task.index("trap cleanup EXIT HUP INT TERM")
        create = task.index("task_root=\"$(mktemp -d")
        self.assertLess(empty, trap)
        self.assertLess(trap, create)
        self.assertIn('/tmp/aster-agent-process-smoke.*)', task[empty:create])

    def test_smoke_uses_independent_generated_go_client(self) -> None:
        # Break caught: reverting the smoke task to the Rust fixture as both
        # server and client removes the independent-language wire proof.
        mise = CHECKER_PATH.parent.parent / "mise.toml"
        source = mise.read_text(encoding="utf-8")
        task = source[source.index("[tasks.agent-process-smoke]") :]
        self.assertIn(
            'go -C conformance/agent-go build -o "$task_root/agent-smoke"', task
        )
        self.assertIn('--client "$task_root/agent-smoke"', task)
        self.assertNotIn('--client "$fixture"', task)

if __name__ == "__main__":
    unittest.main()
