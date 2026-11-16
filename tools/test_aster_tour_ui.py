#!/usr/bin/env python3
# Copyright 2026 Defense Unicorns, Inc.
# SPDX-License-Identifier: Apache-2.0
"""Regression tests for the live Aster capability-tour presenter."""

from __future__ import annotations

import importlib.util
import contextlib
import io
import os
from pathlib import Path
import signal
import subprocess
import sys
import tempfile
import textwrap
import time
import unittest


ROOT = Path(__file__).resolve().parents[1]
UI_PATH = Path(__file__).with_name("aster_tour_ui.py")
SPEC = importlib.util.spec_from_file_location("aster_tour_ui", UI_PATH)
if SPEC is None or SPEC.loader is None:
    raise RuntimeError(f"cannot load {UI_PATH}")
UI = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = UI
SPEC.loader.exec_module(UI)


class TourUiTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary_directory = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary_directory.name)

    def tearDown(self) -> None:
        self.temporary_directory.cleanup()


    def test_control_characters_are_never_rendered(self) -> None:
        malicious = "safe\x1b[31m\npath\x00"
        cleaned = UI.safe_text(malicious)
        self.assertNotIn("\x1b", cleaned)
        self.assertNotIn("\n", cleaned)
        self.assertNotIn("\x00", cleaned)
        self.assertIn("safe?", cleaned)

        state = UI.TourState(UI.make_plan("quick", 2))
        receipt = UI.parse_receipt(
            b"PING status=received producer_state=node-0\x1b[31m "
            b"destination_state=node-1 source_authenticated=true\n"
        )
        self.assertNotIn("\x1b", UI.describe_receipt(state, receipt))

    def test_capture_is_live_and_receipts_are_byte_exact(self) -> None:
        stdout_receipt = self.root / "demo.stdout"
        stderr_receipt = self.root / "demo.stderr"
        stdout_seen: list[tuple[float, bytes]] = []
        stderr_seen: list[bytes] = []
        started = time.monotonic()
        command = [
            sys.executable,
            "-u",
            "-c",
            (
                "import sys,time;"
                "sys.stdout.buffer.write(b'first\\n');sys.stdout.flush();"
                "time.sleep(.20);"
                "sys.stderr.buffer.write(b'\\xffwarning\\n');sys.stderr.flush();"
                "sys.stdout.buffer.write(b'last');sys.stdout.flush()"
            ),
        ]

        result = UI.capture_process(
            command,
            stdout_receipt,
            stderr_receipt,
            lambda data: stdout_seen.append((time.monotonic() - started, data)),
            stderr_seen.append,
            lambda: None,
        )

        self.assertEqual(result.returncode, 0)
        self.assertGreaterEqual(result.elapsed, 0.18)
        self.assertLess(stdout_seen[0][0], result.elapsed - 0.10)
        self.assertEqual(stdout_receipt.read_bytes(), b"first\nlast")
        self.assertEqual(stderr_receipt.read_bytes(), b"\xffwarning\n")
        self.assertEqual(b"".join(data for _, data in stdout_seen), b"first\nlast")
        self.assertEqual(b"".join(stderr_seen), b"\xffwarning\n")

    def test_capture_propagates_failure_and_retains_partial_output(self) -> None:
        stdout_receipt = self.root / "failure.stdout"
        stderr_receipt = self.root / "failure.stderr"
        result = UI.capture_process(
            [
                sys.executable,
                "-u",
                "-c",
                "import sys;print('partial');print('broken',file=sys.stderr);sys.exit(7)",
            ],
            stdout_receipt,
            stderr_receipt,
            lambda _data: None,
            lambda _data: None,
            lambda: None,
        )

        self.assertEqual(result.returncode, 7)
        self.assertEqual(stdout_receipt.read_bytes(), b"partial\n")
        self.assertEqual(stderr_receipt.read_bytes(), b"broken\n")

    def test_capture_refuses_to_overwrite_a_receipt(self) -> None:
        stdout_receipt = self.root / "existing.stdout"
        stderr_receipt = self.root / "new.stderr"
        stdout_receipt.write_bytes(b"retained")

        with self.assertRaisesRegex(RuntimeError, "refusing to overwrite"):
            UI.capture_process(
                [sys.executable, "-c", "print('no')"],
                stdout_receipt,
                stderr_receipt,
                lambda _data: None,
                lambda _data: None,
                lambda: None,
            )
        self.assertEqual(stdout_receipt.read_bytes(), b"retained")
        self.assertFalse(stderr_receipt.exists())

    def test_capture_rolls_back_stdout_when_stderr_already_exists(self) -> None:
        stdout_receipt = self.root / "new.stdout"
        stderr_receipt = self.root / "existing.stderr"
        stderr_receipt.write_bytes(b"retained stderr")

        with self.assertRaisesRegex(RuntimeError, "refusing to overwrite"):
            UI.capture_process(
                [sys.executable, "-c", "print('no')"],
                stdout_receipt,
                stderr_receipt,
                lambda _data: None,
                lambda _data: None,
                lambda: None,
            )
        self.assertFalse(stdout_receipt.exists())
        self.assertEqual(stderr_receipt.read_bytes(), b"retained stderr")

    def test_zero_exit_without_terminal_receipt_is_not_presented_as_pass(self) -> None:
        state = UI.TourState(UI.make_plan("quick", 2))
        for phase in state.plan.phases:
            state.observe(
                UI.parse_receipt(
                    f"PHASE status=pass name={phase.name}\n".encode("ascii")
                )
            )
        presenter = UI.DemoPresenter(state, "plain")
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            presenter.finish(0, 1.25, self.root / "demo.stdout")

        rendered = output.getvalue()
        self.assertIn("process exited 0; terminal DEMO_RESULT receipt missing", rendered)
        self.assertNotIn("passed", rendered)

    def test_unknown_phases_cannot_complete_plan_and_failed_result_is_truthful(self) -> None:
        state = UI.TourState(UI.make_plan("quick", 2))
        for index in range(5):
            state.observe(
                UI.parse_receipt(
                    f"PHASE status=pass name=unknown-{index}\n".encode("ascii")
                )
            )
        state.observe(UI.parse_receipt(b"DEMO_RESULT status=pass\n"))
        self.assertEqual(state.completed, [])
        self.assertEqual(len(state.unknown), 5)

        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            UI.DemoPresenter(state, "plain").finish(
                0, 1.0, self.root / "unknown.stdout"
            )
        self.assertIn("phase receipts incomplete (0/5)", output.getvalue())

        failed = UI.TourState(UI.make_plan("quick", 2))
        failed.observe(UI.parse_receipt(b"DEMO_RESULT status=fail\n"))
        self.assertEqual(failed.current_label(), "Terminal result reported status fail")
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            UI.DemoPresenter(failed, "plain").finish(
                9, 1.0, self.root / "failed.stdout"
            )
        self.assertIn("Tour stopped during: Terminal result reported status fail", output.getvalue())
        self.assertNotIn("invariants passed", output.getvalue())

    @unittest.skipUnless(os.name == "posix", "tour process groups require POSIX")
    def test_leader_failure_stops_inherited_pipe_descendant_without_hanging(self) -> None:
        stdout_receipt = self.root / "leader.stdout"
        stderr_receipt = self.root / "leader.stderr"
        result = UI.capture_process(
            [
                sys.executable,
                "-u",
                "-c",
                (
                    "import subprocess,sys;"
                    "child=subprocess.Popen(['sleep','30']);"
                    "print(f'CHILD_PID={child.pid}',flush=True);"
                    "sys.exit(7)"
                ),
            ],
            stdout_receipt,
            stderr_receipt,
            lambda _data: None,
            lambda _data: None,
            lambda: None,
        )

        self.assertEqual(result.returncode, 7)
        self.assertLess(result.elapsed, 3)
        descendant = int(stdout_receipt.read_text().strip().split("=", 1)[1])
        gone = False
        for _ in range(40):
            try:
                os.kill(descendant, 0)
            except ProcessLookupError:
                gone = True
                break
            time.sleep(0.05)
        if not gone:
            try:
                os.kill(descendant, signal.SIGKILL)
            except ProcessLookupError:
                pass
        self.assertTrue(gone, "failed leader left an inherited-pipe descendant")

    def test_dashboard_detects_a_phase_as_soon_as_logs_exist(self) -> None:
        plan = UI.make_plan("relay", 3)
        state = UI.TourState(plan)
        state.observe(
            UI.parse_receipt(
                b"SUBSCRIPTIONS status=seeded consume=2 carry=1 selectors=3\n"
            )
        )
        logs = self.root / "relay" / "logs"
        logs.mkdir(parents=True)
        (logs / "ping-publish-node-0.log").write_bytes(b"")

        self.assertTrue(state.poll_logs(self.root / "relay"))
        self.assertEqual(state.current_phase, "ping-publish")
        dashboard = "\n".join(UI.dashboard_lines(state, 88, 24))
        self.assertIn("Publish Ping offline", dashboard)
        self.assertIn("n0 Origin", dashboard)
        self.assertNotIn("transfer_id", dashboard)
        self.assertTrue(
            all(len(line) <= 24 for line in UI.dashboard_lines(state, 24, 10))
        )
        self.assertLessEqual(len(UI.dashboard_lines(state, 24, 10)), 10)

    def test_inspection_table_explains_relay_and_captured_state(self) -> None:
        plan = UI.make_plan("control", 4)
        rows = []
        for node, events, cached, controls, highwater in (
            (0, 2, 0, 2, 2),
            (1, 0, 2, 2, 2),
            (2, 2, 0, 2, 2),
            (3, 1, 0, 0, 0),
        ):
            rows.append(
                UI.parse_receipt(
                    (
                        f"INSPECT status=pass state=/tmp/control/node-{node} "
                        f"events={events} route_cached_events={cached} "
                        f"controls={controls} applied_controls={controls} "
                        f"control_highwater={highwater}\n"
                    ).encode()
                )
            )

        table = UI.render_inspections(plan, rows)
        self.assertIn("Blind relay", table)
        self.assertIn("n1", table)
        self.assertIn("2/2", table)

        incomplete = UI.render_inspections(plan, [])
        self.assertIn("scenario conclusions withheld", incomplete)
        self.assertNotIn("its own stale epoch-1 Ping", incomplete)

        malformed_relay = UI.render_inspections(
            UI.make_plan("relay", 3),
            [
                UI.parse_receipt(
                    b"INSPECT status=pass state=/tmp/relay/node-1 events=0\n"
                )
            ],
        )
        self.assertIn("scenario conclusions withheld", malformed_relay)
        self.assertNotIn("protected exact bytes", malformed_relay)

    def test_shell_wrapper_preserves_raw_receipts_and_prints_pretty_view(self) -> None:
        fake_aster = self.root / "fake-aster"
        fake_aster.write_text(
            textwrap.dedent(
                """\
                #!/usr/bin/env python3
                import pathlib
                import sys

                command = sys.argv[1]
                if command == "demo":
                    root = pathlib.Path(sys.argv[sys.argv.index("--root") + 1])
                    (root / "logs").mkdir(parents=True)
                    lines = [
                        "SUBSCRIPTIONS status=seeded consume=2 carry=0 selectors=2",
                        "PHASE status=pass name=ping-publish carrier_authenticated_edges=not-applicable",
                        "PHASE status=pass name=ping-forward-0-to-1 carrier_authenticated_edges=verified",
                        "PHASE status=pass name=pong-publish carrier_authenticated_edges=not-applicable",
                        "PING status=received producer_state=node-0 destination_state=node-1 source_authenticated=true",
                        "PHASE status=pass name=pong-return-1-to-0 carrier_authenticated_edges=verified",
                        "RELAY status=not-applicable intermediates=0",
                        "PONG status=received producer_state=node-1 destination_state=node-0 causal_observation=verified",
                        "PHASE status=pass name=noop carrier_authenticated_edges=verified",
                        "DEMO_RESULT status=pass scenario=ping-pong nodes=2 processes=8",
                    ]
                    for line in lines:
                        print(line, flush=True)
                    raise SystemExit(0)
                if command == "inspect":
                    state = pathlib.Path(sys.argv[sys.argv.index("--state") + 1])
                    node = int(state.name.removeprefix("node-"))
                    print(
                        f"INSPECT status=pass state={state} events=2 "
                        "route_cached_events=0 controls=0 applied_controls=0 "
                        "control_highwater=0"
                    )
                    raise SystemExit(0)
                raise SystemExit(2)
                """
            ),
            encoding="utf-8",
        )
        fake_aster.chmod(0o755)
        tour_parent = self.root / "retained"
        environment = os.environ.copy()
        environment.update(
            {
                "ASTER_TOUR_BIN": str(fake_aster),
                "ASTER_TOUR_PARENT": str(tour_parent),
                "ASTER_TOUR_VIEW": "plain",
                "PATH": "/usr/bin:/bin:/usr/sbin:/sbin",
                "PYTHONDONTWRITEBYTECODE": "1",
            }
        )

        completed = subprocess.run(
            ["sh", str(ROOT / "tools" / "aster-tour.sh"), "quick"],
            cwd=ROOT,
            env=environment,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
            text=True,
        )

        self.assertEqual(completed.returncode, 0, completed.stderr)
        self.assertNotIn("\x1b", completed.stdout)
        self.assertIn("Live view · Causal Ping / Pong", completed.stdout)
        self.assertIn("Deliver Ping to responder", completed.stdout)
        self.assertIn("Final durable state", completed.stdout)
        self.assertIn("Receipts retained", completed.stdout)
        expected_demo = "\n".join(
            (
                "SUBSCRIPTIONS status=seeded consume=2 carry=0 selectors=2",
                "PHASE status=pass name=ping-publish carrier_authenticated_edges=not-applicable",
                "PHASE status=pass name=ping-forward-0-to-1 carrier_authenticated_edges=verified",
                "PHASE status=pass name=pong-publish carrier_authenticated_edges=not-applicable",
                "PING status=received producer_state=node-0 destination_state=node-1 source_authenticated=true",
                "PHASE status=pass name=pong-return-1-to-0 carrier_authenticated_edges=verified",
                "RELAY status=not-applicable intermediates=0",
                "PONG status=received producer_state=node-1 destination_state=node-0 causal_observation=verified",
                "PHASE status=pass name=noop carrier_authenticated_edges=verified",
                "DEMO_RESULT status=pass scenario=ping-pong nodes=2 processes=8",
                "",
            )
        ).encode()
        self.assertEqual(
            (tour_parent / "quick.demo.stdout").read_bytes(), expected_demo
        )
        self.assertEqual((tour_parent / "quick.demo.stderr").read_bytes(), b"")
        self.assertEqual(
            len((tour_parent / "quick.inspect.stdout").read_text().splitlines()), 2
        )

        raw_parent = self.root / "raw-retained"
        raw_environment = environment.copy()
        raw_environment.update(
            {
                "ASTER_TOUR_PARENT": str(raw_parent),
                "ASTER_TOUR_VIEW": "raw",
            }
        )
        raw_completed = subprocess.run(
            ["sh", str(ROOT / "tools" / "aster-tour.sh"), "quick"],
            cwd=ROOT,
            env=raw_environment,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
        )
        self.assertEqual(raw_completed.returncode, 0, raw_completed.stderr)
        self.assertTrue(raw_completed.stdout.startswith(expected_demo))
        raw_inspections = raw_completed.stdout[len(expected_demo) :].splitlines()
        self.assertEqual(len(raw_inspections), 2)
        self.assertTrue(all(line.startswith(b"INSPECT status=pass") for line in raw_inspections))
        self.assertNotIn(b"Aster quick tour", raw_completed.stdout)
        self.assertNotIn(b"Receipts retained", raw_completed.stdout)
        self.assertIn(b"Receipts retained", raw_completed.stderr)

        ascii_parent = self.root / "ascii-retained"
        ascii_environment = environment.copy()
        ascii_environment.update(
            {
                "ASTER_TOUR_PARENT": str(ascii_parent),
                "PYTHONIOENCODING": "ascii",
            }
        )
        ascii_completed = subprocess.run(
            ["sh", str(ROOT / "tools" / "aster-tour.sh"), "quick"],
            cwd=ROOT,
            env=ascii_environment,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
        )
        self.assertEqual(ascii_completed.returncode, 0, ascii_completed.stderr)
        ascii_completed.stdout.decode("ascii")
        ascii_completed.stderr.decode("ascii")
        self.assertNotIn(b"Traceback", ascii_completed.stdout + ascii_completed.stderr)

    def test_shell_wrapper_returns_demo_failure_and_skips_inspection(self) -> None:
        fake_aster = self.root / "failing-aster"
        fake_aster.write_text(
            textwrap.dedent(
                """\
                #!/usr/bin/env python3
                import sys

                if sys.argv[1] == "demo":
                    print("SUBSCRIPTIONS status=seeded consume=2 carry=0 selectors=2")
                    print("demo stopped", file=sys.stderr)
                    raise SystemExit(9)
                if sys.argv[1] == "inspect":
                    print("inspection must not run")
                    raise SystemExit(0)
                raise SystemExit(2)
                """
            ),
            encoding="utf-8",
        )
        fake_aster.chmod(0o755)
        tour_parent = self.root / "failed-retained"
        environment = os.environ.copy()
        environment.update(
            {
                "ASTER_TOUR_BIN": str(fake_aster),
                "ASTER_TOUR_PARENT": str(tour_parent),
                "ASTER_TOUR_VIEW": "plain",
                "PATH": "/usr/bin:/bin:/usr/sbin:/sbin",
                "PYTHONDONTWRITEBYTECODE": "1",
            }
        )

        completed = subprocess.run(
            ["sh", str(ROOT / "tools" / "aster-tour.sh"), "quick"],
            cwd=ROOT,
            env=environment,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
            text=True,
        )

        self.assertEqual(completed.returncode, 9)
        self.assertEqual(
            (tour_parent / "quick.demo.stdout").read_bytes(),
            b"SUBSCRIPTIONS status=seeded consume=2 carry=0 selectors=2\n",
        )
        self.assertEqual(
            (tour_parent / "quick.demo.stderr").read_bytes(), b"demo stopped\n"
        )
        self.assertFalse((tour_parent / "quick.inspect.stdout").exists())
        self.assertIn("Partial raw receipt", completed.stdout)
        self.assertIn("Receipts retained", completed.stdout)
        self.assertIn("Inspection         not run", completed.stdout)
        self.assertIn("Child process logs not created", completed.stdout)

    def test_build_tui_is_ascii_safe_and_restores_cursor(self) -> None:
        stdout_receipt = self.root / "build.stdout"
        stderr_receipt = self.root / "build.stderr"
        environment = os.environ.copy()
        environment.update(
            {
                "PYTHONIOENCODING": "ascii",
                "PYTHONDONTWRITEBYTECODE": "1",
                "TERM": "xterm-256color",
            }
        )
        completed = subprocess.run(
            [
                sys.executable,
                str(UI_PATH),
                "build",
                "--view",
                "tui",
                "--stdout-receipt",
                str(stdout_receipt),
                "--stderr-receipt",
                str(stderr_receipt),
                "--",
                "/usr/bin/true",
            ],
            cwd=ROOT,
            env=environment,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
        )

        self.assertEqual(completed.returncode, 0, completed.stderr)
        completed.stdout.decode("ascii")
        self.assertIn(b"\x1b[?25l", completed.stdout)
        self.assertIn(b"\x1b[?25h", completed.stdout)
        self.assertNotIn(b"Traceback", completed.stdout + completed.stderr)
        self.assertEqual(stdout_receipt.read_bytes(), b"")
        self.assertEqual(stderr_receipt.read_bytes(), b"")

    def test_build_tui_does_not_enter_when_receipt_open_fails(self) -> None:
        missing = self.root / "missing" / "build.stdout"
        environment = os.environ.copy()
        environment.update(
            {
                "PYTHONIOENCODING": "ascii",
                "PYTHONDONTWRITEBYTECODE": "1",
                "TERM": "xterm-256color",
            }
        )
        completed = subprocess.run(
            [
                sys.executable,
                str(UI_PATH),
                "build",
                "--view",
                "tui",
                "--stdout-receipt",
                str(missing),
                "--stderr-receipt",
                str(self.root / "missing" / "build.stderr"),
                "--",
                "/usr/bin/true",
            ],
            cwd=ROOT,
            env=environment,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
        )

        self.assertEqual(completed.returncode, 2)
        self.assertNotIn(b"\x1b[?25l", completed.stdout)
        self.assertNotIn(b"Traceback", completed.stdout + completed.stderr)

    @unittest.skipUnless(os.name == "posix", "tour process groups require POSIX")
    def test_wrapper_sigint_waits_for_presenter_and_descendant_cleanup(self) -> None:
        fake_aster = self.root / "waiting-aster"
        fake_aster.write_text(
            textwrap.dedent(
                """\
                #!/usr/bin/env python3
                import os
                import signal
                import subprocess
                import sys
                import time

                if sys.argv[1] == "demo":
                    descendant_code = (
                        "import signal,time;"
                        "signal.signal(signal.SIGINT,signal.SIG_IGN);"
                        "signal.signal(signal.SIGTERM,signal.SIG_IGN);"
                        "print('WRAPPER_DESCENDANT_READY',flush=True);"
                        "time.sleep(30)"
                    )
                    child = subprocess.Popen(
                        [sys.executable, "-u", "-c", descendant_code]
                    )
                    print(f"DEMO_PID={os.getpid()}", flush=True)
                    print(f"DESCENDANT_PID={child.pid}", flush=True)
                    time.sleep(30)
                    raise SystemExit(0)
                raise SystemExit(2)
                """
            ),
            encoding="utf-8",
        )
        fake_aster.chmod(0o755)
        tour_parent = self.root / "wrapper-interrupt"
        environment = os.environ.copy()
        environment.update(
            {
                "ASTER_TOUR_BIN": str(fake_aster),
                "ASTER_TOUR_PARENT": str(tour_parent),
                "ASTER_TOUR_VIEW": "tui",
                "PATH": "/usr/bin:/bin:/usr/sbin:/sbin",
                "PYTHONDONTWRITEBYTECODE": "1",
                "TERM": "xterm-256color",
            }
        )
        process = subprocess.Popen(
            ["sh", str(ROOT / "tools" / "aster-tour.sh"), "quick"],
            cwd=ROOT,
            env=environment,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        demo_pid = None
        descendant_pid = None
        try:
            receipt = tour_parent / "quick.demo.stdout"
            deadline = time.monotonic() + 5
            while time.monotonic() < deadline:
                if receipt.exists() and receipt.stat().st_size:
                    lines = receipt.read_text().splitlines()
                    demo_lines = [line for line in lines if line.startswith("DEMO_PID=")]
                    descendant_lines = [
                        line for line in lines if line.startswith("DESCENDANT_PID=")
                    ]
                    if (
                        demo_lines
                        and descendant_lines
                        and "WRAPPER_DESCENDANT_READY" in lines
                    ):
                        demo_pid = int(demo_lines[0].split("=", 1)[1])
                        descendant_pid = int(descendant_lines[0].split("=", 1)[1])
                        break
                time.sleep(0.02)
            self.assertIsNotNone(demo_pid, "wrapper did not start the demo presenter")

            self.assertIsNotNone(descendant_pid, "wrapper demo descendant did not start")
            os.kill(process.pid, signal.SIGINT)
            stdout, stderr = process.communicate(timeout=9)
            self.assertEqual(process.returncode, 130, stderr)
            self.assertIn(b"\x1b[?1049h", stdout)
            self.assertIn(b"\x1b[?1049l", stdout)

            receipt_lines = receipt.read_text().splitlines()
            self.assertCountEqual(
                receipt_lines,
                (
                    f"DEMO_PID={demo_pid}",
                    f"DESCENDANT_PID={descendant_pid}",
                    "WRAPPER_DESCENDANT_READY",
                ),
            )

            gone = False
            for _ in range(40):
                try:
                    os.kill(demo_pid, 0)
                except ProcessLookupError:
                    gone = True
                    break
                time.sleep(0.05)
            self.assertTrue(gone, "wrapper termination orphaned the demo")

            descendant_gone = False
            for _ in range(40):
                try:
                    os.kill(descendant_pid, 0)
                except ProcessLookupError:
                    descendant_gone = True
                    break
                time.sleep(0.05)
            self.assertTrue(
                descendant_gone, "wrapper termination orphaned the demo descendant"
            )
        finally:
            if process.poll() is None:
                process.kill()
                process.wait()
            if demo_pid is not None:
                try:
                    os.kill(demo_pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
            if descendant_pid is not None:
                try:
                    os.kill(descendant_pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass

    @unittest.skipUnless(os.name == "posix", "tour process groups require POSIX")
    def test_wrapper_early_sigint_cannot_be_lost_before_presenter_exec(self) -> None:
        shim_directory = self.root / "shim"
        shim_directory.mkdir()
        shim_marker = self.root / "shim-started"
        demo_marker = self.root / "demo-started"
        python_shim = shim_directory / "python3"
        python_shim.write_text(
            textwrap.dedent(
                """\
                #!/bin/sh
                if [ "${2:-}" = "demo" ]; then
                  : >"$SHIM_MARKER"
                  sleep 1
                fi
                exec /usr/bin/python3 "$@"
                """
            ),
            encoding="utf-8",
        )
        python_shim.chmod(0o755)
        fake_aster = self.root / "must-not-start-aster"
        fake_aster.write_text(
            textwrap.dedent(
                """\
                #!/bin/sh
                : >"$DEMO_MARKER"
                sleep 30
                """
            ),
            encoding="utf-8",
        )
        fake_aster.chmod(0o755)
        tour_parent = self.root / "early-interrupt"
        environment = os.environ.copy()
        environment.update(
            {
                "ASTER_TOUR_BIN": str(fake_aster),
                "ASTER_TOUR_PARENT": str(tour_parent),
                "ASTER_TOUR_VIEW": "tui",
                "DEMO_MARKER": str(demo_marker),
                "PATH": f"{shim_directory}:/usr/bin:/bin:/usr/sbin:/sbin",
                "PYTHONDONTWRITEBYTECODE": "1",
                "SHIM_MARKER": str(shim_marker),
                "TERM": "xterm-256color",
            }
        )
        process = subprocess.Popen(
            ["sh", str(ROOT / "tools" / "aster-tour.sh"), "quick"],
            cwd=ROOT,
            env=environment,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            start_new_session=True,
        )
        try:
            deadline = time.monotonic() + 5
            while time.monotonic() < deadline and not shim_marker.exists():
                time.sleep(0.01)
            self.assertTrue(shim_marker.exists(), "presenter shim did not start")

            os.kill(process.pid, signal.SIGINT)
            _stdout, stderr = process.communicate(timeout=5)
            self.assertEqual(process.returncode, 130, stderr)
            self.assertFalse(demo_marker.exists(), "early Ctrl-C was lost")
            self.assertFalse((tour_parent / "quick.demo.stdout").exists())
        finally:
            if process.poll() is None:
                try:
                    os.killpg(process.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
                process.wait()

    @unittest.skipUnless(os.name == "posix", "tour process groups require POSIX")
    def test_interrupt_stops_descendant_and_restores_tui(self) -> None:
        stdout_receipt = self.root / "interrupt.stdout"
        stderr_receipt = self.root / "interrupt.stderr"
        final_stdout = "FINAL_OUT=" + "x" * 32768 + "\n"
        final_stderr = "FINAL_ERR=" + "y" * 32768 + "\n"
        descendant_program = (
            "import signal,time;"
            "signal.signal(signal.SIGINT,signal.SIG_IGN);"
            "print('DESCENDANT_READY',flush=True);"
            "time.sleep(30)"
        )
        demo_program = textwrap.dedent(
            f"""\
            import signal
            import subprocess
            import sys
            import time

            def stop(_signum, _frame):
                sys.stdout.write({final_stdout!r})
                sys.stdout.flush()
                sys.stderr.write({final_stderr!r})
                sys.stderr.flush()
                raise SystemExit(130)

            signal.signal(signal.SIGINT, stop)
            child = subprocess.Popen(
                [sys.executable, "-u", "-c", {descendant_program!r}]
            )
            print(f"CHILD_PID={{child.pid}}", flush=True)
            time.sleep(30)
            """
        )
        command = [
            sys.executable,
            str(UI_PATH),
            "demo",
            "--tour",
            "quick",
            "--nodes",
            "2",
            "--demo-root",
            str(self.root / "interrupt-root"),
            "--view",
            "tui",
            "--stdout-receipt",
            str(stdout_receipt),
            "--stderr-receipt",
            str(stderr_receipt),
            "--",
            sys.executable,
            "-u",
            "-c",
            demo_program,
        ]
        environment = os.environ.copy()
        environment["TERM"] = "xterm-256color"
        process = subprocess.Popen(
            command,
            cwd=ROOT,
            env=environment,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        descendant = None
        try:
            deadline = time.monotonic() + 5
            while time.monotonic() < deadline:
                if stdout_receipt.exists() and stdout_receipt.stat().st_size:
                    lines = stdout_receipt.read_text().splitlines()
                    pid_lines = [line for line in lines if line.startswith("CHILD_PID=")]
                    if pid_lines and "DESCENDANT_READY" in lines:
                        descendant = int(pid_lines[0].split("=", 1)[1])
                        break
                time.sleep(0.02)
            self.assertIsNotNone(descendant, "fake demo did not start its descendant")
            os.kill(process.pid, signal.SIGINT)
            stdout, stderr = process.communicate(timeout=8)
            self.assertEqual(process.returncode, 130)
            self.assertIn(b"\x1b[?1049h", stdout)
            self.assertIn(b"\x1b[?1049l", stdout)
            self.assertNotIn(b"Traceback", stderr)
            retained_stdout = stdout_receipt.read_bytes()
            prefixes = (
                f"CHILD_PID={descendant}\nDESCENDANT_READY\n".encode(),
                f"DESCENDANT_READY\nCHILD_PID={descendant}\n".encode(),
            )
            self.assertIn(
                retained_stdout,
                tuple(prefix + final_stdout.encode() for prefix in prefixes),
            )
            self.assertEqual(stderr_receipt.read_bytes(), final_stderr.encode())
            self.assertNotIn(b"\x1b", retained_stdout + stderr_receipt.read_bytes())

            gone = False
            for _ in range(40):
                try:
                    os.kill(descendant, 0)
                except ProcessLookupError:
                    gone = True
                    break
                time.sleep(0.05)
            self.assertTrue(gone, "interrupted demo descendant remained alive")
        finally:
            if process.poll() is None:
                process.kill()
                process.wait()
            if descendant is not None:
                try:
                    os.kill(descendant, signal.SIGKILL)
                except ProcessLookupError:
                    pass


if __name__ == "__main__":
    unittest.main()
