#!/usr/bin/env python3
# Copyright 2026 Defense Unicorns, Inc.
# SPDX-License-Identifier: Apache-2.0
"""Focused unit tests for the bounded Aster path-lab controller."""

from __future__ import annotations

import contextlib
import importlib.util
import io
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import time
from typing import Any, cast
import unittest
from unittest import mock


MODULE_PATH = Path(__file__).with_name("aster_path_lab.py")
SPEC = importlib.util.spec_from_file_location("aster_path_lab", MODULE_PATH)
assert SPEC is not None and SPEC.loader is not None
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


def fixture_process(
    popen_kwargs: dict[str, Any],
    *,
    stdout: bytes = b"",
    stderr: bytes = b"",
    returncode: int = 0,
) -> subprocess.Popen[bytes]:
    script = (
        "import os,sys; "
        f"os.write(1, {stdout!r}); os.write(2, {stderr!r}); sys.exit({returncode})"
    )
    return cast(
        subprocess.Popen[bytes],
        subprocess.Popen([sys.executable, "-c", script], **popen_kwargs),
    )


class PathLabControllerTests(unittest.TestCase):
    def test_run_command_terminates_output_above_the_capture_bound(self) -> None:
        processes: list[subprocess.Popen[bytes]] = []

        def start(argv: list[str], **kwargs: Any) -> subprocess.Popen[bytes]:
            process = cast(subprocess.Popen[bytes], subprocess.Popen(argv, **kwargs))
            processes.append(process)
            return process

        started = time.monotonic()
        with (
            mock.patch.object(MODULE, "MAX_COMMAND_OUTPUT_BYTES", 1024),
            self.assertRaisesRegex(MODULE.ExecutionError, "output exceeds"),
        ):
            MODULE._run_command(
                start,
                [
                    sys.executable,
                    "-c",
                    "import os; chunk=b'x'*4096\nwhile True: os.write(1, chunk)",
                ],
                timeout=10,
            )

        self.assertLess(time.monotonic() - started, 5)
        self.assertEqual(len(processes), 1)
        self.assertIsNotNone(processes[0].poll())

    def test_run_command_sanitizes_expected_subprocess_failures(self) -> None:
        failures = (
            subprocess.TimeoutExpired(["secret-argv"], 1, output=b"secret-output"),
            subprocess.SubprocessError("secret subprocess detail"),
            OSError("secret operating-system detail"),
        )
        for failure in failures:
            with self.subTest(failure=type(failure).__name__):
                def fail(*_args: object, **_kwargs: object) -> None:
                    raise failure

                with self.assertRaises(MODULE.ExecutionError) as raised:
                    MODULE._run_command(fail, ["secret-argv"], timeout=1)

                self.assertEqual(
                    str(raised.exception), "path-lab command could not be executed"
                )

    def test_cli_prints_one_canonical_plan_without_execution(self) -> None:
        manifest = {
            "schema": "aster-path-lab-scenario/v1",
            "id": "reset-smoke",
            "seed": 7,
            "timeline": [
                {
                    "at_ms": 0,
                    "action": "reset_netem",
                    "node": "wan",
                    "interface": "eth2",
                }
            ],
        }
        with tempfile.TemporaryDirectory() as directory:
            scenario = Path(directory) / "scenario.json"
            scenario.write_text(json.dumps(manifest), encoding="utf-8")
            stdout = io.StringIO()
            with contextlib.redirect_stdout(stdout):
                self.assertEqual(MODULE.main([str(scenario)]), 0)

        rendered = stdout.getvalue()
        self.assertTrue(rendered.endswith("\n"))
        self.assertNotIn(" ", rendered)
        self.assertEqual(json.loads(rendered)["scenario_id"], "reset-smoke")

    def test_cli_execute_runs_preflight_before_the_scenario(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            scenario = root / "scenario.json"
            scenario.write_text(
                json.dumps(
                    {
                        "schema": "aster-path-lab-scenario/v1",
                        "id": "reset-smoke",
                        "seed": 7,
                        "timeline": [
                            {
                                "at_ms": 0,
                                "action": "reset_netem",
                                "node": "wan",
                                "interface": "eth2",
                            }
                        ],
                    }
                ),
                encoding="utf-8",
            )
            executable = root / "containerlab"
            topology = root / "topology.clab.yml"
            receipt: dict[str, object] = {
                "schema": "aster-path-lab-smoke-receipt/v1",
                "status": "pass",
            }
            calls: list[str] = []

            def preflight(*_args: object, **_kwargs: object) -> None:
                calls.append("preflight")

            def execute(*_args: object, **_kwargs: object) -> dict[str, object]:
                calls.append("execute")
                return receipt

            stdout = io.StringIO()
            with (
                mock.patch.object(MODULE, "TOPOLOGY", topology),
                mock.patch.object(MODULE, "preflight_execution", side_effect=preflight),
                mock.patch.object(MODULE, "execute_scenario", side_effect=execute),
                contextlib.redirect_stdout(stdout),
            ):
                self.assertEqual(
                    MODULE.main(
                        [str(scenario), "--execute", "--containerlab", str(executable)]
                    ),
                    0,
                )

        self.assertEqual(calls, ["preflight", "execute"])
        self.assertEqual(json.loads(stdout.getvalue()), receipt)

    def test_containerlab_version_must_match_the_exact_pin(self) -> None:
        MODULE.validate_containerlab_version(b"0.79.0\n")
        with self.assertRaisesRegex(MODULE.ExecutionError, "requires Containerlab 0.79.0"):
            MODULE.validate_containerlab_version(b"0.79.1\n")

    def test_execution_preflight_requires_linux_and_the_exact_tool(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            executable = root / "containerlab"
            executable.write_bytes(b"fixture")
            executable.chmod(0o700)
            topology = root / "topology.clab.yml"
            topology.write_text("name: fixture\n", encoding="utf-8")

            def run(argv: list[str], **kwargs: Any) -> subprocess.Popen[bytes]:
                self.assertEqual(argv, [str(executable), "version", "--short"])
                return fixture_process(kwargs, stdout=b"0.79.0\n")

            MODULE.preflight_execution(
                executable,
                topology,
                runner=run,
                system=lambda: "Linux",
            )
            with self.assertRaisesRegex(MODULE.ExecutionError, "requires Linux"):
                MODULE.preflight_execution(
                    executable,
                    topology,
                    runner=run,
                    system=lambda: "Darwin",
                )

    def test_valid_manifest_compiles_to_one_exact_netem_operation(self) -> None:
        manifest = {
            "schema": "aster-path-lab-scenario/v1",
            "id": "latency-smoke",
            "seed": 104729,
            "timeline": [
                {
                    "at_ms": 0,
                    "action": "set_netem",
                    "node": "wan",
                    "interface": "eth2",
                    "delay_ms": 50,
                    "jitter_ms": 5,
                    "loss_percent": 1.25,
                    "rate_kbit": 512,
                }
            ],
        }

        plan = MODULE.compile_manifest(json.dumps(manifest).encode("utf-8"))

        self.assertEqual(plan["schema"], "aster-path-lab-plan/v1")
        self.assertEqual(plan["scenario_id"], "latency-smoke")
        self.assertEqual(plan["seed"], 104729)
        self.assertEqual(
            plan["operations"],
            [
                {
                    "at_ms": 0,
                    "argv": [
                        "containerlab",
                        "tools",
                        "netem",
                        "set",
                        "--node",
                        "clab-aster-path-lab-wan",
                        "--interface",
                        "eth2",
                        "--delay",
                        "50ms",
                        "--jitter",
                        "5ms",
                        "--loss",
                        "1.25",
                        "--rate",
                        "512",
                    ],
                }
            ],
        )

    def test_manifest_rejects_unknown_unsafe_and_unbounded_values(self) -> None:
        base = {
            "schema": "aster-path-lab-scenario/v1",
            "id": "latency-smoke",
            "seed": 104729,
            "timeline": [
                {
                    "at_ms": 0,
                    "action": "set_netem",
                    "node": "wan",
                    "interface": "eth2",
                    "delay_ms": 50,
                    "jitter_ms": 5,
                    "loss_percent": 1.25,
                    "rate_kbit": 512,
                }
            ],
        }
        mutations = (
            (lambda value: value.update({"extra": True}), "unknown field"),
            (
                lambda value: value["timeline"][0].update({"node": "wan;id"}),
                "node",
            ),
            (
                lambda value: value["timeline"][0].update({"interface": "eth2/../x"}),
                "interface",
            ),
            (
                lambda value: value["timeline"][0].update({"loss_percent": 100.01}),
                "loss_percent",
            ),
            (
                lambda value: value["timeline"][0].update({"jitter_ms": 51}),
                "jitter_ms",
            ),
        )
        for mutate, message in mutations:
            with self.subTest(message=message):
                candidate = json.loads(json.dumps(base))
                mutate(candidate)
                with self.assertRaisesRegex(MODULE.ScenarioError, message):
                    MODULE.compile_manifest(json.dumps(candidate).encode("utf-8"))

        out_of_order = json.loads(json.dumps(base))
        out_of_order["timeline"].append(
            {
                "at_ms": 0,
                "action": "reset_netem",
                "node": "wan",
                "interface": "eth2",
            }
        )
        with self.assertRaisesRegex(MODULE.ScenarioError, "strictly increasing"):
            MODULE.compile_manifest(json.dumps(out_of_order).encode("utf-8"))

    def test_manifest_rejects_duplicate_keys_and_non_finite_numbers(self) -> None:
        duplicate = (
            b'{"schema":"aster-path-lab-scenario/v1","id":"first",'
            b'"id":"second","seed":1,"timeline":[]}'
        )
        with self.assertRaisesRegex(MODULE.ScenarioError, "duplicate field"):
            MODULE.compile_manifest(duplicate)

        non_finite = (
            b'{"schema":"aster-path-lab-scenario/v1","id":"nan-loss","seed":1,'
            b'"timeline":[{"at_ms":0,"action":"set_netem","node":"wan",'
            b'"interface":"eth2","delay_ms":1,"jitter_ms":0,'
            b'"loss_percent":NaN,"rate_kbit":1}]}'
        )
        with self.assertRaisesRegex(MODULE.ScenarioError, "non-finite"):
            MODULE.compile_manifest(non_finite)

    def test_netem_readback_must_match_the_compiled_operation(self) -> None:
        operation = {
            "at_ms": 0,
            "argv": [
                "containerlab",
                "tools",
                "netem",
                "set",
                "--node",
                "clab-aster-path-lab-wan",
                "--interface",
                "eth2",
                "--delay",
                "50ms",
                "--jitter",
                "5ms",
                "--loss",
                "1.25",
                "--rate",
                "512",
            ],
        }
        observed = {
            "clab-aster-path-lab-wan": [
                {
                    "interface": "eth2",
                    "delay": "50ms",
                    "jitter": "5ms",
                    "packet_loss": 1.25,
                    "rate": 512,
                    "corruption": 0,
                }
            ]
        }

        MODULE.validate_netem_readback(operation, json.dumps(observed).encode())

        observed["clab-aster-path-lab-wan"][0]["packet_loss"] = 1.0
        with self.assertRaisesRegex(MODULE.ExecutionError, "read-back mismatch"):
            MODULE.validate_netem_readback(operation, json.dumps(observed).encode())

    def test_execute_scenario_refuses_a_preexisting_lab_without_destroying_it(self) -> None:
        raw = json.dumps(
            {
                "schema": "aster-path-lab-scenario/v1",
                "id": "reset-smoke",
                "seed": 7,
                "timeline": [
                    {
                        "at_ms": 0,
                        "action": "reset_netem",
                        "node": "wan",
                        "interface": "eth2",
                    }
                ],
            }
        ).encode()
        calls: list[list[str]] = []

        def run(_runner: object, argv: list[str], *, timeout: float) -> bytes:
            del timeout
            calls.append(argv)
            return b'{"aster-path-lab":[{"name":"aster-path-lab"}]}'

        with (
            mock.patch.object(MODULE, "_run_command", side_effect=run),
            self.assertRaisesRegex(MODULE.ExecutionError, "already exists"),
        ):
            MODULE.execute_scenario(
                raw,
                containerlab=Path("/usr/local/bin/containerlab"),
                topology=Path("/repo/docker/path-lab/topology.clab.yml"),
                runner=object(),
            )

        self.assertEqual(
            calls,
            [[
                "/usr/local/bin/containerlab",
                "inspect",
                "--all",
                "--format",
                "json",
            ]],
        )

    def test_execute_scenario_rejects_a_non_grouped_inspection_result(self) -> None:
        raw = json.dumps(
            {
                "schema": "aster-path-lab-scenario/v1",
                "id": "reset-smoke",
                "seed": 7,
                "timeline": [
                    {
                        "at_ms": 0,
                        "action": "reset_netem",
                        "node": "wan",
                        "interface": "eth2",
                    }
                ],
            }
        ).encode()
        calls: list[list[str]] = []

        def run(_runner: object, argv: list[str], *, timeout: float) -> bytes:
            del timeout
            calls.append(argv)
            return b"[]"

        with (
            mock.patch.object(MODULE, "_run_command", side_effect=run),
            self.assertRaisesRegex(MODULE.ExecutionError, "lab inspection"),
        ):
            MODULE.execute_scenario(
                raw,
                containerlab=Path("/usr/local/bin/containerlab"),
                topology=Path("/repo/docker/path-lab/topology.clab.yml"),
                runner=object(),
            )

        self.assertEqual(len(calls), 1)

    def test_execute_scenario_ignores_other_grouped_labs(self) -> None:
        raw = json.dumps(
            {
                "schema": "aster-path-lab-scenario/v1",
                "id": "reset-smoke",
                "seed": 7,
                "timeline": [
                    {
                        "at_ms": 0,
                        "action": "reset_netem",
                        "node": "wan",
                        "interface": "eth2",
                    }
                ],
            }
        ).encode()
        calls: list[list[str]] = []

        def run(_runner: object, argv: list[str], *, timeout: float) -> bytes:
            del timeout
            calls.append(argv)
            if argv[1] == "inspect":
                return b'{"other-lab":[{"name":"other-lab"}]}'
            if argv[1] == "deploy":
                raise MODULE.ExecutionError("deploy stopped")
            return b""

        with (
            mock.patch.object(MODULE, "_run_command", side_effect=run),
            self.assertRaisesRegex(MODULE.ExecutionError, "deploy stopped"),
        ):
            MODULE.execute_scenario(
                raw,
                containerlab=Path("/usr/local/bin/containerlab"),
                topology=Path("/repo/docker/path-lab/topology.clab.yml"),
                runner=object(),
            )

        self.assertEqual(
            [call[1] for call in calls], ["inspect", "deploy", "destroy"]
        )

    def test_execute_scenario_destroys_after_a_failed_deploy_attempt(self) -> None:
        raw = json.dumps(
            {
                "schema": "aster-path-lab-scenario/v1",
                "id": "reset-smoke",
                "seed": 7,
                "timeline": [
                    {
                        "at_ms": 0,
                        "action": "reset_netem",
                        "node": "wan",
                        "interface": "eth2",
                    }
                ],
            }
        ).encode()
        failures = (
            "failed with exit status 1",
            "timed out",
            "output exceeds the byte bound",
        )
        for failure in failures:
            with self.subTest(failure=failure):
                calls: list[list[str]] = []

                def run(_runner: object, argv: list[str], *, timeout: float) -> bytes:
                    del timeout
                    calls.append(argv)
                    if argv[1] == "inspect":
                        return b"{}"
                    if argv[1] == "deploy":
                        raise MODULE.ExecutionError(f"path-lab command {failure}")
                    return b""

                with (
                    mock.patch.object(MODULE, "_run_command", side_effect=run),
                    self.assertRaisesRegex(MODULE.ExecutionError, failure),
                ):
                    MODULE.execute_scenario(
                        raw,
                        containerlab=Path("/usr/local/bin/containerlab"),
                        topology=Path("/repo/docker/path-lab/topology.clab.yml"),
                        runner=object(),
                    )

                self.assertEqual(
                    [call[1] for call in calls], ["inspect", "deploy", "destroy"]
                )

    def test_execution_deploys_observes_and_destroys_the_lab(self) -> None:
        raw = json.dumps(
            {
                "schema": "aster-path-lab-scenario/v1",
                "id": "latency-smoke",
                "seed": 104729,
                "timeline": [
                    {
                        "at_ms": 0,
                        "action": "set_netem",
                        "node": "wan",
                        "interface": "eth2",
                        "delay_ms": 50,
                        "jitter_ms": 5,
                        "loss_percent": 1.25,
                        "rate_kbit": 512,
                    }
                ],
            }
        ).encode()
        calls: list[list[str]] = []

        def run(argv: list[str], **kwargs: Any) -> subprocess.Popen[bytes]:
            self.assertIsInstance(argv, list)
            self.assertNotIn("shell", kwargs)
            calls.append(argv)
            if argv[1] == "inspect":
                stdout = b"{}"
            elif argv[1:4] == ["tools", "netem", "show"]:
                stdout = json.dumps(
                    {
                        "clab-aster-path-lab-wan": [
                            {
                                "interface": "eth2",
                                "delay": "50ms",
                                "jitter": "5ms",
                                "packet_loss": 1.25,
                                "rate": 512,
                                "corruption": 0,
                            }
                        ]
                    }
                ).encode()
            else:
                stdout = b""
            return fixture_process(kwargs, stdout=stdout)

        receipt = MODULE.execute_scenario(
            raw,
            containerlab=Path("/usr/local/bin/containerlab"),
            topology=Path("/repo/docker/path-lab/topology.clab.yml"),
            runner=run,
            sleep=lambda _seconds: None,
            monotonic=lambda: 10.0,
        )

        self.assertEqual(receipt["status"], "pass")
        self.assertEqual(receipt["cleanup"], "pass")
        self.assertEqual(
            calls[0],
            [
                "/usr/local/bin/containerlab",
                "inspect",
                "--all",
                "--format",
                "json",
            ],
        )
        self.assertEqual(calls[1][1], "deploy")
        self.assertEqual(calls[-1][1], "destroy")
        self.assertEqual(calls[3][-2:], ["--format", "json"])

    def test_cleanup_failure_is_a_sanitized_execution_failure(self) -> None:
        raw = json.dumps(
            {
                "schema": "aster-path-lab-scenario/v1",
                "id": "reset-smoke",
                "seed": 7,
                "timeline": [
                    {
                        "at_ms": 0,
                        "action": "reset_netem",
                        "node": "wan",
                        "interface": "eth2",
                    }
                ],
            }
        ).encode()

        def run(argv: list[str], **kwargs: Any) -> subprocess.Popen[bytes]:
            return fixture_process(
                kwargs,
                stdout=b"{}" if argv[1] == "inspect" else b"",
                stderr=b"sensitive upstream diagnostic",
                returncode=1 if argv[1] == "destroy" else 0,
            )

        with self.assertRaisesRegex(MODULE.ExecutionError, "cleanup failed"):
            MODULE.execute_scenario(
                raw,
                containerlab=Path("/usr/local/bin/containerlab"),
                topology=Path("/repo/docker/path-lab/topology.clab.yml"),
                runner=run,
                sleep=lambda _seconds: None,
                monotonic=lambda: 10.0,
            )


if __name__ == "__main__":
    unittest.main()
