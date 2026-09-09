#!/usr/bin/env python3
# Copyright 2026 Defense Unicorns, Inc.
# SPDX-License-Identifier: Apache-2.0
"""Focused tests for the bounded real-Event path-delivery controller."""

from __future__ import annotations

import base64
import importlib.util
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import time
import unittest
from unittest import mock


MODULE_PATH = Path(__file__).with_name("aster_path_delivery.py")
SPEC = importlib.util.spec_from_file_location("aster_path_delivery", MODULE_PATH)
assert SPEC is not None and SPEC.loader is not None
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


def load_script(name: str):
    path = MODULE_PATH.parents[1] / "docker/path-lab" / name
    spec = importlib.util.spec_from_file_location(name.replace("-", "_"), path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class PathDeliveryControllerTests(unittest.TestCase):
    def test_second_process_cannot_acquire_fixed_lab_ownership_lock(self) -> None:
        self.assertEqual(MODULE.LAB_LOCK.parent.parent, Path("/run/lock"))
        self.assertEqual(MODULE.LAB_LOCK.parent.name, MODULE.LAB)
        child = (
            "import importlib.util, pathlib, sys; "
            "spec=importlib.util.spec_from_file_location('delivery', sys.argv[1]); "
            "module=importlib.util.module_from_spec(spec); spec.loader.exec_module(module); "
            "lock=pathlib.Path(sys.argv[2]); "
            "\ntry:\n"
            "    with module._lab_lock(lock): pass\n"
            "except module.ExecutionError as error:\n"
            "    raise SystemExit(0 if str(error) == "
            "'another path-delivery execution is active' else 2)\n"
            "raise SystemExit(3)"
        )
        with tempfile.TemporaryDirectory() as directory:
            lock_path = Path(directory) / "aster-path-delivery.lock"
            with MODULE._lab_lock(lock_path):
                completed = subprocess.run(
                    [sys.executable, "-c", child, str(MODULE_PATH), str(lock_path)],
                    check=False,
                    stdin=subprocess.DEVNULL,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    timeout=5,
                )

        self.assertEqual(completed.returncode, 0, completed.stderr.decode(errors="replace"))

        with tempfile.TemporaryDirectory() as directory:
            unsafe_parent = Path(directory) / "unsafe"
            unsafe_parent.mkdir(mode=0o777)
            unsafe_parent.chmod(0o777)
            with self.assertRaisesRegex(MODULE.ExecutionError, "lock directory"):
                with MODULE._lab_lock(unsafe_parent / "owner.lock"):
                    pass

        with tempfile.TemporaryDirectory() as directory:
            lock_path = Path(directory) / "owner.lock"
            lock_path.write_text("", encoding="ascii")
            lock_path.chmod(0o644)
            with self.assertRaisesRegex(MODULE.ExecutionError, "lock file"):
                with MODULE._lab_lock(lock_path):
                    pass

    def test_command_capture_kills_output_above_the_bound(self) -> None:
        started = time.monotonic()
        with (
            mock.patch.object(MODULE, "MAX_OUTPUT_BYTES", 1024),
            self.assertRaisesRegex(MODULE.ExecutionError, "output exceeds"),
        ):
            MODULE._run_command(
                [
                    sys.executable,
                    "-c",
                    "import os; chunk=b'x'*4096\nwhile True: os.write(1, chunk)",
                ],
                5,
            )
        self.assertLess(time.monotonic() - started, 2)

    def test_manifest_compiles_only_the_fixed_delivery_contract(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            oversized = Path(directory) / "oversized.json"
            oversized.write_bytes(b"x" * (MODULE.MAX_SCENARIO_BYTES + 1))
            with self.assertRaisesRegex(MODULE.ScenarioError, "byte bound"):
                MODULE._read_scenario(oversized)

        raw = json.dumps(
            {
                "schema": "aster-path-delivery-scenario/v1",
                "id": "event-delivery-netem",
                "seed": 104729,
                "operation_key": "path-delivery-one",
                "logical_key": "dispatch/one",
                "payload": "bounded real Event over routed netem",
            }
        ).encode()

        plan = MODULE.compile_scenario(raw)

        self.assertEqual(
            plan,
            {
                "schema": "aster-path-delivery-plan/v1",
                "scenario_id": "event-delivery-netem",
                "seed": 104729,
                "operation_key": "path-delivery-one",
                "logical_key": "dispatch/one",
                "payload": "bounded real Event over routed netem",
                "netem": {
                    "node": "clab-aster-path-delivery-wan",
                    "interface": "eth2",
                    "delay": "40ms",
                    "jitter": "5ms",
                    "packet_loss": 1.0,
                    "rate": 100000,
                },
            },
        )

    def test_manifest_rejects_duplicate_unknown_and_control_bearing_input(self) -> None:
        malformed = (
            b'{"schema":"aster-path-delivery-scenario/v1","id":"event-delivery-netem",'
            b'"id":"event-delivery-netem","operation_key":"one",'
            b'"logical_key":"key","payload":"payload"}'
        )
        with self.assertRaisesRegex(MODULE.ScenarioError, "duplicate field"):
            MODULE.compile_scenario(malformed)

        base = {
            "schema": "aster-path-delivery-scenario/v1",
            "id": "event-delivery-netem",
            "seed": 104729,
            "operation_key": "one",
            "logical_key": "key",
            "payload": "payload",
        }
        base["command"] = "sh"
        with self.assertRaisesRegex(MODULE.ScenarioError, "fields"):
            MODULE.compile_scenario(json.dumps(base).encode())

        del base["command"]
        base["payload"] = "line one\nline two"
        with self.assertRaisesRegex(MODULE.ScenarioError, "payload"):
            MODULE.compile_scenario(json.dumps(base).encode())

        for constant in (b"NaN", b"Infinity", b"-Infinity"):
            malformed_constant = (
                b'{"schema":"aster-path-delivery-scenario/v1",'
                b'"id":"event-delivery-netem","operation_key":"one",'
                b'"logical_key":"key","payload":' + constant + b"}"
            )
            with self.assertRaisesRegex(MODULE.ScenarioError, "JSON"):
                MODULE.compile_scenario(malformed_constant)

        with self.assertRaisesRegex(MODULE.ExecutionError, "malformed"):
            MODULE._strict_json(b'{"packet_loss":NaN}', "netem read-back")

    def test_execution_refuses_an_exact_existing_lab_key_even_when_empty(self) -> None:
        scenario = {
            "schema": "aster-path-delivery-scenario/v1",
            "id": "event-delivery-netem",
            "seed": 104729,
            "operation_key": "one",
            "logical_key": "key",
            "payload": "payload",
        }
        calls: list[list[str]] = []

        def run(argv: list[str], timeout: float) -> bytes:
            del timeout
            calls.append(argv)
            return b'{"aster-path-delivery":{}}'

        with (
            tempfile.TemporaryDirectory() as directory,
            self.assertRaisesRegex(MODULE.ExecutionError, "already exists"),
        ):
            topology = Path(directory) / "topology.delivery.clab.yml"
            topology.write_text("name: aster-path-delivery\n", encoding="utf-8")
            MODULE.execute_scenario(
                json.dumps(scenario).encode(),
                containerlab=Path("/usr/local/bin/containerlab"),
                docker=Path("/usr/local/bin/docker"),
                topology=topology,
                run=run,
                lock_path=Path(directory) / "aster-path-delivery.lock",
            )

        self.assertEqual(len(calls), 1)

    def test_execution_reports_primary_and_cleanup_stage_without_inner_output(self) -> None:
        scenario = {
            "schema": "aster-path-delivery-scenario/v1",
            "id": "event-delivery-netem",
            "seed": 104729,
            "operation_key": "one",
            "logical_key": "key",
            "payload": "payload",
        }

        def run(argv: list[str], timeout: float) -> bytes:
            del timeout
            if argv[1:5] == ["inspect", "--all", "--format", "json"]:
                return b"{}"
            if argv[1] == "deploy":
                raise MODULE.ExecutionError("raw-primary-output")
            if argv[1] == "destroy":
                raise MODULE.ExecutionError("raw-cleanup-output")
            return b""

        with tempfile.TemporaryDirectory() as directory:
            topology = Path(directory) / "topology.delivery.clab.yml"
            topology.write_text("name: aster-path-delivery\n", encoding="utf-8")
            with self.assertRaises(MODULE.ExecutionError) as raised:
                MODULE.execute_scenario(
                    json.dumps(scenario).encode(),
                    containerlab=Path("/usr/local/bin/containerlab"),
                    docker=Path("/usr/local/bin/docker"),
                    topology=topology,
                    run=run,
                    lock_path=Path(directory) / "aster-path-delivery.lock",
                )

        message = str(raised.exception)
        self.assertEqual(
            message,
            "path-delivery failed: primary=lab-deploy cleanup=lab-destroy",
        )
        self.assertNotIn("raw-primary-output", message)
        self.assertNotIn("raw-cleanup-output", message)
        causes = []
        cause = raised.exception.__cause__
        while cause is not None:
            causes.append(str(cause))
            cause = cause.__cause__
        self.assertEqual(causes, ["raw-cleanup-output", "raw-primary-output"])

    def test_execution_delivers_exact_event_and_reports_bounded_oracles(self) -> None:
        scenario = {
            "schema": "aster-path-delivery-scenario/v1",
            "id": "event-delivery-netem",
            "seed": 104729,
            "operation_key": "path-delivery-one",
            "logical_key": "dispatch/one",
            "payload": "bounded real Event over routed netem",
        }
        event_id = base64.b64encode(bytes(range(32))).decode("ascii")
        status = {
            "identity": base64.b64encode(bytes([1]) * 32).decode("ascii"),
            "missionAuthority": base64.b64encode(bytes([2]) * 32).decode("ascii"),
            "sync": "AWAITING_AUTHENTICATED_CONTACT",
        }
        calls: list[list[str]] = []

        def run(argv: list[str], timeout: float) -> bytes:
            del timeout
            calls.append(argv)
            if argv[1:5] == ["inspect", "--all", "--format", "json"]:
                return b"{}"
            if argv[1:4] == ["tools", "netem", "show"]:
                return json.dumps(
                    {
                        "clab-aster-path-delivery-wan": [
                            {
                                "interface": "eth2",
                                "delay": "40ms",
                                "jitter": "5ms",
                                "packet_loss": 1.0,
                                "rate": 100000,
                                "corruption": 0,
                            }
                        ]
                    }
                ).encode()
            if "status" in argv:
                return json.dumps(status).encode()
            if argv[1:6] == [
                "exec", "--user", "10001:10001",
                "clab-aster-path-delivery-node-a", "python3",
            ]:
                return (event_id + "\n").encode()
            if argv[1:6] == [
                "exec", "--user", "10001:10001",
                "clab-aster-path-delivery-node-b", "python3",
            ] and "wait" in argv:
                return json.dumps(
                    {
                        "id": event_id,
                        "logicalKey": base64.b64encode(b"dispatch/one").decode(),
                        "payload": base64.b64encode(
                            b"bounded real Event over routed netem"
                        ).decode(),
                    }
                ).encode()
            if argv[1:3] == ["wait", "clab-aster-path-delivery-provisioner"]:
                return b"0\n"
            return b""

        with tempfile.TemporaryDirectory() as directory:
            topology = Path(directory) / "topology.delivery.clab.yml"
            topology.write_text("name: aster-path-delivery\n", encoding="utf-8")
            receipt = MODULE.execute_scenario(
                json.dumps(scenario).encode(),
                containerlab=Path("/usr/local/bin/containerlab"),
                docker=Path("/usr/local/bin/docker"),
                topology=topology,
                run=run,
                lock_path=Path(directory) / "aster-path-delivery.lock",
            )

        self.assertEqual(receipt["status"], "pass")
        self.assertEqual(receipt["event_id"], event_id)
        self.assertEqual(receipt["event_oracle"], "pass")
        self.assertNotIn("configured_netem_oracle", receipt)
        self.assertEqual(receipt["seed"], 104729)
        self.assertEqual(receipt["configured_netem"], MODULE.FIXED_NETEM)
        self.assertEqual(receipt["one_host_container_limitation"], True)
        self.assertEqual(
            receipt["not_run"],
            ["recovery", "resource", "physical", "measured-latency", "actual-loss"],
        )
        self.assertIn("reset", [value for call in calls for value in call])
        self.assertEqual(
            [call[-1] for call in calls if call[1:3] == ["run", "--rm"]],
            ["node-a", "node-b"],
        )
        detached_agents = [call for call in calls if call[1:3] == ["exec", "--detach"]]
        self.assertEqual(len(detached_agents), 2)
        wan_setup = [
            call for call in calls
            if call[-1:] == ["configure"] and call[-2].endswith("/delivery-wan.py")
        ]
        self.assertEqual(len(wan_setup), 1)
        application_helpers = [
            call
            for call in calls
            if "/usr/local/libexec/aster/aster_lan_mvp.py" in call
        ]
        self.assertEqual(len(application_helpers), 5)
        self.assertTrue(
            all(call[1:4] == ["exec", "--user", "10001:10001"] for call in application_helpers)
        )
        self.assertEqual(calls[-1][1], "inspect")

    def test_readiness_and_cleanup_shapes_fail_closed(self) -> None:
        status = {
            "identity": base64.b64encode(bytes([3]) * 32).decode("ascii"),
            "missionAuthority": base64.b64encode(bytes([4]) * 32).decode("ascii"),
            "sync": "AWAITING_AUTHENTICATED_CONTACT",
        }
        self.assertEqual(MODULE._validate_status(json.dumps(status).encode()), status)
        for malformed in (b"{}", b'{"identity":"not-base64"}'):
            with self.subTest(malformed=malformed):
                with self.assertRaisesRegex(MODULE.ExecutionError, "status"):
                    MODULE._validate_status(malformed)
        self.assertTrue(MODULE._lab_is_absent({}))
        self.assertFalse(MODULE._lab_is_absent({MODULE.LAB: {}}))

    def test_delivery_topology_is_isolated_and_role_bounded(self) -> None:
        root = MODULE_PATH.parents[1]
        topology = (root / "docker/path-lab/topology.delivery.clab.yml").read_text(
            encoding="utf-8"
        )
        self.assertIn("name: aster-path-delivery", topology)
        self.assertIn("__clabDir__:/lab", topology)
        self.assertEqual(topology.count("__clabNodeDir__:/clab"), 2)
        self.assertIn("network-mode: none", topology)
        self.assertIn('restart-policy: "no"', topology)
        self.assertIn("net.ipv4.ip_forward: 1", topology)
        self.assertEqual(topology.count("cap-drop:\n        - ALL"), 4)
        self.assertEqual(topology.count("cap-add:\n        - NET_ADMIN"), 1)
        self.assertIn("cmd: sleep infinity", topology)
        self.assertNotIn("delivery-wan.py", topology)
        self.assertNotIn("0.0.0.0:4433", topology)
        self.assertIn('node-a:eth1", "wan:eth1', topology)
        self.assertIn('wan:eth2", "node-b:eth1', topology)

    def test_fixed_role_scripts_compile_exact_network_and_agent_argv(self) -> None:
        network = load_script("delivery-network-init.py")
        self.assertEqual(
            network.commands("node-a"),
            [
                ["ip", "address", "add", "10.77.1.2/30", "dev", "eth1"],
                ["ip", "link", "set", "eth1", "up"],
                ["ip", "route", "add", "10.77.2.0/30", "via", "10.77.1.1"],
            ],
        )
        with self.assertRaisesRegex(ValueError, "role"):
            network.commands("node-a;id")

        agent = load_script("delivery-agent.py")
        provision = load_script("delivery-provision.py")
        with mock.patch.object(provision.os, "umask") as umask:
            provision.set_owner_only_umask()
        umask.assert_called_once_with(0o077)
        self.assertEqual(
            provision.state_targets(Path("/lab")),
            [Path("/lab/node-a/state"), Path("/lab/node-b/state")],
        )
        with tempfile.TemporaryDirectory() as parent:
            seed = provision.seed_root(Path(parent))
            self.assertEqual(seed, Path(parent) / "mission")
            self.assertFalse(seed.exists())
        with tempfile.TemporaryDirectory() as directory:
            lab = Path(directory) / "clab"
            targets = provision.create_state_targets(lab)
            self.assertEqual(targets, provision.state_targets(lab))
            self.assertTrue(all(target.is_dir() for target in targets))
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "source"
            target = root / "target"
            source.mkdir()
            target.mkdir()
            (source / "regular").write_text("safe", encoding="ascii")
            (source / "link").symlink_to(source / "regular")
            with self.assertRaisesRegex(ValueError, "regular"):
                provision.copy_state(source, target)
        started = time.monotonic()
        with (
            mock.patch.object(provision, "MAX_INITIALIZER_OUTPUT_BYTES", 1024),
            self.assertRaisesRegex(ValueError, "initializer output"),
        ):
            provision.run_initializer(
                [
                    sys.executable,
                    "-c",
                    "import os; chunk=b'x'*4096\nwhile True: os.write(1, chunk)",
                ],
                timeout=5,
            )
        self.assertLess(time.monotonic() - started, 2)
        with tempfile.TemporaryDirectory() as directory:
            state = Path(directory)
            (state / "peer").write_text(
                "" + "a" * 64 + "@10.77.2.2:4433=" + "b" * 64 + "\n",
                encoding="ascii",
            )
            argv = agent.agent_argv("node-a", state)
        self.assertEqual(argv[argv.index("--mesh-bind") + 1], "10.77.1.2:4433")
        self.assertEqual(argv[argv.index("--listen") + 1], "127.0.0.1:8181")
        self.assertEqual(argv[argv.index("--peer") + 1], "a" * 64 + "@10.77.2.2:4433=" + "b" * 64)
        self.assertNotIn("sh", argv)

    def test_delivery_image_and_scenario_are_fixed_and_separate(self) -> None:
        root = MODULE_PATH.parents[1]
        dockerfile = (root / "docker/path-lab/Dockerfile.delivery").read_text(encoding="utf-8")
        self.assertIn("cargo build --locked --release -p aster-node -p aster-agent", dockerfile)
        self.assertIn("iproute2", dockerfile)
        self.assertIn("delivery-provision.py", dockerfile)
        scenario = json.loads(
            (root / "docker/path-lab/scenarios/event-delivery-netem.json").read_text(
                encoding="utf-8"
            )
        )
        self.assertEqual(MODULE.compile_scenario(json.dumps(scenario).encode())["netem"], MODULE.FIXED_NETEM)
        self.assertEqual(scenario["payload"], "bounded real Event over routed netem")
        self.assertEqual(scenario["seed"], 104729)

    def test_repository_entrypoints_keep_delivery_as_a_separate_required_lane(self) -> None:
        root = MODULE_PATH.parents[1]
        mise = (root / "mise.toml").read_text(encoding="utf-8")
        self.assertIn("[tasks.path-delivery-plan]", mise)
        self.assertIn("[tasks.path-delivery-smoke]", mise)
        workflow = (root / ".github/workflows/ci.yml").read_text(encoding="utf-8")
        self.assertIn("path-delivery-smoke:", workflow)
        self.assertIn("- path-delivery-smoke", workflow)
        dockerignore = (root / ".dockerignore").read_text(encoding="utf-8")
        for required_context_path in (
            "!proto/",
            "!proto/**",
            "!tools/",
            "!tools/aster_lan_mvp.py",
            "!docker/",
            "!docker/path-lab/",
            "!docker/path-lab/Dockerfile.delivery",
            "!docker/path-lab/delivery-*.py",
        ):
            self.assertIn(required_context_path, dockerignore)
        readme = (root / "docker/path-lab/README.md").read_text(encoding="utf-8")
        self.assertIn("one-host container limitation", readme)
        self.assertIn("does not claim recovery", readme)
        self.assertIn("exact Event ID, logical key, and payload", readme)


if __name__ == "__main__":
    unittest.main()
