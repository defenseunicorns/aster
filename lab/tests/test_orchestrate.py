import importlib.util
import contextlib
import hashlib
import io
import json
import os
from pathlib import Path
import struct
import subprocess
import sys
import tempfile
import unittest
from unittest import mock


MODULE_PATH = Path(__file__).resolve().parents[1] / "orchestrate.py"
SPEC = importlib.util.spec_from_file_location("aster_lab_orchestrate", MODULE_PATH)
assert SPEC is not None and SPEC.loader is not None
orchestrate = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = orchestrate
SPEC.loader.exec_module(orchestrate)


class ControllerTests(unittest.TestCase):
    def context(self, root: Path):
        return orchestrate.RunContext(
            label="test",
            run_id="0123456789abcdef",
            run_dir=root,
            resources=[],
            runner=orchestrate.CommandRunner(root),
            image_id="sha256:" + "a" * 64,
        )

    def test_fixed_networks_are_disjoint_and_namespaced(self):
        specs = orchestrate.network_specs(
            [orchestrate.DIRECT_SPEC, *orchestrate.NAT_NETWORKS.values()]
        )
        self.assertEqual(len(specs), 4)
        self.assertTrue(all(spec.name.startswith("aster-lab-") for spec in specs))

    def test_transfer_can_disable_restart_but_blob_cannot(self):
        transfer = orchestrate.parser().parse_args(
            ["self-contained", "transfer", "--restart-after-frames", "0"]
        )
        self.assertEqual(transfer.restart_after_frames, 0)
        blob = orchestrate.parser().parse_args(
            ["self-contained", "blob-recovery", "--restart-after-frames", "0"]
        )
        with self.assertRaises(orchestrate.LabError):
            orchestrate.run_self_contained(blob)

    def test_run_command_is_pull_never_and_minimum_capability(self):
        with tempfile.TemporaryDirectory() as temporary:
            args = orchestrate.container_run_args(
                self.context(Path(temporary)),
                name="aster-lab-transfer",
                role="transfer",
                command=["transfer", "--root", "/output/run"],
            )
        self.assertIn("--pull=never", args)
        self.assertIn("--cap-drop=ALL", args)
        self.assertIn("--security-opt=no-new-privileges", args)
        self.assertNotIn("--privileged", args)
        self.assertNotIn("--cap-add", args)
        self.assertIn("sha256:" + "a" * 64, args)
        self.assertNotIn(orchestrate.IMAGE, args)

    def test_docker_inspect_capability_projection_is_exact(self):
        self.assertIsNone(orchestrate.expected_docker_cap_add([]))
        self.assertEqual(
            orchestrate.expected_docker_cap_add(["NET_ADMIN"]),
            ["CAP_NET_ADMIN"],
        )
        self.assertEqual(
            orchestrate.expected_docker_cap_add(
                ["NET_ADMIN", "NET_RAW", "SETUID", "SETGID"]
            ),
            ["CAP_NET_ADMIN", "CAP_NET_RAW", "CAP_SETGID", "CAP_SETUID"],
        )
        with self.assertRaises(orchestrate.LabError):
            orchestrate.expected_docker_cap_add(["NET_ADMIN", "NET_ADMIN"])
        with self.assertRaises(orchestrate.LabError):
            orchestrate.expected_docker_cap_add(["CAP_NET_ADMIN"])

    def test_cleanup_rejects_name_outside_exact_allowlist(self):
        resource = orchestrate.PlannedResource(
            "container", "aster-lab-not-allowlisted", "test"
        )
        with self.assertRaises(orchestrate.LabError):
            orchestrate.validate_cleanup_resource(resource, "0123456789abcdef")

    def test_cleanup_accepts_exact_resource_and_run_id(self):
        resource = orchestrate.PlannedResource(
            "network", orchestrate.DIRECT_NETWORK, "direct"
        )
        orchestrate.validate_cleanup_resource(resource, "0123456789abcdef")

    def test_restrictive_nat_rules_allow_only_wan_infrastructure(self):
        rules = orchestrate.nft_rules(
            profile="restrictive",
            lan_if="eth0",
            wan_if="eth1",
            lan_subnet="10.250.1.0/24",
            node_ip="10.250.1.10",
            external_ip="10.250.0.11",
        )
        self.assertIn("10.250.0.20 udp dport 4476 counter accept", rules)
        self.assertIn("10.250.0.20 tcp dport 4477 counter accept", rules)
        self.assertNotIn("dnat to", rules)

    def test_both_dockerignore_files_are_identical_deny_all_policies(self):
        workspace = MODULE_PATH.parents[1]
        self.assertEqual(
            (workspace / ".dockerignore").read_text(encoding="utf-8"),
            orchestrate.EXPECTED_DOCKERIGNORE,
        )
        self.assertEqual(
            (workspace / "lab" / "Dockerfile.dockerignore").read_text(encoding="utf-8"),
            orchestrate.EXPECTED_DOCKERIGNORE,
        )

    def test_runtime_package_inventory_is_exact_and_canonical(self):
        value = """tcpdump\t4.99.3-1
procps\t2:4.0.2-3
nftables\t1.0.6-2
iputils-ping\t3:20221126-1
iproute2\t6.1.0-3
ca-certificates\t20230311
"""
        self.assertEqual(
            orchestrate.canonical_runtime_package_inventory(value),
            """ca-certificates\t20230311
iproute2\t6.1.0-3
iputils-ping\t3:20221126-1
nftables\t1.0.6-2
procps\t2:4.0.2-3
tcpdump\t4.99.3-1
""",
        )

    def test_runtime_package_inventory_rejects_missing_or_unadmitted_rows(self):
        with self.assertRaises(orchestrate.LabError):
            orchestrate.canonical_runtime_package_inventory(
                "iproute2\t6.1.0-3\niputils-ping\t3:20221126-1\n"
            )
        with self.assertRaises(orchestrate.LabError):
            orchestrate.canonical_runtime_package_inventory(
                """ca-certificates\t20230311
iproute2\t6.1.0-3
iputils-ping\t3:20221126-1
nftables\t1.0.6-2
procps\t2:4.0.2-3
tcpdump\t4.99.3-1
curl\t8.0
"""
            )

    def test_public_provision_manifest_parser_never_requires_secret_paths(self):
        manifest = """ASTER_LAB_NODE_MANIFEST\tversion=1\ttopic=lab.live-ip\tscope=lab/live-ip\tnodes=2
index\tserial\tnode_id
0\t1\taaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
1\t2\tbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb
"""
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "manifest.tsv"
            path.write_text(manifest, encoding="utf-8")
            records = orchestrate.parse_provision_manifest(path, 2)
        self.assertEqual(records[0]["identity"], "a" * 64)
        self.assertNotIn("credential", records[0])

    def test_reopened_runner_continues_command_sequence(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "commands.jsonl").write_text(
                '{"sequence":1}\n{"sequence":7}\n', encoding="utf-8"
            )
            (root / "command-0009.stdout").write_text("orphan", encoding="utf-8")
            runner = orchestrate.CommandRunner(root)
        self.assertEqual(runner.sequence, 9)

    def test_role_mounts_never_expose_run_root_or_peer_bundle(self):
        self.assertEqual(
            orchestrate.selected_nat_state_container_path("node-a"),
            "/output/node-a",
        )
        with self.assertRaises(orchestrate.LabError):
            orchestrate.selected_nat_state_container_path("node-c")
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            context = self.context(root)
            node_output = orchestrate.create_output_directory(context, "node-a")
            private = root / "outputs" / "provision" / "private"
            private.mkdir(parents=True, mode=0o700)
            own_bundle = private / "node-0000.bundle"
            peer_bundle = private / "node-0001.bundle"
            own_bundle.write_bytes(b"own")
            peer_bundle.write_bytes(b"peer")
            own_bundle.chmod(0o600)
            peer_bundle.chmod(0o600)
            arguments = orchestrate.container_run_args(
                context,
                name="aster-lab-node-a",
                role="node-a",
                command=["node-udp", "--root", "/output/node-a"],
                output_dir=node_output,
                output_destination="/output/node-a",
                retained_secret_mounts=[(own_bundle, "/run/secrets/node.bundle")],
            )
        mounts = [
            arguments[index + 1]
            for index, value in enumerate(arguments[:-1])
            if value == "--mount"
        ]
        self.assertEqual(len(mounts), 2)
        self.assertIn(f"src={node_output.resolve()},dst=/output/node-a", mounts[0])
        self.assertEqual(
            mounts[1],
            f"type=bind,src={own_bundle.resolve()},dst=/run/secrets/node.bundle",
        )
        self.assertNotIn(str(peer_bundle.resolve()), "\n".join(mounts))
        self.assertNotIn(f"src={root.resolve()},", "\n".join(mounts))

    def test_retained_secret_mount_rejects_unsafe_source_and_duplicate_destination(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            run = root / "run"
            run.mkdir()
            context = self.context(run)
            source = run / "outputs" / "provision" / "private" / "node.bundle"
            source.parent.mkdir(parents=True, mode=0o700)
            source.write_bytes(b"mission")
            source.chmod(0o644)
            with self.assertRaises(orchestrate.LabError):
                orchestrate.container_run_args(
                    context,
                    name="aster-lab-node-a",
                    role="node-a",
                    command=["infinity"],
                    retained_secret_mounts=[
                        (source, "/run/secrets/node.bundle")
                    ],
                )
            outside = root / "outside.bundle"
            outside.write_bytes(b"outside")
            outside.chmod(0o600)
            with self.assertRaises(orchestrate.LabError):
                orchestrate.container_run_args(
                    context,
                    name="aster-lab-node-a",
                    role="node-a",
                    command=["infinity"],
                    retained_secret_mounts=[
                        (outside, "/run/secrets/node.bundle")
                    ],
                )
            source.chmod(0o600)
            witness = orchestrate.retained_secret_mount_witness(source)
            source.write_bytes(b"changed-longer")
            self.assertNotEqual(
                orchestrate.retained_secret_mount_witness(source), witness
            )
            alias = source.with_name("node-alias.bundle")
            os.link(source, alias)
            with self.assertRaises(orchestrate.LabError):
                orchestrate.validate_retained_secret_mount_source(source)
            alias.unlink()
            with self.assertRaises(orchestrate.LabError):
                orchestrate.container_run_args(
                    context,
                    name="aster-lab-node-a",
                    role="node-a",
                    command=["infinity"],
                    read_only_mounts=[(source, "/run/secrets/node.bundle")],
                    retained_secret_mounts=[
                        (source, "/run/secrets/node.bundle")
                    ],
                )

    def test_mount_confinement_rejects_run_root_and_outside(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            context = self.context(root)
            with self.assertRaises(orchestrate.LabError):
                orchestrate.confined_run_path(context, root)
            with self.assertRaises(orchestrate.LabError):
                orchestrate.confined_run_path(context, root.parent / "outside")

    def test_container_requires_preflight_immutable_image(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            context = self.context(root)
            context.image_id = None
            with self.assertRaises(orchestrate.LabError):
                orchestrate.container_run_args(
                    context,
                    name="aster-lab-transfer",
                    role="transfer",
                    command=["transfer", "--root", "/output/run"],
                )

    def test_container_configuration_binds_privilege_and_exact_network_attachment(self):
        for mutation in (
            "none",
            "privileged",
            "disabled-nnp",
            "extra-security-option",
            "executable-tmpfs",
            "host-device",
            "host-pid",
            "extra-env",
            "extra-network",
            "duplicate-cap-drop",
            "canonical-cap-add",
            "unprefixed-cap-add",
            "reordered-cap-add",
            "duplicate-cap-add",
            "missing-cap-add",
            "extra-cap-add",
            "empty-cap-add",
            "unexpected-cap-add",
            "absent-cap-add",
            "read-only-retained-secret",
            "wrong-state-destination",
            "duplicate-mount-destination",
            "non-bind-mount",
        ):
            with self.subTest(mutation=mutation), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                output = root / "outputs" / "node-a"
                output.mkdir(parents=True)
                bundle = root / "outputs" / "provision" / "private" / "node-a.bundle"
                bundle.parent.mkdir(parents=True, mode=0o700)
                bundle.write_bytes(b"mission")
                bundle.chmod(0o600)
                context = self.context(root)
                context.image = orchestrate.SELECTED_NAT_IMAGE
                context.image_environment = list(
                    orchestrate.SELECTED_NAT_IMAGE_ENVIRONMENT
                )
                selected_input_digest = orchestrate.build_input_digest(
                    orchestrate.collect_selected_nat_build_inputs()
                )
                capability_cases = {
                    "canonical-cap-add",
                    "unprefixed-cap-add",
                    "reordered-cap-add",
                    "duplicate-cap-add",
                    "missing-cap-add",
                    "extra-cap-add",
                }
                requested_capabilities = (
                    ["NET_ADMIN", "NET_RAW", "SETUID", "SETGID"]
                    if mutation in capability_cases
                    else []
                )
                value = {
                    "Image": context.image_id,
                    "HostConfig": {
                        "Privileged": mutation == "privileged",
                        "Init": True,
                        "ReadonlyRootfs": True,
                        "Memory": 1024 * 1024 * 1024,
                        "MemorySwap": 1024 * 1024 * 1024,
                        "PidsLimit": 256,
                        "NanoCpus": 1_000_000_000,
                        "CgroupnsMode": "private",
                        "NetworkMode": "aster-lab-lan-a",
                        "CapDrop": ["ALL"],
                        "CapAdd": orchestrate.expected_docker_cap_add(
                            requested_capabilities
                        ),
                        "SecurityOpt": ["no-new-privileges:true"],
                        "Devices": [],
                        "DeviceRequests": None,
                        "DeviceCgroupRules": None,
                        "PidMode": "",
                        "IpcMode": "private",
                        "UTSMode": "",
                        "UsernsMode": "",
                        "PortBindings": {},
                        "PublishAllPorts": False,
                        "AutoRemove": False,
                        "RestartPolicy": {"Name": "no", "MaximumRetryCount": 0},
                        "Links": None,
                        "VolumesFrom": None,
                        "Ulimits": [
                            {"Name": "nofile", "Hard": 65_536, "Soft": 65_536}
                        ],
                        "Tmpfs": {
                            "/tmp": "rw,noexec,nosuid,nodev,size=32m",
                            "/run": "rw,noexec,nosuid,nodev,size=8m",
                        },
                        "Sysctls": {},
                        "ExtraHosts": [],
                    },
                    "Config": {
                        "User": f"{os.getuid()}:{os.getgid()}",
                        "Entrypoint": ["/usr/bin/sleep"],
                        "Env": list(context.image_environment),
                        "ExposedPorts": None,
                        "Volumes": None,
                        "Labels": {
                            **orchestrate.PINNED_BASE_IMAGE_LABELS,
                            orchestrate.MANAGED_LABEL: "true",
                            orchestrate.RUN_LABEL: context.run_id,
                            orchestrate.ROLE_LABEL: "node-a",
                            orchestrate.IMAGE_SCHEMA_LABEL: orchestrate.SELECTED_NAT_IMAGE_SCHEMA,
                            orchestrate.IMAGE_INPUT_LABEL: selected_input_digest,
                            orchestrate.IMAGE_BASE_LABEL: orchestrate.LAB_BASE_IMAGE,
                        },
                    },
                    "Mounts": [
                        {
                            "Type": "bind",
                            "Source": str(output.resolve()),
                            "Destination": "/output/node-a",
                            "RW": True,
                        },
                        {
                            "Type": "bind",
                            "Source": str(bundle.resolve()),
                            "Destination": "/run/secrets/node.bundle",
                            "RW": True,
                        },
                    ],
                    "NetworkSettings": {
                        "Networks": {
                            "aster-lab-lan-a": {"IPAddress": "10.250.1.10"}
                        }
                    },
                }
                if mutation == "extra-network":
                    value["NetworkSettings"]["Networks"]["bridge"] = {
                        "IPAddress": "172.17.0.2"
                    }
                elif mutation == "disabled-nnp":
                    value["HostConfig"]["SecurityOpt"] = [
                        "no-new-privileges:false"
                    ]
                elif mutation == "extra-security-option":
                    value["HostConfig"]["SecurityOpt"].append(
                        "seccomp=unconfined"
                    )
                elif mutation == "executable-tmpfs":
                    value["HostConfig"]["Tmpfs"]["/tmp"] = (
                        "rw,nosuid,nodev,size=32m"
                    )
                elif mutation == "host-device":
                    value["HostConfig"]["Devices"] = [
                        {
                            "PathOnHost": "/dev/null",
                            "PathInContainer": "/dev/escape",
                            "CgroupPermissions": "rwm",
                        }
                    ]
                elif mutation == "host-pid":
                    value["HostConfig"]["PidMode"] = "host"
                elif mutation == "extra-env":
                    value["Config"]["Env"].append("CANARY=" + "ab" * 32)
                elif mutation == "duplicate-cap-drop":
                    value["HostConfig"]["CapDrop"].append("ALL")
                elif mutation == "unprefixed-cap-add":
                    value["HostConfig"]["CapAdd"] = list(requested_capabilities)
                elif mutation == "reordered-cap-add":
                    value["HostConfig"]["CapAdd"].reverse()
                elif mutation == "duplicate-cap-add":
                    value["HostConfig"]["CapAdd"].append("CAP_NET_ADMIN")
                elif mutation == "missing-cap-add":
                    value["HostConfig"]["CapAdd"].pop()
                elif mutation == "extra-cap-add":
                    value["HostConfig"]["CapAdd"].append("CAP_SYS_ADMIN")
                elif mutation == "empty-cap-add":
                    value["HostConfig"]["CapAdd"] = []
                elif mutation == "unexpected-cap-add":
                    value["HostConfig"]["CapAdd"] = ["CAP_NET_ADMIN"]
                elif mutation == "absent-cap-add":
                    value["HostConfig"].pop("CapAdd")
                elif mutation == "read-only-retained-secret":
                    value["Mounts"][1]["RW"] = False
                elif mutation == "wrong-state-destination":
                    value["Mounts"][0]["Destination"] = "/output"
                elif mutation == "duplicate-mount-destination":
                    value["Mounts"].append(dict(value["Mounts"][1]))
                elif mutation == "non-bind-mount":
                    value["Mounts"][1]["Type"] = "volume"
                result = subprocess.CompletedProcess(
                    ["docker"], 0, stdout=json.dumps(value), stderr=""
                )
                with mock.patch.object(
                    orchestrate, "require_docker", return_value="docker"
                ), mock.patch.object(context.runner, "run", return_value=result):
                    invoke = lambda: orchestrate.verify_container_configuration(
                        context,
                        "aster-lab-node-a",
                        output_dir=output,
                        output_destination="/output/node-a",
                        memory="1g",
                        cpus="1",
                        pids=256,
                        network="aster-lab-lan-a",
                        capabilities=requested_capabilities,
                        retained_secret_mounts=[
                            (bundle, "/run/secrets/node.bundle")
                        ],
                        network_addresses={"aster-lab-lan-a": "10.250.1.10"},
                        entrypoint="/usr/bin/sleep",
                    )
                    if mutation in {"none", "canonical-cap-add"}:
                        invoke()
                    else:
                        with self.assertRaises(orchestrate.LabError):
                            invoke()

    def test_timeout_preserves_partial_streams_and_sequence(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            runner = orchestrate.CommandRunner(root)
            timeout = subprocess.TimeoutExpired(
                cmd=["program"], timeout=1, output="partial-out", stderr="partial-err"
            )
            with mock.patch.object(orchestrate.subprocess, "run", side_effect=timeout):
                with self.assertRaises(orchestrate.LabError):
                    runner.run(["program"], timeout=1)
            self.assertEqual((root / "command-0001.stdout").read_text(), "partial-out")
            self.assertEqual((root / "command-0001.stderr").read_text(), "partial-err")
            self.assertEqual((root / "command-0001.stdout").stat().st_mode & 0o777, 0o600)
            self.assertEqual((root / "command-0001.stderr").stat().st_mode & 0o777, 0o600)
            receipt = json.loads((root / "commands.jsonl").read_text().strip())
            self.assertTrue(receipt["timed_out"])
            self.assertEqual(receipt["sequence"], 1)

    def test_async_command_records_ordered_start_and_completion(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            runner = orchestrate.CommandRunner(root)
            process = mock.Mock()
            process.poll.return_value = 0
            process.wait.return_value = 0
            process.returncode = 0
            with mock.patch.object(orchestrate.subprocess, "Popen", return_value=process):
                running = runner.start(["docker", "exec", "aster-lab-resource", "workload"])
                self.assertEqual(
                    (root / "command-0001.stdout").stat().st_mode & 0o777, 0o600
                )
                self.assertEqual(
                    (root / "command-0001.stderr").stat().st_mode & 0o777, 0o600
                )
                self.assertEqual(running.finish(), 0)
            receipts = [
                json.loads(line)
                for line in (root / "commands.jsonl").read_text().splitlines()
            ]
        self.assertEqual([item["phase"] for item in receipts], ["started", "completed"])
        self.assertEqual({item["sequence"] for item in receipts}, {1})

    def test_command_runner_error_streams_are_owner_only(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            runner = orchestrate.CommandRunner(root)
            with mock.patch.object(
                orchestrate.subprocess, "run", side_effect=OSError("synthetic")
            ):
                with self.assertRaises(orchestrate.LabError):
                    runner.run(["program"])
            for suffix in ("stdout", "stderr"):
                path = root / f"command-0001.{suffix}"
                self.assertEqual(path.stat().st_mode & 0o777, 0o600)
                self.assertEqual(path.read_bytes(), b"")

    def test_terminal_resource_sample_does_not_require_process_rss(self):
        sample = {
            "memory.current": "1",
            "memory.max": str(64 * 1024 * 1024),
            "memory.peak": "2",
            "memory.events": "low 0\nhigh 0\nmax 0\noom 0\noom_kill 0",
            "memory.stat": "anon 1",
            "memory.swap.current": "0",
            "memory.swap.max": "0",
            "cpu.stat": "usage_usec 1",
            "cpu.pressure_available": True,
            "cpu.pressure": "some avg10=0.00 avg60=0.00 avg300=0.00 total=0",
            "io.stat": "8:0 rbytes=1 wbytes=2",
            "pids.current": "1",
            "pids.events": "max 0",
            "docker_stats": {"MemUsage": "1MiB / 64MiB"},
        }
        orchestrate.validate_resource_sample(
            sample, 64 * 1024 * 1024, require_process=False
        )

    def test_metrics_cross_check_is_type_strict(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            metrics_root = root / "outputs" / "scale" / "run"
            metrics_root.mkdir(parents=True)
            (metrics_root / "metrics.json").write_text(
                json.dumps(
                    {
                        "schema": "aster-lab-metrics/v1",
                        "converged": True,
                        "nodes": True,
                    }
                ),
                encoding="utf-8",
            )
            with self.assertRaises(orchestrate.LabError):
                orchestrate.scenario_metrics(
                    self.context(root), "outputs/scale/run", {"nodes": 1}
                )

    def test_resource_sample_rejects_oom_and_accepts_complete_values(self):
        sample = {
            "memory.current": "1",
            "memory.max": str(64 * 1024 * 1024),
            "memory.peak": "2",
            "memory.events": "low 0\nhigh 0\nmax 0\noom 0\noom_kill 0",
            "memory.stat": "anon 1",
            "memory.swap.current": "0",
            "memory.swap.max": "0",
            "cpu.stat": "usage_usec 1",
            "cpu.pressure_available": True,
            "cpu.pressure": "some avg10=0.00 avg60=0.00 avg300=0.00 total=0",
            "io.stat": "8:0 rbytes=1 wbytes=2 rios=1 wios=1",
            "pids.current": "1",
            "pids.events": "max 0",
            "smaps_rollup": "Rss: 1 kB",
            "status": "Name:\taster-lab",
            "docker_stats": {"MemUsage": "1MiB / 64MiB"},
        }
        orchestrate.validate_resource_sample(sample, 64 * 1024 * 1024)
        sample["memory.events"] = "oom 1\noom_kill 0"
        with self.assertRaises(orchestrate.LabError):
            orchestrate.validate_resource_sample(sample, 64 * 1024 * 1024)

    def test_resource_sample_accepts_explicitly_unavailable_cpu_pressure(self):
        sample = {
            "memory.current": "1",
            "memory.max": str(64 * 1024 * 1024),
            "memory.peak": "2",
            "memory.events": "low 0\nhigh 0\nmax 0\noom 0\noom_kill 0",
            "memory.stat": "anon 1",
            "memory.swap.current": "0",
            "memory.swap.max": "0",
            "cpu.stat": "usage_usec 1",
            "cpu.pressure_available": False,
            "cpu.pressure": None,
            "io.stat": "8:0 rbytes=1 wbytes=2 rios=1 wios=1",
            "pids.current": "1",
            "pids.events": "max 0",
            "smaps_rollup": "Rss: 1 kB",
            "status": "Name:\taster-lab",
            "docker_stats": {"MemUsage": "1MiB / 64MiB"},
        }
        orchestrate.validate_resource_sample(sample, 64 * 1024 * 1024)

    def test_resource_sample_rejects_empty_io_stat(self):
        with self.assertRaises(orchestrate.LabError):
            orchestrate.parse_io_stat("")

    def test_qdisc_validation_binds_requested_netem_parameters(self):
        value = json.dumps(
            [
                {
                    "kind": "netem",
                    "options": {
                        "limit": 64,
                        "rate": 375,
                        "seed": 424242,
                        "loss-random": {"probability": 0.5},
                    },
                }
            ]
        )
        orchestrate.verify_qdisc_json(
            value,
            expected_bps=3000,
            expected_loss_percent=50,
            expected_limit=64,
            expected_seed=424242,
        )
        with self.assertRaises(orchestrate.LabError):
            orchestrate.verify_qdisc_json(
                value,
                expected_bps=4000,
                expected_loss_percent=50,
                expected_limit=64,
                expected_seed=424242,
            )
        unseeded = json.dumps(
            [
                {
                    "kind": "netem",
                    "options": {
                        "limit": 64,
                        "rate": 375,
                        "loss-random": {"probability": 0.5},
                    },
                }
            ]
        )
        orchestrate.verify_qdisc_json(
            unseeded,
            expected_bps=3000,
            expected_loss_percent=50,
            expected_limit=64,
            expected_seed=None,
        )
        self.assertEqual(orchestrate.tc_rate_bits(375), 3000)

    def test_build_input_receipt_includes_deny_all_policy(self):
        inputs = orchestrate.collect_build_inputs()
        paths = {item.relative_path for item in inputs}
        self.assertIn(".dockerignore", paths)
        self.assertIn("LICENSE", paths)
        self.assertIn("THIRD_PARTY_NOTICES.md", paths)
        self.assertIn("lab/Dockerfile", paths)
        self.assertRegex(orchestrate.build_input_digest(inputs), r"^[0-9a-f]{64}$")

    def test_build_boundary_seals_only_hashed_bytes(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            context = self.context(root)
            sealed, digest = orchestrate.verify_build_boundary(context)
            receipt = json.loads((root / "build-inputs.json").read_text())
            sealed_paths = {
                str(path.relative_to(sealed))
                for path in sealed.rglob("*")
                if path.is_file()
            }
        self.assertEqual(sealed_paths, {item["path"] for item in receipt["files"]})
        self.assertEqual(receipt["aggregate_sha256"], digest)
        self.assertNotIn("lab/orchestrate.py", sealed_paths)
        self.assertNotIn(".git", {path.split("/", 1)[0] for path in sealed_paths})

    def test_pcap_validation_requires_a_complete_known_header(self):
        with tempfile.TemporaryDirectory() as temporary:
            valid = Path(temporary) / "capture.pcap"
            valid.write_bytes(bytes.fromhex("d4c3b2a1") + b"\x00" * 20)
            self.assertEqual(orchestrate.validate_pcap(valid), 24)
            invalid = Path(temporary) / "invalid.pcap"
            invalid.write_bytes(b"not-a-pcap" + b"\x00" * 20)
            with self.assertRaises(orchestrate.LabError):
                orchestrate.validate_pcap(invalid)

    def test_cleanup_presence_probe_failure_is_not_absence(self):
        with tempfile.TemporaryDirectory() as temporary:
            context = self.context(Path(temporary))
            context.runner = mock.Mock()
            context.runner.run.side_effect = orchestrate.LabError("daemon unavailable")
            with mock.patch.object(orchestrate, "require_docker", return_value="docker"):
                with self.assertRaises(orchestrate.LabError):
                    orchestrate.docker_resource_present(
                        context, "container", "aster-lab-node-a"
                    )

    def test_normal_nat_cleanup_refuses_missing_runtime_receipt(self):
        with tempfile.TemporaryDirectory() as temporary:
            context = self.context(Path(temporary))
            context.label = "nat"
            context.resources = [
                orchestrate.PlannedResource(
                    "container", orchestrate.FIXED_CONTAINER_NAMES["nat-a"], "nat-a"
                )
            ]
            with mock.patch.object(orchestrate, "verify_orbstack", return_value=("docker", {})):
                with self.assertRaisesRegex(
                    orchestrate.LabError, "resources were retained"
                ):
                    orchestrate.cleanup_context(context, tolerate_errors=False)

    def test_image_resolution_requires_provenance_and_sets_digest(self):
        with tempfile.TemporaryDirectory() as temporary:
            context = self.context(Path(temporary))
            context.image_id = None
            context.daemon_architecture = "arm64"
            digest = orchestrate.build_input_digest(orchestrate.collect_build_inputs())
            identity = "sha256:" + "b" * 64
            record = {
                "id": identity,
                "repo_digests": [],
                "architecture": "arm64",
                "env": [],
                "labels": {
                    **orchestrate.PINNED_BASE_IMAGE_LABELS,
                    orchestrate.MANAGED_LABEL: "true",
                    orchestrate.RUN_LABEL: "fedcba9876543210",
                    orchestrate.IMAGE_SCHEMA_LABEL: orchestrate.IMAGE_SCHEMA,
                    orchestrate.IMAGE_INPUT_LABEL: digest,
                    orchestrate.IMAGE_BASE_LABEL: orchestrate.LAB_BASE_IMAGE,
                },
            }
            context.runner = mock.Mock()
            context.runner.run.return_value = subprocess.CompletedProcess(
                ["docker"], 0, json.dumps(record), ""
            )
            with mock.patch.object(orchestrate, "require_docker", return_value="docker"):
                observed = orchestrate.resolve_lab_image(context)
        self.assertEqual(observed, identity)
        self.assertEqual(context.image_id, identity)

    def test_selected_image_resolution_binds_base_label_local_digest_and_build_run(self):
        identity = "sha256:" + "c" * 64
        digest = orchestrate.build_input_digest(
            orchestrate.collect_selected_nat_build_inputs()
        )
        record = {
            "id": identity,
            "repo_digests": [
                f"{orchestrate.SELECTED_NAT_LOCAL_REPOSITORY}@{identity}"
            ],
            "architecture": "arm64",
            "env": list(orchestrate.SELECTED_NAT_IMAGE_ENVIRONMENT),
            "labels": {
                **orchestrate.PINNED_BASE_IMAGE_LABELS,
                orchestrate.MANAGED_LABEL: "true",
                orchestrate.RUN_LABEL: "0123456789abcdef",
                orchestrate.IMAGE_SCHEMA_LABEL: orchestrate.SELECTED_NAT_IMAGE_SCHEMA,
                orchestrate.IMAGE_INPUT_LABEL: digest,
                orchestrate.IMAGE_BASE_LABEL: orchestrate.LAB_BASE_IMAGE,
            },
        }

        def resolve(value):
            with tempfile.TemporaryDirectory() as temporary:
                context = self.context(Path(temporary))
                context.daemon_architecture = "arm64"
                context.runner = mock.Mock()
                context.runner.run.return_value = subprocess.CompletedProcess(
                    ["docker"], 0, json.dumps(value), ""
                )
                with mock.patch.object(
                    orchestrate, "require_docker", return_value="docker"
                ):
                    return orchestrate.resolve_selected_nat_image(
                        context, expected_build_run_id=context.run_id
                    )

        self.assertEqual(resolve(record), identity)
        missing_base_label = json.loads(json.dumps(record))
        missing_base_label["labels"].pop(orchestrate.BASE_IMAGE_SOURCE_LABEL)
        with self.assertRaisesRegex(orchestrate.LabError, "provenance label"):
            resolve(missing_base_label)
        foreign_digest = json.loads(json.dumps(record))
        foreign_digest["repo_digests"] = ["foreign@sha256:" + "d" * 64]
        with self.assertRaisesRegex(orchestrate.LabError, "repository digest"):
            resolve(foreign_digest)
        wrong_build_run = json.loads(json.dumps(record))
        wrong_build_run["labels"][orchestrate.RUN_LABEL] = "fedcba9876543210"
        with self.assertRaisesRegex(orchestrate.LabError, "build run identifier"):
            resolve(wrong_build_run)

    def test_existing_nat_finalization_binds_all_terminal_receipts(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            context = self.context(root)
            qdisc = json.dumps(
                [
                    {
                        "kind": "netem",
                        "options": {
                            "limit": 64,
                            "rate": 375,
                            "seed": 424242,
                            "loss": {"probability": 0.5},
                        },
                    }
                ]
            )
            nft = json.dumps({"nftables": []})
            infra = "ASTER_LAB_INFRA_READY\tversion=1\n"
            terminal = {}
            for role in ["nat-a", "nat-b"]:
                qdisc_name = f"{role}-qdisc-final-command-0001.json"
                nft_name = f"{role}-nft-final-command-0002.json"
                (root / qdisc_name).write_text(qdisc, encoding="utf-8")
                (root / nft_name).write_text(nft, encoding="utf-8")
                capture = root / "outputs" / role / f"{role}-wan.pcap"
                capture.parent.mkdir(parents=True)
                capture.write_bytes(bytes.fromhex("d4c3b2a1") + b"\x00" * 20)
                terminal[role] = {
                    "role": role,
                    "qdisc_receipt": qdisc_name,
                    "qdisc_receipt_sha256": orchestrate.sha256_file(root / qdisc_name),
                    "nft_receipt": nft_name,
                    "nft_receipt_sha256": orchestrate.sha256_file(root / nft_name),
                    "capture": f"outputs/{role}/{role}-wan.pcap",
                    "capture_bytes": 24,
                    "capture_sha256": orchestrate.sha256_file(capture),
                }
            infra_name = "nat-infra-final-command-0003.log"
            (root / infra_name).write_text(infra, encoding="utf-8")
            runtime = {
                "schema": orchestrate.SCHEMA,
                "profile": "restrictive",
                "shape_bps": 3000,
                "loss_percent": 50,
                "netem_limit": 64,
                "netem_seed_requested": 424242,
                "netem_seed_status": "applied",
                "netem_seed": 424242,
                "infra": orchestrate.FIXED_CONTAINER_NAMES["infra"],
                "routers": [{"role": "nat-a"}, {"role": "nat-b"}],
            }
            final = {
                "schema": orchestrate.SCHEMA,
                "run_id": context.run_id,
                "infra_log_receipt": infra_name,
                "infra_log_receipt_sha256": orchestrate.sha256_file(root / infra_name),
                "routers": [terminal["nat-a"], terminal["nat-b"]],
            }
            (root / "nat-runtime.json").write_text(json.dumps(runtime), encoding="utf-8")
            (root / "nat-finalization.json").write_text(json.dumps(final), encoding="utf-8")
            orchestrate.finalize_nat(context)
            (root / terminal["nat-a"]["nft_receipt"]).write_text(
                '{"nftables":["changed"]}', encoding="utf-8"
            )
            with self.assertRaises(orchestrate.LabError):
                orchestrate.finalize_nat(context)

    def test_selected_nat_parser_profiles_and_external_default_root(self):
        for profile in ["cone-direct", "restrictive-relay", "all"]:
            parsed = orchestrate.parser().parse_args(
                ["selected-iroh-nat-run", "--profile", profile]
            )
            self.assertEqual(parsed.profile, profile)
            self.assertEqual(
                parsed.duration_seconds,
                orchestrate.SELECTED_NAT_RUN_FOR_SECONDS,
            )
            self.assertEqual(
                parsed.evidence_root, orchestrate.DEFAULT_SELECTED_NAT_EVIDENCE_ROOT
            )
            self.assertFalse(parsed.execute)
        for duration in ["29", "31"]:
            with self.subTest(duration=duration), contextlib.redirect_stderr(
                io.StringIO()
            ), self.assertRaises(SystemExit):
                orchestrate.parser().parse_args(
                    ["selected-iroh-nat-run", "--duration-seconds", duration]
                )
        workspace = orchestrate.WORKSPACE.resolve()
        selected_root = orchestrate.DEFAULT_SELECTED_NAT_EVIDENCE_ROOT.resolve()
        self.assertNotEqual(selected_root, workspace)
        self.assertNotIn(workspace, selected_root.parents)

    def test_selected_nat_node_argv_and_cadence_are_exact(self):
        carrier = "a" * 64
        mission = "b" * 64
        arguments = orchestrate.selected_nat_node_arguments(
            docker="/usr/bin/docker",
            user="502:20",
            role="node-a",
            profile="cone-direct",
            node_address="10.250.1.10",
            peer_external_address="10.250.0.12",
            peer_carrier_id=carrier,
            peer_mission_id=mission,
        )
        self.assertEqual(
            arguments,
            [
                "/usr/bin/docker",
                "exec",
                "--user",
                "502:20",
                "aster-lab-node-a",
                "/usr/local/bin/aster",
                "node",
                "--state",
                "/output/node-a",
                "--bind",
                "10.250.1.10:44000",
                "--mission-bundle-unprotected-reference",
                "/run/secrets/node.bundle",
                "--peer",
                f"{carrier}@10.250.0.12:44000={mission}",
                "--sync-ms",
                "15001",
                "--run-for",
                "30",
                "--application",
                "relay",
            ],
        )
        restrictive = orchestrate.selected_nat_node_arguments(
            docker="/usr/bin/docker",
            user="502:20",
            role="node-a",
            profile="restrictive-relay",
            node_address="10.250.1.10",
            peer_external_address="10.250.0.12",
            peer_carrier_id=carrier,
            peer_mission_id=mission,
        )
        self.assertEqual(
            restrictive,
            arguments
            + [
                "--controlled-relay-url",
                "https://relay.aster.test:8443/",
                "--controlled-relay-trust",
                "der-roots",
                "--controlled-relay-ca-der",
                "/run/relay/ca.der",
            ],
        )
        run_for_ms = orchestrate.SELECTED_NAT_RUN_FOR_SECONDS * 1_000
        self.assertEqual(
            orchestrate.SELECTED_NAT_SYNC_MS,
            run_for_ms // 2 + 1,
        )
        self.assertEqual(run_for_ms // orchestrate.SELECTED_NAT_SYNC_MS, 1)
        self.assertEqual(run_for_ms % orchestrate.SELECTED_NAT_SYNC_MS, 14_999)

    def test_selected_nat_capture_program_is_exact_and_immediate(self):
        base = [
            "/usr/bin/tcpdump",
            "--immediate-mode",
            "-Z",
            "tcpdump",
            "-i",
            "eth1",
            "-s",
            "0",
            "-U",
            "-w",
            "/output/nat-a-wan.pcap",
        ]
        cone = orchestrate.selected_nat_capture_program(
            wan_interface="eth1",
            capture_path="/output/nat-a-wan.pcap",
            profile="cone-direct",
        )
        self.assertEqual(cone, base + ["udp", "port", "44000"])
        restrictive = orchestrate.selected_nat_capture_program(
            wan_interface="eth1",
            capture_path="/output/nat-a-wan.pcap",
            profile="restrictive-relay",
        )
        self.assertEqual(
            restrictive,
            base
            + [
                "(",
                "udp",
                "port",
                "44000",
                ")",
                "or",
                "(",
                "tcp",
                "port",
                "8443",
                ")",
                "or",
                "(",
                "tcp",
                "port",
                "8080",
                ")",
            ],
        )
        with self.assertRaises(orchestrate.LabError):
            orchestrate.selected_nat_capture_program(
                wan_interface="eth1",
                capture_path="/output/nat-a-wan.pcap",
                profile="unknown",
            )

    def test_legacy_nat_parser_and_dry_run_remain_exactly_available(self):
        parsed = orchestrate.parser().parse_args(
            ["nat-up", "--profile", "restrictive"]
        )
        self.assertEqual(parsed.profile, "restrictive")
        self.assertFalse(parsed.execute)
        output = io.StringIO()
        with mock.patch.object(
            orchestrate.RunContext,
            "create",
            side_effect=AssertionError("legacy dry run created state"),
        ), contextlib.redirect_stdout(output):
            orchestrate.run_nat_up(parsed)
        plan = json.loads(output.getvalue())
        self.assertEqual(plan["label"], "nat")
        self.assertEqual(len(plan["resources"]), 8)
        self.assertTrue(
            any("five exact-name containers" in command for command in plan["commands"])
        )

    def test_selected_nat_dry_run_is_mutation_free(self):
        args = orchestrate.parser().parse_args(
            ["selected-iroh-nat-run", "--profile", "all"]
        )
        output = io.StringIO()
        with mock.patch.object(
            orchestrate.RunContext,
            "create",
            side_effect=AssertionError("dry run created state"),
        ), contextlib.redirect_stdout(output):
            orchestrate.run_selected_iroh_nat(args)
        plan = json.loads(output.getvalue())
        self.assertEqual(plan["label"], "selected-iroh-nat")
        self.assertEqual(plan["image"], orchestrate.SELECTED_NAT_IMAGE)
        self.assertEqual(plan["commands"]["profiles"], ["cone-direct", "restrictive-relay"])
        self.assertIn("--network=default", plan["commands"]["build"])

    def test_selected_nat_build_argv_is_exact_and_honest(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            context = self.context(root)
            sealed = root / "build-context"
            arguments = orchestrate.selected_nat_build_arguments(
                context, sealed, "b" * 64
            )
        self.assertEqual(
            arguments[:7],
            [
                "docker",
                "build",
                "--pull=false",
                "--network=default",
                "--no-cache",
                "--load",
                "--progress=plain",
            ],
        )
        self.assertIn(str(sealed / "lab" / "Dockerfile.selected-nat"), arguments)
        self.assertEqual(arguments[-1], str(sealed))
        self.assertEqual(arguments.count("--label"), 5)
        self.assertNotIn("--network=none", arguments)
        self.assertNotIn("--cache-from", arguments)

    def test_selected_build_inputs_include_exact_vendored_patch_and_dockerfiles(self):
        legacy = {item.relative_path for item in orchestrate.collect_build_inputs()}
        selected = {
            item.relative_path for item in orchestrate.collect_selected_nat_build_inputs()
        }
        self.assertIn("lab/Dockerfile", legacy)
        self.assertNotIn("lab/Dockerfile.selected-nat", legacy)
        self.assertIn("lab/Dockerfile.selected-nat", selected)
        self.assertTrue(
            any(
                path.startswith("third-party/netlink-packet-core-0.8.2-aster/")
                for path in legacy
            )
        )
        self.assertIn(
            "COPY third-party ./third-party",
            (orchestrate.WORKSPACE / "lab" / "Dockerfile").read_text(encoding="utf-8"),
        )

    def test_selected_nat_tracked_input_gate_rejects_ignored_untracked_input(self):
        with tempfile.TemporaryDirectory() as temporary:
            context = self.context(Path(temporary))
            context.runner = mock.Mock()
            context.runner.run.return_value = subprocess.CompletedProcess(
                [], 0, "crates/tracked.rs\0", ""
            )
            inputs = [
                orchestrate.BuildInput("crates/tracked.rs", b"tracked", "1" * 64),
                orchestrate.BuildInput(
                    "crates/ignored-generated.rs", b"ignored", "2" * 64
                ),
            ]
            with self.assertRaisesRegex(orchestrate.LabError, "untracked admitted"):
                orchestrate.validate_selected_nat_tracked_inputs(
                    context, "/usr/bin/git", inputs
                )

            context.runner.run.return_value = subprocess.CompletedProcess(
                [], 0, "crates/tracked.rs\0crates/ignored-generated.rs\0", ""
            )
            orchestrate.validate_selected_nat_tracked_inputs(
                context, "/usr/bin/git", inputs
            )

    def test_selected_nat_commit_input_gate_rejects_post_status_byte_mutation(self):
        with tempfile.TemporaryDirectory() as temporary:
            context = self.context(Path(temporary))
            committed = b"committed bytes"
            mutated = b"post-status mutation"
            context.runner = mock.Mock()
            context.runner.run.return_value = subprocess.CompletedProcess(
                [],
                0,
                (
                    "100644 blob "
                    f"{orchestrate.git_sha1_blob(committed)}\tCargo.toml\0"
                ),
                "",
            )
            with self.assertRaisesRegex(orchestrate.LabError, "bytes differ from commit"):
                orchestrate.validate_selected_nat_commit_inputs(
                    context,
                    "/usr/bin/git",
                    "a" * 40,
                    [
                        orchestrate.BuildInput(
                            "Cargo.toml",
                            mutated,
                            hashlib.sha256(mutated).hexdigest(),
                        )
                    ],
                )

    def test_selected_nat_source_recheck_rejects_head_change(self):
        with tempfile.TemporaryDirectory() as temporary:
            context = self.context(Path(temporary))
            context.runner = mock.Mock()
            context.runner.run.side_effect = [
                subprocess.CompletedProcess([], 0, "", ""),
                subprocess.CompletedProcess([], 0, "b" * 40 + "\n", ""),
            ]
            with self.assertRaisesRegex(orchestrate.LabError, "HEAD changed"):
                orchestrate.validate_selected_nat_source_still_clean(
                    context, "/usr/bin/git", "a" * 40
                )

    def test_selected_nat_source_derives_tree_from_captured_commit(self):
        with tempfile.TemporaryDirectory() as temporary:
            context = self.context(Path(temporary))
            commit = "a" * 40
            selected = b"selected Dockerfile"
            inputs = [
                orchestrate.BuildInput(
                    "Cargo.toml", b"cargo", hashlib.sha256(b"cargo").hexdigest()
                ),
                orchestrate.BuildInput(
                    "Cargo.lock", b"lock", hashlib.sha256(b"lock").hexdigest()
                ),
                orchestrate.BuildInput(
                    "lab/Dockerfile.selected-nat",
                    selected,
                    hashlib.sha256(selected).hexdigest(),
                ),
            ]
            context.runner = mock.Mock()
            context.runner.run.side_effect = [
                subprocess.CompletedProcess([], 0, commit + "\n", ""),
                subprocess.CompletedProcess([], 0, "b" * 40 + "\n", ""),
                subprocess.CompletedProcess([], 0, "", ""),
                subprocess.CompletedProcess([], 0, "", "verified"),
            ]
            with mock.patch.object(
                orchestrate.shutil, "which", return_value="/usr/bin/git"
            ), mock.patch.object(
                orchestrate,
                "collect_selected_nat_build_inputs",
                return_value=inputs,
            ), mock.patch.object(
                orchestrate, "validate_selected_nat_tracked_inputs"
            ), mock.patch.object(
                orchestrate, "validate_selected_nat_commit_inputs"
            ):
                result = orchestrate.selected_nat_source_identity(context)
            self.assertEqual(result["commit"], commit)
            commands = [call.args[0] for call in context.runner.run.call_args_list]
            self.assertIn("HEAD^{commit}", commands[0])
            self.assertIn(f"{commit}^{{tree}}", commands[1])
            self.assertTrue(
                all("--no-replace-objects" in command for command in commands[:2])
            )
            self.assertNotIn("HEAD^{tree}", [item for command in commands for item in command])

    def test_selected_nat_rules_are_profile_exact_and_have_no_legacy_ports(self):
        common = {
            "lan_if": "eth0",
            "wan_if": "eth1",
            "lan_subnet": "10.250.1.0/24",
            "node_ip": "10.250.1.10",
            "external_ip": "10.250.0.11",
            "peer_external_ip": "10.250.0.12",
        }
        cone = orchestrate.selected_nat_nft_rules(profile="cone-direct", **common)
        self.assertIn("counter name aster_cone_dnat dnat to 10.250.1.10:44000", cone)
        self.assertIn("counter name aster_cone_snat snat to 10.250.0.11:44000", cone)
        self.assertNotIn("relay", cone)
        restrictive = orchestrate.selected_nat_nft_rules(
            profile="restrictive-relay", **common
        )
        self.assertIn("counter name aster_restrict_direct_drop drop", restrictive)
        self.assertIn("tcp dport 8443 counter name aster_restrict_relay_https", restrictive)
        self.assertIn("tcp dport 8080 counter name aster_restrict_relay_http", restrictive)
        self.assertNotIn("dnat to", restrictive)
        for rules in [cone, restrictive]:
            self.assertNotIn("4476", rules)
            self.assertNotIn("4477", rules)

    def test_selected_nat_legacy_port_scan_does_not_match_unrelated_digests(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "commands.jsonl"
            path.write_text(
                json.dumps(
                    {
                        "arguments": [
                            "docker",
                            "sha256:aaa4476bbb4477ccc",
                            "https://relay.aster.test:8443/",
                        ]
                    }
                )
                + "\n",
                encoding="utf-8",
            )
            orchestrate.validate_selected_nat_command_ports(path)
            path.write_text(
                json.dumps({"arguments": ["--https-bind", "0.0.0.0:4477"]})
                + "\n",
                encoding="utf-8",
            )
            with self.assertRaises(orchestrate.LabError):
                orchestrate.validate_selected_nat_command_ports(path)

    def test_selected_nat_named_counter_parser_and_delta_mutations(self):
        names = sorted(orchestrate.SELECTED_NAT_COUNTERS["restrictive-relay"])
        value = json.dumps(
            {
                "nftables": [
                    {"counter": {"name": name, "packets": 0, "bytes": 0}}
                    for name in names
                ]
            }
        )
        before = orchestrate.selected_nat_counter_snapshot(
            value, "restrictive-relay"
        )
        after = {
            name: {
                "packets": (
                    0
                    if name in {"aster_restrict_direct_drop", "aster_restrict_relay_http"}
                    else 1
                ),
                "bytes": (
                    0
                    if name in {"aster_restrict_direct_drop", "aster_restrict_relay_http"}
                    else 128
                ),
            }
            for name in names
        }
        delta = orchestrate.selected_nat_counter_delta(
            before, after, "restrictive-relay"
        )
        self.assertEqual(delta["aster_restrict_direct_drop"]["packets"], 0)
        duplicate = json.loads(value)
        duplicate["nftables"].append(duplicate["nftables"][0])
        with self.assertRaises(orchestrate.LabError):
            orchestrate.selected_nat_counter_snapshot(
                json.dumps(duplicate), "restrictive-relay"
            )
        bad_http = json.loads(json.dumps(after))
        bad_http["aster_restrict_relay_http"] = {"packets": 1, "bytes": 64}
        with self.assertRaises(orchestrate.LabError):
            orchestrate.selected_nat_counter_delta(
                before, bad_http, "restrictive-relay"
            )

        cone_names = sorted(orchestrate.SELECTED_NAT_COUNTERS["cone-direct"])
        cone_before = {
            name: {"packets": 0, "bytes": 0} for name in cone_names
        }
        cone_after = {
            "aster_cone_dnat": {"packets": 1, "bytes": 1_228},
            "aster_cone_forward_in": {"packets": 3_132, "bytes": 846_070},
            "aster_cone_forward_out": {"packets": 3_093, "bytes": 822_577},
            "aster_cone_snat": {"packets": 0, "bytes": 0},
        }
        cone_delta = orchestrate.selected_nat_counter_delta(
            cone_before, cone_after, "cone-direct"
        )
        self.assertEqual(cone_delta["aster_cone_snat"], {"packets": 0, "bytes": 0})
        no_nat_hook = json.loads(json.dumps(cone_after))
        no_nat_hook["aster_cone_dnat"] = {"packets": 0, "bytes": 0}
        orchestrate.selected_nat_counter_delta(
            cone_before, no_nat_hook, "cone-direct"
        )
        missing_forward = json.loads(json.dumps(cone_after))
        missing_forward["aster_cone_forward_out"] = {"packets": 0, "bytes": 0}
        with self.assertRaises(orchestrate.LabError):
            orchestrate.selected_nat_counter_delta(
                cone_before, missing_forward, "cone-direct"
            )

    def test_selected_nat_cone_directionality_binds_one_sided_nat_hooks(self):
        node_results = {
            "node-a": {
                "ready": {"carrier_id": "f" * 64},
                "contacts": [{"direction": "in"}, {"direction": "in"}],
            },
            "node-b": {
                "ready": {"carrier_id": "1" * 64},
                "contacts": [{"direction": "out"}, {"direction": "out"}]
            },
        }
        nft_deltas = {
            "nat-a": {
                "aster_cone_dnat": {"packets": 1, "bytes": 1_228},
                "aster_cone_forward_in": {"packets": 3_132, "bytes": 846_070},
                "aster_cone_forward_out": {"packets": 3_093, "bytes": 822_577},
                "aster_cone_snat": {"packets": 0, "bytes": 0},
            },
            "nat-b": {
                "aster_cone_dnat": {"packets": 0, "bytes": 0},
                "aster_cone_forward_in": {"packets": 3_093, "bytes": 822_577},
                "aster_cone_forward_out": {"packets": 3_132, "bytes": 846_070},
                "aster_cone_snat": {"packets": 1, "bytes": 1_228},
            },
        }
        wan_direction_packets = {
            "nat-a": {"inbound": 3_132, "outbound": 3_093},
            "nat-b": {"inbound": 3_093, "outbound": 3_132},
        }
        self.assertEqual(
            orchestrate.validate_selected_nat_cone_directionality(
                node_results=node_results,
                nft_deltas=nft_deltas,
                wan_direction_packets=wan_direction_packets,
            ),
            {
                "initiator_node": "node-b",
                "initiator_router": "nat-b",
                "responder_node": "node-a",
                "responder_router": "nat-a",
            },
        )

        mutations = []
        both_out = json.loads(json.dumps(node_results))
        both_out["node-a"]["contacts"] = [{"direction": "out"}]
        mutations.append((both_out, nft_deltas, wan_direction_packets))
        mixed = json.loads(json.dumps(node_results))
        mixed["node-a"]["contacts"].append({"direction": "out"})
        mutations.append((mixed, nft_deltas, wan_direction_packets))
        higher_id_initiates = json.loads(json.dumps(node_results))
        higher_id_initiates["node-a"]["contacts"] = [{"direction": "out"}]
        higher_id_initiates["node-b"]["contacts"] = [{"direction": "in"}]
        swapped_hooks = json.loads(json.dumps(nft_deltas))
        swapped_hooks["nat-a"]["aster_cone_dnat"] = {
            "packets": 0,
            "bytes": 0,
        }
        swapped_hooks["nat-a"]["aster_cone_snat"] = {
            "packets": 1,
            "bytes": 1_228,
        }
        swapped_hooks["nat-b"]["aster_cone_dnat"] = {
            "packets": 1,
            "bytes": 1_228,
        }
        swapped_hooks["nat-b"]["aster_cone_snat"] = {
            "packets": 0,
            "bytes": 0,
        }
        mutations.append(
            (higher_id_initiates, swapped_hooks, wan_direction_packets)
        )
        inactive_advanced = json.loads(json.dumps(nft_deltas))
        inactive_advanced["nat-b"]["aster_cone_dnat"] = {
            "packets": 1,
            "bytes": 1_228,
        }
        mutations.append((node_results, inactive_advanced, wan_direction_packets))
        active_zero = json.loads(json.dumps(nft_deltas))
        active_zero["nat-a"]["aster_cone_dnat"] = {"packets": 0, "bytes": 0}
        mutations.append((node_results, active_zero, wan_direction_packets))
        active_exceeds_wan = json.loads(json.dumps(nft_deltas))
        active_exceeds_wan["nat-b"]["aster_cone_snat"]["packets"] = 3_133
        mutations.append((node_results, active_exceeds_wan, wan_direction_packets))
        for nodes, counters, directions in mutations:
            with self.subTest(
                nodes=nodes, counters=counters, directions=directions
            ), self.assertRaises(orchestrate.LabError):
                orchestrate.validate_selected_nat_cone_directionality(
                    node_results=nodes,
                    nft_deltas=counters,
                    wan_direction_packets=directions,
                )

    def test_selected_nat_manifest_rejects_identity_mutations(self):
        ids = [character * 64 for character in "abcdef"]
        authority = "1" * 64
        manifest = (
            "ASTER_SELECTED_NAT_MANIFEST\tversion=2\tscope=scope\ttopic=topic"
            f"\tmission_authority={authority}\tcanary_sha256={ids[0]}\tnodes=2\n"
            "name\tmission_id\tcarrier_id\tsubscription_id\n"
            f"a\t{ids[1]}\t{ids[2]}\t{ids[3]}\n"
            f"b\t{ids[4]}\t{ids[5]}\t{'0' * 64}\n"
        )
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "manifest.tsv"
            path.write_text(manifest, encoding="utf-8")
            parsed = orchestrate.parse_selected_nat_manifest(
                path, scope="scope", topic="topic"
            )
            self.assertEqual(set(parsed["nodes"]), {"a", "b"})
            self.assertEqual(parsed["mission_authority"], authority)
            authority_field = f"\tmission_authority={authority}"
            mutations = [
                manifest.replace("version=2", "version=1"),
                manifest.replace(authority_field, ""),
                manifest.replace(authority, "A" * 64),
                manifest.replace(authority_field, authority_field * 2),
                manifest.replace(authority, "g" * 64),
                manifest.replace(authority, ids[1]),
                manifest.replace(authority, ids[5]),
                manifest.replace(ids[4], ids[1]),
            ]
            for mutated in mutations:
                path.write_text(mutated, encoding="utf-8")
                with self.subTest(mutation=mutated.splitlines()[0]), self.assertRaises(
                    orchestrate.LabError
                ):
                    orchestrate.parse_selected_nat_manifest(
                        path, scope="scope", topic="topic"
                    )

    def test_selected_nat_prepare_binds_shared_disjoint_mission_authority(self):
        authority = "1" * 64
        manifest = {
            "mission_authority": authority,
            "canary_sha256": "a" * 64,
            "nodes": {
                "a": {
                    "name": "a",
                    "mission_id": "b" * 64,
                    "carrier_id": "c" * 64,
                    "subscription_id": "d" * 64,
                },
                "b": {
                    "name": "b",
                    "mission_id": "e" * 64,
                    "carrier_id": "f" * 64,
                    "subscription_id": "0" * 64,
                },
            },
        }
        prepare = (
            "SELECTED_NAT_PREPARE status=pass version=2 nodes=2 scope=scope topic=topic "
            f"manifest=/output/manifest.tsv mission_authority={authority} "
            "mission_authority_shared=true mission_authority_disjoint=true "
            "mission_ids_distinct=true carrier_ids_distinct=true "
            "mission_carrier_disjoint=true subscriptions=2 pre_inventory_events=0 "
            f"canary_sha256={'a' * 64} canary_bytes=32 canary=redacted\n"
            f"SELECTED_NAT_NODE name=a mission_id={'b' * 64} carrier_id={'c' * 64}\n"
            f"SELECTED_NAT_NODE name=b mission_id={'e' * 64} carrier_id={'f' * 64}\n"
        )
        parsed = orchestrate.validate_selected_nat_prepare(
            prepare, scope="scope", topic="topic", manifest=manifest
        )
        self.assertEqual(parsed["prepare"]["mission_authority"], authority)
        for before, after in [
            ("version=2", "version=1"),
            (f"mission_authority={authority}", f"mission_authority={'2' * 64}"),
            ("mission_authority_shared=true", "mission_authority_shared=false"),
            ("mission_authority_disjoint=true", "mission_authority_disjoint=false"),
        ]:
            with self.subTest(field=before), self.assertRaises(orchestrate.LabError):
                orchestrate.validate_selected_nat_prepare(
                    prepare.replace(before, after, 1),
                    scope="scope",
                    topic="topic",
                    manifest=manifest,
                )

        overlapping = json.loads(json.dumps(manifest))
        overlapping["mission_authority"] = overlapping["nodes"]["a"]["mission_id"]
        with self.assertRaises(orchestrate.LabError):
            orchestrate.validate_selected_nat_prepare(
                prepare.replace(authority, overlapping["mission_authority"]),
                scope="scope",
                topic="topic",
                manifest=overlapping,
            )

    def test_selected_nat_runtime_authorities_are_fresh_and_globally_disjoint(self):
        def runtime(profile, authority, identities):
            return {
                "profile": profile,
                "mission_authority": authority,
                "nodes": {
                    "a": {
                        "mission_id": identities[0],
                        "carrier_id": identities[1],
                    },
                    "b": {
                        "mission_id": identities[2],
                        "carrier_id": identities[3],
                    },
                },
            }

        cone = runtime(
            "cone-direct",
            "1" * 64,
            [character * 64 for character in "abcd"],
        )
        relay = runtime(
            "restrictive-relay",
            "2" * 64,
            [character * 64 for character in "ef34"],
        )
        orchestrate.validate_selected_nat_runtime_identity_domains(
            [("cone-direct", cone), ("restrictive-relay", relay)]
        )

        mutations = []
        reused_authority = json.loads(json.dumps(relay))
        reused_authority["mission_authority"] = cone["mission_authority"]
        mutations.append(reused_authority)
        cross_domain_overlap = json.loads(json.dumps(relay))
        cross_domain_overlap["mission_authority"] = cone["nodes"]["a"]["mission_id"]
        mutations.append(cross_domain_overlap)
        reused_node_identity = json.loads(json.dumps(relay))
        reused_node_identity["nodes"]["a"]["mission_id"] = cone["nodes"]["a"][
            "mission_id"
        ]
        mutations.append(reused_node_identity)
        local_overlap = json.loads(json.dumps(relay))
        local_overlap["mission_authority"] = local_overlap["nodes"]["b"]["carrier_id"]
        mutations.append(local_overlap)
        for mutated in mutations:
            with self.subTest(authority=mutated["mission_authority"]), self.assertRaises(
                orchestrate.LabError
            ):
                orchestrate.validate_selected_nat_runtime_identity_domains(
                    [("cone-direct", cone), ("restrictive-relay", mutated)]
                )

    def test_selected_nat_relay_and_artifact_cleanup_receipts_are_exact(self):
        carrier_ids = {"a" * 64, "b" * 64}
        ready = (
            "SELECTED_NAT_RELAY_READY status=ready version=1 "
            "https=0.0.0.0:8443 http=0.0.0.0:8080 "
            "tls=manual-der-certificate server_trust_claim=none "
            "allowlist=exact-cli-identities allowlist_count=2 "
            "max_admitted_connections=8 pre_auth_connection_cap=not-enforced "
            "client_rx_bytes_per_second=1048576 client_rx_max_burst_bytes=1048576 "
            "key_cache_capacity=256 secrets_logged=false "
            "public_relay_fallback=false hosted_discovery=false port_mapper=false\n"
        )
        stop = (
            "SELECTED_NAT_RELAY_STOP status=pass version=1 accepted_connections=1 "
            "denied_connections=0 active_connections=0 peak_active_connections=1 "
            "sessions=1 bytes_up=64 bytes_down=64 max_admitted_connections=8 "
            "pre_auth_connection_cap=not-enforced client_rx_bytes_per_second=1048576 "
            "client_rx_max_burst_bytes=1048576 key_cache_capacity=256 "
            "allowlist=exact-cli-identities allowlist_count=2 "
            "server_trust_claim=none graceful=true\n"
        )
        receipt = orchestrate.validate_selected_nat_relay_log(
            ready + stop,
            carrier_ids=carrier_ids,
            max_admitted_connections=8,
            client_rx_bytes_per_second=1_048_576,
            client_rx_max_burst_bytes=1_048_576,
            key_cache_capacity=256,
        )
        self.assertEqual(receipt["stop"]["pre_auth_connection_cap"], "not-enforced")
        for mutation in [
            ("pre_auth_connection_cap=not-enforced", "pre_auth_connection_cap=enforced"),
            ("server_trust_claim=none", "server_trust_claim=pinned"),
            ("allowlist=exact-cli-identities", "allowlist=derived"),
            ("status=ready", "status=ready unexpected_field=true"),
        ]:
            with self.assertRaises(orchestrate.LabError):
                orchestrate.validate_selected_nat_relay_log(
                    (ready + stop).replace(*mutation),
                    carrier_ids=carrier_ids,
                    max_admitted_connections=8,
                    client_rx_bytes_per_second=1_048_576,
                    client_rx_max_burst_bytes=1_048_576,
                    key_cache_capacity=256,
                )

        destroyed = (
            "SELECTED_NAT_CANARY_DESTROY status=pass version=2 publication_journals_destroyed=2 "
            "artifact_destroyed=true global_secret_destruction=false "
            "target=private/canary.bin previous_bytes=32 previous_mode=0600 "
            f"owner_uid={os.getuid()} overwrite=zero sync=file+directory unlinked=true "
            "assurance=bounded-software physical_sanitization=not-claimed\n"
        )
        parsed = orchestrate.validate_selected_nat_destroy(
            destroyed,
            prefix="SELECTED_NAT_CANARY_DESTROY",
            target="private/canary.bin",
            expected_bytes=32,
        )
        self.assertEqual(parsed["global_secret_destruction"], "false")
        with self.assertRaises(orchestrate.LabError):
            orchestrate.validate_selected_nat_destroy(
                destroyed.replace("artifact_destroyed=true", "secret_destroyed=true"),
                prefix="SELECTED_NAT_CANARY_DESTROY",
                target="private/canary.bin",
                expected_bytes=32,
            )

    def test_selected_nat_stdout_contact_and_error_mutations(self):
        carrier = "a" * 64
        mission = "b" * 64
        authority = "e" * 64
        ready = (
            "READY selected=true "
            f"pid=1234 carrier_id={carrier} mission_id={mission} mission_authority={authority} "
            "state=/output/node-a "
            "carrier_route=direct public_relay_fallback=false hosted_discovery=false "
            "controlled_relay_readiness=not-applicable nat_traversal=not-claimed "
            "path_observation=not-authorization "
            "peers=1 application=relay mission_auth=hybrid-pq "
            "sockets=10.250.1.10:44000 controlled_relay_url=none "
            "controlled_relay_trust=none provisioning=unprotected-reference "
            "semantics=source-authenticated-event "
            "reconciliation_classes=event,state,record,blob-v5-opt-in "
            "controls=source-authenticated-flash commit_before_activate=true "
            "content_admission=capability-gated\n"
        )
        zeroes = " ".join(
            f"{field}=0" for field in sorted(orchestrate.SELECTED_NAT_NOOP_FIELDS)
        )
        contact = (
            "CONTACT direction=out "
            f"carrier_peer={'c' * 64} mission_peer={'d' * 64} rounds=18 "
            f"{zeroes} carrier_path=direct carrier_path_transitions=1 "
            "handshake_frames=4 handshake_bytes=22874 protected_frames=100 "
            "protected_bytes=6941 "
            "carrier_path_transitions_saturated=false path_observation=not-authorization "
            "mission_auth=hybrid-pq semantics=source-authenticated-event "
            "reconciliation_classes=event,state,record,blob "
            "controls=source-authenticated-flash content_admission=capability-gated "
            "status=pass\n"
        )
        stop = (
            "STOP lifecycle=complete sync_status=contacts_observed "
            f"carrier_id={carrier} mission_id={mission} contacts=1 contact_errors=0 "
            "direct_contacts=1 relay_contacts=0 unknown_path_contacts=0 "
            "carrier_path_transitions=1 carrier_path_transition_saturations=0 "
            "path_observation=not-authorization opaque_items=0 "
            "opaque_acceptance_markers=0 events=1 event_acceptance_markers=1 "
            "route_cached_events=0 controls=0 applied_controls=0 pending_controls=0 "
            "control_highwater=0 blobs=0 pending_blobs=0 blob_ranges_fetched=0 "
            "blob_bytes_fetched=0 blob_remaining=0 blob_deferred=0 "
            "mission_auth=hybrid-pq provisioning=unprotected-reference "
            "semantics=source-authenticated-event "
            "reconciliation_classes=event,state,record,blob-v5 "
            "controls_semantics=source-authenticated-flash\n"
        )
        orchestrate.validate_selected_nat_stderr("", "node-a")
        stdout = ready + contact + stop
        result = orchestrate.validate_selected_nat_node_log(
            stdout,
            profile="cone-direct",
            carrier_id=carrier,
            mission_id=mission,
            mission_authority=authority,
            bind_ip="10.250.1.10",
        )
        self.assertEqual(result["path"], "Direct")
        with self.assertRaises(orchestrate.LabError):
            orchestrate.validate_selected_nat_node_log(
                stdout.replace(authority, "f" * 64, 1),
                profile="cone-direct",
                carrier_id=carrier,
                mission_id=mission,
                mission_authority=authority,
                bind_ip="10.250.1.10",
            )
        with self.assertRaises(orchestrate.LabError):
            orchestrate.validate_selected_nat_node_log(
                stdout.replace(authority, mission, 1),
                profile="cone-direct",
                carrier_id=carrier,
                mission_id=mission,
                mission_authority=mission,
                bind_ip="10.250.1.10",
            )
        with self.assertRaises(orchestrate.LabError):
            orchestrate.validate_selected_nat_node_log(
                stdout.replace(authority, authority.upper(), 1),
                profile="cone-direct",
                carrier_id=carrier,
                mission_id=mission,
                mission_authority=authority.upper(),
                bind_ip="10.250.1.10",
            )
        with self.assertRaises(orchestrate.LabError):
            orchestrate.validate_selected_nat_stderr(
                contact, "node-a"
            )
        with self.assertRaises(orchestrate.LabError):
            orchestrate.validate_selected_nat_stderr(
                "diagnostic secret=unexpected\n", "node-a"
            )
        with self.assertRaises(orchestrate.LabError):
            orchestrate.validate_selected_nat_node_log(
                stdout.replace("contact_errors=0", "contact_errors=1"),
                profile="cone-direct",
                carrier_id=carrier,
                mission_id=mission,
                mission_authority=authority,
                bind_ip="10.250.1.10",
                state_path="/output/node-a",
            )
        with self.assertRaises(orchestrate.LabError):
            orchestrate.validate_selected_nat_node_log(
                stdout.replace(" offered=0", " offered=1", 1),
                profile="cone-direct",
                carrier_id=carrier,
                mission_id=mission,
                mission_authority=authority,
                bind_ip="10.250.1.10",
                state_path="/output/node-a",
            )
        with self.assertRaises(orchestrate.LabError):
            orchestrate.validate_selected_nat_node_log(
                stdout.replace(
                    "content_admission=capability-gated\n",
                    "content_admission=capability-gated unexpected_private_material=redacted\n",
                    1,
                ),
                profile="cone-direct",
                carrier_id=carrier,
                mission_id=mission,
                mission_authority=authority,
                bind_ip="10.250.1.10",
                state_path="/output/node-a",
            )
        with self.assertRaises(orchestrate.LabError):
            orchestrate.validate_selected_nat_node_log(
                stdout.replace(
                    " contacts=1 contact_errors", " contacts=2 contact_errors"
                ),
                profile="cone-direct",
                carrier_id=carrier,
                mission_id=mission,
                mission_authority=authority,
                bind_ip="10.250.1.10",
                state_path="/output/node-a",
            )
        with self.assertRaises(orchestrate.LabError):
            orchestrate.validate_selected_nat_node_log(
                ready + contact.replace("status=pass", "status=error") + stop,
                profile="cone-direct",
                carrier_id=carrier,
                mission_id=mission,
                mission_authority=authority,
                bind_ip="10.250.1.10",
                state_path="/output/node-a",
            )
        for malformed in [
            contact + stop,
            ready + stop + contact,
            ready + ready + contact + stop,
            ready + contact + stop + stop,
            ready + "DIAGNOSTIC unexpected=true\n" + contact + stop,
        ]:
            with self.assertRaises(orchestrate.LabError):
                orchestrate.validate_selected_nat_node_log(
                    malformed,
                    profile="cone-direct",
                    carrier_id=carrier,
                    mission_id=mission,
                    mission_authority=authority,
                    bind_ip="10.250.1.10",
                    state_path="/output/node-a",
                )

    def test_selected_nat_runtime_privilege_is_cap_free_nonroot(self):
        status = "\n".join(
            [
                "CapInh:\t0000000000000000",
                "CapPrm:\t0000000000000000",
                "CapEff:\t0000000000000000",
                "CapBnd:\t0000000000000000",
                "CapAmb:\t0000000000000000",
                "NoNewPrivs:\t1",
            ]
        )
        receipt = orchestrate.validate_runtime_privilege_receipt(status, "501\n", "20\n")
        self.assertEqual(receipt["cap_bounding"], 0)
        with self.assertRaises(orchestrate.LabError):
            orchestrate.validate_runtime_privilege_receipt(
                status.replace("CapEff:\t0000000000000000", "CapEff:\t0000000000001000"),
                "501",
                "20",
            )
        with self.assertRaises(orchestrate.LabError):
            orchestrate.validate_runtime_privilege_receipt(status, "0", "20")

    def test_selected_nat_network_receipt_is_internal_and_exact(self):
        with tempfile.TemporaryDirectory() as temporary:
            context = self.context(Path(temporary))
            context.runner = mock.Mock()
            spec = orchestrate.NetworkSpec.from_tuple(
                orchestrate.NAT_NETWORKS["lan-a"]
            )
            value = {
                "Name": spec.name,
                "Driver": "bridge",
                "Internal": True,
                "Attachable": False,
                "Ingress": False,
                "Labels": {
                    orchestrate.MANAGED_LABEL: "true",
                    orchestrate.RUN_LABEL: context.run_id,
                    orchestrate.ROLE_LABEL: "lan-a",
                },
                "IPAM": {
                    "Driver": "default",
                    "Config": [
                        {"Subnet": str(spec.subnet), "Gateway": str(spec.gateway)}
                    ],
                },
                "Containers": {
                    "endpoint-a": {
                        "Name": orchestrate.FIXED_CONTAINER_NAMES["node-a"],
                        "IPv4Address": "10.250.1.10/24",
                    },
                    "endpoint-b": {
                        "Name": orchestrate.FIXED_CONTAINER_NAMES["nat-a"],
                        "IPv4Address": "10.250.1.1/24",
                    },
                },
            }
            context.runner.run.return_value = subprocess.CompletedProcess(
                [], 0, json.dumps(value), ""
            )
            receipt = orchestrate.selected_nat_network_receipt(
                context,
                role="lan-a",
                spec=spec,
                expected_members={
                    orchestrate.FIXED_CONTAINER_NAMES["node-a"]: "10.250.1.10",
                    orchestrate.FIXED_CONTAINER_NAMES["nat-a"]: "10.250.1.1",
                },
            )
            self.assertTrue(receipt["internal"])
            value["Internal"] = False
            context.runner.run.return_value = subprocess.CompletedProcess(
                [], 0, json.dumps(value), ""
            )
            with self.assertRaises(orchestrate.LabError):
                orchestrate.selected_nat_network_receipt(
                    context,
                    role="lan-a",
                    spec=spec,
                    expected_members={
                        orchestrate.FIXED_CONTAINER_NAMES["node-a"]: "10.250.1.10",
                        orchestrate.FIXED_CONTAINER_NAMES["nat-a"]: "10.250.1.1",
                    },
                )

    def test_selected_nat_pcap_parser_is_exact_and_rejects_truncation(self):
        ethernet = b"\x00" * 12 + b"\x08\x00"
        ipv4 = (
            b"\x45\x00"
            + struct.pack("!H", 28)
            + b"\x00\x00\x00\x00\x40\x11\x00\x00"
            + bytes([10, 250, 0, 11, 10, 250, 0, 12])
        )
        udp = struct.pack("!HHHH", 44000, 44000, 8, 0)
        packet = ethernet + ipv4 + udp
        pcap = struct.pack("<IHHIIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1)
        pcap += struct.pack("<IIII", 1, 0, len(packet), len(packet)) + packet
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "capture.pcap"
            path.write_bytes(pcap)
            summary = orchestrate.parse_pcap_ipv4_tuples(path)
            self.assertEqual(summary["packets"], 1)
            self.assertEqual(summary["tuples"][0]["source_port"], 44000)
            self.assertEqual(
                orchestrate.pcap_tuple_count(
                    summary,
                    addresses={"10.250.0.11", "10.250.0.12"},
                    port=44000,
                    protocol="udp",
                    both_ports=True,
                ),
                1,
            )
            summary["tuples"][0]["destination_port"] = 44001
            self.assertEqual(
                orchestrate.pcap_tuple_count(
                    summary,
                    addresses={"10.250.0.11", "10.250.0.12"},
                    port=44000,
                    protocol="udp",
                    both_ports=True,
                ),
                0,
            )
            path.write_bytes(pcap[:-1])
            with self.assertRaises(orchestrate.LabError):
                orchestrate.parse_pcap_ipv4_tuples(path)

    def test_selected_nat_tcpdump_terminal_counts_are_exact_and_bound_to_pcap(self):
        terminal = (
            "tcpdump: listening on eth1, link-type EN10MB (Ethernet), "
            "snapshot length 262144 bytes\n"
            "7 packets captured\n"
            "7 packets received by filter\n"
            "0 packets dropped by kernel\n"
        )
        counts = orchestrate.tcpdump_terminal_counts(terminal)
        self.assertEqual(
            counts,
            {"captured": 7, "received_by_filter": 7, "dropped": 0},
        )
        orchestrate.validate_tcpdump_pcap_packet_count({"packets": 7}, counts)

        mutations = {
            "malformed": terminal.replace(
                "7 packets captured", "seven packets captured"
            ),
            "missing": terminal.replace("7 packets received by filter\n", ""),
            "duplicate": terminal + "7 packets captured\n",
            "captured-filter-mismatch": terminal.replace(
                "7 packets received by filter", "8 packets received by filter"
            ),
            "kernel-drop": terminal.replace(
                "0 packets dropped by kernel", "1 packets dropped by kernel"
            ),
        }
        for label, value in mutations.items():
            with self.subTest(label=label), self.assertRaises(orchestrate.LabError):
                orchestrate.tcpdump_terminal_counts(value)
        with self.assertRaises(orchestrate.LabError):
            orchestrate.validate_tcpdump_pcap_packet_count({"packets": 6}, counts)

    def test_selected_nat_canary_scanner_bounds_before_read(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            context = self.context(root)
            canary = root / "private" / "canary.bin"
            canary.parent.mkdir(mode=0o700)
            canary.write_bytes(bytes(range(32)))
            canary.chmod(0o600)
            oversized = root / "oversized.log"
            with oversized.open("wb") as stream:
                stream.truncate(128 * 1024 * 1024 + 1)
            oversized.chmod(0o600)
            original_read_bytes = Path.read_bytes

            def guarded_read(path):
                if path == oversized:
                    raise AssertionError("oversized file was read before its size check")
                return original_read_bytes(path)

            with mock.patch.object(Path, "read_bytes", autospec=True, side_effect=guarded_read):
                with self.assertRaisesRegex(orchestrate.LabError, "exceeds 128 MiB"):
                    orchestrate.selected_nat_canary_scan(
                        context,
                        canary_path=canary,
                        captures=[],
                        logs=[oversized],
                    )

    def test_selected_nat_canary_scanner_rejects_link_mutations(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            context = self.context(root)
            canary = root / "private" / "canary.bin"
            canary.parent.mkdir(mode=0o700)
            canary.write_bytes(bytes(range(32)))
            canary.chmod(0o600)
            target = root / "target.log"
            target.write_text("sanitized\n", encoding="utf-8")
            target.chmod(0o600)
            symbolic = root / "symbolic.log"
            symbolic.symlink_to(target.name)
            with self.assertRaisesRegex(orchestrate.LabError, "single-link"):
                orchestrate.selected_nat_canary_scan(
                    context,
                    canary_path=canary,
                    captures=[],
                    logs=[symbolic],
                )
            hard_link = root / "hard-link.log"
            os.link(target, hard_link)
            with self.assertRaisesRegex(orchestrate.LabError, "single-link"):
                orchestrate.selected_nat_canary_scan(
                    context,
                    canary_path=canary,
                    captures=[],
                    logs=[target],
                )

    def test_selected_nat_curated_manifest_normalizes_exact_paths_only(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            root.chmod(0o700)

            def create_owner_only_parents(path):
                path.mkdir(parents=True, exist_ok=True)
                current = path
                while current != root:
                    current.chmod(0o700)
                    current = current.parent

            expected = orchestrate.selected_nat_manifest_paths()
            self.assertEqual(
                {scope: len(roles) for scope, roles in expected.items()},
                {"global": 4, "cone-direct": 44, "restrictive-relay": 51},
            )
            self.assertEqual(sum(len(roles) for roles in expected.values()), 99)
            for roles in expected.values():
                for relative in roles.values():
                    path = root / relative
                    create_owner_only_parents(path.parent)
                    path.write_bytes(b"x" * (24 if path.suffix == ".pcap" else 1))
                    path.chmod(0o644)
            for profile in ["cone-direct", "restrictive-relay"]:
                files = []
                for index in range(4):
                    relative = f"command-{100 + index:04d}.stderr"
                    content = b"" if index < 2 else b"0 packets dropped by kernel\n"
                    command_path = root / "cells" / profile / relative
                    command_path.write_bytes(content)
                    command_path.chmod(0o644)
                    files.append(
                        {
                            "path": relative,
                            "bytes": len(content),
                            "sha256": hashlib.sha256(content).hexdigest(),
                        }
                    )
                scan_path = root / "cells" / profile / "canary-scan.json"
                scan_path.write_text(
                    json.dumps(
                        {
                            "artifact_classes": [
                                {"class": "pcap", "files": []},
                                {"class": "log", "files": files},
                            ]
                        },
                        indent=2,
                        sort_keys=True,
                    )
                    + "\n",
                    encoding="utf-8",
                )
                scan_path.chmod(0o644)
            retained = (
                root
                / "cells"
                / "cone-direct"
                / "outputs"
                / "provision"
                / "private"
                / "node-a.bundle"
            )
            create_owner_only_parents(retained.parent)
            retained.write_bytes(b"retained restricted credential")
            retained.chmod(0o600)
            orchestrate.normalize_selected_nat_curated_artifacts(root)
            manifest = orchestrate.selected_nat_curated_manifest(root)
            self.assertEqual(
                manifest["records"], sum(len(roles) for roles in expected.values())
            )
            self.assertNotIn("node-a.bundle", json.dumps(manifest))
            self.assertTrue(
                all(entry["mode"] == "0600" and entry["nlink"] == 1 for entry in manifest["entries"])
            )
            self.assertEqual(
                (root / "cells/cone-direct/command-0100.stderr").stat().st_mode
                & 0o777,
                0o600,
            )
            transient = root / "build-context" / "discarded.txt"
            transient.parent.mkdir(mode=0o700)
            transient.write_text("controller transient\n", encoding="utf-8")
            transient.chmod(0o600)
            for index, scope in enumerate(
                [
                    root,
                    root / "cells" / "cone-direct",
                    root / "cells" / "restrictive-relay",
                ]
            ):
                stdout_name = f"command-{9000 + index:04d}.stdout"
                stderr_name = f"command-{9000 + index:04d}.stderr"
                for name in (stdout_name, stderr_name):
                    path = scope / name
                    path.write_bytes(b"")
                    path.chmod(0o600)
                commands = scope / "commands.jsonl"
                commands.write_text(
                    json.dumps({"stdout": stdout_name, "stderr": stderr_name}) + "\n",
                    encoding="utf-8",
                )
                commands.chmod(0o600)
            linked_logs = []
            for profile in ("cone-direct", "restrictive-relay"):
                cell = root / "cells" / profile
                route_receipts = []
                for index, (route, node, gateway) in enumerate(
                    (
                        ("route-a", "node-a", "10.250.1.1"),
                        ("route-b", "node-b", "10.250.2.1"),
                    )
                ):
                    log_name = f"reap-aster-lab-{route}-command-{9200 + index:04d}.log"
                    route_log = cell / log_name
                    route_log.write_bytes(b"")
                    route_log.chmod(0o600)
                    linked_logs.append(route_log)
                    route_receipts.append(
                        {
                            "role": route,
                            "log": log_name,
                            "log_sha256": hashlib.sha256(b"").hexdigest(),
                            "node": node,
                            "gateway": gateway,
                        }
                    )
                route_path = cell / "route-init-removal.json"
                route_path.write_text(
                    json.dumps(route_receipts, sort_keys=True) + "\n", encoding="utf-8"
                )
                route_path.chmod(0o600)
                for index in range(2):
                    path = cell / f"reap-aster-lab-provision-command-{9300 + index:04d}.log"
                    path.write_text("provision log\n", encoding="utf-8")
                    path.chmod(0o600)
                    linked_logs.append(path)
                cleanup_roles = ["node-a", "nat-a", "nat-b", "node-b"]
                if profile == "restrictive-relay":
                    cleanup_roles.append("infra")
                for index, role in enumerate(cleanup_roles):
                    path = cell / f"cleanup-aster-lab-{role}-command-{9400 + index:04d}.log"
                    path.write_text("cleanup log\n", encoding="utf-8")
                    path.chmod(0o600)
                    linked_logs.append(path)
            leaked = root / "cells/restrictive-relay/leaked-server.key.pkcs8.der"
            leaked.write_bytes(b"unexpected material")
            leaked.chmod(0o600)
            with self.assertRaises(orchestrate.LabError):
                orchestrate.prune_selected_nat_transient_artifacts(root)
            self.assertTrue(transient.exists())
            self.assertTrue(leaked.exists())
            leaked.unlink()
            orchestrate.prune_selected_nat_transient_artifacts(root)
            self.assertFalse(transient.exists())
            self.assertTrue(all(not path.exists() for path in linked_logs))
            self.assertTrue(retained.exists())
            self.assertTrue((root / "selected-nat-suite.json").exists())
            self.assertTrue(
                (root / "cells/cone-direct/command-0100.stderr").exists()
            )
            outside = root.parent / "outside-prune-target"
            outside.write_text("outside\n", encoding="utf-8")
            link = root / "unexpected-link"
            link.symlink_to(outside)
            with self.assertRaises(orchestrate.LabError):
                orchestrate.prune_selected_nat_transient_artifacts(
                    root, require_complete=False
                )
            self.assertEqual(outside.read_text(encoding="utf-8"), "outside\n")
            link.unlink()
            outside.unlink()
            live_canary = retained.with_name("canary.bin")
            live_canary.write_bytes(b"s" * 32)
            live_canary.chmod(0o600)
            with self.assertRaises(orchestrate.LabError):
                orchestrate.validate_selected_nat_control_file_absence(root)

    def test_selected_nat_restricted_state_is_owner_only_and_not_enumerated(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            context = self.context(root)
            provision = root / "outputs" / "provision"
            private = provision / "private"
            relay_private = provision / "relay" / "private"
            for directory in [private, relay_private, provision / "node-a", provision / "node-b"]:
                directory.mkdir(parents=True, mode=0o755, exist_ok=True)
                directory.chmod(0o755)
            for path in [private / "node-a.bundle", private / "node-b.bundle"]:
                path.write_bytes(b"bundle")
                path.chmod(0o644)
            for role in ["node-a", "node-b"]:
                (provision / role / "mesh.redb").write_bytes(b"state")
            with self.assertRaises(orchestrate.LabError):
                orchestrate.normalize_selected_nat_restricted_state(
                    context, provision, "restrictive-relay"
                )
            for path in [private / "node-a.bundle", private / "node-b.bundle"]:
                path.chmod(0o600)
            receipt = orchestrate.normalize_selected_nat_restricted_state(
                context, provision, "restrictive-relay"
            )
            self.assertEqual(receipt["mission_bundle_files"], 2)
            self.assertEqual(receipt["state_files"], 2)
            self.assertNotIn("node-a.bundle", json.dumps(receipt))
            self.assertEqual((private / "node-a.bundle").stat().st_mode & 0o777, 0o600)
            self.assertEqual((provision / "node-a").stat().st_mode & 0o777, 0o700)

    def test_selected_nat_command_chronology_is_exact(self):
        routes = [
            {"log": "reap-aster-lab-route-a-command-0090.log"},
            {"log": "reap-aster-lab-route-b-command-0091.log"},
        ]
        captures = {
            "nat-a": "command-0100.stderr",
            "nat-b": "command-0101.stderr",
        }
        nodes = {
            "node-a": "command-0201.stderr",
            "node-b": "command-0200.stderr",
        }
        orchestrate.validate_selected_nat_command_chronology(
            route_receipts=routes,
            capture_stderr=captures,
            node_stderr=nodes,
        )
        mutations = [
            ([{"log": "reap-aster-lab-route-a-command-0300.log"}, routes[1]], captures, nodes),
            ([routes[0], {"log": "reap-aster-lab-route-b-command-0089.log"}], captures, nodes),
            (routes, {"nat-a": captures["nat-b"], "nat-b": captures["nat-a"]}, nodes),
            (routes, captures, {"node-a": "command-0202.stderr", "node-b": nodes["node-b"]}),
        ]
        for route_values, capture_values, node_values in mutations:
            with self.subTest(
                routes=route_values, captures=capture_values, nodes=node_values
            ), self.assertRaises(orchestrate.LabError):
                orchestrate.validate_selected_nat_command_chronology(
                    route_receipts=route_values,
                    capture_stderr=capture_values,
                    node_stderr=node_values,
                )

    def test_selected_nat_default_route_is_exact(self):
        gateway = "10.250.1.1"
        route = {
            "dev": "eth0",
            "dst": "default",
            "flags": [],
            "gateway": gateway,
        }
        self.assertEqual(
            orchestrate.validate_selected_nat_default_route(
                [dict(route)], gateway=gateway
            ),
            route,
        )
        mutations = {
            "missing-dev": lambda value: value.pop("dev"),
            "wrong-dev": lambda value: value.__setitem__("dev", "eth1"),
            "missing-flags": lambda value: value.pop("flags"),
            "nonempty-flags": lambda value: value.__setitem__("flags", ["onlink"]),
            "wrong-flags-type": lambda value: value.__setitem__("flags", {}),
            "unexpected-field": lambda value: value.__setitem__("protocol", "static"),
            "wrong-gateway": lambda value: value.__setitem__(
                "gateway", "10.250.1.254"
            ),
        }
        for name, mutate in mutations.items():
            with self.subTest(name=name):
                mutated = dict(route)
                mutate(mutated)
                with self.assertRaises(orchestrate.LabError):
                    orchestrate.validate_selected_nat_default_route(
                        [mutated], gateway=gateway
                    )
        for malformed in ([], [route, route], route, None):
            with self.subTest(malformed=malformed), self.assertRaises(
                orchestrate.LabError
            ):
                orchestrate.validate_selected_nat_default_route(
                    malformed, gateway=gateway
                )

    def test_selected_nat_project_writer_replays_byte_identically(self):
        document = {"schema": "test", "z": 1, "a": [True, "ascii"]}
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            first = root / "first.json"
            second = root / "second.json"
            with mock.patch.object(
                orchestrate, "project_selected_nat_receipt", return_value=document
            ), contextlib.redirect_stdout(io.StringIO()):
                orchestrate.run_selected_nat_project(mock.Mock(raw_root=root, output=first))
                orchestrate.run_selected_nat_project(mock.Mock(raw_root=root, output=second))
            self.assertEqual(first.read_bytes(), second.read_bytes())
            self.assertEqual(
                first.read_bytes(),
                b'{"a":[true,"ascii"],"schema":"test","z":1}\n',
            )

    def test_selected_nat_projection_matches_independent_receipt_schema(self):
        receipt_test_path = (
            orchestrate.WORKSPACE / "tools" / "test-selected-iroh-nat-receipt.py"
        )
        spec = importlib.util.spec_from_file_location(
            "selected_nat_receipt_fixture", receipt_test_path
        )
        assert spec is not None and spec.loader is not None
        fixture = importlib.util.module_from_spec(spec)
        sys.modules[spec.name] = fixture
        spec.loader.exec_module(fixture)
        baseline = fixture.baseline()
        projection_authorities = {
            profile: hashlib.sha256(f"{profile}-mission-authority".encode()).hexdigest()
            for profile in ("cone-direct", "restrictive-relay")
        }
        projected_public_ids = {
            endpoint[field]
            for cell in baseline["cells"]
            for endpoint in cell["endpoints"]
            for field in ("carrier_id", "mission_id")
        }
        self.assertTrue(set(projection_authorities.values()).isdisjoint(projected_public_ids))
        container = baseline["build"]["container"]
        container["base_image"] = orchestrate.LAB_BASE_IMAGE
        command_context = orchestrate.RunContext(
            label="test",
            run_id=container["build_run_id"],
            run_dir=Path("/private/tmp/aster-selected-nat"),
            resources=[],
            runner=mock.Mock(),
        )
        baseline["build"]["command"] = orchestrate.shlex.join(
            orchestrate.selected_nat_build_arguments(
                command_context,
                Path("/private/tmp/aster-selected-nat/build-context"),
                container["input_manifest_sha256"],
            )
        )
        source = {
            "schema": orchestrate.SCHEMA,
            "commit": baseline["source"]["commit"],
            "tree": baseline["source"]["tree"],
            "tracked_and_untracked_nonignored_clean": True,
            "commit_signature_verified": True,
            "cargo_toml_sha256": "1" * 64,
            "cargo_lock_sha256": baseline["source"]["cargo_lock_sha256"],
            "requirements_sha256": baseline["source"]["requirements_sha256"],
            "dockerfile_sha256": container["dockerfile_sha256"],
            "build_input_manifest_sha256": container["input_manifest_sha256"],
        }
        environment = {
            "host_os": baseline["environment"]["host_os"],
            "host_arch": baseline["environment"]["host_arch"],
            "kernel": baseline["environment"]["kernel"],
            "docker_version": baseline["environment"]["docker_version"],
            "orbstack_version": baseline["environment"]["orbstack_version"],
        }
        build = {
            "command": baseline["build"]["command"],
            "dockerfile_sha256": container["dockerfile_sha256"],
            "input_manifest_sha256": container["input_manifest_sha256"],
            "build_run_id": container["build_run_id"],
            "image_id": container["image_id"],
            "image_config_digest": container["image_config_digest"],
            "environment": environment,
        }
        summary = {
            "profile": "all",
            "status": "pass",
            "source_identity": source,
            "build_identity": build,
        }
        inventory = [
            {**artifact, "path": f"/usr/local/bin/{artifact['name']}"}
            for artifact in baseline["build"]["artifacts"]
        ]

        def load(path, **_kwargs):
            if path.name == "selected-nat-suite.json":
                return summary
            if path.name == "source-identity.json":
                return source
            if path.name == "selected-build.json":
                return build
            if path.name == "binary-inventory.json":
                return inventory
            if path.name == "image-identity.json":
                return {"id": container["image_id"]}
            if path.name == "selected-nat-runtime.json":
                profile = path.parent.name
                cell = baseline["cells"][
                    0 if profile == "cone-direct" else 1
                ]
                return {
                    "profile": profile,
                    "mission_authority": projection_authorities[profile],
                    "nodes": {
                        "a": {
                            "mission_id": cell["endpoints"][0]["mission_id"],
                            "carrier_id": cell["endpoints"][0]["carrier_id"],
                        },
                        "b": {
                            "mission_id": cell["endpoints"][1]["mission_id"],
                            "carrier_id": cell["endpoints"][1]["carrier_id"],
                        },
                    },
                }
            raise AssertionError(f"unexpected projection input: {path}")

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            with mock.patch.object(
                orchestrate, "validate_selected_nat_control_file_absence"
            ), mock.patch.object(
                orchestrate, "load_selected_nat_json", side_effect=load
            ), mock.patch.object(
                orchestrate,
                "project_selected_nat_cell",
                side_effect=baseline["cells"],
            ), mock.patch.object(
                orchestrate,
                "selected_nat_curated_manifest",
                return_value=baseline["raw_manifest"],
            ):
                projected = orchestrate.project_selected_nat_receipt(root)
        fixture.CHECKER.validate_receipt(projected)
        self.assertEqual(projected["source"], baseline["source"])
        self.assertEqual(projected["build"], baseline["build"])

        source["build_input_manifest_sha256"] = "e" * 64
        with tempfile.TemporaryDirectory() as temporary:
            with mock.patch.object(
                orchestrate, "validate_selected_nat_control_file_absence"
            ), mock.patch.object(
                orchestrate, "load_selected_nat_json", side_effect=load
            ):
                with self.assertRaisesRegex(orchestrate.LabError, "input bindings differ"):
                    orchestrate.project_selected_nat_receipt(Path(temporary))

    def test_selected_nat_prune_then_real_projection_retains_provenance(self):
        receipt_test_path = (
            orchestrate.WORKSPACE / "tools" / "test-selected-iroh-nat-receipt.py"
        )
        spec = importlib.util.spec_from_file_location(
            "selected_nat_prune_projection_fixture", receipt_test_path
        )
        assert spec is not None and spec.loader is not None
        fixture = importlib.util.module_from_spec(spec)
        sys.modules[spec.name] = fixture
        spec.loader.exec_module(fixture)
        baseline = fixture.baseline()
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            root.chmod(0o700)
            fixture.materialize_raw_root(root, baseline)
            orchestrate.prune_selected_nat_transient_artifacts(
                root, require_complete=False
            )
            self.assertTrue((root / "source-identity.json").is_file())
            self.assertTrue((root / "selected-build.json").is_file())
            projected = orchestrate.project_selected_nat_receipt(root)
            self.assertEqual(projected, baseline)
            fixture.CHECKER.validate_receipt(projected)
            fixture.CHECKER.verify_raw_root(root, projected)

    def test_selected_cleanup_events_bind_resource_roles(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            resources = [
                orchestrate.PlannedResource(
                    "container", "aster-lab-provision", "provision"
                ),
                orchestrate.PlannedResource("network", "aster-lab-lan-a", "lan-a"),
            ]
            context = orchestrate.RunContext(
                label="cone-direct",
                run_id="0123456789abcdef",
                run_dir=root,
                resources=resources,
                runner=mock.Mock(),
                image=orchestrate.SELECTED_NAT_IMAGE,
            )
            context.runner.run.return_value = mock.Mock(
                returncode=0, stdout="", stderr=""
            )
            owned = {
                orchestrate.MANAGED_LABEL: "true",
                orchestrate.RUN_LABEL: context.run_id,
                orchestrate.ROLE_LABEL: "lan-a",
            }
            with mock.patch.object(
                orchestrate, "verify_orbstack", return_value=("docker", {})
            ), mock.patch.object(
                orchestrate, "require_docker", return_value="docker"
            ), mock.patch.object(
                orchestrate, "inspect_labels", side_effect=[None, owned]
            ), mock.patch.object(
                orchestrate, "docker_resource_present", return_value=False
            ):
                orchestrate.cleanup_selected_nat_context(
                    context, tolerate_errors=False
                )
            events = [
                json.loads(line)
                for line in (root / "events.jsonl").read_text().splitlines()
            ]
            self.assertEqual(
                [
                    {
                        key: value
                        for key, value in record.items()
                        if key != "utc"
                    }
                    for record in events
                ],
                [
                    {
                        "schema": orchestrate.SCHEMA,
                        "run_id": context.run_id,
                        "profile": "cone-direct",
                        "event": "cleanup-absent",
                        "kind": "container",
                        "name": "aster-lab-provision",
                        "role": "provision",
                    },
                    {
                        "schema": orchestrate.SCHEMA,
                        "run_id": context.run_id,
                        "profile": "cone-direct",
                        "event": "resource-removed",
                        "kind": "network",
                        "name": "aster-lab-lan-a",
                        "role": "lan-a",
                    },
                ],
            )

    def test_selected_cleanup_never_calls_legacy_finalization(self):
        with tempfile.TemporaryDirectory() as temporary:
            context = self.context(Path(temporary))
            with mock.patch.object(
                orchestrate, "verify_orbstack", return_value=("docker", {})
            ), mock.patch.object(
                orchestrate, "cleanup_context", side_effect=AssertionError("legacy cleanup")
            ):
                orchestrate.cleanup_selected_nat_context(
                    context, tolerate_errors=False
                )


if __name__ == "__main__":
    unittest.main()
