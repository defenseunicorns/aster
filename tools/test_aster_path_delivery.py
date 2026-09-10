#!/usr/bin/env python3
# Copyright 2026 Defense Unicorns, Inc.
# SPDX-License-Identifier: Apache-2.0
"""Focused tests for the bounded real-Event path-delivery controller."""

from __future__ import annotations

import base64
from contextlib import contextmanager, nullcontext
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
    # Docker installs the controller beside these scripts. Bind the exact
    # dynamically loaded test instance while importing, without changing
    # sys.path or leaving a controller cached for unrelated test modules.
    with mock.patch.dict(sys.modules, {"aster_path_delivery": MODULE}):
        spec.loader.exec_module(module)
    return module


class TestImportIsolationTests(unittest.TestCase):
    def test_module_and_discovery_invocations_without_pythonpath(self):
        env = dict(MODULE.os.environ)
        env.pop("PYTHONPATH", None)
        # Select only the controller cases so subprocess discovery cannot recurse
        # into this invocation regression test.
        invocations = (
            ["tools.test_aster_path_delivery.PathDeliveryControllerTests"],
            ["discover", "-s", "tools", "-p", "test_aster_path_delivery.py",
             "-k", "PathDeliveryControllerTests"],
        )
        for args in invocations:
            with self.subTest(args=args):
                result = subprocess.run(
                    [sys.executable, "-m", "unittest", *args],
                    cwd=MODULE_PATH.resolve().parents[1], env=env,
                    stdin=subprocess.DEVNULL, capture_output=True, text=True,
                    timeout=60,
                )
                self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
                self.assertNotIn("Ran 0 tests", result.stderr)
                self.assertIn("\nOK\n", result.stderr)

    def test_helper_imports_use_this_controller_without_leaking_registry_state(self):
        for existing in (None, mock.sentinel.other_controller):
            with self.subTest(existing=existing), mock.patch.dict(sys.modules):
                if existing is None:
                    sys.modules.pop("aster_path_delivery", None)
                else:
                    sys.modules["aster_path_delivery"] = existing
                before_path = list(sys.path)
                for name in ("delivery-wan.py", "delivery-network-init.py"):
                    helper = load_script(name)
                    self.assertIs(helper._run_command, MODULE._run_command)
                    self.assertIs(helper._strict_json, MODULE._strict_json)
                    self.assertIs(helper.ExecutionError, MODULE.ExecutionError)
                    self.assertEqual(sys.path, before_path)
                    if existing is None:
                        self.assertNotIn("aster_path_delivery", sys.modules)
                    else:
                        self.assertIs(sys.modules["aster_path_delivery"], existing)


def unpin(argv):
    if argv[1:3] == ["--host", "unix:///var/run/docker.sock"]:
        return [argv[0], *argv[3:]]
    return argv


class FakeDocker:
    def __init__(self):
        self.calls = []
        self.roles = {}
        self.ids = []
        self.event_id = base64.b64encode(bytes(range(32))).decode()

    def __call__(self, argv, timeout):
        argv = unpin(argv)
        self.calls.append(argv)
        assert 0 < timeout <= 90
        if argv[1:3] == ["network", "create"]:
            return ("d" if "10.77.1.0/29" in argv else "e").encode() * 64
        if argv[1] == "create":
            path = Path(argv[argv.index("--cidfile") + 1])
            cid = f"{len(self.ids) + 1:064x}"
            self.ids.append(cid)
            self.roles[path.stem] = cid
            path.write_text(cid)
            path.chmod(0o600)
            return cid.encode()
        if argv[1] == "wait":
            return b"0\n"
        if argv[1:3] == ["start", "--attach"] and argv[-1] == self.roles.get("wan-setup"):
            return json.dumps([{**MODULE.FIXED_NETEM, "address": f"10.77.{i}.1", "interface": f"eth{i-1}"} for i in (1, 2)]).encode()
        if "status" in argv:
            return json.dumps({"identity": self.event_id, "missionAuthority": self.event_id,
                               "sync": "AWAITING_AUTHENTICATED_CONTACT"}).encode()
        if "verify" in argv:
            return b"CAPABILITIES status=pass\n"
        if "publish" in argv:
            return self.event_id.encode()
        if "wait" in argv and argv[1] == "exec":
            return json.dumps({"id": self.event_id, "logicalKey": base64.b64encode(b"dispatch/one").decode(),
                               "payload": base64.b64encode(b"bounded real Event over routed netem").decode()}).encode()
        return b""


class ExecutableTrustTests(unittest.TestCase):
    @contextmanager
    def filesystem(self, changes=None, links=None):
        # Root ownership cannot be created by this unprivileged Darwin suite.
        # Model Linux lstat/readlink only; run the real trust validator.
        directory = MODULE.stat.S_IFDIR | 0o755
        regular = MODULE.stat.S_IFREG | 0o755
        rows = {"/": (0, directory), "/usr": (0, directory),
                "/usr/bin": (0, directory), "/usr/bin/ip": (0, regular),
                "/usr/bin/docker": (0, regular)}
        rows.update(changes or {})
        def lstat(path):
            if str(path) not in rows:
                raise FileNotFoundError(str(path))
            uid, mode = rows[str(path)]
            return MODULE.os.stat_result((mode, 1, 1, 1, uid, 0, 0, 0, 0, 0))
        with mock.patch.object(Path, "lstat", lstat), \
                mock.patch.object(MODULE.os, "readlink", side_effect=lambda p: (links or {})[str(p)]), \
                mock.patch.object(MODULE.os, "access", return_value=True):
            yield

    def test_rejects_untrusted_executable_or_ancestor_for_ip_and_docker(self):
        for name in ("ip", "docker"):
            for path in ("/", "/usr", "/usr/bin", "/usr/bin/" + name):
                kind = MODULE.stat.S_IFREG if path.endswith("/" + name) else MODULE.stat.S_IFDIR
                for uid, mode in ((1000, 0o755), (0, 0o775), (0, 0o757), (1000, 0o777)):
                    with self.subTest(name=name, path=path, uid=uid, mode=oct(mode)), \
                            self.filesystem({path: (uid, kind | mode)}):
                        with self.assertRaises(MODULE.ExecutionError):
                            MODULE._regular_executable(Path("/usr/bin/" + name), name)

    def test_resolves_trusted_merged_usr_and_executable_symlinks(self):
        link = MODULE.stat.S_IFLNK | 0o777
        for target in ("usr/bin", "/usr/bin"):
            with self.subTest(target=target), self.filesystem(
                    {"/sbin": (0, link)}, {"/sbin": target}):
                self.assertEqual(MODULE._regular_executable(Path("/sbin/ip"), "ip"),
                                 Path("/usr/bin/ip"))
        with self.filesystem({"/usr/bin/ip": (0, link),
                              "/usr/sbin": (0, MODULE.stat.S_IFDIR | 0o755),
                              "/usr/sbin/ip": (0, MODULE.stat.S_IFREG | 0o755)},
                             {"/usr/bin/ip": "../sbin/ip"}):
            self.assertEqual(MODULE._regular_executable(Path("/usr/bin/ip"), "ip"),
                             Path("/usr/sbin/ip"))

    def test_rejects_untrusted_symlink_routes_and_targets(self):
        link = MODULE.stat.S_IFLNK | 0o777
        directory = MODULE.stat.S_IFDIR | 0o755
        for changes, links in (
                ({"/sbin": (1000, link)}, {"/sbin": "usr/bin"}),
                ({"/sbin": (0, link), "/usr": (1000, directory)}, {"/sbin": "usr/bin"}),
                ({"/sbin": (0, link), "/usr/bin/ip": (0, MODULE.stat.S_IFREG | 0o777)}, {"/sbin": "usr/bin"}),
                ({"/sbin": (0, link), "/unsafe": (0, directory | 0o022)}, {"/sbin": "/unsafe/../usr/bin"}),
                ({"/sbin": (0, link)}, {"/sbin": "/missing"}),
                ({"/sbin": (0, link)}, {"/sbin": "/sbin"}),
                ({"/sbin": (0, directory), "/sbin/ip": (1000, link)}, {"/sbin/ip": "/usr/bin/ip"}),
        ):
            with self.subTest(changes=changes, links=links), self.filesystem(changes, links):
                with self.assertRaises(MODULE.ExecutionError):
                    MODULE._regular_executable(Path("/sbin/ip"), "ip")

    def test_preflight_resolves_system_tools_without_path_search(self):
        link = MODULE.stat.S_IFLNK | 0o777
        for override in (Path("/bin/docker"), None):
            with self.subTest(override=override), \
                    self.filesystem({"/bin": (0, link)}, {"/bin": "usr/bin"}), \
                    mock.patch.object(MODULE.platform, "system", return_value="Linux"), \
                    mock.patch.object(MODULE.os, "geteuid", return_value=0), \
                    mock.patch.dict(MODULE.os.environ, {"PATH": "/attacker", "DOCKER_HOST": "", "DOCKER_CONTEXT": ""}), \
                    mock.patch.object(MODULE.shutil, "which", side_effect=AssertionError("PATH discovery")), \
                    mock.patch.object(MODULE, "_run_command", side_effect=[
                        b"unix:///var/run/docker.sock\n", b'{"OSType":"linux","SecurityOptions":[]}']) as run:
                self.assertEqual(MODULE.preflight(override),
                                 (Path("/usr/bin/docker"), Path("/usr/bin/ip")))
                self.assertTrue(all(call.args[0][0] == "/usr/bin/docker" for call in run.call_args_list))

    def test_system_resolution_fails_closed_without_trusted_candidate(self):
        for name in ("ip", "docker"):
            with self.subTest(name=name), \
                    self.filesystem({"/usr/bin/" + name: (1000, MODULE.stat.S_IFREG | 0o777)}), \
                    mock.patch.object(MODULE.shutil, "which", side_effect=AssertionError("PATH fallback")):
                with self.assertRaisesRegex(MODULE.ExecutionError, "trusted host " + name):
                    MODULE._system_executable(name)

    def test_untrusted_docker_override_is_rejected_before_any_command(self):
        with self.filesystem({"/usr/bin/docker": (1000, MODULE.stat.S_IFREG | 0o777)}), \
                mock.patch.object(MODULE.platform, "system", return_value="Linux"), \
                mock.patch.object(MODULE.os, "geteuid", return_value=0), \
                mock.patch.dict(MODULE.os.environ, {"DOCKER_HOST": "", "DOCKER_CONTEXT": ""}), \
                mock.patch.object(MODULE, "_run_command") as run:
            with self.assertRaises(MODULE.ExecutionError):
                MODULE.preflight(Path("/usr/bin/docker"))
            run.assert_not_called()

    def test_rejects_wrong_type_name_relative_path_or_nonexecutable(self):
        for path in (Path("ip"), Path("/usr/bin/docker"), Path("/missing/ip")):
            with self.subTest(path=path), self.filesystem():
                with self.assertRaises(MODULE.ExecutionError):
                    MODULE._regular_executable(path, "ip")
        for kind in (MODULE.stat.S_IFDIR, MODULE.stat.S_IFIFO, MODULE.stat.S_IFSOCK):
            with self.subTest(kind=kind), self.filesystem({"/usr/bin/ip": (0, kind | 0o755)}):
                with self.assertRaises(MODULE.ExecutionError):
                    MODULE._regular_executable(Path("/usr/bin/ip"), "ip")
        with self.filesystem(), mock.patch.object(MODULE.os, "access", return_value=False):
            with self.assertRaises(MODULE.ExecutionError):
                MODULE._regular_executable(Path("/usr/bin/ip"), "ip")


class NamespaceOwnershipTests(unittest.TestCase):
    @contextmanager
    def fixture(self, mutation=None):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            fake = FakeDocker()
            owned = MODULE.OwnedDocker("docker", root, fake)
            holders = {role: owned.create(role, ["--network", "none"], ["sleep", "600"])
                       for role in ("wan", "node-a", "node-b")}
            paths = {}
            for index, cid in enumerate(holders.values()):
                target = root / ("namespace-" + str(index))
                target.touch()
                paths["/var/run/docker/netns/" + cid[:12] + str(index)] = target
            host = root / "host-namespace"
            host.touch()
            snapshots = {cid: {"id": cid, "running": True, "network": "none",
                              "labels": dict([owned.label.split("=", 1)]), "key": key}
                         for cid, key in zip(holders.values(), paths)}
            if mutation:
                mutation(snapshots, paths, host)
            def inspect(argv, timeout):
                argv = unpin(argv)
                fake.calls.append(argv)
                self.assertEqual(argv[1], "inspect")
                return json.dumps(snapshots[argv[-1]]).encode()
            owned.run = MODULE._pinned_docker(inspect)
            original_open, original_stat = MODULE.os.open, MODULE.os.stat
            flags_seen, opened = [], []
            def open_namespace(path, flags, *args, **kwargs):
                if path in paths:
                    flags_seen.append(flags)
                    fd = original_open(paths[path], flags, *args, **kwargs)
                    opened.append(fd)
                    return fd
                return original_open(path, flags, *args, **kwargs)
            def stat_namespace(path, *args, **kwargs):
                return original_stat(host if path == "/proc/self/ns/net" else paths.get(path, path), *args, **kwargs)
            with mock.patch.object(MODULE.os, "open", side_effect=open_namespace), \
                    mock.patch.object(MODULE.os, "stat", side_effect=stat_namespace), \
                    mock.patch.object(MODULE.fcntl, "ioctl", return_value=0x40000000) as ioctl:
                yield owned, holders, flags_seen, opened, ioctl

    def test_namespace_pins_are_nonblocking_and_closed_when_link_setup_fails(self):
        with self.fixture() as (owned, holders, flags, opened, ioctl):
            with self.assertRaisesRegex(RuntimeError, "link failed"):
                with MODULE._namespace_files(owned, holders) as references:
                    self.assertEqual(set(references), set(holders))
                    for ref, fd in zip(references.values(), opened):
                        self.assertEqual(ref, f"/proc/{MODULE.os.getpid()}/fd/{fd}")
                        MODULE.os.fstat(fd)
                    raise RuntimeError("link failed")
            self.assertEqual(len(opened), 3)
            for fd in opened:
                with self.assertRaises(OSError):
                    MODULE.os.fstat(fd)
            self.assertTrue(all(flag & MODULE.os.O_NOFOLLOW for flag in flags))
            self.assertTrue(all(flag & MODULE.os.O_NONBLOCK for flag in flags),
                            "namespace open could block on an unexpected file type")
            self.assertEqual(ioctl.call_count, 3)

    def test_namespace_identity_rejections_release_all_acquired_handles(self):
        for case in ("foreign-id", "foreign-label", "stopped", "host-mode", "path",
                     "shared", "host-netns", "wrong-type", "unowned", "changed"):
            def mutate(snapshots, paths, host):
                rows = list(snapshots.values())
                if case == "foreign-id":
                    rows[1]["id"] = "f" * 64
                elif case == "foreign-label":
                    rows[1]["labels"] = {}
                elif case == "stopped":
                    rows[1]["running"] = False
                elif case == "host-mode":
                    rows[1]["network"] = "host"
                elif case == "path":
                    rows[1]["key"] = "/proc/1/ns/net"
                elif case == "shared":
                    paths[rows[1]["key"]] = paths[rows[0]["key"]]
                elif case == "host-netns":
                    paths[rows[1]["key"]] = host
            with self.subTest(case=case), self.fixture(mutate) as (owned, holders, flags, opened, ioctl):
                if case == "wrong-type":
                    ioctl.return_value = 0x10000000
                if case == "unowned":
                    owned.containers.remove(holders["node-a"])
                if case == "changed":
                    original_run = owned.run
                    count = 0
                    def changed(argv, timeout):
                        nonlocal count
                        count += 1
                        value = json.loads(original_run(argv, timeout))
                        if count == 2:
                            value["running"] = False
                        return json.dumps(value).encode()
                    owned.run = changed
                with self.assertRaises(MODULE.ExecutionError):
                    with MODULE._namespace_files(owned, holders):
                        self.fail("unsafe namespace reached link creation")
                for fd in opened:
                    with self.assertRaises(OSError):
                        MODULE.os.fstat(fd)


class PathDeliveryControllerTests(unittest.TestCase):
    def test_manifest_file_fsync_failure_preserves_previous_checkpoint(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            owned = MODULE.OwnedDocker("docker", root, FakeDocker())
            previous = (root / "ownership.json").read_bytes()
            owned.phase = "next-phase"
            with mock.patch.object(MODULE.os, "fsync", side_effect=OSError("fsync failed")):
                with self.assertRaises(OSError):
                    owned.persist()
            self.assertEqual((root / "ownership.json").read_bytes(), previous)
            self.assertEqual([p.name for p in root.iterdir()], ["ownership.json"])
            synchronized = []
            original = MODULE.os.fsync
            def fsync(fd):
                synchronized.append(MODULE.stat.S_ISDIR(MODULE.os.fstat(fd).st_mode))
                original(fd)
            with mock.patch.object(MODULE.os, "fsync", side_effect=fsync):
                owned.persist()
            self.assertEqual(synchronized, [False, True], "file and directory must both be synchronized")

    def test_interrupted_manifest_temporary_does_not_block_cleanup(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            owned = MODULE.OwnedDocker("docker", root, FakeDocker())
            interrupted = root / "ownership.next"
            interrupted.write_bytes(b"interrupted ownership metadata")
            interrupted.chmod(0o600)
            try:
                errors = owned.cleanup()
            except OSError:
                self.fail("interrupted temporary blocked owned cleanup persistence")
            self.assertEqual(errors, [])
            self.assertEqual(json.loads((root / "ownership.json").read_bytes())["phase"], "absent")
            self.assertEqual(interrupted.read_bytes(), b"interrupted ownership metadata")

    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.recovery = Path(temporary.name) / "recovery"
        patcher = mock.patch.object(MODULE, "RECOVERY_DIRECTORY", self.recovery, create=True)
        patcher.start()
        self.addCleanup(patcher.stop)
        namespace_patcher = mock.patch.object(
            MODULE, "_namespace_files", create=True,
            side_effect=lambda *_: nullcontext({"wan": "/proc/42/fd/4",
                                                "node-a": "/proc/42/fd/5",
                                                "node-b": "/proc/42/fd/6"}))
        namespace_patcher.start()
        self.addCleanup(namespace_patcher.stop)

    def test_manifest_write_outage_keeps_locator_and_attempts_every_owned_cleanup(self):
        fake = FakeDocker()
        original = MODULE.OwnedDocker.persist
        def persist(owned):
            if owned.containers:
                raise OSError("sensitive persistence diagnostic")
            original(owned)
        raw = (MODULE_PATH.parents[1] / "docker/path-lab/scenarios/event-delivery-netem.json").read_bytes()
        with mock.patch.object(MODULE.OwnedDocker, "persist", new=persist):
            try:
                MODULE.execute_direct(raw, docker=Path("docker"), ip=Path("/usr/sbin/ip"), run=fake)
            except MODULE.ExecutionError as error:
                self.assertIn(MODULE.RECOVERY_LOCATOR, str(error))
                self.assertNotIn("sensitive", str(error))
            except OSError:
                self.fail("manifest failure escaped without recovery locator")
            else:
                self.fail("manifest outage passed")
        self.assertTrue(self.recovery.is_dir())
        self.assertTrue((self.recovery / "ownership.json").is_file())
        self.assertTrue((self.recovery / "wan.cid").is_file())
        self.assertEqual({c[-1] for c in fake.calls if c[1:3] == ["rm", "--force"]}, set(fake.ids))

    def test_every_daemon_call_is_pinned_despite_context_changes(self):
        # Docker calls only; host setup is separately scoped below.
        fake = FakeDocker()
        def record(command, timeout):
            if Path(command[0]).name == "docker":
                self.assertEqual(command[1:3], ["--host", "unix:///var/run/docker.sock"])
            return fake(command, timeout)
        raw = (MODULE_PATH.parents[1] / "docker/path-lab/scenarios/event-delivery-netem.json").read_bytes()
        with mock.patch.dict(MODULE.os.environ, {"DOCKER_CONTEXT": "changed-concurrently"}):
            MODULE.execute_direct(raw, docker=Path("docker"), ip=Path("/usr/sbin/ip"), run=record)

    def test_initial_manifest_failure_reports_locator_without_daemon_actions(self):
        fake = FakeDocker()
        raw = (MODULE_PATH.parents[1] / "docker/path-lab/scenarios/event-delivery-netem.json").read_bytes()
        with mock.patch.object(MODULE.OwnedDocker, "persist", side_effect=OSError("private detail")):
            try:
                MODULE.execute_direct(raw, docker=Path("docker"), ip=Path("/usr/sbin/ip"), run=fake)
            except MODULE.ExecutionError as error:
                self.assertIn(MODULE.RECOVERY_LOCATOR, str(error))
                self.assertNotIn("private detail", str(error))
            except OSError:
                self.fail("initial manifest failure lost recovery locator")
            else:
                self.fail("initial manifest failure passed")
        self.assertEqual(fake.calls, [])
        self.assertTrue(self.recovery.is_dir())

    def test_second_veth_timeout_cleans_holders_and_retains_ambiguous_recovery(self):
        fake = FakeDocker()
        links = 0
        def run(argv, timeout):
            nonlocal links
            value = fake(argv, timeout)
            if argv[1:3] == ["link", "add"]:
                links += 1
                if links == 2:
                    raise MODULE.ExecutionError("delivery command timed out")
            return value
        raw = (MODULE_PATH.parents[1] / "docker/path-lab/scenarios/event-delivery-netem.json").read_bytes()
        with self.assertRaises(MODULE.ExecutionError) as error:
            MODULE.execute_direct(raw, docker=Path("docker"), ip=Path("/usr/sbin/ip"), run=run)
        self.assertIn("primary=veth-create code=command-timeout", str(error.exception))
        self.assertIn(MODULE.RECOVERY_LOCATOR, str(error.exception))
        self.assertEqual({c[-1] for c in fake.calls if c[1:3] == ["rm", "--force"]}, set(fake.ids))
        self.assertFalse(any("publish" in c for c in fake.calls))
        manifest = json.loads((self.recovery / "ownership.json").read_bytes())
        self.assertTrue(manifest["create_ambiguous"])
        self.assertEqual(manifest["phase"], "recovery-required")
        self.assertTrue((self.recovery / "lab").is_dir())

    def test_failed_create_remains_recoverable_after_empty_daemon_listing(self):
        calls = []
        def run(argv, timeout):
            argv = unpin(argv)
            calls.append(argv)
            if "create" in argv:
                raise MODULE.ExecutionError("delivery command timed out")
            return b""
        raw = (MODULE_PATH.parents[1] / "docker/path-lab/scenarios/event-delivery-netem.json").read_bytes()
        with self.assertRaises(MODULE.ExecutionError) as error:
            MODULE.execute_direct(raw, docker=Path("docker"), ip=Path("/usr/sbin/ip"), run=run)
        self.assertIn("recovery=/run/lock/aster-path-delivery/recovery", str(error.exception))
        self.assertTrue(self.recovery.is_dir())
        data = json.loads((self.recovery / "ownership.json").read_bytes())
        self.assertTrue(data["create_ambiguous"])
        self.assertEqual(data["phase"], "recovery-required")
        before = len(calls)
        with self.assertRaisesRegex(MODULE.ExecutionError, "recovery-pending"):
            MODULE.execute_direct(raw, docker=Path("docker"), ip=Path("/usr/sbin/ip"), run=run)
        self.assertEqual(len(calls), before)
        # A CLI timeout is not cancellation: the late ID can still be found by
        # the persisted label; an empty immediate listing must not retire it.
        self.assertRegex(data["label"], r"^aster.path-delivery=[0-9a-f]{32}$")

    def test_cleanup_outage_retains_private_recovery_state(self):
        fake = FakeDocker()
        def run(argv, timeout):
            argv = unpin(argv)
            value = fake(argv, timeout)
            if argv[1] in ("rm", "ps") or argv[1:3] == ["network", "ls"]:
                raise MODULE.ExecutionError("daemon-unavailable")
            return value
        raw = (MODULE_PATH.parents[1] / "docker/path-lab/scenarios/event-delivery-netem.json").read_bytes()
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary) / "recovery"
            with mock.patch.object(MODULE, "RECOVERY_DIRECTORY", directory):
                with self.assertRaises(MODULE.ExecutionError):
                    MODULE.execute_direct(raw, docker=Path("docker"), ip=Path("/usr/sbin/ip"), run=run)
            self.assertTrue(directory.exists(), "unconfirmed absence destroyed recovery state")
            manifest = directory / "ownership.json"
            self.assertEqual(manifest.stat().st_mode & 0o777, 0o600)
            data = json.loads(manifest.read_bytes())
            self.assertEqual(set(data["containers"]), set(fake.ids))
            self.assertRegex(data["label"], r"^aster.path-delivery=[0-9a-f]{32}$")
            self.assertEqual(data["phase"], "recovery-required")
            self.assertTrue((directory / "wan.cid").exists())
            self.assertTrue((directory / "lab").exists())

    def test_output_failure_reaping_has_an_explicit_deadline(self):
        provision = load_script("delivery-provision.py")
        original_wait = subprocess.Popen.wait
        waits = []
        def wait(process, *args, **kwargs):
            waits.append(kwargs.get("timeout"))
            return original_wait(process, *args, **kwargs)
        argv = [sys.executable, "-c", "import os; chunk=b'x'*4096\nwhile True: os.write(1, chunk)"]
        with mock.patch.object(subprocess.Popen, "wait", new=wait), mock.patch.object(MODULE, "MAX_OUTPUT_BYTES", 1024), mock.patch.object(provision, "MAX_INITIALIZER_OUTPUT_BYTES", 1024):
            with self.assertRaises(MODULE.ExecutionError):
                MODULE._run_command(argv, 5)
            with self.assertRaises(ValueError):
                provision.run_initializer(argv, 5)
        self.assertTrue(waits)
        self.assertTrue(all(value is not None and value <= 5 for value in waits), waits)

    def test_scenario_fifo_is_rejected_without_waiting_for_a_writer(self):
        with tempfile.TemporaryDirectory() as directory:
            fifo = Path(directory) / "scenario.json"
            MODULE.os.mkfifo(fifo)
            try:
                completed = subprocess.run([sys.executable, str(MODULE_PATH), str(fifo)],
                                           stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                                           stderr=subprocess.PIPE, timeout=1)
            except subprocess.TimeoutExpired:
                self.fail("scenario input blocks on a FIFO")
            self.assertEqual(completed.returncode, 2)
            self.assertIn(b"regular", completed.stderr)

    def test_provision_stops_directory_inventory_at_three_entries(self):
        provision = load_script("delivery-provision.py")
        def entries():
            for name in ("identity.key", "mission.unprotected-reference.bundle", "unexpected"):
                yield Path(name)
            raise AssertionError("unbounded inventory")
        with mock.patch.object(Path, "iterdir", side_effect=lambda: entries()):
            with self.assertRaisesRegex(ValueError, "regular"):
                provision.copy_state(Path("source"), Path("target"))

    def test_provision_copy_bounds_each_generated_credential(self):
        provision = load_script("delivery-provision.py")
        with tempfile.TemporaryDirectory() as directory:
            source, target = Path(directory) / "source", Path(directory) / "target"
            source.mkdir()
            target.mkdir()
            for name in provision.STATE_FILES:
                (source / name).write_bytes(b"x" * 65537)
            with self.assertRaisesRegex(ValueError, "credential.*bound"):
                provision.copy_state(source, target)
            self.assertEqual(list(target.iterdir()), [])

    def test_command_timeout_reports_fixed_diagnostic_after_cleanup(self):
        fake = FakeDocker()
        def run(argv, timeout):
            argv = unpin(argv)
            value = fake(argv, timeout)
            if argv[1] == "create":
                raise MODULE.ExecutionError("delivery command timed out")
            return value
        raw = (MODULE_PATH.parents[1] / "docker/path-lab/scenarios/event-delivery-netem.json").read_bytes()
        with self.assertRaisesRegex(MODULE.ExecutionError, "code=command-timeout"):
            MODULE.execute_direct(raw, docker=Path("docker"), ip=Path("/usr/sbin/ip"), run=run)
        self.assertTrue(any(c[1:3] == ["rm", "--force"] for c in fake.calls))

    def test_cli_io_errors_do_not_echo_paths_or_raw_exception_text(self):
        with mock.patch.object(MODULE, "_read_scenario", side_effect=OSError("secret-path")), mock.patch("builtins.print") as output:
            self.assertEqual(MODULE.main(["scenario.json"]), 2)
        text = str(output.call_args)
        self.assertNotIn("secret-path", text)
        self.assertIn("input-io", text)

    def test_role_capabilities_cannot_be_broadened(self):
        with tempfile.TemporaryDirectory() as directory:
            owned = MODULE.OwnedDocker("docker", Path(directory), mock.Mock())
            for role, caps in (("wan", ("NET_ADMIN",)), ("provision", ("SYS_ADMIN",)), ("node-a-setup", ())):
                with self.subTest(role=role), self.assertRaisesRegex(MODULE.ExecutionError, "role-capabilities"):
                    owned.create(role, [], [], caps)

    def test_wan_malformed_address_shapes_fail_with_fixed_error(self):
        wan = load_script("delivery-wan.py")
        for value in (None, {}, ["bad"], [{"ifname": [], "addr_info": None}]):
            with self.subTest(value=value), self.assertRaisesRegex(RuntimeError, "wan-address"):
                wan.configure(lambda argv, timeout: json.dumps(value).encode())

    def test_unhashable_netem_readback_is_sanitized_and_cleanup_still_runs(self):
        fake = FakeDocker()
        def run(argv, timeout):
            argv = unpin(argv)
            value = fake(argv, timeout)
            if argv[1:3] == ["start", "--attach"] and argv[-1] == fake.roles.get("wan-setup"):
                rows = json.loads(value)
                rows[0]["interface"] = []
                return json.dumps(rows).encode()
            return value
        raw = (MODULE_PATH.parents[1] / "docker/path-lab/scenarios/event-delivery-netem.json").read_bytes()
        with self.assertRaisesRegex(MODULE.ExecutionError, "code=netem-readback"):
            MODULE.execute_direct(raw, docker=Path("docker"), ip=Path("/usr/sbin/ip"), run=run)

    def test_exact_event_failures_report_safe_codes_after_independent_cleanup(self):
        raw = (MODULE_PATH.parents[1] / "docker/path-lab/scenarios/event-delivery-netem.json").read_bytes()
        for field in ("id", "logicalKey", "payload"):
            fake = FakeDocker()
            def run(argv, timeout):
                argv = unpin(argv)
                value = fake(argv, timeout)
                if argv[1] == "exec" and "wait" in argv:
                    event = json.loads(value)
                    event[field] = "wrong"
                    return json.dumps(event).encode()
                if argv[1:3] == ["rm", "--force"]:
                    raise MODULE.ExecutionError("raw-secret")
                return value
            with self.subTest(field=field), self.assertRaises(MODULE.ExecutionError) as error:
                MODULE.execute_direct(raw, docker=Path("docker"), ip=Path("/usr/sbin/ip"), run=run)
            message = str(error.exception)
            self.assertIn("code=event-mismatch", message)
            self.assertNotIn("raw-secret", message)
            self.assertEqual(len([c for c in fake.calls if c[1:3] == ["network", "rm"]]), 0)
            self.assertEqual(len([c for c in fake.calls if c[1:3] == ["rm", "--force"]]), 3)

    def test_wan_readback_accepts_tc_alignment_whitespace(self):
        wan = load_script("delivery-wan.py")
        def run(argv, timeout):
            argv = unpin(argv)
            if argv[:3] == ["ip", "-j", "address"]:
                return json.dumps([{"ifname": f"eth{i}", "addr_info": [{"local": f"10.77.{i}.1"}]} for i in (1, 2)]).encode()
            if argv[:3] == ["tc", "qdisc", "show"]:
                return b"qdisc netem 8001: root refcnt 2 limit 1000 delay 40ms  5ms loss 1% rate 100Mbit\n"
            return b""
        self.assertEqual(len(wan.configure(run)), 2)

    def test_delivery_lane_removes_containerlab_and_packages_bounded_helpers(self):
        root = MODULE_PATH.parents[1]
        workflow = (root / ".github/workflows/ci.yml").read_text()
        lane = workflow.split("  path-delivery-smoke:", 1)[1].split("  macos-tests:", 1)[0]
        self.assertNotIn("containerlab", lane.lower())
        self.assertIn("test_aster_path_delivery.py", lane)
        self.assertFalse((root / "docker/path-lab/topology.delivery.clab.yml").exists())
        self.assertIn("!tools/aster_path_delivery.py", (root / ".dockerignore").read_text())
        self.assertIn("COPY tools/aster_path_delivery.py", (root / "docker/path-lab/Dockerfile.delivery").read_text())
        self.assertIn("USER 10001:10001", (root / "docker/path-lab/Dockerfile.delivery").read_text())

    def test_preflight_checks_actual_context_socket_and_rootless_state(self):
        with mock.patch.object(MODULE.platform, "system", return_value="Linux"), mock.patch.object(MODULE.os, "geteuid", return_value=0), mock.patch.object(MODULE, "_regular_executable"), mock.patch.dict(MODULE.os.environ, {"DOCKER_HOST": "", "DOCKER_CONTEXT": ""}):
            with mock.patch.object(MODULE, "_run_command", return_value=b"tcp://remote\n"):
                with self.assertRaisesRegex(MODULE.ExecutionError, "local"):
                    MODULE.preflight(Path("/usr/bin/docker"))
            with mock.patch.object(MODULE, "_run_command", side_effect=[b"unix:///var/run/docker.sock\n", b'{"OSType":"linux","SecurityOptions":["name=rootless"]}']):
                with self.assertRaisesRegex(MODULE.ExecutionError, "rootful"):
                    MODULE.preflight(Path("/usr/bin/docker"))

    def test_preflight_rejects_missing_host_ip_before_resource_creation(self):
        with mock.patch.object(MODULE.platform, "system", return_value="Linux"), \
                mock.patch.object(MODULE.os, "geteuid", return_value=0), \
                mock.patch.object(MODULE, "_regular_executable"), \
                mock.patch.dict(MODULE.os.environ, {"DOCKER_HOST": "", "DOCKER_CONTEXT": ""}), \
                mock.patch.object(MODULE, "_system_executable", side_effect=MODULE.ExecutionError("requires host ip")), \
                mock.patch.object(MODULE, "_run_command", side_effect=[
                    b"unix:///var/run/docker.sock\n", b'{"OSType":"linux","SecurityOptions":[]}']):
            with self.assertRaisesRegex(MODULE.ExecutionError, "host ip"):
                MODULE.preflight(Path("/usr/bin/docker"))

    def test_recursive_input_is_sanitized(self):
        nested = b"[" * 2000 + b"0" + b"]" * 2000
        with self.assertRaises(MODULE.ScenarioError):
            MODULE.compile_scenario(nested)
        with self.assertRaises(MODULE.ExecutionError):
            MODULE._strict_json(nested, "readback")

    def test_owner_directory_and_roles_fail_closed(self):
        with tempfile.TemporaryDirectory() as directory:
            parent = Path(directory)
            parent.chmod(0o755)
            with self.assertRaisesRegex(MODULE.ExecutionError, "directory"):
                MODULE.OwnedDocker("docker", parent, mock.Mock())
            parent.chmod(0o700)
            owned = MODULE.OwnedDocker("docker", parent, mock.Mock())
            with self.assertRaisesRegex(MODULE.ExecutionError, "role"):
                owned.create("../outside", [], [])


    def test_cleanup_detects_unattributed_labelled_resources_without_deleting_by_name(self):
        with tempfile.TemporaryDirectory() as directory:
            calls = []
            def run(argv, timeout):
                argv = unpin(argv)
                calls.append(argv)
                return b"f" * 64 + b"\n" if any(v.startswith("label=") for v in argv) else b""
            owned = MODULE.OwnedDocker("docker", Path(directory), run)
            self.assertEqual(owned.cleanup(), ["container-labelled-remains", "network-labelled-remains"])
            self.assertFalse(any("rm" in c for c in calls))

    def test_endpoint_setup_bounds_commands_and_verifies_selected_route(self):
        network = load_script("delivery-network-init.py")
        self.assertTrue(hasattr(network, "configure"), "bounded route verification is missing")
        calls = []
        def run(argv, timeout):
            argv = unpin(argv)
            calls.append(argv)
            self.assertLessEqual(timeout, 5)
            if argv[:4] == ["ip", "-j", "route", "get"]:
                return b'[{"dst":"10.77.2.2","gateway":"10.77.1.1","dev":"eth0","prefsrc":"10.77.1.2"}]'
            return b""
        network.configure("node-a", run)
        self.assertIn(["ip", "-j", "route", "get", "10.77.2.2"], calls)
        with self.assertRaises(RuntimeError):
            network.configure("node-a", lambda argv, timeout: b"[]")
        with self.assertRaisesRegex(MODULE.ExecutionError, "route-readback"):
            network.configure("node-a", lambda argv, timeout: (
                b'[{"gateway":"10.77.1.1","dev":"unexpected","prefsrc":"10.77.1.2"}]'))

    def test_peer_input_is_bounded_before_read(self):
        agent = load_script("delivery-agent.py")
        with tempfile.TemporaryDirectory() as directory:
            state = Path(directory)
            (state / "peer").write_text("a" * 64 + "@10.77.2.2:4433=" + "b" * 64)
            with mock.patch.object(Path, "read_bytes", side_effect=AssertionError("unbounded read")):
                self.assertIn("--peer", agent.agent_argv("node-a", state))

    def test_daemon_children_use_owner_only_umask(self):
        result = MODULE._run_command([sys.executable, "-c", "import os; print(oct(os.umask(0)))"], 5)
        self.assertEqual(result, b"0o77\n")

    def test_create_refuses_preexisting_cidfile_before_contacting_daemon(self):
        with tempfile.TemporaryDirectory() as directory:
            cid = Path(directory) / "wan.cid"
            cid.write_text("a" * 64)
            cid.chmod(0o600)
            run = mock.Mock(return_value=b"")
            owned = MODULE.OwnedDocker("docker", Path(directory), run)
            with self.assertRaisesRegex(MODULE.ExecutionError, "cidfile-exists"):
                owned.create("wan", ["--network", "none"], ["sleep", "600"])
            run.assert_not_called()
            self.assertEqual(owned.containers, [])

    def test_direct_preflight_rejects_nonlinux_nonroot_and_remote_daemon(self):
        self.assertEqual(len(__import__("inspect").signature(MODULE.preflight).parameters), 1)
        with mock.patch.object(MODULE.platform, "system", return_value="Darwin"):
            with self.assertRaisesRegex(MODULE.ExecutionError, "Linux"):
                MODULE.preflight(Path("/usr/bin/docker"))
        with mock.patch.object(MODULE.platform, "system", return_value="Linux"), mock.patch.object(MODULE.os, "geteuid", return_value=1000):
            with self.assertRaisesRegex(MODULE.ExecutionError, "root"):
                MODULE.preflight(Path("/usr/bin/docker"))
        with mock.patch.object(MODULE.platform, "system", return_value="Linux"), mock.patch.object(MODULE.os, "geteuid", return_value=0), mock.patch.object(MODULE, "_regular_executable"), mock.patch.dict(MODULE.os.environ, {"DOCKER_HOST": "tcp://remote"}):
            with self.assertRaisesRegex(MODULE.ExecutionError, "local"):
                MODULE.preflight(Path("/usr/bin/docker"))

    def test_delivery_cli_requires_only_docker_and_serializes_the_fixed_run(self):
        raw = MODULE_PATH.parents[1] / "docker/path-lab/scenarios/event-delivery-netem.json"
        with mock.patch("builtins.print"), mock.patch.object(MODULE, "preflight", return_value=(Path("/usr/bin/docker"), Path("/usr/sbin/ip"))) as preflight, mock.patch.object(MODULE, "_lab_lock") as lock, mock.patch.object(MODULE, "execute_direct", return_value={"status": "pass"}) as execute:
            self.assertEqual(MODULE.main([str(raw), "--execute", "--docker", "/usr/bin/docker"]), 0)
        preflight.assert_called_once_with(Path("/usr/bin/docker"))
        lock.assert_called_once_with(MODULE.LAB_LOCK)
        execute.assert_called_once()

    def test_cli_threads_preflight_tools_through_path_mutation_without_rediscovery(self):
        raw = MODULE_PATH.parents[1] / "docker/path-lab/scenarios/event-delivery-netem.json"
        fake = FakeDocker()
        validated = (Path("/usr/bin/docker"), Path("/usr/sbin/ip"))
        @contextmanager
        def lock(_):
            MODULE.os.environ["PATH"] = "/changed-by-attacker"
            yield
        execute = MODULE.execute_direct
        with mock.patch("builtins.print"), \
                mock.patch.dict(MODULE.os.environ, {"PATH": "/initial-attacker"}), \
                mock.patch.object(MODULE, "preflight", return_value=validated) as preflight, \
                mock.patch.object(MODULE, "_lab_lock", side_effect=lock), \
                mock.patch.object(MODULE.shutil, "which", side_effect=AssertionError("PATH rediscovery")), \
                mock.patch.object(MODULE, "_system_executable", side_effect=AssertionError("system rediscovery")), \
                mock.patch.object(MODULE, "_regular_executable", side_effect=AssertionError("executable rediscovery")), \
                mock.patch.object(MODULE, "execute_direct", side_effect=lambda *a, **kw: execute(*a, **kw, run=fake)):
            self.assertEqual(MODULE.main([str(raw), "--execute"]), 0)
        preflight.assert_called_once_with(None)
        links = [c for c in fake.calls if c[1:3] == ["link", "add"]]
        self.assertEqual(len(links), 2)
        self.assertTrue(all(c[0] == str(validated[1]) for c in links))
        self.assertTrue(all(c[0] == str(validated[0]) for c in fake.calls if c not in links))

    def test_direct_readback_checks_exact_configured_values(self):
        fake = FakeDocker()
        def run(argv, timeout):
            argv = unpin(argv)
            value = fake(argv, timeout)
            if argv[1:3] == ["start", "--attach"] and argv[-1] == fake.roles.get("wan-setup"):
                rows = json.loads(value)
                rows[0]["rate"] = 999
                return json.dumps(rows).encode()
            return value
        raw = (MODULE_PATH.parents[1] / "docker/path-lab/scenarios/event-delivery-netem.json").read_bytes()
        with self.assertRaisesRegex(MODULE.ExecutionError, "primary=netem"):
            MODULE.execute_direct(raw, docker=Path("docker"), ip=Path("/usr/sbin/ip"), run=run)

    def test_direct_rejects_netem_readback_before_publish_and_cleans_every_id(self):
        fake = FakeDocker()
        def run(argv, timeout):
            argv = unpin(argv)
            value = fake(argv, timeout)
            if argv[1:3] == ["start", "--attach"] and argv[-1] == fake.roles.get("wan-setup"):
                return b"{}"
            return value
        raw = (MODULE_PATH.parents[1] / "docker/path-lab/scenarios/event-delivery-netem.json").read_bytes()
        with self.assertRaisesRegex(MODULE.ExecutionError, "primary=netem"):
            MODULE.execute_direct(raw, docker=Path("docker"), ip=Path("/usr/sbin/ip"), run=run)
        self.assertFalse(any("publish" in c for c in fake.calls))
        removed = {c[-1] for c in fake.calls if c[1] == "rm"}
        self.assertEqual(removed, set(fake.ids))

    def test_provision_handoff_includes_private_mount_root(self):
        provision = load_script("delivery-provision.py")
        self.assertTrue(hasattr(provision, "handoff"), "mount-root handoff is missing")
        with tempfile.TemporaryDirectory() as directory:
            state = Path(directory) / "node-a/state"
            state.mkdir(parents=True)
            (state / "peer").write_text("test")
            with mock.patch.object(provision.os, "chown") as chown:
                provision.handoff(state)
            self.assertIn(mock.call(state.parent, 10001, 10001), chown.call_args_list)
            self.assertEqual(state.parent.stat().st_mode & 0o777, 0o700)
            self.assertEqual(state.stat().st_mode & 0o777, 0o700)
            self.assertEqual((state / "peer").stat().st_mode & 0o777, 0o600)

    def test_agent_entrypoint_writes_pid_and_exposes_live_verification(self):
        agent = load_script("delivery-agent.py")
        with mock.patch("builtins.print"), mock.patch.object(agent.os, "getuid", return_value=10001), mock.patch.object(agent.os, "getgid", return_value=10001):
            with mock.patch.object(agent, "verify_live") as verify:
                self.assertEqual(agent.main(["verify", "wan"]), 0)
                verify.assert_called_once_with("wan")
            with tempfile.TemporaryDirectory() as directory:
                state = Path(directory)
                (state / "peer").write_text("a" * 64 + "@10.77.2.2:4433=" + "b" * 64)
                with mock.patch.object(agent.os, "execv", side_effect=OSError), mock.patch.object(agent, "STATE", state, create=True):
                    self.assertEqual(agent.main(["node-a"]), 2)
                    self.assertEqual((state / "agent.pid").read_text(), str(agent.os.getpid()))

    def test_direct_execution_routes_exact_event_with_no_shared_endpoint_network(self):
        self.assertTrue(hasattr(MODULE, "execute_direct"), "direct execution is missing")
        fake = FakeDocker()
        raw = (MODULE_PATH.parents[1] / "docker/path-lab/scenarios/event-delivery-netem.json").read_bytes()
        receipt = MODULE.execute_direct(raw, docker=Path("/usr/bin/docker"), ip=Path("/usr/sbin/ip"), run=fake)
        self.assertFalse(any(c[1:3] == ["network", "create"] for c in fake.calls),
                         "Docker bridge firewall still owns the routed path")
        self.assertEqual(receipt["event_id"], fake.event_id)
        self.assertEqual(receipt["capabilities"], "pass")
        self.assertEqual(receipt["cleanup"], "pass")
        self.assertEqual(receipt["not_run"], ["recovery", "resource", "physical", "measured-latency", "actual-loss"])
        creates = [c for c in fake.calls if c[1] == "create"]
        self.assertEqual(len(creates), 7)
        for c in creates:
            self.assertIn("--cidfile", c)
            self.assertEqual(c[c.index("--cap-drop") + 1], "ALL")
            self.assertIn("no-new-privileges", c)
        for role in ("node-a", "node-b", "wan"):
            c = next(c for c in creates if Path(c[c.index("--cidfile") + 1]).stem == role)
            self.assertEqual(c[c.index("--network") + 1], "none")
            self.assertNotIn("--cap-add", c)
        self.assertFalse(any(c[1:3] == ["network", "connect"] for c in fake.calls))
        links = [c for c in fake.calls if c[1:3] == ["link", "add"]]
        self.assertEqual([c[1:] for c in links], [
            ["link", "add", "name", "eth0", "netns", "/proc/42/fd/5", "type", "veth",
             "peer", "name", "wan1", "netns", "/proc/42/fd/4"],
            ["link", "add", "name", "eth0", "netns", "/proc/42/fd/6", "type", "veth",
             "peer", "name", "wan2", "netns", "/proc/42/fd/4"],
        ])
        self.assertTrue(all(Path(c[0]).name == "ip" for c in links))
        for c in fake.calls:
            self.assertNotIn("containerlab", " ".join(c))
            if c[1] in ("exec", "rm", "start", "wait"):
                self.assertTrue(any(i in c for i in fake.ids))
        mounts = [c[c.index("--volume") + 1].split(":")[0] for c in creates if "--volume" in c]
        self.assertTrue(all(not Path(m).exists() for m in mounts))

    def test_live_privilege_reader_checks_pid_one_and_real_agent(self):
        agent = load_script("delivery-agent.py")
        self.assertTrue(hasattr(agent, "verify_live"), "live process verification is missing")
        good = "Name:\taster-agent\nUid:\t10001\t10001\t10001\t10001\nGid:\t10001\t10001\t10001\t10001\nNoNewPrivs:\t1\n" + "".join(f"{k}:\t0000000000000000\n" for k in ("CapInh", "CapPrm", "CapEff", "CapBnd", "CapAmb"))
        with tempfile.TemporaryDirectory() as directory:
            proc = Path(directory) / "proc"
            state = Path(directory) / "state"
            state.mkdir()
            (state / "agent.pid").write_text("42")
            for pid in ("1", "42"):
                (proc / pid).mkdir(parents=True)
                (proc / pid / "status").write_text(good)
            agent.verify_live("node-a", proc, state)
            (proc / "42" / "status").write_text(good.replace("aster-agent", "sleep"))
            with self.assertRaises(ValueError):
                agent.verify_live("node-a", proc, state)
            agent.verify_live("wan", proc, state)

    def test_agent_capability_oracle_rejects_nonzero_sets_or_wrong_uid(self):
        agent = load_script("delivery-agent.py")
        self.assertTrue(hasattr(agent, "validate_privileges"), "live capability oracle is missing")
        good = "Uid:\t10001\t10001\t10001\t10001\nGid:\t10001\t10001\t10001\t10001\nNoNewPrivs:\t1\n" + "".join(f"{k}:\t0000000000000000\n" for k in ("CapInh", "CapPrm", "CapEff", "CapBnd", "CapAmb"))
        agent.validate_privileges(good)
        for bad in (good.replace("CapBnd:\t0000000000000000", "CapBnd:\t0000000000000001"),
                    good.replace("10001", "0"), good.replace("NoNewPrivs:\t1", "NoNewPrivs:\t0"), ""):
            with self.assertRaises(ValueError):
                agent.validate_privileges(bad)

    def test_wan_readback_rejects_swapped_fields_and_shared_interface(self):
        wan = load_script("delivery-wan.py")
        for bad in ("swapped", "shared", "missing"):
            def run(argv, timeout):
                argv = unpin(argv)
                if argv[:3] == ["ip", "-j", "address"]:
                    return json.dumps([
                        {"ifname": "x", "addr_info": [{"local": "10.77.1.1"}]},
                        {"ifname": "x" if bad == "shared" else "y", "addr_info": [{"local": "10.77.2.1"}]},
                    ]).encode()
                if argv[:3] == ["tc", "qdisc", "show"]:
                    return (b"qdisc netem 8001: root refcnt 2 limit 1000 delay 5ms 40ms loss 1% rate 100Mbit\n"
                            if bad == "swapped" else b"qdisc netem 8001: root refcnt 2 limit 1000 delay 40ms 5ms loss 1% rate 100Mbit\n"
                            if bad == "shared" else b"")
                return b""
            with self.subTest(bad=bad), self.assertRaises(RuntimeError):
                wan.configure(run)

    def test_wan_resolves_egress_by_ip_and_reads_back_both_qdiscs(self):
        wan = load_script("delivery-wan.py")
        self.assertTrue(hasattr(wan, "configure"), "IP-resolved netem configuration is missing")
        calls = []
        def run(argv, timeout):
            argv = unpin(argv)
            calls.append(argv)
            if argv[:3] == ["ip", "-j", "address"]:
                return json.dumps([
                    {"ifname": "second", "addr_info": [{"local": "10.77.1.1"}]},
                    {"ifname": "first", "addr_info": [{"local": "10.77.2.1"}]},
                ]).encode()
            if argv[:3] == ["tc", "qdisc", "show"]:
                return b"qdisc netem 8001: root refcnt 2 limit 1000 delay 40ms 5ms loss 1% rate 100Mbit\n"
            return b""
        result = wan.configure(run)
        self.assertEqual(calls[:4], [
            ["ip", "address", "add", "10.77.1.1/29", "dev", "wan1"],
            ["ip", "link", "set", "dev", "wan1", "up"],
            ["ip", "address", "add", "10.77.2.1/29", "dev", "wan2"],
            ["ip", "link", "set", "dev", "wan2", "up"],
        ], "WAN veth ends remain unaddressed/down")
        self.assertEqual([r["interface"] for r in result], ["second", "first"])
        for name in ("first", "second"):
            self.assertTrue(any(c[:3] == ["tc", "qdisc", "replace"] and name in c for c in calls))
            self.assertTrue(any(c[:3] == ["tc", "qdisc", "show"] and name in c for c in calls))
        self.assertFalse(any("eth1" in c or "eth2" in c for c in calls))

    def test_network_ownership_and_cleanup_continue_after_failure(self):
        self.assertTrue(hasattr(MODULE.OwnedDocker, "cleanup"), "ID cleanup is missing")
        calls = []
        with tempfile.TemporaryDirectory() as directory:
            def run(argv, timeout):
                argv = unpin(argv)
                calls.append(argv)
                if argv[1] == "rm":
                    raise MODULE.ExecutionError("secret")
                return b""
            owned = MODULE.OwnedDocker("docker", Path(directory), run)
            # An already captured immutable network ID remains cleanup-only
            # compatibility state; the direct path no longer creates bridges.
            nid = "b" * 64
            owned.networks = [nid]
            owned.containers = ["a" * 64, "c" * 64]
            errors = owned.cleanup()
            self.assertEqual(errors, ["container-remove", "container-remove"])
            removals = [c for c in calls if c[1] == "rm"]
            self.assertEqual({c[-1] for c in removals}, {"a" * 64, "c" * 64})
            self.assertIn(["docker", "network", "rm", nid], calls)
            self.assertTrue(any("id=" + nid in c for c in calls))
            self.assertTrue(any("id=" + "a" * 64 in c for c in calls))

    def test_cidfile_rejects_unsafe_identity_and_recovers_partial_create(self):
        for case in ("name", "short", "symlink", "public", "huge", "partial"):
            with self.subTest(case=case), tempfile.TemporaryDirectory() as directory:
                def run(argv, timeout):
                    argv = unpin(argv)
                    path = Path(argv[argv.index("--cidfile") + 1])
                    value = {"name": "wan", "short": "a" * 12, "huge": "a" * 10000}.get(case, "a" * 64)
                    path.write_text(value)
                    path.chmod(0o644 if case == "public" else 0o600)
                    if case == "symlink":
                        target = path.with_suffix(".target")
                        path.rename(target)
                        path.symlink_to(target)
                    if case == "partial":
                        raise MODULE.ExecutionError("raw-secret")
                    return b""
                owned = MODULE.OwnedDocker("docker", Path(directory), run)
                with self.assertRaises(MODULE.ExecutionError):
                    owned.create("wan", ["--network", "none"], ["sleep", "600"])
                self.assertEqual(owned.containers, ["a" * 64] if case == "partial" else [])

    def test_owned_create_uses_private_cidfile_and_immutable_id(self) -> None:
        self.assertTrue(hasattr(MODULE, "OwnedDocker"), "direct Docker ownership is missing")
        calls = []
        with tempfile.TemporaryDirectory() as directory:
            def run(argv, timeout):
                argv = unpin(argv)
                calls.append(argv)
                self.assertLessEqual(timeout, 90)
                if argv[1] == "create":
                    path = Path(argv[argv.index("--cidfile") + 1])
                    self.assertEqual(path.parent.stat().st_mode & 0o777, 0o700)
                    path.write_text("a" * 64)
                    path.chmod(0o600)
                    return b"untrusted stdout ignored"
                return b""
            owned = MODULE.OwnedDocker("docker", Path(directory), run)
            cid = owned.create("wan", ["--network", "none"], ["sleep", "600"])
            self.assertEqual(cid, "a" * 64)
            self.assertEqual(owned.containers, [cid])
            argv = calls[0]
            for flag, value in [("--cap-drop", "ALL"), ("--user", "10001:10001"),
                                ("--security-opt", "no-new-privileges"), ("--log-driver", "none")]:
                self.assertEqual(argv[argv.index(flag) + 1], value)
            self.assertIn("--label", argv)
            self.assertNotIn("--name", argv)

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
                    "limit": 1000,
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


    def test_fixed_role_scripts_compile_exact_network_and_agent_argv(self) -> None:
        network = load_script("delivery-network-init.py")
        self.assertEqual(
            network.commands("node-a"),
            [
                ["ip", "address", "add", "10.77.1.2/29", "dev", "eth0"],
                ["ip", "link", "set", "dev", "eth0", "up"],
                ["ip", "route", "replace", "10.77.2.0/29", "via", "10.77.1.1"],
                ["ip", "route", "replace", "default", "via", "10.77.1.1"],
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
