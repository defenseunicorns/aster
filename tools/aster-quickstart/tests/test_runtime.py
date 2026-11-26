from __future__ import annotations

import json
import multiprocessing
import os
from pathlib import Path
import signal
import stat
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from dataclasses import replace
from unittest.mock import patch

from aster_quickstart.runtime import (
    OwnedProcessDescriptor,
    RuntimeActiveError,
    RuntimeDescriptor,
    RuntimePublicationCommittedError,
    RuntimeRegistry,
    RuntimeSafetyError,
)


def _proc_identity(pid: int) -> tuple[int, int, str]:
    raw = Path(f"/proc/{pid}/stat").read_text()
    fields = raw[raw.rfind(")") + 2 :].split()
    return int(fields[19]), int(fields[2]), str(Path(f"/proc/{pid}/exe").resolve())


def _proc_state(pid: int) -> str:
    raw = Path(f"/proc/{pid}/stat").read_text()
    return raw[raw.rfind(")") + 2 :].split()[0]


def _publish_runtime_then_exit(runtime_dir_text: str, control) -> None:
    runtime_dir = Path(runtime_dir_text)
    workspace = runtime_dir / "session"
    workspace.mkdir(parents=True, mode=0o700)
    socket_path = workspace / "attach.sock"
    socket_path.touch(mode=0o600)
    registry = RuntimeRegistry(runtime_dir / "quickstart.lock", runtime_dir / "quickstart.json")
    registry.acquire()
    from aster_quickstart.runtime import current_runtime_descriptor

    registry.publish(current_runtime_descriptor(workspace, socket_path))
    control.send("published")
    control.recv()
    registry.close(remove_descriptor=False)
    control.close()


class RuntimeRegistryTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.runtime_dir = self.root / "runtime"
        self.runtime_dir.mkdir(mode=0o700)
        self.lock_path = self.runtime_dir / "quickstart.lock"
        self.descriptor_path = self.runtime_dir / "quickstart.json"

    def registry(self) -> RuntimeRegistry:
        return RuntimeRegistry(self.lock_path, self.descriptor_path)

    @staticmethod
    def _reap_process(process: subprocess.Popen) -> None:
        if process.poll() is None:
            process.kill()
        process.wait(timeout=1)

    def retained_paths(self) -> tuple[Path, Path]:
        workspace = self.runtime_dir / "session"
        workspace.mkdir(mode=0o700)
        socket_path = workspace / "attach.sock"
        socket_path.touch(mode=0o600)
        os.chmod(socket_path, 0o600)
        return workspace, socket_path

    def descriptor_for(
        self,
        pid: int,
        workspace: Path,
        socket_path: Path,
        *,
        owned_processes: tuple[OwnedProcessDescriptor, ...] = (),
        lifecycle: str = "active",
    ) -> RuntimeDescriptor:
        start_time, process_group, executable = _proc_identity(pid)
        workspace_metadata = workspace.stat()
        endpoint_metadata = socket_path.stat()
        return RuntimeDescriptor(
            pid=pid,
            proc_start_time=start_time,
            executable=executable,
            process_group=process_group,
            workspace=str(workspace),
            socket_path=str(socket_path),
            workspace_device=workspace_metadata.st_dev,
            workspace_inode=workspace_metadata.st_ino,
            socket_device=endpoint_metadata.st_dev,
            socket_inode=endpoint_metadata.st_ino,
            lifecycle=lifecycle,
            owned_processes=owned_processes,
        )

    def write_descriptor(self, descriptor: RuntimeDescriptor) -> None:
        self.descriptor_path.write_text(json.dumps(descriptor.to_mapping()))
        self.descriptor_path.chmod(0o600)

    def test_publish_is_owner_only_and_live_discovery_checks_process_identity(self):
        workspace, socket_path = self.retained_paths()
        descriptor = self.descriptor_for(os.getpid(), workspace, socket_path)
        registry = self.registry()
        registry.acquire()
        self.addCleanup(registry.close, remove_descriptor=False)

        registry.publish(descriptor)

        metadata = self.descriptor_path.lstat()
        self.assertTrue(stat.S_ISREG(metadata.st_mode))
        self.assertEqual(stat.S_IMODE(metadata.st_mode), 0o600)
        self.assertEqual(metadata.st_uid, os.geteuid())
        self.assertEqual(registry.read_live(), descriptor)

    def test_live_instance_lock_is_rejected_without_replacing_its_descriptor(self):
        workspace, socket_path = self.retained_paths()
        first = self.registry()
        first.acquire()
        self.addCleanup(first.close, remove_descriptor=False)
        first.publish(self.descriptor_for(os.getpid(), workspace, socket_path))
        before = self.descriptor_path.read_bytes()

        second = self.registry()
        with self.assertRaises(RuntimeActiveError):
            second.acquire()

        self.assertEqual(self.descriptor_path.read_bytes(), before)

    def test_registry_never_follows_lock_or_descriptor_symlinks(self):
        target = self.root / "target"
        target.write_text("do not change")
        self.lock_path.symlink_to(target)
        with self.assertRaises(RuntimeSafetyError):
            self.registry().acquire()
        self.assertEqual(target.read_text(), "do not change")

        self.lock_path.unlink()
        workspace, socket_path = self.retained_paths()
        registry = self.registry()
        registry.acquire()
        self.addCleanup(registry.close, remove_descriptor=False)
        self.descriptor_path.symlink_to(target)
        with self.assertRaises(RuntimeSafetyError):
            registry.publish(self.descriptor_for(os.getpid(), workspace, socket_path))
        self.assertEqual(target.read_text(), "do not change")
        self.assertTrue(self.descriptor_path.is_symlink())

    def test_initial_publication_is_atomic_no_replace_for_regular_entries(self):
        workspace, socket_path = self.retained_paths()
        self.descriptor_path.write_text("existing")
        self.descriptor_path.chmod(0o600)
        registry = self.registry()
        registry.acquire()
        self.addCleanup(registry.close, remove_descriptor=False)

        with self.assertRaises(RuntimeSafetyError):
            registry.publish(self.descriptor_for(os.getpid(), workspace, socket_path))

        self.assertEqual(self.descriptor_path.read_text(), "existing")

    def test_publication_reports_namespace_commit_when_parent_fsync_fails(self):
        workspace, socket_path = self.retained_paths()
        registry = self.registry()
        registry.acquire()
        self.addCleanup(registry.close, remove_descriptor=False)

        with patch.object(registry, "_sync_parent", side_effect=OSError("fsync failed")):
            with self.assertRaises(RuntimePublicationCommittedError):
                registry.publish(self.descriptor_for(os.getpid(), workspace, socket_path))

        self.assertTrue(self.descriptor_path.exists())
        registry.mark_cleanup_pending(())
        registry.delete_workspace()
        registry.remove_descriptor()
        self.assertFalse(self.descriptor_path.exists())

    def test_publication_reports_namespace_commit_when_staging_cleanup_fails(self):
        workspace, socket_path = self.retained_paths()
        registry = self.registry()
        registry.acquire()
        self.addCleanup(registry.close, remove_descriptor=False)
        real_unlink = os.unlink

        def fail_staging_cleanup(path, *args, **kwargs):
            if str(path).startswith(f".{self.descriptor_path.name}."):
                raise OSError("staging cleanup failed")
            return real_unlink(path, *args, **kwargs)

        with patch("aster_quickstart.runtime.os.unlink", side_effect=fail_staging_cleanup):
            with self.assertRaises(RuntimePublicationCommittedError):
                registry.publish(self.descriptor_for(os.getpid(), workspace, socket_path))

        self.assertTrue(self.descriptor_path.exists())
        registry.mark_cleanup_pending(())
        registry.delete_workspace()
        registry.remove_descriptor()
        self.assertFalse(self.descriptor_path.exists())

    def test_stale_recovery_accepts_the_exact_confined_launcher_after_it_exits(self):
        workspace, socket_path = self.retained_paths()
        process = subprocess.Popen(
            [sys.executable, "-c", "import time; time.sleep(30)"],
            start_new_session=True,
        )
        self.addCleanup(self._reap_process, process)
        descriptor = self.descriptor_for(process.pid, workspace, socket_path)
        first = self.registry()
        first.acquire()
        first.publish(descriptor)
        first.close(remove_descriptor=False)
        process.terminate()
        process.wait(timeout=1)

        second = self.registry()
        second.acquire()
        self.addCleanup(second.close, remove_descriptor=False)
        self.assertEqual(second.recover_stale(), descriptor)
        self.assertIsNotNone(process.returncode)
        self.assertFalse(workspace.exists())
        self.assertFalse(self.descriptor_path.exists())

    def test_stale_recovery_accepts_a_registry_owner_that_really_exited(self):
        context = multiprocessing.get_context("fork")
        parent, child = context.Pipe()
        owner = context.Process(
            target=_publish_runtime_then_exit,
            args=(str(self.runtime_dir), child),
        )
        owner.start()
        self.assertTrue(parent.poll(1))
        self.assertEqual(parent.recv(), "published")
        parent.send("exit")
        owner.join(timeout=1)
        self.assertEqual(owner.exitcode, 0)

        registry = self.registry()
        registry.acquire()
        self.addCleanup(registry.close, remove_descriptor=False)
        recovered = registry.recover_stale()

        self.assertEqual(recovered.pid, owner.pid)
        self.assertFalse((self.runtime_dir / "session").exists())
        self.assertFalse(self.descriptor_path.exists())
        parent.close()

    def test_cleanup_pending_recovery_resumes_after_workspace_was_already_deleted(self):
        process = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(30)"])
        workspace, socket_path = self.retained_paths()
        descriptor = self.descriptor_for(
            process.pid,
            workspace,
            socket_path,
            lifecycle="cleanup_pending",
        )
        process.terminate()
        process.wait(timeout=1)
        self.write_descriptor(descriptor)
        import shutil

        shutil.rmtree(workspace)
        registry = self.registry()
        registry.acquire()
        self.addCleanup(registry.close, remove_descriptor=False)

        self.assertEqual(registry.recover_stale(), descriptor)
        self.assertFalse(self.descriptor_path.exists())

    def test_stale_recovery_never_signals_the_launchers_inherited_process_group(self):
        workspace, socket_path = self.retained_paths()
        process = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(30)"])
        self.addCleanup(self._reap_process, process)
        descriptor = self.descriptor_for(process.pid, workspace, socket_path)
        self.assertEqual(descriptor.process_group, os.getpgrp())
        first = self.registry()
        first.acquire()
        first.publish(descriptor)
        first.close(remove_descriptor=False)
        process.terminate()
        process.wait(timeout=1)
        second = self.registry()
        second.acquire()
        self.addCleanup(second.close, remove_descriptor=False)

        with patch("aster_quickstart.runtime.os.killpg", side_effect=AssertionError("inherited group")):
            self.assertEqual(second.recover_stale(), descriptor)

        self.assertFalse(workspace.exists())
        self.assertFalse(self.descriptor_path.exists())

    def test_reused_pid_identity_mismatches_retain_everything_without_signalling(self):
        workspace, socket_path = self.retained_paths()
        live = self.descriptor_for(os.getpid(), workspace, socket_path)
        mismatches = {
            "start-time": RuntimeDescriptor(**{**live.__dict__, "proc_start_time": live.proc_start_time + 1}),
            "executable": RuntimeDescriptor(**{**live.__dict__, "executable": "/usr/bin/false"}),
            "process-group": RuntimeDescriptor(**{**live.__dict__, "process_group": live.process_group + 1}),
        }
        for name, descriptor in mismatches.items():
            with self.subTest(name=name):
                self.write_descriptor(descriptor)
                registry = self.registry()
                registry.acquire()
                try:
                    with self.assertRaises(RuntimeSafetyError):
                        registry.recover_stale()
                finally:
                    registry.close(remove_descriptor=False)
                self.assertTrue(workspace.exists())
                self.assertTrue(self.descriptor_path.exists())

    def test_process_observation_uncertainty_retains_state_without_signalling_or_deletion(self):
        workspace, socket_path = self.retained_paths()
        descriptor = self.descriptor_for(os.getpid(), workspace, socket_path)
        self.write_descriptor(descriptor)
        registry = self.registry()
        registry.acquire()
        self.addCleanup(registry.close, remove_descriptor=False)

        with patch(
            "aster_quickstart.runtime._observe_process",
            side_effect=RuntimeSafetyError("proc unavailable"),
        ), patch("aster_quickstart.runtime.os.kill", side_effect=AssertionError("must not signal")):
            with self.assertRaises(RuntimeSafetyError):
                registry.recover_stale()

        self.assertTrue(workspace.exists())
        self.assertTrue(self.descriptor_path.exists())

    def test_pending_agent_start_blocks_stale_signalling_and_deletion(self):
        workspace, socket_path = self.retained_paths()
        descriptor = replace(
            self.descriptor_for(os.getpid(), workspace, socket_path),
            start_pending="publisher-1",
        )
        self.write_descriptor(descriptor)
        registry = self.registry()
        registry.acquire()
        self.addCleanup(registry.close, remove_descriptor=False)

        with patch("aster_quickstart.runtime.os.killpg") as kill_group:
            with self.assertRaises(RuntimeSafetyError):
                registry.recover_stale()

        kill_group.assert_not_called()
        self.assertTrue(workspace.exists())
        self.assertTrue(self.descriptor_path.exists())

    def test_unsafe_retained_path_is_reported_without_any_mutation(self):
        outside = self.root / "outside"
        outside.mkdir(mode=0o700)
        socket_path = outside / "attach.sock"
        socket_path.write_text("not owned by quickstart")
        descriptor = self.descriptor_for(os.getpid(), outside, socket_path)
        self.write_descriptor(descriptor)
        registry = self.registry()
        registry.acquire()
        self.addCleanup(registry.close, remove_descriptor=False)

        with self.assertRaises(RuntimeSafetyError) as raised:
            registry.recover_stale()

        self.assertIn(str(outside), str(raised.exception))
        self.assertTrue(outside.exists())
        self.assertTrue(socket_path.exists())
        self.assertTrue(self.descriptor_path.exists())

    def test_stale_recovery_retains_paths_until_the_entire_process_group_exits(self):
        workspace, socket_path = self.retained_paths()
        ready = self.root / "child-ready"
        child_code = (
            "import pathlib,signal,time;"
            "signal.signal(signal.SIGTERM, signal.SIG_IGN);"
            f"pathlib.Path({str(ready)!r}).touch();"
            "time.sleep(30)"
        )
        leader_code = (
            "import pathlib,subprocess,sys,time;"
            f"subprocess.Popen([sys.executable,'-c',{child_code!r}]);"
            f"p=pathlib.Path({str(ready)!r});"
            "deadline=time.monotonic()+1;"
            "\nwhile not p.exists() and time.monotonic()<deadline: time.sleep(.005)\n"
            "time.sleep(30)"
        )
        leader = subprocess.Popen([sys.executable, "-c", leader_code], start_new_session=True)

        def kill_group():
            try:
                os.killpg(leader.pid, 9)
            except ProcessLookupError:
                pass
            try:
                leader.wait(timeout=1)
            except subprocess.TimeoutExpired:
                leader.kill()

        self.addCleanup(kill_group)
        deadline = time.monotonic() + 1
        while not ready.exists() and time.monotonic() < deadline:
            time.sleep(0.005)
        self.assertTrue(ready.exists())
        start_time, process_group, executable = _proc_identity(leader.pid)
        owned = OwnedProcessDescriptor(
            pid=leader.pid,
            proc_start_time=start_time,
            executable=executable,
            process_group=process_group,
        )
        descriptor = self.descriptor_for(
            os.getpid(), workspace, socket_path, owned_processes=(owned,)
        )
        first = self.registry()
        first.acquire()
        first.publish(descriptor)
        first.close(remove_descriptor=False)
        second = self.registry()
        second.acquire()
        self.addCleanup(second.close, remove_descriptor=False)

        with self.assertRaises(RuntimeSafetyError):
            second.recover_stale()

        self.assertTrue(workspace.exists())
        self.assertTrue(self.descriptor_path.exists())

    def test_group_exit_observation_uncertainty_retains_all_state(self):
        workspace, socket_path = self.retained_paths()
        launcher = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(30)"])
        self.addCleanup(self._reap_process, launcher)
        process = subprocess.Popen(
            [sys.executable, "-c", "import time; time.sleep(30)"],
            start_new_session=True,
        )
        self.addCleanup(self._reap_process, process)
        start_time, process_group, executable = _proc_identity(process.pid)
        owned = OwnedProcessDescriptor(process.pid, start_time, executable, process_group)
        descriptor = self.descriptor_for(
            launcher.pid, workspace, socket_path, owned_processes=(owned,)
        )
        self.write_descriptor(descriptor)
        launcher.terminate()
        launcher.wait(timeout=1)
        registry = self.registry()
        registry.acquire()
        self.addCleanup(registry.close, remove_descriptor=False)
        real_killpg = os.killpg

        def uncertain_after_signal(group, signum):
            if signum in {signal.SIGTERM, signal.SIGCONT}:
                return real_killpg(group, signum)
            raise PermissionError("group observation denied")

        with patch("aster_quickstart.runtime.os.killpg", side_effect=uncertain_after_signal):
            with self.assertRaises(RuntimeSafetyError):
                registry.recover_stale()

        process.wait(timeout=1)
        self.assertTrue(workspace.exists())
        self.assertTrue(self.descriptor_path.exists())

    def test_failed_post_stop_revalidation_resumes_the_exact_agent_leader(self):
        workspace, socket_path = self.retained_paths()
        process = subprocess.Popen(
            [sys.executable, "-c", "import time; time.sleep(30)"],
            start_new_session=True,
        )
        self.addCleanup(self._reap_process, process)
        start_time, process_group, executable = _proc_identity(process.pid)
        owned = OwnedProcessDescriptor(process.pid, start_time, executable, process_group)
        self.write_descriptor(
            self.descriptor_for(
                os.getpid(), workspace, socket_path, owned_processes=(owned,)
            )
        )
        registry = self.registry()
        registry.acquire()
        self.addCleanup(registry.close, remove_descriptor=False)
        original = RuntimeRegistry._require_matching_process
        calls = 0

        def fail_after_stop(identity, *, dedicated=False):
            nonlocal calls
            calls += 1
            if calls == 3:
                raise RuntimeSafetyError("injected revalidation failure")
            return original(identity, dedicated=dedicated)

        with patch.object(RuntimeRegistry, "_require_matching_process", side_effect=fail_after_stop):
            with self.assertRaises(RuntimeSafetyError):
                registry.recover_stale()

        self.assertNotEqual(_proc_state(process.pid), "T")
        self.assertTrue(self.descriptor_path.exists())

    def test_failed_group_termination_resumes_the_exact_agent_leader(self):
        workspace, socket_path = self.retained_paths()
        process = subprocess.Popen(
            [sys.executable, "-c", "import time; time.sleep(30)"],
            start_new_session=True,
        )
        self.addCleanup(self._reap_process, process)
        start_time, process_group, executable = _proc_identity(process.pid)
        owned = OwnedProcessDescriptor(process.pid, start_time, executable, process_group)
        self.write_descriptor(
            self.descriptor_for(
                os.getpid(), workspace, socket_path, owned_processes=(owned,)
            )
        )
        registry = self.registry()
        registry.acquire()
        self.addCleanup(registry.close, remove_descriptor=False)
        real_killpg = os.killpg

        def fail_termination(group, signum):
            if signum == signal.SIGTERM:
                raise PermissionError("injected termination failure")
            return real_killpg(group, signum)

        with patch("aster_quickstart.runtime.os.killpg", side_effect=fail_termination):
            with self.assertRaises(RuntimeSafetyError):
                registry.recover_stale()

        self.assertNotEqual(_proc_state(process.pid), "T")
        self.assertTrue(self.descriptor_path.exists())

    def test_every_owned_agent_group_is_verified_and_stopped_before_deletion(self):
        workspace, socket_path = self.retained_paths()
        launcher = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(30)"])
        agent = subprocess.Popen(
            [sys.executable, "-c", "import time; time.sleep(30)"], start_new_session=True
        )
        self.addCleanup(lambda: launcher.poll() is None and launcher.kill())
        self.addCleanup(lambda: agent.poll() is None and agent.kill())
        start_time, process_group, executable = _proc_identity(agent.pid)
        owned = OwnedProcessDescriptor(
            pid=agent.pid,
            proc_start_time=start_time,
            executable=executable,
            process_group=process_group,
        )
        descriptor = self.descriptor_for(
            launcher.pid, workspace, socket_path, owned_processes=(owned,)
        )
        first = self.registry()
        first.acquire()
        first.publish(descriptor)
        first.close(remove_descriptor=False)
        launcher.terminate()
        launcher.wait(timeout=1)
        agent_reaper = threading.Thread(target=agent.wait)
        agent_reaper.start()
        second = self.registry()
        second.acquire()
        self.addCleanup(second.close, remove_descriptor=False)

        self.assertEqual(second.recover_stale(), descriptor)

        agent_reaper.join(timeout=1)
        self.assertIsNotNone(launcher.returncode)
        self.assertIsNotNone(agent.returncode)
        self.assertFalse(workspace.exists())

    def test_cleanup_refuses_replaced_workspace_entry_and_keeps_descriptor(self):
        workspace, socket_path = self.retained_paths()
        registry = self.registry()
        registry.acquire()
        registry.publish(self.descriptor_for(os.getpid(), workspace, socket_path))
        registry.mark_cleanup_pending(())
        original = self.runtime_dir / "original"
        workspace.rename(original)
        replacement = self.runtime_dir / workspace.name
        replacement.mkdir(mode=0o700)
        sentinel = replacement / "sentinel"
        sentinel.write_text("keep")
        self.addCleanup(registry.close, remove_descriptor=False)

        with self.assertRaises(RuntimeSafetyError):
            registry.delete_workspace()

        self.assertEqual(sentinel.read_text(), "keep")
        self.assertTrue(self.descriptor_path.exists())

    def test_cleanup_retry_accepts_an_already_deleted_recorded_workspace(self):
        workspace, socket_path = self.retained_paths()
        descriptor = self.descriptor_for(
            os.getpid(), workspace, socket_path, lifecycle="cleanup_pending"
        )
        self.write_descriptor(descriptor)
        registry = self.registry()
        registry.acquire()
        self.addCleanup(registry.close, remove_descriptor=False)

        registry.delete_workspace()
        self.assertFalse(workspace.exists())
        registry.delete_workspace()
        registry.remove_descriptor()

        self.assertFalse(self.descriptor_path.exists())

    def test_descriptor_removal_retries_every_namespace_and_fsync_phase(self):
        cases = (
            ("link", "link"),
            ("link-fsync", "sync-1"),
            ("canonical-unlink", "unlink-canonical"),
            ("canonical-fsync", "sync-2"),
            ("removal-unlink", "unlink-removal"),
            ("removal-fsync", "sync-3"),
        )
        for suffix, fault in cases:
            with self.subTest(phase=fault):
                case_root = self.root / suffix
                case_root.mkdir(mode=0o700)
                lock_path = case_root / "runtime.lock"
                descriptor_path = case_root / "runtime.json"
                removal_path = case_root / "runtime.json.removing"
                workspace = case_root / "session"
                workspace.mkdir(mode=0o700)
                socket_path = workspace / "attach.sock"
                socket_path.touch(mode=0o600)
                registry = RuntimeRegistry(lock_path, descriptor_path)
                registry.acquire()
                registry.publish(self.descriptor_for(os.getpid(), workspace, socket_path))
                registry.mark_cleanup_pending(())
                registry.delete_workspace()

                real_link = os.link
                real_unlink = os.unlink
                link_failed = False
                unlink_failed = False
                sync_count = 0

                def injected_link(*args, **kwargs):
                    nonlocal link_failed
                    if fault == "link" and not link_failed:
                        link_failed = True
                        raise OSError("injected descriptor link failure")
                    return real_link(*args, **kwargs)

                def injected_unlink(path, *args, **kwargs):
                    nonlocal unlink_failed
                    selected = (
                        fault == "unlink-canonical" and path == descriptor_path.name
                    ) or (
                        fault == "unlink-removal" and path == removal_path.name
                    )
                    if selected and not unlink_failed:
                        unlink_failed = True
                        raise OSError("injected descriptor unlink failure")
                    return real_unlink(path, *args, **kwargs)

                original_sync = registry._sync_parent

                def injected_sync():
                    nonlocal sync_count
                    sync_count += 1
                    selected = fault == f"sync-{sync_count}"
                    if selected:
                        raise OSError("injected descriptor fsync failure")
                    return original_sync()

                with (
                    patch("aster_quickstart.runtime.os.link", side_effect=injected_link),
                    patch("aster_quickstart.runtime.os.unlink", side_effect=injected_unlink),
                    patch.object(registry, "_sync_parent", side_effect=injected_sync),
                ):
                    with self.assertRaises((OSError, RuntimeSafetyError)):
                        registry.remove_descriptor()

                contender = RuntimeRegistry(lock_path, descriptor_path)
                with self.assertRaises(RuntimeActiveError):
                    contender.acquire()

                registry.remove_descriptor()
                registry.close(remove_descriptor=False)
                self.assertFalse(descriptor_path.exists())
                self.assertFalse(removal_path.exists())

    def test_descriptor_removal_resumes_from_on_disk_quarantine_after_restart(self):
        workspace, socket_path = self.retained_paths()
        registry = self.registry()
        registry.acquire()
        registry.publish(self.descriptor_for(os.getpid(), workspace, socket_path))
        registry.mark_cleanup_pending(())
        registry.delete_workspace()

        with patch.object(registry, "_sync_parent", side_effect=OSError("fsync failed")):
            with self.assertRaises(OSError):
                registry.remove_descriptor()

        removal_path = self.descriptor_path.with_name(self.descriptor_path.name + ".removing")
        self.assertTrue(removal_path.exists())
        registry.close(remove_descriptor=False)

        recovered = self.registry()
        recovered.acquire()
        recovered.remove_descriptor()
        recovered.close(remove_descriptor=False)
        self.assertFalse(self.descriptor_path.exists())
        self.assertFalse(removal_path.exists())


if __name__ == "__main__":
    unittest.main()
