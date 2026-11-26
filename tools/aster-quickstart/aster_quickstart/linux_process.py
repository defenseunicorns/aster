"""Exact Linux ownership for one quickstart child process group."""

from __future__ import annotations

from dataclasses import dataclass
import errno
import math
import os
from pathlib import Path
import select
import signal
import subprocess
import time


class ProcessSafetyError(RuntimeError):
    """A child process group can no longer be proven safe to signal."""


@dataclass(frozen=True)
class ProcessIdentity:
    pid: int
    proc_start_time: int
    executable: str
    process_group: int


def observe_process(pid: int) -> ProcessIdentity:
    try:
        raw = Path(f"/proc/{pid}/stat").read_text()
        executable = str(Path(f"/proc/{pid}/exe").resolve(strict=True))
    except FileNotFoundError as error:
        raise ProcessLookupError(pid) from error
    except OSError as error:
        raise ProcessSafetyError("process observation failed") from error
    closing = raw.rfind(")")
    fields = raw[closing + 2 :].split() if closing >= 0 else []
    if len(fields) < 20:
        raise ProcessSafetyError("process observation is malformed")
    try:
        return ProcessIdentity(pid, int(fields[19]), executable, int(fields[2]))
    except ValueError as error:
        raise ProcessSafetyError("process observation is malformed") from error


def group_is_gone(process_group: int) -> bool:
    try:
        os.killpg(process_group, 0)
    except ProcessLookupError:
        return True
    except OSError as error:
        if error.errno == errno.ESRCH:
            return True
        raise ProcessSafetyError("process group observation failed") from error
    return False


class OwnedProcessGroup:
    """Pin and signal only the exact dedicated leader captured at spawn."""

    def __init__(self, identity: ProcessIdentity, pidfd: int) -> None:
        if identity.pid != identity.process_group:
            os.close(pidfd)
            raise ProcessSafetyError("owned child is not a dedicated process-group leader")
        self.identity = identity
        self._pidfd = pidfd
        self._closed = False

    @classmethod
    def capture(cls, pid: int) -> "OwnedProcessGroup":
        try:
            pidfd = os.pidfd_open(pid)
        except OSError as error:
            raise ProcessSafetyError("could not pin child process identity") from error
        try:
            identity = observe_process(pid)
        except BaseException:
            os.close(pidfd)
            raise
        return cls(identity, pidfd)

    def leader_gone(self) -> bool:
        poller = select.poll()
        poller.register(self._pidfd, select.POLLIN)
        return bool(poller.poll(0))

    def stop(
        self,
        process: subprocess.Popen[bytes],
        timeout: float,
    ) -> None:
        if group_is_gone(self.identity.process_group):
            self._reap(process)
            self.close()
            return
        if self.leader_gone():
            raise ProcessSafetyError("owned leader is gone while its process group remains")
        if not math.isfinite(timeout) or timeout <= 0:
            raise ProcessSafetyError("owned child cleanup has no deadline")
        frozen = False
        group_killed = False
        try:
            # Freeze the pinned leader before addressing its process group.  A
            # stopped, identity-checked leader keeps the PGID allocated, so the
            # kernel cannot recycle it between verification and killpg().
            signal.pidfd_send_signal(self._pidfd, signal.SIGSTOP)
            frozen = True
            if self.leader_gone() or observe_process(self.identity.pid) != self.identity:
                raise ProcessSafetyError("owned leader identity changed during cleanup")
            os.killpg(self.identity.process_group, signal.SIGKILL)
            group_killed = True
            if not self._wait_group_gone(process, timeout):
                raise ProcessSafetyError("owned child process group did not stop")
            self._reap(process)
            self.close()
        except BaseException as error:
            if frozen and not group_killed and not self.leader_gone():
                try:
                    signal.pidfd_send_signal(self._pidfd, signal.SIGCONT)
                except OSError as resume_error:
                    raise ProcessSafetyError("owned leader resume failed") from resume_error
            if isinstance(error, OSError):
                raise ProcessSafetyError("owned child process group could not be stopped") from error
            raise

    def close(self) -> None:
        if not self._closed:
            os.close(self._pidfd)
            self._closed = True

    def _wait_group_gone(self, process: subprocess.Popen[bytes], timeout: float) -> bool:
        deadline = time.monotonic() + timeout
        while True:
            process.poll()
            if group_is_gone(self.identity.process_group):
                return True
            if time.monotonic() >= deadline:
                return False
            time.sleep(min(0.02, max(0.0, deadline - time.monotonic())))

    @staticmethod
    def _reap(process: subprocess.Popen[bytes]) -> None:
        try:
            process.wait(timeout=0.2)
        except subprocess.TimeoutExpired as error:
            raise ProcessSafetyError("owned child process leader was not reaped") from error


__all__ = [
    "OwnedProcessGroup",
    "ProcessIdentity",
    "ProcessSafetyError",
    "group_is_gone",
    "observe_process",
]
