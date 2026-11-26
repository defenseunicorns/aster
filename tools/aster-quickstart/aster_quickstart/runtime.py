"""Owner-confined runtime metadata and conservative Linux stale recovery.

The runtime directory excludes other UIDs. A process with the same UID is inside
the trust boundary; nevertheless every retained inode and process identity is
revalidated at each mutation boundary and no path is followed through a symlink.
"""

from __future__ import annotations

from dataclasses import dataclass, replace
import errno
import fcntl
import json
import os
from pathlib import Path
import secrets
import select
import shutil
import signal
import stat
import time
from typing import Any, Iterable


_DIRECTORY_MODE = 0o700
_FILE_MODE = 0o600
_MAX_DESCRIPTOR_BYTES = 16_384
_MAX_OWNED_PROCESSES = 8
_PROCESS_EXIT_TIMEOUT = 0.5
_LIFECYCLES = frozenset({"active", "cleanup_pending"})
_DESCRIPTOR_FIELDS = frozenset(
    {
        "pid",
        "proc_start_time",
        "executable",
        "process_group",
        "workspace",
        "socket_path",
        "workspace_device",
        "workspace_inode",
        "socket_device",
        "socket_inode",
        "start_pending",
        "lifecycle",
        "owned_processes",
    }
)
_PROCESS_FIELDS = frozenset({"pid", "proc_start_time", "executable", "process_group"})


class RuntimeActiveError(RuntimeError):
    """Another quickstart owns the runtime lock."""


class RuntimeSafetyError(RuntimeError):
    """Runtime identity or retained state could not be proven safe."""


class RuntimePublicationCommittedError(RuntimeSafetyError):
    """Descriptor namespace commit succeeded but durability confirmation failed."""


class _ProcessGone(RuntimeError):
    pass


def _positive_integer(value: object, name: str) -> int:
    if type(value) is not int or value <= 0:
        raise ValueError(f"{name} must be a positive integer")
    return value


def _absolute_string(value: object, name: str) -> str:
    if type(value) is not str or not value or len(value) > 4_096 or "\x00" in value:
        raise ValueError(f"{name} must be a bounded string")
    if not Path(value).is_absolute():
        raise ValueError(f"{name} must be absolute")
    return value


@dataclass(frozen=True)
class OwnedProcessDescriptor:
    """Exact identity of one dedicated Aster agent process-group leader."""

    pid: int
    proc_start_time: int
    executable: str
    process_group: int

    def __post_init__(self) -> None:
        _positive_integer(self.pid, "pid")
        _positive_integer(self.proc_start_time, "proc_start_time")
        _absolute_string(self.executable, "executable")
        _positive_integer(self.process_group, "process_group")
        if self.pid != self.process_group:
            raise ValueError("owned process must lead its dedicated process group")

    def to_mapping(self) -> dict[str, object]:
        return {
            "pid": self.pid,
            "proc_start_time": self.proc_start_time,
            "executable": self.executable,
            "process_group": self.process_group,
        }

    @classmethod
    def from_mapping(cls, value: object) -> "OwnedProcessDescriptor":
        if type(value) is not dict or set(value) != _PROCESS_FIELDS:
            raise RuntimeSafetyError("owned process inventory is invalid")
        try:
            return cls(**value)  # type: ignore[arg-type]
        except (TypeError, ValueError) as error:
            raise RuntimeSafetyError("owned process inventory is invalid") from error


@dataclass(frozen=True)
class RuntimeDescriptor:
    pid: int
    proc_start_time: int
    executable: str
    process_group: int
    workspace: str
    socket_path: str
    workspace_device: int
    workspace_inode: int
    socket_device: int
    socket_inode: int
    start_pending: str | None = None
    lifecycle: str = "active"
    owned_processes: tuple[OwnedProcessDescriptor, ...] = ()

    def __post_init__(self) -> None:
        _positive_integer(self.pid, "pid")
        _positive_integer(self.proc_start_time, "proc_start_time")
        _absolute_string(self.executable, "executable")
        _positive_integer(self.process_group, "process_group")
        _absolute_string(self.workspace, "workspace")
        _absolute_string(self.socket_path, "socket_path")
        _positive_integer(self.workspace_device, "workspace_device")
        _positive_integer(self.workspace_inode, "workspace_inode")
        _positive_integer(self.socket_device, "socket_device")
        _positive_integer(self.socket_inode, "socket_inode")
        if self.start_pending is not None and (
            type(self.start_pending) is not str
            or not self.start_pending
            or len(self.start_pending) > 128
            or "\x00" in self.start_pending
        ):
            raise ValueError("start_pending is invalid")
        if self.lifecycle not in _LIFECYCLES:
            raise ValueError("lifecycle is invalid")
        if not isinstance(self.owned_processes, tuple):
            raise TypeError("owned_processes must be a tuple")
        if len(self.owned_processes) > _MAX_OWNED_PROCESSES:
            raise ValueError("owned process inventory is too large")
        pids: set[int] = set()
        groups: set[int] = set()
        for process in self.owned_processes:
            if not isinstance(process, OwnedProcessDescriptor):
                raise TypeError("owned process inventory is invalid")
            if process.pid in pids or process.process_group in groups:
                raise ValueError("owned process inventory contains duplicates")
            pids.add(process.pid)
            groups.add(process.process_group)

    def to_mapping(self) -> dict[str, object]:
        return {
            "pid": self.pid,
            "proc_start_time": self.proc_start_time,
            "executable": self.executable,
            "process_group": self.process_group,
            "workspace": self.workspace,
            "socket_path": self.socket_path,
            "workspace_device": self.workspace_device,
            "workspace_inode": self.workspace_inode,
            "socket_device": self.socket_device,
            "socket_inode": self.socket_inode,
            "start_pending": self.start_pending,
            "lifecycle": self.lifecycle,
            "owned_processes": [process.to_mapping() for process in self.owned_processes],
        }

    @classmethod
    def from_mapping(cls, value: object) -> "RuntimeDescriptor":
        if type(value) is not dict or set(value) != _DESCRIPTOR_FIELDS:
            raise RuntimeSafetyError("runtime descriptor has invalid fields")
        processes = value.get("owned_processes")
        if type(processes) is not list:
            raise RuntimeSafetyError("owned process inventory is invalid")
        copied = dict(value)
        copied["owned_processes"] = tuple(
            OwnedProcessDescriptor.from_mapping(process) for process in processes
        )
        try:
            return cls(**copied)  # type: ignore[arg-type]
        except (TypeError, ValueError) as error:
            raise RuntimeSafetyError("runtime descriptor has invalid values") from error


@dataclass(frozen=True)
class _ProcessIdentity:
    pid: int
    start_time: int
    executable: str
    process_group: int


def current_runtime_descriptor(
    workspace: Path,
    socket_path: Path,
    owned_processes: Iterable[OwnedProcessDescriptor] = (),
) -> RuntimeDescriptor:
    """Describe the current launcher and all currently owned agents."""

    identity = _observe_process(os.getpid())
    workspace = Path(workspace).absolute()
    socket_path = Path(socket_path).absolute()
    try:
        workspace_metadata = workspace.lstat()
        socket_metadata = socket_path.lstat()
    except OSError as error:
        raise RuntimeSafetyError("current retained paths are unavailable") from error
    return RuntimeDescriptor(
        pid=identity.pid,
        proc_start_time=identity.start_time,
        executable=identity.executable,
        process_group=identity.process_group,
        workspace=str(workspace),
        socket_path=str(socket_path),
        workspace_device=workspace_metadata.st_dev,
        workspace_inode=workspace_metadata.st_ino,
        socket_device=socket_metadata.st_dev,
        socket_inode=socket_metadata.st_ino,
        owned_processes=tuple(owned_processes),
    )


def default_runtime_paths() -> tuple[Path, Path, Path]:
    configured = os.environ.get("XDG_RUNTIME_DIR")
    runtime_dir = (
        Path(configured) / "aster-quickstart"
        if configured
        else Path("/tmp") / f"aster-quickstart-runtime-{os.geteuid()}"
    )
    return runtime_dir, runtime_dir / "runtime.lock", runtime_dir / "runtime.json"


class RuntimeRegistry:
    """Serialize launches and retain crash-recoverable owner state."""

    def __init__(self, lock_path: Path, descriptor_path: Path) -> None:
        self.lock_path = Path(lock_path)
        self.descriptor_path = Path(descriptor_path)
        if not self.lock_path.is_absolute() or not self.descriptor_path.is_absolute():
            raise ValueError("runtime registry paths must be absolute")
        if self.lock_path.parent != self.descriptor_path.parent:
            raise ValueError("runtime registry paths must share a directory")
        if self.lock_path == self.descriptor_path:
            raise ValueError("runtime lock and descriptor must differ")
        self._lock_fd: int | None = None
        self._parent_fd: int | None = None
        self._parent_identity: tuple[int, int] | None = None
        self._removal_phase: str | None = None

    @property
    def runtime_dir(self) -> Path:
        return self.lock_path.parent

    def acquire(self) -> None:
        if self._lock_fd is not None:
            raise RuntimeError("runtime registry is already acquired")
        self._ensure_parent()
        parent_fd = self._open_parent()
        lock_fd: int | None = None
        flags = os.O_RDWR | os.O_CREAT | os.O_CLOEXEC | os.O_NOFOLLOW
        try:
            lock_fd = os.open(self.lock_path.name, flags, _FILE_MODE, dir_fd=parent_fd)
            metadata = os.fstat(lock_fd)
            if not _owner_file(metadata):
                raise RuntimeSafetyError("runtime lock is not owner-only")
            fcntl.flock(lock_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError as error:
            if lock_fd is not None:
                os.close(lock_fd)
            os.close(parent_fd)
            raise RuntimeActiveError("quickstart is already running") from error
        except OSError as error:
            if lock_fd is not None:
                os.close(lock_fd)
            os.close(parent_fd)
            raise RuntimeSafetyError("runtime lock is unsafe") from error
        except BaseException:
            if lock_fd is not None:
                os.close(lock_fd)
            os.close(parent_fd)
            raise
        self._parent_fd = parent_fd
        self._parent_identity = _identity(os.fstat(parent_fd))
        self._lock_fd = lock_fd

    def publish(self, descriptor: RuntimeDescriptor) -> None:
        self._require_acquired()
        self._validate_descriptor_value(descriptor, require_endpoint=True)
        self._require_matching_process(_launcher_identity(descriptor))
        for process in descriptor.owned_processes:
            self._require_matching_process(_owned_identity(process), dedicated=True)
        self._write_descriptor_no_replace(descriptor)

    def update_owned_processes(self, processes: Iterable[OwnedProcessDescriptor]) -> None:
        self.update_process_state(processes, start_pending=None)

    def update_process_state(
        self,
        processes: Iterable[OwnedProcessDescriptor],
        *,
        start_pending: str | None,
    ) -> None:
        descriptor, inode = self._read_descriptor()
        if descriptor.lifecycle != "active":
            raise RuntimeSafetyError("runtime cleanup is pending")
        inventory = tuple(processes)
        candidate = replace(
            descriptor,
            owned_processes=inventory,
            start_pending=start_pending,
        )
        for process in inventory:
            self._require_matching_process(_owned_identity(process), dedicated=True)
        self._replace_descriptor(candidate, inode)

    def mark_cleanup_pending(self, processes: Iterable[OwnedProcessDescriptor]) -> None:
        descriptor, inode = self._read_descriptor()
        if descriptor.start_pending is not None:
            raise RuntimeSafetyError("an agent start is still pending")
        inventory = tuple(processes)
        candidate = replace(
            descriptor,
            lifecycle="cleanup_pending",
            owned_processes=inventory,
            start_pending=None,
        )
        for process in inventory:
            self._require_matching_process(_owned_identity(process), dedicated=True)
        self._replace_descriptor(candidate, inode)

    def read_live(self) -> RuntimeDescriptor:
        self._validate_existing_parent()
        parent_fd = self._open_parent()
        prior = self._parent_fd
        prior_identity = self._parent_identity
        try:
            self._parent_fd = parent_fd
            self._parent_identity = _identity(os.fstat(parent_fd))
            descriptor, _inode = self._read_descriptor()
            if descriptor.lifecycle != "active":
                raise RuntimeSafetyError("runtime cleanup is pending")
            self._validate_descriptor_value(descriptor, require_endpoint=True)
            self._require_matching_process(_launcher_identity(descriptor))
            for process in descriptor.owned_processes:
                self._require_matching_process(_owned_identity(process), dedicated=True)
            return descriptor
        finally:
            self._parent_fd = prior
            self._parent_identity = prior_identity
            os.close(parent_fd)

    def recover_stale(self) -> RuntimeDescriptor | None:
        self._require_acquired()
        if self._entry_inode(self._removal_name()) is not None:
            self.remove_descriptor()
            return None
        try:
            descriptor, descriptor_inode = self._read_descriptor()
        except FileNotFoundError:
            return None
        self._validate_descriptor_paths(descriptor)
        if descriptor.lifecycle == "active":
            self._validate_descriptor_value(descriptor, require_endpoint=True)
        if descriptor.start_pending is not None:
            raise RuntimeSafetyError("runtime process inventory may be incomplete")

        handles: list[tuple[_ProcessIdentity, int]] = []
        try:
            for process in descriptor.owned_processes:
                identity = _owned_identity(process)
                try:
                    pidfd = self._open_verified_pidfd(identity, dedicated=True)
                except _ProcessGone:
                    self._wait_group_gone(identity.process_group)
                else:
                    handles.append((identity, pidfd))
            launcher = _launcher_identity(descriptor)
            try:
                self._require_matching_process(launcher)
            except _ProcessGone:
                pass
            else:
                raise RuntimeSafetyError("runtime launcher is still active")

            if self._descriptor_inode() != descriptor_inode:
                raise RuntimeSafetyError("runtime descriptor changed")
            for identity, pidfd in handles:
                self._terminate_verified_group(identity, pidfd)
            for identity, _pidfd in handles:
                self._wait_group_gone(identity.process_group)
        except (OSError, _ProcessGone) as error:
            raise RuntimeSafetyError(f"runtime remains at {descriptor.workspace}") from error
        finally:
            for _identity_value, pidfd in handles:
                os.close(pidfd)

        if descriptor.lifecycle == "active":
            pending = replace(
                descriptor,
                lifecycle="cleanup_pending",
                owned_processes=(),
                start_pending=None,
            )
            self._replace_descriptor(pending, descriptor_inode)
        self.delete_workspace()
        self.remove_descriptor()
        return descriptor

    def delete_workspace(self) -> None:
        """Quarantine and delete only the inode named by a cleanup descriptor."""

        descriptor, _inode = self._read_descriptor()
        if descriptor.lifecycle != "cleanup_pending" or descriptor.owned_processes:
            raise RuntimeSafetyError("runtime cleanup is not ready")
        workspace_name = self._find_workspace_inode(descriptor)
        if workspace_name is None:
            self._require_no_workspace_aliases(descriptor)
            return
        parent_fd = self._parent_fd_required()
        prefix = f".cleanup-{Path(descriptor.workspace).name}-"
        if not workspace_name.startswith(prefix):
            quarantine = prefix + secrets.token_hex(8)
            os.rename(workspace_name, quarantine, src_dir_fd=parent_fd, dst_dir_fd=parent_fd)
            moved = os.stat(quarantine, dir_fd=parent_fd, follow_symlinks=False)
            if _identity(moved) != (descriptor.workspace_device, descriptor.workspace_inode):
                raise RuntimeSafetyError("runtime workspace changed during quarantine")
            workspace_name = quarantine
            self._sync_parent()
        try:
            shutil.rmtree(workspace_name, dir_fd=parent_fd)
            self._sync_parent()
        except OSError as error:
            raise RuntimeSafetyError("runtime workspace cleanup failed") from error
        if self._find_workspace_inode(descriptor) is not None:
            raise RuntimeSafetyError("runtime workspace cleanup is incomplete")

    def remove_descriptor(self) -> None:
        self._require_acquired()
        canonical = self._entry_inode(self.descriptor_path.name)
        removal_name = self._removal_name()
        removal = self._entry_inode(removal_name)
        if canonical is None and removal is None:
            if self._removal_phase == "unlinked":
                self._sync_parent()
                self._removal_phase = None
            return
        if canonical is not None and removal is not None and canonical != removal:
            raise RuntimeSafetyError("runtime descriptor removal entry changed")
        source_name = self.descriptor_path.name if canonical is not None else removal_name
        descriptor, inode = self._read_descriptor_name(source_name)
        if descriptor.lifecycle != "cleanup_pending" or descriptor.owned_processes:
            raise RuntimeSafetyError("runtime cleanup is not complete")
        if descriptor.start_pending is not None:
            raise RuntimeSafetyError("runtime process inventory may be incomplete")
        if self._find_workspace_inode(descriptor) is not None:
            raise RuntimeSafetyError("runtime workspace still exists")
        self._require_no_workspace_aliases(descriptor)

        if removal is None:
            try:
                os.link(
                    self.descriptor_path.name,
                    removal_name,
                    src_dir_fd=self._parent_fd_required(),
                    dst_dir_fd=self._parent_fd_required(),
                    follow_symlinks=False,
                )
            except FileExistsError as error:
                raise RuntimeSafetyError("runtime descriptor removal entry exists") from error
            self._removal_phase = "linked"
            self._sync_parent()
            removal = self._entry_inode(removal_name)
            if removal != inode:
                raise RuntimeSafetyError("runtime descriptor removal entry changed")

        if canonical is not None:
            if self._entry_inode(self.descriptor_path.name) != inode:
                raise RuntimeSafetyError("runtime descriptor changed")
            os.unlink(self.descriptor_path.name, dir_fd=self._parent_fd_required())
            self._removal_phase = "removal_only"
            self._sync_parent()

        if self._entry_inode(removal_name) != inode:
            raise RuntimeSafetyError("runtime descriptor removal entry changed")
        os.unlink(removal_name, dir_fd=self._parent_fd_required())
        self._removal_phase = "unlinked"
        self._sync_parent()
        self._removal_phase = None

    def close(self, *, remove_descriptor: bool) -> None:
        if remove_descriptor:
            self.remove_descriptor()
        lock_fd, self._lock_fd = self._lock_fd, None
        parent_fd, self._parent_fd = self._parent_fd, None
        try:
            if lock_fd is not None:
                fcntl.flock(lock_fd, fcntl.LOCK_UN)
        finally:
            if lock_fd is not None:
                os.close(lock_fd)
            if parent_fd is not None:
                os.close(parent_fd)

    def _ensure_parent(self) -> None:
        try:
            self.runtime_dir.mkdir(mode=_DIRECTORY_MODE)
        except FileExistsError:
            pass
        self._validate_existing_parent()

    def _validate_existing_parent(self) -> None:
        try:
            metadata = self.runtime_dir.lstat()
            resolved = self.runtime_dir.resolve(strict=True)
        except OSError as error:
            raise RuntimeSafetyError("runtime directory is unavailable") from error
        if not _owner_directory(metadata) or resolved != self.runtime_dir.absolute():
            raise RuntimeSafetyError("runtime directory is not owner-only")

    def _open_parent(self) -> int:
        self._validate_existing_parent()
        try:
            descriptor = os.open(
                self.runtime_dir,
                os.O_RDONLY | os.O_CLOEXEC | os.O_DIRECTORY | os.O_NOFOLLOW,
            )
        except OSError as error:
            raise RuntimeSafetyError("runtime directory is unavailable") from error
        if not _owner_directory(os.fstat(descriptor)):
            os.close(descriptor)
            raise RuntimeSafetyError("runtime directory is not owner-only")
        return descriptor

    def _write_descriptor_no_replace(self, descriptor: RuntimeDescriptor) -> None:
        encoded = _encode_descriptor(descriptor)
        parent_fd = self._parent_fd_required()
        temporary = f".{self.descriptor_path.name}.{os.getpid()}.{secrets.token_hex(8)}"
        file_fd: int | None = None
        committed = False
        try:
            file_fd = os.open(
                temporary,
                os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC | os.O_NOFOLLOW,
                _FILE_MODE,
                dir_fd=parent_fd,
            )
            _write_all(file_fd, encoded)
            os.fsync(file_fd)
            os.close(file_fd)
            file_fd = None
            try:
                os.link(
                    temporary,
                    self.descriptor_path.name,
                    src_dir_fd=parent_fd,
                    dst_dir_fd=parent_fd,
                    follow_symlinks=False,
                )
            except FileExistsError as error:
                raise RuntimeSafetyError("runtime descriptor already exists") from error
            committed = True
            try:
                self._sync_parent()
            except OSError as error:
                raise RuntimePublicationCommittedError(
                    "runtime descriptor was committed but not durability-confirmed"
                ) from error
        finally:
            if file_fd is not None:
                os.close(file_fd)
            try:
                os.unlink(temporary, dir_fd=parent_fd)
            except FileNotFoundError:
                pass
            except OSError as error:
                if committed:
                    raise RuntimePublicationCommittedError(
                        "runtime descriptor was committed but staging cleanup failed"
                    ) from error
                raise

    def _replace_descriptor(self, descriptor: RuntimeDescriptor, expected_inode: tuple[int, int]) -> None:
        encoded = _encode_descriptor(descriptor)
        parent_fd = self._parent_fd_required()
        temporary = f".{self.descriptor_path.name}.{os.getpid()}.{secrets.token_hex(8)}"
        file_fd: int | None = None
        try:
            file_fd = os.open(
                temporary,
                os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC | os.O_NOFOLLOW,
                _FILE_MODE,
                dir_fd=parent_fd,
            )
            _write_all(file_fd, encoded)
            os.fsync(file_fd)
            os.close(file_fd)
            file_fd = None
            if self._descriptor_inode() != expected_inode:
                raise RuntimeSafetyError("runtime descriptor changed")
            os.replace(
                temporary,
                self.descriptor_path.name,
                src_dir_fd=parent_fd,
                dst_dir_fd=parent_fd,
            )
            self._sync_parent()
        finally:
            if file_fd is not None:
                os.close(file_fd)
            try:
                os.unlink(temporary, dir_fd=parent_fd)
            except FileNotFoundError:
                pass

    def _read_descriptor(self) -> tuple[RuntimeDescriptor, tuple[int, int]]:
        return self._read_descriptor_name(self.descriptor_path.name)

    def _read_descriptor_name(
        self, name: str
    ) -> tuple[RuntimeDescriptor, tuple[int, int]]:
        parent_fd = self._parent_fd_required()
        try:
            file_fd = os.open(
                name,
                os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW,
                dir_fd=parent_fd,
            )
        except FileNotFoundError:
            raise
        except OSError as error:
            raise RuntimeSafetyError("runtime descriptor is unavailable") from error
        try:
            metadata = os.fstat(file_fd)
            if not _owner_file(metadata):
                raise RuntimeSafetyError("runtime descriptor is not owner-only")
            payload = os.read(file_fd, _MAX_DESCRIPTOR_BYTES + 1)
            if len(payload) > _MAX_DESCRIPTOR_BYTES:
                raise RuntimeSafetyError("runtime descriptor is too large")
        finally:
            os.close(file_fd)
        try:
            decoded = json.loads(payload, object_pairs_hook=_unique_object)
        except (UnicodeDecodeError, json.JSONDecodeError, ValueError) as error:
            raise RuntimeSafetyError("runtime descriptor is invalid") from error
        return RuntimeDescriptor.from_mapping(decoded), _identity(metadata)

    def _removal_name(self) -> str:
        return self.descriptor_path.name + ".removing"

    def _entry_inode(self, name: str) -> tuple[int, int] | None:
        try:
            metadata = os.stat(
                name,
                dir_fd=self._parent_fd_required(),
                follow_symlinks=False,
            )
        except FileNotFoundError:
            return None
        except OSError as error:
            raise RuntimeSafetyError("runtime descriptor entry is unavailable") from error
        if not _owner_file(metadata):
            raise RuntimeSafetyError("runtime descriptor entry is unsafe")
        return _identity(metadata)

    def _descriptor_inode(self) -> tuple[int, int]:
        try:
            metadata = os.stat(
                self.descriptor_path.name,
                dir_fd=self._parent_fd_required(),
                follow_symlinks=False,
            )
        except OSError as error:
            raise RuntimeSafetyError("runtime descriptor changed") from error
        if not _owner_file(metadata):
            raise RuntimeSafetyError("runtime descriptor changed")
        return _identity(metadata)

    def _validate_descriptor_value(
        self, descriptor: RuntimeDescriptor, *, require_endpoint: bool
    ) -> None:
        workspace_name = self._locate_workspace(descriptor)
        if require_endpoint:
            workspace_fd = self._open_workspace(workspace_name, descriptor)
            try:
                endpoint = os.stat(
                    Path(descriptor.socket_path).name,
                    dir_fd=workspace_fd,
                    follow_symlinks=False,
                )
            except OSError as error:
                raise RuntimeSafetyError("runtime endpoint is unavailable") from error
            finally:
                os.close(workspace_fd)
            if (
                endpoint.st_uid != os.geteuid()
                or stat.S_ISLNK(endpoint.st_mode)
                or stat.S_ISDIR(endpoint.st_mode)
                or stat.S_IMODE(endpoint.st_mode) != _FILE_MODE
                or _identity(endpoint) != (descriptor.socket_device, descriptor.socket_inode)
            ):
                raise RuntimeSafetyError("runtime endpoint changed")

    def _validate_descriptor_paths(self, descriptor: RuntimeDescriptor) -> None:
        expected_name = Path(descriptor.workspace).name
        if Path(descriptor.workspace).parent != self.runtime_dir:
            raise RuntimeSafetyError(f"unsafe retained path {descriptor.workspace}")
        if Path(descriptor.socket_path).parent != Path(descriptor.workspace):
            raise RuntimeSafetyError(f"unsafe retained path {descriptor.workspace}")
        if expected_name in {"", ".", ".."}:
            raise RuntimeSafetyError(f"unsafe retained path {descriptor.workspace}")

    def _locate_workspace(self, descriptor: RuntimeDescriptor) -> str:
        self._validate_descriptor_paths(descriptor)
        found = self._find_workspace_inode(descriptor)
        if found is None:
            raise RuntimeSafetyError(f"runtime remains at {descriptor.workspace}")
        return found

    def _find_workspace_inode(self, descriptor: RuntimeDescriptor) -> str | None:
        parent_fd = self._parent_fd_required()
        expected_name = Path(descriptor.workspace).name
        allowed_prefix = f".cleanup-{expected_name}-"
        for name in os.listdir(parent_fd):
            if name != expected_name and not name.startswith(allowed_prefix):
                continue
            try:
                metadata = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
            except FileNotFoundError:
                continue
            if _identity(metadata) == (descriptor.workspace_device, descriptor.workspace_inode):
                if not _owner_directory(metadata):
                    raise RuntimeSafetyError("runtime workspace is unsafe")
                return name
        return None

    def _require_no_workspace_aliases(self, descriptor: RuntimeDescriptor) -> None:
        """Prove a completed cleanup was not replaced by another directory entry."""

        expected_name = Path(descriptor.workspace).name
        allowed_prefix = f".cleanup-{expected_name}-"
        for name in os.listdir(self._parent_fd_required()):
            if name == expected_name or name.startswith(allowed_prefix):
                raise RuntimeSafetyError("runtime workspace entry was replaced")

    def _open_workspace(self, name: str, descriptor: RuntimeDescriptor) -> int:
        try:
            workspace_fd = os.open(
                name,
                os.O_RDONLY | os.O_CLOEXEC | os.O_DIRECTORY | os.O_NOFOLLOW,
                dir_fd=self._parent_fd_required(),
            )
        except OSError as error:
            raise RuntimeSafetyError("runtime workspace is unavailable") from error
        metadata = os.fstat(workspace_fd)
        if (
            not _owner_directory(metadata)
            or _identity(metadata) != (descriptor.workspace_device, descriptor.workspace_inode)
        ):
            os.close(workspace_fd)
            raise RuntimeSafetyError("runtime workspace changed")
        return workspace_fd

    def _open_verified_pidfd(self, expected: _ProcessIdentity, *, dedicated: bool = False) -> int:
        self._require_matching_process(expected, dedicated=dedicated)
        try:
            pidfd = os.pidfd_open(expected.pid)
        except ProcessLookupError as error:
            raise _ProcessGone from error
        except OSError as error:
            raise RuntimeSafetyError("process identity is unavailable") from error
        try:
            self._require_matching_process(expected, dedicated=dedicated)
        except BaseException:
            os.close(pidfd)
            raise
        return pidfd

    @staticmethod
    def _require_matching_process(
        expected: _ProcessIdentity, *, dedicated: bool = False
    ) -> _ProcessIdentity:
        observed = _observe_process(expected.pid)
        if observed != expected or (dedicated and observed.pid != observed.process_group):
            raise RuntimeSafetyError("runtime process identity is unproven")
        return observed

    @staticmethod
    def _wait_group_gone(process_group: int) -> None:
        deadline = time.monotonic() + _PROCESS_EXIT_TIMEOUT
        while True:
            try:
                os.killpg(process_group, 0)
            except ProcessLookupError:
                return
            except OSError as error:
                if error.errno == errno.ESRCH:
                    return
                raise RuntimeSafetyError("owned process group observation failed") from error
            if time.monotonic() >= deadline:
                raise RuntimeSafetyError("owned process group did not exit")
            time.sleep(0.01)

    @staticmethod
    def _terminate_verified_group(identity: _ProcessIdentity, pidfd: int) -> None:
        """Pin the leader stopped so its numeric PGID cannot be reused mid-signal."""

        signal.pidfd_send_signal(pidfd, signal.SIGSTOP)
        try:
            RuntimeRegistry._require_matching_process(identity, dedicated=True)
            os.killpg(identity.process_group, signal.SIGTERM)
        finally:
            try:
                signal.pidfd_send_signal(pidfd, signal.SIGCONT)
            except ProcessLookupError as error:
                poller = select.poll()
                poller.register(pidfd, select.POLLIN)
                if not poller.poll(0):
                    raise RuntimeSafetyError(
                        "owned process leader resume is unproven"
                    ) from error
            except OSError as error:
                raise RuntimeSafetyError("owned process leader resume failed") from error

    def _sync_parent(self) -> None:
        os.fsync(self._parent_fd_required())

    def _parent_fd_required(self) -> int:
        if self._parent_fd is None:
            raise RuntimeError("runtime registry is not acquired")
        if _identity(os.fstat(self._parent_fd)) != self._parent_identity:
            raise RuntimeSafetyError("runtime directory changed")
        return self._parent_fd

    def _require_acquired(self) -> None:
        if self._lock_fd is None or self._parent_fd is None:
            raise RuntimeError("runtime registry is not acquired")


def _observe_process(pid: int) -> _ProcessIdentity:
    try:
        raw = Path(f"/proc/{pid}/stat").read_text()
        executable = str(Path(f"/proc/{pid}/exe").resolve(strict=True))
    except FileNotFoundError as error:
        raise _ProcessGone from error
    except OSError as error:
        raise RuntimeSafetyError("process observation failed") from error
    closing = raw.rfind(")")
    fields = raw[closing + 2 :].split() if closing >= 0 else []
    if len(fields) < 20:
        raise RuntimeSafetyError("process observation is malformed")
    try:
        return _ProcessIdentity(
            pid=pid,
            start_time=int(fields[19]),
            executable=executable,
            process_group=int(fields[2]),
        )
    except ValueError as error:
        raise RuntimeSafetyError("process observation is malformed") from error


def _launcher_identity(descriptor: RuntimeDescriptor) -> _ProcessIdentity:
    return _ProcessIdentity(
        descriptor.pid,
        descriptor.proc_start_time,
        descriptor.executable,
        descriptor.process_group,
    )


def _owned_identity(descriptor: OwnedProcessDescriptor) -> _ProcessIdentity:
    return _ProcessIdentity(
        descriptor.pid,
        descriptor.proc_start_time,
        descriptor.executable,
        descriptor.process_group,
    )


def _owner_file(metadata: os.stat_result) -> bool:
    return (
        stat.S_ISREG(metadata.st_mode)
        and metadata.st_uid == os.geteuid()
        and stat.S_IMODE(metadata.st_mode) == _FILE_MODE
    )


def _owner_directory(metadata: os.stat_result) -> bool:
    return (
        stat.S_ISDIR(metadata.st_mode)
        and metadata.st_uid == os.geteuid()
        and stat.S_IMODE(metadata.st_mode) == _DIRECTORY_MODE
    )


def _encode_descriptor(descriptor: RuntimeDescriptor) -> bytes:
    if not isinstance(descriptor, RuntimeDescriptor):
        raise TypeError("descriptor must be a RuntimeDescriptor")
    encoded = json.dumps(
        descriptor.to_mapping(), sort_keys=True, separators=(",", ":")
    ).encode("utf-8") + b"\n"
    if len(encoded) > _MAX_DESCRIPTOR_BYTES:
        raise RuntimeSafetyError("runtime descriptor is too large")
    return encoded


def _write_all(file_descriptor: int, payload: bytes) -> None:
    view = memoryview(payload)
    while view:
        written = os.write(file_descriptor, view)
        view = view[written:]


def _identity(metadata: os.stat_result) -> tuple[int, int]:
    return metadata.st_dev, metadata.st_ino


def _unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate runtime descriptor field")
        result[key] = value
    return result


__all__ = [
    "OwnedProcessDescriptor",
    "RuntimeActiveError",
    "RuntimeDescriptor",
    "RuntimePublicationCommittedError",
    "RuntimeRegistry",
    "RuntimeSafetyError",
    "current_runtime_descriptor",
    "default_runtime_paths",
]
