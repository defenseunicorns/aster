"""One owner-scoped, two-node Aster quickstart session."""

from __future__ import annotations

from dataclasses import dataclass
import ipaddress
import math
import os
from pathlib import Path
import re
import secrets
import shutil
import socket
import stat
import subprocess
import sys
import threading
import time
from typing import BinaryIO, Callable, Literal, Sequence
from urllib.parse import unquote, urlparse

from .connect import ConnectError, ConnectJsonClient, NumberedPublisher
from .linux_process import (
    OwnedProcessGroup,
    ProcessIdentity,
    ProcessSafetyError,
    group_is_gone,
)
from .transcript import CommandHandle, TranscriptJournal


MAX_CAPTURE_BYTES = 256 * 1024
MAX_PARSED_LINE_BYTES = 64 * 1024
MAX_RETAINED_AGENT_RUNS = 3
IDENTITY = re.compile(r"^[0-9a-f]{64}$")
NodeRole = Literal["publisher", "receiver"]


class AsterSessionError(RuntimeError):
    """A sanitized session provisioning, child, or evidence failure."""


class RecoverableOfflinePublishError(AsterSessionError):
    """An offline experiment failed after the authenticated topology recovered."""


@dataclass(frozen=True)
class AsterBinaries:
    aster: Path
    agent: Path
    ctl: Path

    def validate(self) -> "AsterBinaries":
        resolved: list[Path] = []
        for label, candidate in (
            ("aster", self.aster),
            ("aster-agent", self.agent),
            ("asterctl", self.ctl),
        ):
            path = Path(candidate)
            try:
                actual = path.resolve(strict=True)
            except OSError as error:
                raise AsterSessionError(f"{label} binary is unavailable") from error
            if not actual.is_file() or not os.access(actual, os.X_OK):
                raise AsterSessionError(f"{label} binary is not executable")
            resolved.append(actual)
        if len(set(resolved)) != 3:
            raise AsterSessionError("Aster binary paths must identify three distinct executables")
        return self


@dataclass(frozen=True)
class _OwnedProcess:
    """Exact Linux identity for one dedicated quickstart child group."""

    pid: int
    proc_start_time: int
    executable: str
    process_group: int


@dataclass(frozen=True)
class _InitNode:
    index: int
    carrier_id: str
    mission_id: str


@dataclass
class _Node:
    init: _InitNode
    state: Path
    mission: Path
    token_path: Path
    token: str
    mesh_port: int
    publisher: NumberedPublisher
    process: "_BoundedProcess | None" = None
    client: ConnectJsonClient | None = None
    peered: bool = False
    log_path: str | None = None


def _parse_fields(line: str) -> tuple[str, dict[str, str]] | None:
    tokens = line.strip().split()
    if not tokens:
        return "", {}
    fields: dict[str, str] = {}
    for token in tokens[1:]:
        if token.count("=") != 1:
            return None
        key, value = token.split("=", 1)
        if not key or not value or key in fields:
            return None
        fields[key] = value
    return tokens[0], fields


def _is_loopback_http_url(value: str) -> bool:
    parsed = urlparse(value)
    try:
        return (
            parsed.scheme == "http"
            and parsed.hostname is not None
            and ipaddress.ip_address(parsed.hostname).is_loopback
            and parsed.port is not None
            and parsed.username is None
            and parsed.password is None
            and not parsed.query
            and not parsed.fragment
        )
    except ValueError:
        return False


def _group_is_gone(pgid: int) -> bool:
    """Return true only for the kernel's authoritative ESRCH result."""
    try:
        return group_is_gone(pgid)
    except ProcessSafetyError as error:
        raise AsterSessionError("owned child process group observation failed") from error


class _BoundedProcess:
    """A process group with bounded byte logs and optional readiness parsing."""

    def __init__(
        self,
        command: Sequence[str],
        stdout_path: Path | None,
        stderr_path: Path | None,
        *,
        parse_readiness: bool = False,
        output_dir_fd: int | None = None,
        transcript_handle: CommandHandle | None = None,
    ) -> None:
        self.command = tuple(command)
        self._parse_readiness = parse_readiness
        self._ready = threading.Event()
        self._ready_url: str | None = None
        self._buffers = {"stdout": bytearray(), "stderr": bytearray()}
        self._overflow = {"stdout": False, "stderr": False}
        self._threads: list[threading.Thread] = []
        self._files: list[BinaryIO] = []
        self._closed = False
        self._stopped = False
        self._stop_lock = threading.Lock()
        self._overflow_stop_requested = threading.Event()
        self._transcript_handle = transcript_handle
        outputs: dict[str, BinaryIO | None] = {"stdout": None, "stderr": None}
        try:
            for name, path in (("stdout", stdout_path), ("stderr", stderr_path)):
                if path is not None:
                    descriptor = os.open(
                        path.name if output_dir_fd is not None else path,
                        os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                        0o600,
                        dir_fd=output_dir_fd,
                    )
                    output = os.fdopen(descriptor, "wb", buffering=0)
                    outputs[name] = output
                    self._files.append(output)
            self.process = subprocess.Popen(
                list(command),
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                start_new_session=True,
                bufsize=0,
            )
        except BaseException:
            for output in self._files:
                output.close()
            if self._transcript_handle is not None:
                self._transcript_handle.finish(None, outcome="spawn failed")
            raise
        try:
            self._ownership = OwnedProcessGroup.capture(self.process.pid)
        except BaseException as error:
            try:
                self.process.kill()
                self.process.wait(timeout=1.0)
            finally:
                for stream in (self.process.stdout, self.process.stderr):
                    if stream is not None:
                        stream.close()
                for output in self._files:
                    output.close()
            if self._transcript_handle is not None:
                self._transcript_handle.finish(self.process.returncode, outcome="identity failed")
            raise ProcessSafetyError("owned child identity could not be captured") from error
        assert self.process.stdout is not None and self.process.stderr is not None
        for name, stream in (("stdout", self.process.stdout), ("stderr", self.process.stderr)):
            thread = threading.Thread(
                target=self._pump,
                args=(name, stream, outputs[name]),
                name=f"aster-quickstart-{name}-{self.process.pid}",
                daemon=True,
            )
            self._threads.append(thread)
            thread.start()

    @property
    def pid(self) -> int:
        return self.process.pid

    @property
    def ownership_identity(self) -> ProcessIdentity:
        return self._ownership.identity

    def owned_identity(self) -> _OwnedProcess:
        identity = self._ownership.identity
        return _OwnedProcess(
            pid=identity.pid,
            proc_start_time=identity.proc_start_time,
            executable=identity.executable,
            process_group=identity.process_group,
        )

    @property
    def stdout(self) -> bytes:
        return bytes(self._buffers["stdout"])

    @property
    def stderr(self) -> bytes:
        return bytes(self._buffers["stderr"])

    @property
    def overflowed(self) -> bool:
        return any(self._overflow.values())

    def _pump(self, name: str, stream: BinaryIO, output: BinaryIO | None) -> None:
        pending = bytearray()
        discard_line = False
        try:
            while True:
                chunk = stream.read(4096)
                if not chunk:
                    break
                remaining = max(0, MAX_CAPTURE_BYTES - len(self._buffers[name]))
                if remaining:
                    retained = chunk[:remaining]
                    self._buffers[name].extend(retained)
                    if output is not None:
                        output.write(retained)
                    if self._transcript_handle is not None:
                        self._transcript_handle.update(**{name: retained})
                if len(chunk) > remaining:
                    self._overflow[name] = True
                    self._stop_for_output_overflow()
                if name != "stdout" or not self._parse_readiness:
                    continue
                pending.extend(chunk)
                while True:
                    if discard_line:
                        split = pending.find(b"\n")
                        if split < 0:
                            pending.clear()
                            break
                        del pending[: split + 1]
                        discard_line = False
                        continue
                    split = pending.find(b"\n")
                    if split < 0:
                        if len(pending) > MAX_PARSED_LINE_BYTES:
                            pending.clear()
                            discard_line = True
                        break
                    line = bytes(pending[:split])
                    del pending[: split + 1]
                    if len(line) <= MAX_PARSED_LINE_BYTES:
                        self._observe_readiness(line)
            if pending and not discard_line and len(pending) <= MAX_PARSED_LINE_BYTES:
                self._observe_readiness(bytes(pending))
        finally:
            try:
                stream.close()
            except OSError:
                pass

    def _stop_for_output_overflow(self) -> None:
        if self._overflow_stop_requested.is_set():
            return
        self._overflow_stop_requested.set()
        try:
            self.stop(outcome="output overflow")
        except AsterSessionError:
            # The caller that observes the failed process lifecycle reports the
            # sanitized error; this pump must only preserve its bounded output.
            pass

    def _observe_readiness(self, line: bytes) -> None:
        text = line.decode("utf-8", errors="replace").strip()
        parsed = _parse_fields(text)
        if parsed is None:
            return
        kind, fields = parsed
        listen = fields.get("listen", "")
        if (
            kind == "AGENT"
            and {"status", "listen"}.issubset(fields)
            and fields["status"] == "ready"
            and _is_loopback_http_url(listen)
        ):
            self._ready_url = listen
            self._ready.set()

    def wait(self, timeout: float, cancel_event: threading.Event | None = None) -> int:
        deadline = time.monotonic() + timeout
        while True:
            if cancel_event is not None and cancel_event.is_set():
                self.stop(outcome="cancelled")
                raise AsterSessionError("Aster session preparation was cancelled")
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                self.stop(outcome="timed out")
                raise AsterSessionError("playground initialization timed out")
            try:
                returncode = self.process.wait(timeout=min(0.03, remaining))
                break
            except subprocess.TimeoutExpired:
                continue
        if not _group_is_gone(self.process.pid):
            self.stop(outcome="process group retained")
        else:
            self._ownership.close()
            self.close_streams()
            outcome = "output overflow" if self.overflowed else "succeeded" if returncode == 0 else "failed"
            self._finish_transcript(returncode, outcome)
        return returncode

    def wait_ready(self, timeout: float, cancel_event: threading.Event | None = None) -> str:
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            if self.overflowed:
                self.stop(outcome="output overflow")
                raise AsterSessionError("agent output exceeds its bound")
            if cancel_event is not None and cancel_event.is_set():
                self.stop(outcome="cancelled")
                raise AsterSessionError("Aster session preparation was cancelled")
            if self._ready.wait(min(0.03, max(0.0, deadline - time.monotonic()))):
                if self.overflowed:
                    self.stop(outcome="output overflow")
                    raise AsterSessionError("agent output exceeds its bound")
                assert self._ready_url is not None
                return self._ready_url
            returncode = self.process.poll()
            if returncode is not None:
                if _group_is_gone(self.process.pid):
                    self._ownership.close()
                    self.close_streams()
                    outcome = "output overflow" if self.overflowed else "failed"
                    self._finish_transcript(returncode, outcome)
                else:
                    self.stop(outcome="failed")
                if self.overflowed:
                    raise AsterSessionError("agent output exceeds its bound")
                raise AsterSessionError(f"agent exited before readiness with status {returncode}")
        self.stop(outcome="timed out")
        raise AsterSessionError("agent did not become ready before the startup deadline")

    def stop(self, *, outcome: str = "stopped") -> None:
        current = threading.current_thread()
        if not self._stop_lock.acquire(blocking=False):
            if current in self._threads:
                return
            self._stop_lock.acquire()
        try:
            if self._stopped:
                return
            try:
                self._ownership.stop(self.process, 1.2)
            except ProcessSafetyError as error:
                final_outcome = "output overflow" if self.overflowed else "cleanup failed"
                self._finish_transcript(self.process.returncode, final_outcome)
                raise AsterSessionError(str(error)) from error
            self._stopped = True
            self.close_streams()
            final_outcome = "output overflow" if self.overflowed else outcome
            self._finish_transcript(self.process.returncode, final_outcome)
        finally:
            self._stop_lock.release()

    def _finish_transcript(self, returncode: int | None, outcome: str) -> None:
        if self._transcript_handle is not None:
            self._transcript_handle.finish(returncode, outcome=outcome)

    def close_streams(self) -> None:
        if self._closed:
            return
        self._closed = True
        current = threading.current_thread()
        for thread in self._threads:
            if thread is current:
                continue
            thread.join(timeout=1.0)
        for output in self._files:
            output.close()


class AsterSession:
    """A direct Atlas-to-Beacon invitation session owned by one launcher."""

    def __init__(
        self,
        binaries: AsterBinaries,
        root: Path,
        startup_timeout: float = 8.0,
        rpc_timeout: float = 3.0,
        cancel_event: threading.Event | None = None,
        transcript: TranscriptJournal | None = None,
    ) -> None:
        if not sys.platform.startswith("linux"):
            raise AsterSessionError("the Aster quickstart supports Linux only")
        self.binaries = binaries
        self.root = Path(root)
        self.startup_timeout = self._bounded_timeout(startup_timeout, "startup", 60.0)
        self.rpc_timeout = self._bounded_timeout(rpc_timeout, "RPC", 30.0)
        self.cancel_event = cancel_event
        self.transcript = transcript
        self._lock = threading.RLock()
        self._nodes: list[_Node] = []
        self._reservations: list[socket.socket | None] = []
        self._initialized = False
        self._authenticated = False
        self._closed = False
        self._publication_counter = 0
        self._agent_generation = 0
        self._start_pending: str | None = None
        self._transient_processes: dict[str, _OwnedProcess] = {}
        self._process_inventory_observer: (
            Callable[[tuple[_OwnedProcess, ...], str | None], None] | None
        ) = None

    @staticmethod
    def _bounded_timeout(value: float, label: str, maximum: float) -> float:
        try:
            timeout = float(value)
        except (TypeError, ValueError) as error:
            raise AsterSessionError(f"{label} timeout is invalid") from error
        if not math.isfinite(timeout) or not 0 < timeout <= maximum:
            raise AsterSessionError(f"{label} timeout is outside its bound")
        return timeout

    @property
    def owned_pids(self) -> tuple[int, ...]:
        with self._lock:
            return tuple(node.process.pid for node in self._nodes if node.process is not None)

    def set_process_inventory_observer(
        self,
        observer: Callable[[tuple[_OwnedProcess, ...], str | None], None],
    ) -> None:
        """Publish the complete child inventory synchronously at ownership boundaries."""

        if not callable(observer):
            raise AsterSessionError("process inventory observer is invalid")
        with self._lock:
            if self._process_inventory_observer is not None:
                raise AsterSessionError("process inventory observer is already configured")
            self._process_inventory_observer = observer
            self._publish_process_inventory()

    def _publish_process_inventory(self) -> None:
        observer = self._process_inventory_observer
        if observer is None:
            return
        inventory = tuple(
            node.process.owned_identity()
            for node in self._nodes
            if node.process is not None
        ) + tuple(self._transient_processes.values())
        observer(inventory, self._start_pending)

    def _before_child_spawn(self, label: str) -> None:
        if self._start_pending is not None or label in self._transient_processes:
            raise AsterSessionError("another owned child spawn is pending")
        self._start_pending = label
        try:
            self._publish_process_inventory()
        except BaseException:
            self._start_pending = None
            try:
                self._publish_process_inventory()
            except Exception:
                pass
            raise

    def _after_child_spawn(self, label: str, identity: ProcessIdentity) -> None:
        if self._start_pending != label:
            raise AsterSessionError("owned child spawn state is inconsistent")
        self._transient_processes[label] = _OwnedProcess(
            identity.pid,
            identity.proc_start_time,
            identity.executable,
            identity.process_group,
        )
        self._start_pending = None
        self._publish_process_inventory()

    def _after_child_gone(self, label: str) -> None:
        if self._start_pending == label:
            self._start_pending = None
        self._transient_processes.pop(label, None)
        self._publish_process_inventory()

    def _start_command(self, step: str, command: Sequence[str]) -> CommandHandle | None:
        if self.transcript is None:
            return None
        return self.transcript.start_command(step, command, cwd=os.getcwd())

    def initialize(self) -> dict[str, object]:
        with self._lock:
            self._raise_if_cancelled()
            if self._closed:
                raise AsterSessionError("the Aster session is closed")
            if not self._initialized:
                self.binaries.validate()
                root = self._validated_new_root()
                self.root = root
                try:
                    init_nodes = self._initialize(root)
                    self._nodes = self._configure_nodes(root, init_nodes)
                except BaseException as error:
                    cleanup_error = self._finalize_terminal_cleanup()
                    if isinstance(error, (KeyboardInterrupt, SystemExit)):
                        raise
                    if cleanup_error is not None:
                        raise AsterSessionError("Aster session initialization and cleanup failed") from error
                    if isinstance(error, AsterSessionError):
                        raise
                    if isinstance(error, ConnectError):
                        raise AsterSessionError(str(error)) from error
                    raise AsterSessionError("Aster session initialization failed") from error
                self._initialized = True
            return self._initialized_fact()

    def start_node(
        self,
        role: NodeRole,
        *,
        authenticated: bool = False,
    ) -> dict[str, object]:
        with self._lock:
            if authenticated:
                raise AsterSessionError("authenticated node starts are reserved for controlled authentication")
            index = self._role_index(role)
            self._require_initialized()
            self._raise_if_cancelled()
            node = self._nodes[index]
            if node.process is not None and node.process.process.poll() is None:
                return self._running_node_receipt(role, node)
            if node.process is not None:
                cleanup_error = self._stop_node_index(index, reserve=True)
                if cleanup_error is not None:
                    raise AsterSessionError(f"could not stop agent process for node {index}") from cleanup_error
            self._invalidate_authentication()
            try:
                self._start_node(index, with_contacts=False, transcript_step=role)
            except BaseException as error:
                cleanup_error = self._stop_node_index(index, reserve=True)
                if isinstance(error, (KeyboardInterrupt, SystemExit)):
                    raise
                if cleanup_error is not None:
                    raise AsterSessionError(f"agent startup and cleanup failed for node {index}") from error
                if isinstance(error, AsterSessionError):
                    raise
                if isinstance(error, ConnectError):
                    raise AsterSessionError(str(error)) from error
                raise AsterSessionError(f"could not start agent process for node {index}") from error
            assert node.process is not None
            return self._running_node_receipt(role, node)

    def stop_node(self, role: NodeRole) -> dict[str, object]:
        with self._lock:
            index = self._role_index(role)
            self._require_initialized()
            self._invalidate_authentication()
            cleanup_error = self._stop_node_index(index, reserve=True)
            if cleanup_error is not None:
                raise AsterSessionError(f"could not stop agent process for node {index}") from cleanup_error
            return {
                "role": role,
                "state": "stopped",
                "port": self._nodes[index].mesh_port,
            }

    def authenticate(
        self,
        progress: Callable[[dict[str, object]], None] | None = None,
    ) -> dict[str, object]:
        with self._lock:
            self._require_initialized()
            result = {"status": "authenticated", "challenge": "verified"}
            try:
                self._raise_if_cancelled()
                if progress is not None and not callable(progress):
                    raise AsterSessionError("authentication progress observer is invalid")
                if self._has_live_authenticated_topology():
                    return result
                self._invalidate_authentication()
                self._report_progress(progress, {"status": "authenticating"})
                self._require_live_nodes()
                self._restart_nodes(with_contacts=True, transcript_step="authentication")
                self._create_subscriptions(transcript_step="authentication")
                challenge = secrets.token_bytes(32)
                if self.transcript is not None:
                    self.transcript.register_secret(challenge)
                try:
                    publication = self._nodes[0].publisher.publish(
                        b"quickstart-auth-challenge-" + secrets.token_hex(16).encode("ascii"),
                        challenge,
                        transcript_step="authentication",
                    )
                    event = self._wait_for_event(self._nodes[1], publication.event_id, challenge)
                    if event is None:
                        raise AsterSessionError("Beacon did not observe the exact Event before the delivery deadline")
                    self._nodes[0].publisher.acknowledge(
                        publication, transcript_step="authentication"
                    )
                finally:
                    if self.transcript is not None:
                        self.transcript.release_secret(challenge)
                self._authenticated = True
                return result
            except BaseException as error:
                self._invalidate_authentication()
                cleanup_error = None if self._closed else self._stop_all_nodes(reserve=True)
                if isinstance(error, (KeyboardInterrupt, SystemExit)):
                    raise
                if cleanup_error is not None:
                    raise AsterSessionError("Aster authentication cleanup failed") from cleanup_error
                if isinstance(error, AsterSessionError):
                    raise
                if isinstance(error, ConnectError):
                    raise AsterSessionError(str(error)) from error
                raise AsterSessionError("Aster authentication failed") from error

    def _initialized_fact(self) -> dict[str, object]:
        return {
            "status": "initialized",
            "nodes": {
                "publisher": {"identity_fingerprint": self._nodes[0].init.carrier_id},
                "receiver": {"identity_fingerprint": self._nodes[1].init.carrier_id},
            },
        }

    @staticmethod
    def _role_index(role: NodeRole) -> int:
        if role == "publisher":
            return 0
        if role == "receiver":
            return 1
        raise AsterSessionError("node role is invalid")

    def _require_initialized(self) -> None:
        if self._closed or not self._initialized or len(self._nodes) != 2:
            raise AsterSessionError("the Aster session is not initialized")

    def _has_live_authenticated_topology(self) -> bool:
        return (
            self._authenticated
            and len(self._nodes) == 2
            and all(
                node.peered
                and node.process is not None
                and node.process.process.poll() is None
                for node in self._nodes
            )
        )

    def _invalidate_authentication(self) -> None:
        self._authenticated = False

    def _validated_new_root(self) -> Path:
        if not self.root.is_absolute() or self.root.name in {"", ".", ".."}:
            raise AsterSessionError("session root must be a new absolute child path")
        try:
            parent = self.root.parent.resolve(strict=True)
        except OSError as error:
            raise AsterSessionError("session root parent is unavailable") from error
        root = parent / self.root.name
        if root.exists() or root.is_symlink():
            raise AsterSessionError("session root already exists")
        return root

    def _initialize(self, root: Path) -> tuple[_InitNode, _InitNode]:
        command = [
            str(self.binaries.aster),
            "playground-init",
            "--nodes",
            "2",
            "--root",
            str(root),
        ]
        self._before_child_spawn("playground-init")
        handle = self._start_command("setup", command)
        try:
            process = _BoundedProcess(command, None, None, transcript_handle=handle)
        except OSError as error:
            self._after_child_gone("playground-init")
            raise AsterSessionError("could not start the Aster playground initializer") from error
        try:
            self._after_child_spawn("playground-init", process.ownership_identity)
        except BaseException:
            process.stop()
            self._after_child_gone("playground-init")
            raise
        try:
            returncode = process.wait(self.startup_timeout, self.cancel_event)
        finally:
            if _group_is_gone(process.pid):
                self._after_child_gone("playground-init")
        if process.overflowed:
            raise AsterSessionError("playground initializer output exceeds its bound")
        if returncode != 0:
            raise AsterSessionError("playground initializer failed")
        nodes = self._parse_initializer(process.stdout, root)
        self._validate_initialized_paths(root, nodes)
        logs = root / "logs"
        logs.mkdir(mode=0o700)
        self._write_owner_file(logs / "playground-init.stdout", process.stdout)
        self._write_owner_file(logs / "playground-init.stderr", process.stderr)
        return nodes

    def _parse_initializer(self, data: bytes, root: Path) -> tuple[_InitNode, _InitNode]:
        try:
            lines = [line for line in data.decode("utf-8").splitlines() if line.strip()]
        except UnicodeDecodeError as error:
            raise AsterSessionError("playground initializer output is malformed") from error
        if len(lines) != 3:
            raise AsterSessionError("playground initializer returned an unexpected record count")
        parsed_header = _parse_fields(lines[0])
        if parsed_header is None:
            raise AsterSessionError("playground initializer header is malformed")
        kind, header = parsed_header
        expected_header = {
            "status": "pass",
            "nodes": "2",
            "scope": "demo/playground",
            "topic": "mesh.messages",
            "epoch": "1",
            "provisioning": "unprotected-reference",
        }
        if kind != "PLAYGROUND_INIT" or any(header.get(key) != value for key, value in expected_header.items()):
            raise AsterSessionError("playground initializer header is malformed")
        if set(header) != {*expected_header, "root"}:
            raise AsterSessionError("playground initializer header is malformed")
        if Path(unquote(header["root"])).absolute() != root.absolute():
            raise AsterSessionError("playground initializer root differs from the owned root")
        parsed: dict[int, _InitNode] = {}
        for line in lines[1:]:
            parsed_record = _parse_fields(line)
            if parsed_record is None:
                raise AsterSessionError("playground initializer node record is malformed")
            record, fields = parsed_record
            if record != "PLAYGROUND_NODE" or set(fields) != {"index", "carrier_id", "mission_id"}:
                raise AsterSessionError("playground initializer node record is malformed")
            try:
                index = int(fields["index"])
            except ValueError as error:
                raise AsterSessionError("playground initializer node index is malformed") from error
            if index not in {0, 1} or index in parsed:
                raise AsterSessionError("playground initializer node indexes are incomplete")
            if IDENTITY.fullmatch(fields["carrier_id"]) is None or IDENTITY.fullmatch(fields["mission_id"]) is None:
                raise AsterSessionError("playground initializer identity is malformed")
            parsed[index] = _InitNode(index, fields["carrier_id"], fields["mission_id"])
        if set(parsed) != {0, 1}:
            raise AsterSessionError("playground initializer omitted a node")
        return parsed[0], parsed[1]

    def _validate_initialized_paths(self, root: Path, nodes: tuple[_InitNode, _InitNode]) -> None:
        try:
            metadata = root.lstat()
        except OSError as error:
            raise AsterSessionError("playground initializer omitted the session root") from error
        if not stat.S_ISDIR(metadata.st_mode) or stat.S_ISLNK(metadata.st_mode):
            raise AsterSessionError("initialized state is not contained by the session root")
        os.chmod(root, 0o700)
        resolved_root = root.resolve(strict=True)
        for node in nodes:
            state = root / f"node-{node.index}"
            mission = state / "mission.unprotected-reference.bundle"
            try:
                state_meta = state.lstat()
                mission_meta = mission.lstat()
                state.resolve(strict=True).relative_to(resolved_root)
                mission.resolve(strict=True).relative_to(resolved_root)
            except (OSError, ValueError) as error:
                raise AsterSessionError("initialized state is not contained by the session root") from error
            if (
                not stat.S_ISDIR(state_meta.st_mode)
                or stat.S_ISLNK(state_meta.st_mode)
                or not stat.S_ISREG(mission_meta.st_mode)
                or stat.S_ISLNK(mission_meta.st_mode)
            ):
                raise AsterSessionError("initialized state is not contained by the session root")
            os.chmod(state, 0o700)
            os.chmod(mission, 0o600)

    @staticmethod
    def _write_owner_file(path: Path, data: bytes) -> None:
        descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(descriptor, "wb") as output:
            output.write(data)

    def _configure_nodes(self, root: Path, init_nodes: tuple[_InitNode, _InitNode]) -> list[_Node]:
        self._reservations = []
        nodes: list[_Node] = []
        try:
            for _ in init_nodes:
                reservation = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                reservation.bind(("127.0.0.1", 0))
                self._reservations.append(reservation)
            for item, reservation in zip(init_nodes, self._reservations):
                state = root / f"node-{item.index}"
                mission = state / "mission.unprotected-reference.bundle"
                token_path = state / "playground.client.token"
                token = secrets.token_hex(32)
                if self.transcript is not None:
                    self.transcript.register_secret(token)
                self._write_owner_file(token_path, token.encode("ascii"))
                publisher = NumberedPublisher(
                    self.binaries.ctl,
                    state / "publication.redb",
                    f"aster-quickstart/node-{item.index}/v1",
                    self.rpc_timeout,
                    self.cancel_event,
                    self._before_child_spawn,
                    self._after_child_spawn,
                    self._after_child_gone,
                    transcript=self.transcript,
                    transcript_step="setup",
                )
                publisher.initialize()
                nodes.append(
                    _Node(
                        item,
                        state,
                        mission,
                        token_path,
                        token,
                        int(reservation.getsockname()[1]),
                        publisher,
                    )
                )
        except BaseException:
            self._close_reservations()
            raise
        return nodes

    def _node_command(self, index: int, *, with_contacts: bool = True) -> list[str]:
        node = self._nodes[index]
        peer = self._nodes[1 - index]
        command = [
            str(self.binaries.agent),
            "--state",
            str(node.state),
            "--mesh-bind",
            f"127.0.0.1:{node.mesh_port}",
            "--listen",
            "127.0.0.1:0",
            "--mission-bundle-unprotected-reference",
            str(node.mission),
            "--client-token-file",
            str(node.token_path),
            "--sync-ms",
            "200",
        ]
        if with_contacts:
            command.extend([
                "--peer",
                f"{peer.init.carrier_id}@127.0.0.1:{peer.mesh_port}={peer.init.mission_id}",
            ])
        return command

    def _start_nodes(
        self,
        *,
        with_contacts: bool = True,
        create_subscriptions: bool = True,
        honor_cancellation: bool = True,
        transcript_step: str = "authentication",
    ) -> None:
        for index in range(len(self._nodes)):
            self._start_node(
                index,
                with_contacts=with_contacts,
                honor_cancellation=honor_cancellation,
                transcript_step=transcript_step,
            )
        if create_subscriptions:
            self._create_subscriptions(transcript_step=transcript_step)

    def _start_node(
        self,
        index: int,
        *,
        with_contacts: bool,
        honor_cancellation: bool = True,
        transcript_step: str | None = None,
    ) -> None:
        node = self._nodes[index]
        reservation = self._reservations[index]
        if reservation is not None:
            reservation.close()
            self._reservations[index] = None
        self._agent_generation += 1
        logs, logs_fd = self._prepare_agent_log_directory(index, self._agent_generation)
        self._start_pending = f"node-{index}-generation-{self._agent_generation}"
        try:
            self._publish_process_inventory()
        except BaseException:
            self._start_pending = None
            try:
                self._publish_process_inventory()
            finally:
                os.close(logs_fd)
            raise
        try:
            command = self._node_command(index, with_contacts=with_contacts)
            node.process = _BoundedProcess(
                command,
                logs / "agent.stdout",
                logs / "agent.stderr",
                parse_readiness=True,
                output_dir_fd=logs_fd,
                transcript_handle=self._start_command(
                    transcript_step or ("publisher" if index == 0 else "receiver"),
                    command,
                ),
            )
        except OSError as error:
            self._start_pending = None
            self._publish_process_inventory()
            raise AsterSessionError(f"could not start agent process for node {index}") from error
        finally:
            os.close(logs_fd)
        self._start_pending = None
        self._publish_process_inventory()
        cancel_event = self.cancel_event if honor_cancellation else None
        assert node.process is not None
        url = node.process.wait_ready(self.startup_timeout, cancel_event)
        node.client = ConnectJsonClient(url, node.token, self.rpc_timeout)
        node.publisher.connect(url, node.token_path)
        node.peered = with_contacts
        node.log_path = str(logs.relative_to(self.root))

    @staticmethod
    def _running_node_receipt(role: NodeRole, node: _Node) -> dict[str, object]:
        if node.process is None or node.log_path is None:
            raise AsterSessionError("running node evidence is incomplete")
        return {
            "role": role,
            "state": "running",
            "pid": node.process.pid,
            "port": node.mesh_port,
            "command": "aster-agent",
            "confined_path": node.log_path,
        }

    def _create_subscriptions(self, *, transcript_step: str = "authentication") -> None:
        for index, node in enumerate(self._nodes):
            subscription = node.publisher.create_subscription(
                f"aster-quickstart/subscription/node-{index}/v1".encode("ascii"),
                transcript_step=transcript_step,
            )
            if len(subscription) != 32:
                raise AsterSessionError("agent returned an invalid subscription identity")

    def publish(self, text: str) -> dict[str, object]:
        return self._publish(text, None)

    def publish_with_progress(
        self,
        text: str,
        progress: Callable[[dict[str, object]], None],
    ) -> dict[str, object]:
        if not callable(progress):
            raise AsterSessionError("publication progress observer is invalid")
        return self._publish(text, progress)

    def _publish(
        self,
        text: str,
        progress: Callable[[dict[str, object]], None] | None,
    ) -> dict[str, object]:
        with self._lock:
            self._require_initialized()
            if not self._authenticated:
                raise AsterSessionError("the Aster session is not authenticated")
            if not isinstance(text, str) or not text:
                raise AsterSessionError("Event text must not be empty")
            payload = text.encode("utf-8")
            if len(payload) > 4_096:
                raise AsterSessionError("Event text exceeds 4096 UTF-8 bytes")
            atlas = self._nodes[0]
            beacon = self._nodes[1]
            self._publication_counter += 1
            try:
                self._require_live_nodes()
                publication = atlas.publisher.publish(
                    f"quickstart-event-{self._publication_counter}".encode("ascii"),
                    payload,
                    transcript_step="event",
                )
                commit = self._commit_fact(publication.event_id, text)
                self._report_progress(progress, {"commit": commit})
                event = self._wait_for_event(beacon, publication.event_id, payload)
                if event is None:
                    raise AsterSessionError("Beacon did not observe the exact Event before the delivery deadline")
                result = {
                    "commit": commit,
                    "receipt": self._receipt_fact(publication.event_id, text),
                }
                atlas.publisher.acknowledge(publication, transcript_step="event")
            except BaseException as error:
                cleanup_error = self._fail_closed_publication()
                if isinstance(error, (KeyboardInterrupt, SystemExit)):
                    raise
                if cleanup_error is not None:
                    raise AsterSessionError("Aster publication and cleanup failed") from error
                if isinstance(error, AsterSessionError):
                    raise
                if isinstance(error, ConnectError):
                    raise AsterSessionError(str(error)) from error
                raise AsterSessionError("Aster publication failed") from error
            return result

    def _wait_for_event(self, node: _Node, event_id: bytes, payload: bytes) -> dict[str, object] | None:
        if node.client is None:
            raise AsterSessionError("Beacon application endpoint is unavailable")
        deadline = time.monotonic() + self.startup_timeout
        marker = 0
        while True:
            self._raise_if_cancelled()
            self._require_live_nodes()
            try:
                observed, marker = node.client.query_exact_event(
                    event_id,
                    payload,
                    marker,
                    deadline=deadline,
                )
            except ConnectError:
                if time.monotonic() >= deadline:
                    return None
                raise
            if observed is not None:
                return observed
            self._raise_if_cancelled()
            if time.monotonic() >= deadline:
                return None
            self._raise_if_cancelled()
            time.sleep(min(0.05, max(0.0, deadline - time.monotonic())))

    def _raise_if_cancelled(self) -> None:
        if self.cancel_event is not None and self.cancel_event.is_set():
            raise AsterSessionError("Aster session operation was cancelled")

    def _fail_closed_publication(self) -> Exception | None:
        return self._finalize_terminal_cleanup()

    def _require_live_nodes(self) -> None:
        for index, node in enumerate(self._nodes):
            if node.process is None or node.process.process.poll() is not None:
                raise AsterSessionError(f"agent process for node {index} is not running")

    def offline_publish(
        self,
        text: str,
        progress: Callable[[dict[str, object]], None] | None = None,
    ) -> dict[str, object]:
        with self._lock:
            self._require_initialized()
            if not self._authenticated:
                raise AsterSessionError("the Aster session is not authenticated")
            if not isinstance(text, str) or not text:
                raise AsterSessionError("Event text must not be empty")
            payload = text.encode("utf-8")
            if len(payload) > 4_096:
                raise AsterSessionError("Event text exceeds 4096 UTF-8 bytes")
            if progress is not None and not callable(progress):
                raise AsterSessionError("experiment progress observer is invalid")

            atlas = self._nodes[0]
            beacon = self._nodes[1]
            self._publication_counter += 1
            contacts_restored = False
            try:
                self._restart_nodes(with_contacts=False, transcript_step="experiment")
                self._report_progress(progress, {"availability": "unavailable"})
                publication = atlas.publisher.publish(
                    f"quickstart-event-{self._publication_counter}".encode("ascii"),
                    payload,
                    transcript_step="experiment",
                )
                commit = self._commit_fact(publication.event_id, text)
                self._report_progress(
                    progress,
                    {"commit": commit},
                )

                self._restart_nodes(with_contacts=True, transcript_step="experiment")
                contacts_restored = True
                self._report_progress(
                    progress,
                    {"availability": "available"},
                )
                event = self._wait_for_event(beacon, publication.event_id, payload)
                if event is None:
                    raise AsterSessionError(
                        "Beacon did not observe the exact Event before the delivery deadline"
                    )
                receipt = self._receipt_fact(publication.event_id, text)
                result = {"commit": commit, "receipt": receipt}
                self._raise_if_cancelled()
                self._report_progress(
                    progress,
                    {"receipt": receipt},
                )
                atlas.publisher.acknowledge(publication, transcript_step="experiment")
                return result
            except BaseException as error:
                cancelled = self.cancel_event is not None and self.cancel_event.is_set()
                restore_error = None
                if not contacts_restored:
                    try:
                        self._restart_nodes(
                            with_contacts=True,
                            honor_cancellation=False,
                            transcript_step="experiment",
                        )
                        contacts_restored = True
                    except Exception as caught:
                        restore_error = caught
                if restore_error is not None:
                    cleanup_error = self._finalize_terminal_cleanup()
                    if cleanup_error is not None:
                        raise AsterSessionError("offline experiment cleanup failed") from cleanup_error
                    raise AsterSessionError(
                        "offline experiment failed and contacts could not be restored"
                    ) from restore_error
                if cancelled:
                    cleanup_error = self._finalize_terminal_cleanup()
                    if cleanup_error is not None:
                        raise AsterSessionError(
                            "offline experiment cancellation cleanup failed"
                        ) from cleanup_error
                    raise AsterSessionError("Aster session operation was cancelled") from error
                if isinstance(error, (KeyboardInterrupt, SystemExit)):
                    raise
                if (
                    contacts_restored
                    and self._has_live_authenticated_topology()
                    and isinstance(error, (AsterSessionError, ConnectError))
                ):
                    raise RecoverableOfflinePublishError(str(error)) from error
                if isinstance(error, AsterSessionError):
                    raise
                if isinstance(error, ConnectError):
                    raise AsterSessionError(str(error)) from error
                raise AsterSessionError("offline experiment failed") from error

    @staticmethod
    def _report_progress(
        progress: Callable[[dict[str, object]], None] | None,
        update: dict[str, object],
    ) -> None:
        if progress is not None:
            progress(update)

    @staticmethod
    def _commit_fact(event_id: bytes, text: str) -> dict[str, object]:
        return {
            "event_id": event_id.hex(),
            "text": text,
            "status": "committed",
            "durable": True,
            "node": "atlas",
        }

    @staticmethod
    def _receipt_fact(event_id: bytes, text: str) -> dict[str, object]:
        return {
            "event_id": event_id.hex(),
            "text": text,
            "status": "received",
            "observed": True,
            "node": "beacon",
        }

    def _restart_nodes(
        self,
        *,
        with_contacts: bool,
        honor_cancellation: bool = True,
        transcript_step: str = "authentication",
    ) -> None:
        cleanup_error = self._stop_all_nodes(reserve=True)
        if cleanup_error is not None:
            raise AsterSessionError("could not stop agents for the offline experiment") from cleanup_error
        try:
            self._start_nodes(
                with_contacts=with_contacts,
                create_subscriptions=False,
                honor_cancellation=honor_cancellation,
                transcript_step=transcript_step,
            )
        except BaseException:
            self._stop_all_nodes(reserve=True)
            raise

    def _prepare_agent_log_directory(self, index: int, generation: int) -> tuple[Path, int]:
        logs = self.root / "logs"
        self._require_owned_directory(self.root)
        self._require_owned_directory(logs)
        flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
        logs_fd = os.open(logs, flags)
        try:
            node_name = f"node-{index}"
            try:
                os.mkdir(node_name, 0o700, dir_fd=logs_fd)
            except FileExistsError:
                pass
            node_fd = os.open(node_name, flags, dir_fd=logs_fd)
            try:
                self._prune_agent_logs(node_fd)
                run_name = f"run-{generation}"
                os.mkdir(run_name, 0o700, dir_fd=node_fd)
                run_fd = os.open(run_name, flags, dir_fd=node_fd)
            finally:
                os.close(node_fd)
        except OSError as error:
            raise AsterSessionError("agent log directory is unsafe") from error
        finally:
            os.close(logs_fd)
        run = logs / node_name / run_name
        try:
            self._require_owned_directory(logs / node_name)
            self._require_owned_directory(run)
        except BaseException:
            os.close(run_fd)
            raise
        return run, run_fd

    def _require_owned_directory(self, path: Path) -> None:
        try:
            metadata = path.lstat()
            path.resolve(strict=True).relative_to(self.root.resolve(strict=True))
        except (OSError, ValueError) as error:
            raise AsterSessionError("agent log directory is outside the session") from error
        if not stat.S_ISDIR(metadata.st_mode) or stat.S_ISLNK(metadata.st_mode):
            raise AsterSessionError("agent log directory is unsafe")
        if metadata.st_uid != os.geteuid() or stat.S_IMODE(metadata.st_mode) & 0o077:
            raise AsterSessionError("agent log directory is not owner-only")

    @staticmethod
    def _prune_agent_logs(node_fd: int) -> None:
        generations = []
        for name in os.listdir(node_fd):
            match = re.fullmatch(r"run-(\d+)", name)
            if match is None:
                raise AsterSessionError("agent log directory contains an unexpected entry")
            generations.append((int(match.group(1)), name))
        generations.sort()
        for _, name in generations[: max(0, len(generations) - MAX_RETAINED_AGENT_RUNS + 1)]:
            flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
            try:
                run_fd = os.open(name, flags, dir_fd=node_fd)
                try:
                    for entry in os.listdir(run_fd):
                        metadata = os.stat(entry, dir_fd=run_fd, follow_symlinks=False)
                        if not stat.S_ISREG(metadata.st_mode):
                            raise AsterSessionError("agent log generation contains an unsafe entry")
                        os.unlink(entry, dir_fd=run_fd)
                finally:
                    os.close(run_fd)
                os.rmdir(name, dir_fd=node_fd)
            except OSError as error:
                raise AsterSessionError("could not prune bounded agent logs") from error

    def close(self) -> None:
        with self._lock:
            if self._closed:
                return
            cleanup_error = self._finalize_terminal_cleanup()
            if cleanup_error is not None:
                raise AsterSessionError("Aster session cleanup failed") from cleanup_error

    def _finalize_terminal_cleanup(self) -> Exception | None:
        started = time.monotonic()
        self._authenticated = False
        cleanup_error = self._cleanup_processes()
        self._close_reservations()
        if cleanup_error is None:
            cleanup_error = self._delete_root()
        if cleanup_error is None:
            self._initialized = False
            self._closed = True
        if self.transcript is not None:
            self.transcript.record_internal(
                "cleanup",
                "Clean up Aster session",
                outcome="succeeded" if cleanup_error is None else "failed",
                detail="owned Aster processes and workspace finalized",
                duration_ms=max(0, int((time.monotonic() - started) * 1000)),
            )
        return cleanup_error

    def _delete_root(self) -> Exception | None:
        try:
            metadata = self.root.lstat()
        except FileNotFoundError:
            return None
        except OSError as error:
            return error
        if not stat.S_ISDIR(metadata.st_mode) or stat.S_ISLNK(metadata.st_mode):
            return AsterSessionError("owned session root is unsafe")
        try:
            shutil.rmtree(self.root)
        except OSError as error:
            return error
        return None

    def _cleanup_processes(self) -> Exception | None:
        if self._start_pending is not None or self._transient_processes:
            return AsterSessionError("owned child process state remains uncertain")
        return self._stop_all_nodes(reserve=False)

    def _stop_all_nodes(self, *, reserve: bool) -> Exception | None:
        first_error: Exception | None = None
        for index in reversed(range(len(self._nodes))):
            try:
                error = self._stop_node_index(index, reserve=reserve)
            except Exception as error:
                if first_error is None:
                    first_error = error
            else:
                if error is not None and first_error is None:
                    first_error = error
        return first_error

    def _stop_node_index(self, index: int, *, reserve: bool) -> Exception | None:
        node = self._nodes[index]
        node.client = None
        node.peered = False
        process = node.process
        replacement: socket.socket | None = None
        if reserve and process is not None:
            try:
                replacement = self._new_port_reservation()
            except Exception as error:
                return error
            self._reservations[index] = replacement
        if process is not None:
            try:
                process.stop()
            except Exception as error:
                if replacement is not None:
                    replacement.close()
                    self._reservations[index] = None
                return error
            if replacement is not None:
                node.mesh_port = int(replacement.getsockname()[1])
            node.process = None
            try:
                self._publish_process_inventory()
            except Exception as error:
                return error
        if reserve:
            try:
                self._reserve_node_port(index)
            except Exception as error:
                return error
        return None

    def _reserve_node_port(self, index: int) -> None:
        if self._reservations[index] is not None:
            return
        try:
            reservation = self._new_port_reservation()
        except OSError as error:
            raise AsterSessionError(f"could not reserve mesh port for node {index}") from error
        self._nodes[index].mesh_port = int(reservation.getsockname()[1])
        self._reservations[index] = reservation

    @staticmethod
    def _new_port_reservation() -> socket.socket:
        reservation = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            reservation.bind(("127.0.0.1", 0))
        except BaseException:
            reservation.close()
            raise
        return reservation

    def _close_reservations(self) -> None:
        for index, reservation in enumerate(self._reservations):
            if reservation is not None:
                try:
                    reservation.close()
                except OSError:
                    pass
                self._reservations[index] = None
