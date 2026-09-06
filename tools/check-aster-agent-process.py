#!/usr/bin/env python3
"""Bounded black-box crash/recovery acceptance for a customer Aster agent.

The checker treats its agent and independently supplied protocol client as
packaged executables; it never assumes they share an implementation language.
It never provisions production credentials; the repository smoke task supplies
an explicitly unprotected, test-only fixture binary and configuration.
"""

from __future__ import annotations

import argparse
import copy
import contextlib
import dataclasses
import errno
import ipaddress
import json
import os
import select
import signal
import socket
import stat
import subprocess
import sys
import tempfile
import threading
import time
import urllib.parse
from pathlib import Path
from typing import Any, Iterable, Sequence


MIN_TIMEOUT_SECONDS = 1
MAX_TIMEOUT_SECONDS = 120
MAX_CONFIG_BYTES = 1024 * 1024
MAX_CAPTURE_BYTES = 2 * 1024 * 1024
MAX_AGGREGATE_CAPTURE_BYTES = 16 * 1024 * 1024
MAX_AGGREGATE_CAPTURE_CHUNKS = 4_096
MAX_TOKEN_FILE_BYTES = 258
MAX_HEALTH_RESPONSE_BYTES = 8 * 1024
FIXED_PUBLISH_OPERATION = b"aster-agent-process-publish-v1"
FIXED_SUBSCRIBE_OPERATION = b"aster-agent-process-subscribe-v1"
CANARY_TOPIC = "chat.events"
CANARY_SCOPE = "mission/team/alpha"
CANARY_PAYLOAD = b"SECRET_PAYLOAD_CANARY"
CANARY_LOGICAL_KEY = b"SECRET_LOGICAL_KEY_CANARY"
ROTATED_TOKEN = b"SECRET_ROTATED_TOKEN_CANARY_0123456789ABCDEF"
PUBLIC_CLIENT_ERROR_CODES = frozenset(
    {
        "cancelled",
        "unknown",
        "invalidargument",
        "deadlineexceeded",
        "notfound",
        "alreadyexists",
        "permissiondenied",
        "resourceexhausted",
        "failedprecondition",
        "aborted",
        "outofrange",
        "unimplemented",
        "internal",
        "unavailable",
        "dataloss",
        "unauthenticated",
    }
)
PUBLIC_LIFECYCLE_CATEGORIES = (
    ("startup", "started"),
    ("readiness", "ready"),
    ("token_reload", "reloaded"),
    ("token_reload", "rejected"),
    ("drain_start", "terminating"),
    ("shutdown_result", "clean"),
    ("shutdown_result", "forced"),
    ("fatal_transition", "startup"),
    ("fatal_transition", "runtime"),
    ("fatal_transition", "shutdown"),
)


class AcceptanceError(Exception):
    """One fixed public harness failure without caller-controlled values."""


class CheckerInterrupted(Exception):
    """One external checker signal that must bypass operational retries."""


class QuietArgumentParser(argparse.ArgumentParser):
    def error(self, _message: str) -> None:
        raise ValueError("invalid process checker arguments")


@dataclasses.dataclass(frozen=True)
class Arguments:
    agent: Path
    config: Path
    client: Path
    timeout_seconds: int


@dataclasses.dataclass(frozen=True)
class ConfigContract:
    application: str
    health: str
    state: Path
    token_file: Path
    mission_reference_file: Path
    peers: tuple[str, ...]


@dataclasses.dataclass(frozen=True)
class NegativeStartupResult:
    captures: tuple[str, ...]
    canaries: tuple[str, ...]
    receipts: tuple[str, ...]


@dataclasses.dataclass(frozen=True)
class GuardedAddresses:
    application: str
    health: str
    mesh: str


@dataclasses.dataclass(frozen=True)
class DirectorySnapshot:
    device: int
    inode: int
    mode: int
    links: int
    size: int
    modified_ns: int
    changed_ns: int
    entries: tuple[str, ...]


def parse_arguments(argv: Sequence[str]) -> Arguments:
    parser = QuietArgumentParser(add_help=True)
    parser.add_argument("--agent")
    parser.add_argument("--config")
    parser.add_argument("--client")
    parser.add_argument("--timeout-seconds", required=True)
    namespace = parser.parse_args(argv)
    try:
        timeout_seconds = int(namespace.timeout_seconds, 10)
    except (TypeError, ValueError) as error:
        raise ValueError("timeout must be within 1..=120") from error
    if not MIN_TIMEOUT_SECONDS <= timeout_seconds <= MAX_TIMEOUT_SECONDS:
        raise ValueError("timeout must be within 1..=120")
    if namespace.agent is None or namespace.config is None or namespace.client is None:
        raise ValueError("agent, config, and client paths are required")
    return Arguments(
        agent=Path(namespace.agent),
        config=Path(namespace.config),
        client=Path(namespace.client),
        timeout_seconds=timeout_seconds,
    )


def require_executable(path: Path, label: str) -> None:
    try:
        mode = path.stat().st_mode
    except OSError as error:
        raise ValueError(f"{label} executable is unavailable") from error
    if not stat.S_ISREG(mode) or not os.access(path, os.X_OK):
        raise ValueError(f"{label} executable is unavailable")


def require_regular_file(path: Path, label: str) -> None:
    try:
        mode = path.stat().st_mode
    except OSError as error:
        raise ValueError(f"{label} file is unavailable") from error
    if not stat.S_ISREG(mode):
        raise ValueError(f"{label} file is unavailable")


def require_sanitized(output: str, canaries: Iterable[str]) -> None:
    for canary in canaries:
        if canary and canary in output:
            raise ValueError("canary exposed in combined process output")


class CaptureLedger:
    """One bounded, incrementally scanned process-output ledger."""

    def __init__(
        self,
        canaries: Iterable[str],
        *,
        max_bytes: int = MAX_AGGREGATE_CAPTURE_BYTES,
    ) -> None:
        self._chunks: list[str] = []
        self._canaries = list(canaries)
        self._max_bytes = max_bytes
        self._captured_bytes = 0

    def append(self, output: str) -> None:
        self.extend((output,))

    def extend(self, outputs: Iterable[str]) -> None:
        additions = list(outputs)
        output_bytes = sum(len(output.encode("utf-8")) for output in additions)
        if (
            len(self._chunks) + len(additions) > MAX_AGGREGATE_CAPTURE_CHUNKS
            or output_bytes > self._max_bytes - self._captured_bytes
        ):
            raise AcceptanceError("aggregate process output exceeded the bound")
        self._chunks.extend(additions)
        self._captured_bytes += output_bytes
        require_sanitized("\n".join(additions), self._canaries)

    def add_canaries(self, canaries: Iterable[str]) -> None:
        added = list(canaries)
        require_sanitized(self.text(), added)
        self._canaries.extend(added)

    def text(self) -> str:
        return "\n".join(self._chunks)


def sanitized_diagnostic(
    source: str, exit_code: int, stdout: str, stderr: str
) -> str:
    safe_source = source if source in {"agent", "client"} else "process"
    return (
        f"DIAGNOSTIC source={safe_source} exit_code={exit_code} "
        f"stdout_bytes={len(stdout.encode('utf-8'))} "
        f"stderr_bytes={len(stderr.encode('utf-8'))} "
        f"stdout_lines={len(stdout.splitlines())} "
        f"stderr_lines={len(stderr.splitlines())}"
    )


def sanitized_client_diagnostic(
    phase: str, exit_code: int, stdout: str, stderr: str
) -> str:
    safe_phase = phase if phase in {"unary", "stream"} else "activity"
    public_code = public_client_error_code(stderr) or "unrecognized"

    return (
        f"DIAGNOSTIC source=client phase={safe_phase} exit_code={exit_code} "
        f"public_code={public_code} stdout_bytes={len(stdout.encode('utf-8'))} "
        f"stderr_bytes={len(stderr.encode('utf-8'))} "
        f"stdout_lines={len(stdout.splitlines())} "
        f"stderr_lines={len(stderr.splitlines())}"
    )


def public_client_error_code(stderr: str) -> str | None:
    try:
        code = _json_record(stderr).get("code")
        if isinstance(code, str) and code in PUBLIC_CLIENT_ERROR_CODES:
            return code
    except AcceptanceError:
        pass
    return None


def expected_drain_client_outcome(
    phase: str, exit_code: int, stdout: str, stderr: str
) -> bool:
    stdout_records = _exact_json_lines(stdout)
    stderr_records = _exact_json_lines(stderr)
    if phase == "unary":
        return (
            exit_code == 1
            and stdout_records == [{"status": "active", "activity": "unary"}]
            and stderr_records == [{"status": "error", "code": "unavailable"}]
        )
    if phase == "stream":
        return (
            exit_code == 0
            and stdout_records
            == [
                {"status": "active", "activity": "stream"},
                {"status": "ok", "delivered": 0},
            ]
            and stderr_records == []
        )
    return False


def expected_client_failure(result: ClientResult, code: str) -> bool:
    if result.return_code != 1:
        return False
    try:
        return _json_record(result.stderr) == {"status": "error", "code": code}
    except AcceptanceError:
        return False


def _exact_json_lines(output: str) -> list[dict[str, Any]] | None:
    records: list[dict[str, Any]] = []
    for line in output.splitlines():
        try:
            record = json.loads(line)
        except json.JSONDecodeError:
            return None
        if not isinstance(record, dict):
            return None
        records.append(record)
    return records


def sanitized_agent_diagnostic(
    phase: str, exit_code: int, stdout: str, stderr: str
) -> str:
    safe_phase = phase if phase in {"unary", "stream"} else "drain"
    counts = {category: 0 for category in PUBLIC_LIFECYCLE_CATEGORIES}
    for line in stdout.splitlines():
        try:
            record = json.loads(line)
        except json.JSONDecodeError:
            continue
        if not isinstance(record, dict):
            continue
        category = (record.get("operation"), record.get("reason"))
        if category in counts:
            counts[category] += 1
    lifecycle_counts = ",".join(
        f"{operation}.{reason}:{count}"
        for (operation, reason), count in counts.items()
        if count
    )
    if not lifecycle_counts:
        lifecycle_counts = "none"
    return (
        f"DIAGNOSTIC source=agent phase={safe_phase} exit_code={exit_code} "
        f"lifecycle_counts={lifecycle_counts} "
        f"stdout_bytes={len(stdout.encode('utf-8'))} "
        f"stderr_bytes={len(stderr.encode('utf-8'))} "
        f"stdout_lines={len(stdout.splitlines())} "
        f"stderr_lines={len(stderr.splitlines())}"
    )


def load_config_contract(path: Path) -> ConfigContract:
    require_regular_file(path, "config")
    try:
        if path.stat().st_size > MAX_CONFIG_BYTES:
            raise ValueError("config file is invalid")
        document = json.loads(path.read_bytes())
        application = document["application"]["listen"]
        health = document["health"]["listen"]
        state = Path(document["state"]["directory"])
        token_file = Path(document["credentials"]["client_token_file"])
        mission_reference_file = Path(
            document["credentials"]["mission_secret_ref_file"]
        )
        peer_values = document["mesh"]["peers"]
    except (OSError, UnicodeError, json.JSONDecodeError, KeyError, TypeError) as error:
        raise ValueError("config file is invalid") from error
    if (
        not isinstance(application, str)
        or not isinstance(health, str)
        or not isinstance(peer_values, list)
        or not all(isinstance(peer, str) for peer in peer_values)
    ):
        raise ValueError("config file is invalid")
    peers = tuple(peer_values)
    require_regular_file(token_file, "client token")
    require_regular_file(mission_reference_file, "mission reference")
    return ConfigContract(
        application=application,
        health=health,
        state=state,
        token_file=token_file,
        mission_reference_file=mission_reference_file,
        peers=peers,
    )


def _load_config_document(path: Path) -> dict[str, Any]:
    require_regular_file(path, "config")
    try:
        if path.stat().st_size > MAX_CONFIG_BYTES:
            raise ValueError("config file is invalid")
        document = json.loads(path.read_bytes())
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise ValueError("config file is invalid") from error
    if not isinstance(document, dict):
        raise ValueError("config file is invalid")
    return document


def _address_parts(address: str) -> tuple[str, int]:
    try:
        parsed = urllib.parse.urlsplit(f"http://{address}")
        host = parsed.hostname
        port = parsed.port
    except ValueError as error:
        raise AcceptanceError("configured listener is invalid") from error
    if host is None or port is None or parsed.path:
        raise AcceptanceError("configured listener is invalid")
    try:
        ipaddress.ip_address(host)
    except ValueError as error:
        raise AcceptanceError("configured listener is invalid") from error
    return host, port


@contextlib.contextmanager
def guarded_loopback_addresses() -> Iterable[GuardedAddresses]:
    guards: list[socket.socket] = []
    try:
        for socket_type in (socket.SOCK_STREAM, socket.SOCK_STREAM, socket.SOCK_DGRAM):
            guard = socket.socket(socket.AF_INET, socket_type)
            guards.append(guard)
            guard.bind(("127.0.0.1", 0))
        yield GuardedAddresses(
            application=f"127.0.0.1:{guards[0].getsockname()[1]}",
            health=f"127.0.0.1:{guards[1].getsockname()[1]}",
            mesh=f"127.0.0.1:{guards[2].getsockname()[1]}",
        )
    except OSError as error:
        raise AcceptanceError("negative listener guards could not be created") from error
    finally:
        for guard in guards:
            guard.close()


class BoundedCapture:
    def __init__(self) -> None:
        self._bytes = bytearray()
        self._overflow = False
        self._failed = False
        self._condition = threading.Condition()

    def add(self, chunk: bytes) -> None:
        with self._condition:
            available = MAX_CAPTURE_BYTES - len(self._bytes)
            self._bytes.extend(chunk[: max(available, 0)])
            if len(chunk) > available:
                self._overflow = True
            self._condition.notify_all()

    def fail(self) -> None:
        with self._condition:
            self._failed = True
            self._condition.notify_all()

    def _raise_if_unavailable(self) -> None:
        if self._failed:
            raise AcceptanceError("process output capture failed")
        if self._overflow:
            raise AcceptanceError("process output exceeded the capture bound")

    def text(self) -> str:
        with self._condition:
            self._raise_if_unavailable()
            return self._bytes.decode("utf-8", errors="replace")

    def snapshot(self) -> tuple[str, bool]:
        with self._condition:
            return (
                self._bytes.decode("utf-8", errors="replace"),
                not self._failed and not self._overflow,
            )

    def wait_for(self, marker: str, timeout_seconds: int) -> None:
        deadline = time.monotonic() + timeout_seconds
        encoded = marker.encode("utf-8")
        with self._condition:
            while encoded not in self._bytes:
                self._raise_if_unavailable()
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise AcceptanceError("process activity did not start within the bound")
                self._condition.wait(timeout=remaining)

    def contains(self, marker: str) -> bool:
        encoded = marker.encode("utf-8")
        with self._condition:
            self._raise_if_unavailable()
            return encoded in self._bytes


class SignalSafePopen(subprocess.Popen[bytes]):
    """Popen whose posix_spawn atomically restores the child's signal mask."""

    def __init__(self, arguments: Sequence[str], child_signal_mask: Iterable[int], **kwargs: Any):
        self._child_signal_mask = tuple(child_signal_mask)
        self._used_signal_safe_spawn = False
        super().__init__(list(arguments), **kwargs)
        if not self._used_signal_safe_spawn:
            try:
                self.kill()
            finally:
                self.wait()
            raise OSError("signal-safe process creation is unavailable")

    def _posix_spawn(
        self,
        args: list[str],
        executable: str,
        env: dict[str, str],
        restore_signals: bool,
        close_fds: bool,
        p2cread: int,
        p2cwrite: int,
        c2pread: int,
        c2pwrite: int,
        errread: int,
        errwrite: int,
    ) -> None:
        spawn_options: dict[str, Any] = {
            "setsid": True,
            "setsigmask": self._child_signal_mask,
        }
        if restore_signals:
            spawn_options["setsigdef"] = [
                process_signal
                for name in ("SIGPIPE", "SIGXFZ", "SIGXFSZ")
                if (process_signal := getattr(signal, name, None)) is not None
            ]
        file_actions: list[tuple[int, ...]] = []
        for descriptor in (p2cwrite, c2pread, errread):
            if descriptor != -1:
                file_actions.append((os.POSIX_SPAWN_CLOSE, descriptor))
        for descriptor, target in (
            (p2cread, 0),
            (c2pwrite, 1),
            (errwrite, 2),
        ):
            if descriptor != -1:
                file_actions.append((os.POSIX_SPAWN_DUP2, descriptor, target))
        if close_fds:
            file_actions.append((os.POSIX_SPAWN_CLOSEFROM, 3))
        if file_actions:
            spawn_options["file_actions"] = file_actions
        self.pid = os.posix_spawn(executable, args, env, **spawn_options)
        self._child_created = True
        self._used_signal_safe_spawn = True
        self._close_pipe_fds(
            p2cread,
            p2cwrite,
            c2pread,
            c2pwrite,
            errread,
            errwrite,
        )


class ManagedProcess:
    def __init__(
        self,
        arguments: Sequence[str],
        input_bytes: bytes | None = None,
        child_signal_mask: Iterable[int] = (),
    ) -> None:
        self.stdout = BoundedCapture()
        self.stderr = BoundedCapture()
        if not arguments:
            raise AcceptanceError("process could not be started")
        normalized_arguments = [os.path.abspath(arguments[0]), *arguments[1:]]
        try:
            self.process = SignalSafePopen(
                normalized_arguments,
                child_signal_mask,
                stdin=subprocess.PIPE if input_bytes is not None else subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )
        except OSError as error:
            raise AcceptanceError("process could not be started") from error
        assert self.process.stdout is not None
        assert self.process.stderr is not None
        self._threads = [
            threading.Thread(
                target=self._drain,
                args=(self.process.stdout, self.stdout),
                daemon=True,
            ),
            threading.Thread(
                target=self._drain,
                args=(self.process.stderr, self.stderr),
                daemon=True,
            ),
        ]
        for thread in self._threads:
            thread.start()
        if input_bytes is not None:
            assert self.process.stdin is not None
            try:
                self.process.stdin.write(input_bytes)
                self.process.stdin.close()
            except BrokenPipeError:
                pass

    @staticmethod
    def _drain(stream: Any, capture: BoundedCapture) -> None:
        try:
            descriptor = stream.fileno()
            while True:
                try:
                    chunk = os.read(descriptor, 16 * 1024)
                except InterruptedError:
                    continue
                if not chunk:
                    return
                capture.add(chunk)
        except (OSError, ValueError):
            capture.fail()

    def signal(self, process_signal: signal.Signals) -> None:
        if self.process.poll() is None:
            try:
                os.killpg(self.process.pid, process_signal)
            except ProcessLookupError:
                pass

    def wait(self, timeout_seconds: float) -> int:
        deadline = time.monotonic() + timeout_seconds
        try:
            return_code = self.process.wait(timeout=timeout_seconds)
        except subprocess.TimeoutExpired as error:
            raise AcceptanceError("process did not exit within the bound") from error
        for thread in self._threads:
            thread.join(timeout=max(0.0, deadline - time.monotonic()))
        if any(thread.is_alive() for thread in self._threads):
            raise AcceptanceError("process output drain exceeded the bound")
        return return_code

    def wait_for_stdout_activity(
        self, marker: str, timeout_seconds: int, phase: str
    ) -> None:
        safe_phase = phase if phase in {"unary", "stream"} else "activity"
        deadline = time.monotonic() + timeout_seconds
        while True:
            if self.stdout.contains(marker):
                return
            return_code = self.process.poll()
            if return_code is not None:
                self.wait(max(0.01, deadline - time.monotonic()))
                if self.stdout.contains(marker):
                    return
                print(
                    sanitized_client_diagnostic(
                        safe_phase,
                        return_code,
                        self.stdout.text(),
                        self.stderr.text(),
                    ),
                    file=sys.stderr,
                )
                raise AcceptanceError(
                    f"client phase {safe_phase} exited before activity"
                )
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                print(
                    sanitized_client_diagnostic(
                        safe_phase, -1, self.stdout.text(), self.stderr.text()
                    ),
                    file=sys.stderr,
                )
                raise AcceptanceError(
                    f"client phase {safe_phase} activity did not start within the bound"
                )
            time.sleep(min(0.01, remaining))

    def cleanup(self, timeout_seconds: float) -> None:
        deadline = time.monotonic() + timeout_seconds
        try:
            os.killpg(self.process.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        try:
            if self.process.poll() is None:
                try:
                    self.process.wait(timeout=max(0.01, deadline - time.monotonic()))
                except subprocess.TimeoutExpired as error:
                    raise AcceptanceError("process cleanup exceeded the bound") from error
            for thread in self._threads:
                thread.join(timeout=max(0.0, deadline - time.monotonic()))
            if any(thread.is_alive() for thread in self._threads):
                raise AcceptanceError("process output cleanup exceeded the bound")
        finally:
            if self.process.stdout is not None:
                self.process.stdout.close()
            if self.process.stderr is not None:
                self.process.stderr.close()

    def combined(self) -> str:
        return self.stdout.text() + "\n" + self.stderr.text()


class ProcessRegistry:
    """Own every isolated child before checker signals can be delivered."""

    def __init__(self) -> None:
        self._processes: list[ManagedProcess] = []

    def spawn(
        self, arguments: Sequence[str], input_bytes: bytes | None = None
    ) -> ManagedProcess:
        blocked = {signal.SIGTERM, signal.SIGHUP, signal.SIGINT}
        previous = signal.pthread_sigmask(signal.SIG_BLOCK, blocked)
        try:
            process = ManagedProcess(arguments, input_bytes, previous)
            self._processes.append(process)
        finally:
            signal.pthread_sigmask(signal.SIG_SETMASK, previous)
        return process

    def discard(self, process: ManagedProcess) -> None:
        if process in self._processes:
            self._processes.remove(process)

    def cleanup_all(self, timeout_seconds: int) -> None:
        first_error: AcceptanceError | None = None
        for process in reversed(tuple(self._processes)):
            try:
                process.cleanup(timeout_seconds)
            except AcceptanceError as error:
                if first_error is None:
                    first_error = error
            else:
                self.discard(process)
        if first_error is not None:
            raise first_error


def wait_for_process_pair(
    first: ManagedProcess, second: ManagedProcess, timeout_seconds: int
) -> tuple[int, int]:
    deadline = time.monotonic() + timeout_seconds
    processes = (first, second)
    codes: list[int | None] = [None, None]
    while codes[0] is None or codes[1] is None:
        for index, process in enumerate(processes):
            if codes[index] is None and process.process.poll() is not None:
                codes[index] = process.wait(
                    max(0.01, deadline - time.monotonic())
                )
        if codes[0] is not None and codes[1] is not None:
            return codes[0], codes[1]
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise AcceptanceError("process pair did not exit within the bound")
        time.sleep(min(0.01, remaining))
    raise AssertionError("unreachable process-pair state")


def cleanup_and_capture_processes(
    captures: CaptureLedger,
    registry: ProcessRegistry,
    processes: Sequence[ManagedProcess],
    timeout_seconds: float,
) -> None:
    deadline = time.monotonic() + timeout_seconds
    first_error: AcceptanceError | None = None
    cleaned: list[ManagedProcess] = []
    for process in processes:
        try:
            process.cleanup(max(0.01, deadline - time.monotonic()))
        except AcceptanceError as error:
            if first_error is None:
                first_error = error
        else:
            cleaned.append(process)
    outputs: list[str] = []
    for process in processes:
        stdout, _ = process.stdout.snapshot()
        stderr, _ = process.stderr.snapshot()
        outputs.extend((stdout, stderr))
    try:
        captures.extend(outputs)
    finally:
        for process in cleaned:
            registry.discard(process)
    if first_error is not None:
        raise first_error


def wait_for_process_pair_captured(
    captures: CaptureLedger,
    registry: ProcessRegistry,
    first: ManagedProcess,
    second: ManagedProcess,
    timeout_seconds: int,
) -> tuple[int, int]:
    result: tuple[int, int] | None = None
    wait_error: Exception | None = None
    try:
        result = wait_for_process_pair(first, second, timeout_seconds)
    except Exception as error:
        wait_error = error
    cleanup_and_capture_processes(
        captures, registry, (first, second), timeout_seconds
    )
    if wait_error is not None:
        raise wait_error
    if result is None:
        raise AssertionError("process-pair result was unavailable")
    return result


@dataclasses.dataclass(frozen=True)
class ClientResult:
    return_code: int
    stdout: str
    stderr: str
    record: dict[str, Any]
    stdout_capture_complete: bool = True
    stderr_capture_complete: bool = True

    @property
    def capture_complete(self) -> bool:
        return self.stdout_capture_complete and self.stderr_capture_complete


class ClientInvocationError(AcceptanceError):
    """A fixed client failure that retains bounded streams for final scanning."""

    def __init__(self, message: str, result: ClientResult) -> None:
        super().__init__(message)
        self.result = result


def _client_arguments(
    client: Path,
    command: str,
    application: str,
    token_file: Path,
    timeout_seconds: int,
) -> list[str]:
    return [
        str(client),
        command,
        "--url",
        f"http://{application}",
        "--token-file",
        str(token_file),
        "--timeout-seconds",
        str(timeout_seconds),
    ]


def _json_record(output: str) -> dict[str, Any]:
    for line in reversed(output.splitlines()):
        try:
            record = json.loads(line)
        except json.JSONDecodeError:
            continue
        if isinstance(record, dict):
            return record
    raise AcceptanceError("client returned no bounded JSON result")


def invoke_client(
    registry: ProcessRegistry,
    client: Path,
    command: str,
    application: str,
    token_file: Path,
    timeout_seconds: int,
    request: dict[str, Any] | None = None,
    *,
    expect_failure: bool | str = False,
    attempt_timeout_seconds: float | None = None,
) -> ClientResult:
    encoded = json.dumps(request or {}, separators=(",", ":")).encode("utf-8")
    attempt_budget = (
        float(timeout_seconds)
        if attempt_timeout_seconds is None
        else attempt_timeout_seconds
    )
    attempt_deadline = time.monotonic() + attempt_budget
    process = registry.spawn(
        _client_arguments(client, command, application, token_file, timeout_seconds),
        encoded,
    )
    attempt_error: AcceptanceError | None = None
    cleanup_error: AcceptanceError | None = None
    return_code = -1
    try:
        try:
            return_code = process.wait(max(0.01, attempt_deadline - time.monotonic()))
        except AcceptanceError as error:
            attempt_error = error
    finally:
        try:
            process.cleanup(max(0.01, attempt_deadline - time.monotonic()))
        except AcceptanceError as error:
            cleanup_error = error
        else:
            registry.discard(process)
    stdout, stdout_complete = process.stdout.snapshot()
    stderr, stderr_complete = process.stderr.snapshot()
    capture_cleanup_complete = cleanup_error is None
    failed_result = ClientResult(
        return_code,
        stdout,
        stderr,
        {},
        stdout_capture_complete=stdout_complete and capture_cleanup_complete,
        stderr_capture_complete=stderr_complete and capture_cleanup_complete,
    )
    if attempt_error is not None or cleanup_error is not None or not failed_result.capture_complete:
        cause = attempt_error or cleanup_error
        raise ClientInvocationError("client command did not complete", failed_result) from cause
    try:
        if expect_failure:
            if return_code == 0:
                raise AcceptanceError("client unexpectedly accepted rejected work")
            record = _json_record(stderr)
            if isinstance(expect_failure, str) and not expected_client_failure(
                ClientResult(return_code, stdout, stderr, record), expect_failure
            ):
                raise AcceptanceError("client failure did not match the contract")
        else:
            if return_code != 0:
                print(
                    sanitized_diagnostic("client", return_code, stdout, stderr),
                    file=sys.stderr,
                )
                raise AcceptanceError("client command failed")
            record = _json_record(stdout)
            if record.get("status") != "ok":
                raise AcceptanceError("client result was invalid")
    except AcceptanceError as error:
        raise ClientInvocationError(str(error), failed_result) from error
    return dataclasses.replace(failed_result, record=record)


def invoke_client_captured(
    captures: CaptureLedger,
    registry: ProcessRegistry,
    client: Path,
    command: str,
    application: str,
    token_file: Path,
    timeout_seconds: int,
    request: dict[str, Any] | None = None,
    *,
    expect_failure: bool | str = False,
    attempt_timeout_seconds: float | None = None,
) -> ClientResult:
    try:
        result = invoke_client(
            registry,
            client,
            command,
            application,
            token_file,
            timeout_seconds,
            request,
            expect_failure=expect_failure,
            attempt_timeout_seconds=attempt_timeout_seconds,
        )
    except ClientInvocationError as error:
        captures.extend((error.result.stdout, error.result.stderr))
        raise
    captures.extend((result.stdout, result.stderr))
    return result


def start_active_client(
    registry: ProcessRegistry,
    client: Path,
    command: str,
    application: str,
    token_file: Path,
    timeout_seconds: int,
    request: dict[str, Any],
    *,
    captures: CaptureLedger,
) -> ManagedProcess:
    phase = {"status": "unary", "stream": "stream"}.get(command, "activity")
    process = registry.spawn(
        _client_arguments(client, command, application, token_file, timeout_seconds),
        json.dumps(request, separators=(",", ":")).encode("utf-8"),
    )
    try:
        process.wait_for_stdout_activity('"status":"active"', timeout_seconds, phase)
    except Exception:
        cleanup_and_capture_processes(
            captures, registry, (process,), timeout_seconds
        )
        raise
    return process


def wait_for_readiness(
    process: ManagedProcess, health_address: str, timeout_seconds: int
) -> None:
    host, port = _address_parts(health_address)
    deadline = time.monotonic() + timeout_seconds
    while time.monotonic() < deadline:
        if process.process.poll() is not None:
            raise AcceptanceError("agent exited before readiness")
        if _readiness_probe(host, port, deadline):
            return
        time.sleep(min(0.05, max(0.0, deadline - time.monotonic())))
    raise AcceptanceError("agent readiness was not reached within the bound")


def _readiness_probe(host: str, port: int, deadline: float) -> bool:
    address = ipaddress.ip_address(host)
    family = socket.AF_INET6 if address.version == 6 else socket.AF_INET
    socket_address: Any = (host, port, 0, 0) if family == socket.AF_INET6 else (host, port)
    request = b"GET /readyz HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n"
    try:
        with socket.socket(family, socket.SOCK_STREAM) as connection:
            connection.setblocking(False)
            result = connection.connect_ex(socket_address)
            if result not in {
                0,
                errno.EINPROGRESS,
                errno.EWOULDBLOCK,
                errno.EALREADY,
                errno.EINTR,
            }:
                return False
            if result != 0:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    return False
                _, writable, exceptional = select.select(
                    [], [connection], [connection], remaining
                )
                if exceptional or not writable:
                    return False
                if connection.getsockopt(socket.SOL_SOCKET, socket.SO_ERROR) != 0:
                    return False

            pending = memoryview(request)
            while pending:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    return False
                _, writable, exceptional = select.select(
                    [], [connection], [connection], remaining
                )
                if exceptional or not writable:
                    return False
                try:
                    sent = connection.send(pending)
                except (BlockingIOError, InterruptedError):
                    continue
                if sent <= 0:
                    return False
                pending = pending[sent:]

            response = bytearray()
            while b"\r\n\r\n" not in response:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    return False
                readable, _, exceptional = select.select(
                    [connection], [], [connection], remaining
                )
                if exceptional or not readable:
                    return False
                try:
                    chunk = connection.recv(MAX_HEALTH_RESPONSE_BYTES + 1 - len(response))
                except (BlockingIOError, InterruptedError):
                    continue
                if not chunk:
                    return False
                response.extend(chunk)
                if len(response) > MAX_HEALTH_RESPONSE_BYTES:
                    return False
    except OSError:
        return False

    header, separator, body = bytes(response).partition(b"\r\n\r\n")
    if not separator or body:
        return False
    lines = header.split(b"\r\n")
    status = lines[0].split(b" ", 2) if lines else []
    if len(status) < 2 or status[1] != b"200":
        return False
    headers: dict[bytes, bytes] = {}
    for line in lines[1:]:
        name, separator, value = line.partition(b":")
        if not separator:
            return False
        lowered = name.strip().lower()
        if lowered in headers:
            return False
        headers[lowered] = value.strip().lower()
    return headers.get(b"content-length") == b"0" and b"transfer-encoding" not in headers


@dataclasses.dataclass
class PreservedClientToken:
    path: Path
    contents: bytes
    mode: int
    token: bytes
    modified: bool = False

    def replace(self, contents: bytes) -> None:
        self.modified = True
        _write_owner_only(self.path, contents, 0o600)

    def restore(self) -> None:
        if self.modified:
            _write_owner_only(self.path, self.contents, self.mode)


@contextlib.contextmanager
def preserve_client_token(path: Path) -> Iterable[PreservedClientToken]:
    require_regular_file(path, "client token")
    flags = os.O_RDONLY
    if hasattr(os, "O_CLOEXEC"):
        flags |= os.O_CLOEXEC
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        descriptor = os.open(path, flags)
        try:
            metadata = os.fstat(descriptor)
            if not stat.S_ISREG(metadata.st_mode):
                raise AcceptanceError("client token file is invalid")
            contents = bytearray()
            while len(contents) <= MAX_TOKEN_FILE_BYTES:
                chunk = os.read(
                    descriptor,
                    min(4096, MAX_TOKEN_FILE_BYTES + 1 - len(contents)),
                )
                if not chunk:
                    break
                contents.extend(chunk)
        finally:
            os.close(descriptor)
    except OSError as error:
        raise AcceptanceError("client token could not be read") from error
    if len(contents) > MAX_TOKEN_FILE_BYTES:
        raise AcceptanceError("client token is invalid")
    token = bytes(contents).rstrip(b"\r\n")
    if not token:
        raise AcceptanceError("client token is invalid")
    preserved = PreservedClientToken(
        path=path,
        contents=bytes(contents),
        mode=stat.S_IMODE(metadata.st_mode),
        token=token,
    )
    try:
        yield preserved
    finally:
        preserved.restore()


def _write_owner_only(path: Path, contents: bytes, mode: int = 0o600) -> None:
    flags = os.O_WRONLY | os.O_TRUNC
    if hasattr(os, "O_CLOEXEC"):
        flags |= os.O_CLOEXEC
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        descriptor = os.open(path, flags)
        try:
            if not stat.S_ISREG(os.fstat(descriptor).st_mode):
                raise AcceptanceError("client token file is invalid")
            view = memoryview(contents)
            while view:
                written = os.write(descriptor, view)
                if written <= 0:
                    raise AcceptanceError("client token could not be replaced")
                view = view[written:]
            os.fsync(descriptor)
            os.fchmod(descriptor, mode)
        finally:
            os.close(descriptor)
    except OSError as error:
        raise AcceptanceError("client token could not be replaced") from error


def _write_private_json(path: Path, document: dict[str, Any]) -> None:
    contents = json.dumps(document, separators=(",", ":")).encode("utf-8")
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    if hasattr(os, "O_CLOEXEC"):
        flags |= os.O_CLOEXEC
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        descriptor = os.open(path, flags, 0o600)
        try:
            view = memoryview(contents)
            while view:
                written = os.write(descriptor, view)
                if written <= 0:
                    raise AcceptanceError("negative configuration could not be prepared")
                view = view[written:]
            os.fsync(descriptor)
            os.fchmod(descriptor, 0o600)
        finally:
            os.close(descriptor)
    except OSError as error:
        raise AcceptanceError("negative configuration could not be prepared") from error


def _directory_snapshot(path: Path) -> DirectorySnapshot:
    try:
        metadata = path.stat()
        if not stat.S_ISDIR(metadata.st_mode):
            raise AcceptanceError("negative state guard is invalid")
        entries = tuple(sorted(entry.name for entry in path.iterdir()))
    except OSError as error:
        raise AcceptanceError("negative state guard is unavailable") from error
    return DirectorySnapshot(
        device=metadata.st_dev,
        inode=metadata.st_ino,
        mode=metadata.st_mode,
        links=metadata.st_nlink,
        size=metadata.st_size,
        modified_ns=metadata.st_mtime_ns,
        changed_ns=metadata.st_ctime_ns,
        entries=entries,
    )


def run_negative_startup_checks(
    registry: ProcessRegistry,
    agent: Path,
    config_path: Path,
    _contract: ConfigContract,
    timeout_seconds: int,
) -> NegativeStartupResult:
    original = _load_config_document(config_path)
    captures: list[str] = []
    canaries: list[str] = []
    receipts: list[str] = []
    with tempfile.TemporaryDirectory(prefix="aster-agent-negative-") as temporary:
        root = Path(temporary)
        root.chmod(0o700)
        with guarded_loopback_addresses() as guarded:
            canaries.extend((guarded.application, guarded.health, guarded.mesh))
            cases = (
                ("invalid-config-no-side-effects", "schema"),
                ("non-loopback-application-refusal", "application"),
                ("non-loopback-health-refusal", "health"),
            )
            for receipt, invalid_kind in cases:
                state_parent = root / f"state-parent-{receipt}"
                state_parent.mkdir(mode=0o700)
                state = state_parent / "SECRET_PATH_CANARY-state"
                negative_config = root / f"SECRET_PATH_CANARY-{receipt}-config.json"
                document = copy.deepcopy(original)
                document["state"]["directory"] = str(state)
                document["application"]["listen"] = guarded.application
                document["health"]["listen"] = guarded.health
                document["mesh"]["bind"] = guarded.mesh
                if invalid_kind == "schema":
                    document["schema_version"] = 2
                elif invalid_kind == "application":
                    _, application_port = _address_parts(guarded.application)
                    document["application"]["listen"] = f"192.0.2.1:{application_port}"
                else:
                    _, health_port = _address_parts(guarded.health)
                    document["health"]["listen"] = f"192.0.2.1:{health_port}"
                _write_private_json(negative_config, document)
                canaries.extend((str(state), str(negative_config)))
                if invalid_kind in {"application", "health"}:
                    canaries.append(document[invalid_kind]["listen"])

                before = _directory_snapshot(state_parent)
                process = registry.spawn(
                    [str(agent), "--check-config", str(negative_config)]
                )
                try:
                    code = process.wait(timeout_seconds)
                    stdout = process.stdout.text()
                    stderr = process.stderr.text()
                    if code == 0:
                        raise AcceptanceError("invalid configuration was accepted")
                    require_sanitized(
                        stdout + "\n" + stderr,
                        (str(state), str(negative_config), document[invalid_kind].get("listen", ""))
                        if invalid_kind in {"application", "health"}
                        else (str(state), str(negative_config)),
                    )
                    if _directory_snapshot(state_parent) != before:
                        raise AcceptanceError("invalid configuration mutated state")
                finally:
                    process.cleanup(timeout_seconds)
                    registry.discard(process)
                captures.append(stdout + "\n" + stderr)
                receipts.append(receipt)
    return NegativeStartupResult(
        captures=tuple(captures),
        canaries=tuple(canaries),
        receipts=tuple(receipts),
    )


def _reference_path(path: Path) -> str | None:
    try:
        encoded = path.read_bytes()
    except OSError:
        return None
    if len(encoded) < 14 or encoded[:8] != b"ASTRREF1":
        return None
    opaque_length = int.from_bytes(encoded[10:14], "big")
    if 14 + opaque_length != len(encoded):
        return None
    try:
        opaque = encoded[14:].decode("utf-8")
    except UnicodeDecodeError:
        return None
    return opaque if opaque.startswith("/") else None


def _process_canaries(
    arguments: Arguments, contract: ConfigContract, old_token: bytes
) -> list[str]:
    canaries = [
        str(arguments.config),
        str(contract.state),
        str(contract.token_file),
        str(contract.mission_reference_file),
        old_token.decode("ascii", errors="ignore"),
        ROTATED_TOKEN.decode("ascii"),
        CANARY_TOPIC,
        CANARY_SCOPE,
        CANARY_PAYLOAD.decode("ascii"),
        CANARY_LOGICAL_KEY.decode("ascii"),
    ]
    reference_path = _reference_path(contract.mission_reference_file)
    if reference_path is not None:
        canaries.append(reference_path)
    for peer in contract.peers:
        canaries.extend(_peer_canaries(peer))
    return canaries


def _peer_canaries(peer: str) -> tuple[str, ...]:
    carrier, separator, mission = peer.partition("=")
    if not separator:
        return (peer,)
    identity, address_separator, socket_address = carrier.rpartition("@")
    if not address_separator:
        return (peer, carrier, mission)
    return (peer, carrier, identity, socket_address, mission)


def _publish_request(payload: bytes = CANARY_PAYLOAD) -> dict[str, Any]:
    return {
        "operation_key_hex": FIXED_PUBLISH_OPERATION.hex(),
        "topic": CANARY_TOPIC,
        "scope": CANARY_SCOPE,
        "priority": "immediate",
        "logical_key_hex": CANARY_LOGICAL_KEY.hex(),
        "payload_hex": payload.hex(),
    }


def _expected_recovered_event(
    receipt: dict[str, Any], request: dict[str, Any]
) -> dict[str, Any]:
    event_id = receipt.get("event_id_hex")
    publisher = receipt.get("publisher_id_hex")
    publisher_counter = receipt.get("publisher_counter")
    event_sequence = receipt.get("event_sequence")
    acceptance_marker = receipt.get("acceptance_marker")
    if (
        not isinstance(event_id, str)
        or len(event_id) != 64
        or not isinstance(publisher, str)
        or len(publisher) != 64
        or not isinstance(publisher_counter, int)
        or isinstance(publisher_counter, bool)
        or publisher_counter < 1
        or not isinstance(event_sequence, int)
        or isinstance(event_sequence, bool)
        or event_sequence < 1
        or not isinstance(acceptance_marker, int)
        or isinstance(acceptance_marker, bool)
        or acceptance_marker < 1
    ):
        raise AcceptanceError("publish receipt was invalid")
    return {
        "id_hex": event_id,
        "publisher_hex": publisher,
        "publisher_counter": publisher_counter,
        "event_sequence": event_sequence,
        "topic": request["topic"],
        "scope": request["scope"],
        "priority": request["priority"],
        "logical_key_hex": request["logical_key_hex"],
        "payload_hex": request["payload_hex"],
        "tombstone": False,
        "acceptance_marker": acceptance_marker,
    }


def require_exact_recovery_evidence(record: dict[str, Any]) -> None:
    if record != {
        "status": "ok",
        "exact_match": True,
        "count": 1,
        "has_more": False,
    }:
        raise AcceptanceError("recovered publication was not exact")


def require_operation_key_conflict(record: dict[str, Any]) -> None:
    if record != {"status": "error", "code": "aborted"}:
        raise AcceptanceError("operation-key conflict was not rejected")


def run_acceptance(arguments: Arguments) -> None:
    require_executable(arguments.agent, "agent")
    require_executable(arguments.client, "client")
    contract = load_config_contract(arguments.config)
    with preserve_client_token(contract.token_file) as preserved:
        receipt_names = run_acceptance_with_token(arguments, contract, preserved)
    for name in receipt_names:
        print(f"RECEIPT status=pass name={name}")
    print(
        "AGENT_PROCESS_ACCEPTANCE status=pass "
        "provisioning=unprotected-test-provider-only deployment_qualification=not-claimed"
    )


def run_acceptance_with_token(
    arguments: Arguments,
    contract: ConfigContract,
    preserved: PreservedClientToken,
) -> list[str]:
    old_token = preserved.token
    registry = ProcessRegistry()
    captures = CaptureLedger(_process_canaries(arguments, contract, old_token))
    receipt_names: list[str] = []

    def start_agent() -> ManagedProcess:
        agent = registry.spawn(
            [str(arguments.agent), "--config", str(arguments.config)]
        )
        try:
            wait_for_readiness(agent, contract.health, arguments.timeout_seconds)
        except AcceptanceError:
            print(
                sanitized_diagnostic(
                    "agent",
                    agent.process.poll() if agent.process.poll() is not None else -1,
                    agent.stdout.text(),
                    agent.stderr.text(),
                ),
                file=sys.stderr,
            )
            raise
        receipt_names.append("readiness")
        return agent

    def stop_agent(
        agent: ManagedProcess, process_signal: signal.Signals, expected_code: int
    ) -> None:
        agent.signal(process_signal)
        code = agent.wait(arguments.timeout_seconds)
        captures.append(agent.combined())
        agent.cleanup(arguments.timeout_seconds)
        registry.discard(agent)
        if code != expected_code:
            raise AcceptanceError("agent exit status did not match the contract")

    def call(
        command: str,
        request: dict[str, Any] | None = None,
        *,
        token_file: Path | None = None,
        expect_failure: bool = False,
        attempt_timeout_seconds: float | None = None,
    ) -> ClientResult:
        try:
            result = invoke_client_captured(
                captures,
                registry,
                arguments.client,
                command,
                contract.application,
                token_file or contract.token_file,
                arguments.timeout_seconds,
                request,
                expect_failure=expect_failure,
                attempt_timeout_seconds=attempt_timeout_seconds,
            )
        except ClientInvocationError as error:
            raise ClientInvocationError(
                f"client phase {command} failed", error.result
            ) from error
        except AcceptanceError as error:
            raise AcceptanceError(f"client phase {command} failed") from error
        return result

    def drain_with_active_client(
        agent: ManagedProcess, client: ManagedProcess, phase: str
    ) -> None:
        agent.signal(signal.SIGTERM)
        try:
            agent_code, client_code = wait_for_process_pair_captured(
                captures,
                registry,
                agent,
                client,
                arguments.timeout_seconds,
            )
        except AcceptanceError as error:
            agent_stdout, _ = agent.stdout.snapshot()
            agent_stderr, _ = agent.stderr.snapshot()
            client_stdout, _ = client.stdout.snapshot()
            client_stderr, _ = client.stderr.snapshot()
            print(
                sanitized_agent_diagnostic(
                    phase,
                    agent.process.poll() if agent.process.poll() is not None else -1,
                    agent_stdout,
                    agent_stderr,
                ),
                file=sys.stderr,
            )
            print(
                sanitized_client_diagnostic(
                    phase,
                    client.process.poll() if client.process.poll() is not None else -1,
                    client_stdout,
                    client_stderr,
                ),
                file=sys.stderr,
            )
            raise AcceptanceError(f"{phase} drain did not finish within the bound") from error
        client_outcome_is_expected = expected_drain_client_outcome(
            phase, client_code, client.stdout.text(), client.stderr.text()
        )
        if agent_code != 0 or not client_outcome_is_expected:
            print(
                sanitized_agent_diagnostic(
                    phase, agent_code, agent.stdout.text(), agent.stderr.text()
                ),
                file=sys.stderr,
            )
            print(
                sanitized_client_diagnostic(
                    phase, client_code, client.stdout.text(), client.stderr.text()
                ),
                file=sys.stderr,
            )
            raise AcceptanceError(f"{phase} drain outcome did not match the contract")

    try:
        negative = run_negative_startup_checks(
            registry,
            arguments.agent,
            arguments.config,
            contract,
            arguments.timeout_seconds,
        )
        captures.add_canaries(negative.canaries)
        captures.extend(negative.captures)
        receipt_names.extend(negative.receipts)
        with tempfile.TemporaryDirectory(prefix="aster-agent-process-") as temporary:
            temporary_path = Path(temporary)
            temporary_path.chmod(0o700)
            old_token_file = temporary_path / "old-client-token"
            old_token_file.write_bytes(old_token + b"\n")
            old_token_file.chmod(0o600)

            agent = start_agent()
            publish_request = _publish_request()
            published = call("publish", publish_request).record
            expected_event = _expected_recovered_event(published, publish_request)
            event_id = expected_event["id_hex"]
            stop_agent(agent, signal.SIGKILL, -signal.SIGKILL)

            agent = start_agent()
            queried = call(
                "query",
                {"expected": expected_event},
            ).record
            require_exact_recovery_evidence(queried)
            conflict = call(
                "publish",
                _publish_request(CANARY_PAYLOAD + b"-changed"),
                expect_failure=True,
            )
            require_operation_key_conflict(conflict.record)
            subscription = call(
                "subscribe",
                {
                    "operation_key_hex": FIXED_SUBSCRIBE_OPERATION.hex(),
                    "topic": CANARY_TOPIC,
                    "scope": CANARY_SCOPE,
                },
            ).record
            subscription_id = subscription.get("subscription_id_hex")
            if not isinstance(subscription_id, str) or len(subscription_id) != 64:
                raise AcceptanceError("subscription receipt was invalid")
            first_delivery = call(
                "poll",
                {"subscription_id_hex": subscription_id, "delivery_limit": 1, "scan_limit": 8},
            ).record
            first = first_delivery.get("deliveries")
            if not isinstance(first, list) or len(first) != 1:
                raise AcceptanceError("first delivery was invalid")
            first_attempt = first[0].get("attempt")
            if first[0].get("event_id_hex") != event_id or not isinstance(first_attempt, int):
                raise AcceptanceError("first delivery did not match the publication")
            stop_agent(agent, signal.SIGKILL, -signal.SIGKILL)

            agent = start_agent()
            redelivery = call(
                "poll",
                {"subscription_id_hex": subscription_id, "delivery_limit": 1, "scan_limit": 8},
            ).record
            deliveries = redelivery.get("deliveries")
            if not isinstance(deliveries, list) or len(deliveries) != 1:
                raise AcceptanceError("redelivery was invalid")
            if (
                deliveries[0].get("event_id_hex") != event_id
                or not isinstance(deliveries[0].get("attempt"), int)
                or deliveries[0]["attempt"] <= first_attempt
            ):
                raise AcceptanceError("delivery attempt did not increase after restart")
            call(
                "ack",
                {"subscription_id_hex": subscription_id, "event_id_hex": event_id},
            )
            stop_agent(agent, signal.SIGKILL, -signal.SIGKILL)
            receipt_names.extend(("publish-recovery", "redelivery"))

            agent = start_agent()
            completed = call(
                "poll",
                {"subscription_id_hex": subscription_id, "delivery_limit": 1, "scan_limit": 8},
            ).record
            if completed.get("deliveries") != []:
                raise AcceptanceError("acknowledged delivery reappeared after restart")
            receipt_names.append("acknowledgement-persistence")

            preserved.replace(ROTATED_TOKEN + b"\n")
            agent.signal(signal.SIGHUP)
            deadline = time.monotonic() + arguments.timeout_seconds
            while True:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise AcceptanceError("rotated token was not accepted within the bound")
                try:
                    call("status", attempt_timeout_seconds=remaining)
                    break
                except ClientInvocationError as error:
                    if not expected_client_failure(error.result, "unauthenticated"):
                        raise AcceptanceError(
                            "rotated token probe did not match the contract"
                        ) from error
                    remaining = deadline - time.monotonic()
                    if remaining <= 0:
                        raise AcceptanceError("rotated token was not accepted within the bound")
                    time.sleep(min(0.05, remaining))
            rejected = call("status", token_file=old_token_file, expect_failure=True)
            if rejected.record.get("code") != "unauthenticated":
                raise AcceptanceError("old token was not rejected after reload")
            receipt_names.append("token-reload")

            unary = start_active_client(
                registry,
                arguments.client,
                "status",
                contract.application,
                contract.token_file,
                arguments.timeout_seconds,
                {"repeat_until_error": True},
                captures=captures,
            )
            drain_with_active_client(agent, unary, "unary")

            agent = start_agent()
            streaming = start_active_client(
                registry,
                arguments.client,
                "stream",
                contract.application,
                contract.token_file,
                arguments.timeout_seconds,
                {
                    "subscription_id_hex": subscription_id,
                    "delivery_limit": 1,
                    "scan_limit": 8,
                    "poll_backoff_ms": 100,
                    "count": 1,
                },
                captures=captures,
            )
            drain_with_active_client(agent, streaming, "stream")
            receipt_names.append("graceful-drain")

            require_sanitized(
                captures.text(),
                [
                    *_process_canaries(arguments, contract, old_token),
                    *negative.canaries,
                ],
            )
            receipt_names.append("canary-absence")
    finally:
        registry.cleanup_all(arguments.timeout_seconds)

    return receipt_names


@contextlib.contextmanager
def termination_unwinds_cleanup() -> Iterable[None]:
    installed: list[tuple[signal.Signals, Any]] = []
    interrupted = False

    def interrupt(_signal_number: int, _frame: Any) -> None:
        nonlocal interrupted
        if not interrupted:
            interrupted = True
            raise CheckerInterrupted("process checker interrupted")

    for name in ("SIGTERM", "SIGHUP", "SIGINT"):
        process_signal = getattr(signal, name, None)
        if process_signal is not None:
            previous = signal.getsignal(process_signal)
            signal.signal(process_signal, interrupt)
            installed.append((process_signal, previous))
    try:
        yield
    finally:
        for process_signal, previous in installed:
            signal.signal(process_signal, previous)


def main(argv: Sequence[str] | None = None) -> int:
    try:
        with termination_unwinds_cleanup():
            arguments = parse_arguments(sys.argv[1:] if argv is None else argv)
            run_acceptance(arguments)
    except (AcceptanceError, CheckerInterrupted, ValueError) as error:
        print(f"ERROR {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
