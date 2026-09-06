#!/usr/bin/env python3
"""Bounded black-box crash/recovery acceptance for a customer Aster agent.

The checker treats its agent and protocol client as packaged executables.  It
never provisions production credentials; the repository smoke task supplies an
explicitly unprotected, test-only fixture binary and configuration.
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


def parse_arguments(argv: Sequence[str]) -> Arguments:
    parser = QuietArgumentParser(add_help=True)
    parser.add_argument("--agent")
    parser.add_argument("--config")
    parser.add_argument("--client")
    parser.add_argument("--timeout-seconds", default="30")
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


class ManagedProcess:
    def __init__(self, arguments: Sequence[str], input_bytes: bytes | None = None) -> None:
        self.stdout = BoundedCapture()
        self.stderr = BoundedCapture()
        try:
            self.process = subprocess.Popen(
                list(arguments),
                stdin=subprocess.PIPE if input_bytes is not None else subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                start_new_session=True,
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

    def wait(self, timeout_seconds: int) -> int:
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

    def cleanup(self, timeout_seconds: int) -> None:
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


@dataclasses.dataclass(frozen=True)
class ClientResult:
    return_code: int
    stdout: str
    stderr: str
    record: dict[str, Any]


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
    client: Path,
    command: str,
    application: str,
    token_file: Path,
    timeout_seconds: int,
    request: dict[str, Any] | None = None,
    *,
    expect_failure: bool = False,
) -> ClientResult:
    encoded = json.dumps(request or {}, separators=(",", ":")).encode("utf-8")
    process = ManagedProcess(
        _client_arguments(client, command, application, token_file, timeout_seconds),
        encoded,
    )
    try:
        return_code = process.wait(timeout_seconds)
        stdout = process.stdout.text()
        stderr = process.stderr.text()
    finally:
        process.cleanup(timeout_seconds)
    if expect_failure:
        if return_code == 0:
            raise AcceptanceError("client unexpectedly accepted rejected work")
        record = _json_record(stderr)
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
    return ClientResult(return_code, stdout, stderr, record)


def start_active_client(
    client: Path,
    command: str,
    application: str,
    token_file: Path,
    timeout_seconds: int,
    request: dict[str, Any],
) -> ManagedProcess:
    phase = {"status": "unary", "stream": "stream"}.get(command, "activity")
    process = ManagedProcess(
        _client_arguments(client, command, application, token_file, timeout_seconds),
        json.dumps(request, separators=(",", ":")).encode("utf-8"),
    )
    try:
        process.wait_for_stdout_activity('"status":"active"', timeout_seconds, phase)
    except Exception:
        process.cleanup(timeout_seconds)
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


def run_negative_startup_checks(
    agent: Path,
    config_path: Path,
    contract: ConfigContract,
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
                ("invalid-config-no-side-effects", True),
                ("non-loopback-refusal", False),
            )
            for receipt, invalid_schema in cases:
                state = root / f"SECRET_PATH_CANARY-{receipt}-state"
                negative_config = root / f"SECRET_PATH_CANARY-{receipt}-config.json"
                document = copy.deepcopy(original)
                document["state"]["directory"] = str(state)
                document["application"]["listen"] = guarded.application
                document["health"]["listen"] = guarded.health
                document["mesh"]["bind"] = guarded.mesh
                if invalid_schema:
                    document["schema_version"] = 2
                else:
                    _, application_port = _address_parts(guarded.application)
                    document["application"]["listen"] = f"192.0.2.1:{application_port}"
                _write_private_json(negative_config, document)
                canaries.extend((str(state), str(negative_config)))
                if not invalid_schema:
                    canaries.append(document["application"]["listen"])

                process = ManagedProcess([str(agent), "--config", str(negative_config)])
                try:
                    code = process.wait(timeout_seconds)
                    stdout = process.stdout.text()
                    stderr = process.stderr.text()
                    if code == 0:
                        raise AcceptanceError("invalid configuration was accepted")
                    if stdout.splitlines() != [] or stderr.splitlines() != [
                        "ERROR unprotected test fixture configuration failed"
                    ]:
                        raise AcceptanceError(
                            "invalid configuration crossed the validation boundary"
                        )
                    if state.exists():
                        raise AcceptanceError("invalid configuration mutated state")
                finally:
                    process.cleanup(timeout_seconds)
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
        canaries.append(peer)
        carrier, separator, mission = peer.partition("=")
        if separator:
            canaries.extend((carrier, mission))
            if "@" in carrier:
                canaries.append(carrier.rsplit("@", 1)[1])
    return canaries


def _publish_request(payload: bytes = CANARY_PAYLOAD) -> dict[str, Any]:
    return {
        "operation_key_hex": FIXED_PUBLISH_OPERATION.hex(),
        "topic": CANARY_TOPIC,
        "scope": CANARY_SCOPE,
        "priority": "immediate",
        "logical_key_hex": CANARY_LOGICAL_KEY.hex(),
        "payload_hex": payload.hex(),
    }


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
    negative = run_negative_startup_checks(
        arguments.agent,
        arguments.config,
        contract,
        arguments.timeout_seconds,
    )
    captures = list(negative.captures)
    live: list[ManagedProcess] = []
    receipt_names = list(negative.receipts)

    def start_agent() -> ManagedProcess:
        agent = ManagedProcess([str(arguments.agent), "--config", str(arguments.config)])
        live.append(agent)
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
        live.remove(agent)
        if code != expected_code:
            raise AcceptanceError("agent exit status did not match the contract")

    def call(
        command: str,
        request: dict[str, Any] | None = None,
        *,
        token_file: Path | None = None,
        expect_failure: bool = False,
    ) -> ClientResult:
        try:
            result = invoke_client(
                arguments.client,
                command,
                contract.application,
                token_file or contract.token_file,
                arguments.timeout_seconds,
                request,
                expect_failure=expect_failure,
            )
        except AcceptanceError as error:
            raise AcceptanceError(f"client phase {command} failed") from error
        captures.extend((result.stdout, result.stderr))
        return result

    def drain_with_active_client(
        agent: ManagedProcess, client: ManagedProcess, phase: str
    ) -> None:
        agent.signal(signal.SIGTERM)
        try:
            agent_code, client_code = wait_for_process_pair(
                agent, client, arguments.timeout_seconds
            )
        except AcceptanceError as error:
            print(
                sanitized_agent_diagnostic(
                    phase,
                    agent.process.poll() if agent.process.poll() is not None else -1,
                    agent.stdout.text(),
                    agent.stderr.text(),
                ),
                file=sys.stderr,
            )
            print(
                sanitized_client_diagnostic(
                    phase,
                    client.process.poll() if client.process.poll() is not None else -1,
                    client.stdout.text(),
                    client.stderr.text(),
                ),
                file=sys.stderr,
            )
            raise AcceptanceError(f"{phase} drain did not finish within the bound") from error
        captures.extend((agent.combined(), client.combined()))
        agent.cleanup(arguments.timeout_seconds)
        client.cleanup(arguments.timeout_seconds)
        live.remove(agent)
        live.remove(client)
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
        with tempfile.TemporaryDirectory(prefix="aster-agent-process-") as temporary:
            temporary_path = Path(temporary)
            temporary_path.chmod(0o700)
            old_token_file = temporary_path / "old-client-token"
            old_token_file.write_bytes(old_token + b"\n")
            old_token_file.chmod(0o600)

            agent = start_agent()
            published = call("publish", _publish_request()).record
            event_id = published.get("event_id_hex")
            if not isinstance(event_id, str) or len(event_id) != 64:
                raise AcceptanceError("publish receipt was invalid")
            stop_agent(agent, signal.SIGKILL, -signal.SIGKILL)

            agent = start_agent()
            queried = call(
                "query",
                {"topic": CANARY_TOPIC, "scope": CANARY_SCOPE, "limit": 8},
            ).record
            if queried.get("event_ids_hex") != [event_id]:
                raise AcceptanceError("recovered publication did not match the receipt")
            conflict = call(
                "publish",
                _publish_request(CANARY_PAYLOAD + b"-changed"),
                expect_failure=True,
            )
            if conflict.record.get("status") != "error":
                raise AcceptanceError("operation-key conflict was not rejected")
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
                try:
                    call("status")
                    break
                except AcceptanceError:
                    if time.monotonic() >= deadline:
                        raise AcceptanceError("rotated token was not accepted within the bound")
                    time.sleep(0.05)
            rejected = call("status", token_file=old_token_file, expect_failure=True)
            if rejected.record.get("code") != "unauthenticated":
                raise AcceptanceError("old token was not rejected after reload")
            receipt_names.append("token-reload")

            unary = start_active_client(
                arguments.client,
                "status",
                contract.application,
                contract.token_file,
                arguments.timeout_seconds,
                {"repeat_until_error": True},
            )
            live.append(unary)
            drain_with_active_client(agent, unary, "unary")

            agent = start_agent()
            streaming = start_active_client(
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
            )
            live.append(streaming)
            drain_with_active_client(agent, streaming, "stream")
            receipt_names.append("graceful-drain")

            require_sanitized(
                "\n".join(captures),
                [
                    *_process_canaries(arguments, contract, old_token),
                    *negative.canaries,
                ],
            )
            receipt_names.append("canary-absence")
    finally:
        for process in reversed(live):
            process.cleanup(arguments.timeout_seconds)

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
