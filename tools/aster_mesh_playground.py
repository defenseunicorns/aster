#!/usr/bin/env python3
# Copyright 2026 Defense Unicorns, Inc.
# SPDX-License-Identifier: Apache-2.0
"""Interactive, one-host Aster Event playground and Field Notes hello tour.

This controller is deliberately a presentation and application-integration
exercise.  It provisions disposable reference credentials through
``aster playground-init``, starts one real ``aster-agent`` process per node,
uses the public loopback Connect JSON Event API for observation, and publishes
through the durable numbered asterctl SDK journal.  A message is shown
at a node only after that node's QueryEvents response contains the exact Event
identity.  Peer status is displayed as a last-contact observation and is never
promoted into a global-convergence claim.

``assert-unseen`` is intentionally weaker than a convergence assertion: it
performs one fresh full QueryEvents observation at each named node and reports
only that the exact Event was absent from those completed local query views.
It makes no statement about later arrival or any unobserved node.

The playground is bounded to 2..=32 same-implementation processes on one host,
direct loopback, one durable Event topic/scope, and unprotected-reference
provisioning.  It is not production authorization or physical-network,
payload-blind-relay, performance, or requirement-scale evidence.

The opt-in ``--hello`` experience keeps the same technical boundary while
staging a small, named roster for a human-driven first contact.  Its explicit
``nearby`` route source gives the selected runtime only pre-provisioned carrier
and mission identities for a ten-second locator window.  Its explicit
``invitation`` route source uses the controller's already-known loopback
locators.  Neither mode can silently fall back to the other, and friendly names
remain presentation-only metadata.
"""

from __future__ import annotations

import argparse
import base64
from dataclasses import dataclass, field
import http.client
import ipaddress
import json
import math
import os
from pathlib import Path
import re
import secrets
import shutil
import signal
import socket
import subprocess
import sys
import tempfile
import threading
import time
from typing import Any, Callable, Dict, Iterable, List, Mapping, Optional, Sequence, Set, TextIO, Tuple
from urllib.parse import unquote, urlparse


MIN_NODES = 2
MAX_NODES = 32
TOPIC = "mesh.messages"
SCOPE = "demo/playground"
SERVICE = "aster.application.v1alpha1.AsterApplicationService"
MAX_MESSAGE_BYTES = 4 * 1024
MAX_RPC_RESPONSE_BYTES = 2 * 1024 * 1024
QUERY_PAGE_LIMIT = 128
# 1,024 retained Events fit in eight full pages; one defensive page permits a
# final progress check without restoring the old hostile multi-minute bound.
MAX_QUERY_PAGES = 9
DEFAULT_POLL_SECONDS = 0.35
DEFAULT_STARTUP_SECONDS = 30.0
DEFAULT_WAIT_SECONDS = 20.0
MAX_STARTUP_SECONDS = 300.0
MAX_POLL_MILLISECONDS = 60_000
MAX_WAIT_SECONDS = 3_600.0
MAX_PARSED_LINE_BYTES = 64 * 1024
CHILD_LOG_SEGMENT_BYTES = 256 * 1024
CHILD_LOG_SEGMENTS = 4
MAX_TRACKED_MESSAGES = 1024
MAX_COMMAND_LINE_CHARACTERS = MAX_MESSAGE_BYTES + 256
MAX_INITIALIZER_STDOUT_BYTES = 256 * 1024
MAX_INITIALIZER_STDERR_BYTES = 256 * 1024
HELLO_NEARBY_WINDOW_SECONDS = 10
HELLO_SYNC_MILLISECONDS = 1_000
HELLO_NODE_NAMES = (
    "atlas",
    "beacon",
    "cove",
    "drift",
    "ember",
    "fjord",
    "grove",
    "harbor",
    "iris",
    "juno",
    "kite",
    "lumen",
    "mesa",
    "north",
    "orbit",
    "piper",
    "quill",
    "ridge",
    "sol",
    "tide",
    "umbra",
    "vale",
    "wren",
    "xeno",
    "yarrow",
    "zenith",
    "aurora",
    "briar",
    "coral",
    "delta",
    "echo",
    "fern",
)
BOUNDARY = (
    "one host · loopback · Event only · same implementation · "
    "unprotected-reference provisioning"
)

ANSI_ESCAPE = "\x1b"
ASCII_ID = re.compile(r"^[0-9a-f]{64}$")
class PlaygroundError(RuntimeError):
    """Sanitized playground failure."""


class RpcError(PlaygroundError):
    """Sanitized local application RPC failure."""


def safe_text(value: object, limit: Optional[int] = None) -> str:
    """Return display-safe text without terminal control characters."""

    text = str(value)
    cleaned: List[str] = []
    for character in text:
        code = ord(character)
        if character == ANSI_ESCAPE:
            cleaned.append("?")
        elif character in "\n\r\t":
            cleaned.append(" ")
        elif code < 32 or code == 127:
            cleaned.append("?")
        elif character.isprintable():
            cleaned.append(character)
        else:
            cleaned.append("?")
    result = "".join(cleaned)
    if limit is not None and len(result) > limit:
        if limit <= 3:
            return result[:limit]
        return result[: limit - 1] + "…"
    return result


def supports_unicode(stream: object = sys.stdout) -> bool:
    encoding = getattr(stream, "encoding", None) or "ascii"
    try:
        "✓●○─·…".encode(encoding)
    except (LookupError, UnicodeEncodeError):
        return False
    return True


def terminal_text(value: str, unicode: bool) -> str:
    value = safe_text(value)
    if unicode:
        return value
    replacements = {
        "✓": "Y",
        "●": "*",
        "○": "o",
        "◐": "~",
        "×": "x",
        "─": "-",
        "·": "|",
        "…": "...",
        "→": "->",
    }
    for source, replacement in replacements.items():
        value = value.replace(source, replacement)
    return value.encode("ascii", errors="replace").decode("ascii")


def truncate(value: str, width: int, unicode: bool = True) -> str:
    value = terminal_text(value, unicode)
    if width <= 0:
        return ""
    if len(value) <= width:
        return value
    if width <= 3:
        return value[:width]
    suffix = "…" if unicode else "..."
    return value[: width - len(suffix)] + suffix


def parse_fields(line: str) -> Tuple[str, Dict[str, str]]:
    tokens = line.strip().split()
    if not tokens:
        return "", {}
    fields: Dict[str, str] = {}
    for token in tokens[1:]:
        if "=" not in token:
            continue
        key, value = token.split("=", 1)
        if key:
            fields[key] = value
    return tokens[0], fields


def decode_b64(value: object, label: str, expected: Optional[int] = None) -> bytes:
    if not isinstance(value, str):
        raise PlaygroundError("%s is not base64 text" % label)
    try:
        decoded = base64.b64decode(value, validate=True)
    except (ValueError, TypeError) as error:
        raise PlaygroundError("%s is not valid base64" % label) from error
    if expected is not None and len(decoded) != expected:
        raise PlaygroundError("%s has an unexpected length" % label)
    return decoded


def encode_b64(value: bytes) -> str:
    return base64.b64encode(value).decode("ascii")


def bounded_timeout(value: object, label: str, maximum: float) -> float:
    try:
        timeout = float(value)
    except (TypeError, ValueError) as error:
        raise PlaygroundError("%s must be a number" % label) from error
    if not math.isfinite(timeout) or timeout <= 0 or timeout > maximum:
        raise PlaygroundError("%s must be finite and within (0, %g] seconds" % (label, maximum))
    return timeout


@dataclass(frozen=True)
class InitNode:
    index: int
    carrier_id: str
    mission_id: str


@dataclass(frozen=True)
class InitResult:
    root: Path
    nodes: Tuple[InitNode, ...]
    stdout: bytes = b""
    stderr: bytes = b""


def parse_initializer_output(data: bytes, expected_root: Path, expected_nodes: int) -> InitResult:
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError as error:
        raise PlaygroundError("playground initializer stdout is not UTF-8") from error
    lines = [line for line in text.splitlines() if line.strip()]
    if len(lines) != expected_nodes + 1:
        raise PlaygroundError(
            "playground initializer returned %d records; expected %d"
            % (len(lines), expected_nodes + 1)
        )
    kind, header = parse_fields(lines[0])
    if kind != "PLAYGROUND_INIT" or header.get("status") != "pass":
        raise PlaygroundError("playground initializer omitted its passing header")
    try:
        declared_nodes = int(header.get("nodes", ""))
    except ValueError as error:
        raise PlaygroundError("playground initializer node count is malformed") from error
    decoded_root = Path(unquote(header.get("root", "")))
    if declared_nodes != expected_nodes:
        raise PlaygroundError("playground initializer node count differs from the request")
    if header.get("scope") != SCOPE or header.get("topic") != TOPIC:
        raise PlaygroundError("playground initializer topic or scope differs from the demo contract")
    if header.get("epoch") != "1" or header.get("provisioning") != "unprotected-reference":
        raise PlaygroundError("playground initializer reported an unexpected security profile")
    if os.path.abspath(str(decoded_root)) != os.path.abspath(str(expected_root)):
        raise PlaygroundError("playground initializer root differs from the requested root")

    nodes: Dict[int, InitNode] = {}
    for line in lines[1:]:
        kind, fields = parse_fields(line)
        if kind != "PLAYGROUND_NODE":
            raise PlaygroundError("playground initializer returned an unknown record")
        try:
            index = int(fields.get("index", ""))
        except ValueError as error:
            raise PlaygroundError("playground initializer node index is malformed") from error
        carrier_id = fields.get("carrier_id", "")
        mission_id = fields.get("mission_id", "")
        if index in nodes or not 0 <= index < expected_nodes:
            raise PlaygroundError("playground initializer node indexes are incomplete or duplicated")
        if not ASCII_ID.fullmatch(carrier_id) or not ASCII_ID.fullmatch(mission_id):
            raise PlaygroundError("playground initializer returned a malformed identity")
        nodes[index] = InitNode(index, carrier_id, mission_id)
    if set(nodes) != set(range(expected_nodes)):
        raise PlaygroundError("playground initializer omitted a node")
    return InitResult(expected_root, tuple(nodes[index] for index in range(expected_nodes)), data, b"")


def _signal_process_group(process: subprocess.Popen, signum: int) -> None:
    try:
        if os.name == "posix":
            # The session leader may have exited while a descendant still owns
            # the process group.  Address the PGID even after leader exit.
            os.killpg(process.pid, signum)
        elif process.poll() is None:
            process.send_signal(signum)
    except ProcessLookupError:
        return


def _process_group_exists(process: subprocess.Popen) -> bool:
    if os.name != "posix":
        return process.poll() is None
    try:
        os.killpg(process.pid, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        return True
    return True


def _wait_process_group_gone(process: subprocess.Popen, seconds: float) -> bool:
    deadline = time.monotonic() + max(0.0, seconds)
    while True:
        process.poll()
        if not _process_group_exists(process):
            return True
        if time.monotonic() >= deadline:
            return False
        time.sleep(min(0.025, max(0.0, deadline - time.monotonic())))


def stop_subprocess(process: subprocess.Popen, graceful_seconds: float = 3.0) -> int:
    """Bounded process-group cleanup used by initialization and node workers."""

    _signal_process_group(process, signal.SIGINT)
    if not _wait_process_group_gone(process, graceful_seconds):
        _signal_process_group(process, signal.SIGTERM)
    if not _wait_process_group_gone(process, 2.0):
        _signal_process_group(process, signal.SIGKILL)
    if not _wait_process_group_gone(process, 2.0):
        raise PlaygroundError("child process group did not exit after SIGKILL")
    returncode = process.poll()
    if returncode is None:
        returncode = process.wait(timeout=0.2)
    return returncode


def _write_exclusive(path: Path, data: bytes, mode: int = 0o600) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor = os.open(str(path), os.O_WRONLY | os.O_CREAT | os.O_EXCL, mode)
    try:
        with os.fdopen(descriptor, "wb", buffering=0) as output:
            output.write(data)
    except BaseException:
        try:
            os.close(descriptor)
        except OSError:
            pass
        raise


def collect_process_output(
    process: subprocess.Popen,
    timeout: float,
    stdout_limit: int,
    stderr_limit: int,
) -> Tuple[bytes, bytes, bool, bool, bool]:
    """Drain both child pipes while retaining only bounded byte prefixes."""

    assert process.stdout is not None
    assert process.stderr is not None
    buffers = {"stdout": bytearray(), "stderr": bytearray()}
    overflow = {"stdout": False, "stderr": False}

    def collect(name: str, stream: Any, limit: int) -> None:
        try:
            while True:
                chunk = stream.read(4096)
                if not chunk:
                    return
                remaining = max(0, limit - len(buffers[name]))
                if remaining:
                    buffers[name].extend(chunk[:remaining])
                if len(chunk) > remaining:
                    overflow[name] = True
        except OSError:
            return
        finally:
            try:
                stream.close()
            except OSError:
                pass

    threads = [
        threading.Thread(
            target=collect,
            args=("stdout", process.stdout, stdout_limit),
            name="aster-playground-init-stdout",
            daemon=True,
        ),
        threading.Thread(
            target=collect,
            args=("stderr", process.stderr, stderr_limit),
            name="aster-playground-init-stderr",
            daemon=True,
        ),
    ]
    for thread in threads:
        thread.start()
    timed_out = False
    try:
        process.wait(timeout=timeout)
    except subprocess.TimeoutExpired:
        timed_out = True
        stop_subprocess(process)
    except BaseException:
        stop_subprocess(process)
        for thread in threads:
            thread.join(timeout=2.0)
        raise
    for thread in threads:
        thread.join(timeout=2.0)
    if any(thread.is_alive() for thread in threads):
        # A descendant inherited a pipe after its leader exited. Sweep the
        # already-isolated process group before relinquishing supervision.
        stop_subprocess(process, 0.0)
        for thread in threads:
            thread.join(timeout=2.0)
    if any(thread.is_alive() for thread in threads):
        raise PlaygroundError("playground initializer output pipes did not close")
    return (
        bytes(buffers["stdout"]),
        bytes(buffers["stderr"]),
        overflow["stdout"],
        overflow["stderr"],
        timed_out,
    )


def run_initializer(aster: Path, root: Path, nodes: int, timeout: float) -> InitResult:
    command = [str(aster), "playground-init", "--nodes", str(nodes), "--root", str(root)]
    try:
        process = subprocess.Popen(
            command,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            start_new_session=(os.name == "posix"),
        )
    except OSError as error:
        raise PlaygroundError("could not start the Aster playground initializer") from error
    stdout, stderr, stdout_overflow, stderr_overflow, timed_out = collect_process_output(
        process,
        timeout,
        MAX_INITIALIZER_STDOUT_BYTES,
        MAX_INITIALIZER_STDERR_BYTES,
    )

    if root.is_dir():
        logs = root / "logs"
        logs.mkdir(parents=True, exist_ok=True)
        _write_exclusive(logs / "playground-init.stdout", stdout)
        _write_exclusive(logs / "playground-init.stderr", stderr)
    if timed_out:
        raise PlaygroundError("playground initialization timed out")
    if stdout_overflow or stderr_overflow:
        stream = "stdout" if stdout_overflow else "stderr"
        raise PlaygroundError(
            "playground initializer %s exceeds its retained output bound" % stream
        )
    if process.returncode != 0:
        detail = safe_text(stderr.decode("utf-8", errors="replace"), 240)
        raise PlaygroundError("playground initializer failed%s" % (": " + detail if detail else ""))
    result = parse_initializer_output(stdout, root, nodes)
    return InitResult(result.root, result.nodes, stdout, stderr)


class Topology:
    """A line whose isolated nodes have no configured incident peer edge."""

    def __init__(self, count: int) -> None:
        if not MIN_NODES <= count <= MAX_NODES:
            raise PlaygroundError("node count must be within 2..=32")
        self.count = count
        self.isolated: Set[int] = set()

    def validate(self, index: int) -> None:
        if not 0 <= index < self.count:
            raise PlaygroundError("node index must be within 0..%d" % (self.count - 1))

    def baseline_neighbors(self, index: int) -> Set[int]:
        self.validate(index)
        result: Set[int] = set()
        if index > 0:
            result.add(index - 1)
        if index + 1 < self.count:
            result.add(index + 1)
        return result

    def neighbors(self, index: int) -> Set[int]:
        self.validate(index)
        if index in self.isolated:
            return set()
        return {neighbor for neighbor in self.baseline_neighbors(index) if neighbor not in self.isolated}

    def edge_enabled(self, left: int, right: int) -> bool:
        return (
            right == left + 1
            and left not in self.isolated
            and right not in self.isolated
        )

    def isolate(self, index: int) -> Set[int]:
        self.validate(index)
        if index in self.isolated:
            return set()
        affected = self.baseline_neighbors(index) | {index}
        self.isolated.add(index)
        return affected

    def rejoin(self, index: int) -> Set[int]:
        self.validate(index)
        if index not in self.isolated:
            return set()
        affected = self.baseline_neighbors(index) | {index}
        self.isolated.remove(index)
        return affected


class RotatingByteLog:
    """Byte-preserving bounded log segments, newest data in the base path."""

    def __init__(
        self,
        path: Path,
        segment_bytes: int = CHILD_LOG_SEGMENT_BYTES,
        segments: int = CHILD_LOG_SEGMENTS,
    ) -> None:
        if segment_bytes <= 0 or segments <= 0:
            raise ValueError("log rotation bounds must be positive")
        self.path = path
        self.segment_bytes = segment_bytes
        self.segments = segments
        self.size = 0
        self.closed = False
        path.parent.mkdir(parents=True, exist_ok=True)
        if path.exists():
            self._shift_segments()
        self.file = open(path, "xb", buffering=0)

    def _segment(self, number: int) -> Path:
        return self.path.with_name(self.path.name + ".%d" % number)

    def _shift_segments(self) -> None:
        oldest = self._segment(self.segments - 1)
        if self.segments > 1:
            try:
                oldest.unlink()
            except FileNotFoundError:
                pass
            for number in range(self.segments - 1, 1, -1):
                source = self._segment(number - 1)
                if source.exists():
                    os.replace(str(source), str(self._segment(number)))
            if self.path.exists():
                os.replace(str(self.path), str(self._segment(1)))
        else:
            try:
                self.path.unlink()
            except FileNotFoundError:
                pass

    def _rotate(self) -> None:
        self.file.close()
        self._shift_segments()
        self.file = open(self.path, "xb", buffering=0)
        self.size = 0

    def write(self, data: bytes) -> None:
        if self.closed:
            raise ValueError("write to closed rotating log")
        view = memoryview(data)
        while view:
            if self.size >= self.segment_bytes:
                self._rotate()
            available = self.segment_bytes - self.size
            portion = view[:available]
            self.file.write(portion)
            written = len(portion)
            self.size += written
            view = view[written:]

    def write_record(self, data: bytes) -> None:
        """Write one unsplit record, rotating before it when necessary."""

        if self.closed:
            raise ValueError("write to closed rotating log")
        if len(data) > self.segment_bytes:
            raise PlaygroundError("one retained journal record exceeds its segment bound")
        if self.size and self.size + len(data) > self.segment_bytes:
            self._rotate()
        self.file.write(data)
        self.size += len(data)

    def close(self) -> None:
        if not self.closed:
            self.file.close()
            self.closed = True

class ManagedProcess:
    """One child with bounded byte-preserving tail segments and parsed readiness."""

    def __init__(
        self,
        command: Sequence[str],
        stdout_path: Path,
        stderr_path: Path,
        line_callback: Optional[Callable[[str, bytes], None]] = None,
    ) -> None:
        self.command = tuple(command)
        self.stdout_path = stdout_path
        self.stderr_path = stderr_path
        self.line_callback = line_callback
        self._ready = threading.Event()
        self._ready_url: Optional[str] = None
        self._stderr_tail: List[str] = []
        self._threads: List[threading.Thread] = []
        self._closed = False
        stdout_path.parent.mkdir(parents=True, exist_ok=True)
        self._stdout_file = RotatingByteLog(stdout_path)
        self._stderr_file = RotatingByteLog(stderr_path)
        try:
            self.process = subprocess.Popen(
                list(command),
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                start_new_session=(os.name == "posix"),
                bufsize=0,
            )
        except BaseException:
            self._stdout_file.close()
            self._stderr_file.close()
            raise
        assert self.process.stdout is not None
        assert self.process.stderr is not None
        for name, stream, output in (
            ("stdout", self.process.stdout, self._stdout_file),
            ("stderr", self.process.stderr, self._stderr_file),
        ):
            thread = threading.Thread(
                target=self._pump,
                args=(name, stream, output),
                name="aster-playground-%s-%d" % (name, self.process.pid),
                daemon=True,
            )
            thread.start()
            self._threads.append(thread)

    @property
    def pid(self) -> int:
        return self.process.pid

    @property
    def ready_url(self) -> Optional[str]:
        return self._ready_url

    @property
    def stderr_tail(self) -> Tuple[str, ...]:
        return tuple(self._stderr_tail)

    def _pump(self, name: str, stream: Any, output: Any) -> None:
        pending = bytearray()
        discarding_oversized_line = False
        try:
            while True:
                chunk = stream.read(4096)
                if not chunk:
                    break
                output.write(chunk)
                pending.extend(chunk)
                while True:
                    if discarding_oversized_line:
                        split = pending.find(b"\n")
                        if split < 0:
                            pending.clear()
                            break
                        del pending[: split + 1]
                        discarding_oversized_line = False
                        continue
                    split = pending.find(b"\n")
                    if split < 0:
                        if len(pending) > MAX_PARSED_LINE_BYTES:
                            pending.clear()
                            discarding_oversized_line = True
                            if name == "stderr":
                                self._stderr_tail.append(
                                    "unterminated stderr line exceeded the parser bound; inspect retained log segments"
                                )
                                del self._stderr_tail[:-8]
                        break
                    line = bytes(pending[: split + 1])
                    del pending[: split + 1]
                    if len(line) <= MAX_PARSED_LINE_BYTES:
                        self._observe_line(name, line)
                    elif name == "stderr":
                        self._stderr_tail.append(
                            "stderr line exceeded the parser bound; inspect retained log segments"
                        )
                        del self._stderr_tail[:-8]
            if pending and not discarding_oversized_line:
                self._observe_line(name, bytes(pending))
        finally:
            try:
                stream.close()
            except OSError:
                pass

    def _observe_line(self, name: str, line: bytes) -> None:
        if name == "stdout":
            text = line.decode("utf-8", errors="replace").strip()
            kind, fields = parse_fields(text)
            if kind == "AGENT" and fields.get("status") == "ready":
                listen = fields.get("listen", "")
                parsed = urlparse(listen)
                try:
                    loopback = parsed.hostname is not None and ipaddress.ip_address(parsed.hostname).is_loopback
                    port = parsed.port
                except ValueError:
                    loopback = False
                    port = None
                if parsed.scheme == "http" and loopback and port:
                    self._ready_url = listen
                    self._ready.set()
        else:
            text = safe_text(line.decode("utf-8", errors="replace"), 300)
            if text:
                self._stderr_tail.append(text)
                del self._stderr_tail[:-8]
        if self.line_callback is not None:
            try:
                self.line_callback(name, line)
            except Exception:
                # Presentation callbacks never own child lifecycle or status.
                pass

    def wait_ready(self, timeout: float) -> str:
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            if self._ready.wait(timeout=min(0.05, max(0.0, deadline - time.monotonic()))):
                assert self._ready_url is not None
                return self._ready_url
            returncode = self.process.poll()
            if returncode is not None:
                detail = self._stderr_tail[-1] if self._stderr_tail else "no diagnostic"
                raise PlaygroundError(
                    "agent exited before readiness with status %d: %s"
                    % (returncode, safe_text(detail, 200))
                )
        raise PlaygroundError("agent did not become ready before the startup deadline")

    def poll(self) -> Optional[int]:
        return self.process.poll()

    def stop(self, graceful_seconds: float = 4.0) -> int:
        try:
            return stop_subprocess(self.process, graceful_seconds)
        finally:
            self.close_streams()

    def force_stop(self) -> int:
        """Last-resort group kill after an ordinary bounded stop failed."""

        try:
            _signal_process_group(self.process, signal.SIGKILL)
            if not _wait_process_group_gone(self.process, 2.0):
                raise PlaygroundError("child process group resisted forced cleanup")
            returncode = self.process.poll()
            if returncode is None:
                returncode = self.process.wait(timeout=0.2)
            return returncode
        finally:
            self.close_streams()

    def close_streams(self) -> None:
        if self._closed:
            return
        self._closed = True
        for thread in self._threads:
            thread.join(timeout=2.0)
        self._stdout_file.close()
        self._stderr_file.close()


class ConnectJsonClient:
    """Small stdlib Connect JSON client for the existing loopback agent."""

    def __init__(self, base_url: str, token: str, timeout: float = 3.0) -> None:
        parsed = urlparse(base_url)
        try:
            loopback = parsed.hostname is not None and ipaddress.ip_address(parsed.hostname).is_loopback
            port = parsed.port
        except ValueError as error:
            raise PlaygroundError("agent returned a malformed application URL") from error
        if (
            parsed.scheme != "http"
            or not loopback
            or port is None
            or parsed.username is not None
            or parsed.password is not None
            or parsed.query
            or parsed.fragment
        ):
            raise PlaygroundError("agent returned a non-loopback application URL")
        self.host = parsed.hostname
        self.port = port
        self.base_path = parsed.path.rstrip("/")
        self.token = token
        self.timeout = timeout

    def call(self, method: str, payload: Mapping[str, object]) -> Dict[str, object]:
        if not re.fullmatch(r"[A-Za-z][A-Za-z0-9]*", method):
            raise RpcError("invalid local application method")
        body = json.dumps(payload, ensure_ascii=True, separators=(",", ":")).encode("utf-8")
        path = "%s/%s/%s" % (self.base_path, SERVICE, method)
        connection = http.client.HTTPConnection(self.host, self.port, timeout=self.timeout)
        try:
            connection.request(
                "POST",
                path,
                body=body,
                headers={
                "Authorization": "Bearer " + self.token,
                "Content-Type": "application/json",
                },
            )
            response = connection.getresponse()
            data = response.read(MAX_RPC_RESPONSE_BYTES + 1)
            status = response.status
        except (OSError, TimeoutError, http.client.HTTPException) as error:
            raise RpcError("local application request %s is unavailable" % method) from error
        finally:
            connection.close()
        if status < 200 or status >= 300:
            raise RpcError(
                "local application request %s failed with HTTP %d" % (method, status)
            )
        if len(data) > MAX_RPC_RESPONSE_BYTES:
            raise RpcError("local application response exceeds the playground bound")
        try:
            decoded = json.loads(data.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as error:
            raise RpcError("local application response is malformed") from error
        if not isinstance(decoded, dict):
            raise RpcError("local application response is not an object")
        return decoded

    def get_status(self) -> Dict[str, object]:
        return self.call("GetStatus", {})

    def create_subscription(self, operation_key: bytes) -> Dict[str, object]:
        return self.call(
            "CreateEventSubscription",
            {
                "operationKey": encode_b64(operation_key),
                "topic": TOPIC,
                "scope": SCOPE,
                "includeDescendantScopes": False,
            },
        )

    def query_events(self, after_marker: int) -> Tuple[List[Dict[str, object]], int]:
        events: List[Dict[str, object]] = []
        marker = after_marker
        for _ in range(MAX_QUERY_PAGES):
            response = self.call(
                "QueryEvents",
                {
                    "topic": TOPIC,
                    "scope": SCOPE,
                    "includeDescendantScopes": False,
                    "afterAcceptanceMarker": str(marker),
                    "limit": QUERY_PAGE_LIMIT,
                },
            )
            page = response.get("events", [])
            if not isinstance(page, list) or not all(isinstance(item, dict) for item in page):
                raise RpcError("QueryEvents returned a malformed Event page")
            try:
                scanned = int(response.get("scannedThrough", marker))
            except (TypeError, ValueError) as error:
                raise RpcError("QueryEvents returned a malformed scan marker") from error
            if scanned < marker:
                raise RpcError("QueryEvents scan marker moved backward")
            events.extend(page)
            marker = scanned
            if not response.get("hasMore", False):
                return events, marker
            if not page and scanned == after_marker:
                raise RpcError("QueryEvents pagination made no progress")
            after_marker = marker
        raise RpcError("QueryEvents exceeded the playground page bound")


class NumberedPublisher:
    """Application publisher using the same durable journal as asterctl.

    The controller owns one stable identity per node. It applies recovered
    results using their original journaled payload before acknowledging them.
    No transport error silently consumes a sequence or changes the intent.
    """

    def __init__(self, cli: Path, journal: Path, client_id: str) -> None:
        self.cli = cli
        self.journal = journal
        self.client_id = client_id
        self.host: Optional[str] = None
        self.port: Optional[int] = None
        self.token_path: Optional[Path] = None

    def initialize(self) -> None:
        self._run("publication-init", local=True)

    def connect(self, url: str, token_path: Path) -> None:
        parsed = urlparse(url)
        if parsed.scheme != "http" or not parsed.hostname or not parsed.port:
            raise RpcError("numbered publisher requires an explicit loopback agent URL")
        try:
            if not ipaddress.ip_address(parsed.hostname).is_loopback:
                raise ValueError("non-loopback host")
        except ValueError as error:
            raise RpcError("numbered publisher requires a loopback agent") from error
        self.host, self.port, self.token_path = parsed.hostname, parsed.port, token_path

    def _run(
        self, action: str, options: Sequence[str] = (), payload: Optional[bytes] = None,
        *, local: bool = False, json_response: bool = False,
    ) -> Any:
        command = [str(self.cli)]
        if not local:
            if self.host is None or self.port is None or self.token_path is None:
                raise RpcError("numbered publisher is not connected")
            command += ["--token-file", str(self.token_path), "--host", self.host,
                        "--port", str(self.port), "--timeout", "10", "--json"]
        command += [action, "--journal", str(self.journal), "--client-id", self.client_id]
        command += list(options)
        try:
            result = subprocess.run(
                command, input=payload, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                timeout=35, check=False,
            )
        except (OSError, subprocess.TimeoutExpired) as error:
            raise RpcError("numbered publication interrupted; original journal retained") from error
        if result.returncode != 0:
            detail = safe_text(result.stderr.decode("utf-8", errors="replace"), 400)
            raise RpcError("numbered publication failed; journal retained: %s" % detail)
        if len(result.stdout) > MAX_RPC_RESPONSE_BYTES:
            raise RpcError("numbered publication response exceeded the playground bound")
        if not json_response:
            return None
        try:
            value = json.loads(result.stdout)
        except (ValueError, UnicodeError) as error:
            raise RpcError("numbered publication returned malformed JSON") from error
        if not isinstance(value, dict):
            raise RpcError("numbered publication returned a malformed result")
        return value

    def recover(self, apply: Callable[[Mapping[str, Any], Mapping[str, Any], bool, Optional[bool]], str]) -> None:
        report = self._run("publication-recover", json_response=True)
        operations = report.get("operations", [])
        if not isinstance(operations, list) or len(operations) > MAX_TRACKED_MESSAGES:
            raise RpcError("numbered recovery exceeded the playground operation bound")
        for operation in operations:
            if not isinstance(operation, dict):
                raise RpcError("numbered recovery returned a malformed operation")
            sequence = operation.get("operationSequence")
            try:
                if int(sequence) < 1:
                    raise ValueError("non-positive sequence")
            except (TypeError, ValueError) as error:
                raise RpcError("numbered recovery returned an invalid sequence") from error
            state = operation.get("state")
            if state == "retired":
                continue
            intent = self._run("publication-show", ["--sequence", str(sequence)], json_response=True)
            if state == "pending":
                result = self._run("publication-retry", ["--sequence", str(sequence)], json_response=True)
            elif state == "committed" and isinstance(operation.get("result"), dict):
                result = operation["result"]
            else:
                raise RpcError("numbered recovery returned an invalid operation state")
            apply(intent, result, True, None)
            self._run("publication-ack", ["--sequence", str(sequence)])

    def publish(
        self, logical_key: bytes, payload: bytes,
        apply: Callable[[Mapping[str, Any], Mapping[str, Any], bool, Optional[bool]], str],
    ) -> str:
        self.recover(apply)
        response = self._run(
            "publish", ["--topic", TOPIC, "--scope", SCOPE,
                        "--logical-key", logical_key.decode("ascii")],
            payload, json_response=True,
        )
        result = response.get("result")
        inserted = response.get("inserted")
        if not isinstance(result, dict) or not isinstance(inserted, bool):
            raise RpcError("numbered publisher returned a malformed outcome")
        alias = apply({"payload": encode_b64(payload)}, result, False, inserted)
        sequence = result.get("operationSequence")
        if not isinstance(sequence, str) or not sequence.isdigit() or int(sequence) < 1:
            raise RpcError("numbered publisher returned an invalid sequence")
        self._run("publication-ack", ["--sequence", sequence])
        return alias


@dataclass
class EventRecord:
    alias: str
    event_id: str
    payload: bytes
    text: str
    publisher: str = ""
    publisher_node: Optional[int] = None
    event_sequence: Optional[int] = None
    seen: Set[int] = field(default_factory=set)
    published_at: float = field(default_factory=time.monotonic)


@dataclass
class NodeState:
    init: InitNode
    state: Path
    mission_bundle: Path
    token_path: Path
    token: str
    mesh_port: int
    name: str = ""
    activated: bool = True
    desired_online: bool = True
    status: str = "new"
    generation: int = 0
    process: Optional[ManagedProcess] = None
    client: Optional[ConnectJsonClient] = None
    publisher: Optional[NumberedPublisher] = None
    agent_url: Optional[str] = None
    pid: Optional[int] = None
    query_marker: int = 0
    sync: str = "unknown"
    authenticated_contacts: int = 0
    failed_contacts: int = 0
    peers: List[Dict[str, object]] = field(default_factory=list)
    seen: Set[str] = field(default_factory=set)
    observer: str = "pending"
    observer_error: str = ""
    error: str = ""
    last_status_key: Tuple[object, ...] = field(default_factory=tuple)


@dataclass(frozen=True)
class NodePollResult:
    sync: str
    contacts: int
    failures: int
    peers: Tuple[Dict[str, object], ...]
    events: Tuple[Dict[str, object], ...]
    marker: int


class EventSink:
    """Retained JSON journal plus raw/plain live presentation."""

    def __init__(
        self,
        root: Path,
        mode: str,
        stdout: TextIO = sys.stdout,
        stderr: TextIO = sys.stderr,
    ) -> None:
        self.root = root
        self.mode = mode
        self.stdout = stdout
        self.stderr = stderr
        self.unicode = supports_unicode(stdout)
        self.lock = threading.Lock()
        self.node_names: Dict[int, str] = {}
        journal_path = root / "logs" / "controller.jsonl"
        journal_path.parent.mkdir(parents=True, exist_ok=True)
        self.journal = RotatingByteLog(journal_path)

    def close(self) -> None:
        with self.lock:
            if not self.journal.closed:
                self.journal.close()

    def set_mode(self, mode: str) -> None:
        if mode not in {"tui", "plain", "raw"}:
            raise PlaygroundError("invalid presentation mode")
        with self.lock:
            self.mode = mode

    def set_node_names(self, names: Mapping[int, str]) -> None:
        """Install bounded presentation-only labels before live output starts."""

        cleaned: Dict[int, str] = {}
        for index, name in names.items():
            if not isinstance(index, int) or not 0 <= index < MAX_NODES:
                raise PlaygroundError("friendly node-name index is outside the playground bound")
            if name not in HELLO_NODE_NAMES:
                raise PlaygroundError("friendly node name is outside the built-in bounded roster")
            cleaned[index] = name
        with self.lock:
            self.node_names = cleaned

    def _node_label(self, record: Mapping[str, object]) -> str:
        try:
            index = int(record.get("node", -1))
        except (TypeError, ValueError):
            return "unknown"
        return self.node_names.get(index, "n%d" % index)

    def emit(self, event_type: str, **fields: object) -> None:
        record: Dict[str, object] = {
            "type": event_type,
            "elapsedMs": int(fields.pop("elapsed_ms", 0)),
        }
        record.update(fields)
        serialized = json.dumps(record, ensure_ascii=True, sort_keys=True, separators=(",", ":"))
        with self.lock:
            self.journal.write_record((serialized + "\n").encode("utf-8"))
            if self.mode == "raw":
                self.stdout.write(serialized + "\n")
                self.stdout.flush()
            elif self.mode == "plain":
                line = self._plain(record)
                if line:
                    self.stdout.write(terminal_text(line, self.unicode) + "\n")
                    self.stdout.flush()

    def _plain(self, record: Mapping[str, object]) -> str:
        kind = record.get("type")
        if kind == "boundary":
            return "  BOUNDED %s" % safe_text(record.get("text", ""), 180)
        if kind == "root":
            return "  ROOT %s" % safe_text(record.get("path", ""), 240)
        if kind == "network":
            if record.get("mode") == "nearby":
                return (
                    "  ROUTE nearby window=%ss fallback=none "
                    "metadata=carrier-id+direct-address"
                    % safe_text(record.get("windowSeconds", "?"))
                )
            if record.get("mode") == "invitation":
                return "  ROUTE invitation controller-known-loopback fallback=none"
            return ""
        if kind == "node":
            detail = ""
            if record.get("pid") is not None:
                detail += " pid=%s" % safe_text(record.get("pid"))
            if record.get("reason"):
                detail += " reason=%s" % safe_text(record.get("reason"), 100)
            return "  NODE %s %s%s" % (
                self._node_label(record),
                safe_text(record.get("status")),
                detail,
            )
        if kind == "topology":
            return "  TOPOLOGY %s %s" % (
                self._node_label(record),
                safe_text(record.get("status")),
            )
        if kind == "message_published":
            return "  MESSAGE %s published-by=%s text=%s" % (
                safe_text(record.get("message")),
                self._node_label(record),
                safe_text(record.get("text"), 120),
            )
        if kind == "message_seen":
            return "  SEEN %s node=%s exact-event=true" % (
                safe_text(record.get("message")),
                self._node_label(record),
            )
        if kind == "status":
            return "  STATUS %s process=%s observer=%s sync=%s contacts=%s failures=%s seen=%s" % (
                self._node_label(record),
                safe_text(record.get("process")),
                safe_text(record.get("observer", "unknown")),
                safe_text(record.get("sync")),
                safe_text(record.get("authenticatedContacts", "0")),
                safe_text(record.get("failedContactAttempts", "0")),
                safe_text(record.get("seen")),
            )
        if kind == "observer":
            if record.get("status") == "healthy":
                return "  OBSERVER %s healthy" % self._node_label(record)
            return "  OBSERVER %s error=%s" % (
                self._node_label(record),
                safe_text(record.get("error", "unavailable"), 180),
            )
        if kind == "wait":
            return "  WAIT %s status=%s" % (
                safe_text(record.get("message", "events")),
                safe_text(record.get("status")),
            )
        if kind == "assert_unseen":
            return "  ASSERT-UNSEEN %s status=%s nodes=%s exact-query=true snapshot-only=true" % (
                safe_text(record.get("message")),
                safe_text(record.get("status")),
                ",".join(str(node) for node in record.get("nodes", [])),
            )
        if kind == "info":
            return "  INFO %s" % safe_text(record.get("text", ""), 240)
        if kind in {"error", "fatal"}:
            return "  ERROR %s" % safe_text(record.get("error", ""), 240)
        if kind == "finished":
            return "  FINISHED status=%s root=%s" % (
                safe_text(record.get("status")),
                safe_text(record.get("root"), 200),
            )
        return ""


class PlaygroundController:
    def __init__(
        self,
        init: InitResult,
        agent: Path,
        sink: EventSink,
        startup_timeout: float = DEFAULT_STARTUP_SECONDS,
        poll_seconds: float = DEFAULT_POLL_SECONDS,
        process_factory: Callable[..., ManagedProcess] = ManagedProcess,
        client_factory: Callable[[str, str], ConnectJsonClient] = ConnectJsonClient,
        port_reservations: Optional[List[socket.socket]] = None,
        cli: Optional[Path] = None,
        publisher_factory: Callable[[Path, Path, str], NumberedPublisher] = NumberedPublisher,
        hello: bool = False,
        network_provenance: str = "direct",
        nearby_window_seconds: int = HELLO_NEARBY_WINDOW_SECONDS,
    ) -> None:
        self.root = init.root
        self.agent = agent
        self.sink = sink
        self.topology = Topology(len(init.nodes))
        self.startup_timeout = startup_timeout
        self.poll_seconds = poll_seconds
        self.process_factory = process_factory
        self.client_factory = client_factory
        self.cli = cli or agent.with_name("asterctl")
        self.publisher_factory = publisher_factory
        self.hello = hello
        self.network_provenance = network_provenance
        self.nearby_window_seconds = nearby_window_seconds
        self.selected_index: Optional[int] = None
        if self.hello and self.network_provenance not in {"nearby", "invitation"}:
            raise PlaygroundError("hello mode requires an explicit nearby or invitation route source")
        if not self.hello and self.network_provenance != "direct":
            raise PlaygroundError("network provenance selection is available only in hello mode")
        if (
            self.network_provenance == "nearby"
            and not 1 <= self.nearby_window_seconds <= 30
        ):
            raise PlaygroundError("nearby discovery window must be within 1..30 seconds")
        self._lock = threading.RLock()
        self._closed = False
        self._closing = False
        self.had_process_failure = False
        self.had_fatal_failure = False
        self._poll_stop = threading.Event()
        self._poll_thread: Optional[threading.Thread] = None
        self.progress_callback: Optional[Callable[[], None]] = None
        self._message_counter = 0
        self._operation_counter = 0
        self.events: Dict[str, EventRecord] = {}
        self.aliases: Dict[str, str] = {}
        self.last_alias: Optional[str] = None
        reservations = port_reservations or reserve_udp_ports(len(init.nodes))
        if len(reservations) != len(init.nodes):
            raise PlaygroundError("port reservation count differs from node count")
        self._reservations: List[Optional[socket.socket]] = list(reservations)
        self.nodes: List[NodeState] = []
        try:
            os.chmod(self.root, 0o700)
            for item, reservation in zip(init.nodes, reservations):
                state = self.root / ("node-%d" % item.index)
                mission = state / "mission.unprotected-reference.bundle"
                if not state.is_dir() or not mission.is_file():
                    raise PlaygroundError("initializer omitted node-%d state or mission bundle" % item.index)
                os.chmod(state, 0o700)
                token_path = state / "playground.client.token"
                token = secrets.token_hex(32)
                _write_exclusive(token_path, token.encode("ascii"), 0o600)
                port = int(reservation.getsockname()[1])
                name = HELLO_NODE_NAMES[item.index] if self.hello else ""
                publisher = self.publisher_factory(self.cli, state / "publication.redb", "aster-playground/node-%d/v1" % item.index)
                publisher.initialize()
                self.nodes.append(
                    NodeState(
                        item,
                        state,
                        mission,
                        token_path,
                        token,
                        port,
                        name=name,
                        publisher=publisher,
                        activated=not self.hello,
                        desired_online=not self.hello,
                        status="available" if self.hello else "new",
                    )
                )
            if self.hello:
                self.sink.set_node_names(
                    {node.init.index: node.name for node in self.nodes}
                )
        except BaseException:
            self._close_reservations()
            raise

    def _progress(self) -> None:
        callback = self.progress_callback
        if callback is not None:
            try:
                callback()
            except Exception:
                # Presentation must never own process or durable state.
                pass

    def _close_reservations(self) -> None:
        for index, reservation in enumerate(self._reservations):
            if reservation is not None:
                try:
                    reservation.close()
                except OSError:
                    pass
                self._reservations[index] = None

    def start(self) -> None:
        self.sink.emit("root", path=str(self.root))
        self.sink.emit("boundary", text=BOUNDARY)
        if self.hello:
            self.sink.emit(
                "network",
                mode=self.network_provenance,
                windowSeconds=(
                    self.nearby_window_seconds
                    if self.network_provenance == "nearby"
                    else 0
                ),
                fallback="none",
            )
        with self._lock:
            spawned: List[int] = []
            try:
                if not self.hello:
                    for index in range(len(self.nodes)):
                        self._spawn_node(index)
                        spawned.append(index)
                for index in spawned:
                    self._finish_node_start(index)
            except BaseException as error:
                self._close_reservations()
                try:
                    self._stop_indexes(reversed(spawned), reason="startup-failure", desired=False)
                except Exception as cleanup_error:
                    self.sink.emit(
                        "error",
                        error="startup cleanup failed: %s" % safe_text(cleanup_error, 180),
                    )
                    if not isinstance(error, (KeyboardInterrupt, SystemExit)):
                        raise PlaygroundError("playground startup and cleanup failed") from error
                raise
            if not self.hello:
                self._close_reservations()
        self._poll_thread = threading.Thread(
            target=self._poll_loop,
            name="aster-playground-poller",
            daemon=True,
        )
        self._poll_thread.start()

    def _node_command(self, index: int) -> List[str]:
        node = self.nodes[index]
        command = [
            str(self.agent),
            "--state",
            str(node.state),
            "--mesh-bind",
            "127.0.0.1:%d" % node.mesh_port,
            "--listen",
            "127.0.0.1:0",
            "--mission-bundle-unprotected-reference",
            str(node.mission_bundle),
            "--client-token-file",
            str(node.token_path),
            "--sync-ms",
            str(HELLO_SYNC_MILLISECONDS if self.hello else 200),
        ]
        neighbors = sorted(self.topology.neighbors(index))
        for neighbor_index in neighbors:
            neighbor = self.nodes[neighbor_index]
            if self.network_provenance == "nearby":
                peer = "%s=%s" % (
                    neighbor.init.carrier_id,
                    neighbor.init.mission_id,
                )
                command.extend(["--nearby-peer", peer])
            else:
                peer = "%s@127.0.0.1:%d=%s" % (
                    neighbor.init.carrier_id,
                    neighbor.mesh_port,
                    neighbor.init.mission_id,
                )
                command.extend(["--peer", peer])
        if self.network_provenance == "nearby" and neighbors:
            command.extend(["--nearby-window", str(self.nearby_window_seconds)])
        return command

    def _spawn_node(self, index: int) -> None:
        node = self.nodes[index]
        if node.process is not None:
            raise PlaygroundError("node %d already owns a process" % index)
        reservation = self._reservations[index]
        if reservation is not None:
            reservation.close()
            self._reservations[index] = None
        node.generation += 1
        node.status = "starting"
        node.error = ""
        node.observer = "pending"
        node.observer_error = ""
        log_root = self.root / "logs" / ("node-%d" % index)
        # One bounded rotating set per node keeps long CONTACT-heavy sessions
        # inspectable without allowing retained child output to grow forever.
        stdout_path = log_root / "agent.stdout"
        stderr_path = log_root / "agent.stderr"
        try:
            process = self.process_factory(
                self._node_command(index),
                stdout_path,
                stderr_path,
            )
        except OSError as error:
            node.status = "failed"
            node.error = "could not start agent process"
            self.had_process_failure = True
            raise PlaygroundError("could not start agent process for node %d" % index) from error
        node.process = process
        node.pid = process.pid
        self.sink.emit("node", node=index, status="starting", pid=node.pid)
        self._progress()

    def _finish_node_start(self, index: int) -> None:
        node = self.nodes[index]
        if node.process is None:
            raise PlaygroundError("node %d process disappeared during startup" % index)
        try:
            url = node.process.wait_ready(self.startup_timeout)
            client = self.client_factory(url, node.token)
            response = client.create_subscription(
                ("aster-playground/subscription/node-%d/v1" % index).encode("ascii")
            )
            subscription = decode_b64(response.get("subscriptionId"), "subscription ID", 32)
            if not subscription:
                raise PlaygroundError("agent returned an empty subscription identity")
            if node.publisher is None:
                raise PlaygroundError("node has no numbered publication journal")
            node.publisher.connect(url, node.token_path)
        except BaseException as error:
            interrupted = isinstance(error, (KeyboardInterrupt, SystemExit))
            node.status = "stopping" if interrupted else "failed"
            node.error = "" if interrupted else safe_text(error, 200)
            if not interrupted:
                self.had_process_failure = True
            cleanup_error: Optional[Exception] = None
            reaped = False
            try:
                node.process.stop()
                reaped = True
            except Exception as stop_error:
                cleanup_error = stop_error
                try:
                    force_stop = getattr(node.process, "force_stop", None)
                    if force_stop is None:
                        raise stop_error
                    force_stop()
                    cleanup_error = None
                    reaped = True
                except Exception as force_error:
                    cleanup_error = force_error
            node.client = None
            node.agent_url = None
            if reaped:
                node.process = None
                node.pid = None
            if interrupted:
                node.status = "stopped" if reaped else "failed"
                if cleanup_error is not None:
                    node.error = "startup interruption cleanup failed"
                    self.sink.emit(
                        "error",
                        error="node %d startup interruption cleanup failed" % index,
                    )
                raise
            if cleanup_error is not None:
                node.error = "%s; process cleanup also failed" % node.error
            raise PlaygroundError("node %d failed during application startup: %s" % (index, node.error)) from error
        node.agent_url = url
        node.client = client
        node.status = "ready"
        node.error = ""
        self.sink.emit(
            "node",
            node=index,
            status="ready",
            pid=node.pid,
            peers=sorted(self.topology.neighbors(index)),
        )
        try:
            node.publisher.recover(lambda intent, result, recovered, inserted: self._apply_publication(index, intent, result, recovered, inserted))
        except PlaygroundError as error:
            # A blocked application publication must not stop the node's
            # receive/carry or query capabilities. A later send retries the
            # original journaled operation before allocating new work.
            self.sink.emit("error", node=index, error="publication recovery pending: %s" % safe_text(error, 240))
        self._progress()

    def _poll_loop(self) -> None:
        while not self._poll_stop.wait(self.poll_seconds):
            try:
                self.poll_once()
            except Exception as error:
                if not self._closing:
                    self.sink.emit("error", error="polling failed: %s" % safe_text(error, 180))

    def poll_once(self) -> None:
        exited = []
        requests = []
        with self._lock:
            for index, node in enumerate(self.nodes):
                process = node.process
                if process is not None:
                    returncode = process.poll()
                    if returncode is not None:
                        exited.append((index, node.generation, process, returncode))
                        continue
                if node.status != "ready" or node.client is None:
                    continue
                requests.append(
                    (index, node.generation, node.client, node.query_marker)
                )

        # Process-group sweep and application I/O are intentionally outside the
        # controller lock.  Snapshot/status/TUI and cleanup stay responsive if
        # a local agent stalls or returns many bounded pages.
        for index, generation, process, returncode in exited:
            cleanup_error: Optional[Exception] = None
            try:
                force_stop = getattr(process, "force_stop", None)
                if force_stop is not None:
                    force_stop()
                else:
                    process.close_streams()
            except Exception as error:
                cleanup_error = error
            with self._lock:
                node = self.nodes[index]
                if node.generation != generation or node.process is not process:
                    continue
                node.client = None
                node.agent_url = None
                if cleanup_error is None:
                    node.process = None
                    node.pid = None
                if node.desired_online:
                    node.status = "failed"
                    node.error = "agent exited unexpectedly with status %d" % returncode
                    if cleanup_error is not None:
                        node.error += "; descendant cleanup failed"
                    self.had_process_failure = True
                    self.sink.emit(
                        "node",
                        node=index,
                        status="failed",
                        reason=node.error,
                    )
                else:
                    node.status = "stopped" if cleanup_error is None else "failed"

        for index, generation, client, marker in requests:
            try:
                result = self._fetch_node(client, marker)
            except (RpcError, PlaygroundError, TypeError, ValueError) as error:
                detail = safe_text(error, 180)
                with self._lock:
                    node = self.nodes[index]
                    if node.generation != generation or node.client is not client:
                        continue
                    changed = node.observer != "error" or node.observer_error != detail
                    node.observer = "error"
                    node.observer_error = detail
                    node.error = detail
                    if not isinstance(error, RpcError):
                        self.had_fatal_failure = True
                    if changed:
                        self.sink.emit(
                            "observer",
                            node=index,
                            status="error",
                            error=detail,
                        )
                continue
            with self._lock:
                node = self.nodes[index]
                if node.generation != generation or node.client is not client:
                    continue
                recovered = node.observer == "error"
                node.sync = result.sync
                node.authenticated_contacts = result.contacts
                node.failed_contacts = result.failures
                node.peers = list(result.peers)
                try:
                    for event in result.events:
                        self._observe_event(index, event)
                except (RpcError, PlaygroundError, TypeError, ValueError) as error:
                    detail = safe_text(error, 180)
                    node.observer = "error"
                    node.observer_error = detail
                    node.error = detail
                    if not isinstance(error, RpcError):
                        self.had_fatal_failure = True
                    self.sink.emit(
                        "observer",
                        node=index,
                        status="error",
                        error=detail,
                    )
                    continue
                node.query_marker = result.marker
                node.observer = "healthy"
                node.observer_error = ""
                node.error = ""
                if recovered:
                    self.sink.emit("observer", node=index, status="healthy")
                # Authenticated contact count grows on every healthy sync
                # interval; it remains available through explicit status but
                # does not flood progressive plain output.
                status_key = (
                    node.status,
                    result.sync,
                    result.failures,
                    len(node.seen),
                )
                if status_key != node.last_status_key:
                    node.last_status_key = status_key
                    self.sink.emit(
                        "status",
                        node=index,
                        process=node.status,
                        sync=sync_label(result.sync),
                        authenticatedContacts=result.contacts,
                        failedContactAttempts=result.failures,
                        seen=len(node.seen),
                        observer=node.observer,
                    )

    @staticmethod
    def _fetch_node(client: ConnectJsonClient, marker: int) -> NodePollResult:
        try:
            status = client.get_status()
            sync = str(status.get("sync", "SYNC_STATUS_UNSPECIFIED"))
            contacts = int(status.get("authenticatedContacts", "0"))
            failures = int(status.get("failedContactAttempts", "0"))
            peers = status.get("peers", [])
            if not isinstance(peers, list):
                raise RpcError("GetStatus returned malformed peers")
            events, next_marker = client.query_events(marker)
            return NodePollResult(
                sync=sync,
                contacts=contacts,
                failures=failures,
                peers=tuple(peer for peer in peers if isinstance(peer, dict)),
                events=tuple(events),
                marker=next_marker,
            )
        except (RpcError, PlaygroundError, TypeError, ValueError):
            raise

    def _observe_event(self, index: int, event: Mapping[str, object]) -> None:
        if event.get("topic") != TOPIC or event.get("scope") != SCOPE:
            raise PlaygroundError("application query crossed the playground selector")
        event_bytes = decode_b64(event.get("id"), "Event ID", 32)
        payload = decode_b64(event.get("payload"), "Event payload")
        if len(payload) > MAX_MESSAGE_BYTES:
            raise PlaygroundError("observed playground Event payload exceeds the 4096-byte bound")
        event_id = event_bytes.hex()
        publisher_bytes = decode_b64(event.get("publisher"), "publisher", 32)
        publisher = publisher_bytes.hex()
        try:
            sequence = int(event.get("eventSequence", "0"))
        except (TypeError, ValueError) as error:
            raise PlaygroundError("Event sequence is malformed") from error
        record = self.events.get(event_id)
        if record is None:
            if len(self.events) >= MAX_TRACKED_MESSAGES:
                raise PlaygroundError(
                    "tracked Event limit reached; start a fresh playground for more messages"
                )
            alias = self._new_alias(event_id)
            record = EventRecord(
                alias=alias,
                event_id=event_id,
                payload=payload,
                text=payload.decode("utf-8", errors="replace"),
                publisher=publisher,
                publisher_node=self._publisher_node(publisher),
                event_sequence=sequence,
            )
            self.events[event_id] = record
        elif record.payload != payload or (record.publisher and record.publisher != publisher):
            raise PlaygroundError("one Event identity resolved to inconsistent application content")
        record.publisher = publisher
        record.publisher_node = self._publisher_node(publisher)
        record.event_sequence = sequence
        if index not in record.seen:
            record.seen.add(index)
            self.nodes[index].seen.add(event_id)
            self.sink.emit(
                "message_seen",
                message=record.alias,
                eventId=event_id,
                node=index,
                exactEvent=True,
            )

    def _publisher_node(self, publisher: str) -> Optional[int]:
        for node in self.nodes:
            if node.init.mission_id == publisher:
                return node.init.index
        return None

    def _new_alias(self, event_id: str) -> str:
        existing = self.events.get(event_id)
        if existing is not None:
            return existing.alias
        self._message_counter += 1
        alias = "m%d" % self._message_counter
        self.aliases[alias] = event_id
        self.last_alias = alias
        return alias

    def node_label(self, index: int) -> str:
        self.topology.validate(index)
        name = self.nodes[index].name
        return name if name else "n%d" % index

    def resolve_node(self, value: str) -> int:
        normalized = value.strip().lower()
        if not normalized:
            raise PlaygroundError("node name or index must not be empty")
        if normalized.startswith("n") and normalized[1:].isdigit():
            normalized = normalized[1:]
        if normalized.isdigit():
            index = int(normalized)
            self.topology.validate(index)
            return index
        for node in self.nodes:
            if node.name == normalized:
                return node.init.index
        if self.hello:
            available = ", ".join(node.name for node in self.nodes)
            raise PlaygroundError(
                "unknown field node %s; choose one of: %s"
                % (safe_text(value, 32), available)
            )
        raise PlaygroundError("node index must be an integer")

    def select_node(self, index: int) -> None:
        with self._lock:
            self.topology.validate(index)
            node = self.nodes[index]
            if self.hello and not node.activated:
                raise PlaygroundError("add %s before selecting it" % node.name)
            self.selected_index = index

    def add_node(self, index: int) -> None:
        """Activate one pre-provisioned hello-roster slot."""

        with self._lock:
            if not self.hello:
                raise PlaygroundError("add is available only in hello mode")
            self.topology.validate(index)
            node = self.nodes[index]
            if node.activated:
                raise PlaygroundError("%s has already joined the field notebook" % node.name)
            node.activated = True
            node.desired_online = True
            node.status = "stopped"

            restart = []
            if self.network_provenance == "nearby":
                restart = [
                    candidate
                    for candidate, peer in enumerate(self.nodes)
                    if candidate != index
                    and peer.activated
                    and peer.desired_online
                    and peer.process is not None
                ]
                # Nearby locator publication and lookup are both short-lived.
                # Restart the small activated roster so every line edge gets
                # an overlapping explicit window; this never switches to an
                # invitation route when multicast is unavailable.
                if restart:
                    self._stop_indexes(
                        restart,
                        reason="opening-nearby-window",
                        desired=True,
                    )

            started: List[int] = []
            try:
                for item in restart + [index]:
                    self._spawn_node(item)
                    started.append(item)
                for item in started:
                    self._finish_node_start(item)
            except BaseException:
                self.had_process_failure = True
                self._stop_indexes(
                    reversed(started),
                    reason="hello-add-failure",
                    desired=False,
                )
                raise
            self.selected_index = index
            self.sink.emit(
                "info",
                text=(
                    "%s joined through %s; route fallback remains disabled."
                    % (node.name, self.network_provenance)
                ),
            )

    def send(self, index: int, text: str) -> str:
        payload = text.encode("utf-8")
        if not payload:
            raise PlaygroundError("message text must not be empty")
        if len(payload) > MAX_MESSAGE_BYTES:
            raise PlaygroundError("message text exceeds the 4096-byte playground bound")
        with self._lock:
            self.topology.validate(index)
            node = self.nodes[index]
            if node.status != "ready" or node.client is None:
                raise PlaygroundError("node %d is not ready to publish" % index)
            if self._operation_counter >= MAX_TRACKED_MESSAGES:
                raise PlaygroundError(
                    "the playground message-attempt limit (%d) has been reached"
                    % MAX_TRACKED_MESSAGES
                )
            self._operation_counter += 1
            logical_key = ("playground-message-%d" % self._operation_counter).encode("ascii")
            if node.publisher is None:
                raise PlaygroundError("node has no numbered publisher")
            return node.publisher.publish(logical_key, payload, lambda intent, result, recovered, inserted: self._apply_publication(index, intent, result, recovered, inserted))

    def _apply_publication(
        self, index: int, intent: Mapping[str, Any], result: Mapping[str, Any], recovered: bool, inserted: Optional[bool],
    ) -> str:
        payload = decode_b64(intent.get("payload"), "journaled publication payload")
        if not payload or len(payload) > MAX_MESSAGE_BYTES:
            raise PlaygroundError("recovered payload violates the playground message bound")
        try:
            text = payload.decode("utf-8")
        except UnicodeError as error:
            raise PlaygroundError("recovered message is not UTF-8") from error
        receipt = result.get("receipt")
        if not isinstance(receipt, dict):
            raise PlaygroundError("numbered publication omitted its receipt")
        event_id = decode_b64(receipt.get("eventId"), "published Event ID", 32).hex()
        alias = self._new_alias(event_id)
        record = self.events.get(event_id)
        if record is None:
            record = EventRecord(alias=alias, event_id=event_id, payload=payload, text=text, publisher_node=index)
            self.events[event_id] = record
        elif record.payload != payload:
            raise PlaygroundError("publish response reused an Event identity with different content")
        record.publisher_node = index
        fields = {"message": alias, "eventId": event_id, "node": index,
                  "recovered": recovered, "text": safe_text(text, 240)}
        if inserted is not None:
            fields["inserted"] = inserted
        self.sink.emit("message_published", **fields)
        return alias

    def isolate(self, index: int) -> None:
        with self._lock:
            affected = self.topology.isolate(index)
            if not affected:
                self.sink.emit("info", text="node %d is already isolated" % index)
                return
            self.sink.emit("topology", node=index, status="isolated", affected=sorted(affected))
            self._progress()
            self._restart_affected(affected, "isolate")

    def rejoin(self, index: int) -> None:
        with self._lock:
            affected = self.topology.rejoin(index)
            if not affected:
                self.sink.emit("info", text="node %d is already joined" % index)
                return
            self.sink.emit("topology", node=index, status="joined", affected=sorted(affected))
            self._progress()
            self._restart_affected(affected, "rejoin")

    def _restart_affected(self, affected: Iterable[int], reason: str) -> None:
        indexes = sorted(set(affected))
        restart = [index for index in indexes if self.nodes[index].desired_online]
        self._stop_indexes(restart, reason="reconfiguring-%s" % reason, desired=True)
        spawned: List[int] = []
        try:
            for index in restart:
                self._spawn_node(index)
                spawned.append(index)
            for index in spawned:
                self._finish_node_start(index)
        except BaseException as error:
            if not isinstance(error, (KeyboardInterrupt, SystemExit)):
                self.had_process_failure = True
            self._stop_indexes(reversed(spawned), reason="reconfiguration-failure", desired=False)
            raise

    def stop_node(self, index: int) -> None:
        with self._lock:
            self.topology.validate(index)
            node = self.nodes[index]
            if self.hello and not node.activated:
                raise PlaygroundError("add %s before putting it to sleep" % node.name)
            if not node.desired_online and node.process is None:
                self.sink.emit("info", text="node %d is already stopped" % index)
                return
            self._stop_indexes([index], reason="operator-stop", desired=False)

    def start_node(self, index: int) -> None:
        with self._lock:
            self.topology.validate(index)
            node = self.nodes[index]
            if self.hello and not node.activated:
                raise PlaygroundError("add %s before waking it" % node.name)
            if node.process is not None or node.status in {"starting", "ready"}:
                self.sink.emit("info", text="node %d is already running" % index)
                return
            node.desired_online = True
            restart = []
            if self.network_provenance == "nearby":
                restart = [
                    candidate
                    for candidate, peer in enumerate(self.nodes)
                    if candidate != index
                    and peer.activated
                    and peer.desired_online
                    and peer.process is not None
                ]
                if restart:
                    self._stop_indexes(
                        restart,
                        reason="opening-nearby-window",
                        desired=True,
                    )
            started: List[int] = []
            try:
                for item in restart + [index]:
                    self._spawn_node(item)
                    started.append(item)
                for item in started:
                    self._finish_node_start(item)
            except BaseException:
                self.had_process_failure = True
                self._stop_indexes(
                    reversed(started),
                    reason="node-start-failure",
                    desired=False,
                )
                raise

    def _stop_indexes(self, indexes: Iterable[int], reason: str, desired: bool) -> None:
        errors: List[str] = []
        for index in indexes:
            node = self.nodes[index]
            process = node.process
            was_desired = node.desired_online
            already_exited = process.poll() if process is not None else None
            node.desired_online = desired
            if process is not None:
                if already_exited is not None and was_desired:
                    self.had_process_failure = True
                    node.error = "agent exited unexpectedly with status %d" % already_exited
                    self.sink.emit(
                        "node",
                        node=index,
                        status="failed",
                        reason=node.error,
                    )
                node.status = "reconfiguring" if desired else "stopping"
                self.sink.emit("node", node=index, status=node.status, pid=node.pid, reason=reason)
                self._progress()
                returncode: Optional[int] = None
                stop_error: Optional[Exception] = None
                try:
                    returncode = process.stop()
                except Exception as error:
                    stop_error = error
                    self.had_process_failure = True
                    try:
                        force_stop = getattr(process, "force_stop", None)
                        if force_stop is not None:
                            returncode = force_stop()
                        else:
                            returncode = process.stop(0.1)
                    except Exception:
                        # Keep the handle below so a later controller close can
                        # make another bounded attempt; continue with all peers.
                        returncode = None
                try:
                    process.close_streams()
                except Exception as error:
                    if stop_error is None:
                        stop_error = error
                        self.had_process_failure = True
                if returncode is not None:
                    node.process = None
                    node.pid = None
                node.client = None
                node.agent_url = None
                node.observer = "pending"
                node.observer_error = ""
                if stop_error is None:
                    node.status = "stopped"
                    self.sink.emit(
                        "node",
                        node=index,
                        status="stopped",
                        reason=reason,
                        exitCode=returncode,
                    )
                else:
                    node.status = "failed"
                    node.error = "process cleanup failed during %s" % reason
                    errors.append("n%d" % index)
                    self.sink.emit("node", node=index, status="failed", reason=node.error)
                self._progress()
            elif not desired:
                node.client = None
                node.agent_url = None
                node.pid = None
                node.status = "stopped"
                node.observer = "pending"
                node.observer_error = ""
        if errors:
            raise PlaygroundError("process cleanup failed for %s" % ",".join(errors))

    def status(self, index: Optional[int] = None) -> None:
        with self._lock:
            indexes = range(len(self.nodes)) if index is None else [index]
            if index is not None:
                self.topology.validate(index)
            for item in indexes:
                node = self.nodes[item]
                self.sink.emit(
                    "status",
                    node=item,
                    process=node.status,
                    sync=sync_label(node.sync),
                    authenticatedContacts=node.authenticated_contacts,
                    failedContactAttempts=node.failed_contacts,
                    seen=len(node.seen),
                    peers=sorted(self.topology.neighbors(item)),
                    isolated=item in self.topology.isolated,
                    pid=node.pid,
                    observer=node.observer,
                    observerError=node.observer_error,
                )

    def status_summary(self, index: Optional[int] = None) -> str:
        with self._lock:
            indexes = range(len(self.nodes)) if index is None else [index]
            if index is not None:
                self.topology.validate(index)
            parts = []
            for item in indexes:
                node = self.nodes[item]
                peers = ",".join(str(peer) for peer in sorted(self.topology.neighbors(item))) or "none"
                label = self.node_label(item)
                parts.append(
                    "%s %s observer=%s sync=%s contacts=%d failures=%d seen=%d peers=%s pid=%s"
                    % (
                        label,
                        node.status,
                        node.observer,
                        sync_label(node.sync),
                        node.authenticated_contacts,
                        node.failed_contacts,
                        len(node.seen),
                        peers,
                        node.pid if node.pid is not None else "-",
                    )
                )
            return " | ".join(parts)

    def _authenticated_neighbors(self, index: int) -> List[int]:
        """Return peers backed by an authenticated-contact status observation."""

        node = self.nodes[index]
        authenticated: Set[int] = set()
        for status in node.peers:
            authorization = str(status.get("authorization", "")).lower()
            try:
                contacts = int(status.get("authenticatedContacts", "0"))
                peer = decode_b64(status.get("peer"), "peer status identity", 32).hex()
            except (PlaygroundError, TypeError, ValueError):
                continue
            if contacts <= 0 or "active" not in authorization or "revoked" in authorization:
                continue
            for candidate in self.nodes:
                if candidate.init.mission_id == peer:
                    authenticated.add(candidate.init.index)
                    break
        return sorted(authenticated)

    def resolve_alias(self, value: str) -> EventRecord:
        with self._lock:
            if value == "last":
                if self.last_alias is None:
                    raise PlaygroundError("no message has been published")
                value = self.last_alias
            event_id = self.aliases.get(value, value)
            record = self.events.get(event_id)
            if record is None:
                raise PlaygroundError("unknown message %s" % safe_text(value, 40))
            return record

    def wait_seen(self, value: str, nodes: Iterable[int], timeout: float) -> None:
        expected = set(nodes)
        for index in expected:
            self.topology.validate(index)
        deadline = time.monotonic() + timeout
        record = self.resolve_alias(value)
        while True:
            with self._lock:
                if expected <= record.seen:
                    self.sink.emit(
                        "wait",
                        message=record.alias,
                        status="pass",
                        nodes=sorted(expected),
                    )
                    return
            if time.monotonic() >= deadline:
                missing = sorted(expected - record.seen)
                raise PlaygroundError(
                    "%s was not observed at nodes %s before the wait deadline"
                    % (record.alias, ",".join(str(index) for index in missing))
                )
            # The background observer owns RPC polling.  Waiting here on that
            # model keeps the operator deadline exact even if one local agent
            # is stalled inside a bounded application request.
            time.sleep(min(0.1, max(0.0, deadline - time.monotonic())))

    def assert_unseen(self, value: str, nodes: Iterable[int]) -> None:
        expected = sorted(set(nodes))
        if not expected:
            raise PlaygroundError("assert-unseen requires at least one node")
        record = self.resolve_alias(value)
        requests = []
        with self._lock:
            for index in expected:
                self.topology.validate(index)
                node = self.nodes[index]
                if node.status != "ready" or node.client is None:
                    raise PlaygroundError(
                        "node %d is not ready for an exact QueryEvents observation" % index
                    )
                requests.append((index, node.generation, node.client))

        for index, generation, client in requests:
            events, _marker = client.query_events(0)
            with self._lock:
                node = self.nodes[index]
                if node.generation != generation or node.client is not client:
                    raise PlaygroundError(
                        "node %d changed while assert-unseen was observing it" % index
                    )
                try:
                    for event in events:
                        self._observe_event(index, event)
                except (PlaygroundError, TypeError, ValueError):
                    self.had_fatal_failure = True
                    raise
                if index in record.seen:
                    raise PlaygroundError(
                        "%s is present at node %d; assert-unseen failed" % (record.alias, index)
                    )
        self.sink.emit(
            "assert_unseen",
            message=record.alias,
            status="pass",
            nodes=expected,
            exactQuery=True,
            snapshotOnly=True,
            convergenceClaim=False,
        )

    def wait_all(self, timeout: float) -> None:
        with self._lock:
            aliases = [record.alias for record in self.events.values()]
            expected = [
                node.init.index
                for node in self.nodes
                if node.desired_online and node.status == "ready"
            ]
        for alias in aliases:
            remaining = max(0.0, timeout)
            started = time.monotonic()
            self.wait_seen(alias, expected, remaining)
            timeout = max(0.0, timeout - (time.monotonic() - started))
        self.sink.emit("wait", message="all-known-events", status="pass", nodes=expected)

    def snapshot(self) -> Dict[str, object]:
        with self._lock:
            return {
                "root": str(self.root),
                "experience": "hello" if self.hello else "playground",
                "networkProvenance": self.network_provenance,
                "nearbyWindowSeconds": (
                    self.nearby_window_seconds
                    if self.network_provenance == "nearby"
                    else 0
                ),
                "selectedNode": self.selected_index,
                "isolated": sorted(self.topology.isolated),
                "nodes": [
                    {
                        "index": index,
                        "name": node.name,
                        "activated": node.activated,
                        "status": node.status,
                        "pid": node.pid,
                        "sync": sync_label(node.sync),
                        "contacts": node.authenticated_contacts,
                        "failures": node.failed_contacts,
                        "seen": len(node.seen),
                        "neighbors": sorted(self.topology.neighbors(index)),
                        "authenticatedNeighbors": self._authenticated_neighbors(index),
                        "observer": node.observer,
                        "observerError": node.observer_error,
                        "error": node.error,
                    }
                    for index, node in enumerate(self.nodes)
                ],
                "events": [
                    {
                        "alias": record.alias,
                        "id": record.event_id,
                        "text": record.text,
                        "publisherNode": record.publisher_node,
                        "seen": sorted(record.seen),
                    }
                    for record in sorted(self.events.values(), key=lambda item: int(item.alias[1:]))
                ],
            }

    def close(self) -> None:
        with self._lock:
            if self._closed:
                return
            self._closing = True
            self._poll_stop.set()
        if self._poll_thread is not None and self._poll_thread is not threading.current_thread():
            self._poll_thread.join(timeout=0.25)
        cleanup_error: Optional[Exception] = None
        with self._lock:
            try:
                self._stop_indexes(
                    reversed(range(len(self.nodes))),
                    reason="playground-exit",
                    desired=False,
                )
            except Exception as error:
                cleanup_error = error
            finally:
                self._close_reservations()
                # A failed stop+force attempt retains its handle.  Keep close
                # retryable instead of losing the supervisor's last reference.
                self._closed = not any(node.process is not None for node in self.nodes)
                # Keep this true so a late daemon poll completion never emits
                # into a journal already handed off for closure.
                self._closing = True
        if cleanup_error is not None:
            raise cleanup_error


def reserve_udp_ports(count: int) -> List[socket.socket]:
    reservations: List[socket.socket] = []
    try:
        for _ in range(count):
            reservation = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            reservation.bind(("127.0.0.1", 0))
            reservations.append(reservation)
    except BaseException:
        for reservation in reservations:
            reservation.close()
        raise
    return reservations


def sync_label(value: object) -> str:
    text = str(value)
    prefix = "SYNC_STATUS_"
    if text.startswith(prefix):
        text = text[len(prefix) :]
    return text.lower().replace("_", "-")


def render_hello_dashboard(
    snapshot: Mapping[str, object],
    width: int,
    height: int,
    unicode: bool,
) -> List[str]:
    """Render the staged Field Notes story without broadening evidence claims."""

    width = max(1, width)
    height = max(6, height)
    raw_nodes = snapshot.get("nodes", [])
    raw_events = snapshot.get("events", [])
    nodes = [node for node in raw_nodes if isinstance(node, dict)] if isinstance(raw_nodes, list) else []
    events = [event for event in raw_events if isinstance(event, dict)] if isinstance(raw_events, list) else []
    isolated = set(snapshot.get("isolated", []))
    activated = sum(1 for node in nodes if node.get("activated"))
    awake = sum(1 for node in nodes if node.get("status") == "ready")
    route = snapshot.get("networkProvenance")
    if route == "nearby":
        provenance = (
            "ROUTE nearby · %ss locator windows · carrier/direct-address hints only · no fallback"
            % safe_text(snapshot.get("nearbyWindowSeconds", "?"))
        )
    else:
        provenance = "ROUTE invitation · controller-known loopback locators · no fallback"

    lines = [
        "ASTER FIELD NOTES  %d/%d joined · %d awake" % (activated, len(nodes), awake),
        BOUNDARY,
        provenance,
        "Names stay in this local display; they are not discovery metadata.",
        "",
        "Constellation (solid = authenticated contact observed; dots = provisioned roster)",
    ]

    labels: List[str] = []
    for node in nodes:
        status = node.get("status")
        if status == "ready":
            marker = "●"
        elif status in {"starting", "reconfiguring", "stopping"}:
            marker = "◐"
        elif status == "failed":
            marker = "×"
        else:
            marker = "○"
        label = "%s %s" % (marker, safe_text(node.get("name") or "n%s" % node.get("index"), 16))
        if node.get("index") == snapshot.get("selectedNode"):
            label += "*"
        labels.append(label)

    if width >= 64 and labels:
        current = ""
        for offset, label in enumerate(labels):
            separator = ""
            if offset:
                left = nodes[offset - 1]
                right = nodes[offset]
                left_index = int(left.get("index", offset - 1))
                right_index = int(right.get("index", offset))
                if left_index in isolated or right_index in isolated:
                    separator = "  ×  "
                else:
                    left_auth = set(left.get("authenticatedNeighbors", []))
                    right_auth = set(right.get("authenticatedNeighbors", []))
                    observed = right_index in left_auth or left_index in right_auth
                    separator = " ─── " if observed else " ··· "
            candidate = current + separator + label
            if current and len(terminal_text(candidate, unicode)) > width:
                lines.append(current)
                current = label
            else:
                current = candidate
        if current:
            lines.append(current)
    else:
        for node, label in zip(nodes, labels):
            state = "not added" if not node.get("activated") else safe_text(node.get("status"), 16)
            lines.append("  %-18s %s" % (label, state))

    lines.extend(["", "Field notes (presence comes only from exact QueryEvents results)"])
    if not events:
        if activated == 0 and nodes:
            lines.append("  Begin with: add %s" % safe_text(nodes[0].get("name", "atlas"), 16))
        else:
            lines.append("  No notes yet. Use: note TEXT")
    else:
        available = max(1, min(6, height - len(lines) - 4))
        names = {
            int(node.get("index", index)): safe_text(node.get("name") or "n%d" % index, 16)
            for index, node in enumerate(nodes)
        }
        for event in events[-available:]:
            seen = set(event.get("seen", []))
            cells = "".join("✓" if int(node.get("index", 0)) in seen else "·" for node in nodes)
            publisher = event.get("publisherNode")
            publisher_text = names.get(publisher, "unknown")
            lines.append(
                "  %s from %s  %s  [%s] %d/%d"
                % (
                    safe_text(event.get("alias", "?"), 12),
                    publisher_text,
                    safe_text(event.get("text", ""), max(12, width // 3)),
                    cells,
                    len(seen),
                    len(nodes),
                )
            )
    lines.extend(
        [
            "",
            "Commands: add · use · note · sleep/wake · status · help · quit",
        ]
    )
    rendered = [truncate(line, width, unicode) for line in lines]
    if len(rendered) <= height:
        return rendered
    keep = rendered[:4]
    command = rendered[-1]
    middle_budget = max(1, height - len(keep) - 1)
    return (keep + rendered[-(middle_budget + 1) : -1] + [command])[:height]


def render_dashboard(snapshot: Mapping[str, object], width: int, height: int, unicode: bool) -> List[str]:
    if snapshot.get("experience") == "hello":
        return render_hello_dashboard(snapshot, width, height, unicode)
    width = max(1, width)
    height = max(6, height)
    nodes = snapshot.get("nodes", [])
    events = snapshot.get("events", [])
    isolated = set(snapshot.get("isolated", []))
    if not isinstance(nodes, list):
        nodes = []
    if not isinstance(events, list):
        events = []
    ready = sum(1 for node in nodes if isinstance(node, dict) and node.get("status") == "ready")
    lines = [
        "ASTER MESH PLAYGROUND  %d/%d processes ready" % (ready, len(nodes)),
        BOUNDARY,
        "",
    ]

    labels: List[str] = []
    for node in nodes:
        if not isinstance(node, dict):
            continue
        index = int(node.get("index", 0))
        status = node.get("status")
        marker = "●" if status == "ready" else "◐" if status in {"starting", "reconfiguring", "stopping"} else "○"
        if status == "failed":
            marker = "×"
        elif node.get("observer") == "error":
            marker = "!"
        label = "%s n%d" % (marker, index)
        if node.get("observer") == "error":
            label += " observer-error"
        if index in isolated:
            label += " isolated"
        labels.append(label)
    if width >= 72 and labels:
        current = ""
        for index, label in enumerate(labels):
            if index:
                enabled = index - 1 not in isolated and index not in isolated
                separator = " ─── " if enabled else "  ×  "
            else:
                separator = ""
            candidate = current + separator + label
            if current and len(terminal_text(candidate, unicode)) > width:
                lines.append(current)
                current = label
            else:
                current = candidate
        if current:
            lines.append(current)
    else:
        for node in nodes:
            if not isinstance(node, dict):
                continue
            index = int(node.get("index", 0))
            peers = ",".join("n%s" % item for item in node.get("neighbors", [])) or "none"
            display_status = safe_text(node.get("status", "unknown"), 13)
            if node.get("observer") == "error":
                display_status = "observer-error"
            lines.append(
                "n%d %-13s peers=%s seen=%s" % (
                    index,
                    display_status,
                    peers,
                    safe_text(node.get("seen", 0)),
                )
            )
    lines.extend(["", "Messages (presence comes from exact QueryEvents results)"])
    if not events:
        lines.append("  No messages yet.  Use: send NODE TEXT")
    else:
        available = max(1, min(6, height - len(lines) - 4))
        for event in events[-available:]:
            if not isinstance(event, dict):
                continue
            seen = set(event.get("seen", []))
            cells = "".join("✓" if index in seen else "·" for index in range(len(nodes)))
            publisher = event.get("publisherNode")
            publisher_text = "n%s" % publisher if publisher is not None else "unknown"
            lines.append(
                "  %s from %s  %s  [%s] %d/%d" % (
                    safe_text(event.get("alias", "?"), 12),
                    publisher_text,
                    safe_text(event.get("text", ""), max(12, width // 3)),
                    cells,
                    len(seen),
                    len(nodes),
                )
            )
    lines.extend(
        [
            "",
            "Commands: send · assert-unseen · isolate/rejoin · stop/start · status · quit",
        ]
    )
    rendered = [truncate(line, width, unicode) for line in lines]
    if len(rendered) <= height:
        return rendered
    # Preserve the boundary, at least one topology/status line, recent messages,
    # and the command reminder in a short terminal.
    keep = rendered[:2]
    command = rendered[-1]
    middle_budget = max(2, height - len(keep) - 1)
    middle = rendered[-(middle_budget + 1) : -1]
    return (keep + middle + [command])[:height]


HELP_TEXT = (
    "send NODE TEXT | isolate NODE | rejoin NODE | stop NODE | start NODE | "
    "status [NODE] | wait-seen MESSAGE NODE[,NODE...] [SECONDS] | "
    "assert-unseen MESSAGE NODE[,NODE...] | wait-all [SECONDS] | help | quit"
)
HELLO_HELP_TEXT = (
    "add NAME | use NAME | note TEXT | sleep NAME | wake NAME | status [NAME] | "
    "wait-seen MESSAGE NAME[,NAME...] [SECONDS] | wait-all [SECONDS] | help | quit; "
    "advanced: send/isolate/rejoin/assert-unseen"
)


class CommandProcessor:
    def __init__(self, controller: PlaygroundController) -> None:
        self.controller = controller
        self.last_notice = ""

    @staticmethod
    def _index(value: str) -> int:
        try:
            return int(value)
        except ValueError as error:
            raise PlaygroundError("node index must be an integer") from error

    def _node_index(self, value: str) -> int:
        return self.controller.resolve_node(value)

    def execute(self, line: str) -> bool:
        self.last_notice = ""
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            return False
        command, _, remainder = stripped.partition(" ")
        command = command.lower()
        if command in {"quit", "q", "exit"}:
            return True
        if command in {"help", "?"}:
            help_text = HELLO_HELP_TEXT if self.controller.hello else HELP_TEXT
            self.controller.sink.emit("info", text=help_text)
            self.last_notice = help_text
            return False
        if command == "add":
            arguments = remainder.split()
            if len(arguments) != 1:
                raise PlaygroundError("usage: add NAME")
            index = self._node_index(arguments[0])
            self.controller.add_node(index)
            name = self.controller.node_label(index)
            self.last_notice = "%s is awake and selected. Write a field note with: note TEXT" % name
            return False
        if command == "use":
            arguments = remainder.split()
            if len(arguments) != 1:
                raise PlaygroundError("usage: use NAME")
            index = self._node_index(arguments[0])
            self.controller.select_node(index)
            self.last_notice = "%s is selected for the next field note." % self.controller.node_label(index)
            return False
        if command == "note":
            text = remainder.strip()
            if not text:
                raise PlaygroundError("usage: note TEXT")
            index = self.controller.selected_index
            if index is None:
                raise PlaygroundError("add or use a field node before writing a note")
            alias = self.controller.send(index, text)
            self.last_notice = (
                "%s accepted at %s; exact presence is still being queried."
                % (alias, self.controller.node_label(index))
            )
            return False
        if command == "send":
            node_text, separator, text = remainder.strip().partition(" ")
            if not separator or not text:
                raise PlaygroundError("usage: send NODE TEXT")
            alias = self.controller.send(self._node_index(node_text), text)
            self.last_notice = "%s accepted locally; exact node presence is still being queried." % alias
            return False
        if command in {"isolate", "rejoin", "stop", "start", "sleep", "wake"}:
            arguments = remainder.split()
            if len(arguments) != 1:
                raise PlaygroundError("usage: %s NODE" % command)
            index = self._node_index(arguments[0])
            if command in {"stop", "sleep"}:
                self.controller.stop_node(index)
            elif command in {"start", "wake"}:
                self.controller.start_node(index)
            elif command == "isolate":
                self.controller.isolate(index)
            else:
                self.controller.rejoin(index)
            self.last_notice = "%s %s completed." % (
                command,
                self.controller.node_label(index),
            )
            return False
        if command == "status":
            arguments = remainder.split()
            if len(arguments) > 1:
                raise PlaygroundError("usage: status [NODE]")
            index = self._node_index(arguments[0]) if arguments else None
            self.controller.status(index)
            self.last_notice = self.controller.status_summary(index)
            return False
        if command == "wait-all":
            arguments = remainder.split()
            if len(arguments) > 1:
                raise PlaygroundError("usage: wait-all [SECONDS]")
            timeout = bounded_timeout(
                arguments[0] if arguments else DEFAULT_WAIT_SECONDS,
                "wait timeout",
                MAX_WAIT_SECONDS,
            )
            self.controller.wait_all(timeout)
            self.last_notice = "All known Events were observed at all currently ready nodes."
            return False
        if command == "wait-seen":
            arguments = remainder.split()
            if len(arguments) not in {2, 3}:
                raise PlaygroundError("usage: wait-seen MESSAGE NODE[,NODE...] [SECONDS]")
            try:
                indexes = [self._node_index(value) for value in arguments[1].split(",") if value]
            except PlaygroundError:
                raise
            if not indexes:
                raise PlaygroundError("wait-seen requires at least one node")
            timeout = bounded_timeout(
                arguments[2] if len(arguments) == 3 else DEFAULT_WAIT_SECONDS,
                "wait timeout",
                MAX_WAIT_SECONDS,
            )
            self.controller.wait_seen(arguments[0], indexes, timeout)
            self.last_notice = "%s was observed at nodes %s." % (
                arguments[0],
                ",".join(str(index) for index in indexes),
            )
            return False
        if command == "assert-unseen":
            arguments = remainder.split()
            if len(arguments) != 2:
                raise PlaygroundError("usage: assert-unseen MESSAGE NODE[,NODE...]")
            indexes = [self._node_index(value) for value in arguments[1].split(",") if value]
            if not indexes:
                raise PlaygroundError("assert-unseen requires at least one node")
            self.controller.assert_unseen(arguments[0], indexes)
            self.last_notice = (
                "%s was absent from one exact current QueryEvents view at nodes %s; "
                "later arrival and convergence are not claimed."
                % (arguments[0], ",".join(str(index) for index in indexes))
            )
            return False
        raise PlaygroundError("unknown command %s; use help" % safe_text(command, 40))


def resolve_view(requested: str) -> str:
    if requested != "auto":
        return requested
    terminal = shutil.get_terminal_size((88, 24))
    term = os.environ.get("TERM", "")
    if (
        sys.stdin.isatty()
        and sys.stdout.isatty()
        and term.lower() not in {"", "dumb", "unknown"}
        and terminal.columns >= 60
        and terminal.lines >= 16
    ):
        return "tui"
    return "plain"


def run_script(
    processor: CommandProcessor,
    source: TextIO,
    sink: EventSink,
) -> bool:
    line_number = 0
    while True:
        line_number += 1
        try:
            line = read_command_line(source)
            if line is None:
                return False
            if processor.execute(line):
                return True
        except (PlaygroundError, ValueError) as error:
            sink.emit("error", error="script line %d: %s" % (line_number, safe_text(error, 220)))
            raise PlaygroundError("script command failed at line %d" % line_number) from error


def read_command_line(source: TextIO) -> Optional[str]:
    """Read and, when necessary, drain one bounded command line."""

    line = source.readline(MAX_COMMAND_LINE_CHARACTERS + 1)
    if line == "":
        return None
    oversized = len(line) > MAX_COMMAND_LINE_CHARACTERS or len(line.encode("utf-8")) > MAX_COMMAND_LINE_CHARACTERS
    if not line.endswith("\n") and len(line) >= MAX_COMMAND_LINE_CHARACTERS + 1:
        oversized = True
        while True:
            remainder = source.readline(MAX_COMMAND_LINE_CHARACTERS + 1)
            if remainder == "" or remainder.endswith("\n"):
                break
    if oversized:
        raise PlaygroundError(
            "command line exceeds the %d-character playground bound"
            % MAX_COMMAND_LINE_CHARACTERS
        )
    return line


def run_repl(processor: CommandProcessor, sink: EventSink, raw: bool) -> None:
    prompt_stream = sys.stderr if raw else sys.stdout
    sink.emit(
        "info",
        text=HELLO_HELP_TEXT if processor.controller.hello else HELP_TEXT,
    )
    prompt = "field-notes> " if processor.controller.hello else "playground> "
    while True:
        prompt_stream.write(prompt)
        prompt_stream.flush()
        try:
            line = read_command_line(sys.stdin)
            if line is None:
                return
            if processor.execute(line):
                return
        except (PlaygroundError, ValueError) as error:
            sink.emit("error", error=safe_text(error, 220))


def tui_append_character(command: str, character: object) -> str:
    """Append one printable wide character within the shared UTF-8 bound."""

    if not isinstance(character, str) or len(character) != 1 or not character.isprintable():
        return command
    candidate = command + character
    if len(candidate.encode("utf-8")) > MAX_COMMAND_LINE_CHARACTERS:
        return command
    return candidate


def run_tui(processor: CommandProcessor, controller: PlaygroundController) -> None:
    try:
        import curses
    except ImportError as error:
        raise PlaygroundError("the requested TUI is unavailable on this Python installation") from error

    def application(screen: Any) -> None:
        try:
            curses.curs_set(1)
        except curses.error:
            pass
        screen.keypad(True)
        screen.timeout(100)
        command = ""
        notice = (
            "Begin with add atlas. Nearby and invitation never silently replace each other."
            if controller.hello
            else "Type help for commands. Presence is queried, never inferred."
        )

        def redraw() -> None:
            height, width = screen.getmaxyx()
            content_height = max(6, height - 2)
            lines = render_dashboard(
                controller.snapshot(),
                max(1, width - 1),
                content_height,
                supports_unicode(sys.stdout),
            )
            try:
                screen.erase()
                for row, line in enumerate(lines[:content_height]):
                    screen.addnstr(row, 0, line, max(1, width - 1))
                notice_row = min(content_height, max(0, height - 2))
                screen.addnstr(notice_row, 0, truncate(notice, max(1, width - 1)), max(1, width - 1))
                prompt = ("field-note> " if controller.hello else "command> ") + command
                screen.addnstr(max(0, height - 1), 0, prompt, max(1, width - 1))
                screen.move(max(0, height - 1), min(max(0, width - 1), len(prompt)))
                screen.refresh()
            except curses.error:
                pass

        controller.progress_callback = redraw
        try:
            while True:
                redraw()
                try:
                    key = screen.get_wch()
                except curses.error:
                    continue
                if key in {3, "\x03"}:  # Ctrl-C
                    raise KeyboardInterrupt
                if key in {10, 13, "\n", "\r", curses.KEY_ENTER}:
                    line = command
                    command = ""
                    notice = "Working..."
                    redraw()
                    try:
                        if processor.execute(line):
                            return
                        notice = processor.last_notice or "Command completed."
                    except (PlaygroundError, ValueError) as error:
                        width = screen.getmaxyx()[1]
                        notice = "Error: " + safe_text(error, max(20, width - 8))
                    continue
                if key in {curses.KEY_BACKSPACE, 8, 127, "\b", "\x7f"}:
                    command = command[:-1]
                    continue
                if key in {27, "\x1b"}:
                    command = ""
                    continue
                command = tui_append_character(command, key)
        finally:
            controller.progress_callback = None

    curses.wrapper(application)


def choose_root(value: Optional[Path]) -> Path:
    if value is not None:
        root = Path(os.path.abspath(str(value)))
        if root.exists():
            raise PlaygroundError("playground root already exists: %s" % safe_text(root, 220))
        if not root.parent.is_dir():
            raise PlaygroundError("playground root parent does not exist")
        return root
    parent = Path(tempfile.mkdtemp(prefix="aster-playground."))
    os.chmod(parent, 0o700)
    return parent / "mesh"


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Run a bounded local multi-process Aster Event playground",
    )
    parser.add_argument("--aster", type=Path, required=True, help="path to the aster CLI")
    parser.add_argument("--agent", type=Path, required=True, help="path to aster-agent")
    parser.add_argument("--cli", type=Path, help="path to asterctl (default: alongside aster-agent)")
    parser.add_argument("--nodes", type=int, required=True, help="real process count (2..32)")
    parser.add_argument(
        "--hello",
        action="store_true",
        help="stage a named, human-driven Field Notes hello experience",
    )
    parser.add_argument(
        "--network",
        choices=("nearby", "invitation"),
        help="explicit hello route source; no automatic fallback",
    )
    parser.add_argument("--root", type=Path, help="fresh retained playground root")
    parser.add_argument(
        "--view",
        choices=("auto", "tui", "plain", "raw"),
        default="auto",
        help="terminal presentation mode",
    )
    parser.add_argument(
        "--script",
        type=str,
        help="execute commands from a file, or '-' for stdin, then exit",
    )
    parser.add_argument("--startup-timeout", type=float, default=DEFAULT_STARTUP_SECONDS, help=argparse.SUPPRESS)
    parser.add_argument("--poll-ms", type=int, default=int(DEFAULT_POLL_SECONDS * 1000), help=argparse.SUPPRESS)
    return parser


def _validate_executable(path: Path, label: str) -> Path:
    absolute = Path(os.path.abspath(str(path)))
    if not absolute.is_file() or not os.access(str(absolute), os.X_OK):
        raise PlaygroundError("%s is not an executable file: %s" % (label, safe_text(absolute, 200)))
    return absolute


class InterruptLatch:
    """Record the first terminal signal and make later signals cleanup-safe."""

    def __init__(self, handled_signals: Sequence[int]) -> None:
        self.handled_signals = tuple(handled_signals)
        self.signum: Optional[int] = None

    def __call__(self, signum: int, _frame: object) -> None:
        if self.signum is not None:
            return
        self.signum = signum
        for handled in self.handled_signals:
            signal.signal(handled, signal.SIG_IGN)
        raise KeyboardInterrupt

    @property
    def exit_code(self) -> int:
        return 128 + (self.signum if self.signum is not None else signal.SIGINT)


def main(argv: Optional[Sequence[str]] = None) -> int:
    arguments = build_parser().parse_args(argv)
    if not MIN_NODES <= arguments.nodes <= MAX_NODES:
        print("playground error: --nodes must be within 2..32", file=sys.stderr)
        return 2
    if arguments.hello and arguments.network is None:
        print(
            "playground error: --hello requires an explicit --network nearby or invitation",
            file=sys.stderr,
        )
        return 2
    if not arguments.hello and arguments.network is not None:
        print("playground error: --network is available only with --hello", file=sys.stderr)
        return 2
    try:
        startup_timeout = bounded_timeout(
            arguments.startup_timeout,
            "startup timeout",
            MAX_STARTUP_SECONDS,
        )
    except PlaygroundError as error:
        print("playground error: %s" % safe_text(error, 200), file=sys.stderr)
        return 2
    if arguments.poll_ms < 50 or arguments.poll_ms > MAX_POLL_MILLISECONDS:
        print(
            "playground error: --poll-ms must be within 50..%d" % MAX_POLL_MILLISECONDS,
            file=sys.stderr,
        )
        return 2

    controller: Optional[PlaygroundController] = None
    sink: Optional[EventSink] = None
    root: Optional[Path] = None
    interrupted = False
    result = 1
    previous_handlers: Dict[int, Any] = {}
    handled_signals = tuple(
        dict.fromkeys((signal.SIGINT, signal.SIGTERM, getattr(signal, "SIGHUP", signal.SIGTERM)))
    )
    interrupt_latch = InterruptLatch(handled_signals)

    for signum in handled_signals:
        if signum in previous_handlers:
            continue
        previous_handlers[signum] = signal.getsignal(signum)
        signal.signal(signum, interrupt_latch)

    try:
        aster = _validate_executable(arguments.aster, "--aster")
        agent = _validate_executable(arguments.agent, "--agent")
        cli = _validate_executable(arguments.cli or agent.with_name("asterctl"), "--cli")
        root = choose_root(arguments.root)
        view = resolve_view(arguments.view)
        # A script must never enter the alternate screen.  Explicit raw stays
        # machine-readable; every other scripted run uses progressive plain.
        if view == "tui" and (
            arguments.script is not None or not sys.stdin.isatty() or not sys.stdout.isatty()
        ):
            view = "plain"
        if view in {"plain", "tui"}:
            if arguments.hello:
                progress = "ASTER FIELD NOTES  provisioning %d disposable roster slots..." % arguments.nodes
            else:
                progress = "ASTER MESH PLAYGROUND  provisioning %d real processes..." % arguments.nodes
            sys.stdout.write(
                terminal_text(
                    progress,
                    supports_unicode(sys.stdout),
                )
                + "\n"
            )
            sys.stdout.flush()
        init = run_initializer(aster, root, arguments.nodes, startup_timeout)
        sink = EventSink(root, "plain" if view == "tui" else view)
        controller = PlaygroundController(
            init,
            agent,
            sink,
            startup_timeout=startup_timeout,
            cli=cli,
            poll_seconds=arguments.poll_ms / 1000.0,
            hello=arguments.hello,
            network_provenance=arguments.network or "direct",
        )
        controller.start()
        if view == "tui":
            sink.set_mode("tui")
        processor = CommandProcessor(controller)
        if arguments.script is not None:
            if arguments.script == "-":
                source = sys.stdin
                close_source = False
            else:
                source = open(arguments.script, "r", encoding="utf-8")
                close_source = True
            try:
                run_script(processor, source, sink)
            finally:
                if close_source:
                    source.close()
        elif not sys.stdin.isatty():
            run_script(processor, sys.stdin, sink)
        elif view == "tui":
            run_tui(processor, controller)
        else:
            run_repl(processor, sink, view == "raw")
        result = 1 if controller.had_process_failure else 0
    except KeyboardInterrupt:
        interrupted = True
        result = interrupt_latch.exit_code
    except (PlaygroundError, OSError, ValueError) as error:
        if sink is not None:
            sink.emit("fatal", error=safe_text(error, 240))
        else:
            print("playground error: %s" % safe_text(error, 240), file=sys.stderr)
        result = 1
    finally:
        # Cleanup owns the children from this point.  A second terminal signal
        # must not interrupt process-group reaping or terminal restoration.
        for signum in handled_signals:
            signal.signal(signum, signal.SIG_IGN)
        if controller is not None:
            for _attempt in range(2):
                try:
                    controller.close()
                    break
                except Exception as error:
                    if sink is not None:
                        sink.emit("error", error="cleanup failed: %s" % safe_text(error, 180))
                    result = result or 1
                    if controller._closed:
                        break
            if (controller.had_process_failure or controller.had_fatal_failure) and result == 0:
                result = 1
        if sink is not None:
            sink.emit(
                "finished",
                status="interrupted" if interrupted else "pass" if result == 0 else "failed",
                root=str(root) if root is not None else "",
            )
            sink.close()
        if root is not None:
            print("Playground artifacts retained under: %s" % safe_text(root, 240), file=sys.stderr)
        for signum, handler in previous_handlers.items():
            signal.signal(signum, handler)
    return result


if __name__ == "__main__":
    raise SystemExit(main())
