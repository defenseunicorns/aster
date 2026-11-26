"""Bounded, display-safe command evidence for one quickstart session."""

from __future__ import annotations

from collections import deque
from collections.abc import Callable, Iterable, Sequence
from dataclasses import dataclass
import copy
import json
import re
import shlex
import threading
import time
from typing import Any


_REDACTED_ARGUMENT = "<redacted:argument>"
_REDACTED_SECRET = b"<redacted:secret>"
_DEFAULT_MAX_TOTAL_BYTES = 1_048_576
_DEFAULT_MAX_SECRETS = 64
_SENSITIVE_OPTION = re.compile(
    r"(?:^|[-_])(?:access[-_]?token|api[-_]?key|authorization|auth|bearer|"
    r"client[-_]?secret|password|passwd|private[-_]?key|secret|token)(?:$|[-_])",
    re.IGNORECASE,
)
_AUTHORIZATION_HEADER = re.compile(
    r"^(?P<prefix>(?:proxy-)?authorization\s*:\s*)(?:bearer\s+)?(?P<secret>.+)$",
    re.IGNORECASE,
)


def _as_secret_bytes(value: bytes | str) -> bytes:
    if isinstance(value, str):
        value = value.encode()
    elif not isinstance(value, bytes):
        raise TypeError("secret values must be bytes or strings")
    if not value:
        raise ValueError("secret values must not be empty")
    return value


def _require_text(value: str, name: str) -> str:
    if not isinstance(value, str) or not value:
        raise ValueError(f"{name} must be a non-empty string")
    return value


def _is_sensitive_option(argument: str) -> bool:
    if not argument.startswith("-"):
        return False
    option = argument.split("=", 1)[0].lstrip("-").casefold()
    if any(suffix in option for suffix in ("file", "path", "ref")):
        return False
    return _SENSITIVE_OPTION.search(option) is not None


def _redact_authorization_header(argument: str) -> tuple[str, str] | None:
    """Return a redacted argv item and credential for common curl header forms."""

    option = ""
    header = argument
    if argument.startswith("-H") and argument != "-H":
        option, header = "-H", argument[2:]
    elif argument.startswith("--header="):
        option, header = "--header=", argument[len("--header="):]
    match = _AUTHORIZATION_HEADER.fullmatch(header)
    if match is None:
        return None
    return f"{option}{match.group('prefix')}{_REDACTED_ARGUMENT}", match.group("secret")


@dataclass
class _Entry:
    identifier: int
    kind: str
    step: str
    outcome: str
    title: str | None = None
    detail: str | None = None
    command: str | None = None
    cwd: str | None = None
    stdin: str | None = None
    replayable: bool | None = None
    returncode: int | None = None
    duration_ms: int | None = None
    handle: CommandHandle | None = None
    argv: list[str] | None = None
    retained: bool = True


class CommandHandle:
    """Private mutable stream buffers for one command journal entry."""

    def __init__(self, journal: TranscriptJournal, entry: _Entry, started_at: float) -> None:
        self._journal = journal
        self._entry = entry
        self._started_at = started_at
        self._stdout = bytearray()
        self._stderr = bytearray()
        self._stdin = bytearray()
        self._stdin_pending = b""
        self._stdout_pending = b""
        self._stderr_pending = b""
        self._stdin_truncated = False
        self._stdout_truncated = False
        self._stderr_truncated = False
        self._has_stdin = False
        self._finished = False

    def update(self, stdout: bytes = b"", stderr: bytes = b"") -> None:
        """Retain redacted output and coalesce its observer notification."""

        self._journal._update(self, stdout=stdout, stderr=stderr)

    def finish(self, returncode: int | None, *, outcome: str) -> None:
        """Finalize this command once and notify immediately."""

        self._journal._finish(self, returncode=returncode, outcome=outcome)


class TranscriptJournal:
    """A small thread-safe journal whose snapshots are safe to publish."""

    def __init__(
        self,
        max_entries: int = 128,
        max_stream_bytes: int = 65_536,
        update_interval: float = 0.1,
        max_total_bytes: int = _DEFAULT_MAX_TOTAL_BYTES,
        max_secrets: int = _DEFAULT_MAX_SECRETS,
    ) -> None:
        if not isinstance(max_entries, int) or max_entries < 1:
            raise ValueError("max_entries must be a positive integer")
        if not isinstance(max_stream_bytes, int) or max_stream_bytes < 1:
            raise ValueError("max_stream_bytes must be a positive integer")
        if not isinstance(update_interval, (int, float)) or update_interval < 0.1:
            raise ValueError("update_interval must be at least 0.1 seconds")
        if not isinstance(max_total_bytes, int) or max_total_bytes < 1:
            raise ValueError("max_total_bytes must be a positive integer")
        if not isinstance(max_secrets, int) or max_secrets < 1:
            raise ValueError("max_secrets must be a positive integer")
        self._max_entries = max_entries
        self._max_stream_bytes = max_stream_bytes
        self._update_interval = float(update_interval)
        self._max_total_bytes = max_total_bytes
        self._max_secrets = max_secrets
        self._lock = threading.Lock()
        self._entries: deque[_Entry] = deque()
        self._next_identifier = 1
        self._secrets: list[bytes] = []
        self._observer: Callable[[], None] | None = None
        self._last_output_notification: dict[int, float] = {}
        self._output_notification_sent: set[int] = set()

    def register_secret(self, value: bytes | str) -> None:
        """Register an exact value that must not enter later retained evidence."""

        secret = _as_secret_bytes(value)
        with self._lock:
            self._register_secret_locked(secret)
            self._scrub_existing_locked()
            observer = self._observer
        self._notify(observer)

    def release_secret(self, value: bytes | str) -> None:
        """Compatibility no-op that preserves journal-lifetime redaction coverage."""

        secret = _as_secret_bytes(value)
        with self._lock:
            if secret not in self._secrets:
                return
            self._scrub_existing_locked()
            observer = self._observer
        self._notify(observer)

    def set_observer(self, observer: Callable[[], None] | None) -> None:
        if observer is not None and not callable(observer):
            raise TypeError("observer must be callable or None")
        with self._lock:
            self._observer = observer

    def start_command(
        self,
        step: str,
        argv: Sequence[str],
        *,
        cwd: str,
        stdin: bytes | None = None,
        sensitive_values: Iterable[bytes | str] = (),
    ) -> CommandHandle:
        _require_text(step, "step")
        _require_text(cwd, "cwd")
        if isinstance(argv, (str, bytes)) or not argv:
            raise ValueError("argv must be a non-empty sequence of strings")
        arguments = list(argv)
        if any(not isinstance(argument, str) or not argument or "\0" in argument for argument in arguments):
            raise ValueError("argv must contain non-empty strings without NUL bytes")
        if stdin is not None and not isinstance(stdin, bytes):
            raise TypeError("stdin must be bytes or None")
        secrets = [_as_secret_bytes(value) for value in sensitive_values]
        now = time.monotonic()
        with self._lock:
            for secret in secrets:
                self._register_secret_locked(secret)
            command_arguments, replayable = self._redacted_arguments_locked(arguments)
            entry = _Entry(
                identifier=self._next_identifier,
                kind="command",
                step=self._redact_text_locked(step, _REDACTED_SECRET.decode()),
                outcome="running",
                command=shlex.join(command_arguments),
                cwd=self._redact_text_locked(cwd, _REDACTED_SECRET.decode()),
                replayable=replayable,
                argv=list(command_arguments),
            )
            self._next_identifier += 1
            handle = CommandHandle(self, entry, now)
            entry.handle = handle
            if stdin is not None:
                handle._has_stdin = True
                self._append_retained_bytes(handle, "stdin", self._redact_bytes_locked(stdin))
            observer = self._append_locked(entry)
            self._last_output_notification[entry.identifier] = now
            self._enforce_total_budget_locked()
        self._notify(observer)
        return handle

    def record_internal(
        self,
        step: str,
        title: str,
        *,
        outcome: str,
        detail: str,
        duration_ms: int,
    ) -> None:
        _require_text(step, "step")
        _require_text(title, "title")
        _require_text(outcome, "outcome")
        _require_text(detail, "detail")
        if not isinstance(duration_ms, int) or duration_ms < 0:
            raise ValueError("duration_ms must be a non-negative integer")
        with self._lock:
            entry = _Entry(
                identifier=self._next_identifier,
                kind="internal",
                step=self._redact_text_locked(step, _REDACTED_SECRET.decode()),
                outcome=self._redact_text_locked(outcome, _REDACTED_SECRET.decode()),
                title=self._redact_text_locked(title, _REDACTED_SECRET.decode()),
                detail=self._redact_text_locked(detail, _REDACTED_SECRET.decode()),
                duration_ms=duration_ms,
            )
            self._next_identifier += 1
            observer = self._append_locked(entry)
            self._enforce_total_budget_locked()
        self._notify(observer)

    def snapshot(self) -> list[dict[str, object]]:
        """Return new JSON-safe dictionaries, never the journal's mutable state."""

        with self._lock:
            return copy.deepcopy([self._snapshot_entry_locked(entry) for entry in self._entries])

    def sanitize_snapshot(self, snapshot: list[dict[str, object]]) -> list[dict[str, object]]:
        """Return a copied public snapshot scrubbed with every known secret.

        Supervisors use this for retained, previously published revisions when
        a secret is registered after the original snapshot was recorded.
        """

        with self._lock:
            current = {
                entry.identifier: self._snapshot_entry_locked(entry)
                for entry in self._entries
            }
            sanitized = self._sanitize_snapshot_value_locked(snapshot)
            for original, entry in zip(snapshot, sanitized):
                if not isinstance(entry, dict):
                    continue
                latest = current.get(entry.get("id"))
                if latest is not None:
                    entry["command"] = latest["command"]
                    entry["replayable"] = latest["replayable"]
                    continue
                if not isinstance(original, dict):
                    continue
                command = original.get("command")
                if not isinstance(command, str):
                    continue
                try:
                    arguments = shlex.split(command)
                except ValueError:
                    entry["command"] = _REDACTED_SECRET.decode()
                    entry["replayable"] = False
                    continue
                arguments, replayable = self._redacted_arguments_locked(arguments)
                entry["command"] = shlex.join(arguments)
                if not replayable:
                    entry["replayable"] = False
            return sanitized

    def _update(self, handle: CommandHandle, *, stdout: bytes, stderr: bytes) -> None:
        if not isinstance(stdout, bytes) or not isinstance(stderr, bytes):
            raise TypeError("stdout and stderr must be bytes")
        if not stdout and not stderr:
            return
        with self._lock:
            if handle._finished:
                return
            self._append_stream_locked(handle, "stdout", stdout)
            self._append_stream_locked(handle, "stderr", stderr)
            observer: Callable[[], None] | None = None
            now = time.monotonic()
            identifier = handle._entry.identifier
            first_output = identifier not in self._output_notification_sent
            if handle._entry.retained and (
                first_output
                or now - self._last_output_notification.get(identifier, float("-inf"))
                >= self._update_interval
            ):
                self._output_notification_sent.add(identifier)
                self._last_output_notification[handle._entry.identifier] = now
                observer = self._observer
            self._enforce_total_budget_locked()
        self._notify(observer)

    def _finish(self, handle: CommandHandle, *, returncode: int | None, outcome: str) -> None:
        _require_text(outcome, "outcome")
        if returncode is not None and not isinstance(returncode, int):
            raise TypeError("returncode must be an integer or None")
        now = time.monotonic()
        with self._lock:
            if handle._finished:
                return
            handle._finished = True
            self._flush_pending_locked(handle, "stdout")
            self._flush_pending_locked(handle, "stderr")
            entry = handle._entry
            entry.outcome = self._redact_text_locked(outcome, _REDACTED_SECRET.decode())
            entry.returncode = returncode
            entry.duration_ms = max(0, int((now - handle._started_at) * 1000))
            self._enforce_total_budget_locked()
            observer = self._observer if entry.retained else None
        self._notify(observer)

    def _register_secret_locked(self, secret: bytes) -> None:
        if secret not in self._secrets:
            if len(self._secrets) >= self._max_secrets:
                raise ValueError("secret registry is full")
            self._secrets.append(secret)
            self._secrets.sort(key=len, reverse=True)

    def _scrub_existing_locked(self) -> None:
        for entry in self._entries:
            if entry.handle is not None:
                for stream in ("stdin", "stdout", "stderr"):
                    self._scrub_stream_locked(entry.handle, stream)
            for field in ("step", "outcome", "title", "detail", "cwd", "stdin"):
                value = getattr(entry, field)
                if value is not None:
                    setattr(entry, field, self._redact_text_locked(value, _REDACTED_SECRET.decode()))
            if entry.argv is not None:
                arguments, replayable = self._redacted_arguments_locked(entry.argv)
                entry.argv = arguments
                entry.command = shlex.join(arguments)
                if not replayable:
                    entry.replayable = False
        self._enforce_total_budget_locked()

    def _sanitize_snapshot_value_locked(self, value: Any) -> Any:
        if isinstance(value, str):
            return self._redact_text_locked(value, _REDACTED_SECRET.decode())
        if isinstance(value, list):
            return [self._sanitize_snapshot_value_locked(item) for item in value]
        if isinstance(value, dict):
            sanitized = {
                key: self._sanitize_snapshot_value_locked(item)
                for key, item in value.items()
            }
            if (
                isinstance(value.get("command"), str)
                and sanitized["command"] != value["command"]
            ):
                sanitized["replayable"] = False
            return sanitized
        return copy.deepcopy(value)

    def _scrub_stream_locked(self, handle: CommandHandle, stream: str) -> None:
        buffer = getattr(handle, f"_{stream}")
        pending_name = f"_{stream}_pending"
        pending = getattr(handle, pending_name)
        redacted = self._redact_bytes_locked(bytes(buffer) + pending)
        hold_back = self._partial_secret_suffix_length_locked(redacted)
        retained, pending = (
            (redacted[:-hold_back], redacted[-hold_back:])
            if hold_back
            else (redacted, b"")
        )
        buffer.clear()
        buffer.extend(retained[: self._max_stream_bytes])
        setattr(handle, pending_name, pending)
        if len(retained) > self._max_stream_bytes:
            setattr(handle, f"_{stream}_truncated", True)

    def _redact_text_locked(self, value: str, replacement: str) -> str:
        for secret in self._secrets:
            try:
                secret_text = secret.decode()
            except UnicodeDecodeError:
                continue
            value = value.replace(secret_text, replacement)
        return value

    def _redacted_arguments_locked(self, arguments: list[str]) -> tuple[list[str], bool]:
        redacted: list[str] = []
        replayable = True
        redact_next = False
        for argument in arguments:
            if redact_next:
                if argument != _REDACTED_ARGUMENT:
                    self._register_secret_locked(argument.encode())
                redacted.append(_REDACTED_ARGUMENT)
                replayable = False
                redact_next = False
                continue
            if _is_sensitive_option(argument):
                if "=" in argument:
                    option, value = argument.split("=", 1)
                    if value != _REDACTED_ARGUMENT:
                        self._register_secret_locked(value.encode())
                    redacted.append(f"{option}={_REDACTED_ARGUMENT}")
                    replayable = False
                else:
                    redacted.append(argument)
                    redact_next = True
                continue
            header = _redact_authorization_header(argument)
            if header is not None:
                redacted_argument, secret = header
                if secret != _REDACTED_ARGUMENT:
                    self._register_secret_locked(secret.encode())
                redacted.append(redacted_argument)
                replayable = False
                continue
            safe_argument = argument
            safe_argument = self._redact_text_locked(safe_argument, _REDACTED_ARGUMENT)
            if safe_argument != argument:
                replayable = False
            redacted.append(safe_argument)
        return redacted, replayable

    def _redact_bytes_locked(self, value: bytes) -> bytes:
        for secret in self._secrets:
            value = value.replace(secret, _REDACTED_SECRET)
        return value

    def _append_stream_locked(self, handle: CommandHandle, stream: str, value: bytes) -> None:
        if not value:
            return
        pending_name = f"_{stream}_pending"
        pending = getattr(handle, pending_name)
        combined = pending + value
        hold_back = self._partial_secret_suffix_length_locked(combined)
        process, pending = (
            (combined[:-hold_back], combined[-hold_back:]) if hold_back else (combined, b"")
        )
        setattr(handle, pending_name, pending)
        self._append_retained_bytes(handle, stream, self._redact_bytes_locked(process))

    def _flush_pending_locked(self, handle: CommandHandle, stream: str) -> None:
        pending_name = f"_{stream}_pending"
        pending = getattr(handle, pending_name)
        if pending:
            self._append_retained_bytes(handle, stream, self._redact_bytes_locked(pending))
            setattr(handle, pending_name, b"")

    def _partial_secret_suffix_length_locked(self, value: bytes) -> int:
        """Keep only a suffix that could become a registered secret next chunk."""

        longest = 0
        for secret in self._secrets:
            for length in range(1, min(len(secret), len(value) + 1)):
                if length > longest and value.endswith(secret[:length]):
                    longest = length
        return longest

    def _append_retained_bytes(self, handle: CommandHandle, stream: str, value: bytes) -> None:
        buffer = getattr(handle, f"_{stream}")
        remaining = self._max_stream_bytes - len(buffer)
        if remaining > 0:
            buffer.extend(value[:remaining])
        if len(value) > remaining:
            setattr(handle, f"_{stream}_truncated", True)

    def _append_locked(self, entry: _Entry) -> Callable[[], None] | None:
        self._entries.append(entry)
        if len(self._entries) > self._max_entries:
            evicted = self._entries.popleft()
            self._evict_locked(evicted)
        return self._observer

    def _enforce_total_budget_locked(self) -> None:
        while self._entries and self._serialized_snapshot_bytes_locked() > self._max_total_bytes:
            self._evict_locked(self._entries.popleft())

    def _serialized_snapshot_bytes_locked(self) -> int:
        snapshot = [self._snapshot_entry_locked(entry) for entry in self._entries]
        return len(
            json.dumps(snapshot, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
        )

    def _evict_locked(self, entry: _Entry) -> None:
        entry.retained = False
        self._last_output_notification.pop(entry.identifier, None)
        self._output_notification_sent.discard(entry.identifier)

    def _snapshot_entry_locked(self, entry: _Entry) -> dict[str, Any]:
        stdout: str | None = None
        stderr: str | None = None
        stdin: str | None = entry.stdin
        if entry.handle is not None:
            if entry.handle._has_stdin:
                stdin = self._render_stream(entry.handle._stdin, entry.handle._stdin_truncated)
            stdout = self._render_stream(entry.handle._stdout, entry.handle._stdout_truncated)
            stderr = self._render_stream(entry.handle._stderr, entry.handle._stderr_truncated)
        return {
            "id": entry.identifier,
            "kind": entry.kind,
            "step": entry.step,
            "title": entry.title,
            "outcome": entry.outcome,
            "status": self._semantic_status(entry),
            "detail": entry.detail,
            "command": entry.command,
            "cwd": entry.cwd,
            "stdin": stdin,
            "stdout": stdout,
            "stderr": stderr,
            "returncode": entry.returncode,
            "duration_ms": entry.duration_ms,
            "replayable": entry.replayable,
        }

    @staticmethod
    def _semantic_status(entry: _Entry) -> str:
        outcome = entry.outcome.casefold()
        if outcome == "running":
            return "running"
        if outcome in {"stopped", "cancelled"}:
            return "stopped"
        if re.search(r"fail|error|timeout|overflow|retained", outcome):
            return "failed"
        if entry.returncode not in {None, 0}:
            return "failed"
        return "succeeded"

    def _render_stream(self, buffer: bytearray, truncated: bool) -> str:
        text = self._decode(bytes(buffer))
        if truncated:
            return f"{text}\n<truncated: {self._max_stream_bytes} bytes retained>"
        return text

    @staticmethod
    def _decode(value: bytes) -> str:
        return value.decode("utf-8", errors="replace")

    @staticmethod
    def _notify(observer: Callable[[], None] | None) -> None:
        if observer is not None:
            observer()


__all__ = ["CommandHandle", "TranscriptJournal"]
