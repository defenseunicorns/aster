"""Bounded, sanitized operation records shared by quickstart observers."""

from __future__ import annotations

from collections import deque
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from datetime import datetime, timezone
import math
import re
import threading
import time
from types import MappingProxyType
from typing import Literal


DetailLevel = Literal["compact", "guided", "debug"]
SafeScalar = str | int | float | bool | None

MAX_JOURNAL_LIMIT = 1_024
MAX_ACTION_LENGTH = 64
MAX_NODE_LENGTH = 64
MAX_OUTCOME_LENGTH = 64
MAX_MESSAGE_LENGTH = 512
MAX_EXPLANATION_LENGTH = 512
MAX_DEBUG_FIELDS = 32
MAX_DEBUG_KEY_LENGTH = 64
MAX_DEBUG_VALUE_LENGTH = 256

_SECRET_VALUE = re.compile(
    r"(?:bearer\s+\S+|(?:token|secret|password|credential|private[_ -]?key)\s*[:=]\s*\S+|-----begin\s+[^-]*private\s+key-----|^MII[A-Za-z0-9+/]{20,}={0,2}$|^[A-Za-z0-9+/]{48,}={0,2}$|^[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}$)",
    re.IGNORECASE,
)
_CONTROL = re.compile(r"[\x00-\x1f\x7f]")
_PATH_VALUE = re.compile(r"(?<!\w)(?:~[\\/]|\.{1,2}[\\/]|[A-Za-z]:[\\/]|/)[^\s,;\)\]]+")
_RELATIVE_PATH = re.compile(r"(?<!\w)[A-Za-z0-9_.~-]+[\\/][^\s,;\)\]]+")
_RAW_CHILD_OUTPUT = re.compile(
    r"(?:^|[\s:\[(])(stdout|stderr|raw(?:\s+child)?(?:\s+process)?\s+output|child(?:\s+process)?\s+output)(?:$|[\s:\])])",
    re.IGNORECASE,
)
_HISTORY_GAP_MESSAGE = re.compile(r"history before sequence [1-9][0-9]* is no longer available")
_DISPLAY_COPY = frozenset(
    {
        "started",
        "starting",
        "ready",
        "running",
        "stopped",
        "stopping",
        "failed",
        "authenticated",
        "received",
        "cleaned up",
        "cleanup failed",
        "Event committed",
        "Event received",
        "The publisher committed the Event; send another when ready.",
        "Some earlier records have expired from the bounded history.",
        "Intentional UI copy",
        "The node is ready for the next action.",
        "Start the publisher and receiver when ready.",
        "The node is starting; wait for it to become ready.",
        "The node is ready; start the other node or authenticate the pair.",
        "The node is stopping and pair authentication is no longer valid.",
        "Restart the node before authenticating the pair again.",
        "Both nodes restart with reciprocal peer configuration.",
        "Authentication verified; send an Event when ready.",
        "Owned processes are stopping before disposable data is removed.",
        "All owned processes and disposable data are removed.",
        "The action failed safely; clean up or retry an available action.",
    }
)
_RECORD_ACTIONS = frozenset(
    {
        "initialize",
        "start",
        "ready",
        "stop",
        "authenticate",
        "publish",
        "commit",
        "receive",
        "transport",
        "restore",
        "cleanup",
        "error",
        "history-gap",
    }
)
_RECORD_NODES = frozenset({"publisher", "receiver"})
_RECORD_OUTCOMES = frozenset(
    {
        "ok",
        "initialized",
        "started",
        "running",
        "stopped",
        "authenticated",
        "committed",
        "received",
        "unavailable",
        "restored",
        "cleaned",
        "failed",
        "truncated",
    }
)
_DEBUG_STRING_FORMATS = {
    "command": frozenset({
        "aster playground-init",
        "aster-agent",
        "asterctl publication-init",
        "asterctl subscribe",
        "asterctl publish",
        "asterctl publication-ack",
    }),
    "confined_path": re.compile(r"logs/node-[01]/run-[1-9][0-9]{0,8}"),
    "event_id": re.compile(r"[0-9a-f]{64}"),
    "log_name": re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,63}"),
    "state": frozenset({"starting", "running", "stopping", "stopped", "failed", "ready"}),
    "from_state": frozenset({"starting", "running", "stopping", "stopped", "failed", "unauthenticated", "authenticating", "authenticated"}),
    "to_state": frozenset({"starting", "running", "stopping", "stopped", "failed", "unauthenticated", "authenticating", "authenticated"}),
    "status": frozenset({"ok", "failed", "committed", "received", "available", "unavailable"}),
    "transport": frozenset({"loopback", "unavailable", "restored"}),
    "operation": frozenset({"initialize", "start", "stop", "authenticate", "publish", "cleanup"}),
}
_DEBUG_NUMERIC_KEYS = frozenset(
    {"pid", "port", "payload_bytes", "owned_processes", "first_retained_sequence"}
)
_DEBUG_BOOL_KEYS = frozenset(
    {"durable", "observed", "success", "port_reserved", "socket_closed", "workspace_removed", "descriptor_removed"}
)


def _secret_key(value: str) -> bool:
    normalized = re.sub(r"[^a-z0-9]", "", value.casefold())
    return any(
        marker in normalized
        for marker in (
            "token",
            "secret",
            "password",
            "passwd",
            "credential",
            "bearer",
            "authorization",
            "privatekey",
        )
    )


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


def _bounded_text(value: str, *, name: str, maximum: int) -> str:
    if type(value) is not str:
        raise TypeError(f"{name} must be a string")
    if not value or len(value) > maximum:
        raise ValueError(f"{name} is outside its bound")
    if (
        _CONTROL.search(value)
        or _SECRET_VALUE.search(value)
        or _PATH_VALUE.search(value)
        or _RELATIVE_PATH.search(value)
        or _RAW_CHILD_OUTPUT.search(value)
        or value in {"/", ".", ".."}
    ):
        raise ValueError(f"{name} contains unsafe display data")
    return value


def _display_text(value: str, *, name: str, maximum: int) -> str:
    value = _bounded_text(value, name=name, maximum=maximum)
    if value not in _DISPLAY_COPY and not _HISTORY_GAP_MESSAGE.fullmatch(value):
        raise ValueError(f"{name} is not an allowed display copy")
    return value


def _structured_text(
    value: str,
    *,
    name: str,
    maximum: int,
    allowed: frozenset[str],
) -> str:
    value = _bounded_text(value, name=name, maximum=maximum)
    if value not in allowed:
        raise ValueError(f"{name} is not an allowed structured value")
    return value


def _optional_display_text(value: str | None, *, name: str, maximum: int) -> str | None:
    if value is None:
        return None
    return _display_text(value, name=name, maximum=maximum)


def _freeze_debug(debug: Mapping[str, SafeScalar]) -> Mapping[str, SafeScalar]:
    if not isinstance(debug, Mapping):
        raise TypeError("debug must be a mapping")
    copied: dict[str, SafeScalar] = {}
    for index, key in enumerate(debug, start=1):
        if index > MAX_DEBUG_FIELDS:
            raise ValueError("debug has too many fields")
        value = debug[key]
        key = _bounded_text(key, name="debug key", maximum=MAX_DEBUG_KEY_LENGTH)
        if _secret_key(key):
            raise ValueError("debug contains a secret-shaped field")
        if value is not None and type(value) not in {str, int, float, bool}:
            raise TypeError("debug values must be safe scalar values")
        known_key = (
            key in _DEBUG_STRING_FORMATS
            or key in _DEBUG_NUMERIC_KEYS
            or key in _DEBUG_BOOL_KEYS
        )
        if not known_key:
            raise ValueError("debug key is not allowlisted")
        if value is None:
            copied[key] = None
            continue
        if isinstance(value, str):
            format_rule = _DEBUG_STRING_FORMATS.get(key)
            if format_rule is None:
                raise ValueError("debug string key is not allowlisted")
            if key in {"event_id", "confined_path"}:
                if _CONTROL.search(value) or len(value) > MAX_DEBUG_VALUE_LENGTH:
                    raise ValueError("debug string value has an invalid format")
            else:
                value = _bounded_text(value, name="debug value", maximum=MAX_DEBUG_VALUE_LENGTH)
            if isinstance(format_rule, frozenset):
                allowed = value in format_rule
            else:
                allowed = format_rule.fullmatch(value) is not None
            if not allowed:
                raise ValueError("debug string value has an invalid format")
        elif key in _DEBUG_NUMERIC_KEYS:
            if type(value) is not int:
                raise TypeError("debug numeric value has an invalid type")
            if value < 0:
                raise ValueError("debug numeric value is outside its bound")
            if key == "pid" and value < 1:
                raise ValueError("debug process ID is outside its bound")
            if key == "port" and not 1 <= value <= 65_535:
                raise ValueError("debug port is outside its bound")
            if key == "payload_bytes" and value > 4_096:
                raise ValueError("debug payload size is outside its bound")
            if key == "owned_processes" and value > 8:
                raise ValueError("debug process count is outside its bound")
        elif key in _DEBUG_BOOL_KEYS:
            if type(value) is not bool:
                raise TypeError("debug boolean value has an invalid type")
        else:
            raise TypeError("debug string value has an invalid type")
        copied[key] = value
    return MappingProxyType(copied)


@dataclass(frozen=True)
class TerminalRecord:
    """One immutable, sanitized fact emitted by a quickstart operation."""

    sequence: int
    timestamp: str
    action: str
    node: str | None
    outcome: str
    message: str
    explanation: str | None
    debug: Mapping[str, SafeScalar]

    def __post_init__(self) -> None:
        if type(self.sequence) is not int or self.sequence < 0:
            raise ValueError("sequence must be a non-negative integer")
        timestamp = _bounded_text(self.timestamp, name="timestamp", maximum=64)
        action = _structured_text(
            self.action,
            name="action",
            maximum=MAX_ACTION_LENGTH,
            allowed=_RECORD_ACTIONS,
        )
        if self.node is not None:
            node = _structured_text(
                self.node,
                name="node",
                maximum=MAX_NODE_LENGTH,
                allowed=_RECORD_NODES,
            )
        else:
            node = None
        outcome = _structured_text(
            self.outcome,
            name="outcome",
            maximum=MAX_OUTCOME_LENGTH,
            allowed=_RECORD_OUTCOMES,
        )
        message = _display_text(self.message, name="message", maximum=MAX_MESSAGE_LENGTH)
        explanation = _optional_display_text(
            self.explanation,
            name="explanation",
            maximum=MAX_EXPLANATION_LENGTH,
        )
        object.__setattr__(self, "timestamp", timestamp)
        object.__setattr__(self, "action", action)
        object.__setattr__(self, "node", node)
        object.__setattr__(self, "outcome", outcome)
        object.__setattr__(self, "message", message)
        object.__setattr__(self, "explanation", explanation)
        object.__setattr__(self, "debug", _freeze_debug(self.debug))


class RecordJournal:
    """A thread-safe journal with bounded history and blocking readers."""

    def __init__(
        self,
        limit: int = 128,
        clock: Callable[[], datetime] = _utc_now,
    ) -> None:
        if type(limit) is not int or not 0 < limit <= MAX_JOURNAL_LIMIT:
            raise ValueError("limit is outside its bound")
        if not callable(clock):
            raise TypeError("clock must be callable")
        self._records: deque[TerminalRecord] = deque(maxlen=limit)
        self._clock = clock
        self._next_sequence = 1
        self._changed = threading.Condition(threading.RLock())

    def emit(
        self,
        *,
        action: str,
        node: str | None,
        outcome: str,
        message: str,
        explanation: str | None = None,
        debug: Mapping[str, SafeScalar] | None = None,
    ) -> TerminalRecord:
        """Validate, freeze, and append one record."""
        with self._changed:
            timestamp = self._clock()
            if not isinstance(timestamp, datetime):
                raise TypeError("clock must return a datetime")
            record = TerminalRecord(
                sequence=self._next_sequence,
                timestamp=timestamp.isoformat(),
                action=action,
                node=node,
                outcome=outcome,
                message=message,
                explanation=explanation,
                debug={} if debug is None else debug,
            )
            self._records.append(record)
            self._next_sequence += 1
            self._changed.notify_all()
            return record

    def records_after(
        self,
        sequence: int,
        timeout: float | None = None,
    ) -> list[TerminalRecord]:
        """Return records newer than ``sequence``, waiting for one if needed."""
        if type(sequence) is not int or sequence < 0:
            raise ValueError("sequence must be a non-negative integer")
        if timeout is not None:
            if type(timeout) not in {int, float} or not math.isfinite(timeout) or timeout < 0:
                raise ValueError("timeout must be a non-negative finite number or None")
        deadline = None if timeout is None else time.monotonic() + timeout
        with self._changed:
            while True:
                records = self._records_after_locked(sequence)
                if records:
                    return list(records)
                if timeout == 0:
                    return []
                remaining = None if deadline is None else deadline - time.monotonic()
                if remaining is not None and remaining <= 0:
                    return []
                self._changed.wait(timeout=remaining)

    def latest_sequence(self) -> int:
        """Return the greatest sequence committed to the journal."""

        with self._changed:
            return self._next_sequence - 1

    def _records_after_locked(self, sequence: int) -> list[TerminalRecord]:
        if not self._records:
            return []
        first = self._records[0]
        records = [record for record in self._records if record.sequence > sequence]
        if sequence < first.sequence - 1:
            gap_sequence = first.sequence - 1
            gap = TerminalRecord(
                sequence=gap_sequence,
                timestamp=first.timestamp,
                action="history-gap",
                node=None,
                outcome="truncated",
                message=f"history before sequence {first.sequence} is no longer available",
                explanation="Some earlier records have expired from the bounded history.",
                debug={"first_retained_sequence": first.sequence},
            )
            return [gap, *records]
        return records


def parse_detail(value: str) -> DetailLevel:
    """Parse the user-facing terminal detail level."""
    if type(value) is not str:
        raise TypeError("detail must be a string")
    normalized = value.strip().lower()
    if normalized not in {"compact", "guided", "debug"}:
        raise ValueError("detail must be compact, guided, or debug")
    return normalized  # type: ignore[return-value]


def render_record(record: TerminalRecord, detail: DetailLevel) -> str:
    """Render one canonical record without introducing any new data."""
    if not isinstance(record, TerminalRecord):
        raise TypeError("record must be a TerminalRecord")
    detail = parse_detail(detail)
    location = "" if record.node is None else f" {record.node}"
    rendered = f"[{record.action}]{location} {record.outcome}: {record.message}"
    if detail in {"guided", "debug"} and record.explanation is not None:
        rendered += f"\n  {record.explanation}"
    if detail == "debug" and record.debug:
        fields = ", ".join(f"{key}={_display_scalar(value)}" for key, value in sorted(record.debug.items()))
        rendered += f"\n  debug: {fields}"
    return rendered


def _display_scalar(value: SafeScalar) -> str:
    if value is None:
        return "None"
    if isinstance(value, bool):
        return "true" if value else "false"
    return str(value)


__all__ = [
    "DetailLevel",
    "SafeScalar",
    "TerminalRecord",
    "RecordJournal",
    "render_record",
    "parse_detail",
]
