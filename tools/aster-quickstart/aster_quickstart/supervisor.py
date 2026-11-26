"""One authoritative, sanitized state machine for the guided quickstart."""

from __future__ import annotations

from collections import deque
from copy import deepcopy
import json
import math
import re
import threading
import time
from collections.abc import Callable
from typing import Any

from .aster_session import RecoverableOfflinePublishError
from .records import RecordJournal
from .transcript import TranscriptJournal


NODE_ROLES = ("publisher", "receiver")
NODE_STATES = frozenset({"stopped", "starting", "running", "stopping", "failed"})
REVISION_HISTORY_LIMIT = 64
REVISION_HISTORY_BYTES_LIMIT = 2_097_152
MAX_EVENT_BYTES = 4_096
_FAILED_STAGES = frozenset(
    {"workspace", "publisher", "receiver", "authentication", "event", "experiment", "cleanup"}
)

_IDENTITY_FINGERPRINT = re.compile(r"[0-9a-f]{64}")
_EVENT_ID = re.compile(r"[0-9a-f]{64}")
_OPERATION_ERROR_MESSAGE = "The quickstart operation failed."
_CLEANUP_ERROR_MESSAGE = "The quickstart cleanup failed."


class SupervisorStateError(RuntimeError):
    """The requested supervisor action is unavailable in the current state."""


class SupervisorBusyError(SupervisorStateError):
    """A state-changing supervisor operation is already in progress."""


class EventValidationError(ValueError):
    """The submitted Event is outside the bounded quickstart contract."""


class QuickstartSupervisor:
    """Own quickstart state while delegating real work to one ``AsterSession``.

    The session is the production boundary; this class only changes a terminal
    state to success after its matching session method has returned a validated
    receipt.  Every public mutation is serialized by one non-blocking lock.
    """

    def __init__(
        self,
        session: Any,
        records: RecordJournal,
        shutdown_requested: threading.Event,
        cleanup_finalizer: Callable[[], dict[str, Any]] | None = None,
        transcript: TranscriptJournal | None = None,
    ) -> None:
        if not isinstance(records, RecordJournal):
            raise TypeError("records must be a RecordJournal")
        if not callable(getattr(shutdown_requested, "set", None)):
            raise TypeError("shutdown_requested must be an event")
        if cleanup_finalizer is not None and not callable(cleanup_finalizer):
            raise TypeError("cleanup_finalizer must be callable")
        if transcript is not None and not isinstance(transcript, TranscriptJournal):
            raise TypeError("transcript must be a TranscriptJournal or None")
        self._session = session
        self._records = records
        self._shutdown_requested = shutdown_requested
        self._cleanup_finalizer = cleanup_finalizer or (lambda: {})
        self._transcript = transcript
        self._transcript_bound = transcript is not None
        self._state_lock = threading.RLock()
        self._revision_changed = threading.Condition(self._state_lock)
        self._revision_history: deque[dict[str, Any]] = deque()
        self._revision_history_bytes = 0
        self._mutation_lock = threading.Lock()
        self._cleaned = False
        self._state: dict[str, Any] = {
            "revision": 0,
            "record_sequence": 0,
            "initialized": False,
            "cleanup": None,
            "operation": "initializing",
            "nodes": {
                role: {"state": "stopped", "identity_fingerprint": None}
                for role in NODE_ROLES
            },
            "authentication": {"state": "unauthenticated"},
            "pair_transition": None,
            "failed_stage": None,
            "available_actions": [],
            "message": None,
            "commit": None,
            "receipt": None,
            "first_delivery": None,
            "experiment": None,
            "error": None,
            "transcript": [],
        }
        if transcript is not None:
            with self._state_lock:
                transcript.set_observer(self._on_transcript_changed)
                self._state["transcript"] = transcript.snapshot()
        self._initialize()

    def snapshot(self) -> dict[str, Any]:
        """Return a caller-independent sanitized state snapshot."""

        with self._state_lock:
            return deepcopy(self._state)

    def snapshots_after(self, revision: int, timeout: float | None) -> list[dict[str, Any]]:
        """Return retained snapshots newer than ``revision`` in order."""

        if type(revision) is not int or revision < 0:
            raise ValueError("revision must be a non-negative integer")
        if timeout is not None and (
            type(timeout) not in {int, float} or not math.isfinite(timeout) or timeout < 0
        ):
            raise ValueError("timeout must be a non-negative finite number or None")
        deadline = None if timeout is None else time.monotonic() + timeout
        with self._revision_changed:
            while self._state["revision"] <= revision:
                if timeout == 0:
                    return []
                remaining = None if deadline is None else deadline - time.monotonic()
                if remaining is not None and remaining <= 0:
                    return []
                self._revision_changed.wait(timeout=remaining)
            if not self._revision_history or revision < self._revision_history[0]["revision"] - 1:
                state = deepcopy(self._state)
                state["stream"] = {
                    "mode": "full_resync",
                    "after_revision": revision,
                }
                if self._revision_history:
                    state["stream"]["first_retained_revision"] = self._revision_history[0][
                        "revision"
                    ]
                else:
                    state["stream"]["reason"] = "history_budget"
                return [state]
            states = []
            for retained in self._revision_history:
                if retained["revision"] <= revision:
                    continue
                state = deepcopy(retained)
                state["stream"] = {"mode": "incremental"}
                states.append(state)
            return states

    def start_node(self, role: str) -> dict[str, str]:
        """Start one node after the session confirms it is running."""

        self._require_role(role)
        with self._mutation():
            with self._state_lock:
                self._require_active_locked()
                current = self._state["nodes"][role]["state"]
                if current == "running":
                    raise SupervisorStateError("action is unavailable in the current state")
                if current not in {"stopped", "failed"}:
                    raise SupervisorStateError("action is unavailable in the current state")
                self._state["operation"] = "starting"
                self._set_failed_stage_locked(None)
                self._state["nodes"][role]["state"] = "starting"
                self._state["error"] = None
                self._record_revision_locked()

            self._emit(
                action="start",
                node=role,
                outcome="ok",
                message="starting",
                debug={"operation": "start", "from_state": current, "to_state": "starting"},
            )
            try:
                receipt = self._require_node_receipt(self._session.start_node(role), role, "running")
            except Exception:
                self._fail_operation("start", (role,))
                raise RuntimeError(_OPERATION_ERROR_MESSAGE) from None

            with self._state_lock:
                self._state["nodes"][role]["state"] = "running"
                self._state["operation"] = None
                self._state["error"] = None
                self._record_revision_locked()
            self._emit(
                action="ready",
                node=role,
                outcome="running",
                message="running",
                debug={
                    "operation": "start",
                    "from_state": "starting",
                    "to_state": "running",
                    **self._node_debug_facts(receipt),
                },
            )
            return receipt

    def stop_node(self, role: str) -> dict[str, str]:
        """Stop one node and invalidate pair authentication immediately."""

        self._require_role(role)
        with self._mutation():
            with self._state_lock:
                self._require_active_locked()
                current = self._state["nodes"][role]["state"]
                if current == "stopped":
                    raise SupervisorStateError("action is unavailable in the current state")
                if current != "running":
                    raise SupervisorStateError("action is unavailable in the current state")
                self._state["operation"] = "stopping"
                self._set_failed_stage_locked(None)
                self._state["nodes"][role]["state"] = "stopping"
                self._invalidate_authentication_locked()
                self._state["error"] = None
                self._record_revision_locked()

            self._emit(
                action="stop",
                node=role,
                outcome="ok",
                message="stopping",
                debug={"operation": "stop", "from_state": "running", "to_state": "stopping"},
            )
            try:
                receipt = self._require_node_receipt(self._session.stop_node(role), role, "stopped")
            except Exception:
                self._fail_operation("stop", (role,))
                raise RuntimeError(_OPERATION_ERROR_MESSAGE) from None

            with self._state_lock:
                self._state["nodes"][role]["state"] = "stopped"
                self._state["operation"] = None
                self._state["error"] = None
                self._record_revision_locked()
            self._emit(
                action="stop",
                node=role,
                outcome="stopped",
                message="stopped",
                debug={
                    "operation": "stop",
                    "from_state": "stopping",
                    "to_state": "stopped",
                    **self._node_debug_facts(receipt),
                },
            )
            return receipt

    def authenticate(self) -> dict[str, str]:
        """Perform the session's controlled pair restart and challenge."""

        progress_seen = False
        with self._mutation():
            with self._state_lock:
                self._require_active_locked()
                if not self._all_nodes_in_state_locked("running") or self._is_authenticated_locked():
                    raise SupervisorStateError("action is unavailable in the current state")
                self._state["operation"] = "authenticating"
                self._set_failed_stage_locked(None)
                self._state["authentication"] = {"state": "authenticating"}
                self._state["pair_transition"] = {"state": "restarting_for_authentication"}
                self._state["error"] = None
                self._record_revision_locked()

            def progress(update: Any) -> None:
                nonlocal progress_seen
                if progress_seen or update != {"status": "authenticating"}:
                    raise TypeError("invalid authentication progress")
                progress_seen = True
                with self._state_lock:
                    if self._state["operation"] != "authenticating":
                        raise SupervisorStateError("authentication progress is unavailable")
                self._emit(
                    action="authenticate",
                    node=None,
                    outcome="ok",
                    message="starting",
                    debug={"operation": "authenticate", "status": "ok"},
                )

            try:
                receipt = self._require_authentication_receipt(self._session.authenticate(progress))
                if not progress_seen:
                    raise TypeError("authentication progress was omitted")
            except Exception:
                self._fail_operation("authenticate", NODE_ROLES)
                raise RuntimeError(_OPERATION_ERROR_MESSAGE) from None

            with self._state_lock:
                for role in NODE_ROLES:
                    self._state["nodes"][role]["state"] = "running"
                self._state["authentication"] = {"state": "authenticated", "verification": "verified"}
                self._state["pair_transition"] = None
                self._state["operation"] = None
                self._state["error"] = None
                self._record_revision_locked()
            self._emit(
                action="authenticate",
                node=None,
                outcome="authenticated",
                message="authenticated",
                debug={"operation": "authenticate", "success": True},
            )
            return receipt

    def publish_event(self, text: str) -> dict[str, Any]:
        """Publish one user Event, exposing durable commit before receipt."""

        self._validate_text(text)
        commit_progress: dict[str, Any] | None = None
        with self._mutation():
            with self._state_lock:
                self._require_publication_available_locked()
                self._state["operation"] = "publishing"
                self._set_failed_stage_locked(None)
                self._state["message"] = text
                self._state["commit"] = None
                self._state["receipt"] = None
                self._state["experiment"] = None
                self._state["error"] = None
                self._record_revision_locked()
            self._emit(
                action="publish",
                node="publisher",
                outcome="ok",
                message="starting",
                debug={"operation": "publish", "status": "ok"},
            )

            def progress(update: Any) -> None:
                nonlocal commit_progress
                if not isinstance(update, dict) or set(update) != {"commit"}:
                    raise TypeError("invalid publication progress")
                commit = self._require_commit(update["commit"], text)
                with self._state_lock:
                    if self._state["operation"] != "publishing" or commit_progress is not None:
                        raise SupervisorStateError("publication progress is unavailable")
                    commit_progress = deepcopy(commit)
                    self._state["commit"] = deepcopy(commit)
                    self._record_revision_locked()
                self._emit(
                    action="commit",
                    node="publisher",
                    outcome="committed",
                    message="Event committed",
                    explanation="The publisher committed the Event; send another when ready.",
                    debug={
                        "operation": "publish",
                        "event_id": commit["event_id"],
                        "payload_bytes": len(text.encode("utf-8")),
                        "durable": True,
                    },
                )

            try:
                result = self._require_publication_receipt(self._session.publish_with_progress(text, progress), text)
                if commit_progress is None or result["commit"] != commit_progress:
                    raise TypeError("publication commit progress is inconsistent")
            except Exception:
                self._fail_terminal_operation("publish")
                raise RuntimeError(_OPERATION_ERROR_MESSAGE) from None

            with self._state_lock:
                self._state["receipt"] = deepcopy(result["receipt"])
                if self._state["first_delivery"] is None:
                    self._state["first_delivery"] = {
                        "message": text,
                        "commit": deepcopy(result["commit"]),
                        "receipt": deepcopy(result["receipt"]),
                    }
                self._state["operation"] = None
                self._state["error"] = None
                # Publish the receipt record and its state revision while the
                # state lock excludes snapshots; neither fact can outrun its
                # matching watermark.
                self._emit(
                    action="receive",
                    node="receiver",
                    outcome="received",
                    message="Event received",
                    debug={
                        "operation": "publish",
                        "event_id": result["receipt"]["event_id"],
                        "payload_bytes": len(text.encode("utf-8")),
                        "observed": True,
                    },
                )
            return deepcopy(result)

    def run_offline_experiment(self, text: str) -> dict[str, Any]:
        """Run the optional post-delivery transport-unavailable experiment."""

        self._validate_text(text)
        with self._mutation():
            with self._state_lock:
                self._require_publication_available_locked()
                if self._state["first_delivery"] is None:
                    raise SupervisorStateError("action is unavailable in the current state")
                self._state["operation"] = "offline_experiment"
                self._set_failed_stage_locked(None)
                self._state["experiment"] = {"availability": None, "commit": None, "receipt": None}
                self._state["error"] = None
                self._record_revision_locked()
            self._emit(
                action="publish",
                node="publisher",
                outcome="ok",
                message="starting",
                debug={"operation": "publish", "status": "ok"},
            )

            def progress(update: Any) -> None:
                self._record_experiment_progress(text, update)

            try:
                result = self._require_publication_receipt(
                    self._session.offline_publish(text, progress=progress), text
                )
                with self._state_lock:
                    experiment = self._state["experiment"]
                    if (
                        self._state["operation"] != "offline_experiment"
                        or not isinstance(experiment, dict)
                        or experiment["availability"] != "available"
                        or experiment["commit"] != result["commit"]
                        or experiment["receipt"] != result["receipt"]
                    ):
                        raise TypeError("offline experiment progress is inconsistent")
                    self._state["operation"] = None
                    self._state["error"] = None
                    self._record_revision_locked()
            except RecoverableOfflinePublishError:
                self._fail_recoverable_experiment()
                raise RuntimeError(_OPERATION_ERROR_MESSAGE) from None
            except Exception:
                self._fail_terminal_operation("publish")
                raise RuntimeError(_OPERATION_ERROR_MESSAGE) from None
            return deepcopy(result)

    def cleanup(self) -> None:
        """Try one user-requested cleanup without waiting behind another action."""

        with self._mutation():
            self._cleanup_owned()

    def shutdown(self) -> None:
        """Cancel active work, wait for ownership, and attempt complete cleanup."""

        if not self._shutdown_requested.is_set():
            self._shutdown_requested.set()
        with self._mutation_lock:
            self._cleanup_owned()

    def _cleanup_owned(self) -> None:
        """Close the session while the caller owns the mutation lock."""

        with self._state_lock:
            if self._cleaned:
                if not self._shutdown_requested.is_set():
                    self._shutdown_requested.set()
                return
            self._state["operation"] = "cleaning"
            self._set_failed_stage_locked(None)
            self._state["pair_transition"] = None
            self._state["error"] = None
            self._record_revision_locked()
        self._emit(
            action="cleanup",
            node=None,
            outcome="ok",
            message="stopping",
            debug={"operation": "cleanup", "status": "ok"},
        )
        cleanup_evidence: dict[str, Any]
        try:
            self._session.close()
            cleanup_evidence = self._cleanup_finalizer()
            if not isinstance(cleanup_evidence, dict):
                raise TypeError("cleanup finalizer returned invalid evidence")
        except Exception:
            with self._state_lock:
                for role in NODE_ROLES:
                    self._state["nodes"][role]["state"] = "failed"
                self._invalidate_authentication_locked()
                self._state["pair_transition"] = None
                self._state["operation"] = None
                self._state["cleanup"] = "failed"
                self._set_failed_stage_locked("cleanup")
                self._state["error"] = self._cleanup_error()
                self._record_revision_locked()
            self._emit(
                action="error",
                node=None,
                outcome="failed",
                message="cleanup failed",
                debug={"operation": "cleanup", "status": "failed"},
            )
            raise RuntimeError(_CLEANUP_ERROR_MESSAGE) from None

        with self._state_lock:
            self._cleaned = True
            self._transcript_bound = False
            if self._transcript is not None:
                self._state["transcript"] = self._transcript.snapshot()
            self._state["initialized"] = False
            self._state["cleanup"] = "cleaned"
            self._set_failed_stage_locked(None)
            self._state["operation"] = None
            for role in NODE_ROLES:
                self._state["nodes"][role] = {"state": "stopped", "identity_fingerprint": None}
            self._invalidate_authentication_locked()
            self._state["pair_transition"] = None
            self._state["message"] = None
            self._state["commit"] = None
            self._state["receipt"] = None
            self._state["first_delivery"] = None
            self._state["experiment"] = None
            self._state["error"] = None
            self._record_revision_locked()
        if self._transcript is not None:
            self._transcript.set_observer(None)
        self._emit(
            action="cleanup",
            node=None,
            outcome="cleaned",
            message="cleaned up",
            debug={"operation": "cleanup", "success": True, **cleanup_evidence},
        )
        if not self._shutdown_requested.is_set():
            self._shutdown_requested.set()

    def close(self) -> None:
        """Use the blocking shutdown path for launcher termination."""

        self.shutdown()

    def _initialize(self) -> None:
        try:
            receipt = self._require_initialization_receipt(self._session.initialize())
        except Exception:
            with self._state_lock:
                self._state["operation"] = None
                for role in NODE_ROLES:
                    self._state["nodes"][role]["state"] = "failed"
                self._set_failed_stage_locked("workspace")
                self._state["error"] = self._operation_error()
                self._record_revision_locked()
            self._emit(
                action="error",
                node=None,
                outcome="failed",
                message="failed",
                debug={"operation": "initialize", "status": "failed"},
            )
            raise RuntimeError(_OPERATION_ERROR_MESSAGE) from None

        with self._state_lock:
            self._state["initialized"] = True
            self._state["operation"] = None
            for role in NODE_ROLES:
                self._state["nodes"][role] = {
                    "state": "stopped",
                    "identity_fingerprint": receipt["nodes"][role]["identity_fingerprint"],
                }
            self._state["error"] = None
            self._record_revision_locked()
        self._emit(
            action="initialize",
            node=None,
            outcome="initialized",
            message="ready",
            debug={"operation": "initialize", "status": "ok"},
        )

    def _record_experiment_progress(self, text: str, update: Any) -> None:
        if not isinstance(update, dict) or len(update) != 1:
            raise TypeError("invalid experiment progress")
        if "availability" in update:
            availability = update["availability"]
            if availability not in {"unavailable", "available"}:
                raise TypeError("invalid experiment availability")
            with self._state_lock:
                experiment = self._require_experiment_locked()
                expected = "unavailable" if experiment["availability"] is None else "available"
                if availability != expected or (availability == "available" and experiment["commit"] is None):
                    raise TypeError("experiment availability is inconsistent")
                experiment["availability"] = availability
                self._record_revision_locked()
            if availability == "unavailable":
                self._emit(
                    action="transport",
                    node=None,
                    outcome="unavailable",
                    message="stopping",
                    debug={"operation": "publish", "transport": "unavailable"},
                )
            else:
                self._emit(
                    action="restore",
                    node=None,
                    outcome="restored",
                    message="running",
                    debug={"operation": "publish", "transport": "restored"},
                )
            return

        if "commit" in update:
            commit = self._require_commit(update["commit"], text)
            with self._state_lock:
                experiment = self._require_experiment_locked()
                if experiment["availability"] != "unavailable" or experiment["commit"] is not None:
                    raise TypeError("experiment commit is inconsistent")
                experiment["commit"] = deepcopy(commit)
                self._record_revision_locked()
            self._emit(
                action="commit",
                node="publisher",
                outcome="committed",
                message="Event committed",
                explanation="The publisher committed the Event; send another when ready.",
                debug={
                    "operation": "publish",
                    "event_id": commit["event_id"],
                    "payload_bytes": len(text.encode("utf-8")),
                    "durable": True,
                },
            )
            return

        if "receipt" in update:
            receipt = self._require_receipt(update["receipt"], text)
            with self._state_lock:
                experiment = self._require_experiment_locked()
                if (
                    experiment["availability"] != "available"
                    or experiment["commit"] is None
                    or experiment["receipt"] is not None
                    or receipt["event_id"] != experiment["commit"]["event_id"]
                ):
                    raise TypeError("experiment receipt is inconsistent")
                experiment["receipt"] = deepcopy(receipt)
                self._record_revision_locked()
            self._emit(
                action="receive",
                node="receiver",
                outcome="received",
                message="Event received",
                debug={
                    "operation": "publish",
                    "event_id": receipt["event_id"],
                    "payload_bytes": len(text.encode("utf-8")),
                    "observed": True,
                },
            )
            return

        raise TypeError("invalid experiment progress")

    def _fail_operation(self, operation: str, roles: tuple[str, ...]) -> None:
        with self._state_lock:
            for role in roles:
                self._state["nodes"][role]["state"] = "failed"
            self._invalidate_authentication_locked()
            self._state["pair_transition"] = None
            if operation in {"start", "stop"} and len(roles) == 1:
                self._set_failed_stage_locked(roles[0])
            elif operation == "authenticate" and roles == NODE_ROLES:
                self._set_failed_stage_locked("authentication")
            else:
                raise ValueError("operation has no progress stage")
            self._state["operation"] = None
            self._state["error"] = self._operation_error()
            self._record_revision_locked()
        self._emit(
            action="error",
            node=roles[0] if len(roles) == 1 else None,
            outcome="failed",
            message="failed",
            debug={"operation": operation, "status": "failed"},
        )

    def _fail_terminal_operation(self, operation: str) -> None:
        """Fail closed when publication may have terminally closed the session."""

        with self._state_lock:
            self._state["initialized"] = False
            self._state["cleanup"] = None
            for role in NODE_ROLES:
                self._state["nodes"][role] = {"state": "failed", "identity_fingerprint": None}
            self._invalidate_authentication_locked()
            self._state["pair_transition"] = None
            self._set_failed_stage_locked("event")
            self._state["operation"] = None
            self._state["message"] = None
            self._state["commit"] = None
            self._state["receipt"] = None
            self._state["first_delivery"] = None
            self._state["experiment"] = None
            self._state["error"] = self._operation_error()
            self._record_revision_locked()
        self._emit(
            action="error",
            node=None,
            outcome="failed",
            message="failed",
            debug={"operation": operation, "status": "failed"},
        )

    def _fail_recoverable_experiment(self) -> None:
        """Record a typed, restored-topology experiment failure without lying."""

        with self._state_lock:
            if self._state["operation"] != "offline_experiment":
                raise SupervisorStateError("experiment recovery is unavailable")
            self._state["operation"] = None
            self._state["experiment"] = None
            self._set_failed_stage_locked("experiment")
            self._state["error"] = self._operation_error()
            self._record_revision_locked()
        self._emit(
            action="error",
            node=None,
            outcome="failed",
            message="failed",
            debug={"operation": "publish", "status": "failed"},
        )

    def _record_revision_locked(self) -> None:
        self._state["record_sequence"] = self._records.latest_sequence()
        self._state["available_actions"] = self._derive_available_actions_locked()
        self._state["revision"] += 1
        retained = deepcopy(self._state)
        self._revision_history.append(retained)
        self._revision_history_bytes += self._serialized_state_bytes(retained)
        self._trim_revision_history_locked()
        self._revision_changed.notify_all()

    def _on_transcript_changed(self) -> None:
        """Publish one immutable transcript replacement while this session is live."""

        if self._transcript is None:
            return
        with self._state_lock:
            if not self._transcript_bound or self._cleaned:
                return
            snapshot = self._transcript.snapshot()
            for retained in self._revision_history:
                retained["transcript"] = self._transcript.sanitize_snapshot(
                    retained["transcript"]
                )
            self._revision_history_bytes = sum(
                self._serialized_state_bytes(retained)
                for retained in self._revision_history
            )
            self._trim_revision_history_locked()
            if self._state["transcript"] == snapshot:
                return
            self._state["transcript"] = snapshot
            self._record_revision_locked()

    @staticmethod
    def _serialized_state_bytes(state: dict[str, Any]) -> int:
        return len(
            json.dumps(state, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
        )

    def _trim_revision_history_locked(self) -> None:
        while self._revision_history and (
            len(self._revision_history) > REVISION_HISTORY_LIMIT
            or self._revision_history_bytes > REVISION_HISTORY_BYTES_LIMIT
        ):
            removed = self._revision_history.popleft()
            self._revision_history_bytes -= self._serialized_state_bytes(removed)

    def _derive_available_actions_locked(self) -> list[str]:
        if self._cleaned or self._state["operation"] is not None:
            return []
        if self._state["cleanup"] == "failed" or not self._state["initialized"]:
            return ["cleanup"]

        actions: list[str] = []
        for role in NODE_ROLES:
            state = self._state["nodes"][role]["state"]
            if state in {"stopped", "failed"}:
                actions.append(f"start_{role}")
            elif state == "running":
                actions.append(f"stop_{role}")
        if self._all_nodes_in_state_locked("running"):
            if self._is_authenticated_locked():
                actions.append("publish_event")
                if self._state["first_delivery"] is not None:
                    actions.append("offline_experiment")
            else:
                actions.append("authenticate")
        actions.append("cleanup")
        return actions

    def _require_active_locked(self) -> None:
        if self._cleaned or not self._state["initialized"] or self._state["cleanup"] == "failed":
            raise SupervisorStateError("action is unavailable in the current state")

    def _require_publication_available_locked(self) -> None:
        self._require_active_locked()
        if not self._all_nodes_in_state_locked("running") or not self._is_authenticated_locked():
            raise SupervisorStateError("action is unavailable in the current state")

    def _all_nodes_in_state_locked(self, state: str) -> bool:
        return all(self._state["nodes"][role]["state"] == state for role in NODE_ROLES)

    def _is_authenticated_locked(self) -> bool:
        return self._state["authentication"].get("state") == "authenticated"

    def _invalidate_authentication_locked(self) -> None:
        self._state["authentication"] = {"state": "unauthenticated"}

    def _set_failed_stage_locked(self, stage: str | None) -> None:
        if stage is not None and stage not in _FAILED_STAGES:
            raise ValueError("failed stage is invalid")
        self._state["failed_stage"] = stage

    def _require_experiment_locked(self) -> dict[str, Any]:
        experiment = self._state["experiment"]
        if self._state["operation"] != "offline_experiment" or not isinstance(experiment, dict):
            raise SupervisorStateError("experiment progress is unavailable")
        return experiment

    class _Mutation:
        def __init__(self, supervisor: "QuickstartSupervisor") -> None:
            self._supervisor = supervisor

        def __enter__(self) -> "QuickstartSupervisor._Mutation":
            if not self._supervisor._mutation_lock.acquire(blocking=False):
                raise SupervisorBusyError("another quickstart operation is in progress")
            return self

        def __exit__(self, exc_type, exc_value, traceback) -> bool:
            self._supervisor._mutation_lock.release()
            return False

    def _mutation(self) -> "QuickstartSupervisor._Mutation":
        return self._Mutation(self)

    def _emit(
        self,
        *,
        action: str,
        node: str | None,
        outcome: str,
        message: str,
        explanation: str | None = None,
        debug: dict[str, str | int | float | bool | None] | None = None,
    ) -> None:
        if explanation is None:
            explanation = self._guidance(action, outcome)
        self._records.emit(
            action=action,
            node=node,
            outcome=outcome,
            message=message,
            explanation=explanation,
            debug=debug,
        )
        with self._state_lock:
            self._record_revision_locked()

    @staticmethod
    def _guidance(action: str, outcome: str) -> str | None:
        if action == "initialize":
            return "Start the publisher and receiver when ready."
        if action == "start":
            return "The node is starting; wait for it to become ready."
        if action == "ready":
            return "The node is ready; start the other node or authenticate the pair."
        if action == "stop" and outcome == "ok":
            return "The node is stopping and pair authentication is no longer valid."
        if action == "stop":
            return "Restart the node before authenticating the pair again."
        if action == "authenticate" and outcome == "ok":
            return "Both nodes restart with reciprocal peer configuration."
        if action == "authenticate":
            return "Authentication verified; send an Event when ready."
        if action == "cleanup" and outcome == "ok":
            return "Owned processes are stopping before disposable data is removed."
        if action == "cleanup":
            return "All owned processes and disposable data are removed."
        if action == "error":
            return "The action failed safely; clean up or retry an available action."
        return None

    @staticmethod
    def _require_role(role: Any) -> None:
        if role not in NODE_ROLES:
            raise SupervisorStateError("node role is invalid")

    @staticmethod
    def _operation_error() -> dict[str, str]:
        return {"code": "operation_failed", "message": _OPERATION_ERROR_MESSAGE}

    @staticmethod
    def _cleanup_error() -> dict[str, str]:
        return {"code": "cleanup_failed", "message": _CLEANUP_ERROR_MESSAGE}

    @staticmethod
    def _validate_text(text: Any) -> None:
        if not isinstance(text, str):
            raise EventValidationError("event text must be a string")
        if not text:
            raise EventValidationError("event text must not be empty")
        try:
            encoded = text.encode("utf-8")
        except UnicodeEncodeError:
            raise EventValidationError("event text must contain Unicode scalar values") from None
        if len(encoded) > MAX_EVENT_BYTES:
            raise EventValidationError("event text exceeds 4096 UTF-8 bytes")

    @classmethod
    def _require_initialization_receipt(cls, value: Any) -> dict[str, Any]:
        if not isinstance(value, dict) or set(value) != {"status", "nodes"} or value["status"] != "initialized":
            raise TypeError("invalid initialization receipt")
        nodes = value["nodes"]
        if not isinstance(nodes, dict) or set(nodes) != set(NODE_ROLES):
            raise TypeError("invalid initialization receipt")
        sanitized: dict[str, dict[str, str]] = {}
        for role in NODE_ROLES:
            node = nodes[role]
            if not isinstance(node, dict) or set(node) != {"identity_fingerprint"}:
                raise TypeError("invalid initialization receipt")
            fingerprint = node["identity_fingerprint"]
            if type(fingerprint) is not str or _IDENTITY_FINGERPRINT.fullmatch(fingerprint) is None:
                raise TypeError("invalid initialization receipt")
            sanitized[role] = {"identity_fingerprint": fingerprint}
        return {"status": "initialized", "nodes": sanitized}

    @staticmethod
    def _require_node_receipt(value: Any, role: str, state: str) -> dict[str, Any]:
        expected = {"role", "state"}
        optional = {"pid", "port", "command", "confined_path"}
        node_index = 0 if role == "publisher" else 1
        expected_path = rf"logs/node-{node_index}/run-[1-9][0-9]{{0,8}}"
        if (
            not isinstance(value, dict)
            or not expected <= set(value) <= expected | optional
            or value["role"] != role
            or value["state"] != state
            or ("pid" in value and (type(value["pid"]) is not int or value["pid"] < 1))
            or (
                "port" in value
                and (type(value["port"]) is not int or not 1 <= value["port"] <= 65_535)
            )
            or ("command" in value and value["command"] != "aster-agent")
            or (
                "confined_path" in value
                and (
                    type(value["confined_path"]) is not str
                    or re.fullmatch(expected_path, value["confined_path"]) is None
                )
            )
            or (("command" in value) != ("confined_path" in value))
        ):
            raise TypeError("invalid node lifecycle receipt")
        return {
            key: value[key]
            for key in ("role", "state", "pid", "port", "command", "confined_path")
            if key in value
        }

    @staticmethod
    def _node_debug_facts(receipt: dict[str, Any]) -> dict[str, int | bool | str]:
        facts = {
            key: receipt[key]
            for key in ("pid", "port", "command", "confined_path")
            if key in receipt
        }
        if "port" in facts:
            facts["port_reserved"] = receipt["state"] == "stopped"
        return facts

    @staticmethod
    def _require_authentication_receipt(value: Any) -> dict[str, str]:
        if (
            not isinstance(value, dict)
            or set(value) != {"status", "challenge"}
            or value["status"] != "authenticated"
            or value["challenge"] != "verified"
        ):
            raise TypeError("invalid authentication receipt")
        return {"status": "authenticated", "challenge": "verified"}

    @classmethod
    def _require_publication_receipt(cls, value: Any, text: str) -> dict[str, Any]:
        if not isinstance(value, dict) or set(value) != {"commit", "receipt"}:
            raise TypeError("invalid publication receipt")
        commit = cls._require_commit(value["commit"], text)
        receipt = cls._require_receipt(value["receipt"], text)
        if receipt["event_id"] != commit["event_id"]:
            raise TypeError("publication facts identify different Events")
        return {"commit": commit, "receipt": receipt}

    @staticmethod
    def _require_commit(value: Any, text: str) -> dict[str, Any]:
        if (
            not isinstance(value, dict)
            or set(value) != {"event_id", "text", "status", "durable", "node"}
            or type(value["event_id"]) is not str
            or _EVENT_ID.fullmatch(value["event_id"]) is None
            or value["text"] != text
            or value["status"] != "committed"
            or value["durable"] is not True
            or value["node"] != "atlas"
        ):
            raise TypeError("invalid commit receipt")
        return {
            "event_id": value["event_id"],
            "text": text,
            "status": "committed",
            "durable": True,
            "node": "atlas",
        }

    @staticmethod
    def _require_receipt(value: Any, text: str) -> dict[str, Any]:
        if (
            not isinstance(value, dict)
            or set(value) != {"event_id", "text", "status", "observed", "node"}
            or type(value["event_id"]) is not str
            or _EVENT_ID.fullmatch(value["event_id"]) is None
            or value["text"] != text
            or value["status"] != "received"
            or value["observed"] is not True
            or value["node"] != "beacon"
        ):
            raise TypeError("invalid receipt")
        return {
            "event_id": value["event_id"],
            "text": text,
            "status": "received",
            "observed": True,
            "node": "beacon",
        }


__all__ = [
    "EventValidationError",
    "QuickstartSupervisor",
    "REVISION_HISTORY_BYTES_LIMIT",
    "SupervisorBusyError",
    "SupervisorStateError",
]
