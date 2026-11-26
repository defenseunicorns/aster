"""Compose the real Aster session, observers, and private browser surface."""

from __future__ import annotations

import argparse
from contextlib import contextmanager
import os
from pathlib import Path
import secrets
import shutil
import signal
import sys
import tempfile
import threading
import time
from typing import Callable, TextIO
import webbrowser

from .aster_session import AsterBinaries, AsterSession, AsterSessionError
from .attach import AttachServer, follow_records
from .records import DetailLevel, RecordJournal, parse_detail, render_record
from .runtime import (
    OwnedProcessDescriptor,
    RuntimeActiveError,
    RuntimePublicationCommittedError,
    RuntimeRegistry,
    RuntimeSafetyError,
    current_runtime_descriptor,
    default_runtime_paths,
)
from .supervisor import QuickstartSupervisor
from .terminal import ObserverCommand, open_terminal
from .transcript import TranscriptJournal
from .web import QuickstartServer


def discover_binaries(bin_dir: Path) -> AsterBinaries:
    directory = Path(bin_dir).expanduser().resolve()
    return AsterBinaries(
        directory / "aster",
        directory / "aster-agent",
        directory / "asterctl",
    ).validate()


def _build_aster_session(
    binaries: AsterBinaries,
    root: Path,
    cancel_event: CleanupRequest,
    *,
    transcript: TranscriptJournal | None = None,
) -> AsterSession:
    return AsterSession(binaries, root, cancel_event=cancel_event, transcript=transcript)


def _record_internal(
    transcript: TranscriptJournal,
    step: str,
    title: str,
    detail: str,
    operation: Callable[[], object],
) -> object:
    started = time.monotonic()
    try:
        result = operation()
    except BaseException:
        transcript.record_internal(
            step,
            title,
            outcome="failed",
            detail=detail,
            duration_ms=max(0, int((time.monotonic() - started) * 1000)),
        )
        raise
    transcript.record_internal(
        step,
        title,
        outcome="succeeded",
        detail=detail,
        duration_ms=max(0, int((time.monotonic() - started) * 1000)),
    )
    return result


class _RecordWriter:
    """Render one canonical journal to a text stream without owning lifecycle."""

    def __init__(
        self,
        records: RecordJournal,
        detail: DetailLevel,
        output: TextIO,
        failure_callback: Callable[[], None],
    ) -> None:
        self._records = records
        self._detail = parse_detail(detail)
        self._output = output
        self._closing = threading.Event()
        self._thread = threading.Thread(target=self._run, name="quickstart-stdout", daemon=True)
        self._sequence = 0
        self._failure_callback = failure_callback
        self._failure: BaseException | None = None

    def start(self) -> None:
        self._thread.start()

    def close(self) -> None:
        self._closing.set()
        self._thread.join(timeout=1)
        if self._thread.is_alive():
            raise RuntimeError("quickstart output writer did not stop")
        if self._failure is not None:
            raise RuntimeError("quickstart output writer failed") from self._failure

    @property
    def failed(self) -> bool:
        return self._failure is not None

    def _run(self) -> None:
        try:
            while True:
                records = self._records.records_after(self._sequence, timeout=0.05)
                for record in records:
                    self._sequence = max(self._sequence, record.sequence)
                    self._output.write(render_record(record, self._detail) + "\n")
                    self._output.flush()
                if self._closing.is_set() and self._sequence >= self._records.latest_sequence():
                    return
        except BaseException as error:
            self._failure = error
            self._failure_callback()


class CleanupRequest:
    """A counted wakeup that cannot clear a newer cleanup request."""

    def __init__(self) -> None:
        self._event = threading.Event()
        self._lock = threading.RLock()
        self._generation = 0

    def set(self) -> None:
        with self._lock:
            self._generation += 1
            self._event.set()

    def wait(self, timeout: float | None = None) -> bool:
        return self._event.wait(timeout)

    def is_set(self) -> bool:
        return self._event.is_set()

    def generation(self) -> int:
        with self._lock:
            return self._generation

    def clear_if_unchanged(self, generation: int) -> bool:
        with self._lock:
            if generation != self._generation:
                return False
            self._event.clear()
            return True


class _CleanupFinalizer:
    """Commit launcher-owned cleanup once, resuming at the last safe phase."""

    def __init__(
        self,
        registry: RuntimeRegistry,
        attach: object,
        transcript: TranscriptJournal | None = None,
    ) -> None:
        self._registry = registry
        self._attach = attach
        self._transcript = transcript
        self._phase = "registry"

    def __call__(self) -> dict[str, object]:
        if self._transcript is None:
            return self._finalize()
        result = _record_internal(
            self._transcript,
            "cleanup",
            "Finalize quickstart cleanup",
            "launcher-owned cleanup completed",
            self._finalize,
        )
        assert isinstance(result, dict)
        return result

    def _finalize(self) -> dict[str, object]:
        if self._phase == "registry":
            self._registry.mark_cleanup_pending(())
            self._phase = "attach"
        if self._phase == "attach":
            self._attach.close()
            self._phase = "workspace"
        if self._phase == "workspace":
            self._registry.delete_workspace()
            self._phase = "descriptor"
        if self._phase == "descriptor":
            self._registry.remove_descriptor()
            self._phase = "complete"
        return {
            "owned_processes": 0,
            "socket_closed": True,
            "workspace_removed": True,
            "descriptor_removed": True,
        }


class QuickstartLauncher:
    """Own exactly one disposable quickstart from initialization through cleanup."""

    def __init__(
        self,
        binaries: AsterBinaries,
        *,
        no_open: bool = False,
        detail: DetailLevel = "guided",
        browser_open: Callable[[str], object] = webbrowser.open,
        output: TextIO = sys.stdout,
        error: TextIO = sys.stderr,
        runtime_registry: RuntimeRegistry | None = None,
        session_builder: Callable[[AsterBinaries, Path, CleanupRequest], object] = _build_aster_session,
        attach_builder: Callable[[Path, RecordJournal, int], object] = AttachServer,
        server_builder: Callable[..., object] = QuickstartServer,
        terminal_open: Callable[[list[str]], bool] = open_terminal,
    ) -> None:
        self.binaries = binaries
        self.no_open = no_open
        self.detail = parse_detail(detail)
        self.browser_open = browser_open
        self.output = output
        self.error = error
        if runtime_registry is None:
            _runtime_dir, lock_path, descriptor_path = default_runtime_paths()
            runtime_registry = RuntimeRegistry(lock_path, descriptor_path)
        self.runtime_registry = runtime_registry
        self.session_builder = session_builder
        self.attach_builder = attach_builder
        self.server_builder = server_builder
        self.terminal_open = terminal_open

    def run(self, stop: CleanupRequest) -> int:
        registry = self.runtime_registry
        transcript = TranscriptJournal()
        try:
            registry.acquire()
        except RuntimeActiveError:
            transcript.record_internal("setup", "Acquire runtime ownership", outcome="failed", detail="runtime already active", duration_ms=0)
            self.error.write("Quickstart is already running.\n")
            self.error.flush()
            return 1
        except (OSError, RuntimeSafetyError):
            transcript.record_internal("setup", "Acquire runtime ownership", outcome="failed", detail="runtime ownership unavailable", duration_ms=0)
            self._write_retained_failure(registry.runtime_dir)
            return 1
        transcript.record_internal("setup", "Acquire runtime ownership", outcome="succeeded", detail="runtime ownership acquired", duration_ms=0)

        workspace: Path | None = None
        session = None
        supervisor: QuickstartSupervisor | None = None
        records: RecordJournal | None = None
        writer: _RecordWriter | None = None
        attach = None
        server = None
        descriptor_published = False
        operation_failed = False
        writer_closed = False
        server_closed = False
        cleanup_finalizer = None
        try:
            _record_internal(
                transcript,
                "setup",
                "Recover runtime ownership",
                "stale runtime state recovered",
                registry.recover_stale,
            )
            _record_internal(
                transcript,
                "setup",
                "Validate Aster binaries",
                "launcher binary paths validated",
                self.binaries.validate,
            )
            workspace = _record_internal(
                transcript,
                "setup",
                "Create private workspace",
                "owner-only workspace created",
                lambda: self._new_workspace(registry.runtime_dir),
            )
            assert isinstance(workspace, Path)
            records = RecordJournal()
            writer = _RecordWriter(records, self.detail, self.output, stop.set)
            writer.start()
            if self.session_builder is _build_aster_session:
                session = self.session_builder(
                    self.binaries,
                    workspace / "session",
                    stop,
                    transcript=transcript,
                )
            else:
                session = self.session_builder(self.binaries, workspace / "session", stop)
            attach_path = workspace / "attach.sock"
            attach = self.attach_builder(attach_path, records, os.geteuid())
            attach.start()
            cleanup_finalizer = _CleanupFinalizer(registry, attach, transcript)
            try:
                descriptor = current_runtime_descriptor(workspace, attach_path)
                _record_internal(
                    transcript,
                    "setup",
                    "Publish runtime descriptor",
                    "private runtime descriptor published",
                    lambda: registry.publish(descriptor),
                )
            except RuntimePublicationCommittedError:
                descriptor_published = True
                operation_failed = True
                raise
            else:
                descriptor_published = True
            bind_runtime_owner = getattr(attach, "bind_runtime_owner", None)
            if callable(bind_runtime_owner):
                bind_runtime_owner(descriptor.pid)
            session.set_process_inventory_observer(
                lambda inventory, start_pending: registry.update_process_state(
                    (
                        OwnedProcessDescriptor(
                            pid=process.pid,
                            proc_start_time=process.proc_start_time,
                            executable=process.executable,
                            process_group=process.process_group,
                        )
                        for process in inventory
                    ),
                    start_pending=start_pending,
                )
            )
            supervisor = QuickstartSupervisor(
                session,
                records,
                stop,
                cleanup_finalizer=cleanup_finalizer,
                transcript=transcript,
            )
            browser_token = secrets.token_urlsafe(32)
            transcript.register_secret(browser_token)

            def launch_observer(command: ObserverCommand | list[str], role: str) -> bool:
                if self.terminal_open is not open_terminal:
                    vector = command.argv if isinstance(command, ObserverCommand) else command
                    return self.terminal_open(list(vector))
                return open_terminal(command, transcript=transcript, transcript_step=role)

            server = self.server_builder(
                supervisor,
                browser_token,
                records=records,
                attach=attach,
                terminal_open=launch_observer,
            )
            url = _record_internal(
                transcript,
                "setup",
                "Start secured browser surface",
                "credentialed loopback browser surface started",
                server.start,
            )
            assert isinstance(url, str)
            if not self.no_open:
                browser_opened: object = False
                try:
                    browser_opened = self.browser_open(url)
                except Exception:
                    browser_opened = False
                if browser_opened is False:
                    self.error.write(
                        "The quickstart browser could not be opened. "
                        "Configure a default browser, then run the quickstart again.\n"
                    )
                    self.error.flush()
                    operation_failed = True
                    stop.set()
            if not operation_failed:
                self.output.write("Quickstart ready.\n")
                self.output.flush()

        except RuntimeSafetyError:
            operation_failed = True
        except Exception:
            operation_failed = not stop.is_set()

        if not descriptor_published:
            cleanup_failed = False
            try:
                if supervisor is not None:
                    supervisor.shutdown()
                elif session is not None:
                    session.close()
            except Exception:
                cleanup_failed = True
            for adapter in (writer, attach, server):
                if adapter is not None:
                    try:
                        adapter.close()
                    except Exception:
                        cleanup_failed = True
            if workspace is not None:
                try:
                    shutil.rmtree(workspace)
                except OSError:
                    cleanup_failed = True
            registry.close(remove_descriptor=False)
            if workspace is None:
                self._write_retained_failure(registry.runtime_dir)
                return 1
            return self._report_failure(registry.runtime_dir, cleanup_failed)

        if operation_failed and not stop.is_set():
            stop.set()

        while descriptor_published:
            stop.wait()
            observed_generation = stop.generation()
            if writer is not None and writer.failed:
                operation_failed = True
            try:
                if supervisor is not None:
                    supervisor.shutdown()
                elif session is not None:
                    session.close()
                    if cleanup_finalizer is not None:
                        cleanup_finalizer()

                browser_cleanup = bool(
                    server is not None
                    and callable(getattr(server, "browser_cleanup_requested", None))
                    and server.browser_cleanup_requested()
                )
                if browser_cleanup and server.wait_for_cleanup_response(timeout=0.5) != "sent":
                    operation_failed = True

                if writer is not None and not writer_closed:
                    try:
                        writer.close()
                    except Exception:
                        operation_failed = True
                    finally:
                        writer_closed = True
                if server is not None and not server_closed:
                    server.close()
                    server_closed = True
                descriptor_published = False
            except Exception:
                stop.clear_if_unchanged(observed_generation)
                continue

        registry.close(remove_descriptor=False)

        if operation_failed:
            return self._report_failure(registry.runtime_dir, False)
        return 0

    def _report_failure(self, runtime_dir: Path, cleanup_failed: bool) -> int:
        summary = self._retain_failure_summary(runtime_dir, cleanup_failed)
        self.error.write("Quickstart failed.\n")
        if summary is not None:
            self.error.write(f"Summary: {summary}\n")
        self.error.flush()
        return 1

    def _write_retained_failure(self, runtime_dir: Path) -> None:
        self.error.write("Quickstart failed.\n")
        self.error.write(f"Retained: {runtime_dir}\n")
        self.error.flush()

    @staticmethod
    def _new_workspace(runtime_dir: Path) -> Path:
        location = tempfile.mkdtemp(prefix="session-", dir=runtime_dir)
        workspace = Path(location)
        os.chmod(workspace, 0o700)
        return workspace

    @staticmethod
    def _retain_failure_summary(runtime_dir: Path, cleanup_failed: bool) -> Path | None:
        summary = runtime_dir / f"summary-{secrets.token_hex(6)}.txt"
        message = (
            "Quickstart cleanup did not complete; owner-only diagnostics remain here.\n"
            if cleanup_failed
            else "Quickstart failed; raw session data was removed.\n"
        )
        try:
            descriptor = os.open(summary, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            with os.fdopen(descriptor, "w") as output:
                output.write(message)
        except OSError:
            return None
        return summary


@contextmanager
def _stop_on_signals(stop: CleanupRequest):
    previous = {}

    def request_stop(_signum, _frame):
        stop.set()

    try:
        for signum in (signal.SIGINT, signal.SIGTERM):
            previous[signum] = signal.getsignal(signum)
            signal.signal(signum, request_stop)
        yield
    finally:
        for signum, handler in previous.items():
            signal.signal(signum, handler)


def _run_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Run the guided local Aster quickstart.")
    parser.add_argument(
        "--bin-dir",
        required=True,
        type=Path,
        help="directory containing aster, aster-agent, and asterctl",
    )
    parser.add_argument(
        "--detail",
        type=parse_detail,
        default="guided",
        metavar="LEVEL",
        help="terminal detail: compact, guided, or debug (default: guided)",
    )
    parser.add_argument(
        "--no-open",
        action="store_true",
        help="run headless: do not open a browser or print its credentialed URL",
    )
    return parser


def _attach_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Observe one running quickstart node.")
    parser.add_argument("attach", choices=["attach"])
    parser.add_argument("role", choices=["publisher", "receiver"])
    parser.add_argument(
        "--detail",
        type=parse_detail,
        default="guided",
        metavar="LEVEL",
        help="terminal detail: compact, guided, or debug (default: guided)",
    )
    return parser


def main(
    argv: list[str] | None = None,
    *,
    launcher_factory: Callable[[AsterBinaries, bool, DetailLevel], QuickstartLauncher] | None = None,
    registry_factory: Callable[[], RuntimeRegistry] | None = None,
    attach_follow: Callable[..., int] = follow_records,
) -> int:
    selected = list(sys.argv[1:] if argv is None else argv)
    if selected and selected[0] == "attach":
        arguments = _attach_parser().parse_args(selected)
        try:
            if registry_factory is None:
                _runtime_dir, lock_path, descriptor_path = default_runtime_paths()
                registry = RuntimeRegistry(lock_path, descriptor_path)
            else:
                registry = registry_factory()
            descriptor = registry.read_live()
            return attach_follow(
                Path(descriptor.socket_path),
                arguments.role,
                arguments.detail,
                sys.stdout,
                expected_peer_pid=descriptor.pid,
            )
        except (OSError, RuntimeSafetyError, ValueError):
            sys.stderr.write("Quickstart attach failed.\n")
            return 1

    arguments = _run_parser().parse_args(selected)
    try:
        binaries = discover_binaries(arguments.bin_dir)
    except (AsterSessionError, OSError):
        sys.stderr.write("Quickstart failed.\n")
        return 1
    factory = launcher_factory or (
        lambda binaries, no_open, detail: QuickstartLauncher(
            binaries, no_open=no_open, detail=detail
        )
    )
    launcher = factory(binaries, arguments.no_open, arguments.detail)
    stop = CleanupRequest()
    with _stop_on_signals(stop):
        return launcher.run(stop)


if __name__ == "__main__":
    raise SystemExit(main())
