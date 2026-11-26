"""Private HTTP adapter for the supervisor-owned quickstart."""

from __future__ import annotations

from copy import deepcopy
from collections.abc import Callable, Sequence
from hmac import compare_digest
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
from pathlib import Path
import socket
import threading
import time
from typing import Any
from urllib.parse import parse_qsl, quote, urlsplit

from .records import RecordJournal, TerminalRecord, render_record
from .supervisor import (
    EventValidationError,
    QuickstartSupervisor,
    SupervisorBusyError,
    SupervisorStateError,
)
from .terminal import ObserverCommand, open_terminal


# A 4096-byte Event can expand to six JSON bytes per input byte when every
# byte requires escaping, plus the fixed object envelope.
MAX_JSON_BODY_BYTES = 24_640
SSE_MAX_CLIENTS = 4
SSE_HEARTBEAT_SECONDS = 0.25
SSE_MAX_LIFETIME_SECONDS = 300.0
SSE_CATCHUP_BYTES_LIMIT = 1_572_864
RESPONSE_WRITE_TIMEOUT_SECONDS = 0.25
REQUEST_READ_DEADLINE_SECONDS = 0.5
MAX_ACTIVE_HTTP_HANDLERS = 12
HTTP_SHUTDOWN_TIMEOUT_SECONDS = 1.0
TERMINAL_LAUNCH_INTERVAL_SECONDS = 0.25
_STATIC_DIR = Path(__file__).with_name("static")
_STATIC_ROUTES = {
    "/": ("index.html", "text/html; charset=utf-8"),
    "/static/app.js": ("app.js", "application/javascript; charset=utf-8"),
    "/static/styles.css": ("styles.css", "text/css; charset=utf-8"),
}
_NODE_ACTIONS = {
    "/api/nodes/publisher/start": ("start_node", "publisher"),
    "/api/nodes/publisher/stop": ("stop_node", "publisher"),
    "/api/nodes/receiver/start": ("start_node", "receiver"),
    "/api/nodes/receiver/stop": ("stop_node", "receiver"),
}
_TERMINAL_ROUTES = {
    "/api/terminal/publisher": "publisher",
    "/api/terminal/receiver": "receiver",
}
_DETAIL_LEVELS = frozenset({"compact", "guided", "debug"})


def _default_terminal_open(command: ObserverCommand, _role: str) -> bool:
    return open_terminal(command)


class _CleanupResponseBarrier:
    """Publish the first bounded cleanup response outcome to the launcher."""

    def __init__(self) -> None:
        self._ready = threading.Event()
        self._lock = threading.Lock()
        self._result: str | None = None

    def complete(self, result: str) -> None:
        if result not in {"sent", "disconnected", "failed", "timeout"}:
            raise ValueError("invalid cleanup response result")
        with self._lock:
            if self._result is None:
                self._result = result
                self._ready.set()

    def wait(self, timeout: float | None) -> str:
        if not self._ready.wait(timeout):
            return "timeout"
        with self._lock:
            return self._result or "failed"


class QuickstartServer:
    """Serve one supervisor only on a tokenized loopback URL."""

    def __init__(
        self,
        supervisor: QuickstartSupervisor,
        token: str,
        host: str = "127.0.0.1",
        port: int = 0,
        *,
        records: RecordJournal | None = None,
        attach: Any | None = None,
        terminal_open: Callable[[ObserverCommand, str], bool] = _default_terminal_open,
    ) -> None:
        if host != "127.0.0.1":
            raise ValueError("the quickstart server must bind to 127.0.0.1")
        if not isinstance(token, str) or not token:
            raise ValueError("token must be a non-empty string")
        if not isinstance(port, int) or not 0 <= port <= 65_535:
            raise ValueError("port must be between 0 and 65535")
        if records is not None and not isinstance(records, RecordJournal):
            raise TypeError("records must be a RecordJournal")
        if not callable(terminal_open):
            raise TypeError("terminal_open must be callable")
        self._supervisor = supervisor
        self._token = token
        self._host = host
        self._port = port
        self._records = records
        self._attach = attach
        self._terminal_open = terminal_open
        self._httpd: _QuickstartHTTPServer | None = None
        self._thread: threading.Thread | None = None
        self._cleanup_response = _CleanupResponseBarrier()
        self._browser_cleanup = threading.Event()
        self._closing = threading.Event()

    def start(self) -> str:
        if self._httpd is None:
            httpd = _QuickstartHTTPServer(
                (self._host, self._port),
                _QuickstartRequestHandler,
                self._supervisor,
                self._token,
                self._records,
                self._attach,
                self._terminal_open,
                self._cleanup_response,
                self._browser_cleanup,
                self._closing,
            )
            thread = threading.Thread(
                target=httpd.serve_forever,
                kwargs={"poll_interval": 0.05},
                name="quickstart-web",
                daemon=True,
            )
            try:
                thread.start()
            except BaseException:
                httpd.server_close()
                raise
            self._httpd = httpd
            self._thread = thread
        port = self._httpd.server_address[1]
        return f"http://{self._host}:{port}/?token={quote(self._token, safe='')}"

    def wait_for_cleanup_response(self, timeout: float | None) -> str:
        return self._cleanup_response.wait(timeout)

    def browser_cleanup_requested(self) -> bool:
        return self._browser_cleanup.is_set()

    def close(self) -> None:
        if self._httpd is None:
            return
        httpd = self._httpd
        self._closing.set()
        httpd.close_connections()
        httpd.shutdown()
        httpd.server_close()
        if self._thread is not None:
            self._thread.join(timeout=HTTP_SHUTDOWN_TIMEOUT_SECONDS)
            if self._thread.is_alive():
                raise RuntimeError("quickstart HTTP server did not stop")
        if not httpd.wait_for_handlers(HTTP_SHUTDOWN_TIMEOUT_SECONDS):
            raise RuntimeError("quickstart HTTP handlers did not stop")
        self._httpd = None
        self._thread = None


class _QuickstartHTTPServer(ThreadingHTTPServer):
    daemon_threads = True

    def __init__(
        self,
        address,
        handler,
        supervisor,
        token,
        records,
        attach,
        terminal_open,
        cleanup_response,
        browser_cleanup,
        closing,
    ) -> None:
        super().__init__(address, handler)
        self.supervisor = supervisor
        self.token = token
        self.records = records
        self.attach = attach
        self.terminal_open = terminal_open
        self.cleanup_response = cleanup_response
        self.browser_cleanup = browser_cleanup
        self.closing = closing
        self._sse_lock = threading.Lock()
        self._sse_clients: set[socket.socket] = set()
        self._connection_lock = threading.Condition()
        self._connections: set[socket.socket] = set()
        self._active_handlers = 0
        self._handler_slots = threading.BoundedSemaphore(MAX_ACTIVE_HTTP_HANDLERS)
        self._terminal_lock = threading.Lock()
        self._terminal_cleanup = threading.Event()
        self._next_terminal_launch = 0.0

    def begin_cleanup(self) -> None:
        self._terminal_cleanup.set()

    def run_cleanup(self) -> None:
        with self._terminal_lock:
            self.supervisor.cleanup()

    def launch_terminal(self, command: ObserverCommand, role: str) -> tuple[str, bool]:
        if self.closing.is_set() or self._terminal_cleanup.is_set():
            return "unavailable", False
        with self._terminal_lock:
            if self.closing.is_set() or self._terminal_cleanup.is_set():
                return "unavailable", False
            now = time.monotonic()
            if now < self._next_terminal_launch:
                return "busy", False
            try:
                opened = self.terminal_open(command, role) is True
            except Exception:
                opened = False
            finally:
                self._next_terminal_launch = time.monotonic() + TERMINAL_LAUNCH_INTERVAL_SECONDS
            return "ok", opened

    def register_sse_client(self, connection: socket.socket) -> bool:
        with self._sse_lock:
            if self.closing.is_set() or len(self._sse_clients) >= SSE_MAX_CLIENTS:
                return False
            self._sse_clients.add(connection)
            return True

    def unregister_sse_client(self, connection: socket.socket) -> None:
        with self._sse_lock:
            self._sse_clients.discard(connection)

    def close_sse_clients(self) -> None:
        with self._sse_lock:
            clients = tuple(self._sse_clients)
        for connection in clients:
            try:
                connection.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass

    def get_request(self):
        connection, address = super().get_request()
        with self._connection_lock:
            self._connections.add(connection)
        return connection, address

    def process_request(self, request, client_address) -> None:
        if not self._handler_slots.acquire(blocking=False):
            self.shutdown_request(request)
            return
        with self._connection_lock:
            self._active_handlers += 1
        try:
            super().process_request(request, client_address)
        except BaseException:
            self._handler_finished(request)
            raise

    def process_request_thread(self, request, client_address) -> None:
        try:
            super().process_request_thread(request, client_address)
        finally:
            self._handler_finished(request)

    def _handler_finished(self, request) -> None:
        with self._connection_lock:
            self._connections.discard(request)
            self._active_handlers -= 1
            self._connection_lock.notify_all()
        self._handler_slots.release()

    def shutdown_request(self, request) -> None:
        try:
            super().shutdown_request(request)
        finally:
            with self._connection_lock:
                self._connections.discard(request)

    def close_connections(self) -> None:
        with self._connection_lock:
            connections = tuple(self._connections)
        for connection in connections:
            try:
                connection.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass

    def wait_for_handlers(self, timeout: float) -> bool:
        deadline = time.monotonic() + timeout
        with self._connection_lock:
            while self._active_handlers:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    return False
                self._connection_lock.wait(remaining)
            return True

    def public_state(self, state: dict[str, Any] | None = None) -> dict[str, Any]:
        payload = self.supervisor.snapshot() if state is None else deepcopy(state)
        records = [] if self.records is None else self.records.records_after(0, timeout=0)
        watermark = payload.get("record_sequence", 0)
        payload["records"] = [
            _record_payload(record) for record in records if record.sequence <= watermark
        ]
        if records and records[0].action == "history-gap":
            omitted_records = min(watermark, records[0].sequence)
            if omitted_records:
                stream = payload.get("stream")
                if not isinstance(stream, dict):
                    stream = {}
                    payload["stream"] = stream
                stream["records_complete"] = False
                stream["records_omitted"] = omitted_records
        return payload

    def bounded_public_updates(
        self,
        states: Sequence[dict[str, Any]],
        after_revision: int,
    ) -> list[dict[str, Any]]:
        """Bound one catch-up batch, falling back to the newest full state."""

        if not states:
            return []
        public: list[dict[str, Any]] = []
        total_bytes = 0
        for state in states:
            candidate = self.public_state(state)
            total_bytes += _serialized_state_bytes(candidate)
            if total_bytes > SSE_CATCHUP_BYTES_LIMIT:
                break
            public.append(candidate)
        else:
            return public

        latest = self.public_state(states[-1])
        existing_stream = latest.get("stream")
        omitted_records = (
            existing_stream.get("records_omitted", 0)
            if isinstance(existing_stream, dict)
            and existing_stream.get("records_complete") is False
            else 0
        )
        latest["stream"] = {
            "mode": "full_resync",
            "reason": "payload_budget",
            "after_revision": after_revision,
        }
        records = latest.get("records")
        if omitted_records:
            latest["stream"]["records_complete"] = False
            latest["stream"]["records_omitted"] = omitted_records
        while (
            isinstance(records, list)
            and records
            and _serialized_state_bytes(latest) > SSE_CATCHUP_BYTES_LIMIT
        ):
            record = records.pop(0)
            if record["action"] != "history-gap":
                omitted_records += 1
                latest["stream"]["records_complete"] = False
                latest["stream"]["records_omitted"] = omitted_records
        if _serialized_state_bytes(latest) > SSE_CATCHUP_BYTES_LIMIT:
            return [{
                "revision": latest["revision"],
                "stream": {"mode": "resync_required", "reason": "payload_budget"},
            }]
        return [latest]


def _record_payload(record: TerminalRecord) -> dict[str, Any]:
    return {
        "sequence": record.sequence,
        "timestamp": record.timestamp,
        "action": record.action,
        "node": record.node,
        "outcome": record.outcome,
        "message": record.message,
        "explanation": record.explanation,
        "debug": dict(record.debug),
        "rendered": {
            detail: render_record(record, detail)
            for detail in ("compact", "guided", "debug")
        },
    }


def _serialized_state_bytes(state: dict[str, Any]) -> int:
    encoded = json.dumps(state, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
    return len(b"event: state\ndata: ") + len(encoded) + len(b"\n\n")


def _unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    decoded: dict[str, Any] = {}
    for key, value in pairs:
        if key in decoded:
            raise ValueError("duplicate JSON field")
        decoded[key] = value
    return decoded


class _QuickstartRequestHandler(BaseHTTPRequestHandler):
    server: _QuickstartHTTPServer
    protocol_version = "HTTP/1.1"

    def handle(self) -> None:
        try:
            super().handle()
        except (BrokenPipeError, ConnectionResetError, TimeoutError, OSError):
            return

    def setup(self) -> None:
        super().setup()
        self._read_timer: threading.Timer | None = None
        self._start_read_deadline()

    def finish(self) -> None:
        self._cancel_read_deadline()
        super().finish()

    def _start_read_deadline(self) -> None:
        self._cancel_read_deadline()
        timer = threading.Timer(
            REQUEST_READ_DEADLINE_SECONDS,
            self._expire_request_read,
        )
        timer.daemon = True
        self._read_timer = timer
        timer.start()

    def _cancel_read_deadline(self) -> None:
        timer = getattr(self, "_read_timer", None)
        if timer is not None:
            timer.cancel()
            self._read_timer = None

    def _expire_request_read(self) -> None:
        try:
            self.connection.shutdown(socket.SHUT_RDWR)
        except OSError:
            pass

    def do_GET(self) -> None:
        self._cancel_read_deadline()
        self.close_connection = True
        path = self._authenticated_path()
        if path is None:
            return
        if path in _STATIC_ROUTES:
            filename, content_type = _STATIC_ROUTES[path]
            self._send_static(filename, content_type)
        elif path == "/api/state":
            self._send_json(HTTPStatus.OK, self.server.public_state())
        elif path == "/api/events":
            self._stream_events()
        else:
            self._send_error_json(HTTPStatus.NOT_FOUND, "not_found", "The requested resource was not found.")

    def do_POST(self) -> None:
        self._cancel_read_deadline()
        self.close_connection = True
        path = self._authenticated_path()
        if path is None:
            return
        if path in _NODE_ACTIONS:
            if self._read_json({}) is None:
                return
            method_name, role = _NODE_ACTIONS[path]
            self._run_mutation(lambda: getattr(self.server.supervisor, method_name)(role))
        elif path == "/api/authenticate":
            if self._read_json({}) is None:
                return
            self._run_mutation(self.server.supervisor.authenticate)
        elif path == "/api/events":
            payload = self._read_json({"text": str})
            if payload is not None:
                self._run_mutation(lambda: self.server.supervisor.publish_event(payload["text"]))
        elif path == "/api/experiments/offline":
            payload = self._read_json({"text": str})
            if payload is not None:
                self._run_mutation(lambda: self.server.supervisor.run_offline_experiment(payload["text"]))
        elif path in _TERMINAL_ROUTES:
            payload = self._read_json({"detail": str})
            if payload is not None:
                self._open_terminal(_TERMINAL_ROUTES[path], payload["detail"])
        elif path == "/api/cleanup":
            payload = self._read_json({"confirm": bool})
            if payload is None:
                return
            if payload["confirm"] is not True:
                self._send_error_json(HTTPStatus.BAD_REQUEST, "invalid_request", "Cleanup confirmation is required.")
                return
            self.server.browser_cleanup.set()
            self.server.begin_cleanup()
            self._run_mutation(self.server.run_cleanup, cleanup=True)
        else:
            self._send_error_json(HTTPStatus.NOT_FOUND, "not_found", "The requested resource was not found.")

    def _authenticated_path(self) -> str | None:
        parsed = urlsplit(self.path)
        expected_host = f"127.0.0.1:{self.server.server_address[1]}"
        hosts = self.headers.get_all("Host", [])
        origins = self.headers.get_all("Origin", [])
        expected_origin = f"http://{expected_host}"
        if len(hosts) != 1 or hosts[0] != expected_host:
            self._send_error_json(HTTPStatus.FORBIDDEN, "forbidden", "This browser session is not authorized.")
            return None
        if self.command == "POST" and (len(origins) != 1 or origins[0] != expected_origin):
            self._send_error_json(HTTPStatus.FORBIDDEN, "forbidden", "This browser session is not authorized.")
            return None
        fetch_sites = self.headers.get_all("Sec-Fetch-Site", [])
        if len(fetch_sites) > 1 or (fetch_sites and fetch_sites[0] not in {"same-origin", "none"}):
            self._send_error_json(HTTPStatus.FORBIDDEN, "forbidden", "This browser session is not authorized.")
            return None
        try:
            token_items = parse_qsl(parsed.query, keep_blank_values=True, strict_parsing=True)
        except ValueError:
            self._send_error_json(HTTPStatus.FORBIDDEN, "forbidden", "This browser session is not authorized.")
            return None
        if (
            len(token_items) != 1
            or token_items[0][0] != "token"
            or not compare_digest(token_items[0][1], self.server.token)
        ):
            self._send_error_json(HTTPStatus.FORBIDDEN, "forbidden", "This browser session is not authorized.")
            return None
        return parsed.path

    def _read_json(self, schema: dict[str, type]) -> dict[str, Any] | None:
        if self.headers.get_all("Transfer-Encoding", []):
            self._send_error_json(HTTPStatus.BAD_REQUEST, "invalid_request", "The request framing is invalid.")
            return None
        content_types = self.headers.get_all("Content-Type", [])
        if (
            len(content_types) != 1
            or content_types[0].split(";", 1)[0].strip().lower() != "application/json"
        ):
            self._send_error_json(HTTPStatus.UNSUPPORTED_MEDIA_TYPE, "unsupported_media", "Requests must use application/json.")
            return None
        content_lengths = self.headers.get_all("Content-Length", [])
        if len(content_lengths) != 1:
            self._send_error_json(HTTPStatus.LENGTH_REQUIRED, "invalid_request", "A request body is required.")
            return None
        content_length = content_lengths[0]
        try:
            size = int(content_length)
        except ValueError:
            size = -1
        if size < 0:
            self._send_error_json(HTTPStatus.BAD_REQUEST, "invalid_request", "The request body is invalid.")
            return None
        if size > MAX_JSON_BODY_BYTES:
            self._send_error_json(HTTPStatus.REQUEST_ENTITY_TOO_LARGE, "request_too_large", "The request body is too large.")
            return None
        self._start_read_deadline()
        try:
            body = self.rfile.read(size)
        finally:
            self._cancel_read_deadline()
        if len(body) != size:
            return None
        try:
            decoded = json.loads(body.decode("utf-8"), object_pairs_hook=_unique_object)
        except (UnicodeDecodeError, json.JSONDecodeError, ValueError):
            self._send_error_json(HTTPStatus.BAD_REQUEST, "invalid_request", "The request body is invalid.")
            return None
        if type(decoded) is not dict or set(decoded) != set(schema):
            self._send_error_json(HTTPStatus.BAD_REQUEST, "invalid_request", "The request body is invalid.")
            return None
        if any(type(decoded[key]) is not expected for key, expected in schema.items()):
            self._send_error_json(HTTPStatus.BAD_REQUEST, "invalid_request", "The request body is invalid.")
            return None
        return decoded

    def _run_mutation(self, mutation, *, cleanup: bool = False) -> None:
        try:
            mutation()
        except SupervisorBusyError:
            self._send_error_json(HTTPStatus.CONFLICT, "busy", "Another quickstart action is in progress.")
        except EventValidationError:
            self._send_error_json(HTTPStatus.BAD_REQUEST, "invalid_event", "Enter an Event between 1 and 4096 UTF-8 bytes.")
        except SupervisorStateError:
            self._send_error_json(HTTPStatus.CONFLICT, "unavailable", "This action is not available right now.")
        except Exception:
            self._send_error_json(HTTPStatus.INTERNAL_SERVER_ERROR, "operation_failed", "The quickstart operation failed.")
        else:
            if not cleanup:
                self._send_json(HTTPStatus.OK, self.server.public_state())
                return
            try:
                self._send_json(
                    HTTPStatus.OK,
                    self.server.public_state(),
                    write_timeout=RESPONSE_WRITE_TIMEOUT_SECONDS,
                )
            except socket.timeout:
                self.server.cleanup_response.complete("timeout")
            except (BrokenPipeError, ConnectionResetError, TimeoutError, OSError):
                self.server.cleanup_response.complete("disconnected")
            except Exception:
                self.server.cleanup_response.complete("failed")
            else:
                self.server.cleanup_response.complete("sent")

    def _open_terminal(self, role: str, detail: str) -> None:
        if detail not in _DETAIL_LEVELS or self.server.attach is None:
            self._send_error_json(HTTPStatus.BAD_REQUEST, "invalid_request", "The request body is invalid.")
            return
        try:
            provided = self.server.attach.command(role, detail)
            command = ObserverCommand(tuple(provided.argv), Path(provided.cwd))
            launch_status, opened = self.server.launch_terminal(command, role)
            if launch_status != "ok":
                self._send_error_json(
                    HTTPStatus.CONFLICT,
                    launch_status,
                    "This action is not available right now."
                    if launch_status == "unavailable"
                    else "Another terminal launch is already in progress.",
                )
                return
            payload = {
                "state": self.server.public_state(),
                "terminal": {
                    "opened": opened,
                    "argv": list(command.argv),
                    "cwd": str(command.cwd),
                    "attach_command": command.copyable(),
                },
            }
            self._send_json(HTTPStatus.OK, payload)
        except Exception:
            self._send_error_json(HTTPStatus.INTERNAL_SERVER_ERROR, "operation_failed", "The quickstart operation failed.")

    def _stream_events(self) -> None:
        if not self.server.register_sse_client(self.connection):
            self._send_error_json(
                HTTPStatus.SERVICE_UNAVAILABLE,
                "busy",
                "Too many live browser observers are connected.",
            )
            return
        try:
            self.connection.settimeout(RESPONSE_WRITE_TIMEOUT_SECONDS)
            self.send_response(HTTPStatus.OK)
            self._send_common_headers()
            self.send_header("Content-Type", "text/event-stream; charset=utf-8")
            self.send_header("Cache-Control", "no-store")
            self.send_header("Connection", "keep-alive")
            self.end_headers()
            state = self.server.supervisor.snapshot()
            state["stream"] = {"mode": "full"}
            latest = state["revision"]
            initial = self.server.bounded_public_updates([state], 0)
            self._send_state_event(initial[0])
            deadline = time.monotonic() + SSE_MAX_LIFETIME_SECONDS
            while not self.server.closing.is_set() and time.monotonic() < deadline:
                updates = self.server.supervisor.snapshots_after(
                    latest,
                    timeout=SSE_HEARTBEAT_SECONDS,
                )
                if not updates:
                    self._write_bytes(b": keepalive\n\n")
                    continue
                for state in self.server.bounded_public_updates(updates, latest):
                    if state["revision"] <= latest:
                        continue
                    latest = state["revision"]
                    self._send_state_event(state)
        except (BrokenPipeError, ConnectionResetError, TimeoutError, OSError):
            return
        finally:
            self.server.unregister_sse_client(self.connection)
            self.close_connection = True

    def _send_state_event(self, state: dict[str, Any]) -> None:
        encoded = json.dumps(state, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
        self._write_bytes(b"event: state\ndata: " + encoded + b"\n\n")

    def _send_static(self, filename: str, content_type: str) -> None:
        content = (_STATIC_DIR / filename).read_bytes()
        if filename == "index.html":
            content = content.replace(b"__TOKEN__", quote(self.server.token, safe="").encode("ascii"))
        self.connection.settimeout(RESPONSE_WRITE_TIMEOUT_SECONDS)
        self.send_response(HTTPStatus.OK)
        self._send_common_headers()
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(content)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self._write_bytes(content)

    def _send_json(
        self,
        status: HTTPStatus,
        payload: dict[str, Any],
        *,
        write_timeout: float | None = None,
    ) -> None:
        content = json.dumps(payload, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
        self.connection.settimeout(write_timeout or RESPONSE_WRITE_TIMEOUT_SECONDS)
        self.send_response(status)
        self._send_common_headers()
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(content)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self._write_bytes(content)

    def _write_bytes(self, content: bytes) -> None:
        self.connection.settimeout(RESPONSE_WRITE_TIMEOUT_SECONDS)
        self.wfile.write(content)
        self.wfile.flush()

    def _send_error_json(self, status: HTTPStatus, code: str, message: str) -> None:
        self._send_json(status, {"error": {"code": code, "message": message}})

    def _send_common_headers(self) -> None:
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("X-Frame-Options", "DENY")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header(
            "Content-Security-Policy",
            "default-src 'self'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'; connect-src 'self'",
        )

    def log_message(self, format: str, *args: Any) -> None:
        return


__all__ = ["MAX_JSON_BODY_BYTES", "SSE_CATCHUP_BYTES_LIMIT", "QuickstartServer"]
