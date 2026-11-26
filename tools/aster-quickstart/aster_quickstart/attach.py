"""Owner-only terminal observers for the local quickstart."""

from __future__ import annotations

import argparse
from collections.abc import Sequence
import json
import os
from pathlib import Path
import socket
import stat
import struct
import sys
import threading
import time
from typing import Literal, TextIO, cast

from .records import DetailLevel, RecordJournal, parse_detail, render_record
from .terminal import ObserverCommand


NodeRole = Literal["publisher", "receiver"]

_ROLES = frozenset({"publisher", "receiver"})
_REQUEST_KEYS = frozenset({"role", "detail", "after_sequence"})
_MAX_REQUEST_BYTES = 1_024
_MAX_RESPONSE_BYTES = 4_096
_MAX_CLIENTS = 4
_REQUEST_TIMEOUT_SECONDS = 1.0
_WRITE_TIMEOUT_SECONDS = 0.1
_SHUTDOWN_TIMEOUT_SECONDS = 1.0
_SEND_BUFFER_BYTES = 4_096
_SOCKET_MODE = 0o600
_PARENT_MODE = 0o700


def _parse_role(value: str) -> NodeRole:
    if type(value) is not str or value not in _ROLES:
        raise ValueError("role must be publisher or receiver")
    return cast(NodeRole, value)


def _validate_parent(path: Path, owner_uid: int) -> os.stat_result:
    parent = path.parent
    try:
        metadata = parent.lstat()
    except OSError as error:
        raise ValueError("attach parent is unavailable") from error
    if not stat.S_ISDIR(metadata.st_mode) or parent.resolve() != parent.absolute():
        raise ValueError("attach parent must be a real directory")
    if metadata.st_uid != owner_uid or stat.S_IMODE(metadata.st_mode) != _PARENT_MODE:
        raise ValueError("attach parent is not owner-only")
    return metadata


def _validate_socket(path: Path, owner_uid: int) -> os.stat_result:
    try:
        metadata = path.lstat()
    except OSError as error:
        raise ValueError("attach socket is unavailable") from error
    if not stat.S_ISSOCK(metadata.st_mode):
        raise ValueError("attach endpoint is not a socket")
    if metadata.st_uid != owner_uid or stat.S_IMODE(metadata.st_mode) != _SOCKET_MODE:
        raise ValueError("attach socket is not owner-only")
    return metadata


def _same_identity(expected: os.stat_result, actual: os.stat_result) -> bool:
    return (expected.st_dev, expected.st_ino) == (actual.st_dev, actual.st_ino)


def _peer_credentials(connection: socket.socket) -> tuple[int, int, int]:
    credentials = connection.getsockopt(
        socket.SOL_SOCKET,
        socket.SO_PEERCRED,
        struct.calcsize("3i"),
    )
    return struct.unpack("3i", credentials)


def _peer_uid(connection: socket.socket) -> int:
    return _peer_credentials(connection)[1]


def _peer_pid(connection: socket.socket) -> int:
    return _peer_credentials(connection)[0]


def _unique_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    decoded: dict[str, object] = {}
    for key, value in pairs:
        if key in decoded:
            raise ValueError("attach request contains a duplicate field")
        decoded[key] = value
    return decoded


def _read_request(
    connection: socket.socket,
    deadline: float,
) -> tuple[NodeRole, DetailLevel, int]:
    request = bytearray()
    while b"\n" not in request:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise TimeoutError("attach request deadline expired")
        connection.settimeout(remaining)
        chunk = connection.recv(min(256, _MAX_REQUEST_BYTES + 1 - len(request)))
        if time.monotonic() > deadline:
            raise TimeoutError("attach request deadline expired")
        if not chunk:
            raise ValueError("incomplete attach request")
        request.extend(chunk)
        if len(request) > _MAX_REQUEST_BYTES:
            raise ValueError("attach request is too large")
    line, separator, trailing = request.partition(b"\n")
    if not separator or trailing:
        raise ValueError("attach request must contain one line")
    try:
        decoded = json.loads(line, object_pairs_hook=_unique_object)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise ValueError("attach request is invalid") from error
    if type(decoded) is not dict or set(decoded) != _REQUEST_KEYS:
        raise ValueError("attach request has invalid fields")
    role = _parse_role(decoded["role"])
    detail_value = decoded["detail"]
    if type(detail_value) is not str or detail_value not in {"compact", "guided", "debug"}:
        raise ValueError("detail is invalid")
    detail = cast(DetailLevel, detail_value)
    sequence = decoded["after_sequence"]
    if type(sequence) is not int or sequence < 0 or sequence > (2**63 - 1):
        raise ValueError("after_sequence is invalid")
    return role, detail, sequence


class AttachServer:
    """Stream sanitized journal renderings to same-owner Unix peers."""

    def __init__(self, socket_path: Path, records: RecordJournal, owner_uid: int) -> None:
        if not isinstance(socket_path, Path) or not socket_path.is_absolute():
            raise ValueError("socket_path must be an absolute Path")
        if not isinstance(records, RecordJournal):
            raise TypeError("records must be a RecordJournal")
        if type(owner_uid) is not int or owner_uid < 0:
            raise ValueError("owner_uid must be a non-negative integer")
        self._socket_path = socket_path
        self._records = records
        self._owner_uid = owner_uid
        self._runtime_owner_pid: int | None = None
        self._listener: socket.socket | None = None
        self._parent_identity: os.stat_result | None = None
        self._socket_identity: os.stat_result | None = None
        self._closed = threading.Event()
        self._thread: threading.Thread | None = None
        self._clients: set[socket.socket] = set()
        self._handlers: set[threading.Thread] = set()
        self._clients_lock = threading.Lock()

    def start(self) -> None:
        if self._closed.is_set():
            raise RuntimeError("attach server is closed")
        if self._listener is not None:
            raise RuntimeError("attach server is already started")
        parent_identity = _validate_parent(self._socket_path, self._owner_uid)
        if self._socket_path.exists() or self._socket_path.is_symlink():
            raise FileExistsError("attach socket already exists")
        listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        try:
            listener.bind(str(self._socket_path))
            self._socket_identity = self._socket_path.lstat()
            os.chmod(self._socket_path, _SOCKET_MODE)
            socket_identity = _validate_socket(self._socket_path, self._owner_uid)
            current_parent = _validate_parent(self._socket_path, self._owner_uid)
            if not _same_identity(parent_identity, current_parent):
                raise ValueError("attach parent changed during startup")
            listener.listen(_MAX_CLIENTS)
            listener.settimeout(0.1)
        except Exception:
            listener.close()
            self._unlink_created_socket()
            raise
        self._parent_identity = parent_identity
        self._socket_identity = socket_identity
        self._listener = listener
        self._thread = threading.Thread(target=self._serve, name="quickstart-attach", daemon=True)
        self._thread.start()

    def close(self) -> None:
        """Stop observers and best-effort unlink only this server's socket inode.

        The owner-only parent excludes other UIDs. A same-UID pathname
        replacement is deliberately left in place rather than guessed safe to
        remove; the runtime registry owns any later stale-state decision.
        """
        self._closed.set()
        deadline = time.monotonic() + _SHUTDOWN_TIMEOUT_SECONDS
        listener = self._listener
        self._listener = None
        if listener is not None:
            listener.close()
        thread = self._thread
        self._thread = None
        if thread is not None and thread is not threading.current_thread():
            thread.join(timeout=max(0.0, deadline - time.monotonic()))
        with self._clients_lock:
            clients = tuple(self._clients)
        for client in clients:
            try:
                client.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
            client.close()
        with self._clients_lock:
            handlers = tuple(self._handlers)
        for handler in handlers:
            if handler is threading.current_thread():
                continue
            handler.join(timeout=max(0.0, deadline - time.monotonic()))
        self._unlink_created_socket()
        with self._clients_lock:
            unfinished = bool(self._handlers)
        if (thread is not None and thread.is_alive()) or unfinished:
            raise RuntimeError("attach handlers did not stop")

    def bind_runtime_owner(self, pid: int) -> None:
        """Bind attach commands to the launcher PID committed in runtime metadata."""

        if type(pid) is not int or pid <= 0 or pid != os.getpid():
            raise ValueError("runtime owner PID is invalid")
        if self._runtime_owner_pid is not None:
            raise RuntimeError("runtime owner PID is already bound")
        self._runtime_owner_pid = pid

    def command(self, role: NodeRole, detail: DetailLevel) -> ObserverCommand:
        role = _parse_role(role)
        detail = parse_detail(detail)
        if self._runtime_owner_pid is None:
            raise RuntimeError("attach server is not bound to runtime metadata")
        return ObserverCommand(
            argv=(
                sys.executable,
                "-m",
                "aster_quickstart.attach",
                "--socket",
                str(self._socket_path),
                "--role",
                role,
                "--detail",
                detail,
                "--peer-pid",
                str(self._runtime_owner_pid),
            ),
            cwd=Path(__file__).resolve().parents[1],
        )

    def _serve(self) -> None:
        while not self._closed.is_set():
            listener = self._listener
            if listener is None:
                return
            try:
                connection, _ = listener.accept()
            except TimeoutError:
                continue
            except OSError:
                return
            if not self._endpoint_is_unchanged():
                connection.close()
                return
            try:
                connection.setsockopt(
                    socket.SOL_SOCKET,
                    socket.SO_SNDBUF,
                    _SEND_BUFFER_BYTES,
                )
            except OSError:
                connection.close()
                continue
            with self._clients_lock:
                if len(self._clients) >= _MAX_CLIENTS:
                    connection.close()
                    continue
                self._clients.add(connection)
                handler = threading.Thread(
                    target=self._serve_client,
                    args=(connection,),
                    name="quickstart-attach-client",
                    daemon=True,
                )
                self._handlers.add(handler)
                handler.start()

    def _endpoint_is_unchanged(self) -> bool:
        try:
            parent = _validate_parent(self._socket_path, self._owner_uid)
            endpoint = _validate_socket(self._socket_path, self._owner_uid)
        except ValueError:
            return False
        return (
            self._parent_identity is not None
            and self._socket_identity is not None
            and _same_identity(self._parent_identity, parent)
            and _same_identity(self._socket_identity, endpoint)
        )

    def _serve_client(self, connection: socket.socket) -> None:
        try:
            request_deadline = time.monotonic() + _REQUEST_TIMEOUT_SECONDS
            if _peer_uid(connection) != self._owner_uid:
                return
            role, detail, sequence = _read_request(connection, request_deadline)
            connection.settimeout(_WRITE_TIMEOUT_SECONDS)
            while not self._closed.is_set():
                records = self._records.records_after(sequence, timeout=0.1)
                for record in records:
                    sequence = max(sequence, record.sequence)
                    if record.node not in {None, role}:
                        continue
                    rendered = render_record(record, detail)
                    response = (
                        json.dumps(rendered, ensure_ascii=True, separators=(",", ":")).encode()
                        + b"\n"
                    )
                    if len(response) > _MAX_RESPONSE_BYTES:
                        return
                    connection.sendall(response)
        except (BrokenPipeError, ConnectionError, OSError, TypeError, ValueError):
            return
        finally:
            connection.close()
            with self._clients_lock:
                self._clients.discard(connection)
                self._handlers.discard(threading.current_thread())

    def _unlink_created_socket(self) -> None:
        expected = self._socket_identity
        if expected is None:
            return
        try:
            actual = self._socket_path.lstat()
            if _same_identity(expected, actual):
                self._socket_path.unlink()
        except FileNotFoundError:
            pass


def follow_records(
    socket_path: Path,
    role: NodeRole,
    detail: DetailLevel,
    output: TextIO,
    *,
    expected_peer_pid: int,
) -> int:
    """Follow canonical records until the owner closes the attach server."""

    try:
        role = _parse_role(role)
        detail = parse_detail(detail)
        if not hasattr(output, "write"):
            raise TypeError("output must be writable")
        if type(expected_peer_pid) is not int or expected_peer_pid <= 0:
            raise ValueError("expected peer PID is invalid")
        owner_uid = os.getuid()
        parent_identity = _validate_parent(socket_path, owner_uid)
        socket_identity = _validate_socket(socket_path, owner_uid)
        client = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        try:
            client.settimeout(1)
            client.connect(str(socket_path))
            if _peer_pid(client) != expected_peer_pid:
                return 1
            if not _same_identity(parent_identity, _validate_parent(socket_path, owner_uid)):
                return 1
            if not _same_identity(socket_identity, _validate_socket(socket_path, owner_uid)):
                return 1
            request = json.dumps(
                {"role": role, "detail": detail, "after_sequence": 0},
                ensure_ascii=True,
                separators=(",", ":"),
            ).encode() + b"\n"
            client.sendall(request)
            client.settimeout(None)
            pending = bytearray()
            while True:
                chunk = client.recv(1_024)
                if not chunk:
                    if pending:
                        return 1
                    return 0
                pending.extend(chunk)
                if len(pending) > _MAX_RESPONSE_BYTES:
                    return 1
                while b"\n" in pending:
                    line, _, remainder = pending.partition(b"\n")
                    pending = bytearray(remainder)
                    rendered = json.loads(line)
                    if type(rendered) is not str or len(rendered.encode()) > _MAX_RESPONSE_BYTES:
                        return 1
                    output.write(rendered + "\n")
                    flush = getattr(output, "flush", None)
                    if callable(flush):
                        flush()
        finally:
            client.close()
    except (ConnectionError, json.JSONDecodeError, OSError, TypeError, ValueError):
        return 1


def _main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Follow Aster quickstart node records")
    parser.add_argument("--socket", required=True, type=Path)
    parser.add_argument("--role", required=True, choices=sorted(_ROLES))
    parser.add_argument("--detail", default="guided", choices=("compact", "guided", "debug"))
    parser.add_argument("--peer-pid", required=True, type=int)
    arguments = parser.parse_args(argv)
    return follow_records(
        arguments.socket,
        arguments.role,
        arguments.detail,
        sys.stdout,
        expected_peer_pid=arguments.peer_pid,
    )


if __name__ == "__main__":
    raise SystemExit(_main())


__all__ = ["AttachServer", "NodeRole", "follow_records"]
