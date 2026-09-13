# Copyright 2026 Defense Unicorns, Inc.
# SPDX-License-Identifier: Apache-2.0
"""Canonical JSON and descriptor-relative read-only bundle access."""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
import os
from pathlib import Path
import stat
from typing import Any


READ_CHUNK_BYTES = 1024 * 1024
DIRECTORY_FLAGS = os.O_RDONLY | os.O_CLOEXEC | os.O_DIRECTORY | os.O_NOFOLLOW
FILE_FLAGS = os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW


class CanonicalJsonError(ValueError):
    """Canonical JSON bytes violate the frozen encoding contract."""


class SafeInputError(ValueError):
    """An input cannot be safely read beneath its declared root."""


@dataclass(frozen=True)
class ReadResult:
    """Sanitized result of a bounded immutable file read."""

    data: bytes
    digest: str
    size: int


def canonical_json_bytes(value: Any) -> bytes:
    """Encode one canonical, LF-terminated JSON value."""

    try:
        encoded = json.dumps(
            value,
            ensure_ascii=True,
            separators=(",", ":"),
            sort_keys=True,
            allow_nan=False,
        )
    except (TypeError, ValueError) as exc:
        raise CanonicalJsonError("value is not canonical JSON") from exc
    return (encoded + "\n").encode("ascii")


def _reject_duplicate_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise CanonicalJsonError("duplicate object key")
        result[key] = value
    return result


def _reject_number(_value: str) -> None:
    raise CanonicalJsonError("only integer JSON numbers are supported")


def load_canonical_json(data: bytes, *, label: str, maximum: int) -> dict[str, Any]:
    """Decode a canonical object while rejecting ambiguous JSON forms."""

    if not data or len(data) > maximum:
        raise CanonicalJsonError(f"{label} size is outside the supported range")
    if not data.endswith(b"\n") or b"\r" in data or b"\x00" in data:
        raise CanonicalJsonError(f"{label} is not LF-terminated canonical JSON")
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise CanonicalJsonError(f"{label} is not UTF-8") from exc
    try:
        value = json.loads(
            text,
            object_pairs_hook=_reject_duplicate_pairs,
            parse_float=_reject_number,
            parse_constant=_reject_number,
        )
    except CanonicalJsonError:
        raise
    except (json.JSONDecodeError, UnicodeDecodeError) as exc:
        raise CanonicalJsonError(f"{label} is not valid JSON") from exc
    if not isinstance(value, dict):
        raise CanonicalJsonError(f"{label} must contain one JSON object")
    if canonical_json_bytes(value) != data:
        raise CanonicalJsonError(f"{label} bytes are not canonical")
    return value


def _same_identity(left: os.stat_result, right: os.stat_result) -> bool:
    return (
        left.st_dev,
        left.st_ino,
        stat.S_IFMT(left.st_mode),
        left.st_size,
        left.st_mtime_ns,
        left.st_ctime_ns,
    ) == (
        right.st_dev,
        right.st_ino,
        stat.S_IFMT(right.st_mode),
        right.st_size,
        right.st_mtime_ns,
        right.st_ctime_ns,
    )


def _components(path: str, *, allow_absolute: bool) -> list[str]:
    if not isinstance(path, str) or not path:
        raise SafeInputError("empty input path")
    if "\x00" in path:
        raise SafeInputError("NUL in input path")
    absolute = path.startswith("/")
    if absolute != allow_absolute:
        kind = "absolute" if absolute else "relative"
        raise SafeInputError(f"unexpected {kind} input path")
    parts = path.split("/")
    if absolute:
        parts = parts[1:]
    if not parts or any(part in ("", ".", "..") for part in parts):
        raise SafeInputError("non-canonical input path")
    return parts


def _open_child_directory(parent_fd: int, name: str) -> int:
    try:
        before = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
        child_fd = os.open(name, DIRECTORY_FLAGS, dir_fd=parent_fd)
    except OSError as exc:
        raise SafeInputError("cannot open input directory") from exc
    try:
        opened = os.fstat(child_fd)
        after = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
        if not stat.S_ISDIR(opened.st_mode) or not _same_identity(before, opened):
            raise SafeInputError("input directory identity changed")
        if not _same_identity(opened, after):
            raise SafeInputError("input directory changed while opened")
    except BaseException:
        os.close(child_fd)
        raise
    return child_fd


def _open_absolute_directory(path: Path) -> int:
    parts = _components(os.fspath(path.absolute()), allow_absolute=True)
    current = os.open("/", DIRECTORY_FLAGS)
    try:
        for part in parts:
            child = _open_child_directory(current, part)
            os.close(current)
            current = child
        return current
    except BaseException:
        os.close(current)
        raise


class SafeRoot:
    """Retain a directory descriptor and read immutable regular files below it."""

    def __init__(self, path: Path | str):
        self._path = Path(path)
        self._fd: int | None = None

    def __enter__(self) -> "SafeRoot":
        if self._fd is not None:
            raise RuntimeError("safe root is already open")
        self._fd = _open_absolute_directory(self._path)
        return self

    def __exit__(self, _type: object, _value: object, _traceback: object) -> None:
        self.close()

    def close(self) -> None:
        if self._fd is not None:
            os.close(self._fd)
            self._fd = None

    def read_file(self, path: str, *, maximum: int) -> ReadResult:
        if self._fd is None:
            raise RuntimeError("safe root is not open")
        if not isinstance(maximum, int) or isinstance(maximum, bool) or maximum < 1:
            raise ValueError("maximum must be a positive integer")
        parts = _components(path, allow_absolute=False)
        directory_fd = os.dup(self._fd)
        file_fd: int | None = None
        try:
            for part in parts[:-1]:
                child_fd = _open_child_directory(directory_fd, part)
                os.close(directory_fd)
                directory_fd = child_fd
            name = parts[-1]
            try:
                before = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
            except OSError as exc:
                raise SafeInputError("input file is unavailable") from exc
            if not stat.S_ISREG(before.st_mode) or before.st_nlink != 1:
                raise SafeInputError("input is not a singly linked regular file")
            if before.st_size > maximum:
                raise SafeInputError("input file exceeds its size limit")
            try:
                file_fd = os.open(name, FILE_FLAGS, dir_fd=directory_fd)
            except OSError as exc:
                raise SafeInputError("cannot open input file") from exc
            opened = os.fstat(file_fd)
            if not _same_identity(before, opened):
                raise SafeInputError("input file identity changed before read")
            chunks: list[bytes] = []
            total = 0
            digest = hashlib.sha256()
            while True:
                chunk = os.read(file_fd, min(READ_CHUNK_BYTES, maximum + 1 - total))
                if not chunk:
                    break
                total += len(chunk)
                if total > maximum:
                    raise SafeInputError("input file exceeds its size limit")
                chunks.append(chunk)
                digest.update(chunk)
            final = os.fstat(file_fd)
            after = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
            if not _same_identity(opened, final) or not _same_identity(final, after):
                raise SafeInputError("input file changed while read")
            if total != final.st_size:
                raise SafeInputError("input file size changed while read")
            return ReadResult(
                data=b"".join(chunks),
                digest=f"sha256:{digest.hexdigest()}",
                size=total,
            )
        except SafeInputError:
            raise
        except OSError as exc:
            raise SafeInputError("failed to read input file safely") from exc
        finally:
            if file_fd is not None:
                os.close(file_fd)
            os.close(directory_fd)
