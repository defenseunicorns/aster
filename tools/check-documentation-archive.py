#!/usr/bin/env python3
# Copyright 2026 Defense Unicorns, Inc.
# SPDX-License-Identifier: Apache-2.0
"""Validate or explicitly regenerate the documentation archive manifest."""

from __future__ import annotations

import argparse
import errno
import hashlib
import os
from pathlib import Path, PurePosixPath
import re
import stat
import sys


ROOT = Path(__file__).resolve().parents[1]
MANIFEST_RELATIVE = Path("archive/MANIFEST.sha256")
TEMP_MANIFEST_NAME = ".MANIFEST.sha256.tmp"
HASH_CHUNK_BYTES = 1024 * 1024
MANIFEST_ENTRY = re.compile(r"([0-9a-f]{64})  ([^\r\n]+)\n")


class ArchiveViolation(ValueError):
    """The documentation archive does not satisfy its manifest boundary."""


def fail(message: str) -> None:
    raise ArchiveViolation(message)


def _reject_unsafe_name(name: str) -> None:
    if "\n" in name or "\r" in name or "  " in name:
        fail(f"unsafe archive filename {name!r}")


def archive_files(repository_root: Path) -> list[Path]:
    """Return regular archive files in canonical bytewise path order."""
    repository_root = repository_root.resolve()
    archive_root = repository_root / "archive"
    try:
        archive_status = archive_root.lstat()
    except FileNotFoundError:
        fail("archive directory is absent")
    if stat.S_ISLNK(archive_status.st_mode) or not stat.S_ISDIR(
        archive_status.st_mode
    ):
        fail("archive directory is not a real directory")
    archive_root_resolved = archive_root.resolve(strict=True)

    files: list[Path] = []

    def visit(directory: Path) -> None:
        try:
            entries = list(os.scandir(directory))
        except OSError as error:
            fail(f"cannot scan {directory.relative_to(repository_root)}: {error}")

        for entry in entries:
            _reject_unsafe_name(entry.name)
            path = Path(entry.path)
            relative_path = path.relative_to(repository_root)

            if entry.is_symlink():
                fail(f"archive contains symbolic link {relative_path.as_posix()}")

            try:
                resolved_path = path.resolve(strict=True)
                resolved_path.relative_to(archive_root_resolved)
            except (OSError, ValueError):
                fail(f"archive path escapes archive root: {relative_path.as_posix()}")

            try:
                if entry.is_dir(follow_symlinks=False):
                    visit(path)
                elif entry.is_file(follow_symlinks=False):
                    if relative_path != MANIFEST_RELATIVE:
                        files.append(path)
                else:
                    fail(f"archive contains special file {relative_path.as_posix()}")
            except OSError as error:
                fail(f"cannot inspect {relative_path.as_posix()}: {error}")

    visit(archive_root)
    sort_key = lambda path: path.relative_to(repository_root).as_posix().encode("utf-8")
    return sorted(files, key=sort_key)


def render_manifest(repository_root: Path) -> str:
    """Render the canonical SHA-256 manifest for the archive."""
    repository_root = repository_root.resolve()
    rendered: list[str] = []
    for path in archive_files(repository_root):
        digest = hashlib.sha256()
        try:
            with path.open("rb") as source:
                while chunk := source.read(HASH_CHUNK_BYTES):
                    digest.update(chunk)
        except OSError as error:
            fail(f"cannot hash {path.relative_to(repository_root).as_posix()}: {error}")
        relative_path = path.relative_to(repository_root)
        rendered.append(f"{digest.hexdigest()}  {relative_path.as_posix()}\n")
    return "".join(rendered)


def _canonical_manifest_paths(manifest: str) -> list[str]:
    if manifest and not manifest.endswith("\n"):
        fail("manifest must end with a trailing LF")

    paths: list[str] = []
    for line_number, line in enumerate(manifest.splitlines(keepends=True), start=1):
        match = MANIFEST_ENTRY.fullmatch(line)
        if match is None:
            fail(f"non-canonical manifest entry on line {line_number}")
        path_text = match.group(2)
        if not path_text.startswith("archive/"):
            fail(f"manifest entry outside archive on line {line_number}")
        if "  " in path_text:
            fail(f"non-canonical archive path on line {line_number}")
        pure_path = PurePosixPath(path_text)
        if (
            pure_path.as_posix() != path_text
            or any(part in ("", ".", "..") for part in pure_path.parts)
        ):
            fail(f"non-canonical archive path on line {line_number}")
        if path_text == MANIFEST_RELATIVE.as_posix():
            fail("archive manifest must not list itself")
        if path_text in paths:
            fail(f"manifest contains duplicate path {path_text}")
        paths.append(path_text)

    expected_order = sorted(paths, key=lambda path: path.encode("utf-8"))
    if paths != expected_order:
        fail("manifest paths are not bytewise sorted")
    return paths


def _read_manifest(repository_root: Path) -> str:
    manifest_path = repository_root.resolve() / MANIFEST_RELATIVE
    try:
        manifest_status = manifest_path.lstat()
    except FileNotFoundError:
        fail("archive manifest is absent")
    if stat.S_ISLNK(manifest_status.st_mode) or not stat.S_ISREG(
        manifest_status.st_mode
    ):
        fail("archive manifest is not a regular file")
    try:
        manifest_bytes = manifest_path.read_bytes()
    except OSError as error:
        fail(f"cannot read archive manifest: {error}")
    try:
        return manifest_bytes.decode("utf-8", errors="strict")
    except UnicodeDecodeError as error:
        fail(f"archive manifest is not canonical UTF-8: {error}")


def validate_manifest(repository_root: Path, manifest: str | None = None) -> int:
    """Validate canonical grammar and exact bytes; return the entry count."""
    repository_root = repository_root.resolve()
    supplied = _read_manifest(repository_root) if manifest is None else manifest
    if not isinstance(supplied, str):
        fail("archive manifest must be supplied as decoded UTF-8 text")
    paths = _canonical_manifest_paths(supplied)
    expected = render_manifest(repository_root)
    if supplied.encode("utf-8") != expected.encode("utf-8"):
        fail("archive manifest differs from the archived files")
    return len(paths)


def _sync_directory(directory: Path) -> None:
    flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0)
    try:
        descriptor = os.open(directory, flags)
    except OSError as error:
        if error.errno in (errno.EACCES, errno.EINVAL, errno.ENOTSUP):
            return
        raise
    try:
        try:
            os.fsync(descriptor)
        except OSError as error:
            if error.errno not in (errno.EBADF, errno.EINVAL, errno.ENOTSUP):
                raise
    finally:
        os.close(descriptor)


def write_manifest(repository_root: Path) -> int:
    """Atomically write and then validate the canonical archive manifest."""
    repository_root = repository_root.resolve()
    archive_root = repository_root / "archive"
    manifest_path = repository_root / MANIFEST_RELATIVE
    temporary_path = archive_root / TEMP_MANIFEST_NAME

    try:
        existing_status = manifest_path.lstat()
    except FileNotFoundError:
        pass
    else:
        if stat.S_ISLNK(existing_status.st_mode) or not stat.S_ISREG(
            existing_status.st_mode
        ):
            fail("existing manifest is not a regular file")

    rendered = render_manifest(repository_root).encode("utf-8")
    created_temporary = False
    try:
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
        flags |= getattr(os, "O_CLOEXEC", 0)
        flags |= getattr(os, "O_NOFOLLOW", 0)
        descriptor = os.open(temporary_path, flags, 0o644)
        created_temporary = True
        with os.fdopen(descriptor, "wb") as destination:
            destination.write(rendered)
            destination.flush()
            os.fsync(destination.fileno())
        os.replace(temporary_path, manifest_path)
        created_temporary = False
        _sync_directory(archive_root)
    except ArchiveViolation:
        raise
    except OSError as error:
        fail(f"cannot write archive manifest: {error}")
    finally:
        if created_temporary:
            try:
                temporary_path.unlink()
            except FileNotFoundError:
                pass

    return validate_manifest(repository_root, _read_manifest(repository_root))


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--write-manifest",
        action="store_true",
        help="atomically replace the archive manifest before validating it",
    )
    arguments = parser.parse_args(argv)
    try:
        if arguments.write_manifest:
            count = write_manifest(ROOT)
        else:
            count = validate_manifest(ROOT)
    except ArchiveViolation as error:
        print(f"documentation archive failed: {error}", file=sys.stderr)
        return 1
    print(f"documentation archive passed: {count} archive files")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
