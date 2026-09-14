#!/usr/bin/env python3
# Copyright 2026 Defense Unicorns, Inc.
# SPDX-License-Identifier: Apache-2.0
"""Validate the documentation archive manifest and reviewed candidate inventory."""

from __future__ import annotations

import argparse
import csv
import errno
import hashlib
import io
import os
from pathlib import Path, PurePosixPath
import re
import stat
import subprocess
import sys
from typing import NamedTuple


ROOT = Path(__file__).resolve().parents[1]
MANIFEST_RELATIVE = Path("archive/MANIFEST.sha256")
TEMP_MANIFEST_NAME = ".MANIFEST.sha256.tmp"
HASH_CHUNK_BYTES = 1024 * 1024
MANIFEST_ENTRY = re.compile(r"([0-9a-f]{64})  ([^\r\n]+)\n")
INVENTORY_RELATIVE = Path("docs/implementation/documentation-refactor-inventory.csv")
INVENTORY_HEADER = (
    "source_path", "current_path", "target_path", "document_class",
    "disposition", "batch", "reason",
)
DOCUMENT_CLASSES = {
    "decision", "design-history", "implementation", "research", "validation"
}
DISPOSITIONS = {
    "keep-current", "relocate-current", "archive-ready",
    "extract-current-first", "migrate-consumers-first", "archived"
}
BATCHES = {
    "retain", "archive-plans", "archive-research", "archive-decisions",
    "current-hierarchy", "consolidation"
}
ORIGINAL_REVIEW_ROOTS = (
    "docs/superpowers/plans",
    "docs/superpowers/specs",
    "docs/proposals",
    "docs/evaluations",
    "docs/decisions",
)
SOURCE_PREFIXES = tuple(f"{root}/" for root in ORIGINAL_REVIEW_ROOTS)
REVIEW_ROOTS = (
    *ORIGINAL_REVIEW_ROOTS,
    "archive/research/proposals",
    "archive/research/evaluations",
    "archive/design-history/plans",
    "archive/design-history/superseded-specs",
    "archive/design-history/retired-decisions",
)
ARCHIVE_PREFIXES = {
    "research": ("archive/research/proposals/", "archive/research/evaluations/"),
    "design-history": (
        "archive/design-history/plans/", "archive/design-history/superseded-specs/",
    ),
    "decision": ("archive/design-history/retired-decisions/",),
}


class InventoryRow(NamedTuple):
    source_path: str
    current_path: str
    target_path: str
    document_class: str
    disposition: str
    batch: str
    reason: str


class ArchiveViolation(ValueError):
    """The documentation archive or candidate inventory violates its boundary."""


def fail(message: str) -> None:
    raise ArchiveViolation(message)


def _reject_unsafe_name(name: str) -> None:
    if "\n" in name or "\r" in name or "  " in name:
        fail(f"unsafe archive filename {name!r}")


def _utf8_bytes(value: str, description: str) -> bytes:
    try:
        return value.encode("utf-8")
    except UnicodeEncodeError:
        fail(f"{description} is not valid UTF-8")


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
            _utf8_bytes(relative_path.as_posix(), "archive path")

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
    supplied_bytes = _utf8_bytes(supplied, "archive manifest")
    paths = _canonical_manifest_paths(supplied)
    expected = render_manifest(repository_root)
    if supplied_bytes != _utf8_bytes(expected, "rendered archive manifest"):
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


def _inventory_path(path: str) -> None:
    _utf8_bytes(path, "inventory path")
    if (
        not path
        or "\\" in path
        or any(ord(character) < 32 or ord(character) == 127 for character in path)
        or any(part in ("", ".", "..") for part in path.split("/"))
        or PurePosixPath(path).is_absolute()
        or PurePosixPath(path).as_posix() != path
        or path != path.strip()
    ):
        fail(f"non-canonical inventory path {path!r}")


def _validate_inventory_rows(rows: tuple[InventoryRow, ...]) -> None:
    sources: set[str] = set()
    currents: set[str] = set()
    targets: set[str] = set()
    for row in rows:
        for field, value in zip(INVENTORY_HEADER, row):
            if not isinstance(value, str) or (not value and field != "target_path"):
                fail(f"inventory {field} must be nonempty text")
            if value != value.strip():
                fail(f"inventory {field} has whitespace padding")
        for path in (row.source_path, row.current_path, row.target_path):
            if path:
                _inventory_path(path)
        if row.document_class not in DOCUMENT_CLASSES:
            fail(f"invalid document class {row.document_class!r}")
        if row.disposition not in DISPOSITIONS:
            fail(f"invalid disposition {row.disposition!r}")
        if row.batch not in BATCHES:
            fail(f"invalid batch {row.batch!r}")
        if not row.source_path.startswith(SOURCE_PREFIXES):
            fail("inventory source_path must be below an original review root")

        if row.disposition == "archived":
            if row.target_path:
                fail("archived row must have an empty target_path")
            archive_path = row.current_path
        else:
            if row.current_path != row.source_path:
                fail("unarchived current_path must equal source_path")
            archive_path = row.target_path
        if row.disposition == "keep-current":
            if row.target_path:
                fail("keep-current row must have an empty target_path")
        elif row.disposition == "relocate-current":
            if not row.target_path.startswith("docs/"):
                fail("relocate-current target_path must be below docs/")
        elif not archive_path.startswith(ARCHIVE_PREFIXES.get(row.document_class, ())):
            fail(f"archive path is incompatible with {row.document_class}: {archive_path!r}")

        for path, seen, field in (
            (row.source_path, sources, "source_path"),
            (row.current_path, currents, "current_path"),
            (row.target_path, targets, "target_path"),
        ):
            if path:
                if path in seen:
                    fail(f"duplicate inventory {field}: {path}")
                seen.add(path)
    expected_order = sorted(sources, key=lambda path: path.encode("utf-8"))
    if [row.source_path for row in rows] != expected_order:
        fail("inventory source paths are not bytewise sorted")


def parse_inventory(text: str) -> tuple[InventoryRow, ...]:
    """Parse exact canonical UTF-8 CSV, preserving quoted reason text."""
    if not isinstance(text, str):
        fail("inventory must be supplied as decoded UTF-8 text")
    original = _utf8_bytes(text, "inventory")
    if text.startswith("\ufeff") or "\x00" in text or "\r" in text:
        fail("inventory contains a BOM, NUL, or CR")
    try:
        reader = csv.DictReader(io.StringIO(text, newline=""), strict=True)
        if reader.fieldnames != list(INVENTORY_HEADER):
            fail("inventory has a non-canonical header")
        rows = []
        for values in reader:
            if None in values or any(value is None for value in values.values()):
                fail("inventory row has extra or missing columns")
            rows.append(InventoryRow(**values))
    except csv.Error as error:
        fail(f"invalid inventory CSV: {error}")
    result = tuple(rows)
    _validate_inventory_rows(result)
    output = io.StringIO(newline="")
    writer = csv.writer(output, lineterminator="\n")
    writer.writerow(INVENTORY_HEADER)
    writer.writerows(result)
    if output.getvalue().encode("utf-8") != original:
        fail("inventory is not canonical CSV")
    return result


def _regular_candidate(repository_root: Path, relative_path: str) -> None:
    """Reject missing files, special entries, and symlinked ancestors."""
    _inventory_path(relative_path)
    path = repository_root
    parts = relative_path.split("/")
    for index, part in enumerate(parts):
        path = path / part
        try:
            mode = path.lstat().st_mode
        except OSError as error:
            fail(f"cannot inspect candidate {relative_path}: {error}")
        expected = stat.S_ISREG if index == len(parts) - 1 else stat.S_ISDIR
        if not expected(mode):
            fail(f"candidate is not a regular file with real directory parents: {relative_path}")


def tracked_candidate_paths(repository_root: Path) -> tuple[str, ...]:
    """Enumerate exact Git-tracked coverage across current and archive roots."""
    try:
        result = subprocess.run(
            ["git", "-C", str(repository_root), "ls-files", "-z", "--", *REVIEW_ROOTS],
            check=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
    except OSError as error:
        fail(f"cannot enumerate tracked candidates: {error}")
    if result.returncode != 0:
        fail("git ls-files failed while enumerating tracked candidates")
    try:
        decoded = result.stdout.decode("utf-8", errors="strict")
    except UnicodeDecodeError:
        fail("tracked candidate paths are not valid UTF-8")
    if decoded and not decoded.endswith("\x00"):
        fail("git candidate list lacks its NUL terminator")
    paths = decoded[:-1].split("\x00") if decoded else []
    for path in paths:
        _regular_candidate(repository_root, path)
    return tuple(sorted(paths, key=lambda path: path.encode("utf-8")))


def validate_inventory(
    rows: tuple[InventoryRow, ...], candidate_paths: tuple[str, ...]
) -> None:
    """Validate coverage, real current files, unused targets, and archived custody."""
    _validate_inventory_rows(rows)
    current_paths = {row.current_path for row in rows}
    candidates = set(candidate_paths)
    if current_paths != candidates:
        missing = sorted(candidates - current_paths)
        unexpected = sorted(current_paths - candidates)
        fail(f"inventory coverage differs: missing={missing}, unexpected={unexpected}")
    manifest_paths: set[str] | None = None
    for row in rows:
        _regular_candidate(ROOT, row.current_path)
        if row.target_path:
            target = ROOT / row.target_path
            if os.path.lexists(target):
                fail(f"inventory future target already exists: {row.target_path}")
        if row.disposition == "archived":
            if manifest_paths is None:
                manifest = _read_manifest(ROOT)
                validate_manifest(ROOT, manifest)
                manifest_paths = set(_canonical_manifest_paths(manifest))
            if row.current_path not in manifest_paths:
                fail(f"archived inventory path is absent from manifest: {row.current_path}")


def _read_inventory(repository_root: Path) -> tuple[InventoryRow, ...]:
    _regular_candidate(repository_root, INVENTORY_RELATIVE.as_posix())
    try:
        raw = (repository_root / INVENTORY_RELATIVE).read_bytes()
        text = raw.decode("utf-8", errors="strict")
    except (OSError, UnicodeDecodeError) as error:
        fail(f"cannot read inventory as UTF-8: {error}")
    return parse_inventory(text)


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
        rows = _read_inventory(ROOT)
        validate_inventory(rows, tracked_candidate_paths(ROOT))
    except ArchiveViolation as error:
        print(f"documentation archive failed: {error}", file=sys.stderr)
        return 1
    print(f"documentation archive passed: {len(rows)} candidate rows, {count} archive files")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
