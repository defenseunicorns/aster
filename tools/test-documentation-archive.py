#!/usr/bin/env python3
# Copyright 2026 Defense Unicorns, Inc.
# SPDX-License-Identifier: Apache-2.0
"""Regression tests for the deterministic documentation archive manifest."""

from __future__ import annotations

import importlib.util
import os
from pathlib import Path
import tempfile
import unittest


CHECKER_PATH = Path(__file__).with_name("check-documentation-archive.py")
SPEC = importlib.util.spec_from_file_location("documentation_archive", CHECKER_PATH)
if SPEC is None or SPEC.loader is None:
    raise RuntimeError(f"cannot load {CHECKER_PATH}")
CHECKER = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(CHECKER)

ZERO_DIGEST = "0" * 64


class DocumentationArchiveManifestTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary_directory = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary_directory.name)
        (self.root / "archive").mkdir()

    def tearDown(self) -> None:
        self.temporary_directory.cleanup()

    def write(self, relative_path: str, content: bytes) -> Path:
        path = self.root / relative_path
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(content)
        return path

    def test_manifest_is_bytewise_sorted_and_excludes_itself(self) -> None:
        self.write("archive/research/z.md", b"z\n")
        self.write("archive/research/a.md", b"a\n")
        self.write("archive/MANIFEST.sha256", b"ignored\n")

        rendered = CHECKER.render_manifest(self.root)

        self.assertEqual(
            rendered,
            "87428fc522803d31065e7bce3cf03fe475096631e5e07bbd7a0fde60c4cf25c7"
            "  archive/research/a.md\n"
            "c865f6c5ab8d1b0bcd383a5e1e3879d22681c96bf462c269b7581d523fbe70ab"
            "  archive/research/z.md\n",
        )
        paths = [line.split("  ", 1)[1] for line in rendered.splitlines()]
        self.assertEqual(paths, ["archive/research/a.md", "archive/research/z.md"])
        self.assertTrue(rendered.endswith("\n"))

    def test_digest_mismatch_fails(self) -> None:
        self.write("archive/README.md", b"policy\n")
        actual = CHECKER.render_manifest(self.root)
        self.write("archive/README.md", b"changed\n")

        with self.assertRaisesRegex(CHECKER.ArchiveViolation, "manifest differs"):
            CHECKER.validate_manifest(self.root, actual)

    def test_absent_manifest_fails(self) -> None:
        with self.assertRaisesRegex(CHECKER.ArchiveViolation, "manifest is absent"):
            CHECKER.validate_manifest(self.root)

    def test_uppercase_or_malformed_digest_fails(self) -> None:
        invalid_digests = ("A" * 64, "0" * 63, "g" * 64)
        for digest in invalid_digests:
            with self.subTest(digest=digest):
                manifest = f"{digest}  archive/README.md\n"
                with self.assertRaisesRegex(
                    CHECKER.ArchiveViolation, "non-canonical manifest entry"
                ):
                    CHECKER.validate_manifest(self.root, manifest)

    def test_duplicate_path_fails(self) -> None:
        manifest = (
            f"{ZERO_DIGEST}  archive/README.md\n"
            f"{ZERO_DIGEST}  archive/README.md\n"
        )
        with self.assertRaisesRegex(CHECKER.ArchiveViolation, "duplicate path"):
            CHECKER.validate_manifest(self.root, manifest)

    def test_unsorted_entries_fail(self) -> None:
        manifest = (
            f"{ZERO_DIGEST}  archive/z.md\n"
            f"{ZERO_DIGEST}  archive/a.md\n"
        )
        with self.assertRaisesRegex(CHECKER.ArchiveViolation, "bytewise sorted"):
            CHECKER.validate_manifest(self.root, manifest)

    def test_missing_trailing_lf_fails(self) -> None:
        manifest = f"{ZERO_DIGEST}  archive/README.md"
        with self.assertRaisesRegex(CHECKER.ArchiveViolation, "trailing LF"):
            CHECKER.validate_manifest(self.root, manifest)

    def test_unmanifested_file_fails(self) -> None:
        self.write("archive/README.md", b"policy\n")
        with self.assertRaisesRegex(CHECKER.ArchiveViolation, "manifest differs"):
            CHECKER.validate_manifest(self.root, "")

    def test_manifest_self_entry_fails(self) -> None:
        manifest = f"{ZERO_DIGEST}  archive/MANIFEST.sha256\n"
        with self.assertRaisesRegex(CHECKER.ArchiveViolation, "must not list itself"):
            CHECKER.validate_manifest(self.root, manifest)

    def test_manifest_entry_outside_archive_fails(self) -> None:
        manifest = f"{ZERO_DIGEST}  docs/README.md\n"
        with self.assertRaisesRegex(CHECKER.ArchiveViolation, "outside archive"):
            CHECKER.validate_manifest(self.root, manifest)

    def test_noncanonical_archive_path_fails(self) -> None:
        for relative_path in (
            "archive/../README.md",
            "archive//README.md",
            "archive/./README.md",
        ):
            with self.subTest(relative_path=relative_path):
                manifest = f"{ZERO_DIGEST}  {relative_path}\n"
                with self.assertRaisesRegex(
                    CHECKER.ArchiveViolation, "non-canonical archive path"
                ):
                    CHECKER.validate_manifest(self.root, manifest)

    def test_symlinked_file_fails(self) -> None:
        target = self.write("outside.md", b"outside\n")
        link = self.root / "archive" / "linked.md"
        link.symlink_to(target)
        with self.assertRaisesRegex(CHECKER.ArchiveViolation, "symbolic link"):
            CHECKER.render_manifest(self.root)

    def test_symlinked_directory_fails(self) -> None:
        target = self.root / "outside"
        target.mkdir()
        link = self.root / "archive" / "linked"
        link.symlink_to(target, target_is_directory=True)
        with self.assertRaisesRegex(CHECKER.ArchiveViolation, "symbolic link"):
            CHECKER.render_manifest(self.root)

    @unittest.skipUnless(hasattr(os, "mkfifo"), "FIFO creation is unavailable")
    def test_fifo_fails(self) -> None:
        fifo = self.root / "archive" / "named-pipe"
        os.mkfifo(fifo)
        with self.assertRaisesRegex(CHECKER.ArchiveViolation, "special file"):
            CHECKER.render_manifest(self.root)

    def test_unsafe_filename_fails(self) -> None:
        for filename in ("line\nbreak.md", "carriage\rreturn.md", "two  spaces.md"):
            with self.subTest(filename=filename):
                path = self.write(f"archive/{filename}", b"content\n")
                try:
                    with self.assertRaisesRegex(
                        CHECKER.ArchiveViolation, "unsafe archive filename"
                    ):
                        CHECKER.render_manifest(self.root)
                finally:
                    path.unlink()

    def test_write_manifest_atomically_replaces_regular_manifest(self) -> None:
        self.write("archive/README.md", b"policy\n")
        self.write("archive/MANIFEST.sha256", b"stale\n")

        count = CHECKER.write_manifest(self.root)

        self.assertEqual(count, 1)
        self.assertEqual(
            (self.root / "archive/MANIFEST.sha256").read_bytes(),
            b"c82fc52c78bf8154d4dd7d8766c422ab151052d72098d72ded237aafcd78e4e0"
            b"  archive/README.md\n",
        )
        self.assertFalse((self.root / "archive/.MANIFEST.sha256.tmp").exists())

    def test_write_manifest_refuses_existing_manifest_symlink(self) -> None:
        target = self.write("outside-manifest", b"do not replace\n")
        (self.root / "archive/MANIFEST.sha256").symlink_to(target)

        with self.assertRaisesRegex(
            CHECKER.ArchiveViolation, "existing manifest is not a regular file"
        ):
            CHECKER.write_manifest(self.root)

        self.assertEqual(target.read_bytes(), b"do not replace\n")

    def test_write_manifest_refuses_nonregular_existing_manifest(self) -> None:
        (self.root / "archive/MANIFEST.sha256").mkdir()
        with self.assertRaisesRegex(
            CHECKER.ArchiveViolation, "existing manifest is not a regular file"
        ):
            CHECKER.write_manifest(self.root)


if __name__ == "__main__":
    unittest.main()
