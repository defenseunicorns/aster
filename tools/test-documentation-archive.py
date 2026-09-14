#!/usr/bin/env python3
# Copyright 2026 Defense Unicorns, Inc.
# SPDX-License-Identifier: Apache-2.0
"""Regression tests for the documentation archive manifest and inventory."""

from __future__ import annotations

from contextlib import redirect_stderr, redirect_stdout
import csv
import importlib.util
import io
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch


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

    @unittest.skipUnless(os.name == "posix", "byte-oriented filenames need POSIX")
    def test_non_utf8_filesystem_filename_fails_closed(self) -> None:
        archive_bytes = os.fsencode(self.root / "archive")
        path_bytes = archive_bytes + b"/invalid-\xff.md"
        descriptor = os.open(path_bytes, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        os.close(descriptor)

        try:
            CHECKER.render_manifest(self.root)
        except Exception as error:
            self.assertIsInstance(error, CHECKER.ArchiveViolation)
            self.assertRegex(str(error), "UTF-8")
        else:
            self.fail("non-UTF-8 filesystem name was accepted")

    def test_surrogate_in_supplied_manifest_fails_closed(self) -> None:
        manifest = f"{ZERO_DIGEST}  archive/invalid-\udcff.md\n"

        try:
            CHECKER.validate_manifest(self.root, manifest)
        except Exception as error:
            self.assertIsInstance(error, CHECKER.ArchiveViolation)
            self.assertRegex(str(error), "UTF-8")
        else:
            self.fail("surrogate-containing manifest was accepted")

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


class DocumentationInventoryTests(unittest.TestCase):
    HEADER = "source_path,current_path,target_path,document_class,disposition,batch,reason\n"

    def setUp(self) -> None:
        self.temporary_directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary_directory.cleanup)
        self.root = Path(self.temporary_directory.name)
        subprocess.run(["git", "init", "-q", str(self.root)], check=True)
        self.root_patch = patch.object(CHECKER, "ROOT", self.root)
        self.root_patch.start()
        self.addCleanup(self.root_patch.stop)

    def write(self, path: str, content: bytes = b"document\n") -> Path:
        destination = self.root / path
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_bytes(content)
        return destination

    def track(self, *paths: str) -> None:
        subprocess.run(["git", "-C", str(self.root), "add", "--", *paths], check=True)

    def row(self, **changes: str) -> list[str]:
        values = dict(zip(self.HEADER.strip().split(","), (
            "docs/proposals/a.md", "docs/proposals/a.md", "", "research",
            "keep-current", "retain", "ADR 0028 retains this authority",
        )))
        values.update(changes)
        return list(values.values())

    def csv(self, *rows: list[str]) -> str:
        output = io.StringIO(newline="")
        output.write(self.HEADER)
        csv.writer(output, lineterminator="\n").writerows(rows)
        return output.getvalue()

    def test_all_dispositions_and_quoted_reason_roundtrip(self) -> None:
        for disposition, current, target, batch in (
            ("keep-current", "docs/proposals/a.md", "", "retain"),
            ("relocate-current", "docs/proposals/a.md", "docs/architecture/a.md", "current-hierarchy"),
            ("archive-ready", "docs/proposals/a.md", "archive/research/proposals/a.md", "archive-research"),
            ("extract-current-first", "docs/proposals/a.md", "archive/research/proposals/a.md", "consolidation"),
            ("migrate-consumers-first", "docs/proposals/a.md", "archive/research/proposals/a.md", "archive-research"),
            ("archived", "archive/research/proposals/a.md", "", "archive-research"),
        ):
            with self.subTest(disposition=disposition):
                self.write(current)
                self.track(current)
                (self.root / "archive").mkdir(exist_ok=True)
                CHECKER.write_manifest(self.root)
                rows = CHECKER.parse_inventory(self.csv(self.row(
                    disposition=disposition, current_path=current,
                    target_path=target, batch=batch, reason='ADR 0028, "selected" boundary',
                )))
                self.assertEqual(rows[0].reason, 'ADR 0028, "selected" boundary')
                CHECKER.validate_inventory(rows, (current,))

    def test_noncanonical_csv_fails(self) -> None:
        valid = self.csv(self.row())
        for text in (
            valid.replace("source_path", "source"), "\ufeff" + valid,
            valid.replace("\n", "\r\n"), valid + "\n", valid.rstrip("\n"),
            valid.replace("ADR 0028", "ADR\x00 0028"),
            valid.replace("ADR 0028", " ADR 0028"),
            valid.replace("docs/proposals/a.md", '"docs/proposals/a.md"'),
            valid.replace("authority\n", "authority,extra\n"),
            self.HEADER + "docs/proposals/a.md\n",
            self.HEADER + '"unterminated\n',
            valid.replace("authority", "\udcff"),
        ):
            with self.subTest(text=repr(text)):
                with self.assertRaises(CHECKER.ArchiveViolation):
                    CHECKER.parse_inventory(text)

    def test_blank_required_fields_fail(self) -> None:
        for field in ("source_path", "current_path", "document_class", "disposition", "batch", "reason"):
            with self.subTest(field=field):
                with self.assertRaises(CHECKER.ArchiveViolation):
                    CHECKER.parse_inventory(self.csv(self.row(**{field: ""})))

    def test_unsafe_paths_fail_in_every_path_column(self) -> None:
        for path in ("/docs/a.md", "docs/../a.md", "docs/./a.md", "docs//a.md", "docs\\a.md", ".", "..", "docs/a.md/", "docs/a\nb.md"):
            for field in ("source_path", "current_path", "target_path"):
                with self.subTest(path=path, field=field):
                    with self.assertRaises(CHECKER.ArchiveViolation):
                        CHECKER.parse_inventory(self.csv(self.row(**{field: path})))

    def test_duplicate_source_current_and_future_target_fail(self) -> None:
        cases = (
            (self.row(), self.row()),
            (self.row(disposition="archived", current_path="archive/research/proposals/x.md"),
             self.row(source_path="docs/proposals/b.md", disposition="archived", current_path="archive/research/proposals/x.md")),
            (self.row(disposition="archive-ready", target_path="archive/research/proposals/x.md"),
             self.row(source_path="docs/proposals/b.md", current_path="docs/proposals/b.md", disposition="archive-ready", target_path="archive/research/proposals/x.md")),
        )
        for rows in cases:
            with self.subTest(rows=rows):
                with self.assertRaises(CHECKER.ArchiveViolation):
                    CHECKER.parse_inventory(self.csv(*rows))

    def test_unsorted_sources_fail(self) -> None:
        with self.assertRaises(CHECKER.ArchiveViolation):
            CHECKER.parse_inventory(self.csv(
                self.row(source_path="docs/proposals/z.md", current_path="docs/proposals/z.md"), self.row(),
            ))

    def test_invalid_states_classes_and_prefixes_fail(self) -> None:
        for changes in (
            {"document_class": "unknown"}, {"disposition": "pending"}, {"batch": "later"},
            {"current_path": "docs/proposals/b.md"}, {"source_path": "archive/research/proposals/a.md"},
            {"target_path": "docs/a.md"}, {"disposition": "relocate-current"},
            {"disposition": "relocate-current", "target_path": "archive/research/proposals/a.md"},
            {"disposition": "archive-ready", "target_path": "docs/a.md"},
            {"disposition": "extract-current-first", "target_path": "archive/research/a.md"},
            {"disposition": "migrate-consumers-first", "document_class": "decision", "target_path": "archive/research/proposals/a.md"},
            {"disposition": "archived"},
            {"disposition": "archived", "current_path": "archive/design-history/plans/a.md"},
            {"disposition": "archived", "current_path": "archive/research/proposals/a.md", "target_path": "docs/a.md"},
        ):
            with self.subTest(changes=changes):
                with self.assertRaises(CHECKER.ArchiveViolation):
                    CHECKER.parse_inventory(self.csv(self.row(**changes)))
        for document_class in ("implementation", "validation"):
            for disposition in ("archive-ready", "extract-current-first", "migrate-consumers-first", "archived"):
                with self.subTest(document_class=document_class, disposition=disposition):
                    with self.assertRaises(CHECKER.ArchiveViolation):
                        CHECKER.parse_inventory(self.csv(self.row(
                            document_class=document_class, disposition=disposition,
                            target_path="archive/research/proposals/a.md",
                        )))

    def test_class_compatible_archive_prefixes_and_current_classes(self) -> None:
        for document_class, prefix in (
            ("research", "archive/research/proposals/"),
            ("research", "archive/research/evaluations/"),
            ("design-history", "archive/design-history/plans/"),
            ("design-history", "archive/design-history/superseded-specs/"),
            ("decision", "archive/design-history/retired-decisions/"),
        ):
            rows = CHECKER.parse_inventory(self.csv(self.row(
                document_class=document_class, disposition="archive-ready", target_path=prefix + "a.md",
            )))
            self.assertEqual(rows[0].target_path, prefix + "a.md")
        for document_class in ("implementation", "validation"):
            for disposition, target in (("keep-current", ""), ("relocate-current", "docs/validation/a.md")):
                self.assertEqual(len(CHECKER.parse_inventory(self.csv(self.row(
                    document_class=document_class, disposition=disposition, target_path=target,
                )))), 1)

    def test_tracked_coverage_includes_archive_roots_and_ignores_untracked(self) -> None:
        paths = ("archive/research/proposals/a.md", "docs/decisions/a.md", "docs/superpowers/specs/é.md")
        for path in (*paths, "docs/proposals/untracked.md", "docs/implementation/outside.md"):
            self.write(path)
        self.track(*paths, "docs/implementation/outside.md")
        self.assertEqual(CHECKER.tracked_candidate_paths(self.root), paths)

    def test_missing_unexpected_and_nonexistent_current_paths_fail(self) -> None:
        rows = CHECKER.parse_inventory(self.csv(self.row()))
        self.write("docs/proposals/a.md")
        for candidates in ((), ("docs/proposals/a.md", "docs/proposals/b.md")):
            with self.assertRaises(CHECKER.ArchiveViolation):
                CHECKER.validate_inventory(rows, candidates)
        (self.root / "docs/proposals/a.md").unlink()
        with self.assertRaises(CHECKER.ArchiveViolation):
            CHECKER.validate_inventory(rows, ("docs/proposals/a.md",))

    def test_existing_future_target_fails(self) -> None:
        self.write("docs/proposals/a.md")
        target = self.write("archive/research/proposals/a.md")
        rows = CHECKER.parse_inventory(self.csv(self.row(disposition="archive-ready", target_path=target.relative_to(self.root).as_posix())))
        with self.assertRaises(CHECKER.ArchiveViolation):
            CHECKER.validate_inventory(rows, ("docs/proposals/a.md",))
        target.unlink()
        target.symlink_to(self.root / "missing")
        with self.assertRaises(CHECKER.ArchiveViolation):
            CHECKER.validate_inventory(rows, ("docs/proposals/a.md",))

    def test_archived_current_requires_manifest_coverage(self) -> None:
        self.write("archive/research/proposals/a.md")
        self.write("archive/MANIFEST.sha256", b"")
        rows = CHECKER.parse_inventory(self.csv(self.row(disposition="archived", current_path="archive/research/proposals/a.md")))
        with self.assertRaises(CHECKER.ArchiveViolation):
            CHECKER.validate_inventory(rows, ("archive/research/proposals/a.md",))
        CHECKER.write_manifest(self.root)
        CHECKER.validate_inventory(rows, ("archive/research/proposals/a.md",))

    def test_archived_source_must_remain_in_an_original_review_root(self) -> None:
        current = "archive/research/proposals/a.md"
        self.write(current)
        self.track(current)
        CHECKER.write_manifest(self.root)
        candidates = CHECKER.tracked_candidate_paths(self.root)
        for source in (
            "docs/not-a-review-root/wrong.md",
            "docs/proposals-elsewhere/wrong.md",
            "docs/superpowers/plans-elsewhere/wrong.md",
        ):
            with self.subTest(source=source):
                with self.assertRaises(CHECKER.ArchiveViolation):
                    rows = CHECKER.parse_inventory(self.csv(self.row(
                        source_path=source, current_path=current,
                        disposition="archived",
                    )))
                    CHECKER.validate_inventory(rows, candidates)

    def test_git_failure_and_missing_nonregular_tracked_entries_fail(self) -> None:
        with tempfile.TemporaryDirectory() as other:
            with self.assertRaises(CHECKER.ArchiveViolation):
                CHECKER.tracked_candidate_paths(Path(other))
        path = self.write("docs/proposals/a.md")
        self.track("docs/proposals/a.md")
        path.unlink()
        with self.assertRaises(CHECKER.ArchiveViolation):
            CHECKER.tracked_candidate_paths(self.root)
        path.mkdir()
        with self.assertRaises(CHECKER.ArchiveViolation):
            CHECKER.tracked_candidate_paths(self.root)
        path.rmdir()
        path.symlink_to(self.write("outside.md"))
        with self.assertRaises(CHECKER.ArchiveViolation):
            CHECKER.tracked_candidate_paths(self.root)

    @unittest.skipUnless(os.name == "posix", "byte-oriented filenames need POSIX")
    def test_non_utf8_git_path_fails_closed(self) -> None:
        (self.root / "docs/proposals").mkdir(parents=True)
        path = os.fsencode(self.root / "docs/proposals") + b"/invalid-\xff.md"
        descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        os.close(descriptor)
        subprocess.run([b"git", b"-C", os.fsencode(self.root), b"add", b"--", path], check=True)
        with self.assertRaises(CHECKER.ArchiveViolation):
            CHECKER.tracked_candidate_paths(self.root)


class DocumentationNavigationTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary_directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary_directory.cleanup)
        self.root = Path(self.temporary_directory.name)

    def write(self, relative_path: str, content: bytes) -> Path:
        destination = self.root / relative_path
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_bytes(content)
        return destination

    def test_markdown_destinations_decodes_inline_and_reference_destinations(self) -> None:
        text = (
            "[inline](archive&#47;research/)\n"
            "[encoded](archive%2Fresearch%2F)\n"
            "[reference][history]\n"
            "[history]: <docs/design\\(history\\).md> \"Design history\"\n"
        )

        self.assertEqual(
            CHECKER.markdown_destinations(text),
            (
                "archive/research/",
                "archive/research/",
                "docs/design(history).md",
            ),
        )

    def test_default_navigation_rejects_normalized_archive_links(self) -> None:
        cases = (
            ("README.md", "archive/research/"),
            ("README.md", "/archive/design-history/"),
            ("README.md", "docs/../archive/?view=all#history"),
            ("docs/README.md", "../archive/#research"),
        )
        for source, destination in cases:
            with self.subTest(source=source, destination=destination):
                self.write("README.md", b"# Aster\n")
                self.write("docs/README.md", b"# Documentation\n")
                self.write(source, f"[history]({destination})\n".encode())

                with self.assertRaisesRegex(
                    CHECKER.ArchiveViolation,
                    rf"default navigation.*{source.replace('/', r'\/')}",
                ):
                    CHECKER.validate_navigation(self.root)

    def test_reference_definition_resolving_to_archive_fails(self) -> None:
        self.write("README.md", b"# Aster\n")
        self.write(
            "docs/README.md",
            b"[history][archive-history]\n\n"
            b"[archive-history]: ../archive/design-history/\n",
        )

        with self.assertRaisesRegex(
            CHECKER.ArchiveViolation, "default navigation.*docs/README.md"
        ):
            CHECKER.validate_navigation(self.root)

    def test_valid_multiline_and_nested_archive_links_fail(self) -> None:
        cases = (
            ("README.md", b"[outer [inner]](archive/)\n"),
            ("README.md", b"[line\nbreak](archive/)\n"),
            ("README.md", b"[x](\narchive/\n)\n"),
            ("README.md", b"[unclosed\n[history](archive/)\n"),
            (
                "docs/README.md",
                b"[x][r]\n\n[r]:\n  ../archive/\n",
            ),
            (
                "docs/README.md",
                b"[x][r]\n\n[r]:\n<../archive/>\n",
            ),
        )
        for source, content in cases:
            with self.subTest(source=source, content=content):
                self.write("README.md", b"# Aster\n")
                self.write("docs/README.md", b"# Documentation\n")
                self.write(source, content)

                with self.assertRaisesRegex(
                    CHECKER.ArchiveViolation, "default navigation"
                ):
                    CHECKER.validate_navigation(self.root)

    def test_non_link_archive_text_code_and_external_urls_are_allowed(self) -> None:
        self.write(
            "README.md",
            b"The word archive is ordinary prose.\n"
            b"Use `archive/` only for maintenance.\n"
            b"[public](https://example.com/archive/research/)\n"
            b"[protocol-relative](//example.com/archive/)\n"
            b"[mail](mailto:archive@example.com)\n"
            b"```markdown\n[ignored](archive/research/)\n```\n",
        )
        self.write(
            "docs/README.md",
            b"~~~\n[ignored][history]\n[history]: ../archive/\n~~~\n",
        )

        CHECKER.validate_navigation(self.root)

    def test_navigation_ignores_documents_outside_default_indexes(self) -> None:
        self.write("README.md", b"# Aster\n")
        self.write("docs/README.md", b"# Documentation\n")
        self.write("docs/guide.md", b"[history](../archive/)\n")

        CHECKER.validate_navigation(self.root)

    def test_inline_triple_backticks_do_not_hide_a_later_link(self) -> None:
        self.write(
            "README.md",
            b"```[not a fence](archive/)```\n"
            b"[history](archive/design-history/)\n",
        )
        self.write("docs/README.md", b"# Documentation\n")

        with self.assertRaisesRegex(
            CHECKER.ArchiveViolation, "default navigation.*README.md"
        ):
            CHECKER.validate_navigation(self.root)

    def test_malformed_url_fails_closed_without_path_or_traceback(self) -> None:
        subprocess.run(["git", "init", "-q", str(self.root)], check=True)
        self.write("archive/README.md", b"policy\n")
        CHECKER.write_manifest(self.root)
        self.write(
            "docs/implementation/documentation-refactor-inventory.csv",
            (",".join(CHECKER.INVENTORY_HEADER) + "\n").encode(),
        )
        self.write("README.md", b"[bad](http://[)\n")
        self.write("docs/README.md", b"# Documentation\n")

        with self.assertRaisesRegex(
            CHECKER.ArchiveViolation,
            "^default navigation has an invalid destination: README.md$",
        ) as raised:
            CHECKER.validate_navigation(self.root)
        self.assertNotIn(str(self.root), str(raised.exception))

        stdout = io.StringIO()
        stderr = io.StringIO()
        with (
            patch.object(CHECKER, "ROOT", self.root),
            redirect_stdout(stdout),
            redirect_stderr(stderr),
        ):
            self.assertEqual(CHECKER.main([]), 1)
        self.assertEqual(stdout.getvalue(), "")
        self.assertEqual(
            stderr.getvalue(),
            "documentation archive failed: default navigation has an invalid "
            "destination: README.md\n",
        )
        self.assertNotIn(str(self.root), stderr.getvalue())
        self.assertNotIn("Traceback", stderr.getvalue())

    def test_cli_validates_navigation_after_manifest_and_inventory(self) -> None:
        subprocess.run(["git", "init", "-q", str(self.root)], check=True)
        self.write("archive/README.md", b"policy\n")
        self.write("archive/MANIFEST.sha256", b"invalid\n")
        self.write(
            "docs/implementation/documentation-refactor-inventory.csv",
            (",".join(CHECKER.INVENTORY_HEADER) + "\n").encode(),
        )
        self.write("README.md", b"[history](archive/)\n")
        self.write("docs/README.md", b"# Documentation\n")
        stderr = io.StringIO()

        with patch.object(CHECKER, "ROOT", self.root), redirect_stderr(stderr):
            self.assertEqual(CHECKER.main([]), 1)
        self.assertIn("manifest", stderr.getvalue())
        self.assertNotIn("default navigation", stderr.getvalue())

        CHECKER.write_manifest(self.root)
        stdout = io.StringIO()
        stderr = io.StringIO()
        with (
            patch.object(CHECKER, "ROOT", self.root),
            redirect_stdout(stdout),
            redirect_stderr(stderr),
        ):
            self.assertEqual(CHECKER.main([]), 1)
        self.assertEqual(stdout.getvalue(), "")
        self.assertRegex(stderr.getvalue(), "default navigation.*README.md")


if __name__ == "__main__":
    unittest.main()
