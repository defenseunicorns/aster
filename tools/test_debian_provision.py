#!/usr/bin/env python3
# Copyright 2026 Defense Unicorns, Inc.
# SPDX-License-Identifier: Apache-2.0
"""Regression checks for failed admin output and atomic reference handoff."""
import importlib.machinery
import importlib.util
import os
from pathlib import Path
import stat
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]


class ProvisionTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        path = ROOT / "debian/aster-provision"
        if not path.exists():
            return
        loader = importlib.machinery.SourceFileLoader("provision", str(path))
        spec = importlib.util.spec_from_loader(loader.name, loader)
        cls.module = importlib.util.module_from_spec(spec)
        loader.exec_module(cls.module)

    def implementation(self):
        self.assertTrue((ROOT / "debian/aster-provision").exists(), "package handoff is missing")
        return self.module

    def test_failed_admin_output_never_becomes_a_reference(self):
        # A child can report failure after emitting a valid-looking prefix.
        m = self.implementation()
        with self.assertRaises(ValueError):
            m.parse_result("install", 1, b"INSTALL disposition=installed generation=1 reference=abcd\n")

    def test_only_complete_success_of_requested_operation_is_accepted(self):
        m = self.implementation()
        self.assertEqual(m.parse_result("install", 0,
            b"INSTALL disposition=installed generation=1 reference=abcd\n"), bytes.fromhex("abcd"))
        for output in (
            b"INSTALL disposition=installed generation=1 reference=abcd",
            b"INSTALL disposition=installed generation=0 reference=abcd\n",
            b"INSTALL disposition=installed generation=1 reference=abc\n",
            b"INSTALL disposition=installed generation=1 reference=abcd\nextra",
            b"ROTATE disposition=rotated generation=2 reference=abcd\n",
        ):
            with self.subTest(output=output), self.assertRaises(ValueError):
                m.parse_result("install", 0, output)

    def test_atomic_handoff_preserves_old_inode_and_sets_owner_only_mode(self):
        m = self.implementation()
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "mission-reference"
            path.write_bytes(b"old")
            with path.open("rb") as old:
                fd = os.open(tmp, os.O_RDONLY | os.O_DIRECTORY)
                try:
                    m.replace_file(fd, path.name, b"new", os.getuid(), os.getgid(), 0o600)
                finally:
                    os.close(fd)
                self.assertEqual(old.read(), b"old")
            self.assertEqual(path.read_bytes(), b"new")
            self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600)
            self.assertEqual(list(Path(tmp).iterdir()), [path])

    def test_duplicate_configuration_keys_are_not_silently_rewritten(self):
        m = self.implementation()
        with self.assertRaises(ValueError):
            m.unique_object([("mission_load_id", "first"), ("mission_load_id", "second")])

    def test_hardlinked_destination_is_rejected(self):
        m = self.implementation()
        with tempfile.TemporaryDirectory() as tmp:
            target = Path(tmp) / "target"
            target.write_bytes(b"keep")
            os.link(target, Path(tmp) / "mission-reference")
            fd = os.open(tmp, os.O_RDONLY | os.O_DIRECTORY)
            try:
                with self.assertRaises(ValueError):
                    m.replace_file(fd, "mission-reference", b"new", os.getuid(), os.getgid(), 0o600)
            finally:
                os.close(fd)
            self.assertEqual(target.read_bytes(), b"keep")

    def test_symlink_destination_is_rejected_without_touching_target(self):
        m = self.implementation()
        with tempfile.TemporaryDirectory() as tmp:
            target = Path(tmp) / "target"
            target.write_bytes(b"keep")
            (Path(tmp) / "mission-reference").symlink_to(target)
            fd = os.open(tmp, os.O_RDONLY | os.O_DIRECTORY)
            try:
                with self.assertRaises(ValueError):
                    m.replace_file(fd, "mission-reference", b"new", os.getuid(), os.getgid(), 0o600)
            finally:
                os.close(fd)
            self.assertEqual(target.read_bytes(), b"keep")


if __name__ == "__main__":
    unittest.main()
