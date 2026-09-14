#!/usr/bin/env python3
# Copyright 2026 Defense Unicorns, Inc.
# SPDX-License-Identifier: Apache-2.0
"""Regressions for Event verification, project isolation, and cleanup."""
import base64
import importlib.util
import io
import json
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]


class PackageComposeTests(unittest.TestCase):
    def load_runner(self):
        path = ROOT / "tools/aster_deb_compose.py"
        self.assertTrue(path.exists(), "package Compose controller is not implemented")
        spec = importlib.util.spec_from_file_location("deb_compose", path)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        return module

    def package(self, root):
        if shutil.which("dpkg-deb") is None:
            self.skipTest("Debian package regression requires dpkg-deb")
        control = root / "input/DEBIAN"
        control.mkdir(parents=True)
        (control / "control").write_text(
            "Package: aster\nVersion: 1.2.3-1\nArchitecture: amd64\n"
            "Maintainer: Test <test@example.invalid>\nDescription: synthetic test\n"
        )
        package = root / "input with spaces.deb"
        subprocess.run(["dpkg-deb", "--build", str(control.parent), str(package)],
                       check=True, capture_output=True)
        return package

    def test_receipt_rejects_wrong_event_content_even_with_matching_id(self):
        runner = self.load_runner()
        event = {"id": "A" * 43 + "=", "logicalKey": "a2V5", "payload": "d3Jvbmc="}
        with self.assertRaises(runner.SmokeError):
            runner.check_event(json.dumps(event), event["id"], "key", "expected")
        event["payload"] = base64.b64encode(b"expected").decode()
        runner.check_event(json.dumps(event), event["id"], "key", "expected")

    def test_exported_project_name_cannot_retarget_the_test_or_cleanup(self):
        if shutil.which("docker") is None:
            self.skipTest("Compose interpolation regression requires Docker CLI")
        if subprocess.run(["docker", "compose", "version"], capture_output=True).returncode:
            self.skipTest("Compose interpolation regression requires Compose plugin")
        runner = self.load_runner()
        with tempfile.TemporaryDirectory(prefix="aster-deb-test-") as directory:
            stage = Path(directory)
            package = self.package(stage)
            runner.prepare(stage, package)
            with patch.dict("os.environ", {"COMPOSE_PROJECT_NAME": "unrelated-project"}):
                config = json.loads(runner.Compose(stage).run("config", "--format", "json"))
                manual = subprocess.run([str(stage / "compose.sh"), "config", "--format", "json"],
                                        check=True, capture_output=True, text=True)
            self.assertEqual(config["name"], stage.name)
            self.assertEqual(json.loads(manual.stdout)["name"], stage.name)

    def test_cleanup_failure_turns_success_into_failed_receipt(self):
        runner = self.load_runner()
        with tempfile.TemporaryDirectory(prefix="aster-deb-test-") as directory:
            stage = Path(directory)
            package = self.package(stage)
            original_run = runner.subprocess.run

            def docker_info_or_real(command, **kwargs):
                if command[:2] == ["docker", "info"]:
                    return subprocess.CompletedProcess(command, 0, "x86_64\n", "")
                return original_run(command, **kwargs)

            def compose_command(_self, *args, **_kwargs):
                if args[0] == "down":
                    raise runner.SmokeError("synthetic cleanup failure")
                return ""

            with patch.object(runner.tempfile, "mkdtemp", return_value=str(stage)), \
                 patch.object(runner.subprocess, "run", side_effect=docker_info_or_real), \
                 patch.object(runner.Compose, "run", compose_command), \
                 patch.object(runner, "smoke", return_value={"status": "pass"}), \
                 patch("sys.stdout", new_callable=io.StringIO), \
                 patch("sys.stderr", new_callable=io.StringIO):
                code = runner.main(["--deb", str(package)])
            receipt = json.loads((stage / "receipt.json").read_text())
            self.assertEqual(code, 2)
            self.assertEqual(receipt["status"], "fail")
            self.assertFalse(receipt["kept_running"])
            self.assertIn("cleanup", receipt["cleanup_error"])


if __name__ == "__main__":
    unittest.main()
