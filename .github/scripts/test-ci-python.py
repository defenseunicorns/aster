#!/usr/bin/env python3
"""Fail-closed regression tests for the CI interpreter preflight."""
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile
import unittest

PREFLIGHT = Path(__file__).with_name("check-ci-python.py")


class WorkflowSelectionTests(unittest.TestCase):
    def test_selection_is_initialized_before_build_and_mise(self):
        root = PREFLIGHT.resolve().parents[2]
        workflow = (root / ".github/workflows/ci.yml").read_text()
        # GitHub's context-availability table excludes runner from job env,
        # but permits it in step env. This is a focused guard, not a YAML validator.
        # https://docs.github.com/en/actions/reference/workflows-and-actions/contexts
        for job in re.split(r"(?m)^  [\w-]+:\n", workflow.split("\njobs:\n", 1)[1])[1:]:
            header = job.split("    steps:\n", 1)[0]
            for job_env in re.findall(r"(?m)^    env:\n((?:^      .*\n|^\n)+)", header):
                self.assertNotRegex(job_env, r"\$\{\{[^}]*\brunner\s*[.\[]")

        quality = workflow.split("  quality:\n", 1)[1].split("\n  macos-tests:", 1)[0]
        steps = quality.split("      - name: ")[1:]
        initialize = next(i for i, step in enumerate(steps)
                          if step.startswith("Initialize CI Python selection\n"))
        build = next(i for i, step in enumerate(steps)
                     if "run: bash .github/scripts/build-ci-python.sh" in step)
        mise = next(i for i, step in enumerate(steps) if "uses: jdx/mise-action@" in step)
        preflight = next(i for i, step in enumerate(steps)
                         if "python3 .github/scripts/check-ci-python.py" in step)
        self.assertLess(0, initialize)  # checkout precedes the repository shell wrapper
        self.assertLess(initialize, build)
        self.assertLess(build, mise)
        self.assertLess(mise, preflight)
        self.assertIn("mise exec -- mise run ci-python-preflight", steps[preflight])
        script = steps[initialize].split("        run: |\n", 1)[1]
        script = "\n".join(line[10:] for line in script.splitlines() if line.strip())
        self.assertNotIn("${{", script)  # shell resolves runner values, not job expressions
        build_script = (root / ".github/scripts/build-ci-python.sh").read_text()
        prefix_match = re.search(r'^prefix="\$RUNNER_TEMP(/[^"\n]+)"$', build_script, re.M)
        self.assertIsNotNone(prefix_match)
        assert prefix_match is not None
        suffix = prefix_match.group(1)
        with tempfile.TemporaryDirectory(prefix="ci selection ") as directory:
            output = Path(directory) / "github env"
            env = dict(os.environ)
            env.pop("MISE_PYTHON_VERSION", None)
            env.update(RUNNER_TEMP=directory, GITHUB_ENV=str(output))
            result = subprocess.run(
                ["bash", "--noprofile", "--norc", "-eo", "pipefail", "-c", script],
                env=env, capture_output=True, text=True, timeout=15,
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertTrue(output.is_file(), "initialization did not persist GITHUB_ENV")
            # GITHUB_ENV is imported by the runner for all subsequent steps,
            # including uses actions; check its exact export, with spaces intact.
            self.assertEqual(output.read_text(),
                             f"MISE_PYTHON_VERSION=path:{directory}{suffix}\n")
        self.assertNotIn("MISE_PYTHON_VERSION:", quality)


class PreflightTests(unittest.TestCase):
    def test_missing_selection_fails_closed(self):
        env = dict(os.environ)
        env.pop("MISE_PYTHON_VERSION", None)
        result = subprocess.run(
            [sys.executable, str(PREFLIGHT)], env=env,
            capture_output=True, text=True, timeout=15,
        )
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("CI Python preflight failed: missing absolute mise Python path", result.stderr)
        self.assertNotIn("CI Python preflight passed", result.stdout)

    def test_wrong_interpreter_fails_closed(self):
        with tempfile.TemporaryDirectory() as directory:
            prefix = Path(directory)
            (prefix / "bin").mkdir()
            # A real, different executable target, never executed by the probe.
            (prefix / "bin/python3").write_text("not the selected interpreter")
            result = subprocess.run(
                [sys.executable, str(PREFLIGHT)],
                env={**os.environ, "MISE_PYTHON_VERSION": f"path:{prefix}"},
                capture_output=True, text=True, timeout=15,
            )
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("interpreter does not match the mise Python path", result.stderr)
        self.assertNotIn("CI Python preflight passed", result.stdout)

    def test_actual_interpreter_capability(self):
        with tempfile.TemporaryDirectory() as directory:
            prefix = Path(directory)
            (prefix / "bin").mkdir()
            (prefix / "bin/python3").symlink_to(sys.executable)
            result = subprocess.run(
                [sys.executable, str(PREFLIGHT)],
                env={**os.environ, "MISE_PYTHON_VERSION": f"path:{prefix}"},
                capture_output=True, text=True, timeout=15,
            )
        if sys.platform == "linux" and sys.version_info[:3] == (3, 13, 7) and hasattr(os, "POSIX_SPAWN_CLOSEFROM"):
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertIn("CI Python preflight passed", result.stdout)
        else:
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("CI Python preflight failed:", result.stderr)
            self.assertNotIn("CI Python preflight passed", result.stdout)


if __name__ == "__main__":
    unittest.main()
