#!/usr/bin/env python3
"""Fail-closed regression tests for the CI interpreter preflight."""
import os
from pathlib import Path
import re
import shlex
import subprocess
import sys
import tempfile
import unittest

PREFLIGHT = Path(__file__).with_name("check-ci-python.py")


class WorkflowSelectionTests(unittest.TestCase):
    def test_every_required_module_blocks_path_publication_when_missing(self):
        build = PREFLIGHT.with_name("build-ci-python.sh").read_text()
        validation = build[build.index('"$prefix/bin/python3" -c '):]
        imports = shlex.split(validation.splitlines()[0])[2]
        self.assertIn('assert hasattr(os, "POSIX_SPAWN_CLOSEFROM")', imports)
        with tempfile.TemporaryDirectory() as directory:
            prefix = Path(directory)
            (prefix / "bin").mkdir()
            interpreter = prefix / "bin/python3"
            # Execute the real post-install validation, injecting only the
            # absence of one module. Never spoof successful Linux capability.
            interpreter.write_text(
                f"#!{sys.executable}\n"
                "import builtins, os, sys\n"
                "original = builtins.__import__\n"
                "def checked(name, *args, **kwargs):\n"
                "    if name == os.environ['MISSING_MODULE']:\n"
                "        raise ModuleNotFoundError('injected missing ' + name)\n"
                "    return original(name, *args, **kwargs)\n"
                "builtins.__import__ = checked\n"
                "exec(sys.argv[2])\n"
            )
            interpreter.chmod(0o700)
            output = prefix / "github-path"
            for module in ("bz2", "ctypes", "hashlib", "lzma", "sqlite3", "ssl", "zlib"):
                with self.subTest(module=module):
                    result = subprocess.run(
                        ["bash", "--noprofile", "--norc", "-eo", "pipefail", "-c", validation],
                        env={**os.environ, "prefix": directory, "GITHUB_PATH": str(output),
                             "MISSING_MODULE": module},
                        capture_output=True, text=True, timeout=15,
                    )
                    self.assertNotEqual(result.returncode, 0)
                    self.assertIn("injected missing " + module, result.stderr)
                    self.assertFalse(output.exists(), "incomplete interpreter was published")

    def test_build_prerequisites_precede_source_build_and_fail_closed(self):
        root = PREFLIGHT.resolve().parents[2]
        workflow = (root / ".github/workflows/ci.yml").read_text()
        quality = workflow.split("  quality:\n", 1)[1].split("\n  macos-tests:", 1)[0]
        steps = quality.split("      - name: ")[1:]
        candidates = [i for i, step in enumerate(steps)
                      if step.startswith("Install CI Python build prerequisites\n")]
        self.assertEqual(len(candidates), 1, "explicit Python build prerequisites are missing")
        prerequisites = candidates[0]
        build = next(i for i, step in enumerate(steps)
                     if "run: bash .github/scripts/build-ci-python.sh" in step)
        self.assertLess(0, prerequisites)
        self.assertLess(prerequisites, build)
        self.assertNotIn("continue-on-error", steps[prerequisites])
        self.assertNotIn("        if:", steps[prerequisites])
        script = steps[prerequisites].split("        run: |\n", 1)[1]
        script = "\n".join(line[10:] for line in script.splitlines() if line.strip())
        packages = {"build-essential", "pkg-config", "libbz2-dev", "libffi-dev",
                    "liblzma-dev", "libsqlite3-dev", "libssl-dev", "zlib1g-dev"}
        # Run the actual workflow shell; intercept only privileged package calls.
        # No local apt installation or network access is performed by this test.
        with tempfile.TemporaryDirectory() as directory:
            command_log = Path(directory) / "commands"
            stub = Path(directory) / "sudo"
            stub.write_text('#!/bin/bash\nprintf "%s\\n" "$*" >> "$COMMAND_LOG"\n'
                            '[[ "$*" != *"$FAIL_COMMAND"* ]]\n')
            stub.chmod(0o700)
            query = Path(directory) / "dpkg-query"
            query.write_text('#!/bin/bash\nprintf "dpkg-query %s\\n" "$*" >> "$COMMAND_LOG"\n')
            query.chmod(0o700)
            for failure in ("never-match", "update", "install"):
                with self.subTest(failure=failure):
                    command_log.write_text("")
                    result = subprocess.run(
                        ["bash", "--noprofile", "--norc", "-eo", "pipefail", "-c", script],
                        env={**os.environ, "PATH": directory + os.pathsep + os.environ["PATH"],
                             "COMMAND_LOG": str(command_log), "FAIL_COMMAND": failure},
                        capture_output=True, text=True, timeout=15,
                    )
                    commands = command_log.read_text().splitlines()
                    # Plain update can tolerate transient acquisition errors.
                    self.assertEqual(commands[0], "apt-get -o APT::Update::Error-Mode=any update")
                    if failure == "never-match":
                        self.assertEqual(result.returncode, 0, result.stderr)
                        self.assertEqual(len(commands), 3)
                        install = commands[1].split()
                        self.assertEqual(install[:4], ["apt-get", "install", "--yes", "--no-install-recommends"])
                        self.assertEqual(set(install[4:]), packages)
                        receipt = commands[2].split()
                        self.assertEqual(receipt[:3], ["dpkg-query", "--show",
                                                      r"--showformat=${Package}\t${Version}\n"])
                        self.assertEqual(set(receipt[3:]), packages)
                    else:
                        self.assertNotEqual(result.returncode, 0)
                        self.assertEqual(len(commands), 1 if failure == "update" else 2)

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
