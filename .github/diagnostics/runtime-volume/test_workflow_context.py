# Copyright 2026 Defense Unicorns, Inc.
# SPDX-License-Identifier: Apache-2.0
"""Narrow workflow regression; no Rust or network.

Context rule: https://docs.github.com/en/actions/reference/workflows-and-actions/contexts#context-availability
This is not GitHub's complete expression validator. Stdlib-only so the existing
contract step can run it without installing a YAML parser.
"""
import platform
from pathlib import Path
import re
import subprocess
import tempfile
import unittest

WORKFLOW = Path(__file__).parents[2] / 'workflows/diagnostic-runtime-volume.yml'
JOB_ENV_CONTEXTS = {'github', 'needs', 'strategy', 'matrix', 'vars', 'secrets', 'inputs'}


class WorkflowContext(unittest.TestCase):
    def setUp(self):
        self.text = WORKFLOW.read_text()
        self.job_env, self.steps = self.text.split('    env:\n', 1)[1].split('    steps:\n', 1)
        first = self.steps.split('\n      - name:', 1)[0]
        self.prefix = '\n'.join(line[10:] for line in first.split('        run: |\n', 1)[1].splitlines()) + '\n'

    def test_job_env_uses_only_documented_contexts(self):
        violations = []
        for expression in re.findall(r'\$\{\{(.*?)\}\}', self.job_env):
            for context in re.findall(r'\b([A-Za-z_][A-Za-z_0-9]*)\s*\.', expression):
                if context not in JOB_ENV_CONTEXTS:
                    violations.append(context)
        self.assertEqual(violations, [], 'context unavailable in jobs.<job_id>.env')

    def initialization(self):
        lines = [line for line in self.prefix.splitlines() if '>> "$GITHUB_ENV"' in line]
        self.assertEqual(len(lines), 1, 'initialize once in the first verification step')
        return lines[0]

    def test_initialization_after_all_guards_before_consumers(self):
        init = self.initialization()
        guards = [line for line in self.prefix.splitlines() if line.startswith('[[')]
        self.assertEqual(len(guards), 5)
        self.assertTrue(all(self.prefix.index(g) < self.prefix.index(init) for g in guards))
        self.assertEqual(self.prefix.strip().splitlines()[-1], init)
        self.assertNotRegex(self.prefix[:self.prefix.index(init)], r'\$(?:\{)?(?:RUSTUP_HOME|CARGO_HOME)\b')
        self.assertNotIn('RUSTUP_HOME:', self.job_env)
        self.assertNotIn('CARGO_HOME:', self.job_env)
        self.assertIn('installer.py', self.steps.split('\n      - name:', 1)[1])
        self.assertIn('$CARGO_HOME/bin', self.steps.split('\n      - name:', 1)[1])

    def shell_fixture(self, script, changes=None):
        with tempfile.TemporaryDirectory(prefix='workflow-context-') as directory:
            root = Path(directory)
            env_file = root / 'environment file'
            runner = root / 'runner space'
            runner.mkdir()
            env = {'PATH': '/usr/bin:/bin', 'RUNNER_TEMP': str(runner), 'GITHUB_ENV': str(env_file),
                   'REVIEWED_SHA': 'a' * 40, 'GITHUB_SHA': 'a' * 40, 'GITHUB_RUN_ATTEMPT': '1',
                   'SOURCE_ADMISSION_RECEIPT_SHA256': 'b' * 64, 'REVIEWED_RUSTUP_SHA256': 'c' * 64}
            env.update(changes or {})
            script_file = root / 'fixture.bash'
            script_file.write_text(script)
            result = subprocess.run(['bash', '--noprofile', '--norc', '-e', '-o', 'pipefail', str(script_file)],
                                    env=env, capture_output=True, text=True, timeout=5)
            exported = env_file.read_text() if env_file.exists() else ''
            expected = f'RUSTUP_HOME={runner}/volume-rustup\nCARGO_HOME={runner}/volume-cargo\n'
            return result, exported, expected

    def test_initialization_preserves_exact_paths(self):
        result, exported, expected = self.shell_fixture('set -euo pipefail\numask 077\n' + self.initialization())
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(exported, expected)

    @unittest.skipUnless(platform.system() == 'Linux', 'full supported Ubuntu Bash prefix remains unverified on macOS')
    def test_full_prefix_success_and_guard_failures(self):
        result, exported, expected = self.shell_fixture(self.prefix)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(exported, expected)
        for changes in ({'REVIEWED_SHA': 'invalid'}, {'GITHUB_SHA': 'd' * 40},
                        {'GITHUB_RUN_ATTEMPT': '2'}, {'SOURCE_ADMISSION_RECEIPT_SHA256': 'bad'},
                        {'REVIEWED_RUSTUP_SHA256': 'bad'}):
            with self.subTest(changes=changes):
                result, exported, _ = self.shell_fixture(self.prefix, changes)
                self.assertNotEqual(result.returncode, 0)
                self.assertEqual(exported, '')

    def test_failed_predicates_do_not_export_in_explicit_control_flow_seam(self):
        # Bash 3.2 on macOS does not honor errexit for bare [[ failures as the
        # supported Ubuntu Bash does. Test each real predicate through an
        # explicit conditional seam, NOT claim the full target prefix executed.
        guards = [line for line in self.prefix.splitlines() if line.startswith('[[')]
        bad = [{'REVIEWED_SHA': 'invalid'}, {'GITHUB_SHA': 'd' * 40}, {'GITHUB_RUN_ATTEMPT': '2'},
               {'SOURCE_ADMISSION_RECEIPT_SHA256': 'bad'}, {'REVIEWED_RUSTUP_SHA256': 'bad'}]
        self.assertEqual(len(guards), len(bad))
        for guard, changes in zip(guards, bad):
            with self.subTest(guard=guard):
                script = 'set -euo pipefail\nif ' + guard + '; then\n' + self.initialization() + '\nelse\nexit 1\nfi\n'
                result, exported, _ = self.shell_fixture(script, changes)
                self.assertNotEqual(result.returncode, 0)
                self.assertEqual(exported, '')


if __name__ == '__main__':
    unittest.main()
