# Copyright 2026 Defense Unicorns, Inc.
# SPDX-License-Identifier: Apache-2.0
"""Real bounded Python children, no native Rust."""
import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import tempfile
import time
import unittest
from unittest import mock
import driver as d

LINE = '[CI-VOLUME-DIAG-22] kind=progress phase=volume outer_ms=1 loop_started_ms=1 sampled_ms=1 durable_sampled_ms=1 counters=' + str([0]*22) + ' durable=[0, 0, 0, 0] costs=[1, 2, 3, 4, 5]'

class Safety(unittest.TestCase):
    def setUp(self):
        self.root = Path(tempfile.mkdtemp(prefix='volume-regression-'))
        self.children = []
        self.real_popen = subprocess.Popen
    def track(self, *a, **kw):
        p = self.real_popen(*a, **kw)
        self.children.append(p)
        print('owned_fixture_pid', p.pid, flush=True)
        return p
    def tearDown(self):
        # Fixture owner is independent of the supervisor; verify emergency cleanup.
        for p in self.children:
            try:
                if p.poll() is None: os.killpg(p.pid, signal.SIGKILL)
            except (ProcessLookupError, PermissionError):
                # macOS can report EPERM for an already exiting group; reap first.
                pass
            subprocess.Popen.wait(p, timeout=3)
            deadline = time.monotonic() + 3
            while d.group_exists(p.pid) and time.monotonic() < deadline:
                time.sleep(.01)
            self.assertFalse(d.group_exists(p.pid), 'fixture group absent before deleting state')
        import shutil
        shutil.rmtree(self.root)
    def run_child(self, code, seconds=.15, **kw):
        with mock.patch.object(d.subprocess, 'Popen', side_effect=self.track):
            return d.bounded([sys.executable, '-B', '-c', code], self.root, self.root, self.root, 'test', seconds, **kw)
    def test_malformed_costs_timeout_reaps_and_records(self):
        result = None
        caught = None
        try: result = self.run_child('import time;print('+repr(LINE)+',flush=True);time.sleep(20)')
        except Exception as e: caught = type(e).__name__
        self.assertIsNotNone(self.children[0].poll(), 'malformed telemetry stranded child')
        self.assertTrue((self.root/'test.json').exists(), 'missing cleanup receipt')
        self.assertIsNone(caught)
        self.assertTrue(result['timed_out'])
        self.assertFalse(d.success(result))
        self.assertTrue(result['telemetry_error'])

    def test_repeated_signal_cleanup(self):
        old = signal.signal(signal.SIGTERM, d.interrupted)
        original = self.track
        calls = []
        def track(*a, **kw):
            p = original(*a, **kw)
            wait = p.wait
            def signalled_wait(*a, **kw):
                calls.append(1)
                if len(calls) <= 2: signal.raise_signal(signal.SIGTERM)
                return wait(*a, **kw)
            p.wait = signalled_wait
            return p
        try:
            # A live child ignores TERM; real repeated signals must hit cleanup.
            code = 'import signal,time;signal.signal(signal.SIGTERM,signal.SIG_IGN);time.sleep(20)'
            with mock.patch.object(self, 'track', side_effect=track), mock.patch.object(d, 'CLEANUP_SECONDS', .4, create=True):
                try: result = self.run_child(code, seconds=.15)
                except Exception: result = {}
            self.assertGreaterEqual(len(calls), 2, 'both real SIGTERMs delivered')
            self.assertIsNotNone(self.children[0].poll(), 'second signal stranded child')
            self.assertTrue((self.root/'test.json').exists())
            self.assertTrue(result.get('cancelled'))
            self.assertFalse(d.success(result))
        finally: signal.signal(signal.SIGTERM, old)
    def test_signal_after_spawn_before_registration(self):
        old = signal.signal(signal.SIGTERM, d.interrupted)
        original = self.track
        def track(*a, **kw):
            p = original(*a, **kw)
            signal.raise_signal(signal.SIGTERM)
            return p
        try:
            with mock.patch.object(self, 'track', side_effect=track):
                result = self.run_child('import time;time.sleep(20)', seconds=1)
            self.assertIsNotNone(self.children[0].poll(), 'unregistered owned child stranded')
            self.assertTrue(result['cancelled'])
            self.assertFalse(d.success(result))
        finally: signal.signal(signal.SIGTERM, old)

    def test_capture_overflow_is_bounded_failure(self):
        # Small harmless flood: old code ignores the configured cap.
        with mock.patch.object(d, 'CAPTURE_BYTES', 1024, create=True):
            started = time.monotonic()
            result = self.run_child('import os,time;os.write(1,b"x"*8192);time.sleep(20)')
            self.assertLessEqual((self.root/'test.raw').stat().st_size, 1024)
            self.assertTrue(result['capture_overflow'])
            self.assertFalse(d.success(result))
            self.assertLess(time.monotonic()-started, 3)
    def test_oversized_numeric_and_line_fail_closed(self):
        for text in ('[CI-VOLUME-DIAG-22] observation_ns='+'9'*200, 'x'*70000):
            with self.subTest(length=len(text)):
                rows = d.sanitize(text)
                self.assertTrue(any('telemetry_error' in r for r in rows))
    def test_timeout_receipt_failure_never_strands_child(self):
        with mock.patch.object(d, 'write_json', side_effect=OSError('fixture')):
            result = self.run_child('import time;time.sleep(20)')
        self.assertTrue(result['timed_out'])
        self.assertTrue(result['cleanup_absent'])
        self.assertEqual(result['receipt_error'], 'OSError')
        self.assertFalse(d.success(result))
    def test_snapshot_failure_primary_preserved(self):
        with mock.patch.object(d, 'snapshot', side_effect=ValueError('fixture')), mock.patch.object(d, 'write_json', side_effect=OSError('fixture')):
            result = self.run_child('import time;time.sleep(20)')
        self.assertTrue(result['cleanup_absent'])
        self.assertEqual(result['primary_error'], 'ValueError')
        self.assertEqual(result['receipt_error'], 'OSError')

    def test_parser_shapes_are_errors_not_exceptions(self):
        for costs in ('[]', '[1, 2, 3, 4, 5]', '[[1], [2], [3], [4], [5]]', '[null]', '{}', '[[[[1]]]]'):
            with self.subTest(costs=costs):
                rows = d.sanitize(LINE.rsplit('costs=',1)[0]+'costs='+costs)
                self.assertTrue(any('telemetry_error' in row for row in rows))
    def test_descendant_pipe_is_drained_and_group_reaped(self):
        code = ('import subprocess,sys,time,signal;'
                'p=subprocess.Popen([sys.executable,"-c","import time;print(123,flush=True);time.sleep(20)"]);'
                'signal.signal(signal.SIGTERM,lambda *_:(p.wait(timeout=2),sys.exit(0)));'
                'time.sleep(20)')
        result = self.run_child(code, seconds=.3)
        self.assertTrue(result['cleanup_absent'])
        self.assertFalse(result.get('capture_incomplete', False))
        self.assertIn(b'123', (self.root/'test.raw').read_bytes())
    def test_parser_and_hash_only_after_termination(self):
        original = d.sanitize
        def parse(text):
            self.assertTrue(all(p.poll() is not None and not d.group_exists(p.pid) for p in self.children))
            raise RuntimeError('injected parser failure')
        with mock.patch.object(d, 'sanitize', side_effect=parse), mock.patch.object(d, 'digest', side_effect=AssertionError('unbounded file hash')):
            result = self.run_child('import time;time.sleep(20)')
        self.assertTrue(result['cleanup_absent'])
        self.assertEqual(result['snapshot_error'], 'RuntimeError')
        self.assertTrue((self.root/'test.json').exists())
    def test_unconfirmed_absence_preserves_owned_state(self):
        state = self.root/'runtime';state.mkdir();(state/'owned').write_text('fixture')
        original = d.group_exists
        with mock.patch.object(d, 'group_exists', return_value=True), mock.patch.object(d, 'CLEANUP_SECONDS', .1):
            result = self.run_child('import time;time.sleep(20)', seconds=.1)
        self.assertFalse(result['cleanup_absent'])
        self.assertFalse(d.success(result))
        self.assertTrue((state/'owned').exists())
        self.assertIsNotNone(self.children[0].poll())
    def test_cargo_selection_refuses_overflow_even_after_artifact(self):
        record = {'reason':'compiler-artifact','target':{'name':'aster_lab','kind':['lib']},'profile':{'test':True},'manifest_path':'/src/crates/aster-lab/Cargo.toml','executable':'/src/bin'}
        with self.assertRaises(ValueError): d.select_executable(json.dumps(record)+'\n'+'x'*70000)
    def test_real_numeric_flood_explicit_failure(self):
        result = self.run_child('print("[CI-VOLUME-DIAG-22] observation_ns="+"9"*200)')
        self.assertTrue(result['cleanup_absent'])
        self.assertTrue(result['telemetry_error'])
        self.assertFalse(d.success(result))

if __name__ == '__main__': unittest.main()
