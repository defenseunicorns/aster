# Copyright 2026 Defense Unicorns, Inc.
# SPDX-License-Identifier: Apache-2.0
"""Local stdlib contract tests; never invoke Rust."""
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest

class DriverContract(unittest.TestCase):
    def driver(self):
        path=Path(__file__).with_name('driver.py')
        self.assertTrue(path.exists(), 'bounded diagnostic driver missing')
        spec=importlib.util.spec_from_file_location('volume_driver',path)
        assert spec is not None and spec.loader is not None
        mod=importlib.util.module_from_spec(spec); spec.loader.exec_module(mod)
        return mod
    def test_cargo_json_selects_exact_lib_test(self):
        d=self.driver()
        record={'reason':'compiler-artifact','target':{'name':'aster_lab','kind':['lib']},'profile':{'test':True},'manifest_path':'/source/crates/aster-lab/Cargo.toml','executable':'/source/target/debug/deps/actual-123'}
        self.assertEqual(d.select_executable(json.dumps(record)),Path(record['executable']))
        with self.assertRaises(ValueError): d.select_executable(json.dumps(record)+'\n'+json.dumps(record))
        record['profile']['test']=False
        with self.assertRaises(ValueError): d.select_executable(json.dumps(record))
    def test_real_process_exit_failure_and_timeout(self):
        import sys
        d=self.driver()
        with tempfile.TemporaryDirectory() as root:
            p=Path(root)
            for name,code,budget,expected in [('ok','print(123)',2,0),('failure','raise SystemExit(17)',2,17),('timeout','import time; time.sleep(10)',0.1,None)]:
                r=d.bounded([sys.executable,'-c',code],p,p,p,name,budget)
                self.assertTrue(r['cleanup_absent'])
                self.assertEqual(r['timed_out'],name=='timeout')
                if expected is not None: self.assertEqual(r['exit'],expected)
                self.assertEqual(d.success(r),name=='ok')
                receipt=json.loads((p/(name+'.json')).read_text())
                self.assertEqual(receipt['exit'],r['exit'])
                self.assertNotIn('argv',receipt)
                self.assertNotIn(str(p),json.dumps(receipt))
    def test_sanitizer_drops_arbitrary_content_and_limits_records(self):
        d=self.driver()
        self.assertEqual(d.sanitize('private payload\npassword=example\n\u001b[0m[CI-VOLUME-DIAG-22] observation_ns=5'),[])
        self.assertEqual(len(d.sanitize('[CI-VOLUME-DIAG-22] observation_ns=5\n'*200)),160)
        line='[CI-VOLUME-DIAG-22] kind=final phase=volume outer_ms=300001 loop_started_ms=5 sampled_ms=299999 durable_sampled_ms=290000 counters='+str([0]*22)+' durable=[0, 1, 2, 3] costs='+str([[1,2,3]]*5)
        self.assertEqual(d.sanitize(line)[0]['kind'],'final')
        self.assertTrue(d.sanitize(line.replace('phase=volume','phase=private'))[0]['telemetry_error'])
    def test_verify_rejects_missing_source_commit_before_apply(self):
        d=self.driver()
        import subprocess
        from unittest import mock
        # Mock the missing-object seam; no repository initialization or Git writes.
        with mock.patch.object(d.subprocess, 'check_output', side_effect=subprocess.CalledProcessError(128, ['git'])), mock.patch.object(d.subprocess, 'run') as apply:
            with self.assertRaises(subprocess.CalledProcessError):
                d.verify_source(Path('/missing-source-fixture'), {}, '0'*40)
            apply.assert_not_called()

    def test_source_commit_is_bound_to_explicit_workflow_sha(self):
        import subprocess
        d=self.driver()
        root=Path(__file__).resolve().parents[3]
        head=subprocess.check_output(['git','rev-parse','HEAD'],cwd=root,text=True).strip()
        self.assertTrue(hasattr(d,'verify_commit'), 'driver must bind source to the dispatched workflow SHA')
        self.assertEqual(d.verify_commit(root,head),head)
        with self.assertRaises(ValueError):
            d.verify_commit(root,'0'*40)
    def test_inventory_refuses_unadmitted_source_and_checksum(self):
        import preflight
        good={'package':[{'name':'example','version':'1.0.0','source':preflight.REGISTRY,'checksum':'a'*64}]}
        self.assertEqual(preflight.inventory(good)[0]['checksum'],'a'*64)
        for update in ({'source':'git+https://example.invalid/example'}, {'checksum':'bad'}):
            bad={'package':[dict(good['package'][0],**update)]}
            with self.assertRaises(ValueError): preflight.inventory(bad)
    def test_telemetry_manifest_and_add_only_oracle(self):
        import hashlib,re
        root=Path(__file__).parent
        m=json.loads((root/'manifest.json').read_text())
        patch=(root/'telemetry.patch').read_bytes()
        self.assertEqual(hashlib.sha256(patch).hexdigest(),m['telemetry_patch_sha256'])
        # A diagnostic patch may add observations, never delete or replace oracle lines.
        removed=[line for line in patch.decode().splitlines() if line.startswith('-') and not line.startswith('--- ')]
        self.assertEqual(removed,[])
        self.assertEqual(m['test_seconds'],400)
        self.assertNotIn('source_sha',m)
        self.assertEqual(m['source_binding'],'workflow_sha')

    def test_manifest_matches_current_source_context(self):
        import hashlib
        root=Path(__file__).resolve().parents[3]
        m=json.loads((Path(__file__).with_name('manifest.json')).read_text())
        for name,expected in m['source_files'].items():
            with self.subTest(name=name):
                self.assertEqual(hashlib.sha256((root/name).read_bytes()).hexdigest(),expected)
        source=root/m['source_path']
        self.assertEqual(hashlib.sha256(source.read_bytes()).hexdigest(),m['baseline_sha256'])

    def test_published_provenance_excludes_absolute_binary_path(self):
        source=Path(__file__).with_name('driver.py').read_text()
        self.assertNotIn("receipt['binary'] =",source)
        self.assertIn("receipt['test'] = TEST",source)
if __name__=='__main__': unittest.main()
