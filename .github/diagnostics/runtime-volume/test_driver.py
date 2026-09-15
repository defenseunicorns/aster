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
                self.assertEqual(json.loads((p/(name+'.json')).read_text())['exit'],r['exit'])
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
                d.verify_source(Path('/missing-source-fixture'), {'source_sha':'0'*40})
            apply.assert_not_called()
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
        self.assertEqual(m['source_sha'],'14d795390a84d425681d7d40ee4c0e1072be0fb9')
if __name__=='__main__': unittest.main()
