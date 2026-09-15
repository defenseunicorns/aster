# Copyright 2026 Defense Unicorns, Inc.
# SPDX-License-Identifier: Apache-2.0
"""Synthetic integrity fixtures, never Rust executables."""
import hashlib
import importlib
import json
from pathlib import Path
import unittest
import urllib.request
import urllib.error

class Binding(unittest.TestCase):
    def module(self):
        self.assertTrue(Path(__file__).with_name('installer.py').exists(), 'installer-consumed input binding missing')
        return importlib.import_module('installer')
    def fixture(self):
        # Deliberately tiny authored TOML, not a simulated Rust execution receipt.
        components = {}
        text = 'manifest-version="2"\n[profiles]\nminimal=["rustc","cargo","rust-std","rust-mingw"]\n'
        for name in ('rustc','cargo','rust-std'):
            h = hashlib.sha256(name.encode()).hexdigest()
            url = 'https://static.rust-lang.org/dist/2026-07-16/'+name+'-1.97.1-x86_64-unknown-linux-gnu.tar.xz'
            components[name] = {'available':True,'xz_url':url,'xz_hash':h}
            text += '\n[pkg.'+name+'.target.x86_64-unknown-linux-gnu]\navailable=true\nxz_url='+json.dumps(url)+'\nxz_hash='+json.dumps(h)+'\n'
        data = text.encode()
        pin = {'version':'1.97.1','manifest_sha256':hashlib.sha256(data).hexdigest(),'components':components}
        return data, pin
    def test_manifest_substitution_rejected_before_download(self):
        m = self.module();data,pin = self.fixture()
        with self.assertRaises(ValueError): m.verified_plan(data+b'\n',pin)
        self.assertEqual(set(m.verified_plan(data,pin)),{'rustc','cargo','rust-std'})
    def test_component_substitution_and_unsupported_rejected(self):
        m = self.module();data,pin = self.fixture()
        pin['components']['cargo']['xz_hash'] = '0'*64
        with self.assertRaises(ValueError): m.verified_plan(data,pin)
        data,pin = self.fixture();pin['components']['clippy'] = pin['components']['cargo']
        with self.assertRaises(ValueError): m.verified_plan(data,pin)
    def test_archive_tamper_never_reaches_mirror(self):
        m = self.module();data = b'authored harmless archive fixture';h=hashlib.sha256(data).hexdigest()
        with self.assertRaises(ValueError): m.verified_bytes(data+b'!',h,100)
        with self.assertRaises(ValueError): m.verified_bytes(data,h,2)
        self.assertEqual(m.verified_bytes(data,h,100),data)
    def test_actual_local_allowlist_denies_unknown_and_no_fallback(self):
        m = self.module()
        with m.Mirror({'/dist/fixed':b'fixture'}) as mirror:
            with urllib.request.urlopen(mirror.url+'/dist/fixed',timeout=2) as response:
                self.assertEqual(response.read(),b'fixture')
            for path in ('/dist/unsupported','/dist/../fixed','/dist/fixed?other=1'):
                with self.assertRaises(urllib.error.HTTPError) as caught:
                    urllib.request.urlopen(mirror.url+path,timeout=2)
                self.assertEqual(caught.exception.code,403)
            self.assertTrue(mirror.denied)
            self.assertEqual(mirror.served,{'/dist/fixed'})
        self.assertFalse(mirror.thread.is_alive())

if __name__ == '__main__': unittest.main()
