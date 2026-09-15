# Copyright 2026 Defense Unicorns, Inc.
# SPDX-License-Identifier: Apache-2.0
"""Verified immutable distribution mirror, stdlib only.

Runtime entry is Linux/GitHub-only. Import and integrity fixtures never invoke
Rust. This is an owner-pending installer procedure, not an admission receipt.
"""
import hashlib
from http.server import BaseHTTPRequestHandler, HTTPServer
import json
import os
from pathlib import Path
import platform
import re
import shutil
import signal
import sys
import threading
import time
import tomllib
from types import MappingProxyType
import urllib.request
import urllib.parse
import driver

ORIGIN = 'https://static.rust-lang.org'
TARGET = 'x86_64-unknown-linux-gnu'
VERSION = '1.97.1'
INSTALLER_VERSION = '1.28.2'
COMPONENTS = {'rustc', 'cargo', 'rust-std'}
MANIFEST_LIMIT = 2 * 1024 * 1024
ARCHIVE_LIMIT = 256 * 1024 * 1024

def verified_bytes(data, expected, limit):
    if (not isinstance(data, bytes) or len(data) > limit
            or not re.fullmatch('[0-9a-f]{64}', expected)
            or hashlib.sha256(data).hexdigest() != expected):
        raise ValueError('unverified installer input')
    return data

def verified_plan(data, pin):
    verified_bytes(data, pin['manifest_sha256'], MANIFEST_LIMIT)
    manifest = tomllib.loads(data.decode('utf-8'))
    if pin['version'] != VERSION or set(pin['components']) != COMPONENTS:
        raise ValueError('unsupported component set')
    if manifest['manifest-version'] != '2' or set(manifest['profiles']['minimal']) != COMPONENTS | {'rust-mingw'}:
        raise ValueError('unsupported distribution semantics')
    plan = {}
    for name in sorted(COMPONENTS):
        target = manifest['pkg'][name]['target'][TARGET]
        pinned = pin['components'][name]
        for key, value in pinned.items():
            if target.get(key) != value:
                raise ValueError('component manifest disagreement')
        url = target['xz_url']
        if (target['available'] is not True or 'zst_url' in target
                or not re.fullmatch(re.escape(ORIGIN) + r'/dist/[0-9]{4}-[0-9]{2}-[0-9]{2}/' + name + '-' + re.escape(VERSION) + '-' + TARGET + r'\.tar\.xz', url)
                or not re.fullmatch('[0-9a-f]{64}', target['xz_hash'])):
            raise ValueError('unsupported component source or compression')
        plan[name] = {'url': url, 'sha256': target['xz_hash']}
    return plan

class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise ValueError('installer download redirect refused')

def download(url, expected, limit):
    if not url.startswith(ORIGIN + '/dist/'):
        raise ValueError('unapproved download origin')
    # No credentials, proxies, retries, redirects, or alternate distribution.
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect())
    deadline = time.monotonic() + 180
    data = bytearray()
    with opener.open(url, timeout=10) as stream:
        while True:
            if time.monotonic() >= deadline:
                raise TimeoutError('download deadline')
            chunk = stream.read(min(65536, limit + 1 - len(data)))
            if not chunk: break
            data.extend(chunk)
            if len(data) > limit: raise ValueError('download overflow')
    return verified_bytes(bytes(data), expected, limit)

class Mirror:
    """Fixed immutable byte allowlist. No filesystem lookup or remote forwarding."""
    def __init__(self, files):
        if any(not isinstance(v, bytes) for v in files.values()):
            raise ValueError('mirror requires immutable bytes')
        self.files = MappingProxyType(dict(files))
        self.denied = False
        self.served = set()
        self.requests = 0
        owner = self
        class Handler(BaseHTTPRequestHandler):
            def setup(self):
                self.request.settimeout(2)
                super().setup()
            def do_GET(self):
                owner.requests += 1
                body = owner.files.get(self.path)
                if body is None or owner.requests > 32 or self.headers.get('Range'):
                    owner.denied = True
                    self.send_error(403)
                    return
                self.send_response(200)
                self.send_header('Content-Length', str(len(body)))
                self.end_headers()
                try:
                    self.wfile.write(body)
                    owner.served.add(self.path)
                except OSError:
                    owner.denied = True
            def log_message(self, format, *args): pass
        self.server = HTTPServer(('127.0.0.1', 0), Handler)
        self.url = 'http://127.0.0.1:' + str(self.server.server_port)
        self.thread = threading.Thread(target=self.server.serve_forever, kwargs={'poll_interval':.05}, daemon=True)
    def __enter__(self):
        self.thread.start()
        return self
    def __exit__(self, *args):
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=3)
        if self.thread.is_alive(): raise RuntimeError('mirror stop unconfirmed')

def main():
    if platform.system() != 'Linux' or os.environ.get('GITHUB_ACTIONS') != 'true' or platform.machine() != 'x86_64':
        raise SystemExit('installer requires reviewed GitHub Linux workflow')
    private, evidence = map(lambda x: Path(x).resolve(), sys.argv[1:3])
    expected_installer = os.environ.get('REVIEWED_RUSTUP_SHA256', '')
    if not re.fullmatch('[0-9a-f]{64}', expected_installer):
        raise ValueError('accountable exact installer hash required')
    for sig in (signal.SIGTERM, signal.SIGINT, signal.SIGHUP):
        signal.signal(sig, driver.interrupted)
    pin = json.loads(Path(__file__).with_name('rust-distribution.json').read_text())
    manifest_path = '/dist/channel-rust-' + VERSION + '.toml'
    manifest = download(ORIGIN + manifest_path, pin['manifest_sha256'], MANIFEST_LIMIT)
    plan = verified_plan(manifest, pin)
    files = {manifest_path: manifest,
             manifest_path + '.sha256': (pin['manifest_sha256'] + '  channel-rust-' + VERSION + '.toml\n').encode('ascii')}
    for component in plan.values():
        files[urllib.parse.urlsplit(component['url']).path] = download(component['url'], component['sha256'], ARCHIVE_LIMIT)
    # Copy and hash the existing runner installer BEFORE any invocation. The owner
    # must approve the exact 1.28.2 executable hash; mismatch has no install/update path.
    existing = shutil.which('rustup')
    if existing is None: raise ValueError('existing approved rustup absent')
    with open(existing, 'rb') as stream:
        installer = verified_bytes(stream.read(64*1024*1024+1), expected_installer, 64*1024*1024)
    proxy_dir = private / 'verified-bin'
    proxy_dir.mkdir(mode=0o700)
    executable = proxy_dir / 'rustup'
    with executable.open('xb') as stream: stream.write(installer)
    executable.chmod(0o500)
    for proxy in ('cargo', 'rustc'):
        (proxy_dir/proxy).symlink_to('rustup')
    env = os.environ.copy()
    for key in list(env):
        if key.startswith('RUSTUP_') or key.lower().endswith('_proxy'):
            env.pop(key)
    # Fresh homes forbid cached manifests, component archives or toolchain overrides.
    for key in ('RUSTUP_HOME', 'CARGO_HOME'):
        home = Path(os.environ[key]).resolve()
        if home.exists(): raise ValueError('installer homes must not pre-exist')
        home.mkdir(mode=0o700)
        env[key] = str(home)
    env['RUSTUP_AUTO_INSTALL'] = '0'
    receipt = {'diagnostic_only':True, 'qualification':False,
               'manifest_sha256':pin['manifest_sha256'], 'archives':plan,
               'installer_sha256':expected_installer, 'installer_version':INSTALLER_VERSION,
               'approval_verified':False, 'state':'verified_inputs_before_install'}
    driver.write_json(evidence/'installer-binding.json', receipt)
    try:
        with Mirror(files) as mirror:
            env.update({'RUSTUP_DIST_SERVER':mirror.url, 'RUSTUP_UPDATE_ROOT':mirror.url+'/self-update-denied',
                        'NO_PROXY':'127.0.0.1', 'RUSTUP_MAX_RETRIES':'0'})
            version = driver.bounded([str(executable), '--version'], private, private, evidence, 'installer-version', 15, env)
            if not driver.success(version) or not driver.bounded_text(private/'installer-version.raw').startswith('rustup '+INSTALLER_VERSION+' '):
                raise ValueError('unsupported installer identity')
            # Official rustup distribution semantics, not handwritten extraction.
            result = driver.bounded([str(executable), 'toolchain', 'install', VERSION+'-'+TARGET,
                                     '--profile', 'minimal', '--no-self-update'], private, private, evidence, 'installer', 180, env)
            receipt.update({'result':result, 'served_paths':sorted(mirror.served), 'denied_request':mirror.denied})
            if not driver.success(result) or mirror.denied or mirror.served != set(files):
                raise ValueError('installer input consumption unconfirmed')
        receipt['state'] = 'installed_from_verified_allowlist'
        # Later +version commands use aliases of the exact verified installer.
        with open(os.environ['GITHUB_PATH'], 'a') as stream:
            stream.write(str(proxy_dir)+'\n')
    except Exception as error:
        receipt.update({'state':'failed', 'error_type':type(error).__name__})
        raise
    finally:
        driver.write_json(evidence/'installer-binding.json', receipt)

if __name__ == '__main__':
    os.umask(0o077)
    main()
