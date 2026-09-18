# Copyright 2026 Defense Unicorns, Inc.
# SPDX-License-Identifier: Apache-2.0
"""Static exact-input preflight and bounded resource inventory. No Rust invocation."""
import hashlib
import json
import os
from pathlib import Path
import platform
import re
import sys
import tomllib
from driver import HERE, digest, verify_commit, write_json

REGISTRY = 'registry+https://github.com/rust-lang/crates.io-index'

def inventory(lock):
    packages = lock['package']
    if not 1 <= len(packages) <= 1024:
        raise ValueError('unexpected lock inventory size')
    result = []
    for p in packages:
        name, version = p['name'], p['version']
        if not re.fullmatch(r'[A-Za-z0-9_-]{1,100}', name) or not re.fullmatch(r'[0-9A-Za-z.+_-]{1,100}', version):
            raise ValueError('unexpected package coordinate')
        source = p.get('source')
        checksum = p.get('checksum')
        if source is not None and (source != REGISTRY or not re.fullmatch('[0-9a-f]{64}', checksum or '')):
            raise ValueError('unapproved source or missing registry checksum')
        result.append({'name': name, 'version': version, 'source': source or 'approved workspace/path patch',
                       'checksum': checksum, 'public_source': f'https://crates.io/crates/{name}/{version}' if source else 'https://github.com/edgesoftops/astertech',
                       'license_admission': 'requires successful current deny, advisory and exception-scope gates'})
    return result

def main():
    source = Path(sys.argv[1]).resolve()
    evidence = Path(sys.argv[2]).resolve()
    evidence.mkdir(mode=0o700, parents=True, exist_ok=True)
    m = json.loads((HERE / 'manifest.json').read_text())
    source_sha = verify_commit(source, os.environ.get('EXPECTED_SOURCE_SHA', ''))
    for name, expected in m['source_files'].items():
        if digest(source/name) != expected:
            raise ValueError('source digest mismatch')
    if digest(source/m['source_path']) != m['baseline_sha256'] or digest(HERE/'telemetry.patch') != m['telemetry_patch_sha256']:
        raise ValueError('telemetry/source identity mismatch')
    # No source remapping or unreviewed Cargo config may change the approved route.
    if (source/'.cargo').exists():
        raise ValueError('unexpected repository Cargo configuration')
    policy = HERE.parents[2] / 'deny.toml'
    if digest(policy) != digest(source/'deny.toml'):
        raise ValueError('policy differs from dispatched source policy')
    lock = tomllib.loads((source/'Cargo.lock').read_text())
    packages = inventory(lock)
    write_json(evidence/'resources.json', {'diagnostic_only': True,
        'source_sha': source_sha, 'lock_sha256': digest(source/'Cargo.lock'),
        'policy_sha256': digest(policy), 'packages': packages,
        'package_count': len(packages), 'not_full_release_admission': True,
        'tooling_files': {str(p.relative_to(HERE)):digest(p) for p in HERE.iterdir() if p.is_file()},
        'python': platform.python_version()})
    write_json(evidence/'source-provenance.json', m)

if __name__=='__main__': main()
