# Copyright 2026 Defense Unicorns, Inc.
# SPDX-License-Identifier: Apache-2.0
"""One instrumented run, never qualification.

Only stdlib; Linux runtime execution is explicitly gated. Logs stay private,
except fixed-format numeric diagnostic records and harness count summaries.
"""
import hashlib
import io
import select
import json
import os
from pathlib import Path
import platform
import re
import resource
import shutil
import signal
import subprocess
import sys
import time

HERE = Path(__file__).resolve().parent
TEST = 'mesh_experiment::libp2p_candidate::two_persistent_swarms_drive_ten_thousand_runtime_frames_each_way'

def digest(path):
    h = hashlib.sha256()
    with Path(path).open('rb') as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b''):
            h.update(chunk)
    return h.hexdigest()

def select_executable(text):
    found = []
    for line in bounded_lines(text):
        try:
            record = json.loads(line)
        except json.JSONDecodeError:
            continue
        if not isinstance(record, dict):
            continue
        if not isinstance(record.get('target', {}), dict) or not isinstance(record.get('profile', {}), dict):
            raise ValueError('invalid Cargo record shape')
        if (record.get('reason') == 'compiler-artifact'
                and record.get('target', {}).get('name') == 'aster_lab'
                and record.get('target', {}).get('kind') == ['lib']
                and record.get('profile', {}).get('test') is True
                and str(record.get('manifest_path', '')).endswith('/crates/aster-lab/Cargo.toml')
                and record.get('executable')):
            found.append(Path(record['executable']))
    if len(found) != 1:
        raise ValueError('expected exactly one Cargo aster-lab lib test executable')
    return found[0]

def write_json(path, value):
    Path(path).write_text(json.dumps(value, indent=2) + '\n')

def snapshot(pid):
    result = {'monotonic_ns': time.monotonic_ns()}
    # Allowlisted process accounting only; no cmdline, environ, paths or payload.
    for filename, keys in [('status', {'VmRSS', 'VmHWM', 'Threads'}),
                           ('io', {'rchar', 'wchar', 'read_bytes', 'write_bytes', 'syscr', 'syscw'})]:
        try:
            for line in Path(f'/proc/{pid}/{filename}').read_text().splitlines():
                key, _, value = line.partition(':')
                if key in keys and re.fullmatch(r'\s*\d+(?: kB)?\s*', value):
                    result[key] = int(value.split()[0])
        except (OSError, ValueError):
            pass
    try:
        text = Path(f'/proc/{pid}/stat').read_text().rsplit(')', 1)[1].split()
        result['utime_ticks'] = int(text[11])
        result['stime_ticks'] = int(text[12])
    except (OSError, ValueError, IndexError):
        pass
    return result

def group_exists(pgid):
    try:
        os.killpg(pgid, 0)
        return True
    except ProcessLookupError:
        return False

CAPTURE_BYTES = 16 * 1024 * 1024
LINE_BYTES = 64 * 1024
NUMERIC_DIGITS = 20
CLEANUP_SECONDS = 10

def bounded_text(path):
    with Path(path).open('rb') as stream:
        data = stream.read(CAPTURE_BYTES + 1)
    if len(data) > CAPTURE_BYTES:
        raise ValueError('capture byte overflow')
    return data.decode('utf-8', errors='replace')

def bounded_lines(text):
    # No splitlines/materialization. Check before copying or matching hostile text.
    if len(text) > CAPTURE_BYTES:
        raise ValueError('capture byte overflow')
    stream = io.StringIO(text)
    while True:
        line = stream.readline(LINE_BYTES + 1)
        if not line:
            return
        if len(line) > LINE_BYTES or len(line.encode('utf-8')) > LINE_BYTES:
            raise ValueError('line overflow')
        yield line.rstrip('\r\n')

def bounded(argv, cwd, private, evidence, name, seconds, env=None):
    """Single-thread POSIX owner. No parsing/hash/disk writes before group stop.

    Handled signals latch throughout launch/ownership/cleanup; never raise in
    Popen's return-to-registration window. The pipe is nonblocking and each
    scheduling turn reads at most 64 KiB. TERM and KILL use separate wall deadlines.
    """
    global DEFER_INTERRUPTS, CANCELLED
    previous_defer = DEFER_INTERRUPTS
    DEFER_INTERRUPTS = True
    CANCELLED = False
    started = time.monotonic()
    result = {'command': name, 'deadline_seconds': seconds,
              'exit': None, 'started': False, 'timed_out': False,
              'cleanup_absent': False, 'capture_overflow': False, 'samples': []}
    raw = Path(private) / (name + '.raw')
    proc = None
    data = bytearray()
    eof = False
    def drain():
        nonlocal eof
        if eof or proc is None or proc.stdout is None:
            return
        try:
            chunk = os.read(proc.stdout.fileno(), 65536)
        except BlockingIOError:
            return
        if not chunk:
            eof = True
            return
        remaining = CAPTURE_BYTES - len(data)
        data.extend(chunk[:remaining])
        if len(chunk) > remaining:
            result['capture_overflow'] = True
    def stop_group():
        if proc is None:
            return
        # This inner safety path has no telemetry, receipt or filesystem work.
        deadline = time.monotonic() + CLEANUP_SECONDS
        for sig, until in ((signal.SIGTERM, deadline - CLEANUP_SECONDS / 2),
                           (signal.SIGKILL, deadline)):
            try:
                os.killpg(proc.pid, sig)
            except ProcessLookupError:
                pass
            except OSError as error:
                result['cleanup_error'] = type(error).__name__
            while time.monotonic() < until:
                try:
                    proc.wait(timeout=min(.02, max(0, until-time.monotonic())))
                except subprocess.TimeoutExpired:
                    pass
                # Drain while waiting so a TERM handler can finish even with a
                # full inherited pipe; at most one bounded chunk per turn.
                try: drain()
                except OSError as error: result['capture_error'] = type(error).__name__
                try:
                    absent = not group_exists(proc.pid)
                except OSError:
                    absent = False
                if absent and proc.poll() is not None:
                    result['cleanup_absent'] = True
                    return
                time.sleep(.01)
        result['cleanup_absent'] = False
    try:
        try:
            proc = subprocess.Popen(argv, cwd=cwd, env=env, stdout=subprocess.PIPE,
                                    stderr=subprocess.STDOUT, start_new_session=True)
            result['started'] = True
            assert proc.stdout is not None
            os.set_blocking(proc.stdout.fileno(), False)
            next_sample = started
            while proc.poll() is None and not CANCELLED:
                now = time.monotonic()
                if now >= started + seconds:
                    result['timed_out'] = True
                    break
                drain()
                if result['capture_overflow']:
                    break
                if now >= next_sample:
                    result['samples'].append(snapshot(proc.pid))
                    next_sample = now + 5
                # Read readiness, not a blocking pipe read or parse operation.
                select.select([] if eof else [proc.stdout], [], [], min(.05, max(0, started+seconds-time.monotonic())))
        except Exception as error:
            result['primary_error'] = type(error).__name__
        finally:
            # Even a failing snapshot, capture, cancellation or parser cannot
            # bypass this boundary. SIGTERM/SIGINT/SIGHUP only set CANCELLED.
            if proc is not None:
                try:
                    stop_group()
                finally:
                    result['exit'] = proc.poll()
                    # Bounded residual drain AFTER kill/reap. A surviving group
                    # cannot hold the controller waiting indefinitely for EOF.
                    try:
                        for _ in range(CAPTURE_BYTES // 65536 + 2):
                            if eof: break
                            drain()
                        if not eof: result['capture_incomplete'] = True
                    finally:
                        if proc.stdout is not None: proc.stdout.close()
        result['cancelled'] = CANCELLED
        result['captured_bytes'] = len(data)
        result['raw_sha256'] = hashlib.sha256(data).hexdigest()
        try:
            raw.write_bytes(data)
        except Exception as error:
            result['capture_error'] = type(error).__name__
        if name == 'test':
            try:
                known = sanitize(data.decode('utf-8', errors='replace'))
                result['telemetry_error'] = any('telemetry_error' in r for r in known)
                write_json(Path(evidence) / 'last-known-before-cleanup.json', {
                    'kind': 'supervisor_final_snapshot',
                    'sampled_before_termination': False,
                    'resource_sample_is_last_known': True,
                    'child_final_present': any(r.get('kind') == 'final' for r in known),
                    'last_known': next((r for r in reversed(known) if 'counters' in r), None),
                    'resource_sample': result['samples'][-1] if result['samples'] else None})
            except Exception as error:
                result['snapshot_error'] = type(error).__name__
        result['elapsed_seconds'] = time.monotonic() - started
        try:
            result['cancelled'] = CANCELLED
            write_json(Path(evidence) / (name + '.json'), result)
        except Exception as error:
            result['receipt_error'] = type(error).__name__
        result['cancelled'] = CANCELLED
        return result
    finally:
        DEFER_INTERRUPTS = previous_defer

def success(result):
    return (not CANCELLED and result['exit'] == 0 and not result['timed_out'] and result['cleanup_absent']
            and not any(result.get(k) for k in ('primary_error', 'snapshot_error', 'receipt_error', 'telemetry_error', 'cancelled',
                'capture_overflow', 'capture_incomplete', 'capture_error', 'cleanup_error')))

def sanitize(text):
    try:
        return _sanitize(text)
    except (ValueError, TypeError, RecursionError):
        return [{'telemetry_error': 'invalid_or_oversized_record'}]

def _sanitize(text):
    """Fail closed: arbitrary error messages and old free-form logs are excluded."""
    rows = []
    # Rust's arrays are JSON-compatible integer arrays. Reject unknown fields.
    pattern = re.compile(r'\[CI-VOLUME-DIAG-22\] kind=(phase|progress|complete_predicate|final) phase=([a-z_]+) outer_ms=(\d+) loop_started_ms=(\d+) sampled_ms=(\d+) durable_sampled_ms=(\d+) counters=(\[[0-9, ]+\]) durable=(\[[0-9, ]+\]) costs=(\[[0-9, \[\]]+\])')
    phases = {'prepare', 'supervisors', 'adapters', 'listen', 'connect', 'contacts', 'activation', 'volume', 'resource_oracles', 'cleanup'}
    for line in bounded_lines(text):
        if len(rows) >= 160:
            rows[-1] = {'telemetry_error': 'record_overflow'}
            break
        if re.search(r'[0-9]{' + str(NUMERIC_DIGITS + 1) + r',}', line):
            raise ValueError('numeric token overflow')
        match = pattern.fullmatch(line)
        if match and match[2] in phases:
            try:
                counters, durable, costs = [json.loads(match[i]) for i in (7, 8, 9)]
                vector = lambda v, n: isinstance(v, list) and len(v) == n and all(type(x) is int and x >= 0 for x in v)
                if not (vector(counters, 22) and vector(durable, 4) and isinstance(costs, list) and len(costs) == 5 and all(vector(c, 3) for c in costs)):
                    raise ValueError('invalid dimensions')
            except (ValueError, TypeError, RecursionError):
                rows.append({'telemetry_error': 'invalid_numeric_record'})
                continue
            rows.append({'kind': match[1], 'phase': match[2], 'outer_ms': int(match[3]),
                         'loop_started_ms': int(match[4]), 'sampled_ms': int(match[5]),
                         'durable_sampled_ms': int(match[6]), 'counters': counters,
                         'durable': durable, 'costs': costs})
        elif re.fullmatch(r'\[CI-VOLUME-DIAG-22\] observation_ns=\d+', line):
            rows.append({'observation_ns': int(line.rsplit('=', 1)[1])})
        elif re.fullmatch(r'test result: (ok|FAILED)\. \d+ passed; \d+ failed; \d+ ignored; \d+ measured; \d+ filtered out; finished in [0-9.]+s', line):
            rows.append({'harness': line})
        elif line.startswith('[CI-VOLUME-DIAG-22]'):
            rows.append({'telemetry_error': 'invalid_numeric_record'})
    return rows

def verify_commit(source, expected_sha):
    if not re.fullmatch(r'[0-9a-f]{40}', expected_sha or ''):
        raise ValueError('invalid expected source identity')
    actual = subprocess.check_output(['git', 'rev-parse', 'HEAD'], cwd=source, text=True).strip()
    if actual != expected_sha:
        raise ValueError('dispatched source mismatch')
    return actual

def verify_source(source, manifest, expected_sha):
    verify_commit(source, expected_sha)
    for path, expected in manifest['source_files'].items():
        if digest(source / path) != expected:
            raise ValueError('source context digest mismatch')
    if digest(HERE / 'telemetry.patch') != manifest['telemetry_patch_sha256']:
        raise ValueError('telemetry patch digest mismatch')
    if digest(source / manifest['source_path']) != manifest['baseline_sha256']:
        raise ValueError('baseline source digest mismatch')
    subprocess.run(['git', 'apply', '--check', str(HERE / 'telemetry.patch')], cwd=source, check=True)
    subprocess.run(['git', 'apply', str(HERE / 'telemetry.patch')], cwd=source, check=True)
    if digest(source / manifest['source_path']) != manifest['patched_sha256']:
        raise ValueError('patched source digest mismatch')

DEFER_INTERRUPTS = False
CANCELLED = False

def interrupted(_signum, _frame):
    global CANCELLED
    CANCELLED = True
    if not DEFER_INTERRUPTS:
        raise InterruptedError('diagnostic supervisor interrupted')


def main():
    # No incidental local native invocation, including --version.
    if platform.system() != 'Linux' or os.environ.get('GITHUB_ACTIONS') != 'true':
        raise SystemExit('runtime execution requires reviewed GitHub Linux workflow')
    source = Path(sys.argv[1]).resolve()
    signal.signal(signal.SIGTERM, interrupted)
    signal.signal(signal.SIGINT, interrupted)
    signal.signal(signal.SIGHUP, interrupted)
    evidence = Path(sys.argv[2]).resolve()
    private = Path(sys.argv[3]).resolve()
    evidence.mkdir(mode=0o700, parents=True, exist_ok=True)
    private.mkdir(mode=0o700, parents=True, exist_ok=True)
    manifest = json.loads((HERE / 'manifest.json').read_text())
    expected_sha = os.environ.get('EXPECTED_SOURCE_SHA', '')
    receipt = {'diagnostic_only': True, 'qualification': False, 'source': manifest,
               'source_sha': expected_sha, 'workflow_sha': os.environ.get('GITHUB_SHA'),
               'os': platform.system(), 'arch': platform.machine(),
               'kernel': platform.release(), 'python': platform.python_version(),
               'cpu_count': os.cpu_count(), 'clock_ticks': os.sysconf('SC_CLK_TCK'),
               'mem_bytes': os.sysconf('SC_PAGE_SIZE') * os.sysconf('SC_PHYS_PAGES'),
               'disk_free_bytes': shutil.disk_usage(source).free,
               'state': 'preflight', 'test_executions': 0}
    result_code = 1
    try:
        verify_source(source, manifest, expected_sha)
        receipt['toolchain'] = subprocess.check_output(['rustc', '+1.97.1', '-Vv'], text=True)
        receipt['cargo'] = subprocess.check_output(['cargo', '+1.97.1', '-V'], text=True).strip()
        if not receipt['toolchain'].startswith('rustc 1.97.1 '):
            raise ValueError('toolchain mismatch')
        receipt['rustc_sha256'] = digest(subprocess.check_output(['rustup', 'which', '--toolchain', '1.97.1', 'rustc'], text=True).strip())
        receipt['wrapper_sha256'] = digest(source / 'tools/with-test-resources.sh')
        receipt['os_release'] = {key: value.strip('"') for key, _, value in
                                 (line.partition('=') for line in Path('/etc/os-release').read_text().splitlines())
                                 if key in {'ID', 'VERSION_ID'}}
        if receipt['os_release'] != {'ID': 'ubuntu', 'VERSION_ID': '24.04'} or platform.machine() != 'x86_64':
            raise ValueError('supported diagnostic environment mismatch')
        env = os.environ.copy()
        env.update({'CARGO_NET_OFFLINE': 'true', 'RUSTUP_AUTO_INSTALL': '0',
                    'CARGO_INCREMENTAL': '0', 'CARGO_TERM_COLOR': 'never',
                    'CARGO_PROFILE_DEV_DEBUG': '0', 'CARGO_PROFILE_TEST_DEBUG': '0'})
        # Fixed context, no package-only approximation; JSON is the executable authority.
        argv = ['sh', 'tools/with-test-resources.sh', 'cargo', '+1.97.1', 'test',
                '--locked', '--offline', '--workspace', '--all-features', '--no-run', '--message-format=json']
        build = bounded(argv, source, private, evidence, 'build', manifest['build_seconds'], env)
        receipt['state'] = 'build_finished'
        if not success(build):
            return 1
        binary = select_executable(bounded_text(private / 'build.raw')).resolve()
        if not binary.is_file() or not binary.is_relative_to(source):
            raise ValueError('unexpected executable location')
        receipt['binary_sha256'] = digest(binary)
        receipt['binary_identity_claim'] = 'rebuilt instrumented diagnostic, not original CI artifact'
        receipt['test'] = TEST
        runtime = private / 'runtime'
        runtime.mkdir(mode=0o700)
        env['TMPDIR'] = str(runtime)
        argv = ['sh', 'tools/with-test-resources.sh', str(binary), TEST, '--exact', '--nocapture']
        # Preserve intent before launch. There is no retry path.
        receipt['test_launch_attempts'] = 1
        receipt['state'] = 'test_starting'
        write_json(evidence / 'provenance.json', receipt)
        test = bounded(argv, source, private, evidence, 'test', manifest['test_seconds'], env)
        rows = sanitize(bounded_text(private / 'test.raw'))
        write_json(evidence / 'telemetry.json', rows)
        receipt['final_telemetry_present'] = any(r.get('kind') == 'final' for r in rows)
        receipt['state'] = 'test_finished'
        one_pass = any(re.fullmatch(r'test result: ok\. 1 passed; 0 failed; 0 ignored; 0 measured; \d+ filtered out; finished in [0-9.]+s', r.get('harness', '')) for r in rows)
        result_code = 0 if success(test) and one_pass and receipt['final_telemetry_present'] else 1
        if test['cleanup_absent']:
            shutil.rmtree(runtime)
            receipt['runtime_scratch_removed'] = True
        else:
            receipt['runtime_scratch_removed'] = False
        return result_code
    except Exception as error:
        # Exception type is safe. Free-form values can contain paths or private output.
        receipt['error_type'] = type(error).__name__
        result_code = 1
        return 1
    finally:
        if (evidence / 'test.json').exists():
            retained_test = json.loads((evidence / 'test.json').read_text())
            receipt['test_executions'] = int(retained_test['started'])
            if retained_test['cleanup_absent'] and (private / 'runtime').exists():
                shutil.rmtree(private / 'runtime')
                receipt['runtime_scratch_removed'] = True
        if (private / 'test.raw').exists():
            write_json(evidence / 'telemetry.json', sanitize(bounded_text(private / 'test.raw')))
        receipt['driver_exit'] = result_code
        write_json(evidence / 'provenance.json', receipt)
        shutil.copyfile(HERE / 'manifest.json', evidence / 'manifest.json')

if __name__ == '__main__':
    os.umask(0o077)
    raise SystemExit(main())
