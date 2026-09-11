#!/usr/bin/env python3
"""Exercise the stock safe-spawn contract, not just a Python version/attribute."""
import importlib.util
import json
import os
from pathlib import Path
import signal
import subprocess
import sys


def main():
    selection = os.environ.get("MISE_PYTHON_VERSION", "")
    if not selection.startswith("path:/"):
        raise RuntimeError("missing absolute mise Python path")
    expected = (Path(selection[5:]) / "bin/python3").resolve(strict=True)
    if Path(sys.executable).resolve(strict=True) != expected:
        raise RuntimeError("interpreter does not match the mise Python path")
    if sys.platform != "linux" or sys.version_info[:3] != (3, 13, 7):
        raise RuntimeError("Linux CPython 3.13.7 is required")
    if sys.implementation.name != "cpython" or not hasattr(os, "POSIX_SPAWN_CLOSEFROM"):
        raise RuntimeError("CPython POSIX_SPAWN_CLOSEFROM is required")

    source = Path(__file__).resolve().parents[2] / "tools/check-aster-agent-process.py"
    spec = importlib.util.spec_from_file_location("ci_agent_process", source)
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)

    # A child must lose a deliberately inheritable descriptor, enter its own
    # session, and restore an empty mask despite SIGUSR1 being blocked here.
    child = """
import errno, json, os, signal, sys
closed = False
try:
    os.fstat(int(sys.argv[1]))
except OSError as error:
    if error.errno != errno.EBADF:
        raise
    closed = True
print(json.dumps({
    'executable': os.path.realpath(sys.executable),
    'version': list(sys.version_info[:3]),
    'session_leader': os.getsid(0) == os.getpid(),
    'mask_empty': not signal.pthread_sigmask(signal.SIG_BLOCK, []),
    'descriptor_closed': closed,
}))
"""
    descriptor = os.open(os.devnull, os.O_RDONLY)
    try:
        os.set_inheritable(descriptor, True)
        old_mask = signal.pthread_sigmask(signal.SIG_BLOCK, {signal.SIGUSR1})
        try:
            with module.SignalSafePopen(
                [str(expected), "-c", child, str(descriptor)], (),
                stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                stderr=subprocess.PIPE, close_fds=True,
            ) as process:
                try:
                    stdout, stderr = process.communicate(timeout=10)
                except BaseException:
                    process.kill()
                    process.wait()
                    raise
                if process.returncode != 0 or stderr:
                    raise RuntimeError("safe-spawn child failed")
                observed = json.loads(stdout)
                required = {
                    "executable": str(expected), "version": [3, 13, 7],
                    "session_leader": True, "mask_empty": True,
                    "descriptor_closed": True,
                }
                if observed != required:
                    raise RuntimeError("safe-spawn child contract mismatch")
        finally:
            signal.pthread_sigmask(signal.SIG_SETMASK, old_mask)
    finally:
        os.close(descriptor)
    print("CI Python preflight passed: " + json.dumps(observed, sort_keys=True))


if __name__ == "__main__":
    try:
        main()
    except Exception as error:
        print(f"CI Python preflight failed: {error}", file=sys.stderr)
        sys.exit(1)
