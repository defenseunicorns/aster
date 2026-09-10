#!/usr/bin/env python3
"""Repeat real loopback tests under bounded CPU contention; retain every attempt."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import platform
import signal
import subprocess
import sys
import time

ROOT = Path(__file__).resolve().parents[1]
NODE_FILTERS = [
    "live_selected_blob_converges_over_direct_iroh_and_restarts_peerless",
    "live_mutable_handles_converge_disconnected_state_and_record_then_resolve",
    "live_blob_contact_coherence_faults_send_no_result_and_close_the_actor",
    "runtime::convergence_test::",
    "runtime::blob_progress_test::",
]


def bounded_int(low, high):
    def parse(value):
        number = int(value)
        if not low <= number <= high:
            raise argparse.ArgumentTypeError(f"must be between {low} and {high}")
        return number
    return parse


def stop(process):
    # Every child has its own process group, including any descendants it starts.
    try:
        os.killpg(process.pid, signal.SIGTERM)
    except ProcessLookupError:
        pass
    try:
        process.wait(timeout=5)
    except subprocess.TimeoutExpired:
        pass
    try:
        os.killpg(process.pid, signal.SIGKILL)
    except ProcessLookupError:
        pass
    process.wait()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--rounds", type=bounded_int(1, 20), default=3)
    parser.add_argument("--cpu-workers", type=bounded_int(0, 16), default=2)
    parser.add_argument("--test-threads", type=bounded_int(1, 32), default=4)
    parser.add_argument("--round-timeout", type=bounded_int(30, 1800), default=600)
    parser.add_argument("--output", type=Path, required=True, help="new receipt directory")
    args = parser.parse_args()
    if os.name != "posix":
        parser.error("this runner requires POSIX process groups (Linux or macOS)")
    output = args.output.resolve()
    output.mkdir(parents=True, exist_ok=False)
    env = dict(os.environ, RUST_BACKTRACE="1")
    command = ["cargo", "test", "--locked", "--offline", "--all-features", "--lib",
               "-p", "aster-node", "-p", "aster-iroh", "--no-run", "--message-format=json"]
    # Build before adding load; this measures test reliability, not compilation.
    with (output / "build.stderr").open("w") as errors:
        build = subprocess.run(command, cwd=ROOT, env=env, text=True,
                               stdout=subprocess.PIPE, stderr=errors, timeout=1800)
    (output / "build.jsonl").write_text(build.stdout)
    build.check_returncode()
    binaries = {}
    for line in build.stdout.splitlines():
        item = json.loads(line)
        if item.get("reason") == "compiler-artifact" and item.get("executable"):
            binaries[item["target"]["name"]] = item["executable"]
    if set(binaries) != {"aster_node", "aster_iroh"}:
        raise RuntimeError(f"unexpected test artifacts: {binaries}")
    # Refuse a silently empty filtered suite before recording a successful run.
    for name, binary in binaries.items():
        listing = subprocess.check_output([binary, "--list"], cwd=ROOT, env=env, text=True)
        (output / f"{name}.tests").write_text(listing)
        if name == "aster_node" and any(f not in listing for f in NODE_FILTERS):
            raise RuntimeError("a required node test/filter is missing")
        if name == "aster_iroh" and "carrier_adjacent_check_failure_writes_no_application_bytes" not in listing:
            raise RuntimeError("the rejected-request integration test is missing")
    diff = subprocess.check_output(["git", "diff", "HEAD", "--"], cwd=ROOT)
    receipt = {
        "source_commit": subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=ROOT, text=True).strip(),
        "tracked_diff_sha256": hashlib.sha256(diff).hexdigest(),
        "runner_sha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
        "platform": platform.platform(), "logical_cpus": os.cpu_count(),
        "settings": {**vars(args), "output": str(output)}, "runs": [],
        "claim": "same-host loopback reliability under synthetic CPU contention; no performance or hosted-CI claim",
    }
    (output / "source.diff").write_bytes(diff)
    workers = []
    try:
        for _ in range(args.cpu_workers):
            workers.append(subprocess.Popen(
                [sys.executable, "-c", "import hashlib\nb = bytes(65536)\nwhile True: hashlib.sha256(b).digest()"],
                start_new_session=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
            ))
        for round_number in range(1, args.rounds + 1):
            children = []
            started = time.monotonic()
            try:
                for name, binary in binaries.items():
                    filters = NODE_FILTERS if name == "aster_node" else []
                    cmd = [binary, *filters, f"--test-threads={args.test_threads}", "--nocapture"]
                    log_name = f"round-{round_number}-{name}.log"
                    with (output / log_name).open("w") as log:
                        child = subprocess.Popen(cmd, cwd=ROOT, env=env, stdout=log,
                                                 stderr=subprocess.STDOUT, start_new_session=True)
                    children.append((name, child, cmd, log_name))
                while any(child.poll() is None for _, child, _, _ in children):
                    if any(worker.poll() is not None for worker in workers):
                        raise RuntimeError("a CPU contention worker exited unexpectedly")
                    if time.monotonic() - started >= args.round_timeout:
                        raise TimeoutError(f"round {round_number} exceeded its outer deadline")
                    time.sleep(0.2)
            finally:
                for name, child, cmd, log_name in children:
                    completed = child.poll() is not None
                    stop(child)
                    receipt["runs"].append({"round": round_number, "suite": name,
                        "command": cmd, "log": log_name, "completed": completed,
                        "returncode": child.returncode, "round_elapsed_seconds": time.monotonic() - started})
                (output / "receipt.json").write_text(json.dumps(receipt, indent=2) + "\n")
            passed = all(run["completed"] and run["returncode"] == 0
                         for run in receipt["runs"] if run["round"] == round_number)
            print(f"round {round_number}: {'PASS' if passed else 'FAIL'}", flush=True)
            if not passed:
                return 1
        return 0
    finally:
        for worker in workers:
            stop(worker)


if __name__ == "__main__":
    sys.exit(main())
