"""Run selected-node Blob benchmarks sequentially and retain exact receipts."""


import json


import argparse
import csv
import datetime
import glob
import hashlib
import os
from pathlib import Path
import platform
import signal
import statistics
import subprocess
import time
import tomllib


def summarize(runs):
    groups = {}
    for run in runs:
        if run["exit_code"] != 0:
            continue
        result = next(r["data"] for r in run["records"] if r["type"] == "BENCH_RESULT")
        groups.setdefault((run["variant"], result["bytes"]), []).append(result)
    rows = []
    for (variant, size), results in sorted(groups.items()):
        complete = [r for r in results if r["status"] == "complete"]
        rows.append(dict(
            variant=variant,
            bytes=size,
            samples=len(results),
            completed=len(complete),
            visible_median_ns=(
                statistics.median(r["transfer_until_visible_ns"] for r in complete)
                if complete else None
            ),
            settled_median_ns=(
                statistics.median(r["transfer_until_ready_ns"] for r in complete)
                if complete else None
            ),
            publish_to_visible_median_ns=(
                statistics.median(r["publish_to_visible_ns"] for r in complete)
                if complete else None
            ),
        ))
    return rows


CAMPAIGN_SIZES = {
    "default": (16384, 65536, 262144, 1048576),
    "scale": (100 * 1024 * 1024,),
    "profile5-1g": (1024 * 1024 * 1024,),
}


def campaign(profile="default"):
    deadline = 900 if profile == "profile5-1g" else 300
    return [(f"{size}-1", size, deadline) for size in CAMPAIGN_SIZES[profile]]


def parse_records(text):
    records = []
    for line in text.splitlines():
        if line.startswith("BENCH_"):
            label, data = line.split(" ", 1)
            records.append({"type": label, "data": json.loads(data)})
    results = [r["data"] for r in records if r["type"] == "BENCH_RESULT"]
    if len(results) != 1:
        raise ValueError("expected exactly one result")
    result = results[0]
    if result.get("status") == "complete":
        visible = result.get("transfer_until_visible_ns")
        settled = result.get("transfer_until_ready_ns")
        publish_to_visible = result.get("publish_to_visible_ns")
        publish_to_settled = result.get("publish_to_settled_ns")
        if (result.get("verified_bytes") != result.get("bytes")
                or not result.get("source_sha256")
                or result.get("source_sha256") != result.get("receiver_sha256")
                or not all(isinstance(value, int) for value in (
                    visible, settled, publish_to_visible, publish_to_settled
                ))
                or visible > settled
                or publish_to_visible > publish_to_settled):
            raise ValueError(
                "completion requires full verified plaintext and ordered visibility/settlement timing"
            )
    elif result.get("status") not in ("transfer_timeout", "rejected_resource_limit"):
        raise ValueError("unknown result status")
    return records


def command(argv, cwd=None):
    try:
        return subprocess.check_output(argv, cwd=cwd, text=True, stderr=subprocess.STDOUT, timeout=30).strip()
    except (OSError, subprocess.SubprocessError) as error:
        return f"unavailable: {error}"


def power():
    snapshot = {"timestamp_utc": datetime.datetime.now(datetime.timezone.utc).isoformat(),
                "powerprofilesctl": command(["powerprofilesctl", "get"])}
    for pattern in ("/sys/class/power_supply/*/online", "/sys/class/power_supply/*/status",
                    "/sys/devices/system/cpu/cpu*/cpufreq/scaling_governor", "/sys/firmware/acpi/platform_profile"):
        for name in glob.glob(pattern):
            try:
                snapshot[name] = Path(name).read_text().strip()
            except OSError as error:
                snapshot[name] = str(error)
    return snapshot


def digest(path):
    with Path(path).open("rb") as source:
        return hashlib.file_digest(source, "sha256").hexdigest()


def source_identity(repo, binary):
    tracked = subprocess.check_output(["git", "ls-files", "--cached", "--others", "--exclude-standard", "-z"], cwd=repo).decode().split("\0")
    hashes = {name: digest(repo / name) for name in tracked if name and (repo / name).is_file()}
    example = repo / "crates/aster-node/examples/blob_benchmark.rs"
    return {"repo": str(repo), "revision": command(["git", "rev-parse", "HEAD"], repo),
            "status": command(["git", "status", "--porcelain=v1"], repo),
            "diff": command(["git", "diff", "HEAD"], repo), "tracked_sha256": hashes,
            "example_sha256": digest(example), "binary": str(binary), "binary_sha256": digest(binary),
            "rustc": command(["mise", "exec", "--", "rustc", "-Vv"], repo),
            "release_profile": tomllib.loads((repo / "Cargo.toml").read_text())["profile"]["release"]}


def write_json(path, value):
    with path.open("x") as output:
        json.dump(value, output, indent=2)
        output.write("\n")
        output.flush()
        os.fsync(output.fileno())


def run_case(output, state, variant, repo, binary, case):
    name, size, deadline = case
    name = variant + "-" + name
    argv = [str(binary), str(state / name), str(size), str(deadline)]
    run = {"variant": variant, "name": name, "argv": argv, "power_before": power()}
    print("START", name, run["power_before"]["timestamp_utc"], flush=True)
    started = time.monotonic_ns()
    stdout = output / (name + ".stdout.log")
    with stdout.open("x") as out, (output / (name + ".stderr.log")).open("x") as err:
        process = subprocess.Popen(argv, cwd=repo, stdout=out, stderr=err, start_new_session=True)
        try:
            run["exit_code"] = process.wait(timeout=deadline + 180)
        except subprocess.TimeoutExpired:
            os.killpg(process.pid, signal.SIGTERM)
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                os.killpg(process.pid, signal.SIGKILL)
                process.wait()
            run["exit_code"] = "external_timeout"
    run["process_elapsed_ns"] = time.monotonic_ns() - started
    run["power_after"] = power()
    try:
        run["records"] = parse_records(stdout.read_text())
    except (ValueError, KeyError) as error:
        run["records"] = []
        run["validation_error"] = str(error)
    write_json(output / (name + ".json"), run)
    print("END", name, run["exit_code"], [r for r in run["records"] if r["type"] == "BENCH_RESULT"], flush=True)
    if run["exit_code"] != 0 or "validation_error" in run:
        raise RuntimeError(f"failed run retained: {name}")
    return run


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--variant", nargs=3, action="append", required=True, metavar=("LABEL", "REPO", "BINARY"))
    parser.add_argument("--output", type=Path, required=True, help="new durable result directory")
    parser.add_argument("--state", type=Path, required=True, help="new scratch fixture directory")
    parser.add_argument("--campaign", choices=CAMPAIGN_SIZES, default="default")
    parser.add_argument("--sizes", type=int, nargs="+", help="optional subset, exact byte sizes")
    args = parser.parse_args()
    os.umask(0o077)
    labels = [v[0] for v in args.variant]
    if len(set(labels)) != len(labels) or any(not label.replace("-", "").isalnum() for label in labels):
        parser.error("variant labels must be unique alphanumeric/hyphen names")
    cases = [c for c in campaign(args.campaign) if args.sizes is None or c[1] in args.sizes]
    if not cases or (args.sizes and set(args.sizes) != {c[1] for c in cases}):
        parser.error("sizes must be from the documented campaign")
    args.output.mkdir(parents=True, exist_ok=False)
    args.state.mkdir(parents=True, exist_ok=False)
    variants = [(label, Path(repo).resolve(), Path(binary).resolve()) for label, repo, binary in args.variant]
    identities = {label: source_identity(repo, binary) for label, repo, binary in variants}
    if len({v["example_sha256"] for v in identities.values()}) != 1:
        raise ValueError("variant examples differ")
    write_json(args.output / "metadata.json", {"campaign": args.campaign,
        "variants": identities, "cases": cases,
        "planned_runs": len(cases) * len(variants), "machine": platform.uname()._asdict(),
        "cpu": command(["lscpu"]), "memory": Path("/proc/meminfo").read_text(),
        "disk": command(["df", "-B1", str(args.state)]), "power_initial": power()})
    for case in cases:
        for label, repo, binary in variants:
            run_case(args.output, args.state, label, repo, binary, case)
    # Read back durable individual records, rather than trusting an in-memory tally.
    runs = [json.loads(path.read_text()) for path in args.output.glob("*-*.json")]
    if len(runs) != len(cases) * len(variants):
        raise ValueError("retained run count differs from planned campaign")
    after = {label: source_identity(repo, binary) for label, repo, binary in variants}
    write_json(args.output / "source-after.json", after)
    if identities != after:
        raise ValueError("source or binary changed during campaign; inspect retained identities")
    rows = summarize(runs)
    write_json(args.output / "summary.json", rows)
    with (args.output / "summary.csv").open("x", newline="") as output:
        writer = csv.DictWriter(output, fieldnames=list(rows[0]))
        writer.writeheader()
        writer.writerows(rows)


if __name__ == "__main__":
    main()
