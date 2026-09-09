#!/usr/bin/env python3
# Copyright 2026 Defense Unicorns, Inc.
# SPDX-License-Identifier: Apache-2.0
"""Run one bounded real-Event delivery through the routed Containerlab path."""

from __future__ import annotations

import argparse
import base64
import binascii
from collections.abc import Callable
from contextlib import contextmanager
import fcntl
import json
import os
from pathlib import Path
import platform
import selectors
import shutil
import stat
import subprocess
import sys
import tempfile
import time
from typing import Any


SCENARIO_SCHEMA = "aster-path-delivery-scenario/v1"
PLAN_SCHEMA = "aster-path-delivery-plan/v1"
RECEIPT_SCHEMA = "aster-path-delivery-receipt/v1"
MAX_SCENARIO_BYTES = 16 * 1024
MAX_OUTPUT_BYTES = 2 * 1024 * 1024
FIELDS = {"schema", "id", "seed", "operation_key", "logical_key", "payload"}
CONTAINERLAB_VERSION = "0.79.0"
LAB = "aster-path-delivery"
LAB_LOCK = Path("/run/lock") / LAB / "owner.lock"
ROOT = Path(__file__).resolve().parents[1]
TOPOLOGY = ROOT / "docker" / "path-lab" / "topology.delivery.clab.yml"
FIXED_NETEM = {
    "node": "clab-aster-path-delivery-wan",
    "interface": "eth2",
    "delay": "40ms",
    "jitter": "5ms",
    "packet_loss": 1.0,
    "rate": 100000,
}


class ScenarioError(ValueError):
    """One sanitized delivery-scenario validation failure."""


class ExecutionError(RuntimeError):
    """One sanitized delivery execution failure."""


@contextmanager
def _lab_lock(path: Path):
    """Hold exclusive ownership of the fixed lab name without following links."""

    try:
        path.parent.mkdir(mode=0o700)
    except FileExistsError:
        pass
    except OSError as error:
        raise ExecutionError("path-delivery lock directory is unavailable") from error
    try:
        directory_metadata = path.parent.lstat()
    except OSError as error:
        raise ExecutionError("path-delivery lock directory is unavailable") from error
    if (
        path.parent.is_symlink()
        or not stat.S_ISDIR(directory_metadata.st_mode)
        or directory_metadata.st_uid != os.geteuid()
        or stat.S_IMODE(directory_metadata.st_mode) != 0o700
    ):
        raise ExecutionError("path-delivery lock directory is not trusted")

    flags = os.O_CREAT | os.O_RDWR | os.O_CLOEXEC
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        descriptor = os.open(path, flags, 0o600)
    except OSError as error:
        raise ExecutionError("path-delivery ownership lock is unavailable") from error
    try:
        metadata = os.fstat(descriptor)
        if (
            not stat.S_ISREG(metadata.st_mode)
            or metadata.st_nlink != 1
            or metadata.st_uid != os.geteuid()
            or stat.S_IMODE(metadata.st_mode) != 0o600
        ):
            raise ExecutionError("path-delivery lock file is not trusted")
        try:
            fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError as error:
            raise ExecutionError("another path-delivery execution is active") from error
        try:
            path_metadata = path.lstat()
        except OSError as error:
            raise ExecutionError("path-delivery lock file identity changed") from error
        if (
            path.is_symlink()
            or path_metadata.st_dev != metadata.st_dev
            or path_metadata.st_ino != metadata.st_ino
            or path_metadata.st_uid != metadata.st_uid
            or stat.S_IMODE(path_metadata.st_mode) != 0o600
        ):
            raise ExecutionError("path-delivery lock file identity changed")
        yield
    finally:
        os.close(descriptor)


def _text(value: Any, label: str, maximum: int) -> str:
    if not isinstance(value, str):
        raise ScenarioError(f"{label} must be text")
    try:
        encoded = value.encode("utf-8")
    except UnicodeError as error:
        raise ScenarioError(f"{label} is not valid UTF-8") from error
    if not encoded or len(encoded) > maximum or any(byte < 32 or byte == 127 for byte in encoded):
        raise ScenarioError(f"{label} is outside its supported bounds")
    return value


def _strict_json(raw: bytes, label: str) -> Any:
    if len(raw) > MAX_OUTPUT_BYTES:
        raise ExecutionError(f"{label} exceeds the byte bound")

    def object_from_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in pairs:
            if key in result:
                raise ExecutionError(f"{label} contains a duplicate field")
            result[key] = value
        return result

    def reject_constant(_value: str) -> None:
        raise ExecutionError(f"{label} is malformed")

    try:
        return json.loads(
            raw.decode("utf-8"),
            object_pairs_hook=object_from_pairs,
            parse_constant=reject_constant,
        )
    except ExecutionError:
        raise
    except (UnicodeError, ValueError) as error:
        raise ExecutionError(f"{label} is malformed") from error


def compile_scenario(raw: bytes) -> dict[str, object]:
    """Validate the event input and return the single fixed delivery plan."""

    if len(raw) > MAX_SCENARIO_BYTES:
        raise ScenarioError("scenario exceeds the byte bound")

    def object_from_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        value: dict[str, Any] = {}
        for key, item in pairs:
            if key in value:
                raise ScenarioError("scenario contains a duplicate field")
            value[key] = item
        return value

    def reject_constant(_value: str) -> None:
        raise ScenarioError("scenario is not valid UTF-8 JSON")

    try:
        document = json.loads(
            raw.decode("utf-8"),
            object_pairs_hook=object_from_pairs,
            parse_constant=reject_constant,
        )
    except ScenarioError:
        raise
    except (UnicodeError, ValueError) as error:
        raise ScenarioError("scenario is not valid UTF-8 JSON") from error
    if not isinstance(document, dict) or document.get("schema") != SCENARIO_SCHEMA:
        raise ScenarioError("scenario has an unsupported schema")
    if set(document) != FIELDS:
        raise ScenarioError("scenario fields do not match the delivery contract")
    scenario_id = _text(document["id"], "scenario id", 64)
    if scenario_id != "event-delivery-netem":
        raise ScenarioError("scenario id is unsupported")
    if type(document["seed"]) is not int or document["seed"] != 104729:
        raise ScenarioError("scenario seed is unsupported")
    return {
        "schema": PLAN_SCHEMA,
        "scenario_id": scenario_id,
        "seed": document["seed"],
        "operation_key": _text(document["operation_key"], "operation key", 256),
        "logical_key": _text(document["logical_key"], "logical key", 4096),
        "payload": _text(document["payload"], "payload", 4096),
        "netem": dict(FIXED_NETEM),
    }


def _run_command(argv: list[str], timeout: float) -> bytes:
    process: subprocess.Popen[bytes] | None = None
    try:
        process = subprocess.Popen(
            argv,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        if process.stdout is None or process.stderr is None:
            raise ExecutionError("delivery command capture is unavailable")
        stdout = bytearray()
        captured = 0
        deadline = time.monotonic() + timeout
        with selectors.DefaultSelector() as selector:
            selector.register(process.stdout, selectors.EVENT_READ, True)
            selector.register(process.stderr, selectors.EVENT_READ, False)
            while selector.get_map():
                remaining_time = deadline - time.monotonic()
                if remaining_time <= 0:
                    raise ExecutionError("delivery command timed out")
                events = selector.select(remaining_time)
                if not events:
                    raise ExecutionError("delivery command timed out")
                for key, _mask in events:
                    allowance = MAX_OUTPUT_BYTES - captured
                    chunk = os.read(key.fd, min(64 * 1024, allowance + 1))
                    if not chunk:
                        selector.unregister(key.fileobj)
                        continue
                    captured += min(len(chunk), allowance)
                    if key.data:
                        stdout.extend(chunk[:allowance])
                    if len(chunk) > allowance:
                        raise ExecutionError("delivery command output exceeds the byte bound")
        returncode = process.wait(timeout=max(0, deadline - time.monotonic()))
        if returncode != 0:
            raise ExecutionError(f"delivery command failed with exit status {returncode}")
        return bytes(stdout)
    except ExecutionError:
        if process is not None and process.poll() is None:
            process.kill()
            process.wait()
        raise
    except (OSError, subprocess.SubprocessError) as error:
        if process is not None and process.poll() is None:
            process.kill()
            process.wait()
        raise ExecutionError("delivery command could not be executed") from error
    finally:
        if process is not None:
            if process.stdout is not None:
                process.stdout.close()
            if process.stderr is not None:
                process.stderr.close()


def _canonical_event_id(raw: bytes) -> str:
    try:
        value = raw.decode("ascii").strip()
        decoded = base64.b64decode(value, validate=True)
    except (UnicodeError, binascii.Error, ValueError) as error:
        raise ExecutionError("publisher returned a malformed Event ID") from error
    if len(decoded) != 32 or base64.b64encode(decoded).decode("ascii") != value:
        raise ExecutionError("publisher returned a malformed Event ID")
    return value


def _validate_status(raw: bytes) -> dict[str, object]:
    document = _strict_json(raw, "agent status")
    if not isinstance(document, dict):
        raise ExecutionError("agent status is malformed")
    for field in ("identity", "missionAuthority"):
        value = document.get(field)
        if not isinstance(value, str):
            raise ExecutionError("agent status is malformed")
        try:
            decoded = base64.b64decode(value, validate=True)
        except (binascii.Error, ValueError) as error:
            raise ExecutionError("agent status is malformed") from error
        if len(decoded) != 32 or base64.b64encode(decoded).decode("ascii") != value:
            raise ExecutionError("agent status is malformed")
    sync = document.get("sync")
    if (
        not isinstance(sync, str)
        or not sync
        or len(sync) > 64
        or any(ord(character) < 32 or ord(character) == 127 for character in sync)
    ):
        raise ExecutionError("agent status is malformed")
    return document


def _lab_is_absent(document: object) -> bool:
    return isinstance(document, dict) and LAB not in document


def _validate_netem(raw: bytes) -> dict[str, object]:
    document = _strict_json(raw, "netem read-back")
    records = document.get(FIXED_NETEM["node"]) if isinstance(document, dict) else None
    matches = (
        [record for record in records if isinstance(record, dict) and record.get("interface") == "eth2"]
        if isinstance(records, list)
        else []
    )
    expected = {**FIXED_NETEM, "corruption": 0}
    expected.pop("node")
    if len(matches) != 1 or any(matches[0].get(key) != value for key, value in expected.items()):
        raise ExecutionError("netem read-back mismatch")
    return matches[0]


def _event_exec(docker: str, node: str, action: str, plan: dict[str, object], event_id: str | None = None) -> list[str]:
    argv = [
        docker,
        "exec",
        "--user",
        "10001:10001",
        f"clab-{LAB}-{node}",
        "python3",
        "/usr/local/libexec/aster/aster_lan_mvp.py",
        action,
        "--token-file",
        "/clab/state/client.token",
        "--topic",
        "mesh.messages",
        "--scope",
        "demo/playground",
    ]
    if action == "subscribe":
        argv.extend(["--operation-key", "path-delivery-subscription"])
    elif action == "publish":
        argv.extend([
            "--operation-key", str(plan["operation_key"]),
            "--logical-key", str(plan["logical_key"]),
            "--payload", str(plan["payload"]),
            "--id-only",
        ])
    elif action == "wait" and event_id is not None:
        argv.extend([
            "--logical-key", str(plan["logical_key"]),
            "--event-id", event_id,
            "--wait-seconds", "45",
            "--poll-seconds", "0.25",
        ])
    return argv


def execute_scenario(
    raw: bytes,
    *,
    containerlab: Path,
    docker: Path,
    topology: Path,
    run: Callable[[list[str], float], bytes] = _run_command,
    lock_path: Path = LAB_LOCK,
) -> dict[str, object]:
    """Execute the one fixed topology, impairment, and exact-Event oracle."""

    with _lab_lock(lock_path):
        return _execute_scenario(
            raw,
            containerlab=containerlab,
            docker=docker,
            topology=topology,
            run=run,
        )


def _execute_scenario(
    raw: bytes,
    *,
    containerlab: Path,
    docker: Path,
    topology: Path,
    run: Callable[[list[str], float], bytes],
) -> dict[str, object]:
    """Execute while the caller holds exclusive ownership of the fixed lab."""

    plan = compile_scenario(raw)
    clab = str(containerlab)
    docker_exe = str(docker)
    inspect = [clab, "inspect", "--all", "--format", "json"]
    existing = _strict_json(run(inspect, 30), "lab inspection")
    if not isinstance(existing, dict):
        raise ExecutionError("lab inspection is malformed")
    if LAB in existing:
        raise ExecutionError("path-delivery lab already exists")

    deployed = False
    netem_attempted = False
    with tempfile.TemporaryDirectory(prefix="aster-path-delivery-") as directory:
        isolated_topology = Path(directory) / "topology.delivery.clab.yml"
        destroy: list[str] = []
        try:
            isolated_topology.write_bytes(topology.read_bytes())
            deploy = [clab, "deploy", "--topo", str(isolated_topology)]
            destroy = [clab, "destroy", "--topo", str(isolated_topology), "--cleanup"]
            deployed = True
            run(deploy, 240)
            provisioner = f"clab-{LAB}-provisioner"
            if run([docker_exe, "wait", provisioner], 90).strip() != b"0":
                raise ExecutionError("isolated provisioner failed")
            run([docker_exe, "rm", provisioner], 30)
            run([
                docker_exe, "exec", f"clab-{LAB}-wan",
                "/usr/local/libexec/aster/delivery-wan.py", "configure",
            ], 30)
            for node in ("node-a", "node-b"):
                run([
                    docker_exe, "run", "--rm", "--network",
                    f"container:clab-{LAB}-{node}", "--cap-drop", "ALL",
                    "--cap-add", "NET_ADMIN", "aster-path-delivery:local",
                    "/usr/local/libexec/aster/delivery-network-init.py", node,
                ], 30)
                run([
                    docker_exe, "exec", "--detach", "--user", "10001:10001",
                    f"clab-{LAB}-{node}",
                    "/usr/local/libexec/aster/delivery-agent.py", node,
                ], 30)
            for node in ("node-a", "node-b"):
                deadline = time.monotonic() + 60
                status_argv = [
                    docker_exe, "exec", "--user", "10001:10001",
                    f"clab-{LAB}-{node}", "python3",
                    "/usr/local/libexec/aster/aster_lan_mvp.py", "status",
                    "--token-file", "/clab/state/client.token",
                ]
                while True:
                    try:
                        _validate_status(run(status_argv, 5))
                        break
                    except ExecutionError:
                        pass
                    if time.monotonic() >= deadline:
                        raise ExecutionError("agent readiness timed out")
                    time.sleep(0.25)
            run(_event_exec(docker_exe, "node-b", "subscribe", plan), 30)

            netem_attempted = True
            run([
                clab, "tools", "netem", "set", "--node", str(FIXED_NETEM["node"]),
                "--interface", "eth2", "--delay", "40ms", "--jitter", "5ms",
                "--loss", "1.0", "--rate", "100000",
            ], 30)
            readback = run([
                clab, "tools", "netem", "show", "--node", str(FIXED_NETEM["node"]),
                "--format", "json",
            ], 30)
            observed = _validate_netem(readback)
            event_id = _canonical_event_id(run(_event_exec(docker_exe, "node-a", "publish", plan), 30))
            event = _strict_json(
                run(_event_exec(docker_exe, "node-b", "wait", plan, event_id), 60),
                "Event observation",
            )
            expected_key = base64.b64encode(str(plan["logical_key"]).encode()).decode()
            expected_payload = base64.b64encode(str(plan["payload"]).encode()).decode()
            if not isinstance(event, dict) or event.get("id") != event_id or event.get("logicalKey") != expected_key or event.get("payload") != expected_payload:
                raise ExecutionError("exact Event observation mismatch")
        finally:
            cleanup_error: ExecutionError | None = None
            if netem_attempted:
                try:
                    run([
                        clab, "tools", "netem", "reset", "--node", str(FIXED_NETEM["node"]),
                        "--interface", "eth2",
                    ], 30)
                except ExecutionError:
                    cleanup_error = ExecutionError("path-delivery cleanup failed")
            if deployed:
                try:
                    run(destroy, 180)
                except ExecutionError:
                    cleanup_error = ExecutionError("path-delivery cleanup failed")
            try:
                remaining = _strict_json(run(inspect, 30), "post-cleanup lab inspection")
                if not _lab_is_absent(remaining):
                    cleanup_error = ExecutionError("path-delivery cleanup verification failed")
            except ExecutionError:
                cleanup_error = ExecutionError("path-delivery cleanup verification failed")
            if (Path(directory) / f"clab-{LAB}").exists():
                cleanup_error = ExecutionError("credential-bearing lab directory remains")
            if cleanup_error is not None:
                raise cleanup_error

    return {
        "schema": RECEIPT_SCHEMA,
        "scenario_id": plan["scenario_id"],
        "seed": plan["seed"],
        "status": "pass",
        "event_id": event_id,
        "event_oracle": "pass",
        "configured_netem": dict(FIXED_NETEM),
        "observed_netem": observed,
        "cleanup": "pass",
        "one_host_container_limitation": True,
        "not_run": ["recovery", "resource", "physical", "measured-latency", "actual-loss"],
    }


def _regular_executable(path: Path, name: str) -> None:
    try:
        metadata = path.lstat()
    except OSError as error:
        raise ExecutionError(f"{name} executable is missing") from error
    if not path.is_absolute() or path.name != name or path.is_symlink() or not stat.S_ISREG(metadata.st_mode) or not os.access(path, os.X_OK):
        raise ExecutionError(f"{name} executable is not an exact regular executable")


def preflight(containerlab: Path, docker: Path, topology: Path) -> None:
    if platform.system() != "Linux":
        raise ExecutionError("path-delivery execution requires Linux")
    _regular_executable(containerlab, "containerlab")
    _regular_executable(docker, "docker")
    if not topology.is_absolute() or topology.name != "topology.delivery.clab.yml" or topology.is_symlink() or not topology.is_file():
        raise ExecutionError("delivery topology is not an exact regular file")
    if _run_command([str(containerlab), "version", "--short"], 10).decode("ascii").strip() != CONTAINERLAB_VERSION:
        raise ExecutionError(f"path-delivery requires Containerlab {CONTAINERLAB_VERSION}")


def _read_scenario(path: Path) -> bytes:
    with path.open("rb") as handle:
        raw = handle.read(MAX_SCENARIO_BYTES + 1)
    if len(raw) > MAX_SCENARIO_BYTES:
        raise ScenarioError("scenario exceeds the byte bound")
    return raw


def main(arguments: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("scenario", type=Path)
    parser.add_argument("--execute", action="store_true")
    parser.add_argument("--containerlab", type=Path)
    parser.add_argument("--docker", type=Path)
    parsed = parser.parse_args(arguments)
    try:
        raw = _read_scenario(parsed.scenario)
        if parsed.execute:
            containerlab = parsed.containerlab or Path(shutil.which("containerlab") or "")
            docker = parsed.docker or Path(shutil.which("docker") or "")
            preflight(containerlab, docker, TOPOLOGY)
            output = execute_scenario(raw, containerlab=containerlab, docker=docker, topology=TOPOLOGY)
        else:
            output = compile_scenario(raw)
    except (OSError, UnicodeError, ScenarioError, ExecutionError) as error:
        print(f"aster-path-delivery: {error}", file=sys.stderr)
        return 2
    print(json.dumps(output, sort_keys=True, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
