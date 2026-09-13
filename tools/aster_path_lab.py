#!/usr/bin/env python3
# Copyright 2026 Defense Unicorns, Inc.
# SPDX-License-Identifier: Apache-2.0
"""Validate bounded path-lab scenarios and compile exact Containerlab operations."""

from __future__ import annotations

import argparse
from collections.abc import Callable
import json
import os
from pathlib import Path
import platform
import selectors
import shutil
import stat
import subprocess
import sys
import time
from typing import Any


SCENARIO_SCHEMA = "aster-path-lab-scenario/v1"
PLAN_SCHEMA = "aster-path-lab-plan/v1"
LAB_PREFIX = "clab-aster-path-lab-"
CONTAINERLAB_VERSION = "0.79.0"
ROOT = Path(__file__).resolve().parents[1]
TOPOLOGY = ROOT / "docker" / "path-lab" / "topology.clab.yml"
MAX_SCENARIO_BYTES = 64 * 1024
MAX_COMMAND_OUTPUT_BYTES = 1024 * 1024
MAX_TIMELINE_EVENTS = 256
MAX_TIMELINE_MS = 31 * 24 * 60 * 60 * 1000
ROOT_FIELDS = {"schema", "id", "seed", "timeline"}
NETEM_FIELDS = {
    "at_ms",
    "action",
    "node",
    "interface",
    "delay_ms",
    "jitter_ms",
    "loss_percent",
    "rate_kbit",
}
RESET_FIELDS = {"at_ms", "action", "node", "interface"}
NODE_INTERFACES = {
    "node-a": {"eth1"},
    "wan": {"eth1", "eth2"},
    "node-b": {"eth1"},
}


class ScenarioError(ValueError):
    """One sanitized scenario validation failure."""


class ExecutionError(RuntimeError):
    """One sanitized path-lab execution or observation failure."""


def _strict_json(raw: bytes, error_type: type[Exception], label: str) -> Any:
    def object_from_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        value: dict[str, Any] = {}
        for key, item in pairs:
            if key in value:
                raise error_type(f"{label} contains a duplicate field")
            value[key] = item
        return value

    def reject_constant(_value: str) -> None:
        raise error_type(f"{label} contains a non-finite number")

    try:
        return json.loads(
            raw,
            object_pairs_hook=object_from_pairs,
            parse_constant=reject_constant,
        )
    except (json.JSONDecodeError, UnicodeError) as error:
        raise error_type(f"{label} is not valid UTF-8 JSON") from error


def validate_containerlab_version(raw: bytes) -> None:
    """Require the exact reviewed Containerlab release."""

    try:
        version = raw.decode("ascii").strip()
    except UnicodeError as error:
        raise ExecutionError("Containerlab returned an invalid version") from error
    if version != CONTAINERLAB_VERSION:
        raise ExecutionError(f"path-lab requires Containerlab {CONTAINERLAB_VERSION}")


def _exact_fields(value: dict[str, Any], expected: set[str], label: str) -> None:
    unknown = set(value) - expected
    missing = expected - set(value)
    if unknown:
        raise ScenarioError(f"{label} has an unknown field")
    if missing:
        raise ScenarioError(f"{label} is missing a required field")


def _bounded_int(value: Any, label: str, minimum: int, maximum: int) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise ScenarioError(f"{label} must be an integer")
    if value < minimum or value > maximum:
        raise ScenarioError(f"{label} is outside its supported bounds")
    return value


def _bounded_number(
    value: Any, label: str, minimum: float, maximum: float
) -> int | float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise ScenarioError(f"{label} must be a number")
    if value < minimum or value > maximum:
        raise ScenarioError(f"{label} is outside its supported bounds")
    return value


def _target(event: dict[str, Any]) -> tuple[str, str]:
    node = event.get("node")
    interface = event.get("interface")
    if not isinstance(node, str) or node not in NODE_INTERFACES:
        raise ScenarioError("node is not present in the path-lab topology")
    if not isinstance(interface, str) or interface not in NODE_INTERFACES[node]:
        raise ScenarioError("interface is not present on the selected node")
    return node, interface


def _argument(argv: list[str], name: str) -> str:
    try:
        index = argv.index(name)
        value = argv[index + 1]
    except (ValueError, IndexError) as error:
        raise ExecutionError("compiled operation is malformed") from error
    return value


def validate_netem_readback(operation: dict[str, object], raw: bytes) -> None:
    """Require Containerlab JSON read-back to match one compiled netem set."""

    if len(raw) > MAX_SCENARIO_BYTES:
        raise ExecutionError("netem read-back exceeds the byte bound")
    argv = operation.get("argv")
    if not isinstance(argv, list) or not all(isinstance(value, str) for value in argv):
        raise ExecutionError("compiled operation is malformed")
    if argv[0:4] != ["containerlab", "tools", "netem", "set"]:
        raise ExecutionError("compiled operation is not a netem set")
    node = _argument(argv, "--node")
    interface = _argument(argv, "--interface")
    expected = {
        "delay": _argument(argv, "--delay"),
        "jitter": _argument(argv, "--jitter"),
        "packet_loss": float(_argument(argv, "--loss")),
        "rate": int(_argument(argv, "--rate")),
        "corruption": 0,
    }
    document = _strict_json(raw, ExecutionError, "netem read-back")
    records = document.get(node) if isinstance(document, dict) else None
    if not isinstance(records, list):
        raise ExecutionError("netem read-back omitted the selected node")
    matches = [
        value
        for value in records
        if isinstance(value, dict) and value.get("interface") == interface
    ]
    if len(matches) != 1:
        raise ExecutionError("netem read-back omitted the selected interface")
    observed = matches[0]
    if any(observed.get(key) != value for key, value in expected.items()):
        raise ExecutionError("netem read-back mismatch")


def _run_command(
    runner: Callable[..., subprocess.Popen[bytes]],
    argv: list[str],
    *,
    timeout: float,
) -> bytes:
    process: subprocess.Popen[bytes] | None = None
    try:
        process = runner(
            argv,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        if process.stdout is None or process.stderr is None:
            raise ExecutionError("path-lab command capture is unavailable")
        stdout = bytearray()
        captured_bytes = 0
        deadline = time.monotonic() + timeout
        with selectors.DefaultSelector() as selector:
            selector.register(process.stdout, selectors.EVENT_READ, True)
            selector.register(process.stderr, selectors.EVENT_READ, False)
            while selector.get_map():
                remaining_time = deadline - time.monotonic()
                if remaining_time <= 0:
                    raise ExecutionError("path-lab command timed out")
                events = selector.select(remaining_time)
                if not events:
                    raise ExecutionError("path-lab command timed out")
                for key, _mask in events:
                    remaining_bytes = MAX_COMMAND_OUTPUT_BYTES - captured_bytes
                    chunk = os.read(key.fd, min(64 * 1024, remaining_bytes + 1))
                    if not chunk:
                        selector.unregister(key.fileobj)
                        continue
                    captured_bytes += min(len(chunk), remaining_bytes)
                    if key.data:
                        stdout.extend(chunk[:remaining_bytes])
                    if len(chunk) > remaining_bytes:
                        raise ExecutionError(
                            "path-lab command output exceeds the byte bound"
                        )
        returncode = process.wait(timeout=max(0, deadline - time.monotonic()))
        if returncode != 0:
            raise ExecutionError(
                f"path-lab command failed with exit status {returncode}"
            )
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
        raise ExecutionError("path-lab command could not be executed") from error
    finally:
        if process is not None:
            if process.stdout is not None:
                process.stdout.close()
            if process.stderr is not None:
                process.stderr.close()


def preflight_execution(
    containerlab: Path,
    topology: Path,
    *,
    runner: Callable[..., subprocess.Popen[bytes]] = subprocess.Popen,
    system: Callable[[], str] = platform.system,
) -> None:
    """Fail closed unless the exact Linux execution inputs are present."""

    if system() != "Linux":
        raise ExecutionError("path-lab execution requires Linux")
    if not containerlab.is_absolute() or containerlab.name != "containerlab":
        raise ExecutionError("Containerlab executable must be an absolute path")
    try:
        executable_metadata = containerlab.lstat()
        topology_metadata = topology.lstat()
    except OSError as error:
        raise ExecutionError("path-lab execution input is missing") from error
    if (
        not stat.S_ISREG(executable_metadata.st_mode)
        or containerlab.is_symlink()
        or not os.access(containerlab, os.X_OK)
    ):
        raise ExecutionError("Containerlab executable is not a regular executable file")
    if (
        not topology.is_absolute()
        or topology.name != "topology.clab.yml"
        or not stat.S_ISREG(topology_metadata.st_mode)
        or topology.is_symlink()
    ):
        raise ExecutionError("path-lab topology is not an exact regular file")
    version = _run_command(
        runner,
        [str(containerlab), "version", "--short"],
        timeout=10,
    )
    validate_containerlab_version(version)


def execute_scenario(
    raw: bytes,
    *,
    containerlab: Path,
    topology: Path,
    runner: Callable[..., subprocess.Popen[bytes]] = subprocess.Popen,
    sleep: Callable[[float], None] = time.sleep,
    monotonic: Callable[[], float] = time.monotonic,
) -> dict[str, object]:
    """Deploy, execute, observe, and clean up one validated scenario."""

    if not containerlab.is_absolute() or containerlab.name != "containerlab":
        raise ExecutionError("Containerlab executable must be an absolute path")
    if not topology.is_absolute() or topology.name != "topology.clab.yml":
        raise ExecutionError("path-lab topology must be an exact absolute path")
    plan = compile_manifest(raw)
    executable = str(containerlab)
    inspect = [executable, "inspect", "--all", "--format", "json"]
    deploy = [executable, "deploy", "--topo", str(topology)]
    destroy = [executable, "destroy", "--topo", str(topology), "--cleanup"]
    existing = _strict_json(
        _run_command(runner, inspect, timeout=30), ExecutionError, "lab inspection"
    )
    if not isinstance(existing, dict):
        raise ExecutionError("lab inspection is not a grouped JSON object")
    if existing.get("aster-path-lab"):
        raise ExecutionError("path-lab already exists")
    observations: list[dict[str, object]] = []
    deploy_attempted = False
    try:
        deploy_attempted = True
        _run_command(runner, deploy, timeout=180)
        started = monotonic()
        operations = plan.get("operations")
        if not isinstance(operations, list):
            raise ExecutionError("compiled plan omitted operations")
        for operation in operations:
            if not isinstance(operation, dict):
                raise ExecutionError("compiled operation is malformed")
            at_ms = operation.get("at_ms")
            argv = operation.get("argv")
            if not isinstance(at_ms, int) or not isinstance(argv, list):
                raise ExecutionError("compiled operation is malformed")
            remaining = started + at_ms / 1000 - monotonic()
            if remaining > 0:
                sleep(remaining)
            command = [executable, *argv[1:]]
            _run_command(runner, command, timeout=30)
            if argv[0:4] == ["containerlab", "tools", "netem", "set"]:
                node = _argument(argv, "--node")
                show = [
                    executable,
                    "tools",
                    "netem",
                    "show",
                    "--node",
                    node,
                    "--format",
                    "json",
                ]
                observed = _run_command(runner, show, timeout=30)
                validate_netem_readback(operation, observed)
                observations.append({"at_ms": at_ms, "netem": json.loads(observed)})
    finally:
        if deploy_attempted:
            try:
                _run_command(runner, destroy, timeout=120)
            except ExecutionError as error:
                raise ExecutionError("path-lab cleanup failed") from error
    return {
        "schema": "aster-path-lab-smoke-receipt/v1",
        "scenario_id": plan["scenario_id"],
        "seed": plan["seed"],
        "status": "pass",
        "cleanup": "pass",
        "observations": observations,
    }


def compile_manifest(raw: bytes) -> dict[str, object]:
    """Compile one scenario document into a non-shell command plan."""

    if len(raw) > MAX_SCENARIO_BYTES:
        raise ScenarioError("scenario exceeds the byte bound")
    document = _strict_json(raw, ScenarioError, "scenario")
    if not isinstance(document, dict) or document.get("schema") != SCENARIO_SCHEMA:
        raise ScenarioError("scenario has an unsupported schema")
    _exact_fields(document, ROOT_FIELDS, "scenario")
    scenario_id = document.get("id")
    seed = document.get("seed")
    timeline = document.get("timeline")
    if (
        not isinstance(scenario_id, str)
        or not scenario_id
        or len(scenario_id) > 64
        or not scenario_id[0].islower()
        or any(
            character not in "abcdefghijklmnopqrstuvwxyz0123456789-"
            for character in scenario_id
        )
    ):
        raise ScenarioError("scenario id is invalid")
    seed = _bounded_int(seed, "scenario seed", 0, (1 << 63) - 1)
    if (
        not isinstance(timeline, list)
        or not timeline
        or len(timeline) > MAX_TIMELINE_EVENTS
    ):
        raise ScenarioError("scenario timeline is invalid")

    operations: list[dict[str, object]] = []
    previous_at_ms = -1
    for event in timeline:
        if not isinstance(event, dict):
            raise ScenarioError("scenario event must be an object")
        action = event.get("action")
        if action not in {"set_netem", "reset_netem"}:
            raise ScenarioError("scenario action is unsupported")
        expected_fields = NETEM_FIELDS if action == "set_netem" else RESET_FIELDS
        _exact_fields(event, expected_fields, "scenario event")
        at_ms = _bounded_int(event.get("at_ms"), "at_ms", 0, MAX_TIMELINE_MS)
        if at_ms <= previous_at_ms:
            raise ScenarioError("scenario at_ms values must be strictly increasing")
        previous_at_ms = at_ms
        node, interface = _target(event)
        if action == "reset_netem":
            operations.append(
                {
                    "at_ms": at_ms,
                    "argv": [
                        "containerlab",
                        "tools",
                        "netem",
                        "reset",
                        "--node",
                        f"{LAB_PREFIX}{node}",
                        "--interface",
                        interface,
                    ],
                }
            )
            continue
        delay_ms = _bounded_int(event.get("delay_ms"), "delay_ms", 0, 60_000)
        jitter_ms = _bounded_int(event.get("jitter_ms"), "jitter_ms", 0, delay_ms)
        loss_percent = _bounded_number(
            event.get("loss_percent"), "loss_percent", 0, 100
        )
        rate_kbit = _bounded_int(
            event.get("rate_kbit"), "rate_kbit", 0, 1_000_000_000
        )
        argv = [
            "containerlab",
            "tools",
            "netem",
            "set",
            "--node",
            f"{LAB_PREFIX}{node}",
            "--interface",
            interface,
            "--delay",
            f"{delay_ms}ms",
            "--jitter",
            f"{jitter_ms}ms",
            "--loss",
            str(loss_percent),
            "--rate",
            str(rate_kbit),
        ]
        operations.append({"at_ms": at_ms, "argv": argv})

    return {
        "schema": PLAN_SCHEMA,
        "scenario_id": scenario_id,
        "seed": seed,
        "operations": operations,
    }


def _read_scenario(path: Path) -> bytes:
    with path.open("rb") as handle:
        raw = handle.read(MAX_SCENARIO_BYTES + 1)
    if len(raw) > MAX_SCENARIO_BYTES:
        raise ScenarioError("scenario exceeds the byte bound")
    return raw


def main(arguments: list[str] | None = None) -> int:
    """Validate a scenario or explicitly execute it on a qualified Linux host."""

    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("scenario", type=Path)
    parser.add_argument("--execute", action="store_true")
    parser.add_argument("--containerlab", type=Path)
    parsed = parser.parse_args(arguments)
    try:
        raw = _read_scenario(parsed.scenario)
        if parsed.execute:
            containerlab = parsed.containerlab
            if containerlab is None:
                discovered = shutil.which("containerlab")
                if discovered is None:
                    raise ExecutionError("Containerlab executable was not found")
                containerlab = Path(discovered)
            preflight_execution(containerlab, TOPOLOGY)
            output = execute_scenario(
                raw,
                containerlab=containerlab,
                topology=TOPOLOGY,
            )
        else:
            output = compile_manifest(raw)
    except (OSError, ScenarioError, ExecutionError) as error:
        print(f"aster-path-lab: {error}", file=sys.stderr)
        return 2
    print(json.dumps(output, sort_keys=True, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    sys.exit(main())
