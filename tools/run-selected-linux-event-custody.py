#!/usr/bin/env python3
# Copyright 2026 Defense Unicorns, Inc.
# SPDX-License-Identifier: Apache-2.0
"""Create raw evidence for the selected Linux Event-custody acceptance.

The signed checkout is mounted read-only into a pinned linux/arm64 Rust build
container.  Build state is held in a separate temporary directory.  Only the
copied release executable and an owner-only evidence root are available to the
runtime container.
"""

from __future__ import annotations

import argparse
import hashlib
import io
import importlib.util
import json
import os
from pathlib import Path
import re
import shutil
import stat
import subprocess
import sys
import tarfile
import tempfile
from types import ModuleType
from typing import Any


RAW_SCHEMA = "aster-selected-linux-event-custody-raw/v2"
CLAIM = "selected-linux-arm64-event-custody-ttl-quota-receive-only-acceptance"
IMAGE = "rust@sha256:0e2bcaef56d041a486784e54104a81aebe0da44bd03019bd70bc0401e42e4a97"
PLATFORM = "linux/arm64"
EXAMPLE_NAME = "linux_event_custody_acceptance"
BINARY_NAME = "aster-linux-event-custody-acceptance"
TRANSCRIPT_PREFIX = b"LINUX_CUSTODY\t"
CONTAINER_ID = re.compile(r"[0-9a-f]{64}\Z")
RUN_TIMEOUT_SECONDS = 300
BUILD_TIMEOUT_SECONDS = 1800
MAX_STDOUT_BYTES = 8 * 1024 * 1024
MAX_STDERR_BYTES = 64 * 1024
MAX_TRANSCRIPT_BYTES = 256 * 1024
RUNTIME_PIDS = 128
RUNTIME_MEMORY = 1024 * 1024 * 1024
RUNTIME_CPUS = 1_000_000_000

PRODUCER_PATH = "crates/aster-node/examples/linux_event_custody_acceptance.rs"
RUNNER_PATH = "tools/run-selected-linux-event-custody.py"
CHECKER_PATH = "tools/check-selected-linux-event-custody-receipt.py"
TEST_PATH = "tools/test-selected-linux-event-custody-receipt.py"
ADMITTED_PATHS = tuple(
    sorted(
        {
            "Cargo.lock",
            "Cargo.toml",
            "mise.toml",
            "crates/aster-core/Cargo.toml",
            "crates/aster-core/src/custody.rs",
            "crates/aster-core/src/crypto/reference.rs",
            "crates/aster-core/src/lib.rs",
            "crates/aster-core/src/source_event.rs",
            "crates/aster-iroh/Cargo.toml",
            "crates/aster-iroh/src/lib.rs",
            "crates/aster-node/Cargo.toml",
            "crates/aster-node/examples/support/numbered.rs",
            "tools/historical/check-selected-live-event-receipt.py",
            "tools/historical/check-selected-linux-event-custody-receipt.py",

            "crates/aster-node/src/application.rs",
            "crates/aster-node/src/frame.rs",
            "crates/aster-node/src/identity.rs",
            "crates/aster-node/src/lib.rs",
            "crates/aster-node/src/mission.rs",
            "crates/aster-node/src/runtime.rs",
            "crates/aster-redb-store/Cargo.toml",
            "crates/aster-redb-store/src/custody.rs",
            "crates/aster-redb-store/src/lib.rs",
            PRODUCER_PATH,
            RUNNER_PATH,
            CHECKER_PATH,
            TEST_PATH,
            "tools/run-selected-live-event.py",
            "tools/check-selected-live-event-receipt.py",
        }
    )
)
BUILD_COMMAND = [
    "cargo", "build", "--release", "--locked", "-p", "aster-node",
    "--example", EXAMPLE_NAME,
]
RUNTIME_SCRIPT = (
    "umask 077; printf 'LINUX_CUSTODY_RUNTIME\\tschema=aster-linux-event-custody-runtime/v1\\n'; "
    "printf 'LINUX_CUSTODY_RUNTIME\\tkernel_sysname='; uname -s; "
    "printf 'LINUX_CUSTODY_RUNTIME\\tkernel_release='; uname -r; "
    "printf 'LINUX_CUSTODY_RUNTIME\\tkernel_version='; uname -v; "
    "printf 'LINUX_CUSTODY_RUNTIME\\tkernel_machine='; uname -m; "
    "printf 'LINUX_CUSTODY_RUNTIME\\tboot_id='; tr -d '\\n' </proc/sys/kernel/random/boot_id; printf '\\n'; "
    "printf 'LINUX_CUSTODY_RUNTIME\\tuptime='; tr -d '\\n' </proc/uptime; printf '\\n'; "
    "printf 'LINUX_CUSTODY_RUNTIME\\tclocksource='; tr -d '\\n' </sys/devices/system/clocksource/clocksource0/current_clocksource; printf '\\n'; "
    "exec \"$1\" \"$2\""
)


class RunnerFailure(Exception):
    """Sanitized local runner failure."""


def load_live_runner() -> ModuleType:
    path = Path(__file__).with_name("run-selected-live-event.py")
    specification = importlib.util.spec_from_file_location("aster_live_event_runner", path)
    if specification is None or specification.loader is None:
        raise RunnerFailure()
    module = importlib.util.module_from_spec(specification)
    specification.loader.exec_module(module)
    return module


LIVE = load_live_runner()


def fail() -> None:
    print("selected Linux Event custody runner failed", file=sys.stderr)
    raise SystemExit(1)


def canonical_json(value: Any) -> bytes:
    return LIVE.canonical_json(value)


def write_exclusive(path: Path, data: bytes, mode: int = 0o600) -> None:
    LIVE.write_exclusive(path, data, mode)


def trusted_docker() -> str:
    candidate = shutil.which("docker")
    if candidate is None:
        raise RunnerFailure()
    invocation = os.path.abspath(candidate)
    if not os.path.isabs(invocation) or os.path.basename(invocation) != "docker":
        raise RunnerFailure()
    resolved = os.path.realpath(candidate)
    LIVE.trusted_executable(resolved)
    # Multicall clients may dispatch from argv[0]. Validate the final target,
    # but preserve the absolute `docker` invocation path.
    return invocation


def run_command(
    argv: list[str],
    *,
    timeout: int,
    maximum_stdout: int = 4 * 1024 * 1024,
    maximum_stderr: int = 1024 * 1024,
    accepted: set[int] = {0},
) -> subprocess.CompletedProcess[bytes]:
    environment = {
        "HOME": LIVE.reviewer_home_directory(),
        "PATH": os.confstr("CS_PATH") or "/bin:/usr/bin",
        "LC_ALL": "C",
        "LANG": "C",
    }
    try:
        completed = subprocess.run(
            argv,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env=environment,
            check=False,
            timeout=timeout,
        )
    except (OSError, subprocess.TimeoutExpired) as error:
        raise RunnerFailure() from error
    if (
        completed.returncode not in accepted
        or len(completed.stdout) > maximum_stdout
        or len(completed.stderr) > maximum_stderr
    ):
        raise RunnerFailure()
    return completed


def docker_json(docker: str, arguments: list[str]) -> Any:
    completed = run_command([docker, *arguments], timeout=60)
    try:
        return json.loads(completed.stdout, parse_constant=lambda _value: (_ for _ in ()).throw(ValueError()))
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError) as error:
        raise RunnerFailure() from error


def ensure_image(docker: str) -> dict[str, Any]:
    inspected = run_command(
        [docker, "image", "inspect", IMAGE], timeout=60, accepted={0, 1}
    )
    if inspected.returncode != 0:
        # Image acquisition is deliberately outside the evidence run.  This
        # keeps a missing local pin from silently changing network state.
        raise RunnerFailure()
    value = docker_json(docker, ["image", "inspect", IMAGE])
    if not isinstance(value, list) or len(value) != 1 or not isinstance(value[0], dict):
        raise RunnerFailure()
    image = value[0]
    if image.get("Architecture") != "arm64" or image.get("Os") != "linux":
        raise RunnerFailure()
    image_id = image.get("Id")
    if not isinstance(image_id, str) or re.fullmatch(r"sha256:[0-9a-f]{64}", image_id) is None:
        raise RunnerFailure()
    return {
        "reference": IMAGE,
        "platform": PLATFORM,
        "id": image_id,
        "architecture": "arm64",
        "os": "linux",
        "repo_digests": image.get("RepoDigests"),
        "config": {
            key: image.get("Config", {}).get(key)
            for key in ("User", "Env", "Entrypoint", "Cmd", "WorkingDir", "Labels")
        },
    }


def source_snapshot(source: Path) -> dict[str, Any]:
    git_executable, trusted_options = LIVE.reviewer_signature_options()
    original = LIVE.ADMITTED_PATHS
    try:
        LIVE.ADMITTED_PATHS = ADMITTED_PATHS
        return LIVE.source_snapshot(source, git_executable, trusted_options)
    finally:
        LIVE.ADMITTED_PATHS = original


def exact_path(path: str, *, exists: bool) -> Path:
    absolute = os.path.abspath(path)
    if os.path.realpath(absolute) != absolute:
        raise RunnerFailure()
    value = Path(absolute)
    if exists and not value.is_dir():
        raise RunnerFailure()
    return value


def make_raw_root(path: Path) -> None:
    path.mkdir(mode=0o700, parents=False, exist_ok=False)
    os.chmod(path, 0o700)
    if path.lstat().st_uid != os.getuid():
        raise RunnerFailure()


def materialize_signed_tree(source: Path, destination: Path, authority: dict[str, Any]) -> dict[str, Any]:
    git_executable, trusted_options = LIVE.reviewer_signature_options()
    archive = LIVE.git(
        source,
        ["archive", "--format=tar", authority["commit"]],
        git_executable=git_executable,
        trusted_options=trusted_options,
    )
    files = 0
    byte_count = 0
    destination.mkdir(mode=0o700)
    with tarfile.open(fileobj=io.BytesIO(archive), mode="r:") as package:
        members = package.getmembers()
        if not members or len(members) > 20000:
            raise RunnerFailure()
        for member in members:
            target = destination / member.name
            if (
                member.name.startswith("/")
                or ".." in Path(member.name).parts
                or member.issym()
                or member.islnk()
                or not (member.isdir() or member.isfile())
            ):
                raise RunnerFailure()
            if target != destination and destination not in target.parents:
                raise RunnerFailure()
            if member.isdir():
                target.mkdir(mode=0o700, parents=True, exist_ok=True)
                continue
            byte_count += member.size
            files += 1
            if byte_count > 128 * 1024 * 1024 or member.size > 16 * 1024 * 1024:
                raise RunnerFailure()
            target.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
            extracted = package.extractfile(member)
            if extracted is None:
                raise RunnerFailure()
            data = extracted.read(member.size + 1)
            if len(data) != member.size:
                raise RunnerFailure()
            write_exclusive(target, data, 0o500 if member.mode & 0o111 else 0o400)
    for directory, names, _files in os.walk(destination, topdown=False):
        for name in names:
            os.chmod(Path(directory) / name, 0o500)
        os.chmod(directory, 0o500)
    return {
        "commit": authority["commit"],
        "tree": authority["tree"],
        "archive_sha256": LIVE.sha256_bytes(archive),
        "files": files,
        "bytes": byte_count,
        "read_only": True,
    }


def build_release(
    docker: str,
    source: Path,
    build_root: Path,
    uid: int,
    gid: int,
    *,
    allow_network: bool,
) -> tuple[Path, list[str]]:
    source_mount = f"type=bind,src={source},dst=/source,readonly"
    build_mount = f"type=bind,src={build_root},dst=/build"
    argv = [
        docker, "run", "--rm", "--pull=never", "--platform", PLATFORM,
        f"--network={'default' if allow_network else 'none'}", "--read-only",
        "--user", f"{uid}:{gid}",
        "--cap-drop=ALL", "--security-opt=no-new-privileges",
        "--pids-limit=512", "--memory=4g", "--memory-swap=4g", "--cpus=4",
        "--tmpfs", f"/tmp:rw,nosuid,nodev,noexec,size=268435456,uid={uid},gid={gid}",
        "--mount", source_mount, "--mount", build_mount,
        "--env", "CARGO_HOME=/build/cargo-home",
        "--env", "CARGO_TARGET_DIR=/build/target",
        "--env", "RUSTUP_TOOLCHAIN=1.97.1-aarch64-unknown-linux-gnu",
        "--env", "CARGO_INCREMENTAL=0", "--workdir", "/source",
        IMAGE, *BUILD_COMMAND,
    ]
    run_command(
        argv,
        timeout=BUILD_TIMEOUT_SECONDS,
        maximum_stdout=32 * 1024 * 1024,
        maximum_stderr=32 * 1024 * 1024,
    )
    binary = build_root / "target" / "release" / "examples" / EXAMPLE_NAME
    require_built_executable(binary)
    return binary, argv


def require_built_executable(path: Path) -> os.stat_result:
    metadata = path.lstat()
    if (
        not stat.S_ISREG(metadata.st_mode)
        or metadata.st_uid != os.getuid()
        or metadata.st_nlink < 1
        or metadata.st_size <= 0
        or metadata.st_size > 128 * 1024 * 1024
        or metadata.st_mode & 0o111 == 0
    ):
        raise RunnerFailure()
    return metadata


def copy_built_executable(source: Path, destination: Path) -> str:
    descriptor = os.open(
        source,
        os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0),
    )
    try:
        before = os.fstat(descriptor)
        path_before = require_built_executable(source)
        witness = LIVE.stable_stat_witness(before)
        if LIVE.stable_stat_witness(path_before) != witness:
            raise RunnerFailure()
        digest = hashlib.sha256()
        copied = 0
        with LIVE.exclusive_file(destination, 0o700) as output:
            while True:
                chunk = os.read(descriptor, 1024 * 1024)
                if not chunk:
                    break
                copied += len(chunk)
                if copied > before.st_size:
                    raise RunnerFailure()
                digest.update(chunk)
                remaining = memoryview(chunk)
                while remaining:
                    written = output.write(remaining)
                    if written is None or written <= 0:
                        raise RunnerFailure()
                    remaining = remaining[written:]
            if copied != before.st_size:
                raise RunnerFailure()
            os.fsync(output.fileno())
        if (
            LIVE.stable_stat_witness(os.fstat(descriptor)) != witness
            or LIVE.stable_stat_witness(source.lstat()) != witness
        ):
            raise RunnerFailure()
    finally:
        os.close(descriptor)
    os.chmod(destination, 0o700, follow_symlinks=False)
    LIVE.require_regular_executable(destination)
    return digest.hexdigest()


def runtime_create_argv(
    docker: str, raw_root: Path, execution_root: Path, uid: int, gid: int, name: str
) -> list[str]:
    return [
        docker, "create", "--name", name, "--pull=never", "--platform", PLATFORM,
        "--network=none", "--read-only", "--user", f"{uid}:{gid}",
        "--cap-drop=ALL", "--security-opt=no-new-privileges",
        "--cgroupns=private",
        f"--pids-limit={RUNTIME_PIDS}", f"--memory={RUNTIME_MEMORY}",
        f"--memory-swap={RUNTIME_MEMORY}", "--cpus=1",
        "--tmpfs", f"/tmp:rw,nosuid,nodev,noexec,size=33554432,uid={uid},gid={gid}",
        "--mount", f"type=bind,src={raw_root},dst=/evidence",
        "--mount", f"type=bind,src={execution_root},dst=/execution,readonly",
        IMAGE, "/bin/sh", "-eu", "-c", RUNTIME_SCRIPT, "sh",
        f"/execution/{BINARY_NAME}", "/evidence",
    ]


def execute_runtime(
    docker: str, raw_root: Path, execution_root: Path, uid: int, gid: int,
    run_id: str, image_id: str,
) -> tuple[list[str], dict[str, Any], int]:
    name = f"aster-linux-custody-{run_id}"
    create_argv = runtime_create_argv(docker, raw_root, execution_root, uid, gid, name)
    created = run_command(create_argv, timeout=60, maximum_stdout=4096)
    container_id = ""
    try:
        container_id = created.stdout.decode("ascii", errors="strict").strip()
        if CONTAINER_ID.fullmatch(container_id) is None:
            raise RunnerFailure()
        started = run_command(
            [docker, "start", "--attach", container_id],
            timeout=RUN_TIMEOUT_SECONDS,
            maximum_stdout=MAX_STDOUT_BYTES,
            maximum_stderr=MAX_STDERR_BYTES,
            accepted=set(range(256)),
        )
        inspected = docker_json(docker, ["container", "inspect", container_id])
        if not isinstance(inspected, list) or len(inspected) != 1 or not isinstance(inspected[0], dict):
            raise RunnerFailure()
        document = inspected[0]
        validate_container_inspect(document, raw_root, execution_root, uid, gid, image_id)
        exit_code = document.get("State", {}).get("ExitCode")
        if type(exit_code) is not int or exit_code != started.returncode:
            raise RunnerFailure()
        write_exclusive(raw_root / "stdout.log", started.stdout)
        write_exclusive(raw_root / "stderr.log", started.stderr, 0o600)
        write_exclusive(raw_root / "runtime-facts.tsv", extract_runtime_facts(started.stdout))
        write_exclusive(raw_root / "container-inspect.json", canonical_json(document))
        return create_argv, document, exit_code
    finally:
        cleanup_target = container_id if CONTAINER_ID.fullmatch(container_id) else name
        run_command([docker, "rm", "--force", cleanup_target], timeout=60, accepted={0, 1})


def validate_container_inspect(
    document: dict[str, Any], raw_root: Path, execution_root: Path, uid: int,
    gid: int, image_id: str,
) -> None:
    host = document.get("HostConfig")
    config = document.get("Config")
    mounts = document.get("Mounts")
    if not isinstance(host, dict) or not isinstance(config, dict) or not isinstance(mounts, list):
        raise RunnerFailure()
    expected_host = {
        "NetworkMode": "none",
        "ReadonlyRootfs": True,
        "PidsLimit": RUNTIME_PIDS,
        "Memory": RUNTIME_MEMORY,
        "MemorySwap": RUNTIME_MEMORY,
        "NanoCpus": RUNTIME_CPUS,
        "CgroupnsMode": "private",
        "Privileged": False,
    }
    if any(host.get(key) != value for key, value in expected_host.items()):
        raise RunnerFailure()
    if host.get("CapDrop") != ["ALL"] or host.get("CapAdd") is not None:
        raise RunnerFailure()
    for key, expected in {
        "Devices": [], "DeviceRequests": None, "DeviceCgroupRules": None,
        "PortBindings": {}, "PublishAllPorts": False, "AutoRemove": False,
        "RestartPolicy": {"Name": "no", "MaximumRetryCount": 0},
        "PidMode": "", "IpcMode": "private", "UTSMode": "",
    }.items():
        if host.get(key) != expected:
            raise RunnerFailure()
    security = host.get("SecurityOpt")
    if security not in (["no-new-privileges"], ["no-new-privileges:true"]):
        raise RunnerFailure()
    tmpfs = host.get("Tmpfs")
    if not isinstance(tmpfs, dict) or set(tmpfs) != {"/tmp"}:
        raise RunnerFailure()
    options = set(str(tmpfs["/tmp"]).split(","))
    required = {"rw", "nosuid", "nodev", "noexec", "size=33554432"}
    if not required.issubset(options):
        raise RunnerFailure()
    if config.get("User") != f"{uid}:{gid}" or config.get("Image") != IMAGE:
        raise RunnerFailure()
    expected_command = [
        "/bin/sh", "-eu", "-c", RUNTIME_SCRIPT, "sh",
        f"/execution/{BINARY_NAME}", "/evidence",
    ]
    observed_command = (config.get("Entrypoint") or []) + (config.get("Cmd") or [])
    if observed_command != expected_command:
        raise RunnerFailure()
    if document.get("Image") != image_id:
        raise RunnerFailure()
    state = document.get("State")
    if not isinstance(state, dict) or any(
        state.get(key) != value
        for key, value in {
            "Status": "exited", "Running": False, "Paused": False,
            "Restarting": False, "OOMKilled": False, "Dead": False,
            "Pid": 0, "ExitCode": 0, "Error": "",
        }.items()
    ):
        raise RunnerFailure()
    if len(mounts) != 2 or not all(isinstance(mount, dict) for mount in mounts):
        raise RunnerFailure()
    by_destination = {mount.get("Destination"): mount for mount in mounts}
    if set(by_destination) != {"/evidence", "/execution"}:
        raise RunnerFailure()
    mount = by_destination["/evidence"]
    if (
        mount.get("Type") != "bind"
        or mount.get("Source") != os.fspath(raw_root)
        or mount.get("Destination") != "/evidence"
        or mount.get("RW") is not True
    ):
        raise RunnerFailure()
    network = document.get("NetworkSettings")
    if (
        not isinstance(network, dict)
        or network.get("Ports") not in ({}, None)
        or set((network.get("Networks") or {})) not in ({"none"}, set())
    ):
        raise RunnerFailure()
    execution = by_destination["/execution"]
    if (
        execution.get("Type") != "bind"
        or execution.get("Source") != os.fspath(execution_root)
        or execution.get("RW") is not False
    ):
        raise RunnerFailure()


def extract_transcript(stdout: bytes) -> bytes:
    records = []
    for line in stdout.splitlines(keepends=True):
        if line.startswith(TRANSCRIPT_PREFIX):
            if not line.endswith(b"\n") or line.endswith(b"\r\n"):
                raise RunnerFailure()
            records.append(line)
    transcript = b"".join(records)
    if not records or len(transcript) > MAX_TRANSCRIPT_BYTES:
        raise RunnerFailure()
    if any(byte > 0x7f or byte < 0x20 and byte not in (0x09, 0x0a) for byte in transcript):
        raise RunnerFailure()
    return transcript


def extract_runtime_facts(stdout: bytes) -> bytes:
    prefix = b"LINUX_CUSTODY_RUNTIME\t"
    lines = [line[len(prefix):] for line in stdout.splitlines(keepends=True) if line.startswith(prefix)]
    if len(lines) != 8 or any(not line.endswith(b"\n") for line in lines):
        raise RunnerFailure()
    return b"".join(lines)


def artifact(path: Path, relative: str, maximum: int) -> dict[str, Any]:
    return LIVE.file_record(path, relative, max_bytes=maximum, allow_empty=True)


def parse_arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--source", required=True)
    parser.add_argument("--raw-root", required=True)
    parser.add_argument(
        "--allow-build-network",
        action="store_true",
        help="allow Cargo dependency access during the isolated build",
    )
    return parser.parse_args()


def main() -> None:
    arguments = parse_arguments()
    try:
        source = exact_path(arguments.source, exists=True)
        raw_root = exact_path(arguments.raw_root, exists=False)
        if raw_root.parent == source or source in raw_root.parents:
            raise RunnerFailure()
        source_authority = source_snapshot(source)
        docker = trusted_docker()
        image = ensure_image(docker)
        uid, gid = os.getuid(), os.getgid()
        if uid == 0 or gid == 0:
            raise RunnerFailure()
        make_raw_root(raw_root)
        run_id = os.urandom(8).hex()
        with tempfile.TemporaryDirectory(prefix="aster-linux-custody-") as temporary:
            workspace = Path(temporary)
            os.chmod(workspace, 0o700)
            materialized_root = workspace / "signed-source"
            build_root = workspace / "build"
            execution_root = workspace / "execution"
            materialized = materialize_signed_tree(source, materialized_root, source_authority)
            build_root.mkdir(mode=0o700)
            execution_root.mkdir(mode=0o700)
            binary, build_argv = build_release(
                docker,
                materialized_root,
                build_root,
                uid,
                gid,
                allow_network=arguments.allow_build_network,
            )
            execution_binary = execution_root / BINARY_NAME
            binary_sha256 = copy_built_executable(binary, execution_binary)
            os.chmod(execution_binary, 0o500)
            os.chmod(execution_root, 0o500)
            execution_before, execution_witness = LIVE.executable_record(
                execution_binary, BINARY_NAME
            )
            if execution_before["sha256"] != binary_sha256:
                raise RunnerFailure()
            after_build = source_snapshot(source)
            if after_build != source_authority:
                raise RunnerFailure()
            create_argv, inspect_document, exit_code = execute_runtime(
                docker, raw_root, execution_root, uid, gid, run_id, image["id"]
            )
            execution_after, terminal_execution_witness = LIVE.executable_record(
                execution_binary, BINARY_NAME
            )
            if execution_after != execution_before or terminal_execution_witness != execution_witness:
                raise RunnerFailure()
            (raw_root / "binary").mkdir(mode=0o700)
            copied = raw_root / "binary" / BINARY_NAME
            retained_sha256 = LIVE.copy_binary(execution_binary, copied)
            if retained_sha256 != binary_sha256:
                raise RunnerFailure()
        stdout, _ = LIVE.read_regular_file(raw_root / "stdout.log", maximum=MAX_STDOUT_BYTES, allow_empty=True)
        transcript = extract_transcript(stdout)
        write_exclusive(raw_root / "transcript.tsv", transcript)
        terminal_source = source_snapshot(source)
        if terminal_source != source_authority:
            raise RunnerFailure()
        binary_after, terminal_binary_witness = LIVE.executable_record(
            copied, f"binary/{BINARY_NAME}"
        )
        if binary_after["sha256"] != binary_sha256:
            raise RunnerFailure()
        run_document = {
            "schema": RAW_SCHEMA,
            "claim": CLAIM,
            "run_id": run_id,
            "source": source_authority,
            "materialized_source": materialized,
            "image": image,
            "commands": {
                "build": build_argv,
                "runtime_create": create_argv,
                "runtime_start": [docker, "start", "--attach", inspect_document.get("Id")],
            },
            "runtime": {
                "container_id": inspect_document.get("Id"),
                "image_id": inspect_document.get("Image"),
                "exit_code": exit_code,
                "timeout_seconds": RUN_TIMEOUT_SECONDS,
                "uid": uid,
                "gid": gid,
                "platform": PLATFORM,
                "network": "none",
                "read_only_root": True,
                "cap_drop": ["ALL"],
                "no_new_privileges": True,
                "pids_limit": RUNTIME_PIDS,
                "memory_bytes": RUNTIME_MEMORY,
                "memory_swap_bytes": RUNTIME_MEMORY,
                "nano_cpus": RUNTIME_CPUS,
                "raw_mount": {"destination": "/evidence", "read_write": True, "owner_only": True},
            },
            "artifacts": {
                "binary": {"path": f"binary/{BINARY_NAME}", "bytes": copied.stat().st_size, "sha256": binary_sha256},
                "stdout": artifact(raw_root / "stdout.log", "stdout.log", MAX_STDOUT_BYTES),
                "stderr": artifact(raw_root / "stderr.log", "stderr.log", MAX_STDERR_BYTES),
                "transcript": artifact(raw_root / "transcript.tsv", "transcript.tsv", MAX_TRANSCRIPT_BYTES),
                "runtime_facts": artifact(raw_root / "runtime-facts.tsv", "runtime-facts.tsv", 16 * 1024),
                "container_inspect": artifact(raw_root / "container-inspect.json", "container-inspect.json", 1024 * 1024),
            },
            "build_network": "allowed-by-explicit-operator-flag" if arguments.allow_build_network else "none",
            "limitations": [
                "operator-attested-source-binary-execution-link-not-reproducible-build",
                "build-network-not-part-of-runtime" if arguments.allow_build_network else "offline-build-cache-dependent",
                "one-container-one-kernel-one-implementation-observation",
            ],
        }
        write_exclusive(raw_root / "run.json", canonical_json(run_document))
        LIVE.fsync_directory(raw_root / "binary")
        LIVE.fsync_directory(raw_root)
        if exit_code != 0:
            raise RunnerFailure()
    except (
        OSError,
        ValueError,
        UnicodeError,
        TypeError,
        KeyError,
        AttributeError,
        RunnerFailure,
        LIVE.RunnerFailure,
        subprocess.SubprocessError,
    ):
        fail()


if __name__ == "__main__":
    main()
