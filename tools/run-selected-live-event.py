#!/usr/bin/env python3
# Copyright 2026 Defense Unicorns, Inc.
# SPDX-License-Identifier: Apache-2.0
"""Create one exclusive raw root for selected live Event acceptance."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import pwd
import re
import selectors
import shutil
import signal
import stat
import subprocess
import sys
import time
from typing import Any


RAW_SCHEMA = "aster-selected-live-event-raw/v2"
CLAIM = "selected-live-event-one-host-direct-iroh-priority-withheld-authenticated-gap-forced-receiver-process-termination-durable-redelivery-gap-closure-acceptance"
BINARY_NAME = "aster-live-event-acceptance"
EXAMPLE_NAME = "live_event_acceptance"
TRANSCRIPT_PREFIX = b"LIVE_EVENT\t"
TRANSCRIPT_RECORDS = 79
PARTICIPANTS = ("publisher", "receiver")
MAX_STDOUT_BYTES = 8 * 1024 * 1024
MAX_TRANSCRIPT_BYTES = 64 * 1024
MAX_MISSION_BYTES = 1024 * 1024
MAX_STORE_BYTES = 1024 * 1024 * 1024
IDENTITY_BYTES = 32
RUN_TIMEOUT_SECONDS = 180
BUILD_TIMEOUT_SECONDS = 900
SIGNER_FINGERPRINT = re.compile(r"(?:[0-9A-F]{40,64}|SHA256:[A-Za-z0-9+/]{43})\Z")
BUILD_ARGV = [
    "cargo",
    "build",
    "--release",
    "--locked",
    "-p",
    "aster-node",
    "--example",
    EXAMPLE_NAME,
]
ADMITTED_PATHS = tuple(
    sorted(
        (
            "Cargo.toml",
            "Cargo.lock",
            "mise.toml",
            "crates/aster-core/Cargo.toml",
            "crates/aster-core/src/custody.rs",
            "crates/aster-core/src/crypto/reference.rs",
            "crates/aster-core/src/lib.rs",
            "crates/aster-core/src/source_event.rs",
            "crates/aster-node/Cargo.toml",
            "crates/aster-node/src/publication_journal.rs",
            "tools/historical/check-selected-live-event-receipt.py",
            "tools/historical/check-selected-linux-event-custody-receipt.py",

            "crates/aster-node/src/application.rs",
            "crates/aster-node/src/frame.rs",
            "crates/aster-node/src/identity.rs",
            "crates/aster-node/src/lib.rs",
            "crates/aster-node/src/mission.rs",
            "crates/aster-node/src/runtime.rs",
            "crates/aster-node/examples/live_event_acceptance.rs",
            "crates/aster-redb-store/Cargo.toml",
            "crates/aster-redb-store/src/custody.rs",
            "crates/aster-redb-store/src/lib.rs",
            "tools/run-selected-live-event.py",
            "tools/check-selected-live-event-receipt.py",
            "tools/test-selected-live-event-receipt.py",
        )
    )
)
TOOL_PATHS = {
    "producer": "crates/aster-node/examples/live_event_acceptance.rs",
    "runner": "tools/run-selected-live-event.py",
    "checker": "tools/check-selected-live-event-receipt.py",
    "test": "tools/test-selected-live-event-receipt.py",
}
EXPECTED_DIRECTORIES = {
    "",
    "binary",
    "participants",
    "participants/publisher",
    "participants/publisher/state",
    "participants/receiver",
    "participants/receiver/state",
}
PUBLIC_FILES = {
    f"binary/{BINARY_NAME}": 0o700,
    "stdout.log": 0o600,
    "stderr.log": 0o600,
    "transcript.tsv": 0o600,
}
PARTICIPANT_SECRET_FILES = {
    f"participants/{participant}/{relative}": 0o600
    for participant in PARTICIPANTS
    for relative in ("mission.bundle", "state/identity.key", "state/mesh.redb")
}

PARTICIPANT_SECRET_FILES["participants/publisher/state/live-acceptance-publication.redb"] = 0o600

class RunnerFailure(Exception):
    """Sanitized local runner failure."""


def fail() -> None:
    print("selected live Event runner failed", file=sys.stderr)
    raise SystemExit(1)


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def stable_stat_witness(metadata: os.stat_result) -> tuple[int | float | None, ...]:
    """Return metadata that must remain stable while an artifact is inspected."""
    return (
        metadata.st_dev,
        metadata.st_ino,
        metadata.st_mode,
        metadata.st_nlink,
        metadata.st_uid,
        metadata.st_gid,
        metadata.st_size,
        metadata.st_mtime_ns,
        metadata.st_ctime_ns,
        getattr(metadata, "st_birthtime", None),
        getattr(metadata, "st_flags", None),
        getattr(metadata, "st_gen", None),
    )


def read_regular_file(
    path: Path,
    *,
    maximum: int,
    allow_empty: bool = False,
) -> tuple[bytes, os.stat_result]:
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(path, flags)
    try:
        before = os.fstat(descriptor)
        if not stat.S_ISREG(before.st_mode) or before.st_nlink != 1:
            raise RunnerFailure()
        if before.st_size < 0 or before.st_size > maximum:
            raise RunnerFailure()
        if not allow_empty and before.st_size == 0:
            raise RunnerFailure()
        witness = stable_stat_witness(before)
        if stable_stat_witness(path.lstat()) != witness:
            raise RunnerFailure()
        chunks: list[bytes] = []
        remaining = before.st_size
        while remaining:
            chunk = os.read(descriptor, min(1024 * 1024, remaining))
            if not chunk:
                raise RunnerFailure()
            chunks.append(chunk)
            remaining -= len(chunk)
        if os.read(descriptor, 1):
            raise RunnerFailure()
        data = b"".join(chunks)
        if len(data) != before.st_size:
            raise RunnerFailure()
        if stable_stat_witness(os.fstat(descriptor)) != witness:
            raise RunnerFailure()
        if stable_stat_witness(path.lstat()) != witness:
            raise RunnerFailure()
        return data, before
    finally:
        os.close(descriptor)


def file_record(
    path: Path,
    relative: str,
    *,
    max_bytes: int = 64 * 1024 * 1024,
    allow_empty: bool = False,
) -> dict[str, Any]:
    data, _ = read_regular_file(path, maximum=max_bytes, allow_empty=allow_empty)
    return {"path": relative, "bytes": len(data), "sha256": sha256_bytes(data)}


def exclusive_file(path: Path, mode: int):
    flags = (
        os.O_WRONLY
        | os.O_CREAT
        | os.O_EXCL
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_NOFOLLOW", 0)
    )
    descriptor = os.open(path, flags, mode)
    os.fchmod(descriptor, mode)
    return os.fdopen(descriptor, "wb", buffering=0)


def write_exclusive(path: Path, data: bytes, mode: int = 0o600) -> None:
    with exclusive_file(path, mode) as output:
        view = memoryview(data)
        while view:
            written = output.write(view)
            if written is None or written <= 0:
                raise RunnerFailure()
            view = view[written:]
        os.fsync(output.fileno())


def reviewer_home_directory() -> str:
    try:
        home = pwd.getpwuid(os.getuid()).pw_dir
    except (KeyError, OSError) as error:
        raise RunnerFailure() from error
    if not os.path.isabs(home) or os.path.realpath(home) != home:
        raise RunnerFailure()
    metadata = os.lstat(home)
    if (
        not stat.S_ISDIR(metadata.st_mode)
        or metadata.st_uid != os.getuid()
        or stat.S_IMODE(metadata.st_mode) & 0o022
    ):
        raise RunnerFailure()
    return home


def safe_git_environment(global_config: str = os.devnull) -> dict[str, str]:
    environment = os.environ.copy()
    for name in list(environment):
        if name in {
            "GIT_DIR",
            "GIT_WORK_TREE",
            "GIT_COMMON_DIR",
            "GIT_OBJECT_DIRECTORY",
            "GIT_ALTERNATE_OBJECT_DIRECTORIES",
            "GIT_INDEX_FILE",
            "GIT_NAMESPACE",
            "GIT_CONFIG_PARAMETERS",
            "GIT_CONFIG_SYSTEM",
            "GIT_CONFIG_GLOBAL",
            "PYTHONHOME",
            "PYTHONPATH",
        } or any(
            name.startswith(prefix)
            for prefix in ("GIT_CONFIG_KEY_", "GIT_CONFIG_VALUE_", "DYLD_", "LD_")
        ):
            environment.pop(name, None)
    environment.pop("GIT_CONFIG_COUNT", None)
    environment.pop("GNUPGHOME", None)
    environment.pop("GPG_TTY", None)
    environment.update(
        {
            "GIT_NO_REPLACE_OBJECTS": "1",
            "GIT_CONFIG_NOSYSTEM": "1",
            "GIT_CONFIG_GLOBAL": global_config,
            "GIT_OPTIONAL_LOCKS": "0",
            "HOME": reviewer_home_directory(),
            "LC_ALL": "C",
            "LANG": "C",
            "PATH": os.confstr("CS_PATH") or "/bin:/usr/bin",
        }
    )
    return environment


def trusted_executable(path: str) -> str:
    if not os.path.isabs(path) or os.path.realpath(path) != path:
        raise RunnerFailure()
    metadata = os.lstat(path)
    if (
        not stat.S_ISREG(metadata.st_mode)
        or metadata.st_uid not in {0, os.getuid()}
        or metadata.st_nlink < 1
        or (metadata.st_uid != 0 and metadata.st_nlink != 1)
        or metadata.st_size <= 0
        or stat.S_IMODE(metadata.st_mode) & 0o022
        or stat.S_IMODE(metadata.st_mode) & 0o111 == 0
    ):
        raise RunnerFailure()
    return path


def system_executable(name: str) -> str:
    search_path = os.confstr("CS_PATH") or "/bin:/usr/bin"
    resolved = shutil.which(name, path=search_path)
    if resolved is None:
        raise RunnerFailure()
    return trusted_executable(os.path.realpath(resolved))


def reviewer_signature_options() -> tuple[str, list[str]]:
    git_executable = system_executable("git")
    reviewer_home = reviewer_home_directory()
    reviewer_global = os.path.abspath(os.path.join(reviewer_home, ".gitconfig"))
    if os.path.realpath(reviewer_global) != reviewer_global:
        raise RunnerFailure()
    metadata = os.lstat(reviewer_global)
    if (
        not stat.S_ISREG(metadata.st_mode)
        or metadata.st_nlink != 1
        or metadata.st_uid != os.getuid()
        or metadata.st_mode & 0o022 != 0
        or metadata.st_size <= 0
        or metadata.st_size > 1024 * 1024
    ):
        raise RunnerFailure()
    environment = safe_git_environment(reviewer_global)

    def global_value(arguments: list[str]) -> str:
        completed = subprocess.run(
            [git_executable, "config", "--global", *arguments],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            env=environment,
            check=False,
            timeout=10,
        )
        if completed.returncode != 0 or completed.stderr or len(completed.stdout) > 4096:
            raise RunnerFailure()
        try:
            value = completed.stdout.decode("utf-8", errors="strict").strip()
        except UnicodeDecodeError as error:
            raise RunnerFailure() from error
        if not value or "\n" in value or "\x00" in value:
            raise RunnerFailure()
        return value

    signature_format = global_value(["--get", "gpg.format"])
    if signature_format == "ssh":
        allowed = global_value(["--path", "--get", "gpg.ssh.allowedSignersFile"])
        if allowed.startswith("~/"):
            allowed_signers = os.path.join(reviewer_home, allowed[2:])
        elif os.path.isabs(allowed):
            allowed_signers = allowed
        else:
            raise RunnerFailure()
        allowed_signers = os.path.abspath(allowed_signers)
        if os.path.realpath(allowed_signers) != allowed_signers:
            raise RunnerFailure()
        allowed_metadata = os.lstat(allowed_signers)
        if (
            not stat.S_ISREG(allowed_metadata.st_mode)
            or allowed_metadata.st_nlink != 1
            or allowed_metadata.st_uid != os.getuid()
            or allowed_metadata.st_mode & 0o022 != 0
            or allowed_metadata.st_size <= 0
            or allowed_metadata.st_size > 1024 * 1024
        ):
            raise RunnerFailure()
        ssh_keygen = system_executable("ssh-keygen")
        return git_executable, [
            "-c",
            "gpg.format=ssh",
            "-c",
            f"gpg.ssh.allowedSignersFile={allowed_signers}",
            "-c",
            f"gpg.ssh.program={ssh_keygen}",
            "-c",
            "gpg.minTrustLevel=fully",
        ]
    if signature_format == "openpgp":
        gpg = trusted_executable(global_value(["--path", "--get", "gpg.program"]))
        return git_executable, [
            "-c",
            "gpg.format=openpgp",
            "-c",
            f"gpg.program={gpg}",
            "-c",
            f"gpg.openpgp.program={gpg}",
            "-c",
            "gpg.minTrustLevel=fully",
        ]
    raise RunnerFailure()


def git(
    source: Path,
    arguments: list[str],
    *,
    git_executable: str,
    trusted_options: list[str],
    capture: bool = True,
) -> bytes:
    completed = subprocess.run(
        [
            git_executable,
            "--no-replace-objects",
            *trusted_options,
            "-c",
            "core.fsmonitor=false",
            "-c",
            "core.hooksPath=/dev/null",
            "-C",
            os.fspath(source),
            *arguments,
        ],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE if capture else subprocess.DEVNULL,
        stderr=subprocess.PIPE,
        env=safe_git_environment(),
        check=False,
        timeout=60,
    )
    stdout = completed.stdout or b""
    stderr = completed.stderr or b""
    if completed.returncode != 0 or len(stdout) > 64 * 1024 * 1024 or len(stderr) > 1024 * 1024:
        raise RunnerFailure()
    return stdout


def source_snapshot(
    source: Path, git_executable: str, trusted_options: list[str]
) -> dict[str, Any]:
    def source_git(arguments: list[str], *, capture: bool = True) -> bytes:
        return git(
            source,
            arguments,
            git_executable=git_executable,
            trusted_options=trusted_options,
            capture=capture,
        )

    status = source_git(["status", "--porcelain=v1", "--untracked-files=all"])
    if status:
        raise RunnerFailure()
    commit = source_git(["rev-parse", "--verify", "HEAD^{commit}"]).decode("ascii").strip()
    tree = source_git(["show", "-s", "--format=%T", commit]).decode("ascii").strip()
    if len(commit) != 40 or len(tree) != 40:
        raise RunnerFailure()
    int(commit, 16)
    int(tree, 16)
    top_bytes = source_git(["rev-parse", "--show-toplevel"])
    if not top_bytes.endswith(b"\n") or b"\x00" in top_bytes:
        raise RunnerFailure()
    top = Path(os.fsdecode(top_bytes[:-1]))
    if not os.path.samefile(source, top):
        raise RunnerFailure()
    source_git(["verify-commit", commit], capture=False)
    signature_output = source_git(["show", "-s", "--format=%G?%x00%GF", commit])
    if not signature_output.endswith(b"\n") or signature_output.count(b"\x00") != 1:
        raise RunnerFailure()
    status_byte, fingerprint_bytes = signature_output[:-1].split(b"\x00", 1)
    if status_byte != b"G" or not 1 <= len(fingerprint_bytes) <= 512:
        raise RunnerFailure()
    fingerprint = fingerprint_bytes.decode("ascii")
    if SIGNER_FINGERPRINT.fullmatch(fingerprint) is None:
        raise RunnerFailure()

    admitted = []
    for relative in ADMITTED_PATHS:
        path = source / relative
        committed = source_git(["show", f"{commit}:{relative}"])
        if not committed or len(committed) > 16 * 1024 * 1024:
            raise RunnerFailure()
        observed, metadata = read_regular_file(path, maximum=16 * 1024 * 1024)
        if metadata.st_uid != os.getuid() or observed != committed:
            raise RunnerFailure()
        admitted.append(
            {"path": relative, "bytes": len(committed), "sha256": sha256_bytes(committed)}
        )
    return {
        "commit": commit,
        "tree": tree,
        "signature": {"status": "good", "fingerprint": fingerprint},
        "admitted": admitted,
    }


def build_release(source: Path) -> Path:
    environment = os.environ.copy()
    for name in list(environment):
        if name in {
            "CARGO_TARGET_DIR",
            "RUSTFLAGS",
            "CARGO_ENCODED_RUSTFLAGS",
            "RUSTC_WRAPPER",
            "RUSTC_WORKSPACE_WRAPPER",
            "RUSTDOCFLAGS",
            "PYTHONHOME",
            "PYTHONPATH",
        } or name.startswith(("DYLD_", "LD_")):
            environment.pop(name, None)
    environment.update(
        {
            "CARGO_TARGET_DIR": os.fspath(source / "target"),
            "CARGO_INCREMENTAL": "0",
            "LC_ALL": "C",
            "LANG": "C",
        }
    )
    completed = subprocess.run(
        BUILD_ARGV,
        cwd=source,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        env=environment,
        check=False,
        timeout=BUILD_TIMEOUT_SECONDS,
    )
    if completed.returncode != 0:
        raise RunnerFailure()
    binary = source / "target" / "release" / "examples" / EXAMPLE_NAME
    require_regular_executable(binary)
    return binary


def require_regular_executable(path: Path) -> os.stat_result:
    metadata = path.lstat()
    if not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1:
        raise RunnerFailure()
    if metadata.st_size <= 0 or metadata.st_size > 128 * 1024 * 1024:
        raise RunnerFailure()
    if metadata.st_mode & 0o111 == 0:
        raise RunnerFailure()
    return metadata


def copy_binary(source: Path, destination: Path) -> str:
    source_flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    source_descriptor = os.open(source, source_flags)
    try:
        before = os.fstat(source_descriptor)
        require_regular_executable(source)
        source_witness = stable_stat_witness(before)
        if stable_stat_witness(source.lstat()) != source_witness:
            raise RunnerFailure()
        with exclusive_file(destination, 0o700) as output:
            copied = 0
            digest = hashlib.sha256()
            while True:
                chunk = os.read(source_descriptor, 1024 * 1024)
                if not chunk:
                    break
                copied += len(chunk)
                if copied > before.st_size:
                    raise RunnerFailure()
                digest.update(chunk)
                view = memoryview(chunk)
                while view:
                    written = output.write(view)
                    if written is None or written <= 0:
                        raise RunnerFailure()
                    view = view[written:]
            if copied != before.st_size:
                raise RunnerFailure()
            os.fsync(output.fileno())
        if stable_stat_witness(os.fstat(source_descriptor)) != source_witness:
            raise RunnerFailure()
        if stable_stat_witness(source.lstat()) != source_witness:
            raise RunnerFailure()
    finally:
        os.close(source_descriptor)
    os.chmod(destination, 0o700, follow_symlinks=False)
    require_regular_executable(destination)
    return digest.hexdigest()


def executable_record(
    path: Path, relative: str
) -> tuple[dict[str, Any], tuple[int | float | None, ...]]:
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(path, flags)
    try:
        before = os.fstat(descriptor)
        if not stat.S_ISREG(before.st_mode) or before.st_nlink != 1:
            raise RunnerFailure()
        if before.st_size <= 0 or before.st_size > 128 * 1024 * 1024:
            raise RunnerFailure()
        if before.st_mode & 0o111 == 0:
            raise RunnerFailure()
        witness = stable_stat_witness(before)
        if stable_stat_witness(path.lstat()) != witness:
            raise RunnerFailure()
        digest = hashlib.sha256()
        byte_count = 0
        while True:
            chunk = os.read(descriptor, 1024 * 1024)
            if not chunk:
                break
            byte_count += len(chunk)
            if byte_count > before.st_size:
                raise RunnerFailure()
            digest.update(chunk)
        if byte_count != before.st_size:
            raise RunnerFailure()
        if stable_stat_witness(os.fstat(descriptor)) != witness:
            raise RunnerFailure()
        if stable_stat_witness(path.lstat()) != witness:
            raise RunnerFailure()
        return (
            {"path": relative, "bytes": byte_count, "sha256": digest.hexdigest()},
            witness,
        )
    finally:
        os.close(descriptor)


def sanitized_run_environment() -> dict[str, str]:
    environment = os.environ.copy()
    for name in list(environment):
        if name.startswith("DYLD_") or name.startswith("LD_") or name.startswith("ASTER_"):
            environment.pop(name, None)
    environment.update(
        {
            "RUST_BACKTRACE": "0",
            "LC_ALL": "C",
            "LANG": "C",
            "TZ": "UTC",
            "PATH": os.confstr("CS_PATH") or "/bin:/usr/bin",
        }
    )
    return environment


def terminate_process_group(process: subprocess.Popen[bytes]) -> None:
    try:
        os.killpg(process.pid, signal.SIGTERM)
    except ProcessLookupError:
        if process.poll() is None:
            process.wait(timeout=5)
        return
    deadline = time.monotonic() + 5
    while time.monotonic() < deadline:
        try:
            os.killpg(process.pid, 0)
        except ProcessLookupError:
            break
        time.sleep(0.05)
    try:
        os.killpg(process.pid, signal.SIGKILL)
    except ProcessLookupError:
        pass
    try:
        process.wait(timeout=5)
    except subprocess.TimeoutExpired:
        pass


def run_binary(
    binary: Path,
    raw_root: Path,
    source: Path,
    stdout_path: Path,
    stderr_path: Path,
) -> int:
    with exclusive_file(stdout_path, 0o600) as stdout_file, exclusive_file(
        stderr_path, 0o600
    ) as stderr_file:
        process = subprocess.Popen(
            [os.fspath(binary), os.fspath(raw_root)],
            cwd=source,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env=sanitized_run_environment(),
            close_fds=True,
            start_new_session=True,
        )
        if process.stdout is None or process.stderr is None:
            terminate_process_group(process)
            raise RunnerFailure()
        stream_targets = {
            process.stdout.fileno(): (process.stdout, stdout_file),
            process.stderr.fileno(): (process.stderr, stderr_file),
        }
        counts = {descriptor: 0 for descriptor in stream_targets}
        selector = selectors.DefaultSelector()
        for descriptor in stream_targets:
            selector.register(descriptor, selectors.EVENT_READ)
        deadline = time.monotonic() + RUN_TIMEOUT_SECONDS
        try:
            while selector.get_map():
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    terminate_process_group(process)
                    raise RunnerFailure()
                events = selector.select(timeout=min(remaining, 0.25))
                for key, _ in events:
                    descriptor = key.fd
                    stream, target = stream_targets[descriptor]
                    chunk = os.read(descriptor, 64 * 1024)
                    if not chunk:
                        selector.unregister(descriptor)
                        stream.close()
                        continue
                    counts[descriptor] += len(chunk)
                    if counts[descriptor] > MAX_STDOUT_BYTES:
                        terminate_process_group(process)
                        raise RunnerFailure()
                    view = memoryview(chunk)
                    while view:
                        written = target.write(view)
                        if written is None or written <= 0:
                            terminate_process_group(process)
                            raise RunnerFailure()
                        view = view[written:]
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                terminate_process_group(process)
                raise RunnerFailure()
            try:
                exit_code = process.wait(timeout=remaining)
            except subprocess.TimeoutExpired:
                terminate_process_group(process)
                raise RunnerFailure() from None
            try:
                os.killpg(process.pid, 0)
            except ProcessLookupError:
                pass
            else:
                terminate_process_group(process)
                raise RunnerFailure()
            stdout_file.flush()
            stderr_file.flush()
            os.fsync(stdout_file.fileno())
            os.fsync(stderr_file.fileno())
            return exit_code
        finally:
            selector.close()
            if process.poll() is None:
                terminate_process_group(process)
            if not process.stdout.closed:
                process.stdout.close()
            if not process.stderr.closed:
                process.stderr.close()


def extract_transcript(stdout_path: Path) -> bytes:
    stdout, _ = read_regular_file(stdout_path, maximum=MAX_STDOUT_BYTES)
    records = []
    for line in stdout.splitlines(keepends=True):
        if line.startswith(TRANSCRIPT_PREFIX):
            if not line.endswith(b"\n") or line.endswith(b"\r\n"):
                raise RunnerFailure()
            records.append(line)
    if len(records) != TRANSCRIPT_RECORDS:
        raise RunnerFailure()
    transcript = b"".join(records)
    if len(transcript) == 0 or len(transcript) > MAX_TRANSCRIPT_BYTES:
        raise RunnerFailure()
    if any(byte > 0x7F or (byte < 0x20 and byte not in (0x09, 0x0A)) for byte in transcript):
        raise RunnerFailure()
    return transcript


def inventory_metadata(metadata: os.stat_result, relative: str) -> dict[str, Any]:
    return {
        "path": relative,
        "bytes": metadata.st_size,
        "mode": stat.S_IMODE(metadata.st_mode),
        "hard_links": metadata.st_nlink,
        "owner": metadata.st_uid,
    }


def inspect_inventory(
    raw_root: Path,
) -> tuple[dict[str, list[dict[str, Any]]], dict[str, tuple[int | float | None, ...]]]:
    directory_flags = (
        os.O_RDONLY | os.O_DIRECTORY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    )
    root_descriptor = os.open(raw_root, directory_flags)
    observed_directories: dict[str, os.stat_result] = {}
    observed_files: dict[str, os.stat_result] = {}
    identities: list[tuple[int, int]] = []

    def walk(descriptor: int, relative: str) -> None:
        metadata = os.fstat(descriptor)
        if (
            not stat.S_ISDIR(metadata.st_mode)
            or metadata.st_uid != os.getuid()
            or stat.S_IMODE(metadata.st_mode) != 0o700
        ):
            raise RunnerFailure()
        observed_directories[relative] = metadata
        identities.append((metadata.st_dev, metadata.st_ino))
        names = sorted(os.listdir(descriptor))
        if len(names) > 32:
            raise RunnerFailure()
        for name in names:
            if not name or name in {".", ".."} or "/" in name or "\x00" in name:
                raise RunnerFailure()
            child_relative = f"{relative}/{name}" if relative else name
            before = os.stat(name, dir_fd=descriptor, follow_symlinks=False)
            if stat.S_ISDIR(before.st_mode):
                if child_relative not in EXPECTED_DIRECTORIES:
                    raise RunnerFailure()
                child = os.open(name, directory_flags, dir_fd=descriptor)
                try:
                    opened = os.fstat(child)
                    if (before.st_dev, before.st_ino) != (opened.st_dev, opened.st_ino):
                        raise RunnerFailure()
                    walk(child, child_relative)
                finally:
                    os.close(child)
            elif stat.S_ISREG(before.st_mode) and not stat.S_ISLNK(before.st_mode):
                expected_mode = PUBLIC_FILES.get(child_relative)
                if expected_mode is None:
                    expected_mode = PARTICIPANT_SECRET_FILES.get(child_relative)
                if expected_mode is None:
                    raise RunnerFailure()
                if (
                    before.st_uid != os.getuid()
                    or stat.S_IMODE(before.st_mode) != expected_mode
                    or before.st_nlink != 1
                ):
                    raise RunnerFailure()
                observed_files[child_relative] = before
                identities.append((before.st_dev, before.st_ino))
            else:
                raise RunnerFailure()

    try:
        walk(root_descriptor, "")
    finally:
        os.close(root_descriptor)
    if set(observed_directories) != EXPECTED_DIRECTORIES:
        raise RunnerFailure()
    if set(observed_files) != set(PUBLIC_FILES) | set(PARTICIPANT_SECRET_FILES):
        raise RunnerFailure()
    if len(identities) != len(set(identities)):
        raise RunnerFailure()

    for participant in PARTICIPANTS:
        mission = observed_files[f"participants/{participant}/mission.bundle"]
        identity = observed_files[f"participants/{participant}/state/identity.key"]
        store = observed_files[f"participants/{participant}/state/mesh.redb"]
        if not 0 < mission.st_size <= MAX_MISSION_BYTES:
            raise RunnerFailure()
        if identity.st_size != IDENTITY_BYTES:
            raise RunnerFailure()
        if not 0 < store.st_size <= MAX_STORE_BYTES:
            raise RunnerFailure()

    inventory = {
        "directories": [
            {
                "path": relative or ".",
                "mode": stat.S_IMODE(metadata.st_mode),
                "owner": metadata.st_uid,
            }
            for relative, metadata in sorted(observed_directories.items())
        ],
        "public": [
            inventory_metadata(observed_files[relative], relative)
            for relative in sorted(PUBLIC_FILES)
        ],
        "participant_secret": [
            inventory_metadata(observed_files[relative], relative)
            for relative in sorted(PARTICIPANT_SECRET_FILES)
        ],
    }
    witnesses = {
        f"directory:{relative}": stable_stat_witness(metadata)
        for relative, metadata in observed_directories.items()
    }
    witnesses.update(
        {
            f"file:{relative}": stable_stat_witness(metadata)
            for relative, metadata in observed_files.items()
        }
    )
    return inventory, witnesses


def canonical_json(value: Any) -> bytes:
    return (
        json.dumps(value, ensure_ascii=True, allow_nan=False, sort_keys=True, separators=(",", ":"))
        + "\n"
    ).encode("ascii")


def fsync_directory(path: Path) -> None:
    flags = (
        os.O_RDONLY
        | os.O_DIRECTORY
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_NOFOLLOW", 0)
    )
    descriptor = os.open(path, flags)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def parse_arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser(add_help=True)
    parser.add_argument("--source", required=True)
    parser.add_argument("--raw-root", required=True)
    return parser.parse_args()


def main() -> None:
    arguments = parse_arguments()
    source_input = Path(arguments.source)
    raw_input = Path(arguments.raw_root)
    if not source_input.is_absolute() or not raw_input.is_absolute():
        raise RunnerFailure()
    source = source_input.resolve(strict=True)
    raw_parent = raw_input.parent.resolve(strict=True)
    raw_root = raw_parent / raw_input.name
    if (
        raw_root != raw_input
        or not raw_input.name
        or raw_root.exists()
        or raw_root.is_relative_to(source)
    ):
        raise RunnerFailure()
    if not source.is_dir() or not raw_parent.is_dir():
        raise RunnerFailure()

    git_executable, trusted_options = reviewer_signature_options()
    before = source_snapshot(source, git_executable, trusted_options)
    binary = build_release(source)
    after_build = source_snapshot(source, git_executable, trusted_options)
    if after_build != before:
        raise RunnerFailure()

    os.mkdir(raw_root, 0o700)
    os.chmod(raw_root, 0o700, follow_symlinks=False)
    binary_root = raw_root / "binary"
    os.mkdir(binary_root, 0o700)
    os.chmod(binary_root, 0o700, follow_symlinks=False)
    copied_binary = binary_root / BINARY_NAME
    source_binary_sha256 = copy_binary(binary, copied_binary)
    binary_before, binary_witness = executable_record(copied_binary, f"binary/{BINARY_NAME}")
    if binary_before["sha256"] != source_binary_sha256:
        raise RunnerFailure()

    stdout_path = raw_root / "stdout.log"
    stderr_path = raw_root / "stderr.log"
    exit_code = run_binary(copied_binary, raw_root, source, stdout_path, stderr_path)
    if exit_code != 0:
        raise RunnerFailure()
    stderr_data, _ = read_regular_file(
        stderr_path, maximum=MAX_STDOUT_BYTES, allow_empty=True
    )
    if stderr_data:
        raise RunnerFailure()
    transcript = extract_transcript(stdout_path)
    transcript_path = raw_root / "transcript.tsv"
    write_exclusive(transcript_path, transcript)

    after = source_snapshot(source, git_executable, trusted_options)
    if after != before:
        raise RunnerFailure()
    binary_after, binary_after_witness = executable_record(
        copied_binary, f"binary/{BINARY_NAME}"
    )
    if binary_after != binary_before or binary_after_witness != binary_witness:
        raise RunnerFailure()

    inventory, inventory_witnesses = inspect_inventory(raw_root)
    artifacts = {
        "binary": binary_after,
        "stdout": file_record(stdout_path, "stdout.log", max_bytes=MAX_STDOUT_BYTES),
        "stderr": file_record(
            stderr_path, "stderr.log", max_bytes=MAX_STDOUT_BYTES, allow_empty=True
        ),
        "transcript": file_record(
            transcript_path, "transcript.tsv", max_bytes=MAX_TRANSCRIPT_BYTES
        ),
    }
    tools = {
        name: file_record(source / relative, relative, max_bytes=16 * 1024 * 1024)
        for name, relative in TOOL_PATHS.items()
    }
    final_inventory, final_inventory_witnesses = inspect_inventory(raw_root)
    if final_inventory != inventory or final_inventory_witnesses != inventory_witnesses:
        raise RunnerFailure()

    raw = {
        "schema": RAW_SCHEMA,
        "claim": CLAIM,
        "run_id": sha256_bytes(transcript)[:16],
        "source": before,
        "commands": {
            "build_argv": BUILD_ARGV,
            "run_argv": [os.fspath(copied_binary), os.fspath(raw_root)],
        },
        "execution": {
            "exit_code": 0,
            "timeout_seconds": RUN_TIMEOUT_SECONDS,
            "worktree_clean_at_run": True,
            "source_binary_execution_link": "operator-attested-not-cryptographically-proven",
        },
        "artifacts": artifacts,
        "inventory": inventory,
        "tools": tools,
    }
    write_exclusive(raw_root / "run.json", canonical_json(raw))
    fsync_directory(raw_root)
    print(os.fspath(raw_root))


if __name__ == "__main__":
    try:
        main()
    except (OSError, ValueError, RunnerFailure, subprocess.SubprocessError):
        fail()
