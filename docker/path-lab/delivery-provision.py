#!/usr/bin/env python3
# Copyright 2026 Defense Unicorns, Inc.
# SPDX-License-Identifier: Apache-2.0
"""Create two isolated endpoint states without attaching to any network."""

from __future__ import annotations

import os
from pathlib import Path
import re
import selectors
import shutil
import subprocess
import sys
import tempfile
import time


MAX_INITIALIZER_OUTPUT_BYTES = 16 * 1024
STATE_FILES = {"identity.key", "mission.unprotected-reference.bundle"}


def set_owner_only_umask() -> None:
    os.umask(0o077)


def seed_root(parent: Path) -> Path:
    return parent / "mission"


def state_targets(lab: Path) -> list[Path]:
    return [lab / "node-a" / "state", lab / "node-b" / "state"]


def create_state_targets(lab: Path) -> list[Path]:
    targets = state_targets(lab)
    if any(target.exists() or target.is_symlink() for target in targets):
        raise ValueError("endpoint state already exists")
    for target in targets:
        target.mkdir(mode=0o700, parents=True)
    return targets


def copy_state(source: Path, target: Path) -> None:
    items = list(source.iterdir())
    if {item.name for item in items} != STATE_FILES:
        raise ValueError("state source must contain only regular files")
    for item in items:
        if item.is_symlink() or not item.is_file():
            raise ValueError("state source must contain only regular files")
        destination = target / item.name
        if destination.exists() or destination.is_symlink():
            raise ValueError("endpoint state path exists")
        shutil.copy2(item, destination)


def run_initializer(argv: list[str], timeout: float) -> bytes:
    process: subprocess.Popen[bytes] | None = None
    try:
        process = subprocess.Popen(
            argv,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        if process.stdout is None or process.stderr is None:
            raise ValueError("initializer output capture is unavailable")
        raw_stdout = bytearray()
        captured = 0
        deadline = time.monotonic() + timeout
        with selectors.DefaultSelector() as selector:
            selector.register(process.stdout, selectors.EVENT_READ, True)
            selector.register(process.stderr, selectors.EVENT_READ, False)
            while selector.get_map():
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise ValueError("initializer output timed out")
                events = selector.select(remaining)
                if not events:
                    raise ValueError("initializer output timed out")
                for key, _mask in events:
                    allowance = MAX_INITIALIZER_OUTPUT_BYTES - captured
                    chunk = os.read(key.fd, min(64 * 1024, allowance + 1))
                    if not chunk:
                        selector.unregister(key.fileobj)
                        continue
                    if len(chunk) > allowance:
                        raise ValueError("initializer output is oversized")
                    captured += len(chunk)
                    if key.data:
                        raw_stdout.extend(chunk)
        returncode = process.wait(timeout=max(0, deadline - time.monotonic()))
        if returncode != 0:
            raise ValueError("initializer output failed")
        return bytes(raw_stdout)
    except ValueError:
        if process is not None and process.poll() is None:
            process.kill()
            process.wait()
        raise
    except (OSError, subprocess.SubprocessError) as error:
        if process is not None and process.poll() is None:
            process.kill()
            process.wait()
        raise ValueError("initializer output failed") from error
    finally:
        if process is not None:
            if process.stdout is not None:
                process.stdout.close()
            if process.stderr is not None:
                process.stderr.close()


def parse_nodes(raw: bytes) -> list[tuple[str, str]]:
    if len(raw) > MAX_INITIALIZER_OUTPUT_BYTES:
        raise ValueError("initializer output is oversized")
    try:
        lines = raw.decode("ascii").splitlines()
    except UnicodeError as error:
        raise ValueError("initializer output is malformed") from error
    if len(lines) != 3 or not lines[0].startswith("PLAYGROUND_INIT status=pass nodes=2 "):
        raise ValueError("initializer output is malformed")
    nodes: dict[int, tuple[str, str]] = {}
    pattern = re.compile(
        r"PLAYGROUND_NODE index=([01]) carrier_id=([0-9a-f]{64}) mission_id=([0-9a-f]{64})"
    )
    for line in lines[1:]:
        match = pattern.fullmatch(line)
        if match is None:
            raise ValueError("initializer output is malformed")
        index = int(match.group(1))
        if index in nodes:
            raise ValueError("initializer output is malformed")
        nodes[index] = (match.group(2), match.group(3))
    if set(nodes) != {0, 1}:
        raise ValueError("initializer output is malformed")
    return [nodes[0], nodes[1]]


def main() -> int:
    try:
        set_owner_only_umask()
        lab = Path("/lab")
        targets = create_state_targets(lab)
        with tempfile.TemporaryDirectory(prefix="aster-delivery-seed-") as directory:
            seed = seed_root(Path(directory))
            raw = run_initializer(
                ["/usr/local/bin/aster", "playground-init", "--nodes", "2", "--root", str(seed)],
                timeout=30,
            )
            identities = parse_nodes(raw)
            for index, target in enumerate(targets):
                source = seed / f"node-{index}"
                copy_state(source, target)
                subprocess.run(
                    [
                        "python3", "/usr/local/libexec/aster/aster_lan_mvp.py", "token",
                        "--file", str(target / "client.token"),
                    ],
                    stdin=subprocess.DEVNULL,
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                    timeout=10,
                    check=True,
                )
            (targets[0] / "peer").write_text(
                f"{identities[1][0]}@10.77.2.2:4433={identities[1][1]}\n", encoding="ascii"
            )
            (targets[1] / "peer").write_text(
                f"{identities[0][0]}@10.77.1.2:4433={identities[0][1]}\n", encoding="ascii"
            )
            for target in targets:
                os.chmod(target, 0o700)
                for item in target.iterdir():
                    os.chmod(item, 0o600)
                    os.chown(item, 10001, 10001)
                os.chown(target, 10001, 10001)
        print("PROVISION status=pass nodes=2 network=none state=owner-only")
        return 0
    except (OSError, ValueError, subprocess.SubprocessError):
        print("delivery-provision: isolated provisioning failed", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
