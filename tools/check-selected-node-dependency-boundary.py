#!/usr/bin/env python3
# Copyright 2026 Defense Unicorns, Inc.
# SPDX-License-Identifier: Apache-2.0
"""Keep the selected node on its isolated production dependency spine."""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
REQUIRED = {
    "aster-core",
    "aster-iroh",
    "aster-negentropy",
    "aster-node",
    "aster-profile",
    "aster-redb-store",
}
FORBIDDEN = {
    "aster-host",
    "aster-ip",
    "aster-libp2p-provider",
    "libsqlite3-sys",
    "rusqlite",
}


def cargo_tree(*arguments: str) -> str:
    result = subprocess.run(
        ["cargo", "tree", "--locked", "--offline", "-p", "aster-node", *arguments],
        cwd=ROOT,
        check=False,
        capture_output=True,
        text=True,
    )
    if result.returncode != 0:
        raise ValueError(f"cargo tree failed: {result.stderr.strip()}")
    return result.stdout


def main() -> int:
    try:
        normal = cargo_tree("-e", "normal", "--prefix", "none", "--format", "{p}")
        packages = {
            line.split(maxsplit=1)[0]
            for line in normal.splitlines()
            if line.strip()
        }
        missing = sorted(REQUIRED - packages)
        escaped = sorted(FORBIDDEN & packages)
        if missing or escaped:
            raise ValueError(
                f"selected node dependency boundary drift: missing={missing}, forbidden={escaped}"
            )

        features = cargo_tree(
            "-e",
            "features",
            "-i",
            "aster-core",
            "--prefix",
            "none",
            "--format",
            "{p} {f}",
        )
        core_lines = [
            line
            for line in features.splitlines()
            if line.startswith("aster-core v") or line.startswith("aster-core feature ")
        ]
        if not any("reference-session" in line for line in core_lines):
            raise ValueError("aster-node no longer selects aster-core/reference-session")
        if any("sqlite-store" in line or "adapter-sdk" in line for line in core_lines):
            raise ValueError(
                "aster-node normal graph activates aster-core SQLite/adapter features"
            )
    except ValueError as error:
        print(f"selected node dependency boundary failed: {error}", file=sys.stderr)
        return 1

    print(
        "selected node dependency boundary passed: reference-session active; "
        "SQLite and legacy runtime packages absent"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
