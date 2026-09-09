#!/usr/bin/env python3
# Copyright 2026 Defense Unicorns, Inc.
# SPDX-License-Identifier: Apache-2.0
"""Apply one fixed endpoint route inside a shared container network namespace."""

from __future__ import annotations

import subprocess
import sys


def commands(role: str) -> list[list[str]]:
    if role == "node-a":
        return [
            ["ip", "address", "add", "10.77.1.2/30", "dev", "eth1"],
            ["ip", "link", "set", "eth1", "up"],
            ["ip", "route", "add", "10.77.2.0/30", "via", "10.77.1.1"],
        ]
    if role == "node-b":
        return [
            ["ip", "address", "add", "10.77.2.2/30", "dev", "eth1"],
            ["ip", "link", "set", "eth1", "up"],
            ["ip", "route", "add", "10.77.1.0/30", "via", "10.77.2.1"],
        ]
    raise ValueError("unsupported network role")


def main(argv: list[str]) -> int:
    if len(argv) != 1:
        print("delivery-network-init: exactly one role is required", file=sys.stderr)
        return 2
    try:
        operations = commands(argv[0])
        for operation in operations:
            subprocess.run(operation, stdin=subprocess.DEVNULL, check=True)
    except (ValueError, OSError, subprocess.CalledProcessError):
        print("delivery-network-init: fixed network setup failed", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
