#!/usr/bin/env python3
# Copyright 2026 Defense Unicorns, Inc.
# SPDX-License-Identifier: Apache-2.0
"""Configure and retain the fixed two-interface forwarding namespace."""

from __future__ import annotations

import subprocess
import sys

COMMANDS = [
    ["ip", "address", "add", "10.77.1.1/30", "dev", "eth1"],
    ["ip", "link", "set", "eth1", "up"],
    ["ip", "address", "add", "10.77.2.1/30", "dev", "eth2"],
    ["ip", "link", "set", "eth2", "up"],
]


def main(argv: list[str]) -> int:
    if argv != ["configure"]:
        print("delivery-wan: exact configure role is required", file=sys.stderr)
        return 2
    try:
        for command in COMMANDS:
            subprocess.run(command, stdin=subprocess.DEVNULL, check=True)
        return 0
    except (OSError, subprocess.CalledProcessError):
        print("delivery-wan: fixed forwarding setup failed", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
