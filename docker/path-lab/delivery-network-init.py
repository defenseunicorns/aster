#!/usr/bin/env python3
# Copyright 2026 Defense Unicorns, Inc.
# SPDX-License-Identifier: Apache-2.0
"""Apply one fixed endpoint route inside a shared container network namespace."""

from __future__ import annotations

import sys
from aster_path_delivery import _run_command, _strict_json, ExecutionError


def commands(role: str) -> list[list[str]]:
    if role not in ("node-a", "node-b"):
        raise ValueError("unsupported network role")
    local, remote = (1, 2) if role == "node-a" else (2, 1)
    return [
        ["ip", "address", "add", f"10.77.{local}.2/29", "dev", "eth0"],
        ["ip", "link", "set", "dev", "eth0", "up"],
        ["ip", "route", "replace", f"10.77.{remote}.0/29", "via", f"10.77.{local}.1"],
        ["ip", "route", "replace", "default", "via", f"10.77.{local}.1"],
    ]


def configure(role: str, run=_run_command) -> None:
    for operation in commands(role):
        run(operation, 5)
    local, remote = (1, 2) if role == "node-a" else (2, 1)
    rows = _strict_json(run(["ip", "-j", "route", "get", f"10.77.{remote}.2"], 5), "route")
    if (not isinstance(rows, list) or len(rows) != 1 or not isinstance(rows[0], dict)
            or rows[0].get("dev") != "eth0"
            or rows[0].get("gateway") != f"10.77.{local}.1"
            or rows[0].get("prefsrc") != f"10.77.{local}.2"):
        raise ExecutionError("route-readback")


def main(argv: list[str]) -> int:
    if len(argv) != 1:
        print("delivery-network-init: exactly one role is required", file=sys.stderr)
        return 2
    try:
        configure(argv[0])
    except (ValueError, OSError, ExecutionError):
        print("delivery-network-init: fixed network setup failed", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
