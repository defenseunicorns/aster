#!/usr/bin/env python3
# Copyright 2026 Defense Unicorns, Inc.
# SPDX-License-Identifier: Apache-2.0
"""Start one nonroot, capability-free endpoint agent with one fixed peer."""

from __future__ import annotations

import os
from pathlib import Path
import re
import sys

PEER = re.compile(r"[0-9a-f]{64}@10\.77\.[12]\.2:4433=[0-9a-f]{64}")


def agent_argv(role: str, state: Path = Path("/clab/state")) -> list[str]:
    addresses = {"node-a": "10.77.1.2:4433", "node-b": "10.77.2.2:4433"}
    if role not in addresses:
        raise ValueError("unsupported agent role")
    try:
        raw = (state / "peer").read_bytes()
        peer = raw.decode("ascii").strip()
    except (OSError, UnicodeError) as error:
        raise ValueError("peer configuration is unavailable") from error
    if len(raw) > 200 or PEER.fullmatch(peer) is None:
        raise ValueError("peer configuration is malformed")
    expected_peer_ip = "10.77.2.2:4433" if role == "node-a" else "10.77.1.2:4433"
    if f"@{expected_peer_ip}=" not in peer:
        raise ValueError("peer configuration targets the wrong endpoint")
    return [
        "/usr/local/bin/aster-agent",
        "--state", str(state),
        "--mesh-bind", addresses[role],
        "--listen", "127.0.0.1:8181",
        "--mission-bundle-unprotected-reference", str(state / "mission.unprotected-reference.bundle"),
        "--client-token-file", str(state / "client.token"),
        "--peer", peer,
        "--sync-ms", "250",
    ]


def main(argv: list[str]) -> int:
    if len(argv) != 1 or os.getuid() != 10001 or os.getgid() != 10001:
        print("delivery-agent: fixed nonroot role is required", file=sys.stderr)
        return 2
    try:
        os.execv("/usr/local/bin/aster-agent", agent_argv(argv[0]))
    except (OSError, ValueError):
        print("delivery-agent: startup failed", file=sys.stderr)
        return 2
    return 2


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
