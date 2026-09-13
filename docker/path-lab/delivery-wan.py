#!/usr/bin/env python3
# Copyright 2026 Defense Unicorns, Inc.
# SPDX-License-Identifier: Apache-2.0
"""Apply the fixed impairment to both IP-resolved WAN egress interfaces."""
from __future__ import annotations

import json
import re
import sys
from aster_path_delivery import _run_command, _strict_json, ExecutionError


def configure(run=_run_command):
    for segment in (1, 2):
        run(["ip", "address", "add", f"10.77.{segment}.1/29", "dev", f"wan{segment}"], 5)
        run(["ip", "link", "set", "dev", f"wan{segment}", "up"], 5)
    addresses = _strict_json(run(["ip", "-j", "address", "show"], 5), "wan-address")
    if (not isinstance(addresses, list) or any(
            not isinstance(row, dict) or not isinstance(row.get("ifname"), str)
            or not isinstance(row.get("addr_info"), list)
            or any(not isinstance(info, dict) for info in row["addr_info"])
            for row in addresses)):
        raise ExecutionError("wan-address")
    result = []
    for ip in ("10.77.1.1", "10.77.2.1"):
        names = [row["ifname"] for row in addresses
                 if any(info.get("local") == ip for info in row.get("addr_info", []))]
        if len(names) != 1 or re.fullmatch(r"[a-zA-Z0-9_.-]{1,15}", names[0]) is None:
            raise ExecutionError("wan-interface")
        interface = names[0]
        if any(row["interface"] == interface for row in result):
            raise ExecutionError("wan-interface-shared")
        run(["tc", "qdisc", "replace", "dev", interface, "root", "netem", "limit", "1000",
             "delay", "40ms", "5ms", "loss", "1%", "rate", "100mbit"], 5)
        raw = run(["tc", "qdisc", "show", "dev", interface], 5)
        text = " ".join(raw.decode("ascii").split())
        if re.fullmatch(
            r"qdisc netem [0-9a-f]+: root (?:refcnt [0-9]+ )?limit 1000 "
            r"delay 40ms 5ms loss 1% rate 100Mbit\s*", text
        ) is None:
            raise ExecutionError("netem-readback")
        result.append({"address": ip, "interface": interface, "delay": "40ms", "jitter": "5ms",
                       "packet_loss": 1.0, "rate": 100000, "limit": 1000})
    return result


def main(argv: list[str]) -> int:
    if argv != ["configure"]:
        print("delivery-wan: role-invalid", file=sys.stderr)
        return 2
    try:
        print(json.dumps(configure(), sort_keys=True))
        return 0
    except (OSError, ValueError, TypeError, KeyError, ExecutionError):
        print("delivery-wan: configure-failed", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
