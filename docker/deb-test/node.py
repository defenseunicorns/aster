#!/usr/bin/env python3
# Copyright 2026 Defense Unicorns, Inc.
# SPDX-License-Identifier: Apache-2.0
"""Disposable reference provisioning and direct launch of packaged agents."""
import json
import os
from pathlib import Path
import pwd
import re
import shutil
import subprocess
import sys

from aster_lan_mvp import create_token_file


def initialize():
    roots = [Path("/nodes/a"), Path("/nodes/b")]
    if any(list(root.iterdir()) for root in roots):
        raise ValueError("refusing to overwrite existing node state")
    result = subprocess.run(
        ["/usr/bin/aster", "playground-init", "--nodes", "2", "--root", "/seed/mission"],
        check=True, capture_output=True, text=True,
    )
    identities = {}
    for line in result.stdout.splitlines():
        if line.startswith("PLAYGROUND_NODE "):
            fields = dict(item.split("=", 1) for item in line.split()[1:])
            index = int(fields["index"])
            if index not in (0, 1) or index in identities:
                raise ValueError("invalid initializer node index")
            pair = (fields["carrier_id"], fields["mission_id"])
            if not all(re.fullmatch(r"[0-9a-f]{64}", value) for value in pair):
                raise ValueError("invalid initializer identity")
            identities[index] = pair
    if set(identities) != {0, 1} or identities[0][0] == identities[1][0]:
        raise ValueError("initializer did not create two distinct nodes")
    account = pwd.getpwnam("aster")
    for index, root in enumerate(roots):
        shutil.copytree(Path("/seed/mission") / f"node-{index}", root, dirs_exist_ok=True)
        create_token_file(root / "client.token")
        carrier, mission = identities[1 - index]
        address = os.environ["B_IP" if index == 0 else "A_IP"]
        (root / "peer.json").write_text(json.dumps(f"{carrier}@{address}:4433={mission}"))
        os.chmod(root, 0o700)
        for path in [root, *root.rglob("*")]:
            os.chown(path, account.pw_uid, account.pw_gid)
    os.sync()
    print("INIT status=pass nodes=2 peers=static provisioning=unprotected-reference")


def main():
    if sys.argv[1:] == ["init"]:
        initialize()
        return
    if sys.argv[1:] != ["run"]:
        raise ValueError("expected init or run")
    command = [
        "/usr/bin/aster-agent", "--state", "/state", "--mesh-bind", "0.0.0.0:4433",
        "--listen", "127.0.0.1:8181", "--mission-bundle-unprotected-reference",
        "/state/mission.unprotected-reference.bundle", "--client-token-file",
        "/state/client.token", "--sync-ms", "500",
    ]
    peers = os.environ.get("ASTER_DEB_PEERS", "1")
    if peers not in ("0", "1"):
        raise ValueError("ASTER_DEB_PEERS must be 0 or 1")
    if peers == "1":
        command.extend(["--peer", json.loads(Path("/state/peer.json").read_text())])
    os.execv(command[0], command)


if __name__ == "__main__":
    main()
