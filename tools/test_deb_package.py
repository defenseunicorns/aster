#!/usr/bin/env python3
# Copyright 2026 Defense Unicorns, Inc.
# SPDX-License-Identifier: Apache-2.0
"""Check the actual package payload, ELF architecture and installed checksums."""
import gzip
import hashlib
import io
import json
from pathlib import Path
import struct
import subprocess
import sys
import tarfile

package = Path(sys.argv[1])
metadata = Path(sys.argv[3]) if len(sys.argv) > 3 else Path("target/deb-metadata")
architecture = sys.argv[2]
machine = {"amd64": 62, "arm64": 183}[architecture]
def field(name):
    return subprocess.check_output(["dpkg-deb", "-f", str(package), name], text=True).strip()
assert field("Package") == "aster"
assert field("Architecture") == architecture
assert "libc6" in field("Depends") and "systemd" in field("Depends")
archive = subprocess.check_output(["dpkg-deb", "--fsys-tarfile", str(package)])
with tarfile.open(fileobj=io.BytesIO(archive)) as tar:
    members = {m.name.removeprefix("./"): m for m in tar.getmembers()}
    def read(path):
        member = members[path]
        assert member.isfile(), path
        return tar.extractfile(member).read()
    for name, directory in (("aster", "usr/bin"), ("aster-agent", "usr/bin"), ("asterctl", "usr/bin"),
                            ("aster-credential-admin", "usr/sbin")):
        path = directory + "/" + name
        binary = read(path)
        assert binary[:6] == b"\x7fELF\x02\x01", path
        assert struct.unpack_from("<H", binary, 18)[0] == machine, path
        assert members[path].mode & 0o111 == 0o111, path
        bom = json.loads((metadata / (name + ".cdx.json")).read_text())
        assert bom["metadata"]["component"]["name"] == name
        assert bom["specVersion"] == "1.5"
        assert bom["components"] and all(c.get("licenses") for c in bom["components"])
    lines = (metadata / "BINARY-SHA256SUMS").read_text().splitlines()
    checked = set()
    for line in lines:
        digest, name = line.split("  ", 1)
        assert hashlib.sha256(read(name)).hexdigest() == digest, name
        checked.add(name)
    assert {"usr/bin/aster", "usr/bin/aster-agent", "usr/bin/asterctl", "usr/sbin/aster-credential-admin"} <= checked
    for page in ("asterctl", "asterctl-publish", "asterctl-query", "asterctl-subscribe",
                 "asterctl-subscriptions", "asterctl-unsubscribe"):
        assert gzip.decompress(read(f"usr/share/man/man1/{page}.1.gz"))
    assert members["etc/aster/provisioning"].mode == 0o700
    assert members["var/lib/aster/provisioning-systemd"].mode == 0o700
    assert members["var/lib/aster-agent"].mode == 0o700
    assert "etc/aster/agent.json" not in members
    assert any(name.endswith("/systemd/system/aster-agent.service") for name in members)
    assert not any("non-production" in name or name.endswith(".bundle") for name in members)
print("Package payload, manual page, ELF architecture, external SBOMs and checksums: OK")
