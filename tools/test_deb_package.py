#!/usr/bin/env python3
# Copyright 2026 Defense Unicorns, Inc.
# SPDX-License-Identifier: Apache-2.0
"""Check the actual package payload, ELF architecture and installed checksums."""
import gzip
import hashlib
import io
import json
from pathlib import Path
import shlex
import struct
import subprocess
import sys
import tarfile
import xml.etree.ElementTree as ET

package = Path(sys.argv[1])
metadata = Path(sys.argv[3]) if len(sys.argv) > 3 else Path("target/deb-metadata")
architecture = sys.argv[2]
machine = {"amd64": 62, "arm64": 183}[architecture]


def field(name):
    return subprocess.check_output(["dpkg-deb", "-f", str(package), name], text=True).strip()
assert field("Package") == "aster"
assert field("Architecture") == architecture
dependencies = field("Depends")
assert all(
    dependency in dependencies
    for dependency in ("libc6", "libdbus-1-3", "systemd", "acl", "adduser")
)
assert field("Suggests") == "bluez"
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
                 "asterctl-subscriptions", "asterctl-unsubscribe", "asterctl-blob-publish",
                 "asterctl-blob-read"):
        assert gzip.decompress(read(f"usr/share/man/man1/{page}.1.gz"))
    assert members["etc/aster/provisioning"].mode == 0o700
    assert members["var/lib/aster/provisioning-systemd"].mode == 0o700
    assert members["var/lib/aster-agent"].mode == 0o700
    assert "etc/aster/agent.json" not in members
    service_paths = [
        name
        for name in members
        if name.endswith("/systemd/system/aster-agent.service")
    ]
    assert len(service_paths) == 1
    service = read(service_paths[0]).decode().lower().splitlines()
    for directive in ("capabilityboundingset=", "ambientcapabilities="):
        assert [line for line in service if line.startswith(directive)] == [directive]
    assert service.count(
        "restrictaddressfamilies=af_unix af_inet af_inet6 af_netlink af_bluetooth"
    ) == 1
    assert service.count("systemcallarchitectures=native") == 1
    assert service.count("loadcredentialencrypted=aster-btle-roster") == 1
    assert not any(
        value in "\n".join(service)
        for value in ("cap_net_admin", "cap_net_raw")
    )
    bluez_policy = ET.fromstring(read("usr/share/dbus-1/system.d/aster-bluez.conf"))
    aster_policies = [
        policy for policy in bluez_policy.findall("policy")
        if policy.attrib == {"user": "aster"}
    ]
    assert len(aster_policies) == 1
    rules = [(rule.tag, rule.attrib) for rule in aster_policies[0]]
    assert rules == [
        ("deny", {"send_destination": "org.bluez", "send_type": "method_call"}),
        *[
            (
                "allow",
                {
                    "send_destination": "org.bluez",
                    "send_interface": interface,
                    "send_member": member,
                    "send_type": "method_call",
                },
            )
            for interface, member in (
                ("org.freedesktop.DBus.ObjectManager", "GetManagedObjects"),
                ("org.freedesktop.DBus.Properties", "Get"),
                ("org.bluez.Adapter1", "SetDiscoveryFilter"),
                ("org.bluez.Adapter1", "StartDiscovery"),
                ("org.bluez.Adapter1", "StopDiscovery"),
                ("org.bluez.LEAdvertisingManager1", "RegisterAdvertisement"),
                ("org.bluez.LEAdvertisingManager1", "UnregisterAdvertisement"),
            )
        ],
    ]
    assert not any(
        name.startswith(("etc/polkit-1/", "usr/share/polkit-1/"))
        for name in members
    )
    packaged_tmpfiles = read("usr/lib/tmpfiles.d/aster.conf").decode().splitlines()
    packaged_tmpfiles = [
        shlex.split(line)
        for line in packaged_tmpfiles
        if line and not line.startswith("#")
    ]
    assert packaged_tmpfiles == [
        ["d", "/run/aster-agent", "0755", "root", "root", "-"],
        ["f", "/run/aster-agent/btle-authority.lock", "0440", "root", "root", "-"],
        [
            "a",
            "/run/aster-agent/btle-authority.lock",
            "-",
            "-",
            "-",
            "-",
            "u::r--,u:aster:r--,g::---,m::r--,o::---",
        ],
    ]
    assert not any("non-production" in name or name.endswith(".bundle") for name in members)

print("Package payload, manual page, ELF architecture, external SBOMs and checksums: OK")
