#!/usr/bin/env python3
# Copyright 2026 Defense Unicorns, Inc.
# SPDX-License-Identifier: Apache-2.0
"""Fast source contract for the radio-inert BTLE authority-lock package slice."""

from pathlib import Path
import shlex


ROOT = Path(__file__).resolve().parents[1]
ANCHOR = "/run/aster-agent/btle-authority.lock"


def tmpfiles_records() -> list[list[str]]:
    lines = (ROOT / "debian/aster.tmpfiles").read_text().splitlines()
    return [shlex.split(line) for line in lines if line and not line.startswith("#")]


def shell_function(script: str, name: str) -> str:
    start = script.index(f"{name}() {{\n")
    end = script.index("\n}\n", start) + 3
    return script[start:end]


records = tmpfiles_records()
assert records == [
    ["d", "/run/aster-agent", "0755", "root", "root", "-"],
    ["f", ANCHOR, "0440", "root", "root", "-"],
    [
        "a",
        ANCHOR,
        "-",
        "-",
        "-",
        "-",
        "u::r--,u:aster:r--,g::---,m::r--,o::---",
    ],
]

postinst = (ROOT / "debian/aster.postinst").read_text()
helper = postinst.index("#DEBHELPER#")
assert shell_function(postinst, "check_btle_authority_hierarchy") == """\
check_btle_authority_hierarchy() {
    check_btle_authority_ancestor
    check_btle_authority_directory "$1"
    check_btle_authority_lock "$1"
}
"""
pre_helper = postinst.index("check_btle_authority_hierarchy allow-missing")
post_helper = postinst.index("check_btle_authority_hierarchy require-present")
assert pre_helper < helper < post_helper
assert postinst.count("check_btle_authority_hierarchy allow-missing") == 1
assert postinst.count("check_btle_authority_hierarchy require-present") == 1
assert "path=/run\n" in postinst
assert "stat -c '%u:%g:%a'" in postinst and "0:0:755" in postinst
assert "btle_authority_access_acl" in postinst
assert "btle_authority_default_acl" in postinst
assert "getfacl" in postinst and "stat -c '%u:%g:%a:%s:%h'" in postinst
assert "getfacl --access" in postinst and "getfacl --default" in postinst

control = (ROOT / "debian/control").read_text()
assert "systemd (>= 255.4), acl, adduser" in control

service = (ROOT / "debian/aster.aster-agent.service").read_text().lower()
service_directives = [line.strip() for line in service.splitlines()]
assert [line for line in service_directives if line.startswith("capabilityboundingset=")] == [
    "capabilityboundingset="
]
assert [line for line in service_directives if line.startswith("ambientcapabilities=")] == [
    "ambientcapabilities="
]
assert "restrictaddressfamilies=af_unix af_inet af_inet6 af_netlink" in service
for forbidden in (
    "aster-btle-roster",
    "af_bluetooth",
    "cap_net_admin",
    "cap_net_raw",
):
    assert forbidden not in service

install_test = (ROOT / "tools/test-deb-install.sh").read_text()
for required in (
    "assert_btle_authority_lock",
    "assert_btle_authority_ancestor",
    "assert_unsafe_directory_rejected symlink",
    "assert_unsafe_directory_rejected wrong-owner",
    "assert_unsafe_directory_rejected wrong-mode",
    "assert_unsafe_directory_rejected access-acl",
    "assert_unsafe_directory_rejected default-acl",
    "assert_unsafe_anchor_rejected symlink",
    "assert_unsafe_anchor_rejected hardlink",
    "assert_unsafe_anchor_rejected non-empty",
    "assert_unsafe_anchor_rejected wrong-acl",
    "flock -n",
    "systemd-tmpfiles --create",
):
    assert required in install_test

mise = (ROOT / "mise.toml").read_text()
assert mise.count("python3 tools/test_deb_btle_authority_package.py") == 1

print("Radio-inert Debian BTLE authority-lock source contract: OK")
