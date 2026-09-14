#!/usr/bin/env bash
# Copyright 2026 Defense Unicorns, Inc.
# SPDX-License-Identifier: Apache-2.0
#
set -euo pipefail
case "$(dpkg-architecture -qDEB_HOST_ARCH)" in
    amd64) target=x86_64-unknown-linux-gnu ;;
    arm64) target=aarch64-unknown-linux-gnu ;;
    *) echo 'Unsupported package architecture' >&2; exit 1 ;;
esac
stage=target/debian-install
metadata=target/deb-metadata
rm -rf "$stage" "$metadata"
mkdir -p "$stage/bin" "$metadata"
sha256sum Cargo.lock > "$stage/Cargo.lock.sha256"
python3 tools/check-netlink-packet-core-patch.py
cargo build --frozen --release --target "$target" \
    -p aster-node -p aster-agent -p aster-systemd-credentials \
    --bin aster --bin aster-agent --bin aster-credential-admin
cargo cyclonedx --format json --spec-version 1.5 --describe binaries --target "$target"
sha256sum -c "$stage/Cargo.lock.sha256"
for pair in aster-node:aster aster-agent:aster-agent aster-systemd-credentials:aster-credential-admin; do
    crate=${pair%%:*}
    name=${pair#*:}
    install -m 0755 "$CARGO_TARGET_DIR/$target/release/$name" "$stage/bin/$name"
    cp "crates/$crate/${name}_bin.cdx.json" "$metadata/$name.cdx.json"
    if [ "$name" != aster-credential-admin ]; then
        "$stage/bin/$name" --help >/dev/null
    fi
    cdx-ev validate "$metadata/$name.cdx.json" --schema-type default
done
python3 - "$metadata" <<'PY'
import json
from pathlib import Path
import sys
for name in ("aster", "aster-agent", "aster-credential-admin"):
    bom = json.loads((Path(sys.argv[1]) / (name + ".cdx.json")).read_text())
    assert bom.get("bomFormat") == "CycloneDX" and bom.get("specVersion") == "1.5"
    assert bom.get("metadata", {}).get("component", {}).get("name") == name
    assert bom.get("components") and all(c.get("licenses") for c in bom["components"])
PY
cp LICENSE THIRD_PARTY_NOTICES.md "$metadata/"
{
    printf '\n'
    printf 'source_identity=working tree; this record is not a source attestation\n'
    printf 'target=%s\nfeatures=package defaults\nprofile=release\n' "$target"
    sha256sum Cargo.lock
    rustc -Vv
    cargo --version
    cargo cyclonedx --version
    cdx-ev --version
    dpkg-query -W -f='${Package}=${Version}\n' libc6 debhelper
} > "$metadata/BUILD.txt"
