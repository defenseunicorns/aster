#!/usr/bin/env bash
#
# Build one committed Linux source snapshot and package its generated Cargo SBOMs.
set -euo pipefail

root=$(git rev-parse --show-toplevel)
cd "$root"
out="$root/target/sbom"
mkdir -p "$out"
# Never let a failed run leave an earlier bundle looking like its output.
rm -f "$out/aster-linux-x86_64.tar"
if ! git diff --quiet HEAD --; then
    echo 'Commit tracked changes before building the SBOM source snapshot.' >&2
    exit 1
fi

export CARGO_NET_OFFLINE=true
export CARGO_INCREMENTAL=0
export CARGO_TARGET_DIR="${CARGO_TARGET_DIR:-$root/target/sbom-build}"
CARGO_TARGET_DIR=$(realpath -m "$CARGO_TARGET_DIR")
target=x86_64-unknown-linux-gnu
[[ $(rustc --version) == 'rustc 1.97.1 '* ]]
[[ $(cargo cyclonedx --version) =~ (^|[[:space:]])0\.5\.9$ ]]
[[ $(cdx-ev --version) =~ (^|[[:space:]])0\.34\.0$ ]]

revision=$(git rev-parse HEAD)
stage=$(mktemp -d "$out/work.XXXXXXXX")
trap 'rm -rf "$stage"' EXIT
mkdir -p "$stage/source" "$stage/bundle"
git archive "$revision" | tar -xf - -C "$stage/source"
bundle="$stage/bundle"
cd "$stage/source"
sha256sum Cargo.lock > "$stage/Cargo.lock.sha256"
python3 tools/check-netlink-packet-core-patch.py

cargo build --frozen --release --target "$target" \
    -p aster-node -p aster-agent --bin aster --bin aster-agent
cargo cyclonedx --format json --spec-version 1.5 --describe binaries \
    --target "$target"
sha256sum -c "$stage/Cargo.lock.sha256"

cp crates/aster-node/aster_bin.cdx.json "$bundle/aster.cdx.json"
cp crates/aster-agent/aster-agent_bin.cdx.json "$bundle/aster-agent.cdx.json"
for name in aster aster-agent; do
    cp "$CARGO_TARGET_DIR/$target/release/$name" "$bundle/$name"
    "$bundle/$name" --help
    cdx-ev validate "$bundle/$name.cdx.json" --schema-type default
done

# These are acceptance checks only: never rewrite the generator's SBOMs.
python3 - "$bundle" <<'PY'
import json
from pathlib import Path
import sys

for name in ("aster", "aster-agent"):
    document = json.loads((Path(sys.argv[1]) / (name + ".cdx.json")).read_text())
    if document.get("bomFormat") != "CycloneDX" or document.get("specVersion") != "1.5":
        raise SystemExit(f"{name}: expected CycloneDX 1.5")
    if document.get("metadata", {}).get("component", {}).get("name") != name:
        raise SystemExit(f"{name}: wrong application root")
    components = document.get("components", [])
    if not components or any(not c.get("licenses") for c in components):
        raise SystemExit(f"{name}: dependency license declarations are missing")
PY

cp LICENSE "$bundle/"
{
    printf '\ncommit=%s\ntarget=%s\nprofile=release\nfeatures=package defaults\n' "$revision" "$target"
    rustc -Vv
    cargo --version
    cargo cyclonedx --version
    cdx-ev --version
} > "$bundle/BUILD.txt"
cd "$bundle"
sha256sum ./* > SHA256SUMS
sha256sum -c SHA256SUMS
tar -cf "$stage/aster-linux-x86_64.tar" .
mv "$stage/aster-linux-x86_64.tar" "$out/aster-linux-x86_64.tar"
printf 'Artifact: %s\n' "$out/aster-linux-x86_64.tar"
