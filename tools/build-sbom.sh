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
sha256sum Cargo.lock > "$bundle/Cargo.lock.sha256"
python3 tools/check-netlink-packet-core-patch.py

cargo build --frozen --release --target "$target" \
    -p aster-node -p aster-agent --bin aster --bin aster-agent \
    2>&1 | tee "$out/build.log"
cargo cyclonedx --format json --spec-version 1.5 --describe binaries \
    --target "$target" 2>&1 | tee "$out/generate.log"
sha256sum -c "$bundle/Cargo.lock.sha256"

cp crates/aster-node/aster_bin.cdx.json "$bundle/aster.cdx.json"
cp crates/aster-agent/aster-agent_bin.cdx.json "$bundle/aster-agent.cdx.json"
for name in aster aster-agent; do
    cp "$CARGO_TARGET_DIR/$target/release/$name" "$bundle/$name"
    "$bundle/$name" --help > "$out/$name.help.txt"
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

# Preserve current vendored source and its existing patch receipts, not a dated set-list.
tar --sort=name --format=ustar --mtime=@0 --owner=0 --group=0 --numeric-owner \
    -cf "$bundle/netlink-packet-core-0.8.2-aster.tar" \
    -C third-party netlink-packet-core-0.8.2-aster
cp Cargo.lock LICENSE "$bundle/"
cp "$out/build.log" "$out/generate.log" "$out/aster.help.txt" "$out/aster-agent.help.txt" "$bundle/"
{
    printf '\ncommit=%s\ntarget=%s\nprofile=release\nfeatures=package defaults\n' "$revision" "$target"
    rustc -Vv
    cargo --version
    cargo cyclonedx --version
    cdx-ev --version
} > "$bundle/BUILD.txt"
cat > "$bundle/SCOPE.txt" <<'EOF'


These CycloneDX 1.5 files are unmodified cargo-cyclonedx output, including
manifest-declared licenses. The inventory is overinclusive: workspace feature
unification may include unused dependencies such as SQLite. Component presence
does not prove inclusion in either executable. Vulnerability findings require
artifact-specific triage; no blanket advisory exception is granted.

The application source came from the commit recorded in BUILD.txt. SHA256SUMS
binds these files as a bundle; it is not signed provenance or proof of
reproducible builds. This is a CI build, not a release authorization.

The netlink source archive contains the actual vendored snapshot, ASTER-PATCH.md
and upstream hash receipt. This workflow does not apply the historical pedigree
set-list or add that archive's pedigree/hash to the generated SBOM components.
Full native/Rust-std coverage, license notices and release packaging remain open.
EOF
cd "$bundle"
sha256sum ./* > SHA256SUMS
sha256sum -c SHA256SUMS
tar -cf "$stage/aster-linux-x86_64.tar" .
mv "$stage/aster-linux-x86_64.tar" "$out/aster-linux-x86_64.tar"
printf 'Artifact: %s\n' "$out/aster-linux-x86_64.tar"
