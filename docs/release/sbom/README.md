# Executable SBOM workflow



This is the bounded SBOM increment of P0-3, **Produce reproducible deployable
artifacts**. It documents the evaluated workflow for two unpackaged Linux
executables: `aster` (package `aster-node`) and `aster-agent` (package
`aster-agent`, using the node library). It does not complete packaging,
reproducible builds, provenance, signing, or release authorization. The
[capability roadmap](../../implementation/capability-roadmap.md) and
[requirements status](../../implementation/requirements-status.md) retain
their existing claim boundaries.

## Scope and tools

The evaluation target is Ubuntu 24.04 amd64, using Rust/Cargo 1.97.1 and
`x86_64-unknown-linux-gnu`. This is an agreed build target, not a general
platform-support claim. The observed host was Ubuntu 26.04; builds stayed in
the Ubuntu 24.04 chroot. See the [dated observation](2026-09-08-observation.md).

| Tool | Evaluated version | Role |
|---|---|---|
| [cargo-auditable](https://github.com/rust-secure-code/cargo-auditable) | 0.7.5 | Embed dependency metadata in each executable |
| [cargo-cyclonedx](https://github.com/CycloneDX/cyclonedx-rust-cargo) | 0.5.9 | Generate Cargo component/license/dependency SBOMs |
| [CycloneDX Editor/Validator](https://github.com/Festo-se/cyclonedx-editor-validator) | 0.34.0 | Apply explicit pedigree data and validate CycloneDX schemas |
| [cargo-audit](https://github.com/rustsec/rustsec/tree/main/cargo-audit) | Not retained in the observed run | Audit the executable's embedded data; record the version on future runs |

Keep build tools in build-environment/provenance records, rather than adding
them automatically to the delivered application's components. Installation is
an explicit operator step, through the approved package source or offline
cache. The workflow does not install tools or change host configuration.
`cargo install --locked` uses the tool's lockfile; it does not make dependency
acquisition offline or establish a fully locked Python tool environment.

Evaluated Cargo tool installation commands, inside the chroot as `builder`:

```bash
. "$HOME/.cargo/env"
export RUSTUP_TOOLCHAIN=1.97.1
cargo install --locked --version 0.7.5 cargo-auditable
cargo install --locked --version 0.5.9 cargo-cyclonedx
```

The editor can run on the host in an isolated Python environment, as it reads
JSON and does not build Aster. Its Python requirement is >=3.10; PyICU may
require Python/ICU development packages and a compiler. Provision those
separately if needed. In an operator-selected tooling directory:

```bash
python3 -m venv cdx-ev
cdx-ev/bin/pip install 'cyclonedx-editor-validator==0.34.0'
cdx-ev/bin/pip freeze > cdx-ev-requirements-observed.txt
```

## Build the two executables

Commands below use the observed chroot layout: `builder`, sources at
`/build/aster`, logs at `/build/logs`. On the host, prefix these paths with
`/srv/chroot/aster-noble-amd64`. Entering the chroot and provisioning its
dependencies are operator prerequisites, not actions performed by this guide.
Use the same reviewed source snapshot for build and SBOM generation; do not
change manifests or the lockfile between them. Record the source revision,
local changes and lockfile hash with the build log. A revision alone does not
identify uncommitted or omitted files.

```bash
. "$HOME/.cargo/env"
export RUSTUP_TOOLCHAIN=1.97.1
cd /build/aster
set -euo pipefail
mkdir -p /build/logs /build/sbom
export CARGO_TARGET_DIR=/build/target-auditable
export CARGO_INCREMENTAL=0

cargo auditable build --frozen --release \
    --target x86_64-unknown-linux-gnu \
    -p aster-node -p aster-agent \
    --bin aster --bin aster-agent \
    2>&1 | tee /build/logs/auditable-build.log

for name in aster aster-agent; do
    binary="$CARGO_TARGET_DIR/x86_64-unknown-linux-gnu/release/$name"
    sha256sum "$binary"
    readelf -SW "$binary" | grep -F '.dep-v0'
    "$binary" --help
done
```

Default features are intentional. Do not add `--all-features` or enable
`nearby-discovery`. Explicit `--bin` options avoid unrelated/demo executables.
The release profile strips symbols; `.dep-v0` survived in the observed run.
Section presence and `--help` are metadata/smoke checks, not node functional
tests or proof of bit-for-bit reproducibility.

## Generate a Cargo SBOM for each executable

Run from the same `/build/aster` snapshot, with the toolchain above selected:

```bash
sha256sum Cargo.lock > /build/sbom/Cargo.lock.before.sha256

CARGO_NET_OFFLINE=true cargo cyclonedx \
    --format json \
    --spec-version 1.5 \
    --describe binaries \
    --target x86_64-unknown-linux-gnu

sha256sum -c /build/sbom/Cargo.lock.before.sha256

mkdir -p /build/sbom/cyclonedx
cp crates/aster-node/aster_bin.cdx.json /build/sbom/cyclonedx/aster.cdx.json
cp crates/aster-agent/aster-agent_bin.cdx.json /build/sbom/cyclonedx/aster-agent.cdx.json
```

Use `set -euo pipefail` as above, so generation or lockfile-check failure stops
the sequence. The offline setting plus checksum check is not `--frozen`: the
generator does not expose `--locked`/`--frozen`, and the check detects a lockfile
change after the command. Preserve the original source/lockfile snapshot.

Version 0.5.9 generates documents for other workspace binaries too; retain
only the two named outputs for this delivery. It does not expose `-p` or
`--bin`. Its per-binary mode uses the owning package's Cargo graph, not an
analysis of linked machine code. Platform/features are inputs, but exact
agreement with the selected build units must not be inferred from them.

Licenses are manifest declarations, not an independent license-text review.
Registry checksums identify crate archives, not compiled library bytes.
`metadata.component.version` is the application's Cargo version; the document's
top-level `version` is the SBOM revision and `specVersion` is the format version.

## Record the local dependency patch

`netlink-packet-core` is reached through
`aster-node -> aster-iroh -> iroh -> netwatch`, including from `aster-agent`.
The generator identifies the local copy with a file-qualified purl. To express
its origin, keep its current `bom-ref` and add CycloneDX `pedigree`:

- Put the original crates.io component and original crate checksum in
  `ancestors`; do not add it as another runtime dependency.
- Put the actual diff in `patches`, with a short explanation in `notes`.
- Reference a retained archive of the patched source and its SHA-256. Do not
  use the upstream checksum as the checksum of the patched copy.
- Keep version `0.8.2` while that is the local manifest version; do not invent
  a patched version solely in the SBOM.

The repository already has [patch provenance](../../../third-party/netlink-packet-core-0.8.2-aster/ASTER-PATCH.md),
an upstream hash receipt, and an existing checker:

```bash
python3 tools/check-netlink-packet-core-patch.py

tar --sort=name --format=ustar --mtime=@0 \
    --owner=0 --group=0 --numeric-owner \
    -cf /build/sbom/cyclonedx/netlink-packet-core-0.8.2-aster.tar \
    -C third-party netlink-packet-core-0.8.2-aster

sha256sum /build/sbom/cyclonedx/netlink-packet-core-0.8.2-aster.tar
```

Check the source against the receipt before claiming equivalence. Preserve
permissions and archive flags when comparing repeated snapshots. A snapshot
taken after the build identifies those current files; it is not proof they
were the inputs to an earlier executable.

The [dated set-list](2026-09-08-netlink-pedigree.set.json) is the exact input
used in the observed experiment. **It is snapshot-specific, not a default for
future builds**: it includes that archive's checksum and its missing-file
qualification. For a new snapshot, prepare reviewed data from its actual
files. `cdx-ev` applies that data; it does not discover the patch history.

With the observed archive and initial SBOMs present in the working directory,
the evaluated edit/validation pattern is:

```bash
cdx-ev set aster.cdx.json \
    --from-file /build/aster/docs/release/sbom/2026-09-08-netlink-pedigree.set.json \
    --output aster.pedigree.cdx.json
cdx-ev set aster-agent.cdx.json \
    --from-file /build/aster/docs/release/sbom/2026-09-08-netlink-pedigree.set.json \
    --output aster-agent.pedigree.cdx.json

cdx-ev validate aster.pedigree.cdx.json --schema-type default
cdx-ev validate aster-agent.pedigree.cdx.json --schema-type default
```

When running the editor on the host, substitute the host-prefixed input paths
and the actual repository path to the set-list. Keep the referenced source
archive beside the edited SBOMs. In the evaluated editor invocation,
`externalReferences` was replaced: upstream `website`/`vcs` links were lost.
This limitation is retained in the observation. For future set-lists include
all references that must survive; do not assume array append behavior.

## Audit the correct binaries

Use explicit paths; `/build/aster/target/...` can contain older, non-auditable
binaries. With an operator-provisioned `cargo-audit` supporting `bin`:

```bash
cargo audit --version
cargo audit bin \
    /build/target-auditable/x86_64-unknown-linux-gnu/release/aster \
    /build/target-auditable/x86_64-unknown-linux-gnu/release/aster-agent
```

This may update RustSec and the crates.io index. Use approved network access;
record the advisory-db revision, time, audit version, output and exit status.
Do not reuse a past "no advisories reported" result as current assurance.
`yanked` warnings do not by themselves establish a vulnerability.

## Remaining release work

- Build-only crates/procedural macros can appear as `required`. Presence in
  the Cargo SBOM is not proof their code is shipped. Stable auditable metadata
  also has Cargo-metadata limitations; it is not a post-LTO inventory.
- Separately establish coverage of statically included Rust standard-library
  and native code. A `*-sys` crate version is not its native-library version.
  No SQLite defect or inclusion in these executables was established here.
- External system glibc is outside these unpackaged executable inventories;
  record runtime requirements separately. A concrete runtime-container SBOM
  includes installed system packages and their exact versions.
- The current documents do not contain the executables' SHA-256 in their root
  component. Retain artifact checksums separately until that binding is added.
- Preserve dependency/license data and graph links when editing; schema
  validity alone does not establish semantic completeness.
- Produce automatic source/build provenance, license notices, repeat-build
  comparison, signatures and package lifecycle evidence separately.

Syft 1.51.1 was evaluated against the binaries, but found no license fields;
Grant was researched, not run. Neither is required in this workflow. Switching
between SPDX and CycloneDX is not needed and can lose information. No custom
SBOM merging/enrichment code is introduced.
