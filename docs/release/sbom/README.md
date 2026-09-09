# Executable SBOM workflow



This is the bounded SBOM increment of P0-3, **Produce reproducible deployable
artifacts**. It documents the evaluated workflow for the unpackaged Linux
executables `aster` (package `aster-node`) and `aster-agent` (package
`aster-agent`, using the node library). It does not complete packaging,
reproducible builds, provenance, signing, or release authorization. The
[capability roadmap](../../implementation/capability-roadmap.md) and
[requirements status](../../implementation/requirements-status.md) retain
their existing claim boundaries.

## Automated build and artifact

Run `mise run sbom` from a checkout with committed tracked changes. It uses
Rust 1.97.1, cargo-cyclonedx 0.5.9 and cdx-ev 0.34.0 from PATH. Provision the
pinned tools as described below, then run `cargo fetch --locked` once with
approved network access. The task itself runs offline and installs nothing.

The task builds a Git archive of HEAD, excluding untracked local files. It
refuses modified tracked files so BUILD.txt can identify the committed source.
Generator outputs stay in that temporary snapshot. The release target is
`x86_64-unknown-linux-gnu`, with package-default features for `aster-node` and
`aster-agent`. Existing `CARGO_TARGET_DIR` is honored; the default is
`target/sbom-build`.

The result is `target/sbom/aster-linux-x86_64.tar`, containing:

- executables `aster` and `aster-agent`;
- SBOMs `aster.cdx.json` and `aster-agent.cdx.json` from cargo-cyclonedx;
- `SHA256SUMS`, Cargo.lock and its checksum, and `BUILD.txt` with the source
  commit, compiler, Cargo, generator, validator, target and profile;
- build/generation logs, `--help` smoke outputs, project LICENSE and SCOPE.txt;
- the current vendored netlink source archive, including its patch explanation
  and upstream hash receipt. Historical pedigree edits are not applied.

The script requires both schema-valid documents with the expected application
roots and nonempty dependency license declarations. Build, generation, lockfile
drift, smoke or validation failure stops it and removes any previous output
bundle. Build/generation logs remain under `target/sbom/` for diagnosis. The
archive preserves executable permissions and its files have relative checksums.
After extracting it, run `sha256sum -c SHA256SUMS`.

CI runs this same task in its separate required `sbom` job on Ubuntu 24.04.
It uploads `aster-linux-x86_64.tar` as an Actions artifact, retained for 14 days
(subject to repository policy). PR artifacts describe the checked-out test
commit and are CI results, not signed releases. No automatic release publishing
or requirement-status change is implied.

The commands below remain available as the manual equivalent and historical
pedigree-editing reference. The automated bundle preserves patch provenance as
sidecar source evidence; it does not add pedigree or executable hashes inside
the generated CycloneDX documents. Python validator transitive dependencies
and runner system packages are not fully locked by this workflow.

## SBOM generator

Use **cargo-cyclonedx 0.5.9** to produce one CycloneDX 1.5 JSON document for
`aster` and one for `aster-agent`, including declared licenses and dependency
relationships. Keep the shared Cargo.lock unchanged.

Accept the generator's **overinclusive Cargo dependency inventory** for this
increment. Workspace feature unification can include packages that the `aster` and
`aster-agent` builds do not use. In the evaluated documents, `rusqlite` and
`libsqlite3-sys` are present even though compilation of `aster` and `aster-agent`
uses `aster-core` with `reference-session` and its redb storage path. Keep those
entries rather than manually filtering the generated graph. SBOM component
presence is not proof that its code is linked into the executable.

Distribute this scope qualification with the SBOMs. Vulnerability findings for
possibly unused components require artifact-specific triage; this is not a
blanket exception for SQLite advisories. Recheck the build configuration when
sources or features change. Other workspace consumers do use SQLite.

The workflow uses stable Rust, ordinary `cargo build`, and an
unmodified cargo-cyclonedx. Nightly precursor support and local generator or
cargo-auditable patches are outside this workflow. Embedded `.dep-v0` metadata
is not required to generate these CycloneDX documents.

## Scope and tools

The evaluation target is Ubuntu 24.04 amd64, using Rust/Cargo 1.97.1 and
`x86_64-unknown-linux-gnu`. This is an agreed build target, not a general
platform-support claim. The historical evaluation ran in an Ubuntu 24.04
chroot on an Ubuntu 26.04 host and used cargo-auditable for its binaries. The stable plain-build commands
below describe the workflow; they do not change the identities of
those historical artifacts. See the [dated observation](2026-09-08-observation.md).

| Tool | Evaluated version | Role |
|---|---|---|
| [cargo-cyclonedx](https://github.com/CycloneDX/cyclonedx-rust-cargo) | 0.5.9 | Generate Cargo component/license/dependency SBOMs |
| [CycloneDX Editor/Validator](https://github.com/Festo-se/cyclonedx-editor-validator) | 0.34.0 | Apply explicit pedigree data and validate CycloneDX schemas |

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
cargo install --locked --version 0.5.9 cargo-cyclonedx
```

The editor can run on the host in an isolated Python environment, as it reads
JSON and does not build Aster. Its Python requirement is >=3.10; PyICU may
require Python/ICU development packages and a compiler. Provision those
separately if needed. In a directory for the validator:

```bash
python3 -m venv cdx-ev
cdx-ev/bin/pip install 'cyclonedx-editor-validator==0.34.0'
cdx-ev/bin/pip freeze > cdx-ev-requirements-observed.txt
```

## Build `aster` and `aster-agent`

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
export CARGO_TARGET_DIR=/build/target-sbom
export CARGO_INCREMENTAL=0

cargo build --frozen --release \
    --target x86_64-unknown-linux-gnu \
    -p aster-node -p aster-agent \
    --bin aster --bin aster-agent \
    2>&1 | tee /build/logs/build.log

for name in aster aster-agent; do
    binary="$CARGO_TARGET_DIR/x86_64-unknown-linux-gnu/release/$name"
    sha256sum "$binary"
    "$binary" --help
done
```

Default features are intentional. Do not add `--all-features` or enable
`nearby-discovery`. Explicit `--bin` options avoid unrelated/demo executables.
Record the binary SHA-256 values with the generated documents. `--help` is a
smoke check, not a node functional test or proof of bit-for-bit reproducibility.

## Generate a Cargo SBOM for each executable

Run from the same `/build/aster` snapshot, using Rust/Cargo 1.97.1:

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
`aster.cdx.json` and `aster-agent.cdx.json` for this delivery. It does not expose `-p` or
`--bin`. Its per-binary mode uses the owning package's Cargo graph, not an
analysis of linked machine code. Platform/features are inputs, but exact
agreement with the dependencies compiled for `aster` and `aster-agent` must
not be inferred from them.

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

## Deliver and interpret the SBOMs

Retain each executable, its corresponding CycloneDX document, checksums,
source revision/local-change record, Cargo.lock hash, tool versions, and build
and generation logs together. Include the inventory qualification above and
any source archive referenced by patch pedigree. Do not relabel a previous
build's checksums or SBOM as belonging to a fresh build.

License fields contain the declarations from each package's manifest. A full
license-notice bundle and review of native/toolchain licenses remain separate
release work. Use the [historical observation](2026-09-08-observation.md) only
for its dated results, including its optional binary-audit experiment; it is
not a current vulnerability scan.

## Remaining release work

- Build-only crates/procedural macros can appear as `required`. Presence in
  the Cargo SBOM is not proof their code is shipped. The accepted overinclusive
  inventory is not a post-LTO analysis of binary composition.
- Separately establish coverage of statically included Rust standard-library
  and native code. A `*-sys` crate version is not its native-library version.
  The listed SQLite crates must not be treated as evidence of native SQLite
  linkage in `aster` or `aster-agent`.
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
