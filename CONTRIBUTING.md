# Contributing to Aster

## Local verification

Install the exact development tools declared in `mise.toml`, then run the
complete local gate:

```sh
mise install
mise run check
```

The gate checks formatting, strict Clippy warnings, all workspace tests, the C
and C++ headers, the Rust conformance runner, the Python wire oracle and
bindings, and the Go bindings.

Run the bounded hostile-input campaigns when changing parsers, framing,
envelopes, fragmentation, or related limits:

```sh
cargo install cargo-fuzz --version 0.13.2 --locked
rustup toolchain install nightly-2026-08-18 --profile minimal
mise run fuzz-smoke
```

## Troubleshooting stale Cargo lockfiles

If the `Cargo lockfiles` CI check reports that a lockfile needs updating but
`--locked` was passed, inspect the failing manifest and the PR's dependency
changes. A shared workspace pin can affect independently locked graphs, and a
Dependabot update may leave one of their lockfiles stale.

Use Cargo to update the affected resolution. For example, after the workspace
pin moves from `aes-gcm` 0.11.0 to 0.11.1, a stale fuzz lockfile can be refreshed
with:

```sh
cargo update --manifest-path fuzz/Cargo.toml -p aes-gcm@0.11.0 --precise 0.11.1
```

Adapt the manifest, currently locked package version, and target version to the
actual update. Cargo manages the resolution and registry checksums; do not edit
checksums by hand. A compiler or dependency-resolution conflict needs its own
investigation rather than a lockfile-only repair. The Compose workflow policy
hash is a separate mechanism.

Review the affected lockfile diff, including transitive changes, then run:

```sh
sh tools/check-cargo-lockfiles.sh
mise run check
```

Run focused tests for the updated dependency as well. Commit the affected
lockfile with the manifest change or in the same dependency PR; independent
graphs do not need identical dependency sets.

## Change discipline

- Keep `Cargo.lock` and `fuzz/Cargo.lock` synchronized with intentional manifest
  changes. Run `sh tools/check-cargo-lockfiles.sh` to validate all committed Cargo
  graphs without regenerating their lockfiles. Their dependency sets may differ.
- Preserve wire compatibility or update the versioned protocol, conformance
  vectors, and compatibility tests in the same change.
- Add deterministic regression tests for every corrected defect.
- Do not commit credentials, mission data, local environment files, build
  output, fuzz crashes, or generated binaries.
- Keep pull requests narrowly scoped and explain security, compatibility,
  resource, and migration effects.

All GitHub Actions execute untrusted pull requests without repository secrets
and with a read-only token. See `docs/validation/ci.md` before changing workflow files or
tool pins.
