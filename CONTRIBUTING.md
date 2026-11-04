# Contributing to Aster

## Local verification

On Linux, install `pkg-config` and the D-Bus development headers used by the
evaluation-only BlueZ adapter (`libdbus-1-dev` on Ubuntu/Debian). Then install
the exact development tools declared in `mise.toml` and run the complete local
gate:

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
