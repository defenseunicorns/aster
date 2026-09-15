# Candidate-neutral conformance seed

This directory contains a requirements-shaped, non-product evaluation profile
and a small golden/negative vector corpus. It intentionally does not inherit an
Aster wire, store, API, or compatibility constraint.

The executable derives the same semantic profile twice: once through a manual
`minicbor` decoder and once through `ciborium::Value`. Both paths validate
bounds and re-encode through one deterministic encoder. Their agreement is an
oracle check, not independent implementation interoperability.

The historical v0-r1 corpus is immutable. Verify it without regenerating bytes:

```sh
cd conformance/evaluation-v0
shasum -a 256 -c MANIFEST.sha256
```

Review `profile-v0.cddl`, `summary.json`, `MANIFEST.sha256`, and the report at
`archive/research/evaluations/0005/conformance-profile-seed.md`. Build products and repeated
execution evidence remain ignored locally.

The current runner source implements v0-r2 and cannot regenerate the historical
v0-r1 vectors. Revisioned copies of the original source and CDDL live under
`history/v0-r1/` and are bound by `HISTORICAL-v0-r1.sha256`; the corrected
reproduction below always targets a fresh temporary directory.

## v0-r2 extension-registry correction

The original corpus remains frozen under `vectors/`, `summary.json`, and
`MANIFEST.sha256`. Phase 5 later showed that every original positive vector
carried critical extension ID 1 even though neither the CDDL nor profile prose
defined a known-extension registry. That historical corpus is retained for
traceability and must not be used as product-wire authority.

Revision v0-r2 removes the undeclared ID 1 behavior and explicitly makes the
evaluation profile's known-extension registry empty. ID 99 remains the
noncritical positive case and becomes the critical negative case. The revised
runner has three unit tests covering all outcomes and reason-specific structural
failures, and the unchanged independently written Python parser agrees on all
18 outcomes and reaches the intended error for empty protected data,
truncation, trailing bytes, and unknown critical ID 99.

Current artifacts are `vectors-v0-r2/`, `summary-v0-r2.json`,
`independent-v0-r2.json`, and `MANIFEST-v0-r2.sha256`. They remain evaluation
evidence, not a product protocol or independent implementation.
The Rust summary identifies `corpus_revision: "v0-r2"` and an empty
`known_extension_ids` registry. The manifest also binds the unchanged Python
oracle source.

Run the repository-owned gate with:

```sh
mise run conformance-profile-v0-r2
```

That gate checks runner formatting, locked/offline tests, warning-denied
locked/offline Clippy, both historical manifests, the corrected manifest, and
a fresh byte-for-byte reproduction of the 18 revised vectors and Rust summary
against the registered JSON results. The full `mise run check` gate invokes it
as part of the required CI quality lane.

Reproduce the corrected corpus without overwriting the historical files:

```sh
profile_run_root=$(mktemp -d /tmp/aster-profile-v0-r2.XXXXXX)
CARGO_TARGET_DIR="$profile_run_root/target" \
  cargo test --locked --offline \
  --manifest-path conformance/evaluation-v0/runner/Cargo.toml
CARGO_TARGET_DIR="$profile_run_root/target" \
  cargo build --release --locked --offline \
  --manifest-path conformance/evaluation-v0/runner/Cargo.toml
"$profile_run_root/target/release/mesh-eval-conformance" \
  "$profile_run_root/vectors" > "$profile_run_root/rust-summary.json"
python3 conformance/evaluation-v0/independent_oracle.py \
  --vectors "$profile_run_root/vectors" \
  --rust-summary "$profile_run_root/rust-summary.json" \
  --output "$profile_run_root/independent.json"
```
