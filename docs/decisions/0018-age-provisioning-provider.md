# Decision 0018: Pilot an age X25519 provisioning-artifact provider

- Status: experimental pilot contingent on required batch gates; prohibited as a production default
- Date: 2026-08-21; dependency-policy amendment 2026-10-20

## Context

The protected-provisioning boundary deliberately separated artifact
protection from Aster's mission data model and wire cryptography. Leaving that
boundary backed only by behavioral test doubles would continue to put the
correctness of an encrypted-file construction on this project if an operational
provider were later built in-house.

The age file format is a published, implementation-independent format with a
reference Go implementation and a Rust implementation. Reusing it removes a
custom file header, recipient wrapping, streaming encryption, and
authentication design from Aster. It does not remove the assurance work needed
to integrate and operate the chosen implementation safely.

## Decision

Add an isolated first-party crate, `aster-provisioning-age`, implementing only
the existing `ProvisioningProtector` and `ProvisioningUnprotector` traits. The
crate is Apache-2.0, like every other first-party Aster package. Third-party
packages retain their own declared licenses and are evaluated separately by the
dependency-policy gate.

The provider admits this exact dependency identity:

| Attribute | Admitted value |
|---|---|
| Package | crates.io `age` |
| Version | exactly `0.11.5` (current 0.11-line maintenance release, not latest series) |
| Registry checksum | `047a482d1843edf1ce76ada63183698144030fe1191bd5ddba6e41e164e0bc43` |
| Features | `default-features = false`; no explicit features |
| Upstream license | `MIT OR Apache-2.0` |
| Protector input | 1–16 classic X25519 `age1...` recipients only |
| Identity profile | 1–16 classic X25519 `AGE-SECRET-KEY-1...` identities only |
| Protected bytes | binary age-v1; 1–16 `X25519` stanzas and at most one non-scrypt extension stanza |

The crate also exact-direct-depends on `age-core` 0.11.0 with
`default-features = false`, checksum
`e2bf6a89c984ca9d850913ece2da39e1d200563b0a94b002b253beee4c5acf99`
and upstream `MIT OR Apache-2.0` licensing. `age` already brings that exact
package transitively, so making it direct adds no lockfile component. The sole
reason is age's documented custom-identity extension point: Aster inspects the
parsed recipient-stanza set before invoking identity unwrap. It requires 1–16
`X25519` stanzas, rejects `scrypt`, and permits at most one non-X25519 extension
stanza. Standard Rust age emits one mandatory GREASE/unknown stanza for
non-scrypt files, so rejecting every unknown tag would reject the provider's own
valid output. This guard bounds peer-controlled identity work without writing
an age parser or cryptographic construction.

The Aster configuration API rejects empty or over-16 recipient/identity sets and
does not accept passphrases, SSH keys, plugins, tagged hardware recipients, or
post-quantum recipient types. It uses age's streaming
encrypt/decrypt APIs inside Aster's existing one-MiB protected-artifact and
125,877-byte recovered-plaintext ceilings, requires authenticated EOF before
returning plaintext, zeroizes the partial plaintext and ciphertext buffers that
the Aster wrapper owns, and maps upstream detail to Aster's fixed redacted error
categories. It never searches the environment, loads a plugin, invokes a
subprocess, or falls back to raw `ASTRPB03` parsing. This is not a claim that
upstream age clears every internal temporary.

Interoperability must be checked in both directions against the separately
authored reference Go age implementation at exact release `v1.3.1`: the
reference must decrypt an artifact produced by the Rust provider, and the Rust
provider must decrypt an artifact produced by the reference. The provider batch
cannot be accepted unless that required gate passes. A pass is independent
implementation evidence for the outer age file only. It is not an independent
Aster mesh implementation or proof of persistent key custody. The test-only Go
helper is first-party Apache-2.0 code. Its `filippo.io/age` dependency retains
the upstream BSD-3-Clause license; `go.mod` and `go.sum` lock that separate
graph, and the harness refuses any resolved age version other than 1.3.1. An
automated receipt gate enumerates the modules actually compiled for the
canonical non-CGO Linux/amd64 oracle, permits only
Apache/BSD/MIT-compatible SPDX expressions, and binds each reviewed license
file to a SHA-256 digest. Any compiled-module, license-expression, path, or
content change fails closed.
Resolved Go module replacements are rejected before the receipt comparison, so
an alternate source cannot retain an admitted module coordinate.

The CI lane uses Go 1.26.7 and installs `govulncheck` from exact module
`golang.org/x/vuln@v1.6.0`; the audit verifies the built tool's module identity
before canonical non-CGO Linux/amd64 source-mode analysis. Reachable findings
fail the lane. Findings in imported packages without a call path remain visible
as upstream informational output and are non-blocking, matching govulncheck's
documented source-analysis semantics; Aster has no local Go vulnerability
suppression list. The live Go vulnerability database makes this audit
time-sensitive rather than hermetic.

## Total assurance cost

Rust `age` 0.11.5 describes every pre-1.0 release as beta software for testing
only, and the upstream package metadata marks maintenance as experimental. Its
repository has no detected `SECURITY.md`. That prevents production admission
under [Decision 0002](0002-dependency-admission.md), even though the published
format and separate Go implementation make a bounded interoperability pilot
valuable.

The Rust project published one moderate advisory,
`GHSA-4fg7-vxc8-qx5w`, for arbitrary binary execution through malicious plugin
names, recipients, or identities. Release 0.11.0 is affected, 0.11.1 first
shipped the fix, and the admitted 0.11.5 maintenance release includes it. The
pilot also leaves the `plugin` feature disabled and exposes only typed X25519
recipient and identity parsing, so the affected execution path is absent from
Aster's provider surface. The reference Go implementation had the equivalent
moderate plugin advisory,
`GHSA-32gq-x56h-299c`, fixed in 1.2.1; the interoperability oracle is 1.3.1.

`default-features = false` does not make the Rust dependency graph minimal. The
0.11.5 non-optional graph includes `age-core`, X25519,
ChaCha20-Poly1305, HKDF/HMAC/SHA-2, scrypt, parser, localization, and
embedded-resource packages. Several introduce parallel older versions of
cryptographic packages already used by the Aster wire provider. The exact
resolved graph is locked in `Cargo.lock`; license and RustSec checks cover it.
This larger graph, pre-1.0 API, and upstream reporting gap are accepted only
because the crate is isolated and replaceable and deletes a higher-risk custom
encrypted-file construction.

The resolved chain `age` 0.11.5 → `i18n-embed-fl` 0.9.4 → build-time
`proc-macro-error2` 2.0.1 has two explicit maintenance findings. RustSec
`RUSTSEC-2026-0173` classifies `proc-macro-error2` as unmaintained, with no
patched release; it is informational and reports no vulnerability. Current Rust
also emits future-incompatibility diagnostic `E0365`. Neither is a current build
failure: provider tests and strict Clippy pass. `Cargo.lock` fixes the
`proc-macro-error2` 2.0.1 archive checksum at
`11ec05c52be0a07b08061f7dd003e7d7092e0472bc731b4af7bb1ef876109802`.

The same compile-time localization chain reaches `i18n-config` 0.4.8 and
`basic-toml` 0.1.10. RustSec `RUSTSEC-2026-0374` classifies `basic-toml` as
unmaintained, with no patched release and no reported vulnerability. The
resolved archive is fixed in `Cargo.lock` at checksum
`ba62675e8242a4c4e806d12f11d136e626e6c8361d6b829310732241652a178a`.
Upstream `cargo-i18n` merged pull request 176, replacing `basic-toml` with the
maintained `toml` crate, but has not published that change in the admitted
`i18n-config` line. Switching Aster to an unreleased upstream revision would
replace a checksum-locked registry package with a moving source and is not an
acceptable remediation for this pilot.

The bounded pilot therefore carries `cargo-deny` ignores for exactly
`RUSTSEC-2026-0173` and `RUSTSEC-2026-0374`, and no other advisories. This does
not reclassify either package as maintained or safe for production. Both
packages execute only while building localization proc macros, their exact
registry sources and checksums are locked, and CI downloads them before running
offline validation; neither is executed in the deployed runtime. The scope gate
requires exactly one root-lock occurrence of each ignored package, with the
reviewed version, crates.io registry source, and archive checksum. It also
asserts the complete reverse graph of both packages and inspects the separately
excluded fuzz lock, preventing either workspace-wide ignore from silently
covering another version, source, archive, or consumer. Generated output is
still compiled into the dependency, so the build-time supply-chain exposure
remains. Those controls bound the exceptions; they do not erase them.
Production remains prohibited, and a compatible published upstream migration,
a narrowly maintained patch, provider replacement, or provider removal must
eliminate both exceptions before production-readiness review.

The newer Rust `age` 0.12.1 was reevaluated but is not admitted. The attempted
workspace lock selected an `ml-kem`/`kem` API combination that failed to compile
with Aster's current graph. The result applies only to that attempted lock state;
a coordinated dependency update could produce a compatible graph and would
require its own review. Independently of that failure, 0.12.1 brings
non-optional ML-KEM, P-256/HPKE, and later
recipient-profile code that this classic-X25519 pilot does not use. Version
0.11.5 is intentionally selected as the current advisory-patched 0.11-line
maintenance release with the smaller classical surface. This must not be
represented as selection of the latest Rust release series.

Memory clearing is another explicit residual. The Aster wrapper uses
`UnprotectedProvisioning`, `Zeroizing<Vec<u8>>`, and its bounded ciphertext
writer to clear allocations it owns on drop or rejection. Upstream Rust `age`
0.11.5 does not comprehensively zeroize its internal plaintext encryption buffer
or every intermediate created while decoding an X25519 identity. Consequently,
tests establish Aster-owned buffer clearing and no partial plaintext return;
they do not establish complete process-memory erasure. Crash dumps, allocator
copies, upstream temporaries, compiler copies, and operating-system paging
remain outside that claim.

There is one deliberate profile residual. The age parser identifies the
mandatory GREASE stanza only as an unknown extension, so the wrapper cannot
distinguish it from a separately meaningful unknown extension recipient. The
guard therefore permits at most one non-scrypt extension stanza alongside at
least one X25519 stanza. It never loads a plugin or invokes that extension, and
the file remains decryptable through the required X25519 stanza, but this is not
a byte-level guarantee that every incoming recipient stanza is semantically
GREASE or X25519. A future upstream API that labels GREASE explicitly should
replace this conservative allowance.

## Claims explicitly not made

- This X25519 profile is **not post-quantum secure**. The admitted Rust 0.11.5
  release contains no ML-KEM/`tagpq` support, and Go age 1.3's separate native
  hybrid `age1pq` profile is not used by this provider.
- The provider is **not FIPS 140-3 validated** and is not asserted to execute
  inside any CMVP-validated module or approved operational environment.
- An encrypted artifact is **not a persistent secret store**. The node still
  holds recovered keys in its running process, and the reference host retains a
  zeroizing plaintext bundle for backend restarts.
- The pilot is Rust-only and is not the protected-by-default C, Go, or Python
  provisioning workflow.
- Zeroization is limited to Aster-owned wrappers and buffers. Comprehensive
  clearing of upstream age internals, identity-decoding intermediates, allocator
  copies, and process memory is not claimed.
- Reference interoperability, local negative tests, dependency scanning, and
  exact pins are not an independent security audit or production authorization.

## Review and exit gates

This pilot admission expires at the first production-readiness review or any
change to the exact `age`/`age-core` pins, feature set, or
`RUSTSEC-2026-0173`/`RUSTSEC-2026-0374` disposition; continuation requires a
new recorded review.
Production use remains blocked until the unmaintained build dependency and
future-incompatibility finding are removed, there is a verified
vulnerability-reporting route or an explicitly approved maintained fork,
independent review of the integration, operational recipient issuance and
recovery, protected-by-default application paths, persistent platform or
hardware custody, reviewed handling of upstream plaintext/key intermediates,
deployment-specific memory and backup controls, and an approved
cryptographic/FIPS posture where required.

If those gates cannot be met, remove `aster-provisioning-age` without changing
the canonical bundle or application/host boundary and replace it with another
provider. No age bytes enter Aster mesh messages or the `ASTRPB03` inner format.

## Public primary sources

Accessed 2026-08-21; dependency-policy amendment sources accessed 2026-10-20:

- [age 0.11.5 Rust API and beta warning](https://docs.rs/age/0.11.5/age/)
- [crates.io sparse index record for `age`](https://index.crates.io/3/a/age)
- [Rust age 0.11.5 package manifest](https://docs.rs/crate/age/0.11.5/source/Cargo.toml.orig)
- [Rust age 0.11.5 custom identity interface](https://docs.rs/age/0.11.5/age/trait.Identity.html)
- [Rust age-core 0.11.0 package manifest](https://docs.rs/crate/age-core/0.11.0/source/Cargo.toml.orig)
- [Rust age 0.11.5 maintenance release](https://github.com/str4d/rage/releases/tag/v0.11.4)
- [Rust age 0.11.1 security-fix release](https://github.com/str4d/rage/releases/tag/v0.11.1)
- [evaluated Rust age 0.12.1 package manifest](https://raw.githubusercontent.com/str4d/rage/v0.12.1/age/Cargo.toml)
- [Rust age 0.11.5 streaming source](https://raw.githubusercontent.com/str4d/rage/v0.11.4/age/src/primitives/stream.rs)
- [Rust age 0.11.5 X25519 identity source](https://raw.githubusercontent.com/str4d/rage/v0.11.4/age/src/x25519.rs)
- [Rust age 0.11.5 utility source](https://raw.githubusercontent.com/str4d/rage/v0.11.4/age/src/util.rs)
- [Rust age-core 0.11.0 format-parser source](https://raw.githubusercontent.com/str4d/rage/v0.11.4/age-core/src/format.rs)
- [RustSec RUSTSEC-2026-0173 advisory](https://raw.githubusercontent.com/RustSec/advisory-db/main/crates/proc-macro-error2/RUSTSEC-2026-0173.md)
- [RustSec RUSTSEC-2026-0374 advisory](https://raw.githubusercontent.com/RustSec/advisory-db/main/crates/basic-toml/RUSTSEC-2026-0374.md)
- [`basic-toml` upstream archival commit](https://github.com/dtolnay/basic-toml/commit/dd2ea1df197f255a402b8990cb852ade3e37ea34)
- [`cargo-i18n` pull request 176 replacing `basic-toml`](https://github.com/kellpossible/cargo-i18n/pull/176)
- [Rust compiler error code E0365](https://doc.rust-lang.org/error_codes/E0365.html)
- [crates.io sparse index record for `ml-kem`](https://index.crates.io/ml/-k/ml-kem)
- [crates.io sparse index record for `kem`](https://index.crates.io/3/k/kem)
- [Rust age repository security status](https://github.com/str4d/rage/security)
- [Rust age plugin advisory GHSA-4fg7-vxc8-qx5w](https://github.com/str4d/rage/security/advisories/GHSA-4fg7-vxc8-qx5w)
- [C2SP age file-format specification](https://age-encryption.org/v1)
- [reference Go age 1.3.1 release](https://github.com/FiloSottile/age/releases/tag/v1.3.1)
- [reference Go age 1.3.0 profile release](https://github.com/FiloSottile/age/releases/tag/v1.3.0)
- [reference Go age 1.3.1 package documentation](https://pkg.go.dev/filippo.io/age@v1.3.1)
- [reference Go age vulnerability-reporting process](https://filippo.io/maintenance#security)
- [reference Go age plugin advisory GHSA-32gq-x56h-299c](https://github.com/FiloSottile/age/security/advisories/GHSA-32gq-x56h-299c)
- [reference Go age license](https://github.com/FiloSottile/age/blob/v1.3.1/LICENSE)
- [reference Go HPKE v0.4.0 license](https://github.com/FiloSottile/hpke/blob/v0.4.0/LICENSE)
- [Go x/crypto v0.45.0 license](https://github.com/golang/crypto/blob/v0.45.0/LICENSE)
- [Go x/sys v0.38.0 license](https://github.com/golang/sys/blob/v0.38.0/LICENSE)
- [Go 1.26.7 release](https://go.dev/doc/devel/release#go1.26.7)
- [govulncheck v1.6.0 source-analysis and exit semantics](https://pkg.go.dev/golang.org/x/vuln/cmd/govulncheck@v1.6.0)
- [Go vulnerability-database behavior](https://go.dev/doc/security/vuln/database)
