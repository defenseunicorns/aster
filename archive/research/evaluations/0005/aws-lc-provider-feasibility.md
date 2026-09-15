# AWS-LC hybrid-provider feasibility

> Historical experiment summary. Detailed harnesses, raw logs, and execution
> records are retained separately; only linked public summaries and active tests
> are maintained in this repository.


**Date:** 2026-08-22  
**Decision:** **BUY as a primitive-provider candidate; do not treat it as a
security profile or a FIPS result.**

## Question and evidence boundary

The requirements mandate NIST cryptography, hybrid classical plus
post-quantum signatures and key establishment, explicit downgrade protection,
and vetted implementations. This spike asks only whether one maintained Rust
provider can supply the four primitive families through usable APIs.

The exact `aws-lc-rs` 1.18.0 release is registered by BVB-046. Its KEM and
post-quantum signature source surfaces are registered by BVB-484 and BVB-485.
The exact crate archives and every transitive version used here are a subset of
the BVB-695 registered Hardy graph, which was acquired and executed under
BVB-702. No new external source or network endpoint was consulted.

The harness, lock, result, and receipts are under
archived `aws-lc-1.18.0` (archived).
Raw sources, caches, build output, binaries, and execution logs remain local
and candidate-ignored. BVB-710 registers the exact lock, harness, binary, and
bounded execution result. It remains research-only and is not a normalized
production-admission result.

## Executed result

The exact locked graph built and ran offline on `aarch64-apple-darwin`. One
provider build supplied:

- P-256 ECDSA with SHA-256 and fixed-width signatures;
- ML-DSA-65 signatures;
- P-256 ECDH;
- ML-KEM-768; and
- HKDF-SHA-256 for test-only transcript-bound combination.

The positive hybrid-signature case verified only when both signatures were
present. Ten negative cases rejected a missing component, altered content,
changed version/suite/publisher, tampered signature, or wrong verification key.

The positive hybrid-establishment case produced the same combined test key on
both sides. Seven negative cases rejected a missing component or malformed
P-256 key, or produced a different derived key after version/suite/public-key/
ciphertext alteration. A tampered ML-KEM ciphertext followed implicit rejection
and returned a different shared secret rather than a provider error; the
transcript-bound derived key therefore mismatched. A real protocol still needs
authenticated key confirmation and must not infer ciphertext validity from the
KEM call alone.

Observed release-run values are decision data, not gates:

| Surface | Observed value |
|---|---:|
| P-256 public key / signature | 65 / 64 bytes |
| ML-DSA-65 public key DER / signature | 1,974 / 3,309 bytes |
| ML-KEM-768 public key / ciphertext | 1,184 / 1,088 bytes |
| Hybrid-signature stage | 32,611 microseconds |
| Hybrid-establishment stage | 325 microseconds |

These are one warm local run, not a benchmark or a provisional-link failure.

## Requirements credit

| Requirement area | Bounded result | Missing before final credit |
|---|---|---|
| Hybrid signatures (`DM-6-26`) | **Partial executable feasibility.** One provider signs/verifies both components and a wrapper can require both. | Published mandatory-both encoding/profile, protected object, identity/key binding, independent vectors and implementation. |
| Hybrid key establishment (`DM-6-25`) | **Partial executable feasibility.** Both shared secrets can be supplied and required by one wrapper. | Standards-backed combiner/profile, authenticated negotiation and key confirmation, cross-provider vectors, lifecycle integration. |
| Versioning/downgrade (`DM-6-29`, `DM-6-30`) | **Partial mechanism evidence.** Altered version or suite changed verification/derived-key outcome. | A complete offer/selection protocol, minimum policy, persistent rollback handling, mixed-version behavior, independent negative corpus. |
| NIST/FIPS-approved algorithms (`DM-6-24`, `DM-6-28`) | The tested primitive names map to final NIST algorithm families already registered. | Whole-profile mapping, parameter and mode freeze, operational policy, assurance/admission review. |
| No custom primitives (`DM-6-35`) | All tested primitive operations came from the provider. | The test HKDF combination is scaffolding; the final composition must adopt and review a published or explicitly specified hybrid profile without inventing primitives. |
| Vetted implementation (`DM-6-36`) | Maintained provider candidate with registered project/release/security evidence. | Exact dependency admission, audit/verification scope, target/platform evidence, vulnerability disposition, and production graph. |
| FIPS validated modules (`DM-6-27`) | **No credit.** | Exact validated module, version, approved mode, OE, service indicators, entropy path, and every operation within the certificate boundary. |

## FIPS/CMVP disposition

This harness explicitly disabled default features and selected `non-fips`, which
resolved `aws-lc-sys 0.44.0`; `aws-lc-fips-sys` is absent. The executable is
therefore not a validated-module run.

The registered evidence keeps two different facts separate:

- `aws-lc-rs` 1.17.3 is the registered AWS-LC FIPS-3 candidate pin associated
  with active certificate 5314, whose registered policy does not cover ML-DSA;
- `aws-lc-rs` 1.18.0 adds the executable ML-DSA surface shown here, while its
  FIPS-4 transition was submitted but not certified when BVB-046 was reviewed.

There is consequently no evidence that one currently validated provider
boundary covers the complete required primitive set. That does not kill the
technical provider: validated modules are a `Should`, while FIPS-approved
algorithm selection is binding. Any split validated/nonvalidated composition
must label each operation honestly and prove that no fallback is misreported.

## Exact buy/gap result

**Buy:** the safe Rust primitive APIs for P-256, ML-DSA-65, P-256 ECDH,
ML-KEM-768, HKDF, provider randomness, key parsing, and failure reporting.
This execution resolves the earlier registered uncertainty about whether
release 1.18.0 has a usable safe Rust ML-DSA boundary.

**Still custom/profile work:** mandatory-both encoding; hybrid combiner and key
confirmation; node/key/credential binding; nested payload and mesh-metadata
objects; scope membership; disconnected exclusion/rekey; durable replay state;
algorithm negotiation and rollback policy; bridge authorization; zeroization
hook and custody inventory; second implementation and conformance vectors.

The next provider experiment should be differential exchange against an
independent registered implementation using final vectors and a frozen hybrid
profile. The next system-security experiment should place a protected source
object through the already proven temporal carry arm and inspect relay memory,
APIs, storage, and packet capture. Neither should wait on a FIPS build that
cannot presently earn full-profile CMVP credit.
