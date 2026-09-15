# t_cose 1.2.0 source-object freeze

> Historical experiment summary. Detailed harnesses, raw logs, and execution
> records are retained separately; only linked public summaries and active tests
> are maintained in this repository.


**Date:** 2026-08-22

**Decision:** **NO-GO as the complete source-object/hybrid lane; retain only as
a classical COSE_Sign1 component or oracle.**

## Evidence gate

BVB-711 preregistered the exact release page and archive before consultation.
The release resolves to tag `v1.2.0`, commit
`98e34ed6403f01e1779fcfe84debc7c4dd6ed75f`, released
2026-05-05T19:06:08Z. The downloaded archive SHA-256 is
`938cf63064cb3356713ece55ab7e6252bed08d3555978ae6277f17bc4ac7f7bb`.
The source carries BSD-3-Clause and a private vulnerability-reporting policy.

Raw pages, archives, and extracted source remain locally ignored under
archived `t-cose-1.2.0` (archived).
No dependency, registry, or additional upstream endpoint was consulted. No
build was attempted because the decisive required surfaces are absent and the
dependency graph is not registered.

## Exact implementation verdict

| Required source-object surface | Exact v1.2.0 result | Disposition |
|---|---|---|
| COSE_Sign1 classical signing/verifying | Present, with C sign/verify APIs and OpenSSL or MbedTLS/PSA adapters. | Buyable bounded component/oracle after graph/build evidence. |
| COSE_Sign with multiple signatures | **Absent.** Public headers and compiled sources are Sign1-only. | Cannot encode or enforce the required mandatory-both classical+PQ signature as a native multi-signature object. |
| Countersignatures/custom protected headers | **Absent by documented 1.x limitation.** | Required identity/profile binding would need another object/profile layer or replacement. |
| COSE_Encrypt/Encrypt0, recipients, AEAD | **Absent.** | Cannot own source encryption or the inner/outer confidentiality layers. |
| ML-DSA algorithm/provider boundary | **Absent.** Constants and adapters are classical signature/hash only. | The executed AWS-LC provider cannot be substituted through the existing adapter without new algorithm and API work. |
| ML-KEM/hybrid establishment | **Absent and outside this Sign1 component.** | Separate key lifecycle/profile remains required. |
| Rust API/FFI | C API only; no Rust binding in the archive. | Rust wrapper and ownership/error review would be custom. |
| Exact reproducible graph | **Absent.** QCBOR is required but unpinned; OpenSSL/MbedTLS are externally selected. | Build must stop until exact QCBOR and provider graphs are registered. |
| FIPS/CMVP | No certificate/OE/service evidence in this freeze. | No validation credit. |

The source README discusses multiple signatures and encryption only for a
separate 2.0 alpha/dev line. That is not evidence that release 1.2.0 contains
those features, nor is it an executable maturity claim for an unregistered 2.x
artifact.

## Correction to prior discovery evidence

BVB-685 preserved an upstream documentation claim that associated t_cose with
COSE_Sign and multiple-signature support while also naming v1.2.0. The exact
BVB-711 archive resolves the ambiguity: **v1.2.0 is the maintained 1.x Sign1
line and does not implement those 2.x features.** BVB-685 should receive an
append-only qualification; the earlier row must not be rewritten.

## Buy/gap outcome

**Buy from v1.2.0:** small C COSE_Sign1 encoding/verification, bounded-buffer
style, detached-content support, classical provider adapters, test corpus,
BSD-3-Clause license, and an upstream security channel.

**Still missing for the requirements:** encryption, recipients, nested
payload/member metadata objects, mandatory-both hybrid signatures, ML-DSA,
scope key distribution, membership/rekey/revocation, replay persistence,
downgrade policy, Rust integration, and a frozen dependency graph.

Nested independent Sign1 objects plus an external encryption envelope remain
technically possible, but that would assign most security semantics and
canonicalization to custom profile code. It should be scored against a modern
2.x or Rust COSE implementation rather than credited to v1.2.0.

## Re-entry gate

Do not build this release merely to reconfirm the missing surfaces. Re-enter
only for a narrow classical Sign1 oracle, after exact QCBOR and provider graphs
are registered. For the complete object lane, first register and freeze either:

1. an exact t_cose 2.x release/revision that actually contains COSE_Sign,
   multiple signatures, encryption, recipient processing, and usable provider
   hooks; or
2. an exact Rust COSE implementation release plus the executed AWS-LC
   provider, with canonical mandatory-both and nested-encryption behavior
   supplied by a published/reviewable profile.

Either candidate must then pass malformed/duplicate protected-header tests,
independent vectors, and opaque A→B restart→C temporal carry before selection.
