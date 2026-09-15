# Group OSCORE + ACE executable-implementation freeze

> Historical experiment summary. Detailed harnesses, raw logs, and execution
> records are retained separately; only linked public summaries and active tests
> are maintained in this repository.


**Date:** 2026-08-22
**Decision:** **NO-GO as a whole executable Group OSCORE + ACE lane.** The frozen candidates buy two independent implementations of *pairwise* OSCORE, not Group OSCORE or ACE. Keep the standards lane open; do not mistake an implementation gap for a standards rejection.

## Scope and evidence gate

This is a bounded, requirements-first freeze. It uses only `data-mesh-requirements.md` and registered official sources BVB-676, BVB-681, BVB-683, BVB-684, and BVB-697 through BVB-699. No unregistered submodule, dependency source, external link, or registry content was consulted.

Raw clones, HTML captures, archives, dependency caches, and build output remain locally under `` (archived) but are candidate-locally ignored. Reviewable evidence is limited to:

- archived `source-freeze.tsv`
- archived `static-surface-checks.md`
- archived `build-checks.md`
- archived `verify-surfaces.sh`

The authoritative requirements capture used here has SHA-256 `e88bcc6c717a5175a460205fdc084aaa2e1f020a142a84087f9881677da02987`.

## Publication status is not implementation status

| Artifact | Standards status credited here | Implementation credit |
|---|---|---|
| ACE group key management, BVB-676 | RFC 9594 is a published Standards Track specification. | None in either frozen repository. |
| Group OSCORE semantics, BVB-698 | Draft-28 is the successful registered semantic baseline. | None in either frozen repository. |
| AUTH48 transition, BVB-697 and BVB-699 | The transition artifact labels the work RFC 10021 / July 2026, but the canonical RFC endpoints remained unavailable when registered. Final RFC publication credit is therefore withheld. | Transition text is not executable code. |

This separation is deliberate: RFC 9594 can be bought as a published protocol profile, while the Group OSCORE text can inform the bakeoff without being overstated as a successfully verified final RFC.

## Requirements that control this lane

The binding requirements for this lane are:

- source encryption and source authentication that survive relay/store-and-forward, with relays unable to read payload plaintext;
- unique provisioned identities, scope-separated read access, in-field rekeying, mesh-propagated exclusion, and a zeroization hook;
- rejection of duplicate/stale traffic, including across reboot and long disconnected intervals;
- NIST-standardized hybrid classical + post-quantum key establishment and signatures, downgrade protection, algorithm agility, and no hand-rolled primitives;
- operation between peers without a live server for ordinary sync, including intermediate-node delivery under intermittent connectivity.

Strong defaults, rather than binding kill criteria, are exploiting one-to-many delivery on broadcast media, deriving mission/scope keys from pre-placed long-term keys, and using FIPS 140-3 validated modules where available. FIPS-approved algorithms remain binding. No CMVP/FIPS module validation evidence was present in this registered source set, so none is credited.

## Exact frozen candidates

### libOSCORE

- Default branch `master` at `57846b848f01dd41b830a2fc41527790bf4553fd`, commit date 2024-11-11, described as `liboscore-v0.1.0-17-g57846b8`.
- Only main library release tag: annotated `liboscore-v0.1.0`, target `82f71c1d55615b6de2d8de5e61192c0962d69256`, dated 2024-04-17. The tag object contains a PGP signature; trust was not verified and is not credited.
- HEAD declares a Rust workspace version `0.2.0` but has no corresponding release tag. Treat HEAD as an unreleased snapshot, not release 0.2.0.
- Root and Rust workspace declare BSD-3-Clause. Transitive license/security inventory remains unverified because dependency sources were outside this registered closure.
- The repository's workspace metadata points to the canonical location recorded by BVB-684; this freeze used the BVB-683 registered mirror and did not fetch the canonical endpoint separately.

### Californium

- Default branch `main` at `745d07e8929cfaa26a05abf05e5dab3aa8d9eb1b`, commit date 2026-08-02, described as `4.0.0-M6-32-g745d07e89`.
- Supported release `3.14.0` at `9f875e597069188e274b434ad05b3d4aa3115490`; milestone `4.0.0-M6` at `a0eaf3f6c27e9076cd64a6035ef25be6efe073ef`. Its frozen security policy marks main, 4.0.0-M6, and 3.14.0 supported.
- Root license text offers EDL-1.0 or EPL-2.0. This freeze records that choice but does not substitute for a transitive license/SBOM review.

## Implementation verdict

| Required surface | libOSCORE | Californium | Verdict |
|---|---|---|---|
| Pairwise OSCORE protect/unprotect | Yes: portable C implementation and a real `no_std` Rust high-level wrapper. | Yes: Java `cf-oscore`. | Buyable pairwise building blocks, subject to normal build/dependency review. |
| Group-mode multicast protection | No Group Security Context, group-mode processing path, or multicast group test. A multicast response comment is not an implementation. | No Group Security Context or group-mode path. Californium core's generic multicast transport does not add Group OSCORE protection. | **Missing in both.** |
| Per-sender source authentication in a shared group | No signature/countersignature API or processing path. Pairwise AEAD does not implement Group OSCORE group-mode source signatures. | One COSE header-label enum value, `CounterSignature(7)`, with no signing/verifying use. | **Missing in both.** |
| Group replay state and persistence | C has a 32-entry *pairwise* replay window and Appendix B.1 persistence/recovery hooks. The Rust wrapper exports only the primitive context, not B.1. | Pairwise 32-entry replay window in an in-memory `HashMapCtxDB`; no durable adapter found. | Useful pairwise mechanisms, but **no durable per-sender group replay implementation**. |
| ACE authorization, join, and Group Manager/KDC | No ACE, Group Manager, membership, credential, join, or rekey surface. | No ACE module or Group Manager/KDC surface at HEAD, 3.14.0, or 4.0.0-M6. | **Missing in both.** |
| Group rekey and exclusion | None. | None. | **Missing in both.** |
| Disconnected group data plane | A pre-derived pairwise context can protect traffic without infrastructure; that is not a group data plane. | Same limitation for pairwise OSCORE. | **Not implemented for Group OSCORE.** |
| Hybrid-PQ provider boundary | C abstracts OSCORE AEAD/HKDF; the current Rust backend implements classical symmetric AEADs and HKDF-SHA-256 only. There is no signature, KEM, hybrid combiner, or downgrade-binding boundary. | No Group OSCORE signature/KEM surface to bind to a hybrid provider. | **Missing.** A symmetric provider seam alone does not satisfy the hybrid requirement. |
| FIPS/CMVP evidence | None in the registered source set. | None in the registered source set. | **No validation credit.** |

The Rust binding question is therefore resolved narrowly: **Rust bindings exist for libOSCORE's pairwise primitive, but Rust Group OSCORE bindings do not exist because the underlying Group OSCORE implementation does not exist.** The high-level wrapper also omits the C B.1 persistence context.

The Java-oracle question is likewise resolved: **Californium can be retained as an independent pairwise RFC 8613 oracle, but it cannot be frozen as an independent Group OSCORE or ACE oracle.**

## What the standards buy, and what remains

| Concern | Standards material buys | Exact residual gap after this freeze |
|---|---|---|
| Multicast/group confidentiality | Group OSCORE draft-28 defines CoAP group protection, including group mode over multicast. | No frozen executable implementation. The mesh item envelope and non-CoAP transport mapping also remain profile work. |
| Source authentication | Group mode digitally signs protected messages and binds sender credential/context through its countersignature construction. | No countersignature engine, credential store, or group verification path in either candidate. |
| Replay/freshness | Group OSCORE defines a Recipient Context/replay window per sender plus challenge-response recovery behavior. | Durable, crash-atomic group replay state and its Rust API are absent. Mesh-level duplicate/stale-item semantics still need binding above packet replay. |
| Authorization and key distribution | RFC 9594 defines ACE authorization with an AS and Group Manager/KDC interfaces for join, credential/key retrieval, leave, eviction, and rekey. | Neither candidate implements it. An application profile must still choose roles, algorithms, credential formats, KDC interface subset, policies, and rekey scheme. |
| Disconnected operation | Provisioned members can use held group material for the ordinary data plane without consulting the KDC for every message. | Join, missed-rekey recovery, exclusion, and current-key retrieval rely on AS/KDC interactions in RFC 9594. The requirement that exclusion propagate through the mesh under intermittent connectivity is not supplied by the frozen code or by merely adopting the RFC. |
| Hybrid PQ | The COSE-oriented design is algorithm-identified and structurally agile. | Frozen mandatory algorithms and both implementations are classical; no ML-KEM/ML-DSA hybrid profile, provider implementation, downgrade binding, or FIPS validation is present. |

The KDC trust boundary also needs explicit acceptance: group symmetric material enables a KDC holding that material to decrypt shared group-protected content. Group-mode member signatures add a separate member-origin check, but only once an actual countersignature implementation and credential-governance policy exist.

## Build result

The exact libOSCORE workspace parsed successfully offline. A compile/test with an isolated empty dependency cache stopped at its first absent Rust dependency; online resolution was forbidden. Its native test target also names additional unregistered repositories and was not run. Californium could not be built because Java/Maven were unavailable and its dependency closure was not registered.

Accordingly, this freeze awards **source-surface credit only**, not runtime/conformance credit. The negative Group OSCORE/ACE verdict is still definitive for these commits: there is no relevant code path to exercise.

## Re-entry gates for any newly registered implementation

A future candidate should be rejected early unless static inspection finds all required roles and an executable spike can demonstrate:

1. one protected multicast request accepted by multiple authorized recipients, with group confidentiality intact;
2. distinct member source authentication and rejection of a forged message from another holder of shared group material;
3. per-sender replay rejection before and after crash/restart, including atomic persistence failure tests;
4. ACE-authorized join plus Group Manager rekey/removal, with the removed member unable to consume post-rekey traffic;
5. a disconnected member missing one or more rekeys, with the exact recovery/infrastructure dependency measured rather than assumed;
6. registered hybrid classical + ML-KEM key establishment and classical + ML-DSA signatures through an explicit provider boundary, with downgrade attempts rejected;
7. zeroization of local scope material and evidence for any claimed FIPS 140-3 module boundary.

## Decision

- **Buy now:** RFC 9594's published authorization/key-management profile as a design input; pairwise libOSCORE and Californium only where a pairwise OSCORE component or oracle is actually needed.
- **Do not claim:** that either repository implements Group OSCORE, ACE, group multicast source authentication, group rekey, durable group replay, or hybrid PQ.
- **Keep open:** Group OSCORE as a standards candidate. Its implementation lane must be repopulated with a separately registered maintained implementation, or explicitly costed as custom work. The present candidates should not advance to a Group OSCORE runtime bakeoff.
