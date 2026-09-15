# Willow Arm E: data substrate, capability model, and offline Drop


## Result

Willow is now a real FOSS component candidate, not only a design oracle. The
current `willow25` 0.7.5 Rust library builds from the Codeberg repository,
passed all 289 selected upstream tests, and its implemented Drop format passed
a three-process persistent export/import/restart exercise with duplicate-import
idempotence and tamper rejection.

The buy is narrower than the whole Willow protocol family. Version 0.7.5
implements the Willow25 entry model, Meadowcap-style authorisation, grouping,
memory and persistent stores, payload-prefix storage, and Drop Format. It does
not contain an executable Confidential Sync or Willow Transfer Protocol
module. Those remain useful published protocol designs, but receive no runtime
credit here.

Most importantly, native Willow recency is ordered by wall-clock timestamp,
then payload digest, then payload length. That directly conflicts with the
requirements' causal State/Record semantics and prohibition on timestamps as
conflict arbiters. Willow can remain a strong storage, capability, Blob-stream,
offline-media, and potential sync-protocol buy. It cannot own mission State or
Record conflict semantics unless a normative operation/version profile stores
versions at distinct paths and supplies causality, sibling preservation,
annotations, and policy-controlled garbage collection.

## Exact freeze

| Surface | Freeze |
|---|---|
| Current repository | Codeberg `main` commit `9266a735b439cdfe3fec3686e105c37f888c2469`, committed 2026-08-22; local archive SHA-256 `c7a0c0dab8b8c13c54da0e24fd193b5476c202e55c10578d52fcffab8c479794` (BVB-729/BVB-734) |
| Rust library | `willow25` 0.7.5, MIT OR Apache-2.0 |
| Workspace graph | lock SHA-256 `afa5d126a742ab4d93ee95e532ace338e4c8cf11d780e6f01d6af781ce88fc13`; 180 packages: 177 registry and three local, zero git (BVB-734) |
| Upstream test result | 36 unit, 246 documentation, and seven compile-fail tests passed; log SHA-256 `1f9afd3bf8480e59db0701c80fd8e51f9977f540697100aa5a26ad4ec5b47f3c` |
| Evaluator graph | manifest `60fa3687e37fa9d0e21b55554fc707c0a5e64a2787218fda18fb5b2cac1c6cb4`; lock `a4254e926c39ff33661f3e15a907f7d1f23346eaf41b431d5f94401563ea35ed`; 161 packages: 158 registry and three local, zero git (BVB-736) |
| Evaluator | source `1e9c984ca1f0a9d84714aa6f233be3fedd780e1f439dc92abc537ee3f9658bc8`; aarch64 release binary `fa98756a5a8a9195cc18cfd7ec66cbd2cb89e55022341f5fcd68e4bd419cb46e` (BVB-737) |

The exact transitive license, target, security, and production-admission review
is not complete. The successful research build is not admission.

## What exists in FOSS today

The executable crate supplies:

- authorised entries with namespace, subspace, hierarchical path, timestamp,
  payload length, and payload digest;
- delegated read and write capabilities restricted to namespace areas;
- Areas and AreasOfInterest with entry-count and payload-size limits;
- in-memory and Fjall-backed persistent stores;
- payload-prefix storage and verifiable payload-stream primitives; and
- Willow Drop encoding, decoding, export, and import.

The registered Confidential Sync specification separately describes private
interest-overlap discovery, capability-gated partial sync, three-dimensional
range-based set reconciliation, post-reconciliation forwarding, bounded
resource handles, and verified streaming over reliable ordered byte channels.
The registered WTP specification separately describes capability-authorized
entry and contiguous payload-slice get/put, verifiable slices, compact
fingerprint/count/size responses, pagination, and request-driven
reconciliation. These are promising design purchases, but neither protocol is
implemented by the frozen crate and neither was executed.

## Executed Drop evidence

Run `drop-001` used three distinct invocations and persistent stores:

1. `export` created one authorised entry with a 36-byte payload, flushed the
   source store, and emitted a 157-byte Drop.
2. `import` opened a separate target store, imported the exact Drop twice,
   observed one exact target value, and rejected a single-byte-mutated Drop in
   a separate probe store.
3. `verify` opened the target store in a new process and retrieved the exact
   payload after restart.

The Drop SHA-256 is
`6ebe275a03dfc663335a08f7f681accf27c3a4130f2bac9f62fe4fc60781d11a`.
The export, import, and verify log hashes are respectively
`4fd62e478bf8f94bbff15e6ff282ac0e96ed1281b46ddbabd39cb4f0db2c8ed7`,
`43c5e2bf94d609516853c1e20bd44759cacd7b1207dc26f845300e3f193a4005`,
and `307df276789562b240938091c901abf3b9efa0c06665c8d6adde3dcd8897e5b4`.

This is bounded evidence for an offline-serializable exchange (DM-5.8-15),
persistent import/restart, authenticated entry validation, duplicate store
idempotence, and tamper rejection. It is not evidence for a live peer session,
the serialization of an entire interactive sync transcript, an autonomous
temporal relay, or multi-peer convergence. The current import path explicitly
rejects an incomplete partial payload slice, so Drop does not yet receive
durable partial-resume or any-peer-resume credit.

## Four-class mapping

| Required class | Credible Willow mapping | Decision |
|---|---|---|
| State | One logical key can map to a namespace/subspace/path. | **Do not use native overwrite as the arbiter.** Its timestamp-first recency violates DM-5.1-02, DM-5.2-09/10/14, and DM-5.3-01. A separate causal operation profile could store immutable versions at unique paths. |
| Event | Publisher subspace plus a sequence-bearing path, with immutable entries. | Plausible profile substrate. Per-publisher order, gap detection, and immutable-path enforcement remain ours unless another FOSS layer owns them. |
| Record | Each author/version at a distinct immutable path, joined by a logical record ID. | Native same-path pruning is unsafe for this requirement. Causal concurrency, sibling retention, conflict annotation/API, deterministic merge registration, and superseded-version policy remain missing. |
| Blob | Entry payload digest as content identity; persistent payload/prefix store; verified slice primitives; Drop or future sync transport. | Strongest fit. Content addressing, streaming, and prefix verification are plausible buys; full-size curves, durable partial state, cross-peer resume, dedup, and garbage collection remain unproved. |

Willow entries do not natively carry the mission data class, topic, scope,
priority, or TTL. Namespace, area, and path can encode some of these, but the
mapping must be normative and authenticated. Priority scheduling, expiry,
emission thresholds, relay quotas, and bridge policy remain independent
responsibilities.

## Security and lifecycle boundary

Meadowcap is valuable for fine-grained delegated read/write authority and
private-interest sync design. It is not the required intermittent mesh
membership lifecycle. The frozen profile uses Ed25519 authorisation and
WILLIAM3 payload digests. It provides neither source payload encryption nor a
mesh-membership metadata-encryption layer, NIST hybrid classical+PQ
signatures/KEM, FIPS module evidence, replay lifecycle, revocation propagation,
field rekey, downgrade protection, or zeroization.

Confidential Sync deliberately leaves channel handshake and encryption out of
scope. Even if implemented, it would need the selected source-object and
membership-security composition.

## Disposition

Advance Willow in three separable roles:

1. **Buy now for further evaluation:** the Rust entry/capability/persistent
   storage, payload-prefix, and Drop components.
2. **Implement-or-find-FOSS experiment:** a Confidential Sync implementation,
   because its private differential reconciliation and verified streaming map
   well to the requirements but are not present in 0.7.5.
3. **Protocol oracle only:** WTP until an executable implementation is frozen.

Do not adopt native Willow timestamp pruning for mission State or Record. The
comparison against p2panda should use one shared causal operation/profile and
measure whether Willow's storage/capability/Blob/Drop purchases delete enough
custom work to justify an immutable-version overlay.

## No-credit boundaries

No result here proves live sync, temporal multi-hop, duplicate/loop bounds,
priority or expiry, any-peer Blob continuation, IP/NAT, BTLE, tiny-MTU framing,
broadcast, discovery, cross-transport operation, source or metadata
confidentiality, membership lifecycle, hybrid-PQ/FIPS, C ABI/bindings,
independent interoperability, resource curves, governance admission, or
production readiness. Raw registered source, archives, specification pages,
dependency caches, build output, stores, Drop bytes, and logs remain locally
preserved and ignored.
