# Proposal 0006 selected-stack result


## Decision

**Retain Iroh 1.0.3 + Negentropy 0.5.1 + redb 4.2.0 as the bounded engineering
baseline. Stop broad whole-stack substitution work. Do not select it for
production yet.**

The exact reference core built cleanly and the final `selected-stack-003`
corpus passed every registered primary, negative, identity, corruption, and
inventory-curve gate. The result validates a small reconciliation and recovery
core on one host over direct local Iroh. It does not validate the missing
requirements-owned semantics and release layers.

The controlling proposal is
[`Proposal 0006`](../../proposals/0006-selected-foss-reference-stack.md). The
comparison that selected this baseline is
[`final-stack-bakeoff.md`](../0005/final-stack-bakeoff.md).

## Exact build

| Item | Result |
|---|---|
| Graph | 374 packages: 373 registry + one local; zero git/path |
| Manifest | `89e411ce7a0708c7c74bf1b75681d399ac9584fc9479a914ffa9c43ad2f93c22` |
| Lock | `b2fa398834df945531513eb90d4b6b9535274613ae8083695cee4a6189874b9a` |
| Frozen evaluator source | `153e0a37e65866421209bef0d02c7509348a8864a2d55c7433a2e66a69c23a83` |
| Stable-order wrapper | `49f8865eb285e5a289275354f30753998fa576ab0d6bb9f08be80ddfa2cc4dc1` |
| Core binary | 10,196,704 bytes; `e7af0e4677e125c43615380eeb33b11304c0d3b94b5be2124bfddd1052577cb0` |
| Probe binary | 9,425,456 bytes; `1f4060edc9f0c4e18b89c0370ae8e6a8470eefa570697c7aa2707ac926b3897b` |
| Static gates | locked/offline check, warning-denied Clippy, release build: pass |

The core binary is below 10 MiB but above decimal 10 MB. The requirements use
a provisional bracketed value without fixing the unit, so this report records
the number and does not call that threshold pass or fail.

## Substantive finding caught before runtime

The frozen evaluator used a replica-local ordinal as each Negentropy item
timestamp. A shared ID could therefore receive different ordering metadata on
two partially overlapping replicas. The earlier corpus did not expose this
because its important sets were disjoint, equal, or empty-versus-full.

The selected wrapper preserves the frozen evaluator bytes but supplies stable
ordering: every ID uses timestamp zero, and upstream Negentropy orders equal
timestamps by ID. The new shifted-overlap regression started with one shared
and one unique item on each side. It passed with one item sent, one received,
310 protocol bytes, eight frames, one round, and no duplicate effect.

This stable timestamp is task-authored policy. A normative item-ordering rule
still belongs in the requirements-owned profile.

## Recovery result

| Cell | Result | Exact bounded observation |
|---|---|---|
| Divergent A/B | Pass | 3→5 and 2→5 items; 13,386 bytes; 14 frames; one round |
| Equal inventory | Pass | zero item transfer; 335 bytes; four frames; one round |
| Shifted partial overlap | Pass | one sent + one received; three exact items each |
| Producer absent B→C | Pass | five items retained and carried after A exited |
| Crash before commit | Pass | exit 77; zero items/effects after restart; full recovery |
| Crash after commit/pre-ack | Pass | exit 78; one item/effect retained; four-item recovery |
| Final no-op | Pass | zero item transfer; each fixture effect remains one |

These cells demonstrate harmless replay for the frozen fixture schedule. They
do not establish universal exactly-once external effects. The supported
contract remains at-least-once delivery plus stable IDs, deduplication, and an
application idempotency/outbox boundary.

## Negative and identity result

- Unknown tag, truncated PUT, inconsistent length, and wrong content ID were
  all rejected. None received an application acknowledgement.
- After each rejection, the valid store still contained the five exact
  identities, payloads, and one-count effects.
- A positive expected-provider control transferred all five items. On the same
  local port, a wrong expected provider then failed the cryptographic handshake
  with `UnknownIssuer` and delivered zero application frames.
- Repeating the five-item local seed inserted zero and retained five effects.
- A copy with its first 64 bytes zeroed failed closed with a redb magic-number
  mismatch; the valid source stayed unchanged during that corruption step.

Raw redb hashes changed across otherwise logical read/open cycles. This is
housekeeping-byte churn, so raw file equality is not a semantic state oracle.
Logical identity, payload, effect, and schema checks must gate recovery.

## Inventory curve

| Items | Client DB bytes | Wall seconds | Protocol bytes | Frames | Rounds | Items received |
|---:|---:|---:|---:|---:|---:|---:|
| 1 | 57,344 | 1 | 143 | 6 | 1 | 1 |
| 128 | 86,016 | 10 | 16,532 | 262 | 2 | 128 |
| 1,024 | 180,224 | 86 | 132,151 | 2,068 | 9 | 1,024 |

The curve is one-host, sequential, small-item, direct-loopback evidence. It is
not a fleet-scale, energy, endurance, hostile-cardinality, or target-platform
qualification.

## Exact evidence

- Final result: SHA-256
  `3e4f140b40f2247a5c659ef6e0f0a75648b58a305f4eec91aec7fdb7b073c09a`.
- Raw manifest: 1,256 entries, all verified; SHA-256
  `c360225d5ea862f42e4e0bef96ce3db8af720b1c12f0a35fafaffc1411407f76`.
- Curve table: SHA-256
  `6a4762fc3385f644b4d8f9344c6f15c85ae29e1e20e9749df87a3774ff6c7e55`.
- Redb byte-hash measurement table: SHA-256
  `6d5c9761530ae3f5d4e442eb1eb826f650672f347c85b954992d256bcdc6b537`.
- All network processes were READY-gated and watchdog-bounded; no timeout
  marker exists in the final run.

## What remains to build

The recommendation narrows implementation, not the requirements. The next
stages must add and separately prove:

1. a normative item/profile and class semantics plus a second independently
   implemented stack; the corrected evaluation v0-r2 corpus now has 18/18
   parser agreement, but remains explicitly non-product seed material;
2. durable reconciliation-session progression, fallback, any-peer resume, and
   hostile bounds;
3. one persistent temporal scheduler and mission propagation-policy owner;
4. source/metadata protection, membership/rekey/revocation, rollback defense,
   key custody, and exact FIPS operation;
5. streamed Blob files plus a crash-safe file↔redb checkpoint protocol;
6. public/NAT/owned-relay failure, physical BTLE, cross-carrier continuity,
   target, background, energy, scale, and endurance qualification; and
7. stable API/ABI/bindings, SBOM/license/advisory clearance, independent
   conformance, support ownership, and release evidence.

`production_selected=false` until those gates pass.
