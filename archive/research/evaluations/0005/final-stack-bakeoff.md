# Final integrated stack bakeoff


Status: decisive bounded research comparison complete. This report selects an
integration baseline for the next engineering phase; it does not select or
admit a production stack.

Authority: [`data-mesh-requirements.md`](../../../data-mesh-requirements.md),
SHA-256
`e88bcc6c717a5175a460205fdc084aaa2e1f020a142a84087f9881677da02987`.
Current implementation compatibility and migration cost had zero weight.

## Decision

Use **G: Iroh 1.0.3 + Negentropy 0.5.1 + redb 4.2.0 with an explicit
requirements-owned profile** as the bounded integrated research baseline.

Do not use the high-level p2panda-centered composition as the default whole
stack. Retain p2panda v0.7.1 as a conditional component, behavior oracle, and
source of operation/log/sync mechanics. Reconsider its high-level Node path
only after upstream or a separately frozen lower-level composition provides a
deterministic peer/contact surface and passes the same recovery corpus.

Keep BPv7 B1 conditional. Add it only when a named topology or policy case
demonstrates a hard result that the selected native path cannot provide and
justifies a second durable state machine.

`production_selected` is **false**.

## Why G won this comparison

The comparison used the same five opaque fixtures: the four registered
representation examples plus the 8,185-byte protected carrier. Neither arm
receives native four-class or security semantics from carrying those bytes.

| Decisive cell | A — p2panda high-level Node | G — explicit components |
|---|---|---|
| Locked/offline quality gates | Pass | Pass |
| Actual Iroh reconciliation | Partial; initial sessions worked, but the complete sequence did not | Pass |
| Separate-process restart | Pass | Pass |
| A absent, B later contacts C | Pass for the first contact | Pass |
| Pre-effect/pre-commit crash | Checkpoint reached | Recovered correctly |
| Post-commit/pre-ack crash | Checkpoint reached; final recovery did not complete | Recovered correctly |
| Complete recovery without a duplicate fixture effect | Not completed | Pass in the frozen fixture |
| Final equal-inventory duplicate no-op | Not reached | Pass |
| Evaluated-composition endpoint control | High-level Node lacks direct-address injection | Task-authored G controls the Iroh endpoint explicitly |
| Independently committed domains at the evaluated recovery node | Two: p2panda SQLite plus task-authored effect files | One task-authored redb transaction domain |

G's decisive `g-003` run converged divergent stores over authenticated Iroh,
performed a zero-item duplicate round, carried the full set to a fresh C while
A was absent, recovered from both pre-commit and post-commit/pre-ack exits, and
ended with one application effect per fixture item, without a duplicate in the
registered schedule. This is not a general exactly-once guarantee. Its 38-entry
raw manifest
validates every result file (`BVB-922`).

A made substantial progress in `a-integrated-001`: candidate-native
p2panda LogSync over Iroh moved all five operations, restart replay worked,
the first temporal B-to-C contact worked, and both crash checkpoints were
reached. Fresh B and C processes then timed out before recovery completed
(`BVB-932`). The materially different fixed-requested-port diagnostic failed
earlier: A reported send success while B's receive stream ended in
`ConnectionLost(TimedOut)` (`BVB-941`). Actual bound ports were not observable,
so that run does not prove a port-collision theory; it does preserve a
sender-success/receiver-completion asymmetry. No hidden retry was used.

The deterministic verifier checked the exact G manifest, exact A logs, and
required absent result files. Its outputs are
[`comparison-summary.json`](../../../../docs/evaluations/0005/results/stack-comparison.json)
and
[`comparison-matrix.csv`](../../../../docs/evaluations/0005/results/stack-comparison.csv)
under corrected `BVB-948`.

Endpoint control, durable-domain count, graph size, and binary size were
tie-breakers, not must-pass gates: A froze 533
packages and a 28,863,504-byte diagnostic binary; G froze 374 packages and a
10,196,752-byte binary. The decisive difference was complete recovery and
owner clarity, not size.

## Recommended bounded stack

| Responsibility | Baseline mechanism | Boundary retained by us |
|---|---|---|
| IP endpoint and authenticated transport | Iroh 1.0.3 | Mission identity binding, discovery admission, secure owned-relay operation, public/physical qualification |
| Inventory difference | Negentropy 0.5.1 | Durable session progression, object request/apply, hostile-cardinality bounds, fallback policy |
| Small durable replica/effect metadata | redb 4.2.0 | Versioned schema, migrations, quotas, compaction, corruption/disk-full policy; one transaction must own item acceptance and application-effect marker |
| Item identity | NIST-standardized SHA-256 mechanics in the current research graph | The normative identifier/profile and selected validated provider boundary |
| Normative representation | Deterministic CBOR/CDDL mechanics | Versioned four-class semantics, critical extensions, errors, negotiation, independent conformance |
| Record merge | Automerge only for topics that explicitly choose JSON-like CRDT merge | Topic policy, conflicts, non-JSON Record behavior, every other class |
| Blob storage | Ordinary content files plus small transactional checkpoints | Lifecycle, power-loss ordering, resume protocol, quotas/eviction, NIST-approved whole/chunk digest |
| Source object and metadata security | `coset` mechanics plus a replaceable provider; OpenMLS classical membership machinery | Normative hybrid profile, authority/key distribution, protected forwarding metadata, rekey/replay/rollback/zeroization, exact FIPS operation |
| Mission propagation policy | One thin common policy owner | Topics/scopes/bridges, priority, TTL, quotas, eviction and emission; no per-carrier copies |
| SDK and assurance | cbindgen, UniFFI, tracing, SBOM/license/advisory tools | Stable semantic API/ABI, redaction, packaging, target qualification and support lifecycle |

The baseline is deliberately modular, but it is not permission to create
multiple stores or retry engines. Redb owns accepted-item and effect-marker
atomicity. Negentropy owns only set-difference mechanics. Iroh owns transport
and path establishment. The requirements profile owns class, causality,
policy, security, and lifecycle semantics.

## Eliminated or narrowed paths

- **High-level p2panda whole stack:** not selected for the baseline after two
  terminal integrated attempts failed to complete the decisive sequence.
  Component/oracle status remains.
- **Interactive p2panda sync over BPv7 (B2):** stop; repeated contact waves and
  duplicate live/durable ownership did not justify the path.
- **Zenoh whole replica:** stop; the passing encrypted sibling overlay owns the
  very replica/conflict/effect semantics Zenoh was meant to buy. Retain
  routing/replication/RocksDB as conditional components only.
- **Willow, Veilid, and thin BP profile as complete stacks:** stop as current
  whole-stack candidates; retain their standards/component/oracle roles.
- **Large Blob bytes in redb:** reject; the operating-envelope run showed
  memory scaling with Blob size. Use files plus small metadata.
- **AGPL Iroh/BLE components and BUSL/GPL-transitioning SimpleBLE:** exclude
  from production dependency roles under the current license rules.

## What remains before an architecture decision can become a release decision

1. Freeze and independently implement the normative four-class profile and
   close the critical-extension defect found by the independent parser.
2. Integrate the source-object, protected-metadata, membership, rekey, replay,
   rollback, zeroization, and validated FIPS-provider lifecycle with the G
   recovery transaction.
3. Define durable reconciliation progress, bounded hostile inventory behavior,
   compaction, tombstones, disk-full/corruption and power-loss recovery.
4. Complete real two-host discovery/NAT/owned-relay failure and hard-cross
   policy; the current Patchbay result is one-kernel simulation and used an
   insecure local test relay.
5. Execute physical BTLE, radio-silence, background, energy, target-platform,
   Blob lifecycle, scale, endurance, packaging, license, and support gates.
6. Re-run the complete protected corpus against an independently built
   implementation, not merely a second parser library.

Those are release gates, not reasons to restart a broad candidate survey. The
next research should harden and independently verify this baseline, while
keeping p2panda and BPv7 as differential controls for any claimed behavior.
