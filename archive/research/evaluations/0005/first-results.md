# Phase 0 first results: buy/delete decisions and next bakeoff

> Historical checkpoint. Later whole-stack, connectivity, security, carrier,
> Blob, component, and conformance arms supersede its future-work ordering. See
> [`final-frontier.md`](final-frontier.md) for the current research disposition.

>
> Requirements-first research synthesis using only the authoritative
> `data-mesh-requirements.md` and completed local Phase 0 reports. It neither
> admits a dependency nor selects a product architecture. Current Aster APIs,
> wires, stores, identities, ownership boundaries, and implementation effort
> receive **zero compatibility weight**.

- Evaluation date: 2026-08-22
- Requirements SHA-256: `e88bcc6c717a5175a460205fdc084aaa2e1f020a142a84087f9881677da02987`
- Evidence inputs: [`p2panda-freeze.md`](p2panda-freeze.md),
  [`p2panda-temporal-relay.md`](p2panda-temporal-relay.md),
  [`bpv7-freeze.md`](bpv7-freeze.md),
  [`group-oscore-implementation-freeze.md`](group-oscore-implementation-freeze.md),
  [`security-profile-matrix.md`](security-profile-matrix.md), and
  [`responsibility-map.md`](responsibility-map.md)
- Status: first executable results, not final selection or production admission

## Outcome first

The original “build the mesh” problem is already decomposing into buyable
responsibilities. The leading minimum-custom hypothesis is now **p2panda owning
local-first replica state and bounded temporal carry of p2panda-native operations
through eligible full replicas, with source security, membership, and
connectivity composed separately**. BPv7 is no longer presumed necessary for the
basic native temporal chain. B1 must demonstrate an incremental hard capability
or operational value without creating competing storage, retry, expiry,
deduplication, or progress owners; C remains the standards-first fallback/control.

“Delete” below means remove a bespoke implementation responsibility only to the
extent the frozen component has actually demonstrated it. It does not mean
admit the current dependency graph or award untested requirements.

| Layer/result | What is now buyable | Delete from bespoke scope now | Explicit non-credit |
|---|---|---|---|
| p2panda v0.7.1 | A candidate-native Rust vertical slice for one Event-like offline publish, SQLite persistence across restart, later direct LAN synchronization, and one A→full-replica B, B restart, B→C native-operation chain while A was absent | Do not hand-build another proof of this narrow local-first/full-replica temporal sequence or assume a second temporal queue is required for the same native operation before Arm A fails the hard corpus. | No general DTN, arbitrary routing, distinct relay-only role, payload blindness, duplicate/loop bounds, expiry, priority/quota, hostile-fault recovery, requirement security, four-class semantics, BTLE/NAT, FFI, independent interop, or production admission. |
| BPv7 + dtn7-rs | A published temporal-forwarding model and an executable daemon/oracle that persisted one bundle across relay restart and delivered it over non-overlapping contacts | Do not assume temporal store-carry-forward must be hand-rolled. Require a FOSS composition to fail the hard scenarios before authorizing bespoke dissemination state. | The executed relay was unprotected, stored payload plaintext, and did not establish application delivery, duplicate/loop bounds, priority, BPSec, or production suitability. |
| Hardy `hardy-bpv7` | An embeddable Rust BPv7/BPSec library surface whose locked default RFC 9173 graph built and passed 113 tests, including 18 RFC 9173 tests/vectors | Do not build a new BPv7/BPSec codec or default-context implementation before the Hardy composition/interoperability lane is disproven. | No Hardy daemon/temporal-relay run, application security policy, key lifecycle, hybrid profile, metadata privacy, or independent interoperability yet. |
| Group OSCORE + ACE | RFC 9594 is reusable published group-key-management semantics; the registered Group OSCORE transition text remains a useful profile input | No executable implementation responsibility can be deleted. Stop treating libOSCORE or Californium as a whole Group OSCORE/ACE solution. | Frozen libOSCORE and Californium are pairwise OSCORE only. Neither has Group OSCORE, ACE/Group Manager, countersignature processing, group rekey, durable group replay, or hybrid-PQ boundaries. Final Group OSCORE RFC publication credit also remains withheld. |
| Connectivity | Iroh, rust-libp2p, and a Quinn-based native control are credible reopened arms | Delete “compatibility with current Aster” from the scorecard. Do not preserve incumbent provider boundaries by assumption. | No connectivity winner has been executed across the required common NAT, relay, LAN, admission, path-change, and carrier-boundary corpus. |

## Composition decisions from the first results

Four ownership models remain logically possible, but they should not receive
equal near-term effort:

1. **A — p2panda-first, leading minimum-custom arm:** p2panda owns replica/local
   store semantics and has bounded executable evidence for native temporal carry
   through a subscribed full replica. Source protection, relay blindness,
   duplicates/loops, routing, expiry, policy, hostile faults, and production
   admission remain open.
2. **B1 — p2panda operations over BPv7, delta/justification arm:** test only
   whether BP buys a hard property beyond A's bounded full-replica carry while
   leaving one authoritative persistence, retry, expiry, deduplication, and
   progress model.
3. **C — BPv7 plus a thin data profile, standards fallback/control:** retain it
   when A fails a hard invariant or B1's extra state cannot be made authoritative;
   it still requires the largest custom replica/profile surface.
4. **B2 — interactive p2panda sync over BPv7:** hold outside the first bakeoff.
   It begins with the highest risk of two authoritative session, checkpoint,
   retry, and expiry machines. Reopen it only if operation carriage in B1 cannot
   satisfy a hard requirement and the need for interactive sync is demonstrated.

This is a scheduling/delete decision, not proof that B2 can never work. Lead
with A, use B1 to justify only an incremental hard capability, and retain C as
the standards-first fallback/control. A composition survives when the FOSS
semantics it buys exceed the duplicate durable state and assurance burden it
introduces.

## Currently unowned residue

These responsibilities remain custom **unless another frozen FOSS component
demonstrates ownership**. They are a search and composition backlog, not blanket
permission to hand-roll them:

- the normative mission item/profile: four data classes, immutable item identity,
  causality, deterministic State tie-break, Event gaps, Record conflict
  preservation/merge registration, Blob references, and version evolution;
- one authoritative mapping among item, p2panda operation, and BP bundle,
  including restart, duplicate, replay, expiry, fragmentation, and garbage
  collection semantics;
- topic/scope propagation, priority and TTL policy, quotas, bridge filtering,
  emission thresholds, receive-only behavior, and bounded loop/duplicate rules;
- source-to-consumer object encryption/authentication, the mesh-readable but
  outsider-opaque metadata layer, hybrid classical+PQ profiles, downgrade
  protection, durable replay, membership, intermittent revocation/rekey, and
  zeroization;
- the provider-independent carrier boundary, BTLE profile/adapter, discovery
  suppression, mission-identity binding, and owned relay/NAT policy;
- the stable C ABI, language bindings, high-level public API, packaging,
  normative conformance suite, and second implementation.

The Group OSCORE result is important here: published semantics can reduce
profile design, but without an executable maintained implementation they do not
remove a runtime, persistence, or lifecycle responsibility.

## Ordered next composition and connectivity bakeoff

### 1. Establish one architecture-neutral fixture

Use the same signed fixture identity and Event-like item in every arm. Keep the
harness outside product crates. Record item bytes/identity, all durable owners,
retry/expiry authority, process boundaries, and exact dependency graphs. No arm
may import or preserve current Aster code merely to improve its score.

### 2. Lead with A; use B1 as a differential and C as fallback/control

Run the same temporal ownership corpus in sequence rather than treating the arms
as equally unproven:

1. Start with p2panda-native A. BVB-703 already passed one plaintext functional
   chain, so force deterministic contacts and add duplicates through multiple
   peers, a cycle, expiry, and interrupted/restarted partial progress.
2. Verify stable item/source identity and idempotent application behavior, and
   enumerate which component owns persistence, retry, deduplication, expiry,
   replay, and transfer progress.
3. Run B1 with the identical fixture only to test an incremental hard behavior
   that A did not buy. A repeated plaintext A→B→C pass alone does not justify a
   second temporal layer.
4. Retain C as the standards-first fallback/control when A fails a hard invariant
   or B1 leaves competing owners without a deterministic recovery rule.

Use dtn7-rs as the external daemon/oracle and Hardy as the embeddable BP/BPSec
candidate in distinct sub-arms. Do not convert dtn7's successful unprotected
trial into Hardy, BPSec, or payload-blindness credit.

### 3. Apply the opaque-relay hard gate

Before connectivity polish, run A first with a source-protected item through the
same non-overlapping full-replica/restart path. The consumer must verify the
publisher and decrypt; B must not need or durably retain payload plaintext. Then
test restart replay/idempotence and identify all still-visible routing metadata.
The plaintext BVB-703 failure shows that protection is not automatic; it does
not prove that p2panda cannot carry an opaque protected object. Run B1 against
the identical gate only as a delta, and retain C as the fallback/control.

Hardy's RFC 9173 surface should be tested as one possible BP security layer, but
BPSec is not assumed to solve publisher/consumer identity, key lifecycle,
hybrid signatures, revocation, or the separate mesh-metadata view. Group OSCORE
does not enter this executable bakeoff until a maintained exact implementation
is registered and frozen.

### 4. Pair every surviving composition with three connectivity arms

Run each survivor without adapting it to current Aster boundaries:

| Arm | Candidate responsibility | Minimum common test |
|---|---|---|
| Iroh | Authenticated QUIC endpoints, path change, direct connectivity, local discovery, and owned connection-relay option | Manual and automatic LAN peering; direct path; named NAT topologies; self-owned relay fallback; path loss/change; no public service required for local operation |
| rust-libp2p | Swarm/session negotiation, mDNS/manual discovery, reachability, relay/direct upgrade, and multi-transport behavior | The same topology and failure corpus with an exact minimized feature graph, explicit limits, and no credit from current Aster integration |
| Native control | Quinn plus only the minimum registered discovery, NAT, and relay components required by the scenario | Same externally visible outcomes and measurements; every new state machine is counted as bespoke assurance cost |

Across all three, also test mission-identity binding, mutual authentication,
pre-auth resource bounds, reconnect/resume, silent-node non-discovery, owned
offline LAN behavior, and observable link characteristics. A connection relay
is never credited as a temporal store-and-forward relay.

IP success is not BTLE success. The chosen abstraction must allow the same item
and sync semantics to traverse a later BTLE adapter without protocol
translation, and the MVP still needs an executable BTLE carrier test.

### 5. Measure curves, then choose responsibility owners

Only after hard behavior works, sweep offline duration, link rate/loss, MTU,
dataset difference, item/blob size, node count, CPU, RAM, binary size, and idle
cost. Report breakpoints for every arm. Select owners by hard-requirement
coverage, duplicate-state cost, assurance burden, operational ownership, and
measured curves—not by resemblance to Aster.

## Hard gates versus provisional WAGs

Hard gates include offline-first publish/later sync, direct peer exchange without
mandatory infrastructure, non-overlapping store-and-forward delivery, eventual
convergence, idempotent duplicate handling, no-clock correctness, payload-blind
relays, source and metadata protection, intermittent exclusion/rekey, IP and
BTLE carrier support, pluggability, dependency policy, and independent protocol
conformance.

Every bracketed number in the requirements remains a provisional stakeholder
placeholder. This includes `[30 days]`, low-single-digit-kbps and `[50%]` loss
anchors, resource/scale/blob targets, the `[4]` priority count, and integration
size/time goals. They define **measurement curves**, not early elimination
thresholds. A composition that demonstrates 14 days rather than 30 days remains
decision data unless it violates an independently hard invariant. Exact numbers
must be normalized with stakeholders before final acceptance.

The same rule prevents two opposite errors: a candidate is not rejected for
missing an unvalidated WAG point, and it is not selected because one favorable
microbenchmark passed while hard semantics remain unknown.

## First checkpoint decision

Proceed first with **A's opaque-relay and hostile duplicate/loop ownership gate**.
Use **B1 only as a delta/justification arm** for a hard behavior A does not buy,
and retain **C as the standards-first fallback/control**. Keep B2 deferred. Pair
each surviving ownership model with **Iroh, rust-libp2p, and native Quinn-based
connectivity**. Treat p2panda, Hardy, and dtn7-rs as research components/oracles
only in the roles actually executed; retain Group OSCORE/ACE as standards inputs.
No current result admits a production dependency or selects the final architecture.
