# Final research responsibility map


Status: post-bakeoff research responsibility baseline. The Phase 0
preregistration omissions and Phase 2 architecture-collapse gaps remain; owner
assignments follow the bounded A-versus-G result and are not production
selection or dependency admission.

Authority:
[`data-mesh-requirements.md`](../../../data-mesh-requirements.md), SHA-256
`e88bcc6c717a5175a460205fdc084aaa2e1f020a142a84087f9881677da02987`.

## One-owner rule

A layer is bought only when its executable FOSS component owns the observable
semantics, durable state, restart behavior, failure handling, and lifecycle in
the selected composition. A codec, wrapper, database, transport, or standard
buys only its narrow mechanism. Two components that both persist, retry,
expire, deduplicate, route, reconcile, or checkpoint the same object are a
cost until one is explicitly subordinate and recovery is defined.

## Responsibility boundary

| Responsibility | A — p2panda-centered owner | G — greenfield owner/control | Never duplicate or infer |
|---|---|---|---|
| Normative profile | Requirements-specific profile above p2panda operations | Same profile above explicit components | Neither p2panda nor CBOR libraries are the specification |
| Operation identity and causal envelope | p2panda immutable operation/log mechanics, profiled for the four classes | Requirements profile and selected content IDs | A CRDT document or BP bundle is not the universal item identity |
| Local durable operation state | p2panda store only when retained as a component/oracle, subject to SQLite policy/admission resolution | Selected baseline: one task-authored redb transaction domain for accepted item plus fixture-effect marker | Do not place a framework store beside redb or imply this evaluator layout is candidate-inherent |
| Replica sync and apply | p2panda sync/range mechanics remain a comparator/component surface | Selected baseline: Negentropy ID reconciliation plus explicit request/apply and bulk fallback | P2panda's bounded prune/restart metadata and final integrated recovery failed; reconciliation is not object transfer, causality, or a general exactly-once guarantee |
| Record merge | Automerge only for opted-in JSON-like Record topics | Same | Never use it for State, Event, Blob, propagation, or the default Record envelope |
| Application effect | Requirements-specific durable apply ledger/callback contract | Baseline keeps accepted fixture item and effect marker in one redb transaction | The frozen G schedule had no duplicate fixture effect; it does not prove general exactly-once application semantics |
| Blob bytes/progress | Separate profiled Blob owner; p2panda-blobs v0.7.1 receives no executable credit | Ordinary content files plus small transactional checkpoints | Do not store large Blob bytes in redb; do not bind progress to one peer/carrier |
| Blob digest | NIST-approved whole/chunk hash from the selected provider | Same | BLAKE3 is a research/control oracle only pending an explicit requirements interpretation |
| Temporal dissemination | p2panda full-replica carry unless a hard BP delta is proven | Select one authoritative temporal owner, potentially BPv7 | Connection relay is not temporal relay; adding BP under A duplicates state by default |
| BP security and lifetime | Optional only if BP is selected | Optional only if BP is selected | BPSec is not source-object security, membership, or application assurance |
| IP carrier/session | P2panda's high-level Node/Iroh path remains a comparator; direct-address injection is not exposed there | Selected baseline task-authored composition controls the Iroh endpoint directly; Quinn remains a narrow fixed control | Endpoint contrast is scoped to the evaluated compositions. BVB-904 proves 13 supported namespace pairings only; three hard-cross cases stayed relayed, and no physical/public/ISP/CGN or secure-relay result follows |
| Discovery hints | Selected carrier/platform-native advertisements and manual addresses | Same | Hints are untrusted, ephemeral, and never authorization or durable membership |
| Discovery admission/emission | One common bounded policy gate | Same | Do not implement separate unbounded hint tables per carrier |
| Carrier envelope | One common framing/reassembly/restart/offline-record layer | Same | Do not put durable downloader, policy, security, or replica semantics in each adapter |
| BTLE/platform lifecycle | Thin selected platform adapters; BlueR/TrouBLE/btleplug are candidates with holds | Same | No FOSS wrapper currently earns complete cross-platform symmetric credit |
| Source object | `coset` encoding plus replaceable provider under one normative profile | Same | The BVB-825 non-FIPS integrated shape is not a standardized hybrid profile; QUIC/TLS/BLE/BPSec cannot replace source-to-consumer protection |
| Protected forwarding metadata | One member-readable outer envelope | Same | Topic, scope, priority, and routing cannot remain plaintext or be hidden from authorized relays |
| Membership/rekey | OpenMLS classical mechanics if selected, under mission authority/profile | Same | MLS does not own mission identity, scope authority, PQ/hybrid, rollback, or zeroization |
| Replay/application acceptance | One durable item/control acceptance state plus snapshot/rollback policy | Same | COSE is stateless; MLS replay applies only inside its protocol state; BVB-825 restored snapshots reaccepted items |
| Mission propagation policy | One thin common owner above stores and below carriers | Same | Topics, Zenoh queues, BP lifetime, and Trickle each buy only a submechanism |
| High-level API and C ABI | One semantic Rust core; cbindgen/UniFFI generation; optional tonic adapter | Same | Generators do not define ownership, cancellation, threading, packaging, or evolution |
| Observability/assurance | tracing plus optional export; Cargo SBOM/license/advisory gates | Same | Logs must use a protected-field allowlist and never become protocol authority |
| Conformance | Corrected normative profile, vectors, independent implementation | Same | The Phase 5 independent parser exposed missing critical-extension rules and agreed on only 13/18; two parser libraries in one evaluator are not independent stacks |

## Composition checkpoint

| Composition | Durable owners observed | Decision |
|---|---|---|
| A | P2panda SQLite operation/store/sync plus task-authored effect files in the evaluated recovery node; separate class/security/policy/Blob state remains; prune metadata failed and two final integrated attempts did not complete the decisive sequence | **Conditional component/semantic oracle** with medium mechanism and low integrated/whole confidence |
| G | One task-authored redb accepted-item/effect transaction domain plus Negentropy and explicitly controlled Iroh endpoint; frame/classes/durable session progression remain custom | **Selected bounded research baseline** with high confidence for the frozen local recovery corpus and low production-stack confidence |
| B1 | P2panda operation/store/sync plus BP store/forward/progress and the A residuals | **Conditional** on a named hard delta; medium one-function/low whole confidence |
| B2 | Both p2panda live session state and BP temporal state | **Stop** in the current ownership model |
| C | BP temporal owner, but replica/policy/security/Blob/API owners mostly new | **Standards control**, not current finalist |
| D | Zenoh routing/storage plus a required new causal local-first overlay | **Component only**; duplicate fabric risk |
| E | Willow store/capability/Drop plus a required new causal mission profile/runtime | **Standards/component oracle** |
| F | Veilid node/DHT/store plus nearly all mission semantics | **Local lifecycle oracle only** |

## Current checkpoint

`BVB-860`, corrected by `BVB-863`, closes the p2panda Phase 1 surface map:
range and crash/replay slices pass, prune/restart metadata fails, and multiple
class/security/Blob surfaces remain absent or unwired. `BVB-859`, corrected by
`BVB-861`, closes the bounded greenfield local control. `BVB-852` closes the
4/4 manual p2panda/greenfield × Iroh/Quinn opaque-carrier matrix without
topology or reconciliation-over-carrier credit. `BVB-825`/`BVB-835` close the
bounded non-FIPS security shape while leaving normative hybrid, distribution,
rollback, custody, physical, independent, and production owners. `BVB-844`
closes Phase 5 with explicit physical/environment blocks, broadcast and
conformance failures, and license/product-surface gaps. `BVB-904` closes the
Iroh/Patchbay topology definition with 13 supported direct upgrades and three
relayed hard-cross failures.

`BVB-922` completes the G one-host integrated recovery corpus. `BVB-932` and
`BVB-941` preserve two terminal A attempts: the first reached both crash
checkpoints but did not complete fresh recovery; the second exposed sender-
success/receiver-timeout before initial receiver completion. Corrected
`BVB-948` therefore selects G as the bounded research baseline, demotes the
high-level A composition to a conditional component/oracle, and explicitly
keeps production selection false. Endpoint control and durable-domain count
are tie-breakers scoped to these task-authored evaluated compositions.

The qualitative residual bands are **high custom/high assurance** for A,
**very high custom/very high assurance** for G, and **high custom/very high
assurance** for conditional B1. These are post-hoc narrative bands, not
engineer-day estimates or substitutes for missing Phase 0 ordinal anchors.
Detailed definitions and confidence bounds are in
[`final-frontier.md`](final-frontier.md).

Phase 2 remains asymmetric: Iroh has the executable topology lane;
rust-libp2p remains a source/behavior hold and Quinn/greenfield a narrow local
control, both without a complete higher-level architecture-collapse runtime.
Excluded Proposal 0004 receives zero credit under `BVB-865`; the exposed
synthesis thread was contained and no output from it is accepted. `BVB-909`
separately records a contained final-audit allowlist failure that exposed paths
and row-width diagnostics only; the auditor made no post-exposure edit and the
affected conclusions are rejected pending clean replacement validation.

The complete disposition, component buys, and unproved gates are in
[`final-frontier.md`](final-frontier.md).
