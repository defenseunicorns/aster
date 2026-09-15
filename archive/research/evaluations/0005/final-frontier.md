# Requirements-first FOSS architecture frontier


Status: every currently scoped research arm has a registered disposition, but
Proposal 0005 is not fully executed: Phase 0 lacks its preregistered
time/ordinal controls and Phase 2 contains source-accounted rather than executed
architecture-collapse lanes. No production architecture or dependency is
selected or admitted.

Sole product authority:
[`data-mesh-requirements.md`](../../../data-mesh-requirements.md), version 0.1,
SHA-256
`e88bcc6c717a5175a460205fdc084aaa2e1f020a142a84087f9881677da02987`.
Existing implementation, compatibility, migration cost, and current module
boundaries have zero selection weight. Bracketed quantities were measured as
curves and never used as automatic eliminators.

## Outcome

No evaluated FOSS composition is a complete mesh to adopt wholesale. There is,
however, enough FOSS to avoid hand-building most mechanics.

The decisive integrated bakeoff has narrowed the frontier. **G, the explicit
Iroh + Negentropy + redb composition, is the bounded research baseline.** It
completed reconciliation, separate-process restart, temporal B-to-C contact
with A absent, both crash windows, no duplicate fixture effect in the frozen
recovery schedule, and final zero-item duplicate reconciliation in one
manifested run (`BVB-922`). This is not a general exactly-once guarantee.

**The high-level p2panda-centered composition is no longer the default
whole-stack finalist.** It remains a valuable component and behavioral oracle:
its initial native LogSync/Iroh path, restart replay, temporal contact, and
crash checkpoints worked. But the first integrated run timed out during fresh
B/C recovery (`BVB-932`), and a materially different fixed-requested-port run
ended with sender-observed success and receiver-side connection timeout before
initial completion (`BVB-941`). It did not complete the registered recovery-
without-duplicate-effect or post-ack cells. The corrected frozen differential is in
[`final-stack-bakeoff.md`](final-stack-bakeoff.md) and `BVB-948`.

**B1, immutable p2panda operations over BPv7, is conditional rather than a
third default.** It works functionally, but has not yet bought a hard outcome
beyond the p2panda-native temporal path and introduces another durable
store/progress/expiry domain. Add BP only after an exact topology or policy
requirement demonstrates that delta. **B2, interactive sync over BPv7, is a
stop/cost arm.**

## Whole-composition disposition

| Composition | Evidence-backed buy | Principal residual or cost | Disposition |
|---|---|---|---|
| A — p2panda-first | Offline publish, restart replay, native LogSync/Iroh, range selection, full-replica temporal carry, protected opaque carry, and both crash checkpoints | Prune metadata and duplicate-effect findings remain; integrated A-001 failed fresh recovery and A-002 exposed sender-success/receiver-timeout asymmetry; high-level deterministic direct peer control is absent; SQLite plus application-effect state creates two durable owner domains | **Conditional component/oracle; not the selected high-level whole stack** |
| G — greenfield FOSS components | Authenticated Iroh plus Negentropy reconciliation; redb atomic item/effect state; divergent convergence, restart, A-absent temporal carry, pre-commit and post-commit/pre-ack recovery without duplicate fixture effects, final duplicate no-op; separately executed Record, security, Blob, SDK, and assurance mechanics | Normative profile/four classes, durable session progression, mission policy/security lifecycle, Blob lifecycle, hostile bounds, physical/target qualification, and production admission remain ours | **Selected bounded research baseline; not production-selected** |
| B1 — p2panda operations over BPv7 | One-pass immutable operation over a restarted temporal BP relay | Duplicate durable owners; no demonstrated hard delta over A; BP security/policy/application assurance remain separate | **Conditional option only** |
| C — BPv7 plus thin data profile | Published DTN semantics and two independent functional temporal implementations | Nearly the complete replica, class, policy, security, Blob, API, and conformance surface remains original | **Standards-first control, not a current finalist** |
| D — Zenoh overlay | Routing, configuration, pub/sub/query, QoS, storage, APIs, and a bounded encrypted immutable-sibling carriage retest | Native same-key concurrent values collapsed; the successful custom overlay owns immutable keys, identity, encryption, siblings/conflicts, and application-effect gating | **Conditional routing/replication/storage component; stop as a whole stack** |
| E — Willow-centered | Namespace/capability/store primitives and bounded offline Drop behavior | Timestamp-first native recency conflicts with causal State/Record rules; live private sync/runtime gaps are large | **Standards/component oracle; stop as whole replica** |
| F — Veilid-centered | Local DHT/store and restart/lifecycle behavior | Frozen public path did not establish two-node retrieval; mission replica, temporal, policy, security, and carrier ownership remain | **Local-store/lifecycle oracle only** |
| B2 — interactive p2panda sync over BP | Reused exact upstream LogSync | One-pass temporal path failed; completion required four contact waves, three B restarts, seven declarations, six bundles, and live endpoint session state | **Stop** |

The connectivity result does not promote a carrier into a complete
composition. Iroh 1.0.3 passed all 13 upstream-supported one-kernel
Patchbay/NAT pairings from owned local relay to direct path, ping, and close.
The three upstream-ignored hard-cross pairings remained relayed and timed out
their direct waits. The test relay deliberately trusted an insecure
certificate, so this grants no identity or security credit and no physical,
public-Internet, ISP/CGN, endurance, or production credit (`BVB-904`).

## Residual-work and confidence bands

These are post-hoc qualitative decision bands, not replacements for the
missing Phase 0 ordinal anchors or preregistered engineer-day caps. No elapsed
time or engineer-day estimate is inferred.

| Composition | Residual custom semantics | Residual assurance/integration | Confidence in executed slice | Confidence as a complete composition |
|---|---|---|---|---|
| A — p2panda-centered | **High** — four-class profile, State/Record rules, application effect, policy, security/lifecycle, Blob, and product API remain | **Very high** — integrated completion failed twice; prune/apply, endpoint control, pre-1.0/SQLite admission, target/physical, conformance, and independent interop remain | **Medium** for the bounded initial store/sync/range/temporal checkpoints; **low** for integrated recovery | **Low; conditional component/oracle only** |
| G — greenfield | **Very high** — normative profile/classes, durable reconciliation progression, policy, security/lifecycle, and Blob protocol remain | **High** — the decisive failure/recovery composition passed, while target support, physical qualification, conformance, dependency admission, power loss, and long-term ownership remain | **High** for the exact integrated local recovery corpus | **Low** as a complete production composition |
| B1 — A operations over BPv7 | **High** — all A residuals plus operation↔bundle, expiry/retry, assurance, policy, and any custody-like mapping | **Very high** — two durable owner domains require cross-restart recovery, deduplication, lifecycle, security, and interoperability evidence | **Medium** for one bounded one-pass immutable-operation function | **Low**, and conditional on a named BP-only hard delta |

## Buy/build responsibility map

“Buy” means reuse a bounded upstream mechanism. It does not transfer credit to
unexecuted semantics or admit the dependency for production.

| Responsibility | Buy | Keep deliberately small and custom |
|---|---|---|
| Normative wire and evolution | Deterministic CBOR/CDDL mechanics and the dual-decoder seed corpus | The authoritative versioned four-class profile, critical extensions, negotiation, error model, and independent implementation |
| Replica/store/sync | Negentropy for set difference plus redb for one atomic accepted-item/effect state owner; retain p2panda as a comparator/component oracle | Object request/apply, durable reconciliation progression, State arbitration, Event gaps, Record conflict annotations, tombstones, and explicit GC policy |
| Record merge | Automerge for topics that explicitly opt into JSON-like CRDT merge | Topic policy, conflict presentation, non-JSON data, and every other class |
| Reconciliation | Negentropy for identifier-set differences with a bounded bulk fallback | Object request/apply, causality, durable resume, hostile cardinality bounds, and fallback policy |
| Durable state | redb for small metadata/protocol and accepted-item/effect state in the research baseline | Schema, migrations, quotas, compaction, corruption/disk-full and power-loss recovery. Preserve the one-owner transaction rule |
| Blob bytes and resume | Ordinary content files plus small transactional checkpoints; reusable streaming/chunk mechanics | Lifecycle, power-loss ordering, any-peer/carrier protocol, quota/eviction, and a normative NIST-approved whole/chunk digest. BLAKE3 is research/control evidence only unless the algorithm requirement is explicitly narrowed |
| Temporal dissemination | Native G reconciliation/contact path by default; one BPv7 implementation only when BP earns a named hard delta | Store-and-forward scheduling, application assurance, duplicate/loop bounds, mission priority/expiry, custody/BIBE selection, and exact durable-owner recovery |
| IP connectivity | Iroh is the conditional leading mechanism; Quinn is the narrow fixed control | Mission-identity binding, physical automatic discovery, public/ISP/CGN qualification, hard-cross direct-path policy, resource policy, and secure owned-relay operations. The local rust-libp2p graph remains on advisory/alpha-helper hold |
| Discovery/admission | Candidate/platform advertisements, authenticated carrier identity, and manual addresses | Three emission modes, mission/provider binding, bounded ephemeral hints, backoff/fairness, stale pruning, and optional operator bootstrap |
| Carriers | BlueR Linux mechanics subject to legal/graph/hardware hold; TrouBLE for a future no-OS host; btleplug for central-only mechanics; platform APIs for the smallest remaining glue subject to license-policy resolution | One common framing/reassembly/restart envelope and thin OS lifecycle adapters. Never put replica/security/policy semantics in each carrier |
| Source object security | COSE through `coset` plus a replaceable provider; NIST algorithm standards; exact fixed mandatory-both signature mechanics | The normative hybrid profile, key/identity binding, key distribution, outer member-readable metadata envelope, replay acceptance, and downgrade lifecycle |
| Membership and rekey | OpenMLS classical epoch/add/remove machinery; ACE/Group OSCORE semantics as design input | Mission/scope authority, disconnected control dissemination, PQ/hybrid integration, retained generations, rollback/rejoin policy, bridge authorization, and zeroization |
| Propagation policy | Candidate topic/QoS/lifetime/suppression primitives and one selected store | One thin mission-policy owner for topics/scopes/bridges, priority, TTL, quotas, eviction, emission, and durable policy transitions |
| C ABI and bindings | cbindgen and UniFFI; tonic only for the optional local agent | One high-level semantic API, ownership/cancellation/error/threading rules, ABI evolution, packaging, and local-agent authorization |
| Operations and assurance | tracing, optional OpenTelemetry adapter, cargo-cyclonedx, cargo-deny, cargo-audit, property/fault tooling | Redaction allowlist, release policy, target qualification, support lifecycle, and complete-stack fault/conformance evidence |

The security composition is intentionally layered: source objects survive every
carrier; an outer mesh-membership layer protects forwarding metadata; adjacency
TLS or BPSec is optional defense in depth only when the selected carrier makes
it useful. No transport security receives source-to-consumer credit.

## Delete decisions

- Do not preserve current implementation seams, wires, stores, or APIs.
- Do not add BP beneath Arm A until it proves a hard outcome worth a second
  durable state machine.
- Do not select the high-level p2panda Node composition as the default stack
  after the BVB-932/BVB-941 integrated failures; retain it as a component and
  differential oracle until it passes the same frozen recovery corpus.
- Do not tunnel interactive sync over BP in the current ownership model.
- Do not import Zenoh solely for queues, Tower solely for retries, or another
  database solely because it exists.
- Do not equate a topic with a propagation scope, a DHT/pub-sub layer with
  convergence, a connection relay with temporal relay, or a codec/standard with
  an executable lifecycle owner.
- Do not use Willow timestamp recency to arbitrate State or Record correctness.
- Do not store large Blob bytes in redb's mmap data plane; the 256 MiB run made
  the RAM scaling failure explicit.
- Do not ship the reviewed AGPL Iroh/BLE components or BUSL/GPL-transitioning
  SimpleBLE under the dependency rules.
- Do not treat BLAKE3 as the normative security digest without resolving the
  NIST/FIPS algorithm requirement.

## Terminal dispositions do not mean full work-order or requirements proof

Every currently scoped arm has a registered advance, conditional, component,
hold, oracle, exclusion, failure, environment-blocked, or stop disposition.
That is not a claim that every work-order instruction was performed. Phase 0
did not freeze a complete greenfield-native discovery/NAT/relay/runtime/resource
composition, reproducible ordinal anchors, or per-arm engineer-day caps before
execution. Phase 2 executed the common local differential and Iroh topology
lane, while rust-libp2p remained a static source/behavior hold and
Quinn/greenfield remained a narrow local control; neither received a complete
higher-level architecture-collapse runtime. These gaps cannot be repaired by
post-hoc estimates or by transferring Iroh evidence.

The following are final-selection or product-acceptance gates:

- real two-host automatic discovery, named NAT/hole-punch/relay topologies, and
  operator-owned relay failure;
- physical BTLE on target OS/controller combinations, true radio silence,
  broadcast accounting without an oracle, energy, wakeups, and background
  behavior;
- exact source-object plus protected-metadata composition, disconnected
  mission/scope rekey, durable replay/application-effect state, downgrade,
  zeroization, and a complete target-specific FIPS module/service matrix;
- full class semantics, tombstone lifecycle, application conflict API,
  cross-component crash atomicity, disk-full/corruption behavior, and
  application delivery assurance;
- a second independently spec-built implementation and whole-profile
  interoperability;
- production graphs, file-level licenses, advisory disposition, target builds,
  packaging, documentation-only integration, and support ownership; and
- stakeholder decisions for every bracketed quantity, priority doctrine,
  offline retention, policy defaults, and OS-SDK/public-domain license wording.

Two explicit production holds remain easy to misread. P2panda and Hardy inherit
SQLite, whose public-domain status does not literally satisfy “OSI-approved
licenses only” without an approved policy interpretation; that hold affects
those conditional component/BP paths, not G's redb research store. G still
requires a complete file-level license/advisory/target admission. Separately,
no single validated cryptographic module/service boundary currently covers the
complete mandatory classical-plus-PQ profile.

Under `BVB-865`, a discarded synthesis thread accidentally surfaced excluded
Proposal 0004 fragments through a faulty search glob. It was contained before
further synthesis, its output receives zero evidence or semantic credit, and
no Proposal-0004-derived conclusion is accepted here. Human/counsel owner
disposition remains external; this document does not claim the exposure never
occurred. `BVB-909` also contains a final-audit allowlist failure that exposed
excluded-subtree paths and row-width diagnostics only. That auditor stopped,
made no post-exposure edit, and every conclusion from the broad command onward
was rejected; clean replacement validation and external disposition remain
pending.

## Next decision experiment

Harden the selected G research baseline rather than restarting a broad
candidate search. Bind durable reconciliation progression to the single redb
acceptance/effect transaction; integrate the normative four-class profile,
source-object and protected-metadata security, membership/rekey/replay policy,
Blob lifecycle, and thin mission policy; then run disk-full/corruption/power
loss, hostile-cardinality, two-host/public-topology, physical-carrier, target,
scale, endurance, and independent-implementation gates. Keep p2panda and BPv7
as differential controls. Reopen either as the baseline only after it passes
the same protected recovery corpus or demonstrates a named hard outcome G
cannot provide.

## Post-frontier selected-core checkpoint

`BVB-965` completes the first Proposal 0006 build of that G baseline. The exact
374-package graph passed locked/offline check, warning-denied Clippy, release
build, the full primary recovery sequence, a shifted partial-overlap regression,
four malformed-frame rejections, actual-versus-wrong provider controls,
corrupted-copy fail-close, and 1/128/1,024-item inventory curves. The
independent pre-run audit also found and corrected a real evaluator defect:
replica-local Negentropy ordinals were replaced by stable ID ordering while the
frozen source remained byte-exact.

That result validates the bounded reference core and strengthens the direction
to stop broad whole-stack substitution work. It does not close any normative
class, durable-session, policy, security/FIPS, Blob-file, public/physical,
target, scale/endurance, independent-conformance, dependency/legal, support,
or production gate. `production_selected=false`. The exact report is
[`Proposal 0006 selected-stack result`](../0006/README.md).

Detailed arm outcomes and evidence links are in
[`arm-completion-register.md`](arm-completion-register.md).
