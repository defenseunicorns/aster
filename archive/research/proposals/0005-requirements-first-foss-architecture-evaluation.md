# Proposal 0005: Requirements-first FOSS architecture evaluation


- Status: accepted for phased evaluation by Decision 0025; no candidate selected
- Date: 2026-08-22
- Authority: `SRC-001`,
  [`data-mesh-requirements.md`](../../data-mesh-requirements.md), SHA-256
  `e88bcc6c717a5175a460205fdc084aaa2e1f020a142a84087f9881677da02987`
- Relationship to Proposal 0004: independent architecture evaluation; Proposal
  0004 evidence may be reused as component characterization, but its incumbent
  boundaries and selection rules do not constrain this proposal

## Premise

The current Aster implementation is experimental and incomplete. It is not an
architecture baseline, compatibility target, or incumbent that a FOSS candidate
must preserve. Existing source, tests, vectors, and measurements may be reused
when they trace to a requirement, but current wire bytes, APIs, stores, module
boundaries, host/session design, identity composition, and migration path have
zero selection weight.

The requirements define outcomes rather than implementation. They explicitly
prefer maintained FOSS and published standards over bespoke mechanisms and make
the protocol specification, rather than the reference implementation, the
interoperability authority ([§8](../../data-mesh-requirements.md#8-implementation-constraints)).

Bracketed values are stakeholder-validation placeholders
([§1](../../data-mesh-requirements.md#1-project-brief),
[§14](../../data-mesh-requirements.md#14-open-items-for-the-team--stakeholders)).
Values such as 30 days offline, low-single-digit kbps, 50% loss, 10 MiB binary
size, 64 MiB RAM, and the example node counts are measurement points, not
candidate-elimination gates. The evaluation reports capability curves and
breakpoints.

### Boundary with Proposal 0004

Proposal 0004 remains useful evidence about rust-libp2p mechanisms inside the
current shared-node design. It is not a greenfield provider selection because
it limits eligible arms to current native and libp2p, excludes Iroh, fixes the
same Aster host and protected discovery for both arms, rejects changes to Aster
wire/application semantics, and defines rollback as return to unchanged Aster
stores and host seams. It also applies several bracketed resource examples as
non-compensable screens.

This proposal does not rewrite or erase that experiment. It imports only
requirements-relevant observations with their original scope. No Proposal 0004
constraint or result can exclude an architecture here merely because it changes
Aster, uses idiomatic provider facilities, or requires a different wire, API,
store, security composition, or ownership model.

## Question

Which composition of FOSS implementations and published standards can satisfy
the largest part of the requirements while leaving the smallest bespoke
protocol, security, persistence, networking, and lifecycle-assurance surface?

Subsidiary questions are:

1. Can an existing local-first framework supply the replicated-data model,
   causality, anti-entropy, persistence, and application API?
2. Can a Delay-Tolerant Networking implementation supply intermittent
   multi-hop store-and-forward without duplicating the replica engine?
3. Which idiomatic IP connectivity stack—rust-libp2p, Iroh, or a minimal native
   composition—buys the most required behavior at the lowest residual cost?
4. Which published security standards and vetted implementations can replace
   new object-security, group-membership, revocation, and hybrid-PQ design?
5. Which requirements remain genuine profile/integration work after the best
   composition is selected?

The eligible outcome is a ranked, evidence-backed architecture frontier, not a
forced winner. A candidate may become a complete-stack finalist, a component,
a conformance oracle, or a recorded rejection.

## Requirement classes

The final composed stack must satisfy hard invariants. An individual FOSS
component need not implement every requirement itself; a missing feature is an
integration delta unless it contradicts the component's essential model.
Classification is atomic: split compound bullets into capability, quantity,
and preference clauses before assigning a class. For example, extended-offline
resync is binding while `30 days` is provisional; constrained-link operation is
binding while `3 kbps` and `50% loss` are provisional.

| Class | Evaluation treatment | Examples |
|---|---|---|
| Hard correctness or security invariant | The final composition must pass; performance cannot compensate for failure | Eventual convergence, no silent conflict loss, clock-independent correctness, direct sync without mandatory infrastructure, intermittent multi-hop store-and-forward, source-to-consumer protection, relay payload blindness, protected mesh metadata, replay rejection, mutual authentication, no hand-rolled cryptographic primitives |
| Binding product or delivery scope | Must exist somewhere in the composition; absence from one dependency is not rejection | Four data classes, IP and BTLE adapters, Rust core and C FFI, bindings, conformance suite, high-level offline-first API |
| Provisional quantitative target | The associated capability remains binding; measure the bracketed value over a range and report breakpoints | Offline duration, link rate, loss, blob size, priority count, integration time, RAM, binary size, item count, node count |
| Strong default | Score directly; deviation requires a recorded rationale | Every `Should`, including one-to-many broadcast optimization, link-characteristic reporting, and FIPS-validated modules where available |
| Optional capability | Record benefit and cost without implying a release obligation | Every `May`, subject to any conflicting MVP scenario that must first be normalized |
| Future or no-preclusion constraint | Score reversibility and architectural risk; do not require a production implementation now | Future MCU, LoRa, serial, file, and aggregation profiles |

Only an intrinsic contradiction or an irreconcilable dependency-policy problem
can eliminate a candidate before composition. Examples include mandatory
always-online infrastructure for correctness, unavoidable relay plaintext,
unbounded state that cannot be capped without replacing the subsystem, or a
runtime dependency available only under a prohibited license. A rejected
implementation may still serve as a standards or differential oracle.

## Architectural capability map

“Mesh” is the complete outcome. The native-versus-libp2p-versus-Iroh question
is only one part of it.

| Capability | Required outcome |
|---|---|
| Normative interoperability profile | Versioned items and extensions, four data classes, independent implementations, conformance |
| Replica and convergence engine | Causality, conflicts, tombstones, difference-proportional reconciliation, partial sync, any-peer resume |
| Delay-tolerant dissemination | Durable temporal multi-hop forwarding, duplicate/loop suppression, fragmentation, expiration |
| Propagation and resource policy | Topics, scopes, bridges, priority, TTL, quotas, eviction, emission policy, broadcast use |
| Peer connectivity and sessions | Discovery, manual peering, mutual authentication, NAT traversal, connection relay, path lifecycle |
| Carriers and framing | IP, BTLE, small MTUs, future LoRa/serial/file, link-characteristic reporting |
| Security and membership | Source object protection, mesh metadata protection, identity, membership/revocation/key-generation state, exclusion/rekey, zeroization; separately prove NIST-standard and FIPS-approved algorithms, hybrid classical+PQ establishment, hybrid classical+PQ signatures, algorithm agility, and downgrade protection |
| Persistence and blobs | Durable offline publish, bounded storage, chunks, resumability, content-addressed deduplication |
| Embedding and product surface | Rust library, C ABI, bindings, optional local agent, simple high-level API |
| Assurance and operations | Resource curves, hostile-input behavior, SBOM, lifecycle, second implementation, fault and conformance evidence |

Every candidate composition must have a responsibility map naming exactly one
owner—or an intentional layered relationship—for durable storage, retry,
expiration, deduplication, routing, reconciliation, blob progress, identity,
and membership/revocation/key-generation state. Duplicate mechanisms are
counted as residual custom and operational burden rather than hidden as
adapters.

## Initial candidate portfolio

Exact versions, source revisions, licenses, and feature graphs are frozen only
after Phase 0. Inclusion here is authorization to evaluate, not dependency
admission or production selection.

| Arm | Composition | Hypothesis |
|---|---|---|
| A — p2panda-first | p2panda core/sync/store/stream/blobs/auth/encryption/spaces and high-level Node work with a selected connectivity carrier | A Rust local-first framework can buy causality, partial replication, persistence, replay, blobs, group work, and much of the application surface |
| B1 — p2panda operations over BPv7 | Immutable p2panda operations and control objects carried as BPv7 application payloads | BP supplies temporal forwarding while p2panda retains replica convergence without tunneling a live peer session |
| B2 — p2panda sync over BPv7 | The interactive p2panda sync exchange serialized over BPv7/BPSec | A complete existing sync protocol can survive disrupted contacts without redesign, despite potentially duplicated retry and progress state |
| C — BPv7 plus thin data profile | BPv7/BPSec plus the smallest requirements-specific State/Event/Record/Blob and anti-entropy profile | A standards-first DTN base may require less total original work than integrating a second durable replication framework |
| D — Zenoh plus encrypted local-first overlay | Zenoh routing/pub-sub/query/storage and bindings plus a convergent encrypted item layer | A mature edge-data fabric can collapse connectivity, routing, APIs, and operations even if convergence remains an overlay |
| E — Willow-centered protocol | Willow data model, Meadowcap, Confidential Sync, and Drop Format over the best dissemination/connectivity substrate | A published protocol family can reduce bespoke namespace, capability, private-sync, and offline-media design even if its implementation is not the reference base |

Public-source provenance for this initial portfolio is append-only: p2panda
uses BVB-177 through BVB-179, BVB-619, and BVB-644 through BVB-645; BPv7 and
its security/convergence standards use STD-020 and BVB-648 through BVB-652;
Zenoh uses BVB-620 through BVB-621 and BVB-646 through BVB-647; Willow uses
BVB-668 through BVB-675. These IDs authorize research claims only. They are not
dependency admissions, exact source freezes, or executable acceptance evidence.

Phase 0 must run a systematic candidate search and retain both an inclusion and
exclusion register. This initial portfolio is not a closed list, and p2panda is
not a new incumbent. The search must identify any additional maintained
local-first, DTN, replicated-data, or edge-fabric candidates before source
freeze.

Component families to resolve into exact schedulable projects include document
CRDTs for Record merging; reconciliation mechanisms; durable stores; Blob,
range-transfer, and FEC mechanisms; object and group-security standards plus
their maintained implementations; and FOSS tooling for bindings,
observability, testing, packaging, and SBOMs. Standards, executable
dependencies, daemon experiments, and design/differential oracles must be
listed separately rather than grouped as interchangeable candidates.

The initial BPv7 implementation search includes dtn7-rs and Hardy as Rust
candidates and ION/HDTN-class implementations as possible daemon experiments
or interoperability oracles. Their exact role, embeddability, license,
maintenance, and feature support are Phase 0 findings, not assumptions.
The registered discovery sources are BVB-653 through BVB-667 and BVB-686
through BVB-692; a missing advertised feature remains `unknown`, not proof of
absence.

BPv7 receives no automatic credit for application delivery assurance,
requirements-level priority, or custody semantics. RFC 9171 states that the
base protocol does not ensure delivery, removes its predecessor's Quality of
Service markings, and migrates custody transfer to the separate
bundle-in-bundle encapsulation specification
([RFC 9171](https://www.rfc-editor.org/rfc/rfc9171.html)). Arms B1, B2, and C
must name which extension or application mechanism owns each missing outcome
and which selected implementation actually supports it.
The registered source for this limitation is STD-020; BPSec sources are
BVB-648 through BVB-649.

### Reopened IP connectivity candidates

The connectivity comparison has two lanes.

1. **Common outcome lane:** every final composition must support automatic or
   manual peering where applicable, authenticate peers before protocol-data
   exchange, operate directly on a local network without mandatory
   infrastructure, suppress discovery under emission policy, and carry a
   versioned opaque protocol. For each connectivity arm, record automatic and
   manual discovery, carrier identity, mission-identity binding, link reporting,
   NAT methods, connection relay, resource bounding, and channel/session shape
   as candidate-native, composed, or missing delta rather than assuming one
   required provider abstraction.
2. **Architecture-collapse lane:** each arm may use its idiomatic higher-level
   discovery, identity, path management, request/response, pub/sub, gossip,
   blob, and routing facilities when they reduce residual custom work.

The candidates are:

- **Iroh:** evaluate its authenticated QUIC endpoint, addressing, hole punching,
  relay fallback, path lifecycle, and exact adjacent blob/gossip components.
  Its use by another candidate grants no presumption of selection.
- **rust-libp2p:** allow idiomatic Swarm ownership, discovery, protocol
  negotiation, AutoNAT, relay/DCUtR, request/response, pub/sub, and peer/path
  lifecycle where useful. Do not constrain it to one current-Aster substream or
  current-Aster discovery.
- **Greenfield native:** freeze one exact composition of existing FOSS
  primitives for an IP carrier, discovery, NAT traversal, connection relay,
  runtime, and resource control before corpus execution. It cannot cherry-pick
  different mechanisms per scenario without registering a new composition.
  This is the control arm, not the incumbent custom UDP stack.

The connectivity research sources are BVB-630 through BVB-643 for current
rust-libp2p and Iroh evidence, with earlier Quinn sources BVB-155 through
BVB-159 and BVB-213 through BVB-220. Any newly consulted release, feature,
security, or dependency source is registered before it changes an evaluation
artifact.

None of these three should be assumed to provide durable opportunistic
store-and-forward. BPv7 and higher-level replication/dissemination candidates
are evaluated separately and in composition with them.

BLE, tiny-MTU framing, and broadcast are separate carrier-composition tests
available to every architecture. An IP substrate does not fail merely because
BLE is supplied beside it, but the final architecture must demonstrate that
the two coexist without changing protocol semantics.

Architecture-collapse credit requires an exact shipped component and the
corresponding durable semantics to be demonstrated. Pub/sub or gossip receives
no anti-entropy or temporal-forwarding credit; connection relay receives no
durable-relay credit; same-peer stream resume receives no any-peer-resume
credit; and a Blob transfer helper receives no persistence or cross-peer
progress credit unless it actually supplies those outcomes.

## Explicitly excluded selection criteria

No candidate gains or loses selection credit for:

- preserving or changing current Aster wire bytes, schemas, IDs, APIs, stores,
  host/session ownership, contact lifecycle, or module boundaries;
- passing a current-Aster test that does not trace to a requirement;
- minimizing migration effort from the experimental prototype;
- deleting more current native lines than an adapter adds;
- returning to the existing Aster implementation as its rollback path;
- using the same internal events, buffers, retries, identities, or persistent
  state as another candidate; or
- missing one bracketed quantitative example.

Fairness means identical black-box mission workflows, threats, external
resource observations, and evidence quality—not identical internals.

## Evaluation status vocabulary

Every candidate/requirement cell records three orthogonal fields.

**Semantic provenance:**

- **candidate-native** — semantics are owned by the candidate;
- **published standard with named implementation** — an interoperable standard
  and a maintained usable implementation are both identified;
- **published standard requiring implementation** — the semantics are reusable,
  but production implementation work remains;
- **adapter/configuration** — bounded integration with no new protocol semantics;
- **bespoke semantics** — a new protocol or persistent lifecycle must be designed;
- **unknown** — insufficient evidence; not silently treated as failure; or
- **intrinsic contradiction** — the candidate's essential model cannot meet the
  invariant without replacement.

**Implementation availability:** embeddable production dependency, external
daemon/service, research implementation, differential/conformance oracle, or no
usable implementation.

**Evidence confidence:** claim, documented behavior, local demonstration,
hostile fault test, or cross-implementation result. These fields prevent a
specification-only candidate from receiving the same buy credit as maintained
executable FOSS.

## Common black-box corpus

Existing Aster fixtures may seed these tests, but expected behavior is derived
again from the requirements.

1. **Direct offline-first publish:** publish with no peer, restart, then sync
   directly without mandatory infrastructure.
2. **Temporal relay:** A contacts B; B restarts; later B contacts C; A and C are
   never concurrently connected. B does not consume and cannot decrypt the
   payload.
3. **Rejoin and reconciliation:** vary the offline interval and retained state;
   measure whether and how a returning subscriber converges. Separately hold
   actual difference `Δ` constant while increasing total dataset `N`, then hold
   `N` constant while increasing `Δ`; report bytes, CPU, round trips, and
   persistent protocol state.
4. **Class behavior:** verify causal State selection, Event sequence-gap
   detection, concurrent Record preservation/merge annotation, and immutable
   Blob behavior.
5. **Any-peer resume:** interrupt a large transfer, change peer and carrier,
   and continue without restarting completed work.
6. **Propagation policy:** topics, scopes, relay quotas, bridge filtering,
   priority ordering, TTL, eviction, and receive-only behavior.
7. **Broadcast:** determine whether one transmission can serve multiple
   authenticated recipients and quantify duplicated unicast work otherwise.
8. **Hostile transport:** replay, corruption, truncation, duplication,
   reordering, burst loss, and maliciously high candidate/item cardinality.
9. **Revocation and rekey:** partition a member, advance membership/revocation/
   key-generation state, reconnect, and distinguish behavior before and after
   peers learn and accept the newer state.
10. **NAT and relay:** test named NAT topologies, direct upgrade, operator-owned
    fallback, relay loss, path change, and local operation with all
    infrastructure absent.
11. **Capture privacy:** verify that external traffic captures reveal neither
    plaintext payload nor protected mesh metadata and that relay/bridge durable
    state contains no payload plaintext. Authorized consumer storage is outside
    this test unless at-rest protection is separately promoted to a requirement.
12. **Interoperability:** exchange with a second implementation or independently
    derived codec/oracle wherever one exists.

Corpus results must name the tested capability, required composition, and
selection-credit owner. At minimum, distinguish peer connection relay from
durable temporal relay, live gossip from reconciliation, same-peer carrier
resume from durable any-peer resume, carrier authentication from mission-peer
authentication, and session protection from source-object and mesh-metadata
protection.

## Quantitative sweeps

The experiment uses adaptive sweeps rather than an exhaustive Cartesian
product. Exact grids and fixed workloads are frozen with the experiment plan.
Elapsed disconnection, publication count/bytes, tombstone retention, TTL age,
membership/rekey changes, and eviction pressure are independent variables; an
“offline day” is never used as a proxy for all of them. Initial anchors are:

- elapsed disconnection around 1, 7, 14, 30, 60, and 90 days using simulated
  lifecycle state rather than wall-clock waiting;
- divergent item counts/bytes, tombstone counts, membership-generation
  distance, TTL age, and retention policy varied independently;
- link rates around 1, 3, 10, 30, and 100 kbps;
- independent and burst loss around 0%, 10%, 30%, 50%, and 70%;
- MTUs from tens of bytes through 1500 bytes;
- item counts and peer counts increasing until a resource or latency knee is
  visible;
- items from tens of bytes through streamed hundred-megabyte-class Blobs; and
- direct, connectivity-relayed, temporally relayed, and broadcast paths.

Report the full curve or observed breakpoint for application goodput,
convergence time, payload amplification, setup traffic, RAM, binary size, CPU,
idle wakeups, storage/write amplification, retained protocol state, and
recovery behavior. A result such as “converges through the 14-day retained
state but not the 30-day state under this policy” is valid decision data, not
an automatic rejection.

## FOSS-reuse and residual-surface accounting

Raw dependency count and raw lines of code are secondary observations. The
primary accounting names:

- published protocol behaviors adopted unchanged or through a narrow profile;
- complete production mechanisms owned by maintained upstream projects;
- new wire messages and extension semantics;
- custom persistent state machines and recovery transitions;
- custom authorization, membership/revocation/key-generation, or cryptographic
  composition;
- provider forks or patches that must be carried;
- duplicate stores, retry loops, expiry rules, deduplication, or routing state;
- independent implementations and conformance material already available; and
- upstream governance, security response, audit/fuzz history, release cadence,
  platform support, and SBOM/license posture.

The comparison reports separate ordinal axes for:

1. final-stack hard and product-scope coverage;
2. upstream-owned executable FOSS mechanisms;
3. published-standard semantic reuse;
4. residual bespoke protocol and persistent state machines;
5. evidence confidence;
6. empirical operating envelope; and
7. governance, supply-chain, operational, and platform sustainability.

Phase 0 defines reproducible anchors for each axis before results exist. The
preferred architecture is on the Pareto frontier rather than merely maximizing
a blended score. A fixed weighted score may be included for sensitivity
analysis, but it cannot hide a hard invariant, unavailable implementation, or
low-confidence claim.

## Phases

### Phase 0 — requirement matrix and source freeze

- Split every compound requirement into atomic capability, quantitative,
  preference, and phasing clauses; classify each clause using the requirement
  classes above.
- Normalize ambiguous security and correctness terms needed by the corpus,
  without silently adding requirements.
- Run a systematic candidate search across maintained local-first, replicated-
  data, DTN, edge-fabric, connectivity, security, storage, and SDK projects.
  Retain search sources, inclusion criteria, and an exclusion register before
  freezing the initial portfolio.
- Freeze exact candidate versions, features, sources, licenses, governance,
  security policies, advisories, toolchains, and transitive dependency graphs.
- Classify every BPv7 implementation as a possible embeddable dependency,
  external-daemon experiment, research implementation, or interoperability
  oracle. Record exact support for forwarding, delivery reports,
  fragmentation, priority extensions, BPSec, routing, and custody-like/BIBE
  behavior rather than crediting the BPv7 standard as executable FOSS.
- Freeze one exact greenfield-native IP composition, including carrier,
  discovery, NAT method, connection relay, runtime, resource controls, and
  versions.
- Define observable dependency-admission criteria for maintenance and
  governance: release/advisory response history, disclosure channel,
  maintainer activity, bus factor or fork viability, platform support, and
  transitive-license/SBOM posture. Failure for production adoption does not
  automatically remove oracle/research value.
- Run early security feasibility screens for replaceable crypto providers,
  identity/hash/wire coupling, object authentication, metadata protection, and
  disconnected membership change before costly compositions begin.
- Produce the initial responsibility map and gap-closure hypothesis for every
  arm.
- Freeze reproducible ordinal anchors for every comparison axis.
- Set per-arm engineer-day caps before moving the proposal from draft to
  accepted for experiment.

### Phase 1 — whole-system disproof spikes

- Exercise the exact p2panda core, sync, store, stream, Blob, auth, encryption,
  spaces, and high-level Node candidates for local publish, causal forks,
  partial sync, pruning, replay, crash recovery, provider substitution, and the
  current delivery path.
- Exercise at least two frozen BPv7 implementations in the temporal-relay
  topology and distinguish persistence, forwarding, delivery reporting,
  fragmentation, and custody-like behavior.
- Partition and restart all Zenoh routers/stores, then test later transient
  history. Treat raw-Zenoh results as gap quantification, not failure of Arm D;
  the adoption arm is evaluated again with its minimal encrypted durable
  local-first overlay.
- Map all four data classes, scope/topic behavior, conflicts, TTL, bridges, and
  file transport into Willow; implement one sync or Drop exchange if the
  available implementation permits it.
- For every surviving protocol candidate, begin a minimal normative profile,
  golden and negative vectors, and an independently derived codec or parser
  oracle. Do not defer specification ambiguity until final selection.

### Phase 2 — greenfield connectivity comparison

- Run Iroh, idiomatic rust-libp2p, and greenfield native through both
  connectivity lanes and the common black-box networking cells.
- Allow provider-native identities to bind directly to mission identities when
  the composed security profile proves the required properties; do not require
  a duplicate incumbent authentication session by construction.
- Import relevant Proposal 0004 evidence with its original scope and confidence,
  but do not import its candidate exclusions or current-Aster compatibility
  gates.
- Run a faithful BLE/tiny-MTU/broadcast composition spike against every
  architecture class before connectivity down-selection. Production-quality
  platform adapters may remain later work, but stream, handshake, identity,
  framing, and PQ-overhead assumptions must be challenged here.

### Phase 3 — intentional compositions

Phase 1 and Phase 2 end with a recorded down-selection. Exhausting an arm's
budget with an unowned hard gap stops it as an adoption arm while retaining any
oracle value.

Pair each surviving replica/dissemination architecture with each viable
connectivity finalist unless the frozen responsibility maps and black-box
evidence demonstrate that the choices are orthogonal. This includes greenfield
native whenever it survives.

At minimum, compare B1 (operations as BP application payloads), B2 (interactive
sync serialized over BP), and C (thin data profile over BP) as distinct
responsibility models. Add Zenoh or Willow compositions when Phase 1 leaves a
credible path. Measure duplicate responsibility and recovery state as
carefully as throughput. A p2panda-over-BPv7 arm survives only if the
replication behavior it buys is worth the additional durable protocol and
integration surface.

### Phase 4 — continuing security-profile feasibility

- Compare standards-based object and group-security compositions, including
  COSE, current ML-DSA/ML-KEM profiles, Group OSCORE/ACE, BPSec, current
  published or draft hybrid-TLS profiles for IP adjacency, and MLS
  implementations where applicable. Freeze each document's exact standards
  status; separately track hybrid key establishment and hybrid signatures.
  Adjacency TLS never receives source-to-consumer authenticity credit.
- Demonstrate source-to-consumer verification after opaque temporal relay,
  protected forwarding metadata, replay handling across restart and membership
  change, downgrade rejection, disconnected revocation/rekey, and defined
  zeroization hooks. Characterize storage/snapshot rollback separately because
  it is not independently stated as a requirement.
- Reconcile per-item authentication with allowed batching/session amortization:
  every item must be cryptographically bound to its authenticated source
  envelope or batch.
- Record published-standard status, implementation maturity, and exact FIPS
  module/operation coverage in separate columns.
- Gate the final composition separately on NIST-standard and FIPS-approved
  algorithms, hybrid classical+PQ key establishment, hybrid classical+PQ
  signatures, algorithm agility, and downgrade protection. Treat use of a
  FIPS-validated module where available as the distinct strong default stated
  by the requirements.
- Treat a candidate's default crypto mismatch as a gap until the experiment
  proves either a clean provider/profile substitution or an intrinsic
  contradiction.

### Phase 5 — product surface and assurance

- Complete production-quality BTLE and small-MTU adapters and broadcast tests;
  characterize future file-transport compatibility before final selection.
- Compare Record CRDTs, durable stores, Blob/range/FEC mechanisms, binding
  generators, local agents, observability, packaging, and SBOM tooling only
  after the core dissemination, convergence, and security compositions survive.
- Run the adaptive quantitative sweeps and continue the independent
  specification/conformance work begun in Phase 1.
- Produce the final frontier, responsibility maps, residual custom-work
  estimates, confidence grades, and recommended architecture experiments or
  decision records.

## Early exits

Stop an adoption arm only when retained evidence shows:

- an intrinsic contradiction with a hard invariant;
- an irreconcilable license, governance, or security-maintenance constraint
  under the observable Phase 0 admission criteria;
- an unavoidable hosted-infrastructure dependency for required local/direct
  correctness;
- an unavoidable need for relays to read protected payload;
- unbounded or unsafe behavior that cannot be isolated without replacing the
  subsystem; or
- a composition whose required bespoke critical mechanisms clearly dominate a
  surviving alternative and offer no compensating operating advantage.

Missing one soft target, changing current Aster, requiring a different API or
store, or failing a current implementation-specific regression is not an early
exit unless the behavior traces to a hard requirement.

## Deliverables

- Requirements matrix with atomic invariant, product-scope, quantitative,
  strong-default, optional, and future classification
- Candidate source, license, governance, and security register
- Per-arm responsibility and duplicate-mechanism maps
- Reusable black-box scenario corpus and raw measurement curves
- Whole-system and connectivity comparison reports
- Security standards/implementation/FIPS coverage matrix
- Residual custom-semantics and assurance estimate for each finalist
- Final Pareto frontier with confidence grades and explicit unknowns
- Follow-on proposal or architecture decision; this proposal itself selects no
  production stack

## Open controls carried into the phased evaluation

- Owner, scope, evidence plan, and initial engineer-day caps are recorded in
  the Evaluation 0005 execution plan. The remaining items below gate only the
  affected result or production decision; they do not block early disproof
  work or turn an unresolved value into a candidate-elimination rule.
- Decide which provisional sweep anchors are practical for the first cohort.
- Select the two first-class binding targets only if binding work enters Phase 5.
- Resolve the literal treatment of public-domain dependencies under the
  “OSI-approved licenses only” wording.
- Normalize revocation timing, TTL without trusted clocks, permitted metadata
  leakage, replay-versus-idempotent-redelivery, identity rotation, and the exact
  hybrid-signature/key-establishment rule for testable acceptance.
- Define the exact zeroization scope and distinguish software deletion hooks
  from hardware-backed destruction guarantees.
- Define fixed offline-sweep workloads and lifecycle events so elapsed time,
  retained divergence, TTL, tombstones, membership changes, and eviction are
  not conflated.
