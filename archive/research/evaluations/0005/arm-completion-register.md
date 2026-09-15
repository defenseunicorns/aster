# Evaluation 0005 research-arm completion register

> Historical experiment summary. Detailed harnesses, raw logs, and execution
> records are retained separately; only linked public summaries and active tests
> are maintained in this repository.


Status: **every currently scoped arm has a registered terminal disposition;
the work order remains only partially fulfilled because Phase 0 controls and
Phase 2 architecture-collapse executions are missing.** States below include
complete, bounded complete, mixed terminal, source/behavior hold,
environment-blocked, failure, stop, and unimplemented. None means that a final
stack satisfies the associated requirements or that Proposal 0005 was fully
executed.

Authority:
[`data-mesh-requirements.md`](../../../data-mesh-requirements.md), SHA-256
`e88bcc6c717a5175a460205fdc084aaa2e1f020a142a84087f9881677da02987`.

## Phase 0–5 accounting

| Phase | State | Registered disposition |
|---|---|---|
| 0 — normalize, search, freeze, preregister | **Partial** | Requirements decomposition, landscape, selected freezes, dependency/admission screens, and responsibility maps are bounded complete. The greenfield-native discovery/NAT/relay/runtime/resource composition was never fully frozen; reproducible ordinal anchors and per-arm engineer-day caps were not preregistered. No post-hoc numbers are substituted. |
| 1 — protocol surfaces and first disproofs | **Bounded complete** | Selected surfaces have executable, source-only, component, stop, failure, or unimplemented dispositions. P2panda's prune/restart metadata failed; auth/encryption/Spaces and several class surfaces remain unwired or absent. |
| 2 — connectivity and architecture collapse | **Mixed/partial** | Common local differential and Iroh topology simulation are terminal. Iroh has an executable collapse lane; rust-libp2p has a static source/behavior hold; Quinn/greenfield is a narrow local control. The latter two lack complete higher-level architecture-collapse runtimes. Excluded Proposal 0004 receives zero credit. |
| 3 — cross-product and dissemination composition | **Bounded complete** | P2panda/greenfield × Iroh/Quinn manual opaque carriage passed 4/4. B1/B2/C are distinct. No topology orthogonality or reconciliation-over-carrier credit is claimed. |
| 4 — integrated security | **Bounded feasibility complete** | The non-FIPS integrated corpus is terminal with explicit hybrid, distribution, rollback, custody, independent-interoperability, physical, and production gaps. |
| 5 — carriers, conformance, SDK, assurance | **Mixed terminal** | Host sweeps ran; physical BTLE and some product cells are environment-blocked, broadcast has two bounded failures, independent conformance found a profile defect, and the exact license fixture failed. |

`BVB-865` contains a project synthesis-thread exposure. That thread was
discarded, its Proposal-0004-derived output receives zero credit, and external
owner/counsel disposition remains pending. `BVB-909` contains a separate
final-audit allowlist failure that exposed excluded-subtree paths and row-width
diagnostics only; the auditor made no post-exposure edit, its affected
conclusions are discarded, and clean replacement validation is required.

## Controls and portfolio

| Arm | State | Current disposition | Primary evidence |
|---|---|---|---|
| Requirement normalization | Complete | 348 atomic cells; Must/Should/provisional/optional/future kept distinct | [`requirements-notes.md`](requirements-notes.md), [`requirements-matrix.csv`](requirements-matrix.csv) |
| Project evidence controls | Complete | Exact source tuples, hash-frozen local artifacts, scenario/result contracts, and append-only corrections | archived `README.md` (archived), archived `validate.py` |
| Candidate landscape and exclusions | Complete | Whole stacks, components, standards, daemons, oracles, holds, and license exclusions separated | [`candidate-register.md`](candidate-register.md) |
| Responsibility decomposition | Complete | P2P split into replica, temporal dissemination, connectivity, discovery, carriers, security, policy, Blob, API, and assurance owners | [`responsibility-map.md`](responsibility-map.md) |

## Whole-stack and dissemination arms

| Arm | State | Current disposition | Primary evidence |
|---|---|---|---|
| A — p2panda-first | Mixed terminal | Conditional component/oracle, not the selected high-level whole stack. Initial native LogSync/Iroh, restart, temporal carry, range, and crash checkpoints passed; the first integrated run failed fresh recovery and the fixed-requested-port run exposed sender-success/receiver-timeout before receiver completion. Exactly-once recovery and post-ack quiescence did not pass | [`final-stack-bakeoff.md`](final-stack-bakeoff.md), [`p2panda-phase1-closure.md`](p2panda-phase1-closure.md), [`p2panda-temporal-relay.md`](p2panda-temporal-relay.md) |
| G — Iroh + Negentropy + redb | Bounded integrated complete | Selected research baseline, not production-selected. Divergent reconciliation, restart, A-absent temporal carry, both crash windows, one task-authored redb item/effect transaction domain, no duplicate fixture effect in the registered recovery, and final duplicate no-op passed; normative classes, security, policy, Blob lifecycle, physical/target and independent gates remain | [`final-stack-bakeoff.md`](final-stack-bakeoff.md), [`comparison summary`](../../../../docs/evaluations/0005/results/stack-comparison.json) |
| BPv7 implementation 1 — dtn7-rs | Complete | Temporal daemon/oracle only; payload plaintext and advisory/governance holds | [`bpv7-freeze.md`](bpv7-freeze.md) |
| BPv7 implementation 2 — Hardy | Complete | Embeddable BP component and independent temporal oracle; plaintext relay state, SQLite-policy hold, no BPSec application profile | [`bpv7-hardy-temporal-relay.md`](bpv7-hardy-temporal-relay.md) |
| B1 — immutable p2panda operation over BP | Complete | Conditional only; one-pass function passed but no hard delta yet justifies duplicate durable owners | [`dissemination-composition-arms-bvb724.md`](dissemination-composition-arms-bvb724.md) |
| B2 — interactive p2panda sync over BP | Complete | Stop/cost arm; one-pass failed and completion required repeated waves plus live endpoint state | [`dissemination-composition-arms-bvb724.md`](dissemination-composition-arms-bvb724.md) |
| C — BP plus thin data profile | Complete | Standards-first control, not current finalist; most mission semantics remain original | [`dissemination-composition-arms-bvb724.md`](dissemination-composition-arms-bvb724.md) |
| D — Zenoh overlay | Bounded complete | Conditional routing/replication/RocksDB component after the immutable encrypted-sibling overlay passed; stop as whole replica because the custom overlay owns keys, identity, encryption, sibling/conflict semantics, and effect gating | [`zenoh-arm-d.md`](zenoh-arm-d.md) |
| E — Willow-centered | Complete | Buy/retain namespace, capability, store, payload-prefix, and Drop mechanics; standards oracle; stop native State/Record arbitration | [`willow-arm-e.md`](willow-arm-e.md) |
| F — Veilid-centered | Complete | Local DHT/store lifecycle oracle only; stop current whole-stack path | archived `arm-f-local-report.md` |

## Security and membership arms

| Arm | State | Current disposition | Primary evidence |
|---|---|---|---|
| Primitive-provider feasibility | Complete | Buy as replaceable primitive-provider candidate; executed path is explicitly non-FIPS | [`aws-lc-provider-feasibility.md`](aws-lc-provider-feasibility.md) |
| COSE source object | Complete | Buy `coset` codec plus provider mechanics; normative mandatory-both profile, distribution, replay, and metadata layer remain custom | [`coset-hybrid-source-object.md`](coset-hybrid-source-object.md) |
| t_cose comparator | Complete | Classical Sign1 component/oracle only; stop as complete hybrid encrypted-object owner | [`t-cose-source-object-freeze.md`](t-cose-source-object-freeze.md) |
| Group OSCORE plus ACE implementation lane | Complete | Stop frozen executable lane; retain standards semantics pending an actual maintained group implementation | [`group-oscore-implementation-freeze.md`](group-oscore-implementation-freeze.md) |
| OpenMLS membership comparator | Complete | Buy classical epoch/add/remove machinery; mission authority, temporal control, PQ/hybrid, rollback, rejoin, and zeroization remain | [`openmls-disconnected-membership.md`](openmls-disconnected-membership.md) |
| BPSec role | Complete bounded screen | Optional only for a surviving BP composition; Hardy codec/context evidence does not supply application policy or key lifecycle | [`security-responsibility-residual.md`](security-responsibility-residual.md) |
| Integrated security frontier | Bounded feasibility complete | Mandatory ES256+ML-DSA source objects, protected metadata, opaque relay/restart, replay/rekey/batch negatives and hybrid scaffold executed on a non-FIPS graph; no normative hybrid, distribution, rollback resistance, custody, independent interop, physical or production credit | [`integrated-security-profile.md`](integrated-security-profile.md), [`security-responsibility-residual.md`](security-responsibility-residual.md), [`security-profile-matrix.md`](security-profile-matrix.md) |

## Connectivity, discovery, and carrier arms

| Arm | State | Current disposition | Primary evidence |
|---|---|---|---|
| Iroh IP connectivity | Bounded topology complete | Conditional leader: local differential plus 13/13 upstream-supported relay-first/direct-upgrade namespace cases passed; three upstream-ignored hard-cross cases stayed relayed with zero direct. Physical/public Internet, secure-relay identity, ISP/CGN, endurance and production remain open | [`connectivity-comparison.md`](connectivity-comparison.md), [`rolling-results.md`](rolling-results.md) |
| rust-libp2p IP connectivity | Source/behavior hold | Local differential and static ownership screen only; advisory repair, automatic discovery, connection mapping, physical ownership, and a complete higher-level collapse runtime remain absent | [`connectivity-comparison.md`](connectivity-comparison.md) |
| Quinn/greenfield-native IP control | Narrow local control | Strong local rebind control and opaque carriage; discovery/NAT/relay/runtime/resource owners and complete higher-level collapse runtime remain absent | [`connectivity-comparison.md`](connectivity-comparison.md), [`cross-product checkpoint`](rolling-results.md) |
| Discovery and runtime admission | Complete policy arm | Buy provider/platform hint mechanics after physical qualification; retain a small common emission and hostile-admission gate | [`discovery-admission.md`](discovery-admission.md) |
| BTLE/tiny-MTU/broadcast/offline carrier | Mixed terminal | Common carrier envelope above thin adapters; 54/54 composition rows passed, 115/117 broadcast cells completed, physical CoreBluetooth was unsupported, and BlueR/TrouBLE/btleplug retain legal/graph/hardware holds | [`carrier-arm.md`](carrier-arm.md), [`phase5-product-surface-assurance.md`](phase5-product-surface-assurance.md) |

## Data-plane, policy, API, and assurance arms

| Arm | State | Current disposition | Primary evidence |
|---|---|---|---|
| Durable local store | Complete | Use redb as the selected research baseline's single small-state and accepted-item/effect transaction owner; do not place a second store beside it. SQLite remains a p2panda/Hardy component hold under the literal license policy | [`durable-store-component.md`](durable-store-component.md), [`final-stack-bakeoff.md`](final-stack-bakeoff.md) |
| Record CRDT | Complete | Buy Automerge only for explicitly opted-in JSON-like Record merge | [`record-crdt-automerge.md`](record-crdt-automerge.md) |
| Difference reconciliation | Complete | Buy Negentropy narrowly with a deterministic bulk fallback; not a replica engine | [`reconciliation-negentropy.md`](reconciliation-negentropy.md) |
| Blob identity/transfer/resume | Complete | Advance small transactional metadata plus streamed files; reject redb Blob-byte role; normative NIST-approved digest and full lifecycle remain open | [`blob-transfer-operating-envelope.md`](blob-transfer-operating-envelope.md) |
| Propagation/constrained policy | Complete model arm | One thin common mission-policy owner; reuse only selected-stack topic/QoS/lifetime/suppression primitives | [`propagation-policy-component.md`](propagation-policy-component.md) |
| SDK, FFI, local agent, observability, SBOM | Complete | Buy cbindgen/UniFFI and standard assurance tools; tonic optional; semantic API/ABI/lifecycle remain ours | [`sdk-ffi-control-plane.md`](sdk-ffi-control-plane.md) |
| Candidate-neutral conformance | Failure disposition | Buy CBOR/CDDL/parser mechanics only. Registered parser replayed 18/18; independent parser agreed on 13/18 because critical extension ID 1 is absent from the frozen CDDL/prose, so the profile and second-implementation gate remain open | [`conformance-profile-seed.md`](conformance-profile-seed.md), [`phase5-product-surface-assurance.md`](phase5-product-surface-assurance.md) |
| Greenfield integrated control | Bounded complete | The earlier local controls and the final authenticated-Iroh G corpus passed. G is the selected bounded research baseline; custom code still owns the normative frame/classes, durable session progression, policy, security and lifecycle | [`final-stack-bakeoff.md`](final-stack-bakeoff.md) |
| Final A-versus-G bakeoff | Bounded decisive complete | In the frozen one-host fixture, G passed every must-pass recovery, temporal and duplicate-effect cell. A preserved meaningful partial credit but did not complete the sequence across two terminal attempts. P2panda is demoted to conditional component/oracle; no production stack is selected | [`final-stack-bakeoff.md`](final-stack-bakeoff.md), [`comparison matrix`](../../../../docs/evaluations/0005/results/stack-comparison.csv) |
| Semantic/carrier cross-product | Bounded complete | P2panda and greenfield protected frames crossed Iroh and Quinn byte-exact in 4/4 local cells with restart/replay/negative controls; no topology or recon-over-carrier credit | [`cross-product checkpoint`](rolling-results.md) |

## Closure rule

No additional broad FOSS survey is required before the next decision. This is
a closure rule for the current research scope, not a claim of full Proposal
0005 conformance. The Phase 0 omissions and Phase 2 collapse lanes stay visible
until explicitly completed or waived. New research should be opened only by a
concrete gate: a newly identified maintained component, an upstream
security/release change, or a surviving composition's specific unowned hard
requirement. Physical qualification, target admission, stakeholder choices,
and second-implementation work remain engineering and release gates.

The combined architecture disposition is
[`final-frontier.md`](final-frontier.md).
