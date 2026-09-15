# Capability roadmap

- Status date: 2026-09-15
- Product-intent authority: [`data-mesh-requirements.md`](../../data-mesh-requirements.md)
- Security-profile applicability:
  [`security-profile-requirements-disposition.md`](security-profile-requirements-disposition.md)
- Evidence authority: [`requirements-status.md`](requirements-status.md)
- Atomic trace: [`requirements-implementation.csv`](requirements-implementation.csv)
- Current release posture: **evaluation-stage; not production-authorized**

## Purpose

This is the planning and review view of the data-mesh requirements. It groups
the draft target state into demonstrable product outcomes so that progress can
be evaluated without treating the 348-row atomic trace as a flat backlog or a
percentage-complete score.

The hash-bound requirements document remains the provenance baseline. Reviewed
decisions may refine a row's current applicability without rewriting that
baseline; the accepted security-profile overlay does so for metadata and
post-quantum policy. This roadmap does not itself waive a requirement or
advance implementation credit. It defines how work is sequenced and reviewed.
For planning purposes,
the aggregate scope in requirements §§11–13 is called the **complete MVP target
product profile**; incremental PRs and explicitly bounded evaluation profiles
may advance toward it without claiming it complete.

The atomic trace remains useful for stable IDs, exact evidence, duplicated
phase obligations, external gates, and future work. A single capability can
move several rows, and several rows can restate the same outcome. Conversely,
the presence of a mechanism can move a row without completing the user-visible
capability. Capability maturity therefore follows the weakest material gap in
the outcome, not an average of row statuses.

## Maturity vocabulary

| Maturity | Planning meaning |
|---|---|
| **Demonstrated — bounded** | The selected composition produced reproducible evidence for the stated environment and claim boundary. This is not general release evidence. |
| **Implemented — evidence pending** | Material mechanisms and automated tests exist, but the end-to-end outcome lacks retained or representative evidence. |
| **Partial** | Useful parts exist, but a material user-visible, operational, or cross-component path is absent. |
| **Open** | The selected composition does not yet provide the outcome. |
| **External decision/gate** | Completion depends on stakeholder policy, target systems, independent work, or an admitted external component rather than only repository implementation. |

These maturity labels summarize outcomes. They do not replace the conservative
`observed-bounded`, `implemented-uncredited`, and `open` values in the atomic
trace.

## How to treat the 348 atomic rows

The source document is still a draft, and atomization is not stakeholder
ratification. Keep every row traceable until it is affirmed, revised, deferred,
or rejected through a reviewed profile or decision record, but do not turn all
rows into engineering tickets:

- core security, correctness, and compatibility invariants constrain any
  capability to which they apply;
- capability statements describe target outcomes and should be planned in
  coherent groups;
- acceptance and deliverable rows often restate those outcomes and define
  evidence, rather than adding separate product features;
- assumptions, non-goals, provisional values, and open stakeholder choices are
  constraints or decisions, not implementation tasks by themselves; and
- Post-MVP and Future rows stay visible without entering the current merge
  queue unless a named profile pulls them forward.

When a requirement is no longer credible, record the decision and applicability
explicitly; do not manufacture implementation work merely to close its row.

## Execution model

Planning is dependency-aware rather than a serial march through feature areas:

- a named profile and its unresolved decision register form the **P0 gate**;
- causal/lifecycle correctness, executable conformance, operational security,
  and physical carrier risk are **parallel P1 tracks** after that gate;
- scope/bridge policy, representative DDIL/resource fitness, and the adopter
  surface are **P2 integration tracks** built on the relevant P1 contracts; and
- independent review, packaging, dependency admission, and signed disposition
  form the **P3 release gate** for the exact profile under review.

A priority band is not an evidence status, and crossing a planning gate does not
move an atomic requirement. Focused increments may merge before a whole track
exits, but each increment must name its profile or maintenance boundary, the
track and measurable exit criterion it advances, its unresolved dependencies,
and the owner of any external decision or evidence gate. Foundational contracts
must stabilize before dependent public interfaces are frozen, while long-lead
physical and independent evidence work should begin as soon as its inputs are
defined.

## Adopted security-profile direction

[Decision 0033](../decisions/0033-policy-selected-security-profiles.md) and its
[requirements disposition](security-profile-requirements-disposition.md) make
metadata exposure and post-quantum use explicit profile policy:

- source payload encryption/authentication, payload-blind forwarding, Aster
  mission authorization, plaintext minimization, agility, and downgrade
  resistance remain profile-invariant;
- a secure carrier may protect ephemeral contact metadata, while persistent
  forwarding metadata is independently protected where practical and every
  unavoidable exposure is declared;
- complete classical and hybrid-PQ profiles are target capabilities, with
  mission policy setting the minimum and required PQ failing closed; and
- suite/profile `0x0001` keeps all of its hybrid components and wire meanings;
  additive profile `0x0002` now implements a semantic-v1 classical Event/control
  and Iroh-exporter-bound two-node mission path without changing the stock
  selected runtime.

Profile `0x0002` includes provisioned singleton selection, exact mixed-profile
failure, a local durable profile/generation binding, declared metadata exposure,
and same-implementation tests. Runtime/CLI selection, representative capture,
compute/memory/energy evidence, snapshot-resistant rollback, retained receipts,
and release authorization remain open. Existing evidence statuses do not move.

## Current capability outcomes

| Outcome | Current maturity | Demonstrable progress | Next material outcome | Explicitly not claimed |
|---|---|---|---|---|
| **Causal correctness and bounded data lifecycle** | **Partial** | The selected lane retains bounded direct-observation causal schedules, class-specific limits, Linux Event custody age/expiry/quota evidence, and focused transactional rollback/restart mechanisms. The [current schema](../protocol.md#7-causality) deliberately does not provide complete transitive causality; aggregate frontier, accepted-dot, and Event-sequence ledgers lack aggregate bounds and retirement protocols, and selected State/Record/Blob finite lifecycle is open. | Before broader multi-hop mutable or bridge claims, record the accepted causality/trust and authenticated checkpoint/retirement design; then implement cross-class TTL, tombstone and staging retention, garbage collection, and pressure behavior with crash and long-partition tests. | Complete transitive causality, bounded aggregate causal history, finite State/Record/Blob retention, complete process-crash/power-loss recovery, long-offline recovery, difference-proportional local work, or release acceptance. |
| **Scope, bridge, and propagation policy** | **Implemented — evidence pending** | Authenticated topics/scopes, explicit interests, Event Consume/Carry separation, route-only Event custody, and payload-blind relay mechanics now compose with the profile-`0x0001` selected Event bridge. Semantic v6 adds a typed, bounded live bridge lane; startup verifies one static complete authorization chain and local narrowing; receiver results follow durable commit; retained routes require fresh restart promotion; authenticated-peer route grants filter outbound target scopes; and bounded per-peer rotation prevents an eight-route contact batch from permanently starving later routes. An opt-in five-node Compose topology crosses isolated alpha, parent, and bravo IP segments through two multi-homed route-only bridges with no configured peer coordinates. | Retain the exact multi-scope execution boundary, then add supported join/leave administration, bandwidth and complete storage quotas, dynamic routing/interest policy, revocation/rekey behavior, and bounded current-policy replacement before broader scale work. | A supported bridge administration surface, dynamic hierarchy lifecycle, cross-class bridge custody, retained bridged-scale or hostile-input evidence, physical/mixed operation, 100-node-per-scope or 1,000-node bridged capacity, or complete-MVP credit. |
| **Representative DDIL and target-resource fitness** | **Open** | Bounded one-host receipts cover selected N=32 Event operation, Linux Event custody behavior, brief forced-process delivery recovery, and a 96-KiB interrupted Blob transfer; component limits and impairment tests provide a measurement foundation. [Current inventory-selection evidence](conformance.md#implemented-reliability-and-resource-subgates) shows that local construction examines the total selected snapshot and allocates source descriptors first, so at the 100,000-item ceiling it can leave no room for Blob carrier IDs. | Ratify the profile's target platforms and operating brackets, instrument them continuously, and obtain retained long-offline, crash/power-loss, mobility/outage, bandwidth/loss, scale, storage, binary/RSS/CPU, idle, and energy evidence. | Stakeholder-confirmed thresholds, target-hardware acceptance, at-least-100-node scope operation, bridged scale, 3-kbps/50%-loss usefulness, long custody, large-Blob/RSS behavior, or production fitness. |
| **Authenticated offline-first Event exchange** | **Demonstrated — bounded** | Selected nodes publish while disconnected, reconcile source-authenticated Events over direct Iroh contacts, and expose live Rust and local ConnectRPC application paths with durable delivery/custody mechanics. The [9,573-byte signed-source receipt](evidence/selected-live-event-c464129.json) observes three peerless alpha Events plus one authorized beta Event, threshold delivery of alpha sequences 1 and 3 with authenticated gap `[2,3)`, forced receiver-child termination after a flushed unacknowledged poll, fresh-process attempt-2 redelivery with ack/re-ack, and normal sequence-2 gap closure on one same-implementation loopback host. Beta is withheld; a temporary subscription observes `PolicyChangedSinceContact` and is removed without a later contact or delivery. | Turn the bounded Event path into a named supported evaluation profile across declared platforms and network conditions; add positive failed-contact observation and fresh post-policy completion/delivery evidence. | Physical or representative network convergence, NAT/Internet, relay, BTLE, mixed or independent implementations, scale/resource/soak evidence, positive failed-contact propagation, post-policy beta delivery, other-class acceptance, reproducible source-to-execution proof, or production authorization. |
| **Intermittent store-and-forward relay and membership recovery** | **Demonstrated — bounded** | Controlled payload-blind Event relay, temporal custody, mission-authenticated contacts, revocation propagation, explicit rekey, and bounded zeroization have retained or current-code evidence. The [4,377-byte signed-source Linux custody receipt](evidence/selected-linux-event-custody-ade6ee1.json) additionally observes exact route-only Event quota pressure, two Linux-boottime expiries, priority-ordered store-and-forward, and ReceiveOnly ingestion in one loopback container. | Demonstrate the complete operational workflow with representative partitions, protected provisioning, target systems, and declared relay trust. | Automatic/atomic revoke-plus-rekey, route-only custody for every class, platform-complete erasure, physical constrained-link acceptance, mixed implementations, or hostile-field acceptance. |
| **State and Record convergence without silent conflict loss** | **Demonstrated — bounded** | Source-authenticated State and Record objects publish peerless through cloneable live handles and reconcile directly. The [7,752-byte signed-source v2 receipt](evidence/selected-live-mutable-6cabb4c.json) retains exact concurrent State heads, a causally later successor, and an authenticated empty tombstone through one immediate peerless restart, while Record retains explicit siblings through guarded resolution and restart. A separate [9,656-byte signed-source State-delivery receipt](evidence/selected-live-state-subscription-8912fc3.json) observes one durable application subscription across three processes, forced receiver-process replacement, attempt-2 redelivery and acknowledgement, selector withholding, causal ancestor suppression, a current tombstone, and one final peerless reopen. A separate [10,357-byte signed-source Record-delivery receipt](evidence/selected-live-record-subscription-0c11344.json) observes the complete active-head set as one delivery, forced-process attempt-2 redelivery, guarded resolution and a successor projection, selector separation, and final peerless reopen on one same-implementation direct-loopback host. | First close the causality/frontier-retirement and finite-lifecycle contracts that govern multi-hop and long-partition behavior; decide any materialized-view/withdrawal and deterministic registered-merge semantics; then broaden representative relay, physical, mixed, and resource evidence before freezing bindings. | Indefinite tombstone retention, garbage collection, delete-wins, materialized State-view convergence, synthetic withdrawal delivery, State contact/status behavior, dynamic network-interest mutation, selected-node bindings, finite-TTL forwarding age, automatic registered-policy merge, temporal relay coverage, physical/mixed acceptance, scale beyond two, resource thresholds, long-partition acceptance, or release authorization. |
| **Authenticated resumable Blob movement** | **Demonstrated — bounded** | The selected composition has authenticated immutable publication, a cloneable actor-owned live Blob handle for bounded regular-file publication and zeroize-on-drop paged reads, a durable metadata-only application-delivery ledger keyed by exact source publication, bounded-memory encrypted depot streaming, and semantic-v5 direct source-before-carrier range transfer with durable resume state. A [signed-source retained transfer receipt](evidence/selected-live-blob-044d90f.json) observes one peerless-published 96-KiB two-chunk Blob, direct seeding to a replica, a 16-KiB non-public receiver prefix retained across graceful same-process reopen, one-contact continuation from that different eligible peer without source refetch, exact reconstruction, authenticated receiver reads, and final graceful reopen on one same-implementation loopback host. A separate [10,269-byte signed-source delivery receipt](evidence/selected-live-blob-subscription-26e0a09.json) observes two exact publications sharing one `BlobId`, finalized depot variant, and committed chunk; a flushed attempt-one poll, forced receiver `SIGKILL`, attempt-two token rotation, earlier same-tenure token acknowledgement/reacknowledgement, and final empty local-ledger status across three processes/four actor lifetimes on one peerless host. | Define class-specific status, retention, staging cleanup, and fair inventory/custody behavior first; then retain process/crash and long-offline recovery plus network-selector separation, arbitrary-peer/route-only continuation, large-object/RSS, relay, physical, and mixed evidence. | Network contact/transfer or selector-withholding/network-interest-separation delivery acceptance, peer/convergence or transfer-progress status, process-crash/power-loss or long-offline recovery, arbitrary-peer or route-only Blob resume/custody, full TTL/GC policy, large-target/RSS acceptance, mixed implementations, physical systems, or all-carrier transfer. |
| **Reachability and carrier portability** | **Partial** | Manually admitted direct IP contacts and an explicitly configured controlled HTTPS relay work behind one transport abstraction. Default-off, time-boxed nearby discovery has separate rostered and rosterless `--discover-lan` modes plus explicit bounded IPv4-interface selection for multi-homed nodes. Rosterless observations remain untrusted carrier locator candidates; the stock mission handshake independently authenticates and authorizes the mission identity before inventory. Focused mechanism tests, runnable quickstarts, and opt-in same-host Compose evaluations exist without retained physical discovery or resource credit. | Retain the complete rosterless advertise-to-Event-delivery and different-authority-rejection chain on physical hosts; hard-bound or replace all upstream discovery state and qualify packet/resource behavior; then physically qualify the declared IP/NAT and controlled-relay profile and run a small-MTU BTLE Event slice before broader all-class and cross-transport acceptance. | Physical or hostile-LAN-qualified automatic discovery, carrier-to-mission common-ownership proof in stock profile `0x0001`, infrastructure-free NAT traversal, default/public relay dependence, selected-node BTLE platform integration, protected broadcast/repair, multi-carrier failover, or RF broadcast efficiency. |
| **Mission security and operator lifecycle** | **Partial** | Profile `0x0001` provides the stock hybrid-PQ mission/source/control path. Additive profile `0x0002` provides exact provisioned policy, P-256 semantic-v1 Event/control protection, a distinct Iroh ALPN and TLS-exporter-bound four-flight mission path, raw QUIC application frames, local profile-generation store binding, and same-implementation mismatch tests. No retained evidence status moves. | Select the named profile and admitted operational backend, carry protected startup and administration through the stock runtime/CLI, add rollback-resistant policy state and coordinated recovery/destruction, and prove provision/run/revoke/rekey/recover/zeroize with profile-specific capture and resource evidence. | PQ-free distribution/code-size result, profile `0x0002` State/Record/Blob/batch/bridge/rekey, target resource/energy result, retained or mixed-implementation evidence, FIPS-path closure, hardware custody, physical sanitization, complete metadata-exposure acceptance, or production authority. |
| **Embeddable developer surface** | **Partial** | Event, State, Record, and Blob have cloneable live Rust handles; Event has durable stream delivery, State has retained bounded evidence for durable positive-current-version delivery, Record has retained-bounded durable whole-key active-head delivery, and Blob has retained-bounded peerless metadata-only exact-publication delivery plus bounded file publication and authenticated plaintext pages. Event alone has contact status plus a local ConnectRPC API. All four classes retain stopped facades. The retained State/Record/Blob acceptance producers are outside the adopter API and are not minimal developer samples or usability studies. | Select the profile's binding targets and keep minimal compiled Rust samples as contract probes; after the applicable lifecycle, security, status, and policy contracts stabilize, add the selected-node C ABI, first-class bindings, protected administration surface, and independent usability evidence. | Complete four-class peer/status/binding set, networked/selector-separated Blob delivery acceptance, State status/materialized-view/withdrawal behavior if required, dynamic State/Record/Blob network-interest mutation, binding template, protected stock agent administration, independent usability, or the provisional one-day integration target. |
| **Normative protocol and executable conformance** | **Partial** | Versioned selected wire/profile documents, checked-in profile-`0x0001` corpora, a self-runner, compatibility rules, and extensive same-implementation tests provide a foundation. | Treat conformance as a continuous P1 track: freeze the named-profile normative subset, ship an executable black-box SUT contract, runner, and profile-specific vectors, cover highest-common-version, ignorable-extension and downgrade behavior, and appoint the independent implementation owner early. | Complete profile-`0x0002` grammar/vectors/captures, an independently specification-built implementation passing the applicable suite, mixed-version acceptance, or complete MVP conformance. |
| **Release assurance and authorization** | **Open** | Dependency policy, an SBOM path, CI/fuzz gates, retained bounded receipts, and the release-profile checklist provide a foundation. | After applicable P1/P2 exits, close supported-target packaging, resource and physical acceptance, dependency/license/SBOM admission, independent security and interoperability review, reproducible source-to-artifact evidence, deprecation policy, and signed disposition for the exact profile. | A supported release artifact, complete dependency admission, independent review, representative profile acceptance, or production authorization. |

The Record receipt above is 10,357 bytes, has SHA-256
`ba0e2bf47291f7e87000b85fa280cc957f3710ac800def82a51fb9b4657a1b48`,
and binds Good-signed source commit `0c1134411953f4bb52133b50aff9989cd4ce3930`.
Its bounded run uses two participants, three processes, and seven actor
lifetimes. It retains a complete two-head edit/tombstone conflict as one delivery
at `delivery_limit=1` and `scan_limit=16`, then sends the receiver `SIGKILL`
after its flushed durable unacknowledged attempt-one poll. A fresh process gets
the same projection at attempt two with a rotated 89-byte token. A fresh exact
query guard resolves both heads, a new successor projection is delivered, and
both originals remain query-only superseded history. Beta is
network-interested/application-unmatched and retained without delivery; gamma is
application-matched/network-uninterested and withheld, and the subscription does
not mutate network interest. A final peerless reopen replays the subscription
with an empty acknowledged queue, the resolved current successor, and the two
query-only originals.

Only `DM-5.1-08` moves. `DM-7-11`, `DM-7-14`, `DM-7-15`, and
`DM-7-18` remain implemented-uncredited; `DM-7-20` is unchanged. The receipt
adds no finite-TTL/GC, physical/NAT/relay/BTLE, mixed-implementation,
scale/resource/soak, selected-node bindings, automatic-merge, reproducible
source-to-binary proof, or release credit.

The Blob-delivery receipt above is 10,269 bytes, has SHA-256
`3d0c0b2da629282c56de5ae9dacc8920c9960defba083c6bff856e2c0612a675`,
and binds Good-signed source commit
`26e0a090b9a6f644d96b38cfaa23f4e2139ad8b1`. Its 35-record peerless run uses
one host and participant, three processes, and four actor lifetimes: three stop
gracefully and one receiver child is sent `SIGKILL` after a flushed
unacknowledged poll. Two exact source publications share one immutable
`BlobId`, finalized depot variant, and committed chunk but remain separate
deliveries. Attempt one rotates to attempt two after process replacement; the
restored earlier same-tenure token acknowledges and reacknowledges the pending
publication, the second publication is separately acknowledged/reacknowledged,
and final peerless reopen reports an empty local ledger.

Only `DM-5.3-04` moves, producing 43 implemented-uncredited, 84
observed-bounded, and 221 open rows; the DM-5 roll-up is 21/50/51. The receipt
adds no network contact/transfer/synchronization, selector-withholding or
network-interest-separation, peer status, TTL/GC, plaintext/read, physical or
mixed-system, scale/resource, reproducible-build, or release credit.

## Prioritized capability actions

Priority describes dependency leverage and risk reduction. It is not maturity,
evidence credit, requirement applicability, or a promise of strict serial
execution. The IDs below are stable planning labels, not atomic requirement IDs.

| ID | Priority | Capability action | Dependencies | Measurable exit criterion |
|---|---|---|---|---|
| **P0-1** | **P0 — define the claim boundary** | Record one bounded evaluation profile and decision register. | The hash-bound requirements baseline and adopted security-profile policy; no new implementation prerequisite. | A reviewed profile names intended users/use case, declared target platforms and device tiers, carriers/topology, included data classes and APIs, exact permitted security profiles, authenticated mission-policy minimum, rollback policy, metadata budget, operating/resource assumptions, binding choices, applicable acceptance evidence, and exclusions. Every decision needed to define or evaluate that claim boundary, including applicable provisional and `DM-14` matters, is resolved or the affected capability is explicitly excluded. Only production-only, out-of-profile, or demonstrably nonblocking matters may remain provisional, deferred, or unresolved, each with an owner, target decision date, and blocking status. The literal `DM-8-05` dependency-license mismatch retains an owned disposition or technical-alternative path. |
| **P1-1** | **P1 — retire foundational risk** | Close causal correctness and cross-class lifecycle design and implementation. | P0 retention and operating assumptions; reviewed decisions before freezing affected wire/storage contracts. | Across all profile-included classes and platforms, A-to-B-to-C, long-partition, retirement/rejoin, pressure, process-crash/power-loss, and restart/fault tests establish the intended ordering and bounded metadata behavior. Finite retention, crash-safe garbage collection, and ledger retirement cover Event, State, Record, Blob, tombstones, staging state, accepted-dot/frontier/Event-sequence state, and cross-class priority pressure without silent durable-data loss outside declared policy. |
| **P1-2** | **P1 — retire foundational risk** | Make normative specification and executable conformance continuous. | P0 profile plus stable Event wire and security-profile identifiers; Event harness and vector work may proceed from P0, while freezing State/Record/Blob causal or lifecycle grammar depends on the applicable P1-1 decisions. | A shipped black-box SUT contract, runner, vectors, and named-profile coverage exercise normative grammar, highest-common-version selection, unknown-but-ignorable extensions, and downgrade rejection. Independent implementation acceptance remains a separately owned external P3 gate. |
| **P1-3** | **P1 — retire foundational risk** | Operationalize the security and operator lifecycle. | P0 platform/security choices and an early, scoped backend-selection/admission decision sufficient for evaluation; final full-graph admission and independent review remain P3 gates. | The declared target performs protected provision, start/restart, recovery, revoke/rekey, terminalization, and provider destruction through supported runtime/administration surfaces; policy/profile mismatch and rollback fail closed; representative capture stays within the declared exposure budget; retained resource results cover the claimed security profile. |
| **P1-4** | **P1 — retire foundational risk** | Select and stabilize the multi-carrier contract while executing physical IP and BTLE vertical slices in parallel. | P0 platforms/topology, a stable Event/security harness, and target hardware/environment availability. | A stable selected carrier contract is exercised by physical target devices that mutually authenticate and exchange a protected Event larger than the smallest supported BTLE MTU. Bounded fragmentation/reassembly is exercised under duplicate, reorder, truncation/loss, disconnect/reconnect, and resume, and the receiving application verifies consumption after switching from BTLE to IP. Representative NAT direct/fallback and controlled-relay paths have retained evidence, with discovery and emission behavior bounded to the profile. |
| **P2-1** | **P2 — complete and integrate capabilities** | Deliver the selected scope, bridge, and policy lifecycle. | P1-1, P1-3, and applicable P1-2 normative decisions; P1-4 only for physical bridge claims. | A retained multi-scope scenario through the selected supported runtime and administration surface exercises join/leave administration, topic/priority filtering, payload-blind forwarding, bandwidth/storage quotas, loop suppression, dynamic policy change, and revocation/rekey. An explicit authorized/unauthorized matrix observes no unauthorized application delivery in its enumerated negative cases within the declared topology. |
| **P2-2** | **P2 — complete and integrate capabilities** | Retire DDIL, inventory, crash-recovery, and scale risks. | P0 target assumptions plus the relevant P1 lifecycle and carrier contracts. | Use the generated [bounded hierarchy scale diagnostic](../quickstart/hierarchy-scale.md) as the next measurement instrument for static Event fan-out, multi-batch progress, small local peer domains, resource behavior, and acknowledged-route duplicate offers; it changes no maturity or retained-evidence status. At cap and cap-plus-one mixed workloads, including the current 100,000-source starvation case, a bounded local inventory reserves or fairly allocates capacity so Blob carrier IDs make progress. Retained measurements show local inventory construction and anti-entropy work proportional to the difference within declared bounds; retaining the [current total-snapshot work](../protocol.md#9-exact-reconciliation-and-resumption) instead requires a stakeholder-reviewed requirements/applicability disposition and corresponding narrower claim. Long-offline and crash/power-loss recovery, large-Blob/RSS behavior, impairment, storage, CPU, idle, and energy gates pass on declared targets at the profile's ratified bounds. |
| **P2-3** | **P2 — complete and integrate capabilities** | Freeze and validate the adopter surface. | P0 binding choices and a stakeholder-ratified usability target; stable applicable P1 lifecycle/security contracts; and applicable P2-1 policy plus P2-2 status/resource decisions. Samples, status probes, and exploratory studies may advance earlier without closing the target. | For the complete-MVP adopter outcome, the selected-node C ABI and selected first-class bindings expose Event, State, Record, Blob, and required status without transport or cryptographic internals. Independent developers complete the minimal sample within the ratified usability target. A narrower evaluation profile may ship an explicitly named subset without claiming this track complete. |
| **P3-1** | **P3 — close a production candidate** | Close the complete-MVP production profile. | Every applicable complete-MVP capability exit; every baseline, MVP, and release trace row marked as a [final-stack invariant](requirements-matrix-notes.md#final_stack_invariant); and every production-blocking external gate, unless a separately reviewed requirements disposition changes applicability. | An independently specification-built implementation passes the applicable conformance suite; independent cryptographic review and hostile-peer campaigns pass; the profile-specific FIPS/validated-module disposition and a reviewed `DM-8-05` disposition or technical alternative are recorded; full-graph SBOM/license admission, supported and reproducible packages, deprecation policy, representative physical/resource acceptance, and signed release authorization are complete for the exact production profile. |

### Active post-hierarchy implementation lanes

The two bridge increments below remain ordered within the bridge lane, but they
are not a global serialization point for customer-readiness work. The first
customer MVP is single-scope and Event-only, uses exact manually admitted peers,
and permits at most one customer-controlled pinned connectivity relay. It does
not include multi-scope forwarding, dynamic bridge administration, or bridge
route computation.

The customer-operable Event service, deployment artifacts, protected
provisioning, and release-gate work may therefore proceed in parallel under
their own claim and acceptance boundaries. Increasing the fixed Docker tree
beyond the [bounded hierarchy scale diagnostic](../quickstart/hierarchy-scale.md)
remains explicitly outside the next bridge-lane action.

1. **Next — bounded dynamic semantic-v6 Event-bridge configuration.** Add one
   privileged in-process operation that atomically replaces the complete bridge
   configuration at a monotonic durable generation. Every update re-verifies
   the signed authorization chain, local edges, narrowing, limits, and current
   mission policy. Duplicate retries recover the same receipt; stale, rollback,
   malformed, foreign-authority, and over-limit updates fail without changing
   the prior generation; an in-flight contact stops using a generation once it
   changes; restart restores only the latest committed generation.

   The bounded acceptance scenario starts with one required edge absent and
   proves non-delivery, adds that authorized edge and delivers one allowed Event
   across exactly two payload-blind hops, then removes the edge and proves a
   newly published Event cannot cross. Topic denial remains enforced, restart
   preserves the removal, and crash-before-commit, duplicate-retry,
   stale-generation, foreign-authorization, and limit failures leave the prior
   configuration unchanged. This increment does not add general credential
   issuance, full member join/leave, automatic route computation, quotas,
   revocation/rekey of already committed downstream data, cross-class bridging,
   external administration IPC/bindings, broader scale, or `P2-1` completion.

2. **Then — peer-, generation-, and receiver-state-bound static Event-bridge
   difference work.** Replace repeated whole-route offers with bounded
   reconciliation state tied to the authenticated peer, the durable bridge
   policy generation, and an authenticated receiver-store incarnation or
   equivalent exact reset/inventory proof. A focused single-peer receipt varies
   retained routes through 0, 8, 64, 255, and 256. After initial
   acknowledgement, three completed unchanged authenticated contacts at each
   size must report zero eligible route rows examined, zero route offers, and
   zero route applies. Adding one eligible route from the 0-, 8-, 64-, and
   255-route baselines must examine, offer, and apply exactly that one
   difference. At 257 eligible routes, preparation fails with a typed capacity
   result without mutating durable peer progress or receipt state. A receiver
   rebuilt with the same peer identity and policy generation but a new
   authenticated store incarnation or reset proof refetches safely; same-store
   restart remains quiescent; wrong-peer, wrong-generation, wrong-incarnation,
   stale, and malformed receipts cannot advance progress.

   The existing 64-publisher hierarchy must still deliver and peerlessly recover
   all 64 allowed routes, promote 32 through each regional bridge, and report
   both `totalOfferReceiptDelta=0` and `duplicateOfferDelta=0` after settling.

   This second increment does not establish all-class difference proportionality,
   complete `DM-5.2-18`, dynamic membership, a topology larger than the current
   diagnostic, target-resource fitness, production capacity, or release credit.

The two numbered bridge increments above must remain in order relative to each
other. They do not block the single-scope customer-operable Event-service
increment.

`P1-1` through `P1-4` are parallel lanes after `P0-1`. A lane may merge
coherent intermediate increments without satisfying its entire exit criterion
when the PR preserves the narrower claim boundary. P2 work need not wait for an
unrelated P1 gate, but it must not freeze a public, wire, storage, or security
contract whose relevant P1 decision remains unresolved. Future, Post-MVP, and
external-gate rows do not enter the immediate queue unless the named profile
pulls them forward.

After `P0-1`, an externally owned, independently authored Event exchange may run
early as a non-credit risk milestone. It does not satisfy the `P1-2` engineering
exit or the `P3-1` independent-implementation gate.

## PR review and merge standard

A PR should identify its named profile or maintenance boundary, priority action,
capability outcome, and the measurable exit criterion it advances. It must still
distinguish a mechanism from an end-to-end result. Review should answer:

1. Does the change name the profile, priority action, and exit criterion it
   advances, or explain why it is bounded maintenance outside that register?
2. Does it make a coherent, usable, or risk-reducing increment toward the named
   outcome?
3. Are its claims no broader than its code, tests, environment, and retained
   evidence?
4. Are cross-track dependencies, unresolved stakeholder choices, physical or
   independent gates, owners, and exclusions explicit rather than silently
   decided?
5. Does it preserve applicable security, causal/lifecycle, scope, compatibility,
   resource, and ownership invariants?
6. Are regressions and important failure modes tested in proportion to risk?
7. If the evidence boundary changed, are the exact atomic IDs and remaining
   gaps updated conservatively?

A “yes” does not require the PR to close every row associated with the outcome,
or any unrelated target-profile, future, provisional, stakeholder, or external
gate. A PR must not claim the outcome complete merely because a mechanism exists
or a row moved to `implemented-uncredited`.

## Evaluation and release profiles

`P0-1` records a bounded evaluation profile before evidence is aggregated into a
supported evaluation claim. Before creating a production release candidate,
supersede it through a reviewed, traceable production profile while retaining
the prior profile and its evidence boundary. The production profile contains:

- intended users and use case;
- supported platforms, carriers, topology, and operating bounds;
- included capability outcomes, public APIs, and selected bindings;
- normative protocol/conformance versions and applicable vectors;
- applicable security/correctness invariants and acceptance scenarios;
- exact permitted security profiles, authenticated mission-policy minimum and
  rollback policy,
  metadata-exposure budget, connection-idle behavior, and resource/energy bounds;
- required artifacts, independent evidence, and external approvals;
- explicit exclusions and upgrade/compatibility expectations; and
- every unresolved decision or gate with an owner, target disposition date, and
  statement of whether it blocks evaluation, production, or neither.

An **evaluation profile** may intentionally cover a bounded subset and must say
so. Subset scoping is evaluation-only. A **production profile** includes every
applicable baseline, MVP, and release obligation marked as a final-stack
invariant unless a separately reviewed requirements disposition changes
applicability; roadmap exclusions cannot narrow that boundary. Post-MVP work
remains scheduled unless the named profile pulls it forward. The **complete MVP
target product profile** is the broad target in §§11–13 of the requirements
document; it is not the default gate for every incremental merge or partial
evaluation release.

No production release profile is currently authorized.
