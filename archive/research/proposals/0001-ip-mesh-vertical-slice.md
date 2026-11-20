# Proposal 0001: Operational IP mesh vertical-slice experiment


- Status: completed — no production winner; no dependency admitted
- Date: 2026-08-21
- Owner: Aster Clean Team — execution authorized in the designated project
  task on 2026-08-21
- Decision target: a new architecture decision after the experiment
- Proposed execution cap: 30 engineer-days after acceptance; this is a stop
  limit, not an effort estimate
- Requirements exercised, not closed: §5.6–§5.8; §6 transport boundary; §7
  sync/peer status; §8 dependency/interoperability constraints; §9 resource
  targets; §12 relay, NAT, and capture scenarios
- Related decisions: [0002](../decisions/0002-dependency-admission.md),
  [0007](../decisions/0007-ip-and-btle-links.md),
  0014 (“Build versus buy is governed by total assurance cost”;  not part of this repository artifact),
  0015 (“Delete custom mechanism behind narrow library-backed seams”; not part of this repository artifact), and
  0016 (“Tokio owns relay host I/O and scheduling”; not
  part of this repository artifact)

## Activation record — 2026-08-21

Execution is authorized from starting baseline
`9a8a87e11785c98fd1069cb2338c4076f4c728cb`, with requirements SHA-256
`e88bcc6c717a5175a460205fdc084aaa2e1f020a142a84087f9881677da02987`.
Every run must additionally record the exact experiment commit and worktree
state used to produce it.

The following provisional choices close the proposal's execution questions
without deciding the eventual production profile:

- stable carrier identities may be exposed inside the isolated experiment and
  must be measured; production acceptability remains a result-ADR decision;
- the clean LAN handoff timeout is 60 seconds per A→B or B→C contact, while
  the impaired 3 kbps/50%-loss bound remains ten minutes;
- settled automatic-discovery traffic must average no more than 4 KiB per node
  per minute after a two-minute settling interval, measured including UDP/IP
  headers but excluding link-layer framing;
- the provisional binary, RAM, and idle-CPU screening thresholds stated below
  are accepted for this experiment, not ratified as product requirements;
- the first host must support at least two simultaneous authenticated Aster
  contacts at B, with a configurable bound; the staged offline custody path is
  still tested separately;
- the NAT profile uses two independently translated node networks and one
  separately isolated, locally controlled rendezvous/connectivity-relay
  network; it must test direct traversal first and forced relay fallback;
- the first integration is an embedded Rust host plus the `aster-lab`
  demonstration; non-Rust bindings remain a measured follow-on gap; and
- a production-eligible dependency must have an exact transitive SBOM and
  license/advisory review, a usable private vulnerability-reporting route,
  published support expectations, and a named Aster update owner. Missing
  evidence may block production selection but does not abort technical trials.

## Summary

This experiment asks which implementation strategy, if any, gives Aster an
operational IP mesh host at the lowest total assurance cost. The selected
strategy must let independently running nodes discover candidates, then
authenticate and authorize provisioned peers, accept inbound contacts, maintain
and schedule multiple peer relationships, traverse NAT where possible, use
locally controlled connectivity relay fallback, and carry Aster's existing
durable synchronization protocol unchanged.

The primary proof is a three-process vertical slice:

1. A publishes a command-sized Event while C is absent.
2. B discovers A, authenticates it, and durably retains the source item.
3. A stops and B restarts from the same durable store.
4. C appears without knowing B's IP address or port.
5. B and C discover and authenticate one another.
6. C receives the same A-authored ItemID and application-acknowledges it.

A and C must never have a carrier path. B must be a route-only durable Aster
node that cannot consume the payload. This distinguishes actual intermittent
store-and-forward from a live TCP/QUIC relay or an in-memory scale simulation.

The result may select the native mesh-host enhancement, core Iroh, a minimal
rust-libp2p profile, or none. Quinn is measured only as a narrow direct-carrier
control. The proposal does not preselect a dependency.

## Decision question

Which bounded IP host/connectivity profile can satisfy the vertical slice while:

- preserving Aster's mission identity, authorization, wire protocol, durable
  store, source encryption, anti-entropy, priority, TTL, and delivery semantics;
- deleting or avoiding more custom connectivity machinery than it adds in
  integration and supply-chain assurance;
- remaining operable on a local network without any public hosted service;
- fitting the provisional Tier-2 resource and impaired-link envelopes; and
- remaining replaceable behind a narrow host/carrier boundary?

If no arm passes every mandatory gate, the correct outcome is **none** plus a
precise statement of the missing requirement or design work.

## Baseline and problem statement

The current [carrier guide](../transports.md) describes a useful pairwise data
plane but not an autonomous mesh host:

- `MeshService` can configure several peer carriers but services one active
  authenticated contact at a time.
- The embedding selects a known peer with `begin_sync(peer)` and drives the
  nonblocking host.
- IP discovery and rendezvous produce endpoint candidates; they do not enroll a
  peer, bind it permanently to a mission identity, or schedule a contact.
- A failed carrier is not automatically retried or failed over to another
  carrier.
- The live laboratory accepts one expected peer per node invocation and its
  current process-oriented demonstration is a two-node contact.
- The 1,000-node laboratory is valuable protocol/store-forward simulation. It
  is not evidence of 1,000 live IP processes discovering, connecting, failing
  over, or maintaining a mesh.

The core already contains the differentiating pieces that generic P2P stacks do
not provide: authenticated Aster sessions, protected durable objects,
topic/scope policy, route-only custody, exact item identity, peer-neutral
partial progress, and application delivery state. The experiment therefore
targets the missing operational layer rather than replacing the data model.

## Requirements and accepted constraints

The [source requirements](../../data-mesh-requirements.md) require:

- direct synchronization without a central server and indirect delivery through
  intermediate nodes;
- automatic discovery where a transport permits it plus manual/pre-provisioned
  peering;
- mutual authentication before data exchange;
- IP operation across NAT, direct where possible, with relay-assisted fallback
  that is not required for local mesh operation;
- relay nodes that can retain and forward without payload plaintext;
- protected payload and mesh metadata even when the carrier is untrusted;
- transport-neutral application operations and offline-first publication;
- bounded resources, configurable duty cycle, and no busy polling; and
- concrete relay, NAT, and capture-confidentiality acceptance evidence.

Independent-SUT interoperability remains a separate release gate. This
same-implementation host experiment neither exercises nor closes it.

Accepted decisions impose additional experiment rules:

- generic connectivity may be bought or wrapped, but Aster retains its mission
  semantics and implementation-independent wire authority;
- every candidate selected for production must pass provenance, licensing, fit,
  governance, exact-version, resource, reproducibility, and rollback gates;
- no experiment may leave Quinn, Iroh, rust-libp2p, and the native stack as
  overlapping production defaults; and
- a research result must identify the production mechanisms it would actually
  delete, not merely count wrapper lines.

## Non-negotiable invariants

Every arm uses the same:

- authority-issued Aster provisioning bundles and mission NodeIDs;
- Aster hybrid peer authentication and authorization;
- Aster source-encrypted objects and protected forwarding metadata;
- canonical Aster logical messages, envelopes, authentication, and semantic
  results; candidate carrier framing, packetization, retransmission, and stream
  delimiting may differ and are measured;
- SQLite-backed durable state and Blob state;
- synchronization, conflict, priority, TTL, custody, and application-delivery
  behavior;
- topology, workload, fault seeds, and measurement harness; and
- bounded redacted event vocabulary.

Carrier-layer credentials such as an Iroh `EndpointId` or libp2p `PeerId` may
authenticate a transport endpoint; socket addresses and discovery handles are
untrusted locators. Neither grants Aster membership or mission authorization.
Before Aster authentication, a channel may carry only bounded carrier setup and
Aster handshake traffic; application and synchronization data remain
prohibited. The host may then cache the observed NodeID↔carrier association
with provenance and expiry. A new or changed carrier identity inherits no prior
authorization and requires fresh Aster authentication; conflicting reuse across
NodeIDs fails closed. Where a profile has carrier keys, policy-controlled
rotation remains an explicit host operation.

The experiment uses two distinct relay terms:

- **durable mesh relay B** — an Aster node that keeps protected objects while
  endpoints are offline; and
- **connectivity relay R** — live, non-durable forwarding infrastructure that
  may retain bounded ephemeral reservations or connection state but never
  accepts Aster custody.

Discovery provider, NAT rendezvous/hole-punch coordination, connectivity relay
R, and durable Aster relay B are separate capabilities. One deployment service
may implement more than one generic connectivity capability, but its evidence
must not collapse those roles.

Neither Iroh Gossip nor libp2p Gossipsub, Kademlia records, or a connectivity
relay may replace Aster propagation, custody, or anti-entropy.

## Candidate arms

### 0. Sequential current control

Run the existing host without architectural enhancement: manually contact A↔B,
stop A, reopen B, then contact B↔C. This establishes the exact expected ItemID,
custody, restart, delivery, and acknowledgement result while preserving the
known discovery and host limitations. It is a data-plane control, not an
eligible operational-mesh winner.

This is also a Phase-0 prerequisite: B must be route-only, the source item must
be an Event, B must survive restart, B's application surface must not consume
the plaintext, and C must receive and acknowledge the original item. A records
the ItemID and source EnvelopeID; lab evidence proves B's custody of
that EnvelopeID; C recomputes and delivers the original ItemID. If this control
fails, stop the connectivity comparison and open a data-plane proposal rather
than blaming a candidate substrate.

### 1. Native mesh-host arm

Build the minimum long-lived host over the existing `IpLink`, protected local
discovery, rendezvous, and ciphertext-relay mechanisms. Add only the peer/address
book, inbound acceptance, contact scheduling, retry/failover, and status needed
by the shared experiment surface. This is the fair **build** comparator.

### 2. Core Iroh arm

Use one persistent core Iroh endpoint per Aster process for accepting and
dialing, identity-bound address lookup, path changes, NAT traversal, and
explicit locally operated relay fallback. Carry Aster frames over one dedicated
ALPN. Do not use Iroh Gossip, Blobs, Documents, or public infrastructure in an
acceptance run.

Persist the Iroh endpoint secret so restart does not create a new carrier
identity. Build from an explicit offline configuration: do not use the public
`N0` preset or public relay map; disable DNS/Pkarr publishing/resolution and the
Mainline DHT; enable the opt-in local mDNS address-lookup provider for the LAN
lane; and configure only experiment-owned relays/address services in the NAT
lane. The cost and dependency graph of that local provider count against this
arm.

The prior dependency record rejected Iroh because the reviewed public page
exposed no published vulnerability-reporting policy and the defaults used
hosted services. A subsequent direct review still found no `SECURITY.md`, but
did find GitHub private reporting and published support windows that explicitly
include security patches. Official documentation also supports direct/offline
LAN operation, custom address lookup, and self-hosted relays.

Those facts make Iroh eligible for technical research, but Decision 0002 remains
authoritative. A technically successful result remains production-blocked until
the generic dependency gates pass and a later decision explicitly amends the
prior disposition. A missing `SECURITY.md` alone is a documented governance
risk, not an architectural veto.

### 3. Minimal rust-libp2p arm

Use one bounded `Swarm`, a custom Aster stream protocol, local mDNS discovery,
post-connection Identify enrichment, connection limits, and only the AutoNAT,
circuit-relay, and direct-connection-upgrade behavior required by the harness.
mDNS or the explicit bootstrap lane supplies the initial candidate; Identify is
not credited as initial discovery. Disable Gossipsub as a data plane. Do not add
a public DHT or global membership system to satisfy the local vertical slice.

### 4. Quinn direct-carrier control

Measure Quinn as the previously identified narrow reliable-IP research
comparator using manual addresses. It isolates the cost of QUIC reliability and
congestion control, but it cannot win the complete mesh-host question because
it supplies no discovery, peer/address book, contact manager, NAT coordination,
or relay policy by itself.

## Common experimental host surface

The candidate arms must sit behind one lab-only, non-public experimental seam.
The seam reports capabilities and events rather than candidate-specific types:

- candidate discovered, including provenance and expiry;
- inbound contact offered or rejected;
- outbound contact established;
- carrier path changed, failed, or closed;
- Aster identity authenticated or rejected;
- retry scheduled or suppressed;
- contact ready for Aster frames; and
- resource/backpressure limit reached.

Aster owns authorization, NodeID binding, resource ceilings, scheduling policy,
and status semantics. A candidate may own address, dial, connection, retry, or
path state internally when that state is observable enough to enforce the
common policy, demonstrably bounded, and discardable without migrating Aster's
durable protocol state. The composed host accepts inbound and outbound work,
resolves simultaneous opens deterministically, schedules authorized peers
fairly, and exposes no carrier selection to the publish API.

This seam is an experiment fixture, not a commitment to the final public Rust or
FFI API. A selected arm must still justify the production boundary in the
resulting decision.

## Mesh configuration exercised by the experiment

The experiment must exercise a versioned deployment configuration derived from
the requirements. The exact serialization remains an outcome, but every arm
must consume the same concepts:

| Area | Required configuration concept |
|---|---|
| Provisioning | Opaque reference to the node's identity/key bundle; secrets are not embedded in ordinary configuration |
| Membership | Joined scopes and provisioned peer or authority records; carrier identities remain non-authoritative |
| Replication | Exact scoped topics to consume and exact scoped topics to carry without consuming |
| Role | Participant or durable route-only relay, plus storage/bandwidth limits |
| Discovery | Automatic local provider, manual peer fallback, and derived suppression under constrained/silent emission |
| IP host | Listen policy and optional locally controlled rendezvous/connectivity-relay services; never a per-item carrier choice |
| Carrier association | Observed association provenance/expiry and, for profiles with carrier identities, a persistent local key reference and explicit rotation policy |
| Contact policy | Maximum candidates, pending dials, active contacts, retry/backoff, fairness, duty cycle, and timeouts |
| Storage | Local bound, relay quota, tombstone retention, and applicable GC policy |
| Status | Redacted peer/discovery/authentication/path/sync/application-delivery events |

Discovery learns a candidate locator. Provisioning and the Aster handshake
decide whether the peer is a member. In the demo, “join” means a previously
provisioned node becoming discoverable and connected; runtime enrollment is not
claimed.

### Discovery and bootstrap lanes

The experiment separates discovery from bootstrap so no arm receives hidden
coordination:

- **LAN automatic-discovery lane:** configuration contains no peer-specific
  locator or carrier identity. The local provider may reveal untrusted carrier
  identities and addresses. Aster authentication determines whether a
  provisioned mission peer is on the resulting channel.
- **Manual/offline NAT lane:** every arm receives an information-equivalent,
  out-of-band bootstrap hint containing an untrusted candidate carrier identity
  and/or locator or dialing capability, plus any direct-address candidates.
  This tests a direct path without an online rendezvous or relay dependency.
- **Coordinated NAT lane:** every arm receives an equivalently scoped handle for
  experiment-owned rendezvous/connectivity-relay infrastructure. The handle
  permits dialing or coordination but grants no Aster authorization.

Exact hint bytes differ by candidate—such as an Iroh endpoint address, libp2p
peer/multiaddress, or native rendezvous capability—but the report must compare
their information content, lifetime, disclosure, and provisioning burden. A
cross-NAT result may not be called infrastructure-free merely because the final
data path became direct after using rendezvous or relay coordination.

To keep the LAN lane executable across candidates, a carrier public identity
may be observable on the local link. It must be generated independently from
the Aster NodeID and reveal no mission membership, topic, scope, or payload
metadata. The experiment measures its stability and linkability; observing it
is not advance production acceptance of that privacy tradeoff.

## Primary three-process topology

Use three separately provisioned operating-system processes and three durable
directories:

```text
LAN segment 1                         LAN segment 2

 A (publisher)  <---- discovery/contact ---->  B (route-only durable relay)
                                                      |
                                                      | discovery/contact
                                                      v
                                               C (consumer)

 A <---------------------- blocked ----------------------> C
```

B may be dual-homed or the harness may use network namespaces/containers. A
firewall or namespace receipt must prove that A and C had no usable carrier
path. Seeing the item at C without that proof is insufficient store-and-forward
evidence.

### Execution

1. Provision A, B, and C with distinct NodeIDs, one compatible topic/scope, and
   role-appropriate grants. B receives route/custody authority but no payload
   read key.
2. Open C offline, create its durable subscription, and close it again without
   configuring or establishing any carrier contact.
3. Publish one bounded UTF-8/JSON Event at offline A, including a run-generated
   high-entropy nonce, for example
   `{"command":"CHECK_IN","id":"demo-001","nonce":"<128-bit-random>"}`.
   Record the local commit, ItemID, source EnvelopeID, publisher NodeID, logical
   key, and payload digest outside B's reachable state.
4. Start B and then A without configuring either peer's IP address, port, or
   carrier identity.
5. Require automatic discovery, candidate validation, and mutual Aster
   authentication.
6. Require B to hold the exact source EnvelopeID durably; verify through
   lab evidence that custody occurred while B's public application
   surface cannot consume the plaintext or obtain an endpoint-only plaintext
   digest.
7. Stop A completely. Crash and restart B from the same durable directory.
8. Prove through the lab receipt that B has the source EnvelopeID
   before C starts or any second contact begins. This does not expand B's public
   route-only application API.
9. Start C without B's locator or carrier identity. Require B and C to discover
   and authenticate.
10. Require C's subscription to deliver exactly the A-authored ItemID, publisher,
    logical key, and payload digest. B must not republish or replace the item.
11. Commit the demo sink, application-acknowledge the ItemID, then poll again
    and require zero redelivery.
12. Restart C and prove the acknowledged item is not presented as new.
13. Reintroduce A and prove duplicate suppression creates neither a second
    semantic item nor an unbounded propagation loop.

Do not gate this scenario on `SyncStatus::Converged`; the current host lacks an
authenticated terminal-root acknowledgement. Gate it on exact durable item
identity, bounded deadlines, and application acknowledgement. Protocol receipts,
durable custody, and application acknowledgement must remain distinct facts.

## Additional functional and failure scenarios

Every eligible arm must also pass:

- simultaneous inbound/outbound initiation with deterministic duplicate-contact
  resolution;
- B servicing A and C without process restart or configuration editing;
- fair scheduling across at least 100 provisioned peers in the scale lane,
  whether protocol contacts are concurrent or deliberately bounded; the frozen
  run configuration defines one contact quantum, every equally eligible
  responsive peer receives an opportunity within one complete cycle, and
  service-count skew is at most one absent backpressure;
- a peer changing IP address without changing Aster identity;
- automatic discovery disabled under constrained/silent emission;
- manual/pre-provisioned peering while automatic discovery is disabled;
- fully local operation with every rendezvous and connectivity-relay service
  unavailable;
- direct contact across the controlled permissive-NAT/manual-hint case without
  online rendezvous or relay coordination;
- direct-path failure and locally operated relay fallback across the restrictive
  case;
- bounded reconnect/failover after connectivity-relay loss;
- interruption during transfer followed by peer-neutral resume;
- 3,000 bit/s, seeded 50% loss, delay, duplication, and reordering; and
- wall-clock jumps that do not arbitrate item correctness.

Common negative/adversarial cases include invalid or revoked Aster credentials,
carrier identity substitution, address reuse, expired and replayed
advertisements, discovery/connection/handshake floods, malformed/truncated
carrier frames, restart after commit but before receipt, and capacity exhaustion
in every pre-authentication table. Candidate-specific cases include a wrong
native discovery secret and the equivalent malformed or unauthorized input for
each other discovery provider.

Zero candidates must leave bounded idle state and time out cleanly. Multiple
authorized candidates are normal mesh operation: the host must retain,
authenticate, and schedule them fairly. Excess and unauthorized candidates must
remain bounded without displacing durable mesh truth.

An unauthorized candidate must create no application item, peer authorization,
or durable protocol truth beyond explicitly bounded hostile-input accounting.

## Demonstration surface

The experiment must ship both an automated evidence command and a manual
multi-terminal walkthrough. Command spelling is provisional, but the intended
shape is:

```sh
aster-lab mesh-provision --root ./demo --nodes a,b,c
aster-lab mesh-subscribe --root ./demo/c --name demo-sink \
  --topic ops.commands
aster-lab mesh-publish --root ./demo/a --topic ops.commands \
  --json-file ./command-with-random-nonce.json
aster-lab mesh-node --root ./demo/b
aster-lab mesh-node --root ./demo/a
aster-lab mesh-node --root ./demo/c --subscription demo-sink \
  --expect-item ./demo/source-receipt.json --ack
```

No A, B, or C command may receive a peer IP address or port in the automatic
discovery demonstration; a shared multicast group/listen policy is allowed. A
separate manual-peer example must remain available. The sketch deliberately
publishes and creates the subscription while their node processes are stopped.
No two processes may open the same node root concurrently. A future interactive
publish/status surface would require explicit stdin or authenticated local IPC
and is not implied here.

An optional one-command coordinator may run the exact topology for CI:

```sh
aster-lab demo ip-mesh --root ./demo \
  --command CHECK_IN --id demo-001 --generate-random-canary
```

Human-readable status should distinguish at least:

```text
discovered -> authenticating -> authenticated -> carrying -> delivered -> acknowledged
```

The final receipt must also state `A_C_contact_count=0` and whether each path was
direct or used connectivity relay R.

## Measurements

Record the following for every arm:

| Area | Measurements |
|---|---|
| Discovery | Time to first candidate, candidate count/provenance, false candidates, bytes per settled minute, expiry behavior |
| Authentication | Candidate-to-authenticated latency, carrier plus Aster handshake bytes, rejection latency/work |
| Propagation | A→B custody time, B→C delivery time, exact ItemID preservation, retransmitted bytes, application acknowledgement |
| Connectivity | Direct/relay path, address-change recovery, reconnect/failover time, duplicate dial/contact count |
| Efficiency | Useful bytes versus carrier, transport, Aster control, and payload bytes; round trips at each fault profile |
| Resources | Exact artifact size, peak and settled RSS/PSS, CPU, wakeups, threads/tasks, file descriptors, queues |
| Boundedness | Peer/address entries, pending dials, live contacts, retained hostile state, queue and retry ceilings |
| Supply chain | Exact version/features, archive digest, transitive SBOM, licenses, advisories, MSRV, unsafe/native code, security/support ownership |
| Assurance | Local mechanisms added/deleted, adapter complexity, upstream mechanisms relied upon, migration and rollback cost |
| Privacy | Plaintext-canary results and incremental exposure of carrier identities, addresses, timing, and protocol metadata |

Use release builds, identical compiler settings, identical local infrastructure,
and randomized arm order. Preserve failures and outliers rather than reporting
only a successful median.

The matrix is staged so integration time does not masquerade as a technical
result:

- **Phase 0 — data-plane prerequisite:** run the sequential route-only Event
  control 10 times. It must pass 10/10 with exact EnvelopeID/ItemID, restart,
  unreadability, delivery, and acknowledgement evidence before any substrate
  arm begins.
- **Phase A — common LAN slice:** run 30 clean three-process trials for the
  native, Iroh, and minimal libp2p arms. All 30 must complete within the frozen
  clean-lane timeout. Any identity, authorization, plaintext, ItemID, custody,
  or acknowledgement violation is an immediate technical failure.
- **Phase B — surviving arms:** run 10 trials in every NAT, relay-loss, and
  impaired-link cell plus all security/hostile-input gates. Every deterministic
  seeded trial must preserve semantic and security correctness; the activation
  record must ratify any permitted timing-failure count before execution.
- **Phase C — final downselect:** run one 10-minute settled-idle interval, one
  10,000-item Tier-2 resource trial, rollback, and one 100-real-process
  segmented-IP cohort for the remaining candidate or candidates.

Performance distributions are descriptive unless a threshold is explicitly
ratified before the run. Mandatory semantic and security gates are
non-compensable. An arm stopped solely because its predeclared timebox expired
is **inconclusive/timeboxed**, not technically failed; it is failed only when
the evidence shows a required property is absent or violated.

The existing 1,000-node simulated run remains useful semantic stress evidence.
It cannot substitute for any live-IP result, and this experiment must not relabel
it as discovery, NAT, or operational mesh evidence. A 1,000-live-node or bridged
deployment is a later scale gate after the basic host works.

## Mandatory pass gates

An arm is eligible for selection only if:

1. the LAN vertical slice uses no configured peer locator or carrier identity;
2. all three roles are independent processes with independent durable stores;
3. carrier authentication is supplemental; Aster remains the mission
   authentication and authorization authority for the NodeID on the channel;
4. B survives restart and forwards the unchanged A-authored item after A is
   gone;
5. B cannot consume route-only content;
6. C acknowledges through the ordinary application API and sees no new
   redelivery;
7. unauthorized and revoked candidates commit no data;
8. discovery obeys emission policy and manual peering remains available;
9. local operation has no infrastructure dependency;
10. restrictive NAT can use a locally deployable fallback;
11. payload, topic, scope, priority, logical-key, and publisher canaries are
    absent from carrier captures and candidate-owned caches/logs;
12. application code never selects a carrier or path;
13. Aster protocol bytes and semantics remain unchanged;
14. every pre-authentication and contact-management resource is bounded;
15. operation is readiness/timer driven rather than the current laboratory's
    one-millisecond pump loop; excluding the coordinator, cumulative host CPU
    averages below 1% of one core over a settled ten-minute interval, with
    sampled distribution and wakeups also reported and attributable to
    configured discovery/timers or actual I/O;
16. a 1 KiB command completes at 3 kbps and seeded 50% loss within a provisional
    ten-minute experiment timeout without semantic failure; this is a proposed
    trial bound requiring ratification, not the current relay's queued-write
    retention deadline or a product delivery guarantee; and
17. the selected outcome names exactly which current production mechanisms are
    removed or retained and demonstrates rollback through the same seam.

The bracketed resource targets in the requirements are not yet ratified. For
screening, report both absolute and incremental results against the provisional
≤10 MiB added-binary and ≤64 MiB steady-RAM targets, with ≤32 MiB shown as the
preferred RAM target. Exceeding one blocks selection pending a stakeholder
decision; it is not silently converted into a requirements failure or waiver.

## Security and governance gates

The carrier is untrusted and supplemental. A candidate must not receive Aster
scope keys, become the authorization authority, or weaken the Aster handshake.
Captures and persisted-state scans use unique canaries for payload, topic, scope,
priority, logical key, and publisher material. The report must document any new
observable carrier identity, endpoint relationship, address, timing, and volume
metadata even when no plaintext canary appears.

Persisted-state scanning is role-aware. Candidate-owned caches and logs must not
contain Aster payload or protected-metadata canaries. Route-only B must contain
no payload plaintext or plaintext digest accessible outside the authorized
consumer path, although its trusted Aster store may legitimately retain the
protected routing metadata needed to forward. A and C may legitimately retain
payloads they are authorized to publish or consume.

Public infrastructure is prohibited in acceptance runs. Candidate defaults must
be disabled explicitly; network namespaces must prove that the local profile
does not reach the public Internet. NAT fallback must use retained, locally
controlled infrastructure with its own admission and resource limits.

Production selection requires exact-version provenance, an OSI-approved license
with no strong copyleft or proprietary term, complete transitive graph,
reproducible build, SBOM, supported-version policy, actionable
vulnerability-reporting route, advisory and remediation review, update owner,
and removable integration boundary. A research arm is not aborted merely
because an upstream governance document is missing; it may finish as a
technically successful but production-blocked result. This keeps documentation
diligence from predetermining the architecture while preserving the dependency
policy.

## Early-abort rules and timebox

Stop an arm immediately if it:

- requires a public hosted service for local operation;
- exposes protected Aster values at the carrier layer;
- treats a carrier key, address, ticket, or discovery token as mission
  authorization;
- replaces durable anti-entropy with online gossip or DHT value storage;
- requires per-message transport selection in the application API;
- requires an Aster protocol change solely to fit the library;
- cannot bound unauthenticated candidates, dials, queues, connections, or work;
- has a license incompatible with the accepted dependency policy; or
- cannot be removed through the common seam.

Proposed execution budget:

| Work | Stop limit |
|---|---:|
| Shared harness and lab-only host seam | 6 engineer-days |
| Native mesh-host arm | 4 engineer-days |
| Core Iroh arm | 4 engineer-days |
| Minimal rust-libp2p arm | 4 engineer-days |
| Quinn control | 2 engineer-days |
| Phase-B survivor fault/security work | 6 engineer-days total |
| Phase-C downselect, rollback, and disposition | 4 engineer-days |

If the shared host seam cannot reach the sequential control within its limit,
stop the substrate comparison and issue a narrower host-architecture proposal.
If a candidate cannot reach the primary functional gate within its declared
bounded integration window, preserve the result and mark it
**inconclusive/timeboxed** unless a required property was actually disproved.

Rollback in Phase C disables the candidate feature, discards candidate-owned
address/connection caches, reopens the unchanged Aster durable store through the
native/sequential control profile, and completes a contact without migrating
Aster protocol state.

## Selection rule

Mandatory gates are non-compensable. If several arms pass, select one only when
it dominates the others across the predeclared assurance dimensions: semantic
fit, local code/mechanisms deleted, upstream and supply-chain assurance,
resource/link cost, privacy exposure, operational burden, migration, and
rollback. Dominance requires no worse result on every accepted dimension and a
materially better result on at least one. If passers retain unresolved tradeoffs,
the result is **none/needs decision**, not a post-hoc weighted score.

## Reproducibility and evidence

Before execution, freeze:

- exact repository commit and worktree state;
- requirements hash and accepted decision set;
- candidate versions, features, archive digests, lockfiles, and complete source
  registration;
- compiler, target, build profile, host, container/network image, and topology;
- redacted mesh configurations, provisioned role summary, fault seeds, clocks,
  trial count, and stop conditions; and
- exact instrumentation and definitions for bytes, memory, CPU, wakeups, and
  success.

Retain structured event logs, exact ItemID/digest receipts, packet captures and
hashes, firewall/namespace proof, resource samples, every trial result, SBOM,
license/advisory output, and code-deletion/rollback diffs. Evidence must identify
local commit, peer durable custody, protocol receipt if observable, application
delivery, and application acknowledgement separately.

The proposal changes no behavior, so it does not by itself change requirements
traceability. An implementation or selected production profile must update the
traceability and conformance records against its exact accepted commit.

## Non-goals

This experiment does not:

- select or implement BTLE;
- change Aster data classes, causal semantics, authorization, cryptography,
  reconciliation, wire encoding, or compatibility profile;
- build runtime enrollment, a global public DHT, or Internet-wide anonymous
  membership;
- treat a connectivity relay as durable custody;
- complete bridge or broadcast propagation;
- close the independent-SUT interoperability release gate;
- authorize a public hosted service;
- make Iroh, libp2p, Quinn, Zenoh, Veilid, or p2panda an Aster data plane; or
- claim the 100/1,000-node product scale targets from a three-node demonstration.

## Deliverables and disposition

The completed experiment produces:

1. the automated and manual three-process demonstration;
2. the shared topology/fault/measurement harness;
3. reviewable patches/commits and receipts for isolated feature-gated candidate
   arms;
4. exact run and assurance receipts for passing and failed arms;
5. a requirement-by-requirement comparison;
6. a total-assurance disposition of **wrap**, **keep custom**, or **block** for
   the operational IP mesh host; and
7. a new architecture decision that accepts one winner or none and records any
   amendment to Decisions 0002, 0007, 0014, 0015, or 0016.

After the result ADR, production retains code only for the selected arm, if any;
loser code is deleted after its reviewable commits and evidence are preserved.
No production branch retains multiple overlapping default stacks.

## Open questions before acceptance for experiment

- Is stable link-local carrier-identity exposure acceptable in the production
  threat model, or must a selected arm add a rotating/protected pre-authentication
  handle despite the measured cost?
- What provisional binary, RAM, idle CPU, discovery traffic, and completion
  thresholds should stakeholders ratify for this experiment?
- Must the first host support simultaneous authenticated protocol contacts, or
  is fair scheduling across several discovered peers sufficient for the first
  vertical slice?
- Which locally controlled relay/rendezvous topology represents the intended
  NAT deployment?
- Is the network-capable host embedded in Rust first, or must the experiment
  include an out-of-process service usable by the Go/Python/C bindings?
- What evidence satisfies the reporting, response-history, support-window, and
  update-ownership governance gate for each surviving upstream candidate?

## Public comparison sources

The project source register retains the exact access record. Principal
upstream references for the hypotheses are:

- [Iroh endpoints](https://docs.iroh.computer/concepts/endpoints),
  [address lookup](https://docs.iroh.computer/concepts/address-lookup),
  [local mDNS lookup](https://docs.iroh.computer/connecting/local-address-lookup),
  [NAT traversal](https://docs.iroh.computer/concepts/nat-traversal),
  [self-hosted relay](https://docs.iroh.computer/add-a-relay), and
  [release/support policy](https://docs.iroh.computer/about/release-policy), plus
  the repository's [security/reporting status](https://github.com/n0-computer/iroh/security);
- [rust-libp2p `Swarm`](https://docs.rs/libp2p/latest/libp2p/swarm/index.html),
  [mDNS](https://docs.rs/libp2p/latest/libp2p/mdns/struct.Behaviour.html),
  [AutoNAT](https://docs.rs/libp2p/latest/libp2p/autonat/index.html),
  [circuit relay](https://docs.rs/libp2p/latest/libp2p/relay/index.html), and
  [DCUtR](https://docs.rs/libp2p/latest/libp2p/dcutr/index.html); and
- [Quinn](https://docs.rs/quinn/latest/quinn/) as the narrow direct-QUIC control.

## Dated outcome

### 2026-08-21 — Completed with no production winner

Native UDP, Iroh, and rust-libp2p each passed 30/30 clean three-process LAN
vertical-slice trials, including automatic locator-free discovery, Aster mutual
authentication, route-only B custody across restart, exact A-authored ItemID
delivery at C, application acknowledgement, and duplicate suppression. All
three also passed the exercised discovery-disabled, two-simultaneous-contact,
and capture-canary lanes.

No arm satisfied the complete mandatory gate set. The shared implementations
lacked manual peering, emission-policy linkage, fair 100-peer scheduling, NAT
direct/fallback composition, and relay-loss reconnect. Iroh failed the
provisional idle discovery-traffic threshold. Quinn had no runnable host. The
required deterministic netem seed was unsupported by the pinned environment,
so the live impaired-IP cell was blocked rather than replaced by an unseeded
pass. No arm was eligible for Phase C and no dependency was selected.

The complete measurements, failed-run ledger, evidence identities, gate matrix,
supply-chain results, and next boundary are in the
[result report](0001-ip-mesh-vertical-slice-results.md). Decision
[0022](../decisions/0022-ip-mesh-experiment-no-selection.md) records the
no-selection disposition.

## Progress log

### 2026-08-21 — Phase 0 passed

The sequential route-only Event prerequisite passed 10/10 clean trials using
seeds 1001 through 1010. Every trial retained the exact source ItemID and
EnvelopeID through A→B, restarted B from its durable store, delivered the same
A-authored object through B→C, application-acknowledged it once at C, observed
zero post-ack redeliveries, and configured no A↔C contact.

B's route-only application API exposed no Event. Raw durable-state canary scans
found neither payload plaintext nor the payload SHA-256. They did find the
logical key inside the trusted Aster store; the receipt records that fact
explicitly because the current profile treats it as protected forwarding
metadata visible at the authenticated mesh-membership layer. Candidate-owned
carrier caches and logs remain subject to the stricter Phase-A privacy gate.

This checkpoint proves only the data-plane prerequisite over the deterministic
in-memory fault carrier. It is not IP, discovery, concurrent-contact, NAT, or
operational mesh evidence. Exact provenance, commands, failures, receipt hashes,
and the aggregate manifest digest are retained in
`evidence/IP_MESH_EXPERIMENT_20260821.md` and the referenced `lab/runs`
directories.

The current fixed-address UDP control was then rebuilt from the experiment
worktree and run in two independent containers. Both nodes mutually
authenticated, each published one Event, and each observed both Events. This
confirms the current real-UDP carrier still works, but the run explicitly used
configured peer IP addresses and ports and therefore does not satisfy Phase A
discovery or mesh-host gates.
