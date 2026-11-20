# Proposal 0003: Idiomatic IP mesh provider comparison


- Status: completed — no provider selected; no dependency or production profile
  admitted
- Date: 2026-08-21
- Owner: Aster Clean Team — execution authorized in the designated project task
- Survey baseline: `56ea19d89e537a351ceded446c2d38f5313d118b`; execution
  must freeze its exact starting commit
- Signed experiment checkpoint:
  `15f99c37c7310ba7d8f6a3a2f927d7b1a8ddfe2c`
- Requirements baseline SHA-256:
  `e88bcc6c717a5175a460205fdc084aaa2e1f020a142a84087f9881677da02987`
- Execution cap: 36 engineer-days; this is a stop limit, not an estimate
- Result: [Proposal 0003 result](0003-idiomatic-ip-mesh-provider-results.md)
- Decision: [Decision 0024](../decisions/0024-refactor-durable-node-ownership-before-ip-provider-selection.md)
- Preserves: [Decision 0002](../decisions/0002-dependency-admission.md),
  Decision 0014 (“Build versus buy is governed by total assurance cost”;
  Decision 0015 (“Delete custom mechanism behind narrow library-backed seams”;
  [Decision 0022](../decisions/0022-ip-mesh-experiment-no-selection.md), and
  [Decision 0023](../decisions/0023-mesh-host-contract-no-libp2p-selection.md)
- Prior results: [Proposal 0001](0001-ip-mesh-vertical-slice-results.md) and
  [Proposal 0002](0002-provider-neutral-mesh-host-results.md)

## Question

Can one idiomatic IP provider profile satisfy Aster's accepted `MeshHost`
contract and the still-open discovery, NAT, relay, impairment, resource,
assurance, and rollback gates while deleting more overlapping custom mechanism
than it adds?

The eligible outcomes are exactly one of:

- **keep custom** — compose the existing native IP mechanisms through
  `MeshHost`;
- **wrap core Iroh** — use one persistent endpoint and its intended
  connectivity mechanisms;
- **wrap rust-libp2p** — use one Swarm and its intended connectivity
  behaviours; or
- **none** — preserve the current no-selection decision.

The experiment cannot retain overlapping production defaults. A technical pass
with a dependency, governance, mechanism-deletion, or rollback blocker is not a
production selection.

In particular, accepting this experiment does not lift Decision 0002's Iroh
disposition. Only the result decision may amend that disposition after the exact
production graph passes the current gates.

## Why another comparison is justified

Proposal 0001 proved that all three arms could carry Aster's exact durable LAN
store-forward semantics. It did not compose any arm with the later `MeshHost`
contract or implement manual peering, emission linkage, fair scheduling, NAT,
connectivity-relay fallback, or relay-loss recovery.

Its Iroh arm was close to intended upstream use: one persistent endpoint, one
Aster ALPN, one long-lived bidirectional stream, local address lookup, and public
defaults disabled. Its remaining experiment defects were common-host
composition, duplicate-contact ownership, configuration, and 55,258 B/node/min
of settled discovery traffic against the predeclared 4 KiB/min screen.

Proposal 0002 did not provide an equally idiomatic rust-libp2p test. It:

- opened a CBOR request/response exchange for every Aster frame instead of using
  one long-lived stream per contact;
- mapped peer-level request/response traffic onto per-connection Aster drivers,
  then added custom duplicate-connection election and settling delays;
- drove contacts from a fixed 25 ms tick rather than readiness and actual Aster
  deadlines;
- retained Aster UDP discovery while omitting libp2p's NAT, circuit-relay, and
  direct-connection-upgrade mechanisms; and
- added 1,082 provider lines while deleting no native mechanism.

Those results remain valid for that adapter. Proposal 0003 does not erase its
failure; it tests a materially different integration and must replay the failed
trial-14 conditions as a regression.

## Non-negotiable Aster boundary

Every arm uses the same current `MeshHost`, Aster runtime, durable stores,
provisioning, NodeIDs, handshake, protected envelopes, reconciliation, custody,
priority, TTL, application delivery, and acknowledgement semantics.

`MeshHost` owns candidate provenance and expiry, Aster-authenticated
carrier-to-NodeID bindings, emission policy, contact opportunity and fairness,
retry/failover policy, resource ceilings, and operator status. A provider owns
listeners, locators, carrier authentication, connection establishment, path
events, and bounded carrier I/O.

An Iroh `EndpointId`, libp2p `PeerId`, native carrier key, socket address, ticket,
or relay reservation is an untrusted locator. Every new Aster contact performs
fresh Aster authentication. Carrier authentication never grants mission, topic,
scope, payload, custody, or synchronization authority.

The bridge between `MeshHost` and a provider may retain bounded I/O buffers,
cancellation state, and one logical stream record per scheduled contact. It must
not implement a second candidate table, contact scheduler, authorization cache,
retry policy, relay policy, or durable protocol store.

On a bound ordered stream, use the existing bounded-length Aster carrier framing
defined by [the protocol](../protocol.md#15-carrier-fragmentation-broadcast-and-loops).
Provider envelopes must not wrap every Aster frame in a new request/response.

The application API never selects a provider, path, relay, or peer per item.
Iroh Gossip, libp2p Gossipsub/Kademlia, and connectivity relays must not replace
Aster propagation, durable custody, or anti-entropy.

## Arms

### Native control and eligible keep-custom arm

Compose the existing protected IP discovery, manual mapping, rendezvous,
hole-punch, UDP carrier, and locally operated ciphertext-relay components through
`MeshHost`. Correct the prior self-discovery defect. This arm may add bounded
composition glue but may not invent a new NAT or overlay protocol under this
proposal.

### Core Iroh arm

Use one persistent core endpoint per Aster process, one Aster ALPN, and one
long-lived bidirectional stream per scheduled contact. Start from an explicit
minimal configuration: no public preset, DNS/Pkarr publishing or resolution,
Mainline DHT, public relay map, Gossip, Blobs, or Documents. Use only the local
address-lookup provider and experiment-owned relay infrastructure.

Manual peers carry an untrusted endpoint identity plus current address details.
Emission changes must stop local discovery at the provider, not merely ignore
received candidates. Provider configuration must limit advertised interfaces and
addresses to the test topology. Traffic tuning may use documented configuration;
patching the discovery protocol only to beat the threshold is not credited as
idiomatic use.

### Idiomatic rust-libp2p arm

Use one persistent `Swarm` per Aster process with one frozen direct transport,
Identify for post-connection address enrichment, mDNS for the automatic LAN
lane, connection limits, AutoNAT where its controlled service is exercised,
circuit-relay client/server behaviour, DCUtR, and a generic upstream-maintained
stream behaviour for the Aster protocol. Do not compile request/response,
Gossipsub, Kademlia, or public discovery/bootstrap services into the selected
profile.

Open one full-duplex Aster substream per logical contact and carry many bounded
Aster frames on it. A deterministic carrier-only rule may select which side
opens the stream; it grants no Aster authority. The Swarm owns physical
connection and substream state. One physical connection change must not create
parallel Aster drivers for the same logical contact, and reconnect requires a
new stream and fresh Aster authentication.

If the exact registry-published graph cannot supply the required generic stream,
mDNS, relay, or DCUtR behaviour without an unresolved selection blocker, record
that result. Do not replace a missing upstream mechanism with another large
provider-specific state machine and still call the arm idiomatic.

The prior `hickory-proto` vulnerability path and unmaintained `paste` path are
known inputs to Phase 0, not inherited waivers. A pre-release generic-stream API
also requires an explicit stability and update-ownership disposition.

## Common configuration and controls

Before execution, freeze one versioned configuration containing the same
provisioning reference, roles, topics/scopes, emission mode, manual candidates,
listen policy, contact bounds, retry policy, discovery policy, locally controlled
relay handle, and resource ceilings. Provider-specific locator bytes may differ,
but their information, lifetime, and authority must be compared explicitly.

The exact native binary from the starting commit is the build control. The
signed Proposal 0002 libp2p artifact is a diagnostic control only. All eligible
arms use release builds, the same compiler/target, topology, workload, deadlines,
fault schedule, process limits, and randomized run order.

No acceptance network may reach a public discovery, DNS/Pkarr, DHT, rendezvous,
or relay service. A durable Aster relay B and an ephemeral connectivity relay R
are distinct roles; R never receives Aster custody.

Every surviving arm must expose the same automated evidence command and the same
manual multi-terminal walkthrough. The automatic demonstration receives no peer
IP, port, or carrier identity, and neither form lets application code select a
provider or path per item.

## Staged execution and gates

### Phase 0 — activation and dependency freeze

Freeze exact commits, crate versions/features/checksums, target-specific Cargo
trees, SBOMs, licenses, advisories, security/reporting paths, support policy,
MSRV, toolchain, container/network images, thresholds, and an expected
mechanism-deletion manifest for each arm.

An active vulnerability, incompatible license, mandatory public service, or
unbounded hostile-input surface blocks production selection. A safely isolated
technical run may continue only when the activation record labels that blocker;
it cannot later be waived by performance.

### Phase 1 — adapter architecture proof

Before any broad trial, each arm must pass independent review proving:

- one owner for every candidate, connection, logical contact, retry, path, and
  authorization state;
- bounded queues, connections, streams, relay reservations, and pre-auth work;
- readiness/I/O/deadline-driven execution with no fixed fast pump loop;
- provider discovery sends zero bytes in constrained and receive-only modes;
- one Aster logical contact per scheduled peer despite simultaneous opens; and
- fresh Aster authentication after stream, path, address, or process restart.

The Iroh arm must carry 10,000 Aster frames over one bidirectional stream. The
libp2p arm must do the same over one generic substream, with the request/response
feature absent from its exact graph. Both must survive bounded backpressure and a
mid-frame close without committing unauthenticated data. The libp2p arm must also
pass the archived Proposal 0002 trial-14 regression.

### Phase 2 — discovery, manual peering, and LAN custody

For every surviving arm:

1. run 30/30 clean A→B, B restart, B→C trials preserving the source EnvelopeID
   and ItemID, route-only unreadability, application acknowledgement, and no
   redelivery;
2. run 10/10 automatic LAN-discovery trials with no peer locator or carrier
   identity in node configuration;
3. run 10/10 manual/pre-provisioned trials with automatic discovery disabled;
4. prove constrained and receive-only modes emit zero discovery bytes while
   receive-only still accepts an authorized inbound contact; and
5. prove 100 provisioned candidates receive a contact opportunity within one
   complete configured cycle with service-count skew no greater than one.

Settled normal-mode automatic-discovery traffic must be no more than 4 KiB per
node per minute unless the activation record replaces that provisional screen
before implementation with a stakeholder-ratified value. No post-run threshold
change is allowed.

### Phase 3 — controlled NAT and relay

Use reproducible network namespaces with firewall and translation receipts. Run
10/10 trials in each cell:

- direct contact on the same LAN with all infrastructure absent;
- permissive-NAT direct contact using information-equivalent offline hints;
- provider-native traversal/upgrade coordinated only by experiment-owned
  infrastructure, reported honestly as coordinated even when the final path is
  direct;
- restrictive-NAT fallback through a locally operated connectivity relay R;
- relay loss followed by bounded reconnect and direct-path reconsideration; and
- address and port change with stable carrier identity but fresh Aster
  authentication.

The native arm may use only its already accepted rendezvous/punch/relay
mechanisms plus bounded composition. Iroh must use its endpoint path selection
and locally operated relay. Libp2p must exercise its relay and DCUtR behaviours;
having those crates in the graph is not evidence.

### Phase 4 — impairment, security, scale, and resources

First validate a hash-bound userspace packet schedule against a sentinel corpus;
do not reuse the unsupported `netem seed` syntax. Every surviving arm then runs:

- 10/10 deterministic 1 KiB command trials at 3,000 bit/s and 50% loss within a
  predeclared ten-minute experiment timeout;
- interruption/resume, duplication, reordering, wall-clock jump, revoked and
  unauthorized peer, carrier-identity reuse, malformed frame, discovery flood,
  connection/stream flood, and capacity-exhaustion cases;
- unique payload, topic, scope, priority, logical-key, and publisher canary scans
  across packet captures and provider-owned caches/logs;
- one 100-real-process segmented-IP run and one 10,000-item Tier-2 run; and
- ten-minute and one-hour settled idle measurements plus 1 KiB, 64 KiB, and
  1 MiB transfer distributions.

Selection screens are: less than 1% of one core at settled idle, no busy polling,
no more than 10 MiB incremental stripped binary size, no more than 64 MiB steady
RAM at 10,000 items with 32 MiB preferred, and zero protected canary matches.
Bracketed requirement targets remain provisional product values; this experiment
does not close them.

### Phase 5 — mechanism deletion, rollback, and disposition

Before selection, produce an actual reviewable deletion patch. Shared preexisting
`MeshHost` code is charged equally to all arms. Provider-specific changes to it
are charged to that arm. Lab-only harness code is reported separately and cannot
make the production mechanism score look better.

An upstream arm passes the buy-over-build gate only when the selection patch:

- removes the overlapping native discovery, connection, traversal, and relay
  mechanisms that the provider truly replaces;
- adds fewer provider-specific product lines than it deletes and identifies each
  mechanism owner before and after; and
- leaves no dormant overlapping default or optional production stack.

Raw line counts are a check, not a substitute for the mechanism inventory.
The native arm instead must remove superseded lab-only contact maps and prove its
continuing `MeshHost` composition is the sole native host path.

## Exact rollback rule

Rollback must be demonstrated, not described. For each arm:

1. stop all node and local-infrastructure processes;
2. disable the candidate feature and discard only experiment-created
   provider-owned carrier keys, address caches, relay reservations, connection
   state, and experiment config;
3. rebuild the continuing default graph and prove the rejected provider and its
   transitive dependencies are absent;
4. reopen the unchanged Aster SQLite and Blob stores with the native/sequential
   control without schema or protocol migration;
5. authenticate, resume a partial transfer, deliver the original ItemID, and
   application-acknowledge it; and
6. preserve the signed experiment checkpoint and evidence, then delete rejected
   provider source from the continuing branch.

Rollback fails if it deletes Aster durable truth, requires wire/schema/API
migration, retains an overlapping provider, or cannot resume through the same
`MeshHost` boundary.

## Evidence contract

Retain append-only, hash-bound records for every pass, failure, timeout, and
outlier:

- starting and candidate commits, dirty state, exact binaries and build commands;
- sources, versions, features, archive checksums, lockfiles, target-specific
  dependency trees, SBOMs, licenses, advisories, MSRV, unsafe/native code, and
  update owner;
- redacted configuration, topology, firewall/NAT/relay receipts, packet schedule,
  seeds, clocks, process limits, and randomized arm order;
- per-trial structured events separating candidate discovery, carrier connection,
  Aster authentication, local commit, durable custody, delivery, and application
  acknowledgement;
- stream/connection churn, direct/relay path, bytes by layer, CPU, memory,
  wakeups, tasks, descriptors, queues, and high-water marks;
- packet captures and provider-state canary scans;
- incremental exposure of carrier identities, addresses, relationships, timing,
  and volume even when protected canaries remain absent; and
- before/after mechanism inventory, source counts, deletion patch, and rollback
  receipt.

Missing tooling is **blocked**, an expired arm timebox is
**inconclusive/timeboxed**, and an observed semantic, security, boundedness, or
mandatory functional violation is **failed**. Resource advantages never
compensate for such a failure.

## Stop limits

| Work | Stop limit |
|---|---:|
| Freeze, assurance preflight, and common harness | 5 engineer-days |
| Native composition arm | 4 engineer-days |
| Core Iroh arm | 5 engineer-days |
| Idiomatic rust-libp2p arm | 7 engineer-days |
| Controlled NAT/relay lanes | 7 engineer-days total |
| Impairment, security, scale, and resources | 5 engineer-days total |
| Deletion, rollback, report, and decision input | 3 engineer-days |

Stop an arm early if it repeats a Proposal 0002 adapter flaw, changes Aster
protocol/application semantics, requires public infrastructure, cannot suppress
discovery under emission policy, cannot bound unauthenticated work, cannot reach
the mandatory NAT/relay cells, or has no credible deletion patch by Phase 3.

## Selection and outcome

All mandatory gates are non-compensable. If several arms pass, select one only
if it is no worse across semantic fit, assurance, resource/link cost, privacy,
operations, mechanism deletion, migration, and rollback, and materially better
on at least one accepted dimension. Otherwise select **none/needs decision**;
do not invent a post-hoc weighted score.

Completion appends a dated outcome to this proposal and produces a new
architecture decision selecting one profile or none. Until then, Decisions 0022
and 0023 remain authoritative, no dependency is admitted, and no requirement,
conformance scenario, MVP status, or production capability changes.

## Public comparison sources

The exact access records remain in the project source register. Principal
references are the upstream [Iroh endpoint and connectivity documentation](https://docs.iroh.computer/concepts/endpoints),
[Iroh local address lookup](https://docs.iroh.computer/connecting/local-address-lookup),
[rust-libp2p Swarm](https://docs.rs/libp2p/latest/libp2p/swarm/index.html),
[generic libp2p streams](https://docs.rs/libp2p-stream/latest/libp2p_stream/),
[libp2p mDNS](https://docs.rs/libp2p/latest/libp2p/mdns/struct.Behaviour.html),
[circuit relay](https://docs.rs/libp2p/latest/libp2p/relay/index.html), and
[DCUtR](https://docs.rs/libp2p/latest/libp2p/dcutr/index.html).

## Dated outcome

- 2026-08-21: corrected the 38-character transcription
  `56ea19d89e537a351ced446c2d38f5313d118b` (missing `ed`) to the observed
  40-character commit `56ea19d89e537a351ceded446c2d38f5313d118b`; no
  experiment scope or gate changed.
- 2026-08-21: completed with **none selected**. All arms failed the mandatory
  Phase-1 architecture gate because contacts constructed independent durable
  backends before fresh Aster authentication, multiple live authorities shared
  one store without coherent quota/control ownership, and resource ceilings
  were per-contact rather than node-global. Later NAT, relay/path-change,
  impairment, and scale phases were stopped as required. Bounded LAN, resource,
  payload, capture, code-size, dependency, and rollback characterization is
  retained in the [result](0003-idiomatic-ip-mesh-provider-results.md).
  Libp2p-to-native and Iroh-to-native rollbacks each preserved their original
  durable ItemID and EnvelopeID through A→B→C custody and application
  acknowledgement. The rejected Rust adapter modules, Cargo features, and
  dependency graphs were removed while Python evidence tooling was retained;
  Decision 0024 requires one process-owned durable authority before another
  downselection.
