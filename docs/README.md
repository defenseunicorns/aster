# Aster documentation

Use this page to choose a path through the project. You do not need to
understand Aster's wire format or cryptography before building an application.

## Recommended path

1. Read [Core concepts](concepts.md) for the mental model: items, topics,
   scopes, data classes, and contacts.
2. Start with [Aster Field Notes](quickstart/hello.md) to add named real nodes,
   write offline, and watch exact observations move. Run the
   [capability tour](quickstart/capability-tour.md) for deterministic receipts,
   then use the
   [message playground](quickstart/message-playground.md) to keep a bounded
   local line running and publish synthetic Events through different nodes.
3. For default-off networking evaluations, continue with the
   [trusted-LAN MVP](quickstart/lan-mvp.md) and
   [flat-LAN scale baseline](quickstart/lan-scale.md), then compose isolated
   discovery domains through the [static hierarchy MVP](../docker/hierarchy-mvp/README.md)
   and [hierarchy scale diagnostic](quickstart/hierarchy-scale.md). These are
   bounded procedures and same-host diagnostics, not retained physical or
   production evidence.
4. Choose an integration path. Most applications should begin with the
   [local ConnectRPC agent](quickstart/connect-agent.md); Rust applications can
   use the [selected Event](quickstart/selected-event-api.md),
   [State](quickstart/selected-state-api.md),
   [Record](quickstart/selected-record-api.md), or
   [Blob](quickstart/selected-blob-api.md) API directly.
5. Read [Selected architecture](architecture.md), [Security](security.md), the
   [classical Iroh-QUIC profile](classical-iroh-security-profile.md), and the
   adopted [security-profile requirements disposition](implementation/security-profile-requirements-disposition.md)
   before designing a deployment.

## Choose a guide by goal

| I want to… | Read… |
|---|---|
| Understand what Aster is and when it fits | [Project overview](../README.md) and [Core concepts](concepts.md) |
| Meet Aster through a human-driven three-node story | [Aster Field Notes](quickstart/hello.md) |
| See deterministic acceptance evidence | [Capability tour](quickstart/capability-tour.md) |
| Send messages through several live local node processes | [Message playground](quickstart/message-playground.md) |
| Evaluate mission-authenticated automatic discovery on one trusted LAN | [LAN MVP](quickstart/lan-mvp.md) and [LAN scale baseline](quickstart/lan-scale.md) |
| Compose bounded discovery domains through static Event bridges | [Hierarchy MVP](../docker/hierarchy-mvp/README.md) and [hierarchy scale diagnostic](quickstart/hierarchy-scale.md) |
| Call Aster from Connect, gRPC, or gRPC-Web | [Local ConnectRPC agent](quickstart/connect-agent.md) |
| Use the live Event API from Rust | [Selected Event API](quickstart/selected-event-api.md) |
| Review the proposed bounded Linux/Event customer profile | [Linux Event MVP Evaluation Profile v0.1](implementation/linux-event-mvp-evaluation-profile-v0.1.md), its [decision register](implementation/linux-event-mvp-evaluation-profile-v0.1-register.md), and the [candidate-annex schema](implementation/linux-event-mvp-evaluation-profile-v0.1-annex-template.md) |
| Use live State, Record, or Blob from Rust | [Selected State API](quickstart/selected-state-api.md), [Selected Record API](quickstart/selected-record-api.md), or [Selected Blob API](quickstart/selected-blob-api.md) |
| Explore current State, Record, or Blob behavior | [State](quickstart/selected-state-api.md), [Record](quickstart/selected-record-api.md), or [Blob](quickstart/selected-blob-api.md) |
| Use the semantic API from Rust, Python, Go, or C | [Language quickstarts](quickstart/README.md) |
| See examples for every data class | [Application recipes](application-recipes.md) |
| Run and inspect a multi-process mesh | [Live mesh CLI](quickstart/mesh-cli.md) |
| Understand component and trust boundaries | [Selected architecture](architecture.md) |
| Connect nodes or add a carrier | [Carriers and contacts](transports.md) |
| Choose between State, Event, Record, and Blob | [Choosing a data class](concepts.md#choosing-a-data-class) |
| Handle conflicts, deletion, priority, or expiry | [Framework mechanisms](concepts.md#framework-mechanisms) |
| Design a binding | [Binding pattern](bindings/pattern.md) |
| Implement an independent compatible profile-`0x0001` node | [Protocol](protocol.md), [wire grammar](wire.cddl), and [security objects](envelope.md) |
| Review the additive profile-`0x0002` implementation boundary | [Classical Iroh-QUIC profile](classical-iroh-security-profile.md); complete normative byte grammar, independent vectors, and a black-box conformance lane remain open |
| Assess progress, security policy, or production blockers | [Capability roadmap](implementation/capability-roadmap.md), [Security-profile requirements disposition](implementation/security-profile-requirements-disposition.md), [Security](security.md), [Conformance](conformance.md), and [requirements status](implementation/requirements-status.md) |
| Review development inputs and public provenance | [Public development provenance record](provenance/independent-development-record.md) and [public source register](provenance/public-source-register.csv) |
| Run validation or interpret evidence | [CI](ci.md), [Conformance](conformance.md), and the [lab guide](../lab/README.md) |

## Know which kind of document you are reading

| Type | Purpose | Authority |
|---|---|---|
| **Quickstart** | Get to a working result | Demonstrates the bounded behavior it names |
| **Concept guide** | Explain the model and tradeoffs | Educational; links to normative details |
| **Integration guide** | Connect Aster to an application, platform, or carrier | Describes supported seams and explicit gaps |
| **Specification** | Define interoperable bytes and behavior | Normative for protocol compatibility |
| **Decision or proposal** | Record why a boundary exists or how an experiment is scoped | Historical design record; proposals are non-normative |
| **Requirements disposition** | Record reviewed applicability without rewriting the hash-bound source | Current planning/profile authority for the exact rows it names; not implementation evidence |
| **Evidence** | State what has been tested and what remains gated | Authority for implementation and release claims |

If a tutorial and a specification appear to disagree, the specification is
authoritative for interoperability. The
[requirements status](implementation/requirements-status.md) is authoritative
for which production requirements the selected composition has reached. The
[capability roadmap](implementation/capability-roadmap.md) groups those details
into outcomes for planning and PR review. The
[security-profile disposition](implementation/security-profile-requirements-disposition.md)
controls current applicability for its exact metadata and post-quantum rows;
the protocol and security-object specifications define profile `0x0001`; the
[classical Iroh-QUIC profile](classical-iroh-security-profile.md) defines the
additive, evaluation-only profile `0x0002` boundary.

## Capability snapshot

The selected implementation deliberately exposes different maturity levels:

- **Event** has direct-Iroh networking and one operator-pinned controlled Iroh
  connectivity relay, plus live Rust and local ConnectRPC APIs. A
  [retained 9,573-byte live-Event receipt](implementation/evidence/selected-live-event-c464129.json)
  (SHA-256
  `4d71d04e4ebcc9f63c0e84e7f11e83bf1f3d1ad2ca8608486cdcc875b6dfeef0`,
  signed source `c464129`) observes four peerless publications—three alpha and
  one authorized beta—on one same-implementation loopback host. A threshold
  contact transfers alpha sequences 1 and 3 with authenticated gap `[2,3)`;
  after a flushed unacknowledged poll and forced receiver-child termination, a
  fresh process receives the same IDs as attempt 2 and acknowledges/re-acks
  them. A normal contact delivers sequence 2 and closes the gap. Beta remains
  withheld; subscribing observes `PolicyChangedSinceContact`, then removal and
  idempotent removal, with no post-change contact or beta delivery. Awaiting
  status has zero failed attempts. This is not physical, NAT/Internet, relay,
  BTLE, mixed-implementation, scale/resource, other-class, or release evidence.
- **State and Record** have cloneable live Rust handles backed by the running
  actor plus exclusive stopped-node facades, and reconcile directly between
  selected nodes under explicit interests. State additionally has durable
  positive-current-version delivery in Rust. A
  [retained bounded v2 receipt](implementation/evidence/selected-live-mutable-6cabb4c.json)
  covers peerless publication, direct convergence, exact concurrent State
  heads, a causally later successor, a visible authenticated tombstone through
  one immediate peerless restart, explicit Record conflict/resolution, and
  handle closure on one loopback host. A separate
  [retained 9,656-byte State-delivery receipt](implementation/evidence/selected-live-state-subscription-8912fc3.json)
  binds signed source `8912fc3` and observes, on one same-implementation
  loopback host, a flushed unacknowledged poll, forced receiver-process
  termination, fresh-process attempt-2 redelivery and acknowledgement,
  selector withholding, causal ancestor suppression, an explicit current
  tombstone, and one final peerless subscription replay. Record separately has
  durable whole-key active-head delivery and a
  [retained 10,357-byte receipt](implementation/evidence/selected-live-record-subscription-0c11344.json)
  covering a whole conflict, forced-process attempt-2 redelivery, guarded
  resolution, a successor projection, selector separation, and final peerless
  reopen. That receipt moves only `DM-5.1-08`; Blob delivery has separate
  retained acceptance described below. State contact/status and
  materialized-view/synthetic-withdrawal behavior, dynamic State network
  interests, selected-node bindings, finite TTL,
  tombstone retention duration/garbage collection, and representative
  physical/mixed acceptance, scale/resource evidence, and release authorization
  remain open.
- **Blob** has a cloneable `RunningNode::selected_blobs()` Rust handle for
  peerless-capable durable regular-file publication and authenticated reads of
  at most one 64-KiB, zeroize-on-drop plaintext page, plus durable metadata-only
  publication delivery keyed by exact source-publication identity. Its exclusive
  stopped streaming facade retains the same delivery lifecycle when no actor
  owns the store. Semantic v5
  can later synchronize the already-durable source and carrier ranges directly
  between current content-capable peers, with durable restart/resume state and
  bounded retained one-host interrupted/reopened/different-peer resume,
  completion, read, and reopen evidence; that receipt predates the delivery
  ledger. A separate
  [retained 10,269-byte Blob-delivery receipt](implementation/evidence/selected-live-blob-subscription-26e0a09.json)
  (SHA-256
  `3d0c0b2da629282c56de5ae9dacc8920c9960defba083c6bff856e2c0612a675`,
  Good-signed source `26e0a09`) observes one participant on one peerless host
  across three processes and four actor lifetimes. The attempt-one child is
  sent `SIGKILL` after flushing an unacknowledged delivery; a fresh process
  receives attempt 2, acknowledges with the persisted attempt-one token,
  settles a second exact publication sharing the same `BlobId`, and leaves the
  final reopened ledger empty. Peer/convergence status, network transfer,
  selector/network-interest separation, route-only custody, arbitrary-peer
  resume, power-loss/filesystem-crash/long-offline recovery,
  large/RSS acceptance, TTL/expiry/garbage collection, representative physical
  or mixed-implementation evidence, and release authorization remain open.
- **Nearby discovery and static Event hierarchy** are default-off evaluation
  surfaces. Mission-authenticated `--discover-lan` contacts require no
  operator-supplied remote identity or address; semantic v6 adds an opt-in,
  Event-only bridge lane over authenticated, statically authorized directed
  edges. The LAN and hierarchy Compose diagnostics exercise bounded local
  domains, outsider rejection, filtered payload-blind forwarding, and durable
  reopen behavior. They add no retained physical, hostile-network,
  mixed-implementation, capacity, complete-MVP, or production credit; dynamic
  bridge administration and lifecycle remain open.
- The broader semantic Rust implementation and language bindings remain the
  proven migration source for behavior not yet composed into the selected node.

A [retained two-cell receipt](implementation/requirements-status.md#selected-iroh-nat-retained-receipt)
observes exact Event delivery and no-op replay through one cone/direct and one
restrictive/controlled-relay Docker Linux namespace-NAT cell on one Darwin
arm64 host. It is not discovery or punching, temporal fallback chronology,
representative or physical NAT, public Internet or public/default relay,
independent implementation, State/Record/Blob relay, complete-MVP, or release
evidence.

The live mutable receipt is a 7,752-byte canonical projection with SHA-256
`054945ecf94e8bfba1b130f6a5f47e9b1e0e17ad69f3b1472085a1d10f05eeaa`,
bound to signed source `6cabb4c`. Its two participants ran six actor lifetimes
with at most two concurrent, eight direct `CONTACT` records and aggregate 7/7/7
selected-item offer/fetch/insert counts, six graceful shutdowns, four closed
retained handles, and zero Event/control/Blob counters. The State proof starts
with two exact concurrent heads, advances through a successor that observes and
supersedes both, then through an empty tombstone that observes and supersedes
all three predecessors and remains current at both actors and one immediate
peerless restart. This is a producer-attested ordered, one-host,
same-implementation loopback chain with an operator-attested, non-reproducible
source-to-execution link and metadata-only secret inspection; it is not proof
of indefinite tombstone retention, garbage collection, delete-wins, physical
or mixed implementations, NAT/relay, BTLE, scale, resource bounds,
long-duration operation, release, or Event/Blob-live acceptance. Those are
limits of the State/Record receipt, not of the separate receipts
linked above and below; its zero Blob counters do not evidence the newer live
Blob handle.

A separate [retained 10,357-byte v1 Record-delivery receipt](implementation/evidence/selected-live-record-subscription-0c11344.json)
(SHA-256
`ba0e2bf47291f7e87000b85fa280cc957f3710ac800def82a51fb9b4657a1b48`)
binds Good-signed source commit `0c1134411953f4bb52133b50aff9989cd4ce3930`.
On one same-implementation direct-loopback host, two participants ran three
processes and seven actor lifetimes. A complete two-head edit/tombstone conflict
remained one delivery at `delivery_limit=1` and `scan_limit=16`. After the
receiver was sent `SIGKILL` following its flushed durable unacknowledged
attempt-one poll, a fresh process received the same projection at attempt two
with a rotated 89-byte token. A fresh exact query guard was then required to
resolve both heads; the new successor arrived under a new projection and both
originals remained query-only superseded history. The beta object was
network-interested but application-unmatched and retained without delivery; the
gamma object was application-matched but network-uninterested and withheld, so
the subscription did not mutate network interest. A final peerless reopen
replayed the subscription with an empty acknowledged queue, the resolved current
successor, and two query-only superseded originals. This receipt moves only
`DM-5.1-08`. It adds no finite-TTL/GC, physical/NAT/relay/BTLE,
mixed-implementation, scale/resource/soak, selected-node bindings, automatic
merge, reproducible source-to-binary proof, or release credit.

A separate [retained 10,728-byte v2 live-Blob receipt](implementation/evidence/selected-live-blob-044d90f.json)
(SHA-256
`4fea2ffbd16608862a67167fb1b8fcb6d5d8b4b82c576aa9a6b7e25ee9c55909`)
binds signed source commit `044d90ff07c8e754b3d490cb810d42de3c915e3d`
with `Good` signature status. Its three participants ran 11 actor lifetimes and
32 error-free direct `CONTACT` records: a publisher committed while peerless; a replica
received all 98,638 carrier bytes; a receiver retained an interrupted
exactly-one-contact 16,384-byte prefix, reopened peerless with that exact
progress, resumed exactly 16,384 bytes from the different replica without
refetching the source, fetched the exact remaining 65,870 bytes, reconstructed
all 98,638 carrier bytes, and reopened peerless for a final authenticated read.
Its source-to-execution link remains operator-attested, not cryptographically
proven. This is one-host, same-implementation evidence of graceful same-process
actor/store/provider reopen only. It does not prove process-crash, power-loss,
long-offline, arbitrary-peer, or route-only resume; NAT, Internet, relay, or
BTLE paths; independent-implementation interoperability; scale beyond three
participants; resource thresholds or soak; physical sanitization; or release
authorization.

Aster remains an evaluation-stage reference implementation. Do not infer
production authorization from code presence or a passing demo. The
[project overview](../README.md#current-implementation-boundary) gives a compact
boundary; [requirements status](implementation/requirements-status.md),
[Conformance](conformance.md), and [Security](security.md) carry the details.

## Reference collections

- [Reference index](reference-index.md) — primary specifications, integration
  references, validation records, proposals, and architecture decisions.
- [Proposal index](proposals/README.md) — experiment lifecycle and results.
- [Wire grammar](wire.cddl) — compact CDDL definition.
- [Source requirements](../data-mesh-requirements.md) — frozen target-state
  grounding requirements; use the [capability roadmap](implementation/capability-roadmap.md)
  for delivery planning and PR review.
- [Public development provenance record](provenance/independent-development-record.md)
  — review path from product intent and public inputs to decisions,
  implementation, and retained repository history.

## Contributing

Start with [CONTRIBUTING.md](../CONTRIBUTING.md). Follow the project's
project source rules and provenance requirements for every change.
