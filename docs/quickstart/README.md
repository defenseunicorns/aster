# Aster quickstarts

To meet Aster through a human-driven three-node story, begin with
[Aster Field Notes](hello.md). For deterministic acceptance receipts, run the
one-command [capability tour](capability-tour.md). To keep a bounded local
line running, choose publishers, enter synthetic messages, and change node
availability, use the [real-process message playground](message-playground.md).
For an evaluation-only three-host Event flow with automatic mDNS discovery on
one trusted LAN—or its fast, one-host Docker Compose rehearsal—use the
[LAN MVP quickstart](lan-mvp.md).
To measure 8, 16, or 32 rosterless nodes concurrently on a generated private
Docker bridge before beginning hierarchy, use the opt-in
[LAN scale baseline](lan-scale.md).
To compose isolated discovery domains through two static, payload-blind Event
bridge hops, run the [hierarchy MVP](../../docker/hierarchy-mvp/README.md), then
advance through the explicit tiers in the
[hierarchy scale diagnostic](hierarchy-scale.md).
This page indexes the offline application and language-binding quickstarts.

For the shortest operator-focused path through the customer Event evaluation
slice, including health, capacity, ReceiveOnly, restart, and the boundary to
the still-unpackaged D06 provider lifecycle, use the
[Linux Event MVP operator runbook](../mvp/linux-event-mvp-runbook.md).

For the selected production-lane composition, start with the Rust
[live Event quickstart](selected-event-api.md). It demonstrates peerless publish,
bounded query, durable at-least-once subscribe/poll/ack, idempotent unsubscribe,
freshly verified gap inspection, and bounded peer/last-contact status through
the running actor's sole authority. A focused real-process test publishes
offline and synchronizes later. The separate [selected State
quickstart](selected-state-api.md) demonstrates cloneable live publish/query
and durable positive-current-version delivery through the running actor plus
stopped/exclusive latest-value access, causal projection, recoverable versions,
and visible authenticated tombstones. The
[selected Record quickstart](selected-record-api.md) demonstrates live and
stopped durable revisions, explicit conflict siblings, exact-guard application
resolution, and retained-bounded durable whole-key active-head delivery. The
[selected Blob quickstart](selected-blob-api.md)
demonstrates the cloneable live handle's peerless-capable durable regular-file
publication, bounded zeroize-on-drop page reads, and durable metadata-only
publication delivery, as well as the exclusive stopped streaming facade,
immutable metadata-bound identity, crash-resumable encrypted chunks, and exact
durable retry. Its
[retained 10,269-byte Blob-delivery receipt](../implementation/evidence/selected-live-blob-subscription-26e0a09.json)
(SHA-256
`3d0c0b2da629282c56de5ae9dacc8920c9960defba083c6bff856e2c0612a675`,
Good-signed source `26e0a09`) observes one peerless participant across three
processes/four actor lifetimes: forced termination after a flushed attempt-one
poll, fresh-process attempt-2 redelivery acknowledged with the older token, two
exact publications sharing one `BlobId`, and a final empty reopened ledger.
Blob peer/convergence status, network contact/transfer,
selector/network-interest separation, State contact/status and
materialized-view/synthetic-withdrawal behavior,
dynamic State network interests, automatic registered-policy Record merge,
atomic Event subscription update, selected-node language bindings, and
TTL/GC, power-loss/filesystem-crash, resource/soak, representative physical or
mixed-implementation acceptance, and release authorization remain open.

A [retained 9,656-byte State-delivery receipt](../implementation/evidence/selected-live-state-subscription-8912fc3.json)
(SHA-256
`7d0b568dd4d57c3f2967da55953896829261877513c59c51a0b274eeda69485f`,
signed source `8912fc3`) observes one durable State application subscription
on one same-implementation loopback host. A fresh receiver process redelivers
the same State identity as attempt 2 after its predecessor was forcibly
terminated following a flushed unacknowledged poll, then acknowledges,
idempotently re-acknowledges, and polls empty. The run also observes static
network/application selector separation, an authorized but network-uninterested
withheld State, acknowledged/superseded ancestor suppression, a current
tombstone, and final peerless subscription replay. It does not prove a
materialized State view or synthetic withdrawals, dynamic network interests,
physical/NAT/relay/BTLE or mixed implementations, scale beyond two,
resource/soak thresholds, or release authorization.

A [retained 10,357-byte Record-delivery receipt](../implementation/evidence/selected-live-record-subscription-0c11344.json)
(SHA-256
`ba0e2bf47291f7e87000b85fa280cc957f3710ac800def82a51fb9b4657a1b48`,
Good-signed source `0c11344`) observes one complete edit/tombstone projection
across attempt-one flush, forced receiver `SIGKILL`, and fresh-process
attempt-two replay with a rotated 89-byte token. It then requires a fresh query
guard, resolves the conflict, delivers a new successor projection, retains both
siblings as query-only Superseded history, preserves beta/gamma selector
separation, and reopens peerless with an empty queue. It moves only
`DM-5.1-08`; it is not TTL/GC, physical/NAT/relay/BTLE, mixed, scale/resource,
binding, automatic-merge, reproducible-build, or release evidence.

A [retained 9,573-byte live-Event receipt](../implementation/evidence/selected-live-event-c464129.json)
(SHA-256
`4d71d04e4ebcc9f63c0e84e7f11e83bf1f3d1ad2ca8608486cdcc875b6dfeef0`,
signed source `c464129`) observes four peerless Events, threshold transfer of
alpha 1 and 3 with authenticated gap `[2,3)`, forced receiver-child termination
after a flushed unacknowledged poll, fresh-process attempt-2 redelivery with
ack/re-ack, and Normal transfer of alpha 2 closing the gap. Beta stays withheld;
a temporary subscription yields `PolicyChangedSinceContact` and is removed
without another contact or delivery. Awaiting observations have zero failed
attempts. This is one-host, same-implementation direct-loopback evidence—not
physical/NAT/relay/BTLE, mixed, scale/resource, other-class, or release
acceptance.

A [retained 10,728-byte live-Blob receipt](../implementation/evidence/selected-live-blob-044d90f.json)
(SHA-256
`4fea2ffbd16608862a67167fb1b8fcb6d5d8b4b82c576aa9a6b7e25ee9c55909`)
binds source commit `044d90ff07c8e754b3d490cb810d42de3c915e3d` with
`Good` signature status; 45 adversarial verifier tests pass. Its
source-to-execution link remains operator-attested, not cryptographically
proven. Across three participants and 32 direct-loopback `CONTACT` records, it
observes peerless publication and seeding, an exactly-one-contact partial
transfer, exact retained-prefix persistence across receiver reopen, an
exactly-one-contact continuation from the different eligible replica with no
source refetch and exact-complement advancement, exact byte reconstruction and
promotion, bounded live page reads, and a final receiver reopen. This is
one-host, same-implementation evidence, and every interruption or restart is a
graceful same-process actor/store/provider reopen. It does not prove physical
hosts, NAT or Internet paths, controlled or public relay, BTLE, process crash
or power-loss recovery, long-offline recovery, arbitrary-peer or route-only
resume, scale beyond three participants, resource thresholds or soak,
physical sanitization, independent-implementation interoperability, or release
authorization.

The alpha [local ConnectRPC agent](connect-agent.md) exposes that live Event
handle to standard Connect, gRPC, and gRPC-Web clients over an authenticated
loopback listener. Its schema is repository-owned and requires no Buf Schema
Registry. Live State/Record/Blob RPCs and production deployment authorization
remain open.

The evaluation-only [message playground](message-playground.md) composes 2
through 32 real agent processes around that same Event API. It is a one-host,
all-member, unprotected-reference demo, not an end-user chat product or scale,
global-convergence, physical-transport, and release result.

The three-node [Field Notes hello](hello.md) adds staged Atlas/Beacon/Cove
activation and an explicit choice between ten-second nearby locator windows
and controller-known one-host invitation routes. It is the human introduction,
not an automatic-discovery or production evidence claim.

The [three-host LAN MVP](lan-mvp.md) is a separate feature-gated procedure. It
uses mission-authenticated automatic discovery without operator-supplied peer
IDs or addresses, stages one Event across A-to-B and B-to-C contacts, verifies
C's durable reopen, and checks rejection of a separately provisioned outsider.
It is not retained physical, hostile-LAN, NAT/WAN, or production evidence.

The [hierarchy MVP](../../docker/hierarchy-mvp/README.md) is a five-node,
three-segment Compose evaluation. Two route-only bridges discover only adjacent
peers, apply static topic/priority-narrowed authorizations, and carry one Event
across two semantic-v6 bridge hops without configured remote peer coordinates.
The [hierarchy scale diagnostic](hierarchy-scale.md) generates eight leaf
scopes, two regions, and one root at fixed 8-, 32-, or 64-publisher tiers. Both
are same-host development feedback, not retained physical, hostile-network,
capacity, complete-MVP, or production evidence.

Choose the API closest to your application:

| Language | API you use | Quickstart |
|---|---|---|
| Human-driven three-node introduction | `mise run hello` | [Aster Field Notes](hello.md) |
| Ready-built Debian package, two static peers | `mise run deb-compose -- --deb /path/to/aster.deb` | [Package Compose smoke](../../docker/deb-test/README.md) |
| One-host automatic-discovery rehearsal | `mise run lan-mvp-compose` | [LAN MVP](lan-mvp.md#fast-one-host-docker-rehearsal) |
| Concurrent 8/16/32-node LAN diagnostic | `mise run lan-scale-compose -- --nodes N` | [LAN scale baseline](lan-scale.md) |
| Five-node, three-segment static Event hierarchy | `mise run hierarchy-mvp-compose` | [Hierarchy MVP](../../docker/hierarchy-mvp/README.md) |
| Generated 8/32/64-publisher hierarchy diagnostic | `mise run hierarchy-scale-compose -- --publishers-per-leaf N` | [Hierarchy scale](hierarchy-scale.md) |
| Three-host trusted-LAN Event evaluation | `aster-agent --discover-lan` | [LAN MVP](lan-mvp.md) |
| Interactive local process demo | `mise run playground -- --nodes N` | [Message playground](message-playground.md) |
| Rust (selected live Event slice) | `aster_node::start_node` + `SelectedEventHandle` | [Selected Event API](selected-event-api.md) |
| ConnectRPC client (alpha live Event slice) | local `aster.application.v1alpha1` schema | [Local ConnectRPC agent](connect-agent.md) |
| Rust (selected stopped Event slice) | `aster-node::application::SelectedEventNode` | [Selected Event API](selected-event-api.md#one-authority-two-application-modes) |
| Rust (selected live or stopped control administration) | `aster_node::SelectedControlHandle` or `aster_node::SelectedControlAdmin` | [Selected Event API](selected-event-api.md#publish-controls-through-the-live-actor) |
| Rust (selected live State slice) | `aster_node::start_node` + `SelectedStateHandle` | [Selected State API](selected-state-api.md#use-the-live-actor-api) |
| Rust (selected stopped State slice) | `aster-node::application::SelectedStateNode` | [Selected State API](selected-state-api.md#use-the-stopped-api) |
| Rust (selected live Record slice) | `aster_node::start_node` + `SelectedRecordHandle` | [Selected Record API](selected-record-api.md#use-the-live-actor-api) |
| Rust (selected stopped Record slice) | `aster-node::application::SelectedRecordNode` | [Selected Record API](selected-record-api.md#use-the-stopped-api) |
| Rust (selected live Blob slice) | `aster_node::start_node` + `RunningNode::selected_blobs()` | [Selected Blob API](selected-blob-api.md#use-the-live-actor-api) |
| Rust (selected stopped Blob slice) | `aster-node::application::SelectedBlobNode` | [Selected Blob API](selected-blob-api.md#use-the-stopped-streaming-api) |
| Rust | Native high-level `ApplicationNode` | [Rust](rust.md) |
| Python | Dependency-free `ctypes` wrapper over the native library | [Python](python.md) |
| Go | cgo wrapper over the native library | [Go](go.md) |
| C / C-compatible FFI | Stable ABI v1 | [C](c.md) |

The four broader semantic language quickstarts perform the same State flow:

1. Open a node with a disposable, non-production provisioning bundle.
2. Create a durable subscription.
3. Publish State while no peer is connected.
4. Poll the local subscription and acknowledge delivery.
5. Close the node cleanly.

The selected Rust Event guide instead adds a live actor and a focused later-sync
process test. The selected Rust State and Record guides use the production-lane
store and security composition through either the running actor's shared
bounded command lane or an exclusive stopped facade. The Record guide adds
explicit conflict annotation and guarded resolution. The selected Rust Blob
guide either sends bounded commands through the running actor's cloneable
handle or streams through the exclusive stopped facade, without exposing
source-envelope or provider internals. The language examples remain
intentionally offline exercises. After one works, continue with
[Carriers and contacts](../transports.md) to understand live synchronization.
The fixture path is unprotected compatibility/test ingestion. Caller-composed
Rust `NodeConfig`, stopped `SelectedEventNode`, and stopped
`SelectedControlAdmin` compose the provider-owned artifact boundary or opaque
SecretStore-reference load seam, and a running node exposes the privileged
`SelectedControlHandle`. No production backend, protected stock CLI,
cross-process administration, coordinated destroy workflow, or protected C,
Go, or Python entry point is shipped; see
[ADR 0013](../decisions/0013-protected-provisioning-boundary.md).

## Shared toolchain prerequisite

The repository pins Rust 1.97.1, installed with `mise install`. The crates'
minimum supported Rust version (MSRV) is Rust 1.91. Each language quickstart
uses the pinned toolchain to build the Rust core or native library.

## Shared vocabulary

The application APIs share these concepts where the selected data class uses
them:

- a **topic** says what the data is;
- a **scope** says where it is allowed to propagate;
- a **logical key** identifies the thing within State or Record data;
- a **data class** selects convergence behavior;
- **priority** expresses scheduling and pressure intent; selected Event has
  bounded priority scheduling/custody behavior, while State, Record, and Blob
  priority-aware transmission and cross-class eviction remain open;
- **TTL** controls how long an item remains useful; selected Event has a bounded
  finite-custody path, while selected State, Record, and Blob reject finite TTL;
  and
- a **publish result** identifies a durable local commit.

Read [Core concepts](../concepts.md) before adapting the example to operational
data.
