# Decision 0009: Separate the application API from adapter internals

- Status: accepted as an application ergonomics boundary; prior adapter
  security-boundary claim withdrawn
- Date: 2026-08-18
- Amended: 2026-08-27

The default Rust library and every first-class language binding expose only
application operations: node lifecycle, offline publish, streamed Blob I/O,
subscribe and acknowledge, bounded query, conflict inspection/resolution,
emission policy, bridge policy, peer/sync status, provisioning installation,
and zeroization.

Cryptographic algorithms and keys, source-envelope construction, handshake
flights, fragmentation, inventory trees, reconciliation messages, sealed-object
ingest/emission, and link choice are not application APIs. Rust transport
adapters and conformance tooling require some of these contracts, so the core
places them behind the explicit, non-default `adapter-sdk` feature. The IP,
BTLE, C-boundary implementation, and conformance packages opt into that feature;
ordinary Rust dependents do not.

The intended carrier path moves opaque frames through the authenticated runtime,
but the implemented `adapter-sdk` feature is broader than that path. It publicly
exports engine, crypto/provider, store, wire, and control-facing modules,
including `RecordStore`/`StoredItem` mutation seams. Code compiled with this
feature can bypass provider validation or directly mutate state below the
application boundary. It is therefore a privileged, trusted integration
contract and part of Aster's in-process trusted computing base, not a security
boundary for third-party adapter code.

Cargo feature unification expands that public surface for every dependent crate
in the same build when `aster-host`, a workspace adapter, or another dependency
enables `adapter-sdk`. Import discipline is a convention, not capability
enforcement. The claim that untrusted carrier input cannot authorize peer or
application state applies to bytes processed through the built-in `Link` and
runtime path; it does not constrain arbitrary in-process code with access to the
broad feature.

The C header must not export the internal sealed-object emission/ingest seam.
Language bindings are generated from the application portion of that header and
must not reconstruct a transport or sync engine. Internal integration tests may
compile against the adapter feature without turning it into the default public
surface.

The implemented Rust boundary is `ApplicationNode`. It owns the generic engine,
accepts either a provider-owned protected artifact through `open_protected` or
canonical unprotected inner bytes through the documented compatibility/test
path, requires bounded query/delivery pages, rejects generic whole-buffer Blob
publication, selects Blob epochs internally, and maps items/publication receipts
to application records that omit causal vectors and sealed bytes. The
application API never returns keys or protection-provider internals. The
explicit application merge-helper input contains only IDs, publisher IDs,
payloads, and tombstone flags; callers must supply it in ascending full-ItemID
order. All underlying modules are private unless `adapter-sdk` is selected;
every workspace adapter/tool that needs them opts in explicitly.

This separation follows the supplied requirement that application developers
need no knowledge of cryptography, fragmentation, transport selection, or sync
internals while preserving a documented path for future transport packages.

## Required follow-on boundary

Before Aster claims that third-party carrier implementations cannot bypass
authentication, the public feature must be split. A narrow carrier-only SDK
should expose opaque frame I/O, route hints, MTU/characteristics, and discovery
lifecycle without exporting store records, engine ingest, crypto providers, or
control mutation. Compile-time API-surface tests and adversarial integration
tests must prove that code confined to that SDK cannot construct or commit
authenticated application/control state directly.

That split would be a protocol-level least-privilege boundary, not isolation
from hostile code in the same process. Treating an adapter implementation itself
as untrusted additionally requires a separate process or an equivalent OS/runtime
sandbox with a narrow authenticated IPC contract. Neither split nor isolation is
implemented today, so no code-hardening claim is made by this amendment.

## Implementation correction (2026-08-20)

`register_merge_policy` is retained for API compatibility, but registration is
process-local and its only automatic effect is to associate the policy ID with
high-level Record conflict annotations. Direct and forwarded replicated
ingestion never invoke application policy. Applications inspect siblings and
publish reviewed output through explicit `resolve()`. This prevents
peer-triggered ingestion from creating recursive merge publications and leaves
requirements §5.3 automatic merge partial pending a convergent design.

## Selected production-lane Event slices (2026-08-24)

`aster-node::application::SelectedEventNode` was the first high-level surface
over the selected redb/runtime security composition. It owns the exact
mission-bound redb writer authority while the mesh process is stopped and
exposes arbitrary policy-authorized Event publication and bounded
marker-ordered query. Publication is durably idempotent by an application
operation key. A stacked slice adds durable Consume subscriptions, bounded
at-least-once poll attempts, and idempotent semantic-Event acknowledgement.
Queries return freshly source/content-verified plaintext application fields and
semantic Event identities; they omit exact transfer IDs, sealed bytes, keys,
provider selection, inventories, reconciliation, and carrier choice.

Subscription filters are durable receive intent, not capabilities. The live
runtime projects Consume plus internal route-only Carry selectors into a
canonical mission-protected interest, where an empty set means receive-none.
For overlapping local selectors, Consume dominates Carry so forwarding intent
cannot suppress an otherwise authorized application delivery.
Legacy selected stores migrate with an empty selector set and therefore also
receive nothing until explicit local intent is created; there is no wildcard
compatibility fallback or pre-interest Event inventory.
Each contact reconciles a separate exact-ID universe for each receiver and
rechecks source, active control/epoch state, negotiated interest, and current
route authority before transfer or commit. Poll discovery scans unfiltered
acceptance rows so stored header metadata cannot suppress fresh source
verification before the durable cursor advances. The selected surface exposes
only fixed, sanitized error categories rather than store, envelope, provider,
carrier, or transfer details.

The mission channel protects selector names from outside observers, but an
authenticated mission peer can read their topic/scope values under the current
membership-visible forwarding-metadata policy. Route checks still withhold
unauthorized Event identities and bytes. Scope-private subscription intent is
a separate future opaque-selector boundary, not a claim of this slice.

`aster-redb-store` remains an unpublished, privileged composition crate. Its
two-phase poll plan and commit-selection types carry trusted classifications
from the selected node; they do not mint or prove cryptographic authority on
their own. Calling those methods directly is inside Aster's in-process trusted
computing base, just like the broader `adapter-sdk` seams above. The supported
application boundaries are stopped `SelectedEventNode` and live
`SelectedEventHandle`. Both freshly authenticate planned rows, open content only
for authorized Consume deliveries, and return only sanitized application
records and errors.

The live handle is a cloneable command capability for the running node's sole
actor; it does not open another store. It adds idempotent unsubscribe, bounded
authenticated gap inspection, and peer/last-contact status. Selector insertion
and removal serialize against contact policy capture. A replacement selector is
an explicit unsubscribe followed by subscribe, not an atomic update. Gap
intervals are anchored only by freshly source/content-verified positions already
observed in the mission-bound store. Last-contact status is process-local and
does not claim reachability, publisher completeness, or global convergence.

At the PR-C boundary these Event slices did not replace the broader proven
semantic `ApplicationNode` or complete the accepted boundary. They had no
atomic subscription update, live State/Record, Blob, selected-node bindings,
protected operational provisioning, generalized control administration, or
finite TTL. The later selected custody slice now adds Linux-only semantic-v3
finite Event TTL with authenticated cumulative forwarding age and expiry; it
does not close the other boundaries above.
The compiled example and exact claim boundary are documented in the
[selected Event API quickstart](../quickstart/selected-event-api.md).

## Selected production-lane local State slice (2026-08-24)

`aster-node::application::SelectedStateNode` adds a second high-level boundary
over the same selected mission-bound writer, control policy, source-envelope
provider, and causal ledger. It is intentionally an exclusive stopped-node
surface: application callers can publish one source-authenticated State version
idempotently and query the deterministic projection for one exact
topic/scope/logical key. It has no live command handle, subscription, carrier,
or reconciliation operation.

The facade returns semantic `StateId`, authenticated application fields, one
`Current` value, and optionally retained active `Concurrent` and `Superseded`
versions. It omits transfer identities, sealed representations, keys, provider
selection, causal vectors, redb table names, and structural plan tokens. A
current tombstone remains a visible `StateItem` with an empty payload; it is not
collapsed into an unauthenticated absence. Concurrent tombstones and edits use
the same deterministic semantic-ID tie-break as every other State maximum;
there is no special delete-wins rule.

The stopped facade treats redb results as untrusted structural candidates. On
publish it freshly verifies the full authenticated header, semantic and exact
identities, and exact plaintext against the caller's request after the atomic
commit or idempotent replay. On query it freshly source/content verifies all
retained candidates, including inactive revoked or old-epoch rows, recomputes
causal dominance and the complete-semantic-ID tie-break independently, and
requires the exact policy-bound projection plan to remain unchanged. Only active
versions are exposed. The operation mapping remains a privileged store
mechanism, not a capability; current authority and revocation checks precede an
exact replay.

Event and State share publisher counters and the causal frontier, so the new
class cannot reuse an Event dot. The State tables and operation ledger have
dedicated count/byte bounds and participate in aggregate store quotas. None of
this changes the Event frame grammar or reconciliation lanes. Live State,
network replication, subscriptions, TTL, expiry, garbage collection, selected-
node bindings, live or replicated Record, Blob, independent interoperability, and acceptance
evidence remain open. The compiled example and exact boundary are documented in
the [selected State API quickstart](../quickstart/selected-state-api.md).

## Selected production-lane local Record slice (2026-08-24)

`aster-node::application::SelectedRecordNode` adds an exclusive stopped-node
Record boundary over the same mission-bound writer, current control policy,
source-envelope provider, and publisher causal ledger as Event and State. It
publishes source-authenticated Record revisions by durable operation key,
queries one exact topic/scope/logical key, and accepts an explicit reviewed
successor through an opaque exact-sibling resolution guard. It has no live
command handle, subscription, carrier, reconciliation, or language-binding
operation.

The facade exposes semantic `RecordId`, authenticated application fields, one
deterministic `Current` head, every other active causal maximum as
`Concurrent`, optional active `Superseded` history, and an explicit
`RecordConflict` containing sorted sibling identities and a private guard. It
does not expose exact transfer identities, sealed representations, keys,
provider selection, causal vectors, redb table names, or structural plan
tokens. A current tombstone remains a visible empty-payload `RecordItem`;
concurrent deletion has no special delete-wins priority.

The selected slice never invokes registered application merge code during
ingest. An ordinary publication cannot silently collapse an existing conflict:
if its reserved context observes at least two heads, the transaction fails and
leaves the projection unchanged. An application may inspect the verified
siblings, compute a result in its own code, and call `resolve` with the exact
guard it received. The successor must observe every guarded head. The store
rejects stale guards atomically, and the durable operation digest binds the
sorted head set so the same operation key cannot resolve a different conflict.
An exact authorized retry returns the original immutable result after restart
or rekey; a new operation cannot reuse an old-policy guard.

The stopped facade treats stored rows and projection plans as privileged,
untrusted structural inputs. Query freshly source/content verifies every
retained candidate, including inactive rows, independently recomputes causal
maxima, current/concurrent/superseded dispositions, and the exact sorted head
set, then requires the policy-bound plan to remain unchanged. Resolve repeats
that verification for the supplied guard before the store atomically checks and
commits it. Only active rows cross the application boundary, and all errors are
mapped to the same fixed sanitized categories as the other selected facades.

Event, State, and Record share publisher counter high-water and causal frontier
state so Record cannot reuse another class's dot. Record exact/semantic indexes,
acceptance markers, versions, and the bounded operation ledger remain disjoint;
the Event inventory and frame grammar are unchanged. This is local mechanism
evidence only. There is no automatic registered-policy merge, Record network
ingestion, disconnected-process acceptance, live status, finite TTL, expiry,
garbage collection, or retained execution receipt. The compiled example and
exact boundary are documented in the
[selected Record API quickstart](../quickstart/selected-record-api.md).

## Semantic-v4 State/Record network amendment (2026-08-25)

This amendment supersedes the earlier present-tense statements that selected
State/Record objects have no network path; those statements remain above only
as the historical boundary of the stopped-slice decisions and their receipts.

The stopped application boundary remains unchanged: State and Record publish,
query, and guarded resolution still require exclusive ownership while the live
actor is absent. The selected live actor now reconciles their already durable
source objects only after the mission session selects semantic version 4. This
does not create a live State/Record application handle or subscription. The
default offer is `[4, 3, 2, 1]`; Event retains v1-v3 compatibility and v1-v3
contacts expose no mutable frames.

The v4 mechanics boundary is protected, class- and direction-separated, and
bounded. Offer returns exact `MutableApplyResult`; Fetch returns exact
`MutableFetchResult` and requires exact `MutableFetchResultAck`;
Finish/Finished bind exact remaining. Valid class, byte, or causal-
frontier saturation is `DeferredCapacity`, while integrity and policy failures
remain fatal. State and Record each cap objects at 1 MiB and retained network
admission at 4,096 rows/16 MiB. A durable peer/class/local Offer/Fetch cursor
rotates bounded attempts across at most 256 peers and 1,024 rows.

Current source route lineage is mandatory. A same-epoch replacement withholds
the historical lineage from ordinary current projection/query and network
inventory/transfer; it does not delete the row. Exact idempotent State publish
and Record publish/resolution retries may recover their committed historical
result only through the strict cached/projection/historical verification path.
Selected finite State/Record TTL is rejected.

Normal and every AtLeast threshold run the v4 mutable lanes because AtLeast is
an Event-only threshold. ReceiveOnly initiates and discloses no mutable lane.
`SelectedEventHandle` last-contact status remains Event/contact evidence and is
not State/Record convergence. Blob networking and every retained acceptance or
release gate remain open.

## Semantic-v5 stopped-Blob network amendment (2026-08-25)

The default offer is now `[5, 4, 3, 2, 1]`. V5 inherits the State/Record
mechanics above and adds direct transfer of already-durable Blob sources and
carrier prefixes; v1-v4 emit zero Blob frames. This does not create a live Blob
application handle or subscription. `SelectedBlobNode` remains an exclusive
stopped publish/read facade, while `MutableSourceInterests::with_blob` is an
additive runtime receive configuration rather than an application delivery API.

The v5 lane is direct content-capable only, source-before-carrier, bounded to
16-KiB peer-neutral prefix extensions, and completion-gated before ordinary
visibility. Route-only Blob relay/custody, TTL/GC, pure-byte deduplication,
large/RSS/physical/mixed/release acceptance, and selected-node language
bindings remain outside the public boundary.

## Live State/Record application and retained acceptance amendment (2026-08-26)

This amendment supersedes the earlier present-tense statements that selected
State and Record have no live application handle or retained live-path receipt.
Those statements remain above as the dated boundaries of the stopped and
network-mechanics slices; they are not descriptions of the current composition.

`RunningNode::selected_state()` now returns a cloneable `SelectedStateHandle`,
and `RunningNode::selected_records()` returns a cloneable
`SelectedRecordHandle`. Publish, query, and guarded Record resolution commands
share the running actor's one bounded Event/State/Record lane and its sole
mission-bound store/policy authority. Clones do not open a writer. Graceful
shutdown and live zeroization close admission before authority release, and
retained handles fail with sanitized `StateUnavailable`. The exclusive stopped
facades remain available only while no live actor owns the store.

The [retained v2 canonical receipt](../validation/evidence/selected-live-mutable-6cabb4c.json)
is 7,752 bytes with SHA-256
`054945ecf94e8bfba1b130f6a5f47e9b1e0e17ad69f3b1472085a1d10f05eeaa`
and binds the execution to good-signature source commit `6cabb4c`. Two distinct
participants publish State and Record while peerless, then run eight direct
`CONTACT` records with exact aggregate 7/7/7 selected-item
offer/fetch/insert accounting. The six actor lifetimes never exceed two
concurrent actors. State first preserves the exact
max-ID-current/other-concurrent projection. A causally later successor observes
and supersedes both heads; after the other actor observes that successor, an
authenticated empty tombstone observes and supersedes all three predecessors.
Both actors select it as current, and one immediate peerless restart reproduces
the exact projection. Record preserves two siblings, rejects an ordinary
conflict-collapsing publish, resolves under the exact guard, supersedes both
originals, retries without insertion, and preserves the result across restart.
Six graceful shutdowns and four closed retained handles pass; Event, control,
and Blob counters remain zero.

This is a producer-attested ordered, bounded one-host, same-implementation
loopback chain. The source-to-execution link is operator-attested, not
cryptographically proven or reproducible, and the participant secret artifacts
are inspected by metadata only. The single immediate peerless restart does not
claim indefinite tombstone retention, compaction, garbage collection, or
delete-wins. The amendment does not claim physical hosts, NAT or Internet
operation, controlled/public relay, BTLE, independent interoperability, scale
beyond two, resource thresholds, long-duration operation, live Event or Blob
application acceptance, or release authorization. At that dated boundary,
State/Record durable subscriptions had not yet been added; the later delivery
amendments below supersede it. Selected-node bindings, finite TTL/forwarding
age, relay/multi-hop acceptance, expiry, and automatic Record merge remain open.

## Live selected Blob application amendment (2026-08-27)

This amendment supersedes the earlier present-tense statements that selected
Blob has no live application handle. Those statements remain above as the dated
boundaries of the stopped-Blob and semantic-v5 network slices; they are not a
description of the current composition. The earlier retained State/Record
receipt also remains exactly what it was: its zero Blob counters provide no
evidence for this amendment.

`RunningNode::selected_blobs()` now returns a cloneable `SelectedBlobHandle`.
It shares the running actor's bounded application admission and dispatches each
accepted command to one bounded, joined blocking Blob worker; clones do not
open another Store or depot authority. Async `publish` accepts an owned,
nonempty regular file at cursor offset zero, bounded to 64 MiB and the selected
1,024 canonical 64-KiB chunks. It may commit while no peer is configured.
Success is one durable, source-authenticated, operation-key-idempotent local
publication, not delivery. An exact authorized retry freshly verifies and
returns the original publisher counter and acceptance marker. Different bytes
or identity metadata under the same operation key fail closed as a conflict.
Cancellation after enqueue may leave an indeterminate committed result, so the
exact operation key is the recovery path.

Async `read_page` selects the exact current authorized source and returns one
freshly authenticated, nonempty plaintext page of at most 64 KiB. Plaintext is
private behind a borrow and its owned allocation is zeroized on drop; no raw
`Vec` is returned. An application copy becomes caller custody. The live page is
not a streaming provider handle, subscription delivery, peer observation, or
convergence-status assertion. The exclusive stopped `SelectedBlobNode` remains
available for seekable-source publication and caller-owned streaming output
only while no live actor owns the same store.

The semantic-v5 amendment above remains the networking boundary. A peerless
live publication can be synchronized later, after restart, by direct
source-before-carrier transfer to an exactly interested, current
content-capable peer. Receiver source/prefix progress is durable and ordinary
visibility remains gated on whole-Blob verification and promotion; a later
peerless restart can read the completed Blob through the receiver's live
handle. This composes the live application and existing network mechanisms; it
does not create Blob route-only forwarding or custody.

Graceful shutdown and live zeroization close application admission, reject
queued commands, and join the Blob worker before releasing Store authority.
Retained handles then fail with sanitized `StateUnavailable`, and undisclosed
page allocations are zeroized. The node cannot erase caller-copied page bytes,
the caller's backing source file, or externally cloned descriptors. A blocking
FUSE, NFS, device, or other hostile filesystem syscall may delay the joined
worker and therefore shutdown or zeroization; no bounded-latency claim is made
for such providers.

This was mechanism and current-code test coverage, not a retained execution
receipt or acceptance amendment. At this amendment freeze, Blob
subscription/status convergence,
route-only custody, TTL/expiry/garbage collection, metadata-independent
whole-byte deduplication, 100+ MiB or RSS/resource thresholds, representative
physical IP/NAT/relay or BTLE operation, mixed-implementation interoperability,
selected-node language bindings, and release authorization remain open.

## Retained live Blob acceptance amendment (2026-08-27)

This amendment supersedes only the preceding statement that the live selected
Blob composition has no retained execution receipt and supersedes the earlier
v1 live-Blob observation. It does not change the application ownership, page
custody, cancellation, shutdown, or zeroization decision above. The canonical
[`selected-live-blob-044d90f.json`](../validation/evidence/selected-live-blob-044d90f.json)
receipt is 10,728 bytes with SHA-256
`4fea2ffbd16608862a67167fb1b8fcb6d5d8b4b82c576aa9a6b7e25ee9c55909`
and binds the bounded execution to good-signature source commit
`044d90ff07c8e754b3d490cb810d42de3c915e3d`.

Three distinct participant identities under one common mission authority
execute seven phases and 11 actor lifetimes with at most two concurrent. The
publisher's live handle publishes one fixed 98,304-byte file while peerless,
proves exact retry and changed-payload conflict behavior, and reads the exact
two-page result. A replica first receives the completed Blob directly over
Iroh. The receiver then retains a non-public 16,384-byte carrier prefix from
the publisher across graceful shutdown and same-process actor/store/provider
reopen. Exactly one contact with the different eligible replica preserves that
prefix, advances it to 32,768 bytes without refetching the source, and remains
non-public. The replica supplies the remaining 65,870 bytes, reconstructing
exactly 98,638 transferred carrier bytes before promotion and authenticated
reads. A final peerless graceful receiver reopen reproduces the same read.

Eleven retained handles fail closed after shutdown, three direct bind addresses
are reacquired, and typed intermediate Store inspection binds prefix
persistence and advancement to the runtime counters. The private mission,
identity, database, depot-marker, and ciphertext contents are inventoried by
metadata only and are not opened, read, or hashed by the projector. The
independent-oracle checker suite passed 45/45.

This is only a three-party, one-host, same-implementation direct-Iroh
observation of graceful interruption/reopen and different-peer continuation.
The source/binary/execution link remains operator-attested, the selected source
list is not a complete reproducible-build closure, and intermediate Store
inspection and transcript timing are producer-attested. It does not establish
process-crash or power-loss recovery, long-offline recovery, arbitrary-peer or
route-only Blob resume, physical-media sanitization, distinct physical hosts,
NAT or Internet operation, controlled/public relay, BTLE, independent
implementation interoperability, scale beyond three participants, resource
thresholds or long-duration soak, Blob subscription/status/TTL/garbage
collection, Event/State/Record live-application acceptance, complete MVP
acceptance, a release artifact, or production authorization.

## Live selected State delivery amendment (2026-08-27)

This amendment supersedes the earlier present-tense statements that selected
State has no live application subscription or durable delivery subscription.
Those statements remain above only as dated boundaries of the stopped and
semantic-v4 network slices. Record's separate delivery and receipt amendment
follows below. Blob delivery has a later current-code amendment, but at this
State-amendment freeze its retained acceptance remained open.

`SelectedStateHandle` now exposes durable `subscribe`, `poll`, `acknowledge`,
and `unsubscribe` operations backed by the actor-owned Store. The queue is
at-least-once and delivers only freshly verified positive Current State
versions. A current authenticated tombstone is a delivered State version, not a
synthetic withdrawal. The API is not a materialized view or transition feed and
emits no Current-to-None event when a key has no Current version.

Application subscriptions and configured network interests are separate
surfaces. Creating or replaying a subscription does not mutate `NodeConfig`,
expand network receive policy, or authorize transfer. Delivery tokens are
opaque, bound to the subscription, State identity, incarnation, tenure, and
attempt, and exact acknowledgement is idempotent; superseded pending versions
are retired rather than delivered as current.

The canonical
[`selected-live-state-subscription-8912fc3.json`](../validation/evidence/selected-live-state-subscription-8912fc3.json)
receipt retains one bounded two-participant, three-process, one-host direct-Iroh
observation. It includes forced receiver-process termination after a flushed
unacknowledged poll, fresh-process attempt-two redelivery and acknowledgement,
selector separation, causal ancestor suppression, an explicit current
tombstone, and final peerless replay. The source/binary/execution link is
operator-attested and the causal schedule is producer-attested. This amendment
does not claim physical/NAT/relay/BTLE operation, mixed implementations, scale,
resource or soak thresholds, indefinite tombstone retention, dynamic network
interest, Blob delivery, selected-node bindings, a release artifact, or
production authorization.

## Live selected Record delivery amendment (2026-08-27)

This amendment supersedes present-tense statements above that selected Record
has no durable application delivery mechanism. The retained receipt below
updates its bounded acceptance status: only `DM-5.1-08` moves.
`DM-7-11`, `DM-7-14`, `DM-7-15`, and `DM-7-18` remain
implemented-uncredited; `DM-7-20` is unchanged.

`SelectedRecordHandle` now exposes durable `subscribe`, `poll`, `acknowledge`,
and `unsubscribe` operations backed by the actor-owned Store. One delivery is a
complete active-head projection for one exact topic, scope, and logical key;
`delivery_limit` counts projections rather than Record versions, so a conflict
cannot be split across pages. Poll freshly verifies the complete bounded
matching candidate snapshot before atomically advancing an at-least-once
attempt. Superseded history is excluded from delivery and remains available by
explicit query.

The projection identity binds the exact key and complete sorted policy-active
causal head set. Visible Current and Concurrent heads are returned together. A
conflict carries the complete sorted sibling IDs, including opaque IDs for
startup-authenticated heads whose same-epoch lineage now withholds plaintext,
but it is deliberately non-authorizing: it contains no resolution guard. Every
delivery carries a verified `RecordProjectionKey`, and an application must
issue a fresh exact query for a current guard before resolution. A late
dominated ancestor therefore cannot change or rearm an acknowledged active-head
delivery merely by changing the query's historical plan.

Application selectors remain separate from configured Record network
interests. Creating or replaying one does not mutate `NodeConfig`, authorize
transfer, or expand route/content authority. Tokens bind subscription
incarnation, projection identity, active-head tenure, and issued attempt;
exact acknowledgement is idempotent and cannot consume later work. A current
tombstone is an explicit head, concurrent edit/tombstone remains a conflict,
and no synthetic withdrawal is emitted when no positive projection exists.

This is a durable active-head projection queue, not a revision stream,
transition log, materialized view, automatic merge engine, or withdrawal feed.

The canonical 10,357-byte
[`selected-live-record-subscription-0c11344.json`](../validation/evidence/selected-live-record-subscription-0c11344.json)
receipt (SHA-256
`ba0e2bf47291f7e87000b85fa280cc957f3710ac800def82a51fb9b4657a1b48`)
binds Good-signed source commit `0c1134411953f4bb52133b50aff9989cd4ce3930`.
On one same-implementation direct-loopback host, two participants run three
processes and seven actor lifetimes. A complete two-head edit/tombstone conflict
remains one delivery at `delivery_limit=1` and `scan_limit=16`; after the
receiver is sent `SIGKILL` following its flushed durable unacknowledged
attempt-one poll, a fresh process receives the same projection at attempt two
with a rotated 89-byte token. A fresh exact query guard resolves both heads, a
new successor projection is delivered, and the two originals remain query-only
superseded history. Network-interested/application-unmatched beta is retained
without delivery; application-matched/network-uninterested gamma is withheld,
and the subscription does not mutate network interest. A final peerless reopen
replays the subscription with an empty acknowledged queue, the resolved current
successor, and two query-only superseded originals. The source-to-binary
execution link is operator-attested, not reproducible proof.

The compiled `live_record_subscription_acceptance` producer is a receipt-making
acceptance harness outside the adopter API. It is not a minimal developer
sample, an integration-usability result, or a release gate. The receipt adds no
finite Record TTL/GC, physical/NAT/relay/BTLE operation, mixed implementations,
scale/resource/soak evidence, selected-node bindings, automatic registered-policy
merge, reproducible source-to-binary proof, release credit, or production
authorization. At that receipt freeze, Blob delivery/status also remained open.

## Live selected Blob delivery mechanism amendment (2026-08-27)

This amendment supersedes present-tense statements above that selected Blob has
no application subscription or delivery surface. It does not amend the frozen
live-Blob receipt: that retained run predates this queue and provides no Blob
delivery evidence.

`SelectedBlobHandle` and the exclusive stopped `SelectedBlobNode` now expose
durable `subscribe`, `poll`, `acknowledge`, `unsubscribe`, and
`delivery_status` operations. A selector covers one topic and exact scope or its
descendants. It is local application intent only and cannot add or mutate the
semantic-v5 configured network interests, route/content authority, carrier
eligibility, or depot capabilities.

One delivery identifies one exact source-authenticated immutable publication.
Its `BlobPublicationId` is the semantic source-publication identity, not
`BlobId`: distinct publishers, counters, or priorities can sign separate
publications of the same immutable content identity, and acknowledgement of one
cannot consume another. The notification returns only authenticated identity
metadata, total length, local acceptance marker, attempt, and opaque token. It
contains no plaintext, source envelope, manifest, sealed bytes, content key,
nonce, chunk, carrier progress, provider state, or depot path. Applications use
the existing `BlobReadRequest` separately when they need bytes.

Poll snapshots the complete bounded matching publication set, rebinds every
candidate to its startup-authenticated projection and current policy, then
exact-loads and rechecks each still-deliverable source envelope and completed
depot before atomically committing attempts. It fails closed when the caller's
scan bound cannot cover the matching set. The Store durably retains selector
incarnation, pending attempt,
acknowledgement receipt, and monotonic per-publication cursor. Tokens bind the
subscription, incarnation, publication, tenure, and issued attempt. Exact ack
and re-ack are idempotent. An earlier nonzero issued attempt remains valid at or
below the durable high-water while the same publication tenure is pending;
wrong-tenure, wrong-incarnation, malformed, cross-subscription, cross-
publication, future/unissued, removed, and recreated-selector tokens fail
closed.

`delivery_status` reports only structurally audited local selector/pending/ack/
cursor counts. It is not peer, contact, transfer-progress, synchronization, or
convergence status. This amendment has focused mechanism and migration tests,
not a retained Linux delivery receipt. It changes no atomic requirement status
by itself and makes no finite Blob TTL/expiry/GC, route-only custody,
crash/power-loss, physical/NAT/relay/BTLE, mixed-implementation, large/RSS,
binding, reproducible-build, release, or production-authority claim.

## Retained selected Blob delivery amendment (2026-08-27)

This amendment supersedes only the preceding present-tense statement that the
metadata-only queue has no retained delivery receipt. It does not amend the
older direct-transfer receipt, the application ownership decision, or the
separation between application selectors and configured network interests. The
canonical
[`selected-live-blob-subscription-26e0a09.json`](../validation/evidence/selected-live-blob-subscription-26e0a09.json)
receipt is 10,269 bytes with SHA-256
`3d0c0b2da629282c56de5ae9dacc8920c9960defba083c6bff856e2c0612a675`
and binds Good-signed source commit
`26e0a090b9a6f644d96b38cfaa23f4e2139ad8b1`.

One participant executes three processes and four actor lifetimes on one
peerless host. Two exact source publications share one `BlobId`. The
attempt-one child durably flushes its unacknowledged token and is sent
`SIGKILL` without a `STOP`; a fresh process receives the same publication as
attempt 2 and acknowledges it with the persisted attempt-one token. Malformed
and cross-publication tokens fail closed, both publications are acknowledged
and idempotently re-acknowledged, and a final parent reopen replays one
subscription with zero pending, two acknowledged, two cursors, and an empty
poll. Final Store inspection binds two publications/operations to one finalized
variant, one chunk, and 207 committed ciphertext bytes.

This is one-host, same-implementation, peerless local-ledger evidence. The
source/binary/execution link remains operator-attested and not reproducible.
The receipt claims no network contact, transfer, synchronization,
peer/convergence status, selector withholding or network-interest separation,
plaintext delivery or exact-publication read, policy/rekey/revocation behavior,
power-loss/filesystem-crash recovery, long retention, TTL/expiry/GC, physical
or mixed implementations, resource thresholds/soak, selected-node language
bindings, release artifact, or production authorization.
