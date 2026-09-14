# Decision 0010: Source-bound encrypted Blob carriers

- Status: accepted for reference; stopped/local, semantic-v5 direct-content, and bounded live-application selected subsets implemented
- Date: 2026-08-18

## Decision

Blob manifests remain ordinary source-encrypted and hybrid-signed items. Their
canonical protected header additionally commits to the BlobID, nonzero chunk
count, and a Merkle root over the ordered encrypted-chunk records. The header is
part of both ItemID semantics and the source-signature message.

Each network chunk is a bounded `ASTRBT01` carrier identified by a full 256-bit
typed ObjectID. It binds the source EnvelopeID, BlobID, index, ciphertext
SHA-256, ciphertext length, and canonical Merkle proof, followed by the
ciphertext. It intentionally omits plaintext digests. A route-authorized relay
can validate and retain the carrier without a content key. A content-authorized
consumer additionally requires the exact authenticated manifest record before
installing a reader-visible chunk.

Transfer staging records the complete 33-byte typed ObjectID and exact byte
ranges in the durable store. A completed staging object is retired only after
authenticated commit; accepted semantic and event replay ledgers remain
separate. Partial ranges are peer-neutral, so a new runtime and a different
authenticated peer can request only their complement.

## Consequences

- Source envelopes are the authorization root for advertising, serving, or
  accepting every Blob carrier; Blob DATA never carries a peer forwarding
  wrapper.
- Route-only relays cannot open the manifest or payload and content consumers
  reject a route-valid carrier that differs from the manifest's exact record.
- Merkle levels are built once and persisted under a bounded cache; carrier
  scans retain one bounded object at a time.
- Unauthenticated transfer staging is isolated from committed-record eviction:
  it receives at most one quarter of the total byte quota (capped at 64 MiB),
  4 MiB per typed object, 10,000 objects, 4,095 extents per object, and 65,536
  extents globally. Exhaustion rejects the new extent without evicting either
  staged or committed data.
- A terminal full-object identity, route, or source-authentication failure
  transactionally deletes only that typed staging object and resets the reducer
  to an unknown-length request. Transient storage, I/O, and missing-chunk
  failures retain progress for another contact.
- The current profile rejects zero-chunk Blobs, caps the manifest near 1 MiB
  (about 14,543 chunks), and caps a composite contact inventory at 100,000
  source-prioritized identifiers.
- Content-capable nodes retain both the forwarding carrier and canonical
  encrypted chunk, charged to quota; this favors store-and-forward availability
  over minimum disk amplification.

The design uses SHA-256, AES-GCM chunk records, and ordinary authenticated
source envelopes already admitted by Decisions 0001–0006. The local depot
owner token uses the workspace's existing pinned `getrandom` package through a
new direct store dependency; it adds no new third-party package/version or
external implementation input.

## Selected local implementation boundary

The selected stopped `SelectedBlobNode` implements the source-authenticated
manifest and encrypted-at-rest chunk boundary without yet implementing the
network carriers described above. Its profile fixes nonempty objects to 64-KiB
chunks and gives `BlobId` its exact meaning: the ID commits plaintext bytes,
canonical chunk profile, and media/schema identity metadata. It is not a
metadata-independent pure byte-content ID.

Signed publication bytes and operation authority live in the mission-bound
redb store. Ciphertext files live in a private sibling depot, partitioned by
Blob ID, content group, and epoch. A file becomes authoritative only after
write/sync/rename/directory-sync and an exact redb committed marker. The source
publication commits only after a private completion proof checks every
authenticated expected and committed manifest record plus the final manifest
digest. A marked missing or corrupt file fails closed; only unmarked remnants
may be reclaimed.

From its first successful Store open, redb persists a domain-separated binding
over a random owner token, canonical database path, and, on Unix, backing
device/inode. The fixed sibling depot’s private marker must carry that exact
binding before any chunk/variant scan or reclaim. The first database to
initialize a parent’s depot wins; a second cannot adopt it. Moving/copying even
an empty bound database to another path fails on reopen. On Unix, a new inode
also fails, moving the depot with the database does not preserve the binding,
and a same-path replacement cannot adopt an existing depot. This slice
deliberately has no supported rebind or backup-restore migration. Non-Unix
keeps the token/path binding but cannot distinguish a copied database restored
over the same path, so equivalent inode/rollback resistance is not claimed.
Legacy owner-token or binding migration is permitted only when the fields are
wholly absent, every Blob row/counter is canonical empty, and the fixed depot
root is absent; partial fields, any logical Blob state, or any fixed depot root
fail closed without repair.

The facade performs synchronous borrowed streaming, so no provider reader or
copied content key can outlive the exclusive stopped handle. Its redb read plan
is structural: every retained publication is freshly source/content verified,
the active deterministic source publication is recomputed, the exact plan is
rechecked, and only then is the selected depot completion verified and read.

Dedicated limits reserve canonical ciphertext-file bytes for every durable
expected chunk record and count durable chunk-metadata rows and import variants.
Retained unpublished imports, whether expected-only or already finalized, count
against byte/row/variant admission until an explicit-GC policy is implemented.
These limits do not claim complete filesystem allocation accounting or physical sanitization. The
selected slice has no Blob frame, remote chunk request, any-peer resume, live
handle, subscription, carrier-neutral partial staging, or acceptance result;
the network portion of this decision remains a migration target.

## Selected semantic-v5 direct-content amendment (2026-08-25)

This amendment supersedes only the final stopped/local network-boundary
paragraph above. It does not relabel the broader route-only reference design as
selected behavior.

The selected handshake now offers semantic versions `[5, 4, 3, 2, 1]`.
Semantic v5 inherits Event v1-v4 and State/Record v4 behavior and allocates the
direct Blob source/carrier mechanics. Semantic v1-v4 contacts emit and accept
zero Blob frames. Stable wire/ABI version 1, handshake framing, source-envelope
formats, `ASTRBT01` bytes, Blob manifests, typed ObjectIDs, and the suite remain
unchanged.

The selected lane is direct between current content-capable peers. An exact
topic/scope/epoch interest includes a 32-byte provider-minted peer proof bound
to mission authority, authenticated NodeID, and the current content grant. The
sender requires that proof, the peer's current route grant, and durable
nonrevocation at source inventory, source send, and every range send. Route-only
authority is insufficient, so selected route-only Blob relay/custody remains
open.

The complete authenticated source and manifest plan is installed before any
carrier work. Carrier ranges extend one durable contiguous prefix by at most 16
KiB. The prefix is keyed by exact source and kind-2 carrier ID rather than peer
or session, so a later eligible content peer can continue the exact complement.
Per-peer cursor state provides bounded scheduling fairness only. The requester's
carrier Finish remaining count is echoed for sequencing; exact per-range
Result/Ack binds accepted prefix progress and the responder does not independently
attest the requester's disk truth.

Network admission caps plaintext at 64 MiB and 1,024 chunks. Pending source,
manifest-record, and prefix state is capped at 10,000 rows and 64 MiB; each
requested extension is at most 16 KiB. Pending state is not a Blob publication.
Ordinary visibility is installed atomically only after every canonical carrier,
the depot completion marker, a freshly streamed provider content-completion
proof, and a fresh current route/physical-lineage proof all agree with the exact
plan. Before that transaction, query, inventory, read, and carrier serving do
not expose the pending Blob.

Every redb open path cross-audits that pending plan against its manifest route,
carrier set, depot expected plan, and completed namespace; a changed/missing
plan or pending/completed collision fails without repair. Writable migration
adds the four v5 network tables to the predecessor nine-table Blob group only
when the group is wholly absent and the owner-token/binding rules pass.
Read-only and partial-group opens never migrate or repair it.

Same-epoch replacement is deliberately conservative. Replacing the content key
invalidates peer proofs and current-lineage checks and withholds old rows. Redb
also rejects a new physical lineage for the same `(BlobID, content group,
numeric epoch)` with `PhysicalLineageConflict`; republishing or resuming that
Blob requires advancing the numeric epoch.

Terminal and stale cleanup preserve that decision after the pending source is
gone. Pending source and prefix visibility are retired, but the exact depot
import, any expected/committed chunk rows and files, finalized digest, and
reserved/committed accounting remain as bounded non-public, owner/backing-bound
staging under the existing byte, chunk, and variant caps. Exact-lineage retry
may resume it; a different same-epoch lineage still conflicts, and a missing
lineage fails audit. This adds no table, schema, quota, or visibility surface;
an explicit future GC protocol is required to reclaim the abandoned staging.

The node serializes every durable Blob-source transition with its authenticated
cache transition under one local lifecycle lock. Abort reconciliation removes
the old claim, rereads the durable projection, and freshly authenticates any
concurrent exact restage before reinsertion. Terminal scheduling for a
multi-carrier source advances to its lexicographically greatest canonical
carrier ID rather than assuming manifest-last is greatest.

Normal and AtLeast run selected Blob work because AtLeast filters Event only.
ReceiveOnly emits, requests, stages, promotes, and counts zero Blob work. The
application Blob facade remains stopped; this amendment adds no live handle or
subscription, TTL/expiry/custody/garbage collection, pure whole-byte identity
or metadata-independent deduplication, selected route-only relay, large-file or
resource acceptance, physical carrier, mixed-implementation, or release
acceptance claim.

## Selected live-application amendment (2026-08-27)

This amendment supersedes only the preceding present-tense statement that the
selected application facade remains stopped. `RunningNode::selected_blobs()`
now returns a cloneable actor-owned handle for durable publication of a bounded
regular file and authenticated reads of one zeroize-on-drop plaintext page at a
time. The exclusive stopped streaming facade and the semantic-v5 network
boundary above remain unchanged.

The live mechanism composes peerless publication with later direct transfer and
restart. A later current-code amendment adds local metadata-only
exact-publication delivery, but at that amendment freeze adds no Blob
peer/convergence status, route-only custody, TTL/GC, retained delivery evidence,
physical/resource acceptance,
mixed-implementation evidence, or release authorization. The authoritative
application ownership, cancellation, shutdown, and zeroization boundaries are
recorded in [ADR 0009](0009-public-api-boundary.md#live-selected-blob-application-amendment-2026-08-27).

## Retained live direct-transfer amendment (2026-08-27)

This amendment supersedes only the preceding statement that the bounded live
composition has no retained execution receipt and supersedes the earlier v1
live-transfer observation. The canonical
[`selected-live-blob-044d90f.json`](../validation/evidence/selected-live-blob-044d90f.json)
receipt is 10,728 bytes with SHA-256
`4fea2ffbd16608862a67167fb1b8fcb6d5d8b4b82c576aa9a6b7e25ee9c55909`
and binds good-signature source commit
`044d90ff07c8e754b3d490cb810d42de3c915e3d` to seven exact phases across three
participants. After peerless live publication and a direct-Iroh seed, the
receiver takes one publisher contact and retains a non-public 16,384-byte
carrier prefix across graceful shutdown and same-process actor/store/provider
reopen. One contact from the different eligible replica preserves the prefix,
advances it to 32,768 bytes without refetching the source, and remains
non-public. The replica then supplies the remaining 65,870 bytes. The partial,
resume, and finish phases reconstruct exactly 98,638 transferred carrier bytes,
equal to the seed, before whole-Blob visibility, authenticated bounded reads,
and a final peerless graceful reopen.

Typed intermediate Store inspection, exact per-contact and shutdown
aggregation, durable rows, two committed chunks, freshly authenticated reads,
and depot completion—not `blob_remaining` alone—establish the bounded receiver
result. The independent-oracle checker suite passed 45/45, and the private
mission, identity, database, depot-marker, and ciphertext contents remain
metadata-only to the projector.

This receipt does not broaden the semantic-v5 carrier decision to arbitrary-
peer or route-only Blob resume. It is only a three-party, one-host,
same-implementation direct-Iroh observation of graceful interruption/reopen and
different-peer continuation. It does not prove process-crash or power-loss
recovery, long-offline recovery, physical-media sanitization, distinct physical
hosts, NAT or Internet paths, controlled/public relay, BTLE, independent
implementation interoperability, scale beyond three participants, resource
thresholds or long-duration soak, Blob subscription/status/TTL/garbage
collection, Event/State/Record live-application acceptance, complete MVP
acceptance, a release artifact, or production authorization. The
source/binary/execution link and intermediate Store timing remain
operator/producer-attested rather than cryptographically proven.

## Retained peerless delivery amendment (2026-08-27)

Blob application delivery remains separate from the direct source/carrier
protocol decided here. Its canonical
[`selected-live-blob-subscription-26e0a09.json`](../validation/evidence/selected-live-blob-subscription-26e0a09.json)
receipt is 10,269 bytes with SHA-256
`3d0c0b2da629282c56de5ae9dacc8920c9960defba083c6bff856e2c0612a675`
and binds Good-signed source `26e0a09`. On one peerless host, one participant
runs three processes/four actor lifetimes. An attempt-one child is sent
`SIGKILL` after flushing an unacknowledged token; a fresh process receives
attempt 2 and acknowledges it with the persisted older token, settles a second
exact publication sharing the same `BlobId`, and leaves the final reopened
ledger empty.

This amendment adds no carrier or transport result to this decision. It claims
no network contact, source/range transfer, peer/convergence status,
selector/network-interest separation, arbitrary-peer or route-only resume,
power-loss/filesystem-crash or long-offline recovery, TTL/GC, physical or mixed
implementation, resource/soak, reproducible build, release artifact, or
production authorization.
