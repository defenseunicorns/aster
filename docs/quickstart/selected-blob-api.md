# Selected Blob API quickstart

This is the shortest path to Aster's **selected live Blob application surface**,
its durable metadata-delivery queue, its exclusive stopped streaming facade,
and the semantic-v5 direct transfer boundary for already-durable Blobs.
`RunningNode::selected_blobs()` returns a cloneable `SelectedBlobHandle`: an
application may durably publish an owned regular file while the node has no
peers, read one freshly authenticated plaintext page at a time, and consume
at-least-once notifications for exact source-authenticated Blob publications.
Each live page is at most 64 KiB and zeroizes its owned plaintext allocation on
drop; each delivery is metadata only and carries no Blob plaintext.

The live surface deliberately keeps application delivery separate from network
replication. A Blob subscription is durable local intent, not a route/content
grant or a dynamic network interest. The surface has no Blob peer or convergence
status; `delivery_status` reports only local selector and delivery-ledger counts.
The exclusive `SelectedBlobNode` remains available when no runtime owns the same
store and provides the same delivery lifecycle plus synchronous seekable-source
publication and streaming `read_into`. Separately, semantic v5 reconciles
already-durable Blob sources and direct carrier ranges between current
content-capable peers, and semantic v6 inherits that Blob lane unchanged. The
default offer is `[6, 5, 4, 3, 2, 1]`; v1-v4 emit zero Blob frames, and stable
wire/ABI, source, manifest, and `ASTRBT01` formats remain version 1.

A [retained 10,728-byte live-Blob receipt](../validation/evidence/selected-live-blob-044d90f.json)
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
authorization. That frozen receipt predates the delivery queue and gives it no
retained execution credit; the queue currently has focused mechanism tests only.

A separate
[retained 10,269-byte v1 Blob-delivery receipt](../validation/evidence/selected-live-blob-subscription-26e0a09.json)
(SHA-256
`3d0c0b2da629282c56de5ae9dacc8920c9960defba083c6bff856e2c0612a675`)
binds Good-signed source `26e0a09`. It is a peerless one-host,
one-participant run with three processes and four actor lifetimes. Two exact
publications share one `BlobId`. The attempt-one child flushes a durable
unacknowledged token and is sent `SIGKILL`; a fresh process receives the same
publication as attempt 2 and acknowledges it using the persisted attempt-one
token, rejects that publication's token against the second publication, then
settles both exact publications. A final parent reopen replays one subscription
and polls an empty ledger with zero pending and two acknowledged publications.
This receipt observes no contacts or network Blob activity and does not claim
peer/convergence status, selector withholding or network-interest separation,
plaintext delivery or exact-publication reads, power-loss/filesystem-crash
recovery, physical or mixed systems, TTL/GC, resource/soak, reproducible build,
or release authorization.

## Use the live actor API

Start the node as described in the [selected Event quickstart](selected-event-api.md),
then retain a clone of the Blob handle. The configured peer list may be empty;
publication success means the signed publication and encrypted depot content
are durable locally, not that any peer received them.

```rust
use aster_mesh::Priority;
use aster_node::application::{
    BlobPublishRequest, BlobReadPageRequest, BlobReadRequest,
    MAX_SELECTED_BLOB_PAGE_BYTES,
};
use std::{fs::File, io::Write};

let blobs = running.selected_blobs();
let published = blobs
    .publish(
        BlobPublishRequest {
            operation_key: b"my-app/blob/input-v1".to_vec(),
            topic: topic.clone(),
            scope: scope.clone(),
            priority: Priority::Priority,
            media_type: Some("application/octet-stream".into()),
            schema_id: Vec::new(),
        },
        File::open(input_path)?,
    )
    .await?;

let read = BlobReadRequest {
    id: published.id,
    topic,
    scope,
};
let mut output = File::create(output_path)?;
let mut offset = 0;
loop {
    let page = blobs
        .read_page(BlobReadPageRequest {
            blob: read.clone(),
            offset,
            max_bytes: MAX_SELECTED_BLOB_PAGE_BYTES,
        })
        .await?;
    output.write_all(page.as_bytes())?;
    if page.complete {
        break;
    }
    offset = page.next_offset();
}
```

The live publisher accepts a nonempty regular file of at most 64 MiB, with its
cursor at exactly zero, and fixes the selected chunk size at 64 KiB. The file is
moved into a bounded, joined worker rather than cloned into the actor command.
The returned result is durable and operation-key idempotent. Retrying the exact
operation with the same source and identity metadata recovers the original
publisher counter and acceptance marker; reusing that operation key for
different content or metadata fails closed as a conflict.

Cancellation before enqueue cannot publish. Cancellation after enqueue has an
indeterminate result because the worker may have committed; retry the exact
operation key to recover the authoritative outcome. Graceful shutdown and live
zeroization close application admission, reject queued commands, and join the
Blob worker before releasing the store authority. Retained handles then return
sanitized `StateUnavailable`. A `BlobReadPage` zeroizes its private plaintext
buffer on drop, but bytes copied by the application, the caller's source file,
and externally cloned file descriptors remain caller custody. A blocking or
hostile filesystem syscall can delay the joined worker and therefore delay
shutdown or zeroization; no bounded shutdown-latency claim is made for such a
file provider.

## Subscribe to immutable publication metadata

A Blob subscription selects one topic and scope, optionally including
descendant scopes. Each delivery identifies one exact signed publication with
`BlobPublicationId`, which differs from `BlobId`: several publishers, counters,
or priorities can sign distinct publications of the same immutable content.
Acknowledgement and deduplication therefore use the publication identity, while
the existing read API continues to use the content-and-metadata `BlobId` plus
the delivered topic and scope.

```rust
use aster_node::application::{
    BlobPollRequest, BlobReadRequest, BlobSubscriptionRequest,
    MAX_SELECTED_BLOB_DELIVERIES, MAX_SELECTED_BLOB_SUBSCRIPTION_SCAN,
};

let subscription = blobs
    .subscribe(BlobSubscriptionRequest {
        operation_key: b"my-app/blob-subscription/imagery".to_vec(),
        topic: topic.clone(),
        scope: scope.clone(),
        include_descendant_scopes: false,
    })
    .await?;

let page = blobs
    .poll(BlobPollRequest {
        subscription: subscription.id,
        delivery_limit: MAX_SELECTED_BLOB_DELIVERIES,
        scan_limit: MAX_SELECTED_BLOB_SUBSCRIPTION_SCAN,
    })
    .await?;

for delivery in page.deliveries {
    let read = BlobReadRequest {
        id: delivery.id,
        topic: delivery.topic.clone(),
        scope: delivery.scope.clone(),
    };
    // Read `read` with `read_page` when the application needs plaintext.
    blobs
        .acknowledge(subscription.id, delivery.publication, delivery.token)
        .await?;
}

let local = blobs.delivery_status().await?;
assert_eq!(local.subscriptions, 1);
blobs.unsubscribe(subscription.id).await?;
```

Subscription creation is operation-key idempotent. A matching retry returns the
same durable identifier, while changing the selector under that key fails
closed. `scan_limit` bounds the complete matching retained publication set that
one poll freshly authenticates; poll fails closed rather than silently advancing
through a partial snapshot. `delivery_limit` bounds the committed attempts
returned from that verified set.

Before returning a delivery, the node rechecks current mission policy, exact
source envelope and identity metadata, route/content authority, revocation and
epoch, and the completed encrypted-depot content. The notification exposes only
the publication ID, Blob ID, publisher/counter, topic/scope, priority, byte
length, media/schema identity metadata, acceptance marker, attempt, and opaque
acknowledgement token. It never returns a manifest, source envelope, sealed
bytes, key, nonce, chunk, carrier state, or depot path.

Unacknowledged work is retried with a higher nonzero attempt and a new opaque
token. Tokens bind the mission-local subscription incarnation, exact publication
identity, delivery tenure, and issued attempt. Any earlier nonzero token at or
below the durable attempt high-water remains valid while that exact publication
tenure remains active, so a response lost to process termination can still be
acknowledged after a later retry. Exact acknowledgement and reacknowledgement
are idempotent; tokens above the issued high-water, cross-subscription or
cross-publication tokens, prior-tenure tokens, stale incarnations, malformed
tokens, and removed/recreated selectors fail closed.
`unsubscribe` removes the selector and its delivery ledger without changing
configured semantic-v5 Blob interests.

Cancellation before enqueue cannot mutate the ledger. After enqueue, the
worker may have committed: retry `subscribe` with the exact operation key to
recover its durable selector; a later `poll` safely issues another attempt if
the prior page was lost; retry `acknowledge` with the exact token to observe its
idempotent outcome; and retry `unsubscribe` to observe `AlreadyAbsent` after a
completed removal. `delivery_status` is read-only. These recovery rules do not
make application side effects transactional with acknowledgement.

`delivery_status` is a structurally audited local ledger snapshot, not sync,
contact, peer, transfer-progress, or convergence status. The focused mechanism
tests cover retry, re-acknowledgement, selector replacement/removal, durable
reopen, policy withholding, bounded scans, and distinct publications sharing
one Blob ID. The retained receipt above covers only its narrower peerless
forced-process retry and final empty ledger.

## Run the example

Install the pinned toolchain, create a disposable two-node fixture, and provide
one nonempty input file. The demo provisions a mission bundle and releases its
stores before the Blob example opens node 0 exclusively.

```sh
mise install
ASTER_BLOB_ROOT="$(mktemp -d)"
printf 'selected Blob streaming example\n' > "$ASTER_BLOB_ROOT/input.bin"
cargo run --locked -p aster-node --bin aster -- \
  demo --nodes 2 --root "$ASTER_BLOB_ROOT/mesh"

cargo run --locked -p aster-node --example blob_application -- \
  "$ASTER_BLOB_ROOT/mesh/node-0" \
  "$ASTER_BLOB_ROOT/mesh/node-0/mission.unprotected-reference.bundle" \
  "$ASTER_BLOB_ROOT/input.bin" \
  "$ASTER_BLOB_ROOT/output.bin"
cmp "$ASTER_BLOB_ROOT/input.bin" "$ASTER_BLOB_ROOT/output.bin"
```

Expect one line shaped like:

```text
BLOB id=<64 hex characters> bytes=<n> chunks=<n> inserted=true media_type=application/octet-stream
```

Run the `cargo run ... --example blob_application` command again against the
same paths. The fixed operation key and unchanged source resolve the original
durable publication, so `inserted=false`; the Blob ID remains identical and
`cmp` still succeeds. Changing the input or identity metadata under that same
operation key fails closed rather than silently rebinding the operation.

The fixture persists explicitly unprotected reference mission material. It is
appropriate for this disposable demonstration, not operational provisioning.
Remove the temporary directory when you no longer need it.

## Use the stopped streaming API

The complete runnable source is
[`crates/aster-node/examples/blob_application.rs`](../../crates/aster-node/examples/blob_application.rs).
Its central shape is:

```rust
let mut blobs = SelectedBlobNode::open_unprotected_reference(
    state_directory,
    mission_bundle,
)?;

let mut input = std::fs::File::open(input_path)?;
let published = blobs.publish(
    BlobPublishRequest {
        operation_key: b"my-app/blob/input-v1".to_vec(),
        topic: topic.clone(),
        scope: scope.clone(),
        priority: Priority::Priority,
        media_type: Some("application/octet-stream".into()),
        schema_id: Vec::new(),
    },
    &mut input,
)?;

let mut output = std::fs::File::create(output_path)?;
let read = blobs.read_into(
    BlobReadRequest {
        id: published.id,
        topic,
        scope,
    },
    &mut output,
)?;
assert_eq!(read.id, published.id);
```

## Opt in to semantic-v5 transfer

The runtime does not infer Blob receive intent from State/Record interests. Add
an exact Blob selector to `NodeConfig::mutable_interests`; descendant scope is
rejected for Blob because one selector must bind one current content epoch:

```rust
let mutable_interests = MutableSourceInterests::new(state, record).with_blob(vec![
    SourceInterestSelector::new(blob_topic, blob_scope, false),
]);
```

This composes with peerless live publication rather than changing its success
condition. A source may publish through `selected_blobs()` with no peers, shut
down, and later restart with an exact configured peer. On a v5 or v6 contact, a
content-capable interested receiver can durably stage the source and missing
carrier ranges, promote only after whole-Blob verification, and read the Blob
through its own live handle. The receiver's completed publication and page
reads survive another peerless restart. Current same-implementation loopback
tests exercise that sequence, and the retained receipt above now observes it
alongside the bounded interrupted partial/different-eligible-peer continuation.
That receipt is still one-host direct loopback with graceful same-process
reopens, not a physical-carrier, crash-recovery, arbitrary-peer,
mixed-implementation, scale, or resource acceptance artifact.

The provider turns that exact topic/scope and the current epoch into an opaque
32-byte peer proof inside the protected v5-or-v6 contact. Every Blob inventory,
source, and range send requires the authenticated peer to have both the current
content proof and current route authorization and to remain nonrevoked.
Route-only peers cannot use the selected Blob lane. The source-envelope and
complete manifest plan reconcile first; carrier requests begin only after that
pending source is durably staged.

Each carrier request extends one exact contiguous prefix by at most 16 KiB. The
prefix is peer-neutral: its durable key is the source transfer ID plus strict
kind-2 carrier ID, not the peer or session, so after runtime/store/provider-cache
teardown and reopen any other eligible content peer can continue at the first
missing byte. The requester's
Finish remaining count is echoed for sequencing only; each exact Result/Ack
tuple binds the accepted prefix.

Network admission is bounded to 64 MiB of plaintext and 1,024 chunks. Pending
source/manifest/prefix state is bounded to 10,000 rows and 64 MiB. A pending
source, partial prefix, and even carrier-complete depot are not an ordinary Blob
publication. Visibility appears only after the exact depot completion, a fresh
provider pass that decrypts/authenticates every chunk and whole Blob, and a
fresh current route/physical-lineage proof agree in one redb promotion
transaction.

Same-epoch key replacement invalidates old peer proofs and withholds old rows,
but it is not a transparent physical replacement. Redb rejects another physical
lineage for the same `(BlobID, content group, numeric epoch)` with
`PhysicalLineageConflict`; republishing or resuming that Blob requires advancing
the numeric epoch.

Terminal or stale cleanup therefore does not erase the last physical-lineage
witness. It removes pending source, prefix, and authenticated-cache visibility,
but deliberately retains the exact depot import, its expected or committed
chunk rows, any chunk files and finalized digest already present, and their
reserved/committed accounting. That bounded staging is not a publication and
cannot be read or served; it remains charged to the configured depot byte,
chunk, and variant quotas until a future explicit GC protocol. An exact-lineage
retry can resume it, while a different lineage at the same numeric epoch still
fails and must advance the epoch.

Source/store/cache transitions are locally serialized. A successful abort
removes the old authenticated claim, rereads durable source state, and freshly
authenticates any exact concurrent restage before restoring its claim. Terminal
multi-carrier scheduling advances past the lexicographically greatest carrier
ID, not the last manifest record.

Normal and `AtLeast` run the v5 lane because `AtLeast` filters Event only.
`ReceiveOnly` advertises, requests, stages, promotes, and counts zero Blob work.
The live handle does not change those contact rules and reports no Blob peer or
convergence status. The retained direct-transfer receipt above is only the bounded
three-participant, one-host, graceful-reopen observation described there. The
selected slice still has no route-only Blob relay/custody, arbitrary-peer
resume evidence, network/application selector-separation acceptance, Blob
TTL/expiry/GC,
metadata-independent
whole-byte identity or deduplication, 100+ MiB/RSS or resource/soak acceptance,
representative physical carrier, NAT/Internet, relay, BTLE,
mixed-implementation, crash/power-loss, or long-offline acceptance, or release
authorization.

`publish` requires a seekable source because it makes two bounded passes. The
first computes the whole-content and per-chunk digests with one bounded,
zeroizing plaintext chunk buffer; after that pass it retains only the
manifest-bounded digest vector and no plaintext. The second encrypts and
durably commits independently authenticated chunks. The selected profile fixes
chunking at 64 KiB and rejects empty input. The canonical manifest is capped at
one MiB.

Choose an operation key for the application effect, not an individual attempt.
The key is bounded to 1–256 bytes. Exact retry rehashes the caller's source,
passes current policy and revocation checks, freshly verifies the original
publication and completed depot variant, and returns its original publisher
counter and acceptance marker. A different operation over the same Blob may
commit a distinct signed publication while reusing the completed encrypted
variant in the same content group and epoch.

## Keep identity claims exact

`BlobId` is immutable object identity for:

- the exact plaintext bytes;
- the selected canonical chunk profile; and
- the media-type and schema identity metadata.

Changing any of those inputs produces another ID. This is not a separate pure
whole-byte `BlobContentId`, and this slice does not claim metadata-independent
physical deduplication. A scope rekey also creates a distinct encrypted depot
variant even when the `BlobId` stays the same. Exact retry of an authorized old
operation returns its historical publication without allocating a new variant;
a new operation at the active epoch installs or reuses that epoch's variant.

## Follow the durable verification boundary

Signed publication metadata and exact source-envelope bytes live in redb.
Potentially large ciphertext chunks live in the private sibling
`blob-depot-v1` directory. A chunk becomes durable in this order:

1. write and synchronize a private temporary file;
2. rename it to its canonical final name;
3. synchronize the containing directory; and
4. atomically record the matching committed-chunk marker in redb.

An unmarked temporary or final file is not authority and is reclaimed on a
mission-bound writable reopen. A marked missing, truncated, or mismatched file
is an integrity failure and is never silently repaired. A signed Blob
publication commits only after every authenticated manifest record equals both
the expected and committed durable record and the finalized manifest digest is
exact.

The database is pinned to one physical depot owner from its first successful
Store open, before the depot exists. Redb persists a domain-separated
commitment over a random owner token, the canonical database path, and, on
Unix, the exact device/inode backing identity; the sibling depot’s private
marker must carry the same binding before any chunk/variant scan or reclaim.
The first database to initialize that parent’s fixed depot wins; another
database is rejected without adopting or cleaning it. Moving/copying even an
empty bound database to another path fails on reopen. On Unix, a new inode also
fails, moving the depot with the database does not preserve the binding, and a
same-path replacement cannot adopt an existing depot. This slice has no
supported depot-rebind or backup-restore migration. Non-Unix retains the
database-token and canonical-path binding, but a copied database restored over
that same path is not distinguishable; equivalent inode/rollback resistance is
not claimed.
Legacy owner-token or owner-binding migration is all-or-none: only canonical
empty Blob rows/counters with no fixed depot root may acquire the missing
fields. Partial fields, any logical Blob state, or any fixed depot root fail
without repair.

```mermaid
sequenceDiagram
    participant A as Application
    participant N as SelectedBlobNode
    participant C as Source-envelope and Blob provider
    participant S as Mission-bound redb
    participant D as Encrypted Blob depot

    A->>N: publish(operation key, metadata, seekable source)
    N->>S: current policy + operation preflight
    N->>C: bounded preparation pass
    N->>D: encrypt, sync, rename, mark chunks
    N->>C: source-seal + fresh route/content verification
    N->>D: prove exact authenticated completion
    N->>S: atomic policy-bound publication + operation commit
    N->>C: fresh durable-result verification
    N-->>A: BlobPublishResult

    A->>N: read_into(topic, scope, BlobId, output)
    N->>S: bounded structural publication plan
    S-->>N: all retained source publications
    N->>C: fresh source/content verification for every candidate
    N->>N: select greatest active semantic publication ID
    N->>S: recheck exact policy-bound plan
    N->>D: prove selected completion once, then stream verified chunks
    N-->>A: BlobReadResult
```

The redb read plan is structural, not authorization. The facade freshly
authenticates every retained publication, checks exact topic, scope, Blob ID,
variant, source identity, and active epoch, excludes revoked or inactive
publications, independently recomputes the deterministic active selection, and
rechecks the complete plan before opening the selected depot variant.

`read_into` never returns a provider reader or copied epoch key. It borrows the
node and caller output synchronously, verifies each chunk's stored record,
ciphertext digest, AEAD tag, plaintext digest, and final whole-content digest,
and reports the core streaming engine's peak chunk-buffer capacity. Store
adapters may concurrently use additional independently chunk-bounded buffers;
the field is not a whole-operation memory measurement. If a later chunk or the
final digest fails, the caller-owned output may already contain an
independently verified prefix; write to a temporary destination if all-or-none
application output is required.

## Understand the current limits

`StoreLimits` account for signed Blob publications and durable operation rows
alongside Event, State, Record, control, and route-cache rows. Separate
`BlobDepotLimits` bound ciphertext-file bytes reserved by every durable expected
chunk record, durable per-chunk metadata rows, and epoch-specific import
variants. Those bounds include both committed content and unfinished resumable
imports, so abandoned but structurally valid staging retained after terminal or
stale network cleanup continues to consume byte, chunk, and variant admission
until a future explicit-GC policy is implemented.
The defaults are 512 MiB, 100,000 chunk rows, and 4,096 variants. These limits
do not account for redb allocation, directory blocks, snapshots, backups, swap,
an attacker-created population of unrelated directory entries, or every host
filesystem overhead; they are not a complete physical-storage or sanitization
claim.

On Unix, depot directories are opened relative to owner-controlled directory
descriptors with no-follow checks and private modes. Non-Unix uses a narrower
path-based fallback and does not receive equivalent hardened-filesystem credit.
Blob ciphertext remains after software zeroization, but mission and content
secrets are destroyed and the terminal store cannot reopen normally. Physical
media sanitization is explicitly outside this evidence.

The stopped handle takes the same process-exclusive store authority used by
the live actor and stopped State and Record facades. Stop that actor and drop
every other stopped facade before opening `SelectedBlobNode`; use
`RunningNode::selected_blobs()` instead while the actor is running. Continue
with the [selected architecture](../architecture.md), the
[selected Record API](selected-record-api.md), the
[selected State API](selected-state-api.md), the
[selected Event API](selected-event-api.md), and the
[requirements status](../validation/requirements-status.md) for the exact
partial credit and remaining network, acceptance, and release gaps.
