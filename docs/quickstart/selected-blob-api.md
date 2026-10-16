# Selected Blob API quickstart

This is the shortest path to Aster's **selected live Blob application surface**,
its durable metadata-delivery queue, its exclusive stopped streaming facade,
and the semantic-v7/v8 receipt-free streaming boundary for Blob transfer.
`RunningNode::selected_blobs()` returns a cloneable `SelectedBlobHandle`: an
application may publish a durable or finite-TTL owned regular file while the
node has no peers, read one freshly authenticated plaintext page at a time,
and consume tagged at-least-once content or retirement notifications for exact
source-authenticated Blob publications.
Each live page is at most 64 KiB and zeroizes its owned plaintext allocation on
drop; each delivery is metadata only and carries no Blob plaintext.

The live surface deliberately keeps application delivery separate from network
replication. A Blob subscription is durable local intent, not a route/content
grant or a dynamic network interest. The surface has no Blob peer or convergence
status; `delivery_status` reports local selector/delivery-ledger counts, while
`transfer_status` reports audited local durable storage and receive progress.
The exclusive `SelectedBlobNode` remains available when no runtime owns the same
store and provides the same delivery lifecycle plus synchronous seekable-source
publication and streaming `read_into`. Separately, semantic v7/v8 profile 4
reconciles Blob sources and direct carrier ranges between current
content-capable peers. V7 admits durable work only; v8 also admits finite work
with exact authenticated custody provenance. Both endpoints must support
`BlobRangesStreamV1`; old Blob transfer has no fallback. Incompatible profile
offers and v5/v6 carrier attempts fail before carrier IO. `EventPagesV1` is
Event-only. The default semantic offer is `[8, 7, 6, 5, 4, 3, 2, 1]`; stable
wire/ABI, source, manifest, and `ASTRBT01` formats remain version 1.

## Use the live actor API

Start the node as described in the [selected Event quickstart](selected-event-api.md),
then retain a clone of the Blob handle. The configured peer list may be empty;
publication success means the signed publication and encrypted depot content
are durable locally, not that any peer received them.

```rust
use aster_mesh::Priority;
use aster_node::application::{
    BlobPublishOptions, BlobPublishRequest, BlobReadPageRequest, BlobReadRequest,
    MAX_SELECTED_BLOB_PAGE_BYTES,
};
use std::{fs::File, io::Write};

let blobs = running.selected_blobs();
let published = blobs
    .publish_with_options(
        BlobPublishRequest {
            operation_key: b"my-app/blob/input-v1".to_vec(),
            topic: topic.clone(),
            scope: scope.clone(),
            priority: Priority::Priority,
            media_type: Some("application/octet-stream".into()),
            schema_id: Vec::new(),
        },
        BlobPublishOptions::finite_ttl_ms(60_000)?,
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
The 64-MiB ceiling is the current selected-backend policy, not a public RPC or
wire-format guarantee.
The returned publication is operation-key idempotent and echoes its original
signed TTL (`None` means durable), never a remaining lifetime or deletion
timestamp. `BlobPublishOptions::finite_ttl_ms(0)` returns `InvalidRequest` before
source I/O, and a host without a supported finite custody clock returns
`UnsupportedValue` before source I/O or mutation. `publish` remains the durable
wrapper. Retrying the exact operation with the same source, identity metadata,
and lifetime recovers the original publisher counter and acceptance marker;
changing content, metadata, or lifetime under that key fails closed as a
conflict.

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

## Use the local agent and `asterctl`

On Linux, the local `aster-agent` exposes native gRPC `PublishBlob` and
`ReadBlob` streams backed by the same running node authority. Its plaintext
listener is loopback-only. On non-Linux hosts, `ReadBlob` remains available to
a capable native-gRPC client, while secure agent upload staging and
`asterctl blob-read` finalization are unsupported. Supply exactly one
bearer-token source to `asterctl`; a protected token file avoids placing the
token in the command line:

```sh
TOKEN_FILE=/run/aster/client.token

# Durable publication.
asterctl --token-file "$TOKEN_FILE" blob-publish \
  --file ./map.bin \
  --topic imagery.maps \
  --scope mission/team/alpha \
  --operation-key map-001 \
  --media-type application/octet-stream

# Finite publication. The original 60000-ms TTL is echoed on every result.
asterctl --token-file "$TOKEN_FILE" --json blob-publish \
  --file ./overlay.bin \
  --topic imagery.maps \
  --scope mission/team/alpha \
  --operation-key auto \
  --ttl-ms 60000

# Copy the returned Blob ID into BLOB_ID and read to a path that does not exist.
asterctl --token-file "$TOKEN_FILE" blob-read \
  --id "$BLOB_ID" \
  --topic imagery.maps \
  --scope mission/team/alpha \
  --output ./downloaded-map.bin
```

`--operation-key auto` writes
`asterctl: operation-key=<32-lowercase-hex-digits>` to stderr before sending.
Save that exact value; JSON output also includes it as `operation_key`. A lost
response or other unknown publication outcome must be recovered by repeating
the identical file bytes, metadata, TTL, and other options with
`--operation-key=<saved-key>`. The authoritative idempotent result can report
`inserted: false`. A new key would describe a new application operation rather
than recover the uncertain one.

Text metadata uses exactly `TTL: durable` or `TTL: 60000 ms`. Finite JSON uses
exactly `"ttlMs": "60000"`; durable JSON omits `ttlMs`. The value is the
original authenticated lifetime, never a countdown or deletion time. Blob
plaintext is written only to the requested output and is never printed.

The RPC and CLI use checked `u64` lengths and bounded 64-KiB frames/pages; they
do not promise a fixed total-size ceiling. The current selected backend rejects
objects above 64 MiB. The shared agent deadline policy currently defaults to
10 seconds and caps a stream at 30 seconds, even if `asterctl --timeout` asks
for longer. These values describe this implementation, not durable RPC
semantics, supported large-file behavior, or performance qualification.

`blob-read` currently requires Linux, a destination directory owned by the
current user and not writable by group or other users, and a filesystem that
supports named staging, atomic no-replace rename, and directory synchronization.
It creates one randomly named mode-0600 sibling, synchronizes the complete
verified stream, then renames that exact inode atomically without replacing an
existing or concurrently created path and synchronizes the directory. The
requested destination remains absent until publication. Cleanup removes the
sibling on a best-effort basis; filesystem errors or an abrupt process or host
failure can leave that hidden owner-only file for operator cleanup. A reported
post-publication directory-sync failure means the destination exists and must
be verified before retrying. Unsupported platforms and filesystems fail closed.

The caller's source file and completed output file remain outside node
zeroization custody. Node zeroization does not erase them, and callers must
apply their own retention and sanitization policy. The agent separately stages
an upload in one private allocated file under its pinned state root, unlinks it
before accepting payload bytes, and currently requires Linux for that custody
boundary. Keep the publish source contents and length unchanged until command
exit; detectable size changes have an unknown publication outcome, while
same-length in-place mutation is outside the command contract.

The agent and CLI provide Blob publish and read, not Blob subscription, poll,
acknowledgement, transfer status, peer/convergence status, or FFI lifetime
controls. The Rust subscription API below remains a separate application
surface.

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
    BlobDeliveryItem, BlobPollRequest, BlobReadRequest, BlobSubscriptionRequest,
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

for item in page.deliveries {
    match item {
        BlobDeliveryItem::Content(delivery) => {
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
        BlobDeliveryItem::Retirement(retirement) => {
            blobs
                .acknowledge(
                    subscription.id,
                    retirement.publication,
                    retirement.token,
                )
                .await?;
        }
    }
}

let local = blobs.delivery_status().await?;
assert_eq!(local.subscriptions, 1);

let transfers = blobs.transfer_status().await?;
for pending in transfers.pending {
    println!(
        "blob={} durable_carriers={}/{} durable_bytes={}/{} phase={:?}",
        pending.id,
        pending.durable_carriers,
        pending.total_carriers,
        pending.durable_carrier_bytes,
        pending.total_carrier_bytes,
        pending.phase,
    );
}
blobs.unsubscribe(subscription.id).await?;
```

Subscription creation is operation-key idempotent. A matching retry returns the
same durable identifier, while changing the selector under that key fails
closed. `scan_limit` bounds the complete matching retained publication set that
one poll freshly authenticates; poll fails closed rather than silently advancing
through a partial snapshot. `delivery_limit` bounds the committed attempts
returned from that verified set.

Before returning a content delivery, the node rechecks current mission policy,
exact source envelope and identity metadata, route/content authority, revocation
and epoch, and the completed encrypted-depot content. The notification exposes
only the publication ID, Blob ID, publisher/counter, topic/scope, priority, byte
length, media/schema identity metadata, acceptance marker, attempt, and opaque
acknowledgement token. A retirement notice instead identifies the retired
publication, original TTL, typed reason, retirement generation, attempt, and a
separately bound token. Neither form returns a manifest, source envelope, sealed
bytes, key, nonce, chunk, carrier state, or depot path.

Unacknowledged work is retried with a higher nonzero attempt and a new opaque
token. Version-1 tokens bind content tenure; version-2 tokens bind retirement
generation, and acknowledgement dispatches strictly by that tag. Any earlier
valid token at or below the durable attempt high-water remains valid while its
exact content tenure or retirement evidence remains active, so a response lost
to process termination can still be acknowledged after a later retry. Exact
acknowledgement and reacknowledgement are idempotent; tokens above the issued
high-water, cross-subscription or cross-publication tokens, prior-tenure tokens,
stale incarnations, malformed tokens, and removed/recreated selectors fail
closed. Reads and expired unacknowledged content tokens return
`ExpiredOrRetired` while retirement evidence is retained. After its existing
45-day conservative lower-bound
retention expires, the retired publication and retirement token return
`NotFound`.
`unsubscribe` removes the selector and its delivery ledger without changing
configured Blob network interests.

Cancellation before enqueue cannot mutate the ledger. After enqueue, the
worker may have committed: retry `subscribe` with the exact operation key to
recover its durable selector; a later `poll` safely issues another attempt if
the prior page was lost; retry `acknowledge` with the exact token to observe its
idempotent outcome; and retry `unsubscribe` to observe `AlreadyAbsent` after a
completed removal. `delivery_status` is read-only. These recovery rules do not
make application side effects transactional with acknowledgement.

`delivery_status` is a structurally audited local ledger snapshot, not sync,
contact, peer, transfer-progress, or convergence status.

`transfer_status` is also read-only and is available on both
`SelectedBlobHandle` and `SelectedBlobNode`. Its retained counters include all
local rows that still consume durable capacity; its `pending` list includes
only currently authorized source projections. `AwaitingCarrier`, `Receiving`,
and `ReadyToFinalize` are derived from durable carrier prefixes and committed
chunks. Byte counts describe encrypted carrier representations, not plaintext.
The snapshot deliberately omits peer identities, carrier object identities,
routes, lineages, paths, and keys, and makes no peer or global convergence
claim.

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

## Opt in to semantic-v7/v8 transfer

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
down, and later restart with an exact configured peer. On a v7 or v8 profile-4
contact, a content-capable interested receiver can durably stage the source and
missing carrier ranges, promote only after whole-Blob verification, and read
the Blob through its own live handle. The receiver's completed publication and
page reads survive another peerless restart.

The provider turns that exact topic/scope and the current epoch into an opaque
32-byte peer proof inside the protected v7/v8 contact. Every Blob inventory,
source, and range send requires the authenticated peer to have both the current
content proof and current route authorization and to remain nonrevoked.
Route-only peers cannot use the selected Blob lane. The source-envelope and
complete manifest plan reconcile first; carrier requests begin only after that
pending source is durably staged.

Each scheduled range extends one exact contiguous prefix by at most 16 KiB. A
bounded `ABRS` schedule receives indexed Data or Unavailable `ABRD` records
and one schedule-bound `ABRE` terminal plus FIN; there is no per-range storage
Result/Ack. The prefix is peer-neutral: its durable key is the source transfer
ID plus strict kind-2 carrier ID, not the peer or session, so after
runtime/store/provider-cache teardown and reopen any other eligible content
peer can continue at the first missing byte. A valid terminal authorizes the
turn's completion and cursor outcome but is not proof of remote storage.

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
chunk, and variant quotas until exact manifest-backed reclamation finalizes.
Bounded maintenance can reclaim authorized unreferenced variants; an
exact-lineage retry can resume retained staging, while a different lineage at
the same numeric epoch still fails and must advance the epoch.

Source/store/cache transitions are locally serialized. A successful abort
removes the old authenticated claim, rereads durable source state, and freshly
authenticates any exact concurrent restage before restoring its claim. A
terminal content-verification failure aborts only the exact pending source and
is cursor-neutral. Successful terminal source rotation uses the
lexicographically greatest carrier ID, not the last manifest record.

Normal and `AtLeast` run eligible v7/v8 profile-4 Blob work because `AtLeast`
filters Event only.
`ReceiveOnly` advertises, requests, stages, promotes, and counts zero Blob work.
The live handle does not change those contact rules and reports no Blob peer or
convergence status. On a host with a supported custody clock, the Rust
`publish_with_options` surface activates local finite Blob publication and
expiry. Finite transfer between peers remains restricted to semantic v8 with
profile 4; v7 transfers durable Blob work only. Bounded strictly-lower-priority
pressure recovery remains internal.
Route-only Blob relay/custody, a metadata-independent whole-byte identity, and
Blob TTL fields in the FFI surface are not implemented. The selected Linux
local-agent and `asterctl` path exposes Blob publish/read TTL, but not the Rust
Blob subscription or transfer-status operations.

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

## Durable storage and verification boundary

Blob publication becomes authoritative only after private chunk files are
written, synchronized, renamed, directory-synchronized, and matched by exact
redb commit markers. Unmarked files are reclaimed; a marked missing, truncated,
or mismatched file is an integrity failure rather than repair input.

The database and sibling depot are owner-bound. Moving, copying, replacing, or
partially migrating them is rejected where the platform can prove the identity
change; no supported depot-rebind or backup-restore workflow exists.

Every read rechecks current policy, source identity, content authority, active
epoch, publication selection, and depot completion. A late `read_into` failure
may leave an independently verified prefix in caller-owned output, so use a
temporary destination when replacement must be all-or-none. The complete trust
path is documented in the [selected architecture](../architecture.md).

## Understand the current limits

`StoreLimits` account for signed Blob publications and durable operation rows
alongside Event, State, Record, control, and route-cache rows. Separate
`BlobDepotLimits` bound ciphertext-file bytes reserved by every durable expected
chunk record, durable per-chunk metadata rows, and epoch-specific import
variants. Those bounds include both committed content and unfinished resumable
imports, so abandoned but structurally valid staging retained after terminal or
stale network cleanup continues to consume byte, chunk, and variant admission
until exact manifest-backed physical reclamation finalizes.
The defaults are 512 MiB, 100,000 chunk rows, and 4,096 variants. These limits
do not account for redb allocation, directory blocks, snapshots, backups, swap,
an attacker-created population of unrelated directory entries, or every host
filesystem overhead; they are not a complete physical-storage or sanitization
claim.

### Pressure recovery is narrow and deterministic

Before returning an eligible Blob capacity error, admission runs its existing
bounded routine cleanup. If the exact rejected partition remains full, it can
recover capacity only from the matching Blob kind:

- aggregate item/byte and per-content-publication pressure select live
  publications;
- network-staging row/byte pressure selects pending sources; and
- depot byte/chunk/variant pressure selects whole physical variants.

Operation, publication-lifecycle, causal-frontier, lease, lineage-fence, and
replay-fence capacity are cleanup-only: pressure recovery never evicts them.
The candidate must have an effective priority *strictly* lower than the incoming
work, so equal- and higher-priority live Blob work remains protected.

Within an eligible partition, selection is deterministic: lower effective
priority first; incomplete transfers before completed content; then expired
finite work, live finite work by nearest final-reference deadline, and durable
work last; followed by exact completion fraction, acceptance order, and exact
identity. Semantic-v8 finite work uses authenticated conservative lower-bound
age; semantic-v7 work remains durable-only.
Completion compares the durable carrier-prefix or committed-plaintext fraction
exactly, rather than using floating point.

One selected candidate is a whole atomic work unit. The store preflights its
roots, delivery and operation edges, indexes, lease generations, retirement
records, and any deletion-manifest work within explicit bounds. If it cannot
prove the first candidate or that complete unit exceeds the remaining recovery
budget, it changes nothing and does not skip to a later candidate. A final
physical root is retired with a durable deletion manifest; filesystem unlink is
then idempotent and resumable across interruption or restart while the retired
content stays unavailable and every variant, chunk, and byte remains charged
until deletion finalizes. Depot pressure authorizes the single retry only after
that physical finalization measurably releases the rejected partition.

After a successful bounded recovery, the node removes every returned evicted
transfer from its authenticated route and pending-completion caches while it
holds the Blob lifecycle lock, then retries the original admission once. It
preserves the original capacity result when recovery is ineligible or
insufficient, and never turns pressure recovery into an unbounded retry loop.
If the retry fails with anything other than the equivalent capacity rejection,
that second policy, schema, integrity, or coherence result is propagated.

On Unix, depot directories are opened relative to owner-controlled directory
descriptors with no-follow checks and private modes. Non-Unix uses a narrower
path-based fallback and does not receive equivalent hardened-filesystem credit.
Blob ciphertext remains after software zeroization, but mission and content
secrets are destroyed and the terminal store cannot reopen normally. Physical
media sanitization is outside the software-zeroization boundary.

The stopped handle takes the same process-exclusive store authority used by
the live actor and stopped State and Record facades. Stop that actor and drop
every other stopped facade before opening `SelectedBlobNode`; use
`RunningNode::selected_blobs()` instead while the actor is running. Continue
with the [selected architecture](../architecture.md), the
[selected Record API](selected-record-api.md), the
[selected State API](selected-state-api.md), the
[selected Event API](selected-event-api.md), and the
[requirements status](../validation/requirements-status.md) for credited
behavior and open validation gaps.
