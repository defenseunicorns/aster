# Application recipes

Use this page to choose an application operation and understand its safety
boundary. Runnable examples live in the linked quickstarts so they do not drift
across several documents.

## Choose an application surface

| Need | Use |
|---|---|
| Embed the selected runtime in Rust | The live and stopped [Event](quickstart/selected-event-api.md), [State](quickstart/selected-state-api.md), [Record](quickstart/selected-record-api.md), and [Blob](quickstart/selected-blob-api.md) APIs |
| Call a running local service | The authenticated Event and Blob [ConnectRPC/gRPC agent](quickstart/connect-agent.md) |
| Use the broader language bindings | The [Rust, C, Go, and Python quickstarts](quickstart/README.md) |
| Configure the local agent | The [agent configuration reference](reference/aster-agent-config-v1.md) |

The selected Rust handles are actor-owned and bounded. Cloning a handle does
not open a second store authority. A retained handle returns a sanitized
`StateUnavailable` result after its node closes.

The broader language bindings and the selected Rust runtime are related but
not identical surfaces. Check the operation table below instead of assuming
that a Rust-only operation exists in every binding.

## Choose a data class

| Data class | Use it when | Important boundary |
|---|---|---|
| **State** | Consumers need the current value for one logical key | Concurrent values resolve deterministically; recoverable history is not an application conflict notification |
| **Event** | Every immutable entry in a publisher stream matters | Reusing a logical key does not replace earlier Events; Rust can inspect sequence gaps |
| **Record** | Disconnected writers may edit the same logical document | Concurrent heads remain visible until the application resolves the exact head set |
| **Blob** | Content is large and immutable | Publish and read through streaming/file APIs; do not place a Blob in generic `publish` |

See [Core concepts](concepts.md#choosing-a-data-class) for the full selection
guide.

## Publish and retry

A successful publish confirms a local durable commit. It does not confirm that
a peer received the item or that all reachable nodes converged.

Use a stable operation key for an exact retry. Repeating the same operation
recovers the committed result; reusing the key with different content or
identity metadata fails as a conflict. Topic, scope, logical key, priority, and
TTL are separate application choices.

Selected runnable examples:

- [Event publication](quickstart/selected-event-api.md#use-the-live-api)
- [State publication](quickstart/selected-state-api.md#use-the-live-actor-api)
- [Record publication](quickstart/selected-record-api.md#use-the-live-actor-api)
- [Blob publication](quickstart/selected-blob-api.md#use-the-live-actor-api)

## Query local data

A query is a bounded snapshot of the local store. It does not contact peers.
Select the exact class, topic, scope, and logical key whenever possible. Read a
scope subtree or recoverable history only when the application explicitly
needs that broader result.

Peer/contact status is not proof that a particular item converged. Use the
class-specific query or delivery result for application decisions.

## Process durable subscriptions

Subscriptions are at-least-once. Commit the application-side effect
idempotently, keyed by the delivery identity, before acknowledging it. A stop
or crash before acknowledgement may produce another delivery attempt.

Delivery identity differs by class:

- Event follows an exact immutable Event.
- State follows a positive current version.
- Record follows one complete active-head projection, not independent siblings.
- Blob follows exact publication metadata; plaintext remains on the Blob read
  surface.

Subscriptions do not change network interests, and local delivery status is
not peer or convergence status. See the selected
[State](quickstart/selected-state-api.md#deliver-positive-current-state-versions-durably),
[Record](quickstart/selected-record-api.md#subscribe-to-whole-key-active-head-projections),
and [Blob](quickstart/selected-blob-api.md#subscribe-to-immutable-publication-metadata)
delivery guides.

## Stream Blob content safely

The broad bindings use `blob_writer`/`BlobWriter`-style streaming. The legacy
selected Rust live-file facade publishes an owned regular file, reads
authenticated pages of at most 64 KiB, and retains its 64-MiB ceiling. The
Linux local agent and `asterctl` use resumable 512-KiB application frames over
the same canonical authority and admit objects through 8 GiB. The selected
Blob profile and map-unit contract is machine checked:

<!-- ASTER-BLOB-CAPABILITY:BEGIN -->
```json
{
  "schema": 1,
  "surface": "recipes",
  "semantic_v7_v8_profile": "4:BlobRangesStreamV1",
  "semantic_v9_profile": "5:BlobStreamV1",
  "map_unit": "1048576-byte native plaintext segment",
  "record": "ASTRBS02, at most 1048706 bytes",
  "data_body": "4-byte length prefix plus one ASTRBS02 record, at most 1048710 bytes"
}
```
<!-- ASTER-BLOB-CAPABILITY:RENDERED -->
Semantic v7/v8 selects profile 4 BlobRangesStreamV1; semantic v9 selects profile 5 BlobStreamV1. Profile 5 maps 1,048,576-byte plaintext segments into append-only ASTRBS02 records of at most 1,048,706 bytes and sends one complete length-prefixed record per DATA body, at most 1,048,710 bytes, without repacking or re-encryption.
<!-- ASTER-BLOB-CAPABILITY:END -->

Each returned chunk or page is authenticated, but whole-content verification
finishes only at end-of-file. Write to a temporary destination and rename it
only after the final read succeeds. Caller-owned files and copied plaintext
remain outside node zeroization.

Local publication is independent of peer availability. The sync scheduler
opens a bounded profile-5 transfer when an eligible destination becomes
available, and interruption resumes from lifecycle-owned provisional source
state plus the native pack checkpoint journal. Atomic promotion precedes
RESULT; RESULT_ACK or EOF settles only the attempt and owns no durable resume
state. See the
[Blob streaming engineering runbook](validation/blob-streaming-engineering-runbook.md)
for large-object commands, network-path checks, and performance diagnostics.

## Resolve Record conflicts

Query the current Record conflict, load every exact sibling named by that
projection, compute a deterministic merged payload, and resolve using the fresh
exact head-set guard. If another revision arrives first, the stale guard fails
instead of discarding it.

Replicated ingestion never executes application merge code. Rust can register
a process-local merge-policy identifier for annotations, but the application
still computes and submits the resolution. Registration does not survive a
process restart.

## Use tombstones, batches, and emission policy

- A tombstone is a replicated update, not immediate physical deletion. Older
  data can reappear after the configured retention boundary if a long-absent
  node returns.
- An atomic batch contains 2–64 ordered items with the same publisher, class,
  topic, scope, and active epoch. Either every member commits or none does.
- Emission policy changes what a node may send; it does not rewrite priority,
  delete queued data, or broaden authorization.
- `ReceiveOnly` suppresses Aster contact initiation and data disclosure while
  accepting eligible inbound synchronization. It is not a physical RF-silence
  guarantee.
- In the selected runtime, `AtLeast` filters Event work only; State, Record,
  and Blob are suppressed only by `ReceiveOnly`.

## Operation names across bindings

An em dash means that the operation is not exposed by that language binding.

| Purpose | Rust | Python | Go | C ABI |
|---|---|---|---|---|
| Open node | `ApplicationNode::open` | `Node(...)` | `Open` | `aster_node_open` |
| Publish | `publish` | `publish` | `Publish` | `aster_node_publish` |
| Query | `query` | `query` | `Query` | `aster_node_query` |
| Subscribe | `subscribe` | `subscribe` | `Subscribe` | `aster_node_subscribe` |
| Poll / acknowledge | `poll` / `acknowledge` | `poll` / `acknowledge` | `Poll` / `Acknowledge` | `aster_node_poll` / `aster_node_acknowledge` |
| Atomic batch | `publish_batch` | `publish_batch` | `PublishBatch` | `aster_node_publish_batch` |
| Stream Blob | `open_blob_service` | `blob_writer` | `NewBlobWriter` | `aster_node_blob_writer_open` |
| Inspect conflicts | `conflicts` | `conflicts` | `Conflicts` | `aster_node_conflicts` |
| Resolve conflict | `resolve` | `resolve` | `Resolve` | `aster_node_resolve` |
| Inspect Event gaps | `event_gaps` | — | — | — |
| Register merge-policy ID | `register_merge_policy` | — | — | — |
| Run garbage collection | `collect_garbage` | — | — | — |
| Emission policy | `set_emission_policy` | `emission_threshold` | `SetEmissionThreshold` | `aster_node_set_emission` |
| Zeroize | `zeroize` | `zeroize` | `Zeroize` | `aster_node_zeroize` |

For protocol semantics use the [protocol specification](protocol.md). For
networking and synchronization use [Carriers and contacts](transports.md). For
implemented trust and lifecycle boundaries use
[Architecture](architecture.md) and [Security](security.md).
