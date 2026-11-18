# C ABI v2

Clean Room — Privileged.

`aster_mesh.h` declares the synchronous ABI over the current `aster-node` actor
and redb store. Link the matching `aster_ffi` library and check
`aster_abi_version() == ASTER_ABI_VERSION`. ABI v1 is incompatible.

The node runs locally without binding a transport, administration socket, or
process signal handler. Publication commits without a peer. This binding does
not configure network contacts or claim remote delivery/convergence.

## Construction and ownership

Initialize versioned structures to zero, then set `abi_version` and
`struct_size = sizeof(structure)`. `AsterBytes`, `AsterClient`,
`AsterSubscription`, and `AsterRekeyRecipient` are embedded values without
headers. `aster_node_options_init` supplies the store/depot defaults.

`state_path` is an absolute state **directory**.
`provisioning_path` names an absolute owner-only Aster reference mission file.
The reference backend reads the artifact itself and retains its exact identity.
The binding does not expose a protected-provider callback. Aggregate store
and Blob depot admission limits are configurable.

Input byte slices are borrowed for the call; nonempty slices require valid
storage. Output handles must start at zero. Output buffers must start empty.
All pointers require correctly aligned, live allocations of the declared size;
an ABI cannot validate arbitrary dangling addresses. Callers must not mutate
input/output structures during a call or pass overlapping mutable outputs.

Handles are node-owned, process-local capabilities with non-reused numeric IDs.
Every child operation supplies its owning node. A result, reader, or writer
from another node is rejected. There are at most 128 open nodes and 64 results,
64 readers, and 64 writers per node. Calls serialize with close and zeroize.
Closing a node invalidates its children and joins its actor and workers.
Repeated close on a zero handle succeeds. Stale nonzero handles fail closed.

Free results with `aster_result_close`, entries with `aster_entry_free`, items
with `aster_item_free`, and buffers with `aster_buffer_free`. Owned output copies
remain caller custody after node closure/zeroization. Output allocation IDs
prevent stale copied buffers from freeing a newly reused allocation address.
Release each allocation exactly once; do not alter its pointer, length, or ID.

`aster_node_zeroize` consumes the handle even on failure. It asks the same
actor to check the retained artifact, close admission, drain workers,
and perform durable software erasure. It destroys the retained provisioning
artifact and permanently terminalizes the state. A replaced artifact fails
preflight rather than erasing another file. This does not erase caller copies
or establish physical-media sanitization. Platform limitations remain those of
the node; the exercised environment is Linux.

## Operations

| Family | ABI v2 contract |
|---|---|
| State | `publish` requires an operation key and logical key. `query` requires exact topic/scope/logical key. Current tombstones remain visible; optional recovery history carries dispositions. Finite TTL is rejected. |
| Record | The same exact-key and no-TTL rules apply. Query returns all visible current/concurrent heads, optional superseded history, sibling IDs, and an opaque guard retained by the result. Resolve accepts that result/entry, operation key, payload, priority and tombstone flag. Delivery results never authorize resolution. |
| Event | Publish requires durable client ID, recovered session and positive sequence. Persist a claim nonce before `begin_recovery`, reconcile every outstanding receipt with local intent, then `complete_recovery`. Acknowledge a publication result only after retaining/applying it. `abandon_publication` explicitly advances a sequence without an Event. Ordinary operation-key publication is absent. |
| Query pages | Event `limit` bounds rows scanned. Continue from `scanned_through` while `has_more`, even for empty pages. State/Record projections cannot be truncated: leave limit/markers zero and descendant selection false. |
| Subscriptions | Explicit class, topic/scope and operation key; Event additionally requires client/session. Persist the returned 32-byte subscription ID. Poll returns complete entries, attempt counts and `has_more`. Record entries contain the entire active-head projection, even at delivery limit one. State/Record/Blob acknowledgements require the exact returned token and delivery ID. Event acknowledgements use its semantic ID and owner session. Unsubscribe is idempotent. |
| Blob | Writer open requires operation key and total length; the native stream owns encrypted staging. Write at the exact accepted offset, without crossing a 1 MiB segment boundary (maximum `1048576 - offset % 1048576` bytes per call). Python and Go split arbitrary buffers at these boundaries. Reopening the same operation replaces the prior stream and reports `durable_offset`; resume the source there. Finish requires all bytes, and successful finish can be repeated. After a storage/actor failure during write or finish, reopen the identical operation (temporary state-unavailable can require retry). Close drops the live session; durable checkpoints remain owned by the node’s lifecycle rules. |
| Blob reads/status | Reader pages are bounded to 512 KiB (`ASTER_BLOB_READ_PAGE_BYTES`) and freshly authorized. EOF is empty; zero-length publications have authenticated empty EOF. Exact Blob query takes the 32-byte content ID as logical key and returns metadata, without plaintext/manifests. `item.id` is zero for that content lookup because it is not an exact-publication lookup. Publication receipts and deliveries retain exact publication IDs. |
| Blob lifetime/delivery | Durable or positive finite TTL is supported. Receipts/metadata echo original TTL. Delivery `kind=0` is content; `kind=1` is retirement, with generation and reason (1 expired, 2 invalidated, 3 evicted). Retirement replaces an outstanding content delivery; acknowledged content does not receive a later notice. Content and retirement notices share token-based acknowledgement. |
| Status/control | Local delivery-ledger status for State/Record/Blob; authenticated Event peer observations; emission threshold 0–3 or ReceiveOnly 4; authority scope rekey with signed public registry, independent generation witness and explicit recipients. Empty recipient topic lists mean route-only. Unknown peers return not-found, never fabricated convergence. |

`aster_result_info(node, result, &info)` reports entry count and pagination.
Use `aster_result_entry(node, result, entry_index, &entry)` then
`aster_result_item(node, result, entry_index, item_index, &item)` for
projections/deliveries. Initialize `info`, `entry`, and `item` as versioned
`AsterResultInfo`, `AsterEntry`, and `AsterItem` structures and check each status.
Free copied entries/items with `aster_entry_free` / `aster_item_free`.
Recovery results instead use `aster_result_receipt`; peer results use
`aster_result_peer`. Item dispositions are 0 current, 1 concurrent, 2 superseded.
Record sibling buffers are concatenated 32-byte IDs. Keep query results open
until resolution and any exact retry finish; closed or foreign guards fail.
Numbered Event receipts expose semantic ID, sequence, acceptance marker and
content-retirement disposition; fields unavailable in the retained commit
receipt remain zero. `inserted` distinguishes new commits from exact retries.

A nonzero operation status leaves the output unchanged, apart from consuming
close/zeroize calls. Freeing an invalid multi-buffer structure can release valid
fields before reporting the invalid field. Capture `aster_last_error` immediately on the same OS thread;
error retrieval/free preserve the diagnostic. Errors are sanitized and panics
are contained. Header constants enumerate the stable status categories.

## Build and exercise

```sh
mise exec -- sh tools/with-test-resources.sh sh tools/test-ffi-bindings.sh
```

The test script builds the library and disposable fixture helper, compiles and
executes the C runtime probe, and runs Python and Go tests against the real
library.
See [the C sample](../../examples/c_basic.c) and
[quickstart](../../docs/quickstart/c.md). No release qualification or requirements
credit is inferred from these local tests.
