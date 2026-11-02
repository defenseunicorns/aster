# C ABI

Use the ABI when embedding Aster in C, C++, or another language with a
C-compatible foreign-function interface. Start with the
[commented C quickstart](../../docs/quickstart/c.md); this page is the complete
ownership, versioning, and capability reference.

`aster_mesh.h` is the authoritative ABI v1 declaration. Link the matching
`aster-ffi` shared or static library and initialize every versioned structure
with `ASTER_STRUCT_INIT(type)` before use.

Version reporting separates stable encoding from negotiated behavior.
`aster_protocol_version()` remains a compatibility alias for
`aster_replication_wire_version()` and returns wire/profile version `1`.
`aster_default_semantic_version()` and
`aster_highest_supported_semantic_version()` both return `9` for this build;
authenticated sessions retain semantic versions 8, 7, 6, 5, 4, 3, 2, and 1 for
compatibility. Semantic v6 preserves every v5 ordinary lane and adds the
selected node's mutually enabled Event-bridge frame lane; it does not change
ABI or replication-wire version `1`.
None of these process-wide functions reports the version selected by a
particular authenticated session.

Semantic-v7 transfer-profile selection and Event page controls are
runtime-internal. This application binding exposes neither; State, Record, Blob,
and EventBridge remain available through the negotiated `LegacyV6` profile.

Explicit atomic publication uses `aster_node_publish_batch` with 2-64 ordered,
same-class, same-topic, same-scope items. `ASTER_BATCH_RETAINED_DUAL` is the
offline-safe default; `ASTER_BATCH_ONLY` opts out of retaining unchanged
format-2 singleton representations for semantic-v1 peers. The opaque result
preserves publish-result order and exposes aggregate
post-insert eviction IDs; close it with `aster_batch_result_close`. Rejection
commits no member and consumes no publisher counter or event sequence.

Blob payloads use `aster_blob_writer_t` and `aster_blob_reader_t`; generic
`aster_node_publish` rejects `ASTER_BLOB`. Initialize writer options with
`aster_blob_publish_options_init`, stream bounded caller slices with
`aster_blob_writer_write`, then call the idempotent `finish`. The returned full
Blob ID is the manifest item's logical key. Readers fill caller-owned buffers
incrementally, authenticating each chunk before returning it. Whole-content
digest verification completes only when a read reports zero bytes; do not act
on accumulated plaintext before that EOF result.
`aster_node_publish_blob_batch` finalizes and atomically publishes 2-64
distinct, unpublished writers without exposing manifests or route commitments.
Writers remain open and retryable; after success their ordinary `finish`
returns the matching batch receipt.

Input slices are borrowed only for one call. Items, conflicts, deliveries,
peer snapshots, and owned buffers returned by the library are independent
copies; release them with their matching `*_free` function. Close
every result handle and call `aster_node_close` or `aster_node_zeroize` for each
node handle. Numeric handles are process-local capabilities and must not be
serialized.

Returned items distinguish the source-authenticated `origin_scope` from the
`current_scope` where an authorized bridge projection is visible. The legacy
`scope` field is an exact alias of `current_scope`.

Bridge administration is capability-based. A bridge node calls
`aster_node_bridge_enrollment_create`; the returned
`aster_bridge_enrollment_t` is process-local, cannot be serialized, and reveals
no credential or provider bytes. An authority passes its address to
`aster_node_bridge_enable`. Once native authority processing starts, enable
move-consumes and zeros the enrollment on both success and error. Close an
unused enrollment explicitly.

Authority policy contains 1-128 exact topics, an explicit nonzero four-bit
priority mask, and a 1-8 hop bound. First-hop creation takes only an ItemID,
authorization ID, and local narrowing. Nested creation takes only a durable
32-byte route handle, authorization ID, and narrowing. The narrowing topic list
may be empty to retain every authority-permitted topic, but its priority mask is
always explicit. No operation accepts sealed objects, route descriptors,
transport choices, keys, or provider handles.

Authorization IDs and route handles are stable 32-byte durable values. Exact
status lookup and the bounded `aster_node_bridge_authorizations` /
`aster_node_bridge_routes` page APIs reauthenticate stored metadata and work
after reopening the node. Page cursors are exclusive IDs/handles and page sizes
are capped at 4096. Free each returned status or route result, then close its
page handle. Authorization topic metadata is encoded as `topic_count`
repetitions of `u16` big-endian byte length followed by UTF-8 bytes.

Control-authority nodes may call `aster_node_rekey_scope` with an opaque signed
public registry, an independently retained minimum generation, a strictly newer
scope epoch, and 1-128 explicit recipients. `ASTER_REKEY_ROUTE_ONLY` recipients
must have no topics; `ASTER_REKEY_READ_TOPICS` recipients must have 1-128
borrowed topic slices. The receipt contains only generation, epoch, recipient
count, and durable control sequence. The ABI never returns keys, provider state,
grant plans, wrapped grants, or sealed control bytes.

The application ABI intentionally does not expose sealed-envelope emission or
ingestion. Authenticated transport and reconciliation are owned by the runtime,
while this header keeps publish, query, subscription, conflict, and policy
operations at the application level.

Closing or zeroizing a node also invalidates all still-open query, delivery,
conflict, peer-list, Blob writer, Blob reader, unused bridge enrollment, and
bridge status-page handles created by that node. Individual owned output
buffers already handed to the caller remain valid until freed.

All operations are synchronous and may be called from multiple threads. A node
serializes its durable mutations internally. Close and zeroize invalidate the
caller's handle and wait for operations already using that node; wrappers must
still provide exclusive access to the handle variable itself while changing it.

Every exported entry point contains Rust unwinding and returns `ASTER_PANIC`.
The release profile therefore uses unwind semantics; changing it to `panic =
"abort"` would bypass the ABI boundary and terminate the embedding process.

`aster_node_open` currently accepts the canonical unprotected inner
provisioning bundle for compatibility and tests. Its format and contained
credentials remain outside the ABI, and the C surface has no protected-provider
entry point yet. Do not treat raw bundle ingestion as an operational custody
solution or place provisioning material in source control. See the
[protected-provisioning gate](../../docs/decisions/0013-protected-provisioning-boundary.md).
