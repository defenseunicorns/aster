# Language binding pattern

Clean Room — Privileged.

Bindings wrap C ABI v2; they do not implement storage, crypto, wire, or
reconciliation semantics. Each node runs a redb-backed `aster-node` actor
with embedding-owned shutdown and in-process zeroization. The [C contract](../../bindings/c/README.md) is the operation and
ownership reference; `aster_mesh.h` declares the exact layouts.

1. Check ABI version before calling. Mirror structure sizes, integer widths,
   pointer alignment, explicit booleans and binary buffer lengths exactly.
2. Keep input buffers alive until return; copy outputs before freeing them.
   Initialize versioned outputs, empty buffers and zero handles. Never expose
   raw native pointers as long-lived language values.
3. Serialize wrapper handle mutation with close. Retain the owning node in every
   child object. Provide deterministic result/stream/node cleanup and a leak
   backstop. Native registries independently reject foreign/stale handles.
4. Capture errors on the operation's OS thread before another successful call
   clears them. Go pins its goroutine across the native call and error capture.
5. Preserve API semantics: exact State/Record keys, explicit Record sibling
   sets and opaque query guards, complete Record delivery projections, numbered
   Event recovery, and tagged Blob content/retirement notifications. Propagate
   pagination and original TTL without inventing missing status.
6. Keep Record query results alive for resolution/retry. Delivery annotations do
   not authorize resolution. Never reconstruct a guard from sibling IDs.
7. Make byte limits and lifetimes visible. Blob sources have declared total
   length; writes/read pages are bounded. Reopen an identical operation and
   resume at its reported durable offset after an interrupted stream.
8. Build and execute examples and foreign-language behavioral tests against the
   real native library.

The current startup accepts an owner-only reference artifact path. Protected
provisioning/SecretStore callbacks remain a separate unimplemented binding gate.
Zeroization destroys the exact retained artifact and terminalizes the state;
caller-owned output copies and physical-media sanitization are outside that
software boundary. The local binding opens no transport, administration socket,
or process signal handler.

State/Record finite TTL and retention controls are unsupported.

The shared executable suite is `tools/test-ffi-bindings.sh`. It covers native
C calls, Python ctypes and Go cgo, including binary values, durable reopen,
numbered recovery/fencing, whole conflicts and guarded resolution, rekey,
streaming/empty Blob, lifetime notifications, handle invalidation and zeroize.
Rust FFI tests additionally check allocation IDs, invalid outputs, bounded
handle counts, cross-node guards, concurrent closure and artifact replacement.
These are local implementation tests, not usability or release qualification.
