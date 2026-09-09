# Go binding

Use this module when a Go application needs Aster's offline publish, query,
subscription, conflict, batch, Blob, bridge, or rekey operations. Start with the
[commented ten-minute quickstart](../../docs/quickstart/go.md); this page is the
binding-specific build and lifecycle reference.

Build or install the native library first. The binding links with
`-laster_ffi` and does not embed a repository-relative library path. Use the
platform linker configuration, or set `CGO_LDFLAGS` to add the directory that
contains the matching shared/static library. `Open` currently accepts the
canonical unprotected inner provisioning bytes for compatibility and tests; it
does not derive identity or scope access from an application password or seed,
and no protected-provider binding is shipped. Raw open is not an operational
custody solution. See the
[protected-provisioning gate](../../docs/decisions/0013-protected-provisioning-boundary.md).

The core application flow is `Open` → `Subscribe`/`Query` → `Publish` → `Poll`
→ `Acknowledge` → `Close`. Publish returns after a durable local commit and does
not wait for a peer. Subscriptions are durable and at-least-once; acknowledge
only after the application has committed its own result.

`ProtocolVersion()` is retained as the legacy name for replication-wire version
`1`; new code should use `ReplicationWireVersion()`. The default and highest
implemented semantic version are reported separately by
`DefaultSemanticVersion()` and `HighestSupportedSemanticVersion()` and are both
`6` in this build; authenticated sessions retain semantic versions 5, 4, 3, 2,
and 1 for compatibility. These process-wide values do not report a particular
session's negotiated result.

Queried and subscribed `Item` values expose `OriginScope` and `CurrentScope`.
`Scope` remains an exact compatibility alias of `CurrentScope`.

`Node` provides synchronous offline publish/query, durable subscriptions,
conflict inspection/resolution, emission policy, peer/sync status, bridge
filters, and zeroization. It deterministically closes
native result and output allocations. Call `Close` (or `Zeroize`) even though a
finalizer exists as a leak backstop.

`PublishBatch` atomically commits 2-64 ordered, same-route items and returns
ordered receipts plus aggregate eviction IDs. `RetainedDual` is the safe
default/zero-value policy; `BatchOnly` explicitly omits unchanged format-2
singleton representations used by semantic-v1 peers. Rejected batches consume
no publisher counter or event sequence.

The high-level cross-scope surface consists of `CreateBridgeEnrollment`,
`EnableBridge`, `DisableBridge`, `BridgeItem`, `ExtendBridgeRoute`, exact status
lookups, and bounded `BridgeAuthorizations` / `BridgeRoutes` pages. Enrollment
is a process-local move-only capability: `EnableBridge` consumes it once native
authority processing begins, including rejected authorization attempts. Call
`Close` for an unused enrollment. Durable `BridgeAuthorizationID` and
`BridgeRouteHandle` values are fixed 32-byte arrays and remain usable after a
node reopen.

`BridgeAuthorizationPolicy` and `BridgeNarrowingPolicy` use exact topic lists
and an explicit nonzero `PriorityMask`; the authority additionally selects a
1-8 hop bound. An empty narrowing topic list retains the authority-permitted
topics. The binding never represents sealed controls/wrappers, credential
bytes, keys, provider state, transports, or synchronization internals.

Large immutable values use `NewBlobWriter` and `OpenBlobReader`. The writer
implements `io.Writer`, the reader implements `io.Reader`, and `Finish` is
idempotent across retries. Generic `Publish(Blob, ...)` is rejected so a Blob
payload cannot accidentally be collected into one native allocation. Each Blob
chunk is authenticated before `Read` returns it, but the whole-content digest is
verified only at the read that reaches `io.EOF`; do not act on accumulated bytes
before that boundary.
`PublishBlobBatch` finalizes and atomically publishes 2-64 distinct writers;
the writers remain retryable on failure, and `Finish` returns their matching
batch receipts after success.

Control-authority nodes use `RekeyScope` with opaque signed registry bytes, a
caller-retained minimum generation, a newer epoch, and explicit
`RouteOnlyRecipient` or `ReadTopicsRecipient` values. Nested native memory is
borrowed only for the synchronous call. The binding exposes the durable receipt,
never keys, provider state, grant plans, or sealed controls.

Run the actual shared-library tests with:

```sh
cargo build -p aster-ffi
env CGO_LDFLAGS="-L$(pwd)/target/debug" \
  LD_LIBRARY_PATH="$(pwd)/target/debug" \
  DYLD_LIBRARY_PATH="$(pwd)/target/debug" \
  go -C bindings/go test ./...
```

Repository verification instead uses the `aster_workspace` build tag, which
adds only the workspace-local debug library directory and runtime search path:

```sh
cargo build -p aster-ffi
GOCACHE=/tmp/aster-mesh-go-cache \
  go -C bindings/go test -tags aster_workspace ./...
```
