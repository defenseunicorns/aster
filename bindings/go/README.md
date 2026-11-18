# Go binding

Clean Room — Privileged.

This cgo package wraps the redb-backed `aster-node` runtime through C ABI v2.
It requires the matching `aster_ffi` library. `-tags aster_workspace` adds the repository's
`target/debug` library directory; downstream packages configure their link path.

```go
node, err := aster.Open("/absolute/state", "/absolute/owner-only-mission.bundle")
if err != nil { return err }
defer node.Close()
_, err = node.Publish(aster.PublishRequest{
    Class: aster.State, Topic: "position.current", Scope: "mission/team/alpha",
    OperationKey: []byte("position/1"), LogicalKey: []byte("unit-7"),
    Payload: []byte("position"),
})
```

State/Record require operation keys, exact-key queries, and no finite TTL.
`Query` returns a `*Result`: close it explicitly, and retain it while calling
`Resolve`. `Entries` preserves whole Record projections and sibling annotations;
`Items` is a convenience flattening. Poll results expose `HasMore`; Event queries
also expose `ScannedThrough`. A delivery is acknowledged as a complete `Delivery`
with its returned token. `RestoreSubscription` restores a durable ID after reopen.

Events use explicit `Client`, `Sequence`, `BeginRecovery`, `CompleteRecovery`,
`AcknowledgePublication` and `AbandonPublication`. Persist intent and claim nonce
before calls and reconcile outstanding results before completing recovery.
The wrapper does not synthesize a durable application journal.

`NewBlobWriter` requires an operation key and total length, exposes `Offset()`
for checkpoint resume, and implements `io.Writer`. `Finish` is repeatable after
success. `OpenBlobReader` implements `io.Reader`. Blob options/receipts include
finite TTL; subscription deliveries distinguish content from retirement.
Emission, authenticated peer status, local delivery status and scope rekey remain
available. All wrapper methods serialize with node closure. Error capture pins
the goroutine to the originating OS thread.

Explicit `Close` is required for nodes/results/readers/writers; finalizers are
only a leak backstop. Node closure invalidates its children and joins native
work. `Zeroize` consumes the node, destroys its retained provisioning artifact,
and terminalizes the state. Caller-owned Go copies survive. No transport or
process signal handler is installed by the binding.

See the [ABI contract](../c/README.md),
[Go sample](../../examples/go_basic.go), and [quickstart](../../docs/quickstart/go.md).
Run the real suite from the repository root:

```sh
mise exec -- sh tools/with-test-resources.sh sh tools/test-ffi-bindings.sh
```
