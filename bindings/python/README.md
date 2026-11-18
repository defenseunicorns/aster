# Python binding

Clean Room — Privileged.

The standard-library `ctypes` package wraps C ABI v2 and the redb-backed
`aster-node` runtime. Build `aster-ffi`, put `bindings/python` on `PYTHONPATH`,
and optionally set `ASTER_MESH_LIBRARY` to its shared library. The header and library must match.

```python
from aster_mesh import DataClass, Node

with Node("/absolute/state", "/absolute/owner-only-mission.bundle") as node:
    node.publish(DataClass.STATE, "position.current", "mission/team/alpha",
                 b"position", logical_key=b"unit-7", operation_key=b"position/1")
    with node.query(DataClass.STATE, topic="position.current",
                    scope="mission/team/alpha", logical_key=b"unit-7") as result:
        print(result[0].payload)
```

State/Record have no finite TTL and use exact logical keys. Results are context
managers: `.items` is the complete visible version list, `.entries` retains
projection/delivery groups, sibling IDs, tokens and retirement tags. Keep a
Record query result open for `node.resolve(result, payload, operation_key=...)`.
A polled Record delivery is a complete projection and cannot be used as a guard.

`subscribe(class, topic, scope, operation_key=..., client=...)` returns a durable
subscription. `subscription.poll()` returns a `Result`; process each `.entries`
delivery and acknowledge that complete delivery. Persist `subscription_id` to
restore it after restart. Application selectors do not configure transport or
network receive interests. Follow `has_more` on polls and Event queries; the
Event query continuation is `scanned_through`.

Events require an explicit `Client`, recovered session and numbered sequence.
Use `begin_recovery(client_id, expected_session, persisted_claim_nonce)`, reconcile
its outstanding receipts against durable local intent, and call
`complete_recovery(client, revision)`. Publish with `client=...`, `sequence=...`
and an empty operation key. `acknowledge_publication` releases retained result
metadata only after the application has applied/retained it. This low-level
binding does not invent a client journal or infer recovery completion.

`blob_writer(..., operation_key=..., total_len=...)` returns a context manager.
Resume from `.offset`, write bytes, and finish for an immutable receipt.
`blob_reader(topic, scope, blob_id)` implements `io.RawIOBase`, including bounded
`readinto`. Finite Blob TTL and tagged retirement deliveries are supported.
`delivery_status`, `peers`, `peer_status`, emission policy and `rekey_scope`
remain available. Errors expose a numeric `.status`.

Close releases the runtime and invalidates child handles. Zeroize also destroys
the retained provisioning artifact and terminalizes the state; caller-owned
Python byte copies remain caller custody. The node binds no sockets or signal
handlers. Raw reference provisioning remains an evaluation boundary.

See the [full ABI contract](../c/README.md) for ownership, recovery, limits
and failures.
Run `sh tools/with-test-resources.sh sh tools/test-ffi-bindings.sh` from the
repository root to build the fixture helper and exercise all real bindings.
