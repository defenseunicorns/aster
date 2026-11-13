# Decision 0030: Admit a bounded Event-first local ConnectRPC agent


- Status: accepted for an alpha implementation slice; production and release
  gates remain open
- Date: 2026-08-25
- Authority: [`data-mesh-requirements.md`](../../data-mesh-requirements.md)
- Related: [Decision 0002](0002-dependency-admission.md),
  [Decision 0008](0008-local-agent-phasing.md),
  [Decision 0009](0009-public-api-boundary.md), and
  [Decision 0028](0028-selected-stack-implementation-boundary.md)

## Context

Requirements section 7 marks a gRPC-or-similar local agent as an MVP Should,
requires the same high-level application boundary as the library, and gives a
short integration target. Decision 0008 correctly rejected a thin
unauthenticated daemon and deferred work until local authentication, service
lifecycle, versioning, and bounded backpressure could be addressed.

The selected node now has a cloneable live `SelectedEventHandle` into its sole
actor and durable-store authority. It can support an out-of-process Event API
without opening a second store or exposing privileged adapter seams. State and
Record have real class-specific mesh reconciliation, but their application
facades remain stopped-only and cannot honestly back live RPCs.

The project convention is Buf plus ConnectRPC without use of the Buf Schema
Registry. A repository-owned Protobuf module and descriptor set preserve that
choice while allowing standard Connect, gRPC, and gRPC-Web clients.

## Decision

1. Add the `aster.application.v1alpha1.AsterApplicationService` protocol as a
   local Buf module. The alpha surface contains status plus high-level Event
   publish, query, durable subscription, bounded poll, server stream, explicit
   acknowledgement, unsubscribe, and authenticated gap inspection.
2. Omit State, Record, and Blob RPCs. They enter this live service only after
   the selected node has corresponding handle-backed operations; the agent
   must never open the store beside the running actor.
3. Build the Rust server with ConnectRPC 0.9.0 and checked-in descriptors.
   Cargo builds do not invoke Buf or `protoc`. Buf 1.72.0 is a pinned developer
   tool for local format, lint, and descriptor reproduction. No schema,
   dependency, plugin, build, or runtime action uses the Buf Schema Registry.
4. Bind the plaintext listener only to a loopback address. Require an exact
   bearer credential on every unary and streaming call. Load it once from a
   no-final-symlink regular file owned by the effective process user with no
   group/other permissions on Unix, retain it in zeroizing
   memory, and compare it in constant time. Keep the service/router private so
   library consumers cannot construct an unauthenticated server accidentally.
5. Bound request body and decoded message size at 1 MiB, element memory at
   4 MiB, and each encoded Protobuf response at 2 MiB before protocol framing.
   Oversized pages fail with `ResourceExhausted` so callers can retry with a
   smaller limit. Bound RPC deadlines to 10 ms through 30 seconds with a
   10-second default, concurrent HTTP/2 streams at 32, idle connections at 60
   seconds, connection age at 30 minutes, and keepalive behavior.
   Authentication occurs after the bounded body read but before Protobuf
   decoding or handler execution.
6. Implement `StreamEvents` as repeated bounded durable polls. Require a
   100 ms through 60 second backoff and apply it after delivered as well as
   caught-up polls so an unacknowledged Event cannot hot-loop through attempts.
   Stream cancellation never acknowledges an Event; clients commit their
   effect and acknowledge separately for explicit at-least-once semantics.
7. Share graceful shutdown state with active delivery streams so they stop
   before the transport drain completes.

This supersedes only Decision 0008's scheduling deferral. Its security and
lifecycle concerns remain requirements and gates.

## Exact dependency admission

The directly admitted runtime/code-generation packages are pinned exactly:

| Package | Version | Role | Declared license |
|---|---:|---|---|
| `connectrpc`, `connectrpc-build`, `connectrpc-codegen` | 0.9.0 | protocol server/client and descriptor-based Rust generation | Apache-2.0 |
| `buffa`, `buffa-codegen`, `buffa-descriptor` | 0.9.1 | Protobuf messages, JSON, and descriptors used by ConnectRPC | Apache-2.0 |
| `buf` | 1.72.0 | pinned developer CLI only | Apache-2.0 |

ConnectRPC 0.9.0 was reviewed at signed tag `v0.9.0`, tag object
`9d6c9be1fbeeb7b5afe87e463b52f32601100f57`, resolving to commit
`26e77f2ee835e61a5473647a3c64d6b859bcc266`; its published security contact is
`security@connectrpc.com`. The release is pre-1.0 and was current on the review
date, so exact API and graph review is required again before an upgrade.

Buf v1.72.0 resolves to lightweight tag commit
`7d6f05675219fa077f776e9f05b7c7d1a9882e0c`. The locally exercised pinned
Darwin arm64 executable is SHA-256
`5176f23a6118b9978de1340c3e3301a4ed0d48e16a669510be44b4c355170d57`;
that local hash is tool evidence, not a supported-target release artifact.

The new lockfile graph also contains `smoothutf8` 0.2.3 (Apache-2.0) and
`prettyplease` 0.2.37, `serde_json` 1.0.145, and `tempfile` 3.27.0
(MIT OR Apache-2.0). Exact registry checksums remain recorded by `Cargo.lock`.
The agent packages require no new license-policy exception. The inherited Iroh
graph carries the five stakeholder-approved, exact-coordinate CDLA/Unlicense
exceptions recorded by Decision 0028; they remain scoped to those packages and
must not be reclassified as agent dependency admission.

The checked-in descriptor set is SHA-256
`ef08aecf732adbd30d5f52361e31ba3c57659135e4d2423c3d3479cfdef3d375`.
CI reproduces it from the local schema and fails on a difference.

## Evidence and claim boundary

The focused integration test starts the real selected node, its mission-bound
redb authority, and a loopback ConnectRPC server. A generated Rust client proves
that missing credentials fail for Connect unary and streaming calls. The
authenticated flow uses the recommended shared HTTP/2 transport and actual
gRPC protocol to read status, create a durable subscription and offline Event,
poll and acknowledge it, and redeliver an unacknowledged streamed Event at
attempt two while another unary call shares the connection. This is
same-implementation loopback evidence, not independent gRPC interoperability
or physical deployment acceptance.

The developer sample remains below the requirements' approximate 50-line
target, but author-counting and an independent developer usability exercise are
not complete. The alpha service is not a production authorization boundary:
TCP is plaintext, possession of the token confers application authority, token
reload/rotation is absent, and protected operational mission provisioning is
not shipped.

## Consequences and open gates

- Existing Rust and C-language boundaries remain available; the local agent is
  an additional process boundary, not a replacement or a new mesh wire format.
- Kubernetes deployments may use the agent as a same-Pod sidecar with no RPC
  Service. Zarf and UDS packages can carry the schema and workload without BSR
  or registry egress at runtime.
- Kubernetes projected-secret symlinks do not satisfy the token loader. A
  same-UID init-copy into an owner-only regular file is required for this slice.
- Before production use: add protected provisioning, credential rotation and
  revocation, a stronger OS-identity or protected local transport boundary,
  pre-body authentication or equivalent resource isolation, supported-target
  packaging, SBOM/advisory review, independent client interoperability,
  operational observability, and deployment acceptance.
- State and Record RPCs remain blocked on live handle-backed application APIs,
  not on their already-present mesh reconciliation lanes.

## Maintenance review — serde_json 1.0.151 (2026-08-31)

The exact direct `serde_json` pin advances from 1.0.145 to 1.0.151. The locked
runtime graph replaces `ryu` on this path with `zmij` 1.0.23; both direct and
transitive versions remain exact in `Cargo.lock`. Upstream also raises
serde_json's compiler floor from Rust 1.61 to 1.71, below Aster's Rust 1.91
minimum, rejects malformed non-string enum object keys, and adds an unsafe raw
value constructor behind a feature Aster does not enable.

The provider's finite-float formatter changes from `ryu` to `zmij`. Aster's
checked-in ConnectRPC schema contains no `float` or `double` fields and the
resolved serde_json graph enables only the default and `std` features, not
`arbitrary_precision`, `preserve_order`, or `raw_value`. Consequently this
maintenance update does not change the selected Protobuf wire profile or any
currently exposed ConnectRPC JSON field representation. That boundary must be
reviewed again before adding floating-point fields or enabling another
serde_json feature.

This review changes no requirement evidence, production authorization, or
independent-interoperability claim. The locked workspace tests, generated-schema
checks, dependency policy, MSRV lane, and real ConnectRPC integration remain the
acceptance evidence.
