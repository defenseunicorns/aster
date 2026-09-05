#

# Customer-operable Event service design

**Status:** Approved in design review; awaiting written-spec review

**Date:** 2026-09-05

**Capability:** Customer-operable Event service

**Primary component:** `aster-agent`

## Summary

Harden the existing loopback ConnectRPC `aster-agent` into a customer-operable
Event-service runtime. The service remains a thin authenticated and bounded
adapter over the running node's `SelectedEventHandle`. It does not introduce a
second database, journal, reconciliation engine, transport selector, or mesh
wire format.

This work defines runtime behavior and the contract consumed by deployment and
provisioning owners. It does not produce packages, container images,
Kubernetes manifests, Zarf or UDS artifacts, or concrete TPM, HSM, Vault, or
SecretStore providers.

## Goals

1. Provide a strict, stable, versioned service configuration.
2. Expose useful liveness and readiness semantics without making network
   reachability a prerequisite for offline-first operation.
3. Preserve bounded, durable Event publish, query, poll, stream,
   acknowledgement, deletion, and gap-query behavior.
4. Document idempotency, retry, redelivery, and unknown-outcome handling.
5. Support graceful termination and deterministic crash recovery.
6. Return actionable, machine-readable, sanitized failures.
7. Supply a black-box acceptance suite that deployment owners can run against
   their artifacts.

## Non-goals

- State, Record, or Blob application RPCs.
- Dynamic routing or transport selection through the application API.
- A remotely exposed application listener.
- A second durable Event authority or service-owned journal.
- Systemd units, Linux packages, container images, Kubernetes manifests,
  Helm, Zarf, UDS, SBOMs, signatures, or upgrade packaging.
- Implementation of mission credential custody, TPM, HSM, Vault, or another
  protected secret backend.
- A production-release authorization claim.

## Existing baseline

The repository already provides:

- a loopback-only Connect, gRPC, and gRPC-Web server;
- bearer authentication for unary and streaming RPCs;
- an owner-only, no-final-symlink Unix token loader with zeroizing storage and
  constant-time comparison;
- live Event publication, query, durable subscription, poll, stream,
  acknowledgement, deletion, gap query, and status operations;
- idempotent operation keys for publication and subscription creation;
- at-least-once durable delivery and restart redelivery;
- request, decode-memory, response, deadline, connection, and HTTP/2 stream
  bounds; and
- a same-implementation real-node ConnectRPC integration test.

The missing customer-operability surface is stable configuration, explicit
health and lifecycle semantics, token reload, Unix termination handling,
crash-oriented process acceptance, a stable public error contract, and
independent client evidence.

## Approaches considered

### 1. Incrementally harden `aster-agent` — selected

Retain the current binary, protocol package, and `SelectedEventHandle` data
path. Extract configuration and lifecycle responsibilities into focused units,
then add health, shutdown, reload, failure-detail, and black-box acceptance
behavior.

This is the smallest change that addresses the capability without creating a
new authority or destabilizing the selected node.

### 2. Extract a generic daemon framework

Create a reusable daemon layer intended for future State, Record, and Blob
services. This could reduce later duplication but introduces abstractions with
no second live service consumer today. It is deferred until another selected
service needs the same boundary.

### 3. Build a replacement Event service

Create a new service process and migrate operations from `aster-agent`. This
duplicates already-working authentication, bounds, and Event adaptation while
increasing migration and recovery risk. It is rejected for the MVP.

## Architecture

The customer-operable runtime has five responsibilities:

### `AgentConfig`

Loads and strictly validates the versioned configuration. It owns no runtime
resources and has no network or state side effects.

### `LifecycleSupervisor`

Owns service state transitions and coordinates the health listener,
application listener, selected node, token reload, signal handling, draining,
and shutdown deadline.

### `EventService`

Implements the repository-owned `aster.application.v1alpha1` RPC surface. It
performs authentication, request validation, and response-bound enforcement,
then delegates to `SelectedEventHandle`.

### `ServiceStatus`

Stores the current lifecycle state and a bounded sanitized failure reason. It
is the sole input to the liveness and readiness handlers.

### `CredentialSource` boundary

Consumes client and mission credential references supplied through the
provisioning contract. The Event-service work implements secure consumption
and client-token reload, not external credential custody. The mission
credential configuration type is supplied by the provisioning workstream and
is not redefined here.

The business request path remains:

```text
client
  -> bearer authentication
  -> protocol and resource bounds
  -> EventService
  -> SelectedEventHandle
  -> the running node's sole durable Event authority
  -> bounded sanitized response
```

## Lifecycle model

The supervisor exposes these states:

| State | Liveness | Readiness | Business RPC behavior |
|---|---:|---:|---|
| `Starting` | healthy after health-listener bind | not ready | unavailable |
| `Ready` | healthy | ready | accepted subject to auth and bounds |
| `Draining` | healthy until process exit | not ready | new work rejected; accepted in-flight work receives bounded grace |
| `Stopped` | endpoint absent | endpoint absent | endpoint absent |
| `Failed` | unhealthy until process exit | not ready | unavailable |

Readiness means the local durable Event authority and application listener can
accept operations. It does not require a configured peer, carrier
connectivity, recent contact, an empty outbound queue, or full mesh
convergence. Offline-first publication is therefore ready behavior.

The supervisor enters `Ready` only after configuration and credential
references validate, the state opens exclusively, the selected node returns a
live Event handle, and the application listener is serving.

## Health contract

The service exposes a separate loopback-only HTTP health listener. The
application listener defaults to `127.0.0.1:8181`; the health listener defaults
to `127.0.0.1:8182`:

- `GET /livez` returns `200` in `Starting`, `Ready`, and `Draining`, and `503`
  in `Failed`.
- `GET /readyz` returns `200` only in `Ready` and `503` otherwise.
- Successful and unsuccessful responses have an empty body and do not include
  node, mission, peer, carrier, path, queue, or failure details.
- Unsupported paths return `404`; unsupported methods return `405`.
- Health requests accept no body. Header, connection, and request-deadline
  limits are compiled, documented, and covered by black-box tests; the version
  one config cannot relax them.
- The health listener refuses non-loopback addresses.

The endpoints are intentionally unauthenticated because they expose only
lifecycle status and must support service-manager probes. Detailed operational
state remains available only through authenticated `GetStatus`.

## Stable configuration

### Format and invocation

The supported profile uses strict JSON and starts with:

```text
aster-agent --config /absolute/path/to/agent.json
```

JSON reuses the crate's admitted `serde_json` dependency. The document carries
`schema_version: 1`. Unknown fields, duplicate fields, missing required fields,
ambiguous alternatives, and unsupported versions are errors.

Existing individual CLI flags remain an alpha compatibility surface during
migration. `--config` cannot be combined with those flags. The supported
profile also provides `--check-config`, which performs syntax, semantic,
cross-field, path, permission, and credential-reference validation without
opening state or binding network sockets.

### Configuration domains

The version-one document contains these domains:

- `state`: one absolute lexical state-directory path;
- `application`: loopback application-listener address;
- `health`: loopback health-listener address;
- `mesh`: mesh bind address, bounded synchronization interval, exact manually
  admitted peer records, and at most one customer-controlled pinned relay;
- `credentials`: an owner-only client-token file reference plus the
  provisioning workstream's versioned mission credential reference; and
- `limits`: optional values that may tighten, but never raise, compiled safety
  ceilings and the bounded shutdown grace period.

The optional relay record contains one HTTPS relay URL, an explicit trust mode
(`webpki` or bounded DER-root file references), and one route policy
(`direct_preferred` or `relay_only`). It maps to the selected node's existing
`PinnedRelay` and `SelectedForwardingConfig` boundary. Relay configuration is
a carrier locator and never supplies mission identity or authorization. The
same exact carrier and mission authentication applies after every direct or
relay contact. Version one accepts no more than 256 exact peer records, one
relay URL of at most 2 KiB, eight DER roots of at most 64 KiB each, and 256 KiB
of DER roots in total.

The supported Event profile does not include State or Record interests,
automatic LAN discovery, public/default relay selection, or
application-visible transport configuration. Existing feature-gated
evaluation flags remain outside the supported configuration schema.

All syntax and cross-field validation completes before state mutation or mesh
network creation. Config diagnostics identify the public field and rule but do
not echo field values, credential paths, peer coordinates, or secret material.

### Reload

Runtime configuration is immutable in version one and changes through a
controlled restart. `SIGHUP` reloads only the client bearer token:

1. Load the same configured reference without following a final symlink.
2. Verify regular-file type, effective-user ownership, permissions, size, and
   URL-safe token syntax.
3. Construct the new zeroizing authorization value completely.
4. Atomically replace the active token.
5. Immediately reject the old token.

A failed reload retains the active token, keeps readiness unchanged, and emits
one sanitized operator error. Mission rotation follows the provisioning and
mission-control contracts and is not implemented as config reload.

## Authentication and credential handling

- Every Event RPC, stream establishment, and detailed status RPC requires the
  exact bearer token.
- Tokens contain 32 through 256 URL-safe ASCII bytes and remain in shared
  zeroizing memory.
- Authentication comparison remains constant time for equal-length values.
- Unix token loading requires an effective-user-owned regular file with no
  group or other permissions and refuses a final symlink.
- Credentials are never accepted inline through JSON or CLI arguments.
- Health responses are the only unauthenticated surface and reveal only an
  HTTP status code.
- Plaintext application and health listeners remain loopback-only. Remote
  exposure is unsupported.

## Event operation semantics

### Publish

`PublishEvent` succeeds locally without peers or connectivity and returns only
after durable acceptance. Its `operation_key` names the application effect,
not a network attempt.

- The same key and byte-equivalent request return the original durable result.
- The same key with different content fails closed.
- When the caller cannot determine whether a request completed, it repeats the
  original request with the same key.

### Query

`QueryEvents` returns one acceptance-marker-ordered bounded page. The response
retains `scanned_through` and `has_more`; callers continue from the returned
marker rather than increasing a request beyond configured limits.

### Durable subscriptions

- `CreateEventSubscription` is idempotent by operation key and creates an
  immutable durable selector.
- `PollEvents` and `StreamEvents` share the same durable delivery ledger.
- Delivery is at least once until `AcknowledgeEvent` succeeds.
- Stream cancellation, disconnect, deadline expiry, process failure, or client
  failure before acknowledgement leaves the delivery eligible for redelivery
  with a higher attempt count.
- Applications commit their own effect before acknowledging the Event.
- `AcknowledgeEvent` is idempotent and reports whether the delivery was already
  acknowledged.
- `DeleteEventSubscription` is idempotent and deletes the selector and its
  delivery ledger. Recreating a selector is a new subscription contract.
- `StreamEvents` is bounded polling convenience and does not imply
  acknowledgement or exactly-once processing.

### Gap queries and status

`QueryEventGaps` remains bounded by publisher, topic, scope, sequence marker,
and scan limit. `GetStatus` remains an authenticated bounded snapshot; it does
not change readiness semantics or expose transport control.

## Resource and backpressure contract

The existing server bounds become documented supported-profile hard ceilings:

| Resource | Hard ceiling or range |
|---|---:|
| Encoded request body and protobuf message | 1 MiB |
| Protobuf decode element memory | 4 MiB |
| Encoded protobuf response | 2 MiB |
| RPC deadline | 10 ms through 30 seconds |
| Default RPC deadline | 10 seconds |
| Concurrent HTTP/2 streams per connection | 32 |
| Streaming poll backoff | 100 ms through 60 seconds |

Page, scan, delivery, connection, and total in-flight operation counts remain
bounded. Configured values may only tighten these ceilings. Limit validation
occurs before actor enqueue where possible. A slow stream performs sequential
bounded polls and never creates an unbounded server-side delivery queue.

Saturation or a response that cannot fit the encoded-response ceiling returns
`ResourceExhausted`. Draining or a temporarily closed local authority returns
`Unavailable`. Clients do not bypass bounds by retrying with larger values.

## Public error contract

RPC failures retain standard ConnectRPC codes and add one bounded public error
detail containing:

- a stable `reason` enum;
- a fixed public `operation` name;
- a `retryable` boolean; and
- an optional bounded retry delay where the server can safely recommend one.

The reason vocabulary distinguishes malformed input, unsupported value,
operation-key conflict, missing durable object, failed precondition, deadline,
resource exhaustion, draining, state unavailability, and sanitized internal
failure. Authentication failures use one indistinguishable public reason.

Messages and details never contain credentials, filesystem paths, Event
payloads, logical keys, topic or scope values, peer or carrier addresses,
cryptographic material, internal type names, or raw lower-level error chains.
Unknown internal failures become a fixed `Internal` result.

Retry guidance follows these rules:

- unknown publish outcome: retry the identical request with the same operation
  key;
- resource exhaustion: retry only after backoff or with a smaller valid page;
- draining or temporary state unavailability: retry after readiness returns;
- unauthenticated: refresh credentials before retrying; and
- malformed input, unsupported value, operation-key conflict, and failed
  precondition: do not automatically retry.

## Logging contract

Each request receives a bounded correlation identifier. Structured operator
logs may contain timestamp, lifecycle state, public operation, public reason,
retryability, response code, and a bounded latency bucket. They do not contain
request bodies, Event content, protected metadata, authorization headers,
credential references, state paths, peer coordinates, or raw internal errors.

Startup, readiness transition, token reload result, drain start, shutdown
result, and fatal state transition each produce one structured lifecycle
record. Repeated client failures are rate-limited or aggregated.

## Graceful shutdown and crash recovery

`SIGINT` and `SIGTERM` initiate the same bounded shutdown sequence:

1. Atomically enter `Draining` and make readiness false.
2. Reject new business operations with sanitized `Unavailable`.
3. Notify active streams and stop scheduling new polls.
4. Allow already accepted unary work to complete within the configured grace
   period.
5. Shut down the selected node so its sole durable authority closes cleanly.
6. Stop the health listener and exit successfully.

A second termination signal or expiration of the shutdown deadline forces
termination with a distinct non-success exit code.

Crash recovery adds no journal. On restart, the selected node reopens the
existing durable authority. Durably accepted publications remain queryable;
unacknowledged deliveries are eligible for redelivery; acknowledged deliveries
remain complete; and uncertain publish outcomes are resolved by operation-key
retry. Unreadable, incompatible, corrupt, or multiply owned state fails closed
and never reaches `Ready`.

## Verification design

### Unit tests

- strict JSON version, unknown-field, duplicate-field, cross-field, and bounds
  validation;
- validation ordering before state and network effects;
- lifecycle state transitions and health status mapping;
- token reload success, old-token rejection, failed-reload retention, and
  zeroizing ownership;
- public error-code, reason, retryability, and sanitization mapping; and
- shutdown-deadline and second-signal decisions.

### In-process integration tests

- authenticated and unauthenticated unary and streaming calls;
- health behavior throughout startup, ready, drain, and failure states;
- request, response, deadline, page, connection, concurrency, and streaming
  backpressure;
- offline durable publication and idempotent retry; and
- poll/stream parity and explicit acknowledgement behavior.

### Black-box process acceptance

- start from a valid config and observe readiness;
- reject invalid config without state mutation or network bind;
- receive a publish receipt, force-kill the process, restart, and recover the
  exact publication;
- force-kill after delivery but before acknowledgement, restart, and observe a
  higher delivery attempt;
- acknowledge, restart, and prove the delivery does not reappear;
- terminate with `SIGTERM` during bounded unary and streaming activity and
  prove deterministic draining;
- rotate the client token with `SIGHUP` and prove atomic authorization change;
- inject canary secrets, paths, payloads, topics, scopes, and peer coordinates
  and prove they never appear in public errors or logs; and
- use at least one generated non-Rust client for authenticated unary and
  server-streaming interoperability.

The suite is deterministic, time-bounded, and runnable against an arbitrary
packaged `aster-agent` binary. The deployment owner runs this same suite across
its systemd, Kubernetes, amd64, and arm64 matrices.

### Repository verification

The implementation runs focused agent tests throughout development, the
requirements traceability checker whenever evidence mapping changes, and the
repository's pinned `mise run check` gate before handoff. Parser changes also
receive the repository-required hostile-input or fuzz-smoke coverage.

## Documentation deliverables

The Event-service workstream owns:

- a versioned JSON configuration reference and supported example;
- lifecycle, health, signal, shutdown, and exit-code documentation;
- publish idempotency and unknown-outcome retry guidance;
- polling, streaming, acknowledgement, deletion, and redelivery semantics;
- the public error reason and retryability catalog;
- the black-box acceptance-suite contract; and
- a clear supported/unsupported boundary.

## Cross-workstream handoffs

### Deployment artifacts

The deployment owner consumes the binary contract: config path, credential
references, loopback listeners, health semantics, signals, exit codes,
state-directory ownership, and the black-box acceptance suite. That owner
produces and qualifies service-manager units, images, packages, manifests,
multi-architecture builds, SBOMs, signatures, and upgrade/rollback assets.

### Provisioning and secret custody

The provisioning owner supplies the versioned mission credential-reference
type and concrete protected providers. The Event service consumes that type,
validates the reference before state/network effects, and reports only
sanitized provider failures. It does not implement or claim external custody.
The current unprotected-reference adapter may remain available only for
development and migration. Customer-readiness acceptance requires the
provisioning owner's protected provider and does not silently promote that
adapter into the supported customer profile.

## Traceability and claim boundary

The implementation is expected to strengthen the mechanism and current-code
evidence for `DM-7-09`, `DM-7-10`, `DM-7-11`, `DM-7-14`, `DM-7-15`,
`DM-7-16`, `DM-7-17`, and `DM-7-18`. This design document alone changes no
requirement status and is not acceptance evidence.

Completion of this work establishes a customer-operable Event-service runtime
within its declared loopback, Event-only boundary. Production packaging,
protected provisioning, representative deployment acceptance, physical and
mixed-implementation network evidence, and release authorization remain
separate gates.
