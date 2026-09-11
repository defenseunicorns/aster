# Local ConnectRPC Event agent quickstart

> ****

`aster-agent` is an Event-only, out-of-process application boundary over the
running selected Aster node. It serves Connect, gRPC, and gRPC-Web on
plaintext loopback TCP and exposes high-level status, publish, query, durable
subscription, poll, stream, acknowledgement, deletion, and gap operations. It
does not expose keys, sealed content, carriers, transport choice,
reconciliation messages, or mission provisioning over RPC.

The customer profile is single-scope, accepts exact manual peers, and permits
at most one customer-controlled pinned connectivity relay. It does not include
State, Record, Blob, automatic discovery, bridges, or multi-scope forwarding.

## Choose the correct runtime boundary

The repository's stock binary has two deliberately different modes:

- strict `--check-config` validates the customer JSON and credential files;
- the legacy individual flags run a development-only unprotected reference
  loader for local integration.

The stock binary does **not** turn that legacy loader into a customer provider.
A customer binary must compose the public `run_customer_agent` entry point
with exactly one protected `ProvisioningSecretLoader`. The deployment and
provisioning owners supply and qualify that binary and its secret store.

The repository acceptance fixture is an unprotected test-only provider. It is
never a customer binary or production provisioning option.

## Validate customer configuration

Create the paths and JSON described in the
[version-one configuration reference](../reference/aster-agent-config-v1.md),
then run:

```sh
ASTER_AGENT_CONFIG=/absolute/path/to/agent.json
cargo run --locked -p aster-agent -- \
  --check-config "$ASTER_AGENT_CONFIG"
```

Exit `0` is silent success. A nonzero result contains only a fixed sanitized
rule category. Validation reads the configuration, optional relay roots, and
both credential files, but does not create/open state, bind sockets, or invoke
a protected provider.

For the provider-composed artifact, the supported start interface is:

```sh
CUSTOMER_ASTER_AGENT=/absolute/path/to/provider-composed-aster-agent
ASTER_AGENT_CONFIG=/absolute/path/to/agent.json
"$CUSTOMER_ASTER_AGENT" --config "$ASTER_AGENT_CONFIG" &
ASTER_AGENT_PID=$!
```

Keep the PID in the service manager in a real deployment. The selected
provider is checked during startup; the service does not become ready merely
because JSON validation succeeded.

## Observe liveness and readiness

The separate health listener is unauthenticated and returns an empty body. For
a configuration using `127.0.0.1:8182`:

```sh
curl --fail --silent --output /dev/null \
  --write-out 'livez=%{http_code}\n' \
  http://127.0.0.1:8182/livez
curl --fail --silent --output /dev/null \
  --write-out 'readyz=%{http_code}\n' \
  http://127.0.0.1:8182/readyz
```

`/livez` is `200` while Starting, Ready, or Draining and `503` in Failed.
`/readyz` is `200` only in Ready and `503` while Starting, Draining, or Failed.
After Stopped, the listener is absent. Readiness means the local durable Event
authority and application listener accept work; it does not require a peer,
carrier connectivity, a recent contact, an empty queue, or convergence.
Offline-first publication is ready behavior.

`GetStatus` also returns the configured and effective emission mode, aggregate
logical store use/limits, durable publish-operation rows/bytes and headroom,
and pending-delivery pressure. For this profile, the operation warning begins
at 512 rows and the workload stops at 1,024 rows; pending-delivery workload
saturates at 256. These profile boundaries are lower than the implementation
hard ceilings and are intended to trigger operator action before refusal.

Only `GET` with no body is accepted. Unknown paths return `404`, other methods
return `405`, and responses contain no node, mission, peer, path, queue, or
failure detail. Use authenticated `GetStatus` when an application needs its
bounded synchronization snapshot.

## Select normal or receive-only operation

Set required `mesh.emission_policy` to `normal` or `receive_only` before
startup. Changing it requires process restart. Receive-only keeps local health
and authenticated application APIs ready and continues to accept authenticated
inbound mesh work. It does not initiate contacts or disclose local Event or
control inventory/objects.

Receive-only is a zero-transfer mode for locally held application/control
objects, not physical radio silence: the carrier may still receive traffic and
the protocol may emit mandatory acknowledgements or other transport responses.
Use deployment/network controls when a customer requires actual radio silence.

## Exercise the repository development path

For local development only, prepare disposable owner-only files:

```sh
mise install
ASTER_AGENT_ROOT="$(mktemp -d)"
install -m 600 bindings/testdata/non-production-provisioning.bundle \
  "$ASTER_AGENT_ROOT/mission.unprotected-reference.bundle"
openssl rand -hex 32 > "$ASTER_AGENT_ROOT/client.token"
chmod 600 "$ASTER_AGENT_ROOT/client.token"
```

Start the legacy development adapter in one terminal:

```sh
cargo run --locked -p aster-agent -- \
  --state "$ASTER_AGENT_ROOT/state" \
  --mesh-bind 127.0.0.1:0 \
  --listen 127.0.0.1:8181 \
  --mission-bundle-unprotected-reference \
    "$ASTER_AGENT_ROOT/mission.unprotected-reference.bundle" \
  --client-token-file "$ASTER_AGENT_ROOT/client.token"
```

In another terminal, run the repository's small Connect sample:

```sh
./examples/connect_agent.sh "$ASTER_AGENT_ROOT/client.token"
```

The sample gets status, creates a durable subscription, publishes while no
peer is configured, polls, and acknowledges the Event. Protobuf JSON encodes
`bytes` fields as base64. This path is useful for API integration only; it does
not exercise customer configuration, health, token reload, protected
provisioning, or the customer supervisor.

## Authenticate application calls

Generate a normal client from the local authoritative schema at
[`proto/aster/application/v1alpha1/aster.proto`](../../proto/aster/application/v1alpha1/aster.proto).
The module needs no Buf Schema Registry. Point it at the configured application
listener and attach exactly one header to every unary call and stream:

```text
Authorization: Bearer <contents of client_token_file>
```

The server authenticates headers before reading or decoding a request body.
Missing, invalid, or duplicate authorization values all return the same public
authentication failure. Request/message, decode-memory, response, deadline,
header, connection, HTTP/2 stream, and in-flight operation bounds remain in
force; see the [configuration reference](../reference/aster-agent-config-v1.md).

## Publish and retry safely

`PublishEvent` returns only after the local durable authority accepts the
Event. Its `operation_key` identifies the application effect, not a single RPC
attempt:

1. Generate and persist one key before sending the application effect.
2. If the response is known successful, retain its durable receipt.
3. If disconnect, deadline, process failure, or another transport outcome
   leaves success unknown, resend the **identical** request with the **same**
   operation key.
4. Never create a new key merely because the result was unknown.

The same key and byte-equivalent request returns the original effect; it does
not publish a duplicate. Durable receipt fields stay the same, while the
per-call `inserted` flag changes from `true` on first acceptance to `false` on
retry. Do not compare the complete responses as byte-identical. Reusing the
key with different content fails closed
with `Aborted` and `PUBLIC_ERROR_REASON_OPERATION_KEY_CONFLICT`. This resolves
uncertain outcomes; it does not make two different application effects
equivalent.

`QueryEvents` returns an acceptance-marker-ordered page. Continue from
`scanned_through` while `has_more` is true rather than raising the request
above its bound.

## Commit before acknowledging

`CreateEventSubscription` creates or replays an immutable durable selector by
operation key. `PollEvents` and `StreamEvents` use the same durable ledger and
deliver at least once until acknowledgement succeeds:

1. Receive an Event and its delivery attempt.
2. Apply and durably commit the application's idempotent effect.
3. Call `AcknowledgeEvent` with the subscription and Event IDs.
4. Treat a successful repeat acknowledgement as completion as well.

If the client disconnects, a deadline expires, the process fails, or the
stream is cancelled before acknowledgement, the Event remains eligible for
redelivery. After restart, an unacknowledged Event is returned with a higher
attempt count. The attempt count is observability, not a deduplication key;
deduplicate application work by stable Event identity. An acknowledged Event
remains complete across restart.

`StreamEvents` is sequential bounded polling convenience. It never
acknowledges implicitly and does not provide exactly-once application effects.
`DeleteEventSubscription` idempotently removes the selector and its delivery
ledger; recreating a selector establishes a new subscription contract.

### Generated-Go client replacement example

The [two-process Go example](../../conformance/agent-go/cmd/agent-smoke/README.md)
publishes and retries one fixed operation key, then exits after validating the
exact attempt-one delivery without ACK. A new client process attaches to the
same live agent and durable subscription, validates exact attempt-two
redelivery, and ACKs. Successful empty, caught-up polls then span at least
500 ms before a final exact retained-Event query. The window starts after the
first successful empty response and requires a successful final poll initiated
at or after its end; slow RPC responses cannot consume the observation window.

This is a bounded exclusive-consumer integration example, not agent-crash,
exactly-once application, physical-network, or production-provider evidence.
The existing process checker includes it without changing runtime or wire
semantics. Its fixture remains unprotected and test-only.

## Back off on resource pressure

`ResourceExhausted` with public reason
`PUBLIC_ERROR_REASON_RESOURCE_EXHAUSTION` is retryable, but
immediate repetition cannot bypass a configured capacity or response bound.
Use the optional `retry_delay_ms` when present; otherwise apply bounded
jittered application backoff. For query, poll, or gap pages, reduce the valid
page/scan request. For durable-storage pressure, wait for operator-controlled
retirement/capacity recovery rather than silently increasing the configured
limit or changing the operation key.

`ResourceExhausted` with
`PUBLIC_ERROR_REASON_OPERATION_CAPACITY_EXHAUSTED` is different: the durable
idempotency map reached its dedicated row or byte hard ceiling. It is
non-retryable and carries no retry delay. Stop new publication, preserve the
original operation key, and escalate to the operator; creating another key
only consumes more capacity and changes the application effect identity.

`Unavailable` with `PUBLIC_ERROR_REASON_DRAINING` or
`PUBLIC_ERROR_REASON_STATE_UNAVAILABLE` is retryable only after `/readyz`
returns `200`. Authentication failures require credential refresh.
Malformed input, unsupported values, operation-key conflicts, missing durable
objects, and failed preconditions are not automatic-retry conditions.

## Decode public error details

Application and admission failures constructed by Aster contain one protobuf
detail with type `aster.application.v1alpha1.PublicErrorDetail`. It carries a
stable `reason`, fixed `operation`, `retryable`, and optional
`retry_delay_ms`. Transport/protocol failures constructed by the Connect layer
may carry only their standard code, so the Connect/gRPC/gRPC-Web code remains
authoritative. The typed detail supplies safe handling without exposing
request values or internal chains.

| Current public reason | Usual Connect code | Retryable | Meaning/action |
|---|---|---:|---|
| `PUBLIC_ERROR_REASON_MALFORMED_INPUT` | `InvalidArgument` | no | Correct the request encoding or required identifier. |
| `PUBLIC_ERROR_REASON_UNSUPPORTED_VALUE` | `InvalidArgument` | no | Correct a bounded value such as stream backoff or page limit. |
| `PUBLIC_ERROR_REASON_OPERATION_KEY_CONFLICT` | `Aborted` | no | Do not reuse the operation key for different content. |
| `PUBLIC_ERROR_REASON_MISSING_DURABLE_OBJECT` | `NotFound` | no | The named subscription/Event is unavailable or retired. |
| `PUBLIC_ERROR_REASON_FAILED_PRECONDITION` | `PermissionDenied`, `Unavailable`, or `FailedPrecondition` | no | Resolve authorization, policy, or provisioning state before retrying. |
| `PUBLIC_ERROR_REASON_RESOURCE_EXHAUSTION` | `ResourceExhausted` | yes | Back off, reduce a valid page, or wait for capacity recovery. |
| `PUBLIC_ERROR_REASON_OPERATION_CAPACITY_EXHAUSTED` | `ResourceExhausted` | no | Stop new publication and escalate; do not replace the operation key. |
| `PUBLIC_ERROR_REASON_DRAINING` | `Unavailable` | yes | Wait for a Ready process. |
| `PUBLIC_ERROR_REASON_STATE_UNAVAILABLE` | `Unavailable` | yes | Wait for a Ready process. |
| `PUBLIC_ERROR_REASON_AUTHENTICATION_FAILED` | `Unauthenticated` | no | Refresh credentials; do not repeat the same failed authorization. |
| `PUBLIC_ERROR_REASON_INTERNAL` | `Internal` or `DataLoss` | no | Treat as a sanitized terminal request failure and investigate fixed operator telemetry. |

`PUBLIC_ERROR_REASON_UNSPECIFIED` is not intentionally emitted.
`PUBLIC_ERROR_REASON_DEADLINE` is present in the schema vocabulary, but the
current Aster mapping does not construct it; enforce deadline handling from the
standard Connect code. Production paths currently omit `retry_delay_ms`, so a
client must use its own bounded backoff when `retryable` is true and no delay
is supplied.

Framework decoding and protocol failures retain standard error codes with a
fixed sanitized message; raw decoder diagnostics are not part of the public
contract. Rejected requests retain only their protocol framing choice before
authentication failure encoding.

With the generated Go client, decode typed details rather than parsing the
human message:

```go
var connectErr *connect.Error
if errors.As(err, &connectErr) {
    for _, encoded := range connectErr.Details() {
        value, decodeErr := encoded.Value()
        if decodeErr != nil {
            continue
        }
        if detail, ok := value.(*applicationv1alpha1.PublicErrorDetail); ok {
            retryable := detail.GetRetryable()
            delayMS := detail.RetryDelayMs // nil means no server delay supplied
            _ = retryable
            _ = delayMS
        }
    }
}
```

Do not log request bodies, authorization headers, Event payloads, logical
keys, topics/scopes, credential references, state paths, peers, or raw
lower-level errors. Unknown internal failures are reduced to a fixed Internal
result.

## Reload and stop

Replace the configured token file atomically while preserving its owner-only
regular-file rules, then signal the process:

```sh
kill -HUP "$ASTER_AGENT_PID"
```

Only the bearer token reloads. A valid replacement becomes active atomically
and the old token is rejected; a failed reload retains the old token and Ready
state. Emission policy, mission reference, peers, relay, storage, and limits
require restart.

Start bounded draining with either signal:

```sh
kill -TERM "$ASTER_AGENT_PID"
# Or, for an interactive supervisor:
kill -INT "$ASTER_AGENT_PID"
wait "$ASTER_AGENT_PID"
```

The first signal makes readiness false, rejects new business work, stops new
stream polls, gives accepted unary work and selected-node shutdown the one
configured `shutdown_grace_ms` deadline, then stops health. Clean drain exits
`0`. Deadline expiry or a second termination signal forces exit `2`; terminal
runtime failure exits `1`. The compiled maximum and default grace are 30,000
ms. The selected-node acceptance passed with 10,000 ms and forced with 3,000
ms in that scenario; this is operational sizing evidence, not a universal
deployment recommendation.

After an unclean stop, restart against the same exclusively owned state.
Durably accepted Events remain queryable, unacknowledged deliveries remain
eligible for redelivery, and acknowledged deliveries remain complete. Corrupt,
incompatible, unreadable, or multiply owned state fails closed before Ready.

## Customer support boundary

Both listeners are plaintext loopback. Customer use requires a
deployment-owned dedicated network namespace containing only the agent and its
intended trusted application; bearer authentication remains mandatory inside
it. An unisolated loopback process is development-only. Do not expose either
listener through a Service, ingress, host port, or remote tunnel.

Protected provider delivery, namespace and service-manager artifacts,
packaging, amd64/arm64 qualification, representative deployment,
physical/mixed-network acceptance, security review, SBOM/signing, and release
authorization are still open and owned outside this Event-service increment.
The black-box checker in `tools/check-aster-agent-process.py` is the executable
contract those owners run against their artifacts; its repository fixture does
not satisfy those gates.

The checker includes a nonempty streaming phase: the generated client compares
every exposed Event field against the retained publication and verifies that
the delivery attempt increased. Its receipt contains only the match result,
delivery count, and attempt. Scanning that sanitized client receipt alone does
not establish wire-error redaction; the server wire regressions inspect raw
error bodies and trailers separately.
