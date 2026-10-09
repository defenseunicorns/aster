## Checked Rust API examples

The Debian/package binary statically selects the systemd credential provider
and configuration schema v1. The separate Docker binary is built by
`aster-compose-credentials`, is also named `aster-agent`, and statically selects
the dedicated Compose provider with schema v2. There is no runtime provider
selector. See the [schema v2 reference](../../docs/reference/aster-agent-config-v2.md)
and [manual Compose operator procedure](../../docs/release/docker-compose.md).

These examples target the loopback-only live Event/status API. Call the
async functions from a Tokio runtime. The client examples require the `client`
feature and an already running agent at `127.0.0.1:8181`; pass its provisioned
client token (without the `Bearer ` prefix). See the
[agent quickstart](../../docs/quickstart/connect-agent.md) for local setup.

### Connect client and borrowed response

`view()` borrows fields from the response buffer. Keep the response alive while
using them. Aster status has byte-valued `identity` and `mission_authority`
fields, not a `name` field. Compose startup also returns the public
`credential_generation` as exactly 32 bytes; systemd and legacy startup return
that field empty. The generation is observability metadata only and is not an
authorization value, state key, mesh value, or provisioning-bundle input.

```no_run
# #[cfg(feature = "client")]
async fn connect_status(token: &str) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    use aster_agent::proto::aster::application::v1alpha1 as api;
    use connectrpc::{Protocol, client::{ClientConfig, HttpClient}};

    let config = ClientConfig::new("http://127.0.0.1:8181".parse()?)
        .with_protocol(Protocol::Connect)
        .with_default_header("authorization", format!("Bearer {token}"));
    let client = api::AsterApplicationServiceClient::new(HttpClient::plaintext(), config);
    let response = client.get_status(api::GetStatusRequest::default()).await?;
    let view = response.view();
    let identity: &[u8] = view.identity;
    let authority: &[u8] = view.mission_authority;
    assert_eq!(identity.len(), 32);
    assert_eq!(authority.len(), 32);
    Ok(())
}
```

### gRPC client and owned response

gRPC uses an HTTP/2 connection. `into_owned()` consumes the response and returns
the generated message with owned fields, which can outlive the client.

```no_run
# #[cfg(feature = "client")]
async fn grpc_status(
    token: &str,
) -> Result<aster_agent::proto::aster::application::v1alpha1::GetStatusResponse,
            Box<dyn std::error::Error + Send + Sync>> {
    use aster_agent::proto::aster::application::v1alpha1 as api;
    use connectrpc::{Protocol, client::{ClientConfig, Http2Connection}};

    let uri = "http://127.0.0.1:8181".parse()?;
    let connection = Http2Connection::connect_plaintext(uri).await?.shared(32);
    let config = ClientConfig::new("http://127.0.0.1:8181".parse()?)
        .with_protocol(Protocol::Grpc)
        .with_default_header("authorization", format!("Bearer {token}"));
    let client = api::AsterApplicationServiceClient::new(connection, config);
    let response = client.get_status(api::GetStatusRequest::default()).await?;
    let owned: api::GetStatusResponse = response.into_owned();
    Ok(owned)
}
```

### Pipelined durable Event publication

Native Connect and gRPC clients over HTTP/2 can keep independent ordinary
Event publications in flight with [`sdk::PipelinedEventPublisher`]. Each
ordered published outcome is returned only after the running selected node's
local durable authority has committed that Event and its operation-key mapping.
A sanitized application failure is returned in order without claiming an Event
commit. Neither outcome waits for mesh delivery: synchronization starts from a
successfully published durable local object independently.

Persist every operation key before calling the publisher. If a bounded stream
session rotates or disconnects, the helper resends only sent requests without
an observed response and keeps their original keys. The durable operation
ledger resolves a commit whose response was lost. The retry budget passed to
`new` bounds consecutive transport disconnects; healthy session rotation does
not consume it.

```no_run
# #[cfg(feature = "client")]
async fn publish_telemetry(
    token: &str,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    use aster_agent::{
        proto::aster::application::v1alpha1 as api,
        sdk::PipelinedEventPublisher,
    };
    use connectrpc::{Protocol, client::{ClientConfig, Http2Connection}};

    let uri = "http://127.0.0.1:8181".parse()?;
    let connection = Http2Connection::connect_plaintext(uri).await?.shared(32);
    let config = ClientConfig::new("http://127.0.0.1:8181".parse()?)
        .with_protocol(Protocol::Connect)
        .with_default_header("authorization", format!("Bearer {token}"));
    let client = api::AsterApplicationServiceClient::new(connection, config);
    let requests = (0_u8..4)
        .map(|sample| api::PublishEventRequest {
            operation_key: format!("sensor-a/{sample}").into_bytes(),
            topic: "telemetry.temperature".to_owned(),
            scope: "mission/team/alpha".to_owned(),
            priority: api::Priority::Routine.into(),
            logical_key: b"sensor-a".to_vec(),
            payload: vec![sample],
            ..Default::default()
        })
        .collect();
    let outcomes = PipelinedEventPublisher::new(client, 3)
        .publish_all(requests)
        .await?;
    assert_eq!(outcomes.len(), 4);
    Ok(())
}
```

The helper's active window and session-rotation interval are bounded reference
implementation choices, not protocol rate or batch limits. The stream keeps
ordinary publications independent; it is not the atomic cryptographic batch
API and does not accept numbered publication. gRPC-Web cannot stream request
bodies, so browser clients must use a bounded application-selected window of
concurrent unary `PublishEvent` calls with the same operation-key retry rule.

### Crash-safe numbered publication

With the `client` feature, [`sdk::PublicationJournal`] and
[`sdk::NumberedEventSdk`] implement the experimental numbered-publication
profile. Journal creation is explicit. The journal contains plaintext publication
intents and payloads: keep it in a protected directory. On Unix, creation uses
mode `0600`, and opening rejects symlinks, non-regular files, files owned by
another user, or group/other permissions. Existing journals with broader
permissions must be restricted by their owner before opening. On other
platforms, protect access through the directory and file ACLs.

Opening a missing, corrupt,
already-open, or differently configured journal fails closed. Call `recover`
once per SDK process incarnation before assigning work; transport reconnects
on the same SDK do not roll the publication session.

The SDK writes each complete intent with immediate durability before sending
it and writes each returned or recovered result before exposing it. `recover()`
returns a sequence-ordered `RecoveryReport` only after the server completes
recovery. `Pending` operations can be sent with `publish_journaled` or cancelled
with `abandon`; `Committed(result)` operations need idempotent application
followed by `acknowledge`; `Retired` operations need no action. Consumed rows
and their payloads are removed from the journal. A `publish()` error exposes
`assigned_sequence()` when the intent was durably journaled, so callers can
retain that sequence for recovery after an uncertain RPC outcome. See the
[agent quickstart](../../docs/quickstart/connect-agent.md#use-crash-safe-numbered-publication)
for an end-to-end example and the exact Increment 1 boundary.

### Serving a live node for development or migration

`BoundAgent` is a development/migration compatibility entry point, not the
customer runtime. Customer binaries compose `runtime::run_customer_agent` with
one protected `ProvisioningSecretLoader`; follow the
[customer runtime boundary](../../docs/quickstart/connect-agent.md#choose-the-correct-runtime-boundary)
for configuration, provisioning, health, token reload, and supervision.

For an existing development node, use `BoundAgent` (the default `server`
feature) with a running node's `selected_events()` handle, a provisioned `ClientToken`, and a shutdown watch
channel. Its serving path registers the internal service and applies bearer
authentication, message limits, deadlines, and connection bounds. Send `true`
on the watch channel to close streams and drain the server; keep the node alive
until serving finishes, then shut down the node.

```no_run
# #[cfg(feature = "server")]
async fn serve_agent(
    events: aster_node::application::SelectedEventHandle,
    token: aster_agent::ClientToken,
    shutdown: tokio::sync::watch::Receiver<bool>,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let agent = aster_agent::BoundAgent::bind("127.0.0.1:8181".parse()?).await?;
    agent.serve(events, token, shutdown).await
}
```

### Verification and generated-documentation boundary

This README is included in the crate's rustdoc, so these `no_run` examples are
compiled by `cargo test --locked -p aster-agent --all-features --doc`. They do
not start a listener during documentation tests. Normal CI runs them through
`mise run check`'s workspace tests with all features enabled. The existing
`tests/real_node_connect.rs` test exercises the listener with a real selected
node, authenticated gRPC publication/subscription/poll/ack and stream redelivery,
missing-token unary/stream rejection, and shutdown. The `event_service` tests
cover authenticated Connect/gRPC/gRPC-Web public error decoding. The real-node
test also checks successful
authenticated Connect status, borrowed byte fields, and preservation of those
fields after converting the response into an owned message.

All six generated examples remain ignored intentionally:

| Generated example | Aster coverage and reason to retain `ignore` |
| --- | --- |
| Service registration | The real-node test reaches the internal `event_service::AsterConnectService::router()` registration. The generated `MyServiceImpl` is an undefined placeholder; registration alone omits the agent's authentication and bounds. |
| Server construction | The maintained development/migration `BoundAgent` example compiles and the real-node test runs it. The generated monomorphic `AsterApplicationServiceServer::new(MyImpl)` uses an undefined implementation and is an alternative dispatcher, not the selected agent serving path. |
| gRPC client setup | The maintained example compiles and the real-node test uses authenticated HTTP/2 gRPC. The generated snippet omits a concrete request, imports, async context, and Aster's bearer token. |
| Connect client setup | The maintained example compiles and the real-node test checks authenticated Connect. The generated snippet omits a concrete request, imports, async context, and Aster's bearer token. |
| Borrowing a response | The maintained example and real-node assertions use actual byte fields. The generated `resp.view().name` does not exist on `GetStatusResponse`. |
| Converting into an owned value | The maintained example compiles and the real-node test verifies owned fields. The generated fragment depends on undefined `client` and `request` variables and an async context. |

`build.rs` generates these snippets from the checked-in descriptor set via the
locked `connectrpc-build`/`connectrpc-codegen` 0.9.0 and buffa 0.9.1 dependencies.
The six snippets are templates in `connectrpc-codegen`'s `src/codegen.rs`, not
examples from Aster's `.proto` comments. That version's generator options have
no hook for replacing these service/client example templates. Maintained
crate documentation is therefore the correction boundary; neither generated
build output nor the external generator is patched. Reassess the templates on
a generator upgrade. This is documentation/test maintenance, with no wire,
supported-profile, requirement-credit, or reconciliation-performance change.
