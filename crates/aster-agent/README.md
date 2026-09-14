## Checked Rust API examples

These examples target the loopback-only live Event/status API. Call the
async functions from a Tokio runtime. The client examples require the `client`
feature and an already running agent at `127.0.0.1:8181`; pass its provisioned
client token (without the `Bearer ` prefix). See the
[agent quickstart](../../docs/quickstart/connect-agent.md) for local setup.

### Connect client and borrowed response

`view()` borrows fields from the response buffer. Keep the response alive while
using them. Aster status has byte-valued `identity` and `mission_authority`
fields, not a `name` field.

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
