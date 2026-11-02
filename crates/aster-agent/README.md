## Checked Rust API examples

<!-- ASTER-BLOB-CAPABILITY:BEGIN -->
```json
{
  "schema": 1,
  "surface": "agent_readme",
  "local_publish_waits_for_peer": false,
  "rust_agent_asterctl_publish_read": "implemented",
  "blob_status_scope": "receiver_local_durable_state",
  "blob_status_reports_remote_delivery_peer_or_convergence": false,
  "cli_download_resume": "post_merge"
}
```
<!-- ASTER-BLOB-CAPABILITY:RENDERED -->
Local Blob publication commits without waiting for a peer. Rust, the native-gRPC agent, and asterctl implement bounded Blob publication and authenticated reads. blob-status reports receiver-local durable state, not remote delivery, peer status, or convergence. CLI download resume is post-merge work; an interrupted download restarts at byte zero.
<!-- ASTER-BLOB-CAPABILITY:END -->

The Debian/package binary statically selects the systemd credential provider
and configuration schema v1. The separate Docker binary is built by
`aster-compose-credentials`, is also named `aster-agent`, and statically selects
the dedicated Compose provider with schema v2. There is no runtime provider
selector. See the [schema v2 reference](../../docs/reference/aster-agent-config-v2.md)
and [manual Compose operator procedure](../../docs/release/docker-compose.md).

These examples target the loopback-only live Event/Blob/status API. Call the
async functions from a Tokio runtime. The client examples require the `client`
feature and an already running agent at `127.0.0.1:8181`; pass its provisioned
client token (without the `Bearer ` prefix). See the
[agent quickstart](../../docs/quickstart/connect-agent.md) for local setup.

Blob API access is independent of network receive policy. Strict schema v1/v2
configuration defaults absent or empty `mesh.blob_interests` to receive none.
A nonempty list accepts at most 256 unique canonical exact `TOPIC@SCOPE`
selectors and requires explicit nonzero `storage.blob_depot.max_bytes`,
`max_chunks`, and `max_variants`; all of these fields are restart-only. Mission
route/content authorization remains authoritative, and authenticated peers can
observe exact configured topic/scope interest metadata under the current
policy. `receive_only` retains the selectors in configuration but performs
zero Blob network work. Receiving through the mesh does not create an
application subscription, and the agent does not expose the separate Rust Blob
subscription surface. Older agents reject the new fields, so rollback must
restore the older configuration shape as well as the executable.

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

### Publish and read Blobs with `asterctl`

The running agent exposes bounded `PublishBlob` and `ReadBlob` streams. The
ready-to-use client is `asterctl`, which uses native gRPC over HTTP/2 for these
two commands. The plaintext listener remains loopback-only, and every command
requires exactly one bearer-token source. Prefer a protected token file rather
than a literal token in shell history:

`PublishBlob` streams directly into the running node's durable upload
authority on platforms supported by the selected node and store. The agent
does not create a separate whole-upload plaintext staging file and therefore
has no Linux-only upload-staging gate. This differs from `asterctl blob-read`,
whose safe destination-file publication still requires Linux and a qualifying
filesystem.

The machine-checked capability block above is authoritative for publication,
status, and download behavior. Node-to-node profile-5 native-pack checkpoint
resume remains a separate protocol mechanism.

```sh
TOKEN_FILE=/run/aster/client.token

# Durable publication with an application-owned recovery key.
asterctl --token-file "$TOKEN_FILE" blob-publish \
  --file ./map.bin \
  --topic imagery.maps \
  --scope mission/team/alpha \
  --operation-key map-001 \
  --media-type application/octet-stream \
  --progress auto

# Finite publication with a generated recovery key and exact JSON TTL output.
asterctl --token-file "$TOKEN_FILE" --json blob-publish \
  --file ./overlay.bin \
  --topic imagery.maps \
  --scope mission/team/alpha \
  --operation-key auto \
  --ttl-ms 60000

# Inspect or wait for this exact publication in the local node's durable state.
asterctl --token-file "$TOKEN_FILE" blob-status \
  --publication-id "$PUBLICATION_ID" \
  --topic imagery.maps \
  --scope mission/team/alpha \
  --wait

# Read the returned ID to a new path; an existing path is never overwritten.
asterctl --token-file "$TOKEN_FILE" blob-read \
  --id "$BLOB_ID" \
  --topic imagery.maps \
  --scope mission/team/alpha \
  --output ./downloaded-map.bin
```

Before sending an `auto` publication, `asterctl` writes
`asterctl: operation-key=<32-lowercase-hex-digits>` to stderr. Save that exact
key. JSON output also includes it as `operation_key`. If the result is unknown,
retry the identical file bytes and publication options with
`--operation-key=<saved-key>`; do not generate a new key. If the earlier attempt
committed, the retry recovers it with `inserted: false`; if it did not, the
retry may insert the publication and return `inserted: true`.

At the RPC level, `PublishBlobAccepted.publication_id` is a stable nonzero
32-byte identity returned before data byte zero. Native clients should persist
it immediately, may inspect provisional durable progress with that ID, and
must reject a terminal receipt carrying a different ID. The CLI emits the same
identity in its single terminal result. Status transfer-byte counters are exact
length-prefixed `ASTRBS02` pack payload bytes rather than Blob-depot reservation
or filesystem byte counts.

Text output renders the original signed TTL as exactly `TTL: durable` or
`TTL: 60000 ms`. Finite JSON renders exactly `"ttlMs": "60000"`; durable JSON
omits `ttlMs`. These values are the original lifetime, not remaining time.

The CLI and wire fields use checked `u64` lengths. The semantic-v9/profile-5
stream admits at most 8 GiB per Blob and uses bounded 512-KiB application
frames. Node-to-node DATA carries one complete length-prefixed native
`ASTRBS02` pack record per message; checkpoint batches are at most 128 MiB.
The exact maxima are 1,048,576 plaintext segment bytes, 1,048,706 encoded
record bytes, 1,048,710 DATA-body bytes, and 134,217,728 checkpoint bytes.
Provisional uploads, pending native packs, and completed variants all use the
configured Blob depot limits; there is no independent stream pool.
Its two-minute authenticated-progress timeout is the shorter stall bound. The
sender derives the hard deadline from exact canonical wire bytes; because PLAN
does not disclose size, the receiver opens transport before authenticated OPEN
and derives its initial hard deadline from the full profile wire ceiling. Those
network bounds are independent of this agent's local RPC deadline.
Blob RPCs currently default to 15 minutes; other RPCs retain the 10-second
default, and the server caps an explicitly requested RPC deadline at 15
minutes. These are current implementation limits, not compatibility
guarantees.

`blob-read` currently requires Linux, an owner-controlled destination directory
(owned by the current user and not writable by group or other users), and a
filesystem that supports named staging, atomic no-replace rename, and directory
synchronization.
It writes to a randomly named mode-0600 sibling, synchronizes the complete
verified stream, atomically renames that exact inode without replacing an
existing or concurrently created path, and synchronizes the directory. Failure
cleanup is best-effort; filesystem errors or an abrupt process or host failure
can leave the hidden owner-only file for operator cleanup. A post-publication
directory-sync error says the output exists and must be verified before retrying.
Unsupported output platforms or filesystems fail closed. The caller's publish
source and completed read output remain caller-owned files outside node
zeroization custody; zeroizing the node does not erase either file. Upload
bytes pass through bounded agent frames into node-owned durable
packs/checkpoints rather than an agent-owned plaintext file.

The current `PublishBlob` method intentionally replaces the unreleased PR 95
`v1alpha1` client-streaming/unary exchange with a bidirectional stream. There
are no production deployments, so there is no deployed-client compatibility
promise. Regenerate clients
from the repository schema, implement accepted-offset/checkpoint responses, and
preserve the original operation key and exact intent for recovery. An additive
legacy method is not retained because it would freeze a second mutation and
recovery grammar without a deployed consumer.

This agent surface also exposes capacity observation. Blob subscription, poll,
acknowledgement, network-wide visibility, and Blob FFI lifetime fields remain
outside this surface.

The legacy binary flag `--blob-interest TOPIC@SCOPE` is repeatable but exists
only for development/migration mode. Customer service deployments use strict
schema v1 or v2 configuration; neither form grants public API access or creates
an application subscription.

### Pipelined durable Event publication

Shipped Event publication is numbered-only. `PublishEvent`, `PublishEvents`,
and the ordinary-publication SDK helpers have been removed. Both unary and
pipelined publishers require a stable client ID, an explicitly initialized
journal, and recovery before assigning new work.

Native Connect and gRPC over HTTP/2 use `PublishNumberedEvents`. The SDK journals
complete intents before sending, persists each ordered result before freeing a
window slot, and replays the exact unanswered sequences after a disconnect.

Initialize `path` once with `PublicationJournal::initialize(path, client_id)`
during explicit fresh provisioning. Reopen it on subsequent process launches;
a missing journal must be diagnosed rather than recreated.

```no_run
# #[cfg(feature = "client")]
async fn publish_telemetry(
    token: &str,
    path: &std::path::Path,
    mut apply: impl FnMut(u64, &aster_agent::proto::aster::application::v1alpha1::CommittedPublicationResult) -> Result<(), Box<dyn std::error::Error + Send + Sync>>,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    use aster_agent::{proto::aster::application::v1alpha1 as api, sdk::{NumberedEventSdk, RecoveredState}};
    use connectrpc::{Protocol, client::{ClientConfig, Http2Connection}};
    let connection = Http2Connection::connect_plaintext("http://127.0.0.1:8181".parse()?).await?.shared(32);
    let config = ClientConfig::new("http://127.0.0.1:8181".parse()?)
        .with_protocol(Protocol::Connect)
        .with_default_header("authorization", format!("Bearer {token}"));
    let client = api::AsterApplicationServiceClient::new(connection, config);
    let sdk = NumberedEventSdk::open(client, path, b"sensor-a")?;
    for operation in sdk.recover().await?.operations {
        let result = match operation.state {
            RecoveredState::Pending => Some(sdk.publish_journaled(operation.sequence).await?),
            RecoveredState::Committed(result) => Some(result),
            RecoveredState::Retired => None,
        };
        if let Some(result) = result {
            apply(operation.sequence, &result)?; // durable, idempotent application progress
            sdk.acknowledge(operation.sequence).await?;
        }
    }
    let sequences = (0_u8..4).map(|sample| sdk.journal_publication(api::PublishNumberedEventRequest {
        topic: "telemetry.temperature".to_owned(), scope: "mission/team/alpha".to_owned(),
        priority: api::Priority::Routine.into(), logical_key: b"sensor-a".to_vec(), payload: vec![sample], ..Default::default()
    })).collect::<Result<Vec<_>, _>>()?;
    let results = sdk.publish_journaled_pipeline(&sequences, 3).await?;
    for (sequence, result) in sequences.into_iter().zip(results) {
        apply(sequence, &result)?;
        sdk.acknowledge(sequence).await?;
    }
    Ok(())
}
```

The reference window is eight and healthy streams rotate after eight seconds,
before the ten-second server deadline. These are implementation bounds, not
validated rates. gRPC-Web uses ordered unary `PublishNumberedEvent` calls per
client; different configured clients may proceed concurrently. The SDK stops
at the first rejected sequence and preserves that intent and later journaled
work for explicit repair or abandonment. It never abandons work automatically.

### Crash-safe numbered publication

With the `client` feature, [`sdk::PublicationJournal`] and
[`sdk::NumberedEventSdk`] implement numbered Event publication. Journal creation is explicit. The journal contains plaintext publication
intents and payloads: keep it in a protected directory. On Unix, creation uses
mode `0600`, and opening rejects symlinks, non-regular files, files owned by
another user, or group/other permissions. Existing journals with broader
permissions must be restricted by their owner before opening. On other
platforms, protect access through the directory and file ACLs.
Initialization commits the initial state with immediate durability, then opens
and synchronizes the parent directory before reporting success, matching the
Go and native journals. A directory-sync failure returns an error and retains
the journal; preserve that state rather than deleting or reinitializing it.
Parent lookup currently uses the pathname; retaining the exact creation-directory
handle against concurrent renames or replacement is tracked in
[issue #111](https://github.com/defenseunicorns/aster/issues/111).

The Rust SDK retains at most **eight entries** and charges a **1 MiB logical
serialized-state budget** across metadata, entry keys, intents, and saved
results. Admission reserves 1,024 serialized bytes per result plus worst-case
recovery-claim and counter metadata, so a full journal can still save current
receipts, retire content, and recover. Event payloads are limited to 65,536
bytes, matching the Go journal. These are local journal bounds; the independent
eight-request network window limits only concurrent transmission. The byte
budget does not cap redb's physical file size or allocator overhead.

Checks run inside each journal write transaction. A rejected publication does
not consume a sequence or change retained state. Pending intents and committed
results awaiting acknowledgement both occupy slots; acknowledgement or
confirmed abandonment/removal frees capacity. Opening rejects an existing
journal above these limits without discarding its retained state. Preserve an
incompatible journal for diagnosis rather than deleting or recreating it.

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

`publish_journaled_pipeline(&sequences, max_disconnect_retries)` sends a
contiguous range beginning at the next first admission over native HTTP/2
`PublishNumberedEvents`. Complete intents must already be journaled. It uses
the existing eight-input window and rotates before the server's default
stream deadline; each committed receipt is saved before the SDK releases a
window slot. Disconnect replay preserves client ID, session, sequence, and
intent. A rejected input stops this SDK pipeline and remains journaled, along
with unresolved later inputs, for explicit repair or abandonment. Successful
receipts already saved before a later error are available through recovery.
The service returns ordered per-input numbered outcomes and rejects gRPC-Web
request streaming; numbered unary calls remain available there. Migrate
ordinary publishers to this journaled lifecycle and regenerate clients against
the current service schema. Nonempty legacy Event publication ledgers are
refused at startup; preserve them for read-only inspection and explicitly
provision fresh state. See the
[numbered-publication migration guide](../../docs/quickstart/connect-agent.md#use-crash-safe-numbered-publication).

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
