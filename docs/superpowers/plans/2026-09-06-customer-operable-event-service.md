# Customer-operable Event Service Implementation Plan

> ****

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Harden the existing loopback `aster-agent` into the Event-owned runtime portion of the single-scope customer MVP, with strict configuration, protected-loader injection, explicit health and lifecycle behavior, pre-body authentication, bounded resources, durable recovery acceptance, and sanitized retry guidance.

**Architecture:** Keep `SelectedEventHandle` and the running selected node as the sole Event authority. Split the agent crate into focused configuration, credential, error, lifecycle, HTTP-serving, service, and runtime-supervision modules; use a generic `ProvisioningSecretLoader` entry point so the provisioning workstream can statically compose its provider without redefining the reference format. Wrap `ConnectRpcService` in a small Hyper/Tower pre-body gate and run it through a bounded loopback accept loop, because ConnectRPC 0.9.0 interceptors intentionally run after bounded body collection.

**Tech Stack:** Rust 1.97.1 with workspace MSRV 1.91, Tokio 1.53.1, ConnectRPC 0.9.0, Buffa 0.9.1, serde 1.0.229, serde_json 1.0.151, Hyper 1.11.0, hyper-util 0.1.20, Tower 0.5.3, Go 1.26.7, connect-go 1.20.0, and protobuf-go 1.36.11.

**Spec:** `docs/superpowers/specs/2026-09-05-customer-operable-event-service-design.md`

## Global Constraints

- Every project communication and new project document is labeled ``; do not access any OPI source named by `CONTRIBUTING.md`.
- The customer profile is single-scope and Event-only, with at most 256 exact manually admitted peers and at most one customer-controlled pinned relay; do not add bridge or multi-scope configuration.
- Preserve `SelectedEventHandle` and the running selected node as the sole durable Event authority; do not add a store, journal, reconciliation engine, transport selector, or wire format.
- Application and health listeners remain plaintext loopback TCP. Customer qualification additionally requires the deployment-owned dedicated network namespace; this plan creates no systemd, Kubernetes, Zarf, UDS, package, or image artifact.
- Stable JSON contains only a path to a canonical `ProvisioningSecretRef`; it never contains mission plaintext or opaque reference bytes. Runtime startup accepts exactly one caller-supplied `ProvisioningSecretLoader`.
- The repository stock binary may validate customer configuration, but it must not pretend that the development-only unprotected mission adapter is a customer provider. The provisioning/deployment binary calls the public `run_customer_agent` entry point with its concrete protected loader.
- Aggregate logical storage limits map directly to `StoreLimits`; derive the ordinary global custody quota with `CustodyQuota::for_store_limits`. Do not add per-scope, bridge, or Blob-depot quota configuration.
- Preserve hard ceilings: 1 MiB encoded request/message, 4 MiB decode element memory, 2 MiB encoded response, 10 ms through 30 seconds RPC deadlines, 32 HTTP/2 streams per connection, and 100 ms through 60 seconds stream polling backoff.
- Add compiled customer ceilings of 64 total application connections, 8 not-yet-authenticated application connections, 16 KiB request headers, 5 seconds to authenticate the first request on a connection, 64 in-flight business requests, and 30 seconds maximum graceful-shutdown time. JSON may tighten but never raise these values.
- Add no floating dependency. Any new direct dependency uses the exact version already locked transitively, is recorded in Decision 0041, and is checked by the repository dependency and provenance gates.
- Follow red-green-refactor for every behavior change and commit after each task's focused test set passes.
- Do not move a requirement status merely because code exists. Update `docs/implementation/requirements-status.md` only for evidence actually produced by the final process acceptance run.

## File structure

- `crates/aster-agent/src/config.rs` — strict version-one JSON parsing and conversion to validated node, forwarding, storage, listener, and server limits.
- `crates/aster-agent/src/credentials.rs` — owner-only bounded file reads, canonical mission-reference loading, and atomically reloadable bearer tokens.
- `crates/aster-agent/src/error.rs` — stable public reason/operation/retry mapping and sanitized startup/runtime errors.
- `crates/aster-agent/src/lifecycle.rs` — legal lifecycle transitions, detail-free health decisions, drain admission, and signal events.
- `crates/aster-agent/src/health.rs` — loopback health listener and exact `/livez` and `/readyz` HTTP behavior.
- `crates/aster-agent/src/server.rs` — bounded Hyper accept loop and Tower pre-body authentication/admission gate around ConnectRPC.
- `crates/aster-agent/src/service.rs` — the existing Event RPC adapter, response bounds, streaming poll loop, and application error conversion.
- `crates/aster-agent/src/runtime.rs` — protected-loader node bootstrap, listener ordering, supervisor, token reload, drain, and shutdown deadline.
- `crates/aster-agent/src/lib.rs` — module declarations and the small supported public surface.
- `crates/aster-agent/src/main.rs` — strict mode selection, `--check-config`, legacy development mode, Unix signal translation, and sanitized exit handling.
- `crates/aster-agent/tests/real_node_connect.rs` — focused real-node regression for the refactored server.
- `crates/aster-agent/tests/customer_runtime.rs` — in-process customer runtime tests with a recording protected-loader double.
- `crates/aster-agent/src/bin/aster-agent-acceptance-fixture.rs` — feature-gated test-only binary supplying a file-backed loader double; never a customer artifact.
- `tools/check-aster-agent-process.py` — bounded black-box process orchestration and secret/log canary checks.
- `conformance/agent-go/` — checked-in generated non-Rust Connect client and bounded smoke CLI.
- `proto/aster/application/v1alpha1/aster.proto` and `.fds.bin` — additive public error detail schema and reproduced descriptor.
- `docs/reference/aster-agent-config-v1.md` and `docs/quickstart/connect-agent.md` — supported configuration and executable operation/retry guidance after runtime behavior exists.

---

### Task 1: Strict customer configuration and aggregate quotas

**Files:**
- Create: `crates/aster-agent/src/config.rs`
- Modify: `crates/aster-agent/src/lib.rs`
- Modify: `crates/aster-agent/src/main.rs`
- Modify: `crates/aster-agent/Cargo.toml`
- Test: `crates/aster-agent/src/config.rs`

**Interfaces:**
- Consumes: `MissionExpectedPeer: FromStr`, `StoreLimits::new`, `CustodyQuota::for_store_limits`, `SelectedForwardingConfig::with_store_limits`, and `PinnedRelay::{new,with_ca_roots}`.
- Produces: `load_and_validate_config(path: &Path) -> Result<ValidatedAgentConfig, ConfigError>`, `check_config(path: &Path) -> Result<(), ConfigError>`, `ValidatedAgentConfig::node_options() -> NodeConfigOptions`, `ValidatedAgentConfig::forwarding() -> SelectedForwardingConfig`, `CredentialPaths`, and `AgentLimits`.

- [ ] **Step 1: Add failing strict-schema tests**

```rust
#[test]
fn v1_rejects_unknown_duplicate_and_bridge_fields() {
    assert_reason(json_with("unknown", "true"), ConfigReason::UnknownField);
    assert_reason(json_with_duplicate("schema_version", "1"), ConfigReason::DuplicateField);
    assert_reason(json_with("event_bridge", "{}"), ConfigReason::UnknownField);
}

#[test]
fn quota_must_leave_reserves_and_one_maximum_event() {
    let minimum_items = MAX_CONTROL_ITEMS + CUSTODY_EMERGENCY_ITEM_RESERVE + 1;
    let minimum_bytes = MAX_CONTROL_BYTES
        + CUSTODY_EMERGENCY_BYTE_RESERVE
        + MAX_AGENT_MESSAGE_BYTES as u64;
    assert_reason(config_with_storage(minimum_items - 1, minimum_bytes), ConfigReason::StorageTooSmall);
    assert!(validate_storage(minimum_items, minimum_bytes).is_ok());
}
```

- [ ] **Step 2: Run the focused tests and confirm the new module is absent**

Run: `cargo test --locked -p aster-agent config::tests --all-features`

Expected: FAIL because `config`, `ConfigReason`, and the v1 parser do not exist.

- [ ] **Step 3: Implement exact raw and validated configuration types**

```rust
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawAgentConfig {
    schema_version: u32,
    state: RawState,
    application: RawListener,
    health: RawListener,
    mesh: RawMesh,
    credentials: RawCredentials,
    storage: RawStorage,
    #[serde(default)]
    limits: RawLimits,
}

pub struct ValidatedAgentConfig {
    state: PathBuf,
    application: SocketAddr,
    health: SocketAddr,
    mesh_bind: SocketAddr,
    peers: Vec<MissionExpectedPeer>,
    forwarding: SelectedForwardingConfig,
    credentials: CredentialPaths,
    limits: AgentLimits,
}

pub fn load_and_validate_config(path: &Path) -> Result<ValidatedAgentConfig, ConfigError>;
pub fn check_config(path: &Path) -> Result<(), ConfigError>;
```

Use exact JSON keys `directory`, `listen`, `bind`, `sync_interval_ms`, `peers`, `relay`, `client_token_file`, `mission_secret_ref_file`, `mission_load_id`, `max_items`, and `max_payload_bytes`. Require absolute lexical paths, distinct loopback application/health listeners, nonzero bounded synchronization interval, unique peer carrier and mission identities, no more than 256 peers, one optional relay with `webpki` or `der_roots`, and exact 64-hex-character `mission_load_id`.

Add exact internal path dependencies on `aster-core`, `aster-iroh`, and `aster-redb-store` to consume the existing provisioning, relay, and reserve constants directly; do not duplicate those authorities in the agent crate.

- [ ] **Step 4: Wire only mode selection into `main.rs`**

```rust
enum Invocation {
    CheckConfig(PathBuf),
    CustomerConfig(PathBuf),
    LegacyDevelopment(Arguments),
}

// --config cannot be combined with any legacy flag.
// --check-config validates and exits without binding or opening state.
```

For this task, `CustomerConfig` returns the stable sanitized `protected provider required` startup result; Task 6 replaces that branch in provider-composed binaries through `run_customer_agent`.

- [ ] **Step 5: Prove syntax and semantic validation are side-effect free**

Run: `cargo test --locked -p aster-agent config::tests --all-features`

Expected: PASS, including a test that places canaries at the configured state and socket addresses and proves invalid config neither creates state nor binds either port.

- [ ] **Step 6: Commit the configuration boundary**

```bash
git add crates/aster-agent/Cargo.toml crates/aster-agent/src/config.rs crates/aster-agent/src/lib.rs crates/aster-agent/src/main.rs
git commit -m "feat(agent): add strict customer configuration"
```

### Task 2: Secure credential files and protected-loader bootstrap seam

**Files:**
- Create: `crates/aster-agent/src/credentials.rs`
- Create: `crates/aster-agent/tests/customer_runtime.rs`
- Modify: `crates/aster-agent/src/config.rs`
- Modify: `crates/aster-agent/src/lib.rs`
- Modify: `crates/aster-agent/Cargo.toml`
- Test: `crates/aster-agent/src/credentials.rs`
- Test: `crates/aster-agent/tests/customer_runtime.rs`

**Interfaces:**
- Consumes: `ValidatedAgentConfig::credential_paths`, `ProvisioningSecretRef::from_bytes`, `ProvisioningLoadId::new`, `ProvisioningSecretLoader`, and `NodeConfig::open_secret_ref`.
- Produces: `load_startup_credentials(&CredentialPaths) -> Result<StartupCredentials, CredentialError>`, `open_node_config<L>(&ValidatedAgentConfig, &StartupCredentials, &mut L) -> Result<NodeConfig, NodeBootstrapError>`, `ReloadableClientToken::{new,authorizes,reload_from}`, and the protected-loader arguments later consumed by `run_customer_agent`.

- [ ] **Step 1: Add failing owner-only reference and reload tests**

```rust
#[cfg(unix)]
#[test]
fn mission_reference_is_owner_only_bounded_canonical_and_zeroized() {
    let fixture = OwnerOnlyFixture::canonical_secret_ref();
    assert!(load_mission_reference(fixture.path()).is_ok());
    fixture.chmod(0o640);
    assert_eq!(load_mission_reference(fixture.path()).unwrap_err().reason(), CredentialReason::Permissions);
    fixture.replace_with_symlink();
    assert_eq!(load_mission_reference(fixture.path()).unwrap_err().reason(), CredentialReason::FinalSymlink);
}

#[test]
fn failed_reload_keeps_the_old_token() {
    let active = ReloadableClientToken::new(token(b'a'));
    assert!(active.reload_from(invalid_token_file()).is_err());
    assert!(active.authorizes(Some(b"Bearer aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")));
}
```

- [ ] **Step 2: Run the focused tests and verify red**

Run: `cargo test --locked -p aster-agent credentials::tests --all-features`

Expected: FAIL because the shared secure-file loader and reloadable token do not exist.

- [ ] **Step 3: Extract one secure bounded file primitive and load canonical references**

```rust
fn read_owner_only_bounded(
    path: &Path,
    maximum: usize,
    kind: CredentialFileKind,
) -> Result<Zeroizing<Vec<u8>>, CredentialError>;

pub struct StartupCredentials {
    pub token: ReloadableClientToken,
    pub mission_ref: ProvisioningSecretRef,
    pub mission_load: ProvisioningLoadId,
}
```

Open with `O_CLOEXEC | O_NOFOLLOW`, verify regular-file type, effective-user ownership, mode `0o600` or stricter, stable metadata before/after the read, and the exact public size bound. Never include a path, byte value, provider reference, or raw I/O error in `Display` or `Debug`.

- [ ] **Step 4: Implement atomic token replacement with standard-library synchronization**

```rust
#[derive(Clone)]
pub struct ReloadableClientToken(Arc<RwLock<ClientToken>>);

impl ReloadableClientToken {
    pub fn reload_from(&self, path: &Path) -> Result<(), CredentialError> {
        let replacement = ClientToken::load(path)?;
        *self.0.write().unwrap_or_else(PoisonError::into_inner) = replacement;
        Ok(())
    }
}
```

Construct and validate the replacement before taking the write lock. A request reads one complete token value; no partially initialized value is observable.

- [ ] **Step 5: Prove `--check-config` never invokes a provider and bootstrap does**

```rust
#[test]
fn config_check_does_not_invoke_loader_but_bootstrap_uses_exact_reference() {
    let mut loader = RecordingLoader::returning(valid_mission_bundle());
    check_config(config_path()).expect("valid config");
    assert_eq!(loader.calls(), 0);
    let config = validated_config();
    let credentials = load_startup_credentials(config.credential_paths()).expect("credentials");
    open_node_config(&config, &credentials, &mut loader).expect("protected node config");
    assert_eq!(loader.calls(), 1);
    assert_eq!(loader.last_reference(), expected_reference());
    assert_eq!(loader.last_operation(), expected_load_id());
}
```

Run: `cargo test --locked -p aster-agent credentials::tests --all-features && cargo test --locked -p aster-agent --test customer_runtime --all-features`

Expected: PASS; provider failure text and reference canaries do not appear in returned errors.

- [ ] **Step 6: Commit the credential seam**

```bash
git add crates/aster-agent/Cargo.toml crates/aster-agent/src/config.rs crates/aster-agent/src/credentials.rs crates/aster-agent/src/lib.rs crates/aster-agent/tests/customer_runtime.rs
git commit -m "feat(agent): consume protected provisioning references"
```

### Task 3: Stable sanitized RPC error detail

**Files:**
- Create: `crates/aster-agent/src/error.rs`
- Create: `crates/aster-agent/src/service.rs`
- Modify: `crates/aster-agent/src/lib.rs`
- Modify: `proto/aster/application/v1alpha1/aster.proto`
- Modify: `proto/aster/application/v1alpha1/aster.fds.bin`
- Test: `crates/aster-agent/src/error.rs`
- Test: `crates/aster-agent/src/service.rs`

**Interfaces:**
- Consumes: `ApplicationError::{kind,operation}` and `ConnectError::with_detail`.
- Produces: generated `api::PublicErrorReason`, local `PublicOperation`, `public_error(...) -> ConnectError`, and `connect_application_error(ApplicationError) -> ConnectError`.

- [ ] **Step 1: Add the additive public error message and failing mapping tests**

```proto
enum PublicErrorReason {
  PUBLIC_ERROR_REASON_UNSPECIFIED = 0;
  PUBLIC_ERROR_REASON_MALFORMED_INPUT = 1;
  PUBLIC_ERROR_REASON_UNSUPPORTED_VALUE = 2;
  PUBLIC_ERROR_REASON_OPERATION_KEY_CONFLICT = 3;
  PUBLIC_ERROR_REASON_MISSING_DURABLE_OBJECT = 4;
  PUBLIC_ERROR_REASON_FAILED_PRECONDITION = 5;
  PUBLIC_ERROR_REASON_DEADLINE = 6;
  PUBLIC_ERROR_REASON_RESOURCE_EXHAUSTION = 7;
  PUBLIC_ERROR_REASON_DRAINING = 8;
  PUBLIC_ERROR_REASON_STATE_UNAVAILABLE = 9;
  PUBLIC_ERROR_REASON_AUTHENTICATION_FAILED = 10;
  PUBLIC_ERROR_REASON_INTERNAL = 11;
}

message PublicErrorDetail {
  PublicErrorReason reason = 1;
  string operation = 2;
  bool retryable = 3;
  optional uint32 retry_delay_ms = 4;
}
```

```rust
#[test]
fn internal_failure_never_exposes_source_text() {
    let error = public_error(
        ErrorCode::Internal,
        api::PublicErrorReason::Internal,
        PublicOperation::PublishEvent,
        false,
        None,
    );
    assert_eq!(error.code, ErrorCode::Internal);
    assert_detail(error, api::PublicErrorReason::Internal, "publish_event", false, None);
}
```

- [ ] **Step 2: Run the schema and mapping tests and verify red**

Run: `cargo test --locked -p aster-agent error::tests --all-features`

Expected: FAIL because generated `PublicErrorDetail` and `error.rs` do not exist.

- [ ] **Step 3: Regenerate and verify the checked-in descriptor locally**

Run: `buf build --as-file-descriptor-set -o proto/aster/application/v1alpha1/aster.fds.bin . && sh tools/check-agent-proto.sh`

Expected: PASS after the descriptor matches the additive schema.

- [ ] **Step 4: Implement one closed mapping table and move the existing adapter to `service.rs`**

```rust
pub fn public_error(
    code: ErrorCode,
    reason: api::PublicErrorReason,
    operation: PublicOperation,
    retryable: bool,
    retry_delay: Option<Duration>,
) -> ConnectError {
    let detail = api::PublicErrorDetail {
        reason: reason.into(),
        operation: operation.as_str().to_owned(),
        retryable,
        retry_delay_ms: retry_delay.and_then(bounded_millis),
        ..Default::default()
    };
    ConnectError::new(code, reason.public_message())
        .with_detail(ErrorDetail::from_message("aster.application.v1alpha1.PublicErrorDetail", &detail))
}
```

Map every current `ApplicationErrorKind` explicitly. Map `ApplicationError::operation()` through a fixed allowlist to `PublicOperation` rather than forwarding arbitrary text. Treat the non-exhaustive fallback as fixed `Internal`; never call `error.to_string()` in a public response. Parser helpers use `MalformedInput` or `UnsupportedValue`, conflict uses `OperationKeyConflict`, expiry/retirement uses `MissingDurableObject`, resource limits use `ResourceExhaustion`, and closed local authority uses `StateUnavailable`.

- [ ] **Step 5: Run focused and real-node regressions**

Run: `cargo test --locked -p aster-agent --all-targets --all-features`

Expected: PASS with the existing Event semantics unchanged and error-detail decoding covered for Connect, gRPC, and gRPC-Web encodings.

- [ ] **Step 6: Commit the public failure contract**

```bash
git add crates/aster-agent/src/error.rs crates/aster-agent/src/service.rs crates/aster-agent/src/lib.rs proto/aster/application/v1alpha1/aster.proto proto/aster/application/v1alpha1/aster.fds.bin
git commit -m "feat(agent): add sanitized public error details"
```

### Task 4: Lifecycle state and detail-free health listener

**Files:**
- Create: `crates/aster-agent/src/lifecycle.rs`
- Create: `crates/aster-agent/src/health.rs`
- Modify: `crates/aster-agent/src/lib.rs`
- Modify: `crates/aster-agent/Cargo.toml`
- Modify: `Cargo.toml`
- Modify: `Cargo.lock`
- Test: `crates/aster-agent/src/lifecycle.rs`
- Test: `crates/aster-agent/src/health.rs`

**Interfaces:**
- Consumes: validated loopback health address and compiled header/deadline limits.
- Produces: `LifecycleState`, `FailureReason`, `ServiceStatus::{starting,transition,state}`, `HealthDecision`, and `BoundHealth::{bind,local_addr,serve}`.

- [ ] **Step 1: Add failing transition and HTTP decision tests**

```rust
#[test]
fn lifecycle_health_matrix_is_exact() {
    assert_health(LifecycleState::Starting, 200, 503);
    assert_health(LifecycleState::Ready, 200, 200);
    assert_health(LifecycleState::Draining, 200, 503);
    assert_health(LifecycleState::Failed, 503, 503);
}

#[test]
fn health_reveals_only_status_and_rejects_body_method_and_path() {
    assert_empty(health(GET, "/livez", empty_body()), 200);
    assert_empty(health(GET, "/missing", empty_body()), 404);
    assert_empty(health(POST, "/readyz", empty_body()), 405);
    assert_empty(health(GET, "/livez", one_byte_body()), 400);
}
```

- [ ] **Step 2: Run focused tests and verify red**

Run: `cargo test --locked -p aster-agent lifecycle::tests --all-features && cargo test --locked -p aster-agent health::tests --all-features`

Expected: FAIL because the lifecycle and health modules do not exist.

- [ ] **Step 3: Implement legal state transitions with fixed failure reasons**

```rust
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum LifecycleState { Starting, Ready, Draining, Stopped, Failed }

#[derive(Clone)]
pub struct ServiceStatus {
    state: Arc<AtomicU8>,
    failure: Arc<Mutex<Option<FailureReason>>>,
}

impl ServiceStatus {
    pub fn transition(&self, next: LifecycleState) -> Result<(), LifecycleError>;
    pub fn health(&self, endpoint: HealthEndpoint) -> HealthDecision;
}
```

Allow only `Starting -> Ready|Failed`, `Ready -> Draining|Failed`, `Draining -> Stopped|Failed`, and terminal self-observation. Store only a bounded `FailureReason` enum, never an error chain.

- [ ] **Step 4: Add exact Hyper dependencies already present in the lockfile**

Add workspace pins `bytes = "=1.12.1"`, `http = "=1.5.0"`, `http-body-util = "=0.1.5"`, `hyper = { version = "=1.11.0", features = ["http1", "http2", "server"] }`, `hyper-util = { version = "=0.1.20", features = ["http1", "http2", "server-auto", "server-graceful", "service", "tokio"] }`, `tower = { version = "=0.5.3", features = ["util"] }`, and `tower-service = "=0.3.3"`. Reference them with `.workspace = true` from `aster-agent`; do not change resolved versions.

- [ ] **Step 5: Implement the loopback-only health server**

```rust
pub struct BoundHealth { listener: TcpListener }

impl BoundHealth {
    pub async fn bind(address: SocketAddr) -> Result<Self, HealthError>;
    pub fn local_addr(&self) -> Result<SocketAddr, HealthError>;
    pub async fn serve(self, status: ServiceStatus, stop: watch::Receiver<bool>) -> Result<(), HealthError>;
}
```

Use Hyper's HTTP/1+HTTP/2 auto builder, a 4 KiB health header ceiling, 2-second header deadline, 16-connection semaphore, empty `Full<Bytes>` responses, and no structured detail body.

- [ ] **Step 6: Run focused tests and commit**

Run: `cargo test --locked -p aster-agent lifecycle::tests --all-features && cargo test --locked -p aster-agent health::tests --all-features`

Expected: PASS, including non-loopback bind refusal and live socket checks.

```bash
git add Cargo.toml Cargo.lock crates/aster-agent/Cargo.toml crates/aster-agent/src/lifecycle.rs crates/aster-agent/src/health.rs crates/aster-agent/src/lib.rs
git commit -m "feat(agent): add lifecycle health contract"
```

### Task 5: Pre-body authentication and node-global server bounds

**Files:**
- Create: `crates/aster-agent/src/server.rs`
- Modify: `crates/aster-agent/src/service.rs`
- Modify: `crates/aster-agent/src/lib.rs`
- Modify: `crates/aster-agent/tests/real_node_connect.rs`
- Modify: `docs/decisions/0041-customer-operable-event-service.md`
- Test: `crates/aster-agent/src/server.rs`
- Test: `crates/aster-agent/tests/real_node_connect.rs`

**Interfaces:**
- Consumes: `ReloadableClientToken`, `ServiceStatus`, `AgentLimits`, `public_error`, the Event router, and ConnectRPC limits/deadline policy.
- Produces: `PreBodyGate<S>`, `PermitBody<B>`, `BoundAgent::{bind,local_addr,serve}`, and `ServerStop::{Run,Drain,Force}`.

- [ ] **Step 1: Add a body-poll canary and saturation tests**

```rust
#[tokio::test]
async fn unauthenticated_request_is_rejected_without_polling_body() {
    let body = PanicOnPollBody::new();
    let response = pre_body_gate(valid_service(), token(), ready())
        .oneshot(request_without_authorization(body))
        .await
        .expect("infallible service");
    assert_public_error(response, ErrorCode::Unauthenticated, api::PublicErrorReason::AuthenticationFailed);
}

#[tokio::test]
async fn ninth_unauthenticated_connection_is_refused() {
    let server = server_with_limits(64, 8);
    let first_eight = open_idle_connections(&server, 8).await;
    assert_refused(open_idle_connection(&server).await);
    drop(first_eight);
}
```

- [ ] **Step 2: Run focused tests and verify red**

Run: `cargo test --locked -p aster-agent server::tests --all-features`

Expected: FAIL because the pre-body service and custom accept loop do not exist.

- [ ] **Step 3: Implement the pre-body gate around `ConnectRpcService`**

```rust
#[derive(Clone)]
pub struct PreBodyGate<S> {
    accepted: S,
    rejected: S,
    token: ReloadableClientToken,
    status: ServiceStatus,
    in_flight: Arc<Semaphore>,
    connection_auth: ConnectionAuthState,
}
```

On missing/invalid bearer, draining state, or exhausted in-flight capacity, replace the network body with `http_body_util::Empty<Bytes>` and invoke a rejection `ConnectRpcService` whose first interceptor returns the appropriate structured error. This preserves Connect/gRPC/gRPC-Web error encoding while ensuring the original network body is dropped without a poll. On valid auth, mark the connection authenticated, release its unauthenticated permit, acquire the in-flight permit, and pass the untouched body to the accepted service. Wrap the returned body in `PermitBody<B>` so unary work holds the permit to end-of-body and streaming work holds it until stream completion or cancellation.

- [ ] **Step 4: Implement the bounded loopback accept loop**

```rust
pub async fn serve(
    self,
    service: ConnectRpcService<Router>,
    token: ReloadableClientToken,
    status: ServiceStatus,
    limits: AgentLimits,
    mut stop: watch::Receiver<ServerStop>,
) -> Result<(), ServerError>;
```

Use one 64-permit total connection semaphore and one 8-permit unauthenticated semaphore, both tightened from config. Configure Hyper HTTP/1 `header_read_timeout(5s)` and `max_buf_size(16 KiB)`, HTTP/2 `max_header_list_size(16 KiB)` and `max_concurrent_streams(32)`, and `GracefulShutdown` for tracked connections. Race each new connection against the 5-second first-authentication deadline so an HTTP/2 preface or idle stream cannot hold an unauthenticated permit indefinitely. A connection releases the unauthenticated permit only after its first valid request and retains the total permit until close.

- [ ] **Step 5: Preserve all three protocols and existing Event behavior**

Run: `cargo test --locked -p aster-agent --test real_node_connect --all-features`

Expected: PASS for authenticated unary and server streaming, with new cases proving unauthenticated Connect, gRPC, and gRPC-Web requests receive the same public reason and never reach the Event handler.

- [ ] **Step 6: Record exact direct dependency admission in Decision 0041**

Add Hyper 1.11.0, hyper-util 0.1.20, Tower 0.5.3, and their direct helper crates with public crates.io sources, MIT licenses, the pre-body gate role, and the fact that all versions were already present transitively under ConnectRPC 0.9.0. State that the custom accept loop exists because the pinned server's public serve method accepts `ConnectRpcService` rather than a wrapped generic Tower service.

- [ ] **Step 7: Commit the authenticated server**

```bash
git add crates/aster-agent/src/server.rs crates/aster-agent/src/service.rs crates/aster-agent/src/lib.rs crates/aster-agent/tests/real_node_connect.rs docs/decisions/0041-customer-operable-event-service.md
git commit -m "feat(agent): authenticate before request bodies"
```

### Task 6: Runtime supervisor, token reload, and bounded shutdown

**Files:**
- Create: `crates/aster-agent/src/runtime.rs`
- Modify: `crates/aster-agent/src/main.rs`
- Modify: `crates/aster-agent/src/lib.rs`
- Modify: `crates/aster-agent/src/service.rs`
- Modify: `crates/aster-agent/tests/customer_runtime.rs`
- Test: `crates/aster-agent/src/runtime.rs`
- Test: `crates/aster-agent/tests/customer_runtime.rs`

**Interfaces:**
- Consumes: `ValidatedAgentConfig`, `StartupCredentials`, `ProvisioningSecretLoader`, `BoundHealth`, `BoundAgent`, `ServiceStatus`, and `start_node_with_forwarding`.
- Produces: `AgentSignal`, `AgentExit`, `run_customer_agent`, and Unix signal translation in `main.rs`.

- [ ] **Step 1: Add failing startup-order, reload, and drain tests**

```rust
#[tokio::test]
async fn readiness_requires_provider_node_and_application_listener() {
    let gates = StartupGates::closed();
    let running = spawn_customer_agent(gates.clone()).await;
    gates.release_health_bind();
    assert_health(&running, 200, 503).await;
    gates.release_provider_and_node();
    assert_health(&running, 200, 503).await;
    gates.release_application_serve();
    assert_health(&running, 200, 200).await;
}

#[tokio::test]
async fn failed_hup_keeps_token_and_readiness() {
    let running = ready_agent().await;
    corrupt_token_file();
    running.signal(AgentSignal::Hangup).await;
    assert_authorized(&running, old_token()).await;
    assert_ready(&running).await;
}
```

- [ ] **Step 2: Run runtime tests and verify red**

Run: `cargo test --locked -p aster-agent --test customer_runtime --all-features`

Expected: FAIL because the supervisor and injectable signal boundary do not exist.

- [ ] **Step 3: Implement the protected-loader runtime entry point**

```rust
pub async fn run_customer_agent<L>(
    config: ValidatedAgentConfig,
    loader: &mut L,
    mut signals: mpsc::Receiver<AgentSignal>,
) -> Result<AgentExit, AgentRuntimeError>
where
    L: ProvisioningSecretLoader + ?Sized;
```

Execute in this order: validate complete config and credential files; bind health; set `Starting`; call `NodeConfig::open_secret_ref`; start the node with exact `SelectedForwardingConfig`; bind/start the application listener; set `Ready`; process signals and task failures. Do not derive readiness from peer, relay, contact, queue, or convergence state.

- [ ] **Step 4: Implement signal and shutdown semantics**

```rust
pub enum AgentSignal { Hangup, Terminate }
pub enum AgentExit { Clean, Forced, Failed(FailureReason) }
pub enum AgentRuntimeError {
    Configuration(ConfigReason),
    Credential(CredentialReason),
    Bootstrap(NodeBootstrapErrorKind),
    Listener(FailureReason),
    Lifecycle(FailureReason),
}
```

`Hangup` reloads only the configured client token file. The first `Terminate` changes `Ready -> Draining`, closes business admission, stops new stream polls, starts Hyper graceful shutdown, and calls `RunningNode::shutdown`. A second `Terminate` or grace expiry returns `Forced`; `main` maps it to a distinct non-success exit code. Stop health last and record `Stopped` only after both server and node complete.

- [ ] **Step 5: Emit bounded structured lifecycle logs**

Serialize one fixed-field JSON object for startup, readiness transition, reload result, drain start, shutdown result, and fatal transition. Permit only timestamp, lifecycle state, public operation/reason, retryability, response code, bounded latency bucket, and correlation ID. Tests inject canaries into config, errors, Event fields, provider failures, and paths and assert none occur in captured logs.

- [ ] **Step 6: Run focused runtime and agent tests**

Run: `cargo test --locked -p aster-agent --all-targets --all-features`

Expected: PASS for startup ordering, offline readiness, reload atomicity, drain rejection, in-flight grace, stream stop, second signal, forced deadline, and fatal-task propagation.

- [ ] **Step 7: Commit the supervisor**

```bash
git add crates/aster-agent/src/runtime.rs crates/aster-agent/src/main.rs crates/aster-agent/src/lib.rs crates/aster-agent/src/service.rs crates/aster-agent/tests/customer_runtime.rs
git commit -m "feat(agent): supervise reload drain and recovery"
```

### Task 7: Black-box crash and recovery acceptance

**Files:**
- Create: `crates/aster-agent/src/bin/aster-agent-acceptance-fixture.rs`
- Create: `tools/check-aster-agent-process.py`
- Create: `tools/test-aster-agent-process.py`
- Modify: `crates/aster-agent/Cargo.toml`
- Modify: `mise.toml`
- Test: `tools/test-aster-agent-process.py`

**Interfaces:**
- Consumes: the public `run_customer_agent` function and an already provisioned v1 config.
- Produces: a bounded `check-aster-agent-process.py --agent PATH --config PATH --client PATH` contract usable by deployment artifacts, plus a feature-gated repository fixture implementing `ProvisioningSecretLoader` only for acceptance tests.

- [ ] **Step 1: Add failing harness contract tests**

```python
def test_rejects_unbounded_or_missing_process_inputs(self):
    result = run_checker("--timeout-seconds", "0")
    self.assertNotEqual(result.returncode, 0)
    self.assertIn("timeout must be within 1..=120", result.stderr)

def test_canary_scanner_rejects_public_output(self):
    with self.assertRaisesRegex(ValueError, "canary exposed"):
        require_sanitized("SECRET_PATH_CANARY", ["SECRET_PATH_CANARY"])
```

- [ ] **Step 2: Run harness unit tests and verify red**

Run: `python3 -m unittest tools/test-aster-agent-process.py`

Expected: FAIL because the checker and fixture contract do not exist.

- [ ] **Step 3: Add the test-only provider binary**

Declare an `acceptance-test-provider` feature and an `aster-agent-acceptance-fixture` binary requiring that feature. Its opaque reference is a canonical owner-only mission-bundle path used only by tests; its logs and errors call it an unprotected test provider. It invokes `run_customer_agent` exactly as a protected production provider binary would, so process behavior after loader invocation is identical.

- [ ] **Step 4: Implement bounded process orchestration**

The checker must: validate executable/config/client paths without echoing them; spawn a new process group; wait on `/readyz`; publish with a fixed operation key; force-kill; restart on the same state; query the exact receipt; create a durable subscription; kill after delivery before acknowledgement; restart and require a higher attempt; acknowledge; restart and require no redelivery; send `SIGTERM` during unary and streaming activity; rotate the token with `SIGHUP`; and scan stdout, stderr, and client errors for secret/path/payload/topic/scope/peer canaries. Every wait uses the caller's 1..=120-second bound and cleanup targets only the spawned process group and exact temporary directory.

- [ ] **Step 5: Add and run a real-process smoke task**

Add `mise run agent-process-smoke` that builds the acceptance fixture with `client,acceptance-test-provider` and runs the checker against a private temporary state.

Run: `python3 -m unittest tools/test-aster-agent-process.py && mise run agent-process-smoke`

Expected: PASS with explicit receipts for readiness, publish recovery, redelivery, acknowledgement persistence, reload, graceful drain, and canary absence.

- [ ] **Step 6: Commit black-box acceptance**

```bash
git add crates/aster-agent/Cargo.toml crates/aster-agent/src/bin/aster-agent-acceptance-fixture.rs tools/check-aster-agent-process.py tools/test-aster-agent-process.py mise.toml
git commit -m "test(agent): add crash recovery process acceptance"
```

### Task 8: Generated Go interoperability client

**Files:**
- Create: `conformance/agent-go/go.mod`
- Create: `conformance/agent-go/go.sum`
- Create: `conformance/agent-go/buf.gen.yaml`
- Create: `conformance/agent-go/gen/aster/application/v1alpha1/aster.pb.go`
- Create: `conformance/agent-go/gen/aster/application/v1alpha1/aster.connect.go`
- Create: `conformance/agent-go/cmd/agent-smoke/main.go`
- Create: `tools/check-agent-go-generated.sh`
- Modify: `tools/check-aster-agent-process.py`
- Modify: `mise.toml`
- Modify: `docs/provenance/public-source-register.csv`
- Test: `conformance/agent-go/cmd/agent-smoke/main_test.go`

**Interfaces:**
- Consumes: the checked-in Protobuf schema and the black-box checker client contract.
- Produces: `agent-smoke status|publish|subscribe|poll|stream|ack` commands and a reproducible generated-client check using local plugins only.

- [ ] **Step 1: Add failing CLI validation tests**

```go
func TestTokenIsReadFromOwnerOnlyFile(t *testing.T) {
    token := writeToken(t, 0o640)
    if err := validateTokenFile(token); err == nil {
        t.Fatal("group-readable token accepted")
    }
}

func TestResultNeverPrintsAuthorization(t *testing.T) {
    got := renderResult(resultFixture(), "Bearer SECRET_TOKEN_CANARY")
    if strings.Contains(got, "SECRET_TOKEN_CANARY") {
        t.Fatal("authorization value exposed")
    }
}
```

- [ ] **Step 2: Pin public Go modules and local generators**

Use `connectrpc.com/connect v1.20.0` from `https://github.com/connectrpc/connect-go/releases/tag/v1.20.0` and `google.golang.org/protobuf v1.36.11` from `https://github.com/protocolbuffers/protobuf-go/releases/tag/v1.36.11`. Run local `protoc-gen-connect-go` and `protoc-gen-go` binaries through Buf 1.72.0; do not use Buf Schema Registry modules or remote plugins. Record those public URLs, Apache-2.0/BSD-3-Clause licenses, versions, and repository evidence in consecutive public-source-register rows.

- [ ] **Step 3: Generate and check in the client**

Run: `buf generate --template conformance/agent-go/buf.gen.yaml && sh tools/check-agent-go-generated.sh`

Expected: PASS and a clean second generation diff.

- [ ] **Step 4: Implement the bounded smoke CLI**

```go
client := applicationv1alpha1connect.NewAsterApplicationServiceClient(
    httpClient,
    baseURL,
    connect.WithGRPC(),
)
request.Header().Set("Authorization", "Bearer "+token)
```

Use a 30-second maximum command context, bounded JSON output without Event payloads or credentials, and exact operation/subscription/event IDs passed as hex. `stream` consumes at most the requested count and does not acknowledge implicitly.

- [ ] **Step 5: Replace the process harness's protocol client with the Go binary**

Run: `go -C conformance/agent-go test ./... && mise run agent-process-smoke`

Expected: PASS with the generated Go client performing authenticated unary and server streaming against the Rust service.

- [ ] **Step 6: Commit independent-language interoperability evidence**

```bash
git add conformance/agent-go tools/check-agent-go-generated.sh tools/check-aster-agent-process.py mise.toml docs/provenance/public-source-register.csv
git commit -m "test(agent): add generated Go client acceptance"
```

### Task 9: Supported documentation and evidence boundary

**Files:**
- Create: `docs/reference/aster-agent-config-v1.md`
- Modify: `docs/quickstart/connect-agent.md`
- Modify: `docs/reference-index.md`
- Modify: `docs/implementation/requirements-status.md`
- Modify: `docs/decisions/0041-customer-operable-event-service.md`
- Test: `tools/check-implementation-requirements.py`

**Interfaces:**
- Consumes: the exact implemented schema, exit codes, public errors, acceptance receipts, and provider/deployment exclusions from Tasks 1-8.
- Produces: customer-facing configuration and operation guidance whose commands match executable behavior.

- [ ] **Step 1: Write the exact v1 JSON reference and safe example**

Document every field, default, minimum, maximum, cross-field rule, file ownership rule, relay trust rule, storage reserve calculation, `--check-config` behavior, and sanitized diagnostic reason. Use non-routable example addresses and concrete synthetic fixture names; do not include any real credential or reference bytes.

- [ ] **Step 2: Update the quickstart only to implemented behavior**

Add `/livez`, `/readyz`, `SIGHUP`, `SIGINT`/`SIGTERM`, unknown publish outcome retry with the same operation key, at-least-once commit-before-acknowledge, redelivery, resource backoff, and public detail decoding. State that the repository acceptance fixture is not a customer provider and that an unisolated loopback process is development-only.

- [ ] **Step 3: Reconcile ADR and requirement evidence**

Add final dependency admission and acceptance references to Decision 0041. Update the existing `DM-7-09`/`DM-7-10` and `DM-7-11`/`DM-7-14`/`DM-7-15`/`DM-7-18` narrative rows only with evidence emitted by the passing process and Go-client runs; retain `implemented-uncredited` or `observed-bounded` status unless the exact matrix exit criterion is independently satisfied. Keep protected-provider, namespace deployment, service-manager, physical/mixed-network, packaging, and release gates open and owned.

- [ ] **Step 4: Run documentation and traceability checks**

Run: `sh tools/check-agent-proto.sh && sh tools/check-agent-go-generated.sh && python3 tools/check-public-provenance.py && python3 tools/check-implementation-requirements.py && git diff --check`

Expected: all commands exit 0; the trace checker still reports exactly 348 matrix IDs and 137 exact selected mappings unless a separately reviewed baseline change has occurred.

- [ ] **Step 5: Commit executable documentation**

```bash
git add docs/reference/aster-agent-config-v1.md docs/quickstart/connect-agent.md docs/reference-index.md docs/implementation/requirements-status.md docs/decisions/0041-customer-operable-event-service.md
git commit -m "docs: publish customer Event service operations"
```

### Task 10: Full verification and review handoff

**Files:**
- Modify only files required to correct failures found by the commands below.

**Interfaces:**
- Consumes: all prior task commits.
- Produces: one clean branch with retained verification output and an explicit remaining-gates statement.

- [ ] **Step 1: Run formatting and focused failure-path tests**

Run: `cargo fmt --all -- --check && cargo test --locked -p aster-agent --all-targets --all-features && python3 -m unittest tools/test-aster-agent-process.py && go -C conformance/agent-go test ./...`

Expected: all commands exit 0 with no ignored customer-agent test.

- [ ] **Step 2: Run hostile-input coverage required by the repository**

Run: `mise run fuzz-smoke`

Expected: exit 0 because strict JSON, header parsing, and protocol-facing error detail changed hostile-input boundaries.

- [ ] **Step 3: Run real-process and full repository gates**

Run: `mise run agent-process-smoke && mise run check`

Expected: both commands exit 0. Preserve the process receipt in the repository's established retained-evidence form only if its environment and checker qualify it; otherwise report it as same-host bounded evidence.

- [ ] **Step 4: Inspect the final claim boundary**

If Steps 1-3 fail, return to the task that owns the failing file, add a focused regression there, use that task's explicit commit boundary, and rerun Steps 1-3 before continuing.

Run: `git status --short --branch && git log --oneline --decorate -12 && git diff origin/docs...HEAD --stat`

Expected: clean worktree; commits are limited to the Event-service runtime, conformance client, tests, and exact documentation. The handoff explicitly says that the protected production provider, dedicated namespace, service-manager artifacts, amd64/arm64 packaging, representative deployment, physical/mixed-network evidence, and release authorization remain open.

- [ ] **Step 5: Request code review before integration**

Use `superpowers:requesting-code-review` against the complete branch. Correct each verified blocker with a focused test and separate commit, rerun the affected command, then rerun `mise run check` before claiming completion.
