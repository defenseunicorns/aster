#![cfg(unix)]

use std::{
    fs,
    net::SocketAddr,
    os::unix::fs::PermissionsExt as _,
    path::{Path, PathBuf},
    sync::atomic::{AtomicU64, Ordering},
    sync::mpsc as std_mpsc,
    time::Duration,
};

use aster_agent::{
    config::{check_config, load_and_validate_config},
    credentials::{load_startup_credentials, open_node_config},
    lifecycle::FailureReason,
    runtime::{AgentExit, AgentRuntimeError, AgentSignal, run_customer_agent},
};
use aster_mesh::{
    ProvisioningLoadId, ProvisioningLoadReceipt, ProvisioningSecretLoader, ProvisioningSecretRef,
    ProvisioningSecretStoreError, UnprotectedProvisioning,
};
use buffa::Message as _;

static NEXT_FIXTURE: AtomicU64 = AtomicU64::new(0);

#[test]
fn customer_fixture_prepares_an_owner_only_state_directory() {
    // Break caught: leaving state creation to the node makes its security
    // depend on the test runner's ordinary process umask.
    let fixture = CustomerFixture::new();
    let metadata = fs::metadata(fixture.root.join("state")).expect("prepared state directory");
    assert!(metadata.is_dir());
    assert_eq!(metadata.permissions().mode() & 0o777, 0o700);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn startup_validates_credentials_before_binding_any_listener() {
    // Break caught: moving credential validation after listener binding exposes
    // health or application sockets for an invalid startup configuration.
    let fixture = CustomerFixture::new();
    fixture.write_token(b"invalid");
    let config = load_and_validate_config(fixture.config_path()).expect("validated config");
    let (_signals, receiver) = tokio::sync::mpsc::channel(4);
    let mut loader = RecordingLoader::new();

    let result = run_customer_agent(config, &mut loader, receiver).await;
    assert_eq!(
        result,
        Err(AgentRuntimeError::Credential(
            aster_agent::credentials::CredentialReason::InvalidToken,
        ))
    );
    assert_eq!(loader.calls(), 0);
    if socket_access_available() {
        std::net::TcpListener::bind(fixture.application()).expect("application was never bound");
        std::net::TcpListener::bind(fixture.health()).expect("health was never bound");
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn protected_bootstrap_finishes_before_any_listener_is_bound() {
    // Break caught: binding even the health listener before the protected
    // bundle is authenticated violates D06's fail-before-side-effects boundary.
    let sockets_available = socket_access_available();
    let fixture = CustomerFixture::new();
    let config = load_and_validate_config(fixture.config_path()).expect("validated config");
    let (entered_send, mut entered_receive) = tokio::sync::mpsc::unbounded_channel();
    let (release_send, release_receive) = std_mpsc::channel();
    let (signals, receiver) = tokio::sync::mpsc::channel(4);
    let task = tokio::spawn(async move {
        let mut loader = BlockingLoader {
            entered: entered_send,
            release: release_receive,
        };
        run_customer_agent(config, &mut loader, receiver).await
    });

    tokio::time::timeout(Duration::from_secs(2), entered_receive.recv())
        .await
        .expect("protected loader entry deadline")
        .expect("protected loader entered before listener bind");
    if sockets_available {
        let application_probe = std::net::TcpListener::bind(fixture.application())
            .expect("application remains unbound");
        let health_probe =
            std::net::TcpListener::bind(fixture.health()).expect("health remains unbound");
        drop((application_probe, health_probe));
    }
    release_send.send(()).expect("release protected bootstrap");
    if !sockets_available {
        assert_eq!(
            task.await.expect("runtime task joins"),
            Err(AgentRuntimeError::Listener(FailureReason::Startup))
        );
        return;
    }
    wait_until_ready(&fixture).await;
    assert_eq!(
        application_status(fixture.application(), fixture.token_bytes()).await,
        200
    );

    signals
        .send(AgentSignal::Terminate)
        .await
        .expect("request clean stop");
    assert_eq!(
        tokio::time::timeout(Duration::from_secs(5), task)
            .await
            .expect("clean stop deadline")
            .expect("runtime task joins")
            .expect("runtime result"),
        AgentExit::Clean
    );
    assert!(
        tokio::net::TcpStream::connect(fixture.health())
            .await
            .is_err()
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn rejected_protected_bootstrap_leaves_no_listener_or_state_side_effect() {
    // Break caught: recovering from a rejected provider only after opening
    // listeners or durable node state exposes a partially started service.
    let sockets_available = socket_access_available();
    let fixture = CustomerFixture::new();
    let config = load_and_validate_config(fixture.config_path()).expect("validated config");
    let (_signals, receiver) = tokio::sync::mpsc::channel(4);
    let mut loader = RejectingLoader;

    assert_eq!(
        run_customer_agent(config, &mut loader, receiver).await,
        Err(AgentRuntimeError::Bootstrap(
            aster_node::NodeBootstrapErrorKind::Rejected,
        ))
    );
    if sockets_available {
        std::net::TcpListener::bind(fixture.application()).expect("application was never bound");
        std::net::TcpListener::bind(fixture.health()).expect("health was never bound");
    }
    assert!(
        fs::read_dir(fixture.root.join("state"))
            .expect("inspect state directory")
            .next()
            .is_none(),
        "protected bootstrap failure must not create durable state"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn receive_only_starts_ready_and_accepts_local_publication() {
    // Break caught: parsing receive_only without wiring it through customer
    // startup can either fail readiness or accidentally disable the local API.
    if !socket_access_available() {
        return;
    }
    let fixture = CustomerFixture::new();
    fixture.set_emission_policy("receive_only");
    let running = RunningFixture::start(&fixture).await;

    assert_eq!(
        publish_event_status(fixture.application(), fixture.token_bytes()).await,
        200
    );
    assert_eq!(health_status(fixture.health(), "/readyz").await, 200);
    running.stop_clean().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn customer_operation_limits_process_preserves_over_limit_reopen() {
    // Break caught: customer startup defaults the selected quota, consumes its
    // emergency reserve, or treats a smaller reopen quota as ledger corruption.
    const CHILD: &str = "ASTER_TEST_OPERATION_LIMITS_CHILD";
    if std::env::var_os(CHILD).is_none() {
        let output = std::process::Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "customer_operation_limits_process_preserves_over_limit_reopen",
                "--nocapture",
            ])
            .env(CHILD, "1")
            .output()
            .expect("start customer runtime test process");
        assert!(
            output.status.success(),
            "child failed:\n{}\n{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        return;
    }
    assert!(
        socket_access_available(),
        "this process test requires loopback sockets"
    );
    for (records, bytes, ordinary, lower_records, lower_bytes) in [
        (6, 1_296, 4, 5, 1_296), // record quota, then retained count above the new maximum
        (10, 648, 2, 10, 486),   // byte quota, then retained bytes above the new maximum
    ] {
        let fixture = CustomerFixture::new();
        fixture.set_operation_limits(records, bytes, 2);
        let running = RunningFixture::start(&fixture).await;
        let mut originals = Vec::new();
        for key in 0..ordinary {
            let (status, response) = publish_operation(&fixture, key, false, false).await;
            assert_eq!(status, 200, "{response}");
            assert_eq!(response["inserted"], true);
            originals.push(response);
        }
        let (status, response) = publish_operation(&fixture, 8, false, false).await;
        assert_eq!(status, 429, "{response}");
        assert_eq!(response["message"], "durable operation capacity exhausted");
        for key in ordinary..ordinary + 2 {
            let (status, response) = publish_operation(&fixture, key, true, false).await;
            assert_eq!(status, 200, "reserved tombstone: {response}");
            originals.push(response);
        }
        let (status, response) = publish_operation(&fixture, 9, true, false).await;
        assert_eq!(status, 429, "{response}");
        assert_eq!(response["message"], "durable operation capacity exhausted");
        running.stop_clean().await;

        fixture.set_operation_limits(lower_records, lower_bytes, 2);
        let running = RunningFixture::start(&fixture).await;
        for (key, original) in originals.iter().enumerate() {
            let (status, response) = publish_operation(&fixture, key, key >= ordinary, false).await;
            assert_eq!(status, 200, "exact retained retry: {response}");
            assert_eq!(response["id"], original["id"]);
            assert_eq!(response["acceptanceMarker"], original["acceptanceMarker"]);
            // Proto JSON omits the default false value.
            assert!(!response["inserted"].as_bool().unwrap_or(false));
        }
        let (status, response) = publish_operation(&fixture, 0, false, true).await;
        assert_eq!(status, 409, "{response}");
        assert_eq!(
            response["message"],
            "operation key conflicts with an existing request"
        );
        for emergency in [false, true] {
            let (status, response) = publish_operation(&fixture, 8, emergency, false).await;
            assert_eq!(status, 429, "{response}");
            assert_eq!(response["message"], "durable operation capacity exhausted");
        }
        assert_eq!(health_status(fixture.health(), "/readyz").await, 200);
        running.stop_clean().await;
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn failed_hangup_keeps_the_old_token_and_readiness() {
    // Break caught: destructive or non-atomic reload revokes the working token
    // or drops readiness when the replacement file is invalid.
    if !socket_access_available() {
        return;
    }
    let fixture = CustomerFixture::new();
    let running = RunningFixture::start(&fixture).await;

    fixture.write_token(b"invalid");
    running
        .signals
        .send(AgentSignal::Hangup)
        .await
        .expect("request failed reload");
    tokio::time::sleep(Duration::from_millis(50)).await;
    assert_eq!(
        application_status(fixture.application(), fixture.token_bytes()).await,
        200
    );
    assert_eq!(health_status(fixture.health(), "/readyz").await, 200);
    running.stop_clean().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn successful_hangup_reloads_only_the_client_token_atomically() {
    // Break caught: reload reopens mission material or exposes a window where
    // neither the old nor fully validated replacement token authorizes.
    if !socket_access_available() {
        return;
    }
    let fixture = CustomerFixture::new();
    let old_token = fixture.token_bytes().to_vec();
    let running = RunningFixture::start(&fixture).await;
    fixture.write_reference(b"invalid-reference-canary");
    let replacement = b"replacement-client-token-00000001";
    fixture.write_token(replacement);

    running
        .signals
        .send(AgentSignal::Hangup)
        .await
        .expect("request token reload");
    wait_for_application_status(fixture.application(), replacement, 200).await;
    assert_eq!(
        application_status(fixture.application(), &old_token).await,
        401
    );
    assert_eq!(health_status(fixture.health(), "/readyz").await, 200);
    running.stop_clean().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn second_terminate_forces_a_blocked_graceful_drain() {
    // Break caught: ignoring the second termination signal can strand an
    // operator behind an in-flight connection until the whole grace expires.
    if !socket_access_available() {
        return;
    }
    let fixture = CustomerFixture::with_shutdown_grace(5_000);
    let running = RunningFixture::start(&fixture).await;
    let stalled = fill_unauthenticated_admission(fixture.application()).await;

    running
        .signals
        .send(AgentSignal::Terminate)
        .await
        .expect("begin drain");
    wait_for_health_status(fixture.health(), "/readyz", 503).await;
    running
        .signals
        .send(AgentSignal::Terminate)
        .await
        .expect("force drain");
    assert_eq!(running.finish().await, AgentExit::Forced);
    drop(stalled);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn grace_expiry_forces_a_blocked_graceful_drain() {
    // Break caught: waiting indefinitely for a stalled connection violates the
    // configured process shutdown bound.
    if !socket_access_available() {
        return;
    }
    let fixture = CustomerFixture::with_shutdown_grace(50);
    let running = RunningFixture::start(&fixture).await;
    let stalled = fill_unauthenticated_admission(fixture.application()).await;

    running
        .signals
        .send(AgentSignal::Terminate)
        .await
        .expect("begin drain");
    assert_eq!(running.finish().await, AgentExit::Forced);
    drop(stalled);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn admitted_publish_finishes_before_node_shutdown() {
    // Break caught: starting selected-node shutdown concurrently with HTTP
    // drain can reject a mutating unary request that already passed the
    // pre-body admission gate but has not finished decoding its body.
    if !socket_access_available() {
        return;
    }
    use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};

    let fixture = CustomerFixture::with_shutdown_grace(2_000);
    let running = RunningFixture::start(&fixture).await;
    let request = aster_agent::proto::aster::application::v1alpha1::PublishEventRequest {
        operation_key: b"drain-admitted-publication".to_vec(),
        topic: "chat.events".to_owned(),
        scope: "mission/team/alpha".to_owned(),
        priority: aster_agent::proto::aster::application::v1alpha1::Priority::Immediate.into(),
        logical_key: b"drain-message".to_vec(),
        payload: b"accepted before shutdown".to_vec(),
        ..Default::default()
    };
    let body = request.encode_to_vec();
    let mut connection = tokio::net::TcpStream::connect(fixture.application())
        .await
        .expect("connect admitted publish");
    connection
        .write_all(
            format!(
                "POST /aster.application.v1alpha1.AsterApplicationService/PublishEvent HTTP/1.1\r\nHost: localhost\r\nContent-Type: application/proto\r\nConnect-Protocol-Version: 1\r\nAuthorization: Bearer {}\r\nContent-Length: {}\r\nExpect: 100-continue\r\nConnection: close\r\n\r\n",
                String::from_utf8_lossy(fixture.token_bytes()),
                body.len(),
            )
            .as_bytes(),
        )
        .await
        .expect("write admitted publish headers");

    // Wait for body polling before issuing a competing one-slot status probe.
    // Otherwise that probe can win admission and reject the publish itself.
    let mut interim = Vec::new();
    tokio::time::timeout(Duration::from_secs(2), async {
        while !interim.ends_with(b"\r\n\r\n") {
            interim.push(connection.read_u8().await.expect("continue response byte"));
            assert!(interim.len() <= 1024);
        }
    })
    .await
    .expect("continue response deadline");
    assert!(interim.starts_with(b"HTTP/1.1 100"));

    // With one global in-flight slot, a rejected status probe proves the
    // Publish headers passed the gate and its permit is held before draining.
    wait_for_application_status(fixture.application(), fixture.token_bytes(), 429).await;
    running
        .signals
        .send(AgentSignal::Terminate)
        .await
        .expect("begin drain");
    wait_for_health_status(fixture.health(), "/readyz", 503).await;
    connection
        .write_all(&body)
        .await
        .expect("finish admitted publish body");

    let mut response = Vec::new();
    tokio::time::timeout(
        Duration::from_secs(2),
        connection.read_to_end(&mut response),
    )
    .await
    .expect("admitted publish response deadline")
    .expect("read admitted publish response");
    assert_eq!(
        http_response_status(&response),
        200,
        "admitted publish response: {}",
        String::from_utf8_lossy(&response)
    );
    let response_body = chunked_response_body(&response);
    let published =
        aster_agent::proto::aster::application::v1alpha1::PublishEventResponse::decode_from_slice(
            &response_body,
        )
        .expect("decode admitted publish response");
    assert!(published.inserted);
    assert_eq!(running.finish().await, AgentExit::Clean);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn closed_signal_task_propagates_only_a_bounded_failure_reason() {
    // Break caught: losing the signal task without a terminal transition can
    // leave the process serving forever or expose an internal channel error.
    if !socket_access_available() {
        return;
    }
    let fixture = CustomerFixture::new();
    let running = RunningFixture::start(&fixture).await;
    let RunningFixture { signals, task } = running;
    drop(signals);
    assert_eq!(
        finish_runtime(task).await,
        AgentExit::Failed(FailureReason::Runtime)
    );
}

#[test]
fn config_check_validates_files_without_a_provider_and_bootstrap_uses_exact_reference() {
    // Break caught: configuration checking that skips credential-file safety
    // accepts an unsafe provider capability; bootstrap that substitutes a
    // reference or operation directs the provider to the wrong secret.
    let fixture = CustomerFixture::new();
    let expected_reference = fixture.reference();
    let expected_operation = ProvisioningLoadId::new([0x11; 32]);
    let mut loader = RecordingLoader::new();

    check_config(fixture.config_path()).expect("valid customer configuration");
    assert_eq!(loader.calls(), 0);

    fixture.chmod_reference(0o640);
    assert!(check_config(fixture.config_path()).is_err());
    assert_eq!(loader.calls(), 0);
    fixture.chmod_reference(0o600);

    let config = load_and_validate_config(fixture.config_path()).expect("validated config");
    let credentials =
        load_startup_credentials(config.credential_paths()).expect("startup credentials");
    open_node_config(&config, &credentials, &mut loader).expect("protected node config");
    assert_eq!(loader.calls(), 1);
    assert_eq!(loader.last_reference(), Some(&expected_reference));
    assert_eq!(loader.last_operation(), Some(expected_operation));
}

#[test]
fn bootstrap_failure_redacts_the_provider_reference() {
    // Break caught: forwarding provider detail or the opaque reference from a
    // failed bootstrap would expose a customer credential in diagnostics.
    let fixture = CustomerFixture::new();
    let config = load_and_validate_config(fixture.config_path()).expect("validated config");
    let credentials =
        load_startup_credentials(config.credential_paths()).expect("startup credentials");
    let mut loader = RejectingLoader;

    let error = open_node_config(&config, &credentials, &mut loader)
        .expect_err("provider rejection must not become a node configuration");
    let rendered = format!("{error:?} {error}");
    assert_eq!(error.kind(), aster_node::NodeBootstrapErrorKind::Rejected);
    assert!(!rendered.contains("customer-provider-capability"));
    assert!(!rendered.contains(&fixture.mission_reference.display().to_string()));
}

struct CustomerFixture {
    root: PathBuf,
    config: PathBuf,
    token: PathBuf,
    mission_reference: PathBuf,
    reference: ProvisioningSecretRef,
    application: SocketAddr,
    health: SocketAddr,
}

impl CustomerFixture {
    fn new() -> Self {
        Self::with_shutdown_grace(1_000)
    }

    fn with_shutdown_grace(shutdown_grace_ms: u64) -> Self {
        let sequence = NEXT_FIXTURE.fetch_add(1, Ordering::Relaxed);
        let nonce = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("system time")
            .as_nanos();
        let root = std::env::temp_dir().join(format!(
            "aster-agent-customer-runtime-{}-{nonce}-{sequence}",
            std::process::id()
        ));
        fs::create_dir(&root).expect("create fixture root");
        fs::set_permissions(&root, fs::Permissions::from_mode(0o700))
            .expect("protect fixture root");
        let state = root.join("state");
        fs::create_dir(&state).expect("create fixture state directory");
        fs::set_permissions(&state, fs::Permissions::from_mode(0o700))
            .expect("protect fixture state directory");

        let token = root.join("client-token");
        fs::write(&token, b"0123456789abcdef0123456789abcdef\n").expect("write token");
        fs::set_permissions(&token, fs::Permissions::from_mode(0o600)).expect("protect token");

        let mission_reference = root.join("mission-reference");
        let reference =
            ProvisioningSecretRef::from_opaque(b"customer-provider-capability".to_vec())
                .expect("valid reference");
        fs::write(&mission_reference, reference.to_bytes()).expect("write reference");
        fs::set_permissions(&mission_reference, fs::Permissions::from_mode(0o600))
            .expect("protect reference");

        let application = unused_address();
        let health = unused_address();
        assert_ne!(application, health);
        let config = root.join("agent.json");
        fs::write(
            &config,
            format!(
                r#"{{"schema_version":1,"state":{{"directory":"{}"}},"application":{{"listen":"{application}"}},"health":{{"listen":"{health}"}},"mesh":{{"bind":"127.0.0.1:0","sync_interval_ms":500,"emission_policy":"normal","peers":[]}},"credentials":{{"client_token_file":"{}","mission_secret_ref_file":"{}","mission_load_id":"{}"}},"storage":{{"max_items":10000,"max_payload_bytes":67108864,"operations":{{"max_records":1000000,"max_logical_bytes":201326592,"emergency_reserve":10000}}}},"limits":{{"max_in_flight_requests":1,"shutdown_grace_ms":{shutdown_grace_ms}}}}}"#,
                state.display(),
                token.display(),
                mission_reference.display(),
                "11".repeat(32),
            ),
        )
        .expect("write customer configuration");

        Self {
            root,
            config,
            token,
            mission_reference,
            reference,
            application,
            health,
        }
    }

    fn config_path(&self) -> &Path {
        &self.config
    }

    fn reference(&self) -> ProvisioningSecretRef {
        self.reference.clone()
    }

    fn application(&self) -> SocketAddr {
        self.application
    }

    fn health(&self) -> SocketAddr {
        self.health
    }

    fn token_bytes(&self) -> &[u8] {
        b"0123456789abcdef0123456789abcdef"
    }

    fn write_token(&self, token: &[u8]) {
        fs::write(&self.token, token).expect("replace token");
        fs::set_permissions(&self.token, fs::Permissions::from_mode(0o600))
            .expect("protect replacement token");
    }

    fn write_reference(&self, reference: &[u8]) {
        fs::write(&self.mission_reference, reference).expect("replace mission reference");
        fs::set_permissions(&self.mission_reference, fs::Permissions::from_mode(0o600))
            .expect("protect replacement mission reference");
    }

    fn set_emission_policy(&self, policy: &str) {
        let mut config: serde_json::Value =
            serde_json::from_slice(&fs::read(&self.config).expect("read customer config"))
                .expect("parse customer config");
        config["mesh"]["emission_policy"] = policy.into();
        fs::write(
            &self.config,
            serde_json::to_vec(&config).expect("encode customer config"),
        )
        .expect("write customer config");
    }

    fn chmod_reference(&self, mode: u32) {
        fs::set_permissions(&self.mission_reference, fs::Permissions::from_mode(mode))
            .expect("change reference permissions");
    }

    fn set_operation_limits(&self, records: u64, bytes: u64, reserve: u64) {
        let mut config: serde_json::Value =
            serde_json::from_slice(&fs::read(&self.config).unwrap()).unwrap();
        config["storage"]["operations"] = serde_json::json!({
            "max_records": records, "max_logical_bytes": bytes, "emergency_reserve": reserve,
        });
        fs::write(&self.config, serde_json::to_vec(&config).unwrap()).unwrap();
    }
}

fn unused_address() -> SocketAddr {
    static NEXT_PORT: AtomicU64 = AtomicU64::new(40_000);
    match std::net::TcpListener::bind("127.0.0.1:0") {
        Ok(listener) => listener.local_addr().expect("test address"),
        Err(error) if error.kind() == std::io::ErrorKind::PermissionDenied => {
            let port = NEXT_PORT.fetch_add(1, Ordering::Relaxed) as u16;
            SocketAddr::from(([127, 0, 0, 1], port))
        }
        Err(error) => panic!("reserve test address: {error}"),
    }
}

fn socket_access_available() -> bool {
    match std::net::TcpListener::bind("127.0.0.1:0") {
        Ok(_) => true,
        Err(error) if error.kind() == std::io::ErrorKind::PermissionDenied => {
            eprintln!("SKIP live customer runtime: loopback sockets denied by sandbox");
            false
        }
        Err(error) => panic!("probe loopback socket access: {error}"),
    }
}

struct RunningFixture {
    signals: tokio::sync::mpsc::Sender<AgentSignal>,
    task: tokio::task::JoinHandle<Result<AgentExit, AgentRuntimeError>>,
}

impl RunningFixture {
    async fn start(fixture: &CustomerFixture) -> Self {
        let config = load_and_validate_config(fixture.config_path()).expect("validated config");
        let (signals, receiver) = tokio::sync::mpsc::channel(4);
        let task = tokio::spawn(async move {
            let mut loader = RecordingLoader::new();
            run_customer_agent(config, &mut loader, receiver).await
        });
        wait_until_ready(fixture).await;
        Self { signals, task }
    }

    async fn stop_clean(self) {
        self.signals
            .send(AgentSignal::Terminate)
            .await
            .expect("request clean stop");
        assert_eq!(self.finish().await, AgentExit::Clean);
    }

    async fn finish(self) -> AgentExit {
        finish_runtime(self.task).await
    }
}

async fn finish_runtime(
    task: tokio::task::JoinHandle<Result<AgentExit, AgentRuntimeError>>,
) -> AgentExit {
    tokio::time::timeout(Duration::from_secs(5), task)
        .await
        .expect("runtime completion deadline")
        .expect("runtime task joins")
        .expect("runtime result")
}

struct BlockingLoader {
    entered: tokio::sync::mpsc::UnboundedSender<()>,
    release: std_mpsc::Receiver<()>,
}

impl ProvisioningSecretLoader for BlockingLoader {
    fn load(
        &mut self,
        operation: ProvisioningLoadId,
        reference: &ProvisioningSecretRef,
    ) -> Result<ProvisioningLoadReceipt, ProvisioningSecretStoreError> {
        self.entered.send(()).expect("announce loader entry");
        self.release.recv().expect("wait for loader release");
        test_load_receipt(operation, reference)
    }
}

async fn wait_until_ready(fixture: &CustomerFixture) {
    wait_for_health_status(fixture.health(), "/readyz", 200).await;
}

async fn fill_unauthenticated_admission(address: SocketAddr) -> Vec<tokio::net::TcpStream> {
    use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};

    let limit = aster_agent::config::AgentLimits::default().max_unauthenticated_connections();
    let mut admitted = Vec::with_capacity(limit);
    for _ in 0..limit {
        let mut stream = tokio::net::TcpStream::connect(address)
            .await
            .expect("open admitted incomplete connection");
        stream
            .write_all(b"G")
            .await
            .expect("start incomplete request");
        admitted.push(stream);
    }

    let mut refused = tokio::net::TcpStream::connect(address)
        .await
        .expect("kernel accepts saturation probe");
    refused
        .write_all(b"G")
        .await
        .expect("write saturation probe");
    let mut byte = [0_u8; 1];
    match tokio::time::timeout(Duration::from_secs(1), refused.read(&mut byte))
        .await
        .expect("saturation probe is refused promptly")
    {
        Ok(0) => {}
        Err(error) if error.kind() == std::io::ErrorKind::ConnectionReset => {}
        Ok(read) => panic!("saturation probe received {read} response bytes"),
        Err(error) => panic!("unexpected saturation refusal: {error}"),
    }
    admitted
}

async fn wait_for_health_status(address: SocketAddr, path: &str, expected: u16) {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
    loop {
        if tokio::time::Instant::now() >= deadline {
            panic!("health endpoint did not reach {expected}");
        }
        if health_status(address, path).await == expected {
            return;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
}

async fn wait_for_application_status(address: SocketAddr, token: &[u8], expected: u16) {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
    loop {
        if tokio::time::Instant::now() >= deadline {
            panic!("application endpoint did not reach {expected}");
        }
        if application_status(address, token).await == expected {
            return;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
}

async fn health_status(address: SocketAddr, path: &str) -> u16 {
    http_status(
        address,
        format!("GET {path} HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n").as_bytes(),
    )
    .await
}

async fn application_status(address: SocketAddr, token: &[u8]) -> u16 {
    http_status(
        address,
        format!(
            "POST /aster.application.v1alpha1.AsterApplicationService/GetStatus HTTP/1.1\r\nHost: localhost\r\nContent-Type: application/proto\r\nConnect-Protocol-Version: 1\r\nAuthorization: Bearer {}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
            String::from_utf8_lossy(token),
        )
        .as_bytes(),
    )
    .await
}

async fn publish_event_status(address: SocketAddr, token: &[u8]) -> u16 {
    let body = serde_json::to_vec(&serde_json::json!({
        "operationKey": "cmVjZWl2ZS1vbmx5LWxvY2FsLXB1YmxpY2F0aW9u",
        "topic": "chat.events",
        "scope": "mission/team/alpha",
        "priority": "PRIORITY_IMMEDIATE",
        "logicalKey": "cmVjZWl2ZS1vbmx5LWxvY2FsLWtleQ==",
        "payload": "YWNjZXB0ZWQgd2l0aG91dCBvdXRib3VuZCBlbWlzc2lvbg=="
    }))
    .expect("encode publication request");
    http_status(
        address,
        format!(
            "POST /aster.application.v1alpha1.AsterApplicationService/PublishEvent HTTP/1.1\r\nHost: localhost\r\nContent-Type: application/json\r\nAuthorization: Bearer {}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
            String::from_utf8_lossy(token),
            body.len(),
            String::from_utf8_lossy(&body),
        )
        .as_bytes(),
    )
    .await
}

async fn http_status(address: SocketAddr, request: &[u8]) -> u16 {
    let response = http_response(address, request).await;
    if response.is_empty() {
        return 0;
    }
    http_response_status(&response)
}

async fn publish_operation(
    fixture: &CustomerFixture,
    key: usize,
    tombstone: bool,
    changed: bool,
) -> (u16, serde_json::Value) {
    // Base64 encoding of one distinct byte per operation key (0 through 9).
    let keys = [
        "AA==", "AQ==", "Ag==", "Aw==", "BA==", "BQ==", "Bg==", "Bw==", "CA==", "CQ==",
    ];
    let body = serde_json::json!({
        "operationKey": keys[key], "topic": "chat.events", "scope": "mission/team/alpha",
        "priority": "PRIORITY_IMMEDIATE", "logicalKey": keys[key],
        "payload": if tombstone { "" } else if changed { "dHdv" } else { "b25l" },
        "tombstone": tombstone,
    })
    .to_string();
    let request = format!(
        "POST /aster.application.v1alpha1.AsterApplicationService/PublishEvent HTTP/1.1\r\nHost: localhost\r\nContent-Type: application/json\r\nAuthorization: Bearer {}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
        String::from_utf8_lossy(fixture.token_bytes()),
        body.len(),
        body,
    );
    let response = http_response(fixture.application(), request.as_bytes()).await;
    let offset = response
        .windows(4)
        .position(|window| window == b"\r\n\r\n")
        .unwrap()
        + 4;
    let body = if String::from_utf8_lossy(&response[..offset])
        .to_ascii_lowercase()
        .contains("transfer-encoding: chunked")
    {
        chunked_response_body(&response)
    } else {
        response[offset..].to_vec()
    };
    (
        http_response_status(&response),
        serde_json::from_slice(&body).expect("publication response"),
    )
}

async fn http_response(address: SocketAddr, request: &[u8]) -> Vec<u8> {
    use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};

    let Ok(mut stream) = tokio::net::TcpStream::connect(address).await else {
        return Vec::new();
    };
    stream.write_all(request).await.expect("write HTTP request");
    let mut response = Vec::new();
    tokio::time::timeout(Duration::from_secs(2), stream.read_to_end(&mut response))
        .await
        .expect("HTTP response deadline")
        .expect("read HTTP response");
    response
}

fn http_response_status(response: &[u8]) -> u16 {
    String::from_utf8_lossy(response)
        .split_whitespace()
        .nth(1)
        .expect("HTTP status")
        .parse()
        .expect("numeric HTTP status")
}

fn chunked_response_body(response: &[u8]) -> Vec<u8> {
    let body_offset = response
        .windows(4)
        .position(|window| window == b"\r\n\r\n")
        .map(|offset| offset + 4)
        .expect("HTTP response body");
    let mut encoded = &response[body_offset..];
    let mut decoded = Vec::new();
    loop {
        let size_end = encoded
            .windows(2)
            .position(|window| window == b"\r\n")
            .expect("chunk size terminator");
        let size = usize::from_str_radix(
            std::str::from_utf8(&encoded[..size_end]).expect("ASCII chunk size"),
            16,
        )
        .expect("hexadecimal chunk size");
        encoded = &encoded[size_end + 2..];
        if size == 0 {
            break;
        }
        decoded.extend_from_slice(&encoded[..size]);
        encoded = &encoded[size + 2..];
    }
    decoded
}

impl Drop for CustomerFixture {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.root);
    }
}

struct RecordingLoader {
    calls: usize,
    operation: Option<ProvisioningLoadId>,
    reference: Option<ProvisioningSecretRef>,
}

impl RecordingLoader {
    fn new() -> Self {
        Self {
            calls: 0,
            operation: None,
            reference: None,
        }
    }

    fn calls(&self) -> usize {
        self.calls
    }

    fn last_operation(&self) -> Option<ProvisioningLoadId> {
        self.operation
    }

    fn last_reference(&self) -> Option<&ProvisioningSecretRef> {
        self.reference.as_ref()
    }
}

impl ProvisioningSecretLoader for RecordingLoader {
    fn load(
        &mut self,
        operation: ProvisioningLoadId,
        reference: &ProvisioningSecretRef,
    ) -> Result<ProvisioningLoadReceipt, ProvisioningSecretStoreError> {
        self.calls += 1;
        self.operation = Some(operation);
        self.reference = Some(reference.clone());
        test_load_receipt(operation, reference)
    }
}

fn test_load_receipt(
    operation: ProvisioningLoadId,
    reference: &ProvisioningSecretRef,
) -> Result<ProvisioningLoadReceipt, ProvisioningSecretStoreError> {
    let bundle = include_bytes!("../../../bindings/testdata/non-production-provisioning.bundle");
    Ok(ProvisioningLoadReceipt::new(
        operation,
        reference.clone(),
        UnprotectedProvisioning::new(bundle.to_vec())
            .expect("bounded disposable public test provisioning"),
    ))
}

struct RejectingLoader;

impl ProvisioningSecretLoader for RejectingLoader {
    fn load(
        &mut self,
        _operation: ProvisioningLoadId,
        _reference: &ProvisioningSecretRef,
    ) -> Result<ProvisioningLoadReceipt, ProvisioningSecretStoreError> {
        Err(ProvisioningSecretStoreError::Rejected)
    }
}
