//! Unprotected, test-only process fixture for Aster agent acceptance.
//!
//! This binary is feature-gated out of normal builds. Its file-backed loader
//! is deliberately not a production provider and makes no custody, recovery,
//! deployment-isolation, or physical-erasure claim.

use std::{
    env,
    fs::{self, OpenOptions},
    io::{Read as _, Write as _},
    net::{SocketAddr, TcpListener},
    path::{Path, PathBuf},
    process::ExitCode,
    time::Duration,
};

use aster_agent::{
    config::{check_config, load_and_validate_config},
    proto::aster::application::v1alpha1 as api,
    runtime::{AgentExit, AgentSignal, run_customer_agent},
};
use aster_mesh::{
    MAX_UNPROTECTED_PROVISIONING_BYTES, ProvisioningLoadId, ProvisioningLoadReceipt,
    ProvisioningSecretLoader, ProvisioningSecretRef, ProvisioningSecretStoreError,
    UnprotectedProvisioning,
};
use connectrpc::{
    ConnectError,
    client::{ClientConfig, Http2Connection},
};
use serde::{Deserialize, de::DeserializeOwned};
use serde_json::json;

const MAX_CLIENT_INPUT_BYTES: u64 = 64 * 1024;
const MAX_CLIENT_TIMEOUT_SECONDS: u64 = 120;
const TEST_STORAGE_MAX_ITEMS: u32 = 10_000;
const TEST_STORAGE_MAX_PAYLOAD_BYTES: u64 = 64 * 1024 * 1024;
const TEST_SHUTDOWN_GRACE_MS: u64 = 10_000;
const EVENT_OPERATION_HARD_ROWS: u64 = 1_000_000;
const EVENT_OPERATION_HARD_BYTES: u64 = 201_326_592;
const EVENT_OPERATION_WARNING_ROWS: u64 = 512;
const EVENT_OPERATION_PROFILE_ROWS: u64 = 1_024;
const EVENT_DELIVERY_PROFILE_ROWS: u64 = 256;
const EVENT_DELIVERY_HARD_ROWS: u64 = 262_144;
const INITIAL_TOKEN: &[u8] = b"SECRET_TOKEN_CANARY_0123456789ABCDEF";

fn main() -> ExitCode {
    let arguments = env::args().skip(1).collect::<Vec<_>>();
    if arguments
        .first()
        .is_some_and(|argument| argument == "--check-config")
    {
        return run_config_check_process(&arguments);
    }
    if arguments
        .first()
        .is_some_and(|argument| argument == "--config")
    {
        return run_agent_process(&arguments);
    }
    if arguments
        .first()
        .is_some_and(|argument| argument == "prepare")
    {
        return match prepare_fixture(&arguments[1..]) {
            Ok(()) => {
                println!(
                    "TEST_FIXTURE status=prepared provisioning=unprotected-test-provider-only"
                );
                ExitCode::SUCCESS
            }
            Err(()) => {
                eprintln!("ERROR unprotected test fixture preparation failed");
                ExitCode::FAILURE
            }
        };
    }
    run_client_process(&arguments)
}

fn run_config_check_process(arguments: &[String]) -> ExitCode {
    match check_config_arguments(arguments) {
        Ok(()) => ExitCode::SUCCESS,
        Err(()) => {
            eprintln!("ERROR configuration check failed");
            ExitCode::FAILURE
        }
    }
}

fn check_config_arguments(arguments: &[String]) -> Result<(), ()> {
    if arguments.len() != 2 || arguments[0] != "--check-config" {
        return Err(());
    }
    check_config(Path::new(&arguments[1])).map_err(|_| ())
}

fn run_agent_process(arguments: &[String]) -> ExitCode {
    if arguments.len() != 2 || arguments[0] != "--config" {
        eprintln!("ERROR unprotected test fixture arguments are invalid");
        return ExitCode::FAILURE;
    }
    let config = match load_and_validate_config(Path::new(&arguments[1])) {
        Ok(config) => config,
        Err(_) => {
            eprintln!("ERROR unprotected test fixture configuration failed");
            return ExitCode::FAILURE;
        }
    };
    let (runtime, signals) = match build_runtime_and_signals() {
        Ok(runtime_and_signals) => runtime_and_signals,
        Err(_) => {
            eprintln!("ERROR unprotected test fixture runtime or signal setup failed");
            return ExitCode::FAILURE;
        }
    };
    eprintln!("TEST_PROVIDER kind=unprotected-test-only customer-provider=false");
    let mut loader = UnprotectedTestFileLoader;
    match runtime.block_on(run_customer_agent(config, &mut loader, signals)) {
        Ok(AgentExit::Clean) => ExitCode::SUCCESS,
        Ok(AgentExit::Forced) => ExitCode::from(2),
        Ok(AgentExit::Failed(_)) | Err(_) => {
            eprintln!("ERROR unprotected test fixture agent failed");
            ExitCode::FAILURE
        }
    }
}

fn build_runtime_and_signals() -> Result<
    (
        tokio::runtime::Runtime,
        tokio::sync::mpsc::Receiver<AgentSignal>,
    ),
    (),
> {
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .map_err(|_| ())?;
    let guard = runtime.enter();
    let signals = translated_signals()?;
    drop(guard);
    Ok((runtime, signals))
}

struct UnprotectedTestFileLoader;

impl ProvisioningSecretLoader for UnprotectedTestFileLoader {
    fn load(
        &mut self,
        operation: ProvisioningLoadId,
        secret_ref: &ProvisioningSecretRef,
    ) -> Result<ProvisioningLoadReceipt, ProvisioningSecretStoreError> {
        let plaintext = load_unprotected_test_bundle(secret_ref)
            .map_err(|()| ProvisioningSecretStoreError::Rejected)?;
        Ok(ProvisioningLoadReceipt::new(
            operation,
            secret_ref.clone(),
            plaintext,
        ))
    }
}

#[cfg(unix)]
fn load_unprotected_test_bundle(
    secret_ref: &ProvisioningSecretRef,
) -> Result<UnprotectedProvisioning, ()> {
    use std::os::unix::{
        ffi::OsStrExt as _,
        fs::{MetadataExt as _, OpenOptionsExt as _, PermissionsExt as _},
    };

    let path = PathBuf::from(std::ffi::OsStr::from_bytes(secret_ref.expose_opaque()));
    if !path.is_absolute() || fs::canonicalize(&path).map_err(|_| ())? != path {
        return Err(());
    }
    let mut file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW)
        .open(&path)
        .map_err(|_| ())?;
    let before = file.metadata().map_err(|_| ())?;
    if !before.is_file()
        || before.uid() != rustix::process::geteuid().as_raw()
        || before.permissions().mode() & 0o077 != 0
        || before.len() > MAX_UNPROTECTED_PROVISIONING_BYTES as u64
    {
        return Err(());
    }
    let mut bytes = Vec::with_capacity(usize::try_from(before.len()).map_err(|_| ())?);
    std::io::Read::take(&mut file, MAX_UNPROTECTED_PROVISIONING_BYTES as u64 + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| ())?;
    let after = file.metadata().map_err(|_| ())?;
    if bytes.len() > MAX_UNPROTECTED_PROVISIONING_BYTES
        || before.dev() != after.dev()
        || before.ino() != after.ino()
        || before.len() != after.len()
        || before.mtime() != after.mtime()
        || before.mtime_nsec() != after.mtime_nsec()
    {
        return Err(());
    }
    UnprotectedProvisioning::new(bytes).map_err(|_| ())
}

#[cfg(not(unix))]
fn load_unprotected_test_bundle(
    _secret_ref: &ProvisioningSecretRef,
) -> Result<UnprotectedProvisioning, ()> {
    Err(())
}

#[cfg(unix)]
fn translated_signals() -> Result<tokio::sync::mpsc::Receiver<AgentSignal>, ()> {
    use tokio::signal::unix::{SignalKind, signal};

    let mut hangup = signal(SignalKind::hangup()).map_err(|_| ())?;
    let mut interrupt = signal(SignalKind::interrupt()).map_err(|_| ())?;
    let mut terminate = signal(SignalKind::terminate()).map_err(|_| ())?;
    let (sender, receiver) = tokio::sync::mpsc::channel(4);
    tokio::spawn(async move {
        loop {
            let translated = tokio::select! {
                received = hangup.recv() => received.map(|()| AgentSignal::Hangup),
                received = interrupt.recv() => received.map(|()| AgentSignal::Terminate),
                received = terminate.recv() => received.map(|()| AgentSignal::Terminate),
            };
            let Some(translated) = translated else {
                return;
            };
            if sender.send(translated).await.is_err() {
                return;
            }
        }
    });
    Ok(receiver)
}

#[cfg(not(unix))]
fn translated_signals() -> Result<tokio::sync::mpsc::Receiver<AgentSignal>, ()> {
    Err(())
}

fn prepare_fixture(arguments: &[String]) -> Result<(), ()> {
    if arguments.len() != 2 || arguments[0] != "--root" {
        return Err(());
    }
    let root = fs::canonicalize(&arguments[1]).map_err(|_| ())?;
    if !root.is_dir() {
        return Err(());
    }
    protect_directory(&root)?;
    let state = root.join("SECRET_PATH_CANARY-state");
    fs::create_dir(&state).map_err(|_| ())?;
    protect_directory(&state)?;

    let token = root.join("SECRET_PATH_CANARY-client-token");
    write_owner_only(&token, &[INITIAL_TOKEN, b"\n"].concat())?;
    let bundle = root.join("SECRET_PATH_CANARY-mission-bundle");
    write_owner_only(
        &bundle,
        include_bytes!("../../../../bindings/testdata/non-production-provisioning.bundle"),
    )?;
    let bundle = fs::canonicalize(bundle).map_err(|_| ())?;
    let reference = reference_for_path(&bundle)?;
    let reference_file = root.join("SECRET_PATH_CANARY-mission-reference");
    write_owner_only(&reference_file, &reference.to_bytes())?;

    let application = unused_address()?;
    let health = unused_address()?;
    if application == health {
        return Err(());
    }
    let carrier = aster_iroh::SecretKey::from_bytes(&[41; 32]).public();
    let peer = format!("{carrier}@127.0.0.1:9={}", "2a".repeat(32));
    let config = json!({
        "schema_version": 1,
        "state": {"directory": path_text(&state)?},
        "application": {"listen": application.to_string()},
        "health": {"listen": health.to_string()},
        "mesh": {
            "bind": "127.0.0.1:0",
            "sync_interval_ms": 500,
            "emission_policy": "normal",
            "peers": [peer]
        },
        "credentials": {
            "client_token_file": path_text(&token)?,
            "mission_secret_ref_file": path_text(&reference_file)?,
            "mission_load_id": "11".repeat(32)
        },
        "storage": {
            "max_items": TEST_STORAGE_MAX_ITEMS,
            "max_payload_bytes": TEST_STORAGE_MAX_PAYLOAD_BYTES,
            "operations": {
                "max_records": 1_000_000,
                "max_logical_bytes": 201_326_592,
                "emergency_reserve": 10_000
            }
        },
        "limits": {"shutdown_grace_ms": TEST_SHUTDOWN_GRACE_MS}
    });
    write_owner_only(
        &root.join("agent.json"),
        &serde_json::to_vec(&config).map_err(|_| ())?,
    )?;
    Ok(())
}

#[cfg(unix)]
fn reference_for_path(path: &Path) -> Result<ProvisioningSecretRef, ()> {
    use std::os::unix::ffi::OsStrExt as _;
    ProvisioningSecretRef::from_opaque(path.as_os_str().as_bytes().to_vec()).map_err(|_| ())
}

#[cfg(not(unix))]
fn reference_for_path(_path: &Path) -> Result<ProvisioningSecretRef, ()> {
    Err(())
}

fn path_text(path: &Path) -> Result<&str, ()> {
    path.to_str().ok_or(())
}

fn unused_address() -> Result<SocketAddr, ()> {
    let listener = TcpListener::bind("127.0.0.1:0").map_err(|_| ())?;
    listener.local_addr().map_err(|_| ())
}

#[cfg(unix)]
fn protect_directory(path: &Path) -> Result<(), ()> {
    use std::os::unix::fs::PermissionsExt as _;
    fs::set_permissions(path, fs::Permissions::from_mode(0o700)).map_err(|_| ())
}

#[cfg(not(unix))]
fn protect_directory(_path: &Path) -> Result<(), ()> {
    Err(())
}

#[cfg(unix)]
fn write_owner_only(path: &Path, bytes: &[u8]) -> Result<(), ()> {
    use std::os::unix::fs::{OpenOptionsExt as _, PermissionsExt as _};
    let mut file = OpenOptions::new()
        .create_new(true)
        .write(true)
        .mode(0o600)
        .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW)
        .open(path)
        .map_err(|_| ())?;
    file.write_all(bytes).map_err(|_| ())?;
    file.sync_all().map_err(|_| ())?;
    file.set_permissions(fs::Permissions::from_mode(0o600))
        .map_err(|_| ())
}

#[cfg(not(unix))]
fn write_owner_only(_path: &Path, _bytes: &[u8]) -> Result<(), ()> {
    Err(())
}

struct ClientArguments {
    command: String,
    url: String,
    token_file: PathBuf,
    timeout: Duration,
}

impl ClientArguments {
    fn parse(arguments: &[String]) -> Result<Self, FixtureError> {
        let Some(command) = arguments.first() else {
            return Err(FixtureError::Local);
        };
        let mut url = None;
        let mut token_file = None;
        let mut timeout = None;
        let mut index = 1;
        while index < arguments.len() {
            if index + 1 >= arguments.len() {
                return Err(FixtureError::Local);
            }
            match arguments[index].as_str() {
                "--url" if url.is_none() => url = Some(arguments[index + 1].clone()),
                "--token-file" if token_file.is_none() => {
                    token_file = Some(PathBuf::from(&arguments[index + 1]));
                }
                "--timeout-seconds" if timeout.is_none() => {
                    let seconds = arguments[index + 1]
                        .parse::<u64>()
                        .map_err(|_| FixtureError::Local)?;
                    if !(1..=MAX_CLIENT_TIMEOUT_SECONDS).contains(&seconds) {
                        return Err(FixtureError::Local);
                    }
                    timeout = Some(Duration::from_secs(seconds));
                }
                _ => return Err(FixtureError::Local),
            }
            index += 2;
        }
        Ok(Self {
            command: command.clone(),
            url: url.ok_or(FixtureError::Local)?,
            token_file: token_file.ok_or(FixtureError::Local)?,
            timeout: timeout.ok_or(FixtureError::Local)?,
        })
    }
}

#[derive(Debug)]
enum FixtureError {
    Local,
    Connect(ConnectError),
}

impl From<ConnectError> for FixtureError {
    fn from(error: ConnectError) -> Self {
        Self::Connect(error)
    }
}

impl FixtureError {
    fn code(&self) -> String {
        match self {
            Self::Local => "internal".to_owned(),
            Self::Connect(error) => format!("{:?}", error.code).to_ascii_lowercase(),
        }
    }
}

fn run_client_process(arguments: &[String]) -> ExitCode {
    let options = match ClientArguments::parse(arguments) {
        Ok(options) => options,
        Err(error) => return client_failure(&error),
    };
    let runtime = match tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
    {
        Ok(runtime) => runtime,
        Err(_) => return client_failure(&FixtureError::Local),
    };
    match block_on_with_timeout(&runtime, options.timeout, run_client_command(&options)) {
        Ok(Ok(())) => ExitCode::SUCCESS,
        Ok(Err(error)) => client_failure(&error),
        Err(_) => client_failure(&FixtureError::Local),
    }
}

fn block_on_with_timeout<F>(
    runtime: &tokio::runtime::Runtime,
    timeout: Duration,
    future: F,
) -> Result<F::Output, tokio::time::error::Elapsed>
where
    F: std::future::Future,
{
    runtime.block_on(async move { tokio::time::timeout(timeout, future).await })
}

fn client_failure(error: &FixtureError) -> ExitCode {
    eprintln!(
        "{}",
        serde_json::to_string(&json!({"status": "error", "code": error.code()}))
            .unwrap_or_else(|_| "{\"status\":\"error\",\"code\":\"internal\"}".to_owned())
    );
    ExitCode::FAILURE
}

async fn run_client_command(options: &ClientArguments) -> Result<(), FixtureError> {
    let token = read_owner_only_token(&options.token_file)?;
    let uri = options
        .url
        .parse::<http::Uri>()
        .map_err(|_| FixtureError::Local)?;
    let connection = Http2Connection::connect_plaintext(uri.clone())
        .await
        .map_err(|_| FixtureError::Local)?
        .shared(32);
    let client = api::AsterApplicationServiceClient::new(connection, client_config(uri, &token));
    match options.command.as_str() {
        "status" => client_status(&client).await,
        "publish" => client_publish(&client).await,
        "query" => client_query(&client).await,
        "subscribe" => client_subscribe(&client).await,
        "poll" => client_poll(&client).await,
        "stream" => client_stream(&client).await,
        "ack" => client_ack(&client).await,
        _ => Err(FixtureError::Local),
    }
}

type Client = api::AsterApplicationServiceClient<connectrpc::client::SharedHttp2Connection>;

fn client_config(uri: http::Uri, token: &[u8]) -> ClientConfig {
    ClientConfig::new(uri)
        .with_protocol(connectrpc::Protocol::Grpc)
        .with_default_header(
            "authorization",
            format!("Bearer {}", String::from_utf8_lossy(token)),
        )
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct StatusInput {
    #[serde(default)]
    repeat_until_error: bool,
}

async fn client_status(client: &Client) -> Result<(), FixtureError> {
    let input: StatusInput = read_client_input()?;
    let response = client
        .get_status(api::GetStatusRequest::default())
        .await?
        .into_owned();
    let evidence = status_evidence(&response)?;
    if !input.repeat_until_error {
        print_json(evidence)?;
        return Ok(());
    }
    print_json(json!({"status": "active", "activity": "unary"}))?;
    loop {
        let response = client
            .get_status(api::GetStatusRequest::default())
            .await?
            .into_owned();
        status_evidence(&response)?;
        tokio::time::sleep(Duration::from_millis(1)).await;
    }
}

fn emission_mode_name(
    value: buffa::EnumValue<api::EmissionMode>,
) -> Result<&'static str, FixtureError> {
    match value.as_known() {
        Some(api::EmissionMode::Normal) => Ok("normal"),
        Some(api::EmissionMode::ReceiveOnly) => Ok("receive_only"),
        Some(api::EmissionMode::Unspecified) | None => Err(FixtureError::Local),
    }
}

fn status_evidence(response: &api::GetStatusResponse) -> Result<serde_json::Value, FixtureError> {
    if !matches!(response.credential_generation.len(), 0 | 32) {
        return Err(FixtureError::Local);
    }
    let configured = emission_mode_name(response.configured_emission_mode)?;
    let effective = emission_mode_name(response.effective_emission_mode)?;
    let store = response
        .store_capacity
        .as_option()
        .ok_or(FixtureError::Local)?;
    let operations = response
        .publish_operation_capacity
        .as_option()
        .ok_or(FixtureError::Local)?;
    let operation_ledger_mode = if operations.ledger_mode == api::PublishOperationLedgerMode::Legacy
    {
        "legacy"
    } else if operations.ledger_mode == api::PublishOperationLedgerMode::Numbered {
        "numbered"
    } else {
        return Err(FixtureError::Local);
    };
    let deliveries = response
        .delivery_capacity
        .as_option()
        .ok_or(FixtureError::Local)?;
    if store.item_limit != u64::from(TEST_STORAGE_MAX_ITEMS)
        || store.payload_byte_limit != TEST_STORAGE_MAX_PAYLOAD_BYTES
        || store.items > store.item_limit
        || store.payload_bytes > store.payload_byte_limit
    {
        return Err(FixtureError::Local);
    }
    let remaining = EVENT_OPERATION_PROFILE_ROWS.saturating_sub(operations.rows);
    if operations.row_hard_limit != EVENT_OPERATION_HARD_ROWS
        || operations.byte_hard_limit != EVENT_OPERATION_HARD_BYTES
        || operations.profile_boundary != EVENT_OPERATION_PROFILE_ROWS
        || operations.profile_remaining != remaining
        || operations.profile_warning != (operations.rows >= EVENT_OPERATION_WARNING_ROWS)
        || operations.profile_exhausted != (operations.rows >= EVENT_OPERATION_PROFILE_ROWS)
    {
        return Err(FixtureError::Local);
    }
    let (warning, audit) = operation_health(operations)?;
    if deliveries.profile_boundary != EVENT_DELIVERY_PROFILE_ROWS
        || deliveries.hard_limit != EVENT_DELIVERY_HARD_ROWS
        || deliveries.profile_saturated != (deliveries.pending >= EVENT_DELIVERY_PROFILE_ROWS)
        || deliveries.pending > deliveries.hard_limit
    {
        return Err(FixtureError::Local);
    }
    let mut evidence = json!({
        "status": "ok",
        "configured_emission_mode": configured,
        "effective_emission_mode": effective,
        "store_items": store.items,
        "store_item_limit": store.item_limit,
        "store_payload_bytes": store.payload_bytes,
        "store_payload_byte_limit": store.payload_byte_limit,
        "operation_rows": operations.rows,
        "operation_bytes": operations.bytes,
        "operation_profile_remaining": operations.profile_remaining,
        "operation_profile_warning": operations.profile_warning,
        "operation_profile_exhausted": operations.profile_exhausted,
        "operation_ledger_mode": operation_ledger_mode,
        "operation_active_rows": operations.active_rows,
        "operation_retired_rows": operations.retired_rows,
        "operation_reverse_rows": operations.reverse_rows,
        "operation_numbered_clients": operations.numbered_clients,
        "operation_numbered_outstanding_results": operations.numbered_outstanding_results,
        "operation_numbered_reverse_rows": operations.numbered_reverse_rows,
        "operation_ordinary_remaining": operations.ordinary_remaining,
        "operation_emergency_remaining": operations.emergency_remaining,
        "operation_rolling_accept_rate": operations.rolling_accept_rate,
        "operation_estimated_seconds_to_exhaustion": operations.estimated_seconds_to_exhaustion,
        "operation_warning_state": warning,
        "operation_audit_state": audit,
        "operation_audit_scanned": operations.audit.as_option().ok_or(FixtureError::Local)?.scanned,
        "operation_audit_total": operations.audit.as_option().ok_or(FixtureError::Local)?.total,
        "pending_deliveries": deliveries.pending,
        "delivery_profile_saturated": deliveries.profile_saturated,
    });
    if !response.credential_generation.is_empty() {
        evidence.as_object_mut().ok_or(FixtureError::Local)?.insert(
            "credential_generation".to_owned(),
            lower_hex(&response.credential_generation).into(),
        );
    }
    Ok(evidence)
}

fn lower_hex(bytes: &[u8]) -> String {
    const LOWER_HEX: &[u8; 16] = b"0123456789abcdef";
    let mut encoded = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        encoded.push(char::from(LOWER_HEX[usize::from(byte >> 4)]));
        encoded.push(char::from(LOWER_HEX[usize::from(byte & 0x0f)]));
    }
    encoded
}

fn operation_health(
    operations: &api::PublishOperationCapacityStatus,
) -> Result<(&'static str, &'static str), FixtureError> {
    use aster_node::application::{EventOperationCapacity, EventOperationCapacityWarning};
    use aster_redb_store::{
        EventOperationLimits, EventOperationStats, NumberedEventOperationStats,
    };
    let capacity = if operations.ledger_mode == api::PublishOperationLedgerMode::Unspecified
        || operations.ledger_mode == api::PublishOperationLedgerMode::Legacy
    {
        if operations.active_rows.checked_add(operations.retired_rows) != Some(operations.rows)
            || operations.reverse_rows != operations.active_rows
            || u128::from(operations.bytes)
                != u128::from(operations.active_rows) * 162
                    + u128::from(operations.retired_rows) * 67
            || operations.numbered_clients != 0
            || operations.numbered_outstanding_results != 0
            || operations.numbered_reverse_rows != 0
        {
            return Err(FixtureError::Local);
        }
        EventOperationCapacity::new(
            EventOperationStats {
                records_total: operations.rows,
                records_active: operations.active_rows,
                records_retired: operations.retired_rows,
                reverse_rows: operations.reverse_rows,
                logical_bytes: operations.bytes,
            },
            EventOperationLimits::DEFAULT,
        )
    } else if operations.ledger_mode == api::PublishOperationLedgerMode::Numbered {
        if operations.active_rows != 0
            || operations.retired_rows != 0
            || operations.reverse_rows != 0
            || operations
                .numbered_clients
                .checked_add(operations.numbered_outstanding_results)
                != Some(operations.rows)
            || operations.numbered_reverse_rows != operations.numbered_outstanding_results
        {
            return Err(FixtureError::Local);
        }
        EventOperationCapacity::for_ledgers(
            EventOperationStats::default(),
            NumberedEventOperationStats {
                clients: operations.numbered_clients,
                outstanding_results: operations.numbered_outstanding_results,
                reverse_edges: operations.numbered_reverse_rows,
                logical_bytes: operations.bytes,
            },
            EventOperationLimits::DEFAULT,
        )
    } else {
        return Err(FixtureError::Local);
    };
    let (expected_warning, warning) = match capacity.warning {
        EventOperationCapacityWarning::Ok => (api::OperationCapacityWarning::Ok, "ok"),
        EventOperationCapacityWarning::Warning => {
            (api::OperationCapacityWarning::Warning, "warning")
        }
        EventOperationCapacityWarning::Critical => {
            (api::OperationCapacityWarning::Critical, "critical")
        }
        EventOperationCapacityWarning::Exhausted => {
            (api::OperationCapacityWarning::Exhausted, "exhausted")
        }
    };
    if operations.ordinary_remaining != capacity.ordinary_remaining
        || operations.emergency_remaining != capacity.emergency_remaining
        || operations.warning_state != expected_warning
        || operation_estimate(capacity.ordinary_remaining, operations.rolling_accept_rate)
            != Some(operations.estimated_seconds_to_exhaustion)
    {
        return Err(FixtureError::Local);
    }
    let audit = operations.audit.as_option().ok_or(FixtureError::Local)?;
    if audit.scanned > audit.total {
        return Err(FixtureError::Local);
    }
    let audit_name = match audit.state.as_known() {
        Some(api::OperationLedgerAudit::Pending) if audit.scanned == 0 => "pending",
        Some(api::OperationLedgerAudit::Running) => "running",
        Some(api::OperationLedgerAudit::Complete) if audit.scanned == audit.total => "complete",
        Some(api::OperationLedgerAudit::Failed) => "failed",
        _ => return Err(FixtureError::Local),
    };
    Ok((warning, audit_name))
}

fn operation_estimate(remaining: u64, rate: f64) -> Option<u64> {
    if !rate.is_finite() || rate < 0.0 {
        return None;
    }
    if rate == 0.0 || remaining == 0 {
        return Some(0);
    }
    // The actor emits count/60 as a double but computes its ceiling in integers.
    // Recover exactly round-tripping counts to avoid a spurious extra second
    // (e.g. remaining=988908, rate=69/60). No epsilon or adjacent estimate passes.
    let count = (rate * 60.0).round();
    if count >= 1.0 && count < u64::MAX as f64 && (count as u64) as f64 / 60.0 == rate {
        let seconds = (u128::from(remaining) * 60).div_ceil(u128::from(count as u64));
        return Some(u64::try_from(seconds).unwrap_or(u64::MAX));
    }
    // Other finite positive wire rates use ceil(remaining/rate). Explicitly
    // saturate quotient overflow, including infinity produced by division.
    let seconds = (remaining as f64 / rate).ceil();
    Some(if seconds >= u64::MAX as f64 {
        u64::MAX
    } else {
        (seconds as u64).max(1)
    })
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct PublishInput {
    operation_key_hex: String,
    topic: String,
    scope: String,
    priority: String,
    logical_key_hex: String,
    payload_hex: String,
}

async fn client_publish(client: &Client) -> Result<(), FixtureError> {
    let input: PublishInput = read_client_input()?;
    let priority = match input.priority.as_str() {
        "routine" => api::Priority::Routine,
        "priority" => api::Priority::Priority,
        "immediate" => api::Priority::Immediate,
        "flash" => api::Priority::Flash,
        _ => return Err(FixtureError::Local),
    };
    let response = client
        .publish_event(api::PublishEventRequest {
            operation_key: decode_hex(&input.operation_key_hex)?,
            topic: input.topic,
            scope: input.scope,
            priority: priority.into(),
            logical_key: decode_hex(&input.logical_key_hex)?,
            payload: decode_hex(&input.payload_hex)?,
            ..Default::default()
        })
        .await?
        .into_owned();
    print_json(json!({
        "status": "ok",
        "event_id_hex": encode_hex(&response.id),
        "publisher_id_hex": encode_hex(&response.publisher),
        "publisher_counter": response.publisher_counter,
        "event_sequence": response.event_sequence,
        "acceptance_marker": response.acceptance_marker,
        "inserted": response.inserted
    }))
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct QueryInput {
    expected: ExpectedEventInput,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ExpectedEventInput {
    id_hex: String,
    publisher_hex: String,
    publisher_counter: u64,
    event_sequence: u64,
    topic: String,
    scope: String,
    priority: String,
    logical_key_hex: String,
    payload_hex: String,
    tombstone: bool,
    acceptance_marker: u64,
}

async fn client_query(client: &Client) -> Result<(), FixtureError> {
    let input: QueryInput = read_client_input()?;
    let response = client
        .query_events(api::QueryEventsRequest {
            topic: Some(input.expected.topic.clone()),
            scope: Some(input.expected.scope.clone()),
            limit: 2,
            ..Default::default()
        })
        .await?
        .into_owned();
    let exact_match =
        response.events.len() == 1 && event_exactly_matches(&response.events[0], &input.expected)?;
    print_json(query_evidence(
        exact_match,
        response.events.len(),
        response.has_more,
    ))
}

fn event_exactly_matches(
    event: &api::Event,
    expected: &ExpectedEventInput,
) -> Result<bool, FixtureError> {
    let priority = match expected.priority.as_str() {
        "routine" => api::Priority::Routine,
        "priority" => api::Priority::Priority,
        "immediate" => api::Priority::Immediate,
        "flash" => api::Priority::Flash,
        _ => return Err(FixtureError::Local),
    };
    Ok(event.id == decode_hex(&expected.id_hex)?
        && event.publisher == decode_hex(&expected.publisher_hex)?
        && event.publisher_counter == expected.publisher_counter
        && event.event_sequence == expected.event_sequence
        && event.topic == expected.topic
        && event.scope == expected.scope
        && event.priority == priority
        && event.logical_key == decode_hex(&expected.logical_key_hex)?
        && event.payload == decode_hex(&expected.payload_hex)?
        && event.tombstone == expected.tombstone
        && event.acceptance_marker == expected.acceptance_marker)
}

fn query_evidence(exact_match: bool, count: usize, has_more: bool) -> serde_json::Value {
    json!({
        "status": "ok",
        "exact_match": exact_match,
        "count": count,
        "has_more": has_more,
    })
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct SubscribeInput {
    operation_key_hex: String,
    topic: String,
    scope: String,
}

async fn client_subscribe(client: &Client) -> Result<(), FixtureError> {
    let input: SubscribeInput = read_client_input()?;
    let response = client
        .create_event_subscription(api::CreateEventSubscriptionRequest {
            operation_key: decode_hex(&input.operation_key_hex)?,
            topic: input.topic,
            scope: input.scope,
            include_descendant_scopes: false,
            ..Default::default()
        })
        .await?
        .into_owned();
    print_json(json!({
        "status": "ok",
        "subscription_id_hex": encode_hex(&response.subscription_id),
        "inserted": response.inserted
    }))
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct PollInput {
    subscription_id_hex: String,
    delivery_limit: u32,
    scan_limit: u32,
}

async fn client_poll(client: &Client) -> Result<(), FixtureError> {
    let input: PollInput = read_client_input()?;
    let response = client
        .poll_events(api::PollEventsRequest {
            subscription_id: decode_hex(&input.subscription_id_hex)?,
            delivery_limit: input.delivery_limit,
            scan_limit: input.scan_limit,
            ..Default::default()
        })
        .await?
        .into_owned();
    let deliveries = response
        .deliveries
        .iter()
        .map(|delivery| {
            let event = delivery.event.as_option().ok_or(FixtureError::Local)?;
            Ok(json!({
                "event_id_hex": encode_hex(&event.id),
                "attempt": delivery.attempt
            }))
        })
        .collect::<Result<Vec<_>, FixtureError>>()?;
    print_json(json!({
        "status": "ok",
        "deliveries": deliveries,
        "has_more": response.has_more
    }))
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct StreamInput {
    subscription_id_hex: String,
    delivery_limit: u32,
    scan_limit: u32,
    poll_backoff_ms: u32,
    count: u32,
    expected: Option<ExpectedEventInput>,
    #[serde(default)]
    after_attempt: u64,
}

async fn client_stream(client: &Client) -> Result<(), FixtureError> {
    let input: StreamInput = read_client_input()?;
    if input.count == 0 || input.count > 32 {
        return Err(FixtureError::Local);
    }
    let mut stream = client
        .stream_events(api::StreamEventsRequest {
            subscription_id: decode_hex(&input.subscription_id_hex)?,
            delivery_limit: input.delivery_limit,
            scan_limit: input.scan_limit,
            poll_backoff_ms: input.poll_backoff_ms,
            ..Default::default()
        })
        .await?;
    print_json(json!({"status": "active", "activity": "stream"}))?;
    let mut delivered = 0_u32;
    let mut attempt = 0_u64;
    while delivered < input.count {
        match stream.message().await? {
            Some(message) => {
                let message = message.to_owned_message();
                let event = message.event.as_option().ok_or(FixtureError::Local)?;
                if message.attempt == 0 {
                    return Err(FixtureError::Local);
                }
                if let Some(expected) = &input.expected
                    && (!event_exactly_matches(event, expected)?
                        || message.attempt <= input.after_attempt)
                {
                    return Err(FixtureError::Local);
                }
                attempt = message.attempt;
                delivered += 1;
            }
            None => break,
        }
    }
    if input.expected.is_some() {
        if delivered != input.count {
            return Err(FixtureError::Local);
        }
        return print_json(
            json!({"status":"ok", "delivered":delivered, "exact_match":true, "attempt":attempt}),
        );
    }
    print_json(json!({"status": "ok", "delivered": delivered}))
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct AckInput {
    subscription_id_hex: String,
    event_id_hex: String,
}

async fn client_ack(client: &Client) -> Result<(), FixtureError> {
    let input: AckInput = read_client_input()?;
    let response = client
        .acknowledge_event(api::AcknowledgeEventRequest {
            subscription_id: decode_hex(&input.subscription_id_hex)?,
            event_id: decode_hex(&input.event_id_hex)?,
            ..Default::default()
        })
        .await?
        .into_owned();
    print_json(json!({
        "status": "ok",
        "already_acknowledged": response.already_acknowledged
    }))
}

fn read_client_input<T: DeserializeOwned>() -> Result<T, FixtureError> {
    let mut bytes = Vec::new();
    std::io::stdin()
        .take(MAX_CLIENT_INPUT_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| FixtureError::Local)?;
    if bytes.len() as u64 > MAX_CLIENT_INPUT_BYTES {
        return Err(FixtureError::Local);
    }
    serde_json::from_slice(&bytes).map_err(|_| FixtureError::Local)
}

fn print_json(value: serde_json::Value) -> Result<(), FixtureError> {
    println!(
        "{}",
        serde_json::to_string(&value).map_err(|_| FixtureError::Local)?
    );
    std::io::stdout().flush().map_err(|_| FixtureError::Local)
}

fn encode_hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut encoded = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        encoded.push(HEX[usize::from(byte >> 4)] as char);
        encoded.push(HEX[usize::from(byte & 0x0f)] as char);
    }
    encoded
}

fn decode_hex(value: &str) -> Result<Vec<u8>, FixtureError> {
    if value.is_empty() || !value.len().is_multiple_of(2) {
        return Err(FixtureError::Local);
    }
    value
        .as_bytes()
        .chunks_exact(2)
        .map(|pair| Ok((hex_nibble(pair[0])? << 4) | hex_nibble(pair[1])?))
        .collect()
}

fn hex_nibble(byte: u8) -> Result<u8, FixtureError> {
    match byte {
        b'0'..=b'9' => Ok(byte - b'0'),
        b'a'..=b'f' => Ok(byte - b'a' + 10),
        b'A'..=b'F' => Ok(byte - b'A' + 10),
        _ => Err(FixtureError::Local),
    }
}

#[cfg(unix)]
fn read_owner_only_token(path: &Path) -> Result<Vec<u8>, FixtureError> {
    use std::os::unix::fs::{MetadataExt as _, OpenOptionsExt as _, PermissionsExt as _};
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW)
        .open(path)
        .map_err(|_| FixtureError::Local)?;
    let metadata = file.metadata().map_err(|_| FixtureError::Local)?;
    if !metadata.is_file()
        || metadata.uid() != rustix::process::geteuid().as_raw()
        || metadata.permissions().mode() & 0o077 != 0
        || metadata.len() > 257
    {
        return Err(FixtureError::Local);
    }
    let mut token = Vec::new();
    file.take(258)
        .read_to_end(&mut token)
        .map_err(|_| FixtureError::Local)?;
    while matches!(token.last(), Some(b'\r' | b'\n')) {
        token.pop();
    }
    if !(32..=256).contains(&token.len())
        || !token
            .iter()
            .all(|byte| byte.is_ascii_alphanumeric() || b"-._~".contains(byte))
    {
        return Err(FixtureError::Local);
    }
    Ok(token)
}

#[cfg(not(unix))]
fn read_owner_only_token(_path: &Path) -> Result<Vec<u8>, FixtureError> {
    Err(FixtureError::Local)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn preconnected_http2_client_selects_grpc_protocol() {
        let config = client_config(
            "http://127.0.0.1:8181".parse().expect("client URI"),
            INITIAL_TOKEN,
        );

        assert_eq!(config.protocol(), connectrpc::Protocol::Grpc);
    }

    fn representative_event() -> api::Event {
        api::Event {
            id: vec![1; 32],
            publisher: vec![2; 32],
            publisher_counter: 3,
            event_sequence: 4,
            topic: "SECRET_TOPIC_CANARY".to_owned(),
            scope: "SECRET_SCOPE_CANARY".to_owned(),
            priority: api::Priority::Immediate.into(),
            logical_key: b"SECRET_LOGICAL_KEY_CANARY".to_vec(),
            payload: b"SECRET_PAYLOAD_CANARY".to_vec(),
            tombstone: false,
            acceptance_marker: 5,
            ..Default::default()
        }
    }

    fn representative_expected_event() -> ExpectedEventInput {
        ExpectedEventInput {
            id_hex: encode_hex(&[1; 32]),
            publisher_hex: encode_hex(&[2; 32]),
            publisher_counter: 3,
            event_sequence: 4,
            topic: "SECRET_TOPIC_CANARY".to_owned(),
            scope: "SECRET_SCOPE_CANARY".to_owned(),
            priority: "immediate".to_owned(),
            logical_key_hex: encode_hex(b"SECRET_LOGICAL_KEY_CANARY"),
            payload_hex: encode_hex(b"SECRET_PAYLOAD_CANARY"),
            tombstone: false,
            acceptance_marker: 5,
        }
    }

    #[cfg(unix)]
    #[test]
    fn runtime_is_entered_before_signal_registration() {
        // Break caught: registering Tokio signals before entering a runtime
        // panics instead of starting the acceptance agent process.
        let (_runtime, _signals) = build_runtime_and_signals().expect("runtime and signals");
    }

    #[test]
    fn runtime_is_entered_before_timeout_construction() {
        // Break caught: constructing Tokio's timeout future before block_on
        // enters the client runtime panics before the first RPC starts.
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("client runtime");
        let value = block_on_with_timeout(&runtime, Duration::from_secs(1), async { 7_u8 })
            .expect("bounded client work");
        assert_eq!(value, 7);
    }

    #[test]
    fn prepared_bounds_cover_durable_records_and_selected_node_drain() {
        // Break caught: the validation-floor capacity leaves only one usable
        // record after reservations, so an Event plus its operation mapping is
        // rejected before crash recovery; a three-second grace forces the real
        // selected-node drain before it can complete cleanly.
        assert_eq!(TEST_STORAGE_MAX_ITEMS, 10_000);
        assert_eq!(TEST_STORAGE_MAX_PAYLOAD_BYTES, 64 * 1024 * 1024);
        assert_eq!(TEST_SHUTDOWN_GRACE_MS, 10_000);
    }

    #[test]
    fn status_evidence_requires_profile_modes_and_capacity_contract() {
        let valid = valid_status_response();

        let evidence = status_evidence(&valid).expect("valid profile status");
        assert_eq!(evidence["configured_emission_mode"], "normal");
        assert_eq!(evidence["effective_emission_mode"], "receive_only");
        assert_eq!(evidence["operation_ledger_mode"], "legacy");
        assert_eq!(evidence["operation_ordinary_remaining"], 990_000);
        assert_eq!(evidence["operation_audit_state"], "pending");

        let mut invalid = valid;
        invalid
            .publish_operation_capacity
            .get_or_insert_default()
            .profile_boundary = 2_048;
        assert!(status_evidence(&invalid).is_err());
    }

    #[test]
    fn status_evidence_accepts_only_absent_or_exact_generation_bytes() {
        // Break caught: verifier evidence accepts a malformed generation or
        // emits a noncanonical representation that cannot match a manifest.
        let empty = valid_status_response();
        let empty_evidence = status_evidence(&empty).expect("empty generation is valid");
        assert!(empty_evidence.get("credential_generation").is_none());

        let mut exact = valid_status_response();
        exact.credential_generation = (0_u8..32).collect();
        let exact_evidence = status_evidence(&exact).expect("32-byte generation is valid");
        assert_eq!(
            exact_evidence["credential_generation"],
            "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"
        );

        for length in [31, 33] {
            let mut malformed = valid_status_response();
            malformed.credential_generation = vec![0xab; length];
            assert!(status_evidence(&malformed).is_err(), "length {length}");
        }
    }

    fn valid_status_response() -> api::GetStatusResponse {
        api::GetStatusResponse {
            configured_emission_mode: api::EmissionMode::Normal.into(),
            effective_emission_mode: api::EmissionMode::ReceiveOnly.into(),
            store_capacity: api::StoreCapacityStatus {
                item_limit: 10_000,
                payload_byte_limit: 64 * 1024 * 1024,
                ..Default::default()
            }
            .into(),
            publish_operation_capacity: api::PublishOperationCapacityStatus {
                row_hard_limit: 1_000_000,
                byte_hard_limit: 201_326_592,
                profile_boundary: 1_024,
                profile_remaining: 1_024,
                ordinary_remaining: 990_000,
                emergency_remaining: 10_000,
                warning_state: api::OperationCapacityWarning::Ok.into(),
                ledger_mode: api::PublishOperationLedgerMode::Legacy.into(),
                audit: api::OperationLedgerAuditStatus {
                    state: api::OperationLedgerAudit::Pending.into(),
                    ..Default::default()
                }
                .into(),
                ..Default::default()
            }
            .into(),
            delivery_capacity: api::DeliveryCapacityStatus {
                profile_boundary: 256,
                hard_limit: 262_144,
                ..Default::default()
            }
            .into(),
            ..Default::default()
        }
    }

    #[test]
    fn operation_health_requires_coherent_rate_estimate() {
        for (name, rows, rate, estimate, valid) in [
            ("exact", 1_024, 2.0, 494_488, true),
            ("positive-rate-zero", 1_024, 2.0, 0, false),
            ("positive-rate-one", 1_024, 2.0, 1, false),
            ("positive-rate-max", 1_024, 2.0, u64::MAX, false),
            ("one-second-low", 1_024, 2.0, 494_487, false),
            ("one-second-high", 1_024, 2.0, 494_489, false),
            ("fraction-round-up", 1_024, 3.0, 329_659, true),
            ("subsecond", 1_024, 1_977_952.0, 1, true),
            ("subsecond-zero", 1_024, 1_977_952.0, 0, false),
            (
                "quotient-overflow",
                1_024,
                f64::from_bits(1),
                u64::MAX,
                true,
            ),
            (
                "quotient-overflow-not-saturated",
                1_024,
                f64::from_bits(1),
                u64::MAX - 1,
                false,
            ),
            ("maximum-rate", 1_024, f64::MAX, 1, true),
            ("zero-rate", 1_024, 0.0, 0, true),
            ("zero-rate-estimate", 1_024, 0.0, 1, false),
            ("negative-rate", 1_024, -1.0, 0, false),
            ("nan-rate", 1_024, f64::NAN, 0, false),
            ("infinite-rate", 1_024, f64::INFINITY, 0, false),
            ("negative-infinite-rate", 1_024, f64::NEG_INFINITY, 0, false),
            (
                "non-actor-rate-below-two",
                1_024,
                2.0_f64.next_down(),
                494_489,
                true,
            ),
            // 69/60 is rounded on the wire: direct floating ceil is one too high.
            (
                "actor-rate-exact-ceiling",
                1_092,
                69.0 / 60.0,
                859_920,
                true,
            ),
            (
                "actor-rate-float-ceiling-rejected",
                1_092,
                69.0 / 60.0,
                859_921,
                false,
            ),
            ("zero-headroom", 990_000, 2.0, 0, true),
            ("zero-headroom-estimate", 990_000, 2.0, 1, false),
        ] {
            let operations = api::PublishOperationCapacityStatus {
                rows,
                active_rows: 24,
                retired_rows: rows - 24,
                reverse_rows: 24,
                bytes: 3_888 + (rows - 24) * 67,
                ordinary_remaining: 990_000 - rows,
                emergency_remaining: 10_000,
                rolling_accept_rate: rate,
                estimated_seconds_to_exhaustion: estimate,
                warning_state: if rows == 990_000 {
                    api::OperationCapacityWarning::Exhausted
                } else {
                    api::OperationCapacityWarning::Ok
                }
                .into(),
                audit: api::OperationLedgerAuditStatus {
                    state: api::OperationLedgerAudit::Pending.into(),
                    ..Default::default()
                }
                .into(),
                ..Default::default()
            };
            assert_eq!(operation_health(&operations).is_ok(), valid, "{name}");
        }
    }

    #[test]
    fn operation_health_accepts_coherent_numbered_capacity() {
        let operations = api::PublishOperationCapacityStatus {
            rows: 2,
            bytes: 300,
            ordinary_remaining: 683_925,
            emergency_remaining: 5_548,
            warning_state: api::OperationCapacityWarning::Ok.into(),
            ledger_mode: api::PublishOperationLedgerMode::Numbered.into(),
            numbered_clients: 1,
            numbered_outstanding_results: 1,
            numbered_reverse_rows: 1,
            audit: api::OperationLedgerAuditStatus {
                state: api::OperationLedgerAudit::Pending.into(),
                ..Default::default()
            }
            .into(),
            ..Default::default()
        };

        assert!(operation_health(&operations).is_ok());
    }

    #[test]
    fn config_check_mode_uses_validation_without_creating_state() {
        let root = env::temp_dir().join(format!(
            "aster-agent-acceptance-config-check-{}",
            std::process::id()
        ));
        let _ = fs::remove_dir_all(&root);
        fs::create_dir(&root).expect("test root");
        let config = root.join("invalid.json");
        let state = root.join("state");
        fs::write(&config, b"{}").expect("invalid config");

        assert!(
            check_config_arguments(&[
                "--check-config".to_owned(),
                config.to_string_lossy().into_owned(),
            ])
            .is_err()
        );
        assert!(!state.exists());
        fs::remove_dir_all(root).expect("remove test root");
    }

    #[test]
    fn recovered_event_match_is_sensitive_to_every_exposed_field() {
        let event = representative_event();
        let expected = representative_expected_event();
        assert!(event_exactly_matches(&event, &expected).expect("exact event"));

        let mut mutations = Vec::new();
        let mut changed = event.clone();
        changed.id[0] ^= 1;
        mutations.push(changed);
        let mut changed = event.clone();
        changed.publisher[0] ^= 1;
        mutations.push(changed);
        let mut changed = event.clone();
        changed.publisher_counter += 1;
        mutations.push(changed);
        let mut changed = event.clone();
        changed.event_sequence += 1;
        mutations.push(changed);
        let mut changed = event.clone();
        changed.topic.push('x');
        mutations.push(changed);
        let mut changed = event.clone();
        changed.scope.push('x');
        mutations.push(changed);
        let mut changed = event.clone();
        changed.priority = api::Priority::Flash.into();
        mutations.push(changed);
        let mut changed = event.clone();
        changed.logical_key[0] ^= 1;
        mutations.push(changed);
        let mut changed = event.clone();
        changed.payload[0] ^= 1;
        mutations.push(changed);
        let mut changed = event.clone();
        changed.tombstone = true;
        mutations.push(changed);
        let mut changed = event;
        changed.acceptance_marker += 1;
        mutations.push(changed);

        assert_eq!(mutations.len(), 11);
        for mutation in mutations {
            assert!(!event_exactly_matches(&mutation, &expected).expect("mutated event"));
        }
    }

    #[test]
    fn query_evidence_never_contains_expected_event_values() {
        let output = serde_json::to_string(&query_evidence(true, 1, false))
            .expect("bounded equality evidence");
        for canary in [
            "SECRET_TOPIC_CANARY",
            "SECRET_SCOPE_CANARY",
            "SECRET_PAYLOAD_CANARY",
        ] {
            assert!(!output.contains(canary));
        }
        assert_eq!(
            output,
            r#"{"count":1,"exact_match":true,"has_more":false,"status":"ok"}"#
        );
    }
}
