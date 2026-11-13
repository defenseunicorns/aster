//! Customer runtime supervision for the protected selected Event and Blob service.

use std::{error::Error, fmt, path::PathBuf, time::Duration};

use aster_mesh::ProvisioningSecretLoader;
use aster_node::{
    NodeBootstrapErrorKind, NodeError, NodeOperatorOutputPolicy, RunningNode,
    start_supervised_node_with_forwarding_and_output_policy,
};
use tokio::{sync::mpsc, task::JoinHandle};

use crate::{
    config::{ConfigReason, ValidatedRuntimeConfig, ValidatedSystemdAgentConfig},
    credentials::{
        CredentialReason, StartupCredentials, load_startup_credentials, open_node_config,
    },
    event_service::application_service_with_blobs,
    health::BoundHealth,
    lifecycle::{FailureReason, LifecycleState, ServiceStatus, credential_generation_hex},
    server::{BoundAgent, ServerStop},
};

const NODE_FAILURE_CHECK_INTERVAL: Duration = Duration::from_millis(100);

mod btle;

use btle::ActiveBtleRuntime;
#[cfg(not(feature = "sdk-test-support"))]
use btle::BtleRuntimeOwnerError;
pub use btle::BtleRuntimeStartup;
#[cfg(feature = "sdk-test-support")]
#[doc(hidden)]
pub use btle::{BtleRuntimeOwner, BtleRuntimeOwnerError};

/// Conservative single-line test envelope: more than twice the current fixed
/// lifecycle record while keeping operator metadata below one kibibyte.
#[cfg(test)]
const MAX_OPERATOR_RECORD_BYTES: usize = 512;

/// One process-control signal after platform-specific translation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AgentSignal {
    /// Reload the configured client bearer-token file.
    Hangup,
    /// Begin or force process shutdown.
    Terminate,
}

pub enum TokenReloadPolicy {
    Disabled,
    ReloadFrom(PathBuf),
}

impl fmt::Debug for TokenReloadPolicy {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Disabled => formatter.write_str("Disabled"),
            Self::ReloadFrom(_) => formatter.write_str("ReloadFrom([REDACTED])"),
        }
    }
}

/// Bounded process outcome returned to the customer binary.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AgentExit {
    /// Every owned server and node resource stopped cleanly.
    Clean,
    /// A second signal or the configured grace deadline forced termination.
    Forced,
    /// A runtime task failed with only a fixed public category retained.
    Failed(FailureReason),
}

/// Sanitized startup or supervision failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AgentRuntimeError {
    Configuration(ConfigReason),
    Credential(CredentialReason),
    Bootstrap(NodeBootstrapErrorKind),
    Listener(FailureReason),
    Lifecycle(FailureReason),
}

impl fmt::Display for AgentRuntimeError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Configuration(_) => formatter.write_str("agent configuration failed"),
            Self::Credential(_) => formatter.write_str("agent credential validation failed"),
            Self::Bootstrap(_) => formatter.write_str("agent node bootstrap failed"),
            Self::Listener(_) => formatter.write_str("agent listener failed"),
            Self::Lifecycle(_) => formatter.write_str("agent lifecycle failed"),
        }
    }
}

impl Error for AgentRuntimeError {}

/// Runs one protected customer agent until a translated terminal signal or a
/// bounded fatal task transition.
pub async fn run_customer_agent<L>(
    config: ValidatedSystemdAgentConfig,
    loader: &mut L,
    signals: mpsc::Receiver<AgentSignal>,
) -> Result<AgentExit, AgentRuntimeError>
where
    L: ProvisioningSecretLoader + ?Sized,
{
    run_customer_agent_with_btle(config, loader, signals, BtleRuntimeStartup::disabled()).await
}

/// Runs the systemd-style customer agent with one optional prepared BTLE owner.
#[doc(hidden)]
pub async fn run_customer_agent_with_btle<L>(
    config: ValidatedSystemdAgentConfig,
    loader: &mut L,
    signals: mpsc::Receiver<AgentSignal>,
    btle: BtleRuntimeStartup,
) -> Result<AgentExit, AgentRuntimeError>
where
    L: ProvisioningSecretLoader + ?Sized,
{
    require_matching_btle_policy(config.runtime(), &btle)?;
    // The complete credential set is read and checked before any listener or
    // state side effect. The already-validated config owns all stable values.
    let credentials = load_startup_credentials(config.credential_paths())
        .map_err(|error| AgentRuntimeError::Credential(error.reason()))?;
    let token_path = PathBuf::from(config.credential_paths().client_token_file());
    let (runtime, _) = config.into_parts();
    run_customer_agent_with_credentials_and_btle_inner(
        runtime,
        credentials,
        loader,
        signals,
        TokenReloadPolicy::ReloadFrom(token_path),
        btle,
    )
    .await
}

pub async fn run_customer_agent_with_credentials<L>(
    config: ValidatedRuntimeConfig,
    credentials: StartupCredentials,
    loader: &mut L,
    signals: mpsc::Receiver<AgentSignal>,
    reload: TokenReloadPolicy,
) -> Result<AgentExit, AgentRuntimeError>
where
    L: ProvisioningSecretLoader + ?Sized,
{
    run_customer_agent_with_credentials_and_btle_inner(
        config,
        credentials,
        loader,
        signals,
        reload,
        BtleRuntimeStartup::disabled(),
    )
    .await
}

fn require_matching_btle_policy(
    config: &ValidatedRuntimeConfig,
    btle: &BtleRuntimeStartup,
) -> Result<(), AgentRuntimeError> {
    if btle.matches_config(config.btle_policy(), config.state()) {
        Ok(())
    } else {
        Err(AgentRuntimeError::Lifecycle(FailureReason::Startup))
    }
}

async fn run_customer_agent_with_credentials_and_btle_inner<L>(
    config: ValidatedRuntimeConfig,
    credentials: StartupCredentials,
    loader: &mut L,
    mut signals: mpsc::Receiver<AgentSignal>,
    reload: TokenReloadPolicy,
    btle: BtleRuntimeStartup,
) -> Result<AgentExit, AgentRuntimeError>
where
    L: ProvisioningSecretLoader + ?Sized,
{
    require_matching_btle_policy(&config, &btle)?;
    let application_address = config.application();
    let health_address = config.health();
    let forwarding = config.forwarding();
    let configured_emission_policy = config.emission_policy();
    let credential_generation = credentials.generation();
    let limits = *config.limits();
    let node_config = open_node_config(&config, &credentials, loader)
        .map_err(|error| AgentRuntimeError::Bootstrap(error.kind()))?;
    let health = BoundHealth::bind(health_address)
        .await
        .map_err(|_| AgentRuntimeError::Listener(FailureReason::Startup))?;
    let status = ServiceStatus::starting();
    let (health_stop_send, health_stop_receive) = tokio::sync::watch::channel(false);
    let mut health_task = tokio::spawn(health.serve(status.clone(), health_stop_receive));
    emit_lifecycle(LifecycleState::Starting, "startup", "started", false, 0);
    tokio::task::yield_now().await;

    let node = match start_supervised_node_with_forwarding_and_output_policy(
        node_config,
        forwarding,
        customer_node_output_policy(),
    )
    .await
    {
        Ok(node) => node,
        Err(error) => {
            let kind = classify_node_startup(&error);
            fail_startup(&status, &health_stop_send, &mut health_task).await;
            return Err(AgentRuntimeError::Bootstrap(kind));
        }
    };
    let mut btle_runtime = match btle.start(&node) {
        Ok(runtime) => runtime,
        Err(_) => {
            let mut absent_btle = ActiveBtleRuntime::absent();
            cleanup_node_with_btle(node, &mut absent_btle, limits.shutdown_grace()).await;
            fail_startup(&status, &health_stop_send, &mut health_task).await;
            return Err(AgentRuntimeError::Lifecycle(FailureReason::Startup));
        }
    };
    let state_root = node.state_root().to_path_buf();
    let application = match BoundAgent::bind(application_address).await {
        Ok(application) => application,
        Err(_) => {
            cleanup_node_with_btle(node, &mut btle_runtime, limits.shutdown_grace()).await;
            fail_startup(&status, &health_stop_send, &mut health_task).await;
            return Err(AgentRuntimeError::Listener(FailureReason::Startup));
        }
    };

    let events = node.selected_events();
    let blobs = node.selected_blobs();
    let monitored_events = events.clone();
    let (stream_stop_send, stream_stop_receive) = tokio::sync::watch::channel(false);
    let (server_stop_send, server_stop_receive) = tokio::sync::watch::channel(ServerStop::Run);
    let service = match application_service_with_blobs(
        events,
        blobs,
        state_root,
        configured_emission_policy,
        credential_generation,
        stream_stop_receive,
    ) {
        Ok(service) => service,
        Err(_) => {
            cleanup_node_with_btle(node, &mut btle_runtime, limits.shutdown_grace()).await;
            fail_startup(&status, &health_stop_send, &mut health_task).await;
            return Err(AgentRuntimeError::Listener(FailureReason::Startup));
        }
    };
    let mut server_task = tokio::spawn(application.serve(
        service,
        credentials.token().clone(),
        status.clone(),
        limits,
        server_stop_receive,
    ));
    tokio::task::yield_now().await;
    if server_task.is_finished() {
        cleanup_node_with_btle(node, &mut btle_runtime, limits.shutdown_grace()).await;
        fail_startup(&status, &health_stop_send, &mut health_task).await;
        return Err(AgentRuntimeError::Listener(FailureReason::Startup));
    }
    // This final terminal observation is the startup linearization point.
    // Completion observed here is startup failure; completion published after
    // it is a runtime failure even if the synchronous Ready transition below
    // has not yet returned.
    let startup_ready = !btle_runtime.is_terminal()
        && node.open_transport_admission()
        && status.transition(LifecycleState::Ready).is_ok();
    if !startup_ready {
        let _ = server_stop_send.send(ServerStop::Force);
        server_task.abort();
        cleanup_node_with_btle(node, &mut btle_runtime, limits.shutdown_grace()).await;
        fail_startup(&status, &health_stop_send, &mut health_task).await;
        return Err(AgentRuntimeError::Lifecycle(FailureReason::Startup));
    }
    emit_ready_lifecycle(credential_generation);

    let mut node_monitor = tokio::spawn(async move {
        loop {
            tokio::time::sleep(NODE_FAILURE_CHECK_INTERVAL).await;
            if monitored_events.status().await.is_err() {
                return;
            }
        }
    });

    enum RunningTransition {
        Drain,
        Fatal { health_completed: bool },
    }

    let transition = loop {
        tokio::select! {
            signal = signals.recv() => match signal {
                Some(AgentSignal::Hangup) => {
                    let (reason, retryable, response_code) =
                        apply_token_reload(&reload, &credentials);
                    emit_lifecycle(
                        LifecycleState::Ready,
                        "token_reload",
                        reason,
                        retryable,
                        response_code,
                    );
                }
                Some(AgentSignal::Terminate) => break RunningTransition::Drain,
                None => break RunningTransition::Fatal { health_completed: false },
            },
            _ = &mut node_monitor => {
                break RunningTransition::Fatal { health_completed: false };
            }
            _ = &mut server_task => {
                break RunningTransition::Fatal { health_completed: false };
            }
            _ = &mut health_task => {
                break RunningTransition::Fatal { health_completed: true };
            }
            () = btle_runtime.wait_terminal(), if btle_runtime.is_present() => {
                break RunningTransition::Fatal { health_completed: false };
            }
        }
    };

    match transition {
        RunningTransition::Drain => {
            let resources = DrainResources {
                stream_stop_send,
                server_stop_send,
                server_task,
                health_stop_send,
                health_task,
                node_monitor,
                node,
                btle_runtime,
            };
            drain(status, signals, resources, limits.shutdown_grace()).await
        }
        RunningTransition::Fatal { health_completed } => {
            let _ = status.fail(FailureReason::Runtime);
            emit_lifecycle(
                LifecycleState::Failed,
                "fatal_transition",
                "runtime",
                false,
                500,
            );
            let _ = stream_stop_send.send(true);
            let _ = server_stop_send.send(ServerStop::Force);
            server_task.abort();
            node_monitor.abort();
            cleanup_node_with_btle(node, &mut btle_runtime, limits.shutdown_grace()).await;
            if !health_completed {
                stop_health(health_stop_send, health_task).await;
            }
            Ok(AgentExit::Failed(FailureReason::Runtime))
        }
    }
}

fn apply_token_reload(
    policy: &TokenReloadPolicy,
    credentials: &StartupCredentials,
) -> (&'static str, bool, u16) {
    match policy {
        TokenReloadPolicy::Disabled => ("unsupported", false, 501),
        TokenReloadPolicy::ReloadFrom(token_path) => {
            if credentials.token().reload_from(token_path).is_ok() {
                ("reloaded", false, 200)
            } else {
                ("rejected", true, 503)
            }
        }
    }
}

async fn cleanup_node_with_btle(node: RunningNode, btle: &mut ActiveBtleRuntime, grace: Duration) {
    node.close_admission();
    let deadline = tokio::time::Instant::now() + grace;
    let mut btle_task = btle.begin_cleanup();
    let (btle_clean, btle_timed_out) = match btle_task.as_mut() {
        Some(task) => match wait_until(deadline, task).await {
            Some(Ok(Ok(()))) => (true, false),
            Some(_) => (false, false),
            None => (false, true),
        },
        None => (true, false),
    };
    if btle_timed_out {
        abort_btle_task(&mut btle_task).await;
    } else {
        btle_task.take();
    }
    let node_clean = wait_until(deadline, async move { node.shutdown().await.is_ok() })
        .await
        .unwrap_or(false);
    let _ = btle_clean && node_clean;
}

async fn wait_until<T>(
    deadline: tokio::time::Instant,
    future: impl std::future::Future<Output = T>,
) -> Option<T> {
    tokio::time::timeout_at(deadline, future).await.ok()
}

const fn customer_node_output_policy() -> NodeOperatorOutputPolicy {
    NodeOperatorOutputPolicy::CustomerSafe
}

struct DrainResources {
    stream_stop_send: tokio::sync::watch::Sender<bool>,
    server_stop_send: tokio::sync::watch::Sender<ServerStop>,
    server_task: JoinHandle<Result<(), crate::server::ServerError>>,
    health_stop_send: tokio::sync::watch::Sender<bool>,
    health_task: JoinHandle<Result<(), crate::health::HealthError>>,
    node_monitor: JoinHandle<()>,
    node: RunningNode,
    btle_runtime: ActiveBtleRuntime,
}

async fn drain(
    status: ServiceStatus,
    mut signals: mpsc::Receiver<AgentSignal>,
    resources: DrainResources,
    grace: Duration,
) -> Result<AgentExit, AgentRuntimeError> {
    let DrainResources {
        stream_stop_send,
        server_stop_send,
        mut server_task,
        health_stop_send,
        mut health_task,
        node_monitor,
        node,
        mut btle_runtime,
    } = resources;
    status
        .transition(LifecycleState::Draining)
        .map_err(|_| AgentRuntimeError::Lifecycle(FailureReason::Shutdown))?;
    emit_lifecycle(
        LifecycleState::Draining,
        "drain_start",
        "terminating",
        false,
        503,
    );
    let _ = stream_stop_send.send(true);
    let _ = server_stop_send.send(ServerStop::Drain);
    node_monitor.abort();
    node.close_transport_admission();

    #[cfg(feature = "sdk-test-support")]
    let node_shutdown_observer = btle_runtime.node_shutdown_observer();
    #[cfg(feature = "sdk-test-support")]
    let cleanup_retired_observer = btle_runtime.cleanup_retired_observer();
    let deadline = tokio::time::sleep(grace);
    tokio::pin!(deadline);
    let mut btle_task = btle_runtime.begin_cleanup();

    let (node_shutdown_send, node_shutdown_receive) = tokio::sync::oneshot::channel();
    let mut node_shutdown_send = Some(node_shutdown_send);
    let mut node_task = tokio::spawn(async move {
        let _ = node_shutdown_receive.await;
        node.shutdown().await.map(|_| ())
    });
    let mut server_done = false;
    let mut btle_done = btle_task.is_none();
    let mut node_done = false;
    let mut failed = false;
    let mut signals_open = true;

    while !server_done || !btle_done || !node_done {
        tokio::select! {
            signal = signals.recv(), if signals_open => match signal {
                Some(AgentSignal::Terminate) => {
                    force_shutdown(
                        &server_stop_send,
                        &mut server_task,
                        &mut btle_task,
                        &mut node_task,
                        health_stop_send,
                        health_task,
                    ).await;
                    emit_lifecycle(
                        LifecycleState::Draining,
                        "shutdown_result",
                        "forced",
                        false,
                        500,
                    );
                    return Ok(AgentExit::Forced);
                }
                Some(AgentSignal::Hangup) => {}
                None => signals_open = false,
            },
            result = &mut server_task, if !server_done => {
                server_done = true;
                failed |= !matches!(result, Ok(Ok(())));
                if btle_done && let Some(send) = node_shutdown_send.take() {
                    #[cfg(feature = "sdk-test-support")]
                    if let Some(observer) = &node_shutdown_observer {
                        observer();
                    }
                    let _ = send.send(());
                }
            }
            result = wait_btle_task(&mut btle_task), if !btle_done => {
                btle_done = true;
                failed |= !matches!(result, Ok(Ok(())));
                btle_task.take();
                #[cfg(feature = "sdk-test-support")]
                if let Some(observer) = &cleanup_retired_observer {
                    observer();
                }
                if server_done && let Some(send) = node_shutdown_send.take() {
                    #[cfg(feature = "sdk-test-support")]
                    if let Some(observer) = &node_shutdown_observer {
                        observer();
                    }
                    let _ = send.send(());
                }
            }
            result = &mut node_task, if !node_done => {
                node_done = true;
                failed |= !matches!(result, Ok(Ok(())));
            }
            _ = &mut health_task => {
                server_task.abort();
                abort_btle_task(&mut btle_task).await;
                node_task.abort();
                let _ = status.fail(FailureReason::Shutdown);
                emit_lifecycle(
                    LifecycleState::Failed,
                    "fatal_transition",
                    "shutdown",
                    false,
                    500,
                );
                return Ok(AgentExit::Failed(FailureReason::Shutdown));
            }
            () = &mut deadline => {
                force_shutdown(
                    &server_stop_send,
                    &mut server_task,
                    &mut btle_task,
                    &mut node_task,
                    health_stop_send,
                    health_task,
                ).await;
                emit_lifecycle(
                    LifecycleState::Draining,
                    "shutdown_result",
                    "forced",
                    false,
                    500,
                );
                return Ok(AgentExit::Forced);
            }
        }
    }

    if failed {
        let _ = status.fail(FailureReason::Shutdown);
        emit_lifecycle(
            LifecycleState::Failed,
            "fatal_transition",
            "shutdown",
            false,
            500,
        );
        stop_health(health_stop_send, health_task).await;
        return Ok(AgentExit::Failed(FailureReason::Shutdown));
    }

    status
        .transition(LifecycleState::Stopped)
        .map_err(|_| AgentRuntimeError::Lifecycle(FailureReason::Shutdown))?;
    emit_lifecycle(
        LifecycleState::Stopped,
        "shutdown_result",
        "clean",
        false,
        200,
    );
    stop_health(health_stop_send, health_task).await;
    Ok(AgentExit::Clean)
}

async fn force_shutdown(
    server_stop_send: &tokio::sync::watch::Sender<ServerStop>,
    server_task: &mut JoinHandle<Result<(), crate::server::ServerError>>,
    btle_task: &mut Option<JoinHandle<Result<(), BtleRuntimeOwnerError>>>,
    node_task: &mut JoinHandle<Result<(), NodeError>>,
    health_stop_send: tokio::sync::watch::Sender<bool>,
    health_task: JoinHandle<Result<(), crate::health::HealthError>>,
) {
    let _ = server_stop_send.send(ServerStop::Force);
    server_task.abort();
    abort_btle_task(btle_task).await;
    node_task.abort();
    stop_health(health_stop_send, health_task).await;
}

async fn wait_btle_task(
    task: &mut Option<JoinHandle<Result<(), BtleRuntimeOwnerError>>>,
) -> Result<Result<(), BtleRuntimeOwnerError>, tokio::task::JoinError> {
    match task.as_mut() {
        Some(task) => task.await,
        None => std::future::pending().await,
    }
}

async fn abort_btle_task(task: &mut Option<JoinHandle<Result<(), BtleRuntimeOwnerError>>>) {
    if let Some(mut task) = task.take() {
        task.abort();
        let _ = (&mut task).await;
    }
}

async fn fail_startup(
    status: &ServiceStatus,
    health_stop_send: &tokio::sync::watch::Sender<bool>,
    health_task: &mut JoinHandle<Result<(), crate::health::HealthError>>,
) {
    let _ = status.fail(FailureReason::Startup);
    emit_lifecycle(
        LifecycleState::Failed,
        "fatal_transition",
        "startup",
        false,
        500,
    );
    let _ = health_stop_send.send(true);
    let _ = health_task.await;
}

async fn stop_health(
    health_stop_send: tokio::sync::watch::Sender<bool>,
    mut health_task: JoinHandle<Result<(), crate::health::HealthError>>,
) {
    let _ = health_stop_send.send(true);
    let _ = (&mut health_task).await;
}

fn classify_node_startup(error: &NodeError) -> NodeBootstrapErrorKind {
    match error {
        NodeError::Configuration(_) => NodeBootstrapErrorKind::InvalidConfiguration,
        _ => NodeBootstrapErrorKind::StateUnavailable,
    }
}

fn emit_lifecycle(
    state: LifecycleState,
    operation: &'static str,
    reason: &'static str,
    retryable: bool,
    response_code: u16,
) {
    println!(
        "{}",
        lifecycle_record(state, operation, reason, retryable, response_code)
    );
}

fn emit_ready_lifecycle(generation: Option<crate::credentials::CredentialGeneration>) {
    let mut record = lifecycle_record(LifecycleState::Ready, "readiness", "ready", false, 200);
    if let Some(generation) = generation {
        record
            .as_object_mut()
            .expect("lifecycle record is an object")
            .insert(
                "credential_generation".to_owned(),
                credential_generation_hex(generation).into(),
            );
    }
    println!("{record}");
}

fn lifecycle_record(
    state: LifecycleState,
    operation: &'static str,
    reason: &'static str,
    retryable: bool,
    response_code: u16,
) -> serde_json::Value {
    let timestamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis();
    serde_json::json!({
        "timestamp": timestamp,
        "lifecycle_state": lifecycle_state_name(state),
        "operation": operation,
        "reason": reason,
        "retryable": retryable,
        "response_code": response_code,
        "latency_bucket": "not_applicable",
        "correlation_id": "agent-lifecycle",
    })
}

const fn lifecycle_state_name(state: LifecycleState) -> &'static str {
    match state {
        LifecycleState::Starting => "starting",
        LifecycleState::Ready => "ready",
        LifecycleState::Draining => "draining",
        LifecycleState::Stopped => "stopped",
        LifecycleState::Failed => "failed",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn terminal_check_reloads_a_watch_change_after_its_first_observation() {
        // Break caught: returning false on `has_changed() == Ok(true)` can
        // publish Ready after the owner already reported completion.
        let (completion_send, completion) = tokio::sync::watch::channel(false);
        let mut completion = Some(completion);

        assert!(btle::completion_is_terminal_after_read(
            &mut completion,
            || completion_send.send(true).expect("publish terminal state")
        ));
    }

    #[tokio::test(start_paused = true)]
    async fn btle_and_node_cleanup_share_one_process_deadline() {
        // Break caught: assigning the full grace period independently to BTLE
        // cleanup and node shutdown can make one process stop take two grace
        // periods instead of the configured process-level bound.
        let grace = Duration::from_millis(100);
        let started = tokio::time::Instant::now();
        let deadline = started + grace;
        let first = wait_until(deadline, tokio::time::sleep(Duration::from_millis(60))).await;
        let second = wait_until(deadline, tokio::time::sleep(Duration::from_millis(60))).await;

        assert!(first.is_some());
        assert!(second.is_none());
        assert_eq!(tokio::time::Instant::now() - started, grace);
    }

    #[test]
    fn disabled_reload_has_one_fixed_unsupported_outcome() {
        let token = crate::ClientToken::from_bytes(b"0123456789abcdef0123456789abcdef".to_vec())
            .expect("test token");
        let credentials = crate::credentials::StartupCredentials::new(
            token,
            aster_mesh::ProvisioningSecretRef::from_opaque(b"reference".to_vec())
                .expect("test reference"),
            aster_mesh::ProvisioningLoadId::new([7; 32]),
            None,
        );
        assert_eq!(
            apply_token_reload(&TokenReloadPolicy::Disabled, &credentials),
            ("unsupported", false, 501)
        );
        assert!(
            credentials
                .token()
                .authorizes(Some(b"Bearer 0123456789abcdef0123456789abcdef"))
        );
    }

    #[test]
    fn customer_output_boundary_selects_silent_node_and_fixed_agent_records() {
        // Break caught: starting the selected node in legacy mode mixes raw
        // node receipts with the agent lifecycle allowlist even when the JSON
        // serializer itself remains bounded.
        assert_eq!(
            customer_node_output_policy(),
            aster_node::NodeOperatorOutputPolicy::CustomerSafe
        );
        use LifecycleState::{Draining, Failed, Ready, Starting, Stopped};
        let mut records = [
            (Starting, "startup", "started", false, 0),
            (
                Starting,
                "btle_availability",
                "unqualified_package",
                false,
                503,
            ),
            (Ready, "readiness", "ready", false, 200),
            (Ready, "token_reload", "unsupported", false, 501),
            (Ready, "token_reload", "reloaded", false, 200),
            (Ready, "token_reload", "rejected", true, 503),
            (Draining, "drain_start", "terminating", false, 503),
            (Failed, "fatal_transition", "startup", false, 500),
            (Failed, "fatal_transition", "runtime", false, 500),
            (Failed, "fatal_transition", "shutdown", false, 500),
            (Draining, "shutdown_result", "forced", false, 500),
            (Stopped, "shutdown_result", "clean", false, 200),
        ]
        .map(|(state, operation, reason, retryable, code)| {
            lifecycle_record(state, operation, reason, retryable, code)
        })
        .to_vec();
        let mut ready_with_generation =
            lifecycle_record(LifecycleState::Ready, "readiness", "ready", false, 200);
        ready_with_generation
            .as_object_mut()
            .expect("lifecycle record object")
            .insert(
                "credential_generation".to_owned(),
                credential_generation_hex(crate::credentials::CredentialGeneration::new(
                    [0xab; 32],
                ))
                .into(),
            );
        records.push(ready_with_generation);
        let combined = records
            .iter()
            .map(serde_json::Value::to_string)
            .collect::<Vec<_>>()
            .join("\n");
        const ALLOWED_FIELDS: [&str; 9] = [
            "timestamp",
            "lifecycle_state",
            "operation",
            "reason",
            "retryable",
            "response_code",
            "latency_bucket",
            "correlation_id",
            "credential_generation",
        ];
        for canary in [
            "config-canary",
            "error-canary",
            "event-canary",
            "peer-canary",
            "provider-canary",
            "/path-canary",
        ] {
            assert!(!combined.contains(canary));
        }
        for line in combined.lines() {
            assert!(line.len() < MAX_OPERATOR_RECORD_BYTES);
            let record: serde_json::Value = serde_json::from_str(line).expect("lifecycle JSON");
            let object = record.as_object().expect("JSON object");
            let has_generation = object.contains_key("credential_generation");
            assert_eq!(object.len(), 8 + usize::from(has_generation));
            for required in &ALLOWED_FIELDS[..8] {
                assert!(object.contains_key(*required));
            }
            assert!(
                object
                    .keys()
                    .all(|field| ALLOWED_FIELDS.contains(&field.as_str()))
            );
            if has_generation {
                assert_eq!(record["operation"], "readiness");
                assert_eq!(
                    record["credential_generation"].as_str().map(str::len),
                    Some(64)
                );
            }
        }
        let btle = records
            .iter()
            .find(|record| record["operation"] == "btle_availability")
            .expect("fixed BTLE lifecycle JSON");
        assert_eq!(btle["operation"], "btle_availability");
        assert_eq!(btle["reason"], "unqualified_package");
        assert_eq!(btle["retryable"], false);
        assert_eq!(btle["response_code"], 503);
    }

    #[test]
    fn btle_owner_errors_are_fixed_and_redacted() {
        // Break caught: carrying a platform error through the owner boundary
        // can leak controller, path, or credential metadata.
        assert_eq!(
            BtleRuntimeOwnerError::Startup.to_string(),
            "BTLE runtime owner failed"
        );
        assert_eq!(
            BtleRuntimeOwnerError::Cleanup.to_string(),
            "BTLE runtime owner failed"
        );
    }

    #[test]
    fn runtime_errors_render_without_variant_details() {
        // Break caught: Debug-like rendering of fixed variants can disclose a
        // lower-level source when the enum later gains internal context.
        assert_eq!(
            AgentRuntimeError::Bootstrap(NodeBootstrapErrorKind::Rejected).to_string(),
            "agent node bootstrap failed"
        );
        assert_eq!(
            AgentRuntimeError::Credential(CredentialReason::FileAccess).to_string(),
            "agent credential validation failed"
        );
    }
}
