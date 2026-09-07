//! Customer runtime supervision for the protected selected Event service.

use std::{error::Error, fmt, path::PathBuf, time::Duration};

use aster_mesh::ProvisioningSecretLoader;
use aster_node::{
    NodeBootstrapErrorKind, NodeError, NodeOperatorOutputPolicy, RunningNode,
    start_supervised_node_with_forwarding_and_output_policy,
};
use tokio::{sync::mpsc, task::JoinHandle};

use crate::{
    config::{ConfigReason, ValidatedAgentConfig},
    credentials::{CredentialReason, load_startup_credentials, open_node_config},
    event_service::application_service,
    health::BoundHealth,
    lifecycle::{FailureReason, LifecycleState, ServiceStatus},
    server::{BoundAgent, ServerStop},
};

const NODE_FAILURE_CHECK_INTERVAL: Duration = Duration::from_millis(100);

/// One process-control signal after platform-specific translation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AgentSignal {
    /// Reload the configured client bearer-token file.
    Hangup,
    /// Begin or force process shutdown.
    Terminate,
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
    config: ValidatedAgentConfig,
    loader: &mut L,
    mut signals: mpsc::Receiver<AgentSignal>,
) -> Result<AgentExit, AgentRuntimeError>
where
    L: ProvisioningSecretLoader + ?Sized,
{
    // The complete credential set is read and checked before any listener or
    // state side effect. The already-validated config owns all stable values.
    let credentials = load_startup_credentials(config.credential_paths())
        .map_err(|error| AgentRuntimeError::Credential(error.reason()))?;
    let token_path = PathBuf::from(config.credential_paths().client_token_file());
    let application_address = config.application();
    let health_address = config.health();
    let forwarding = config.forwarding();
    let limits = *config.limits();

    let health = BoundHealth::bind(health_address)
        .await
        .map_err(|_| AgentRuntimeError::Listener(FailureReason::Startup))?;
    let status = ServiceStatus::starting();
    let (health_stop_send, health_stop_receive) = tokio::sync::watch::channel(false);
    let mut health_task = tokio::spawn(health.serve(status.clone(), health_stop_receive));
    emit_lifecycle(LifecycleState::Starting, "startup", "started", false, 0);
    tokio::task::yield_now().await;

    let node_config = match open_node_config(&config, &credentials, loader) {
        Ok(node_config) => node_config,
        Err(error) => {
            fail_startup(&status, &health_stop_send, &mut health_task).await;
            return Err(AgentRuntimeError::Bootstrap(error.kind()));
        }
    };
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
    let application = match BoundAgent::bind(application_address).await {
        Ok(application) => application,
        Err(_) => {
            let _ = node.shutdown().await;
            fail_startup(&status, &health_stop_send, &mut health_task).await;
            return Err(AgentRuntimeError::Listener(FailureReason::Startup));
        }
    };

    let events = node.selected_events();
    let monitored_events = events.clone();
    let (stream_stop_send, stream_stop_receive) = tokio::sync::watch::channel(false);
    let (server_stop_send, server_stop_receive) = tokio::sync::watch::channel(ServerStop::Run);
    let service = application_service(events, stream_stop_receive);
    let mut server_task = tokio::spawn(application.serve(
        service,
        credentials.token.clone(),
        status.clone(),
        limits,
        server_stop_receive,
    ));
    tokio::task::yield_now().await;
    if server_task.is_finished() {
        let _ = node.shutdown().await;
        fail_startup(&status, &health_stop_send, &mut health_task).await;
        return Err(AgentRuntimeError::Listener(FailureReason::Startup));
    }
    if status.transition(LifecycleState::Ready).is_err() {
        let _ = server_stop_send.send(ServerStop::Force);
        server_task.abort();
        let _ = node.shutdown().await;
        fail_startup(&status, &health_stop_send, &mut health_task).await;
        return Err(AgentRuntimeError::Lifecycle(FailureReason::Startup));
    }
    emit_lifecycle(LifecycleState::Ready, "readiness", "ready", false, 200);

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
                    let succeeded = credentials.token.reload_from(&token_path).is_ok();
                    emit_lifecycle(
                        LifecycleState::Ready,
                        "token_reload",
                        if succeeded { "reloaded" } else { "rejected" },
                        !succeeded,
                        if succeeded { 200 } else { 503 },
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
        }
    };

    match transition {
        RunningTransition::Drain => {
            drain(
                status,
                signals,
                stream_stop_send,
                server_stop_send,
                server_task,
                health_stop_send,
                health_task,
                node_monitor,
                node,
                limits.shutdown_grace(),
            )
            .await
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
            let _ = tokio::time::timeout(limits.shutdown_grace(), node.shutdown()).await;
            if !health_completed {
                stop_health(health_stop_send, health_task).await;
            }
            Ok(AgentExit::Failed(FailureReason::Runtime))
        }
    }
}

const fn customer_node_output_policy() -> NodeOperatorOutputPolicy {
    NodeOperatorOutputPolicy::CustomerSafe
}

#[allow(clippy::too_many_arguments)]
async fn drain(
    status: ServiceStatus,
    mut signals: mpsc::Receiver<AgentSignal>,
    stream_stop_send: tokio::sync::watch::Sender<bool>,
    server_stop_send: tokio::sync::watch::Sender<ServerStop>,
    mut server_task: JoinHandle<Result<(), crate::server::ServerError>>,
    health_stop_send: tokio::sync::watch::Sender<bool>,
    mut health_task: JoinHandle<Result<(), crate::health::HealthError>>,
    node_monitor: JoinHandle<()>,
    node: RunningNode,
    grace: Duration,
) -> Result<AgentExit, AgentRuntimeError> {
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

    let (node_shutdown_send, node_shutdown_receive) = tokio::sync::oneshot::channel();
    let mut node_shutdown_send = Some(node_shutdown_send);
    let mut node_task = tokio::spawn(async move {
        let _ = node_shutdown_receive.await;
        node.shutdown().await.map(|_| ())
    });
    let deadline = tokio::time::sleep(grace);
    tokio::pin!(deadline);
    let mut server_done = false;
    let mut node_done = false;
    let mut failed = false;
    let mut signals_open = true;

    while !server_done || !node_done {
        tokio::select! {
            signal = signals.recv(), if signals_open => match signal {
                Some(AgentSignal::Terminate) => {
                    force_shutdown(
                        &server_stop_send,
                        &mut server_task,
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
                if let Some(send) = node_shutdown_send.take() {
                    let _ = send.send(());
                }
            }
            result = &mut node_task, if !node_done => {
                node_done = true;
                failed |= !matches!(result, Ok(Ok(())));
            }
            _ = &mut health_task => {
                server_task.abort();
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
    node_task: &mut JoinHandle<Result<(), NodeError>>,
    health_stop_send: tokio::sync::watch::Sender<bool>,
    health_task: JoinHandle<Result<(), crate::health::HealthError>>,
) {
    let _ = server_stop_send.send(ServerStop::Force);
    server_task.abort();
    node_task.abort();
    stop_health(health_stop_send, health_task).await;
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
        lifecycle_json(state, operation, reason, retryable, response_code)
    );
}

fn lifecycle_json(
    state: LifecycleState,
    operation: &'static str,
    reason: &'static str,
    retryable: bool,
    response_code: u16,
) -> String {
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
    .to_string()
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
    fn customer_output_boundary_selects_silent_node_and_fixed_agent_records() {
        // Break caught: starting the selected node in legacy mode mixes raw
        // node receipts with the agent lifecycle allowlist even when the JSON
        // serializer itself remains bounded.
        assert_eq!(
            customer_node_output_policy(),
            aster_node::NodeOperatorOutputPolicy::CustomerSafe
        );
        let combined = [
            lifecycle_json(LifecycleState::Starting, "startup", "started", false, 0),
            lifecycle_json(
                LifecycleState::Failed,
                "fatal_transition",
                "runtime",
                false,
                500,
            ),
        ]
        .join("\n");
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
            let record: serde_json::Value = serde_json::from_str(line).expect("lifecycle JSON");
            let object = record.as_object().expect("JSON object");
            assert_eq!(object.len(), 8);
            for field in object.keys() {
                assert!(matches!(
                    field.as_str(),
                    "timestamp"
                        | "lifecycle_state"
                        | "operation"
                        | "reason"
                        | "retryable"
                        | "response_code"
                        | "latency_bucket"
                        | "correlation_id"
                ));
            }
        }
    }

    #[test]
    fn lifecycle_records_have_only_fixed_public_fields_and_values() {
        // Break caught: adding raw errors, paths, configuration, Event fields,
        // or provider text to lifecycle records violates the log boundary.
        let canaries = [
            "config-canary",
            "error-canary",
            "event-canary",
            "provider-canary",
            "/path-canary",
        ];
        let encoded = lifecycle_json(
            LifecycleState::Failed,
            "fatal_transition",
            "runtime",
            false,
            500,
        );
        let record: serde_json::Value = serde_json::from_str(&encoded).expect("lifecycle JSON");
        let object = record.as_object().expect("JSON object");
        let mut fields = object.keys().map(String::as_str).collect::<Vec<_>>();
        fields.sort_unstable();
        assert_eq!(
            fields,
            [
                "correlation_id",
                "latency_bucket",
                "lifecycle_state",
                "operation",
                "reason",
                "response_code",
                "retryable",
                "timestamp",
            ]
        );
        for canary in canaries {
            assert!(!encoded.contains(canary));
        }
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
