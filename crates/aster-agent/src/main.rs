use std::{env, net::SocketAddr, path::PathBuf, process::ExitCode, time::Duration};

use aster_agent::{
    BoundAgent, ClientToken,
    config::{check_config, load_and_validate_config},
    runtime::{AgentExit, AgentSignal, run_customer_agent},
};
use aster_node::application::{Scope, Topic};
use aster_node::mission::UnprotectedReferenceMission;
use aster_node::{
    MissionExpectedPeer, MutableSourceInterests, NodeApplication, NodeConfig,
    SourceInterestSelector, ensure_state_accepts_normal_operation, format_path_field, start_node,
};
#[cfg(feature = "nearby-discovery")]
use aster_node::{MissionNearbyPeer, SelectedForwardingConfig, start_node_with_forwarding};
use aster_systemd_credentials::SystemdCredentialLoader;

type BoxError = Box<dyn std::error::Error + Send + Sync>;

enum Invocation {
    CheckConfig(PathBuf),
    CustomerConfig(PathBuf),
    LegacyDevelopment(Arguments),
}

impl Invocation {
    fn parse(mut arguments: Arguments) -> Result<Self, BoxError> {
        let config = arguments.optional("--config")?;
        let check_config = arguments.optional("--check-config")?;
        match (config, check_config) {
            (Some(_), Some(_)) => Err("--config cannot be combined with --check-config".into()),
            (Some(path), None) => {
                if !arguments.values.is_empty() {
                    return Err("--config cannot be combined with legacy flags".into());
                }
                Ok(Self::CustomerConfig(PathBuf::from(path)))
            }
            (None, Some(path)) => {
                if !arguments.values.is_empty() {
                    return Err("--check-config cannot be combined with legacy flags".into());
                }
                Ok(Self::CheckConfig(PathBuf::from(path)))
            }
            (None, None) => Ok(Self::LegacyDevelopment(arguments)),
        }
    }
}

fn main() -> ExitCode {
    let runtime = match tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
    {
        Ok(runtime) => runtime,
        Err(error) => {
            eprintln!("failed to start runtime: {error}");
            return ExitCode::FAILURE;
        }
    };
    match runtime.block_on(run()) {
        Ok(Some(exit)) => ExitCode::from(agent_exit_code(exit)),
        Ok(None) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("ERROR {error}");
            ExitCode::FAILURE
        }
    }
}

async fn run() -> Result<Option<AgentExit>, BoxError> {
    match Invocation::parse(Arguments::new(env::args().skip(1)))? {
        Invocation::CheckConfig(path) => {
            check_config(&path)?;
            Ok(None)
        }
        Invocation::CustomerConfig(path) => {
            let config = load_and_validate_config(&path)?;
            let mut loader = SystemdCredentialLoader::from_environment()?;
            let signals = translated_signals()?;
            Ok(Some(
                run_customer_agent(config, &mut loader, signals).await?,
            ))
        }
        Invocation::LegacyDevelopment(mut arguments) => {
            if arguments.take_flag("--help") || arguments.take_flag("-h") {
                print_help();
                return Ok(None);
            }
            run_legacy(arguments).await?;
            Ok(None)
        }
    }
}

fn agent_exit_code(exit: AgentExit) -> u8 {
    match exit {
        AgentExit::Clean => 0,
        AgentExit::Failed(_) => 1,
        AgentExit::Forced => 2,
    }
}

async fn run_legacy(mut arguments: Arguments) -> Result<(), BoxError> {
    let state = arguments.required_path("--state")?;
    let mesh_bind: SocketAddr = arguments.required("--mesh-bind")?.parse()?;
    let listen: SocketAddr = arguments
        .optional("--listen")?
        .unwrap_or_else(|| "127.0.0.1:8181".to_owned())
        .parse()?;
    let mission_bundle = arguments.required_path("--mission-bundle-unprotected-reference")?;
    let client_token_file = arguments.required_path("--client-token-file")?;
    let peers = arguments
        .repeated("--peer")?
        .into_iter()
        .map(|peer| peer.parse::<MissionExpectedPeer>())
        .collect::<Result<Vec<_>, _>>()?;
    #[cfg(feature = "nearby-discovery")]
    let nearby_peers = arguments
        .repeated("--nearby-peer")?
        .into_iter()
        .map(|peer| peer.parse::<MissionNearbyPeer>())
        .collect::<Result<Vec<_>, _>>()?;
    #[cfg(feature = "nearby-discovery")]
    let nearby_window = arguments
        .optional("--nearby-window")?
        .map(|seconds| seconds.parse::<u64>())
        .transpose()?;
    #[cfg(feature = "nearby-discovery")]
    let discover_lan = arguments.switch("--discover-lan")?;
    let state_interests = arguments
        .repeated("--state-interest")?
        .into_iter()
        .map(|value| parse_source_interest(&value, "State"))
        .collect::<Result<Vec<_>, _>>()?;
    let record_interests = arguments
        .repeated("--record-interest")?
        .into_iter()
        .map(|value| parse_source_interest(&value, "Record"))
        .collect::<Result<Vec<_>, _>>()?;
    let sync_interval = Duration::from_millis(
        arguments
            .optional("--sync-ms")?
            .map_or(Ok(500_u64), |value| value.parse())?,
    );
    arguments.finish()?;

    #[cfg(feature = "nearby-discovery")]
    let (forwarding, nearby_enabled) = apply_nearby_cli(
        SelectedForwardingConfig::default(),
        peers.len(),
        nearby_peers,
        discover_lan,
        nearby_window,
    )?;

    ensure_state_accepts_normal_operation(&state)?;
    let agent = BoundAgent::bind(listen).await?;
    let listen = agent.local_addr()?;
    let client_token = ClientToken::load(&client_token_file)?;
    let mission = UnprotectedReferenceMission::load(&mission_bundle)?;
    let config = NodeConfig {
        state: state.clone(),
        bind: mesh_bind,
        mission,
        peers,
        mutable_interests: MutableSourceInterests::new(state_interests, record_interests),
        sync_interval,
        run_for: None,
        application: NodeApplication::Relay,
    };
    #[cfg(feature = "nearby-discovery")]
    let node = if nearby_enabled {
        start_node_with_forwarding(config, forwarding).await?
    } else {
        start_node(config).await?
    };
    #[cfg(not(feature = "nearby-discovery"))]
    let node = start_node(config).await?;
    let events = node.selected_events();

    println!(
        "AGENT status=ready listen=http://{listen} mesh_bind={mesh_bind} state={} protocol=connect+grpc+grpc-web api=aster.application.v1alpha1 event_live=true state_live=false record_live=false plaintext=loopback-only",
        format_path_field(&state),
    );

    let (shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);
    let mut signals = translated_signals()?;
    let signal = tokio::spawn(async move {
        while let Some(signal) = signals.recv().await {
            if signal == AgentSignal::Terminate {
                let _ = shutdown_tx.send(true);
                return;
            }
        }
    });
    let server_result = agent.serve(events, client_token, shutdown_rx).await;
    signal.abort();
    let node_result = node.shutdown().await;
    server_result?;
    node_result?;
    Ok(())
}

#[cfg(unix)]
fn translated_signals() -> Result<tokio::sync::mpsc::Receiver<AgentSignal>, BoxError> {
    use tokio::signal::unix::{SignalKind, signal};

    let mut hangup = signal(SignalKind::hangup())?;
    let mut interrupt = signal(SignalKind::interrupt())?;
    let mut terminate = signal(SignalKind::terminate())?;
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
fn translated_signals() -> Result<tokio::sync::mpsc::Receiver<AgentSignal>, BoxError> {
    let (sender, receiver) = tokio::sync::mpsc::channel(4);
    tokio::spawn(async move {
        if tokio::signal::ctrl_c().await.is_ok() {
            let _ = sender.send(AgentSignal::Terminate).await;
        }
    });
    Ok(receiver)
}

fn parse_source_interest(value: &str, class: &str) -> Result<SourceInterestSelector, BoxError> {
    let (topic, scope) = value
        .split_once('@')
        .ok_or_else(|| format!("{class} interest must use exact TOPIC@SCOPE syntax"))?;
    if scope.contains('@') {
        return Err(format!("{class} interest contains more than one separator").into());
    }
    Ok(SourceInterestSelector::new(
        Topic::new(topic)?,
        Scope::new(scope)?,
        false,
    ))
}

#[cfg(feature = "nearby-discovery")]
fn validate_discover_lan_conflicts(
    discover_lan: bool,
    direct_peer_count: usize,
    nearby_peer_count: usize,
) -> Result<(), BoxError> {
    if discover_lan && direct_peer_count != 0 {
        return Err("--discover-lan cannot be combined with --peer".into());
    }
    if discover_lan && nearby_peer_count != 0 {
        return Err("--discover-lan cannot be combined with --nearby-peer".into());
    }
    Ok(())
}

#[cfg(feature = "nearby-discovery")]
fn apply_nearby_cli(
    forwarding: SelectedForwardingConfig,
    direct_peer_count: usize,
    nearby_peers: Vec<MissionNearbyPeer>,
    discover_lan: bool,
    nearby_window: Option<u64>,
) -> Result<(SelectedForwardingConfig, bool), BoxError> {
    validate_discover_lan_conflicts(discover_lan, direct_peer_count, nearby_peers.len())?;
    let window = Duration::from_secs(nearby_window.unwrap_or(10));
    if discover_lan {
        return Ok((forwarding.with_automatic_nearby_discovery(window)?, true));
    }
    if nearby_peers.is_empty() {
        if nearby_window.is_some() {
            return Err("--nearby-window requires at least one --nearby-peer".into());
        }
        return Ok((forwarding, false));
    }
    Ok((
        forwarding.with_nearby_discovery(nearby_peers, window)?,
        true,
    ))
}

const HELP: &str = r#"Aster process-local ConnectRPC agent

Usage:
  aster-agent --state DIR --mesh-bind IP:PORT \
    --mission-bundle-unprotected-reference FILE \
    --client-token-file FILE \
    [--listen 127.0.0.1:8181] \
    [--peer CARRIER_ID@IP:PORT=MISSION_NODE_ID_HEX64 ...] \
    [--nearby-peer CARRIER_ID=MISSION_NODE_ID_HEX64 ...] \
    [--discover-lan] [--nearby-window SECONDS] \
    [--state-interest TOPIC@SCOPE ...] \
    [--record-interest TOPIC@SCOPE ...] [--sync-ms N]

The plaintext application listener is restricted to loopback and every RPC
requires an owner-provisioned bearer token from an owner-only regular file.
This makes the deployment unit suitable for a same-host process or Kubernetes
sidecar, not a remotely exposed service. State and Record interests configure
mesh carriage; their live application RPCs remain unavailable until
handle-backed APIs exist. The explicitly named unprotected-reference mission
bundle is non-production provisioning and must remain owner-only on supported
Unix platforms. Nearby flags are available only in explicitly discovery-enabled
demo/evaluation builds; they publish carrier identity and direct address hints
for a bounded window, never mission or application metadata. --discover-lan
takes no peer identity or address, cannot be combined with --peer or
--nearby-peer, and admits an mDNS candidate only after the independent mission
handshake authenticates it and current mission authorization succeeds."#;

fn print_help() {
    println!("{HELP}");
}

struct Arguments {
    values: Vec<String>,
}

impl Arguments {
    fn new(values: impl Iterator<Item = String>) -> Self {
        Self {
            values: values.collect(),
        }
    }

    fn take_flag(&mut self, flag: &str) -> bool {
        let Some(index) = self.values.iter().position(|value| value == flag) else {
            return false;
        };
        self.values.remove(index);
        true
    }

    fn required(&mut self, flag: &str) -> Result<String, BoxError> {
        self.optional(flag)?
            .ok_or_else(|| format!("missing required {flag}").into())
    }

    fn required_path(&mut self, flag: &str) -> Result<PathBuf, BoxError> {
        self.required(flag).map(PathBuf::from)
    }

    fn optional(&mut self, flag: &str) -> Result<Option<String>, BoxError> {
        let Some(index) = self.values.iter().position(|value| value == flag) else {
            return Ok(None);
        };
        if index + 1 >= self.values.len() || self.values[index + 1].starts_with("--") {
            return Err(format!("{flag} requires a value").into());
        }
        self.values.remove(index);
        Ok(Some(self.values.remove(index)))
    }

    fn repeated(&mut self, flag: &str) -> Result<Vec<String>, BoxError> {
        let mut output = Vec::new();
        while let Some(value) = self.optional(flag)? {
            output.push(value);
        }
        Ok(output)
    }

    #[cfg(feature = "nearby-discovery")]
    fn switch(&mut self, flag: &str) -> Result<bool, BoxError> {
        let matches = self.values.iter().filter(|value| *value == flag).count();
        if matches > 1 {
            return Err(format!("{flag} may be specified at most once").into());
        }
        let Some(index) = self.values.iter().position(|value| value == flag) else {
            return Ok(false);
        };
        self.values.remove(index);
        Ok(true)
    }

    fn finish(self) -> Result<(), BoxError> {
        if self.values.is_empty() {
            Ok(())
        } else {
            Err(format!("unexpected arguments: {}", self.values.join(" ")).into())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn discover_lan_help_names_identity_free_authorized_mode() {
        assert!(HELP.contains("[--discover-lan]"));
        assert!(HELP.contains("takes no peer identity or address"));
        assert!(HELP.contains("cannot be combined with --peer or\n--nearby-peer"));
        assert!(HELP.contains("authenticates it and current mission authorization succeeds"));
    }

    #[test]
    fn customer_configuration_modes_are_exclusive_with_legacy_flags() {
        let check = Invocation::parse(Arguments::new(
            ["--check-config", "/etc/aster-agent.json"]
                .into_iter()
                .map(str::to_owned),
        ))
        .expect("check-config invocation");
        assert!(matches!(check, Invocation::CheckConfig(_)));

        let result = Invocation::parse(Arguments::new(
            [
                "--config",
                "/etc/aster-agent.json",
                "--state",
                "/var/lib/aster",
            ]
            .into_iter()
            .map(str::to_owned),
        ));
        let error = match result {
            Ok(_) => panic!("legacy flags must not mix with customer config"),
            Err(error) => error,
        };
        assert_eq!(
            error.to_string(),
            "--config cannot be combined with legacy flags"
        );
    }

    #[test]
    fn forced_customer_shutdown_has_a_distinct_non_success_exit_code() {
        assert_eq!(agent_exit_code(aster_agent::runtime::AgentExit::Clean), 0);
        assert_eq!(
            agent_exit_code(aster_agent::runtime::AgentExit::Failed(
                aster_agent::lifecycle::FailureReason::Runtime,
            )),
            1
        );
        assert_eq!(agent_exit_code(aster_agent::runtime::AgentExit::Forced), 2);
    }

    #[cfg(feature = "nearby-discovery")]
    #[test]
    fn discover_lan_switch_and_conflicts_fail_closed() {
        let mut arguments = Arguments::new(["--discover-lan"].into_iter().map(str::to_owned));
        assert!(arguments.switch("--discover-lan").expect("single switch"));
        arguments.finish().expect("all arguments consumed");

        let mut duplicate = Arguments::new(
            ["--discover-lan", "--discover-lan"]
                .into_iter()
                .map(str::to_owned),
        );
        assert!(duplicate.switch("--discover-lan").is_err());
        assert!(validate_discover_lan_conflicts(true, 1, 0).is_err());
        assert!(validate_discover_lan_conflicts(true, 0, 1).is_err());
        validate_discover_lan_conflicts(true, 0, 0).expect("identity-free discovery");
    }

    #[cfg(feature = "nearby-discovery")]
    #[test]
    fn discover_lan_uses_default_window_and_runtime_bounds() {
        let (defaulted, enabled) = apply_nearby_cli(
            SelectedForwardingConfig::default(),
            0,
            Vec::new(),
            true,
            None,
        )
        .expect("default automatic discovery");
        assert!(enabled);
        assert!(defaulted.automatic_nearby_discovery());
        assert_eq!(
            defaulted.nearby_discovery_window(),
            Some(Duration::from_secs(10))
        );

        for seconds in [0, 31] {
            assert!(
                apply_nearby_cli(
                    SelectedForwardingConfig::default(),
                    0,
                    Vec::new(),
                    true,
                    Some(seconds),
                )
                .is_err(),
                "accepted invalid automatic discovery window {seconds}"
            );
        }
    }
}
