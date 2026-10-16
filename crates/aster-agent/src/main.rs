use std::{
    collections::BTreeSet, env, net::SocketAddr, path::PathBuf, process::ExitCode, time::Duration,
};

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

const MAX_BLOB_INTERESTS: usize = 256;

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
    let mutable_interests = parse_legacy_mutable_interests(&mut arguments)?;
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
        mutable_interests,
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
    let pinned_state = node.state_root().to_path_buf();
    let events = node.selected_events();
    let blobs = node.selected_blobs();
    let (shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);
    // Construct every fallible route before announcing readiness.
    let server = agent.serve_with_blobs(events, blobs, pinned_state, client_token, shutdown_rx)?;

    println!(
        "AGENT status=ready listen=http://{listen} mesh_bind={mesh_bind} state={} protocol=connect+grpc+grpc-web api=aster.application.v1alpha1 event_live=true blob_live={} state_live=false record_live=false plaintext=loopback-only",
        format_path_field(&state),
        cfg!(target_os = "linux"),
    );

    let mut signals = translated_signals()?;
    let signal = tokio::spawn(async move {
        while let Some(signal) = signals.recv().await {
            if signal == AgentSignal::Terminate {
                let _ = shutdown_tx.send(true);
                return;
            }
        }
    });
    let server_result = server.await;
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
    let topic = match Topic::new(topic) {
        Ok(topic) => topic,
        Err(_) if class == "Blob" => return Err("Blob interest topic is invalid".into()),
        Err(error) => return Err(error.into()),
    };
    let scope = match Scope::new(scope) {
        Ok(scope) => scope,
        Err(_) if class == "Blob" => return Err("Blob interest scope is invalid".into()),
        Err(error) => return Err(error.into()),
    };
    Ok(SourceInterestSelector::new(topic, scope, false))
}

fn parse_legacy_mutable_interests(
    arguments: &mut Arguments,
) -> Result<MutableSourceInterests, BoxError> {
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
    let raw_blob_interests = arguments.repeated("--blob-interest")?;
    if raw_blob_interests.len() > MAX_BLOB_INTERESTS {
        return Err(format!("Blob interest selector count exceeds {MAX_BLOB_INTERESTS}").into());
    }
    let mut exact_blob_interests = BTreeSet::new();
    let mut blob_interests = Vec::with_capacity(raw_blob_interests.len());
    for value in raw_blob_interests {
        let selector = parse_source_interest(&value, "Blob")?;
        if !exact_blob_interests.insert((selector.topic().clone(), selector.scope().clone())) {
            return Err("Blob interest repeats an exact topic/scope selector".into());
        }
        blob_interests.push(selector);
    }
    Ok(MutableSourceInterests::new(state_interests, record_interests).with_blob(blob_interests))
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
    [--record-interest TOPIC@SCOPE ...] \
    [--blob-interest TOPIC@SCOPE ...] [--sync-ms N]

The plaintext application listener is restricted to loopback and every RPC
requires an owner-provisioned bearer token from an owner-only regular file.
This makes the deployment unit suitable for a same-host process or Kubernetes
sidecar, not a remotely exposed service. State and Record interests configure
mesh carriage; their live application RPCs remain unavailable until
handle-backed APIs exist. Blob interests are restart-only mesh receive configuration;
they do not grant or configure application API access. The explicitly named
unprotected-reference mission
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

    fn blob_interest_arguments(interests: impl IntoIterator<Item = String>) -> Arguments {
        Arguments::new(
            interests
                .into_iter()
                .flat_map(|interest| ["--blob-interest".to_owned(), interest]),
        )
    }

    #[test]
    fn discover_lan_help_names_identity_free_authorized_mode() {
        assert!(HELP.contains("[--discover-lan]"));
        assert!(HELP.contains("takes no peer identity or address"));
        assert!(HELP.contains("cannot be combined with --peer or\n--nearby-peer"));
        assert!(HELP.contains("authenticates it and current mission authorization succeeds"));
    }

    #[test]
    fn help_distinguishes_blob_mesh_receive_interest_from_application_api_access() {
        assert!(HELP.contains("[--blob-interest TOPIC@SCOPE ...]"));
        assert!(HELP.contains("Blob interests are restart-only mesh receive configuration"));
        assert!(HELP.contains("do not grant or configure application API access"));
    }

    #[test]
    fn legacy_cli_accepts_repeatable_blob_interests_without_changing_state_or_record() {
        let mut arguments = Arguments::new(
            [
                "--blob-interest",
                "imagery@mission/alpha",
                "--state-interest",
                "sensors@mission/bravo",
                "--blob-interest",
                "documents@mission/charlie",
                "--record-interest",
                "audit@mission/delta",
            ]
            .into_iter()
            .map(str::to_owned),
        );

        let interests =
            parse_legacy_mutable_interests(&mut arguments).expect("parse legacy interests");
        arguments.finish().expect("consume all interest flags");

        assert_eq!(
            interests,
            MutableSourceInterests::new(
                vec![SourceInterestSelector::new(
                    Topic::new("sensors").expect("literal topic"),
                    Scope::new("mission/bravo").expect("literal scope"),
                    false,
                )],
                vec![SourceInterestSelector::new(
                    Topic::new("audit").expect("literal topic"),
                    Scope::new("mission/delta").expect("literal scope"),
                    false,
                )],
            )
            .with_blob(vec![
                SourceInterestSelector::new(
                    Topic::new("imagery").expect("literal topic"),
                    Scope::new("mission/alpha").expect("literal scope"),
                    false,
                ),
                SourceInterestSelector::new(
                    Topic::new("documents").expect("literal topic"),
                    Scope::new("mission/charlie").expect("literal scope"),
                    false,
                ),
            ])
        );
    }

    #[test]
    fn legacy_cli_rejects_malformed_blob_interest_with_fixed_class_without_echoing_value() {
        let canary = "blob-interest-secret-canary";
        let mut arguments =
            Arguments::new(["--blob-interest", canary].into_iter().map(str::to_owned));

        let error = parse_legacy_mutable_interests(&mut arguments)
            .expect_err("malformed Blob interest must fail");

        assert_eq!(
            error.to_string(),
            "Blob interest must use exact TOPIC@SCOPE syntax"
        );
        assert!(!error.to_string().contains(canary));
    }

    #[test]
    fn legacy_cli_rejects_duplicate_blob_interests_without_echoing_value() {
        let canary = "duplicate-secret-canary@mission/alpha";
        let mut arguments = blob_interest_arguments([canary, canary].map(str::to_owned));

        let error = parse_legacy_mutable_interests(&mut arguments)
            .expect_err("duplicate Blob interests must fail");

        assert_eq!(
            error.to_string(),
            "Blob interest repeats an exact topic/scope selector"
        );
        assert!(!error.to_string().contains(canary));
    }

    #[test]
    fn legacy_cli_accepts_exactly_256_unique_blob_interests() {
        let mut arguments =
            blob_interest_arguments((0..256).map(|index| format!("blob-{index}@mission/alpha")));

        parse_legacy_mutable_interests(&mut arguments).expect("exactly 256 unique Blob interests");
        arguments.finish().expect("consume all interest flags");
    }

    #[test]
    fn legacy_cli_rejects_257_blob_interests_without_echoing_values() {
        let mut arguments = blob_interest_arguments(
            (0..257).map(|index| format!("excess-secret-canary-{index}@mission/alpha")),
        );

        let error = parse_legacy_mutable_interests(&mut arguments)
            .expect_err("257 Blob interests must fail");

        assert_eq!(
            error.to_string(),
            "Blob interest selector count exceeds 256"
        );
        assert!(!error.to_string().contains("excess-secret-canary"));
    }

    #[test]
    fn legacy_cli_rejects_invalid_blob_topic_with_fixed_value_free_diagnostic() {
        let canary = "invalid topic secret@mission/alpha";
        let mut arguments = blob_interest_arguments([canary.to_owned()]);

        let error = parse_legacy_mutable_interests(&mut arguments)
            .expect_err("invalid Blob topic must fail");

        assert_eq!(error.to_string(), "Blob interest topic is invalid");
        assert!(!error.to_string().contains(canary));
    }

    #[test]
    fn legacy_cli_rejects_invalid_blob_scope_with_fixed_value_free_diagnostic() {
        let canary = "imagery@mission//invalid-scope-secret";
        let mut arguments = blob_interest_arguments([canary.to_owned()]);

        let error = parse_legacy_mutable_interests(&mut arguments)
            .expect_err("invalid Blob scope must fail");

        assert_eq!(error.to_string(), "Blob interest scope is invalid");
        assert!(!error.to_string().contains(canary));
    }

    #[test]
    fn legacy_cli_rejects_empty_blob_components_with_fixed_value_free_diagnostics() {
        for (selector, expected) in [
            ("@mission/alpha", "Blob interest topic is invalid"),
            ("imagery@", "Blob interest scope is invalid"),
        ] {
            let mut arguments = blob_interest_arguments([selector.to_owned()]);
            let error = parse_legacy_mutable_interests(&mut arguments)
                .expect_err("empty Blob component must fail");
            assert_eq!(error.to_string(), expected);
            assert!(!error.to_string().contains(selector));
        }
    }

    #[test]
    fn legacy_cli_rejects_overlength_blob_components_with_fixed_value_free_diagnostics() {
        let oversized = "x".repeat(129);
        for (selector, expected) in [
            (
                format!("{oversized}@mission/alpha"),
                "Blob interest topic is invalid",
            ),
            (
                format!("imagery@{oversized}"),
                "Blob interest scope is invalid",
            ),
        ] {
            let mut arguments = blob_interest_arguments([selector]);
            let error = parse_legacy_mutable_interests(&mut arguments)
                .expect_err("overlength Blob component must fail");
            assert_eq!(error.to_string(), expected);
            assert!(!error.to_string().contains(&oversized));
        }
    }

    #[test]
    fn state_and_record_name_diagnostics_remain_unchanged() {
        let state_error = parse_source_interest("invalid topic@mission/alpha", "State")
            .expect_err("invalid State topic must fail");
        assert_eq!(
            state_error.to_string(),
            "name contains a non-canonical character"
        );

        let record_error = parse_source_interest("audit@mission//alpha", "Record")
            .expect_err("invalid Record scope must fail");
        assert_eq!(
            record_error.to_string(),
            "scope must contain canonical non-empty path segments"
        );
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
