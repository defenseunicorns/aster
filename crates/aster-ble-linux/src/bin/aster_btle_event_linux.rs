use aster_ble_linux::{
    ContactLimits, ControllerConfig, DiscoveryCredential, DiscoveryGeneration, DiscoverySecret,
    LeasedDiscoveryCredentialSet, LinkConfig, RING1_MAXIMUM_DEADLINE,
    RING1_MAXIMUM_EXCHANGE_BYTES, RING1_MAXIMUM_FRAME_BYTES, RosteredDiscoveryConfig,
    RosteredSupervisorConfig, SupervisorConfig, spawn_linux_btle_event_supervisor,
    spawn_linux_rostered_btle_event_supervisor,
};
use aster_host::{
    TrustedClockLeaseGuard, TrustedClockSample,
    load_unprotected_reference_discovery_credentials,
};
use aster_node::{
    MutableSourceInterests, NodeApplication, NodeOperatorOutputPolicy, TransportNeutralNodeConfig,
    mission::UnprotectedReferenceMission, parse_node_id,
    start_externally_supervised_transport_neutral_node,
};
use bluer::{Address, AddressType};
use std::{
    collections::BTreeMap,
    fs,
    future::Future,
    os::unix::fs::DirBuilderExt,
    path::PathBuf,
    process::ExitCode,
    str::FromStr,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

const DEFAULT_CONTACT_CADENCE_SECONDS: u64 = 60;
const MAXIMUM_CONTACT_CADENCE_SECONDS: u64 = 24 * 60 * 60;
const TRUSTED_CLOCK_RESAMPLE_INTERVAL: Duration = Duration::from_secs(60);
const USAGE: &str = "usage: aster-btle-event --transport fixed|rostered --adapter hciN \
    --local-address AA:BB:CC:DD:EE:FF --local-address-type public|random \
    --state PATH --mission-bundle PATH --mission-peer NODE_ID_HEX \
    [fixed: --peer-address AA:BB:CC:DD:EE:FF --peer-address-type public|random --psm 0x80..0xff] \
    [rostered: --discovery-scope-id HEX --discovery-credential-unprotected-reference FILE] \
    [--contact-cadence-seconds 1..86400]";

enum EvaluationTransport {
    Fixed(LinkConfig),
    Rostered {
        controller: ControllerConfig,
        discovery_scope_id: [u8; 32],
        credential_reference: PathBuf,
    },
}

struct EvaluationConfig {
    transport: EvaluationTransport,
    state: PathBuf,
    mission_bundle: PathBuf,
    mission_peer: [u8; 32],
    contact_cadence: Duration,
}

enum EvaluationCommand {
    Help,
    Run(EvaluationConfig),
}

fn parse_command(arguments: Vec<String>) -> Result<EvaluationCommand, String> {
    if arguments == ["--help"] {
        return Ok(EvaluationCommand::Help);
    }
    if !arguments.len().is_multiple_of(2) {
        return Err(USAGE.to_owned());
    }

    let mut options = BTreeMap::new();
    for pair in arguments.chunks_exact(2) {
        if !matches!(
            pair[0].as_str(),
            "--transport"
                | "--adapter"
                | "--local-address"
                | "--local-address-type"
                | "--peer-address"
                | "--peer-address-type"
                | "--psm"
                | "--state"
                | "--mission-bundle"
                | "--mission-peer"
                | "--contact-cadence-seconds"
                | "--discovery-scope-id"
                | "--discovery-credential-unprotected-reference"
        ) || options.insert(pair[0].clone(), pair[1].clone()).is_some()
        {
            return Err(USAGE.to_owned());
        }
    }

    let value = |name: &str| options.get(name).cloned().ok_or_else(|| USAGE.to_owned());
    let parse_address = |name: &str| {
        Address::from_str(&value(name)?).map_err(|_| "invalid Bluetooth address".to_owned())
    };
    let address_type = |name: &str| match value(name)?.as_str() {
        "public" => Ok(AddressType::LePublic),
        "random" => Ok(AddressType::LeRandom),
        _ => Err(USAGE.to_owned()),
    };
    let cadence_seconds = match options.get("--contact-cadence-seconds") {
        Some(value) => value
            .parse::<u64>()
            .map_err(|_| "invalid contact cadence".to_owned())?,
        None => DEFAULT_CONTACT_CADENCE_SECONDS,
    };
    if !(1..=MAXIMUM_CONTACT_CADENCE_SECONDS).contains(&cadence_seconds) {
        return Err("invalid contact cadence".to_owned());
    }

    let adapter_name = value("--adapter")?;
    let local_address = parse_address("--local-address")?;
    let local_address_type = address_type("--local-address-type")?;
    let transport = match value("--transport")?.as_str() {
        "fixed" => {
            if options.contains_key("--discovery-scope-id")
                || options.contains_key("--discovery-credential-unprotected-reference")
            {
                return Err(USAGE.to_owned());
            }
            let psm_text = value("--psm")?;
            let psm = if let Some(hex) = psm_text.strip_prefix("0x") {
                u16::from_str_radix(hex, 16)
            } else {
                psm_text.parse()
            }
            .map_err(|_| "invalid LE PSM".to_owned())?;
            EvaluationTransport::Fixed(LinkConfig {
                adapter_name,
                local_address,
                local_address_type,
                peer_address: parse_address("--peer-address")?,
                peer_address_type: address_type("--peer-address-type")?,
                psm,
                maximum_frame_bytes: RING1_MAXIMUM_FRAME_BYTES,
                maximum_exchange_bytes: RING1_MAXIMUM_EXCHANGE_BYTES,
                open_timeout: RING1_MAXIMUM_DEADLINE,
                operation_timeout: RING1_MAXIMUM_DEADLINE,
            })
        }
        "rostered" => {
            if options.contains_key("--peer-address")
                || options.contains_key("--peer-address-type")
                || options.contains_key("--psm")
            {
                return Err(USAGE.to_owned());
            }
            EvaluationTransport::Rostered {
                controller: ControllerConfig {
                    adapter_name,
                    local_address,
                    local_address_type,
                },
                discovery_scope_id: parse_node_id(&value("--discovery-scope-id")?)
                    .map_err(|_| USAGE.to_owned())?,
                credential_reference: PathBuf::from(value(
                    "--discovery-credential-unprotected-reference",
                )?),
            }
        }
        _ => return Err(USAGE.to_owned()),
    };

    Ok(EvaluationCommand::Run(EvaluationConfig {
        transport,
        state: PathBuf::from(value("--state")?),
        mission_bundle: PathBuf::from(value("--mission-bundle")?),
        mission_peer: parse_node_id(&value("--mission-peer")?).map_err(|_| USAGE.to_owned())?,
        contact_cadence: Duration::from_secs(cadence_seconds),
    }))
}

async fn wait_for_fixed_stop(
    shutdown_signal: impl Future<Output = Result<(), String>>,
    supervisor_completion: impl Future<Output = ()>,
) -> Result<(), String> {
    tokio::select! {
        result = shutdown_signal => result,
        () = supervisor_completion => {
            Err("Linux BTLE supervisor stopped unexpectedly".to_owned())
        }
    }
}

async fn finish_shutdown(
    supervisor_stop: impl Future<Output = Result<(), String>>,
    wait_result: Result<(), String>,
    node_stop: impl Future<Output = Result<(), String>>,
) -> Result<(), String> {
    let supervisor_result = supervisor_stop.await;
    let node_result = node_stop.await;
    supervisor_result?;
    wait_result?;
    node_result
}

async fn wait_for_shutdown_signal() -> Result<(), String> {
    let mut terminate = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
        .map_err(|_| "failed to install termination handler".to_owned())?;
    tokio::select! {
        result = tokio::signal::ctrl_c() => {
            result.map_err(|_| "failed to install interrupt handler".to_owned())
        }
        _ = terminate.recv() => Ok(()),
    }
}

async fn run(config: EvaluationConfig) -> Result<(), String> {
    let mission = UnprotectedReferenceMission::load(&config.mission_bundle)
        .map_err(|_| "failed to load the evaluation mission bundle".to_owned())?;
    let local_mission_id = mission.identity();
    let node_config = TransportNeutralNodeConfig {
        state: config.state,
        mission,
        mutable_interests: MutableSourceInterests::default(),
        sync_interval: Duration::from_secs(DEFAULT_CONTACT_CADENCE_SECONDS),
        run_for: None,
        application: NodeApplication::Relay,
    };

    match config.transport {
        EvaluationTransport::Fixed(link) => {
            let supervisor_config = SupervisorConfig {
                link,
                local_mission_id,
                peer_mission_id: config.mission_peer,
                contact_cadence: config.contact_cadence,
            }
            .validate()
            .map_err(|_| "invalid fixed Linux BTLE supervisor configuration".to_owned())?;
            let node = start_externally_supervised_transport_neutral_node(
                node_config,
                NodeOperatorOutputPolicy::CustomerSafe,
            )
            .await
            .map_err(|_| "failed to start the transport-neutral node".to_owned())?;
            let supervisor = spawn_linux_btle_event_supervisor(
                supervisor_config,
                node.ordered_event_contacts(),
            );
            let wait_result = wait_for_fixed_stop(
                wait_for_shutdown_signal(),
                supervisor.wait_for_completion(),
            )
            .await;
            finish_shutdown(
                async move {
                    supervisor
                        .shutdown()
                        .await
                        .map_err(|error| error.to_string())
                },
                wait_result,
                async move {
                    node.shutdown()
                        .await
                        .map(|_| ())
                        .map_err(|_| "node shutdown failed".to_owned())
                },
            )
            .await
        }
        EvaluationTransport::Rostered {
            controller,
            discovery_scope_id,
            credential_reference,
        } => {
            let (credentials, mut clock) = load_reference_credentials(
                discovery_scope_id,
                &credential_reference,
            )?;
            let supervisor_config = RosteredSupervisorConfig {
                controller,
                discovery: RosteredDiscoveryConfig { credentials },
                local_mission_id,
                peer_mission_id: config.mission_peer,
                contact_cadence: config.contact_cadence,
                contact_limits: ContactLimits {
                    maximum_frame_bytes: RING1_MAXIMUM_FRAME_BYTES,
                    maximum_exchange_bytes: RING1_MAXIMUM_EXCHANGE_BYTES,
                    open_timeout: RING1_MAXIMUM_DEADLINE,
                    operation_timeout: RING1_MAXIMUM_DEADLINE,
                },
            }
            .validate()
            .map_err(|_| "invalid rostered Linux BTLE supervisor configuration".to_owned())?;
            let node = start_externally_supervised_transport_neutral_node(
                node_config,
                NodeOperatorOutputPolicy::CustomerSafe,
            )
            .await
            .map_err(|_| "failed to start the transport-neutral node".to_owned())?;
            let supervisor = spawn_linux_rostered_btle_event_supervisor(
                supervisor_config,
                node.ordered_event_contacts(),
            );
            let mut shutdown_signal = Box::pin(wait_for_shutdown_signal());
            let wait_result = loop {
                tokio::select! {
                    result = &mut shutdown_signal => break result,
                    () = supervisor.wait_for_completion() => {
                        break Err("Linux BTLE supervisor stopped unexpectedly".to_owned());
                    }
                    () = tokio::time::sleep(TRUSTED_CLOCK_RESAMPLE_INTERVAL) => {
                        let sample = match trusted_clock_sample() {
                            Ok(sample) => sample,
                            Err(error) => break Err(error),
                        };
                        if clock.resample(sample).is_err() {
                            break Err("trusted clock continuity was lost".to_owned());
                        }
                    }
                }
            };
            if wait_result.is_err() {
                supervisor.cancel();
            }
            finish_shutdown(
                async move {
                    supervisor
                        .shutdown()
                        .await
                        .map_err(|error| error.to_string())
                },
                wait_result,
                async move {
                    node.shutdown()
                        .await
                        .map(|_| ())
                        .map_err(|_| "node shutdown failed".to_owned())
                },
            )
            .await
        }
    }
}

fn load_reference_credentials(
    discovery_scope_id: [u8; 32],
    reference: &std::path::Path,
) -> Result<(LeasedDiscoveryCredentialSet, TrustedClockLeaseGuard), String> {
    let checkpoint = TemporaryCheckpoint::create()?;
    let parent = reference
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| std::path::Path::new("."));
    let basename = reference
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or_else(|| "invalid discovery credential reference".to_owned())?;
    let sample = trusted_clock_sample()?;
    let material = load_unprotected_reference_discovery_credentials(
        discovery_scope_id,
        &checkpoint.0,
        parent,
        basename,
        sample,
    )
    .map_err(|_| "discovery credential reference was rejected".to_owned())?;
    let (emitting, overlap, expires_at) = material.into_parts();
    let emitting = adopt_credential(emitting)?;
    let overlap = overlap.map(adopt_credential).transpose()?;
    let credentials = LeasedDiscoveryCredentialSet::new(emitting, overlap, expires_at)
        .map_err(|_| "discovery credential lease was rejected".to_owned())?;
    Ok((credentials, TrustedClockLeaseGuard::new(sample)))
}

fn trusted_clock_sample() -> Result<TrustedClockSample, String> {
    let wall_unix_seconds = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| "trusted clock is unavailable".to_owned())?
        .as_secs();
    Ok(TrustedClockSample::new(wall_unix_seconds, Instant::now()))
}

fn adopt_credential(
    (generation, secret): (u32, zeroize::Zeroizing<[u8; 32]>),
) -> Result<DiscoveryCredential, String> {
    let generation = DiscoveryGeneration::new(generation)
        .map_err(|_| "discovery credential generation was rejected".to_owned())?;
    let secret = DiscoverySecret::from_zeroizing(secret)
        .map_err(|_| "discovery credential secret was rejected".to_owned())?;
    Ok(DiscoveryCredential::new(generation, secret))
}

struct TemporaryCheckpoint(PathBuf);

impl TemporaryCheckpoint {
    fn create() -> Result<Self, String> {
        for _ in 0..4 {
            let mut suffix = [0_u8; 16];
            getrandom::fill(&mut suffix)
                .map_err(|_| "temporary checkpoint entropy is unavailable".to_owned())?;
            let name = format!(
                "aster-btle-discovery-{}-{}",
                std::process::id(),
                suffix
                    .iter()
                    .map(|byte| format!("{byte:02x}"))
                    .collect::<String>()
            );
            let path = std::env::temp_dir().join(name);
            let mut builder = fs::DirBuilder::new();
            builder.mode(0o700);
            match builder.create(&path) {
                Ok(()) => return Ok(Self(path)),
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => continue,
                Err(_) => return Err("temporary checkpoint could not be created".to_owned()),
            }
        }
        Err("temporary checkpoint name could not be allocated".to_owned())
    }
}

impl Drop for TemporaryCheckpoint {
    fn drop(&mut self) {
        let _ = fs::remove_file(self.0.join("discovery-checkpoint.next"));
        let _ = fs::remove_file(self.0.join("discovery-checkpoint"));
        let _ = fs::remove_dir(&self.0);
    }
}

#[tokio::main]
async fn main() -> ExitCode {
    match parse_command(std::env::args().skip(1).collect()) {
        Ok(EvaluationCommand::Help) => {
            println!("{USAGE}");
            ExitCode::SUCCESS
        }
        Ok(EvaluationCommand::Run(config)) => match run(config).await {
            Ok(()) => ExitCode::SUCCESS,
            Err(error) => {
                eprintln!("aster-btle-event: {error}");
                ExitCode::FAILURE
            }
        },
        Err(error) => {
            eprintln!("aster-btle-event: {error}");
            ExitCode::FAILURE
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{os::unix::fs::PermissionsExt, sync::{Arc, Mutex}};

    fn arguments() -> Vec<String> {
        [
            "--transport",
            "fixed",
            "--adapter",
            "hci2",
            "--local-address",
            "02:00:00:00:00:01",
            "--local-address-type",
            "random",
            "--peer-address",
            "02:00:00:00:00:02",
            "--peer-address-type",
            "public",
            "--psm",
            "0x81",
            "--state",
            "/tmp/aster-btle-event-state",
            "--mission-bundle",
            "/tmp/aster-btle-event-mission.bundle",
            "--mission-peer",
            "0101010101010101010101010101010101010101010101010101010101010101",
        ]
        .into_iter()
        .map(str::to_owned)
        .collect()
    }

    fn rostered_arguments() -> Vec<String> {
        [
            "--transport",
            "rostered",
            "--adapter",
            "hci2",
            "--local-address",
            "02:00:00:00:00:01",
            "--local-address-type",
            "random",
            "--state",
            "/tmp/aster-btle-event-state",
            "--mission-bundle",
            "/tmp/aster-btle-event-mission.bundle",
            "--mission-peer",
            "0101010101010101010101010101010101010101010101010101010101010101",
            "--discovery-scope-id",
            "0202020202020202020202020202020202020202020202020202020202020202",
            "--discovery-credential-unprotected-reference",
            "/tmp/aster-btle-discovery.credential",
        ]
        .into_iter()
        .map(str::to_owned)
        .collect()
    }

    #[test]
    fn parses_unattended_configuration_without_role() {
        let EvaluationCommand::Run(config) = parse_command(arguments()).unwrap() else {
            panic!("run command");
        };
        assert!(matches!(config.transport, EvaluationTransport::Fixed(_)));
        assert_eq!(
            config.contact_cadence,
            Duration::from_secs(DEFAULT_CONTACT_CADENCE_SECONDS)
        );
        assert!(matches!(
            parse_command(vec!["--help".to_owned()]).unwrap(),
            EvaluationCommand::Help
        ));
    }

    #[test]
    fn parses_explicit_rostered_configuration_without_fixed_locator_or_psm() {
        let EvaluationCommand::Run(config) = parse_command(rostered_arguments()).unwrap() else {
            panic!("run command");
        };
        assert!(matches!(
            config.transport,
            EvaluationTransport::Rostered { .. }
        ));

        let mut mixed = rostered_arguments();
        mixed.extend(["--psm".to_owned(), "0x81".to_owned()]);
        assert!(parse_command(mixed).is_err());

        let mut missing_mode = arguments();
        missing_mode.drain(0..2);
        assert!(parse_command(missing_mode).is_err());
    }

    #[test]
    fn temporary_discovery_checkpoint_is_private_and_removed_on_drop() {
        let checkpoint = TemporaryCheckpoint::create().unwrap();
        let path = checkpoint.0.clone();
        assert_eq!(fs::metadata(&path).unwrap().permissions().mode() & 0o777, 0o700);

        drop(checkpoint);
        assert!(!path.exists());
    }

    #[test]
    fn rejects_role_unknown_duplicate_and_invalid_cadence() {
        let mut with_role = arguments();
        with_role.extend(["--role".to_owned(), "initiator".to_owned()]);
        assert!(parse_command(with_role).is_err());

        let mut unknown = arguments();
        unknown.extend(["--fallback".to_owned(), "iroh".to_owned()]);
        assert!(parse_command(unknown).is_err());

        let mut duplicate = arguments();
        duplicate.extend(["--adapter".to_owned(), "hci3".to_owned()]);
        assert!(parse_command(duplicate).is_err());

        for invalid in ["0", "86401", "seconds"] {
            let mut candidate = arguments();
            candidate.extend([
                "--contact-cadence-seconds".to_owned(),
                invalid.to_owned(),
            ]);
            assert!(parse_command(candidate).is_err());
        }
    }

    #[tokio::test]
    async fn shutdown_orders_supervisor_before_node() {
        let events = Arc::new(Mutex::new(Vec::new()));
        let observed = events.clone();
        finish_shutdown(
            {
                let events = events.clone();
                async move {
                    events.lock().unwrap().push("supervisor-stop");
                    Ok(())
                }
            },
            Err("signal failure".to_owned()),
            {
                let events = events.clone();
                async move {
                    events.lock().unwrap().push("node-stop");
                    Ok(())
                }
            },
        )
        .await
        .unwrap_err();

        assert_eq!(
            *observed.lock().unwrap(),
            ["supervisor-stop", "node-stop"]
        );
    }

    #[tokio::test]
    async fn supervisor_failure_wins_over_wait_and_node_failures() {
        let result = finish_shutdown(
            async { Err("supervisor failure".to_owned()) },
            Err("wait failure".to_owned()),
            async { Err("node failure".to_owned()) },
        )
        .await;

        assert_eq!(result.unwrap_err(), "supervisor failure");
    }

    #[tokio::test]
    async fn wait_failure_wins_over_node_failure() {
        let result = finish_shutdown(
            async { Ok(()) },
            Err("wait failure".to_owned()),
            async { Err("node failure".to_owned()) },
        )
        .await;

        assert_eq!(result.unwrap_err(), "wait failure");
    }

    #[tokio::test]
    async fn supervisor_completion_triggers_prompt_shutdown() {
        let result = tokio::time::timeout(
            Duration::from_secs(1),
            wait_for_fixed_stop(std::future::pending(), std::future::ready(())),
        )
        .await
        .expect("supervisor completion must not wait for a process signal")
        .expect_err("unexpected supervisor completion must fail the evaluator");

        assert_eq!(result, "Linux BTLE supervisor stopped unexpectedly");
    }
}
