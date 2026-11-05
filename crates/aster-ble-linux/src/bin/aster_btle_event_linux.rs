use aster_ble_linux::{
    LinkConfig, RING1_MAXIMUM_DEADLINE, RING1_MAXIMUM_EXCHANGE_BYTES,
    RING1_MAXIMUM_FRAME_BYTES, SupervisorConfig, spawn_linux_btle_event_supervisor,
};
use aster_node::{
    MutableSourceInterests, NodeApplication, TransportNeutralNodeConfig,
    mission::UnprotectedReferenceMission, parse_node_id, start_transport_neutral_node,
};
use bluer::{Address, AddressType};
use std::{
    collections::BTreeMap,
    future::Future,
    path::PathBuf,
    pin::Pin,
    process::ExitCode,
    str::FromStr,
    time::Duration,
};

const DEFAULT_CONTACT_CADENCE_SECONDS: u64 = 60;
const MAXIMUM_CONTACT_CADENCE_SECONDS: u64 = 24 * 60 * 60;
const USAGE: &str = "usage: aster-btle-event --adapter hciN \
    --local-address AA:BB:CC:DD:EE:FF --local-address-type public|random \
    --peer-address AA:BB:CC:DD:EE:FF --peer-address-type public|random \
    --psm 0x80..0xff --state PATH --mission-bundle PATH --mission-peer NODE_ID_HEX \
    [--contact-cadence-seconds 1..86400]";

struct EvaluationConfig {
    link: LinkConfig,
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
            "--adapter"
                | "--local-address"
                | "--local-address-type"
                | "--peer-address"
                | "--peer-address-type"
                | "--psm"
                | "--state"
                | "--mission-bundle"
                | "--mission-peer"
                | "--contact-cadence-seconds"
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
    let psm_text = value("--psm")?;
    let psm = if let Some(hex) = psm_text.strip_prefix("0x") {
        u16::from_str_radix(hex, 16)
    } else {
        psm_text.parse()
    }
    .map_err(|_| "invalid LE PSM".to_owned())?;
    let cadence_seconds = match options.get("--contact-cadence-seconds") {
        Some(value) => value
            .parse::<u64>()
            .map_err(|_| "invalid contact cadence".to_owned())?,
        None => DEFAULT_CONTACT_CADENCE_SECONDS,
    };
    if !(1..=MAXIMUM_CONTACT_CADENCE_SECONDS).contains(&cadence_seconds) {
        return Err("invalid contact cadence".to_owned());
    }

    Ok(EvaluationCommand::Run(EvaluationConfig {
        link: LinkConfig {
            adapter_name: value("--adapter")?,
            local_address: parse_address("--local-address")?,
            local_address_type: address_type("--local-address-type")?,
            peer_address: parse_address("--peer-address")?,
            peer_address_type: address_type("--peer-address-type")?,
            psm,
            maximum_frame_bytes: RING1_MAXIMUM_FRAME_BYTES,
            maximum_exchange_bytes: RING1_MAXIMUM_EXCHANGE_BYTES,
            open_timeout: RING1_MAXIMUM_DEADLINE,
            operation_timeout: RING1_MAXIMUM_DEADLINE,
        },
        state: PathBuf::from(value("--state")?),
        mission_bundle: PathBuf::from(value("--mission-bundle")?),
        mission_peer: parse_node_id(&value("--mission-peer")?).map_err(|_| USAGE.to_owned())?,
        contact_cadence: Duration::from_secs(cadence_seconds),
    }))
}

type LifecycleFuture<T> = Pin<Box<dyn Future<Output = Result<T, String>> + Send>>;
type StartNode<N> = Box<dyn FnOnce() -> LifecycleFuture<N> + Send>;
type StartSupervisor<N, S> = Box<dyn FnOnce(&N) -> S + Send>;
type WaitForShutdown = Box<dyn FnOnce() -> LifecycleFuture<()> + Send>;
type StopSupervisor<S> = Box<dyn FnOnce(S) -> LifecycleFuture<()> + Send>;
type StopNode<N> = Box<dyn FnOnce(N) -> LifecycleFuture<()> + Send>;

struct Lifecycle<N, S> {
    start_node: StartNode<N>,
    start_supervisor: StartSupervisor<N, S>,
    wait: WaitForShutdown,
    stop_supervisor: StopSupervisor<S>,
    stop_node: StopNode<N>,
}

async fn run_owned<N, S>(lifecycle: Lifecycle<N, S>) -> Result<(), String> {
    let node = (lifecycle.start_node)().await?;
    let supervisor = (lifecycle.start_supervisor)(&node);

    let wait_result = (lifecycle.wait)().await;
    let supervisor_result = (lifecycle.stop_supervisor)(supervisor).await;
    let node_result = (lifecycle.stop_node)(node).await;
    wait_result?;
    supervisor_result?;
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
    let supervisor_config = SupervisorConfig {
        link: config.link,
        local_mission_id,
        peer_mission_id: config.mission_peer,
        contact_cadence: config.contact_cadence,
    }
    .validate()
    .map_err(|_| "invalid Linux BTLE supervisor configuration".to_owned())?;
    let node_config = TransportNeutralNodeConfig {
        state: config.state,
        mission,
        mutable_interests: MutableSourceInterests::default(),
        sync_interval: Duration::from_secs(DEFAULT_CONTACT_CADENCE_SECONDS),
        run_for: None,
        application: NodeApplication::Relay,
    };

    run_owned(Lifecycle {
        start_node: Box::new(|| {
            Box::pin(async move {
                start_transport_neutral_node(node_config)
                    .await
                    .map_err(|_| "failed to start the transport-neutral node".to_owned())
            })
        }),
        start_supervisor: Box::new(|node| {
            spawn_linux_btle_event_supervisor(
                supervisor_config,
                node.ordered_event_contacts(),
            )
        }),
        wait: Box::new(|| Box::pin(wait_for_shutdown_signal())),
        stop_supervisor: Box::new(|supervisor| {
            Box::pin(async move {
                supervisor
                    .shutdown()
                    .await
                    .map_err(|_| "Linux BTLE supervisor shutdown failed".to_owned())
            })
        }),
        stop_node: Box::new(|node| {
            Box::pin(async move {
                node.shutdown()
                    .await
                    .map(|_| ())
                    .map_err(|_| "node shutdown failed".to_owned())
            })
        }),
    })
    .await
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
    use std::sync::{Arc, Mutex};

    fn arguments() -> Vec<String> {
        [
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

    #[test]
    fn parses_unattended_configuration_without_role() {
        let EvaluationCommand::Run(config) = parse_command(arguments()).unwrap() else {
            panic!("run command");
        };
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
        run_owned(Lifecycle {
            start_node: Box::new({
                let events = events.clone();
                move || {
                    Box::pin(async move {
                        events.lock().unwrap().push("node-start");
                        Ok(())
                    })
                }
            }),
            start_supervisor: Box::new({
                let events = events.clone();
                move |_| {
                    events.lock().unwrap().push("supervisor-start");
                }
            }),
            wait: Box::new(|| Box::pin(async { Err("signal failure".to_owned()) })),
            stop_supervisor: Box::new({
                let events = events.clone();
                move |_| {
                    Box::pin(async move {
                        events.lock().unwrap().push("supervisor-stop");
                        Ok(())
                    })
                }
            }),
            stop_node: Box::new({
                let events = events.clone();
                move |_| {
                    Box::pin(async move {
                        events.lock().unwrap().push("node-stop");
                        Ok(())
                    })
                }
            }),
        })
        .await
        .unwrap_err();

        assert_eq!(
            *observed.lock().unwrap(),
            ["node-start", "supervisor-start", "supervisor-stop", "node-stop"]
        );
    }
}
