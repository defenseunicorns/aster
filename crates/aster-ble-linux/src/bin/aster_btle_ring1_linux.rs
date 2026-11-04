use aster_ble_linux::{
    DriverConfig, FixedRole, OpenCancellation, RING1_MAXIMUM_DEADLINE,
    RING1_MAXIMUM_EXCHANGE_BYTES, RING1_MAXIMUM_FRAME_BYTES, ValidatedConfig, open_contact,
};
use aster_contact::{
    CarrierPeerEvidence, ContactFuture, ContactPreflight, ContactRequestHandler, OrderedContact,
};
use aster_mesh::{
    TransferProfileOfferV1, negotiate_transfer_profiles_for_semantic_version,
    transfer_profile_digest,
};
use aster_node::{
    MissionPeerExpectation, MutableSourceInterests, NodeApplication, OrderedEventContactRole,
    PeerReceipt, TransportNeutralNodeConfig, mission::UnprotectedReferenceMission, parse_node_id,
    start_transport_neutral_node,
};
use bluer::{Address, AddressType};
use std::{
    collections::BTreeMap,
    path::PathBuf,
    process::ExitCode,
    str::FromStr,
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    time::Duration,
};

const USAGE: &str = "usage: aster-btle-ring1 --role initiator|listener --adapter hciN \
    --local-address AA:BB:CC:DD:EE:FF --local-address-type public|random \
    --peer-address AA:BB:CC:DD:EE:FF --peer-address-type public|random \
    --psm 0x80..0xff --state PATH --mission-bundle PATH --mission-peer NODE_ID_HEX \
    --require-event-larger-than-mtu yes|no";

struct HarnessConfig {
    driver: ValidatedConfig,
    state: PathBuf,
    mission_bundle: PathBuf,
    mission_peer: [u8; 32],
    require_event_larger_than_mtu: bool,
}

enum HarnessCommand {
    Help,
    Run(HarnessConfig),
}

#[derive(Debug, Default)]
struct ContactAttemptEvidence {
    exchanges_started: AtomicUsize,
}

#[derive(Debug, Eq, PartialEq)]
struct FailedContactEvidence {
    post_handshake_exchanges_started: usize,
    no_post_handshake_exchange_observed: bool,
}

fn failed_contact_evidence(exchanges_started: usize) -> FailedContactEvidence {
    let post_handshake_exchanges_started = exchanges_started.saturating_sub(2);
    FailedContactEvidence {
        post_handshake_exchanges_started,
        no_post_handshake_exchange_observed: post_handshake_exchanges_started == 0,
    }
}

struct EvidenceContact {
    inner: Arc<dyn OrderedContact>,
    evidence: Arc<ContactAttemptEvidence>,
}

impl EvidenceContact {
    fn begin_exchange(&self) {
        self.evidence
            .exchanges_started
            .fetch_add(1, Ordering::AcqRel);
    }
}

impl OrderedContact for EvidenceContact {
    fn peer_evidence(&self) -> CarrierPeerEvidence {
        self.inner.peer_evidence()
    }

    fn max_frame_bytes(&self) -> usize {
        self.inner.max_frame_bytes()
    }

    fn request_with_total_limit<'a>(
        &'a self,
        request: &'a [u8],
        total_limit: usize,
    ) -> ContactFuture<'a, Vec<u8>> {
        self.begin_exchange();
        self.inner
            .request_with_total_limit(request, total_limit)
    }

    fn request_with_total_limit_checked<'a>(
        &'a self,
        request: &'a [u8],
        total_limit: usize,
        before_write: ContactPreflight<'a>,
    ) -> ContactFuture<'a, Vec<u8>> {
        self.begin_exchange();
        self.inner
            .request_with_total_limit_checked(request, total_limit, before_write)
    }

    fn respond_once_with_total_limit<'a>(
        &'a self,
        total_limit: usize,
        handler: ContactRequestHandler<'a>,
    ) -> ContactFuture<'a, bool> {
        self.begin_exchange();
        self.inner
            .respond_once_with_total_limit(total_limit, handler)
    }

    fn finish_as_initiator(&self) -> ContactFuture<'_, ()> {
        self.inner.finish_as_initiator()
    }

    fn finish_as_responder(&self) -> ContactFuture<'_, ()> {
        self.inner.finish_as_responder()
    }

    fn close(&self) {
        self.inner.close();
    }
}

fn parse_command(arguments: Vec<String>) -> Result<HarnessCommand, String> {
    if arguments == ["--help"] {
        return Ok(HarnessCommand::Help);
    }
    if !arguments.len().is_multiple_of(2) {
        return Err(USAGE.to_owned());
    }
    let mut options = BTreeMap::new();
    for pair in arguments.chunks_exact(2) {
        if !matches!(
            pair[0].as_str(),
            "--role"
                | "--adapter"
                | "--local-address"
                | "--local-address-type"
                | "--peer-address"
                | "--peer-address-type"
                | "--psm"
                | "--state"
                | "--mission-bundle"
                | "--mission-peer"
                | "--require-event-larger-than-mtu"
        ) || options.insert(pair[0].clone(), pair[1].clone()).is_some()
        {
            return Err(USAGE.to_owned());
        }
    }
    let value = |name: &str| options.get(name).cloned().ok_or_else(|| USAGE.to_owned());
    let role = match value("--role")?.as_str() {
        "initiator" => FixedRole::Initiator,
        "listener" => FixedRole::Listener,
        _ => return Err(USAGE.to_owned()),
    };
    let address_type = |name: &str| match value(name)?.as_str() {
        "public" => Ok(AddressType::LePublic),
        "random" => Ok(AddressType::LeRandom),
        _ => Err(USAGE.to_owned()),
    };
    let parse_address = |name: &str| {
        Address::from_str(&value(name)?).map_err(|_| "invalid Bluetooth address".to_owned())
    };
    let psm_text = value("--psm")?;
    let psm = if let Some(hex) = psm_text.strip_prefix("0x") {
        u16::from_str_radix(hex, 16)
    } else {
        psm_text.parse()
    }
    .map_err(|_| "invalid LE PSM".to_owned())?;
    let driver = DriverConfig {
        adapter_name: value("--adapter")?,
        local_address: parse_address("--local-address")?,
        local_address_type: address_type("--local-address-type")?,
        peer_address: parse_address("--peer-address")?,
        peer_address_type: address_type("--peer-address-type")?,
        psm,
        role,
        maximum_frame_bytes: RING1_MAXIMUM_FRAME_BYTES,
        maximum_exchange_bytes: RING1_MAXIMUM_EXCHANGE_BYTES,
        open_timeout: RING1_MAXIMUM_DEADLINE,
        operation_timeout: RING1_MAXIMUM_DEADLINE,
    }
    .validate()
    .map_err(|error| error.to_string())?;
    let mission_peer = parse_node_id(&value("--mission-peer")?).map_err(|_| USAGE.to_owned())?;
    let require_event_larger_than_mtu = match value("--require-event-larger-than-mtu")?.as_str() {
        "yes" => true,
        "no" => false,
        _ => return Err(USAGE.to_owned()),
    };
    Ok(HarnessCommand::Run(HarnessConfig {
        driver,
        state: PathBuf::from(value("--state")?),
        mission_bundle: PathBuf::from(value("--mission-bundle")?),
        mission_peer,
        require_event_larger_than_mtu,
    }))
}

async fn run(config: HarnessConfig) -> Result<(), String> {
    let mission = UnprotectedReferenceMission::load(&config.mission_bundle)
        .map_err(|_| "failed to load the evaluation mission bundle".to_owned())?;
    let node = start_transport_neutral_node(TransportNeutralNodeConfig {
        state: config.state,
        mission,
        mutable_interests: MutableSourceInterests::default(),
        sync_interval: Duration::from_secs(60),
        run_for: None,
        application: NodeApplication::Relay,
    })
    .await
    .map_err(|_| "failed to start the transport-neutral node".to_owned())?;
    let role = config.driver.role();
    let cancellation = OpenCancellation::new();
    let open = open_contact(&config.driver, &cancellation);
    tokio::pin!(open);
    let opened = tokio::select! {
        result = &mut open => match result {
            Ok(opened) => opened,
            Err(error) => {
                node.shutdown().await.map_err(|_| "node shutdown failed".to_owned())?;
                return Err(error.to_string());
            }
        },
        signal = tokio::signal::ctrl_c() => {
            signal.map_err(|_| "failed to install interrupt handler".to_owned())?;
            cancellation.cancel();
            node.shutdown().await.map_err(|_| "node shutdown failed".to_owned())?;
            return Ok(());
        }
    };
    eprintln!(
        "BTLE_RING1 status=carrier-connected role={role:?} maximum_exchange_bytes={} claim=none",
        opened.maximum_exchange_bytes()
    );
    let expectation = MissionPeerExpectation::new(
        OrderedContact::peer_evidence(opened.contact().as_ref()),
        config.mission_peer,
    );
    let event_role = match role {
        FixedRole::Initiator => OrderedEventContactRole::Initiator,
        FixedRole::Listener => OrderedEventContactRole::Responder,
    };
    let evidence = Arc::new(ContactAttemptEvidence::default());
    let contact: Arc<dyn OrderedContact> = Arc::new(EvidenceContact {
        inner: opened.contact().clone(),
        evidence: evidence.clone(),
    });
    let contacts = node.ordered_event_contacts();
    let session = contacts.run(event_role, contact, expectation);
    tokio::pin!(session);
    let session_result = tokio::select! {
        result = &mut session => result.map_err(|_| "protected Event contact failed".to_owned()),
        signal = tokio::signal::ctrl_c() => {
            signal.map_err(|_| "failed to wait for interrupt".to_owned())?;
            opened.contact().close();
            Err("protected Event contact was interrupted".to_owned())
        }
    };
    let exchanges_started = evidence.exchanges_started.load(Ordering::Acquire);
    let mtu = opened.negotiated_mtu();
    let shutdown_result = node
        .shutdown()
        .await
        .map_err(|_| "node shutdown failed".to_owned());
    let receipt = match session_result {
        Ok(receipt) => receipt,
        Err(error) => {
            let failure_evidence = failed_contact_evidence(exchanges_started);
            eprintln!(
                "BTLE_RING1 status=contact-failed role={role:?} ordered_exchanges_started={exchanges_started} post_handshake_exchanges_started={} no_post_handshake_exchange_observed={} receipt_available=false event_validation=false daemon=false",
                failure_evidence.post_handshake_exchanges_started,
                failure_evidence.no_post_handshake_exchange_observed,
            );
            shutdown_result?;
            return Err(error);
        }
    };
    let mtu = mtu.ok_or_else(|| "kernel did not report both negotiated L2CAP MTUs".to_owned())?;
    let event_larger_than_mtu = validate_ring1_receipt(
        &receipt,
        mtu.send_bytes(),
        mtu.receive_bytes(),
        config.require_event_larger_than_mtu,
    )?;
    let digest = receipt
        .transfer_profile_digest
        .map(format_digest)
        .unwrap_or_else(|| "none".to_owned());
    eprintln!(
        "BTLE_RING1 status=complete role={role:?} send_mtu={} receive_mtu={} semantic_version={} offered={} fetched={} inserted={} duplicates={} event_page_entries_sent={} event_page_entries_received={} event_page_bytes_sent={} event_page_bytes_received={} event_larger_than_directional_mtu={} transfer_profiles={:?} transfer_profile_digest={} profile_validation=true event_validation={} daemon=false",
        mtu.send_bytes(),
        mtu.receive_bytes(),
        receipt.semantic_version,
        receipt.offered,
        receipt.fetched,
        receipt.inserted,
        receipt.duplicates,
        receipt.event_page_entries_sent,
        receipt.event_page_entries_received,
        receipt.event_page_bytes_sent,
        receipt.event_page_bytes_received,
        event_larger_than_mtu,
        receipt.negotiated_transfer_profiles,
        digest,
        event_larger_than_mtu,
    );
    shutdown_result.map(|_| ())
}

fn canonical_v9_profile_digest() -> Result<[u8; 32], String> {
    let offer = TransferProfileOfferV1::for_semantic_version(9)
        .map_err(|_| "canonical v9 transfer-profile offer is unavailable".to_owned())?;
    let negotiated = negotiate_transfer_profiles_for_semantic_version(9, &offer, &offer)
        .map_err(|_| "canonical v9 transfer-profile negotiation is unavailable".to_owned())?;
    Ok(transfer_profile_digest(&offer, &offer, &negotiated))
}

fn validate_ring1_receipt(
    receipt: &PeerReceipt,
    send_mtu: usize,
    receive_mtu: usize,
    require_event_larger_than_mtu: bool,
) -> Result<bool, String> {
    if receipt.semantic_version != 9
        || receipt.negotiated_transfer_profiles != Some([2, 1, 1, 5, 1])
        || receipt.transfer_profile_digest != Some(canonical_v9_profile_digest()?)
        || receipt.blob_stream != Default::default()
    {
        return Err("contact differs from the exact Ring-1 v9 profile".to_owned());
    }
    let sent_larger = receipt.event_page_entries_sent == 1
        && receipt.event_page_bytes_sent > send_mtu;
    let received_larger = receipt.event_page_entries_received == 1
        && receipt.event_page_bytes_received > receive_mtu;
    let event_larger_than_mtu = sent_larger || received_larger;
    if require_event_larger_than_mtu && !event_larger_than_mtu {
        return Err(
            "contact did not carry one Event larger than its directional negotiated MTU"
                .to_owned(),
        );
    }
    Ok(event_larger_than_mtu)
}

fn format_digest(digest: [u8; 32]) -> String {
    use std::fmt::Write as _;

    let mut encoded = String::with_capacity(64);
    for byte in digest {
        let _ = write!(&mut encoded, "{byte:02x}");
    }
    encoded
}

#[tokio::main]
async fn main() -> ExitCode {
    match parse_command(std::env::args().skip(1).collect()) {
        Ok(HarnessCommand::Help) => {
            println!("{USAGE}");
            ExitCode::SUCCESS
        }
        Ok(HarnessCommand::Run(config)) => match run(config).await {
            Ok(()) => ExitCode::SUCCESS,
            Err(error) => {
                eprintln!("aster-btle-ring1: {error}");
                ExitCode::FAILURE
            }
        },
        Err(error) => {
            eprintln!("aster-btle-ring1: {error}");
            ExitCode::FAILURE
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use aster_ble_linux::{FixedRole, RING1_MAXIMUM_EXCHANGE_BYTES};
    use aster_node::PeerReceipt;

    fn arguments(role: &str) -> Vec<String> {
        [
            "--role",
            role,
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
            "/tmp/aster-btle-ring1-state",
            "--mission-bundle",
            "/tmp/aster-btle-ring1-mission.bundle",
            "--mission-peer",
            "0101010101010101010101010101010101010101010101010101010101010101",
            "--require-event-larger-than-mtu",
            "yes",
        ]
        .into_iter()
        .map(str::to_owned)
        .collect()
    }

    #[test]
    fn parses_the_exact_fixed_role_evaluation_configuration() {
        let HarnessCommand::Run(initiator) = parse_command(arguments("initiator")).unwrap() else {
            panic!("run command");
        };
        assert_eq!(initiator.driver.role(), FixedRole::Initiator);
        assert!(initiator.require_event_larger_than_mtu);
        assert_eq!(
            initiator.driver.maximum_exchange_bytes(),
            RING1_MAXIMUM_EXCHANGE_BYTES
        );

        let HarnessCommand::Run(listener) = parse_command(arguments("listener")).unwrap() else {
            panic!("run command");
        };
        assert_eq!(listener.driver.role(), FixedRole::Listener);
        assert!(matches!(
            parse_command(vec!["--help".to_owned()]).unwrap(),
            HarnessCommand::Help
        ));
    }

    #[test]
    fn rejects_unknown_duplicate_and_incomplete_options() {
        let mut unknown = arguments("initiator");
        unknown.extend(["--fallback".to_owned(), "iroh".to_owned()]);
        assert!(parse_command(unknown).is_err());

        let mut duplicate = arguments("initiator");
        duplicate.extend(["--role".to_owned(), "listener".to_owned()]);
        assert!(parse_command(duplicate).is_err());

        let mut incomplete = arguments("initiator");
        incomplete.pop();
        assert!(parse_command(incomplete).is_err());
    }

    #[test]
    fn transport_failure_is_only_classified_by_observed_exchange_progress() {
        assert_eq!(
            failed_contact_evidence(1),
            FailedContactEvidence {
                post_handshake_exchanges_started: 0,
                no_post_handshake_exchange_observed: true,
            }
        );
        assert_eq!(
            failed_contact_evidence(3),
            FailedContactEvidence {
                post_handshake_exchanges_started: 1,
                no_post_handshake_exchange_observed: false,
            }
        );
    }

    #[test]
    fn ring1_receipt_requires_one_individually_larger_event_and_exact_v9_profile() {
        let mut receipt = PeerReceipt {
            semantic_version: 9,
            negotiated_transfer_profiles: Some([2, 1, 1, 5, 1]),
            transfer_profile_digest: Some(canonical_v9_profile_digest().unwrap()),
            event_page_entries_sent: 1,
            event_page_bytes_sent: 129,
            ..PeerReceipt::default()
        };
        assert!(validate_ring1_receipt(&receipt, 128, 96, true).is_ok());

        receipt.event_page_entries_sent = 2;
        receipt.event_page_bytes_sent = 256;
        assert!(validate_ring1_receipt(&receipt, 128, 96, true).is_err());

        receipt.event_page_entries_sent = 1;
        receipt.event_page_bytes_sent = 100;
        assert!(validate_ring1_receipt(&receipt, 128, 96, true).is_err());

        receipt.event_page_entries_sent = 0;
        receipt.event_page_bytes_sent = 0;
        receipt.event_page_entries_received = 1;
        receipt.event_page_bytes_received = 97;
        assert!(validate_ring1_receipt(&receipt, 128, 96, true).is_ok());

        receipt.event_page_entries_received = 0;
        receipt.event_page_bytes_received = 0;
        receipt.event_page_entries_sent = 1;
        receipt.event_page_bytes_sent = 129;
        receipt.semantic_version = 8;
        assert!(validate_ring1_receipt(&receipt, 128, 96, true).is_err());

        receipt.semantic_version = 9;
        receipt.blob_stream.sent_bytes = 1;
        assert!(validate_ring1_receipt(&receipt, 128, 96, true).is_err());
    }
}
