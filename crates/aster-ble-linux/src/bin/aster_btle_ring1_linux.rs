use aster_ble_linux::{
    DriverConfig, FixedRole, LinkConfig, OpenCancellation, RING1_MAXIMUM_DEADLINE,
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
    PeerReceipt, RunningNode, TransportNeutralNodeConfig,
    application::{
        EventClientContext, EventClientDisposition, EventClientId, EventItem, EventQuery,
        EventSubscriptionRequest, Scope, SelectedEventHandle, Topic,
    },
    mission::UnprotectedReferenceMission,
    parse_node_id, start_transport_neutral_node,
};
use bluer::{Address, AddressType};
use sha2::{Digest as _, Sha256};
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
const TEXT_EVENT_CLIENT_ID: &[u8] = b"aster.linux-btle-ring1.text-consumer.v1";
const TEXT_EVENT_CLAIM_NONCE: &[u8] = b"aster.linux-btle-ring1.text-consumer-claim.v1";
const TEXT_EVENT_SUBSCRIPTION_KEY: &[u8] = b"aster.linux-btle-ring1.text-consume.v1";
const TEXT_EVENT_TOPIC: &str = "mesh.messages";
const TEXT_EVENT_SCOPE: &str = "demo/playground";
const TEXT_EVENT_LOGICAL_KEY: &[u8] = b"android-btle-ring1/text/v1";
const MAX_TEXT_EVENT_BYTES: usize = 1_024;

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
        role,
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
    if let Err(error) = ensure_text_event_subscription(&node).await {
        let _ = node.shutdown().await;
        return Err(error);
    }
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
    let completed = async {
        let receipt = match session_result {
            Ok(receipt) => receipt,
            Err(error) => {
                let failure_evidence = failed_contact_evidence(exchanges_started);
                eprintln!(
                    "BTLE_RING1 status=contact-failed role={role:?} ordered_exchanges_started={exchanges_started} post_handshake_exchanges_started={} no_post_handshake_exchange_observed={} receipt_available=false event_validation=false daemon=false",
                    failure_evidence.post_handshake_exchanges_started,
                    failure_evidence.no_post_handshake_exchange_observed,
                );
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
        let text_event = query_text_event(&node.selected_events(), config.mission_peer).await?;
        eprintln!("{}", render_text_event(&text_event)?);
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
        Ok(())
    }
    .await;
    let shutdown = node
        .shutdown()
        .await
        .map_err(|_| "node shutdown failed".to_owned());
    match (completed, shutdown) {
        (Ok(()), Ok(_)) => Ok(()),
        (Err(error), _) | (Ok(()), Err(error)) => Err(error),
    }
}

async fn ensure_text_event_subscription(node: &RunningNode) -> Result<(), String> {
    let events = node.selected_events();
    let client_id = EventClientId::new(TEXT_EVENT_CLIENT_ID.to_vec())
        .map_err(|_| "text Event client configuration is invalid".to_owned())?;
    let observed = events
        .client_status(client_id.clone(), None)
        .await
        .map_err(|_| "text Event subscription state is unavailable".to_owned())?;
    let context = match observed.current_session {
        Some(session) => {
            let current = events
                .client_status(client_id.clone(), Some(session))
                .await
                .map_err(|_| "text Event subscription state is unavailable".to_owned())?;
            if current.disposition == EventClientDisposition::Current {
                EventClientContext { client_id, session }
            } else {
                recover_text_event_client(&events, client_id, session.get()).await?
            }
        }
        None if observed.disposition == EventClientDisposition::Unregistered => {
            recover_text_event_client(&events, client_id, 0).await?
        }
        None => return Err("text Event subscription state is invalid".to_owned()),
    };
    events
        .subscribe(EventSubscriptionRequest {
            client: context,
            operation_key: TEXT_EVENT_SUBSCRIPTION_KEY.to_vec(),
            topic: Topic::new(TEXT_EVENT_TOPIC)
                .map_err(|_| "text Event selector is invalid".to_owned())?,
            scope: Scope::new(TEXT_EVENT_SCOPE)
                .map_err(|_| "text Event selector is invalid".to_owned())?,
            include_descendant_scopes: false,
        })
        .await
        .map_err(|_| "text Event subscription could not be prepared".to_owned())?;
    Ok(())
}

async fn recover_text_event_client(
    events: &SelectedEventHandle,
    client_id: EventClientId,
    expected_session: u64,
) -> Result<EventClientContext, String> {
    let recovery = events
        .begin_publication_session(
            client_id.clone(),
            expected_session,
            TEXT_EVENT_CLAIM_NONCE.to_vec(),
        )
        .await
        .map_err(|_| "text Event subscription recovery failed".to_owned())?;
    events
        .complete_publication_recovery(
            client_id.clone(),
            recovery.session,
            recovery.snapshot_revision,
        )
        .await
        .map_err(|_| "text Event subscription recovery failed".to_owned())?;
    Ok(EventClientContext {
        client_id,
        session: recovery.session,
    })
}

async fn query_text_event(
    events: &SelectedEventHandle,
    publisher: [u8; 32],
) -> Result<EventItem, String> {
    let mut query = EventQuery {
        publisher: Some(publisher),
        topic: Some(Topic::new(TEXT_EVENT_TOPIC).map_err(|_| "text Event selector is invalid")?),
        scope: Some(Scope::new(TEXT_EVENT_SCOPE).map_err(|_| "text Event selector is invalid")?),
        logical_key: Some(TEXT_EVENT_LOGICAL_KEY.to_vec()),
        limit: 128,
        ..EventQuery::default()
    };
    let mut items = Vec::new();
    loop {
        let page = events
            .query(query.clone())
            .await
            .map_err(|_| "received text Event query failed".to_owned())?;
        items.extend(page.items);
        if !page.has_more {
            return select_text_event(items, publisher);
        }
        query.after_acceptance_marker = page.scanned_through;
    }
}

fn select_text_event(items: Vec<EventItem>, publisher: [u8; 32]) -> Result<EventItem, String> {
    let event = items
        .into_iter()
        .filter(|event| {
            event.publisher == publisher
                && event.topic.as_str() == TEXT_EVENT_TOPIC
                && event.scope.as_str() == TEXT_EVENT_SCOPE
                && event.logical_key == TEXT_EVENT_LOGICAL_KEY
                && !event.tombstone
                && event.ttl_ms.is_none()
        })
        .max_by_key(|event| event.event_sequence)
        .ok_or_else(|| "authenticated Android text Event was not received".to_owned())?;
    if event.payload.is_empty() || event.payload.len() > MAX_TEXT_EVENT_BYTES {
        return Err("received text Event payload is outside its bound".to_owned());
    }
    std::str::from_utf8(&event.payload)
        .map_err(|_| "received text Event payload is not UTF-8".to_owned())?;
    Ok(event)
}

fn render_text_event(event: &EventItem) -> Result<String, String> {
    let text = std::str::from_utf8(&event.payload)
        .map_err(|_| "received text Event payload is not UTF-8".to_owned())?;
    let escaped = serde_json::to_string(text)
        .map_err(|_| "received text Event could not be rendered".to_owned())?;
    Ok(format!(
        "BTLE_RING1_EVENT status=received publisher={} sequence={} id={} payload_sha256={} text={escaped}",
        format_digest(event.publisher),
        event.event_sequence,
        event.id,
        format_digest(Sha256::digest(&event.payload).into()),
    ))
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
    use aster_node::{
        PeerReceipt,
        application::{EventId, EventItem, Priority, Scope, Topic},
    };

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

    fn text_event(publisher: [u8; 32], sequence: u64, payload: &[u8]) -> EventItem {
        EventItem {
            id: EventId::from_bytes([u8::try_from(sequence).unwrap(); 32]),
            publisher,
            publisher_counter: sequence,
            event_sequence: sequence,
            topic: Topic::new("mesh.messages").unwrap(),
            scope: Scope::new("demo/playground").unwrap(),
            priority: Priority::Priority,
            ttl_ms: None,
            logical_key: b"android-btle-ring1/text/v1".to_vec(),
            payload: payload.to_vec(),
            tombstone: false,
            acceptance_marker: sequence,
        }
    }

    #[test]
    fn selects_greatest_exact_authenticated_android_text_event() {
        let publisher = [0x11; 32];
        let mut wrong_selector = text_event(publisher, 10, b"wrong selector");
        wrong_selector.logical_key = b"other".to_vec();
        let events = vec![
            text_event([0x22; 32], 9, b"untrusted"),
            wrong_selector,
            text_event(publisher, 1, b"first"),
            text_event(publisher, 2, b"second"),
        ];

        let selected = select_text_event(events, publisher).expect("select exact text Event");

        assert_eq!(selected.event_sequence, 2);
        assert_eq!(selected.payload, b"second");
    }

    #[test]
    fn rejects_invalid_text_payload_and_renders_controls_on_one_line() {
        let publisher = [0x11; 32];
        for payload in [Vec::new(), vec![0xff], vec![b'x'; 1_025]] {
            assert!(select_text_event(vec![text_event(publisher, 1, &payload)], publisher).is_err());
        }

        let event = select_text_event(
            vec![text_event(publisher, 7, b"Snowman \xe2\x98\x83\n\"quoted\"\0")],
            publisher,
        )
        .expect("valid control text Event");
        let rendered = render_text_event(&event).expect("render text Event");
        assert!(!rendered.contains('\n'));
        assert!(rendered.contains("text=\"Snowman ☃\\n\\\"quoted\\\"\\u0000\""));
        assert!(rendered.contains("sequence=7"));
    }
}
