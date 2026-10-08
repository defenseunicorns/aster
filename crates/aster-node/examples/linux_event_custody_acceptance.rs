//! Retained Linux acceptance producer for finite-TTL selected Event custody.
//!
//! This producer deliberately uses three independently provisioned participants
//! and two non-overlapping authenticated contacts. The origin first pushes into
//! a route-only Carry relay. The origin is then stopped and its old socket is
//! held while the relay reopens under a smaller exact-scope quota and forwards
//! to a content-authorized Consume receiver.
//!
//! `LINUX_CUSTODY` records are emitted only after every assertion succeeds.
//! Runtime `READY`/`CONTACT`/`STOP` records and narrowly scoped
//! `LINUX_CUSTODY_CHILD` coordination records remain visible as they occur.

#[path = "support/numbered.rs"]
mod numbered;

use std::{
    collections::{BTreeMap, BTreeSet},
    env,
    error::Error,
    ffi::OsString,
    fmt, fs,
    io::{BufRead as _, BufReader, Write as _},
    net::{SocketAddr, UdpSocket},
    path::{Path, PathBuf},
    process::{Child, Command, Stdio},
    str::FromStr as _,
    time::{Duration, Instant},
};

use aster_iroh::{EndpointId, ExpectedPeer};
use aster_mesh::{ProvisioningAccess, ReferenceProvisioner};
use aster_node::{
    CustodyQuota, EventEmissionPolicy, MissionExpectedPeer, MutableSourceInterests,
    NodeApplication, NodeConfig, NodeIdentity, NodeReceipt, SelectedForwardingConfig,
    application::{
        ApplicationError, ContactSyncStatus, EventDeliveryPage, EventItem, EventPollRequest,
        EventPublishResult, EventQuery, EventQueryPage, EventSubscription,
        EventSubscriptionRequest, EventSyncStatus, PeerAuthorization, Priority, Scope,
        SelectedEventHandle, SelectedEventStatus, Topic,
    },
    format_node_id,
    mission::UnprotectedReferenceMission,
    start_node_with_forwarding,
};
use aster_redb_store::{
    CustodyObjectClass, CustodyPressureDemand, CustodyUsage, EventSubscriptionKey,
    EventSubscriptionMode, EventSubscriptionSpec, Store, StoreInspection,
};
use sha2::{Digest as _, Sha256};
use tokio::{
    sync::mpsc::UnboundedReceiver,
    time::{sleep, timeout},
};
use zeroize::Zeroize as _;

const TRANSCRIPT_SCHEMA: &str = "aster-linux-event-custody-transcript/v2";
const CLAIM: &str = "linux-boottime-finite-ttl-priority-quota-route-only-store-and-forward-receive-only-zero-disclosure";
const STORE_FILE: &str = "mesh.redb";
const TOPIC: &str = "opaque.custody";
const SCOPE: &str = "test/linux-event-custody";
const LOGICAL_KEY: &[u8] = b"acceptance/linux-event-custody/stream";
const RELAY_SELECTOR_KEY: &[u8] = b"acceptance/linux-event-custody/relay-carry";
const RECEIVER_SELECTOR_KEY: &[u8] = b"acceptance/linux-event-custody/receiver-consume";
const RECEIVER_SUBSCRIPTION_OPERATION: &[u8] = b"acceptance/linux-event-custody/receiver-consume";

const ALREADY_EXPIRED_PAYLOAD: &[u8] = b"expired before first authenticated contact";
const RELAY_EXPIRING_PAYLOAD: &[u8] = b"expires while retained by route-only relay";
const LIVE_FLASH_PAYLOAD: &[u8] = b"live flash custody event";
const LIVE_IMMEDIATE_PAYLOAD: &[u8] = b"live immediate custody event";
const LIVE_PRIORITY_PAYLOAD: &[u8] = b"priority event retired by quota pressure";
const ROUTINE_PAYLOAD: &[u8] = b"routine event withheld below sender floor";

const ALREADY_EXPIRED_TTL_MS: u64 = 500;
const RELAY_EXPIRING_TTL_MS: u64 = 20_000;
const INITIAL_RELAY_QUOTA_ITEMS: u64 = 4;
const FINAL_RELAY_QUOTA_ITEMS: u64 = 2;
const STOPPED_PRESSURE_DEMAND_ITEMS: u64 = 2;
const RELAY_QUOTA_BYTES: u64 = 1024 * 1024;
const CONTACT_DEADLINE: Duration = Duration::from_secs(15);
const PROCESS_DEADLINE: Duration = Duration::from_secs(20);
const SINGLE_CONTACT_SYNC_INTERVAL: Duration = Duration::from_secs(300);

type DynError = Box<dyn Error + Send + Sync>;
type ChildFields = BTreeMap<String, String>;

#[derive(Debug)]
struct AcceptanceFailure(&'static str);

impl fmt::Display for AcceptanceFailure {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.0)
    }
}

impl Error for AcceptanceFailure {}

fn require(condition: bool, label: &'static str) -> Result<(), DynError> {
    if condition {
        Ok(())
    } else {
        Err(Box::new(AcceptanceFailure(label)))
    }
}

#[derive(Clone, Debug)]
struct Participant {
    name: &'static str,
    state: PathBuf,
    mission_path: PathBuf,
    mission_id: [u8; 32],
    mission_authority: [u8; 32],
    carrier_id: EndpointId,
    access: &'static str,
}

#[derive(Clone, Copy)]
struct PublicationSpec {
    label: &'static str,
    payload: &'static [u8],
    priority: Priority,
    ttl_ms: Option<u64>,
}

struct Publications {
    already_expired: EventPublishResult,
    relay_expiring: EventPublishResult,
    live_flash: EventPublishResult,
    live_immediate: EventPublishResult,
    live_priority: EventPublishResult,
    routine: EventPublishResult,
}

impl Publications {
    fn ordered(&self) -> [(&'static str, &EventPublishResult, &'static [u8]); 6] {
        [
            (
                "already_expired",
                &self.already_expired,
                ALREADY_EXPIRED_PAYLOAD,
            ),
            (
                "relay_expiring",
                &self.relay_expiring,
                RELAY_EXPIRING_PAYLOAD,
            ),
            ("live_flash", &self.live_flash, LIVE_FLASH_PAYLOAD),
            (
                "live_immediate",
                &self.live_immediate,
                LIVE_IMMEDIATE_PAYLOAD,
            ),
            ("live_priority", &self.live_priority, LIVE_PRIORITY_PAYLOAD),
            ("routine", &self.routine, ROUTINE_PAYLOAD),
        ]
    }
}

struct ChildActor {
    child: Child,
    lines: UnboundedReceiver<Result<String, std::io::Error>>,
}

impl Drop for ChildActor {
    fn drop(&mut self) {
        if self.child.try_wait().ok().flatten().is_none() {
            let _ = self.child.kill();
            let _ = self.child.wait();
        }
    }
}

#[tokio::main]
async fn main() {
    let arguments = env::args_os().collect::<Vec<_>>();
    let child_mode = arguments
        .get(1)
        .and_then(|argument| argument.to_str())
        .is_some_and(|argument| argument.starts_with("--internal-"));
    let result = if !cfg!(target_os = "linux") {
        Err(Box::new(AcceptanceFailure(
            "linux suspend-inclusive boottime clock required",
        )) as DynError)
    } else if child_mode {
        run_child(&arguments[1..]).await
    } else {
        run_parent(&arguments[1..]).await
    };
    if let Err(error) = result {
        let stage = failure_stage(error.as_ref());
        if child_mode {
            eprintln!("LINUX_CUSTODY_CHILD_FAILURE status=error stage={stage}");
        } else {
            eprintln!("LINUX_CUSTODY_FAILURE status=error stage={stage}");
        }
        std::process::exit(1);
    }
}

fn failure_stage(error: &(dyn Error + 'static)) -> String {
    let stage = if let Some(failure) = error.downcast_ref::<AcceptanceFailure>() {
        failure.0.to_owned()
    } else if let Some(failure) = error.downcast_ref::<ApplicationError>() {
        format!("application_{:?}_{}", failure.kind(), failure.operation())
    } else {
        "runtime".to_owned()
    };
    stage.replace(' ', "_").to_ascii_lowercase()
}

async fn run_parent(arguments: &[OsString]) -> Result<(), DynError> {
    require(arguments.len() == 1, "unexpected arguments")?;
    let raw_root = canonical_raw_root(PathBuf::from(&arguments[0]))?;
    let topic = Topic::new(TOPIC)?;
    let scope = Scope::new(SCOPE)?;
    let participants_root = raw_root.join("participants");
    create_owner_directory(&participants_root)?;
    let [origin, relay, receiver] = provision_participants(&participants_root, &topic, &scope)?;
    validate_participant_domains(&origin, &relay, &receiver)?;

    seed_selector(
        &relay,
        EventSubscriptionMode::Carry,
        RELAY_SELECTOR_KEY,
        &topic,
        &scope,
    )?;
    seed_selector(
        &receiver,
        EventSubscriptionMode::Consume,
        RECEIVER_SELECTOR_KEY,
        &topic,
        &scope,
    )?;
    let relay_seeded = inspect_participant(&relay)?;
    let receiver_seeded = inspect_participant(&receiver)?;
    validate_seeded_selector(&relay_seeded)?;
    validate_seeded_selector(&receiver_seeded)?;

    let journal_path = origin.state.join("linux-custody-publication.redb");
    numbered::Journal::initialize(&journal_path, b"native.linux-custody.v1")?;
    let mut journal = numbered::Journal::open(&journal_path, b"native.linux-custody.v1")?;
    let peerless = start_participant(
        &origin,
        SocketAddr::from(([127, 0, 0, 1], 0)),
        None,
        SelectedForwardingConfig::default(),
    )
    .await?;
    let peerless_events = peerless.selected_events();
    validate_handle(&origin, &peerless_events)?;
    journal
        .recover(&mut numbered::Backend::Live(&peerless_events))
        .await?;

    let already_expired = publish_spec(
        &mut journal,
        &peerless_events,
        &origin,
        &topic,
        &scope,
        PublicationSpec {
            label: "already_expired",
            payload: ALREADY_EXPIRED_PAYLOAD,
            priority: Priority::Flash,
            ttl_ms: Some(ALREADY_EXPIRED_TTL_MS),
        },
        1,
    )
    .await?;
    let relay_published_at = Instant::now();
    let relay_expiring = publish_spec(
        &mut journal,
        &peerless_events,
        &origin,
        &topic,
        &scope,
        PublicationSpec {
            label: "relay_expiring",
            payload: RELAY_EXPIRING_PAYLOAD,
            priority: Priority::Flash,
            ttl_ms: Some(RELAY_EXPIRING_TTL_MS),
        },
        2,
    )
    .await?;
    let live_flash = publish_spec(
        &mut journal,
        &peerless_events,
        &origin,
        &topic,
        &scope,
        PublicationSpec {
            label: "live_flash",
            payload: LIVE_FLASH_PAYLOAD,
            priority: Priority::Flash,
            ttl_ms: None,
        },
        3,
    )
    .await?;
    let live_immediate = publish_spec(
        &mut journal,
        &peerless_events,
        &origin,
        &topic,
        &scope,
        PublicationSpec {
            label: "live_immediate",
            payload: LIVE_IMMEDIATE_PAYLOAD,
            priority: Priority::Immediate,
            ttl_ms: None,
        },
        4,
    )
    .await?;
    let live_priority = publish_spec(
        &mut journal,
        &peerless_events,
        &origin,
        &topic,
        &scope,
        PublicationSpec {
            label: "live_priority",
            payload: LIVE_PRIORITY_PAYLOAD,
            priority: Priority::Priority,
            ttl_ms: None,
        },
        5,
    )
    .await?;
    let routine = publish_spec(
        &mut journal,
        &peerless_events,
        &origin,
        &topic,
        &scope,
        PublicationSpec {
            label: "routine",
            payload: ROUTINE_PAYLOAD,
            priority: Priority::Routine,
            ttl_ms: None,
        },
        6,
    )
    .await?;
    let publication_status = peerless_events.status().await?;
    require(
        publication_status
            .event_operation_capacity
            .numbered_stats
            .clients
            == 1
            && publication_status
                .event_operation_capacity
                .numbered_stats
                .outstanding_results
                == 0,
        "bounded numbered publication clients and acknowledged results",
    )?;
    let publications = Publications {
        already_expired,
        relay_expiring,
        live_flash,
        live_immediate,
        live_priority,
        routine,
    };

    sleep(Duration::from_millis(ALREADY_EXPIRED_TTL_MS + 250)).await;
    let after_first_expiry =
        query_stream(&peerless_events, origin.mission_id, &topic, &scope).await?;
    validate_origin_active_set(&after_first_expiry, &publications)?;
    let peerless_status = peerless_events.status().await?;
    validate_offline_status(&peerless_status)?;
    let peerless_receipt = peerless.shutdown().await?;
    validate_receipt(&peerless_receipt, 0, 5, 6, 0, 0, 0, 0)?;
    drop(peerless_events);
    let origin_after_expiry = inspect_participant(&origin)?;
    validate_origin_inspection(&origin_after_expiry)?;

    let origin_reservation = UdpSocket::bind(("127.0.0.1", 0))?;
    let relay_reservation = UdpSocket::bind(("127.0.0.1", 0))?;
    let origin_address = origin_reservation.local_addr()?;
    let relay_address = relay_reservation.local_addr()?;
    drop(relay_reservation);

    let mut relay_phase_one =
        spawn_phase_one_relay(&relay, relay_address, &origin, origin_address)?;
    let relay_phase_one_ready = wait_child_record(&mut relay_phase_one, "PHASE1_READY").await?;
    validate_child_ready(
        &relay_phase_one_ready,
        "relay",
        "receive_only",
        INITIAL_RELAY_QUOTA_ITEMS,
    )?;

    drop(origin_reservation);
    let origin_contact = start_participant(
        &origin,
        origin_address,
        Some((&relay, relay_address)),
        SelectedForwardingConfig::default()
            .with_emission_policy(EventEmissionPolicy::at_least(Priority::Priority)),
    )
    .await?;
    let origin_contact_events = origin_contact.selected_events();
    let origin_contact_status = wait_for_contact(&origin_contact_events, relay.mission_id).await?;
    let relay_phase_one_done = wait_child_record(&mut relay_phase_one, "PHASE1_DONE").await?;
    let origin_after_contact =
        query_stream(&origin_contact_events, origin.mission_id, &topic, &scope).await?;
    validate_origin_active_set(&origin_after_contact, &publications)?;
    let origin_contact_receipt = origin_contact.shutdown().await?;
    validate_receipt(&origin_contact_receipt, 1, 5, 6, 0, 4, 0, 0)?;
    finish_child(relay_phase_one).await?;

    let origin_absence_guard = reacquire_socket(origin_address).await?;
    let relay_phase_two_guard = reacquire_socket(relay_address).await?;
    let origin_phase_one = inspect_participant(&origin)?;
    let relay_phase_one_inspection = inspect_participant(&relay)?;
    validate_origin_inspection(&origin_phase_one)?;
    validate_origin_send_only_change(&origin_after_expiry, &origin_phase_one)?;
    validate_relay_phase_one_inspection(&relay_phase_one_inspection)?;
    validate_phase_one_child(&relay_phase_one_done, &relay_phase_one_inspection)?;
    validate_connected_status(&origin_contact_status, relay.mission_id)?;

    wait_past_relay_expiry(relay_published_at).await?;

    drop(relay_phase_two_guard);
    let relay_expiry_runtime = start_participant(
        &relay,
        relay_address,
        None,
        SelectedForwardingConfig::default().with_scope_quota(CustodyQuota::for_scope(
            scope.clone(),
            INITIAL_RELAY_QUOTA_ITEMS,
            RELAY_QUOTA_BYTES,
        )?)?,
    )
    .await?;
    let relay_expiry_events = relay_expiry_runtime.selected_events();
    validate_handle(&relay, &relay_expiry_events)?;
    validate_offline_status(&relay_expiry_events.status().await?)?;
    let relay_expiry_receipt = relay_expiry_runtime.shutdown().await?;
    validate_receipt(&relay_expiry_receipt, 0, 0, 0, 3, 0, 0, 0)?;
    drop(relay_expiry_events);
    let relay_after_expiry = inspect_participant(&relay)?;
    validate_relay_after_expiry_inspection(&relay_after_expiry)?;
    let relay_phase_two_guard = reacquire_socket(relay_address).await?;

    apply_stopped_relay_pressure(&relay, &scope)?;
    let relay_after_pressure = inspect_participant(&relay)?;
    validate_relay_after_pressure_inspection(&relay_after_pressure)?;

    let receiver_reservation = UdpSocket::bind(("127.0.0.1", 0))?;
    let receiver_address = receiver_reservation.local_addr()?;
    drop(receiver_reservation);
    let mut receiver_phase_two = spawn_phase_two_receiver(
        &receiver,
        receiver_address,
        &relay,
        relay_address,
        &origin,
        &publications,
    )?;
    let receiver_ready =
        wait_child_record(&mut receiver_phase_two, "PHASE2_RECEIVER_READY").await?;
    validate_child_ready(&receiver_ready, "receiver", "receive_only", 0)?;

    drop(relay_phase_two_guard);
    let mut relay_phase_two = spawn_phase_two_relay(
        &relay,
        relay_address,
        &receiver,
        receiver_address,
        origin.mission_id,
    )?;
    let relay_phase_two_ready =
        wait_child_record(&mut relay_phase_two, "PHASE2_RELAY_READY").await?;
    validate_child_ready(
        &relay_phase_two_ready,
        "relay",
        "normal",
        FINAL_RELAY_QUOTA_ITEMS,
    )?;
    let relay_phase_two_done = wait_child_record(&mut relay_phase_two, "PHASE2_RELAY_DONE").await?;
    let receiver_phase_two_done =
        wait_child_record(&mut receiver_phase_two, "PHASE2_RECEIVER_DONE").await?;
    finish_child(relay_phase_two).await?;
    finish_child(receiver_phase_two).await?;

    require(
        origin_absence_guard.local_addr()? == origin_address,
        "origin absence socket guard",
    )?;
    let relay_final_socket = reacquire_socket(relay_address).await?;
    let receiver_final_socket = reacquire_socket(receiver_address).await?;
    let relay_final = inspect_participant(&relay)?;
    let receiver_final = inspect_participant(&receiver)?;
    let origin_final = inspect_participant(&origin)?;
    require(
        origin_final == origin_phase_one,
        "absent origin store remained unchanged",
    )?;
    validate_relay_final_inspection(&relay_final)?;
    validate_relay_pressure_persistence(&relay_after_pressure, &relay_final)?;
    validate_receiver_final_inspection(&receiver_final)?;
    validate_phase_two_relay_child(&relay_phase_two_done, &relay_final)?;
    validate_phase_two_receiver_child(&receiver_phase_two_done, &publications, &receiver_final)?;

    drop(origin_absence_guard);
    let origin_final_socket = reacquire_socket(origin_address).await?;
    require(
        origin_final_socket.local_addr()? == origin_address
            && relay_final_socket.local_addr()? == relay_address
            && receiver_final_socket.local_addr()? == receiver_address,
        "final socket reacquisition",
    )?;

    emit_transcript(
        [&origin, &relay, &receiver],
        &publications,
        &relay_seeded,
        &receiver_seeded,
        &origin_phase_one,
        &relay_phase_one_inspection,
        &relay_after_expiry,
        &relay_after_pressure,
        &relay_final,
        &receiver_final,
        &origin_contact_receipt,
        &relay_phase_one_done,
        &relay_phase_two_done,
        &receiver_phase_two_done,
        origin_address,
        relay_address,
        receiver_address,
    )?;
    Ok(())
}

async fn publish_spec(
    journal: &mut numbered::Journal,
    events: &SelectedEventHandle,
    origin: &Participant,
    topic: &Topic,
    scope: &Scope,
    spec: PublicationSpec,
    sequence: u64,
) -> Result<EventPublishResult, DynError> {
    let intent = numbered::Intent {
        predecessor: None,
        topic: topic.as_str().into(),
        scope: scope.as_str().into(),
        priority: spec.priority as u8,
        logical_key: LOGICAL_KEY.to_vec(),
        payload: spec.payload.to_vec(),
        tombstone: false,
        ttl_ms: spec.ttl_ms,
    };
    let publication = journal
        .publish_metadata(&mut numbered::Backend::Live(events), intent)
        .await?;
    require(
        publication.inserted
            && publication.publisher == origin.mission_id
            && publication.publisher_counter == sequence
            && publication.event_sequence == sequence
            && publication.priority == spec.priority
            && publication.ttl_ms == spec.ttl_ms
            && publication.acceptance_marker == sequence,
        spec.label,
    )?;
    journal
        .acknowledge(&mut numbered::Backend::Live(events))
        .await?;
    Ok(publication)
}

async fn wait_past_relay_expiry(published_at: Instant) -> Result<(), DynError> {
    let deadline = published_at
        .checked_add(Duration::from_millis(RELAY_EXPIRING_TTL_MS + 500))
        .ok_or(AcceptanceFailure("relay expiry deadline overflow"))?;
    if let Some(remaining) = deadline.checked_duration_since(Instant::now()) {
        sleep(remaining).await;
    }
    Ok(())
}

fn apply_stopped_relay_pressure(relay: &Participant, scope: &Scope) -> Result<(), DynError> {
    let store = Store::open_for_mission(relay.state.join(STORE_FILE), relay.mission_authority)?;
    store.require_process_exclusive_lock()?;
    let policy = store.custody_policy_revision()?;
    let pressure = store.collect_custody_pressure(
        Some(scope),
        CustodyPressureDemand {
            usage: CustodyUsage {
                items: STOPPED_PRESSURE_DEMAND_ITEMS,
                bytes: 0,
            },
            priority: Priority::Flash,
        },
        None,
        policy,
        1,
    )?;
    require(
        pressure.marked.len() == 1
            && pressure.retired.len() == 1
            && pressure.marked == pressure.retired
            && pressure.retired[0].class() == CustodyObjectClass::RouteEvent
            && pressure.released_bytes > 0
            && pressure.blocked_by_leases == 0,
        "stopped exact-scope pressure retired one route Event",
    )?;
    store.set_custody_quota(CustodyQuota::for_scope(
        scope.clone(),
        FINAL_RELAY_QUOTA_ITEMS,
        RELAY_QUOTA_BYTES,
    )?)?;
    drop(store);
    Ok(())
}

async fn run_child(arguments: &[OsString]) -> Result<(), DynError> {
    match arguments.first().and_then(|argument| argument.to_str()) {
        Some("--internal-relay-phase-1") => run_phase_one_relay_child(&arguments[1..]).await,
        Some("--internal-relay-phase-2") => run_phase_two_relay_child(&arguments[1..]).await,
        Some("--internal-receiver-phase-2") => run_phase_two_receiver_child(&arguments[1..]).await,
        _ => Err(Box::new(AcceptanceFailure("unknown internal child mode"))),
    }
}

async fn run_phase_one_relay_child(arguments: &[OsString]) -> Result<(), DynError> {
    require(arguments.len() == 6, "phase-one relay child arguments")?;
    let state = PathBuf::from(&arguments[0]);
    let mission_path = PathBuf::from(&arguments[1]);
    let bind = parse_socket(&arguments[2])?;
    let remote_address = parse_socket(&arguments[3])?;
    let remote_carrier = parse_endpoint(&arguments[4])?;
    let origin = parse_node_id(&arguments[5])?;
    let scope = Scope::new(SCOPE)?;
    let running = start_child_node(
        state,
        mission_path,
        bind,
        remote_address,
        remote_carrier,
        origin,
        EventEmissionPolicy::ReceiveOnly,
        Some(INITIAL_RELAY_QUOTA_ITEMS),
    )
    .await?;
    let events = running.selected_events();
    emit_child(
        "PHASE1_READY",
        &[
            ("participant", "relay".to_owned()),
            ("mode", "receive_only".to_owned()),
            ("quota_items", INITIAL_RELAY_QUOTA_ITEMS.to_string()),
        ],
    )?;
    let status = wait_for_contact(&events, origin).await?;
    let route_query = query_stream(&events, origin, &Topic::new(TOPIC)?, &scope).await?;
    require(
        route_query.items.is_empty(),
        "route-only relay exposed application Event content",
    )?;
    let receipt = running.shutdown().await?;
    validate_receipt(&receipt, 1, 0, 0, 4, 0, 4, 4)?;
    validate_receive_only_receipt(&receipt)?;
    let inspection = Store::inspect_existing(state_path_from_store_owner(&events, &arguments[0])?)?;
    validate_relay_phase_one_inspection(&inspection)?;
    let mut fields = child_contact_fields(&status, &receipt);
    fields.extend(inspection_fields(&inspection));
    fields.push(("participant", "relay".to_owned()));
    fields.push(("route_query_items", route_query.items.len().to_string()));
    emit_child("PHASE1_DONE", &fields)?;
    Ok(())
}

async fn run_phase_two_relay_child(arguments: &[OsString]) -> Result<(), DynError> {
    require(arguments.len() == 7, "phase-two relay child arguments")?;
    let state = PathBuf::from(&arguments[0]);
    let mission_path = PathBuf::from(&arguments[1]);
    let bind = parse_socket(&arguments[2])?;
    let remote_address = parse_socket(&arguments[3])?;
    let remote_carrier = parse_endpoint(&arguments[4])?;
    let receiver = parse_node_id(&arguments[5])?;
    let origin = parse_node_id(&arguments[6])?;
    let running = start_child_node(
        state.clone(),
        mission_path,
        bind,
        remote_address,
        remote_carrier,
        receiver,
        EventEmissionPolicy::Normal,
        Some(FINAL_RELAY_QUOTA_ITEMS),
    )
    .await?;
    let events = running.selected_events();
    emit_child(
        "PHASE2_RELAY_READY",
        &[
            ("participant", "relay".to_owned()),
            ("mode", "normal".to_owned()),
            ("quota_items", FINAL_RELAY_QUOTA_ITEMS.to_string()),
        ],
    )?;
    let status = wait_for_contact(&events, receiver).await?;
    let route_query =
        query_stream(&events, origin, &Topic::new(TOPIC)?, &Scope::new(SCOPE)?).await?;
    require(
        route_query.items.is_empty(),
        "reopened route-only relay exposed Event content",
    )?;
    let receipt = running.shutdown().await?;
    validate_receipt(&receipt, 1, 0, 0, 2, 2, 0, 0)?;
    let inspection = Store::inspect_existing(state.join(STORE_FILE))?;
    validate_relay_final_inspection(&inspection)?;
    let mut fields = child_contact_fields(&status, &receipt);
    fields.extend(inspection_fields(&inspection));
    fields.push(("participant", "relay".to_owned()));
    fields.push(("route_query_items", route_query.items.len().to_string()));
    emit_child("PHASE2_RELAY_DONE", &fields)?;
    Ok(())
}

async fn run_phase_two_receiver_child(arguments: &[OsString]) -> Result<(), DynError> {
    require(arguments.len() == 13, "phase-two receiver child arguments")?;
    let state = PathBuf::from(&arguments[0]);
    let mission_path = PathBuf::from(&arguments[1]);
    let bind = parse_socket(&arguments[2])?;
    let remote_address = parse_socket(&arguments[3])?;
    let remote_carrier = parse_endpoint(&arguments[4])?;
    let relay = parse_node_id(&arguments[5])?;
    let origin = parse_node_id(&arguments[6])?;
    let expected_ids = arguments[7..13]
        .iter()
        .map(|value| {
            value.to_str().map(str::to_owned).ok_or_else(|| {
                Box::new(AcceptanceFailure("receiver Event id encoding")) as DynError
            })
        })
        .collect::<Result<Vec<_>, _>>()?;
    let running = start_child_node(
        state.clone(),
        mission_path,
        bind,
        remote_address,
        remote_carrier,
        relay,
        EventEmissionPolicy::ReceiveOnly,
        None,
    )
    .await?;
    let events = running.selected_events();
    let topic = Topic::new(TOPIC)?;
    let scope = Scope::new(SCOPE)?;
    let subscription = events
        .subscribe(EventSubscriptionRequest {
            operation_key: RECEIVER_SUBSCRIPTION_OPERATION.to_vec(),
            topic: topic.clone(),
            scope: scope.clone(),
            include_descendant_scopes: false,
        })
        .await?;
    require(!subscription.inserted, "receiver Consume selector replay")?;
    emit_child(
        "PHASE2_RECEIVER_READY",
        &[
            ("participant", "receiver".to_owned()),
            ("mode", "receive_only".to_owned()),
            ("quota_items", "0".to_owned()),
            ("subscription", subscription.id.to_string()),
        ],
    )?;
    let status = wait_for_contact(&events, relay).await?;
    let query = query_stream(&events, origin, &topic, &scope).await?;
    validate_receiver_items(&query.items, &expected_ids)?;
    let poll = poll_subscription(&events, subscription).await?;
    validate_receiver_deliveries(&poll, &expected_ids)?;
    let receipt = running.shutdown().await?;
    validate_receipt(&receipt, 1, 2, 2, 0, 0, 2, 2)?;
    validate_receive_only_receipt(&receipt)?;
    let inspection = Store::inspect_existing(state.join(STORE_FILE))?;
    validate_receiver_final_inspection(&inspection)?;
    let mut fields = child_contact_fields(&status, &receipt);
    fields.extend(inspection_fields(&inspection));
    fields.extend([
        ("participant", "receiver".to_owned()),
        ("subscription", subscription.id.to_string()),
        ("query_items", query.items.len().to_string()),
        ("poll_deliveries", poll.deliveries.len().to_string()),
        ("first_id", poll.deliveries[0].event.id.to_string()),
        (
            "first_priority",
            priority_name(poll.deliveries[0].event.priority).to_owned(),
        ),
        ("first_attempt", poll.deliveries[0].attempt.to_string()),
        ("second_id", poll.deliveries[1].event.id.to_string()),
        (
            "second_priority",
            priority_name(poll.deliveries[1].event.priority).to_owned(),
        ),
        ("second_attempt", poll.deliveries[1].attempt.to_string()),
    ]);
    emit_child("PHASE2_RECEIVER_DONE", &fields)?;
    Ok(())
}

fn state_path_from_store_owner(
    _events: &SelectedEventHandle,
    argument: &OsString,
) -> Result<PathBuf, DynError> {
    Ok(PathBuf::from(argument).join(STORE_FILE))
}

#[allow(clippy::too_many_arguments)]
async fn start_child_node(
    state: PathBuf,
    mission_path: PathBuf,
    bind: SocketAddr,
    remote_address: SocketAddr,
    remote_carrier: EndpointId,
    remote_mission: [u8; 32],
    policy: EventEmissionPolicy,
    scope_quota_items: Option<u64>,
) -> Result<aster_node::RunningNode, DynError> {
    let mission = UnprotectedReferenceMission::load(mission_path)?;
    let mut forwarding = SelectedForwardingConfig::default().with_emission_policy(policy);
    if let Some(items) = scope_quota_items {
        forwarding = forwarding.with_scope_quota(CustodyQuota::for_scope(
            Scope::new(SCOPE)?,
            items,
            RELAY_QUOTA_BYTES,
        )?)?;
    }
    Ok(start_node_with_forwarding(
        NodeConfig {
            state,
            bind,
            mission,
            peers: vec![MissionExpectedPeer {
                carrier: ExpectedPeer {
                    id: remote_carrier,
                    address: remote_address,
                },
                mission: remote_mission,
            }],
            mutable_interests: MutableSourceInterests::default(),
            sync_interval: SINGLE_CONTACT_SYNC_INTERVAL,
            run_for: None,
            application: NodeApplication::Relay,
        },
        forwarding,
    )
    .await?)
}

async fn start_participant(
    participant: &Participant,
    bind: SocketAddr,
    peer: Option<(&Participant, SocketAddr)>,
    forwarding: SelectedForwardingConfig,
) -> Result<aster_node::RunningNode, DynError> {
    let peers = peer
        .map(|(remote, address)| MissionExpectedPeer {
            carrier: ExpectedPeer {
                id: remote.carrier_id,
                address,
            },
            mission: remote.mission_id,
        })
        .into_iter()
        .collect();
    Ok(start_node_with_forwarding(
        NodeConfig {
            state: participant.state.clone(),
            bind,
            mission: UnprotectedReferenceMission::load(&participant.mission_path)?,
            peers,
            mutable_interests: MutableSourceInterests::default(),
            sync_interval: SINGLE_CONTACT_SYNC_INTERVAL,
            run_for: None,
            application: NodeApplication::Relay,
        },
        forwarding,
    )
    .await?)
}

async fn wait_for_contact(
    events: &SelectedEventHandle,
    remote: [u8; 32],
) -> Result<SelectedEventStatus, DynError> {
    timeout(CONTACT_DEADLINE, async {
        loop {
            let status = events.status().await?;
            require(
                status.authenticated_contacts <= 1 && status.failed_contact_attempts == 0,
                "single authenticated contact bound",
            )?;
            if status.authenticated_contacts == 1
                && status.sync == EventSyncStatus::LastContactComplete
            {
                validate_connected_status(&status, remote)?;
                return Ok::<_, DynError>(status);
            }
            sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .map_err(|_| AcceptanceFailure("authenticated contact deadline"))?
}

fn validate_connected_status(
    status: &SelectedEventStatus,
    remote: [u8; 32],
) -> Result<(), DynError> {
    require(
        status.sync == EventSyncStatus::LastContactComplete
            && status.authenticated_contacts == 1
            && status.failed_contact_attempts == 0
            && status.peers.len() == 1
            && status.peers[0].peer == remote
            && status.peers[0].contacts == 1
            && status.peers[0].authorization == PeerAuthorization::Active
            && status.peers[0].last_contact == ContactSyncStatus::CompleteForLastNegotiatedContact,
        "authenticated peer completion status",
    )
}

fn validate_offline_status(status: &SelectedEventStatus) -> Result<(), DynError> {
    require(
        status.sync == EventSyncStatus::Offline
            && status.authenticated_contacts == 0
            && status.failed_contact_attempts == 0
            && status.peers.is_empty(),
        "peerless selected Event status",
    )
}

async fn query_stream(
    events: &SelectedEventHandle,
    publisher: [u8; 32],
    topic: &Topic,
    scope: &Scope,
) -> Result<EventQueryPage, ApplicationError> {
    events
        .query(EventQuery {
            publisher: Some(publisher),
            topic: Some(topic.clone()),
            scope: Some(scope.clone()),
            include_descendant_scopes: false,
            logical_key: Some(LOGICAL_KEY.to_vec()),
            after_acceptance_marker: 0,
            before_acceptance_marker: None,
            limit: 16,
        })
        .await
}

async fn poll_subscription(
    events: &SelectedEventHandle,
    subscription: EventSubscription,
) -> Result<EventDeliveryPage, ApplicationError> {
    events
        .poll(EventPollRequest {
            subscription: subscription.id,
            delivery_limit: 8,
            scan_limit: 8,
        })
        .await
}

fn validate_origin_active_set(
    page: &EventQueryPage,
    publications: &Publications,
) -> Result<(), DynError> {
    require(
        page.items.len() == 5 && !page.has_more,
        "origin active Event count after finite expiry",
    )?;
    let expected = [
        &publications.relay_expiring,
        &publications.live_flash,
        &publications.live_immediate,
        &publications.live_priority,
        &publications.routine,
    ];
    require(
        page.items.iter().zip(expected).all(|(item, publication)| {
            item.id == publication.id
                && item.event_sequence == publication.event_sequence
                && item.priority == publication.priority
                && item.ttl_ms == publication.ttl_ms
        }) && page
            .items
            .iter()
            .all(|item| item.id != publications.already_expired.id),
        "origin marker-ordered active Event identities",
    )
}

fn validate_receiver_items(items: &[EventItem], expected_ids: &[String]) -> Result<(), DynError> {
    require(expected_ids.len() == 6, "receiver expected Event id count")?;
    require(
        items.len() == 2
            && items[0].id.to_string() == expected_ids[2]
            && items[0].priority == Priority::Flash
            && items[0].ttl_ms.is_none()
            && items[0].payload == LIVE_FLASH_PAYLOAD
            && items[1].id.to_string() == expected_ids[3]
            && items[1].priority == Priority::Immediate
            && items[1].ttl_ms.is_none()
            && items[1].payload == LIVE_IMMEDIATE_PAYLOAD
            && items.iter().all(|item| {
                let id = item.id.to_string();
                id != expected_ids[0]
                    && id != expected_ids[1]
                    && id != expected_ids[4]
                    && id != expected_ids[5]
            }),
        "receiver exact query order and absent identities",
    )
}

fn validate_receiver_deliveries(
    page: &EventDeliveryPage,
    expected_ids: &[String],
) -> Result<(), DynError> {
    require(
        page.deliveries.len() == 2
            && !page.has_more
            && page.deliveries[0].event.id.to_string() == expected_ids[2]
            && page.deliveries[0].event.priority == Priority::Flash
            && page.deliveries[0].event.payload == LIVE_FLASH_PAYLOAD
            && page.deliveries[0].attempt == 1
            && page.deliveries[1].event.id.to_string() == expected_ids[3]
            && page.deliveries[1].event.priority == Priority::Immediate
            && page.deliveries[1].event.payload == LIVE_IMMEDIATE_PAYLOAD
            && page.deliveries[1].attempt == 1,
        "receiver exact priority-ordered poll",
    )
}

fn validate_handle(
    participant: &Participant,
    events: &SelectedEventHandle,
) -> Result<(), DynError> {
    require(
        events.identity() == participant.mission_id
            && events.mission_authority() == participant.mission_authority,
        "selected Event handle mission binding",
    )
}

#[allow(clippy::too_many_arguments)]
fn validate_receipt(
    receipt: &NodeReceipt,
    contacts: usize,
    events: u64,
    event_markers: u64,
    route_cached: u64,
    offered: u64,
    fetched: u64,
    inserted: u64,
) -> Result<(), DynError> {
    require(
        receipt.contacts == contacts
            && receipt.contact_errors == 0
            && receipt.direct_contacts + receipt.relay_contacts + receipt.unknown_path_contacts
                == contacts
            && receipt.items == 0
            && receipt.acceptance_markers == 0
            && receipt.events == events
            && receipt.event_acceptance_markers == event_markers
            && receipt.route_cached_events == route_cached
            && receipt.data_offered == offered
            && receipt.data_fetched == fetched
            && receipt.data_inserted == inserted
            && receipt.data_duplicates == 0
            && receipt.data_remaining == 0
            && receipt.mutable_remaining == 0
            && receipt.deferred_mutable_lanes == 0
            && receipt.controls == 0
            && receipt.applied_controls == 0
            && receipt.pending_controls == 0
            && receipt.control_highwater == 0
            && receipt.blob_ranges_fetched == 0
            && receipt.blob_bytes_fetched == 0
            && receipt.blob_remaining == 0
            && receipt.blob_deferred == 0
            && receipt.blobs == 0
            && receipt.blob_acceptance_markers == 0
            && receipt.blob_last_acceptance_marker == 0
            && receipt.blob_sealed_bytes == 0
            && receipt.blob_operations == 0
            && receipt.blob_operation_bytes == 0
            && receipt.blob_variants == 0
            && receipt.blob_finalized_variants == 0
            && receipt.blob_committed_chunks == 0
            && receipt.blob_committed_file_bytes == 0
            && receipt.blob_reserved_file_bytes == 0
            && receipt.pending_blobs == 0
            && receipt.blob_carrier_prefixes == 0
            && receipt.blob_carrier_fetch_cursors == 0
            && receipt.blob_network_staging_bytes == 0,
        "bounded Event-only node receipt",
    )
}

fn validate_receive_only_receipt(receipt: &NodeReceipt) -> Result<(), DynError> {
    require(
        receipt.data_offered == 0
            && receipt.controls == 0
            && receipt.applied_controls == 0
            && receipt.pending_controls == 0
            && receipt.mutable_remaining == 0
            && receipt.deferred_mutable_lanes == 0
            && receipt.blob_ranges_fetched == 0
            && receipt.blob_bytes_fetched == 0
            && receipt.blob_remaining == 0
            && receipt.blob_deferred == 0,
        "ReceiveOnly initiated or disclosed application work",
    )
}

fn validate_zero_namespaces(inspection: &StoreInspection) -> Result<(), DynError> {
    require(
        inspection.stats == Default::default()
            && inspection.state_stats == Default::default()
            && inspection.record_stats == Default::default()
            && inspection.blob_stats == Default::default()
            && inspection.control_stats == Default::default(),
        "exact zero legacy State Record Blob control namespaces",
    )
}

fn validate_seeded_selector(inspection: &StoreInspection) -> Result<(), DynError> {
    validate_zero_namespaces(inspection)?;
    require(
        inspection.event_stats == Default::default()
            && inspection.event_subscription_stats.subscriptions == 1
            && inspection.event_subscription_stats.pending_deliveries == 0
            && inspection.event_subscription_stats.acknowledged_deliveries == 0
            && inspection.event_subscription_stats.selector_revision == 1
            && inspection.custody_stats.items == 0
            && inspection.custody_stats.retirements == 0,
        "stopped seeded selector inspection",
    )
}

fn validate_origin_inspection(inspection: &StoreInspection) -> Result<(), DynError> {
    validate_zero_namespaces(inspection)?;
    require(
        inspection.event_stats.events == 5
            && inspection.event_stats.acceptance_markers == 6
            && inspection.event_stats.retiring_events == 0
            && inspection.event_stats.route_cached == 0
            && inspection.event_stats.retiring_route_cached == 0
            && inspection.event_subscription_stats == Default::default()
            && inspection.custody_stats.items == 5
            && inspection.custody_stats.retirements == 1
            && inspection.custody_stats.transfer_leases == 0
            && inspection.custody_stats.retries == 0
            && inspection.custody_stats.quotas == 1,
        "origin finite-expiry stopped inspection",
    )
}

fn validate_origin_send_only_change(
    before: &StoreInspection,
    after: &StoreInspection,
) -> Result<(), DynError> {
    require(
        after.event_stats == before.event_stats
            && after.state_stats == before.state_stats
            && after.record_stats == before.record_stats
            && after.blob_stats == before.blob_stats
            && after.event_subscription_stats == before.event_subscription_stats
            && after.control_stats == before.control_stats
            && after.custody_stats.items == before.custody_stats.items
            && after.custody_stats.bytes == before.custody_stats.bytes
            && after.custody_stats.retirements == before.custody_stats.retirements
            && after.custody_stats.transfer_leases == 0
            && after.custody_stats.retries == 0
            && after.custody_stats.quotas == before.custody_stats.quotas
            && before.custody_stats.peer_receipts == 0
            && after.custody_stats.peer_receipts == 4,
        "origin contact changed payload or non-Event namespaces",
    )
}

fn validate_relay_phase_one_inspection(inspection: &StoreInspection) -> Result<(), DynError> {
    validate_zero_namespaces(inspection)?;
    require(
        inspection.event_stats.events == 0
            && inspection.event_stats.retiring_events == 0
            && inspection.event_stats.route_cached == 4
            && inspection.event_stats.retiring_route_cached == 0
            && inspection.event_stats.route_cached_bytes > 0
            && inspection.event_stats.acceptance_markers == 0
            && inspection.event_stats.operation_stats.records_total == 0
            && inspection.event_subscription_stats.subscriptions == 1
            && inspection.event_subscription_stats.pending_deliveries == 0
            && inspection.event_subscription_stats.acknowledged_deliveries == 0
            && inspection.event_subscription_stats.selector_revision == 1
            && inspection.custody_stats.items == 4
            && inspection.custody_stats.bytes > 0
            && inspection.custody_stats.retirements == 0
            && inspection.custody_stats.transfer_leases == 0
            && inspection.custody_stats.peer_receipts == 0
            && inspection.custody_stats.retries == 0
            && inspection.custody_stats.quotas == 2,
        "phase-one route-only exact quota inspection",
    )
}

fn validate_relay_after_expiry_inspection(inspection: &StoreInspection) -> Result<(), DynError> {
    validate_zero_namespaces(inspection)?;
    require(
        inspection.event_stats.events == 0
            && inspection.event_stats.retiring_events == 0
            && inspection.event_stats.route_cached == 3
            && inspection.event_stats.retiring_route_cached == 0
            && inspection.event_stats.route_cached_bytes > 0
            && inspection.event_stats.acceptance_markers == 0
            && inspection.event_stats.operation_stats.records_total == 0
            && inspection.event_subscription_stats.subscriptions == 1
            && inspection.event_subscription_stats.pending_deliveries == 0
            && inspection.event_subscription_stats.acknowledged_deliveries == 0
            && inspection.event_subscription_stats.selector_revision == 1
            && inspection.custody_stats.items == 3
            && inspection.custody_stats.bytes > 0
            && inspection.custody_stats.retirements == 1
            && inspection.custody_stats.transfer_leases == 0
            && inspection.custody_stats.peer_receipts == 0
            && inspection.custody_stats.retries == 0
            && inspection.custody_stats.quotas == 2,
        "peerless relay expiry maintenance inspection",
    )
}

fn validate_relay_after_pressure_inspection(inspection: &StoreInspection) -> Result<(), DynError> {
    validate_zero_namespaces(inspection)?;
    require(
        inspection.event_stats.events == 0
            && inspection.event_stats.retiring_events == 0
            && inspection.event_stats.route_cached == 2
            && inspection.event_stats.retiring_route_cached == 0
            && inspection.event_stats.route_cached_bytes > 0
            && inspection.event_stats.acceptance_markers == 0
            && inspection.event_stats.operation_stats.records_total == 0
            && inspection.event_subscription_stats.subscriptions == 1
            && inspection.event_subscription_stats.pending_deliveries == 0
            && inspection.event_subscription_stats.acknowledged_deliveries == 0
            && inspection.event_subscription_stats.selector_revision == 1
            && inspection.custody_stats.items == 2
            && inspection.custody_stats.bytes > 0
            && inspection.custody_stats.retirements == 2
            && inspection.custody_stats.transfer_leases == 0
            && inspection.custody_stats.peer_receipts == 0
            && inspection.custody_stats.retries == 0
            && inspection.custody_stats.quotas == 2,
        "stopped relay pressure and lowered quota inspection",
    )
}

fn validate_relay_final_inspection(inspection: &StoreInspection) -> Result<(), DynError> {
    validate_zero_namespaces(inspection)?;
    require(
        inspection.event_stats.events == 0
            && inspection.event_stats.retiring_events == 0
            && inspection.event_stats.route_cached == 2
            && inspection.event_stats.retiring_route_cached == 0
            && inspection.event_stats.route_cached_bytes > 0
            && inspection.event_stats.acceptance_markers == 0
            && inspection.event_stats.operation_stats.records_total == 0
            && inspection.event_subscription_stats.subscriptions == 1
            && inspection.event_subscription_stats.pending_deliveries == 0
            && inspection.event_subscription_stats.acknowledged_deliveries == 0
            && inspection.event_subscription_stats.selector_revision == 1
            && inspection.custody_stats.items == 2
            && inspection.custody_stats.bytes > 0
            && inspection.custody_stats.retirements == 2
            && inspection.custody_stats.transfer_leases == 0
            && inspection.custody_stats.peer_receipts == 2
            && inspection.custody_stats.retries == 0
            && inspection.custody_stats.quotas == 2,
        "reopened relay expiry and pressure retirement inspection",
    )
}

fn validate_relay_pressure_persistence(
    after_pressure: &StoreInspection,
    final_inspection: &StoreInspection,
) -> Result<(), DynError> {
    require(
        final_inspection.event_stats == after_pressure.event_stats
            && final_inspection.state_stats == after_pressure.state_stats
            && final_inspection.record_stats == after_pressure.record_stats
            && final_inspection.blob_stats == after_pressure.blob_stats
            && final_inspection.event_subscription_stats == after_pressure.event_subscription_stats
            && final_inspection.control_stats == after_pressure.control_stats
            && final_inspection.custody_stats.items == after_pressure.custody_stats.items
            && final_inspection.custody_stats.bytes == after_pressure.custody_stats.bytes
            && final_inspection.custody_stats.retirements
                == after_pressure.custody_stats.retirements
            && final_inspection.custody_stats.transfer_leases == 0
            && final_inspection.custody_stats.retries == 0
            && final_inspection.custody_stats.quotas == after_pressure.custody_stats.quotas
            && after_pressure.custody_stats.peer_receipts == 0
            && final_inspection.custody_stats.peer_receipts == 2,
        "relay pressure retirement persisted through forwarding",
    )
}

fn validate_receiver_final_inspection(inspection: &StoreInspection) -> Result<(), DynError> {
    validate_zero_namespaces(inspection)?;
    require(
        inspection.event_stats.events == 2
            && inspection.event_stats.retiring_events == 0
            && inspection.event_stats.route_cached == 0
            && inspection.event_stats.retiring_route_cached == 0
            && inspection.event_stats.acceptance_markers == 2
            && inspection.event_stats.operation_stats.records_total == 0
            && inspection.event_subscription_stats.subscriptions == 1
            && inspection.event_subscription_stats.pending_deliveries == 2
            && inspection.event_subscription_stats.acknowledged_deliveries == 0
            && inspection.event_subscription_stats.selector_revision == 1
            && inspection.custody_stats.items == 2
            && inspection.custody_stats.bytes > 0
            && inspection.custody_stats.retirements == 0
            && inspection.custody_stats.transfer_leases == 0
            && inspection.custody_stats.peer_receipts == 0
            && inspection.custody_stats.retries == 0
            && inspection.custody_stats.quotas == 1,
        "ReceiveOnly Consume receiver stopped inspection",
    )
}

fn inspect_participant(participant: &Participant) -> Result<StoreInspection, DynError> {
    let inspection = Store::inspect_existing(participant.state.join(STORE_FILE))?;
    require(
        inspection.mission_authority == Some(participant.mission_authority),
        "store mission authority binding",
    )?;
    Ok(inspection)
}

fn seed_selector(
    participant: &Participant,
    mode: EventSubscriptionMode,
    key: &[u8],
    topic: &Topic,
    scope: &Scope,
) -> Result<(), DynError> {
    let store = Store::open_for_mission(
        participant.state.join(STORE_FILE),
        participant.mission_authority,
    )?;
    store.require_process_exclusive_lock()?;
    let policy = store.control_policy_snapshot()?;
    let outcome = store.create_event_subscription_with_policy(
        &policy,
        &EventSubscriptionKey::new(key.to_vec())?,
        EventSubscriptionSpec {
            mode,
            topic: topic.clone(),
            scope: scope.clone(),
            include_descendant_scopes: false,
        },
    )?;
    require(outcome.inserted, "stopped selector insertion")?;
    drop(store);
    Ok(())
}

fn provision_participants(
    participants_root: &Path,
    topic: &Topic,
    scope: &Scope,
) -> Result<[Participant; 3], DynError> {
    #[derive(Debug)]
    struct CarrierCandidate {
        root: PathBuf,
        id: EndpointId,
    }

    let mut carriers = Vec::new();
    for name in ["carrier-a", "carrier-b", "carrier-c"] {
        let root = participants_root.join(name);
        let state = root.join("state");
        create_owner_directory(&root)?;
        create_owner_directory(&state)?;
        let identity = NodeIdentity::load_or_create(&state)?;
        carriers.push(CarrierCandidate {
            root,
            id: identity.id(),
        });
    }
    carriers.sort_by_key(|candidate| candidate.id);
    require(
        carriers
            .windows(2)
            .all(|window| window[0].id < window[1].id),
        "distinct ordered carrier identities",
    )?;
    for (candidate, role) in carriers.iter().zip(["origin", "relay", "receiver"]) {
        fs::rename(&candidate.root, participants_root.join(role))?;
    }

    let member = ProvisioningAccess::member(scope.clone(), vec![1], vec![topic.clone()])?;
    let route_only = ProvisioningAccess::relay(scope.clone(), vec![1])?;
    let mut seed = [0u8; 32];
    if let Err(error) = getrandom::fill(&mut seed) {
        seed.zeroize();
        return Err(Box::new(error));
    }
    let provisioner = ReferenceProvisioner::from_seed(seed);
    seed.zeroize();
    let mut provisioner = provisioner?;
    let origin_bytes = provisioner
        .issue_node(1, std::slice::from_ref(&member))?
        .to_bytes()?;
    let relay_bytes = provisioner
        .issue_node(2, std::slice::from_ref(&route_only))?
        .to_bytes()?;
    let receiver_bytes = provisioner
        .issue_node(3, std::slice::from_ref(&member))?
        .to_bytes()?;
    let origin = persist_participant(participants_root, "origin", origin_bytes, "member")?;
    let relay = persist_participant(participants_root, "relay", relay_bytes, "route_only")?;
    let receiver = persist_participant(participants_root, "receiver", receiver_bytes, "member")?;
    require(
        origin.carrier_id < relay.carrier_id && relay.carrier_id < receiver.carrier_id,
        "deterministic two-contact initiation ordering",
    )?;
    Ok([origin, relay, receiver])
}

fn persist_participant(
    participants_root: &Path,
    name: &'static str,
    mission_bytes: Vec<u8>,
    access: &'static str,
) -> Result<Participant, DynError> {
    let root = participants_root.join(name);
    let state = root.join("state");
    let mission_path = root.join("mission.bundle");
    let mission = UnprotectedReferenceMission::persist(&mission_path, mission_bytes)?;
    let mission_id = mission.identity();
    let mission_authority = mission.mission_authority_id();
    drop(mission);
    let identity = NodeIdentity::load_existing(&state)?;
    let carrier_id = identity.id();
    drop(identity);
    Ok(Participant {
        name,
        state,
        mission_path,
        mission_id,
        mission_authority,
        carrier_id,
        access,
    })
}

fn validate_participant_domains(
    origin: &Participant,
    relay: &Participant,
    receiver: &Participant,
) -> Result<(), DynError> {
    require(
        origin.mission_authority == relay.mission_authority
            && relay.mission_authority == receiver.mission_authority
            && origin.access == "member"
            && relay.access == "route_only"
            && receiver.access == "member",
        "three participant mission access roles",
    )?;
    let values = [
        origin.carrier_id.to_string(),
        relay.carrier_id.to_string(),
        receiver.carrier_id.to_string(),
        format_node_id(origin.mission_id),
        format_node_id(relay.mission_id),
        format_node_id(receiver.mission_id),
        format_node_id(origin.mission_authority),
    ];
    require(
        values.iter().collect::<BTreeSet<_>>().len() == values.len(),
        "participant carrier mission authority domains",
    )
}

fn canonical_raw_root(root: PathBuf) -> Result<PathBuf, DynError> {
    require(root.is_absolute(), "raw root must be absolute")?;
    let root = fs::canonicalize(root)?;
    require(root.is_dir(), "raw root must be a directory")?;
    Ok(root)
}

#[cfg(unix)]
fn create_owner_directory(path: &Path) -> Result<(), DynError> {
    use std::os::unix::fs::DirBuilderExt as _;

    fs::DirBuilder::new().mode(0o700).create(path)?;
    Ok(())
}

#[cfg(not(unix))]
fn create_owner_directory(path: &Path) -> Result<(), DynError> {
    fs::create_dir(path)?;
    Ok(())
}

fn spawn_phase_one_relay(
    relay: &Participant,
    relay_address: SocketAddr,
    origin: &Participant,
    origin_address: SocketAddr,
) -> Result<ChildActor, DynError> {
    let mut command = Command::new(env::current_exe()?);
    command
        .arg("--internal-relay-phase-1")
        .arg(&relay.state)
        .arg(&relay.mission_path)
        .arg(relay_address.to_string())
        .arg(origin_address.to_string())
        .arg(origin.carrier_id.to_string())
        .arg(format_node_id(origin.mission_id));
    spawn_child(command)
}

fn spawn_phase_two_relay(
    relay: &Participant,
    relay_address: SocketAddr,
    receiver: &Participant,
    receiver_address: SocketAddr,
    origin: [u8; 32],
) -> Result<ChildActor, DynError> {
    let mut command = Command::new(env::current_exe()?);
    command
        .arg("--internal-relay-phase-2")
        .arg(&relay.state)
        .arg(&relay.mission_path)
        .arg(relay_address.to_string())
        .arg(receiver_address.to_string())
        .arg(receiver.carrier_id.to_string())
        .arg(format_node_id(receiver.mission_id))
        .arg(format_node_id(origin));
    spawn_child(command)
}

fn spawn_phase_two_receiver(
    receiver: &Participant,
    receiver_address: SocketAddr,
    relay: &Participant,
    relay_address: SocketAddr,
    origin: &Participant,
    publications: &Publications,
) -> Result<ChildActor, DynError> {
    let mut command = Command::new(env::current_exe()?);
    command
        .arg("--internal-receiver-phase-2")
        .arg(&receiver.state)
        .arg(&receiver.mission_path)
        .arg(receiver_address.to_string())
        .arg(relay_address.to_string())
        .arg(relay.carrier_id.to_string())
        .arg(format_node_id(relay.mission_id))
        .arg(format_node_id(origin.mission_id));
    for (_, publication, _) in publications.ordered() {
        command.arg(publication.id.to_string());
    }
    spawn_child(command)
}

fn spawn_child(mut command: Command) -> Result<ChildActor, DynError> {
    command
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit());
    let mut child = command.spawn()?;
    let stdout = child
        .stdout
        .take()
        .ok_or(AcceptanceFailure("child stdout unavailable"))?;
    let (sender, lines) = tokio::sync::mpsc::unbounded_channel();
    std::thread::spawn(move || {
        for line in BufReader::new(stdout).lines() {
            let terminal = line.is_err();
            if sender.send(line).is_err() || terminal {
                break;
            }
        }
    });
    Ok(ChildActor { child, lines })
}

async fn wait_child_record(
    child: &mut ChildActor,
    expected_kind: &'static str,
) -> Result<ChildFields, DynError> {
    timeout(PROCESS_DEADLINE, async {
        loop {
            let line = child
                .lines
                .recv()
                .await
                .ok_or(AcceptanceFailure("child stdout ended early"))??;
            println!("{line}");
            std::io::stdout().flush()?;
            if let Some((kind, fields)) = parse_child_record(&line)?
                && kind == expected_kind
            {
                return Ok::<_, DynError>(fields);
            }
        }
    })
    .await
    .map_err(|_| AcceptanceFailure("child record deadline"))?
}

async fn finish_child(mut child: ChildActor) -> Result<(), DynError> {
    while let Ok(line) = child.lines.try_recv() {
        let line = line?;
        println!("{line}");
    }
    std::io::stdout().flush()?;
    let status = child.child.wait()?;
    require(status.success(), "child process success")
}

fn emit_child(kind: &str, fields: &[(&str, String)]) -> Result<(), DynError> {
    print!("LINUX_CUSTODY_CHILD\t{kind}");
    for (key, value) in fields {
        validate_field(key, value)?;
        print!("\t{key}={value}");
    }
    println!();
    std::io::stdout().flush()?;
    Ok(())
}

fn parse_child_record(line: &str) -> Result<Option<(String, ChildFields)>, DynError> {
    if !line.starts_with("LINUX_CUSTODY_CHILD\t") {
        return Ok(None);
    }
    let mut parts = line.split('\t');
    require(
        parts.next() == Some("LINUX_CUSTODY_CHILD"),
        "child record prefix",
    )?;
    let kind = parts
        .next()
        .filter(|kind| !kind.is_empty())
        .ok_or(AcceptanceFailure("child record kind"))?
        .to_owned();
    let mut fields = ChildFields::new();
    for part in parts {
        let (key, value) = part
            .split_once('=')
            .ok_or(AcceptanceFailure("child record field"))?;
        require(
            !key.is_empty()
                && !value.is_empty()
                && fields.insert(key.to_owned(), value.to_owned()).is_none(),
            "child record fields",
        )?;
    }
    Ok(Some((kind, fields)))
}

fn child_contact_fields(
    status: &SelectedEventStatus,
    receipt: &NodeReceipt,
) -> Vec<(&'static str, String)> {
    vec![
        (
            "authenticated_contacts",
            status.authenticated_contacts.to_string(),
        ),
        (
            "failed_contact_attempts",
            status.failed_contact_attempts.to_string(),
        ),
        ("receipt_contacts", receipt.contacts.to_string()),
        ("receipt_contact_errors", receipt.contact_errors.to_string()),
        ("receipt_events", receipt.events.to_string()),
        (
            "receipt_event_markers",
            receipt.event_acceptance_markers.to_string(),
        ),
        (
            "receipt_route_cached",
            receipt.route_cached_events.to_string(),
        ),
        ("receipt_data_offered", receipt.data_offered.to_string()),
        ("receipt_data_fetched", receipt.data_fetched.to_string()),
        ("receipt_data_inserted", receipt.data_inserted.to_string()),
        ("receipt_data_remaining", receipt.data_remaining.to_string()),
        (
            "receipt_mutable_remaining",
            receipt.mutable_remaining.to_string(),
        ),
        ("receipt_controls", receipt.controls.to_string()),
        ("receipt_blobs", receipt.blobs.to_string()),
    ]
}

fn inspection_fields(inspection: &StoreInspection) -> Vec<(&'static str, String)> {
    vec![
        ("store_events", inspection.event_stats.events.to_string()),
        (
            "store_route_cached",
            inspection.event_stats.route_cached.to_string(),
        ),
        (
            "store_subscriptions",
            inspection
                .event_subscription_stats
                .subscriptions
                .to_string(),
        ),
        (
            "store_pending_deliveries",
            inspection
                .event_subscription_stats
                .pending_deliveries
                .to_string(),
        ),
        (
            "store_custody_items",
            inspection.custody_stats.items.to_string(),
        ),
        (
            "store_custody_bytes",
            inspection.custody_stats.bytes.to_string(),
        ),
        (
            "store_retirements",
            inspection.custody_stats.retirements.to_string(),
        ),
        ("store_quotas", inspection.custody_stats.quotas.to_string()),
        ("store_states", inspection.state_stats.states.to_string()),
        ("store_records", inspection.record_stats.records.to_string()),
        (
            "store_blobs",
            inspection.blob_stats.publications.to_string(),
        ),
        (
            "store_controls",
            inspection.control_stats.controls.to_string(),
        ),
    ]
}

fn validate_child_ready(
    fields: &ChildFields,
    participant: &str,
    mode: &str,
    quota_items: u64,
) -> Result<(), DynError> {
    require(
        child_field(fields, "participant")? == participant
            && child_field(fields, "mode")? == mode
            && child_field(fields, "quota_items")? == quota_items.to_string(),
        "child ready record",
    )
}

fn validate_phase_one_child(
    fields: &ChildFields,
    inspection: &StoreInspection,
) -> Result<(), DynError> {
    validate_child_inspection_fields(fields, inspection)?;
    require(
        child_field(fields, "participant")? == "relay"
            && child_field(fields, "authenticated_contacts")? == "1"
            && child_field(fields, "failed_contact_attempts")? == "0"
            && child_field(fields, "receipt_contacts")? == "1"
            && child_field(fields, "receipt_route_cached")? == "4"
            && child_field(fields, "receipt_data_offered")? == "0"
            && child_field(fields, "receipt_data_fetched")? == "4"
            && child_field(fields, "receipt_data_inserted")? == "4"
            && child_field(fields, "route_query_items")? == "0",
        "phase-one child evidence",
    )
}

fn validate_phase_two_relay_child(
    fields: &ChildFields,
    inspection: &StoreInspection,
) -> Result<(), DynError> {
    validate_child_inspection_fields(fields, inspection)?;
    require(
        child_field(fields, "participant")? == "relay"
            && child_field(fields, "authenticated_contacts")? == "1"
            && child_field(fields, "receipt_route_cached")? == "2"
            && child_field(fields, "receipt_data_offered")? == "2"
            && child_field(fields, "receipt_data_fetched")? == "0"
            && child_field(fields, "route_query_items")? == "0",
        "phase-two relay child evidence",
    )
}

fn validate_phase_two_receiver_child(
    fields: &ChildFields,
    publications: &Publications,
    inspection: &StoreInspection,
) -> Result<(), DynError> {
    validate_child_inspection_fields(fields, inspection)?;
    require(
        child_field(fields, "participant")? == "receiver"
            && child_field(fields, "authenticated_contacts")? == "1"
            && child_field(fields, "receipt_events")? == "2"
            && child_field(fields, "receipt_data_offered")? == "0"
            && child_field(fields, "receipt_data_fetched")? == "2"
            && child_field(fields, "receipt_data_inserted")? == "2"
            && child_field(fields, "query_items")? == "2"
            && child_field(fields, "poll_deliveries")? == "2"
            && child_field(fields, "first_id")? == publications.live_flash.id.to_string()
            && child_field(fields, "first_priority")? == "flash"
            && child_field(fields, "first_attempt")? == "1"
            && child_field(fields, "second_id")? == publications.live_immediate.id.to_string()
            && child_field(fields, "second_priority")? == "immediate"
            && child_field(fields, "second_attempt")? == "1",
        "phase-two receiver child evidence",
    )
}

fn validate_child_inspection_fields(
    fields: &ChildFields,
    inspection: &StoreInspection,
) -> Result<(), DynError> {
    require(
        child_field(fields, "store_events")? == inspection.event_stats.events.to_string()
            && child_field(fields, "store_route_cached")?
                == inspection.event_stats.route_cached.to_string()
            && child_field(fields, "store_subscriptions")?
                == inspection
                    .event_subscription_stats
                    .subscriptions
                    .to_string()
            && child_field(fields, "store_pending_deliveries")?
                == inspection
                    .event_subscription_stats
                    .pending_deliveries
                    .to_string()
            && child_field(fields, "store_custody_items")?
                == inspection.custody_stats.items.to_string()
            && child_field(fields, "store_custody_bytes")?
                == inspection.custody_stats.bytes.to_string()
            && child_field(fields, "store_retirements")?
                == inspection.custody_stats.retirements.to_string()
            && child_field(fields, "store_quotas")? == inspection.custody_stats.quotas.to_string()
            && child_field(fields, "store_states")? == "0"
            && child_field(fields, "store_records")? == "0"
            && child_field(fields, "store_blobs")? == "0"
            && child_field(fields, "store_controls")? == "0",
        "child stopped inspection agreement",
    )
}

fn child_field<'a>(fields: &'a ChildFields, key: &'static str) -> Result<&'a str, DynError> {
    fields
        .get(key)
        .map(String::as_str)
        .ok_or_else(|| Box::new(AcceptanceFailure("child field missing")) as DynError)
}

fn parse_socket(argument: &OsString) -> Result<SocketAddr, DynError> {
    argument
        .to_str()
        .ok_or_else(|| Box::new(AcceptanceFailure("child socket encoding")) as DynError)?
        .parse()
        .map_err(|_| Box::new(AcceptanceFailure("child socket value")) as DynError)
}

fn parse_endpoint(argument: &OsString) -> Result<EndpointId, DynError> {
    let value = argument
        .to_str()
        .ok_or_else(|| Box::new(AcceptanceFailure("child endpoint encoding")) as DynError)?;
    EndpointId::from_str(value)
        .map_err(|_| Box::new(AcceptanceFailure("child endpoint value")) as DynError)
}

fn parse_node_id(argument: &OsString) -> Result<[u8; 32], DynError> {
    let value = argument
        .to_str()
        .ok_or_else(|| Box::new(AcceptanceFailure("child node encoding")) as DynError)?;
    require(value.len() == 64, "child node length")?;
    let mut bytes = [0u8; 32];
    for (index, byte) in bytes.iter_mut().enumerate() {
        let offset = index * 2;
        *byte = u8::from_str_radix(&value[offset..offset + 2], 16)
            .map_err(|_| AcceptanceFailure("child node value"))?;
    }
    Ok(bytes)
}

async fn reacquire_socket(address: SocketAddr) -> Result<UdpSocket, DynError> {
    timeout(Duration::from_secs(5), async {
        loop {
            match UdpSocket::bind(address) {
                Ok(socket) => return Ok::<_, DynError>(socket),
                Err(error) if error.kind() == std::io::ErrorKind::AddrInUse => {
                    sleep(Duration::from_millis(10)).await;
                }
                Err(error) => return Err(Box::new(error) as DynError),
            }
        }
    })
    .await
    .map_err(|_| AcceptanceFailure("socket reacquisition deadline"))?
}

fn priority_name(priority: Priority) -> &'static str {
    match priority {
        Priority::Routine => "routine",
        Priority::Priority => "priority",
        Priority::Immediate => "immediate",
        Priority::Flash => "flash",
    }
}

fn sha256_hex(bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    digest.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn inspection_summary(inspection: &StoreInspection) -> String {
    format!(
        "events:{},route:{},custody:{},retirements:{},quotas:{},selectors:{},pending:{},state:0,record:0,blob:0,control:0",
        inspection.event_stats.events,
        inspection.event_stats.route_cached,
        inspection.custody_stats.items,
        inspection.custody_stats.retirements,
        inspection.custody_stats.quotas,
        inspection.event_subscription_stats.subscriptions,
        inspection.event_subscription_stats.pending_deliveries,
    )
}

#[allow(clippy::too_many_arguments)]
fn emit_transcript(
    participants: [&Participant; 3],
    publications: &Publications,
    relay_seeded: &StoreInspection,
    receiver_seeded: &StoreInspection,
    origin_phase_one: &StoreInspection,
    relay_phase_one: &StoreInspection,
    relay_after_expiry: &StoreInspection,
    relay_after_pressure: &StoreInspection,
    relay_final: &StoreInspection,
    receiver_final: &StoreInspection,
    origin_receipt: &NodeReceipt,
    relay_phase_one_child: &ChildFields,
    relay_phase_two_child: &ChildFields,
    receiver_phase_two_child: &ChildFields,
    origin_address: SocketAddr,
    relay_address: SocketAddr,
    receiver_address: SocketAddr,
) -> Result<(), DynError> {
    let mut transcript = Transcript::default();
    transcript.emit(
        "META",
        &[
            ("schema", TRANSCRIPT_SCHEMA.to_owned()),
            ("claim", CLAIM.to_owned()),
            ("platform", "linux".to_owned()),
            (
                "custody_clock",
                "clock_boottime_suspend_inclusive".to_owned(),
            ),
            ("participants", "3".to_owned()),
            ("contacts", "2".to_owned()),
            ("publication_model", "numbered-v1".to_owned()),
        ],
    )?;
    for participant in participants {
        transcript.emit(
            "PARTICIPANT",
            &[
                ("participant", participant.name.to_owned()),
                ("access", participant.access.to_owned()),
                ("carrier", participant.carrier_id.to_string()),
                ("mission", format_node_id(participant.mission_id)),
                ("authority", format_node_id(participant.mission_authority)),
                ("provisioning", "independent_reference_bundle".to_owned()),
            ],
        )?;
    }
    transcript.emit(
        "SELECTOR",
        &[
            ("participant", "relay".to_owned()),
            ("mode", "carry".to_owned()),
            ("seeded_while", "stopped".to_owned()),
            ("topic", TOPIC.to_owned()),
            ("scope", SCOPE.to_owned()),
            ("inspection", inspection_summary(relay_seeded)),
        ],
    )?;
    transcript.emit(
        "SELECTOR",
        &[
            ("participant", "receiver".to_owned()),
            ("mode", "consume".to_owned()),
            ("seeded_while", "stopped".to_owned()),
            ("topic", TOPIC.to_owned()),
            ("scope", SCOPE.to_owned()),
            ("inspection", inspection_summary(receiver_seeded)),
        ],
    )?;
    transcript.emit(
        "QUOTA",
        &[
            ("participant", "relay".to_owned()),
            ("phase", "origin_to_relay".to_owned()),
            ("scope", SCOPE.to_owned()),
            ("max_items", INITIAL_RELAY_QUOTA_ITEMS.to_string()),
            ("max_bytes", RELAY_QUOTA_BYTES.to_string()),
            ("exact_scope", "true".to_owned()),
        ],
    )?;
    transcript.emit(
        "QUOTA",
        &[
            ("participant", "relay".to_owned()),
            ("phase", "relay_to_receiver".to_owned()),
            ("scope", SCOPE.to_owned()),
            ("max_items", FINAL_RELAY_QUOTA_ITEMS.to_string()),
            ("max_bytes", RELAY_QUOTA_BYTES.to_string()),
            ("exact_scope", "true".to_owned()),
        ],
    )?;
    for (label, publication, payload) in publications.ordered() {
        transcript.emit(
            "EVENT",
            &[
                ("label", label.to_owned()),
                ("id", publication.id.to_string()),
                ("publisher", format_node_id(publication.publisher)),
                ("sequence", publication.event_sequence.to_string()),
                ("priority", priority_name(publication.priority).to_owned()),
                (
                    "ttl_ms",
                    publication
                        .ttl_ms
                        .map_or_else(|| "durable".to_owned(), |ttl| ttl.to_string()),
                ),
                ("payload_sha256", sha256_hex(payload)),
            ],
        )?;
    }
    transcript.emit(
        "EXPIRY",
        &[
            ("event", publications.already_expired.id.to_string()),
            ("phase", "before_first_contact".to_owned()),
            ("offered", "false".to_owned()),
            ("origin_retirements", "1".to_owned()),
            ("origin_active_events", "5".to_owned()),
        ],
    )?;
    transcript.emit(
        "CONTACT",
        &[
            ("phase", "origin_to_relay".to_owned()),
            ("initiator", "origin".to_owned()),
            ("initiator_policy", "at_least_priority".to_owned()),
            ("responder", "relay".to_owned()),
            ("responder_policy", "receive_only".to_owned()),
            ("offered", origin_receipt.data_offered.to_string()),
            (
                "relay_fetched",
                child_field(relay_phase_one_child, "receipt_data_fetched")?.to_owned(),
            ),
            ("routine_withheld", publications.routine.id.to_string()),
        ],
    )?;
    transcript.emit(
        "STORE",
        &[
            ("phase", "after_origin_stop".to_owned()),
            ("participant", "origin".to_owned()),
            ("inspection", inspection_summary(origin_phase_one)),
        ],
    )?;
    transcript.emit(
        "STORE",
        &[
            ("phase", "after_first_contact".to_owned()),
            ("participant", "relay".to_owned()),
            ("inspection", inspection_summary(relay_phase_one)),
            ("content_events", "0".to_owned()),
            ("route_cached", "4".to_owned()),
        ],
    )?;
    transcript.emit(
        "REOPEN_MAINTENANCE",
        &[
            ("participant", "relay".to_owned()),
            ("expired", publications.relay_expiring.id.to_string()),
            (
                "expiry_runtime_quota_items",
                INITIAL_RELAY_QUOTA_ITEMS.to_string(),
            ),
            (
                "expiry_items_after",
                relay_after_expiry.custody_stats.items.to_string(),
            ),
            (
                "expiry_retirements_after",
                relay_after_expiry.custody_stats.retirements.to_string(),
            ),
            ("pressure_execution", "stopped_store".to_owned()),
            (
                "pressure_demand_items",
                STOPPED_PRESSURE_DEMAND_ITEMS.to_string(),
            ),
            ("pressure_demand_bytes", "0".to_owned()),
            ("pressure_demand_priority", "flash".to_owned()),
            (
                "pressure_retired",
                publications.live_priority.id.to_string(),
            ),
            (
                "pressure_items_after",
                relay_after_pressure.custody_stats.items.to_string(),
            ),
            (
                "retirements_after",
                relay_after_pressure.custody_stats.retirements.to_string(),
            ),
            ("quota_items_after", FINAL_RELAY_QUOTA_ITEMS.to_string()),
            ("retirement_fence_persisted", "true".to_owned()),
        ],
    )?;
    transcript.emit(
        "CONTACT",
        &[
            ("phase", "relay_to_receiver".to_owned()),
            ("initiator", "relay".to_owned()),
            ("initiator_policy", "normal".to_owned()),
            ("responder", "receiver".to_owned()),
            ("responder_policy", "receive_only".to_owned()),
            (
                "offered",
                child_field(relay_phase_two_child, "receipt_data_offered")?.to_owned(),
            ),
            (
                "receiver_fetched",
                child_field(receiver_phase_two_child, "receipt_data_fetched")?.to_owned(),
            ),
            ("origin_runtime_active", "false".to_owned()),
        ],
    )?;
    transcript.emit(
        "DELIVERY",
        &[
            ("order", "1".to_owned()),
            ("event", publications.live_flash.id.to_string()),
            ("priority", "flash".to_owned()),
            ("poll_attempt", "1".to_owned()),
        ],
    )?;
    transcript.emit(
        "DELIVERY",
        &[
            ("order", "2".to_owned()),
            ("event", publications.live_immediate.id.to_string()),
            ("priority", "immediate".to_owned()),
            ("poll_attempt", "1".to_owned()),
        ],
    )?;
    transcript.emit(
        "ABSENCE",
        &[
            (
                "already_expired",
                publications.already_expired.id.to_string(),
            ),
            ("relay_expired", publications.relay_expiring.id.to_string()),
            ("quota_pressure", publications.live_priority.id.to_string()),
            ("below_floor", publications.routine.id.to_string()),
            ("receiver_query_count", "2".to_owned()),
            ("receiver_poll_count", "2".to_owned()),
        ],
    )?;
    transcript.emit(
        "RECEIVE_ONLY",
        &[
            ("participants", "relay,receiver".to_owned()),
            ("initiated_contacts", "0".to_owned()),
            ("event_data_offered", "0".to_owned()),
            ("state_offered", "0".to_owned()),
            ("record_offered", "0".to_owned()),
            ("blob_offered", "0".to_owned()),
            ("control_offered", "0".to_owned()),
        ],
    )?;
    transcript.emit(
        "STORE",
        &[
            ("phase", "final".to_owned()),
            ("participant", "relay".to_owned()),
            ("inspection", inspection_summary(relay_final)),
            ("route_only", "true".to_owned()),
        ],
    )?;
    transcript.emit(
        "STORE",
        &[
            ("phase", "final".to_owned()),
            ("participant", "receiver".to_owned()),
            ("inspection", inspection_summary(receiver_final)),
            ("pending_deliveries", "2".to_owned()),
        ],
    )?;
    transcript.emit(
        "NAMESPACE_ZERO",
        &[
            ("participants", "origin,relay,receiver".to_owned()),
            ("legacy", "0".to_owned()),
            ("state", "0".to_owned()),
            ("record", "0".to_owned()),
            ("blob", "0".to_owned()),
            ("control", "0".to_owned()),
            ("exact", "true".to_owned()),
        ],
    )?;
    transcript.emit(
        "SOCKET_FENCE",
        &[
            ("origin", origin_address.to_string()),
            ("relay", relay_address.to_string()),
            ("receiver", receiver_address.to_string()),
            (
                "origin_socket_held_during_second_contact",
                "true".to_owned(),
            ),
            ("all_reacquired_after_stop", "true".to_owned()),
        ],
    )?;
    let total = transcript.records + 1;
    transcript.emit(
        "RESULT",
        &[
            ("status", "pass".to_owned()),
            ("records", total.to_string()),
            ("bounded", "true".to_owned()),
            ("payload_representation", "sha256_only".to_owned()),
            ("secret_values_emitted", "false".to_owned()),
            ("physical_network_claimed", "false".to_owned()),
            ("global_convergence_claimed", "false".to_owned()),
        ],
    )?;
    require(
        transcript.records == total,
        "canonical transcript record count",
    )
}

#[derive(Default)]
struct Transcript {
    records: usize,
}

impl Transcript {
    fn emit(&mut self, kind: &str, fields: &[(&str, String)]) -> Result<(), DynError> {
        validate_field("kind", kind)?;
        print!("LINUX_CUSTODY\t{kind}");
        for (key, value) in fields {
            validate_field(key, value)?;
            print!("\t{key}={value}");
        }
        println!();
        std::io::stdout().flush()?;
        self.records = self
            .records
            .checked_add(1)
            .ok_or(AcceptanceFailure("transcript record overflow"))?;
        Ok(())
    }
}

fn validate_field(key: &str, value: &str) -> Result<(), DynError> {
    require(
        !key.is_empty()
            && !value.is_empty()
            && !key.contains(['\t', '\n', '='])
            && !value.contains(['\t', '\n']),
        "transcript field encoding",
    )
}
