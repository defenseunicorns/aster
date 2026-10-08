//! Retained one-host acceptance producer for durable live selected Event delivery.
//!
//! The canonical `LIVE_EVENT` transcript contains only bounded application
//! metadata and payload digests. Runtime `READY`/`CONTACT`/`STOP` lines and the
//! narrowly scoped `LIVE_EVENT_CHILD` process-coordination lines remain in
//! stdout so an independent checker can bind the forced receiver termination to
//! a poll whose durable attempt was already returned and flushed.

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
    time::Duration,
};

use aster_iroh::{EndpointId, ExpectedPeer};
use aster_mesh::{ProvisioningAccess, ReferenceProvisioner};
use aster_node::{
    EventEmissionPolicy, MissionExpectedPeer, MutableSourceInterests, NodeApplication, NodeConfig,
    NodeIdentity, NodeReceipt, SelectedForwardingConfig,
    application::{
        ApplicationError, ApplicationErrorKind, AuthenticatedPeerStatus, ContactSyncStatus,
        EventAcknowledgement, EventDelivery, EventGapPage, EventGapQuery, EventPollRequest,
        EventPublishResult, EventQuery, EventQueryPage, EventSubscription,
        EventSubscriptionRequest, EventSyncStatus, EventUnsubscribe, PeerAuthorization, Priority,
        Scope, SelectedEventHandle, SelectedEventStatus, Topic,
    },
    format_node_id,
    mission::UnprotectedReferenceMission,
    start_node, start_node_with_forwarding,
};
use sha2::{Digest as _, Sha256};
use tokio::{
    sync::mpsc::UnboundedReceiver,
    time::{sleep, timeout},
};
use zeroize::Zeroize as _;

const TRANSCRIPT_SCHEMA: &str = "aster-selected-live-event-transcript/v2";
const CLAIM: &str = "selected-live-event-one-host-direct-iroh-priority-withheld-authenticated-gap-forced-receiver-process-termination-durable-redelivery-gap-closure-acceptance";
const TOPIC: &str = "opaque";
const BETA_TOPIC: &str = "opaque.beta";
const SCOPE: &str = "test/runtime-contact";
const LOGICAL_KEY: &[u8] = b"acceptance/live-event-stream";
const FIRST_PAYLOAD: &[u8] = b"priority event one";
const SECOND_PAYLOAD: &[u8] = b"routine event two";
const THIRD_PAYLOAD: &[u8] = b"flash event three";
const BETA_PAYLOAD: &[u8] = b"authorized but initially unsubscribed beta event";
const CHANGED_FIRST_PAYLOAD: &[u8] = b"changed event one";
const FIRST_OPERATION: &[u8] = b"acceptance/live-event/first";
const SECOND_OPERATION: &[u8] = b"acceptance/live-event/second";
const THIRD_OPERATION: &[u8] = b"acceptance/live-event/third";
const BETA_OPERATION: &[u8] = b"acceptance/live-event/beta-first";
const SUBSCRIPTION_OPERATION: &[u8] = b"acceptance/live-event/subscription";
const BETA_SUBSCRIPTION_OPERATION: &[u8] = b"acceptance/live-event/beta-subscription";
const POLL_DEADLINE: Duration = Duration::from_secs(30);
const SINGLE_CONTACT_SYNC_INTERVAL: Duration = Duration::from_secs(300);
const TRANSCRIPT_RECORDS: usize = 79;

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

#[derive(Clone)]
struct Participant {
    name: &'static str,
    root: PathBuf,
    state: PathBuf,
    mission_path: PathBuf,
    mission: UnprotectedReferenceMission,
    mission_id: [u8; 32],
    mission_authority: [u8; 32],
    carrier_id: EndpointId,
}

#[derive(Clone, Copy)]
struct PublicationSpec {
    payload: &'static [u8],
    priority: Priority,
}

struct ChildActor {
    child: Child,
    lines: UnboundedReceiver<Result<String, std::io::Error>>,
}

#[tokio::main]
async fn main() {
    let arguments = env::args_os().collect::<Vec<_>>();
    let child_mode = arguments
        .get(1)
        .and_then(|argument| argument.to_str())
        .is_some_and(|argument| argument.starts_with("--internal-"));
    let result = if child_mode {
        run_child(&arguments[1..]).await
    } else {
        run_parent(&arguments[1..]).await
    };
    if let Err(error) = result {
        let stage = failure_stage(error.as_ref());
        if child_mode {
            eprintln!("LIVE_EVENT_CHILD_FAILURE status=error stage={stage}");
        } else {
            eprintln!("LIVE_EVENT_FAILURE status=error stage={stage}");
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
    let beta_topic = Topic::new(BETA_TOPIC)?;
    let scope = Scope::new(SCOPE)?;
    let participants_root = raw_root.join("participants");
    create_owner_directory(&participants_root)?;
    let [publisher, mut receiver] =
        provision_participants(&participants_root, &topic, &beta_topic, &scope)?;
    validate_participant_domains(&publisher, &receiver)?;

    let journal_path = publisher.state.join("live-acceptance-publication.redb");
    numbered::Journal::initialize(&journal_path, b"native.live-acceptance.v1")?;
    let mut journal = numbered::Journal::open(&journal_path, b"native.live-acceptance.v1")?;
    let peerless = start_peerless(&publisher).await?;
    let peerless_events = peerless.selected_events();
    validate_handle(&publisher, &peerless_events)?;
    journal
        .recover(&mut numbered::Backend::Live(&peerless_events))
        .await?;
    let first_request = publication_request(
        PublicationSpec {
            payload: FIRST_PAYLOAD,
            priority: Priority::Priority,
        },
        &topic,
        &scope,
    );
    let first = journal
        .publish_metadata(
            &mut numbered::Backend::Live(&peerless_events),
            first_request.clone(),
        )
        .await?;
    validate_publication(&first, &publisher, Priority::Priority, 1, 1)?;
    let first_retry = journal
        .publish_metadata(
            &mut numbered::Backend::Live(&peerless_events),
            first_request.clone(),
        )
        .await?;
    validate_exact_retry(&first, &first_retry)?;
    let mut changed = first_request;
    changed.payload = CHANGED_FIRST_PAYLOAD.to_vec();
    let conflict = match journal
        .probe_changed(&mut numbered::Backend::Live(&peerless_events), &changed)
        .await
    {
        Err(error) => *error.downcast::<ApplicationError>()?,
        Ok(_) => {
            return Err(Box::new(AcceptanceFailure(
                "changed Event operation accepted",
            )));
        }
    };
    validate_sanitized_conflict(&conflict)?;
    journal
        .acknowledge(&mut numbered::Backend::Live(&peerless_events))
        .await?;

    let second = journal
        .publish_metadata(
            &mut numbered::Backend::Live(&peerless_events),
            publication_request(
                PublicationSpec {
                    payload: SECOND_PAYLOAD,
                    priority: Priority::Routine,
                },
                &topic,
                &scope,
            ),
        )
        .await?;
    validate_publication(&second, &publisher, Priority::Routine, 2, 2)?;
    journal
        .acknowledge(&mut numbered::Backend::Live(&peerless_events))
        .await?;
    let third = journal
        .publish_metadata(
            &mut numbered::Backend::Live(&peerless_events),
            publication_request(
                PublicationSpec {
                    payload: THIRD_PAYLOAD,
                    priority: Priority::Flash,
                },
                &topic,
                &scope,
            ),
        )
        .await?;
    validate_publication(&third, &publisher, Priority::Flash, 3, 3)?;
    journal
        .acknowledge(&mut numbered::Backend::Live(&peerless_events))
        .await?;
    let beta = journal
        .publish_metadata(
            &mut numbered::Backend::Live(&peerless_events),
            numbered::Intent {
                predecessor: None,
                topic: beta_topic.as_str().into(),
                scope: scope.as_str().into(),
                priority: Priority::Priority as u8,
                logical_key: LOGICAL_KEY.to_vec(),
                payload: BETA_PAYLOAD.to_vec(),
                tombstone: false,
                ttl_ms: None,
            },
        )
        .await?;
    validate_publication(&beta, &publisher, Priority::Priority, 4, 1)?;
    journal
        .acknowledge(&mut numbered::Backend::Live(&peerless_events))
        .await?;
    let peerless_query =
        query_stream(&peerless_events, publisher.mission_id, &topic, &scope).await?;
    validate_exact_stream(&peerless_query.items, &first, &second, &third)?;
    validate_query_page(&peerless_query, 3, 4, false, "publisher alpha query")?;
    let peerless_beta_query =
        query_stream(&peerless_events, publisher.mission_id, &beta_topic, &scope).await?;
    require(
        peerless_beta_query.items.len() == 1
            && peerless_beta_query.items[0].id == beta.id
            && peerless_beta_query.items[0].payload == BETA_PAYLOAD,
        "publisher beta Event",
    )?;
    validate_query_page(&peerless_beta_query, 1, 4, false, "publisher beta query")?;
    let peerless_status = peerless_events.status().await?;
    require(
        peerless_status
            .event_operation_capacity
            .numbered_stats
            .clients
            == 1
            && peerless_status
                .event_operation_capacity
                .numbered_stats
                .outstanding_results
                == 0,
        "bounded numbered publication clients and acknowledged results",
    )?;
    validate_offline_status(&peerless_status)?;
    let retained_peerless = peerless_events.clone();
    let peerless_receipt = peerless.shutdown().await?;
    validate_peerless_receipt(&peerless_receipt, 4)?;
    validate_closed_handle(&retained_peerless).await?;
    drop((peerless_events, retained_peerless));

    let publisher_socket = UdpSocket::bind(("127.0.0.1", 0))?;
    let receiver_socket = UdpSocket::bind(("127.0.0.1", 0))?;
    let publisher_address = publisher_socket.local_addr()?;
    let receiver_address = receiver_socket.local_addr()?;
    drop(receiver_socket);

    // The reference mission loader holds an exclusive process-lifetime artifact
    // guard. Release the parent's receiver guard while the two independent
    // receiver child processes own that participant, retaining only public IDs
    // and the already-persisted state/path in the parent.
    let receiver_mission = std::mem::replace(&mut receiver.mission, publisher.mission.clone());
    drop(receiver_mission);

    let mut attempt_one =
        spawn_attempt_one(&receiver, receiver_address, &publisher, publisher_address)?;
    let awaiting = wait_child_record(&mut attempt_one, "AWAITING").await?;
    validate_attempt_one_awaiting(&awaiting, &receiver)?;
    drop(publisher_socket);
    let threshold_publisher = start_node_with_forwarding(
        connected_config(&publisher, publisher_address, &receiver, receiver_address),
        SelectedForwardingConfig::default()
            .with_emission_policy(EventEmissionPolicy::at_least(Priority::Priority)),
    )
    .await?;
    let threshold_events = threshold_publisher.selected_events();
    validate_handle(&publisher, &threshold_events)?;
    let attempt_one_ready = wait_child_record(&mut attempt_one, "ATTEMPT1_READY").await?;
    validate_attempt_one_ready(&attempt_one_ready, &publisher, &first, &third)?;
    attempt_one.child.kill()?;
    drain_child_lines(&mut attempt_one.lines).await?;
    let killed_status = attempt_one.child.wait()?;
    require(
        !killed_status.success(),
        "receiver child was not force terminated",
    )?;

    let threshold_status = wait_for_status(&threshold_events, |status| {
        status.authenticated_contacts == 1 && status.sync == EventSyncStatus::LastContactComplete
    })
    .await?;
    validate_connected_status(
        &threshold_status,
        &receiver,
        ContactSyncStatus::CompleteForLastNegotiatedContact,
        EventSyncStatus::LastContactComplete,
    )?;
    let retained_threshold = threshold_events.clone();
    let threshold_receipt = threshold_publisher.shutdown().await?;
    validate_single_direct_receipt(&threshold_receipt, 4)?;
    validate_closed_handle(&retained_threshold).await?;
    drop((threshold_events, retained_threshold));

    let mut attempt_two = spawn_attempt_two(&receiver, &publisher)?;
    let attempt_two_done = wait_child_record(&mut attempt_two, "ATTEMPT2_DONE").await?;
    drain_child_lines(&mut attempt_two.lines).await?;
    let attempt_two_status = attempt_two.child.wait()?;
    require(attempt_two_status.success(), "receiver retry child failed")?;
    validate_attempt_two(&attempt_two_done, &publisher, &first, &third)?;
    receiver.mission = UnprotectedReferenceMission::load(&receiver.mission_path)?;

    let normal_receiver = start_node(connected_config(
        &receiver,
        receiver_address,
        &publisher,
        publisher_address,
    ))
    .await?;
    let normal_receiver_events = normal_receiver.selected_events();
    validate_handle(&receiver, &normal_receiver_events)?;
    let reopened_subscription = normal_receiver_events
        .subscribe(subscription_request(&topic, &scope))
        .await?;
    require(
        !reopened_subscription.inserted,
        "normal subscription replay inserted",
    )?;
    let before_normal = normal_receiver_events.status().await?;
    validate_awaiting_status(&before_normal)?;
    let before_normal_poll = poll(&normal_receiver_events, reopened_subscription).await?;
    require(
        before_normal_poll.deliveries.is_empty() && !before_normal_poll.has_more,
        "normal pre-contact poll",
    )?;

    let normal_publisher = start_node(connected_config(
        &publisher,
        publisher_address,
        &receiver,
        receiver_address,
    ))
    .await?;
    let normal_publisher_events = normal_publisher.selected_events();
    validate_handle(&publisher, &normal_publisher_events)?;
    let after_normal = wait_for_status(&normal_receiver_events, |status| {
        status.authenticated_contacts == 1 && status.sync == EventSyncStatus::LastContactComplete
    })
    .await?;
    validate_connected_status(
        &after_normal,
        &publisher,
        ContactSyncStatus::CompleteForLastNegotiatedContact,
        EventSyncStatus::LastContactComplete,
    )?;
    let publisher_normal_status = wait_for_status(&normal_publisher_events, |status| {
        status.authenticated_contacts == 1 && status.sync == EventSyncStatus::LastContactComplete
    })
    .await?;
    validate_connected_status(
        &publisher_normal_status,
        &receiver,
        ContactSyncStatus::CompleteForLastNegotiatedContact,
        EventSyncStatus::LastContactComplete,
    )?;
    let closed_gap = normal_receiver_events
        .gaps(gap_query(publisher.mission_id, &topic, &scope))
        .await?;
    validate_closed_gap(&closed_gap)?;
    let second_delivery_page = poll(&normal_receiver_events, reopened_subscription).await?;
    require(
        second_delivery_page.deliveries.len() == 1 && !second_delivery_page.has_more,
        "gap-closing delivery count",
    )?;
    let second_delivery = &second_delivery_page.deliveries[0];
    validate_delivery(second_delivery, &second, SECOND_PAYLOAD, 1)?;
    let second_ack = normal_receiver_events
        .acknowledge(reopened_subscription.id, second.id)
        .await?;
    let second_reack = normal_receiver_events
        .acknowledge(reopened_subscription.id, second.id)
        .await?;
    require(
        second_ack == EventAcknowledgement::Acknowledged
            && second_reack == EventAcknowledgement::AlreadyAcknowledged,
        "gap-closing acknowledgement",
    )?;
    let normal_empty = poll(&normal_receiver_events, reopened_subscription).await?;
    require(
        normal_empty.deliveries.is_empty() && !normal_empty.has_more,
        "normal empty poll",
    )?;
    let normal_query = query_stream(
        &normal_receiver_events,
        publisher.mission_id,
        &topic,
        &scope,
    )
    .await?;
    validate_exact_stream(&normal_query.items, &first, &second, &third)?;
    validate_query_page(&normal_query, 3, 3, false, "receiver alpha query")?;
    let normal_beta_query = query_stream(
        &normal_receiver_events,
        publisher.mission_id,
        &beta_topic,
        &scope,
    )
    .await?;
    require(
        normal_beta_query.items.is_empty() && !normal_beta_query.has_more,
        "unsubscribed beta Event withheld",
    )?;
    validate_query_page(&normal_beta_query, 0, 3, false, "receiver beta query")?;
    let beta_subscription = normal_receiver_events
        .subscribe(EventSubscriptionRequest {
            operation_key: BETA_SUBSCRIPTION_OPERATION.to_vec(),
            topic: beta_topic.clone(),
            scope: scope.clone(),
            include_descendant_scopes: false,
        })
        .await?;
    require(beta_subscription.inserted, "beta subscription creation")?;
    let policy_changed = normal_receiver_events.status().await?;
    validate_connected_status(
        &policy_changed,
        &publisher,
        ContactSyncStatus::PolicyChangedSinceContact,
        EventSyncStatus::PolicyChangedSinceContact,
    )?;
    let beta_removed = normal_receiver_events
        .unsubscribe(beta_subscription.id)
        .await?;
    let beta_removed_again = normal_receiver_events
        .unsubscribe(beta_subscription.id)
        .await?;
    require(
        beta_removed == EventUnsubscribe::Removed
            && beta_removed_again == EventUnsubscribe::AlreadyAbsent,
        "beta subscription removal",
    )?;
    let retained_normal_publisher = normal_publisher_events.clone();
    let retained_normal_receiver = normal_receiver_events.clone();
    let (normal_publisher_receipt, normal_receiver_receipt) =
        tokio::join!(normal_publisher.shutdown(), normal_receiver.shutdown());
    let normal_publisher_receipt = normal_publisher_receipt?;
    let normal_receiver_receipt = normal_receiver_receipt?;
    validate_single_direct_receipt(&normal_publisher_receipt, 4)?;
    validate_single_direct_receipt(&normal_receiver_receipt, 3)?;
    validate_closed_handle(&retained_normal_publisher).await?;
    validate_closed_handle(&retained_normal_receiver).await?;
    drop((
        normal_publisher_events,
        normal_receiver_events,
        retained_normal_publisher,
        retained_normal_receiver,
    ));

    let final_receiver = start_peerless(&receiver).await?;
    let final_events = final_receiver.selected_events();
    validate_handle(&receiver, &final_events)?;
    let final_subscription = final_events
        .subscribe(subscription_request(&topic, &scope))
        .await?;
    require(
        !final_subscription.inserted,
        "final subscription replay inserted",
    )?;
    let final_status = final_events.status().await?;
    validate_offline_status(&final_status)?;
    let final_gap = final_events
        .gaps(gap_query(publisher.mission_id, &topic, &scope))
        .await?;
    validate_closed_gap(&final_gap)?;
    let final_empty = poll(&final_events, final_subscription).await?;
    require(
        final_empty.deliveries.is_empty() && !final_empty.has_more,
        "final empty poll",
    )?;
    let final_query = query_stream(&final_events, publisher.mission_id, &topic, &scope).await?;
    validate_exact_stream(&final_query.items, &first, &second, &third)?;
    validate_query_page(&final_query, 3, 3, false, "final alpha query")?;
    let final_beta_query =
        query_stream(&final_events, publisher.mission_id, &beta_topic, &scope).await?;
    validate_query_page(&final_beta_query, 0, 3, false, "final beta query")?;
    let retained_final = final_events.clone();
    let final_receipt = final_receiver.shutdown().await?;
    validate_peerless_receipt(&final_receipt, 3)?;
    validate_closed_handle(&retained_final).await?;
    drop((final_events, retained_final));

    validate_reacquired_bind(publisher_address)?;
    validate_reacquired_bind(receiver_address)?;

    emit_transcript(
        &publisher,
        &receiver,
        &first,
        &first_retry,
        &second,
        &third,
        &beta,
        &peerless_query,
        &peerless_beta_query,
        &peerless_status,
        &peerless_receipt,
        &awaiting,
        &attempt_one_ready,
        &threshold_status,
        &threshold_receipt,
        &attempt_two_done,
        reopened_subscription,
        &before_normal,
        &after_normal,
        beta_subscription,
        &policy_changed,
        beta_removed,
        beta_removed_again,
        second_delivery,
        second_ack,
        second_reack,
        &normal_query,
        &normal_beta_query,
        &normal_publisher_receipt,
        &normal_receiver_receipt,
        final_subscription,
        &final_status,
        &final_query,
        &final_beta_query,
        &final_receipt,
    );
    Ok(())
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

fn provision_participants(
    participants_root: &Path,
    topic: &Topic,
    beta_topic: &Topic,
    scope: &Scope,
) -> Result<[Participant; 2], DynError> {
    let access = ProvisioningAccess::member(
        scope.clone(),
        vec![1],
        vec![topic.clone(), beta_topic.clone()],
    )?;
    let mut seed = [0u8; 32];
    if let Err(error) = getrandom::fill(&mut seed) {
        seed.zeroize();
        return Err(Box::new(error));
    }
    let provisioner = ReferenceProvisioner::from_seed(seed);
    seed.zeroize();
    let mut provisioner = provisioner?;
    let first_bundle = provisioner.issue_node(1, std::slice::from_ref(&access))?;
    let second_bundle = provisioner.issue_node(2, std::slice::from_ref(&access))?;
    let first = persist_participant(participants_root, "candidate-a", first_bundle.to_bytes()?)?;
    let second = persist_participant(participants_root, "candidate-b", second_bundle.to_bytes()?)?;
    let first_is_publisher = first.carrier_id < second.carrier_id;
    let first_root = first.root.clone();
    let second_root = second.root.clone();
    drop((first, second));
    let (publisher_candidate, receiver_candidate) = if first_is_publisher {
        (first_root, second_root)
    } else {
        (second_root, first_root)
    };
    fs::rename(publisher_candidate, participants_root.join("publisher"))?;
    fs::rename(receiver_candidate, participants_root.join("receiver"))?;
    let publisher = load_participant(participants_root, "publisher")?;
    let receiver = load_participant(participants_root, "receiver")?;
    require(
        publisher.carrier_id < receiver.carrier_id,
        "deterministic publisher initiation ordering",
    )?;
    Ok([publisher, receiver])
}

fn persist_participant(
    participants_root: &Path,
    name: &'static str,
    mission_bytes: Vec<u8>,
) -> Result<Participant, DynError> {
    let root = participants_root.join(name);
    let state = root.join("state");
    let mission_path = root.join("mission.bundle");
    create_owner_directory(&root)?;
    create_owner_directory(&state)?;
    let mission = UnprotectedReferenceMission::persist(&mission_path, mission_bytes)?;
    let mission_id = mission.identity();
    let mission_authority = mission.mission_authority_id();
    let identity = NodeIdentity::load_or_create(&state)?;
    let carrier_id = identity.id();
    drop(identity);
    Ok(Participant {
        name,
        root,
        state,
        mission_path,
        mission,
        mission_id,
        mission_authority,
        carrier_id,
    })
}

fn load_participant(participants_root: &Path, name: &'static str) -> Result<Participant, DynError> {
    let root = participants_root.join(name);
    let state = root.join("state");
    let mission_path = root.join("mission.bundle");
    let mission = UnprotectedReferenceMission::load(&mission_path)?;
    let mission_id = mission.identity();
    let mission_authority = mission.mission_authority_id();
    let identity = NodeIdentity::load_or_create(&state)?;
    let carrier_id = identity.id();
    drop(identity);
    Ok(Participant {
        name,
        root,
        state,
        mission_path,
        mission,
        mission_id,
        mission_authority,
        carrier_id,
    })
}

fn validate_participant_domains(
    publisher: &Participant,
    receiver: &Participant,
) -> Result<(), DynError> {
    require(
        publisher.mission_id != receiver.mission_id
            && publisher.carrier_id != receiver.carrier_id
            && publisher.mission_authority == receiver.mission_authority,
        "independently provisioned participant identities",
    )?;
    let domains = [
        publisher.carrier_id.to_string(),
        receiver.carrier_id.to_string(),
        format_node_id(publisher.mission_id),
        format_node_id(receiver.mission_id),
        format_node_id(publisher.mission_authority),
    ];
    require(
        domains.iter().collect::<BTreeSet<_>>().len() == domains.len(),
        "participant identity domains",
    )
}

async fn start_peerless(participant: &Participant) -> Result<aster_node::RunningNode, DynError> {
    Ok(start_node(NodeConfig {
        state: participant.state.clone(),
        bind: SocketAddr::from(([127, 0, 0, 1], 0)),
        mission: participant.mission.clone(),
        peers: Vec::new(),
        mutable_interests: MutableSourceInterests::default(),
        sync_interval: SINGLE_CONTACT_SYNC_INTERVAL,
        run_for: None,
        application: NodeApplication::Relay,
    })
    .await?)
}

fn connected_config(
    local: &Participant,
    bind: SocketAddr,
    remote: &Participant,
    remote_address: SocketAddr,
) -> NodeConfig {
    NodeConfig {
        state: local.state.clone(),
        bind,
        mission: local.mission.clone(),
        peers: vec![MissionExpectedPeer {
            carrier: ExpectedPeer {
                id: remote.carrier_id,
                address: remote_address,
            },
            mission: remote.mission_id,
        }],
        mutable_interests: MutableSourceInterests::default(),
        sync_interval: SINGLE_CONTACT_SYNC_INTERVAL,
        run_for: None,
        application: NodeApplication::Relay,
    }
}

fn publication_request(spec: PublicationSpec, topic: &Topic, scope: &Scope) -> numbered::Intent {
    numbered::Intent {
        predecessor: None,
        topic: topic.as_str().into(),
        scope: scope.as_str().into(),
        priority: spec.priority as u8,
        logical_key: LOGICAL_KEY.to_vec(),
        payload: spec.payload.to_vec(),
        tombstone: false,
        ttl_ms: None,
    }
}

fn subscription_request(topic: &Topic, scope: &Scope) -> EventSubscriptionRequest {
    EventSubscriptionRequest {
        operation_key: SUBSCRIPTION_OPERATION.to_vec(),
        topic: topic.clone(),
        scope: scope.clone(),
        include_descendant_scopes: false,
    }
}

fn gap_query(publisher: [u8; 32], topic: &Topic, scope: &Scope) -> EventGapQuery {
    EventGapQuery {
        publisher,
        topic: topic.clone(),
        scope: scope.clone(),
        after_sequence: 0,
        scan_limit: 8,
    }
}

async fn poll(
    handle: &SelectedEventHandle,
    subscription: EventSubscription,
) -> Result<aster_node::application::EventDeliveryPage, ApplicationError> {
    handle
        .poll(EventPollRequest {
            subscription: subscription.id,
            delivery_limit: 8,
            scan_limit: 8,
        })
        .await
}

async fn query_stream(
    handle: &SelectedEventHandle,
    publisher: [u8; 32],
    topic: &Topic,
    scope: &Scope,
) -> Result<aster_node::application::EventQueryPage, ApplicationError> {
    handle
        .query(EventQuery {
            publisher: Some(publisher),
            topic: Some(topic.clone()),
            scope: Some(scope.clone()),
            include_descendant_scopes: false,
            logical_key: Some(LOGICAL_KEY.to_vec()),
            after_acceptance_marker: 0,
            before_acceptance_marker: None,
            limit: 8,
        })
        .await
}

fn validate_handle(
    participant: &Participant,
    handle: &SelectedEventHandle,
) -> Result<(), DynError> {
    require(
        handle.identity() == participant.mission_id
            && handle.mission_authority() == participant.mission_authority,
        "selected Event handle mission binding",
    )
}

fn validate_publication(
    publication: &EventPublishResult,
    publisher: &Participant,
    priority: Priority,
    counter: u64,
    sequence: u64,
) -> Result<(), DynError> {
    require(
        publication.inserted
            && publication.publisher == publisher.mission_id
            && publication.publisher_counter == counter
            && publication.event_sequence == sequence
            && publication.priority == priority
            && publication.ttl_ms.is_none()
            && publication.acceptance_marker == counter,
        "Event publication metadata",
    )
}

fn validate_exact_retry(
    publication: &EventPublishResult,
    retry: &EventPublishResult,
) -> Result<(), DynError> {
    require(
        !retry.inserted
            && retry.id == publication.id
            && retry.publisher == publication.publisher
            && retry.publisher_counter == publication.publisher_counter
            && retry.event_sequence == publication.event_sequence
            && retry.priority == publication.priority
            && retry.ttl_ms == publication.ttl_ms
            && retry.acceptance_marker == publication.acceptance_marker,
        "Event exact retry",
    )
}

fn validate_sanitized_conflict(error: &ApplicationError) -> Result<(), DynError> {
    let displayed = format!("{error}");
    let debugged = format!("{error:?}");
    let request_bytes: &[&[u8]] = &[
        FIRST_PAYLOAD,
        CHANGED_FIRST_PAYLOAD,
        SECOND_PAYLOAD,
        THIRD_PAYLOAD,
        BETA_PAYLOAD,
        LOGICAL_KEY,
        FIRST_OPERATION,
        SECOND_OPERATION,
        THIRD_OPERATION,
        BETA_OPERATION,
        SUBSCRIPTION_OPERATION,
        BETA_SUBSCRIPTION_OPERATION,
    ];
    let mut forbidden = request_bytes
        .iter()
        .map(|bytes| String::from_utf8_lossy(bytes).into_owned())
        .collect::<Vec<_>>();
    forbidden.extend([
        TOPIC.to_owned(),
        BETA_TOPIC.to_owned(),
        SCOPE.to_owned(),
        "redb".to_owned(),
        "transfer".to_owned(),
        "source Event".to_owned(),
    ]);
    require(
        error.kind() == ApplicationErrorKind::Conflict
            && error.operation() == "publish_numbered"
            && Error::source(error).is_none()
            && forbidden
                .iter()
                .all(|needle| !displayed.contains(needle) && !debugged.contains(needle)),
        "sanitized changed Event operation conflict",
    )
}

fn validate_query_page(
    page: &EventQueryPage,
    expected_items: usize,
    expected_scanned_through: u64,
    expected_has_more: bool,
    label: &'static str,
) -> Result<(), DynError> {
    require(
        page.items.len() == expected_items
            && page.scanned_through == expected_scanned_through
            && page.has_more == expected_has_more,
        label,
    )
}

fn validate_exact_stream(
    items: &[aster_node::application::EventItem],
    first: &EventPublishResult,
    second: &EventPublishResult,
    third: &EventPublishResult,
) -> Result<(), DynError> {
    require(items.len() == 3, "exact Event stream count")?;
    let mut items = items.iter().collect::<Vec<_>>();
    items.sort_by_key(|item| item.event_sequence);
    for (item, publication, payload, priority, sequence) in [
        (&items[0], first, FIRST_PAYLOAD, Priority::Priority, 1),
        (&items[1], second, SECOND_PAYLOAD, Priority::Routine, 2),
        (&items[2], third, THIRD_PAYLOAD, Priority::Flash, 3),
    ] {
        require(
            item.id == publication.id
                && item.publisher == publication.publisher
                && item.publisher_counter == publication.publisher_counter
                && item.event_sequence == sequence
                && item.priority == priority
                && item.ttl_ms.is_none()
                && item.logical_key == LOGICAL_KEY
                && item.payload == payload
                && !item.tombstone,
            "exact Event stream item",
        )?;
    }
    Ok(())
}

fn validate_delivery(
    delivery: &EventDelivery,
    publication: &EventPublishResult,
    payload: &[u8],
    attempt: u64,
) -> Result<(), DynError> {
    require(
        delivery.event.id == publication.id
            && delivery.event.publisher == publication.publisher
            && delivery.event.publisher_counter == publication.publisher_counter
            && delivery.event.event_sequence == publication.event_sequence
            && delivery.event.priority == publication.priority
            && delivery.event.ttl_ms.is_none()
            && delivery.event.logical_key == LOGICAL_KEY
            && delivery.event.payload == payload
            && !delivery.event.tombstone
            && delivery.attempt == attempt,
        "Event delivery metadata",
    )
}

fn validate_offline_status(status: &SelectedEventStatus) -> Result<(), DynError> {
    require(
        status.sync == EventSyncStatus::Offline
            && status.authenticated_contacts == 0
            && status.failed_contact_attempts == 0
            && status.peers.is_empty(),
        "peerless Event status",
    )
}

fn validate_awaiting_status(status: &SelectedEventStatus) -> Result<(), DynError> {
    require(
        status.sync == EventSyncStatus::AwaitingAuthenticatedContact
            && status.authenticated_contacts == 0
            && status.failed_contact_attempts == 0
            && status.peers.is_empty(),
        "awaiting authenticated Event contact",
    )
}

fn validate_connected_status(
    status: &SelectedEventStatus,
    remote: &Participant,
    contact: ContactSyncStatus,
    sync: EventSyncStatus,
) -> Result<(), DynError> {
    require(
        status.sync == sync
            && status.authenticated_contacts == 1
            && status.failed_contact_attempts == 0
            && status.peers
                == vec![AuthenticatedPeerStatus {
                    peer: remote.mission_id,
                    contacts: 1,
                    authorization: PeerAuthorization::Active,
                    last_contact: contact,
                }],
        "bounded authenticated Event status",
    )
}

fn validate_open_gap(page: &EventGapPage, publisher: [u8; 32]) -> Result<(), DynError> {
    require(
        page.gaps.len() == 1
            && page.gaps[0].publisher == publisher
            && page.gaps[0].start_sequence == 2
            && page.gaps[0].end_sequence == 3
            && page.scanned_through_sequence == 3
            && !page.has_more,
        "authenticated Event gap",
    )
}

fn validate_closed_gap(page: &EventGapPage) -> Result<(), DynError> {
    require(
        page.gaps.is_empty() && page.scanned_through_sequence == 3 && !page.has_more,
        "closed authenticated Event gap",
    )
}

async fn wait_for_status(
    handle: &SelectedEventHandle,
    predicate: impl Fn(&SelectedEventStatus) -> bool,
) -> Result<SelectedEventStatus, DynError> {
    timeout(POLL_DEADLINE, async {
        loop {
            let status = handle.status().await?;
            require(
                status.authenticated_contacts <= 1 && status.failed_contact_attempts == 0,
                "single-contact Event status bound",
            )?;
            if predicate(&status) {
                return Ok::<_, DynError>(status);
            }
            sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .map_err(|_| AcceptanceFailure("Event status deadline"))?
}

async fn validate_closed_handle(handle: &SelectedEventHandle) -> Result<(), DynError> {
    let error = match handle.status().await {
        Err(error) => error,
        Ok(_) => return Err(Box::new(AcceptanceFailure("closed Event handle accepted"))),
    };
    require(
        error.kind() == ApplicationErrorKind::StateUnavailable && error.operation() == "status",
        "closed Event handle",
    )
}

fn validate_excluded_receipt(receipt: &NodeReceipt) -> Result<(), DynError> {
    require(
        receipt.items == 0
            && receipt.acceptance_markers == 0
            && receipt.route_cached_events == 0
            && receipt.mutable_remaining == 0
            && receipt.deferred_mutable_lanes == 0
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
        "excluded receipt classes",
    )
}

fn validate_peerless_receipt(receipt: &NodeReceipt, events: u64) -> Result<(), DynError> {
    validate_excluded_receipt(receipt)?;
    require(
        receipt.contacts == 0
            && receipt.contact_errors == 0
            && receipt.direct_contacts == 0
            && receipt.relay_contacts == 0
            && receipt.unknown_path_contacts == 0
            && receipt.carrier_path_transitions == 0
            && receipt.carrier_path_transition_saturations == 0
            && receipt.events == events
            && receipt.event_acceptance_markers == events
            && receipt.data_offered == 0
            && receipt.data_fetched == 0
            && receipt.data_inserted == 0
            && receipt.data_duplicates == 0
            && receipt.data_remaining == 0,
        "peerless Event shutdown receipt",
    )
}

fn validate_single_direct_receipt(receipt: &NodeReceipt, events: u64) -> Result<(), DynError> {
    validate_excluded_receipt(receipt)?;
    require(
        receipt.contacts == 1
            && receipt.contact_errors == 0
            && receipt.direct_contacts == 1
            && receipt.relay_contacts == 0
            && receipt.unknown_path_contacts == 0
            && receipt.carrier_path_transitions == 0
            && receipt.carrier_path_transition_saturations == 0
            && receipt.events == events
            && receipt.event_acceptance_markers == events,
        "single direct Event shutdown receipt",
    )
}

fn validate_reacquired_bind(address: SocketAddr) -> Result<(), DynError> {
    let socket = UdpSocket::bind(address)?;
    require(socket.local_addr()? == address, "Event bind reacquisition")?;
    drop(socket);
    Ok(())
}

async fn run_child(arguments: &[OsString]) -> Result<(), DynError> {
    match arguments.first().and_then(|argument| argument.to_str()) {
        Some("--internal-attempt-1") => run_attempt_one_child(&arguments[1..]).await,
        Some("--internal-attempt-2") => run_attempt_two_child(&arguments[1..]).await,
        _ => Err(Box::new(AcceptanceFailure("unknown internal child mode"))),
    }
}

async fn run_attempt_one_child(arguments: &[OsString]) -> Result<(), DynError> {
    require(arguments.len() == 6, "attempt-one child arguments")?;
    let state = PathBuf::from(&arguments[0]);
    let mission_path = PathBuf::from(&arguments[1]);
    let bind = parse_socket(&arguments[2])?;
    let remote_address = parse_socket(&arguments[3])?;
    let remote_carrier = parse_endpoint(&arguments[4])?;
    let remote_mission = parse_node_id(&arguments[5])?;
    let mission = UnprotectedReferenceMission::load(&mission_path)?;
    let receiver_id = mission.identity();
    let receiver_authority = mission.mission_authority_id();
    let running = start_node(NodeConfig {
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
    })
    .await?;
    let events = running.selected_events();
    require(
        events.identity() == receiver_id && events.mission_authority() == receiver_authority,
        "attempt-one child handle binding",
    )?;
    let topic = Topic::new(TOPIC)?;
    let scope = Scope::new(SCOPE)?;
    let subscription = events
        .subscribe(subscription_request(&topic, &scope))
        .await?;
    require(subscription.inserted, "attempt-one subscription creation")?;
    let awaiting = events.status().await?;
    validate_awaiting_status(&awaiting)?;
    emit_child(
        "AWAITING",
        &[
            ("participant", "receiver".to_owned()),
            ("identity", format_node_id(receiver_id)),
            ("subscription_id", subscription.id.to_string()),
            ("subscription_inserted", subscription.inserted.to_string()),
            ("sync", sync_name(awaiting.sync).to_owned()),
            (
                "authenticated_contacts",
                awaiting.authenticated_contacts.to_string(),
            ),
            (
                "failed_contact_attempts",
                awaiting.failed_contact_attempts.to_string(),
            ),
            ("peers", awaiting.peers.len().to_string()),
        ],
    )?;

    let contacted = wait_for_status(&events, |status| {
        status.authenticated_contacts == 1 && status.sync == EventSyncStatus::LastContactComplete
    })
    .await?;
    require(
        contacted.peers.len() == 1
            && contacted.peers[0].peer == remote_mission
            && contacted.peers[0].contacts == 1
            && contacted.peers[0].authorization == PeerAuthorization::Active
            && contacted.peers[0].last_contact
                == ContactSyncStatus::CompleteForLastNegotiatedContact,
        "attempt-one authenticated peer status",
    )?;
    let gaps = events
        .gaps(gap_query(remote_mission, &topic, &scope))
        .await?;
    validate_open_gap(&gaps, remote_mission)?;
    let page = poll(&events, subscription).await?;
    require(
        page.deliveries.len() == 2 && !page.has_more,
        "attempt-one delivery count",
    )?;
    let deliveries = sorted_deliveries(&page.deliveries)?;
    validate_child_delivery(deliveries[0], 1, Priority::Priority, FIRST_PAYLOAD, 1)?;
    validate_child_delivery(deliveries[1], 3, Priority::Flash, THIRD_PAYLOAD, 1)?;
    emit_child(
        "ATTEMPT1_READY",
        &[
            ("participant", "receiver".to_owned()),
            ("subscription_id", subscription.id.to_string()),
            ("sync", sync_name(contacted.sync).to_owned()),
            (
                "authenticated_contacts",
                contacted.authenticated_contacts.to_string(),
            ),
            (
                "failed_contact_attempts",
                contacted.failed_contact_attempts.to_string(),
            ),
            ("peer", format_node_id(contacted.peers[0].peer)),
            ("peer_contacts", contacted.peers[0].contacts.to_string()),
            (
                "peer_authorization",
                authorization_name(contacted.peers[0].authorization).to_owned(),
            ),
            (
                "peer_last_contact",
                contact_name(contacted.peers[0].last_contact).to_owned(),
            ),
            ("gap_start", gaps.gaps[0].start_sequence.to_string()),
            ("gap_end", gaps.gaps[0].end_sequence.to_string()),
            (
                "gap_scanned_through",
                gaps.scanned_through_sequence.to_string(),
            ),
            ("gap_has_more", gaps.has_more.to_string()),
            ("first_id", deliveries[0].event.id.to_string()),
            (
                "first_sequence",
                deliveries[0].event.event_sequence.to_string(),
            ),
            (
                "first_priority",
                priority_name(deliveries[0].event.priority).to_owned(),
            ),
            ("first_attempt", deliveries[0].attempt.to_string()),
            (
                "first_payload_sha256",
                sha256_hex(&deliveries[0].event.payload),
            ),
            ("third_id", deliveries[1].event.id.to_string()),
            (
                "third_sequence",
                deliveries[1].event.event_sequence.to_string(),
            ),
            (
                "third_priority",
                priority_name(deliveries[1].event.priority).to_owned(),
            ),
            ("third_attempt", deliveries[1].attempt.to_string()),
            (
                "third_payload_sha256",
                sha256_hex(&deliveries[1].event.payload),
            ),
            ("acknowledged", "false".to_owned()),
        ],
    )?;
    std::future::pending::<()>().await;
    #[allow(unreachable_code)]
    Ok(())
}

async fn run_attempt_two_child(arguments: &[OsString]) -> Result<(), DynError> {
    require(arguments.len() == 3, "attempt-two child arguments")?;
    let state = PathBuf::from(&arguments[0]);
    let mission_path = PathBuf::from(&arguments[1]);
    let publisher = parse_node_id(&arguments[2])?;
    let mission = UnprotectedReferenceMission::load(&mission_path)?;
    let running = start_node(NodeConfig {
        state,
        bind: SocketAddr::from(([127, 0, 0, 1], 0)),
        mission,
        peers: Vec::new(),
        mutable_interests: MutableSourceInterests::default(),
        sync_interval: SINGLE_CONTACT_SYNC_INTERVAL,
        run_for: None,
        application: NodeApplication::Relay,
    })
    .await?;
    let events = running.selected_events();
    let topic = Topic::new(TOPIC)?;
    let scope = Scope::new(SCOPE)?;
    let subscription = events
        .subscribe(subscription_request(&topic, &scope))
        .await?;
    require(!subscription.inserted, "attempt-two subscription replay")?;
    let status = events.status().await?;
    validate_offline_status(&status)?;
    let gaps = events.gaps(gap_query(publisher, &topic, &scope)).await?;
    validate_open_gap(&gaps, publisher)?;
    let page = poll(&events, subscription).await?;
    require(
        page.deliveries.len() == 2 && !page.has_more,
        "attempt-two delivery count",
    )?;
    let deliveries = sorted_deliveries(&page.deliveries)?;
    validate_child_delivery(deliveries[0], 1, Priority::Priority, FIRST_PAYLOAD, 2)?;
    validate_child_delivery(deliveries[1], 3, Priority::Flash, THIRD_PAYLOAD, 2)?;
    require(
        deliveries[0].event.publisher == publisher && deliveries[1].event.publisher == publisher,
        "attempt-two publisher consistency",
    )?;
    let first_ack = events
        .acknowledge(subscription.id, deliveries[0].event.id)
        .await?;
    let first_reack = events
        .acknowledge(subscription.id, deliveries[0].event.id)
        .await?;
    let third_ack = events
        .acknowledge(subscription.id, deliveries[1].event.id)
        .await?;
    let third_reack = events
        .acknowledge(subscription.id, deliveries[1].event.id)
        .await?;
    require(
        first_ack == EventAcknowledgement::Acknowledged
            && first_reack == EventAcknowledgement::AlreadyAcknowledged
            && third_ack == EventAcknowledgement::Acknowledged
            && third_reack == EventAcknowledgement::AlreadyAcknowledged,
        "attempt-two acknowledgements",
    )?;
    let empty = poll(&events, subscription).await?;
    require(
        empty.deliveries.is_empty() && !empty.has_more,
        "attempt-two empty poll",
    )?;
    let retained = events.clone();
    let receipt = running.shutdown().await?;
    validate_peerless_receipt(&receipt, 2)?;
    validate_closed_handle(&retained).await?;
    let mut child_fields = vec![
        ("participant", "receiver".to_owned()),
        ("publisher", format_node_id(publisher)),
        ("subscription_id", subscription.id.to_string()),
        ("subscription_inserted", subscription.inserted.to_string()),
        ("sync", sync_name(status.sync).to_owned()),
        (
            "authenticated_contacts",
            status.authenticated_contacts.to_string(),
        ),
        (
            "failed_contact_attempts",
            status.failed_contact_attempts.to_string(),
        ),
        ("peers", status.peers.len().to_string()),
        ("gap_start", gaps.gaps[0].start_sequence.to_string()),
        ("gap_end", gaps.gaps[0].end_sequence.to_string()),
        (
            "gap_scanned_through",
            gaps.scanned_through_sequence.to_string(),
        ),
        ("gap_has_more", gaps.has_more.to_string()),
        ("first_id", deliveries[0].event.id.to_string()),
        (
            "first_sequence",
            deliveries[0].event.event_sequence.to_string(),
        ),
        (
            "first_priority",
            priority_name(deliveries[0].event.priority).to_owned(),
        ),
        ("first_attempt", deliveries[0].attempt.to_string()),
        (
            "first_payload_sha256",
            sha256_hex(&deliveries[0].event.payload),
        ),
        ("first_ack", acknowledgement_name(first_ack).to_owned()),
        ("first_reack", acknowledgement_name(first_reack).to_owned()),
        ("third_id", deliveries[1].event.id.to_string()),
        (
            "third_sequence",
            deliveries[1].event.event_sequence.to_string(),
        ),
        (
            "third_priority",
            priority_name(deliveries[1].event.priority).to_owned(),
        ),
        ("third_attempt", deliveries[1].attempt.to_string()),
        (
            "third_payload_sha256",
            sha256_hex(&deliveries[1].event.payload),
        ),
        ("third_ack", acknowledgement_name(third_ack).to_owned()),
        ("third_reack", acknowledgement_name(third_reack).to_owned()),
        ("empty_deliveries", empty.deliveries.len().to_string()),
        ("empty_has_more", empty.has_more.to_string()),
    ];
    child_fields.extend(prefixed_receipt_fields(&receipt));
    child_fields.extend([
        ("closed_kind", "state_unavailable".to_owned()),
        ("closed_operation", "status".to_owned()),
    ]);
    emit_child("ATTEMPT2_DONE", &child_fields)?;
    Ok(())
}

fn sorted_deliveries(deliveries: &[EventDelivery]) -> Result<Vec<&EventDelivery>, DynError> {
    let mut deliveries = deliveries.iter().collect::<Vec<_>>();
    deliveries.sort_by_key(|delivery| delivery.event.event_sequence);
    require(
        deliveries
            .windows(2)
            .all(|window| window[0].event.event_sequence < window[1].event.event_sequence),
        "distinct Event delivery sequences",
    )?;
    Ok(deliveries)
}

fn validate_child_delivery(
    delivery: &EventDelivery,
    sequence: u64,
    priority: Priority,
    payload: &[u8],
    attempt: u64,
) -> Result<(), DynError> {
    require(
        delivery.event.event_sequence == sequence
            && delivery.event.priority == priority
            && delivery.event.ttl_ms.is_none()
            && delivery.event.logical_key == LOGICAL_KEY
            && delivery.event.payload == payload
            && !delivery.event.tombstone
            && delivery.attempt == attempt,
        "child Event delivery metadata",
    )
}

fn spawn_attempt_one(
    receiver: &Participant,
    receiver_address: SocketAddr,
    publisher: &Participant,
    publisher_address: SocketAddr,
) -> Result<ChildActor, DynError> {
    let mut command = Command::new(env::current_exe()?);
    command
        .arg("--internal-attempt-1")
        .arg(&receiver.state)
        .arg(&receiver.mission_path)
        .arg(receiver_address.to_string())
        .arg(publisher_address.to_string())
        .arg(publisher.carrier_id.to_string())
        .arg(format_node_id(publisher.mission_id));
    spawn_child(command)
}

fn spawn_attempt_two(
    receiver: &Participant,
    publisher: &Participant,
) -> Result<ChildActor, DynError> {
    let mut command = Command::new(env::current_exe()?);
    command
        .arg("--internal-attempt-2")
        .arg(&receiver.state)
        .arg(&receiver.mission_path)
        .arg(format_node_id(publisher.mission_id));
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
    timeout(POLL_DEADLINE, async {
        loop {
            let line = child
                .lines
                .recv()
                .await
                .ok_or(AcceptanceFailure("child stdout ended early"))??;
            forward_child_line(&line)?;
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

async fn drain_child_lines(
    lines: &mut UnboundedReceiver<Result<String, std::io::Error>>,
) -> Result<(), DynError> {
    while let Some(line) = lines.recv().await {
        let line = line?;
        forward_child_line(&line)?;
    }
    Ok(())
}

fn forward_child_line(line: &str) -> Result<(), DynError> {
    println!("{line}");
    std::io::stdout().flush()?;
    Ok(())
}

fn emit_child(kind: &str, fields: &[(&str, String)]) -> Result<(), DynError> {
    print!("LIVE_EVENT_CHILD\t{kind}");
    for (key, value) in fields {
        require(
            !key.is_empty()
                && !value.is_empty()
                && !key.contains(['\t', '\n', '='])
                && !value.contains(['\t', '\n']),
            "child record encoding",
        )?;
        print!("\t{key}={value}");
    }
    println!();
    std::io::stdout().flush()?;
    Ok(())
}

fn parse_child_record(line: &str) -> Result<Option<(String, ChildFields)>, DynError> {
    if !line.starts_with("LIVE_EVENT_CHILD\t") {
        return Ok(None);
    }
    let mut parts = line.split('\t');
    require(
        parts.next() == Some("LIVE_EVENT_CHILD"),
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

fn child_field<'a>(fields: &'a ChildFields, key: &'static str) -> Result<&'a str, DynError> {
    fields
        .get(key)
        .map(String::as_str)
        .ok_or_else(|| Box::new(AcceptanceFailure("child field missing")) as DynError)
}

fn validate_attempt_one_awaiting(
    fields: &ChildFields,
    receiver: &Participant,
) -> Result<(), DynError> {
    require(
        child_field(fields, "participant")? == "receiver"
            && child_field(fields, "identity")? == format_node_id(receiver.mission_id)
            && child_field(fields, "subscription_inserted")? == "true"
            && child_field(fields, "sync")? == "awaiting_authenticated_contact"
            && child_field(fields, "authenticated_contacts")? == "0"
            && child_field(fields, "failed_contact_attempts")? == "0"
            && child_field(fields, "peers")? == "0",
        "attempt-one awaiting record",
    )
}

fn validate_attempt_one_ready(
    fields: &ChildFields,
    publisher: &Participant,
    first: &EventPublishResult,
    third: &EventPublishResult,
) -> Result<(), DynError> {
    require(
        child_field(fields, "participant")? == "receiver"
            && child_field(fields, "sync")? == "last_contact_complete"
            && child_field(fields, "authenticated_contacts")? == "1"
            && child_field(fields, "failed_contact_attempts")? == "0"
            && child_field(fields, "peer")? == format_node_id(publisher.mission_id)
            && child_field(fields, "peer_contacts")? == "1"
            && child_field(fields, "peer_authorization")? == "active"
            && child_field(fields, "peer_last_contact")? == "complete_for_last_negotiated_contact"
            && child_field(fields, "gap_start")? == "2"
            && child_field(fields, "gap_end")? == "3"
            && child_field(fields, "gap_scanned_through")? == "3"
            && child_field(fields, "gap_has_more")? == "false"
            && child_field(fields, "first_id")? == first.id.to_string()
            && child_field(fields, "first_sequence")? == "1"
            && child_field(fields, "first_priority")? == "priority"
            && child_field(fields, "first_attempt")? == "1"
            && child_field(fields, "first_payload_sha256")? == sha256_hex(FIRST_PAYLOAD)
            && child_field(fields, "third_id")? == third.id.to_string()
            && child_field(fields, "third_sequence")? == "3"
            && child_field(fields, "third_priority")? == "flash"
            && child_field(fields, "third_attempt")? == "1"
            && child_field(fields, "third_payload_sha256")? == sha256_hex(THIRD_PAYLOAD)
            && child_field(fields, "acknowledged")? == "false",
        "attempt-one ready record",
    )
}

fn validate_attempt_two(
    fields: &ChildFields,
    publisher: &Participant,
    first: &EventPublishResult,
    third: &EventPublishResult,
) -> Result<(), DynError> {
    require(
        child_field(fields, "participant")? == "receiver"
            && child_field(fields, "publisher")? == format_node_id(publisher.mission_id)
            && child_field(fields, "subscription_inserted")? == "false"
            && child_field(fields, "sync")? == "offline"
            && child_field(fields, "authenticated_contacts")? == "0"
            && child_field(fields, "failed_contact_attempts")? == "0"
            && child_field(fields, "peers")? == "0"
            && child_field(fields, "gap_start")? == "2"
            && child_field(fields, "gap_end")? == "3"
            && child_field(fields, "gap_scanned_through")? == "3"
            && child_field(fields, "gap_has_more")? == "false"
            && child_field(fields, "first_id")? == first.id.to_string()
            && child_field(fields, "first_sequence")? == "1"
            && child_field(fields, "first_priority")? == "priority"
            && child_field(fields, "first_attempt")? == "2"
            && child_field(fields, "first_payload_sha256")? == sha256_hex(FIRST_PAYLOAD)
            && child_field(fields, "first_ack")? == "acknowledged"
            && child_field(fields, "first_reack")? == "already_acknowledged"
            && child_field(fields, "third_id")? == third.id.to_string()
            && child_field(fields, "third_sequence")? == "3"
            && child_field(fields, "third_priority")? == "flash"
            && child_field(fields, "third_attempt")? == "2"
            && child_field(fields, "third_payload_sha256")? == sha256_hex(THIRD_PAYLOAD)
            && child_field(fields, "third_ack")? == "acknowledged"
            && child_field(fields, "third_reack")? == "already_acknowledged"
            && child_field(fields, "empty_deliveries")? == "0"
            && child_field(fields, "empty_has_more")? == "false"
            && child_field(fields, "shutdown_contacts")? == "0"
            && child_field(fields, "shutdown_contact_errors")? == "0"
            && child_field(fields, "shutdown_direct_contacts")? == "0"
            && child_field(fields, "shutdown_relay_contacts")? == "0"
            && child_field(fields, "shutdown_unknown_path_contacts")? == "0"
            && child_field(fields, "shutdown_events")? == "2"
            && child_field(fields, "shutdown_event_acceptance_markers")? == "2"
            && child_field(fields, "closed_kind")? == "state_unavailable"
            && child_field(fields, "closed_operation")? == "status",
        "attempt-two completion record",
    )
}

fn prefixed_receipt_fields(receipt: &NodeReceipt) -> Vec<(&'static str, String)> {
    vec![
        ("shutdown_contacts", receipt.contacts.to_string()),
        (
            "shutdown_contact_errors",
            receipt.contact_errors.to_string(),
        ),
        (
            "shutdown_direct_contacts",
            receipt.direct_contacts.to_string(),
        ),
        (
            "shutdown_relay_contacts",
            receipt.relay_contacts.to_string(),
        ),
        (
            "shutdown_unknown_path_contacts",
            receipt.unknown_path_contacts.to_string(),
        ),
        (
            "shutdown_carrier_path_transitions",
            receipt.carrier_path_transitions.to_string(),
        ),
        (
            "shutdown_carrier_path_transition_saturations",
            receipt.carrier_path_transition_saturations.to_string(),
        ),
        ("shutdown_items", receipt.items.to_string()),
        (
            "shutdown_acceptance_markers",
            receipt.acceptance_markers.to_string(),
        ),
        ("shutdown_events", receipt.events.to_string()),
        (
            "shutdown_event_acceptance_markers",
            receipt.event_acceptance_markers.to_string(),
        ),
        (
            "shutdown_route_cached_events",
            receipt.route_cached_events.to_string(),
        ),
        ("shutdown_controls", receipt.controls.to_string()),
        (
            "shutdown_applied_controls",
            receipt.applied_controls.to_string(),
        ),
        (
            "shutdown_pending_controls",
            receipt.pending_controls.to_string(),
        ),
        (
            "shutdown_control_highwater",
            receipt.control_highwater.to_string(),
        ),
        ("shutdown_data_offered", receipt.data_offered.to_string()),
        ("shutdown_data_fetched", receipt.data_fetched.to_string()),
        ("shutdown_data_inserted", receipt.data_inserted.to_string()),
        (
            "shutdown_data_duplicates",
            receipt.data_duplicates.to_string(),
        ),
        (
            "shutdown_data_remaining",
            receipt.data_remaining.to_string(),
        ),
        (
            "shutdown_mutable_remaining",
            receipt.mutable_remaining.to_string(),
        ),
        (
            "shutdown_deferred_mutable_lanes",
            receipt.deferred_mutable_lanes.to_string(),
        ),
        (
            "shutdown_blob_ranges_fetched",
            receipt.blob_ranges_fetched.to_string(),
        ),
        (
            "shutdown_blob_bytes_fetched",
            receipt.blob_bytes_fetched.to_string(),
        ),
        (
            "shutdown_blob_remaining",
            receipt.blob_remaining.to_string(),
        ),
        ("shutdown_blob_deferred", receipt.blob_deferred.to_string()),
        ("shutdown_blobs", receipt.blobs.to_string()),
        (
            "shutdown_blob_acceptance_markers",
            receipt.blob_acceptance_markers.to_string(),
        ),
        (
            "shutdown_blob_last_acceptance_marker",
            receipt.blob_last_acceptance_marker.to_string(),
        ),
        (
            "shutdown_blob_sealed_bytes",
            receipt.blob_sealed_bytes.to_string(),
        ),
        (
            "shutdown_blob_operations",
            receipt.blob_operations.to_string(),
        ),
        (
            "shutdown_blob_operation_bytes",
            receipt.blob_operation_bytes.to_string(),
        ),
        ("shutdown_blob_variants", receipt.blob_variants.to_string()),
        (
            "shutdown_blob_finalized_variants",
            receipt.blob_finalized_variants.to_string(),
        ),
        (
            "shutdown_blob_committed_chunks",
            receipt.blob_committed_chunks.to_string(),
        ),
        (
            "shutdown_blob_committed_file_bytes",
            receipt.blob_committed_file_bytes.to_string(),
        ),
        (
            "shutdown_blob_reserved_file_bytes",
            receipt.blob_reserved_file_bytes.to_string(),
        ),
        ("shutdown_pending_blobs", receipt.pending_blobs.to_string()),
        (
            "shutdown_blob_carrier_prefixes",
            receipt.blob_carrier_prefixes.to_string(),
        ),
        (
            "shutdown_blob_carrier_fetch_cursors",
            receipt.blob_carrier_fetch_cursors.to_string(),
        ),
        (
            "shutdown_blob_network_staging_bytes",
            receipt.blob_network_staging_bytes.to_string(),
        ),
    ]
}

fn sync_name(sync: EventSyncStatus) -> &'static str {
    match sync {
        EventSyncStatus::Offline => "offline",
        EventSyncStatus::NoActiveConfiguredPeers => "no_active_configured_peers",
        EventSyncStatus::AwaitingAuthenticatedContact => "awaiting_authenticated_contact",
        EventSyncStatus::LastContactComplete => "last_contact_complete",
        EventSyncStatus::WorkRemained => "work_remained",
        EventSyncStatus::PolicyChangedSinceContact => "policy_changed_since_contact",
    }
}

fn contact_name(contact: ContactSyncStatus) -> &'static str {
    match contact {
        ContactSyncStatus::CompleteForLastNegotiatedContact => {
            "complete_for_last_negotiated_contact"
        }
        ContactSyncStatus::WorkRemained => "work_remained",
        ContactSyncStatus::PolicyChangedSinceContact => "policy_changed_since_contact",
    }
}

fn authorization_name(authorization: PeerAuthorization) -> &'static str {
    match authorization {
        PeerAuthorization::Active => "active",
        PeerAuthorization::Revoked => "revoked",
    }
}

fn priority_name(priority: Priority) -> &'static str {
    match priority {
        Priority::Routine => "routine",
        Priority::Priority => "priority",
        Priority::Immediate => "immediate",
        Priority::Flash => "flash",
    }
}

fn acknowledgement_name(acknowledgement: EventAcknowledgement) -> &'static str {
    match acknowledgement {
        EventAcknowledgement::Acknowledged => "acknowledged",
        EventAcknowledgement::AlreadyAcknowledged => "already_acknowledged",
    }
}

fn unsubscribe_name(unsubscribe: EventUnsubscribe) -> &'static str {
    match unsubscribe {
        EventUnsubscribe::Removed => "removed",
        EventUnsubscribe::AlreadyAbsent => "already_absent",
    }
}

fn sha256_hex(bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    let mut output = String::with_capacity(digest.len() * 2);
    for byte in digest {
        use fmt::Write as _;
        let _ = write!(output, "{byte:02x}");
    }
    output
}

#[allow(clippy::too_many_arguments)]
fn emit_transcript(
    publisher: &Participant,
    receiver: &Participant,
    first: &EventPublishResult,
    first_retry: &EventPublishResult,
    second: &EventPublishResult,
    third: &EventPublishResult,
    beta: &EventPublishResult,
    peerless_query: &EventQueryPage,
    peerless_beta_query: &EventQueryPage,
    peerless_status: &SelectedEventStatus,
    peerless_receipt: &NodeReceipt,
    awaiting: &ChildFields,
    attempt_one: &ChildFields,
    threshold_status: &SelectedEventStatus,
    threshold_receipt: &NodeReceipt,
    attempt_two: &ChildFields,
    normal_subscription: EventSubscription,
    before_normal: &SelectedEventStatus,
    after_normal: &SelectedEventStatus,
    beta_subscription: EventSubscription,
    policy_changed: &SelectedEventStatus,
    beta_removed: EventUnsubscribe,
    beta_removed_again: EventUnsubscribe,
    second_delivery: &EventDelivery,
    second_ack: EventAcknowledgement,
    second_reack: EventAcknowledgement,
    normal_query: &EventQueryPage,
    normal_beta_query: &EventQueryPage,
    normal_publisher_receipt: &NodeReceipt,
    normal_receiver_receipt: &NodeReceipt,
    final_subscription: EventSubscription,
    final_status: &SelectedEventStatus,
    final_query: &EventQueryPage,
    final_beta_query: &EventQueryPage,
    final_receipt: &NodeReceipt,
) {
    emit(
        "RUN",
        &[
            ("schema", TRANSCRIPT_SCHEMA.to_owned()),
            ("claim", CLAIM.to_owned()),
            ("participants", "2".to_owned()),
            ("actor_lifetimes", "7".to_owned()),
            ("maximum_concurrent_actors", "2".to_owned()),
            ("topic", TOPIC.to_owned()),
            ("beta_topic", BETA_TOPIC.to_owned()),
            ("scope", SCOPE.to_owned()),
            ("stream_events", "3".to_owned()),
            ("authorized_unsubscribed_events", "1".to_owned()),
            ("publication_model", "numbered-v1".to_owned()),
        ],
    );
    emit_participant(publisher);
    emit_participant(receiver);
    emit_peer_binding(publisher, receiver);
    emit_peer_binding(receiver, publisher);

    emit_phase(1, "peerless_publish", "publisher", "published");
    emit_handle("peerless_publish", publisher);
    emit_publication("peerless_publish", "alpha", first, FIRST_PAYLOAD);
    emit(
        "EVENT_RETRY",
        &[
            ("phase", "peerless_publish".to_owned()),
            ("participant", "publisher".to_owned()),
            ("id", first_retry.id.to_string()),
            ("publisher", format_node_id(first_retry.publisher)),
            (
                "publisher_counter",
                first_retry.publisher_counter.to_string(),
            ),
            ("event_sequence", first_retry.event_sequence.to_string()),
            ("inserted", first_retry.inserted.to_string()),
            ("exact_match", (first_retry.id == first.id).to_string()),
        ],
    );
    emit(
        "OPERATION_CONFLICT",
        &[
            ("phase", "peerless_publish".to_owned()),
            ("participant", "publisher".to_owned()),
            ("original_id", first.id.to_string()),
            ("original_payload_sha256", sha256_hex(FIRST_PAYLOAD)),
            ("changed_payload_sha256", sha256_hex(CHANGED_FIRST_PAYLOAD)),
            ("error_kind", "conflict".to_owned()),
            ("operation", "publish_numbered".to_owned()),
            ("sanitized", "true".to_owned()),
            ("publication_preserved", "true".to_owned()),
        ],
    );
    emit_publication("peerless_publish", "alpha", second, SECOND_PAYLOAD);
    emit_publication("peerless_publish", "alpha", third, THIRD_PAYLOAD);
    emit_publication("peerless_publish", "beta", beta, BETA_PAYLOAD);
    emit_query("peerless_publish", "publisher", "alpha", peerless_query);
    emit_query("peerless_publish", "publisher", "beta", peerless_beta_query);
    emit_status("peerless_publish", "publisher", peerless_status);
    emit_shutdown("peerless_publish", "publisher", peerless_receipt);
    emit_closed_handle("peerless_publish", "publisher");

    emit_phase(
        2,
        "threshold_delivery",
        "publisher+receiver",
        "receiver-force-terminated",
    );
    emit_handle("threshold_delivery", publisher);
    emit_child_handle("threshold_delivery", receiver, awaiting);
    emit_subscription_from_child("threshold_delivery", "receiver", awaiting, true);
    emit_status_from_child(
        "threshold_delivery",
        "receiver",
        "before_publisher_start",
        awaiting,
    );
    emit_status("threshold_delivery", "publisher", threshold_status);
    emit_gap_from_child("threshold_delivery", "receiver", attempt_one, "open");
    emit_child_delivery("threshold_delivery", attempt_one, "first", "alpha", 1);
    emit_child_delivery("threshold_delivery", attempt_one, "third", "alpha", 1);
    emit(
        "PROCESS_TERMINATION",
        &[
            ("phase", "threshold_delivery".to_owned()),
            ("participant", "receiver".to_owned()),
            ("mechanism", "parent_child_kill".to_owned()),
            ("after_flushed_poll", "true".to_owned()),
            ("graceful", "false".to_owned()),
            ("stop_record_expected", "false".to_owned()),
            ("acknowledged", "false".to_owned()),
        ],
    );
    emit_shutdown("threshold_delivery", "publisher", threshold_receipt);
    emit_closed_handle("threshold_delivery", "publisher");

    emit_phase(3, "peerless_redelivery", "receiver", "acknowledged");
    emit_child_handle("peerless_redelivery", receiver, attempt_two);
    emit_subscription_from_child("peerless_redelivery", "receiver", attempt_two, false);
    emit_status_from_child(
        "peerless_redelivery",
        "receiver",
        "peerless_reopen",
        attempt_two,
    );
    emit_gap_from_child("peerless_redelivery", "receiver", attempt_two, "open");
    emit_child_delivery("peerless_redelivery", attempt_two, "first", "alpha", 2);
    emit_child_delivery("peerless_redelivery", attempt_two, "third", "alpha", 2);
    emit_child_ack(
        "peerless_redelivery",
        attempt_two,
        "first",
        "ACKNOWLEDGEMENT",
        "first_ack",
    );
    emit_child_ack(
        "peerless_redelivery",
        attempt_two,
        "first",
        "REACKNOWLEDGEMENT",
        "first_reack",
    );
    emit_child_ack(
        "peerless_redelivery",
        attempt_two,
        "third",
        "ACKNOWLEDGEMENT",
        "third_ack",
    );
    emit_child_ack(
        "peerless_redelivery",
        attempt_two,
        "third",
        "REACKNOWLEDGEMENT",
        "third_reack",
    );
    emit_empty_poll("peerless_redelivery", "receiver", "after_acknowledgement");
    emit_shutdown_from_child("peerless_redelivery", "receiver", attempt_two);
    emit_closed_handle("peerless_redelivery", "receiver");

    emit_phase(4, "normal_gap_closure", "publisher+receiver", "gap-closed");
    emit_handle("normal_gap_closure", receiver);
    emit_handle("normal_gap_closure", publisher);
    emit_subscription(
        "normal_gap_closure",
        "receiver",
        "alpha",
        normal_subscription,
    );
    emit_empty_poll("normal_gap_closure", "receiver", "before_normal_contact");
    emit_status("normal_gap_closure", "receiver", before_normal);
    emit_status("normal_gap_closure", "receiver", after_normal);
    emit_gap("normal_gap_closure", "receiver", "closed", 0, 0, 3, false);
    emit_delivery("normal_gap_closure", "receiver", "alpha", second_delivery);
    emit_ack(
        "normal_gap_closure",
        "receiver",
        second.id.to_string(),
        second_ack,
        "ACKNOWLEDGEMENT",
    );
    emit_ack(
        "normal_gap_closure",
        "receiver",
        second.id.to_string(),
        second_reack,
        "REACKNOWLEDGEMENT",
    );
    emit_empty_poll(
        "normal_gap_closure",
        "receiver",
        "after_gap_acknowledgement",
    );
    emit_query("normal_gap_closure", "receiver", "alpha", normal_query);
    emit_query("normal_gap_closure", "receiver", "beta", normal_beta_query);
    emit_subscription("normal_gap_closure", "receiver", "beta", beta_subscription);
    emit_status("normal_gap_closure", "receiver", policy_changed);
    emit_unsubscribe(
        "normal_gap_closure",
        beta_subscription,
        beta_removed,
        "UNSUBSCRIBE",
    );
    emit_unsubscribe(
        "normal_gap_closure",
        beta_subscription,
        beta_removed_again,
        "REUNSUBSCRIBE",
    );
    emit_shutdown("normal_gap_closure", "publisher", normal_publisher_receipt);
    emit_shutdown("normal_gap_closure", "receiver", normal_receiver_receipt);
    emit_closed_handle("normal_gap_closure", "publisher");
    emit_closed_handle("normal_gap_closure", "receiver");

    emit_phase(5, "final_peerless_reopen", "receiver", "durable-empty");
    emit_handle("final_peerless_reopen", receiver);
    emit_subscription(
        "final_peerless_reopen",
        "receiver",
        "alpha",
        final_subscription,
    );
    emit_status("final_peerless_reopen", "receiver", final_status);
    emit_gap(
        "final_peerless_reopen",
        "receiver",
        "closed",
        0,
        0,
        3,
        false,
    );
    emit_empty_poll("final_peerless_reopen", "receiver", "final_reopen");
    emit_query("final_peerless_reopen", "receiver", "alpha", final_query);
    emit_query(
        "final_peerless_reopen",
        "receiver",
        "beta",
        final_beta_query,
    );
    emit_shutdown("final_peerless_reopen", "receiver", final_receipt);
    emit_closed_handle("final_peerless_reopen", "receiver");
    emit_bind("publisher");
    emit_bind("receiver");
    emit(
        "RESULT",
        &[
            ("status", "pass".to_owned()),
            ("records", TRANSCRIPT_RECORDS.to_string()),
            ("phases", "5".to_owned()),
            ("actor_lifetimes", "7".to_owned()),
            ("maximum_concurrent_actors", "2".to_owned()),
            ("graceful_shutdowns", "6".to_owned()),
            ("forced_process_terminations", "1".to_owned()),
            ("retained_handles", "6".to_owned()),
            ("closed_handles", "6".to_owned()),
            ("bind_reacquisitions", "2".to_owned()),
            ("secret_values_emitted", "false".to_owned()),
            ("payload_representation", "sha256_only".to_owned()),
            ("physical_network_claimed", "false".to_owned()),
            ("global_convergence_claimed", "false".to_owned()),
        ],
    );
}

fn emit_participant(participant: &Participant) {
    emit(
        "PARTICIPANT",
        &[
            ("participant", participant.name.to_owned()),
            ("carrier_id", participant.carrier_id.to_string()),
            ("mission_id", format_node_id(participant.mission_id)),
            (
                "mission_authority",
                format_node_id(participant.mission_authority),
            ),
            ("provisioning", "independent_reference_bundle".to_owned()),
        ],
    );
}

fn emit_peer_binding(local: &Participant, remote: &Participant) {
    emit(
        "PEER_BINDING",
        &[
            ("local", local.name.to_owned()),
            ("remote", remote.name.to_owned()),
            ("local_carrier", local.carrier_id.to_string()),
            ("local_mission", format_node_id(local.mission_id)),
            ("remote_carrier", remote.carrier_id.to_string()),
            ("remote_mission", format_node_id(remote.mission_id)),
            ("mission_authenticated", "true".to_owned()),
        ],
    );
}

fn emit_phase(index: usize, phase: &str, actors: &str, outcome: &str) {
    emit(
        "PHASE",
        &[
            ("index", index.to_string()),
            ("phase", phase.to_owned()),
            ("actors", actors.to_owned()),
            ("outcome", outcome.to_owned()),
        ],
    );
}

fn emit_handle(phase: &str, participant: &Participant) {
    emit(
        "HANDLE",
        &[
            ("phase", phase.to_owned()),
            ("participant", participant.name.to_owned()),
            ("event_identity", format_node_id(participant.mission_id)),
            (
                "event_authority",
                format_node_id(participant.mission_authority),
            ),
        ],
    );
}

fn emit_child_handle(phase: &str, participant: &Participant, _fields: &ChildFields) {
    emit_handle(phase, participant);
}

fn emit_publication(phase: &str, stream: &str, publication: &EventPublishResult, payload: &[u8]) {
    emit(
        "EVENT",
        &[
            ("phase", phase.to_owned()),
            ("participant", "publisher".to_owned()),
            ("stream", stream.to_owned()),
            ("id", publication.id.to_string()),
            ("publisher", format_node_id(publication.publisher)),
            (
                "publisher_counter",
                publication.publisher_counter.to_string(),
            ),
            ("event_sequence", publication.event_sequence.to_string()),
            ("priority", priority_name(publication.priority).to_owned()),
            ("ttl", "durable".to_owned()),
            (
                "acceptance_marker",
                publication.acceptance_marker.to_string(),
            ),
            ("inserted", publication.inserted.to_string()),
            ("payload_sha256", sha256_hex(payload)),
        ],
    );
}

fn emit_query(phase: &str, participant: &str, stream: &str, page: &EventQueryPage) {
    emit(
        "QUERY",
        &[
            ("phase", phase.to_owned()),
            ("participant", participant.to_owned()),
            ("stream", stream.to_owned()),
            ("items", page.items.len().to_string()),
            ("scanned_through", page.scanned_through.to_string()),
            ("has_more", page.has_more.to_string()),
            ("limit", "8".to_owned()),
        ],
    );
}

fn emit_status(phase: &str, participant: &str, status: &SelectedEventStatus) {
    let peer = status.peers.first();
    emit(
        "STATUS",
        &[
            ("phase", phase.to_owned()),
            ("participant", participant.to_owned()),
            ("sync", sync_name(status.sync).to_owned()),
            (
                "authenticated_contacts",
                status.authenticated_contacts.to_string(),
            ),
            (
                "failed_contact_attempts",
                status.failed_contact_attempts.to_string(),
            ),
            ("peers", status.peers.len().to_string()),
            (
                "peer",
                peer.map_or_else(|| "none".to_owned(), |peer| format_node_id(peer.peer)),
            ),
            (
                "peer_contacts",
                peer.map_or(0, |peer| peer.contacts).to_string(),
            ),
            (
                "peer_authorization",
                peer.map_or("none", |peer| authorization_name(peer.authorization))
                    .to_owned(),
            ),
            (
                "peer_last_contact",
                peer.map_or("none", |peer| contact_name(peer.last_contact))
                    .to_owned(),
            ),
        ],
    );
}

fn emit_status_from_child(phase: &str, participant: &str, observation: &str, fields: &ChildFields) {
    emit(
        "STATUS",
        &[
            ("phase", phase.to_owned()),
            ("participant", participant.to_owned()),
            ("observation", observation.to_owned()),
            ("sync", fields["sync"].clone()),
            (
                "authenticated_contacts",
                fields["authenticated_contacts"].clone(),
            ),
            (
                "failed_contact_attempts",
                fields["failed_contact_attempts"].clone(),
            ),
            (
                "peers",
                fields
                    .get("peers")
                    .cloned()
                    .unwrap_or_else(|| "1".to_owned()),
            ),
            (
                "peer",
                fields
                    .get("peer")
                    .cloned()
                    .unwrap_or_else(|| "none".to_owned()),
            ),
            (
                "peer_contacts",
                fields
                    .get("peer_contacts")
                    .cloned()
                    .unwrap_or_else(|| "0".to_owned()),
            ),
            (
                "peer_authorization",
                fields
                    .get("peer_authorization")
                    .cloned()
                    .unwrap_or_else(|| "none".to_owned()),
            ),
            (
                "peer_last_contact",
                fields
                    .get("peer_last_contact")
                    .cloned()
                    .unwrap_or_else(|| "none".to_owned()),
            ),
        ],
    );
}

fn emit_subscription(
    phase: &str,
    participant: &str,
    stream: &str,
    subscription: EventSubscription,
) {
    emit(
        "SUBSCRIPTION",
        &[
            ("phase", phase.to_owned()),
            ("participant", participant.to_owned()),
            ("stream", stream.to_owned()),
            ("id", subscription.id.to_string()),
            ("inserted", subscription.inserted.to_string()),
            ("durable", "true".to_owned()),
            ("include_descendant_scopes", "false".to_owned()),
        ],
    );
}

fn emit_subscription_from_child(
    phase: &str,
    participant: &str,
    fields: &ChildFields,
    inserted: bool,
) {
    emit(
        "SUBSCRIPTION",
        &[
            ("phase", phase.to_owned()),
            ("participant", participant.to_owned()),
            ("stream", "alpha".to_owned()),
            ("id", fields["subscription_id"].clone()),
            ("inserted", inserted.to_string()),
            ("durable", "true".to_owned()),
            ("include_descendant_scopes", "false".to_owned()),
        ],
    );
}

fn emit_gap(
    phase: &str,
    participant: &str,
    disposition: &str,
    start: u64,
    end: u64,
    scanned: u64,
    has_more: bool,
) {
    emit(
        "GAP",
        &[
            ("phase", phase.to_owned()),
            ("participant", participant.to_owned()),
            ("stream", "alpha".to_owned()),
            ("disposition", disposition.to_owned()),
            ("start_sequence", start.to_string()),
            ("end_sequence", end.to_string()),
            ("scanned_through_sequence", scanned.to_string()),
            ("has_more", has_more.to_string()),
            ("authenticated", "true".to_owned()),
        ],
    );
}

fn emit_gap_from_child(phase: &str, participant: &str, fields: &ChildFields, disposition: &str) {
    emit_gap(
        phase,
        participant,
        disposition,
        fields["gap_start"].parse().unwrap_or(0),
        fields["gap_end"].parse().unwrap_or(0),
        fields["gap_scanned_through"].parse().unwrap_or(0),
        fields["gap_has_more"] == "true",
    );
}

fn emit_child_delivery(
    phase: &str,
    fields: &ChildFields,
    prefix: &str,
    stream: &str,
    attempt: u64,
) {
    emit(
        "DELIVERY",
        &[
            ("phase", phase.to_owned()),
            ("participant", "receiver".to_owned()),
            ("stream", stream.to_owned()),
            ("id", fields[&format!("{prefix}_id")].clone()),
            (
                "event_sequence",
                fields[&format!("{prefix}_sequence")].clone(),
            ),
            ("priority", fields[&format!("{prefix}_priority")].clone()),
            ("attempt", attempt.to_string()),
            (
                "payload_sha256",
                fields[&format!("{prefix}_payload_sha256")].clone(),
            ),
        ],
    );
}

fn emit_delivery(phase: &str, participant: &str, stream: &str, delivery: &EventDelivery) {
    emit(
        "DELIVERY",
        &[
            ("phase", phase.to_owned()),
            ("participant", participant.to_owned()),
            ("stream", stream.to_owned()),
            ("id", delivery.event.id.to_string()),
            ("event_sequence", delivery.event.event_sequence.to_string()),
            (
                "priority",
                priority_name(delivery.event.priority).to_owned(),
            ),
            ("attempt", delivery.attempt.to_string()),
            ("payload_sha256", sha256_hex(&delivery.event.payload)),
        ],
    );
}

fn emit_child_ack(phase: &str, fields: &ChildFields, prefix: &str, kind: &str, key: &str) {
    emit(
        kind,
        &[
            ("phase", phase.to_owned()),
            ("participant", "receiver".to_owned()),
            ("id", fields[&format!("{prefix}_id")].clone()),
            ("disposition", fields[key].clone()),
        ],
    );
}

fn emit_ack(
    phase: &str,
    participant: &str,
    id: String,
    acknowledgement: EventAcknowledgement,
    kind: &str,
) {
    emit(
        kind,
        &[
            ("phase", phase.to_owned()),
            ("participant", participant.to_owned()),
            ("id", id),
            (
                "disposition",
                acknowledgement_name(acknowledgement).to_owned(),
            ),
        ],
    );
}

fn emit_empty_poll(phase: &str, participant: &str, observation: &str) {
    emit(
        "EMPTY_POLL",
        &[
            ("phase", phase.to_owned()),
            ("participant", participant.to_owned()),
            ("observation", observation.to_owned()),
            ("deliveries", "0".to_owned()),
            ("has_more", "false".to_owned()),
            ("delivery_limit", "8".to_owned()),
            ("scan_limit", "8".to_owned()),
        ],
    );
}

fn emit_unsubscribe(
    phase: &str,
    subscription: EventSubscription,
    disposition: EventUnsubscribe,
    kind: &str,
) {
    emit(
        kind,
        &[
            ("phase", phase.to_owned()),
            ("participant", "receiver".to_owned()),
            ("stream", "beta".to_owned()),
            ("subscription_id", subscription.id.to_string()),
            ("disposition", unsubscribe_name(disposition).to_owned()),
        ],
    );
}

fn emit_shutdown(phase: &str, participant: &str, receipt: &NodeReceipt) {
    let mut fields = vec![
        ("phase", phase.to_owned()),
        ("participant", participant.to_owned()),
    ];
    fields.extend(unprefixed_receipt_fields(receipt));
    emit("SHUTDOWN", &fields);
}

fn unprefixed_receipt_fields(receipt: &NodeReceipt) -> Vec<(&'static str, String)> {
    prefixed_receipt_fields(receipt)
        .into_iter()
        .map(|(key, value)| (&key[9..], value))
        .map(|(key, value)| {
            let key = match key {
                "contacts" => "contacts",
                "contact_errors" => "contact_errors",
                "direct_contacts" => "direct_contacts",
                "relay_contacts" => "relay_contacts",
                "unknown_path_contacts" => "unknown_path_contacts",
                "carrier_path_transitions" => "carrier_path_transitions",
                "carrier_path_transition_saturations" => "carrier_path_transition_saturations",
                "items" => "items",
                "acceptance_markers" => "acceptance_markers",
                "events" => "events",
                "event_acceptance_markers" => "event_acceptance_markers",
                "route_cached_events" => "route_cached_events",
                "controls" => "controls",
                "applied_controls" => "applied_controls",
                "pending_controls" => "pending_controls",
                "control_highwater" => "control_highwater",
                "data_offered" => "data_offered",
                "data_fetched" => "data_fetched",
                "data_inserted" => "data_inserted",
                "data_duplicates" => "data_duplicates",
                "data_remaining" => "data_remaining",
                "mutable_remaining" => "mutable_remaining",
                "deferred_mutable_lanes" => "deferred_mutable_lanes",
                "blob_ranges_fetched" => "blob_ranges_fetched",
                "blob_bytes_fetched" => "blob_bytes_fetched",
                "blob_remaining" => "blob_remaining",
                "blob_deferred" => "blob_deferred",
                "blobs" => "blobs",
                "blob_acceptance_markers" => "blob_acceptance_markers",
                "blob_last_acceptance_marker" => "blob_last_acceptance_marker",
                "blob_sealed_bytes" => "blob_sealed_bytes",
                "blob_operations" => "blob_operations",
                "blob_operation_bytes" => "blob_operation_bytes",
                "blob_variants" => "blob_variants",
                "blob_finalized_variants" => "blob_finalized_variants",
                "blob_committed_chunks" => "blob_committed_chunks",
                "blob_committed_file_bytes" => "blob_committed_file_bytes",
                "blob_reserved_file_bytes" => "blob_reserved_file_bytes",
                "pending_blobs" => "pending_blobs",
                "blob_carrier_prefixes" => "blob_carrier_prefixes",
                "blob_carrier_fetch_cursors" => "blob_carrier_fetch_cursors",
                "blob_network_staging_bytes" => "blob_network_staging_bytes",
                _ => unreachable!(),
            };
            (key, value)
        })
        .collect()
}

fn emit_shutdown_from_child(phase: &str, participant: &str, fields: &ChildFields) {
    let mut output = vec![
        ("phase", phase.to_owned()),
        ("participant", participant.to_owned()),
    ];
    for (key, _) in prefixed_receipt_fields(&NodeReceipt::default()) {
        output.push((
            &key[9..],
            fields[&format!("shutdown_{}", &key[9..])].clone(),
        ));
    }
    emit("SHUTDOWN", &output);
}

fn emit_closed_handle(phase: &str, participant: &str) {
    emit(
        "CLOSED_HANDLE",
        &[
            ("phase", phase.to_owned()),
            ("participant", participant.to_owned()),
            ("error_kind", "state_unavailable".to_owned()),
            ("operation", "status".to_owned()),
        ],
    );
}

fn emit_bind(participant: &str) {
    emit(
        "BIND_REACQUIRED",
        &[
            ("participant", participant.to_owned()),
            ("status", "reacquired".to_owned()),
        ],
    );
}

fn emit(record: &str, fields: &[(&str, String)]) {
    print!("LIVE_EVENT\t{record}");
    for (key, value) in fields {
        print!("\t{key}={value}");
    }
    println!();
}
