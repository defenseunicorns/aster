//! Retained one-host acceptance producer for durable selected State delivery.
//!
//! The public `LIVE_STATE_SUBSCRIPTION` transcript contains bounded application
//! metadata and payload digests only. Runtime `READY`/`CONTACT`/`STOP` records
//! and the narrowly scoped child coordination lines remain in stdout so an
//! independent checker can bind one forced receiver-process termination to a
//! flushed, unacknowledged State delivery attempt.

use std::{
    collections::{BTreeMap, BTreeSet},
    env,
    error::Error,
    ffi::OsString,
    fmt, fs,
    io::{BufRead as _, BufReader, Read as _, Write as _},
    net::{SocketAddr, UdpSocket},
    path::{Path, PathBuf},
    process::{Child, Command, Stdio},
    time::Duration,
};

use aster_iroh::{EndpointId, ExpectedPeer};
use aster_mesh::{ProvisioningAccess, ReferenceProvisioner};
use aster_node::{
    MissionExpectedPeer, MutableSourceInterests, NodeApplication, NodeConfig, NodeIdentity,
    NodeReceipt, SourceInterestSelector,
    application::{
        ApplicationError, ApplicationErrorKind, Priority, STATE_DELIVERY_TOKEN_BYTES, Scope,
        SelectedStateHandle, StateAcknowledgement, StateDelivery, StateDeliveryToken, StateId,
        StateItem, StatePollRequest, StateProjection, StatePublishRequest, StatePublishResult,
        StateQuery, StateSubscription, StateSubscriptionId, StateSubscriptionRequest,
        StateVersionDisposition, Topic,
    },
    format_node_id,
    mission::UnprotectedReferenceMission,
    start_node,
};
use aster_redb_store::{StateSubscriptionStats, Store, StoreInspection};
use sha2::{Digest as _, Sha256};
use tokio::{
    sync::mpsc::UnboundedReceiver,
    time::{sleep, timeout},
};
use zeroize::Zeroize as _;

const TRANSCRIPT_SCHEMA: &str = "aster-selected-live-state-subscription-transcript/v1";
const CLAIM: &str = "selected-live-state-subscription-one-host-direct-iroh-positive-current-version-selector-withholding-forced-receiver-process-termination-durable-redelivery-tombstone-acceptance";
const ALPHA_TOPIC: &str = "opaque";
const BETA_TOPIC: &str = "opaque.beta";
const GAMMA_TOPIC: &str = "opaque.gamma";
const SCOPE: &str = "test/runtime-contact";
const ALPHA_KEY: &[u8] = b"acceptance/state/alpha-key";
const BETA_KEY: &[u8] = b"acceptance/state/beta-key";
const GAMMA_KEY: &[u8] = b"acceptance/state/gamma-key";
const LEFT_PAYLOAD: &[u8] = b"left State";
const RIGHT_PAYLOAD: &[u8] = b"right State";
const SUCCESSOR_PAYLOAD: &[u8] = b"joined State";
const BETA_PAYLOAD: &[u8] = b"network-interested application-unsubscribed State";
const GAMMA_PAYLOAD: &[u8] = b"authorized network-uninterested State";
const TOMBSTONE_PAYLOAD: &[u8] = b"";
const LEFT_OPERATION: &[u8] = b"acceptance/state/left";
const RIGHT_OPERATION: &[u8] = b"acceptance/state/right";
const SUCCESSOR_OPERATION: &[u8] = b"acceptance/state/successor";
const BETA_OPERATION: &[u8] = b"acceptance/state/beta";
const GAMMA_OPERATION: &[u8] = b"acceptance/state/gamma";
const TOMBSTONE_OPERATION: &[u8] = b"acceptance/state/tombstone";
const SUBSCRIPTION_OPERATION: &[u8] = b"acceptance/state/subscription";
const POLL_DEADLINE: Duration = Duration::from_secs(40);
const SYNC_INTERVAL: Duration = Duration::from_secs(5);
const TRANSCRIPT_RECORDS: usize = 70;

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

struct ChildActor {
    child: Child,
    lines: UnboundedReceiver<Result<String, std::io::Error>>,
    saw_runtime_stop: bool,
}

struct AttemptArtifacts {
    retry_token: PathBuf,
    retired_origin_token: PathBuf,
}

struct ReceiptEvidence {
    phase: &'static str,
    participant: &'static str,
    receipt: NodeReceipt,
}

struct AcceptanceEvidence {
    subscription: StateSubscription,
    left: StatePublishResult,
    right: StatePublishResult,
    successor: StatePublishResult,
    beta: StatePublishResult,
    gamma: StatePublishResult,
    tombstone: StatePublishResult,
    initial_delivery: StateDelivery,
    tombstone_delivery: StateDelivery,
    initial_projections: [StateProjection; 2],
    concurrent_projections: [StateProjection; 2],
    successor_projections: [StateProjection; 2],
    tombstone_local_projection: StateProjection,
    tombstone_network_projections: [StateProjection; 2],
    final_projection: StateProjection,
    attempt_one: ChildFields,
    attempt_two: ChildFields,
    tombstone_ack: StateAcknowledgement,
    tombstone_reack: StateAcknowledgement,
    receipts: Vec<ReceiptEvidence>,
    inspections: [StoreInspection; 2],
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
            eprintln!("LIVE_STATE_SUBSCRIPTION_CHILD_FAILURE status=error stage={stage}");
        } else {
            eprintln!("LIVE_STATE_SUBSCRIPTION_FAILURE status=error stage={stage}");
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
    let alpha = Topic::new(ALPHA_TOPIC)?;
    let beta_topic = Topic::new(BETA_TOPIC)?;
    let gamma_topic = Topic::new(GAMMA_TOPIC)?;
    let scope = Scope::new(SCOPE)?;
    let alpha_query = state_query(&alpha, &scope, ALPHA_KEY);
    let beta_query = state_query(&beta_topic, &scope, BETA_KEY);
    let gamma_query = state_query(&gamma_topic, &scope, GAMMA_KEY);
    let participants_root = raw_root.join("participants");
    create_owner_directory(&participants_root)?;
    let [publisher, mut receiver] = provision_participants(
        &participants_root,
        [&alpha, &beta_topic, &gamma_topic],
        &scope,
    )?;
    validate_participant_domains(&publisher, &receiver)?;

    // Phase 1: two disconnected origins and one deliberately unacknowledged
    // current projection on the receiver.
    let publisher_peerless = start_peerless(&publisher).await?;
    let receiver_peerless = start_peerless(&receiver).await?;
    let publisher_states = publisher_peerless.selected_state();
    let receiver_states = receiver_peerless.selected_state();
    validate_handle(&publisher, &publisher_states)?;
    validate_handle(&receiver, &receiver_states)?;
    let subscription = receiver_states
        .subscribe(subscription_request(&alpha, &scope))
        .await?;
    require(
        subscription.inserted,
        "initial State subscription insertion",
    )?;
    let subscription_retry = receiver_states
        .subscribe(subscription_request(&alpha, &scope))
        .await?;
    require(
        !subscription_retry.inserted && subscription_retry.id == subscription.id,
        "initial State subscription replay",
    )?;
    let left = publisher_states
        .publish(state_request(
            LEFT_OPERATION,
            &alpha,
            &scope,
            ALPHA_KEY,
            LEFT_PAYLOAD,
            false,
        ))
        .await?;
    let right = receiver_states
        .publish(state_request(
            RIGHT_OPERATION,
            &alpha,
            &scope,
            ALPHA_KEY,
            RIGHT_PAYLOAD,
            false,
        ))
        .await?;
    validate_publication(&left, &publisher, 1, true)?;
    validate_publication(&right, &receiver, 1, true)?;
    require(left.id != right.id, "distinct State origin identities")?;
    let initial_page = poll(&receiver_states, subscription).await?;
    require(
        initial_page.deliveries.len() == 1 && !initial_page.has_more,
        "initial State delivery count",
    )?;
    let initial_delivery = initial_page.deliveries[0].clone();
    validate_delivery(
        &initial_delivery,
        right.id,
        receiver.mission_id,
        RIGHT_PAYLOAD,
        false,
        1,
    )?;
    let initial_projections = [
        publisher_states.query(alpha_query.clone()).await?,
        receiver_states.query(alpha_query.clone()).await?,
    ];
    validate_single_projection(&initial_projections[0], left.id, LEFT_PAYLOAD, false)?;
    validate_single_projection(&initial_projections[1], right.id, RIGHT_PAYLOAD, false)?;
    let retained_publisher_peerless = publisher_states.clone();
    let retained_receiver_peerless = receiver_states.clone();
    let (publisher_peerless_receipt, receiver_peerless_receipt) =
        tokio::join!(publisher_peerless.shutdown(), receiver_peerless.shutdown());
    let publisher_peerless_receipt = publisher_peerless_receipt?;
    let receiver_peerless_receipt = receiver_peerless_receipt?;
    validate_peerless_receipt(&publisher_peerless_receipt)?;
    validate_peerless_receipt(&receiver_peerless_receipt)?;
    validate_closed_handle(&retained_publisher_peerless, alpha_query.clone()).await?;
    validate_closed_handle(&retained_receiver_peerless, alpha_query.clone()).await?;
    drop((
        publisher_states,
        receiver_states,
        retained_publisher_peerless,
        retained_receiver_peerless,
    ));

    let publisher_reservation = UdpSocket::bind(("127.0.0.1", 0))?;
    let receiver_reservation = UdpSocket::bind(("127.0.0.1", 0))?;
    let publisher_address = publisher_reservation.local_addr()?;
    let receiver_address = receiver_reservation.local_addr()?;
    require(
        publisher_address != receiver_address,
        "distinct State acceptance binds",
    )?;
    drop((publisher_reservation, receiver_reservation));

    // Phase 2: static network interests converge the origins, then carry a
    // causally later alpha successor and beta while excluding gamma.
    let interests = configured_state_interests(&alpha, &beta_topic, &scope);
    let (publisher_connected, receiver_connected) = start_pair(
        &publisher,
        publisher_address,
        &receiver,
        receiver_address,
        interests.clone(),
    )
    .await?;
    let publisher_connected_states = publisher_connected.selected_state();
    let receiver_connected_states = receiver_connected.selected_state();
    let publisher_contact_status = publisher_connected.selected_events();
    let receiver_contact_status = receiver_connected.selected_events();
    validate_handle(&publisher, &publisher_connected_states)?;
    validate_handle(&receiver, &receiver_connected_states)?;
    let connected_subscription = receiver_connected_states
        .subscribe(subscription_request(&alpha, &scope))
        .await?;
    require(
        !connected_subscription.inserted && connected_subscription.id == subscription.id,
        "connected State subscription replay",
    )?;
    let origin_ids = sorted_state_ids(left.id, right.id);
    let concurrent_projections = wait_for_pair_projections(
        &publisher_connected_states,
        &receiver_connected_states,
        &alpha_query,
        |projection| concurrent_projection_ready(projection, origin_ids),
        "concurrent State projection deadline",
    )
    .await?;
    validate_concurrent_projection(
        &concurrent_projections[0],
        &left,
        &right,
        LEFT_PAYLOAD,
        RIGHT_PAYLOAD,
    )?;
    require(
        equivalent_state_projections(&concurrent_projections[0], &concurrent_projections[1]),
        "identical concurrent State projections",
    )?;
    let initial_contact = wait_for_contact_advance(
        &publisher_contact_status,
        &receiver_contact_status,
        [0, 0],
        "initial State contact deadline",
    )
    .await?;

    let successor = publish_state_eventually(
        &publisher_connected_states,
        state_request(
            SUCCESSOR_OPERATION,
            &alpha,
            &scope,
            ALPHA_KEY,
            SUCCESSOR_PAYLOAD,
            false,
        ),
        "State successor publication deadline",
    )
    .await?;
    validate_publication(&successor, &publisher, 2, true)?;
    require(
        !origin_ids.contains(&successor.id),
        "distinct State successor identity",
    )?;
    let successor_projections = wait_for_pair_projections(
        &publisher_connected_states,
        &receiver_connected_states,
        &alpha_query,
        |projection| causal_projection_ready(projection, successor.id, &origin_ids),
        "State successor convergence deadline",
    )
    .await?;
    validate_causal_projection(
        &successor_projections[0],
        successor.id,
        SUCCESSOR_PAYLOAD,
        false,
        &origin_ids,
    )?;
    require(
        equivalent_state_projections(&successor_projections[0], &successor_projections[1]),
        "identical State successor projections",
    )?;
    let successor_contact = wait_for_contact_advance(
        &publisher_contact_status,
        &receiver_contact_status,
        initial_contact,
        "State successor contact deadline",
    )
    .await?;
    let beta = publish_state_eventually(
        &publisher_connected_states,
        state_request(
            BETA_OPERATION,
            &beta_topic,
            &scope,
            BETA_KEY,
            BETA_PAYLOAD,
            false,
        ),
        "beta State publication deadline",
    )
    .await?;
    validate_publication(&beta, &publisher, 3, true)?;
    let receiver_beta = wait_for_projection(
        &receiver_connected_states,
        &beta_query,
        |projection| single_projection_ready(projection, beta.id),
        "beta State network-interest deadline",
    )
    .await?;
    validate_single_projection(&receiver_beta, beta.id, BETA_PAYLOAD, false)?;
    let beta_contact = wait_for_contact_advance(
        &publisher_contact_status,
        &receiver_contact_status,
        successor_contact,
        "beta State contact deadline",
    )
    .await?;

    let gamma = publish_state_eventually(
        &publisher_connected_states,
        state_request(
            GAMMA_OPERATION,
            &gamma_topic,
            &scope,
            GAMMA_KEY,
            GAMMA_PAYLOAD,
            false,
        ),
        "gamma State publication deadline",
    )
    .await?;
    validate_publication(&gamma, &publisher, 4, true)?;
    let publisher_gamma = query_state_eventually(
        &publisher_connected_states,
        gamma_query.clone(),
        "publisher gamma State query deadline",
    )
    .await?;
    validate_single_projection(&publisher_gamma, gamma.id, GAMMA_PAYLOAD, false)?;
    let _gamma_contact = wait_for_contact_advance(
        &publisher_contact_status,
        &receiver_contact_status,
        beta_contact,
        "gamma withholding contact deadline",
    )
    .await?;
    let receiver_gamma = query_state_eventually(
        &receiver_connected_states,
        gamma_query.clone(),
        "receiver gamma State query deadline",
    )
    .await?;
    require(
        receiver_gamma.current.is_none() && receiver_gamma.recoverable.is_empty(),
        "gamma State crossed configured network interest",
    )?;
    let retained_publisher_connected = publisher_connected_states.clone();
    let retained_receiver_connected = receiver_connected_states.clone();
    let (publisher_connected_receipt, receiver_connected_receipt) = tokio::join!(
        publisher_connected.shutdown(),
        receiver_connected.shutdown()
    );
    let publisher_connected_receipt = publisher_connected_receipt?;
    let receiver_connected_receipt = receiver_connected_receipt?;
    validate_direct_receipt(&publisher_connected_receipt)?;
    validate_direct_receipt(&receiver_connected_receipt)?;
    validate_transfer_pair(&publisher_connected_receipt, &receiver_connected_receipt, 4)?;
    validate_closed_handle(&retained_publisher_connected, alpha_query.clone()).await?;
    validate_closed_handle(&retained_receiver_connected, alpha_query.clone()).await?;
    drop((
        publisher_connected_states,
        receiver_connected_states,
        publisher_contact_status,
        receiver_contact_status,
        retained_publisher_connected,
        retained_receiver_connected,
    ));

    // Release the receiver's process-lifetime artifact guard while independent
    // child processes own the exact receiver state and mission artifact.
    let receiver_mission = std::mem::replace(&mut receiver.mission, publisher.mission.clone());
    drop(receiver_mission);

    // Phase 3: a fresh peerless receiver process durably returns successor
    // attempt one, flushes its evidence, and is killed before acknowledgement.
    let attempt_artifacts = AttemptArtifacts {
        retry_token: receiver.root.join("attempt-one.state-token"),
        retired_origin_token: receiver.root.join("retired-origin.state-token"),
    };
    persist_delivery_token(
        &attempt_artifacts.retired_origin_token,
        initial_delivery.token,
    )?;
    let mut attempt_one = spawn_attempt_one(
        &receiver,
        &attempt_artifacts.retry_token,
        subscription.id,
        left.id,
        right.id,
        successor.id,
        beta.id,
    )?;
    let attempt_one_pid = attempt_one.child.id();
    let attempt_one_fields = wait_child_record(&mut attempt_one, "ATTEMPT1_READY").await?;
    validate_attempt_one(
        &attempt_one_fields,
        &receiver,
        subscription.id,
        left.id,
        right.id,
        successor.id,
        beta.id,
    )?;
    validate_token_artifact(
        &attempt_artifacts.retry_token,
        child_field(&attempt_one_fields, "successor_token_sha256")?,
    )?;
    attempt_one.child.kill()?;
    drain_child_lines(&mut attempt_one).await?;
    let killed_status = attempt_one.child.wait()?;
    validate_forced_child_termination(
        attempt_one_pid,
        killed_status,
        attempt_one.saw_runtime_stop,
    )?;

    // Phase 4: another process replays the same successor at attempt two and
    // leaves a durable acknowledgement receipt.
    let mut attempt_two = spawn_attempt_two(
        &receiver,
        &attempt_artifacts,
        subscription.id,
        left.id,
        right.id,
        successor.id,
        beta.id,
    )?;
    let attempt_two_fields = wait_child_record(&mut attempt_two, "ATTEMPT2_DONE").await?;
    drain_child_lines(&mut attempt_two).await?;
    let attempt_two_status = attempt_two.child.wait()?;
    require(
        attempt_two_status.success() && attempt_two.saw_runtime_stop,
        "receiver retry child failed",
    )?;
    validate_attempt_two(
        &attempt_two_fields,
        &receiver,
        subscription.id,
        successor.id,
        initial_delivery.token,
    )?;
    require(
        !attempt_artifacts.retry_token.exists() && !attempt_artifacts.retired_origin_token.exists(),
        "token artifact survived acknowledgement",
    )?;
    receiver.mission = UnprotectedReferenceMission::load(&receiver.mission_path)?;

    // Phase 5: an authenticated empty State remains an explicit current
    // projection and delivery, while acknowledged history stays causal input.
    let tombstone_running = start_peerless(&receiver).await?;
    let tombstone_states = tombstone_running.selected_state();
    let tombstone_subscription = tombstone_states
        .subscribe(subscription_request(&alpha, &scope))
        .await?;
    require(
        !tombstone_subscription.inserted && tombstone_subscription.id == subscription.id,
        "tombstone State subscription replay",
    )?;
    let pre_tombstone = tombstone_states.query(alpha_query.clone()).await?;
    validate_causal_projection(
        &pre_tombstone,
        successor.id,
        SUCCESSOR_PAYLOAD,
        false,
        &origin_ids,
    )?;
    let tombstone = tombstone_states
        .publish(state_request(
            TOMBSTONE_OPERATION,
            &alpha,
            &scope,
            ALPHA_KEY,
            TOMBSTONE_PAYLOAD,
            true,
        ))
        .await?;
    validate_publication(&tombstone, &receiver, 2, true)?;
    let tombstone_page = poll(&tombstone_states, subscription).await?;
    require(
        tombstone_page.deliveries.len() == 1 && !tombstone_page.has_more,
        "tombstone State delivery count",
    )?;
    let tombstone_delivery = tombstone_page.deliveries[0].clone();
    validate_delivery(
        &tombstone_delivery,
        tombstone.id,
        receiver.mission_id,
        TOMBSTONE_PAYLOAD,
        true,
        1,
    )?;
    let tombstone_ack = tombstone_states
        .acknowledge(subscription.id, tombstone.id, tombstone_delivery.token)
        .await?;
    let tombstone_reack = tombstone_states
        .acknowledge(subscription.id, tombstone.id, tombstone_delivery.token)
        .await?;
    require(
        tombstone_ack == StateAcknowledgement::Acknowledged
            && tombstone_reack == StateAcknowledgement::AlreadyAcknowledged,
        "tombstone State acknowledgements",
    )?;
    validate_empty_poll(&tombstone_states, subscription).await?;
    let pre_tombstone_ids = [left.id, right.id, successor.id];
    let tombstone_local_projection = tombstone_states.query(alpha_query.clone()).await?;
    validate_causal_projection(
        &tombstone_local_projection,
        tombstone.id,
        TOMBSTONE_PAYLOAD,
        true,
        &pre_tombstone_ids,
    )?;
    let retained_tombstone = tombstone_states.clone();
    let tombstone_receipt = tombstone_running.shutdown().await?;
    validate_peerless_receipt(&tombstone_receipt)?;
    validate_closed_handle(&retained_tombstone, alpha_query.clone()).await?;
    drop((tombstone_states, retained_tombstone));

    // Phase 6: the tombstone propagates in the opposite direction; the
    // acknowledged receiver subscription remains empty.
    let (publisher_tombstone_running, receiver_tombstone_running) = start_pair(
        &publisher,
        publisher_address,
        &receiver,
        receiver_address,
        interests,
    )
    .await?;
    let publisher_tombstone_states = publisher_tombstone_running.selected_state();
    let receiver_tombstone_states = receiver_tombstone_running.selected_state();
    let publisher_tombstone_status = publisher_tombstone_running.selected_events();
    let receiver_tombstone_status = receiver_tombstone_running.selected_events();
    let propagated_subscription = receiver_tombstone_states
        .subscribe(subscription_request(&alpha, &scope))
        .await?;
    require(
        !propagated_subscription.inserted && propagated_subscription.id == subscription.id,
        "propagated State subscription replay",
    )?;
    let tombstone_network_projections = wait_for_pair_projections(
        &publisher_tombstone_states,
        &receiver_tombstone_states,
        &alpha_query,
        |projection| causal_projection_ready(projection, tombstone.id, &pre_tombstone_ids),
        "State tombstone propagation deadline",
    )
    .await?;
    validate_causal_projection(
        &tombstone_network_projections[0],
        tombstone.id,
        TOMBSTONE_PAYLOAD,
        true,
        &pre_tombstone_ids,
    )?;
    require(
        equivalent_state_projections(
            &tombstone_network_projections[0],
            &tombstone_network_projections[1],
        ),
        "identical propagated State tombstones",
    )?;
    let propagated_beta = query_state_eventually(
        &receiver_tombstone_states,
        beta_query.clone(),
        "propagated beta State query deadline",
    )
    .await?;
    validate_single_projection(&propagated_beta, beta.id, BETA_PAYLOAD, false)?;
    let propagated_gamma = receiver_tombstone_states.query(gamma_query.clone()).await?;
    require(
        propagated_gamma.current.is_none() && propagated_gamma.recoverable.is_empty(),
        "gamma State appeared after tombstone propagation",
    )?;
    validate_empty_poll(&receiver_tombstone_states, subscription).await?;
    let _tombstone_contact = wait_for_contact_advance(
        &publisher_tombstone_status,
        &receiver_tombstone_status,
        [0, 0],
        "State tombstone contact deadline",
    )
    .await?;
    let retained_publisher_tombstone = publisher_tombstone_states.clone();
    let retained_receiver_tombstone = receiver_tombstone_states.clone();
    let (publisher_tombstone_receipt, receiver_tombstone_receipt) = tokio::join!(
        publisher_tombstone_running.shutdown(),
        receiver_tombstone_running.shutdown()
    );
    let publisher_tombstone_receipt = publisher_tombstone_receipt?;
    let receiver_tombstone_receipt = receiver_tombstone_receipt?;
    validate_direct_receipt(&publisher_tombstone_receipt)?;
    validate_direct_receipt(&receiver_tombstone_receipt)?;
    validate_transfer_pair(&publisher_tombstone_receipt, &receiver_tombstone_receipt, 1)?;
    validate_closed_handle(&retained_publisher_tombstone, alpha_query.clone()).await?;
    validate_closed_handle(&retained_receiver_tombstone, alpha_query.clone()).await?;
    drop((
        publisher_tombstone_states,
        receiver_tombstone_states,
        publisher_tombstone_status,
        receiver_tombstone_status,
        retained_publisher_tombstone,
        retained_receiver_tombstone,
    ));

    // Phase 7: the final peerless reopen reproduces the exact projection and
    // durable empty subscription state.
    let final_running = start_peerless(&receiver).await?;
    let final_states = final_running.selected_state();
    let final_subscription = final_states
        .subscribe(subscription_request(&alpha, &scope))
        .await?;
    require(
        !final_subscription.inserted && final_subscription.id == subscription.id,
        "final State subscription replay",
    )?;
    let final_projection = final_states.query(alpha_query.clone()).await?;
    validate_causal_projection(
        &final_projection,
        tombstone.id,
        TOMBSTONE_PAYLOAD,
        true,
        &pre_tombstone_ids,
    )?;
    let final_beta = final_states.query(beta_query).await?;
    validate_single_projection(&final_beta, beta.id, BETA_PAYLOAD, false)?;
    let final_gamma = final_states.query(gamma_query).await?;
    require(
        final_gamma.current.is_none() && final_gamma.recoverable.is_empty(),
        "gamma State appeared on final reopen",
    )?;
    validate_empty_poll(&final_states, subscription).await?;
    let retained_final = final_states.clone();
    let final_receipt = final_running.shutdown().await?;
    validate_peerless_receipt(&final_receipt)?;
    validate_closed_handle(&retained_final, alpha_query).await?;
    drop((final_states, retained_final));

    let publisher_inspection = Store::inspect_existing(publisher.state.join("mesh.redb"))?;
    let receiver_inspection = Store::inspect_existing(receiver.state.join("mesh.redb"))?;
    validate_inspections(&publisher_inspection, &receiver_inspection)?;
    validate_reacquired_bind(publisher_address)?;
    validate_reacquired_bind(receiver_address)?;

    let receipts = vec![
        ReceiptEvidence {
            phase: "peerless_origins",
            participant: "publisher",
            receipt: publisher_peerless_receipt,
        },
        ReceiptEvidence {
            phase: "peerless_origins",
            participant: "receiver",
            receipt: receiver_peerless_receipt,
        },
        ReceiptEvidence {
            phase: "direct_convergence_and_successor",
            participant: "publisher",
            receipt: publisher_connected_receipt,
        },
        ReceiptEvidence {
            phase: "direct_convergence_and_successor",
            participant: "receiver",
            receipt: receiver_connected_receipt,
        },
        ReceiptEvidence {
            phase: "peerless_tombstone",
            participant: "receiver",
            receipt: tombstone_receipt,
        },
        ReceiptEvidence {
            phase: "direct_tombstone_propagation",
            participant: "publisher",
            receipt: publisher_tombstone_receipt,
        },
        ReceiptEvidence {
            phase: "direct_tombstone_propagation",
            participant: "receiver",
            receipt: receiver_tombstone_receipt,
        },
        ReceiptEvidence {
            phase: "final_peerless_reopen",
            participant: "receiver",
            receipt: final_receipt,
        },
    ];
    let evidence = AcceptanceEvidence {
        subscription,
        left,
        right,
        successor,
        beta,
        gamma,
        tombstone,
        initial_delivery,
        tombstone_delivery,
        initial_projections,
        concurrent_projections,
        successor_projections,
        tombstone_local_projection,
        tombstone_network_projections,
        final_projection,
        attempt_one: attempt_one_fields,
        attempt_two: attempt_two_fields,
        tombstone_ack,
        tombstone_reack,
        receipts,
        inspections: [publisher_inspection, receiver_inspection],
    };
    emit_transcript(&publisher, &receiver, &evidence)?;
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
    require(arguments.len() == 8, "attempt-one child arguments")?;
    let state = PathBuf::from(&arguments[0]);
    let mission_path = PathBuf::from(&arguments[1]);
    let attempt_token_path = PathBuf::from(&arguments[2]);
    let expected_subscription = parse_state_subscription_id(&arguments[3])?;
    let left = parse_state_id(&arguments[4])?;
    let right = parse_state_id(&arguments[5])?;
    let successor = parse_state_id(&arguments[6])?;
    let beta = parse_state_id(&arguments[7])?;
    let mission = UnprotectedReferenceMission::load(&mission_path)?;
    let receiver_id = mission.identity();
    let receiver_authority = mission.mission_authority_id();
    let running = start_node(NodeConfig {
        state,
        bind: SocketAddr::from(([127, 0, 0, 1], 0)),
        mission,
        peers: Vec::new(),
        mutable_interests: MutableSourceInterests::default(),
        sync_interval: SYNC_INTERVAL,
        run_for: None,
        application: NodeApplication::Relay,
    })
    .await?;
    let states = running.selected_state();
    require(
        states.identity() == receiver_id && states.mission_authority() == receiver_authority,
        "attempt-one child handle binding",
    )?;
    let alpha = Topic::new(ALPHA_TOPIC)?;
    let beta_topic = Topic::new(BETA_TOPIC)?;
    let gamma_topic = Topic::new(GAMMA_TOPIC)?;
    let scope = Scope::new(SCOPE)?;
    let subscription = states
        .subscribe(subscription_request(&alpha, &scope))
        .await?;
    require(
        !subscription.inserted && subscription.id == expected_subscription,
        "attempt-one child subscription replay",
    )?;
    let origin_ids = sorted_state_ids(left, right);
    let projection = states.query(state_query(&alpha, &scope, ALPHA_KEY)).await?;
    validate_causal_projection(
        &projection,
        successor,
        SUCCESSOR_PAYLOAD,
        false,
        &origin_ids,
    )?;
    let beta_projection = states
        .query(state_query(&beta_topic, &scope, BETA_KEY))
        .await?;
    validate_single_projection(&beta_projection, beta, BETA_PAYLOAD, false)?;
    let gamma_projection = states
        .query(state_query(&gamma_topic, &scope, GAMMA_KEY))
        .await?;
    require(
        gamma_projection.current.is_none() && gamma_projection.recoverable.is_empty(),
        "attempt-one gamma State present",
    )?;
    let page = poll(&states, subscription).await?;
    require(
        page.deliveries.len() == 1 && !page.has_more,
        "attempt-one State delivery count",
    )?;
    let delivery = &page.deliveries[0];
    validate_delivery(
        delivery,
        successor,
        delivery.state.publisher,
        SUCCESSOR_PAYLOAD,
        false,
        1,
    )?;
    require(
        delivery.state.id != left && delivery.state.id != right && delivery.state.id != beta,
        "attempt-one delivered excluded State",
    )?;
    persist_delivery_token(&attempt_token_path, delivery.token)?;
    emit_child(
        "ATTEMPT1_READY",
        &[
            ("participant", "receiver".to_owned()),
            ("identity", format_node_id(receiver_id)),
            ("subscription_id", subscription.id.to_string()),
            ("subscription_inserted", subscription.inserted.to_string()),
            ("successor_id", delivery.state.id.to_string()),
            (
                "successor_publisher",
                format_node_id(delivery.state.publisher),
            ),
            (
                "successor_counter",
                delivery.state.publisher_counter.to_string(),
            ),
            ("successor_attempt", delivery.attempt.to_string()),
            (
                "successor_token_sha256",
                sha256_hex(delivery.token.as_bytes()),
            ),
            ("successor_token_persisted", "true".to_owned()),
            (
                "successor_payload_sha256",
                sha256_hex(&delivery.state.payload),
            ),
            (
                "successor_disposition",
                disposition_name(delivery.state.disposition).to_owned(),
            ),
            ("successor_tombstone", delivery.state.tombstone.to_string()),
            ("old_left_absent", (delivery.state.id != left).to_string()),
            ("old_right_absent", (delivery.state.id != right).to_string()),
            ("beta_absent", (delivery.state.id != beta).to_string()),
            (
                "gamma_query_empty",
                gamma_projection.current.is_none().to_string(),
            ),
            ("acknowledged", "false".to_owned()),
        ],
    )?;
    std::future::pending::<()>().await;
    #[allow(unreachable_code)]
    Ok(())
}

async fn run_attempt_two_child(arguments: &[OsString]) -> Result<(), DynError> {
    require(arguments.len() == 9, "attempt-two child arguments")?;
    let state = PathBuf::from(&arguments[0]);
    let mission_path = PathBuf::from(&arguments[1]);
    let attempt_token_path = PathBuf::from(&arguments[2]);
    let retired_origin_token_path = PathBuf::from(&arguments[3]);
    let expected_subscription = parse_state_subscription_id(&arguments[4])?;
    let left = parse_state_id(&arguments[5])?;
    let right = parse_state_id(&arguments[6])?;
    let successor = parse_state_id(&arguments[7])?;
    let beta = parse_state_id(&arguments[8])?;
    let mission = UnprotectedReferenceMission::load(&mission_path)?;
    let receiver_id = mission.identity();
    let running = start_node(NodeConfig {
        state,
        bind: SocketAddr::from(([127, 0, 0, 1], 0)),
        mission,
        peers: Vec::new(),
        mutable_interests: MutableSourceInterests::default(),
        sync_interval: SYNC_INTERVAL,
        run_for: None,
        application: NodeApplication::Relay,
    })
    .await?;
    let states = running.selected_state();
    let alpha = Topic::new(ALPHA_TOPIC)?;
    let beta_topic = Topic::new(BETA_TOPIC)?;
    let scope = Scope::new(SCOPE)?;
    let subscription = states
        .subscribe(subscription_request(&alpha, &scope))
        .await?;
    require(
        !subscription.inserted && subscription.id == expected_subscription,
        "attempt-two child subscription replay",
    )?;
    let origin_ids = sorted_state_ids(left, right);
    let projection = states.query(state_query(&alpha, &scope, ALPHA_KEY)).await?;
    validate_causal_projection(
        &projection,
        successor,
        SUCCESSOR_PAYLOAD,
        false,
        &origin_ids,
    )?;
    let beta_projection = states
        .query(state_query(&beta_topic, &scope, BETA_KEY))
        .await?;
    validate_single_projection(&beta_projection, beta, BETA_PAYLOAD, false)?;
    let page = poll(&states, subscription).await?;
    require(
        page.deliveries.len() == 1 && !page.has_more,
        "attempt-two State delivery count",
    )?;
    let delivery = &page.deliveries[0];
    validate_delivery(
        delivery,
        successor,
        delivery.state.publisher,
        SUCCESSOR_PAYLOAD,
        false,
        2,
    )?;
    require(
        delivery.state.id != left && delivery.state.id != right && delivery.state.id != beta,
        "attempt-two delivered excluded State",
    )?;
    let first_token = consume_delivery_token(&attempt_token_path)?;
    let retired_origin_token = consume_delivery_token(&retired_origin_token_path)?;
    require(
        first_token != delivery.token,
        "State retry reused its opaque delivery token",
    )?;
    let malformed_token_error = StateDeliveryToken::from_bytes([0_u8; STATE_DELIVERY_TOKEN_BYTES])
        .expect_err("all-zero State delivery token must be rejected");
    require(
        malformed_token_error.kind() == ApplicationErrorKind::InvalidRequest
            && malformed_token_error.operation() == "state delivery token",
        "malformed State delivery token rejection",
    )?;
    let mut wrong_subscription_bytes = *subscription.id.as_bytes();
    wrong_subscription_bytes[0] ^= 0x80;
    let wrong_subscription = StateSubscriptionId::from_bytes(wrong_subscription_bytes);
    wrong_subscription_bytes.zeroize();
    let wrong_subscription_error = states
        .acknowledge(wrong_subscription, successor, first_token)
        .await
        .expect_err("State delivery token must bind its subscription");
    require(
        wrong_subscription_error.kind() == ApplicationErrorKind::InvalidRequest
            && wrong_subscription_error.operation() == "state acknowledge",
        "State delivery token subscription binding",
    )?;
    let wrong_state_error = states
        .acknowledge(subscription.id, left, first_token)
        .await
        .expect_err("State delivery token must bind its semantic identity");
    require(
        wrong_state_error.kind() == ApplicationErrorKind::InvalidRequest
            && wrong_state_error.operation() == "state acknowledge",
        "State delivery token semantic binding",
    )?;
    let retired_origin_error = states
        .acknowledge(subscription.id, right, retired_origin_token)
        .await
        .expect_err("retired State delivery tenure must reject its token");
    require(
        retired_origin_error.kind() == ApplicationErrorKind::InvalidRequest
            && retired_origin_error.operation() == "state acknowledge",
        "retired State delivery token rejection",
    )?;
    let acknowledgement = states
        .acknowledge(subscription.id, successor, first_token)
        .await?;
    let reacknowledgement = states
        .acknowledge(subscription.id, successor, delivery.token)
        .await?;
    require(
        acknowledgement == StateAcknowledgement::Acknowledged
            && reacknowledgement == StateAcknowledgement::AlreadyAcknowledged,
        "attempt-two State acknowledgements",
    )?;
    let empty = poll(&states, subscription).await?;
    require(
        empty.deliveries.is_empty() && !empty.has_more,
        "attempt-two State empty poll",
    )?;
    let retained = states.clone();
    let receipt = running.shutdown().await?;
    validate_peerless_receipt(&receipt)?;
    validate_closed_handle(
        &retained,
        state_query(&Topic::new(ALPHA_TOPIC)?, &Scope::new(SCOPE)?, ALPHA_KEY),
    )
    .await?;
    let mut fields = vec![
        ("participant", "receiver".to_owned()),
        ("identity", format_node_id(receiver_id)),
        ("subscription_id", subscription.id.to_string()),
        ("subscription_inserted", subscription.inserted.to_string()),
        ("successor_id", delivery.state.id.to_string()),
        (
            "successor_publisher",
            format_node_id(delivery.state.publisher),
        ),
        (
            "successor_counter",
            delivery.state.publisher_counter.to_string(),
        ),
        ("successor_attempt", delivery.attempt.to_string()),
        (
            "successor_token_sha256",
            sha256_hex(delivery.token.as_bytes()),
        ),
        ("previous_token_sha256", sha256_hex(first_token.as_bytes())),
        ("tokens_distinct", "true".to_owned()),
        ("previous_token_restored", "true".to_owned()),
        ("malformed_token_rejected", "true".to_owned()),
        ("wrong_subscription_token_rejected", "true".to_owned()),
        ("wrong_state_token_rejected", "true".to_owned()),
        ("retired_token_rejected", "true".to_owned()),
        (
            "retired_token_sha256",
            sha256_hex(retired_origin_token.as_bytes()),
        ),
        ("ack_token_attempt", "1".to_owned()),
        ("reack_token_attempt", "2".to_owned()),
        ("token_artifact_removed", "true".to_owned()),
        (
            "successor_payload_sha256",
            sha256_hex(&delivery.state.payload),
        ),
        (
            "successor_disposition",
            disposition_name(delivery.state.disposition).to_owned(),
        ),
        ("successor_tombstone", delivery.state.tombstone.to_string()),
        ("ack", acknowledgement_name(acknowledgement).to_owned()),
        ("reack", acknowledgement_name(reacknowledgement).to_owned()),
        ("empty_deliveries", empty.deliveries.len().to_string()),
        ("empty_has_more", empty.has_more.to_string()),
        ("closed_kind", "state_unavailable".to_owned()),
        ("closed_operation", "state_query".to_owned()),
    ];
    fields.extend(prefixed_receipt_fields(&receipt));
    emit_child("ATTEMPT2_DONE", &fields)?;
    Ok(())
}

fn spawn_attempt_one(
    receiver: &Participant,
    attempt_token_path: &Path,
    subscription: aster_node::application::StateSubscriptionId,
    left: StateId,
    right: StateId,
    successor: StateId,
    beta: StateId,
) -> Result<ChildActor, DynError> {
    let mut command = Command::new(env::current_exe()?);
    command
        .arg("--internal-attempt-1")
        .arg(&receiver.state)
        .arg(&receiver.mission_path)
        .arg(attempt_token_path)
        .arg(subscription.to_string())
        .arg(left.to_string())
        .arg(right.to_string())
        .arg(successor.to_string())
        .arg(beta.to_string());
    spawn_child(command)
}

fn spawn_attempt_two(
    receiver: &Participant,
    artifacts: &AttemptArtifacts,
    subscription: aster_node::application::StateSubscriptionId,
    left: StateId,
    right: StateId,
    successor: StateId,
    beta: StateId,
) -> Result<ChildActor, DynError> {
    let mut command = Command::new(env::current_exe()?);
    command
        .arg("--internal-attempt-2")
        .arg(&receiver.state)
        .arg(&receiver.mission_path)
        .arg(&artifacts.retry_token)
        .arg(&artifacts.retired_origin_token)
        .arg(subscription.to_string())
        .arg(left.to_string())
        .arg(right.to_string())
        .arg(successor.to_string())
        .arg(beta.to_string());
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
    Ok(ChildActor {
        child,
        lines,
        saw_runtime_stop: false,
    })
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
            child.saw_runtime_stop |= runtime_stop_record(&line);
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

async fn drain_child_lines(child: &mut ChildActor) -> Result<(), DynError> {
    while let Some(line) = child.lines.recv().await {
        let line = line?;
        forward_child_line(&line)?;
        child.saw_runtime_stop |= runtime_stop_record(&line);
    }
    Ok(())
}

fn runtime_stop_record(line: &str) -> bool {
    line.starts_with("STOP ")
}

fn forward_child_line(line: &str) -> Result<(), DynError> {
    println!("{line}");
    std::io::stdout().flush()?;
    Ok(())
}

fn emit_child(kind: &str, fields: &[(&str, String)]) -> Result<(), DynError> {
    print!("LIVE_STATE_SUBSCRIPTION_CHILD\t{kind}");
    for (key, value) in fields {
        require(
            valid_field(key) && valid_value(value),
            "child record encoding",
        )?;
        print!("\t{key}={value}");
    }
    println!();
    std::io::stdout().flush()?;
    Ok(())
}

fn parse_child_record(line: &str) -> Result<Option<(String, ChildFields)>, DynError> {
    if !line.starts_with("LIVE_STATE_SUBSCRIPTION_CHILD\t") {
        return Ok(None);
    }
    let mut parts = line.split('\t');
    require(
        parts.next() == Some("LIVE_STATE_SUBSCRIPTION_CHILD"),
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
            valid_field(key)
                && valid_value(value)
                && fields.insert(key.to_owned(), value.to_owned()).is_none(),
            "child record fields",
        )?;
    }
    Ok(Some((kind, fields)))
}

fn child_field<'a>(fields: &'a ChildFields, key: &'static str) -> Result<&'a str, DynError> {
    fields
        .get(key)
        .map(String::as_str)
        .ok_or_else(|| Box::new(AcceptanceFailure("child field missing")) as DynError)
}

fn validate_attempt_one(
    fields: &ChildFields,
    receiver: &Participant,
    subscription: aster_node::application::StateSubscriptionId,
    left: StateId,
    right: StateId,
    successor: StateId,
    beta: StateId,
) -> Result<(), DynError> {
    require(
        child_field(fields, "participant")? == "receiver"
            && child_field(fields, "identity")? == format_node_id(receiver.mission_id)
            && child_field(fields, "subscription_id")? == subscription.to_string()
            && child_field(fields, "subscription_inserted")? == "false"
            && child_field(fields, "successor_id")? == successor.to_string()
            && child_field(fields, "successor_publisher")? != format_node_id(receiver.mission_id)
            && child_field(fields, "successor_counter")? == "2"
            && child_field(fields, "successor_attempt")? == "1"
            && is_sha256(child_field(fields, "successor_token_sha256")?)
            && child_field(fields, "successor_token_persisted")? == "true"
            && child_field(fields, "successor_payload_sha256")? == sha256_hex(SUCCESSOR_PAYLOAD)
            && child_field(fields, "successor_disposition")? == "current"
            && child_field(fields, "successor_tombstone")? == "false"
            && child_field(fields, "old_left_absent")? == "true"
            && child_field(fields, "old_right_absent")? == "true"
            && child_field(fields, "beta_absent")? == "true"
            && child_field(fields, "gamma_query_empty")? == "true"
            && child_field(fields, "acknowledged")? == "false"
            && successor != left
            && successor != right
            && successor != beta,
        "attempt-one child evidence",
    )
}

fn validate_attempt_two(
    fields: &ChildFields,
    receiver: &Participant,
    subscription: aster_node::application::StateSubscriptionId,
    successor: StateId,
    retired_origin_token: StateDeliveryToken,
) -> Result<(), DynError> {
    require(
        child_field(fields, "participant")? == "receiver"
            && child_field(fields, "identity")? == format_node_id(receiver.mission_id)
            && child_field(fields, "subscription_id")? == subscription.to_string()
            && child_field(fields, "subscription_inserted")? == "false"
            && child_field(fields, "successor_id")? == successor.to_string()
            && child_field(fields, "successor_counter")? == "2"
            && child_field(fields, "successor_attempt")? == "2"
            && is_sha256(child_field(fields, "successor_token_sha256")?)
            && is_sha256(child_field(fields, "previous_token_sha256")?)
            && child_field(fields, "successor_token_sha256")?
                != child_field(fields, "previous_token_sha256")?
            && child_field(fields, "tokens_distinct")? == "true"
            && child_field(fields, "previous_token_restored")? == "true"
            && child_field(fields, "malformed_token_rejected")? == "true"
            && child_field(fields, "wrong_subscription_token_rejected")? == "true"
            && child_field(fields, "wrong_state_token_rejected")? == "true"
            && child_field(fields, "retired_token_rejected")? == "true"
            && child_field(fields, "retired_token_sha256")?
                == sha256_hex(retired_origin_token.as_bytes())
            && child_field(fields, "ack_token_attempt")? == "1"
            && child_field(fields, "reack_token_attempt")? == "2"
            && child_field(fields, "token_artifact_removed")? == "true"
            && child_field(fields, "successor_payload_sha256")? == sha256_hex(SUCCESSOR_PAYLOAD)
            && child_field(fields, "successor_disposition")? == "current"
            && child_field(fields, "successor_tombstone")? == "false"
            && child_field(fields, "ack")? == "acknowledged"
            && child_field(fields, "reack")? == "already_acknowledged"
            && child_field(fields, "empty_deliveries")? == "0"
            && child_field(fields, "empty_has_more")? == "false"
            && child_field(fields, "shutdown_contacts")? == "0"
            && child_field(fields, "shutdown_contact_errors")? == "0"
            && child_field(fields, "shutdown_direct_contacts")? == "0"
            && child_field(fields, "shutdown_relay_contacts")? == "0"
            && child_field(fields, "shutdown_unknown_path_contacts")? == "0"
            && child_field(fields, "shutdown_events")? == "0"
            && child_field(fields, "shutdown_blobs")? == "0"
            && child_field(fields, "closed_kind")? == "state_unavailable"
            && child_field(fields, "closed_operation")? == "state_query",
        "attempt-two child evidence",
    )
}

fn is_sha256(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn parse_state_id(argument: &OsString) -> Result<StateId, DynError> {
    Ok(StateId::from_bytes(parse_hex_32(argument)?))
}

fn parse_state_subscription_id(
    argument: &OsString,
) -> Result<aster_node::application::StateSubscriptionId, DynError> {
    Ok(aster_node::application::StateSubscriptionId::from_bytes(
        parse_hex_32(argument)?,
    ))
}

fn parse_hex_32(argument: &OsString) -> Result<[u8; 32], DynError> {
    let value = argument
        .to_str()
        .ok_or_else(|| Box::new(AcceptanceFailure("child identifier encoding")) as DynError)?;
    require(value.len() == 64, "child identifier length")?;
    let mut bytes = [0u8; 32];
    for (index, byte) in bytes.iter_mut().enumerate() {
        let offset = index * 2;
        *byte = u8::from_str_radix(&value[offset..offset + 2], 16)
            .map_err(|_| AcceptanceFailure("child identifier value"))?;
    }
    Ok(bytes)
}

#[cfg(unix)]
fn persist_delivery_token(path: &Path, token: StateDeliveryToken) -> Result<(), DynError> {
    use std::os::unix::fs::OpenOptionsExt as _;

    require(path.is_absolute(), "attempt token path must be absolute")?;
    let mut file = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)?;
    file.write_all(token.as_bytes())?;
    file.sync_all()?;
    drop(file);
    validate_token_artifact(path, &sha256_hex(token.as_bytes()))
}

#[cfg(not(unix))]
fn persist_delivery_token(path: &Path, token: StateDeliveryToken) -> Result<(), DynError> {
    require(path.is_absolute(), "attempt token path must be absolute")?;
    let mut file = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)?;
    file.write_all(token.as_bytes())?;
    file.sync_all()?;
    drop(file);
    validate_token_artifact(path, &sha256_hex(token.as_bytes()))
}

fn validate_token_artifact(path: &Path, expected_digest: &str) -> Result<(), DynError> {
    let token = read_delivery_token(path)?;
    require(
        sha256_hex(token.as_bytes()) == expected_digest,
        "attempt token artifact digest",
    )
}

fn consume_delivery_token(path: &Path) -> Result<StateDeliveryToken, DynError> {
    let token = read_delivery_token(path)?;
    fs::remove_file(path)?;
    require(!path.exists(), "attempt token artifact removal")?;
    Ok(token)
}

fn read_delivery_token(path: &Path) -> Result<StateDeliveryToken, DynError> {
    let metadata = fs::symlink_metadata(path)?;
    require(
        metadata.file_type().is_file() && metadata.len() == STATE_DELIVERY_TOKEN_BYTES as u64,
        "attempt token artifact type",
    )?;
    validate_token_permissions(&metadata)?;
    let mut file = fs::File::open(path)?;
    let mut bytes = [0_u8; STATE_DELIVERY_TOKEN_BYTES];
    file.read_exact(&mut bytes)?;
    let token = StateDeliveryToken::from_bytes(bytes)?;
    bytes.zeroize();
    Ok(token)
}

#[cfg(unix)]
fn validate_token_permissions(metadata: &fs::Metadata) -> Result<(), DynError> {
    use std::os::unix::fs::PermissionsExt as _;

    require(
        metadata.permissions().mode() & 0o777 == 0o600,
        "attempt token artifact permissions",
    )
}

#[cfg(not(unix))]
fn validate_token_permissions(_metadata: &fs::Metadata) -> Result<(), DynError> {
    Ok(())
}

#[cfg(unix)]
fn validate_forced_child_termination(
    child_pid: u32,
    status: std::process::ExitStatus,
    saw_runtime_stop: bool,
) -> Result<(), DynError> {
    use std::os::unix::process::ExitStatusExt as _;

    require(
        child_pid != std::process::id()
            && !status.success()
            && status.signal() == Some(9)
            && !saw_runtime_stop,
        "receiver child was not force terminated",
    )
}

#[cfg(not(unix))]
fn validate_forced_child_termination(
    child_pid: u32,
    status: std::process::ExitStatus,
    saw_runtime_stop: bool,
) -> Result<(), DynError> {
    require(
        child_pid != std::process::id() && !status.success() && !saw_runtime_stop,
        "receiver child was not force terminated",
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

fn provision_participants(
    participants_root: &Path,
    topics: [&Topic; 3],
    scope: &Scope,
) -> Result<[Participant; 2], DynError> {
    let access = ProvisioningAccess::member(
        scope.clone(),
        vec![1],
        topics.into_iter().cloned().collect(),
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
        "deterministic publisher ordering",
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
        "independently provisioned State participants",
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
        "State participant identity domains",
    )
}

async fn start_peerless(participant: &Participant) -> Result<aster_node::RunningNode, DynError> {
    Ok(start_node(NodeConfig {
        state: participant.state.clone(),
        bind: SocketAddr::from(([127, 0, 0, 1], 0)),
        mission: participant.mission.clone(),
        peers: Vec::new(),
        mutable_interests: MutableSourceInterests::default(),
        sync_interval: SYNC_INTERVAL,
        run_for: None,
        application: NodeApplication::Relay,
    })
    .await?)
}

fn configured_state_interests(
    alpha: &Topic,
    beta: &Topic,
    scope: &Scope,
) -> MutableSourceInterests {
    MutableSourceInterests::new(
        vec![
            SourceInterestSelector::new(alpha.clone(), scope.clone(), false),
            SourceInterestSelector::new(beta.clone(), scope.clone(), false),
        ],
        Vec::new(),
    )
}

fn connected_config(
    local: &Participant,
    bind: SocketAddr,
    remote: &Participant,
    remote_address: SocketAddr,
    interests: MutableSourceInterests,
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
        mutable_interests: interests,
        sync_interval: SYNC_INTERVAL,
        run_for: None,
        application: NodeApplication::Relay,
    }
}

async fn start_pair(
    publisher: &Participant,
    publisher_address: SocketAddr,
    receiver: &Participant,
    receiver_address: SocketAddr,
    interests: MutableSourceInterests,
) -> Result<(aster_node::RunningNode, aster_node::RunningNode), DynError> {
    let publisher_config = connected_config(
        publisher,
        publisher_address,
        receiver,
        receiver_address,
        interests.clone(),
    );
    let receiver_config = connected_config(
        receiver,
        receiver_address,
        publisher,
        publisher_address,
        interests,
    );
    // Starting the greater carrier identity first leaves the deterministic
    // lower identity as the first successful initiator.
    if publisher.carrier_id > receiver.carrier_id {
        let publisher_running = start_node(publisher_config).await?;
        let receiver_running = start_node(receiver_config).await?;
        Ok((publisher_running, receiver_running))
    } else {
        let receiver_running = start_node(receiver_config).await?;
        let publisher_running = start_node(publisher_config).await?;
        Ok((publisher_running, receiver_running))
    }
}

fn state_request(
    operation: &[u8],
    topic: &Topic,
    scope: &Scope,
    logical_key: &[u8],
    payload: &[u8],
    tombstone: bool,
) -> StatePublishRequest {
    StatePublishRequest {
        operation_key: operation.to_vec(),
        topic: topic.clone(),
        scope: scope.clone(),
        priority: Priority::Priority,
        logical_key: logical_key.to_vec(),
        payload: payload.to_vec(),
        tombstone,
    }
}

fn subscription_request(topic: &Topic, scope: &Scope) -> StateSubscriptionRequest {
    StateSubscriptionRequest {
        operation_key: SUBSCRIPTION_OPERATION.to_vec(),
        topic: topic.clone(),
        scope: scope.clone(),
        include_descendant_scopes: false,
    }
}

fn state_query(topic: &Topic, scope: &Scope, logical_key: &[u8]) -> StateQuery {
    StateQuery {
        topic: topic.clone(),
        scope: scope.clone(),
        logical_key: logical_key.to_vec(),
        include_recoverable_versions: true,
    }
}

async fn poll(
    states: &SelectedStateHandle,
    subscription: StateSubscription,
) -> Result<aster_node::application::StateDeliveryPage, ApplicationError> {
    states
        .poll(StatePollRequest {
            subscription: subscription.id,
            delivery_limit: 8,
            scan_limit: 16,
        })
        .await
}

async fn validate_empty_poll(
    states: &SelectedStateHandle,
    subscription: StateSubscription,
) -> Result<(), DynError> {
    let page = poll(states, subscription).await?;
    require(
        page.deliveries.is_empty() && !page.has_more,
        "State poll was not empty",
    )
}

fn validate_handle(
    participant: &Participant,
    handle: &SelectedStateHandle,
) -> Result<(), DynError> {
    require(
        handle.identity() == participant.mission_id
            && handle.mission_authority() == participant.mission_authority,
        "selected State handle mission binding",
    )
}

fn validate_publication(
    publication: &StatePublishResult,
    participant: &Participant,
    counter: u64,
    inserted: bool,
) -> Result<(), DynError> {
    require(
        publication.publisher == participant.mission_id
            && publication.publisher_counter == counter
            && publication.priority == Priority::Priority
            && publication.inserted == inserted
            && publication.acceptance_marker > 0,
        "State publication metadata",
    )
}

fn validate_delivery(
    delivery: &StateDelivery,
    expected: StateId,
    publisher: [u8; 32],
    payload: &[u8],
    tombstone: bool,
    attempt: u64,
) -> Result<(), DynError> {
    require(
        delivery.state.id == expected
            && delivery.state.publisher == publisher
            && delivery.state.topic == Topic::new(ALPHA_TOPIC)?
            && delivery.state.scope == Scope::new(SCOPE)?
            && delivery.state.priority == Priority::Priority
            && delivery.state.logical_key == ALPHA_KEY
            && delivery.state.payload == payload
            && delivery.state.tombstone == tombstone
            && delivery.state.disposition == StateVersionDisposition::Current
            && delivery.attempt == attempt,
        "State delivery metadata",
    )
}

fn validate_single_projection(
    projection: &StateProjection,
    expected: StateId,
    payload: &[u8],
    tombstone: bool,
) -> Result<(), DynError> {
    let current = projection
        .current
        .as_ref()
        .ok_or(AcceptanceFailure("missing current State projection"))?;
    require(
        current.id == expected
            && current.payload == payload
            && current.tombstone == tombstone
            && current.disposition == StateVersionDisposition::Current
            && projection.recoverable.is_empty(),
        "single current State projection",
    )
}

fn validate_concurrent_projection(
    projection: &StateProjection,
    left: &StatePublishResult,
    right: &StatePublishResult,
    left_payload: &[u8],
    right_payload: &[u8],
) -> Result<(), DynError> {
    let ids = sorted_state_ids(left.id, right.id);
    let current = projection
        .current
        .as_ref()
        .ok_or(AcceptanceFailure("missing concurrent State current"))?;
    require(
        current.id == ids[1]
            && current.disposition == StateVersionDisposition::Current
            && projection.recoverable.len() == 1
            && projection.recoverable[0].id == ids[0]
            && projection.recoverable[0].disposition == StateVersionDisposition::Concurrent,
        "concurrent State reduction",
    )?;
    for item in std::iter::once(current).chain(&projection.recoverable) {
        if item.id == left.id {
            require(
                item.publisher == left.publisher && item.payload == left_payload && !item.tombstone,
                "left concurrent State item",
            )?;
        } else if item.id == right.id {
            require(
                item.publisher == right.publisher
                    && item.payload == right_payload
                    && !item.tombstone,
                "right concurrent State item",
            )?;
        } else {
            return Err(Box::new(AcceptanceFailure(
                "unexpected concurrent State item",
            )));
        }
    }
    Ok(())
}

fn validate_causal_projection(
    projection: &StateProjection,
    expected_current: StateId,
    payload: &[u8],
    tombstone: bool,
    expected_superseded: &[StateId],
) -> Result<(), DynError> {
    let current = projection
        .current
        .as_ref()
        .ok_or(AcceptanceFailure("missing causal State current"))?;
    let actual_superseded = projection
        .recoverable
        .iter()
        .map(|item| item.id)
        .collect::<BTreeSet<_>>();
    let expected_superseded = expected_superseded.iter().copied().collect::<BTreeSet<_>>();
    require(
        current.id == expected_current
            && current.payload == payload
            && current.tombstone == tombstone
            && current.disposition == StateVersionDisposition::Current
            && actual_superseded == expected_superseded
            && projection
                .recoverable
                .iter()
                .all(|item| item.disposition == StateVersionDisposition::Superseded),
        "causal State projection",
    )
}

// Acceptance markers are durable insertion order local to each Store. Two
// converged nodes therefore prove the same authenticated State projection
// while legitimately assigning different marker values to versions received
// in opposite orders. Compare the portable State facts, not that local ledger
// coordinate.
fn equivalent_state_projections(left: &StateProjection, right: &StateProjection) -> bool {
    match (&left.current, &right.current) {
        (Some(left), Some(right)) if equivalent_state_items(left, right) => {}
        (None, None) => {}
        _ => return false,
    }

    let left_recoverable = left
        .recoverable
        .iter()
        .map(|item| (item.id, item))
        .collect::<BTreeMap<_, _>>();
    let right_recoverable = right
        .recoverable
        .iter()
        .map(|item| (item.id, item))
        .collect::<BTreeMap<_, _>>();
    left_recoverable.len() == left.recoverable.len()
        && right_recoverable.len() == right.recoverable.len()
        && left_recoverable.len() == right_recoverable.len()
        && left_recoverable.iter().all(|(id, left)| {
            right_recoverable
                .get(id)
                .is_some_and(|right| equivalent_state_items(left, right))
        })
}

fn equivalent_state_items(left: &StateItem, right: &StateItem) -> bool {
    left.id == right.id
        && left.publisher == right.publisher
        && left.publisher_counter == right.publisher_counter
        && left.topic == right.topic
        && left.scope == right.scope
        && left.priority == right.priority
        && left.logical_key == right.logical_key
        && left.payload == right.payload
        && left.tombstone == right.tombstone
        && left.disposition == right.disposition
}

fn sorted_state_ids(left: StateId, right: StateId) -> [StateId; 2] {
    if left < right {
        [left, right]
    } else {
        [right, left]
    }
}

fn single_projection_ready(projection: &StateProjection, expected: StateId) -> bool {
    projection
        .current
        .as_ref()
        .is_some_and(|item| item.id == expected)
        && projection.recoverable.is_empty()
}

fn concurrent_projection_ready(projection: &StateProjection, ids: [StateId; 2]) -> bool {
    projection
        .current
        .as_ref()
        .is_some_and(|item| item.id == ids[1])
        && projection.recoverable.len() == 1
        && projection.recoverable[0].id == ids[0]
}

fn causal_projection_ready(
    projection: &StateProjection,
    current: StateId,
    superseded: &[StateId],
) -> bool {
    projection
        .current
        .as_ref()
        .is_some_and(|item| item.id == current)
        && projection.recoverable.len() == superseded.len()
        && projection
            .recoverable
            .iter()
            .map(|item| item.id)
            .collect::<BTreeSet<_>>()
            == superseded.iter().copied().collect::<BTreeSet<_>>()
}

async fn query_state_eventually(
    handle: &SelectedStateHandle,
    query: StateQuery,
    deadline_label: &'static str,
) -> Result<StateProjection, DynError> {
    timeout(POLL_DEADLINE, async {
        loop {
            match handle.query(query.clone()).await {
                Ok(projection) => break Ok::<_, DynError>(projection),
                Err(error) if error.kind() == ApplicationErrorKind::PolicyUnsettled => {
                    sleep(Duration::from_millis(20)).await;
                }
                Err(error) => break Err(error.into()),
            }
        }
    })
    .await
    .map_err(|_| AcceptanceFailure(deadline_label))?
}

async fn publish_state_eventually(
    handle: &SelectedStateHandle,
    request: StatePublishRequest,
    deadline_label: &'static str,
) -> Result<StatePublishResult, DynError> {
    timeout(POLL_DEADLINE, async {
        loop {
            match handle.publish(request.clone()).await {
                Ok(result) => break Ok::<_, DynError>(result),
                Err(error) if error.kind() == ApplicationErrorKind::PolicyUnsettled => {
                    sleep(Duration::from_millis(20)).await;
                }
                Err(error) => break Err(error.into()),
            }
        }
    })
    .await
    .map_err(|_| AcceptanceFailure(deadline_label))?
}

async fn wait_for_projection<F>(
    handle: &SelectedStateHandle,
    query: &StateQuery,
    ready: F,
    deadline_label: &'static str,
) -> Result<StateProjection, DynError>
where
    F: Fn(&StateProjection) -> bool,
{
    timeout(POLL_DEADLINE, async {
        loop {
            match handle.query(query.clone()).await {
                Ok(projection) if ready(&projection) => break Ok::<_, DynError>(projection),
                Ok(_) => sleep(Duration::from_millis(20)).await,
                Err(error) if error.kind() == ApplicationErrorKind::PolicyUnsettled => {
                    sleep(Duration::from_millis(20)).await;
                }
                Err(error) => break Err(error.into()),
            }
        }
    })
    .await
    .map_err(|_| AcceptanceFailure(deadline_label))?
}

async fn wait_for_pair_projections<F>(
    left: &SelectedStateHandle,
    right: &SelectedStateHandle,
    query: &StateQuery,
    ready: F,
    deadline_label: &'static str,
) -> Result<[StateProjection; 2], DynError>
where
    F: Fn(&StateProjection) -> bool,
{
    timeout(POLL_DEADLINE, async {
        loop {
            let left_projection = match left.query(query.clone()).await {
                Ok(projection) => projection,
                Err(error) if error.kind() == ApplicationErrorKind::PolicyUnsettled => {
                    sleep(Duration::from_millis(20)).await;
                    continue;
                }
                Err(error) => return Err(error.into()),
            };
            let right_projection = match right.query(query.clone()).await {
                Ok(projection) => projection,
                Err(error) if error.kind() == ApplicationErrorKind::PolicyUnsettled => {
                    sleep(Duration::from_millis(20)).await;
                    continue;
                }
                Err(error) => return Err(error.into()),
            };
            if ready(&left_projection) && ready(&right_projection) {
                break Ok::<_, DynError>([left_projection, right_projection]);
            }
            sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .map_err(|_| AcceptanceFailure(deadline_label))?
}

async fn wait_for_contact_advance(
    left: &aster_node::application::SelectedEventHandle,
    right: &aster_node::application::SelectedEventHandle,
    baseline: [u64; 2],
    deadline_label: &'static str,
) -> Result<[u64; 2], DynError> {
    timeout(POLL_DEADLINE, async {
        loop {
            let left_status = left.status().await?;
            let right_status = right.status().await?;
            require(
                left_status.failed_contact_attempts == 0
                    && right_status.failed_contact_attempts == 0,
                "connected State status contact errors",
            )?;
            if left_status.authenticated_contacts > baseline[0]
                && right_status.authenticated_contacts > baseline[1]
            {
                break Ok::<_, DynError>([
                    left_status.authenticated_contacts,
                    right_status.authenticated_contacts,
                ]);
            }
            sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .map_err(|_| AcceptanceFailure(deadline_label))?
}

async fn validate_closed_handle(
    handle: &SelectedStateHandle,
    query: StateQuery,
) -> Result<(), DynError> {
    let error = match handle.query(query).await {
        Err(error) => error,
        Ok(_) => return Err(Box::new(AcceptanceFailure("closed State handle accepted"))),
    };
    require(
        error.kind() == ApplicationErrorKind::StateUnavailable
            && error.operation() == "state query",
        "closed State handle",
    )
}

fn validate_excluded_receipt(receipt: &NodeReceipt) -> Result<(), DynError> {
    require(
        receipt.events == 0
            && receipt.event_acceptance_markers == 0
            && receipt.route_cached_events == 0
            && receipt.controls == 0
            && receipt.applied_controls == 0
            && receipt.pending_controls == 0
            && receipt.control_highwater == 0
            && receipt.data_duplicates == 0
            && receipt.data_remaining == 0
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
        "excluded State receipt classes",
    )
}

fn validate_peerless_receipt(receipt: &NodeReceipt) -> Result<(), DynError> {
    validate_excluded_receipt(receipt)?;
    require(
        receipt.contacts == 0
            && receipt.contact_errors == 0
            && receipt.direct_contacts == 0
            && receipt.relay_contacts == 0
            && receipt.unknown_path_contacts == 0
            && receipt.carrier_path_transitions == 0
            && receipt.carrier_path_transition_saturations == 0
            && receipt.data_offered == 0
            && receipt.data_fetched == 0
            && receipt.data_inserted == 0,
        "peerless State shutdown receipt",
    )
}

fn validate_direct_receipt(receipt: &NodeReceipt) -> Result<(), DynError> {
    validate_excluded_receipt(receipt)?;
    require(
        receipt.contacts > 0
            && receipt.contact_errors == 0
            && receipt.direct_contacts == receipt.contacts
            && receipt.relay_contacts == 0
            && receipt.unknown_path_contacts == 0
            && receipt.carrier_path_transitions == 0
            && receipt.carrier_path_transition_saturations == 0,
        "direct State shutdown receipt",
    )
}

fn validate_transfer_pair(
    left: &NodeReceipt,
    right: &NodeReceipt,
    inserted: u64,
) -> Result<(), DynError> {
    require(
        left.data_offered + right.data_offered == inserted
            && left.data_fetched + right.data_fetched == inserted
            && left.data_inserted + right.data_inserted == inserted,
        "State transfer accounting",
    )
}

fn validate_inspections(
    publisher: &StoreInspection,
    receiver: &StoreInspection,
) -> Result<(), DynError> {
    require(
        publisher.state_stats.states == 6
            && publisher.state_stats.acceptance_markers == 6
            && publisher.state_stats.operations == 4
            && receiver.state_stats.states == 5
            && receiver.state_stats.acceptance_markers == 5
            && receiver.state_stats.operations == 2,
        "final State store statistics",
    )?;
    require(
        publisher.state_subscription_stats == StateSubscriptionStats::default()
            && receiver.state_subscription_stats
                == StateSubscriptionStats {
                    subscriptions: 1,
                    pending_deliveries: 0,
                    acknowledged_deliveries: 1,
                    delivery_cursors: 3,
                    selector_generation: 1,
                },
        "final State subscription statistics",
    )?;
    for inspection in [publisher, receiver] {
        require(
            inspection.event_stats == Default::default()
                && inspection.record_stats == Default::default()
                && inspection.blob_stats == Default::default()
                && inspection.event_subscription_stats == Default::default()
                && inspection.control_stats == Default::default(),
            "final excluded store statistics",
        )?;
    }
    Ok(())
}

fn validate_reacquired_bind(address: SocketAddr) -> Result<(), DynError> {
    let socket = UdpSocket::bind(address)?;
    require(socket.local_addr()? == address, "State bind reacquisition")?;
    drop(socket);
    Ok(())
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
        ("shutdown_events", receipt.events.to_string()),
        ("shutdown_blobs", receipt.blobs.to_string()),
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
    ]
}

const fn disposition_name(disposition: StateVersionDisposition) -> &'static str {
    match disposition {
        StateVersionDisposition::Current => "current",
        StateVersionDisposition::Concurrent => "concurrent",
        StateVersionDisposition::Superseded => "superseded",
    }
}

const fn acknowledgement_name(acknowledgement: StateAcknowledgement) -> &'static str {
    match acknowledgement {
        StateAcknowledgement::Acknowledged => "acknowledged",
        StateAcknowledgement::AlreadyAcknowledged => "already_acknowledged",
    }
}

fn sha256_hex(bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    digest.iter().map(|byte| format!("{byte:02x}")).collect()
}

struct TranscriptEmitter {
    records: usize,
}

impl TranscriptEmitter {
    fn new() -> Self {
        Self { records: 0 }
    }

    fn emit(&mut self, kind: &str, fields: &[(&str, String)]) -> Result<(), DynError> {
        require(valid_field(kind), "transcript record kind")?;
        print!("LIVE_STATE_SUBSCRIPTION\t{kind}");
        let mut seen = BTreeSet::new();
        for (key, value) in fields {
            require(
                valid_field(key) && valid_value(value) && seen.insert(*key),
                "transcript record encoding",
            )?;
            print!("\t{key}={value}");
        }
        println!();
        self.records = self
            .records
            .checked_add(1)
            .ok_or(AcceptanceFailure("transcript record overflow"))?;
        Ok(())
    }
}

fn valid_field(value: &str) -> bool {
    !value.is_empty()
        && value
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'_')
}

fn valid_value(value: &str) -> bool {
    !value.is_empty()
        && value.is_ascii()
        && !value.contains(['\t', '\n', '\r'])
        && value.bytes().all(|byte| (0x21..=0x7e).contains(&byte))
}

fn emit_transcript(
    publisher: &Participant,
    receiver: &Participant,
    evidence: &AcceptanceEvidence,
) -> Result<(), DynError> {
    let mut transcript = TranscriptEmitter::new();
    transcript.emit(
        "run",
        &[
            ("schema", TRANSCRIPT_SCHEMA.to_owned()),
            ("claim", CLAIM.to_owned()),
            ("participants", "2".to_owned()),
            ("processes", "3".to_owned()),
            ("actor_lifetimes", "10".to_owned()),
            ("maximum_concurrent_actors", "2".to_owned()),
            ("alpha_topic", ALPHA_TOPIC.to_owned()),
            ("beta_topic", BETA_TOPIC.to_owned()),
            ("gamma_topic", GAMMA_TOPIC.to_owned()),
            ("scope", SCOPE.to_owned()),
        ],
    )?;
    emit_participant(&mut transcript, publisher)?;
    emit_participant(&mut transcript, receiver)?;
    emit_peer_binding(&mut transcript, publisher, receiver)?;
    emit_peer_binding(&mut transcript, receiver, publisher)?;

    // Phase 1: records 6-15.
    emit_phase(
        &mut transcript,
        1,
        "peerless_origins",
        "publisher+receiver",
        "unacknowledged-origin",
    )?;
    emit_subscription(
        &mut transcript,
        "peerless_origins",
        evidence.subscription,
        true,
    )?;
    emit_subscription(
        &mut transcript,
        "peerless_origins",
        evidence.subscription,
        false,
    )?;
    emit_publication(
        &mut transcript,
        "peerless_origins",
        "publisher",
        "alpha-left",
        &evidence.left,
        LEFT_PAYLOAD,
        false,
    )?;
    emit_publication(
        &mut transcript,
        "peerless_origins",
        "receiver",
        "alpha-right",
        &evidence.right,
        RIGHT_PAYLOAD,
        false,
    )?;
    emit_delivery(
        &mut transcript,
        "peerless_origins",
        "receiver",
        "alpha-right",
        &evidence.initial_delivery,
    )?;
    emit_projection(
        &mut transcript,
        "peerless_origins",
        "publisher",
        "alpha",
        &evidence.initial_projections[0],
    )?;
    emit_projection(
        &mut transcript,
        "peerless_origins",
        "receiver",
        "alpha",
        &evidence.initial_projections[1],
    )?;
    emit_receipt(
        &mut transcript,
        receipt(evidence, "peerless_origins", "publisher")?,
    )?;
    emit_receipt(
        &mut transcript,
        receipt(evidence, "peerless_origins", "receiver")?,
    )?;

    // Phase 2: records 16-28.
    emit_phase(
        &mut transcript,
        2,
        "direct_convergence_and_successor",
        "publisher+receiver",
        "successor-and-selectors",
    )?;
    emit_subscription(
        &mut transcript,
        "direct_convergence_and_successor",
        evidence.subscription,
        false,
    )?;
    emit_projection(
        &mut transcript,
        "direct_convergence_and_successor",
        "publisher",
        "alpha-concurrent",
        &evidence.concurrent_projections[0],
    )?;
    emit_projection(
        &mut transcript,
        "direct_convergence_and_successor",
        "receiver",
        "alpha-concurrent",
        &evidence.concurrent_projections[1],
    )?;
    emit_publication(
        &mut transcript,
        "direct_convergence_and_successor",
        "publisher",
        "alpha-successor",
        &evidence.successor,
        SUCCESSOR_PAYLOAD,
        false,
    )?;
    emit_projection(
        &mut transcript,
        "direct_convergence_and_successor",
        "publisher",
        "alpha-successor",
        &evidence.successor_projections[0],
    )?;
    emit_projection(
        &mut transcript,
        "direct_convergence_and_successor",
        "receiver",
        "alpha-successor",
        &evidence.successor_projections[1],
    )?;
    emit_publication(
        &mut transcript,
        "direct_convergence_and_successor",
        "publisher",
        "beta",
        &evidence.beta,
        BETA_PAYLOAD,
        false,
    )?;
    emit_publication(
        &mut transcript,
        "direct_convergence_and_successor",
        "publisher",
        "gamma",
        &evidence.gamma,
        GAMMA_PAYLOAD,
        false,
    )?;
    emit_selector(
        &mut transcript,
        "direct_convergence_and_successor",
        "beta",
        evidence.beta.id,
        true,
        true,
        false,
    )?;
    emit_selector(
        &mut transcript,
        "direct_convergence_and_successor",
        "gamma",
        evidence.gamma.id,
        false,
        false,
        false,
    )?;
    emit_receipt(
        &mut transcript,
        receipt(evidence, "direct_convergence_and_successor", "publisher")?,
    )?;
    emit_receipt(
        &mut transcript,
        receipt(evidence, "direct_convergence_and_successor", "receiver")?,
    )?;

    // Phase 3: records 29-33.
    emit_phase(
        &mut transcript,
        3,
        "forced_successor_delivery",
        "receiver-child",
        "force-terminated",
    )?;
    emit_subscription(
        &mut transcript,
        "forced_successor_delivery",
        evidence.subscription,
        false,
    )?;
    emit_projection(
        &mut transcript,
        "forced_successor_delivery",
        "receiver",
        "alpha-successor-child-validated",
        &evidence.successor_projections[1],
    )?;
    emit_child_delivery(
        &mut transcript,
        "forced_successor_delivery",
        &evidence.attempt_one,
    )?;
    transcript.emit(
        "process_termination",
        &[
            ("phase", "forced_successor_delivery".to_owned()),
            ("participant", "receiver".to_owned()),
            ("mechanism", "parent-child-kill".to_owned()),
            ("termination_signal", "sigkill".to_owned()),
            ("distinct_process", "true".to_owned()),
            ("after_flushed_poll", "true".to_owned()),
            ("graceful", "false".to_owned()),
            ("stop_record_expected", "false".to_owned()),
            ("stop_record_observed", "false".to_owned()),
            ("acknowledged", "false".to_owned()),
            ("token_persisted", "true".to_owned()),
            ("token_artifact_permissions", "owner-only".to_owned()),
            ("token_representation", "sha256-only".to_owned()),
        ],
    )?;

    // Phase 4: records 34-40.
    emit_phase(
        &mut transcript,
        4,
        "peerless_redelivery_ack",
        "receiver-child",
        "acknowledged",
    )?;
    emit_subscription(
        &mut transcript,
        "peerless_redelivery_ack",
        evidence.subscription,
        false,
    )?;
    emit_child_delivery(
        &mut transcript,
        "peerless_redelivery_ack",
        &evidence.attempt_two,
    )?;
    emit_child_ack(
        &mut transcript,
        "acknowledgement",
        "peerless_redelivery_ack",
        &evidence.attempt_two,
        "ack",
        "previous_token_sha256",
        "1",
    )?;
    emit_child_ack(
        &mut transcript,
        "reacknowledgement",
        "peerless_redelivery_ack",
        &evidence.attempt_two,
        "reack",
        "successor_token_sha256",
        "2",
    )?;
    emit_empty(&mut transcript, "peerless_redelivery_ack", "receiver")?;
    emit_child_shutdown(
        &mut transcript,
        "peerless_redelivery_ack",
        &evidence.attempt_two,
    )?;

    // Phase 5: records 41-49.
    emit_phase(
        &mut transcript,
        5,
        "peerless_tombstone",
        "receiver",
        "explicit-current-tombstone",
    )?;
    emit_subscription(
        &mut transcript,
        "peerless_tombstone",
        evidence.subscription,
        false,
    )?;
    emit_publication(
        &mut transcript,
        "peerless_tombstone",
        "receiver",
        "alpha-tombstone",
        &evidence.tombstone,
        TOMBSTONE_PAYLOAD,
        true,
    )?;
    emit_delivery(
        &mut transcript,
        "peerless_tombstone",
        "receiver",
        "alpha-tombstone",
        &evidence.tombstone_delivery,
    )?;
    emit_ack(
        &mut transcript,
        "acknowledgement",
        "peerless_tombstone",
        evidence.tombstone.id,
        evidence.tombstone_delivery.token,
        1,
        evidence.tombstone_ack,
    )?;
    emit_ack(
        &mut transcript,
        "reacknowledgement",
        "peerless_tombstone",
        evidence.tombstone.id,
        evidence.tombstone_delivery.token,
        1,
        evidence.tombstone_reack,
    )?;
    emit_empty(&mut transcript, "peerless_tombstone", "receiver")?;
    emit_projection(
        &mut transcript,
        "peerless_tombstone",
        "receiver",
        "alpha-tombstone",
        &evidence.tombstone_local_projection,
    )?;
    emit_receipt(
        &mut transcript,
        receipt(evidence, "peerless_tombstone", "receiver")?,
    )?;

    // Phase 6: records 50-58.
    emit_phase(
        &mut transcript,
        6,
        "direct_tombstone_propagation",
        "publisher+receiver",
        "converged-empty",
    )?;
    emit_subscription(
        &mut transcript,
        "direct_tombstone_propagation",
        evidence.subscription,
        false,
    )?;
    emit_projection(
        &mut transcript,
        "direct_tombstone_propagation",
        "publisher",
        "alpha-tombstone",
        &evidence.tombstone_network_projections[0],
    )?;
    emit_projection(
        &mut transcript,
        "direct_tombstone_propagation",
        "receiver",
        "alpha-tombstone",
        &evidence.tombstone_network_projections[1],
    )?;
    emit_selector(
        &mut transcript,
        "direct_tombstone_propagation",
        "beta",
        evidence.beta.id,
        true,
        true,
        false,
    )?;
    emit_selector(
        &mut transcript,
        "direct_tombstone_propagation",
        "gamma",
        evidence.gamma.id,
        false,
        false,
        false,
    )?;
    emit_empty(&mut transcript, "direct_tombstone_propagation", "receiver")?;
    emit_receipt(
        &mut transcript,
        receipt(evidence, "direct_tombstone_propagation", "publisher")?,
    )?;
    emit_receipt(
        &mut transcript,
        receipt(evidence, "direct_tombstone_propagation", "receiver")?,
    )?;

    // Phase 7: records 59-70.
    emit_phase(
        &mut transcript,
        7,
        "final_peerless_reopen",
        "receiver",
        "durable-empty",
    )?;
    emit_subscription(
        &mut transcript,
        "final_peerless_reopen",
        evidence.subscription,
        false,
    )?;
    emit_projection(
        &mut transcript,
        "final_peerless_reopen",
        "receiver",
        "alpha-tombstone",
        &evidence.final_projection,
    )?;
    emit_selector(
        &mut transcript,
        "final_peerless_reopen",
        "beta",
        evidence.beta.id,
        true,
        true,
        false,
    )?;
    emit_selector(
        &mut transcript,
        "final_peerless_reopen",
        "gamma",
        evidence.gamma.id,
        false,
        false,
        false,
    )?;
    emit_empty(&mut transcript, "final_peerless_reopen", "receiver")?;
    emit_receipt(
        &mut transcript,
        receipt(evidence, "final_peerless_reopen", "receiver")?,
    )?;
    emit_inspection(&mut transcript, "publisher", &evidence.inspections[0])?;
    emit_inspection(&mut transcript, "receiver", &evidence.inspections[1])?;
    emit_bind(&mut transcript, "publisher")?;
    emit_bind(&mut transcript, "receiver")?;
    transcript.emit(
        "result",
        &[
            ("status", "pass".to_owned()),
            ("records", TRANSCRIPT_RECORDS.to_string()),
            ("phases", "7".to_owned()),
            ("participants", "2".to_owned()),
            ("processes", "3".to_owned()),
            ("actor_lifetimes", "10".to_owned()),
            ("maximum_concurrent_actors", "2".to_owned()),
            ("graceful_shutdowns", "9".to_owned()),
            ("forced_process_terminations", "1".to_owned()),
            ("closed_handles", "9".to_owned()),
            ("state_publications", "6".to_owned()),
            ("network_state_insertions", "5".to_owned()),
            ("deliveries", "4".to_owned()),
            ("acknowledgements", "2".to_owned()),
            ("reacknowledgements", "2".to_owned()),
            ("token_binding_checks", "8".to_owned()),
            ("malformed_token_rejected", "true".to_owned()),
            ("wrong_subscription_token_rejected", "true".to_owned()),
            ("wrong_state_token_rejected", "true".to_owned()),
            ("retired_token_rejected", "true".to_owned()),
            ("empty_polls", "4".to_owned()),
            ("subscription_insertions", "1".to_owned()),
            ("subscription_replays", "7".to_owned()),
            ("bind_reacquisitions", "2".to_owned()),
            ("payload_representation", "sha256-only".to_owned()),
            ("token_representation", "sha256-only".to_owned()),
            ("opaque_tokens_emitted", "false".to_owned()),
            ("secret_values_emitted", "false".to_owned()),
            ("physical_network_claimed", "false".to_owned()),
            ("global_convergence_claimed", "false".to_owned()),
        ],
    )?;
    require(
        transcript.records == TRANSCRIPT_RECORDS,
        "State transcript record count",
    )?;
    std::io::stdout().flush()?;
    Ok(())
}

fn emit_participant(
    transcript: &mut TranscriptEmitter,
    participant: &Participant,
) -> Result<(), DynError> {
    transcript.emit(
        "participant",
        &[
            ("participant", participant.name.to_owned()),
            ("carrier_id", participant.carrier_id.to_string()),
            ("mission_id", format_node_id(participant.mission_id)),
            (
                "mission_authority",
                format_node_id(participant.mission_authority),
            ),
            ("provisioning", "independent-reference-bundle".to_owned()),
        ],
    )
}

fn emit_peer_binding(
    transcript: &mut TranscriptEmitter,
    local: &Participant,
    remote: &Participant,
) -> Result<(), DynError> {
    transcript.emit(
        "peer_binding",
        &[
            ("local", local.name.to_owned()),
            ("remote", remote.name.to_owned()),
            ("local_carrier", local.carrier_id.to_string()),
            ("local_mission", format_node_id(local.mission_id)),
            ("remote_carrier", remote.carrier_id.to_string()),
            ("remote_mission", format_node_id(remote.mission_id)),
            ("mission_authenticated", "true".to_owned()),
        ],
    )
}

fn emit_phase(
    transcript: &mut TranscriptEmitter,
    index: usize,
    phase: &str,
    actors: &str,
    outcome: &str,
) -> Result<(), DynError> {
    transcript.emit(
        "phase",
        &[
            ("index", index.to_string()),
            ("phase", phase.to_owned()),
            ("actors", actors.to_owned()),
            ("outcome", outcome.to_owned()),
        ],
    )
}

fn emit_subscription(
    transcript: &mut TranscriptEmitter,
    phase: &str,
    subscription: StateSubscription,
    inserted: bool,
) -> Result<(), DynError> {
    transcript.emit(
        "subscription",
        &[
            ("phase", phase.to_owned()),
            ("participant", "receiver".to_owned()),
            ("stream", "alpha".to_owned()),
            ("id", subscription.id.to_string()),
            ("inserted", inserted.to_string()),
            ("durable", "true".to_owned()),
            ("include_descendant_scopes", "false".to_owned()),
        ],
    )
}

fn emit_publication(
    transcript: &mut TranscriptEmitter,
    phase: &str,
    participant: &str,
    stream: &str,
    publication: &StatePublishResult,
    payload: &[u8],
    tombstone: bool,
) -> Result<(), DynError> {
    transcript.emit(
        "state",
        &[
            ("phase", phase.to_owned()),
            ("participant", participant.to_owned()),
            ("stream", stream.to_owned()),
            ("id", publication.id.to_string()),
            ("publisher", format_node_id(publication.publisher)),
            (
                "publisher_counter",
                publication.publisher_counter.to_string(),
            ),
            ("priority", "priority".to_owned()),
            (
                "acceptance_marker",
                publication.acceptance_marker.to_string(),
            ),
            ("inserted", publication.inserted.to_string()),
            ("tombstone", tombstone.to_string()),
            ("payload_sha256", sha256_hex(payload)),
        ],
    )
}

fn emit_delivery(
    transcript: &mut TranscriptEmitter,
    phase: &str,
    participant: &str,
    stream: &str,
    delivery: &StateDelivery,
) -> Result<(), DynError> {
    transcript.emit(
        "delivery",
        &[
            ("phase", phase.to_owned()),
            ("participant", participant.to_owned()),
            ("stream", stream.to_owned()),
            ("id", delivery.state.id.to_string()),
            ("publisher", format_node_id(delivery.state.publisher)),
            (
                "publisher_counter",
                delivery.state.publisher_counter.to_string(),
            ),
            ("attempt", delivery.attempt.to_string()),
            ("token_sha256", sha256_hex(delivery.token.as_bytes())),
            (
                "disposition",
                disposition_name(delivery.state.disposition).to_owned(),
            ),
            ("tombstone", delivery.state.tombstone.to_string()),
            ("payload_sha256", sha256_hex(&delivery.state.payload)),
        ],
    )
}

fn emit_child_delivery(
    transcript: &mut TranscriptEmitter,
    phase: &str,
    fields: &ChildFields,
) -> Result<(), DynError> {
    transcript.emit(
        "delivery",
        &[
            ("phase", phase.to_owned()),
            ("participant", "receiver".to_owned()),
            ("stream", "alpha-successor".to_owned()),
            ("id", child_field(fields, "successor_id")?.to_owned()),
            (
                "publisher",
                child_field(fields, "successor_publisher")?.to_owned(),
            ),
            (
                "publisher_counter",
                child_field(fields, "successor_counter")?.to_owned(),
            ),
            (
                "attempt",
                child_field(fields, "successor_attempt")?.to_owned(),
            ),
            (
                "token_sha256",
                child_field(fields, "successor_token_sha256")?.to_owned(),
            ),
            (
                "disposition",
                child_field(fields, "successor_disposition")?.to_owned(),
            ),
            (
                "tombstone",
                child_field(fields, "successor_tombstone")?.to_owned(),
            ),
            (
                "payload_sha256",
                child_field(fields, "successor_payload_sha256")?.to_owned(),
            ),
        ],
    )
}

fn emit_projection(
    transcript: &mut TranscriptEmitter,
    phase: &str,
    participant: &str,
    stream: &str,
    projection: &StateProjection,
) -> Result<(), DynError> {
    let current = projection.current.as_ref();
    let mut recoverable = projection.recoverable.iter().collect::<Vec<_>>();
    recoverable.sort_by_key(|item| item.id);
    transcript.emit(
        "projection",
        &[
            ("phase", phase.to_owned()),
            ("participant", participant.to_owned()),
            ("stream", stream.to_owned()),
            (
                "current_id",
                current.map_or_else(|| "none".to_owned(), |item| item.id.to_string()),
            ),
            (
                "current_publisher",
                current.map_or_else(|| "none".to_owned(), |item| format_node_id(item.publisher)),
            ),
            (
                "current_counter",
                current.map_or_else(|| "0".to_owned(), |item| item.publisher_counter.to_string()),
            ),
            (
                "current_disposition",
                current
                    .map_or("none", |item| disposition_name(item.disposition))
                    .to_owned(),
            ),
            (
                "current_tombstone",
                current.is_some_and(|item| item.tombstone).to_string(),
            ),
            (
                "current_payload_sha256",
                current.map_or_else(|| "none".to_owned(), |item| sha256_hex(&item.payload)),
            ),
            ("recoverable_count", recoverable.len().to_string()),
            (
                "recoverable_ids",
                joined_or_none(recoverable.iter().map(|item| item.id.to_string())),
            ),
            (
                "recoverable_dispositions",
                joined_or_none(
                    recoverable
                        .iter()
                        .map(|item| disposition_name(item.disposition).to_owned()),
                ),
            ),
            (
                "recoverable_tombstones",
                joined_or_none(recoverable.iter().map(|item| item.tombstone.to_string())),
            ),
            (
                "recoverable_payload_sha256",
                joined_or_none(recoverable.iter().map(|item| sha256_hex(&item.payload))),
            ),
        ],
    )
}

fn joined_or_none(values: impl IntoIterator<Item = String>) -> String {
    let values = values.into_iter().collect::<Vec<_>>();
    if values.is_empty() {
        "none".to_owned()
    } else {
        values.join(",")
    }
}

fn emit_selector(
    transcript: &mut TranscriptEmitter,
    phase: &str,
    stream: &str,
    id: StateId,
    network_interested: bool,
    receiver_retained: bool,
    application_delivered: bool,
) -> Result<(), DynError> {
    transcript.emit(
        "selector",
        &[
            ("phase", phase.to_owned()),
            ("stream", stream.to_owned()),
            ("id", id.to_string()),
            ("publisher_retained", "true".to_owned()),
            ("network_interested", network_interested.to_string()),
            ("receiver_retained", receiver_retained.to_string()),
            (
                "alpha_application_delivered",
                application_delivered.to_string(),
            ),
        ],
    )
}

fn emit_ack(
    transcript: &mut TranscriptEmitter,
    kind: &str,
    phase: &str,
    id: StateId,
    token: StateDeliveryToken,
    token_attempt: u64,
    acknowledgement: StateAcknowledgement,
) -> Result<(), DynError> {
    transcript.emit(
        kind,
        &[
            ("phase", phase.to_owned()),
            ("participant", "receiver".to_owned()),
            ("id", id.to_string()),
            ("token_sha256", sha256_hex(token.as_bytes())),
            ("token_attempt", token_attempt.to_string()),
            (
                "disposition",
                acknowledgement_name(acknowledgement).to_owned(),
            ),
        ],
    )
}

fn emit_child_ack(
    transcript: &mut TranscriptEmitter,
    kind: &str,
    phase: &str,
    fields: &ChildFields,
    disposition_key: &'static str,
    token_digest_key: &'static str,
    token_attempt: &'static str,
) -> Result<(), DynError> {
    transcript.emit(
        kind,
        &[
            ("phase", phase.to_owned()),
            ("participant", "receiver".to_owned()),
            ("id", child_field(fields, "successor_id")?.to_owned()),
            (
                "token_sha256",
                child_field(fields, token_digest_key)?.to_owned(),
            ),
            ("token_attempt", token_attempt.to_owned()),
            (
                "disposition",
                child_field(fields, disposition_key)?.to_owned(),
            ),
        ],
    )
}

fn emit_empty(
    transcript: &mut TranscriptEmitter,
    phase: &str,
    participant: &str,
) -> Result<(), DynError> {
    transcript.emit(
        "empty_poll",
        &[
            ("phase", phase.to_owned()),
            ("participant", participant.to_owned()),
            ("deliveries", "0".to_owned()),
            ("has_more", "false".to_owned()),
            ("delivery_limit", "8".to_owned()),
            ("scan_limit", "16".to_owned()),
        ],
    )
}

fn receipt<'a>(
    evidence: &'a AcceptanceEvidence,
    phase: &str,
    participant: &str,
) -> Result<&'a ReceiptEvidence, DynError> {
    evidence
        .receipts
        .iter()
        .find(|receipt| receipt.phase == phase && receipt.participant == participant)
        .ok_or_else(|| Box::new(AcceptanceFailure("missing shutdown receipt")) as DynError)
}

fn emit_receipt(
    transcript: &mut TranscriptEmitter,
    evidence: &ReceiptEvidence,
) -> Result<(), DynError> {
    transcript.emit(
        "shutdown",
        &[
            ("phase", evidence.phase.to_owned()),
            ("participant", evidence.participant.to_owned()),
            ("contacts", evidence.receipt.contacts.to_string()),
            (
                "contact_errors",
                evidence.receipt.contact_errors.to_string(),
            ),
            (
                "direct_contacts",
                evidence.receipt.direct_contacts.to_string(),
            ),
            (
                "relay_contacts",
                evidence.receipt.relay_contacts.to_string(),
            ),
            (
                "unknown_path_contacts",
                evidence.receipt.unknown_path_contacts.to_string(),
            ),
            ("data_offered", evidence.receipt.data_offered.to_string()),
            ("data_fetched", evidence.receipt.data_fetched.to_string()),
            ("data_inserted", evidence.receipt.data_inserted.to_string()),
            (
                "data_duplicates",
                evidence.receipt.data_duplicates.to_string(),
            ),
            (
                "data_remaining",
                evidence.receipt.data_remaining.to_string(),
            ),
            (
                "mutable_remaining",
                evidence.receipt.mutable_remaining.to_string(),
            ),
            (
                "deferred_mutable_lanes",
                evidence.receipt.deferred_mutable_lanes.to_string(),
            ),
            ("excluded_class_counters", "all-zero".to_owned()),
        ],
    )
}

fn emit_child_shutdown(
    transcript: &mut TranscriptEmitter,
    phase: &str,
    fields: &ChildFields,
) -> Result<(), DynError> {
    transcript.emit(
        "shutdown",
        &[
            ("phase", phase.to_owned()),
            ("participant", "receiver".to_owned()),
            (
                "contacts",
                child_field(fields, "shutdown_contacts")?.to_owned(),
            ),
            (
                "contact_errors",
                child_field(fields, "shutdown_contact_errors")?.to_owned(),
            ),
            (
                "direct_contacts",
                child_field(fields, "shutdown_direct_contacts")?.to_owned(),
            ),
            (
                "relay_contacts",
                child_field(fields, "shutdown_relay_contacts")?.to_owned(),
            ),
            (
                "unknown_path_contacts",
                child_field(fields, "shutdown_unknown_path_contacts")?.to_owned(),
            ),
            (
                "data_offered",
                child_field(fields, "shutdown_data_offered")?.to_owned(),
            ),
            (
                "data_fetched",
                child_field(fields, "shutdown_data_fetched")?.to_owned(),
            ),
            (
                "data_inserted",
                child_field(fields, "shutdown_data_inserted")?.to_owned(),
            ),
            (
                "data_duplicates",
                child_field(fields, "shutdown_data_duplicates")?.to_owned(),
            ),
            (
                "data_remaining",
                child_field(fields, "shutdown_data_remaining")?.to_owned(),
            ),
            (
                "mutable_remaining",
                child_field(fields, "shutdown_mutable_remaining")?.to_owned(),
            ),
            (
                "deferred_mutable_lanes",
                child_field(fields, "shutdown_deferred_mutable_lanes")?.to_owned(),
            ),
            ("excluded_class_counters", "all-zero".to_owned()),
        ],
    )
}

fn emit_inspection(
    transcript: &mut TranscriptEmitter,
    participant: &str,
    inspection: &StoreInspection,
) -> Result<(), DynError> {
    transcript.emit(
        "store_inspection",
        &[
            ("participant", participant.to_owned()),
            ("states", inspection.state_stats.states.to_string()),
            (
                "state_acceptance_markers",
                inspection.state_stats.acceptance_markers.to_string(),
            ),
            (
                "state_operations",
                inspection.state_stats.operations.to_string(),
            ),
            (
                "subscriptions",
                inspection
                    .state_subscription_stats
                    .subscriptions
                    .to_string(),
            ),
            (
                "pending_deliveries",
                inspection
                    .state_subscription_stats
                    .pending_deliveries
                    .to_string(),
            ),
            (
                "acknowledged_deliveries",
                inspection
                    .state_subscription_stats
                    .acknowledged_deliveries
                    .to_string(),
            ),
            (
                "delivery_cursors",
                inspection
                    .state_subscription_stats
                    .delivery_cursors
                    .to_string(),
            ),
            (
                "selector_generation",
                inspection
                    .state_subscription_stats
                    .selector_generation
                    .to_string(),
            ),
            ("event_record_blob_opaque_control", "all-zero".to_owned()),
        ],
    )
}

fn emit_bind(transcript: &mut TranscriptEmitter, participant: &str) -> Result<(), DynError> {
    transcript.emit(
        "bind",
        &[
            ("participant", participant.to_owned()),
            ("status", "reacquired".to_owned()),
        ],
    )
}
