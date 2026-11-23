//! Retained peerless acceptance producer for durable Blob metadata delivery.
//!
//! One mission-bound participant publishes two exact source publications that
//! share an immutable `BlobId`. The receiver process is replaced between
//! durable delivery attempts. The producer emits bounded ASCII metadata and
//! payload/token digests only; Blob
//! plaintext never crosses the delivery boundary.

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

use aster_iroh::EndpointId;
use aster_mesh::{ProvisioningAccess, ReferenceProvisioner};
use aster_node::{
    MutableSourceInterests, NodeApplication, NodeConfig, NodeIdentity, NodeReceipt,
    application::{
        ApplicationErrorKind, BLOB_DELIVERY_TOKEN_BYTES, BlobAcknowledgement, BlobDelivery,
        BlobDeliveryStatus, BlobDeliveryToken, BlobId, BlobPollRequest, BlobPublishRequest,
        BlobPublishResult, BlobSubscription, BlobSubscriptionId, BlobSubscriptionRequest, Priority,
        Scope, SelectedBlobHandle, Topic,
    },
    format_node_id,
    mission::UnprotectedReferenceMission,
    start_node,
};
use aster_redb_store::{Store, StoreInspection};
use sha2::{Digest as _, Sha256};
use tokio::{sync::mpsc::UnboundedReceiver, time::timeout};
use zeroize::Zeroize as _;

pub const TRANSCRIPT_SCHEMA: &str = "aster-selected-live-blob-subscription-transcript/v1";
pub const RAW_SCHEMA: &str = "aster-selected-live-blob-subscription-raw/v1";
pub const RECEIPT_SCHEMA: &str = "aster-selected-live-blob-subscription-receipt/v1";
pub const CLAIM: &str = "selected-live-blob-subscription-one-host-peerless-exact-publication-shared-content-forced-receiver-process-termination-durable-redelivery-reopen-acceptance";
pub const TRANSCRIPT_PREFIX: &str = "LIVE_BLOB_SUBSCRIPTION";
pub const CHILD_PREFIX: &str = "LIVE_BLOB_SUBSCRIPTION_CHILD";
pub const TRANSCRIPT_RECORDS: usize = 35;
pub const PARTICIPANT: &str = "node";

const ALPHA_TOPIC: &str = "opaque";
const ROOT_SCOPE: &str = "test/runtime-contact";
const MEDIA_TYPE: &str = "application/x-aster-live-blob-subscription-acceptance";
const SCHEMA_ID: &[u8] = b"acceptance/live-blob-subscription-v1";
const SHARED_PAYLOAD: &[u8] = b"shared immutable Blob delivery payload";
const MATCHING_A_OPERATION: &[u8] = b"acceptance/blob-subscription/matching-a";
const MATCHING_B_OPERATION: &[u8] = b"acceptance/blob-subscription/matching-b";
const SUBSCRIPTION_OPERATION: &[u8] = b"acceptance/blob-subscription/selector";
const DELIVERY_LIMIT: usize = 1;
const SCAN_LIMIT: usize = 16;
const CHILD_DEADLINE: Duration = Duration::from_secs(40);
const SYNC_INTERVAL: Duration = Duration::from_secs(5);
const STORE_FILE: &str = "mesh.redb";

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
    root: PathBuf,
    state: PathBuf,
    mission_path: PathBuf,
    mission: Option<UnprotectedReferenceMission>,
    mission_id: [u8; 32],
    mission_authority: [u8; 32],
    carrier_id: EndpointId,
}

struct ChildActor {
    child: Child,
    lines: UnboundedReceiver<Result<String, std::io::Error>>,
    saw_runtime_stop: bool,
}

impl Drop for ChildActor {
    fn drop(&mut self) {
        if !matches!(self.child.try_wait(), Ok(Some(_))) {
            let _ = self.child.kill();
            let _ = self.child.wait();
        }
    }
}

struct AcceptanceEvidence {
    subscription: BlobSubscription,
    publications: [BlobPublishResult; 2],
    initial_status: BlobDeliveryStatus,
    attempt_one: ChildFields,
    attempt_two: ChildFields,
    final_status: BlobDeliveryStatus,
    initial_receipt: NodeReceipt,
    final_receipt: NodeReceipt,
    inspection: StoreInspection,
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
        let prefix = if child_mode {
            "LIVE_BLOB_SUBSCRIPTION_CHILD_FAILURE"
        } else {
            "LIVE_BLOB_SUBSCRIPTION_FAILURE"
        };
        eprintln!("{prefix} status=error stage={stage}");
        std::process::exit(1);
    }
}

fn failure_stage(error: &(dyn Error + 'static)) -> String {
    let stage = if let Some(failure) = error.downcast_ref::<AcceptanceFailure>() {
        failure.0.to_owned()
    } else if let Some(failure) = error.downcast_ref::<aster_node::application::ApplicationError>()
    {
        format!("application_{:?}_{}", failure.kind(), failure.operation())
    } else {
        "runtime".to_owned()
    };
    stage.replace(' ', "_").to_ascii_lowercase()
}

async fn run_parent(arguments: &[OsString]) -> Result<(), DynError> {
    require(arguments.len() == 1, "unexpected arguments")?;
    let raw_root = canonical_raw_root(PathBuf::from(&arguments[0]))?;
    run_acceptance(raw_root).await
}

async fn run_child(arguments: &[OsString]) -> Result<(), DynError> {
    match arguments.first().and_then(|argument| argument.to_str()) {
        Some("--internal-attempt-1") => run_attempt_one_child(&arguments[1..]).await,
        Some("--internal-attempt-2") => run_attempt_two_child(&arguments[1..]).await,
        _ => Err(Box::new(AcceptanceFailure("unknown internal child mode"))),
    }
}

struct TranscriptEmitter {
    records: usize,
}

impl TranscriptEmitter {
    const fn new() -> Self {
        Self { records: 0 }
    }

    fn emit(&mut self, kind: &str, fields: &[(&str, String)]) -> Result<(), DynError> {
        require(valid_field(kind), "transcript record kind")?;
        print!("{TRANSCRIPT_PREFIX}\t{kind}");
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

fn subscription_request(
    topic: &Topic,
    scope: &Scope,
    include_descendant_scopes: bool,
) -> BlobSubscriptionRequest {
    BlobSubscriptionRequest {
        operation_key: SUBSCRIPTION_OPERATION.to_vec(),
        topic: topic.clone(),
        scope: scope.clone(),
        include_descendant_scopes,
    }
}

fn publish_request(
    operation: &[u8],
    topic: &Topic,
    scope: &Scope,
    priority: Priority,
) -> BlobPublishRequest {
    BlobPublishRequest {
        operation_key: operation.to_vec(),
        topic: topic.clone(),
        scope: scope.clone(),
        priority,
        media_type: Some(MEDIA_TYPE.to_owned()),
        schema_id: SCHEMA_ID.to_vec(),
    }
}

async fn poll(
    blobs: &SelectedBlobHandle,
    subscription: BlobSubscription,
) -> Result<aster_node::application::BlobDeliveryPage, aster_node::application::ApplicationError> {
    blobs
        .poll(BlobPollRequest {
            subscription: subscription.id,
            delivery_limit: DELIVERY_LIMIT,
            scan_limit: SCAN_LIMIT,
        })
        .await
}

async fn run_acceptance(raw_root: PathBuf) -> Result<(), DynError> {
    require(BLOB_DELIVERY_TOKEN_BYTES == 57, "Blob delivery token width")?;
    let topic = Topic::new(ALPHA_TOPIC)?;
    let scope = Scope::new(ROOT_SCOPE)?;
    let participants_root = raw_root.join("participants");
    create_owner_directory(&participants_root)?;
    let mut participant = provision_participant(&participants_root, &topic, &scope)?;

    let bind_reservation = UdpSocket::bind(("127.0.0.1", 0))?;
    let bind_address = bind_reservation.local_addr()?;
    drop(bind_reservation);

    let source_path = raw_root.join("blob-subscription-source.bin");
    write_source(&source_path, SHARED_PAYLOAD)?;

    let initial = start_peerless(&participant, bind_address).await?;
    let blobs = initial.selected_blobs();
    validate_handle(&participant, &blobs)?;
    let subscription = blobs
        .subscribe(subscription_request(&topic, &scope, false))
        .await?;
    require(subscription.inserted, "initial Blob subscription insertion")?;
    let replay = blobs
        .subscribe(subscription_request(&topic, &scope, false))
        .await?;
    require(
        !replay.inserted && replay.id == subscription.id,
        "initial Blob subscription replay",
    )?;
    let changed = blobs
        .subscribe(subscription_request(&topic, &scope, true))
        .await
        .expect_err("changed Blob subscription operation must conflict");
    require(
        changed.kind() == ApplicationErrorKind::Conflict && changed.operation() == "blob subscribe",
        "changed Blob subscription conflict",
    )?;

    let matching_a = blobs
        .publish(
            publish_request(MATCHING_A_OPERATION, &topic, &scope, Priority::Priority),
            fs::File::open(&source_path)?,
        )
        .await?;
    let matching_b = blobs
        .publish(
            publish_request(MATCHING_B_OPERATION, &topic, &scope, Priority::Immediate),
            fs::File::open(&source_path)?,
        )
        .await?;
    let publications = [matching_a, matching_b];
    validate_publications(&participant, &publications)?;
    fs::remove_file(&source_path)?;
    sync_directory(&raw_root)?;
    require(!source_path.exists(), "Blob plaintext source removal")?;

    let initial_status = blobs.delivery_status().await?;
    validate_status(
        initial_status,
        [1, 0, 0, 0, 1],
        "initial Blob delivery status",
    )?;
    let retained_initial = blobs.clone();
    let initial_receipt = initial.shutdown().await?;
    validate_peerless_receipt(&initial_receipt)?;
    validate_closed_handle(&retained_initial).await?;
    drop((blobs, retained_initial));

    // Child processes must exclusively load the same process-lifetime mission artifact.
    drop(participant.mission.take());
    let token_path = participant.root.join("attempt-one.blob-token");
    let mut attempt_one = spawn_attempt_one(
        &participant,
        &token_path,
        subscription.id,
        publications[0].id,
    )?;
    let attempt_one_pid = attempt_one.child.id();
    let attempt_one_fields = wait_child_record(&mut attempt_one, "ATTEMPT1_READY").await?;
    validate_attempt_one_fields(
        &attempt_one_fields,
        &participant,
        subscription.id,
        &publications,
    )?;
    validate_token_artifact(
        &token_path,
        child_field(&attempt_one_fields, "token_sha256")?,
    )?;
    attempt_one.child.kill()?;
    drain_child_lines(&mut attempt_one).await?;
    let killed_status = attempt_one.child.wait()?;
    validate_forced_child_termination(
        attempt_one_pid,
        killed_status,
        attempt_one.saw_runtime_stop,
    )?;

    let mut attempt_two = spawn_attempt_two(
        &participant,
        &token_path,
        subscription.id,
        publications[0].id,
    )?;
    let attempt_two_fields = wait_child_record(&mut attempt_two, "ATTEMPT2_DONE").await?;
    drain_child_lines(&mut attempt_two).await?;
    let attempt_two_status = attempt_two.child.wait()?;
    require(
        attempt_two_status.success() && attempt_two.saw_runtime_stop,
        "Blob retry child failed",
    )?;
    validate_attempt_two_fields(
        &attempt_two_fields,
        &participant,
        subscription.id,
        &publications,
        child_field(&attempt_one_fields, "publication_id")?,
    )?;
    require(!token_path.exists(), "Blob token artifact survived retry")?;

    participant.mission = Some(UnprotectedReferenceMission::load(
        &participant.mission_path,
    )?);
    let final_running = start_peerless(&participant, bind_address).await?;
    let final_blobs = final_running.selected_blobs();
    validate_handle(&participant, &final_blobs)?;
    let final_subscription = final_blobs
        .subscribe(subscription_request(&topic, &scope, false))
        .await?;
    require(
        !final_subscription.inserted && final_subscription.id == subscription.id,
        "final Blob subscription replay",
    )?;
    validate_empty_poll(&final_blobs, subscription).await?;
    let final_status = final_blobs.delivery_status().await?;
    validate_status(final_status, [1, 0, 2, 2, 1], "final Blob delivery status")?;
    let retained_final = final_blobs.clone();
    let final_receipt = final_running.shutdown().await?;
    validate_peerless_receipt(&final_receipt)?;
    validate_closed_handle(&retained_final).await?;
    drop((final_blobs, retained_final));

    let inspection = Store::inspect_existing(participant.state.join(STORE_FILE))?;
    validate_inspection(&inspection)?;
    validate_reacquired_bind(bind_address)?;
    emit_transcript(
        &participant,
        &AcceptanceEvidence {
            subscription,
            publications,
            initial_status,
            attempt_one: attempt_one_fields,
            attempt_two: attempt_two_fields,
            final_status,
            initial_receipt,
            final_receipt,
            inspection,
        },
    )?;
    Ok(())
}

async fn run_attempt_one_child(arguments: &[OsString]) -> Result<(), DynError> {
    require(arguments.len() == 5, "attempt-one child arguments")?;
    let state = PathBuf::from(&arguments[0]);
    let mission_path = PathBuf::from(&arguments[1]);
    let token_path = PathBuf::from(&arguments[2]);
    let expected_subscription = parse_blob_subscription_id(&arguments[3])?;
    let expected_blob = parse_blob_id(&arguments[4])?;
    let mission = UnprotectedReferenceMission::load(&mission_path)?;
    let identity = mission.identity();
    let authority = mission.mission_authority_id();
    let running = start_child_node(state, mission).await?;
    let blobs = running.selected_blobs();
    require(
        blobs.identity() == identity && blobs.mission_authority() == authority,
        "attempt-one child Blob handle binding",
    )?;
    let subscription = blobs
        .subscribe(subscription_request(
            &Topic::new(ALPHA_TOPIC)?,
            &Scope::new(ROOT_SCOPE)?,
            false,
        ))
        .await?;
    require(
        !subscription.inserted && subscription.id == expected_subscription,
        "attempt-one child Blob subscription replay",
    )?;
    let page = poll(&blobs, subscription).await?;
    require(
        page.deliveries.len() == 1 && page.has_more,
        "attempt-one Blob delivery count",
    )?;
    let delivery = page
        .deliveries
        .first()
        .ok_or(AcceptanceFailure("attempt-one Blob delivery missing"))?
        .content()
        .ok_or(AcceptanceFailure(
            "attempt-one unexpectedly returned a Blob retirement",
        ))?;
    validate_delivery(delivery, expected_blob, 1, 1, Priority::Priority)?;
    persist_delivery_token(&token_path, delivery.token)?;
    let status = blobs.delivery_status().await?;
    validate_status(status, [1, 1, 0, 1, 1], "attempt-one Blob delivery status")?;
    let mut fields = delivery_fields(delivery, "");
    fields.splice(
        0..0,
        [
            ("participant", PARTICIPANT.to_owned()),
            ("identity", format_node_id(identity)),
            ("subscription_id", subscription.id.to_string()),
            ("subscription_inserted", subscription.inserted.to_string()),
        ],
    );
    fields.extend([
        ("delivery_limit", DELIVERY_LIMIT.to_string()),
        ("scan_limit", SCAN_LIMIT.to_string()),
        ("has_more", page.has_more.to_string()),
        ("metadata_only", "true".to_owned()),
        ("acknowledged", "false".to_owned()),
        ("token_persisted", "true".to_owned()),
    ]);
    fields.extend(status_fields(status, ""));
    emit_child("ATTEMPT1_READY", &fields)?;
    std::future::pending::<()>().await;
    #[allow(unreachable_code)]
    Ok(())
}

async fn run_attempt_two_child(arguments: &[OsString]) -> Result<(), DynError> {
    require(arguments.len() == 5, "attempt-two child arguments")?;
    let state = PathBuf::from(&arguments[0]);
    let mission_path = PathBuf::from(&arguments[1]);
    let token_path = PathBuf::from(&arguments[2]);
    let expected_subscription = parse_blob_subscription_id(&arguments[3])?;
    let expected_blob = parse_blob_id(&arguments[4])?;
    let mission = UnprotectedReferenceMission::load(&mission_path)?;
    let identity = mission.identity();
    let running = start_child_node(state, mission).await?;
    let blobs = running.selected_blobs();
    let subscription = blobs
        .subscribe(subscription_request(
            &Topic::new(ALPHA_TOPIC)?,
            &Scope::new(ROOT_SCOPE)?,
            false,
        ))
        .await?;
    require(
        !subscription.inserted && subscription.id == expected_subscription,
        "attempt-two child Blob subscription replay",
    )?;
    let retry_page = poll(&blobs, subscription).await?;
    require(
        retry_page.deliveries.len() == 1 && retry_page.has_more,
        "attempt-two retry Blob delivery count",
    )?;
    let retry = retry_page
        .deliveries
        .first()
        .ok_or(AcceptanceFailure("attempt-two retry Blob delivery missing"))?
        .content()
        .ok_or(AcceptanceFailure(
            "attempt-two unexpectedly returned a Blob retirement",
        ))?
        .clone();
    validate_delivery(&retry, expected_blob, 1, 2, Priority::Priority)?;
    let previous_token = consume_delivery_token(&token_path)?;
    require(
        previous_token != retry.token,
        "Blob retry reused delivery token",
    )?;
    let malformed = BlobDeliveryToken::from_bytes([0_u8; BLOB_DELIVERY_TOKEN_BYTES])
        .expect_err("all-zero Blob delivery token must be rejected");
    require(
        malformed.kind() == ApplicationErrorKind::InvalidRequest
            && malformed.operation() == "blob delivery token",
        "malformed Blob delivery token rejection",
    )?;
    let first_ack = blobs
        .acknowledge(subscription.id, retry.publication, previous_token)
        .await?;
    let first_reack = blobs
        .acknowledge(subscription.id, retry.publication, retry.token)
        .await?;
    require(
        first_ack == BlobAcknowledgement::Acknowledged
            && first_reack == BlobAcknowledgement::AlreadyAcknowledged,
        "first Blob acknowledgements",
    )?;

    let second_page = poll(&blobs, subscription).await?;
    require(
        second_page.deliveries.len() == 1 && !second_page.has_more,
        "second Blob delivery count",
    )?;
    let second = second_page
        .deliveries
        .first()
        .ok_or(AcceptanceFailure("second Blob delivery missing"))?
        .content()
        .ok_or(AcceptanceFailure(
            "second poll unexpectedly returned a Blob retirement",
        ))?
        .clone();
    validate_delivery(&second, expected_blob, 2, 1, Priority::Immediate)?;
    require(
        retry.id == second.id && retry.publication != second.publication,
        "same Blob distinct publications",
    )?;
    let wrong_publication = blobs
        .acknowledge(subscription.id, second.publication, retry.token)
        .await
        .expect_err("Blob token must bind publication");
    require(
        wrong_publication.kind() == ApplicationErrorKind::InvalidRequest
            && wrong_publication.operation() == "blob acknowledge",
        "Blob token publication binding",
    )?;
    let second_ack = blobs
        .acknowledge(subscription.id, second.publication, second.token)
        .await?;
    let second_reack = blobs
        .acknowledge(subscription.id, second.publication, second.token)
        .await?;
    require(
        second_ack == BlobAcknowledgement::Acknowledged
            && second_reack == BlobAcknowledgement::AlreadyAcknowledged,
        "second Blob acknowledgements",
    )?;
    validate_empty_poll(&blobs, subscription).await?;
    let status = blobs.delivery_status().await?;
    validate_status(status, [1, 0, 2, 2, 1], "attempt-two Blob delivery status")?;
    require(!token_path.exists(), "Blob retry token removal")?;
    sync_directory(
        token_path
            .parent()
            .ok_or(AcceptanceFailure("Blob token parent missing"))?,
    )?;
    let retained = blobs.clone();
    let receipt = running.shutdown().await?;
    validate_peerless_receipt(&receipt)?;
    validate_closed_handle(&retained).await?;

    let mut fields = vec![
        ("participant", PARTICIPANT.to_owned()),
        ("identity", format_node_id(identity)),
        ("subscription_id", subscription.id.to_string()),
        ("subscription_inserted", subscription.inserted.to_string()),
    ];
    fields.extend(delivery_fields(&retry, "retry_"));
    fields.extend([
        (
            "previous_token_sha256",
            sha256_hex(previous_token.as_bytes()),
        ),
        ("tokens_distinct", "true".to_owned()),
        ("previous_token_restored", "true".to_owned()),
        ("malformed_token_rejected", "true".to_owned()),
        ("first_ack", acknowledgement_name(first_ack).to_owned()),
        ("first_reack", acknowledgement_name(first_reack).to_owned()),
        ("first_ack_token_attempt", "1".to_owned()),
        ("first_reack_token_attempt", "2".to_owned()),
    ]);
    fields.extend(delivery_fields(&second, "second_"));
    fields.extend([
        ("same_blob_id", "true".to_owned()),
        ("distinct_publications", "true".to_owned()),
        ("wrong_publication_token_rejected", "true".to_owned()),
        ("second_ack", acknowledgement_name(second_ack).to_owned()),
        (
            "second_reack",
            acknowledgement_name(second_reack).to_owned(),
        ),
        ("second_ack_token_attempt", "1".to_owned()),
        ("second_reack_token_attempt", "1".to_owned()),
        ("empty_poll", "true".to_owned()),
        ("token_artifact_removed", "true".to_owned()),
    ]);
    fields.extend(status_fields(status, ""));
    fields.extend([
        ("closed_kind", "state_unavailable".to_owned()),
        ("closed_operation", "blob_delivery_status".to_owned()),
    ]);
    fields.extend(prefixed_receipt_fields(&receipt));
    emit_child("ATTEMPT2_DONE", &fields)?;
    Ok(())
}

fn provision_participant(
    participants_root: &Path,
    topic: &Topic,
    scope: &Scope,
) -> Result<Participant, DynError> {
    let root_access = ProvisioningAccess::member(scope.clone(), vec![1], vec![topic.clone()])?;
    let mut seed = [0_u8; 32];
    if let Err(error) = getrandom::fill(&mut seed) {
        seed.zeroize();
        return Err(Box::new(error));
    }
    let provisioner = ReferenceProvisioner::from_seed(seed);
    seed.zeroize();
    let mut provisioner = provisioner?;
    let bundle = provisioner.issue_node(1, &[root_access])?;
    let root = participants_root.join(PARTICIPANT);
    let state = root.join("state");
    let mission_path = root.join("mission.bundle");
    create_owner_directory(&root)?;
    create_owner_directory(&state)?;
    let mission = UnprotectedReferenceMission::persist(&mission_path, bundle.to_bytes()?)?;
    let mission_id = mission.identity();
    let mission_authority = mission.mission_authority_id();
    let identity = NodeIdentity::load_or_create(&state)?;
    let carrier_id = identity.id();
    drop(identity);
    let domains = [
        carrier_id.to_string(),
        format_node_id(mission_id),
        format_node_id(mission_authority),
    ];
    require(
        domains.iter().collect::<BTreeSet<_>>().len() == domains.len(),
        "Blob participant identity domains",
    )?;
    Ok(Participant {
        root,
        state,
        mission_path,
        mission: Some(mission),
        mission_id,
        mission_authority,
        carrier_id,
    })
}

async fn start_peerless(
    participant: &Participant,
    bind: SocketAddr,
) -> Result<aster_node::RunningNode, DynError> {
    let mission = participant
        .mission
        .as_ref()
        .ok_or(AcceptanceFailure("participant mission unavailable"))?
        .clone();
    Ok(start_node(NodeConfig {
        state: participant.state.clone(),
        bind,
        mission,
        peers: Vec::new(),
        mutable_interests: MutableSourceInterests::default(),
        sync_interval: SYNC_INTERVAL,
        run_for: None,
        application: NodeApplication::Relay,
    })
    .await?)
}

async fn start_child_node(
    state: PathBuf,
    mission: UnprotectedReferenceMission,
) -> Result<aster_node::RunningNode, DynError> {
    Ok(start_node(NodeConfig {
        state,
        bind: SocketAddr::from(([127, 0, 0, 1], 0)),
        mission,
        peers: Vec::new(),
        mutable_interests: MutableSourceInterests::default(),
        sync_interval: SYNC_INTERVAL,
        run_for: None,
        application: NodeApplication::Relay,
    })
    .await?)
}

fn spawn_attempt_one(
    participant: &Participant,
    token_path: &Path,
    subscription: BlobSubscriptionId,
    blob: BlobId,
) -> Result<ChildActor, DynError> {
    let mut command = Command::new(env::current_exe()?);
    command
        .arg("--internal-attempt-1")
        .arg(&participant.state)
        .arg(&participant.mission_path)
        .arg(token_path)
        .arg(subscription.to_string())
        .arg(blob.to_string());
    spawn_child(command)
}

fn spawn_attempt_two(
    participant: &Participant,
    token_path: &Path,
    subscription: BlobSubscriptionId,
    blob: BlobId,
) -> Result<ChildActor, DynError> {
    let mut command = Command::new(env::current_exe()?);
    command
        .arg("--internal-attempt-2")
        .arg(&participant.state)
        .arg(&participant.mission_path)
        .arg(token_path)
        .arg(subscription.to_string())
        .arg(blob.to_string());
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
    timeout(CHILD_DEADLINE, async {
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
    require(
        !kind.is_empty()
            && kind
                .bytes()
                .all(|byte| byte.is_ascii_uppercase() || byte.is_ascii_digit() || byte == b'_'),
        "child record kind",
    )?;
    print!("{CHILD_PREFIX}\t{kind}");
    let mut seen = BTreeSet::new();
    for (key, value) in fields {
        require(
            valid_field(key) && valid_value(value) && seen.insert(*key),
            "child record encoding",
        )?;
        print!("\t{key}={value}");
    }
    println!();
    std::io::stdout().flush()?;
    Ok(())
}

fn parse_child_record(line: &str) -> Result<Option<(String, ChildFields)>, DynError> {
    let prefix = format!("{CHILD_PREFIX}\t");
    if !line.starts_with(&prefix) {
        return Ok(None);
    }
    let mut parts = line.split('\t');
    require(parts.next() == Some(CHILD_PREFIX), "child record prefix")?;
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

fn parse_blob_id(argument: &OsString) -> Result<BlobId, DynError> {
    Ok(BlobId::from_bytes(parse_hex_32_os(argument)?))
}

fn parse_blob_subscription_id(argument: &OsString) -> Result<BlobSubscriptionId, DynError> {
    Ok(BlobSubscriptionId::from_bytes(parse_hex_32_os(argument)?))
}

fn parse_hex_32_os(argument: &OsString) -> Result<[u8; 32], DynError> {
    let value = argument
        .to_str()
        .ok_or_else(|| Box::new(AcceptanceFailure("child identifier encoding")) as DynError)?;
    parse_hex_32(value)
}

fn parse_hex_32(value: &str) -> Result<[u8; 32], DynError> {
    require(value.len() == 64, "identifier length")?;
    let mut bytes = [0_u8; 32];
    for (index, byte) in bytes.iter_mut().enumerate() {
        let offset = index * 2;
        *byte = u8::from_str_radix(&value[offset..offset + 2], 16)
            .map_err(|_| AcceptanceFailure("identifier value"))?;
    }
    Ok(bytes)
}

#[cfg(unix)]
fn persist_delivery_token(path: &Path, token: BlobDeliveryToken) -> Result<(), DynError> {
    use std::os::unix::fs::OpenOptionsExt as _;

    require(path.is_absolute(), "Blob token path must be absolute")?;
    let mut file = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)?;
    file.write_all(token.as_bytes())?;
    file.sync_all()?;
    drop(file);
    sync_directory(
        path.parent()
            .ok_or(AcceptanceFailure("Blob token parent missing"))?,
    )?;
    validate_token_artifact(path, &sha256_hex(token.as_bytes()))
}

#[cfg(not(unix))]
fn persist_delivery_token(path: &Path, token: BlobDeliveryToken) -> Result<(), DynError> {
    require(path.is_absolute(), "Blob token path must be absolute")?;
    let mut file = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)?;
    file.write_all(token.as_bytes())?;
    file.sync_all()?;
    drop(file);
    sync_directory(
        path.parent()
            .ok_or(AcceptanceFailure("Blob token parent missing"))?,
    )?;
    validate_token_artifact(path, &sha256_hex(token.as_bytes()))
}

fn validate_token_artifact(path: &Path, expected_digest: &str) -> Result<(), DynError> {
    let token = read_delivery_token(path)?;
    require(
        sha256_hex(token.as_bytes()) == expected_digest,
        "Blob token artifact digest",
    )
}

fn consume_delivery_token(path: &Path) -> Result<BlobDeliveryToken, DynError> {
    let token = read_delivery_token(path)?;
    fs::remove_file(path)?;
    require(!path.exists(), "Blob token artifact removal")?;
    Ok(token)
}

fn read_delivery_token(path: &Path) -> Result<BlobDeliveryToken, DynError> {
    let metadata = fs::symlink_metadata(path)?;
    require(
        metadata.file_type().is_file()
            && metadata.len() == u64::try_from(BLOB_DELIVERY_TOKEN_BYTES)?,
        "Blob token artifact type",
    )?;
    validate_token_permissions(&metadata)?;
    let mut file = fs::File::open(path)?;
    let mut bytes = [0_u8; BLOB_DELIVERY_TOKEN_BYTES];
    file.read_exact(&mut bytes)?;
    let token = BlobDeliveryToken::from_bytes(bytes)?;
    bytes.zeroize();
    Ok(token)
}

#[cfg(unix)]
fn validate_token_permissions(metadata: &fs::Metadata) -> Result<(), DynError> {
    use std::os::unix::fs::PermissionsExt as _;

    require(
        metadata.permissions().mode() & 0o777 == 0o600,
        "Blob token artifact permissions",
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
        "Blob child was not force terminated",
    )
}

fn validate_handle(participant: &Participant, handle: &SelectedBlobHandle) -> Result<(), DynError> {
    require(
        handle.identity() == participant.mission_id
            && handle.mission_authority() == participant.mission_authority,
        "selected Blob handle mission binding",
    )
}

fn validate_publications(
    participant: &Participant,
    publications: &[BlobPublishResult; 2],
) -> Result<(), DynError> {
    let priorities = [Priority::Priority, Priority::Immediate];
    for (index, publication) in publications.iter().enumerate() {
        let ordinal = u64::try_from(index + 1)?;
        require(
            publication.publisher == participant.mission_id
                && publication.publisher_counter == ordinal
                && publication.priority == priorities[index]
                && publication.total_len == u64::try_from(SHARED_PAYLOAD.len())?
                && publication.media_type.as_deref() == Some(MEDIA_TYPE)
                && publication.schema_id == SCHEMA_ID
                && publication.acceptance_marker == ordinal
                && publication.inserted,
            "Blob publication metadata",
        )?;
    }
    require(
        publications
            .iter()
            .map(|publication| publication.id)
            .collect::<BTreeSet<_>>()
            .len()
            == 1,
        "shared Blob content identity",
    )
}

fn validate_delivery(
    delivery: &BlobDelivery,
    expected_blob: BlobId,
    counter: u64,
    attempt: u64,
    priority: Priority,
) -> Result<(), DynError> {
    require(
        delivery.id == expected_blob
            && delivery.publisher_counter == counter
            && delivery.topic == Topic::new(ALPHA_TOPIC)?
            && delivery.scope == Scope::new(ROOT_SCOPE)?
            && delivery.priority == priority
            && delivery.total_len == u64::try_from(SHARED_PAYLOAD.len())?
            && delivery.media_type.as_deref() == Some(MEDIA_TYPE)
            && delivery.schema_id == SCHEMA_ID
            && delivery.acceptance_marker == counter
            && delivery.attempt == attempt,
        "Blob delivery metadata",
    )
}

fn validate_status(
    status: BlobDeliveryStatus,
    expected: [u64; 5],
    label: &'static str,
) -> Result<(), DynError> {
    require(
        [
            status.subscriptions,
            status.pending_deliveries,
            status.acknowledged_deliveries,
            status.delivery_cursors,
            status.selector_generation,
        ] == expected,
        label,
    )
}

async fn validate_empty_poll(
    blobs: &SelectedBlobHandle,
    subscription: BlobSubscription,
) -> Result<(), DynError> {
    let page = poll(blobs, subscription).await?;
    require(
        page.deliveries.is_empty() && !page.has_more,
        "Blob poll was not empty",
    )
}

async fn validate_closed_handle(handle: &SelectedBlobHandle) -> Result<(), DynError> {
    let error = handle
        .delivery_status()
        .await
        .expect_err("closed Blob handle accepted status");
    require(
        error.kind() == ApplicationErrorKind::StateUnavailable
            && error.operation() == "blob delivery status",
        "closed Blob handle",
    )
}

fn validate_peerless_receipt(receipt: &NodeReceipt) -> Result<(), DynError> {
    require(
        receipt.contacts == 0
            && receipt.contact_errors == 0
            && receipt.direct_contacts == 0
            && receipt.relay_contacts == 0
            && receipt.unknown_path_contacts == 0
            && receipt.data_offered == 0
            && receipt.data_fetched == 0
            && receipt.data_inserted == 0
            && receipt.data_duplicates == 0
            && receipt.data_remaining == 0
            && receipt.mutable_remaining == 0
            && receipt.deferred_mutable_lanes == 0
            && receipt.blob_ranges_fetched == 0
            && receipt.blob_bytes_fetched == 0
            && receipt.blob_remaining == 0
            && receipt.blob_deferred == 0
            && receipt.blobs == 2
            && receipt.blob_acceptance_markers == 2
            && receipt.blob_last_acceptance_marker == 2
            && receipt.blob_sealed_bytes > 0
            && receipt.blob_operations == 2
            && receipt.blob_operation_bytes > 0
            && receipt.blob_variants == 1
            && receipt.blob_finalized_variants == 1
            && receipt.blob_committed_chunks == 1
            && receipt.blob_committed_file_bytes > 0
            && receipt.blob_reserved_file_bytes == receipt.blob_committed_file_bytes
            && receipt.pending_blobs == 0
            && receipt.blob_carrier_prefixes == 0
            && receipt.blob_carrier_fetch_cursors == 0
            && receipt.blob_network_staging_bytes == 0
            && receipt.events == 0
            && receipt.event_acceptance_markers == 0
            && receipt.route_cached_events == 0
            && receipt.controls == 0
            && receipt.applied_controls == 0
            && receipt.pending_controls == 0
            && receipt.control_highwater == 0,
        "peerless Blob shutdown receipt",
    )
}

fn validate_inspection(inspection: &StoreInspection) -> Result<(), DynError> {
    require(
        inspection.blob_stats.publications == 2
            && inspection.blob_stats.acceptance_markers == 2
            && inspection.blob_stats.last_acceptance_marker == 2
            && inspection.blob_stats.operations == 2
            && inspection.blob_stats.variants == 1
            && inspection.blob_stats.finalized_variants == 1
            && inspection.blob_stats.committed_chunks == 1
            && inspection.blob_stats.committed_file_bytes > 0
            && inspection.blob_stats.reserved_file_bytes
                == inspection.blob_stats.committed_file_bytes
            && inspection.blob_stats.pending_sources == 0
            && inspection.blob_stats.carrier_prefixes == 0
            && inspection.blob_stats.carrier_fetch_cursors == 0
            && inspection.blob_stats.network_staging_bytes == 0,
        "final Blob store statistics",
    )?;
    require(
        inspection.blob_subscription_stats.subscriptions == 1
            && inspection.blob_subscription_stats.pending_deliveries == 0
            && inspection.blob_subscription_stats.acknowledged_deliveries == 2
            && inspection.blob_subscription_stats.delivery_cursors == 2
            && inspection.blob_subscription_stats.selector_generation == 1,
        "final Blob subscription statistics",
    )?;
    require(
        other_namespaces_empty(inspection),
        "excluded store statistics",
    )
}

fn other_namespaces_empty(inspection: &StoreInspection) -> bool {
    inspection.event_stats == Default::default()
        && inspection.state_stats == Default::default()
        && inspection.record_stats == Default::default()
        && inspection.event_subscription_stats == Default::default()
        && inspection.state_subscription_stats == Default::default()
        && inspection.record_subscription_stats == Default::default()
        && inspection.control_stats == Default::default()
}

fn validate_reacquired_bind(address: SocketAddr) -> Result<(), DynError> {
    let socket = UdpSocket::bind(address)?;
    require(socket.local_addr()? == address, "Blob bind reacquisition")?;
    drop(socket);
    Ok(())
}

fn delivery_fields(delivery: &BlobDelivery, prefix: &str) -> Vec<(&'static str, String)> {
    let keys = match prefix {
        "" => [
            "publication_id",
            "blob_id",
            "publisher",
            "counter",
            "topic",
            "scope",
            "priority",
            "total_len",
            "media_type",
            "schema_sha256",
            "acceptance_marker",
            "attempt",
            "token_sha256",
        ],
        "retry_" => [
            "retry_publication_id",
            "retry_blob_id",
            "retry_publisher",
            "retry_counter",
            "retry_topic",
            "retry_scope",
            "retry_priority",
            "retry_total_len",
            "retry_media_type",
            "retry_schema_sha256",
            "retry_acceptance_marker",
            "retry_attempt",
            "retry_token_sha256",
        ],
        "second_" => [
            "second_publication_id",
            "second_blob_id",
            "second_publisher",
            "second_counter",
            "second_topic",
            "second_scope",
            "second_priority",
            "second_total_len",
            "second_media_type",
            "second_schema_sha256",
            "second_acceptance_marker",
            "second_attempt",
            "second_token_sha256",
        ],
        _ => unreachable!("fixed delivery-field prefix"),
    };
    let values = [
        delivery.publication.to_string(),
        delivery.id.to_string(),
        format_node_id(delivery.publisher),
        delivery.publisher_counter.to_string(),
        delivery.topic.as_str().to_owned(),
        delivery.scope.as_str().to_owned(),
        priority_name(delivery.priority).to_owned(),
        delivery.total_len.to_string(),
        delivery.media_type.as_deref().unwrap_or("none").to_owned(),
        sha256_hex(&delivery.schema_id),
        delivery.acceptance_marker.to_string(),
        delivery.attempt.to_string(),
        sha256_hex(delivery.token.as_bytes()),
    ];
    keys.into_iter().zip(values).collect()
}

fn status_fields(status: BlobDeliveryStatus, prefix: &str) -> Vec<(&'static str, String)> {
    let keys = match prefix {
        "" => [
            "subscriptions",
            "pending_deliveries",
            "acknowledged_deliveries",
            "delivery_cursors",
            "selector_generation",
        ],
        "shutdown_" => [
            "shutdown_subscriptions",
            "shutdown_pending_deliveries",
            "shutdown_acknowledged_deliveries",
            "shutdown_delivery_cursors",
            "shutdown_selector_generation",
        ],
        _ => unreachable!("fixed status-field prefix"),
    };
    let values = [
        status.subscriptions.to_string(),
        status.pending_deliveries.to_string(),
        status.acknowledged_deliveries.to_string(),
        status.delivery_cursors.to_string(),
        status.selector_generation.to_string(),
    ];
    keys.into_iter().zip(values).collect()
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
            "shutdown_blob_operations",
            receipt.blob_operations.to_string(),
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
            "shutdown_blob_network_staging_bytes",
            receipt.blob_network_staging_bytes.to_string(),
        ),
        ("shutdown_events", receipt.events.to_string()),
        ("shutdown_controls", receipt.controls.to_string()),
    ]
}

fn validate_attempt_one_fields(
    fields: &ChildFields,
    participant: &Participant,
    subscription: BlobSubscriptionId,
    publications: &[BlobPublishResult; 2],
) -> Result<(), DynError> {
    require(
        fields.len() == 28
            && child_field(fields, "participant")? == PARTICIPANT
            && child_field(fields, "identity")? == format_node_id(participant.mission_id)
            && child_field(fields, "subscription_id")? == subscription.to_string()
            && child_field(fields, "subscription_inserted")? == "false"
            && is_hex_32(child_field(fields, "publication_id")?)
            && child_field(fields, "blob_id")? == publications[0].id.to_string()
            && child_field(fields, "publisher")? == format_node_id(participant.mission_id)
            && child_field(fields, "counter")? == "1"
            && child_field(fields, "topic")? == ALPHA_TOPIC
            && child_field(fields, "scope")? == ROOT_SCOPE
            && child_field(fields, "priority")? == "priority"
            && child_field(fields, "total_len")? == SHARED_PAYLOAD.len().to_string()
            && child_field(fields, "media_type")? == MEDIA_TYPE
            && child_field(fields, "schema_sha256")? == sha256_hex(SCHEMA_ID)
            && child_field(fields, "acceptance_marker")? == "1"
            && child_field(fields, "attempt")? == "1"
            && is_sha256(child_field(fields, "token_sha256")?)
            && child_field(fields, "delivery_limit")? == DELIVERY_LIMIT.to_string()
            && child_field(fields, "scan_limit")? == SCAN_LIMIT.to_string()
            && child_field(fields, "has_more")? == "true"
            && child_field(fields, "metadata_only")? == "true"
            && child_field(fields, "acknowledged")? == "false"
            && child_field(fields, "token_persisted")? == "true"
            && child_field(fields, "subscriptions")? == "1"
            && child_field(fields, "pending_deliveries")? == "1"
            && child_field(fields, "acknowledged_deliveries")? == "0"
            && child_field(fields, "delivery_cursors")? == "1"
            && child_field(fields, "selector_generation")? == "1",
        "attempt-one Blob child evidence",
    )
}

fn validate_attempt_two_fields(
    fields: &ChildFields,
    participant: &Participant,
    subscription: BlobSubscriptionId,
    publications: &[BlobPublishResult; 2],
    attempt_one_publication: &str,
) -> Result<(), DynError> {
    require(
        child_field(fields, "participant")? == PARTICIPANT
            && child_field(fields, "identity")? == format_node_id(participant.mission_id)
            && child_field(fields, "subscription_id")? == subscription.to_string()
            && child_field(fields, "subscription_inserted")? == "false"
            && child_field(fields, "retry_publication_id")? == attempt_one_publication
            && child_field(fields, "retry_blob_id")? == publications[0].id.to_string()
            && child_field(fields, "retry_publisher")? == format_node_id(participant.mission_id)
            && child_field(fields, "retry_counter")? == "1"
            && child_field(fields, "retry_topic")? == ALPHA_TOPIC
            && child_field(fields, "retry_scope")? == ROOT_SCOPE
            && child_field(fields, "retry_priority")? == "priority"
            && child_field(fields, "retry_total_len")? == SHARED_PAYLOAD.len().to_string()
            && child_field(fields, "retry_media_type")? == MEDIA_TYPE
            && child_field(fields, "retry_schema_sha256")? == sha256_hex(SCHEMA_ID)
            && child_field(fields, "retry_acceptance_marker")? == "1"
            && child_field(fields, "retry_attempt")? == "2"
            && is_sha256(child_field(fields, "retry_token_sha256")?)
            && is_sha256(child_field(fields, "previous_token_sha256")?)
            && child_field(fields, "retry_token_sha256")?
                != child_field(fields, "previous_token_sha256")?
            && child_field(fields, "tokens_distinct")? == "true"
            && child_field(fields, "previous_token_restored")? == "true"
            && child_field(fields, "malformed_token_rejected")? == "true"
            && child_field(fields, "first_ack")? == "acknowledged"
            && child_field(fields, "first_reack")? == "already_acknowledged"
            && child_field(fields, "first_ack_token_attempt")? == "1"
            && child_field(fields, "first_reack_token_attempt")? == "2"
            && is_hex_32(child_field(fields, "second_publication_id")?)
            && child_field(fields, "second_publication_id")? != attempt_one_publication
            && child_field(fields, "second_blob_id")? == publications[1].id.to_string()
            && child_field(fields, "second_publisher")? == format_node_id(participant.mission_id)
            && child_field(fields, "second_counter")? == "2"
            && child_field(fields, "second_topic")? == ALPHA_TOPIC
            && child_field(fields, "second_scope")? == ROOT_SCOPE
            && child_field(fields, "second_priority")? == "immediate"
            && child_field(fields, "second_total_len")? == SHARED_PAYLOAD.len().to_string()
            && child_field(fields, "second_media_type")? == MEDIA_TYPE
            && child_field(fields, "second_schema_sha256")? == sha256_hex(SCHEMA_ID)
            && child_field(fields, "second_acceptance_marker")? == "2"
            && child_field(fields, "second_attempt")? == "1"
            && is_sha256(child_field(fields, "second_token_sha256")?)
            && child_field(fields, "same_blob_id")? == "true"
            && child_field(fields, "distinct_publications")? == "true"
            && child_field(fields, "wrong_publication_token_rejected")? == "true"
            && child_field(fields, "second_ack")? == "acknowledged"
            && child_field(fields, "second_reack")? == "already_acknowledged"
            && child_field(fields, "second_ack_token_attempt")? == "1"
            && child_field(fields, "second_reack_token_attempt")? == "1"
            && child_field(fields, "empty_poll")? == "true"
            && child_field(fields, "token_artifact_removed")? == "true"
            && child_field(fields, "subscriptions")? == "1"
            && child_field(fields, "pending_deliveries")? == "0"
            && child_field(fields, "acknowledged_deliveries")? == "2"
            && child_field(fields, "delivery_cursors")? == "2"
            && child_field(fields, "selector_generation")? == "1"
            && child_field(fields, "closed_kind")? == "state_unavailable"
            && child_field(fields, "closed_operation")? == "blob_delivery_status"
            && peerless_child_receipt_fields_match(fields)?,
        "attempt-two Blob child evidence",
    )
}

fn peerless_child_receipt_fields_match(fields: &ChildFields) -> Result<bool, DynError> {
    for key in [
        "shutdown_contacts",
        "shutdown_contact_errors",
        "shutdown_direct_contacts",
        "shutdown_relay_contacts",
        "shutdown_unknown_path_contacts",
        "shutdown_data_offered",
        "shutdown_data_fetched",
        "shutdown_data_inserted",
        "shutdown_data_duplicates",
        "shutdown_data_remaining",
        "shutdown_mutable_remaining",
        "shutdown_deferred_mutable_lanes",
        "shutdown_blob_ranges_fetched",
        "shutdown_blob_bytes_fetched",
        "shutdown_blob_remaining",
        "shutdown_blob_deferred",
        "shutdown_pending_blobs",
        "shutdown_blob_carrier_prefixes",
        "shutdown_blob_network_staging_bytes",
        "shutdown_events",
        "shutdown_controls",
    ] {
        if child_field(fields, key)? != "0" {
            return Ok(false);
        }
    }
    Ok(child_field(fields, "shutdown_blobs")? == "2"
        && child_field(fields, "shutdown_blob_acceptance_markers")? == "2"
        && child_field(fields, "shutdown_blob_last_acceptance_marker")? == "2"
        && child_field(fields, "shutdown_blob_operations")? == "2"
        && child_field(fields, "shutdown_blob_variants")? == "1"
        && child_field(fields, "shutdown_blob_finalized_variants")? == "1"
        && child_field(fields, "shutdown_blob_committed_chunks")? == "1"
        && child_field(fields, "shutdown_blob_committed_file_bytes")?
            == child_field(fields, "shutdown_blob_reserved_file_bytes")?
        && child_field(fields, "shutdown_blob_committed_file_bytes")? != "0")
}

fn is_sha256(value: &str) -> bool {
    is_hex_32(value)
}

fn is_hex_32(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

#[cfg(unix)]
fn write_source(path: &Path, payload: &[u8]) -> Result<(), DynError> {
    use std::os::unix::fs::OpenOptionsExt as _;

    let mut file = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)?;
    file.write_all(payload)?;
    file.sync_all()?;
    Ok(())
}

#[cfg(not(unix))]
fn write_source(path: &Path, payload: &[u8]) -> Result<(), DynError> {
    let mut file = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)?;
    file.write_all(payload)?;
    file.sync_all()?;
    Ok(())
}

fn sync_directory(path: &Path) -> Result<(), DynError> {
    fs::File::open(path)?.sync_all()?;
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

const fn priority_name(priority: Priority) -> &'static str {
    match priority {
        Priority::Routine => "routine",
        Priority::Priority => "priority",
        Priority::Immediate => "immediate",
        Priority::Flash => "flash",
    }
}

const fn acknowledgement_name(acknowledgement: BlobAcknowledgement) -> &'static str {
    match acknowledgement {
        BlobAcknowledgement::Acknowledged => "acknowledged",
        BlobAcknowledgement::AlreadyAcknowledged => "already_acknowledged",
    }
}

fn sha256_hex(bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    digest.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn emit_transcript(
    participant: &Participant,
    evidence: &AcceptanceEvidence,
) -> Result<(), DynError> {
    let mut transcript = TranscriptEmitter::new();
    transcript.emit(
        "run",
        &[
            ("schema", TRANSCRIPT_SCHEMA.to_owned()),
            ("claim", CLAIM.to_owned()),
            ("participants", "1".to_owned()),
            ("processes", "3".to_owned()),
            ("actor_lifetimes", "4".to_owned()),
            ("maximum_concurrent_processes", "2".to_owned()),
            ("maximum_concurrent_actors", "1".to_owned()),
            ("phases", "4".to_owned()),
            ("topic", ALPHA_TOPIC.to_owned()),
            ("root_scope", ROOT_SCOPE.to_owned()),
            ("delivery_limit", DELIVERY_LIMIT.to_string()),
            ("scan_limit", SCAN_LIMIT.to_string()),
            ("token_bytes", BLOB_DELIVERY_TOKEN_BYTES.to_string()),
        ],
    )?;
    transcript.emit(
        "participant",
        &[
            ("participant", PARTICIPANT.to_owned()),
            ("carrier_id", participant.carrier_id.to_string()),
            ("mission_id", format_node_id(participant.mission_id)),
            (
                "mission_authority",
                format_node_id(participant.mission_authority),
            ),
            ("provisioning", "one-node-bundle".to_owned()),
        ],
    )?;
    emit_phase(
        &mut transcript,
        1,
        "initial_peerless",
        "parent",
        "published-and-durable",
    )?;
    emit_subscription(
        &mut transcript,
        "initial_peerless",
        evidence.subscription,
        true,
    )?;
    emit_subscription(
        &mut transcript,
        "initial_peerless",
        evidence.subscription,
        false,
    )?;
    transcript.emit(
        "subscription_conflict",
        &[
            ("phase", "initial_peerless".to_owned()),
            ("participant", PARTICIPANT.to_owned()),
            ("kind", "conflict".to_owned()),
            ("operation", "blob_subscribe".to_owned()),
            ("changed_descendants", "true".to_owned()),
            ("rejected", "true".to_owned()),
        ],
    )?;
    emit_publication(
        &mut transcript,
        "matching-a",
        &evidence.publications[0],
        ALPHA_TOPIC,
        ROOT_SCOPE,
    )?;
    emit_publication(
        &mut transcript,
        "matching-b",
        &evidence.publications[1],
        ALPHA_TOPIC,
        ROOT_SCOPE,
    )?;
    emit_status(&mut transcript, "initial_peerless", evidence.initial_status)?;
    emit_receipt(
        &mut transcript,
        "initial_peerless",
        &evidence.initial_receipt,
    )?;

    emit_phase(
        &mut transcript,
        2,
        "forced_delivery_attempt",
        "attempt-one-child",
        "force-terminated",
    )?;
    emit_child_subscription(
        &mut transcript,
        "forced_delivery_attempt",
        &evidence.attempt_one,
    )?;
    emit_child_delivery(
        &mut transcript,
        "forced_delivery_attempt",
        "matching-a",
        &evidence.attempt_one,
        "",
        true,
        false,
    )?;
    emit_child_status(
        &mut transcript,
        "forced_delivery_attempt",
        &evidence.attempt_one,
    )?;
    transcript.emit(
        "process_termination",
        &[
            ("phase", "forced_delivery_attempt".to_owned()),
            ("participant", PARTICIPANT.to_owned()),
            ("mechanism", "parent-child-kill".to_owned()),
            ("signal", "sigkill".to_owned()),
            ("distinct_process", "true".to_owned()),
            ("after_flushed_poll", "true".to_owned()),
            ("graceful", "false".to_owned()),
            ("stop_record_observed", "false".to_owned()),
            ("acknowledged", "false".to_owned()),
            ("token_persisted", "true".to_owned()),
            ("token_artifact_mode", "0600".to_owned()),
            ("token_artifact_fsynced", "true".to_owned()),
        ],
    )?;

    emit_phase(
        &mut transcript,
        3,
        "peerless_redelivery",
        "attempt-two-child",
        "acknowledged-and-empty",
    )?;
    emit_child_subscription(
        &mut transcript,
        "peerless_redelivery",
        &evidence.attempt_two,
    )?;
    emit_child_delivery(
        &mut transcript,
        "peerless_redelivery",
        "matching-a-retry",
        &evidence.attempt_two,
        "retry_",
        true,
        false,
    )?;
    emit_token_checks(
        &mut transcript,
        "retry",
        &evidence.attempt_two,
        false,
        false,
    )?;
    emit_acknowledgement(
        &mut transcript,
        "matching-a",
        child_field(&evidence.attempt_two, "retry_publication_id")?,
        child_field(&evidence.attempt_two, "first_ack")?,
        child_field(&evidence.attempt_two, "first_reack")?,
        "1",
        "2",
    )?;
    emit_child_delivery(
        &mut transcript,
        "peerless_redelivery",
        "matching-b",
        &evidence.attempt_two,
        "second_",
        false,
        false,
    )?;
    emit_token_checks(
        &mut transcript,
        "binding",
        &evidence.attempt_two,
        true,
        true,
    )?;
    emit_acknowledgement(
        &mut transcript,
        "matching-b",
        child_field(&evidence.attempt_two, "second_publication_id")?,
        child_field(&evidence.attempt_two, "second_ack")?,
        child_field(&evidence.attempt_two, "second_reack")?,
        "1",
        "1",
    )?;
    emit_empty_poll(
        &mut transcript,
        "peerless_redelivery",
        "post-acknowledgement",
    )?;
    emit_child_status(
        &mut transcript,
        "peerless_redelivery",
        &evidence.attempt_two,
    )?;
    emit_child_receipt(
        &mut transcript,
        "peerless_redelivery",
        &evidence.attempt_two,
    )?;

    emit_phase(
        &mut transcript,
        4,
        "final_peerless_reopen",
        "parent",
        "durable-empty",
    )?;
    emit_subscription(
        &mut transcript,
        "final_peerless_reopen",
        evidence.subscription,
        false,
    )?;
    emit_empty_poll(&mut transcript, "final_peerless_reopen", "durable-empty")?;
    emit_status(
        &mut transcript,
        "final_peerless_reopen",
        evidence.final_status,
    )?;
    emit_receipt(
        &mut transcript,
        "final_peerless_reopen",
        &evidence.final_receipt,
    )?;
    emit_inspection(&mut transcript, &evidence.inspection)?;
    transcript.emit(
        "closed_handle",
        &[
            ("phase", "final_peerless_reopen".to_owned()),
            ("participant", PARTICIPANT.to_owned()),
            ("operation", "blob_delivery_status".to_owned()),
            ("kind", "state_unavailable".to_owned()),
        ],
    )?;
    transcript.emit(
        "bind",
        &[
            ("participant", PARTICIPANT.to_owned()),
            ("reacquired", "true".to_owned()),
        ],
    )?;
    transcript.emit(
        "result",
        &[
            ("status", "pass".to_owned()),
            ("records", TRANSCRIPT_RECORDS.to_string()),
            ("phases", "4".to_owned()),
            ("participants", "1".to_owned()),
            ("processes", "3".to_owned()),
            ("actor_lifetimes", "4".to_owned()),
            ("maximum_concurrent_processes", "2".to_owned()),
            ("maximum_concurrent_actors", "1".to_owned()),
            ("graceful_shutdowns", "3".to_owned()),
            ("forced_process_terminations", "1".to_owned()),
            ("blob_publications", "2".to_owned()),
            ("matching_publications", "2".to_owned()),
            ("withheld_publications", "0".to_owned()),
            ("unique_deliveries", "2".to_owned()),
            ("delivery_attempts", "3".to_owned()),
            ("polls", "5".to_owned()),
            ("acknowledgements", "2".to_owned()),
            ("reacknowledgements", "2".to_owned()),
            ("subscription_insertions", "1".to_owned()),
            ("subscription_replays", "4".to_owned()),
            ("token_binding_checks", "2".to_owned()),
            ("empty_polls", "2".to_owned()),
            ("status_observations", "4".to_owned()),
            ("bind_reacquisitions", "1".to_owned()),
            ("payload_representation", "sha256-only".to_owned()),
            ("token_representation", "sha256-only".to_owned()),
            ("opaque_tokens_emitted", "false".to_owned()),
            ("secret_values_emitted", "false".to_owned()),
            ("network_contact_claimed", "false".to_owned()),
            ("peer_status_claimed", "false".to_owned()),
            ("selector_withholding_claimed", "false".to_owned()),
            ("network_interest_separation_claimed", "false".to_owned()),
            ("long_retention_claimed", "false".to_owned()),
        ],
    )?;
    require(
        transcript.records == TRANSCRIPT_RECORDS,
        "Blob transcript record count",
    )?;
    std::io::stdout().flush()?;
    Ok(())
}

fn emit_phase(
    transcript: &mut TranscriptEmitter,
    phase: usize,
    name: &'static str,
    actors: &'static str,
    outcome: &'static str,
) -> Result<(), DynError> {
    transcript.emit(
        "phase",
        &[
            ("phase", phase.to_string()),
            ("name", name.to_owned()),
            ("actors", actors.to_owned()),
            ("outcome", outcome.to_owned()),
        ],
    )
}

fn emit_subscription(
    transcript: &mut TranscriptEmitter,
    phase: &'static str,
    subscription: BlobSubscription,
    inserted: bool,
) -> Result<(), DynError> {
    transcript.emit(
        "subscription",
        &[
            ("phase", phase.to_owned()),
            ("participant", PARTICIPANT.to_owned()),
            ("id", subscription.id.to_string()),
            ("inserted", inserted.to_string()),
            ("topic", ALPHA_TOPIC.to_owned()),
            ("scope", ROOT_SCOPE.to_owned()),
            ("include_descendant_scopes", "false".to_owned()),
        ],
    )
}

fn emit_child_subscription(
    transcript: &mut TranscriptEmitter,
    phase: &'static str,
    fields: &ChildFields,
) -> Result<(), DynError> {
    transcript.emit(
        "subscription",
        &[
            ("phase", phase.to_owned()),
            ("participant", PARTICIPANT.to_owned()),
            ("id", child_field(fields, "subscription_id")?.to_owned()),
            (
                "inserted",
                child_field(fields, "subscription_inserted")?.to_owned(),
            ),
            ("topic", ALPHA_TOPIC.to_owned()),
            ("scope", ROOT_SCOPE.to_owned()),
            ("include_descendant_scopes", "false".to_owned()),
        ],
    )
}

fn emit_publication(
    transcript: &mut TranscriptEmitter,
    label: &'static str,
    publication: &BlobPublishResult,
    topic: &str,
    scope: &str,
) -> Result<(), DynError> {
    transcript.emit(
        "publication",
        &[
            ("phase", "initial_peerless".to_owned()),
            ("participant", PARTICIPANT.to_owned()),
            ("label", label.to_owned()),
            ("blob_id", publication.id.to_string()),
            ("publisher", format_node_id(publication.publisher)),
            ("counter", publication.publisher_counter.to_string()),
            ("topic", topic.to_owned()),
            ("scope", scope.to_owned()),
            ("priority", priority_name(publication.priority).to_owned()),
            ("total_len", publication.total_len.to_string()),
            (
                "media_type",
                publication
                    .media_type
                    .as_deref()
                    .unwrap_or("none")
                    .to_owned(),
            ),
            ("schema_sha256", sha256_hex(&publication.schema_id)),
            ("payload_sha256", sha256_hex(SHARED_PAYLOAD)),
            (
                "acceptance_marker",
                publication.acceptance_marker.to_string(),
            ),
            ("inserted", publication.inserted.to_string()),
        ],
    )
}

fn emit_status(
    transcript: &mut TranscriptEmitter,
    phase: &'static str,
    status: BlobDeliveryStatus,
) -> Result<(), DynError> {
    transcript.emit(
        "status",
        &[
            ("phase", phase.to_owned()),
            ("participant", PARTICIPANT.to_owned()),
            ("subscriptions", status.subscriptions.to_string()),
            ("pending_deliveries", status.pending_deliveries.to_string()),
            (
                "acknowledged_deliveries",
                status.acknowledged_deliveries.to_string(),
            ),
            ("delivery_cursors", status.delivery_cursors.to_string()),
            (
                "selector_generation",
                status.selector_generation.to_string(),
            ),
        ],
    )
}

fn emit_child_status(
    transcript: &mut TranscriptEmitter,
    phase: &'static str,
    fields: &ChildFields,
) -> Result<(), DynError> {
    transcript.emit(
        "status",
        &[
            ("phase", phase.to_owned()),
            ("participant", PARTICIPANT.to_owned()),
            (
                "subscriptions",
                child_field(fields, "subscriptions")?.to_owned(),
            ),
            (
                "pending_deliveries",
                child_field(fields, "pending_deliveries")?.to_owned(),
            ),
            (
                "acknowledged_deliveries",
                child_field(fields, "acknowledged_deliveries")?.to_owned(),
            ),
            (
                "delivery_cursors",
                child_field(fields, "delivery_cursors")?.to_owned(),
            ),
            (
                "selector_generation",
                child_field(fields, "selector_generation")?.to_owned(),
            ),
        ],
    )
}

fn receipt_fields(receipt: &NodeReceipt) -> Vec<(&'static str, String)> {
    vec![
        ("contacts", receipt.contacts.to_string()),
        ("contact_errors", receipt.contact_errors.to_string()),
        ("direct_contacts", receipt.direct_contacts.to_string()),
        ("relay_contacts", receipt.relay_contacts.to_string()),
        (
            "unknown_path_contacts",
            receipt.unknown_path_contacts.to_string(),
        ),
        ("data_offered", receipt.data_offered.to_string()),
        ("data_fetched", receipt.data_fetched.to_string()),
        ("data_inserted", receipt.data_inserted.to_string()),
        ("data_duplicates", receipt.data_duplicates.to_string()),
        ("data_remaining", receipt.data_remaining.to_string()),
        ("mutable_remaining", receipt.mutable_remaining.to_string()),
        (
            "deferred_mutable_lanes",
            receipt.deferred_mutable_lanes.to_string(),
        ),
        (
            "blob_ranges_fetched",
            receipt.blob_ranges_fetched.to_string(),
        ),
        ("blob_bytes_fetched", receipt.blob_bytes_fetched.to_string()),
        ("blob_remaining", receipt.blob_remaining.to_string()),
        ("blob_deferred", receipt.blob_deferred.to_string()),
        ("blobs", receipt.blobs.to_string()),
        (
            "blob_acceptance_markers",
            receipt.blob_acceptance_markers.to_string(),
        ),
        (
            "blob_last_acceptance_marker",
            receipt.blob_last_acceptance_marker.to_string(),
        ),
        ("blob_operations", receipt.blob_operations.to_string()),
        ("blob_variants", receipt.blob_variants.to_string()),
        (
            "blob_finalized_variants",
            receipt.blob_finalized_variants.to_string(),
        ),
        (
            "blob_committed_chunks",
            receipt.blob_committed_chunks.to_string(),
        ),
        (
            "blob_committed_file_bytes",
            receipt.blob_committed_file_bytes.to_string(),
        ),
        (
            "blob_reserved_file_bytes",
            receipt.blob_reserved_file_bytes.to_string(),
        ),
        ("pending_blobs", receipt.pending_blobs.to_string()),
        (
            "blob_carrier_prefixes",
            receipt.blob_carrier_prefixes.to_string(),
        ),
        (
            "blob_network_staging_bytes",
            receipt.blob_network_staging_bytes.to_string(),
        ),
        ("events", receipt.events.to_string()),
        ("controls", receipt.controls.to_string()),
    ]
}

fn emit_receipt(
    transcript: &mut TranscriptEmitter,
    phase: &'static str,
    receipt: &NodeReceipt,
) -> Result<(), DynError> {
    let mut fields = vec![
        ("phase", phase.to_owned()),
        ("participant", PARTICIPANT.to_owned()),
    ];
    fields.extend(receipt_fields(receipt));
    transcript.emit("receipt", &fields)
}

fn emit_child_receipt(
    transcript: &mut TranscriptEmitter,
    phase: &'static str,
    fields: &ChildFields,
) -> Result<(), DynError> {
    let mappings = [
        ("contacts", "shutdown_contacts"),
        ("contact_errors", "shutdown_contact_errors"),
        ("direct_contacts", "shutdown_direct_contacts"),
        ("relay_contacts", "shutdown_relay_contacts"),
        ("unknown_path_contacts", "shutdown_unknown_path_contacts"),
        ("data_offered", "shutdown_data_offered"),
        ("data_fetched", "shutdown_data_fetched"),
        ("data_inserted", "shutdown_data_inserted"),
        ("data_duplicates", "shutdown_data_duplicates"),
        ("data_remaining", "shutdown_data_remaining"),
        ("mutable_remaining", "shutdown_mutable_remaining"),
        ("deferred_mutable_lanes", "shutdown_deferred_mutable_lanes"),
        ("blob_ranges_fetched", "shutdown_blob_ranges_fetched"),
        ("blob_bytes_fetched", "shutdown_blob_bytes_fetched"),
        ("blob_remaining", "shutdown_blob_remaining"),
        ("blob_deferred", "shutdown_blob_deferred"),
        ("blobs", "shutdown_blobs"),
        (
            "blob_acceptance_markers",
            "shutdown_blob_acceptance_markers",
        ),
        (
            "blob_last_acceptance_marker",
            "shutdown_blob_last_acceptance_marker",
        ),
        ("blob_operations", "shutdown_blob_operations"),
        ("blob_variants", "shutdown_blob_variants"),
        (
            "blob_finalized_variants",
            "shutdown_blob_finalized_variants",
        ),
        ("blob_committed_chunks", "shutdown_blob_committed_chunks"),
        (
            "blob_committed_file_bytes",
            "shutdown_blob_committed_file_bytes",
        ),
        (
            "blob_reserved_file_bytes",
            "shutdown_blob_reserved_file_bytes",
        ),
        ("pending_blobs", "shutdown_pending_blobs"),
        ("blob_carrier_prefixes", "shutdown_blob_carrier_prefixes"),
        (
            "blob_network_staging_bytes",
            "shutdown_blob_network_staging_bytes",
        ),
        ("events", "shutdown_events"),
        ("controls", "shutdown_controls"),
    ];
    let mut projected = vec![
        ("phase", phase.to_owned()),
        ("participant", PARTICIPANT.to_owned()),
    ];
    for (output, input) in mappings {
        projected.push((output, child_field(fields, input)?.to_owned()));
    }
    transcript.emit("receipt", &projected)
}

#[allow(clippy::too_many_arguments)]
fn emit_child_delivery(
    transcript: &mut TranscriptEmitter,
    phase: &'static str,
    label: &'static str,
    fields: &ChildFields,
    prefix: &'static str,
    has_more: bool,
    acknowledged: bool,
) -> Result<(), DynError> {
    let key = |suffix: &'static str| -> &'static str {
        match (prefix, suffix) {
            ("", "publication_id") => "publication_id",
            ("", "blob_id") => "blob_id",
            ("", "publisher") => "publisher",
            ("", "counter") => "counter",
            ("", "topic") => "topic",
            ("", "scope") => "scope",
            ("", "priority") => "priority",
            ("", "total_len") => "total_len",
            ("", "media_type") => "media_type",
            ("", "schema_sha256") => "schema_sha256",
            ("", "acceptance_marker") => "acceptance_marker",
            ("", "attempt") => "attempt",
            ("", "token_sha256") => "token_sha256",
            ("retry_", "publication_id") => "retry_publication_id",
            ("retry_", "blob_id") => "retry_blob_id",
            ("retry_", "publisher") => "retry_publisher",
            ("retry_", "counter") => "retry_counter",
            ("retry_", "topic") => "retry_topic",
            ("retry_", "scope") => "retry_scope",
            ("retry_", "priority") => "retry_priority",
            ("retry_", "total_len") => "retry_total_len",
            ("retry_", "media_type") => "retry_media_type",
            ("retry_", "schema_sha256") => "retry_schema_sha256",
            ("retry_", "acceptance_marker") => "retry_acceptance_marker",
            ("retry_", "attempt") => "retry_attempt",
            ("retry_", "token_sha256") => "retry_token_sha256",
            ("second_", "publication_id") => "second_publication_id",
            ("second_", "blob_id") => "second_blob_id",
            ("second_", "publisher") => "second_publisher",
            ("second_", "counter") => "second_counter",
            ("second_", "topic") => "second_topic",
            ("second_", "scope") => "second_scope",
            ("second_", "priority") => "second_priority",
            ("second_", "total_len") => "second_total_len",
            ("second_", "media_type") => "second_media_type",
            ("second_", "schema_sha256") => "second_schema_sha256",
            ("second_", "acceptance_marker") => "second_acceptance_marker",
            ("second_", "attempt") => "second_attempt",
            ("second_", "token_sha256") => "second_token_sha256",
            _ => unreachable!("fixed child delivery key"),
        }
    };
    transcript.emit(
        "delivery",
        &[
            ("phase", phase.to_owned()),
            ("participant", PARTICIPANT.to_owned()),
            ("label", label.to_owned()),
            (
                "subscription_id",
                child_field(fields, "subscription_id")?.to_owned(),
            ),
            (
                "publication_id",
                child_field(fields, key("publication_id"))?.to_owned(),
            ),
            ("blob_id", child_field(fields, key("blob_id"))?.to_owned()),
            (
                "publisher",
                child_field(fields, key("publisher"))?.to_owned(),
            ),
            ("counter", child_field(fields, key("counter"))?.to_owned()),
            ("topic", child_field(fields, key("topic"))?.to_owned()),
            ("scope", child_field(fields, key("scope"))?.to_owned()),
            ("priority", child_field(fields, key("priority"))?.to_owned()),
            (
                "total_len",
                child_field(fields, key("total_len"))?.to_owned(),
            ),
            (
                "media_type",
                child_field(fields, key("media_type"))?.to_owned(),
            ),
            (
                "schema_sha256",
                child_field(fields, key("schema_sha256"))?.to_owned(),
            ),
            (
                "acceptance_marker",
                child_field(fields, key("acceptance_marker"))?.to_owned(),
            ),
            ("attempt", child_field(fields, key("attempt"))?.to_owned()),
            (
                "token_sha256",
                child_field(fields, key("token_sha256"))?.to_owned(),
            ),
            ("delivery_limit", DELIVERY_LIMIT.to_string()),
            ("scan_limit", SCAN_LIMIT.to_string()),
            ("has_more", has_more.to_string()),
            ("metadata_only", "true".to_owned()),
            ("acknowledged", acknowledged.to_string()),
        ],
    )
}

fn emit_token_checks(
    transcript: &mut TranscriptEmitter,
    label: &'static str,
    fields: &ChildFields,
    wrong_publication: bool,
    artifact_removed: bool,
) -> Result<(), DynError> {
    transcript.emit(
        "token_checks",
        &[
            ("phase", "peerless_redelivery".to_owned()),
            ("label", label.to_owned()),
            ("token_bytes", BLOB_DELIVERY_TOKEN_BYTES.to_string()),
            (
                "attempt_tokens_distinct",
                child_field(fields, "tokens_distinct")?.to_owned(),
            ),
            (
                "previous_token_restored",
                child_field(fields, "previous_token_restored")?.to_owned(),
            ),
            (
                "malformed_token_rejected",
                child_field(fields, "malformed_token_rejected")?.to_owned(),
            ),
            (
                "wrong_publication_token_rejected",
                wrong_publication.to_string(),
            ),
            ("token_artifact_removed", artifact_removed.to_string()),
        ],
    )
}

fn emit_acknowledgement(
    transcript: &mut TranscriptEmitter,
    label: &'static str,
    publication: &str,
    ack: &str,
    reack: &str,
    ack_attempt: &'static str,
    reack_attempt: &'static str,
) -> Result<(), DynError> {
    transcript.emit(
        "acknowledgement",
        &[
            ("phase", "peerless_redelivery".to_owned()),
            ("participant", PARTICIPANT.to_owned()),
            ("label", label.to_owned()),
            ("publication_id", publication.to_owned()),
            ("ack", ack.to_owned()),
            ("reack", reack.to_owned()),
            ("ack_token_attempt", ack_attempt.to_owned()),
            ("reack_token_attempt", reack_attempt.to_owned()),
        ],
    )
}

fn emit_empty_poll(
    transcript: &mut TranscriptEmitter,
    phase: &'static str,
    label: &'static str,
) -> Result<(), DynError> {
    transcript.emit(
        "empty_poll",
        &[
            ("phase", phase.to_owned()),
            ("participant", PARTICIPANT.to_owned()),
            ("label", label.to_owned()),
            ("deliveries", "0".to_owned()),
            ("has_more", "false".to_owned()),
        ],
    )
}

fn emit_inspection(
    transcript: &mut TranscriptEmitter,
    inspection: &StoreInspection,
) -> Result<(), DynError> {
    transcript.emit(
        "inspection",
        &[
            ("participant", PARTICIPANT.to_owned()),
            (
                "blob_publications",
                inspection.blob_stats.publications.to_string(),
            ),
            (
                "blob_acceptance_markers",
                inspection.blob_stats.acceptance_markers.to_string(),
            ),
            (
                "blob_operations",
                inspection.blob_stats.operations.to_string(),
            ),
            ("blob_variants", inspection.blob_stats.variants.to_string()),
            (
                "blob_finalized_variants",
                inspection.blob_stats.finalized_variants.to_string(),
            ),
            (
                "blob_committed_chunks",
                inspection.blob_stats.committed_chunks.to_string(),
            ),
            (
                "blob_committed_file_bytes",
                inspection.blob_stats.committed_file_bytes.to_string(),
            ),
            (
                "blob_reserved_file_bytes",
                inspection.blob_stats.reserved_file_bytes.to_string(),
            ),
            (
                "subscriptions",
                inspection.blob_subscription_stats.subscriptions.to_string(),
            ),
            (
                "pending_deliveries",
                inspection
                    .blob_subscription_stats
                    .pending_deliveries
                    .to_string(),
            ),
            (
                "acknowledged_deliveries",
                inspection
                    .blob_subscription_stats
                    .acknowledged_deliveries
                    .to_string(),
            ),
            (
                "delivery_cursors",
                inspection
                    .blob_subscription_stats
                    .delivery_cursors
                    .to_string(),
            ),
            (
                "selector_generation",
                inspection
                    .blob_subscription_stats
                    .selector_generation
                    .to_string(),
            ),
            (
                "other_namespaces_empty",
                other_namespaces_empty(inspection).to_string(),
            ),
            (
                "pending_blobs",
                inspection.blob_stats.pending_sources.to_string(),
            ),
            (
                "carrier_prefixes",
                inspection.blob_stats.carrier_prefixes.to_string(),
            ),
            (
                "network_staging_bytes",
                inspection.blob_stats.network_staging_bytes.to_string(),
            ),
        ],
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
        "Blob child was not force terminated",
    )
}
