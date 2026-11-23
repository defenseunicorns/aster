//! Retained one-host acceptance producer for durable whole-Record delivery.
//!
//! Two independently provisioned participants create disconnected edit and
//! tombstone heads, reconcile them over direct Iroh under explicit Record
//! interests, then replace the receiver process between durable delivery
//! attempts. The producer emits only bounded metadata and payload/token
//! digests. Runtime `READY`/`CONTACT`/`STOP` lines remain on stdout for an
//! independent receipt projector.

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
        ApplicationError, ApplicationErrorKind, Priority, RECORD_DELIVERY_TOKEN_BYTES,
        RecordAcknowledgement, RecordDelivery, RecordDeliveryToken, RecordId, RecordItem,
        RecordPollRequest, RecordProjection, RecordProjectionId, RecordProjectionKey,
        RecordPublishRequest, RecordPublishResult, RecordQuery, RecordResolveRequest,
        RecordSubscription, RecordSubscriptionId, RecordSubscriptionRequest,
        RecordVersionDisposition, Scope, SelectedRecordHandle, Topic,
    },
    format_node_id,
    mission::UnprotectedReferenceMission,
    start_node,
};
use aster_redb_store::{RecordSubscriptionStats, Store, StoreInspection};
use sha2::{Digest as _, Sha256};
use tokio::{
    sync::mpsc::UnboundedReceiver,
    time::{sleep, timeout},
};
use zeroize::Zeroize as _;

const TRANSCRIPT_SCHEMA: &str = "aster-selected-live-record-subscription-transcript/v1";
const CLAIM: &str = "selected-live-record-subscription-one-host-direct-iroh-whole-conflict-forced-receiver-process-termination-durable-redelivery-fresh-query-resolution-successor-acceptance";
const TRANSCRIPT_RECORDS: usize = 53;
const ALPHA_TOPIC: &str = "opaque";
const BETA_TOPIC: &str = "opaque.beta";
const SCOPE: &str = "test/runtime-contact";
const GAMMA_SCOPE_SUFFIX: &str = "withheld";
const ALPHA_KEY: &[u8] = b"acceptance/record/alpha-key";
const BETA_KEY: &[u8] = b"acceptance/record/beta-key";
const GAMMA_KEY: &[u8] = b"acceptance/record/gamma-key";
const EDIT_PAYLOAD: &[u8] = b"disconnected Record edit";
const TOMBSTONE_PAYLOAD: &[u8] = b"";
const BETA_PAYLOAD: &[u8] = b"network-interested application-unsubscribed Record";
const GAMMA_PAYLOAD: &[u8] = b"application-matched network-uninterested Record";
const RESOLVED_PAYLOAD: &[u8] = b"guarded Record resolution";
const EDIT_OPERATION: &[u8] = b"acceptance/record/edit";
const TOMBSTONE_OPERATION: &[u8] = b"acceptance/record/tombstone";
const BETA_OPERATION: &[u8] = b"acceptance/record/beta";
const GAMMA_OPERATION: &[u8] = b"acceptance/record/gamma";
const RESOLUTION_OPERATION: &[u8] = b"acceptance/record/resolution";
const SUBSCRIPTION_OPERATION: &[u8] = b"acceptance/record/subscription";
const POLL_DEADLINE: Duration = Duration::from_secs(40);
const SYNC_INTERVAL: Duration = Duration::from_secs(5);
const DELIVERY_LIMIT: usize = 1;
const SCAN_LIMIT: usize = 16;

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

impl Drop for ChildActor {
    fn drop(&mut self) {
        if !matches!(self.child.try_wait(), Ok(Some(_))) {
            let _ = self.child.kill();
            let _ = self.child.wait();
        }
    }
}

struct AttemptArtifacts {
    retry_token: PathBuf,
    retired_singleton_token: PathBuf,
}

struct ReceiptEvidence {
    phase: &'static str,
    participant: &'static str,
    receipt: NodeReceipt,
}

struct AcceptanceEvidence {
    subscription: RecordSubscription,
    edit: RecordPublishResult,
    tombstone: RecordPublishResult,
    beta: RecordPublishResult,
    gamma: RecordPublishResult,
    singleton_delivery: RecordDelivery,
    singleton_projections: [RecordProjection; 2],
    conflict_projections: [RecordProjection; 2],
    attempt_one: ChildFields,
    attempt_two: ChildFields,
    final_projection: RecordProjection,
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
            eprintln!("LIVE_RECORD_SUBSCRIPTION_CHILD_FAILURE status=error stage={stage}");
        } else {
            eprintln!("LIVE_RECORD_SUBSCRIPTION_FAILURE status=error stage={stage}");
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
    fn new() -> Self {
        Self { records: 0 }
    }

    fn emit(&mut self, kind: &str, fields: &[(&str, String)]) -> Result<(), DynError> {
        require(valid_field(kind), "transcript record kind")?;
        print!("LIVE_RECORD_SUBSCRIPTION\t{kind}");
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
    gamma_scope: &Scope,
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
            ("actor_lifetimes", "7".to_owned()),
            ("maximum_concurrent_processes", "2".to_owned()),
            ("maximum_concurrent_actors", "2".to_owned()),
            ("phases", "5".to_owned()),
            ("alpha_topic", ALPHA_TOPIC.to_owned()),
            ("beta_topic", BETA_TOPIC.to_owned()),
            ("root_scope", SCOPE.to_owned()),
            ("gamma_scope", gamma_scope.as_str().to_owned()),
            ("application_descendants", "true".to_owned()),
            ("network_alpha_descendants", "false".to_owned()),
            ("network_beta_descendants", "false".to_owned()),
        ],
    )?;
    emit_participant(&mut transcript, publisher)?;
    emit_participant(&mut transcript, receiver)?;
    emit_peer_binding(&mut transcript, publisher, receiver)?;
    emit_peer_binding(&mut transcript, receiver, publisher)?;

    emit_phase(
        &mut transcript,
        1,
        "peerless_origins",
        "publisher+receiver",
        "unacknowledged-singleton",
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
        "alpha-edit",
        &evidence.edit,
        EDIT_PAYLOAD,
        false,
    )?;
    emit_publication(
        &mut transcript,
        "peerless_origins",
        "receiver",
        "alpha-tombstone",
        &evidence.tombstone,
        TOMBSTONE_PAYLOAD,
        true,
    )?;
    emit_delivery(
        &mut transcript,
        "peerless_origins",
        "receiver",
        "alpha-singleton",
        evidence.subscription.id,
        &evidence.singleton_delivery,
        false,
    )?;
    emit_projection(
        &mut transcript,
        "peerless_origins",
        "publisher",
        "alpha-edit",
        &evidence.singleton_projections[0],
    )?;
    emit_projection(
        &mut transcript,
        "peerless_origins",
        "receiver",
        "alpha-tombstone",
        &evidence.singleton_projections[1],
    )?;
    emit_receipt(
        &mut transcript,
        receipt(evidence, "peerless_origins", "publisher")?,
    )?;
    emit_receipt(
        &mut transcript,
        receipt(evidence, "peerless_origins", "receiver")?,
    )?;

    emit_phase(
        &mut transcript,
        2,
        "direct_conflict_and_selectors",
        "publisher+receiver",
        "whole-conflict-and-withholding",
    )?;
    emit_subscription(
        &mut transcript,
        "direct_conflict_and_selectors",
        evidence.subscription,
        false,
    )?;
    emit_projection(
        &mut transcript,
        "direct_conflict_and_selectors",
        "publisher",
        "alpha-conflict",
        &evidence.conflict_projections[0],
    )?;
    emit_projection(
        &mut transcript,
        "direct_conflict_and_selectors",
        "receiver",
        "alpha-conflict",
        &evidence.conflict_projections[1],
    )?;
    emit_publication(
        &mut transcript,
        "direct_conflict_and_selectors",
        "publisher",
        "beta",
        &evidence.beta,
        BETA_PAYLOAD,
        false,
    )?;
    emit_publication(
        &mut transcript,
        "direct_conflict_and_selectors",
        "publisher",
        "gamma",
        &evidence.gamma,
        GAMMA_PAYLOAD,
        false,
    )?;
    emit_selector(
        &mut transcript,
        "direct_conflict_and_selectors",
        "beta",
        BETA_TOPIC,
        SCOPE,
        evidence.beta.id,
        true,
        false,
        true,
        false,
    )?;
    emit_selector(
        &mut transcript,
        "direct_conflict_and_selectors",
        "gamma",
        ALPHA_TOPIC,
        gamma_scope.as_str(),
        evidence.gamma.id,
        false,
        true,
        false,
        false,
    )?;
    emit_receipt(
        &mut transcript,
        receipt(evidence, "direct_conflict_and_selectors", "publisher")?,
    )?;
    emit_receipt(
        &mut transcript,
        receipt(evidence, "direct_conflict_and_selectors", "receiver")?,
    )?;

    emit_phase(
        &mut transcript,
        3,
        "forced_conflict_delivery",
        "receiver-child",
        "force-terminated",
    )?;
    emit_subscription(
        &mut transcript,
        "forced_conflict_delivery",
        evidence.subscription,
        false,
    )?;
    emit_child_delivery(
        &mut transcript,
        "forced_conflict_delivery",
        &evidence.attempt_one,
        "none",
        false,
    )?;
    transcript.emit(
        "process_termination",
        &[
            ("phase", "forced_conflict_delivery".to_owned()),
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
            ("token_artifact_mode", "0600".to_owned()),
            ("token_artifact_fsynced", "true".to_owned()),
        ],
    )?;

    emit_phase(
        &mut transcript,
        4,
        "peerless_redelivery_resolution",
        "receiver-child",
        "acknowledged-and-resolved",
    )?;
    emit_subscription(
        &mut transcript,
        "peerless_redelivery_resolution",
        evidence.subscription,
        false,
    )?;
    emit_child_delivery(
        &mut transcript,
        "peerless_redelivery_resolution",
        &evidence.attempt_two,
        child_field(&evidence.attempt_two, "previous_token_sha256")?,
        true,
    )?;
    emit_token_checks(&mut transcript, &evidence.attempt_two)?;
    emit_child_ack(
        &mut transcript,
        "peerless_redelivery_resolution",
        "conflict",
        &evidence.attempt_two,
        "projection_id",
        "conflict_ack",
        "conflict_reack",
        "1",
        "2",
        "not-applicable",
    )?;
    emit_empty(
        &mut transcript,
        "peerless_redelivery_resolution",
        "receiver",
        "post-conflict-ack",
    )?;
    emit_resolution(&mut transcript, &evidence.attempt_two)?;
    emit_child_successor_delivery(&mut transcript, &evidence.attempt_two)?;
    emit_child_ack(
        &mut transcript,
        "peerless_redelivery_resolution",
        "successor",
        &evidence.attempt_two,
        "successor_projection_id",
        "successor_ack",
        "successor_reack",
        "1",
        "1",
        child_field(&evidence.attempt_two, "old_conflict_reack")?,
    )?;
    emit_empty(
        &mut transcript,
        "peerless_redelivery_resolution",
        "receiver",
        "post-successor-ack",
    )?;
    emit_child_resolved_projection(&mut transcript, &evidence.attempt_two)?;
    emit_child_receipt(&mut transcript, &evidence.attempt_two)?;

    emit_phase(
        &mut transcript,
        5,
        "final_peerless_reopen",
        "receiver",
        "durable-resolved-empty",
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
        "alpha-resolved",
        &evidence.final_projection,
    )?;
    emit_selector(
        &mut transcript,
        "final_peerless_reopen",
        "beta",
        BETA_TOPIC,
        SCOPE,
        evidence.beta.id,
        true,
        false,
        true,
        false,
    )?;
    emit_selector(
        &mut transcript,
        "final_peerless_reopen",
        "gamma",
        ALPHA_TOPIC,
        gamma_scope.as_str(),
        evidence.gamma.id,
        false,
        true,
        false,
        false,
    )?;
    emit_empty(
        &mut transcript,
        "final_peerless_reopen",
        "receiver",
        "durable-empty",
    )?;
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
            ("phases", "5".to_owned()),
            ("participants", "2".to_owned()),
            ("processes", "3".to_owned()),
            ("actor_lifetimes", "7".to_owned()),
            ("maximum_concurrent_processes", "2".to_owned()),
            ("maximum_concurrent_actors", "2".to_owned()),
            ("graceful_shutdowns", "6".to_owned()),
            ("forced_process_terminations", "1".to_owned()),
            ("record_publications", "5".to_owned()),
            ("network_record_insertions", "3".to_owned()),
            ("polls", "7".to_owned()),
            ("deliveries", "4".to_owned()),
            ("acknowledgements", "2".to_owned()),
            ("reacknowledgements", "3".to_owned()),
            ("subscription_insertions", "1".to_owned()),
            ("subscription_replays", "5".to_owned()),
            ("token_binding_checks", "4".to_owned()),
            ("empty_polls", "3".to_owned()),
            ("bind_reacquisitions", "2".to_owned()),
            ("query_only_superseded", "2".to_owned()),
            ("payload_representation", "sha256-only".to_owned()),
            ("token_representation", "sha256-only".to_owned()),
            ("opaque_tokens_emitted", "false".to_owned()),
            ("secret_values_emitted", "false".to_owned()),
            ("physical_network_claimed", "false".to_owned()),
            ("automatic_merge_claimed", "false".to_owned()),
            ("global_convergence_claimed", "false".to_owned()),
            ("long_retention_claimed", "false".to_owned()),
        ],
    )?;
    require(
        transcript.records == TRANSCRIPT_RECORDS,
        "Record transcript record count",
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
            ("provisioning", "independent-node-bundle".to_owned()),
        ],
    )
}

fn emit_peer_binding(
    transcript: &mut TranscriptEmitter,
    participant: &Participant,
    remote: &Participant,
) -> Result<(), DynError> {
    transcript.emit(
        "peer_binding",
        &[
            ("participant", participant.name.to_owned()),
            ("expected_carrier_peer", remote.carrier_id.to_string()),
            ("expected_mission_peer", format_node_id(remote.mission_id)),
        ],
    )
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
    subscription: RecordSubscription,
    inserted: bool,
) -> Result<(), DynError> {
    transcript.emit(
        "subscription",
        &[
            ("phase", phase.to_owned()),
            ("participant", "receiver".to_owned()),
            ("id", subscription.id.to_string()),
            ("inserted", inserted.to_string()),
            ("topic", ALPHA_TOPIC.to_owned()),
            ("scope", SCOPE.to_owned()),
            ("include_descendant_scopes", "true".to_owned()),
        ],
    )
}

fn emit_publication(
    transcript: &mut TranscriptEmitter,
    phase: &'static str,
    participant: &'static str,
    label: &'static str,
    publication: &RecordPublishResult,
    payload: &[u8],
    tombstone: bool,
) -> Result<(), DynError> {
    transcript.emit(
        "publication",
        &[
            ("phase", phase.to_owned()),
            ("participant", participant.to_owned()),
            ("label", label.to_owned()),
            ("id", publication.id.to_string()),
            ("publisher", format_node_id(publication.publisher)),
            ("counter", publication.publisher_counter.to_string()),
            ("priority", priority_name(publication.priority).to_owned()),
            ("payload_sha256", sha256_hex(payload)),
            ("tombstone", tombstone.to_string()),
            ("inserted", publication.inserted.to_string()),
        ],
    )
}

fn emit_delivery(
    transcript: &mut TranscriptEmitter,
    phase: &'static str,
    participant: &'static str,
    label: &'static str,
    subscription: RecordSubscriptionId,
    delivery: &RecordDelivery,
    acknowledged: bool,
) -> Result<(), DynError> {
    let current = delivery
        .projection
        .current
        .as_ref()
        .ok_or(AcceptanceFailure("delivery current missing"))?;
    transcript.emit(
        "delivery",
        &[
            ("phase", phase.to_owned()),
            ("participant", participant.to_owned()),
            ("label", label.to_owned()),
            ("subscription_id", subscription.to_string()),
            ("projection_id", delivery.projection_id.to_string()),
            ("topic", delivery.key.topic.as_str().to_owned()),
            ("scope", delivery.key.scope.as_str().to_owned()),
            ("logical_key_sha256", sha256_hex(&delivery.key.logical_key)),
            ("current_id", current.id.to_string()),
            ("current_payload_sha256", sha256_hex(&current.payload)),
            ("current_tombstone", current.tombstone.to_string()),
            (
                "current_disposition",
                disposition_name(current.disposition).to_owned(),
            ),
            (
                "concurrent_ids",
                record_items_csv(&delivery.projection.concurrent),
            ),
            (
                "conflict_siblings",
                delivery
                    .projection
                    .conflict
                    .as_ref()
                    .map_or_else(|| "none".to_owned(), |conflict| ids_csv(&conflict.siblings)),
            ),
            ("attempt", delivery.attempt.to_string()),
            ("token_sha256", sha256_hex(delivery.token.as_bytes())),
            ("delivery_limit", DELIVERY_LIMIT.to_string()),
            ("scan_limit", SCAN_LIMIT.to_string()),
            ("has_more", "false".to_owned()),
            ("superseded_exposed", "false".to_owned()),
            ("resolution_guard_exposed", "false".to_owned()),
            ("acknowledged", acknowledged.to_string()),
        ],
    )
}

fn emit_projection(
    transcript: &mut TranscriptEmitter,
    phase: &'static str,
    participant: &'static str,
    label: &'static str,
    projection: &RecordProjection,
) -> Result<(), DynError> {
    let current = projection
        .current
        .as_ref()
        .ok_or(AcceptanceFailure("projection current missing"))?;
    transcript.emit(
        "projection",
        &[
            ("phase", phase.to_owned()),
            ("participant", participant.to_owned()),
            ("label", label.to_owned()),
            ("topic", current.topic.as_str().to_owned()),
            ("scope", current.scope.as_str().to_owned()),
            ("logical_key_sha256", sha256_hex(&current.logical_key)),
            ("current_id", current.id.to_string()),
            ("current_payload_sha256", sha256_hex(&current.payload)),
            ("current_tombstone", current.tombstone.to_string()),
            (
                "current_disposition",
                disposition_name(current.disposition).to_owned(),
            ),
            ("concurrent_ids", record_items_csv(&projection.concurrent)),
            ("superseded_ids", record_items_csv(&projection.superseded)),
            (
                "conflict_siblings",
                projection
                    .conflict
                    .as_ref()
                    .map_or_else(|| "none".to_owned(), |conflict| ids_csv(&conflict.siblings)),
            ),
            (
                "guard_siblings",
                projection.conflict.as_ref().map_or_else(
                    || "none".to_owned(),
                    |conflict| ids_csv(conflict.resolution_guard.siblings()),
                ),
            ),
        ],
    )
}

#[allow(clippy::too_many_arguments)]
fn emit_selector(
    transcript: &mut TranscriptEmitter,
    phase: &'static str,
    label: &'static str,
    topic: &str,
    scope: &str,
    record: RecordId,
    network_interested: bool,
    application_matched: bool,
    receiver_retained: bool,
    delivered: bool,
) -> Result<(), DynError> {
    transcript.emit(
        "selector",
        &[
            ("phase", phase.to_owned()),
            ("label", label.to_owned()),
            ("topic", topic.to_owned()),
            ("scope", scope.to_owned()),
            ("record_id", record.to_string()),
            ("network_interested", network_interested.to_string()),
            ("application_matched", application_matched.to_string()),
            ("receiver_retained", receiver_retained.to_string()),
            ("delivered", delivered.to_string()),
        ],
    )
}

fn emit_receipt(
    transcript: &mut TranscriptEmitter,
    evidence: &ReceiptEvidence,
) -> Result<(), DynError> {
    transcript.emit(
        "receipt",
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
            ("events", evidence.receipt.events.to_string()),
            ("blobs", evidence.receipt.blobs.to_string()),
        ],
    )
}

fn emit_child_delivery(
    transcript: &mut TranscriptEmitter,
    phase: &'static str,
    fields: &ChildFields,
    previous_token_sha256: &str,
    acknowledged: bool,
) -> Result<(), DynError> {
    transcript.emit(
        "child_delivery",
        &[
            ("phase", phase.to_owned()),
            (
                "participant",
                child_field(fields, "participant")?.to_owned(),
            ),
            (
                "projection_id",
                child_field(fields, "projection_id")?.to_owned(),
            ),
            (
                "projection_key_sha256",
                child_field(fields, "projection_key_sha256")?.to_owned(),
            ),
            ("siblings", child_field(fields, "siblings")?.to_owned()),
            ("current_id", child_field(fields, "current_id")?.to_owned()),
            (
                "concurrent_id",
                child_field(fields, "concurrent_id")?.to_owned(),
            ),
            ("attempt", child_field(fields, "attempt")?.to_owned()),
            (
                "token_sha256",
                child_field(fields, "token_sha256")?.to_owned(),
            ),
            ("previous_token_sha256", previous_token_sha256.to_owned()),
            (
                "delivery_limit",
                child_field(fields, "delivery_limit")?.to_owned(),
            ),
            ("scan_limit", child_field(fields, "scan_limit")?.to_owned()),
            ("has_more", child_field(fields, "has_more")?.to_owned()),
            (
                "superseded_exposed",
                child_field(fields, "superseded_exposed")?.to_owned(),
            ),
            (
                "resolution_guard_exposed",
                child_field(fields, "resolution_guard_exposed")?.to_owned(),
            ),
            ("acknowledged", acknowledged.to_string()),
        ],
    )
}

fn emit_token_checks(
    transcript: &mut TranscriptEmitter,
    fields: &ChildFields,
) -> Result<(), DynError> {
    transcript.emit(
        "token_checks",
        &[
            ("phase", "peerless_redelivery_resolution".to_owned()),
            ("token_bytes", RECORD_DELIVERY_TOKEN_BYTES.to_string()),
            (
                "attempt_tokens_distinct",
                child_field(fields, "tokens_distinct")?.to_owned(),
            ),
            (
                "attempt_one_restored",
                child_field(fields, "previous_token_restored")?.to_owned(),
            ),
            (
                "malformed_token_rejected",
                child_field(fields, "malformed_token_rejected")?.to_owned(),
            ),
            (
                "wrong_subscription_token_rejected",
                child_field(fields, "wrong_subscription_token_rejected")?.to_owned(),
            ),
            (
                "wrong_projection_token_rejected",
                child_field(fields, "wrong_projection_token_rejected")?.to_owned(),
            ),
            (
                "retired_singleton_token_rejected",
                child_field(fields, "retired_singleton_token_rejected")?.to_owned(),
            ),
            (
                "token_artifacts_removed",
                child_field(fields, "token_artifacts_removed")?.to_owned(),
            ),
        ],
    )
}

#[allow(clippy::too_many_arguments)]
fn emit_child_ack(
    transcript: &mut TranscriptEmitter,
    phase: &'static str,
    projection: &'static str,
    fields: &ChildFields,
    projection_id_field: &'static str,
    ack_field: &'static str,
    reack_field: &'static str,
    ack_token_attempt: &'static str,
    reack_token_attempt: &'static str,
    old_projection_reack: &str,
) -> Result<(), DynError> {
    transcript.emit(
        "acknowledgement",
        &[
            ("phase", phase.to_owned()),
            ("participant", "receiver".to_owned()),
            ("projection", projection.to_owned()),
            (
                "projection_id",
                child_field(fields, projection_id_field)?.to_owned(),
            ),
            ("ack", child_field(fields, ack_field)?.to_owned()),
            ("reack", child_field(fields, reack_field)?.to_owned()),
            ("ack_token_attempt", ack_token_attempt.to_owned()),
            ("reack_token_attempt", reack_token_attempt.to_owned()),
            ("old_projection_reack", old_projection_reack.to_owned()),
        ],
    )
}

fn emit_empty(
    transcript: &mut TranscriptEmitter,
    phase: &'static str,
    participant: &'static str,
    label: &'static str,
) -> Result<(), DynError> {
    transcript.emit(
        "empty_poll",
        &[
            ("phase", phase.to_owned()),
            ("participant", participant.to_owned()),
            ("label", label.to_owned()),
            ("deliveries", "0".to_owned()),
            ("has_more", "false".to_owned()),
        ],
    )
}

fn emit_resolution(
    transcript: &mut TranscriptEmitter,
    fields: &ChildFields,
) -> Result<(), DynError> {
    transcript.emit(
        "resolution",
        &[
            ("phase", "peerless_redelivery_resolution".to_owned()),
            ("participant", "receiver".to_owned()),
            ("id", child_field(fields, "resolution_id")?.to_owned()),
            (
                "publisher",
                child_field(fields, "resolution_publisher")?.to_owned(),
            ),
            (
                "counter",
                child_field(fields, "resolution_counter")?.to_owned(),
            ),
            ("priority", "immediate".to_owned()),
            ("payload_sha256", sha256_hex(RESOLVED_PAYLOAD)),
            ("tombstone", "false".to_owned()),
            (
                "inserted",
                child_field(fields, "resolution_inserted")?.to_owned(),
            ),
            (
                "retry_inserted",
                child_field(fields, "resolution_retry_inserted")?.to_owned(),
            ),
            (
                "retry_same",
                child_field(fields, "resolution_retry_same")?.to_owned(),
            ),
            (
                "guard_fresh_query",
                child_field(fields, "guard_fresh_query")?.to_owned(),
            ),
            (
                "guard_siblings",
                child_field(fields, "guard_siblings")?.to_owned(),
            ),
        ],
    )
}

fn emit_child_successor_delivery(
    transcript: &mut TranscriptEmitter,
    fields: &ChildFields,
) -> Result<(), DynError> {
    transcript.emit(
        "delivery",
        &[
            ("phase", "peerless_redelivery_resolution".to_owned()),
            ("participant", "receiver".to_owned()),
            ("label", "resolved-successor".to_owned()),
            (
                "subscription_id",
                child_field(fields, "subscription_id")?.to_owned(),
            ),
            (
                "projection_id",
                child_field(fields, "successor_projection_id")?.to_owned(),
            ),
            ("topic", ALPHA_TOPIC.to_owned()),
            ("scope", SCOPE.to_owned()),
            ("logical_key_sha256", sha256_hex(ALPHA_KEY)),
            (
                "current_id",
                child_field(fields, "resolution_id")?.to_owned(),
            ),
            ("current_payload_sha256", sha256_hex(RESOLVED_PAYLOAD)),
            ("current_tombstone", "false".to_owned()),
            ("current_disposition", "current".to_owned()),
            ("concurrent_ids", "none".to_owned()),
            ("conflict_siblings", "none".to_owned()),
            (
                "attempt",
                child_field(fields, "successor_attempt")?.to_owned(),
            ),
            (
                "token_sha256",
                child_field(fields, "successor_token_sha256")?.to_owned(),
            ),
            ("delivery_limit", DELIVERY_LIMIT.to_string()),
            ("scan_limit", SCAN_LIMIT.to_string()),
            ("has_more", "false".to_owned()),
            ("superseded_exposed", "false".to_owned()),
            ("resolution_guard_exposed", "false".to_owned()),
            ("acknowledged", "true".to_owned()),
        ],
    )
}

fn emit_child_resolved_projection(
    transcript: &mut TranscriptEmitter,
    fields: &ChildFields,
) -> Result<(), DynError> {
    transcript.emit(
        "projection",
        &[
            ("phase", "peerless_redelivery_resolution".to_owned()),
            ("participant", "receiver".to_owned()),
            ("label", "alpha-resolved-query".to_owned()),
            ("topic", ALPHA_TOPIC.to_owned()),
            ("scope", SCOPE.to_owned()),
            ("logical_key_sha256", sha256_hex(ALPHA_KEY)),
            (
                "current_id",
                child_field(fields, "resolution_id")?.to_owned(),
            ),
            ("current_payload_sha256", sha256_hex(RESOLVED_PAYLOAD)),
            ("current_tombstone", "false".to_owned()),
            ("current_disposition", "current".to_owned()),
            ("concurrent_ids", "none".to_owned()),
            (
                "superseded_ids",
                child_field(fields, "superseded_ids")?.to_owned(),
            ),
            ("conflict_siblings", "none".to_owned()),
            ("guard_siblings", "none".to_owned()),
        ],
    )
}

fn emit_child_receipt(
    transcript: &mut TranscriptEmitter,
    fields: &ChildFields,
) -> Result<(), DynError> {
    transcript.emit(
        "receipt",
        &[
            ("phase", "peerless_redelivery_resolution".to_owned()),
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
            ("events", child_field(fields, "shutdown_events")?.to_owned()),
            ("blobs", child_field(fields, "shutdown_blobs")?.to_owned()),
        ],
    )
}

fn emit_inspection(
    transcript: &mut TranscriptEmitter,
    participant: &'static str,
    inspection: &StoreInspection,
) -> Result<(), DynError> {
    transcript.emit(
        "inspection",
        &[
            ("participant", participant.to_owned()),
            ("record_rows", inspection.record_stats.records.to_string()),
            (
                "record_acceptance_markers",
                inspection.record_stats.acceptance_markers.to_string(),
            ),
            (
                "record_operations",
                inspection.record_stats.operations.to_string(),
            ),
            (
                "subscriptions",
                inspection
                    .record_subscription_stats
                    .subscriptions
                    .to_string(),
            ),
            (
                "pending_deliveries",
                inspection
                    .record_subscription_stats
                    .pending_deliveries
                    .to_string(),
            ),
            (
                "acknowledged_deliveries",
                inspection
                    .record_subscription_stats
                    .acknowledged_deliveries
                    .to_string(),
            ),
            (
                "delivery_cursors",
                inspection
                    .record_subscription_stats
                    .delivery_cursors
                    .to_string(),
            ),
            (
                "selector_generation",
                inspection
                    .record_subscription_stats
                    .selector_generation
                    .to_string(),
            ),
            (
                "other_namespaces_empty",
                other_namespaces_empty(inspection).to_string(),
            ),
        ],
    )
}

fn emit_bind(
    transcript: &mut TranscriptEmitter,
    participant: &'static str,
) -> Result<(), DynError> {
    transcript.emit(
        "bind",
        &[
            ("participant", participant.to_owned()),
            ("reacquired", "true".to_owned()),
        ],
    )
}

async fn run_acceptance(raw_root: PathBuf) -> Result<(), DynError> {
    let alpha = Topic::new(ALPHA_TOPIC)?;
    let beta_topic = Topic::new(BETA_TOPIC)?;
    let scope = Scope::new(SCOPE)?;
    let gamma_scope = Scope::new(format!("{SCOPE}/{GAMMA_SCOPE_SUFFIX}"))?;
    let alpha_query = record_query(&alpha, &scope, ALPHA_KEY, true);
    let beta_query = record_query(&beta_topic, &scope, BETA_KEY, true);
    let gamma_query = record_query(&alpha, &gamma_scope, GAMMA_KEY, true);
    let participants_root = raw_root.join("participants");
    create_owner_directory(&participants_root)?;
    let [publisher, mut receiver] = provision_participants(
        &participants_root,
        &alpha,
        &beta_topic,
        &scope,
        &gamma_scope,
    )?;
    validate_participant_domains(&publisher, &receiver)?;

    // Phase 1: two disconnected alpha origins and one unacknowledged
    // singleton delivery on the receiver.
    let publisher_peerless = start_peerless(&publisher).await?;
    let receiver_peerless = start_peerless(&receiver).await?;
    let publisher_records = publisher_peerless.selected_records();
    let receiver_records = receiver_peerless.selected_records();
    validate_handle(&publisher, &publisher_records)?;
    validate_handle(&receiver, &receiver_records)?;
    let subscription = receiver_records
        .subscribe(subscription_request(&alpha, &scope))
        .await?;
    require(
        subscription.inserted,
        "initial Record subscription insertion",
    )?;
    let subscription_retry = receiver_records
        .subscribe(subscription_request(&alpha, &scope))
        .await?;
    require(
        !subscription_retry.inserted && subscription_retry.id == subscription.id,
        "initial Record subscription replay",
    )?;

    let edit = publisher_records
        .publish(record_request(
            EDIT_OPERATION,
            &alpha,
            &scope,
            ALPHA_KEY,
            EDIT_PAYLOAD,
            false,
            Priority::Priority,
        ))
        .await?;
    let tombstone = receiver_records
        .publish(record_request(
            TOMBSTONE_OPERATION,
            &alpha,
            &scope,
            ALPHA_KEY,
            TOMBSTONE_PAYLOAD,
            true,
            Priority::Priority,
        ))
        .await?;
    validate_publication(&edit, &publisher, 1, Priority::Priority, true)?;
    validate_publication(&tombstone, &receiver, 1, Priority::Priority, true)?;
    require(edit.id != tombstone.id, "distinct Record origin identities")?;

    let singleton_page = poll(&receiver_records, subscription).await?;
    require(
        singleton_page.deliveries.len() == 1 && !singleton_page.has_more,
        "singleton Record delivery count",
    )?;
    let singleton_delivery = singleton_page.deliveries[0].clone();
    validate_singleton_delivery(&singleton_delivery, tombstone.id, 1)?;
    let singleton_projections = [
        publisher_records.query(alpha_query.clone()).await?,
        receiver_records.query(alpha_query.clone()).await?,
    ];
    validate_single_projection(
        &singleton_projections[0],
        &alpha,
        &scope,
        ALPHA_KEY,
        &edit,
        EDIT_PAYLOAD,
        false,
    )?;
    validate_single_projection(
        &singleton_projections[1],
        &alpha,
        &scope,
        ALPHA_KEY,
        &tombstone,
        TOMBSTONE_PAYLOAD,
        true,
    )?;
    let retained_publisher_peerless = publisher_records.clone();
    let retained_receiver_peerless = receiver_records.clone();
    let (publisher_peerless_receipt, receiver_peerless_receipt) =
        tokio::join!(publisher_peerless.shutdown(), receiver_peerless.shutdown());
    let publisher_peerless_receipt = publisher_peerless_receipt?;
    let receiver_peerless_receipt = receiver_peerless_receipt?;
    validate_peerless_receipt(&publisher_peerless_receipt)?;
    validate_peerless_receipt(&receiver_peerless_receipt)?;
    validate_closed_handle(&retained_publisher_peerless, alpha_query.clone()).await?;
    validate_closed_handle(&retained_receiver_peerless, alpha_query.clone()).await?;
    drop((
        publisher_records,
        receiver_records,
        retained_publisher_peerless,
        retained_receiver_peerless,
    ));

    let publisher_reservation = UdpSocket::bind(("127.0.0.1", 0))?;
    let receiver_reservation = UdpSocket::bind(("127.0.0.1", 0))?;
    let publisher_address = publisher_reservation.local_addr()?;
    let receiver_address = receiver_reservation.local_addr()?;
    require(
        publisher_address != receiver_address,
        "distinct Record acceptance binds",
    )?;
    drop((publisher_reservation, receiver_reservation));

    // Phase 2: exact-root Record interests converge the two alpha heads and
    // beta, while the alpha-descendant gamma remains outside network policy.
    let interests = configured_record_interests(&alpha, &beta_topic, &scope);
    let (publisher_connected, receiver_connected) = start_pair(
        &publisher,
        publisher_address,
        &receiver,
        receiver_address,
        interests,
    )
    .await?;
    let publisher_connected_records = publisher_connected.selected_records();
    let receiver_connected_records = receiver_connected.selected_records();
    let publisher_status = publisher_connected.selected_events();
    let receiver_status = receiver_connected.selected_events();
    validate_handle(&publisher, &publisher_connected_records)?;
    validate_handle(&receiver, &receiver_connected_records)?;
    let connected_subscription = receiver_connected_records
        .subscribe(subscription_request(&alpha, &scope))
        .await?;
    require(
        !connected_subscription.inserted && connected_subscription.id == subscription.id,
        "connected Record subscription replay",
    )?;
    let origin_ids = sorted_record_ids(edit.id, tombstone.id);
    let conflict_projections = wait_for_pair_conflict(
        &publisher_connected_records,
        &receiver_connected_records,
        &alpha_query,
        &origin_ids,
        "Record conflict convergence deadline",
    )
    .await?;
    validate_conflict_projection(
        &conflict_projections[0],
        &alpha,
        &scope,
        &edit,
        &tombstone,
        &origin_ids,
    )?;
    validate_conflict_projection(
        &conflict_projections[1],
        &alpha,
        &scope,
        &edit,
        &tombstone,
        &origin_ids,
    )?;
    require(
        equivalent_record_projections(&conflict_projections[0], &conflict_projections[1]),
        "identical connected Record conflicts",
    )?;
    let initial_contact = wait_for_contact_advance(
        &publisher_status,
        &receiver_status,
        [0, 0],
        "initial Record contact deadline",
    )
    .await?;

    let beta = publish_record_eventually(
        &publisher_connected_records,
        record_request(
            BETA_OPERATION,
            &beta_topic,
            &scope,
            BETA_KEY,
            BETA_PAYLOAD,
            false,
            Priority::Priority,
        ),
        "beta Record publication deadline",
    )
    .await?;
    validate_publication(&beta, &publisher, 2, Priority::Priority, true)?;
    let receiver_beta = wait_for_single_projection(
        &receiver_connected_records,
        &beta_query,
        beta.id,
        "beta Record network-interest deadline",
    )
    .await?;
    validate_single_projection(
        &receiver_beta,
        &beta_topic,
        &scope,
        BETA_KEY,
        &beta,
        BETA_PAYLOAD,
        false,
    )?;
    let _beta_contact = wait_for_contact_advance(
        &publisher_status,
        &receiver_status,
        initial_contact,
        "beta Record contact deadline",
    )
    .await?;

    let gamma = publish_record_eventually(
        &publisher_connected_records,
        record_request(
            GAMMA_OPERATION,
            &alpha,
            &gamma_scope,
            GAMMA_KEY,
            GAMMA_PAYLOAD,
            false,
            Priority::Priority,
        ),
        "gamma Record publication deadline",
    )
    .await?;
    validate_publication(&gamma, &publisher, 3, Priority::Priority, true)?;
    let publisher_gamma = query_record_eventually(
        &publisher_connected_records,
        gamma_query.clone(),
        "publisher gamma Record query deadline",
    )
    .await?;
    validate_single_projection(
        &publisher_gamma,
        &alpha,
        &gamma_scope,
        GAMMA_KEY,
        &gamma,
        GAMMA_PAYLOAD,
        false,
    )?;
    let gamma_contact_baseline = [
        publisher_status.status().await?.authenticated_contacts,
        receiver_status.status().await?.authenticated_contacts,
    ];
    let gamma_contact = wait_for_contact_advance(
        &publisher_status,
        &receiver_status,
        gamma_contact_baseline,
        "gamma Record withholding contact deadline",
    )
    .await?;
    let _post_gamma_contact = wait_for_contact_advance(
        &publisher_status,
        &receiver_status,
        gamma_contact,
        "post-gamma Record withholding contact deadline",
    )
    .await?;
    let receiver_gamma = query_record_eventually(
        &receiver_connected_records,
        gamma_query.clone(),
        "receiver gamma Record query deadline",
    )
    .await?;
    validate_empty_projection(&receiver_gamma, "gamma crossed configured Record interest")?;

    let retained_publisher_connected = publisher_connected_records.clone();
    let retained_receiver_connected = receiver_connected_records.clone();
    let (publisher_connected_receipt, receiver_connected_receipt) = tokio::join!(
        publisher_connected.shutdown(),
        receiver_connected.shutdown()
    );
    let publisher_connected_receipt = publisher_connected_receipt?;
    let receiver_connected_receipt = receiver_connected_receipt?;
    validate_direct_receipt(&publisher_connected_receipt)?;
    validate_direct_receipt(&receiver_connected_receipt)?;
    validate_transfer_pair(&publisher_connected_receipt, &receiver_connected_receipt, 3)?;
    validate_closed_handle(&retained_publisher_connected, alpha_query.clone()).await?;
    validate_closed_handle(&retained_receiver_connected, alpha_query.clone()).await?;
    drop((
        publisher_connected_records,
        receiver_connected_records,
        publisher_status,
        receiver_status,
        retained_publisher_connected,
        retained_receiver_connected,
    ));

    // Independent child processes must exclusively load the receiver mission
    // artifact, so release the parent's process-lifetime guard first.
    let receiver_mission = std::mem::replace(&mut receiver.mission, publisher.mission.clone());
    drop(receiver_mission);
    let artifacts = AttemptArtifacts {
        retry_token: receiver.root.join("attempt-one.record-token"),
        retired_singleton_token: receiver.root.join("retired-singleton.record-token"),
    };
    persist_delivery_token(&artifacts.retired_singleton_token, singleton_delivery.token)?;

    // Phase 3: the first receiver child commits whole-conflict attempt one,
    // flushes its token/evidence, and is killed before acknowledgement.
    let mut attempt_one = spawn_attempt_one(
        &receiver,
        &artifacts.retry_token,
        subscription.id,
        edit.id,
        tombstone.id,
        singleton_delivery.projection_id,
        beta.id,
    )?;
    let attempt_one_pid = attempt_one.child.id();
    let attempt_one_fields = wait_child_record(&mut attempt_one, "ATTEMPT1_READY").await?;
    validate_attempt_one_fields(
        &attempt_one_fields,
        &receiver,
        subscription.id,
        &origin_ids,
        singleton_delivery.projection_id,
        beta.id,
    )?;
    validate_token_artifact(
        &artifacts.retry_token,
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
    // Phase 4: a second receiver child replays attempt two, acknowledges it,
    // obtains a fresh query guard, resolves, and acknowledges the successor.
    let conflict_projection =
        parse_record_projection_id_value(child_field(&attempt_one_fields, "projection_id")?)?;
    let mut attempt_two = spawn_attempt_two(
        &receiver,
        &artifacts,
        subscription.id,
        edit.id,
        tombstone.id,
        singleton_delivery.projection_id,
        conflict_projection,
        beta.id,
    )?;
    let attempt_two_fields = wait_child_record(&mut attempt_two, "ATTEMPT2_DONE").await?;
    drain_child_lines(&mut attempt_two).await?;
    let attempt_two_status = attempt_two.child.wait()?;
    require(
        attempt_two_status.success() && attempt_two.saw_runtime_stop,
        "receiver Record retry child failed",
    )?;
    validate_attempt_two_fields(
        &attempt_two_fields,
        &receiver,
        subscription.id,
        &origin_ids,
        conflict_projection,
        beta.id,
        singleton_delivery.token,
    )?;
    require(
        !artifacts.retry_token.exists() && !artifacts.retired_singleton_token.exists(),
        "Record token artifact survived acknowledgement",
    )?;
    receiver.mission = UnprotectedReferenceMission::load(&receiver.mission_path)?;

    // Phase 5: final peerless reopen preserves the resolved query view, beta,
    // gamma withholding, durable selector, and empty acknowledged queue.
    let final_running = start_peerless(&receiver).await?;
    let final_records = final_running.selected_records();
    let final_subscription = final_records
        .subscribe(subscription_request(&alpha, &scope))
        .await?;
    require(
        !final_subscription.inserted && final_subscription.id == subscription.id,
        "final Record subscription replay",
    )?;
    let resolution_id = parse_record_id_value(child_field(&attempt_two_fields, "resolution_id")?)?;
    let final_projection = final_records.query(alpha_query.clone()).await?;
    validate_resolved_projection(&final_projection, resolution_id, &origin_ids)?;
    let final_beta = final_records.query(beta_query).await?;
    validate_single_projection(
        &final_beta,
        &beta_topic,
        &scope,
        BETA_KEY,
        &beta,
        BETA_PAYLOAD,
        false,
    )?;
    let final_gamma = final_records.query(gamma_query).await?;
    validate_empty_projection(&final_gamma, "gamma appeared on final Record reopen")?;
    validate_empty_poll(&final_records, subscription).await?;
    let retained_final = final_records.clone();
    let final_receipt = final_running.shutdown().await?;
    validate_peerless_receipt(&final_receipt)?;
    validate_closed_handle(&retained_final, alpha_query).await?;
    drop((final_records, retained_final));

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
            phase: "direct_conflict_and_selectors",
            participant: "publisher",
            receipt: publisher_connected_receipt,
        },
        ReceiptEvidence {
            phase: "direct_conflict_and_selectors",
            participant: "receiver",
            receipt: receiver_connected_receipt,
        },
        ReceiptEvidence {
            phase: "final_peerless_reopen",
            participant: "receiver",
            receipt: final_receipt,
        },
    ];
    emit_transcript(
        &publisher,
        &receiver,
        &gamma_scope,
        &AcceptanceEvidence {
            subscription,
            edit,
            tombstone,
            beta,
            gamma,
            singleton_delivery,
            singleton_projections,
            conflict_projections,
            attempt_one: attempt_one_fields,
            attempt_two: attempt_two_fields,
            final_projection,
            receipts,
            inspections: [publisher_inspection, receiver_inspection],
        },
    )?;
    Ok(())
}

async fn run_attempt_one_child(arguments: &[OsString]) -> Result<(), DynError> {
    require(arguments.len() == 8, "attempt-one child arguments")?;
    let state = PathBuf::from(&arguments[0]);
    let mission_path = PathBuf::from(&arguments[1]);
    let attempt_token_path = PathBuf::from(&arguments[2]);
    let expected_subscription = parse_record_subscription_id(&arguments[3])?;
    let edit = parse_record_id(&arguments[4])?;
    let tombstone = parse_record_id(&arguments[5])?;
    let singleton_projection = parse_record_projection_id(&arguments[6])?;
    let beta = parse_record_id(&arguments[7])?;
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
    let records = running.selected_records();
    require(
        records.identity() == receiver_id && records.mission_authority() == receiver_authority,
        "attempt-one child Record handle binding",
    )?;
    let alpha = Topic::new(ALPHA_TOPIC)?;
    let beta_topic = Topic::new(BETA_TOPIC)?;
    let scope = Scope::new(SCOPE)?;
    let gamma_scope = Scope::new(format!("{SCOPE}/{GAMMA_SCOPE_SUFFIX}"))?;
    let subscription = records
        .subscribe(subscription_request(&alpha, &scope))
        .await?;
    require(
        !subscription.inserted && subscription.id == expected_subscription,
        "attempt-one child Record subscription replay",
    )?;
    let siblings = sorted_record_ids(edit, tombstone);
    let projection = records
        .query(record_query(&alpha, &scope, ALPHA_KEY, true))
        .await?;
    validate_conflict_projection_ids(&projection, edit, tombstone, &siblings)?;
    let beta_projection = records
        .query(record_query(&beta_topic, &scope, BETA_KEY, true))
        .await?;
    validate_single_projection_id(
        &beta_projection,
        beta,
        &beta_topic,
        &scope,
        BETA_KEY,
        BETA_PAYLOAD,
        false,
    )?;
    let gamma_projection = records
        .query(record_query(&alpha, &gamma_scope, GAMMA_KEY, true))
        .await?;
    validate_empty_projection(&gamma_projection, "attempt-one gamma Record present")?;
    let page = poll(&records, subscription).await?;
    require(
        page.deliveries.len() == 1 && !page.has_more,
        "attempt-one Record delivery count",
    )?;
    let delivery = &page.deliveries[0];
    validate_conflict_delivery(delivery, edit, tombstone, &siblings, 1)?;
    require(
        delivery.projection_id != singleton_projection,
        "attempt-one Record singleton projection not retired",
    )?;
    persist_delivery_token(&attempt_token_path, delivery.token)?;
    let current = delivery
        .projection
        .current
        .as_ref()
        .ok_or(AcceptanceFailure("attempt-one current missing"))?;
    let concurrent = delivery
        .projection
        .concurrent
        .first()
        .ok_or(AcceptanceFailure("attempt-one concurrent missing"))?;
    emit_child(
        "ATTEMPT1_READY",
        &[
            ("participant", "receiver".to_owned()),
            ("identity", format_node_id(receiver_id)),
            ("subscription_id", subscription.id.to_string()),
            ("subscription_inserted", subscription.inserted.to_string()),
            ("projection_id", delivery.projection_id.to_string()),
            ("projection_topic", delivery.key.topic.as_str().to_owned()),
            ("projection_scope", delivery.key.scope.as_str().to_owned()),
            (
                "projection_key_sha256",
                projection_key_sha256(&delivery.key),
            ),
            ("edit_id", edit.to_string()),
            ("tombstone_id", tombstone.to_string()),
            ("current_id", current.id.to_string()),
            ("concurrent_id", concurrent.id.to_string()),
            ("siblings", ids_csv(&siblings)),
            ("attempt", delivery.attempt.to_string()),
            ("token_sha256", sha256_hex(delivery.token.as_bytes())),
            ("delivery_limit", DELIVERY_LIMIT.to_string()),
            ("scan_limit", SCAN_LIMIT.to_string()),
            ("has_more", page.has_more.to_string()),
            ("superseded_exposed", "false".to_owned()),
            ("resolution_guard_exposed", "false".to_owned()),
            ("token_persisted", "true".to_owned()),
            ("singleton_projection_changed", "true".to_owned()),
            ("beta_id", beta.to_string()),
            ("beta_present", "true".to_owned()),
            ("gamma_empty", "true".to_owned()),
            ("acknowledged", "false".to_owned()),
        ],
    )?;
    std::future::pending::<()>().await;
    #[allow(unreachable_code)]
    Ok(())
}

async fn run_attempt_two_child(arguments: &[OsString]) -> Result<(), DynError> {
    require(arguments.len() == 10, "attempt-two child arguments")?;
    let state = PathBuf::from(&arguments[0]);
    let mission_path = PathBuf::from(&arguments[1]);
    let attempt_token_path = PathBuf::from(&arguments[2]);
    let retired_token_path = PathBuf::from(&arguments[3]);
    let expected_subscription = parse_record_subscription_id(&arguments[4])?;
    let edit = parse_record_id(&arguments[5])?;
    let tombstone = parse_record_id(&arguments[6])?;
    let singleton_projection = parse_record_projection_id(&arguments[7])?;
    let expected_projection = parse_record_projection_id(&arguments[8])?;
    let beta = parse_record_id(&arguments[9])?;
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
    let records = running.selected_records();
    let alpha = Topic::new(ALPHA_TOPIC)?;
    let beta_topic = Topic::new(BETA_TOPIC)?;
    let scope = Scope::new(SCOPE)?;
    let gamma_scope = Scope::new(format!("{SCOPE}/{GAMMA_SCOPE_SUFFIX}"))?;
    let subscription = records
        .subscribe(subscription_request(&alpha, &scope))
        .await?;
    require(
        !subscription.inserted && subscription.id == expected_subscription,
        "attempt-two child Record subscription replay",
    )?;
    let siblings = sorted_record_ids(edit, tombstone);
    let projection = records
        .query(record_query(&alpha, &scope, ALPHA_KEY, true))
        .await?;
    validate_conflict_projection_ids(&projection, edit, tombstone, &siblings)?;
    let beta_projection = records
        .query(record_query(&beta_topic, &scope, BETA_KEY, true))
        .await?;
    validate_single_projection_id(
        &beta_projection,
        beta,
        &beta_topic,
        &scope,
        BETA_KEY,
        BETA_PAYLOAD,
        false,
    )?;
    let gamma_projection = records
        .query(record_query(&alpha, &gamma_scope, GAMMA_KEY, true))
        .await?;
    validate_empty_projection(&gamma_projection, "attempt-two gamma Record present")?;
    let page = poll(&records, subscription).await?;
    require(
        page.deliveries.len() == 1 && !page.has_more,
        "attempt-two Record delivery count",
    )?;
    let delivery = page
        .deliveries
        .into_iter()
        .next()
        .ok_or(AcceptanceFailure("attempt-two Record delivery missing"))?;
    validate_conflict_delivery(&delivery, edit, tombstone, &siblings, 2)?;
    require(
        delivery.projection_id == expected_projection,
        "attempt-two Record projection identity changed",
    )?;
    let first_token = consume_delivery_token(&attempt_token_path)?;
    let retired_singleton_token = consume_delivery_token(&retired_token_path)?;
    require(
        first_token != delivery.token,
        "Record retry reused opaque delivery token",
    )?;
    let malformed = RecordDeliveryToken::from_bytes([0_u8; RECORD_DELIVERY_TOKEN_BYTES])
        .expect_err("all-zero Record delivery token must be rejected");
    require(
        malformed.kind() == ApplicationErrorKind::InvalidRequest
            && malformed.operation() == "record delivery token",
        "malformed Record delivery token rejection",
    )?;
    let mut wrong_subscription_bytes = *subscription.id.as_bytes();
    wrong_subscription_bytes[0] ^= 0x80;
    let wrong_subscription = RecordSubscriptionId::from_bytes(wrong_subscription_bytes);
    wrong_subscription_bytes.zeroize();
    let wrong_subscription_error = records
        .acknowledge(wrong_subscription, delivery.projection_id, first_token)
        .await
        .expect_err("Record token must bind subscription");
    require(
        wrong_subscription_error.kind() == ApplicationErrorKind::InvalidRequest
            && wrong_subscription_error.operation() == "record acknowledge",
        "Record token subscription binding",
    )?;
    let mut wrong_projection_bytes = *delivery.projection_id.as_bytes();
    wrong_projection_bytes[0] ^= 0x80;
    let wrong_projection = RecordProjectionId::from_bytes(wrong_projection_bytes);
    wrong_projection_bytes.zeroize();
    let wrong_projection_error = records
        .acknowledge(subscription.id, wrong_projection, first_token)
        .await
        .expect_err("Record token must bind projection");
    require(
        wrong_projection_error.kind() == ApplicationErrorKind::InvalidRequest
            && wrong_projection_error.operation() == "record acknowledge",
        "Record token projection binding",
    )?;
    let retired_error = records
        .acknowledge(
            subscription.id,
            singleton_projection,
            retired_singleton_token,
        )
        .await
        .expect_err("retired singleton Record token must fail");
    require(
        retired_error.kind() == ApplicationErrorKind::InvalidRequest
            && retired_error.operation() == "record acknowledge",
        "retired singleton Record token rejection",
    )?;
    let conflict_ack = records
        .acknowledge(subscription.id, delivery.projection_id, first_token)
        .await?;
    let conflict_reack = records
        .acknowledge(subscription.id, delivery.projection_id, delivery.token)
        .await?;
    require(
        conflict_ack == RecordAcknowledgement::Acknowledged
            && conflict_reack == RecordAcknowledgement::AlreadyAcknowledged,
        "conflict Record acknowledgements",
    )?;
    validate_empty_poll(&records, subscription).await?;

    let fresh_query = RecordQuery {
        topic: delivery.key.topic.clone(),
        scope: delivery.key.scope.clone(),
        logical_key: delivery.key.logical_key.clone(),
        include_superseded_versions: false,
    };
    let queried = records.query(fresh_query).await?;
    let conflict = queried
        .conflict
        .ok_or(AcceptanceFailure("fresh Record query conflict missing"))?;
    require(
        conflict.siblings == siblings
            && conflict.resolution_guard.siblings() == siblings
            && conflict.resolution_guard.topic() == &delivery.key.topic
            && conflict.resolution_guard.scope() == &delivery.key.scope
            && conflict.resolution_guard.logical_key() == delivery.key.logical_key,
        "fresh Record query guard binding",
    )?;
    let guard_siblings = conflict.siblings.clone();
    let resolution_request = RecordResolveRequest {
        operation_key: RESOLUTION_OPERATION.to_vec(),
        resolution_guard: conflict.resolution_guard,
        priority: Priority::Immediate,
        payload: RESOLVED_PAYLOAD.to_vec(),
        tombstone: false,
    };
    let resolution = records.resolve(resolution_request.clone()).await?;
    let resolution_retry = records.resolve(resolution_request).await?;
    require(
        resolution.inserted
            && !resolution_retry.inserted
            && resolution_retry.id == resolution.id
            && resolution.publisher == receiver_id
            && resolution.publisher_counter == 2
            && resolution.priority == Priority::Immediate,
        "guarded Record resolution",
    )?;
    let successor_page = poll(&records, subscription).await?;
    require(
        successor_page.deliveries.len() == 1 && !successor_page.has_more,
        "successor Record delivery count",
    )?;
    let successor = successor_page
        .deliveries
        .into_iter()
        .next()
        .ok_or(AcceptanceFailure("successor Record delivery missing"))?;
    validate_successor_delivery(
        &successor,
        &delivery.key,
        resolution.id,
        delivery.projection_id,
    )?;
    let old_conflict_reack = records
        .acknowledge(subscription.id, delivery.projection_id, delivery.token)
        .await?;
    require(
        old_conflict_reack == RecordAcknowledgement::AlreadyAcknowledged,
        "old conflict Record reacknowledgement",
    )?;
    let successor_ack = records
        .acknowledge(subscription.id, successor.projection_id, successor.token)
        .await?;
    let successor_reack = records
        .acknowledge(subscription.id, successor.projection_id, successor.token)
        .await?;
    require(
        successor_ack == RecordAcknowledgement::Acknowledged
            && successor_reack == RecordAcknowledgement::AlreadyAcknowledged,
        "successor Record acknowledgements",
    )?;
    validate_empty_poll(&records, subscription).await?;
    let resolved_projection = records
        .query(record_query(&alpha, &scope, ALPHA_KEY, true))
        .await?;
    validate_resolved_projection(&resolved_projection, resolution.id, &siblings)?;
    let superseded_ids = resolved_projection
        .superseded
        .iter()
        .map(|item| item.id)
        .collect::<Vec<_>>();
    let current = delivery
        .projection
        .current
        .as_ref()
        .ok_or(AcceptanceFailure("attempt-two current missing"))?;
    let concurrent = delivery
        .projection
        .concurrent
        .first()
        .ok_or(AcceptanceFailure("attempt-two concurrent missing"))?;
    let retained = records.clone();
    let receipt = running.shutdown().await?;
    validate_peerless_receipt(&receipt)?;
    validate_closed_handle(&retained, record_query(&alpha, &scope, ALPHA_KEY, true)).await?;
    let mut fields = vec![
        ("participant", "receiver".to_owned()),
        ("identity", format_node_id(receiver_id)),
        ("subscription_id", subscription.id.to_string()),
        ("subscription_inserted", subscription.inserted.to_string()),
        ("projection_id", delivery.projection_id.to_string()),
        ("projection_topic", delivery.key.topic.as_str().to_owned()),
        ("projection_scope", delivery.key.scope.as_str().to_owned()),
        (
            "projection_key_sha256",
            projection_key_sha256(&delivery.key),
        ),
        ("edit_id", edit.to_string()),
        ("tombstone_id", tombstone.to_string()),
        ("current_id", current.id.to_string()),
        ("concurrent_id", concurrent.id.to_string()),
        ("siblings", ids_csv(&siblings)),
        ("attempt", delivery.attempt.to_string()),
        ("token_sha256", sha256_hex(delivery.token.as_bytes())),
        ("delivery_limit", DELIVERY_LIMIT.to_string()),
        ("scan_limit", SCAN_LIMIT.to_string()),
        ("has_more", page.has_more.to_string()),
        ("superseded_exposed", "false".to_owned()),
        ("resolution_guard_exposed", "false".to_owned()),
        ("previous_token_sha256", sha256_hex(first_token.as_bytes())),
        ("tokens_distinct", "true".to_owned()),
        ("previous_token_restored", "true".to_owned()),
        ("malformed_token_rejected", "true".to_owned()),
        ("wrong_subscription_token_rejected", "true".to_owned()),
        ("wrong_projection_token_rejected", "true".to_owned()),
        ("retired_singleton_token_rejected", "true".to_owned()),
        (
            "retired_singleton_token_sha256",
            sha256_hex(retired_singleton_token.as_bytes()),
        ),
        ("ack_token_attempt", "1".to_owned()),
        ("reack_token_attempt", "2".to_owned()),
        (
            "conflict_ack",
            acknowledgement_name(conflict_ack).to_owned(),
        ),
        (
            "conflict_reack",
            acknowledgement_name(conflict_reack).to_owned(),
        ),
        ("post_conflict_empty", "true".to_owned()),
        ("guard_fresh_query", "true".to_owned()),
        ("guard_siblings", ids_csv(&guard_siblings)),
        ("resolution_id", resolution.id.to_string()),
        ("resolution_publisher", format_node_id(resolution.publisher)),
        (
            "resolution_counter",
            resolution.publisher_counter.to_string(),
        ),
        ("resolution_inserted", resolution.inserted.to_string()),
        (
            "resolution_retry_inserted",
            resolution_retry.inserted.to_string(),
        ),
        ("resolution_retry_same", "true".to_owned()),
        (
            "successor_projection_id",
            successor.projection_id.to_string(),
        ),
        ("successor_attempt", successor.attempt.to_string()),
        (
            "successor_token_sha256",
            sha256_hex(successor.token.as_bytes()),
        ),
        (
            "successor_ack",
            acknowledgement_name(successor_ack).to_owned(),
        ),
        (
            "successor_reack",
            acknowledgement_name(successor_reack).to_owned(),
        ),
        (
            "old_conflict_reack",
            acknowledgement_name(old_conflict_reack).to_owned(),
        ),
        ("post_successor_empty", "true".to_owned()),
        ("superseded_ids", ids_csv(&superseded_ids)),
        ("beta_id", beta.to_string()),
        ("beta_present", "true".to_owned()),
        ("gamma_empty", "true".to_owned()),
        ("token_artifacts_removed", "true".to_owned()),
        ("closed_kind", "state_unavailable".to_owned()),
        ("closed_operation", "record_query".to_owned()),
    ];
    fields.extend(prefixed_receipt_fields(&receipt));
    emit_child("ATTEMPT2_DONE", &fields)?;
    Ok(())
}

fn provision_participants(
    participants_root: &Path,
    alpha: &Topic,
    beta: &Topic,
    scope: &Scope,
    gamma_scope: &Scope,
) -> Result<[Participant; 2], DynError> {
    let root_access =
        ProvisioningAccess::member(scope.clone(), vec![1], vec![alpha.clone(), beta.clone()])?;
    let gamma_access =
        ProvisioningAccess::member(gamma_scope.clone(), vec![1], vec![alpha.clone()])?;
    let accesses = [root_access, gamma_access];
    let mut seed = [0u8; 32];
    if let Err(error) = getrandom::fill(&mut seed) {
        seed.zeroize();
        return Err(Box::new(error));
    }
    let provisioner = ReferenceProvisioner::from_seed(seed);
    seed.zeroize();
    let mut provisioner = provisioner?;
    let first_bundle = provisioner.issue_node(1, &accesses)?;
    let second_bundle = provisioner.issue_node(2, &accesses)?;
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
        "deterministic Record publisher ordering",
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
        "independently provisioned Record participants",
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
        "Record participant identity domains",
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

fn configured_record_interests(
    alpha: &Topic,
    beta: &Topic,
    scope: &Scope,
) -> MutableSourceInterests {
    MutableSourceInterests::new(
        Vec::new(),
        vec![
            SourceInterestSelector::new(alpha.clone(), scope.clone(), false),
            SourceInterestSelector::new(beta.clone(), scope.clone(), false),
        ],
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

#[allow(clippy::too_many_arguments)]
fn record_request(
    operation: &[u8],
    topic: &Topic,
    scope: &Scope,
    logical_key: &[u8],
    payload: &[u8],
    tombstone: bool,
    priority: Priority,
) -> RecordPublishRequest {
    RecordPublishRequest {
        operation_key: operation.to_vec(),
        topic: topic.clone(),
        scope: scope.clone(),
        priority,
        logical_key: logical_key.to_vec(),
        payload: payload.to_vec(),
        tombstone,
    }
}

fn subscription_request(topic: &Topic, scope: &Scope) -> RecordSubscriptionRequest {
    RecordSubscriptionRequest {
        operation_key: SUBSCRIPTION_OPERATION.to_vec(),
        topic: topic.clone(),
        scope: scope.clone(),
        include_descendant_scopes: true,
    }
}

fn record_query(
    topic: &Topic,
    scope: &Scope,
    logical_key: &[u8],
    include_superseded_versions: bool,
) -> RecordQuery {
    RecordQuery {
        topic: topic.clone(),
        scope: scope.clone(),
        logical_key: logical_key.to_vec(),
        include_superseded_versions,
    }
}

async fn poll(
    records: &SelectedRecordHandle,
    subscription: RecordSubscription,
) -> Result<aster_node::application::RecordDeliveryPage, ApplicationError> {
    records
        .poll(RecordPollRequest {
            subscription: subscription.id,
            delivery_limit: DELIVERY_LIMIT,
            scan_limit: SCAN_LIMIT,
        })
        .await
}

async fn validate_empty_poll(
    records: &SelectedRecordHandle,
    subscription: RecordSubscription,
) -> Result<(), DynError> {
    let page = poll(records, subscription).await?;
    require(
        page.deliveries.is_empty() && !page.has_more,
        "Record poll was not empty",
    )
}

fn spawn_attempt_one(
    receiver: &Participant,
    retry_token: &Path,
    subscription: RecordSubscriptionId,
    edit: RecordId,
    tombstone: RecordId,
    singleton_projection: RecordProjectionId,
    beta: RecordId,
) -> Result<ChildActor, DynError> {
    let mut command = Command::new(env::current_exe()?);
    command
        .arg("--internal-attempt-1")
        .arg(&receiver.state)
        .arg(&receiver.mission_path)
        .arg(retry_token)
        .arg(subscription.to_string())
        .arg(edit.to_string())
        .arg(tombstone.to_string())
        .arg(singleton_projection.to_string())
        .arg(beta.to_string());
    spawn_child(command)
}

#[allow(clippy::too_many_arguments)]
fn spawn_attempt_two(
    receiver: &Participant,
    artifacts: &AttemptArtifacts,
    subscription: RecordSubscriptionId,
    edit: RecordId,
    tombstone: RecordId,
    singleton_projection: RecordProjectionId,
    conflict_projection: RecordProjectionId,
    beta: RecordId,
) -> Result<ChildActor, DynError> {
    let mut command = Command::new(env::current_exe()?);
    command
        .arg("--internal-attempt-2")
        .arg(&receiver.state)
        .arg(&receiver.mission_path)
        .arg(&artifacts.retry_token)
        .arg(&artifacts.retired_singleton_token)
        .arg(subscription.to_string())
        .arg(edit.to_string())
        .arg(tombstone.to_string())
        .arg(singleton_projection.to_string())
        .arg(conflict_projection.to_string())
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
    print!("LIVE_RECORD_SUBSCRIPTION_CHILD\t{kind}");
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
    if !line.starts_with("LIVE_RECORD_SUBSCRIPTION_CHILD\t") {
        return Ok(None);
    }
    let mut parts = line.split('\t');
    require(
        parts.next() == Some("LIVE_RECORD_SUBSCRIPTION_CHILD"),
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

fn parse_record_id(argument: &OsString) -> Result<RecordId, DynError> {
    Ok(RecordId::from_bytes(parse_hex_32_os(argument)?))
}

fn parse_record_projection_id(argument: &OsString) -> Result<RecordProjectionId, DynError> {
    Ok(RecordProjectionId::from_bytes(parse_hex_32_os(argument)?))
}

fn parse_record_subscription_id(argument: &OsString) -> Result<RecordSubscriptionId, DynError> {
    Ok(RecordSubscriptionId::from_bytes(parse_hex_32_os(argument)?))
}

fn parse_hex_32_os(argument: &OsString) -> Result<[u8; 32], DynError> {
    let value = argument
        .to_str()
        .ok_or_else(|| Box::new(AcceptanceFailure("child identifier encoding")) as DynError)?;
    parse_hex_32(value)
}

fn parse_record_id_value(value: &str) -> Result<RecordId, DynError> {
    Ok(RecordId::from_bytes(parse_hex_32(value)?))
}

fn parse_record_projection_id_value(value: &str) -> Result<RecordProjectionId, DynError> {
    Ok(RecordProjectionId::from_bytes(parse_hex_32(value)?))
}

fn parse_hex_32(value: &str) -> Result<[u8; 32], DynError> {
    require(value.len() == 64, "identifier length")?;
    let mut bytes = [0u8; 32];
    for (index, byte) in bytes.iter_mut().enumerate() {
        let offset = index * 2;
        *byte = u8::from_str_radix(&value[offset..offset + 2], 16)
            .map_err(|_| AcceptanceFailure("identifier value"))?;
    }
    Ok(bytes)
}

#[cfg(unix)]
fn persist_delivery_token(path: &Path, token: RecordDeliveryToken) -> Result<(), DynError> {
    use std::os::unix::fs::OpenOptionsExt as _;

    require(path.is_absolute(), "Record token path must be absolute")?;
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
fn persist_delivery_token(path: &Path, token: RecordDeliveryToken) -> Result<(), DynError> {
    require(path.is_absolute(), "Record token path must be absolute")?;
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
        "Record token artifact digest",
    )
}

fn consume_delivery_token(path: &Path) -> Result<RecordDeliveryToken, DynError> {
    let token = read_delivery_token(path)?;
    fs::remove_file(path)?;
    require(!path.exists(), "Record token artifact removal")?;
    Ok(token)
}

fn read_delivery_token(path: &Path) -> Result<RecordDeliveryToken, DynError> {
    let metadata = fs::symlink_metadata(path)?;
    require(
        metadata.file_type().is_file()
            && metadata.len() == u64::try_from(RECORD_DELIVERY_TOKEN_BYTES)?,
        "Record token artifact type",
    )?;
    validate_token_permissions(&metadata)?;
    let mut file = fs::File::open(path)?;
    let mut bytes = [0_u8; RECORD_DELIVERY_TOKEN_BYTES];
    file.read_exact(&mut bytes)?;
    let token = RecordDeliveryToken::from_bytes(bytes)?;
    bytes.zeroize();
    Ok(token)
}

#[cfg(unix)]
fn validate_token_permissions(metadata: &fs::Metadata) -> Result<(), DynError> {
    use std::os::unix::fs::PermissionsExt as _;

    require(
        metadata.permissions().mode() & 0o777 == 0o600,
        "Record token artifact permissions",
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
        "receiver Record child was not force terminated",
    )
}

fn validate_handle(
    participant: &Participant,
    handle: &SelectedRecordHandle,
) -> Result<(), DynError> {
    require(
        handle.identity() == participant.mission_id
            && handle.mission_authority() == participant.mission_authority,
        "selected Record handle mission binding",
    )
}

fn validate_publication(
    publication: &RecordPublishResult,
    participant: &Participant,
    counter: u64,
    priority: Priority,
    inserted: bool,
) -> Result<(), DynError> {
    require(
        publication.publisher == participant.mission_id
            && publication.publisher_counter == counter
            && publication.priority == priority
            && publication.inserted == inserted
            && publication.acceptance_marker > 0,
        "Record publication metadata",
    )
}

fn validate_singleton_delivery(
    delivery: &RecordDelivery,
    expected: RecordId,
    attempt: u64,
) -> Result<(), DynError> {
    let current = delivery
        .projection
        .current
        .as_ref()
        .ok_or(AcceptanceFailure("singleton Record current missing"))?;
    require(
        delivery.key.topic == Topic::new(ALPHA_TOPIC)?
            && delivery.key.scope == Scope::new(SCOPE)?
            && delivery.key.logical_key == ALPHA_KEY
            && current.id == expected
            && current.payload == TOMBSTONE_PAYLOAD
            && current.tombstone
            && current.disposition == RecordVersionDisposition::Current
            && delivery.projection.concurrent.is_empty()
            && delivery.projection.conflict.is_none()
            && delivery.attempt == attempt,
        "singleton Record delivery",
    )
}

#[allow(clippy::too_many_arguments)]
fn validate_single_projection(
    projection: &RecordProjection,
    topic: &Topic,
    scope: &Scope,
    logical_key: &[u8],
    publication: &RecordPublishResult,
    payload: &[u8],
    tombstone: bool,
) -> Result<(), DynError> {
    validate_single_projection_id(
        projection,
        publication.id,
        topic,
        scope,
        logical_key,
        payload,
        tombstone,
    )?;
    let current = projection
        .current
        .as_ref()
        .ok_or(AcceptanceFailure("single Record current missing"))?;
    require(
        current.publisher == publication.publisher
            && current.publisher_counter == publication.publisher_counter
            && current.priority == publication.priority
            && current.acceptance_marker == publication.acceptance_marker,
        "single Record publication binding",
    )
}

#[allow(clippy::too_many_arguments)]
fn validate_single_projection_id(
    projection: &RecordProjection,
    expected: RecordId,
    topic: &Topic,
    scope: &Scope,
    logical_key: &[u8],
    payload: &[u8],
    tombstone: bool,
) -> Result<(), DynError> {
    let current = projection
        .current
        .as_ref()
        .ok_or(AcceptanceFailure("single Record current missing"))?;
    require(
        current.id == expected
            && current.topic == *topic
            && current.scope == *scope
            && current.logical_key == logical_key
            && current.payload == payload
            && current.tombstone == tombstone
            && current.disposition == RecordVersionDisposition::Current
            && projection.concurrent.is_empty()
            && projection.superseded.is_empty()
            && projection.conflict.is_none(),
        "single Record projection",
    )
}

fn validate_empty_projection(
    projection: &RecordProjection,
    label: &'static str,
) -> Result<(), DynError> {
    require(
        projection.current.is_none()
            && projection.concurrent.is_empty()
            && projection.superseded.is_empty()
            && projection.conflict.is_none(),
        label,
    )
}

fn validate_conflict_projection(
    projection: &RecordProjection,
    topic: &Topic,
    scope: &Scope,
    edit: &RecordPublishResult,
    tombstone: &RecordPublishResult,
    expected_ids: &[RecordId],
) -> Result<(), DynError> {
    validate_conflict_projection_ids(projection, edit.id, tombstone.id, expected_ids)?;
    for item in projection.current.iter().chain(&projection.concurrent) {
        let expected = if item.id == edit.id { edit } else { tombstone };
        require(
            item.publisher == expected.publisher
                && item.publisher_counter == expected.publisher_counter
                && item.topic == *topic
                && item.scope == *scope
                && item.priority == Priority::Priority
                && item.logical_key == ALPHA_KEY,
            "Record conflict publication binding",
        )?;
    }
    Ok(())
}

fn validate_conflict_projection_ids(
    projection: &RecordProjection,
    edit: RecordId,
    tombstone: RecordId,
    expected_ids: &[RecordId],
) -> Result<(), DynError> {
    let current = projection
        .current
        .as_ref()
        .ok_or(AcceptanceFailure("Record conflict current missing"))?;
    let concurrent = projection
        .concurrent
        .first()
        .ok_or(AcceptanceFailure("Record conflict concurrent missing"))?;
    let conflict = projection
        .conflict
        .as_ref()
        .ok_or(AcceptanceFailure("Record conflict annotation missing"))?;
    require(
        projection.concurrent.len() == 1
            && projection.superseded.is_empty()
            && conflict.siblings == expected_ids
            && conflict.resolution_guard.siblings() == expected_ids
            && current.id == edit.max(tombstone)
            && concurrent.id == edit.min(tombstone)
            && current.disposition == RecordVersionDisposition::Current
            && concurrent.disposition == RecordVersionDisposition::Concurrent,
        "whole Record conflict projection",
    )?;
    validate_origin_item(current, edit, tombstone)?;
    validate_origin_item(concurrent, edit, tombstone)
}

fn validate_origin_item(
    item: &RecordItem,
    edit: RecordId,
    tombstone: RecordId,
) -> Result<(), DynError> {
    let (payload, is_tombstone) = if item.id == edit {
        (EDIT_PAYLOAD, false)
    } else if item.id == tombstone {
        (TOMBSTONE_PAYLOAD, true)
    } else {
        return Err(Box::new(AcceptanceFailure("unknown Record origin item")));
    };
    require(
        item.topic == Topic::new(ALPHA_TOPIC)?
            && item.scope == Scope::new(SCOPE)?
            && item.logical_key == ALPHA_KEY
            && item.priority == Priority::Priority
            && item.payload == payload
            && item.tombstone == is_tombstone,
        "Record origin item metadata",
    )
}

fn validate_conflict_delivery(
    delivery: &RecordDelivery,
    edit: RecordId,
    tombstone: RecordId,
    expected_ids: &[RecordId],
    attempt: u64,
) -> Result<(), DynError> {
    let current = delivery
        .projection
        .current
        .as_ref()
        .ok_or(AcceptanceFailure("Record delivery current missing"))?;
    let concurrent = delivery
        .projection
        .concurrent
        .first()
        .ok_or(AcceptanceFailure("Record delivery concurrent missing"))?;
    let conflict = delivery
        .projection
        .conflict
        .as_ref()
        .ok_or(AcceptanceFailure("Record delivery conflict missing"))?;
    require(
        delivery.key.topic == Topic::new(ALPHA_TOPIC)?
            && delivery.key.scope == Scope::new(SCOPE)?
            && delivery.key.logical_key == ALPHA_KEY
            && delivery.projection.concurrent.len() == 1
            && conflict.siblings == expected_ids
            && conflict.siblings.windows(2).all(|pair| pair[0] < pair[1])
            && current.id == edit.max(tombstone)
            && concurrent.id == edit.min(tombstone)
            && delivery.attempt == attempt,
        "whole Record conflict delivery",
    )?;
    validate_origin_item(current, edit, tombstone)?;
    validate_origin_item(concurrent, edit, tombstone)
}

fn validate_successor_delivery(
    delivery: &RecordDelivery,
    expected_key: &RecordProjectionKey,
    resolution: RecordId,
    old_projection: RecordProjectionId,
) -> Result<(), DynError> {
    let current = delivery
        .projection
        .current
        .as_ref()
        .ok_or(AcceptanceFailure("successor Record current missing"))?;
    require(
        delivery.projection_id != old_projection
            && delivery.key == *expected_key
            && delivery.attempt == 1
            && current.id == resolution
            && current.priority == Priority::Immediate
            && current.payload == RESOLVED_PAYLOAD
            && !current.tombstone
            && current.disposition == RecordVersionDisposition::Current
            && delivery.projection.concurrent.is_empty()
            && delivery.projection.conflict.is_none(),
        "resolved successor Record delivery",
    )
}

fn validate_resolved_projection(
    projection: &RecordProjection,
    resolution: RecordId,
    expected_superseded: &[RecordId],
) -> Result<(), DynError> {
    let current = projection
        .current
        .as_ref()
        .ok_or(AcceptanceFailure("resolved Record current missing"))?;
    let superseded = projection
        .superseded
        .iter()
        .map(|item| item.id)
        .collect::<BTreeSet<_>>();
    require(
        current.id == resolution
            && current.topic == Topic::new(ALPHA_TOPIC)?
            && current.scope == Scope::new(SCOPE)?
            && current.logical_key == ALPHA_KEY
            && current.priority == Priority::Immediate
            && current.payload == RESOLVED_PAYLOAD
            && !current.tombstone
            && current.disposition == RecordVersionDisposition::Current
            && projection.concurrent.is_empty()
            && projection.conflict.is_none()
            && projection.superseded.len() == 2
            && projection
                .superseded
                .iter()
                .all(|item| item.disposition == RecordVersionDisposition::Superseded)
            && superseded == expected_superseded.iter().copied().collect(),
        "resolved Record projection",
    )
}

fn equivalent_record_projections(left: &RecordProjection, right: &RecordProjection) -> bool {
    match (&left.current, &right.current) {
        (Some(left), Some(right)) if equivalent_record_items(left, right) => {}
        (None, None) => {}
        _ => return false,
    }
    if !equivalent_record_item_sets(&left.concurrent, &right.concurrent)
        || !equivalent_record_item_sets(&left.superseded, &right.superseded)
    {
        return false;
    }
    match (&left.conflict, &right.conflict) {
        (None, None) => true,
        (Some(left), Some(right)) => {
            left.siblings == right.siblings
                && left.resolution_guard.siblings() == right.resolution_guard.siblings()
                && left.resolution_guard.topic() == right.resolution_guard.topic()
                && left.resolution_guard.scope() == right.resolution_guard.scope()
                && left.resolution_guard.logical_key() == right.resolution_guard.logical_key()
        }
        _ => false,
    }
}

fn equivalent_record_item_sets(left: &[RecordItem], right: &[RecordItem]) -> bool {
    let left = left
        .iter()
        .map(|item| (item.id, item))
        .collect::<BTreeMap<_, _>>();
    let right = right
        .iter()
        .map(|item| (item.id, item))
        .collect::<BTreeMap<_, _>>();
    left.len() == right.len()
        && left.iter().all(|(id, left)| {
            right
                .get(id)
                .is_some_and(|right| equivalent_record_items(left, right))
        })
}

fn equivalent_record_items(left: &RecordItem, right: &RecordItem) -> bool {
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

fn sorted_record_ids(left: RecordId, right: RecordId) -> Vec<RecordId> {
    [left, right]
        .into_iter()
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect()
}

fn conflict_projection_ready(projection: &RecordProjection, ids: &[RecordId]) -> bool {
    projection.current.is_some()
        && projection.concurrent.len() == 1
        && projection.superseded.is_empty()
        && projection
            .conflict
            .as_ref()
            .is_some_and(|conflict| conflict.siblings == ids)
}

async fn wait_for_pair_conflict(
    left: &SelectedRecordHandle,
    right: &SelectedRecordHandle,
    query: &RecordQuery,
    ids: &[RecordId],
    deadline_label: &'static str,
) -> Result<[RecordProjection; 2], DynError> {
    timeout(POLL_DEADLINE, async {
        loop {
            let left_projection = match left.query(query.clone()).await {
                Ok(projection) => projection,
                Err(error) if is_transient_record_query(&error) => {
                    sleep(Duration::from_millis(20)).await;
                    continue;
                }
                Err(error) => return Err(error.into()),
            };
            let right_projection = match right.query(query.clone()).await {
                Ok(projection) => projection,
                Err(error) if is_transient_record_query(&error) => {
                    sleep(Duration::from_millis(20)).await;
                    continue;
                }
                Err(error) => return Err(error.into()),
            };
            if conflict_projection_ready(&left_projection, ids)
                && conflict_projection_ready(&right_projection, ids)
            {
                break Ok::<_, DynError>([left_projection, right_projection]);
            }
            sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .map_err(|_| AcceptanceFailure(deadline_label))?
}

async fn wait_for_single_projection(
    handle: &SelectedRecordHandle,
    query: &RecordQuery,
    expected: RecordId,
    deadline_label: &'static str,
) -> Result<RecordProjection, DynError> {
    timeout(POLL_DEADLINE, async {
        loop {
            match handle.query(query.clone()).await {
                Ok(projection)
                    if projection
                        .current
                        .as_ref()
                        .is_some_and(|item| item.id == expected)
                        && projection.concurrent.is_empty()
                        && projection.conflict.is_none() =>
                {
                    break Ok::<_, DynError>(projection);
                }
                Ok(_) => sleep(Duration::from_millis(20)).await,
                Err(error) if is_transient_record_query(&error) => {
                    sleep(Duration::from_millis(20)).await;
                }
                Err(error) => break Err(error.into()),
            }
        }
    })
    .await
    .map_err(|_| AcceptanceFailure(deadline_label))?
}

fn is_transient_record_query(error: &ApplicationError) -> bool {
    matches!(
        error.kind(),
        ApplicationErrorKind::PolicyUnsettled | ApplicationErrorKind::Conflict
    ) && error.operation() == "record query"
}

async fn query_record_eventually(
    handle: &SelectedRecordHandle,
    query: RecordQuery,
    deadline_label: &'static str,
) -> Result<RecordProjection, DynError> {
    timeout(POLL_DEADLINE, async {
        loop {
            match handle.query(query.clone()).await {
                Ok(projection) => break Ok::<_, DynError>(projection),
                Err(error) if is_transient_record_query(&error) => {
                    sleep(Duration::from_millis(20)).await;
                }
                Err(error) => break Err(error.into()),
            }
        }
    })
    .await
    .map_err(|_| AcceptanceFailure(deadline_label))?
}

async fn publish_record_eventually(
    handle: &SelectedRecordHandle,
    request: RecordPublishRequest,
    deadline_label: &'static str,
) -> Result<RecordPublishResult, DynError> {
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
                "connected Record status contact errors",
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
    handle: &SelectedRecordHandle,
    query: RecordQuery,
) -> Result<(), DynError> {
    let error = handle
        .query(query)
        .await
        .expect_err("closed Record handle accepted query");
    require(
        error.kind() == ApplicationErrorKind::StateUnavailable
            && error.operation() == "record query",
        "closed Record handle",
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
        "receiver Record child was not force terminated",
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

fn validate_attempt_one_fields(
    fields: &ChildFields,
    receiver: &Participant,
    subscription: RecordSubscriptionId,
    origin_ids: &[RecordId],
    retired_singleton: RecordProjectionId,
    beta: RecordId,
) -> Result<(), DynError> {
    require(origin_ids.len() == 2, "attempt-one Record origin count")?;
    let edit = parse_record_id_value(child_field(fields, "edit_id")?)?;
    let tombstone = parse_record_id_value(child_field(fields, "tombstone_id")?)?;
    let projection = parse_record_projection_id_value(child_field(fields, "projection_id")?)?;
    let expected_key = RecordProjectionKey {
        topic: Topic::new(ALPHA_TOPIC)?,
        scope: Scope::new(SCOPE)?,
        logical_key: ALPHA_KEY.to_vec(),
    };
    require(
        fields.len() == 26
            && child_field(fields, "participant")? == "receiver"
            && child_field(fields, "identity")? == format_node_id(receiver.mission_id)
            && child_field(fields, "subscription_id")? == subscription.to_string()
            && child_field(fields, "subscription_inserted")? == "false"
            && projection != retired_singleton
            && child_field(fields, "projection_topic")? == ALPHA_TOPIC
            && child_field(fields, "projection_scope")? == SCOPE
            && child_field(fields, "projection_key_sha256")?
                == projection_key_sha256(&expected_key)
            && sorted_record_ids(edit, tombstone) == origin_ids
            && child_field(fields, "current_id")? == origin_ids[1].to_string()
            && child_field(fields, "concurrent_id")? == origin_ids[0].to_string()
            && child_field(fields, "siblings")? == ids_csv(origin_ids)
            && child_field(fields, "attempt")? == "1"
            && is_sha256(child_field(fields, "token_sha256")?)
            && child_field(fields, "delivery_limit")? == DELIVERY_LIMIT.to_string()
            && child_field(fields, "scan_limit")? == SCAN_LIMIT.to_string()
            && child_field(fields, "has_more")? == "false"
            && child_field(fields, "superseded_exposed")? == "false"
            && child_field(fields, "resolution_guard_exposed")? == "false"
            && child_field(fields, "token_persisted")? == "true"
            && child_field(fields, "singleton_projection_changed")? == "true"
            && child_field(fields, "beta_id")? == beta.to_string()
            && child_field(fields, "beta_present")? == "true"
            && child_field(fields, "gamma_empty")? == "true"
            && child_field(fields, "acknowledged")? == "false",
        "attempt-one Record child evidence",
    )
}

#[allow(clippy::too_many_arguments)]
fn validate_attempt_two_fields(
    fields: &ChildFields,
    receiver: &Participant,
    subscription: RecordSubscriptionId,
    origin_ids: &[RecordId],
    conflict_projection: RecordProjectionId,
    beta: RecordId,
    retired_singleton_token: RecordDeliveryToken,
) -> Result<(), DynError> {
    require(origin_ids.len() == 2, "attempt-two Record origin count")?;
    let edit = parse_record_id_value(child_field(fields, "edit_id")?)?;
    let tombstone = parse_record_id_value(child_field(fields, "tombstone_id")?)?;
    let resolution = parse_record_id_value(child_field(fields, "resolution_id")?)?;
    let successor_projection =
        parse_record_projection_id_value(child_field(fields, "successor_projection_id")?)?;
    let expected_key = RecordProjectionKey {
        topic: Topic::new(ALPHA_TOPIC)?,
        scope: Scope::new(SCOPE)?,
        logical_key: ALPHA_KEY.to_vec(),
    };
    require(
        child_field(fields, "participant")? == "receiver"
            && child_field(fields, "identity")? == format_node_id(receiver.mission_id)
            && child_field(fields, "subscription_id")? == subscription.to_string()
            && child_field(fields, "subscription_inserted")? == "false"
            && child_field(fields, "projection_id")? == conflict_projection.to_string()
            && child_field(fields, "projection_topic")? == ALPHA_TOPIC
            && child_field(fields, "projection_scope")? == SCOPE
            && child_field(fields, "projection_key_sha256")?
                == projection_key_sha256(&expected_key)
            && sorted_record_ids(edit, tombstone) == origin_ids
            && child_field(fields, "current_id")? == origin_ids[1].to_string()
            && child_field(fields, "concurrent_id")? == origin_ids[0].to_string()
            && child_field(fields, "siblings")? == ids_csv(origin_ids)
            && child_field(fields, "attempt")? == "2"
            && is_sha256(child_field(fields, "token_sha256")?)
            && is_sha256(child_field(fields, "previous_token_sha256")?)
            && child_field(fields, "token_sha256")?
                != child_field(fields, "previous_token_sha256")?
            && child_field(fields, "delivery_limit")? == DELIVERY_LIMIT.to_string()
            && child_field(fields, "scan_limit")? == SCAN_LIMIT.to_string()
            && child_field(fields, "has_more")? == "false"
            && child_field(fields, "superseded_exposed")? == "false"
            && child_field(fields, "resolution_guard_exposed")? == "false"
            && child_field(fields, "tokens_distinct")? == "true"
            && child_field(fields, "previous_token_restored")? == "true"
            && child_field(fields, "malformed_token_rejected")? == "true"
            && child_field(fields, "wrong_subscription_token_rejected")? == "true"
            && child_field(fields, "wrong_projection_token_rejected")? == "true"
            && child_field(fields, "retired_singleton_token_rejected")? == "true"
            && child_field(fields, "retired_singleton_token_sha256")?
                == sha256_hex(retired_singleton_token.as_bytes())
            && child_field(fields, "ack_token_attempt")? == "1"
            && child_field(fields, "reack_token_attempt")? == "2"
            && child_field(fields, "conflict_ack")? == "acknowledged"
            && child_field(fields, "conflict_reack")? == "already_acknowledged"
            && child_field(fields, "post_conflict_empty")? == "true"
            && child_field(fields, "guard_fresh_query")? == "true"
            && child_field(fields, "guard_siblings")? == ids_csv(origin_ids)
            && !origin_ids.contains(&resolution)
            && resolution != beta
            && child_field(fields, "resolution_publisher")? == format_node_id(receiver.mission_id)
            && child_field(fields, "resolution_counter")? == "2"
            && child_field(fields, "resolution_inserted")? == "true"
            && child_field(fields, "resolution_retry_inserted")? == "false"
            && child_field(fields, "resolution_retry_same")? == "true"
            && successor_projection != conflict_projection
            && child_field(fields, "successor_attempt")? == "1"
            && is_sha256(child_field(fields, "successor_token_sha256")?)
            && child_field(fields, "successor_ack")? == "acknowledged"
            && child_field(fields, "successor_reack")? == "already_acknowledged"
            && child_field(fields, "old_conflict_reack")? == "already_acknowledged"
            && child_field(fields, "post_successor_empty")? == "true"
            && child_field(fields, "superseded_ids")? == ids_csv(origin_ids)
            && child_field(fields, "beta_id")? == beta.to_string()
            && child_field(fields, "beta_present")? == "true"
            && child_field(fields, "gamma_empty")? == "true"
            && child_field(fields, "token_artifacts_removed")? == "true"
            && child_field(fields, "closed_kind")? == "state_unavailable"
            && child_field(fields, "closed_operation")? == "record_query"
            && peerless_child_receipt_fields_are_zero(fields)?,
        "attempt-two Record child evidence",
    )
}

fn peerless_child_receipt_fields_are_zero(fields: &ChildFields) -> Result<bool, DynError> {
    for key in [
        "shutdown_contacts",
        "shutdown_contact_errors",
        "shutdown_direct_contacts",
        "shutdown_relay_contacts",
        "shutdown_unknown_path_contacts",
        "shutdown_events",
        "shutdown_blobs",
        "shutdown_data_offered",
        "shutdown_data_fetched",
        "shutdown_data_inserted",
        "shutdown_data_duplicates",
        "shutdown_data_remaining",
        "shutdown_mutable_remaining",
        "shutdown_deferred_mutable_lanes",
    ] {
        if child_field(fields, key)? != "0" {
            return Ok(false);
        }
    }
    Ok(true)
}

fn is_sha256(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
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
        "excluded Record receipt classes",
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
        "peerless Record shutdown receipt",
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
        "direct Record shutdown receipt",
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
            && left.data_inserted + right.data_inserted == inserted
            && left.data_offered == right.data_fetched
            && right.data_offered == left.data_fetched,
        "Record transfer accounting",
    )
}

fn validate_inspections(
    publisher: &StoreInspection,
    receiver: &StoreInspection,
) -> Result<(), DynError> {
    require(
        publisher.record_stats.records == 4
            && publisher.record_stats.acceptance_markers == 4
            && publisher.record_stats.operations == 3
            && receiver.record_stats.records == 4
            && receiver.record_stats.acceptance_markers == 4
            && receiver.record_stats.operations == 2,
        "final Record store statistics",
    )?;
    require(
        publisher.record_subscription_stats == RecordSubscriptionStats::default()
            && receiver.record_subscription_stats
                == RecordSubscriptionStats {
                    subscriptions: 1,
                    pending_deliveries: 0,
                    acknowledged_deliveries: 1,
                    delivery_cursors: 1,
                    selector_generation: 1,
                },
        "final Record subscription statistics",
    )?;
    require(
        other_namespaces_empty(publisher) && other_namespaces_empty(receiver),
        "final excluded store statistics",
    )
}

fn other_namespaces_empty(inspection: &StoreInspection) -> bool {
    inspection.event_stats == Default::default()
        && inspection.state_stats == Default::default()
        && inspection.blob_stats == Default::default()
        && inspection.event_subscription_stats == Default::default()
        && inspection.state_subscription_stats == Default::default()
        && inspection.control_stats == Default::default()
}

fn validate_reacquired_bind(address: SocketAddr) -> Result<(), DynError> {
    let socket = UdpSocket::bind(address)?;
    require(socket.local_addr()? == address, "Record bind reacquisition")?;
    drop(socket);
    Ok(())
}

fn receipt<'a>(
    evidence: &'a AcceptanceEvidence,
    phase: &str,
    participant: &str,
) -> Result<&'a ReceiptEvidence, DynError> {
    let mut matches = evidence
        .receipts
        .iter()
        .filter(|receipt| receipt.phase == phase && receipt.participant == participant);
    let receipt = matches
        .next()
        .ok_or(AcceptanceFailure("Record receipt evidence missing"))?;
    require(
        matches.next().is_none(),
        "duplicate Record receipt evidence",
    )?;
    Ok(receipt)
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

const fn priority_name(priority: Priority) -> &'static str {
    match priority {
        Priority::Routine => "routine",
        Priority::Priority => "priority",
        Priority::Immediate => "immediate",
        Priority::Flash => "flash",
    }
}

const fn disposition_name(disposition: RecordVersionDisposition) -> &'static str {
    match disposition {
        RecordVersionDisposition::Current => "current",
        RecordVersionDisposition::Concurrent => "concurrent",
        RecordVersionDisposition::Superseded => "superseded",
    }
}

const fn acknowledgement_name(acknowledgement: RecordAcknowledgement) -> &'static str {
    match acknowledgement {
        RecordAcknowledgement::Acknowledged => "acknowledged",
        RecordAcknowledgement::AlreadyAcknowledged => "already_acknowledged",
    }
}

fn sha256_hex(bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    digest.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn projection_key_sha256(key: &RecordProjectionKey) -> String {
    let mut digest = Sha256::new();
    digest.update(key.topic.as_str().as_bytes());
    digest.update([0]);
    digest.update(key.scope.as_str().as_bytes());
    digest.update([0]);
    digest.update(&key.logical_key);
    digest
        .finalize()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

fn ids_csv(ids: &[RecordId]) -> String {
    if ids.is_empty() {
        return "none".to_owned();
    }
    let mut ids = ids.to_vec();
    ids.sort_unstable();
    ids.iter()
        .map(ToString::to_string)
        .collect::<Vec<_>>()
        .join(",")
}

fn record_items_csv(items: &[RecordItem]) -> String {
    ids_csv(&items.iter().map(|item| item.id).collect::<Vec<_>>())
}
