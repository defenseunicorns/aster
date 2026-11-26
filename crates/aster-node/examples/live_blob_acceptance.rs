//! Retained one-host acceptance producer for interrupted live selected Blob recovery.
//!
//! Application plaintext, operation keys, provisioning bytes, filesystem paths,
//! socket addresses, process identifiers, and secrets are deliberately absent
//! from the `LIVE_BLOB` transcript. Runtime `READY`/`CONTACT`/`STOP` records stay
//! in stdout so an independent verifier can bind the sanitized observations to
//! all eleven actor lifetimes.

use std::{
    collections::BTreeSet,
    env,
    error::Error,
    fmt,
    fs::{self, File, OpenOptions},
    io::Write as _,
    net::{SocketAddr, UdpSocket},
    path::{Path, PathBuf},
    time::Duration,
};

use aster_iroh::{EndpointId, ExpectedPeer};
use aster_mesh::{ProvisioningAccess, ReferenceProvisioner};
use aster_node::{
    MissionExpectedPeer, MutableSourceInterests, NodeApplication, NodeConfig, NodeIdentity,
    NodeReceipt, SourceInterestSelector,
    application::{
        ApplicationError, ApplicationErrorKind, BlobId, BlobPublishRequest, BlobPublishResult,
        BlobReadPageRequest, BlobReadRequest, MAX_SELECTED_BLOB_PAGE_BYTES, Priority, Scope,
        SelectedBlobHandle, Topic,
    },
    format_node_id,
    mission::UnprotectedReferenceMission,
    start_node,
};
use aster_redb_store::{BlobTransferId, MAX_BLOB_NETWORK_RANGE_BYTES, Store};
use sha2::{Digest as _, Sha256};
use tokio::time::{sleep, timeout};
use zeroize::{Zeroize as _, Zeroizing};

const TRANSCRIPT_SCHEMA: &str = "aster-selected-live-blob-transcript/v2";
const CLAIM: &str = "selected-live-blob-one-host-direct-iroh-peerless-publish-seed-interrupt-reopen-different-peer-resume-read-restart-acceptance";
const TOPIC: &str = "opaque";
const SCOPE: &str = "test/runtime-contact";
const MEDIA_TYPE: &str = "application/x-aster-live-blob-acceptance";
const SCHEMA_ID: &[u8] = b"acceptance/live-blob-v2";
const SCHEMA_ID_SHA256: &str = "ff1499ba5c4448784c8b5f1137ddcc0dd85dad9e51204b9236b3759e6b9d8826";
const OPERATION_KEY: &[u8] = b"acceptance/live-blob-operation-v2";
const PAYLOAD_LEN: usize = 96 * 1024;
const PAYLOAD_SHA256: &str = "8609fd29a7c72634fe10beaab26ab44441a97abf85fa428cba0898c69e1ed524";
const CHANGED_PAYLOAD_SHA256: &str =
    "db24aedc940e3af4d8b49a44db5d486c3c6773213153e6f17e8d72151c196b82";
const FIRST_PAGE_SHA256: &str = "1047ab624c89856e2a3c2dea5cea7a299c2d0ba0a9bcbf1cb951a6d54927239a";
const LAST_PAGE_SHA256: &str = "256acbd5fca30ff42275d172630103a1f6f087426ead5881fe07e2a7fef2974f";
const EXPECTED_PAGES: usize = 2;
const POLL_DEADLINE: Duration = Duration::from_secs(30);
const NORMAL_SYNC_INTERVAL: Duration = Duration::from_millis(20);
const SINGLE_CONTACT_SYNC_INTERVAL: Duration = Duration::from_secs(300);
const STORE_FILE: &str = "mesh.redb";
const TRANSCRIPT_RECORDS: usize = 81;

type DynError = Box<dyn Error + Send + Sync>;

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
    state: PathBuf,
    mission: UnprotectedReferenceMission,
    mission_id: [u8; 32],
    mission_authority: [u8; 32],
    carrier_id: EndpointId,
}

struct ParticipantTranscript {
    name: &'static str,
    carrier_id: String,
    mission_id: String,
    mission_authority: String,
}

struct PeerBindingTranscript {
    phase: &'static str,
    local: &'static str,
    remote: &'static str,
    local_carrier: String,
    local_mission: String,
    remote_carrier: String,
    remote_mission: String,
}

struct HandleEvidence {
    phase: &'static str,
    participant: &'static str,
    blob_identity: String,
    blob_authority: String,
}

struct PageEvidence {
    page_index: usize,
    offset: u64,
    max_bytes: usize,
    page_len: usize,
    next_offset: u64,
    complete: bool,
    page_sha256: String,
}

struct ReadEvidence {
    pages: Vec<PageEvidence>,
    payload_sha256: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct PendingProgressEvidence {
    source_transfer_id: String,
    blob_id: String,
    staging_sha256: String,
    public_blobs: u64,
    pending_sources: u64,
    carrier_count: usize,
    progressed_carriers: usize,
    carrier_prefixes: u64,
    prefix_bytes: u64,
    prefix_object_id: String,
    prefix_carrier_index: u64,
    prefix_len: u64,
    prefix_total_len: u64,
    total_carrier_bytes: u64,
    remaining_bytes: u64,
    remaining_ranges: u64,
    next_object_id: String,
    next_carrier_index: u64,
    next_offset: u64,
    next_end: u64,
    network_staging_bytes: u64,
    committed_chunks: u64,
    committed_file_bytes: u64,
    reserved_file_bytes: u64,
}

struct CompletedProgressEvidence {
    source_transfer_id: String,
    blob_id: String,
    public_blobs: u64,
    pending_sources: u64,
    carrier_prefixes: u64,
    network_staging_bytes: u64,
}

struct AcceptanceTranscript {
    participants: [ParticipantTranscript; 3],
    peer_bindings: [PeerBindingTranscript; 6],
    peerless_handle: HandleEvidence,
    publication: BlobPublishResult,
    retry: BlobPublishResult,
    peerless_read: ReadEvidence,
    peerless_shutdown: NodeReceipt,
    seed_handles: [HandleEvidence; 2],
    seed_read: ReadEvidence,
    seed_shutdowns: [NodeReceipt; 2],
    partial_handles: [HandleEvidence; 2],
    partial_shutdowns: [NodeReceipt; 2],
    partial_progress: PendingProgressEvidence,
    partial_reopen_handle: HandleEvidence,
    partial_reopen_shutdown: NodeReceipt,
    partial_reopen_progress: PendingProgressEvidence,
    resume_handles: [HandleEvidence; 2],
    resume_shutdowns: [NodeReceipt; 2],
    resume_progress: PendingProgressEvidence,
    finish_handles: [HandleEvidence; 2],
    finish_read: ReadEvidence,
    finish_shutdowns: [NodeReceipt; 2],
    completed_progress: CompletedProgressEvidence,
    final_handle: HandleEvidence,
    final_read: ReadEvidence,
    final_shutdown: NodeReceipt,
}

#[tokio::main]
async fn main() {
    if let Err(error) = run().await {
        let stage = if let Some(failure) = error.downcast_ref::<AcceptanceFailure>() {
            failure.0.to_owned()
        } else if let Some(failure) = error.downcast_ref::<ApplicationError>() {
            format!("application_{:?}_{}", failure.kind(), failure.operation())
        } else {
            "runtime".to_owned()
        };
        let stage = stage.replace(' ', "_").to_ascii_lowercase();
        eprintln!("LIVE_BLOB_FAILURE status=error stage={stage}");
        std::process::exit(1);
    }
}

async fn run() -> Result<(), DynError> {
    require(
        MAX_SELECTED_BLOB_PAGE_BYTES == 65_536,
        "selected Blob page limit",
    )?;
    require(
        sha256_hex(SCHEMA_ID) == SCHEMA_ID_SHA256,
        "schema identifier digest",
    )?;

    let raw_root = parse_raw_root()?;
    let topic = Topic::new(TOPIC)?;
    let scope = Scope::new(SCOPE)?;
    let participants_root = raw_root.join("participants");
    create_owner_directory(&participants_root)?;
    let [publisher, replica, receiver] =
        provision_participants(&participants_root, &topic, &scope)?;
    validate_participant_domains(&publisher, &replica, &receiver)?;

    let source_path = raw_root.join("live-blob-source.bin");
    let changed_source_path = raw_root.join("live-blob-conflict-source.bin");
    let payload = original_payload();
    require(
        payload.len() == PAYLOAD_LEN && sha256_hex(&payload) == PAYLOAD_SHA256,
        "fixed Blob payload",
    )?;
    write_source(&source_path, &payload)?;
    drop(payload);
    let changed_payload = changed_payload();
    require(
        changed_payload.len() == PAYLOAD_LEN
            && sha256_hex(&changed_payload) == CHANGED_PAYLOAD_SHA256,
        "fixed changed Blob payload",
    )?;
    write_source(&changed_source_path, &changed_payload)?;
    drop(changed_payload);

    let publish_request = BlobPublishRequest {
        operation_key: OPERATION_KEY.to_vec(),
        topic: topic.clone(),
        scope: scope.clone(),
        priority: Priority::Priority,
        media_type: Some(MEDIA_TYPE.to_owned()),
        schema_id: SCHEMA_ID.to_vec(),
    };

    let peerless = start_peerless(&publisher).await?;
    let peerless_blobs = peerless.selected_blobs();
    let peerless_handle = handle_evidence("peerless_publish", &publisher, &peerless_blobs)?;
    let publication = peerless_blobs
        .publish(publish_request.clone(), File::open(&source_path)?)
        .await?;
    validate_publication(&publication, &publisher)?;
    let retry = peerless_blobs
        .publish(publish_request.clone(), File::open(&source_path)?)
        .await?;
    validate_exact_retry(&publication, &retry)?;
    let conflict = match peerless_blobs
        .publish(publish_request.clone(), File::open(&changed_source_path)?)
        .await
    {
        Err(error) => error,
        Ok(_) => {
            return Err(Box::new(AcceptanceFailure(
                "changed Blob operation key accepted",
            )));
        }
    };
    require(
        conflict.kind() == ApplicationErrorKind::Conflict && conflict.operation() == "blob publish",
        "changed Blob operation key conflict",
    )?;
    let read_request = BlobReadRequest {
        id: publication.id,
        topic: topic.clone(),
        scope: scope.clone(),
    };
    let peerless_read = read_blob_pages(&peerless_blobs, &read_request, &publication).await?;
    let peerless_retained = peerless_blobs.clone();
    let peerless_shutdown = peerless.shutdown().await?;
    validate_peerless_publisher_receipt(&peerless_shutdown)?;
    validate_closed_blob_handle(&peerless_retained, &read_request).await?;
    drop((peerless_blobs, peerless_retained));

    let source_transfer_id = completed_source_transfer(&publisher, publication.id)?;

    fs::remove_file(&source_path)?;
    fs::remove_file(&changed_source_path)?;
    sync_directory(&raw_root)?;
    require(
        !source_path.exists() && !changed_source_path.exists(),
        "Blob plaintext sources removed",
    )?;

    let publisher_socket = UdpSocket::bind(("127.0.0.1", 0))?;
    let replica_socket = UdpSocket::bind(("127.0.0.1", 0))?;
    let receiver_socket = UdpSocket::bind(("127.0.0.1", 0))?;
    let publisher_address = publisher_socket.local_addr()?;
    let replica_address = replica_socket.local_addr()?;
    let receiver_address = receiver_socket.local_addr()?;
    require(
        [publisher_address, replica_address, receiver_address]
            .into_iter()
            .collect::<BTreeSet<_>>()
            .len()
            == 3,
        "distinct connected binds",
    )?;
    drop((publisher_socket, replica_socket, receiver_socket));

    let interests = MutableSourceInterests::default().with_blob(vec![SourceInterestSelector::new(
        topic.clone(),
        scope.clone(),
        false,
    )]);

    let (seed_publisher_running, seed_replica_running) = start_connected_pair(
        &publisher,
        publisher_address,
        &replica,
        replica_address,
        interests.clone(),
        NORMAL_SYNC_INTERVAL,
    )
    .await?;
    let seed_publisher_blobs = seed_publisher_running.selected_blobs();
    let seed_replica_blobs = seed_replica_running.selected_blobs();
    let seed_handles = [
        handle_evidence("seed_replica", &publisher, &seed_publisher_blobs)?,
        handle_evidence("seed_replica", &replica, &seed_replica_blobs)?,
    ];
    wait_for_blob_transfer(&seed_replica_blobs, &read_request, &publication).await?;
    let seed_read = read_blob_pages(&seed_replica_blobs, &read_request, &publication).await?;
    wait_for_post_read_contact_accounting(&seed_publisher_running, &seed_replica_running).await?;
    let seed_publisher_retained = seed_publisher_blobs.clone();
    let seed_replica_retained = seed_replica_blobs.clone();
    let (seed_publisher_shutdown, seed_replica_shutdown) = tokio::join!(
        seed_publisher_running.shutdown(),
        seed_replica_running.shutdown()
    );
    let seed_publisher_shutdown = seed_publisher_shutdown?;
    let seed_replica_shutdown = seed_replica_shutdown?;
    validate_seed_receipts(
        &peerless_shutdown,
        &seed_publisher_shutdown,
        &seed_replica_shutdown,
    )?;
    validate_closed_blob_handle(&seed_publisher_retained, &read_request).await?;
    validate_closed_blob_handle(&seed_replica_retained, &read_request).await?;

    let (partial_publisher_running, partial_receiver_running) = start_connected_pair(
        &publisher,
        publisher_address,
        &receiver,
        receiver_address,
        interests.clone(),
        SINGLE_CONTACT_SYNC_INTERVAL,
    )
    .await?;
    let partial_publisher_blobs = partial_publisher_running.selected_blobs();
    let partial_receiver_blobs = partial_receiver_running.selected_blobs();
    let partial_handles = [
        handle_evidence(
            "partial_from_publisher",
            &publisher,
            &partial_publisher_blobs,
        )?,
        handle_evidence("partial_from_publisher", &receiver, &partial_receiver_blobs)?,
    ];
    wait_for_exactly_one_contact(&partial_publisher_running, &partial_receiver_running).await?;
    validate_read_unavailable(&partial_receiver_blobs, &read_request).await?;
    let partial_publisher_retained = partial_publisher_blobs.clone();
    let partial_receiver_retained = partial_receiver_blobs.clone();
    let (partial_publisher_shutdown, partial_receiver_shutdown) = tokio::join!(
        partial_publisher_running.shutdown(),
        partial_receiver_running.shutdown()
    );
    let partial_publisher_shutdown = partial_publisher_shutdown?;
    let partial_receiver_shutdown = partial_receiver_shutdown?;
    validate_partial_receipts(
        &seed_publisher_shutdown,
        &partial_publisher_shutdown,
        &partial_receiver_shutdown,
    )?;
    validate_closed_blob_handle(&partial_publisher_retained, &read_request).await?;
    validate_closed_blob_handle(&partial_receiver_retained, &read_request).await?;
    let partial_progress = inspect_pending_progress(&receiver, source_transfer_id, publication.id)?;
    require(
        partial_progress.prefix_bytes == partial_receiver_shutdown.blob_bytes_fetched,
        "partial receipt matches exact durable prefix",
    )?;

    let partial_reopen = start_peerless(&receiver).await?;
    let partial_reopen_blobs = partial_reopen.selected_blobs();
    let partial_reopen_handle =
        handle_evidence("partial_receiver_reopen", &receiver, &partial_reopen_blobs)?;
    validate_read_unavailable(&partial_reopen_blobs, &read_request).await?;
    let partial_reopen_retained = partial_reopen_blobs.clone();
    let partial_reopen_shutdown = partial_reopen.shutdown().await?;
    validate_peerless_pending_receipt(&partial_receiver_shutdown, &partial_reopen_shutdown)?;
    validate_closed_blob_handle(&partial_reopen_retained, &read_request).await?;
    let partial_reopen_progress =
        inspect_pending_progress(&receiver, source_transfer_id, publication.id)?;
    require(
        partial_progress == partial_reopen_progress,
        "pending Blob staging changed across peerless reopen",
    )?;

    let (resume_replica_running, resume_receiver_running) = start_connected_pair(
        &replica,
        replica_address,
        &receiver,
        receiver_address,
        interests.clone(),
        SINGLE_CONTACT_SYNC_INTERVAL,
    )
    .await?;
    let resume_replica_blobs = resume_replica_running.selected_blobs();
    let resume_receiver_blobs = resume_receiver_running.selected_blobs();
    let resume_handles = [
        handle_evidence("resume_from_replica", &replica, &resume_replica_blobs)?,
        handle_evidence("resume_from_replica", &receiver, &resume_receiver_blobs)?,
    ];
    wait_for_exactly_one_contact(&resume_replica_running, &resume_receiver_running).await?;
    validate_read_unavailable(&resume_receiver_blobs, &read_request).await?;
    let resume_replica_retained = resume_replica_blobs.clone();
    let resume_receiver_retained = resume_receiver_blobs.clone();
    let (resume_replica_shutdown, resume_receiver_shutdown) = tokio::join!(
        resume_replica_running.shutdown(),
        resume_receiver_running.shutdown()
    );
    let resume_replica_shutdown = resume_replica_shutdown?;
    let resume_receiver_shutdown = resume_receiver_shutdown?;
    validate_resume_contact_receipts(
        &seed_replica_shutdown,
        &resume_replica_shutdown,
        &resume_receiver_shutdown,
    )?;
    validate_closed_blob_handle(&resume_replica_retained, &read_request).await?;
    validate_closed_blob_handle(&resume_receiver_retained, &read_request).await?;
    let resume_progress = inspect_pending_progress(&receiver, source_transfer_id, publication.id)?;
    validate_exact_progress_advance(
        &partial_reopen_progress,
        &resume_progress,
        &resume_receiver_shutdown,
    )?;

    let (finish_replica_running, finish_receiver_running) = start_connected_pair(
        &replica,
        replica_address,
        &receiver,
        receiver_address,
        interests,
        NORMAL_SYNC_INTERVAL,
    )
    .await?;
    let finish_replica_blobs = finish_replica_running.selected_blobs();
    let finish_receiver_blobs = finish_receiver_running.selected_blobs();
    let finish_handles = [
        handle_evidence("finish_from_replica", &replica, &finish_replica_blobs)?,
        handle_evidence("finish_from_replica", &receiver, &finish_receiver_blobs)?,
    ];
    wait_for_blob_transfer(&finish_receiver_blobs, &read_request, &publication).await?;
    let finish_read = read_blob_pages(&finish_receiver_blobs, &read_request, &publication).await?;
    wait_for_post_read_contact_accounting(&finish_replica_running, &finish_receiver_running)
        .await?;
    let finish_replica_retained = finish_replica_blobs.clone();
    let finish_receiver_retained = finish_receiver_blobs.clone();
    let (finish_replica_shutdown, finish_receiver_shutdown) = tokio::join!(
        finish_replica_running.shutdown(),
        finish_receiver_running.shutdown()
    );
    let finish_replica_shutdown = finish_replica_shutdown?;
    let finish_receiver_shutdown = finish_receiver_shutdown?;
    validate_finish_receipts(
        &seed_replica_shutdown,
        &finish_replica_shutdown,
        &finish_receiver_shutdown,
        &partial_receiver_shutdown,
        &resume_receiver_shutdown,
        &resume_progress,
    )?;
    validate_closed_blob_handle(&finish_replica_retained, &read_request).await?;
    validate_closed_blob_handle(&finish_receiver_retained, &read_request).await?;
    let completed_progress =
        inspect_completed_progress(&receiver, source_transfer_id, publication.id)?;

    let final_reopen = start_peerless(&receiver).await?;
    let final_blobs = final_reopen.selected_blobs();
    let final_handle = handle_evidence("final_receiver_reopen", &receiver, &final_blobs)?;
    let final_read = read_blob_pages(&final_blobs, &read_request, &publication).await?;
    let final_retained = final_blobs.clone();
    let final_shutdown = final_reopen.shutdown().await?;
    validate_final_receiver_receipt(&finish_receiver_shutdown, &final_shutdown)?;
    validate_closed_blob_handle(&final_retained, &read_request).await?;

    let rebound_publisher = UdpSocket::bind(publisher_address)?;
    let rebound_replica = UdpSocket::bind(replica_address)?;
    let rebound_receiver = UdpSocket::bind(receiver_address)?;
    require(
        rebound_publisher.local_addr()? == publisher_address
            && rebound_replica.local_addr()? == replica_address
            && rebound_receiver.local_addr()? == receiver_address,
        "connected binds reacquired",
    )?;
    drop((rebound_publisher, rebound_replica, rebound_receiver));

    let transcript = AcceptanceTranscript {
        participants: [
            participant_transcript(&publisher),
            participant_transcript(&replica),
            participant_transcript(&receiver),
        ],
        peer_bindings: [
            peer_binding_transcript("seed_replica", &publisher, &replica),
            peer_binding_transcript("seed_replica", &replica, &publisher),
            peer_binding_transcript("partial_from_publisher", &publisher, &receiver),
            peer_binding_transcript("partial_from_publisher", &receiver, &publisher),
            peer_binding_transcript("resume_from_replica", &replica, &receiver),
            peer_binding_transcript("resume_from_replica", &receiver, &replica),
        ],
        peerless_handle,
        publication,
        retry,
        peerless_read,
        peerless_shutdown,
        seed_handles,
        seed_read,
        seed_shutdowns: [seed_publisher_shutdown, seed_replica_shutdown],
        partial_handles,
        partial_shutdowns: [partial_publisher_shutdown, partial_receiver_shutdown],
        partial_progress,
        partial_reopen_handle,
        partial_reopen_shutdown,
        partial_reopen_progress,
        resume_handles,
        resume_shutdowns: [resume_replica_shutdown, resume_receiver_shutdown],
        resume_progress,
        finish_handles,
        finish_read,
        finish_shutdowns: [finish_replica_shutdown, finish_receiver_shutdown],
        completed_progress,
        final_handle,
        final_read,
        final_shutdown,
    };
    emit_transcript(&transcript);
    Ok(())
}

fn parse_raw_root() -> Result<PathBuf, DynError> {
    let mut arguments = env::args_os();
    let _program = arguments.next();
    let root = arguments
        .next()
        .map(PathBuf::from)
        .ok_or(AcceptanceFailure("missing raw root"))?;
    require(arguments.next().is_none(), "unexpected arguments")?;
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

#[cfg(unix)]
fn write_source(path: &Path, bytes: &[u8]) -> Result<(), DynError> {
    use std::os::unix::fs::OpenOptionsExt as _;

    let mut options = OpenOptions::new();
    options.write(true).create_new(true).mode(0o600);
    let mut output = options.open(path)?;
    output.write_all(bytes)?;
    output.sync_all()?;
    Ok(())
}

#[cfg(not(unix))]
fn write_source(path: &Path, bytes: &[u8]) -> Result<(), DynError> {
    let mut output = OpenOptions::new().write(true).create_new(true).open(path)?;
    output.write_all(bytes)?;
    output.sync_all()?;
    Ok(())
}

#[cfg(unix)]
fn sync_directory(path: &Path) -> Result<(), DynError> {
    File::open(path)?.sync_all()?;
    Ok(())
}

#[cfg(not(unix))]
fn sync_directory(_path: &Path) -> Result<(), DynError> {
    Ok(())
}

fn original_payload() -> Zeroizing<Vec<u8>> {
    Zeroizing::new(
        (0..PAYLOAD_LEN)
            .map(|index| (index.wrapping_mul(13) % 251) as u8)
            .collect(),
    )
}

fn changed_payload() -> Zeroizing<Vec<u8>> {
    Zeroizing::new(
        (0..PAYLOAD_LEN)
            .map(|index| (index.wrapping_mul(17).wrapping_add(1) % 251) as u8)
            .collect(),
    )
}

fn provision_participants(
    participants_root: &Path,
    topic: &Topic,
    scope: &Scope,
) -> Result<[Participant; 3], DynError> {
    let access = ProvisioningAccess::member(scope.clone(), vec![1], vec![topic.clone()])?;
    let mut seed = [0u8; 32];
    if let Err(error) = getrandom::fill(&mut seed) {
        seed.zeroize();
        return Err(Box::new(error));
    }
    let provisioner_result = ReferenceProvisioner::from_seed(seed);
    seed.zeroize();
    let mut provisioner = provisioner_result?;
    let publisher_bundle = provisioner.issue_node(1, std::slice::from_ref(&access))?;
    let replica_bundle = provisioner.issue_node(2, std::slice::from_ref(&access))?;
    let receiver_bundle = provisioner.issue_node(3, std::slice::from_ref(&access))?;
    let publisher =
        persist_participant(participants_root, "publisher", publisher_bundle.to_bytes()?)?;
    let replica = persist_participant(participants_root, "replica", replica_bundle.to_bytes()?)?;
    let receiver = persist_participant(participants_root, "receiver", receiver_bundle.to_bytes()?)?;
    Ok([publisher, replica, receiver])
}

fn persist_participant(
    participants_root: &Path,
    name: &'static str,
    mission_bytes: Vec<u8>,
) -> Result<Participant, DynError> {
    let root = participants_root.join(name);
    let state = root.join("state");
    create_owner_directory(&root)?;
    create_owner_directory(&state)?;
    let mission = UnprotectedReferenceMission::persist(root.join("mission.bundle"), mission_bytes)?;
    let mission_id = mission.identity();
    let mission_authority = mission.mission_authority_id();
    let identity = NodeIdentity::load_or_create(&state)?;
    let carrier_id = identity.id();
    drop(identity);
    Ok(Participant {
        name,
        state,
        mission,
        mission_id,
        mission_authority,
        carrier_id,
    })
}

fn validate_participant_domains(
    publisher: &Participant,
    replica: &Participant,
    receiver: &Participant,
) -> Result<(), DynError> {
    require(
        [
            publisher.mission_id,
            replica.mission_id,
            receiver.mission_id,
        ]
        .into_iter()
        .collect::<BTreeSet<_>>()
        .len()
            == 3,
        "distinct mission identities",
    )?;
    require(
        [
            publisher.carrier_id,
            replica.carrier_id,
            receiver.carrier_id,
        ]
        .into_iter()
        .collect::<BTreeSet<_>>()
        .len()
            == 3,
        "distinct carrier identities",
    )?;
    require(
        publisher.mission_authority == replica.mission_authority
            && replica.mission_authority == receiver.mission_authority,
        "common mission authority",
    )?;
    let domains = [
        publisher.carrier_id.to_string(),
        replica.carrier_id.to_string(),
        receiver.carrier_id.to_string(),
        format_node_id(publisher.mission_id),
        format_node_id(replica.mission_id),
        format_node_id(receiver.mission_id),
        format_node_id(publisher.mission_authority),
    ];
    require(
        domains.iter().collect::<BTreeSet<_>>().len() == domains.len(),
        "identity domains",
    )
}

async fn start_peerless(participant: &Participant) -> Result<aster_node::RunningNode, DynError> {
    Ok(start_node(NodeConfig {
        state: participant.state.clone(),
        bind: SocketAddr::from(([127, 0, 0, 1], 0)),
        mission: participant.mission.clone(),
        peers: Vec::new(),
        mutable_interests: MutableSourceInterests::default(),
        sync_interval: Duration::from_millis(10),
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
    mutable_interests: MutableSourceInterests,
    sync_interval: Duration,
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
        mutable_interests,
        sync_interval,
        run_for: None,
        application: NodeApplication::Relay,
    }
}

async fn start_connected_pair(
    local: &Participant,
    local_address: SocketAddr,
    remote: &Participant,
    remote_address: SocketAddr,
    mutable_interests: MutableSourceInterests,
    sync_interval: Duration,
) -> Result<(aster_node::RunningNode, aster_node::RunningNode), DynError> {
    let local_config = connected_config(
        local,
        local_address,
        remote,
        remote_address,
        mutable_interests.clone(),
        sync_interval,
    );
    let remote_config = connected_config(
        remote,
        remote_address,
        local,
        local_address,
        mutable_interests,
        sync_interval,
    );
    if local.carrier_id > remote.carrier_id {
        let local_running = start_node(local_config).await?;
        let remote_running = start_node(remote_config).await?;
        Ok((local_running, remote_running))
    } else {
        let remote_running = start_node(remote_config).await?;
        let local_running = start_node(local_config).await?;
        Ok((local_running, remote_running))
    }
}

fn handle_evidence(
    phase: &'static str,
    participant: &Participant,
    handle: &SelectedBlobHandle,
) -> Result<HandleEvidence, DynError> {
    require(
        handle.identity() == participant.mission_id
            && handle.mission_authority() == participant.mission_authority,
        "live Blob handle mission binding",
    )?;
    Ok(HandleEvidence {
        phase,
        participant: participant.name,
        blob_identity: format_node_id(handle.identity()),
        blob_authority: format_node_id(handle.mission_authority()),
    })
}

fn validate_publication(
    publication: &BlobPublishResult,
    publisher: &Participant,
) -> Result<(), DynError> {
    require(
        publication.inserted
            && publication.publisher == publisher.mission_id
            && publication.publisher_counter == 1
            && publication.priority == Priority::Priority
            && publication.total_len == PAYLOAD_LEN as u64
            && publication.media_type.as_deref() == Some(MEDIA_TYPE)
            && publication.schema_id == SCHEMA_ID
            && publication.acceptance_marker == 1,
        "live Blob publication metadata",
    )
}

fn validate_exact_retry(
    publication: &BlobPublishResult,
    retry: &BlobPublishResult,
) -> Result<(), DynError> {
    require(
        !retry.inserted
            && retry.id == publication.id
            && retry.publisher == publication.publisher
            && retry.publisher_counter == publication.publisher_counter
            && retry.priority == publication.priority
            && retry.total_len == publication.total_len
            && retry.media_type == publication.media_type
            && retry.schema_id == publication.schema_id
            && retry.acceptance_marker == publication.acceptance_marker,
        "live Blob exact retry",
    )
}

fn validate_page_metadata(
    page: &aster_node::application::BlobReadPage,
    request: &BlobReadRequest,
    publication: &BlobPublishResult,
) -> Result<(), DynError> {
    require(
        page.id == request.id
            && page.id == publication.id
            && page.publisher == publication.publisher
            && page.publisher_counter == publication.publisher_counter
            && page.priority == publication.priority
            && page.total_len == publication.total_len
            && page.media_type == publication.media_type
            && page.schema_id == publication.schema_id
            && page.acceptance_marker == publication.acceptance_marker,
        "live Blob page metadata",
    )
}

async fn read_blob_pages(
    handle: &SelectedBlobHandle,
    request: &BlobReadRequest,
    publication: &BlobPublishResult,
) -> Result<ReadEvidence, DynError> {
    let mut offset = 0u64;
    let mut whole = Sha256::new();
    let mut pages = Vec::with_capacity(EXPECTED_PAGES);
    loop {
        require(pages.len() < EXPECTED_PAGES, "live Blob page count")?;
        let page = handle
            .read_page(BlobReadPageRequest {
                blob: request.clone(),
                offset,
                max_bytes: MAX_SELECTED_BLOB_PAGE_BYTES,
            })
            .await?;
        validate_page_metadata(&page, request, publication)?;
        require(
            page.offset == offset && !page.is_empty() && page.len() <= MAX_SELECTED_BLOB_PAGE_BYTES,
            "bounded live Blob page",
        )?;
        let page_index = pages.len();
        let page_sha256 = sha256_hex(page.as_bytes());
        let (expected_offset, expected_len, expected_next, expected_complete, expected_sha256) =
            match page_index {
                0 => (
                    0,
                    MAX_SELECTED_BLOB_PAGE_BYTES,
                    MAX_SELECTED_BLOB_PAGE_BYTES as u64,
                    false,
                    FIRST_PAGE_SHA256,
                ),
                1 => (
                    MAX_SELECTED_BLOB_PAGE_BYTES as u64,
                    PAYLOAD_LEN - MAX_SELECTED_BLOB_PAGE_BYTES,
                    PAYLOAD_LEN as u64,
                    true,
                    LAST_PAGE_SHA256,
                ),
                _ => return Err(Box::new(AcceptanceFailure("unexpected live Blob page"))),
            };
        require(
            page.offset == expected_offset
                && page.len() == expected_len
                && page.next_offset() == expected_next
                && page.complete == expected_complete
                && page_sha256 == expected_sha256,
            "exact live Blob page",
        )?;
        whole.update(page.as_bytes());
        let next_offset = page.next_offset();
        let complete = page.complete;
        pages.push(PageEvidence {
            page_index,
            offset: page.offset,
            max_bytes: MAX_SELECTED_BLOB_PAGE_BYTES,
            page_len: page.len(),
            next_offset,
            complete,
            page_sha256,
        });
        drop(page);
        if complete {
            break;
        }
        offset = next_offset;
    }
    let payload_sha256 = hex_bytes(&whole.finalize());
    require(
        pages.len() == EXPECTED_PAGES && payload_sha256 == PAYLOAD_SHA256,
        "complete live Blob digest",
    )?;
    Ok(ReadEvidence {
        pages,
        payload_sha256,
    })
}

async fn wait_for_blob_transfer(
    handle: &SelectedBlobHandle,
    request: &BlobReadRequest,
    publication: &BlobPublishResult,
) -> Result<(), DynError> {
    timeout(POLL_DEADLINE, async {
        loop {
            match handle
                .read_page(BlobReadPageRequest {
                    blob: request.clone(),
                    offset: 0,
                    max_bytes: 1,
                })
                .await
            {
                Ok(page) => {
                    validate_page_metadata(&page, request, publication)?;
                    require(
                        page.offset == 0
                            && page.len() == 1
                            && page.next_offset() == 1
                            && !page.complete,
                        "direct Blob readiness page",
                    )?;
                    return Ok::<(), DynError>(());
                }
                Err(error)
                    if matches!(
                        error.kind(),
                        ApplicationErrorKind::RequestRejected
                            | ApplicationErrorKind::UnauthorizedOrRevoked
                            | ApplicationErrorKind::PolicyUnsettled
                    ) =>
                {
                    sleep(Duration::from_millis(20)).await;
                }
                Err(error) => return Err(Box::new(error) as DynError),
            }
        }
    })
    .await
    .map_err(|_| AcceptanceFailure("direct Blob convergence deadline"))??;
    Ok(())
}

async fn wait_for_post_read_contact_accounting(
    first: &aster_node::RunningNode,
    second: &aster_node::RunningNode,
) -> Result<(), DynError> {
    let first_status = first.selected_events();
    let second_status = second.selected_events();
    let (first_baseline, second_baseline) =
        tokio::join!(first_status.status(), second_status.status());
    let first_baseline = first_baseline?;
    let second_baseline = second_baseline?;
    require(
        first_baseline.failed_contact_attempts == 0 && second_baseline.failed_contact_attempts == 0,
        "direct Blob contact errors",
    )?;
    timeout(POLL_DEADLINE, async {
        loop {
            let (first, second) = tokio::join!(first_status.status(), second_status.status());
            let first = first?;
            let second = second?;
            require(
                first.failed_contact_attempts == 0 && second.failed_contact_attempts == 0,
                "direct Blob contact errors",
            )?;
            // Blob promotion can become visible to the application worker before the
            // completing network task returns. A strictly later contact observation
            // proves both actors folded that task into their terminal NodeReceipts.
            if first.authenticated_contacts > first_baseline.authenticated_contacts
                && second.authenticated_contacts > second_baseline.authenticated_contacts
                && first.authenticated_contacts == second.authenticated_contacts
            {
                return Ok::<(), DynError>(());
            }
            sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .map_err(|_| AcceptanceFailure("post-read Blob contact accounting deadline"))??;
    Ok(())
}

async fn wait_for_exactly_one_contact(
    first: &aster_node::RunningNode,
    second: &aster_node::RunningNode,
) -> Result<(), DynError> {
    let first_status = first.selected_events();
    let second_status = second.selected_events();
    timeout(POLL_DEADLINE, async {
        loop {
            let first = first_status.status().await?;
            let second = second_status.status().await?;
            require(
                first.failed_contact_attempts == 0 && second.failed_contact_attempts == 0,
                "single Blob contact errors",
            )?;
            require(
                first.authenticated_contacts <= 1 && second.authenticated_contacts <= 1,
                "single Blob contact exceeded",
            )?;
            if first.authenticated_contacts == 1 && second.authenticated_contacts == 1 {
                return Ok::<(), DynError>(());
            }
            sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .map_err(|_| AcceptanceFailure("single Blob contact accounting deadline"))??;
    Ok(())
}

async fn validate_read_unavailable(
    handle: &SelectedBlobHandle,
    request: &BlobReadRequest,
) -> Result<(), DynError> {
    let error = match handle
        .read_page(BlobReadPageRequest {
            blob: request.clone(),
            offset: 0,
            max_bytes: 1,
        })
        .await
    {
        Err(error) => error,
        Ok(_) => {
            return Err(Box::new(AcceptanceFailure(
                "pending Blob became application-visible",
            )));
        }
    };
    require(
        error.kind() == ApplicationErrorKind::UnauthorizedOrRevoked
            && error.operation() == "blob read page",
        "pending Blob read unavailable",
    )
}

fn completed_source_transfer(
    participant: &Participant,
    blob_id: BlobId,
) -> Result<BlobTransferId, DynError> {
    let store = Store::open_for_mission(
        participant.state.join(STORE_FILE),
        participant.mission_authority,
    )
    .map_err(|_| AcceptanceFailure("completed source Store reopen"))?;
    let inventory = store
        .blob_inventory()
        .map_err(|_| AcceptanceFailure("completed source inventory"))?;
    require(inventory.len() == 1, "single completed Blob source")?;
    let source = inventory[0];
    let projection = store
        .blob_source_projection(source)
        .map_err(|_| AcceptanceFailure("completed source projection"))?
        .ok_or(AcceptanceFailure(
            "completed Blob source projection missing",
        ))?;
    require(
        projection.source.blob_id.as_bytes() == blob_id.as_bytes(),
        "completed Blob source identity",
    )?;
    Ok(source)
}

fn inspect_pending_progress(
    participant: &Participant,
    source: BlobTransferId,
    blob_id: BlobId,
) -> Result<PendingProgressEvidence, DynError> {
    let store = Store::open_for_mission(
        participant.state.join(STORE_FILE),
        participant.mission_authority,
    )?;
    let inventory = store.blob_inventory()?;
    let stats = store.blob_stats()?;
    let pending = store
        .pending_blob_source(source)?
        .ok_or(AcceptanceFailure("pending Blob source missing"))?;
    require(
        inventory.is_empty()
            && stats.publications == 0
            && stats.acceptance_markers == 0
            && stats.pending_sources == 1
            && pending.transfer_id == source
            && pending.blob_id.as_bytes() == blob_id.as_bytes()
            && pending.carriers.len() == EXPECTED_PAGES,
        "pending Blob nonpublic shape",
    )?;

    let mut carriers = pending.carriers.clone();
    carriers.sort_by_key(|carrier| carrier.object);
    let mut fingerprint = Sha256::new();
    fingerprint.update(source.as_bytes());
    fingerprint.update(blob_id.as_bytes());
    fingerprint.update(pending.semantic_id.as_bytes());
    fingerprint.update(pending.variant_id.as_bytes());
    fingerprint.update(pending.manifest_digest);
    fingerprint.update(u64::try_from(pending.sealed.len())?.to_be_bytes());

    let mut progressed_carriers = 0usize;
    let mut progressed = None;
    let mut prefix_bytes = 0u64;
    let mut total_carrier_bytes = 0u64;
    let mut remaining_ranges = 0u64;
    let mut next = None;
    let range_bound = u64::try_from(MAX_BLOB_NETWORK_RANGE_BYTES)?;
    for carrier in carriers {
        let status = store.blob_carrier_prefix_status(source, carrier.object)?;
        let prefix_len = status.map_or(0, |status| status.prefix_len());
        if let Some(status) = status {
            require(
                status.source() == source
                    && status.object() == carrier.object
                    && status.total_len() == carrier.total_len
                    && prefix_len > 0,
                "pending Blob carrier prefix identity",
            )?;
            progressed_carriers += 1;
            progressed = Some((carrier.object, carrier.index, prefix_len, carrier.total_len));
        }
        require(prefix_len <= carrier.total_len, "pending Blob prefix bound")?;
        let remaining = carrier.total_len - prefix_len;
        prefix_bytes = prefix_bytes
            .checked_add(prefix_len)
            .ok_or(AcceptanceFailure("pending Blob prefix accounting"))?;
        total_carrier_bytes = total_carrier_bytes
            .checked_add(carrier.total_len)
            .ok_or(AcceptanceFailure("pending Blob carrier accounting"))?;
        remaining_ranges = remaining_ranges
            .checked_add(remaining.div_ceil(range_bound))
            .ok_or(AcceptanceFailure("pending Blob range accounting"))?;
        if remaining > 0 && next.is_none() {
            next = Some((
                carrier.object,
                carrier.index,
                prefix_len,
                prefix_len + remaining.min(range_bound),
            ));
        }
        fingerprint.update(carrier.object.as_bytes());
        fingerprint.update(carrier.index.to_be_bytes());
        fingerprint.update(carrier.total_len.to_be_bytes());
        fingerprint.update(prefix_len.to_be_bytes());
    }
    let remaining_bytes = total_carrier_bytes
        .checked_sub(prefix_bytes)
        .ok_or(AcceptanceFailure("pending Blob remaining accounting"))?;
    let (next_object, next_carrier_index, next_offset, next_end) =
        next.ok_or(AcceptanceFailure("pending Blob exact complement missing"))?;
    require(
        progressed_carriers == 1
            && progressed_carriers == usize::try_from(stats.carrier_prefixes)?
            && prefix_bytes > 0
            && remaining_bytes > 0
            && remaining_ranges > 0,
        "pending Blob durable progress",
    )?;
    let (prefix_object, prefix_carrier_index, prefix_len, prefix_total_len) =
        progressed.ok_or(AcceptanceFailure("pending Blob exact prefix missing"))?;

    Ok(PendingProgressEvidence {
        source_transfer_id: hex_bytes(source.as_bytes()),
        blob_id: blob_id.to_string(),
        staging_sha256: hex_bytes(&fingerprint.finalize()),
        public_blobs: stats.publications,
        pending_sources: stats.pending_sources,
        carrier_count: pending.carriers.len(),
        progressed_carriers,
        carrier_prefixes: stats.carrier_prefixes,
        prefix_bytes,
        prefix_object_id: hex_bytes(prefix_object.as_bytes()),
        prefix_carrier_index,
        prefix_len,
        prefix_total_len,
        total_carrier_bytes,
        remaining_bytes,
        remaining_ranges,
        next_object_id: hex_bytes(next_object.as_bytes()),
        next_carrier_index,
        next_offset,
        next_end,
        network_staging_bytes: stats.network_staging_bytes,
        committed_chunks: stats.committed_chunks,
        committed_file_bytes: stats.committed_file_bytes,
        reserved_file_bytes: stats.reserved_file_bytes,
    })
}

fn inspect_completed_progress(
    participant: &Participant,
    source: BlobTransferId,
    blob_id: BlobId,
) -> Result<CompletedProgressEvidence, DynError> {
    let store = Store::open_for_mission(
        participant.state.join(STORE_FILE),
        participant.mission_authority,
    )?;
    let inventory = store.blob_inventory()?;
    let stats = store.blob_stats()?;
    require(
        inventory == vec![source]
            && store.pending_blob_source(source)?.is_none()
            && stats.publications == 1
            && stats.acceptance_markers == 1
            && stats.pending_sources == 0
            && stats.carrier_prefixes == 0
            && stats.network_staging_bytes == 0,
        "completed Blob promotion shape",
    )?;
    let projection = store
        .blob_source_projection(source)?
        .ok_or(AcceptanceFailure("completed receiver Blob source missing"))?;
    require(
        projection.source.blob_id.as_bytes() == blob_id.as_bytes(),
        "completed receiver Blob identity",
    )?;
    Ok(CompletedProgressEvidence {
        source_transfer_id: hex_bytes(source.as_bytes()),
        blob_id: blob_id.to_string(),
        public_blobs: stats.publications,
        pending_sources: stats.pending_sources,
        carrier_prefixes: stats.carrier_prefixes,
        network_staging_bytes: stats.network_staging_bytes,
    })
}

async fn validate_closed_blob_handle(
    handle: &SelectedBlobHandle,
    request: &BlobReadRequest,
) -> Result<(), DynError> {
    let error = match handle
        .read_page(BlobReadPageRequest {
            blob: request.clone(),
            offset: 0,
            max_bytes: 1,
        })
        .await
    {
        Err(error) => error,
        Ok(_) => {
            return Err(Box::new(AcceptanceFailure(
                "closed Blob handle accepted read",
            )));
        }
    };
    require(
        error.kind() == ApplicationErrorKind::StateUnavailable
            && error.operation() == "blob read page",
        "closed live Blob handle",
    )
}

fn validate_non_blob_receipt(receipt: &NodeReceipt) -> Result<(), DynError> {
    require(
        receipt.events == 0
            && receipt.event_acceptance_markers == 0
            && receipt.route_cached_events == 0
            && receipt.controls == 0
            && receipt.applied_controls == 0
            && receipt.pending_controls == 0
            && receipt.control_highwater == 0
            && receipt.data_remaining == 0
            && receipt.deferred_mutable_lanes == 0,
        "excluded durable classes remain empty",
    )
}

fn validate_blob_shape(receipt: &NodeReceipt, operation_count: u64) -> Result<(), DynError> {
    require(
        receipt.blobs == 1
            && receipt.blob_acceptance_markers == 1
            && receipt.blob_last_acceptance_marker == 1
            && receipt.blob_sealed_bytes > 0
            && receipt.blob_operations == operation_count
            && ((operation_count == 0 && receipt.blob_operation_bytes == 0)
                || (operation_count == 1 && receipt.blob_operation_bytes > 0))
            && receipt.blob_variants == 1
            && receipt.blob_finalized_variants == 1
            && receipt.blob_committed_chunks == EXPECTED_PAGES as u64
            && receipt.blob_committed_file_bytes >= PAYLOAD_LEN as u64
            && receipt.blob_reserved_file_bytes == receipt.blob_committed_file_bytes
            && receipt.pending_blobs == 0
            && receipt.blob_carrier_prefixes == 0
            && receipt.blob_network_staging_bytes == 0
            && receipt.blob_deferred == 0,
        "durable live Blob shape",
    )
}

fn validate_pending_blob_shape(receipt: &NodeReceipt) -> Result<(), DynError> {
    require(
        receipt.blobs == 0
            && receipt.blob_acceptance_markers == 0
            && receipt.blob_last_acceptance_marker == 0
            && receipt.blob_sealed_bytes == 0
            && receipt.blob_operations == 0
            && receipt.blob_operation_bytes == 0
            && receipt.pending_blobs == 1
            && receipt.blob_carrier_prefixes == 1
            && receipt.blob_network_staging_bytes > 0
            && receipt.blob_deferred == 0,
        "pending live Blob shape",
    )
}

fn validate_peerless_metrics(receipt: &NodeReceipt) -> Result<(), DynError> {
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
            && receipt.data_inserted == 0
            && receipt.data_duplicates == 0
            && receipt.blob_ranges_fetched == 0
            && receipt.blob_bytes_fetched == 0
            && receipt.blob_remaining == 0
            && receipt.blob_carrier_fetch_cursors == 0,
        "peerless Blob metrics",
    )
}

fn validate_direct_receipt(
    receipt: &NodeReceipt,
    exact_contacts: Option<usize>,
) -> Result<(), DynError> {
    require(
        receipt.contacts > 0
            && exact_contacts.is_none_or(|expected| receipt.contacts == expected)
            && receipt.direct_contacts == receipt.contacts
            && receipt.relay_contacts == 0
            && receipt.unknown_path_contacts == 0
            && receipt.contact_errors == 0
            && receipt.carrier_path_transitions == 0
            && receipt.carrier_path_transition_saturations == 0
            && receipt.blob_carrier_fetch_cursors <= 1,
        "direct-only Blob receipt",
    )
}

fn validate_peerless_publisher_receipt(receipt: &NodeReceipt) -> Result<(), DynError> {
    validate_non_blob_receipt(receipt)?;
    validate_blob_shape(receipt, 1)?;
    validate_peerless_metrics(receipt)
}

fn validate_seed_receipts(
    peerless: &NodeReceipt,
    publisher: &NodeReceipt,
    replica: &NodeReceipt,
) -> Result<(), DynError> {
    validate_non_blob_receipt(publisher)?;
    validate_non_blob_receipt(replica)?;
    validate_blob_shape(publisher, 1)?;
    validate_blob_shape(replica, 0)?;
    validate_direct_receipt(publisher, None)?;
    validate_direct_receipt(replica, None)?;
    require(
        publisher.contacts == replica.contacts
            && publisher.blob_ranges_fetched == 0
            && publisher.blob_bytes_fetched == 0
            && publisher.mutable_remaining == 0
            && replica.data_fetched == 1
            && replica.data_inserted == 1
            && replica.mutable_remaining > 0
            && replica.blob_ranges_fetched > 1
            && replica.blob_bytes_fetched > 0,
        "replica seed transfer accounting",
    )?;
    require_same_durable_blob(peerless, publisher, true)?;
    require_same_physical_blob(publisher, replica)
}

fn validate_partial_receipts(
    seeded_publisher: &NodeReceipt,
    publisher: &NodeReceipt,
    receiver: &NodeReceipt,
) -> Result<(), DynError> {
    validate_non_blob_receipt(publisher)?;
    validate_non_blob_receipt(receiver)?;
    validate_blob_shape(publisher, 1)?;
    validate_pending_blob_shape(receiver)?;
    validate_direct_receipt(publisher, Some(1))?;
    validate_direct_receipt(receiver, Some(1))?;
    require(
        publisher.blob_ranges_fetched == 0
            && publisher.blob_bytes_fetched == 0
            && publisher.mutable_remaining == 0
            && receiver.data_fetched == 1
            && receiver.data_inserted == 1
            && receiver.mutable_remaining > 0
            && receiver.blob_ranges_fetched == 1
            && receiver.blob_bytes_fetched > 0
            && receiver.blob_remaining > 0,
        "interrupted Blob transfer accounting",
    )?;
    require_same_durable_blob(seeded_publisher, publisher, true)
}

fn validate_peerless_pending_receipt(
    partial: &NodeReceipt,
    reopened: &NodeReceipt,
) -> Result<(), DynError> {
    validate_non_blob_receipt(reopened)?;
    validate_pending_blob_shape(reopened)?;
    validate_peerless_metrics(reopened)?;
    require_same_durable_blob(partial, reopened, true)
}

fn validate_resume_contact_receipts(
    seeded_replica: &NodeReceipt,
    replica: &NodeReceipt,
    receiver: &NodeReceipt,
) -> Result<(), DynError> {
    validate_non_blob_receipt(replica)?;
    validate_non_blob_receipt(receiver)?;
    validate_blob_shape(replica, 0)?;
    validate_pending_blob_shape(receiver)?;
    validate_direct_receipt(replica, Some(1))?;
    validate_direct_receipt(receiver, Some(1))?;
    require(
        replica.blob_ranges_fetched == 0
            && replica.blob_bytes_fetched == 0
            && replica.mutable_remaining == 0
            && receiver.data_fetched == 0
            && receiver.data_inserted == 0
            && receiver.mutable_remaining > 0
            && receiver.blob_ranges_fetched == 1
            && receiver.blob_bytes_fetched > 0
            && receiver.blob_remaining > 0,
        "different-peer Blob resume accounting",
    )?;
    require_same_durable_blob(seeded_replica, replica, true)
}

fn validate_exact_progress_advance(
    before: &PendingProgressEvidence,
    after: &PendingProgressEvidence,
    receipt: &NodeReceipt,
) -> Result<(), DynError> {
    require(
        before.source_transfer_id == after.source_transfer_id
            && before.blob_id == after.blob_id
            && before.public_blobs == 0
            && after.public_blobs == 0
            && before.pending_sources == 1
            && after.pending_sources == 1
            && before.carrier_count == after.carrier_count
            && before.total_carrier_bytes == after.total_carrier_bytes
            && before.prefix_object_id == after.prefix_object_id
            && before.prefix_carrier_index == after.prefix_carrier_index
            && before.prefix_total_len == after.prefix_total_len
            && after.prefix_len
                == before
                    .prefix_len
                    .checked_add(receipt.blob_bytes_fetched)
                    .ok_or(AcceptanceFailure("resumed exact prefix accounting"))?
            && after.prefix_bytes
                == before
                    .prefix_bytes
                    .checked_add(receipt.blob_bytes_fetched)
                    .ok_or(AcceptanceFailure("resumed prefix accounting"))?
            && before.remaining_bytes
                == after
                    .remaining_bytes
                    .checked_add(receipt.blob_bytes_fetched)
                    .ok_or(AcceptanceFailure("resumed complement accounting"))?
            && before.remaining_ranges == after.remaining_ranges + receipt.blob_ranges_fetched
            && before.staging_sha256 != after.staging_sha256,
        "different peer resumed exact durable complement",
    )
}

fn validate_finish_receipts(
    seeded_replica: &NodeReceipt,
    replica: &NodeReceipt,
    receiver: &NodeReceipt,
    partial_receiver: &NodeReceipt,
    resume_receiver: &NodeReceipt,
    resume_progress: &PendingProgressEvidence,
) -> Result<(), DynError> {
    validate_non_blob_receipt(replica)?;
    validate_non_blob_receipt(receiver)?;
    validate_blob_shape(replica, 0)?;
    validate_blob_shape(receiver, 0)?;
    validate_direct_receipt(replica, None)?;
    validate_direct_receipt(receiver, None)?;
    let reconstructed = partial_receiver
        .blob_bytes_fetched
        .checked_add(resume_receiver.blob_bytes_fetched)
        .and_then(|bytes| bytes.checked_add(receiver.blob_bytes_fetched))
        .ok_or(AcceptanceFailure("Blob transfer reconstruction accounting"))?;
    require(
        replica.blob_ranges_fetched == 0
            && replica.blob_bytes_fetched == 0
            && replica.mutable_remaining == 0
            && receiver.data_fetched == 0
            && receiver.data_inserted == 0
            && receiver.mutable_remaining > 0
            && receiver.blob_bytes_fetched == resume_progress.remaining_bytes
            && receiver.blob_ranges_fetched == resume_progress.remaining_ranges
            && reconstructed == seeded_replica.blob_bytes_fetched,
        "finished Blob exact transfer reconstruction",
    )?;
    require_same_durable_blob(seeded_replica, replica, true)?;
    require_same_physical_blob(replica, receiver)
}

fn validate_final_receiver_receipt(
    finished: &NodeReceipt,
    reopened: &NodeReceipt,
) -> Result<(), DynError> {
    validate_non_blob_receipt(reopened)?;
    validate_blob_shape(reopened, 0)?;
    validate_peerless_metrics(reopened)?;
    require_same_durable_blob(finished, reopened, true)
}

fn require_same_durable_blob(
    before: &NodeReceipt,
    after: &NodeReceipt,
    include_operation: bool,
) -> Result<(), DynError> {
    require(
        before.blobs == after.blobs
            && before.blob_acceptance_markers == after.blob_acceptance_markers
            && before.blob_last_acceptance_marker == after.blob_last_acceptance_marker
            && before.blob_sealed_bytes == after.blob_sealed_bytes
            && (!include_operation
                || (before.blob_operations == after.blob_operations
                    && before.blob_operation_bytes == after.blob_operation_bytes))
            && before.blob_variants == after.blob_variants
            && before.blob_finalized_variants == after.blob_finalized_variants
            && before.blob_committed_chunks == after.blob_committed_chunks
            && before.blob_committed_file_bytes == after.blob_committed_file_bytes
            && before.blob_reserved_file_bytes == after.blob_reserved_file_bytes
            && before.pending_blobs == after.pending_blobs
            && before.blob_carrier_prefixes == after.blob_carrier_prefixes
            && before.blob_network_staging_bytes == after.blob_network_staging_bytes,
        "durable Blob unchanged across actor lifetime",
    )
}

fn require_same_physical_blob(
    publisher: &NodeReceipt,
    receiver: &NodeReceipt,
) -> Result<(), DynError> {
    require(
        publisher.blobs == receiver.blobs
            && publisher.blob_acceptance_markers == receiver.blob_acceptance_markers
            && publisher.blob_last_acceptance_marker == receiver.blob_last_acceptance_marker
            && publisher.blob_sealed_bytes == receiver.blob_sealed_bytes
            && publisher.blob_variants == receiver.blob_variants
            && publisher.blob_finalized_variants == receiver.blob_finalized_variants
            && publisher.blob_committed_chunks == receiver.blob_committed_chunks
            && publisher.blob_committed_file_bytes == receiver.blob_committed_file_bytes
            && publisher.blob_reserved_file_bytes == receiver.blob_reserved_file_bytes,
        "direct receiver retained exact physical Blob",
    )
}

fn participant_transcript(local: &Participant) -> ParticipantTranscript {
    ParticipantTranscript {
        name: local.name,
        carrier_id: local.carrier_id.to_string(),
        mission_id: format_node_id(local.mission_id),
        mission_authority: format_node_id(local.mission_authority),
    }
}

fn peer_binding_transcript(
    phase: &'static str,
    local: &Participant,
    remote: &Participant,
) -> PeerBindingTranscript {
    PeerBindingTranscript {
        phase,
        local: local.name,
        remote: remote.name,
        local_carrier: local.carrier_id.to_string(),
        local_mission: format_node_id(local.mission_id),
        remote_carrier: remote.carrier_id.to_string(),
        remote_mission: format_node_id(remote.mission_id),
    }
}

fn priority_label(priority: Priority) -> &'static str {
    match priority {
        Priority::Routine => "routine",
        Priority::Priority => "priority",
        Priority::Immediate => "immediate",
        Priority::Flash => "flash",
    }
}

fn sha256_hex(bytes: &[u8]) -> String {
    hex_bytes(&Sha256::digest(bytes))
}

fn hex_bytes(bytes: &[u8]) -> String {
    let mut output = String::with_capacity(bytes.len().saturating_mul(2));
    for byte in bytes {
        use fmt::Write as _;
        let _ = write!(output, "{byte:02x}");
    }
    output
}

fn emit_transcript(transcript: &AcceptanceTranscript) {
    emit(
        "RUN",
        &[
            ("schema", TRANSCRIPT_SCHEMA.to_owned()),
            ("claim", CLAIM.to_owned()),
            ("participants", "3".to_owned()),
            ("actor_lifetimes", "11".to_owned()),
            ("maximum_concurrent_actors", "2".to_owned()),
            ("topic", TOPIC.to_owned()),
            ("scope", SCOPE.to_owned()),
            ("payload_len", PAYLOAD_LEN.to_string()),
            ("payload_sha256", PAYLOAD_SHA256.to_owned()),
            ("page_limit", MAX_SELECTED_BLOB_PAGE_BYTES.to_string()),
            ("expected_pages", EXPECTED_PAGES.to_string()),
        ],
    );
    for participant in &transcript.participants {
        emit_participant(participant);
    }
    for binding in &transcript.peer_bindings {
        emit_peer_binding(binding);
    }

    emit_phase(1, "peerless_publish", "publisher", "published-and-read");
    emit_handle(&transcript.peerless_handle);
    emit_publication(&transcript.publication);
    emit_retry(&transcript.publication, &transcript.retry);
    emit(
        "BLOB_CONFLICT",
        &[
            ("phase", "peerless_publish".to_owned()),
            ("participant", "publisher".to_owned()),
            ("original_id", transcript.publication.id.to_string()),
            ("original_payload_sha256", PAYLOAD_SHA256.to_owned()),
            ("changed_payload_sha256", CHANGED_PAYLOAD_SHA256.to_owned()),
            ("error_kind", "conflict".to_owned()),
            ("operation", "blob_publish".to_owned()),
            ("publication_preserved", "true".to_owned()),
        ],
    );
    emit_read(
        "peerless_publish",
        "publisher",
        &transcript.publication,
        &transcript.peerless_read,
    );
    emit_shutdown(
        "peerless_publish",
        "publisher",
        &transcript.peerless_shutdown,
    );
    emit_closed_handle("peerless_publish", "publisher");
    emit(
        "SOURCE_REMOVED",
        &[
            ("source", "original".to_owned()),
            ("participant", "publisher".to_owned()),
            ("status", "removed-and-parent-synced".to_owned()),
            ("bytes", PAYLOAD_LEN.to_string()),
            ("sha256", PAYLOAD_SHA256.to_owned()),
        ],
    );
    emit(
        "SOURCE_REMOVED",
        &[
            ("source", "conflict-probe".to_owned()),
            ("participant", "publisher".to_owned()),
            ("status", "removed-and-parent-synced".to_owned()),
            ("bytes", PAYLOAD_LEN.to_string()),
            ("sha256", CHANGED_PAYLOAD_SHA256.to_owned()),
        ],
    );

    emit_phase(2, "seed_replica", "publisher+replica", "completed");
    for handle in &transcript.seed_handles {
        emit_handle(handle);
    }
    emit_read(
        "seed_replica",
        "replica",
        &transcript.publication,
        &transcript.seed_read,
    );
    emit_shutdown("seed_replica", "publisher", &transcript.seed_shutdowns[0]);
    emit_shutdown("seed_replica", "replica", &transcript.seed_shutdowns[1]);
    emit_closed_handle("seed_replica", "publisher");
    emit_closed_handle("seed_replica", "replica");
    emit(
        "SEED",
        &[
            ("phase", "seed_replica".to_owned()),
            ("source", "publisher".to_owned()),
            ("replica", "replica".to_owned()),
            ("status", "completed".to_owned()),
            (
                "data_fetched",
                transcript.seed_shutdowns[1].data_fetched.to_string(),
            ),
            (
                "blob_ranges_fetched",
                transcript.seed_shutdowns[1].blob_ranges_fetched.to_string(),
            ),
            (
                "blob_bytes_fetched",
                transcript.seed_shutdowns[1].blob_bytes_fetched.to_string(),
            ),
            (
                "public_blobs",
                transcript.seed_shutdowns[1].blobs.to_string(),
            ),
        ],
    );

    emit_phase(
        3,
        "partial_from_publisher",
        "publisher+receiver",
        "one-contact-interrupted",
    );
    for handle in &transcript.partial_handles {
        emit_handle(handle);
    }
    emit_read_unavailable("partial_from_publisher", "receiver");
    emit_shutdown(
        "partial_from_publisher",
        "publisher",
        &transcript.partial_shutdowns[0],
    );
    emit_shutdown(
        "partial_from_publisher",
        "receiver",
        &transcript.partial_shutdowns[1],
    );
    emit_closed_handle("partial_from_publisher", "publisher");
    emit_closed_handle("partial_from_publisher", "receiver");
    emit_progress(
        "partial_from_publisher",
        "receiver",
        &transcript.partial_progress,
    );

    emit_phase(
        4,
        "partial_receiver_reopen",
        "receiver",
        "pending-unchanged",
    );
    emit_handle(&transcript.partial_reopen_handle);
    emit_read_unavailable("partial_receiver_reopen", "receiver");
    emit_shutdown(
        "partial_receiver_reopen",
        "receiver",
        &transcript.partial_reopen_shutdown,
    );
    emit_closed_handle("partial_receiver_reopen", "receiver");
    emit_progress(
        "partial_receiver_reopen",
        "receiver",
        &transcript.partial_reopen_progress,
    );
    emit(
        "PERSISTENCE",
        &[
            ("phase", "partial_receiver_reopen".to_owned()),
            ("participant", "receiver".to_owned()),
            (
                "source_transfer_id",
                transcript.partial_progress.source_transfer_id.clone(),
            ),
            (
                "staging_before_sha256",
                transcript.partial_progress.staging_sha256.clone(),
            ),
            (
                "staging_after_sha256",
                transcript.partial_reopen_progress.staging_sha256.clone(),
            ),
            (
                "prefix_before",
                transcript.partial_progress.prefix_len.to_string(),
            ),
            (
                "prefix_after",
                transcript.partial_reopen_progress.prefix_len.to_string(),
            ),
            (
                "prefix_object_id",
                transcript.partial_progress.prefix_object_id.clone(),
            ),
            (
                "prefix_total_len",
                transcript.partial_progress.prefix_total_len.to_string(),
            ),
            ("exact_match", "true".to_owned()),
            ("public", "false".to_owned()),
        ],
    );

    emit_phase(
        5,
        "resume_from_replica",
        "replica+receiver",
        "one-contact-resumed",
    );
    for handle in &transcript.resume_handles {
        emit_handle(handle);
    }
    emit_shutdown(
        "resume_from_replica",
        "replica",
        &transcript.resume_shutdowns[0],
    );
    emit_shutdown(
        "resume_from_replica",
        "receiver",
        &transcript.resume_shutdowns[1],
    );
    emit_closed_handle("resume_from_replica", "replica");
    emit_closed_handle("resume_from_replica", "receiver");
    emit_progress(
        "resume_from_replica",
        "receiver",
        &transcript.resume_progress,
    );
    emit(
        "RESUME",
        &[
            ("phase", "resume_from_replica".to_owned()),
            ("source", "replica".to_owned()),
            ("receiver", "receiver".to_owned()),
            ("original_source", "publisher".to_owned()),
            (
                "source_transfer_id",
                transcript.resume_progress.source_transfer_id.clone(),
            ),
            ("different_peer", "true".to_owned()),
            ("source_refetched", "false".to_owned()),
            ("exact_complement", "true".to_owned()),
            (
                "contacts",
                transcript.resume_shutdowns[1].contacts.to_string(),
            ),
            (
                "data_fetched",
                transcript.resume_shutdowns[1].data_fetched.to_string(),
            ),
            (
                "blob_ranges_fetched",
                transcript.resume_shutdowns[1]
                    .blob_ranges_fetched
                    .to_string(),
            ),
            (
                "blob_bytes_fetched",
                transcript.resume_shutdowns[1]
                    .blob_bytes_fetched
                    .to_string(),
            ),
            (
                "prefix_before",
                transcript.partial_reopen_progress.prefix_len.to_string(),
            ),
            (
                "prefix_after",
                transcript.resume_progress.prefix_len.to_string(),
            ),
            (
                "prefix_object_id",
                transcript.resume_progress.prefix_object_id.clone(),
            ),
            (
                "prefix_total_len",
                transcript.resume_progress.prefix_total_len.to_string(),
            ),
            (
                "remaining_before",
                transcript
                    .partial_reopen_progress
                    .remaining_bytes
                    .to_string(),
            ),
            (
                "remaining_after",
                transcript.resume_progress.remaining_bytes.to_string(),
            ),
            ("public", "false".to_owned()),
        ],
    );

    emit_phase(6, "finish_from_replica", "replica+receiver", "completed");
    for handle in &transcript.finish_handles {
        emit_handle(handle);
    }
    emit_read(
        "finish_from_replica",
        "receiver",
        &transcript.publication,
        &transcript.finish_read,
    );
    emit_shutdown(
        "finish_from_replica",
        "replica",
        &transcript.finish_shutdowns[0],
    );
    emit_shutdown(
        "finish_from_replica",
        "receiver",
        &transcript.finish_shutdowns[1],
    );
    emit_closed_handle("finish_from_replica", "replica");
    emit_closed_handle("finish_from_replica", "receiver");
    emit(
        "FINISH",
        &[
            ("phase", "finish_from_replica".to_owned()),
            ("source", "replica".to_owned()),
            ("receiver", "receiver".to_owned()),
            ("source_refetched", "false".to_owned()),
            (
                "data_fetched",
                transcript.finish_shutdowns[1].data_fetched.to_string(),
            ),
            (
                "blob_ranges_fetched",
                transcript.finish_shutdowns[1]
                    .blob_ranges_fetched
                    .to_string(),
            ),
            (
                "blob_bytes_fetched",
                transcript.finish_shutdowns[1]
                    .blob_bytes_fetched
                    .to_string(),
            ),
            (
                "reconstructed_transfer_bytes",
                (transcript.partial_shutdowns[1].blob_bytes_fetched
                    + transcript.resume_shutdowns[1].blob_bytes_fetched
                    + transcript.finish_shutdowns[1].blob_bytes_fetched)
                    .to_string(),
            ),
            (
                "seed_transfer_bytes",
                transcript.seed_shutdowns[1].blob_bytes_fetched.to_string(),
            ),
            ("promoted", "true".to_owned()),
        ],
    );
    emit_completed_progress(&transcript.completed_progress);

    emit_phase(7, "final_receiver_reopen", "receiver", "completed-read");
    emit_handle(&transcript.final_handle);
    emit_read(
        "final_receiver_reopen",
        "receiver",
        &transcript.publication,
        &transcript.final_read,
    );
    emit_shutdown(
        "final_receiver_reopen",
        "receiver",
        &transcript.final_shutdown,
    );
    emit_closed_handle("final_receiver_reopen", "receiver");
    for participant in ["publisher", "replica", "receiver"] {
        emit(
            "BIND_REACQUIRED",
            &[
                ("participant", participant.to_owned()),
                ("status", "reacquired".to_owned()),
            ],
        );
    }
    emit(
        "RESULT",
        &[
            ("status", "pass".to_owned()),
            ("secret_values_emitted", "false".to_owned()),
            ("payload_representation", "sha256_only".to_owned()),
            ("records", TRANSCRIPT_RECORDS.to_string()),
            ("phases", "7".to_owned()),
            ("actor_lifetimes", "11".to_owned()),
            ("maximum_concurrent_actors", "2".to_owned()),
            ("graceful_shutdowns", "11".to_owned()),
            ("retained_handles", "11".to_owned()),
            ("closed_handles", "11".to_owned()),
            ("bind_reacquisitions", "3".to_owned()),
            ("source_files_removed", "2".to_owned()),
            ("source_removed", "true".to_owned()),
        ],
    );
}

fn emit_participant(participant: &ParticipantTranscript) {
    emit(
        "PARTICIPANT",
        &[
            ("participant", participant.name.to_owned()),
            ("carrier_id", participant.carrier_id.clone()),
            ("mission_id", participant.mission_id.clone()),
            ("mission_authority", participant.mission_authority.clone()),
        ],
    );
}

fn emit_peer_binding(binding: &PeerBindingTranscript) {
    emit(
        "PEER_BINDING",
        &[
            ("phase", binding.phase.to_owned()),
            ("local", binding.local.to_owned()),
            ("remote", binding.remote.to_owned()),
            ("local_carrier", binding.local_carrier.clone()),
            ("local_mission", binding.local_mission.clone()),
            ("expected_carrier_peer", binding.remote_carrier.clone()),
            ("expected_mission_peer", binding.remote_mission.clone()),
        ],
    );
}

fn emit_phase(sequence: usize, phase: &str, actors: &str, outcome: &str) {
    emit(
        "PHASE",
        &[
            ("sequence", sequence.to_string()),
            ("phase", phase.to_owned()),
            ("actors", actors.to_owned()),
            ("outcome", outcome.to_owned()),
        ],
    );
}

fn emit_read_unavailable(phase: &str, participant: &str) {
    emit(
        "READ_UNAVAILABLE",
        &[
            ("phase", phase.to_owned()),
            ("participant", participant.to_owned()),
            ("error_kind", "unauthorized_or_revoked".to_owned()),
            ("operation", "blob_read_page".to_owned()),
            ("public", "false".to_owned()),
        ],
    );
}

fn emit_progress(phase: &str, participant: &str, progress: &PendingProgressEvidence) {
    emit(
        "PROGRESS",
        &[
            ("phase", phase.to_owned()),
            ("participant", participant.to_owned()),
            ("source_transfer_id", progress.source_transfer_id.clone()),
            ("id", progress.blob_id.clone()),
            ("staging_sha256", progress.staging_sha256.clone()),
            ("public_blobs", progress.public_blobs.to_string()),
            ("pending_sources", progress.pending_sources.to_string()),
            ("carrier_count", progress.carrier_count.to_string()),
            (
                "progressed_carriers",
                progress.progressed_carriers.to_string(),
            ),
            ("carrier_prefixes", progress.carrier_prefixes.to_string()),
            ("prefix_bytes", progress.prefix_bytes.to_string()),
            ("prefix_object_id", progress.prefix_object_id.clone()),
            (
                "prefix_carrier_index",
                progress.prefix_carrier_index.to_string(),
            ),
            ("prefix_len", progress.prefix_len.to_string()),
            ("prefix_total_len", progress.prefix_total_len.to_string()),
            (
                "total_carrier_bytes",
                progress.total_carrier_bytes.to_string(),
            ),
            ("remaining_bytes", progress.remaining_bytes.to_string()),
            ("remaining_ranges", progress.remaining_ranges.to_string()),
            ("next_object_id", progress.next_object_id.clone()),
            (
                "next_carrier_index",
                progress.next_carrier_index.to_string(),
            ),
            ("next_offset", progress.next_offset.to_string()),
            ("next_end", progress.next_end.to_string()),
            (
                "network_staging_bytes",
                progress.network_staging_bytes.to_string(),
            ),
            ("committed_chunks", progress.committed_chunks.to_string()),
            (
                "committed_file_bytes",
                progress.committed_file_bytes.to_string(),
            ),
            (
                "reserved_file_bytes",
                progress.reserved_file_bytes.to_string(),
            ),
            ("public", "false".to_owned()),
        ],
    );
}

fn emit_completed_progress(progress: &CompletedProgressEvidence) {
    emit(
        "COMPLETED_PROGRESS",
        &[
            ("phase", "finish_from_replica".to_owned()),
            ("participant", "receiver".to_owned()),
            ("source_transfer_id", progress.source_transfer_id.clone()),
            ("id", progress.blob_id.clone()),
            ("public_blobs", progress.public_blobs.to_string()),
            ("pending_sources", progress.pending_sources.to_string()),
            ("carrier_prefixes", progress.carrier_prefixes.to_string()),
            (
                "network_staging_bytes",
                progress.network_staging_bytes.to_string(),
            ),
            ("public", "true".to_owned()),
        ],
    );
}

fn emit_handle(handle: &HandleEvidence) {
    emit(
        "HANDLE",
        &[
            ("phase", handle.phase.to_owned()),
            ("participant", handle.participant.to_owned()),
            ("blob_identity", handle.blob_identity.clone()),
            ("blob_authority", handle.blob_authority.clone()),
        ],
    );
}

fn publication_fields(publication: &BlobPublishResult) -> [(&'static str, String); 10] {
    [
        ("id", publication.id.to_string()),
        ("publisher", format_node_id(publication.publisher)),
        ("counter", publication.publisher_counter.to_string()),
        ("priority", priority_label(publication.priority).to_owned()),
        ("total_len", publication.total_len.to_string()),
        (
            "media_type",
            publication
                .media_type
                .as_deref()
                .unwrap_or("none")
                .to_owned(),
        ),
        ("schema_id_sha256", sha256_hex(&publication.schema_id)),
        (
            "acceptance_marker",
            publication.acceptance_marker.to_string(),
        ),
        ("inserted", publication.inserted.to_string()),
        ("payload_sha256", PAYLOAD_SHA256.to_owned()),
    ]
}

fn emit_publication(publication: &BlobPublishResult) {
    let common = publication_fields(publication);
    let mut fields = vec![
        ("phase", "peerless_publish".to_owned()),
        ("participant", "publisher".to_owned()),
    ];
    fields.extend(common);
    emit("BLOB_PUBLICATION", &fields);
}

fn emit_retry(publication: &BlobPublishResult, retry: &BlobPublishResult) {
    emit(
        "BLOB_RETRY",
        &[
            ("phase", "peerless_publish".to_owned()),
            ("participant", "publisher".to_owned()),
            ("original_id", publication.id.to_string()),
            ("retry_id", retry.id.to_string()),
            ("publisher", format_node_id(retry.publisher)),
            ("counter", retry.publisher_counter.to_string()),
            ("priority", priority_label(retry.priority).to_owned()),
            ("total_len", retry.total_len.to_string()),
            (
                "media_type",
                retry.media_type.as_deref().unwrap_or("none").to_owned(),
            ),
            ("schema_id_sha256", sha256_hex(&retry.schema_id)),
            ("acceptance_marker", retry.acceptance_marker.to_string()),
            ("inserted", retry.inserted.to_string()),
            ("exact_match", "true".to_owned()),
        ],
    );
}

fn emit_read(phase: &str, participant: &str, publication: &BlobPublishResult, read: &ReadEvidence) {
    for page in &read.pages {
        emit(
            "PAGE",
            &[
                ("phase", phase.to_owned()),
                ("participant", participant.to_owned()),
                ("page_index", page.page_index.to_string()),
                ("id", publication.id.to_string()),
                ("publisher", format_node_id(publication.publisher)),
                ("counter", publication.publisher_counter.to_string()),
                ("priority", priority_label(publication.priority).to_owned()),
                ("total_len", publication.total_len.to_string()),
                (
                    "media_type",
                    publication
                        .media_type
                        .as_deref()
                        .unwrap_or("none")
                        .to_owned(),
                ),
                ("schema_id_sha256", sha256_hex(&publication.schema_id)),
                (
                    "acceptance_marker",
                    publication.acceptance_marker.to_string(),
                ),
                ("offset", page.offset.to_string()),
                ("max_bytes", page.max_bytes.to_string()),
                ("page_len", page.page_len.to_string()),
                ("next_offset", page.next_offset.to_string()),
                ("complete", page.complete.to_string()),
                ("page_sha256", page.page_sha256.clone()),
            ],
        );
    }
    emit(
        "READ",
        &[
            ("phase", phase.to_owned()),
            ("participant", participant.to_owned()),
            ("id", publication.id.to_string()),
            ("publisher", format_node_id(publication.publisher)),
            ("counter", publication.publisher_counter.to_string()),
            ("priority", priority_label(publication.priority).to_owned()),
            ("total_len", publication.total_len.to_string()),
            (
                "media_type",
                publication
                    .media_type
                    .as_deref()
                    .unwrap_or("none")
                    .to_owned(),
            ),
            ("schema_id_sha256", sha256_hex(&publication.schema_id)),
            (
                "acceptance_marker",
                publication.acceptance_marker.to_string(),
            ),
            ("pages", read.pages.len().to_string()),
            ("max_page_bytes", MAX_SELECTED_BLOB_PAGE_BYTES.to_string()),
            ("payload_sha256", read.payload_sha256.clone()),
        ],
    );
}

fn emit_shutdown(phase: &str, participant: &str, receipt: &NodeReceipt) {
    emit(
        "SHUTDOWN",
        &[
            ("phase", phase.to_owned()),
            ("participant", participant.to_owned()),
            ("contacts", receipt.contacts.to_string()),
            ("contact_errors", receipt.contact_errors.to_string()),
            ("direct_contacts", receipt.direct_contacts.to_string()),
            ("relay_contacts", receipt.relay_contacts.to_string()),
            (
                "unknown_path_contacts",
                receipt.unknown_path_contacts.to_string(),
            ),
            (
                "carrier_path_transitions",
                receipt.carrier_path_transitions.to_string(),
            ),
            (
                "carrier_path_transition_saturations",
                receipt.carrier_path_transition_saturations.to_string(),
            ),
            ("events", receipt.events.to_string()),
            (
                "event_acceptance_markers",
                receipt.event_acceptance_markers.to_string(),
            ),
            (
                "route_cached_events",
                receipt.route_cached_events.to_string(),
            ),
            ("controls", receipt.controls.to_string()),
            ("applied_controls", receipt.applied_controls.to_string()),
            ("pending_controls", receipt.pending_controls.to_string()),
            ("control_highwater", receipt.control_highwater.to_string()),
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
            ("blob_sealed_bytes", receipt.blob_sealed_bytes.to_string()),
            ("blob_operations", receipt.blob_operations.to_string()),
            (
                "blob_operation_bytes",
                receipt.blob_operation_bytes.to_string(),
            ),
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
                "blob_carrier_fetch_cursors",
                receipt.blob_carrier_fetch_cursors.to_string(),
            ),
            (
                "blob_network_staging_bytes",
                receipt.blob_network_staging_bytes.to_string(),
            ),
        ],
    );
}

fn emit_closed_handle(phase: &str, participant: &str) {
    emit(
        "CLOSED_HANDLE",
        &[
            ("phase", phase.to_owned()),
            ("participant", participant.to_owned()),
            ("error_kind", "state_unavailable".to_owned()),
            ("operation", "blob_read_page".to_owned()),
        ],
    );
}

fn emit(record: &str, fields: &[(&str, String)]) {
    print!("LIVE_BLOB\t{record}");
    for (key, value) in fields {
        print!("\t{key}={value}");
    }
    println!();
}
