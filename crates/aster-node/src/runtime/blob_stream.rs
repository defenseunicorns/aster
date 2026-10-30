//! Profile-5 Blob network DAG composition.

use crate::{
    event_pages::TransferProfileId,
    frame::{BlobStreamSourceOfferV1, EventDirection},
    mission::MissionSession,
    stream_pipeline::{
        MappedPartition, PipelineError, PipelineLimits, PipelineReport, StreamJobId,
        StreamPartition, run_ordered_channel_pipeline_from,
    },
    stream_transfer::{
        MAX_STREAM_CHECKPOINT_BATCH_BYTES, PROFILE5_IDLE_TIMEOUT,
        PROFILE5_PACK_SEGMENT_RECORD_BYTES, PROFILE5_PACK_TRANSPORT_FRAME_BYTES, StreamAction,
        StreamClass, StreamDirection, StreamExtentAction, StreamFrame, StreamOpenV1,
        StreamReceiverState, StreamResultCode, StreamSenderState, blob_pack_wire_len,
        encode_composite_data_prefix, inspect_native_pack_record,
        profile5_attempt_bounds_for_extents, profile5_attempt_hard_timeout, profile5_receive_limit,
        split_composite_data_record,
    },
    stream_transport::{
        AttemptOpenRequest, AuthenticatedPeerSupport, AuthenticatedSupportSource,
        AuthenticatedTransportContext, IrohQuicV1Adapter, StreamAttempt, StreamReceiveAttempt,
        StreamTransportAdapter, StreamTransportRegistry, TransferRequirements,
    },
};
use aster_iroh::Connection;
use aster_mesh::{
    AuthenticatedBlobCustodyContactV2, BlobCustodyClaimV2, BlobCustodyTransferId,
    BlobStreamFinalCommitment, ReferenceEnvelopeSealer, VerifiedBlobCustodyClaimV2,
    VerifiedBlobStreamOpen, VerifiedBlobStreamPublication, VerifiedBlobStreamPublicationSource,
};
use aster_redb_store::pack::{BlobPackReader, BlobPackWriter, PinnedBlobPackRoot};
use aster_redb_store::{
    BlobOperationKey, BlobOperationOwner, BlobSourceProjection, BlobSourceRetention,
    BlobStoreError, BlobTransferId, BlobUploadCheckpoint, BlobVariantId, ControlPolicySnapshot,
    Store, StoreError, StoredBlob,
};
use sha2::{Digest, Sha256};
use std::{future::Future, sync::Arc};
use tokio::sync::mpsc;
use tokio::time::Instant;
use zeroize::Zeroize;

#[cfg(test)]
tokio::task_local! {
    static TEST_NATIVE_PROFILE5_CHECKPOINT_BATCH_BYTES: u32;
    static TEST_NATIVE_PROFILE5_PREPROMOTION_HOOK: Arc<dyn Fn() + Send + Sync>;
}

pub(super) type NativeProfile5Sink =
    Arc<std::sync::Mutex<(BlobPackWriter, BlobUploadCheckpoint, u64)>>;

pub(super) fn spawn_native_profile5_checkpoint(
    sink: NativeProfile5Sink,
    store: Arc<Store>,
    policy: ControlPolicySnapshot,
    reservation: aster_redb_store::BlobUploadReservation,
    expected: BlobUploadCheckpoint,
    durable: BlobPackCheckpoint,
) -> tokio::task::JoinHandle<Result<BlobUploadCheckpoint, StoreError>> {
    tokio::task::spawn_blocking(move || {
        // A blocking commit survives cancellation of the receive future. Keep
        // the physical writer owned until that commit has published its bytes.
        let _ownership = sink;
        store.checkpoint_blob_upload(&policy, &reservation, expected, durable)
    })
}

fn native_profile5_checkpoint_batch_bytes() -> u32 {
    #[cfg(test)]
    if let Ok(bytes) = TEST_NATIVE_PROFILE5_CHECKPOINT_BATCH_BYTES.try_with(|bytes| *bytes) {
        return bytes;
    }
    MAX_STREAM_CHECKPOINT_BATCH_BYTES
}

fn terminal_profile5_promotion_error(error: &StoreError) -> bool {
    matches!(
        error,
        StoreError::ControlPolicyUnsettled { .. }
            | StoreError::ControlPolicyChanged
            | StoreError::Blob(
                BlobStoreError::PublisherRevoked(_)
                    | BlobStoreError::KeyEpochStale { .. }
                    | BlobStoreError::KeyEpochNotActive { .. }
                    | BlobStoreError::ExpiredOrRetired
                    | BlobStoreError::ReadPlanChanged
            )
    )
}

#[cfg(test)]
fn run_native_profile5_prepromotion_hook() {
    let _ = TEST_NATIVE_PROFILE5_PREPROMOTION_HOOK.try_with(|hook| hook());
}

#[cfg(not(test))]
const fn run_native_profile5_prepromotion_hook() {}

/// Drop-safe owner for the peer-visible DATA half of a transport attempt.
/// Normal completion disarms it only after `finish_data` succeeds; every
/// error or cancellation path synchronously signals adapter cancellation.
struct SenderDataCancellation {
    attempt: Arc<dyn StreamAttempt>,
    armed: bool,
}

impl SenderDataCancellation {
    fn new(attempt: Arc<dyn StreamAttempt>) -> Self {
        Self {
            attempt,
            armed: true,
        }
    }

    fn disarm(&mut self) {
        self.armed = false;
    }
}

impl Drop for SenderDataCancellation {
    fn drop(&mut self) {
        if self.armed {
            self.attempt.cancel_data();
        }
    }
}

#[cfg(any(test, feature = "device-validation"))]
use crate::stream_transfer::{PROFILE5_ATTEMPT_TIMEOUT, profile5_attempt_bounds};
#[cfg(any(test, feature = "device-validation"))]
use aster_mesh::{BlobStreamOpen, BlobStreamSegmentOpener};
#[cfg(any(test, feature = "device-validation"))]
use aster_redb_store::BlobStreamResume;
use aster_redb_store::pack::BlobPackCheckpoint;
#[cfg(any(test, feature = "device-validation"))]
use std::path::Path;

/// Capability-bearing native Profile-5 send input. Construction requires the
/// lifecycle-visible source projection plus the Store's completion-gated pack
/// session; a raw `Store + BlobTransferId` is intentionally insufficient.
pub(crate) struct CanonicalBlobSendSource {
    stored: StoredBlob,
    projection: BlobSourceProjection,
    retention: BlobSourceRetention,
    publication: VerifiedBlobStreamPublication,
    physical_open: VerifiedBlobStreamOpen,
    commitment: BlobStreamFinalCommitment,
    authenticated_commitment: Vec<u8>,
    wire_len: u64,
}

impl CanonicalBlobSendSource {
    pub(crate) fn new_native(
        stored: StoredBlob,
        projection: BlobSourceProjection,
        retention: BlobSourceRetention,
        authority: VerifiedBlobStreamPublicationSource,
        session: &aster_redb_store::Profile5PackReadSession,
    ) -> Result<Self, BlobNetworkError> {
        let source = authority.source();
        let publication = authority.publication();
        let physical_open = authority.physical_open();
        let value = publication.publication().open();
        let physical_value = physical_open.open();
        let publication_value = publication.publication();
        let commitment = session.commitment();
        let transfer_id = BlobTransferId::new(Sha256::digest(&stored.sealed).into());
        let semantic_id = aster_redb_store::BlobSemanticId::new(
            Sha256::digest(publication.authenticated_bytes()).into(),
        );
        let manifest_digest: [u8; 32] = Sha256::digest(commitment.encode()).into();
        let sealed_len = u64::try_from(stored.sealed.len()).map_err(|_| {
            authentication_failure("bind native Profile-5 source", "length overflow")
        })?;
        if source.authenticated_publication() != publication.authenticated_bytes()
            || source.authenticated_open() != physical_open.authenticated_bytes()
            || source.authenticated_commitment() != session.authenticated_commitment()
            || session.authenticated_open() != physical_open.authenticated_bytes()
            || stored.transfer_id != projection.transfer_id
            || stored.transfer_id != transfer_id
            || stored.semantic_id != projection.semantic_id
            || stored.semantic_id != semantic_id
            || stored.blob_id != projection.blob_id
            || stored.route_lineage != Some(projection.route_lineage)
            || stored.physical_lineage != Some(projection.physical_lineage)
            || stored.variant_id
                != BlobVariantId::for_content(
                    commitment.blob_id(),
                    &physical_value.content_group(),
                    physical_value.content_epoch(),
                )
            || publication_value.blob_id() != commitment.blob_id()
            || publication_value.physical_lineage() != session.physical_lineage()
            || physical_value.content_group() != value.content_group()
            || physical_value.content_epoch() != value.content_epoch()
            || physical_value.total_len() != value.total_len()
            || physical_value.metadata() != value.metadata()
            || value.publisher() != projection.publisher
            || value.topic() != &projection.topic
            || value.scope() != &projection.scope
            || value.content_epoch() != projection.epoch
            || value.total_len() != projection.total_len
            || projection.sealed_len != sealed_len
            || commitment.blob_id() != projection.blob_id
            || commitment.segment_count() != projection.chunk_count
            || manifest_digest != projection.manifest_digest
            || session.route_lineage() != physical_value.authorization_digest()
            || session.physical_lineage() != &projection.physical_lineage
            || stored.header.stamp.dot.publisher != value.publisher()
            || stored.header.stamp.dot.counter != value.publisher_counter()
            || stored.header.topic != *value.topic()
            || stored.header.scope != *value.scope()
            || stored.header.priority != value.priority()
            || stored.header.ttl_ms != value.ttl_ms()
            || stored.header.key_epoch != value.content_epoch()
            || stored.header.logical_key.as_slice() != commitment.blob_id().as_bytes()
        {
            return Err(authentication_failure(
                "bind native Profile-5 send source",
                "authenticated open, commitment, and lifecycle projection differ",
            ));
        }
        Ok(Self {
            stored,
            projection,
            retention,
            publication: publication.clone(),
            physical_open: physical_open.clone(),
            commitment: commitment.clone(),
            authenticated_commitment: session.authenticated_commitment().to_vec(),
            wire_len: session.wire_len(),
        })
    }

    pub(crate) const fn publication(&self) -> BlobTransferId {
        self.stored.transfer_id
    }

    pub(crate) fn source_record(&self) -> &[u8] {
        &self.stored.sealed
    }

    pub(crate) const fn topic(&self) -> &aster_mesh::Topic {
        &self.stored.header.topic
    }

    pub(crate) const fn scope(&self) -> &aster_mesh::Scope {
        &self.stored.header.scope
    }

    pub(crate) const fn key_epoch(&self) -> u64 {
        self.stored.header.key_epoch
    }

    pub(crate) const fn is_finite(&self) -> bool {
        matches!(self.retention, BlobSourceRetention::Completed { .. })
            && self.publication.publication().open().ttl_ms().is_some()
    }
}

fn canonical_sender_requires_final_checkpoint(
    accepted: StreamAction,
) -> Result<bool, BlobNetworkError> {
    match accepted {
        StreamAction::SendData => Ok(true),
        StreamAction::SendFinish => Ok(false),
        _ => Err("stream acceptance produced an invalid sender action".into()),
    }
}

#[cfg(test)]
static ACTIVE_RECEIVE_PIPELINES: std::sync::Mutex<Vec<StreamJobId>> =
    std::sync::Mutex::new(Vec::new());

#[cfg(test)]
struct ReceivePipelineGuard {
    job: StreamJobId,
}

#[cfg(test)]
impl ReceivePipelineGuard {
    fn enter(job: StreamJobId) -> Self {
        ACTIVE_RECEIVE_PIPELINES.lock().unwrap().push(job);
        Self { job }
    }
}

#[cfg(test)]
impl Drop for ReceivePipelineGuard {
    fn drop(&mut self) {
        let mut active = ACTIVE_RECEIVE_PIPELINES.lock().unwrap();
        let index = active
            .iter()
            .position(|job| *job == self.job)
            .expect("receive pipeline guard was registered");
        active.swap_remove(index);
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BlobNetworkStage {
    Framing,
    Authentication,
    Transport,
    Protocol,
    Verification,
    Durability,
    Lifecycle,
    Settlement,
}

#[derive(Clone, Debug)]
pub struct BlobNetworkError {
    stage: BlobNetworkStage,
    context: String,
    detail: String,
    source: Option<Arc<dyn std::error::Error + Send + Sync>>,
}

impl BlobNetworkError {
    fn new(
        stage: BlobNetworkStage,
        context: impl Into<String>,
        detail: impl std::fmt::Display,
    ) -> Self {
        Self {
            stage,
            context: context.into(),
            detail: detail.to_string(),
            source: None,
        }
    }

    fn with_source(
        stage: BlobNetworkStage,
        context: impl Into<String>,
        source: impl std::error::Error + Send + Sync + 'static,
    ) -> Self {
        Self {
            stage,
            context: context.into(),
            detail: source.to_string(),
            source: Some(Arc::new(source)),
        }
    }

    #[cfg(test)]
    pub const fn stage(&self) -> BlobNetworkStage {
        self.stage
    }

    pub const fn public_message(&self) -> &'static str {
        match self.stage {
            BlobNetworkStage::Framing => "profile-5 Blob framing failed",
            BlobNetworkStage::Authentication => "profile-5 Blob authentication failed",
            BlobNetworkStage::Transport => "profile-5 Blob transport failed",
            BlobNetworkStage::Protocol => "profile-5 Blob protocol failed",
            BlobNetworkStage::Verification => "profile-5 Blob verification failed",
            BlobNetworkStage::Durability => "profile-5 Blob durability failed",
            BlobNetworkStage::Lifecycle => "profile-5 Blob lifecycle failed",
            BlobNetworkStage::Settlement => "profile-5 Blob settlement failed",
        }
    }
}

impl From<&'static str> for BlobNetworkError {
    fn from(detail: &'static str) -> Self {
        Self::new(
            BlobNetworkStage::Protocol,
            "profile-5 Blob protocol",
            detail,
        )
    }
}

impl From<String> for BlobNetworkError {
    fn from(detail: String) -> Self {
        Self::new(
            BlobNetworkStage::Protocol,
            "profile-5 Blob protocol",
            detail,
        )
    }
}

impl std::fmt::Display for BlobNetworkError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(formatter, "{}: {}", self.context, self.detail)
    }
}

impl PartialEq for BlobNetworkError {
    fn eq(&self, other: &Self) -> bool {
        self.stage == other.stage && self.context == other.context && self.detail == other.detail
    }
}

impl Eq for BlobNetworkError {}

impl std::error::Error for BlobNetworkError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.source
            .as_deref()
            .map(|source| source as &(dyn std::error::Error + 'static))
    }
}

async fn await_authenticated_progress<T>(
    context: &'static str,
    future: impl Future<Output = Result<T, crate::stream_transport::StreamTransportError>>,
) -> Result<T, BlobNetworkError> {
    let _contact_deadline = super::enter_authenticated_contact_idle_deadline(PROFILE5_IDLE_TIMEOUT);
    let value = tokio::time::timeout(PROFILE5_IDLE_TIMEOUT, future)
        .await
        .map_err(|_| transport_failure(context, "authenticated progress idle timeout"))?
        .map_err(|error| {
            BlobNetworkError::with_source(BlobNetworkStage::Transport, context, error)
        })?;
    super::record_authenticated_contact_progress();
    Ok(value)
}

#[derive(Debug)]
pub struct BlobNetworkReport {
    pub wire_bytes: u64,
    pub resumed_from: u64,
    pub attempt_bytes: u64,
    pub roots: ([u8; 32], [u8; 32]),
    pub checkpoints: u64,
    pub pipeline: Option<PipelineReport>,
}

fn failure(context: impl Into<String>, error: impl std::fmt::Display) -> BlobNetworkError {
    BlobNetworkError::new(BlobNetworkStage::Protocol, context, error)
}

fn authentication_failure(
    context: impl Into<String>,
    error: impl std::fmt::Display,
) -> BlobNetworkError {
    BlobNetworkError::new(BlobNetworkStage::Authentication, context, error)
}

fn transport_failure(
    context: impl Into<String>,
    error: impl std::fmt::Display,
) -> BlobNetworkError {
    BlobNetworkError::new(BlobNetworkStage::Transport, context, error)
}

fn verification_failure(
    context: impl Into<String>,
    error: impl std::fmt::Display,
) -> BlobNetworkError {
    BlobNetworkError::new(BlobNetworkStage::Verification, context, error)
}

fn durability_failure(
    context: impl Into<String>,
    error: impl std::fmt::Display,
) -> BlobNetworkError {
    BlobNetworkError::new(BlobNetworkStage::Durability, context, error)
}

fn lifecycle_failure(
    context: impl Into<String>,
    error: impl std::fmt::Display,
) -> BlobNetworkError {
    BlobNetworkError::new(BlobNetworkStage::Lifecycle, context, error)
}

fn settlement_failure(
    context: impl Into<String>,
    error: impl std::fmt::Display,
) -> BlobNetworkError {
    BlobNetworkError::new(BlobNetworkStage::Settlement, context, error)
}

pub(crate) fn production_stream_transport_registry(
    connection: Connection,
) -> Result<StreamTransportRegistry, BlobNetworkError> {
    let adapter: Arc<dyn StreamTransportAdapter> = Arc::new(IrohQuicV1Adapter::new(connection));
    let mut registry = StreamTransportRegistry::new();
    registry
        .register(
            adapter,
            AuthenticatedTransportContext {
                locally_enabled: true,
                policy_allowed: true,
                peer_support: Some(AuthenticatedPeerSupport::new(
                    AuthenticatedSupportSource::MissionSessionNegotiation,
                    true,
                )),
                configured_priority: 0,
            },
        )
        .map_err(|error| {
            transport_failure("register production stream transport", format!("{error:?}"))
        })?;
    Ok(registry)
}

pub(crate) fn select_stream_transport(
    registry: &StreamTransportRegistry,
) -> Result<Arc<dyn StreamTransportAdapter>, BlobNetworkError> {
    registry
        .select(TransferRequirements::default())
        .ok_or_else(|| {
            transport_failure(
                "select stream transport",
                "no eligible transport is available",
            )
        })
}

pub(crate) fn select_production_stream_transport(
    connection: Connection,
) -> Result<Arc<dyn StreamTransportAdapter>, BlobNetworkError> {
    let registry = production_stream_transport_registry(connection)?;
    select_stream_transport(&registry)
}

#[cfg(any(test, feature = "device-validation"))]
fn encoded(frame: StreamFrame) -> Result<Vec<u8>, BlobNetworkError> {
    frame.encode_for_context(9, 5).map_err(|error| {
        BlobNetworkError::new(BlobNetworkStage::Framing, "encode stream frame", error)
    })
}

#[cfg(any(test, feature = "device-validation"))]
fn decoded(bytes: &[u8]) -> Result<StreamFrame, BlobNetworkError> {
    StreamFrame::decode_for_context(9, 5, bytes).map_err(|error| {
        BlobNetworkError::new(BlobNetworkStage::Framing, "decode stream frame", error)
    })
}

trait BlobRecordCodec: Send {
    fn encode(&mut self, frame: StreamFrame) -> Result<Vec<u8>, BlobNetworkError>;
    fn encode_data_parts(
        &mut self,
        data: crate::stream_transfer::StreamDataV1,
    ) -> Result<(Vec<u8>, Vec<u8>), BlobNetworkError>;
    fn decode(&mut self, bytes: &[u8]) -> Result<StreamFrame, BlobNetworkError>;
}

#[cfg(any(test, feature = "device-validation"))]
struct PlainBlobRecordCodec;

#[cfg(any(test, feature = "device-validation"))]
impl BlobRecordCodec for PlainBlobRecordCodec {
    fn encode(&mut self, frame: StreamFrame) -> Result<Vec<u8>, BlobNetworkError> {
        if let StreamFrame::Data(data) = frame {
            let (mut header, body) = self.encode_data_parts(data)?;
            header.extend_from_slice(&body);
            return Ok(header);
        }
        encoded(frame)
    }

    fn encode_data_parts(
        &mut self,
        data: crate::stream_transfer::StreamDataV1,
    ) -> Result<(Vec<u8>, Vec<u8>), BlobNetworkError> {
        inspect_native_pack_record(&data.bytes).map_err(|error| {
            BlobNetworkError::new(
                BlobNetworkStage::Framing,
                "validate native Profile-5 DATA body",
                error,
            )
        })?;
        let (header, mut body) = data.into_header_and_body().map_err(|error| {
            BlobNetworkError::new(BlobNetworkStage::Framing, "split data frame", error)
        })?;
        let encoded_header = match header.encode_for_context(9, 5) {
            Ok(header) => header,
            Err(error) => {
                body.zeroize();
                return Err(BlobNetworkError::new(
                    BlobNetworkStage::Framing,
                    "encode data header",
                    error,
                ));
            }
        };
        Ok((encoded_header, body))
    }

    fn decode(&mut self, bytes: &[u8]) -> Result<StreamFrame, BlobNetworkError> {
        decoded(bytes)
    }
}

struct MissionBlobRecordCodec<'a> {
    mission: &'a mut MissionSession,
    profile_digest: [u8; 32],
    direction: EventDirection,
    attempt_nonce: [u8; 32],
}

fn stream_frame_name(frame: &StreamFrame) -> &'static str {
    match frame {
        StreamFrame::Open(_) => "open",
        StreamFrame::Source(_) => "source",
        StreamFrame::Accept(_) => "accept",
        StreamFrame::Data(_) => "data",
        StreamFrame::Checkpoint(_) => "checkpoint",
        StreamFrame::Finish(_) => "finish",
        StreamFrame::Result(_) => "result",
        StreamFrame::ResultAck(_) => "result acknowledgement",
    }
}

impl BlobRecordCodec for MissionBlobRecordCodec<'_> {
    fn encode(&mut self, frame: StreamFrame) -> Result<Vec<u8>, BlobNetworkError> {
        if let StreamFrame::Data(data) = frame {
            let (mut prefix, body) = self.encode_data_parts(data)?;
            prefix.extend_from_slice(&body);
            return Ok(prefix);
        }
        let frame_name = stream_frame_name(&frame);
        let plaintext = frame
            .encode_for_context(9, TransferProfileId::BlobStreamV1 as u16)
            .map_err(|error| {
                BlobNetworkError::new(BlobNetworkStage::Framing, "encode control frame", error)
            })?;
        self.mission
            .seal_v9_blob_application_frame(
                self.profile_digest,
                self.direction,
                self.attempt_nonce,
                &plaintext,
            )
            .map_err(|error| {
                authentication_failure(format!("seal {frame_name} mission record"), error)
            })
    }

    fn encode_data_parts(
        &mut self,
        data: crate::stream_transfer::StreamDataV1,
    ) -> Result<(Vec<u8>, Vec<u8>), BlobNetworkError> {
        let (header, mut body) = data.into_header_and_body().map_err(|error| {
            BlobNetworkError::new(BlobNetworkStage::Framing, "split data frame", error)
        })?;
        let encoded_header =
            match header.encode_for_context(9, TransferProfileId::BlobStreamV1 as u16) {
                Ok(header) => header,
                Err(error) => {
                    body.zeroize();
                    return Err(BlobNetworkError::new(
                        BlobNetworkStage::Framing,
                        "encode data header",
                        error,
                    ));
                }
            };
        let protected_header = match self.mission.seal_v9_blob_data_header(
            self.profile_digest,
            self.direction,
            self.attempt_nonce,
            &encoded_header,
        ) {
            Ok(header) => header,
            Err(error) => {
                body.zeroize();
                return Err(authentication_failure(
                    "seal data-header mission record",
                    error,
                ));
            }
        };
        let prefix = match encode_composite_data_prefix(&protected_header) {
            Ok(prefix) => prefix,
            Err(error) => {
                body.zeroize();
                return Err(BlobNetworkError::new(
                    BlobNetworkStage::Framing,
                    "encode composite data prefix",
                    error,
                ));
            }
        };
        Ok((prefix, body))
    }

    fn decode(&mut self, bytes: &[u8]) -> Result<StreamFrame, BlobNetworkError> {
        if bytes.starts_with(b"ASD1") {
            let (protected_header, body) = split_composite_data_record(bytes).map_err(|error| {
                BlobNetworkError::new(
                    BlobNetworkStage::Framing,
                    "split composite data record",
                    error,
                )
            })?;
            let header = self
                .mission
                .open_v9_blob_data_header(
                    self.profile_digest,
                    self.direction,
                    self.attempt_nonce,
                    protected_header,
                )
                .map_err(|error| {
                    authentication_failure("open data-header mission record", error)
                })?;
            inspect_native_pack_record(body).map_err(|error| {
                BlobNetworkError::new(
                    BlobNetworkStage::Framing,
                    "validate native Profile-5 DATA body",
                    error,
                )
            })?;
            return header
                .decode_body(body)
                .map(StreamFrame::Data)
                .map_err(|error| {
                    BlobNetworkError::new(
                        BlobNetworkStage::Framing,
                        "decode composite data body",
                        error,
                    )
                });
        }
        let plaintext = self
            .mission
            .open_v9_blob_application_frame(
                self.profile_digest,
                self.direction,
                self.attempt_nonce,
                bytes,
            )
            .map_err(|error| authentication_failure("open mission record", error))?;
        let frame =
            StreamFrame::decode_for_context(9, TransferProfileId::BlobStreamV1 as u16, &plaintext)
                .map_err(|error| {
                    BlobNetworkError::new(BlobNetworkStage::Framing, "decode control frame", error)
                })?;
        if matches!(frame, StreamFrame::Data(_)) {
            return Err("StreamData requires the profile-5 composite record".into());
        }
        Ok(frame)
    }
}

#[cfg(all(feature = "fuzzing", test))]
pub(crate) fn fuzz_protect_profile5_data_extent(
    extent: Vec<u8>,
) -> Result<Vec<u8>, BlobNetworkError> {
    let (mut sender, _receiver, profile_digest) = crate::mission::fuzz_mission_pair();
    MissionBlobRecordCodec {
        mission: &mut sender,
        profile_digest,
        direction: EventDirection::ToSessionResponder,
        attempt_nonce: [0x22; 32],
    }
    .encode(StreamFrame::Data(crate::stream_transfer::StreamDataV1 {
        transfer_id: [0x11; 32],
        attempt_nonce: [0x22; 32],
        sequence: 0,
        offset: 0,
        bytes: extent,
    }))
}

#[cfg(feature = "fuzzing")]
pub(crate) fn fuzz_open_profile5_data_extent(
    bytes: &[u8],
) -> Result<crate::stream_transfer::StreamDataV1, BlobNetworkError> {
    let (_sender, mut receiver, profile_digest) = crate::mission::fuzz_mission_pair();
    let frame = MissionBlobRecordCodec {
        mission: &mut receiver,
        profile_digest,
        direction: EventDirection::ToSessionResponder,
        attempt_nonce: [0x22; 32],
    }
    .decode(bytes)?;
    let StreamFrame::Data(data) = frame else {
        return Err("fuzz fixture did not open as profile-5 DATA".into());
    };
    Ok(data)
}

async fn send_authenticated_source(
    attempt: &dyn StreamAttempt,
    codec: &mut dyn BlobRecordCodec,
    open: &StreamOpenV1,
    source: &[u8],
) -> Result<(), BlobNetworkError> {
    if u32::try_from(source.len()).ok() != Some(open.source_len)
        || <[u8; 32]>::from(Sha256::digest(source)) != open.source_digest
    {
        return Err(authentication_failure(
            "bind authenticated source phase",
            "source length or digest differs from open",
        ));
    }
    for (sequence, chunk) in source
        .chunks(crate::stream_transfer::PROFILE5_SOURCE_CHUNK_BYTES)
        .enumerate()
    {
        let offset = sequence
            .checked_mul(crate::stream_transfer::PROFILE5_SOURCE_CHUNK_BYTES)
            .and_then(|value| u32::try_from(value).ok())
            .ok_or("authenticated source offset overflows")?;
        let frame = StreamFrame::Source(crate::stream_transfer::StreamSourceV1 {
            transfer_id: open.transfer_id,
            attempt_nonce: open.attempt_nonce,
            sequence: u64::try_from(sequence)
                .map_err(|_| "authenticated source sequence overflows")?,
            offset,
            total_len: open.source_len,
            bytes: chunk.to_vec(),
        });
        await_authenticated_progress(
            "send authenticated source chunk",
            attempt.send_data(&codec.encode(frame)?),
        )
        .await?;
    }
    Ok(())
}

async fn receive_authenticated_source(
    attempt: &dyn StreamReceiveAttempt,
    codec: &mut dyn BlobRecordCodec,
    open: &StreamOpenV1,
) -> Result<Vec<u8>, BlobNetworkError> {
    let capacity =
        usize::try_from(open.source_len).map_err(|_| "authenticated source length overflows")?;
    if capacity == 0 || capacity > crate::stream_transfer::MAX_STREAM_AUTHENTICATED_OPEN_BYTES {
        return Err("authenticated source length is out of bounds".into());
    }
    let mut source = Vec::with_capacity(capacity);
    let mut sequence = 0_u64;
    while source.len() < capacity {
        let encoded = await_authenticated_progress(
            "receive authenticated source chunk",
            attempt.receive_data(),
        )
        .await?
        .ok_or("data stream closed during authenticated source")?;
        let StreamFrame::Source(chunk) = codec.decode(&encoded)? else {
            return Err("authenticated source phase received another frame kind".into());
        };
        if chunk.transfer_id != open.transfer_id
            || chunk.attempt_nonce != open.attempt_nonce
            || chunk.sequence != sequence
            || usize::try_from(chunk.offset).ok() != Some(source.len())
            || chunk.total_len != open.source_len
        {
            return Err(authentication_failure(
                "validate authenticated source chunk",
                "source order or attempt binding differs",
            ));
        }
        source.extend_from_slice(&chunk.bytes);
        sequence = sequence
            .checked_add(1)
            .ok_or("authenticated source sequence overflows")?;
    }
    if source.len() != capacity || <[u8; 32]>::from(Sha256::digest(&source)) != open.source_digest {
        return Err(authentication_failure(
            "validate authenticated source",
            "source length or digest differs from open",
        ));
    }
    Ok(source)
}

#[cfg(any(test, feature = "device-validation"))]
fn result_digest(open: &BlobStreamOpen, roots: ([u8; 32], [u8; 32])) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(b"aster/blob-network-result/v1");
    hasher.update(open.digest());
    hasher.update(roots.0);
    hasher.update(roots.1);
    hasher.finalize().into()
}

#[cfg(any(test, feature = "device-validation"))]
async fn finish_receiver_attempt(
    attempt: Arc<dyn crate::stream_transport::StreamReceiveAttempt>,
) -> Result<(), BlobNetworkError> {
    if attempt
        .receive_data()
        .await
        .map_err(|error| transport_failure("receive data EOF", format!("{error:?}")))?
        .is_some()
    {
        return Err("data stream contained a frame after result acknowledgement".into());
    }
    attempt
        .finish_control()
        .await
        .map_err(|error| transport_failure("finish control stream", format!("{error:?}")))
}

#[cfg(test)]
pub(crate) fn completed_pack_wire_len(
    root: &Path,
    open: &BlobStreamOpen,
) -> Result<u64, BlobNetworkError> {
    let reader =
        BlobPackReader::open(root, open).map_err(|error| durability_failure("open pack", error))?;
    Ok(reader.checkpoint().payload_len())
}

#[cfg(any(test, feature = "device-validation"))]
enum PackAccess<'a> {
    Path(&'a Path),
}

#[cfg(any(test, feature = "device-validation"))]
impl PackAccess<'_> {
    fn reader(&self, open: &BlobStreamOpen) -> Result<BlobPackReader, BlobNetworkError> {
        match self {
            Self::Path(root) => BlobPackReader::open(root, open),
        }
        .map_err(|error| durability_failure("open pack", error))
    }

    fn reader_at(
        &self,
        open: &BlobStreamOpen,
        next_index: u64,
        wire_offset: u64,
    ) -> Result<BlobPackReader, BlobNetworkError> {
        match self {
            Self::Path(root) => {
                BlobPackReader::open_at_payload_offset(root, open, next_index, wire_offset)
            }
        }
        .map_err(|error| durability_failure("open resumed source pack", error))
    }

    fn projected_writer(
        &self,
        open: &BlobStreamOpen,
        resume: BlobStreamResume,
    ) -> Result<BlobPackWriter, BlobNetworkError> {
        match self {
            Self::Path(root) => BlobPackWriter::open_projected(
                root,
                open,
                resume.generation(),
                resume.next_segment_index(),
                resume.durable_plaintext_offset(),
                resume.durable_pack_len(),
                resume.durable_wire_offset(),
            ),
        }
        .map_err(|error| durability_failure("open receiver pack", error))
    }
}

#[cfg(any(test, feature = "device-validation"))]
pub(crate) fn expected_pack_wire_len(plaintext_len: u64) -> Result<u64, BlobNetworkError> {
    blob_pack_wire_len(plaintext_len).map_err(|error| {
        BlobNetworkError::new(
            BlobNetworkStage::Framing,
            "calculate Blob pack wire length",
            error,
        )
    })
}

#[cfg(any(test, feature = "device-validation"))]
struct PackExtentSource {
    reader: BlobPackReader,
}

#[cfg(any(test, feature = "device-validation"))]
impl PackExtentSource {
    fn new(root: &PackAccess<'_>, open: &BlobStreamOpen) -> Result<Self, BlobNetworkError> {
        Ok(Self {
            reader: root.reader(open)?,
        })
    }

    fn new_at(
        root: &PackAccess<'_>,
        open: &BlobStreamOpen,
        wire_offset: u64,
    ) -> Result<Self, BlobNetworkError> {
        if wire_offset == 0 {
            return Self::new(root, open);
        }
        let full_record = 4_u64
            .checked_add(aster_mesh::BLOB_STREAM_SEGMENT_BYTES as u64)
            .and_then(|value| {
                value.checked_add(aster_mesh::BLOB_STREAM_SEGMENT_ENCODED_OVERHEAD_BYTES as u64)
            })
            .ok_or("Blob record length overflow")?;
        let full_segments = open.total_len() / aster_mesh::BLOB_STREAM_SEGMENT_BYTES as u64;
        let full_prefix = full_segments
            .checked_mul(full_record)
            .ok_or("Blob resume prefix overflow")?;
        let next_index = if wire_offset <= full_prefix && wire_offset.is_multiple_of(full_record) {
            wire_offset / full_record
        } else if wire_offset == expected_pack_wire_len(open.total_len())? {
            open.total_len()
                .div_ceil(aster_mesh::BLOB_STREAM_SEGMENT_BYTES as u64)
        } else {
            return Err(BlobNetworkError::new(
                BlobNetworkStage::Framing,
                "resume source pack",
                "offset is not a canonical Blob record boundary",
            ));
        };
        Ok(Self {
            reader: root.reader_at(open, next_index, wire_offset)?,
        })
    }

    fn next_extent(&mut self) -> Result<Option<Vec<u8>>, BlobNetworkError> {
        self.reader
            .next_record()
            .map(|record| record.map(|record| record.into_bytes()))
            .map_err(|error| durability_failure("read source record", error))
    }
}

#[cfg(any(test, feature = "device-validation"))]
fn protocol_open(
    open: &BlobStreamOpen,
    authenticated_open: &[u8],
    wire_len: u64,
    attempt_nonce: [u8; 32],
    direction: StreamDirection,
) -> StreamOpenV1 {
    let source_len = u32::try_from(authenticated_open.len()).unwrap_or(u32::MAX);
    let source_digest = Sha256::digest(authenticated_open).into();
    StreamOpenV1 {
        class: StreamClass::Blob,
        direction,
        session_transcript: open.digest(),
        exchange_id: 1,
        transfer_id: open.digest(),
        source_transfer_id: *open.stream_id().as_bytes(),
        publication_id: *open.stream_id().as_bytes(),
        variant_id: open.digest(),
        total_len: wire_len,
        attempt_nonce,
        checkpoint_generation: 0,
        custody_digest: None,
        source_len,
        source_digest,
    }
}

#[cfg(any(test, feature = "device-validation"))]
pub(crate) async fn send_completed_pack(
    connection: Connection,
    open: &BlobStreamOpen,
    authenticated_open: Vec<u8>,
    root: &Path,
    roots: ([u8; 32], [u8; 32]),
    semantic_commitment: Vec<u8>,
) -> Result<BlobNetworkReport, BlobNetworkError> {
    let mut codec = PlainBlobRecordCodec;
    let transport = select_production_stream_transport(connection)?;
    send_completed_pack_inner(
        transport.as_ref(),
        open,
        authenticated_open,
        PackAccess::Path(root),
        roots,
        semantic_commitment,
        None,
        StreamDirection::ToSessionResponder,
        &mut codec,
    )
    .await
}

fn canonical_result_digest(open: &StreamOpenV1, roots: ([u8; 32], [u8; 32])) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(b"aster/canonical-blob-network-result/v1");
    hasher.update(open.source_transfer_id);
    hasher.update(open.publication_id);
    hasher.update(open.variant_id);
    hasher.update(open.total_len.to_be_bytes());
    hasher.update(roots.0);
    hasher.update(roots.1);
    hasher.finalize().into()
}

fn require_canonical_send_source(
    store: &Store,
    policy: &ControlPolicySnapshot,
    source: &CanonicalBlobSendSource,
) -> Result<(), BlobNetworkError> {
    let exact = store
        .get_blob(source.stored.transfer_id)
        .map_err(|error| lifecycle_failure("load native Profile-5 source", error))?
        .ok_or_else(|| {
            lifecycle_failure("load native Profile-5 source", "publication is absent")
        })?;
    if exact != source.stored {
        return Err(authentication_failure(
            "recheck native Profile-5 source",
            "source bytes or metadata changed",
        ));
    }
    let mut authorized = false;
    store
        .visit_retained_blob_sources(Some(policy), |retained| {
            let current = &retained.source;
            let selected = &source.projection;
            if current.transfer_id == selected.transfer_id
                && current.semantic_id == selected.semantic_id
                && current.publisher == selected.publisher
                && current.topic == selected.topic
                && current.scope == selected.scope
                && current.epoch == selected.epoch
                && current.sealed_len == selected.sealed_len
                && current.route_lineage == selected.route_lineage
                && current.physical_lineage == selected.physical_lineage
                && current.manifest_digest == selected.manifest_digest
                && current.blob_id == selected.blob_id
                && current.total_len == selected.total_len
                && current.chunk_size == selected.chunk_size
                && current.chunk_count == selected.chunk_count
                && retained.retention == source.retention
                && retained.source.transfer_id == source.stored.transfer_id
                && matches!(
                    retained.retention,
                    BlobSourceRetention::Completed { acceptance_marker }
                        if acceptance_marker == source.stored.acceptance_marker
                )
            {
                authorized = true;
            }
        })
        .map_err(|error| lifecycle_failure("authorize native Profile-5 source", error))?;
    if !authorized {
        return Err(lifecycle_failure(
            "authorize native Profile-5 source",
            "publication is not current and lifecycle-visible",
        ));
    }
    Ok(())
}

fn profile5_segment_for_wire_offset(
    total_len: u64,
    wire_len: u64,
    wire_offset: u64,
) -> Result<u64, BlobNetworkError> {
    let record_bytes = PROFILE5_PACK_SEGMENT_RECORD_BYTES as u64 + 4;
    let full_segments = total_len / aster_mesh::BLOB_STREAM_SEGMENT_BYTES as u64;
    let full_prefix = full_segments
        .checked_mul(record_bytes)
        .ok_or("Profile-5 wire prefix overflow")?;
    if wire_offset == wire_len {
        return Ok(total_len.div_ceil(aster_mesh::BLOB_STREAM_SEGMENT_BYTES as u64));
    }
    if wire_offset <= full_prefix && wire_offset.is_multiple_of(record_bytes) {
        return Ok(wire_offset / record_bytes);
    }
    Err(BlobNetworkError::new(
        BlobNetworkStage::Framing,
        "resume native Profile-5 pack",
        "durable offset is not a canonical segment boundary",
    ))
}

#[allow(clippy::too_many_arguments)]
async fn send_native_profile5_pack(
    adapter: &dyn StreamTransportAdapter,
    store: Arc<Store>,
    policy: &ControlPolicySnapshot,
    source: &CanonicalBlobSendSource,
    session: &mut MissionSession,
    profile_digest: [u8; 32],
    direction: EventDirection,
    attempt_nonce: [u8; 32],
) -> Result<BlobNetworkReport, BlobNetworkError> {
    let open_value = source.publication.publication().open();
    let expected_wire = blob_pack_wire_len(open_value.total_len())
        .map_err(|error| failure("calculate native Profile-5 wire length", error))?;
    if source.wire_len != expected_wire {
        return Err(durability_failure(
            "open native Profile-5 pack",
            "durable pack length differs from its segment contract",
        ));
    }
    let frame_count = usize::try_from(
        open_value
            .total_len()
            .div_ceil(aster_mesh::BLOB_STREAM_SEGMENT_BYTES as u64),
    )
    .map_err(|_| {
        BlobNetworkError::new(
            BlobNetworkStage::Framing,
            "bound native Profile-5 stream",
            "segment count overflows platform limits",
        )
    })?;
    let (max_data_bytes, max_control_bytes) =
        profile5_attempt_bounds_for_extents(source.wire_len, frame_count).map_err(|error| {
            BlobNetworkError::new(
                BlobNetworkStage::Framing,
                "bound native Profile-5 stream",
                error,
            )
        })?;
    let attempt = await_authenticated_progress(
        "open native Profile-5 transport attempt",
        adapter.open_attempt(AttemptOpenRequest {
            deadline: Instant::now() + profile5_attempt_hard_timeout(source.wire_len),
            max_data_bytes,
            max_control_bytes,
        }),
    )
    .await?;
    let mut cancellation = SenderDataCancellation::new(Arc::clone(&attempt));
    let finite_custody = if open_value.ttl_ms().is_some() {
        let exact_len = u64::try_from(source.stored.sealed.len())
            .map_err(|_| "finite native Profile-5 source length overflows")?;
        let charge = super::custody_finalization_charge_ms(exact_len)
            .map_err(|error| lifecycle_failure("bound native Profile-5 custody age", error))?;
        let context = session
            .mint_blob_custody_send_context_v2(direction, 1, attempt_nonce, charge)
            .map_err(|error| {
                authentication_failure("authorize native Profile-5 custody record", error)
            })?;
        let sample = super::contact_custody_sample()
            .map_err(|error| lifecycle_failure("sample native Profile-5 custody clock", error))?
            .ok_or_else(|| {
                lifecycle_failure("sample native Profile-5 custody clock", "clock unavailable")
            })?;
        let current = store
            .blob_source_projection(source.stored.transfer_id)
            .map_err(|error| lifecycle_failure("refresh finite native Profile-5 source", error))?
            .ok_or_else(|| {
                lifecycle_failure(
                    "refresh finite native Profile-5 source",
                    "publication is no longer visible",
                )
            })?;
        let pack = store
            .open_profile5_pack_transfer_read(source.stored.variant_id)
            .map_err(|error| durability_failure("open finite native Profile-5 pack", error))?;
        let authorization = store
            .authorize_finite_profile5_pack_send_v2_with_policy(
                policy,
                &source.stored,
                &current.source,
                current.retention,
                &source.publication,
                &pack,
                context,
                sample,
            )
            .map_err(|error| lifecycle_failure("authorize finite native Profile-5 source", error))?
            .ok_or_else(|| {
                lifecycle_failure("authorize finite native Profile-5 source", "source expired")
            })?;
        let (claim, prepared) = authorization.into_profile5_claim().map_err(|error| {
            authentication_failure("construct native Profile-5 custody claim", error)
        })?;
        let custody_digest = claim.digest();
        let custody_frame = session
            .seal_blob_custody_frame_v2(profile_digest, direction, attempt_nonce, &claim)
            .map_err(|error| {
                authentication_failure("seal native Profile-5 custody claim", error)
            })?;
        #[cfg(test)]
        super::apply_test_blob_finalization_delay().map_err(|error| {
            lifecycle_failure("delay native Profile-5 custody finalization", error)
        })?;
        let final_sample = super::contact_custody_sample()
            .map_err(|error| lifecycle_failure("finalize native Profile-5 custody clock", error))?
            .ok_or_else(|| {
                lifecycle_failure(
                    "finalize native Profile-5 custody clock",
                    "clock unavailable",
                )
            })?;
        if !store
            .finalize_finite_profile5_pack_send_with_policy(
                policy,
                prepared,
                &source.stored,
                &source.publication,
                &pack,
                final_sample,
            )
            .map_err(|error| lifecycle_failure("finalize finite native Profile-5 source", error))?
        {
            return Err(lifecycle_failure(
                "finalize finite native Profile-5 source",
                "source expired or changed before custody emission",
            ));
        }
        Some((custody_frame, custody_digest))
    } else {
        None
    };
    let stream_direction = match direction {
        EventDirection::ToSessionInitiator => StreamDirection::ToSessionInitiator,
        EventDirection::ToSessionResponder => StreamDirection::ToSessionResponder,
    };
    let transfer_open = StreamOpenV1 {
        class: StreamClass::Blob,
        direction: stream_direction,
        session_transcript: session.session_id(),
        exchange_id: 1,
        transfer_id: *source.stored.transfer_id.as_bytes(),
        source_transfer_id: *source.stored.transfer_id.as_bytes(),
        publication_id: *source.stored.semantic_id.as_bytes(),
        variant_id: *source.stored.variant_id.as_bytes(),
        total_len: source.wire_len,
        attempt_nonce,
        checkpoint_generation: 0,
        custody_digest: finite_custody.as_ref().map(|(_, digest)| *digest),
        source_len: u32::try_from(source.stored.sealed.len()).map_err(|_| {
            BlobNetworkError::new(
                BlobNetworkStage::Framing,
                "bind native Profile-5 publication source",
                "authenticated publication source length overflows",
            )
        })?,
        source_digest: Sha256::digest(&source.stored.sealed).into(),
    };
    let mut codec = MissionBlobRecordCodec {
        mission: session,
        profile_digest,
        direction,
        attempt_nonce,
    };
    if let Some((custody_frame, _)) = finite_custody {
        await_authenticated_progress(
            "send native Profile-5 custody authority",
            attempt.send_data(&custody_frame),
        )
        .await?;
    }
    await_authenticated_progress(
        "send native Profile-5 open",
        attempt.send_data(&codec.encode(StreamFrame::Open(transfer_open.clone()))?),
    )
    .await?;
    send_authenticated_source(
        attempt.as_ref(),
        &mut codec,
        &transfer_open,
        &source.stored.sealed,
    )
    .await?;
    let accept =
        await_authenticated_progress("receive native Profile-5 accept", attempt.receive_control())
            .await?
            .ok_or("control stream closed before native Profile-5 accept")?;
    let StreamFrame::Accept(accept) = codec.decode(&accept)? else {
        return Err("first native Profile-5 control frame was not ACCEPT".into());
    };
    let resumed_from = accept.durable_offset;
    let first_segment =
        profile5_segment_for_wire_offset(open_value.total_len(), source.wire_len, resumed_from)?;
    let mut state =
        StreamSenderState::new(transfer_open.transfer_id, attempt_nonce, source.wire_len);
    let accepted = state
        .accept(accept)
        .map_err(|error| failure("accept native Profile-5 stream", error))?;
    let requires_final_checkpoint = canonical_sender_requires_final_checkpoint(accepted)?;
    let mut checkpoints = 0_u64;
    if requires_final_checkpoint {
        let mut reader = store
            .open_profile5_pack_transfer_read_at_segment(source.stored.variant_id, first_segment)
            .map_err(|error| durability_failure("open native Profile-5 transfer lease", error))?;
        if reader.authenticated_open() != source.physical_open.authenticated_bytes()
            || reader.authenticated_commitment() != source.authenticated_commitment
            || reader.commitment() != &source.commitment
        {
            return Err(authentication_failure(
                "recheck native Profile-5 transfer source",
                "leased pack metadata changed",
            ));
        }
        while let Some(record) = reader
            .next_record()
            .map_err(|error| durability_failure("read native Profile-5 record", error))?
        {
            let mut pending = record.into_bytes();
            loop {
                match state
                    .send_extent(pending)
                    .map_err(|error| failure("advance native Profile-5 sender", error))?
                {
                    StreamExtentAction::Send(data) => {
                        let (prefix, body) = codec.encode_data_parts(data)?;
                        await_authenticated_progress(
                            "send native Profile-5 data",
                            attempt.send_data_parts(&prefix, &body),
                        )
                        .await?;
                        break;
                    }
                    StreamExtentAction::Retry {
                        reason: crate::stream_transfer::StreamRetry::CreditBlocked,
                        bytes,
                    } => {
                        let checkpoint = await_authenticated_progress(
                            "receive native Profile-5 checkpoint",
                            attempt.receive_control(),
                        )
                        .await?
                        .ok_or("control stream closed before native Profile-5 checkpoint")?;
                        let StreamFrame::Checkpoint(checkpoint) = codec.decode(&checkpoint)? else {
                            return Err(
                                "native Profile-5 credit wait received another frame".into()
                            );
                        };
                        state.checkpoint(checkpoint).map_err(|error| {
                            failure("advance native Profile-5 checkpoint", error)
                        })?;
                        require_canonical_send_source(&store, policy, source)?;
                        checkpoints = checkpoints.saturating_add(1);
                        pending = bytes;
                    }
                    StreamExtentAction::Retry { .. } => {
                        return Err("native Profile-5 sender produced an invalid retry".into());
                    }
                }
            }
        }
        let checkpoint = await_authenticated_progress(
            "receive final native Profile-5 checkpoint",
            attempt.receive_control(),
        )
        .await?
        .ok_or("control stream closed before final native Profile-5 checkpoint")?;
        let StreamFrame::Checkpoint(checkpoint) = codec.decode(&checkpoint)? else {
            return Err("final native Profile-5 control frame was not CHECKPOINT".into());
        };
        state
            .checkpoint(checkpoint)
            .map_err(|error| failure("advance final native Profile-5 checkpoint", error))?;
        require_canonical_send_source(&store, policy, source)?;
        checkpoints = checkpoints.saturating_add(1);
    }
    require_canonical_send_source(&store, policy, source)?;
    let StreamAction::Send(finish) = state
        .finish(source.authenticated_commitment.clone())
        .map_err(|error| failure("finish native Profile-5 sender", error))?
    else {
        return Err("native Profile-5 sender did not produce FINISH".into());
    };
    await_authenticated_progress(
        "send native Profile-5 finish",
        attempt.send_data(&codec.encode(finish)?),
    )
    .await?;
    let result =
        await_authenticated_progress("receive native Profile-5 result", attempt.receive_control())
            .await?
            .ok_or("control stream closed before native Profile-5 result")?;
    let StreamFrame::Result(result) = codec.decode(&result)? else {
        return Err("native Profile-5 terminal control frame was not RESULT".into());
    };
    let roots = (
        *source.commitment.blob_id().as_bytes(),
        Sha256::digest(source.commitment.encode()).into(),
    );
    if !matches!(
        result.code,
        StreamResultCode::Promoted | StreamResultCode::AlreadyPresent
    ) || result.result_digest != canonical_result_digest(&transfer_open, roots)
    {
        return Err(settlement_failure(
            "validate native Profile-5 result",
            "result did not bind the exact pack commitment",
        ));
    }
    let expected = result.code;
    let (StreamAction::Send(ack), StreamAction::Terminal(settled)) = state
        .result(result)
        .map_err(|error| settlement_failure("settle native Profile-5 sender", error))?
    else {
        return Err(settlement_failure(
            "settle native Profile-5 sender",
            "settlement action differed",
        ));
    };
    if settled != expected {
        return Err(settlement_failure(
            "settle native Profile-5 sender",
            "result code differed",
        ));
    }
    await_authenticated_progress(
        "send native Profile-5 result acknowledgement",
        attempt.send_data(&codec.encode(ack)?),
    )
    .await?;
    await_authenticated_progress("finish native Profile-5 data stream", attempt.finish_data())
        .await?;
    cancellation.disarm();
    if await_authenticated_progress(
        "receive native Profile-5 control EOF",
        attempt.receive_control(),
    )
    .await?
    .is_some()
    {
        return Err("native Profile-5 control stream contained trailing data".into());
    }
    Ok(BlobNetworkReport {
        wire_bytes: source.wire_len,
        resumed_from,
        attempt_bytes: source.wire_len.saturating_sub(resumed_from),
        roots,
        checkpoints,
        pipeline: None,
    })
}

struct NativeProfile5RecordParser {
    buffer: Vec<u8>,
    next_index: u64,
    consumed: u64,
}

impl NativeProfile5RecordParser {
    fn new(next_index: u64, consumed: u64) -> Self {
        Self {
            buffer: Vec::with_capacity(PROFILE5_PACK_SEGMENT_RECORD_BYTES + 4),
            next_index,
            consumed,
        }
    }

    async fn push(
        &mut self,
        bytes: &[u8],
        sender: &mpsc::Sender<Result<StreamPartition, PipelineError>>,
    ) -> Result<(), BlobNetworkError> {
        self.buffer.extend_from_slice(bytes);
        loop {
            if self.buffer.len() < 4 {
                return Ok(());
            }
            let encoded_len =
                u32::from_be_bytes(self.buffer[..4].try_into().expect("record length")) as usize;
            if encoded_len == 0
                || encoded_len
                    > aster_mesh::BLOB_STREAM_SEGMENT_BYTES
                        + aster_mesh::BLOB_STREAM_SEGMENT_ENCODED_OVERHEAD_BYTES
            {
                return Err(verification_failure(
                    "partition native Profile-5 record",
                    "record length is out of bounds",
                ));
            }
            let record_len = encoded_len
                .checked_add(4)
                .ok_or("native Profile-5 record length overflow")?;
            if self.buffer.len() < record_len {
                return Ok(());
            }
            let wire_end = self
                .consumed
                .checked_add(record_len as u64)
                .ok_or("native Profile-5 wire offset overflow")?;
            let record = self.buffer.drain(..record_len).collect::<Vec<_>>();
            sender
                .send(Ok(StreamPartition::new_at(
                    self.next_index,
                    wire_end,
                    record,
                )))
                .await
                .map_err(|_| {
                    verification_failure(
                        "submit native Profile-5 record",
                        "verification pipeline closed",
                    )
                })?;
            self.next_index = self
                .next_index
                .checked_add(1)
                .ok_or("native Profile-5 segment index overflow")?;
            self.consumed = wire_end;
        }
    }

    fn finish(&self, wire_len: u64) -> Result<(), BlobNetworkError> {
        if self.buffer.is_empty() && self.consumed == wire_len {
            Ok(())
        } else {
            Err(verification_failure(
                "finish native Profile-5 records",
                "stream ended with a partial record",
            ))
        }
    }
}

#[derive(Clone)]
struct NativeProfile5DurableProgress {
    wire_offset: u64,
    checkpoint: BlobUploadCheckpoint,
}

fn existing_native_profile5_pack(
    store: &Store,
    policy: &ControlPolicySnapshot,
    authority: &VerifiedBlobStreamPublicationSource,
    source: &[u8],
    transfer_open: &StreamOpenV1,
) -> Result<Option<(StoredBlob, aster_redb_store::Profile5PackReadSession)>, BlobNetworkError> {
    let publication = authority.publication();
    let physical_open = authority.physical_open();
    let open = publication.publication().open();
    let operation = BlobOperationKey::new(open.operation_key().to_vec())
        .map_err(|error| authentication_failure("bind native Profile-5 operation", error))?;
    let owner = BlobOperationOwner::new(open.publisher(), operation);
    let Some(blob) = store
        .blob_for_owner_with_policy(policy, &owner)
        .map_err(|error| lifecycle_failure("resolve native Profile-5 retry", error))?
    else {
        return Ok(None);
    };
    let pack = store
        .open_profile5_pack_transfer_read(blob.variant_id)
        .map_err(|error| durability_failure("open promoted native Profile-5 retry", error))?;
    let decoded = authority.source();
    let inbound_transfer_id = BlobTransferId::new(Sha256::digest(source).into());
    let semantic_id = aster_redb_store::BlobSemanticId::new(
        Sha256::digest(publication.authenticated_bytes()).into(),
    );
    let inbound_variant_id = BlobVariantId::for_content(
        pack.commitment().blob_id(),
        &physical_open.open().content_group(),
        physical_open.open().content_epoch(),
    );
    let local_source = aster_mesh::BlobStreamPublicationSource::new(
        publication.authenticated_bytes().to_vec(),
        pack.authenticated_open().to_vec(),
        pack.authenticated_commitment().to_vec(),
    )
    .and_then(|source| source.encode())
    .map_err(|error| authentication_failure("bind promoted native Profile-5 retry", error))?;
    let local_transfer_id = BlobTransferId::new(Sha256::digest(&local_source).into());
    let local_variant_id = BlobVariantId::for_content(
        pack.commitment().blob_id(),
        &pack.open().content_group(),
        pack.open().content_epoch(),
    );
    if decoded.authenticated_publication() != publication.authenticated_bytes()
        || decoded.authenticated_open() != physical_open.authenticated_bytes()
        || decoded.authenticated_commitment()
            != authority.physical_commitment().authenticated_bytes()
        || publication.publication().blob_id() != pack.commitment().blob_id()
        || publication.publication().physical_lineage() != pack.physical_lineage()
        || open.total_len() != pack.open().total_len()
        || open.content_epoch() != pack.open().content_epoch()
        || open.metadata() != pack.open().metadata()
        || open.content_group() != pack.open().content_group()
        || blob.sealed != local_source
        || blob.transfer_id != local_transfer_id
        || blob.semantic_id != semantic_id
        || blob.variant_id != local_variant_id
        || local_variant_id != inbound_variant_id
        || transfer_open.transfer_id != *inbound_transfer_id.as_bytes()
        || transfer_open.source_transfer_id != *inbound_transfer_id.as_bytes()
        || transfer_open.publication_id != *semantic_id.as_bytes()
        || transfer_open.variant_id != *inbound_variant_id.as_bytes()
    {
        return Err(authentication_failure(
            "bind promoted native Profile-5 retry",
            "existing publication differs from authenticated transport source",
        ));
    }
    Ok(Some((blob, pack)))
}

struct ExistingNativeProfile5Settlement<'a> {
    authority: &'a VerifiedBlobStreamPublicationSource,
    store: &'a Store,
    policy: &'a ControlPolicySnapshot,
}

enum NativeProfile5Completion {
    Published {
        blob: Box<StoredBlob>,
        pack: Box<aster_redb_store::Profile5PackReadSession>,
    },
    Retained(Box<aster_redb_store::Profile5PackReadSession>),
    Upload(Box<CompletedNativeProfile5Upload>),
}

struct CompletedNativeProfile5Upload {
    reservation: aster_redb_store::BlobUploadReservation,
    checkpoint: BlobUploadCheckpoint,
    _reader: BlobPackReader,
    _retained_lease: Option<aster_redb_store::Profile5PackReadSession>,
}

struct ExistingNativeProfile5Pack {
    completion: NativeProfile5Completion,
    wire_len: u64,
    pending_custody: Option<(VerifiedBlobCustodyClaimV2, aster_mesh::CustodySample)>,
}

async fn settle_existing_native_profile5_pack(
    attempt: Arc<dyn StreamReceiveAttempt>,
    mut codec: MissionBlobRecordCodec<'_>,
    verifier: &mut ReferenceEnvelopeSealer,
    transfer_open: StreamOpenV1,
    settlement: ExistingNativeProfile5Settlement<'_>,
    existing: ExistingNativeProfile5Pack,
) -> Result<BlobNetworkReport, BlobNetworkError> {
    let ExistingNativeProfile5Settlement {
        authority,
        store,
        policy,
    } = settlement;
    let physical_open = authority.physical_open();
    let physical_commitment = authority.physical_commitment();
    let ExistingNativeProfile5Pack {
        completion,
        wire_len,
        pending_custody,
    } = existing;
    let mut state = StreamReceiverState::new(
        &transfer_open,
        wire_len,
        0,
        wire_len,
        PROFILE5_PACK_TRANSPORT_FRAME_BYTES as u32,
    )
    .map_err(|error| failure("resume promoted native Profile-5 receiver", error))?;
    let StreamAction::Send(accept) = state
        .accept(MAX_STREAM_CHECKPOINT_BATCH_BYTES)
        .map_err(|error| failure("accept promoted native Profile-5 retry", error))?
    else {
        return Err("promoted native Profile-5 retry did not produce ACCEPT".into());
    };
    await_authenticated_progress(
        "send promoted native Profile-5 accept",
        attempt.send_control(&codec.encode(accept)?),
    )
    .await?;
    let encoded_finish = await_authenticated_progress(
        "receive promoted native Profile-5 finish",
        attempt.receive_data(),
    )
    .await?
    .ok_or("data stream closed before promoted native Profile-5 finish")?;
    let StreamFrame::Finish(finish) = codec.decode(&encoded_finish)? else {
        return Err("promoted native Profile-5 retry did not receive FINISH".into());
    };
    if finish.semantic_commitment != physical_commitment.authenticated_bytes() {
        return Err(authentication_failure(
            "bind promoted native Profile-5 finish",
            "authenticated commitment differs from inbound transfer source",
        ));
    }
    verifier
        .verify_blob_stream_commitment(physical_open, &finish.semantic_commitment)
        .map_err(|error| {
            authentication_failure("authenticate promoted native Profile-5 commitment", error)
        })?;
    let StreamAction::Promote = state
        .finish(finish)
        .map_err(|error| settlement_failure("finish promoted native Profile-5 retry", error))?
    else {
        return Err("promoted native Profile-5 retry did not request settlement".into());
    };
    run_native_profile5_prepromotion_hook();
    let finite = pending_custody
        .map(|(verified, received_sample)| {
            let promotion_sample = super::contact_custody_sample()
                .map_err(|error| {
                    lifecycle_failure("sample existing native receiver promotion clock", error)
                })?
                .ok_or_else(|| {
                    lifecycle_failure(
                        "sample existing native receiver promotion clock",
                        "clock unavailable",
                    )
                })?;
            Ok::<_, BlobNetworkError>((verified, received_sample, promotion_sample))
        })
        .transpose()?;
    let (blob, result_code) = match completion {
        NativeProfile5Completion::Published { blob, pack } => {
            if let Some((verified, received_sample, promotion_sample)) = finite {
                store
                    .admit_existing_finite_profile5_pack_with_policy(
                        policy,
                        &blob,
                        authority,
                        &pack,
                        verified,
                        received_sample,
                        promotion_sample,
                    )
                    .map_err(|error| {
                        lifecycle_failure("refresh existing native Profile-5 custody", error)
                    })?;
            }
            (*blob, StreamResultCode::AlreadyPresent)
        }
        completion => {
            let cache = super::contact_mutable_route_cache(verifier).map_err(|error| {
                lifecycle_failure("bind completed native Profile-5 route cache", error)
            })?;
            let lifecycle = cache.lock_blob_lifecycle().map_err(|error| {
                lifecycle_failure("lock completed native Profile-5 lifecycle", error)
            })?;
            let finite = finite.map(|(verified, received, promoted)| {
                aster_redb_store::ReceivedProfile5FinitePromotion::new(verified, received, promoted)
            });
            let outcome = match &completion {
                NativeProfile5Completion::Retained(pack) => store
                    .commit_received_existing_profile5_pack_with_policy(
                        policy, authority, pack, finite,
                    ),
                NativeProfile5Completion::Upload(upload) => {
                    let reservation = &upload.reservation;
                    let checkpoint = &upload.checkpoint;
                    let promoted = match finite {
                        Some(finite) => store.commit_received_profile5_upload_once_with_policy(
                            policy,
                            reservation,
                            checkpoint,
                            authority.publication(),
                            finite,
                        ),
                        None => store.commit_received_durable_profile5_upload_once_with_policy(
                            policy,
                            reservation,
                            checkpoint,
                            authority.publication(),
                        ),
                    };
                    if let Err(error) = &promoted
                        && terminal_profile5_promotion_error(error)
                    {
                        store.abort_blob_upload(reservation).map_err(|error| {
                            lifecycle_failure(
                                "abort rejected completed native Profile-5 upload",
                                error,
                            )
                        })?;
                    }
                    promoted
                }
                NativeProfile5Completion::Published { .. } => {
                    unreachable!("handled existing publication")
                }
            }
            .map_err(|error| {
                lifecycle_failure("accept completed native Profile-5 publication", error)
            })?;
            super::cache_authenticated_profile5_blob_route_claim(
                store,
                &cache,
                verifier,
                outcome.blob(),
                &lifecycle,
            )
            .map_err(|error| {
                lifecycle_failure("cache completed native Profile-5 publication", error)
            })?;
            let code = if outcome.inserted() {
                StreamResultCode::Promoted
            } else {
                StreamResultCode::AlreadyPresent
            };
            (outcome.blob().clone(), code)
        }
    };
    let roots = (
        *physical_commitment.commitment().blob_id().as_bytes(),
        Sha256::digest(physical_commitment.commitment().encode()).into(),
    );
    if blob.blob_id != physical_commitment.commitment().blob_id() {
        return Err(authentication_failure(
            "bind promoted native Profile-5 roots",
            "retained publication differs from retained pack commitment",
        ));
    }
    let digest = canonical_result_digest(&transfer_open, roots);
    let StreamAction::Send(result) = state
        .promoted(result_code, digest)
        .map_err(|error| settlement_failure("settle promoted native Profile-5 retry", error))?
    else {
        return Err("promoted native Profile-5 retry did not produce RESULT".into());
    };
    await_authenticated_progress(
        "send promoted native Profile-5 result",
        attempt.send_control(&codec.encode(result)?),
    )
    .await?;
    let encoded_ack = await_authenticated_progress(
        "receive promoted native Profile-5 result acknowledgement",
        attempt.receive_data(),
    )
    .await?
    .ok_or("data stream closed before promoted native Profile-5 acknowledgement")?;
    let StreamFrame::ResultAck(ack) = codec.decode(&encoded_ack)? else {
        return Err("promoted native Profile-5 retry did not receive RESULT_ACK".into());
    };
    if !matches!(
        state
            .result_ack(ack, result_code)
            .map_err(|error| settlement_failure("acknowledge promoted Profile-5 retry", error))?,
        StreamAction::Terminal(code) if code == result_code
    ) {
        return Err("promoted native Profile-5 retry did not terminate".into());
    }
    if await_authenticated_progress(
        "receive promoted native Profile-5 data EOF",
        attempt.receive_data(),
    )
    .await?
    .is_some()
    {
        return Err("promoted native Profile-5 retry contained trailing data".into());
    }
    await_authenticated_progress(
        "finish promoted native Profile-5 control stream",
        attempt.finish_control(),
    )
    .await?;
    Ok(BlobNetworkReport {
        wire_bytes: wire_len,
        resumed_from: wire_len,
        attempt_bytes: 0,
        roots,
        checkpoints: 0,
        pipeline: None,
    })
}

#[allow(clippy::too_many_arguments)]
async fn receive_native_profile5_pack(
    attempt: Arc<dyn StreamReceiveAttempt>,
    mut codec: MissionBlobRecordCodec<'_>,
    store: Arc<Store>,
    policy: &ControlPolicySnapshot,
    verifier: &mut ReferenceEnvelopeSealer,
    transfer_open: StreamOpenV1,
    source: Vec<u8>,
    authority: VerifiedBlobStreamPublicationSource,
    offer: &BlobStreamSourceOfferV1,
    opened_custody: Option<(BlobCustodyClaimV2, AuthenticatedBlobCustodyContactV2)>,
    custody_received_sample: Option<aster_mesh::CustodySample>,
) -> Result<BlobNetworkReport, BlobNetworkError> {
    let publication = authority.publication().clone();
    let physical_open = authority.physical_open().clone();
    let physical_commitment = authority.physical_commitment().clone();
    let open = publication.publication().open();
    let physical_open_value = physical_open.open();
    let commitment = physical_commitment.commitment();
    let source_record = authority.source();
    let lineage = verifier
        .blob_stream_lineage(&physical_open)
        .map_err(|error| authentication_failure("derive native Profile-5 lineage", error))?;
    let transfer_id = BlobTransferId::new(Sha256::digest(&source).into());
    let semantic_id = aster_redb_store::BlobSemanticId::new(
        Sha256::digest(publication.authenticated_bytes()).into(),
    );
    let variant = BlobVariantId::for_content(
        commitment.blob_id(),
        &physical_open_value.content_group(),
        physical_open_value.content_epoch(),
    );
    let wire_len = blob_pack_wire_len(physical_open_value.total_len())
        .map_err(|error| failure("calculate received Profile-5 pack length", error))?;
    if source_record.authenticated_publication() != publication.authenticated_bytes()
        || source_record.authenticated_open() != physical_open.authenticated_bytes()
        || source_record.authenticated_commitment() != physical_commitment.authenticated_bytes()
        || publication.publication().blob_id() != commitment.blob_id()
        || publication.publication().physical_lineage() != lineage.physical().binding()
        || physical_open_value.content_group() != open.content_group()
        || physical_open_value.content_epoch() != open.content_epoch()
        || physical_open_value.total_len() != open.total_len()
        || physical_open_value.metadata() != open.metadata()
        || (offer.finite != open.ttl_ms().is_some())
        || (offer.finite != opened_custody.is_some())
        || (offer.finite != custody_received_sample.is_some())
        || open.publisher() == [0; 32]
        || open.topic() != &offer.topic
        || open.scope() != &offer.scope
        || open.content_epoch() != offer.key_epoch
        || transfer_open.total_len != wire_len
        || transfer_open.source_len != offer.source_len
        || transfer_open.source_digest != offer.source_digest
        || transfer_open.transfer_id != *transfer_id.as_bytes()
        || transfer_open.source_transfer_id != *transfer_id.as_bytes()
        || transfer_open.publication_id != *semantic_id.as_bytes()
        || transfer_open.variant_id != *variant.as_bytes()
    {
        return Err(authentication_failure(
            "validate native Profile-5 source",
            "authenticated open differs from PLAN/OPEN metadata",
        ));
    }
    let pending_custody = if let Some((claim, authority)) = opened_custody {
        let ttl_ms = open.ttl_ms().ok_or_else(|| {
            authentication_failure(
                "verify native Profile-5 custody claim",
                "durable source carried finite custody authority",
            )
        })?;
        let verified = claim
            .verify_authenticated_profile5_source(
                authority,
                1,
                BlobCustodyTransferId::from_exact_hash(*transfer_id.as_bytes()),
                u64::try_from(source.len()).map_err(|_| {
                    authentication_failure(
                        "verify native Profile-5 custody claim",
                        "publication source length overflows",
                    )
                })?,
                *semantic_id.as_bytes(),
                commitment.blob_id(),
                open.priority(),
                ttl_ms,
                claim.prior_cumulative_age_ms(),
            )
            .map_err(|error| {
                authentication_failure("verify native Profile-5 custody claim", error)
            })?;
        if transfer_open.custody_digest != Some(verified.digest()) {
            return Err(authentication_failure(
                "bind native Profile-5 custody claim",
                "OPEN custody digest differs from authenticated claim",
            ));
        }
        Some((
            verified,
            custody_received_sample.ok_or_else(|| {
                lifecycle_failure(
                    "bind native receiver custody clock",
                    "receipt sample unavailable",
                )
            })?,
        ))
    } else {
        None
    };
    if let Some((blob, pack)) =
        existing_native_profile5_pack(&store, policy, &authority, &source, &transfer_open)?
    {
        return settle_existing_native_profile5_pack(
            attempt,
            codec,
            verifier,
            transfer_open,
            ExistingNativeProfile5Settlement {
                authority: &authority,
                store: &store,
                policy,
            },
            ExistingNativeProfile5Pack {
                completion: NativeProfile5Completion::Published {
                    blob: Box::new(blob),
                    pack: Box::new(pack),
                },
                wire_len,
                pending_custody,
            },
        )
        .await;
    }
    let incoming_owner = BlobOperationOwner::new(
        open.publisher(),
        BlobOperationKey::new(open.operation_key().to_vec())
            .map_err(|error| authentication_failure("bind native Profile-5 owner", error))?,
    );
    if store
        .resume_blob_upload(&incoming_owner)
        .map_err(|error| lifecycle_failure("resolve native Profile-5 pending upload", error))?
        .is_none()
    {
        match store.open_profile5_pack_transfer_read(variant) {
            Ok(pack) => {
                if pack.commitment().blob_id() != commitment.blob_id()
                    || pack.open().total_len() != physical_open_value.total_len()
                    || pack.open().content_group() != physical_open_value.content_group()
                    || pack.open().content_epoch() != physical_open_value.content_epoch()
                    || pack.open().metadata() != physical_open_value.metadata()
                    || pack.physical_lineage() != lineage.physical().binding()
                {
                    return Err(authentication_failure(
                        "bind retained native Profile-5 pack",
                        "retained content differs from incoming publication",
                    ));
                }
                return settle_existing_native_profile5_pack(
                    attempt,
                    codec,
                    verifier,
                    transfer_open,
                    ExistingNativeProfile5Settlement {
                        authority: &authority,
                        store: &store,
                        policy,
                    },
                    ExistingNativeProfile5Pack {
                        completion: NativeProfile5Completion::Retained(Box::new(pack)),
                        wire_len,
                        pending_custody,
                    },
                )
                .await;
            }
            Err(StoreError::Blob(BlobStoreError::NotFound)) => {}
            Err(error) => {
                return Err(durability_failure(
                    "open retained native Profile-5 pack",
                    error,
                ));
            }
        }
    }
    let (reservation, initial_checkpoint, restored_open) = store
        .reserve_received_profile5_upload_with_policy(policy, &publication, &physical_open)
        .map_err(|error| lifecycle_failure("reserve native Profile-5 receiver pack", error))?;
    if restored_open != physical_open {
        return Err(authentication_failure(
            "restore native Profile-5 receiver open",
            "durable authenticated open changed",
        ));
    }
    if let Some(completion) = initial_checkpoint.profile5_completion() {
        if completion.commitment() != physical_commitment.commitment()
            || completion.authenticated_commitment() != physical_commitment.authenticated_bytes()
        {
            return Err(authentication_failure(
                "restore completed native Profile-5 upload",
                "durable finish authority differs from incoming source",
            ));
        }
        // A reused completion refers to a lifecycle-owned pack, whose last
        // existing publication may otherwise be evicted while FINISH is pending.
        let retained_lease = completion
            .reuses_existing_pack()
            .then(|| store.open_profile5_pack_transfer_read(variant))
            .transpose()
            .map_err(|error| durability_failure("lease completed native Profile-5 pack", error))?;
        let root = PinnedBlobPackRoot::open(&store)
            .map_err(|error| durability_failure("open completed native Profile-5 root", error))?;
        let reader = BlobPackReader::open_completed_upload_pinned(&root, completion.pack())
            .map_err(|error| durability_failure("open completed native Profile-5 pack", error))?;
        return settle_existing_native_profile5_pack(
            attempt,
            codec,
            verifier,
            transfer_open,
            ExistingNativeProfile5Settlement {
                authority: &authority,
                store: &store,
                policy,
            },
            ExistingNativeProfile5Pack {
                completion: NativeProfile5Completion::Upload(Box::new(
                    CompletedNativeProfile5Upload {
                        reservation,
                        checkpoint: initial_checkpoint,
                        _reader: reader,
                        _retained_lease: retained_lease,
                    },
                )),
                wire_len,
                pending_custody,
            },
        )
        .await;
    }
    let durable_pack = initial_checkpoint.durable_pack_checkpoint();
    let resumed_from = durable_pack.map_or(0, |checkpoint| checkpoint.payload_len());
    let writer = store
        .open_blob_upload_writer(&reservation, &initial_checkpoint)
        .map_err(|error| durability_failure("restore native Profile-5 pack writer", error))?;
    let opener = verifier
        .blob_stream_segment_opener(&physical_open)
        .map_err(|error| authentication_failure("open native Profile-5 segments", error))?;
    let checkpoint_batch_bytes = native_profile5_checkpoint_batch_bytes();
    let mut current_limit = profile5_receive_limit(wire_len, resumed_from, checkpoint_batch_bytes);
    let mut state = StreamReceiverState::new(
        &transfer_open,
        resumed_from,
        durable_pack.map_or(0, BlobPackCheckpoint::generation),
        current_limit,
        PROFILE5_PACK_TRANSPORT_FRAME_BYTES as u32,
    )
    .map_err(|error| failure("initialize native Profile-5 receiver", error))?;
    let StreamAction::Send(accept) = state
        .accept(checkpoint_batch_bytes)
        .map_err(|error| failure("accept native Profile-5 receiver", error))?
    else {
        return Err("native Profile-5 receiver did not produce ACCEPT".into());
    };
    await_authenticated_progress(
        "send native Profile-5 accept",
        attempt.send_control(&codec.encode(accept)?),
    )
    .await?;

    let next_index = durable_pack.map_or(0, BlobPackCheckpoint::next_index);
    let (partition_tx, partition_rx) = mpsc::channel(8);
    let (durable_tx, mut durable_rx) = mpsc::unbounded_channel();
    let sink_store = Arc::clone(&store);
    let sink_policy = *policy;
    let sink_reservation = reservation.clone();
    let sink_initial = initial_checkpoint.clone();
    let total_plaintext = open.total_len();
    let mut job = [0_u8; 16];
    job.copy_from_slice(&transfer_open.transfer_id[..16]);
    let pipeline_job = StreamJobId::from_bytes(job);
    let mut pipeline_task = tokio::spawn(async move {
        let sink = Arc::new(std::sync::Mutex::new((writer, sink_initial, resumed_from)));
        let sink_for_pipeline = Arc::clone(&sink);
        let report = run_ordered_channel_pipeline_from(
            pipeline_job,
            partition_rx,
            next_index,
            PipelineLimits::new(4, 8, 16 * 1024 * 1024, 8)
                .map_err(|_| PipelineError::InvalidLimits)?,
            move |partition| {
                let index = partition.index();
                let wire_end = partition.source_end();
                let record = partition.into_bytes();
                let (header, _plaintext, leaves) = opener
                    .open_encoded(&record[4..])
                    .map_err(|error| PipelineError::MapFailed(error.to_string()))?;
                if header.index() != index {
                    return Err(PipelineError::MapFailed(
                        "native Profile-5 segment index differs".into(),
                    ));
                }
                Ok((record, header, leaves, wire_end))
            },
            move |mapped: MappedPartition<_>| {
                let (record, header, leaves, wire_end) = mapped.into_value();
                let sink = Arc::clone(&sink_for_pipeline);
                let store = Arc::clone(&sink_store);
                let reservation = sink_reservation.clone();
                let durable_tx = durable_tx.clone();
                Box::pin(async move {
                    let checkpoint = {
                        let mut state = sink
                            .lock()
                            .unwrap_or_else(std::sync::PoisonError::into_inner);
                        let (writer, projected, last_checkpoint_wire) = &mut *state;
                        writer
                            .append_record(&record[4..], leaves)
                            .map_err(|error| PipelineError::SinkFailed(error.to_string()))?;
                        let plaintext_end = header
                            .offset()
                            .checked_add(u64::from(header.plaintext_len()))
                            .ok_or_else(|| {
                                PipelineError::SinkFailed(
                                    "native Profile-5 plaintext progress overflow".into(),
                                )
                            })?;
                        if wire_end.saturating_sub(*last_checkpoint_wire)
                            >= u64::from(checkpoint_batch_bytes)
                            || plaintext_end == total_plaintext
                        {
                            Some((
                                projected.clone(),
                                writer.checkpoint().map_err(|error| {
                                    PipelineError::SinkFailed(error.to_string())
                                })?,
                            ))
                        } else {
                            None
                        }
                    };
                    if let Some((expected, durable)) = checkpoint {
                        let projected = spawn_native_profile5_checkpoint(
                            Arc::clone(&sink),
                            store,
                            sink_policy,
                            reservation,
                            expected.clone(),
                            durable,
                        )
                        .await
                        .map_err(|error| PipelineError::SinkFailed(error.to_string()))?
                        .map_err(|error| PipelineError::SinkFailed(error.to_string()))?;
                        let mut state = sink
                            .lock()
                            .unwrap_or_else(std::sync::PoisonError::into_inner);
                        let (_, current, last_checkpoint_wire) = &mut *state;
                        if *current != expected {
                            return Err(PipelineError::SinkFailed(
                                "native Profile-5 checkpoint authority changed".into(),
                            ));
                        }
                        *current = projected.clone();
                        *last_checkpoint_wire = wire_end;
                        durable_tx
                            .send(NativeProfile5DurableProgress {
                                wire_offset: wire_end,
                                checkpoint: projected,
                            })
                            .map_err(|_| {
                                PipelineError::SinkFailed(
                                    "native Profile-5 checkpoint receiver closed".into(),
                                )
                            })?;
                    }
                    Ok(())
                })
            },
        )
        .await?;
        let (writer, projected, _) = Arc::try_unwrap(sink)
            .map_err(|_| PipelineError::WorkerPanicked)?
            .into_inner()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        Ok::<_, PipelineError>((report, writer, projected))
    });

    let mut parser = NativeProfile5RecordParser::new(next_index, resumed_from);
    let mut received = resumed_from;
    let mut durable_wire = resumed_from;
    let mut checkpoints = 0_u64;
    let mut receive = Box::pin(async {
        while received < wire_len {
            let encoded = await_authenticated_progress(
                "receive native Profile-5 data",
                attempt.receive_data(),
            )
            .await?
            .ok_or("data stream closed before native Profile-5 completion")?;
            let StreamFrame::Data(data) = codec.decode(&encoded)? else {
                return Err("native Profile-5 content phase received another frame".into());
            };
            let through = match state
                .data(&data)
                .map_err(|error| failure("advance native Profile-5 receiver", error))?
            {
                StreamAction::Persist { through } => through,
                StreamAction::Retry(_) => continue,
                _ => return Err("native Profile-5 receiver produced an invalid DATA action".into()),
            };
            parser.push(&data.bytes, &partition_tx).await?;
            received = through;
            if parser.consumed.saturating_sub(durable_wire) >= u64::from(checkpoint_batch_bytes)
                || parser.consumed == wire_len
            {
                let progress = durable_rx.recv().await.ok_or_else(|| {
                    durability_failure(
                        "checkpoint native Profile-5 pipeline",
                        "durable progress channel closed",
                    )
                })?;
                let generation = progress
                    .checkpoint
                    .durable_pack_checkpoint()
                    .ok_or_else(|| {
                        durability_failure(
                            "checkpoint native Profile-5 pipeline",
                            "durable pack checkpoint is absent",
                        )
                    })?
                    .generation();
                current_limit =
                    profile5_receive_limit(wire_len, progress.wire_offset, checkpoint_batch_bytes);
                let StreamAction::Send(checkpoint) = state
                    .persisted(progress.wire_offset, generation, current_limit)
                    .map_err(|error| failure("persist native Profile-5 checkpoint", error))?
                else {
                    return Err("native Profile-5 receiver did not produce CHECKPOINT".into());
                };
                await_authenticated_progress(
                    "send native Profile-5 checkpoint",
                    attempt.send_control(&codec.encode(checkpoint)?),
                )
                .await?;
                durable_wire = progress.wire_offset;
                checkpoints = checkpoints.saturating_add(1);
            }
        }
        parser.finish(wire_len)?;
        drop(partition_tx);
        Ok::<_, BlobNetworkError>((codec, state, checkpoints))
    });
    let map_pipeline_error = |error| match error {
        PipelineError::MapFailed(_) => {
            verification_failure("authenticate native ASTRBS02 segment", error)
        }
        PipelineError::SinkFailed(_) => durability_failure("commit native Profile-5 pack", error),
        _ => failure("run native Profile-5 receive pipeline", error),
    };
    let (receive_result, pipeline_result) = tokio::select! {
        received = &mut receive => {
            match received {
                Ok(received) => {
                    let pipeline = pipeline_task
                        .await
                        .map_err(|error| failure("join native Profile-5 receive pipeline", error))?
                        .map_err(map_pipeline_error)?;
                    (received, pipeline)
                }
                Err(error) => {
                    pipeline_task.abort();
                    let _ = pipeline_task.await;
                    return Err(error);
                }
            }
        }
        joined = &mut pipeline_task => {
            let pipeline = joined
                .map_err(|error| failure("join native Profile-5 receive pipeline", error))?
                .map_err(map_pipeline_error)?;
            let received = receive.await?;
            (received, pipeline)
        }
    };
    let (mut codec, mut state, checkpoints) = receive_result;
    let (pipeline, writer, projected) = pipeline_result;
    let encoded_finish =
        await_authenticated_progress("receive native Profile-5 finish", attempt.receive_data())
            .await?
            .ok_or("data stream closed before native Profile-5 finish")?;
    let StreamFrame::Finish(finish) = codec.decode(&encoded_finish)? else {
        return Err("native Profile-5 terminal data frame was not FINISH".into());
    };
    if finish.semantic_commitment != physical_commitment.authenticated_bytes() {
        return Err(authentication_failure(
            "bind native Profile-5 finish",
            "FINISH differs from the physical commitment authenticated in SOURCE",
        ));
    }
    let imported_custody = pending_custody;
    let StreamAction::Promote = state
        .finish(finish)
        .map_err(|error| settlement_failure("finish native Profile-5 receiver", error))?
    else {
        return Err("native Profile-5 receiver did not request promotion".into());
    };
    let roots = (
        *commitment.blob_id().as_bytes(),
        Sha256::digest(commitment.encode()).into(),
    );
    let finish_store = Arc::clone(&store);
    let finish_policy = *policy;
    let finish_reservation = reservation.clone();
    let projected = tokio::task::spawn_blocking(move || {
        let completion = (|| {
            let completion = writer
                .finish_profile5(&physical_commitment)
                .map_err(|error| {
                    StoreError::Blob(BlobStoreError::Verification(error.to_string()))
                })?;
            let projected = finish_store.checkpoint_blob_upload(
                &finish_policy,
                &finish_reservation,
                projected,
                completion.checkpoint().clone(),
            )?;
            finish_store.complete_profile5_upload_pack(
                &finish_policy,
                &finish_reservation,
                projected,
                completion,
                &physical_commitment,
                lineage,
            )
        })();
        if let Err(error) = &completion
            && terminal_profile5_promotion_error(error)
        {
            finish_store.abort_blob_upload(&finish_reservation)?;
        }
        completion
    })
    .await
    .map_err(|error| failure("join native Profile-5 pack completion", error))?
    .map_err(|error| lifecycle_failure("complete native Profile-5 pack", error))?;
    run_native_profile5_prepromotion_hook();
    let imported_custody = match imported_custody {
        Some((verified, received_sample)) => {
            let promotion_sample = super::contact_custody_sample()
                .map_err(|error| lifecycle_failure("sample native receiver custody clock", error))?
                .ok_or_else(|| {
                    lifecycle_failure("sample native receiver custody clock", "clock unavailable")
                })?;
            Some((verified, received_sample, promotion_sample))
        }
        None => None,
    };
    let outcome = {
        let cache = super::contact_mutable_route_cache(verifier)
            .map_err(|error| lifecycle_failure("bind native Profile-5 route cache", error))?;
        let lifecycle = cache
            .lock_blob_lifecycle()
            .map_err(|error| lifecycle_failure("lock native Profile-5 lifecycle", error))?;
        let promotion = match imported_custody {
            Some((verified, received_sample, promotion_sample)) => store
                .commit_received_profile5_upload_once_with_policy(
                    policy,
                    &reservation,
                    &projected,
                    &publication,
                    aster_redb_store::ReceivedProfile5FinitePromotion::new(
                        verified,
                        received_sample,
                        promotion_sample,
                    ),
                ),
            None => store.commit_received_durable_profile5_upload_once_with_policy(
                policy,
                &reservation,
                &projected,
                &publication,
            ),
        };
        if let Err(error) = &promotion
            && terminal_profile5_promotion_error(error)
        {
            store.abort_blob_upload(&reservation).map_err(|error| {
                lifecycle_failure("abort rejected native Profile-5 promotion", error)
            })?;
        }
        let outcome =
            promotion.map_err(|error| lifecycle_failure("promote native Profile-5 pack", error))?;
        super::cache_authenticated_profile5_blob_route_claim(
            &store,
            &cache,
            verifier,
            outcome.blob(),
            &lifecycle,
        )
        .map_err(|error| lifecycle_failure("cache native Profile-5 publication", error))?;
        outcome
    };
    let promoted_authority = verifier
        .verify_blob_stream_publication_source(&outcome.blob().sealed)
        .map_err(|error| {
            authentication_failure("verify promoted native Profile-5 source", error)
        })?;
    if promoted_authority.publication().authenticated_bytes()
        != authority.publication().authenticated_bytes()
        || promoted_authority.publication().publication().blob_id()
            != authority.physical_commitment().commitment().blob_id()
        || Sha256::digest(&outcome.blob().sealed).as_slice()
            != outcome.blob().transfer_id.as_bytes()
        || *outcome.blob().semantic_id.as_bytes() != transfer_open.publication_id
        || outcome.blob().variant_id != variant
    {
        return Err(authentication_failure(
            "bind promoted native Profile-5 source",
            "promoted semantic publication differs from authenticated transport source",
        ));
    }
    let code = if outcome.inserted() {
        StreamResultCode::Promoted
    } else {
        StreamResultCode::AlreadyPresent
    };
    let digest = canonical_result_digest(&transfer_open, roots);
    let StreamAction::Send(result) = state
        .promoted(code, digest)
        .map_err(|error| settlement_failure("build native Profile-5 result", error))?
    else {
        return Err("native Profile-5 receiver did not produce RESULT".into());
    };
    await_authenticated_progress(
        "send native Profile-5 result",
        attempt.send_control(&codec.encode(result)?),
    )
    .await?;
    let encoded_ack = await_authenticated_progress(
        "receive native Profile-5 result acknowledgement",
        attempt.receive_data(),
    )
    .await?
    .ok_or("data stream closed before native Profile-5 result acknowledgement")?;
    let StreamFrame::ResultAck(ack) = codec.decode(&encoded_ack)? else {
        return Err("native Profile-5 settlement frame was not RESULT_ACK".into());
    };
    if !matches!(
        state
            .result_ack(ack, code)
            .map_err(|error| settlement_failure("settle native Profile-5 receiver", error))?,
        StreamAction::Terminal(settled) if settled == code
    ) {
        return Err("native Profile-5 receiver settlement did not terminate".into());
    }
    if await_authenticated_progress("receive native Profile-5 data EOF", attempt.receive_data())
        .await?
        .is_some()
    {
        return Err("native Profile-5 data stream contained trailing bytes".into());
    }
    await_authenticated_progress(
        "finish native Profile-5 control stream",
        attempt.finish_control(),
    )
    .await?;
    Ok(BlobNetworkReport {
        wire_bytes: wire_len,
        resumed_from,
        attempt_bytes: wire_len.saturating_sub(resumed_from),
        roots,
        checkpoints,
        pipeline: Some(pipeline),
    })
}

/// Sends one already source/content-authenticated canonical publication.
///
/// The capability-bearing `source` is deliberately required in addition to
/// `Store + BlobTransferId`; callers cannot bypass source verification or the
/// completion-gated depot read API.
#[allow(clippy::too_many_arguments)]
pub(crate) async fn send_canonical_blob_profile5(
    adapter: &dyn StreamTransportAdapter,
    store: Arc<Store>,
    policy: &ControlPolicySnapshot,
    source: &CanonicalBlobSendSource,
    session: &mut MissionSession,
    profile_digest: [u8; 32],
    direction: EventDirection,
    attempt_nonce: [u8; 32],
) -> Result<BlobNetworkReport, BlobNetworkError> {
    require_canonical_send_source(&store, policy, source)?;
    Box::pin(send_native_profile5_pack(
        adapter,
        store,
        policy,
        source,
        session,
        profile_digest,
        direction,
        attempt_nonce,
    ))
    .await
}
/// Receives one canonical profile-5 publication and promotes it exclusively
/// through the ordinary pending-source/depot/application authorities.
#[allow(clippy::too_many_arguments)]
pub(crate) async fn receive_canonical_blob_profile5(
    adapter: &dyn StreamTransportAdapter,
    store: Arc<Store>,
    policy: &ControlPolicySnapshot,
    verifier: &mut ReferenceEnvelopeSealer,
    mission: &mut MissionSession,
    profile_digest: [u8; 32],
    direction: EventDirection,
    expected_nonce: [u8; 32],
    offer: &BlobStreamSourceOfferV1,
) -> Result<BlobNetworkReport, BlobNetworkError> {
    // PLAN intentionally discloses no content size. Bound the attempt by the
    // maximum native pack until the authenticated ASTRBO02 open supplies the
    // exact plaintext and wire lengths.
    let profile_ceiling = blob_pack_wire_len(aster_mesh::MAX_BLOB_STREAM_BYTES)
        .map_err(|error| failure("calculate native Profile-5 receive ceiling", error))?;
    let max_segments = usize::try_from(
        aster_mesh::MAX_BLOB_STREAM_BYTES.div_ceil(aster_mesh::BLOB_STREAM_SEGMENT_BYTES as u64),
    )
    .map_err(|_| {
        BlobNetworkError::new(
            BlobNetworkStage::Framing,
            "bound native Profile-5 receive attempt",
            "maximum segment count overflows platform limits",
        )
    })?;
    let (max_data_bytes, max_control_bytes) =
        profile5_attempt_bounds_for_extents(profile_ceiling, max_segments).map_err(|error| {
            BlobNetworkError::new(
                BlobNetworkStage::Framing,
                "bound native Profile-5 receive attempt",
                error,
            )
        })?;
    let attempt = await_authenticated_progress(
        "accept native Profile-5 transport attempt",
        adapter.accept_attempt(AttemptOpenRequest {
            deadline: Instant::now() + profile5_attempt_hard_timeout(profile_ceiling),
            max_data_bytes,
            max_control_bytes,
        }),
    )
    .await?;
    let mut codec = MissionBlobRecordCodec {
        mission,
        profile_digest,
        direction,
        attempt_nonce: expected_nonce,
    };
    let opened_custody = if offer.finite {
        let frame = await_authenticated_progress(
            "receive native Profile-5 custody authority",
            attempt.receive_data(),
        )
        .await?
        .ok_or("data stream closed before native Profile-5 custody authority")?;
        Some(
            codec
                .mission
                .open_blob_custody_frame_v2(profile_digest, direction, expected_nonce, &frame)
                .map_err(|error| {
                    authentication_failure("open native Profile-5 custody authority", error)
                })?,
        )
    } else {
        None
    };
    let custody_received_sample = if opened_custody.is_some() {
        Some(
            super::contact_custody_sample()
                .map_err(|error| lifecycle_failure("sample native custody receipt clock", error))?
                .ok_or_else(|| {
                    lifecycle_failure("sample native custody receipt clock", "clock unavailable")
                })?,
        )
    } else {
        None
    };
    let encoded_open =
        await_authenticated_progress("receive native Profile-5 open", attempt.receive_data())
            .await?
            .ok_or("data stream closed before native Profile-5 open")?;
    let StreamFrame::Open(open) = codec.decode(&encoded_open)? else {
        return Err("first native Profile-5 data frame was not OPEN".into());
    };
    let expected_direction = match direction {
        EventDirection::ToSessionInitiator => StreamDirection::ToSessionInitiator,
        EventDirection::ToSessionResponder => StreamDirection::ToSessionResponder,
    };
    if open.class != StreamClass::Blob
        || open.direction != expected_direction
        || open.session_transcript != codec.mission.session_id()
        || open.exchange_id != 1
        || open.transfer_id != offer.transfer_id
        || open.source_transfer_id != offer.transfer_id
        || open.attempt_nonce != expected_nonce
        || open.source_len != offer.source_len
        || open.source_digest != offer.source_digest
        || (open.custody_digest.is_some() != offer.finite)
    {
        return Err(authentication_failure(
            "validate native Profile-5 OPEN",
            "OPEN differs from acknowledged PLAN/session or durable-source contract",
        ));
    }

    let sealed = receive_authenticated_source(attempt.as_ref(), &mut codec, &open).await?;
    let authority = verifier
        .verify_blob_stream_publication_source(&sealed)
        .map_err(|error| {
            authentication_failure("authenticate native Profile-5 publication source", error)
        })?;
    Box::pin(receive_native_profile5_pack(
        attempt,
        codec,
        store,
        policy,
        verifier,
        open,
        sealed,
        authority,
        offer,
        opened_custody,
        custody_received_sample,
    ))
    .await
}

#[allow(clippy::too_many_arguments)]
#[cfg(any(test, feature = "device-validation"))]
async fn send_completed_pack_inner(
    transport: &dyn StreamTransportAdapter,
    open: &BlobStreamOpen,
    authenticated_open: Vec<u8>,
    root: PackAccess<'_>,
    roots: ([u8; 32], [u8; 32]),
    semantic_commitment: Vec<u8>,
    planned_nonce: Option<[u8; 32]>,
    direction: StreamDirection,
    codec: &mut dyn BlobRecordCodec,
) -> Result<BlobNetworkReport, BlobNetworkError> {
    let wire_len = root.reader(open)?.checkpoint().payload_len();
    if wire_len != expected_pack_wire_len(open.total_len())? {
        return Err(BlobNetworkError::new(
            BlobNetworkStage::Framing,
            "validate completed pack",
            "wire length differs from canonical segment framing",
        ));
    }
    let (max_data_bytes, max_control_bytes) =
        profile5_attempt_bounds(wire_len).map_err(|error| {
            BlobNetworkError::new(BlobNetworkStage::Framing, "bound stream attempt", error)
        })?;
    let attempt = transport
        .open_attempt(AttemptOpenRequest {
            deadline: Instant::now() + PROFILE5_ATTEMPT_TIMEOUT,
            max_data_bytes,
            max_control_bytes,
        })
        .await
        .map_err(|error| transport_failure("open transport attempt", format!("{error:?}")))?;
    let mut attempt_nonce = planned_nonce.unwrap_or([0; 32]);
    if planned_nonce.is_none() {
        getrandom::fill(&mut attempt_nonce)
            .map_err(|error| authentication_failure("attempt nonce", error))?;
    }
    let transfer_open = protocol_open(
        open,
        &authenticated_open,
        wire_len,
        attempt_nonce,
        direction,
    );
    attempt
        .send_data(&codec.encode(StreamFrame::Open(transfer_open.clone()))?)
        .await
        .map_err(|error| transport_failure("send open", format!("{error:?}")))?;
    send_authenticated_source(attempt.as_ref(), codec, &transfer_open, &authenticated_open).await?;
    let accept = attempt
        .receive_control()
        .await
        .map_err(|error| transport_failure("receive accept", format!("{error:?}")))?
        .ok_or("control stream closed before accept")?;
    let StreamFrame::Accept(accept) = codec.decode(&accept)? else {
        return Err("first control frame was not accept".into());
    };
    let resume_offset = accept.durable_offset;
    let mut state = StreamSenderState::new(transfer_open.transfer_id, attempt_nonce, wire_len);
    let accepted = state
        .accept(accept)
        .map_err(|error| failure("accept stream", error))?;
    let mut source = PackExtentSource::new_at(&root, open, resume_offset)?;
    let requires_final_checkpoint = canonical_sender_requires_final_checkpoint(accepted)?;
    let mut pending = if requires_final_checkpoint {
        source.next_extent()?
    } else {
        None
    };
    let mut checkpoints = 0;
    while let Some(extent) = pending.take() {
        match state
            .send_extent(extent)
            .map_err(|error| failure("advance sender extent", error))?
        {
            StreamExtentAction::Send(data) => {
                let (prefix, body) = codec.encode_data_parts(data)?;
                attempt
                    .send_data_parts(&prefix, &body)
                    .await
                    .map_err(|error| transport_failure("send data", format!("{error:?}")))?;
                pending = source.next_extent()?;
            }
            StreamExtentAction::Retry {
                reason: crate::stream_transfer::StreamRetry::CreditBlocked,
                bytes,
            } => {
                let checkpoint = attempt
                    .receive_control()
                    .await
                    .map_err(|error| transport_failure("receive checkpoint", format!("{error:?}")))?
                    .ok_or("control stream closed before checkpoint")?;
                let StreamFrame::Checkpoint(checkpoint) = codec.decode(&checkpoint)? else {
                    return Err("credit wait received a non-checkpoint frame".into());
                };
                state
                    .checkpoint(checkpoint)
                    .map_err(|error| failure("advance sender checkpoint", error))?;
                checkpoints += 1;
                pending = Some(bytes);
            }
            StreamExtentAction::Retry { .. } => {
                return Err("sender produced an invalid extent retry".into());
            }
        }
    }
    if requires_final_checkpoint {
        let checkpoint = attempt
            .receive_control()
            .await
            .map_err(|error| transport_failure("receive final checkpoint", format!("{error:?}")))?
            .ok_or("control stream closed before final checkpoint")?;
        let StreamFrame::Checkpoint(checkpoint) = codec.decode(&checkpoint)? else {
            return Err("final control frame was not checkpoint".into());
        };
        state
            .checkpoint(checkpoint)
            .map_err(|error| failure("advance final sender checkpoint", error))?;
        checkpoints += 1;
    }
    let StreamAction::Send(finish) = state
        .finish(semantic_commitment)
        .map_err(|error| failure("finish sender state", error))?
    else {
        return Err("sender did not produce finish".into());
    };
    attempt
        .send_data(&codec.encode(finish)?)
        .await
        .map_err(|error| transport_failure("send finish", format!("{error:?}")))?;
    let result = attempt
        .receive_control()
        .await
        .map_err(|error| transport_failure("receive result", format!("{error:?}")))?
        .ok_or("control stream closed before result")?;
    let StreamFrame::Result(result) = codec.decode(&result)? else {
        return Err("terminal control frame was not result".into());
    };
    if !matches!(
        result.code,
        StreamResultCode::Promoted | StreamResultCode::AlreadyPresent
    ) || result.result_digest != result_digest(open, roots)
    {
        return Err(settlement_failure(
            "validate receiver result",
            "result did not bind the expected Blob roots",
        ));
    }
    let expected_result = result.code;
    let (StreamAction::Send(ack), StreamAction::Terminal(settled)) = state
        .result(result)
        .map_err(|error| settlement_failure("settle sender state", error))?
    else {
        return Err(settlement_failure(
            "settle sender",
            "settlement action differed",
        ));
    };
    if settled != expected_result {
        return Err(settlement_failure("settle sender", "result code differed"));
    }
    attempt
        .send_data(&codec.encode(ack)?)
        .await
        .map_err(|error| transport_failure("send result acknowledgement", format!("{error:?}")))?;
    attempt
        .finish_data()
        .await
        .map_err(|error| transport_failure("finish data stream", format!("{error:?}")))?;
    if attempt
        .receive_control()
        .await
        .map_err(|error| transport_failure("receive control EOF", format!("{error:?}")))?
        .is_some()
    {
        return Err("control stream contained data after terminal result".into());
    }
    Ok(BlobNetworkReport {
        wire_bytes: wire_len,
        resumed_from: resume_offset,
        attempt_bytes: wire_len - resume_offset,
        roots,
        checkpoints,
        pipeline: None,
    })
}

#[cfg(any(test, feature = "device-validation"))]
struct RecordPartitioner {
    next_index: u64,
    consumed: u64,
    max_record_bytes: usize,
}

#[cfg(any(test, feature = "device-validation"))]
impl RecordPartitioner {
    fn new(next_index: u64, consumed: u64) -> Self {
        Self {
            next_index,
            consumed,
            max_record_bytes: PROFILE5_PACK_SEGMENT_RECORD_BYTES,
        }
    }

    #[cfg(test)]
    fn with_max_record_bytes_for_test(mut self, max_record_bytes: usize) -> Self {
        assert!(
            max_record_bytes > 0 && max_record_bytes <= PROFILE5_PACK_SEGMENT_RECORD_BYTES,
            "test record bound must be within the production limit"
        );
        self.max_record_bytes = max_record_bytes;
        self
    }

    async fn push(
        &mut self,
        bytes: Vec<u8>,
        sender: &mpsc::Sender<Result<StreamPartition, PipelineError>>,
    ) -> Result<(), BlobNetworkError> {
        if bytes.len() < 4 {
            return Err(BlobNetworkError::new(
                BlobNetworkStage::Framing,
                "partition network extent",
                "extent is shorter than its record length",
            ));
        }
        let len = u32::from_be_bytes(bytes[..4].try_into().expect("record length")) as usize;
        if len == 0 || len > self.max_record_bytes {
            return Err(BlobNetworkError::new(
                BlobNetworkStage::Framing,
                "partition network extent",
                "record length is out of bounds",
            ));
        }
        let record_len = 4usize.checked_add(len).ok_or("record length overflow")?;
        if bytes.len() != record_len {
            return Err(BlobNetworkError::new(
                BlobNetworkStage::Framing,
                "partition network extent",
                "extent is not exactly one canonical record",
            ));
        }
        let wire_end = self
            .consumed
            .checked_add(record_len as u64)
            .ok_or("wire offset overflow")?;
        sender
            .send(Ok(StreamPartition::new_at(
                self.next_index,
                wire_end,
                bytes,
            )))
            .await
            .map_err(|_| {
                verification_failure("submit network extent", "verification pipeline closed")
            })?;
        self.next_index += 1;
        self.consumed = wire_end;
        Ok(())
    }

    fn finish(&self, expected: u64) -> Result<(), BlobNetworkError> {
        if self.consumed == expected {
            Ok(())
        } else {
            Err("network stream ended before the complete Blob pack".into())
        }
    }
}

#[derive(Clone)]
#[cfg(any(test, feature = "device-validation"))]
struct DurableProgress {
    wire_offset: u64,
    checkpoint: BlobPackCheckpoint,
}

#[cfg(any(test, feature = "device-validation"))]
async fn send_durable_checkpoint(
    attempt: &std::sync::Arc<dyn crate::stream_transport::StreamReceiveAttempt>,
    state: &mut StreamReceiverState,
    progress: &DurableProgress,
    wire_len: u64,
    current_limit: &mut u64,
    codec: &mut dyn BlobRecordCodec,
) -> Result<(), BlobNetworkError> {
    let new_limit = (*current_limit).max(profile5_receive_limit(
        wire_len,
        progress.wire_offset,
        MAX_STREAM_CHECKPOINT_BATCH_BYTES,
    ));
    let StreamAction::Send(checkpoint) = state
        .persisted(
            progress.wire_offset,
            progress.checkpoint.generation(),
            new_limit,
        )
        .map_err(|error| failure("advance receiver checkpoint", error))?
    else {
        return Err("receiver did not produce checkpoint".into());
    };
    attempt
        .send_control(&codec.encode(checkpoint)?)
        .await
        .map_err(|error| transport_failure("send checkpoint", format!("{error:?}")))?;
    *current_limit = new_limit;
    Ok(())
}

#[cfg(any(test, feature = "device-validation"))]
pub(crate) async fn receive_completed_pack(
    connection: Connection,
    open: &BlobStreamOpen,
    opener: BlobStreamSegmentOpener,
    root: &Path,
    wire_len: u64,
    limits: PipelineLimits,
) -> Result<BlobNetworkReport, BlobNetworkError> {
    let mut codec = PlainBlobRecordCodec;
    let transport = select_production_stream_transport(connection)?;
    receive_completed_pack_inner(
        CompletedPackReceive {
            transport: transport.as_ref(),
            open,
            opener,
            root: PackAccess::Path(root),
            wire_len,
            limits,
            direction: StreamDirection::ToSessionResponder,
        },
        &mut codec,
    )
    .await
}

#[cfg(any(test, feature = "device-validation"))]
struct CompletedPackReceive<'a> {
    transport: &'a dyn StreamTransportAdapter,
    open: &'a BlobStreamOpen,
    opener: BlobStreamSegmentOpener,
    root: PackAccess<'a>,
    wire_len: u64,
    limits: PipelineLimits,
    direction: StreamDirection,
}

#[cfg(any(test, feature = "device-validation"))]
async fn receive_completed_pack_inner(
    context: CompletedPackReceive<'_>,
    codec: &mut dyn BlobRecordCodec,
) -> Result<BlobNetworkReport, BlobNetworkError> {
    let CompletedPackReceive {
        transport,
        open,
        opener,
        root,
        wire_len,
        limits,
        direction,
    } = context;
    let (max_data_bytes, max_control_bytes) =
        profile5_attempt_bounds(wire_len).map_err(|error| {
            BlobNetworkError::new(BlobNetworkStage::Framing, "bound stream attempt", error)
        })?;
    let attempt = transport
        .accept_attempt(AttemptOpenRequest {
            deadline: Instant::now() + PROFILE5_ATTEMPT_TIMEOUT,
            max_data_bytes,
            max_control_bytes,
        })
        .await
        .map_err(|error| transport_failure("accept transport attempt", format!("{error:?}")))?;
    let frame = attempt
        .receive_data()
        .await
        .map_err(|error| transport_failure("receive open", format!("{error:?}")))?
        .ok_or("data stream closed before open")?;
    let StreamFrame::Open(transfer_open) = codec.decode(&frame)? else {
        return Err("first data frame was not open".into());
    };
    receive_authenticated_source(attempt.as_ref(), codec, &transfer_open).await?;
    if transfer_open.class != StreamClass::Blob
        || transfer_open.direction != direction
        || transfer_open.total_len != wire_len
        || transfer_open.session_transcript != open.digest()
        || transfer_open.publication_id != *open.stream_id().as_bytes()
    {
        return Err(authentication_failure(
            "validate transport open",
            "open differs from authenticated Blob open",
        ));
    }
    let resume = BlobStreamResume::default();
    let durable_wire = resume.durable_wire_offset();
    let resumed_from = durable_wire;
    let mut writer = root.projected_writer(open, resume)?;
    let mut current_limit =
        profile5_receive_limit(wire_len, durable_wire, MAX_STREAM_CHECKPOINT_BATCH_BYTES);
    let mut state = StreamReceiverState::new(
        &transfer_open,
        durable_wire,
        resume.generation(),
        current_limit,
        PROFILE5_PACK_TRANSPORT_FRAME_BYTES as u32,
    )
    .map_err(|error| failure("initialize receiver state", error))?;
    let StreamAction::Send(accept) = state
        .accept(MAX_STREAM_CHECKPOINT_BATCH_BYTES)
        .map_err(|error| failure("accept receiver stream", error))?
    else {
        return Err("receiver did not produce accept".into());
    };
    attempt
        .send_control(&codec.encode(accept)?)
        .await
        .map_err(|error| transport_failure("send accept", format!("{error:?}")))?;

    let (partition_tx, partition_rx) = mpsc::channel(limits.max_in_flight_items());
    let (durable_tx, mut durable_rx) = mpsc::unbounded_channel();
    let total_plaintext = open.total_len();
    let stream_job = StreamJobId::from_bytes(
        open.stream_id().as_bytes()[..16]
            .try_into()
            .expect("job ID"),
    );
    let pipeline = Box::pin(async move {
        #[cfg(test)]
        let _lifetime = ReceivePipelineGuard::enter(stream_job);
        let mut last_checkpoint_wire = resume.durable_wire_offset();
        let report = run_ordered_channel_pipeline_from(
            stream_job,
            partition_rx,
            resume.next_segment_index(),
            limits,
            move |partition| {
                let index = partition.index();
                let wire_end = partition.source_end();
                let bytes = partition.into_bytes();
                let (header, _plaintext, leaves) = opener
                    .open_encoded(&bytes[4..])
                    .map_err(|error| PipelineError::MapFailed(error.to_string()))?;
                if header.index() != index {
                    return Err(PipelineError::MapFailed("segment index differs".into()));
                }
                Ok((bytes, header, leaves, wire_end))
            },
            |mapped: MappedPartition<_>| {
                let (record, header, leaves, wire_end) = mapped.into_value();
                let plaintext_end = header.offset() + u64::from(header.plaintext_len());
                let result = writer
                    .append_record(&record[4..], leaves)
                    .map_err(|error| PipelineError::SinkFailed(error.to_string()))
                    .and_then(|()| {
                        if wire_end - last_checkpoint_wire
                            >= u64::from(MAX_STREAM_CHECKPOINT_BATCH_BYTES)
                            || plaintext_end == total_plaintext
                        {
                            let checkpoint = writer
                                .checkpoint()
                                .map_err(|error| PipelineError::SinkFailed(error.to_string()))?;
                            durable_tx
                                .send(DurableProgress {
                                    wire_offset: wire_end,
                                    checkpoint,
                                })
                                .map_err(|_| {
                                    PipelineError::SinkFailed("checkpoint consumer closed".into())
                                })?;
                            last_checkpoint_wire = wire_end;
                        }
                        Ok(())
                    });
                std::future::ready(result)
            },
        )
        .await?;
        let roots = writer
            .finish()
            .map_err(|error| PipelineError::SinkFailed(error.to_string()))?;
        Ok::<_, PipelineError>((report, roots))
    });

    let mut partitioner = RecordPartitioner::new(resume.next_segment_index(), durable_wire);
    let mut received = durable_wire;
    let mut durable_wire = durable_wire;
    let mut checkpoints = 0_u64;
    let receive = Box::pin(async {
        while received < wire_len {
            let frame = attempt
                .receive_data()
                .await
                .map_err(|error| transport_failure("receive data", format!("{error:?}")))?
                .ok_or("data stream closed before completion")?;
            let StreamFrame::Data(data) = codec.decode(&frame)? else {
                return Err("non-data frame before complete payload".into());
            };
            let StreamAction::Persist { through } = state
                .data(&data)
                .map_err(|error| failure("advance receiver data", error))?
            else {
                return Err("receiver did not accept new data".into());
            };
            partitioner.push(data.bytes, &partition_tx).await?;
            received = through;
            if partitioner.consumed - durable_wire >= u64::from(MAX_STREAM_CHECKPOINT_BATCH_BYTES)
                || partitioner.consumed == wire_len
            {
                let progress = durable_rx.recv().await.ok_or_else(|| {
                    verification_failure(
                        "receive durable checkpoint",
                        "verification pipeline closed before checkpoint",
                    )
                })?;
                send_durable_checkpoint(
                    &attempt,
                    &mut state,
                    &progress,
                    wire_len,
                    &mut current_limit,
                    codec,
                )
                .await?;
                durable_wire = progress.wire_offset;
                checkpoints += 1;
            }
        }
        partitioner.finish(wire_len)?;
        drop(partition_tx);
        Ok::<(), BlobNetworkError>(())
    });
    let verify = Box::pin(async move {
        pipeline
            .await
            .map_err(|error| verification_failure("verification pipeline", error))
    });
    let ((), (pipeline, roots)) = tokio::try_join!(receive, verify)?;
    let finish = attempt
        .receive_data()
        .await
        .map_err(|error| transport_failure("receive finish", format!("{error:?}")))?
        .ok_or("data stream closed before finish")?;
    let StreamFrame::Finish(finish) = codec.decode(&finish)? else {
        return Err("terminal data frame was not finish".into());
    };
    let StreamAction::Promote = state
        .finish(finish)
        .map_err(|error| failure("finish receiver state", error))?
    else {
        return Err("receiver did not reach promotion".into());
    };
    let result_code = StreamResultCode::Promoted;
    let digest = result_digest(open, roots);
    let StreamAction::Send(result) = state
        .promoted(result_code, digest)
        .map_err(|error| settlement_failure("record receiver promotion", error))?
    else {
        return Err("receiver did not produce result".into());
    };
    attempt
        .send_control(&codec.encode(result)?)
        .await
        .map_err(|error| transport_failure("send result", format!("{error:?}")))?;
    let ack = attempt
        .receive_data()
        .await
        .map_err(|error| transport_failure("receive result acknowledgement", format!("{error:?}")))?
        .ok_or("data stream closed before result acknowledgement")?;
    let StreamFrame::ResultAck(ack) = codec.decode(&ack)? else {
        return Err("settlement frame was not result acknowledgement".into());
    };
    let StreamAction::Terminal(settled) = state
        .result_ack(ack, result_code)
        .map_err(|error| settlement_failure("settle receiver state", error))?
    else {
        return Err(settlement_failure(
            "settle receiver",
            "settlement action differed",
        ));
    };
    if settled != result_code {
        return Err(settlement_failure(
            "settle receiver",
            "result code differed",
        ));
    }
    finish_receiver_attempt(attempt).await?;
    Ok(BlobNetworkReport {
        wire_bytes: wire_len,
        resumed_from,
        attempt_bytes: wire_len - resumed_from,
        roots,
        checkpoints,
        pipeline: Some(pipeline),
    })
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::mission::{MissionPeerBinding, MissionSessionInitiator, MissionSessionResponder};
    use crate::stream_transport::{
        AdapterFuture, CandidateHealth, StreamAttempt, StreamReceiveAttempt,
        StreamTransportAdapter, StreamTransportCapabilities, StreamTransportError,
        StreamTransportId,
    };
    use crate::{application::blob_stream::publish_blob_stream, stream_pipeline::PipelineLimits};
    use aster_iroh::{CarrierSecurityProfile, Endpoint, EndpointConfig, ExpectedPeer, SecretKey};
    use aster_mesh::{
        BLOB_STREAM_SEGMENT_BYTES, BlobMetadata, BlobPublicationStreamId, BlobStreamOpen,
        BlobStreamSegmentOpener, BlobStreamSegmentSealer, Priority, ProvisioningAccess,
        ProvisioningBundle, ReferenceEnvelopeSealer, ReferenceProvisioner, Scope, Topic,
        VersionVector,
    };
    use std::{
        collections::BTreeSet,
        sync::{
            Arc,
            atomic::{AtomicU64, Ordering},
        },
    };

    static TEMP_SEQUENCE: AtomicU64 = AtomicU64::new(1);

    pub(crate) async fn with_native_profile5_checkpoint_batch<F: Future>(
        bytes: u32,
        future: F,
    ) -> F::Output {
        assert!(bytes > 0);
        TEST_NATIVE_PROFILE5_CHECKPOINT_BATCH_BYTES
            .scope(bytes, future)
            .await
    }

    pub(crate) async fn with_native_profile5_prepromotion_hook<F: Future>(
        hook: Arc<dyn Fn() + Send + Sync>,
        future: F,
    ) -> F::Output {
        TEST_NATIVE_PROFILE5_PREPROMOTION_HOOK
            .scope(hook, future)
            .await
    }

    #[test]
    fn network_error_retains_stage_but_sanitizes_internal_detail() {
        let error = expected_pack_wire_len(u64::MAX).expect_err("wire length must overflow");

        assert_eq!(error.stage(), BlobNetworkStage::Framing);
        assert!(error.to_string().contains("wire length overflow"));
        assert_eq!(error.public_message(), "profile-5 Blob framing failed");
        assert!(!error.public_message().contains("overflow"));
    }

    #[tokio::test(start_paused = true)]
    async fn authenticated_progress_keeps_large_attempt_alive_past_ten_minutes() {
        let started = tokio::time::Instant::now();
        for _ in 0..8 {
            let value = await_authenticated_progress("slow progress", async {
                tokio::time::sleep(std::time::Duration::from_secs(90)).await;
                Ok::<_, StreamTransportError>(())
            })
            .await;
            assert!(value.is_ok());
        }
        assert!(started.elapsed() >= std::time::Duration::from_secs(12 * 60));
    }

    #[tokio::test(start_paused = true)]
    async fn profile5_operations_refresh_the_outer_contact_progress_deadline() {
        let result = super::super::with_authenticated_contact_progress_deadline(async {
            for _ in 0..4 {
                await_authenticated_progress("outer contact progress", async {
                    tokio::time::sleep(
                        super::super::CONTACT_DEADLINE - std::time::Duration::from_secs(1),
                    )
                    .await;
                    Ok::<_, StreamTransportError>(())
                })
                .await?;
            }
            Ok::<_, BlobNetworkError>(())
        })
        .await;

        assert!(matches!(result, Ok(Ok(()))));
    }

    #[tokio::test(start_paused = true)]
    async fn single_profile5_operation_may_use_its_idle_timeout() {
        let result = super::super::with_authenticated_contact_progress_deadline(async {
            await_authenticated_progress("slow valid operation", async {
                tokio::time::sleep(
                    super::super::CONTACT_DEADLINE + std::time::Duration::from_secs(1),
                )
                .await;
                Ok::<_, StreamTransportError>(())
            })
            .await
        })
        .await;

        assert!(matches!(result, Ok(Ok(()))));
    }

    #[tokio::test(start_paused = true)]
    async fn stalled_authenticated_transfer_times_out_retryably() {
        let error = await_authenticated_progress("stalled progress", async {
            std::future::pending::<Result<(), StreamTransportError>>().await
        })
        .await
        .expect_err("idle transfer must time out");
        assert_eq!(error.stage(), BlobNetworkStage::Transport);
        assert!(error.to_string().contains("idle timeout"));
    }

    pub(crate) fn mission_pair_from_bundles(
        initiator_bytes: &[u8],
        responder_bytes: &[u8],
    ) -> (MissionSession, MissionSession, [u8; 32]) {
        let initiator_identity =
            ReferenceEnvelopeSealer::open(ProvisioningBundle::from_bytes(initiator_bytes).unwrap())
                .unwrap()
                .identity();
        let responder_identity =
            ReferenceEnvelopeSealer::open(ProvisioningBundle::from_bytes(responder_bytes).unwrap())
                .unwrap()
                .identity();
        let initiator_carrier = SecretKey::generate();
        let responder_carrier = SecretKey::generate();
        let (initiator, first) = MissionSessionInitiator::start(
            ProvisioningBundle::from_bytes(initiator_bytes).unwrap(),
            MissionPeerBinding::new(responder_carrier.public(), responder_identity),
            responder_carrier.public(),
        )
        .unwrap();
        let responder = MissionSessionResponder::open(
            ProvisioningBundle::from_bytes(responder_bytes).unwrap(),
            MissionPeerBinding::new(initiator_carrier.public(), initiator_identity),
            initiator_carrier.public(),
        )
        .unwrap();
        let (responder, second) = responder.receive_client(first.as_bytes()).unwrap();
        let (initiator, third) = initiator.receive_server(second.as_bytes()).unwrap();
        let (mut responder, fourth) = responder.receive_client_auth(third.as_bytes()).unwrap();
        let mut initiator = initiator.receive_finished(fourth.as_bytes()).unwrap();

        let offer = crate::event_pages::TransferProfileOfferV1::for_semantic_version(9).unwrap();
        let initiator_offer = initiator.seal_transfer_profile_offer(&offer).unwrap();
        responder
            .open_transfer_profile_offer(&initiator_offer)
            .unwrap();
        let responder_offer = responder.seal_transfer_profile_offer(&offer).unwrap();
        initiator
            .open_transfer_profile_offer(&responder_offer)
            .unwrap();
        let negotiated = crate::event_pages::negotiate_transfer_profiles(&offer, &offer).unwrap();
        let digest = crate::event_pages::transfer_profile_digest(&offer, &offer, &negotiated);
        (initiator, responder, digest)
    }

    fn mission_pair() -> (MissionSession, MissionSession, [u8; 32]) {
        let scope = Scope::new("mission/alpha").unwrap();
        let access =
            ProvisioningAccess::member(scope, vec![1], vec![Topic::new("imagery").unwrap()])
                .unwrap();
        let mut provisioner = ReferenceProvisioner::from_seed([0xc1; 32]).unwrap();
        let initiator_bytes = provisioner
            .issue_node(1, std::slice::from_ref(&access))
            .unwrap()
            .to_bytes()
            .unwrap();
        let responder_bytes = provisioner
            .issue_node(2, &[access])
            .unwrap()
            .to_bytes()
            .unwrap();
        mission_pair_from_bundles(&initiator_bytes, &responder_bytes)
    }

    fn native_profile5_test_record(plaintext_len: usize) -> Vec<u8> {
        let stream_id = [0xe1; 32];
        let open_digest = [0xe2; 32];
        let sealer = BlobStreamSegmentSealer::from_test_key(
            stream_id,
            open_digest,
            1,
            [0xe3; 32],
            [0xe4; 12],
        );
        let partition = aster_mesh::BlobStreamPlainPartition::new(
            stream_id,
            open_digest,
            1,
            0,
            0,
            plaintext_len as u64,
            vec![0xe5; plaintext_len],
        )
        .expect("native Profile-5 partition");
        let (segment, _) = sealer
            .seal(partition)
            .expect("seal native Profile-5 segment");
        let segment = segment.encode();
        let mut record = Vec::with_capacity(4 + segment.len());
        record.extend_from_slice(&(segment.len() as u32).to_be_bytes());
        record.extend_from_slice(&segment);
        record
    }

    fn decode_mission_data_body(body: Vec<u8>) -> Result<StreamFrame, BlobNetworkError> {
        let (mut sender, mut receiver, profile_digest) = mission_pair();
        let attempt_nonce = [0xe6; 32];
        let data = crate::stream_transfer::StreamDataV1 {
            transfer_id: [0xe7; 32],
            attempt_nonce,
            sequence: 0,
            offset: 0,
            bytes: body,
        };
        let (header, body) = data.into_header_and_body().expect("split test DATA");
        let header = header
            .encode_for_context(9, TransferProfileId::BlobStreamV1 as u16)
            .expect("encode test DATA header");
        let protected_header = sender
            .seal_v9_blob_data_header(
                profile_digest,
                EventDirection::ToSessionResponder,
                attempt_nonce,
                &header,
            )
            .expect("protect test DATA header");
        let mut encoded =
            encode_composite_data_prefix(&protected_header).expect("encode test composite prefix");
        encoded.extend_from_slice(&body);
        MissionBlobRecordCodec {
            mission: &mut receiver,
            profile_digest,
            direction: EventDirection::ToSessionResponder,
            attempt_nonce,
        }
        .decode(&encoded)
    }

    #[test]
    fn production_mission_codec_requires_exactly_one_native_profile5_record() {
        let exact = native_profile5_test_record(17);
        let decoded = decode_mission_data_body(exact.clone()).expect("one complete native record");
        assert!(matches!(decoded, StreamFrame::Data(_)));

        let mut coalesced = exact.clone();
        coalesced.extend_from_slice(&exact);
        let mut zero_length = exact.clone();
        zero_length[..4].copy_from_slice(&0_u32.to_be_bytes());
        let mut wrong_length = exact.clone();
        wrong_length[..4].copy_from_slice(&((exact.len() - 5) as u32).to_be_bytes());
        let mut trailing = exact.clone();
        trailing.push(0xff);

        for (case, body) in [
            ("fragmented", exact[..exact.len() - 1].to_vec()),
            ("coalesced", coalesced),
            ("zero-length", zero_length),
            ("wrong-length", wrong_length),
            ("trailing", trailing),
        ] {
            let error = decode_mission_data_body(body)
                .expect_err("malformed native Profile-5 DATA body must fail");
            assert_eq!(error.stage(), BlobNetworkStage::Framing, "{case}");
        }
    }

    #[test]
    fn fully_checkpointed_runtime_retry_settles_exactly_once() {
        let transfer_id = [0x51; 32];
        let attempt_nonce = [0x52; 32];
        let total = 1024;
        let mut sender = StreamSenderState::new(transfer_id, attempt_nonce, total);

        let action = sender
            .accept(crate::stream_transfer::StreamAcceptV1 {
                transfer_id,
                attempt_nonce,
                sequence: 0,
                durable_offset: total,
                checkpoint_generation: 9,
                absolute_receive_limit: total,
                max_extent_bytes: PROFILE5_PACK_TRANSPORT_FRAME_BYTES as u32,
                checkpoint_batch_bytes: MAX_STREAM_CHECKPOINT_BATCH_BYTES,
            })
            .expect("fully checkpointed ACCEPT");

        assert_eq!(action, StreamAction::SendFinish);
        assert!(!canonical_sender_requires_final_checkpoint(action).unwrap());
    }

    #[test]
    fn maximum_source_and_native_profile5_record_fit_iroh_frames() {
        let (mut sender, mut receiver, profile_digest) = mission_pair();
        let attempt_nonce = [0x61; 32];
        let source = vec![0x5a; crate::stream_transfer::MAX_STREAM_AUTHENTICATED_OPEN_BYTES];
        let source_digest = Sha256::digest(&source).into();
        let source_len = u32::try_from(source.len()).unwrap();
        let plan = crate::frame::Frame::BlobStreamPlan {
            direction: EventDirection::ToSessionResponder,
            attempt_nonce: Some(attempt_nonce),
            source: Some(crate::frame::BlobStreamSourceOfferV1 {
                transfer_id: [0x62; 32],
                topic: Topic::new("imagery").unwrap(),
                scope: Scope::new("mission/alpha").unwrap(),
                key_epoch: 1,
                content_proof: [0x65; crate::frame::BLOB_CONTENT_PROOF_BYTES],
                source_len,
                source_digest,
                finite: false,
            }),
        }
        .encode_for_semantic_version(9)
        .expect("bounded production plan");
        let protected_plan = sender.seal_application_frame(&plan).expect("protect plan");
        assert!(protected_plan.len() <= aster_iroh::DEFAULT_MAX_EXCHANGE_BYTES);
        assert_eq!(
            receiver.open_application_frame(&protected_plan).unwrap(),
            plan
        );

        let open = StreamOpenV1 {
            class: StreamClass::Blob,
            direction: StreamDirection::ToSessionResponder,
            session_transcript: sender.session_id(),
            exchange_id: 1,
            transfer_id: [0x62; 32],
            source_transfer_id: [0x62; 32],
            publication_id: [0x63; 32],
            variant_id: [0x64; 32],
            total_len: 8 * 1024 * 1024 * 1024,
            attempt_nonce,
            checkpoint_generation: 0,
            custody_digest: None,
            source_len,
            source_digest,
        };
        let mut send_codec = MissionBlobRecordCodec {
            mission: &mut sender,
            profile_digest,
            direction: EventDirection::ToSessionResponder,
            attempt_nonce,
        };
        let protected_open = send_codec
            .encode(StreamFrame::Open(open.clone()))
            .expect("protect open");
        assert!(protected_open.len() <= aster_iroh::DEFAULT_MAX_EXCHANGE_BYTES);

        let mut protected_sources = Vec::new();
        for (sequence, chunk) in source
            .chunks(crate::stream_transfer::PROFILE5_SOURCE_CHUNK_BYTES)
            .enumerate()
        {
            let offset =
                u32::try_from(sequence * crate::stream_transfer::PROFILE5_SOURCE_CHUNK_BYTES)
                    .unwrap();
            let protected = send_codec
                .encode(StreamFrame::Source(
                    crate::stream_transfer::StreamSourceV1 {
                        transfer_id: open.transfer_id,
                        attempt_nonce,
                        sequence: sequence as u64,
                        offset,
                        total_len: source_len,
                        bytes: chunk.to_vec(),
                    },
                ))
                .expect("protect source chunk");
            assert!(protected.len() <= aster_iroh::DEFAULT_MAX_EXCHANGE_BYTES);
            assert!(protected.len() + 4 <= aster_iroh::DEFAULT_MAX_EXCHANGE_BYTES + 4);
            protected_sources.push(protected);
        }

        let stream_id = [0x63; 32];
        let open_digest = [0x66; 32];
        let sealer = aster_mesh::BlobStreamSegmentSealer::from_test_key(
            stream_id,
            open_digest,
            1,
            [0x67; 32],
            [0x68; 12],
        );
        let partition = aster_mesh::BlobStreamPlainPartition::new(
            stream_id,
            open_digest,
            1,
            0,
            0,
            aster_mesh::BLOB_STREAM_SEGMENT_BYTES as u64,
            vec![0xa5; aster_mesh::BLOB_STREAM_SEGMENT_BYTES],
        )
        .expect("maximum native partition");
        let (segment, _) = sealer.seal(partition).expect("seal native segment");
        let segment = segment.encode();
        let mut record = Vec::with_capacity(4 + segment.len());
        record.extend_from_slice(&(segment.len() as u32).to_be_bytes());
        record.extend_from_slice(&segment);
        assert_eq!(record.len(), PROFILE5_PACK_TRANSPORT_FRAME_BYTES);
        let data = crate::stream_transfer::StreamDataV1 {
            transfer_id: open.transfer_id,
            attempt_nonce,
            sequence: protected_sources.len() as u64,
            offset: 0,
            bytes: record.clone(),
        };
        let (prefix, body) = send_codec
            .encode_data_parts(data)
            .expect("protect data extent");
        assert!(prefix.len() + body.len() <= aster_iroh::DEFAULT_MAX_EXCHANGE_BYTES);
        assert!(prefix.len() + body.len() + 4 <= aster_iroh::DEFAULT_MAX_EXCHANGE_BYTES + 4);

        let mut receive_codec = MissionBlobRecordCodec {
            mission: &mut receiver,
            profile_digest,
            direction: EventDirection::ToSessionResponder,
            attempt_nonce,
        };
        assert_eq!(
            receive_codec.decode(&protected_open).unwrap(),
            StreamFrame::Open(open)
        );
        for protected in protected_sources {
            assert!(matches!(
                receive_codec.decode(&protected).unwrap(),
                StreamFrame::Source(_)
            ));
        }
        let mut emitted = prefix;
        emitted.extend_from_slice(&body);
        let StreamFrame::Data(decoded) = receive_codec.decode(&emitted).unwrap() else {
            panic!("production data frame decoded as another kind");
        };
        assert_eq!(decoded.bytes, record);
        let declared = u32::from_be_bytes(decoded.bytes[..4].try_into().unwrap()) as usize;
        assert_eq!(declared, decoded.bytes.len() - 4);
        let decoded_segment =
            aster_mesh::EncryptedBlobStreamSegment::decode(&decoded.bytes[4..]).unwrap();
        assert_eq!(decoded_segment.index(), 0);
        assert_eq!(decoded_segment.offset(), 0);
    }

    #[test]
    fn mission_data_record_protects_only_the_canonical_header() {
        let (mut sender, mut receiver, profile_digest) = mission_pair();
        let nonce = [0xc2; 32];
        let body = native_profile5_test_record(32);
        let frame = StreamFrame::Data(crate::stream_transfer::StreamDataV1 {
            transfer_id: [0xc4; 32],
            attempt_nonce: nonce,
            sequence: 0,
            offset: 0,
            bytes: body.clone(),
        });
        let mut sender_codec = MissionBlobRecordCodec {
            mission: &mut sender,
            profile_digest,
            direction: EventDirection::ToSessionResponder,
            attempt_nonce: nonce,
        };
        let encoded = sender_codec.encode(frame.clone()).unwrap();

        assert_eq!(&encoded[encoded.len() - body.len()..], body);
        assert!(
            encoded.len()
                < body.len() + crate::stream_transfer::MAX_PROTECTED_STREAM_DATA_HEADER_BYTES
        );

        let mut receiver_codec = MissionBlobRecordCodec {
            mission: &mut receiver,
            profile_digest,
            direction: EventDirection::ToSessionResponder,
            attempt_nonce: nonce,
        };
        assert_eq!(receiver_codec.decode(&encoded).unwrap(), frame);
    }

    #[cfg(feature = "fuzzing")]
    #[test]
    fn deterministic_profile5_fuzz_header_fixture_matches_production_codec() {
        for (seed, fixture) in [
            (
                include_bytes!(
                    "../../../../fuzz/corpus/stream_transfer_decode/profile5-composite-valid.bin"
                )
                .as_slice(),
                include_bytes!("../../../../conformance/profile5-protected-data-header.bin")
                    .as_slice(),
            ),
            (
                include_bytes!(
                    "../../../../fuzz/corpus/stream_transfer_decode/profile5-composite-maximum.bin"
                )
                .as_slice(),
                include_bytes!(
                    "../../../../conformance/profile5-protected-data-header-maximum.bin"
                )
                .as_slice(),
            ),
        ] {
            let (_, extent) = crate::stream_transfer::split_composite_data_record(seed).unwrap();
            let protected = super::fuzz_protect_profile5_data_extent(extent.to_vec()).unwrap();
            let (header, _) =
                crate::stream_transfer::split_composite_data_record(&protected).unwrap();
            assert!(header.starts_with(b"ASTRFR01"));
            assert_eq!(header, fixture);
        }
    }

    #[test]
    fn plain_data_framing_moves_the_canonical_record_allocation() {
        let body = native_profile5_test_record(32);
        let allocation = body.as_ptr();
        let data = crate::stream_transfer::StreamDataV1 {
            transfer_id: [0xc4; 32],
            attempt_nonce: [0xc2; 32],
            sequence: 0,
            offset: 0,
            bytes: body,
        };

        let (header, body) = PlainBlobRecordCodec
            .encode_data_parts(data)
            .expect("split data frame");

        assert_eq!(
            header.len(),
            crate::stream_transfer::STREAM_DATA_FIXED_BYTES
        );
        assert_eq!(body.as_ptr(), allocation);
    }

    #[test]
    fn wrong_mission_direction_is_an_authentication_failure() {
        let (mut sender, mut receiver, profile_digest) = mission_pair();
        let nonce = [0xc8; 32];
        let frame = StreamFrame::Data(crate::stream_transfer::StreamDataV1 {
            transfer_id: [0xc9; 32],
            attempt_nonce: nonce,
            sequence: 0,
            offset: 0,
            bytes: native_profile5_test_record(32),
        });
        let encoded = MissionBlobRecordCodec {
            mission: &mut sender,
            profile_digest,
            direction: EventDirection::ToSessionResponder,
            attempt_nonce: nonce,
        }
        .encode(frame)
        .unwrap();
        let error = MissionBlobRecordCodec {
            mission: &mut receiver,
            profile_digest,
            direction: EventDirection::ToSessionInitiator,
            attempt_nonce: nonce,
        }
        .decode(&encoded)
        .expect_err("wrong mission direction must fail");

        assert_eq!(error.stage(), BlobNetworkStage::Authentication);
        assert_eq!(
            error.public_message(),
            "profile-5 Blob authentication failed"
        );
    }

    #[test]
    fn mission_codec_rejects_a_fully_wrapped_data_record() {
        let (mut sender, mut receiver, profile_digest) = mission_pair();
        let nonce = [0xc5; 32];
        let frame = StreamFrame::Data(crate::stream_transfer::StreamDataV1 {
            transfer_id: [0xc6; 32],
            attempt_nonce: nonce,
            sequence: 0,
            offset: 0,
            bytes: vec![0xc7; 32],
        });
        let plaintext = frame.encode_for_context(9, 5).unwrap();
        let fully_wrapped = sender
            .seal_v9_blob_application_frame(
                profile_digest,
                EventDirection::ToSessionResponder,
                nonce,
                &plaintext,
            )
            .unwrap();
        let mut receiver_codec = MissionBlobRecordCodec {
            mission: &mut receiver,
            profile_digest,
            direction: EventDirection::ToSessionResponder,
            attempt_nonce: nonce,
        };

        assert!(receiver_codec.decode(&fully_wrapped).is_err());
    }

    #[test]
    #[ignore = "explicit 256 MiB profile-5 composite-record measurement"]
    fn composite_profile5_records_process_256_mib_in_bounded_extents() {
        const TOTAL: u64 = 256 * 1024 * 1024;
        let (mut sender, mut receiver, profile_digest) = mission_pair();
        let nonce = [0xd1; 32];
        let mut sender_codec = MissionBlobRecordCodec {
            mission: &mut sender,
            profile_digest,
            direction: EventDirection::ToSessionResponder,
            attempt_nonce: nonce,
        };
        let mut receiver_codec = MissionBlobRecordCodec {
            mission: &mut receiver,
            profile_digest,
            direction: EventDirection::ToSessionResponder,
            attempt_nonce: nonce,
        };
        let started = std::time::Instant::now();
        let record = native_profile5_test_record(BLOB_STREAM_SEGMENT_BYTES);
        let mut offset = 0_u64;
        let mut sequence = 0_u64;
        while offset < TOTAL {
            let frame = StreamFrame::Data(crate::stream_transfer::StreamDataV1 {
                transfer_id: [0xd3; 32],
                attempt_nonce: nonce,
                sequence,
                offset,
                bytes: record.clone(),
            });
            let protected = sender_codec.encode(frame).unwrap();
            std::hint::black_box(receiver_codec.decode(&protected).unwrap());
            offset += record.len() as u64;
            sequence += 1;
        }
        let elapsed = started.elapsed();
        let mib_per_second = TOTAL as f64 / (1024.0 * 1024.0) / elapsed.as_secs_f64();
        eprintln!(
            "composite_profile5_record_benchmark bytes={TOTAL} extents={sequence} elapsed_ns={} mib_per_second={mib_per_second:.3}",
            elapsed.as_nanos()
        );
    }

    struct TerminalReceiveAttempt {
        events: std::sync::Mutex<Vec<&'static str>>,
    }

    struct MemorySenderAttempt {
        data: mpsc::UnboundedSender<Option<Vec<u8>>>,
        control: tokio::sync::Mutex<mpsc::UnboundedReceiver<Option<Vec<u8>>>>,
        pending_data_send: Option<(Arc<tokio::sync::Semaphore>, usize)>,
        data_frames_sent: Arc<std::sync::atomic::AtomicUsize>,
        data_part_body_lengths: Arc<std::sync::Mutex<Vec<usize>>>,
    }

    struct SmallMtuSenderAttempt {
        data: mpsc::UnboundedSender<Option<Vec<u8>>>,
        control: tokio::sync::Mutex<mpsc::UnboundedReceiver<Option<Vec<u8>>>>,
    }

    impl StreamAttempt for SmallMtuSenderAttempt {
        fn send_data<'a>(&'a self, frame: &'a [u8]) -> AdapterFuture<'a, ()> {
            Box::pin(async move {
                let mut reassembled = Vec::with_capacity(frame.len());
                for fragment in frame.chunks(3) {
                    reassembled.extend_from_slice(fragment);
                }
                self.data
                    .send(Some(reassembled))
                    .map_err(|_| StreamTransportError::Closed)
            })
        }

        fn send_data_parts<'a>(
            &'a self,
            prefix: &'a [u8],
            body: &'a [u8],
        ) -> AdapterFuture<'a, ()> {
            Box::pin(async move {
                let mut frame = Vec::with_capacity(prefix.len() + body.len());
                frame.extend_from_slice(prefix);
                frame.extend_from_slice(body);
                self.send_data(&frame).await
            })
        }

        fn receive_control(&self) -> AdapterFuture<'_, Option<Vec<u8>>> {
            Box::pin(async move { Ok(self.control.lock().await.recv().await.flatten()) })
        }

        fn finish_data(&self) -> AdapterFuture<'_, ()> {
            Box::pin(async move {
                self.data
                    .send(None)
                    .map_err(|_| StreamTransportError::Closed)
            })
        }

        fn cancel_data(&self) {
            let _ = self.data.send(None);
        }
    }

    impl StreamAttempt for MemorySenderAttempt {
        fn send_data<'a>(&'a self, frame: &'a [u8]) -> AdapterFuture<'a, ()> {
            Box::pin(async move {
                self.data_frames_sent.fetch_add(1, Ordering::SeqCst);
                self.data
                    .send(Some(frame.to_vec()))
                    .map_err(|_| StreamTransportError::Closed)
            })
        }

        fn send_data_parts<'a>(
            &'a self,
            prefix: &'a [u8],
            body: &'a [u8],
        ) -> AdapterFuture<'a, ()> {
            Box::pin(async move {
                self.data_frames_sent.fetch_add(1, Ordering::SeqCst);
                let data_parts_sent = {
                    let mut lengths = self
                        .data_part_body_lengths
                        .lock()
                        .unwrap_or_else(std::sync::PoisonError::into_inner);
                    lengths.push(body.len());
                    lengths.len()
                };
                if let Some((entered, send_before_pending)) = &self.pending_data_send
                    && data_parts_sent > *send_before_pending
                {
                    entered.add_permits(1);
                    std::future::pending::<()>().await;
                }
                let mut frame = Vec::with_capacity(prefix.len() + body.len());
                frame.extend_from_slice(prefix);
                frame.extend_from_slice(body);
                self.data
                    .send(Some(frame))
                    .map_err(|_| StreamTransportError::Closed)
            })
        }

        fn receive_control(&self) -> AdapterFuture<'_, Option<Vec<u8>>> {
            Box::pin(async move { Ok(self.control.lock().await.recv().await.flatten()) })
        }

        fn finish_data(&self) -> AdapterFuture<'_, ()> {
            Box::pin(async move {
                self.data
                    .send(None)
                    .map_err(|_| StreamTransportError::Closed)
            })
        }

        fn cancel_data(&self) {
            let _ = self.data.send(None);
        }
    }

    struct MemoryReceiverAttempt {
        data: tokio::sync::Mutex<mpsc::UnboundedReceiver<Option<Vec<u8>>>>,
        control: mpsc::UnboundedSender<Option<Vec<u8>>>,
        fail_after_receives: Option<usize>,
        receives: std::sync::atomic::AtomicUsize,
    }

    impl StreamReceiveAttempt for MemoryReceiverAttempt {
        fn receive_data(&self) -> AdapterFuture<'_, Option<Vec<u8>>> {
            Box::pin(async move {
                let receive = self.receives.fetch_add(1, Ordering::SeqCst);
                if self
                    .fail_after_receives
                    .is_some_and(|limit| receive >= limit)
                {
                    let _ = self.control.send(None);
                    return Err(StreamTransportError::Closed);
                }
                Ok(self.data.lock().await.recv().await.flatten())
            })
        }

        fn send_control<'a>(&'a self, frame: &'a [u8]) -> AdapterFuture<'a, ()> {
            Box::pin(async move {
                self.control
                    .send(Some(frame.to_vec()))
                    .map_err(|_| StreamTransportError::Closed)
            })
        }

        fn finish_control(&self) -> AdapterFuture<'_, ()> {
            Box::pin(async move {
                self.control
                    .send(None)
                    .map_err(|_| StreamTransportError::Closed)
            })
        }
    }

    pub(crate) struct MemoryTransportAdapter {
        sender: Arc<MemorySenderAttempt>,
        receiver: Arc<MemoryReceiverAttempt>,
    }

    pub(crate) struct PendingDataSendControl {
        entered: Arc<tokio::sync::Semaphore>,
    }

    impl PendingDataSendControl {
        pub(crate) async fn wait_entered(&self) {
            self.entered
                .acquire()
                .await
                .expect("pending DATA sender remains open")
                .forget();
        }
    }

    impl MemoryTransportAdapter {
        pub(crate) fn new() -> Self {
            Self::with_receive_failure(None)
        }

        pub(crate) fn with_receive_failure(fail_after_receives: Option<usize>) -> Self {
            let (data_send, data_receive) = mpsc::unbounded_channel();
            let (control_send, control_receive) = mpsc::unbounded_channel();
            Self {
                sender: Arc::new(MemorySenderAttempt {
                    data: data_send,
                    control: tokio::sync::Mutex::new(control_receive),
                    pending_data_send: None,
                    data_frames_sent: Arc::new(std::sync::atomic::AtomicUsize::new(0)),
                    data_part_body_lengths: Arc::new(std::sync::Mutex::new(Vec::new())),
                }),
                receiver: Arc::new(MemoryReceiverAttempt {
                    data: tokio::sync::Mutex::new(data_receive),
                    control: control_send,
                    fail_after_receives,
                    receives: std::sync::atomic::AtomicUsize::new(0),
                }),
            }
        }

        pub(crate) fn with_pending_data_send() -> (Self, PendingDataSendControl) {
            let (data_send, data_receive) = mpsc::unbounded_channel();
            let (control_send, control_receive) = mpsc::unbounded_channel();
            let entered = Arc::new(tokio::sync::Semaphore::new(0));
            let control = PendingDataSendControl {
                entered: Arc::clone(&entered),
            };
            (
                Self {
                    sender: Arc::new(MemorySenderAttempt {
                        data: data_send,
                        control: tokio::sync::Mutex::new(control_receive),
                        pending_data_send: Some((entered, 1)),
                        data_frames_sent: Arc::new(std::sync::atomic::AtomicUsize::new(0)),
                        data_part_body_lengths: Arc::new(std::sync::Mutex::new(Vec::new())),
                    }),
                    receiver: Arc::new(MemoryReceiverAttempt {
                        data: tokio::sync::Mutex::new(data_receive),
                        control: control_send,
                        fail_after_receives: None,
                        receives: std::sync::atomic::AtomicUsize::new(0),
                    }),
                },
                control,
            )
        }

        pub(crate) fn data_part_body_lengths(&self) -> Vec<usize> {
            self.sender
                .data_part_body_lengths
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .clone()
        }

        pub(crate) fn data_frames_sent(&self) -> usize {
            self.sender.data_frames_sent.load(Ordering::SeqCst)
        }
    }

    impl StreamTransportAdapter for MemoryTransportAdapter {
        fn id(&self) -> StreamTransportId {
            StreamTransportId::IROH_QUIC_V1
        }

        fn capabilities(&self) -> StreamTransportCapabilities {
            StreamTransportCapabilities {
                reliable_ordered: true,
                full_duplex: true,
            }
        }

        fn health(&self) -> CandidateHealth {
            CandidateHealth::Healthy
        }

        fn open_attempt<'a>(
            &'a self,
            _request: AttemptOpenRequest,
        ) -> AdapterFuture<'a, Arc<dyn StreamAttempt>> {
            let sender = Arc::clone(&self.sender);
            Box::pin(async move { Ok(sender as Arc<dyn StreamAttempt>) })
        }

        fn accept_attempt<'a>(
            &'a self,
            _request: AttemptOpenRequest,
        ) -> AdapterFuture<'a, Arc<dyn StreamReceiveAttempt>> {
            let receiver = Arc::clone(&self.receiver);
            Box::pin(async move { Ok(receiver as Arc<dyn StreamReceiveAttempt>) })
        }
    }

    pub(crate) struct SmallMtuTransportAdapter {
        sender: Arc<SmallMtuSenderAttempt>,
        receiver: Arc<MemoryReceiverAttempt>,
    }

    impl SmallMtuTransportAdapter {
        pub(crate) fn with_receive_failure(fail_after_receives: usize) -> Self {
            let (data_send, data_receive) = mpsc::unbounded_channel();
            let (control_send, control_receive) = mpsc::unbounded_channel();
            Self {
                sender: Arc::new(SmallMtuSenderAttempt {
                    data: data_send,
                    control: tokio::sync::Mutex::new(control_receive),
                }),
                receiver: Arc::new(MemoryReceiverAttempt {
                    data: tokio::sync::Mutex::new(data_receive),
                    control: control_send,
                    fail_after_receives: Some(fail_after_receives),
                    receives: std::sync::atomic::AtomicUsize::new(0),
                }),
            }
        }
    }

    impl StreamTransportAdapter for SmallMtuTransportAdapter {
        fn id(&self) -> StreamTransportId {
            StreamTransportId::IROH_QUIC_V1
        }

        fn capabilities(&self) -> StreamTransportCapabilities {
            StreamTransportCapabilities {
                reliable_ordered: true,
                full_duplex: true,
            }
        }

        fn health(&self) -> CandidateHealth {
            CandidateHealth::Degraded
        }

        fn open_attempt<'a>(
            &'a self,
            _request: AttemptOpenRequest,
        ) -> AdapterFuture<'a, Arc<dyn StreamAttempt>> {
            let sender = Arc::clone(&self.sender);
            Box::pin(async move { Ok(sender as Arc<dyn StreamAttempt>) })
        }

        fn accept_attempt<'a>(
            &'a self,
            _request: AttemptOpenRequest,
        ) -> AdapterFuture<'a, Arc<dyn StreamReceiveAttempt>> {
            let receiver = Arc::clone(&self.receiver);
            Box::pin(async move { Ok(receiver as Arc<dyn StreamReceiveAttempt>) })
        }
    }

    #[tokio::test]
    async fn authenticated_source_reassembly_binds_order_length_and_digest() {
        const TEST_SOURCE_CHUNK_BYTES: usize = 128;

        fn receiver_with(frames: Vec<Vec<u8>>) -> Arc<MemoryReceiverAttempt> {
            let (data, receive) = mpsc::unbounded_channel();
            for frame in frames {
                data.send(Some(frame)).unwrap();
            }
            let (control, _control_receive) = mpsc::unbounded_channel();
            Arc::new(MemoryReceiverAttempt {
                data: tokio::sync::Mutex::new(receive),
                control,
                fail_after_receives: None,
                receives: std::sync::atomic::AtomicUsize::new(0),
            })
        }

        let source = vec![0x91; TEST_SOURCE_CHUNK_BYTES + 3];
        let open = StreamOpenV1 {
            class: StreamClass::Blob,
            direction: StreamDirection::ToSessionResponder,
            session_transcript: [0x92; 32],
            exchange_id: 1,
            transfer_id: [0x93; 32],
            source_transfer_id: [0x93; 32],
            publication_id: [0x94; 32],
            variant_id: [0x95; 32],
            total_len: 0,
            attempt_nonce: [0x96; 32],
            checkpoint_generation: 0,
            custody_digest: None,
            source_len: source.len() as u32,
            source_digest: Sha256::digest(&source).into(),
        };
        let frames = source
            .chunks(TEST_SOURCE_CHUNK_BYTES)
            .enumerate()
            .map(|(sequence, bytes)| {
                encoded(StreamFrame::Source(
                    crate::stream_transfer::StreamSourceV1 {
                        transfer_id: open.transfer_id,
                        attempt_nonce: open.attempt_nonce,
                        sequence: sequence as u64,
                        offset: (sequence * TEST_SOURCE_CHUNK_BYTES) as u32,
                        total_len: open.source_len,
                        bytes: bytes.to_vec(),
                    },
                ))
                .unwrap()
            })
            .collect::<Vec<_>>();
        assert_eq!(
            receive_authenticated_source(
                receiver_with(frames.clone()).as_ref(),
                &mut PlainBlobRecordCodec,
                &open,
            )
            .await
            .unwrap(),
            source
        );

        let mut out_of_order = frames;
        out_of_order.swap(0, 1);
        let error = receive_authenticated_source(
            receiver_with(out_of_order).as_ref(),
            &mut PlainBlobRecordCodec,
            &open,
        )
        .await
        .expect_err("out-of-order source must fail closed");
        assert_eq!(error.stage(), BlobNetworkStage::Authentication);

        let mut wrong_digest = open;
        wrong_digest.source_digest = [0x97; 32];
        let valid_frames = source
            .chunks(TEST_SOURCE_CHUNK_BYTES)
            .enumerate()
            .map(|(sequence, bytes)| {
                encoded(StreamFrame::Source(
                    crate::stream_transfer::StreamSourceV1 {
                        transfer_id: wrong_digest.transfer_id,
                        attempt_nonce: wrong_digest.attempt_nonce,
                        sequence: sequence as u64,
                        offset: (sequence * TEST_SOURCE_CHUNK_BYTES) as u32,
                        total_len: wrong_digest.source_len,
                        bytes: bytes.to_vec(),
                    },
                ))
                .unwrap()
            })
            .collect();
        assert!(
            receive_authenticated_source(
                receiver_with(valid_frames).as_ref(),
                &mut PlainBlobRecordCodec,
                &wrong_digest,
            )
            .await
            .is_err()
        );
    }

    impl StreamReceiveAttempt for TerminalReceiveAttempt {
        fn receive_data(&self) -> AdapterFuture<'_, Option<Vec<u8>>> {
            Box::pin(async move {
                self.events.lock().unwrap().push("data-eof");
                Ok(None)
            })
        }

        fn send_control<'a>(&'a self, _frame: &'a [u8]) -> AdapterFuture<'a, ()> {
            Box::pin(async { Err(StreamTransportError::Closed) })
        }

        fn finish_control(&self) -> AdapterFuture<'_, ()> {
            Box::pin(async move {
                let mut events = self.events.lock().unwrap();
                assert_eq!(events.as_slice(), ["data-eof"]);
                events.push("control-fin");
                Ok(())
            })
        }
    }

    #[tokio::test]
    async fn receiver_consumes_data_eof_before_finishing_control() {
        let attempt = Arc::new(TerminalReceiveAttempt {
            events: std::sync::Mutex::new(Vec::new()),
        });
        finish_receiver_attempt(attempt.clone()).await.unwrap();
        assert_eq!(
            attempt.events.lock().unwrap().as_slice(),
            ["data-eof", "control-fin"]
        );
    }

    struct TempRoot(std::path::PathBuf);
    impl TempRoot {
        fn new(label: &str) -> Self {
            let path = std::env::temp_dir().join(format!(
                "aster-network-stream-{label}-{}-{}-{}",
                std::process::id(),
                TEMP_SEQUENCE.fetch_add(1, Ordering::Relaxed),
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .expect("clock")
                    .as_nanos()
            ));
            std::fs::create_dir(&path).expect("temp root");
            Self(path)
        }
    }
    impl Drop for TempRoot {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    fn open(total_len: u64) -> BlobStreamOpen {
        open_with_stream_seed(total_len, 0x12)
    }

    fn open_with_stream_seed(total_len: u64, stream_seed: u8) -> BlobStreamOpen {
        BlobStreamOpen::new(
            BlobPublicationStreamId::from_bytes([stream_seed; 32]).expect("stream"),
            [0x22; 32],
            b"network-pipeline".to_vec(),
            [0x32; 32],
            1,
            VersionVector::default(),
            Topic::new("imagery").expect("topic"),
            Scope::new("mission/alpha").expect("scope"),
            BlobMetadata::new(Some("image/tiff".into()), Vec::new()).expect("metadata"),
            Priority::Immediate,
            None,
            None,
            total_len,
            1,
            1,
            [0x42; 32],
            [0x52; 32],
        )
        .expect("open")
    }

    #[tokio::test]
    async fn native_pack_source_preserves_one_record_per_transport_extent() {
        let source_root = TempRoot::new("record-extents");
        let total_len = 2 * BLOB_STREAM_SEGMENT_BYTES + 17;
        let open = open(total_len as u64);
        let key = [0x63; 32];
        let nonce = [0x73; 12];
        let limits = PipelineLimits::new(2, 4, 5 * 1024 * 1024, 4).expect("limits");
        let published = publish_blob_stream(
            std::io::Cursor::new(vec![0x5a; total_len]),
            &open,
            BlobStreamSegmentSealer::from_test_key(
                *open.stream_id().as_bytes(),
                open.digest(),
                open.content_epoch(),
                key,
                nonce,
            ),
            &source_root.0,
            limits,
        )
        .await
        .expect("publish");
        let opener = BlobStreamSegmentOpener::from_test_key(
            *open.stream_id().as_bytes(),
            open.digest(),
            open.content_epoch(),
            key,
            nonce,
        );
        let mut source =
            PackExtentSource::new(&PackAccess::Path(&source_root.0), &open).expect("pack source");
        let mut extents = Vec::new();
        while let Some(extent) = source.next_extent().expect("next extent") {
            let declared = u32::from_be_bytes(extent[..4].try_into().expect("record length"));
            assert_eq!(extent.len(), declared as usize + 4);
            opener
                .open_encoded(&extent[4..])
                .expect("independently authenticated extent");
            extents.push(extent);
        }

        assert_eq!(extents.len() as u64, published.segment_count);
        let native_record_bytes = crate::stream_transfer::PROFILE5_PACK_RECORD_PREFIX_BYTES
            + crate::stream_transfer::PROFILE5_PACK_SEGMENT_RECORD_BYTES;
        assert_eq!(extents[0].len(), native_record_bytes);
        assert_eq!(extents[1].len(), native_record_bytes);
        assert_eq!(native_record_bytes, PROFILE5_PACK_TRANSPORT_FRAME_BYTES);
    }

    #[tokio::test]
    async fn record_partitioner_rejects_fragmented_or_coalesced_transport_extents() {
        let (sender, _receiver) = mpsc::channel(1);
        let mut fragmented = RecordPartitioner::new(0, 0);
        assert!(
            fragmented
                .push(vec![0, 0, 0, 3, 0xa1, 0xa2], &sender)
                .await
                .is_err()
        );

        let mut coalesced = RecordPartitioner::new(0, 0);
        assert!(
            coalesced
                .push(vec![0, 0, 0, 1, 0xa1, 0, 0, 0, 1, 0xa2], &sender)
                .await
                .is_err()
        );
    }

    #[tokio::test]
    async fn record_partitioner_rejects_records_larger_than_one_profile_extent() {
        let (sender, _receiver) = mpsc::channel(1);
        const TEST_RECORD_BYTES: usize = 4;
        let declared = TEST_RECORD_BYTES + 1;
        let mut bytes =
            vec![0; declared + crate::stream_transfer::PROFILE5_PACK_RECORD_PREFIX_BYTES];
        bytes[..crate::stream_transfer::PROFILE5_PACK_RECORD_PREFIX_BYTES]
            .copy_from_slice(&(declared as u32).to_be_bytes());

        let error = RecordPartitioner::new(0, 0)
            .with_max_record_bytes_for_test(TEST_RECORD_BYTES)
            .push(bytes, &sender)
            .await
            .expect_err("oversized profile-5 record must fail before verification");

        assert_eq!(error.stage(), BlobNetworkStage::Framing);
    }

    #[tokio::test]
    async fn completed_pack_runtime_uses_selected_transport_adapter() {
        let source_root = TempRoot::new("adapter-source");
        let receiver_root = TempRoot::new("adapter-receiver");
        let total_len = PROFILE5_PACK_TRANSPORT_FRAME_BYTES
            - crate::stream_transfer::PROFILE5_PACK_RECORD_PREFIX_BYTES
            - aster_mesh::BLOB_STREAM_SEGMENT_ENCODED_OVERHEAD_BYTES;
        let open = open(total_len as u64);
        let key = [0x66; 32];
        let nonce = [0x76; 12];
        let limits = PipelineLimits::new(2, 4, 5 * 1024 * 1024, 4).unwrap();
        let published = publish_blob_stream(
            std::io::Cursor::new(vec![0x5c; total_len]),
            &open,
            BlobStreamSegmentSealer::from_test_key(
                *open.stream_id().as_bytes(),
                open.digest(),
                open.content_epoch(),
                key,
                nonce,
            ),
            &source_root.0,
            limits,
        )
        .await
        .unwrap();
        let roots = (published.plaintext_root, published.ciphertext_root);
        let wire_len = completed_pack_wire_len(&source_root.0, &open).unwrap();
        let transport = MemoryTransportAdapter::new();
        let mut sender_codec = PlainBlobRecordCodec;
        let mut receiver_codec = PlainBlobRecordCodec;

        let sender = send_completed_pack_inner(
            &transport,
            &open,
            open.encode(),
            PackAccess::Path(&source_root.0),
            roots,
            open.digest().to_vec(),
            None,
            StreamDirection::ToSessionResponder,
            &mut sender_codec,
        );
        let receiver = receive_completed_pack_inner(
            CompletedPackReceive {
                transport: &transport,
                open: &open,
                opener: BlobStreamSegmentOpener::from_test_key(
                    *open.stream_id().as_bytes(),
                    open.digest(),
                    open.content_epoch(),
                    key,
                    nonce,
                ),
                root: PackAccess::Path(&receiver_root.0),
                wire_len,
                limits,
                direction: StreamDirection::ToSessionResponder,
            },
            &mut receiver_codec,
        );
        let (sent, received) = tokio::time::timeout(std::time::Duration::from_secs(5), async {
            tokio::join!(sender, receiver)
        })
        .await
        .expect("selected transport adapter round-trip must remain bounded");
        let sent = sent.unwrap();
        let received = received.unwrap();

        assert_eq!(sent.roots, roots);
        assert_eq!(received.roots, roots);
        assert_eq!(sent.wire_bytes, wire_len);
        assert_eq!(received.wire_bytes, wire_len);
        assert_eq!(
            received.pipeline.unwrap().completed_items(),
            published.segment_count
        );
    }

    #[tokio::test]
    async fn multi_record_native_pack_streams_without_legacy_extent_ceiling() {
        let source_root = TempRoot::new("multi-record-source");
        let receiver_root = TempRoot::new("multi-record-receiver");
        let total_len = 3 * BLOB_STREAM_SEGMENT_BYTES + 17;
        let open = open_with_stream_seed(total_len as u64, 0x13);
        let key = [0x67; 32];
        let nonce = [0x77; 12];
        let limits = PipelineLimits::new(2, 4, 5 * 1024 * 1024, 4).unwrap();
        let published = publish_blob_stream(
            std::io::Cursor::new(vec![0x5b; total_len]),
            &open,
            BlobStreamSegmentSealer::from_test_key(
                *open.stream_id().as_bytes(),
                open.digest(),
                open.content_epoch(),
                key,
                nonce,
            ),
            &source_root.0,
            limits,
        )
        .await
        .unwrap();
        let roots = (published.plaintext_root, published.ciphertext_root);
        let wire_len = completed_pack_wire_len(&source_root.0, &open).unwrap();
        let transport = MemoryTransportAdapter::new();
        let mut sender_codec = PlainBlobRecordCodec;
        let mut receiver_codec = PlainBlobRecordCodec;

        let sender = send_completed_pack_inner(
            &transport,
            &open,
            open.encode(),
            PackAccess::Path(&source_root.0),
            roots,
            open.digest().to_vec(),
            None,
            StreamDirection::ToSessionResponder,
            &mut sender_codec,
        );
        let receiver = receive_completed_pack_inner(
            CompletedPackReceive {
                transport: &transport,
                open: &open,
                opener: BlobStreamSegmentOpener::from_test_key(
                    *open.stream_id().as_bytes(),
                    open.digest(),
                    open.content_epoch(),
                    key,
                    nonce,
                ),
                root: PackAccess::Path(&receiver_root.0),
                wire_len,
                limits,
                direction: StreamDirection::ToSessionResponder,
            },
            &mut receiver_codec,
        );
        let (sent, received) = tokio::time::timeout(std::time::Duration::from_secs(5), async {
            tokio::try_join!(sender, receiver)
        })
        .await
        .expect("multi-record native transfer must remain bounded")
        .expect("multi-record native transfer must succeed");

        assert_eq!(sent.roots, roots);
        assert_eq!(received.roots, roots);
        assert_eq!(sent.wire_bytes, wire_len);
        assert_eq!(received.wire_bytes, wire_len);
        assert_eq!(
            received.pipeline.unwrap().completed_items(),
            published.segment_count
        );
    }

    #[tokio::test]
    async fn completed_pack_crosses_v9_as_verified_checkpointed_segments() {
        let source_root = TempRoot::new("source");
        let receiver_root = TempRoot::new("receiver");
        let total_len = PROFILE5_PACK_TRANSPORT_FRAME_BYTES
            - crate::stream_transfer::PROFILE5_PACK_RECORD_PREFIX_BYTES
            - aster_mesh::BLOB_STREAM_SEGMENT_ENCODED_OVERHEAD_BYTES;
        let plaintext = (0..total_len)
            .map(|index| (index % 251) as u8)
            .collect::<Vec<_>>();
        let open = open(total_len as u64);
        let key = [0x62; 32];
        let nonce = [0x72; 12];
        let limits = PipelineLimits::new(4, 4, 5 * 1024 * 1024, 4).expect("limits");
        let published = publish_blob_stream(
            std::io::Cursor::new(plaintext),
            &open,
            BlobStreamSegmentSealer::from_test_key(
                *open.stream_id().as_bytes(),
                open.digest(),
                open.content_epoch(),
                key,
                nonce,
            ),
            &source_root.0,
            limits,
        )
        .await
        .expect("publish");
        let roots = (published.plaintext_root, published.ciphertext_root);
        let wire_len = completed_pack_wire_len(&source_root.0, &open).expect("wire length");
        assert_eq!(
            wire_len,
            expected_pack_wire_len(total_len as u64).expect("expected wire length")
        );

        let config = EndpointConfig::direct("127.0.0.1:0".parse().expect("address"));
        let server = Endpoint::bind_with_security_profile(
            SecretKey::generate(),
            config,
            CarrierSecurityProfile::IrohQuicV1,
        )
        .await
        .expect("server");
        let client = Endpoint::bind_with_security_profile(
            SecretKey::generate(),
            config,
            CarrierSecurityProfile::IrohQuicV1,
        )
        .await
        .expect("client");
        let address = server
            .bound_sockets()
            .into_iter()
            .find(std::net::SocketAddr::is_ipv4)
            .expect("IPv4 address");
        let receiver = tokio::spawn({
            let server = server.clone();
            let allowed = BTreeSet::from([client.id()]);
            let open = open.clone();
            let root = receiver_root.0.clone();
            async move {
                let connection = server.accept(&allowed).await.expect("accept");
                let report = receive_completed_pack(
                    connection.clone(),
                    &open,
                    BlobStreamSegmentOpener::from_test_key(
                        *open.stream_id().as_bytes(),
                        open.digest(),
                        open.content_epoch(),
                        key,
                        nonce,
                    ),
                    &root,
                    wire_len,
                    limits,
                )
                .await
                .expect("receive");
                connection.close();
                report
            }
        });
        let connection = client
            .connect(ExpectedPeer {
                id: server.id(),
                address,
            })
            .await
            .expect("connect");
        let sent = send_completed_pack(
            connection,
            &open,
            open.encode(),
            &source_root.0,
            roots,
            open.digest().to_vec(),
        )
        .await
        .expect("send");
        let received = receiver.await.expect("receiver task");

        assert_eq!(sent.roots, roots);
        assert_eq!(received.roots, roots);
        assert_eq!(sent.wire_bytes, wire_len);
        assert_eq!(received.wire_bytes, wire_len);
        assert_eq!(received.checkpoints, 1);
        assert_eq!(
            received
                .pipeline
                .as_ref()
                .expect("receiver pipeline")
                .completed_items(),
            published.segment_count
        );
        client.close().await;
        server.close().await;
    }
}
