//! High-level live and stopped-state surfaces for immutable, source-authenticated Blobs.
//!
//! The stopped facade preserves caller-owned streaming readers and writers.
//! The live facade accepts only an already-open regular [`fs::File`] and
//! returns at most one zeroize-on-drop 512 KiB page. Encrypted chunks remain in
//! the mission-bound depot; source-envelope bytes, manifest records, keys,
//! nonces, and depot mechanics are never returned to applications. Both
//! facades also expose a durable at-least-once metadata-notification queue.
//! A delivery identifies one exact signed Blob publication, but never carries
//! plaintext; applications use the existing read surface when bytes are needed.
//! Subscription intent is local and cannot expand network receive policy or
//! current route/content authority.

use std::{
    collections::BTreeMap,
    fmt, fs,
    io::{Read, Seek, Write},
    path::Path,
    sync::{
        Arc, Weak,
        atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering},
    },
};

#[cfg(test)]
use aster_mesh::prepare_blob;
use aster_mesh::{
    BLOB_STREAM_SEGMENT_BYTES, BlobError, BlobId as CoreBlobId, BlobMetadata as CoreBlobMetadata,
    BlobPublicationStreamId, BlobStreamFinalCommitment, BlobStreamOpen,
    BlobStreamPlaintextFrontier, BlobStreamPublication, CustodySample, EncryptedBlobStreamSegment,
    MAX_BLOB_CHUNKS, MAX_BLOB_MEDIA_TYPE_BYTES, MAX_BLOB_SCHEMA_ID_BYTES, NodeId, Priority,
    ReferenceEnvelopeSealer, SELECTED_BLOB_CHUNK_SIZE, Scope, Topic, VerifiedBlobStreamOpen,
    VerifiedBlobStreamPublication, VerifiedBlobStreamPublicationSource,
    local_blob_publication_stream_id,
};
use aster_redb_store::pack::BlobPackWriter;
#[cfg(test)]
use aster_redb_store::{BlobCapacityGcTarget, BlobMaintenanceBudget};
use aster_redb_store::{
    BlobDeliveryAck as StoreBlobDeliveryAck, BlobDeliveryToken as StoreBlobDeliveryToken,
    BlobOperationKey, BlobOperationOwner, BlobPublicationDisposition, BlobReadPlan, BlobSemanticId,
    BlobSourceProjection, BlobSourceRetention, BlobStoreError, BlobStoreStats,
    BlobSubscriptionId as StoreBlobSubscriptionId, BlobSubscriptionKey,
    BlobSubscriptionPollSelection, BlobSubscriptionRemoveOutcome, BlobSubscriptionSpec,
    BlobTransferId, BlobTransferStatusSnapshot as StoreBlobTransferStatusSnapshot,
    BlobUploadCheckpoint, BlobUploadRequest, BlobUploadReservation, ControlPolicySnapshot,
    ControlTransferId, MAX_BLOB_OPERATION_KEY_BYTES, MAX_BLOB_POLL_DELIVERIES,
    MAX_BLOB_SUBSCRIPTION_SCAN, MAX_NETWORK_BLOB_BYTES, MAX_NETWORK_BLOB_CHUNKS, Store, StoreError,
    StoreLimits, StoredBlob,
};
pub use aster_redb_store::{
    BlobDepotLimits, BlobGcFailureCategory, BlobGcRetryState, BlobGcStatus, BlobRetirementReason,
};
use sha2::{Digest as _, Sha256};
use tokio::sync::{mpsc, oneshot};
use zeroize::{Zeroize as _, Zeroizing};

use super::blob_stream::{
    BlobPublishProgress, BlobPublishStreamRequest, BlobPublishStreamSession,
    LocalBlobPublishStream, OpenedBlobPublishStream, SelectedBlobPublishStream,
    blob_pack_application_error, blob_stream_map_pool, blob_stream_pipeline_error,
    sink_mapped_stream_partitions, take_zeroizing_bytes,
};
use super::{
    ApplicationError, ApplicationErrorKind, SelectedApplicationCommand, actor_unavailable,
    application_error,
};
use crate::{
    NodeError,
    mission::UnprotectedReferenceMission,
    runtime::{
        AuthenticatedEventRouteCache, NodeCustodyClock, STORE_FILE, StartupEventVerification,
        blob_capacity_gc_target, ensure_principal_active, ensure_state_accepts_normal_operation,
        equivalent_blob_capacity_error, open_replayed_verifier,
        open_startup_event_verifier_and_cache, recover_local_blob_capacity_after_cleanup,
        refresh_application_policy,
    },
    stream_pipeline::{FixedPartitionMapPool, MappedPartition, PipelineError, StreamPartition},
};

/// Maximum plaintext accepted by one live Blob publication.
pub const MAX_SELECTED_LIVE_BLOB_BYTES: u64 = MAX_NETWORK_BLOB_BYTES;

/// Maximum plaintext accepted by the independently segmented streaming
/// protocol. The legacy live-file/profile-4 path retains its 64 MiB ceiling.
pub const MAX_SELECTED_BLOB_STREAM_BYTES: u64 = MAX_BLOB_CHUNKS * SELECTED_BLOB_CHUNK_SIZE as u64;

/// Historical Profile-4 64-KiB chunks represented by the live compatibility limit.
pub const MAX_SELECTED_LIVE_BLOB_CHUNKS: u64 = MAX_NETWORK_BLOB_CHUNKS;

/// Maximum plaintext returned by one live Blob page read.
///
/// Eight 64-KiB application-page quanta amortize protocol and policy
/// checks while keeping each encoded agent response below its 1-MiB ceiling.
pub const MAX_SELECTED_BLOB_PAGE_BYTES: usize = 8 * SELECTED_BLOB_CHUNK_SIZE as usize;

/// Maximum number of immutable Blob publication notifications returned by one poll.
pub const MAX_SELECTED_BLOB_DELIVERIES: usize = MAX_BLOB_POLL_DELIVERIES;

/// Maximum retained Blob publications freshly authenticated by one poll.
pub const MAX_SELECTED_BLOB_SUBSCRIPTION_SCAN: usize = MAX_BLOB_SUBSCRIPTION_SCAN;

/// Canonical byte length of an opaque [`BlobDeliveryToken`].
pub const BLOB_DELIVERY_TOKEN_BYTES: usize = aster_redb_store::BLOB_DELIVERY_TOKEN_BYTES;

const MAX_SELECTED_BLOB_PLAN_RETRIES: usize = 4;

/// Stable selected-profile identity of immutable Blob bytes and identity metadata.
///
/// The historical profile-4 content identity uses a fixed 64-KiB logical
/// projection. Profile 5 transfers its separately authenticated completed pack
/// as 1-MiB plaintext segments and does not recreate that projection on the
/// wire. Media type and schema bytes are committed by this identity, so changing
/// either produces another ID.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct BlobId([u8; 32]);

impl BlobId {
    /// Constructs an identity from its complete collision-resistant bytes.
    pub const fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// Returns the complete identity bytes.
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    fn from_core(id: CoreBlobId) -> Self {
        Self(*id.as_bytes())
    }

    fn into_core(self) -> CoreBlobId {
        CoreBlobId::from_bytes(self.0)
    }
}

impl fmt::Display for BlobId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        for byte in self.0 {
            write!(formatter, "{byte:02x}")?;
        }
        Ok(())
    }
}

/// Source-authenticated semantic identity of one immutable Blob publication.
///
/// This differs from [`BlobId`]: multiple publishers, counters, or priorities
/// can sign distinct publications of the same immutable content identity.
/// Delivery acknowledgement and deduplication always use this publication
/// identity so one source publication cannot consume another's attempt.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct BlobPublicationId([u8; 32]);

impl BlobPublicationId {
    /// Constructs an identity from its complete source-authenticated bytes.
    pub const fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// Returns the complete semantic publication identity bytes.
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    fn from_store(id: BlobSemanticId) -> Self {
        Self(*id.as_bytes())
    }

    fn into_store(self) -> BlobSemanticId {
        BlobSemanticId::new(self.0)
    }
}

impl fmt::Display for BlobPublicationId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        for byte in self.0 {
            write!(formatter, "{byte:02x}")?;
        }
        Ok(())
    }
}

/// Transport-neutral authenticated identity of one profile-5 Blob publication.
///
/// This identity exists before data byte zero and tracks one publication through
/// interrupted attempts. It is distinct from both legacy [`BlobPublicationId`]
/// and the content-derived [`BlobId`].
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct BlobStreamPublicationId([u8; 32]);

impl BlobStreamPublicationId {
    pub fn from_bytes(bytes: [u8; 32]) -> Result<Self, ApplicationError> {
        BlobPublicationStreamId::from_bytes(bytes)
            .map(Self::from_core)
            .map_err(|_| {
                ApplicationError::new(
                    ApplicationErrorKind::InvalidRequest,
                    "blob publication identity",
                )
            })
    }

    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    fn from_core(id: BlobPublicationStreamId) -> Self {
        Self(*id.as_bytes())
    }

    fn into_core(self) -> BlobPublicationStreamId {
        BlobPublicationStreamId::from_bytes(self.0)
            .expect("validated Blob stream publication identity")
    }
}

impl fmt::Display for BlobStreamPublicationId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        for byte in self.0 {
            write!(formatter, "{byte:02x}")?;
        }
        Ok(())
    }
}

/// Stable mission-local identity of one durable Blob metadata subscription.
///
/// The identifier grants no route, content, carrier, or network interest
/// authority. Every candidate is intersected with current policy and freshly
/// authenticated before it can become a delivery.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct BlobSubscriptionId([u8; 32]);

impl BlobSubscriptionId {
    /// Constructs an identifier from its complete durable bytes.
    pub const fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// Returns the complete durable identifier bytes.
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    fn from_store(id: StoreBlobSubscriptionId) -> Self {
        Self(*id.as_bytes())
    }

    fn into_store(self) -> StoreBlobSubscriptionId {
        StoreBlobSubscriptionId::from_bytes(self.0)
    }
}

impl fmt::Display for BlobSubscriptionId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        for byte in self.0 {
            write!(formatter, "{byte:02x}")?;
        }
        Ok(())
    }
}

/// Idempotent creation request for one durable Blob publication subscription.
///
/// The selector covers exact signed publications in the selected topic and
/// scope. When descendants are enabled, each descendant scope remains visible
/// in its delivery metadata. The request changes only the local application
/// ledger; configured Blob/network interests remain the receive policy.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BlobSubscriptionRequest {
    pub operation_key: Vec<u8>,
    pub topic: Topic,
    pub scope: Scope,
    pub include_descendant_scopes: bool,
}

/// Result of creating or replaying one durable Blob subscription request.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BlobSubscription {
    pub id: BlobSubscriptionId,
    pub inserted: bool,
}

/// One bounded immutable-publication metadata poll.
///
/// `scan_limit` bounds the complete matching candidate set freshly verified by
/// one poll. Poll fails closed instead of advancing through a partial set.
/// `delivery_limit` bounds attempts committed and returned by the call.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BlobPollRequest {
    pub subscription: BlobSubscriptionId,
    pub delivery_limit: usize,
    pub scan_limit: usize,
}

impl BlobPollRequest {
    fn validate(self) -> Result<Self, ApplicationError> {
        if self.delivery_limit == 0
            || self.delivery_limit > MAX_SELECTED_BLOB_DELIVERIES
            || self.scan_limit == 0
            || self.scan_limit > MAX_SELECTED_BLOB_SUBSCRIPTION_SCAN
        {
            return Err(ApplicationError::new(
                ApplicationErrorKind::InvalidRequest,
                "blob poll",
            ));
        }
        Ok(self)
    }
}

/// Opaque acknowledgement identity for one exact Blob delivery retry.
///
/// Content tokens bind the subscription incarnation, publication identity,
/// delivery tenure, and one issued attempt. Retirement tokens instead bind the
/// retirement generation and its issued attempt. A token from an earlier retry
/// remains valid while that same content tenure or retirement evidence remains
/// active, which permits crash-safe acknowledgement; it cannot cross a later
/// tenure or generation, subscription incarnation, publication, or
/// subscription. Applications may persist the canonical bytes without learning
/// or reconstructing the binding fields.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct BlobDeliveryToken(StoreBlobDeliveryToken);

impl BlobDeliveryToken {
    /// Restores a canonical token previously obtained from [`Self::as_bytes`].
    pub fn from_bytes(bytes: [u8; BLOB_DELIVERY_TOKEN_BYTES]) -> Result<Self, ApplicationError> {
        StoreBlobDeliveryToken::from_bytes(bytes)
            .map(Self::from_store)
            .map_err(|_| {
                ApplicationError::new(ApplicationErrorKind::InvalidRequest, "blob delivery token")
            })
    }

    /// Returns the canonical opaque bytes for durable application transport.
    pub fn as_bytes(&self) -> &[u8; BLOB_DELIVERY_TOKEN_BYTES] {
        self.0.as_bytes()
    }

    fn from_store(token: StoreBlobDeliveryToken) -> Self {
        Self(token)
    }

    fn into_store(self) -> StoreBlobDeliveryToken {
        self.0
    }

    #[cfg(test)]
    fn inert_for_command_rejection() -> Self {
        let mut bytes = [0_u8; BLOB_DELIVERY_TOKEN_BYTES];
        bytes[0] = 1;
        bytes[8] = 1;
        bytes[16] = 1;
        bytes[24] = 1;
        Self::from_bytes(bytes).expect("canonical inert Blob delivery token")
    }
}

/// Metadata-only notification for one exact source-authenticated publication.
///
/// No plaintext, manifest bytes, source envelope, content key, nonce, carrier,
/// or depot path crosses this boundary. Use [`BlobReadRequest`] with `id`,
/// `topic`, and `scope` when the application separately needs the Blob bytes.
/// That read resolves immutable content under the current read plan; it is not
/// an exact-publication read and may select a different authorized source
/// publication of the same [`BlobId`].
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BlobDelivery {
    pub publication: BlobPublicationId,
    pub id: BlobId,
    pub publisher: NodeId,
    pub publisher_counter: u64,
    pub topic: Topic,
    pub scope: Scope,
    pub priority: Priority,
    /// Original source-authenticated TTL; `None` means durable.
    pub ttl_ms: Option<u64>,
    pub total_len: u64,
    pub media_type: Option<String>,
    pub schema_id: Vec<u8>,
    pub acceptance_marker: u64,
    /// Nonzero durable at-least-once attempt number.
    pub attempt: u64,
    /// Opaque token issued for this publication tenure and attempt.
    ///
    /// A previously issued token for an earlier attempt in the same still-
    /// pending tenure remains valid; cross-tenure/incarnation bindings fail.
    pub token: BlobDeliveryToken,
}

/// Metadata-only notice that one previously delivered publication retired.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BlobRetirementDelivery {
    pub publication: BlobPublicationId,
    pub id: BlobId,
    pub publisher: NodeId,
    pub publisher_counter: u64,
    pub topic: Topic,
    pub scope: Scope,
    pub priority: Priority,
    /// Original source-authenticated TTL; `None` means durable.
    pub ttl_ms: Option<u64>,
    pub acceptance_marker: u64,
    pub reason: BlobRetirementReason,
    pub retirement_generation: u64,
    pub attempt: u64,
    pub token: BlobDeliveryToken,
}

/// One tagged content or retirement notification.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum BlobDeliveryItem {
    Content(BlobDelivery),
    Retirement(BlobRetirementDelivery),
}

impl BlobDeliveryItem {
    pub const fn content(&self) -> Option<&BlobDelivery> {
        match self {
            Self::Content(delivery) => Some(delivery),
            Self::Retirement(_) => None,
        }
    }

    pub const fn retirement(&self) -> Option<&BlobRetirementDelivery> {
        match self {
            Self::Content(_) => None,
            Self::Retirement(delivery) => Some(delivery),
        }
    }
}

/// Bounded source-authenticated immutable-publication delivery result.
///
/// A page contains exactly one delivery family: pending retirements win over
/// content, so content remains pending for a later page whenever a retirement
/// page is returned. Within either family, pending attempts are returned first
/// and otherwise ordered by this receiver's durable acceptance markers. That
/// order is local bookkeeping, not publisher-counter, causal,
/// source-acceptance, or global/network order. `has_more` covers both families.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct BlobDeliveryPage {
    pub deliveries: Vec<BlobDeliveryItem>,
    pub has_more: bool,
}

/// Idempotent acknowledgement disposition for one exact Blob publication.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BlobAcknowledgement {
    Acknowledged,
    AlreadyAcknowledged,
}

/// Idempotent disposition from removing one durable Blob selector.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BlobUnsubscribe {
    Removed,
    AlreadyAbsent,
}

/// Structurally audited local Blob delivery-ledger status.
///
/// This is intentionally not network sync or peer status. It reports only the
/// durable application selector and at-least-once delivery ledger.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct BlobDeliveryStatus {
    pub subscriptions: u64,
    pub pending_deliveries: u64,
    pub acknowledged_deliveries: u64,
    pub delivery_cursors: u64,
    pub selector_generation: u64,
}

/// Durable receive progress for one authenticated pending Blob publication.
///
/// Byte counters cover canonical encrypted carrier bytes, not plaintext Blob
/// bytes. Peer identities, carrier object identities, lineages, and paths are
/// deliberately absent.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PendingBlobTransferStatus {
    pub publication: BlobPublicationId,
    pub id: BlobId,
    pub topic: Topic,
    pub scope: Scope,
    pub plaintext_bytes: u64,
    pub total_carriers: u64,
    pub durable_carriers: u64,
    pub total_carrier_bytes: u64,
    pub durable_carrier_bytes: u64,
    pub phase: BlobTransferPhase,
}

/// Observable durable phase of one still-pending Blob transfer.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BlobTransferPhase {
    /// The authenticated source and manifest are durable, but no carrier bytes are.
    AwaitingCarrier,
    /// At least one carrier byte is durable, with work still outstanding.
    Receiving,
    /// Every carrier is committed; publication promotion has not completed.
    ReadyToFinalize,
}

/// Audited local Blob storage and authenticated pending-transfer snapshot.
///
/// This is not peer convergence or global delivery status. Retained counters
/// include policy-inactive rows that still consume local durable capacity;
/// `pending` contains only currently authorized source projections.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct BlobTransferStatus {
    pub retained_publications: u64,
    pub retained_pending_transfers: u64,
    pub network_staging_bytes: u64,
    pub reserved_file_bytes: u64,
    /// Sanitized pending reclamation and permanent lifecycle-capacity usage.
    pub gc: BlobGcStatus,
    pub pending: Vec<PendingBlobTransferStatus>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BlobPublicationInspectionRequest {
    pub publication_id: BlobStreamPublicationId,
    pub topic: Topic,
    pub scope: Scope,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BlobPublicationPhase {
    Missing,
    AwaitingData,
    Receiving,
    ReadyToFinalize,
    Available,
    ExpiredOrRetired,
}

/// One bounded receiver-local profile-5 publication snapshot.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BlobPublicationInspection {
    pub publication_id: BlobStreamPublicationId,
    pub phase: BlobPublicationPhase,
    pub plaintext_total_bytes: u64,
    pub durable_plaintext_bytes: u64,
    pub transfer_total_bytes: u64,
    pub durable_transfer_bytes: u64,
    pub total_units: u64,
    pub durable_units: u64,
    pub blob_id: Option<BlobId>,
}

fn missing_blob_publication_inspection(
    publication_id: BlobStreamPublicationId,
) -> BlobPublicationInspection {
    BlobPublicationInspection {
        publication_id,
        phase: BlobPublicationPhase::Missing,
        plaintext_total_bytes: 0,
        durable_plaintext_bytes: 0,
        transfer_total_bytes: 0,
        durable_transfer_bytes: 0,
        total_units: 0,
        durable_units: 0,
        blob_id: None,
    }
}

fn retired_blob_publication_inspection(
    publication_id: BlobStreamPublicationId,
) -> BlobPublicationInspection {
    BlobPublicationInspection {
        publication_id,
        phase: BlobPublicationPhase::ExpiredOrRetired,
        plaintext_total_bytes: 0,
        durable_plaintext_bytes: 0,
        transfer_total_bytes: 0,
        durable_transfer_bytes: 0,
        total_units: 0,
        durable_units: 0,
        blob_id: None,
    }
}

fn profile5_transfer_total_bytes(total_len: u64) -> Result<u64, ApplicationError> {
    crate::stream_transfer::blob_pack_wire_len(total_len).map_err(|_| {
        ApplicationError::new(ApplicationErrorKind::Integrity, "blob publication status")
    })
}

/// Local durable Blob capacity observations. These counters do not reserve space.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct BlobCapacityStatus {
    pub reserved_bytes: u64,
    pub byte_limit: u64,
    pub variants: u64,
    pub variant_limit: u64,
    pub expected_chunks: u64,
    pub chunk_limit: u64,
    pub pending_sources: u64,
    pub network_staging_bytes: u64,
    pub bytes_exhausted: bool,
    pub variants_exhausted: bool,
    pub chunks_exhausted: bool,
}

fn map_blob_capacity_status(
    stats: BlobStoreStats,
    limits: BlobDepotLimits,
) -> Result<BlobCapacityStatus, ApplicationError> {
    if stats.reserved_file_bytes > limits.max_bytes()
        || stats.committed_chunks > limits.max_chunks()
        || stats.variants > limits.max_variants()
    {
        return Err(ApplicationError::new(
            ApplicationErrorKind::Integrity,
            "blob capacity status",
        ));
    }
    Ok(BlobCapacityStatus {
        reserved_bytes: stats.reserved_file_bytes,
        byte_limit: limits.max_bytes(),
        variants: stats.variants,
        variant_limit: limits.max_variants(),
        expected_chunks: stats.committed_chunks,
        chunk_limit: limits.max_chunks(),
        pending_sources: stats.pending_sources,
        network_staging_bytes: stats.network_staging_bytes,
        bytes_exhausted: stats.reserved_file_bytes >= limits.max_bytes(),
        variants_exhausted: stats.variants >= limits.max_variants(),
        chunks_exhausted: stats.committed_chunks >= limits.max_chunks(),
    })
}

fn blob_transfer_phase(
    total_carriers: u64,
    durable_carriers: u64,
    total_carrier_bytes: u64,
    durable_carrier_bytes: u64,
) -> Result<BlobTransferPhase, ApplicationError> {
    let impossible = total_carriers == 0
        || total_carrier_bytes == 0
        || durable_carriers > total_carriers
        || durable_carrier_bytes > total_carrier_bytes
        || (durable_carriers > 0 && durable_carrier_bytes == 0)
        || (durable_carriers == total_carriers && durable_carrier_bytes != total_carrier_bytes);
    if impossible {
        return Err(ApplicationError::new(
            ApplicationErrorKind::Integrity,
            "blob transfer status",
        ));
    }
    Ok(if durable_carriers == total_carriers {
        BlobTransferPhase::ReadyToFinalize
    } else if durable_carrier_bytes == 0 {
        BlobTransferPhase::AwaitingCarrier
    } else {
        BlobTransferPhase::Receiving
    })
}

/// One durable, operation-key-idempotent Blob publication request.
///
/// `source` is supplied separately to [`SelectedBlobNode::publish`] and must
/// remain byte-for-byte stable across its bounded hash and encryption passes.
/// Empty content is rejected by the selected Blob profile. `operation_key` is
/// a non-secret, non-path, low-sensitivity idempotency identifier retained with
/// the durable store. `media_type` and arbitrary `schema_id` bytes are likewise
/// non-secret, non-path metadata: they are retained in plaintext by the
/// depot/application projection and may appear in publication results and
/// pages. All three fields may appear in `Debug` output. For
/// [`SelectedBlobHandle::publish`], the owned regular file must have its cursor
/// positioned at exactly zero. Exact-operation retry remains available only
/// while the publisher and Store are authorized and not zeroized. A failed
/// publication may leave bounded, quota-charged unfinished or completed
/// provisional upload staging with no semantic/operation row. That staging is
/// not a second publication authority; only canonical publication commits it.
/// Exact already-unreferenced variants are eligible for manifest-authorized,
/// bounded background reclamation and remain fully charged until deletion
/// finalizes. Capacity admission may run one cursor-neutral bounded reclamation
/// attempt and retry once; it never retires or evicts live content.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BlobPublishRequest {
    pub operation_key: Vec<u8>,
    pub topic: Topic,
    pub scope: Scope,
    pub priority: Priority,
    pub media_type: Option<String>,
    pub schema_id: Vec<u8>,
}

/// Additive lifetime selection for one Blob publication.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct BlobPublishOptions {
    ttl_ms: Option<u64>,
}

impl BlobPublishOptions {
    /// Selects durable, non-expiring publication.
    pub const fn durable() -> Self {
        Self { ttl_ms: None }
    }

    /// Selects a positive original lifetime in milliseconds.
    pub const fn finite_ttl_ms(ttl_ms: u64) -> Result<Self, ApplicationError> {
        if ttl_ms == 0 {
            return Err(ApplicationError::new(
                ApplicationErrorKind::InvalidRequest,
                "blob publish",
            ));
        }
        Ok(Self {
            ttl_ms: Some(ttl_ms),
        })
    }

    /// Returns the exact original lifetime, never a remaining lifetime.
    pub const fn ttl_ms(self) -> Option<u64> {
        self.ttl_ms
    }
}

/// Successful Blob publication without manifest or provider details.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BlobPublishResult {
    /// Present for semantic-v9/profile-5 streaming publications only.
    pub publication_id: Option<BlobStreamPublicationId>,
    pub id: BlobId,
    pub publisher: NodeId,
    pub publisher_counter: u64,
    pub priority: Priority,
    /// Original source-authenticated TTL; `None` means durable.
    pub ttl_ms: Option<u64>,
    pub total_len: u64,
    pub media_type: Option<String>,
    pub schema_id: Vec<u8>,
    pub acceptance_marker: u64,
    /// True only when this call inserted a new signed publication.
    ///
    /// A different operation may insert another source publication while
    /// reusing the same immutable encrypted depot variant.
    pub inserted: bool,
}

/// Exact immutable-content lookup in one selected topic and scope.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BlobReadRequest {
    pub id: BlobId,
    pub topic: Topic,
    pub scope: Scope,
}

/// One bounded live Blob plaintext page.
///
/// `offset` is an absolute plaintext byte offset and `max_bytes` must be in
/// `1..=MAX_SELECTED_BLOB_PAGE_BYTES`. The final page may be shorter. An
/// offset at or beyond a nonempty authenticated Blob length is rejected rather
/// than manufacturing an empty plaintext result. The sole exception is an
/// authenticated zero-length semantic-v9/profile-5 publication: exact offset
/// zero returns one empty, complete terminal page. That page is authenticated
/// EOF, not unauthenticated absence; no other offset is accepted.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BlobReadPageRequest {
    pub blob: BlobReadRequest,
    pub offset: u64,
    pub max_bytes: usize,
}

/// One freshly authenticated live Blob plaintext page.
///
/// Plaintext is deliberately private and cannot be moved into a raw `Vec`.
/// Borrow it through [`Self::as_bytes`]; the owned allocation is zeroized when
/// this value is dropped. Any bytes the caller copies from that borrow become
/// caller custody and may outlive node shutdown or zeroization. Closing live
/// admission prevents new pages; it cannot erase caller-owned copies.
pub struct BlobReadPage {
    publication: BlobPublicationId,
    pub id: BlobId,
    pub publisher: NodeId,
    pub publisher_counter: u64,
    pub priority: Priority,
    /// Original source-authenticated TTL; `None` means durable.
    pub ttl_ms: Option<u64>,
    pub total_len: u64,
    pub media_type: Option<String>,
    pub schema_id: Vec<u8>,
    pub acceptance_marker: u64,
    pub offset: u64,
    pub complete: bool,
    next_offset: u64,
    plaintext: Zeroizing<Vec<u8>>,
}

impl BlobReadPage {
    /// Authenticated plaintext bytes for this page.
    pub fn as_bytes(&self) -> &[u8] {
        &self.plaintext
    }

    /// Number of authenticated plaintext bytes in this page.
    pub fn len(&self) -> usize {
        self.plaintext.len()
    }

    /// True only for the authenticated empty terminal EOF page.
    ///
    /// Missing or unauthorized content and offsets beyond a nonempty Blob are
    /// errors and never manufacture an empty page.
    pub fn is_empty(&self) -> bool {
        self.plaintext.is_empty()
    }

    /// Absolute byte offset for the next page.
    pub const fn next_offset(&self) -> u64 {
        self.next_offset
    }
}

impl fmt::Debug for BlobReadPage {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("BlobReadPage")
            .field("id", &self.id)
            .field("publisher", &self.publisher)
            .field("publisher_counter", &self.publisher_counter)
            .field("priority", &self.priority)
            .field("ttl_ms", &self.ttl_ms)
            .field("total_len", &self.total_len)
            .field("media_type", &self.media_type)
            .field("schema_id", &self.schema_id)
            .field("acceptance_marker", &self.acceptance_marker)
            .field("offset", &self.offset)
            .field("complete", &self.complete)
            .field("next_offset", &self.next_offset)
            .field("plaintext_bytes", &self.plaintext.len())
            .finish()
    }
}

impl Drop for BlobReadPage {
    fn drop(&mut self) {
        self.plaintext.zeroize();
    }
}

/// Statistics and authenticated identity metadata from one complete Blob read.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BlobReadResult {
    pub id: BlobId,
    pub publisher: NodeId,
    pub publisher_counter: u64,
    pub priority: Priority,
    /// Original source-authenticated TTL; `None` means durable.
    pub ttl_ms: Option<u64>,
    pub total_len: u64,
    pub media_type: Option<String>,
    pub schema_id: Vec<u8>,
    pub acceptance_marker: u64,
    pub verified_chunks: u64,
    /// Peak buffer capacity reported by the core Blob streaming engine.
    ///
    /// Store adapters may concurrently hold additional independently bounded,
    /// chunk-sized buffers; this is not a whole-operation peak-memory measure.
    pub peak_working_buffer_bytes: usize,
}

/// Explicit admission limits for the selected Blob depot.
///
/// The byte cap covers marked committed chunk files (including their fixed
/// file headers) plus the incoming serialized file before its marker. Chunk
/// and variant caps count all durable chunk-metadata and import rows, including
/// unfinished staging; exact already-unreferenced durable rows remain charged
/// until bounded manifest-backed maintenance reaches finalization. Unmarked
/// temporary or otherwise untracked filesystem allocation is outside these
/// counters.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct SelectedBlobOptions {
    pub depot_limits: BlobDepotLimits,
}

/// Cloneable live Blob handle backed by the running node's protected worker.
#[derive(Clone)]
pub struct SelectedBlobHandle {
    commands: mpsc::Sender<SelectedApplicationCommand>,
    admission: Arc<AtomicBool>,
    identity: NodeId,
    mission_authority: NodeId,
}

impl SelectedBlobHandle {
    pub(crate) fn new(
        commands: mpsc::Sender<SelectedApplicationCommand>,
        admission: Arc<AtomicBool>,
        identity: NodeId,
        mission_authority: NodeId,
    ) -> Self {
        Self {
            commands,
            admission,
            identity,
            mission_authority,
        }
    }

    /// Authenticated local Blob publisher identity.
    pub const fn identity(&self) -> NodeId {
        self.identity
    }

    /// Stable mission authority bound to the live store and depot.
    pub const fn mission_authority(&self) -> NodeId {
        self.mission_authority
    }

    /// Durably publishes one already-open regular file through the live worker.
    ///
    /// The file must be nonempty, no larger than the live limit, and positioned
    /// at cursor offset exactly zero when this method is called.
    ///
    /// Dropping this future before its command is successfully enqueued in the
    /// shared application lane drops the file and cannot publish. After enqueue,
    /// cancellation leaves the outcome indeterminate and the worker may durably
    /// commit; retry the exact `operation_key` to recover the authoritative
    /// result only while that publisher and Store remain authorized and have
    /// not been zeroized. A failed or concurrently mutated source can leave
    /// bounded, quota-charged unfinished or completed provisional upload
    /// staging without a semantic or operation row. This is not a second
    /// publication authority; only canonical publication commits it. Bounded
    /// maintenance can reclaim that exact already-unreferenced staging, but it
    /// remains charged through finalization and provides no live-retirement or
    /// pressure-eviction guarantee. An authorized publisher can therefore
    /// exhaust the default 512-MiB depot with roughly eight maximum-size Blobs
    /// before cleanup, and
    /// before separately bounded carrier-prefix staging.
    /// Admitted file syscalls run on the joined blocking worker, so a hostile or
    /// delayed FUSE/NFS/other filesystem can delay rekey, shutdown, and
    /// zeroization completion. A control change that wins the Store/final policy
    /// check prevents a stale-authority commit or page; an operation which
    /// linearizes first may return afterward. Rekey is logical forward
    /// authorization, not synchronous erasure of prior-epoch keys; facade drop
    /// or terminal zeroization is the node custody-erasure boundary. Node
    /// zeroization cannot erase the caller's backing source file or any
    /// externally cloned file descriptors.
    pub async fn publish(
        &self,
        request: BlobPublishRequest,
        source: fs::File,
    ) -> Result<BlobPublishResult, ApplicationError> {
        self.publish_with_options(request, BlobPublishOptions::durable(), source)
            .await
    }

    /// Durably publishes one regular file with an explicit lifetime choice.
    pub async fn publish_with_options(
        &self,
        request: BlobPublishRequest,
        options: BlobPublishOptions,
        source: fs::File,
    ) -> Result<BlobPublishResult, ApplicationError> {
        validate_live_publish_request(&request)?;
        let (response, received) = oneshot::channel();
        self.send(
            SelectedBlobCommand::Publish {
                request,
                options,
                source,
                response,
            },
            received,
            "blob publish",
        )
        .await
    }

    /// Opens or resumes one bounded single-pass Blob publication stream.
    ///
    /// Dropping the returned handle releases its runtime workers and discards
    /// uncheckpointed bytes, while retaining the durable upload for exact resume.
    /// Reopening the same operation replaces its prior live handle; writes and
    /// finalization through that older handle are rejected.
    /// Once finalization is prepared, an exact reopen returns temporary
    /// `StateUnavailable` until the job releases its writer. Retry the identical
    /// operation after backoff to recover its durable result; dropping a caller
    /// does not cancel a scheduled finalization.
    ///
    /// `total_len == 0` is valid for semantic-v9/profile-5. Such a stream accepts
    /// no data writes and is finalized directly; a later read at offset zero
    /// returns the authenticated empty terminal page documented by
    /// [`BlobReadPageRequest`]. Profile-4 peers cannot receive that publication.
    pub async fn open_publish_stream(
        &self,
        request: BlobPublishStreamRequest,
    ) -> Result<SelectedBlobPublishStream, ApplicationError> {
        validate_live_publish_request(&request.publication)?;
        if request.total_len > MAX_SELECTED_BLOB_STREAM_BYTES {
            return Err(ApplicationError::new(
                ApplicationErrorKind::ResourceLimit,
                "blob stream open",
            ));
        }
        let (response, received) = oneshot::channel();
        let (opened, session) = self
            .send(
                SelectedBlobCommand::OpenPublishStream { request, response },
                received,
                "blob stream open",
            )
            .await?;
        Ok(SelectedBlobPublishStream::new(
            self.commands.clone(),
            opened.token,
            opened.progress,
            session,
        ))
    }

    /// Reads one authenticated, zeroize-on-drop plaintext page.
    ///
    /// An authenticated zero-length semantic-v9/profile-5 publication returns
    /// exactly one empty, complete page at offset zero. This terminal EOF is the
    /// only successful zero-length page; it must not be inferred from a missing
    /// publication, failed authorization, or an offset beyond nonempty content.
    ///
    /// The unique current source is exact-loaded and content-authenticated.
    /// Inactive alternates are rechecked as projection-only durable rows
    /// against startup-authenticated cache capabilities under the Store's
    /// exclusive-writer boundary; their sealed bytes are not rehashed for
    /// every page and can never supply plaintext.
    ///
    /// Dropping the future cancels this side-effect-free read and prevents any
    /// subsequently produced page from being disclosed.
    pub async fn read_page(
        &self,
        request: BlobReadPageRequest,
    ) -> Result<BlobReadPage, ApplicationError> {
        let (response, received) = oneshot::channel();
        self.send(
            SelectedBlobCommand::ReadPage { request, response },
            received,
            "blob read page",
        )
        .await
    }

    /// Idempotently creates one durable metadata-only Blob subscription.
    ///
    /// Dropping the future before enqueue prevents the mutation. After enqueue,
    /// cancellation leaves the outcome indeterminate; retry the exact operation
    /// key and selector to recover the stable identity and inserted/replayed
    /// disposition.
    pub async fn subscribe(
        &self,
        request: BlobSubscriptionRequest,
    ) -> Result<BlobSubscription, ApplicationError> {
        let (response, received) = oneshot::channel();
        self.send(
            SelectedBlobCommand::Subscribe { request, response },
            received,
            "blob subscribe",
        )
        .await
    }

    /// Polls freshly authenticated immutable-publication metadata.
    ///
    /// Dropping the future before enqueue commits no attempt. After enqueue, a
    /// cancelled poll may commit an attempt without disclosing its token; that
    /// unacknowledged publication remains pending and a later poll retries it
    /// with a higher attempt.
    pub async fn poll(
        &self,
        request: BlobPollRequest,
    ) -> Result<BlobDeliveryPage, ApplicationError> {
        let (response, received) = oneshot::channel();
        self.send(
            SelectedBlobCommand::Poll { request, response },
            received,
            "blob poll",
        )
        .await
    }

    /// Idempotently acknowledges one properly bound Blob publication delivery token.
    ///
    /// Dropping the future before enqueue cannot acknowledge. After enqueue,
    /// cancellation leaves the outcome indeterminate; retrying the same valid
    /// token returns [`BlobAcknowledgement::AlreadyAcknowledged`] if the first
    /// call committed.
    pub async fn acknowledge(
        &self,
        subscription: BlobSubscriptionId,
        publication: BlobPublicationId,
        token: BlobDeliveryToken,
    ) -> Result<BlobAcknowledgement, ApplicationError> {
        let (response, received) = oneshot::channel();
        self.send(
            SelectedBlobCommand::Acknowledge {
                subscription,
                publication,
                token,
                response,
            },
            received,
            "blob acknowledge",
        )
        .await
    }

    /// Idempotently removes one Blob selector and its delivery ledger.
    ///
    /// Dropping the future before enqueue preserves the selector. After enqueue,
    /// cancellation leaves the outcome indeterminate; retrying the same stable
    /// identifier returns [`BlobUnsubscribe::AlreadyAbsent`] if removal committed.
    pub async fn unsubscribe(
        &self,
        subscription: BlobSubscriptionId,
    ) -> Result<BlobUnsubscribe, ApplicationError> {
        let (response, received) = oneshot::channel();
        self.send(
            SelectedBlobCommand::Unsubscribe {
                subscription,
                response,
            },
            received,
            "blob unsubscribe",
        )
        .await
    }

    /// Returns audited local Blob selector and delivery-ledger counts.
    ///
    /// Cancellation has no durable side effect; a completed snapshot that loses
    /// its receiver is simply discarded.
    pub async fn delivery_status(&self) -> Result<BlobDeliveryStatus, ApplicationError> {
        let (response, received) = oneshot::channel();
        self.send(
            SelectedBlobCommand::DeliveryStatus { response },
            received,
            "blob delivery status",
        )
        .await
    }

    /// Returns audited local Blob storage and pending-transfer progress.
    ///
    /// Cancellation has no durable side effect; a completed snapshot that loses
    /// its receiver is simply discarded.
    pub async fn transfer_status(&self) -> Result<BlobTransferStatus, ApplicationError> {
        let (response, received) = oneshot::channel();
        self.send(
            SelectedBlobCommand::TransferStatus { response },
            received,
            "blob transfer status",
        )
        .await
    }

    pub async fn inspect_publication(
        &self,
        request: BlobPublicationInspectionRequest,
    ) -> Result<BlobPublicationInspection, ApplicationError> {
        let (response, received) = oneshot::channel();
        self.send(
            SelectedBlobCommand::InspectPublication { request, response },
            received,
            "blob publication status",
        )
        .await
    }

    pub async fn capacity_status(&self) -> Result<BlobCapacityStatus, ApplicationError> {
        let (response, received) = oneshot::channel();
        self.send(
            SelectedBlobCommand::CapacityStatus { response },
            received,
            "blob capacity status",
        )
        .await
    }

    async fn send<T>(
        &self,
        command: SelectedBlobCommand,
        received: oneshot::Receiver<Result<T, ApplicationError>>,
        operation: &'static str,
    ) -> Result<T, ApplicationError> {
        if !self.admission.load(Ordering::Acquire) {
            return Err(actor_unavailable(operation));
        }
        self.commands
            .send(SelectedApplicationCommand::Blob(command))
            .await
            .map_err(|_| actor_unavailable(operation))?;
        received.await.map_err(|_| actor_unavailable(operation))?
    }
}

pub(crate) enum SelectedBlobCommand {
    Publish {
        request: BlobPublishRequest,
        options: BlobPublishOptions,
        source: fs::File,
        response: oneshot::Sender<Result<BlobPublishResult, ApplicationError>>,
    },
    OpenPublishStream {
        request: BlobPublishStreamRequest,
        response: oneshot::Sender<
            Result<(OpenedBlobPublishStream, Arc<BlobPublishStreamSession>), ApplicationError>,
        >,
    },
    AppendPublishStream {
        token: [u8; 32],
        session: Arc<BlobPublishStreamSession>,
        offset: u64,
        bytes: Zeroizing<Vec<u8>>,
        response: oneshot::Sender<Result<BlobPublishProgress, ApplicationError>>,
    },
    FinishPublishStream {
        token: [u8; 32],
        session: Arc<BlobPublishStreamSession>,
        response: oneshot::Sender<Result<BlobPublishFinalization, ApplicationError>>,
    },
    ReadPage {
        request: BlobReadPageRequest,
        response: oneshot::Sender<Result<BlobReadPage, ApplicationError>>,
    },
    Subscribe {
        request: BlobSubscriptionRequest,
        response: oneshot::Sender<Result<BlobSubscription, ApplicationError>>,
    },
    Poll {
        request: BlobPollRequest,
        response: oneshot::Sender<Result<BlobDeliveryPage, ApplicationError>>,
    },
    Acknowledge {
        subscription: BlobSubscriptionId,
        publication: BlobPublicationId,
        token: BlobDeliveryToken,
        response: oneshot::Sender<Result<BlobAcknowledgement, ApplicationError>>,
    },
    Unsubscribe {
        subscription: BlobSubscriptionId,
        response: oneshot::Sender<Result<BlobUnsubscribe, ApplicationError>>,
    },
    DeliveryStatus {
        response: oneshot::Sender<Result<BlobDeliveryStatus, ApplicationError>>,
    },
    TransferStatus {
        response: oneshot::Sender<Result<BlobTransferStatus, ApplicationError>>,
    },
    InspectPublication {
        request: BlobPublicationInspectionRequest,
        response: oneshot::Sender<Result<BlobPublicationInspection, ApplicationError>>,
    },
    CapacityStatus {
        response: oneshot::Sender<Result<BlobCapacityStatus, ApplicationError>>,
    },
}

impl SelectedBlobCommand {
    pub(crate) fn reject(self) {
        match self {
            Self::Publish { response, .. } => {
                _ = response.send(Err(actor_unavailable("blob publish")));
            }
            Self::OpenPublishStream { response, .. } => {
                _ = response.send(Err(actor_unavailable("blob stream open")));
            }
            Self::AppendPublishStream { response, .. } => {
                _ = response.send(Err(actor_unavailable("blob stream write")));
            }
            Self::FinishPublishStream { response, .. } => {
                _ = response.send(Err(actor_unavailable("blob stream finish")));
            }
            Self::ReadPage { response, .. } => {
                _ = response.send(Err(actor_unavailable("blob read page")));
            }
            Self::Subscribe { response, .. } => {
                _ = response.send(Err(actor_unavailable("blob subscribe")));
            }
            Self::Poll { response, .. } => {
                _ = response.send(Err(actor_unavailable("blob poll")));
            }
            Self::Acknowledge { response, .. } => {
                _ = response.send(Err(actor_unavailable("blob acknowledge")));
            }
            Self::Unsubscribe { response, .. } => {
                _ = response.send(Err(actor_unavailable("blob unsubscribe")));
            }
            Self::DeliveryStatus { response } => {
                _ = response.send(Err(actor_unavailable("blob delivery status")));
            }
            Self::TransferStatus { response } => {
                _ = response.send(Err(actor_unavailable("blob transfer status")));
            }
            Self::InspectPublication { response, .. } => {
                _ = response.send(Err(actor_unavailable("blob publication status")));
            }
            Self::CapacityStatus { response } => {
                _ = response.send(Err(actor_unavailable("blob capacity status")));
            }
        }
    }

    pub(crate) fn reject_resource_limit(self) {
        match self {
            Self::Publish { response, .. } => {
                _ = response.send(Err(ApplicationError::new(
                    ApplicationErrorKind::ResourceLimit,
                    "blob publish",
                )));
            }
            Self::OpenPublishStream { response, .. } => {
                _ = response.send(Err(ApplicationError::new(
                    ApplicationErrorKind::ResourceLimit,
                    "blob stream open",
                )));
            }
            Self::AppendPublishStream { response, .. } => {
                _ = response.send(Err(ApplicationError::new(
                    ApplicationErrorKind::ResourceLimit,
                    "blob stream write",
                )));
            }
            Self::FinishPublishStream { response, .. } => {
                _ = response.send(Err(ApplicationError::new(
                    ApplicationErrorKind::ResourceLimit,
                    "blob stream finish",
                )));
            }
            Self::ReadPage { response, .. } => {
                _ = response.send(Err(ApplicationError::new(
                    ApplicationErrorKind::ResourceLimit,
                    "blob read page",
                )));
            }
            Self::Subscribe { response, .. } => {
                _ = response.send(Err(ApplicationError::new(
                    ApplicationErrorKind::ResourceLimit,
                    "blob subscribe",
                )));
            }
            Self::Poll { response, .. } => {
                _ = response.send(Err(ApplicationError::new(
                    ApplicationErrorKind::ResourceLimit,
                    "blob poll",
                )));
            }
            Self::Acknowledge { response, .. } => {
                _ = response.send(Err(ApplicationError::new(
                    ApplicationErrorKind::ResourceLimit,
                    "blob acknowledge",
                )));
            }
            Self::Unsubscribe { response, .. } => {
                _ = response.send(Err(ApplicationError::new(
                    ApplicationErrorKind::ResourceLimit,
                    "blob unsubscribe",
                )));
            }
            Self::DeliveryStatus { response } => {
                _ = response.send(Err(ApplicationError::new(
                    ApplicationErrorKind::ResourceLimit,
                    "blob delivery status",
                )));
            }
            Self::TransferStatus { response } => {
                _ = response.send(Err(ApplicationError::new(
                    ApplicationErrorKind::ResourceLimit,
                    "blob transfer status",
                )));
            }
            Self::InspectPublication { response, .. } => {
                _ = response.send(Err(ApplicationError::new(
                    ApplicationErrorKind::ResourceLimit,
                    "blob publication status",
                )));
            }
            Self::CapacityStatus { response } => {
                _ = response.send(Err(ApplicationError::new(
                    ApplicationErrorKind::ResourceLimit,
                    "blob capacity status",
                )));
            }
        }
    }
}

struct VerifiedProfile5LiveBlob {
    stored: StoredBlob,
    projection: BlobSourceProjection,
    retention: BlobSourceRetention,
    publication: VerifiedBlobStreamPublication,
    physical_open: VerifiedBlobStreamOpen,
    commitment: BlobStreamFinalCommitment,
}

const BLOB_READ_MAP_WORKERS: usize = 4;
const BLOB_READ_PIPELINE_ITEMS: u64 = 4;

struct OpenedBlobReadSegment {
    offset: u64,
    plaintext: Zeroizing<Vec<u8>>,
}

struct LocalBlobReadCache {
    request: BlobReadRequest,
    plan: BlobReadPlan,
    selected: VerifiedProfile5LiveBlob,
    reader: Option<aster_redb_store::Profile5PackReadSession>,
    map_pool: Option<FixedPartitionMapPool<OpenedBlobReadSegment>>,
    mapped: BTreeMap<u64, MappedPartition<OpenedBlobReadSegment>>,
    submitted_index: u64,
    next_segment_index: u64,
    segment_count: u64,
    active_segment: Option<OpenedBlobReadSegment>,
    active_position: usize,
    next_offset: u64,
    #[cfg(test)]
    opened_segments: u64,
}

impl LocalBlobReadCache {
    fn fill_pipeline(&mut self) -> Result<(), ApplicationError> {
        while self.submitted_index < self.segment_count
            && self.submitted_index.saturating_sub(self.next_segment_index)
                < BLOB_READ_PIPELINE_ITEMS
        {
            let record = self
                .reader
                .as_mut()
                .ok_or_else(|| {
                    ApplicationError::new(ApplicationErrorKind::Integrity, "blob read page")
                })?
                .next_record()
                .map_err(|error| application_error("blob read page", error.into()))?
                .ok_or_else(|| {
                    ApplicationError::new(ApplicationErrorKind::Integrity, "blob read page")
                })?;
            self.map_pool
                .as_ref()
                .ok_or_else(|| {
                    ApplicationError::new(ApplicationErrorKind::Integrity, "blob read page")
                })?
                .submit_unbudgeted(StreamPartition::new(
                    self.submitted_index,
                    record.into_bytes(),
                ))
                .map_err(blob_read_pipeline_error)?;
            self.submitted_index = self.submitted_index.checked_add(1).ok_or_else(|| {
                ApplicationError::new(ApplicationErrorKind::Integrity, "blob read page")
            })?;
        }
        Ok(())
    }

    fn next_opened_segment(&mut self) -> Result<OpenedBlobReadSegment, ApplicationError> {
        while !self.mapped.contains_key(&self.next_segment_index) {
            let mapped = self
                .map_pool
                .as_mut()
                .ok_or_else(|| {
                    ApplicationError::new(ApplicationErrorKind::Integrity, "blob read page")
                })?
                .recv_mapped_blocking()
                .map_err(blob_read_pipeline_error)?;
            let index = mapped.index();
            if index < self.next_segment_index
                || index >= self.submitted_index
                || self.mapped.insert(index, mapped).is_some()
            {
                return Err(ApplicationError::new(
                    ApplicationErrorKind::Integrity,
                    "blob read page",
                ));
            }
        }
        let mapped = self
            .mapped
            .remove(&self.next_segment_index)
            .ok_or_else(|| {
                ApplicationError::new(ApplicationErrorKind::Integrity, "blob read page")
            })?;
        let opened = mapped.into_value();
        let expected_offset = self
            .next_segment_index
            .checked_mul(BLOB_STREAM_SEGMENT_BYTES as u64)
            .ok_or_else(|| {
                ApplicationError::new(ApplicationErrorKind::Integrity, "blob read page")
            })?;
        if opened.offset != expected_offset {
            return Err(ApplicationError::new(
                ApplicationErrorKind::Integrity,
                "blob read page",
            ));
        }
        self.next_segment_index = self.next_segment_index.checked_add(1).ok_or_else(|| {
            ApplicationError::new(ApplicationErrorKind::Integrity, "blob read page")
        })?;
        #[cfg(test)]
        {
            self.opened_segments += 1;
        }
        self.fill_pipeline()?;
        Ok(opened)
    }
}

fn blob_read_pipeline_error(_error: PipelineError) -> ApplicationError {
    ApplicationError::new(ApplicationErrorKind::Integrity, "blob read page")
}

struct VerifiedBlobDeliveryMetadata {
    publication: BlobPublicationId,
    id: BlobId,
    publisher: NodeId,
    publisher_counter: u64,
    topic: Topic,
    scope: Scope,
    priority: Priority,
    ttl_ms: Option<u64>,
    total_len: u64,
    media_type: Option<String>,
    schema_id: Vec<u8>,
    acceptance_marker: u64,
}

impl VerifiedBlobDeliveryMetadata {
    fn into_delivery(self, attempt: u64, token: StoreBlobDeliveryToken) -> BlobDelivery {
        BlobDelivery {
            publication: self.publication,
            id: self.id,
            publisher: self.publisher,
            publisher_counter: self.publisher_counter,
            topic: self.topic,
            scope: self.scope,
            priority: self.priority,
            ttl_ms: self.ttl_ms,
            total_len: self.total_len,
            media_type: self.media_type,
            schema_id: self.schema_id,
            acceptance_marker: self.acceptance_marker,
            attempt,
            token: BlobDeliveryToken::from_store(token),
        }
    }
}

// Two promotion workers bound simultaneous metadata authentication and atomic
// promotion. The already-encrypted pack remains the only data representation.
const BLOB_PACK_PROMOTION_WORKERS: usize = 2;
const BLOB_PACK_PROMOTION_QUEUE_CAPACITY: usize = 2;

mod promotion_store {
    use super::*;

    /// One attempted call across the complete promotion-worker-to-Store/helper
    /// boundary. These are orchestration operations, not nested redb calls.
    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    pub(super) enum BlobPackPromotionStoreOperation {
        ReplayAuthority,
        ReadControlHead,
        RefreshPolicy,
        ReserveProfile5Upload,
        CheckpointProfile5Pack,
        CompleteProfile5Pack,
        ReadProfile5PackBinding,
        CommitProfile5Publication,
        CacheProfile5Publication,
        AbortProfile5Upload,
    }

    /// Non-escaping Store authority for one promotion job.
    ///
    /// Deliberately has no `Deref`, `AsRef<Store>`, or raw Store getter. Every
    /// top-level Store-backed action in `run_measured` must be named here.
    pub(super) struct BlobPackPromotionStore {
        inner: Arc<Store>,
        operations: AtomicU64,
        #[cfg(test)]
        trace: std::sync::Mutex<Vec<BlobPackPromotionStoreOperation>>,
    }

    impl BlobPackPromotionStore {
        pub(super) fn new(inner: Arc<Store>) -> Self {
            Self {
                inner,
                operations: AtomicU64::new(0),
                #[cfg(test)]
                trace: std::sync::Mutex::new(Vec::new()),
            }
        }

        fn record(&self, operation: BlobPackPromotionStoreOperation) {
            self.operations.fetch_add(1, Ordering::Relaxed);
            #[cfg(not(test))]
            let _ = operation;
            #[cfg(test)]
            self.trace
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .push(operation);
        }

        pub(super) fn operation_count(&self) -> u64 {
            self.operations.load(Ordering::Relaxed)
        }

        #[cfg(test)]
        pub(super) fn trace(&self) -> Vec<BlobPackPromotionStoreOperation> {
            self.trace
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .clone()
        }

        pub(super) fn replay_authority(
            &self,
            mission: &UnprotectedReferenceMission,
        ) -> Result<ReferenceEnvelopeSealer, NodeError> {
            self.record(BlobPackPromotionStoreOperation::ReplayAuthority);
            open_replayed_verifier(&self.inner, mission)
        }

        pub(super) fn control_head(&self) -> Result<Option<(u64, ControlTransferId)>, StoreError> {
            self.record(BlobPackPromotionStoreOperation::ReadControlHead);
            self.inner.control_head()
        }

        pub(super) fn refresh_policy(
            &self,
            mission: &UnprotectedReferenceMission,
            verifier: &mut ReferenceEnvelopeSealer,
            verifier_head: &mut Option<(u64, ControlTransferId)>,
        ) -> Result<Option<ControlPolicySnapshot>, NodeError> {
            self.record(BlobPackPromotionStoreOperation::RefreshPolicy);
            refresh_application_policy(&self.inner, mission, verifier, verifier_head)
        }

        pub(super) fn reserve_profile5_upload<F>(
            &self,
            policy: &ControlPolicySnapshot,
            request: &BlobUploadRequest,
            initial_custody: Option<CustodySample>,
            build: F,
        ) -> Result<
            (
                BlobUploadReservation,
                aster_redb_store::BlobUploadCheckpoint,
                VerifiedBlobStreamOpen,
            ),
            StoreError,
        >
        where
            F: FnOnce(
                &aster_redb_store::BlobReservation,
                Option<&[u8]>,
            ) -> Result<(VerifiedBlobStreamOpen, Vec<u8>), StoreError>,
        {
            self.record(BlobPackPromotionStoreOperation::ReserveProfile5Upload);
            self.inner
                .reserve_profile5_upload_with_policy(policy, request, initial_custody, build)
        }

        pub(super) fn checkpoint_profile5_pack(
            &self,
            policy: &ControlPolicySnapshot,
            reservation: &BlobUploadReservation,
            expected: aster_redb_store::BlobUploadCheckpoint,
            durable: aster_redb_store::pack::BlobPackCheckpoint,
        ) -> Result<aster_redb_store::BlobUploadCheckpoint, StoreError> {
            self.record(BlobPackPromotionStoreOperation::CheckpointProfile5Pack);
            self.inner
                .checkpoint_blob_upload(policy, reservation, expected, durable)
        }

        pub(super) fn complete_profile5_pack(
            &self,
            policy: &ControlPolicySnapshot,
            reservation: &BlobUploadReservation,
            expected: aster_redb_store::BlobUploadCheckpoint,
            completion: aster_redb_store::pack::BlobPackCompletion,
            commitment: &aster_mesh::VerifiedBlobStreamFinalCommitment,
            lineage: aster_mesh::BlobStreamLineage,
        ) -> Result<aster_redb_store::BlobUploadCheckpoint, StoreError> {
            self.record(BlobPackPromotionStoreOperation::CompleteProfile5Pack);
            self.inner.complete_profile5_upload_pack(
                policy,
                reservation,
                expected,
                completion,
                commitment,
                lineage,
            )
        }

        pub(super) fn commit_profile5_publication(
            &self,
            policy: &ControlPolicySnapshot,
            reservation: &BlobUploadReservation,
            expected: &aster_redb_store::BlobUploadCheckpoint,
            publication: &aster_mesh::VerifiedBlobStreamPublication,
            precommit_sample: Option<CustodySample>,
        ) -> Result<aster_redb_store::BlobOnceOutcome, StoreError> {
            self.record(BlobPackPromotionStoreOperation::CommitProfile5Publication);
            self.inner.commit_profile5_publication_once_with_policy(
                policy,
                reservation,
                expected,
                publication,
                precommit_sample,
            )
        }

        pub(super) fn profile5_publication_binding(
            &self,
            reservation: &BlobUploadReservation,
            expected: &aster_redb_store::BlobUploadCheckpoint,
        ) -> Result<[u8; 32], StoreError> {
            self.record(BlobPackPromotionStoreOperation::ReadProfile5PackBinding);
            self.inner
                .profile5_upload_publication_binding(reservation, expected)
        }

        pub(super) fn cache_profile5_publication(
            &self,
            cache: &AuthenticatedEventRouteCache,
            verifier: &ReferenceEnvelopeSealer,
            stored: &StoredBlob,
            lifecycle: &std::sync::MutexGuard<'_, ()>,
        ) -> Result<(), NodeError> {
            self.record(BlobPackPromotionStoreOperation::CacheProfile5Publication);
            crate::runtime::cache_authenticated_profile5_blob_route_claim(
                &self.inner,
                cache,
                verifier,
                stored,
                lifecycle,
            )
        }

        pub(super) fn abort_profile5_upload(
            &self,
            reservation: &BlobUploadReservation,
        ) -> Result<bool, StoreError> {
            self.record(BlobPackPromotionStoreOperation::AbortProfile5Upload);
            self.inner.abort_blob_upload(reservation)
        }
    }
}

use promotion_store::BlobPackPromotionStore;
#[cfg(test)]
use promotion_store::BlobPackPromotionStoreOperation;

pub(crate) type BlobPackPromotionCompletion =
    oneshot::Receiver<Result<BlobPublishResult, ApplicationError>>;

pub(crate) enum BlobPublishFinalization {
    Completed(BlobPublishResult),
    Scheduled(BlobPackPromotionCompletion),
}

enum PreparedBlobPublishFinalization {
    Completed(BlobPublishResult),
    Pending(Box<BlobPackPromotionJob>),
}

struct BlobPackPromotionAuthority {
    mission: UnprotectedReferenceMission,
    store: BlobPackPromotionStore,
    custody_clock: NodeCustodyClock,
    source_route_cache: Arc<AuthenticatedEventRouteCache>,
}

struct BlobPackPromotionJob {
    mission: UnprotectedReferenceMission,
    store: BlobPackPromotionStore,
    custody_clock: NodeCustodyClock,
    source_route_cache: Arc<AuthenticatedEventRouteCache>,
    reservation: BlobUploadReservation,
    checkpoint: aster_redb_store::BlobUploadCheckpoint,
    open: VerifiedBlobStreamOpen,
    writer: Option<BlobPackWriter>,
    #[cfg(test)]
    gate: Option<BlobPackPromotionTestGate>,
    // Last field: rejection/drop closes the writer before releasing ownership.
    finalizing: Arc<BlobPublishStreamRequest>,
}

struct BlobPackPromotionWork {
    job: BlobPackPromotionJob,
    completion: oneshot::Sender<Result<BlobPublishResult, ApplicationError>>,
}

#[derive(Default)]
struct BlobPackPromotionCounts {
    accepted: AtomicU64,
    completed: AtomicU64,
    active: AtomicUsize,
    peak_active: AtomicUsize,
    last_report: std::sync::Mutex<Option<BlobPackPromotionMetrics>>,
}

#[derive(Clone, Debug)]
struct BlobPackPromotionMetrics {
    #[cfg(test)]
    segment_count: u64,
    plaintext_bytes_reprocessed: u64,
    ciphertext_bytes_rewritten: u64,
    /// Attempted calls through the complete private promotion-worker Store boundary.
    store_boundary_operations: u64,
    #[cfg(test)]
    store_boundary_trace: Vec<BlobPackPromotionStoreOperation>,
}

#[cfg(test)]
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum BlobLiveWaitObservation {
    Idle,
    Closed,
}

#[derive(Default)]
struct BlobPackPromotionFailure {
    integrity: AtomicBool,
    wake: tokio::sync::Notify,
}

struct BlobPackPromotionPool {
    sender: Option<std::sync::mpsc::SyncSender<BlobPackPromotionWork>>,
    workers: Vec<std::thread::JoinHandle<()>>,
    counts: Arc<BlobPackPromotionCounts>,
    failure: Arc<BlobPackPromotionFailure>,
}

#[cfg(test)]
#[derive(Clone)]
struct BlobPackPromotionTestGate {
    started: std::sync::mpsc::SyncSender<()>,
    finished: std::sync::mpsc::SyncSender<()>,
    release: Arc<(std::sync::Mutex<bool>, std::sync::Condvar)>,
    panic_remaining: Arc<AtomicUsize>,
}

#[cfg(test)]
impl BlobPackPromotionTestGate {
    fn enter(&self) {
        _ = self.started.try_send(());
        let (released, wake) = &*self.release;
        let mut released = released
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        while !*released {
            released = wake
                .wait(released)
                .unwrap_or_else(std::sync::PoisonError::into_inner);
        }
        if self
            .panic_remaining
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |remaining| {
                if remaining > 0 {
                    Some(remaining - 1)
                } else {
                    None
                }
            })
            .is_ok()
        {
            panic!("injected Blob promotion worker panic");
        }
    }

    fn observe_finished(&self) {
        _ = self.finished.try_send(());
    }
}

impl BlobPackPromotionPool {
    fn new() -> Result<Self, ApplicationError> {
        let (sender, receiver) = std::sync::mpsc::sync_channel::<BlobPackPromotionWork>(
            BLOB_PACK_PROMOTION_QUEUE_CAPACITY,
        );
        let receiver = Arc::new(std::sync::Mutex::new(receiver));
        let counts = Arc::new(BlobPackPromotionCounts::default());
        let failure = Arc::new(BlobPackPromotionFailure::default());
        let mut workers: Vec<std::thread::JoinHandle<()>> =
            Vec::with_capacity(BLOB_PACK_PROMOTION_WORKERS);
        for worker_index in 0..BLOB_PACK_PROMOTION_WORKERS {
            let receiver = Arc::clone(&receiver);
            let counts = Arc::clone(&counts);
            let failure = Arc::clone(&failure);
            let worker = match std::thread::Builder::new()
                .name(format!("aster-blob-promote-{worker_index}"))
                .spawn(move || {
                    loop {
                        let work = receiver
                            .lock()
                            .unwrap_or_else(std::sync::PoisonError::into_inner)
                            .recv();
                        let Ok(work) = work else { break };
                        let active = counts.active.fetch_add(1, Ordering::AcqRel) + 1;
                        counts.peak_active.fetch_max(active, Ordering::AcqRel);
                        #[cfg(test)]
                        let gate = work.job.gate.clone();
                        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                            work.job.run_measured()
                        }))
                        .unwrap_or_else(|_| {
                            Err(ApplicationError::new(
                                ApplicationErrorKind::StateUnavailable,
                                "blob stream finish",
                            ))
                        })
                        .map(|(result, report)| {
                            *counts
                                .last_report
                                .lock()
                                .unwrap_or_else(std::sync::PoisonError::into_inner) = Some(report);
                            result
                        });
                        // Actor delivery cannot depend on a caller retaining or
                        // awaiting its completion. Publish before that response,
                        // and retain the fatal state across wakeups and shutdown.
                        if result
                            .as_ref()
                            .is_err_and(|error| error.kind() == ApplicationErrorKind::Integrity)
                        {
                            failure.integrity.store(true, Ordering::Release);
                            failure.wake.notify_one();
                        }
                        counts.active.fetch_sub(1, Ordering::AcqRel);
                        counts.completed.fetch_add(1, Ordering::AcqRel);
                        #[cfg(test)]
                        if let Some(gate) = gate {
                            gate.observe_finished();
                        }
                        _ = work.completion.send(result);
                    }
                }) {
                Ok(worker) => worker,
                Err(_) => {
                    drop(sender);
                    for worker in workers {
                        _ = worker.join();
                    }
                    return Err(ApplicationError::new(
                        ApplicationErrorKind::StateUnavailable,
                        "blob pack promotion pool",
                    ));
                }
            };
            workers.push(worker);
        }
        Ok(Self {
            sender: Some(sender),
            workers,
            counts,
            failure,
        })
    }

    fn try_submit(
        &self,
        job: BlobPackPromotionJob,
    ) -> Result<BlobPackPromotionCompletion, ApplicationError> {
        if self.failure.integrity.load(Ordering::Acquire) {
            return Err(ApplicationError::new(
                ApplicationErrorKind::Integrity,
                "blob stream finish",
            ));
        }
        let (completion, received) = oneshot::channel();
        let work = BlobPackPromotionWork { job, completion };
        match self
            .sender
            .as_ref()
            .ok_or_else(|| {
                ApplicationError::new(ApplicationErrorKind::StateUnavailable, "blob stream finish")
            })?
            .try_send(work)
        {
            Ok(()) => {
                self.counts.accepted.fetch_add(1, Ordering::AcqRel);
                Ok(received)
            }
            Err(std::sync::mpsc::TrySendError::Full(_)) => Err(ApplicationError::new(
                ApplicationErrorKind::ResourceLimit,
                "blob stream finish",
            )),
            Err(std::sync::mpsc::TrySendError::Disconnected(_)) => Err(ApplicationError::new(
                ApplicationErrorKind::StateUnavailable,
                "blob stream finish",
            )),
        }
    }

    #[cfg(test)]
    fn last_report_for_test(&self) -> BlobPackPromotionMetrics {
        self.counts
            .last_report
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone()
            .expect("completed local pack promotion report")
    }

    fn check_fatal(&self) -> Result<(), NodeError> {
        if self.failure.integrity.load(Ordering::Acquire) {
            Err(NodeError::FatalBlobCoherence(
                "live Blob pack promotion failed a durable invariant".into(),
            ))
        } else {
            Ok(())
        }
    }

    fn shutdown(&mut self) {
        drop(self.sender.take());
        for worker in self.workers.drain(..) {
            _ = worker.join();
        }
        debug_assert_eq!(self.counts.active.load(Ordering::Acquire), 0);
        debug_assert_eq!(
            self.counts.accepted.load(Ordering::Acquire),
            self.counts.completed.load(Ordering::Acquire)
        );
        debug_assert!(
            self.counts.peak_active.load(Ordering::Acquire) <= BLOB_PACK_PROMOTION_WORKERS
        );
        if let Some(report) = self
            .counts
            .last_report
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .as_ref()
        {
            debug_assert_eq!(report.plaintext_bytes_reprocessed, 0);
            debug_assert_eq!(report.ciphertext_bytes_rewritten, 0);
            debug_assert!(matches!(report.store_boundary_operations, 7 | 9));
        }
    }
}

impl Drop for BlobPackPromotionPool {
    fn drop(&mut self) {
        // Pack promotion jobs are synchronous and never await the Tokio runtime or
        // application actor, so joining here is safe even when facade teardown
        // originates on a runtime thread.
        self.shutdown();
    }
}

impl BlobPackPromotionJob {
    fn new(
        authority: BlobPackPromotionAuthority,
        reservation: BlobUploadReservation,
        checkpoint: aster_redb_store::BlobUploadCheckpoint,
        open: VerifiedBlobStreamOpen,
        writer: Option<BlobPackWriter>,
        finalizing: Arc<BlobPublishStreamRequest>,
    ) -> Self {
        let BlobPackPromotionAuthority {
            mission,
            store,
            custody_clock,
            source_route_cache,
        } = authority;
        Self {
            mission,
            store,
            custody_clock,
            source_route_cache,
            reservation,
            checkpoint,
            open,
            writer,
            #[cfg(test)]
            gate: None,
            finalizing,
        }
    }

    #[cfg(test)]
    fn with_test_gate(mut self, gate: Option<BlobPackPromotionTestGate>) -> Self {
        self.gate = gate;
        self
    }

    fn run_measured(
        self,
    ) -> Result<(BlobPublishResult, BlobPackPromotionMetrics), ApplicationError> {
        // Hold ownership outside the frame which owns/moves the writer. This
        // outlives all inner resources on success, error, and panic unwinding.
        let _finalizing = Arc::clone(&self.finalizing);
        self.run_owned()
    }

    fn run_owned(self) -> Result<(BlobPublishResult, BlobPackPromotionMetrics), ApplicationError> {
        let BlobPackPromotionJob {
            mission,
            store,
            custody_clock,
            source_route_cache,
            reservation,
            checkpoint,
            open,
            writer,
            #[cfg(test)]
            gate,
            finalizing: _,
        } = self;
        let mut verifier = store
            .replay_authority(&mission)
            .map_err(|error| application_error("blob stream finish", error))?;
        let mut verifier_head = store
            .control_head()
            .map_err(|error| application_error("blob stream finish", error.into()))?;
        let policy = match store.refresh_policy(&mission, &mut verifier, &mut verifier_head) {
            Ok(Some(policy)) => policy,
            Ok(None) => {
                return Err(ApplicationError::new(
                    ApplicationErrorKind::PolicyUnsettled,
                    "blob stream finish",
                ));
            }
            Err(error) => return Err(application_error("blob stream finish", error)),
        };
        let request = reservation.request().clone();
        let expected_open = open.clone();
        let (current, current_checkpoint, current_open) = store
            .reserve_profile5_upload(
                &policy,
                &request,
                open.open().initial_custody(),
                |_, authenticated| {
                    // This job only restores its existing upload authority.
                    // Terminal cleanup can remove a completed upload while it
                    // waits for promotion; absence is an ordinary lost reservation.
                    let authenticated = authenticated
                        .ok_or_else(|| StoreError::Blob(BlobStoreError::ReservationChanged))?;
                    let verified =
                        verifier
                            .verify_blob_stream_open(authenticated)
                            .map_err(|error| {
                                StoreError::Blob(BlobStoreError::Verification(error.to_string()))
                            })?;
                    Ok((verified, authenticated.to_vec()))
                },
            )
            .map_err(|error| application_error("blob stream finish", error.into()))?;
        if current != reservation
            || current_checkpoint != checkpoint
            || current_open != expected_open
            || checkpoint.durable_plaintext_offset() != request.total_len
        {
            return Err(ApplicationError::new(
                ApplicationErrorKind::Integrity,
                "blob stream finish",
            ));
        }

        #[cfg(test)]
        if let Some(gate) = &gate {
            gate.enter();
        }

        let final_sample = if request.ttl_ms.is_some() {
            Some(
                custody_clock
                    .sample()
                    .map_err(|error| application_error("blob stream finish", error))?,
            )
        } else {
            None
        };
        let (commitment, completed) =
            if let Some(completion) = current_checkpoint.profile5_completion() {
                // Recovery can remove a deduplicated candidate after recording
                // this completion. Authenticate the retained finish authority and
                // resume only semantic promotion, without reopening a writer.
                let verified = verifier
                    .verify_blob_stream_commitment(&open, completion.authenticated_commitment())
                    .map_err(|error| application_error("blob stream finish", error.into()))?;
                if verified.commitment() != completion.commitment() {
                    return Err(ApplicationError::new(
                        ApplicationErrorKind::Integrity,
                        "blob stream finish",
                    ));
                }
                (verified.commitment().clone(), current_checkpoint)
            } else {
                let writer = writer.ok_or_else(|| {
                    ApplicationError::new(ApplicationErrorKind::Integrity, "blob stream finish")
                })?;
                let (plaintext_root, ciphertext_root) = writer
                    .final_roots()
                    .map_err(|error| blob_pack_application_error("blob stream finish", error))?;
                let commitment = BlobStreamFinalCommitment::new(
                    &open,
                    plaintext_root,
                    ciphertext_root,
                    writer.next_index(),
                    final_sample,
                )
                .map_err(|error| blob_core_error("blob stream finish", error))?;
                let authenticated_commitment = verifier
                    .seal_blob_stream_commitment(&commitment)
                    .map_err(|error| application_error("blob stream finish", error.into()))?;
                let verified_commitment = verifier
                    .verify_blob_stream_commitment(&open, &authenticated_commitment)
                    .map_err(|error| application_error("blob stream finish", error.into()))?;
                let lineage = verifier
                    .blob_stream_lineage(&open)
                    .map_err(|error| application_error("blob stream finish", error.into()))?;
                let completion = writer
                    .finish_profile5(&verified_commitment)
                    .map_err(|error| blob_pack_application_error("blob stream finish", error))?;
                let projected = store
                    .checkpoint_profile5_pack(
                        &policy,
                        &current,
                        current_checkpoint,
                        completion.checkpoint().clone(),
                    )
                    .map_err(|error| application_error("blob stream finish", error.into()))?;
                let completed = store
                    .complete_profile5_pack(
                        &policy,
                        &current,
                        projected,
                        completion,
                        &verified_commitment,
                        lineage,
                    )
                    .map_err(|error| application_error("blob stream finish", error.into()))?;
                (commitment, completed)
            };
        #[cfg(test)]
        let segment_count = commitment.segment_count();
        let physical_lineage = store
            .profile5_publication_binding(&current, &completed)
            .map_err(|error| application_error("blob stream finish", error.into()))?;
        let publication = BlobStreamPublication::new(
            open.open().clone(),
            commitment.blob_id(),
            final_sample,
            physical_lineage,
        )
        .map_err(|error| blob_core_error("blob stream finish", error))?;
        let authenticated_publication = verifier
            .seal_blob_stream_publication(&publication)
            .map_err(|error| application_error("blob stream finish", error.into()))?;
        let verified_publication = verifier
            .verify_blob_stream_publication(&authenticated_publication)
            .map_err(|error| application_error("blob stream finish", error.into()))?;
        let lifecycle = source_route_cache
            .lock_blob_lifecycle()
            .map_err(|error| application_error("blob stream finish", error))?;
        let outcome = match store.commit_profile5_publication(
            &policy,
            &current,
            &completed,
            &verified_publication,
            final_sample,
        ) {
            Ok(outcome) => outcome,
            Err(error) => {
                if terminal_local_profile5_promotion_error(&error) {
                    store
                        .abort_profile5_upload(&current)
                        .map_err(|abort| application_error("blob stream finish", abort.into()))?;
                }
                return Err(application_error("blob stream finish", error.into()));
            }
        };
        let stored = outcome.blob();
        store
            .cache_profile5_publication(&source_route_cache, &verifier, stored, &lifecycle)
            .map_err(|error| application_error("blob stream finish", error))?;
        if stored.blob_id != commitment.blob_id()
            || stored.header.stamp.dot.publisher != open.open().publisher()
            || stored.header.stamp.dot.counter != open.open().publisher_counter()
            || stored.header.topic != *open.open().topic()
            || stored.header.scope != *open.open().scope()
            || stored.header.priority != open.open().priority()
            || stored.header.ttl_ms != open.open().ttl_ms()
            || stored.header.key_epoch != open.open().content_epoch()
        {
            return Err(ApplicationError::new(
                ApplicationErrorKind::Integrity,
                "blob stream finish",
            ));
        }
        let metadata = open.open().metadata();
        let result = BlobPublishResult {
            publication_id: Some(BlobStreamPublicationId::from_bytes(
                *open.open().stream_id().as_bytes(),
            )?),
            id: BlobId::from_core(commitment.blob_id()),
            publisher: open.open().publisher(),
            publisher_counter: open.open().publisher_counter(),
            priority: open.open().priority(),
            ttl_ms: open.open().ttl_ms(),
            total_len: open.open().total_len(),
            media_type: metadata.media_type().map(str::to_owned),
            schema_id: metadata.schema_id().to_vec(),
            acceptance_marker: stored.acceptance_marker,
            inserted: outcome.inserted(),
        };
        let store_boundary_operations = store.operation_count();
        #[cfg(test)]
        let store_boundary_trace = store.trace();
        Ok((
            result,
            BlobPackPromotionMetrics {
                #[cfg(test)]
                segment_count,
                plaintext_bytes_reprocessed: 0,
                ciphertext_bytes_rewritten: 0,
                store_boundary_operations,
                #[cfg(test)]
                store_boundary_trace,
            },
        ))
    }
}

/// Exclusive stopped-state handle over selected immutable Blob content.
///
/// This owns the same process-exclusive mission-bound redb writer as Event,
/// State, Record, and the live runtime. Blob network reconciliation is absent
/// from this stopped local slice.
pub struct SelectedBlobNode {
    pack_promotion_pool: BlobPackPromotionPool,
    mission: UnprotectedReferenceMission,
    store: Arc<Store>,
    verifier: ReferenceEnvelopeSealer,
    verifier_head: Option<(u64, ControlTransferId)>,
    source_route_cache: Arc<AuthenticatedEventRouteCache>,
    custody_clock: NodeCustodyClock,
    publish_streams: BTreeMap<[u8; 32], LocalBlobPublishStream>,
    // The job owns the strong reference, never a client/session or this map.
    // Admission prunes dead entries; only prepared, queued, or running work is
    // retained. No busy state is persisted across process exit.
    finalizing_publish_streams: BTreeMap<[u8; 32], Weak<BlobPublishStreamRequest>>,
    live_publish_sessions: BTreeMap<[u8; 32], Weak<BlobPublishStreamSession>>,
    publish_stream_cleanup: Arc<tokio::sync::Notify>,
    #[cfg(test)]
    live_command_wait_observer: Option<mpsc::UnboundedSender<BlobLiveWaitObservation>>,
    completed_publish_streams: BTreeMap<[u8; 32], CompletedBlobPublishStream>,
    read_cache: Option<LocalBlobReadCache>,
    #[cfg(test)]
    final_read_gate: Option<(Arc<std::sync::Barrier>, Arc<std::sync::Barrier>)>,
    #[cfg(test)]
    stream_pack_promotion_gate: Option<BlobPackPromotionTestGate>,
    #[cfg(test)]
    live_operation_preflight_coherence_fault: bool,
    #[cfg(test)]
    live_read_projection_coherence_fault: bool,
    #[cfg(test)]
    live_pack_projection_coherence_fault: bool,
    #[cfg(test)]
    live_selected_load_policy_race_fault: bool,
    #[cfg(test)]
    live_poll_coherence_fault: bool,
    #[cfg(test)]
    live_poll_postcommit_completion_fault: bool,
    #[cfg(test)]
    capacity_gc_attempts: u64,
    #[cfg(test)]
    capacity_gc_targets: Vec<BlobCapacityGcTarget>,
    #[cfg(test)]
    injected_capacity_failures: std::collections::VecDeque<StoreError>,
    #[cfg(test)]
    publish_attempts: u64,
    #[cfg(test)]
    last_live_publish_source_bytes_read: u64,
    #[cfg(test)]
    last_read_cache_opened_segments: u64,
}

struct CompletedBlobPublishStream {
    request: BlobPublishStreamRequest,
    result: BlobPublishResult,
    plaintext_root: [u8; 32],
}

#[cfg(test)]
struct TestReadCounter<'a, R> {
    inner: &'a mut R,
    bytes_read: u64,
}

#[cfg(test)]
impl<R: Read> Read for TestReadCounter<'_, R> {
    fn read(&mut self, output: &mut [u8]) -> std::io::Result<usize> {
        let read = self.inner.read(output)?;
        self.bytes_read = self
            .bytes_read
            .checked_add(u64::try_from(read).map_err(std::io::Error::other)?)
            .ok_or_else(|| std::io::Error::other("test source byte count overflowed"))?;
        Ok(read)
    }
}

#[cfg(test)]
impl<R: Seek> Seek for TestReadCounter<'_, R> {
    fn seek(&mut self, position: std::io::SeekFrom) -> std::io::Result<u64> {
        self.inner.seek(position)
    }
}

impl SelectedBlobNode {
    /// Opens the explicitly unprotected reference provisioning path with
    /// conservative default depot limits.
    pub fn open_unprotected_reference(
        state: impl AsRef<Path>,
        mission_bundle: impl AsRef<Path>,
    ) -> Result<Self, ApplicationError> {
        Self::open_unprotected_reference_with_options(
            state,
            mission_bundle,
            SelectedBlobOptions::default(),
        )
    }

    /// Opens the stopped selected Blob surface with explicit physical limits.
    ///
    /// Terminal state is rejected before mission bytes are loaded. The exact
    /// store and depot are then mission-bound and process-locked, and every
    /// committed control is replayed before Blob operations become available.
    pub fn open_unprotected_reference_with_options(
        state: impl AsRef<Path>,
        mission_bundle: impl AsRef<Path>,
        options: SelectedBlobOptions,
    ) -> Result<Self, ApplicationError> {
        let state = state.as_ref();
        ensure_state_accepts_normal_operation(state)
            .map_err(|error| application_error("blob open", error))?;
        let mission = UnprotectedReferenceMission::load(mission_bundle)
            .map_err(|error| application_error("blob open", error.into()))?;
        fs::create_dir_all(state).map_err(|error| application_error("blob open", error.into()))?;
        let store = Store::open_with_limits_and_blob_depot_limits_for_mission(
            state.join(STORE_FILE),
            StoreLimits::default(),
            options.depot_limits,
            mission.mission_authority_id(),
        )
        .map_err(|error| application_error("blob open", error.into()))?;
        store
            .require_process_exclusive_lock()
            .map_err(|error| application_error("blob open", error.into()))?;
        let StartupEventVerification {
            verifier,
            historical_verifier,
            cache: source_route_cache,
            policy: _,
        } = open_startup_event_verifier_and_cache(&store, &mission)
            .map_err(|error| application_error("blob open", error))?;
        drop(historical_verifier);
        ensure_principal_active(&store, verifier.identity())
            .map_err(|error| application_error("blob open", error))?;
        let verifier_head = store
            .control_head()
            .map_err(|error| application_error("blob open", error.into()))?;
        let custody_clock = NodeCustodyClock::open(verifier.identity())
            .map_err(|error| application_error("blob open", error))?;
        let mut selected = Self {
            pack_promotion_pool: BlobPackPromotionPool::new()?,
            mission,
            store: Arc::new(store),
            verifier,
            verifier_head,
            source_route_cache,
            custody_clock,
            publish_streams: BTreeMap::new(),
            finalizing_publish_streams: BTreeMap::new(),
            live_publish_sessions: BTreeMap::new(),
            publish_stream_cleanup: Arc::new(tokio::sync::Notify::new()),
            completed_publish_streams: BTreeMap::new(),
            read_cache: None,
            #[cfg(test)]
            final_read_gate: None,
            #[cfg(test)]
            stream_pack_promotion_gate: None,
            #[cfg(test)]
            live_command_wait_observer: None,
            #[cfg(test)]
            live_operation_preflight_coherence_fault: false,
            #[cfg(test)]
            live_read_projection_coherence_fault: false,
            #[cfg(test)]
            live_pack_projection_coherence_fault: false,
            #[cfg(test)]
            live_selected_load_policy_race_fault: false,
            #[cfg(test)]
            live_poll_coherence_fault: false,
            #[cfg(test)]
            live_poll_postcommit_completion_fault: false,
            #[cfg(test)]
            capacity_gc_attempts: 0,
            #[cfg(test)]
            capacity_gc_targets: Vec::new(),
            #[cfg(test)]
            injected_capacity_failures: std::collections::VecDeque::new(),
            #[cfg(test)]
            publish_attempts: 0,
            #[cfg(test)]
            last_live_publish_source_bytes_read: 0,
            #[cfg(test)]
            last_read_cache_opened_segments: 0,
        };
        selected.current_policy("blob open")?;
        Ok(selected)
    }

    pub(crate) fn from_runtime(
        mission: UnprotectedReferenceMission,
        store: Arc<Store>,
        verifier: ReferenceEnvelopeSealer,
        verifier_head: Option<(u64, ControlTransferId)>,
        source_route_cache: Arc<AuthenticatedEventRouteCache>,
        custody_clock: NodeCustodyClock,
    ) -> Result<Self, ApplicationError> {
        Ok(Self {
            pack_promotion_pool: BlobPackPromotionPool::new()?,
            mission,
            store,
            verifier,
            verifier_head,
            source_route_cache,
            custody_clock,
            publish_streams: BTreeMap::new(),
            finalizing_publish_streams: BTreeMap::new(),
            live_publish_sessions: BTreeMap::new(),
            publish_stream_cleanup: Arc::new(tokio::sync::Notify::new()),
            completed_publish_streams: BTreeMap::new(),
            read_cache: None,
            #[cfg(test)]
            final_read_gate: None,
            #[cfg(test)]
            stream_pack_promotion_gate: None,
            #[cfg(test)]
            live_command_wait_observer: None,
            #[cfg(test)]
            live_operation_preflight_coherence_fault: false,
            #[cfg(test)]
            live_read_projection_coherence_fault: false,
            #[cfg(test)]
            live_pack_projection_coherence_fault: false,
            #[cfg(test)]
            live_selected_load_policy_race_fault: false,
            #[cfg(test)]
            live_poll_coherence_fault: false,
            #[cfg(test)]
            live_poll_postcommit_completion_fault: false,
            #[cfg(test)]
            capacity_gc_attempts: 0,
            #[cfg(test)]
            capacity_gc_targets: Vec::new(),
            #[cfg(test)]
            injected_capacity_failures: std::collections::VecDeque::new(),
            #[cfg(test)]
            publish_attempts: 0,
            #[cfg(test)]
            last_live_publish_source_bytes_read: 0,
            #[cfg(test)]
            last_read_cache_opened_segments: 0,
        })
    }

    #[cfg(test)]
    pub(crate) fn set_final_read_gate(
        &mut self,
        reached: Arc<std::sync::Barrier>,
        release: Arc<std::sync::Barrier>,
    ) {
        self.final_read_gate = Some((reached, release));
    }

    #[cfg(test)]
    fn set_stream_pack_promotion_gate_for_test(
        &mut self,
        started: std::sync::mpsc::SyncSender<()>,
        finished: std::sync::mpsc::SyncSender<()>,
        release: Arc<(std::sync::Mutex<bool>, std::sync::Condvar)>,
    ) {
        self.stream_pack_promotion_gate = Some(BlobPackPromotionTestGate {
            started,
            finished,
            release,
            panic_remaining: Arc::new(AtomicUsize::new(0)),
        });
    }

    #[cfg(test)]
    fn panic_stream_pack_promotions_for_test(&mut self, count: usize) {
        self.stream_pack_promotion_gate
            .as_ref()
            .expect("pack promotion panic injection requires a gate")
            .panic_remaining
            .store(count, Ordering::Release);
    }

    #[cfg(test)]
    fn inject_live_poll_coherence_fault(&mut self) {
        self.live_poll_coherence_fault = true;
    }

    #[cfg(test)]
    fn inject_live_poll_postcommit_completion_fault(&mut self) {
        self.live_poll_postcommit_completion_fault = true;
    }

    /// Executes one worker-owned live command.
    ///
    /// Ordinary application failures are sent through the command response.
    /// An authenticated cache/depot invariant failure, including any failure
    /// after a durable Blob commit, drops that response and escapes as a fatal
    /// [`NodeError`] so the runtime can stop.
    pub(crate) fn execute_live(
        &mut self,
        command: SelectedBlobCommand,
        admission: &AtomicBool,
    ) -> Result<(), NodeError> {
        self.pack_promotion_pool.check_fatal()?;
        if !admission.load(Ordering::Acquire) {
            command.reject();
            return Ok(());
        }
        self.cleanup_abandoned_publish_streams();
        match command {
            SelectedBlobCommand::Publish {
                request,
                options,
                source,
                response,
            } => {
                let mut fatal = None;
                let result = self
                    .publish_live_with_admission(request, options, source, admission, &mut fatal);
                if let Some(error) = fatal {
                    drop(response);
                    Err(error)
                } else {
                    if admission.load(Ordering::Acquire) {
                        _ = response.send(result);
                    } else {
                        drop(result);
                        _ = response.send(Err(actor_unavailable("blob publish")));
                    }
                    Ok(())
                }
            }
            SelectedBlobCommand::OpenPublishStream { request, response } => {
                let result = self.open_publish_stream_inner(request).map(|opened| {
                    let session = Arc::new(BlobPublishStreamSession::new(Arc::clone(
                        &self.publish_stream_cleanup,
                    )));
                    self.live_publish_sessions
                        .insert(opened.token, Arc::downgrade(&session));
                    (opened, session)
                });
                finish_live_blob_ledger_command(
                    result,
                    response,
                    admission,
                    "blob stream open",
                    "live Blob stream open failed a durable invariant",
                )
            }
            SelectedBlobCommand::AppendPublishStream {
                token,
                session,
                offset,
                bytes,
                response,
            } => {
                let result = self
                    .require_publish_session(token, &session, "blob stream write")
                    .and_then(|()| self.append_publish_stream_inner(token, offset, bytes));
                finish_live_blob_ledger_command(
                    result,
                    response,
                    admission,
                    "blob stream write",
                    "live Blob stream write failed a durable invariant",
                )
            }
            SelectedBlobCommand::FinishPublishStream {
                token,
                session,
                response,
            } => {
                let result = self
                    .require_publish_session(token, &session, "blob stream finish")
                    .and_then(|()| self.schedule_publish_stream_finalization(token));
                finish_live_blob_ledger_command(
                    result,
                    response,
                    admission,
                    "blob stream finish",
                    "live Blob stream finish failed a durable invariant",
                )
            }
            SelectedBlobCommand::ReadPage { request, response } => {
                let mut fatal = None;
                let result =
                    self.read_page_with_admission(request, admission, Some(&response), &mut fatal);
                if let Some(error) = fatal {
                    drop(response);
                    Err(error)
                } else {
                    if admission.load(Ordering::Acquire) {
                        if response.send(result).is_err() {
                            self.finish_read_cache();
                        }
                    } else {
                        drop(result);
                        self.finish_read_cache();
                        _ = response.send(Err(actor_unavailable("blob read page")));
                    }
                    Ok(())
                }
            }
            SelectedBlobCommand::Subscribe { request, response } => {
                let result = self.subscribe(request);
                finish_live_blob_ledger_command(
                    result,
                    response,
                    admission,
                    "blob subscribe",
                    "live Blob subscription mutation failed a durable invariant",
                )
            }
            SelectedBlobCommand::Poll { request, response } => {
                let result = self.poll(request);
                finish_live_blob_ledger_command(
                    result,
                    response,
                    admission,
                    "blob poll",
                    "live Blob delivery poll lost an exact authenticated source/depot claim",
                )
            }
            SelectedBlobCommand::Acknowledge {
                subscription,
                publication,
                token,
                response,
            } => {
                let result = self.acknowledge(subscription, publication, token);
                finish_live_blob_ledger_command(
                    result,
                    response,
                    admission,
                    "blob acknowledge",
                    "live Blob acknowledgement failed a durable ledger invariant",
                )
            }
            SelectedBlobCommand::Unsubscribe {
                subscription,
                response,
            } => {
                let result = self.unsubscribe(subscription);
                finish_live_blob_ledger_command(
                    result,
                    response,
                    admission,
                    "blob unsubscribe",
                    "live Blob subscription removal failed a durable ledger invariant",
                )
            }
            SelectedBlobCommand::DeliveryStatus { response } => {
                let result = self.delivery_status();
                finish_live_blob_ledger_command(
                    result,
                    response,
                    admission,
                    "blob delivery status",
                    "live Blob delivery status failed a durable ledger invariant",
                )
            }
            SelectedBlobCommand::TransferStatus { response } => {
                let result = self.transfer_status();
                finish_live_blob_ledger_command(
                    result,
                    response,
                    admission,
                    "blob transfer status",
                    "live Blob transfer status failed a durable/network invariant",
                )
            }
            SelectedBlobCommand::InspectPublication { request, response } => {
                let result = self.inspect_publication(request);
                finish_live_blob_ledger_command(
                    result,
                    response,
                    admission,
                    "blob publication status",
                    "live Blob publication status failed a durable invariant",
                )
            }
            SelectedBlobCommand::CapacityStatus { response } => {
                let result = self.capacity_status();
                finish_live_blob_ledger_command(
                    result,
                    response,
                    admission,
                    "blob capacity status",
                    "live Blob capacity status failed a durable invariant",
                )
            }
        }
    }

    /// Waits for commands, abandoned-upload cleanup, or fatal promotion results.
    /// The durable reservation and checkpoint remain available for exact resume.
    pub(crate) async fn next_live_command<T>(
        &mut self,
        commands: &mut mpsc::Receiver<T>,
    ) -> Result<Option<T>, NodeError> {
        loop {
            self.pack_promotion_pool.check_fatal()?;
            self.cleanup_abandoned_publish_streams();
            let command = commands.recv();
            tokio::pin!(command);
            #[cfg(test)]
            let command = std::future::poll_fn(|cx| {
                let poll = std::future::Future::poll(command.as_mut(), cx);
                if let Some(observer) = &self.live_command_wait_observer {
                    match &poll {
                        std::task::Poll::Pending => {
                            _ = observer.send(BlobLiveWaitObservation::Idle);
                        }
                        std::task::Poll::Ready(None) => {
                            _ = observer.send(BlobLiveWaitObservation::Closed);
                        }
                        _ => {}
                    }
                }
                poll
            });
            tokio::select! {
                command = command => {
                    self.pack_promotion_pool.check_fatal()?;
                    return Ok(command);
                },
                () = self.pack_promotion_pool.failure.wake.notified() => {},
                () = self.publish_stream_cleanup.notified() => {}
            }
        }
    }

    pub(crate) fn join_live_promotions(&mut self) -> Result<(), NodeError> {
        self.pack_promotion_pool.shutdown();
        self.pack_promotion_pool.check_fatal()
    }

    fn cleanup_abandoned_publish_streams(&mut self) {
        self.live_publish_sessions.retain(|token, session| {
            if session.strong_count() != 0 {
                return true;
            }
            self.publish_streams.remove(token);
            self.completed_publish_streams.remove(token);
            false
        });
    }

    fn require_publish_session(
        &self,
        token: [u8; 32],
        session: &Arc<BlobPublishStreamSession>,
        operation: &'static str,
    ) -> Result<(), ApplicationError> {
        if self
            .live_publish_sessions
            .get(&token)
            .is_some_and(|current| current.ptr_eq(&Arc::downgrade(session)))
        {
            Ok(())
        } else {
            Err(ApplicationError::new(
                ApplicationErrorKind::NotFound,
                operation,
            ))
        }
    }

    /// Authenticated local Blob publisher identity.
    pub fn identity(&self) -> NodeId {
        self.verifier.identity()
    }

    /// Stable mission authority bound to provisioning, redb, and the depot.
    pub const fn mission_authority(&self) -> NodeId {
        self.mission.mission_authority_id()
    }

    fn open_publish_stream_inner(
        &mut self,
        request: BlobPublishStreamRequest,
    ) -> Result<OpenedBlobPublishStream, ApplicationError> {
        validate_live_publish_request(&request.publication)?;
        if request.total_len > MAX_SELECTED_BLOB_STREAM_BYTES {
            return Err(ApplicationError::new(
                ApplicationErrorKind::ResourceLimit,
                "blob stream open",
            ));
        }
        let operation = BlobOperationKey::new(request.publication.operation_key.clone())
            .map_err(|error| application_error("blob stream open", error.into()))?;
        let token =
            *local_blob_publication_stream_id(self.identity(), operation.as_bytes()).as_bytes();
        self.finalizing_publish_streams
            .retain(|_, job| job.strong_count() != 0);
        if let Some(active) = self
            .finalizing_publish_streams
            .get(&token)
            .and_then(Weak::upgrade)
        {
            return Err(ApplicationError::new(
                if *active == request {
                    ApplicationErrorKind::StateUnavailable
                } else {
                    ApplicationErrorKind::Conflict
                },
                "blob stream open",
            ));
        }
        if let Some(mut stream) = self.publish_streams.remove(&token) {
            if stream.request != request.publication
                || stream.options != request.options
                || stream.total_len != request.total_len
            {
                self.publish_streams.insert(token, stream);
                return Err(ApplicationError::new(
                    ApplicationErrorKind::Conflict,
                    "blob stream open",
                ));
            }
            if let Some(map_pool) = stream.map_pool.take() {
                map_pool.shutdown().map_err(blob_stream_pipeline_error)?;
            }
        }
        let policy = self.current_policy("blob stream open")?;
        let epoch = self.active_epoch(&request.publication.scope, "blob stream open")?;
        self.require_blob_grants(
            &request.publication.topic,
            &request.publication.scope,
            epoch,
            "blob stream open",
        )?;
        let owner = BlobOperationOwner::new(self.identity(), operation.clone());
        let upload_request = BlobUploadRequest {
            owner: owner.clone(),
            topic: request.publication.topic.clone(),
            scope: request.publication.scope.clone(),
            priority: request.publication.priority,
            ttl_ms: request.options.ttl_ms(),
            media_type: request.publication.media_type.clone(),
            schema_id: request.publication.schema_id.clone(),
            total_len: request.total_len,
        };
        let existing_upload = self
            .store
            .resume_blob_upload(&owner)
            .map_err(|error| application_error("blob stream open", error.into()))?;
        // Finite operation retries must advance receiver-local custody before
        // resolving the completed owner mapping. Otherwise an exact retry can
        // return a publication which expired since its previous operation.
        let initial_custody = self.finite_publish_initial_sample(request.options)?;
        #[cfg(test)]
        if std::mem::replace(&mut self.live_operation_preflight_coherence_fault, false) {
            return Err(ApplicationError::new(
                ApplicationErrorKind::Integrity,
                "blob stream open",
            ));
        }
        if let Some(stored) = self
            .store
            .blob_for_owner_with_policy(&policy, &owner)
            .map_err(|error| application_error("blob stream open", error.into()))?
        {
            let (result, plaintext_root) =
                self.completed_blob_upload_result(&stored, &request, epoch, token)?;
            if let Some((reservation, _)) = existing_upload {
                self.store
                    .complete_blob_upload(&reservation, stored.transfer_id)
                    .map_err(|error| application_error("blob stream open", error.into()))?;
            }
            self.completed_publish_streams.insert(
                token,
                CompletedBlobPublishStream {
                    request: request.clone(),
                    result,
                    plaintext_root,
                },
            );
            return Ok(OpenedBlobPublishStream {
                token,
                progress: BlobPublishProgress {
                    accepted_offset: request.total_len,
                    durable_offset: request.total_len,
                },
            });
        }
        let first = self.reserve_profile5_publish_stream(
            &policy,
            &upload_request,
            &request,
            initial_custody,
            epoch,
        );
        let (reservation, checkpoint, open) = match first {
            Ok(reserved) => reserved,
            Err(error) if blob_capacity_gc_target(&error).is_some() => {
                let source_route_cache = Arc::clone(&self.source_route_cache);
                let lifecycle = source_route_cache
                    .lock_blob_lifecycle()
                    .map_err(|error| application_error("blob stream open", error))?;
                if !self.recover_native_capacity_while_locked(
                    &source_route_cache,
                    &lifecycle,
                    &error,
                    &request,
                )? {
                    return Err(blob_store_application_error("blob stream open", error));
                }
                match self.reserve_profile5_publish_stream(
                    &policy,
                    &upload_request,
                    &request,
                    initial_custody,
                    epoch,
                ) {
                    Ok(reserved) => reserved,
                    Err(retry) if equivalent_blob_capacity_error(&error, &retry) => {
                        return Err(blob_store_application_error("blob stream open", error));
                    }
                    Err(retry) => {
                        return Err(application_error("blob stream open", retry.into()));
                    }
                }
            }
            Err(error) => return Err(application_error("blob stream open", error.into())),
        };
        let (writer, map_pool) = if checkpoint.profile5_completion().is_some() {
            (None, None)
        } else {
            let sealer = self
                .verifier
                .blob_stream_segment_sealer(&open)
                .map_err(|error| application_error("blob stream open", error.into()))?;
            let writer = self
                .store
                .open_blob_upload_writer(&reservation, &checkpoint)
                .map_err(|error| application_error("blob stream open", error.into()))?;
            (Some(writer), Some(blob_stream_map_pool(&open, &sealer)?))
        };
        let durable_offset = checkpoint.durable_plaintext_offset();
        let next_segment_index = checkpoint
            .durable_pack_checkpoint()
            .map_or(0, |checkpoint| checkpoint.next_index());
        self.publish_streams.insert(
            token,
            LocalBlobPublishStream {
                reservation,
                checkpoint,
                open,
                writer,
                request: request.publication,
                options: request.options,
                total_len: request.total_len,
                accepted_offset: durable_offset,
                pending: Zeroizing::new(Vec::with_capacity(BLOB_STREAM_SEGMENT_BYTES)),
                map_pool,
                mapped: BTreeMap::new(),
                next_map_index: next_segment_index,
                next_sink_index: next_segment_index,
                mapped_segments: next_segment_index,
                checkpoint_segments: LocalBlobPublishStream::production_checkpoint_segments(),
            },
        );
        Ok(OpenedBlobPublishStream {
            token,
            progress: BlobPublishProgress {
                accepted_offset: durable_offset,
                durable_offset,
            },
        })
    }

    fn reserve_profile5_publish_stream(
        &mut self,
        policy: &ControlPolicySnapshot,
        upload_request: &BlobUploadRequest,
        request: &BlobPublishStreamRequest,
        initial_custody: Option<CustodySample>,
        epoch: u64,
    ) -> Result<
        (
            BlobUploadReservation,
            BlobUploadCheckpoint,
            VerifiedBlobStreamOpen,
        ),
        StoreError,
    > {
        #[cfg(test)]
        {
            self.publish_attempts = self.publish_attempts.saturating_add(1);
            if let Some(error) = self.injected_capacity_failures.pop_front() {
                return Err(error);
            }
        }
        let policy_revision = policy.head().map_or(1, |(revision, _)| revision);
        let authorization_digest = self
            .verifier
            .blob_stream_authorization_digest(&request.publication.scope, epoch)
            .ok_or_else(|| {
                StoreError::Blob(BlobStoreError::Verification(
                    "Profile-5 publisher lacks current Blob authorization".into(),
                ))
            })?;
        let publication = &request.publication;
        let mission_id = self.verifier.mission_authority_id();
        let verifier = &self.verifier;
        self.store.reserve_profile5_upload_with_policy(
            policy,
            upload_request,
            initial_custody,
            |semantic, authenticated| {
                if let Some(authenticated) = authenticated {
                    let verified =
                        verifier
                            .verify_blob_stream_open(authenticated)
                            .map_err(|error| {
                                StoreError::Blob(BlobStoreError::Verification(error.to_string()))
                            })?;
                    return Ok((verified, authenticated.to_vec()));
                }
                let mut publication_salt = [0_u8; 32];
                getrandom::fill(&mut publication_salt).map_err(|error| {
                    StoreError::Blob(BlobStoreError::Verification(error.to_string()))
                })?;
                let open = BlobStreamOpen::new(
                    local_blob_publication_stream_id(
                        upload_request.owner.publisher,
                        upload_request.owner.operation.as_bytes(),
                    ),
                    upload_request.owner.publisher,
                    upload_request.owner.operation.as_bytes().to_vec(),
                    mission_id,
                    semantic.counter(),
                    semantic.context().clone(),
                    publication.topic.clone(),
                    publication.scope.clone(),
                    CoreBlobMetadata::new(
                        publication.media_type.clone(),
                        publication.schema_id.clone(),
                    )
                    .map_err(|error| {
                        StoreError::Blob(BlobStoreError::Verification(error.to_string()))
                    })?,
                    publication.priority,
                    request.options.ttl_ms(),
                    initial_custody,
                    request.total_len,
                    epoch,
                    policy_revision,
                    authorization_digest,
                    publication_salt,
                )
                .map_err(|error| {
                    StoreError::Blob(BlobStoreError::Verification(error.to_string()))
                })?;
                let authenticated = verifier.seal_blob_stream_open(&open).map_err(|error| {
                    StoreError::Blob(BlobStoreError::Verification(error.to_string()))
                })?;
                let verified =
                    verifier
                        .verify_blob_stream_open(&authenticated)
                        .map_err(|error| {
                            StoreError::Blob(BlobStoreError::Verification(error.to_string()))
                        })?;
                Ok((verified, authenticated))
            },
        )
    }

    fn recover_native_capacity_while_locked(
        &mut self,
        source_route_cache: &AuthenticatedEventRouteCache,
        lifecycle: &std::sync::MutexGuard<'_, ()>,
        error: &StoreError,
        request: &BlobPublishStreamRequest,
    ) -> Result<bool, ApplicationError> {
        let Some(target) = blob_capacity_gc_target(error) else {
            return Ok(false);
        };
        #[cfg(not(test))]
        let _ = target;
        #[cfg(test)]
        {
            self.capacity_gc_attempts = self.capacity_gc_attempts.saturating_add(1);
            self.capacity_gc_targets.push(target);
        }
        let sample = self
            .custody_clock
            .sample()
            .map_err(|error| application_error("blob stream open", error))?;
        recover_local_blob_capacity_after_cleanup(
            &self.store,
            &self.verifier,
            source_route_cache,
            error,
            request.publication.priority,
            None,
            0,
            1,
            Some(sample),
            lifecycle,
        )
        .map_err(|error| application_error("blob stream open", error))
    }

    fn append_publish_stream_inner(
        &mut self,
        token: [u8; 32],
        offset: u64,
        bytes: Zeroizing<Vec<u8>>,
    ) -> Result<BlobPublishProgress, ApplicationError> {
        let policy = self.current_policy("blob stream write")?;
        let stream = self.publish_streams.get_mut(&token).ok_or_else(|| {
            ApplicationError::new(ApplicationErrorKind::NotFound, "blob stream write")
        })?;
        sink_mapped_stream_partitions(stream, false)?;
        let byte_len = u64::try_from(bytes.len()).map_err(|_| {
            ApplicationError::new(ApplicationErrorKind::InvalidRequest, "blob stream write")
        })?;
        let end = offset.checked_add(byte_len).ok_or_else(|| {
            ApplicationError::new(ApplicationErrorKind::InvalidRequest, "blob stream write")
        })?;
        if offset != stream.accepted_offset
            || bytes.is_empty()
            || bytes.len() > BLOB_STREAM_SEGMENT_BYTES
            || end > stream.total_len
            || stream.pending.len().saturating_add(bytes.len()) > BLOB_STREAM_SEGMENT_BYTES
        {
            return Err(ApplicationError::new(
                ApplicationErrorKind::InvalidRequest,
                "blob stream write",
            ));
        }
        stream.pending.extend_from_slice(&bytes);
        stream.accepted_offset = end;
        if stream.pending.len() == BLOB_STREAM_SEGMENT_BYTES || end == stream.total_len {
            let pending = std::mem::replace(
                &mut stream.pending,
                Zeroizing::new(Vec::with_capacity(BLOB_STREAM_SEGMENT_BYTES)),
            );
            stream
                .map_pool
                .as_ref()
                .expect("open stream map pool")
                .submit_unbudgeted(StreamPartition::new(
                    stream.next_map_index,
                    take_zeroizing_bytes(pending),
                ))
                .map_err(blob_stream_pipeline_error)?;
            stream.next_map_index += 1;
            let checkpoint_due = stream.map_checkpoint_due();
            sink_mapped_stream_partitions(stream, end == stream.total_len || checkpoint_due)?;
        }
        if stream.durable_checkpoint_due()
            || stream
                .writer
                .as_ref()
                .expect("incomplete stream writer")
                .plaintext_offset()
                == stream.total_len
        {
            let checkpoint = stream
                .writer
                .as_mut()
                .expect("incomplete stream writer")
                .checkpoint()
                .map_err(|error| blob_pack_application_error("blob stream write", error))?;
            stream.checkpoint = self
                .store
                .checkpoint_blob_upload(
                    &policy,
                    &stream.reservation,
                    stream.checkpoint.clone(),
                    checkpoint,
                )
                .map_err(|error| application_error("blob stream write", error.into()))?;
        }
        Ok(BlobPublishProgress {
            accepted_offset: stream.accepted_offset,
            durable_offset: stream.checkpoint.durable_plaintext_offset(),
        })
    }

    #[cfg_attr(not(test), allow(dead_code))]
    fn finish_publish_stream_inner(
        &mut self,
        token: [u8; 32],
    ) -> Result<BlobPublishResult, ApplicationError> {
        match self.schedule_publish_stream_finalization(token)? {
            BlobPublishFinalization::Completed(result) => Ok(result),
            BlobPublishFinalization::Scheduled(mut completion) => loop {
                match completion.try_recv() {
                    Ok(result) => break result,
                    Err(oneshot::error::TryRecvError::Empty) => {
                        // Promotion runs on its own bounded OS-thread pool. A
                        // synchronous caller may itself be inside Tokio, where
                        // `blocking_recv` would panic by nesting the runtime.
                        std::thread::park_timeout(std::time::Duration::from_micros(50));
                    }
                    Err(oneshot::error::TryRecvError::Closed) => {
                        break Err(actor_unavailable("blob stream finish"));
                    }
                }
            },
        }
    }

    fn schedule_publish_stream_finalization(
        &mut self,
        token: [u8; 32],
    ) -> Result<BlobPublishFinalization, ApplicationError> {
        match self.prepare_publish_stream_finalization(token)? {
            PreparedBlobPublishFinalization::Completed(result) => {
                Ok(BlobPublishFinalization::Completed(result))
            }
            PreparedBlobPublishFinalization::Pending(job) => self
                .pack_promotion_pool
                .try_submit(*job)
                .map(BlobPublishFinalization::Scheduled),
        }
    }

    fn prepare_publish_stream_finalization(
        &mut self,
        token: [u8; 32],
    ) -> Result<PreparedBlobPublishFinalization, ApplicationError> {
        self.finalizing_publish_streams
            .retain(|_, job| job.strong_count() != 0);
        if self.finalizing_publish_streams.contains_key(&token) {
            return Err(ApplicationError::new(
                ApplicationErrorKind::StateUnavailable,
                "blob stream finish",
            ));
        }
        if let Some(completed) = self.completed_publish_streams.remove(&token) {
            return Ok(PreparedBlobPublishFinalization::Completed(completed.result));
        }
        let mut stream = self.publish_streams.remove(&token).ok_or_else(|| {
            ApplicationError::new(ApplicationErrorKind::NotFound, "blob stream finish")
        })?;
        sink_mapped_stream_partitions(&mut stream, true)?;
        if stream.accepted_offset != stream.total_len
            || !stream.pending.is_empty()
            || stream.checkpoint.durable_plaintext_offset() != stream.total_len
        {
            self.publish_streams.insert(token, stream);
            return Err(ApplicationError::new(
                ApplicationErrorKind::InvalidRequest,
                "blob stream finish",
            ));
        }
        if let Some(map_pool) = stream.map_pool.take() {
            map_pool.shutdown().map_err(blob_stream_pipeline_error)?;
        }
        if stream.checkpoint.durable_pack_checkpoint().is_none() {
            let policy = self.current_policy("blob stream finish")?;
            let durable = stream
                .writer
                .as_mut()
                .expect("incomplete stream writer")
                .checkpoint()
                .map_err(|error| blob_pack_application_error("blob stream finish", error))?;
            stream.checkpoint = self
                .store
                .checkpoint_blob_upload(
                    &policy,
                    &stream.reservation,
                    stream.checkpoint.clone(),
                    durable,
                )
                .map_err(|error| application_error("blob stream finish", error.into()))?;
        }
        let finalizing = Arc::new(BlobPublishStreamRequest {
            publication: stream.request,
            options: stream.options,
            total_len: stream.total_len,
        });
        self.finalizing_publish_streams
            .insert(token, Arc::downgrade(&finalizing));
        let job = BlobPackPromotionJob::new(
            BlobPackPromotionAuthority {
                mission: self.mission.clone(),
                store: BlobPackPromotionStore::new(Arc::clone(&self.store)),
                custody_clock: self.custody_clock.clone(),
                source_route_cache: Arc::clone(&self.source_route_cache),
            },
            stream.reservation,
            stream.checkpoint,
            stream.open,
            stream.writer,
            finalizing,
        );
        #[cfg(test)]
        let job = job.with_test_gate(self.stream_pack_promotion_gate.clone());
        Ok(PreparedBlobPublishFinalization::Pending(Box::new(job)))
    }

    fn completed_blob_upload_result(
        &mut self,
        stored: &StoredBlob,
        request: &BlobPublishStreamRequest,
        current_epoch: u64,
        token: [u8; 32],
    ) -> Result<(BlobPublishResult, [u8; 32]), ApplicationError> {
        let source_route_cache = Arc::clone(&self.source_route_cache);
        let _lifecycle = source_route_cache
            .lock_blob_lifecycle()
            .map_err(|error| application_error("blob stream open", error))?;
        let (projection, retention) = self.completed_projection(stored, "blob stream open")?;
        let verified = source_route_cache
            .authenticated_profile5_blob_source(&self.verifier, &projection, retention)
            .map_err(|_| {
                ApplicationError::new(ApplicationErrorKind::Integrity, "blob stream open")
            })?;
        match self
            .store
            .open_profile5_pack_application_read(stored.variant_id)
        {
            Ok(session) => {
                self.require_profile5_stored_source_match(
                    stored,
                    &projection,
                    &session,
                    &verified,
                    "blob stream open",
                )?;
                let open = verified.publication().publication().open();
                let commitment = verified.physical_commitment().commitment();
                let metadata = open.metadata();
                if open.stream_id().as_bytes() != &token
                    || open.publisher() != self.identity()
                    || open.operation_key() != request.publication.operation_key
                    || open.mission_id() != &self.mission_authority()
                    || commitment.blob_id() != stored.blob_id
                    || commitment.total_len() != open.total_len()
                    || stored.header.stamp.dot.publisher != open.publisher()
                    || stored.header.stamp.dot.counter != open.publisher_counter()
                    || stored.header.topic != *open.topic()
                    || stored.header.scope != *open.scope()
                    || stored.header.priority != open.priority()
                    || stored.header.ttl_ms != open.ttl_ms()
                    || stored.header.key_epoch != open.content_epoch()
                    || open.content_epoch() > current_epoch
                    || !self
                        .verifier
                        .can_route_blob(open.scope(), open.content_epoch())
                    || !self.verifier.can_open_blob_content(
                        open.scope(),
                        open.topic(),
                        open.content_epoch(),
                    )
                {
                    return Err(ApplicationError::new(
                        ApplicationErrorKind::Integrity,
                        "blob stream open",
                    ));
                }
                if open.topic() != &request.publication.topic
                    || open.scope() != &request.publication.scope
                    || open.priority() != request.publication.priority
                    || open.ttl_ms() != request.options.ttl_ms()
                    || open.total_len() != request.total_len
                    || metadata.media_type() != request.publication.media_type.as_deref()
                    || metadata.schema_id() != request.publication.schema_id
                {
                    return Err(ApplicationError::new(
                        ApplicationErrorKind::Conflict,
                        "blob stream open",
                    ));
                }
                Ok((
                    BlobPublishResult {
                        publication_id: Some(BlobStreamPublicationId::from_bytes(token)?),
                        id: BlobId::from_core(commitment.blob_id()),
                        publisher: open.publisher(),
                        publisher_counter: open.publisher_counter(),
                        priority: open.priority(),
                        ttl_ms: open.ttl_ms(),
                        total_len: open.total_len(),
                        media_type: metadata.media_type().map(str::to_owned),
                        schema_id: metadata.schema_id().to_vec(),
                        acceptance_marker: stored.acceptance_marker,
                        inserted: false,
                    },
                    *commitment.plaintext_root(),
                ))
            }
            Err(StoreError::Blob(BlobStoreError::NotFound)) => {
                Err(incompatible_profile5_storage("blob stream open"))
            }
            Err(error) => Err(application_error("blob stream open", error.into())),
        }
    }

    /// Streams, encrypts, and durably publishes one immutable Blob.
    ///
    /// Plaintext is read once through the bounded Profile-5 map/reorder/sink
    /// pipeline. Each 1-MiB segment becomes one independently authenticated
    /// `ASTRBS02` pack record, and those same records are the network DATA
    /// units. A semantic publication becomes visible only after the complete
    /// native pack, source envelope, and operation mapping commit atomically.
    pub fn publish<R: Read + Seek>(
        &mut self,
        request: BlobPublishRequest,
        source: &mut R,
    ) -> Result<BlobPublishResult, ApplicationError> {
        self.publish_with_options(request, BlobPublishOptions::durable(), source)
    }

    /// Streams, encrypts, and durably publishes one immutable Blob with an explicit lifetime.
    pub fn publish_with_options<R: Read + Seek>(
        &mut self,
        request: BlobPublishRequest,
        options: BlobPublishOptions,
        source: &mut R,
    ) -> Result<BlobPublishResult, ApplicationError> {
        self.publish_native_reader(
            request,
            options,
            source,
            MAX_SELECTED_BLOB_STREAM_BYTES,
            None,
            None,
        )
    }

    /// Executes one live publication after accepting ownership of its file.
    #[cfg(test)]
    pub(crate) fn publish_live(
        &mut self,
        request: BlobPublishRequest,
        source: fs::File,
    ) -> Result<BlobPublishResult, ApplicationError> {
        let admission = AtomicBool::new(true);
        let mut fatal = None;
        let result = self.publish_live_with_admission(
            request,
            BlobPublishOptions::durable(),
            source,
            &admission,
            &mut fatal,
        );
        if let Some(error) = fatal {
            Err(application_error("blob publish", error))
        } else {
            result
        }
    }

    fn publish_live_with_admission(
        &mut self,
        request: BlobPublishRequest,
        options: BlobPublishOptions,
        mut source: fs::File,
        admission: &AtomicBool,
        fatal: &mut Option<NodeError>,
    ) -> Result<BlobPublishResult, ApplicationError> {
        if !admission.load(Ordering::Acquire) {
            return Err(actor_unavailable("blob publish"));
        }
        if source
            .stream_position()
            .map_err(|error| application_error("blob publish", error.into()))?
            != 0
        {
            return Err(ApplicationError::new(
                ApplicationErrorKind::InvalidRequest,
                "blob publish",
            ));
        }
        let metadata = source
            .metadata()
            .map_err(|error| application_error("blob publish", error.into()))?;
        if !metadata.is_file() || metadata.len() == 0 {
            return Err(ApplicationError::new(
                ApplicationErrorKind::InvalidRequest,
                "blob publish",
            ));
        }
        if metadata.len() > MAX_SELECTED_LIVE_BLOB_BYTES {
            return Err(ApplicationError::new(
                ApplicationErrorKind::ResourceLimit,
                "blob publish",
            ));
        }
        let expected_len = metadata.len();
        #[cfg(not(test))]
        let result = self.publish_native_reader(
            request,
            options,
            &mut source,
            MAX_SELECTED_LIVE_BLOB_BYTES,
            Some(expected_len),
            Some(admission),
        );
        #[cfg(test)]
        let result = {
            let mut counted = TestReadCounter {
                inner: &mut source,
                bytes_read: 0,
            };
            let result = self.publish_native_reader(
                request,
                options,
                &mut counted,
                MAX_SELECTED_LIVE_BLOB_BYTES,
                Some(expected_len),
                Some(admission),
            );
            self.last_live_publish_source_bytes_read = counted.bytes_read;
            result
        };
        if result
            .as_ref()
            .is_err_and(|error| error.kind() == ApplicationErrorKind::Integrity)
        {
            *fatal = Some(NodeError::FatalBlobCoherence(
                "live native Blob publication failed a durable invariant".into(),
            ));
        }
        result
    }

    fn publish_native_reader<R: Read + Seek>(
        &mut self,
        request: BlobPublishRequest,
        options: BlobPublishOptions,
        source: &mut R,
        max_len: u64,
        expected_len: Option<u64>,
        admission: Option<&AtomicBool>,
    ) -> Result<BlobPublishResult, ApplicationError> {
        if source
            .stream_position()
            .map_err(|error| application_error("blob publish", error.into()))?
            != 0
        {
            return Err(ApplicationError::new(
                ApplicationErrorKind::InvalidRequest,
                "blob publish",
            ));
        }
        let total_len = source
            .seek(std::io::SeekFrom::End(0))
            .map_err(|error| application_error("blob publish", error.into()))?;
        source
            .seek(std::io::SeekFrom::Start(0))
            .map_err(|error| application_error("blob publish", error.into()))?;
        if total_len == 0 {
            return Err(ApplicationError::new(
                ApplicationErrorKind::InvalidRequest,
                "blob publish",
            ));
        }
        if total_len > max_len {
            return Err(ApplicationError::new(
                ApplicationErrorKind::ResourceLimit,
                "blob publish",
            ));
        }
        if expected_len.is_some_and(|expected| expected != total_len) {
            return Err(ApplicationError::new(
                ApplicationErrorKind::Conflict,
                "blob publish",
            ));
        }
        if admission.is_some_and(|admission| !admission.load(Ordering::Acquire)) {
            return Err(actor_unavailable("blob publish"));
        }

        let opened = self.open_publish_stream_inner(BlobPublishStreamRequest {
            publication: request,
            options,
            total_len,
        })?;
        let result = (|| {
            let mut offset = opened.progress.accepted_offset;
            self.verify_native_publish_retry_prefix(opened.token, source, offset, admission)?;
            source
                .seek(std::io::SeekFrom::Start(offset))
                .map_err(|error| application_error("blob publish", error.into()))?;
            while offset < total_len {
                if admission.is_some_and(|admission| !admission.load(Ordering::Acquire)) {
                    return Err(actor_unavailable("blob publish"));
                }
                let remaining = total_len - offset;
                let read_len = usize::try_from(remaining.min(BLOB_STREAM_SEGMENT_BYTES as u64))
                    .expect("bounded native Blob segment length");
                let mut bytes = Zeroizing::new(vec![0_u8; read_len]);
                source
                    .read_exact(&mut bytes)
                    .map_err(|error| application_error("blob publish", error.into()))?;
                let progress = self.append_publish_stream_inner(opened.token, offset, bytes)?;
                offset = progress.accepted_offset;
            }
            let observed_len = source
                .seek(std::io::SeekFrom::End(0))
                .map_err(|error| application_error("blob publish", error.into()))?;
            if observed_len != total_len
                || admission.is_some_and(|admission| !admission.load(Ordering::Acquire))
            {
                return Err(if observed_len != total_len {
                    ApplicationError::new(ApplicationErrorKind::Conflict, "blob publish")
                } else {
                    actor_unavailable("blob publish")
                });
            }
            self.finish_publish_stream_inner(opened.token)
                .map_err(|error| ApplicationError::new(error.kind(), "blob publish"))
        })();
        // One-shot calls own their runtime state only for this call. The Store
        // retains the reservation/checkpoint needed by an exact later retry.
        self.publish_streams.remove(&opened.token);
        self.completed_publish_streams.remove(&opened.token);
        self.live_publish_sessions.remove(&opened.token);
        result
    }

    /// Verifies bytes skipped by a resumed one-shot publication against the
    /// exact durable Profile-5 pack. Fresh publications remain single-pass:
    /// this path is entered only when the Store reports a nonzero durable
    /// offset. It prevents a changed file from being silently combined with a
    /// prior durable prefix or accepted as an exact completed-operation retry.
    fn verify_native_publish_retry_prefix<R: Read>(
        &mut self,
        token: [u8; 32],
        source: &mut R,
        prefix_len: u64,
        admission: Option<&AtomicBool>,
    ) -> Result<(), ApplicationError> {
        if prefix_len == 0 {
            return Ok(());
        }
        if admission.is_some_and(|admission| !admission.load(Ordering::Acquire)) {
            return Err(actor_unavailable("blob publish"));
        }

        let (total_len, expected_prefix, expected_root) =
            if let Some(stream) = self.publish_streams.get(&token) {
                let checkpoint = stream
                    .checkpoint
                    .durable_pack_checkpoint()
                    .ok_or_else(|| {
                        ApplicationError::new(ApplicationErrorKind::Integrity, "blob publish")
                    })?
                    .clone();
                if checkpoint.plaintext_offset() != prefix_len {
                    return Err(ApplicationError::new(
                        ApplicationErrorKind::Integrity,
                        "blob publish",
                    ));
                }
                (
                    stream.total_len,
                    Some(checkpoint.frontier().plaintext_commitment()),
                    None,
                )
            } else {
                let completed = self.completed_publish_streams.get(&token).ok_or_else(|| {
                    ApplicationError::new(ApplicationErrorKind::Integrity, "blob publish")
                })?;
                if completed.request.total_len != prefix_len {
                    return Err(ApplicationError::new(
                        ApplicationErrorKind::Integrity,
                        "blob publish",
                    ));
                }
                (
                    completed.request.total_len,
                    None,
                    Some(completed.plaintext_root),
                )
            };

        let mut frontier = BlobStreamPlaintextFrontier::new();
        let mut offset = 0_u64;
        let mut index = 0_u64;
        while offset < prefix_len {
            if admission.is_some_and(|admission| !admission.load(Ordering::Acquire)) {
                return Err(actor_unavailable("blob publish"));
            }
            let read_len =
                usize::try_from((prefix_len - offset).min(BLOB_STREAM_SEGMENT_BYTES as u64))
                    .expect("bounded Profile-5 retry partition");
            let mut bytes = Zeroizing::new(vec![0_u8; read_len]);
            source
                .read_exact(&mut bytes)
                .map_err(|error| application_error("blob publish", error.into()))?;
            frontier
                .append(index, offset, total_len, &bytes)
                .map_err(|error| blob_core_error("blob publish", error))?;
            offset = offset.checked_add(read_len as u64).ok_or_else(|| {
                ApplicationError::new(ApplicationErrorKind::Integrity, "blob publish")
            })?;
            index += 1;
        }
        let matches = if let Some(expected) = expected_root {
            frontier
                .finish(total_len)
                .map_err(|error| blob_core_error("blob publish", error))?
                == expected
        } else {
            frontier.checkpoint().plaintext_commitment()
                == expected_prefix.expect("resumed upload has a prefix commitment")
        };
        if !matches {
            return Err(ApplicationError::new(
                ApplicationErrorKind::Conflict,
                "blob publish",
            ));
        }
        Ok(())
    }

    fn finite_publish_initial_sample(
        &self,
        options: BlobPublishOptions,
    ) -> Result<Option<CustodySample>, ApplicationError> {
        if options.ttl_ms().is_none() {
            return Ok(None);
        }
        if !self.custody_clock.supports_finite_ttl() {
            return Err(ApplicationError::new(
                ApplicationErrorKind::UnsupportedValue,
                "blob publish",
            ));
        }
        self.observe_current_blob_custody_sample("blob stream open")
            .map(Some)
    }

    /// Idempotently creates one durable metadata-only Blob subscription.
    ///
    /// The selector is local delivery intent only. It neither mutates the
    /// runtime's network interests nor grants route/content authority.
    pub fn subscribe(
        &mut self,
        request: BlobSubscriptionRequest,
    ) -> Result<BlobSubscription, ApplicationError> {
        let BlobSubscriptionRequest {
            operation_key,
            topic,
            scope,
            include_descendant_scopes,
        } = request;
        let key = BlobSubscriptionKey::new(operation_key)
            .map_err(|error| application_error("blob subscribe", error.into()))?;
        let policy = self.current_policy("blob subscribe")?;
        let epoch = self.active_epoch(&scope, "blob subscribe")?;
        self.require_blob_grants(&topic, &scope, epoch, "blob subscribe")?;
        let outcome = self
            .store
            .create_blob_subscription_with_policy(
                &policy,
                &key,
                BlobSubscriptionSpec {
                    topic,
                    scope,
                    include_descendant_scopes,
                },
            )
            .map_err(|error| application_error("blob subscribe", error.into()))?;
        Ok(BlobSubscription {
            id: BlobSubscriptionId::from_store(outcome.id),
            inserted: outcome.inserted,
        })
    }

    /// Polls freshly authenticated immutable-publication metadata.
    ///
    /// Every complete matching candidate is rebound to its startup-authenticated
    /// source claim and current policy. A deliverable candidate is then exact-
    /// loaded, source/content authenticated, and checked against its completed
    /// depot capability before the Store atomically advances its retry. No Blob
    /// plaintext is opened or returned by this operation.
    pub fn poll(&mut self, request: BlobPollRequest) -> Result<BlobDeliveryPage, ApplicationError> {
        let request = request.validate()?;
        for _ in 0..MAX_SELECTED_BLOB_PLAN_RETRIES {
            let source_route_cache = Arc::clone(&self.source_route_cache);
            let _lifecycle = source_route_cache
                .lock_blob_lifecycle()
                .map_err(|error| application_error("blob poll", error))?;
            self.observe_current_blob_custody_sample("blob poll")?;
            let policy = self.current_policy("blob poll")?;
            let plan = self
                .store
                .prepare_blob_subscription_poll_with_policy(
                    &policy,
                    request.subscription.into_store(),
                    request.delivery_limit,
                    request.scan_limit,
                )
                .map_err(|error| application_error("blob poll", error.into()))?;
            let retirement_plan = self
                .store
                .prepare_blob_retirement_poll_with_policy(
                    &policy,
                    request.subscription.into_store(),
                    request.delivery_limit,
                )
                .map_err(|error| application_error("blob poll", error.into()))?;
            if plan.subscription() != request.subscription.into_store() {
                return Err(ApplicationError::new(
                    ApplicationErrorKind::Integrity,
                    "blob poll",
                ));
            }

            let spec = plan.spec();
            let mut seen = std::collections::BTreeSet::new();
            let mut verified = std::collections::BTreeMap::new();
            let mut selection = BlobSubscriptionPollSelection::default();
            for candidate in plan.candidates() {
                if candidate.acceptance_marker() == 0
                    || candidate
                        .pending_attempt()
                        .is_some_and(|attempt| attempt == 0)
                    || candidate
                        .acknowledged_attempt()
                        .is_some_and(|attempt| attempt == 0)
                    || (candidate.pending_attempt().is_some()
                        && candidate.acknowledged_attempt().is_some())
                {
                    return Err(ApplicationError::new(
                        ApplicationErrorKind::Integrity,
                        "blob poll",
                    ));
                }
                let projection = candidate.projection();
                let publication = BlobPublicationId::from_store(projection.semantic_id);
                if !seen.insert(publication) {
                    return Err(ApplicationError::new(
                        ApplicationErrorKind::Integrity,
                        "blob poll",
                    ));
                }
                let scope_matches = if spec.include_descendant_scopes {
                    spec.scope.contains(&projection.scope)
                } else {
                    spec.scope == projection.scope
                };
                if spec.topic != projection.topic || !scope_matches {
                    return Err(ApplicationError::new(
                        ApplicationErrorKind::Integrity,
                        "blob poll",
                    ));
                }
                let retention = BlobSourceRetention::Completed {
                    acceptance_marker: candidate.acceptance_marker(),
                };
                let current_epoch = self.active_epoch(&projection.scope, "blob poll")?;
                let revoked = self
                    .store
                    .is_control_principal_revoked(projection.publisher)
                    .map_err(|error| application_error("blob poll", error.into()))?;
                let granted = self
                    .verifier
                    .can_route_blob(&projection.scope, current_epoch)
                    && self.verifier.can_open_blob_content(
                        &projection.scope,
                        &projection.topic,
                        current_epoch,
                    );
                if revoked || projection.epoch != current_epoch || !granted {
                    selection.inactive.push(projection.semantic_id);
                    continue;
                }

                let stored = self
                    .store
                    .blob_by_semantic_id(projection.semantic_id)
                    .map_err(|error| application_error("blob poll", error.into()))?
                    .ok_or_else(|| {
                        ApplicationError::new(ApplicationErrorKind::Integrity, "blob poll")
                    })?;
                let (durable_projection, durable_retention) =
                    self.completed_projection(&stored, "blob poll")?;
                if durable_projection != *projection || durable_retention != retention {
                    return Err(ApplicationError::new(
                        ApplicationErrorKind::Integrity,
                        "blob poll",
                    ));
                }
                match self
                    .store
                    .open_profile5_pack_application_read(stored.variant_id)
                {
                    Ok(session) => {
                        let verified_source = self.verify_profile5_stored_source(
                            &stored,
                            projection,
                            &session,
                            "blob poll",
                        )?;
                        let open = verified_source.publication().publication().open();
                        let commitment = verified_source.physical_commitment().commitment();
                        let metadata = open.metadata();
                        if stored.acceptance_marker != candidate.acceptance_marker() {
                            return Err(ApplicationError::new(
                                ApplicationErrorKind::Integrity,
                                "blob poll",
                            ));
                        }
                        let delivery = VerifiedBlobDeliveryMetadata {
                            publication,
                            id: BlobId::from_core(commitment.blob_id()),
                            publisher: open.publisher(),
                            publisher_counter: open.publisher_counter(),
                            topic: open.topic().clone(),
                            scope: open.scope().clone(),
                            priority: open.priority(),
                            ttl_ms: open.ttl_ms(),
                            total_len: open.total_len(),
                            media_type: metadata.media_type().map(str::to_owned),
                            schema_id: metadata.schema_id().to_vec(),
                            acceptance_marker: stored.acceptance_marker,
                        };
                        // Poll returns authenticated metadata only. Keeping a
                        // pack read lease per candidate would make page size
                        // depend on the depot's concurrent-reader limit.
                        drop(session);
                        if verified.insert(publication, delivery).is_some() {
                            return Err(ApplicationError::new(
                                ApplicationErrorKind::Integrity,
                                "blob poll",
                            ));
                        }
                        selection.deliverable.push(projection.semantic_id);
                        continue;
                    }
                    Err(StoreError::Blob(BlobStoreError::NotFound)) => {
                        return Err(incompatible_profile5_storage("blob poll"));
                    }
                    Err(error) => return Err(application_error("blob poll", error.into())),
                }
            }

            // Retirements are one delivery family and always win the page. Verify
            // the content plan first so the combined lookahead is exact rather
            // than merely reporting that unverified content candidates exist.
            let content_has_more = plan.candidates().iter().any(|candidate| {
                selection
                    .deliverable
                    .contains(&candidate.projection().semantic_id)
                    && candidate.acknowledged_attempt().is_none()
            });
            #[cfg(test)]
            if std::mem::replace(&mut self.live_poll_coherence_fault, false) {
                return Err(ApplicationError::new(
                    ApplicationErrorKind::Integrity,
                    "blob poll",
                ));
            }
            self.observe_current_blob_custody_sample("blob poll")?;
            let rechecked_plan = self
                .store
                .prepare_blob_subscription_poll_with_policy(
                    &policy,
                    request.subscription.into_store(),
                    request.delivery_limit,
                    request.scan_limit,
                )
                .map_err(|error| application_error("blob poll", error.into()))?;
            let rechecked_retirement_plan = self
                .store
                .prepare_blob_retirement_poll_with_policy(
                    &policy,
                    request.subscription.into_store(),
                    request.delivery_limit,
                )
                .map_err(|error| application_error("blob poll", error.into()))?;
            if rechecked_plan != plan || rechecked_retirement_plan != retirement_plan {
                continue;
            }
            let retirement_page = match self
                .store
                .commit_blob_retirement_poll_with_policy(&policy, &retirement_plan)
            {
                Ok(page) => page,
                Err(
                    StoreError::BlobSubscriptionPlanChanged
                    | StoreError::BlobSelectorGenerationChanged
                    | StoreError::ControlPolicyChanged,
                ) => continue,
                Err(error) => return Err(application_error("blob poll", error.into())),
            };
            if !retirement_page.deliveries.is_empty() {
                let has_more = retirement_page.has_more || content_has_more;
                let deliveries = retirement_page
                    .deliveries
                    .into_iter()
                    .map(|delivery| {
                        BlobDeliveryItem::Retirement(BlobRetirementDelivery {
                            publication: BlobPublicationId::from_store(delivery.semantic_id()),
                            id: BlobId::from_core(delivery.blob_id()),
                            publisher: delivery.publisher(),
                            publisher_counter: delivery.publisher_counter(),
                            topic: delivery.topic().clone(),
                            scope: delivery.scope().clone(),
                            priority: delivery.priority(),
                            ttl_ms: delivery.ttl_ms(),
                            acceptance_marker: delivery.acceptance_marker(),
                            reason: delivery.reason(),
                            retirement_generation: delivery.retirement_generation(),
                            attempt: delivery.attempt(),
                            token: BlobDeliveryToken::from_store(delivery.token()),
                        })
                    })
                    .collect();
                return Ok(BlobDeliveryPage {
                    deliveries,
                    has_more,
                });
            }

            let committed = match self
                .store
                .commit_blob_subscription_poll_with_policy(&policy, &plan, &selection)
            {
                Ok(committed) => committed,
                Err(
                    StoreError::BlobSubscriptionPlanChanged
                    | StoreError::BlobSelectorGenerationChanged
                    | StoreError::ControlPolicyChanged,
                ) => continue,
                Err(error) => return Err(application_error("blob poll", error.into())),
            };
            let mut deliveries = Vec::with_capacity(committed.deliveries.len());
            for delivery in committed.deliveries {
                let publication = BlobPublicationId::from_store(delivery.semantic_id);
                let metadata = verified.remove(&publication).ok_or_else(|| {
                    ApplicationError::new(ApplicationErrorKind::Integrity, "blob poll")
                })?;
                if metadata.publication != publication
                    || metadata.acceptance_marker != delivery.acceptance_marker
                    || delivery.attempt == 0
                {
                    return Err(ApplicationError::new(
                        ApplicationErrorKind::Integrity,
                        "blob poll",
                    ));
                }
                #[cfg(test)]
                if std::mem::replace(&mut self.live_poll_postcommit_completion_fault, false) {
                    return Err(ApplicationError::new(
                        ApplicationErrorKind::Integrity,
                        "blob poll",
                    ));
                }
                deliveries.push(BlobDeliveryItem::Content(
                    metadata.into_delivery(delivery.attempt, delivery.token),
                ));
            }
            return Ok(BlobDeliveryPage {
                deliveries,
                has_more: committed.has_more,
            });
        }
        Err(ApplicationError::new(
            ApplicationErrorKind::PolicyUnsettled,
            "blob poll",
        ))
    }

    /// Idempotently acknowledges one exact token-bound Blob delivery.
    pub fn acknowledge(
        &mut self,
        subscription: BlobSubscriptionId,
        publication: BlobPublicationId,
        token: BlobDeliveryToken,
    ) -> Result<BlobAcknowledgement, ApplicationError> {
        let source_route_cache = Arc::clone(&self.source_route_cache);
        let _lifecycle = source_route_cache
            .lock_blob_lifecycle()
            .map_err(|error| application_error("blob acknowledge", error))?;
        self.observe_current_blob_custody_sample("blob acknowledge")?;
        let policy = self.current_policy("blob acknowledge")?;
        let token = token.into_store();
        let acknowledged = if token.is_retirement() {
            self.store.acknowledge_blob_retirement_with_policy(
                &policy,
                subscription.into_store(),
                publication.into_store(),
                token,
            )
        } else {
            self.store.acknowledge_blob_delivery_with_policy(
                &policy,
                subscription.into_store(),
                publication.into_store(),
                token,
            )
        }
        .map_err(|error| application_error("blob acknowledge", error.into()))?;
        match acknowledged {
            StoreBlobDeliveryAck::Acknowledged => Ok(BlobAcknowledgement::Acknowledged),
            StoreBlobDeliveryAck::AlreadyAcknowledged => {
                Ok(BlobAcknowledgement::AlreadyAcknowledged)
            }
        }
    }

    /// Idempotently removes one Blob selector and its delivery ledger.
    pub fn unsubscribe(
        &mut self,
        subscription: BlobSubscriptionId,
    ) -> Result<BlobUnsubscribe, ApplicationError> {
        let policy = self.current_policy("blob unsubscribe")?;
        let BlobSubscriptionRemoveOutcome { removed, .. } = self
            .store
            .remove_blob_subscription_with_policy(&policy, subscription.into_store())
            .map_err(|error| application_error("blob unsubscribe", error.into()))?;
        Ok(if removed {
            BlobUnsubscribe::Removed
        } else {
            BlobUnsubscribe::AlreadyAbsent
        })
    }

    /// Returns audited local Blob selector and delivery-ledger counts.
    pub fn delivery_status(&mut self) -> Result<BlobDeliveryStatus, ApplicationError> {
        let _policy = self.current_policy("blob delivery status")?;
        let stats = self
            .store
            .blob_subscription_stats()
            .map_err(|error| application_error("blob delivery status", error.into()))?;
        Ok(BlobDeliveryStatus {
            subscriptions: stats.subscriptions,
            pending_deliveries: stats.pending_deliveries,
            acknowledged_deliveries: stats.acknowledged_deliveries,
            delivery_cursors: stats.delivery_cursors,
            selector_generation: stats.selector_generation,
        })
    }

    /// Returns audited local storage counts and authenticated pending transfer progress.
    ///
    /// The snapshot reports durable local work only. It does not claim that any
    /// peer has, lacks, or will deliver a Blob.
    pub fn transfer_status(&mut self) -> Result<BlobTransferStatus, ApplicationError> {
        let policy = self.current_policy("blob transfer status")?;
        let source_route_cache = Arc::clone(&self.source_route_cache);
        let _lifecycle = source_route_cache
            .lock_blob_lifecycle()
            .map_err(|error| application_error("blob transfer status", error))?;
        let sample = self.observe_current_blob_custody_sample("blob transfer status")?;
        let snapshot = self
            .store
            .pending_blob_transfer_progress_with_policy(&policy)
            .map_err(|error| application_error("blob transfer status", error.into()))?;
        let gc = self
            .store
            .blob_gc_status(Some(sample))
            .map_err(|error| application_error("blob transfer status", error.into()))?;
        self.map_transfer_status(snapshot, gc)
    }

    pub fn inspect_publication(
        &mut self,
        request: BlobPublicationInspectionRequest,
    ) -> Result<BlobPublicationInspection, ApplicationError> {
        let policy = self.current_policy("blob publication status")?;
        // Authorize the requested selector before looking up any identity,
        // including absent, pending and retired publications.
        let epoch = self.active_epoch(&request.scope, "blob publication status")?;
        self.require_blob_grants(
            &request.topic,
            &request.scope,
            epoch,
            "blob publication status",
        )?;
        let source_route_cache = Arc::clone(&self.source_route_cache);
        let _lifecycle = source_route_cache
            .lock_blob_lifecycle()
            .map_err(|error| application_error("blob publication status", error))?;
        self.observe_current_blob_custody_sample("blob publication status")?;
        // A lifecycle operation is authoritative even while cleanup authority
        // for its provisional pack remains durably charged after a crash.
        let local_publication = match self.store.blob_for_local_publication_with_policy(
            &policy,
            request.publication_id.into_core(),
            &request.topic,
            &request.scope,
        ) {
            Ok(stored) => stored,
            Err(StoreError::Blob(BlobStoreError::ExpiredOrRetired)) => {
                return Ok(retired_blob_publication_inspection(request.publication_id));
            }
            Err(error) => {
                return Err(application_error("blob publication status", error.into()));
            }
        };
        if let Some(stored) = local_publication {
            let epoch = self.active_epoch(&request.scope, "blob publication status")?;
            self.require_blob_grants(
                &request.topic,
                &request.scope,
                epoch,
                "blob publication status",
            )?;
            match self
                .store
                .open_profile5_pack_application_read(stored.variant_id)
            {
                Ok(session) => {
                    let transfer_total_bytes = session.wire_len();
                    let (projection, _) =
                        self.completed_projection(&stored, "blob publication status")?;
                    let verified = self.verify_profile5_stored_source(
                        &stored,
                        &projection,
                        &session,
                        "blob publication status",
                    )?;
                    let open = verified.publication().publication().open();
                    let commitment = verified.physical_commitment().commitment();
                    if open.stream_id() != request.publication_id.into_core()
                        || open.topic() != &request.topic
                        || open.scope() != &request.scope
                        || open.content_epoch() > epoch
                        || commitment.blob_id() != stored.blob_id
                        || stored.header.stamp.dot.publisher != open.publisher()
                        || stored.header.stamp.dot.counter != open.publisher_counter()
                        || stored.header.key_epoch != open.content_epoch()
                    {
                        return Err(ApplicationError::new(
                            ApplicationErrorKind::Integrity,
                            "blob publication status",
                        ));
                    }
                    return Ok(BlobPublicationInspection {
                        publication_id: request.publication_id,
                        phase: BlobPublicationPhase::Available,
                        plaintext_total_bytes: open.total_len(),
                        durable_plaintext_bytes: open.total_len(),
                        transfer_total_bytes,
                        durable_transfer_bytes: transfer_total_bytes,
                        total_units: commitment.segment_count(),
                        durable_units: commitment.segment_count(),
                        blob_id: Some(BlobId::from_core(commitment.blob_id())),
                    });
                }
                Err(StoreError::Blob(BlobStoreError::NotFound)) => {
                    return Err(incompatible_profile5_storage("blob publication status"));
                }
                Err(error) => {
                    return Err(application_error("blob publication status", error.into()));
                }
            }
        }
        if let Some((reservation, checkpoint)) = self
            .store
            .resume_blob_upload_by_publication_id(request.publication_id.into_core())
            .map_err(|error| application_error("blob publication status", error.into()))?
        {
            let upload = reservation.request();
            if upload.topic != request.topic || upload.scope != request.scope {
                return Ok(missing_blob_publication_inspection(request.publication_id));
            }
            if reservation.control_policy() != &policy {
                return Err(ApplicationError::new(
                    ApplicationErrorKind::RequestRejected,
                    "blob publication status",
                ));
            }
            let epoch = self.active_epoch(&upload.scope, "blob publication status")?;
            self.require_blob_grants(
                &upload.topic,
                &upload.scope,
                epoch,
                "blob publication status",
            )?;
            if reservation.content_epoch() != epoch {
                return Err(ApplicationError::new(
                    ApplicationErrorKind::ExpiredOrRetired,
                    "blob publication status",
                ));
            }
            let durable_plaintext = checkpoint.durable_plaintext_offset();
            let transfer_total_bytes = profile5_transfer_total_bytes(upload.total_len)?;
            return Ok(BlobPublicationInspection {
                publication_id: request.publication_id,
                phase: if durable_plaintext == 0 {
                    BlobPublicationPhase::AwaitingData
                } else if durable_plaintext < upload.total_len {
                    BlobPublicationPhase::Receiving
                } else {
                    BlobPublicationPhase::ReadyToFinalize
                },
                plaintext_total_bytes: upload.total_len,
                durable_plaintext_bytes: durable_plaintext,
                transfer_total_bytes,
                durable_transfer_bytes: checkpoint
                    .durable_pack_checkpoint()
                    .map_or(0, |checkpoint| checkpoint.payload_len()),
                total_units: upload.total_len.div_ceil(BLOB_STREAM_SEGMENT_BYTES as u64),
                durable_units: checkpoint
                    .durable_pack_checkpoint()
                    .map_or(0, |checkpoint| checkpoint.next_index()),
                blob_id: None,
            });
        }
        // Incoming profile-5 publication identity is the authenticated source
        // transfer ID. Native pack upload state and its checkpoint journal are
        // the only pre-publication progress authority.
        let profile5_source =
            aster_redb_store::BlobTransferId::new(*request.publication_id.as_bytes());
        let received_publication = match self.store.blob_for_transfer_selector(
            profile5_source,
            &request.topic,
            &request.scope,
        ) {
            Ok(stored) => stored,
            Err(StoreError::Blob(BlobStoreError::ExpiredOrRetired)) => {
                return Ok(retired_blob_publication_inspection(request.publication_id));
            }
            Err(error) => {
                return Err(application_error("blob publication status", error.into()));
            }
        };
        if let Some(stored) = received_publication {
            let epoch = self.active_epoch(&request.scope, "blob publication status")?;
            self.require_blob_grants(
                &request.topic,
                &request.scope,
                epoch,
                "blob publication status",
            )?;
            match self
                .store
                .open_profile5_pack_application_read(stored.variant_id)
            {
                Ok(session) => {
                    let transfer_total_bytes = session.wire_len();
                    let (projection, _) =
                        self.completed_projection(&stored, "blob publication status")?;
                    let verified = self.verify_profile5_stored_source(
                        &stored,
                        &projection,
                        &session,
                        "blob publication status",
                    )?;
                    let open = verified.publication().publication().open();
                    let commitment = verified.physical_commitment().commitment();
                    if stored.transfer_id.as_bytes() != request.publication_id.as_bytes()
                        || open.topic() != &request.topic
                        || open.scope() != &request.scope
                        || open.content_epoch() > epoch
                        || commitment.blob_id() != stored.blob_id
                        || stored.header.stamp.dot.publisher != open.publisher()
                        || stored.header.stamp.dot.counter != open.publisher_counter()
                        || stored.header.key_epoch != open.content_epoch()
                    {
                        return Err(ApplicationError::new(
                            ApplicationErrorKind::Integrity,
                            "blob publication status",
                        ));
                    }
                    return Ok(BlobPublicationInspection {
                        publication_id: request.publication_id,
                        phase: BlobPublicationPhase::Available,
                        plaintext_total_bytes: open.total_len(),
                        durable_plaintext_bytes: open.total_len(),
                        transfer_total_bytes,
                        durable_transfer_bytes: transfer_total_bytes,
                        total_units: commitment.segment_count(),
                        durable_units: commitment.segment_count(),
                        blob_id: Some(BlobId::from_core(commitment.blob_id())),
                    });
                }
                Err(StoreError::Blob(BlobStoreError::NotFound)) => {
                    return Err(incompatible_profile5_storage("blob publication status"));
                }
                Err(error) => {
                    return Err(application_error("blob publication status", error.into()));
                }
            }
        }
        Ok(missing_blob_publication_inspection(request.publication_id))
    }

    pub fn capacity_status(&mut self) -> Result<BlobCapacityStatus, ApplicationError> {
        let _policy = self.current_policy("blob capacity status")?;
        let stats = self
            .store
            .blob_stats()
            .map_err(|error| application_error("blob capacity status", error.into()))?;
        map_blob_capacity_status(stats, self.store.blob_depot_limits())
    }

    fn observe_current_blob_custody_sample(
        &self,
        operation: &'static str,
    ) -> Result<CustodySample, ApplicationError> {
        let sample = self
            .custody_clock
            .sample()
            .map_err(|error| application_error(operation, error))?;
        self.store
            .observe_blob_custody_sample(sample)
            .map_err(|error| application_error(operation, error.into()))?;
        Ok(sample)
    }

    fn map_transfer_status(
        &self,
        snapshot: StoreBlobTransferStatusSnapshot,
        gc: BlobGcStatus,
    ) -> Result<BlobTransferStatus, ApplicationError> {
        let mut pending = Vec::with_capacity(snapshot.pending.len());
        for progress in snapshot.pending {
            let current = self
                .source_route_cache
                .is_current_blob_source_projection(
                    &self.verifier,
                    &progress.source,
                    BlobSourceRetention::Pending,
                )
                .map_err(|error| application_error("blob transfer status", error))?;
            if !current {
                continue;
            }
            let phase = blob_transfer_phase(
                progress.total_carriers,
                progress.durable_carriers,
                progress.total_carrier_bytes,
                progress.durable_carrier_bytes,
            )?;
            pending.push(PendingBlobTransferStatus {
                publication: BlobPublicationId::from_store(progress.source.semantic_id),
                id: BlobId::from_core(progress.source.blob_id),
                topic: progress.source.topic,
                scope: progress.source.scope,
                plaintext_bytes: progress.source.total_len,
                total_carriers: progress.total_carriers,
                durable_carriers: progress.durable_carriers,
                total_carrier_bytes: progress.total_carrier_bytes,
                durable_carrier_bytes: progress.durable_carrier_bytes,
                phase,
            });
        }
        Ok(BlobTransferStatus {
            retained_publications: snapshot.stats.publications,
            retained_pending_transfers: snapshot.stats.pending_sources,
            network_staging_bytes: snapshot.stats.network_staging_bytes,
            reserved_file_bytes: snapshot.stats.reserved_file_bytes,
            gc,
            pending,
        })
    }

    /// Streams one freshly source/content/depot-verified Blob into `output`.
    ///
    /// Every retained source publication for the requested content is freshly
    /// verified before a deterministic active publication is selected and the
    /// exact plan is rechecked. If a later chunk or final whole-content digest
    /// fails, `output` may already contain the independently verified prefix.
    pub fn read_into<W: Write>(
        &mut self,
        request: BlobReadRequest,
        output: &mut W,
    ) -> Result<BlobReadResult, ApplicationError> {
        let admission = AtomicBool::new(true);
        let mut offset = 0_u64;
        let mut verified_chunks = 0_u64;
        let mut peak_working_buffer_bytes = 0_usize;
        let mut identity = None;
        loop {
            let mut fatal = None;
            let page = self
                .read_page_with_admission(
                    BlobReadPageRequest {
                        blob: request.clone(),
                        offset,
                        max_bytes: MAX_SELECTED_BLOB_PAGE_BYTES,
                    },
                    &admission,
                    None,
                    &mut fatal,
                )
                .map_err(|error| ApplicationError::new(error.kind(), "blob read"))?;
            if fatal.is_some() {
                return Err(ApplicationError::new(
                    ApplicationErrorKind::Integrity,
                    "blob read",
                ));
            }
            let page_identity = (
                page.publication,
                page.id,
                page.publisher,
                page.publisher_counter,
                page.priority,
                page.ttl_ms,
                page.total_len,
                page.media_type.clone(),
                page.schema_id.clone(),
                page.acceptance_marker,
            );
            if let Some(initial) = identity.as_ref() {
                if initial != &page_identity {
                    return Err(ApplicationError::new(
                        ApplicationErrorKind::Integrity,
                        "blob read",
                    ));
                }
            } else {
                identity = Some(page_identity);
            }
            output.write_all(page.as_bytes()).map_err(|_| {
                ApplicationError::new(ApplicationErrorKind::StateUnavailable, "blob read")
            })?;
            peak_working_buffer_bytes = peak_working_buffer_bytes.max(page.len());
            verified_chunks = verified_chunks.checked_add(1).ok_or_else(|| {
                ApplicationError::new(ApplicationErrorKind::Integrity, "blob read")
            })?;
            offset = page.next_offset();
            if page.complete {
                break;
            }
        }
        let (
            _publication,
            id,
            publisher,
            publisher_counter,
            priority,
            ttl_ms,
            total_len,
            media_type,
            schema_id,
            acceptance_marker,
        ) = identity
            .ok_or_else(|| ApplicationError::new(ApplicationErrorKind::Integrity, "blob read"))?;
        Ok(BlobReadResult {
            id,
            publisher,
            publisher_counter,
            priority,
            ttl_ms,
            total_len,
            media_type,
            schema_id,
            acceptance_marker,
            verified_chunks,
            peak_working_buffer_bytes,
        })
    }

    /// Reads one bounded page for the protected live facade.
    #[cfg(test)]
    pub(crate) fn read_page(
        &mut self,
        request: BlobReadPageRequest,
    ) -> Result<BlobReadPage, ApplicationError> {
        let admission = AtomicBool::new(true);
        let mut fatal = None;
        let result = self.read_page_with_admission(request, &admission, None, &mut fatal);
        if let Some(error) = fatal {
            Err(application_error("blob read page", error))
        } else {
            result
        }
    }

    fn read_page_with_admission(
        &mut self,
        request: BlobReadPageRequest,
        admission: &AtomicBool,
        response: Option<&oneshot::Sender<Result<BlobReadPage, ApplicationError>>>,
        fatal: &mut Option<NodeError>,
    ) -> Result<BlobReadPage, ApplicationError> {
        if live_blob_read_cancelled(admission, response) {
            return Err(actor_unavailable("blob read page"));
        }
        if request.max_bytes == 0 || request.max_bytes > MAX_SELECTED_BLOB_PAGE_BYTES {
            return Err(ApplicationError::new(
                ApplicationErrorKind::InvalidRequest,
                "blob read page",
            ));
        }
        if request
            .offset
            .checked_add(u64::try_from(request.max_bytes).map_err(|_| {
                ApplicationError::new(ApplicationErrorKind::InvalidRequest, "blob read page")
            })?)
            .is_none()
        {
            return Err(ApplicationError::new(
                ApplicationErrorKind::InvalidRequest,
                "blob read page",
            ));
        }
        self.store
            .observe_blob_custody_sample(
                self.custody_clock
                    .sample()
                    .map_err(|error| application_error("blob read page", error))?,
            )
            .map_err(|error| application_error("blob read page", error.into()))?;
        let policy = self.current_policy("blob read page")?;
        let epoch = self.active_epoch(&request.blob.scope, "blob read page")?;
        self.require_blob_grants(
            &request.blob.topic,
            &request.blob.scope,
            epoch,
            "blob read page",
        )?;
        let reusable = self.read_cache.as_ref().is_some_and(|cache| {
            cache.request == request.blob && cache.next_offset == request.offset
        });
        let mut cache = if reusable {
            self.read_cache.take().expect("reusable Blob read cache")
        } else {
            self.finish_read_cache();
            let source_route_cache = Arc::clone(&self.source_route_cache);
            let initial_lifecycle = match source_route_cache.lock_blob_lifecycle() {
                Ok(lifecycle) => lifecycle,
                Err(error) => {
                    *fatal = Some(live_blob_coherence_fatal(
                        "initial live Blob read lifecycle lock",
                        error,
                    ));
                    return Err(ApplicationError::new(
                        ApplicationErrorKind::Integrity,
                        "blob read page",
                    ));
                }
            };
            if live_blob_read_cancelled(admission, response) {
                drop(initial_lifecycle);
                return Err(actor_unavailable("blob read page"));
            }
            let read_projection = {
                #[cfg(test)]
                if std::mem::replace(&mut self.live_read_projection_coherence_fault, false) {
                    Err(StoreError::Blob(BlobStoreError::SchemaInvariant(
                        "injected orphan live Blob content index",
                    )))
                } else {
                    self.store.prepare_blob_read_with_policy(
                        &policy,
                        &request.blob.topic,
                        &request.blob.scope,
                        request.blob.id.into_core(),
                    )
                }
                #[cfg(not(test))]
                self.store.prepare_blob_read_with_policy(
                    &policy,
                    &request.blob.topic,
                    &request.blob.scope,
                    request.blob.id.into_core(),
                )
            };
            let plan = match read_projection {
                Ok(plan) => plan,
                Err(StoreError::Blob(BlobStoreError::NotFound)) => {
                    drop(initial_lifecycle);
                    return Err(ApplicationError::new(
                        ApplicationErrorKind::NotFound,
                        "blob read page",
                    ));
                }
                Err(error) => {
                    if live_blob_durable_coherence_error(&error) {
                        *fatal = Some(live_blob_coherence_fatal(
                            "live Blob durable read projection",
                            error.into(),
                        ));
                        return Err(ApplicationError::new(
                            ApplicationErrorKind::Integrity,
                            "blob read page",
                        ));
                    }
                    return Err(application_error("blob read page", error.into()));
                }
            };
            let selected = self.prepare_profile5_live_read(&plan, epoch, fatal)?;
            let cache = self.prepare_profile5_read_cache(
                request.blob.clone(),
                request.offset,
                plan,
                selected,
                fatal,
            )?;
            drop(initial_lifecycle);
            cache
        };
        let result = self
            .read_profile5_cached_page(&request, &policy, epoch, &mut cache, admission, response);
        if result.as_ref().is_ok_and(|page| !page.complete) {
            // The caller may never request another page. Keep bounded decoded
            // pipeline state, but release the file and deletion lease now.
            cache.reader = None;
            self.read_cache = Some(cache);
        } else {
            self.record_finished_read_cache(cache);
        }
        result
    }

    fn prepare_profile5_live_read(
        &mut self,
        plan: &BlobReadPlan,
        current_epoch: u64,
        fatal: &mut Option<NodeError>,
    ) -> Result<VerifiedProfile5LiveBlob, ApplicationError> {
        let Some(plan_current) = plan.current() else {
            return Err(ApplicationError::new(
                ApplicationErrorKind::UnauthorizedOrRevoked,
                "blob read page",
            ));
        };
        let exact_stored = match self
            .store
            .load_blob_read_candidate_with_policy(plan.control_policy(), plan_current)
        {
            Ok(stored) => stored,
            Err(error) => return Err(application_error("blob read page", error.into())),
        };
        #[cfg(test)]
        if std::mem::replace(&mut self.live_selected_load_policy_race_fault, false) {
            return Err(ApplicationError::new(
                ApplicationErrorKind::PolicyUnsettled,
                "blob read page",
            ));
        }
        let mut active = Vec::new();
        for candidate in plan.candidates() {
            let projection = candidate.projection();
            if projection.topic != *plan.topic()
                || projection.scope != *plan.scope()
                || projection.blob_id != plan.blob_id()
            {
                return Err(ApplicationError::new(
                    ApplicationErrorKind::Integrity,
                    "blob read page",
                ));
            }
            let revoked = self
                .store
                .is_control_principal_revoked(projection.publisher)
                .map_err(|error| application_error("blob read page", error.into()))?;
            if !revoked && projection.epoch == current_epoch {
                active.push(projection.semantic_id);
            } else if candidate.disposition().is_some() {
                return Err(ApplicationError::new(
                    ApplicationErrorKind::Integrity,
                    "blob read page",
                ));
            }
        }
        let selected = active.iter().copied().max().ok_or_else(|| {
            ApplicationError::new(
                ApplicationErrorKind::UnauthorizedOrRevoked,
                "blob read page",
            )
        })?;
        for candidate in plan.candidates() {
            let expected = if !active.contains(&candidate.projection().semantic_id) {
                None
            } else if candidate.projection().semantic_id == selected {
                Some(BlobPublicationDisposition::Current)
            } else {
                Some(BlobPublicationDisposition::Alternate)
            };
            if candidate.disposition() != expected {
                return Err(ApplicationError::new(
                    ApplicationErrorKind::Integrity,
                    "blob read page",
                ));
            }
        }
        let projection = plan_current.projection().clone();
        #[cfg(test)]
        let mut projection = projection;
        if projection.semantic_id != selected
            || exact_stored.transfer_id != projection.transfer_id
            || exact_stored.semantic_id != projection.semantic_id
            || exact_stored.blob_id != projection.blob_id
        {
            return Err(ApplicationError::new(
                ApplicationErrorKind::Integrity,
                "blob read page",
            ));
        }
        if self
            .verifier
            .blob_stream_authorization_digest(&projection.scope, projection.epoch)
            != Some(projection.route_lineage)
            || !self.verifier.is_current_blob_physical_lineage_binding(
                &projection.scope,
                &projection.topic,
                projection.epoch,
                &projection.physical_lineage,
            )
        {
            return Err(ApplicationError::new(
                ApplicationErrorKind::UnauthorizedOrRevoked,
                "blob read page",
            ));
        }
        let session = match self
            .store
            .open_profile5_pack_application_read(exact_stored.variant_id)
        {
            Ok(session) => session,
            Err(StoreError::Blob(BlobStoreError::NotFound)) => {
                return Err(incompatible_profile5_storage("blob read page"));
            }
            Err(error) => return Err(application_error("blob read page", error.into())),
        };
        #[cfg(test)]
        if std::mem::replace(&mut self.live_pack_projection_coherence_fault, false) {
            projection.route_lineage[0] ^= 1;
        }
        let authority = match self.verify_profile5_stored_source(
            &exact_stored,
            &projection,
            &session,
            "blob read page",
        ) {
            Ok(authority) => authority,
            Err(_) => {
                *fatal = Some(NodeError::FatalBlobCoherence(
                    "live Profile-5 Blob source proof differs from its read plan".into(),
                ));
                return Err(ApplicationError::new(
                    ApplicationErrorKind::Integrity,
                    "blob read page",
                ));
            }
        };
        let publication = authority.publication().clone();
        let physical_open = authority.physical_open().clone();
        let commitment = authority.physical_commitment().commitment().clone();
        let open_value = publication.publication().open();
        if self
            .verifier
            .blob_stream_authorization_digest(open_value.scope(), open_value.content_epoch())
            != Some(projection.route_lineage)
            || !self.verifier.is_current_blob_physical_lineage_binding(
                open_value.scope(),
                open_value.topic(),
                open_value.content_epoch(),
                &projection.physical_lineage,
            )
        {
            return Err(ApplicationError::new(
                ApplicationErrorKind::UnauthorizedOrRevoked,
                "blob read page",
            ));
        }
        Ok(VerifiedProfile5LiveBlob {
            retention: BlobSourceRetention::Completed {
                acceptance_marker: plan_current.acceptance_marker(),
            },
            stored: exact_stored,
            projection,
            publication,
            physical_open,
            commitment,
        })
    }

    fn require_profile5_live_read_authority(
        &self,
        policy: &ControlPolicySnapshot,
        plan: &BlobReadPlan,
        selected: &VerifiedProfile5LiveBlob,
    ) -> Result<(), ApplicationError> {
        if plan.current().is_none_or(|candidate| {
            candidate.projection().transfer_id != selected.projection.transfer_id
                || candidate.projection().semantic_id != selected.projection.semantic_id
                || candidate.disposition() != Some(BlobPublicationDisposition::Current)
        }) {
            return Err(ApplicationError::new(
                ApplicationErrorKind::Integrity,
                "blob read page",
            ));
        }
        let open = selected.publication.publication().open();
        if self
            .store
            .is_control_principal_revoked(open.publisher())
            .map_err(|error| application_error("blob read page", error.into()))?
            || self
                .verifier
                .blob_stream_authorization_digest(open.scope(), open.content_epoch())
                != Some(selected.projection.route_lineage)
            || !self.verifier.is_current_blob_physical_lineage_binding(
                open.scope(),
                open.topic(),
                open.content_epoch(),
                &selected.projection.physical_lineage,
            )
        {
            return Err(ApplicationError::new(
                ApplicationErrorKind::UnauthorizedOrRevoked,
                "blob read page",
            ));
        }
        self.store
            .require_blob_read_plan_with_policy(policy, plan)
            .map_err(|error| application_error("blob read page", error.into()))?;
        let retained = self
            .store
            .blob_source_projection(selected.projection.transfer_id)
            .map_err(|error| application_error("blob read page", error.into()))?
            .ok_or_else(|| {
                ApplicationError::new(ApplicationErrorKind::Integrity, "blob read page")
            })?;
        if retained.source != selected.projection || retained.retention != selected.retention {
            return Err(ApplicationError::new(
                ApplicationErrorKind::UnauthorizedOrRevoked,
                "blob read page",
            ));
        }
        Ok(())
    }

    fn prepare_profile5_read_cache(
        &self,
        request: BlobReadRequest,
        offset: u64,
        plan: BlobReadPlan,
        selected: VerifiedProfile5LiveBlob,
        fatal: &mut Option<NodeError>,
    ) -> Result<LocalBlobReadCache, ApplicationError> {
        let open = selected.publication.publication().open();
        let total_len = open.total_len();
        if (total_len == 0 && offset != 0) || (total_len != 0 && offset >= total_len) {
            return Err(ApplicationError::new(
                ApplicationErrorKind::InvalidRequest,
                "blob read page",
            ));
        }
        let segment_count = selected.commitment.segment_count();
        if segment_count != total_len.div_ceil(BLOB_STREAM_SEGMENT_BYTES as u64) {
            *fatal = Some(NodeError::FatalBlobCoherence(
                "live Profile-5 Blob commitment has an invalid segment count".into(),
            ));
            return Err(ApplicationError::new(
                ApplicationErrorKind::Integrity,
                "blob read page",
            ));
        }
        let first_segment = offset / BLOB_STREAM_SEGMENT_BYTES as u64;
        let (reader, map_pool) = if segment_count == 0 {
            (None, None)
        } else {
            let reader = self
                .store
                .open_profile5_pack_application_read_at_segment(
                    selected.stored.variant_id,
                    first_segment,
                )
                .map_err(|error| application_error("blob read page", error.into()))?;
            if reader.authenticated_open() != selected.physical_open.authenticated_bytes()
                || reader.commitment() != &selected.commitment
                || reader.route_lineage() != selected.physical_open.open().authorization_digest()
                || reader.physical_lineage() != &selected.projection.physical_lineage
            {
                *fatal = Some(NodeError::FatalBlobCoherence(
                    "live Profile-5 Blob pack changed before bounded read".into(),
                ));
                return Err(ApplicationError::new(
                    ApplicationErrorKind::Integrity,
                    "blob read page",
                ));
            }
            let opener = self
                .verifier
                .blob_stream_segment_opener(&selected.physical_open)
                .map_err(|error| application_error("blob read page", error.into()))?;
            let physical_open = selected.physical_open.open();
            let stream_id = *physical_open.stream_id().as_bytes();
            let open_digest = physical_open.digest();
            let physical_total_len = physical_open.total_len();
            if physical_total_len != total_len {
                *fatal = Some(NodeError::FatalBlobCoherence(
                    "live Profile-5 Blob physical and semantic lengths differ".into(),
                ));
                return Err(ApplicationError::new(
                    ApplicationErrorKind::Integrity,
                    "blob read page",
                ));
            }
            let pool = FixedPartitionMapPool::new(
                BLOB_READ_MAP_WORKERS,
                BLOB_READ_PIPELINE_ITEMS as usize,
                move |partition| {
                    let expected_index = partition.index();
                    let record = partition.into_bytes();
                    let (prefix, encoded) = record.split_at_checked(4).ok_or_else(|| {
                        PipelineError::MapFailed("Blob read record is truncated".into())
                    })?;
                    let declared = u32::from_be_bytes(
                        prefix
                            .try_into()
                            .map_err(|_| PipelineError::MapFailed("invalid length".into()))?,
                    ) as usize;
                    if declared == 0 || declared != encoded.len() {
                        return Err(PipelineError::MapFailed(
                            "Blob read record length is invalid".into(),
                        ));
                    }
                    let segment = EncryptedBlobStreamSegment::decode(encoded)
                        .map_err(|error| PipelineError::MapFailed(error.to_string()))?;
                    let header = segment.header();
                    if header.index() != expected_index
                        || header.stream_id() != &stream_id
                        || header.open_digest() != &open_digest
                        || header.total_len() != physical_total_len
                        || header.offset()
                            != expected_index
                                .checked_mul(BLOB_STREAM_SEGMENT_BYTES as u64)
                                .ok_or_else(|| {
                                    PipelineError::MapFailed("Blob read offset overflow".into())
                                })?
                    {
                        return Err(PipelineError::MapFailed(
                            "Blob read segment identity is invalid".into(),
                        ));
                    }
                    let (plaintext, _) = opener
                        .open(&segment)
                        .map_err(|error| PipelineError::MapFailed(error.to_string()))?;
                    if plaintext.len() != header.plaintext_len() as usize {
                        return Err(PipelineError::MapFailed(
                            "Blob read plaintext length is invalid".into(),
                        ));
                    }
                    Ok(OpenedBlobReadSegment {
                        offset: header.offset(),
                        plaintext,
                    })
                },
            )
            .map_err(blob_read_pipeline_error)?;
            (Some(reader), Some(pool))
        };
        let mut cache = LocalBlobReadCache {
            request,
            plan,
            selected,
            reader,
            map_pool,
            mapped: BTreeMap::new(),
            submitted_index: first_segment,
            next_segment_index: first_segment,
            segment_count,
            active_segment: None,
            active_position: 0,
            next_offset: offset,
            #[cfg(test)]
            opened_segments: 0,
        };
        cache.fill_pipeline()?;
        Ok(cache)
    }

    #[allow(clippy::too_many_arguments)]
    fn read_profile5_cached_page(
        &mut self,
        request: &BlobReadPageRequest,
        policy: &ControlPolicySnapshot,
        current_epoch: u64,
        cache: &mut LocalBlobReadCache,
        admission: &AtomicBool,
        response: Option<&oneshot::Sender<Result<BlobReadPage, ApplicationError>>>,
    ) -> Result<BlobReadPage, ApplicationError> {
        let (
            total_len,
            content_epoch,
            publisher,
            publisher_counter,
            priority,
            ttl_ms,
            media_type,
            schema_id,
        ) = {
            let open = cache.selected.publication.publication().open();
            let metadata = open.metadata();
            (
                open.total_len(),
                open.content_epoch(),
                open.publisher(),
                open.publisher_counter(),
                open.priority(),
                open.ttl_ms(),
                metadata.media_type().map(str::to_owned),
                metadata.schema_id().to_vec(),
            )
        };
        if cache.request != request.blob
            || cache.next_offset != request.offset
            || content_epoch != current_epoch
        {
            return Err(ApplicationError::new(
                ApplicationErrorKind::UnauthorizedOrRevoked,
                "blob read page",
            ));
        }
        let page_len = usize::try_from(
            total_len
                .saturating_sub(request.offset)
                .min(request.max_bytes as u64),
        )
        .map_err(|_| {
            ApplicationError::new(ApplicationErrorKind::ResourceLimit, "blob read page")
        })?;
        let next_offset = request.offset.checked_add(page_len as u64).ok_or_else(|| {
            ApplicationError::new(ApplicationErrorKind::InvalidRequest, "blob read page")
        })?;
        self.require_profile5_live_read_authority(policy, &cache.plan, &cache.selected)?;
        if live_blob_read_cancelled(admission, response) {
            return Err(actor_unavailable("blob read page"));
        }

        if cache.reader.is_none() && cache.submitted_index < cache.segment_count {
            let reader = self
                .store
                .open_profile5_pack_application_read_at_segment(
                    cache.selected.stored.variant_id,
                    cache.submitted_index,
                )
                .map_err(|error| application_error("blob read page", error.into()))?;
            if reader.authenticated_open() != cache.selected.physical_open.authenticated_bytes()
                || reader.commitment() != &cache.selected.commitment
                || reader.route_lineage()
                    != cache.selected.physical_open.open().authorization_digest()
                || reader.physical_lineage() != &cache.selected.projection.physical_lineage
            {
                return Err(ApplicationError::new(
                    ApplicationErrorKind::Integrity,
                    "blob read page",
                ));
            }
            cache.reader = Some(reader);
        }

        let mut plaintext = Zeroizing::new(vec![0; page_len]);
        let mut copied = 0usize;
        while copied < page_len {
            if cache.active_segment.is_none() {
                let opened = cache.next_opened_segment()?;
                let target = request.offset.checked_add(copied as u64).ok_or_else(|| {
                    ApplicationError::new(ApplicationErrorKind::Integrity, "blob read page")
                })?;
                let end = opened
                    .offset
                    .checked_add(opened.plaintext.len() as u64)
                    .ok_or_else(|| {
                        ApplicationError::new(ApplicationErrorKind::Integrity, "blob read page")
                    })?;
                if target < opened.offset || target >= end {
                    return Err(ApplicationError::new(
                        ApplicationErrorKind::Integrity,
                        "blob read page",
                    ));
                }
                cache.active_position = usize::try_from(target - opened.offset).map_err(|_| {
                    ApplicationError::new(ApplicationErrorKind::Integrity, "blob read page")
                })?;
                cache.active_segment = Some(opened);
            }
            let active = cache.active_segment.as_ref().expect("active Blob segment");
            let available = active
                .plaintext
                .len()
                .checked_sub(cache.active_position)
                .ok_or_else(|| {
                    ApplicationError::new(ApplicationErrorKind::Integrity, "blob read page")
                })?;
            if available == 0 {
                return Err(ApplicationError::new(
                    ApplicationErrorKind::Integrity,
                    "blob read page",
                ));
            }
            let copy_len = available.min(page_len - copied);
            plaintext[copied..copied + copy_len].copy_from_slice(
                &active.plaintext[cache.active_position..cache.active_position + copy_len],
            );
            copied += copy_len;
            cache.active_position += copy_len;
            if cache.active_position == active.plaintext.len() {
                cache.active_segment = None;
                cache.active_position = 0;
            }
        }
        if live_blob_read_cancelled(admission, response) {
            return Err(actor_unavailable("blob read page"));
        }
        #[cfg(test)]
        if let Some((reached, release)) = self.final_read_gate.take() {
            reached.wait();
            release.wait();
        }
        let source_route_cache = Arc::clone(&self.source_route_cache);
        let _final_lifecycle = source_route_cache
            .lock_blob_lifecycle()
            .map_err(|error| application_error("blob read page", error))?;
        self.require_profile5_live_read_authority(policy, &cache.plan, &cache.selected)?;
        if live_blob_read_cancelled(admission, response) {
            return Err(actor_unavailable("blob read page"));
        }
        cache.next_offset = next_offset;
        Ok(BlobReadPage {
            publication: BlobPublicationId::from_store(cache.selected.stored.semantic_id),
            id: BlobId::from_core(cache.selected.commitment.blob_id()),
            publisher,
            publisher_counter,
            priority,
            ttl_ms,
            total_len,
            media_type,
            schema_id,
            acceptance_marker: cache.selected.stored.acceptance_marker,
            offset: request.offset,
            complete: next_offset == total_len,
            next_offset,
            plaintext,
        })
    }

    fn finish_read_cache(&mut self) {
        if let Some(cache) = self.read_cache.take() {
            self.record_finished_read_cache(cache);
        }
    }

    fn record_finished_read_cache(&mut self, cache: LocalBlobReadCache) {
        #[cfg(test)]
        {
            self.last_read_cache_opened_segments = cache.opened_segments;
        }
        drop(cache);
    }

    fn completed_projection(
        &self,
        stored: &StoredBlob,
        operation: &'static str,
    ) -> Result<(BlobSourceProjection, BlobSourceRetention), ApplicationError> {
        let retained = self
            .store
            .blob_source_projection(stored.transfer_id)
            .map_err(|error| application_error(operation, error.into()))?
            .ok_or_else(|| ApplicationError::new(ApplicationErrorKind::Integrity, operation))?;
        let expected = BlobSourceRetention::Completed {
            acceptance_marker: stored.acceptance_marker,
        };
        if retained.retention != expected
            || retained.source.transfer_id != stored.transfer_id
            || retained.source.semantic_id != stored.semantic_id
            || retained.source.publisher != stored.header.stamp.dot.publisher
            || retained.source.topic != stored.header.topic
            || retained.source.scope != stored.header.scope
            || retained.source.epoch != stored.header.key_epoch
            || retained.source.blob_id != stored.blob_id
            || retained.source.manifest_digest != stored.manifest_digest
            || stored.route_lineage != Some(retained.source.route_lineage)
            || stored.physical_lineage != Some(retained.source.physical_lineage)
            || retained.source.sealed_len
                != u64::try_from(stored.sealed.len()).map_err(|_| {
                    ApplicationError::new(ApplicationErrorKind::Integrity, operation)
                })?
        {
            return Err(ApplicationError::new(
                ApplicationErrorKind::Integrity,
                operation,
            ));
        }
        Ok((retained.source, retained.retention))
    }

    fn verify_profile5_stored_source(
        &self,
        stored: &StoredBlob,
        projection: &BlobSourceProjection,
        session: &aster_redb_store::Profile5PackReadSession,
        operation: &'static str,
    ) -> Result<VerifiedBlobStreamPublicationSource, ApplicationError> {
        let verified = self
            .verifier
            .verify_blob_stream_publication_source(&stored.sealed)
            .map_err(|error| application_error(operation, error.into()))?;
        self.require_profile5_stored_source_match(
            stored, projection, session, &verified, operation,
        )?;
        Ok(verified)
    }

    fn require_profile5_stored_source_match(
        &self,
        stored: &StoredBlob,
        projection: &BlobSourceProjection,
        session: &aster_redb_store::Profile5PackReadSession,
        verified: &VerifiedBlobStreamPublicationSource,
        operation: &'static str,
    ) -> Result<(), ApplicationError> {
        let publication = verified.publication().publication();
        let open = publication.open();
        let physical_open = verified.physical_open().open();
        let commitment = verified.physical_commitment().commitment();
        let sealed_len = u64::try_from(stored.sealed.len())
            .map_err(|_| ApplicationError::new(ApplicationErrorKind::Integrity, operation))?;
        let transfer_id = BlobTransferId::new(Sha256::digest(&stored.sealed).into());
        let semantic_id = BlobSemanticId::new(
            Sha256::digest(verified.publication().authenticated_bytes()).into(),
        );
        let manifest_digest: [u8; 32] = Sha256::digest(commitment.encode()).into();
        let variant_id = aster_redb_store::BlobVariantId::for_content(
            commitment.blob_id(),
            &physical_open.content_group(),
            physical_open.content_epoch(),
        );
        if session.authenticated_open() != verified.source().authenticated_open()
            || session.authenticated_commitment() != verified.source().authenticated_commitment()
            || session.open() != physical_open
            || session.commitment() != commitment
            || session.route_lineage() != physical_open.authorization_digest()
            || session.physical_lineage() != publication.physical_lineage()
            || stored.transfer_id != transfer_id
            || stored.semantic_id != semantic_id
            || stored.blob_id != publication.blob_id()
            || stored.blob_id != commitment.blob_id()
            || stored.variant_id != variant_id
            || stored.manifest_digest != manifest_digest
            || stored.route_lineage != Some(*open.authorization_digest())
            || stored.physical_lineage != Some(*publication.physical_lineage())
            || stored.header.stamp.dot.publisher != open.publisher()
            || stored.header.stamp.dot.counter != open.publisher_counter()
            || stored.header.stamp.context != *open.causal_context()
            || stored.header.topic != *open.topic()
            || stored.header.scope != *open.scope()
            || stored.header.priority != open.priority()
            || stored.header.ttl_ms != open.ttl_ms()
            || stored.header.content_len != sealed_len
            || stored.header.key_epoch != open.content_epoch()
            || stored.header.logical_key.as_slice() != commitment.blob_id().as_bytes()
            || stored.header.blob_route.is_none_or(|route| {
                route.blob_id() != commitment.blob_id()
                    || route.chunk_count() != commitment.segment_count()
                    || route.root() != commitment.ciphertext_root()
            })
            || projection.transfer_id != transfer_id
            || projection.semantic_id != semantic_id
            || projection.publisher != open.publisher()
            || projection.topic != *open.topic()
            || projection.scope != *open.scope()
            || projection.epoch != open.content_epoch()
            || projection.sealed_len != sealed_len
            || projection.route_lineage != *open.authorization_digest()
            || projection.physical_lineage != *publication.physical_lineage()
            || projection.manifest_digest != manifest_digest
            || projection.blob_id != commitment.blob_id()
            || projection.total_len != open.total_len()
            || projection.chunk_size != BLOB_STREAM_SEGMENT_BYTES as u32
            || projection.chunk_count != commitment.segment_count()
        {
            return Err(ApplicationError::new(
                ApplicationErrorKind::Integrity,
                operation,
            ));
        }
        Ok(())
    }

    fn active_epoch(
        &self,
        scope: &Scope,
        operation: &'static str,
    ) -> Result<u64, ApplicationError> {
        self.store
            .active_scope_epoch(scope)
            .map(|epoch| epoch.map_or(1, |(epoch, _)| epoch))
            .map_err(|error| application_error(operation, error.into()))
    }

    fn require_blob_grants(
        &self,
        topic: &Topic,
        scope: &Scope,
        epoch: u64,
        operation: &'static str,
    ) -> Result<(), ApplicationError> {
        if self.verifier.can_route_blob(scope, epoch)
            && self.verifier.can_open_blob_content(scope, topic, epoch)
        {
            Ok(())
        } else {
            Err(ApplicationError::new(
                ApplicationErrorKind::RequestRejected,
                operation,
            ))
        }
    }

    fn current_policy(
        &mut self,
        operation: &'static str,
    ) -> Result<ControlPolicySnapshot, ApplicationError> {
        match refresh_application_policy(
            &self.store,
            &self.mission,
            &mut self.verifier,
            &mut self.verifier_head,
        ) {
            Ok(Some(policy)) => Ok(policy),
            Ok(None) => Err(ApplicationError::new(
                ApplicationErrorKind::PolicyUnsettled,
                operation,
            )),
            Err(error) => Err(application_error(operation, error)),
        }
    }
}

fn live_blob_durable_coherence_error(error: &StoreError) -> bool {
    matches!(
        error,
        StoreError::Blob(
            BlobStoreError::SchemaInvariant(_)
                | BlobStoreError::DepotIntegrity(_)
                | BlobStoreError::CompletionMismatch
        )
    )
}

fn live_blob_coherence_fatal(context: &'static str, error: NodeError) -> NodeError {
    match error {
        NodeError::FatalBlobCoherence(_) => error,
        error => NodeError::FatalBlobCoherence(format!("{context}: {error}")),
    }
}

fn incompatible_profile5_storage(operation: &'static str) -> ApplicationError {
    ApplicationError::new(ApplicationErrorKind::LegacyState, operation)
}

fn finish_live_blob_ledger_command<T>(
    result: Result<T, ApplicationError>,
    response: oneshot::Sender<Result<T, ApplicationError>>,
    admission: &AtomicBool,
    operation: &'static str,
    fatal_context: &'static str,
) -> Result<(), NodeError> {
    if result
        .as_ref()
        .is_err_and(|error| error.kind() == ApplicationErrorKind::Integrity)
    {
        drop(response);
        return Err(NodeError::FatalBlobCoherence(fatal_context.into()));
    }
    if admission.load(Ordering::Acquire) {
        _ = response.send(result);
    } else {
        drop(result);
        _ = response.send(Err(actor_unavailable(operation)));
    }
    Ok(())
}

fn validate_live_publish_request(request: &BlobPublishRequest) -> Result<(), ApplicationError> {
    if request.operation_key.is_empty()
        || request.operation_key.len() > MAX_BLOB_OPERATION_KEY_BYTES
        || request
            .media_type
            .as_ref()
            .is_some_and(|value| value.is_empty() || value.len() > MAX_BLOB_MEDIA_TYPE_BYTES)
        || request.schema_id.len() > MAX_BLOB_SCHEMA_ID_BYTES
    {
        return Err(ApplicationError::new(
            ApplicationErrorKind::InvalidRequest,
            "blob publish",
        ));
    }
    Ok(())
}

fn live_blob_read_cancelled(
    admission: &AtomicBool,
    response: Option<&oneshot::Sender<Result<BlobReadPage, ApplicationError>>>,
) -> bool {
    !admission.load(Ordering::Acquire) || response.is_some_and(oneshot::Sender::is_closed)
}

#[cfg(test)]
fn blob_prepare_error(error: BlobError) -> ApplicationError {
    match error {
        BlobError::InvalidManifest => {
            ApplicationError::new(ApplicationErrorKind::ResourceLimit, "blob publish")
        }
        error => blob_core_error("blob publish", error),
    }
}

#[cfg(test)]
fn blob_store_error_recoverable_capacity(error: &BlobStoreError) -> Option<BlobCapacityGcTarget> {
    match error {
        BlobStoreError::DepotByteLimitExceeded { .. }
        | BlobStoreError::DepotChunkLimitExceeded { .. }
        | BlobStoreError::DepotVariantLimitExceeded { .. } => Some(BlobCapacityGcTarget::Depot),
        BlobStoreError::OperationLimitExceeded { .. }
        | BlobStoreError::OperationByteLimitExceeded { .. } => {
            Some(BlobCapacityGcTarget::Operation)
        }
        BlobStoreError::PublicationLifecycleCapacity { .. } => {
            Some(BlobCapacityGcTarget::PublicationLifecycle)
        }
        _ => None,
    }
}

fn blob_store_application_error(operation: &'static str, error: StoreError) -> ApplicationError {
    application_error(operation, error.into())
}

fn terminal_local_profile5_promotion_error(error: &StoreError) -> bool {
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

fn blob_core_error(operation: &'static str, error: BlobError) -> ApplicationError {
    // The generic service deliberately erases its adapter's exact failure kind.
    // Never infer a quota from that opaque category; typed direct store calls
    // retain their precise resource, availability, and policy classifications.
    let kind = match error {
        BlobError::InvalidChunkSize | BlobError::InvalidMetadata | BlobError::WorkLimitZero => {
            ApplicationErrorKind::InvalidRequest
        }
        BlobError::LengthOverflow => ApplicationErrorKind::ResourceLimit,
        BlobError::SourceChanged => ApplicationErrorKind::Conflict,
        BlobError::Io(error) if error.kind() == std::io::ErrorKind::FileTooLarge => {
            ApplicationErrorKind::ResourceLimit
        }
        BlobError::Io(_) => ApplicationErrorKind::StateUnavailable,
        BlobError::Store(_) => ApplicationErrorKind::Integrity,
        BlobError::InvalidManifest
        | BlobError::InvalidChunkIndex
        | BlobError::MissingChunk
        | BlobError::AuthenticationFailed => ApplicationErrorKind::Integrity,
    };
    ApplicationError::new(kind, operation)
}

#[cfg(test)]
pub(crate) mod tests {
    use std::{
        fs,
        io::{Cursor, SeekFrom},
        path::{Path, PathBuf},
        sync::atomic::{AtomicU64, Ordering},
    };

    #[cfg(unix)]
    use std::time::Duration;

    use aster_mesh::{
        ProvisioningAccess, ReferenceEnvelopeSealer, ReferenceProvisioner, ScopeRekeyRecipient,
    };

    use super::*;
    use crate::application::SelectedEventNode;

    static NEXT_ROOT: AtomicU64 = AtomicU64::new(0);

    #[test]
    fn stream_partition_moves_the_zeroizing_plaintext_allocation() {
        let plaintext = Zeroizing::new(vec![0x5a; 32]);
        let allocation = plaintext.as_ptr();
        let moved = take_zeroizing_bytes(plaintext);

        assert_eq!(moved.as_ptr(), allocation);
        assert_eq!(moved.len(), 32);
    }

    fn content_delivery(item: &BlobDeliveryItem) -> &BlobDelivery {
        item.content().expect("content Blob delivery")
    }

    #[test]
    fn blob_publish_options_preserve_exact_positive_ttl() {
        assert_eq!(BlobPublishOptions::default(), BlobPublishOptions::durable());
        assert_eq!(BlobPublishOptions::durable().ttl_ms(), None);
        assert_eq!(
            BlobPublishOptions::finite_ttl_ms(1)
                .expect("positive minimum TTL")
                .ttl_ms(),
            Some(1)
        );
        assert_eq!(
            BlobPublishOptions::finite_ttl_ms(u64::MAX)
                .expect("positive maximum TTL")
                .ttl_ms(),
            Some(u64::MAX)
        );
        assert_eq!(
            BlobPublishOptions::finite_ttl_ms(0)
                .expect_err("zero TTL must be rejected")
                .kind(),
            ApplicationErrorKind::InvalidRequest
        );
    }

    #[test]
    fn finite_publish_unsupported_clock_rejects_before_source_io_or_mutation() {
        let root = TestRoot::new("finite-unsupported-clock");
        let mut node = selected_node(&root);
        node.custody_clock = NodeCustodyClock::open_from_linux_boot_id(node.identity(), None)
            .expect("unsupported process-local custody clock");
        assert!(!node.custody_clock.supports_finite_ttl());
        let before = node.store.blob_stats().expect("pre-rejection stats");
        let mut source = CountingCursor::new(payload(17));

        let error = node
            .publish_with_options(
                request(b"blob/finite-unsupported-clock"),
                BlobPublishOptions::finite_ttl_ms(1_000).expect("positive TTL"),
                &mut source,
            )
            .expect_err("finite publication requires a supported custody clock");

        assert_eq!(error.kind(), ApplicationErrorKind::UnsupportedValue);
        assert_eq!(source.bytes_read, 0);
        assert_eq!(
            node.store.blob_stats().expect("post-rejection stats"),
            before
        );
    }

    #[test]
    fn finite_publish_echoes_ttl_and_operation_identity_rejects_lifetime_changes() {
        let root = TestRoot::new("finite-publish-api");
        let mut node = selected_node(&root);
        node.custody_clock = NodeCustodyClock::injected([0xd1; 16], 1_000, 1);
        let bytes = payload(SELECTED_BLOB_CHUNK_SIZE as usize + 7);
        let publish_request = request(b"blob/finite-publish-api");
        let finite = BlobPublishOptions::finite_ttl_ms(60_000).expect("positive TTL");

        let elapsed = node
            .publish_with_options(
                request(b"blob/finite-publish-elapsed-before-commit"),
                BlobPublishOptions::finite_ttl_ms(1).expect("positive TTL"),
                &mut Cursor::new(bytes.clone()),
            )
            .expect_err("staging time reaching the TTL must prevent publication");
        assert_eq!(elapsed.kind(), ApplicationErrorKind::ExpiredOrRetired);
        let elapsed_stats = node
            .store
            .blob_stats()
            .expect("stats after elapsed publication");
        assert_eq!(elapsed_stats.publications, 0);
        assert_eq!(elapsed_stats.operations, 0);
        assert_eq!(elapsed_stats.variants, 0);

        let published = node
            .publish_with_options(
                publish_request.clone(),
                finite,
                &mut Cursor::new(bytes.clone()),
            )
            .expect("publish finite Blob");
        assert_eq!(published.ttl_ms, Some(60_000));

        let replay = node
            .publish_with_options(
                publish_request.clone(),
                finite,
                &mut Cursor::new(bytes.clone()),
            )
            .expect("replay exact finite Blob");
        assert!(!replay.inserted);
        assert_eq!(replay.ttl_ms, Some(60_000));

        let durable_conflict = node
            .publish(publish_request.clone(), &mut Cursor::new(bytes.clone()))
            .expect_err("finite operation cannot replay as durable");
        assert_eq!(durable_conflict.kind(), ApplicationErrorKind::Conflict);
        let ttl_conflict = node
            .publish_with_options(
                publish_request,
                BlobPublishOptions::finite_ttl_ms(60_001).expect("different positive TTL"),
                &mut Cursor::new(bytes.clone()),
            )
            .expect_err("finite operation cannot replay with a different TTL");
        assert_eq!(ttl_conflict.kind(), ApplicationErrorKind::Conflict);

        let mut output = Vec::new();
        let read = node
            .read_into(
                BlobReadRequest {
                    id: published.id,
                    topic: blob_topic(),
                    scope: blob_scope(),
                },
                &mut output,
            )
            .expect("read finite Blob");
        assert_eq!(output, bytes);
        assert_eq!(read.ttl_ms, Some(60_000));
    }

    #[test]
    fn durable_wrapper_and_explicit_options_share_exact_operation_semantics() {
        let root = TestRoot::new("durable-publish-wrapper-equivalence");
        let mut node = selected_node(&root);
        let bytes = payload(37);
        let publish_request = request(b"blob/durable-wrapper-equivalence");

        let published = node
            .publish(publish_request.clone(), &mut Cursor::new(bytes.clone()))
            .expect("publish through durable wrapper");
        let replayed = node
            .publish_with_options(
                publish_request,
                BlobPublishOptions::durable(),
                &mut Cursor::new(bytes),
            )
            .expect("replay through explicit durable options");

        assert!(published.inserted);
        assert!(!replayed.inserted);
        assert_eq!(published.ttl_ms, None);
        assert_eq!(replayed.ttl_ms, None);
        assert_eq!(published.id, replayed.id);
        assert_eq!(published.publisher, replayed.publisher);
        assert_eq!(published.publisher_counter, replayed.publisher_counter);
        assert_eq!(published.acceptance_marker, replayed.acceptance_marker);
    }

    #[test]
    fn maximum_finite_ttl_has_an_unreachable_saturated_deadline() {
        let root = TestRoot::new("finite-maximum-ttl");
        let mut node = selected_node(&root);
        node.custody_clock = NodeCustodyClock::injected([0xd5; 16], 1_000, 0);

        let published = node
            .publish_with_options(
                request(b"blob/finite-maximum-ttl"),
                BlobPublishOptions::finite_ttl_ms(u64::MAX).expect("maximum positive TTL"),
                &mut Cursor::new(payload(41)),
            )
            .expect("publish maximum finite TTL");

        assert_eq!(published.ttl_ms, Some(u64::MAX));
        let read = node
            .read_into(
                BlobReadRequest {
                    id: published.id,
                    topic: blob_topic(),
                    scope: blob_scope(),
                },
                &mut Vec::new(),
            )
            .expect("maximum finite TTL remains live");
        assert_eq!(read.ttl_ms, Some(u64::MAX));
    }

    #[test]
    fn exact_finite_retry_rechecks_expiry_stopped_live_and_after_reopen() {
        let bytes = payload(43);

        let stopped_root = TestRoot::new("finite-retry-expired-stopped");
        let mut stopped = selected_node(&stopped_root);
        stopped.custody_clock = NodeCustodyClock::injected([0xd6; 16], 1_000, 0);
        let stopped_request = request(b"blob/finite-retry-expired-stopped");
        stopped
            .publish_with_options(
                stopped_request.clone(),
                BlobPublishOptions::finite_ttl_ms(50).expect("positive TTL"),
                &mut Cursor::new(bytes.clone()),
            )
            .expect("publish stopped retry fixture");
        stopped
            .custody_clock
            .set_injected_tick(1_050)
            .expect("advance stopped custody clock");
        let stopped_error = stopped
            .publish_with_options(
                stopped_request,
                BlobPublishOptions::finite_ttl_ms(50).expect("positive TTL"),
                &mut Cursor::new(bytes.clone()),
            )
            .expect_err("stopped exact retry cannot revive an expired publication");
        assert_eq!(stopped_error.kind(), ApplicationErrorKind::ExpiredOrRetired);

        let live_root = TestRoot::new("finite-retry-expired-live");
        let mut live = selected_node(&live_root);
        live.custody_clock = NodeCustodyClock::injected([0xd7; 16], 2_000, 0);
        let live_request = request(b"blob/finite-retry-expired-live");
        let source_path = live_root.path().join("finite-retry-expired-live.bin");
        fs::write(&source_path, &bytes).expect("write live finite source");
        let admission = AtomicBool::new(true);
        let mut fatal = None;
        live.publish_live_with_admission(
            live_request.clone(),
            BlobPublishOptions::finite_ttl_ms(50).expect("positive TTL"),
            fs::File::open(&source_path).expect("open live finite source"),
            &admission,
            &mut fatal,
        )
        .expect("publish live retry fixture");
        assert!(fatal.is_none());
        live.custody_clock
            .set_injected_tick(2_050)
            .expect("advance live custody clock");
        let live_error = live
            .publish_live_with_admission(
                live_request,
                BlobPublishOptions::finite_ttl_ms(50).expect("positive TTL"),
                fs::File::open(&source_path).expect("reopen live finite source"),
                &admission,
                &mut fatal,
            )
            .expect_err("live exact retry cannot revive an expired publication");
        assert_eq!(live_error.kind(), ApplicationErrorKind::ExpiredOrRetired);
        assert!(
            fatal.is_none(),
            "ordinary expiry is not a coherence failure"
        );

        let reopen_root = TestRoot::new("finite-retry-expired-reopen");
        let reopen_request = request(b"blob/finite-retry-expired-reopen");
        {
            let mut node = selected_node(&reopen_root);
            node.custody_clock = NodeCustodyClock::injected([0xd8; 16], 3_000, 0);
            node.publish_with_options(
                reopen_request.clone(),
                BlobPublishOptions::finite_ttl_ms(50).expect("positive TTL"),
                &mut Cursor::new(bytes.clone()),
            )
            .expect("publish reopen retry fixture");
        }
        let mut reopened = selected_node(&reopen_root);
        reopened.custody_clock = NodeCustodyClock::injected([0xd8; 16], 3_050, 0);
        let reopen_error = reopened
            .publish_with_options(
                reopen_request,
                BlobPublishOptions::finite_ttl_ms(50).expect("positive TTL"),
                &mut Cursor::new(bytes),
            )
            .expect_err("reopened exact retry cannot revive an expired publication");
        assert_eq!(reopen_error.kind(), ApplicationErrorKind::ExpiredOrRetired);
    }

    #[test]
    fn stopped_finite_read_never_opens_a_later_page_after_expiry() {
        let root = TestRoot::new("finite-read-page-boundary");
        let mut node = selected_node(&root);
        node.custody_clock = NodeCustodyClock::injected([0xd2; 16], 100, 0);
        let bytes = payload(MAX_SELECTED_BLOB_PAGE_BYTES + 11);
        let published = node
            .publish_with_options(
                request(b"blob/finite-read-page-boundary"),
                BlobPublishOptions::finite_ttl_ms(4).expect("positive TTL"),
                &mut Cursor::new(bytes),
            )
            .expect("publish finite boundary Blob");
        let first = node
            .read_page(BlobReadPageRequest {
                blob: BlobReadRequest {
                    id: published.id,
                    topic: blob_topic(),
                    scope: blob_scope(),
                },
                offset: 0,
                max_bytes: MAX_SELECTED_BLOB_PAGE_BYTES,
            })
            .expect("first page opens before expiry");
        assert!(!first.complete);
        assert_eq!(first.as_bytes().len(), MAX_SELECTED_BLOB_PAGE_BYTES);
        node.custody_clock
            .set_injected_tick(104)
            .expect("advance custody clock to exact TTL boundary");
        let error = node
            .read_page(BlobReadPageRequest {
                blob: BlobReadRequest {
                    id: published.id,
                    topic: blob_topic(),
                    scope: blob_scope(),
                },
                offset: first.next_offset,
                max_bytes: 11,
            })
            .expect_err("later page must not open at the exact TTL boundary");
        assert_eq!(error.kind(), ApplicationErrorKind::ExpiredOrRetired);
    }

    #[test]
    fn missing_blob_read_is_not_found_without_retirement_evidence() {
        let root = TestRoot::new("missing-read-not-found");
        let mut node = selected_node(&root);
        let error = node
            .read_into(
                BlobReadRequest {
                    id: BlobId::from_bytes([0xe4; 32]),
                    topic: blob_topic(),
                    scope: blob_scope(),
                },
                &mut Vec::new(),
            )
            .expect_err("unknown Blob has no retained retirement evidence");
        assert_eq!(error.kind(), ApplicationErrorKind::NotFound);
    }

    #[test]
    fn finite_publish_reopens_with_exact_ttl_and_shares_durable_physical_variant() {
        let root = TestRoot::new("finite-reopen-shared-variant");
        let bytes = payload(SELECTED_BLOB_CHUNK_SIZE as usize + 29);
        let finite_id = {
            let mut node = selected_node(&root);
            node.custody_clock = NodeCustodyClock::injected([0xd4; 16], 1_000, 1);
            let finite = node
                .publish_with_options(
                    request(b"blob/finite-reopen"),
                    BlobPublishOptions::finite_ttl_ms(10_000).expect("positive TTL"),
                    &mut Cursor::new(bytes.clone()),
                )
                .expect("publish finite Blob before restart");
            finite.id
        };

        let mut reopened = selected_node(&root);
        reopened.custody_clock = NodeCustodyClock::injected([0xd4; 16], 1_100, 1);
        let mut output = Vec::new();
        let read = reopened
            .read_into(
                BlobReadRequest {
                    id: finite_id,
                    topic: blob_topic(),
                    scope: blob_scope(),
                },
                &mut output,
            )
            .expect("read shared physical variant after restart");
        assert_eq!(output, bytes);
        assert_eq!(read.ttl_ms, Some(10_000));

        let durable = reopened
            .publish(
                request(b"blob/durable-shared-variant"),
                &mut Cursor::new(bytes.clone()),
            )
            .expect("publish durable reference to same immutable bytes");
        assert_eq!(finite_id, durable.id);
        let stats = reopened.store.blob_stats().expect("mixed lifetime stats");
        assert_eq!(stats.publications, 2);
        assert_eq!(stats.variants, 1);

        let expired_sample = CustodySample {
            clock_id: [0xd4; 16],
            tick_ms: 11_001,
        };
        for _ in 0..16 {
            reopened
                .store
                .run_blob_maintenance_turn_with_sample(
                    BlobMaintenanceBudget::new(64, 16, 128 * 1024 * 1024)
                        .expect("shared-variant maintenance budget"),
                    Some(expired_sample),
                )
                .expect("retire only finite shared-variant member");
        }
        let stats = reopened
            .store
            .blob_stats()
            .expect("post-expiry shared-variant stats");
        assert_eq!(stats.publications, 1);
        assert_eq!(stats.variants, 1);
        let durable_read = reopened
            .read_into(
                BlobReadRequest {
                    id: durable.id,
                    topic: blob_topic(),
                    scope: blob_scope(),
                },
                &mut Vec::new(),
            )
            .expect("durable member remains readable after finite retirement");
        assert_eq!(durable_read.ttl_ms, None);
    }

    #[test]
    fn finite_retirement_delivery_is_tagged_and_acknowledged_with_v2_token() {
        let root = TestRoot::new("finite-retirement-delivery");
        let mut node = selected_node(&root);
        node.custody_clock = NodeCustodyClock::injected([0xd3; 16], 100, 1);
        let subscription = node
            .subscribe(subscription_request(b"blob/finite-retirement-selector"))
            .expect("subscribe before finite publication");
        let published = node
            .publish_with_options(
                request(b"blob/finite-retirement-publication"),
                BlobPublishOptions::finite_ttl_ms(50).expect("positive TTL"),
                &mut Cursor::new(payload(17)),
            )
            .expect("publish finite retirement fixture");
        let durable = node
            .publish(
                request(b"blob/finite-retirement-durable-follower"),
                &mut Cursor::new(payload(19)),
            )
            .expect("publish durable follower");
        let content_page = node
            .poll(BlobPollRequest {
                subscription: subscription.id,
                delivery_limit: 1,
                scan_limit: 4,
            })
            .expect("poll finite content");
        assert!(content_page.has_more);
        let content = content_delivery(&content_page.deliveries[0]);
        assert_eq!(content.ttl_ms, Some(50));
        let old_token = content.token;
        let publication = content.publication;

        let expired_sample = CustodySample {
            clock_id: [0xd3; 16],
            tick_ms: 151,
        };
        node.custody_clock
            .set_injected_tick(expired_sample.tick_ms)
            .expect("advance custody clock past finite TTL");
        let durable_before_maintenance = node
            .poll(BlobPollRequest {
                subscription: subscription.id,
                delivery_limit: 1,
                scan_limit: 4,
            })
            .expect("poll hides expired content without maintenance");
        assert_eq!(durable_before_maintenance.deliveries.len(), 1);
        assert_eq!(
            content_delivery(&durable_before_maintenance.deliveries[0]).id,
            durable.id
        );
        let old_ack = node
            .acknowledge(subscription.id, publication, old_token)
            .expect_err("hidden finite publication cannot be acknowledged as content");
        assert_eq!(old_ack.kind(), ApplicationErrorKind::ExpiredOrRetired);

        for _ in 0..16 {
            node.store
                .run_blob_maintenance_turn_with_sample(
                    BlobMaintenanceBudget::new(64, 16, 128 * 1024 * 1024)
                        .expect("retirement maintenance budget"),
                    Some(expired_sample),
                )
                .expect("retire expired finite Blob");
        }

        let retired_read = node
            .read_into(
                BlobReadRequest {
                    id: published.id,
                    topic: blob_topic(),
                    scope: blob_scope(),
                },
                &mut Vec::new(),
            )
            .expect_err("retained retirement evidence distinguishes expiry from absence");
        assert_eq!(retired_read.kind(), ApplicationErrorKind::ExpiredOrRetired);
        let status = node
            .transfer_status()
            .expect("status after finite retirement");
        assert_eq!(status.retained_publications, 1);
        assert!(status.pending.is_empty());

        let retirement_page = node
            .poll(BlobPollRequest {
                subscription: subscription.id,
                delivery_limit: 1,
                scan_limit: 4,
            })
            .expect("poll retirement notice");
        assert_eq!(retirement_page.deliveries.len(), 1);
        assert!(
            retirement_page.has_more,
            "authenticated durable content remains after the retirement-first page"
        );
        let retirement = retirement_page.deliveries[0]
            .retirement()
            .expect("tagged retirement delivery");
        assert_eq!(retirement.publication, publication);
        assert_eq!(retirement.id, published.id);
        assert_eq!(retirement.ttl_ms, Some(50));
        assert_eq!(retirement.reason, BlobRetirementReason::Expired);
        assert!(retirement.retirement_generation > 0);
        assert!(retirement.attempt >= 2);
        assert_eq!(
            node.acknowledge(subscription.id, publication, retirement.token)
                .expect("acknowledge retirement"),
            BlobAcknowledgement::Acknowledged
        );
        assert_eq!(
            node.acknowledge(subscription.id, publication, retirement.token)
                .expect("retry retirement acknowledgement"),
            BlobAcknowledgement::AlreadyAcknowledged
        );
        let durable_page = node
            .poll(BlobPollRequest {
                subscription: subscription.id,
                delivery_limit: 1,
                scan_limit: 4,
            })
            .expect("poll durable content after retirement family");
        let durable_delivery = durable_page.deliveries[0]
            .content()
            .expect("content follows retirement family");
        assert_eq!(durable_delivery.id, durable.id);
        assert_eq!(durable_delivery.ttl_ms, None);
        assert!(!durable_page.has_more);
    }

    #[test]
    fn poll_hides_finite_publication_after_custody_continuity_loss() {
        let root = TestRoot::new("finite-poll-continuity-loss");
        let mut node = selected_node(&root);
        node.custody_clock = NodeCustodyClock::injected([0xd9; 16], 100, 0);
        let subscription = node
            .subscribe(subscription_request(b"blob/finite-poll-continuity-loss"))
            .expect("subscribe before finite publication");
        node.publish_with_options(
            request(b"blob/finite-poll-continuity-loss"),
            BlobPublishOptions::finite_ttl_ms(10_000).expect("positive TTL"),
            &mut Cursor::new(payload(47)),
        )
        .expect("publish finite continuity fixture");

        node.custody_clock = NodeCustodyClock::injected([0xda; 16], 100, 0);
        let page = node
            .poll(BlobPollRequest {
                subscription: subscription.id,
                delivery_limit: 1,
                scan_limit: 4,
            })
            .expect("poll after custody-domain transition");

        assert!(page.deliveries.is_empty());
        assert!(!page.has_more);
    }

    #[test]
    fn publication_inspection_observes_elapsed_expiry_without_other_calls() {
        let root = TestRoot::new("inspection-elapsed-expiry");
        let mut node = selected_node(&root);
        node.custody_clock = NodeCustodyClock::injected([0xcd; 16], 1_000, 0);
        let published = node
            .publish_with_options(
                request(b"inspection/elapsed-expiry"),
                BlobPublishOptions::finite_ttl_ms(50).unwrap(),
                &mut Cursor::new(payload(53)),
            )
            .unwrap();
        node.custody_clock.set_injected_tick(1_050).unwrap();
        let status = node
            .inspect_publication(BlobPublicationInspectionRequest {
                publication_id: published.publication_id.unwrap(),
                topic: blob_topic(),
                scope: blob_scope(),
            })
            .unwrap();
        assert_eq!(status.phase, BlobPublicationPhase::ExpiredOrRetired);
    }

    #[test]
    fn publication_inspection_does_not_revive_expired_cached_completion() {
        let root = TestRoot::new("inspection-cached-expiry");
        let mut node = selected_node(&root);
        node.custody_clock = NodeCustodyClock::injected([0xcc; 16], 1_000, 0);
        let publication = request(b"inspection/cached-expiry");
        let options = BlobPublishOptions::finite_ttl_ms(50).unwrap();
        node.publish_with_options(publication.clone(), options, &mut Cursor::new(payload(53)))
            .unwrap();
        let opened = node
            .open_publish_stream_inner(BlobPublishStreamRequest {
                publication,
                options,
                total_len: 53,
            })
            .unwrap();
        node.custody_clock.set_injected_tick(1_050).unwrap();
        node.transfer_status().unwrap();
        let status = node
            .inspect_publication(BlobPublicationInspectionRequest {
                publication_id: BlobStreamPublicationId::from_bytes(opened.token).unwrap(),
                topic: blob_topic(),
                scope: blob_scope(),
            })
            .unwrap();
        assert_eq!(status.phase, BlobPublicationPhase::ExpiredOrRetired);
    }

    #[test]
    fn publication_inspection_rechecks_policy_for_active_and_reopened_uploads() {
        for reopen in [false, true] {
            let root = TestRoot::new("inspection-upload-policy");
            let mut services = persist_rekey_mission(&root);
            let mut node = selected_node(&root);
            let opened = node
                .open_publish_stream_inner(BlobPublishStreamRequest {
                    publication: request(b"inspection/upload-policy"),
                    options: BlobPublishOptions::durable(),
                    total_len: 2,
                })
                .unwrap();
            apply_scope_rekey_to_store(&node.store, &mut services, 2, 1, false);
            if reopen {
                drop(node);
                node = selected_node(&root);
            }
            let status = node.inspect_publication(BlobPublicationInspectionRequest {
                publication_id: BlobStreamPublicationId::from_bytes(opened.token).unwrap(),
                topic: blob_topic(),
                scope: blob_scope(),
            });
            assert!(
                status.is_err(),
                "current policy must reject stale upload status, reopened={reopen}"
            );
        }
    }

    fn live_stream_test_actor(
        mut node: SelectedBlobNode,
    ) -> (
        SelectedBlobHandle,
        tokio::task::JoinHandle<SelectedBlobNode>,
    ) {
        let admission = Arc::new(AtomicBool::new(true));
        let (commands, mut received) = mpsc::channel(1);
        let handle = SelectedBlobHandle::new(
            commands,
            Arc::clone(&admission),
            node.identity(),
            node.mission_authority(),
        );
        let worker = tokio::task::spawn_blocking(move || {
            let runtime = tokio::runtime::Handle::current();
            while let Some(command) = runtime
                .block_on(node.next_live_command(&mut received))
                .unwrap()
            {
                let SelectedApplicationCommand::Blob(command) = command else {
                    panic!("unexpected command")
                };
                node.execute_live(command, &admission).unwrap();
            }
            node
        });
        (handle, worker)
    }

    fn open_live_test_stream(
        node: &mut SelectedBlobNode,
        commands: mpsc::Sender<SelectedApplicationCommand>,
    ) -> SelectedBlobPublishStream {
        let (response, received) = oneshot::channel();
        node.execute_live(
            SelectedBlobCommand::OpenPublishStream {
                request: BlobPublishStreamRequest {
                    publication: request(b"abandoned/live-session"),
                    options: BlobPublishOptions::durable(),
                    total_len: 2,
                },
                response,
            },
            &AtomicBool::new(true),
        )
        .unwrap();
        let (opened, session) = received.blocking_recv().unwrap().unwrap();
        SelectedBlobPublishStream::new(commands, opened.token, opened.progress, session)
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn abandoned_live_publish_stream_wakes_idle_worker_cleanup() {
        let root = TestRoot::new("abandoned-idle-worker");
        let mut node = selected_node(&root);
        let (commands, mut received) = mpsc::channel::<SelectedApplicationCommand>(1);
        let stream =
            tokio::task::block_in_place(|| open_live_test_stream(&mut node, commands.clone()));
        {
            let wait = node.next_live_command(&mut received);
            tokio::pin!(wait);
            // Register the idle worker's wait before dropping the live API handle.
            std::future::poll_fn(|cx| {
                assert!(std::future::Future::poll(wait.as_mut(), cx).is_pending());
                std::task::Poll::Ready(())
            })
            .await;
            drop(stream);
            assert!(
                tokio::time::timeout(std::time::Duration::from_millis(30), &mut wait)
                    .await
                    .is_err()
            );
        }
        assert!(
            node.publish_streams.is_empty(),
            "idle cancellation must release worker pools without a follow-up command"
        );
        drop(commands);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn abandoned_live_publish_stream_cleanup_survives_full_command_queue() {
        let root = TestRoot::new("abandoned-full-queue");
        let mut node = selected_node(&root);
        let (commands, mut received) = mpsc::channel(1);
        let stream =
            tokio::task::block_in_place(|| open_live_test_stream(&mut node, commands.clone()));
        let (response, _received) = oneshot::channel();
        commands
            .try_send(SelectedApplicationCommand::Blob(
                SelectedBlobCommand::CapacityStatus { response },
            ))
            .unwrap_or_else(|_| panic!("fill command queue"));
        assert_eq!(commands.capacity(), 0);
        drop(stream);
        let command = node
            .next_live_command(&mut received)
            .await
            .unwrap()
            .unwrap();
        assert!(
            node.publish_streams.is_empty(),
            "Drop must release runtime state even when the command queue is full"
        );
        let SelectedApplicationCommand::Blob(command) = command else {
            panic!("unexpected command")
        };
        node.execute_live(command, &AtomicBool::new(true)).unwrap();
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn abandoned_live_publish_stream_open_response_releases_runtime_state() {
        let root = TestRoot::new("abandoned-open-response");
        let mut node = selected_node(&root);
        let (_commands, mut commands) = mpsc::channel::<SelectedApplicationCommand>(1);
        let (response, received) = oneshot::channel();
        drop(received);
        node.execute_live(
            SelectedBlobCommand::OpenPublishStream {
                request: BlobPublishStreamRequest {
                    publication: request(b"abandoned/open-response"),
                    options: BlobPublishOptions::durable(),
                    total_len: 1,
                },
                response,
            },
            &AtomicBool::new(true),
        )
        .unwrap();
        assert!(
            tokio::time::timeout(
                std::time::Duration::from_millis(30),
                node.next_live_command(&mut commands)
            )
            .await
            .is_err()
        );
        assert!(
            node.publish_streams.is_empty(),
            "cancelled open response must release native worker pools"
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn abandoned_live_publish_stream_does_not_close_replacement_or_lose_resume() {
        let root = TestRoot::new("abandoned-replacement-resume");
        let (handle, worker) = live_stream_test_actor(selected_node(&root));
        let request = BlobPublishStreamRequest {
            publication: request(b"abandoned/replacement"),
            options: BlobPublishOptions::durable(),
            total_len: 2,
        };
        let mut old = handle.open_publish_stream(request.clone()).await.unwrap();
        old.write(0, Zeroizing::new(vec![1])).await.unwrap();
        let mut replacement = handle.open_publish_stream(request.clone()).await.unwrap();
        assert_eq!(
            replacement.durable_offset(),
            0,
            "uncheckpointed prefix is discarded on resume"
        );
        assert_eq!(
            old.write(0, Zeroizing::new(vec![3, 4]))
                .await
                .unwrap_err()
                .kind(),
            ApplicationErrorKind::NotFound
        );
        assert!(
            old.finish().await.is_err(),
            "stale finish must not consume the replacement"
        );
        replacement
            .write(0, Zeroizing::new(vec![3, 4]))
            .await
            .unwrap();
        drop(replacement);
        let resumed = handle.open_publish_stream(request).await.unwrap();
        assert_eq!(
            resumed.durable_offset(),
            2,
            "durable checkpoint survives abandoned runtime cleanup"
        );
        let result = resumed.finish().await.unwrap();
        let page = handle
            .read_page(BlobReadPageRequest {
                blob: BlobReadRequest {
                    id: result.id,
                    topic: blob_topic(),
                    scope: blob_scope(),
                },
                offset: 0,
                max_bytes: 2,
            })
            .await
            .unwrap();
        assert_eq!(page.as_bytes(), &[3, 4]);
        drop(handle);
        let node = worker.await.unwrap();
        assert!(node.publish_streams.is_empty());
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn abandoned_live_publish_stream_releases_runtime_state() {
        let root = TestRoot::new("abandoned-live-stream");
        let (handle, worker) = live_stream_test_actor(selected_node(&root));
        let stream = handle
            .open_publish_stream(BlobPublishStreamRequest {
                publication: request(b"abandoned/runtime"),
                options: BlobPublishOptions::durable(),
                total_len: 1,
            })
            .await
            .unwrap();
        drop(stream);
        handle.capacity_status().await.unwrap();
        drop(handle);
        let node = worker.await.unwrap();
        assert!(
            node.publish_streams.is_empty(),
            "abandoned streams must release map pools and writers"
        );
    }

    #[test]
    fn transfer_status_observes_finite_expiry_without_maintenance() {
        let root = TestRoot::new("finite-status-observes-expiry");
        let mut node = selected_node(&root);
        node.custody_clock = NodeCustodyClock::injected([0xdb; 16], 1_000, 0);
        let published = node
            .publish_with_options(
                request(b"blob/finite-status-observes-expiry"),
                BlobPublishOptions::finite_ttl_ms(50).expect("positive TTL"),
                &mut Cursor::new(payload(53)),
            )
            .expect("publish finite status fixture");

        node.custody_clock
            .set_injected_tick(1_050)
            .expect("advance status custody clock");
        let status = node
            .transfer_status()
            .expect("status observes current custody sample");
        assert_eq!(status.retained_publications, 1);
        node.custody_clock
            .set_injected_tick(1_000)
            .expect("rewind injected reader below persisted high-water");

        let error = node
            .read_into(
                BlobReadRequest {
                    id: published.id,
                    topic: blob_topic(),
                    scope: blob_scope(),
                },
                &mut Vec::new(),
            )
            .expect_err("status-persisted expiry cannot be revived by a lower later sample");
        assert_eq!(error.kind(), ApplicationErrorKind::ExpiredOrRetired);
    }

    struct TestRoot(PathBuf);

    impl TestRoot {
        fn new(label: &str) -> Self {
            let sequence = NEXT_ROOT.fetch_add(1, Ordering::Relaxed);
            let path = std::env::temp_dir().join(format!(
                "aster-selected-blob-{}-{sequence}-{label}",
                std::process::id()
            ));
            fs::create_dir(&path).expect("create Blob test root");
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt as _;
                fs::set_permissions(&path, fs::Permissions::from_mode(0o700))
                    .expect("make Blob test root private");
            }
            Self(path)
        }

        fn path(&self) -> &Path {
            &self.0
        }

        fn mission_path(&self) -> PathBuf {
            self.path().join("mission.unprotected-reference.bundle")
        }

        fn depot_path(&self) -> PathBuf {
            self.path().join("blob-depot-v1")
        }
    }

    impl Drop for TestRoot {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    fn blob_topic() -> Topic {
        Topic::new("ops.blob").expect("Blob topic")
    }

    fn blob_scope() -> Scope {
        Scope::new("mission/apps").expect("Blob scope")
    }

    fn persist_member_mission(root: &TestRoot) {
        let access = ProvisioningAccess::member(blob_scope(), vec![1], vec![blob_topic()])
            .expect("member access");
        let mut provisioner = ReferenceProvisioner::from_seed([0xb1; 32]).expect("provisioner");
        let bytes = provisioner
            .issue_node(1, &[access])
            .expect("issue node")
            .to_bytes()
            .expect("encode mission");
        drop(
            UnprotectedReferenceMission::persist(root.mission_path(), bytes)
                .expect("persist mission"),
        );
    }

    fn persist_relay_mission(root: &TestRoot) {
        let access = ProvisioningAccess::relay(blob_scope(), vec![1]).expect("relay access");
        let mut provisioner = ReferenceProvisioner::from_seed([0xb2; 32]).expect("provisioner");
        let bytes = provisioner
            .issue_node(1, &[access])
            .expect("issue relay")
            .to_bytes()
            .expect("encode relay mission");
        drop(
            UnprotectedReferenceMission::persist(root.mission_path(), bytes)
                .expect("persist relay mission"),
        );
    }

    fn persist_future_only_mission(root: &TestRoot) {
        let access = ProvisioningAccess::member(blob_scope(), vec![2], vec![blob_topic()])
            .expect("future-only member access");
        let mut provisioner = ReferenceProvisioner::from_seed([0xb4; 32]).expect("provisioner");
        let bytes = provisioner
            .issue_node(1, &[access])
            .expect("issue future-only node")
            .to_bytes()
            .expect("encode future-only mission");
        drop(
            UnprotectedReferenceMission::persist(root.mission_path(), bytes)
                .expect("persist future-only mission"),
        );
    }

    struct RekeyServices {
        control_authority: ReferenceEnvelopeSealer,
        reader: ReferenceEnvelopeSealer,
        registry: Vec<u8>,
        selected_identity: NodeId,
        mission_authority: NodeId,
    }

    fn persist_rekey_mission(root: &TestRoot) -> RekeyServices {
        let access = ProvisioningAccess::member(blob_scope(), vec![1], vec![blob_topic()])
            .expect("member access");
        let mut provisioner = ReferenceProvisioner::from_seed([0xb3; 32]).expect("provisioner");
        let control_authority = provisioner
            .issue_control_authority(60, std::slice::from_ref(&access))
            .and_then(ReferenceEnvelopeSealer::open)
            .expect("control authority");
        let reader = provisioner
            .issue_node(51, std::slice::from_ref(&access))
            .and_then(ReferenceEnvelopeSealer::open)
            .expect("control reader");
        let selected_bundle = provisioner
            .issue_node(52, std::slice::from_ref(&access))
            .expect("selected node bundle");
        let selected_bytes = selected_bundle
            .to_bytes()
            .expect("encode selected node bundle");
        let selected_mission = UnprotectedReferenceMission::from_bytes(selected_bytes.clone())
            .expect("parse selected mission");
        let selected_identity = ReferenceEnvelopeSealer::open(
            selected_mission
                .fresh_bundle()
                .expect("fresh selected bundle"),
        )
        .expect("open selected identity")
        .identity();
        let registry = provisioner.export_rekey_registry().expect("rekey registry");
        drop(
            UnprotectedReferenceMission::persist(root.mission_path(), selected_bytes)
                .expect("persist selected mission"),
        );
        RekeyServices {
            mission_authority: control_authority.mission_authority_id(),
            control_authority,
            reader,
            registry,
            selected_identity,
        }
    }

    fn apply_scope_rekey(
        root: &TestRoot,
        services: &mut RekeyServices,
        epoch: u64,
        sequence: u64,
        previous: Option<[u8; 32]>,
    ) -> [u8; 32] {
        let recipients = vec![
            ScopeRekeyRecipient::member(services.control_authority.identity(), vec![blob_topic()])
                .expect("authority recipient"),
            ScopeRekeyRecipient::member(services.reader.identity(), vec![blob_topic()])
                .expect("reader recipient"),
            ScopeRekeyRecipient::member(services.selected_identity, vec![blob_topic()])
                .expect("selected recipient"),
        ];
        let (sealed, _) = services
            .control_authority
            .seal_chained_scope_rekey_control_from_registry(
                &services.registry,
                0,
                blob_scope(),
                epoch,
                recipients,
                sequence,
                previous,
            )
            .expect("seal scope rekey");
        let verified = services
            .reader
            .verify_control(&sealed)
            .expect("verify scope rekey");
        let transfer_id = verified.envelope_id();
        let store =
            Store::open_for_mission(root.path().join(STORE_FILE), services.mission_authority)
                .expect("open Blob store for rekey");
        let outcome = store
            .ingest_verified_control(&verified, &sealed)
            .expect("commit scope rekey");
        assert_eq!(outcome.activated().len(), 1);
        assert_eq!(
            store
                .active_scope_epoch(&blob_scope())
                .expect("active epoch")
                .map(|(epoch, _)| epoch),
            Some(epoch)
        );
        transfer_id
    }

    fn apply_epoch_two_rekey(root: &TestRoot, services: &mut RekeyServices) {
        let _ = apply_scope_rekey(root, services, 2, 1, None);
    }

    fn apply_scope_rekey_to_open_node(
        node: &SelectedBlobNode,
        services: &mut RekeyServices,
        epoch: u64,
        sequence: u64,
    ) {
        let recipients = vec![
            ScopeRekeyRecipient::member(services.control_authority.identity(), vec![blob_topic()])
                .expect("authority recipient"),
            ScopeRekeyRecipient::member(services.reader.identity(), vec![blob_topic()])
                .expect("reader recipient"),
            ScopeRekeyRecipient::member(services.selected_identity, vec![blob_topic()])
                .expect("selected recipient"),
        ];
        let (sealed, _) = services
            .control_authority
            .seal_chained_scope_rekey_control_from_registry(
                &services.registry,
                0,
                blob_scope(),
                epoch,
                recipients,
                sequence,
                None,
            )
            .expect("seal open-node rekey");
        let verified = services
            .reader
            .verify_control(&sealed)
            .expect("verify open-node rekey");
        node.store
            .ingest_verified_control(&verified, &sealed)
            .expect("commit open-node rekey");
    }

    fn apply_scope_rekey_to_store(
        store: &Store,
        services: &mut RekeyServices,
        epoch: u64,
        sequence: u64,
        include_selected: bool,
    ) {
        let mut recipients = vec![
            ScopeRekeyRecipient::member(services.control_authority.identity(), vec![blob_topic()])
                .expect("authority recipient"),
            ScopeRekeyRecipient::member(services.reader.identity(), vec![blob_topic()])
                .expect("reader recipient"),
        ];
        if include_selected {
            recipients.push(
                ScopeRekeyRecipient::member(services.selected_identity, vec![blob_topic()])
                    .expect("selected recipient"),
            );
        }
        let (sealed, _) = services
            .control_authority
            .seal_chained_scope_rekey_control_from_registry(
                &services.registry,
                0,
                blob_scope(),
                epoch,
                recipients,
                sequence,
                None,
            )
            .expect("seal concurrent rekey");
        let verified = services
            .reader
            .verify_control(&sealed)
            .expect("verify concurrent rekey");
        store
            .ingest_verified_control(&verified, &sealed)
            .expect("commit concurrent rekey");
    }

    fn assert_post_decrypt_read_denied(
        mut node: SelectedBlobNode,
        blob: BlobReadRequest,
        mutate: impl FnOnce(&Store),
    ) -> ApplicationErrorKind {
        let reached = Arc::new(std::sync::Barrier::new(2));
        let release = Arc::new(std::sync::Barrier::new(2));
        node.set_final_read_gate(Arc::clone(&reached), Arc::clone(&release));
        let store = Arc::clone(&node.store);
        let admission = Arc::new(AtomicBool::new(true));
        let worker_admission = Arc::clone(&admission);
        let (response, received) = oneshot::channel();
        let worker = std::thread::spawn(move || {
            node.execute_live(
                SelectedBlobCommand::ReadPage {
                    request: BlobReadPageRequest {
                        blob,
                        offset: 0,
                        max_bytes: 31,
                    },
                    response,
                },
                &worker_admission,
            )
        });
        reached.wait();
        mutate(&store);
        release.wait();
        let _ = worker.join().expect("join post-decrypt reader");
        received
            .blocking_recv()
            .expect("post-decrypt response")
            .expect_err("post-decrypt mutation cannot release plaintext")
            .kind()
    }

    fn selected_node(root: &TestRoot) -> SelectedBlobNode {
        if !root.mission_path().exists() {
            persist_member_mission(root);
        }
        SelectedBlobNode::open_unprotected_reference(root.path(), root.mission_path())
            .expect("open selected Blob node")
    }

    fn prime_blob_policy_for_pressure(node: &SelectedBlobNode) {
        const BLOB_MAINTENANCE_CLASSES: u64 = 6;
        const POLICY_SETUP_AND_COMPLETION_UNITS: u64 = 6;
        let stats = node.store.blob_stats().expect("pressure priming stats");
        let root_count = stats
            .publications
            .checked_add(stats.pending_sources)
            .expect("pressure priming root count fits u64");
        let bound = BLOB_MAINTENANCE_CLASSES
            .checked_mul(
                root_count
                    .checked_add(POLICY_SETUP_AND_COMPLETION_UNITS)
                    .expect("pressure priming unit count fits u64"),
            )
            .expect("pressure priming turn bound fits u64");
        let sample = node
            .custody_clock
            .sample()
            .expect("sample pressure priming custody clock");
        for _ in 0..bound {
            node.store
                .run_blob_maintenance_turn_with_sample(
                    BlobMaintenanceBudget::new(64, 16, 128 * 1024 * 1024)
                        .expect("pressure priming maintenance budget"),
                    Some(sample),
                )
                .expect("prime Blob policy before pressure retry");
        }
    }

    fn selected_node_with_lifecycle_limits_and_clock(
        root: &TestRoot,
        limits: aster_redb_store::BlobLifecycleLimits,
        custody_clock: NodeCustodyClock,
    ) -> SelectedBlobNode {
        let mission = UnprotectedReferenceMission::load(root.mission_path())
            .expect("load selected Blob test mission");
        let store = Store::open_with_all_limits_for_mission(
            root.path().join(STORE_FILE),
            StoreLimits::default(),
            BlobDepotLimits::default(),
            aster_redb_store::EventOperationLimits::DEFAULT,
            limits,
            mission.mission_authority_id(),
        )
        .expect("open selected Blob test store with lifecycle limits");
        store
            .require_process_exclusive_lock()
            .expect("lock selected Blob test store");
        let StartupEventVerification {
            verifier,
            historical_verifier,
            cache,
            policy: _,
        } = open_startup_event_verifier_and_cache(&store, &mission)
            .expect("open selected Blob test verifier");
        drop(historical_verifier);
        ensure_principal_active(&store, verifier.identity())
            .expect("selected Blob test principal is active");
        let verifier_head = store
            .control_head()
            .expect("selected Blob test control head");
        let mut selected = SelectedBlobNode::from_runtime(
            mission,
            Arc::new(store),
            verifier,
            verifier_head,
            cache,
            custody_clock,
        )
        .expect("open selected Blob pack promotion pool");
        selected
            .current_policy("blob test open")
            .expect("load selected Blob test policy");
        selected
    }

    fn request(operation: &[u8]) -> BlobPublishRequest {
        BlobPublishRequest {
            operation_key: operation.to_vec(),
            topic: blob_topic(),
            scope: blob_scope(),
            priority: Priority::Priority,
            media_type: Some("application/x-aster-test".into()),
            schema_id: b"schema/blob-v1".to_vec(),
        }
    }

    fn subscription_request(operation: &[u8]) -> BlobSubscriptionRequest {
        BlobSubscriptionRequest {
            operation_key: operation.to_vec(),
            topic: blob_topic(),
            scope: blob_scope(),
            include_descendant_scopes: false,
        }
    }

    fn payload(length: usize) -> Vec<u8> {
        (0..length).map(|index| (index % 251) as u8).collect()
    }

    fn prepare_ready_stream(
        node: &mut SelectedBlobNode,
        operation: &[u8],
        bytes: &[u8],
    ) -> ([u8; 32], BlobPublishStreamRequest) {
        let request = BlobPublishStreamRequest {
            publication: request(operation),
            options: BlobPublishOptions::durable(),
            total_len: bytes.len() as u64,
        };
        let opened = node
            .open_publish_stream_inner(request.clone())
            .expect("open ready stream");
        for (index, chunk) in bytes.chunks(64 * 1024).enumerate() {
            node.append_publish_stream_inner(
                opened.token,
                (index * 64 * 1024) as u64,
                Zeroizing::new(chunk.to_vec()),
            )
            .expect("append ready stream");
        }
        (opened.token, request)
    }

    fn finish_stream_read_fixture(
        node: &mut SelectedBlobNode,
        operation: &[u8],
        bytes: &[u8],
        options: BlobPublishOptions,
    ) -> BlobReadRequest {
        let request = BlobPublishStreamRequest {
            publication: request(operation),
            options,
            total_len: bytes.len() as u64,
        };
        let opened = node
            .open_publish_stream_inner(request)
            .expect("open streamed read fixture");
        for (offset, chunk) in bytes.chunks(64 * 1024).enumerate() {
            node.append_publish_stream_inner(
                opened.token,
                (offset * 64 * 1024) as u64,
                Zeroizing::new(chunk.to_vec()),
            )
            .expect("append streamed read fixture");
        }
        let published = node
            .finish_publish_stream_inner(opened.token)
            .expect("finish streamed read fixture");
        BlobReadRequest {
            id: published.id,
            topic: blob_topic(),
            scope: blob_scope(),
        }
    }

    fn read_fixture_page(
        node: &mut SelectedBlobNode,
        blob: BlobReadRequest,
        offset: u64,
    ) -> Result<BlobReadPage, ApplicationError> {
        node.read_page(BlobReadPageRequest {
            blob,
            offset,
            max_bytes: 31,
        })
    }

    #[test]
    fn empty_stream_blob_returns_one_authorized_terminal_page() {
        // Break caught: a native empty pack publication must expose one
        // authenticated EOF page rather than being permanently unreadable.
        let root = TestRoot::new("empty-stream-read");
        let mut node = selected_node(&root);
        let blob = finish_stream_read_fixture(
            &mut node,
            b"blob/read-empty-stream",
            &[],
            BlobPublishOptions::durable(),
        );

        let page = node
            .read_page(BlobReadPageRequest {
                blob: blob.clone(),
                offset: 0,
                max_bytes: 31,
            })
            .expect("read authenticated empty EOF");
        assert!(page.is_empty());
        assert_eq!(page.offset, 0);
        assert_eq!(page.next_offset(), 0);
        assert_eq!(page.total_len, 0);
        assert!(page.complete);

        let error = node
            .read_page(BlobReadPageRequest {
                blob,
                offset: 1,
                max_bytes: 31,
            })
            .expect_err("nonzero empty offset is invalid");
        assert_eq!(error.kind(), ApplicationErrorKind::InvalidRequest);
    }

    #[test]
    fn cached_blob_reader_rechecks_revocation_epoch_grants_and_lifecycle_each_page() {
        // Break caught: a page-one authorization must not become reusable
        // plaintext authority after any control, selector, lifecycle, or
        // shutdown transition. Stream-created Blobs use the native pack plan.
        let bytes = payload(97);

        let policy_root = TestRoot::new("page-policy-generation");
        let mut policy_services = persist_rekey_mission(&policy_root);
        let mut policy_node = selected_node(&policy_root);
        let policy_blob = finish_stream_read_fixture(
            &mut policy_node,
            b"blob/read-matrix/policy",
            &bytes,
            BlobPublishOptions::durable(),
        );
        assert_eq!(
            read_fixture_page(&mut policy_node, policy_blob.clone(), 0)
                .expect("policy page one")
                .as_bytes(),
            &bytes[..31]
        );
        apply_scope_rekey_to_open_node(&policy_node, &mut policy_services, 1, 1);
        let error = read_fixture_page(&mut policy_node, policy_blob.clone(), 31)
            .expect_err("policy generation change denies page two");
        assert_eq!(error.kind(), ApplicationErrorKind::UnauthorizedOrRevoked);
        drop(policy_node);
        let mut reopened = selected_node(&policy_root);
        assert_eq!(
            read_fixture_page(&mut reopened, policy_blob, 31)
                .expect_err("policy denial survives reopen")
                .kind(),
            ApplicationErrorKind::UnauthorizedOrRevoked
        );

        let epoch_root = TestRoot::new("page-epoch");
        let mut epoch_services = persist_rekey_mission(&epoch_root);
        let mut epoch_node = selected_node(&epoch_root);
        let epoch_blob = finish_stream_read_fixture(
            &mut epoch_node,
            b"blob/read-matrix/epoch",
            &bytes,
            BlobPublishOptions::durable(),
        );
        read_fixture_page(&mut epoch_node, epoch_blob.clone(), 0).expect("epoch page one");
        apply_scope_rekey_to_open_node(&epoch_node, &mut epoch_services, 2, 1);
        assert_eq!(
            read_fixture_page(&mut epoch_node, epoch_blob, 31)
                .expect_err("rekey denies page two")
                .kind(),
            ApplicationErrorKind::UnauthorizedOrRevoked
        );

        let selector_root = TestRoot::new("page-selector");
        let mut selector_node = selected_node(&selector_root);
        let selector_blob = finish_stream_read_fixture(
            &mut selector_node,
            b"blob/read-matrix/selector",
            &bytes,
            BlobPublishOptions::durable(),
        );
        read_fixture_page(&mut selector_node, selector_blob.clone(), 0).expect("selector page one");
        let mut wrong_selector = selector_blob;
        wrong_selector.topic = Topic::new("ops.not-granted").expect("wrong selector topic");
        assert_eq!(
            read_fixture_page(&mut selector_node, wrong_selector, 31)
                .expect_err("selector change denies page two")
                .kind(),
            ApplicationErrorKind::RequestRejected
        );

        let revocation_root = TestRoot::new("page-revocation");
        let mut revocation_services = persist_rekey_mission(&revocation_root);
        let mut revocation_node = selected_node(&revocation_root);
        let revocation_blob = finish_stream_read_fixture(
            &mut revocation_node,
            b"blob/read-matrix/revocation",
            &bytes,
            BlobPublishOptions::durable(),
        );
        read_fixture_page(&mut revocation_node, revocation_blob.clone(), 0)
            .expect("revocation page one");
        let sealed = revocation_services
            .control_authority
            .seal_chained_revocation_control(revocation_services.selected_identity, 1, 1, None)
            .expect("seal page-two revocation");
        let verified = revocation_services
            .reader
            .verify_control(&sealed)
            .expect("verify page-two revocation");
        revocation_node
            .store
            .ingest_verified_control(&verified, &sealed)
            .expect("commit page-two revocation");
        assert_eq!(
            read_fixture_page(&mut revocation_node, revocation_blob, 31)
                .expect_err("publisher revocation denies page two")
                .kind(),
            ApplicationErrorKind::UnauthorizedOrRevoked
        );

        let lifecycle_root = TestRoot::new("page-lifecycle");
        let mut lifecycle_node = selected_node(&lifecycle_root);
        lifecycle_node.custody_clock = NodeCustodyClock::injected([0xe1; 16], 100, 0);
        let lifecycle_blob = finish_stream_read_fixture(
            &mut lifecycle_node,
            b"blob/read-matrix/lifecycle",
            &bytes,
            BlobPublishOptions::finite_ttl_ms(50).expect("finite fixture TTL"),
        );
        read_fixture_page(&mut lifecycle_node, lifecycle_blob.clone(), 0)
            .expect("lifecycle page one");
        lifecycle_node
            .custody_clock
            .set_injected_tick(151)
            .expect("expire page-two fixture");
        assert_eq!(
            read_fixture_page(&mut lifecycle_node, lifecycle_blob, 31)
                .expect_err("expiry denies page two")
                .kind(),
            ApplicationErrorKind::ExpiredOrRetired
        );

        let shutdown_root = TestRoot::new("page-shutdown");
        let mut shutdown_node = selected_node(&shutdown_root);
        let shutdown_blob = finish_stream_read_fixture(
            &mut shutdown_node,
            b"blob/read-matrix/shutdown",
            &bytes,
            BlobPublishOptions::durable(),
        );
        read_fixture_page(&mut shutdown_node, shutdown_blob.clone(), 0).expect("shutdown page one");
        let admission = AtomicBool::new(false);
        let mut fatal = None;
        let error = shutdown_node
            .read_page_with_admission(
                BlobReadPageRequest {
                    blob: shutdown_blob,
                    offset: 31,
                    max_bytes: 31,
                },
                &admission,
                None,
                &mut fatal,
            )
            .expect_err("shutdown denies page two");
        assert_eq!(error.kind(), ApplicationErrorKind::StateUnavailable);
        assert!(fatal.is_none());
    }

    #[test]
    fn live_profile5_pack_projection_mismatch_is_integrity_and_actor_fatal() {
        let root = TestRoot::new("live-pack-projection-mismatch");
        let mut node = selected_node(&root);
        let blob = finish_stream_read_fixture(
            &mut node,
            b"blob/read-pack-projection-mismatch",
            &payload(97),
            BlobPublishOptions::durable(),
        );
        node.live_pack_projection_coherence_fault = true;
        let (response, received) = oneshot::channel();
        let admission = AtomicBool::new(true);

        let error = node
            .execute_live(
                SelectedBlobCommand::ReadPage {
                    request: BlobReadPageRequest {
                        blob,
                        offset: 0,
                        max_bytes: 31,
                    },
                    response,
                },
                &admission,
            )
            .expect_err("stored projection/pack mismatch must stop the Blob actor");

        assert!(matches!(error, NodeError::FatalBlobCoherence(_)));
        assert!(received.blocking_recv().is_err());
    }

    #[test]
    fn final_blob_read_gate_rechecks_every_authority_dimension_after_decrypt() {
        let bytes = payload(97);

        let policy_root = TestRoot::new("post-decrypt-policy");
        let mut policy_services = persist_rekey_mission(&policy_root);
        let mut policy_node = selected_node(&policy_root);
        let policy_blob = finish_stream_read_fixture(
            &mut policy_node,
            b"blob/post-decrypt/policy",
            &bytes,
            BlobPublishOptions::durable(),
        );
        let kind = assert_post_decrypt_read_denied(policy_node, policy_blob.clone(), |store| {
            apply_scope_rekey_to_store(store, &mut policy_services, 1, 1, true);
        });
        assert_ne!(kind, ApplicationErrorKind::Integrity);
        let mut reopened = selected_node(&policy_root);
        assert!(read_fixture_page(&mut reopened, policy_blob, 0).is_err());

        let epoch_root = TestRoot::new("post-decrypt-epoch");
        let mut epoch_services = persist_rekey_mission(&epoch_root);
        let mut epoch_node = selected_node(&epoch_root);
        let epoch_blob = finish_stream_read_fixture(
            &mut epoch_node,
            b"blob/post-decrypt/epoch",
            &bytes,
            BlobPublishOptions::durable(),
        );
        let kind = assert_post_decrypt_read_denied(epoch_node, epoch_blob.clone(), |store| {
            apply_scope_rekey_to_store(store, &mut epoch_services, 2, 1, true);
        });
        assert_ne!(kind, ApplicationErrorKind::Integrity);
        let mut reopened = selected_node(&epoch_root);
        assert!(read_fixture_page(&mut reopened, epoch_blob, 0).is_err());

        let grant_root = TestRoot::new("post-decrypt-grant");
        let mut grant_services = persist_rekey_mission(&grant_root);
        let mut grant_node = selected_node(&grant_root);
        let grant_blob = finish_stream_read_fixture(
            &mut grant_node,
            b"blob/post-decrypt/grant",
            &bytes,
            BlobPublishOptions::durable(),
        );
        let kind = assert_post_decrypt_read_denied(grant_node, grant_blob, |store| {
            apply_scope_rekey_to_store(store, &mut grant_services, 2, 1, false);
        });
        assert_ne!(kind, ApplicationErrorKind::Integrity);

        let revocation_root = TestRoot::new("post-decrypt-revocation");
        let mut revocation_services = persist_rekey_mission(&revocation_root);
        let mut revocation_node = selected_node(&revocation_root);
        let revocation_blob = finish_stream_read_fixture(
            &mut revocation_node,
            b"blob/post-decrypt/revocation",
            &bytes,
            BlobPublishOptions::durable(),
        );
        let selected = revocation_services.selected_identity;
        let kind = assert_post_decrypt_read_denied(revocation_node, revocation_blob, |store| {
            let sealed = revocation_services
                .control_authority
                .seal_chained_revocation_control(selected, 1, 1, None)
                .expect("seal concurrent revocation");
            let verified = revocation_services
                .reader
                .verify_control(&sealed)
                .expect("verify concurrent revocation");
            store
                .ingest_verified_control(&verified, &sealed)
                .expect("commit concurrent revocation");
        });
        assert_ne!(kind, ApplicationErrorKind::Integrity);
        assert!(
            SelectedBlobNode::open_unprotected_reference(
                revocation_root.path(),
                revocation_root.mission_path(),
            )
            .is_err()
        );

        let lifecycle_root = TestRoot::new("post-decrypt-lifecycle");
        let mut lifecycle_node = selected_node(&lifecycle_root);
        lifecycle_node.custody_clock = NodeCustodyClock::injected([0xe2; 16], 100, 0);
        let lifecycle_blob = finish_stream_read_fixture(
            &mut lifecycle_node,
            b"blob/post-decrypt/lifecycle",
            &bytes,
            BlobPublishOptions::finite_ttl_ms(50).expect("finite lifecycle TTL"),
        );
        let kind =
            assert_post_decrypt_read_denied(lifecycle_node, lifecycle_blob.clone(), |store| {
                for _ in 0..16 {
                    store
                        .run_blob_maintenance_turn_with_sample(
                            BlobMaintenanceBudget::new(64, 16, 128 * 1024 * 1024)
                                .expect("post-decrypt maintenance budget"),
                            Some(CustodySample {
                                clock_id: [0xe2; 16],
                                tick_ms: 151,
                            }),
                        )
                        .expect("retire during post-decrypt gate");
                }
            });
        assert_ne!(kind, ApplicationErrorKind::Integrity);
        let mut reopened = selected_node(&lifecycle_root);
        assert!(read_fixture_page(&mut reopened, lifecycle_blob, 0).is_err());
    }

    async fn schedule_stream_pack_promotion_for_test(
        commands: &mpsc::Sender<SelectedApplicationCommand>,
        request: BlobPublishStreamRequest,
    ) -> Result<BlobPackPromotionCompletion, ApplicationError> {
        let (response, received) = oneshot::channel();
        commands
            .send(SelectedApplicationCommand::Blob(
                SelectedBlobCommand::OpenPublishStream { request, response },
            ))
            .await
            .expect("send live stream resume command");
        let (opened, session) = received
            .await
            .expect("receive live stream resume")
            .expect("resume ready stream");
        let token = opened.token;
        let (response, received) = oneshot::channel();
        commands
            .send(SelectedApplicationCommand::Blob(
                SelectedBlobCommand::FinishPublishStream {
                    token,
                    session,
                    response,
                },
            ))
            .await
            .expect("send stream finish command");
        match received
            .await
            .expect("receive stream finish scheduling ack")?
        {
            BlobPublishFinalization::Scheduled(completion) => Ok(completion),
            BlobPublishFinalization::Completed(_) => {
                panic!("fresh ready stream unexpectedly completed before scheduling")
            }
        }
    }

    #[test]
    fn stream_upload_finishes_as_native_pack_and_exact_retry() {
        // Break caught: finishing an application upload must enter the ordinary
        // Blob operation, acceptance, subscription, lifecycle, and capacity
        // authorities instead of a parallel stream-publication namespace.
        let root = TestRoot::new("native-pack-stream-upload");
        let bytes = payload(BLOB_STREAM_SEGMENT_BYTES + 7);
        let stream_request = BlobPublishStreamRequest {
            publication: request(b"blob/stream/single-pass"),
            options: BlobPublishOptions::durable(),
            total_len: bytes.len() as u64,
        };
        let result = {
            let mut node = selected_node(&root);
            let subscription = node
                .subscribe(subscription_request(b"blob/stream/subscription"))
                .expect("subscribe before upload");
            let opened = node
                .open_publish_stream_inner(stream_request.clone())
                .expect("open stream");
            assert_eq!(opened.progress.durable_offset, 0);
            for (offset, chunk) in bytes.chunks(64 * 1024).enumerate() {
                node.append_publish_stream_inner(
                    opened.token,
                    (offset * 64 * 1024) as u64,
                    Zeroizing::new(chunk.to_vec()),
                )
                .expect("append frame");
            }
            let result = node
                .finish_publish_stream_inner(opened.token)
                .expect("finish stream");
            assert!(result.inserted);
            assert_eq!(
                result.publication_id,
                Some(BlobStreamPublicationId::from_bytes(opened.token).unwrap())
            );
            let operation = BlobOperationKey::new(stream_request.publication.operation_key.clone())
                .expect("operation key");
            let stored = node
                .store
                .blob_for_operation(&operation)
                .expect("lifecycle operation lookup")
                .expect("lifecycle operation publication");
            assert_eq!(stored.blob_id, result.id.into_core());
            assert_eq!(stored.acceptance_marker, result.acceptance_marker);
            let status = node
                .transfer_status()
                .expect("native pack lifecycle status");
            assert_eq!(status.retained_publications, 1);
            assert_eq!(status.retained_pending_transfers, 0);
            let inspection = node
                .inspect_publication(BlobPublicationInspectionRequest {
                    publication_id: result.publication_id.expect("upload publication identity"),
                    topic: blob_topic(),
                    scope: blob_scope(),
                })
                .expect("inspect native pack upload");
            assert_eq!(inspection.phase, BlobPublicationPhase::Available);
            assert_eq!(inspection.blob_id, Some(result.id));
            let capacity = node.capacity_status().expect("native pack capacity status");
            assert_eq!(capacity.variants, 1);
            assert!(capacity.expected_chunks > 0);
            let page = node
                .poll(BlobPollRequest {
                    subscription: subscription.id,
                    delivery_limit: 1,
                    scan_limit: 4,
                })
                .expect("poll native pack upload");
            assert_eq!(page.deliveries.len(), 1);
            assert_eq!(content_delivery(&page.deliveries[0]).id, result.id);
            result
        };

        let mut reopened = selected_node(&root);
        let opened = reopened
            .open_publish_stream_inner(stream_request)
            .expect("reopen completed stream");
        assert_eq!(opened.progress.durable_offset, bytes.len() as u64);
        let replay = reopened
            .finish_publish_stream_inner(opened.token)
            .expect("replay completion");
        assert_eq!(replay.id, result.id);
        assert!(!replay.inserted);
        let mut restored = Vec::new();
        let mut offset = 0_u64;
        while offset < bytes.len() as u64 {
            let page = reopened
                .read_page(BlobReadPageRequest {
                    blob: BlobReadRequest {
                        id: result.id,
                        topic: blob_topic(),
                        scope: blob_scope(),
                    },
                    offset,
                    max_bytes: 64 * 1024,
                })
                .expect("read promoted stream page");
            assert_eq!(page.offset, offset);
            offset = page.next_offset;
            restored.extend_from_slice(page.as_bytes());
        }
        assert_eq!(restored, bytes);
    }

    #[test]
    fn stream_upload_promotes_native_pack_without_second_data_pass() {
        let root = TestRoot::new("stream-promote-native-pack");
        let bytes = payload(2 * BLOB_STREAM_SEGMENT_BYTES + 19);
        let stream_request = BlobPublishStreamRequest {
            publication: request(b"blob/stream/native-pack"),
            options: BlobPublishOptions::durable(),
            total_len: bytes.len() as u64,
        };
        let mut node = selected_node(&root);
        let opened = node
            .open_publish_stream_inner(stream_request.clone())
            .expect("open native pack upload");
        for (index, chunk) in bytes.chunks(64 * 1024).enumerate() {
            node.append_publish_stream_inner(
                opened.token,
                (index * 64 * 1024) as u64,
                Zeroizing::new(chunk.to_vec()),
            )
            .expect("append native pack upload");
        }
        let result = node
            .finish_publish_stream_inner(opened.token)
            .expect("promote native pack");
        let measured = node.pack_promotion_pool.last_report_for_test();
        assert_eq!(
            measured.segment_count,
            (bytes.len() as u64).div_ceil(BLOB_STREAM_SEGMENT_BYTES as u64)
        );
        assert_eq!(measured.plaintext_bytes_reprocessed, 0);
        assert_eq!(measured.ciphertext_bytes_rewritten, 0);
        assert_eq!(measured.store_boundary_operations, 9);
        assert_eq!(
            measured.store_boundary_trace,
            expected_native_pack_promotion_store_trace()
        );

        let owner = BlobOperationOwner::new(
            node.identity(),
            BlobOperationKey::new(stream_request.publication.operation_key.clone())
                .expect("native pack operation"),
        );
        assert!(
            node.store
                .resume_blob_upload(&owner)
                .expect("inspect promoted upload")
                .is_none(),
            "atomic promotion must consume provisional upload authority"
        );
        let policy = node.current_policy("inspect native pack").expect("policy");
        let stored = node
            .store
            .blob_for_owner_with_policy(&policy, &owner)
            .expect("lookup promoted publication")
            .expect("promoted publication");
        let session = node
            .store
            .open_profile5_pack_application_read(stored.variant_id)
            .expect("open lifecycle-owned native pack");
        assert_eq!(session.commitment().blob_id(), result.id.into_core());
        assert_eq!(session.open().total_len(), bytes.len() as u64);
    }

    fn expected_native_pack_promotion_store_trace() -> Vec<BlobPackPromotionStoreOperation> {
        vec![
            BlobPackPromotionStoreOperation::ReplayAuthority,
            BlobPackPromotionStoreOperation::ReadControlHead,
            BlobPackPromotionStoreOperation::RefreshPolicy,
            BlobPackPromotionStoreOperation::ReserveProfile5Upload,
            BlobPackPromotionStoreOperation::CheckpointProfile5Pack,
            BlobPackPromotionStoreOperation::CompleteProfile5Pack,
            BlobPackPromotionStoreOperation::ReadProfile5PackBinding,
            BlobPackPromotionStoreOperation::CommitProfile5Publication,
            BlobPackPromotionStoreOperation::CacheProfile5Publication,
        ]
    }

    #[test]
    fn native_pack_promotion_job_requires_non_escaping_store_facade() {
        type Constructor = fn(
            BlobPackPromotionAuthority,
            BlobUploadReservation,
            aster_redb_store::BlobUploadCheckpoint,
            VerifiedBlobStreamOpen,
            Option<BlobPackWriter>,
            Arc<BlobPublishStreamRequest>,
        ) -> BlobPackPromotionJob;

        fn take_owned_store(job: BlobPackPromotionJob) -> BlobPackPromotionStore {
            job.store
        }

        trait AmbiguousIfStoreDeref<Marker> {
            fn assert_not_store_deref() {}
        }
        impl<T: ?Sized> AmbiguousIfStoreDeref<()> for T {}
        impl<T: ?Sized + std::ops::Deref> AmbiguousIfStoreDeref<u8> for T {}

        trait AmbiguousIfStoreAsRef<Marker> {
            fn assert_not_store_as_ref() {}
        }
        impl<T: ?Sized> AmbiguousIfStoreAsRef<()> for T {}
        impl<T: ?Sized + AsRef<Store>> AmbiguousIfStoreAsRef<u8> for T {}

        trait AmbiguousIfArcStoreAsRef<Marker> {
            fn assert_not_arc_store_as_ref() {}
        }
        impl<T: ?Sized> AmbiguousIfArcStoreAsRef<()> for T {}
        impl<T: ?Sized + AsRef<Arc<Store>>> AmbiguousIfArcStoreAsRef<u8> for T {}

        let _: Constructor = BlobPackPromotionJob::new;
        let _: fn(BlobPackPromotionJob) -> BlobPackPromotionStore = take_owned_store;
        let _ = <BlobPackPromotionStore as AmbiguousIfStoreDeref<_>>::assert_not_store_deref;
        let _ = <BlobPackPromotionStore as AmbiguousIfStoreAsRef<_>>::assert_not_store_as_ref;
        let _ =
            <BlobPackPromotionStore as AmbiguousIfArcStoreAsRef<_>>::assert_not_arc_store_as_ref;
    }

    fn blob_pack_promotion_measurement_json(
        total_len: u64,
        measured: &BlobPackPromotionMetrics,
    ) -> serde_json::Value {
        serde_json::json!({
            "schema": "aster.local_blob_pack_promotion.measurement.v1",
            "requested_plaintext_bytes": total_len,
            "segments": measured.segment_count,
            "plaintext_bytes_reprocessed": measured.plaintext_bytes_reprocessed,
            "ciphertext_bytes_rewritten": measured.ciphertext_bytes_rewritten,
            "store_boundary_operations": measured.store_boundary_operations,
        })
    }

    fn run_stream_pack_promotion_measurement_gate(label: &str, total_len: u64) {
        let root = TestRoot::new(label);
        persist_member_mission(&root);
        let mut node = SelectedBlobNode::open_unprotected_reference_with_options(
            root.path(),
            root.mission_path(),
            SelectedBlobOptions {
                depot_limits: BlobDepotLimits::new(3 * 1024 * 1024 * 1024, MAX_BLOB_CHUNKS, 2)
                    .expect("measurement depot limits"),
            },
        )
        .expect("open measurement node");
        let opened = node
            .open_publish_stream_inner(BlobPublishStreamRequest {
                publication: request(label.as_bytes()),
                options: BlobPublishOptions::durable(),
                total_len,
            })
            .expect("open measurement stream");
        let mut offset = 0_u64;
        while offset < total_len {
            let len =
                usize::try_from((total_len - offset).min(u64::from(SELECTED_BLOB_CHUNK_SIZE)))
                    .expect("measurement chunk length");
            let bytes = (0..len)
                .map(|index| ((offset as usize + index) % 251) as u8)
                .collect::<Vec<_>>();
            node.append_publish_stream_inner(opened.token, offset, Zeroizing::new(bytes))
                .expect("append measurement stream");
            offset += len as u64;
        }
        node.finish_publish_stream_inner(opened.token)
            .expect("finish measurement stream");
        let measured = node.pack_promotion_pool.last_report_for_test();
        println!(
            "{}",
            blob_pack_promotion_measurement_json(total_len, &measured)
        );
    }

    #[test]
    #[ignore = "exact-size local performance gate; run on an authorized measurement host"]
    fn stream_upload_pack_promotion_measurement_800_mib() {
        run_stream_pack_promotion_measurement_gate(
            "blob/stream/pack-promotion-measurement-800-mib",
            800 * 1024 * 1024,
        );
    }

    #[test]
    #[ignore = "exact-size local performance gate; run on an authorized measurement host"]
    fn stream_upload_pack_promotion_measurement_1_gib() {
        run_stream_pack_promotion_measurement_gate(
            "blob/stream/pack-promotion-measurement-1-gib",
            1024 * 1024 * 1024,
        );
    }

    #[test]
    fn selected_blob_publish_stream_promotes_and_replays_exact_operation() {
        // Preserve the focused PR 95 contract gate while the native pack test
        // name records the repaired authority model.
        stream_upload_finishes_as_native_pack_and_exact_retry();
    }

    #[test]
    fn two_uploads_and_unrelated_publication_get_unique_dots() {
        // Stream OPEN durably reserves publisher counters so arbitrary finish
        // order and cross-class publication cannot reuse a causal identity.
        let root = TestRoot::new("stream-upload-dot-order");
        let first = payload(71);
        let second = payload(89);
        let first_request = BlobPublishStreamRequest {
            publication: request(b"blob/stream/dot/first"),
            options: BlobPublishOptions::durable(),
            total_len: first.len() as u64,
        };
        let second_request = BlobPublishStreamRequest {
            publication: request(b"blob/stream/dot/second"),
            options: BlobPublishOptions::durable(),
            total_len: second.len() as u64,
        };
        let mut node = selected_node(&root);
        let first_open = node
            .open_publish_stream_inner(first_request)
            .expect("open first upload");
        let second_open = node
            .open_publish_stream_inner(second_request)
            .expect("open second upload");
        node.append_publish_stream_inner(first_open.token, 0, Zeroizing::new(first))
            .expect("write first upload");
        node.append_publish_stream_inner(second_open.token, 0, Zeroizing::new(second))
            .expect("write second upload");

        let unrelated = node
            .publish(
                request(b"blob/unrelated-between-uploads"),
                &mut Cursor::new(payload(43)),
            )
            .expect("publish unrelated Blob");
        let second_result = node
            .finish_publish_stream_inner(second_open.token)
            .expect("finish second upload");
        let first_result = node
            .finish_publish_stream_inner(first_open.token)
            .expect("finish first upload");

        assert_eq!(first_result.publisher_counter, 1);
        assert_eq!(second_result.publisher_counter, 2);
        assert_eq!(unrelated.publisher_counter, 3);
        assert_eq!(node.store.blob_stats().expect("Blob stats").publications, 3);
    }

    #[test]
    fn stream_upload_policy_change_before_finish_publishes_nothing() {
        // Break caught: a stale upload reservation must fail current-policy
        // reauthorization without publishing or leaving a causal hole.
        let root = TestRoot::new("stream-upload-policy-change");
        let mut services = persist_rekey_mission(&root);
        let bytes = payload(79);
        let total_len = bytes.len() as u64;
        let stream_request = BlobPublishStreamRequest {
            publication: request(b"blob/stream/stale-policy"),
            options: BlobPublishOptions::durable(),
            total_len,
        };
        let owner = BlobOperationOwner::new(
            selected_node(&root).identity(),
            BlobOperationKey::new(stream_request.publication.operation_key.clone())
                .expect("stale-policy operation"),
        );
        {
            let mut node = selected_node(&root);
            let opened = node
                .open_publish_stream_inner(stream_request.clone())
                .expect("open old-policy upload");
            node.append_publish_stream_inner(opened.token, 0, Zeroizing::new(bytes))
                .expect("write old-policy upload");
        }
        apply_epoch_two_rekey(&root, &mut services);

        let mut reopened = selected_node(&root);
        let first = match reopened.open_publish_stream_inner(stream_request.clone()) {
            Ok(_) => panic!("stale upload policy must fail reauthorization"),
            Err(error) => error,
        };
        let error = if first.kind() == ApplicationErrorKind::PolicyUnsettled {
            match reopened.open_publish_stream_inner(stream_request) {
                Ok(_) => panic!("stale upload policy must fail after policy refresh"),
                Err(error) => error,
            }
        } else {
            first
        };
        assert!(matches!(
            error.kind(),
            ApplicationErrorKind::RequestRejected | ApplicationErrorKind::PolicyUnsettled
        ));
        let stats = reopened.store.blob_stats().expect("post-policy Blob stats");
        assert_eq!(stats.publications, 0);
        assert_eq!(stats.pending_sources, 0);
        let (reservation, checkpoint) = reopened
            .store
            .resume_blob_upload(&owner)
            .expect("inspect stale upload cleanup authority")
            .expect("stale upload remains cleanup-authorized");
        assert_eq!(checkpoint.durable_plaintext_offset(), total_len);
        assert_eq!(
            checkpoint
                .credit_consumed_bytes()
                .checked_add(checkpoint.credit_remaining_bytes())
                .expect("upload credit total"),
            reservation.reserved_bytes(),
        );
        assert!(reservation.reserved_bytes() > 0);
    }

    #[test]
    fn stream_upload_handles_empty_exact_segment_and_maximum_boundaries() {
        // Break caught: empty native pack publication must settle without data,
        // replay exactly, and leave no provisional capacity behind.
        let root = TestRoot::new("stream-upload-boundaries");
        let mut node = selected_node(&root);
        assert_eq!(
            MAX_SELECTED_BLOB_STREAM_BYTES,
            8 * 1024 * 1024 * 1024,
            "public stream ceiling remains 8 GiB"
        );
        let error = match node.open_publish_stream_inner(BlobPublishStreamRequest {
            publication: request(b"blob/stream/oversize"),
            options: BlobPublishOptions::durable(),
            total_len: MAX_SELECTED_BLOB_STREAM_BYTES + 1,
        }) {
            Ok(_) => panic!("invalid stream boundary was admitted"),
            Err(error) => error,
        };
        assert_eq!(error.kind(), ApplicationErrorKind::ResourceLimit);

        let empty = BlobPublishStreamRequest {
            publication: request(b"blob/stream/empty"),
            options: BlobPublishOptions::durable(),
            total_len: 0,
        };
        let opened = node
            .open_publish_stream_inner(empty.clone())
            .expect("open empty stream");
        let empty_result = node
            .finish_publish_stream_inner(opened.token)
            .expect("finish empty stream without data");
        let empty_status = node
            .inspect_publication(BlobPublicationInspectionRequest {
                publication_id: empty_result
                    .publication_id
                    .expect("empty publication identity"),
                topic: blob_topic(),
                scope: blob_scope(),
            })
            .expect("inspect empty publication");
        assert_eq!(empty_status.phase, BlobPublicationPhase::Available);
        assert_eq!(empty_status.plaintext_total_bytes, 0);
        assert_eq!(empty_status.transfer_total_bytes, 0);
        assert_eq!(empty_status.durable_transfer_bytes, 0);
        assert_eq!(empty_status.total_units, 0);
        assert_eq!(empty_status.blob_id, Some(empty_result.id));
        let before_retry = node.capacity_status().expect("capacity after empty finish");
        assert_eq!(before_retry.pending_sources, 0);
        assert_eq!(before_retry.network_staging_bytes, 0);
        let retry = node
            .open_publish_stream_inner(empty)
            .expect("reopen exact empty stream");
        let replay = node
            .finish_publish_stream_inner(retry.token)
            .expect("replay empty stream");
        assert_eq!(replay.id, empty_result.id);
        assert!(!replay.inserted);
        assert_eq!(node.capacity_status().unwrap(), before_retry);

        let bytes = payload(BLOB_STREAM_SEGMENT_BYTES);
        let exact = BlobPublishStreamRequest {
            publication: request(b"blob/stream/exact-native-segment"),
            options: BlobPublishOptions::durable(),
            total_len: bytes.len() as u64,
        };
        let opened = node
            .open_publish_stream_inner(exact)
            .expect("open exact native segment");
        node.append_publish_stream_inner(opened.token, 0, Zeroizing::new(bytes.clone()))
            .expect("write exact native segment");
        let result = node
            .finish_publish_stream_inner(opened.token)
            .expect("finish exact native segment");
        let mut restored = Vec::new();
        node.read_into(
            BlobReadRequest {
                id: result.id,
                topic: blob_topic(),
                scope: blob_scope(),
            },
            &mut restored,
        )
        .expect("ordinary native pack read");
        assert_eq!(restored, bytes);

        drop(node);
        let maximum_root = TestRoot::new("stream-upload-maximum");
        persist_member_mission(&maximum_root);
        let mut maximum_node = SelectedBlobNode::open_unprotected_reference_with_options(
            maximum_root.path(),
            maximum_root.mission_path(),
            SelectedBlobOptions {
                depot_limits: BlobDepotLimits::new(u64::MAX, MAX_BLOB_CHUNKS, 1)
                    .expect("maximum-upload depot limits"),
            },
        )
        .expect("open maximum-upload node");
        let maximum = maximum_node
            .open_publish_stream_inner(BlobPublishStreamRequest {
                publication: request(b"blob/stream/maximum"),
                options: BlobPublishOptions::durable(),
                total_len: MAX_SELECTED_BLOB_STREAM_BYTES,
            })
            .expect("maximum upload is admitted within configured limits");
        assert_eq!(
            maximum.progress,
            BlobPublishProgress {
                accepted_offset: 0,
                durable_offset: 0
            }
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 3)]
    async fn stream_pack_promotion_worker_does_not_block_unrelated_application_command() {
        // Break caught: native pack promotion on the actor prevents
        // unrelated application commands from being serviced.
        let root = TestRoot::new("stream-pack-promotion-worker");
        let bytes = payload(SELECTED_BLOB_CHUNK_SIZE as usize + 19);
        let mut node = selected_node(&root);
        let (reached_tx, reached_rx) = std::sync::mpsc::sync_channel(1);
        let (finished_tx, _finished_rx) = std::sync::mpsc::sync_channel(1);
        let release = Arc::new((std::sync::Mutex::new(false), std::sync::Condvar::new()));
        node.set_stream_pack_promotion_gate_for_test(reached_tx, finished_tx, Arc::clone(&release));
        let identity = node.identity();
        let mission_authority = node.mission_authority();
        let admission = Arc::new(AtomicBool::new(true));
        let worker_admission = Arc::clone(&admission);
        let (commands, mut received) = mpsc::channel(4);
        let handle = SelectedBlobHandle::new(commands, admission, identity, mission_authority);
        let worker = tokio::task::spawn_blocking(move || {
            while let Some(command) = received.blocking_recv() {
                let SelectedApplicationCommand::Blob(command) = command else {
                    panic!("pack promotion responsiveness test received another application class");
                };
                node.execute_live(command, &worker_admission)
                    .expect("execute pack promotion responsiveness command");
            }
        });
        let mut stream = handle
            .open_publish_stream(BlobPublishStreamRequest {
                publication: request(b"blob/stream/pack-promotion-worker"),
                options: BlobPublishOptions::durable(),
                total_len: bytes.len() as u64,
            })
            .await
            .expect("open live upload");
        for (offset, chunk) in bytes.chunks(64 * 1024).enumerate() {
            stream
                .write((offset * 64 * 1024) as u64, Zeroizing::new(chunk.to_vec()))
                .await
                .expect("write live upload");
        }
        let finishing = tokio::spawn(async move { stream.finish().await });
        tokio::task::spawn_blocking(move || {
            reached_rx.recv().expect("promotion worker reached gate")
        })
        .await
        .expect("join gate observer");
        tokio::time::timeout(std::time::Duration::from_secs(1), handle.capacity_status())
            .await
            .expect("actor services capacity command while promotion worker is held")
            .expect("capacity status");
        {
            let (released, wake) = &*release;
            *released.lock().expect("promotion worker release lock") = true;
            wake.notify_all();
        }
        finishing
            .await
            .expect("join finish task")
            .expect("finish live upload");
        drop(handle);
        worker.await.expect("join live application actor");
    }

    // Always release a paused real worker before dropping its joined pool, even
    // when an assertion fails. This guard belongs only to the test harness.
    struct ReleasePromotionGate(Arc<(std::sync::Mutex<bool>, std::sync::Condvar)>);

    impl Drop for ReleasePromotionGate {
        fn drop(&mut self) {
            let (released, wake) = &*self.0;
            *released
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner) = true;
            wake.notify_all();
        }
    }

    #[test]
    fn stream_pack_promotion_prepared_job_excludes_retry_until_dropped() {
        // Break caught: an owned but not-yet-scheduled job must retain the only
        // writer, and dropping that job must permit recovery of the checkpoint.
        let root = TestRoot::new("promotion-prepared-ownership");
        let mut node = selected_node(&root);
        let bytes = payload(31);
        let (token, request) = prepare_ready_stream(&mut node, b"prepared-owner", &bytes);
        let prepared = node.prepare_publish_stream_finalization(token).unwrap();
        let retry = node.open_publish_stream_inner(request.clone());
        assert!(
            matches!(retry, Err(error) if error.kind() == ApplicationErrorKind::StateUnavailable)
        );
        let duplicate_finish = node.prepare_publish_stream_finalization(token);
        assert!(
            matches!(duplicate_finish, Err(error) if error.kind() == ApplicationErrorKind::StateUnavailable)
        );
        let mut changed = request.clone();
        changed.total_len += 1;
        assert!(
            matches!(node.open_publish_stream_inner(changed), Err(error) if error.kind() == ApplicationErrorKind::Conflict)
        );
        drop(prepared);
        let resumed = node.open_publish_stream_inner(request).unwrap();
        assert_eq!(resumed.progress.durable_offset, 31);
        let result = node.finish_publish_stream_inner(resumed.token).unwrap();
        assert!(result.inserted);
        let page = read_fixture_page(
            &mut node,
            BlobReadRequest {
                id: result.id,
                topic: blob_topic(),
                scope: blob_scope(),
            },
            0,
        )
        .unwrap();
        assert_eq!(page.as_bytes(), bytes);
    }

    #[test]
    fn stream_pack_promotion_active_retry_preserves_committed_pack() {
        // Break caught: reopening the same operation after worker preflight can
        // restore/truncate its writer or overwrite its authenticated completion.
        for ttl_ms in [None, Some(50_000)] {
            let root = TestRoot::new("promotion-active-ownership");
            let mut node = selected_node(&root);
            node.custody_clock = NodeCustodyClock::injected([0xa3; 16], 1_000, 0);
            let bytes = payload(31);
            let request = BlobPublishStreamRequest {
                publication: request(b"active-owner"),
                options: ttl_ms.map_or(BlobPublishOptions::durable(), |ttl| {
                    BlobPublishOptions::finite_ttl_ms(ttl).unwrap()
                }),
                total_len: 31,
            };
            let opened = node.open_publish_stream_inner(request.clone()).unwrap();
            node.append_publish_stream_inner(opened.token, 0, Zeroizing::new(bytes.clone()))
                .unwrap();
            let (started_tx, started_rx) = std::sync::mpsc::sync_channel(1);
            let (finished_tx, _finished_rx) = std::sync::mpsc::sync_channel(1);
            let release = ReleasePromotionGate(Arc::new((
                std::sync::Mutex::new(false),
                std::sync::Condvar::new(),
            )));
            node.set_stream_pack_promotion_gate_for_test(
                started_tx,
                finished_tx,
                Arc::clone(&release.0),
            );
            let BlobPublishFinalization::Scheduled(completion) = node
                .schedule_publish_stream_finalization(opened.token)
                .unwrap()
            else {
                panic!("fresh publication must be scheduled");
            };
            started_rx
                .recv_timeout(std::time::Duration::from_secs(10))
                .unwrap();
            assert!(
                matches!(node.open_publish_stream_inner(request.clone()), Err(error) if error.kind() == ApplicationErrorKind::StateUnavailable)
            );
            let one_shot = node.publish_native_reader(
                request.publication.clone(),
                request.options,
                &mut Cursor::new(bytes.clone()),
                31,
                Some(31),
                None,
            );
            assert!(
                matches!(one_shot, Err(error) if error.kind() == ApplicationErrorKind::StateUnavailable)
            );

            // The other worker can publish a different operation while this
            // one is held. Distinct content avoids unrelated dedup policy.
            node.stream_pack_promotion_gate = None;
            let (other, _) = prepare_ready_stream(&mut node, b"other-owner", &payload(37));
            assert!(node.finish_publish_stream_inner(other).unwrap().inserted);
            node.custody_clock.set_injected_tick(1_005).unwrap();
            drop(release);
            let result = completion.blocking_recv().unwrap().unwrap();
            let blob = BlobReadRequest {
                id: result.id,
                topic: blob_topic(),
                scope: blob_scope(),
            };
            assert_eq!(
                read_fixture_page(&mut node, blob.clone(), 0)
                    .unwrap()
                    .as_bytes(),
                bytes
            );
            drop(node);
            let mut reopened = selected_node(&root);
            reopened.custody_clock = NodeCustodyClock::injected([0xa3; 16], 1_006, 0);
            assert_eq!(
                read_fixture_page(&mut reopened, blob, 0)
                    .unwrap()
                    .as_bytes(),
                bytes
            );
            let replay = reopened.open_publish_stream_inner(request).unwrap();
            assert!(
                !reopened
                    .finish_publish_stream_inner(replay.token)
                    .unwrap()
                    .inserted
            );
        }
    }

    #[test]
    fn stream_pack_promotion_integrity_releases_operation_for_retry_after_reopen() {
        // Break caught: a fatal promotion must release owned resources so a
        // fresh facade can resume the durable upload after the fault is repaired.
        let root = TestRoot::new("promotion-error-ownership");
        let mut node = selected_node(&root);
        node.custody_clock = NodeCustodyClock::injected([0xa4; 16], 1_000, 1);
        let request = BlobPublishStreamRequest {
            publication: request(b"error-owner"),
            options: BlobPublishOptions::finite_ttl_ms(50_000).unwrap(),
            total_len: 31,
        };
        let opened = node.open_publish_stream_inner(request.clone()).unwrap();
        node.append_publish_stream_inner(opened.token, 0, Zeroizing::new(payload(31)))
            .unwrap();
        let (started_tx, started_rx) = std::sync::mpsc::sync_channel(1);
        let (finished_tx, _finished_rx) = std::sync::mpsc::sync_channel(1);
        let release = ReleasePromotionGate(Arc::new((
            std::sync::Mutex::new(false),
            std::sync::Condvar::new(),
        )));
        node.set_stream_pack_promotion_gate_for_test(
            started_tx,
            finished_tx,
            Arc::clone(&release.0),
        );
        let BlobPublishFinalization::Scheduled(completion) = node
            .schedule_publish_stream_finalization(opened.token)
            .unwrap()
        else {
            panic!("fresh publication must be scheduled");
        };
        started_rx
            .recv_timeout(std::time::Duration::from_secs(10))
            .unwrap();
        // Existing injected clock fails its next sample, exercising a real
        // fallible production operation without changing filesystem contents.
        node.custody_clock.set_injected_tick(u64::MAX).unwrap();
        drop(release);
        assert_eq!(
            completion.blocking_recv().unwrap().unwrap_err().kind(),
            ApplicationErrorKind::Integrity
        );
        assert!(matches!(
            node.join_live_promotions(),
            Err(NodeError::FatalBlobCoherence(_))
        ));
        drop(node);
        let mut node = selected_node(&root);
        node.custody_clock = NodeCustodyClock::injected([0xa4; 16], 1_005, 1);
        let retry = node.open_publish_stream_inner(request).unwrap();
        let result = node.finish_publish_stream_inner(retry.token).unwrap();
        assert!(result.inserted);
        let blob = BlobReadRequest {
            id: result.id,
            topic: blob_topic(),
            scope: blob_scope(),
        };
        assert_eq!(
            read_fixture_page(&mut node, blob, 0).unwrap().as_bytes(),
            payload(31)
        );
    }

    #[test]
    fn stream_pack_promotion_process_exit_does_not_leave_busy_operation() {
        // Break caught: a receiver process exits without running destructors;
        // upload recovery must remain possible without a durable busy flag.
        const CHILD_ROOT: &str = "ASTER_TEST_PROMOTION_EXIT_ROOT";
        const CHILD_STAGE: &str = "ASTER_TEST_PROMOTION_EXIT_STAGE";
        const TEST: &str = "application::blob::tests::stream_pack_promotion_process_exit_does_not_leave_busy_operation";
        if let Some(path) = std::env::var_os(CHILD_ROOT) {
            let root = std::mem::ManuallyDrop::new(TestRoot(PathBuf::from(path)));
            let mut node = selected_node(&root);
            let stage = std::env::var(CHILD_STAGE).unwrap();
            let opened = node
                .open_publish_stream_inner(BlobPublishStreamRequest {
                    publication: request(b"process-exit-owner"),
                    options: BlobPublishOptions::durable(),
                    total_len: if stage == "upload" { 62 } else { 31 },
                })
                .unwrap();
            let token = opened.token;
            node.append_publish_stream_inner(token, 0, Zeroizing::new(payload(31)))
                .unwrap();
            match stage.as_str() {
                "upload" => std::process::exit(73),
                "prepared" => {
                    let _job = node.prepare_publish_stream_finalization(token).unwrap();
                    std::process::exit(73);
                }
                "running" => {
                    let (started_tx, started_rx) = std::sync::mpsc::sync_channel(1);
                    let (finished_tx, _finished_rx) = std::sync::mpsc::sync_channel(1);
                    let release = ReleasePromotionGate(Arc::new((
                        std::sync::Mutex::new(false),
                        std::sync::Condvar::new(),
                    )));
                    node.set_stream_pack_promotion_gate_for_test(
                        started_tx,
                        finished_tx,
                        Arc::clone(&release.0),
                    );
                    let _completion = node.schedule_publish_stream_finalization(token).unwrap();
                    started_rx
                        .recv_timeout(std::time::Duration::from_secs(10))
                        .unwrap();
                    std::process::exit(73);
                }
                "committed" => {
                    node.finish_publish_stream_inner(token).unwrap();
                    std::process::exit(73);
                }
                _ => panic!("unknown process-exit stage"),
            }
        }
        for stage in ["upload", "prepared", "running", "committed"] {
            let root = TestRoot::new("promotion-process-exit");
            drop(selected_node(&root));
            let mut child = std::process::Command::new(std::env::current_exe().unwrap())
                .args(["--exact", TEST, "--nocapture"])
                .env(CHILD_ROOT, root.path())
                .env(CHILD_STAGE, stage)
                .spawn()
                .unwrap();
            let deadline = std::time::Instant::now() + std::time::Duration::from_secs(30);
            let status = loop {
                if let Some(status) = child.try_wait().unwrap() {
                    break status;
                }
                if std::time::Instant::now() >= deadline {
                    child.kill().unwrap();
                    child.wait().unwrap();
                    panic!("process-exit child timed out at {stage}");
                }
                std::thread::sleep(std::time::Duration::from_millis(10));
            };
            assert_eq!(status.code(), Some(73), "child reached {stage}");
            let request = BlobPublishStreamRequest {
                publication: request(b"process-exit-owner"),
                options: BlobPublishOptions::durable(),
                total_len: if stage == "upload" { 62 } else { 31 },
            };
            let mut reopened = selected_node(&root);
            let retry = reopened.open_publish_stream_inner(request).unwrap();
            assert_eq!(
                retry.progress.durable_offset,
                if stage == "upload" { 0 } else { 31 }
            );
            if retry.progress.durable_offset == 0 {
                reopened
                    .append_publish_stream_inner(retry.token, 0, Zeroizing::new(payload(62)))
                    .unwrap();
            }
            let result = reopened.finish_publish_stream_inner(retry.token).unwrap();
            assert_eq!(result.inserted, stage != "committed");
            let blob = BlobReadRequest {
                id: result.id,
                topic: blob_topic(),
                scope: blob_scope(),
            };
            assert_eq!(
                read_fixture_page(&mut reopened, blob, 0)
                    .unwrap()
                    .as_bytes(),
                payload(31)
            );
        }
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn stream_pack_promotion_pool_bounds_active_and_queued_jobs_and_retry_after_saturation() {
        // Break caught: delegating each finish to Tokio's global blocking pool
        // admits an unbounded number of expensive native pack promotions.
        let root = TestRoot::new("stream-pack-promotion-saturation");
        let (mut node, ready) = tokio::task::block_in_place(|| {
            let mut node = selected_node(&root);
            let mut ready = Vec::new();
            for index in 0..5 {
                // Distinct content keeps this worker-capacity test independent
                // from same-content physical-lineage conflict policy.
                let bytes = payload(SELECTED_BLOB_CHUNK_SIZE as usize + 29 + index);
                ready.push(prepare_ready_stream(
                    &mut node,
                    format!("blob/stream/pack-promotion-saturation-{index}").as_bytes(),
                    &bytes,
                ));
            }
            (node, ready)
        });
        let (started_tx, started_rx) = std::sync::mpsc::sync_channel(8);
        let (finished_tx, _finished_rx) = std::sync::mpsc::sync_channel(8);
        let release = Arc::new((std::sync::Mutex::new(false), std::sync::Condvar::new()));
        node.set_stream_pack_promotion_gate_for_test(started_tx, finished_tx, Arc::clone(&release));
        let identity = node.identity();
        let mission_authority = node.mission_authority();
        let admission = Arc::new(AtomicBool::new(true));
        let worker_admission = Arc::clone(&admission);
        let (commands, mut received) = mpsc::channel(16);
        let direct = commands.clone();
        let handle = SelectedBlobHandle::new(commands, admission, identity, mission_authority);
        let worker = tokio::task::spawn_blocking(move || {
            while let Some(command) = received.blocking_recv() {
                let SelectedApplicationCommand::Blob(command) = command else {
                    panic!("pack promotion saturation test received another application class");
                };
                node.execute_live(command, &worker_admission)
                    .expect("execute pack promotion saturation command");
            }
        });

        let mut completions = Vec::new();
        completions.push(
            schedule_stream_pack_promotion_for_test(&direct, ready[0].1.clone())
                .await
                .expect("admit first active promotion worker"),
        );
        completions.push(
            schedule_stream_pack_promotion_for_test(&direct, ready[1].1.clone())
                .await
                .expect("admit second active promotion worker"),
        );
        tokio::task::spawn_blocking(move || {
            started_rx.recv().expect("first promotion worker started");
            started_rx.recv().expect("second promotion worker started");
        })
        .await
        .expect("observe bounded active promotion workers");
        completions.push(
            schedule_stream_pack_promotion_for_test(&direct, ready[2].1.clone())
                .await
                .expect("admit first queued promotion job"),
        );
        completions.push(
            schedule_stream_pack_promotion_for_test(&direct, ready[3].1.clone())
                .await
                .expect("admit second queued promotion job"),
        );
        let saturated = schedule_stream_pack_promotion_for_test(&direct, ready[4].1.clone())
            .await
            .expect_err("fifth promotion job exceeds two workers plus two queued jobs");
        assert_eq!(saturated.kind(), ApplicationErrorKind::ResourceLimit);
        tokio::time::timeout(std::time::Duration::from_secs(1), handle.capacity_status())
            .await
            .expect("actor remains responsive while pack promotion pool is saturated")
            .expect("capacity status while saturated");

        {
            let (released, wake) = &*release;
            *released.lock().expect("promotion worker release lock") = true;
            wake.notify_all();
        }
        for completion in completions {
            tokio::time::timeout(std::time::Duration::from_secs(10), completion)
                .await
                .expect("admitted promotion job completes")
                .expect("completion sender retained")
                .expect("native pack promotion succeeds");
        }
        let retry = handle
            .open_publish_stream(ready[4].1.clone())
            .await
            .expect("saturated upload remains retry-safe");
        assert_eq!(retry.durable_offset(), ready[4].1.total_len);
        assert!(
            retry
                .finish()
                .await
                .expect("retry after pool drain")
                .inserted
        );

        drop(handle);
        drop(direct);
        worker.await.expect("join saturated application actor");
    }

    #[test]
    fn stream_pack_promotion_closed_pool_leaves_sealed_upload_retry_safe() {
        // Break caught: closed admission must not consume the durable upload
        // reservation after the actor seals and removes the in-memory stream.
        let root = TestRoot::new("stream-pack-promotion-closed-pool");
        let bytes = payload(SELECTED_BLOB_CHUNK_SIZE as usize + 31);
        let mut node = selected_node(&root);
        let (token, request) =
            prepare_ready_stream(&mut node, b"blob/stream/pack-promotion-closed-pool", &bytes);
        node.pack_promotion_pool.shutdown();

        let error = node
            .finish_publish_stream_inner(token)
            .expect_err("closed pack promotion pool rejects admission");
        assert_eq!(error.kind(), ApplicationErrorKind::StateUnavailable);
        node.open_publish_stream_inner(request.clone())
            .expect("closed admission releases ownership without a restart");
        drop(node);

        let mut reopened = selected_node(&root);
        let retry = reopened
            .open_publish_stream_inner(request)
            .expect("closed admission leaves exact durable upload retry-safe");
        assert_eq!(retry.progress.durable_offset, bytes.len() as u64);
        assert!(
            reopened
                .finish_publish_stream_inner(retry.token)
                .expect("reopened pool promotes retained upload")
                .inserted
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 3)]
    async fn stream_pack_promotion_survives_caller_drop_after_scheduling_ack() {
        // Break caught: returning the owned job through the response lets a
        // cancelled finish future drop it after the actor removed the stream.
        let root = TestRoot::new("stream-pack-promotion-caller-drop");
        let bytes = payload(SELECTED_BLOB_CHUNK_SIZE as usize + 37);
        let (mut node, (token, request)) = tokio::task::block_in_place(|| {
            let mut node = selected_node(&root);
            let ready =
                prepare_ready_stream(&mut node, b"blob/stream/pack-promotion-caller-drop", &bytes);
            (node, ready)
        });
        let (started_tx, started_rx) = std::sync::mpsc::sync_channel(1);
        let (finished_tx, finished_rx) = std::sync::mpsc::sync_channel(1);
        let release = Arc::new((std::sync::Mutex::new(false), std::sync::Condvar::new()));
        node.set_stream_pack_promotion_gate_for_test(started_tx, finished_tx, Arc::clone(&release));
        let identity = node.identity();
        let mission_authority = node.mission_authority();
        let admission = Arc::new(AtomicBool::new(true));
        let worker_admission = Arc::clone(&admission);
        let (commands, mut received) = mpsc::channel(4);
        let direct = commands.clone();
        let handle = SelectedBlobHandle::new(commands, admission, identity, mission_authority);
        let worker = tokio::task::spawn_blocking(move || {
            while let Some(command) = received.blocking_recv() {
                let SelectedApplicationCommand::Blob(command) = command else {
                    panic!("caller-drop test received another application class");
                };
                node.execute_live(command, &worker_admission)
                    .expect("execute caller-drop command");
            }
        });

        let completion = schedule_stream_pack_promotion_for_test(&direct, request.clone())
            .await
            .expect("actor schedules promotion before acknowledging");
        let _release_on_failure = ReleasePromotionGate(Arc::clone(&release));
        tokio::task::spawn_blocking(move || started_rx.recv().expect("promotion worker started"))
            .await
            .expect("observe retained promotion job");
        drop(completion);
        assert!(
            matches!(
                handle.open_publish_stream(request.clone()).await,
                Err(error) if error.kind() == ApplicationErrorKind::StateUnavailable
            ),
            "dropping the caller and its session must not release the running writer"
        );
        drop(handle);
        drop(direct);
        let mut worker = worker;
        assert!(
            tokio::time::timeout(std::time::Duration::from_millis(100), &mut worker)
                .await
                .is_err(),
            "actor shutdown joins rather than abandons the accepted promotion job"
        );
        {
            let (released, wake) = &*release;
            *released.lock().expect("promotion worker release lock") = true;
            wake.notify_all();
        }
        tokio::time::timeout(std::time::Duration::from_secs(10), &mut worker)
            .await
            .expect("joined shutdown completes after promotion worker release")
            .expect("join caller-drop application actor");
        tokio::task::spawn_blocking(move || finished_rx.recv().expect("promotion job completed"))
            .await
            .expect("join retained promotion job observation");

        let publication_id = BlobStreamPublicationId::from_bytes(token).expect("publication id");
        let (available, before_retry, replay, after_retry) = tokio::task::block_in_place(|| {
            let mut reopened = selected_node(&root);
            let available = reopened
                .inspect_publication(BlobPublicationInspectionRequest {
                    publication_id,
                    topic: blob_topic(),
                    scope: blob_scope(),
                })
                .expect("cancelled caller still observes terminal publication");
            let before_retry = reopened.capacity_status().expect("capacity after finish");
            let opened = reopened
                .open_publish_stream_inner(request)
                .expect("open exact operation after caller cancellation");
            let replay = reopened
                .finish_publish_stream_inner(opened.token)
                .expect("replay exact operation after caller cancellation");
            let after_retry = reopened.capacity_status().expect("capacity after replay");
            (available, before_retry, replay, after_retry)
        });
        assert_eq!(available.phase, BlobPublicationPhase::Available);
        assert!(!replay.inserted);
        assert_eq!(
            after_retry, before_retry,
            "exact retry does not leak upload authority or capacity"
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 3)]
    async fn stream_pack_promotion_worker_panics_resolve_completions_and_reclaim_both_slots() {
        // Break caught: an unwound promotion worker must not strand its completion or
        // permanently consume one of the two application-owned worker slots.
        let root = TestRoot::new("stream-pack-promotion-worker-panic");
        let bytes = payload(SELECTED_BLOB_CHUNK_SIZE as usize + 41);
        let (mut node, first, second) = tokio::task::block_in_place(|| {
            let mut node = selected_node(&root);
            let first = prepare_ready_stream(
                &mut node,
                b"blob/stream/pack-promotion-worker-panic-first",
                &bytes,
            );
            let second = prepare_ready_stream(
                &mut node,
                b"blob/stream/pack-promotion-worker-panic-second",
                &bytes,
            );
            (node, first, second)
        });
        let (started_tx, _started_rx) = std::sync::mpsc::sync_channel(2);
        let (finished_tx, finished_rx) = std::sync::mpsc::sync_channel(2);
        let release = Arc::new((std::sync::Mutex::new(true), std::sync::Condvar::new()));
        node.set_stream_pack_promotion_gate_for_test(started_tx, finished_tx, release);
        node.panic_stream_pack_promotions_for_test(2);
        let identity = node.identity();
        let mission_authority = node.mission_authority();
        let admission = Arc::new(AtomicBool::new(true));
        let worker_admission = Arc::clone(&admission);
        let (commands, mut received) = mpsc::channel(4);
        let direct = commands.clone();
        let handle = SelectedBlobHandle::new(commands, admission, identity, mission_authority);
        let worker = tokio::task::spawn_blocking(move || {
            while let Some(command) = received.blocking_recv() {
                let SelectedApplicationCommand::Blob(command) = command else {
                    panic!("promotion panic test received another application class");
                };
                node.execute_live(command, &worker_admission)
                    .expect("execute promotion-worker panic command");
            }
        });

        let first_completion = schedule_stream_pack_promotion_for_test(&direct, first.1.clone())
            .await
            .expect("schedule first panicking promotion job");
        let second_completion = schedule_stream_pack_promotion_for_test(&direct, second.1.clone())
            .await
            .expect("schedule second panicking promotion job");
        for completion in [first_completion, second_completion] {
            let error = completion
                .await
                .expect("panicking worker resolves completion sender")
                .expect_err("injected worker panic is reported");
            assert_eq!(error.kind(), ApplicationErrorKind::StateUnavailable);
        }
        tokio::task::spawn_blocking(move || {
            finished_rx.recv().expect("first panic accounted");
            finished_rx.recv().expect("second panic accounted");
        })
        .await
        .expect("join panic accounting observer");

        let retry = handle
            .open_publish_stream(first.1)
            .await
            .expect("panicked promotion job leaves exact upload retry-safe");
        assert!(
            retry
                .finish()
                .await
                .expect("reclaimed pool runs retry")
                .inserted
        );

        drop(handle);
        drop(direct);
        worker.await.expect("join panic application actor");
    }

    #[test]
    fn profile5_receipt_preserves_publication_id_through_completion() {
        let root = TestRoot::new("profile5-publication-identity");
        let bytes = payload(BLOB_STREAM_SEGMENT_BYTES + 17);
        let stream_request = BlobPublishStreamRequest {
            publication: request(b"blob/stream/publication-identity"),
            options: BlobPublishOptions::durable(),
            total_len: bytes.len() as u64,
        };
        let (publication_id, result) = {
            let mut node = selected_node(&root);
            let opened = node
                .open_publish_stream_inner(stream_request.clone())
                .expect("open publication stream");
            let publication_id = BlobStreamPublicationId::from_bytes(opened.token).unwrap();
            let awaiting = node
                .inspect_publication(BlobPublicationInspectionRequest {
                    publication_id,
                    topic: blob_topic(),
                    scope: blob_scope(),
                })
                .expect("inspect awaiting publication");
            assert_eq!(awaiting.phase, BlobPublicationPhase::AwaitingData);
            for (offset, chunk) in bytes.chunks(64 * 1024).enumerate() {
                node.append_publish_stream_inner(
                    opened.token,
                    (offset * 64 * 1024) as u64,
                    Zeroizing::new(chunk.to_vec()),
                )
                .expect("append publication bytes");
            }
            let result = node
                .finish_publish_stream_inner(opened.token)
                .expect("finish publication stream");
            assert_eq!(result.publication_id, Some(publication_id));
            (publication_id, result)
        };
        let mut reopened = selected_node(&root);
        let available = reopened
            .inspect_publication(BlobPublicationInspectionRequest {
                publication_id,
                topic: blob_topic(),
                scope: blob_scope(),
            })
            .expect("inspect restarted publication");
        assert_eq!(available.phase, BlobPublicationPhase::Available);
        assert_eq!(available.blob_id, Some(result.id));
        assert_eq!(available.plaintext_total_bytes, bytes.len() as u64);
        let wire_len = crate::stream_transfer::blob_pack_wire_len(bytes.len() as u64)
            .expect("native pack wire length");
        assert_eq!(available.transfer_total_bytes, wire_len);
        assert_eq!(available.durable_transfer_bytes, wire_len);
    }

    #[test]
    fn publication_inspection_survives_restart_with_monotonic_progress() {
        const CHECKPOINT_SEGMENTS: u64 = 1;
        let root = TestRoot::new("publication-inspection-restart");
        let bytes = payload(2 * BLOB_STREAM_SEGMENT_BYTES);
        let stream_request = BlobPublishStreamRequest {
            publication: request(b"blob/stream/inspection-restart"),
            options: BlobPublishOptions::durable(),
            total_len: bytes.len() as u64,
        };
        let (publication_id, before) = {
            let mut node = selected_node(&root);
            let opened = node
                .open_publish_stream_inner(stream_request.clone())
                .expect("open restart stream");
            node.publish_streams
                .get_mut(&opened.token)
                .expect("open local stream")
                .set_checkpoint_segments_for_test(CHECKPOINT_SEGMENTS);
            node.append_publish_stream_inner(
                opened.token,
                0,
                Zeroizing::new(bytes[..BLOB_STREAM_SEGMENT_BYTES].to_vec()),
            )
            .expect("append first durable segment");
            let publication_id = BlobStreamPublicationId::from_bytes(opened.token).unwrap();
            let status = node
                .inspect_publication(BlobPublicationInspectionRequest {
                    publication_id,
                    topic: blob_topic(),
                    scope: blob_scope(),
                })
                .expect("inspect first durable segment");
            assert_eq!(status.phase, BlobPublicationPhase::Receiving);
            (publication_id, status)
        };
        let mut restarted = selected_node(&root);
        let after = restarted
            .inspect_publication(BlobPublicationInspectionRequest {
                publication_id,
                topic: blob_topic(),
                scope: blob_scope(),
            })
            .expect("inspect after restart");
        assert_eq!(after, before);
        assert!(after.durable_plaintext_bytes > 0);
        assert!(after.durable_transfer_bytes > 0);
    }

    #[test]
    fn blob_capacity_status_handles_zero_and_maximum_counters() {
        let limits = BlobDepotLimits::new(u64::MAX, u64::MAX, u64::MAX).unwrap();
        let empty = map_blob_capacity_status(aster_redb_store::BlobStoreStats::default(), limits)
            .expect("map empty capacity");
        assert_eq!(empty.reserved_bytes, 0);
        assert_eq!(empty.byte_limit, u64::MAX);
        assert!(!empty.bytes_exhausted);
        assert!(!empty.chunks_exhausted);
        assert!(!empty.variants_exhausted);

        let maximum = map_blob_capacity_status(
            aster_redb_store::BlobStoreStats {
                reserved_file_bytes: u64::MAX,
                committed_chunks: u64::MAX,
                variants: u64::MAX,
                pending_sources: u64::MAX,
                network_staging_bytes: u64::MAX,
                ..Default::default()
            },
            limits,
        )
        .expect("map maximum capacity");
        assert!(maximum.bytes_exhausted);
        assert!(maximum.chunks_exhausted);
        assert!(maximum.variants_exhausted);
        assert_eq!(maximum.pending_sources, u64::MAX);
        assert_eq!(maximum.network_staging_bytes, u64::MAX);
    }

    #[test]
    fn selected_blob_publish_stream_restarts_from_store_durable_frontier() {
        let root = TestRoot::new("selected-blob-publish-stream-resume");
        const TEST_CHECKPOINT_SEGMENTS: u64 = 2;
        let checkpoint_bytes = TEST_CHECKPOINT_SEGMENTS as usize * BLOB_STREAM_SEGMENT_BYTES;
        let total_len = checkpoint_bytes + 2 * 64 * 1024;
        let bytes = payload(total_len);
        let stream_request = BlobPublishStreamRequest {
            publication: request(b"blob/stream/resume"),
            options: BlobPublishOptions::durable(),
            total_len: total_len as u64,
        };
        {
            let mut node = selected_node(&root);
            let opened = node
                .open_publish_stream_inner(stream_request.clone())
                .expect("open stream");
            node.publish_streams
                .get_mut(&opened.token)
                .expect("open local stream")
                .set_checkpoint_segments_for_test(TEST_CHECKPOINT_SEGMENTS);
            for (offset, chunk) in bytes[..checkpoint_bytes + 64 * 1024]
                .chunks(64 * 1024)
                .enumerate()
            {
                node.append_publish_stream_inner(
                    opened.token,
                    (offset * 64 * 1024) as u64,
                    Zeroizing::new(chunk.to_vec()),
                )
                .expect("append before disconnect");
            }
        }

        let mut restarted = selected_node(&root);
        let mut changed = bytes.clone();
        changed[17] ^= 0x80;
        let error = restarted
            .publish(
                stream_request.publication.clone(),
                &mut Cursor::new(changed),
            )
            .expect_err("changed one-shot source cannot reuse a durable prefix");
        assert_eq!(error.kind(), ApplicationErrorKind::Conflict);
        assert_eq!(error.operation(), "blob publish");
        assert!(restarted.publish_streams.is_empty());
        assert!(restarted.completed_publish_streams.is_empty());
        let opened = restarted
            .open_publish_stream_inner(stream_request)
            .expect("resume stream");
        assert_eq!(opened.progress.accepted_offset, checkpoint_bytes as u64);
        assert_eq!(opened.progress.durable_offset, checkpoint_bytes as u64);
        restarted
            .append_publish_stream_inner(
                opened.token,
                checkpoint_bytes as u64,
                Zeroizing::new(bytes[checkpoint_bytes..].to_vec()),
            )
            .expect("append resumed suffix");
        let result = restarted
            .finish_publish_stream_inner(opened.token)
            .expect("finish resumed stream");
        assert!(result.inserted);
        assert_eq!(result.total_len, total_len as u64);
    }

    fn persist_completed_unpublished_upload(
        root: &TestRoot,
        stream_request: BlobPublishStreamRequest,
        reuse: bool,
    ) -> ([u8; 32], BlobOperationOwner, u64) {
        let total_len = usize::try_from(stream_request.total_len).unwrap();
        let bytes = payload(total_len);
        let options = stream_request.options;
        let ttl_ms = options.ttl_ms();
        let publication = stream_request.publication;
        let mut node = selected_node(root);
        node.custody_clock = NodeCustodyClock::injected([0xcf; 16], 1_000, 0);
        if reuse {
            let first = node
                .open_publish_stream_inner(BlobPublishStreamRequest {
                    publication: request(b"blob/completed-upload/first"),
                    options,
                    total_len: total_len as u64,
                })
                .unwrap();
            if !bytes.is_empty() {
                node.append_publish_stream_inner(first.token, 0, Zeroizing::new(bytes.clone()))
                    .unwrap();
            }
            node.finish_publish_stream_inner(first.token)
                .expect("publish reusable pack");
        }
        let opened = node
            .open_publish_stream_inner(BlobPublishStreamRequest {
                publication: publication.clone(),
                options,
                total_len: total_len as u64,
            })
            .expect("open pending publication");
        if !bytes.is_empty() {
            node.append_publish_stream_inner(opened.token, 0, Zeroizing::new(bytes.clone()))
                .expect("append pending publication");
        }
        let PreparedBlobPublishFinalization::Pending(job) = node
            .prepare_publish_stream_finalization(opened.token)
            .expect("prepare physical completion")
        else {
            panic!("publication must still be pending");
        };
        // Stop at the real durable boundary between pack completion
        // (including dedup cleanup) and semantic publication.
        let BlobPackPromotionJob {
            mission,
            store,
            reservation,
            checkpoint,
            open,
            writer,
            ..
        } = *job;
        drop((mission, store));
        let writer = writer.expect("new upload writer");
        let counter = open.open().publisher_counter();
        let (plaintext_root, ciphertext_root) = writer.final_roots().unwrap();
        node.custody_clock.set_injected_tick(1_005).unwrap();
        let final_sample = ttl_ms.map(|_| node.custody_clock.sample().unwrap());
        let commitment = BlobStreamFinalCommitment::new(
            &open,
            plaintext_root,
            ciphertext_root,
            writer.next_index(),
            final_sample,
        )
        .unwrap();
        let authenticated = node
            .verifier
            .seal_blob_stream_commitment(&commitment)
            .unwrap();
        let verified = node
            .verifier
            .verify_blob_stream_commitment(&open, &authenticated)
            .unwrap();
        let lineage = node.verifier.blob_stream_lineage(&open).unwrap();
        let completion = writer.finish_profile5(&verified).unwrap();
        let policy = node.current_policy("test completion").unwrap();
        let projected = node
            .store
            .checkpoint_blob_upload(
                &policy,
                &reservation,
                checkpoint,
                completion.checkpoint().clone(),
            )
            .unwrap();
        let completed = node
            .store
            .complete_profile5_upload_pack(
                &policy,
                &reservation,
                projected,
                completion,
                &verified,
                lineage,
            )
            .unwrap();
        assert_eq!(
            completed
                .profile5_completion()
                .unwrap()
                .reuses_existing_pack(),
            reuse
        );
        let owner = reservation.request().owner.clone();
        assert!(
            node.store
                .blob_for_owner_with_policy(&policy, &owner)
                .unwrap()
                .is_none()
        );
        drop(node);
        (opened.token, owner, counter)
    }

    #[test]
    fn completed_upload_resumes_publication_after_restart() {
        for reuse in [true, false] {
            for (total_len, ttl_ms) in [(4096, None), (0, None), (4096, Some(50))] {
                let options = ttl_ms.map_or(BlobPublishOptions::durable(), |ttl| {
                    BlobPublishOptions::finite_ttl_ms(ttl).unwrap()
                });
                let root = TestRoot::new("completed-upload-resume");
                let bytes = payload(total_len);
                let publication = request(b"blob/completed-upload/retry");
                let (token, owner, counter) = persist_completed_unpublished_upload(
                    &root,
                    BlobPublishStreamRequest {
                        publication: publication.clone(),
                        options,
                        total_len: total_len as u64,
                    },
                    reuse,
                );

                let mut restarted = selected_node(&root);
                restarted.custody_clock = NodeCustodyClock::injected([0xcf; 16], 1_020, 0);
                let resumed = restarted
                    .open_publish_stream_inner(BlobPublishStreamRequest {
                        publication: publication.clone(),
                        options,
                        total_len: total_len as u64,
                    })
                    .expect("resume completed upload without reopening its candidate writer");
                assert_eq!(resumed.token, token);
                assert_eq!(resumed.progress.durable_offset, total_len as u64);
                if !bytes.is_empty() {
                    let mut changed = bytes.clone();
                    changed[0] ^= 0x80;
                    let error = restarted
                        .publish_with_options(
                            publication.clone(),
                            options,
                            &mut Cursor::new(changed),
                        )
                        .expect_err(
                            "completed upload still verifies retry content before publishing",
                        );
                    assert_eq!(error.kind(), ApplicationErrorKind::Conflict);
                    let policy = restarted
                        .current_policy("test pending publication")
                        .unwrap();
                    assert!(
                        restarted
                            .store
                            .blob_for_owner_with_policy(&policy, &owner)
                            .unwrap()
                            .is_none()
                    );
                }
                let result = if bytes.is_empty() {
                    restarted.finish_publish_stream_inner(resumed.token)
                } else {
                    restarted.publish_with_options(
                        publication.clone(),
                        options,
                        &mut Cursor::new(bytes.clone()),
                    )
                }
                .expect("retry promotes durable completion");
                assert!(result.inserted);
                let measured = restarted.pack_promotion_pool.last_report_for_test();
                assert_eq!(measured.store_boundary_operations, 7);
                assert_eq!(measured.plaintext_bytes_reprocessed, 0);
                assert_eq!(measured.ciphertext_bytes_rewritten, 0);
                let policy = restarted
                    .current_policy("test resumed publication")
                    .unwrap();
                let stored = restarted
                    .store
                    .blob_for_owner_with_policy(&policy, &owner)
                    .unwrap()
                    .unwrap();
                let (projection, retention) = restarted
                    .completed_projection(&stored, "test resumed publication")
                    .unwrap();
                let verified = restarted
                    .source_route_cache
                    .authenticated_profile5_blob_source(&restarted.verifier, &projection, retention)
                    .unwrap();
                assert_eq!(
                    verified.publication().publication().final_custody(),
                    ttl_ms.map(|_| CustodySample {
                        clock_id: [0xcf; 16],
                        tick_ms: 1_020
                    })
                );
                assert_eq!(result.publication_id.unwrap().as_bytes(), &token);
                assert_eq!(result.publisher_counter, counter);
                assert!(
                    restarted
                        .store
                        .resume_blob_upload(&owner)
                        .unwrap()
                        .is_none()
                );
                let reopened = restarted
                    .open_publish_stream_inner(BlobPublishStreamRequest {
                        publication,
                        options,
                        total_len: total_len as u64,
                    })
                    .unwrap();
                let repeated = restarted
                    .finish_publish_stream_inner(reopened.token)
                    .expect("completed retry remains idempotent");
                assert!(!repeated.inserted);
                assert_eq!(repeated.publication_id, result.publication_id);
                assert_eq!(repeated.acceptance_marker, result.acceptance_marker);
            }
        }
    }

    fn assert_completed_upload_cleanup_before_promotion_is_ordinary(prepare_before_cleanup: bool) {
        // Break caught: a restore-only promotion must not recreate a removed
        // completed upload, nor treat legitimate terminal cleanup as Integrity.
        let root = TestRoot::new("completed-upload-cleanup-before-promotion");
        let stream_request = BlobPublishStreamRequest {
            publication: request(b"blob/completed-upload/expired-retry"),
            options: BlobPublishOptions::finite_ttl_ms(50).unwrap(),
            total_len: 4096,
        };
        let (token, owner, old_counter) =
            persist_completed_unpublished_upload(&root, stream_request.clone(), false);
        let mut restarted = selected_node(&root);
        restarted.custody_clock = NodeCustodyClock::injected([0xcf; 16], 1_020, 0);
        let resumed = restarted.open_publish_stream_inner(stream_request).unwrap();
        assert_eq!(resumed.token, token);
        assert_eq!(resumed.progress.durable_offset, 4096);
        let stream = restarted.publish_streams.get(&token).unwrap();
        assert!(stream.writer.is_none());
        assert!(stream.checkpoint.profile5_completion().is_some());
        let session = Arc::new(BlobPublishStreamSession::new(Arc::clone(
            &restarted.publish_stream_cleanup,
        )));
        restarted
            .live_publish_sessions
            .insert(token, Arc::downgrade(&session));
        let prepared = if prepare_before_cleanup {
            let PreparedBlobPublishFinalization::Pending(job) = restarted
                .prepare_publish_stream_finalization(token)
                .unwrap()
            else {
                panic!("completed upload is still unpublished");
            };
            assert!(job.writer.is_none());
            Some(job)
        } else {
            None
        };
        restarted.custody_clock.set_injected_tick(1_050).unwrap();
        let expired = restarted.custody_clock.sample().unwrap();
        let budget = BlobMaintenanceBudget::new(4096, 1, 32 * 1024 * 1024).unwrap();
        for _ in 0..128 {
            restarted
                .store
                .run_blob_maintenance_turn_with_sample(budget, Some(expired))
                .unwrap();
        }
        assert!(
            restarted
                .store
                .resume_blob_upload(&owner)
                .unwrap()
                .is_none()
        );
        let after_cleanup = restarted.capacity_status().unwrap();
        assert_eq!(after_cleanup.reserved_bytes, 0);
        assert_eq!(after_cleanup.variants, 0);
        let admission = AtomicBool::new(true);
        let completion = if let Some(job) = prepared {
            restarted.pack_promotion_pool.try_submit(*job).unwrap()
        } else {
            let (response, received) = oneshot::channel();
            restarted
                .execute_live(
                    SelectedBlobCommand::FinishPublishStream {
                        token,
                        session,
                        response,
                    },
                    &admission,
                )
                .unwrap();
            let BlobPublishFinalization::Scheduled(completion) =
                received.blocking_recv().unwrap().unwrap()
            else {
                panic!("held resumed stream schedules its finalization");
            };
            completion
        };
        let error = completion.blocking_recv().unwrap().unwrap_err();
        assert_eq!(
            error.kind(),
            ApplicationErrorKind::PolicyUnsettled,
            "missing prior reservation must be an ordinary restore failure"
        );
        assert!(
            restarted
                .store
                .resume_blob_upload(&owner)
                .unwrap()
                .is_none()
        );
        let policy = restarted
            .current_policy("test expired publication")
            .unwrap();
        assert!(
            restarted
                .store
                .blob_for_owner_with_policy(&policy, &owner)
                .unwrap()
                .is_none()
        );
        let (response, received) = oneshot::channel();
        restarted
            .execute_live(SelectedBlobCommand::CapacityStatus { response }, &admission)
            .unwrap();
        assert_eq!(received.blocking_recv().unwrap().unwrap(), after_cleanup);
        assert!(admission.load(Ordering::Acquire));
        let unrelated = restarted
            .publish(
                request(b"blob/completed-upload/after-cleanup"),
                &mut Cursor::new(payload(1)),
            )
            .unwrap();
        // Diagnostic only: counter gaps are allowed, so do not impose a
        // contiguous-allocation contract when checking rollback of this failure.
        println!(
            "prepared={prepare_before_cleanup}, retired counter={old_counter}, next publication counter={}",
            unrelated.publisher_counter
        );
        restarted.join_live_promotions().unwrap();
    }

    #[test]
    fn completed_upload_cleanup_before_prepared_promotion_is_ordinary() {
        assert_completed_upload_cleanup_before_promotion_is_ordinary(true);
    }

    #[test]
    fn completed_upload_cleanup_before_live_finish_is_ordinary() {
        assert_completed_upload_cleanup_before_promotion_is_ordinary(false);
    }

    #[test]
    fn one_shot_reader_failure_releases_runtime_and_retains_retry() {
        struct FailingSource(Cursor<Vec<u8>>);
        impl Read for FailingSource {
            fn read(&mut self, _: &mut [u8]) -> std::io::Result<usize> {
                Err(std::io::Error::other("injected source read failure"))
            }
        }
        impl Seek for FailingSource {
            fn seek(&mut self, position: SeekFrom) -> std::io::Result<u64> {
                self.0.seek(position)
            }
        }
        let root = TestRoot::new("one-shot-reader-failure");
        let mut node = selected_node(&root);
        let bytes = vec![7; 1024];
        for index in 0..3 {
            let request = request(format!("blob/reader-failure/{index}").as_bytes());
            let owner = BlobOperationOwner::new(
                node.identity(),
                BlobOperationKey::new(request.operation_key.clone()).unwrap(),
            );
            let error = node
                .publish(
                    request.clone(),
                    &mut FailingSource(Cursor::new(bytes.clone())),
                )
                .expect_err("source error is returned");
            assert_eq!(error.kind(), ApplicationErrorKind::StateUnavailable);
            assert!(
                node.publish_streams.is_empty(),
                "failed one-shot upload retained runtime workers"
            );
            assert!(node.completed_publish_streams.is_empty());
            let (reservation, checkpoint) = node
                .store
                .resume_blob_upload(&owner)
                .unwrap()
                .expect("durable retry state");
            assert_eq!(checkpoint.durable_plaintext_offset(), 0);
            let publication = node
                .publish(request, &mut Cursor::new(bytes.clone()))
                .expect("exact retry succeeds");
            assert!(publication.inserted);
            assert_eq!(
                publication
                    .publication_id
                    .expect("native publication")
                    .as_bytes(),
                reservation.pack_identity().upload_id().as_bytes()
            );
            assert!(node.publish_streams.is_empty());
            assert!(node.completed_publish_streams.is_empty());
        }
    }

    struct CountingCursor {
        inner: Cursor<Vec<u8>>,
        bytes_read: u64,
    }

    impl CountingCursor {
        fn new(bytes: Vec<u8>) -> Self {
            Self {
                inner: Cursor::new(bytes),
                bytes_read: 0,
            }
        }
    }

    impl Read for CountingCursor {
        fn read(&mut self, output: &mut [u8]) -> std::io::Result<usize> {
            let read = self.inner.read(output)?;
            self.bytes_read = self
                .bytes_read
                .checked_add(u64::try_from(read).map_err(std::io::Error::other)?)
                .ok_or_else(|| std::io::Error::other("test source byte count overflowed"))?;
            Ok(read)
        }
    }

    impl Seek for CountingCursor {
        fn seek(&mut self, position: SeekFrom) -> std::io::Result<u64> {
            self.inner.seek(position)
        }
    }

    struct GrowingReadCursor {
        inner: Cursor<Vec<u8>>,
        grew: bool,
    }

    impl GrowingReadCursor {
        fn new(bytes: Vec<u8>) -> Self {
            Self {
                inner: Cursor::new(bytes),
                grew: false,
            }
        }
    }

    impl Read for GrowingReadCursor {
        fn read(&mut self, output: &mut [u8]) -> std::io::Result<usize> {
            let read = self.inner.read(output)?;
            if read != 0 && !self.grew {
                self.inner.get_mut().push(0xff);
                self.grew = true;
            }
            Ok(read)
        }
    }

    impl Seek for GrowingReadCursor {
        fn seek(&mut self, position: SeekFrom) -> std::io::Result<u64> {
            self.inner.seek(position)
        }
    }

    fn install_unreferenced_completed_variant(node: &SelectedBlobNode, plaintext: &[u8]) {
        let metadata = CoreBlobMetadata::new(
            Some("application/x-aster-test".into()),
            b"schema/blob-v1".to_vec(),
        )
        .expect("unreferenced fixture metadata");
        let mut first_pass = Cursor::new(plaintext);
        let prepared = prepare_blob(&mut first_pass, SELECTED_BLOB_CHUNK_SIZE, metadata)
            .expect("prepare unreferenced fixture");
        let depot = node.store.blob_depot().expect("unreferenced fixture depot");
        let mut service = node
            .verifier
            .blob_service_with_store(&blob_scope(), &blob_topic(), 1, depot)
            .expect("unreferenced fixture service");
        let manifest = service
            .install_prepared(&prepared)
            .expect("install unreferenced fixture");
        let mut second_pass = Cursor::new(plaintext);
        let progress = service
            .encrypt_some(&mut second_pass, &manifest, prepared.chunk_count())
            .expect("encrypt unreferenced fixture");
        assert!(progress.complete);
        service
            .finish_manifest(&manifest)
            .expect("finish unreferenced fixture");
    }

    #[test]
    fn transfer_status_separates_retained_publications_from_pending_network_work() {
        // Break caught: treating accepted local publications as pending network
        // transfers gives operators a permanently nonzero transfer backlog.
        let root = TestRoot::new("transfer-status-local");
        let mut node = selected_node(&root);
        let limits = node.store.blob_lifecycle_limits();
        assert_eq!(
            node.transfer_status().expect("empty Blob transfer status"),
            BlobTransferStatus {
                retained_publications: 0,
                retained_pending_transfers: 0,
                network_staging_bytes: 0,
                reserved_file_bytes: 0,
                gc: BlobGcStatus {
                    lineage_fence_row_cap: limits.max_lineage_rows(),
                    lineage_fence_byte_cap: limits.max_lineage_bytes(),
                    replay_fence_row_cap: limits.max_replay_rows(),
                    replay_fence_byte_cap: limits.max_replay_bytes(),
                    publication_lifecycle_row_cap: limits.max_publication_rows(),
                    ..BlobGcStatus::default()
                },
                pending: Vec::new(),
            }
        );

        node.publish(
            request(b"blob/transfer-status/local"),
            &mut Cursor::new(payload(73)),
        )
        .expect("publish transfer-status fixture");
        let status = node
            .transfer_status()
            .expect("published Blob transfer status");
        assert_eq!(status.retained_publications, 1);
        assert_eq!(status.retained_pending_transfers, 0);
        assert_eq!(status.network_staging_bytes, 0);
        assert!(status.reserved_file_bytes > 0);
        assert!(status.pending.is_empty());
    }

    #[test]
    fn blob_gc_status_reports_security_fence_and_publication_lifecycle_usage_and_caps() {
        // Break caught: the application status projection must retain the
        // store's security-authority usage and configured caps verbatim.
        let root = TestRoot::new("application-gc-status-security-capacity");
        let mut node = selected_node(&root);
        let status = node.transfer_status().expect("Blob GC transfer status");
        let limits = node.store.blob_lifecycle_limits();
        assert_eq!(status.gc.lineage_fence_row_cap, limits.max_lineage_rows());
        assert_eq!(status.gc.replay_fence_row_cap, limits.max_replay_rows());
        assert_eq!(
            status.gc.publication_lifecycle_row_cap,
            limits.max_publication_rows()
        );
        assert_eq!(status.gc.last_failure, None);
    }

    #[test]
    fn transfer_phase_rejects_impossible_progress_and_classifies_durable_work() {
        assert_eq!(
            blob_transfer_phase(2, 0, 100, 0).expect("waiting transfer"),
            BlobTransferPhase::AwaitingCarrier
        );
        assert_eq!(
            blob_transfer_phase(2, 0, 100, 17).expect("partially received transfer"),
            BlobTransferPhase::Receiving
        );
        assert_eq!(
            blob_transfer_phase(2, 2, 100, 100).expect("ready transfer"),
            BlobTransferPhase::ReadyToFinalize
        );
        for invalid in [
            blob_transfer_phase(0, 0, 0, 0),
            blob_transfer_phase(2, 3, 100, 100),
            blob_transfer_phase(2, 1, 100, 0),
            blob_transfer_phase(2, 2, 100, 99),
            blob_transfer_phase(2, 0, 100, 101),
        ] {
            let error = invalid.expect_err("impossible durable progress must fail closed");
            assert_eq!(error.kind(), ApplicationErrorKind::Integrity);
            assert_eq!(error.operation(), "blob transfer status");
        }
    }

    #[test]
    fn blob_subscription_delivers_exact_publications_with_durable_token_bound_retries() {
        let root = TestRoot::new("subscription-lifecycle");
        let bytes = payload(SELECTED_BLOB_CHUNK_SIZE as usize + 19);
        let operation = b"blob/subscriptions/exact";
        let (subscription, second_publication, acknowledged_token) = {
            let mut node = selected_node(&root);
            let subscription = node
                .subscribe(subscription_request(operation))
                .expect("create Blob subscription");
            assert!(subscription.inserted);
            assert_eq!(
                node.subscribe(subscription_request(operation))
                    .expect("replay Blob subscription"),
                BlobSubscription {
                    inserted: false,
                    ..subscription
                }
            );

            let mut conflicting = subscription_request(operation);
            conflicting.include_descendant_scopes = true;
            let conflict = node
                .subscribe(conflicting)
                .expect_err("changed selector under one operation key");
            assert_eq!(conflict.kind(), ApplicationErrorKind::Conflict);
            assert_eq!(conflict.operation(), "blob subscribe");

            for invalid in [
                BlobPollRequest {
                    subscription: subscription.id,
                    delivery_limit: 0,
                    scan_limit: 1,
                },
                BlobPollRequest {
                    subscription: subscription.id,
                    delivery_limit: 1,
                    scan_limit: 0,
                },
                BlobPollRequest {
                    subscription: subscription.id,
                    delivery_limit: MAX_SELECTED_BLOB_DELIVERIES + 1,
                    scan_limit: 1,
                },
                BlobPollRequest {
                    subscription: subscription.id,
                    delivery_limit: 1,
                    scan_limit: MAX_SELECTED_BLOB_SUBSCRIPTION_SCAN + 1,
                },
            ] {
                let error = node.poll(invalid).expect_err("invalid Blob poll bounds");
                assert_eq!(error.kind(), ApplicationErrorKind::InvalidRequest);
                assert_eq!(error.operation(), "blob poll");
            }

            let first = node
                .publish(
                    request(b"blob/subscriptions/publication-one"),
                    &mut Cursor::new(bytes.clone()),
                )
                .expect("publish first source publication");
            let mut second_request = request(b"blob/subscriptions/publication-two");
            second_request.priority = Priority::Flash;
            let second = node
                .publish(second_request, &mut Cursor::new(bytes.clone()))
                .expect("publish second source publication");
            assert_eq!(first.id, second.id, "content identity is shared");
            assert_ne!(first.publisher_counter, second.publisher_counter);
            assert_ne!(first.priority, second.priority);

            let first_page = node
                .poll(BlobPollRequest {
                    subscription: subscription.id,
                    delivery_limit: 1,
                    scan_limit: 8,
                })
                .expect("poll first Blob publication");
            assert_eq!(first_page.deliveries.len(), 1);
            assert!(first_page.has_more);
            let first_delivery = content_delivery(&first_page.deliveries[0]);
            assert_eq!(first_delivery.id, first.id);
            assert_eq!(first_delivery.acceptance_marker, first.acceptance_marker);
            assert_eq!(first_delivery.publisher, first.publisher);
            assert_eq!(first_delivery.publisher_counter, first.publisher_counter);
            assert_eq!(first_delivery.topic, blob_topic());
            assert_eq!(first_delivery.scope, blob_scope());
            assert_eq!(first_delivery.priority, first.priority);
            assert_eq!(first_delivery.total_len, bytes.len() as u64);
            assert_eq!(first_delivery.media_type, first.media_type);
            assert_eq!(first_delivery.schema_id, first.schema_id);
            assert_eq!(first_delivery.attempt, 1);
            let first_publication = first_delivery.publication;
            let prior_attempt = first_delivery.token;

            let retried = node
                .poll(BlobPollRequest {
                    subscription: subscription.id,
                    delivery_limit: 1,
                    scan_limit: 8,
                })
                .expect("retry unacknowledged Blob publication");
            assert_eq!(retried.deliveries.len(), 1);
            assert!(retried.has_more);
            let retried_delivery = content_delivery(&retried.deliveries[0]);
            assert_eq!(retried_delivery.publication, first_publication);
            assert_eq!(retried_delivery.attempt, 2);
            assert_ne!(retried_delivery.token, prior_attempt);
            assert_eq!(
                node.acknowledge(subscription.id, first_publication, prior_attempt)
                    .expect("an earlier same-tenure token remains crash-safe"),
                BlobAcknowledgement::Acknowledged
            );
            assert_eq!(
                node.acknowledge(subscription.id, first_publication, retried_delivery.token,)
                    .expect("the latest same-tenure token is idempotent"),
                BlobAcknowledgement::AlreadyAcknowledged
            );

            let second_page = node
                .poll(BlobPollRequest {
                    subscription: subscription.id,
                    delivery_limit: 1,
                    scan_limit: 8,
                })
                .expect("poll second Blob publication");
            assert_eq!(second_page.deliveries.len(), 1);
            assert!(!second_page.has_more);
            let second_delivery = content_delivery(&second_page.deliveries[0]);
            assert_eq!(second_delivery.id, second.id);
            assert_eq!(second_delivery.acceptance_marker, second.acceptance_marker);
            assert_eq!(second_delivery.publisher_counter, second.publisher_counter);
            assert_eq!(second_delivery.priority, second.priority);
            assert_ne!(second_delivery.publication, first_publication);
            assert_eq!(second_delivery.attempt, 1);
            let second_publication = second_delivery.publication;
            let acknowledged_token = second_delivery.token;
            assert_eq!(
                node.acknowledge(subscription.id, second_publication, acknowledged_token,)
                    .expect("acknowledge second publication"),
                BlobAcknowledgement::Acknowledged
            );
            assert_eq!(
                node.acknowledge(subscription.id, second_publication, acknowledged_token,)
                    .expect("idempotent second acknowledgement"),
                BlobAcknowledgement::AlreadyAcknowledged
            );
            assert!(
                node.poll(BlobPollRequest {
                    subscription: subscription.id,
                    delivery_limit: 8,
                    scan_limit: 8,
                })
                .expect("poll after acknowledgements")
                .deliveries
                .is_empty()
            );
            assert_eq!(
                node.delivery_status().expect("Blob delivery status"),
                BlobDeliveryStatus {
                    subscriptions: 1,
                    pending_deliveries: 0,
                    acknowledged_deliveries: 2,
                    delivery_cursors: 2,
                    selector_generation: 1,
                }
            );
            (subscription, second_publication, acknowledged_token)
        };

        let mut reopened = selected_node(&root);
        assert!(
            reopened
                .poll(BlobPollRequest {
                    subscription: subscription.id,
                    delivery_limit: 8,
                    scan_limit: 8,
                })
                .expect("restart preserves acknowledgements")
                .deliveries
                .is_empty()
        );
        assert_eq!(
            reopened
                .unsubscribe(subscription.id)
                .expect("remove Blob subscription"),
            BlobUnsubscribe::Removed
        );
        assert_eq!(
            reopened
                .unsubscribe(subscription.id)
                .expect("repeat Blob subscription removal"),
            BlobUnsubscribe::AlreadyAbsent
        );
        let recreated = reopened
            .subscribe(subscription_request(operation))
            .expect("recreate stable Blob subscription identity");
        assert_eq!(recreated.id, subscription.id);
        assert!(recreated.inserted);
        let stale = reopened
            .acknowledge(recreated.id, second_publication, acknowledged_token)
            .expect_err("removed-incarnation token cannot cross recreation");
        assert_eq!(stale.kind(), ApplicationErrorKind::InvalidRequest);
        assert_eq!(stale.operation(), "blob acknowledge");
        assert_eq!(
            reopened
                .delivery_status()
                .expect("recreated Blob delivery status"),
            BlobDeliveryStatus {
                subscriptions: 1,
                pending_deliveries: 0,
                acknowledged_deliveries: 0,
                delivery_cursors: 0,
                selector_generation: 3,
            }
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn live_blob_handle_routes_subscription_lifecycle_through_joined_worker() {
        let root = TestRoot::new("live-subscription-lifecycle");
        let mut node = selected_node(&root);
        let published = node
            .publish(
                request(b"blob/live-subscriptions/publication"),
                &mut Cursor::new(payload(73)),
            )
            .expect("publish live subscription fixture");
        let identity = node.identity();
        let mission_authority = node.mission_authority();
        let admission = Arc::new(AtomicBool::new(true));
        let worker_admission = Arc::clone(&admission);
        let (commands, mut received) = mpsc::channel(2);
        let handle = SelectedBlobHandle::new(commands, admission, identity, mission_authority);
        let worker = tokio::task::spawn_blocking(move || {
            while let Some(command) = received.blocking_recv() {
                let SelectedApplicationCommand::Blob(command) = command else {
                    panic!("live Blob test received another application class");
                };
                node.execute_live(command, &worker_admission)
                    .expect("execute live Blob subscription command");
            }
        });

        let subscription = handle
            .subscribe(subscription_request(b"blob/live-subscriptions/selector"))
            .await
            .expect("live Blob subscribe");
        assert!(subscription.inserted);
        let page = handle
            .poll(BlobPollRequest {
                subscription: subscription.id,
                delivery_limit: 1,
                scan_limit: 4,
            })
            .await
            .expect("live Blob poll");
        assert_eq!(page.deliveries.len(), 1);
        let delivery = content_delivery(&page.deliveries[0]);
        assert_eq!(delivery.id, published.id);
        assert_eq!(
            handle
                .acknowledge(subscription.id, delivery.publication, delivery.token,)
                .await
                .expect("live Blob acknowledgement"),
            BlobAcknowledgement::Acknowledged
        );
        assert_eq!(
            handle
                .delivery_status()
                .await
                .expect("live Blob delivery status"),
            BlobDeliveryStatus {
                subscriptions: 1,
                pending_deliveries: 0,
                acknowledged_deliveries: 1,
                delivery_cursors: 1,
                selector_generation: 1,
            }
        );
        let transfer_status = handle
            .transfer_status()
            .await
            .expect("live Blob transfer status");
        assert_eq!(transfer_status.retained_publications, 1);
        assert_eq!(transfer_status.retained_pending_transfers, 0);
        assert_eq!(transfer_status.network_staging_bytes, 0);
        assert!(transfer_status.reserved_file_bytes > 0);
        assert!(transfer_status.pending.is_empty());
        assert_eq!(
            handle
                .unsubscribe(subscription.id)
                .await
                .expect("live Blob unsubscribe"),
            BlobUnsubscribe::Removed
        );
        drop(handle);
        worker.await.expect("join live Blob subscription worker");
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn live_blob_handle_publishes_and_reads_exact_finite_ttl() {
        let root = TestRoot::new("live-finite-publish");
        let source_path = root.path().join("finite-source.bin");
        let bytes = payload(SELECTED_BLOB_CHUNK_SIZE as usize + 9);
        fs::write(&source_path, &bytes).expect("write finite live source");
        let mut node = selected_node(&root);
        node.custody_clock = NodeCustodyClock::injected([0xd4; 16], 1_000, 1);
        let identity = node.identity();
        let mission_authority = node.mission_authority();
        let admission = Arc::new(AtomicBool::new(true));
        let worker_admission = Arc::clone(&admission);
        let (commands, mut received) = mpsc::channel(2);
        let handle = SelectedBlobHandle::new(commands, admission, identity, mission_authority);
        let worker = tokio::task::spawn_blocking(move || {
            while let Some(command) = received.blocking_recv() {
                let SelectedApplicationCommand::Blob(command) = command else {
                    panic!("live finite test received another application class");
                };
                node.execute_live(command, &worker_admission)
                    .expect("execute live finite command");
            }
        });

        let published = handle
            .publish_with_options(
                request(b"blob/live-finite-publish"),
                BlobPublishOptions::finite_ttl_ms(60_000).expect("positive TTL"),
                fs::File::open(&source_path).expect("open finite live source"),
            )
            .await
            .expect("publish finite live Blob");
        assert_eq!(published.ttl_ms, Some(60_000));
        let page = handle
            .read_page(BlobReadPageRequest {
                blob: BlobReadRequest {
                    id: published.id,
                    topic: blob_topic(),
                    scope: blob_scope(),
                },
                offset: 0,
                max_bytes: MAX_SELECTED_BLOB_PAGE_BYTES,
            })
            .await
            .expect("read finite live page");
        assert_eq!(page.ttl_ms, Some(60_000));
        assert_eq!(page.as_bytes(), bytes.as_slice());
        drop(handle);
        worker.await.expect("join finite live worker");
    }

    #[test]
    fn blob_subscription_withholds_stale_epoch_and_delivers_only_current_publication() {
        let root = TestRoot::new("subscription-policy-withholding");
        let mut services = persist_rekey_mission(&root);
        let bytes = payload(91);
        let (subscription, old_publication) = {
            let mut node = selected_node(&root);
            let old = node
                .publish(
                    request(b"blob/subscriptions/pre-rekey"),
                    &mut Cursor::new(bytes.clone()),
                )
                .expect("publish pre-rekey Blob");
            let subscription = node
                .subscribe(subscription_request(
                    b"blob/subscriptions/policy-withholding",
                ))
                .expect("subscribe before Blob rekey");
            (subscription, old)
        };

        apply_epoch_two_rekey(&root, &mut services);
        let mut reopened = selected_node(&root);
        let withheld = reopened
            .poll(BlobPollRequest {
                subscription: subscription.id,
                delivery_limit: 4,
                scan_limit: 8,
            })
            .expect("poll stale-epoch Blob publication");
        assert!(withheld.deliveries.is_empty());
        assert!(!withheld.has_more);
        assert_eq!(
            reopened
                .delivery_status()
                .expect("withheld Blob ledger status")
                .pending_deliveries,
            0
        );

        let current = reopened
            .publish(
                request(b"blob/subscriptions/post-rekey"),
                &mut Cursor::new(bytes),
            )
            .expect("publish post-rekey Blob");
        assert_eq!(current.id, old_publication.id);
        let delivered = reopened
            .poll(BlobPollRequest {
                subscription: subscription.id,
                delivery_limit: 4,
                scan_limit: 8,
            })
            .expect("poll current-epoch Blob publication");
        assert_eq!(delivered.deliveries.len(), 1);
        let delivery = content_delivery(&delivered.deliveries[0]);
        assert_eq!(delivery.id, current.id);
        assert_eq!(delivery.publisher_counter, current.publisher_counter);
        assert_eq!(delivery.acceptance_marker, current.acceptance_marker);
        assert_ne!(
            delivery.acceptance_marker,
            old_publication.acceptance_marker
        );
    }

    #[test]
    fn live_blob_page_is_bounded_exact_and_rejects_invalid_ranges() {
        let root = TestRoot::new("live-page");
        let bytes = payload(MAX_SELECTED_BLOB_PAGE_BYTES + 73);
        let mut node = selected_node(&root);
        let published = node
            .publish(request(b"blob/live-page"), &mut Cursor::new(bytes.clone()))
            .expect("publish live page fixture");
        let blob = BlobReadRequest {
            id: published.id,
            topic: blob_topic(),
            scope: blob_scope(),
        };

        let offset = 31u64;
        let page = node
            .read_page(BlobReadPageRequest {
                blob: blob.clone(),
                offset,
                max_bytes: MAX_SELECTED_BLOB_PAGE_BYTES,
            })
            .expect("read cross-chunk live page");
        assert_eq!(page.len(), MAX_SELECTED_BLOB_PAGE_BYTES);
        assert_eq!(
            page.as_bytes(),
            &bytes[offset as usize..page.next_offset() as usize]
        );
        assert_eq!(
            page.next_offset(),
            offset + MAX_SELECTED_BLOB_PAGE_BYTES as u64
        );
        assert!(!page.complete);

        let final_offset = bytes.len() as u64 - 17;
        let final_page = node
            .read_page(BlobReadPageRequest {
                blob: blob.clone(),
                offset: final_offset,
                max_bytes: MAX_SELECTED_BLOB_PAGE_BYTES,
            })
            .expect("read final live page");
        assert_eq!(final_page.as_bytes(), &bytes[bytes.len() - 17..]);
        assert_eq!(final_page.next_offset(), bytes.len() as u64);
        assert!(final_page.complete);

        for (request, label) in [
            (
                BlobReadPageRequest {
                    blob: blob.clone(),
                    offset: 0,
                    max_bytes: 0,
                },
                "empty page",
            ),
            (
                BlobReadPageRequest {
                    blob: blob.clone(),
                    offset: 0,
                    max_bytes: MAX_SELECTED_BLOB_PAGE_BYTES + 1,
                },
                "oversized page",
            ),
            (
                BlobReadPageRequest {
                    blob: blob.clone(),
                    offset: u64::MAX,
                    max_bytes: 1,
                },
                "overflowing page",
            ),
            (
                BlobReadPageRequest {
                    blob: blob.clone(),
                    offset: bytes.len() as u64,
                    max_bytes: 1,
                },
                "past-end page",
            ),
        ] {
            let error = node.read_page(request).expect_err(label);
            assert_eq!(
                error.kind(),
                ApplicationErrorKind::InvalidRequest,
                "{label}"
            );
            assert_eq!(error.operation(), "blob read page", "{label}");
        }
    }

    #[test]
    fn sequential_live_blob_pages_open_each_profile5_segment_once() {
        let root = TestRoot::new("live-page-pipeline-reuse");
        let bytes = payload(BLOB_STREAM_SEGMENT_BYTES * 8 + 19);
        let mut node = selected_node(&root);
        let published = node
            .publish(
                request(b"blob/live-page-pipeline-reuse"),
                &mut Cursor::new(bytes.clone()),
            )
            .expect("publish sequential read fixture");

        let mut restored = Vec::new();
        let result = node
            .read_into(
                BlobReadRequest {
                    id: published.id,
                    topic: blob_topic(),
                    scope: blob_scope(),
                },
                &mut restored,
            )
            .expect("read sequential pages through one pipeline");

        assert_eq!(restored, bytes);
        assert_eq!(result.total_len, bytes.len() as u64);
        assert_eq!(result.verified_chunks, 17);
        assert_eq!(node.last_read_cache_opened_segments, 9);
        assert!(node.read_cache.is_none());
    }

    #[test]
    fn live_blob_commands_reject_exactly_when_closed_or_saturated() {
        let request = BlobReadPageRequest {
            blob: BlobReadRequest {
                id: BlobId::from_bytes([7; 32]),
                topic: blob_topic(),
                scope: blob_scope(),
            },
            offset: 0,
            max_bytes: 1,
        };
        let (response, received) = oneshot::channel();
        SelectedBlobCommand::ReadPage {
            request: request.clone(),
            response,
        }
        .reject();
        let error = received
            .blocking_recv()
            .expect("closed command response")
            .expect_err("closed worker rejects");
        assert_eq!(error.kind(), ApplicationErrorKind::StateUnavailable);
        assert_eq!(error.operation(), "blob read page");

        let (response, received) = oneshot::channel();
        SelectedBlobCommand::ReadPage { request, response }.reject_resource_limit();
        let error = received
            .blocking_recv()
            .expect("saturated command response")
            .expect_err("saturated worker rejects");
        assert_eq!(error.kind(), ApplicationErrorKind::ResourceLimit);
        assert_eq!(error.operation(), "blob read page");

        let subscription = BlobSubscriptionId::from_bytes([8; 32]);
        let publication = BlobPublicationId::from_bytes([9; 32]);
        let token = BlobDeliveryToken::inert_for_command_rejection();

        let (response, received) = oneshot::channel();
        SelectedBlobCommand::Subscribe {
            request: subscription_request(b"blob/command-rejection"),
            response,
        }
        .reject();
        let error = received
            .blocking_recv()
            .expect("closed subscribe response")
            .expect_err("closed subscribe rejects");
        assert_eq!(error.kind(), ApplicationErrorKind::StateUnavailable);
        assert_eq!(error.operation(), "blob subscribe");

        let (response, received) = oneshot::channel();
        SelectedBlobCommand::Poll {
            request: BlobPollRequest {
                subscription,
                delivery_limit: 1,
                scan_limit: 1,
            },
            response,
        }
        .reject_resource_limit();
        let error = received
            .blocking_recv()
            .expect("saturated poll response")
            .expect_err("saturated poll rejects");
        assert_eq!(error.kind(), ApplicationErrorKind::ResourceLimit);
        assert_eq!(error.operation(), "blob poll");

        let (response, received) = oneshot::channel();
        SelectedBlobCommand::Acknowledge {
            subscription,
            publication,
            token,
            response,
        }
        .reject();
        let error = received
            .blocking_recv()
            .expect("closed acknowledgement response")
            .expect_err("closed acknowledgement rejects");
        assert_eq!(error.kind(), ApplicationErrorKind::StateUnavailable);
        assert_eq!(error.operation(), "blob acknowledge");

        let (response, received) = oneshot::channel();
        SelectedBlobCommand::Unsubscribe {
            subscription,
            response,
        }
        .reject_resource_limit();
        let error = received
            .blocking_recv()
            .expect("saturated unsubscribe response")
            .expect_err("saturated unsubscribe rejects");
        assert_eq!(error.kind(), ApplicationErrorKind::ResourceLimit);
        assert_eq!(error.operation(), "blob unsubscribe");

        let (response, received) = oneshot::channel();
        SelectedBlobCommand::DeliveryStatus { response }.reject();
        let error = received
            .blocking_recv()
            .expect("closed delivery-status response")
            .expect_err("closed delivery-status rejects");
        assert_eq!(error.kind(), ApplicationErrorKind::StateUnavailable);
        assert_eq!(error.operation(), "blob delivery status");

        let (response, received) = oneshot::channel();
        SelectedBlobCommand::TransferStatus { response }.reject_resource_limit();
        let error = received
            .blocking_recv()
            .expect("saturated transfer-status response")
            .expect_err("saturated transfer-status rejects");
        assert_eq!(error.kind(), ApplicationErrorKind::ResourceLimit);
        assert_eq!(error.operation(), "blob transfer status");
    }

    #[tokio::test]
    async fn live_blob_handle_rejects_oversized_request_before_enqueuing_file() {
        let root = TestRoot::new("live-handle-preflight");
        let source_path = root.path().join("source.bin");
        fs::write(&source_path, [1u8]).expect("write live handle source");
        let node = selected_node(&root);
        let identity = node.identity();
        let mission_authority = node.mission_authority();
        drop(node);
        let (commands, mut received) = mpsc::channel(1);
        let handle = SelectedBlobHandle::new(
            commands,
            Arc::new(AtomicBool::new(true)),
            identity,
            mission_authority,
        );

        let mut oversized_operation = request(b"blob/handle-operation");
        oversized_operation.operation_key = vec![1; MAX_BLOB_OPERATION_KEY_BYTES + 1];
        let mut oversized_media_type = request(b"blob/handle-media");
        oversized_media_type.media_type = Some("a".repeat(MAX_BLOB_MEDIA_TYPE_BYTES + 1));
        let mut oversized_schema = request(b"blob/handle-schema");
        oversized_schema.schema_id = vec![2; MAX_BLOB_SCHEMA_ID_BYTES + 1];

        for invalid in [oversized_operation, oversized_media_type, oversized_schema] {
            let source = fs::File::open(&source_path).expect("open live handle source");
            let error = handle
                .publish(invalid, source)
                .await
                .expect_err("oversized request must fail in handle preflight");
            assert_eq!(error.kind(), ApplicationErrorKind::InvalidRequest);
            assert_eq!(error.operation(), "blob publish");
            assert!(matches!(
                received.try_recv(),
                Err(mpsc::error::TryRecvError::Empty)
            ));
        }
    }

    #[test]
    fn live_blob_precommit_cache_poison_is_actor_fatal_and_drops_response() {
        let root = TestRoot::new("live-precommit-cache-poison");
        let source_path = root.path().join("source.bin");
        fs::write(&source_path, [1u8, 2, 3]).expect("write live poison source");
        let mut node = selected_node(&root);
        let cache = Arc::clone(&node.source_route_cache);
        let poison = std::thread::spawn(move || {
            let _lifecycle = cache
                .lock_blob_lifecycle()
                .expect("lock lifecycle before poisoning");
            panic!("deliberately poison live Blob lifecycle lock");
        });
        assert!(poison.join().is_err());

        let (response, received) = oneshot::channel();
        let command = SelectedBlobCommand::Publish {
            request: request(b"blob/live-precommit-cache-poison"),
            options: BlobPublishOptions::durable(),
            source: fs::File::open(&source_path).expect("open live poison source"),
            response,
        };
        let admission = AtomicBool::new(true);
        let error = node
            .execute_live(command, &admission)
            .expect_err("cache poison must escape the worker as actor-fatal");
        assert!(matches!(&error, NodeError::FatalBlobCoherence(_)));
        assert!(
            error
                .to_string()
                .contains("live native Blob publication failed a durable invariant")
        );
        assert!(received.blocking_recv().is_err());
        assert_eq!(
            node.store
                .blob_stats()
                .expect("post-poison Blob stats")
                .publications,
            0
        );
    }

    #[test]
    fn live_blob_poll_coherence_failure_is_actor_fatal_and_does_not_advance_attempt() {
        let root = TestRoot::new("live-poll-coherence-fatal");
        let mut node = selected_node(&root);
        node.publish(
            request(b"blob/live-poll-coherence/publication"),
            &mut Cursor::new(vec![1, 2, 3]),
        )
        .expect("publish live poll coherence fixture");
        let subscription = node
            .subscribe(subscription_request(
                b"blob/live-poll-coherence/subscription",
            ))
            .expect("subscribe live poll coherence fixture");
        node.inject_live_poll_coherence_fault();

        let (response, received) = oneshot::channel();
        let command = SelectedBlobCommand::Poll {
            request: BlobPollRequest {
                subscription: subscription.id,
                delivery_limit: 1,
                scan_limit: 4,
            },
            response,
        };
        let admission = AtomicBool::new(true);
        let error = node
            .execute_live(command, &admission)
            .expect_err("live poll coherence contradiction must escape as actor-fatal");
        assert!(matches!(&error, NodeError::FatalBlobCoherence(_)));
        assert!(error.to_string().contains("delivery poll"));
        assert!(received.blocking_recv().is_err());
        assert_eq!(
            node.delivery_status()
                .expect("unadvanced delivery ledger after fatal poll"),
            BlobDeliveryStatus {
                subscriptions: 1,
                pending_deliveries: 0,
                acknowledged_deliveries: 0,
                delivery_cursors: 0,
                selector_generation: 1,
            }
        );
    }

    #[test]
    fn live_blob_poll_postcommit_completion_failure_is_fatal_and_attempt_retries() {
        let root = TestRoot::new("live-poll-postcommit-completion-fatal");
        let mut node = selected_node(&root);
        node.publish(
            request(b"blob/live-poll-postcommit/publication"),
            &mut Cursor::new(vec![4, 5, 6]),
        )
        .expect("publish live postcommit poll fixture");
        let subscription = node
            .subscribe(subscription_request(
                b"blob/live-poll-postcommit/subscription",
            ))
            .expect("subscribe live postcommit poll fixture");
        node.inject_live_poll_postcommit_completion_fault();

        let (response, received) = oneshot::channel();
        let command = SelectedBlobCommand::Poll {
            request: BlobPollRequest {
                subscription: subscription.id,
                delivery_limit: 1,
                scan_limit: 4,
            },
            response,
        };
        let admission = AtomicBool::new(true);
        let error = node
            .execute_live(command, &admission)
            .expect_err("postcommit completion contradiction must escape as actor-fatal");
        assert!(matches!(&error, NodeError::FatalBlobCoherence(_)));
        assert!(received.blocking_recv().is_err());
        assert_eq!(
            node.delivery_status()
                .expect("pending ledger after hidden postcommit attempt"),
            BlobDeliveryStatus {
                subscriptions: 1,
                pending_deliveries: 1,
                acknowledged_deliveries: 0,
                delivery_cursors: 1,
                selector_generation: 1,
            }
        );
        let retried = node
            .poll(BlobPollRequest {
                subscription: subscription.id,
                delivery_limit: 1,
                scan_limit: 4,
            })
            .expect("hidden postcommit attempt remains retryable");
        assert_eq!(retried.deliveries.len(), 1);
        assert_eq!(content_delivery(&retried.deliveries[0]).attempt, 2);
    }

    #[test]
    fn live_blob_depot_quota_is_ordinary_resource_limit() {
        let root = TestRoot::new("live-depot-quota-ordinary");
        persist_member_mission(&root);
        let source_path = root.path().join("live-depot-quota.bin");
        fs::write(&source_path, [0x51; 128]).expect("write quota source");
        let mut node = SelectedBlobNode::open_unprotected_reference_with_options(
            root.path(),
            root.mission_path(),
            SelectedBlobOptions {
                depot_limits: BlobDepotLimits::new(1, 4, 1).expect("tiny depot limits"),
            },
        )
        .expect("open tiny-depot Blob node");
        let admission = AtomicBool::new(true);
        let (response, received) = oneshot::channel();
        node.execute_live(
            SelectedBlobCommand::Publish {
                request: request(b"blob/live-depot-quota"),
                options: BlobPublishOptions::durable(),
                source: fs::File::open(source_path).expect("open quota source"),
                response,
            },
            &admission,
        )
        .expect("depot quota must not stop the Blob worker");
        let error = received
            .blocking_recv()
            .expect("quota response")
            .expect_err("tiny depot must reject publication");
        assert_eq!(error.kind(), ApplicationErrorKind::ResourceLimit);
    }

    #[test]
    fn blob_routine_cleanup_without_pressure_proof_returns_original_without_retry() {
        // Ordinary GC still runs first, but freeing an abandoned variant does
        // not by itself prove the rejected request's exact pressure deficit.
        for live in [false, true] {
            let root = TestRoot::new(if live {
                "live-capacity-gc-success"
            } else {
                "stopped-capacity-gc-success"
            });
            persist_member_mission(&root);
            let mut node = SelectedBlobNode::open_unprotected_reference_with_options(
                root.path(),
                root.mission_path(),
                SelectedBlobOptions {
                    depot_limits: BlobDepotLimits::new(1_000_000, 4, 1)
                        .expect("one-variant depot limits"),
                },
            )
            .expect("open capacity retry node");
            install_unreferenced_completed_variant(&node, &[0x59; 128]);
            let plaintext = vec![0x5a; 129];

            if live {
                let source_path = root.path().join("live-capacity-gc-success.bin");
                fs::write(&source_path, &plaintext).expect("write live capacity retry source");
                node.publish_live(
                    request(b"blob/live-capacity-gc-success"),
                    fs::File::open(source_path).expect("open live capacity retry source"),
                )
                .expect_err("routine cleanup alone cannot authorize the retry");
                assert_eq!(
                    node.last_live_publish_source_bytes_read, 0,
                    "a failed reservation cannot consume the live source",
                );
            } else {
                let mut source = CountingCursor::new(plaintext.clone());
                node.publish(request(b"blob/stopped-capacity-gc-success"), &mut source)
                    .expect_err("routine cleanup alone cannot authorize the retry");
                assert_eq!(
                    source.bytes_read, 0,
                    "a failed reservation cannot consume the stopped source",
                );
            }
            assert_eq!(node.capacity_gc_attempts, 1);
            assert_eq!(node.capacity_gc_targets, [BlobCapacityGcTarget::Depot]);
            assert_eq!(node.publish_attempts, 1);
            let stats = node.store.blob_stats().expect("post-retry Blob stats");
            assert_eq!(stats.publications, 0);
            assert_eq!(
                stats.variants, 1,
                "physical-only cleanup cannot invent deletion authority for an unreferenced variant"
            );
        }
    }

    #[test]
    fn blob_pressure_recovery_evicts_completed_native_pack_before_one_retry() {
        // Break caught: local publication cannot merely run ordinary GC and
        // retry while a lower-priority live variant still owns the rejected
        // depot partition.
        let root = TestRoot::new("local-pressure-completed-cache");
        persist_member_mission(&root);
        let mut node = SelectedBlobNode::open_unprotected_reference_with_options(
            root.path(),
            root.mission_path(),
            SelectedBlobOptions {
                depot_limits: BlobDepotLimits::new(1_000_000, 4, 1)
                    .expect("one-variant pressure limits"),
            },
        )
        .expect("open local pressure node");
        let mut low = request(b"blob/local-pressure/low");
        low.priority = Priority::Routine;
        node.publish(low, &mut Cursor::new(vec![0x31; 128]))
            .expect("publish lower-priority fixture");
        let evicted = node
            .store
            .blob_inventory()
            .expect("low-priority inventory")
            .into_iter()
            .next()
            .expect("low-priority transfer");
        prime_blob_policy_for_pressure(&node);
        let attempts_before = node.publish_attempts;
        let mut incoming = request(b"blob/local-pressure/high");
        incoming.priority = Priority::Flash;

        node.publish(incoming, &mut Cursor::new(vec![0x32; 129]))
            .expect("strictly higher-priority publication recovers depot capacity");

        assert_eq!(node.publish_attempts - attempts_before, 2);
        assert_eq!(node.capacity_gc_attempts, 1);
        assert!(
            !node
                .store
                .blob_inventory()
                .expect("post-pressure inventory")
                .contains(&evicted)
        );
        assert_eq!(
            node.store
                .blob_inventory()
                .expect("post-pressure inventory")
                .len(),
            1
        );
    }

    #[test]
    fn blob_pressure_retires_one_publication_with_the_production_budget() {
        // Break caught: a sole-root publication was rejected by a worst-case
        // fan-out gate even when its actual retirement plan fit the fixed node
        // recovery budget.
        let root = TestRoot::new("local-pressure-actual-publication-plan");
        persist_member_mission(&root);
        let mut node = selected_node(&root);
        let mut low = request(b"blob/local-pressure/actual-plan-low");
        low.priority = Priority::Routine;
        node.publish(low, &mut Cursor::new(vec![0x81; 128]))
            .expect("publish actual-plan fixture");
        let evicted = node.store.blob_inventory().expect("fixture inventory")[0];
        prime_blob_policy_for_pressure(&node);
        node.injected_capacity_failures
            .push_back(StoreError::ItemLimitExceeded {
                current: 1,
                limit: 1,
            });
        let attempts_before = node.publish_attempts;
        let mut incoming = request(b"blob/local-pressure/actual-plan-high");
        incoming.priority = Priority::Flash;

        node.publish(incoming, &mut Cursor::new(vec![0x82; 129]))
            .expect("actual sole-root plan fits production recovery budget");

        assert_eq!(node.publish_attempts - attempts_before, 2);
        assert_eq!(node.capacity_gc_attempts, 1);
        assert!(
            !node
                .store
                .blob_inventory()
                .expect("post-pressure inventory")
                .contains(&evicted)
        );
        assert_eq!(
            node.store
                .blob_inventory()
                .expect("post-pressure inventory")
                .len(),
            1
        );
    }

    #[test]
    fn blob_pressure_retry_propagates_a_second_attempt_invariant() {
        let root = TestRoot::new("local-pressure-second-invariant");
        persist_member_mission(&root);
        let mut node = selected_node(&root);
        let mut low = request(b"blob/local-pressure/second-invariant-low");
        low.priority = Priority::Routine;
        node.publish(low, &mut Cursor::new(vec![0x83; 128]))
            .expect("publish second-invariant fixture");
        prime_blob_policy_for_pressure(&node);
        node.injected_capacity_failures.extend([
            StoreError::ItemLimitExceeded {
                current: 1,
                limit: 1,
            },
            StoreError::Blob(BlobStoreError::SchemaInvariant(
                "injected second Blob publication attempt invariant",
            )),
        ]);
        let attempts_before = node.publish_attempts;
        let mut incoming = request(b"blob/local-pressure/second-invariant-high");
        incoming.priority = Priority::Flash;

        let error = node
            .publish(incoming, &mut Cursor::new(vec![0x84; 129]))
            .expect_err("second-attempt invariant must not be replaced by capacity");

        assert_eq!(error.kind(), ApplicationErrorKind::Integrity);
        assert_eq!(node.publish_attempts - attempts_before, 2);
        assert_eq!(node.capacity_gc_attempts, 1);
    }

    #[test]
    fn blob_pressure_retry_reads_source_once_after_reservation_succeeds() {
        // Reservation and pressure recovery complete before the native pack
        // consumes plaintext, so the sole successful reservation reads once.
        let root = TestRoot::new("local-pressure-single-read");
        persist_member_mission(&root);
        let mut node = SelectedBlobNode::open_unprotected_reference_with_options(
            root.path(),
            root.mission_path(),
            SelectedBlobOptions {
                depot_limits: BlobDepotLimits::new(1_000_000, 4, 1)
                    .expect("one-variant pressure limits"),
            },
        )
        .expect("open pressure node");
        let mut low = request(b"blob/local-pressure/single-read-low");
        low.priority = Priority::Routine;
        node.publish(low, &mut Cursor::new(vec![0x35; 128]))
            .expect("publish lower-priority fixture");
        let low = node.store.blob_inventory().expect("low inventory")[0];
        prime_blob_policy_for_pressure(&node);
        let attempts_before = node.publish_attempts;
        let mut incoming = request(b"blob/local-pressure/single-read-incoming");
        incoming.priority = Priority::Flash;
        let plaintext = vec![0x36; 129];
        let mut source = CountingCursor::new(plaintext.clone());

        node.publish(incoming, &mut source)
            .expect("capacity recovery reserves before consuming plaintext");

        assert_eq!(source.bytes_read, plaintext.len() as u64);
        assert_eq!(node.publish_attempts - attempts_before, 2);
        assert_eq!(node.capacity_gc_attempts, 1);
        assert!(
            !node
                .store
                .blob_inventory()
                .expect("single admitted inventory")
                .contains(&low)
        );
        assert_eq!(
            node.store
                .blob_inventory()
                .expect("single admitted inventory")
                .len(),
            1
        );
    }

    #[test]
    fn blob_native_one_pass_rejects_source_growth_during_read() {
        let root = TestRoot::new("native-source-growth");
        let mut node = selected_node(&root);
        let mut source = GrowingReadCursor::new(vec![0x37; 129]);

        let error = node
            .publish(request(b"blob/native-source-growth"), &mut source)
            .expect_err("source growth during the native read must conflict");

        assert_eq!(error.kind(), ApplicationErrorKind::Conflict);
        assert!(node.store.blob_inventory().expect("inventory").is_empty());
    }

    #[test]
    fn blob_insufficient_pressure_returns_without_retrying_admission() {
        // Break caught: equal-priority data cannot be evicted and an
        // unproven deficit cannot authorize the single admission retry.
        let root = TestRoot::new("local-pressure-insufficient");
        persist_member_mission(&root);
        let mut node = SelectedBlobNode::open_unprotected_reference_with_options(
            root.path(),
            root.mission_path(),
            SelectedBlobOptions {
                depot_limits: BlobDepotLimits::new(1_000_000, 4, 1)
                    .expect("one-variant pressure limits"),
            },
        )
        .expect("open insufficient-pressure node");
        let mut retained = request(b"blob/local-pressure/retained");
        retained.priority = Priority::Priority;
        node.publish(retained, &mut Cursor::new(vec![0x41; 128]))
            .expect("publish equal-priority fixture");
        let retained = node
            .store
            .blob_inventory()
            .expect("retained inventory")
            .into_iter()
            .next()
            .expect("retained transfer");
        let attempts_before = node.publish_attempts;
        let mut incoming = request(b"blob/local-pressure/equal");
        incoming.priority = Priority::Priority;

        let error = node
            .publish(incoming, &mut Cursor::new(vec![0x42; 129]))
            .expect_err("equal priority cannot recover the rejected partition");

        assert_eq!(error.kind(), ApplicationErrorKind::ResourceLimit);
        assert_eq!(node.publish_attempts - attempts_before, 1);
        assert_eq!(node.capacity_gc_attempts, 1);
        assert!(
            node.store
                .get_blob(retained)
                .expect("retained native publication lookup")
                .is_some(),
            "insufficient recovery preserves the unrelated equal-priority publication"
        );
    }

    #[cfg(unix)]
    #[test]
    fn blob_physical_deletion_failure_records_retry_and_reconciles_before_single_retry() {
        use std::os::unix::fs::PermissionsExt as _;

        let root = TestRoot::new("local-pressure-physical-failure");
        persist_member_mission(&root);
        let mut node = SelectedBlobNode::open_unprotected_reference_with_options(
            root.path(),
            root.mission_path(),
            SelectedBlobOptions {
                depot_limits: BlobDepotLimits::new(70_000, 4, 4)
                    .expect("byte-constrained physical-failure limits"),
            },
        )
        .expect("open physical-failure pressure node");
        let mut low = request(b"blob/local-pressure/physical-low");
        low.priority = Priority::Routine;
        node.publish(low, &mut Cursor::new(vec![0x61; 128]))
            .expect("publish physical-failure fixture");
        let evicted = node
            .store
            .blob_inventory()
            .expect("physical-failure inventory")[0];
        let variant_directory = first_profile5_pack_file(&root.depot_path())
            .parent()
            .expect("physical-failure variant directory")
            .to_path_buf();
        prime_blob_policy_for_pressure(&node);
        fs::set_permissions(&variant_directory, fs::Permissions::from_mode(0o500))
            .expect("make variant directory non-writable");
        let attempts_before = node.publish_attempts;
        let mut incoming = request(b"blob/local-pressure/physical-high");
        incoming.priority = Priority::Flash;

        let result = node.publish(incoming, &mut Cursor::new(vec![0x62; 129]));
        for _ in 0..16 {
            node.store
                .run_blob_maintenance_turn(
                    BlobMaintenanceBudget::new(64, 16, 128 * 1024 * 1024)
                        .expect("physical-failure maintenance budget"),
                )
                .expect("physical unlink failure remains durable maintenance state");
            if node
                .store
                .blob_gc_status(None)
                .expect("physical-failure interim status")
                .retry_attempts
                > 0
            {
                break;
            }
        }
        fs::set_permissions(&variant_directory, fs::Permissions::from_mode(0o700))
            .expect("restore variant directory permissions");
        let error =
            result.expect_err("deferred physical unlink cannot prove the rejected depot deficit");
        assert_eq!(error.kind(), ApplicationErrorKind::ResourceLimit);
        assert_eq!(node.publish_attempts - attempts_before, 1);
        assert_eq!(node.capacity_gc_attempts, 1);
        assert!(
            !node
                .store
                .blob_inventory()
                .expect("retired inventory")
                .contains(&evicted)
        );
        let status = node
            .store
            .blob_gc_status(None)
            .expect("physical-failure GC status");
        assert!(status.retry_attempts > 0);
        assert!(status.last_failure.is_some());
    }

    #[test]
    fn blob_unrecoverable_depot_capacity_returns_without_retrying_source() {
        // Break caught: eligible but unsatisfiable depot pressure must stop
        // after one targeted attempt without an admission retry.
        for live in [false, true] {
            let root = TestRoot::new(if live {
                "live-capacity-gc-unsatisfied"
            } else {
                "stopped-capacity-gc-unsatisfied"
            });
            persist_member_mission(&root);
            let mut node = SelectedBlobNode::open_unprotected_reference_with_options(
                root.path(),
                root.mission_path(),
                SelectedBlobOptions {
                    depot_limits: BlobDepotLimits::new(1, 4, 1).expect("tiny depot limits"),
                },
            )
            .expect("open unsatisfied capacity node");
            let plaintext = vec![0x5b; 128];

            let error = if live {
                let source_path = root.path().join("live-capacity-gc-unsatisfied.bin");
                fs::write(&source_path, &plaintext).expect("write live unsatisfied source");
                let error = node
                    .publish_live(
                        request(b"blob/live-capacity-gc-unsatisfied"),
                        fs::File::open(source_path).expect("open live unsatisfied source"),
                    )
                    .expect_err("live tiny depot remains exhausted");
                assert_eq!(
                    node.last_live_publish_source_bytes_read, 0,
                    "unrecoverable reservation pressure cannot consume the live source",
                );
                error
            } else {
                let mut source = CountingCursor::new(plaintext.clone());
                let error = node
                    .publish(
                        request(b"blob/stopped-capacity-gc-unsatisfied"),
                        &mut source,
                    )
                    .expect_err("stopped tiny depot remains exhausted");
                assert_eq!(
                    source.bytes_read, 0,
                    "unrecoverable reservation pressure cannot consume the stopped source",
                );
                error
            };
            assert_eq!(error.kind(), ApplicationErrorKind::ResourceLimit);
            assert_eq!(node.capacity_gc_attempts, 1);
            assert_eq!(node.capacity_gc_targets, [BlobCapacityGcTarget::Depot]);
            assert_eq!(node.publish_attempts, 1);
        }
    }

    #[test]
    fn blob_lifecycle_capacity_control_flow_requires_pressure_deficit_proof() {
        // A due routine-expiry unit can release authority, but its progress
        // alone cannot authorize retry without exact pressure deficit proof.
        let reclaimable_root = TestRoot::new("lifecycle-capacity-reclaimable");
        let mut rekey = persist_rekey_mission(&reclaimable_root);
        let publication_cap =
            aster_redb_store::BlobLifecycleLimits::new(4, 4 * 1024, 4, 4 * 1024, 1)
                .expect("one-row publication lifecycle cap");
        let clock_id = [0xc1; 16];
        let retirement_tick = 100;
        let retention_deadline = retirement_tick + 45 * 24 * 60 * 60 * 1_000;
        {
            let mut node = selected_node_with_lifecycle_limits_and_clock(
                &reclaimable_root,
                publication_cap,
                NodeCustodyClock::injected(clock_id, retirement_tick, 0),
            );
            node.publish(
                request(b"blob/lifecycle-capacity/retired"),
                &mut Cursor::new(b"retired lifecycle capacity source".to_vec()),
            )
            .expect("publish lifecycle-capacity fixture");
        }
        apply_epoch_two_rekey(&reclaimable_root, &mut rekey);

        let mut node = selected_node_with_lifecycle_limits_and_clock(
            &reclaimable_root,
            publication_cap,
            NodeCustodyClock::injected(clock_id, retention_deadline, 0),
        );
        let retired_at = aster_mesh::CustodySample {
            clock_id,
            tick_ms: retirement_tick,
        };
        const BLOB_MAINTENANCE_CLASSES: u64 = 6;
        const POLICY_SETUP_AND_COMPLETION_UNITS: u64 = 6;
        let initial_stats = node
            .store
            .blob_stats()
            .expect("pre-retirement lifecycle-capacity stats");
        let finite_root_count = initial_stats
            .publications
            .checked_add(initial_stats.pending_sources)
            .expect("finite root count fits u64");
        assert_eq!(finite_root_count, 1, "fixture has one finite root");
        let maintenance_turn_bound = BLOB_MAINTENANCE_CLASSES
            .checked_mul(
                finite_root_count
                    .checked_add(POLICY_SETUP_AND_COMPLETION_UNITS)
                    .expect("policy unit count fits u64"),
            )
            .expect("maintenance turn bound fits u64");
        let mut retained_status = node
            .store
            .blob_gc_status(Some(retired_at))
            .expect("initial lifecycle-capacity status");
        for _ in 0..maintenance_turn_bound {
            node.store
                .run_blob_maintenance_turn_with_sample(
                    BlobMaintenanceBudget::new(64, 16, 128 * 1024 * 1024)
                        .expect("lifecycle retirement budget"),
                    Some(retired_at),
                )
                .expect("retire stale lifecycle-capacity publication");
            retained_status = node
                .store
                .blob_gc_status(Some(retired_at))
                .expect("retired lifecycle-capacity status");
            if retained_status.retained_publication_records == 1 {
                break;
            }
        }
        assert_eq!(
            retained_status.retained_publication_records, 1,
            "the publication cap is occupied by one due retired record after at most {maintenance_turn_bound} turns; final status: {retained_status:?}"
        );
        let error = node
            .publish(
                request(b"blob/lifecycle-capacity/replacement"),
                &mut Cursor::new(b"replacement lifecycle capacity source".to_vec()),
            )
            .expect_err("routine lifecycle expiry alone cannot authorize the retry");
        assert_eq!(error.kind(), ApplicationErrorKind::ResourceLimit);
        assert_eq!(node.capacity_gc_attempts, 1);
        assert_eq!(
            node.capacity_gc_targets,
            [BlobCapacityGcTarget::PublicationLifecycle]
        );
        assert_eq!(node.publish_attempts, 1);
        let after_recovery = node
            .store
            .blob_gc_status(Some(aster_mesh::CustodySample {
                clock_id,
                tick_ms: retention_deadline,
            }))
            .expect("post-retry lifecycle status");
        assert_eq!(after_recovery.retained_publication_records, 0);
        assert_eq!(after_recovery.retained_operation_records, 1);
        assert_eq!(
            node.store
                .blob_stats()
                .expect("post-retry lifecycle stats")
                .publications,
            0
        );

        // An eligible capacity failure that remains unsatisfied gets exactly
        // one cleanup/pressure attempt and no admission retry.
        let unsatisfied_root = TestRoot::new("lifecycle-capacity-unsatisfied");
        persist_member_mission(&unsatisfied_root);
        let mut unsatisfied = selected_node_with_lifecycle_limits_and_clock(
            &unsatisfied_root,
            publication_cap,
            NodeCustodyClock::injected([0xc2; 16], 100, 0),
        );
        unsatisfied
            .publish(
                request(b"blob/lifecycle-capacity/full"),
                &mut Cursor::new(b"live lifecycle capacity source".to_vec()),
            )
            .expect("fill live publication lifecycle cap");
        let error = unsatisfied
            .publish(
                request(b"blob/lifecycle-capacity/still-full"),
                &mut Cursor::new(b"second live lifecycle capacity source".to_vec()),
            )
            .expect_err("live publication cap remains exhausted after one retry");
        assert_eq!(error.kind(), ApplicationErrorKind::ResourceLimit);
        assert_eq!(unsatisfied.capacity_gc_attempts, 1);
        assert_eq!(
            unsatisfied.capacity_gc_targets,
            [BlobCapacityGcTarget::PublicationLifecycle]
        );
        assert_eq!(unsatisfied.publish_attempts, 2);

        // Permanent replay authority is not reclaimable and therefore must
        // not enter the capacity-GC retry path at all.
        let ineligible_root = TestRoot::new("lifecycle-capacity-ineligible");
        persist_member_mission(&ineligible_root);
        let replay_cap = aster_redb_store::BlobLifecycleLimits::new(4, 4 * 1024, 1, 4 * 1024, 4)
            .expect("one-row replay fence cap");
        let mut ineligible = selected_node_with_lifecycle_limits_and_clock(
            &ineligible_root,
            replay_cap,
            NodeCustodyClock::injected([0xc3; 16], 100, 0),
        );
        ineligible
            .publish(
                request(b"blob/replay-capacity/full"),
                &mut Cursor::new(b"first permanent replay fence".to_vec()),
            )
            .expect("fill permanent replay fence cap");
        let error = ineligible
            .publish(
                request(b"blob/replay-capacity/ineligible"),
                &mut Cursor::new(b"second permanent replay fence".to_vec()),
            )
            .expect_err("permanent replay capacity is not reclaimable");
        assert_eq!(error.kind(), ApplicationErrorKind::ResourceLimit);
        assert_eq!(ineligible.capacity_gc_attempts, 0);
        assert!(ineligible.capacity_gc_targets.is_empty());
        assert_eq!(ineligible.publish_attempts, 2);
    }

    #[test]
    fn blob_operation_capacity_without_pressure_evidence_does_not_retry() {
        // The fixed production limits are intentionally large, so inject the
        // typed store boundary immediately before preparation. The ordinary
        // publish loop, classifier, and bounded capacity call remain real;
        // no candidate means no pressure proof and therefore no retry.
        for (case, failure) in [
            (
                "operation-count",
                BlobStoreError::OperationLimitExceeded {
                    current: 4_096,
                    limit: 4_096,
                },
            ),
            (
                "operation-bytes",
                BlobStoreError::OperationByteLimitExceeded {
                    current: 512 * 1024,
                    incoming: 64,
                    limit: 512 * 1024,
                },
            ),
        ] {
            let root = TestRoot::new(case);
            persist_member_mission(&root);
            let mut node = selected_node(&root);
            node.injected_capacity_failures
                .push_back(StoreError::Blob(failure));

            let error = node
                .publish(
                    request(format!("blob/{case}").as_bytes()),
                    &mut Cursor::new(format!("{case} source").into_bytes()),
                )
                .expect_err("operation pressure without a candidate remains rejected");

            assert_eq!(error.kind(), ApplicationErrorKind::ResourceLimit);
            assert_eq!(node.capacity_gc_attempts, 1);
            assert_eq!(node.capacity_gc_targets, [BlobCapacityGcTarget::Operation]);
            assert_eq!(node.publish_attempts, 1);
        }
    }

    #[test]
    fn live_blob_orphan_preflights_are_actor_fatal_but_absence_is_ordinary() {
        let publish_root = TestRoot::new("live-orphan-operation");
        let source_path = publish_root.path().join("source.bin");
        fs::write(&source_path, [1u8, 2, 3]).expect("write orphan-operation source");
        let mut publish_node = selected_node(&publish_root);
        publish_node.live_operation_preflight_coherence_fault = true;
        let (response, received) = oneshot::channel();
        let publish_command = SelectedBlobCommand::Publish {
            request: request(b"blob/live-orphan-operation"),
            options: BlobPublishOptions::durable(),
            source: fs::File::open(&source_path).expect("open orphan-operation source"),
            response,
        };
        let admission = AtomicBool::new(true);
        let error = publish_node
            .execute_live(publish_command, &admission)
            .expect_err("orphan operation must escape actor-fatal");
        assert!(matches!(error, NodeError::FatalBlobCoherence(_)));
        assert!(received.blocking_recv().is_err());
        assert_eq!(
            publish_node
                .store
                .blob_stats()
                .expect("orphan-operation stats")
                .publications,
            0
        );

        let read_root = TestRoot::new("live-orphan-content");
        let mut read_node = selected_node(&read_root);
        read_node.live_read_projection_coherence_fault = true;
        let missing = BlobReadPageRequest {
            blob: BlobReadRequest {
                id: BlobId::from_bytes([0x91; 32]),
                topic: blob_topic(),
                scope: blob_scope(),
            },
            offset: 0,
            max_bytes: 1,
        };
        let (response, received) = oneshot::channel();
        let error = read_node
            .execute_live(
                SelectedBlobCommand::ReadPage {
                    request: missing.clone(),
                    response,
                },
                &admission,
            )
            .expect_err("orphan content index must escape actor-fatal");
        assert!(matches!(error, NodeError::FatalBlobCoherence(_)));
        assert!(received.blocking_recv().is_err());

        let absent_root = TestRoot::new("live-absent-content");
        let mut absent_node = selected_node(&absent_root);
        let (response, received) = oneshot::channel();
        absent_node
            .execute_live(
                SelectedBlobCommand::ReadPage {
                    request: missing,
                    response,
                },
                &admission,
            )
            .expect("absent Blob is an ordinary application result");
        let absent = received
            .blocking_recv()
            .expect("absent Blob response")
            .expect_err("absent Blob cannot return plaintext");
        assert_eq!(absent.kind(), ApplicationErrorKind::NotFound);
    }

    #[test]
    fn live_blob_selected_load_policy_race_is_ordinary_and_discloses_no_page() {
        let root = TestRoot::new("live-selected-load-policy-race");
        let bytes = payload(SELECTED_BLOB_CHUNK_SIZE as usize + 9);
        let mut node = selected_node(&root);
        let published = node
            .publish(
                request(b"blob/live-selected-load-policy-race"),
                &mut Cursor::new(bytes),
            )
            .expect("publish selected-load race fixture");
        node.live_selected_load_policy_race_fault = true;
        let admission = AtomicBool::new(true);
        let (response, received) = oneshot::channel();
        node.execute_live(
            SelectedBlobCommand::ReadPage {
                request: BlobReadPageRequest {
                    blob: BlobReadRequest {
                        id: published.id,
                        topic: blob_topic(),
                        scope: blob_scope(),
                    },
                    offset: 0,
                    max_bytes: 1,
                },
                response,
            },
            &admission,
        )
        .expect("selected-load control race must not stop the Blob worker");
        let error = received
            .blocking_recv()
            .expect("selected-load race response")
            .expect_err("selected-load race cannot disclose a page");
        assert_eq!(error.kind(), ApplicationErrorKind::PolicyUnsettled);
    }

    #[test]
    fn live_blob_durable_coherence_classifier_is_narrow() {
        for fatal in [
            BlobStoreError::SchemaInvariant("test invariant"),
            BlobStoreError::DepotIntegrity("test depot invariant"),
            BlobStoreError::CompletionMismatch,
        ] {
            assert!(live_blob_durable_coherence_error(&StoreError::Blob(fatal)));
        }
        for ordinary in [
            BlobStoreError::OperationConflict,
            BlobStoreError::PublisherRevoked([0x44; 32]),
            BlobStoreError::KeyEpochStale {
                current: 2,
                received: 1,
            },
            BlobStoreError::KeyEpochNotActive {
                current: 1,
                received: 2,
            },
            BlobStoreError::ReadPlanChanged,
            BlobStoreError::PublicationLimitExceeded {
                current: 1,
                limit: 1,
            },
            BlobStoreError::PhysicalLineageConflict,
            BlobStoreError::PhysicalLineageMigrationRequired,
        ] {
            assert!(!live_blob_durable_coherence_error(&StoreError::Blob(
                ordinary
            )));
        }
    }

    #[test]
    fn live_blob_page_closes_after_waiting_for_final_lifecycle_check() {
        let root = TestRoot::new("page-final-close");
        let bytes = payload(SELECTED_BLOB_CHUNK_SIZE as usize + 19);
        let mut node = selected_node(&root);
        let published = node
            .publish(request(b"blob/page-final-close"), &mut Cursor::new(bytes))
            .expect("publish final-close fixture");
        let reached = Arc::new(std::sync::Barrier::new(2));
        let release = Arc::new(std::sync::Barrier::new(2));
        node.set_final_read_gate(Arc::clone(&reached), Arc::clone(&release));
        let cache = Arc::clone(&node.source_route_cache);
        let admission = Arc::new(AtomicBool::new(true));
        let worker_admission = Arc::clone(&admission);
        let (response, received) = oneshot::channel();
        let command = SelectedBlobCommand::ReadPage {
            request: BlobReadPageRequest {
                blob: BlobReadRequest {
                    id: published.id,
                    topic: blob_topic(),
                    scope: blob_scope(),
                },
                offset: 7,
                max_bytes: 31,
            },
            response,
        };
        let worker = std::thread::spawn(move || {
            node.execute_live(command, &worker_admission)
                .expect("closed page is an ordinary rejection")
        });

        reached.wait();
        let lifecycle = cache
            .lock_blob_lifecycle()
            .expect("hold final Blob lifecycle");
        admission.store(false, Ordering::Release);
        release.wait();
        drop(lifecycle);
        worker.join().expect("join live Blob page worker");
        let error = received
            .blocking_recv()
            .expect("closed final page response")
            .expect_err("closed final page cannot disclose plaintext");
        assert_eq!(error.kind(), ApplicationErrorKind::StateUnavailable);
        assert_eq!(error.operation(), "blob read page");
    }

    #[test]
    fn live_blob_file_requires_zero_cursor_and_growth_cannot_cross_ceiling() {
        let root = TestRoot::new("live-file-boundary");
        let source_path = root.path().join("source.bin");
        fs::write(&source_path, [1u8, 2, 3]).expect("write live source");
        let mut source = fs::File::open(&source_path).expect("open live source");
        source
            .seek(std::io::SeekFrom::Start(1))
            .expect("pre-seek live source");
        let mut node = selected_node(&root);
        let error = node
            .publish_live(request(b"blob/live-preseek"), source)
            .expect_err("pre-seeked live file must fail");
        assert_eq!(error.kind(), ApplicationErrorKind::InvalidRequest);

        fs::OpenOptions::new()
            .write(true)
            .open(&source_path)
            .expect("open growing source")
            .set_len(MAX_SELECTED_LIVE_BLOB_BYTES + 1)
            .expect("grow sparse source past live ceiling");
        let oversized = fs::File::open(&source_path).expect("reopen oversized live source");
        let error = node
            .publish_live(request(b"blob/live-oversized"), oversized)
            .expect_err("oversized live file must fail with its public category");
        assert_eq!(error.kind(), ApplicationErrorKind::ResourceLimit);
        assert_eq!(error.operation(), "blob publish");
        let streamed_growth = blob_core_error(
            "blob publish",
            BlobError::Io(std::io::Error::new(
                std::io::ErrorKind::FileTooLarge,
                "simulated concurrent live source growth",
            )),
        );
        assert_eq!(streamed_growth.kind(), ApplicationErrorKind::ResourceLimit);
    }

    #[test]
    fn blob_publish_retry_change_conflict_dedup_read_and_reopen_are_stable() {
        let root = TestRoot::new("lifecycle");
        let bytes = payload(4 * SELECTED_BLOB_CHUNK_SIZE as usize + 317);
        let first_request = request(b"blob/lifecycle/first");
        let (first, second, first_stats) = {
            let mut node = selected_node(&root);
            let first = node
                .publish(first_request.clone(), &mut Cursor::new(bytes.clone()))
                .expect("publish first Blob");
            assert!(first.inserted);
            assert_eq!(first.total_len, bytes.len() as u64);
            assert_eq!(first.publisher_counter, 1);
            assert_eq!(
                first.media_type.as_deref(),
                Some("application/x-aster-test")
            );
            assert_eq!(first.schema_id, b"schema/blob-v1");
            let first_stats = node.store.blob_stats().expect("first Blob stats");
            assert_eq!(first_stats.publications, 1);
            assert_eq!(first_stats.variants, 1);
            assert_eq!(first_stats.finalized_variants, 1);
            assert_eq!(
                first_stats.committed_chunks,
                bytes.len().div_ceil(BLOB_STREAM_SEGMENT_BYTES) as u64
            );

            let replay = node
                .publish(first_request.clone(), &mut Cursor::new(bytes.clone()))
                .expect("exact retry");
            assert!(!replay.inserted);
            assert_eq!(
                replay,
                BlobPublishResult {
                    inserted: false,
                    ..first.clone()
                }
            );
            assert_eq!(node.store.blob_stats().expect("retry stats"), first_stats);

            let changed = payload(bytes.len() + 1);
            let conflict = node
                .publish(first_request.clone(), &mut Cursor::new(changed))
                .expect_err("changed source must conflict before depot install");
            assert_eq!(conflict.kind(), ApplicationErrorKind::Conflict);
            assert_eq!(
                node.store.blob_stats().expect("conflict stats"),
                first_stats
            );

            let mut changed_metadata = first_request.clone();
            changed_metadata.media_type = Some("application/x-changed".into());
            let conflict = node
                .publish(changed_metadata, &mut Cursor::new(bytes.clone()))
                .expect_err("changed identity metadata under one operation must conflict");
            assert_eq!(conflict.kind(), ApplicationErrorKind::Conflict);
            assert_eq!(
                node.store.blob_stats().expect("metadata conflict stats"),
                first_stats
            );

            let stale_policy = node.current_policy("blob stale plan").expect("policy");
            let stale_plan = node
                .store
                .prepare_blob_read_with_policy(
                    &stale_policy,
                    &blob_topic(),
                    &blob_scope(),
                    first.id.into_core(),
                )
                .expect("single-publication read plan");
            let mut second_request = request(b"blob/lifecycle/second-publication");
            second_request.priority = Priority::Flash;
            let second = node
                .publish(second_request, &mut Cursor::new(bytes.clone()))
                .expect("publish another source envelope over same content");
            assert!(second.inserted);
            assert_eq!(second.id, first.id);
            assert_eq!(second.publisher_counter, 2);
            assert_eq!(second.priority, Priority::Flash);
            let second_stats = node.store.blob_stats().expect("dedup stats");
            assert_eq!(second_stats.publications, 2);
            assert_eq!(second_stats.variants, first_stats.variants);
            assert_eq!(second_stats.committed_chunks, first_stats.committed_chunks);
            assert_eq!(
                second_stats.committed_file_bytes,
                first_stats.committed_file_bytes
            );
            let drift = node
                .store
                .require_blob_read_plan_with_policy(&stale_policy, &stale_plan)
                .expect_err("new signed publication must invalidate the exact read plan");
            assert_eq!(
                application_error("blob read", drift.into()).kind(),
                ApplicationErrorKind::PolicyUnsettled
            );

            let mut output = Vec::new();
            let read = node
                .read_into(
                    BlobReadRequest {
                        id: first.id,
                        topic: blob_topic(),
                        scope: blob_scope(),
                    },
                    &mut output,
                )
                .expect("stream selected Blob");
            assert_eq!(output, bytes);
            assert_eq!(read.id, first.id);
            assert_eq!(read.total_len, bytes.len() as u64);
            assert_eq!(
                read.verified_chunks,
                bytes.len().div_ceil(MAX_SELECTED_BLOB_PAGE_BYTES) as u64
            );
            assert!(
                read.peak_working_buffer_bytes <= MAX_SELECTED_BLOB_PAGE_BYTES,
                "Blob reader exceeded its application-page buffer bound"
            );
            assert_eq!(read.media_type, first.media_type);
            assert_eq!(read.schema_id, first.schema_id);
            let policy = node.current_policy("blob test plan").expect("policy");
            let plan = node
                .store
                .prepare_blob_read_with_policy(
                    &policy,
                    &blob_topic(),
                    &blob_scope(),
                    first.id.into_core(),
                )
                .expect("read plan");
            let current = plan.current().expect("deterministic active publication");
            let current = node
                .store
                .load_blob_read_candidate_with_policy(&policy, current)
                .expect("exact-load selected publication");
            assert_eq!(read.publisher_counter, current.header.stamp.dot.counter);
            (first, second, first_stats)
        };

        let mut reopened = selected_node(&root);
        let replay = reopened
            .publish(first_request, &mut Cursor::new(bytes.clone()))
            .expect("restart-stable exact retry");
        assert!(!replay.inserted);
        assert_eq!(replay.id, first.id);
        assert_eq!(replay.publisher, first.publisher);
        assert_eq!(replay.publisher_counter, first.publisher_counter);
        assert_eq!(replay.acceptance_marker, first.acceptance_marker);
        let reopened_stats = reopened.store.blob_stats().expect("reopened stats");
        assert_eq!(reopened_stats.publications, 2);
        assert_eq!(reopened_stats.variants, first_stats.variants);
        assert_eq!(
            reopened_stats.committed_chunks,
            first_stats.committed_chunks
        );
        assert_eq!(
            reopened_stats.committed_file_bytes,
            first_stats.committed_file_bytes
        );
        assert_eq!(second.id, replay.id);
    }

    #[test]
    fn blob_invalid_empty_metadata_operation_and_route_only_requests_fail_closed() {
        let root = TestRoot::new("invalid");
        let mut node = selected_node(&root);
        let empty = node
            .publish(request(b"blob/empty"), &mut Cursor::new(Vec::new()))
            .expect_err("empty selected Blob");
        assert_eq!(empty.kind(), ApplicationErrorKind::InvalidRequest);

        let mut invalid_metadata = request(b"blob/metadata");
        invalid_metadata.media_type = Some(String::new());
        let metadata = node
            .publish(invalid_metadata, &mut Cursor::new(vec![1]))
            .expect_err("empty media type");
        assert_eq!(metadata.kind(), ApplicationErrorKind::InvalidRequest);

        let mut invalid_operation = request(&vec![0x41; 257]);
        invalid_operation.operation_key = vec![0x41; 257];
        let operation = node
            .publish(invalid_operation, &mut Cursor::new(vec![1]))
            .expect_err("oversized operation key");
        assert_eq!(operation.kind(), ApplicationErrorKind::InvalidRequest);

        let mut wrong_topic = request(b"blob/wrong-topic");
        wrong_topic.topic = Topic::new("ops.not-granted").expect("wrong topic");
        let denied = node
            .publish(wrong_topic, &mut Cursor::new(vec![1, 2, 3]))
            .expect_err("ungranted topic");
        assert_eq!(denied.kind(), ApplicationErrorKind::RequestRejected);
        assert_eq!(node.store.blob_stats().expect("empty stats").variants, 0);
        drop(node);

        let relay_root = TestRoot::new("route-only");
        persist_relay_mission(&relay_root);
        let mut relay = SelectedBlobNode::open_unprotected_reference(
            relay_root.path(),
            relay_root.mission_path(),
        )
        .expect("open route-only selected node");
        let denied = relay
            .publish(request(b"blob/route-only"), &mut Cursor::new(vec![1, 2, 3]))
            .expect_err("route-only node cannot publish plaintext");
        assert_eq!(denied.kind(), ApplicationErrorKind::RequestRejected);

        let future_root = TestRoot::new("future-only");
        persist_future_only_mission(&future_root);
        let mut future = SelectedBlobNode::open_unprotected_reference(
            future_root.path(),
            future_root.mission_path(),
        )
        .expect("open future-only selected node");
        let denied = future
            .publish(
                request(b"blob/future-only"),
                &mut Cursor::new(vec![1, 2, 3]),
            )
            .expect_err("future epoch key is not current authority");
        assert_eq!(denied.kind(), ApplicationErrorKind::RequestRejected);
        assert_eq!(
            future
                .store
                .blob_stats()
                .expect("future-only stats")
                .variants,
            0
        );

        let erased_adapter = blob_core_error(
            "blob publish",
            BlobError::Store(Box::new(std::io::Error::other(
                "provider-sanitized adapter failure",
            ))),
        );
        assert_eq!(erased_adapter.kind(), ApplicationErrorKind::Integrity);
        assert_eq!(
            blob_prepare_error(BlobError::InvalidManifest).kind(),
            ApplicationErrorKind::ResourceLimit
        );
        assert_eq!(
            blob_core_error("blob publish", BlobError::InvalidManifest).kind(),
            ApplicationErrorKind::Integrity
        );
    }

    #[test]
    fn blob_capacity_gc_classifier_accepts_only_reclaimable_local_limits() {
        // Break caught: only local limits that one cursor-neutral reclamation
        // pass can relieve may authorize the single admission retry.
        for (error, target) in [
            (
                BlobStoreError::DepotByteLimitExceeded {
                    current: 10,
                    incoming: 1,
                    limit: 10,
                },
                BlobCapacityGcTarget::Depot,
            ),
            (
                BlobStoreError::DepotChunkLimitExceeded {
                    current: 10,
                    limit: 10,
                },
                BlobCapacityGcTarget::Depot,
            ),
            (
                BlobStoreError::DepotVariantLimitExceeded {
                    current: 10,
                    limit: 10,
                },
                BlobCapacityGcTarget::Depot,
            ),
            (
                BlobStoreError::OperationLimitExceeded {
                    current: 1,
                    limit: 1,
                },
                BlobCapacityGcTarget::Operation,
            ),
            (
                BlobStoreError::OperationByteLimitExceeded {
                    current: 1,
                    incoming: 1,
                    limit: 1,
                },
                BlobCapacityGcTarget::Operation,
            ),
            (
                BlobStoreError::PublicationLifecycleCapacity {
                    required_rows: 2,
                    max_rows: 1,
                },
                BlobCapacityGcTarget::PublicationLifecycle,
            ),
        ] {
            assert_eq!(blob_store_error_recoverable_capacity(&error), Some(target));
        }

        for error in [
            BlobStoreError::PublicationLimitExceeded {
                current: 1,
                limit: 1,
            },
            BlobStoreError::CausalFrontierLimitExceeded {
                current: 1,
                limit: 1,
            },
            BlobStoreError::LineageFenceCapacity {
                required_rows: 2,
                required_bytes: 2,
                max_rows: 1,
                max_bytes: 1,
            },
            BlobStoreError::ReplayFenceCapacity {
                required_rows: 2,
                required_bytes: 2,
                max_rows: 1,
                max_bytes: 1,
            },
            BlobStoreError::NetworkBlobTooLarge {
                total_len: 2,
                chunk_count: 2,
                max_total_len: 1,
                max_chunks: 1,
            },
            BlobStoreError::NetworkSourceTooLarge {
                sealed_len: 2,
                limit: 1,
            },
            BlobStoreError::NetworkStagingRowLimitExceeded {
                current: 1,
                incoming: 1,
                limit: 1,
            },
            BlobStoreError::NetworkStagingByteLimitExceeded {
                current: 1,
                incoming: 1,
                limit: 1,
            },
            BlobStoreError::LeaseCapacity,
        ] {
            assert!(blob_store_error_recoverable_capacity(&error).is_none());
        }
    }

    #[test]
    fn blob_pack_tamper_fails_stream_and_reopen_and_writer_lock_is_shared() {
        let root = TestRoot::new("tamper");
        let bytes = payload(SELECTED_BLOB_CHUNK_SIZE as usize + 23);
        let mut node = selected_node(&root);
        let published = node
            .publish(request(b"blob/tamper"), &mut Cursor::new(bytes))
            .expect("publish tamper fixture");
        let locked =
            match SelectedEventNode::open_unprotected_reference(root.path(), root.mission_path()) {
                Ok(_) => panic!("Blob handle must own the shared writer lock"),
                Err(error) => error,
            };
        assert_eq!(locked.kind(), ApplicationErrorKind::StateUnavailable);

        let pack = first_profile5_pack_file(&root.depot_path());
        let mut ciphertext = fs::read(&pack).expect("read committed native pack");
        let last = ciphertext.last_mut().expect("nonempty native pack");
        *last ^= 0x80;
        fs::write(&pack, ciphertext).expect("tamper committed native pack");
        let mut output = Vec::new();
        let error = node
            .read_into(
                BlobReadRequest {
                    id: published.id,
                    topic: blob_topic(),
                    scope: blob_scope(),
                },
                &mut output,
            )
            .expect_err("tampered depot must not stream successfully");
        assert_eq!(error.kind(), ApplicationErrorKind::Integrity);
        drop(node);

        let reopen =
            match SelectedBlobNode::open_unprotected_reference(root.path(), root.mission_path()) {
                Ok(_) => panic!("marked corrupt depot must fail closed on reopen"),
                Err(error) => error,
            };
        assert_eq!(reopen.kind(), ApplicationErrorKind::Integrity);
    }

    #[test]
    fn blob_rekey_retries_old_operation_without_install_then_new_operation_gets_new_variant() {
        let root = TestRoot::new("rekey");
        let mut services = persist_rekey_mission(&root);
        let bytes = payload(SELECTED_BLOB_CHUNK_SIZE as usize + 73);
        let old_request = request(b"blob/rekey/old-operation");
        let first = {
            let mut node =
                SelectedBlobNode::open_unprotected_reference(root.path(), root.mission_path())
                    .expect("open epoch-one Blob node");
            node.publish(old_request.clone(), &mut Cursor::new(bytes.clone()))
                .expect("publish epoch-one Blob")
        };
        let before_rekey =
            Store::open_for_mission(root.path().join(STORE_FILE), services.mission_authority)
                .expect("inspect epoch-one store")
                .blob_stats()
                .expect("epoch-one stats");
        assert_eq!(before_rekey.variants, 1);
        assert_eq!(before_rekey.committed_chunks, 1);

        apply_epoch_two_rekey(&root, &mut services);
        let mut node =
            SelectedBlobNode::open_unprotected_reference(root.path(), root.mission_path())
                .expect("open epoch-two Blob node");
        let replay = node
            .publish(old_request, &mut Cursor::new(bytes.clone()))
            .expect("authorized historical operation retry");
        assert!(!replay.inserted);
        assert_eq!(replay.id, first.id);
        assert_eq!(replay.publisher_counter, first.publisher_counter);
        assert_eq!(replay.acceptance_marker, first.acceptance_marker);
        assert_eq!(
            node.store.blob_stats().expect("post-retry stats"),
            before_rekey
        );

        let inactive = node
            .read_into(
                BlobReadRequest {
                    id: first.id,
                    topic: blob_topic(),
                    scope: blob_scope(),
                },
                &mut Vec::new(),
            )
            .expect_err("epoch-one-only publication is inactive after rekey");
        assert_eq!(inactive.kind(), ApplicationErrorKind::UnauthorizedOrRevoked);

        let current = node
            .publish(
                request(b"blob/rekey/current-operation"),
                &mut Cursor::new(bytes.clone()),
            )
            .expect("publish current-epoch source envelope");
        assert!(current.inserted);
        assert_eq!(current.id, first.id);
        let current_stats = node.store.blob_stats().expect("epoch-two stats");
        assert_eq!(current_stats.publications, 2);
        assert_eq!(current_stats.variants, 2);
        assert_eq!(current_stats.committed_chunks, 2);

        let mut output = Vec::new();
        let read = node
            .read_into(
                BlobReadRequest {
                    id: first.id,
                    topic: blob_topic(),
                    scope: blob_scope(),
                },
                &mut output,
            )
            .expect("read current-epoch Blob");
        assert_eq!(output, bytes);
        assert_eq!(read.publisher_counter, current.publisher_counter);
    }

    #[test]
    fn live_blob_claims_survive_intermediate_same_epoch_lineage_and_reopen() {
        let root = TestRoot::new("three-lineage-reopen");
        let mut services = persist_rekey_mission(&root);
        let bytes = payload(SELECTED_BLOB_CHUNK_SIZE as usize + 211);
        let first_request = request(b"blob/three-epoch/one");
        let mut middle_request = request(b"blob/three-epoch/two");
        // A same-epoch replacement needs a distinct immutable variant; priority
        // changes only envelope semantics and does not affect Blob identity, so
        // vary authenticated schema metadata as well as the semantic priority.
        middle_request.priority = Priority::Flash;
        middle_request.schema_id = b"schema/blob-v2".to_vec();
        let current_request = request(b"blob/three-epoch/three");

        let first = {
            let mut node =
                SelectedBlobNode::open_unprotected_reference(root.path(), root.mission_path())
                    .expect("open epoch-one Blob node");
            node.publish(first_request.clone(), &mut Cursor::new(bytes.clone()))
                .expect("publish epoch-one Blob")
        };
        let second_lineage = apply_scope_rekey(&root, &mut services, 1, 1, None);
        let middle = {
            let mut node =
                SelectedBlobNode::open_unprotected_reference(root.path(), root.mission_path())
                    .expect("open second-lineage Blob node");
            let retry = node
                .publish(first_request.clone(), &mut Cursor::new(bytes.clone()))
                .expect("claim-only first-lineage retry after replacement");
            assert!(!retry.inserted);
            node.publish(middle_request.clone(), &mut Cursor::new(bytes.clone()))
                .expect("publish second-lineage Blob")
        };
        let _third_lineage = apply_scope_rekey(&root, &mut services, 2, 2, Some(second_lineage));

        let current = {
            let mut node =
                SelectedBlobNode::open_unprotected_reference(root.path(), root.mission_path())
                    .expect("open third-lineage Blob node");
            let inventory = node
                .store
                .blob_inventory()
                .expect("third-lineage inventory");
            let middle_stored = inventory
                .into_iter()
                .find_map(|transfer_id| {
                    let stored = node
                        .store
                        .get_blob(transfer_id)
                        .expect("load third-lineage stored Blob")
                        .expect("inventory Blob must exist");
                    (stored.header.stamp.dot.counter == middle.publisher_counter).then_some(stored)
                })
                .expect("middle lineage stored Blob");
            let (middle_projection, middle_retention) = node
                .completed_projection(&middle_stored, "blob retry lineage test")
                .expect("middle lineage projection");
            assert_eq!(middle_stored.header.key_epoch, 1);
            assert_eq!(
                node.active_epoch(&blob_scope(), "blob retry lineage test")
                    .expect("third-lineage active epoch"),
                2
            );
            assert!(
                node.source_route_cache
                    .is_current_blob_source_projection(
                        &node.verifier,
                        &middle_projection,
                        middle_retention,
                    )
                    .expect("middle lineage exact cached claim"),
                "middle epoch-one lineage remains provider-current inside its old epoch"
            );
            for (request, expected) in [
                (first_request.clone(), &first),
                (middle_request.clone(), &middle),
            ] {
                let retry = node
                    .publish(request, &mut Cursor::new(bytes.clone()))
                    .expect("claim-only historical retry at third lineage");
                assert!(!retry.inserted);
                assert_eq!(retry.publisher_counter, expected.publisher_counter);
                assert_eq!(retry.acceptance_marker, expected.acceptance_marker);
            }
            let inactive = node
                .read_page(BlobReadPageRequest {
                    blob: BlobReadRequest {
                        id: first.id,
                        topic: blob_topic(),
                        scope: blob_scope(),
                    },
                    offset: 0,
                    max_bytes: 32,
                })
                .expect_err("noncurrent plan-selected source cannot disclose plaintext");
            assert_eq!(inactive.kind(), ApplicationErrorKind::UnauthorizedOrRevoked);
            let current = node
                .publish(current_request, &mut Cursor::new(bytes.clone()))
                .expect("publish third-lineage Blob");
            let page = node
                .read_page(BlobReadPageRequest {
                    blob: BlobReadRequest {
                        id: first.id,
                        topic: blob_topic(),
                        scope: blob_scope(),
                    },
                    offset: 29,
                    max_bytes: 97,
                })
                .expect("read current third-lineage page");
            assert_eq!(page.as_bytes(), &bytes[29..126]);
            current
        };

        let mut reopened =
            SelectedBlobNode::open_unprotected_reference(root.path(), root.mission_path())
                .expect("reopen third-lineage Blob node");
        for (request, expected) in [(first_request, first), (middle_request, middle)] {
            let retry = reopened
                .publish(request, &mut Cursor::new(bytes.clone()))
                .expect("reopened claim-only historical retry");
            assert!(!retry.inserted);
            assert_eq!(retry.publisher_counter, expected.publisher_counter);
            assert_eq!(retry.acceptance_marker, expected.acceptance_marker);
        }
        let page = reopened
            .read_page(BlobReadPageRequest {
                blob: BlobReadRequest {
                    id: current.id,
                    topic: blob_topic(),
                    scope: blob_scope(),
                },
                offset: SELECTED_BLOB_CHUNK_SIZE as u64 - 11,
                max_bytes: 64,
            })
            .expect("reopened third-lineage live page");
        let offset = SELECTED_BLOB_CHUNK_SIZE as usize - 11;
        assert_eq!(page.as_bytes(), &bytes[offset..offset + 64]);
    }

    #[test]
    fn blob_publisher_revocation_closes_retained_and_reopened_facades() {
        let root = TestRoot::new("revocation");
        let mut services = persist_rekey_mission(&root);
        let mut node =
            SelectedBlobNode::open_unprotected_reference(root.path(), root.mission_path())
                .expect("open pre-revocation Blob node");
        let published = node
            .publish(request(b"blob/revocation"), &mut Cursor::new(vec![1, 2, 3]))
            .expect("publish before revocation");
        let sealed = services
            .control_authority
            .seal_chained_revocation_control(services.selected_identity, 1, 1, None)
            .expect("seal selected publisher revocation");
        let verified = services
            .reader
            .verify_control(&sealed)
            .expect("verify selected publisher revocation");
        let outcome = node
            .store
            .ingest_verified_control(&verified, &sealed)
            .expect("commit selected publisher revocation");
        assert_eq!(outcome.activated().len(), 1);

        let error = node
            .read_into(
                BlobReadRequest {
                    id: published.id,
                    topic: blob_topic(),
                    scope: blob_scope(),
                },
                &mut Vec::new(),
            )
            .expect_err("retained facade must refresh durable revocation");
        assert_eq!(error.kind(), ApplicationErrorKind::UnauthorizedOrRevoked);
        drop(node);

        let error =
            match SelectedBlobNode::open_unprotected_reference(root.path(), root.mission_path()) {
                Ok(_) => panic!("revoked publisher facade reopened"),
                Err(error) => error,
            };
        assert_eq!(error.kind(), ApplicationErrorKind::UnauthorizedOrRevoked);
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn blob_terminal_zeroization_prevents_facade_reopen() {
        let root = TestRoot::new("terminal");
        drop(crate::NodeIdentity::load_or_create(root.path()).expect("create carrier identity"));
        let mut node = selected_node(&root);
        node.publish(request(b"blob/terminal"), &mut Cursor::new(vec![1, 2, 3]))
            .expect("publish before terminal zeroization");
        drop(node);

        let receipt =
            crate::zeroize_node(root.path(), &root.mission_path(), Duration::from_secs(2))
                .await
                .expect("zeroize stopped Blob state");
        assert!(receipt.mission_destroyed && receipt.identity_destroyed);
        let error =
            match SelectedBlobNode::open_unprotected_reference(root.path(), root.mission_path()) {
                Ok(_) => panic!("terminal Blob state reopened"),
                Err(error) => error,
            };
        assert_eq!(error.kind(), ApplicationErrorKind::StateUnavailable);
    }

    fn first_profile5_pack_file(depot: &Path) -> PathBuf {
        let pack_root = depot.join("stream-packs-v2");
        let mut packs = Vec::new();
        for publication in fs::read_dir(pack_root).expect("read native pack root") {
            let publication = publication.expect("native pack entry").path();
            if !publication.is_dir() {
                continue;
            }
            let pack = publication.join("segments.pack");
            if pack.is_file() {
                packs.push(pack);
            }
        }
        packs.sort();
        packs.into_iter().next().expect("committed native pack")
    }
    #[test]
    fn partial_read_cache_does_not_pin_expired_pack() {
        let root = TestRoot::new("review-partial-cache-pin");
        let mut node = selected_node(&root);
        node.custody_clock = NodeCustodyClock::injected([0xe1; 16], 1000, 0);
        let published = node
            .publish_with_options(
                request(b"review/cache-pin"),
                BlobPublishOptions::finite_ttl_ms(50).unwrap(),
                &mut Cursor::new(payload(4096)),
            )
            .unwrap();
        let page = node
            .read_page(BlobReadPageRequest {
                blob: BlobReadRequest {
                    id: published.id,
                    topic: blob_topic(),
                    scope: blob_scope(),
                },
                offset: 0,
                max_bytes: 1,
            })
            .unwrap();
        assert!(!page.complete);
        drop(page); // The application accepted one page and requests no more.
        node.custody_clock.set_injected_tick(1050).unwrap();
        let sample = node.custody_clock.sample().unwrap();
        let budget =
            aster_redb_store::BlobMaintenanceBudget::new(4096, 8, 32 * 1024 * 1024).unwrap();
        for turn in 0..128 {
            node.store
                .run_blob_maintenance_turn_with_sample(budget, (turn == 0).then_some(sample))
                .unwrap();
            node.store.run_blob_capacity_gc(budget, None).unwrap();
        }
        let pinned = node.capacity_status().unwrap().variants;
        node.finish_read_cache();
        for _ in 0..128 {
            node.store.run_blob_maintenance_turn(budget).unwrap();
            node.store.run_blob_capacity_gc(budget, None).unwrap();
        }
        let released = node.capacity_status().unwrap().variants;
        println!(
            "after expiry: cached={pinned} variants, after clearing cache={released} variants"
        );
        assert_eq!((pinned, released), (0, 0));
    }

    #[test]
    fn publication_status_authorizes_before_identity_lookup() {
        for phase in ["pending", "available", "expired"] {
            let root = TestRoot::new(&format!("review-status-visibility-{phase}"));
            let mut node = selected_node(&root);
            node.custody_clock = NodeCustodyClock::injected([0xe2; 16], 1000, 0);
            let publication = request(b"review/status-visible");
            let options = BlobPublishOptions::finite_ttl_ms(50).unwrap();
            if phase != "pending" {
                node.publish_with_options(
                    publication.clone(),
                    options,
                    &mut Cursor::new(payload(17)),
                )
                .unwrap();
            }
            let opened = node
                .open_publish_stream_inner(BlobPublishStreamRequest {
                    publication,
                    options,
                    total_len: 17,
                })
                .unwrap();
            if phase == "expired" {
                node.custody_clock.set_injected_tick(1050).unwrap();
            }
            let wrong_topic = Topic::new("ungranted-topic").unwrap();
            for id in [opened.token, [0x92; 32]] {
                let status = node.inspect_publication(BlobPublicationInspectionRequest {
                    publication_id: BlobStreamPublicationId::from_bytes(id).unwrap(),
                    topic: wrong_topic.clone(),
                    scope: blob_scope(),
                });
                assert_eq!(
                    status.unwrap_err().kind(),
                    ApplicationErrorKind::RequestRejected,
                    "{phase}"
                );
            }
        }
    }

    #[test]
    fn publication_status_hides_existence_across_authorized_selectors() {
        let root = TestRoot::new("status-authorized-selector");
        let other_topic = Topic::new("ops.other").unwrap();
        let access = ProvisioningAccess::member(
            blob_scope(),
            vec![1],
            vec![blob_topic(), other_topic.clone()],
        )
        .unwrap();
        let mut provisioner = ReferenceProvisioner::from_seed([0xf1; 32]).unwrap();
        let bytes = provisioner
            .issue_node(1, &[access])
            .unwrap()
            .to_bytes()
            .unwrap();
        drop(UnprotectedReferenceMission::persist(root.mission_path(), bytes).unwrap());
        let mut node = selected_node(&root);
        let published = node
            .publish(
                request(b"status-authorized-selector"),
                &mut Cursor::new(payload(17)),
            )
            .unwrap();

        let absent = node
            .inspect_publication(BlobPublicationInspectionRequest {
                publication_id: BlobStreamPublicationId::from_bytes([0x92; 32]).unwrap(),
                topic: other_topic.clone(),
                scope: blob_scope(),
            })
            .unwrap();
        assert_eq!(absent.phase, BlobPublicationPhase::Missing);
        let hidden = node
            .inspect_publication(BlobPublicationInspectionRequest {
                publication_id: published.publication_id.unwrap(),
                topic: other_topic,
                scope: blob_scope(),
            })
            .expect("selector-invisible publication is indistinguishable from absent");
        assert_eq!(hidden.phase, BlobPublicationPhase::Missing);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn end_to_end_review_abandoned_finite_upload_expires_before_new_admission() {
        let root = TestRoot::new("review-actor-expired-abandoned-capacity");
        persist_member_mission(&root);
        let options = SelectedBlobOptions {
            depot_limits: BlobDepotLimits::new(1_000_000, 4, 1).unwrap(),
        };
        let mut node = SelectedBlobNode::open_unprotected_reference_with_options(
            root.path(),
            root.mission_path(),
            options,
        )
        .unwrap();
        node.custody_clock = NodeCustodyClock::injected([0xec; 16], 10, 0);
        let publisher = node.identity();
        let mut first = request(b"review/actor-expired-abandoned-capacity");
        first.priority = Priority::Routine;
        let owner = BlobOperationOwner::new(
            publisher,
            BlobOperationKey::new(first.operation_key.clone()).unwrap(),
        );
        let (handle, worker) = live_stream_test_actor(node);
        let mut stream = handle
            .open_publish_stream(BlobPublishStreamRequest {
                publication: first,
                options: BlobPublishOptions::finite_ttl_ms(90_000).unwrap(),
                total_len: 4096,
            })
            .await
            .unwrap();
        let progress = stream.write(0, Zeroizing::new(payload(17))).await.unwrap();
        assert_eq!(progress.accepted_offset, 17);
        assert_eq!(progress.durable_offset, 0);
        drop(stream);
        let before_close = handle.capacity_status().await.unwrap();
        println!(
            "before close, capacity status committed variants={}",
            before_close.variants
        );
        drop(handle);
        let node = worker.await.unwrap();
        assert!(
            node.publish_streams.is_empty(),
            "real handle drop released writer and map workers"
        );
        let (reserved, _) = node.store.resume_blob_upload(&owner).unwrap().unwrap();
        assert_eq!(
            reserved.reserved_variants(),
            1,
            "abandoned durable upload retains one admission reservation"
        );
        drop(node);

        let mut reopened = SelectedBlobNode::open_unprotected_reference_with_options(
            root.path(),
            root.mission_path(),
            options,
        )
        .unwrap();
        reopened.custody_clock = NodeCustodyClock::injected([0xec; 16], 100_100, 0);
        let expired = reopened.custody_clock.sample().unwrap();
        let budget = BlobMaintenanceBudget::new(4096, 1, 32 * 1024 * 1024).unwrap();
        for _ in 0..128 {
            reopened
                .store
                .run_blob_maintenance_turn_with_sample(budget, Some(expired))
                .unwrap();
            reopened
                .store
                .run_blob_capacity_gc(budget, Some(expired))
                .unwrap();
        }
        let mut replacement = request(b"review/actor-after-expired-abandoned");
        replacement.priority = Priority::Flash;
        let replacement_request = BlobPublishStreamRequest {
            publication: replacement,
            options: BlobPublishOptions::durable(),
            total_len: 53,
        };
        let (handle, worker) = live_stream_test_actor(reopened);
        let mut stream = handle
            .open_publish_stream(replacement_request)
            .await
            .expect("expired abandoned upload automatically releases capacity");
        stream.write(0, Zeroizing::new(payload(53))).await.unwrap();
        let published = stream.finish().await.unwrap();
        let page = handle
            .read_page(BlobReadPageRequest {
                blob: BlobReadRequest {
                    id: published.id,
                    topic: blob_topic(),
                    scope: blob_scope(),
                },
                offset: 0,
                max_bytes: 53,
            })
            .await
            .unwrap();
        assert_eq!(page.as_bytes(), payload(53).as_slice());
        assert!(page.complete);
        drop(handle);
        drop(worker.await.unwrap());
    }

    #[test]
    fn stream_promotion_integrity_stops_subsequent_live_commands() {
        let root = TestRoot::new("review-stream-promotion-fatal-containment");
        let mut node = selected_node(&root);
        let (token, _) = prepare_ready_stream(
            &mut node,
            b"review/stream-promotion-fatal-containment",
            &payload(53),
        );
        let session = Arc::new(BlobPublishStreamSession::new(Arc::clone(
            &node.publish_stream_cleanup,
        )));
        node.live_publish_sessions
            .insert(token, Arc::downgrade(&session));
        let cache = Arc::clone(&node.source_route_cache);
        assert!(std::thread::spawn(move || {
            let _lifecycle = cache.lock_blob_lifecycle().unwrap();
            panic!("deliberately poison live Blob lifecycle lock, same boundary as existing one-shot test");
        }).join().is_err());
        let admission = AtomicBool::new(true);
        let (response, received) = oneshot::channel();
        node.execute_live(
            SelectedBlobCommand::FinishPublishStream {
                token,
                session,
                response,
            },
            &admission,
        )
        .expect("stream scheduling does not observe worker error");
        let BlobPublishFinalization::Scheduled(completion) =
            received.blocking_recv().unwrap().unwrap()
        else {
            panic!("fresh stream must schedule");
        };
        let error = completion.blocking_recv().unwrap().unwrap_err();
        assert_eq!(error.kind(), ApplicationErrorKind::Integrity);
        let (response, received) = oneshot::channel();
        let fatal = node
            .execute_live(SelectedBlobCommand::CapacityStatus { response }, &admission)
            .expect_err("promotion integrity must reach the actor before its next command");
        assert!(matches!(fatal, NodeError::FatalBlobCoherence(_)));
        assert!(received.blocking_recv().is_err());
    }

    #[cfg(unix)]
    pub(crate) struct PromotionFailureFixture {
        _release_on_drop: ReleasePromotionGate,
        _root: TestRoot,
        pub(crate) node: SelectedBlobNode,
        pub(crate) custody_clock: NodeCustodyClock,
        pub(crate) finish: SelectedBlobCommand,
        pub(crate) scheduled: oneshot::Receiver<Result<BlobPublishFinalization, ApplicationError>>,
        pub(crate) started: std::sync::mpsc::Receiver<()>,
        pub(crate) finished: std::sync::mpsc::Receiver<()>,
        pub(crate) release: Arc<(std::sync::Mutex<bool>, std::sync::Condvar)>,
        pub(crate) waits: mpsc::UnboundedReceiver<BlobLiveWaitObservation>,
    }

    #[cfg(unix)]
    pub(crate) fn promotion_failure_fixture(kind: ApplicationErrorKind) -> PromotionFailureFixture {
        let root = TestRoot::new("promotion-worker-failure");
        let mut node = selected_node(&root);
        node.custody_clock = NodeCustodyClock::injected([0xee; 16], 100, 0);
        let custody_clock = node.custody_clock.clone();
        let opened = node
            .open_publish_stream_inner(BlobPublishStreamRequest {
                publication: request(b"promotion/worker-failure"),
                options: if kind == ApplicationErrorKind::ExpiredOrRetired {
                    BlobPublishOptions::finite_ttl_ms(50).unwrap()
                } else {
                    BlobPublishOptions::durable()
                },
                total_len: 53,
            })
            .unwrap();
        let token = opened.token;
        node.append_publish_stream_inner(token, 0, Zeroizing::new(payload(53)))
            .unwrap();
        let session = Arc::new(BlobPublishStreamSession::new(Arc::clone(
            &node.publish_stream_cleanup,
        )));
        node.live_publish_sessions
            .insert(token, Arc::downgrade(&session));
        if kind == ApplicationErrorKind::Integrity {
            let cache = Arc::clone(&node.source_route_cache);
            assert!(
                std::thread::spawn(move || {
                    let _lifecycle = cache.lock_blob_lifecycle().unwrap();
                    panic!("deliberately poison live Blob lifecycle lock");
                })
                .join()
                .is_err()
            );
        }
        let (started_tx, started) = std::sync::mpsc::sync_channel(1);
        let (finished_tx, finished) = std::sync::mpsc::sync_channel(1);
        let release = Arc::new((std::sync::Mutex::new(false), std::sync::Condvar::new()));
        node.set_stream_pack_promotion_gate_for_test(started_tx, finished_tx, release.clone());
        if kind == ApplicationErrorKind::StateUnavailable {
            node.panic_stream_pack_promotions_for_test(1);
        }
        let (observer, waits) = mpsc::unbounded_channel();
        node.live_command_wait_observer = Some(observer);
        let (response, scheduled) = oneshot::channel();
        PromotionFailureFixture {
            _release_on_drop: ReleasePromotionGate(release.clone()),
            _root: root,
            node,
            custody_clock,
            finish: SelectedBlobCommand::FinishPublishStream {
                token,
                session,
                response,
            },
            scheduled,
            started,
            finished,
            release,
            waits,
        }
    }
}
