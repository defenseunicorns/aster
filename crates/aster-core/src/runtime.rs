//! Internal authenticated synchronization driver.
//!
//! This is deliberately not an application API.  It is the composition root
//! for four-flight mutual authentication, replay-protected session records,
//! deterministic sync messages, bounded fragmentation, and a pluggable Link.
//! Before `ReferenceAuthenticatedSession` exists, received bytes are examined
//! only as the expected handshake flight; a rejected flight leaves the exact
//! transition state intact, and wire DATA and inventory messages are never
//! decoded or passed to the backend.

use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::fmt;
use std::io;
use std::time::{Duration, Instant};

use sha2::{Digest, Sha256};

use crate::blob::{
    AuthenticatedBlobRoute, BlobError, BlobTransferStore, inspect_blob_transfer_object,
};
use crate::crypto::{
    ProvisioningBundle, ReferenceAuthenticatedSession, ReferenceSessionAwaitingFinished,
    ReferenceSessionInitiator, ReferenceSessionResponder, ReferenceSessionResponderPending,
};
use crate::engine::{EngineError, EnvelopeSealer, ForwardedIngest, Node};
use crate::fragment::{self, Fragment, FragmentError, Reassembler};
use crate::inventory::SparseInventory;
use crate::link::Link;
use crate::model::{ItemId, NodeId, Priority};
use crate::scheduler::Scheduler;
use crate::store::{ApplyOutcome, ChunkRange, MAX_COMPOSITE_INVENTORY_OBJECTS, RecordStore};
use crate::sync::{InterestFilter, InventoryPurpose, SyncAction, SyncError, SyncEvent, SyncState};
use crate::wire::{
    self, ByteRange, Data, EnvelopeId, Limits, Message, ObjectId, ObjectKind, WantItem, WireError,
};

mod reference_semantic;
pub use reference_semantic::{
    AppliedAuthorizationControl, ReferenceSemanticBlobQuotaSnapshot,
    ReferenceSemanticRuntimeAuthority, ReferenceSemanticRuntimeBackend,
    ReferenceSemanticRuntimeSession, SignedAuthorizationControl,
};

/// Engine/storage boundary used only after session authentication.
///
/// An engine implementation must apply topic, scope, minimum-priority, scope
/// key, revocation, and peer policy in `select_authorized_inventory`.  Stable
/// source-sealed bytes are chunked; peer-specific forwarding metadata remains
/// separate and is authenticated again by `ingest_authenticated`.
pub trait RuntimeBackend {
    type Error: fmt::Display;

    /// Monotonic process-wide authorization epoch.
    ///
    /// Backends without mutable authorization state retain generation zero.
    /// Shared authorities override this so a driver can fail closed when
    /// revocation, rekey, or other control state changes after admission.
    fn authorization_generation(&mut self) -> Result<u64, Self::Error> {
        Ok(0)
    }

    fn authorize_adjacency(&mut self, _authenticated_peer: NodeId) -> Result<(), Self::Error> {
        Ok(())
    }

    /// Exact storage-authoritative ranges for restart recovery. Entries are
    /// peer-neutral and bounded by `limit`.
    fn durable_progress(
        &mut self,
        _limit: usize,
    ) -> Result<Vec<RuntimeTransferProgress>, Self::Error> {
        Ok(Vec::new())
    }

    /// Selected-version restart seam. The default removes typed kinds outside
    /// the negotiated registry; semantic backends additionally suppress
    /// version-1-shaped dependencies that belong only to an extended object.
    fn durable_progress_for_semantic_version(
        &mut self,
        limit: usize,
        semantic_version: u16,
    ) -> Result<Vec<RuntimeTransferProgress>, Self::Error> {
        self.durable_progress(limit).map(|progress| {
            progress
                .into_iter()
                .filter(|entry| {
                    entry
                        .object_id
                        .kind()
                        .is_allowed_in_semantic_version(semantic_version)
                })
                .collect()
        })
    }

    /// Exact dependencies named by complete objects which are durably pending
    /// authentication. Implementations return only dependency identities, never
    /// the pending object's bytes or an acceptance claim.
    fn durable_dependencies(&mut self, _limit: usize) -> Result<Vec<ObjectId>, Self::Error> {
        Ok(Vec::new())
    }

    fn durable_dependencies_for_semantic_version(
        &mut self,
        limit: usize,
        semantic_version: u16,
    ) -> Result<Vec<ObjectId>, Self::Error> {
        self.durable_dependencies(limit).map(|dependencies| {
            dependencies
                .into_iter()
                .filter(|object_id| {
                    object_id
                        .kind()
                        .is_allowed_in_semantic_version(semantic_version)
                })
                .collect()
        })
    }

    /// Storage-authoritative bounded point lookup for an exact object which
    /// was durably moved out of transfer staging as `Deferred` or
    /// `Quarantined`. A positive result permits only an idempotent complete
    /// transport receipt; it must not imply inventory membership, semantic
    /// acceptance, or application visibility. Implementations return the
    /// immutable total length only when the origin semantic version matches.
    /// This method is required so any backend which can return `Deferred` or
    /// `Quarantined` must explicitly preserve duplicate-DATA liveness.
    fn durably_disposed_object_len(
        &mut self,
        object_id: ObjectId,
        semantic_version: u16,
    ) -> Result<Option<u64>, Self::Error>;

    fn select_authorized_inventory(
        &mut self,
        authenticated_peer: NodeId,
        peer_route_commitments: &[[u8; 32]],
        filter: &InterestFilter,
        purpose: InventoryPurpose,
    ) -> Result<SparseInventory, Self::Error>;

    /// Version-aware inventory seam. Existing backends inherit safe typed-kind
    /// filtering; semantic-v2 backends override this to select format-2 versus
    /// format-3 source representations before the inventory root is computed.
    fn select_authorized_inventory_for_semantic_version(
        &mut self,
        authenticated_peer: NodeId,
        peer_route_commitments: &[[u8; 32]],
        filter: &InterestFilter,
        purpose: InventoryPurpose,
        semantic_version: u16,
    ) -> Result<SparseInventory, Self::Error> {
        self.select_authorized_inventory(
            authenticated_peer,
            peer_route_commitments,
            filter,
            purpose,
        )
        .map(|inventory| inventory.filtered_for_semantic_version(semantic_version))
    }

    /// Durably writes one exact range. Rewriting the same authenticated bytes
    /// at the same extent must be idempotent.
    fn store_object_chunk(
        &mut self,
        object_id: ObjectId,
        total_len: u64,
        offset: u64,
        bytes: &[u8],
    ) -> Result<(), Self::Error>;

    /// Version-aware staging seam. Durable implementations override this so
    /// restart recovery can prove which representation registry first wrote
    /// an exact partial object. The legacy default preserves test backends
    /// that do not retain progress across sessions.
    fn store_object_chunk_for_semantic_version(
        &mut self,
        object_id: ObjectId,
        total_len: u64,
        offset: u64,
        bytes: &[u8],
        _semantic_version: u16,
    ) -> Result<(), Self::Error> {
        self.store_object_chunk(object_id, total_len, offset, bytes)
    }

    /// Reads complete staged bytes without consuming or otherwise mutating
    /// staging; transient failures leave the same completion retryable.
    fn complete_object_bytes(
        &mut self,
        object_id: ObjectId,
        total_len: u64,
    ) -> Result<Vec<u8>, Self::Error>;

    /// Atomically discards only this typed object's staging after terminal
    /// validation failure. The default supports non-durable test backends.
    fn abort_object(&mut self, _object_id: ObjectId) -> Result<(), Self::Error> {
        Ok(())
    }

    /// Verifies and atomically commits one complete typed object. An error does
    /// not commit the submitted object. A backend may nevertheless durably
    /// activate an independently staged authorization prefix while rejecting
    /// that input; such a side effect must be exposed by a changed
    /// [`Self::authorization_generation`]. A successful disposition is durable
    /// and irreversible.
    /// Source
    /// envelopes must authenticate the hop wrapper against
    /// `authenticated_peer`; Blob chunks must verify their source-authenticated
    /// route proof and, when available, the exact encrypted manifest record.
    fn commit_authenticated_object(
        &mut self,
        authenticated_peer: NodeId,
        exchange_id: u64,
        object_id: ObjectId,
        bytes: Vec<u8>,
        forwarding: Vec<u8>,
    ) -> Result<Option<ItemId>, Self::Error>;

    /// Dependency-aware completion seam. The submitted-object error contract
    /// and authorization-generation exception are identical to
    /// [`Self::commit_authenticated_object`]. A deferred result means the backend
    /// has crash-atomically moved exact bytes out of transfer staging and has
    /// not inserted the object into semantic state or authorized inventory.
    fn commit_authenticated_object_with_dependencies(
        &mut self,
        authenticated_peer: NodeId,
        exchange_id: u64,
        _semantic_version: u16,
        object_id: ObjectId,
        bytes: Vec<u8>,
        forwarding: Vec<u8>,
    ) -> Result<RuntimeCommit, Self::Error> {
        self.commit_authenticated_object(
            authenticated_peer,
            exchange_id,
            object_id,
            bytes,
            forwarding,
        )
        .map(|item_id| RuntimeCommit::Committed {
            item_id,
            promoted: Vec::new(),
        })
    }

    /// Distinguishes terminal identity/authentication failures from transient
    /// storage failures. Only terminal failures authorize staging destruction.
    fn is_terminal_commit_error(&self, _error: &Self::Error) -> bool {
        false
    }

    /// Returns the source-authenticated precedence for retry scheduling.
    /// Backends without locally inspectable metadata conservatively use
    /// ROUTINE; protocol-control messages still inherit the requested minimum.
    fn object_priority(&mut self, _object_id: ObjectId) -> Result<Priority, Self::Error> {
        Ok(Priority::Routine)
    }

    /// Produces bounded DATA messages for one request.  DATA payload ranges
    /// must refer only to stable source-sealed bytes; forwarding is separate.
    fn data_for_want(
        &mut self,
        authenticated_peer: NodeId,
        peer_route_commitments: &[[u8; 32]],
        exchange_id: u64,
        want: &WantItem,
    ) -> Result<Vec<Data>, Self::Error>;

    /// Version-aware serve seam used to prevent a semantic-v1 adjacency from
    /// receiving a format-3 source representation even though both use typed
    /// ObjectKind 1.
    fn data_for_want_for_semantic_version(
        &mut self,
        authenticated_peer: NodeId,
        peer_route_commitments: &[[u8; 32]],
        exchange_id: u64,
        semantic_version: u16,
        want: &WantItem,
    ) -> Result<Vec<Data>, Self::Error> {
        let _ = semantic_version;
        self.data_for_want(
            authenticated_peer,
            peer_route_commitments,
            exchange_id,
            want,
        )
    }

    /// Applies an authenticated peer receipt to durable representation-specific
    /// outbox state. Applying the same receipt more than once must be
    /// idempotent. Legacy backends have no durable receipt index and safely
    /// retain the historical no-op behavior.
    fn acknowledge_receipt(
        &mut self,
        _authenticated_peer: NodeId,
        _semantic_version: u16,
        _receipt: &wire::Receipt,
    ) -> Result<(), Self::Error> {
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RuntimeTransferProgress {
    pub object_id: ObjectId,
    /// Semantic protocol selected when this exact transfer was first staged.
    /// `None` is fail-closed durable provenance for migrated rows.
    pub origin_semantic_version: Option<u16>,
    pub total_len: u64,
    pub received: Vec<ByteRange>,
}

/// Result of kind-specific authentication after a complete ranged transfer.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum RuntimeCommit {
    /// The primary object is accepted. `promoted` contains previously deferred
    /// exact objects which became fully authenticated in the same backend step.
    Committed {
        item_id: Option<ItemId>,
        promoted: Vec<ObjectId>,
    },
    /// Exact bytes are durable but have no inventory or application visibility.
    Deferred { dependencies: Vec<ObjectId> },
    /// Exact bytes are durable in a semantics-free quarantine and have no
    /// inventory or application visibility. A later authenticated dependency
    /// may promote them without retaining unauthenticated transfer staging.
    Quarantined,
}

const MAX_DATA_PAYLOAD_BYTES: usize = 64 * 1024;
const MAX_DATA_MESSAGES_PER_WANT: usize = 16;
const MAX_IN_FLIGHT_LOGICAL_FRAMES: usize = 16;
const MAX_REASSEMBLY_BYTES: usize = 4 * 1024 * 1024;
const PARTIAL_TRANSFER_IDLE_TTL: Duration = Duration::from_secs(10 * 60);
const MAX_RECEIVED_FRAMES_PER_PUMP: usize = 4_096;
const MAX_UNAUTHENTICATED_FAILURES_PER_PUMP: usize = 64;
const MAX_PENDING_RETRIES: usize = 128;
const MAX_PENDING_OUTBOX: usize = 128;
/// Exact cap over retained retry messages and transport epochs, deferred WANT
/// epochs, encoded one-shot outbox records, and the retained handshake flight.
/// Normal work leaves a fixed reserve so a saturated durable WANT can still
/// retain one bounded repair epoch.
const MAX_PENDING_LOGICAL_BYTES: usize = 16 * 1024 * 1024;
const DEFERRED_WANT_EPOCH_RESERVE: usize = 2 * 1024 * 1024;
const MAX_RETRY_SENDS_PER_PUMP: usize = 128;
const MAX_COMPLETED_TRANSFERS: usize = 1_024;
const MAX_WIRE_MESSAGE_BYTES: usize = 1_048_576;
const MAX_WIRE_DEPTH: usize = 16;
const MAX_WIRE_COLLECTION_ITEMS: usize = 4_096;
const MAX_WIRE_BYTE_STRING: usize = 1_048_576;
const MAX_WIRE_TEXT_STRING: usize = 4_096;
const MIN_RECORD_REPAIR_ROUNDS: u16 = 8;
const MAX_SUCCESSFUL_RECORD_REPAIR_ROUNDS: u16 = 8;
const SECURE_REPLAY_WINDOW_RECORDS: u64 = u128::BITS as u64;

/// Per-contact runtime bounds.
///
/// Defaults preserve the limits that predated this configuration surface. The
/// same values are hard maxima: callers may tighten a contact reservation but
/// cannot silently expand the audited resource envelope. `max_reassembly_bytes`
/// and `max_pending_logical_bytes` are the retained inbound and outbound
/// payload-byte reservations respectively; the count fields separately bound
/// retained metadata and work performed by one pump.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RuntimeLimits {
    pub max_in_flight_logical_frames: usize,
    pub max_reassembly_bytes: usize,
    pub partial_transfer_idle_ttl: Duration,
    pub max_received_frames_per_pump: usize,
    pub max_unauthenticated_failures_per_pump: usize,
    pub max_pending_retries: usize,
    pub max_pending_outbox: usize,
    pub max_pending_logical_bytes: usize,
    pub deferred_want_epoch_reserve: usize,
    pub max_retry_sends_per_pump: usize,
    pub max_completed_transfers: usize,
    pub wire: Limits,
}

impl Default for RuntimeLimits {
    fn default() -> Self {
        Self {
            max_in_flight_logical_frames: MAX_IN_FLIGHT_LOGICAL_FRAMES,
            max_reassembly_bytes: MAX_REASSEMBLY_BYTES,
            partial_transfer_idle_ttl: PARTIAL_TRANSFER_IDLE_TTL,
            max_received_frames_per_pump: MAX_RECEIVED_FRAMES_PER_PUMP,
            max_unauthenticated_failures_per_pump: MAX_UNAUTHENTICATED_FAILURES_PER_PUMP,
            max_pending_retries: MAX_PENDING_RETRIES,
            max_pending_outbox: MAX_PENDING_OUTBOX,
            max_pending_logical_bytes: MAX_PENDING_LOGICAL_BYTES,
            deferred_want_epoch_reserve: DEFERRED_WANT_EPOCH_RESERVE,
            max_retry_sends_per_pump: MAX_RETRY_SENDS_PER_PUMP,
            max_completed_transfers: MAX_COMPLETED_TRANSFERS,
            wire: Limits::default(),
        }
    }
}

impl RuntimeLimits {
    /// Validates non-zero operational bounds, cross-field relationships, and
    /// the audited hard maxima.
    pub fn validate(&self) -> Result<(), RuntimeLimitsError> {
        for (field, value, maximum) in [
            (
                "max_in_flight_logical_frames",
                self.max_in_flight_logical_frames,
                MAX_IN_FLIGHT_LOGICAL_FRAMES,
            ),
            (
                "max_reassembly_bytes",
                self.max_reassembly_bytes,
                MAX_REASSEMBLY_BYTES,
            ),
            (
                "max_received_frames_per_pump",
                self.max_received_frames_per_pump,
                MAX_RECEIVED_FRAMES_PER_PUMP,
            ),
            (
                "max_unauthenticated_failures_per_pump",
                self.max_unauthenticated_failures_per_pump,
                MAX_UNAUTHENTICATED_FAILURES_PER_PUMP,
            ),
            (
                "max_pending_retries",
                self.max_pending_retries,
                MAX_PENDING_RETRIES,
            ),
            (
                "max_pending_outbox",
                self.max_pending_outbox,
                MAX_PENDING_OUTBOX,
            ),
            (
                "max_pending_logical_bytes",
                self.max_pending_logical_bytes,
                MAX_PENDING_LOGICAL_BYTES,
            ),
            (
                "max_retry_sends_per_pump",
                self.max_retry_sends_per_pump,
                MAX_RETRY_SENDS_PER_PUMP,
            ),
            (
                "max_completed_transfers",
                self.max_completed_transfers,
                MAX_COMPLETED_TRANSFERS,
            ),
            (
                "wire.max_message_bytes",
                self.wire.max_message_bytes,
                MAX_WIRE_MESSAGE_BYTES,
            ),
            ("wire.max_depth", self.wire.max_depth, MAX_WIRE_DEPTH),
            (
                "wire.max_collection_items",
                self.wire.max_collection_items,
                MAX_WIRE_COLLECTION_ITEMS,
            ),
            (
                "wire.max_byte_string",
                self.wire.max_byte_string,
                MAX_WIRE_BYTE_STRING,
            ),
            (
                "wire.max_text_string",
                self.wire.max_text_string,
                MAX_WIRE_TEXT_STRING,
            ),
        ] {
            if value == 0 {
                return Err(RuntimeLimitsError::Zero(field));
            }
            if value > maximum {
                return Err(RuntimeLimitsError::ExceedsHardMaximum(field));
            }
        }
        if self.partial_transfer_idle_ttl.is_zero() {
            return Err(RuntimeLimitsError::Zero("partial_transfer_idle_ttl"));
        }
        if self.partial_transfer_idle_ttl > PARTIAL_TRANSFER_IDLE_TTL {
            return Err(RuntimeLimitsError::ExceedsHardMaximum(
                "partial_transfer_idle_ttl",
            ));
        }
        if self.deferred_want_epoch_reserve > DEFERRED_WANT_EPOCH_RESERVE {
            return Err(RuntimeLimitsError::ExceedsHardMaximum(
                "deferred_want_epoch_reserve",
            ));
        }
        if self.deferred_want_epoch_reserve > self.max_pending_logical_bytes {
            return Err(RuntimeLimitsError::InvalidRelationship(
                "deferred_want_epoch_reserve exceeds max_pending_logical_bytes",
            ));
        }
        if self.wire.max_byte_string > self.wire.max_message_bytes {
            return Err(RuntimeLimitsError::InvalidRelationship(
                "wire.max_byte_string exceeds wire.max_message_bytes",
            ));
        }
        if self.wire.max_text_string > self.wire.max_message_bytes {
            return Err(RuntimeLimitsError::InvalidRelationship(
                "wire.max_text_string exceeds wire.max_message_bytes",
            ));
        }
        Ok(())
    }

    /// Maximum retained partial inbound payload bytes for one contact.
    pub const fn retained_inbound_payload_bytes(&self) -> usize {
        self.max_reassembly_bytes
    }

    /// Maximum retained queued outbound payload bytes for one contact.
    pub const fn retained_outbound_payload_bytes(&self) -> usize {
        self.max_pending_logical_bytes
    }
}

/// Invalid per-contact resource configuration.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RuntimeLimitsError {
    Zero(&'static str),
    ExceedsHardMaximum(&'static str),
    InvalidRelationship(&'static str),
}

impl fmt::Display for RuntimeLimitsError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Zero(field) => write!(formatter, "runtime limit {field} must be non-zero"),
            Self::ExceedsHardMaximum(field) => {
                write!(formatter, "runtime limit {field} exceeds its hard maximum")
            }
            Self::InvalidRelationship(message) => formatter.write_str(message),
        }
    }
}

impl std::error::Error for RuntimeLimitsError {}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct StartRequest {
    pub exchange_id: u64,
    pub topics: Vec<String>,
    pub scopes: Vec<String>,
    pub min_priority: u8,
}

#[derive(Debug)]
pub enum RuntimeError {
    Io(io::Error),
    Fragment(FragmentError),
    Wire(WireError),
    Sync(SyncError),
    Session(String),
    Backend(String),
    BackendContract(&'static str),
    InvalidLimits(RuntimeLimitsError),
    AuthorizationGenerationChanged,
    EnvelopeLengthMismatch,
    EnvelopeHashMismatch,
    TransportPeerChanged,
    TransferIdReuse,
    Backpressure,
    TransferIdExhausted,
    FailedState,
}

/// The authorization-generation comparison performed by a runtime before it
/// admits authenticated state or flushes authenticated Aster bytes.
///
/// Embeddings may drain this observation for structured lifecycle evidence;
/// it does not replace the fail-closed check itself.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RuntimeAuthorizationGenerationCheck {
    Current {
        generation: u64,
    },
    Changed {
        expected_generation: u64,
        observed_generation: u64,
    },
    Unavailable {
        expected_generation: Option<u64>,
    },
}

/// Cumulative authorization-generation comparisons performed by one runtime.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct RuntimeAuthorizationGenerationCounters {
    pub checks: u64,
    pub mismatches: u64,
    pub unavailable: u64,
}

impl fmt::Display for RuntimeError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(error) => write!(formatter, "link I/O failed: {error}"),
            Self::Fragment(error) => write!(formatter, "fragment failure: {error}"),
            Self::Wire(error) => write!(formatter, "wire failure: {error}"),
            Self::Sync(error) => write!(formatter, "sync failure: {error}"),
            Self::Session(error) => write!(formatter, "session authentication failed: {error}"),
            Self::Backend(error) => write!(formatter, "runtime backend failed: {error}"),
            Self::BackendContract(error) => write!(formatter, "backend contract failed: {error}"),
            Self::InvalidLimits(error) => write!(formatter, "invalid runtime limits: {error}"),
            Self::AuthorizationGenerationChanged => {
                formatter.write_str("runtime authorization changed after adjacency admission")
            }
            Self::EnvelopeLengthMismatch => formatter.write_str("sealed envelope length mismatch"),
            Self::EnvelopeHashMismatch => formatter.write_str("sealed envelope hash mismatch"),
            Self::TransportPeerChanged => {
                formatter.write_str("transport route changed within one adjacency")
            }
            Self::TransferIdReuse => {
                formatter.write_str("transport transfer identifier was reused with different bytes")
            }
            Self::Backpressure => formatter.write_str("bounded outbound logical queue is full"),
            Self::TransferIdExhausted => formatter.write_str("fragment transfer IDs exhausted"),
            Self::FailedState => formatter.write_str("runtime is in a failed state"),
        }
    }
}

impl std::error::Error for RuntimeError {}

impl From<io::Error> for RuntimeError {
    fn from(value: io::Error) -> Self {
        Self::Io(value)
    }
}

impl From<FragmentError> for RuntimeError {
    fn from(value: FragmentError) -> Self {
        Self::Fragment(value)
    }
}

impl From<WireError> for RuntimeError {
    fn from(value: WireError) -> Self {
        Self::Wire(value)
    }
}

impl From<SyncError> for RuntimeError {
    fn from(value: SyncError) -> Self {
        Self::Sync(value)
    }
}

enum SessionPhase {
    Initiator(ReferenceSessionInitiator),
    InitiatorAwaitingFinished(ReferenceSessionAwaitingFinished),
    Responder(ReferenceSessionResponder),
    ResponderPending(ReferenceSessionResponderPending),
    Authenticated(ReferenceAuthenticatedSession),
    Failed,
}

fn semantic_versions_through(semantic_ceiling: u16) -> Result<Vec<u16>, RuntimeError> {
    if semantic_ceiling == 0 || semantic_ceiling > crate::HIGHEST_SUPPORTED_SEMANTIC_VERSION {
        return Err(RuntimeError::Session(
            "semantic capability ceiling is unsupported".into(),
        ));
    }
    Ok((1..=semantic_ceiling).rev().collect())
}

#[derive(Clone)]
struct Outbound {
    plaintext: Vec<u8>,
    priority: Priority,
    attempts: u16,
    due: Instant,
    sequence: u64,
    semantic_version: u16,
    retained_bytes: usize,
    transport_epoch: Option<RetryTransportEpoch>,
}

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
enum RetryKey {
    Interest(u64),
    Summary(u64, u64),
    Probe(u64, u64, u8, Vec<u8>),
    Node(u64, u64, u8, Vec<u8>),
    Want(u64, ObjectId),
    Data(u64, ObjectId, u64, u64, u64),
}

#[derive(Clone)]
struct RetryEntry {
    message: Message,
    priority: Priority,
    transport_epoch: Option<RetryTransportEpoch>,
    unchanged_sends: u8,
    attempts: u16,
    due: Instant,
    sequence: u64,
    retained_bytes: usize,
    semantic_version: u16,
}

#[derive(Clone)]
struct RetryTransportEpoch {
    transfer_id: u64,
    sealed: Vec<u8>,
    repair_rounds: u16,
    emission_cursor: u16,
    repair_round_limit: u16,
    sealed_ordinal: u64,
    mtu: u16,
    semantic_digest: [u8; 32],
}

struct PreparedTransportDispatch {
    transfer_id: u64,
    sealed: Vec<u8>,
    mtu: u16,
    emission_cursor: u16,
}

#[derive(Clone)]
struct DeferredWant {
    exchange_id: u64,
    priority: Priority,
    attempts: u16,
    due: Instant,
    sequence: u64,
    semantic_version: u16,
    transport_epoch: Option<RetryTransportEpoch>,
}

struct HandshakeRetry {
    transfer_id: u64,
    bytes: Vec<u8>,
    attempts: u16,
    due: Instant,
    emission_cursor: u16,
    mtu: Option<u16>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum InventoryRefreshScope {
    ServeOnly,
    Both,
}

impl InventoryRefreshScope {
    fn merged(self, other: Self) -> Self {
        if self == Self::Both || other == Self::Both {
            Self::Both
        } else {
            Self::ServeOnly
        }
    }

    fn event(self) -> SyncEvent {
        match self {
            Self::ServeOnly => SyncEvent::ServeInventoryChanged,
            Self::Both => SyncEvent::LocalInventoryChanged,
        }
    }
}

struct InventoryRefreshRetry {
    scope: InventoryRefreshScope,
    attempts: u16,
    due: Instant,
}

#[derive(Clone)]
struct ControlCheckpoint {
    sync: SyncState,
    outbox: VecDeque<Outbound>,
    retries: BTreeMap<RetryKey, RetryEntry>,
    deferred_wants: BTreeMap<ObjectId, DeferredWant>,
    start_request: Option<StartRequest>,
    next_retry_sequence: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct CompletedTransfer {
    peer: Option<NodeId>,
    transfer_id: u64,
    logical_len: usize,
    logical_digest: [u8; 32],
}

/// Adapter routing metadata is not the authenticated protocol identity. Keep
/// anonymous delivery distinct from a routed contact so neither form can be
/// silently substituted for the other during fragmentation or after session
/// establishment.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum CarrierRoute {
    Anonymous,
    Routed(NodeId),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct PartialTransferRoute {
    route: CarrierRoute,
    first_seen: Instant,
    last_seen: Instant,
}

impl CarrierRoute {
    fn from_peer(peer: Option<NodeId>) -> Self {
        peer.map_or(Self::Anonymous, Self::Routed)
    }

    fn peer(self) -> Option<NodeId> {
        match self {
            Self::Anonymous => None,
            Self::Routed(peer) => Some(peer),
        }
    }
}

/// One authenticated adjacency.  The type remains crate-internal so public
/// application APIs cannot select links, construct wire messages, or bypass
/// authorization policy.
pub struct RuntimeDriver<B: RuntimeBackend> {
    phase: SessionPhase,
    sync: SyncState,
    backend: B,
    start_request: Option<StartRequest>,
    committed_route: Option<CarrierRoute>,
    candidate_route: Option<CarrierRoute>,
    fragment_routes: BTreeMap<u64, PartialTransferRoute>,
    limits: RuntimeLimits,
    wire_limits: Limits,
    reassembler: Reassembler,
    outbox: VecDeque<Outbound>,
    retries: BTreeMap<RetryKey, RetryEntry>,
    deferred_wants: BTreeMap<ObjectId, DeferredWant>,
    handshake_retry: Option<HandshakeRetry>,
    completed_transfers: VecDeque<CompletedTransfer>,
    failed_transfers: VecDeque<CompletedTransfer>,
    logical_authenticated: bool,
    clock: Instant,
    next_retry_sequence: u64,
    next_transfer_id: u64,
    secure_records_sealed: u64,
    irreversible_generation: u64,
    inventory_refresh_retry: Option<InventoryRefreshRetry>,
    initiates_sync: bool,
    external_admission_required: bool,
    authenticated_initialized: bool,
    admitted_authorization_generation: Option<u64>,
    authorization_generation_check: Option<RuntimeAuthorizationGenerationCheck>,
    authorization_generation_counters: RuntimeAuthorizationGenerationCounters,
    local_inventory_changed: bool,
}

impl<B: RuntimeBackend> RuntimeDriver<B> {
    pub fn initiator(
        bundle: ProvisioningBundle,
        sync: SyncState,
        backend: B,
        start_request: StartRequest,
        peer_hint: Option<NodeId>,
    ) -> Result<Self, RuntimeError> {
        Self::initiator_with_limits(
            bundle,
            sync,
            backend,
            start_request,
            peer_hint,
            RuntimeLimits::default(),
        )
    }

    pub fn initiator_with_limits(
        bundle: ProvisioningBundle,
        sync: SyncState,
        backend: B,
        start_request: StartRequest,
        peer_hint: Option<NodeId>,
        limits: RuntimeLimits,
    ) -> Result<Self, RuntimeError> {
        limits.validate().map_err(RuntimeError::InvalidLimits)?;
        let (initiator, first_flight) = ReferenceSessionInitiator::start(bundle)
            .map_err(|error| RuntimeError::Session(error.to_string()))?;
        Self::initiator_from_started(
            initiator,
            first_flight,
            sync,
            backend,
            start_request,
            peer_hint,
            limits,
        )
    }

    /// Opens an initiator whose implementation supports semantic versions only
    /// through `semantic_ceiling`.
    ///
    /// This is a transport-adapter capability declaration, not an application
    /// preference. Adapters must use the highest version whose negotiated lanes
    /// they fully implement.
    pub fn initiator_with_semantic_ceiling(
        bundle: ProvisioningBundle,
        sync: SyncState,
        backend: B,
        start_request: StartRequest,
        peer_hint: Option<NodeId>,
        semantic_ceiling: u16,
    ) -> Result<Self, RuntimeError> {
        Self::initiator_with_limits_and_semantic_ceiling(
            bundle,
            sync,
            backend,
            start_request,
            peer_hint,
            RuntimeLimits::default(),
            semantic_ceiling,
        )
    }

    /// Opens a capability-limited initiator with explicit runtime bounds.
    #[allow(clippy::too_many_arguments)]
    pub fn initiator_with_limits_and_semantic_ceiling(
        bundle: ProvisioningBundle,
        sync: SyncState,
        backend: B,
        start_request: StartRequest,
        peer_hint: Option<NodeId>,
        limits: RuntimeLimits,
        semantic_ceiling: u16,
    ) -> Result<Self, RuntimeError> {
        limits.validate().map_err(RuntimeError::InvalidLimits)?;
        let semantic_versions = semantic_versions_through(semantic_ceiling)?;
        let (initiator, first_flight) =
            ReferenceSessionInitiator::start_with_semantic_versions(bundle, semantic_versions)
                .map_err(|error| RuntimeError::Session(error.to_string()))?;
        Self::initiator_from_started(
            initiator,
            first_flight,
            sync,
            backend,
            start_request,
            peer_hint,
            limits,
        )
    }

    #[cfg(test)]
    fn initiator_with_semantic_versions(
        bundle: ProvisioningBundle,
        sync: SyncState,
        backend: B,
        start_request: StartRequest,
        peer_hint: Option<NodeId>,
        semantic_versions: Vec<u16>,
    ) -> Result<Self, RuntimeError> {
        let (initiator, first_flight) =
            ReferenceSessionInitiator::start_with_semantic_versions(bundle, semantic_versions)
                .map_err(|error| RuntimeError::Session(error.to_string()))?;
        Self::initiator_from_started(
            initiator,
            first_flight,
            sync,
            backend,
            start_request,
            peer_hint,
            RuntimeLimits::default(),
        )
    }

    fn initiator_from_started(
        initiator: ReferenceSessionInitiator,
        first_flight: Vec<u8>,
        sync: SyncState,
        backend: B,
        start_request: StartRequest,
        peer_hint: Option<NodeId>,
        limits: RuntimeLimits,
    ) -> Result<Self, RuntimeError> {
        let clock = Instant::now();
        let mut driver = Self {
            phase: SessionPhase::Initiator(initiator),
            sync,
            backend,
            start_request: Some(start_request),
            committed_route: peer_hint.map(CarrierRoute::Routed),
            candidate_route: None,
            fragment_routes: BTreeMap::new(),
            limits,
            wire_limits: limits.wire,
            reassembler: Reassembler::with_budget(
                limits.max_in_flight_logical_frames,
                limits.max_reassembly_bytes,
            ),
            outbox: VecDeque::new(),
            retries: BTreeMap::new(),
            deferred_wants: BTreeMap::new(),
            handshake_retry: None,
            completed_transfers: VecDeque::new(),
            failed_transfers: VecDeque::new(),
            logical_authenticated: false,
            clock,
            next_retry_sequence: 0,
            next_transfer_id: 1,
            secure_records_sealed: 0,
            irreversible_generation: 0,
            inventory_refresh_retry: None,
            initiates_sync: true,
            external_admission_required: false,
            authenticated_initialized: false,
            admitted_authorization_generation: None,
            authorization_generation_check: None,
            authorization_generation_counters: RuntimeAuthorizationGenerationCounters::default(),
            local_inventory_changed: false,
        };
        driver.queue_handshake(first_flight)?;
        Ok(driver)
    }

    pub fn responder(
        bundle: ProvisioningBundle,
        sync: SyncState,
        backend: B,
        peer_hint: Option<NodeId>,
    ) -> Result<Self, RuntimeError> {
        Self::responder_with_limits(bundle, sync, backend, peer_hint, RuntimeLimits::default())
    }

    pub fn responder_with_limits(
        bundle: ProvisioningBundle,
        sync: SyncState,
        backend: B,
        peer_hint: Option<NodeId>,
        limits: RuntimeLimits,
    ) -> Result<Self, RuntimeError> {
        Self::responder_inner(bundle, sync, backend, None, peer_hint, limits, None)
    }

    /// Opens a responder that also advertises a local interest after receiving
    /// the authenticated initiator's first interest. `start_request` supplies
    /// the local filter; its exchange identifier is a template value and is
    /// replaced by the identifier selected by the initiating peer.
    pub fn responder_with_start(
        bundle: ProvisioningBundle,
        sync: SyncState,
        backend: B,
        start_request: StartRequest,
        peer_hint: Option<NodeId>,
    ) -> Result<Self, RuntimeError> {
        Self::responder_with_start_and_limits(
            bundle,
            sync,
            backend,
            start_request,
            peer_hint,
            RuntimeLimits::default(),
        )
    }

    pub fn responder_with_start_and_limits(
        bundle: ProvisioningBundle,
        sync: SyncState,
        backend: B,
        start_request: StartRequest,
        peer_hint: Option<NodeId>,
        limits: RuntimeLimits,
    ) -> Result<Self, RuntimeError> {
        Self::responder_inner(
            bundle,
            sync,
            backend,
            Some(start_request),
            peer_hint,
            limits,
            None,
        )
    }

    /// Opens a responder whose implementation supports semantic versions only
    /// through `semantic_ceiling` and advertises a local interest.
    ///
    /// See [`Self::initiator_with_semantic_ceiling`].
    pub fn responder_with_start_and_semantic_ceiling(
        bundle: ProvisioningBundle,
        sync: SyncState,
        backend: B,
        start_request: StartRequest,
        peer_hint: Option<NodeId>,
        semantic_ceiling: u16,
    ) -> Result<Self, RuntimeError> {
        Self::responder_with_start_and_limits_and_semantic_ceiling(
            bundle,
            sync,
            backend,
            start_request,
            peer_hint,
            RuntimeLimits::default(),
            semantic_ceiling,
        )
    }

    /// Opens a capability-limited responder with explicit runtime bounds.
    #[allow(clippy::too_many_arguments)]
    pub fn responder_with_start_and_limits_and_semantic_ceiling(
        bundle: ProvisioningBundle,
        sync: SyncState,
        backend: B,
        start_request: StartRequest,
        peer_hint: Option<NodeId>,
        limits: RuntimeLimits,
        semantic_ceiling: u16,
    ) -> Result<Self, RuntimeError> {
        Self::responder_inner(
            bundle,
            sync,
            backend,
            Some(start_request),
            peer_hint,
            limits,
            Some(semantic_versions_through(semantic_ceiling)?),
        )
    }

    fn responder_inner(
        bundle: ProvisioningBundle,
        sync: SyncState,
        backend: B,
        start_request: Option<StartRequest>,
        peer_hint: Option<NodeId>,
        limits: RuntimeLimits,
        semantic_versions: Option<Vec<u16>>,
    ) -> Result<Self, RuntimeError> {
        limits.validate().map_err(RuntimeError::InvalidLimits)?;
        let responder = match semantic_versions {
            Some(versions) => {
                ReferenceSessionResponder::open_with_semantic_versions(bundle, versions)
            }
            None => ReferenceSessionResponder::open(bundle),
        }
        .map_err(|error| RuntimeError::Session(error.to_string()))?;
        let clock = Instant::now();
        Ok(Self {
            phase: SessionPhase::Responder(responder),
            sync,
            backend,
            start_request,
            committed_route: peer_hint.map(CarrierRoute::Routed),
            candidate_route: None,
            fragment_routes: BTreeMap::new(),
            limits,
            wire_limits: limits.wire,
            reassembler: Reassembler::with_budget(
                limits.max_in_flight_logical_frames,
                limits.max_reassembly_bytes,
            ),
            outbox: VecDeque::new(),
            retries: BTreeMap::new(),
            deferred_wants: BTreeMap::new(),
            handshake_retry: None,
            completed_transfers: VecDeque::new(),
            failed_transfers: VecDeque::new(),
            logical_authenticated: false,
            clock,
            next_retry_sequence: 0,
            next_transfer_id: 1,
            secure_records_sealed: 0,
            irreversible_generation: 0,
            inventory_refresh_retry: None,
            initiates_sync: false,
            external_admission_required: false,
            authenticated_initialized: false,
            admitted_authorization_generation: None,
            authorization_generation_check: None,
            authorization_generation_counters: RuntimeAuthorizationGenerationCounters::default(),
            local_inventory_changed: false,
        })
    }

    /// Defers all authenticated synchronization work until the embedding host
    /// admits the cryptographic peer on this carrier. The authenticated
    /// handshake may finish, but the backend is not consulted, durable
    /// progress is not hydrated, and no sync frame is accepted or emitted
    /// before [`Self::admit_authenticated`] succeeds.
    ///
    /// This must be enabled before the first pump. It exists for contact
    /// managers whose carrier-to-node binding policy is intentionally outside
    /// the wire/runtime layer.
    pub fn require_external_admission(&mut self) -> Result<(), RuntimeError> {
        if self.is_authenticated()
            || self.authenticated_initialized
            || self.external_admission_required
        {
            return Err(RuntimeError::FailedState);
        }
        self.external_admission_required = true;
        Ok(())
    }

    /// Completes backend authorization/hydration and, for an initiator,
    /// schedules its initial interest after the embedding host has accepted
    /// the authenticated carrier binding.
    pub fn admit_authenticated(&mut self) -> Result<(), RuntimeError> {
        if !self.external_admission_required
            || !self.is_authenticated()
            || self.authenticated_initialized
        {
            return Err(RuntimeError::FailedState);
        }
        self.initialize_authenticated()
    }

    /// True only at the host-policy barrier between a completed cryptographic
    /// handshake and authenticated synchronization.
    pub fn awaiting_external_admission(&self) -> bool {
        self.external_admission_required
            && self.is_authenticated()
            && !self.authenticated_initialized
    }

    pub fn is_authenticated(&self) -> bool {
        matches!(self.phase, SessionPhase::Authenticated(_))
    }

    pub fn authenticated_peer(&self) -> Option<NodeId> {
        match &self.phase {
            SessionPhase::Authenticated(session) => Some(session.peer_identity()),
            _ => None,
        }
    }

    /// Returns and clears the latest exact generation comparison performed by
    /// durable admission or an authenticated outbound flush.
    ///
    /// Repeated successful comparisons in one pump are coalesced. A changed
    /// or unavailable result is always the terminal comparison for that pump.
    pub fn take_authorization_generation_check(
        &mut self,
    ) -> Option<RuntimeAuthorizationGenerationCheck> {
        self.authorization_generation_check.take()
    }

    /// Cumulative exact checks performed by this contact runtime.
    pub const fn authorization_generation_counters(
        &self,
    ) -> RuntimeAuthorizationGenerationCounters {
        self.authorization_generation_counters
    }

    /// Revalidates an admitted session's captured authorization generation
    /// without reading or writing its carrier. Shared coordinators use this to
    /// retire an explicitly invalidated contact before invoking a link pump.
    pub fn revalidate_authorization_generation(&mut self) -> Result<(), RuntimeError> {
        self.ensure_authorization_generation_current()
    }

    fn record_authorization_generation_check(
        &mut self,
        check: RuntimeAuthorizationGenerationCheck,
    ) {
        self.authorization_generation_counters.checks = self
            .authorization_generation_counters
            .checks
            .saturating_add(1);
        match check {
            RuntimeAuthorizationGenerationCheck::Changed { .. } => {
                self.authorization_generation_counters.mismatches = self
                    .authorization_generation_counters
                    .mismatches
                    .saturating_add(1);
            }
            RuntimeAuthorizationGenerationCheck::Unavailable { .. } => {
                self.authorization_generation_counters.unavailable = self
                    .authorization_generation_counters
                    .unavailable
                    .saturating_add(1);
            }
            RuntimeAuthorizationGenerationCheck::Current { .. } => {}
        }
        self.authorization_generation_check = Some(check);
    }

    /// Number of already-allocated carrier frames awaiting an outbound flush.
    /// This read-only diagnostic proves a generation race exercised queued
    /// bytes rather than an idle contact.
    pub fn pending_outbound_frame_count(&self) -> usize {
        self.outbox
            .len()
            .saturating_add(self.retries.len())
            .saturating_add(usize::from(self.handshake_retry.is_some()))
    }

    fn outbound_route(&self) -> Option<NodeId> {
        self.committed_route
            .or(self.candidate_route)
            .and_then(CarrierRoute::peer)
    }

    fn reset_reassembly(&mut self) {
        self.reassembler = Reassembler::with_budget(
            self.limits.max_in_flight_logical_frames,
            self.limits.max_reassembly_bytes,
        );
        self.fragment_routes.clear();
    }

    fn expire_partial_transfers(&mut self, now: Instant) {
        let expired = self
            .fragment_routes
            .iter()
            .filter_map(|(transfer_id, partial)| {
                (now.saturating_duration_since(partial.last_seen)
                    > self.limits.partial_transfer_idle_ttl)
                    .then_some(*transfer_id)
            })
            .collect::<Vec<_>>();
        for transfer_id in expired {
            self.fragment_routes.remove(&transfer_id);
            self.reassembler.remove(transfer_id);
        }
    }

    fn retain_authenticated_route(&mut self, route: CarrierRoute) {
        if self.committed_route.is_some() || !self.logical_authenticated {
            return;
        }
        // The route becomes a session candidate only after a complete logical
        // flight verifies at the current handshake phase. For a responder,
        // flight 1 proves mission membership but not yet the initiator's full
        // peer identity. Syntactically valid incomplete fragments cannot pin an
        // unknown-peer contact.
        self.candidate_route = Some(route);
        let incompatible = self
            .fragment_routes
            .iter()
            .filter_map(|(transfer_id, partial)| (partial.route != route).then_some(*transfer_id))
            .collect::<Vec<_>>();
        for transfer_id in incompatible {
            self.fragment_routes.remove(&transfer_id);
            self.reassembler.remove(transfer_id);
        }
        if self.is_authenticated() {
            self.committed_route = Some(route);
            self.candidate_route = None;
        }
    }

    fn admit_fragment_route(
        &mut self,
        transfer_id: u64,
        route: CarrierRoute,
        now: Instant,
    ) -> bool {
        if let Some(partial) = self.fragment_routes.get_mut(&transfer_id) {
            if partial.route != route {
                return false;
            }
            partial.last_seen = now;
            return true;
        }
        if self.fragment_routes.len() >= self.limits.max_in_flight_logical_frames
            && let Some(oldest) = self
                .fragment_routes
                .iter()
                .min_by_key(|(id, partial)| (partial.last_seen, partial.first_seen, **id))
                .map(|(id, _)| *id)
        {
            self.fragment_routes.remove(&oldest);
            self.reassembler.remove(oldest);
        }
        self.fragment_routes.insert(
            transfer_id,
            PartialTransferRoute {
                route,
                first_seen: now,
                last_seen: now,
            },
        );
        true
    }

    /// Authenticated semantic capability selected for this peer session.
    /// Applications can observe this status but cannot choose it.
    pub fn authenticated_semantic_version(&self) -> Option<u16> {
        match &self.phase {
            SessionPhase::Authenticated(session) => Some(session.semantic_version()),
            _ => None,
        }
    }

    pub fn sync(&self) -> &SyncState {
        &self.sync
    }

    /// Validated bounds reserved by this contact.
    pub const fn limits(&self) -> &RuntimeLimits {
        &self.limits
    }

    pub fn backend(&self) -> &B {
        &self.backend
    }

    pub fn backend_mut(&mut self) -> &mut B {
        &mut self.backend
    }

    /// Notifies an active contact that durable local objects or authorization
    /// changed outside the reducer. Both inventory directions are selected
    /// again through the authenticated backend before new reconciliation
    /// messages are produced.
    pub fn local_inventory_changed(&mut self) -> Result<(), RuntimeError> {
        let semantic_version = self
            .authenticated_semantic_version()
            .unwrap_or(wire::SEMANTIC_PROTOCOL_V1);
        let sync_checkpoint = self.sync.clone();
        let outbox_checkpoint = self.outbox.clone();
        let retries_checkpoint = self.retries.clone();
        let deferred_checkpoint = self.deferred_wants.clone();
        let retry_sequence_checkpoint = self.next_retry_sequence;
        let actions = self
            .sync
            .apply_for_semantic_version(SyncEvent::LocalInventoryChanged, semantic_version)?;
        if actions.is_empty() {
            return Ok(());
        }
        let handled = self.handle_actions(actions);
        if handled.is_err() {
            self.sync = sync_checkpoint;
            self.outbox = outbox_checkpoint;
            self.retries = retries_checkpoint;
            self.deferred_wants = deferred_checkpoint;
            self.next_retry_sequence = retry_sequence_checkpoint;
        }
        handled
    }

    /// Returns and clears the coalesced signal that this contact durably
    /// committed at least one inventory-visible object. Embeddings use this to
    /// notify other live contacts that share the same durable store.
    pub fn take_local_inventory_changed(&mut self) -> bool {
        std::mem::take(&mut self.local_inventory_changed)
    }

    pub fn into_backend(self) -> B {
        self.backend
    }

    /// Drains currently available fragments without blocking, processes every
    /// completed logical frame, and sends all resulting frames on `link`.
    pub fn pump(&mut self, link: &dyn Link) -> Result<usize, RuntimeError> {
        self.pump_at(link, Instant::now())
    }

    /// Earliest deadline at which retry work or adapter maintenance is due.
    /// The driver never sleeps or polls internally; an embedding event loop can
    /// wait until this instant, link readiness, or an application command.
    pub fn next_wakeup(&self, link: &dyn Link) -> Option<Instant> {
        let retry = self
            .outbox
            .iter()
            .map(|entry| entry.due)
            .chain(self.retries.values().map(|entry| entry.due))
            .chain(self.deferred_wants.values().map(|entry| entry.due))
            .chain(self.handshake_retry.iter().map(|entry| entry.due))
            .chain(self.inventory_refresh_retry.iter().map(|entry| entry.due))
            .min();
        match (retry, link.next_wakeup()) {
            (Some(left), Some(right)) => Some(left.min(right)),
            (Some(deadline), None) | (None, Some(deadline)) => Some(deadline),
            (None, None) => None,
        }
    }

    fn pump_at(&mut self, link: &dyn Link, now: Instant) -> Result<usize, RuntimeError> {
        self.clock = now;
        if self.awaiting_external_admission() {
            // A responder must be able to finish its fourth handshake flight
            // so the initiator can learn the authenticated peer, but neither
            // side may consume or emit synchronization traffic until the host
            // accepts the carrier binding.
            let mut send_budget = self.limits.max_retry_sends_per_pump;
            self.flush(link, &mut send_budget)?;
            return Ok(0);
        }
        self.retry_pending_inventory_refresh();
        self.expire_partial_transfers(now);
        let mut completed = 0_usize;
        let mut send_budget = self.limits.max_retry_sends_per_pump;
        let mut received_frames = 0_usize;
        let mut unauthenticated_failures = 0_usize;
        let mut deferred_send_error = None;
        if let Err(error) = self.flush(link, &mut send_budget) {
            match error {
                RuntimeError::Io(_) => deferred_send_error = Some(error),
                _ => return Err(error),
            }
        }
        while received_frames < self.limits.max_received_frames_per_pump {
            if send_budget == 0 && !self.outbox.is_empty() {
                // Do not keep accepting authenticated work after this pass
                // has exhausted its send budget while a one-shot response is
                // waiting. Yield to the embedding loop so the next pump can
                // drain that response before receiving more DATA. This keeps
                // advisory RECEIPTs from being crowded out by a large WANT
                // burst without raising any count or byte ceiling.
                break;
            }
            let Some(received) = link.try_receive()? else {
                break;
            };
            received_frames = received_frames.saturating_add(1);
            let carrier_route = CarrierRoute::from_peer(received.peer);
            if self
                .committed_route
                .is_some_and(|expected| expected != carrier_route)
                || self
                    .candidate_route
                    .is_some_and(|expected| expected != carrier_route)
            {
                // A configured or authenticated route is exact, including the
                // distinction between anonymous and routed delivery. Compare
                // before parsing attacker-controlled fragment bytes.
                unauthenticated_failures = unauthenticated_failures.saturating_add(1);
                if unauthenticated_failures >= self.limits.max_unauthenticated_failures_per_pump {
                    break;
                }
                continue;
            }
            let fragment = match Fragment::decode(&received.bytes) {
                Ok(fragment) => fragment,
                Err(FragmentError::Malformed) => {
                    unauthenticated_failures = unauthenticated_failures.saturating_add(1);
                    if unauthenticated_failures >= self.limits.max_unauthenticated_failures_per_pump
                    {
                        break;
                    }
                    continue;
                }
                Err(error) => return Err(error.into()),
            };
            let transfer_id = fragment.transfer_id;
            if !self.admit_fragment_route(transfer_id, carrier_route, now) {
                // Reassembly is keyed by transfer identifier, so retain a
                // parallel exact-route key and never combine fragments
                // received anonymously and/or through different routes.
                unauthenticated_failures = unauthenticated_failures.saturating_add(1);
                if unauthenticated_failures >= self.limits.max_unauthenticated_failures_per_pump {
                    break;
                }
                continue;
            }
            let reassembled = match self.reassembler.push(fragment.clone()) {
                Ok(value) => value,
                Err(FragmentError::MessageTooLarge) => {
                    // The bounded set can fill with incomplete transfers on a
                    // lossy link. Drop only volatile partial reassembly state;
                    // retained senders will refill it. Inconsistent reuse is
                    // handled below as bounded unauthenticated carrier input.
                    self.reset_reassembly();
                    self.admit_fragment_route(transfer_id, carrier_route, now);
                    self.reassembler.push(fragment)?
                }
                Err(FragmentError::Inconsistent) => {
                    self.fragment_routes.remove(&transfer_id);
                    self.reassembler.remove(transfer_id);
                    unauthenticated_failures = unauthenticated_failures.saturating_add(1);
                    if unauthenticated_failures >= self.limits.max_unauthenticated_failures_per_pump
                    {
                        break;
                    }
                    continue;
                }
                Err(error) => return Err(error.into()),
            };
            if let Some(logical) = reassembled {
                let completed_route = self
                    .fragment_routes
                    .remove(&transfer_id)
                    .map_or(carrier_route, |partial| partial.route);
                // Cache keys use only the stable adapter route. The
                // cryptographic peer becomes known during the handshake and
                // therefore cannot serve as a stable pre/post-flight key.
                let peer = completed_route.peer();
                let logical_digest: [u8; 32] = Sha256::digest(&logical).into();
                if let Some(previous) = self
                    .completed_transfers
                    .iter()
                    .chain(self.failed_transfers.iter())
                    .find(|entry| entry.peer == peer && entry.transfer_id == transfer_id)
                {
                    if previous.logical_len != logical.len()
                        || previous.logical_digest != logical_digest
                    {
                        unauthenticated_failures = unauthenticated_failures.saturating_add(1);
                        if unauthenticated_failures
                            >= self.limits.max_unauthenticated_failures_per_pump
                        {
                            break;
                        }
                    }
                    continue;
                }

                self.logical_authenticated = false;
                let result = self.receive_logical(&logical);
                self.retain_authenticated_route(completed_route);
                if matches!(result, Err(RuntimeError::Session(_))) && !self.logical_authenticated {
                    unauthenticated_failures = unauthenticated_failures.saturating_add(1);
                    if unauthenticated_failures >= self.limits.max_unauthenticated_failures_per_pump
                    {
                        break;
                    }
                    continue;
                }
                if self.logical_authenticated {
                    let transfer = CompletedTransfer {
                        peer,
                        transfer_id,
                        logical_len: logical.len(),
                        logical_digest,
                    };
                    if result.is_ok() {
                        self.remember_completed_transfer(transfer);
                    } else {
                        self.remember_failed_transfer(transfer);
                    }
                }
                result?;
                completed = completed.saturating_add(1);
                if let Err(error) = self.flush(link, &mut send_budget) {
                    match error {
                        RuntimeError::Io(_) if deferred_send_error.is_none() => {
                            deferred_send_error = Some(error);
                        }
                        RuntimeError::Io(_) => {}
                        _ => return Err(error),
                    }
                }
                if self.awaiting_external_admission() {
                    break;
                }
            }
        }
        if let Some(error) = deferred_send_error {
            Err(error)
        } else {
            Ok(completed)
        }
    }

    fn remember_completed_transfer(&mut self, completed: CompletedTransfer) {
        if self.completed_transfers.len() == self.limits.max_completed_transfers {
            self.completed_transfers.pop_front();
        }
        self.completed_transfers.push_back(completed);
    }

    fn remember_failed_transfer(&mut self, failed: CompletedTransfer) {
        if self.failed_transfers.len() == self.limits.max_completed_transfers {
            self.failed_transfers.pop_front();
        }
        self.failed_transfers.push_back(failed);
    }

    fn control_checkpoint(&self) -> ControlCheckpoint {
        ControlCheckpoint {
            sync: self.sync.clone(),
            outbox: self.outbox.clone(),
            retries: self.retries.clone(),
            deferred_wants: self.deferred_wants.clone(),
            start_request: self.start_request.clone(),
            next_retry_sequence: self.next_retry_sequence,
        }
    }

    fn restore_control_checkpoint(&mut self, checkpoint: ControlCheckpoint) {
        self.sync = checkpoint.sync;
        self.outbox = checkpoint.outbox;
        self.retries = checkpoint.retries;
        self.deferred_wants = checkpoint.deferred_wants;
        self.start_request = checkpoint.start_request;
        self.next_retry_sequence = checkpoint.next_retry_sequence;
    }

    fn receive_logical(&mut self, bytes: &[u8]) -> Result<(), RuntimeError> {
        if let SessionPhase::Authenticated(session) = &mut self.phase {
            let semantic_version = session.semantic_version();
            let peer_identity = session.peer_identity();
            let plaintext = session
                .open_frame(bytes)
                .map_err(|error| RuntimeError::Session(error.to_string()))?;
            self.logical_authenticated = true;
            // The responder's retained fourth flight is acknowledged only by
            // the initiator's first successfully authenticated session frame.
            self.handshake_retry = None;
            let message = wire::decode_message_for_semantic_version(
                &plaintext,
                semantic_version,
                self.wire_limits,
            )?;
            let peer_exchange_id = match &message {
                Message::Interest(interest) if self.start_request.is_some() => {
                    Some(interest.exchange_id)
                }
                _ => None,
            };
            let retry_control_after_backpressure = matches!(
                message,
                Message::Interest(_) | Message::Summary(_) | Message::Probe(_) | Message::Node(_)
            );
            let complete_receipt =
                matches!(&message, Message::Receipt(receipt) if receipt.complete);
            let disposed_data = match &message {
                Message::Data(data)
                    if !self.sync.inventory().contains(&data.object_id)
                        && !self.sync.wants().contains(&data.object_id) =>
                {
                    let expected = self
                        .sync
                        .active_exchange_id()
                        .ok_or(RuntimeError::Sync(SyncError::NoActiveExchange))?;
                    if expected != data.exchange_id {
                        return Err(RuntimeError::Sync(SyncError::ExchangeMismatch {
                            expected,
                            received: data.exchange_id,
                        }));
                    }
                    match self
                        .backend
                        .durably_disposed_object_len(data.object_id, semantic_version)
                        .map_err(|error| RuntimeError::Backend(error.to_string()))?
                    {
                        Some(total_len) if total_len == data.total_len => true,
                        Some(_) => {
                            return Err(RuntimeError::BackendContract(
                                "disposed object length changed",
                            ));
                        }
                        None => false,
                    }
                }
                _ => false,
            };
            let irreversible_checkpoint = self.irreversible_generation;
            let control_checkpoint = matches!(
                message,
                Message::Interest(_)
                    | Message::Summary(_)
                    | Message::Probe(_)
                    | Message::Node(_)
                    | Message::Offer(_)
                    | Message::Data(_)
            )
            .then(|| self.control_checkpoint());
            let mut actions = if disposed_data {
                let Message::Data(data) = &message else {
                    unreachable!("durable disposition lookup is DATA-only");
                };
                vec![SyncAction::Send(Message::Receipt(wire::Receipt {
                    exchange_id: data.exchange_id,
                    object_id: data.object_id,
                    total_len: data.total_len,
                    received: (data.total_len > 0)
                        .then_some(ByteRange {
                            start: 0,
                            end: data.total_len,
                        })
                        .into_iter()
                        .collect(),
                    complete: true,
                }))]
            } else {
                match self.sync.apply_for_semantic_version(
                    SyncEvent::Receive(message.clone()),
                    semantic_version,
                ) {
                    Ok(actions) => actions,
                    Err(error) => {
                        if let Some(checkpoint) = control_checkpoint {
                            self.restore_control_checkpoint(checkpoint);
                        }
                        return Err(error.into());
                    }
                }
            };
            if let Some(exchange_id) = peer_exchange_id {
                let Some(request) = self.start_request.clone() else {
                    if let Some(checkpoint) = control_checkpoint {
                        self.restore_control_checkpoint(checkpoint);
                    }
                    return Err(RuntimeError::FailedState);
                };
                let start_actions = match self.sync.apply_for_semantic_version(
                    SyncEvent::Start {
                        exchange_id,
                        topics: request.topics,
                        scopes: request.scopes,
                        min_priority: request.min_priority,
                    },
                    semantic_version,
                ) {
                    Ok(actions) => actions,
                    Err(error) => {
                        if let Some(checkpoint) = control_checkpoint {
                            self.restore_control_checkpoint(checkpoint);
                        }
                        return Err(error.into());
                    }
                };
                actions.extend(start_actions);
                self.start_request = None;
            }
            if let Message::Receipt(receipt) = &message {
                self.backend
                    .acknowledge_receipt(peer_identity, semantic_version, receipt)
                    .map_err(|error| RuntimeError::Backend(error.to_string()))?;
                // Representation-specific receipts can unlock a different
                // exact inventory (for example BatchProof -> compact item ->
                // Blob carriers). This changes only what this peer may be
                // served; resetting the independent receive-side traversal
                // here can invalidate honest NODE responses still in flight.
                if receipt.complete {
                    self.irreversible_generation = self.irreversible_generation.wrapping_add(1);
                    self.schedule_inventory_refresh(InventoryRefreshScope::ServeOnly);
                    let refresh_actions = match self.sync.apply_for_semantic_version(
                        SyncEvent::ServeInventoryChanged,
                        semantic_version,
                    ) {
                        Ok(actions) => actions,
                        Err(error) => {
                            self.phase = SessionPhase::Failed;
                            return Err(error.into());
                        }
                    };
                    actions.extend(refresh_actions);
                }
            }
            self.observe_authenticated_message(&message)?;
            let handled = self.handle_actions(actions);
            if handled.is_err() && self.irreversible_generation != irreversible_checkpoint {
                // A successful commit, defer, quarantine, or terminal abort
                // cannot be rolled back in the backend. Preserve the matching
                // reducer state and retry only the derived inventory controls.
                let scope = if complete_receipt {
                    InventoryRefreshScope::ServeOnly
                } else {
                    InventoryRefreshScope::Both
                };
                self.schedule_inventory_refresh(scope);
            } else if handled.is_err()
                && !matches!(
                    handled,
                    Err(RuntimeError::EnvelopeLengthMismatch | RuntimeError::EnvelopeHashMismatch)
                )
                && let Some(checkpoint) = control_checkpoint
            {
                // Fallible action handling can mutate causal reducer state
                // before all derived controls are admitted. Restore the whole
                // queue/reducer checkpoint so a fresh authenticated retry can
                // re-emit every causal control.
                self.restore_control_checkpoint(checkpoint);
                if let Message::Data(data) = &message
                    && let Some(item) = self.sync.retry_want_item(data.object_id)
                {
                    self.queue_sync_message(&Message::Want(crate::wire::Want {
                        exchange_id: data.exchange_id,
                        items: vec![item],
                    }))?;
                }
                if retry_control_after_backpressure
                    && matches!(handled, Err(RuntimeError::Backpressure))
                {
                    return Ok(());
                }
            }
            if handled.is_ok()
                && complete_receipt
                && self
                    .inventory_refresh_retry
                    .as_ref()
                    .is_some_and(|retry| retry.scope == InventoryRefreshScope::ServeOnly)
            {
                self.inventory_refresh_retry = None;
            }
            if self.irreversible_generation != irreversible_checkpoint
                && matches!(handled, Err(RuntimeError::Backpressure))
            {
                // The object disposition or peer acknowledgement is already
                // durable and the derived inventory refresh remains
                // represented by `inventory_refresh_retry`. Queue pressure is
                // therefore retryable host flow control, not a failed
                // authenticated contact. Other post-commit failures still
                // propagate.
                return Ok(());
            }
            return handled;
        }

        let phase = std::mem::replace(&mut self.phase, SessionPhase::Failed);
        match phase {
            SessionPhase::Initiator(initiator) => {
                let (pending, third_flight) = match initiator.receive_server_retryable(bytes) {
                    Ok(transition) => transition,
                    Err((initiator, error)) => {
                        self.phase = SessionPhase::Initiator(initiator);
                        return Err(RuntimeError::Session(error.to_string()));
                    }
                };
                self.logical_authenticated = true;
                self.handshake_retry = None;
                self.phase = SessionPhase::InitiatorAwaitingFinished(pending);
                self.queue_handshake(third_flight)
            }
            SessionPhase::InitiatorAwaitingFinished(pending) => {
                let session = match pending.receive_finished_retryable(bytes) {
                    Ok(session) => session,
                    Err((pending, error)) => {
                        self.phase = SessionPhase::InitiatorAwaitingFinished(pending);
                        return Err(RuntimeError::Session(error.to_string()));
                    }
                };
                self.logical_authenticated = true;
                self.handshake_retry = None;
                self.phase = SessionPhase::Authenticated(session);
                if self.external_admission_required {
                    Ok(())
                } else {
                    self.initialize_authenticated()
                }
            }
            SessionPhase::Responder(responder) => {
                let (pending, second_flight) = match responder.receive_client_retryable(bytes) {
                    Ok(transition) => transition,
                    Err((responder, error)) => {
                        self.phase = SessionPhase::Responder(responder);
                        return Err(RuntimeError::Session(error.to_string()));
                    }
                };
                self.logical_authenticated = true;
                self.handshake_retry = None;
                self.phase = SessionPhase::ResponderPending(pending);
                self.queue_handshake(second_flight)
            }
            SessionPhase::ResponderPending(pending) => {
                let (session, fourth_flight) = match pending.receive_client_auth_retryable(bytes) {
                    Ok(transition) => transition,
                    Err((pending, error)) => {
                        self.phase = SessionPhase::ResponderPending(pending);
                        return Err(RuntimeError::Session(error.to_string()));
                    }
                };
                self.logical_authenticated = true;
                self.handshake_retry = None;
                self.phase = SessionPhase::Authenticated(session);
                if !self.external_admission_required {
                    self.initialize_authenticated()?;
                }
                let finalized = self.queue_handshake(fourth_flight);
                if finalized.is_err() {
                    self.fail_authenticated_initialization();
                }
                finalized
            }
            SessionPhase::Authenticated(_) => unreachable!("authenticated phase handled above"),
            SessionPhase::Failed => Err(RuntimeError::FailedState),
        }
    }

    fn authorize_and_hydrate_authenticated(&mut self) -> Result<(), RuntimeError> {
        let result = (|| {
            let peer = self.authenticated_peer().ok_or(RuntimeError::FailedState)?;
            let generation_before = match self.backend.authorization_generation() {
                Ok(generation) => generation,
                Err(error) => {
                    self.record_authorization_generation_check(
                        RuntimeAuthorizationGenerationCheck::Unavailable {
                            expected_generation: None,
                        },
                    );
                    return Err(RuntimeError::Backend(error.to_string()));
                }
            };
            self.backend
                .authorize_adjacency(peer)
                .map_err(|error| RuntimeError::Backend(error.to_string()))?;
            let generation_after = match self.backend.authorization_generation() {
                Ok(generation) => generation,
                Err(error) => {
                    self.record_authorization_generation_check(
                        RuntimeAuthorizationGenerationCheck::Unavailable {
                            expected_generation: Some(generation_before),
                        },
                    );
                    return Err(RuntimeError::Backend(error.to_string()));
                }
            };
            if generation_before != generation_after {
                self.record_authorization_generation_check(
                    RuntimeAuthorizationGenerationCheck::Changed {
                        expected_generation: generation_before,
                        observed_generation: generation_after,
                    },
                );
                return Err(RuntimeError::AuthorizationGenerationChanged);
            }
            self.record_authorization_generation_check(
                RuntimeAuthorizationGenerationCheck::Current {
                    generation: generation_after,
                },
            );
            self.admitted_authorization_generation = Some(generation_after);
            self.hydrate_durable_progress()
        })();
        if result.is_err() {
            self.fail_authenticated_initialization();
        }
        result
    }

    fn initialize_authenticated(&mut self) -> Result<(), RuntimeError> {
        let initialized = (|| {
            self.authorize_and_hydrate_authenticated()?;
            if self.initiates_sync {
                let request = self
                    .start_request
                    .clone()
                    .ok_or(RuntimeError::FailedState)?;
                let semantic_version = self
                    .authenticated_semantic_version()
                    .ok_or(RuntimeError::FailedState)?;
                let actions = self.sync.apply_for_semantic_version(
                    SyncEvent::Start {
                        exchange_id: request.exchange_id,
                        topics: request.topics,
                        scopes: request.scopes,
                        min_priority: request.min_priority,
                    },
                    semantic_version,
                )?;
                self.handle_actions(actions)?;
                self.start_request = None;
            }
            self.authenticated_initialized = true;
            Ok(())
        })();
        if initialized.is_err() {
            self.fail_authenticated_initialization();
        }
        initialized
    }

    fn fail_authenticated_initialization(&mut self) {
        self.phase = SessionPhase::Failed;
        self.logical_authenticated = false;
        self.handshake_retry = None;
        self.outbox.clear();
        self.retries.clear();
        self.deferred_wants.clear();
        self.inventory_refresh_retry = None;
        self.authenticated_initialized = false;
        self.admitted_authorization_generation = None;
    }

    fn ensure_authorization_generation_current(&mut self) -> Result<(), RuntimeError> {
        let Some(admitted) = self.admitted_authorization_generation else {
            return Ok(());
        };
        let current = match self.backend.authorization_generation() {
            Ok(generation) => generation,
            Err(error) => {
                self.record_authorization_generation_check(
                    RuntimeAuthorizationGenerationCheck::Unavailable {
                        expected_generation: Some(admitted),
                    },
                );
                self.fail_authenticated_initialization();
                return Err(RuntimeError::Backend(error.to_string()));
            }
        };
        if current != admitted {
            self.record_authorization_generation_check(
                RuntimeAuthorizationGenerationCheck::Changed {
                    expected_generation: admitted,
                    observed_generation: current,
                },
            );
            self.fail_authenticated_initialization();
            return Err(RuntimeError::AuthorizationGenerationChanged);
        }
        self.record_authorization_generation_check(RuntimeAuthorizationGenerationCheck::Current {
            generation: current,
        });
        Ok(())
    }

    fn schedule_inventory_refresh(&mut self, scope: InventoryRefreshScope) {
        if let Some(retry) = self.inventory_refresh_retry.as_mut() {
            retry.scope = retry.scope.merged(scope);
            retry.due = retry.due.min(self.clock);
        } else {
            self.inventory_refresh_retry = Some(InventoryRefreshRetry {
                scope,
                attempts: 0,
                due: self.clock,
            });
        }
    }

    fn retry_pending_inventory_refresh(&mut self) {
        let Some(retry) = self.inventory_refresh_retry.as_ref() else {
            return;
        };
        if retry.due > self.clock || !self.is_authenticated() {
            return;
        }
        let scope = retry.scope;
        let attempt = retry.attempts;
        let semantic_version = match self.authenticated_semantic_version() {
            Some(version) => version,
            None => return,
        };
        let sync_checkpoint = self.sync.clone();
        let outbox_checkpoint = self.outbox.clone();
        let retries_checkpoint = self.retries.clone();
        let deferred_checkpoint = self.deferred_wants.clone();
        let retry_sequence_checkpoint = self.next_retry_sequence;
        let refreshed = self
            .sync
            .apply_for_semantic_version(scope.event(), semantic_version)
            .map_err(RuntimeError::from)
            .and_then(|actions| self.handle_actions(actions));
        if refreshed.is_ok() {
            self.inventory_refresh_retry = None;
        } else {
            self.sync = sync_checkpoint;
            self.outbox = outbox_checkpoint;
            self.retries = retries_checkpoint;
            self.deferred_wants = deferred_checkpoint;
            self.next_retry_sequence = retry_sequence_checkpoint;
            self.inventory_refresh_retry = Some(InventoryRefreshRetry {
                scope,
                attempts: attempt.saturating_add(1),
                due: Self::next_retry_deadline(
                    self.clock,
                    Priority::Immediate,
                    attempt,
                    Duration::from_millis(1),
                ),
            });
        }
    }

    fn hydrate_durable_progress(&mut self) -> Result<(), RuntimeError> {
        let semantic_version = self
            .authenticated_semantic_version()
            .ok_or(RuntimeError::FailedState)?;
        let progress = self
            .backend
            .durable_progress_for_semantic_version(self.sync.max_durable_wants(), semantic_version)
            .map_err(|error| RuntimeError::Backend(error.to_string()))?;
        if progress.len() > self.sync.max_durable_wants() {
            return Err(RuntimeError::BackendContract(
                "durable progress exceeds requested bound",
            ));
        }
        let remaining = self.sync.max_durable_wants().saturating_sub(progress.len());
        let dependencies = self
            .backend
            .durable_dependencies_for_semantic_version(remaining, semantic_version)
            .map_err(|error| RuntimeError::Backend(error.to_string()))?;
        if dependencies.len() > remaining {
            return Err(RuntimeError::BackendContract(
                "durable dependencies exceed requested bound",
            ));
        }
        self.sync.hydrate_durable_progress_for_semantic_version(
            progress
                .into_iter()
                .map(|entry| (entry.object_id, entry.total_len, entry.received)),
            semantic_version,
        )?;
        self.sync
            .hydrate_dependency_wants_for_semantic_version(dependencies, semantic_version)?;
        Ok(())
    }

    fn handle_actions(&mut self, initial: Vec<SyncAction>) -> Result<(), RuntimeError> {
        let (peer, peer_route_commitments, semantic_version) = match &self.phase {
            SessionPhase::Authenticated(session) => (
                session.peer_identity(),
                session.peer_route_grant_commitments().to_vec(),
                session.semantic_version(),
            ),
            _ => return Err(RuntimeError::FailedState),
        };
        let initial = if initial
            .iter()
            .all(|action| matches!(action, SyncAction::Serve(_)))
        {
            // A peer may coalesce multiple WANT items in hash order. Rank the
            // bounded batch by authenticated local precedence before reading
            // payloads so flow control cannot leave a later FLASH object
            // behind earlier ROUTINE work solely because of its ObjectID.
            let mut ranked = Vec::with_capacity(initial.len());
            for action in initial {
                let SyncAction::Serve(want) = action else {
                    unreachable!("all actions were checked as Serve")
                };
                ensure_object_allowed(want.object_id, semantic_version)?;
                let priority = self
                    .backend
                    .object_priority(want.object_id)
                    .map_err(|error| RuntimeError::Backend(error.to_string()))?;
                ranked.push((priority, want.object_id, SyncAction::Serve(want)));
            }
            ranked.sort_by(|left, right| right.0.cmp(&left.0).then_with(|| left.1.cmp(&right.1)));
            ranked.into_iter().map(|(_, _, action)| action).collect()
        } else {
            initial
        };
        let mut actions: VecDeque<_> = initial.into();
        let mut data_saturated = false;
        while let Some(action) = actions.pop_front() {
            match action {
                SyncAction::Send(message) => match self.queue_sync_message(&message) {
                    Ok(()) => {}
                    Err(RuntimeError::Backpressure) if matches!(message, Message::Receipt(_)) => {
                        // A RECEIPT is advisory and its DATA sender retains the
                        // causal retry. When the bounded one-shot queue is
                        // full, omit this copy and re-acknowledge the sender's
                        // next authenticated DATA retry instead of failing the
                        // whole contact.
                    }
                    Err(error) => return Err(error),
                },
                SyncAction::SelectInventory {
                    request_id,
                    purpose,
                    filter,
                } => {
                    let inventory = self
                        .backend
                        .select_authorized_inventory_for_semantic_version(
                            peer,
                            &peer_route_commitments,
                            &filter,
                            purpose,
                            semantic_version,
                        )
                        .map_err(|error| RuntimeError::Backend(error.to_string()))?
                        .filtered_for_semantic_version(semantic_version);
                    let exchange_id = self
                        .sync
                        .active_exchange_id()
                        .ok_or(RuntimeError::FailedState)?;
                    actions.extend(self.sync.apply_for_semantic_version(
                        SyncEvent::InventorySelected {
                            exchange_id,
                            request_id,
                            purpose,
                            filter,
                            inventory,
                        },
                        semantic_version,
                    )?);
                }
                SyncAction::StoreChunk {
                    object_id,
                    total_len,
                    offset,
                    bytes,
                } => {
                    ensure_object_allowed(object_id, semantic_version)?;
                    let end = offset
                        .checked_add(u64::try_from(bytes.len()).map_err(|_| {
                            RuntimeError::BackendContract("stored chunk length overflow")
                        })?)
                        .ok_or(RuntimeError::BackendContract(
                            "stored chunk extent overflow",
                        ))?;
                    let range = ByteRange { start: offset, end };
                    if let Err(error) = self.backend.store_object_chunk_for_semantic_version(
                        object_id,
                        total_len,
                        offset,
                        &bytes,
                        semantic_version,
                    ) {
                        let retry_actions = self.sync.apply_for_semantic_version(
                            SyncEvent::ChunkStoreFailed { object_id, range },
                            semantic_version,
                        )?;
                        for action in retry_actions {
                            match action {
                                SyncAction::Send(message) => self.queue_sync_message(&message)?,
                                _ => {
                                    return Err(RuntimeError::BackendContract(
                                        "chunk failure recovery emitted a non-send action",
                                    ));
                                }
                            }
                        }
                        return Err(RuntimeError::Backend(error.to_string()));
                    }
                    actions.extend(self.sync.apply_for_semantic_version(
                        SyncEvent::ChunkStored {
                            object_id,
                            total_len,
                            range,
                        },
                        semantic_version,
                    )?);
                }
                SyncAction::Serve(want) => {
                    if data_saturated {
                        continue;
                    }
                    ensure_object_allowed(want.object_id, semantic_version)?;
                    let exchange_id = self
                        .sync
                        .active_exchange_id()
                        .ok_or(RuntimeError::FailedState)?;
                    let data = self
                        .backend
                        .data_for_want_for_semantic_version(
                            peer,
                            &peer_route_commitments,
                            exchange_id,
                            semantic_version,
                            &want,
                        )
                        .map_err(|error| RuntimeError::Backend(error.to_string()))?;
                    self.validate_served_data(exchange_id, &want, &data)?;
                    // A WANT is a retained causal request until the receiver
                    // durably completes the object. Treat DATA queue
                    // saturation as hop-local flow control: keep every hard
                    // count/byte ceiling, stop expanding this WANT batch, and
                    // let the peer's authenticated retry regenerate the
                    // omitted ranges after receipts release capacity. Other
                    // queue failures remain contact failures.
                    for data in data {
                        match self.queue_sync_message(&Message::Data(data)) {
                            Ok(()) => {}
                            Err(RuntimeError::Backpressure) => {
                                data_saturated = true;
                                break;
                            }
                            Err(error) => return Err(error),
                        }
                    }
                }
                SyncAction::CompleteObject {
                    object_id,
                    total_len,
                    forwarding,
                } => {
                    ensure_object_allowed(object_id, semantic_version)?;
                    let bytes = self
                        .backend
                        .complete_object_bytes(object_id, total_len)
                        .map_err(|error| RuntimeError::Backend(error.to_string()))?;
                    if u64::try_from(bytes.len()).ok() != Some(total_len) {
                        self.abort_terminal_object(object_id)?;
                        return Err(RuntimeError::EnvelopeLengthMismatch);
                    }
                    if object_id.kind() != ObjectKind::BlobChunk {
                        let exact_digest: [u8; 32] = Sha256::digest(&bytes).into();
                        if object_id.digest() != &exact_digest {
                            self.abort_terminal_object(object_id)?;
                            return Err(RuntimeError::EnvelopeHashMismatch);
                        }
                    }
                    let commit = self.backend.commit_authenticated_object_with_dependencies(
                        peer,
                        self.sync
                            .active_exchange_id()
                            .ok_or(RuntimeError::FailedState)?,
                        semantic_version,
                        object_id,
                        bytes,
                        forwarding,
                    );
                    let disposition = match commit {
                        Ok(disposition) => disposition,
                        Err(error) => {
                            let terminal = self.backend.is_terminal_commit_error(&error);
                            let message = error.to_string();
                            let abort_result = if terminal {
                                self.abort_terminal_object(object_id)
                            } else {
                                Ok(())
                            };
                            if self.authorization_changed_after_commit_error()? {
                                return Err(RuntimeError::AuthorizationGenerationChanged);
                            }
                            abort_result?;
                            return Err(RuntimeError::Backend(message));
                        }
                    };
                    // Every successful disposition is durable and cannot be
                    // reversed by restoring the in-memory reducer checkpoint.
                    self.irreversible_generation = self.irreversible_generation.wrapping_add(1);
                    match disposition {
                        RuntimeCommit::Committed { item_id, promoted } => {
                            self.local_inventory_changed = true;
                            let was_new_wanted = !self.sync.inventory().contains(&object_id)
                                && self.sync.wants().contains(&object_id);
                            let mut committed_actions = match self.sync.apply_for_semantic_version(
                                SyncEvent::ObjectCommitted { object_id, item_id },
                                semantic_version,
                            ) {
                                Ok(actions) => actions,
                                Err(error) => {
                                    self.phase = SessionPhase::Failed;
                                    return Err(error.into());
                                }
                            };
                            if was_new_wanted {
                                let exchange_id = self
                                    .sync
                                    .active_exchange_id()
                                    .ok_or(RuntimeError::FailedState)?;
                                self.retire_completed_want_and_refill_window(
                                    exchange_id,
                                    semantic_version,
                                    object_id,
                                );
                            }
                            for promoted in promoted {
                                if let Err(error) =
                                    ensure_object_allowed(promoted, semantic_version)
                                {
                                    self.phase = SessionPhase::Failed;
                                    return Err(error);
                                }
                                let promoted_actions = match self.sync.apply_for_semantic_version(
                                    SyncEvent::LocalObjectAdded {
                                        object_id: promoted,
                                    },
                                    semantic_version,
                                ) {
                                    Ok(actions) => actions,
                                    Err(error) => {
                                        self.phase = SessionPhase::Failed;
                                        return Err(error.into());
                                    }
                                };
                                committed_actions.extend(promoted_actions);
                            }
                            actions.extend(committed_actions);
                        }
                        RuntimeCommit::Deferred { dependencies } => {
                            let deferred_actions = match self.sync.apply_for_semantic_version(
                                SyncEvent::ObjectDeferred {
                                    object_id,
                                    dependencies,
                                },
                                semantic_version,
                            ) {
                                Ok(actions) => actions,
                                Err(error) => {
                                    self.phase = SessionPhase::Failed;
                                    return Err(error.into());
                                }
                            };
                            actions.extend(deferred_actions);
                        }
                        RuntimeCommit::Quarantined => {
                            let quarantined_actions = match self.sync.apply_for_semantic_version(
                                SyncEvent::ObjectQuarantined { object_id },
                                semantic_version,
                            ) {
                                Ok(actions) => actions,
                                Err(error) => {
                                    self.phase = SessionPhase::Failed;
                                    return Err(error.into());
                                }
                            };
                            actions.extend(quarantined_actions);
                        }
                    }
                }
            }
        }
        Ok(())
    }

    fn abort_terminal_object(&mut self, object_id: ObjectId) -> Result<(), RuntimeError> {
        let semantic_version = self
            .authenticated_semantic_version()
            .ok_or(RuntimeError::FailedState)?;
        ensure_object_allowed(object_id, semantic_version)?;
        self.backend
            .abort_object(object_id)
            .map_err(|error| RuntimeError::Backend(error.to_string()))?;
        self.irreversible_generation = self.irreversible_generation.wrapping_add(1);
        let retry = match self
            .sync
            .apply_for_semantic_version(SyncEvent::ObjectRejected { object_id }, semantic_version)
        {
            Ok(actions) => actions,
            Err(error) => {
                self.phase = SessionPhase::Failed;
                return Err(error.into());
            }
        };
        for action in retry {
            match action {
                SyncAction::Send(message) => self.queue_sync_message(&message)?,
                _ => {
                    return Err(RuntimeError::BackendContract(
                        "terminal object reset emitted a non-send action",
                    ));
                }
            }
        }
        Ok(())
    }

    fn authorization_changed_after_commit_error(&mut self) -> Result<bool, RuntimeError> {
        let Some(expected_generation) = self.admitted_authorization_generation else {
            return Ok(false);
        };
        let observed_generation = match self.backend.authorization_generation() {
            Ok(generation) => generation,
            Err(_) => {
                self.record_authorization_generation_check(
                    RuntimeAuthorizationGenerationCheck::Unavailable {
                        expected_generation: Some(expected_generation),
                    },
                );
                self.irreversible_generation = self.irreversible_generation.wrapping_add(1);
                self.local_inventory_changed = true;
                self.schedule_inventory_refresh(InventoryRefreshScope::Both);
                self.fail_after_authorization_generation_change();
                return Ok(true);
            }
        };
        if observed_generation == expected_generation {
            return Ok(false);
        }
        self.record_authorization_generation_check(RuntimeAuthorizationGenerationCheck::Changed {
            expected_generation,
            observed_generation,
        });
        // The authorization prefix is already durable and cannot be rolled
        // back with the reducer checkpoint even though this object receives
        // no completion receipt.
        self.irreversible_generation = self.irreversible_generation.wrapping_add(1);
        self.local_inventory_changed = true;
        self.schedule_inventory_refresh(InventoryRefreshScope::Both);
        self.fail_after_authorization_generation_change();
        Ok(true)
    }

    fn fail_after_authorization_generation_change(&mut self) {
        self.phase = SessionPhase::Failed;
        self.logical_authenticated = false;
        self.handshake_retry = None;
        self.outbox.clear();
        self.retries.clear();
        self.deferred_wants.clear();
        self.authenticated_initialized = false;
        self.admitted_authorization_generation = None;
        // Preserve the reducer and its Both-scope refresh witness. The host
        // retires this stale session; a fresh session hydrates durable state.
    }

    fn validate_served_data(
        &self,
        exchange_id: u64,
        want: &WantItem,
        data: &[Data],
    ) -> Result<(), RuntimeError> {
        let semantic_version = self
            .authenticated_semantic_version()
            .ok_or(RuntimeError::FailedState)?;
        ensure_object_allowed(want.object_id, semantic_version)?;
        if data.len() > self.wire_limits.max_collection_items {
            return Err(RuntimeError::BackendContract("too many DATA messages"));
        }
        let mut supplied_forwarding = false;
        for chunk in data {
            if chunk.exchange_id != exchange_id || chunk.object_id != want.object_id {
                return Err(RuntimeError::BackendContract("DATA identity mismatch"));
            }
            if let Some(total_len) = want.total_len
                && chunk.total_len != total_len
            {
                return Err(RuntimeError::BackendContract("DATA total length mismatch"));
            }
            let end =
                chunk
                    .offset
                    .checked_add(u64::try_from(chunk.payload.len()).map_err(|_| {
                        RuntimeError::BackendContract("DATA payload length overflow")
                    })?)
                    .ok_or(RuntimeError::BackendContract("DATA extent overflow"))?;
            if !chunk.payload.is_empty()
                && !want.missing.is_empty()
                && !want
                    .missing
                    .iter()
                    .any(|range| range.start <= chunk.offset && range.end >= end)
            {
                return Err(RuntimeError::BackendContract("DATA outside wanted ranges"));
            }
            supplied_forwarding |= !chunk.forwarding.is_empty();
            wire::encode_message_for_semantic_version(
                &Message::Data(chunk.clone()),
                semantic_version,
                self.wire_limits,
            )?;
        }
        if want.need_forwarding && !supplied_forwarding {
            return Err(RuntimeError::BackendContract("forwarding metadata omitted"));
        }
        Ok(())
    }

    fn queue_sync_message(&mut self, message: &Message) -> Result<(), RuntimeError> {
        let priority = self.message_priority(message)?;
        if let Message::Want(want) = message {
            for item in &want.items {
                self.queue_retry_message(
                    RetryKey::Want(want.exchange_id, item.object_id),
                    Message::Want(crate::wire::Want {
                        exchange_id: want.exchange_id,
                        items: vec![item.clone()],
                    }),
                    priority,
                )?;
            }
            return Ok(());
        }
        if let Some(key) = retry_key(message)? {
            self.queue_retry_message(key, message.clone(), priority)
        } else {
            let (semantic_version, plaintext) = self.encode_message(message)?;
            self.queue_logical_once(plaintext, priority, semantic_version)
        }
    }

    fn message_priority(&mut self, message: &Message) -> Result<Priority, RuntimeError> {
        let local_minimum = || {
            self.sync
                .local_min_priority()
                .and_then(Priority::from_wire)
                .unwrap_or(Priority::Routine)
        };
        match message {
            Message::Interest(interest) => Priority::from_wire(interest.min_priority)
                .ok_or(RuntimeError::BackendContract("invalid interest priority")),
            Message::Data(data) => self
                .backend
                .object_priority(data.object_id)
                .map_err(|error| RuntimeError::Backend(error.to_string())),
            Message::Want(_) | Message::Receipt(_) => Ok(local_minimum()),
            Message::Summary(_) | Message::Probe(_) | Message::Node(_) | Message::Offer(_) => {
                Ok(Priority::Immediate.max(local_minimum()))
            }
        }
    }

    fn encode_message(&self, message: &Message) -> Result<(u16, Vec<u8>), RuntimeError> {
        let semantic_version = self
            .authenticated_semantic_version()
            .ok_or(RuntimeError::FailedState)?;
        let plaintext =
            wire::encode_message_for_semantic_version(message, semantic_version, self.wire_limits)?;
        Ok((semantic_version, plaintext))
    }

    fn seal_plaintext(&mut self, plaintext: &[u8]) -> Result<Vec<u8>, RuntimeError> {
        let sealed = match &mut self.phase {
            SessionPhase::Authenticated(session) => session
                .seal_frame(plaintext)
                .map_err(|error| RuntimeError::Session(error.to_string())),
            _ => Err(RuntimeError::FailedState),
        }?;
        self.secure_records_sealed = self.secure_records_sealed.saturating_add(1);
        Ok(sealed)
    }

    fn take_transfer_id(&mut self) -> Result<u64, RuntimeError> {
        let transfer_id = self.next_transfer_id;
        self.next_transfer_id = self
            .next_transfer_id
            .checked_add(1)
            .ok_or(RuntimeError::TransferIdExhausted)?;
        Ok(transfer_id)
    }

    fn queue_logical_once(
        &mut self,
        plaintext: Vec<u8>,
        priority: Priority,
        semantic_version: u16,
    ) -> Result<(), RuntimeError> {
        let retained_bytes = plaintext
            .capacity()
            .saturating_add(transport_record_reservation(&plaintext));
        while self.outbox.len() >= self.limits.max_pending_outbox
            || self
                .non_deferred_pending_bytes()
                .saturating_add(retained_bytes)
                > self
                    .limits
                    .max_pending_logical_bytes
                    .saturating_sub(self.limits.deferred_want_epoch_reserve)
            || self.pending_logical_bytes().saturating_add(retained_bytes)
                > self.limits.max_pending_logical_bytes
        {
            let deferred_candidate = self
                .deferred_wants
                .iter()
                .filter(|(_, entry)| entry.priority < priority && entry.transport_epoch.is_some())
                .min_by_key(|(_, entry)| (entry.priority, std::cmp::Reverse(entry.sequence)))
                .map(|(object_id, _)| *object_id);
            if let Some(object_id) = deferred_candidate {
                if let Some(entry) = self.deferred_wants.get_mut(&object_id) {
                    entry.transport_epoch = None;
                }
                continue;
            }
            let outbox_candidate = self
                .outbox
                .iter()
                .enumerate()
                .filter(|(_, entry)| entry.priority < priority)
                .min_by_key(|(_, entry)| (entry.priority, std::cmp::Reverse(entry.sequence)))
                .map(|(position, entry)| (position, entry.priority, entry.sequence));
            let retry_candidate = self
                .retries
                .iter()
                .filter(|(key, entry)| {
                    entry.priority < priority
                        && matches!(
                            key,
                            RetryKey::Node(..) | RetryKey::Want(..) | RetryKey::Data(..)
                        )
                })
                .min_by_key(|(_, entry)| (entry.priority, std::cmp::Reverse(entry.sequence)))
                .map(|(key, entry)| (key.clone(), entry.priority, entry.sequence));
            match (outbox_candidate, retry_candidate) {
                (
                    Some((position, outbox_priority, outbox_sequence)),
                    Some((_key, retry_priority, retry_sequence)),
                ) if (outbox_priority, std::cmp::Reverse(outbox_sequence))
                    <= (retry_priority, std::cmp::Reverse(retry_sequence)) =>
                {
                    self.outbox.remove(position);
                }
                (_, Some((key, _, _))) => self.demote_retry(&key),
                (Some((position, _, _)), None) => {
                    self.outbox.remove(position);
                }
                (None, None) => return Err(RuntimeError::Backpressure),
            }
        }
        let sequence = self.next_retry_sequence;
        self.next_retry_sequence = self.next_retry_sequence.wrapping_add(1);
        self.outbox.push_back(Outbound {
            plaintext,
            priority,
            attempts: 0,
            due: self.clock,
            sequence,
            semantic_version,
            retained_bytes,
            transport_epoch: None,
        });
        Ok(())
    }

    fn queue_handshake(&mut self, bytes: Vec<u8>) -> Result<(), RuntimeError> {
        let prior = self
            .handshake_retry
            .as_ref()
            .map(|entry| entry.bytes.capacity())
            .unwrap_or(0);
        if self
            .pending_logical_bytes()
            .saturating_sub(prior)
            .saturating_add(bytes.capacity())
            > self.limits.max_pending_logical_bytes
        {
            return Err(RuntimeError::Backpressure);
        }
        let transfer_id = self.take_transfer_id()?;
        self.handshake_retry = Some(HandshakeRetry {
            transfer_id,
            bytes,
            attempts: 0,
            due: self.clock,
            emission_cursor: 0,
            mtu: None,
        });
        Ok(())
    }

    fn retained_retry_bytes(&self) -> usize {
        self.retries
            .values()
            .map(|entry| entry.retained_bytes)
            .sum()
    }

    fn deferred_want_epoch_bytes(&self) -> usize {
        self.deferred_wants
            .values()
            .filter_map(|entry| entry.transport_epoch.as_ref())
            .map(|epoch| epoch.sealed.capacity())
            .sum()
    }

    fn pending_logical_bytes(&self) -> usize {
        self.retained_retry_bytes()
            .saturating_add(self.deferred_want_epoch_bytes())
            .saturating_add(self.outbox.iter().map(|entry| entry.retained_bytes).sum())
            .saturating_add(
                self.handshake_retry
                    .as_ref()
                    .map(|entry| entry.bytes.capacity())
                    .unwrap_or(0),
            )
    }

    fn non_deferred_pending_bytes(&self) -> usize {
        self.pending_logical_bytes()
            .saturating_sub(self.deferred_want_epoch_bytes())
    }

    fn defer_want(&mut self, object_id: ObjectId, deferred: DeferredWant) {
        if !self.sync.wants().contains(&object_id)
            || !object_id
                .kind()
                .is_allowed_in_semantic_version(deferred.semantic_version)
        {
            return;
        }
        self.deferred_wants
            .entry(object_id)
            .and_modify(|entry| {
                if entry.exchange_id != deferred.exchange_id
                    || entry.semantic_version != deferred.semantic_version
                {
                    entry.transport_epoch = None;
                } else if entry.transport_epoch.is_none() {
                    entry.transport_epoch = deferred.transport_epoch.clone();
                }
                entry.exchange_id = deferred.exchange_id;
                entry.priority = entry.priority.max(deferred.priority);
                entry.attempts = entry.attempts.max(deferred.attempts);
                entry.due = entry.due.min(deferred.due);
                entry.semantic_version = deferred.semantic_version;
            })
            .or_insert(deferred);
    }

    fn retire_completed_want_and_refill_window(
        &mut self,
        exchange_id: u64,
        semantic_version: u16,
        object_id: ObjectId,
    ) {
        self.retries.remove(&RetryKey::Want(exchange_id, object_id));
        self.deferred_wants.remove(&object_id);

        // Completion frees one bounded receiver request slot and, after the
        // already-queued RECEIPT arrives, one sender DATA slot. ACK-clock one
        // sleeping request into that opening instead of waking the whole
        // overflow set or waiting for its prior exponential deadline.
        let candidate = self
            .retries
            .iter()
            .filter_map(|(key, entry)| {
                let RetryKey::Want(candidate_exchange, candidate_id) = key else {
                    return None;
                };
                (*candidate_exchange == exchange_id
                    && entry.semantic_version == semantic_version
                    && self.sync.retry_want_item(*candidate_id).is_some())
                .then_some((
                    std::cmp::Reverse(entry.priority),
                    entry.sequence,
                    *candidate_id,
                    true,
                ))
            })
            .chain(
                self.deferred_wants
                    .iter()
                    .filter(|(candidate_id, entry)| {
                        entry.exchange_id == exchange_id
                            && entry.semantic_version == semantic_version
                            && self.sync.retry_want_item(**candidate_id).is_some()
                    })
                    .map(|(candidate_id, entry)| {
                        (
                            std::cmp::Reverse(entry.priority),
                            entry.sequence,
                            *candidate_id,
                            false,
                        )
                    }),
            )
            .min();
        let Some((_, _, candidate, retained)) = candidate else {
            return;
        };
        let sequence = self.next_retry_sequence;
        self.next_retry_sequence = self.next_retry_sequence.wrapping_add(1);
        if retained {
            let Some(entry) = self
                .retries
                .get_mut(&RetryKey::Want(exchange_id, candidate))
            else {
                return;
            };
            entry.due = entry.due.min(self.clock);
            entry.sequence = sequence;
            // The prior WANT may already be in the peer's completed-transfer
            // cache even though DATA pressure prevented it from serving the
            // request. New durable credit must therefore use a fresh secure
            // transport epoch so the peer reprocesses the causal request.
            entry.transport_epoch = None;
            entry.unchanged_sends = 0;
        } else if let Some(entry) = self.deferred_wants.get_mut(&candidate) {
            entry.due = entry.due.min(self.clock);
            entry.sequence = sequence;
            entry.transport_epoch = None;
        }
        // Whether retained or deferred, move the accelerated request behind
        // older same-priority sleepers. Charged attempts remain, so repeated
        // completion cannot erase backoff state.
    }

    fn demote_retry(&mut self, key: &RetryKey) {
        let Some(entry) = self.retries.remove(key) else {
            return;
        };
        if let RetryKey::Want(exchange_id, object_id) = key {
            self.defer_want(
                *object_id,
                DeferredWant {
                    exchange_id: *exchange_id,
                    priority: entry.priority,
                    attempts: entry.attempts,
                    due: entry.due,
                    sequence: entry.sequence,
                    semantic_version: entry.semantic_version,
                    transport_epoch: entry.transport_epoch,
                },
            );
        }
    }

    fn ensure_retry_capacity(
        &mut self,
        required_bytes: usize,
        priority: Priority,
        replacing: Option<&RetryKey>,
    ) -> bool {
        let normal_byte_limit = self
            .limits
            .max_pending_logical_bytes
            .saturating_sub(self.limits.deferred_want_epoch_reserve);
        if required_bytes > normal_byte_limit {
            return false;
        }
        loop {
            let replaced_bytes = replacing
                .and_then(|key| self.retries.get(key))
                .map(|entry| entry.retained_bytes)
                .unwrap_or(0);
            let replaced_count =
                usize::from(replacing.is_some_and(|key| self.retries.contains_key(key)));
            let bytes_without_replaced = self
                .non_deferred_pending_bytes()
                .saturating_sub(replaced_bytes);
            let total_bytes_without_replaced =
                self.pending_logical_bytes().saturating_sub(replaced_bytes);
            let count_without_replaced = self.retries.len().saturating_sub(replaced_count);
            if count_without_replaced < self.limits.max_pending_retries
                && bytes_without_replaced.saturating_add(required_bytes) <= normal_byte_limit
                && total_bytes_without_replaced.saturating_add(required_bytes)
                    <= self.limits.max_pending_logical_bytes
            {
                return true;
            }

            let deferred_candidate = self
                .deferred_wants
                .iter()
                .filter(|(_, entry)| entry.priority < priority && entry.transport_epoch.is_some())
                .min_by_key(|(_, entry)| (entry.priority, std::cmp::Reverse(entry.sequence)))
                .map(|(object_id, _)| *object_id);
            if let Some(object_id) = deferred_candidate {
                if let Some(entry) = self.deferred_wants.get_mut(&object_id) {
                    entry.transport_epoch = None;
                }
                continue;
            }

            let candidate = self
                .retries
                .iter()
                .filter(|(key, entry)| {
                    replacing != Some(*key)
                        && entry.priority < priority
                        && matches!(
                            key,
                            RetryKey::Node(..) | RetryKey::Want(..) | RetryKey::Data(..)
                        )
                })
                .min_by_key(|(_, entry)| (entry.priority, std::cmp::Reverse(entry.sequence)))
                .map(|(key, _)| key.clone());
            if let Some(candidate) = candidate {
                self.demote_retry(&candidate);
                continue;
            }
            let outbox_candidate = self
                .outbox
                .iter()
                .enumerate()
                .filter(|(_, entry)| entry.priority < priority)
                .min_by_key(|(_, entry)| (entry.priority, std::cmp::Reverse(entry.sequence)))
                .map(|(position, _)| position);
            let Some(position) = outbox_candidate else {
                return false;
            };
            self.outbox.remove(position);
        }
    }

    fn queue_retry_message(
        &mut self,
        key: RetryKey,
        message: Message,
        priority: Priority,
    ) -> Result<(), RuntimeError> {
        let (semantic_version, plaintext) = self.encode_message(&message)?;
        if self.retries.contains_key(&key) {
            // A fresh causal request (for example a repeated WANT after a
            // failed store) replaces the retained semantic record. Secure
            // sequence numbers and transfer identifiers are assigned only
            // when the scheduler actually dispatches it.
            let retained_bytes =
                retry_record_bytes(&key, &message, transport_record_reservation(&plaintext));
            if !self.ensure_retry_capacity(retained_bytes, priority, Some(&key)) {
                if let RetryKey::Want(exchange_id, object_id) = key {
                    self.demote_retry(&RetryKey::Want(exchange_id, object_id));
                    let sequence = self.next_retry_sequence;
                    self.next_retry_sequence = self.next_retry_sequence.wrapping_add(1);
                    self.defer_want(
                        object_id,
                        DeferredWant {
                            exchange_id,
                            priority,
                            attempts: 0,
                            due: self.clock,
                            sequence,
                            semantic_version,
                            transport_epoch: None,
                        },
                    );
                    return Ok(());
                }
                return Err(RuntimeError::Backpressure);
            }
            let sequence = self.next_retry_sequence;
            self.next_retry_sequence = self.next_retry_sequence.wrapping_add(1);
            let entry = self
                .retries
                .get_mut(&key)
                .ok_or(RuntimeError::FailedState)?;
            entry.message = message;
            entry.priority = entry.priority.max(priority);
            entry.transport_epoch = None;
            entry.unchanged_sends = 0;
            entry.due = self.clock;
            // A semantic refresh is new causal work. Give it a fresh FIFO
            // position so a RECEIPT queued immediately before an updated WANT
            // reaches the sender first and releases the DATA slot needed for
            // the newly requested tail.
            entry.sequence = sequence;
            entry.retained_bytes = retained_bytes;
            entry.semantic_version = semantic_version;
            if let RetryKey::Want(_, object_id) = key {
                self.deferred_wants.remove(&object_id);
            }
            return Ok(());
        }

        if let RetryKey::Summary(exchange_id, _) = key {
            self.retries.retain(|candidate, _| {
                !matches!(candidate, RetryKey::Summary(candidate_exchange, _) if *candidate_exchange == exchange_id)
            });
        }
        let carried_epoch = match &key {
            RetryKey::Want(_, object_id) => self
                .deferred_wants
                .get(object_id)
                .and_then(|entry| entry.transport_epoch.clone()),
            _ => None,
        };
        let record_reservation = transport_record_reservation(&plaintext).max(
            carried_epoch
                .as_ref()
                .map(|epoch| epoch.sealed.capacity())
                .unwrap_or(0),
        );
        let retained_bytes = retry_record_bytes(&key, &message, record_reservation);
        let sequence = self.next_retry_sequence;
        self.next_retry_sequence = self.next_retry_sequence.wrapping_add(1);
        if !self.ensure_retry_capacity(retained_bytes, priority, None) {
            if let RetryKey::Want(exchange_id, object_id) = key {
                self.defer_want(
                    object_id,
                    DeferredWant {
                        exchange_id,
                        priority,
                        attempts: 0,
                        due: self.clock,
                        sequence,
                        semantic_version,
                        transport_epoch: None,
                    },
                );
                return Ok(());
            }
            return Err(RuntimeError::Backpressure);
        }
        self.retries.insert(
            key.clone(),
            RetryEntry {
                message,
                priority,
                transport_epoch: carried_epoch,
                unchanged_sends: 0,
                attempts: 0,
                due: self.clock,
                sequence,
                retained_bytes,
                semantic_version,
            },
        );
        if let RetryKey::Want(_, object_id) = key {
            self.deferred_wants.remove(&object_id);
        }
        Ok(())
    }

    fn observe_authenticated_message(&mut self, message: &Message) -> Result<(), RuntimeError> {
        if let Message::Interest(interest) = message {
            self.retries
                .retain(|key, _| retry_exchange_id(key) == interest.exchange_id);
        }
        match message {
            Message::Summary(summary) => {
                self.retries
                    .remove(&RetryKey::Interest(summary.exchange_id));
            }
            Message::Probe(probe) => {
                self.retries
                    .remove(&RetryKey::Summary(probe.exchange_id, probe.snapshot_id));
                self.retries.retain(|key, _| {
                    !matches!(
                        key,
                        RetryKey::Node(exchange_id, snapshot_id, nibbles, prefix)
                            if *exchange_id == probe.exchange_id
                                && *snapshot_id == probe.snapshot_id
                                && packed_prefix_is_strict_parent(
                                    prefix,
                                    *nibbles,
                                    &probe.prefix,
                                    probe.prefix_nibbles,
                                )
                    )
                });
            }
            Message::Node(node) => {
                self.retries.remove(&RetryKey::Probe(
                    node.exchange_id,
                    node.snapshot_id,
                    node.prefix_nibbles,
                    node.prefix.clone(),
                ));
            }
            Message::Offer(offer) => {
                // A complete validated root OFFER resolves every branch of
                // this snapshot. Retire child Probe retries too; otherwise a
                // delayed response can restart the superseded Merkle walk.
                self.retries.retain(|key, _| {
                    !matches!(
                        key,
                        RetryKey::Probe(exchange_id, snapshot_id, ..)
                            if *exchange_id == offer.exchange_id
                                && *snapshot_id == offer.snapshot_id
                    )
                });
            }
            Message::Receipt(receipt) => {
                self.retries.retain(|key, entry| {
                    let RetryKey::Data(exchange_id, object_id, total_len, start, end) = key else {
                        return true;
                    };
                    if *exchange_id != receipt.exchange_id
                        || *object_id != receipt.object_id
                        || *total_len != receipt.total_len
                    {
                        return true;
                    }
                    if receipt.complete {
                        return false;
                    }
                    let covered = receipt
                        .received
                        .iter()
                        .any(|range| range.start <= *start && range.end >= *end);
                    // A forwarding-only DATA record has an empty byte extent;
                    // it is retired only by a complete receipt.
                    !(covered && start < end && matches!(entry.message, Message::Data(_)))
                });
            }
            Message::Want(want) => {
                self.retries.retain(|key, _| {
                    match key {
                        RetryKey::Node(exchange_id, _, wire::OBJECT_ID_NIBBLES, prefix)
                            if *exchange_id == want.exchange_id
                                && want.items.iter().any(|item| {
                                    prefix.as_slice() == item.object_id.to_wire_bytes().as_slice()
                                }) =>
                        {
                            false
                        }
                        RetryKey::Data(exchange_id, object_id, total_len, start, end)
                            if *exchange_id == want.exchange_id =>
                        {
                            let Some(item) =
                                want.items.iter().find(|item| item.object_id == *object_id)
                            else {
                                return true;
                            };
                            if item.total_len != Some(*total_len) || item.need_forwarding {
                                return true;
                            }
                            // An authenticated exact-range WANT is also safe
                            // hop-local negative acknowledgement: ranges it no
                            // longer lists are durably present at that peer.
                            // Retire only superseded DATA retries so a delayed
                            // RECEIPT cannot block the newly requested tail.
                            // This does not record peer possession in the
                            // backend; only RECEIPT retains that authority.
                            start < end
                                && item
                                    .missing
                                    .iter()
                                    .any(|range| range.start < *end && *start < range.end)
                        }
                        _ => true,
                    }
                });
            }
            Message::Interest(_) | Message::Data(_) => {}
        }
        Ok(())
    }

    fn refresh_retry(&mut self, key: &RetryKey) -> Result<bool, RuntimeError> {
        if !self.retries.contains_key(key) {
            return Ok(false);
        }
        let semantic_version = self
            .authenticated_semantic_version()
            .ok_or(RuntimeError::FailedState)?;
        if self
            .retries
            .get(key)
            .is_some_and(|entry| entry.semantic_version != semantic_version)
        {
            self.retries.remove(key);
            return Ok(false);
        }
        if self
            .retries
            .get(key)
            .is_some_and(|entry| u16::from(entry.unchanged_sends) >= MIN_RECORD_REPAIR_ROUNDS)
            && matches!(key, RetryKey::Node(..))
        {
            // NODE is a response to an independently retained Probe. Bound its
            // standalone repeats; a lost response is regenerated by the still
            // pending causal request. SUMMARY has an explicit root-Probe ACK.
            self.retries.remove(key);
            return Ok(false);
        }
        let refreshed_want = match key {
            RetryKey::Want(exchange_id, object_id) => {
                let Some(item) = self.sync.retry_want_item(*object_id) else {
                    self.retries.remove(key);
                    return Ok(false);
                };
                Some(Message::Want(crate::wire::Want {
                    exchange_id: *exchange_id,
                    items: vec![item],
                }))
            }
            _ => None,
        };
        let (message, changed) = {
            let entry = self.retries.get(key).ok_or(RuntimeError::FailedState)?;
            let message = refreshed_want.unwrap_or_else(|| entry.message.clone());
            let changed = message != entry.message;
            (message, changed)
        };
        if changed {
            let (_, plaintext) = self.encode_message(&message)?;
            let retained_bytes =
                retry_record_bytes(key, &message, transport_record_reservation(&plaintext));
            let priority = self
                .retries
                .get(key)
                .ok_or(RuntimeError::FailedState)?
                .priority;
            if !self.ensure_retry_capacity(retained_bytes, priority, Some(key)) {
                if matches!(key, RetryKey::Want(..)) {
                    self.demote_retry(key);
                    return Ok(false);
                }
                return Err(RuntimeError::Backpressure);
            }
            let entry = self.retries.get_mut(key).ok_or(RuntimeError::FailedState)?;
            entry.message = message;
            entry.transport_epoch = None;
            entry.unchanged_sends = 0;
            entry.retained_bytes = retained_bytes;
        }
        Ok(true)
    }

    fn send_retry_epoch(
        &self,
        link: &dyn Link,
        transfer_id: u64,
        sealed: &[u8],
        mtu: u16,
        repair_round: u16,
    ) -> Result<(), RuntimeError> {
        let mut fragments = fragment::fragment(sealed, usize::from(mtu), transfer_id)?;
        if !fragments.is_empty() {
            let offset = transport_fragment_emission_offset(fragments.len(), repair_round);
            fragments.rotate_left(offset);
        }
        let target = self.outbound_route();
        for fragment in fragments {
            link.send(target, &fragment.encode()?)?;
        }
        Ok(())
    }

    fn prepare_outbox_transport_epoch(
        &mut self,
        sequence: u64,
        mtu: u16,
    ) -> Result<Option<PreparedTransportDispatch>, RuntimeError> {
        let Some(entry) = self.outbox.iter().find(|entry| entry.sequence == sequence) else {
            return Ok(None);
        };
        let plaintext = entry.plaintext.clone();
        let semantic_digest: [u8; 32] = Sha256::digest(&plaintext).into();
        let needs_fresh_epoch = entry.transport_epoch.as_ref().is_none_or(|epoch| {
            epoch.semantic_digest != semantic_digest
                || epoch.repair_rounds >= MAX_SUCCESSFUL_RECORD_REPAIR_ROUNDS
                || epoch.emission_cursor >= epoch.repair_round_limit
                || epoch.mtu != mtu
                || self
                    .secure_records_sealed
                    .saturating_sub(epoch.sealed_ordinal)
                    >= SECURE_REPLAY_WINDOW_RECORDS
        });
        if needs_fresh_epoch {
            let reserved_record_bytes = transport_record_reservation(&plaintext);
            let transfer_id = self.take_transfer_id()?;
            let sealed_ordinal = self.secure_records_sealed;
            let sealed = self.seal_plaintext(&plaintext)?;
            if sealed.capacity() > reserved_record_bytes {
                self.phase = SessionPhase::Failed;
                return Err(RuntimeError::BackendContract(
                    "secure record exceeded its bounded reservation",
                ));
            }
            let fragment_count = fragment::fragment(&sealed, usize::from(mtu), transfer_id)?.len();
            let entry = self
                .outbox
                .iter_mut()
                .find(|entry| entry.sequence == sequence)
                .ok_or(RuntimeError::FailedState)?;
            entry.transport_epoch = Some(RetryTransportEpoch {
                transfer_id,
                sealed,
                repair_rounds: 0,
                emission_cursor: 0,
                repair_round_limit: transport_repair_round_limit(fragment_count),
                sealed_ordinal,
                mtu,
                semantic_digest,
            });
        }
        let epoch = self
            .outbox
            .iter_mut()
            .find(|entry| entry.sequence == sequence)
            .and_then(|entry| entry.transport_epoch.as_mut())
            .ok_or(RuntimeError::FailedState)?;
        let emission_cursor = epoch.emission_cursor;
        epoch.emission_cursor = epoch.emission_cursor.wrapping_add(1);
        Ok(Some(PreparedTransportDispatch {
            transfer_id: epoch.transfer_id,
            sealed: epoch.sealed.clone(),
            mtu: epoch.mtu,
            emission_cursor,
        }))
    }

    fn prepare_retry_transport_epoch(
        &mut self,
        key: &RetryKey,
        mtu: u16,
    ) -> Result<Option<(u64, Vec<u8>)>, RuntimeError> {
        let Some(entry) = self.retries.get(key) else {
            return Ok(None);
        };
        let message = entry.message.clone();
        let priority = entry.priority;
        let (_, plaintext) = self.encode_message(&message)?;
        let semantic_digest: [u8; 32] = Sha256::digest(&plaintext).into();
        let needs_fresh_epoch = entry.transport_epoch.as_ref().is_none_or(|epoch| {
            epoch.semantic_digest != semantic_digest
                || epoch.repair_rounds >= MAX_SUCCESSFUL_RECORD_REPAIR_ROUNDS
                || epoch.emission_cursor >= epoch.repair_round_limit
                || epoch.mtu != mtu
                || self
                    .secure_records_sealed
                    .saturating_sub(epoch.sealed_ordinal)
                    >= SECURE_REPLAY_WINDOW_RECORDS
        });
        if needs_fresh_epoch {
            let reserved_record_bytes = transport_record_reservation(&plaintext);
            let retained_bytes = retry_record_bytes(key, &message, reserved_record_bytes);
            if !self.ensure_retry_capacity(retained_bytes, priority, Some(key)) {
                if matches!(key, RetryKey::Want(..)) {
                    self.demote_retry(key);
                    return Ok(None);
                }
                return Err(RuntimeError::Backpressure);
            }

            let transfer_id = self.take_transfer_id()?;
            let sealed_ordinal = self.secure_records_sealed;
            let sealed = self.seal_plaintext(&plaintext)?;
            if sealed.capacity() > reserved_record_bytes {
                self.phase = SessionPhase::Failed;
                return Err(RuntimeError::BackendContract(
                    "secure record exceeded its bounded reservation",
                ));
            }
            let fragment_count = fragment::fragment(&sealed, usize::from(mtu), transfer_id)?.len();
            let entry = self.retries.get_mut(key).ok_or(RuntimeError::FailedState)?;
            entry.transport_epoch = Some(RetryTransportEpoch {
                transfer_id,
                sealed,
                repair_rounds: 0,
                emission_cursor: 0,
                repair_round_limit: transport_repair_round_limit(fragment_count),
                sealed_ordinal,
                mtu,
                semantic_digest,
            });
            entry.retained_bytes = retained_bytes;
        }

        let epoch = self
            .retries
            .get(key)
            .and_then(|entry| entry.transport_epoch.as_ref())
            .ok_or(RuntimeError::FailedState)?;
        Ok(Some((epoch.transfer_id, epoch.sealed.clone())))
    }

    fn prepare_deferred_want_epoch(
        &mut self,
        object_id: ObjectId,
        message: &Message,
        mtu: u16,
    ) -> Result<Option<PreparedTransportDispatch>, RuntimeError> {
        let (_, plaintext) = self.encode_message(message)?;
        let semantic_digest: [u8; 32] = Sha256::digest(&plaintext).into();
        let Some(entry) = self.deferred_wants.get(&object_id) else {
            return Ok(None);
        };
        let priority = entry.priority;
        let needs_fresh_epoch = entry.transport_epoch.as_ref().is_none_or(|epoch| {
            epoch.semantic_digest != semantic_digest
                || epoch.repair_rounds >= MAX_SUCCESSFUL_RECORD_REPAIR_ROUNDS
                || epoch.emission_cursor >= epoch.repair_round_limit
                || epoch.mtu != mtu
                || self
                    .secure_records_sealed
                    .saturating_sub(epoch.sealed_ordinal)
                    >= SECURE_REPLAY_WINDOW_RECORDS
        });
        if needs_fresh_epoch {
            let reserved_record_bytes = transport_record_reservation(&plaintext);
            let old_capacity = self
                .deferred_wants
                .get(&object_id)
                .and_then(|entry| entry.transport_epoch.as_ref())
                .map(|epoch| epoch.sealed.capacity())
                .unwrap_or(0);
            while self
                .pending_logical_bytes()
                .saturating_sub(old_capacity)
                .saturating_add(reserved_record_bytes)
                > self.limits.max_pending_logical_bytes
            {
                let candidate = self
                    .deferred_wants
                    .iter()
                    .filter(|(candidate_id, candidate)| {
                        **candidate_id != object_id
                            && candidate.priority < priority
                            && candidate.transport_epoch.is_some()
                    })
                    .min_by_key(|(_, candidate)| {
                        (candidate.priority, std::cmp::Reverse(candidate.sequence))
                    })
                    .map(|(candidate_id, _)| *candidate_id);
                let Some(candidate_id) = candidate else {
                    let due = Self::next_retry_deadline(
                        self.clock,
                        priority,
                        self.deferred_wants
                            .get(&object_id)
                            .map(|entry| entry.attempts)
                            .unwrap_or(0),
                        Duration::from_millis(1),
                    );
                    if let Some(entry) = self.deferred_wants.get_mut(&object_id) {
                        entry.attempts = entry.attempts.saturating_add(1);
                        entry.due = due;
                    }
                    return Ok(None);
                };
                if let Some(candidate) = self.deferred_wants.get_mut(&candidate_id) {
                    candidate.transport_epoch = None;
                }
            }
            let transfer_id = self.take_transfer_id()?;
            let sealed_ordinal = self.secure_records_sealed;
            let sealed = self.seal_plaintext(&plaintext)?;
            if sealed.capacity() > reserved_record_bytes {
                self.phase = SessionPhase::Failed;
                return Err(RuntimeError::BackendContract(
                    "secure record exceeded its bounded reservation",
                ));
            }
            let fragment_count = fragment::fragment(&sealed, usize::from(mtu), transfer_id)?.len();
            let entry = self
                .deferred_wants
                .get_mut(&object_id)
                .ok_or(RuntimeError::FailedState)?;
            entry.transport_epoch = Some(RetryTransportEpoch {
                transfer_id,
                sealed,
                repair_rounds: 0,
                emission_cursor: 0,
                repair_round_limit: transport_repair_round_limit(fragment_count),
                sealed_ordinal,
                mtu,
                semantic_digest,
            });
        }

        let entry = self
            .deferred_wants
            .get_mut(&object_id)
            .ok_or(RuntimeError::FailedState)?;
        let epoch = entry
            .transport_epoch
            .as_mut()
            .ok_or(RuntimeError::FailedState)?;
        let emission_cursor = epoch.emission_cursor;
        epoch.emission_cursor = epoch.emission_cursor.wrapping_add(1);
        Ok(Some(PreparedTransportDispatch {
            transfer_id: epoch.transfer_id,
            sealed: epoch.sealed.clone(),
            mtu: epoch.mtu,
            emission_cursor,
        }))
    }

    fn next_retry_deadline(
        now: Instant,
        priority: Priority,
        attempt: u16,
        link_floor: Duration,
    ) -> Instant {
        now.checked_add(Scheduler::retry_delay_with_floor(
            priority, attempt, link_floor,
        ))
        .unwrap_or(now)
    }

    fn flush(&mut self, link: &dyn Link, budget: &mut usize) -> Result<(), RuntimeError> {
        #[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
        enum DueWork {
            Outbox(u64),
            Retained(RetryKey),
            Deferred(ObjectId),
        }

        self.ensure_authorization_generation_current()?;
        let link_floor = link.retry_floor();

        if self
            .handshake_retry
            .as_ref()
            .is_some_and(|entry| entry.due <= self.clock)
            && *budget > 0
        {
            let mtu = link.characteristics().mtu;
            if self
                .handshake_retry
                .as_ref()
                .and_then(|entry| entry.mtu)
                .is_some_and(|pinned| pinned != mtu)
            {
                let transfer_id = self.take_transfer_id()?;
                let entry = self
                    .handshake_retry
                    .as_mut()
                    .ok_or(RuntimeError::FailedState)?;
                entry.transfer_id = transfer_id;
                entry.emission_cursor = 0;
            }
            let (transfer_id, bytes, emission_cursor) = {
                let entry = self
                    .handshake_retry
                    .as_mut()
                    .ok_or(RuntimeError::FailedState)?;
                entry.mtu = Some(mtu);
                let emission_cursor = entry.emission_cursor;
                entry.emission_cursor = entry.emission_cursor.wrapping_add(1);
                entry.due = Self::next_retry_deadline(
                    self.clock,
                    Priority::Flash,
                    entry.attempts,
                    link_floor,
                );
                entry.attempts = entry.attempts.saturating_add(1);
                (entry.transfer_id, entry.bytes.clone(), emission_cursor)
            };
            *budget -= 1;
            self.send_retry_epoch(link, transfer_id, &bytes, mtu, emission_cursor)?;
        }

        let selected_semantic_version = self.authenticated_semantic_version();
        self.outbox
            .retain(|entry| Some(entry.semantic_version) == selected_semantic_version);

        let active_exchange = self.sync.active_exchange_id();
        self.retries.retain(|key, entry| {
            active_exchange.is_some_and(|exchange_id| retry_exchange_id(key) == exchange_id)
                && Some(entry.semantic_version) == selected_semantic_version
        });
        let live_wants: BTreeSet<_> = self.sync.wants().iter().map(|(id, _)| *id).collect();
        self.deferred_wants.retain(|object_id, entry| {
            active_exchange == Some(entry.exchange_id)
                && live_wants.contains(object_id)
                && Some(entry.semantic_version) == selected_semantic_version
        });

        // Promote due durable WANTs back into the retained retry set whenever
        // capacity becomes available. A higher-precedence WANT may displace a
        // lower-precedence expendable NODE/WANT/DATA entry. If no retained
        // space exists, the compact durable marker remains and is sent once
        // below, so saturation never silently abandons receiver progress.
        let mut promotions: Vec<_> = self
            .deferred_wants
            .iter()
            .filter(|(_, entry)| entry.due <= self.clock)
            .map(|(object_id, entry)| (*object_id, entry.priority, entry.sequence))
            .collect();
        promotions.sort_by(|left, right| {
            right
                .1
                .cmp(&left.1)
                .then_with(|| left.2.cmp(&right.2))
                .then_with(|| left.0.cmp(&right.0))
        });
        for (object_id, priority, _) in promotions.into_iter().take(*budget) {
            let Some(entry) = self.deferred_wants.get(&object_id).cloned() else {
                continue;
            };
            let Some(item) = self.sync.retry_want_item(object_id) else {
                self.deferred_wants.remove(&object_id);
                continue;
            };
            self.queue_retry_message(
                RetryKey::Want(entry.exchange_id, object_id),
                Message::Want(crate::wire::Want {
                    exchange_id: entry.exchange_id,
                    items: vec![item],
                }),
                priority,
            )?;
        }

        let mut due: Vec<_> = self
            .outbox
            .iter()
            .filter(|entry| entry.due <= self.clock)
            .map(|entry| {
                (
                    DueWork::Outbox(entry.sequence),
                    entry.priority,
                    entry.sequence,
                )
            })
            .chain(
                self.retries
                    .iter()
                    .filter(|(_, entry)| entry.due <= self.clock)
                    .map(|(key, entry)| {
                        (
                            DueWork::Retained(key.clone()),
                            entry.priority,
                            entry.sequence,
                        )
                    }),
            )
            .chain(
                self.deferred_wants
                    .iter()
                    .filter(|(_, entry)| entry.due <= self.clock)
                    .map(|(object_id, entry)| {
                        (
                            DueWork::Deferred(*object_id),
                            entry.priority,
                            entry.sequence,
                        )
                    }),
            )
            .collect();
        due.sort_by(|left, right| {
            right
                .1
                .cmp(&left.1)
                .then_with(|| left.2.cmp(&right.2))
                .then_with(|| left.0.cmp(&right.0))
        });
        for (work, _, _) in due.into_iter() {
            if *budget == 0 {
                break;
            }
            match work {
                DueWork::Outbox(sequence) => {
                    let Some(prepared) =
                        self.prepare_outbox_transport_epoch(sequence, link.characteristics().mtu)?
                    else {
                        continue;
                    };
                    let entry = self
                        .outbox
                        .iter_mut()
                        .find(|entry| entry.sequence == sequence)
                        .ok_or(RuntimeError::FailedState)?;
                    entry.due = Self::next_retry_deadline(
                        self.clock,
                        entry.priority,
                        entry.attempts,
                        link_floor,
                    );
                    entry.attempts = entry.attempts.saturating_add(1);
                    *budget -= 1;
                    self.send_retry_epoch(
                        link,
                        prepared.transfer_id,
                        &prepared.sealed,
                        prepared.mtu,
                        prepared.emission_cursor,
                    )?;
                    if let Some(position) = self
                        .outbox
                        .iter()
                        .position(|entry| entry.sequence == sequence)
                    {
                        self.outbox.remove(position);
                    }
                }
                DueWork::Retained(key) => {
                    if !self.refresh_retry(&key)? {
                        continue;
                    }
                    let Some((transfer_id, sealed)) =
                        self.prepare_retry_transport_epoch(&key, link.characteristics().mtu)?
                    else {
                        continue;
                    };
                    let (mtu, emission_cursor) = {
                        let entry = self
                            .retries
                            .get_mut(&key)
                            .ok_or(RuntimeError::FailedState)?;
                        entry.due = Self::next_retry_deadline(
                            self.clock,
                            entry.priority,
                            entry.attempts,
                            link_floor,
                        );
                        entry.attempts = entry.attempts.saturating_add(1);
                        let epoch = entry
                            .transport_epoch
                            .as_mut()
                            .ok_or(RuntimeError::FailedState)?;
                        let emission_cursor = epoch.emission_cursor;
                        epoch.emission_cursor = epoch.emission_cursor.wrapping_add(1);
                        (epoch.mtu, emission_cursor)
                    };
                    *budget -= 1;
                    self.send_retry_epoch(link, transfer_id, &sealed, mtu, emission_cursor)?;
                    if let Some(entry) = self.retries.get_mut(&key) {
                        if let Some(epoch) = entry.transport_epoch.as_mut() {
                            epoch.repair_rounds = epoch.repair_rounds.saturating_add(1);
                        }
                        entry.unchanged_sends = entry.unchanged_sends.saturating_add(1);
                    }
                }
                DueWork::Deferred(object_id) => {
                    let Some(entry) = self.deferred_wants.get(&object_id).cloned() else {
                        continue;
                    };
                    let Some(item) = self.sync.retry_want_item(object_id) else {
                        self.deferred_wants.remove(&object_id);
                        continue;
                    };
                    let message = Message::Want(crate::wire::Want {
                        exchange_id: entry.exchange_id,
                        items: vec![item],
                    });
                    let Some(prepared) = self.prepare_deferred_want_epoch(
                        object_id,
                        &message,
                        link.characteristics().mtu,
                    )?
                    else {
                        continue;
                    };
                    let current = self
                        .deferred_wants
                        .get_mut(&object_id)
                        .ok_or(RuntimeError::FailedState)?;
                    current.due = Self::next_retry_deadline(
                        self.clock,
                        current.priority,
                        current.attempts,
                        link_floor,
                    );
                    current.attempts = current.attempts.saturating_add(1);
                    *budget -= 1;
                    self.send_retry_epoch(
                        link,
                        prepared.transfer_id,
                        &prepared.sealed,
                        prepared.mtu,
                        prepared.emission_cursor,
                    )?;
                    if let Some(current) = self.deferred_wants.get_mut(&object_id)
                        && let Some(epoch) = current.transport_epoch.as_mut()
                    {
                        epoch.repair_rounds = epoch.repair_rounds.saturating_add(1);
                    }
                }
            }
        }
        Ok(())
    }
}

fn ensure_object_allowed(object_id: ObjectId, semantic_version: u16) -> Result<(), RuntimeError> {
    wire::validate_semantic_version(semantic_version)?;
    if object_id
        .kind()
        .is_allowed_in_semantic_version(semantic_version)
    {
        Ok(())
    } else {
        Err(RuntimeError::Wire(WireError::ObjectKindRequiresSemanticV2(
            object_id.kind(),
        )))
    }
}

fn retry_exchange_id(key: &RetryKey) -> u64 {
    match key {
        RetryKey::Interest(exchange_id)
        | RetryKey::Summary(exchange_id, _)
        | RetryKey::Probe(exchange_id, ..)
        | RetryKey::Node(exchange_id, ..)
        | RetryKey::Want(exchange_id, _)
        | RetryKey::Data(exchange_id, ..) => *exchange_id,
    }
}

fn retry_key(message: &Message) -> Result<Option<RetryKey>, RuntimeError> {
    Ok(match message {
        Message::Interest(interest) => Some(RetryKey::Interest(interest.exchange_id)),
        Message::Summary(summary) => {
            Some(RetryKey::Summary(summary.exchange_id, summary.snapshot_id))
        }
        Message::Probe(probe) => Some(RetryKey::Probe(
            probe.exchange_id,
            probe.snapshot_id,
            probe.prefix_nibbles,
            probe.prefix.clone(),
        )),
        Message::Node(node) => Some(RetryKey::Node(
            node.exchange_id,
            node.snapshot_id,
            node.prefix_nibbles,
            node.prefix.clone(),
        )),
        Message::Want(want) => want
            .items
            .first()
            .map(|item| RetryKey::Want(want.exchange_id, item.object_id)),
        Message::Data(data) => {
            let end = data
                .offset
                .checked_add(
                    u64::try_from(data.payload.len())
                        .map_err(|_| RuntimeError::BackendContract("DATA length overflow"))?,
                )
                .ok_or(RuntimeError::BackendContract("DATA extent overflow"))?;
            Some(RetryKey::Data(
                data.exchange_id,
                data.object_id,
                data.total_len,
                data.offset,
                end,
            ))
        }
        Message::Offer(_) | Message::Receipt(_) => None,
    })
}

fn transport_record_reservation(plaintext: &[u8]) -> usize {
    plaintext
        .len()
        .saturating_add(128)
        .checked_next_power_of_two()
        .unwrap_or(usize::MAX)
}

fn transport_repair_round_limit(fragment_count: usize) -> u16 {
    u16::try_from(fragment_count)
        .unwrap_or(u16::MAX)
        .saturating_add(MIN_RECORD_REPAIR_ROUNDS)
        .max(MIN_RECORD_REPAIR_ROUNDS)
}

fn transport_fragment_emission_offset(fragment_count: usize, repair_round: u16) -> usize {
    if fragment_count <= 1 {
        return 0;
    }
    let mut stride = fragment_count / 2 + 1;
    while greatest_common_divisor(stride, fragment_count) != 1 {
        stride = stride.saturating_add(1);
    }
    usize::from(repair_round).saturating_mul(stride) % fragment_count
}

fn greatest_common_divisor(mut left: usize, mut right: usize) -> usize {
    while right != 0 {
        let remainder = left % right;
        left = right;
        right = remainder;
    }
    left
}

fn retry_record_bytes(key: &RetryKey, message: &Message, record_reservation: usize) -> usize {
    let key_heap_bytes = match key {
        RetryKey::Probe(_, _, _, prefix) | RetryKey::Node(_, _, _, prefix) => prefix.capacity(),
        RetryKey::Interest(_)
        | RetryKey::Summary(_, _)
        | RetryKey::Want(_, _)
        | RetryKey::Data(_, _, _, _, _) => 0,
    };
    let heap_bytes = match message {
        Message::Interest(interest) => interest
            .topics
            .capacity()
            .saturating_mul(std::mem::size_of::<String>())
            .saturating_add(interest.topics.iter().map(String::capacity).sum::<usize>())
            .saturating_add(
                interest
                    .scopes
                    .capacity()
                    .saturating_mul(std::mem::size_of::<String>()),
            )
            .saturating_add(interest.scopes.iter().map(String::capacity).sum::<usize>()),
        Message::Summary(_) => 0,
        Message::Probe(probe) => probe.prefix.capacity(),
        Message::Node(node) => node.prefix.capacity().saturating_add(
            node.children
                .capacity()
                .saturating_mul(std::mem::size_of::<crate::wire::ChildSummary>()),
        ),
        Message::Offer(offer) => offer
            .object_ids
            .capacity()
            .saturating_mul(std::mem::size_of::<ObjectId>()),
        Message::Want(want) => want
            .items
            .capacity()
            .saturating_mul(std::mem::size_of::<WantItem>())
            .saturating_add(
                want.items
                    .iter()
                    .map(|item| {
                        item.missing
                            .capacity()
                            .saturating_mul(std::mem::size_of::<ByteRange>())
                    })
                    .sum::<usize>(),
            ),
        Message::Data(data) => data
            .payload
            .capacity()
            .saturating_add(data.forwarding.capacity()),
        Message::Receipt(receipt) => receipt
            .received
            .capacity()
            .saturating_mul(std::mem::size_of::<ByteRange>()),
    };
    std::mem::size_of::<Message>()
        .saturating_add(key_heap_bytes)
        .saturating_add(heap_bytes)
        .saturating_add(record_reservation)
}

fn packed_prefix_is_strict_parent(
    parent: &[u8],
    parent_nibbles: u8,
    child: &[u8],
    child_nibbles: u8,
) -> bool {
    if parent_nibbles >= child_nibbles {
        return false;
    }
    (0..parent_nibbles).all(|index| {
        let index = usize::from(index);
        let parent_nibble = if index & 1 == 0 {
            parent[index / 2] >> 4
        } else {
            parent[index / 2] & 0x0f
        };
        let child_nibble = if index & 1 == 0 {
            child[index / 2] >> 4
        } else {
            child[index / 2] & 0x0f
        };
        parent_nibble == child_nibble
    })
}

/// Engine plus encrypted Blob carrier store used by the authenticated runtime.
/// Source envelopes remain the sole authorization root for every advertised or
/// accepted Blob chunk object.
pub struct BlobRuntimeBackend<S: RecordStore, E: EnvelopeSealer> {
    node: Node<S, E>,
    blobs: BlobTransferStore,
    serve_routes: BTreeMap<ObjectId, AuthenticatedBlobRoute>,
}

impl<S: RecordStore, E: EnvelopeSealer> BlobRuntimeBackend<S, E> {
    pub fn new(node: Node<S, E>, blobs: BlobTransferStore) -> Self {
        Self {
            node,
            blobs,
            serve_routes: BTreeMap::new(),
        }
    }

    pub fn node(&self) -> &Node<S, E> {
        &self.node
    }

    pub fn node_mut(&mut self) -> &mut Node<S, E> {
        &mut self.node
    }

    pub fn blobs(&self) -> &BlobTransferStore {
        &self.blobs
    }

    pub fn blobs_mut(&mut self) -> &mut BlobTransferStore {
        &mut self.blobs
    }

    pub fn into_parts(self) -> (Node<S, E>, BlobTransferStore) {
        (self.node, self.blobs)
    }

    /// Removes ordinary Blob serve grants rooted in source representations
    /// which a semantic wrapper will replace before publishing its inventory.
    pub(crate) fn discard_serve_routes_for_sources(
        &mut self,
        sources: &BTreeSet<EnvelopeId>,
    ) -> Vec<ObjectId> {
        let removed = self
            .serve_routes
            .iter()
            .filter_map(|(object_id, route)| {
                sources
                    .contains(&route.source_envelope())
                    .then_some(*object_id)
            })
            .collect::<Vec<_>>();
        for object_id in &removed {
            self.serve_routes.remove(object_id);
        }
        removed
    }

    pub(crate) fn blob_object_ids_for_source(
        &mut self,
        source_envelope: EnvelopeId,
        limit: usize,
    ) -> Result<Vec<ObjectId>, BlobRuntimeError> {
        let Some((route, _, _)) = self.authenticated_blob_source(source_envelope)? else {
            return Ok(Vec::new());
        };
        Ok(self.blobs.object_ids_for_route(route, limit)?)
    }

    fn authenticated_blob_source(
        &mut self,
        source_envelope: EnvelopeId,
    ) -> Result<
        Option<(
            AuthenticatedBlobRoute,
            crate::engine::VerifiedEnvelope,
            Vec<u8>,
        )>,
        BlobRuntimeError,
    > {
        // Format-3 compact batch items share ObjectKind::SourceEnvelope with
        // singleton sources, but require their exact BatchProof before the
        // envelope provider can authenticate them. The semantic-v2 wrapper
        // owns that dependency-aware path.
        if self
            .node
            .store_mut()
            .get_by_envelope(&source_envelope.into_bytes())
            .map_err(EngineError::Store)?
            .is_some_and(|item| item.sealed.starts_with(b"ASTRENV3"))
        {
            return Ok(None);
        }
        let Some((verified, sealed)) = self.node.inspect_stored_data_envelope(source_envelope)?
        else {
            return Ok(None);
        };
        let Some(commitment) = verified.header.blob_route else {
            return Ok(None);
        };
        Ok(Some((
            AuthenticatedBlobRoute::new(source_envelope, commitment),
            verified,
            sealed,
        )))
    }

    fn install_manifest_if_authorized(
        &mut self,
        source_envelope: EnvelopeId,
    ) -> Result<(), BlobRuntimeError> {
        let Some((route, verified, sealed)) = self.authenticated_blob_source(source_envelope)?
        else {
            return Ok(());
        };
        let Some(manifest) = self
            .node
            .open_verified_payload_if_authorized(&verified, &sealed)?
        else {
            return Ok(());
        };
        self.blobs.install_authenticated_manifest(
            &manifest,
            &verified.header.scope,
            &verified.header.topic,
            verified.header.key_epoch,
            route,
        )?;
        Ok(())
    }
}

#[derive(Debug)]
pub enum BlobRuntimeError {
    Engine(EngineError),
    Blob(BlobError),
    AuthorityUnavailable,
    AuthorityPoisoned,
    Invalid(&'static str),
}

impl fmt::Display for BlobRuntimeError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Engine(error) => write!(formatter, "engine: {error}"),
            Self::Blob(error) => write!(formatter, "Blob: {error}"),
            Self::AuthorityUnavailable => {
                formatter.write_str("semantic runtime authority is unavailable")
            }
            Self::AuthorityPoisoned => {
                formatter.write_str("semantic runtime authority lock is poisoned")
            }
            Self::Invalid(message) => formatter.write_str(message),
        }
    }
}

impl std::error::Error for BlobRuntimeError {}

impl From<EngineError> for BlobRuntimeError {
    fn from(error: EngineError) -> Self {
        Self::Engine(error)
    }
}

impl From<BlobError> for BlobRuntimeError {
    fn from(error: BlobError) -> Self {
        Self::Blob(error)
    }
}

fn terminal_engine_commit_error(error: &EngineError) -> bool {
    !matches!(error, EngineError::Store(_))
}

fn terminal_blob_commit_error(error: &BlobError) -> bool {
    !matches!(
        error,
        BlobError::Io(_) | BlobError::Store(_) | BlobError::MissingChunk
    )
}

impl BlobRuntimeError {
    fn is_terminal_commit_failure(&self) -> bool {
        match self {
            Self::Engine(error) => terminal_engine_commit_error(error),
            Self::Blob(error) => terminal_blob_commit_error(error),
            Self::AuthorityUnavailable | Self::AuthorityPoisoned => false,
            Self::Invalid(_) => true,
        }
    }
}

impl<S: RecordStore, E: EnvelopeSealer> RuntimeBackend for BlobRuntimeBackend<S, E> {
    type Error = BlobRuntimeError;

    fn authorize_adjacency(&mut self, authenticated_peer: NodeId) -> Result<(), Self::Error> {
        self.node.authorize_peer(authenticated_peer)?;
        Ok(())
    }

    fn durable_progress(
        &mut self,
        limit: usize,
    ) -> Result<Vec<RuntimeTransferProgress>, Self::Error> {
        Ok(self
            .node
            .durable_transfer_progress(limit)?
            .into_iter()
            .map(|entry| RuntimeTransferProgress {
                object_id: entry.object_id,
                origin_semantic_version: entry.origin_semantic_version,
                total_len: entry.total_len,
                received: entry.received.into_iter().map(Into::into).collect(),
            })
            .collect())
    }

    fn durable_progress_for_semantic_version(
        &mut self,
        limit: usize,
        semantic_version: u16,
    ) -> Result<Vec<RuntimeTransferProgress>, Self::Error> {
        Ok(self
            .node
            .store_mut()
            .transfer_progress_for_semantic_version(semantic_version, limit)
            .map_err(EngineError::Store)?
            .into_iter()
            .map(|entry| RuntimeTransferProgress {
                object_id: entry.object_id,
                origin_semantic_version: entry.origin_semantic_version,
                total_len: entry.total_len,
                received: entry.received.into_iter().map(Into::into).collect(),
            })
            .collect())
    }

    fn durably_disposed_object_len(
        &mut self,
        _object_id: ObjectId,
        _semantic_version: u16,
    ) -> Result<Option<u64>, Self::Error> {
        // This backend's completion seam produces only committed objects.
        Ok(None)
    }

    fn abort_object(&mut self, object_id: ObjectId) -> Result<(), Self::Error> {
        self.node.abort_transfer(object_id)?;
        Ok(())
    }

    fn select_authorized_inventory(
        &mut self,
        authenticated_peer: NodeId,
        peer_route_commitments: &[[u8; 32]],
        filter: &InterestFilter,
        purpose: InventoryPurpose,
    ) -> Result<SparseInventory, Self::Error> {
        let descriptors = self.node.authorized_envelopes(
            authenticated_peer,
            peer_route_commitments,
            filter,
            purpose,
        )?;
        if purpose == InventoryPurpose::ServePeer {
            self.serve_routes.clear();
        }
        let configured_chunk_limit = usize::try_from(self.blobs.config().max_chunks)
            .unwrap_or(usize::MAX)
            .min(MAX_COMPOSITE_INVENTORY_OBJECTS);
        let mut ids = BTreeSet::new();
        for descriptor in &descriptors {
            if ids.len() >= MAX_COMPOSITE_INVENTORY_OBJECTS {
                break;
            }
            ids.insert(ObjectId::for_envelope(descriptor.envelope_id));
        }
        for descriptor in descriptors {
            let remaining = configured_chunk_limit
                .min(MAX_COMPOSITE_INVENTORY_OBJECTS.saturating_sub(ids.len()));
            if remaining == 0 {
                break;
            }
            let Some((route, _verified, _sealed)) =
                self.authenticated_blob_source(descriptor.envelope_id)?
            else {
                continue;
            };
            for object_id in self.blobs.object_ids_for_route(route, remaining)? {
                if purpose == InventoryPurpose::ServePeer {
                    self.serve_routes.insert(object_id, route);
                }
                ids.insert(object_id);
            }
        }
        Ok(SparseInventory::from_ids(ids))
    }

    fn store_object_chunk(
        &mut self,
        object_id: ObjectId,
        total_len: u64,
        offset: u64,
        bytes: &[u8],
    ) -> Result<(), Self::Error> {
        self.node
            .store_transfer_chunk(object_id, total_len, offset, bytes)?;
        Ok(())
    }

    fn store_object_chunk_for_semantic_version(
        &mut self,
        object_id: ObjectId,
        total_len: u64,
        offset: u64,
        bytes: &[u8],
        semantic_version: u16,
    ) -> Result<(), Self::Error> {
        self.node.store_transfer_chunk_for_semantic_version(
            object_id,
            total_len,
            offset,
            bytes,
            semantic_version,
        )?;
        Ok(())
    }

    fn complete_object_bytes(
        &mut self,
        object_id: ObjectId,
        total_len: u64,
    ) -> Result<Vec<u8>, Self::Error> {
        Ok(self.node.complete_transfer_object(object_id, total_len)?)
    }

    fn commit_authenticated_object(
        &mut self,
        authenticated_peer: NodeId,
        exchange_id: u64,
        object_id: ObjectId,
        bytes: Vec<u8>,
        forwarding: Vec<u8>,
    ) -> Result<Option<ItemId>, Self::Error> {
        match object_id.kind() {
            ObjectKind::SourceEnvelope => {
                let item_id = <Node<S, E> as RuntimeBackend>::commit_authenticated_object(
                    &mut self.node,
                    authenticated_peer,
                    exchange_id,
                    object_id,
                    bytes,
                    forwarding,
                )?;
                let source_envelope = object_id
                    .envelope_id()
                    .ok_or(BlobRuntimeError::Invalid("source object kind mismatch"))?;
                self.install_manifest_if_authorized(source_envelope)?;
                Ok(item_id)
            }
            ObjectKind::BlobChunk => {
                if !forwarding.is_empty() {
                    return Err(BlobRuntimeError::Invalid(
                        "Blob chunk forwarding metadata is forbidden",
                    ));
                }
                let inspected = inspect_blob_transfer_object(&bytes)?;
                if inspected.object_id() != object_id {
                    return Err(BlobRuntimeError::Invalid("Blob carrier identity mismatch"));
                }
                let Some((route, _verified, _sealed)) =
                    self.authenticated_blob_source(inspected.source_envelope())?
                else {
                    return Err(BlobRuntimeError::Invalid(
                        "Blob carrier source envelope is unavailable",
                    ));
                };
                self.blobs.commit_carrier(object_id, &bytes, route)?;
                self.node.finish_transfer(object_id)?;
                Ok(None)
            }
            ObjectKind::SourceBatchProof
            | ObjectKind::BridgeAuthorization
            | ObjectKind::BridgeRouteWrapper => Err(BlobRuntimeError::Invalid(
                "semantic-v2 transfer object storage is not installed",
            )),
        }
    }

    fn is_terminal_commit_error(&self, error: &Self::Error) -> bool {
        error.is_terminal_commit_failure()
    }

    fn object_priority(&mut self, object_id: ObjectId) -> Result<Priority, Self::Error> {
        let source_envelope = match object_id.kind() {
            ObjectKind::SourceEnvelope => object_id
                .envelope_id()
                .ok_or(BlobRuntimeError::Invalid("source object kind mismatch"))?,
            ObjectKind::BlobChunk => self
                .serve_routes
                .get(&object_id)
                .map(|route| route.source_envelope())
                .ok_or(BlobRuntimeError::Invalid(
                    "Blob chunk was not in the authorized served inventory",
                ))?,
            ObjectKind::SourceBatchProof
            | ObjectKind::BridgeAuthorization
            | ObjectKind::BridgeRouteWrapper => {
                return Err(BlobRuntimeError::Invalid(
                    "semantic-v2 transfer object storage is not installed",
                ));
            }
        };
        Ok(self
            .node
            .inspect_stored_data_envelope(source_envelope)?
            .map(|(verified, _)| verified.header.priority)
            .unwrap_or(Priority::Routine))
    }

    fn data_for_want(
        &mut self,
        authenticated_peer: NodeId,
        peer_route_commitments: &[[u8; 32]],
        exchange_id: u64,
        want: &WantItem,
    ) -> Result<Vec<Data>, Self::Error> {
        match want.object_id.kind() {
            ObjectKind::SourceEnvelope => {
                return <Node<S, E> as RuntimeBackend>::data_for_want(
                    &mut self.node,
                    authenticated_peer,
                    peer_route_commitments,
                    exchange_id,
                    want,
                )
                .map_err(Into::into);
            }
            ObjectKind::BlobChunk => {}
            ObjectKind::SourceBatchProof
            | ObjectKind::BridgeAuthorization
            | ObjectKind::BridgeRouteWrapper => {
                return Err(BlobRuntimeError::Invalid(
                    "semantic-v2 transfer object storage is not installed",
                ));
            }
        }
        if want.need_forwarding {
            return Err(BlobRuntimeError::Invalid(
                "Blob chunk WANT requested forwarding metadata",
            ));
        }
        let route =
            self.serve_routes
                .get(&want.object_id)
                .copied()
                .ok_or(BlobRuntimeError::Invalid(
                    "Blob chunk was not in the authorized served inventory",
                ))?;
        // Repeat peer authorization at serve time against the source envelope.
        self.node.read_authorized_envelope_range(
            authenticated_peer,
            peer_route_commitments,
            route.source_envelope(),
            ChunkRange {
                start: 0,
                end: u64::MAX,
            },
            0,
        )?;
        if want.missing.is_empty() && want.total_len.is_some() {
            return Ok(Vec::new());
        }
        let requested = if want.missing.is_empty() {
            vec![ByteRange {
                start: 0,
                end: u64::MAX,
            }]
        } else {
            want.missing.clone()
        };
        let mut data = Vec::new();
        for requested_range in requested {
            let mut offset = requested_range.start;
            while offset < requested_range.end && data.len() < MAX_DATA_MESSAGES_PER_WANT {
                let range_budget = requested_range.end.saturating_sub(offset);
                let max_bytes = usize::try_from(range_budget)
                    .unwrap_or(usize::MAX)
                    .min(MAX_DATA_PAYLOAD_BYTES);
                let (total_len, payload) =
                    self.blobs
                        .read_object_range(route, want.object_id, offset, max_bytes)?;
                if let Some(expected) = want.total_len
                    && expected != total_len
                {
                    return Err(BlobRuntimeError::Invalid(
                        "wanted Blob carrier length changed",
                    ));
                }
                if payload.is_empty() {
                    break;
                }
                let payload_len = u64::try_from(payload.len())
                    .map_err(|_| BlobRuntimeError::Invalid("Blob DATA payload length overflow"))?;
                data.push(Data {
                    exchange_id,
                    object_id: want.object_id,
                    total_len,
                    offset,
                    payload,
                    forwarding: Vec::new(),
                });
                offset = offset.saturating_add(payload_len);
                if offset >= total_len {
                    break;
                }
            }
            if data.len() >= MAX_DATA_MESSAGES_PER_WANT {
                break;
            }
        }
        Ok(data)
    }
}

impl<S: RecordStore, E: crate::engine::EnvelopeSealer> RuntimeBackend for Node<S, E> {
    type Error = EngineError;

    fn authorize_adjacency(&mut self, authenticated_peer: NodeId) -> Result<(), Self::Error> {
        self.authorize_peer(authenticated_peer)
    }

    fn durable_progress(
        &mut self,
        limit: usize,
    ) -> Result<Vec<RuntimeTransferProgress>, Self::Error> {
        self.durable_transfer_progress(limit).map(|entries| {
            entries
                .into_iter()
                .map(|entry| RuntimeTransferProgress {
                    object_id: entry.object_id,
                    origin_semantic_version: entry.origin_semantic_version,
                    total_len: entry.total_len,
                    received: entry.received.into_iter().map(Into::into).collect(),
                })
                .collect()
        })
    }

    fn durable_progress_for_semantic_version(
        &mut self,
        limit: usize,
        semantic_version: u16,
    ) -> Result<Vec<RuntimeTransferProgress>, Self::Error> {
        self.store_mut()
            .transfer_progress_for_semantic_version(semantic_version, limit)
            .map(|entries| {
                entries
                    .into_iter()
                    .map(|entry| RuntimeTransferProgress {
                        object_id: entry.object_id,
                        origin_semantic_version: entry.origin_semantic_version,
                        total_len: entry.total_len,
                        received: entry.received.into_iter().map(Into::into).collect(),
                    })
                    .collect()
            })
            .map_err(Into::into)
    }

    fn durably_disposed_object_len(
        &mut self,
        _object_id: ObjectId,
        _semantic_version: u16,
    ) -> Result<Option<u64>, Self::Error> {
        // This backend's completion seam produces only committed objects.
        Ok(None)
    }

    fn select_authorized_inventory(
        &mut self,
        authenticated_peer: NodeId,
        peer_route_commitments: &[[u8; 32]],
        filter: &InterestFilter,
        purpose: InventoryPurpose,
    ) -> Result<SparseInventory, Self::Error> {
        let descriptors =
            self.authorized_envelopes(authenticated_peer, peer_route_commitments, filter, purpose)?;
        Ok(SparseInventory::from_ids(
            descriptors
                .into_iter()
                .map(|entry| ObjectId::for_envelope(entry.envelope_id)),
        ))
    }

    fn store_object_chunk(
        &mut self,
        object_id: ObjectId,
        total_len: u64,
        offset: u64,
        bytes: &[u8],
    ) -> Result<(), Self::Error> {
        self.store_transfer_chunk(object_id, total_len, offset, bytes)
    }

    fn store_object_chunk_for_semantic_version(
        &mut self,
        object_id: ObjectId,
        total_len: u64,
        offset: u64,
        bytes: &[u8],
        semantic_version: u16,
    ) -> Result<(), Self::Error> {
        self.store_transfer_chunk_for_semantic_version(
            object_id,
            total_len,
            offset,
            bytes,
            semantic_version,
        )
    }

    fn complete_object_bytes(
        &mut self,
        object_id: ObjectId,
        total_len: u64,
    ) -> Result<Vec<u8>, Self::Error> {
        self.complete_transfer_object(object_id, total_len)
    }

    fn abort_object(&mut self, object_id: ObjectId) -> Result<(), Self::Error> {
        self.abort_transfer(object_id)
    }

    fn commit_authenticated_object(
        &mut self,
        authenticated_peer: NodeId,
        exchange_id: u64,
        object_id: ObjectId,
        sealed: Vec<u8>,
        forwarding: Vec<u8>,
    ) -> Result<Option<ItemId>, Self::Error> {
        let envelope_id = object_id.envelope_id().ok_or_else(|| {
            EngineError::Invalid("Node backend only accepts source envelopes".into())
        })?;
        // The durable envelope commit and retirement of its resumable transfer
        // live in different stores.  If power is lost between those writes,
        // hydration presents the completed transfer again without the
        // ephemeral hop-forwarding record.  Only accept that replay when the
        // exact bytes are already present under the authenticated envelope
        // identity; a first-time ingest must still prove the live adjacency.
        if forwarding.is_empty()
            && let Some((verified, stored)) = self.inspect_stored_data_envelope(envelope_id)?
            && stored == sealed
        {
            self.finish_transfer(object_id)?;
            return Ok(Some(verified.id));
        }
        let item_id = match self.ingest_forwarded(
            authenticated_peer,
            exchange_id,
            envelope_id,
            &sealed,
            &forwarding,
        )? {
            ForwardedIngest::Data(receipt) => Some(match receipt.outcome {
                ApplyOutcome::Inserted { id, .. } | ApplyOutcome::Duplicate { id } => id,
            }),
            ForwardedIngest::Control(_) => None,
        };
        self.finish_transfer(object_id)?;
        Ok(item_id)
    }

    fn is_terminal_commit_error(&self, error: &Self::Error) -> bool {
        terminal_engine_commit_error(error)
    }

    fn object_priority(&mut self, object_id: ObjectId) -> Result<Priority, Self::Error> {
        let envelope_id = object_id.envelope_id().ok_or_else(|| {
            EngineError::Invalid("Node backend only schedules source envelopes".into())
        })?;
        Ok(self
            .inspect_stored_data_envelope(envelope_id)?
            .map(|(verified, _)| verified.header.priority)
            .unwrap_or(Priority::Routine))
    }

    fn data_for_want(
        &mut self,
        authenticated_peer: NodeId,
        peer_route_commitments: &[[u8; 32]],
        exchange_id: u64,
        want: &WantItem,
    ) -> Result<Vec<Data>, Self::Error> {
        let envelope_id = want.object_id.envelope_id().ok_or_else(|| {
            EngineError::Invalid("Node backend only serves source envelopes".into())
        })?;
        let forwarding = if want.need_forwarding {
            self.forwarding_for_envelope(
                authenticated_peer,
                peer_route_commitments,
                exchange_id,
                envelope_id,
            )?
        } else {
            Vec::new()
        };
        if want.missing.is_empty() && want.total_len.is_some() {
            let (total_len, _, _) = self.read_authorized_envelope_range(
                authenticated_peer,
                peer_route_commitments,
                envelope_id,
                ChunkRange {
                    start: 0,
                    end: u64::MAX,
                },
                0,
            )?;
            return Ok(if forwarding.is_empty() {
                Vec::new()
            } else {
                vec![Data {
                    exchange_id,
                    object_id: want.object_id,
                    total_len,
                    offset: 0,
                    payload: Vec::new(),
                    forwarding,
                }]
            });
        }

        let requested = if want.missing.is_empty() {
            vec![ByteRange {
                start: 0,
                end: u64::MAX,
            }]
        } else {
            want.missing.clone()
        };
        let mut data = Vec::new();
        let mut first = true;
        for requested_range in requested {
            let mut offset = requested_range.start;
            while offset < requested_range.end {
                let end = requested_range
                    .end
                    .min(offset.saturating_add(MAX_DATA_PAYLOAD_BYTES as u64));
                let (total_len, _, payload) = self.read_authorized_envelope_range(
                    authenticated_peer,
                    peer_route_commitments,
                    envelope_id,
                    ChunkRange { start: offset, end },
                    MAX_DATA_PAYLOAD_BYTES,
                )?;
                if let Some(expected) = want.total_len
                    && expected != total_len
                {
                    return Err(EngineError::Invalid(
                        "wanted envelope length changed".into(),
                    ));
                }
                if payload.is_empty() {
                    break;
                }
                let payload_len = payload.len() as u64;
                data.push(Data {
                    exchange_id,
                    object_id: want.object_id,
                    total_len,
                    offset,
                    payload,
                    forwarding: if first {
                        forwarding.clone()
                    } else {
                        Vec::new()
                    },
                });
                first = false;
                offset = offset.saturating_add(payload_len);
                if offset >= total_len || data.len() >= MAX_DATA_MESSAGES_PER_WANT {
                    break;
                }
            }
            if data.len() >= MAX_DATA_MESSAGES_PER_WANT {
                break;
            }
        }
        Ok(data)
    }
}

#[cfg(test)]
mod tests {
    #[cfg(feature = "adapter-sdk")]
    mod batch;
    #[cfg(feature = "adapter-sdk")]
    mod record;

    use super::*;
    use crate::blob::{BlobMetadata, BlobStoreConfig, MAX_BLOB_CHUNK_SIZE};
    use crate::crypto::{
        ProvisioningAccess, ReferenceProvisioner, SessionPrivacyCanaries, open_reference_node,
        session_privacy_canaries,
    };
    use crate::engine::{NodeConfig, PublishRequest};
    use crate::link::{LinkCharacteristics, ReceivedFrame};
    use crate::model::{DataClass, Priority, Scope, Topic};
    use crate::sync::SyncConfig;
    use std::collections::{BTreeMap, VecDeque};
    use std::fs;
    use std::io::Cursor;
    use std::path::PathBuf;
    use std::sync::{
        Arc, Mutex,
        atomic::{AtomicBool, AtomicU64, Ordering},
    };
    use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

    #[derive(Clone, Copy, Debug)]
    struct SeededLoss {
        state: u64,
        delivered: usize,
        dropped: usize,
    }

    impl SeededLoss {
        fn new(seed: u64) -> Self {
            Self {
                state: seed.max(1),
                delivered: 0,
                dropped: 0,
            }
        }

        fn drop_half(&mut self) -> bool {
            let mut value = self.state;
            value ^= value << 13;
            value ^= value >> 7;
            value ^= value << 17;
            self.state = value;
            let drop = value & 1 == 0;
            if drop {
                self.dropped += 1;
            } else {
                self.delivered += 1;
            }
            drop
        }
    }

    #[derive(Clone)]
    struct MemoryLink {
        name: &'static str,
        mtu: u16,
        local_route: Option<NodeId>,
        inbound: Arc<Mutex<VecDeque<ReceivedFrame>>>,
        outbound: Arc<Mutex<VecDeque<ReceivedFrame>>>,
        capture: Arc<Mutex<Vec<Vec<u8>>>>,
        targets: Arc<Mutex<Vec<Option<NodeId>>>>,
        receive_budget: Arc<Mutex<Option<usize>>>,
        loss: Arc<Mutex<Option<SeededLoss>>>,
        forced_drop_transfer: Arc<Mutex<Option<u64>>>,
    }

    impl MemoryLink {
        fn pair(mtu: u16) -> (Self, Self) {
            Self::pair_with_routes(mtu, None, None)
        }

        fn pair_with_routes(
            mtu: u16,
            left_route: Option<NodeId>,
            right_route: Option<NodeId>,
        ) -> (Self, Self) {
            let left = Arc::new(Mutex::new(VecDeque::new()));
            let right = Arc::new(Mutex::new(VecDeque::new()));
            let left_capture = Arc::new(Mutex::new(Vec::new()));
            let right_capture = Arc::new(Mutex::new(Vec::new()));
            let left_targets = Arc::new(Mutex::new(Vec::new()));
            let right_targets = Arc::new(Mutex::new(Vec::new()));
            let left_receive_budget = Arc::new(Mutex::new(None));
            let right_receive_budget = Arc::new(Mutex::new(None));
            let left_loss = Arc::new(Mutex::new(None));
            let right_loss = Arc::new(Mutex::new(None));
            let left_forced_drop = Arc::new(Mutex::new(None));
            let right_forced_drop = Arc::new(Mutex::new(None));
            (
                Self {
                    name: "memory-left",
                    mtu,
                    local_route: left_route,
                    inbound: left.clone(),
                    outbound: right.clone(),
                    capture: left_capture,
                    targets: left_targets,
                    receive_budget: left_receive_budget,
                    loss: left_loss,
                    forced_drop_transfer: left_forced_drop,
                },
                Self {
                    name: "memory-right",
                    mtu,
                    local_route: right_route,
                    inbound: right,
                    outbound: left,
                    capture: right_capture,
                    targets: right_targets,
                    receive_budget: right_receive_budget,
                    loss: right_loss,
                    forced_drop_transfer: right_forced_drop,
                },
            )
        }

        fn enable_seeded_half_loss(&self, seed: u64) {
            *self.loss.lock().unwrap() = Some(SeededLoss::new(seed));
        }

        fn force_drop_transfer(&self, transfer_id: u64) {
            *self.forced_drop_transfer.lock().unwrap() = Some(transfer_id);
        }

        fn loss_counts(&self) -> (usize, usize) {
            self.loss
                .lock()
                .unwrap()
                .as_ref()
                .map(|loss| (loss.delivered, loss.dropped))
                .unwrap_or_default()
        }

        fn allow_receives(&self, count: usize) {
            *self.receive_budget.lock().unwrap() = Some(count);
        }

        fn with_mtu(&self, mtu: u16) -> Self {
            let mut changed = self.clone();
            changed.mtu = mtu;
            changed
        }

        fn captured_logical_through(&self, maximum_transfer_id: u64) -> Vec<Vec<u8>> {
            let captured = self.capture.lock().unwrap();
            let mut reassembler =
                Reassembler::new(usize::try_from(maximum_transfer_id).unwrap_or(usize::MAX));
            let mut logical = Vec::new();
            for bytes in captured.iter() {
                let fragment = Fragment::decode(bytes).unwrap();
                if fragment.transfer_id <= maximum_transfer_id
                    && let Some(message) = reassembler.push(fragment).unwrap()
                {
                    logical.push(message);
                }
            }
            logical
        }
    }

    impl Link for MemoryLink {
        fn name(&self) -> &str {
            self.name
        }

        fn characteristics(&self) -> LinkCharacteristics {
            LinkCharacteristics {
                mtu: self.mtu,
                bits_per_second: Some(8_000),
                cost: 1,
                emission: 1,
                broadcast: false,
            }
        }

        fn send(&self, peer: Option<NodeId>, frame: &[u8]) -> io::Result<()> {
            self.capture
                .lock()
                .map_err(|_| io::Error::other("memory link capture poisoned"))?
                .push(frame.to_vec());
            self.targets
                .lock()
                .map_err(|_| io::Error::other("memory link targets poisoned"))?
                .push(peer);
            let transfer_id = Fragment::decode(frame)
                .map_err(|_| io::Error::other("memory link received invalid fragment"))?
                .transfer_id;
            if self
                .forced_drop_transfer
                .lock()
                .map_err(|_| io::Error::other("memory link forced loss poisoned"))?
                .is_some_and(|forced| forced == transfer_id)
            {
                return Ok(());
            }
            if self
                .loss
                .lock()
                .map_err(|_| io::Error::other("memory link loss poisoned"))?
                .as_mut()
                .is_some_and(SeededLoss::drop_half)
            {
                return Ok(());
            }
            self.outbound
                .lock()
                .map_err(|_| io::Error::other("memory link poisoned"))?
                .push_back(ReceivedFrame {
                    peer: self.local_route,
                    bytes: frame.to_vec(),
                });
            Ok(())
        }

        fn try_receive(&self) -> io::Result<Option<ReceivedFrame>> {
            let mut budget = self
                .receive_budget
                .lock()
                .map_err(|_| io::Error::other("memory link budget poisoned"))?;
            if let Some(remaining) = budget.as_mut() {
                if *remaining == 0 {
                    return Ok(None);
                }
                *remaining -= 1;
            }
            drop(budget);
            Ok(self
                .inbound
                .lock()
                .map_err(|_| io::Error::other("memory link poisoned"))?
                .pop_front())
        }

        fn set_discovery(&self, _enabled: bool) -> io::Result<()> {
            Ok(())
        }

        fn retry_floor(&self) -> Duration {
            Duration::from_millis(1)
        }
    }

    #[derive(Clone)]
    struct PrefixErrorLink {
        inner: MemoryLink,
        accepted: Arc<Mutex<usize>>,
        limit: Arc<Mutex<usize>>,
    }

    impl PrefixErrorLink {
        fn new(inner: MemoryLink) -> Self {
            Self {
                inner,
                accepted: Arc::new(Mutex::new(0)),
                limit: Arc::new(Mutex::new(0)),
            }
        }

        fn begin_attempt(&self, limit: usize) {
            *self.accepted.lock().unwrap() = 0;
            *self.limit.lock().unwrap() = limit;
        }
    }

    impl Link for PrefixErrorLink {
        fn name(&self) -> &str {
            "prefix-error"
        }

        fn characteristics(&self) -> LinkCharacteristics {
            self.inner.characteristics()
        }

        fn send(&self, peer: Option<NodeId>, frame: &[u8]) -> io::Result<()> {
            let mut accepted = self
                .accepted
                .lock()
                .map_err(|_| io::Error::other("prefix error counter poisoned"))?;
            let limit = *self
                .limit
                .lock()
                .map_err(|_| io::Error::other("prefix error limit poisoned"))?;
            if *accepted >= limit {
                return Err(io::Error::other("injected partial send"));
            }
            *accepted = (*accepted).saturating_add(1);
            self.inner.send(peer, frame)
        }

        fn try_receive(&self) -> io::Result<Option<ReceivedFrame>> {
            self.inner.try_receive()
        }

        fn set_discovery(&self, enabled: bool) -> io::Result<()> {
            self.inner.set_discovery(enabled)
        }

        fn next_wakeup(&self) -> Option<Instant> {
            self.inner.next_wakeup()
        }

        fn retry_floor(&self) -> Duration {
            self.inner.retry_floor()
        }
    }

    #[derive(Clone, Default)]
    struct FakeBackend {
        available: BTreeMap<ObjectId, Vec<u8>>,
        priorities: BTreeMap<ObjectId, Priority>,
        partial: BTreeMap<ObjectId, Vec<u8>>,
        durable_progress: Vec<RuntimeTransferProgress>,
        disposed: BTreeMap<(ObjectId, u16), u64>,
        selections: Vec<(NodeId, InterestFilter, InventoryPurpose)>,
        ingested: Vec<(ObjectId, ItemId)>,
        fail_store_attempts: usize,
        fail_complete_attempts: usize,
        fail_commit_attempts: usize,
        advance_generation_on_commit_error: bool,
        make_generation_unavailable_on_commit_error: bool,
        terminal_commit_errors: bool,
        aborted: Vec<ObjectId>,
        fanout_messages: usize,
        data_requests: usize,
        receipts: Vec<(NodeId, u16, wire::Receipt)>,
        fail_authorize: bool,
        fail_durable_progress: bool,
        fail_inventory_selection: bool,
        fail_inventory_selection_attempts: usize,
        authorization_generation: Arc<AtomicU64>,
        authorization_generation_unavailable: Arc<AtomicBool>,
    }

    impl RuntimeBackend for FakeBackend {
        type Error = &'static str;

        fn authorization_generation(&mut self) -> Result<u64, Self::Error> {
            if self
                .authorization_generation_unavailable
                .load(Ordering::SeqCst)
            {
                Err("authorization generation unavailable")
            } else {
                Ok(self.authorization_generation.load(Ordering::SeqCst))
            }
        }

        fn authorize_adjacency(&mut self, _peer: NodeId) -> Result<(), Self::Error> {
            if self.fail_authorize {
                Err("authorization")
            } else {
                Ok(())
            }
        }

        fn durable_progress(
            &mut self,
            limit: usize,
        ) -> Result<Vec<RuntimeTransferProgress>, Self::Error> {
            if self.fail_durable_progress {
                Err("durable progress")
            } else {
                Ok(self.durable_progress.iter().take(limit).cloned().collect())
            }
        }

        fn durably_disposed_object_len(
            &mut self,
            object_id: ObjectId,
            semantic_version: u16,
        ) -> Result<Option<u64>, Self::Error> {
            Ok(self.disposed.get(&(object_id, semantic_version)).copied())
        }

        fn select_authorized_inventory(
            &mut self,
            peer: NodeId,
            _peer_route_commitments: &[[u8; 32]],
            filter: &InterestFilter,
            purpose: InventoryPurpose,
        ) -> Result<SparseInventory, Self::Error> {
            if self.fail_inventory_selection_attempts > 0 {
                self.fail_inventory_selection_attempts -= 1;
                return Err("transient inventory selection");
            }
            if self.fail_inventory_selection {
                return Err("inventory selection");
            }
            self.selections.push((peer, filter.clone(), purpose));
            let allowed = filter.topics == ["alpha"]
                && filter.scopes == ["mission/team"]
                && filter.min_priority <= Priority::Priority as u8;
            Ok(if allowed {
                SparseInventory::from_ids(self.available.keys().copied())
            } else {
                SparseInventory::new()
            })
        }

        fn store_object_chunk(
            &mut self,
            object_id: ObjectId,
            total_len: u64,
            offset: u64,
            bytes: &[u8],
        ) -> Result<(), Self::Error> {
            if self.fail_store_attempts > 0 {
                self.fail_store_attempts -= 1;
                return Err("transient store");
            }
            let len = usize::try_from(total_len).map_err(|_| "length")?;
            let start = usize::try_from(offset).map_err(|_| "offset")?;
            let end = start.checked_add(bytes.len()).ok_or("extent")?;
            if end > len {
                return Err("extent");
            }
            let partial = self
                .partial
                .entry(object_id)
                .or_insert_with(|| vec![0; len]);
            partial[start..end].copy_from_slice(bytes);
            Ok(())
        }

        fn complete_object_bytes(
            &mut self,
            object_id: ObjectId,
            _total_len: u64,
        ) -> Result<Vec<u8>, Self::Error> {
            if self.fail_complete_attempts > 0 {
                self.fail_complete_attempts -= 1;
                return Err("transient complete");
            }
            self.partial.get(&object_id).cloned().ok_or("missing")
        }

        fn abort_object(&mut self, object_id: ObjectId) -> Result<(), Self::Error> {
            self.partial.remove(&object_id);
            self.aborted.push(object_id);
            Ok(())
        }

        fn commit_authenticated_object(
            &mut self,
            _peer: NodeId,
            _exchange_id: u64,
            object_id: ObjectId,
            sealed: Vec<u8>,
            forwarding: Vec<u8>,
        ) -> Result<Option<ItemId>, Self::Error> {
            if self.fail_commit_attempts > 0 {
                self.fail_commit_attempts -= 1;
                if self.advance_generation_on_commit_error {
                    self.authorization_generation.fetch_add(1, Ordering::SeqCst);
                }
                if self.make_generation_unavailable_on_commit_error {
                    self.authorization_generation_unavailable
                        .store(true, Ordering::SeqCst);
                }
                return Err("transient commit");
            }
            if forwarding.is_empty() {
                return Err("forwarding");
            }
            let item_id = [0xa5; 32];
            self.available.insert(object_id, sealed);
            self.ingested.push((object_id, item_id));
            Ok(Some(item_id))
        }

        fn is_terminal_commit_error(&self, _error: &Self::Error) -> bool {
            self.terminal_commit_errors
        }

        fn object_priority(&mut self, object_id: ObjectId) -> Result<Priority, Self::Error> {
            Ok(self
                .priorities
                .get(&object_id)
                .copied()
                .unwrap_or(Priority::Routine))
        }

        fn data_for_want(
            &mut self,
            _peer: NodeId,
            _peer_route_commitments: &[[u8; 32]],
            exchange_id: u64,
            want: &WantItem,
        ) -> Result<Vec<Data>, Self::Error> {
            self.data_requests = self.data_requests.saturating_add(1);
            let sealed = self.available.get(&want.object_id).ok_or("unknown")?;
            let fanout = self.fanout_messages.max(1);
            if fanout == 1 {
                let total_len = u64::try_from(sealed.len()).map_err(|_| "length")?;
                let range = want.missing.first().copied().unwrap_or(ByteRange {
                    start: 0,
                    end: total_len,
                });
                let start = usize::try_from(range.start).map_err(|_| "start")?;
                let end = usize::try_from(range.end).map_err(|_| "end")?;
                let payload = if want.missing.is_empty() && want.total_len.is_some() {
                    Vec::new()
                } else {
                    sealed[start..end].to_vec()
                };
                return Ok(vec![Data {
                    exchange_id,
                    object_id: want.object_id,
                    total_len,
                    offset: range.start,
                    payload,
                    forwarding: b"authenticated-forwarding".to_vec(),
                }]);
            }
            let total_len = u64::try_from(sealed.len())
                .map_err(|_| "length")?
                .checked_mul(u64::try_from(fanout).map_err(|_| "fanout")?)
                .ok_or("length")?;
            let range = want.missing.first().copied().unwrap_or(ByteRange {
                start: 0,
                end: total_len,
            });
            let mut result = Vec::with_capacity(fanout);
            let chunk_len = u64::try_from(sealed.len()).map_err(|_| "length")?;
            for index in 0..fanout {
                let offset = chunk_len
                    .checked_mul(u64::try_from(index).map_err(|_| "offset")?)
                    .ok_or("offset")?;
                let end = offset.checked_add(chunk_len).ok_or("extent")?;
                if offset < range.start || end > range.end {
                    continue;
                }
                let payload = if want.missing.is_empty() && want.total_len.is_some() {
                    Vec::new()
                } else {
                    sealed.clone()
                };
                result.push(Data {
                    exchange_id,
                    object_id: want.object_id,
                    total_len,
                    offset,
                    payload,
                    forwarding: if index == 0 {
                        b"authenticated-forwarding".to_vec()
                    } else {
                        Vec::new()
                    },
                });
            }
            Ok(result)
        }

        fn acknowledge_receipt(
            &mut self,
            peer: NodeId,
            semantic_version: u16,
            receipt: &wire::Receipt,
        ) -> Result<(), Self::Error> {
            let recorded = (peer, semantic_version, receipt.clone());
            if !self.receipts.contains(&recorded) {
                self.receipts.push(recorded);
            }
            Ok(())
        }
    }

    struct RecordingBackend<B: RuntimeBackend> {
        inner: B,
        blob_wants: Vec<WantItem>,
        inventories: Vec<(InventoryPurpose, SparseInventory)>,
        max_blob_messages: Option<usize>,
        aborted: Vec<ObjectId>,
        corrupt_next_blob_payload: bool,
    }

    impl<B: RuntimeBackend> RecordingBackend<B> {
        fn new(inner: B, max_blob_messages: Option<usize>) -> Self {
            Self {
                inner,
                blob_wants: Vec::new(),
                inventories: Vec::new(),
                max_blob_messages,
                aborted: Vec::new(),
                corrupt_next_blob_payload: false,
            }
        }

        fn corrupt_next_blob_payload(mut self) -> Self {
            self.corrupt_next_blob_payload = true;
            self
        }
    }

    impl<B: RuntimeBackend> RuntimeBackend for RecordingBackend<B> {
        type Error = B::Error;

        fn authorization_generation(&mut self) -> Result<u64, Self::Error> {
            self.inner.authorization_generation()
        }

        fn authorize_adjacency(&mut self, peer: NodeId) -> Result<(), Self::Error> {
            self.inner.authorize_adjacency(peer)
        }

        fn durable_progress(
            &mut self,
            limit: usize,
        ) -> Result<Vec<RuntimeTransferProgress>, Self::Error> {
            self.inner.durable_progress(limit)
        }

        fn durable_progress_for_semantic_version(
            &mut self,
            limit: usize,
            semantic_version: u16,
        ) -> Result<Vec<RuntimeTransferProgress>, Self::Error> {
            self.inner
                .durable_progress_for_semantic_version(limit, semantic_version)
        }

        fn durable_dependencies(&mut self, limit: usize) -> Result<Vec<ObjectId>, Self::Error> {
            self.inner.durable_dependencies(limit)
        }

        fn durable_dependencies_for_semantic_version(
            &mut self,
            limit: usize,
            semantic_version: u16,
        ) -> Result<Vec<ObjectId>, Self::Error> {
            self.inner
                .durable_dependencies_for_semantic_version(limit, semantic_version)
        }

        fn durably_disposed_object_len(
            &mut self,
            object_id: ObjectId,
            semantic_version: u16,
        ) -> Result<Option<u64>, Self::Error> {
            self.inner
                .durably_disposed_object_len(object_id, semantic_version)
        }

        fn select_authorized_inventory(
            &mut self,
            peer: NodeId,
            commitments: &[[u8; 32]],
            filter: &InterestFilter,
            purpose: InventoryPurpose,
        ) -> Result<SparseInventory, Self::Error> {
            let inventory =
                self.inner
                    .select_authorized_inventory(peer, commitments, filter, purpose)?;
            self.inventories.push((purpose, inventory.clone()));
            Ok(inventory)
        }

        fn select_authorized_inventory_for_semantic_version(
            &mut self,
            peer: NodeId,
            commitments: &[[u8; 32]],
            filter: &InterestFilter,
            purpose: InventoryPurpose,
            semantic_version: u16,
        ) -> Result<SparseInventory, Self::Error> {
            let inventory = self
                .inner
                .select_authorized_inventory_for_semantic_version(
                    peer,
                    commitments,
                    filter,
                    purpose,
                    semantic_version,
                )?;
            self.inventories.push((purpose, inventory.clone()));
            Ok(inventory)
        }

        fn store_object_chunk(
            &mut self,
            object_id: ObjectId,
            total_len: u64,
            offset: u64,
            bytes: &[u8],
        ) -> Result<(), Self::Error> {
            self.inner
                .store_object_chunk(object_id, total_len, offset, bytes)
        }

        fn store_object_chunk_for_semantic_version(
            &mut self,
            object_id: ObjectId,
            total_len: u64,
            offset: u64,
            bytes: &[u8],
            semantic_version: u16,
        ) -> Result<(), Self::Error> {
            self.inner.store_object_chunk_for_semantic_version(
                object_id,
                total_len,
                offset,
                bytes,
                semantic_version,
            )
        }

        fn complete_object_bytes(
            &mut self,
            object_id: ObjectId,
            total_len: u64,
        ) -> Result<Vec<u8>, Self::Error> {
            self.inner.complete_object_bytes(object_id, total_len)
        }

        fn abort_object(&mut self, object_id: ObjectId) -> Result<(), Self::Error> {
            self.inner.abort_object(object_id)?;
            self.aborted.push(object_id);
            Ok(())
        }

        fn commit_authenticated_object(
            &mut self,
            peer: NodeId,
            exchange_id: u64,
            object_id: ObjectId,
            bytes: Vec<u8>,
            forwarding: Vec<u8>,
        ) -> Result<Option<ItemId>, Self::Error> {
            self.inner
                .commit_authenticated_object(peer, exchange_id, object_id, bytes, forwarding)
        }

        fn commit_authenticated_object_with_dependencies(
            &mut self,
            peer: NodeId,
            exchange_id: u64,
            semantic_version: u16,
            object_id: ObjectId,
            bytes: Vec<u8>,
            forwarding: Vec<u8>,
        ) -> Result<RuntimeCommit, Self::Error> {
            self.inner.commit_authenticated_object_with_dependencies(
                peer,
                exchange_id,
                semantic_version,
                object_id,
                bytes,
                forwarding,
            )
        }

        fn is_terminal_commit_error(&self, error: &Self::Error) -> bool {
            self.inner.is_terminal_commit_error(error)
        }

        fn object_priority(&mut self, object_id: ObjectId) -> Result<Priority, Self::Error> {
            self.inner.object_priority(object_id)
        }

        fn data_for_want(
            &mut self,
            peer: NodeId,
            commitments: &[[u8; 32]],
            exchange_id: u64,
            want: &WantItem,
        ) -> Result<Vec<Data>, Self::Error> {
            if want.object_id.kind() == ObjectKind::BlobChunk {
                self.blob_wants.push(want.clone());
            }
            let mut data = self
                .inner
                .data_for_want(peer, commitments, exchange_id, want)?;
            if want.object_id.kind() == ObjectKind::BlobChunk
                && let Some(limit) = self.max_blob_messages
            {
                data.truncate(limit);
            }
            if want.object_id.kind() == ObjectKind::BlobChunk
                && self.corrupt_next_blob_payload
                && let Some(byte) = data
                    .iter_mut()
                    .find_map(|message| message.payload.last_mut())
            {
                *byte ^= 0x80;
                self.corrupt_next_blob_payload = false;
            }
            Ok(data)
        }

        fn data_for_want_for_semantic_version(
            &mut self,
            peer: NodeId,
            commitments: &[[u8; 32]],
            exchange_id: u64,
            semantic_version: u16,
            want: &WantItem,
        ) -> Result<Vec<Data>, Self::Error> {
            if want.object_id.kind() == ObjectKind::BlobChunk {
                self.blob_wants.push(want.clone());
            }
            let mut data = self.inner.data_for_want_for_semantic_version(
                peer,
                commitments,
                exchange_id,
                semantic_version,
                want,
            )?;
            if want.object_id.kind() == ObjectKind::BlobChunk
                && let Some(limit) = self.max_blob_messages
            {
                data.truncate(limit);
            }
            if want.object_id.kind() == ObjectKind::BlobChunk
                && self.corrupt_next_blob_payload
                && let Some(byte) = data
                    .iter_mut()
                    .find_map(|message| message.payload.last_mut())
            {
                *byte ^= 0x80;
                self.corrupt_next_blob_payload = false;
            }
            Ok(data)
        }

        fn acknowledge_receipt(
            &mut self,
            peer: NodeId,
            semantic_version: u16,
            receipt: &wire::Receipt,
        ) -> Result<(), Self::Error> {
            self.inner
                .acknowledge_receipt(peer, semantic_version, receipt)
        }
    }

    fn bundles() -> (ProvisioningBundle, ProvisioningBundle) {
        let mut provisioner = ReferenceProvisioner::from_seed([0x42; 32]).unwrap();
        let access = ProvisioningAccess::member(
            Scope::new("mission/team").unwrap(),
            vec![0],
            vec![Topic::new("alpha").unwrap()],
        )
        .unwrap();
        (
            provisioner
                .issue_node(1, std::slice::from_ref(&access))
                .unwrap(),
            provisioner.issue_node(2, &[access]).unwrap(),
        )
    }

    fn authenticated_runtime_pair(
        exchange_id: u64,
        min_priority: Priority,
    ) -> (
        RuntimeDriver<FakeBackend>,
        RuntimeDriver<FakeBackend>,
        MemoryLink,
        MemoryLink,
        Instant,
    ) {
        authenticated_runtime_pair_with_limits(
            exchange_id,
            min_priority,
            RuntimeLimits::default(),
            RuntimeLimits::default(),
        )
    }

    fn authenticated_runtime_pair_with_limits(
        exchange_id: u64,
        min_priority: Priority,
        left_limits: RuntimeLimits,
        right_limits: RuntimeLimits,
    ) -> (
        RuntimeDriver<FakeBackend>,
        RuntimeDriver<FakeBackend>,
        MemoryLink,
        MemoryLink,
        Instant,
    ) {
        let (left_bundle, right_bundle) = bundles();
        let mut left_driver = RuntimeDriver::initiator_with_limits(
            left_bundle,
            SyncState::new(Default::default(), SparseInventory::new()).unwrap(),
            FakeBackend::default(),
            StartRequest {
                exchange_id,
                topics: vec!["alpha".into()],
                scopes: vec!["mission/team".into()],
                min_priority: min_priority as u8,
            },
            None,
            left_limits,
        )
        .unwrap();
        let mut right_driver = RuntimeDriver::responder_with_limits(
            right_bundle,
            SyncState::new(Default::default(), SparseInventory::new()).unwrap(),
            FakeBackend::default(),
            None,
            right_limits,
        )
        .unwrap();
        let (left, right) = MemoryLink::pair(256);
        let now = Instant::now();
        for _ in 0..64 {
            left_driver.pump_at(&left, now).unwrap();
            right_driver.pump_at(&right, now).unwrap();
            if left_driver.is_authenticated()
                && right_driver.is_authenticated()
                && right_driver.handshake_retry.is_none()
                && right_driver.sync.active_exchange_id() == Some(exchange_id)
            {
                break;
            }
        }
        assert!(left_driver.is_authenticated());
        assert!(right_driver.is_authenticated());
        assert_eq!(right_driver.sync.active_exchange_id(), Some(exchange_id));
        right_driver.retries.clear();
        right_driver.deferred_wants.clear();
        right_driver.outbox.clear();
        right.capture.lock().unwrap().clear();
        (left_driver, right_driver, left, right, now)
    }

    #[test]
    fn runtime_limits_validate_hard_maxima_and_relationships() {
        let defaults = RuntimeLimits::default();
        assert_eq!(defaults.validate(), Ok(()));
        assert_eq!(
            defaults.retained_inbound_payload_bytes(),
            MAX_REASSEMBLY_BYTES
        );
        assert_eq!(
            defaults.retained_outbound_payload_bytes(),
            MAX_PENDING_LOGICAL_BYTES
        );

        let zero = RuntimeLimits {
            max_pending_outbox: 0,
            ..defaults
        };
        assert_eq!(
            zero.validate(),
            Err(RuntimeLimitsError::Zero("max_pending_outbox"))
        );

        let above_hard_maximum = RuntimeLimits {
            max_reassembly_bytes: MAX_REASSEMBLY_BYTES + 1,
            ..defaults
        };
        assert_eq!(
            above_hard_maximum.validate(),
            Err(RuntimeLimitsError::ExceedsHardMaximum(
                "max_reassembly_bytes"
            ))
        );

        let invalid_reserve = RuntimeLimits {
            max_pending_logical_bytes: DEFERRED_WANT_EPOCH_RESERVE - 1,
            ..defaults
        };
        assert_eq!(
            invalid_reserve.validate(),
            Err(RuntimeLimitsError::InvalidRelationship(
                "deferred_want_epoch_reserve exceeds max_pending_logical_bytes"
            ))
        );

        let (left_bundle, _) = bundles();
        assert!(matches!(
            RuntimeDriver::responder_with_limits(
                left_bundle,
                SyncState::new(Default::default(), SparseInventory::new()).unwrap(),
                FakeBackend::default(),
                None,
                zero,
            ),
            Err(RuntimeError::InvalidLimits(RuntimeLimitsError::Zero(
                "max_pending_outbox"
            )))
        ));
    }

    #[test]
    fn lowered_runtime_queue_limits_apply_backpressure() {
        let limits = RuntimeLimits {
            max_pending_outbox: 1,
            max_pending_logical_bytes: 64 * 1024,
            deferred_want_epoch_reserve: 0,
            ..RuntimeLimits::default()
        };
        let (_left_driver, mut right_driver, _left, _right, _) =
            authenticated_runtime_pair_with_limits(
                41,
                Priority::Routine,
                RuntimeLimits::default(),
                limits,
            );
        assert_eq!(right_driver.limits(), &limits);

        let receipt = Message::Receipt(wire::Receipt {
            exchange_id: 41,
            object_id: ObjectId::new(ObjectKind::SourceEnvelope, [0x92; 32]),
            total_len: 1,
            received: vec![ByteRange { start: 0, end: 1 }],
            complete: true,
        });
        right_driver.queue_sync_message(&receipt).unwrap();
        assert!(matches!(
            right_driver.queue_sync_message(&receipt),
            Err(RuntimeError::Backpressure)
        ));
        assert_eq!(right_driver.outbox.len(), 1);

        right_driver.outbox.clear();
        assert!(matches!(
            right_driver.queue_logical_once(
                vec![0; 48 * 1024],
                Priority::Routine,
                wire::SEMANTIC_PROTOCOL_V1,
            ),
            Err(RuntimeError::Backpressure)
        ));
        assert!(right_driver.pending_logical_bytes() <= limits.max_pending_logical_bytes);
    }

    #[test]
    fn lowered_reassembly_frame_limit_evicts_oldest_partial_route() {
        let limits = RuntimeLimits {
            max_in_flight_logical_frames: 1,
            ..RuntimeLimits::default()
        };
        let (bundle, _) = bundles();
        let mut driver = RuntimeDriver::responder_with_limits(
            bundle,
            SyncState::new(Default::default(), SparseInventory::new()).unwrap(),
            FakeBackend::default(),
            None,
            limits,
        )
        .unwrap();
        let now = Instant::now();

        assert!(driver.admit_fragment_route(10, CarrierRoute::Anonymous, now));
        assert!(driver.admit_fragment_route(11, CarrierRoute::Anonymous, now));
        assert_eq!(driver.fragment_routes.len(), 1);
        assert!(!driver.fragment_routes.contains_key(&10));
        assert!(driver.fragment_routes.contains_key(&11));
    }

    #[test]
    fn authorization_generation_change_blocks_stale_outbound_flush() {
        let (_current, mut stale, _current_link, stale_link, now) =
            authenticated_runtime_pair(40, Priority::Routine);
        assert_eq!(stale.admitted_authorization_generation, Some(0));
        let object_id = ObjectId::new(ObjectKind::SourceEnvelope, [0x91; 32]);
        stale
            .queue_sync_message(&Message::Receipt(wire::Receipt {
                exchange_id: 40,
                object_id,
                total_len: 1,
                received: vec![ByteRange { start: 0, end: 1 }],
                complete: true,
            }))
            .unwrap();
        assert!(!stale.outbox.is_empty());
        let captured_before = stale_link.capture.lock().unwrap().len();
        let counters_before = stale.authorization_generation_counters();

        stale
            .backend
            .authorization_generation
            .store(1, Ordering::SeqCst);
        assert!(matches!(
            stale.pump_at(&stale_link, now),
            Err(RuntimeError::AuthorizationGenerationChanged)
        ));
        assert_eq!(
            stale.take_authorization_generation_check(),
            Some(RuntimeAuthorizationGenerationCheck::Changed {
                expected_generation: 0,
                observed_generation: 1,
            })
        );
        assert_eq!(
            stale.authorization_generation_counters(),
            RuntimeAuthorizationGenerationCounters {
                checks: counters_before.checks + 1,
                mismatches: counters_before.mismatches + 1,
                unavailable: counters_before.unavailable,
            }
        );
        assert_eq!(
            stale_link.capture.lock().unwrap().len(),
            captured_before,
            "stale authorization must be rejected before the first link send"
        );
        assert!(stale.outbox.is_empty());
        assert!(!stale.is_authenticated());
    }

    #[test]
    fn commit_error_with_durable_authorization_change_preserves_checkpoint_and_reauthenticates() {
        let (mut sender, mut receiver, left, right, now) =
            authenticated_runtime_pair(401, Priority::Routine);
        sender.retries.clear();
        sender.deferred_wants.clear();
        sender.outbox.clear();
        receiver.retries.clear();
        receiver.deferred_wants.clear();
        receiver.outbox.clear();

        let payload = b"mixed-authorization-activation".to_vec();
        let object_id = ObjectId::for_envelope(EnvelopeId::from_sealed_bytes(&payload));
        prepare_expected_object(&mut receiver, 401, object_id);
        receiver.backend_mut().fail_commit_attempts = 1;
        receiver.backend_mut().advance_generation_on_commit_error = true;
        receiver.backend_mut().terminal_commit_errors = true;
        sender
            .backend_mut()
            .priorities
            .insert(object_id, Priority::Flash);
        sender
            .queue_sync_message(&Message::Data(Data {
                exchange_id: 401,
                object_id,
                total_len: payload.len() as u64,
                offset: 0,
                payload,
                forwarding: b"authenticated-forwarding".to_vec(),
            }))
            .unwrap();
        sender.pump_at(&left, now).unwrap();

        let irreversible_before = receiver.irreversible_generation;
        assert!(matches!(
            receiver.pump_at(&right, now),
            Err(RuntimeError::AuthorizationGenerationChanged)
        ));
        assert_eq!(
            receiver.take_authorization_generation_check(),
            Some(RuntimeAuthorizationGenerationCheck::Changed {
                expected_generation: 0,
                observed_generation: 1,
            })
        );
        assert!(receiver.irreversible_generation > irreversible_before);
        assert!(receiver.local_inventory_changed);
        assert_eq!(
            receiver
                .inventory_refresh_retry
                .as_ref()
                .map(|retry| retry.scope),
            Some(InventoryRefreshScope::Both)
        );
        assert!(!receiver.sync.inventory().contains(&object_id));
        assert!(receiver.sync.wants().contains(&object_id));
        assert!(receiver.backend().ingested.is_empty());
        assert_eq!(receiver.backend().aborted, vec![object_id]);
        assert!(
            receiver.outbox.is_empty(),
            "no completion receipt is emitted"
        );
        assert!(!receiver.is_authenticated());
    }

    #[test]
    fn commit_error_with_unavailable_authorization_generation_fails_closed_without_receipt() {
        let (mut sender, mut receiver, left, right, now) =
            authenticated_runtime_pair(402, Priority::Routine);
        sender.retries.clear();
        sender.deferred_wants.clear();
        sender.outbox.clear();
        receiver.retries.clear();
        receiver.deferred_wants.clear();
        receiver.outbox.clear();

        let payload = b"authorization-generation-unavailable".to_vec();
        let object_id = ObjectId::for_envelope(EnvelopeId::from_sealed_bytes(&payload));
        prepare_expected_object(&mut receiver, 402, object_id);
        receiver.backend_mut().fail_commit_attempts = 1;
        receiver
            .backend_mut()
            .make_generation_unavailable_on_commit_error = true;
        sender
            .queue_sync_message(&Message::Data(Data {
                exchange_id: 402,
                object_id,
                total_len: payload.len() as u64,
                offset: 0,
                payload,
                forwarding: b"authenticated-forwarding".to_vec(),
            }))
            .unwrap();
        sender.pump_at(&left, now).unwrap();

        assert!(matches!(
            receiver.pump_at(&right, now),
            Err(RuntimeError::AuthorizationGenerationChanged)
        ));
        assert_eq!(
            receiver.take_authorization_generation_check(),
            Some(RuntimeAuthorizationGenerationCheck::Unavailable {
                expected_generation: Some(0),
            })
        );
        assert!(receiver.backend().ingested.is_empty());
        assert!(receiver.outbox.is_empty());
        assert!(!receiver.is_authenticated());
    }

    #[test]
    fn external_admission_blocks_backend_and_sync_until_host_accepts() {
        let (left_bundle, right_bundle) = bundles();
        let left_backend = FakeBackend {
            fail_authorize: true,
            ..FakeBackend::default()
        };
        let mut initiator = RuntimeDriver::initiator(
            left_bundle,
            SyncState::new(Default::default(), SparseInventory::new()).unwrap(),
            left_backend,
            StartRequest {
                exchange_id: 41,
                topics: vec!["alpha".into()],
                scopes: vec!["mission/team".into()],
                min_priority: Priority::Routine as u8,
            },
            None,
        )
        .unwrap();
        let mut responder = RuntimeDriver::responder_with_start(
            right_bundle,
            SyncState::new(Default::default(), SparseInventory::new()).unwrap(),
            FakeBackend::default(),
            StartRequest {
                exchange_id: 1,
                topics: vec!["alpha".into()],
                scopes: vec!["mission/team".into()],
                min_priority: Priority::Routine as u8,
            },
            None,
        )
        .unwrap();
        initiator.require_external_admission().unwrap();
        responder.require_external_admission().unwrap();
        let (left, right) = MemoryLink::pair(256);
        let now = Instant::now();

        for _ in 0..64 {
            initiator.pump_at(&left, now).unwrap();
            responder.pump_at(&right, now).unwrap();
            if initiator.awaiting_external_admission() && responder.awaiting_external_admission() {
                break;
            }
        }

        assert!(initiator.awaiting_external_admission());
        assert!(responder.awaiting_external_admission());
        assert_eq!(initiator.sync.active_exchange_id(), None);
        assert_eq!(responder.sync.active_exchange_id(), None);
        assert!(initiator.backend.selections.is_empty());
        assert!(responder.backend.selections.is_empty());
        let captured_before = (
            left.capture.lock().unwrap().len(),
            right.capture.lock().unwrap().len(),
        );

        for _ in 0..4 {
            initiator.pump_at(&left, now).unwrap();
            responder.pump_at(&right, now).unwrap();
        }
        assert_eq!(
            captured_before,
            (
                left.capture.lock().unwrap().len(),
                right.capture.lock().unwrap().len(),
            )
        );
        assert!(matches!(
            initiator.admit_authenticated(),
            Err(RuntimeError::Backend(_))
        ));
    }

    #[test]
    fn accepted_external_admission_starts_normal_sync() {
        let (left_bundle, right_bundle) = bundles();
        let mut initiator = RuntimeDriver::initiator(
            left_bundle,
            SyncState::new(Default::default(), SparseInventory::new()).unwrap(),
            FakeBackend::default(),
            StartRequest {
                exchange_id: 42,
                topics: vec!["alpha".into()],
                scopes: vec!["mission/team".into()],
                min_priority: Priority::Routine as u8,
            },
            None,
        )
        .unwrap();
        let mut responder = RuntimeDriver::responder_with_start(
            right_bundle,
            SyncState::new(Default::default(), SparseInventory::new()).unwrap(),
            FakeBackend::default(),
            StartRequest {
                exchange_id: 1,
                topics: vec!["alpha".into()],
                scopes: vec!["mission/team".into()],
                min_priority: Priority::Routine as u8,
            },
            None,
        )
        .unwrap();
        initiator.require_external_admission().unwrap();
        responder.require_external_admission().unwrap();
        let (left, right) = MemoryLink::pair(256);
        let now = Instant::now();

        for _ in 0..64 {
            initiator.pump_at(&left, now).unwrap();
            responder.pump_at(&right, now).unwrap();
            if initiator.awaiting_external_admission() && responder.awaiting_external_admission() {
                break;
            }
        }
        responder.admit_authenticated().unwrap();
        initiator.admit_authenticated().unwrap();

        for _ in 0..64 {
            initiator.pump_at(&left, now).unwrap();
            responder.pump_at(&right, now).unwrap();
            if responder.sync.active_exchange_id() == Some(42) {
                break;
            }
        }
        assert_eq!(initiator.sync.active_exchange_id(), Some(42));
        assert_eq!(responder.sync.active_exchange_id(), Some(42));
        assert!(!initiator.awaiting_external_admission());
        assert!(!responder.awaiting_external_admission());
        assert!(matches!(
            initiator.admit_authenticated(),
            Err(RuntimeError::FailedState)
        ));
    }

    #[test]
    fn unadmitted_responder_does_not_consume_authenticated_sync_frames() {
        let (left_bundle, right_bundle) = bundles();
        let mut initiator = RuntimeDriver::initiator(
            left_bundle,
            SyncState::new(Default::default(), SparseInventory::new()).unwrap(),
            FakeBackend::default(),
            StartRequest {
                exchange_id: 43,
                topics: vec!["alpha".into()],
                scopes: vec!["mission/team".into()],
                min_priority: Priority::Routine as u8,
            },
            None,
        )
        .unwrap();
        let mut responder = RuntimeDriver::responder_with_start(
            right_bundle,
            SyncState::new(Default::default(), SparseInventory::new()).unwrap(),
            FakeBackend::default(),
            StartRequest {
                exchange_id: 1,
                topics: vec!["alpha".into()],
                scopes: vec!["mission/team".into()],
                min_priority: Priority::Routine as u8,
            },
            None,
        )
        .unwrap();
        initiator.require_external_admission().unwrap();
        responder.require_external_admission().unwrap();
        let (left, right) = MemoryLink::pair(256);
        let now = Instant::now();

        for _ in 0..64 {
            initiator.pump_at(&left, now).unwrap();
            responder.pump_at(&right, now).unwrap();
            if initiator.awaiting_external_admission() && responder.awaiting_external_admission() {
                break;
            }
        }
        assert!(initiator.awaiting_external_admission());
        assert!(responder.awaiting_external_admission());

        initiator.admit_authenticated().unwrap();
        for _ in 0..8 {
            initiator.pump_at(&left, now).unwrap();
            if !right.inbound.lock().unwrap().is_empty() {
                break;
            }
        }
        let queued = right.inbound.lock().unwrap().len();
        assert!(
            queued > 0,
            "initiator should queue authenticated sync traffic"
        );

        for _ in 0..4 {
            responder.pump_at(&right, now).unwrap();
        }
        assert_eq!(right.inbound.lock().unwrap().len(), queued);
        assert_eq!(responder.sync.active_exchange_id(), None);
        assert!(responder.backend.selections.is_empty());

        responder.admit_authenticated().unwrap();
        for _ in 0..64 {
            responder.pump_at(&right, now).unwrap();
            initiator.pump_at(&left, now).unwrap();
            if responder.sync.active_exchange_id() == Some(43) {
                break;
            }
        }
        assert_eq!(responder.sync.active_exchange_id(), Some(43));
    }

    fn restored_bundle(bytes: &[u8]) -> ProvisioningBundle {
        ProvisioningBundle::from_bytes(bytes)
            .unwrap_or_else(|error| panic!("bundle restore failed: {error}"))
    }

    fn runtime_directory(label: &str) -> PathBuf {
        let path = std::env::temp_dir().join(format!(
            "aster-runtime-{label}-{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        fs::create_dir_all(&path).unwrap();
        path
    }

    fn blob_start(exchange_id: u64) -> StartRequest {
        StartRequest {
            exchange_id,
            topics: vec!["alpha".into()],
            scopes: vec!["mission/team".into()],
            min_priority: Priority::Routine as u8,
        }
    }

    fn missing_complement(total_len: u64, received: &[ByteRange]) -> Vec<ByteRange> {
        let mut missing = Vec::new();
        let mut cursor = 0_u64;
        for range in received {
            if cursor < range.start {
                missing.push(ByteRange {
                    start: cursor,
                    end: range.start,
                });
            }
            cursor = cursor.max(range.end);
        }
        if cursor < total_len {
            missing.push(ByteRange {
                start: cursor,
                end: total_len,
            });
        }
        missing
    }

    fn prepare_expected_object(
        receiver: &mut RuntimeDriver<FakeBackend>,
        exchange_id: u64,
        object_id: ObjectId,
    ) {
        let offer = pending_offer_for(receiver, exchange_id, [object_id]);
        let actions = receiver
            .sync
            .apply(SyncEvent::Receive(Message::Offer(offer)))
            .unwrap();
        receiver.handle_actions(actions).unwrap();
        receiver.retries.clear();
        receiver.deferred_wants.clear();
        receiver.outbox.clear();
    }

    fn pending_offer_for(
        receiver: &mut RuntimeDriver<FakeBackend>,
        exchange_id: u64,
        object_ids: impl IntoIterator<Item = ObjectId>,
    ) -> crate::wire::Offer {
        let inventory = SparseInventory::from_ids(object_ids);
        let summary = Message::Summary(crate::wire::Summary {
            exchange_id,
            root_hash: inventory.root_hash(),
            item_count: inventory.item_count(),
            snapshot_id: inventory.snapshot_id(),
        });
        let mut actions = receiver
            .sync
            .apply(SyncEvent::Receive(summary.clone()))
            .unwrap();
        let is_root_probe = |action: &SyncAction| {
            matches!(
                action,
                SyncAction::Send(Message::Probe(crate::wire::Probe {
                    prefix_nibbles: 0,
                    ..
                }))
            )
        };
        if !actions.iter().any(is_root_probe) {
            let start_actions = receiver
                .sync
                .apply(SyncEvent::Start {
                    exchange_id,
                    topics: vec!["alpha".into()],
                    scopes: vec!["mission/team".into()],
                    min_priority: Priority::Routine as u8,
                })
                .unwrap();
            receiver.handle_actions(start_actions).unwrap();
            receiver.retries.clear();
            receiver.deferred_wants.clear();
            receiver.outbox.clear();
            actions = receiver.sync.apply(SyncEvent::Receive(summary)).unwrap();
        }
        assert!(actions.iter().any(|action| matches!(
            action,
            SyncAction::Send(Message::Probe(crate::wire::Probe {
                prefix_nibbles: 0,
                ..
            }))
        )));
        crate::wire::Offer {
            exchange_id,
            object_ids: inventory
                .ids_under(&crate::inventory::NibblePrefix::root(), inventory.len()),
            snapshot_id: inventory.snapshot_id(),
        }
    }

    fn contains_bytes(haystack: &[u8], needle: &[u8]) -> bool {
        !needle.is_empty()
            && haystack.len() >= needle.len()
            && haystack
                .windows(needle.len())
                .any(|window| window == needle)
    }

    fn assert_capture_hides_canaries(messages: &[Vec<u8>], canaries: &SessionPrivacyCanaries) {
        for message in messages {
            assert!(!contains_bytes(message, &canaries.mission));
            assert!(!contains_bytes(message, &canaries.credential));
            assert!(!contains_bytes(message, &canaries.credential_body));
            assert!(!contains_bytes(message, &canaries.identity));
            for commitment in &canaries.route_grant_commitments {
                assert!(!contains_bytes(message, commitment));
            }
        }
    }

    #[test]
    fn plaintext_data_before_authentication_never_reaches_backend() {
        let (_initiator_bundle, responder_bundle) = bundles();
        let mut responder = RuntimeDriver::responder(
            responder_bundle,
            SyncState::new(Default::default(), SparseInventory::new()).unwrap(),
            FakeBackend::default(),
            None,
        )
        .unwrap();
        let (attacker, victim) = MemoryLink::pair(256);
        let sealed = b"not authenticated";
        let data = Message::Data(Data {
            exchange_id: 1,
            object_id: ObjectId::for_envelope(EnvelopeId::from_sealed_bytes(sealed)),
            total_len: sealed.len() as u64,
            offset: 0,
            payload: sealed.to_vec(),
            forwarding: b"fake".to_vec(),
        });
        let plaintext = wire::encode_message(&data, Limits::default()).unwrap();
        for part in fragment::fragment(&plaintext, 256, 1).unwrap() {
            attacker.send(None, &part.encode().unwrap()).unwrap();
        }
        assert_eq!(responder.pump(&victim).unwrap(), 0);
        assert!(matches!(responder.phase, SessionPhase::Responder(_)));
        assert!(responder.backend().partial.is_empty());
        assert!(responder.backend().selections.is_empty());
        assert!(responder.backend().ingested.is_empty());
        assert!(responder.completed_transfers.is_empty());
    }

    #[test]
    fn authorization_and_hydration_fail_closed_without_caching_final_flight() {
        let request = StartRequest {
            exchange_id: 72,
            topics: vec!["alpha".into()],
            scopes: vec!["mission/team".into()],
            min_priority: Priority::Routine as u8,
        };

        let (left_bundle, right_bundle) = bundles();
        let mut initiator = RuntimeDriver::initiator(
            left_bundle,
            SyncState::new(Default::default(), SparseInventory::new()).unwrap(),
            FakeBackend::default(),
            request.clone(),
            None,
        )
        .unwrap();
        let mut responder = RuntimeDriver::responder(
            right_bundle,
            SyncState::new(Default::default(), SparseInventory::new()).unwrap(),
            FakeBackend {
                fail_authorize: true,
                ..FakeBackend::default()
            },
            None,
        )
        .unwrap();
        let (left, right) = MemoryLink::pair(256);
        let now = Instant::now();
        let mut observed = false;
        for _ in 0..64 {
            initiator.pump_at(&left, now).unwrap();
            let completed_before = responder.completed_transfers.len();
            match responder.pump_at(&right, now) {
                Err(RuntimeError::Backend(error)) => {
                    assert_eq!(error, "authorization");
                    assert_eq!(responder.completed_transfers.len(), completed_before);
                    assert!(responder.failed_transfers.is_empty());
                    observed = true;
                    break;
                }
                Ok(_) => {}
                Err(error) => panic!("unexpected authorization result: {error}"),
            }
        }
        assert!(
            observed,
            "hydration failure was not reached: initiator_authenticated={}, responder_authenticated={}, left_inbound={}, right_inbound={}",
            initiator.is_authenticated(),
            responder.is_authenticated(),
            left.inbound.lock().unwrap().len(),
            right.inbound.lock().unwrap().len(),
        );
        assert!(matches!(responder.phase, SessionPhase::Failed));
        assert!(!responder.logical_authenticated);

        let (left_bundle, right_bundle) = bundles();
        let mut initiator = RuntimeDriver::initiator(
            left_bundle,
            SyncState::new(Default::default(), SparseInventory::new()).unwrap(),
            FakeBackend {
                fail_durable_progress: true,
                ..FakeBackend::default()
            },
            request,
            None,
        )
        .unwrap();
        let mut responder = RuntimeDriver::responder(
            right_bundle,
            SyncState::new(Default::default(), SparseInventory::new()).unwrap(),
            FakeBackend::default(),
            None,
        )
        .unwrap();
        let (left, right) = MemoryLink::pair(256);
        let now = Instant::now();
        let mut observed = false;
        for _ in 0..64 {
            let completed_before = initiator.completed_transfers.len();
            match initiator.pump_at(&left, now) {
                Err(RuntimeError::Backend(error)) => {
                    assert_eq!(error, "durable progress");
                    assert_eq!(initiator.completed_transfers.len(), completed_before);
                    assert!(initiator.failed_transfers.is_empty());
                    observed = true;
                    break;
                }
                Ok(_) => {}
                Err(error) => panic!("unexpected hydration result: {error}"),
            }
            responder.pump_at(&right, now).unwrap();
        }
        assert!(
            observed,
            "hydration failure was not reached: initiator_authenticated={}, responder_authenticated={}, left_inbound={}, right_inbound={}",
            initiator.is_authenticated(),
            responder.is_authenticated(),
            left.inbound.lock().unwrap().len(),
            right.inbound.lock().unwrap().len(),
        );
        assert!(matches!(initiator.phase, SessionPhase::Failed));
        assert!(!initiator.logical_authenticated);
    }

    #[test]
    fn post_session_handshake_finalization_errors_fail_closed() {
        let request = StartRequest {
            exchange_id: 71,
            topics: vec!["alpha".into()],
            scopes: vec!["mission/team".into()],
            min_priority: Priority::Routine as u8,
        };
        let (left_bundle, right_bundle) = bundles();
        let mut initiator = RuntimeDriver::initiator(
            left_bundle,
            SyncState::new(Default::default(), SparseInventory::new()).unwrap(),
            FakeBackend {
                fail_inventory_selection: true,
                ..FakeBackend::default()
            },
            request.clone(),
            None,
        )
        .unwrap();
        let mut responder = RuntimeDriver::responder(
            right_bundle,
            SyncState::new(Default::default(), SparseInventory::new()).unwrap(),
            FakeBackend::default(),
            None,
        )
        .unwrap();
        let (left, right) = MemoryLink::pair(256);
        let now = Instant::now();
        let mut observed = false;
        for _ in 0..64 {
            let completed_before = initiator.completed_transfers.len();
            match initiator.pump_at(&left, now) {
                Err(RuntimeError::Backend(error)) => {
                    assert_eq!(error, "inventory selection");
                    assert_eq!(initiator.completed_transfers.len(), completed_before);
                    assert!(initiator.start_request.is_some());
                    observed = true;
                    break;
                }
                Ok(_) => {}
                Err(error) => panic!("unexpected start finalization result: {error}"),
            }
            responder.pump_at(&right, now).unwrap();
        }
        assert!(observed);
        assert!(matches!(initiator.phase, SessionPhase::Failed));

        let (left_bundle, right_bundle) = bundles();
        let mut initiator = RuntimeDriver::initiator(
            left_bundle,
            SyncState::new(Default::default(), SparseInventory::new()).unwrap(),
            FakeBackend::default(),
            request,
            None,
        )
        .unwrap();
        let mut responder = RuntimeDriver::responder(
            right_bundle,
            SyncState::new(Default::default(), SparseInventory::new()).unwrap(),
            FakeBackend::default(),
            None,
        )
        .unwrap();
        let (left, right) = MemoryLink::pair(256);
        let now = Instant::now();
        initiator.pump_at(&left, now).unwrap();
        responder.pump_at(&right, now).unwrap();
        initiator.pump_at(&left, now).unwrap();
        assert!(matches!(responder.phase, SessionPhase::ResponderPending(_)));
        responder.next_transfer_id = u64::MAX;
        let completed_before = responder.completed_transfers.len();
        assert!(matches!(
            responder.pump_at(&right, now),
            Err(RuntimeError::TransferIdExhausted)
        ));
        assert_eq!(responder.completed_transfers.len(), completed_before);
        assert!(responder.failed_transfers.is_empty());
        assert!(matches!(responder.phase, SessionPhase::Failed));
        assert!(!responder.logical_authenticated);
    }

    #[test]
    fn v1_session_filters_extended_backend_inventory_before_summary_root() {
        let (initiator_bundle, responder_bundle) = bundles();
        let source_bytes = b"v1-visible-source".to_vec();
        let source_id = ObjectId::for_envelope(EnvelopeId::from_sealed_bytes(&source_bytes));
        let extended_id = ObjectId::new(ObjectKind::SourceBatchProof, [0x93; 32]);
        let mut responder_backend = FakeBackend::default();
        responder_backend
            .available
            .insert(source_id, source_bytes.clone());
        responder_backend
            .available
            .insert(extended_id, b"must-not-enter-v1-root".to_vec());

        let mut initiator = RuntimeDriver::initiator_with_semantic_versions(
            initiator_bundle,
            SyncState::new(Default::default(), SparseInventory::new()).unwrap(),
            FakeBackend::default(),
            StartRequest {
                exchange_id: 91,
                topics: vec!["alpha".into()],
                scopes: vec!["mission/team".into()],
                min_priority: Priority::Routine as u8,
            },
            None,
            vec![wire::SEMANTIC_PROTOCOL_V1],
        )
        .unwrap();
        let mut responder = RuntimeDriver::responder(
            responder_bundle,
            SyncState::new(Default::default(), SparseInventory::new()).unwrap(),
            responder_backend,
            None,
        )
        .unwrap();
        let (left, right) = MemoryLink::pair(256);
        let now = Instant::now();
        for _ in 0..128 {
            initiator.pump_at(&left, now).unwrap();
            responder.pump_at(&right, now).unwrap();
            if initiator.backend().available.contains_key(&source_id)
                && responder.sync.selected_serve_inventory().is_some()
            {
                break;
            }
        }

        assert_eq!(
            initiator.authenticated_semantic_version(),
            Some(wire::SEMANTIC_PROTOCOL_V1)
        );
        assert_eq!(
            responder.authenticated_semantic_version(),
            Some(wire::SEMANTIC_PROTOCOL_V1)
        );
        let served = responder
            .sync
            .selected_serve_inventory()
            .expect("authorized v1 serve inventory");
        let expected = SparseInventory::from_ids([source_id]);
        assert_eq!(served, &expected);
        assert_eq!(served.root_hash(), expected.root_hash());
        assert!(!served.contains(&extended_id));
        assert!(responder.backend().available.contains_key(&extended_id));
        assert_eq!(responder.backend().data_requests, 1);
        assert!(initiator.backend().available.contains_key(&source_id));
        assert!(!initiator.backend().available.contains_key(&extended_id));
        assert!(
            initiator
                .retries
                .values()
                .all(|entry| entry.semantic_version == wire::SEMANTIC_PROTOCOL_V1)
        );
        assert!(
            responder
                .retries
                .values()
                .all(|entry| entry.semantic_version == wire::SEMANTIC_PROTOCOL_V1)
        );
        assert!(
            initiator
                .outbox
                .iter()
                .all(|entry| entry.semantic_version == wire::SEMANTIC_PROTOCOL_V1)
        );
    }

    #[test]
    fn authenticated_in_memory_link_filters_then_ingests_typed_envelope() {
        let (initiator_bundle, responder_bundle) = bundles();
        let initiator_canaries = session_privacy_canaries(&initiator_bundle).unwrap();
        let responder_canaries = session_privacy_canaries(&responder_bundle).unwrap();
        let sealed = b"source-sealed-envelope".to_vec();
        let envelope_id = EnvelopeId::from_sealed_bytes(&sealed);
        let object_id = ObjectId::for_envelope(envelope_id);
        let mut responder_backend = FakeBackend::default();
        responder_backend.available.insert(object_id, sealed);
        let mut initiator = RuntimeDriver::initiator(
            initiator_bundle,
            SyncState::new(Default::default(), SparseInventory::new()).unwrap(),
            FakeBackend::default(),
            StartRequest {
                exchange_id: 9,
                topics: vec!["alpha".into()],
                scopes: vec!["mission/team".into()],
                min_priority: Priority::Priority as u8,
            },
            None,
        )
        .unwrap();
        let mut responder = RuntimeDriver::responder(
            responder_bundle,
            SyncState::new(Default::default(), SparseInventory::from_ids([object_id])).unwrap(),
            responder_backend,
            None,
        )
        .unwrap();
        // Tiny MTU exercises the same Link/fragment path used by a constrained
        // adapter; all sync bytes remain encrypted session records.
        let (left, right) = MemoryLink::pair(128);
        let now = Instant::now();
        for _ in 0..160 {
            initiator.pump_at(&left, now).unwrap();
            responder.pump_at(&right, now).unwrap();
            if !initiator.backend().ingested.is_empty()
                && responder
                    .backend()
                    .receipts
                    .iter()
                    .any(|(_, version, receipt)| {
                        *version == wire::SEMANTIC_PROTOCOL_V9
                            && receipt.object_id == object_id
                            && receipt.complete
                    })
            {
                break;
            }
        }
        assert!(initiator.is_authenticated());
        assert!(responder.is_authenticated());
        assert_eq!(initiator.backend().ingested, vec![(object_id, [0xa5; 32])]);
        assert!(initiator.sync().inventory().contains(&object_id));
        assert!(
            responder
                .backend()
                .receipts
                .iter()
                .any(|(_, version, receipt)| {
                    *version == wire::SEMANTIC_PROTOCOL_V9
                        && receipt.object_id == object_id
                        && receipt.complete
                }),
            "the authenticated complete receipt reached the durable-backend seam"
        );
        assert!(
            initiator
                .backend()
                .selections
                .iter()
                .all(|(_, filter, _)| filter.topics == ["alpha"])
        );
        assert_ne!(envelope_id.as_bytes(), &[0xa5; 32]);

        // Transfer IDs 1 and 2 in each direction are exactly the four handshake flights.
        // Reassemble the real tiny-MTU captures before scanning so a canary cannot evade the
        // assertion by crossing a fragment boundary.
        let left_handshake = left.captured_logical_through(2);
        let right_handshake = right.captured_logical_through(2);
        assert_eq!(left_handshake.len(), 2);
        assert_eq!(right_handshake.len(), 2);
        assert_capture_hides_canaries(&left_handshake, &initiator_canaries);
        assert_capture_hides_canaries(&left_handshake, &responder_canaries);
        assert_capture_hides_canaries(&right_handshake, &initiator_canaries);
        assert_capture_hides_canaries(&right_handshake, &responder_canaries);
    }

    #[test]
    fn authenticated_session_converges_simultaneous_publishes_in_both_directions() {
        let (left_bundle, right_bundle) = bundles();
        let left_sealed = b"left-source-envelope".to_vec();
        let right_sealed = b"right-source-envelope".to_vec();
        let left_id = ObjectId::for_envelope(EnvelopeId::from_sealed_bytes(&left_sealed));
        let right_id = ObjectId::for_envelope(EnvelopeId::from_sealed_bytes(&right_sealed));

        let mut left_backend = FakeBackend::default();
        left_backend.available.insert(left_id, left_sealed);
        let mut right_backend = FakeBackend::default();
        right_backend.available.insert(right_id, right_sealed);

        let filter = StartRequest {
            exchange_id: 31,
            topics: vec!["alpha".into()],
            scopes: vec!["mission/team".into()],
            min_priority: Priority::Priority as u8,
        };
        let mut left_driver = RuntimeDriver::initiator(
            left_bundle,
            SyncState::new(Default::default(), SparseInventory::from_ids([left_id])).unwrap(),
            left_backend,
            filter.clone(),
            None,
        )
        .unwrap();
        let mut right_driver = RuntimeDriver::responder_with_start(
            right_bundle,
            SyncState::new(Default::default(), SparseInventory::from_ids([right_id])).unwrap(),
            right_backend,
            StartRequest {
                exchange_id: 999,
                ..filter
            },
            None,
        )
        .unwrap();
        let (left, right) = MemoryLink::pair(128);

        for _ in 0..300 {
            left_driver.pump(&left).unwrap();
            right_driver.pump(&right).unwrap();
            if left_driver.sync().inventory().contains(&right_id)
                && right_driver.sync().inventory().contains(&left_id)
            {
                break;
            }
        }

        assert_eq!(left_driver.sync().active_exchange_id(), Some(31));
        assert_eq!(right_driver.sync().active_exchange_id(), Some(31));
        assert_eq!(left_driver.backend().ingested, vec![(right_id, [0xa5; 32])]);
        assert_eq!(right_driver.backend().ingested, vec![(left_id, [0xa5; 32])]);
        assert!(left_driver.sync().inventory().contains(&left_id));
        assert!(left_driver.sync().inventory().contains(&right_id));
        assert!(right_driver.sync().inventory().contains(&left_id));
        assert!(right_driver.sync().inventory().contains(&right_id));
    }

    #[test]
    fn nonempty_converged_recontact_does_not_request_retained_data() {
        let (left_bundle, right_bundle) = bundles();
        let sealed = b"already-retained-source-envelope".to_vec();
        let object_id = ObjectId::for_envelope(EnvelopeId::from_sealed_bytes(&sealed));

        let mut left_backend = FakeBackend::default();
        left_backend.available.insert(object_id, sealed.clone());
        let mut right_backend = FakeBackend::default();
        right_backend.available.insert(object_id, sealed);

        let filter = StartRequest {
            exchange_id: 32,
            topics: vec!["alpha".into()],
            scopes: vec!["mission/team".into()],
            min_priority: Priority::Priority as u8,
        };
        let mut left_driver = RuntimeDriver::initiator(
            left_bundle,
            SyncState::new(Default::default(), SparseInventory::new()).unwrap(),
            left_backend,
            filter.clone(),
            None,
        )
        .unwrap();
        let mut right_driver = RuntimeDriver::responder_with_start(
            right_bundle,
            SyncState::new(Default::default(), SparseInventory::new()).unwrap(),
            right_backend,
            StartRequest {
                exchange_id: 999,
                ..filter
            },
            None,
        )
        .unwrap();
        let (left, right) = MemoryLink::pair(256);

        for _ in 0..300 {
            left_driver.pump(&left).unwrap();
            right_driver.pump(&right).unwrap();
        }

        assert!(left_driver.is_authenticated());
        assert!(right_driver.is_authenticated());
        assert_eq!(left_driver.sync().active_exchange_id(), Some(32));
        assert_eq!(right_driver.sync().active_exchange_id(), Some(32));
        assert!(left_driver.sync().wants().is_empty());
        assert!(right_driver.sync().wants().is_empty());
        assert_eq!(left_driver.backend().data_requests, 0);
        assert_eq!(right_driver.backend().data_requests, 0);
        assert!(left_driver.backend().ingested.is_empty());
        assert!(right_driver.backend().ingested.is_empty());
        assert!(
            left_driver
                .backend()
                .selections
                .iter()
                .any(|(_, _, purpose)| { *purpose == InventoryPurpose::ReceiveBaseline })
        );
        assert!(
            right_driver
                .backend()
                .selections
                .iter()
                .any(|(_, _, purpose)| { *purpose == InventoryPurpose::ReceiveBaseline })
        );
    }

    #[test]
    fn active_two_way_sync_converges_below_root_offer_boundary() {
        assert_two_way_sync_converges(3, 4);
    }

    #[test]
    fn active_two_way_sync_converges_at_root_offer_boundary() {
        assert_two_way_sync_converges(4, 4);
    }

    #[test]
    fn active_two_way_sync_converges_above_root_offer_boundary() {
        assert_two_way_sync_converges(5, 4);
    }

    fn assert_two_way_sync_converges(item_count: usize, max_offer_ids: usize) {
        let unique_delta = item_count.min(max_offer_ids);
        let (left_bundle, right_bundle) = bundles();
        let object = |domain: u8, index: usize| {
            let mut sealed = vec![domain];
            sealed.extend_from_slice(
                &u64::try_from(index)
                    .expect("bounded test index")
                    .to_be_bytes(),
            );
            let object_id = ObjectId::for_envelope(EnvelopeId::from_sealed_bytes(&sealed));
            (object_id, sealed)
        };
        let mut common = BTreeMap::new();
        for index in 0..item_count - unique_delta {
            let (object_id, sealed) = object(0x43, index);
            assert!(common.insert(object_id, sealed).is_none());
        }
        let mut left_backend = FakeBackend {
            available: common.clone(),
            ..FakeBackend::default()
        };
        let mut right_backend = FakeBackend {
            available: common,
            ..FakeBackend::default()
        };
        let mut left_unique = BTreeSet::new();
        let mut right_unique = BTreeSet::new();
        for index in 0..unique_delta {
            let (left_id, left_sealed) = object(0x4c, index);
            let (right_id, right_sealed) = object(0x52, index);
            assert!(
                left_backend
                    .available
                    .insert(left_id, left_sealed)
                    .is_none()
            );
            assert!(
                right_backend
                    .available
                    .insert(right_id, right_sealed)
                    .is_none()
            );
            assert!(left_unique.insert(left_id));
            assert!(right_unique.insert(right_id));
        }
        let left_initial = left_backend
            .available
            .keys()
            .copied()
            .collect::<BTreeSet<_>>();
        let right_initial = right_backend
            .available
            .keys()
            .copied()
            .collect::<BTreeSet<_>>();
        assert_eq!(left_initial.len(), item_count);
        assert_eq!(right_initial.len(), item_count);
        assert_eq!(
            left_initial.difference(&right_initial).count(),
            unique_delta
        );
        assert_eq!(
            right_initial.difference(&left_initial).count(),
            unique_delta
        );
        let expected = left_initial
            .union(&right_initial)
            .copied()
            .collect::<BTreeSet<_>>();

        let request = StartRequest {
            exchange_id: 132,
            topics: vec!["alpha".into()],
            scopes: vec!["mission/team".into()],
            min_priority: Priority::Routine as u8,
        };
        let mut left_driver = RuntimeDriver::initiator(
            left_bundle,
            SyncState::new(
                SyncConfig {
                    max_offer_ids,
                    ..SyncConfig::default()
                },
                SparseInventory::new(),
            )
            .unwrap(),
            left_backend,
            request.clone(),
            None,
        )
        .unwrap();
        let mut right_driver = RuntimeDriver::responder_with_start(
            right_bundle,
            SyncState::new(
                SyncConfig {
                    max_offer_ids,
                    ..SyncConfig::default()
                },
                SparseInventory::new(),
            )
            .unwrap(),
            right_backend,
            StartRequest {
                exchange_id: 9_999,
                ..request
            },
            None,
        )
        .unwrap();
        assert!(left_driver.sync().inventory().is_empty());
        assert!(right_driver.sync().inventory().is_empty());
        let (left, right) = MemoryLink::pair(u16::MAX);
        let now = Instant::now();
        let mut converged = false;

        for step in 0..5_000 {
            left_driver.pump_at(&left, now).unwrap_or_else(|error| {
                panic!("{item_count}-item left pump failed at step {step}: {error}")
            });
            right_driver.pump_at(&right, now).unwrap_or_else(|error| {
                panic!("{item_count}-item right pump failed at step {step}: {error}")
            });

            let left_ids = left_driver
                .backend()
                .available
                .keys()
                .copied()
                .collect::<BTreeSet<_>>();
            let right_ids = right_driver
                .backend()
                .available
                .keys()
                .copied()
                .collect::<BTreeSet<_>>();
            let data_or_want_pending = |driver: &RuntimeDriver<FakeBackend>| {
                driver
                    .retries
                    .keys()
                    .any(|key| matches!(key, RetryKey::Want(..) | RetryKey::Data(..)))
                    || !driver.deferred_wants.is_empty()
            };
            if left_ids == expected
                && right_ids == expected
                && left_driver.sync().wants().is_empty()
                && right_driver.sync().wants().is_empty()
                && !data_or_want_pending(&left_driver)
                && !data_or_want_pending(&right_driver)
                && left.inbound.lock().unwrap().is_empty()
                && right.inbound.lock().unwrap().is_empty()
            {
                converged = true;
                break;
            }
        }

        assert!(
            converged,
            "{item_count}-item active two-way exchange did not converge"
        );
        assert!(left_driver.is_authenticated());
        assert!(right_driver.is_authenticated());
        assert_eq!(
            left_driver
                .backend()
                .ingested
                .iter()
                .map(|(object_id, _)| *object_id)
                .collect::<BTreeSet<_>>(),
            right_unique
        );
        assert_eq!(
            right_driver
                .backend()
                .ingested
                .iter()
                .map(|(object_id, _)| *object_id)
                .collect::<BTreeSet<_>>(),
            left_unique
        );
        assert_eq!(left_driver.backend().ingested.len(), unique_delta);
        assert_eq!(right_driver.backend().ingested.len(), unique_delta);
        assert!((unique_delta..=unique_delta * 2).contains(&left_driver.backend().data_requests));
        assert!((unique_delta..=unique_delta * 2).contains(&right_driver.backend().data_requests));
        assert!(left_driver.sync().wants().is_empty());
        assert!(right_driver.sync().wants().is_empty());
    }

    #[test]
    fn authenticated_sync_converges_through_seeded_half_loss_and_a_dropped_response() {
        let (left_bundle, right_bundle) = bundles();
        let sealed = vec![0x5a; 4_096];
        let object_id = ObjectId::for_envelope(EnvelopeId::from_sealed_bytes(&sealed));
        let request = StartRequest {
            exchange_id: 73,
            topics: vec!["alpha".into()],
            scopes: vec!["mission/team".into()],
            min_priority: Priority::Routine as u8,
        };
        let mut left_driver = RuntimeDriver::initiator(
            left_bundle,
            SyncState::new(Default::default(), SparseInventory::new()).unwrap(),
            FakeBackend::default(),
            request,
            None,
        )
        .unwrap();
        let mut right_driver = RuntimeDriver::responder(
            right_bundle,
            SyncState::new(Default::default(), SparseInventory::new()).unwrap(),
            FakeBackend::default(),
            None,
        )
        .unwrap();
        let (left, right) = MemoryLink::pair(96);
        let mut now = Instant::now();

        // Establish and quiesce the session reliably so the forced loss below
        // is unambiguously an authenticated inventory response, not a flight.
        for _ in 0..64 {
            left_driver.pump_at(&left, now).unwrap();
            right_driver.pump_at(&right, now).unwrap();
            if left_driver.is_authenticated()
                && right_driver.is_authenticated()
                && right_driver.handshake_retry.is_none()
            {
                break;
            }
        }
        assert!(left_driver.is_authenticated());
        assert!(right_driver.is_authenticated());
        assert!(right_driver.handshake_retry.is_none());
        left.capture.lock().unwrap().clear();
        right.capture.lock().unwrap().clear();

        right_driver
            .backend_mut()
            .available
            .insert(object_id, sealed.clone());
        right_driver
            .backend_mut()
            .priorities
            .insert(object_id, Priority::Flash);
        right_driver.local_inventory_changed().unwrap();
        assert!(
            right_driver
                .retries
                .keys()
                .any(|key| matches!(key, RetryKey::Summary(73, _))),
            "changed inventory queued a SUMMARY response"
        );
        let dropped_summary = right_driver.next_transfer_id;
        right.force_drop_transfer(dropped_summary);
        left.enable_seeded_half_loss(0x0ddc_0ffe_e15e_beef);
        right.enable_seeded_half_loss(0x51de_d00d_7654_3210);

        // Advancing a synthetic monotonic clock exercises deadlines without a
        // sleep or busy loop. The 4 KiB DATA record is fragmented at this MTU.
        for _ in 0..1_000 {
            now += Duration::from_secs(70);
            left_driver.pump_at(&left, now).unwrap();
            right_driver.pump_at(&right, now).unwrap();
            if left_driver.sync().inventory().contains(&object_id) {
                break;
            }
        }
        assert!(left_driver.sync().inventory().contains(&object_id));
        assert_eq!(
            left_driver.backend().ingested,
            vec![(object_id, [0xa5; 32])]
        );
        assert!(
            right
                .capture
                .lock()
                .unwrap()
                .iter()
                .map(|frame| Fragment::decode(frame).unwrap())
                .any(|fragment| fragment.count > 32)
        );
        assert!(
            right
                .capture
                .lock()
                .unwrap()
                .iter()
                .any(|frame| { Fragment::decode(frame).unwrap().transfer_id == dropped_summary })
        );
        assert!(
            !left_driver
                .completed_transfers
                .iter()
                .any(|entry| { entry.transfer_id == dropped_summary }),
            "the explicitly dropped SUMMARY response was never delivered"
        );
        let (left_delivered, left_dropped) = left.loss_counts();
        let (right_delivered, right_dropped) = right.loss_counts();
        assert!(left_delivered > 0 && left_dropped > 0);
        assert!(right_delivered > 0 && right_dropped > 0);
        let left_percent = left_dropped * 100 / (left_delivered + left_dropped);
        let right_percent = right_dropped * 100 / (right_delivered + right_dropped);
        assert!((40..=60).contains(&left_percent));
        assert!((40..=60).contains(&right_percent));

        // A lost receipt causes another authenticated DATA delivery, which the
        // committed receiver re-acknowledges without a second durable apply.
        for _ in 0..128 {
            if !right_driver
                .retries
                .keys()
                .any(|key| matches!(key, RetryKey::Data(_, id, ..) if *id == object_id))
            {
                break;
            }
            now += Duration::from_secs(70);
            left_driver.pump_at(&left, now).unwrap();
            right_driver.pump_at(&right, now).unwrap();
        }
        assert!(
            !right_driver
                .retries
                .keys()
                .any(|key| matches!(key, RetryKey::Data(_, id, ..) if *id == object_id))
        );
        assert_eq!(left_driver.backend().ingested.len(), 1);
    }

    #[test]
    fn dropped_root_offer_and_invalid_offer_preserve_probe_retry_until_convergence() {
        let (mut receiver, mut provider, left, right, mut now) =
            authenticated_runtime_pair(92, Priority::Routine);
        receiver.retries.clear();
        receiver.deferred_wants.clear();
        receiver.outbox.clear();
        provider.retries.clear();
        provider.deferred_wants.clear();
        provider.outbox.clear();
        left.inbound.lock().unwrap().clear();
        right.inbound.lock().unwrap().clear();
        left.capture.lock().unwrap().clear();
        right.capture.lock().unwrap().clear();

        let sealed = b"root-offer-retry-object".to_vec();
        let object_id = ObjectId::for_envelope(EnvelopeId::from_sealed_bytes(&sealed));
        let remote = SparseInventory::from_ids([object_id]);
        provider
            .backend_mut()
            .available
            .insert(object_id, sealed.clone());
        provider
            .backend_mut()
            .priorities
            .insert(object_id, Priority::Routine);
        provider.local_inventory_changed().unwrap();
        assert!(
            provider
                .sync
                .selected_serve_inventory()
                .is_some_and(|inventory| inventory.contains(&object_id))
        );

        // Isolate the root-OFFER exchange from the bidirectional refresh
        // controls that selected the provider's new authorized inventory.
        provider.retries.clear();
        provider.deferred_wants.clear();
        provider.outbox.clear();
        provider
            .queue_sync_message(&Message::Summary(crate::wire::Summary {
                exchange_id: 92,
                root_hash: remote.root_hash(),
                item_count: remote.item_count(),
                snapshot_id: remote.snapshot_id(),
            }))
            .unwrap();
        provider.pump_at(&right, now).unwrap();
        receiver.pump_at(&left, now).unwrap();

        let root_probe = RetryKey::Probe(92, remote.snapshot_id(), 0, Vec::new());
        let first_probe_transfer = receiver.retries[&root_probe]
            .transport_epoch
            .as_ref()
            .expect("root Probe was transmitted after SUMMARY")
            .transfer_id;
        assert_eq!(receiver.retries[&root_probe].attempts, 1);

        // The Probe is already waiting at the provider. Its generated OFFER
        // is a one-shot record, so arrange to lose that exact next transfer.
        let first_offer_transfer = provider.next_transfer_id;
        right.force_drop_transfer(first_offer_transfer);
        provider.pump_at(&right, now).unwrap();
        assert!(receiver.retries.contains_key(&root_probe));
        assert!(!receiver.sync.wants().contains(&object_id));
        assert!(
            right.capture.lock().unwrap().iter().any(|frame| {
                Fragment::decode(frame).unwrap().transfer_id == first_offer_transfer
            })
        );
        assert!(
            !receiver
                .completed_transfers
                .iter()
                .any(|transfer| { transfer.transfer_id == first_offer_transfer })
        );

        // A separately authenticated but truncated OFFER must fail before it
        // can acknowledge the root Probe or create durable object requests.
        provider
            .queue_sync_message(&Message::Offer(crate::wire::Offer {
                exchange_id: 92,
                object_ids: Vec::new(),
                snapshot_id: remote.snapshot_id(),
            }))
            .unwrap();
        provider.pump_at(&right, now).unwrap();
        assert!(matches!(
            receiver.pump_at(&left, now),
            Err(RuntimeError::Sync(SyncError::SnapshotMismatch))
        ));
        assert!(receiver.retries.contains_key(&root_probe));
        assert!(!receiver.sync.wants().contains(&object_id));

        let initial_attempts = receiver.retries[&root_probe].attempts;
        let mut maximum_attempts = initial_attempts;
        let mut probe_transfers = BTreeSet::from([first_probe_transfer]);
        for _ in 0..=MAX_SUCCESSFUL_RECORD_REPAIR_ROUNDS {
            let Some(due) = receiver.retries.get(&root_probe).map(|entry| entry.due) else {
                break;
            };
            now = due;
            receiver.pump_at(&left, now).unwrap();
            if let Some(entry) = receiver.retries.get(&root_probe) {
                maximum_attempts = maximum_attempts.max(entry.attempts);
                probe_transfers.insert(
                    entry
                        .transport_epoch
                        .as_ref()
                        .expect("transmitted root Probe retains its transport epoch")
                        .transfer_id,
                );
            }
            provider.pump_at(&right, now).unwrap();
            receiver.pump_at(&left, now).unwrap();
        }

        assert!(
            !receiver.retries.contains_key(&root_probe),
            "a validated regenerated OFFER retires the root Probe"
        );
        assert!(receiver.sync.wants().contains(&object_id));
        assert!(maximum_attempts > initial_attempts);
        assert!(
            probe_transfers.len() >= 2,
            "the Probe rotated to a fresh record"
        );

        for _ in 0..64 {
            now += Duration::from_secs(70);
            provider.pump_at(&right, now).unwrap();
            receiver.pump_at(&left, now).unwrap();
            if receiver.sync.inventory().contains(&object_id) {
                break;
            }
        }
        assert!(receiver.sync.inventory().contains(&object_id));
        assert_eq!(receiver.backend().ingested, vec![(object_id, [0xa5; 32])]);
        assert!(receiver.take_local_inventory_changed());
        assert!(!receiver.take_local_inventory_changed());
        assert!(!provider.take_local_inventory_changed());
    }

    #[test]
    fn delayed_authenticated_single_item_offer_is_idempotent_after_commit() {
        let (mut receiver, mut provider, left, right, mut now) =
            authenticated_runtime_pair(97, Priority::Routine);
        receiver.retries.clear();
        receiver.deferred_wants.clear();
        receiver.outbox.clear();
        provider.retries.clear();
        provider.deferred_wants.clear();
        provider.outbox.clear();
        left.inbound.lock().unwrap().clear();
        right.inbound.lock().unwrap().clear();

        let sealed = vec![0x5c; 16 * 1_024];
        let object_id = ObjectId::for_envelope(EnvelopeId::from_sealed_bytes(&sealed));
        provider.backend_mut().available.insert(object_id, sealed);
        provider.local_inventory_changed().unwrap();
        assert!(
            provider
                .sync()
                .selected_serve_inventory()
                .is_some_and(|inventory| inventory.contains(&object_id))
        );
        provider.retries.clear();
        provider.deferred_wants.clear();
        provider.outbox.clear();
        let offer = pending_offer_for(&mut receiver, 97, [object_id]);
        let snapshot_id = offer.snapshot_id;
        receiver
            .queue_sync_message(&Message::Probe(crate::wire::Probe {
                exchange_id: 97,
                prefix: Vec::new(),
                prefix_nibbles: 0,
                snapshot_id,
            }))
            .unwrap();
        receiver
            .queue_sync_message(&Message::Probe(crate::wire::Probe {
                exchange_id: 97,
                prefix: vec![0x10],
                prefix_nibbles: 1,
                snapshot_id,
            }))
            .unwrap();
        for entry in receiver.retries.values_mut() {
            entry.due = now + Duration::from_secs(3_600);
        }

        provider
            .queue_sync_message(&Message::Offer(offer.clone()))
            .unwrap();
        provider.pump_at(&right, now).unwrap();
        receiver.pump_at(&left, now).unwrap();
        assert!(receiver.sync.wants().contains(&object_id));
        assert!(!receiver.retries.keys().any(|key| matches!(
            key,
            RetryKey::Probe(97, actual_snapshot, ..) if *actual_snapshot == snapshot_id
        )));

        for _ in 0..64 {
            now += Duration::from_secs(70);
            provider.pump_at(&right, now).unwrap();
            receiver.pump_at(&left, now).unwrap();
            if receiver.sync.inventory().contains(&object_id) {
                break;
            }
        }
        assert!(receiver.sync.inventory().contains(&object_id));
        assert_eq!(receiver.backend().ingested, vec![(object_id, [0xa5; 32])]);

        // Isolate a delayed fresh authenticated retransmission after the
        // commit-triggered local inventory refresh retired the old traversal.
        receiver.retries.clear();
        receiver.deferred_wants.clear();
        receiver.outbox.clear();
        provider.retries.clear();
        provider.deferred_wants.clear();
        provider.outbox.clear();
        left.inbound.lock().unwrap().clear();
        right.inbound.lock().unwrap().clear();
        provider.queue_sync_message(&Message::Offer(offer)).unwrap();
        provider.pump_at(&right, now).unwrap();
        receiver.pump_at(&left, now).unwrap();
        assert!(receiver.is_authenticated());
        assert!(receiver.sync.wants().is_empty());
        assert!(receiver.sync.inventory().contains(&object_id));
    }

    #[test]
    fn live_retry_deadlines_and_due_order_follow_authenticated_priority() {
        let (left_bundle, right_bundle) = bundles();
        let mut left_driver = RuntimeDriver::initiator(
            left_bundle,
            SyncState::new(Default::default(), SparseInventory::new()).unwrap(),
            FakeBackend::default(),
            StartRequest {
                exchange_id: 74,
                topics: vec!["alpha".into()],
                scopes: vec!["mission/team".into()],
                min_priority: Priority::Routine as u8,
            },
            None,
        )
        .unwrap();
        let mut right_driver = RuntimeDriver::responder(
            right_bundle,
            SyncState::new(Default::default(), SparseInventory::new()).unwrap(),
            FakeBackend::default(),
            None,
        )
        .unwrap();
        let (left, right) = MemoryLink::pair(256);
        let now = Instant::now();
        for _ in 0..64 {
            left_driver.pump_at(&left, now).unwrap();
            right_driver.pump_at(&right, now).unwrap();
            if left_driver.is_authenticated()
                && right_driver.is_authenticated()
                && right_driver.handshake_retry.is_none()
            {
                break;
            }
        }
        assert!(right_driver.is_authenticated());
        right_driver.retries.clear();
        right.capture.lock().unwrap().clear();

        let routine_id = ObjectId::for_envelope(EnvelopeId::from_sealed_bytes(b"routine"));
        let flash_id = ObjectId::for_envelope(EnvelopeId::from_sealed_bytes(b"flash"));
        right_driver
            .backend_mut()
            .priorities
            .insert(routine_id, Priority::Routine);
        right_driver
            .backend_mut()
            .priorities
            .insert(flash_id, Priority::Flash);
        for _ in 0..(MAX_RETRY_SENDS_PER_PUMP - 1) {
            right_driver
                .queue_sync_message(&Message::Receipt(wire::Receipt {
                    exchange_id: 74,
                    object_id: routine_id,
                    total_len: 1,
                    received: Vec::new(),
                    complete: false,
                }))
                .unwrap();
        }
        let make_data = |object_id, payload: &[u8]| {
            Message::Data(Data {
                exchange_id: 74,
                object_id,
                total_len: payload.len() as u64,
                offset: 0,
                payload: payload.to_vec(),
                forwarding: b"authenticated-forwarding".to_vec(),
            })
        };
        right_driver
            .queue_sync_message(&make_data(routine_id, b"routine"))
            .unwrap();
        right_driver
            .queue_sync_message(&make_data(flash_id, b"flash"))
            .unwrap();
        let routine_key = RetryKey::Data(74, routine_id, 7, 0, 7);
        let flash_key = RetryKey::Data(74, flash_id, 5, 0, 5);

        right_driver.pump_at(&right, now).unwrap();
        assert_eq!(right_driver.retries[&flash_key].attempts, 1);
        assert_eq!(right_driver.retries[&routine_key].attempts, 0);
        assert!(right_driver.retries[&flash_key].due > right_driver.retries[&routine_key].due);
        assert_eq!(right_driver.next_wakeup(&right), Some(now));

        right_driver.pump_at(&right, now).unwrap();
        assert_eq!(right_driver.retries[&flash_key].attempts, 1);
        assert_eq!(right_driver.retries[&routine_key].attempts, 1);
        assert_eq!(
            right_driver.next_wakeup(&right),
            Some(right_driver.retries[&flash_key].due)
        );
    }

    #[test]
    fn dispatch_order_assigns_secure_sequences_after_outbox_selection() {
        let (mut receiver, mut sender, left, right, now) =
            authenticated_runtime_pair(75, Priority::Routine);
        receiver.retries.clear();
        receiver.deferred_wants.clear();
        receiver.outbox.clear();
        left.capture.lock().unwrap().clear();
        left.inbound.lock().unwrap().clear();
        right.inbound.lock().unwrap().clear();

        for index in 0..MAX_PENDING_RETRIES {
            let object_id = ObjectId::for_envelope(EnvelopeId::from_sealed_bytes(
                &u64::try_from(index).unwrap().to_le_bytes(),
            ));
            sender
                .queue_retry_message(
                    RetryKey::Data(75, object_id, 1, 0, 1),
                    Message::Receipt(wire::Receipt {
                        exchange_id: 75,
                        object_id,
                        total_len: 1,
                        received: Vec::new(),
                        complete: false,
                    }),
                    Priority::Routine,
                )
                .unwrap();
        }
        assert_eq!(sender.retries.len(), MAX_PENDING_RETRIES);

        let one_shot_id = ObjectId::for_envelope(EnvelopeId::from_sealed_bytes(b"later-one-shot"));
        sender
            .queue_sync_message(&Message::Receipt(wire::Receipt {
                exchange_id: 75,
                object_id: one_shot_id,
                total_len: 1,
                received: Vec::new(),
                complete: false,
            }))
            .unwrap();

        sender.pump_at(&right, now).unwrap();
        assert_eq!(
            receiver.pump_at(&left, now).unwrap(),
            MAX_RETRY_SENDS_PER_PUMP
        );
        assert!(receiver.is_authenticated());
    }

    #[test]
    fn retry_after_completed_transfer_eviction_is_fresh_and_idempotent() {
        let (mut receiver, mut sender, left, right, now) =
            authenticated_runtime_pair(79, Priority::Routine);
        receiver.retries.clear();
        receiver.deferred_wants.clear();
        receiver.outbox.clear();
        left.capture.lock().unwrap().clear();
        left.inbound.lock().unwrap().clear();
        right.inbound.lock().unwrap().clear();

        let payload = b"fresh authenticated retry".to_vec();
        let object_id = ObjectId::for_envelope(EnvelopeId::from_sealed_bytes(&payload));
        prepare_expected_object(&mut receiver, 79, object_id);

        sender
            .backend_mut()
            .priorities
            .insert(object_id, Priority::Routine);
        sender
            .queue_sync_message(&Message::Data(Data {
                exchange_id: 79,
                object_id,
                total_len: payload.len() as u64,
                offset: 0,
                payload: payload.clone(),
                forwarding: b"authenticated-forwarding".to_vec(),
            }))
            .unwrap();
        let key = RetryKey::Data(79, object_id, payload.len() as u64, 0, payload.len() as u64);

        sender.pump_at(&right, now).unwrap();
        let first_frames = right.capture.lock().unwrap().clone();
        let first_transfer_id = Fragment::decode(first_frames.first().unwrap())
            .unwrap()
            .transfer_id;
        receiver.pump_at(&left, now).unwrap();
        assert_eq!(receiver.backend().ingested.len(), 1);

        // Suppress the causal receipt, advance beyond the replay-safe repair
        // epoch with higher-priority traffic, and evict transport-level
        // duplicate memory. The next DATA retry must be a fresh secure record;
        // semantic idempotence keeps the durable application count at one.
        right.inbound.lock().unwrap().clear();
        right.capture.lock().unwrap().clear();
        for index in 0..SECURE_REPLAY_WINDOW_RECORDS {
            let marker_id =
                ObjectId::for_envelope(EnvelopeId::from_sealed_bytes(&index.to_be_bytes()));
            let (semantic_version, plaintext) = sender
                .encode_message(&Message::Receipt(wire::Receipt {
                    exchange_id: 79,
                    object_id: marker_id,
                    total_len: 1,
                    received: Vec::new(),
                    complete: false,
                }))
                .unwrap();
            sender
                .queue_logical_once(plaintext, Priority::Flash, semantic_version)
                .unwrap();
        }
        sender.pump_at(&right, now).unwrap();
        receiver.pump_at(&left, now).unwrap();
        for offset in 0..MAX_COMPLETED_TRANSFERS {
            receiver.remember_completed_transfer(CompletedTransfer {
                peer: None,
                transfer_id: 50_000 + offset as u64,
                logical_len: offset,
                logical_digest: [offset as u8; 32],
            });
        }
        assert!(
            !receiver
                .completed_transfers
                .iter()
                .any(|entry| entry.transfer_id == first_transfer_id)
        );

        right.capture.lock().unwrap().clear();
        let retry_at = sender.retries[&key].due;
        sender.pump_at(&right, retry_at).unwrap();
        let second_frames = right.capture.lock().unwrap().clone();
        let second_transfer_id = Fragment::decode(second_frames.first().unwrap())
            .unwrap()
            .transfer_id;
        assert_ne!(second_transfer_id, first_transfer_id);
        assert_ne!(second_frames, first_frames);

        receiver.pump_at(&left, retry_at).unwrap();
        assert!(receiver.is_authenticated());
        assert_eq!(receiver.backend().ingested.len(), 1);
    }

    #[test]
    fn partial_send_errors_advance_fragment_coverage_without_duplicate_commit() {
        let (mut receiver, mut sender, left, right, mut now) =
            authenticated_runtime_pair(80, Priority::Routine);
        let payload = vec![0x6d; MAX_DATA_PAYLOAD_BYTES];
        let object_id = ObjectId::for_envelope(EnvelopeId::from_sealed_bytes(&payload));
        prepare_expected_object(&mut receiver, 80, object_id);
        sender
            .backend_mut()
            .priorities
            .insert(object_id, Priority::Routine);
        sender
            .queue_sync_message(&Message::Data(Data {
                exchange_id: 80,
                object_id,
                total_len: payload.len() as u64,
                offset: 0,
                payload,
                forwarding: b"authenticated-forwarding".to_vec(),
            }))
            .unwrap();
        let key = RetryKey::Data(
            80,
            object_id,
            MAX_DATA_PAYLOAD_BYTES as u64,
            0,
            MAX_DATA_PAYLOAD_BYTES as u64,
        );
        let flaky = PrefixErrorLink::new(right.with_mtu(96));

        flaky.begin_attempt(1);
        assert!(matches!(
            sender.pump_at(&flaky, now),
            Err(RuntimeError::Io(_))
        ));
        receiver.pump_at(&left, now).unwrap();
        let fragment_count = {
            let epoch = sender.retries[&key].transport_epoch.as_ref().unwrap();
            fragment::fragment(&epoch.sealed, usize::from(epoch.mtu), epoch.transfer_id)
                .unwrap()
                .len()
        };
        assert!(fragment_count > 4);

        let accepted_prefix = (fragment_count / 4).max(1);
        for _ in 0..fragment_count {
            now = sender.retries[&key].due;
            flaky.begin_attempt(accepted_prefix);
            assert!(matches!(
                sender.pump_at(&flaky, now),
                Err(RuntimeError::Io(_))
            ));
            receiver.pump_at(&left, now).unwrap();
            if receiver.sync.inventory().contains(&object_id) {
                break;
            }
        }
        assert!(receiver.sync.inventory().contains(&object_id));
        assert_eq!(receiver.backend().ingested.len(), 1);
        assert!(
            sender.retries[&key]
                .transport_epoch
                .as_ref()
                .is_some_and(|epoch| epoch.emission_cursor > 1)
        );

        now = sender.retries[&key].due;
        flaky.begin_attempt(usize::MAX);
        sender.pump_at(&flaky, now).unwrap();
        assert!(!sender.retries.contains_key(&key));
        assert_eq!(receiver.backend().ingested.len(), 1);
    }

    #[test]
    fn successful_repair_rounds_rotate_before_fragment_scaled_partial_limit() {
        let (_receiver, mut sender, _left, right, mut now) =
            authenticated_runtime_pair(825, Priority::Routine);
        let payload = vec![0x25; MAX_DATA_PAYLOAD_BYTES];
        let object_id = ObjectId::for_envelope(EnvelopeId::from_sealed_bytes(&payload));
        sender
            .queue_sync_message(&Message::Data(Data {
                exchange_id: 825,
                object_id,
                total_len: payload.len() as u64,
                offset: 0,
                payload,
                forwarding: b"authenticated-forwarding".to_vec(),
            }))
            .unwrap();
        let key = RetryKey::Data(
            825,
            object_id,
            MAX_DATA_PAYLOAD_BYTES as u64,
            0,
            MAX_DATA_PAYLOAD_BYTES as u64,
        );
        let narrow = right.with_mtu(96);
        let sealed_before = sender.secure_records_sealed;

        sender.pump_at(&narrow, now).unwrap();
        let first_transfer_id = sender.retries[&key]
            .transport_epoch
            .as_ref()
            .unwrap()
            .transfer_id;
        let fragment_count = fragment::fragment(
            &sender.retries[&key]
                .transport_epoch
                .as_ref()
                .unwrap()
                .sealed,
            96,
            first_transfer_id,
        )
        .unwrap()
        .len();
        assert!(fragment_count > usize::from(MAX_SUCCESSFUL_RECORD_REPAIR_ROUNDS));

        for _ in 1..MAX_SUCCESSFUL_RECORD_REPAIR_ROUNDS {
            now = sender.retries[&key].due;
            sender.pump_at(&narrow, now).unwrap();
        }
        let exhausted = sender.retries[&key].transport_epoch.as_ref().unwrap();
        assert_eq!(exhausted.repair_rounds, MAX_SUCCESSFUL_RECORD_REPAIR_ROUNDS);
        assert_eq!(exhausted.transfer_id, first_transfer_id);

        now = sender.retries[&key].due;
        sender.pump_at(&narrow, now).unwrap();
        let fresh = sender.retries[&key].transport_epoch.as_ref().unwrap();
        assert_ne!(fresh.transfer_id, first_transfer_id);
        assert_eq!(fresh.repair_rounds, 1);
        assert_eq!(sender.secure_records_sealed, sealed_before + 2);
    }

    #[test]
    fn retry_epoch_rotates_when_link_mtu_changes() {
        let (mut receiver, mut sender, left, right, now) =
            authenticated_runtime_pair(81, Priority::Routine);
        let payload = vec![0x7a; 4_096];
        let object_id = ObjectId::for_envelope(EnvelopeId::from_sealed_bytes(&payload));
        prepare_expected_object(&mut receiver, 81, object_id);
        sender
            .backend_mut()
            .priorities
            .insert(object_id, Priority::Routine);
        sender
            .queue_sync_message(&Message::Data(Data {
                exchange_id: 81,
                object_id,
                total_len: payload.len() as u64,
                offset: 0,
                payload,
                forwarding: b"authenticated-forwarding".to_vec(),
            }))
            .unwrap();
        let key = RetryKey::Data(81, object_id, 4_096, 0, 4_096);

        sender.pump_at(&right, now).unwrap();
        let old_epoch = sender.retries[&key].transport_epoch.as_ref().unwrap();
        let old_transfer_id = old_epoch.transfer_id;
        right.force_drop_transfer(old_transfer_id);
        left.inbound.lock().unwrap().clear();
        right.capture.lock().unwrap().clear();
        sender.retries.get_mut(&key).unwrap().due = now;

        let narrower = right.with_mtu(96);
        sender.pump_at(&narrower, now).unwrap();
        let new_epoch = sender.retries[&key].transport_epoch.as_ref().unwrap();
        assert_eq!(new_epoch.mtu, 96);
        assert_ne!(new_epoch.transfer_id, old_transfer_id);
        receiver.pump_at(&left, now).unwrap();
        assert!(receiver.sync.inventory().contains(&object_id));
        assert_eq!(receiver.backend().ingested.len(), 1);
    }

    #[test]
    fn one_shot_outbox_is_retained_across_partial_send_failure() {
        let (mut receiver, mut sender, left, right, mut now) =
            authenticated_runtime_pair(82, Priority::Routine);
        let object_id = ObjectId::for_envelope(EnvelopeId::from_sealed_bytes(b"one-shot"));
        sender
            .queue_sync_message(&Message::Receipt(wire::Receipt {
                exchange_id: 82,
                object_id,
                total_len: 1,
                received: Vec::new(),
                complete: false,
            }))
            .unwrap();
        let flaky = PrefixErrorLink::new(right);
        let sealed_before = sender.secure_records_sealed;

        flaky.begin_attempt(0);
        assert!(matches!(
            sender.pump_at(&flaky, now),
            Err(RuntimeError::Io(_))
        ));
        assert_eq!(sender.outbox.len(), 1);
        assert_eq!(sender.secure_records_sealed, sealed_before + 1);

        now = sender.outbox[0].due;
        flaky.begin_attempt(usize::MAX);
        sender.pump_at(&flaky, now).unwrap();
        assert!(sender.outbox.is_empty());
        assert_eq!(sender.secure_records_sealed, sealed_before + 1);
        receiver.pump_at(&left, now).unwrap();
        assert!(receiver.is_authenticated());
    }

    #[test]
    fn failed_outbox_send_is_charged_and_rescheduled_while_inbound_is_drained() {
        let (mut receiver, mut sender, left, right, now) =
            authenticated_runtime_pair(826, Priority::Routine);
        receiver.retries.clear();
        receiver.deferred_wants.clear();
        receiver.outbox.clear();
        sender.retries.clear();
        sender.deferred_wants.clear();
        sender.outbox.clear();
        receiver.backend_mut().receipts.clear();
        left.inbound.lock().unwrap().clear();
        right.inbound.lock().unwrap().clear();

        for index in 0..MAX_PENDING_OUTBOX {
            let object_id = ObjectId::for_envelope(EnvelopeId::from_sealed_bytes(
                &u64::try_from(index).unwrap().to_le_bytes(),
            ));
            sender
                .queue_sync_message(&Message::Receipt(wire::Receipt {
                    exchange_id: 826,
                    object_id,
                    total_len: 1,
                    received: Vec::new(),
                    complete: false,
                }))
                .unwrap();
        }
        sender.pump_at(&right, now).unwrap();
        assert!(sender.outbox.is_empty());

        let failing_id = ObjectId::for_envelope(EnvelopeId::from_sealed_bytes(b"failing-outbox"));
        receiver
            .queue_sync_message(&Message::Receipt(wire::Receipt {
                exchange_id: 826,
                object_id: failing_id,
                total_len: 1,
                received: Vec::new(),
                complete: false,
            }))
            .unwrap();
        let flaky = PrefixErrorLink::new(left);
        flaky.begin_attempt(0);
        let sealed_before = receiver.secure_records_sealed;

        assert!(matches!(
            receiver.pump_at(&flaky, now),
            Err(RuntimeError::Io(_))
        ));
        assert_eq!(receiver.backend().receipts.len(), MAX_PENDING_OUTBOX);
        assert_eq!(receiver.outbox.len(), 1);
        assert_eq!(receiver.outbox[0].attempts, 1);
        assert!(receiver.outbox[0].due > now);
        assert_eq!(
            receiver.outbox[0]
                .transport_epoch
                .as_ref()
                .unwrap()
                .emission_cursor,
            1
        );
        assert_eq!(receiver.secure_records_sealed, sealed_before + 1);
    }

    #[test]
    fn one_shot_outbox_rotates_fragment_prefixes_until_persistently_partial_delivery() {
        let (mut receiver, mut sender, left, right, mut now) =
            authenticated_runtime_pair(820, Priority::Routine);
        let object_id = ObjectId::for_envelope(EnvelopeId::from_sealed_bytes(b"large-receipt"));
        let received = (0_u64..512)
            .map(|index| ByteRange {
                start: index * 2,
                end: index * 2 + 1,
            })
            .collect();
        sender
            .queue_sync_message(&Message::Receipt(wire::Receipt {
                exchange_id: 820,
                object_id,
                total_len: 1_024,
                received,
                complete: false,
            }))
            .unwrap();
        let flaky = PrefixErrorLink::new(right.with_mtu(96));

        flaky.begin_attempt(0);
        assert!(matches!(
            sender.pump_at(&flaky, now),
            Err(RuntimeError::Io(_))
        ));
        let fragment_count = {
            let epoch = sender.outbox[0].transport_epoch.as_ref().unwrap();
            fragment::fragment(&epoch.sealed, usize::from(epoch.mtu), epoch.transfer_id)
                .unwrap()
                .len()
        };
        assert!(fragment_count > 8);

        let accepted_prefix = (fragment_count / 4).max(1);
        for _ in 0..fragment_count {
            now = sender.outbox[0].due;
            flaky.begin_attempt(accepted_prefix);
            assert!(matches!(
                sender.pump_at(&flaky, now),
                Err(RuntimeError::Io(_))
            ));
            receiver.pump_at(&left, now).unwrap();
            if !receiver.backend().receipts.is_empty() {
                break;
            }
        }
        assert_eq!(receiver.backend().receipts.len(), 1);
        assert_eq!(receiver.backend().receipts[0].2.object_id, object_id);
        assert_eq!(sender.outbox.len(), 1);

        now = sender.outbox[0].due;
        flaky.begin_attempt(usize::MAX);
        sender.pump_at(&flaky, now).unwrap();
        assert!(sender.outbox.is_empty());
        receiver.pump_at(&left, now).unwrap();
        assert_eq!(receiver.backend().receipts.len(), 1);
    }

    #[test]
    fn handshake_retries_rotate_fragment_prefixes_under_persistent_partial_sends() {
        let (initiator_bundle, responder_bundle) = bundles();
        let mut initiator = RuntimeDriver::initiator(
            initiator_bundle,
            SyncState::new(Default::default(), SparseInventory::new()).unwrap(),
            FakeBackend::default(),
            StartRequest {
                exchange_id: 821,
                topics: vec!["alpha".into()],
                scopes: vec!["mission/team".into()],
                min_priority: Priority::Routine as u8,
            },
            None,
        )
        .unwrap();
        let mut responder = RuntimeDriver::responder(
            responder_bundle,
            SyncState::new(Default::default(), SparseInventory::new()).unwrap(),
            FakeBackend::default(),
            None,
        )
        .unwrap();
        let (left, right) = MemoryLink::pair(96);
        let flaky_left = PrefixErrorLink::new(left);
        let flaky_right = PrefixErrorLink::new(right);
        let mut now = Instant::now();
        let mut partial_errors = 0_usize;

        for _ in 0..1_024 {
            now += Duration::from_secs(70);
            flaky_left.begin_attempt(1);
            if matches!(
                initiator.pump_at(&flaky_left, now),
                Err(RuntimeError::Io(_))
            ) {
                partial_errors += 1;
            }
            flaky_right.begin_attempt(1);
            if matches!(
                responder.pump_at(&flaky_right, now),
                Err(RuntimeError::Io(_))
            ) {
                partial_errors += 1;
            }
            if initiator.is_authenticated()
                && responder.is_authenticated()
                && responder.handshake_retry.is_none()
                && responder.sync.active_exchange_id() == Some(821)
            {
                break;
            }
        }

        assert!(partial_errors > 0);
        assert!(initiator.is_authenticated());
        assert!(responder.is_authenticated());
        assert_eq!(responder.sync.active_exchange_id(), Some(821));
    }

    #[test]
    fn handshake_retry_uses_a_fresh_transfer_id_after_mtu_change() {
        let (initiator_bundle, _responder_bundle) = bundles();
        let mut initiator = RuntimeDriver::initiator(
            initiator_bundle,
            SyncState::new(Default::default(), SparseInventory::new()).unwrap(),
            FakeBackend::default(),
            StartRequest {
                exchange_id: 822,
                topics: vec!["alpha".into()],
                scopes: vec!["mission/team".into()],
                min_priority: Priority::Routine as u8,
            },
            None,
        )
        .unwrap();
        let (left, _right) = MemoryLink::pair(96);
        let narrow = PrefixErrorLink::new(left.clone());
        narrow.begin_attempt(0);
        assert!(matches!(
            initiator.pump_at(&narrow, Instant::now()),
            Err(RuntimeError::Io(_))
        ));
        let first_transfer_id = initiator.handshake_retry.as_ref().unwrap().transfer_id;

        let wider = PrefixErrorLink::new(left.with_mtu(128));
        wider.begin_attempt(0);
        let later = Instant::now() + Duration::from_secs(70);
        assert!(matches!(
            initiator.pump_at(&wider, later),
            Err(RuntimeError::Io(_))
        ));
        let retry = initiator.handshake_retry.as_ref().unwrap();
        assert_eq!(retry.mtu, Some(128));
        assert_ne!(retry.transfer_id, first_transfer_id);
    }

    #[test]
    fn reopened_durable_disposition_reissues_complete_receipt_without_visibility() {
        let (mut receiver, mut sender, left, right, now) =
            authenticated_runtime_pair(823, Priority::Routine);
        let payload = b"durably-disposed-before-runtime-reopen".to_vec();
        let object_id = ObjectId::for_envelope(EnvelopeId::from_sealed_bytes(&payload));
        let semantic_version = receiver.authenticated_semantic_version().unwrap();
        receiver
            .backend_mut()
            .disposed
            .insert((object_id, semantic_version), payload.len() as u64);
        sender
            .queue_sync_message(&Message::Data(Data {
                exchange_id: 823,
                object_id,
                total_len: payload.len() as u64,
                offset: 0,
                payload,
                forwarding: b"authenticated-forwarding".to_vec(),
            }))
            .unwrap();
        let key = RetryKey::Data(
            823,
            object_id,
            b"durably-disposed-before-runtime-reopen".len() as u64,
            0,
            b"durably-disposed-before-runtime-reopen".len() as u64,
        );

        sender.pump_at(&right, now).unwrap();
        receiver.pump_at(&left, now).unwrap();
        assert!(receiver.backend().partial.is_empty());
        assert!(receiver.backend().ingested.is_empty());
        assert!(!receiver.sync.inventory().contains(&object_id));
        assert!(!receiver.sync.wants().contains(&object_id));

        sender.pump_at(&right, now).unwrap();
        assert!(!sender.retries.contains_key(&key));
        assert_eq!(sender.backend().receipts.len(), 1);
        let receipt = &sender.backend().receipts[0].2;
        assert!(receipt.complete);
        assert_eq!(receipt.object_id, object_id);
        assert_eq!(
            receipt.received,
            vec![ByteRange {
                start: 0,
                end: receipt.total_len,
            }]
        );
    }

    #[test]
    fn durable_disposition_length_mismatch_fails_closed() {
        let (mut receiver, mut sender, left, right, now) =
            authenticated_runtime_pair(824, Priority::Routine);
        let payload = b"durable-length".to_vec();
        let object_id = ObjectId::for_envelope(EnvelopeId::from_sealed_bytes(&payload));
        let semantic_version = receiver.authenticated_semantic_version().unwrap();
        receiver.backend_mut().disposed.insert(
            (object_id, semantic_version),
            payload.len().saturating_add(1) as u64,
        );
        sender
            .queue_sync_message(&Message::Data(Data {
                exchange_id: 824,
                object_id,
                total_len: payload.len() as u64,
                offset: 0,
                payload,
                forwarding: b"authenticated-forwarding".to_vec(),
            }))
            .unwrap();

        sender.pump_at(&right, now).unwrap();
        assert!(matches!(
            receiver.pump_at(&left, now),
            Err(RuntimeError::BackendContract(
                "disposed object length changed"
            ))
        ));
        assert!(receiver.backend().partial.is_empty());
        assert!(receiver.backend().ingested.is_empty());
        assert!(!receiver.sync.inventory().contains(&object_id));
    }

    #[test]
    fn stale_routine_epoch_waits_for_due_time_without_blocking_flash() {
        let (_receiver, mut sender, _left, right, now) =
            authenticated_runtime_pair(83, Priority::Routine);
        let interest = Message::Interest(crate::wire::Interest {
            exchange_id: 83,
            topics: vec!["alpha".into()],
            scopes: vec!["mission/team".into()],
            min_priority: Priority::Routine as u8,
            max_offers: 1,
        });
        sender.queue_sync_message(&interest).unwrap();
        sender.pump_at(&right, now).unwrap();
        let key = RetryKey::Interest(83);
        let old_epoch = sender.retries[&key]
            .transport_epoch
            .as_ref()
            .unwrap()
            .clone();
        let old_attempts = sender.retries[&key].attempts;
        sender.secure_records_sealed = old_epoch.sealed_ordinal + SECURE_REPLAY_WINDOW_RECORDS;
        let routine_due = now + Duration::from_secs(64);
        sender.retries.get_mut(&key).unwrap().due = routine_due;
        right.capture.lock().unwrap().clear();

        let marker_id = ObjectId::for_envelope(EnvelopeId::from_sealed_bytes(b"flash-marker"));
        let (semantic_version, plaintext) = sender
            .encode_message(&Message::Receipt(wire::Receipt {
                exchange_id: 83,
                object_id: marker_id,
                total_len: 1,
                received: Vec::new(),
                complete: false,
            }))
            .unwrap();
        sender
            .queue_logical_once(plaintext, Priority::Flash, semantic_version)
            .unwrap();
        assert_eq!(sender.next_wakeup(&right), Some(now));

        sender.pump_at(&right, now).unwrap();
        assert!(sender.outbox.is_empty());
        assert_eq!(sender.retries[&key].attempts, old_attempts);
        assert_eq!(
            sender.retries[&key]
                .transport_epoch
                .as_ref()
                .unwrap()
                .transfer_id,
            old_epoch.transfer_id
        );
        assert_eq!(sender.next_wakeup(&right), Some(routine_due));

        right.capture.lock().unwrap().clear();
        sender.pump_at(&right, routine_due).unwrap();
        let rotated_epoch = sender.retries[&key].transport_epoch.as_ref().unwrap();
        assert_ne!(rotated_epoch.transfer_id, old_epoch.transfer_id);
        assert_eq!(sender.retries[&key].attempts, old_attempts + 1);
        let dispatched = Fragment::decode(right.capture.lock().unwrap().first().unwrap())
            .unwrap()
            .transfer_id;
        assert_eq!(dispatched, rotated_epoch.transfer_id);
    }

    #[test]
    fn rotated_prefixes_cover_exact_periodic_half_loss() {
        for fragment_count in [2, 3, 17, 1_000] {
            let mut delivered = vec![false; fragment_count];
            let prefix_len = fragment_count.div_ceil(2);
            for round in 0..transport_repair_round_limit(fragment_count) {
                let offset = transport_fragment_emission_offset(fragment_count, round);
                for index in 0..prefix_len {
                    delivered[(offset + index) % fragment_count] = true;
                }
            }
            assert!(
                delivered.into_iter().all(|seen| seen),
                "periodic half-loss left a hole for {fragment_count} fragments"
            );
        }
    }

    #[test]
    fn pump_bounds_hostile_incomplete_fragment_queue() {
        let (mut receiver, _sender, left, _right, now) =
            authenticated_runtime_pair(84, Priority::Routine);
        let logical = vec![0x44; 256];
        left.inbound.lock().unwrap().clear();
        for transfer_id in 1..=MAX_RECEIVED_FRAMES_PER_PUMP + 1 {
            let first = fragment::fragment(&logical, 64, transfer_id as u64)
                .unwrap()
                .remove(0)
                .encode()
                .unwrap();
            left.inbound.lock().unwrap().push_back(ReceivedFrame {
                peer: None,
                bytes: first,
            });
        }

        assert_eq!(receiver.pump_at(&left, now).unwrap(), 0);
        assert_eq!(left.inbound.lock().unwrap().len(), 1);
    }

    #[test]
    fn stale_future_retry_does_not_preempt_equal_priority_receipt() {
        let (mut receiver, _sender, left, right, now) =
            authenticated_runtime_pair(841, Priority::Routine);
        receiver.retries.clear();
        receiver.deferred_wants.clear();
        receiver.outbox.clear();
        left.inbound.lock().unwrap().clear();
        right.inbound.lock().unwrap().clear();

        receiver
            .queue_sync_message(&Message::Interest(crate::wire::Interest {
                exchange_id: 841,
                topics: vec!["alpha".into()],
                scopes: vec!["mission/team".into()],
                min_priority: Priority::Routine as u8,
                max_offers: 1,
            }))
            .unwrap();
        receiver.pump_at(&left, now).unwrap();
        let retry_key = RetryKey::Interest(841);
        let old_epoch = receiver.retries[&retry_key]
            .transport_epoch
            .as_ref()
            .unwrap()
            .clone();
        let old_attempts = receiver.retries[&retry_key].attempts;
        let retry_due = now + Duration::from_secs(64);
        receiver.retries.get_mut(&retry_key).unwrap().due = retry_due;
        receiver.secure_records_sealed = old_epoch.sealed_ordinal + SECURE_REPLAY_WINDOW_RECORDS;
        right.inbound.lock().unwrap().clear();
        left.capture.lock().unwrap().clear();

        let marker_id = ObjectId::for_envelope(EnvelopeId::from_sealed_bytes(b"pump-yield-marker"));
        let receipt = Message::Receipt(wire::Receipt {
            exchange_id: 841,
            object_id: marker_id,
            total_len: 1,
            received: vec![ByteRange { start: 0, end: 1 }],
            complete: true,
        });
        receiver.queue_sync_message(&receipt).unwrap();
        let waiting_sequence = receiver.outbox.front().unwrap().sequence;
        let sealed_before = receiver.secure_records_sealed;
        assert_eq!(receiver.next_wakeup(&left), Some(now));

        assert_eq!(receiver.pump_at(&left, now).unwrap(), 0);
        assert_eq!(receiver.secure_records_sealed, sealed_before + 1);
        assert_eq!(receiver.retries[&retry_key].attempts, old_attempts);
        assert_eq!(
            receiver.retries[&retry_key]
                .transport_epoch
                .as_ref()
                .unwrap()
                .transfer_id,
            old_epoch.transfer_id
        );
        let first_dispatched = Fragment::decode(left.capture.lock().unwrap().first().unwrap())
            .unwrap()
            .transfer_id;
        assert_ne!(first_dispatched, old_epoch.transfer_id);
        assert!(
            receiver
                .outbox
                .iter()
                .all(|entry| entry.sequence != waiting_sequence)
        );
        assert_eq!(receiver.next_wakeup(&left), Some(retry_due));

        left.capture.lock().unwrap().clear();
        receiver.pump_at(&left, retry_due).unwrap();
        let rotated_epoch = receiver.retries[&retry_key]
            .transport_epoch
            .as_ref()
            .unwrap();
        assert_ne!(rotated_epoch.transfer_id, old_epoch.transfer_id);
        assert_eq!(receiver.retries[&retry_key].attempts, old_attempts + 1);
    }

    #[test]
    fn full_replay_window_does_not_starve_one_shot_and_reseals_retry_on_demand() {
        let (mut receiver, _sender, left, right, now) =
            authenticated_runtime_pair(842, Priority::Routine);
        receiver.retries.clear();
        receiver.deferred_wants.clear();
        receiver.outbox.clear();
        left.inbound.lock().unwrap().clear();
        right.inbound.lock().unwrap().clear();

        for index in 0..MAX_RETRY_SENDS_PER_PUMP {
            let object_id = ObjectId::for_envelope(EnvelopeId::from_sealed_bytes(
                &u64::try_from(index).unwrap().to_le_bytes(),
            ));
            receiver
                .backend_mut()
                .priorities
                .insert(object_id, Priority::Routine);
            receiver
                .queue_sync_message(&Message::Data(Data {
                    exchange_id: 842,
                    object_id,
                    total_len: 1,
                    offset: 0,
                    payload: vec![index as u8],
                    forwarding: b"authenticated-forwarding".to_vec(),
                }))
                .unwrap();
        }
        let marker_id = ObjectId::for_envelope(EnvelopeId::from_sealed_bytes(b"pump-yield-marker"));
        let receipt = Message::Receipt(wire::Receipt {
            exchange_id: 842,
            object_id: marker_id,
            total_len: 1,
            received: vec![ByteRange { start: 0, end: 1 }],
            complete: true,
        });
        receiver.queue_sync_message(&receipt).unwrap();
        let waiting_sequence = receiver.outbox.front().unwrap().sequence;

        assert_eq!(receiver.pump_at(&left, now).unwrap(), 0);
        assert_eq!(receiver.outbox.len(), 1);
        assert_eq!(receiver.retries.len(), MAX_RETRY_SENDS_PER_PUMP);

        let oldest_key = receiver
            .retries
            .iter()
            .min_by_key(|(_, entry)| entry.transport_epoch.as_ref().unwrap().sealed_ordinal)
            .map(|(key, _)| key.clone())
            .unwrap();
        let retry_due = receiver.retries[&oldest_key].due;
        for (key, entry) in &mut receiver.retries {
            if *key != oldest_key {
                entry.due = retry_due + Duration::from_secs(60);
            }
        }
        let retry_snapshot = receiver
            .retries
            .iter()
            .map(|(key, entry)| {
                (
                    key.clone(),
                    (
                        entry.attempts,
                        entry.transport_epoch.as_ref().unwrap().transfer_id,
                    ),
                )
            })
            .collect::<BTreeMap<_, _>>();
        let sealed_before_receipt = receiver.secure_records_sealed;
        right.inbound.lock().unwrap().clear();

        receiver.pump_at(&left, now).unwrap();
        assert!(
            receiver
                .outbox
                .iter()
                .all(|entry| entry.sequence != waiting_sequence)
        );
        assert_eq!(receiver.secure_records_sealed, sealed_before_receipt + 1);
        let after_receipt = receiver
            .retries
            .iter()
            .map(|(key, entry)| {
                (
                    key.clone(),
                    (
                        entry.attempts,
                        entry.transport_epoch.as_ref().unwrap().transfer_id,
                    ),
                )
            })
            .collect::<BTreeMap<_, _>>();
        assert_eq!(after_receipt, retry_snapshot);
        assert_eq!(receiver.next_wakeup(&left), Some(retry_due));

        let old_epoch = receiver.retries[&oldest_key]
            .transport_epoch
            .as_ref()
            .unwrap()
            .clone();
        receiver.pump_at(&left, retry_due).unwrap();
        let refreshed = receiver.retries[&oldest_key]
            .transport_epoch
            .as_ref()
            .unwrap();
        assert_ne!(refreshed.transfer_id, old_epoch.transfer_id);
        assert!(refreshed.sealed_ordinal > old_epoch.sealed_ordinal);
        assert_eq!(
            receiver.retries[&oldest_key].attempts,
            retry_snapshot[&oldest_key].0 + 1
        );
    }

    #[test]
    fn retained_retry_budget_is_byte_accounted_and_flash_displaces_routine() {
        let (_left_driver, mut driver, _left, _right, _now) =
            authenticated_runtime_pair(76, Priority::Routine);
        let payload = vec![0x55; MAX_DATA_PAYLOAD_BYTES];
        let mut saturated = false;

        for index in 0..(MAX_PENDING_RETRIES * 2) {
            let object_id = ObjectId::for_envelope(EnvelopeId::from_sealed_bytes(
                &u64::try_from(index).unwrap().to_le_bytes(),
            ));
            driver
                .backend_mut()
                .priorities
                .insert(object_id, Priority::Routine);
            let result = driver.queue_sync_message(&Message::Data(Data {
                exchange_id: 76,
                object_id,
                total_len: payload.len() as u64,
                offset: 0,
                payload: payload.clone(),
                forwarding: b"authenticated-forwarding".to_vec(),
            }));
            match result {
                Ok(()) => {
                    assert!(driver.pending_logical_bytes() <= MAX_PENDING_LOGICAL_BYTES);
                    assert!(
                        driver.non_deferred_pending_bytes()
                            <= MAX_PENDING_LOGICAL_BYTES - DEFERRED_WANT_EPOCH_RESERVE
                    );
                }
                Err(RuntimeError::Backpressure) => {
                    saturated = true;
                    break;
                }
                Err(error) => panic!("unexpected queue failure: {error}"),
            }
        }

        assert!(
            saturated,
            "hostile routine traffic reached explicit backpressure"
        );
        assert!(driver.retries.len() <= MAX_PENDING_RETRIES);
        assert!(driver.outbox.len() <= MAX_PENDING_OUTBOX);
        assert!(driver.pending_logical_bytes() <= MAX_PENDING_LOGICAL_BYTES);
        assert!(
            driver.non_deferred_pending_bytes()
                <= MAX_PENDING_LOGICAL_BYTES - DEFERRED_WANT_EPOCH_RESERVE
        );
        for (key, entry) in &driver.retries {
            let plaintext = wire::encode_message_for_semantic_version(
                &entry.message,
                entry.semantic_version,
                driver.wire_limits,
            )
            .unwrap();
            let record_reservation = transport_record_reservation(&plaintext).max(
                entry
                    .transport_epoch
                    .as_ref()
                    .map(|epoch| epoch.sealed.capacity())
                    .unwrap_or(0),
            );
            assert_eq!(
                entry.retained_bytes,
                retry_record_bytes(key, &entry.message, record_reservation)
            );
        }

        let routine_before = driver
            .retries
            .values()
            .filter(|entry| entry.priority == Priority::Routine)
            .count();
        let flash_id = ObjectId::for_envelope(EnvelopeId::from_sealed_bytes(b"flash-replacement"));
        driver
            .backend_mut()
            .priorities
            .insert(flash_id, Priority::Flash);
        driver
            .queue_sync_message(&Message::Data(Data {
                exchange_id: 76,
                object_id: flash_id,
                total_len: payload.len() as u64,
                offset: 0,
                payload,
                forwarding: b"authenticated-forwarding".to_vec(),
            }))
            .unwrap();

        assert!(driver.retries.contains_key(&RetryKey::Data(
            76,
            flash_id,
            MAX_DATA_PAYLOAD_BYTES as u64,
            0,
            MAX_DATA_PAYLOAD_BYTES as u64,
        )));
        assert!(
            driver
                .retries
                .values()
                .filter(|entry| entry.priority == Priority::Routine)
                .count()
                < routine_before
        );
        assert!(driver.pending_logical_bytes() <= MAX_PENDING_LOGICAL_BYTES);
    }

    #[test]
    fn saturated_retry_set_keeps_and_reschedules_durable_want_progress() {
        let (mut driver, _right_driver, left, _right, now) =
            authenticated_runtime_pair(77, Priority::Routine);
        let payload = vec![0x33; 1_024];

        for index in 0..(MAX_PENDING_RETRIES + MAX_PENDING_OUTBOX + 1) {
            let object_id = ObjectId::for_envelope(EnvelopeId::from_sealed_bytes(
                &u64::try_from(index).unwrap().to_be_bytes(),
            ));
            driver
                .backend_mut()
                .priorities
                .insert(object_id, Priority::Flash);
            let result = driver.queue_sync_message(&Message::Data(Data {
                exchange_id: 77,
                object_id,
                total_len: payload.len() as u64,
                offset: 0,
                payload: payload.clone(),
                forwarding: b"authenticated-forwarding".to_vec(),
            }));
            if matches!(result, Err(RuntimeError::Backpressure)) {
                break;
            }
            result.unwrap();
        }
        let marker_id = ObjectId::for_envelope(EnvelopeId::from_sealed_bytes(b"outbox-marker"));
        for _ in 0..MAX_PENDING_OUTBOX {
            let (semantic_version, plaintext) = driver
                .encode_message(&Message::Receipt(wire::Receipt {
                    exchange_id: 77,
                    object_id: marker_id,
                    total_len: 1,
                    received: Vec::new(),
                    complete: false,
                }))
                .unwrap();
            driver
                .queue_logical_once(plaintext, Priority::Flash, semantic_version)
                .unwrap();
        }
        assert_eq!(driver.retries.len(), MAX_PENDING_RETRIES);
        assert_eq!(driver.outbox.len(), MAX_PENDING_OUTBOX);

        let wanted_id = ObjectId::for_envelope(EnvelopeId::from_sealed_bytes(b"durable-want"));
        let offer = pending_offer_for(&mut driver, 77, [wanted_id]);
        let actions = driver
            .sync
            .apply(SyncEvent::Receive(Message::Offer(offer)))
            .unwrap();
        driver.handle_actions(actions).unwrap();
        assert!(driver.sync.wants().contains(&wanted_id));
        assert!(driver.deferred_wants.contains_key(&wanted_id));
        assert!(driver.pending_logical_bytes() <= MAX_PENDING_LOGICAL_BYTES);

        // Model successful dispatch of the one-shot queue while all retained
        // FLASH slots remain occupied. The compact ROUTINE WANT cannot replace
        // them, but it still receives a fresh authenticated retry.
        driver.outbox.clear();
        for entry in driver.retries.values_mut() {
            entry.due = now + Duration::from_secs(3_600);
        }
        left.capture.lock().unwrap().clear();
        driver.pump_at(&left, now).unwrap();
        let deferred = driver
            .deferred_wants
            .get(&wanted_id)
            .expect("durable WANT remains represented while slots are saturated");
        assert_eq!(deferred.attempts, 1);
        assert!(deferred.due > now);
        assert!(!left.capture.lock().unwrap().is_empty());
        assert!(driver.sync.wants().contains(&wanted_id));

        // Once acknowledged work frees slots, the same durable request is
        // promoted to a retained retry without an application re-request.
        driver.retries.clear();
        let retry_at = deferred.due;
        left.capture.lock().unwrap().clear();
        driver.pump_at(&left, retry_at).unwrap();
        assert!(!driver.deferred_wants.contains_key(&wanted_id));
        assert!(driver.retries.contains_key(&RetryKey::Want(77, wanted_id)));
        assert!(driver.sync.wants().contains(&wanted_id));
        assert!(driver.pending_logical_bytes() <= MAX_PENDING_LOGICAL_BYTES);
    }

    #[test]
    fn maximum_want_fanout_uses_bounded_flow_control_without_contact_failure() {
        let (_left_driver, mut driver, _left, _right, _now) =
            authenticated_runtime_pair(78, Priority::Routine);
        driver.backend_mut().fanout_messages = MAX_DATA_MESSAGES_PER_WANT;
        let mut items = Vec::with_capacity(128);
        for index in 0_u64..128 {
            let object_id =
                ObjectId::for_envelope(EnvelopeId::from_sealed_bytes(&index.to_le_bytes()));
            driver
                .backend_mut()
                .available
                .insert(object_id, vec![index as u8; MAX_DATA_PAYLOAD_BYTES]);
            items.push(WantItem {
                object_id,
                total_len: None,
                missing: Vec::new(),
                need_forwarding: true,
            });
        }
        items.sort_by_key(|item| item.object_id);
        driver.local_inventory_changed().unwrap();
        driver.retries.clear();
        driver.deferred_wants.clear();
        driver.outbox.clear();
        let replay = items.last().cloned().unwrap();
        let actions = driver
            .sync
            .apply(SyncEvent::Receive(Message::Want(crate::wire::Want {
                exchange_id: 78,
                items,
            })))
            .unwrap();
        assert_eq!(actions.len(), 128);

        driver.handle_actions(actions).unwrap();
        let requests_before_replay = driver.backend().data_requests;
        assert!(requests_before_replay > 0);
        assert!(requests_before_replay < 128);
        assert!(driver.retries.len() <= MAX_PENDING_RETRIES);
        assert!(driver.outbox.len() <= MAX_PENDING_OUTBOX);
        assert!(driver.pending_logical_bytes() <= MAX_PENDING_LOGICAL_BYTES);

        // The requester retains every incomplete WANT. Once receipts free
        // capacity, replay of a previously skipped singleton resumes that
        // exact object without rebuilding the inventory exchange.
        driver.retries.clear();
        driver
            .handle_actions(vec![SyncAction::Serve(replay.clone())])
            .unwrap();
        assert_eq!(driver.backend().data_requests, requests_before_replay + 1);
        assert!(driver.retries.contains_key(&RetryKey::Data(
            78,
            replay.object_id,
            u64::try_from(MAX_DATA_PAYLOAD_BYTES * MAX_DATA_MESSAGES_PER_WANT).unwrap(),
            0,
            u64::try_from(MAX_DATA_PAYLOAD_BYTES).unwrap(),
        )));
    }

    #[test]
    fn peer_neutral_durable_want_skips_unavailable_peer_and_resumes_with_another() {
        let mut provisioner = ReferenceProvisioner::from_seed([0x71; 32]).unwrap();
        let access = ProvisioningAccess::member(
            Scope::new("mission/team").unwrap(),
            vec![0],
            vec![Topic::new("alpha").unwrap()],
        )
        .unwrap();
        let requester_bytes = provisioner
            .issue_node(1, std::slice::from_ref(&access))
            .unwrap()
            .to_bytes()
            .unwrap();
        let empty_peer_bytes = provisioner
            .issue_node(2, std::slice::from_ref(&access))
            .unwrap()
            .to_bytes()
            .unwrap();
        let provider_bytes = provisioner
            .issue_node(3, std::slice::from_ref(&access))
            .unwrap()
            .to_bytes()
            .unwrap();
        let payload = b"peer-neutral-resume".to_vec();
        let object_id = ObjectId::for_envelope(EnvelopeId::from_sealed_bytes(&payload));
        let split = payload.len() / 2;
        let mut partial = vec![0; payload.len()];
        partial[split..].copy_from_slice(&payload[split..]);
        let progress = RuntimeTransferProgress {
            object_id,
            origin_semantic_version: Some(wire::SEMANTIC_PROTOCOL_V1),
            total_len: payload.len() as u64,
            received: vec![ByteRange {
                start: split as u64,
                end: payload.len() as u64,
            }],
        };
        let mut requester_backend = FakeBackend {
            durable_progress: vec![progress],
            ..FakeBackend::default()
        };
        requester_backend.partial.insert(object_id, partial);
        let request = |exchange_id| StartRequest {
            exchange_id,
            topics: vec!["alpha".into()],
            scopes: vec!["mission/team".into()],
            min_priority: Priority::Routine as u8,
        };

        let mut requester = RuntimeDriver::initiator(
            ProvisioningBundle::from_bytes(&requester_bytes).unwrap(),
            SyncState::new(Default::default(), SparseInventory::new()).unwrap(),
            requester_backend,
            request(784),
            None,
        )
        .unwrap();
        let mut empty_peer = RuntimeDriver::responder(
            ProvisioningBundle::from_bytes(&empty_peer_bytes).unwrap(),
            SyncState::new(Default::default(), SparseInventory::new()).unwrap(),
            FakeBackend::default(),
            None,
        )
        .unwrap();
        let (requester_link, empty_link) = MemoryLink::pair(256);
        let mut now = Instant::now();
        for _ in 0..128 {
            requester.pump_at(&requester_link, now).unwrap();
            empty_peer.pump_at(&empty_link, now).unwrap();
            now += Duration::from_secs(70);
        }
        let first_peer = requester.authenticated_peer().unwrap();
        assert!(requester.is_authenticated());
        assert!(empty_peer.is_authenticated());
        assert_eq!(empty_peer.backend().data_requests, 0);
        assert!(requester.sync().wants().contains(&object_id));
        assert!(
            requester
                .retries
                .keys()
                .any(|key| matches!(key, RetryKey::Want(784, id) if *id == object_id))
        );

        let requester_backend = requester.into_backend();
        let mut requester = RuntimeDriver::initiator(
            ProvisioningBundle::from_bytes(&requester_bytes).unwrap(),
            SyncState::new(Default::default(), SparseInventory::new()).unwrap(),
            requester_backend,
            request(785),
            None,
        )
        .unwrap();
        let mut provider_backend = FakeBackend::default();
        provider_backend.available.insert(object_id, payload);
        let mut provider = RuntimeDriver::responder(
            ProvisioningBundle::from_bytes(&provider_bytes).unwrap(),
            SyncState::new(Default::default(), SparseInventory::new()).unwrap(),
            provider_backend,
            None,
        )
        .unwrap();
        let (requester_link, provider_link) = MemoryLink::pair(256);
        for _ in 0..256 {
            requester.pump_at(&requester_link, now).unwrap();
            provider.pump_at(&provider_link, now).unwrap();
            if requester
                .backend()
                .ingested
                .iter()
                .any(|(id, _)| *id == object_id)
            {
                break;
            }
            now += Duration::from_secs(70);
        }
        assert_ne!(requester.authenticated_peer(), Some(first_peer));
        assert!(provider.backend().data_requests > 0);
        assert_eq!(requester.backend().ingested, vec![(object_id, [0xa5; 32])]);
        assert!(!requester.sync().wants().contains(&object_id));
        assert!(
            !requester
                .retries
                .keys()
                .any(|key| matches!(key, RetryKey::Want(_, id) if *id == object_id))
        );

        // Silence is permitted only before a serve action, while the typed ID
        // is absent from this contact's selected served view. If a previously
        // selected object disappears and the backend is reached, its error
        // remains contact-fatal rather than being reclassified as absence.
        provider.backend_mut().available.remove(&object_id);
        let stale = WantItem {
            object_id,
            total_len: None,
            missing: Vec::new(),
            need_forwarding: true,
        };
        let actions = provider
            .sync
            .apply(SyncEvent::Receive(Message::Want(crate::wire::Want {
                exchange_id: 785,
                items: vec![stale.clone()],
            })))
            .unwrap();
        assert_eq!(actions, vec![SyncAction::Serve(stale)]);
        assert!(matches!(
            provider.handle_actions(actions),
            Err(RuntimeError::Backend(message)) if message == "unknown"
        ));
    }

    #[test]
    fn refreshed_want_retires_superseded_data_before_serving_tail() {
        let (_peer, mut driver, _left, _right, _now) =
            authenticated_runtime_pair(782, Priority::Routine);
        driver.retries.clear();
        driver.deferred_wants.clear();
        driver.outbox.clear();
        let payload = vec![0x7b; 65_927];
        let object_id = ObjectId::for_envelope(EnvelopeId::from_sealed_bytes(&payload));
        driver
            .backend_mut()
            .available
            .insert(object_id, payload.clone());
        driver
            .backend_mut()
            .priorities
            .insert(object_id, Priority::Routine);
        driver
            .queue_sync_message(&Message::Data(Data {
                exchange_id: 782,
                object_id,
                total_len: payload.len() as u64,
                offset: 0,
                payload: payload[..65_536].to_vec(),
                forwarding: b"authenticated-forwarding".to_vec(),
            }))
            .unwrap();
        let prefix_key = RetryKey::Data(782, object_id, payload.len() as u64, 0, 65_536);
        for index in 0..(MAX_PENDING_RETRIES - 1) {
            let filler = ObjectId::for_envelope(EnvelopeId::from_sealed_bytes(
                &u64::try_from(index).unwrap().to_le_bytes(),
            ));
            driver
                .queue_sync_message(&Message::Data(Data {
                    exchange_id: 782,
                    object_id: filler,
                    total_len: 1,
                    offset: 0,
                    payload: vec![index as u8],
                    forwarding: b"authenticated-forwarding".to_vec(),
                }))
                .unwrap();
        }
        assert_eq!(driver.retries.len(), MAX_PENDING_RETRIES);

        let tail = WantItem {
            object_id,
            total_len: Some(payload.len() as u64),
            missing: vec![ByteRange {
                start: 65_536,
                end: payload.len() as u64,
            }],
            need_forwarding: false,
        };
        let refreshed = Message::Want(crate::wire::Want {
            exchange_id: 782,
            items: vec![tail.clone()],
        });
        driver.observe_authenticated_message(&refreshed).unwrap();
        assert!(!driver.retries.contains_key(&prefix_key));
        assert_eq!(driver.retries.len(), MAX_PENDING_RETRIES - 1);

        driver
            .handle_actions(vec![SyncAction::Serve(tail.clone())])
            .unwrap();
        let tail_key = RetryKey::Data(
            782,
            object_id,
            payload.len() as u64,
            65_536,
            payload.len() as u64,
        );
        assert!(driver.retries.contains_key(&tail_key));
        assert_eq!(driver.retries.len(), MAX_PENDING_RETRIES);
        driver.observe_authenticated_message(&refreshed).unwrap();
        assert!(
            driver.retries.contains_key(&tail_key),
            "a DATA retry that still intersects the exact missing range remains live"
        );
        assert!(driver.pending_logical_bytes() <= MAX_PENDING_LOGICAL_BYTES);
    }

    #[test]
    fn serve_flow_control_still_admits_later_flash_data() {
        let (_peer, mut driver, _left, _right, _now) =
            authenticated_runtime_pair(781, Priority::Routine);
        for index in 0..MAX_PENDING_RETRIES {
            let object_id = ObjectId::for_envelope(EnvelopeId::from_sealed_bytes(
                &u64::try_from(index).unwrap().to_le_bytes(),
            ));
            driver
                .queue_sync_message(&Message::Data(Data {
                    exchange_id: 781,
                    object_id,
                    total_len: 1,
                    offset: 0,
                    payload: vec![index as u8],
                    forwarding: b"authenticated-forwarding".to_vec(),
                }))
                .unwrap();
        }
        assert_eq!(driver.retries.len(), MAX_PENDING_RETRIES);

        let routine_id =
            ObjectId::for_envelope(EnvelopeId::from_sealed_bytes(b"later-routine-serve"));
        let flash_id = ObjectId::for_envelope(EnvelopeId::from_sealed_bytes(b"later-flash-serve"));
        driver
            .backend_mut()
            .available
            .insert(routine_id, b"r".to_vec());
        driver
            .backend_mut()
            .available
            .insert(flash_id, b"f".to_vec());
        driver
            .backend_mut()
            .priorities
            .insert(routine_id, Priority::Routine);
        driver
            .backend_mut()
            .priorities
            .insert(flash_id, Priority::Flash);
        let want = |object_id| WantItem {
            object_id,
            total_len: None,
            missing: Vec::new(),
            need_forwarding: true,
        };

        driver
            .handle_actions(vec![
                SyncAction::Serve(want(routine_id)),
                SyncAction::Serve(want(flash_id)),
            ])
            .unwrap();

        assert_eq!(driver.backend().data_requests, 2);
        assert!(
            !driver
                .retries
                .contains_key(&RetryKey::Data(781, routine_id, 1, 0, 1))
        );
        assert!(
            driver
                .retries
                .contains_key(&RetryKey::Data(781, flash_id, 1, 0, 1))
        );
        assert_eq!(driver.retries.len(), MAX_PENDING_RETRIES);
        assert!(driver.pending_logical_bytes() <= MAX_PENDING_LOGICAL_BYTES);
    }

    #[test]
    fn converged_contact_retires_response_repeats_and_returns_to_zero_wakeups() {
        let (left_bundle, right_bundle) = bundles();
        let mut left_driver = RuntimeDriver::initiator(
            left_bundle,
            SyncState::new(Default::default(), SparseInventory::new()).unwrap(),
            FakeBackend::default(),
            StartRequest {
                exchange_id: 75,
                topics: vec!["alpha".into()],
                scopes: vec!["mission/team".into()],
                min_priority: Priority::Routine as u8,
            },
            None,
        )
        .unwrap();
        let mut right_driver = RuntimeDriver::responder(
            right_bundle,
            SyncState::new(Default::default(), SparseInventory::new()).unwrap(),
            FakeBackend::default(),
            None,
        )
        .unwrap();
        let (left, right) = MemoryLink::pair(256);
        let mut now = Instant::now();
        for _ in 0..64 {
            left_driver.pump_at(&left, now).unwrap();
            right_driver.pump_at(&right, now).unwrap();
            if left_driver.is_authenticated()
                && right_driver.is_authenticated()
                && !left_driver
                    .retries
                    .keys()
                    .any(|key| matches!(key, RetryKey::Interest(75)))
            {
                break;
            }
        }
        for _ in 0..16 {
            now += Duration::from_secs(70);
            right_driver.pump_at(&right, now).unwrap();
            left_driver.pump_at(&left, now).unwrap();
        }
        assert!(left_driver.retries.is_empty());
        assert!(right_driver.retries.is_empty());
        assert_eq!(left_driver.next_wakeup(&left), None);
        assert_eq!(right_driver.next_wakeup(&right), None);
    }

    #[test]
    fn failed_chunk_store_is_rolled_back_and_retried() {
        let (initiator_bundle, responder_bundle) = bundles();
        let sealed = b"retry-source-envelope".to_vec();
        let object_id = ObjectId::for_envelope(EnvelopeId::from_sealed_bytes(&sealed));
        let initiator_backend = FakeBackend {
            fail_store_attempts: 1,
            ..FakeBackend::default()
        };
        let mut responder_backend = FakeBackend::default();
        responder_backend.available.insert(object_id, sealed);

        let mut initiator = RuntimeDriver::initiator(
            initiator_bundle,
            SyncState::new(Default::default(), SparseInventory::new()).unwrap(),
            initiator_backend,
            StartRequest {
                exchange_id: 41,
                topics: vec!["alpha".into()],
                scopes: vec!["mission/team".into()],
                min_priority: Priority::Priority as u8,
            },
            None,
        )
        .unwrap();
        let mut responder = RuntimeDriver::responder(
            responder_bundle,
            SyncState::new(Default::default(), SparseInventory::from_ids([object_id])).unwrap(),
            responder_backend,
            None,
        )
        .unwrap();
        let (left, right) = MemoryLink::pair(128);
        let mut store_failures = 0;

        for _ in 0..300 {
            match initiator.pump(&left) {
                Ok(_) => {}
                Err(RuntimeError::Backend(error)) if error == "transient store" => {
                    store_failures += 1;
                }
                Err(error) => panic!("unexpected initiator error: {error}"),
            }
            responder.pump(&right).unwrap();
            if initiator.sync().inventory().contains(&object_id) {
                break;
            }
        }

        assert_eq!(store_failures, 1);
        assert_eq!(initiator.backend().fail_store_attempts, 0);
        assert_eq!(initiator.backend().ingested, vec![(object_id, [0xa5; 32])]);
        assert!(initiator.sync().inventory().contains(&object_id));
    }

    #[test]
    fn transient_inventory_selection_rolls_back_and_replays_authenticated_interest() {
        let (mut sender, mut receiver, left, right, mut now) =
            authenticated_runtime_pair(85, Priority::Routine);
        sender.retries.clear();
        sender.deferred_wants.clear();
        sender.outbox.clear();
        left.capture.lock().unwrap().clear();
        left.inbound.lock().unwrap().clear();
        right.inbound.lock().unwrap().clear();
        let selections_before = receiver.backend().selections.len();
        receiver.backend_mut().fail_inventory_selection_attempts = 1;
        receiver.start_request = Some(StartRequest {
            exchange_id: 85,
            topics: vec!["alpha".into()],
            scopes: vec!["mission/team".into()],
            min_priority: Priority::Routine as u8,
        });
        sender
            .queue_sync_message(&Message::Interest(crate::wire::Interest {
                exchange_id: 85,
                topics: vec!["alpha".into()],
                scopes: vec!["mission/team".into()],
                min_priority: Priority::Priority as u8,
                max_offers: 1,
            }))
            .unwrap();

        let mut failures = 0;
        for _ in 0..32 {
            now += Duration::from_secs(70);
            sender.pump_at(&left, now).unwrap();
            match receiver.pump_at(&right, now) {
                Ok(_) => {}
                Err(RuntimeError::Backend(error)) if error == "transient inventory selection" => {
                    failures += 1;
                    assert!(receiver.start_request.is_some());
                }
                Err(error) => panic!("unexpected receiver error: {error}"),
            }
            if receiver.backend().selections.len() > selections_before {
                break;
            }
        }

        assert_eq!(failures, 1);
        assert_eq!(receiver.backend().fail_inventory_selection_attempts, 0);
        assert!(receiver.backend().selections.len() > selections_before);
        assert!(receiver.is_authenticated());
        assert!(receiver.start_request.is_none());
    }

    #[test]
    fn interest_summary_backpressure_restores_and_retries_authenticated_control() {
        let (mut sender, mut receiver, left, right, mut now) =
            authenticated_runtime_pair(851, Priority::Routine);
        sender.retries.clear();
        sender.deferred_wants.clear();
        sender.outbox.clear();
        receiver.retries.clear();
        receiver.deferred_wants.clear();
        receiver.outbox.clear();
        left.inbound.lock().unwrap().clear();
        right.inbound.lock().unwrap().clear();

        for index in 0..MAX_PENDING_RETRIES {
            let object_id = ObjectId::for_envelope(EnvelopeId::from_sealed_bytes(
                &u64::try_from(index).unwrap().to_le_bytes(),
            ));
            receiver
                .backend_mut()
                .priorities
                .insert(object_id, Priority::Flash);
            receiver
                .queue_sync_message(&Message::Data(Data {
                    exchange_id: 851,
                    object_id,
                    total_len: 1,
                    offset: 0,
                    payload: vec![index as u8],
                    forwarding: b"authenticated-forwarding".to_vec(),
                }))
                .unwrap();
        }
        for entry in receiver.retries.values_mut() {
            entry.due = now + Duration::from_secs(3_600);
        }

        sender
            .queue_sync_message(&Message::Interest(crate::wire::Interest {
                exchange_id: 851,
                topics: vec!["alpha".into()],
                scopes: vec!["mission/team".into()],
                min_priority: Priority::Routine as u8,
                max_offers: 1,
            }))
            .unwrap();
        let interest_key = RetryKey::Interest(851);
        sender.pump_at(&left, now).unwrap();
        receiver.pump_at(&right, now).unwrap();

        assert!(receiver.is_authenticated());
        assert!(sender.retries.contains_key(&interest_key));
        assert_eq!(receiver.retries.len(), MAX_PENDING_RETRIES);
        assert!(
            !receiver
                .retries
                .keys()
                .any(|key| matches!(key, RetryKey::Summary(851, _)))
        );
        receiver.retries.clear();
        for _ in 0..=MAX_SUCCESSFUL_RECORD_REPAIR_ROUNDS + 2 {
            let Some(due) = sender.retries.get(&interest_key).map(|entry| entry.due) else {
                break;
            };
            now = due;
            sender.pump_at(&left, now).unwrap();
            receiver.pump_at(&right, now).unwrap();
            sender.pump_at(&left, now).unwrap();
        }

        assert!(!sender.retries.contains_key(&interest_key));
        assert!(
            receiver
                .retries
                .keys()
                .any(|key| matches!(key, RetryKey::Summary(851, _)))
        );
        assert!(receiver.is_authenticated());
    }

    #[test]
    fn oversized_offer_rolls_back_every_partially_inserted_want() {
        let (sender_bundle, receiver_bundle) = bundles();
        let mut sender = RuntimeDriver::initiator(
            sender_bundle,
            SyncState::new(Default::default(), SparseInventory::new()).unwrap(),
            FakeBackend::default(),
            StartRequest {
                exchange_id: 827,
                topics: vec!["alpha".into()],
                scopes: vec!["mission/team".into()],
                min_priority: Priority::Routine as u8,
            },
            None,
        )
        .unwrap();
        let mut receiver = RuntimeDriver::responder(
            receiver_bundle,
            SyncState::new(
                crate::sync::SyncConfig {
                    max_durable_wants: 1,
                    ..Default::default()
                },
                SparseInventory::new(),
            )
            .unwrap(),
            FakeBackend::default(),
            None,
        )
        .unwrap();
        let (left, right) = MemoryLink::pair(256);
        let now = Instant::now();
        for _ in 0..64 {
            sender.pump_at(&left, now).unwrap();
            receiver.pump_at(&right, now).unwrap();
            if sender.is_authenticated()
                && receiver.is_authenticated()
                && receiver.handshake_retry.is_none()
                && receiver.sync.active_exchange_id() == Some(827)
            {
                break;
            }
        }
        assert!(sender.is_authenticated());
        assert!(receiver.is_authenticated());
        sender.retries.clear();
        sender.deferred_wants.clear();
        sender.outbox.clear();
        receiver.retries.clear();
        receiver.deferred_wants.clear();
        receiver.outbox.clear();
        left.inbound.lock().unwrap().clear();
        right.inbound.lock().unwrap().clear();

        let mut object_ids = vec![
            ObjectId::for_envelope(EnvelopeId::from_sealed_bytes(b"offer-first")),
            ObjectId::for_envelope(EnvelopeId::from_sealed_bytes(b"offer-second")),
        ];
        object_ids.sort_unstable();
        let offer = pending_offer_for(&mut receiver, 827, object_ids);
        sender.queue_sync_message(&Message::Offer(offer)).unwrap();
        sender.pump_at(&left, now).unwrap();

        assert!(matches!(
            receiver.pump_at(&right, now),
            Err(RuntimeError::Sync(SyncError::WantLimit))
        ));
        assert!(receiver.sync.wants().is_empty());
        assert!(receiver.retries.is_empty());
        assert!(receiver.deferred_wants.is_empty());
        assert!(receiver.outbox.is_empty());
    }

    #[test]
    fn local_inventory_change_is_transactional_across_selection_failure() {
        let (_peer, mut driver, _left, _right, _now) =
            authenticated_runtime_pair(86, Priority::Routine);
        driver.backend_mut().fail_inventory_selection_attempts = 1;
        let sequence_before = driver.next_retry_sequence;
        let retries_before = driver.retries.len();
        let outbox_before = driver.outbox.len();

        assert!(matches!(
            driver.local_inventory_changed(),
            Err(RuntimeError::Backend(error)) if error == "transient inventory selection"
        ));
        assert_eq!(driver.next_retry_sequence, sequence_before);
        assert_eq!(driver.retries.len(), retries_before);
        assert_eq!(driver.outbox.len(), outbox_before);

        driver.local_inventory_changed().unwrap();
        assert_eq!(driver.backend().fail_inventory_selection_attempts, 0);
        assert!(!driver.backend().selections.is_empty());
    }

    #[test]
    fn transient_completion_and_commit_failures_apply_exactly_once() {
        for fail_completion in [true, false] {
            let (initiator_bundle, responder_bundle) = bundles();
            let payload = if fail_completion {
                b"transient-completion".to_vec()
            } else {
                b"transient-commit".to_vec()
            };
            let object_id = ObjectId::for_envelope(EnvelopeId::from_sealed_bytes(&payload));
            let initiator_backend = FakeBackend {
                fail_complete_attempts: usize::from(fail_completion),
                fail_commit_attempts: usize::from(!fail_completion),
                ..FakeBackend::default()
            };
            let mut responder_backend = FakeBackend::default();
            responder_backend.available.insert(object_id, payload);
            let mut initiator = RuntimeDriver::initiator(
                initiator_bundle,
                SyncState::new(Default::default(), SparseInventory::new()).unwrap(),
                initiator_backend,
                StartRequest {
                    exchange_id: 87,
                    topics: vec!["alpha".into()],
                    scopes: vec!["mission/team".into()],
                    min_priority: Priority::Routine as u8,
                },
                None,
            )
            .unwrap();
            let mut responder = RuntimeDriver::responder(
                responder_bundle,
                SyncState::new(Default::default(), SparseInventory::from_ids([object_id])).unwrap(),
                responder_backend,
                None,
            )
            .unwrap();
            let (left, right) = MemoryLink::pair(128);
            let mut now = Instant::now();
            let expected_error = if fail_completion {
                "transient complete"
            } else {
                "transient commit"
            };
            let mut failures = 0;

            for _ in 0..96 {
                now += Duration::from_secs(70);
                match initiator.pump_at(&left, now) {
                    Ok(_) => {}
                    Err(RuntimeError::Backend(error)) if error == expected_error => failures += 1,
                    Err(error) => panic!("unexpected initiator error: {error}"),
                }
                responder.pump_at(&right, now).unwrap();
                if initiator.backend().ingested.len() == 1 {
                    break;
                }
            }

            assert_eq!(failures, 1);
            assert_eq!(initiator.backend().ingested.len(), 1);
            assert!(initiator.sync.inventory().contains(&object_id));
        }
    }

    #[test]
    fn post_commit_selection_failure_never_reapplies_backend_commit() {
        let (mut sender, mut receiver, left, right, now) =
            authenticated_runtime_pair(88, Priority::Routine);
        sender.retries.clear();
        sender.deferred_wants.clear();
        sender.outbox.clear();
        let payload = b"commit-barrier".to_vec();
        let object_id = ObjectId::for_envelope(EnvelopeId::from_sealed_bytes(&payload));
        prepare_expected_object(&mut receiver, 88, object_id);
        receiver.backend_mut().fail_inventory_selection_attempts = 1;
        sender
            .backend_mut()
            .priorities
            .insert(object_id, Priority::Routine);
        let data = Message::Data(Data {
            exchange_id: 88,
            object_id,
            total_len: payload.len() as u64,
            offset: 0,
            payload,
            forwarding: b"authenticated-forwarding".to_vec(),
        });
        sender.queue_sync_message(&data).unwrap();
        sender.pump_at(&left, now).unwrap();

        assert!(matches!(
            receiver.pump_at(&right, now),
            Err(RuntimeError::Backend(error)) if error == "transient inventory selection"
        ));
        assert!(receiver.sync.inventory().contains(&object_id));
        assert_eq!(receiver.backend().ingested.len(), 1);
        let retry_due = receiver
            .inventory_refresh_retry
            .as_ref()
            .expect("post-commit refresh remains represented")
            .due;
        assert_eq!(receiver.next_wakeup(&right), Some(retry_due));

        receiver.pump_at(&right, retry_due).unwrap();
        assert!(receiver.inventory_refresh_retry.is_none());
        sender.pump_at(&left, retry_due).unwrap();
        sender.queue_sync_message(&data).unwrap();
        sender.pump_at(&left, retry_due).unwrap();
        receiver.pump_at(&right, retry_due).unwrap();
        assert_eq!(receiver.backend().ingested.len(), 1);
    }

    #[test]
    fn post_commit_backpressure_keeps_commit_once_and_retries_inventory_refresh() {
        let (mut receiver, mut sender, left, right, now) =
            authenticated_runtime_pair(90, Priority::Routine);
        let payload = b"receipt-backpressure".to_vec();
        let object_id = ObjectId::for_envelope(EnvelopeId::from_sealed_bytes(&payload));
        prepare_expected_object(&mut receiver, 90, object_id);
        let serve_actions = receiver
            .sync
            .apply(SyncEvent::Receive(Message::Interest(
                crate::wire::Interest {
                    exchange_id: 90,
                    topics: vec!["alpha".into()],
                    scopes: vec!["mission/team".into()],
                    min_priority: Priority::Routine as u8,
                    max_offers: 1,
                },
            )))
            .unwrap();
        receiver.handle_actions(serve_actions).unwrap();
        assert!(receiver.sync.selected_serve_inventory().is_some());
        receiver.retries.clear();
        receiver.deferred_wants.clear();
        receiver.outbox.clear();
        sender
            .backend_mut()
            .priorities
            .insert(object_id, Priority::Routine);
        sender
            .backend_mut()
            .available
            .insert(object_id, payload.clone());
        sender
            .queue_sync_message(&Message::Data(Data {
                exchange_id: 90,
                object_id,
                total_len: payload.len() as u64,
                offset: 0,
                payload,
                forwarding: b"authenticated-forwarding".to_vec(),
            }))
            .unwrap();
        for index in 0..MAX_PENDING_RETRIES {
            let saturating_id = ObjectId::for_envelope(EnvelopeId::from_sealed_bytes(
                &u64::try_from(index).unwrap().to_le_bytes(),
            ));
            receiver
                .backend_mut()
                .priorities
                .insert(saturating_id, Priority::Flash);
            receiver
                .queue_sync_message(&Message::Data(Data {
                    exchange_id: 90,
                    object_id: saturating_id,
                    total_len: 1,
                    offset: 0,
                    payload: vec![index as u8],
                    forwarding: b"authenticated-forwarding".to_vec(),
                }))
                .unwrap();
        }
        for entry in receiver.retries.values_mut() {
            entry.due = now + Duration::from_secs(3_600);
        }

        sender.pump_at(&right, now).unwrap();
        receiver.pump_at(&left, now).unwrap();
        assert!(receiver.sync.inventory().contains(&object_id));
        assert_eq!(receiver.backend().ingested.len(), 1);
        let retry_due = receiver
            .inventory_refresh_retry
            .as_ref()
            .expect("committed object retains its blocked inventory refresh")
            .due;

        receiver.retries.clear();
        receiver.pump_at(&left, retry_due).unwrap();
        assert!(receiver.inventory_refresh_retry.is_none());

        sender.pump_at(&right, retry_due).unwrap();
        receiver.pump_at(&left, retry_due).unwrap();
        assert_eq!(receiver.backend().ingested.len(), 1);
        assert!(receiver.sync.inventory().contains(&object_id));
    }

    #[test]
    fn dropped_partial_receipt_is_reissued_and_retires_data_retry() {
        let (mut receiver, mut sender, left, right, mut now) =
            authenticated_runtime_pair(901, Priority::Routine);
        receiver.retries.clear();
        receiver.deferred_wants.clear();
        receiver.outbox.clear();
        sender.retries.clear();
        sender.deferred_wants.clear();
        sender.outbox.clear();
        let payload = b"partial-receipt".to_vec();
        let object_id = ObjectId::for_envelope(EnvelopeId::from_sealed_bytes(&payload));
        prepare_expected_object(&mut receiver, 901, object_id);
        sender
            .backend_mut()
            .priorities
            .insert(object_id, Priority::Routine);
        let partial_end = 4_u64;
        let data = Message::Data(Data {
            exchange_id: 901,
            object_id,
            total_len: payload.len() as u64,
            offset: 0,
            payload: payload[..partial_end as usize].to_vec(),
            forwarding: b"authenticated-forwarding".to_vec(),
        });
        sender.queue_sync_message(&data).unwrap();
        let data_key = RetryKey::Data(901, object_id, payload.len() as u64, 0, partial_end);

        let marker_id =
            ObjectId::for_envelope(EnvelopeId::from_sealed_bytes(b"partial-receipt-outbox"));
        for _ in 0..MAX_PENDING_OUTBOX {
            let (semantic_version, plaintext) = receiver
                .encode_message(&Message::Receipt(wire::Receipt {
                    exchange_id: 901,
                    object_id: marker_id,
                    total_len: 1,
                    received: Vec::new(),
                    complete: false,
                }))
                .unwrap();
            receiver
                .queue_logical_once(plaintext, Priority::Flash, semantic_version)
                .unwrap();
        }
        for entry in &mut receiver.outbox {
            entry.due = now + Duration::from_secs(3_600);
        }

        sender.pump_at(&right, now).unwrap();
        receiver.pump_at(&left, now).unwrap();
        assert!(sender.retries.contains_key(&data_key));
        assert_eq!(
            receiver.sync.retry_want_item(object_id).unwrap().missing,
            vec![ByteRange {
                start: partial_end,
                end: payload.len() as u64,
            }]
        );

        // This case isolates duplicate-DATA receipt regeneration: drop the
        // newly introduced progress WANT as well as the saturated receipt,
        // while leaving its durable retry represented beyond this test's
        // DATA-repair horizon.
        right.inbound.lock().unwrap().clear();
        receiver
            .retries
            .get_mut(&RetryKey::Want(901, object_id))
            .unwrap()
            .due = now + Duration::from_secs(3_600);
        receiver.outbox.clear();
        for _ in 0..=MAX_SUCCESSFUL_RECORD_REPAIR_ROUNDS {
            let Some(due) = sender.retries.get(&data_key).map(|entry| entry.due) else {
                break;
            };
            now = due;
            sender.pump_at(&right, now).unwrap();
            receiver.pump_at(&left, now).unwrap();
            sender.pump_at(&right, now).unwrap();
        }

        assert!(!sender.retries.contains_key(&data_key));
        assert!(receiver.backend().ingested.is_empty());
        assert!(receiver.sync.wants().contains(&object_id));
    }

    #[test]
    fn promoted_deferred_want_rotates_stale_missing_ranges() {
        let (_peer, mut driver, _left, right, now) =
            authenticated_runtime_pair(91, Priority::Routine);
        let payload = b"range-sensitive-want".to_vec();
        let object_id = ObjectId::for_envelope(EnvelopeId::from_sealed_bytes(&payload));
        prepare_expected_object(&mut driver, 91, object_id);
        let semantic_version = driver.authenticated_semantic_version().unwrap();
        let initial_item = driver.sync.retry_want_item(object_id).unwrap();
        let initial_message = Message::Want(crate::wire::Want {
            exchange_id: 91,
            items: vec![initial_item],
        });
        driver.defer_want(
            object_id,
            DeferredWant {
                exchange_id: 91,
                priority: Priority::Routine,
                attempts: 0,
                due: now,
                sequence: driver.next_retry_sequence,
                semantic_version,
                transport_epoch: None,
            },
        );
        let old_transfer_id = driver
            .prepare_deferred_want_epoch(object_id, &initial_message, right.characteristics().mtu)
            .unwrap()
            .unwrap()
            .transfer_id;

        let stored_end = 5_u64;
        let actions = driver
            .sync
            .apply(SyncEvent::Receive(Message::Data(Data {
                exchange_id: 91,
                object_id,
                total_len: payload.len() as u64,
                offset: 0,
                payload: payload[..stored_end as usize].to_vec(),
                forwarding: b"authenticated-forwarding".to_vec(),
            })))
            .unwrap();
        assert!(actions.iter().any(|action| matches!(
            action,
            SyncAction::StoreChunk { object_id: stored, .. } if *stored == object_id
        )));
        let stored_actions = driver
            .sync
            .apply(SyncEvent::ChunkStored {
                object_id,
                total_len: payload.len() as u64,
                range: ByteRange {
                    start: 0,
                    end: stored_end,
                },
            })
            .unwrap();
        assert!(stored_actions.iter().any(|action| matches!(
            action,
            SyncAction::Send(Message::Want(want))
                if want.items.iter().any(|item| {
                    item.object_id == object_id
                        && item.missing == vec![ByteRange {
                            start: stored_end,
                            end: payload.len() as u64,
                        }]
                })
        )));
        driver.handle_actions(stored_actions).unwrap();
        let refreshed_item = driver.sync.retry_want_item(object_id).unwrap();
        assert_eq!(
            refreshed_item.missing,
            vec![ByteRange {
                start: stored_end,
                end: payload.len() as u64,
            }]
        );
        let refreshed_retry = driver
            .retries
            .get(&RetryKey::Want(91, object_id))
            .expect("durable progress must promote the refreshed WANT");
        assert_eq!(refreshed_retry.due, now);
        assert_eq!(
            refreshed_retry.message,
            Message::Want(crate::wire::Want {
                exchange_id: 91,
                items: vec![refreshed_item],
            })
        );
        let (new_transfer_id, _) = driver
            .prepare_retry_transport_epoch(
                &RetryKey::Want(91, object_id),
                right.characteristics().mtu,
            )
            .unwrap()
            .unwrap();
        assert_ne!(new_transfer_id, old_transfer_id);
    }

    #[test]
    fn durable_progress_orders_receipt_before_refreshed_retained_want() {
        let (_peer, mut driver, _left, _right, now) =
            authenticated_runtime_pair(912, Priority::Routine);
        driver.retries.clear();
        driver.deferred_wants.clear();
        driver.outbox.clear();
        let payload = vec![0x5a; 65_927];
        let object_id = ObjectId::for_envelope(EnvelopeId::from_sealed_bytes(&payload));
        prepare_expected_object(&mut driver, 912, object_id);
        let initial_want = Message::Want(crate::wire::Want {
            exchange_id: 912,
            items: vec![driver.sync.retry_want_item(object_id).unwrap()],
        });
        driver.queue_sync_message(&initial_want).unwrap();
        let key = RetryKey::Want(912, object_id);
        let old_sequence = driver.retries[&key].sequence;
        driver.retries.get_mut(&key).unwrap().attempts = 7;
        driver.retries.get_mut(&key).unwrap().due = now + Duration::from_secs(64);

        let stored_end = 65_536_u64;
        let receive_actions = driver
            .sync
            .apply(SyncEvent::Receive(Message::Data(Data {
                exchange_id: 912,
                object_id,
                total_len: payload.len() as u64,
                offset: 0,
                payload: payload[..stored_end as usize].to_vec(),
                forwarding: b"authenticated-forwarding".to_vec(),
            })))
            .unwrap();
        assert!(matches!(
            receive_actions.as_slice(),
            [SyncAction::StoreChunk { .. }]
        ));
        let stored_actions = driver
            .sync
            .apply(SyncEvent::ChunkStored {
                object_id,
                total_len: payload.len() as u64,
                range: ByteRange {
                    start: 0,
                    end: stored_end,
                },
            })
            .unwrap();
        driver.handle_actions(stored_actions).unwrap();

        let receipt_sequence = driver
            .outbox
            .front()
            .expect("partial progress must queue a receipt")
            .sequence;
        let refreshed = &driver.retries[&key];
        assert_eq!(refreshed.attempts, 7);
        assert_eq!(refreshed.due, now);
        assert!(refreshed.transport_epoch.is_none());
        assert!(refreshed.sequence > old_sequence);
        assert!(receipt_sequence < refreshed.sequence);
        assert!(matches!(
            &refreshed.message,
            Message::Want(crate::wire::Want { items, .. })
                if items == &[crate::wire::WantItem {
                    object_id,
                    total_len: Some(payload.len() as u64),
                    missing: vec![ByteRange {
                        start: stored_end,
                        end: payload.len() as u64,
                    }],
                    need_forwarding: false,
                }]
        ));
    }

    #[test]
    fn completed_want_refills_exactly_one_sleeping_window_slot() {
        let (_peer, mut driver, _left, right, now) =
            authenticated_runtime_pair(913, Priority::Routine);
        driver.retries.clear();
        driver.deferred_wants.clear();
        driver.outbox.clear();
        let completed = ObjectId::for_envelope(EnvelopeId::from_sealed_bytes(b"completed"));
        let sleeping_old = ObjectId::for_envelope(EnvelopeId::from_sealed_bytes(b"sleeping-old"));
        let sleeping_new = ObjectId::for_envelope(EnvelopeId::from_sealed_bytes(b"sleeping-new"));
        let offer = pending_offer_for(&mut driver, 913, [completed, sleeping_old, sleeping_new]);
        let actions = driver
            .sync
            .apply(SyncEvent::Receive(Message::Offer(offer)))
            .unwrap();
        driver.handle_actions(actions).unwrap();
        driver
            .prepare_retry_transport_epoch(
                &RetryKey::Want(913, sleeping_old),
                right.characteristics().mtu,
            )
            .unwrap();
        driver.demote_retry(&RetryKey::Want(913, sleeping_old));
        driver.demote_retry(&RetryKey::Want(913, sleeping_new));
        let sleeping_due = now + Duration::from_secs(64);
        {
            let entry = driver.deferred_wants.get_mut(&sleeping_old).unwrap();
            entry.attempts = 7;
            entry.due = sleeping_due;
            entry.sequence = 50;
        }
        {
            let entry = driver.deferred_wants.get_mut(&sleeping_new).unwrap();
            entry.attempts = 9;
            entry.due = sleeping_due;
            entry.sequence = 51;
        }
        driver.next_retry_sequence = 100;
        let receipt = Message::Receipt(wire::Receipt {
            exchange_id: 913,
            object_id: completed,
            total_len: 1,
            received: vec![ByteRange { start: 0, end: 1 }],
            complete: true,
        });
        driver.queue_sync_message(&receipt).unwrap();
        let receipt_sequence = driver.outbox.front().unwrap().sequence;
        let semantic_version = driver.authenticated_semantic_version().unwrap();

        driver.retire_completed_want_and_refill_window(913, semantic_version, completed);

        assert!(!driver.retries.contains_key(&RetryKey::Want(913, completed)));
        let accelerated = &driver.deferred_wants[&sleeping_old];
        assert_eq!(accelerated.attempts, 7);
        assert_eq!(accelerated.due, now);
        assert!(accelerated.sequence > receipt_sequence);
        assert!(accelerated.transport_epoch.is_none());
        let untouched = &driver.deferred_wants[&sleeping_new];
        assert_eq!(untouched.attempts, 9);
        assert_eq!(untouched.due, sleeping_due);
        assert_eq!(untouched.sequence, 51);
        assert!(driver.retries.len() <= MAX_PENDING_RETRIES);
        assert!(driver.pending_logical_bytes() <= MAX_PENDING_LOGICAL_BYTES);
    }

    #[test]
    fn completed_want_wakes_one_retained_request_without_advancing_time() {
        let (_peer, mut driver, _left, right, now) =
            authenticated_runtime_pair(914, Priority::Routine);
        driver.retries.clear();
        driver.deferred_wants.clear();
        driver.outbox.clear();
        let completed = ObjectId::for_envelope(EnvelopeId::from_sealed_bytes(b"completed-slot"));
        let sleeping_old = ObjectId::for_envelope(EnvelopeId::from_sealed_bytes(b"retained-old"));
        let sleeping_new = ObjectId::for_envelope(EnvelopeId::from_sealed_bytes(b"retained-new"));
        let offer = pending_offer_for(&mut driver, 914, [completed, sleeping_old, sleeping_new]);
        let actions = driver
            .sync
            .apply(SyncEvent::Receive(Message::Offer(offer)))
            .unwrap();
        driver.handle_actions(actions).unwrap();
        driver
            .prepare_retry_transport_epoch(
                &RetryKey::Want(914, sleeping_old),
                right.characteristics().mtu,
            )
            .unwrap();
        let sleeping_due = now + Duration::from_secs(64);
        {
            let entry = driver
                .retries
                .get_mut(&RetryKey::Want(914, sleeping_old))
                .unwrap();
            entry.attempts = 7;
            entry.due = sleeping_due;
            entry.sequence = 50;
        }
        {
            let entry = driver
                .retries
                .get_mut(&RetryKey::Want(914, sleeping_new))
                .unwrap();
            entry.attempts = 9;
            entry.due = sleeping_due;
            entry.sequence = 51;
        }
        driver.next_retry_sequence = 100;
        driver
            .queue_sync_message(&Message::Receipt(wire::Receipt {
                exchange_id: 914,
                object_id: completed,
                total_len: 1,
                received: vec![ByteRange { start: 0, end: 1 }],
                complete: true,
            }))
            .unwrap();
        let receipt_sequence = driver.outbox.front().unwrap().sequence;
        let semantic_version = driver.authenticated_semantic_version().unwrap();

        driver.retire_completed_want_and_refill_window(914, semantic_version, completed);

        assert!(!driver.retries.contains_key(&RetryKey::Want(914, completed)));
        let accelerated = &driver.retries[&RetryKey::Want(914, sleeping_old)];
        assert_eq!(accelerated.attempts, 7);
        assert_eq!(accelerated.due, now);
        assert!(accelerated.sequence > receipt_sequence);
        assert!(accelerated.transport_epoch.is_none());
        let untouched = &driver.retries[&RetryKey::Want(914, sleeping_new)];
        assert_eq!(untouched.attempts, 9);
        assert_eq!(untouched.due, sleeping_due);
        assert_eq!(untouched.sequence, 51);
        assert!(driver.deferred_wants.is_empty());
        assert!(driver.retries.len() <= MAX_PENDING_RETRIES);
        assert!(driver.pending_logical_bytes() <= MAX_PENDING_LOGICAL_BYTES);
    }

    #[test]
    fn receipt_queue_saturation_is_advisory_flow_control() {
        let (_peer, mut driver, _left, _right, _now) =
            authenticated_runtime_pair(911, Priority::Routine);
        let marker_id =
            ObjectId::for_envelope(EnvelopeId::from_sealed_bytes(b"receipt-flow-marker"));
        let receipt = Message::Receipt(wire::Receipt {
            exchange_id: 911,
            object_id: marker_id,
            total_len: 1,
            received: vec![ByteRange { start: 0, end: 1 }],
            complete: true,
        });
        for _ in 0..MAX_PENDING_OUTBOX {
            let (semantic_version, plaintext) = driver.encode_message(&receipt).unwrap();
            driver
                .queue_logical_once(plaintext, Priority::Flash, semantic_version)
                .unwrap();
        }

        driver
            .handle_actions(vec![SyncAction::Send(receipt.clone())])
            .unwrap();
        assert_eq!(driver.outbox.len(), MAX_PENDING_OUTBOX);
        assert!(driver.pending_logical_bytes() <= MAX_PENDING_LOGICAL_BYTES);

        driver.outbox.clear();
        driver
            .handle_actions(vec![SyncAction::Send(receipt)])
            .unwrap();
        assert_eq!(driver.outbox.len(), 1);
    }

    #[test]
    fn complete_receipt_refresh_backpressure_is_retried_without_contact_failure() {
        let (mut receiver, mut sender, left, right, now) =
            authenticated_runtime_pair(912, Priority::Routine);
        receiver.retries.clear();
        receiver.deferred_wants.clear();
        receiver.outbox.clear();
        receiver.backend_mut().receipts.clear();
        let serve_actions = receiver
            .sync
            .apply(SyncEvent::Receive(Message::Interest(
                crate::wire::Interest {
                    exchange_id: 912,
                    topics: vec!["alpha".into()],
                    scopes: vec!["mission/team".into()],
                    min_priority: Priority::Routine as u8,
                    max_offers: 256,
                },
            )))
            .unwrap();
        receiver.handle_actions(serve_actions).unwrap();
        receiver.retries.clear();
        receiver.outbox.clear();
        for index in 0..MAX_PENDING_RETRIES {
            let object_id = ObjectId::for_envelope(EnvelopeId::from_sealed_bytes(
                &u64::try_from(index).unwrap().to_be_bytes(),
            ));
            receiver
                .backend_mut()
                .priorities
                .insert(object_id, Priority::Flash);
            receiver
                .queue_sync_message(&Message::Data(Data {
                    exchange_id: 912,
                    object_id,
                    total_len: 1,
                    offset: 0,
                    payload: vec![index as u8],
                    forwarding: b"authenticated-forwarding".to_vec(),
                }))
                .unwrap();
        }
        for entry in receiver.retries.values_mut() {
            entry.due = now + Duration::from_secs(3_600);
        }
        assert_eq!(receiver.retries.len(), MAX_PENDING_RETRIES);

        let acknowledged_id =
            ObjectId::for_envelope(EnvelopeId::from_sealed_bytes(b"durable-receipt-pressure"));
        sender
            .queue_sync_message(&Message::Receipt(wire::Receipt {
                exchange_id: 912,
                object_id: acknowledged_id,
                total_len: 1,
                received: vec![ByteRange { start: 0, end: 1 }],
                complete: true,
            }))
            .unwrap();
        sender.pump_at(&right, now).unwrap();

        receiver.pump_at(&left, now).unwrap();
        assert!(receiver.is_authenticated());
        assert_eq!(receiver.backend().receipts.len(), 1);
        let retry_due = receiver
            .inventory_refresh_retry
            .as_ref()
            .expect("durable acknowledgement retains its blocked refresh")
            .due;
        assert_eq!(
            receiver
                .inventory_refresh_retry
                .as_ref()
                .expect("durable acknowledgement retains its blocked refresh")
                .scope,
            InventoryRefreshScope::ServeOnly
        );

        // Model the peer acknowledgements that release the retained send
        // capacity, then prove the scheduled refresh completes without
        // applying the durable receipt a second time.
        receiver.retries.clear();
        receiver.pump_at(&left, retry_due).unwrap();
        assert!(receiver.inventory_refresh_retry.is_none());
        assert_eq!(receiver.backend().receipts.len(), 1);
    }

    #[test]
    fn complete_receipt_refresh_is_durable_and_wakes_after_transient_failure() {
        let (mut receiver, mut sender, left, right, now) =
            authenticated_runtime_pair(89, Priority::Routine);
        let serve_actions = receiver
            .sync
            .apply(SyncEvent::Receive(Message::Interest(
                crate::wire::Interest {
                    exchange_id: 89,
                    topics: vec!["alpha".into()],
                    scopes: vec!["mission/team".into()],
                    min_priority: Priority::Routine as u8,
                    max_offers: 256,
                },
            )))
            .unwrap();
        receiver.handle_actions(serve_actions).unwrap();
        let selections_before = receiver.backend().selections.len();
        receiver.backend_mut().fail_inventory_selection_attempts = 1;
        let object_id = ObjectId::for_envelope(EnvelopeId::from_sealed_bytes(b"receipt-refresh"));
        sender
            .queue_sync_message(&Message::Receipt(wire::Receipt {
                exchange_id: 89,
                object_id,
                total_len: 1,
                received: vec![ByteRange { start: 0, end: 1 }],
                complete: true,
            }))
            .unwrap();
        sender.pump_at(&right, now).unwrap();

        assert!(matches!(
            receiver.pump_at(&left, now),
            Err(RuntimeError::Backend(error)) if error == "transient inventory selection"
        ));
        assert_eq!(receiver.backend().receipts.len(), 1);
        let retry_due = receiver
            .inventory_refresh_retry
            .as_ref()
            .expect("acknowledged receipt refresh remains represented")
            .due;
        assert_eq!(
            receiver
                .inventory_refresh_retry
                .as_ref()
                .expect("acknowledged receipt refresh remains represented")
                .scope,
            InventoryRefreshScope::ServeOnly
        );
        assert_eq!(receiver.next_wakeup(&left), Some(retry_due));

        receiver.pump_at(&left, retry_due).unwrap();
        assert!(receiver.inventory_refresh_retry.is_none());
        assert_eq!(receiver.backend().receipts.len(), 1);
        let refreshed_purposes = receiver.backend().selections[selections_before..]
            .iter()
            .map(|(_, _, purpose)| *purpose)
            .collect::<Vec<_>>();
        assert_eq!(refreshed_purposes, vec![InventoryPurpose::ServePeer]);
    }

    #[test]
    fn transport_route_is_latched_for_replies_and_other_routes_are_discarded() {
        let (initiator_bundle, responder_bundle) = bundles();
        let mut initiator = RuntimeDriver::initiator(
            initiator_bundle,
            SyncState::new(Default::default(), SparseInventory::new()).unwrap(),
            FakeBackend::default(),
            StartRequest {
                exchange_id: 19,
                topics: vec!["alpha".into()],
                scopes: vec!["mission/team".into()],
                min_priority: Priority::Priority as u8,
            },
            None,
        )
        .unwrap();
        let mut responder = RuntimeDriver::responder(
            responder_bundle,
            SyncState::new(Default::default(), SparseInventory::new()).unwrap(),
            FakeBackend::default(),
            None,
        )
        .unwrap();
        let left_route = [0x11; 32];
        let right_route = [0x22; 32];
        let changed_route = [0x33; 32];
        let (left, right) = MemoryLink::pair_with_routes(256, Some(left_route), Some(right_route));

        for _ in 0..32 {
            initiator.pump(&left).unwrap();
            responder.pump(&right).unwrap();
            if initiator.is_authenticated() && responder.is_authenticated() {
                break;
            }
        }
        assert!(initiator.is_authenticated());
        assert!(responder.is_authenticated());
        assert_eq!(
            initiator.committed_route,
            Some(CarrierRoute::Routed(right_route))
        );
        assert_eq!(
            responder.committed_route,
            Some(CarrierRoute::Routed(left_route))
        );
        assert!(left.targets.lock().unwrap().contains(&Some(right_route)));
        assert!(
            right
                .targets
                .lock()
                .unwrap()
                .iter()
                .all(|target| *target == Some(left_route))
        );

        left.inbound.lock().unwrap().push_back(ReceivedFrame {
            peer: Some(changed_route),
            bytes: Fragment {
                transfer_id: 8_999,
                index: 0,
                count: 1,
                payload: b"syntactically-valid-wrong-route".to_vec(),
            }
            .encode()
            .unwrap(),
        });
        assert!(initiator.pump(&left).is_ok());
        assert!(initiator.is_authenticated());

        let receipt_id =
            ObjectId::for_envelope(EnvelopeId::from_sealed_bytes(b"right-route-progress"));
        responder
            .queue_sync_message(&Message::Receipt(wire::Receipt {
                exchange_id: 19,
                object_id: receipt_id,
                total_len: 1,
                received: Vec::new(),
                complete: false,
            }))
            .unwrap();
        responder.pump(&right).unwrap();
        initiator.pump(&left).unwrap();
        assert!(
            initiator
                .backend()
                .receipts
                .iter()
                .any(|(_, _, receipt)| receipt.object_id == receipt_id)
        );
    }

    #[test]
    fn configured_route_rejects_anonymous_flights_and_keeps_exact_send_target() {
        let (initiator_bundle, responder_bundle) = bundles();
        let left_route = [0x51; 32];
        let right_route = [0x52; 32];
        let mut initiator = RuntimeDriver::initiator(
            initiator_bundle,
            SyncState::new(Default::default(), SparseInventory::new()).unwrap(),
            FakeBackend::default(),
            StartRequest {
                exchange_id: 20,
                topics: vec!["alpha".into()],
                scopes: vec!["mission/team".into()],
                min_priority: Priority::Routine as u8,
            },
            Some(right_route),
        )
        .unwrap();
        let mut responder = RuntimeDriver::responder(
            responder_bundle,
            SyncState::new(Default::default(), SparseInventory::new()).unwrap(),
            FakeBackend::default(),
            Some(left_route),
        )
        .unwrap();
        let (left, right) = MemoryLink::pair_with_routes(256, Some(left_route), Some(right_route));

        initiator.pump(&left).unwrap();
        {
            let mut inbound = right.inbound.lock().unwrap();
            let legitimate = inbound.pop_front().unwrap();
            inbound.push_front(legitimate.clone());
            inbound.push_front(ReceivedFrame {
                peer: None,
                bytes: legitimate.bytes,
            });
        }
        right.allow_receives(1);
        assert_eq!(responder.pump(&right).unwrap(), 0);
        assert!(matches!(responder.phase, SessionPhase::Responder(_)));

        right.allow_receives(usize::MAX);
        for _ in 0..32 {
            responder.pump(&right).unwrap();
            initiator.pump(&left).unwrap();
            if initiator.is_authenticated() && responder.is_authenticated() {
                break;
            }
        }
        assert!(initiator.is_authenticated());
        assert!(responder.is_authenticated());
        assert!(
            left.targets
                .lock()
                .unwrap()
                .iter()
                .all(|target| *target == Some(right_route))
        );
        assert!(
            right
                .targets
                .lock()
                .unwrap()
                .iter()
                .all(|target| *target == Some(left_route))
        );
    }

    #[test]
    fn authenticated_anonymous_route_cannot_latch_a_later_routed_source() {
        let (initiator_bundle, responder_bundle) = bundles();
        let mut initiator = RuntimeDriver::initiator(
            initiator_bundle,
            SyncState::new(Default::default(), SparseInventory::new()).unwrap(),
            FakeBackend::default(),
            StartRequest {
                exchange_id: 21,
                topics: vec!["alpha".into()],
                scopes: vec!["mission/team".into()],
                min_priority: Priority::Routine as u8,
            },
            None,
        )
        .unwrap();
        let mut responder = RuntimeDriver::responder(
            responder_bundle,
            SyncState::new(Default::default(), SparseInventory::new()).unwrap(),
            FakeBackend::default(),
            None,
        )
        .unwrap();
        let (left, right) = MemoryLink::pair(256);
        for _ in 0..32 {
            initiator.pump(&left).unwrap();
            responder.pump(&right).unwrap();
            if initiator.is_authenticated() && responder.is_authenticated() {
                break;
            }
        }
        assert!(initiator.is_authenticated());
        assert!(responder.is_authenticated());
        assert_eq!(initiator.committed_route, Some(CarrierRoute::Anonymous));
        assert_eq!(responder.committed_route, Some(CarrierRoute::Anonymous));
        left.targets.lock().unwrap().clear();
        right.targets.lock().unwrap().clear();

        left.inbound.lock().unwrap().push_back(ReceivedFrame {
            peer: Some([0x53; 32]),
            bytes: Fragment {
                transfer_id: 80_001,
                index: 0,
                count: 1,
                payload: b"routed-after-anonymous-authentication".to_vec(),
            }
            .encode()
            .unwrap(),
        });
        initiator.pump(&left).unwrap();
        assert_eq!(initiator.committed_route, Some(CarrierRoute::Anonymous));

        let receipt_id =
            ObjectId::for_envelope(EnvelopeId::from_sealed_bytes(b"anonymous-route-progress"));
        responder
            .queue_sync_message(&Message::Receipt(wire::Receipt {
                exchange_id: 21,
                object_id: receipt_id,
                total_len: 1,
                received: Vec::new(),
                complete: false,
            }))
            .unwrap();
        responder.pump(&right).unwrap();
        initiator.pump(&left).unwrap();
        assert!(
            initiator
                .backend()
                .receipts
                .iter()
                .any(|(_, _, receipt)| receipt.object_id == receipt_id)
        );
        assert!(left.targets.lock().unwrap().iter().all(Option::is_none));
        assert!(right.targets.lock().unwrap().iter().all(Option::is_none));
    }

    #[test]
    fn fragments_from_different_candidate_routes_cannot_form_one_handshake_flight() {
        let (initiator_bundle, responder_bundle) = bundles();
        let route = [0x61; 32];
        let other_route = [0x62; 32];
        let mut initiator = RuntimeDriver::initiator(
            initiator_bundle,
            SyncState::new(Default::default(), SparseInventory::new()).unwrap(),
            FakeBackend::default(),
            StartRequest {
                exchange_id: 22,
                topics: vec!["alpha".into()],
                scopes: vec!["mission/team".into()],
                min_priority: Priority::Routine as u8,
            },
            None,
        )
        .unwrap();
        let mut responder = RuntimeDriver::responder(
            responder_bundle,
            SyncState::new(Default::default(), SparseInventory::new()).unwrap(),
            FakeBackend::default(),
            None,
        )
        .unwrap();
        let (left, right) = MemoryLink::pair_with_routes(96, Some(route), Some([0x63; 32]));

        initiator.pump(&left).unwrap();
        let correct_final = {
            let mut inbound = right.inbound.lock().unwrap();
            assert!(inbound.len() > 1);
            let final_frame = inbound.back_mut().unwrap();
            let correct = final_frame.bytes.clone();
            final_frame.peer = Some(other_route);
            correct
        };
        assert_eq!(responder.pump(&right).unwrap(), 0);
        assert!(matches!(responder.phase, SessionPhase::Responder(_)));
        let transfer_id = Fragment::decode(&correct_final).unwrap().transfer_id;
        assert_eq!(
            responder.candidate_route, None,
            "an incomplete transfer must not pin the contact route"
        );
        assert_eq!(
            responder.fragment_routes[&transfer_id].route,
            CarrierRoute::Routed(route)
        );

        right.inbound.lock().unwrap().push_back(ReceivedFrame {
            peer: Some(route),
            bytes: correct_final,
        });
        assert_eq!(responder.pump(&right).unwrap(), 1);
        assert!(matches!(responder.phase, SessionPhase::ResponderPending(_)));
        assert!(
            right
                .targets
                .lock()
                .unwrap()
                .iter()
                .all(|target| *target == Some(route))
        );
    }

    #[test]
    fn anonymous_and_routed_fragments_cannot_form_one_handshake_flight() {
        let (initiator_bundle, responder_bundle) = bundles();
        let route = [0x71; 32];
        let mut initiator = RuntimeDriver::initiator(
            initiator_bundle,
            SyncState::new(Default::default(), SparseInventory::new()).unwrap(),
            FakeBackend::default(),
            StartRequest {
                exchange_id: 23,
                topics: vec!["alpha".into()],
                scopes: vec!["mission/team".into()],
                min_priority: Priority::Routine as u8,
            },
            None,
        )
        .unwrap();
        let mut responder = RuntimeDriver::responder(
            responder_bundle,
            SyncState::new(Default::default(), SparseInventory::new()).unwrap(),
            FakeBackend::default(),
            None,
        )
        .unwrap();
        let (left, right) = MemoryLink::pair_with_routes(96, None, Some(route));

        initiator.pump(&left).unwrap();
        let routed_remainder = {
            let mut inbound = right.inbound.lock().unwrap();
            assert!(inbound.len() > 1);
            inbound
                .iter_mut()
                .skip(1)
                .map(|frame| {
                    frame.peer = Some(route);
                    frame.bytes.clone()
                })
                .collect::<Vec<_>>()
        };
        assert_eq!(responder.pump(&right).unwrap(), 0);
        assert!(matches!(responder.phase, SessionPhase::Responder(_)));
        let transfer_id = Fragment::decode(&routed_remainder[0]).unwrap().transfer_id;
        assert_eq!(
            responder.candidate_route, None,
            "an incomplete anonymous transfer must not pin the contact route"
        );
        assert_eq!(
            responder.fragment_routes[&transfer_id].route,
            CarrierRoute::Anonymous
        );

        for bytes in routed_remainder {
            right
                .inbound
                .lock()
                .unwrap()
                .push_back(ReceivedFrame { peer: None, bytes });
        }
        assert_eq!(responder.pump(&right).unwrap(), 1);
        assert!(matches!(responder.phase, SessionPhase::ResponderPending(_)));
        assert!(right.targets.lock().unwrap().iter().all(Option::is_none));
    }

    #[test]
    fn incomplete_route_does_not_exclude_a_complete_authenticated_flight_on_another_route() {
        let (initiator_bundle, responder_bundle) = bundles();
        let incomplete_route = [0x72; 32];
        let authenticated_route = [0x73; 32];
        let mut initiator = RuntimeDriver::initiator(
            initiator_bundle,
            SyncState::new(Default::default(), SparseInventory::new()).unwrap(),
            FakeBackend::default(),
            StartRequest {
                exchange_id: 24,
                topics: vec!["alpha".into()],
                scopes: vec!["mission/team".into()],
                min_priority: Priority::Routine as u8,
            },
            None,
        )
        .unwrap();
        let mut responder = RuntimeDriver::responder(
            responder_bundle,
            SyncState::new(Default::default(), SparseInventory::new()).unwrap(),
            FakeBackend::default(),
            None,
        )
        .unwrap();
        let (left, right) =
            MemoryLink::pair_with_routes(96, Some(incomplete_route), Some([0x74; 32]));

        initiator.pump(&left).unwrap();
        let captured = right.inbound.lock().unwrap().drain(..).collect::<Vec<_>>();
        assert!(captured.len() > 1);
        right.inbound.lock().unwrap().push_back(captured[0].clone());
        for frame in captured {
            let mut fragment = Fragment::decode(&frame.bytes).unwrap();
            fragment.transfer_id = fragment.transfer_id.saturating_add(10_000);
            right.inbound.lock().unwrap().push_back(ReceivedFrame {
                peer: Some(authenticated_route),
                bytes: fragment.encode().unwrap(),
            });
        }

        assert_eq!(responder.pump(&right).unwrap(), 1);
        assert!(matches!(responder.phase, SessionPhase::ResponderPending(_)));
        assert_eq!(
            responder.candidate_route,
            Some(CarrierRoute::Routed(authenticated_route))
        );
        assert!(responder.fragment_routes.is_empty());
        assert!(
            right
                .targets
                .lock()
                .unwrap()
                .iter()
                .all(|target| *target == Some(authenticated_route))
        );
    }

    #[test]
    fn idle_partial_route_and_reassembly_state_expire_together() {
        let (_, responder_bundle) = bundles();
        let mut responder = RuntimeDriver::responder(
            responder_bundle,
            SyncState::new(Default::default(), SparseInventory::new()).unwrap(),
            FakeBackend::default(),
            None,
        )
        .unwrap();
        let (_, right) = MemoryLink::pair(256);
        let route = [0x75; 32];
        let now = Instant::now();
        right.inbound.lock().unwrap().push_back(ReceivedFrame {
            peer: Some(route),
            bytes: Fragment {
                transfer_id: 90_000,
                index: 0,
                count: 2,
                payload: b"first".to_vec(),
            }
            .encode()
            .unwrap(),
        });
        assert_eq!(responder.pump_at(&right, now).unwrap(), 0);
        assert!(responder.fragment_routes.contains_key(&90_000));

        let expired = now + PARTIAL_TRANSFER_IDLE_TTL + Duration::from_millis(1);
        assert_eq!(responder.pump_at(&right, expired).unwrap(), 0);
        assert!(!responder.fragment_routes.contains_key(&90_000));

        right.inbound.lock().unwrap().push_back(ReceivedFrame {
            peer: Some(route),
            bytes: Fragment {
                transfer_id: 90_000,
                index: 1,
                count: 2,
                payload: b"second".to_vec(),
            }
            .encode()
            .unwrap(),
        });
        assert_eq!(responder.pump_at(&right, expired).unwrap(), 0);
        assert!(
            responder.fragment_routes.contains_key(&90_000),
            "the second fragment must start a new partial, not complete expired state"
        );
    }

    #[test]
    fn forged_server_hello_preserves_initiator_state_and_valid_flight_converges() {
        let (initiator_bundle, responder_bundle) = bundles();
        let mut initiator = RuntimeDriver::initiator(
            initiator_bundle,
            SyncState::new(Default::default(), SparseInventory::new()).unwrap(),
            FakeBackend::default(),
            StartRequest {
                exchange_id: 96,
                topics: vec!["alpha".into()],
                scopes: vec!["mission/team".into()],
                min_priority: Priority::Routine as u8,
            },
            None,
        )
        .unwrap();
        let mut responder = RuntimeDriver::responder(
            responder_bundle,
            SyncState::new(Default::default(), SparseInventory::new()).unwrap(),
            FakeBackend::default(),
            None,
        )
        .unwrap();
        let (left, right) = MemoryLink::pair(256);
        let now = Instant::now();

        initiator.pump_at(&left, now).unwrap();
        responder.pump_at(&right, now).unwrap();
        let captured = right.captured_logical_through(1);
        assert_eq!(captured.len(), 1);
        let mut forged_server_hello = captured[0].clone();
        *forged_server_hello.last_mut().unwrap() ^= 0x80;
        let forged = fragment::fragment(&forged_server_hello, 256, 90_000).unwrap();
        left.allow_receives(forged.len());
        for fragment in forged.into_iter().rev() {
            left.inbound.lock().unwrap().push_front(ReceivedFrame {
                peer: None,
                bytes: fragment.encode().unwrap(),
            });
        }

        assert_eq!(initiator.pump_at(&left, now).unwrap(), 0);
        assert!(matches!(initiator.phase, SessionPhase::Initiator(_)));
        assert!(initiator.handshake_retry.is_some());

        left.allow_receives(usize::MAX);
        initiator.pump_at(&left, now).unwrap();
        responder.pump_at(&right, now).unwrap();
        initiator.pump_at(&left, now).unwrap();
        assert!(initiator.is_authenticated());
        assert!(responder.is_authenticated());
    }

    #[test]
    fn forged_client_auth_preserves_responder_state_and_valid_flight_converges() {
        let (initiator_bundle, responder_bundle) = bundles();
        let mut initiator = RuntimeDriver::initiator(
            initiator_bundle,
            SyncState::new(Default::default(), SparseInventory::new()).unwrap(),
            FakeBackend::default(),
            StartRequest {
                exchange_id: 94,
                topics: vec!["alpha".into()],
                scopes: vec!["mission/team".into()],
                min_priority: Priority::Routine as u8,
            },
            None,
        )
        .unwrap();
        let mut responder = RuntimeDriver::responder(
            responder_bundle,
            SyncState::new(Default::default(), SparseInventory::new()).unwrap(),
            FakeBackend::default(),
            None,
        )
        .unwrap();
        let (left, right) = MemoryLink::pair(256);
        let now = Instant::now();

        initiator.pump_at(&left, now).unwrap();
        responder.pump_at(&right, now).unwrap();
        initiator.pump_at(&left, now).unwrap();
        assert!(matches!(responder.phase, SessionPhase::ResponderPending(_)));

        let captured = left.captured_logical_through(2);
        assert_eq!(captured.len(), 2);
        let mut forged_client_auth = captured[1].clone();
        *forged_client_auth.last_mut().unwrap() ^= 0x80;
        let forged = fragment::fragment(&forged_client_auth, 256, 90_001).unwrap();
        right.allow_receives(forged.len());
        for fragment in forged.into_iter().rev() {
            right.inbound.lock().unwrap().push_front(ReceivedFrame {
                peer: None,
                bytes: fragment.encode().unwrap(),
            });
        }
        assert_eq!(responder.pump_at(&right, now).unwrap(), 0);
        assert!(matches!(responder.phase, SessionPhase::ResponderPending(_)));
        assert!(responder.handshake_retry.is_some());

        right.allow_receives(usize::MAX);
        responder.pump_at(&right, now).unwrap();
        initiator.pump_at(&left, now).unwrap();
        assert!(initiator.is_authenticated());
        assert!(responder.is_authenticated());
    }

    #[test]
    fn forged_server_finished_preserves_initiator_state_and_valid_flight_converges() {
        let (initiator_bundle, responder_bundle) = bundles();
        let mut initiator = RuntimeDriver::initiator(
            initiator_bundle,
            SyncState::new(Default::default(), SparseInventory::new()).unwrap(),
            FakeBackend::default(),
            StartRequest {
                exchange_id: 95,
                topics: vec!["alpha".into()],
                scopes: vec!["mission/team".into()],
                min_priority: Priority::Routine as u8,
            },
            None,
        )
        .unwrap();
        let mut responder = RuntimeDriver::responder(
            responder_bundle,
            SyncState::new(Default::default(), SparseInventory::new()).unwrap(),
            FakeBackend::default(),
            None,
        )
        .unwrap();
        let (left, right) = MemoryLink::pair(256);
        let now = Instant::now();

        initiator.pump_at(&left, now).unwrap();
        responder.pump_at(&right, now).unwrap();
        initiator.pump_at(&left, now).unwrap();
        assert!(matches!(
            initiator.phase,
            SessionPhase::InitiatorAwaitingFinished(_)
        ));

        responder.pump_at(&right, now).unwrap();
        assert!(responder.is_authenticated());
        let captured = right.captured_logical_through(2);
        assert_eq!(captured.len(), 2);
        let mut forged_server_finished = captured[1].clone();
        *forged_server_finished.last_mut().unwrap() ^= 0x80;
        let forged = fragment::fragment(&forged_server_finished, 256, 90_002).unwrap();
        left.allow_receives(forged.len());
        for fragment in forged.into_iter().rev() {
            left.inbound.lock().unwrap().push_front(ReceivedFrame {
                peer: None,
                bytes: fragment.encode().unwrap(),
            });
        }
        assert_eq!(initiator.pump_at(&left, now).unwrap(), 0);
        assert!(matches!(
            initiator.phase,
            SessionPhase::InitiatorAwaitingFinished(_)
        ));
        assert!(initiator.handshake_retry.is_some());

        left.allow_receives(usize::MAX);
        initiator.pump_at(&left, now).unwrap();
        assert!(initiator.is_authenticated());
        assert!(responder.is_authenticated());
    }

    #[test]
    fn unauthenticated_carrier_failures_are_bounded_without_masking_authenticated_errors() {
        let (initiator_bundle, responder_bundle) = bundles();
        let left_route = [0x41; 32];
        let right_route = [0x42; 32];
        let mut initiator = RuntimeDriver::initiator(
            initiator_bundle,
            SyncState::new(Default::default(), SparseInventory::new()).unwrap(),
            FakeBackend::default(),
            StartRequest {
                exchange_id: 93,
                topics: vec!["alpha".into()],
                scopes: vec!["mission/team".into()],
                min_priority: Priority::Routine as u8,
            },
            Some(right_route),
        )
        .unwrap();
        let mut responder = RuntimeDriver::responder(
            responder_bundle,
            SyncState::new(Default::default(), SparseInventory::new()).unwrap(),
            FakeBackend::default(),
            Some(left_route),
        )
        .unwrap();
        let (left, right) = MemoryLink::pair_with_routes(256, Some(left_route), Some(right_route));
        let mut now = Instant::now();

        right.inbound.lock().unwrap().push_back(ReceivedFrame {
            peer: Some([0x43; 32]),
            bytes: Fragment {
                transfer_id: 8_999,
                index: 0,
                count: 1,
                payload: b"syntactically-valid-wrong-route-client-flight".to_vec(),
            }
            .encode()
            .unwrap(),
        });
        right.inbound.lock().unwrap().push_back(ReceivedFrame {
            peer: Some(left_route),
            bytes: Fragment {
                transfer_id: 9_000,
                index: 0,
                count: 1,
                payload: b"syntactically-valid-invalid-client-flight".to_vec(),
            }
            .encode()
            .unwrap(),
        });
        assert_eq!(responder.pump_at(&right, now).unwrap(), 0);
        assert!(matches!(responder.phase, SessionPhase::Responder(_)));

        for _ in 0..64 {
            now += Duration::from_secs(60);
            initiator.pump_at(&left, now).unwrap();
            responder.pump_at(&right, now).unwrap();
            if initiator.is_authenticated() && responder.is_authenticated() {
                break;
            }
        }
        assert!(initiator.is_authenticated());
        assert!(responder.is_authenticated());

        initiator.retries.clear();
        initiator.deferred_wants.clear();
        initiator.outbox.clear();
        responder.retries.clear();
        responder.deferred_wants.clear();
        responder.outbox.clear();
        left.inbound.lock().unwrap().clear();
        right.inbound.lock().unwrap().clear();

        for index in 0..MAX_UNAUTHENTICATED_FAILURES_PER_PUMP {
            let bytes = if index == 0 {
                Vec::new()
            } else {
                Fragment {
                    transfer_id: 10_000 + index as u64,
                    index: 0,
                    count: 1,
                    payload: b"not-an-authenticated-session-record".to_vec(),
                }
                .encode()
                .unwrap()
            };
            left.inbound.lock().unwrap().push_back(ReceivedFrame {
                peer: Some(right_route),
                bytes,
            });
        }
        let receipt_id = ObjectId::for_envelope(EnvelopeId::from_sealed_bytes(b"carrier-fairness"));
        responder
            .queue_sync_message(&Message::Receipt(wire::Receipt {
                exchange_id: 93,
                object_id: receipt_id,
                total_len: 1,
                received: Vec::new(),
                complete: false,
            }))
            .unwrap();
        responder.pump_at(&right, now).unwrap();

        assert_eq!(initiator.pump_at(&left, now).unwrap(), 0);
        assert!(initiator.is_authenticated());
        assert!(initiator.backend().receipts.is_empty());
        assert_eq!(initiator.pump_at(&left, now).unwrap(), 1);
        assert_eq!(initiator.backend().receipts.len(), 1);
        assert_eq!(initiator.backend().receipts[0].2.object_id, receipt_id);

        let authenticated_invalid = responder
            .seal_plaintext(b"authenticated-but-not-a-wire-message")
            .unwrap();
        let transfer_id = responder.take_transfer_id().unwrap();
        for fragment in fragment::fragment(&authenticated_invalid, 256, transfer_id).unwrap() {
            right
                .send(Some(left_route), &fragment.encode().unwrap())
                .unwrap();
        }
        assert!(matches!(
            initiator.pump_at(&left, now),
            Err(RuntimeError::Wire(_))
        ));
        assert_eq!(initiator.backend().receipts.len(), 1);
    }

    #[test]
    fn completed_transfer_cache_drops_unauthenticated_conflicting_identifier_reuse() {
        let (initiator_bundle, responder_bundle) = bundles();
        let mut initiator = RuntimeDriver::initiator(
            initiator_bundle,
            SyncState::new(Default::default(), SparseInventory::new()).unwrap(),
            FakeBackend::default(),
            StartRequest {
                exchange_id: 29,
                topics: vec!["alpha".into()],
                scopes: vec!["mission/team".into()],
                min_priority: Priority::Routine as u8,
            },
            None,
        )
        .unwrap();
        let mut responder = RuntimeDriver::responder(
            responder_bundle,
            SyncState::new(Default::default(), SparseInventory::new()).unwrap(),
            FakeBackend::default(),
            None,
        )
        .unwrap();
        let (left, right) = MemoryLink::pair(256);
        for _ in 0..64 {
            initiator.pump(&left).unwrap();
            responder.pump(&right).unwrap();
            if initiator.is_authenticated()
                && responder.is_authenticated()
                && !initiator.completed_transfers.is_empty()
            {
                break;
            }
        }
        let completed = *initiator
            .completed_transfers
            .back()
            .expect("successful authenticated logical transfer was cached");
        left.inbound.lock().unwrap().push_back(ReceivedFrame {
            peer: completed.peer,
            bytes: Fragment {
                transfer_id: completed.transfer_id,
                index: 0,
                count: 1,
                payload: b"conflicting-transfer-reuse".to_vec(),
            }
            .encode()
            .unwrap(),
        });
        assert!(initiator.pump(&left).is_ok());
        assert!(initiator.is_authenticated());

        for offset in 0..MAX_COMPLETED_TRANSFERS + 5 {
            initiator.remember_completed_transfer(CompletedTransfer {
                peer: None,
                transfer_id: 10_000 + offset as u64,
                logical_len: offset,
                logical_digest: [offset as u8; 32],
            });
        }
        assert_eq!(initiator.completed_transfers.len(), MAX_COMPLETED_TRANSFERS);
        assert_eq!(
            initiator.completed_transfers.front().unwrap().transfer_id,
            10_005
        );
    }

    #[test]
    fn blob_runtime_relays_then_resumes_from_a_different_authenticated_peer() {
        let root = runtime_directory("blob-resume");
        let producer_db = root.join("producer.sqlite3");
        let relay_db = root.join("relay.sqlite3");
        let consumer_db = root.join("consumer.sqlite3");
        let poisoned_consumer_db = root.join("poisoned-consumer.sqlite3");
        let producer_blob_dir = root.join("producer-blobs");
        let relay_blob_dir = root.join("relay-blobs");
        let consumer_blob_dir = root.join("consumer-blobs");
        let poisoned_consumer_blob_dir = root.join("poisoned-consumer-blobs");
        let scope = Scope::new("mission/team").unwrap();
        let topic = Topic::new("alpha").unwrap();
        let member =
            ProvisioningAccess::member(scope.clone(), vec![0], vec![topic.clone()]).unwrap();
        let route_only = ProvisioningAccess::relay(scope.clone(), vec![0]).unwrap();
        let mut provisioner = ReferenceProvisioner::from_seed([0x6d; 32]).unwrap();
        let producer_bundle = provisioner
            .issue_node(101, std::slice::from_ref(&member))
            .unwrap();
        let relay_bundle = provisioner.issue_node(102, &[route_only]).unwrap();
        let consumer_bundle = provisioner.issue_node(103, &[member]).unwrap();
        let producer_bundle_bytes = producer_bundle.to_bytes().unwrap();
        let relay_bundle_bytes = relay_bundle.to_bytes().unwrap();
        let consumer_bundle_bytes = consumer_bundle.to_bytes().unwrap();
        let blob_config = BlobStoreConfig {
            max_bytes: 16 * 1024 * 1024,
            max_chunks: 128,
        };
        let filter = InterestFilter {
            topics: vec![topic.as_str().to_owned()],
            scopes: vec![scope.as_str().to_owned()],
            min_priority: Priority::Routine as u8,
        };
        let legacy_blob_versions = || {
            vec![
                wire::SEMANTIC_PROTOCOL_V8,
                wire::SEMANTIC_PROTOCOL_V7,
                wire::SEMANTIC_PROTOCOL_V6,
                wire::SEMANTIC_PROTOCOL_V5,
                wire::SEMANTIC_PROTOCOL_V4,
                wire::SEMANTIC_PROTOCOL_V3,
                wire::SEMANTIC_PROTOCOL_V2,
                wire::SEMANTIC_PROTOCOL_V1,
            ]
        };

        let mut producer_node = open_reference_node(
            &producer_db,
            restored_bundle(&producer_bundle_bytes),
            NodeConfig::default(),
        )
        .unwrap();
        let producer_identity = producer_node.identity();
        let plaintext = (0..(usize::try_from(MAX_BLOB_CHUNK_SIZE).unwrap() + 937))
            .map(|index| ((index * 31 + 7) % 251) as u8)
            .collect::<Vec<_>>();
        let mut source = Cursor::new(plaintext.clone());
        let mut scratch = Cursor::new(Vec::new());
        let mut producer_blob_service = producer_node
            .current_blob_service(&scope, &topic, &producer_blob_dir, blob_config)
            .unwrap();
        let manifest = producer_blob_service
            .prepare(
                &mut source,
                &mut scratch,
                MAX_BLOB_CHUNK_SIZE,
                BlobMetadata::new(Some("application/test".into()), b"resume-v1".to_vec()).unwrap(),
            )
            .unwrap();
        producer_blob_service
            .encrypt_some(&mut source, &manifest, u64::MAX)
            .unwrap();
        let finished = producer_blob_service.finish(manifest.id()).unwrap();
        drop(producer_blob_service);
        producer_node
            .publish_blob_manifest(
                PublishRequest {
                    class: DataClass::Blob,
                    topic: topic.clone(),
                    scope: scope.clone(),
                    priority: Priority::Priority,
                    ttl_ms: None,
                    logical_key: finished.id().as_bytes().to_vec(),
                    payload: finished.manifest_bytes().to_vec(),
                    tombstone: false,
                },
                finished.route_commitment(),
            )
            .unwrap();
        let descriptors = producer_node
            .authorized_envelopes([0; 32], &[], &filter, InventoryPurpose::ReceiveBaseline)
            .unwrap();
        assert_eq!(descriptors.len(), 1);
        let source_envelope = descriptors[0].envelope_id;
        let route = AuthenticatedBlobRoute::new(source_envelope, finished.route_commitment());
        let mut producer_blobs =
            BlobTransferStore::open_with_config(&producer_blob_dir, blob_config).unwrap();
        let object_ids = producer_blobs.object_ids_for_route(route, 16).unwrap();
        assert_eq!(object_ids.len() as u64, manifest.chunk_count());
        let carriers = object_ids
            .iter()
            .map(|object_id| {
                producer_blobs
                    .read_object_range(route, *object_id, 0, usize::MAX)
                    .unwrap()
                    .1
            })
            .collect::<Vec<_>>();
        drop(producer_blobs);

        let relay_node = open_reference_node(
            &relay_db,
            restored_bundle(&relay_bundle_bytes),
            NodeConfig::default(),
        )
        .unwrap();
        let relay_identity = relay_node.identity();
        assert_ne!(producer_identity, relay_identity);
        let relay_blobs =
            BlobTransferStore::open_with_config(&relay_blob_dir, blob_config).unwrap();
        let mut relay_backend = BlobRuntimeBackend::new(relay_node, relay_blobs);
        assert!(
            relay_backend
                .commit_authenticated_object(
                    producer_identity,
                    1,
                    object_ids[0],
                    carriers[0].clone(),
                    Vec::new(),
                )
                .is_err()
        );

        // First RuntimeDriver contact makes a route-only relay ingest the
        // source envelope before accepting and retaining its opaque carriers.
        let producer_backend = RecordingBackend::new(
            BlobRuntimeBackend::new(
                producer_node,
                BlobTransferStore::open_with_config(&producer_blob_dir, blob_config).unwrap(),
            ),
            None,
        );
        let mut relay_driver = RuntimeDriver::initiator_with_semantic_versions(
            restored_bundle(&relay_bundle_bytes),
            SyncState::new(Default::default(), SparseInventory::new()).unwrap(),
            relay_backend,
            blob_start(201),
            None,
            legacy_blob_versions(),
        )
        .unwrap();
        let mut producer_driver = RuntimeDriver::responder(
            restored_bundle(&producer_bundle_bytes),
            SyncState::new(Default::default(), SparseInventory::new()).unwrap(),
            producer_backend,
            None,
        )
        .unwrap();
        let (relay_link, producer_link) = MemoryLink::pair(1400);
        for _ in 0..2000 {
            relay_driver.pump(&relay_link).unwrap();
            producer_driver.pump(&producer_link).unwrap();
            if relay_driver
                .sync()
                .inventory()
                .contains(&ObjectId::for_envelope(source_envelope))
                && object_ids
                    .iter()
                    .all(|object_id| relay_driver.sync().inventory().contains(object_id))
            {
                break;
            }
        }
        assert!(relay_driver.is_authenticated());
        assert!(
            producer_driver
                .backend()
                .inventories
                .iter()
                .filter(|(purpose, _)| *purpose == InventoryPurpose::ServePeer)
                .any(|(_, inventory)| object_ids
                    .iter()
                    .all(|object_id| inventory.contains(object_id)))
        );
        assert!(
            relay_driver
                .sync()
                .inventory()
                .contains(&ObjectId::for_envelope(source_envelope))
        );
        assert!(
            object_ids
                .iter()
                .all(|object_id| relay_driver.sync().inventory().contains(object_id)),
            "blob membership={:?}, pending wants={:?}, server wants={:?}",
            object_ids
                .iter()
                .map(|object_id| relay_driver.sync().inventory().contains(object_id))
                .collect::<Vec<_>>(),
            relay_driver
                .sync()
                .wants()
                .iter()
                .map(|(object_id, progress)| (
                    *object_id,
                    progress.total_len(),
                    progress.received_ranges().to_vec()
                ))
                .collect::<Vec<_>>(),
            producer_driver.backend().blob_wants
        );
        assert_eq!(
            relay_driver
                .backend_mut()
                .blobs_mut()
                .object_ids_for_route(route, 16)
                .unwrap(),
            object_ids
        );

        // Model a crash after the authenticated source record is durable but
        // before its completed staging rows are retired. A restart cannot
        // reconstruct hop-forwarding bytes, so the exact already-authenticated
        // envelope must retire idempotently while a novel envelope still
        // requires live forwarding authorization.
        let source_object = ObjectId::for_envelope(source_envelope);
        let source_sealed = relay_driver
            .backend_mut()
            .node_mut()
            .inspect_stored_data_envelope(source_envelope)
            .unwrap()
            .unwrap()
            .1;
        relay_driver
            .backend_mut()
            .node_mut()
            .store_transfer_chunk(source_object, source_sealed.len() as u64, 0, &source_sealed)
            .unwrap();
        let replay_bytes = relay_driver
            .backend_mut()
            .node_mut()
            .complete_transfer_object(source_object, source_sealed.len() as u64)
            .unwrap();
        let replay_item = relay_driver
            .backend_mut()
            .commit_authenticated_object(
                producer_identity,
                1,
                source_object,
                replay_bytes,
                Vec::new(),
            )
            .unwrap();
        let stored_item = relay_driver
            .backend_mut()
            .node_mut()
            .inspect_stored_data_envelope(source_envelope)
            .unwrap()
            .map(|(verified, _)| verified.id);
        assert_eq!(replay_item, stored_item);
        assert!(
            relay_driver
                .backend_mut()
                .durable_progress(128)
                .unwrap()
                .iter()
                .all(|progress| progress.object_id != source_object)
        );
        drop(producer_driver);
        drop(relay_driver);

        // An authenticated first peer now supplies one deliberately corrupted
        // carrier range under the genuine advertised ObjectID. The remaining
        // bytes are honest, so the poison is detected only by terminal carrier
        // verification after the object is complete. The runtime must then
        // atomically remove every persisted range/known length for precisely
        // that typed object and reset its in-memory WANT.
        let producer_node = open_reference_node(
            &producer_db,
            restored_bundle(&producer_bundle_bytes),
            NodeConfig::default(),
        )
        .unwrap();
        let malicious_backend = RecordingBackend::new(
            BlobRuntimeBackend::new(
                producer_node,
                BlobTransferStore::open_with_config(&producer_blob_dir, blob_config).unwrap(),
            ),
            None,
        )
        .corrupt_next_blob_payload();
        let poisoned_consumer_node = open_reference_node(
            &poisoned_consumer_db,
            restored_bundle(&consumer_bundle_bytes),
            NodeConfig::default(),
        )
        .unwrap();
        let poisoned_consumer_backend = RecordingBackend::new(
            BlobRuntimeBackend::new(
                poisoned_consumer_node,
                BlobTransferStore::open_with_config(&poisoned_consumer_blob_dir, blob_config)
                    .unwrap(),
            ),
            None,
        );
        let mut poisoned_consumer_driver = RuntimeDriver::initiator_with_semantic_versions(
            restored_bundle(&consumer_bundle_bytes),
            SyncState::new(Default::default(), SparseInventory::new()).unwrap(),
            poisoned_consumer_backend,
            blob_start(204),
            None,
            legacy_blob_versions(),
        )
        .unwrap();
        let mut malicious_peer_driver = RuntimeDriver::responder(
            restored_bundle(&producer_bundle_bytes),
            SyncState::new(Default::default(), SparseInventory::new()).unwrap(),
            malicious_backend,
            None,
        )
        .unwrap();
        let (poisoned_consumer_link, malicious_link) = MemoryLink::pair(1400);
        let mut terminal_failure = None;
        for _ in 0..5000 {
            match poisoned_consumer_driver.pump(&poisoned_consumer_link) {
                Ok(_) => {}
                Err(error) => {
                    terminal_failure = Some(error);
                    break;
                }
            }
            malicious_peer_driver.pump(&malicious_link).unwrap();
        }
        assert!(matches!(terminal_failure, Some(RuntimeError::Backend(_))));
        assert_eq!(
            poisoned_consumer_driver.authenticated_peer(),
            Some(producer_identity)
        );
        let rejected_object = *poisoned_consumer_driver
            .backend()
            .aborted
            .last()
            .expect("terminal carrier authentication must abort staging");
        assert_eq!(rejected_object.kind(), ObjectKind::BlobChunk);
        let reset_progress = poisoned_consumer_driver
            .sync()
            .wants()
            .get(&rejected_object)
            .expect("terminal rejection keeps a peer-neutral request");
        assert_eq!(reset_progress.total_len(), None);
        assert!(reset_progress.received_ranges().is_empty());
        assert!(
            poisoned_consumer_driver
                .backend_mut()
                .durable_progress(128)
                .unwrap()
                .iter()
                .all(|entry| entry.object_id != rejected_object)
        );
        drop(malicious_peer_driver);
        drop(poisoned_consumer_driver);

        // A brand-new reducer and store handles then authenticate a different,
        // honest route-only relay. Restart hydration contains no poisoned
        // offsets, so the exact same carrier is requested from byte zero and
        // commits normally.
        let relay_node = open_reference_node(
            &relay_db,
            restored_bundle(&relay_bundle_bytes),
            NodeConfig::default(),
        )
        .unwrap();
        let honest_relay_backend = RecordingBackend::new(
            BlobRuntimeBackend::new(
                relay_node,
                BlobTransferStore::open_with_config(&relay_blob_dir, blob_config).unwrap(),
            ),
            None,
        );
        let poisoned_consumer_node = open_reference_node(
            &poisoned_consumer_db,
            restored_bundle(&consumer_bundle_bytes),
            NodeConfig::default(),
        )
        .unwrap();
        let poisoned_consumer_backend = BlobRuntimeBackend::new(
            poisoned_consumer_node,
            BlobTransferStore::open_with_config(&poisoned_consumer_blob_dir, blob_config).unwrap(),
        );
        let mut recovered_consumer_driver = RuntimeDriver::initiator_with_semantic_versions(
            restored_bundle(&consumer_bundle_bytes),
            SyncState::new(Default::default(), SparseInventory::new()).unwrap(),
            poisoned_consumer_backend,
            blob_start(205),
            None,
            legacy_blob_versions(),
        )
        .unwrap();
        let mut honest_relay_driver = RuntimeDriver::responder(
            restored_bundle(&relay_bundle_bytes),
            SyncState::new(Default::default(), SparseInventory::new()).unwrap(),
            honest_relay_backend,
            None,
        )
        .unwrap();
        let (recovered_consumer_link, honest_relay_link) = MemoryLink::pair(1400);
        let mut recovered_after_poison = false;
        for _ in 0..5000 {
            recovered_consumer_driver
                .pump(&recovered_consumer_link)
                .unwrap();
            honest_relay_driver.pump(&honest_relay_link).unwrap();
            if recovered_consumer_driver
                .backend_mut()
                .blobs_mut()
                .object_ids_for_route(route, 16)
                .is_ok_and(|ids| ids == object_ids)
            {
                recovered_after_poison = true;
                break;
            }
        }
        assert!(recovered_after_poison);
        assert_eq!(
            recovered_consumer_driver.authenticated_peer(),
            Some(relay_identity)
        );
        assert!(
            honest_relay_driver
                .backend()
                .blob_wants
                .iter()
                .any(|want| want.object_id == rejected_object
                    && want.total_len.is_none()
                    && want.missing.is_empty())
        );
        assert!(
            recovered_consumer_driver
                .backend_mut()
                .durable_progress(128)
                .unwrap()
                .iter()
                .all(|entry| entry.object_id != rejected_object)
        );
        drop(honest_relay_driver);
        let poisoned_consumer_backend = recovered_consumer_driver.into_backend();
        let (mut poisoned_consumer_node, poisoned_consumer_blobs) =
            poisoned_consumer_backend.into_parts();
        drop(poisoned_consumer_blobs);
        let mut poisoned_reader_service = poisoned_consumer_node
            .current_blob_service(&scope, &topic, &poisoned_consumer_blob_dir, blob_config)
            .unwrap();
        let mut poisoned_reader = poisoned_reader_service
            .reader_for_local(finished.id())
            .unwrap();
        let mut recovered_poisoned = Vec::new();
        poisoned_reader
            .stream_into(&mut recovered_poisoned)
            .unwrap();
        assert_eq!(recovered_poisoned, plaintext);

        // A content-authorized consumer starts with the original producer. The
        // server deliberately emits only one DATA message per Blob WANT and
        // the receiving link admits one fragment per pump, guaranteeing a
        // genuine durable partial carrier before disconnection.
        let producer_node = open_reference_node(
            &producer_db,
            restored_bundle(&producer_bundle_bytes),
            NodeConfig::default(),
        )
        .unwrap();
        let producer_backend = RecordingBackend::new(
            BlobRuntimeBackend::new(
                producer_node,
                BlobTransferStore::open_with_config(&producer_blob_dir, blob_config).unwrap(),
            ),
            Some(1),
        );
        let consumer_node = open_reference_node(
            &consumer_db,
            restored_bundle(&consumer_bundle_bytes),
            NodeConfig::default(),
        )
        .unwrap();
        let consumer_backend = BlobRuntimeBackend::new(
            consumer_node,
            BlobTransferStore::open_with_config(&consumer_blob_dir, blob_config).unwrap(),
        );
        let mut consumer_driver = RuntimeDriver::initiator_with_semantic_versions(
            restored_bundle(&consumer_bundle_bytes),
            SyncState::new(Default::default(), SparseInventory::new()).unwrap(),
            consumer_backend,
            blob_start(202),
            None,
            legacy_blob_versions(),
        )
        .unwrap();
        let mut first_peer_driver = RuntimeDriver::responder(
            restored_bundle(&producer_bundle_bytes),
            SyncState::new(Default::default(), SparseInventory::new()).unwrap(),
            producer_backend,
            None,
        )
        .unwrap();
        let (consumer_link, producer_link) = MemoryLink::pair(1400);
        let mut interrupted = None;
        for _ in 0..5000 {
            consumer_link.allow_receives(1);
            consumer_driver.pump(&consumer_link).unwrap();
            let progress = consumer_driver.backend_mut().durable_progress(128).unwrap();
            interrupted = progress.into_iter().find(|entry| {
                entry.object_id.kind() == ObjectKind::BlobChunk
                    && !entry.received.is_empty()
                    && entry.received.iter().map(|range| range.len()).sum::<u64>() < entry.total_len
            });
            if interrupted.is_some() {
                break;
            }
            first_peer_driver.pump(&producer_link).unwrap();
        }
        let interrupted = interrupted.expect("a carrier must be durably partial");
        assert_eq!(
            consumer_driver.authenticated_peer(),
            Some(producer_identity)
        );
        let expected_missing = missing_complement(interrupted.total_len, &interrupted.received);
        assert!(!expected_missing.is_empty());
        drop(first_peer_driver);
        drop(consumer_driver);

        // A genuinely new driver/reducer opens the same SQLite and Blob
        // stores, authenticates a different route-only peer, hydrates exact
        // peer-neutral ranges, and requests only the complement.
        let relay_node = open_reference_node(
            &relay_db,
            restored_bundle(&relay_bundle_bytes),
            NodeConfig::default(),
        )
        .unwrap();
        let relay_backend = RecordingBackend::new(
            BlobRuntimeBackend::new(
                relay_node,
                BlobTransferStore::open_with_config(&relay_blob_dir, blob_config).unwrap(),
            ),
            None,
        );
        let consumer_node = open_reference_node(
            &consumer_db,
            restored_bundle(&consumer_bundle_bytes),
            NodeConfig::default(),
        )
        .unwrap();
        let consumer_backend = BlobRuntimeBackend::new(
            consumer_node,
            BlobTransferStore::open_with_config(&consumer_blob_dir, blob_config).unwrap(),
        );
        let mut consumer_driver = RuntimeDriver::initiator_with_semantic_versions(
            restored_bundle(&consumer_bundle_bytes),
            SyncState::new(Default::default(), SparseInventory::new()).unwrap(),
            consumer_backend,
            blob_start(203),
            None,
            legacy_blob_versions(),
        )
        .unwrap();
        let mut relay_driver = RuntimeDriver::responder(
            restored_bundle(&relay_bundle_bytes),
            SyncState::new(Default::default(), SparseInventory::new()).unwrap(),
            relay_backend,
            None,
        )
        .unwrap();
        let (consumer_link, relay_link) = MemoryLink::pair(1400);
        let mut completed = false;
        for _ in 0..3000 {
            consumer_driver.pump(&consumer_link).unwrap();
            relay_driver.pump(&relay_link).unwrap();
            if consumer_driver
                .backend_mut()
                .blobs_mut()
                .object_ids_for_route(route, 16)
                .is_ok_and(|ids| ids == object_ids)
            {
                completed = true;
                break;
            }
        }
        assert!(completed);
        assert_eq!(consumer_driver.authenticated_peer(), Some(relay_identity));
        assert_ne!(
            consumer_driver.authenticated_peer(),
            Some(producer_identity)
        );
        assert!(
            relay_driver
                .backend()
                .blob_wants
                .iter()
                .any(|want| want.object_id == interrupted.object_id
                    && want.total_len == Some(interrupted.total_len)
                    && want.missing == expected_missing)
        );
        assert!(
            consumer_driver
                .backend_mut()
                .durable_progress(128)
                .unwrap()
                .iter()
                .all(|entry| entry.object_id != interrupted.object_id)
        );
        drop(relay_driver);
        let consumer_backend = consumer_driver.into_backend();
        let (mut consumer_node, consumer_blobs) = consumer_backend.into_parts();
        drop(consumer_blobs);
        let mut reader_service = consumer_node
            .current_blob_service(&scope, &topic, &consumer_blob_dir, blob_config)
            .unwrap();
        let mut reader = reader_service.reader_for_local(finished.id()).unwrap();
        let mut recovered = Vec::new();
        reader.stream_into(&mut recovered).unwrap();
        assert_eq!(recovered, plaintext);

        fs::remove_dir_all(root).unwrap();
    }
}
