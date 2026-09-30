//! High-level selected Event, State, Record, and Blob application surfaces.
//!
//! This module deliberately exposes no source-envelope, cryptographic-provider,
//! carrier, inventory, reconciliation, or sealed-byte operations. Stopped Blob
//! access is synchronous and streaming; live Blob access uses the bounded
//! actor and returns one zeroize-on-drop page. Other plaintext is bounded.
//! This module composes the same mission-bound redb authority used by the
//! selected runtime and freshly verifies every application result before
//! returning plaintext.

use std::{
    fmt, fs,
    path::Path,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
};

#[cfg(test)]
use aster_mesh::CustodySample;
use aster_mesh::{
    EventContentVerification, ProvisioningLoadId, ProvisioningSecretLoader, ProvisioningSecretRef,
    ProvisioningUnprotector, ReferenceEnvelopeSealer,
};
pub use aster_mesh::{NodeId, Priority, Scope, Topic};
use aster_redb_store::{
    AggregateStoreUsage, BlobStoreError, ControlPolicySnapshot, ControlTransferId,
    CustodyObjectKey, CustodyQuota, CustodyStoreError, EventDeliveryAck as StoreEventDeliveryAck,
    EventGapScanPlan, EventOperationKey, EventQueryFilter, EventReplicationPolicySnapshot,
    EventSemanticId, EventSubscriptionId as StoreEventSubscriptionId, EventSubscriptionKey,
    EventSubscriptionMode, EventSubscriptionPollSelection, EventSubscriptionRemoveOutcome,
    EventSubscriptionSpec, MAX_EVENT_PAGE, MAX_EVENT_POLL_DELIVERIES, MAX_EVENT_SUBSCRIPTION_SCAN,
    Store, StoreError, StoreLimits, StoredEvent, StoredEventTransfer,
};
pub use aster_redb_store::{
    CommittedEventContent, CommittedEventReceipt, EventClientId, EventOperationAbandonment,
    EventOperationAuditState, EventOperationAuditStatus, EventOperationLimits,
    EventOperationSequence, EventOperationStats, EventPublicationSession, EventRecoverySnapshot,
    EventResultAcknowledgement, NumberedEventOperationError, NumberedEventOperationStats,
    NumberedEventPublishOutcome, NumberedEventResult,
};
use tokio::sync::{mpsc, oneshot};

use crate::{
    NodeError,
    mission::UnprotectedReferenceMission,
    runtime::{
        AuthenticatedEventRouteCache, EVENT_OPERATION_CONFLICT, EVENT_OPERATION_RETIRED,
        EventEmissionPolicy, NodeCustodyClock, STORE_FILE, SelectedEventPublish,
        StartupEventVerification, absolute_path_from, absolute_state_path,
        cache_accepted_stored_event, drive_custody_maintenance, ensure_principal_active,
        ensure_state_accepts_normal_operation, event_is_inactive,
        open_startup_event_verifier_and_cache,
        prune_authenticated_event_route_cache_to_sender_projection, publish_selected_event_once,
        refresh_application_policy, verify_content_stored_claim, verify_stored_claim,
    },
};

mod blob;
#[cfg(test)]
#[path = "application/operation_capacity_test.rs"]
mod operation_capacity_test;
mod record;
mod state;
pub(crate) use blob::SelectedBlobCommand;
pub use blob::{
    BLOB_DELIVERY_TOKEN_BYTES, BlobAcknowledgement, BlobDelivery, BlobDeliveryPage,
    BlobDeliveryStatus, BlobDeliveryToken, BlobDepotLimits, BlobId, BlobPollRequest,
    BlobPublicationId, BlobPublishRequest, BlobPublishResult, BlobReadPage, BlobReadPageRequest,
    BlobReadRequest, BlobReadResult, BlobSubscription, BlobSubscriptionId, BlobSubscriptionRequest,
    BlobTransferPhase, BlobTransferStatus, BlobUnsubscribe, MAX_SELECTED_BLOB_DELIVERIES,
    MAX_SELECTED_BLOB_PAGE_BYTES, MAX_SELECTED_BLOB_SUBSCRIPTION_SCAN,
    MAX_SELECTED_LIVE_BLOB_BYTES, MAX_SELECTED_LIVE_BLOB_CHUNKS, PendingBlobTransferStatus,
    SelectedBlobHandle, SelectedBlobNode, SelectedBlobOptions,
};
pub(crate) use record::SelectedRecordCommand;
pub use record::{
    MAX_SELECTED_RECORD_DELIVERIES, MAX_SELECTED_RECORD_SUBSCRIPTION_SCAN,
    RECORD_DELIVERY_TOKEN_BYTES, RecordAcknowledgement, RecordConflict, RecordDelivery,
    RecordDeliveryConflict, RecordDeliveryPage, RecordDeliveryProjection, RecordDeliveryStatus,
    RecordDeliveryToken, RecordId, RecordItem, RecordPollRequest, RecordProjection,
    RecordProjectionId, RecordProjectionKey, RecordPublishRequest, RecordPublishResult,
    RecordQuery, RecordResolutionGuard, RecordResolveRequest, RecordSubscription,
    RecordSubscriptionId, RecordSubscriptionRequest, RecordUnsubscribe, RecordVersionDisposition,
    SelectedRecordHandle, SelectedRecordNode,
};
pub(crate) use state::SelectedStateCommand;
pub use state::{
    MAX_SELECTED_STATE_DELIVERIES, MAX_SELECTED_STATE_SUBSCRIPTION_SCAN,
    STATE_DELIVERY_TOKEN_BYTES, SelectedStateHandle, SelectedStateNode, StateAcknowledgement,
    StateDelivery, StateDeliveryPage, StateDeliveryStatus, StateDeliveryToken, StateId, StateItem,
    StatePollRequest, StateProjection, StatePublishRequest, StatePublishResult, StateQuery,
    StateSubscription, StateSubscriptionId, StateSubscriptionRequest, StateUnsubscribe,
    StateVersionDisposition,
};

/// Maximum number of accepted Event rows one query call may scan.
pub const MAX_SELECTED_EVENT_PAGE: usize = MAX_EVENT_PAGE;

/// Maximum number of at-least-once deliveries returned by one poll.
pub const MAX_SELECTED_EVENT_DELIVERIES: usize = MAX_EVENT_POLL_DELIVERIES;

/// Maximum accepted or pending rows freshly verified by one poll.
pub const MAX_SELECTED_EVENT_SUBSCRIPTION_SCAN: usize = MAX_EVENT_SUBSCRIPTION_SCAN;
const MAX_SELECTED_EVENT_PLAN_RETRIES: usize = 4;

/// Stable, high-level failure category for selected application operations.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum ApplicationErrorKind {
    InvalidRequest,
    RequestRejected,
    UnauthorizedOrRevoked,
    PolicyUnsettled,
    Conflict,
    SessionFenced,
    SequenceGap,
    SequenceRetired,
    RecoveryRequired,
    LegacyState,
    /// The operation remains durably bound after its finite payload was retired.
    ExpiredOrRetired,
    /// The durable Event idempotency map reached its dedicated hard ceiling.
    OperationCapacity,
    ResourceLimit,
    StateUnavailable,
    Integrity,
    Provisioning,
}

/// Sanitized selected application failure.
///
/// The underlying store, source-envelope, carrier, and provider errors remain
/// private so an application cannot couple itself to privileged mechanics or
/// learn exact transfer/schema details through an error path.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ApplicationError {
    kind: ApplicationErrorKind,
    operation: &'static str,
}

impl ApplicationError {
    /// Stable category suitable for application control flow.
    pub const fn kind(&self) -> ApplicationErrorKind {
        self.kind
    }

    /// High-level operation that failed.
    pub const fn operation(&self) -> &'static str {
        self.operation
    }

    const fn new(kind: ApplicationErrorKind, operation: &'static str) -> Self {
        Self { kind, operation }
    }
}

impl fmt::Display for ApplicationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let disposition = match self.kind {
            ApplicationErrorKind::InvalidRequest => "invalid application request",
            ApplicationErrorKind::RequestRejected => "request rejected by selected data policy",
            ApplicationErrorKind::UnauthorizedOrRevoked => {
                "application identity or selected data is not currently authorized"
            }
            ApplicationErrorKind::PolicyUnsettled => "mission policy is not settled",
            ApplicationErrorKind::Conflict => "idempotency or causal conflict",
            ApplicationErrorKind::SessionFenced => "publication session is fenced",
            ApplicationErrorKind::SequenceGap => "publication sequence has a gap",
            ApplicationErrorKind::SequenceRetired => "publication sequence is retired",
            ApplicationErrorKind::RecoveryRequired => "publication recovery is required",
            ApplicationErrorKind::LegacyState => "legacy publication state requires a fresh store",
            ApplicationErrorKind::ExpiredOrRetired => {
                "idempotent publication expired or was retired"
            }
            ApplicationErrorKind::OperationCapacity => "durable Event operation capacity exhausted",
            ApplicationErrorKind::ResourceLimit => "selected data resource limit reached",
            ApplicationErrorKind::StateUnavailable => "selected application state is unavailable",
            ApplicationErrorKind::Integrity => "selected data integrity check failed",
            ApplicationErrorKind::Provisioning => "mission provisioning is unavailable",
        };
        write!(
            formatter,
            "selected application {} failed: {disposition}",
            self.operation
        )
    }
}

impl std::error::Error for ApplicationError {}

/// Source-authenticated semantic identity returned to applications.
///
/// This deliberately omits the randomized exact transfer representation used
/// by reconciliation. Application deduplication uses this semantic identity
/// instead.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct EventId([u8; 32]);

impl EventId {
    /// Constructs an application Event identity from complete semantic identity bytes.
    pub const fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// Returns the complete semantic identity bytes.
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    fn from_store(id: EventSemanticId) -> Self {
        Self(*id.as_bytes())
    }

    pub(crate) fn into_store(self) -> EventSemanticId {
        EventSemanticId::new(self.0)
    }
}

impl fmt::Display for EventId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        for byte in self.0 {
            write!(formatter, "{byte:02x}")?;
        }
        Ok(())
    }
}

/// One durable, idempotent Event publication request.
///
/// The operation key is application-chosen and bounded to 256 bytes. Reusing
/// the same key with the same request returns the original Event; reusing it
/// with different content fails closed. Resolution still requires the caller
/// to remain authorized by current mission policy. [`EventPublishOptions`]
/// supplies the additive finite-TTL path without changing this durable request.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EventPublishRequest {
    pub operation_key: Vec<u8>,
    pub predecessor: Option<EventId>,
    pub topic: Topic,
    pub scope: Scope,
    pub priority: Priority,
    pub logical_key: Vec<u8>,
    pub payload: Vec<u8>,
    pub tombstone: bool,
}

/// Numbered Event publication owned by one configured application client.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NumberedEventPublishRequest {
    pub client_id: EventClientId,
    pub session: EventPublicationSession,
    pub sequence: EventOperationSequence,
    pub predecessor: Option<EventId>,
    pub topic: Topic,
    pub scope: Scope,
    pub priority: Priority,
    pub logical_key: Vec<u8>,
    pub payload: Vec<u8>,
    pub tombstone: bool,
}

/// Additive publication behavior for one selected Event.
///
/// Durable publication is the default. A finite TTL is source authenticated,
/// begins at the local custody checkpoint, and can only cross semantic-v3+
/// mission sessions (v3, v4, or v5) carrying an authenticated cumulative
/// custody claim.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct EventPublishOptions {
    ttl_ms: Option<u64>,
}

impl EventPublishOptions {
    /// Selects the durable, non-expiring Event form.
    pub const fn durable() -> Self {
        Self { ttl_ms: None }
    }

    /// Selects a positive source-authenticated lifetime in milliseconds.
    pub const fn finite_ttl_ms(ttl_ms: u64) -> Result<Self, ApplicationError> {
        if ttl_ms == 0 {
            return Err(ApplicationError::new(
                ApplicationErrorKind::InvalidRequest,
                "publish",
            ));
        }
        Ok(Self {
            ttl_ms: Some(ttl_ms),
        })
    }

    /// Returns the exact source-authenticated lifetime, when finite.
    pub const fn ttl_ms(self) -> Option<u64> {
        self.ttl_ms
    }
}

/// Successful durable publication without sealed bytes or provider internals.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EventPublishResult {
    pub id: EventId,
    pub publisher: NodeId,
    pub publisher_counter: u64,
    pub event_sequence: u64,
    pub priority: Priority,
    /// Exact source-authenticated lifetime, or `None` for a durable Event.
    pub ttl_ms: Option<u64>,
    pub acceptance_marker: u64,
    pub inserted: bool,
}

/// Bounded application query over content-accepted Event rows.
///
/// `limit` bounds rows scanned, not only rows returned. A selective query may
/// therefore return no items while `has_more` is true; continue from the
/// returned `scanned_through` marker.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EventQuery {
    pub publisher: Option<NodeId>,
    pub topic: Option<Topic>,
    pub scope: Option<Scope>,
    pub include_descendant_scopes: bool,
    pub logical_key: Option<Vec<u8>>,
    pub after_acceptance_marker: u64,
    pub limit: usize,
}

impl Default for EventQuery {
    fn default() -> Self {
        Self {
            publisher: None,
            topic: None,
            scope: None,
            include_descendant_scopes: false,
            logical_key: None,
            after_acceptance_marker: 0,
            limit: 128,
        }
    }
}

impl EventQuery {
    fn validate(&self) -> Result<(), ApplicationError> {
        if self.limit == 0 || self.limit > MAX_SELECTED_EVENT_PAGE {
            return Err(ApplicationError::new(
                ApplicationErrorKind::InvalidRequest,
                "query",
            ));
        }
        Ok(())
    }

    fn matches_verified(&self, event: &StoredEvent) -> bool {
        self.publisher
            .is_none_or(|publisher| event.header.stamp.dot.publisher == publisher)
            && self
                .topic
                .as_ref()
                .is_none_or(|topic| &event.header.topic == topic)
            && self.scope.as_ref().is_none_or(|scope| {
                if self.include_descendant_scopes {
                    scope.contains(&event.header.scope)
                } else {
                    &event.header.scope == scope
                }
            })
            && self
                .logical_key
                .as_ref()
                .is_none_or(|key| &event.header.logical_key == key)
    }
}

/// One freshly source/content-verified application Event.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EventItem {
    pub id: EventId,
    pub publisher: NodeId,
    pub publisher_counter: u64,
    pub event_sequence: u64,
    pub topic: Topic,
    pub scope: Scope,
    pub priority: Priority,
    /// Exact source-authenticated lifetime, or `None` for a durable Event.
    pub ttl_ms: Option<u64>,
    pub logical_key: Vec<u8>,
    pub payload: Vec<u8>,
    pub tombstone: bool,
    pub acceptance_marker: u64,
}

/// Marker-ordered bounded query result.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EventQueryPage {
    pub items: Vec<EventItem>,
    pub scanned_through: u64,
    pub has_more: bool,
}

/// Stable mission-local identity of one durable application subscription.
///
/// This is a local ledger identity, not a content or route capability.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct EventSubscriptionId([u8; 32]);

impl EventSubscriptionId {
    /// Constructs an identifier from complete durable bytes.
    pub const fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// Returns the complete durable identifier bytes.
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    fn from_store(id: StoreEventSubscriptionId) -> Self {
        Self(*id.as_bytes())
    }

    fn into_store(self) -> StoreEventSubscriptionId {
        StoreEventSubscriptionId::from_bytes(self.0)
    }
}

impl fmt::Display for EventSubscriptionId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        for byte in self.0 {
            write!(formatter, "{byte:02x}")?;
        }
        Ok(())
    }
}

/// Idempotent creation request for one durable Consume subscription.
///
/// The operation key identifies the subscription across process restarts.
/// Topic and scope intent never grant authority: current mission policy must
/// independently permit both route verification and content opening.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EventSubscriptionRequest {
    pub operation_key: Vec<u8>,
    pub topic: Topic,
    pub scope: Scope,
    pub include_descendant_scopes: bool,
}

/// Result of creating or replaying one durable subscription request.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct EventSubscription {
    pub id: EventSubscriptionId,
    pub inserted: bool,
}

/// One bounded at-least-once delivery poll.
///
/// `scan_limit` bounds all pending and accepted rows freshly source-verified,
/// not only matching rows returned. An empty page can therefore report
/// `has_more=true`; poll again to continue from the durable internal cursor.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct EventPollRequest {
    pub subscription: EventSubscriptionId,
    pub delivery_limit: usize,
    pub scan_limit: usize,
}

impl EventPollRequest {
    fn validate(self) -> Result<Self, ApplicationError> {
        if self.delivery_limit == 0
            || self.delivery_limit > MAX_SELECTED_EVENT_DELIVERIES
            || self.scan_limit == 0
            || self.scan_limit > MAX_SELECTED_EVENT_SUBSCRIPTION_SCAN
        {
            return Err(ApplicationError::new(
                ApplicationErrorKind::InvalidRequest,
                "poll",
            ));
        }
        Ok(self)
    }
}

/// One Event delivery whose attempt was durably incremented before return.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EventDelivery {
    pub event: EventItem,
    pub attempt: u64,
}

/// Bounded at-least-once delivery result.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct EventDeliveryPage {
    pub deliveries: Vec<EventDelivery>,
    pub has_more: bool,
}

/// Idempotent acknowledgement disposition for one semantic Event.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EventAcknowledgement {
    Acknowledged,
    AlreadyAcknowledged,
}

/// Idempotent disposition from withdrawing one durable receive selector.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EventUnsubscribe {
    /// This call removed the selector and its delivery ledger.
    Removed,
    /// The exact selector was already absent.
    AlreadyAbsent,
}

/// One bounded exact publisher/topic/scope stream gap query.
///
/// `scan_limit` bounds accepted stream positions which are freshly source
/// verified. Continue from `scanned_through_sequence`, including when a page
/// contains no gap.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EventGapQuery {
    pub publisher: NodeId,
    pub topic: Topic,
    pub scope: Scope,
    pub after_sequence: u64,
    pub scan_limit: usize,
}

impl EventGapQuery {
    fn validate(&self) -> Result<(), ApplicationError> {
        if self.scan_limit == 0 || self.scan_limit > MAX_SELECTED_EVENT_PAGE {
            return Err(ApplicationError::new(
                ApplicationErrorKind::InvalidRequest,
                "gaps",
            ));
        }
        Ok(())
    }
}

/// Missing half-open sequence interval anchored by a later authenticated Event.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EventGap {
    pub publisher: NodeId,
    pub topic: Topic,
    pub scope: Scope,
    pub start_sequence: u64,
    pub end_sequence: u64,
}

/// Bounded authenticated stream-gap page.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EventGapPage {
    pub gaps: Vec<EventGap>,
    pub scanned_through_sequence: u64,
    /// Conservative continuation hint derived only from a full verified page.
    ///
    /// A full page may be followed by an empty page; this never exposes an
    /// unverified structural look-ahead row.
    pub has_more: bool,
}

/// Current authorization of a previously authenticated mission peer.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PeerAuthorization {
    Active,
    Revoked,
}

/// Bounded outcome of the most recently completed authenticated contact.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ContactSyncStatus {
    /// That contact completed its negotiated bounded control and Event work.
    CompleteForLastNegotiatedContact,
    /// That contact reported bounded work which must continue later.
    WorkRemained,
    /// Durable control or receive-selector policy changed after that contact.
    PolicyChangedSinceContact,
}

/// One mission-authenticated peer observation without carrier or protocol details.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AuthenticatedPeerStatus {
    pub peer: NodeId,
    pub contacts: u64,
    pub authorization: PeerAuthorization,
    pub last_contact: ContactSyncStatus,
}

/// High-level local synchronization disposition.
///
/// This deliberately does not claim global convergence. `LastContactComplete`
/// describes only the last bounded authenticated negotiation with every
/// currently configured active peer.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EventSyncStatus {
    Offline,
    NoActiveConfiguredPeers,
    AwaitingAuthenticatedContact,
    LastContactComplete,
    WorkRemained,
    PolicyChangedSinceContact,
}

/// Occupancy-only warning against the configured ordinary operation limits.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EventOperationCapacityWarning {
    Ok,
    Warning,
    Critical,
    Exhausted,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EventOperationLedgerMode {
    Legacy,
    Numbered,
}

/// Candidate ledger headroom, independent of the approved evaluation profile.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct EventOperationCapacity {
    pub stats: EventOperationStats,
    pub numbered_stats: NumberedEventOperationStats,
    pub mode: EventOperationLedgerMode,
    pub limits: EventOperationLimits,
    pub rows: u64,
    pub logical_bytes: u64,
    pub ordinary_remaining: u64,
    pub emergency_remaining: u64,
    pub warning: EventOperationCapacityWarning,
}

impl EventOperationCapacity {
    pub fn new(stats: EventOperationStats, limits: EventOperationLimits) -> Self {
        Self::for_ledgers(stats, NumberedEventOperationStats::default(), limits)
    }

    pub fn for_ledgers(
        stats: EventOperationStats,
        numbered_stats: NumberedEventOperationStats,
        limits: EventOperationLimits,
    ) -> Self {
        const LEGACY_ACTIVE_BYTES: u64 = 162;
        const NUMBERED_RESULT_BYTES: u64 = 292;
        // EventOperationLimits construction checked both reserve arithmetic
        // and subtraction. Retained usage may exceed a lower reopened limit.
        let mode = if numbered_stats != NumberedEventOperationStats::default() {
            EventOperationLedgerMode::Numbered
        } else {
            EventOperationLedgerMode::Legacy
        };
        let rows = match mode {
            EventOperationLedgerMode::Legacy => stats.records_total,
            EventOperationLedgerMode::Numbered => numbered_stats
                .clients
                .saturating_add(numbered_stats.outstanding_results),
        };
        let logical_bytes = match mode {
            EventOperationLedgerMode::Legacy => stats.logical_bytes,
            EventOperationLedgerMode::Numbered => numbered_stats.logical_bytes,
        };
        let ordinary_records = limits.ordinary_record_limit();
        let ordinary_bytes = limits.max_logical_bytes() - limits.emergency_byte_reserve();
        let ordinary_remaining = ordinary_records.saturating_sub(rows).min(
            ordinary_bytes.saturating_sub(logical_bytes)
                / match mode {
                    EventOperationLedgerMode::Legacy => LEGACY_ACTIVE_BYTES,
                    EventOperationLedgerMode::Numbered => NUMBERED_RESULT_BYTES,
                },
        );
        let emergency_remaining = match mode {
            EventOperationLedgerMode::Legacy => {
                let total_remaining = limits.max_records().saturating_sub(rows).min(
                    limits.max_logical_bytes().saturating_sub(logical_bytes) / LEGACY_ACTIVE_BYTES,
                );
                total_remaining.saturating_sub(ordinary_remaining)
            }
            EventOperationLedgerMode::Numbered => {
                let total_remaining = limits.max_records().saturating_sub(rows).min(
                    limits.max_logical_bytes().saturating_sub(logical_bytes)
                        / NUMBERED_RESULT_BYTES,
                );
                total_remaining.saturating_sub(ordinary_remaining)
            }
        };
        let at_percent = |percent: u128| {
            u128::from(rows) * 100 >= u128::from(ordinary_records) * percent
                || u128::from(logical_bytes) * 100 >= u128::from(ordinary_bytes) * percent
        };
        let warning = if ordinary_remaining == 0 {
            EventOperationCapacityWarning::Exhausted
        } else if at_percent(90) {
            EventOperationCapacityWarning::Critical
        } else if at_percent(70) {
            EventOperationCapacityWarning::Warning
        } else {
            EventOperationCapacityWarning::Ok
        };
        Self {
            stats,
            numbered_stats,
            mode,
            limits,
            rows,
            logical_bytes,
            ordinary_remaining,
            emergency_remaining,
            warning,
        }
    }
}

/// Sanitized live selected-Event status snapshot. When the operation audit is
/// `Failed`, store usage, operation counts/bytes, and pending deliveries are
/// the last successfully read figures, not current or trusted capacity. Peer,
/// synchronization, emission, and audit observations remain actor-current.
#[derive(Clone, Debug, PartialEq)]
pub struct SelectedEventStatus {
    /// Legacy-ledger background audit; it does not claim numbered-ledger coverage.
    pub event_operation_audit: EventOperationAuditStatus,
    pub sync: EventSyncStatus,
    pub authenticated_contacts: u64,
    pub failed_contact_attempts: u64,
    pub peers: Vec<AuthenticatedPeerStatus>,
    pub emission_policy: EventEmissionPolicy,
    pub store_usage: AggregateStoreUsage,
    pub store_limits: StoreLimits,
    pub event_operation_capacity: EventOperationCapacity,
    /// New durable ledger rows committed in the preceding monotonic 60 seconds / 60.
    pub event_operation_rolling_accept_rate: f64,
    /// Ceiling of remaining / rate, saturated to u64; zero without observations.
    pub event_operation_estimated_seconds_to_exhaustion: u64,
    pub pending_deliveries: u64,
}

/// Cloneable live application handle backed by the running node's sole authority.
#[derive(Clone)]
pub struct SelectedEventHandle {
    commands: mpsc::Sender<SelectedApplicationCommand>,
    admission: Arc<AtomicBool>,
    identity: NodeId,
    mission_authority: NodeId,
}

impl SelectedEventHandle {
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

    /// Authenticated local publisher identity.
    pub const fn identity(&self) -> NodeId {
        self.identity
    }

    /// Stable mission authority bound to the live store.
    pub const fn mission_authority(&self) -> NodeId {
        self.mission_authority
    }

    pub async fn publish(
        &self,
        request: EventPublishRequest,
    ) -> Result<EventPublishResult, ApplicationError> {
        self.publish_with_options(request, EventPublishOptions::durable())
            .await
    }

    /// Publishes with an explicit durable or finite-TTL custody policy.
    pub async fn publish_with_options(
        &self,
        request: EventPublishRequest,
        options: EventPublishOptions,
    ) -> Result<EventPublishResult, ApplicationError> {
        let (response, received) = oneshot::channel();
        self.send(
            SelectedEventCommand::Publish {
                request,
                options,
                response,
            },
            received,
            "publish",
        )
        .await
    }

    pub async fn begin_publication_session(
        &self,
        client_id: EventClientId,
        expected_session: u64,
        claim_nonce: Vec<u8>,
    ) -> Result<EventRecoverySnapshot, ApplicationError> {
        let (response, received) = oneshot::channel();
        self.send(
            SelectedEventCommand::BeginPublicationSession {
                client_id,
                expected_session,
                claim_nonce,
                response,
            },
            received,
            "begin_publication_session",
        )
        .await
    }

    pub async fn complete_publication_recovery(
        &self,
        client_id: EventClientId,
        session: EventPublicationSession,
        snapshot_revision: u64,
    ) -> Result<(), ApplicationError> {
        let (response, received) = oneshot::channel();
        self.send(
            SelectedEventCommand::CompletePublicationRecovery {
                client_id,
                session,
                snapshot_revision,
                response,
            },
            received,
            "complete_publication_recovery",
        )
        .await
    }

    pub async fn publish_numbered(
        &self,
        request: NumberedEventPublishRequest,
        options: EventPublishOptions,
    ) -> Result<NumberedEventPublishOutcome, ApplicationError> {
        let (response, received) = oneshot::channel();
        self.send(
            SelectedEventCommand::PublishNumbered {
                request,
                options,
                response,
            },
            received,
            "publish_numbered",
        )
        .await
    }

    pub async fn abandon_publication(
        &self,
        client_id: EventClientId,
        session: EventPublicationSession,
        sequence: EventOperationSequence,
    ) -> Result<EventOperationAbandonment, ApplicationError> {
        let (response, received) = oneshot::channel();
        self.send(
            SelectedEventCommand::AbandonPublication {
                client_id,
                session,
                sequence,
                response,
            },
            received,
            "abandon_publication",
        )
        .await
    }

    pub async fn acknowledge_publication_result(
        &self,
        client_id: EventClientId,
        session: EventPublicationSession,
        sequence: EventOperationSequence,
    ) -> Result<EventResultAcknowledgement, ApplicationError> {
        let (response, received) = oneshot::channel();
        self.send(
            SelectedEventCommand::AcknowledgePublicationResult {
                client_id,
                session,
                sequence,
                response,
            },
            received,
            "acknowledge_publication_result",
        )
        .await
    }

    pub async fn query(&self, query: EventQuery) -> Result<EventQueryPage, ApplicationError> {
        let (response, received) = oneshot::channel();
        self.send(
            SelectedEventCommand::Query { query, response },
            received,
            "query",
        )
        .await
    }

    pub async fn subscribe(
        &self,
        request: EventSubscriptionRequest,
    ) -> Result<EventSubscription, ApplicationError> {
        let (response, received) = oneshot::channel();
        self.send(
            SelectedEventCommand::Subscribe { request, response },
            received,
            "subscribe",
        )
        .await
    }

    pub async fn poll(
        &self,
        request: EventPollRequest,
    ) -> Result<EventDeliveryPage, ApplicationError> {
        let (response, received) = oneshot::channel();
        self.send(
            SelectedEventCommand::Poll { request, response },
            received,
            "poll",
        )
        .await
    }

    pub async fn acknowledge(
        &self,
        subscription: EventSubscriptionId,
        event: EventId,
    ) -> Result<EventAcknowledgement, ApplicationError> {
        let (response, received) = oneshot::channel();
        self.send(
            SelectedEventCommand::Acknowledge {
                subscription,
                event,
                response,
            },
            received,
            "acknowledge",
        )
        .await
    }

    pub async fn unsubscribe(
        &self,
        subscription: EventSubscriptionId,
    ) -> Result<EventUnsubscribe, ApplicationError> {
        let (response, received) = oneshot::channel();
        self.send(
            SelectedEventCommand::Unsubscribe {
                subscription,
                response,
            },
            received,
            "unsubscribe",
        )
        .await
    }

    pub async fn gaps(&self, query: EventGapQuery) -> Result<EventGapPage, ApplicationError> {
        let (response, received) = oneshot::channel();
        self.send(
            SelectedEventCommand::Gaps { query, response },
            received,
            "gaps",
        )
        .await
    }

    pub async fn status(&self) -> Result<SelectedEventStatus, ApplicationError> {
        let (response, received) = oneshot::channel();
        self.send(
            SelectedEventCommand::Status { response },
            received,
            "status",
        )
        .await
    }

    async fn send<T>(
        &self,
        command: SelectedEventCommand,
        received: oneshot::Receiver<Result<T, ApplicationError>>,
        operation: &'static str,
    ) -> Result<T, ApplicationError> {
        if !self.admission.load(Ordering::Acquire) {
            return Err(actor_unavailable(operation));
        }
        self.commands
            .send(SelectedApplicationCommand::Event(command))
            .await
            .map_err(|_| actor_unavailable(operation))?;
        received.await.map_err(|_| actor_unavailable(operation))?
    }
}

pub(crate) fn actor_unavailable(operation: &'static str) -> ApplicationError {
    ApplicationError::new(ApplicationErrorKind::StateUnavailable, operation)
}

pub(crate) enum SelectedEventCommand {
    Publish {
        request: EventPublishRequest,
        options: EventPublishOptions,
        response: oneshot::Sender<Result<EventPublishResult, ApplicationError>>,
    },
    BeginPublicationSession {
        client_id: EventClientId,
        expected_session: u64,
        claim_nonce: Vec<u8>,
        response: oneshot::Sender<Result<EventRecoverySnapshot, ApplicationError>>,
    },
    CompletePublicationRecovery {
        client_id: EventClientId,
        session: EventPublicationSession,
        snapshot_revision: u64,
        response: oneshot::Sender<Result<(), ApplicationError>>,
    },
    PublishNumbered {
        request: NumberedEventPublishRequest,
        options: EventPublishOptions,
        response: oneshot::Sender<Result<NumberedEventPublishOutcome, ApplicationError>>,
    },
    AbandonPublication {
        client_id: EventClientId,
        session: EventPublicationSession,
        sequence: EventOperationSequence,
        response: oneshot::Sender<Result<EventOperationAbandonment, ApplicationError>>,
    },
    AcknowledgePublicationResult {
        client_id: EventClientId,
        session: EventPublicationSession,
        sequence: EventOperationSequence,
        response: oneshot::Sender<Result<EventResultAcknowledgement, ApplicationError>>,
    },
    Query {
        query: EventQuery,
        response: oneshot::Sender<Result<EventQueryPage, ApplicationError>>,
    },
    Subscribe {
        request: EventSubscriptionRequest,
        response: oneshot::Sender<Result<EventSubscription, ApplicationError>>,
    },
    Poll {
        request: EventPollRequest,
        response: oneshot::Sender<Result<EventDeliveryPage, ApplicationError>>,
    },
    Acknowledge {
        subscription: EventSubscriptionId,
        event: EventId,
        response: oneshot::Sender<Result<EventAcknowledgement, ApplicationError>>,
    },
    Unsubscribe {
        subscription: EventSubscriptionId,
        response: oneshot::Sender<Result<EventUnsubscribe, ApplicationError>>,
    },
    Gaps {
        query: EventGapQuery,
        response: oneshot::Sender<Result<EventGapPage, ApplicationError>>,
    },
    Status {
        response: oneshot::Sender<Result<SelectedEventStatus, ApplicationError>>,
    },
}

impl SelectedEventCommand {
    pub(crate) const fn mutates_selectors(&self) -> bool {
        matches!(self, Self::Subscribe { .. } | Self::Unsubscribe { .. })
    }

    pub(crate) fn reject(self) {
        match self {
            Self::Publish { response, .. } => {
                _ = response.send(Err(actor_unavailable("publish")));
            }
            Self::BeginPublicationSession { response, .. } => {
                _ = response.send(Err(actor_unavailable("begin_publication_session")));
            }
            Self::CompletePublicationRecovery { response, .. } => {
                _ = response.send(Err(actor_unavailable("complete_publication_recovery")));
            }
            Self::PublishNumbered { response, .. } => {
                _ = response.send(Err(actor_unavailable("publish_numbered")));
            }
            Self::AbandonPublication { response, .. } => {
                _ = response.send(Err(actor_unavailable("abandon_publication")));
            }
            Self::AcknowledgePublicationResult { response, .. } => {
                _ = response.send(Err(actor_unavailable("acknowledge_publication_result")));
            }
            Self::Query { response, .. } => _ = response.send(Err(actor_unavailable("query"))),
            Self::Subscribe { response, .. } => {
                _ = response.send(Err(actor_unavailable("subscribe")));
            }
            Self::Poll { response, .. } => _ = response.send(Err(actor_unavailable("poll"))),
            Self::Acknowledge { response, .. } => {
                _ = response.send(Err(actor_unavailable("acknowledge")));
            }
            Self::Unsubscribe { response, .. } => {
                _ = response.send(Err(actor_unavailable("unsubscribe")));
            }
            Self::Gaps { response, .. } => _ = response.send(Err(actor_unavailable("gaps"))),
            Self::Status { response } => _ = response.send(Err(actor_unavailable("status"))),
        }
    }
}

/// One bounded high-level application command owned by the running node actor.
///
/// The wrapper keeps Event, State, Record, and Blob operations on one admission and
/// fairness lane. Event, State, and Record subscription changes execute while
/// holding the actor's selector-write lease. Blob commands are handed to the
/// separate joined worker, where selector changes replay current policy and
/// commit under the Store's exact policy transaction instead of relying on an
/// enqueue-only outer lease. Plaintext operations for every class remain
/// behind the same mission-bound store authority.
pub(crate) enum SelectedApplicationCommand {
    Event(SelectedEventCommand),
    State(SelectedStateCommand),
    Record(SelectedRecordCommand),
    Blob(SelectedBlobCommand),
}

impl SelectedApplicationCommand {
    pub(crate) const fn mutates_selectors(&self) -> bool {
        match self {
            Self::Event(command) => command.mutates_selectors(),
            Self::State(command) => command.mutates_selectors(),
            Self::Record(command) => command.mutates_selectors(),
            Self::Blob(_) => false,
        }
    }

    pub(crate) fn reject(self) {
        match self {
            Self::Event(command) => command.reject(),
            Self::State(command) => command.reject(),
            Self::Record(command) => command.reject(),
            Self::Blob(command) => command.reject(),
        }
    }
}

enum VerifiedSubscriptionCandidate {
    Inactive(EventSemanticId),
    NotSelected,
    Delivery(
        EventSemanticId,
        aster_redb_store::EventTransferId,
        bool,
        Box<EventItem>,
    ),
}

/// Exclusive high-level handle over the selected Event composition.
///
/// This stopped-state handle owns the same exact redb writer lock as the mesh
/// runtime, so a second process cannot mutate or query around its policy
/// snapshot. While the runtime is active, `SelectedEventHandle` reaches this
/// same authority only through its bounded actor.
pub struct SelectedEventNode {
    mission: UnprotectedReferenceMission,
    store: Arc<Store>,
    verifier: ReferenceEnvelopeSealer,
    verifier_head: Option<(u64, ControlTransferId)>,
    custody_clock: NodeCustodyClock,
    event_route_cache: Arc<AuthenticatedEventRouteCache>,
    operation_retirement_quarantined: bool,
}

impl SelectedEventNode {
    /// Opens the current explicitly unprotected reference provisioning path.
    ///
    /// Relative state and mission paths are bound to one current-directory
    /// snapshot before terminal inspection; this lexical binding does not read
    /// mission bytes. Terminal state is rejected before mission bytes are
    /// loaded. The mission authority is then bound to the exact no-follow redb
    /// file, all committed controls are freshly replayed, and pending control
    /// gaps defer use.
    pub fn open_unprotected_reference(
        state: impl AsRef<Path>,
        mission_bundle: impl AsRef<Path>,
    ) -> Result<Self, ApplicationError> {
        let path_base =
            std::env::current_dir().map_err(|error| application_error("open", error.into()))?;
        let state = absolute_path_from(&path_base, state.as_ref())
            .map_err(|error| application_error("open", error))?;
        let mission_bundle = absolute_path_from(&path_base, mission_bundle.as_ref())
            .map_err(|error| application_error("open", error))?;
        Self::open_with_mission(&state, || {
            UnprotectedReferenceMission::load(&mission_bundle)
                .map_err(|error| application_error("open", error.into()))
        })
    }

    /// Opens one provider-protected reference provisioning artifact.
    ///
    /// Relative state and protected paths are bound to one current-directory
    /// snapshot without inspecting the artifact. Durable terminal state is
    /// rejected before the protected file is inspected or the provider is
    /// called. Provider rejection never falls back to the unprotected reference
    /// parser, and durable application state is not created until the artifact
    /// has authenticated and parsed.
    pub fn open_protected<P>(
        state: impl AsRef<Path>,
        protected_mission_bundle: impl AsRef<Path>,
        unprotector: &mut P,
    ) -> Result<Self, ApplicationError>
    where
        P: ProvisioningUnprotector + ?Sized,
    {
        let path_base =
            std::env::current_dir().map_err(|error| application_error("open", error.into()))?;
        let state = absolute_path_from(&path_base, state.as_ref())
            .map_err(|error| application_error("open", error))?;
        let protected_mission_bundle =
            absolute_path_from(&path_base, protected_mission_bundle.as_ref())
                .map_err(|error| application_error("open", error))?;
        Self::open_with_mission(&state, || {
            UnprotectedReferenceMission::load_protected(&protected_mission_bundle, unprotector)
                .map_err(|error| application_error("open", error.into()))
        })
    }

    /// Opens provider-protected reference provisioning bytes supplied by the
    /// embedding application.
    ///
    /// Durable terminal state is rejected before the provider is called.
    /// Provider failure occurs before state-directory or store creation and
    /// never falls back to treating `protected` as canonical plaintext.
    pub fn from_protected_bytes<P>(
        state: impl AsRef<Path>,
        protected: &[u8],
        unprotector: &mut P,
    ) -> Result<Self, ApplicationError>
    where
        P: ProvisioningUnprotector + ?Sized,
    {
        let state = state.as_ref();
        Self::open_with_mission(state, || {
            UnprotectedReferenceMission::from_protected_bytes(protected, unprotector)
                .map_err(|error| application_error("open", error.into()))
        })
    }

    /// Opens one authenticated opaque reference to a provider-persisted
    /// provisioning secret.
    ///
    /// Durable terminal state is rejected before the loader is called. The
    /// returned load receipt must bind the exact caller-selected operation and
    /// reference, and rejection occurs before state-directory or store
    /// creation.
    pub fn open_secret_ref<L>(
        state: impl AsRef<Path>,
        secret_ref: &ProvisioningSecretRef,
        operation: ProvisioningLoadId,
        loader: &mut L,
    ) -> Result<Self, ApplicationError>
    where
        L: ProvisioningSecretLoader + ?Sized,
    {
        let state = state.as_ref();
        Self::open_with_mission(state, || {
            UnprotectedReferenceMission::load_from_secret_store(secret_ref, operation, loader)
                .map_err(|error| application_error("open", error.into()))
        })
    }

    fn open_with_mission<F>(state: &Path, load_mission: F) -> Result<Self, ApplicationError>
    where
        F: FnOnce() -> Result<UnprotectedReferenceMission, ApplicationError>,
    {
        let state = absolute_state_path(state).map_err(|error| application_error("open", error))?;
        ensure_state_accepts_normal_operation(&state)
            .map_err(|error| application_error("open", error))?;
        let mission = load_mission()?;
        fs::create_dir_all(&state).map_err(|error| application_error("open", error.into()))?;
        let store = Store::open_for_mission(state.join(STORE_FILE), mission.mission_authority_id())
            .map_err(|error| application_error("open", error.into()))?;
        store
            .require_process_exclusive_lock()
            .map_err(|error| application_error("open", error.into()))?;
        let StartupEventVerification {
            verifier,
            historical_verifier,
            cache: event_route_cache,
            policy,
        } = open_startup_event_verifier_and_cache(&store, &mission)
            .map_err(|error| application_error("open", error))?;
        ensure_principal_active(&store, verifier.identity())
            .map_err(|error| application_error("open", error))?;
        drop(historical_verifier);
        let verifier_head = store
            .control_head()
            .map_err(|error| application_error("open", error.into()))?;
        let custody_clock = NodeCustodyClock::open(verifier.identity())
            .map_err(|error| application_error("open", error))?;
        drive_custody_maintenance(&store, &custody_clock, &[])
            .map_err(|error| application_error("open", error))?;
        prune_authenticated_event_route_cache_to_sender_projection(
            &store,
            &policy,
            &verifier,
            Some(
                custody_clock
                    .sample()
                    .map_err(|error| application_error("open", error))?,
            ),
            &event_route_cache,
        )
        .map_err(|error| application_error("open", error))?;
        let mut selected = Self {
            mission,
            store: Arc::new(store),
            verifier,
            verifier_head,
            custody_clock,
            event_route_cache,
            operation_retirement_quarantined: false,
        };
        selected.current_policy("open")?;
        Ok(selected)
    }

    pub(crate) fn from_runtime(
        mission: UnprotectedReferenceMission,
        store: Arc<Store>,
        verifier: ReferenceEnvelopeSealer,
        verifier_head: Option<(u64, ControlTransferId)>,
        custody_clock: NodeCustodyClock,
        event_route_cache: Arc<AuthenticatedEventRouteCache>,
    ) -> Self {
        Self {
            mission,
            store,
            verifier,
            verifier_head,
            custody_clock,
            event_route_cache,
            operation_retirement_quarantined: false,
        }
    }

    pub(crate) fn quarantine_operation_retirement(&mut self) {
        self.operation_retirement_quarantined = true;
    }

    pub(crate) fn maintain_runtime_custody(
        &self,
        scope_quotas: &[CustodyQuota],
    ) -> Result<(), NodeError> {
        operation_audit_maintenance_result(
            self.operation_retirement_quarantined,
            drive_custody_maintenance(&self.store, &self.custody_clock, scope_quotas),
        )
    }

    pub(crate) fn refresh_runtime_policy(
        &mut self,
    ) -> Result<Option<ControlPolicySnapshot>, NodeError> {
        refresh_application_policy(
            &self.store,
            &self.mission,
            &mut self.verifier,
            &mut self.verifier_head,
        )
    }

    pub(crate) fn runtime_verifier_mut(&mut self) -> &mut ReferenceEnvelopeSealer {
        &mut self.verifier
    }

    /// Authenticated local publisher identity.
    pub fn identity(&self) -> NodeId {
        self.verifier.identity()
    }

    /// Stable mission authority bound to this store and provisioning artifact.
    pub const fn mission_authority(&self) -> NodeId {
        self.mission.mission_authority_id()
    }

    /// Performs one bounded expiry and quota-pressure maintenance pass.
    ///
    /// Live nodes run the same pass on their scheduler tick. Stopped
    /// applications can call this method to advance physical retirement even
    /// when no contacts or selected-data operations occur.
    pub fn maintain_custody(&self) -> Result<(), ApplicationError> {
        self.maintain_custody_for("maintain custody")
    }

    /// Idempotently creates one durable application-delivery subscription.
    ///
    /// The local selector is intersected with current mission route and
    /// content capabilities. It narrows what the node asks to receive and does
    /// not grant authority to receive, retain, or open an Event.
    pub fn subscribe(
        &mut self,
        request: EventSubscriptionRequest,
    ) -> Result<EventSubscription, ApplicationError> {
        let EventSubscriptionRequest {
            operation_key,
            topic,
            scope,
            include_descendant_scopes,
        } = request;
        let key = EventSubscriptionKey::new(operation_key)
            .map_err(|error| application_error("subscribe", error.into()))?;
        let policy = self.current_policy("subscribe")?;
        let epoch = self
            .store
            .active_scope_epoch(&scope)
            .map_err(|error| application_error("subscribe", error.into()))?
            .map_or(1, |(epoch, _)| epoch);
        if !self.verifier.can_route_event(&scope, epoch)
            || !self.verifier.can_open_event_content(&scope, &topic, epoch)
        {
            return Err(ApplicationError::new(
                ApplicationErrorKind::RequestRejected,
                "subscribe",
            ));
        }
        let outcome = self
            .store
            .create_event_subscription_with_policy(
                &policy,
                &key,
                EventSubscriptionSpec {
                    mode: EventSubscriptionMode::Consume,
                    topic,
                    scope,
                    include_descendant_scopes,
                },
            )
            .map_err(|error| application_error("subscribe", error.into()))?;
        Ok(EventSubscription {
            id: EventSubscriptionId::from_store(outcome.id),
            inserted: outcome.inserted,
        })
    }

    /// Polls one durable subscription with at-least-once delivery semantics.
    ///
    /// Every pending and newly accepted row in the bounded plan is freshly
    /// source-verified before the durable discovery cursor advances. Matching
    /// active rows are also content-verified. Attempts are incremented in the
    /// same commit that records delivery, so a crash before return repeats the
    /// Event with a larger attempt number until acknowledged.
    pub fn poll(
        &mut self,
        request: EventPollRequest,
    ) -> Result<EventDeliveryPage, ApplicationError> {
        self.maintain_custody_for("poll")?;
        let request = request.validate()?;
        for _ in 0..MAX_SELECTED_EVENT_PLAN_RETRIES {
            let policy = self.current_policy("poll")?;
            let plan = self
                .store
                .prepare_event_subscription_poll_with_policy(
                    &policy,
                    request.subscription.into_store(),
                    request.delivery_limit,
                    request.scan_limit,
                )
                .map_err(|error| application_error("poll", error.into()))?;
            let spec = plan.spec().clone();
            let mut selection = EventSubscriptionPollSelection::default();
            let mut opened = Vec::new();

            for candidate in plan.pending_candidates() {
                match self.verify_subscription_candidate(&spec, candidate.event.clone())? {
                    VerifiedSubscriptionCandidate::Inactive(id) => {
                        selection.inactive_pending.push(id);
                    }
                    VerifiedSubscriptionCandidate::Delivery(id, transfer_id, finite, event) => {
                        selection.deliveries.push(id);
                        opened.push((id, transfer_id, finite, event));
                    }
                    VerifiedSubscriptionCandidate::NotSelected => {
                        return Err(ApplicationError::new(
                            ApplicationErrorKind::Integrity,
                            "poll",
                        ));
                    }
                }
            }
            for candidate in plan.scanned_candidates() {
                match self.verify_subscription_candidate(&spec, candidate.clone())? {
                    VerifiedSubscriptionCandidate::Delivery(id, transfer_id, finite, event) => {
                        selection.deliveries.push(id);
                        opened.push((id, transfer_id, finite, event));
                    }
                    VerifiedSubscriptionCandidate::Inactive(_)
                    | VerifiedSubscriptionCandidate::NotSelected => {}
                }
            }

            let committed = match self
                .store
                .commit_event_subscription_poll_with_policy(&policy, &plan, &selection)
            {
                Ok(committed) => committed,
                Err(
                    StoreError::EventSubscriptionPlanChanged
                    | StoreError::EventSelectorRevisionChanged
                    | StoreError::ControlPolicyChanged
                    | StoreError::Custody(CustodyStoreError::PolicyChanged),
                ) => continue,
                Err(error) => return Err(application_error("poll", error.into())),
            };
            if committed.deliveries.len() != opened.len() {
                return Err(ApplicationError::new(
                    ApplicationErrorKind::Integrity,
                    "poll",
                ));
            }
            let mut deliveries = Vec::with_capacity(committed.deliveries.len());
            for (committed, (verified_id, transfer_id, finite, event)) in
                committed.deliveries.into_iter().zip(opened)
            {
                if committed.event.semantic_id != verified_id {
                    return Err(ApplicationError::new(
                        ApplicationErrorKind::Integrity,
                        "poll",
                    ));
                }
                if !self.transfer_is_custody_visible(transfer_id, finite, "poll")? {
                    continue;
                }
                deliveries.push(EventDelivery {
                    event: *event,
                    attempt: committed.attempt,
                });
            }
            return Ok(EventDeliveryPage {
                deliveries,
                has_more: committed.has_more,
            });
        }
        Err(ApplicationError::new(
            ApplicationErrorKind::PolicyUnsettled,
            "poll",
        ))
    }

    /// Idempotently acknowledges one semantic Event delivery.
    pub fn acknowledge(
        &mut self,
        subscription: EventSubscriptionId,
        event: EventId,
    ) -> Result<EventAcknowledgement, ApplicationError> {
        let policy = self.current_policy("acknowledge")?;
        match self
            .store
            .acknowledge_event_delivery_with_policy(
                &policy,
                subscription.into_store(),
                event.into_store(),
            )
            .map_err(|error| application_error("acknowledge", error.into()))?
        {
            StoreEventDeliveryAck::Acknowledged => Ok(EventAcknowledgement::Acknowledged),
            StoreEventDeliveryAck::AlreadyAcknowledged => {
                Ok(EventAcknowledgement::AlreadyAcknowledged)
            }
        }
    }

    /// Idempotently withdraws one durable receive selector and its delivery ledger.
    pub fn unsubscribe(
        &mut self,
        subscription: EventSubscriptionId,
    ) -> Result<EventUnsubscribe, ApplicationError> {
        let policy = self.current_policy("unsubscribe")?;
        let EventSubscriptionRemoveOutcome { removed, .. } = self
            .store
            .remove_event_subscription_with_policy(&policy, subscription.into_store())
            .map_err(|error| application_error("unsubscribe", error.into()))?;
        Ok(if removed {
            EventUnsubscribe::Removed
        } else {
            EventUnsubscribe::AlreadyAbsent
        })
    }

    /// Returns bounded, freshly authenticated gaps in one exact Event stream.
    ///
    /// The store's structural plan is not treated as authority: every retained
    /// anchor is source- and content-verified, and the exact plan is required
    /// again after verification before any gap is exposed.
    pub fn gaps(&mut self, query: EventGapQuery) -> Result<EventGapPage, ApplicationError> {
        self.maintain_custody_for("gaps")?;
        query.validate()?;
        let policy = self.current_policy("gaps")?;
        if self
            .store
            .is_control_principal_revoked(query.publisher)
            .map_err(|error| application_error("gaps", error.into()))?
        {
            return Err(ApplicationError::new(
                ApplicationErrorKind::UnauthorizedOrRevoked,
                "gaps",
            ));
        }
        let epoch = self
            .store
            .active_scope_epoch(&query.scope)
            .map_err(|error| application_error("gaps", error.into()))?
            .map_or(1, |(epoch, _)| epoch);
        if !self.verifier.can_route_event(&query.scope, epoch)
            || !self
                .verifier
                .can_open_event_content(&query.scope, &query.topic, epoch)
        {
            return Err(ApplicationError::new(
                ApplicationErrorKind::RequestRejected,
                "gaps",
            ));
        }

        let plan = self
            .store
            .prepare_event_gap_scan_with_policy(
                &policy,
                query.publisher,
                &query.topic,
                &query.scope,
                query.after_sequence,
                query.scan_limit,
            )
            .map_err(|error| application_error("gaps", error.into()))?;
        let gaps = self.verify_gap_plan(&query, &plan)?;
        self.store
            .require_event_gap_scan_plan_with_policy(&policy, &plan)
            .map_err(|error| application_error("gaps", error.into()))?;
        let has_more = plan.candidates().len() == query.scan_limit;
        Ok(EventGapPage {
            gaps,
            scanned_through_sequence: plan.scanned_through(),
            has_more,
        })
    }

    /// Durably publishes one arbitrary selected Event exactly once per operation key.
    pub fn publish(
        &mut self,
        request: EventPublishRequest,
    ) -> Result<EventPublishResult, ApplicationError> {
        self.publish_with_options(request, EventPublishOptions::durable())
    }

    /// Durably publishes with an explicit finite or durable custody lifetime.
    pub fn publish_with_options(
        &mut self,
        request: EventPublishRequest,
        options: EventPublishOptions,
    ) -> Result<EventPublishResult, ApplicationError> {
        if options.ttl_ms().is_some()
            && !request.tombstone
            && !self.custody_clock.supports_finite_ttl()
        {
            return Err(ApplicationError::new(
                ApplicationErrorKind::RequestRejected,
                "publish",
            ));
        }
        self.maintain_custody_for("publish")?;
        let custody_sample = Some(
            self.custody_clock
                .sample()
                .map_err(|error| application_error("publish", error))?,
        );
        let EventPublishRequest {
            operation_key,
            predecessor,
            topic,
            scope,
            priority,
            logical_key,
            payload,
            tombstone,
        } = request;
        let operation = EventOperationKey::new(operation_key)
            .map_err(|error| application_error("publish", error.into()))?;
        let predecessor = predecessor.map(EventId::into_store);
        let policy = self.current_policy("publish")?;
        let (stored, inserted) = publish_selected_event_once(
            &self.store,
            &policy,
            &mut self.verifier,
            SelectedEventPublish {
                operation: &operation,
                predecessor,
                topic: &topic,
                scope: &scope,
                priority,
                ttl_ms: options.ttl_ms(),
                custody_sample,
                logical_key: &logical_key,
                payload: &payload,
                tombstone,
            },
        )
        .map_err(|error| application_error("publish", error))?;
        cache_accepted_stored_event(&self.event_route_cache, &mut self.verifier, &stored)
            .map_err(|error| application_error("publish", error))?;
        Ok(EventPublishResult {
            id: EventId::from_store(stored.semantic_id),
            publisher: stored.header.stamp.dot.publisher,
            publisher_counter: stored.header.stamp.dot.counter,
            event_sequence: event_sequence(&stored, "publish")?,
            priority: stored.header.priority,
            ttl_ms: stored.header.ttl_ms,
            acceptance_marker: stored.acceptance_marker,
            inserted,
        })
    }

    pub fn begin_publication_session(
        &self,
        client_id: &EventClientId,
        expected_session: u64,
        claim_nonce: &[u8],
    ) -> Result<EventRecoverySnapshot, ApplicationError> {
        self.store
            .begin_event_publication_session(client_id, expected_session, claim_nonce)
            .map_err(|error| application_error("begin_publication_session", error.into()))
    }

    pub fn complete_publication_recovery(
        &self,
        client_id: &EventClientId,
        session: EventPublicationSession,
        snapshot_revision: u64,
    ) -> Result<(), ApplicationError> {
        self.store
            .complete_event_publication_recovery(client_id, session, snapshot_revision)
            .map_err(|error| application_error("complete_publication_recovery", error.into()))
    }

    pub fn abandon_publication(
        &self,
        client_id: &EventClientId,
        session: EventPublicationSession,
        sequence: EventOperationSequence,
    ) -> Result<EventOperationAbandonment, ApplicationError> {
        self.store
            .abandon_event_publication(client_id, session, sequence)
            .map_err(|error| application_error("abandon_publication", error.into()))
    }

    pub fn acknowledge_publication_result(
        &self,
        client_id: &EventClientId,
        session: EventPublicationSession,
        sequence: EventOperationSequence,
    ) -> Result<EventResultAcknowledgement, ApplicationError> {
        self.store
            .acknowledge_event_publication_result(client_id, session, sequence)
            .map_err(|error| application_error("acknowledge_publication_result", error.into()))
    }

    pub fn publish_numbered(
        &mut self,
        request: NumberedEventPublishRequest,
        options: EventPublishOptions,
    ) -> Result<NumberedEventPublishOutcome, ApplicationError> {
        if options.ttl_ms().is_some()
            && !request.tombstone
            && !self.custody_clock.supports_finite_ttl()
        {
            return Err(ApplicationError::new(
                ApplicationErrorKind::RequestRejected,
                "publish_numbered",
            ));
        }
        self.maintain_custody_for("publish_numbered")?;
        let custody_sample = Some(
            self.custody_clock
                .sample()
                .map_err(|error| application_error("publish_numbered", error))?,
        );
        let policy = self.current_policy("publish_numbered")?;
        let outcome = crate::runtime::publish_selected_numbered_event_once(
            &self.store,
            &policy,
            &mut self.verifier,
            request,
            options,
            custody_sample,
        )
        .map_err(|error| application_error("publish_numbered", error))?;
        if let Some(StoredEventTransfer::Accepted(stored)) = self
            .store
            .get_transfer_with_policy(&policy, outcome.result.receipt.transfer_id)
            .map_err(|error| application_error("publish_numbered", error.into()))?
        {
            cache_accepted_stored_event(&self.event_route_cache, &mut self.verifier, &stored)
                .map_err(|error| application_error("publish_numbered", error))?;
        }
        Ok(outcome)
    }

    /// Returns one bounded marker-ordered page of active, content-verified Events.
    pub fn query(&mut self, query: EventQuery) -> Result<EventQueryPage, ApplicationError> {
        self.maintain_custody_for("query")?;
        query.validate()?;
        let policy = self.current_policy("query")?;
        // Retained metadata only narrows the candidate set. Each candidate is
        // still freshly authenticated and checked against these filters below.
        let filter = EventQueryFilter {
            publisher: query.publisher,
            topic: query.topic.clone(),
            scope: query.scope.clone(),
            logical_key: query.logical_key.clone(),
            include_descendant_scopes: query.include_descendant_scopes,
        };
        let candidates = self
            .store
            .query_event_candidates_with_policy(
                &policy,
                &filter,
                query.after_acceptance_marker,
                query.limit,
            )
            .map_err(|error| application_error("query", error.into()))?;
        let mut items = Vec::with_capacity(candidates.events.len());
        for event in candidates.events {
            if let Some(item) = self.open_application_event(&query, event)? {
                items.push(item);
            }
        }
        Ok(EventQueryPage {
            items,
            scanned_through: candidates.scanned_through,
            has_more: candidates.has_more,
        })
    }

    pub(crate) fn runtime_policy_for_status(
        &mut self,
    ) -> Result<EventReplicationPolicySnapshot, ApplicationError> {
        let policy = self.current_policy("status")?;
        let replication = self
            .store
            .event_replication_policy_snapshot()
            .map_err(|error| application_error("status", error.into()))?;
        if replication.control_policy() != &policy {
            return Err(ApplicationError::new(
                ApplicationErrorKind::PolicyUnsettled,
                "status",
            ));
        }
        Ok(replication)
    }

    fn maintain_custody_for(&self, operation: &'static str) -> Result<(), ApplicationError> {
        self.maintain_runtime_custody(&[])
            .map_err(|error| application_error(operation, error))
    }

    fn verify_gap_plan(
        &mut self,
        query: &EventGapQuery,
        plan: &EventGapScanPlan,
    ) -> Result<Vec<EventGap>, ApplicationError> {
        if plan.publisher() != query.publisher
            || plan.topic() != &query.topic
            || plan.scope() != &query.scope
            || plan.after_sequence() != query.after_sequence
            || plan.scan_limit() != query.scan_limit
            || plan.candidates().len() > query.scan_limit
            || (plan.has_more() && plan.candidates().len() != query.scan_limit)
        {
            return Err(ApplicationError::new(
                ApplicationErrorKind::Integrity,
                "gaps",
            ));
        }

        let mut gaps = Vec::new();
        let mut expected = query.after_sequence.checked_add(1);
        let mut structural_previous = query.after_sequence;
        for candidate in plan.candidates() {
            let sequence = candidate.sequence();
            if sequence <= structural_previous {
                return Err(ApplicationError::new(
                    ApplicationErrorKind::Integrity,
                    "gaps",
                ));
            }
            structural_previous = sequence;
            let stored = candidate.event();
            let route_verified = self
                .verifier
                .verify_event(&stored.sealed)
                .map_err(|error| application_error("gaps", error.into()))?;
            verify_stored_claim(
                &route_verified,
                stored.transfer_id,
                stored.semantic_id,
                &stored.header,
            )
            .map_err(|error| application_error("gaps", error))?;
            if stored.header.stamp.dot.publisher != query.publisher
                || stored.header.topic != query.topic
                || stored.header.scope != query.scope
                || event_sequence(stored, "gaps")? != sequence
            {
                return Err(ApplicationError::new(
                    ApplicationErrorKind::Integrity,
                    "gaps",
                ));
            }
            if event_is_inactive(&self.store, &route_verified)
                .map_err(|error| application_error("gaps", error))?
            {
                continue;
            }
            if !self.event_is_custody_visible(stored.transfer_id, &route_verified, "gaps")? {
                continue;
            }
            match self
                .verifier
                .verify_event_content(route_verified, &stored.sealed)
                .map_err(|error| application_error("gaps", error.into()))?
            {
                EventContentVerification::ContentVerified { event, .. } => {
                    verify_content_stored_claim(&event, stored)
                        .map_err(|error| application_error("gaps", error))?;
                }
                EventContentVerification::RouteOnly(_) => {
                    return Err(ApplicationError::new(
                        ApplicationErrorKind::RequestRejected,
                        "gaps",
                    ));
                }
            }
            if !self.transfer_is_custody_visible(
                stored.transfer_id,
                stored.header.ttl_ms.is_some() && !stored.header.tombstone,
                "gaps",
            )? {
                continue;
            }
            if let Some(start_sequence) = expected
                && start_sequence < sequence
            {
                gaps.push(EventGap {
                    publisher: query.publisher,
                    topic: query.topic.clone(),
                    scope: query.scope.clone(),
                    start_sequence,
                    end_sequence: sequence,
                });
            }
            expected = sequence.checked_add(1);
        }
        if structural_previous != plan.scanned_through()
            || (!plan.candidates().is_empty() && plan.scanned_through() > plan.high_water())
        {
            return Err(ApplicationError::new(
                ApplicationErrorKind::Integrity,
                "gaps",
            ));
        }
        Ok(gaps)
    }

    fn verify_subscription_candidate(
        &mut self,
        spec: &EventSubscriptionSpec,
        stored: StoredEvent,
    ) -> Result<VerifiedSubscriptionCandidate, ApplicationError> {
        let route_verified = self
            .verifier
            .verify_event(&stored.sealed)
            .map_err(|error| application_error("poll", error.into()))?;
        let finite = route_verified.ttl_ms().is_some() && !route_verified.tombstone();
        verify_stored_claim(
            &route_verified,
            stored.transfer_id,
            stored.semantic_id,
            &stored.header,
        )
        .map_err(|error| application_error("poll", error))?;
        if event_is_inactive(&self.store, &route_verified)
            .map_err(|error| application_error("poll", error))?
        {
            return Ok(VerifiedSubscriptionCandidate::Inactive(stored.semantic_id));
        }
        // Custody visibility is rechecked only after the exact poll-plan
        // commit below. The store's `inactive_pending` class is reserved for
        // epoch/revocation policy; misclassifying an expired row there would
        // make the authenticated selection disagree forever. A finite row may
        // therefore acquire a pending attempt, but plaintext is withheld if
        // age reaches TTL before final exposure.
        let matches = spec.topic == stored.header.topic
            && if spec.include_descendant_scopes {
                spec.scope.contains(&stored.header.scope)
            } else {
                spec.scope == stored.header.scope
            };
        if !matches {
            return Ok(VerifiedSubscriptionCandidate::NotSelected);
        }
        let payload = match self
            .verifier
            .verify_event_content(route_verified, &stored.sealed)
            .map_err(|error| application_error("poll", error.into()))?
        {
            EventContentVerification::ContentVerified { event, payload } => {
                verify_content_stored_claim(&event, &stored)
                    .map_err(|error| application_error("poll", error))?;
                payload
            }
            EventContentVerification::RouteOnly(_) => {
                return Err(ApplicationError::new(
                    ApplicationErrorKind::Integrity,
                    "poll",
                ));
            }
        };
        let id = stored.semantic_id;
        Ok(VerifiedSubscriptionCandidate::Delivery(
            id,
            stored.transfer_id,
            finite,
            Box::new(EventItem {
                id: EventId::from_store(id),
                publisher: stored.header.stamp.dot.publisher,
                publisher_counter: stored.header.stamp.dot.counter,
                event_sequence: event_sequence(&stored, "poll")?,
                topic: stored.header.topic,
                scope: stored.header.scope,
                priority: stored.header.priority,
                ttl_ms: stored.header.ttl_ms,
                logical_key: stored.header.logical_key,
                payload,
                tombstone: stored.header.tombstone,
                acceptance_marker: stored.acceptance_marker,
            }),
        ))
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

    fn open_application_event(
        &mut self,
        query: &EventQuery,
        stored: StoredEvent,
    ) -> Result<Option<EventItem>, ApplicationError> {
        let route_verified = self
            .verifier
            .verify_event(&stored.sealed)
            .map_err(|error| application_error("query", error.into()))?;
        let finite = route_verified.ttl_ms().is_some() && !route_verified.tombstone();
        verify_stored_claim(
            &route_verified,
            stored.transfer_id,
            stored.semantic_id,
            &stored.header,
        )
        .map_err(|error| application_error("query", error))?;
        if !query.matches_verified(&stored) {
            return Ok(None);
        }
        if event_is_inactive(&self.store, &route_verified)
            .map_err(|error| application_error("query", error))?
        {
            return Ok(None);
        }
        if !self.event_is_custody_visible(stored.transfer_id, &route_verified, "query")? {
            return Ok(None);
        }
        let payload = match self
            .verifier
            .verify_event_content(route_verified, &stored.sealed)
            .map_err(|error| application_error("query", error.into()))?
        {
            EventContentVerification::ContentVerified { event, payload } => {
                verify_content_stored_claim(&event, &stored)
                    .map_err(|error| application_error("query", error))?;
                payload
            }
            EventContentVerification::RouteOnly(_) => {
                return Err(ApplicationError::new(
                    ApplicationErrorKind::Integrity,
                    "query",
                ));
            }
        };
        if !self.transfer_is_custody_visible(stored.transfer_id, finite, "query")? {
            return Ok(None);
        }
        Ok(Some(EventItem {
            id: EventId::from_store(stored.semantic_id),
            publisher: stored.header.stamp.dot.publisher,
            publisher_counter: stored.header.stamp.dot.counter,
            event_sequence: event_sequence(&stored, "query")?,
            topic: stored.header.topic,
            scope: stored.header.scope,
            priority: stored.header.priority,
            ttl_ms: stored.header.ttl_ms,
            logical_key: stored.header.logical_key,
            payload,
            tombstone: stored.header.tombstone,
            acceptance_marker: stored.acceptance_marker,
        }))
    }

    fn event_is_custody_visible(
        &self,
        transfer_id: aster_redb_store::EventTransferId,
        event: &aster_mesh::RouteVerifiedEventEnvelope,
        operation: &'static str,
    ) -> Result<bool, ApplicationError> {
        self.transfer_is_custody_visible(
            transfer_id,
            event.ttl_ms().is_some() && !event.tombstone(),
            operation,
        )
    }

    fn transfer_is_custody_visible(
        &self,
        transfer_id: aster_redb_store::EventTransferId,
        finite: bool,
        operation: &'static str,
    ) -> Result<bool, ApplicationError> {
        let sample = if finite {
            if !self.custody_clock.supports_finite_ttl() {
                return Ok(false);
            }
            Some(
                self.custody_clock
                    .sample()
                    .map_err(|error| application_error(operation, error))?,
            )
        } else {
            None
        };
        let status = self
            .store
            .custody_sender_status(CustodyObjectKey::event(transfer_id), sample)
            .map_err(|error| application_error(operation, error.into()))?;
        Ok(status.is_some_and(|status| status.is_sendable()))
    }
}

fn event_sequence(stored: &StoredEvent, operation: &'static str) -> Result<u64, ApplicationError> {
    stored
        .header
        .event_sequence
        .ok_or_else(|| ApplicationError::new(ApplicationErrorKind::Integrity, operation))
}

fn operation_audit_maintenance_result(
    quarantined: bool,
    result: Result<(), NodeError>,
) -> Result<(), NodeError> {
    match result {
        Err(NodeError::Store(StoreError::EventOperationRetirementInvariant(_))) if quarantined => {
            // The compaction transaction aborted. Retain the untrusted rows,
            // without repair; reads still enforce custody TTL/authorization.
            // Unrelated storage/security errors propagate unchanged.
            Ok(())
        }
        result => result,
    }
}

fn application_error(operation: &'static str, error: NodeError) -> ApplicationError {
    let kind = match error {
        NodeError::Configuration(_) => ApplicationErrorKind::InvalidRequest,
        NodeError::MissionProvisioning(_) => ApplicationErrorKind::Provisioning,
        NodeError::Revoked(_) => ApplicationErrorKind::UnauthorizedOrRevoked,
        NodeError::SourceEnvelope(_) if matches!(operation, "publish" | "publish_numbered") => {
            ApplicationErrorKind::RequestRejected
        }
        NodeError::SourceEnvelope(_) => ApplicationErrorKind::Integrity,
        NodeError::Store(error) => store_error_kind(&error),
        NodeError::EmissionPolicyChanged => ApplicationErrorKind::PolicyUnsettled,
        NodeError::CustodySendSkipped => ApplicationErrorKind::ExpiredOrRetired,
        NodeError::Protocol(message) if message == EVENT_OPERATION_CONFLICT => {
            ApplicationErrorKind::Conflict
        }
        NodeError::Protocol(message) if message == EVENT_OPERATION_RETIRED => {
            ApplicationErrorKind::ExpiredOrRetired
        }
        NodeError::Protocol(_) => ApplicationErrorKind::Integrity,
        NodeError::FatalBlobCoherence(_) => ApplicationErrorKind::StateUnavailable,
        NodeError::Identity(_)
        | NodeError::SoftwareErasure(_)
        | NodeError::Mission(_)
        | NodeError::Reconciliation(_)
        | NodeError::Carrier(_)
        | NodeError::Io(_)
        | NodeError::Demo(_) => ApplicationErrorKind::StateUnavailable,
    };
    ApplicationError::new(kind, operation)
}

pub(crate) fn runtime_application_error(
    operation: &'static str,
    error: NodeError,
) -> ApplicationError {
    application_error(operation, error)
}

fn store_error_kind(error: &StoreError) -> ApplicationErrorKind {
    match error {
        StoreError::NumberedEventOperation(error) => match error {
            NumberedEventOperationError::InvalidClientId
            | NumberedEventOperationError::InvalidClaimNonce
            | NumberedEventOperationError::InvalidSession
            | NumberedEventOperationError::InvalidSequence
            | NumberedEventOperationError::ClientNotFound
            | NumberedEventOperationError::ResultNotFound => ApplicationErrorKind::InvalidRequest,
            NumberedEventOperationError::SessionFenced => ApplicationErrorKind::SessionFenced,
            NumberedEventOperationError::IntentConflict => ApplicationErrorKind::Conflict,
            NumberedEventOperationError::SequenceRetired => ApplicationErrorKind::SequenceRetired,
            NumberedEventOperationError::RecoveryRequired
            | NumberedEventOperationError::RecoveryRevisionChanged => {
                ApplicationErrorKind::RecoveryRequired
            }
            NumberedEventOperationError::SequenceGap => ApplicationErrorKind::SequenceGap,
            NumberedEventOperationError::ClientLimitExceeded
            | NumberedEventOperationError::OutstandingLimitExceeded
            | NumberedEventOperationError::GlobalRecordLimitExceeded
            | NumberedEventOperationError::GlobalByteLimitExceeded
            | NumberedEventOperationError::RecoverySnapshotTooLarge => {
                ApplicationErrorKind::OperationCapacity
            }
            NumberedEventOperationError::SequenceExhausted
            | NumberedEventOperationError::SessionExhausted
            | NumberedEventOperationError::RevisionExhausted
            | NumberedEventOperationError::Invariant(_) => ApplicationErrorKind::StateUnavailable,
            NumberedEventOperationError::LegacyStoreRequiresFreshState
            | NumberedEventOperationError::LegacyOperationDisabled => {
                ApplicationErrorKind::LegacyState
            }
            _ => ApplicationErrorKind::StateUnavailable,
        },
        StoreError::EventOperationAuditCancelled => ApplicationErrorKind::StateUnavailable,
        StoreError::Blob(error) => blob_store_error_kind(error),
        // The bridge foundation has no selected application surface yet. Any
        // bridge-store error reaching this classifier is therefore an internal
        // integrity failure rather than a caller-actionable request result.
        StoreError::Bridge(_) => ApplicationErrorKind::Integrity,
        StoreError::Custody(error) => custody_store_error_kind(error),
        StoreError::InvalidEventOperationKey { .. }
        | StoreError::InvalidStateOperationKey { .. }
        | StoreError::InvalidRecordOperationKey { .. }
        | StoreError::InvalidEventSubscriptionKey { .. }
        | StoreError::InvalidStateSubscriptionKey { .. }
        | StoreError::InvalidRecordSubscriptionKey { .. }
        | StoreError::InvalidBlobSubscriptionKey { .. }
        | StoreError::EventPageLimitExceeded { .. }
        | StoreError::EventSubscriptionNotFound
        | StoreError::EventSubscriptionNotConsumable
        | StoreError::EventSubscriptionPollLimitExceeded { .. }
        | StoreError::EventDeliveryNotFound
        | StoreError::StateSubscriptionNotFound
        | StoreError::StateSubscriptionPollLimitExceeded { .. }
        | StoreError::StateDeliveryNotFound
        | StoreError::InvalidStateDeliveryToken
        | StoreError::StateDeliveryTokenBindingMismatch
        | StoreError::StateSubscriptionIncarnationChanged { .. }
        | StoreError::StateDeliveryTenureChanged { .. }
        | StoreError::StateDeliveryAttemptChanged { .. }
        | StoreError::RecordSubscriptionNotFound
        | StoreError::RecordSubscriptionPollLimitExceeded { .. }
        | StoreError::RecordDeliveryNotFound
        | StoreError::InvalidRecordDeliveryToken
        | StoreError::RecordDeliveryTokenBindingMismatch
        | StoreError::RecordSubscriptionIncarnationChanged { .. }
        | StoreError::RecordDeliveryTenureChanged { .. }
        | StoreError::RecordDeliveryAttemptChanged { .. }
        | StoreError::BlobSubscriptionNotFound
        | StoreError::BlobSubscriptionPollLimitExceeded { .. }
        | StoreError::BlobDeliveryNotFound
        | StoreError::InvalidBlobDeliveryToken
        | StoreError::BlobDeliveryTokenBindingMismatch
        | StoreError::BlobSubscriptionIncarnationChanged { .. }
        | StoreError::BlobDeliveryTenureChanged { .. }
        | StoreError::BlobDeliveryAttemptChanged { .. }
        | StoreError::EventReplicationNotSelected
        | StoreError::EventReplicationNotConsumable
        | StoreError::InvalidSemanticEvent(_)
        | StoreError::InvalidSemanticState(_)
        | StoreError::InvalidSemanticRecord(_)
        | StoreError::MutableTransferCursorPeerLimitExceeded { .. }
        | StoreError::AuthenticatedCustodyAgeRequired => ApplicationErrorKind::InvalidRequest,
        StoreError::EventPublisherRevoked(_)
        | StoreError::StatePublisherRevoked(_)
        | StoreError::RecordPublisherRevoked(_)
        | StoreError::EventKeyEpochStale { .. }
        | StoreError::EventKeyEpochNotActive { .. }
        | StoreError::StateKeyEpochStale { .. }
        | StoreError::StateKeyEpochNotActive { .. }
        | StoreError::RecordKeyEpochStale { .. }
        | StoreError::RecordKeyEpochNotActive { .. }
        | StoreError::MissionAuthorityMismatch { .. }
        | StoreError::ControlSignerRevoked(_)
        | StoreError::ControlAuthorityRevoked(_)
        | StoreError::ControlRecipientRevoked(_) => ApplicationErrorKind::UnauthorizedOrRevoked,
        StoreError::ControlPolicyUnsettled { .. }
        | StoreError::ControlRecipientMetadataMigrationRequired { .. }
        | StoreError::ControlPolicyChanged
        | StoreError::ReservationChanged
        | StoreError::StateReservationChanged
        | StoreError::RecordReservationChanged
        | StoreError::StateProjectionPlanChanged
        | StoreError::StateSubscriptionPlanChanged
        | StoreError::StateSelectorGenerationChanged
        | StoreError::RecordSubscriptionPlanChanged
        | StoreError::RecordSelectorGenerationChanged
        | StoreError::BlobSubscriptionPlanChanged
        | StoreError::BlobSelectorGenerationChanged
        | StoreError::EventSubscriptionPlanChanged
        | StoreError::EventGapScanPlanChanged
        | StoreError::EventSelectorRevisionChanged
        | StoreError::SecurityProfileMismatch { .. }
        | StoreError::SecurityPolicyGenerationRollback { .. }
        | StoreError::SecurityPolicyGenerationAdvanceRequired { .. } => {
            ApplicationErrorKind::PolicyUnsettled
        }
        StoreError::IdentityConflict { .. }
        | StoreError::SemanticRepresentationConflict { .. }
        | StoreError::StateRepresentationConflict { .. }
        | StoreError::RecordRepresentationConflict { .. }
        | StoreError::CausalEquivocation { .. }
        | StoreError::EventEquivocation { .. }
        | StoreError::MissingReactionPredecessor { .. }
        | StoreError::ReactionContextMissing { .. }
        | StoreError::OperationPredecessorMismatch
        | StoreError::EventOperationConflict
        | StoreError::StateOperationConflict
        | StoreError::RecordOperationConflict
        | StoreError::RecordConflictRequiresResolution
        | StoreError::RecordProjectionPlanChanged
        | StoreError::EventSubscriptionConflict
        | StoreError::StateSubscriptionConflict
        | StoreError::RecordSubscriptionConflict
        | StoreError::BlobSubscriptionConflict => ApplicationErrorKind::Conflict,
        StoreError::EventOperationLimitExceeded { .. }
        | StoreError::EventOperationByteLimitExceeded { .. }
        | StoreError::EventOperationMigrationAliasOverflow
        | StoreError::EventOperationMigrationDestinationCapacity => {
            ApplicationErrorKind::OperationCapacity
        }
        StoreError::ItemLimitExceeded { .. }
        | StoreError::StateProjectionLimitExceeded { .. }
        | StoreError::StateCausalFrontierLimitExceeded { .. }
        | StoreError::StateOperationLimitExceeded { .. }
        | StoreError::StateOperationByteLimitExceeded { .. }
        | StoreError::RecordProjectionLimitExceeded { .. }
        | StoreError::RecordCausalFrontierLimitExceeded { .. }
        | StoreError::RecordOperationLimitExceeded { .. }
        | StoreError::RecordOperationByteLimitExceeded { .. }
        | StoreError::EventSubscriptionLimitExceeded { .. }
        | StoreError::EventPendingDeliveryLimitExceeded { .. }
        | StoreError::EventAcknowledgementReceiptLimitExceeded { .. }
        | StoreError::EventDeliveryLedgerLimitExceeded { .. }
        | StoreError::EventDeliveryAttemptExhausted
        | StoreError::StateSubscriptionLimitExceeded { .. }
        | StoreError::StatePendingDeliveryLimitExceeded { .. }
        | StoreError::StateAcknowledgementReceiptLimitExceeded { .. }
        | StoreError::StateDeliveryLedgerLimitExceeded { .. }
        | StoreError::StateDeliveryAttemptExhausted
        | StoreError::StateDeliveryTenureExhausted
        | StoreError::RecordSubscriptionLimitExceeded { .. }
        | StoreError::RecordPendingDeliveryLimitExceeded { .. }
        | StoreError::RecordAcknowledgementReceiptLimitExceeded { .. }
        | StoreError::RecordDeliveryLedgerLimitExceeded { .. }
        | StoreError::RecordDeliveryAttemptExhausted
        | StoreError::RecordDeliveryTenureExhausted
        | StoreError::BlobSubscriptionLimitExceeded { .. }
        | StoreError::BlobPendingDeliveryLimitExceeded { .. }
        | StoreError::BlobAcknowledgementReceiptLimitExceeded { .. }
        | StoreError::BlobDeliveryLedgerLimitExceeded { .. }
        | StoreError::BlobDeliveryAttemptExhausted
        | StoreError::BlobDeliveryTenureExhausted
        | StoreError::PayloadByteLimitExceeded { .. }
        | StoreError::AcceptanceMarkerExhausted
        | StoreError::ItemCountAccountingOverflow
        | StoreError::PayloadByteAccountingOverflow
        | StoreError::RouteCacheItemLimitExceeded { .. }
        | StoreError::RouteCacheByteLimitExceeded { .. }
        | StoreError::RouteCacheSemanticRepresentationLimit { .. }
        | StoreError::MutableTransferCursorLimitExceeded { .. }
        | StoreError::ControlItemLimitExceeded { .. }
        | StoreError::ControlByteLimitExceeded { .. }
        | StoreError::ControlSequenceExhausted => ApplicationErrorKind::ResourceLimit,
        StoreError::Backend(_)
        | StoreError::StorePath(_)
        | StoreError::StoreBackingInvariant(_)
        | StoreError::MissionNotBound
        | StoreError::ProcessExclusiveLockUnavailable
        | StoreError::StoreInUse
        | StoreError::StoreZeroized(_) => ApplicationErrorKind::StateUnavailable,
        StoreError::SemanticVerification(_)
        | StoreError::EventOperationMigrationMissingMissionBinding
        | StoreError::EventOperationMigrationMissingAuthenticatedIntent
        | StoreError::EventOperationMigrationFingerprintCollision
        | StoreError::StateVerification(_)
        | StoreError::RecordVerification(_)
        | StoreError::MissingAcceptanceMarker { .. }
        | StoreError::OrphanedAcceptanceMarker { .. }
        | StoreError::InvalidStoredIdLength { .. }
        | StoreError::AccountingMismatch { .. }
        | StoreError::MissingAccountingMetadata { .. }
        | StoreError::SemanticInvariant(_)
        | StoreError::EventOperationRetirementInvariant(_)
        | StoreError::StateInvariant(_)
        | StoreError::RecordInvariant(_)
        | StoreError::BlobInvariant(_)
        | StoreError::SemanticNamespaceCollision { .. }
        | StoreError::ControlVerification(_)
        | StoreError::InvalidControl(_)
        | StoreError::ControlFork
        | StoreError::ControlRollback
        | StoreError::ControlReservationChanged
        | StoreError::ControlInvariant(_)
        | StoreError::InvalidControlPublicationIntent
        | StoreError::MissingControlPublicationIntent
        | StoreError::ControlPublicationIntentUnknown { .. }
        | StoreError::ControlPublicationIntentConflict { .. }
        | StoreError::TransferNamespaceCollision { .. }
        | StoreError::MutableTransferCursorInvariant(_)
        | StoreError::SecurityProfilePolicyInvariant(_)
        | StoreError::ZeroizationInvariant(_)
        | StoreError::InvalidZeroizationDescriptor { .. }
        | StoreError::ZeroizationIntentConflict
        | StoreError::ZeroizationOrderViolation(_) => ApplicationErrorKind::Integrity,
    }
}

fn custody_store_error_kind(error: &CustodyStoreError) -> ApplicationErrorKind {
    match error {
        CustodyStoreError::InvalidQuota
        | CustodyStoreError::InvalidAdmission(_)
        | CustodyStoreError::PageLimitExceeded { .. } => ApplicationErrorKind::InvalidRequest,
        CustodyStoreError::ContinuityUnavailable
        | CustodyStoreError::ContinuityLost
        | CustodyStoreError::Expired
        | CustodyStoreError::AlreadyRetired
        | CustodyStoreError::Retiring
        | CustodyStoreError::Protected => ApplicationErrorKind::RequestRejected,
        CustodyStoreError::RetryNotDue { .. } => ApplicationErrorKind::RequestRejected,
        CustodyStoreError::PolicyChanged | CustodyStoreError::ItemChanged => {
            ApplicationErrorKind::PolicyUnsettled
        }
        CustodyStoreError::LeaseLimitExceeded { .. }
        | CustodyStoreError::ReceiptLimitExceeded { .. }
        | CustodyStoreError::RetryLimitExceeded { .. }
        | CustodyStoreError::RetirementLimitExceeded { .. }
        | CustodyStoreError::QuotaLimitExceeded { .. }
        | CustodyStoreError::ItemQuotaExceeded { .. }
        | CustodyStoreError::ByteQuotaExceeded { .. } => ApplicationErrorKind::ResourceLimit,
        CustodyStoreError::MissionNotBound
        | CustodyStoreError::MissionMismatch
        | CustodyStoreError::ItemNotFound
        | CustodyStoreError::LeaseNotFound => ApplicationErrorKind::StateUnavailable,
        CustodyStoreError::AgeOverflow
        | CustodyStoreError::CounterOverflow
        | CustodyStoreError::UnsupportedRetirementClass(_)
        | CustodyStoreError::Invariant(_) => ApplicationErrorKind::Integrity,
    }
}

fn blob_store_error_kind(error: &BlobStoreError) -> ApplicationErrorKind {
    match error {
        BlobStoreError::InvalidDepotLimits
        | BlobStoreError::InvalidOperationKey { .. }
        | BlobStoreError::InvalidPublication(_)
        | BlobStoreError::InvalidCarrierObjectId
        | BlobStoreError::InvalidCarrierRange(_)
        | BlobStoreError::CarrierCursorPeerLimitExceeded { .. } => {
            ApplicationErrorKind::InvalidRequest
        }
        BlobStoreError::PublisherRevoked(_)
        | BlobStoreError::KeyEpochStale { .. }
        | BlobStoreError::KeyEpochNotActive { .. } => ApplicationErrorKind::UnauthorizedOrRevoked,
        BlobStoreError::ReservationChanged
        | BlobStoreError::ReadPlanChanged
        | BlobStoreError::PhysicalLineageMigrationRequired => ApplicationErrorKind::PolicyUnsettled,
        BlobStoreError::OperationConflict
        | BlobStoreError::PendingSourceConflict
        | BlobStoreError::CarrierPrefixConflict
        | BlobStoreError::PhysicalLineageConflict => ApplicationErrorKind::Conflict,
        BlobStoreError::PublicationLimitExceeded { .. }
        | BlobStoreError::CausalFrontierLimitExceeded { .. }
        | BlobStoreError::OperationLimitExceeded { .. }
        | BlobStoreError::OperationByteLimitExceeded { .. }
        | BlobStoreError::DepotByteLimitExceeded { .. }
        | BlobStoreError::DepotChunkLimitExceeded { .. }
        | BlobStoreError::DepotVariantLimitExceeded { .. }
        | BlobStoreError::NetworkSourceTooLarge { .. }
        | BlobStoreError::NetworkBlobTooLarge { .. }
        | BlobStoreError::NetworkStagingRowLimitExceeded { .. }
        | BlobStoreError::NetworkStagingByteLimitExceeded { .. } => {
            ApplicationErrorKind::ResourceLimit
        }
        BlobStoreError::PendingSourceMissing | BlobStoreError::Io(_) => {
            ApplicationErrorKind::StateUnavailable
        }
        BlobStoreError::Verification(_)
        | BlobStoreError::SchemaInvariant(_)
        | BlobStoreError::DepotIntegrity(_)
        | BlobStoreError::CompletionMismatch
        | BlobStoreError::CarrierCursorInvariant(_) => ApplicationErrorKind::Integrity,
    }
}

#[cfg(test)]
mod tests {
    use std::{
        fs,
        path::{Path, PathBuf},
        sync::atomic::{AtomicU64, Ordering},
    };

    use super::*;
    use aster_mesh::{
        ProvisioningAccess, ProvisioningLoadReceipt, ProvisioningProtectionError,
        ProvisioningSecretStoreError, ReferenceProvisioner, UnprotectedProvisioning,
    };

    static NEXT_ROOT: AtomicU64 = AtomicU64::new(0);

    #[test]
    fn mutable_cursor_and_frontier_store_errors_have_narrow_application_kinds() {
        for error in [
            StoreError::StateCausalFrontierLimitExceeded {
                current: 4_096,
                limit: 4_096,
            },
            StoreError::RecordCausalFrontierLimitExceeded {
                current: 4_096,
                limit: 4_096,
            },
            StoreError::MutableTransferCursorLimitExceeded {
                current: 1_024,
                limit: 1_024,
            },
        ] {
            assert_eq!(
                store_error_kind(&error),
                ApplicationErrorKind::ResourceLimit
            );
        }
        assert_eq!(
            store_error_kind(&StoreError::MutableTransferCursorPeerLimitExceeded {
                requested: 257,
                limit: 256,
            }),
            ApplicationErrorKind::InvalidRequest
        );
        assert_eq!(
            store_error_kind(&StoreError::MutableTransferCursorInvariant(
                "test integrity"
            )),
            ApplicationErrorKind::Integrity
        );
    }

    #[test]
    fn event_operation_capacity_has_a_distinct_application_kind() {
        for error in [
            StoreError::EventOperationLimitExceeded {
                current: 64,
                limit: 64,
            },
            StoreError::EventOperationMigrationAliasOverflow,
            StoreError::EventOperationMigrationDestinationCapacity,
            StoreError::EventOperationLimitExceeded {
                current: 4_096,
                limit: 4_096,
            },
            StoreError::EventOperationByteLimitExceeded {
                current: 524_200,
                incoming: 100,
                limit: 524_288,
            },
        ] {
            assert_eq!(
                store_error_kind(&error),
                ApplicationErrorKind::OperationCapacity
            );
        }
        assert_eq!(
            store_error_kind(&StoreError::ItemLimitExceeded {
                current: 10_000,
                limit: 10_000,
            }),
            ApplicationErrorKind::ResourceLimit
        );
        for error in [
            StoreError::EventOperationMigrationMissingMissionBinding,
            StoreError::EventOperationMigrationMissingAuthenticatedIntent,
            StoreError::EventOperationMigrationFingerprintCollision,
        ] {
            assert_eq!(store_error_kind(&error), ApplicationErrorKind::Integrity);
        }
    }

    #[test]
    fn operation_audit_maintenance_quarantine_is_narrow_and_requires_failure() {
        for quarantined in [false, true] {
            let ledger_error = StoreError::EventOperationRetirementInvariant(Box::new(
                StoreError::SemanticInvariant("ledger retirement"),
            ));
            assert_eq!(
                operation_audit_maintenance_result(quarantined, Err(ledger_error.into())).is_ok(),
                quarantined
            );
            for error in [
                StoreError::Backend(redb::Error::Io(std::io::Error::other("storage"))),
                StoreError::Custody(CustodyStoreError::Invariant("custody")),
                StoreError::ControlPolicyUnsettled { pending: 1 },
                StoreError::SemanticInvariant("outside ledger retirement"),
                StoreError::AccountingMismatch {
                    field: "outside ledger retirement",
                    durable: 1,
                    reconstructed: 0,
                },
            ] {
                assert!(
                    operation_audit_maintenance_result(quarantined, Err(error.into())).is_err()
                );
            }
        }
    }

    struct TestRoot(PathBuf);

    impl TestRoot {
        fn new(label: &str) -> Self {
            let sequence = NEXT_ROOT.fetch_add(1, Ordering::Relaxed);
            let path = std::env::temp_dir().join(format!(
                "aster-selected-event-{}-{sequence}-{label}",
                std::process::id()
            ));
            fs::create_dir(&path).expect("create test root");
            Self(path)
        }

        fn path(&self) -> &Path {
            &self.0
        }
    }

    impl Drop for TestRoot {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    struct CountingUnprotector {
        calls: usize,
        plaintext: Option<Vec<u8>>,
        reject: bool,
    }

    impl CountingUnprotector {
        fn accepting(plaintext: Vec<u8>) -> Self {
            Self {
                calls: 0,
                plaintext: Some(plaintext),
                reject: false,
            }
        }

        fn rejecting() -> Self {
            Self {
                calls: 0,
                plaintext: None,
                reject: true,
            }
        }
    }

    impl ProvisioningUnprotector for CountingUnprotector {
        fn unprotect(
            &mut self,
            _protected: &[u8],
            _maximum_plaintext_len: usize,
        ) -> Result<UnprotectedProvisioning, ProvisioningProtectionError> {
            self.calls += 1;
            if self.reject {
                return Err(ProvisioningProtectionError::Rejected);
            }
            UnprotectedProvisioning::new(
                self.plaintext
                    .take()
                    .ok_or(ProvisioningProtectionError::Unavailable)?,
            )
        }
    }

    struct CountingSecretLoader {
        calls: usize,
        expected_operation: ProvisioningLoadId,
        expected_ref: ProvisioningSecretRef,
        returned_operation: ProvisioningLoadId,
        returned_ref: ProvisioningSecretRef,
        plaintext: Option<Vec<u8>>,
    }

    impl ProvisioningSecretLoader for CountingSecretLoader {
        fn load(
            &mut self,
            operation: ProvisioningLoadId,
            secret_ref: &ProvisioningSecretRef,
        ) -> Result<ProvisioningLoadReceipt, ProvisioningSecretStoreError> {
            self.calls += 1;
            assert_eq!(operation, self.expected_operation);
            assert_eq!(secret_ref, &self.expected_ref);
            let plaintext = UnprotectedProvisioning::new(
                self.plaintext
                    .take()
                    .ok_or(ProvisioningSecretStoreError::Unavailable)?,
            )
            .map_err(|_| ProvisioningSecretStoreError::Rejected)?;
            Ok(ProvisioningLoadReceipt::new(
                self.returned_operation,
                self.returned_ref.clone(),
                plaintext,
            ))
        }
    }

    struct ChdirUnprotector {
        calls: usize,
        destination: PathBuf,
        expected_protected: Vec<u8>,
        plaintext: Option<Vec<u8>>,
    }

    impl ProvisioningUnprotector for ChdirUnprotector {
        fn unprotect(
            &mut self,
            protected: &[u8],
            _maximum_plaintext_len: usize,
        ) -> Result<UnprotectedProvisioning, ProvisioningProtectionError> {
            self.calls += 1;
            assert_eq!(protected, self.expected_protected);
            std::env::set_current_dir(&self.destination)
                .expect("provider changes the process current directory");
            UnprotectedProvisioning::new(
                self.plaintext
                    .take()
                    .ok_or(ProvisioningProtectionError::Unavailable)?,
            )
        }
    }

    struct ChdirPath {
        destination: PathBuf,
        relative: PathBuf,
    }

    impl AsRef<Path> for ChdirPath {
        fn as_ref(&self) -> &Path {
            std::env::set_current_dir(&self.destination)
                .expect("path callback changes the process current directory");
            &self.relative
        }
    }

    struct ChdirSecretLoader {
        calls: usize,
        destination: PathBuf,
        expected_operation: ProvisioningLoadId,
        expected_ref: ProvisioningSecretRef,
        plaintext: Option<Vec<u8>>,
    }

    impl ProvisioningSecretLoader for ChdirSecretLoader {
        fn load(
            &mut self,
            operation: ProvisioningLoadId,
            secret_ref: &ProvisioningSecretRef,
        ) -> Result<ProvisioningLoadReceipt, ProvisioningSecretStoreError> {
            self.calls += 1;
            assert_eq!(operation, self.expected_operation);
            assert_eq!(secret_ref, &self.expected_ref);
            std::env::set_current_dir(&self.destination)
                .expect("secret loader changes the process current directory");
            let plaintext = UnprotectedProvisioning::new(
                self.plaintext
                    .take()
                    .ok_or(ProvisioningSecretStoreError::Unavailable)?,
            )
            .map_err(|_| ProvisioningSecretStoreError::Rejected)?;
            Ok(ProvisioningLoadReceipt::new(
                operation,
                secret_ref.clone(),
                plaintext,
            ))
        }
    }

    fn run_isolated_cwd_test(test_name: &str, body: impl FnOnce()) {
        const CHILD_ENV: &str = "ASTER_SELECTED_EVENT_CWD_TEST_CHILD";
        if std::env::var_os(CHILD_ENV).as_deref() == Some(std::ffi::OsStr::new(test_name)) {
            body();
            return;
        }
        let output = std::process::Command::new(std::env::current_exe().expect("test binary"))
            .arg(test_name)
            .arg("--exact")
            .arg("--nocapture")
            .env(CHILD_ENV, test_name)
            .output()
            .expect("run isolated current-directory regression child");
        assert!(
            output.status.success(),
            "isolated current-directory regression failed\nstdout:\n{}\nstderr:\n{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr),
        );
    }

    fn selected_mission_bytes(seed: [u8; 32]) -> Vec<u8> {
        let scope = Scope::new("mission/apps").expect("scope");
        let alpha = Topic::new("ops.alpha").expect("topic");
        let beta = Topic::new("ops.beta").expect("topic");
        let access =
            ProvisioningAccess::member(scope, vec![1], vec![alpha, beta]).expect("member access");
        let mut provisioner = ReferenceProvisioner::from_seed(seed).expect("provisioner");
        provisioner
            .issue_node(1, &[access])
            .expect("issue node")
            .to_bytes()
            .expect("encode mission")
    }

    fn selected_node(root: &TestRoot) -> SelectedEventNode {
        let bytes = selected_mission_bytes([0x5a; 32]);
        let mission_path = root.path().join("mission.unprotected-reference.bundle");
        drop(
            UnprotectedReferenceMission::persist(&mission_path, bytes)
                .expect("persist owner-only mission"),
        );
        // Preserve the original load failure before the public API maps it to
        // a deliberately opaque provisioning error. Keep loading inside the
        // opener so terminal-state inspection still precedes mission access.
        SelectedEventNode::open_with_mission(root.path(), || {
            Ok(UnprotectedReferenceMission::load(&mission_path)
                .expect("reload persisted test mission after dropping its owner"))
        })
        .expect("open selected Event node")
    }

    #[test]
    fn event_operation_quota_is_terminal_and_exact_retry_survives_exhaustion() {
        use aster_redb_store::{BlobDepotLimits, EventOperationLimits, StoreLimits};
        for (records, bytes) in [(2, 1_000), (10, 324)] {
            let root = TestRoot::new("operation-capacity-classification");
            let mut node = selected_node(&root);
            node.store = Arc::new(
                Store::open_with_limits_and_operation_limits_for_mission(
                    root.path().join("limited.redb"),
                    StoreLimits::default(),
                    BlobDepotLimits::DEFAULT,
                    EventOperationLimits::new(records, bytes, 1).expect("limits"),
                    node.mission.mission_authority_id(),
                )
                .expect("limited store"),
            );
            let first_request = request(b"first", "ops.alpha", b"asset", b"ready");
            let first = node
                .publish(first_request.clone())
                .expect("first ordinary slot");
            let error = node
                .publish(request(b"second", "ops.alpha", b"asset", b"ready"))
                .expect_err("new key at operation capacity");
            assert_eq!(error.kind(), ApplicationErrorKind::OperationCapacity);
            let retry = node
                .publish(first_request)
                .expect("exact retry at capacity");
            assert_eq!(retry.id, first.id);
            assert!(!retry.inserted);
        }
    }

    #[test]
    fn relative_paths_remain_bound_across_path_provider_and_loader_cwd_changes() {
        run_isolated_cwd_test(
            "application::tests::relative_paths_remain_bound_across_path_provider_and_loader_cwd_changes",
            || {
                let original_cwd = std::env::current_dir().expect("original current directory");
                let root = TestRoot::new("relative-state-cwd-binding");
                let origin = root.path().join("origin");
                let callback_cwd = root.path().join("callback-cwd");
                fs::create_dir_all(&origin).expect("create original current directory");
                fs::create_dir_all(&callback_cwd).expect("create callback current directory");
                std::env::set_current_dir(&origin).expect("select original current directory");
                let bound_origin =
                    std::env::current_dir().expect("resolved original current directory");

                let mission_name = Path::new("mission.unprotected-reference.bundle");
                let origin_mission = selected_mission_bytes([0x6a; 32]);
                let expected_identity =
                    UnprotectedReferenceMission::from_bytes(origin_mission.clone())
                        .expect("parse original mission fixture")
                        .identity();
                drop(
                    UnprotectedReferenceMission::persist(
                        bound_origin.join(mission_name),
                        origin_mission,
                    )
                    .expect("persist original mission fixture"),
                );
                drop(
                    UnprotectedReferenceMission::persist(
                        callback_cwd.join(mission_name),
                        selected_mission_bytes([0x6b; 32]),
                    )
                    .expect("persist decoy mission fixture"),
                );
                let mission = ChdirPath {
                    destination: callback_cwd.clone(),
                    relative: mission_name.to_path_buf(),
                };
                let unprotected_state = Path::new("unprotected-relative-state");
                let node =
                    SelectedEventNode::open_unprotected_reference(unprotected_state, &mission)
                        .expect("open Event node after mission-path cwd change");
                assert_eq!(node.identity(), expected_identity);
                assert!(
                    bound_origin
                        .join(unprotected_state)
                        .join(STORE_FILE)
                        .is_file()
                );
                assert!(!callback_cwd.join(unprotected_state).exists());
                drop(node);

                std::env::set_current_dir(&origin)
                    .expect("restore origin before protected-path case");

                let protected_name = Path::new("mission.protected");
                let origin_protected = b"origin-provider-authenticated-envelope";
                fs::write(bound_origin.join(protected_name), origin_protected)
                    .expect("write original protected mission fixture");
                fs::write(
                    callback_cwd.join(protected_name),
                    b"decoy-provider-authenticated-envelope",
                )
                .expect("write decoy protected mission fixture");
                let protected = ChdirPath {
                    destination: callback_cwd.clone(),
                    relative: protected_name.to_path_buf(),
                };
                let protected_state = Path::new("protected-relative-state");
                let mut unprotector = ChdirUnprotector {
                    calls: 0,
                    destination: callback_cwd.clone(),
                    expected_protected: origin_protected.to_vec(),
                    plaintext: Some(selected_mission_bytes([0x6c; 32])),
                };
                let node = SelectedEventNode::open_protected(
                    protected_state,
                    &protected,
                    &mut unprotector,
                )
                .expect("open Event node after provider cwd change");
                assert_eq!(unprotector.calls, 1);
                assert!(
                    bound_origin
                        .join(protected_state)
                        .join(STORE_FILE)
                        .is_file()
                );
                assert!(!callback_cwd.join(protected_state).exists());
                drop(node);

                std::env::set_current_dir(&origin)
                    .expect("restore origin before secret-loader case");
                let secret_state = Path::new("secret-relative-state");
                let operation = ProvisioningLoadId::new([0x6d; 32]);
                let secret_ref =
                    ProvisioningSecretRef::from_opaque(b"cwd-bound-secret-ref".to_vec())
                        .expect("secret reference");
                let mut loader = ChdirSecretLoader {
                    calls: 0,
                    destination: callback_cwd.clone(),
                    expected_operation: operation,
                    expected_ref: secret_ref.clone(),
                    plaintext: Some(selected_mission_bytes([0x6e; 32])),
                };
                let node = SelectedEventNode::open_secret_ref(
                    secret_state,
                    &secret_ref,
                    operation,
                    &mut loader,
                )
                .expect("open Event node after secret-loader cwd change");
                assert_eq!(loader.calls, 1);
                assert!(bound_origin.join(secret_state).join(STORE_FILE).is_file());
                assert!(!callback_cwd.join(secret_state).exists());
                drop(node);

                std::env::set_current_dir(original_cwd)
                    .expect("restore process current directory after regression");
            },
        );
    }

    #[test]
    fn protected_bytes_open_calls_provider_once_and_raw_input_never_falls_back() {
        let root = TestRoot::new("protected-bytes-open");
        let bytes = selected_mission_bytes([0x61; 32]);
        let expected =
            UnprotectedReferenceMission::from_bytes(bytes.clone()).expect("parse expected mission");

        let protected_state = root.path().join("protected-state");
        let mut unprotector = CountingUnprotector::accepting(bytes.clone());
        let node = SelectedEventNode::from_protected_bytes(
            &protected_state,
            b"provider-authenticated-envelope",
            &mut unprotector,
        )
        .expect("open protected selected Event node");
        assert_eq!(unprotector.calls, 1);
        assert_eq!(node.identity(), expected.identity());
        assert!(protected_state.join(STORE_FILE).is_file());
        drop(node);

        let raw_state = root.path().join("raw-fallback-state");
        let mut no_fallback = CountingUnprotector::accepting(bytes.clone());
        let Err(error) =
            SelectedEventNode::from_protected_bytes(&raw_state, &bytes, &mut no_fallback)
        else {
            panic!("raw provisioning bytes must not open through the protected API");
        };
        assert_eq!(error.kind(), ApplicationErrorKind::Provisioning);
        assert_eq!(no_fallback.calls, 0);
        assert!(!raw_state.exists());
    }

    #[test]
    fn protected_file_provider_failure_does_not_create_selected_state() {
        let root = TestRoot::new("protected-file-rejection");
        let protected = root.path().join("mission.protected");
        fs::write(&protected, b"provider-authenticated-envelope").expect("write protected fixture");
        let state = root.path().join("rejected-state");
        let mut unprotector = CountingUnprotector::rejecting();

        let Err(error) = SelectedEventNode::open_protected(&state, &protected, &mut unprotector)
        else {
            panic!("rejecting provider must fail selected open");
        };
        assert_eq!(error.kind(), ApplicationErrorKind::Provisioning);
        assert_eq!(unprotector.calls, 1);
        assert!(!state.exists());
    }

    #[test]
    fn secret_ref_open_requires_exact_receipt_and_rejection_creates_no_state() {
        let root = TestRoot::new("secret-ref-open");
        let bytes = selected_mission_bytes([0x63; 32]);
        let expected =
            UnprotectedReferenceMission::from_bytes(bytes.clone()).expect("parse expected mission");
        let operation = ProvisioningLoadId::new([0x64; 32]);
        let secret_ref = ProvisioningSecretRef::from_opaque(b"selected-secret-ref".to_vec())
            .expect("secret ref");
        let mut exact = CountingSecretLoader {
            calls: 0,
            expected_operation: operation,
            expected_ref: secret_ref.clone(),
            returned_operation: operation,
            returned_ref: secret_ref.clone(),
            plaintext: Some(bytes.clone()),
        };
        let state = root.path().join("secret-ref-state");
        let node = SelectedEventNode::open_secret_ref(&state, &secret_ref, operation, &mut exact)
            .expect("open exact secret reference");
        assert_eq!(exact.calls, 1);
        assert_eq!(node.identity(), expected.identity());
        assert_eq!(node.mission.persistent_secret_ref(), Some(&secret_ref));
        assert!(state.join(STORE_FILE).is_file());
        drop(node);

        let rejected_state = root.path().join("rejected-secret-ref-state");
        let other_ref = ProvisioningSecretRef::from_opaque(b"mismatched-secret-ref".to_vec())
            .expect("other secret ref");
        let mut mismatched = CountingSecretLoader {
            calls: 0,
            expected_operation: operation,
            expected_ref: secret_ref.clone(),
            returned_operation: ProvisioningLoadId::new([0x65; 32]),
            returned_ref: other_ref,
            plaintext: Some(bytes),
        };
        let Err(error) = SelectedEventNode::open_secret_ref(
            &rejected_state,
            &secret_ref,
            operation,
            &mut mismatched,
        ) else {
            panic!("mismatched persistent-secret receipt must be rejected");
        };
        assert_eq!(error.kind(), ApplicationErrorKind::Provisioning);
        assert_eq!(mismatched.calls, 1);
        assert!(!rejected_state.exists());
    }

    #[test]
    fn terminal_state_precedes_protected_file_and_provider_access() {
        let root = TestRoot::new("protected-terminal-preflight");
        let bytes = selected_mission_bytes([0x62; 32]);
        let mission =
            UnprotectedReferenceMission::from_bytes(bytes.clone()).expect("parse terminal mission");
        let state = root.path().join("terminal-state");
        fs::create_dir(&state).expect("create terminal state");
        let mut store =
            Store::open_for_mission(state.join(STORE_FILE), mission.mission_authority_id())
                .expect("open terminal store");
        let intent = aster_redb_store::ZeroizationIntent::new(
            b"mission-artifact".to_vec(),
            b"carrier-identity".to_vec(),
        )
        .expect("zeroization intent");
        store
            .begin_zeroization(&intent)
            .expect("enter terminal state");
        drop(store);

        let missing_protected = root.path().join("must-not-be-read.protected");
        let mut unprotector = CountingUnprotector::accepting(bytes);
        let Err(error) =
            SelectedEventNode::open_protected(&state, &missing_protected, &mut unprotector)
        else {
            panic!("terminal state must reject selected protected open");
        };
        assert_eq!(error.kind(), ApplicationErrorKind::StateUnavailable);
        assert_eq!(unprotector.calls, 0);
        assert!(!missing_protected.exists());

        let operation = ProvisioningLoadId::new([0x66; 32]);
        let secret_ref = ProvisioningSecretRef::from_opaque(b"terminal-secret-ref".to_vec())
            .expect("terminal secret ref");
        let mut loader = CountingSecretLoader {
            calls: 0,
            expected_operation: operation,
            expected_ref: secret_ref.clone(),
            returned_operation: operation,
            returned_ref: secret_ref.clone(),
            plaintext: Some(selected_mission_bytes([0x62; 32])),
        };
        let Err(error) =
            SelectedEventNode::open_secret_ref(&state, &secret_ref, operation, &mut loader)
        else {
            panic!("terminal state must reject selected secret-reference open");
        };
        assert_eq!(error.kind(), ApplicationErrorKind::StateUnavailable);
        assert_eq!(loader.calls, 0);
    }

    fn request(operation: &[u8], topic: &str, key: &[u8], payload: &[u8]) -> EventPublishRequest {
        EventPublishRequest {
            operation_key: operation.to_vec(),
            predecessor: None,
            topic: Topic::new(topic).expect("topic"),
            scope: Scope::new("mission/apps").expect("scope"),
            priority: Priority::Priority,
            logical_key: key.to_vec(),
            payload: payload.to_vec(),
            tombstone: false,
        }
    }

    fn numbered_request(
        client_id: &EventClientId,
        session: EventPublicationSession,
        sequence: u64,
        payload: &[u8],
    ) -> NumberedEventPublishRequest {
        NumberedEventPublishRequest {
            client_id: client_id.clone(),
            session,
            sequence: EventOperationSequence::new(sequence).expect("sequence"),
            predecessor: None,
            topic: Topic::new("ops.alpha").expect("topic"),
            scope: Scope::new("mission/apps").expect("scope"),
            priority: Priority::Priority,
            logical_key: b"numbered-asset".to_vec(),
            payload: payload.to_vec(),
            tombstone: false,
        }
    }

    #[test]
    fn numbered_publication_rejects_unprovisioned_topic_after_recovery() {
        let root = TestRoot::new("numbered-unprovisioned-topic");
        let client = EventClientId::new(b"numbered-rejected-client".to_vec()).expect("client");
        let mut node = selected_node(&root);
        let recovery = node
            .begin_publication_session(&client, 0, b"rejected-topic-session")
            .expect("claim");
        node.complete_publication_recovery(&client, recovery.session, recovery.snapshot_revision)
            .expect("complete recovery");

        let mut request = numbered_request(&client, recovery.session, 1, b"rejected");
        request.topic = Topic::new("ops.unprovisioned").expect("topic");
        let error = node
            .publish_numbered(request, EventPublishOptions::durable())
            .expect_err("unprovisioned topic must fail");
        assert_eq!(error.kind(), ApplicationErrorKind::RequestRejected);
        assert_eq!(error.operation(), "publish_numbered");
    }

    #[test]
    fn numbered_publication_retries_compacts_sparse_results_and_recovers_after_restart() {
        let root = TestRoot::new("numbered-publication");
        let client = EventClientId::new(b"numbered-client".to_vec()).expect("client");
        let first_session;
        let first_result;
        {
            let mut node = selected_node(&root);
            let recovery = node
                .begin_publication_session(&client, 0, b"first-process")
                .expect("claim");
            first_session = recovery.session;
            node.complete_publication_recovery(
                &client,
                recovery.session,
                recovery.snapshot_revision,
            )
            .expect("complete recovery");

            first_result = node
                .publish_numbered(
                    numbered_request(&client, recovery.session, 1, b"first"),
                    EventPublishOptions::durable(),
                )
                .expect("first publication");
            assert!(first_result.inserted);
            let exact = node
                .publish_numbered(
                    numbered_request(&client, recovery.session, 1, b"first"),
                    EventPublishOptions::durable(),
                )
                .expect("exact retry");
            assert!(!exact.inserted);
            assert_eq!(exact.result, first_result.result);

            let conflict = node
                .publish_numbered(
                    numbered_request(&client, recovery.session, 1, b"changed"),
                    EventPublishOptions::durable(),
                )
                .expect_err("changed intent");
            assert_eq!(conflict.kind(), ApplicationErrorKind::Conflict);
            let gap = node
                .publish_numbered(
                    numbered_request(&client, recovery.session, 3, b"gap"),
                    EventPublishOptions::durable(),
                )
                .expect_err("sequence gap");
            assert_eq!(gap.kind(), ApplicationErrorKind::SequenceGap);

            node.publish_numbered(
                numbered_request(&client, recovery.session, 2, b"second"),
                EventPublishOptions::durable(),
            )
            .expect("second publication");
            assert_eq!(
                node.acknowledge_publication_result(
                    &client,
                    recovery.session,
                    EventOperationSequence::new(2).expect("sequence"),
                )
                .expect("compact later result"),
                EventResultAcknowledgement::Acknowledged
            );
        }

        let mut reopened = SelectedEventNode::open_unprotected_reference(
            root.path(),
            root.path().join("mission.unprotected-reference.bundle"),
        )
        .expect("reopen selected Event node");
        let recovery = reopened
            .begin_publication_session(&client, first_session.get(), b"second-process")
            .expect("take over");
        assert_eq!(recovery.allocated_through, 2);
        assert_eq!(recovery.outstanding, vec![first_result.result]);
        reopened
            .complete_publication_recovery(&client, recovery.session, recovery.snapshot_revision)
            .expect("complete restart recovery");
        reopened
            .complete_publication_recovery(&client, recovery.session, recovery.snapshot_revision)
            .expect("repeat lost completion response");
        let stale = reopened
            .abandon_publication(
                &client,
                first_session,
                EventOperationSequence::new(3).expect("sequence"),
            )
            .expect_err("stale process is fenced");
        assert_eq!(stale.kind(), ApplicationErrorKind::SessionFenced);
        reopened
            .acknowledge_publication_result(
                &client,
                recovery.session,
                EventOperationSequence::new(1).expect("sequence"),
            )
            .expect("acknowledge old result");
        let retired = reopened
            .publish_numbered(
                numbered_request(&client, recovery.session, 1, b"first"),
                EventPublishOptions::durable(),
            )
            .expect_err("compacted sequence is permanently retired");
        assert_eq!(retired.kind(), ApplicationErrorKind::SequenceRetired);
    }

    #[test]
    fn numbered_result_preserves_committed_truth_after_ttl_retirement() {
        let root = TestRoot::new("numbered-ttl-result");
        let client = EventClientId::new(b"ttl-client".to_vec()).expect("client");
        let clock_id = [0x7d; 16];
        let mut node = selected_node(&root);
        node.custody_clock = NodeCustodyClock::injected(clock_id, 0, 0);
        let recovery = node
            .begin_publication_session(&client, 0, b"ttl-session")
            .expect("claim");
        node.complete_publication_recovery(&client, recovery.session, recovery.snapshot_revision)
            .expect("complete recovery");
        let published = node
            .publish_numbered(
                numbered_request(&client, recovery.session, 1, b"brief"),
                EventPublishOptions::finite_ttl_ms(10).expect("ttl"),
            )
            .expect("publish finite Event");
        assert_eq!(published.result.content, CommittedEventContent::Available);

        node.custody_clock = NodeCustodyClock::injected(clock_id, 10, 0);
        node.maintain_custody().expect("expire content");
        let next = node
            .begin_publication_session(&client, recovery.session.get(), b"after-expiry")
            .expect("take over after expiry");
        assert_eq!(next.outstanding.len(), 1);
        assert_eq!(next.outstanding[0].receipt, published.result.receipt);
        assert_eq!(
            next.outstanding[0].content,
            CommittedEventContent::Retired(aster_redb_store::CustodyRetirementReason::Expired)
        );
    }

    #[test]
    fn numbered_profile_refuses_legacy_ledger_without_modifying_it() {
        let root = TestRoot::new("numbered-refuses-legacy");
        let mut node = selected_node(&root);
        let legacy = node
            .publish(request(
                b"legacy-operation",
                "ops.alpha",
                b"legacy-asset",
                b"preserve-me",
            ))
            .expect("legacy publication");
        let client = EventClientId::new(b"new-profile-client".to_vec()).expect("client");
        let error = node
            .begin_publication_session(&client, 0, b"cannot-migrate")
            .expect_err("legacy state requires a fresh boundary");
        assert_eq!(error.kind(), ApplicationErrorKind::LegacyState);
        let retained = node.query(EventQuery::default()).expect("legacy query");
        assert_eq!(retained.items.len(), 1);
        assert_eq!(retained.items[0].id, legacy.id);
        assert_eq!(retained.items[0].payload, b"preserve-me");

        let numbered_root = TestRoot::new("legacy-refuses-numbered");
        let mut numbered_node = selected_node(&numbered_root);
        let recovery = numbered_node
            .begin_publication_session(&client, 0, b"numbered-only")
            .expect("initialize numbered profile");
        numbered_node
            .complete_publication_recovery(&client, recovery.session, recovery.snapshot_revision)
            .expect("complete recovery");
        let legacy_error = numbered_node
            .publish(request(
                b"legacy-after-numbered",
                "ops.alpha",
                b"legacy-asset",
                b"must-not-commit",
            ))
            .expect_err("numbered state disables the legacy ledger");
        assert_eq!(legacy_error.kind(), ApplicationErrorKind::LegacyState);
        assert!(
            numbered_node
                .query(EventQuery::default())
                .expect("query numbered store")
                .items
                .is_empty()
        );
    }

    #[test]
    fn numbered_recovery_retry_and_cleanup_remain_available_at_global_saturation() {
        use aster_redb_store::{BlobDepotLimits, EventOperationLimits, StoreLimits};

        let root = TestRoot::new("numbered-saturation");
        let mut node = selected_node(&root);
        node.store = Arc::new(
            Store::open_with_limits_and_operation_limits_for_mission(
                root.path().join("numbered-limited.redb"),
                StoreLimits::default(),
                BlobDepotLimits::DEFAULT,
                EventOperationLimits::new(3, 10_000, 1).expect("limits"),
                node.mission.mission_authority_id(),
            )
            .expect("limited store"),
        );
        let client = EventClientId::new(b"saturated-client".to_vec()).expect("client");
        let first = node
            .begin_publication_session(&client, 0, b"first-session")
            .expect("claim");
        node.complete_publication_recovery(&client, first.session, first.snapshot_revision)
            .expect("complete");
        let published = node
            .publish_numbered(
                numbered_request(&client, first.session, 1, b"fills-limit"),
                EventPublishOptions::durable(),
            )
            .expect("first publication");
        let full = node
            .publish_numbered(
                numbered_request(&client, first.session, 2, b"cannot-grow"),
                EventPublishOptions::durable(),
            )
            .expect_err("global result record limit");
        assert_eq!(full.kind(), ApplicationErrorKind::OperationCapacity);
        assert!(
            !node
                .publish_numbered(
                    numbered_request(&client, first.session, 1, b"fills-limit"),
                    EventPublishOptions::durable(),
                )
                .expect("exact retry at saturation")
                .inserted
        );

        let takeover = node
            .begin_publication_session(&client, first.session.get(), b"takeover-at-limit")
            .expect("takeover at saturation");
        assert_eq!(takeover.outstanding, vec![published.result]);
        node.complete_publication_recovery(&client, takeover.session, takeover.snapshot_revision)
            .expect("recovery at saturation");
        node.acknowledge_publication_result(
            &client,
            takeover.session,
            EventOperationSequence::new(1).expect("sequence"),
        )
        .expect("state-reducing acknowledgement at saturation");
        node.publish_numbered(
            numbered_request(&client, takeover.session, 2, b"fits-after-ack"),
            EventPublishOptions::durable(),
        )
        .expect("capacity reused after acknowledgement");
    }

    fn subscription_request(operation: &[u8], topic: &str) -> EventSubscriptionRequest {
        EventSubscriptionRequest {
            operation_key: operation.to_vec(),
            topic: Topic::new(topic).expect("topic"),
            scope: Scope::new("mission/apps").expect("scope"),
            include_descendant_scopes: false,
        }
    }

    #[test]
    fn arbitrary_event_publish_query_and_retry_share_one_selected_authority() {
        let root = TestRoot::new("publish-query");
        let mut node = selected_node(&root);
        let first_request = request(b"ops/first", "ops.alpha", b"asset-7", b"ready");
        let first = node.publish(first_request.clone()).expect("publish first");
        assert!(first.inserted);
        assert_eq!(first.publisher_counter, 1);
        assert_eq!(first.event_sequence, 1);
        assert_eq!(first.priority, Priority::Priority);

        let retried = node.publish(first_request).expect("retry first");
        assert!(!retried.inserted);
        assert_eq!(retried.id, first.id);
        assert_eq!(retried.acceptance_marker, first.acceptance_marker);

        let second = node
            .publish(request(b"ops/second", "ops.beta", b"asset-8", b"moving"))
            .expect("publish second");
        assert!(second.inserted);
        assert_eq!(second.publisher_counter, 2);
        assert_eq!(second.event_sequence, 1);

        let first_scan = node
            .query(EventQuery {
                topic: Some(Topic::new("ops.beta").expect("topic")),
                limit: 1,
                ..EventQuery::default()
            })
            .expect("first selective scan");
        assert!(first_scan.items.is_empty());
        assert_eq!(first_scan.scanned_through, first.acceptance_marker);
        assert!(first_scan.has_more);

        let second_scan = node
            .query(EventQuery {
                topic: Some(Topic::new("ops.beta").expect("topic")),
                after_acceptance_marker: first_scan.scanned_through,
                limit: 1,
                ..EventQuery::default()
            })
            .expect("second selective scan");
        assert_eq!(second_scan.items.len(), 1);
        assert_eq!(second_scan.items[0].id, second.id);
        assert_eq!(second_scan.items[0].payload, b"moving");
        assert!(!second_scan.has_more);

        let all = node.query(EventQuery::default()).expect("query all");
        assert_eq!(all.items.len(), 2);
        assert_eq!(all.scanned_through, 2);
        assert!(!all.has_more);
    }

    #[test]
    fn query_prefilters_each_field_before_source_verification() {
        let root = TestRoot::new("query-prefilter");
        let mut node = selected_node(&root);
        node.publish(request(b"query/one", "ops.alpha", b"asset", b"ready"))
            .expect("publish fixture");
        let publisher = node.identity();
        // Every source verification now fails under a different mission trust
        // root. A nonmatching query can succeed only if no candidate reaches
        // that verifier. No production counter or mock verifier is needed.
        let other_mission =
            UnprotectedReferenceMission::from_bytes(selected_mission_bytes([0x6b; 32]))
                .expect("independent test mission");
        node.verifier = ReferenceEnvelopeSealer::open(other_mission.fresh_bundle().unwrap())
            .expect("different trust root");
        let matching = EventQuery {
            publisher: Some(publisher),
            topic: Some(Topic::new("ops.alpha").unwrap()),
            scope: Some(Scope::new("mission/apps").unwrap()),
            logical_key: Some(b"asset".to_vec()),
            ..EventQuery::default()
        };
        let mismatches = [
            EventQuery {
                publisher: Some([0xee; 32]),
                ..matching.clone()
            },
            EventQuery {
                topic: Some(Topic::new("ops.beta").unwrap()),
                ..matching.clone()
            },
            EventQuery {
                scope: Some(Scope::new("mission").unwrap()),
                ..matching.clone()
            },
            EventQuery {
                scope: Some(Scope::new("mission/elsewhere").unwrap()),
                include_descendant_scopes: true,
                ..matching.clone()
            },
            EventQuery {
                logical_key: Some(b"absent".to_vec()),
                ..matching.clone()
            },
        ];
        for query in mismatches {
            let page = node.query(query.clone()).unwrap_or_else(|error| {
                panic!("nonmatching query reached source verification: {query:?}: {error}")
            });
            assert!(page.items.is_empty());
            assert_eq!(page.scanned_through, 1);
            assert!(!page.has_more);
        }
        for query in [
            matching,
            EventQuery::default(),
            EventQuery {
                scope: Some(Scope::new("mission").unwrap()),
                include_descendant_scopes: true,
                ..EventQuery::default()
            },
        ] {
            assert!(
                node.query(query).is_err(),
                "selected candidates must still be authenticated"
            );
        }
    }

    #[test]
    fn query_filters_and_combinations_preserve_authenticated_results() {
        let root = TestRoot::new("query-filter-results");
        let mut node = selected_node(&root);
        node.publish(request(b"query/one", "ops.alpha", b"asset", b"alpha"))
            .unwrap();
        node.publish(request(b"query/two", "ops.beta", b"other", b"beta"))
            .unwrap();
        // Every combination of optional filters must select the first Event.
        // With no filters, both Events remain visible in acceptance order.
        for mask in 0..16 {
            let page = node
                .query(EventQuery {
                    publisher: (mask & 1 != 0).then_some(node.identity()),
                    topic: (mask & 2 != 0).then(|| Topic::new("ops.alpha").unwrap()),
                    scope: (mask & 4 != 0).then(|| Scope::new("mission/apps").unwrap()),
                    logical_key: (mask & 8 != 0).then(|| b"asset".to_vec()),
                    ..EventQuery::default()
                })
                .unwrap();
            let expected = if mask & (2 | 8) == 0 {
                vec![1, 2]
            } else {
                vec![1]
            };
            assert_eq!(
                page.items
                    .iter()
                    .map(|item| item.acceptance_marker)
                    .collect::<Vec<_>>(),
                expected,
                "mask {mask}"
            );
            assert_eq!(page.items[0].payload, b"alpha");
            assert_eq!(page.scanned_through, 2);
            assert!(!page.has_more);
        }
        for (scope, descendants, expected) in [
            (Some("mission"), false, 0),
            (Some("mission"), true, 2),
            (Some("mission/app"), true, 0),
            (Some("mission/apps"), false, 2),
            (Some("mission/apps"), true, 2),
            (None, true, 2),
        ] {
            let page = node
                .query(EventQuery {
                    scope: scope.map(|scope| Scope::new(scope).unwrap()),
                    include_descendant_scopes: descendants,
                    ..EventQuery::default()
                })
                .unwrap();
            assert_eq!(
                page.items.len(),
                expected,
                "scope {scope:?}, descendants {descendants}"
            );
        }
    }

    #[test]
    fn filtered_query_rechecks_current_content_grants_and_local_revocation() {
        use aster_mesh::ScopeRekeyRecipient;

        let root = TestRoot::new("query-current-grants");
        let scope = Scope::new("mission/apps").unwrap();
        let topics = vec![
            Topic::new("ops.alpha").unwrap(),
            Topic::new("ops.beta").unwrap(),
        ];
        let access = ProvisioningAccess::member(scope.clone(), vec![1], topics.clone()).unwrap();
        let mut provisioner = ReferenceProvisioner::from_seed([0x5a; 32]).unwrap();
        let mission_path = root.path().join("query-mission.bundle");
        let bundle = provisioner
            .issue_node(1, std::slice::from_ref(&access))
            .unwrap();
        drop(
            UnprotectedReferenceMission::persist(&mission_path, bundle.to_bytes().unwrap())
                .unwrap(),
        );
        let mut node =
            SelectedEventNode::open_unprotected_reference(root.path(), &mission_path).unwrap();
        node.publish(request(b"query/one", "ops.alpha", b"asset", b"ready"))
            .unwrap();
        let query = EventQuery {
            topic: Some(Topic::new("ops.alpha").unwrap()),
            logical_key: Some(b"asset".to_vec()),
            ..EventQuery::default()
        };
        assert_eq!(node.query(query.clone()).unwrap().items.len(), 1);
        let mut authority = provisioner
            .issue_control_authority(60, &[access])
            .and_then(ReferenceEnvelopeSealer::open)
            .unwrap();
        let registry = provisioner.export_rekey_registry().unwrap();
        let (sealed, _) = authority
            .seal_chained_scope_rekey_control_from_registry(
                &registry,
                0,
                scope,
                1,
                vec![
                    ScopeRekeyRecipient::member(authority.identity(), topics).unwrap(),
                    ScopeRekeyRecipient::member(
                        node.identity(),
                        vec![Topic::new("ops.beta").unwrap()],
                    )
                    .unwrap(),
                ],
                1,
                None,
            )
            .unwrap();
        let verified = node.verifier.verify_control(&sealed).unwrap();
        let rekey_id = verified.envelope_id();
        node.store
            .ingest_verified_control(&verified, &sealed)
            .unwrap();
        // Same epoch and unchanged stored metadata still match. Fresh policy
        // replay must remove alpha content access before returning plaintext.
        assert_eq!(
            node.query(query).unwrap_err().kind(),
            ApplicationErrorKind::Integrity
        );
        let revocation = authority
            .seal_chained_revocation_control(node.identity(), 1, 2, Some(rekey_id))
            .unwrap();
        let verified = node.verifier.verify_control(&revocation).unwrap();
        node.store
            .ingest_verified_control(&verified, &revocation)
            .unwrap();
        assert!(
            node.query(EventQuery {
                logical_key: Some(b"absent".to_vec()),
                ..EventQuery::default()
            })
            .is_err(),
            "even an empty selection must enforce current local authorization"
        );
    }

    #[test]
    fn query_candidates_reject_corrupt_bytes_and_forged_metadata() {
        let root = TestRoot::new("query-candidate-integrity");
        let mut node = selected_node(&root);
        node.publish(request(b"query/one", "ops.alpha", b"asset", b"ready"))
            .unwrap();
        let stored = node.store.events_after(0, 1).unwrap().remove(0);
        let matching = EventQuery {
            publisher: Some(node.identity()),
            topic: Some(Topic::new("ops.alpha").unwrap()),
            scope: Some(Scope::new("mission/apps").unwrap()),
            logical_key: Some(b"asset".to_vec()),
            ..EventQuery::default()
        };
        assert!(
            node.open_application_event(&matching, stored.clone())
                .unwrap()
                .is_some()
        );
        let mut corrupt = stored.clone();
        *corrupt.sealed.last_mut().unwrap() ^= 0x40;
        assert!(node.open_application_event(&matching, corrupt).is_err());
        for field in 0..5 {
            let mut forged = stored.clone();
            let mut query = matching.clone();
            match field {
                0 => {
                    forged.header.stamp.dot.publisher = [0xee; 32];
                    query.publisher = Some([0xee; 32]);
                }
                1 => {
                    forged.header.topic = Topic::new("ops.beta").unwrap();
                    query.topic = Some(forged.header.topic.clone());
                }
                2 => {
                    forged.header.scope = Scope::new("mission/elsewhere").unwrap();
                    query.scope = Some(forged.header.scope.clone());
                }
                3 => {
                    forged.header.logical_key = b"forged".to_vec();
                    query.logical_key = Some(b"forged".to_vec());
                }
                _ => {
                    forged.header.priority = Priority::Flash;
                }
            }
            assert_eq!(
                node.open_application_event(&query, forged)
                    .unwrap_err()
                    .kind(),
                ApplicationErrorKind::Integrity
            );
        }
        assert!(
            node.open_application_event(
                &EventQuery {
                    logical_key: Some(b"absent".to_vec()),
                    ..matching
                },
                stored
            )
            .unwrap()
            .is_none(),
            "authenticated candidates are checked against the query again"
        );
    }

    #[test]
    fn finite_event_crossing_ttl_during_final_query_and_poll_recheck_is_withheld() {
        let query_root = TestRoot::new("finite-final-query-recheck");
        let mut node = selected_node(&query_root);
        let clock_id = [0x9a; 16];
        node.custody_clock = NodeCustodyClock::injected(clock_id, 0, 0);
        let published = node
            .publish_with_options(
                request(b"ops/finite", "ops.alpha", b"asset-ttl", b"brief"),
                EventPublishOptions::finite_ttl_ms(10).expect("positive TTL"),
            )
            .expect("publish finite Event");

        // The initial source/age check observes TTL-1. Content verification is
        // followed by the final sample at exactly TTL, which must not escape.
        node.custody_clock = NodeCustodyClock::injected(clock_id, 8, 1);
        let queried = node
            .query(EventQuery {
                logical_key: Some(b"asset-ttl".to_vec()),
                ..EventQuery::default()
            })
            .expect("finite filtered query");
        assert!(queried.items.is_empty());

        // Use an independent durable clock history to exercise the same
        // boundary after the poll-plan commit without ever rewinding a
        // continuity domain. The pending attempt may remain, but plaintext at
        // age == TTL must not be returned.
        let poll_root = TestRoot::new("finite-final-poll-recheck");
        let mut poll_node = selected_node(&poll_root);
        let poll_clock_id = [0x9b; 16];
        poll_node.custody_clock = NodeCustodyClock::injected(poll_clock_id, 0, 0);
        poll_node
            .publish_with_options(
                request(b"ops/finite", "ops.alpha", b"asset-ttl", b"brief"),
                EventPublishOptions::finite_ttl_ms(10).expect("positive TTL"),
            )
            .expect("publish finite poll Event");
        let subscription = poll_node
            .subscribe(subscription_request(b"subscriptions/finite", "ops.alpha"))
            .expect("subscribe finite Event");
        poll_node.custody_clock = NodeCustodyClock::injected(poll_clock_id, 9, 1);
        let polled = poll_node
            .poll(EventPollRequest {
                subscription: subscription.id,
                delivery_limit: 8,
                scan_limit: 8,
            })
            .expect("finite poll");
        assert!(polled.deliveries.is_empty());
        assert_eq!(published.event_sequence, 1);
    }

    #[test]
    fn finite_event_expiry_reuses_full_store_capacity_without_reusing_operation_keys() {
        let root = TestRoot::new("finite-capacity-reuse");
        let mut node = selected_node(&root);
        node.store = Arc::new(
            Store::open_with_limits_for_mission(
                root.path().join("limited.redb"),
                aster_redb_store::StoreLimits::new(
                    aster_redb_store::MAX_CONTROL_ITEMS
                        + aster_redb_store::CUSTODY_EMERGENCY_ITEM_RESERVE
                        + 1,
                    aster_redb_store::MAX_CONTROL_BYTES
                        + aster_redb_store::CUSTODY_EMERGENCY_BYTE_RESERVE
                        + 1024 * 1024,
                )
                .unwrap(),
                node.mission.mission_authority_id(),
            )
            .unwrap(),
        );
        let clock_id = [0x91; 16];
        let options = EventPublishOptions::finite_ttl_ms(10).unwrap();
        for round in 0_u64..8 {
            node.custody_clock = NodeCustodyClock::injected(clock_id, round * 10, 0);
            let publication = request(&round.to_be_bytes(), "ops.alpha", b"asset", b"brief");
            let result = node
                .publish_with_options(publication.clone(), options)
                .unwrap();
            assert_eq!(result.event_sequence, round + 1);
            let full = node.store.aggregate_usage().unwrap();
            assert_eq!(full.items, 1);
            assert!(full.payload_bytes > 0);
            let overflow = node.publish_with_options(
                request(b"cannot-fit", "ops.alpha", b"asset", b"another"),
                options,
            );
            assert!(
                overflow.is_err(),
                "equal priority cannot displace the live Event"
            );
            assert_eq!(node.store.aggregate_usage().unwrap(), full);
            let mut changed = publication.clone();
            changed.payload = b"changed".to_vec();
            assert_eq!(
                node.publish_with_options(changed, options)
                    .unwrap_err()
                    .kind(),
                ApplicationErrorKind::Conflict
            );
            assert_eq!(
                node.publish_with_options(
                    publication.clone(),
                    EventPublishOptions::finite_ttl_ms(11).unwrap()
                )
                .unwrap_err()
                .kind(),
                ApplicationErrorKind::Conflict
            );
            node.custody_clock = NodeCustodyClock::injected(clock_id, (round + 1) * 10, 0);
            assert_eq!(
                node.publish_with_options(publication, options)
                    .unwrap_err()
                    .kind(),
                ApplicationErrorKind::ExpiredOrRetired
            );
            // Publication itself runs cleanup; no separate maintenance call.
            assert_eq!(
                node.store.aggregate_usage().unwrap(),
                AggregateStoreUsage::default()
            );
        }
    }

    #[test]
    fn finite_retirement_waits_for_lease_and_operation_fence_survives_reopen() {
        let root = TestRoot::new("finite-retirement-fence");
        let clock_id = [0x8b; 16];
        let publication = request(
            b"ops/finite-retired",
            "ops.alpha",
            b"asset-retired",
            b"short-lived",
        );
        let options = EventPublishOptions::finite_ttl_ms(10).expect("positive TTL");
        {
            let mut node = selected_node(&root);
            node.custody_clock = NodeCustodyClock::injected(clock_id, 0, 0);
            node.publish_with_options(publication.clone(), options)
                .expect("publish finite Event");
            let operation =
                EventOperationKey::new(publication.operation_key.clone()).expect("operation key");
            let aster_redb_store::EventOperationResolution::Live(stored) = node
                .store
                .event_operation_resolution(&operation)
                .expect("resolve operation")
                .expect("operation exists")
            else {
                panic!("fresh finite operation is not live");
            };
            let revision = node
                .store
                .custody_policy_revision()
                .expect("custody revision");
            let lease = node
                .store
                .begin_custody_send(
                    [0x37; 32],
                    CustodyObjectKey::event(stored.transfer_id),
                    aster_redb_store::CustodyPeerSelectorRevision::new(0),
                    Some(CustodySample {
                        clock_id,
                        tick_ms: 9,
                    }),
                    0,
                    revision,
                )
                .expect("hold transfer lease");

            node.custody_clock = NodeCustodyClock::injected(clock_id, 10, 0);
            node.maintain_custody().expect("mark expired custody");
            let held = node.store.event_stats().expect("leased Event stats");
            assert_eq!(held.events, 1, "active lease must retain the source row");
            assert_eq!(
                held.retiring_events, 1,
                "active lease must leave the expired source marked retiring"
            );
            assert!(
                held.total_sealed_bytes > 0,
                "active lease must delay physical byte retirement"
            );
            assert!(
                node.query(EventQuery::default())
                    .expect("expired query")
                    .items
                    .is_empty(),
                "expired bytes held by a lease must remain application-invisible"
            );

            assert_eq!(
                node.publish_with_options(publication.clone(), options)
                    .expect_err("exact retry while the lease retains bytes")
                    .kind(),
                ApplicationErrorKind::ExpiredOrRetired,
            );
            let mut changed_held = publication.clone();
            changed_held.payload = b"changed-while-held".to_vec();
            assert_eq!(
                node.publish_with_options(changed_held, options)
                    .expect_err("changed retry while the lease retains bytes")
                    .kind(),
                ApplicationErrorKind::Conflict
            );
            node.store
                .release_transfer_lease(lease.id)
                .expect("release held lease");
            node.maintain_custody().expect("finalize retirement");
            assert_eq!(
                node.store
                    .event_operation_resolution(&operation)
                    .expect("compact resolution"),
                Some(
                    aster_redb_store::EventOperationResolution::RetiredOperation {
                        reason: aster_redb_store::CustodyRetirementReason::Expired,
                    }
                )
            );
            let retired = node.store.event_stats().expect("retired Event stats");
            assert_eq!(retired.events, 0);
            assert_eq!(retired.retiring_events, 0);
            assert_eq!(retired.total_sealed_bytes, 0);
            assert!(
                node.store
                    .get_transfer(stored.transfer_id)
                    .expect("retired transfer lookup")
                    .is_none()
            );
        }

        let mut reopened = SelectedEventNode::open_unprotected_reference(
            root.path(),
            root.path().join("mission.unprotected-reference.bundle"),
        )
        .expect("reopen retired node");
        reopened.custody_clock = NodeCustodyClock::injected(clock_id, 11, 0);
        let exact = reopened
            .publish_with_options(publication.clone(), options)
            .expect_err("exact retired retry must remain fenced");
        assert_eq!(exact.kind(), ApplicationErrorKind::ExpiredOrRetired);

        let mut changed = publication;
        changed.payload = b"changed-after-retirement".to_vec();
        let changed_error = reopened
            .publish_with_options(changed, options)
            .expect_err("changed retired operation must remain fenced");
        assert_eq!(changed_error.kind(), ApplicationErrorKind::Conflict);

        let next = reopened
            .publish(request(
                b"ops/after-retired",
                "ops.alpha",
                b"asset-next",
                b"next",
            ))
            .expect("publish after retired retries");
        assert_eq!(
            next.publisher_counter, 2,
            "retired retries must not consume a new source dot"
        );
    }

    #[test]
    fn durable_subscription_repeats_until_idempotent_ack_across_restart() {
        let root = TestRoot::new("subscription-retry");
        let (subscription_id, event_id) = {
            let mut node = selected_node(&root);
            let published = node
                .publish(request(
                    b"ops/subscribed",
                    "ops.alpha",
                    b"asset-7",
                    b"ready",
                ))
                .expect("publish");
            let subscription = node
                .subscribe(subscription_request(b"subscriptions/alpha", "ops.alpha"))
                .expect("subscribe");
            assert!(subscription.inserted);
            let replayed = node
                .subscribe(subscription_request(b"subscriptions/alpha", "ops.alpha"))
                .expect("replay subscribe");
            assert!(!replayed.inserted);
            assert_eq!(replayed.id, subscription.id);
            let conflict = node
                .subscribe(subscription_request(b"subscriptions/alpha", "ops.beta"))
                .expect_err("subscription operation mismatch must fail");
            assert_eq!(conflict.kind(), ApplicationErrorKind::Conflict);

            let first = node
                .poll(EventPollRequest {
                    subscription: subscription.id,
                    delivery_limit: 8,
                    scan_limit: 8,
                })
                .expect("first poll");
            assert_eq!(first.deliveries.len(), 1);
            assert_eq!(first.deliveries[0].event.id, published.id);
            assert_eq!(first.deliveries[0].attempt, 1);
            assert!(!first.has_more);
            (subscription.id, published.id)
        };

        let mut reopened = SelectedEventNode::open_unprotected_reference(
            root.path(),
            root.path().join("mission.unprotected-reference.bundle"),
        )
        .expect("reopen selected Event node");
        let repeated = reopened
            .poll(EventPollRequest {
                subscription: subscription_id,
                delivery_limit: 8,
                scan_limit: 8,
            })
            .expect("repeat pending delivery");
        assert_eq!(repeated.deliveries.len(), 1);
        assert_eq!(repeated.deliveries[0].event.id, event_id);
        assert_eq!(repeated.deliveries[0].attempt, 2);

        assert_eq!(
            reopened
                .acknowledge(subscription_id, event_id)
                .expect("acknowledge"),
            EventAcknowledgement::Acknowledged
        );
        assert_eq!(
            reopened
                .acknowledge(subscription_id, event_id)
                .expect("idempotent acknowledge"),
            EventAcknowledgement::AlreadyAcknowledged
        );
        assert!(
            reopened
                .poll(EventPollRequest {
                    subscription: subscription_id,
                    delivery_limit: 8,
                    scan_limit: 8,
                })
                .expect("empty after acknowledgement")
                .deliveries
                .is_empty()
        );
    }

    #[test]
    fn subscription_scan_advances_over_verified_nonmatching_events() {
        let root = TestRoot::new("subscription-selective-scan");
        let mut node = selected_node(&root);
        node.publish(request(
            b"ops/alpha-first",
            "ops.alpha",
            b"asset-7",
            b"alpha",
        ))
        .expect("publish alpha");
        let beta = node
            .publish(request(b"ops/beta-second", "ops.beta", b"asset-8", b"beta"))
            .expect("publish beta");
        let subscription = node
            .subscribe(subscription_request(b"subscriptions/beta", "ops.beta"))
            .expect("subscribe beta");

        let first = node
            .poll(EventPollRequest {
                subscription: subscription.id,
                delivery_limit: 1,
                scan_limit: 1,
            })
            .expect("scan nonmatching alpha");
        assert!(first.deliveries.is_empty());
        assert!(first.has_more);

        let second = node
            .poll(EventPollRequest {
                subscription: subscription.id,
                delivery_limit: 1,
                scan_limit: 1,
            })
            .expect("deliver matching beta");
        assert_eq!(second.deliveries.len(), 1);
        assert_eq!(second.deliveries[0].event.id, beta.id);
        assert_eq!(second.deliveries[0].event.payload, b"beta");
        assert_eq!(second.deliveries[0].attempt, 1);
        assert!(!second.has_more);
    }

    #[test]
    fn reused_operation_with_different_application_contract_fails_closed() {
        let root = TestRoot::new("operation-conflict");
        let mut node = selected_node(&root);
        node.publish(request(b"ops/stable", "ops.alpha", b"asset", b"first"))
            .expect("publish");
        let error = node
            .publish(request(b"ops/stable", "ops.alpha", b"asset", b"different"))
            .expect_err("operation mismatch must fail");
        assert_eq!(error.kind(), ApplicationErrorKind::Conflict);
        assert_eq!(
            node.query(EventQuery::default())
                .expect("query")
                .items
                .len(),
            1
        );
    }

    #[test]
    fn public_facade_restart_reuses_the_exact_durable_operation() {
        let root = TestRoot::new("restart-operation");
        let request = request(b"ops/restart", "ops.alpha", b"asset", b"ready");
        let first = {
            let mut node = selected_node(&root);
            node.publish(request.clone()).expect("initial publication")
        };
        let mut reopened = SelectedEventNode::open_unprotected_reference(
            root.path(),
            root.path().join("mission.unprotected-reference.bundle"),
        )
        .expect("reopen selected Event node");
        let retried = reopened.publish(request).expect("restart retry");
        assert!(!retried.inserted);
        assert_eq!(retried.id, first.id);
        assert_eq!(retried.publisher_counter, first.publisher_counter);
        assert_eq!(retried.event_sequence, first.event_sequence);
        assert_eq!(retried.acceptance_marker, first.acceptance_marker);
    }

    #[test]
    fn query_limits_and_tombstone_payloads_fail_before_publication() {
        let root = TestRoot::new("bounds");
        let mut node = selected_node(&root);
        assert!(
            node.query(EventQuery {
                limit: 0,
                ..EventQuery::default()
            })
            .is_err()
        );
        let mut tombstone = request(b"ops/tombstone", "ops.alpha", b"asset", b"not-empty");
        tombstone.tombstone = true;
        assert!(node.publish(tombstone).is_err());
        assert!(
            node.query(EventQuery::default())
                .expect("query")
                .items
                .is_empty()
        );
    }

    #[test]
    fn unauthorized_topic_fails_without_consuming_publisher_or_stream_position() {
        let root = TestRoot::new("unauthorized-topic");
        let mut node = selected_node(&root);
        let denied_subscription = node
            .subscribe(subscription_request(
                b"subscriptions/denied",
                "ops.unprovisioned",
            ))
            .expect_err("unprovisioned subscription must fail");
        assert_eq!(
            denied_subscription.kind(),
            ApplicationErrorKind::RequestRejected
        );
        let denied = node
            .publish(request(
                b"ops/denied",
                "ops.unprovisioned",
                b"asset",
                b"denied",
            ))
            .expect_err("unprovisioned topic must fail");
        assert_eq!(denied.kind(), ApplicationErrorKind::RequestRejected);
        assert!(std::error::Error::source(&denied).is_none());
        for rendered in [format!("{denied}"), format!("{denied:?}")] {
            assert!(!rendered.contains("source Event"));
            assert!(!rendered.contains("redb"));
            assert!(!rendered.contains("ops.unprovisioned"));
            assert!(!rendered.contains("transfer"));
        }
        let accepted = node
            .publish(request(b"ops/accepted", "ops.alpha", b"asset", b"accepted"))
            .expect("authorized Event");
        assert_eq!(accepted.publisher_counter, 1);
        assert_eq!(accepted.event_sequence, 1);
        assert_eq!(accepted.acceptance_marker, 1);
        assert_eq!(
            node.query(EventQuery::default())
                .expect("query")
                .items
                .len(),
            1
        );
    }
}
