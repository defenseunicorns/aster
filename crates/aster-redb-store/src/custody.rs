//! Mission-bound custody, finite-lifetime, quota, lease, and peer-receipt state.
//!
//! This module is deliberately metadata-only except for the Event and route-only
//! retirement paths which are integrated with their exact redb payload rows.  A
//! custody row never derives elapsed time from wall time.  Finite lifetimes use
//! only an authenticated cumulative age plus elapsed ticks from one continuous
//! local clock domain.  Losing that continuity is sticky for the affected row.

use std::collections::{BTreeMap, BTreeSet, BinaryHeap};
use std::fmt;

use aster_mesh::{CustodySample, NodeId, Priority, Scope, Topic, retry_delay_ms};
use redb::{ReadableTable, ReadableTableMetadata, TableDefinition, TableHandle};

use super::*;

pub(crate) const CUSTODY_ITEMS: TableDefinition<&[u8], &[u8]> =
    TableDefinition::new("aster.custody-items.v1");
pub(crate) const CUSTODY_EXPIRATIONS: TableDefinition<&[u8], &[u8]> =
    TableDefinition::new("aster.custody-expirations.v2");
pub(crate) const CUSTODY_RETIRING: TableDefinition<&[u8], &[u8]> =
    TableDefinition::new("aster.custody-retiring.v2");
pub(crate) const CUSTODY_RETIREMENT_REFERENCES: TableDefinition<&[u8], &[u8]> =
    TableDefinition::new("aster.custody-retirement-references.v3");
pub(crate) const CUSTODY_RETIREMENTS: TableDefinition<&[u8], &[u8]> =
    TableDefinition::new("aster.custody-retirements.v1");
pub(crate) const CUSTODY_RETIRED_SEMANTICS: TableDefinition<&[u8], &[u8]> =
    TableDefinition::new("aster.custody-retired-semantics.v1");
pub(crate) const CUSTODY_LEASES: TableDefinition<u64, &[u8]> =
    TableDefinition::new("aster.custody-transfer-leases.v1");
pub(crate) const CUSTODY_PEER_RECEIPTS: TableDefinition<&[u8], &[u8]> =
    TableDefinition::new("aster.custody-peer-receipts.v1");
pub(crate) const CUSTODY_RETRIES: TableDefinition<&[u8], &[u8]> =
    TableDefinition::new("aster.custody-peer-retries.v1");
pub(crate) const CUSTODY_QUOTAS: TableDefinition<&str, &[u8]> =
    TableDefinition::new("aster.custody-quotas.v1");
pub(crate) const CUSTODY_SCOPE_USAGE: TableDefinition<&str, &[u8]> =
    TableDefinition::new("aster.custody-scope-usage.v1");
pub(crate) const CUSTODY_CONTINUITY: TableDefinition<&str, &[u8]> =
    TableDefinition::new("aster.custody-continuity.v1");
pub(crate) const CUSTODY_DOMAIN: TableDefinition<&str, &[u8]> =
    TableDefinition::new("aster.custody-domain.v1");
pub(crate) const CUSTODY_METADATA: TableDefinition<&str, u64> =
    TableDefinition::new("aster.custody-metadata.v1");

const CUSTODY_SCHEMA_VERSION_KEY: &str = "schema_version";
const CUSTODY_POLICY_REVISION_KEY: &str = "policy_revision";
const CUSTODY_MUTATION_REVISION_KEY: &str = "mutation_revision";
const CUSTODY_ITEM_COUNT_KEY: &str = "item_count";
const CUSTODY_TOTAL_BYTES_KEY: &str = "total_bytes";
const CUSTODY_ORDINARY_ITEM_COUNT_KEY: &str = "ordinary_item_count";
const CUSTODY_ORDINARY_TOTAL_BYTES_KEY: &str = "ordinary_total_bytes";
const CUSTODY_RETIREMENT_COUNT_KEY: &str = "retirement_count";
const CUSTODY_LEASE_COUNT_KEY: &str = "lease_count";
const CUSTODY_RECEIPT_COUNT_KEY: &str = "receipt_count";
const CUSTODY_RETRY_COUNT_KEY: &str = "retry_count";
const CUSTODY_QUOTA_COUNT_KEY: &str = "quota_count";
const CUSTODY_NEXT_LEASE_KEY: &str = "next_lease";
const CUSTODY_RETRY_SEQUENCE_KEY: &str = "retry_sequence";
const CUSTODY_MISSION_AUTHORITY_KEY: &str = "mission_authority";
const CUSTODY_CONTINUITY_KEY: &str = "clock";
const GLOBAL_QUOTA_KEY: &str = "";

const CUSTODY_SCHEMA_VERSION: u64 = 3;
const CUSTODY_ITEM_VERSION: u8 = 1;
const CUSTODY_RETIREMENT_VERSION: u8 = 1;
const CUSTODY_LEASE_LEGACY_VERSION: u8 = 1;
const CUSTODY_LEASE_VERSION: u8 = 2;
const CUSTODY_RECEIPT_LEGACY_VERSION: u8 = 1;
const CUSTODY_RECEIPT_VERSION: u8 = 2;
const CUSTODY_RETRY_VERSION: u8 = 1;
const CUSTODY_QUOTA_VERSION: u8 = 1;
const CUSTODY_CONTINUITY_VERSION: u8 = 1;
const CUSTODY_RETIREMENT_CLEANUP_VERSION: u8 = 1;

/// Maximum permanent retired-transfer fences in one selected store.
///
/// Accepted-dot, stream-position, and operation-key ledgers remain separate
/// permanent authorities.  This explicit cap prevents payload retirement from
/// turning the exact-transfer age high-water into an unbounded side ledger.
pub const MAX_CUSTODY_RETIREMENTS: u64 = 262_144;
/// Maximum concurrently active durable transfer leases.
pub const MAX_CUSTODY_TRANSFER_LEASES: u64 = 4_096;
/// Maximum durable per-peer custody receipts retained as send-suppression hints.
///
/// Receipts are not receiver acceptance authority: exact accepted and retired
/// fences live elsewhere. At this cap the lexicographically smallest retained
/// key is deterministically replaced so a successful remote acknowledgement
/// can always drain its lease/retry; replacement may cause one bounded duplicate
/// offer to the evicted peer but cannot resurrect or lose accepted content.
pub const MAX_CUSTODY_PEER_RECEIPTS: u64 = 262_144;
/// Maximum retained DATA retry records selected by protocol section 18.
pub const MAX_CUSTODY_RETRY_RECORDS: u64 = 128;
const MAX_CUSTODY_RETIREMENT_REFERENCES: u64 = MAX_CUSTODY_TRANSFER_LEASES
    + MAX_CUSTODY_PEER_RECEIPTS
    + MAX_CUSTODY_RETRY_RECORDS
    + MAX_EVENT_ACKNOWLEDGEMENT_RECEIPTS;
/// Maximum global plus scope-specific custody quotas.
pub const MAX_CUSTODY_QUOTAS: u64 = 1_025;
/// Maximum candidates returned by one bounded outbound or collection call.
pub const MAX_CUSTODY_PAGE: usize = 1_024;
/// Maximum dependency units removed or examined by one maintenance transaction.
pub const MAX_CUSTODY_MAINTENANCE_DEPENDENCIES_PER_PASS: u64 = MAX_CUSTODY_PAGE as u64;
/// Maximum retirement queue rows examined by one maintenance transaction.
pub const MAX_CUSTODY_RETIREMENT_SCAN: usize =
    MAX_CUSTODY_PAGE + MAX_CUSTODY_TRANSFER_LEASES as usize;
/// Maximum exact reconciliation difference accepted by one bulk scheduling
/// snapshot. This matches the selected Event lane's hard cardinality bound.
pub const MAX_CUSTODY_BULK_CANDIDATES: usize = 1_000_000;
/// Maximum metadata-only candidates retained by one bulk scheduling snapshot.
pub const MAX_CUSTODY_BULK_SELECTION: usize = 3_500;
/// Additional aggregate item slack retained for durable tombstones after the
/// full mission-control domain is reserved.
pub const CUSTODY_EMERGENCY_ITEM_RESERVE: u64 = 64;
/// Additional aggregate byte slack retained for durable tombstones after the
/// full mission-control domain is reserved.
pub const CUSTODY_EMERGENCY_BYTE_RESERVE: u64 = 64 * 1024;

pub(crate) const fn custody_emergency_reserve(limits: StoreLimits) -> (u64, u64) {
    const fn amount(limit: u64, control: u64, tombstone_slack: u64) -> u64 {
        let required = control.saturating_add(tombstone_slack);
        if required > limit { limit } else { required }
    }
    (
        amount(
            limits.max_items(),
            MAX_CONTROL_ITEMS,
            CUSTODY_EMERGENCY_ITEM_RESERVE,
        ),
        amount(
            limits.max_total_payload_bytes(),
            MAX_CONTROL_BYTES,
            CUSTODY_EMERGENCY_BYTE_RESERVE,
        ),
    )
}

pub(crate) const fn custody_tombstone_allowance(limits: StoreLimits) -> (u64, u64) {
    const fn allowance(limit: u64, control: u64, slack: u64) -> u64 {
        let after_control = limit - if control > limit { limit } else { control };
        if slack > after_control {
            after_control
        } else {
            slack
        }
    }
    (
        allowance(
            limits.max_items(),
            MAX_CONTROL_ITEMS,
            CUSTODY_EMERGENCY_ITEM_RESERVE,
        ),
        allowance(
            limits.max_total_payload_bytes(),
            MAX_CONTROL_BYTES,
            CUSTODY_EMERGENCY_BYTE_RESERVE,
        ),
    )
}

const FLAG_TOMBSTONE: u8 = 1 << 0;
const FLAG_ROUTE_ONLY: u8 = 1 << 1;
const FLAG_RETIRING: u8 = 1 << 2;
const FLAG_CONTINUITY_LOST: u8 = 1 << 3;
const FLAG_PROTECTED_DELIVERY: u8 = 1 << 4;
const FLAG_REQUIRED_CAUSAL: u8 = 1 << 5;
const FLAG_TOMBSTONE_RETENTION: u8 = 1 << 6;
const FLAG_EQUIVOCATION_FENCE: u8 = 1 << 7;

/// Exact selected-store namespace governed by one custody row.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
#[repr(u8)]
pub enum CustodyObjectClass {
    Event = 1,
    RouteEvent = 2,
    State = 3,
    Record = 4,
    Blob = 5,
}

impl CustodyObjectClass {
    fn from_wire(value: u8) -> Result<Self, CustodyStoreError> {
        match value {
            1 => Ok(Self::Event),
            2 => Ok(Self::RouteEvent),
            3 => Ok(Self::State),
            4 => Ok(Self::Record),
            5 => Ok(Self::Blob),
            _ => Err(CustodyStoreError::Invariant(
                "custody object key contains an unknown class",
            )),
        }
    }
}

/// Class-separated exact transfer key for custody policy.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct CustodyObjectKey {
    class: CustodyObjectClass,
    transfer_id: [u8; 32],
}

impl CustodyObjectKey {
    pub const fn new(class: CustodyObjectClass, transfer_id: [u8; 32]) -> Self {
        Self { class, transfer_id }
    }

    pub const fn event(transfer_id: EventTransferId) -> Self {
        Self::new(CustodyObjectClass::Event, *transfer_id.as_bytes())
    }

    pub const fn route_event(transfer_id: EventTransferId) -> Self {
        Self::new(CustodyObjectClass::RouteEvent, *transfer_id.as_bytes())
    }

    pub const fn class(self) -> CustodyObjectClass {
        self.class
    }

    pub const fn transfer_id(self) -> [u8; 32] {
        self.transfer_id
    }

    fn encoded(self) -> [u8; 33] {
        let mut encoded = [0u8; 33];
        encoded[0] = self.class as u8;
        encoded[1..].copy_from_slice(&self.transfer_id);
        encoded
    }

    fn decode(bytes: &[u8]) -> Result<Self, CustodyStoreError> {
        let bytes: [u8; 33] = bytes
            .try_into()
            .map_err(|_| CustodyStoreError::Invariant("custody object key has invalid length"))?;
        Ok(Self {
            class: CustodyObjectClass::from_wire(bytes[0])?,
            transfer_id: bytes[1..].try_into().expect("fixed key suffix"),
        })
    }
}

fn opposite_event_key(key: CustodyObjectKey) -> Option<CustodyObjectKey> {
    let transfer_id = EventTransferId::new(key.transfer_id);
    match key.class {
        CustodyObjectClass::Event => Some(CustodyObjectKey::route_event(transfer_id)),
        CustodyObjectClass::RouteEvent => Some(CustodyObjectKey::event(transfer_id)),
        CustodyObjectClass::State | CustodyObjectClass::Record | CustodyObjectClass::Blob => None,
    }
}

/// Eviction protections retained independently of publisher priority.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct CustodyProtection {
    delivery: bool,
    required_causal: bool,
    tombstone_retention: bool,
    equivocation_fence: bool,
}

impl CustodyProtection {
    pub const NONE: Self = Self {
        delivery: false,
        required_causal: false,
        tombstone_retention: false,
        equivocation_fence: false,
    };

    pub const fn new(
        delivery: bool,
        required_causal: bool,
        tombstone_retention: bool,
        equivocation_fence: bool,
    ) -> Self {
        Self {
            delivery,
            required_causal,
            tombstone_retention,
            equivocation_fence,
        }
    }

    pub const fn protects_eviction(self) -> bool {
        self.delivery || self.required_causal || self.tombstone_retention || self.equivocation_fence
    }
}

/// Persisted global or scope-specific logical payload quota.
///
/// Caller-configured quotas are nonzero. The global quota derived from
/// [`StoreLimits`] may be zero in one dimension when the aggregate bound is so
/// small that its sole unit must remain reserved for control or tombstone
/// authority; that intentionally admits no ordinary custody row.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CustodyQuota {
    scope: Option<Scope>,
    max_items: u64,
    max_bytes: u64,
}

impl CustodyQuota {
    pub fn global(max_items: u64, max_bytes: u64) -> Result<Self, CustodyStoreError> {
        Self::new(None, max_items, max_bytes)
    }

    pub fn for_scope(
        scope: Scope,
        max_items: u64,
        max_bytes: u64,
    ) -> Result<Self, CustodyStoreError> {
        Self::new(Some(scope), max_items, max_bytes)
    }

    /// Derives the ordinary-data ceiling while retaining the bounded
    /// aggregate reserve used by control, key, and tombstone authority. Limits
    /// of one therefore produce a zero ordinary ceiling rather than silently
    /// dropping the emergency reserve.
    pub fn for_store_limits(limits: StoreLimits) -> Result<Self, CustodyStoreError> {
        let (item_reserve, byte_reserve) = custody_emergency_reserve(limits);
        Ok(Self {
            scope: None,
            max_items: limits.max_items().checked_sub(item_reserve).ok_or(
                CustodyStoreError::Invariant("custody item reserve exceeds aggregate limit"),
            )?,
            max_bytes: limits
                .max_total_payload_bytes()
                .checked_sub(byte_reserve)
                .ok_or(CustodyStoreError::Invariant(
                    "custody byte reserve exceeds aggregate limit",
                ))?,
        })
    }

    fn new(
        scope: Option<Scope>,
        max_items: u64,
        max_bytes: u64,
    ) -> Result<Self, CustodyStoreError> {
        if max_items == 0 || max_bytes == 0 {
            return Err(CustodyStoreError::InvalidQuota);
        }
        Ok(Self {
            scope,
            max_items,
            max_bytes,
        })
    }

    pub const fn scope(&self) -> Option<&Scope> {
        self.scope.as_ref()
    }

    pub const fn max_items(&self) -> u64 {
        self.max_items
    }

    pub const fn max_bytes(&self) -> u64 {
        self.max_bytes
    }
}

/// Current exact logical payload accounting for custody-managed rows.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct CustodyUsage {
    pub items: u64,
    pub bytes: u64,
}

/// Bounded item/byte budget for one deterministic outbound projection.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CustodyOutboundBudget {
    pub max_items: usize,
    pub max_bytes: u64,
}

/// Evidence carried by one bounded peer reconciliation candidate set.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CustodyReconciliationEvidence {
    /// No authenticated peer-held baseline is available. Durable receipts
    /// remain authoritative only while bound to this exact opaque selector
    /// generation.
    Blind(CustodyPeerSelectorRevision),
    /// An authenticated negotiation states that every supplied transfer is
    /// missing for the peer's current receive disposition. A receipt may be
    /// invalidated only if that exact object is selected for reoffer.
    AuthenticatedPeerMissing(CustodyPeerSelectorRevision),
}

impl CustodyReconciliationEvidence {
    fn receipt_suppresses(self, receipt: ReceiptRecord) -> bool {
        matches!(self, Self::Blind(revision) if receipt.peer_selector_revision == Some(revision.0))
    }
}

/// Opaque authenticated generation of a peer's receive selector projection.
///
/// Zero is the canonical empty/default generation. The value reveals no
/// selector mode or content; it only scopes durable send-suppression receipts.
#[derive(Clone, Copy, Debug, Default, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct CustodyPeerSelectorRevision(u64);

impl CustodyPeerSelectorRevision {
    pub const fn new(value: u64) -> Self {
        Self(value)
    }

    pub const fn value(self) -> u64 {
        self.0
    }
}

/// Receiver-authenticated outcome for a completed semantic-v3 custody offer.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CustodyPeerApplyDisposition {
    /// The receiver retained the exact transfer in the class required by its
    /// current policy, so a durable suppression receipt is sound.
    Satisfied,
    /// The receiver retained only route-verifiable bytes while its current
    /// policy requires content acceptance. The send completed, but bounded
    /// retry/backoff must remain available for a later key-driven promotion.
    ContentAcceptancePending,
}

/// Receiver-authenticated disposition and opaque selector generation bound to
/// one semantic-v3 apply result.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CustodyPeerApplyEvidence {
    disposition: CustodyPeerApplyDisposition,
    selector_revision: CustodyPeerSelectorRevision,
}

impl CustodyPeerApplyEvidence {
    pub const fn new(
        disposition: CustodyPeerApplyDisposition,
        selector_revision: CustodyPeerSelectorRevision,
    ) -> Self {
        Self {
            disposition,
            selector_revision,
        }
    }

    pub const fn disposition(self) -> CustodyPeerApplyDisposition {
        self.disposition
    }

    pub const fn selector_revision(self) -> CustodyPeerSelectorRevision {
        self.selector_revision
    }
}

/// Scheduling policy for one authenticated or blind reconciliation set.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CustodyReconciliationSelection {
    minimum_priority: Priority,
    evidence: CustodyReconciliationEvidence,
}

impl CustodyReconciliationSelection {
    pub const fn new(minimum_priority: Priority, evidence: CustodyReconciliationEvidence) -> Self {
        Self {
            minimum_priority,
            evidence,
        }
    }

    pub const fn minimum_priority(self) -> Priority {
        self.minimum_priority
    }

    pub const fn evidence(self) -> CustodyReconciliationEvidence {
        self.evidence
    }
}

/// Capacity requested by one pressure collection decision.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CustodyPressureDemand {
    pub usage: CustodyUsage,
    pub priority: Priority,
}

#[derive(Clone, Copy)]
pub(crate) struct AggregateCapacityRequest {
    pub usage: CustodyUsage,
    pub priority: Priority,
    pub emergency: bool,
    pub continuity: Option<ContinuityRecord>,
    pub sample: Option<CustodySample>,
}

/// Mutation generation captured by admission, send, and collection plans.
#[derive(Clone, Copy, Debug, Default, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct CustodyPolicyRevision(u64);

impl CustodyPolicyRevision {
    pub const fn value(self) -> u64 {
        self.0
    }
}

/// Immutable metadata required to admit one source-authenticated object.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CustodyAdmission {
    pub key: CustodyObjectKey,
    pub semantic_id: [u8; 32],
    pub topic: Topic,
    pub scope: Scope,
    pub source_publisher: NodeId,
    pub key_epoch: u64,
    pub priority: Priority,
    pub ttl_ms: Option<u64>,
    pub tombstone: bool,
    pub route_only: bool,
    pub accounted_bytes: u64,
    pub authenticated_age_ms: u64,
    pub sample: Option<CustodySample>,
    pub acceptance_order: u64,
    pub protection: CustodyProtection,
}

impl CustodyAdmission {
    pub(crate) fn validate(&self) -> Result<(), CustodyStoreError> {
        if self.accounted_bytes == 0 || self.acceptance_order == 0 {
            return Err(CustodyStoreError::InvalidAdmission(
                "accounted bytes and acceptance order must be nonzero",
            ));
        }
        if self.route_only != (self.key.class == CustodyObjectClass::RouteEvent) {
            return Err(CustodyStoreError::InvalidAdmission(
                "route-only flag differs from the custody object class",
            ));
        }
        if self.ttl_ms.is_some() && !self.tombstone && self.sample.is_none() {
            return Err(CustodyStoreError::ContinuityUnavailable);
        }
        Ok(())
    }
}

/// Durable finite-lifetime evaluation at one exact store operation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CustodyAgeStatus {
    Durable,
    Forwardable { age_ms: u64, remaining_ms: u64 },
    Expired { age_ms: u64 },
    WithheldUnknownAge,
}

/// Snapshot status used by every sender path, including semantic versions
/// which do not carry finite-lifetime claims on the wire.  `Retiring` is a
/// receiver-only suppression state: retained bytes may exist for lease drain,
/// but they are never public send authority.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CustodySenderStatus {
    Age(CustodyAgeStatus),
    Retiring,
    Retired { age_ms: u64 },
}

impl CustodySenderStatus {
    pub const fn is_sendable(self) -> bool {
        matches!(
            self,
            Self::Age(CustodyAgeStatus::Durable | CustodyAgeStatus::Forwardable { .. })
        )
    }
}

/// Result of idempotently inserting or updating one custody row.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CustodyAdmissionOutcome {
    Inserted,
    Duplicate { durable_age_ms: u64 },
    AlreadyRetired { durable_age_ms: u64 },
}

/// Durable transfer-lease identifier.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct TransferLeaseId(u64);

impl TransferLeaseId {
    pub const fn value(self) -> u64 {
        self.0
    }
}

/// One exact async-send guard created only after policy and age rechecks.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TransferLease {
    pub id: TransferLeaseId,
    pub object: CustodyObjectKey,
    pub peer: NodeId,
    pub age_ms: u64,
    pub sample: CustodySample,
    pub priority: Priority,
    pub policy_revision: CustodyPolicyRevision,
    pub peer_selector_revision: CustodyPeerSelectorRevision,
}

/// One bounded outbound candidate ordered by priority and expiry urgency.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CustodyOutbound {
    pub object: CustodyObjectKey,
    pub semantic_id: [u8; 32],
    pub priority: Priority,
    pub age_ms: u64,
    pub remaining_ms: Option<u64>,
    pub accounted_bytes: u64,
    pub acceptance_order: u64,
}

/// One metadata-only sender projection checked against the paired exact Event
/// or route representation in the same policy and continuity snapshot.
///
/// These fields narrow a freshly verified in-memory source capability; they
/// never replace source-envelope verification or confer send authority alone.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CustodySenderProjection {
    object: CustodyObjectKey,
    semantic_id: [u8; 32],
    source_publisher: NodeId,
    topic: Topic,
    scope: Scope,
    key_epoch: u64,
    priority: Priority,
    ttl_ms: Option<u64>,
    tombstone: bool,
    accounted_bytes: u64,
    acceptance_order: u64,
    status: CustodyAgeStatus,
}

impl CustodySenderProjection {
    pub const fn object(&self) -> CustodyObjectKey {
        self.object
    }

    pub const fn semantic_id(&self) -> [u8; 32] {
        self.semantic_id
    }

    pub const fn source_publisher(&self) -> NodeId {
        self.source_publisher
    }

    pub const fn topic(&self) -> &Topic {
        &self.topic
    }

    pub const fn scope(&self) -> &Scope {
        &self.scope
    }

    pub const fn key_epoch(&self) -> u64 {
        self.key_epoch
    }

    pub const fn priority(&self) -> Priority {
        self.priority
    }

    pub const fn ttl_ms(&self) -> Option<u64> {
        self.ttl_ms
    }

    pub const fn tombstone(&self) -> bool {
        self.tombstone
    }

    pub const fn accounted_bytes(&self) -> u64 {
        self.accounted_bytes
    }

    pub const fn acceptance_order(&self) -> u64 {
        self.acceptance_order
    }

    pub const fn status(&self) -> CustodyAgeStatus {
        self.status
    }
}

type CustodyOutboundOrder = (std::cmp::Reverse<Priority>, u64, u64, CustodyObjectKey);

fn custody_outbound_order(candidate: &CustodyOutbound) -> CustodyOutboundOrder {
    (
        std::cmp::Reverse(candidate.priority),
        candidate.remaining_ms.unwrap_or(u64::MAX),
        candidate.acceptance_order,
        candidate.object,
    )
}

#[derive(Eq, PartialEq)]
struct RankedCustodyOutbound {
    order: CustodyOutboundOrder,
    candidate: CustodyOutbound,
}

impl Ord for RankedCustodyOutbound {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.order.cmp(&other.order)
    }
}

impl PartialOrd for RankedCustodyOutbound {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

pub(crate) fn bulk_custody_lookup_visits(candidate_count: usize, item_count: u64) -> u64 {
    let direct = u64::try_from(candidate_count)
        .unwrap_or(u64::MAX)
        .saturating_mul(2);
    direct.min(item_count)
}

struct BulkCustodySelection<'table, 'transaction> {
    receipts: &'table redb::Table<'transaction, &'static [u8], &'static [u8]>,
    retries: &'table redb::Table<'transaction, &'static [u8], &'static [u8]>,
    best: std::collections::BinaryHeap<RankedCustodyOutbound>,
    max_items: usize,
    peer: NodeId,
    minimum_priority: Priority,
    continuity: Option<ContinuityRecord>,
    sample: Option<CustodySample>,
    evidence: CustodyReconciliationEvidence,
}

impl<'table, 'transaction> BulkCustodySelection<'table, 'transaction> {
    fn consider(
        &mut self,
        key: CustodyObjectKey,
        record: CustodyItemRecord,
    ) -> Result<(), StoreError> {
        if record.retiring || record.priority < self.minimum_priority {
            return Ok(());
        }
        let peer_key = peer_object_key(self.peer, key);
        if let Some(receipt) = self
            .receipts
            .get(peer_key.as_slice())?
            .map(|value| decode_receipt(value.value()))
            .transpose()?
            && self.evidence.receipt_suppresses(receipt)
        {
            return Ok(());
        }
        if let Some(retry) = self
            .retries
            .get(peer_key.as_slice())?
            .map(|value| decode_retry(value.value()))
            .transpose()?
            && !self.sample.is_some_and(|sample| {
                sample.clock_id == retry.clock_id && sample.tick_ms >= retry.due_tick_ms
            })
        {
            return Ok(());
        }
        let (status, _) = evaluate_item(&record, self.continuity, self.sample);
        let (age_ms, remaining_ms) = match status {
            CustodyAgeStatus::Durable => (record.cumulative_age_ms, None),
            CustodyAgeStatus::Forwardable {
                age_ms,
                remaining_ms,
            } => (age_ms, Some(remaining_ms)),
            CustodyAgeStatus::Expired { .. } | CustodyAgeStatus::WithheldUnknownAge => {
                return Ok(());
            }
        };
        let candidate = CustodyOutbound {
            object: key,
            semantic_id: record.semantic_id,
            priority: record.priority,
            age_ms,
            remaining_ms,
            accounted_bytes: record.accounted_bytes,
            acceptance_order: record.acceptance_order,
        };
        let ranked = RankedCustodyOutbound {
            order: custody_outbound_order(&candidate),
            candidate,
        };
        if self.best.len() < self.max_items {
            self.best.push(ranked);
        } else if self
            .best
            .peek()
            .is_some_and(|worst| ranked.order < worst.order)
        {
            self.best.pop();
            self.best.push(ranked);
        }
        Ok(())
    }

    fn into_sorted(self) -> Vec<RankedCustodyOutbound> {
        let mut selected = self.best.into_vec();
        selected.sort_by_key(|candidate| candidate.order);
        selected
    }
}

/// Last-moment send authority bound to the exact effective custody checkpoint.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CustodySendAuthorization {
    pub age_ms: u64,
    pub sample: Option<CustodySample>,
}

/// Compact receiver-only reconciliation state retained while retirement is
/// pending and after the exact logical payload row is removed. It carries
/// interest metadata but confers no send or payload lookup authority and makes
/// no claim about physical media erasure or immediate page reclamation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CustodyReceiverFence {
    pub object: CustodyObjectKey,
    pub semantic_id: [u8; 32],
    pub topic: Topic,
    pub scope: Scope,
    pub source_publisher: NodeId,
    pub key_epoch: u64,
    pub reason: CustodyRetirementReason,
}

/// Reason a logical payload row entered permanent retirement.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum CustodyRetirementReason {
    Expired = 1,
    QuotaPressure = 2,
}

/// Bounded result of one garbage-collection transaction.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct CustodyGcReport {
    pub examined_expirations: u64,
    pub examined_retirements: u64,
    pub examined_candidates: u64,
    pub lease_probes: u64,
    pub examined_dependencies: u64,
    pub removed_pairs: u64,
    pub examined_numbered_results: u64,
    pub rewritten_numbered_results: u64,
    pub marked: Vec<CustodyObjectKey>,
    pub retired: Vec<CustodyObjectKey>,
    pub released_bytes: u64,
    pub blocked_by_leases: u64,
}

/// One custody collection attempt paired with its exact durable writer count.
///
/// The result may be an error after a policy-significant continuity transition
/// was deliberately committed. Callers that retry maintenance can therefore
/// account for every redb commit without inferring it from the report.
pub struct CustodyCollectionAttempt {
    result: Result<CustodyGcReport, StoreError>,
    writer_commits: u64,
}

impl CustodyCollectionAttempt {
    /// Returns the exact number of redb writer transactions committed.
    pub const fn writer_commits(&self) -> u64 {
        self.writer_commits
    }

    /// Consumes the attempt and returns its collection report or exact error.
    pub fn into_result(self) -> Result<CustodyGcReport, StoreError> {
        self.result
    }
}

/// Structurally audited custody-schema counts.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct CustodyStoreStats {
    pub items: u64,
    pub bytes: u64,
    pub retirements: u64,
    pub transfer_leases: u64,
    pub peer_receipts: u64,
    pub retries: u64,
    pub quotas: u64,
    pub policy_revision: CustodyPolicyRevision,
    pub mutation_revision: u64,
}

/// Custody schema, continuity, capacity, or stale-plan failure.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum CustodyStoreError {
    InvalidQuota,
    InvalidAdmission(&'static str),
    MissionNotBound,
    MissionMismatch,
    ContinuityUnavailable,
    ContinuityLost,
    AgeOverflow,
    Expired,
    AlreadyRetired,
    Retiring,
    Protected,
    PolicyChanged,
    ItemChanged,
    ItemNotFound,
    LeaseNotFound,
    LeaseLimitExceeded {
        current: u64,
        limit: u64,
    },
    ReceiptLimitExceeded {
        current: u64,
        limit: u64,
    },
    RetryLimitExceeded {
        current: u64,
        limit: u64,
    },
    RetryNotDue {
        current: u64,
        due: u64,
    },
    RetirementLimitExceeded {
        current: u64,
        limit: u64,
    },
    QuotaLimitExceeded {
        current: u64,
        limit: u64,
    },
    ItemQuotaExceeded {
        current: u64,
        incoming: u64,
        limit: u64,
    },
    ByteQuotaExceeded {
        current: u64,
        incoming: u64,
        limit: u64,
    },
    PageLimitExceeded {
        requested: usize,
        maximum: usize,
    },
    CounterOverflow,
    UnsupportedSchemaVersion {
        found: u64,
        supported: u64,
    },
    UnsupportedRetirementClass(CustodyObjectClass),
    LegacyCustodyMigrationRequired,
    Invariant(&'static str),
}

impl fmt::Display for CustodyStoreError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidQuota => formatter.write_str("explicit custody quotas must be nonzero"),
            Self::InvalidAdmission(reason) => {
                write!(formatter, "invalid custody admission: {reason}")
            }
            Self::MissionNotBound => {
                formatter.write_str("custody state requires a mission-bound store")
            }
            Self::MissionMismatch => {
                formatter.write_str("custody schema belongs to another mission")
            }
            Self::ContinuityUnavailable => {
                formatter.write_str("finite TTL requires a continuous local custody sample")
            }
            Self::ContinuityLost => formatter.write_str("finite-TTL custody continuity is lost"),
            Self::AgeOverflow => formatter.write_str("custody age arithmetic overflowed"),
            Self::Expired => {
                formatter.write_str("custody age is at or beyond the authenticated TTL")
            }
            Self::AlreadyRetired => formatter.write_str("exact transfer is permanently retired"),
            Self::Retiring => formatter.write_str("exact transfer is marked for retirement"),
            Self::Protected => formatter.write_str("custody object is protected from eviction"),
            Self::PolicyChanged => formatter.write_str("custody policy revision changed"),
            Self::ItemChanged => formatter.write_str("custody object revision changed"),
            Self::ItemNotFound => formatter.write_str("custody object was not found"),
            Self::LeaseNotFound => formatter.write_str("transfer lease was not found"),
            Self::LeaseLimitExceeded { current, limit } => write!(
                formatter,
                "custody lease count {current} is at limit {limit}"
            ),
            Self::ReceiptLimitExceeded { current, limit } => write!(
                formatter,
                "peer receipt count {current} is at limit {limit}"
            ),
            Self::RetryLimitExceeded { current, limit } => {
                write!(formatter, "retry count {current} is at limit {limit}")
            }
            Self::RetryNotDue { current, due } => write!(
                formatter,
                "custody retry tick {current} is before monotonic deadline {due}"
            ),
            Self::RetirementLimitExceeded { current, limit } => {
                write!(formatter, "retirement count {current} is at limit {limit}")
            }
            Self::QuotaLimitExceeded { current, limit } => write!(
                formatter,
                "custody quota count {current} is at limit {limit}"
            ),
            Self::ItemQuotaExceeded {
                current,
                incoming,
                limit,
            } => write!(
                formatter,
                "custody item usage {current} cannot admit {incoming} under limit {limit}"
            ),
            Self::ByteQuotaExceeded {
                current,
                incoming,
                limit,
            } => write!(
                formatter,
                "custody byte usage {current} cannot admit {incoming} under limit {limit}"
            ),
            Self::PageLimitExceeded { requested, maximum } => write!(
                formatter,
                "custody page limit {requested} exceeds {maximum}"
            ),
            Self::CounterOverflow => formatter.write_str("custody accounting counter overflowed"),
            Self::UnsupportedSchemaVersion { found, supported } => write!(
                formatter,
                "custody schema version {found} is unsupported; recreate the store for version {supported}"
            ),
            Self::UnsupportedRetirementClass(class) => write!(
                formatter,
                "payload retirement for {class:?} is not selected"
            ),
            Self::LegacyCustodyMigrationRequired => {
                formatter.write_str("legacy custody state requires a writable migration")
            }
            Self::Invariant(reason) => {
                write!(formatter, "custody schema invariant failed: {reason}")
            }
        }
    }
}

impl std::error::Error for CustodyStoreError {}

#[derive(Clone, Debug, Eq, PartialEq)]
struct CustodyItemRecord {
    semantic_id: [u8; 32],
    topic: Topic,
    scope: Scope,
    source_publisher: NodeId,
    key_epoch: u64,
    priority: Priority,
    ttl_ms: Option<u64>,
    tombstone: bool,
    route_only: bool,
    retiring: bool,
    continuity_lost: bool,
    protection: CustodyProtection,
    accounted_bytes: u64,
    cumulative_age_ms: u64,
    checkpoint: Option<CustodySample>,
    continuity_generation: u64,
    acceptance_order: u64,
    revision: u64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct RetirementRecord {
    semantic_id: [u8; 32],
    topic: Topic,
    scope: Scope,
    source_publisher: NodeId,
    key_epoch: u64,
    reason: CustodyRetirementReason,
    cumulative_age_ms: u64,
    accounted_bytes: u64,
    acceptance_order: u64,
    retired_revision: u64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct LeaseRecord {
    object: CustodyObjectKey,
    peer: NodeId,
    item_revision: u64,
    policy_revision: u64,
    age_ms: u64,
    priority: Priority,
    peer_selector_revision: Option<u64>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct ContinuityRecord {
    generation: u64,
    sample: CustodySample,
}

impl ContinuityRecord {
    pub(crate) const fn sample(self) -> CustodySample {
        self.sample
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct ReceiptRecord {
    cumulative_age_ms: u64,
    item_revision: u64,
    peer_selector_revision: Option<u64>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct RetryRecord {
    attempts: u64,
    item_revision: u64,
    policy_revision: u64,
    clock_id: [u8; 16],
    due_tick_ms: u64,
    priority: Priority,
}

fn quota_key(scope: Option<&Scope>) -> &str {
    scope.map_or(GLOBAL_QUOTA_KEY, Scope::as_str)
}

fn encode_scope_usage(usage: CustodyUsage) -> [u8; 16] {
    let mut encoded = [0u8; 16];
    encoded[..8].copy_from_slice(&usage.items.to_be_bytes());
    encoded[8..].copy_from_slice(&usage.bytes.to_be_bytes());
    encoded
}

fn decode_scope_usage(bytes: &[u8]) -> Result<CustodyUsage, CustodyStoreError> {
    let bytes: [u8; 16] = bytes
        .try_into()
        .map_err(|_| CustodyStoreError::Invariant("custody scope usage has invalid length"))?;
    let usage = CustodyUsage {
        items: u64::from_be_bytes(bytes[..8].try_into().expect("fixed item count")),
        bytes: u64::from_be_bytes(bytes[8..].try_into().expect("fixed byte count")),
    };
    if usage.items == 0 || usage.bytes == 0 {
        return Err(CustodyStoreError::Invariant(
            "custody scope usage contains an empty row",
        ));
    }
    Ok(usage)
}

fn encode_quota(quota: &CustodyQuota) -> Vec<u8> {
    let mut encoded = Vec::with_capacity(17);
    encoded.push(CUSTODY_QUOTA_VERSION);
    encoded.extend_from_slice(&quota.max_items.to_be_bytes());
    encoded.extend_from_slice(&quota.max_bytes.to_be_bytes());
    encoded
}

fn decode_quota(key: &str, bytes: &[u8]) -> Result<CustodyQuota, CustodyStoreError> {
    let mut cursor = CustodyCursor::new(bytes);
    if cursor.u8()? != CUSTODY_QUOTA_VERSION {
        return Err(CustodyStoreError::Invariant(
            "unknown custody quota version",
        ));
    }
    let max_items = cursor.u64()?;
    let max_bytes = cursor.u64()?;
    cursor.finish()?;
    let scope = if key.is_empty() {
        None
    } else {
        Some(
            Scope::new(key)
                .map_err(|_| CustodyStoreError::Invariant("invalid custody quota scope"))?,
        )
    };
    let quota = if scope.is_none() {
        CustodyQuota {
            scope,
            max_items,
            max_bytes,
        }
    } else {
        CustodyQuota::new(scope, max_items, max_bytes)?
    };
    if encode_quota(&quota).as_slice() != bytes {
        return Err(CustodyStoreError::Invariant(
            "custody quota is not canonical",
        ));
    }
    Ok(quota)
}

fn encode_continuity(record: ContinuityRecord) -> Vec<u8> {
    let mut encoded = Vec::with_capacity(33);
    encoded.push(CUSTODY_CONTINUITY_VERSION);
    encoded.extend_from_slice(&record.generation.to_be_bytes());
    encoded.extend_from_slice(&record.sample.clock_id);
    encoded.extend_from_slice(&record.sample.tick_ms.to_be_bytes());
    encoded
}

fn decode_continuity(bytes: &[u8]) -> Result<ContinuityRecord, CustodyStoreError> {
    let mut cursor = CustodyCursor::new(bytes);
    if cursor.u8()? != CUSTODY_CONTINUITY_VERSION {
        return Err(CustodyStoreError::Invariant(
            "unknown custody continuity version",
        ));
    }
    let generation = cursor.u64()?;
    let clock_id = cursor.array()?;
    let tick_ms = cursor.u64()?;
    cursor.finish()?;
    if generation == 0 {
        return Err(CustodyStoreError::Invariant(
            "custody continuity generation is zero",
        ));
    }
    Ok(ContinuityRecord {
        generation,
        sample: CustodySample { clock_id, tick_ms },
    })
}

fn item_flags(record: &CustodyItemRecord) -> u8 {
    let mut flags = 0;
    for (present, flag) in [
        (record.tombstone, FLAG_TOMBSTONE),
        (record.route_only, FLAG_ROUTE_ONLY),
        (record.retiring, FLAG_RETIRING),
        (record.continuity_lost, FLAG_CONTINUITY_LOST),
        (record.protection.delivery, FLAG_PROTECTED_DELIVERY),
        (record.protection.required_causal, FLAG_REQUIRED_CAUSAL),
        (
            record.protection.tombstone_retention,
            FLAG_TOMBSTONE_RETENTION,
        ),
        (
            record.protection.equivocation_fence,
            FLAG_EQUIVOCATION_FENCE,
        ),
    ] {
        if present {
            flags |= flag;
        }
    }
    flags
}

fn encode_item(record: &CustodyItemRecord) -> Result<Vec<u8>, CustodyStoreError> {
    let topic = record.topic.as_str().as_bytes();
    let topic_len = u16::try_from(topic.len())
        .map_err(|_| CustodyStoreError::Invariant("custody topic exceeds encoding bound"))?;
    let scope = record.scope.as_str().as_bytes();
    let scope_len = u16::try_from(scope.len())
        .map_err(|_| CustodyStoreError::Invariant("custody scope exceeds encoding bound"))?;
    let mut encoded = Vec::with_capacity(114 + topic.len() + scope.len());
    encoded.push(CUSTODY_ITEM_VERSION);
    encoded.extend_from_slice(&record.semantic_id);
    encoded.extend_from_slice(&topic_len.to_be_bytes());
    encoded.extend_from_slice(topic);
    encoded.extend_from_slice(&scope_len.to_be_bytes());
    encoded.extend_from_slice(scope);
    encoded.extend_from_slice(&record.source_publisher);
    encoded.extend_from_slice(&record.key_epoch.to_be_bytes());
    encoded.push(record.priority as u8);
    encoded.push(item_flags(record));
    match record.ttl_ms {
        Some(ttl) => {
            encoded.push(1);
            encoded.extend_from_slice(&ttl.to_be_bytes());
        }
        None => encoded.push(0),
    }
    encoded.extend_from_slice(&record.accounted_bytes.to_be_bytes());
    encoded.extend_from_slice(&record.cumulative_age_ms.to_be_bytes());
    match record.checkpoint {
        Some(sample) => {
            encoded.push(1);
            encoded.extend_from_slice(&sample.clock_id);
            encoded.extend_from_slice(&sample.tick_ms.to_be_bytes());
        }
        None => encoded.push(0),
    }
    encoded.extend_from_slice(&record.continuity_generation.to_be_bytes());
    encoded.extend_from_slice(&record.acceptance_order.to_be_bytes());
    encoded.extend_from_slice(&record.revision.to_be_bytes());
    Ok(encoded)
}

fn decode_item(bytes: &[u8]) -> Result<CustodyItemRecord, CustodyStoreError> {
    let mut cursor = CustodyCursor::new(bytes);
    if cursor.u8()? != CUSTODY_ITEM_VERSION {
        return Err(CustodyStoreError::Invariant("unknown custody item version"));
    }
    let semantic_id = cursor.array()?;
    let topic_len = usize::from(cursor.u16()?);
    let topic_text = std::str::from_utf8(cursor.take(topic_len)?)
        .map_err(|_| CustodyStoreError::Invariant("custody topic is not UTF-8"))?;
    let topic = Topic::new(topic_text)
        .map_err(|_| CustodyStoreError::Invariant("custody topic is invalid"))?;
    let scope_len = usize::from(cursor.u16()?);
    let scope_text = std::str::from_utf8(cursor.take(scope_len)?)
        .map_err(|_| CustodyStoreError::Invariant("custody scope is not UTF-8"))?;
    let scope = Scope::new(scope_text)
        .map_err(|_| CustodyStoreError::Invariant("custody scope is invalid"))?;
    let source_publisher = cursor.array()?;
    let key_epoch = cursor.u64()?;
    let priority = Priority::from_wire(cursor.u8()?)
        .ok_or(CustodyStoreError::Invariant("custody priority is unknown"))?;
    let flags = cursor.u8()?;
    let ttl_ms = match cursor.u8()? {
        0 => None,
        1 => Some(cursor.u64()?),
        _ => return Err(CustodyStoreError::Invariant("invalid custody TTL flag")),
    };
    let accounted_bytes = cursor.u64()?;
    let cumulative_age_ms = cursor.u64()?;
    let checkpoint = match cursor.u8()? {
        0 => None,
        1 => Some(CustodySample {
            clock_id: cursor.array()?,
            tick_ms: cursor.u64()?,
        }),
        _ => {
            return Err(CustodyStoreError::Invariant(
                "invalid custody checkpoint flag",
            ));
        }
    };
    let continuity_generation = cursor.u64()?;
    let acceptance_order = cursor.u64()?;
    let revision = cursor.u64()?;
    cursor.finish()?;
    if accounted_bytes == 0 || acceptance_order == 0 || revision == 0 {
        return Err(CustodyStoreError::Invariant(
            "custody item contains a zero bound or revision",
        ));
    }
    let record = CustodyItemRecord {
        semantic_id,
        topic,
        scope,
        source_publisher,
        key_epoch,
        priority,
        ttl_ms,
        tombstone: flags & FLAG_TOMBSTONE != 0,
        route_only: flags & FLAG_ROUTE_ONLY != 0,
        retiring: flags & FLAG_RETIRING != 0,
        continuity_lost: flags & FLAG_CONTINUITY_LOST != 0,
        protection: CustodyProtection {
            delivery: flags & FLAG_PROTECTED_DELIVERY != 0,
            required_causal: flags & FLAG_REQUIRED_CAUSAL != 0,
            tombstone_retention: flags & FLAG_TOMBSTONE_RETENTION != 0,
            equivocation_fence: flags & FLAG_EQUIVOCATION_FENCE != 0,
        },
        accounted_bytes,
        cumulative_age_ms,
        checkpoint,
        continuity_generation,
        acceptance_order,
        revision,
    };
    if record.ttl_ms.is_some()
        && !record.tombstone
        && !record.retiring
        && (record.checkpoint.is_some() != (record.continuity_generation != 0))
        && !(record.continuity_lost
            && record.checkpoint.is_none()
            && record.continuity_generation != 0)
    {
        return Err(CustodyStoreError::Invariant(
            "finite custody checkpoint and generation differ",
        ));
    }
    if record.ttl_ms.is_some()
        && !record.tombstone
        && !record.retiring
        && !record.continuity_lost
        && (record.checkpoint.is_none() || record.continuity_generation == 0)
    {
        return Err(CustodyStoreError::Invariant(
            "finite custody item lacks a continuous checkpoint",
        ));
    }
    if encode_item(&record)?.as_slice() != bytes {
        return Err(CustodyStoreError::Invariant(
            "custody item is not canonical",
        ));
    }
    Ok(record)
}

const CUSTODY_EXPIRATION_KEY_LEN: usize = 8 + 16 + 8 + 33;
const CUSTODY_RETIRING_KEY_LEN: usize = 8 + 33;

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct RetirementCleanupRecord {
    pub(crate) original_revision: u64,
    pub(crate) priority: Priority,
    pub(crate) semantic_id: [u8; 32],
    pub(crate) reason: CustodyRetirementReason,
    pub(crate) numbered_cursor: Option<Vec<u8>>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum EventCustodyAuthority {
    Live {
        semantic_id: EventSemanticId,
        acceptance_marker: u64,
    },
    Retired {
        semantic_id: EventSemanticId,
        acceptance_marker: u64,
        reason: CustodyRetirementReason,
        cleanup_pending: bool,
    },
    Missing,
}

fn encode_retirement_cleanup(
    record: &RetirementCleanupRecord,
) -> Result<Vec<u8>, CustodyStoreError> {
    if record.original_revision == 0 {
        return Err(CustodyStoreError::Invariant(
            "custody retirement cleanup has a zero original revision",
        ));
    }
    let cursor_len = record.numbered_cursor.as_ref().map_or(Ok(0u32), |cursor| {
        u32::try_from(cursor.len()).map_err(|_| {
            CustodyStoreError::Invariant("custody retirement cleanup cursor exceeds its bound")
        })
    })?;
    let mut encoded = Vec::with_capacity(48 + cursor_len as usize);
    encoded.push(CUSTODY_RETIREMENT_CLEANUP_VERSION);
    encoded.extend_from_slice(&record.original_revision.to_be_bytes());
    encoded.push(record.priority as u8);
    encoded.extend_from_slice(&record.semantic_id);
    encoded.push(record.reason as u8);
    encoded.push(u8::from(record.numbered_cursor.is_some()));
    encoded.extend_from_slice(&cursor_len.to_be_bytes());
    if let Some(cursor) = &record.numbered_cursor {
        encoded.extend_from_slice(cursor);
    }
    Ok(encoded)
}

fn decode_retirement_cleanup(bytes: &[u8]) -> Result<RetirementCleanupRecord, CustodyStoreError> {
    let mut cursor = CustodyCursor::new(bytes);
    if cursor.u8()? != CUSTODY_RETIREMENT_CLEANUP_VERSION {
        return Err(CustodyStoreError::Invariant(
            "unknown custody retirement cleanup version",
        ));
    }
    let original_revision = cursor.u64()?;
    let priority = Priority::from_wire(cursor.u8()?).ok_or(CustodyStoreError::Invariant(
        "custody retirement cleanup has an invalid priority",
    ))?;
    let semantic_id = cursor.array()?;
    let reason = match cursor.u8()? {
        1 => CustodyRetirementReason::Expired,
        2 => CustodyRetirementReason::QuotaPressure,
        _ => {
            return Err(CustodyStoreError::Invariant(
                "custody retirement cleanup has an invalid reason",
            ));
        }
    };
    let cursor_present = match cursor.u8()? {
        0 => false,
        1 => true,
        _ => {
            return Err(CustodyStoreError::Invariant(
                "custody retirement cleanup has an invalid cursor flag",
            ));
        }
    };
    let cursor_len =
        usize::try_from(cursor.u32()?).map_err(|_| CustodyStoreError::CounterOverflow)?;
    let numbered_cursor = if cursor_present {
        Some(cursor.take(cursor_len)?.to_vec())
    } else {
        if cursor_len != 0 {
            return Err(CustodyStoreError::Invariant(
                "custody retirement cleanup has bytes for an absent cursor",
            ));
        }
        None
    };
    cursor.finish()?;
    let record = RetirementCleanupRecord {
        original_revision,
        priority,
        semantic_id,
        reason,
        numbered_cursor,
    };
    if encode_retirement_cleanup(&record)?.as_slice() != bytes {
        return Err(CustodyStoreError::Invariant(
            "custody retirement cleanup is not canonical",
        ));
    }
    Ok(record)
}

fn custody_expiration_key(
    key: CustodyObjectKey,
    record: &CustodyItemRecord,
) -> Result<Option<Vec<u8>>, CustodyStoreError> {
    if record.retiring || record.tombstone || record.ttl_ms.is_none() {
        return Ok(None);
    }
    let (generation, clock_id, due_tick_ms) = match record.checkpoint {
        Some(checkpoint) => {
            if record.continuity_generation == 0 {
                return Err(CustodyStoreError::Invariant(
                    "anchored finite custody item has a zero expiry generation",
                ));
            }
            let remaining = record
                .ttl_ms
                .expect("finite branch")
                .saturating_sub(record.cumulative_age_ms);
            (
                record.continuity_generation,
                checkpoint.clock_id,
                checkpoint.tick_ms.saturating_add(remaining),
            )
        }
        None if record.continuity_lost && record.continuity_generation == 0 => (0, [0; 16], 0),
        None => {
            return Err(CustodyStoreError::Invariant(
                "finite custody item lacks a canonical expiry anchor",
            ));
        }
    };
    let mut encoded = Vec::with_capacity(CUSTODY_EXPIRATION_KEY_LEN);
    encoded.extend_from_slice(&generation.to_be_bytes());
    encoded.extend_from_slice(&clock_id);
    encoded.extend_from_slice(&due_tick_ms.to_be_bytes());
    encoded.extend_from_slice(&key.encoded());
    Ok(Some(encoded))
}

fn decode_custody_expiration_key(
    encoded: &[u8],
) -> Result<(u64, [u8; 16], u64, CustodyObjectKey), CustodyStoreError> {
    if encoded.len() != CUSTODY_EXPIRATION_KEY_LEN {
        return Err(CustodyStoreError::Invariant(
            "custody expiration key has invalid length",
        ));
    }
    let generation = u64::from_be_bytes(encoded[..8].try_into().expect("generation bytes"));
    let clock_id = encoded[8..24].try_into().expect("clock bytes");
    let due_tick_ms = u64::from_be_bytes(encoded[24..32].try_into().expect("tick bytes"));
    let object = CustodyObjectKey::decode(&encoded[32..])?;
    Ok((generation, clock_id, due_tick_ms, object))
}

fn is_unanchored_lost_finite(record: &CustodyItemRecord) -> bool {
    record.ttl_ms.is_some()
        && !record.tombstone
        && !record.retiring
        && record.continuity_lost
        && record.checkpoint.is_none()
}

fn is_canonical_lost_sentinel_for(
    encoded: &[u8],
    items: &BTreeMap<CustodyObjectKey, CustodyItemRecord>,
) -> Result<bool, CustodyStoreError> {
    let (generation, clock_id, due_tick_ms, object) = decode_custody_expiration_key(encoded)?;
    Ok(generation == 0
        && clock_id == [0; 16]
        && due_tick_ms == 0
        && items.get(&object).is_some_and(is_unanchored_lost_finite))
}

fn custody_retiring_key(key: CustodyObjectKey, record: &CustodyItemRecord) -> Option<Vec<u8>> {
    record.retiring.then(|| {
        let mut encoded = Vec::with_capacity(CUSTODY_RETIRING_KEY_LEN);
        encoded.extend_from_slice(&record.acceptance_order.to_be_bytes());
        encoded.extend_from_slice(&key.encoded());
        encoded
    })
}

fn decode_custody_retiring_key(
    encoded: &[u8],
) -> Result<(u64, CustodyObjectKey), CustodyStoreError> {
    if encoded.len() != CUSTODY_RETIRING_KEY_LEN {
        return Err(CustodyStoreError::Invariant(
            "custody retiring key has invalid length",
        ));
    }
    let order = u64::from_be_bytes(encoded[..8].try_into().expect("acceptance-order bytes"));
    let object = CustodyObjectKey::decode(&encoded[8..])?;
    Ok((order, object))
}

fn cleanup_record_for_row(
    value: &[u8],
    item: Option<&CustodyItemRecord>,
) -> Result<RetirementCleanupRecord, CustodyStoreError> {
    if !value.is_empty() {
        return decode_retirement_cleanup(value);
    }
    let item = item.ok_or(CustodyStoreError::Invariant(
        "legacy custody retirement cleanup lacks its marked item",
    ))?;
    if !item.retiring {
        return Err(CustodyStoreError::Invariant(
            "legacy custody retirement cleanup targets a live item",
        ));
    }
    Ok(RetirementCleanupRecord {
        original_revision: item.revision,
        priority: item.priority,
        semantic_id: item.semantic_id,
        reason: deferred_retirement_reason(item),
        numbered_cursor: None,
    })
}

fn validate_cleanup_identity(
    cleanup: &RetirementCleanupRecord,
    item: Option<&CustodyItemRecord>,
    fence: Option<&RetirementRecord>,
) -> Result<(), CustodyStoreError> {
    if let Some(item) = item {
        if !item.retiring
            || item.revision != cleanup.original_revision
            || item.priority != cleanup.priority
            || item.semantic_id != cleanup.semantic_id
            || deferred_retirement_reason(item) != cleanup.reason
        {
            return Err(CustodyStoreError::Invariant(
                "custody retirement cleanup differs from its marked item",
            ));
        }
        if fence.is_some() {
            return Err(CustodyStoreError::Invariant(
                "marked custody item overlaps a retirement fence",
            ));
        }
        return Ok(());
    }
    let fence = fence.ok_or(CustodyStoreError::Invariant(
        "custody retirement cleanup lacks marked item or fence",
    ))?;
    if fence.semantic_id != cleanup.semantic_id || fence.reason != cleanup.reason {
        return Err(CustodyStoreError::Invariant(
            "custody retirement cleanup differs from its fence",
        ));
    }
    Ok(())
}

fn validate_cleanup_control_state(
    object: CustodyObjectKey,
    acceptance_order: u64,
    cleanup: &RetirementCleanupRecord,
    item: Option<&CustodyItemRecord>,
    fence: Option<&RetirementRecord>,
) -> Result<(), StoreError> {
    validate_cleanup_identity(cleanup, item, fence)?;
    let authority_order = item
        .map(|item| item.acceptance_order)
        .or_else(|| fence.map(|fence| fence.acceptance_order))
        .ok_or(CustodyStoreError::Invariant(
            "custody retirement cleanup lacks marked item or fence",
        ))?;
    if acceptance_order != authority_order {
        return Err(CustodyStoreError::Invariant(
            "custody retirement cleanup order differs from its authority",
        )
        .into());
    }
    if let Some(cursor) = cleanup.numbered_cursor.as_deref() {
        if object.class != CustodyObjectClass::Event {
            return Err(CustodyStoreError::Invariant(
                "non-Event custody cleanup has a numbered result cursor",
            )
            .into());
        }
        crate::numbered_event_operation::validate_numbered_cleanup_cursor(
            EventTransferId::new(object.transfer_id),
            cursor,
        )?;
    }
    Ok(())
}

fn fenced_cleanup_record_write(
    write: &redb::WriteTransaction,
    key: CustodyObjectKey,
) -> Result<RetirementCleanupRecord, StoreError> {
    let encoded_key = key.encoded();
    let fence = write
        .open_table(CUSTODY_RETIREMENTS)?
        .get(encoded_key.as_slice())?
        .map(|value| decode_retirement(value.value()))
        .transpose()?
        .ok_or(CustodyStoreError::Invariant(
            "missing custody item lacks a retirement fence",
        ))?;
    let mut cleanup_key = Vec::with_capacity(CUSTODY_RETIRING_KEY_LEN);
    cleanup_key.extend_from_slice(&fence.acceptance_order.to_be_bytes());
    cleanup_key.extend_from_slice(&encoded_key);
    let cleanup_value = write
        .open_table(CUSTODY_RETIRING)?
        .get(cleanup_key.as_slice())?
        .ok_or(CustodyStoreError::Invariant(
            "retirement fence lacks its cleanup record",
        ))?
        .value()
        .to_vec();
    let cleanup = cleanup_record_for_row(&cleanup_value, None)?;
    validate_cleanup_identity(&cleanup, None, Some(&fence))?;
    Ok(cleanup)
}

fn retirement_cleanup_key_for_authority(key: CustodyObjectKey, acceptance_order: u64) -> Vec<u8> {
    let mut cleanup_key = Vec::with_capacity(CUSTODY_RETIRING_KEY_LEN);
    cleanup_key.extend_from_slice(&acceptance_order.to_be_bytes());
    cleanup_key.extend_from_slice(&key.encoded());
    cleanup_key
}

pub(crate) fn event_custody_authority_write(
    write: &redb::WriteTransaction,
    transfer_id: EventTransferId,
) -> Result<EventCustodyAuthority, StoreError> {
    let key = CustodyObjectKey::event(transfer_id);
    let encoded_key = key.encoded();
    let item = write
        .open_table(CUSTODY_ITEMS)?
        .get(encoded_key.as_slice())?
        .map(|value| decode_item(value.value()))
        .transpose()?;
    let fence = write
        .open_table(CUSTODY_RETIREMENTS)?
        .get(encoded_key.as_slice())?
        .map(|value| decode_retirement(value.value()))
        .transpose()?;
    match (item, fence) {
        (Some(item), None) if !item.retiring => Ok(EventCustodyAuthority::Live {
            semantic_id: EventSemanticId::new(item.semantic_id),
            acceptance_marker: item.acceptance_order,
        }),
        (Some(item), None) => {
            let cleanup_key = retirement_cleanup_key_for_authority(key, item.acceptance_order);
            let cleanup_value = write
                .open_table(CUSTODY_RETIRING)?
                .get(cleanup_key.as_slice())?
                .ok_or(CustodyStoreError::Invariant(
                    "marked custody Event lacks its cleanup authority",
                ))?
                .value()
                .to_vec();
            let cleanup = cleanup_record_for_row(&cleanup_value, Some(&item))?;
            validate_cleanup_identity(&cleanup, Some(&item), None)?;
            Ok(EventCustodyAuthority::Retired {
                semantic_id: EventSemanticId::new(cleanup.semantic_id),
                acceptance_marker: item.acceptance_order,
                reason: cleanup.reason,
                cleanup_pending: true,
            })
        }
        (None, Some(fence)) => {
            let cleanup_key = retirement_cleanup_key_for_authority(key, fence.acceptance_order);
            let cleanup = write
                .open_table(CUSTODY_RETIRING)?
                .get(cleanup_key.as_slice())?
                .map(|value| cleanup_record_for_row(value.value(), None))
                .transpose()?;
            if let Some(cleanup) = &cleanup {
                validate_cleanup_identity(cleanup, None, Some(&fence))?;
            }
            Ok(EventCustodyAuthority::Retired {
                semantic_id: EventSemanticId::new(fence.semantic_id),
                acceptance_marker: fence.acceptance_order,
                reason: fence.reason,
                cleanup_pending: cleanup.is_some(),
            })
        }
        (None, None) => Ok(EventCustodyAuthority::Missing),
        (Some(_), Some(_)) => Err(CustodyStoreError::Invariant(
            "custody Event overlaps live and retired authority",
        )
        .into()),
    }
}

pub(crate) fn event_custody_authority_read(
    read: &redb::ReadTransaction,
    transfer_id: EventTransferId,
) -> Result<EventCustodyAuthority, StoreError> {
    let key = CustodyObjectKey::event(transfer_id);
    let encoded_key = key.encoded();
    let item = read
        .open_table(CUSTODY_ITEMS)?
        .get(encoded_key.as_slice())?
        .map(|value| decode_item(value.value()))
        .transpose()?;
    let fence = read
        .open_table(CUSTODY_RETIREMENTS)?
        .get(encoded_key.as_slice())?
        .map(|value| decode_retirement(value.value()))
        .transpose()?;
    match (item, fence) {
        (Some(item), None) if !item.retiring => Ok(EventCustodyAuthority::Live {
            semantic_id: EventSemanticId::new(item.semantic_id),
            acceptance_marker: item.acceptance_order,
        }),
        (Some(item), None) => {
            let cleanup_key = retirement_cleanup_key_for_authority(key, item.acceptance_order);
            let cleanup_value = read
                .open_table(CUSTODY_RETIRING)?
                .get(cleanup_key.as_slice())?
                .ok_or(CustodyStoreError::Invariant(
                    "marked custody Event lacks its cleanup authority",
                ))?
                .value()
                .to_vec();
            let cleanup = cleanup_record_for_row(&cleanup_value, Some(&item))?;
            validate_cleanup_identity(&cleanup, Some(&item), None)?;
            Ok(EventCustodyAuthority::Retired {
                semantic_id: EventSemanticId::new(cleanup.semantic_id),
                acceptance_marker: item.acceptance_order,
                reason: cleanup.reason,
                cleanup_pending: true,
            })
        }
        (None, Some(fence)) => {
            let cleanup_key = retirement_cleanup_key_for_authority(key, fence.acceptance_order);
            let cleanup = read
                .open_table(CUSTODY_RETIRING)?
                .get(cleanup_key.as_slice())?
                .map(|value| cleanup_record_for_row(value.value(), None))
                .transpose()?;
            if let Some(cleanup) = &cleanup {
                validate_cleanup_identity(cleanup, None, Some(&fence))?;
            }
            Ok(EventCustodyAuthority::Retired {
                semantic_id: EventSemanticId::new(fence.semantic_id),
                acceptance_marker: fence.acceptance_order,
                reason: fence.reason,
                cleanup_pending: cleanup.is_some(),
            })
        }
        (None, None) => Ok(EventCustodyAuthority::Missing),
        (Some(_), Some(_)) => Err(CustodyStoreError::Invariant(
            "custody Event overlaps live and retired authority",
        )
        .into()),
    }
}

#[cfg(test)]
pub(crate) fn seed_event_custody_authority_for_numbered_test(
    write: &redb::WriteTransaction,
    receipt: CommittedEventReceipt,
) -> Result<(), StoreError> {
    let key = CustodyObjectKey::event(receipt.transfer_id);
    if write
        .open_table(CUSTODY_ITEMS)?
        .get(key.encoded().as_slice())?
        .is_some()
    {
        return Ok(());
    }
    let record = CustodyItemRecord {
        semantic_id: *receipt.semantic_id.as_bytes(),
        topic: Topic::new("test")
            .map_err(|_| CustodyStoreError::Invariant("test numbered custody topic is invalid"))?,
        scope: Scope::new("alpha")
            .map_err(|_| CustodyStoreError::Invariant("test numbered custody scope is invalid"))?,
        source_publisher: [0x71; 32],
        key_epoch: 1,
        priority: Priority::Routine,
        ttl_ms: None,
        tombstone: false,
        route_only: false,
        retiring: false,
        continuity_lost: false,
        protection: CustodyProtection::NONE,
        accounted_bytes: 1,
        cumulative_age_ms: 0,
        checkpoint: None,
        continuity_generation: 0,
        acceptance_order: receipt.acceptance_marker,
        revision: 1,
    };
    write
        .open_table(CUSTODY_ITEMS)?
        .insert(key.encoded().as_slice(), encode_item(&record)?.as_slice())?;
    Ok(())
}

#[cfg(test)]
pub(crate) fn seed_retired_event_custody_authority_for_numbered_test(
    write: &redb::WriteTransaction,
    receipt: CommittedEventReceipt,
    reason: CustodyRetirementReason,
) -> Result<(), StoreError> {
    let key = CustodyObjectKey::event(receipt.transfer_id);
    write
        .open_table(CUSTODY_ITEMS)?
        .remove(key.encoded().as_slice())?;
    let record = RetirementRecord {
        semantic_id: *receipt.semantic_id.as_bytes(),
        topic: Topic::new("test")
            .map_err(|_| CustodyStoreError::Invariant("test numbered custody topic is invalid"))?,
        scope: Scope::new("alpha")
            .map_err(|_| CustodyStoreError::Invariant("test numbered custody scope is invalid"))?,
        source_publisher: [0x71; 32],
        key_epoch: 1,
        reason,
        cumulative_age_ms: 0,
        accounted_bytes: 1,
        acceptance_order: receipt.acceptance_marker,
        retired_revision: 1,
    };
    write.open_table(CUSTODY_RETIREMENTS)?.insert(
        key.encoded().as_slice(),
        encode_retirement(&record)?.as_slice(),
    )?;
    Ok(())
}

fn replace_custody_maintenance_indexes_write(
    write: &redb::WriteTransaction,
    key: CustodyObjectKey,
    before: Option<&CustodyItemRecord>,
    after: Option<&CustodyItemRecord>,
) -> Result<(), StoreError> {
    let before_expiration = before
        .map(|record| custody_expiration_key(key, record))
        .transpose()?
        .flatten();
    let after_expiration = after
        .map(|record| custody_expiration_key(key, record))
        .transpose()?
        .flatten();
    if before_expiration != after_expiration {
        let mut expirations = write.open_table(CUSTODY_EXPIRATIONS)?;
        if let Some(encoded) = before_expiration
            && expirations.remove(encoded.as_slice())?.is_none()
        {
            return Err(CustodyStoreError::Invariant(
                "custody item is missing its expiration index",
            )
            .into());
        }
        if let Some(encoded) = after_expiration
            && expirations.insert(encoded.as_slice(), &[][..])?.is_some()
        {
            return Err(CustodyStoreError::Invariant("custody expiration index collides").into());
        }
    }

    let before_retiring = before.and_then(|record| custody_retiring_key(key, record));
    let after_retiring = after.and_then(|record| custody_retiring_key(key, record));
    if before_retiring != after_retiring {
        let mut retiring = write.open_table(CUSTODY_RETIRING)?;
        if let Some(encoded) = before_retiring
            && retiring.remove(encoded.as_slice())?.is_none()
        {
            return Err(
                CustodyStoreError::Invariant("custody item is missing its retiring index").into(),
            );
        }
        if let Some(encoded) = after_retiring {
            let record = after.expect("retiring index requires an item");
            let cleanup = encode_retirement_cleanup(&RetirementCleanupRecord {
                original_revision: record.revision,
                priority: record.priority,
                semantic_id: record.semantic_id,
                reason: deferred_retirement_reason(record),
                numbered_cursor: None,
            })?;
            if retiring
                .insert(encoded.as_slice(), cleanup.as_slice())?
                .is_some()
            {
                return Err(CustodyStoreError::Invariant("custody retiring index collides").into());
            }
        }
    }
    Ok(())
}

#[cfg(test)]
pub(crate) fn reencode_item_source_claims_for_test(
    bytes: &[u8],
    priority: Priority,
    ttl_ms: Option<u64>,
) -> Result<Vec<u8>, CustodyStoreError> {
    let mut record = decode_item(bytes)?;
    record.priority = priority;
    record.ttl_ms = ttl_ms;
    if ttl_ms.is_some() && !record.tombstone {
        record.continuity_lost = true;
        record.checkpoint = None;
        record.continuity_generation = 0;
    }
    encode_item(&record)
}

#[cfg(test)]
pub(crate) fn reencode_legacy_lost_item_for_test(
    bytes: &[u8],
    retain_generation: bool,
) -> Result<Vec<u8>, CustodyStoreError> {
    let mut record = decode_item(bytes)?;
    record.continuity_lost = true;
    record.checkpoint = None;
    if !retain_generation {
        record.continuity_generation = 0;
    }
    encode_item(&record)
}

#[cfg(test)]
pub(crate) fn custody_expiration_key_for_test(
    encoded_key: &[u8],
    encoded_item: &[u8],
) -> Result<Option<Vec<u8>>, CustodyStoreError> {
    custody_expiration_key(
        CustodyObjectKey::decode(encoded_key)?,
        &decode_item(encoded_item)?,
    )
}

#[cfg(test)]
pub(crate) fn custody_expiration_generation_for_test(
    encoded: &[u8],
) -> Result<u64, CustodyStoreError> {
    decode_custody_expiration_key(encoded).map(|(generation, _, _, _)| generation)
}

fn encode_retirement(record: &RetirementRecord) -> Result<Vec<u8>, CustodyStoreError> {
    let topic = record.topic.as_str().as_bytes();
    let scope = record.scope.as_str().as_bytes();
    let topic_len = u16::try_from(topic.len())
        .map_err(|_| CustodyStoreError::Invariant("retirement topic exceeds encoding bound"))?;
    let scope_len = u16::try_from(scope.len())
        .map_err(|_| CustodyStoreError::Invariant("retirement scope exceeds encoding bound"))?;
    let mut encoded = Vec::with_capacity(70 + topic.len() + scope.len());
    encoded.push(CUSTODY_RETIREMENT_VERSION);
    encoded.extend_from_slice(&record.semantic_id);
    encoded.extend_from_slice(&topic_len.to_be_bytes());
    encoded.extend_from_slice(topic);
    encoded.extend_from_slice(&scope_len.to_be_bytes());
    encoded.extend_from_slice(scope);
    encoded.extend_from_slice(&record.source_publisher);
    encoded.extend_from_slice(&record.key_epoch.to_be_bytes());
    encoded.push(record.reason as u8);
    encoded.extend_from_slice(&record.cumulative_age_ms.to_be_bytes());
    encoded.extend_from_slice(&record.accounted_bytes.to_be_bytes());
    encoded.extend_from_slice(&record.acceptance_order.to_be_bytes());
    encoded.extend_from_slice(&record.retired_revision.to_be_bytes());
    Ok(encoded)
}

fn decode_retirement(bytes: &[u8]) -> Result<RetirementRecord, CustodyStoreError> {
    let mut cursor = CustodyCursor::new(bytes);
    if cursor.u8()? != CUSTODY_RETIREMENT_VERSION {
        return Err(CustodyStoreError::Invariant(
            "unknown custody retirement version",
        ));
    }
    let semantic_id = cursor.array()?;
    let topic_len = usize::from(cursor.u16()?);
    let topic = Topic::new(
        std::str::from_utf8(cursor.take(topic_len)?)
            .map_err(|_| CustodyStoreError::Invariant("retirement topic is not UTF-8"))?,
    )
    .map_err(|_| CustodyStoreError::Invariant("retirement topic is invalid"))?;
    let scope_len = usize::from(cursor.u16()?);
    let scope = Scope::new(
        std::str::from_utf8(cursor.take(scope_len)?)
            .map_err(|_| CustodyStoreError::Invariant("retirement scope is not UTF-8"))?,
    )
    .map_err(|_| CustodyStoreError::Invariant("retirement scope is invalid"))?;
    let source_publisher = cursor.array()?;
    let key_epoch = cursor.u64()?;
    let reason = match cursor.u8()? {
        1 => CustodyRetirementReason::Expired,
        2 => CustodyRetirementReason::QuotaPressure,
        _ => {
            return Err(CustodyStoreError::Invariant(
                "unknown custody retirement reason",
            ));
        }
    };
    let record = RetirementRecord {
        semantic_id,
        topic,
        scope,
        source_publisher,
        key_epoch,
        reason,
        cumulative_age_ms: cursor.u64()?,
        accounted_bytes: cursor.u64()?,
        acceptance_order: cursor.u64()?,
        retired_revision: cursor.u64()?,
    };
    cursor.finish()?;
    if record.accounted_bytes == 0 || record.acceptance_order == 0 || record.retired_revision == 0 {
        return Err(CustodyStoreError::Invariant(
            "retirement fence contains a zero bound or revision",
        ));
    }
    if encode_retirement(&record)?.as_slice() != bytes {
        return Err(CustodyStoreError::Invariant(
            "custody retirement is not canonical",
        ));
    }
    Ok(record)
}

fn encode_lease(record: &LeaseRecord) -> Result<Vec<u8>, CustodyStoreError> {
    let peer_selector_revision =
        record
            .peer_selector_revision
            .ok_or(CustodyStoreError::Invariant(
                "cannot encode an unbound legacy custody lease",
            ))?;
    let mut encoded = Vec::with_capacity(99);
    encoded.push(CUSTODY_LEASE_VERSION);
    encoded.extend_from_slice(&record.object.encoded());
    encoded.extend_from_slice(&record.peer);
    encoded.extend_from_slice(&record.item_revision.to_be_bytes());
    encoded.extend_from_slice(&record.policy_revision.to_be_bytes());
    encoded.extend_from_slice(&record.age_ms.to_be_bytes());
    encoded.push(record.priority as u8);
    encoded.extend_from_slice(&peer_selector_revision.to_be_bytes());
    Ok(encoded)
}

fn decode_lease(bytes: &[u8]) -> Result<LeaseRecord, CustodyStoreError> {
    let mut cursor = CustodyCursor::new(bytes);
    let version = cursor.u8()?;
    if !matches!(
        version,
        CUSTODY_LEASE_LEGACY_VERSION | CUSTODY_LEASE_VERSION
    ) {
        return Err(CustodyStoreError::Invariant(
            "unknown custody lease version",
        ));
    }
    let object = CustodyObjectKey::decode(cursor.take(33)?)?;
    let peer = cursor.array()?;
    let item_revision = cursor.u64()?;
    let policy_revision = cursor.u64()?;
    let age_ms = cursor.u64()?;
    let priority = Priority::from_wire(cursor.u8()?).ok_or(CustodyStoreError::Invariant(
        "custody lease priority is unknown",
    ))?;
    let peer_selector_revision = match version {
        CUSTODY_LEASE_LEGACY_VERSION => None,
        CUSTODY_LEASE_VERSION => Some(cursor.u64()?),
        _ => unreachable!("lease version was checked"),
    };
    cursor.finish()?;
    if item_revision == 0 || policy_revision == 0 {
        return Err(CustodyStoreError::Invariant(
            "custody lease contains a zero revision",
        ));
    }
    Ok(LeaseRecord {
        object,
        peer,
        item_revision,
        policy_revision,
        age_ms,
        priority,
        peer_selector_revision,
    })
}

fn peer_object_key(peer: NodeId, object: CustodyObjectKey) -> [u8; 65] {
    let mut key = [0u8; 65];
    key[..32].copy_from_slice(&peer);
    key[32..].copy_from_slice(&object.encoded());
    key
}

fn parse_peer_object_key(bytes: &[u8]) -> Result<(NodeId, CustodyObjectKey), CustodyStoreError> {
    let bytes: [u8; 65] = bytes
        .try_into()
        .map_err(|_| CustodyStoreError::Invariant("custody peer/object key has invalid length"))?;
    Ok((
        bytes[..32].try_into().expect("fixed peer prefix"),
        CustodyObjectKey::decode(&bytes[32..])?,
    ))
}

fn encode_receipt(record: ReceiptRecord) -> Result<Vec<u8>, CustodyStoreError> {
    let peer_selector_revision =
        record
            .peer_selector_revision
            .ok_or(CustodyStoreError::Invariant(
                "cannot encode an unbound legacy custody receipt",
            ))?;
    let mut encoded = Vec::with_capacity(25);
    encoded.push(CUSTODY_RECEIPT_VERSION);
    encoded.extend_from_slice(&record.cumulative_age_ms.to_be_bytes());
    encoded.extend_from_slice(&record.item_revision.to_be_bytes());
    encoded.extend_from_slice(&peer_selector_revision.to_be_bytes());
    Ok(encoded)
}

#[cfg(test)]
pub(crate) fn seed_peer_receipt_fanout_write(
    write: &redb::WriteTransaction,
    object: CustodyObjectKey,
    count: usize,
) -> Result<(), StoreError> {
    let encoded_object = object.encoded();
    let item = write
        .open_table(CUSTODY_ITEMS)?
        .get(encoded_object.as_slice())?
        .map(|value| decode_item(value.value()))
        .transpose()?
        .ok_or(CustodyStoreError::ItemNotFound)?;
    let encoded_receipt = encode_receipt(ReceiptRecord {
        cumulative_age_ms: item.cumulative_age_ms,
        item_revision: item.revision,
        peer_selector_revision: Some(1),
    })?;
    let mut receipts = write.open_table(CUSTODY_PEER_RECEIPTS)?;
    let mut references = write.open_table(CUSTODY_RETIREMENT_REFERENCES)?;
    for index in 0..count {
        let mut peer = [0u8; 32];
        peer[..8].copy_from_slice(
            &u64::try_from(index + 1)
                .map_err(|_| CustodyStoreError::CounterOverflow)?
                .to_be_bytes(),
        );
        let key = peer_object_key(peer, object);
        if receipts
            .insert(key.as_slice(), encoded_receipt.as_slice())?
            .is_some()
        {
            return Err(CustodyStoreError::Invariant("test receipt fan-out collides").into());
        }
        let reference = retirement_reference_key(
            RETIREMENT_REFERENCE_RECEIPT,
            encoded_object.as_slice(),
            key.as_slice(),
        );
        if references.insert(reference.as_slice(), &[][..])?.is_some() {
            return Err(
                CustodyStoreError::Invariant("test receipt retirement reference collides").into(),
            );
        }
    }
    drop(references);
    drop(receipts);
    let mut metadata = write.open_table(CUSTODY_METADATA)?;
    let current = metadata_value(&metadata, CUSTODY_RECEIPT_COUNT_KEY)?;
    metadata.insert(
        CUSTODY_RECEIPT_COUNT_KEY,
        current
            .checked_add(u64::try_from(count).map_err(|_| CustodyStoreError::CounterOverflow)?)
            .ok_or(CustodyStoreError::CounterOverflow)?,
    )?;
    Ok(())
}

fn decode_receipt(bytes: &[u8]) -> Result<ReceiptRecord, CustodyStoreError> {
    let mut cursor = CustodyCursor::new(bytes);
    let version = cursor.u8()?;
    if !matches!(
        version,
        CUSTODY_RECEIPT_LEGACY_VERSION | CUSTODY_RECEIPT_VERSION
    ) {
        return Err(CustodyStoreError::Invariant(
            "unknown custody receipt version",
        ));
    }
    let record = ReceiptRecord {
        cumulative_age_ms: cursor.u64()?,
        item_revision: cursor.u64()?,
        peer_selector_revision: match version {
            CUSTODY_RECEIPT_LEGACY_VERSION => None,
            CUSTODY_RECEIPT_VERSION => Some(cursor.u64()?),
            _ => unreachable!("receipt version was checked"),
        },
    };
    cursor.finish()?;
    if record.item_revision == 0 {
        return Err(CustodyStoreError::Invariant(
            "custody receipt has a zero item revision",
        ));
    }
    Ok(record)
}

fn encode_retry(record: RetryRecord) -> Vec<u8> {
    let mut encoded = Vec::with_capacity(50);
    encoded.push(CUSTODY_RETRY_VERSION);
    encoded.extend_from_slice(&record.attempts.to_be_bytes());
    encoded.extend_from_slice(&record.item_revision.to_be_bytes());
    encoded.extend_from_slice(&record.policy_revision.to_be_bytes());
    encoded.extend_from_slice(&record.clock_id);
    encoded.extend_from_slice(&record.due_tick_ms.to_be_bytes());
    encoded.push(record.priority as u8);
    encoded
}

fn decode_retry(bytes: &[u8]) -> Result<RetryRecord, CustodyStoreError> {
    let mut cursor = CustodyCursor::new(bytes);
    if cursor.u8()? != CUSTODY_RETRY_VERSION {
        return Err(CustodyStoreError::Invariant(
            "unknown custody retry version",
        ));
    }
    let attempts = cursor.u64()?;
    let item_revision = cursor.u64()?;
    let policy_revision = cursor.u64()?;
    let clock_id = cursor.array()?;
    let due_tick_ms = cursor.u64()?;
    let priority = Priority::from_wire(cursor.u8()?).ok_or(CustodyStoreError::Invariant(
        "custody retry priority is unknown",
    ))?;
    cursor.finish()?;
    if attempts == 0 || item_revision == 0 || policy_revision == 0 || due_tick_ms == 0 {
        return Err(CustodyStoreError::Invariant(
            "custody retry contains a zero counter",
        ));
    }
    Ok(RetryRecord {
        attempts,
        item_revision,
        policy_revision,
        clock_id,
        due_tick_ms,
        priority,
    })
}

struct CustodyCursor<'a> {
    bytes: &'a [u8],
    offset: usize,
}

impl<'a> CustodyCursor<'a> {
    const fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, offset: 0 }
    }

    fn take(&mut self, length: usize) -> Result<&'a [u8], CustodyStoreError> {
        let end = self
            .offset
            .checked_add(length)
            .ok_or(CustodyStoreError::Invariant(
                "custody record length overflow",
            ))?;
        let value = self
            .bytes
            .get(self.offset..end)
            .ok_or(CustodyStoreError::Invariant("truncated custody record"))?;
        self.offset = end;
        Ok(value)
    }

    fn u8(&mut self) -> Result<u8, CustodyStoreError> {
        Ok(self.take(1)?[0])
    }

    fn u16(&mut self) -> Result<u16, CustodyStoreError> {
        Ok(u16::from_be_bytes(
            self.take(2)?.try_into().expect("two bytes"),
        ))
    }

    fn u32(&mut self) -> Result<u32, CustodyStoreError> {
        Ok(u32::from_be_bytes(
            self.take(4)?.try_into().expect("four bytes"),
        ))
    }

    fn u64(&mut self) -> Result<u64, CustodyStoreError> {
        Ok(u64::from_be_bytes(
            self.take(8)?.try_into().expect("eight bytes"),
        ))
    }

    fn array<const N: usize>(&mut self) -> Result<[u8; N], CustodyStoreError> {
        Ok(self.take(N)?.try_into().expect("checked fixed length"))
    }

    fn finish(self) -> Result<(), CustodyStoreError> {
        if self.offset == self.bytes.len() {
            Ok(())
        } else {
            Err(CustodyStoreError::Invariant(
                "custody record has trailing bytes",
            ))
        }
    }
}

const CUSTODY_SCHEMA_V1_TABLE_NAMES: [&str; 11] = [
    "aster.custody-items.v1",
    "aster.custody-retirements.v1",
    "aster.custody-retired-semantics.v1",
    "aster.custody-transfer-leases.v1",
    "aster.custody-peer-receipts.v1",
    "aster.custody-peer-retries.v1",
    "aster.custody-quotas.v1",
    "aster.custody-scope-usage.v1",
    "aster.custody-continuity.v1",
    "aster.custody-domain.v1",
    "aster.custody-metadata.v1",
];

const CUSTODY_SCHEMA_V2_TABLE_NAMES: [&str; 13] = [
    "aster.custody-items.v1",
    "aster.custody-expirations.v2",
    "aster.custody-retiring.v2",
    "aster.custody-retirements.v1",
    "aster.custody-retired-semantics.v1",
    "aster.custody-transfer-leases.v1",
    "aster.custody-peer-receipts.v1",
    "aster.custody-peer-retries.v1",
    "aster.custody-quotas.v1",
    "aster.custody-scope-usage.v1",
    "aster.custody-continuity.v1",
    "aster.custody-domain.v1",
    "aster.custody-metadata.v1",
];

const CUSTODY_TABLE_NAMES: [&str; 14] = [
    "aster.custody-items.v1",
    "aster.custody-expirations.v2",
    "aster.custody-retiring.v2",
    "aster.custody-retirement-references.v3",
    "aster.custody-retirements.v1",
    "aster.custody-retired-semantics.v1",
    "aster.custody-transfer-leases.v1",
    "aster.custody-peer-receipts.v1",
    "aster.custody-peer-retries.v1",
    "aster.custody-quotas.v1",
    "aster.custody-scope-usage.v1",
    "aster.custody-continuity.v1",
    "aster.custody-domain.v1",
    "aster.custody-metadata.v1",
];

fn unsupported_predecessor_version(
    regular: &BTreeSet<String>,
    metadata_version: Option<u64>,
) -> Option<u64> {
    [
        (1, &CUSTODY_SCHEMA_V1_TABLE_NAMES[..]),
        (2, &CUSTODY_SCHEMA_V2_TABLE_NAMES[..]),
    ]
    .into_iter()
    .find_map(|(version, names)| {
        let exact = names.iter().all(|name| regular.contains(*name))
            && CUSTODY_TABLE_NAMES
                .iter()
                .filter(|name| !names.contains(name))
                .all(|name| !regular.contains(*name));
        (exact && metadata_version == Some(version)).then_some(version)
    })
}

fn preflight_custody_schema_write(write: &redb::WriteTransaction) -> Result<bool, StoreError> {
    let regular = write
        .list_tables()?
        .map(|table| table.name().to_owned())
        .collect::<BTreeSet<_>>();
    let multimaps = write
        .list_multimap_tables()?
        .map(|table| table.name().to_owned())
        .collect::<BTreeSet<_>>();
    if CUSTODY_TABLE_NAMES
        .iter()
        .any(|name| multimaps.contains(*name))
    {
        return Err(CustodyStoreError::Invariant(
            "custody schema contains a table with the wrong kind",
        )
        .into());
    }
    let present = CUSTODY_TABLE_NAMES
        .iter()
        .filter(|name| regular.contains(**name))
        .count();
    if present != 0 && present != CUSTODY_TABLE_NAMES.len() {
        let metadata_version = if regular.contains(CUSTODY_METADATA.name()) {
            write
                .open_table(CUSTODY_METADATA)?
                .get(CUSTODY_SCHEMA_VERSION_KEY)?
                .map(|value| value.value())
        } else {
            None
        };
        if let Some(found) = unsupported_predecessor_version(&regular, metadata_version) {
            return Err(CustodyStoreError::UnsupportedSchemaVersion {
                found,
                supported: CUSTODY_SCHEMA_VERSION,
            }
            .into());
        }
        return Err(CustodyStoreError::Invariant("custody schema group is incomplete").into());
    }
    Ok(present == CUSTODY_TABLE_NAMES.len())
}

fn custody_schema_present_read(read: &redb::ReadTransaction) -> Result<bool, StoreError> {
    let regular = read
        .list_tables()?
        .map(|table| table.name().to_owned())
        .collect::<BTreeSet<_>>();
    let multimaps = read
        .list_multimap_tables()?
        .map(|table| table.name().to_owned())
        .collect::<BTreeSet<_>>();
    if CUSTODY_TABLE_NAMES
        .iter()
        .any(|name| multimaps.contains(*name))
    {
        return Err(CustodyStoreError::Invariant(
            "custody schema contains a table with the wrong kind",
        )
        .into());
    }
    let present = CUSTODY_TABLE_NAMES
        .iter()
        .filter(|name| regular.contains(**name))
        .count();
    if present != 0 && present != CUSTODY_TABLE_NAMES.len() {
        let metadata_version = if regular.contains(CUSTODY_METADATA.name()) {
            read.open_table(CUSTODY_METADATA)?
                .get(CUSTODY_SCHEMA_VERSION_KEY)?
                .map(|value| value.value())
        } else {
            None
        };
        if let Some(found) = unsupported_predecessor_version(&regular, metadata_version) {
            return Err(CustodyStoreError::UnsupportedSchemaVersion {
                found,
                supported: CUSTODY_SCHEMA_VERSION,
            }
            .into());
        }
        return Err(CustodyStoreError::Invariant("custody schema group is incomplete").into());
    }
    Ok(present == CUSTODY_TABLE_NAMES.len())
}

fn initialize_custody_schema(
    write: &redb::WriteTransaction,
    limits: StoreLimits,
    mission_authority: Option<NodeId>,
) -> Result<(), StoreError> {
    // Unbound stores have no mission partition yet. Mission-bound migration
    // performs the exact classified ordinary/control/tombstone check after its
    // reconstructed custody counters are staged in this same atomic writer.
    if mission_authority.is_none() {
        require_aggregate_capacity(&write.open_table(METADATA)?, limits, 0, 0)?;
    }
    let mut backfill = Vec::<(CustodyObjectKey, CustodyItemRecord)>::new();
    let mut total_bytes = 0u64;
    let mut revision = 1u64;
    let mut last_event_order = 0u64;
    {
        let events = write.open_table(EVENTS)?;
        let event_bytes = write.open_table(EVENT_BYTES)?;
        let markers = write.open_table(EVENT_ACCEPTANCE_MARKERS)?;
        for row in events.iter()? {
            let (key, value) = row?;
            let transfer_id = parse_transfer_id("Event metadata table", key.value())?;
            let metadata = decode_event_metadata(value.value())?;
            let accounted_bytes = event_bytes
                .get(key.value())?
                .map(|bytes| u64::try_from(bytes.value().len()))
                .transpose()
                .map_err(|_| CustodyStoreError::CounterOverflow)?
                .ok_or(CustodyStoreError::Invariant(
                    "legacy Event is missing exact bytes during custody migration",
                ))?;
            let acceptance_order = markers
                .get(key.value())?
                .map(|marker| marker.value())
                .ok_or(CustodyStoreError::Invariant(
                    "legacy Event is missing its acceptance marker during custody migration",
                ))?;
            last_event_order = last_event_order.max(acceptance_order);
            revision = next_counter(revision)?;
            total_bytes = total_bytes
                .checked_add(accounted_bytes)
                .ok_or(CustodyStoreError::CounterOverflow)?;
            backfill.push((
                CustodyObjectKey::event(transfer_id),
                CustodyItemRecord {
                    semantic_id: *metadata.semantic_id.as_bytes(),
                    topic: metadata.header.topic,
                    scope: metadata.header.scope,
                    source_publisher: metadata.header.stamp.dot.publisher,
                    key_epoch: metadata.header.key_epoch,
                    priority: metadata.header.priority,
                    ttl_ms: metadata.header.ttl_ms,
                    tombstone: metadata.header.tombstone,
                    route_only: false,
                    retiring: false,
                    continuity_lost: metadata.header.ttl_ms.is_some() && !metadata.header.tombstone,
                    protection: CustodyProtection::new(
                        false,
                        false,
                        metadata.header.tombstone,
                        false,
                    ),
                    accounted_bytes,
                    cumulative_age_ms: 0,
                    checkpoint: None,
                    continuity_generation: 0,
                    acceptance_order,
                    revision,
                },
            ));
        }
    }
    {
        let cache = write.open_table(ROUTE_CACHE)?;
        let claims = write.open_table(ROUTE_CACHE_CLAIMS)?;
        let mut route_rank = 0u64;
        for row in cache.iter()? {
            let (key, bytes) = row?;
            let transfer_id = parse_transfer_id("route Event cache", key.value())?;
            let metadata = claims
                .get(key.value())?
                .map(|claim| decode_event_metadata(claim.value()))
                .transpose()?
                .ok_or(CustodyStoreError::Invariant(
                    "legacy route Event is missing its claim during custody migration",
                ))?;
            let accounted_bytes = u64::try_from(bytes.value().len())
                .map_err(|_| CustodyStoreError::CounterOverflow)?;
            route_rank = next_counter(route_rank)?;
            let acceptance_order = last_event_order
                .checked_add(route_rank)
                .ok_or(CustodyStoreError::CounterOverflow)?;
            revision = next_counter(revision)?;
            total_bytes = total_bytes
                .checked_add(accounted_bytes)
                .ok_or(CustodyStoreError::CounterOverflow)?;
            backfill.push((
                CustodyObjectKey::route_event(transfer_id),
                CustodyItemRecord {
                    semantic_id: *metadata.semantic_id.as_bytes(),
                    topic: metadata.header.topic,
                    scope: metadata.header.scope,
                    source_publisher: metadata.header.stamp.dot.publisher,
                    key_epoch: metadata.header.key_epoch,
                    priority: metadata.header.priority,
                    ttl_ms: metadata.header.ttl_ms,
                    tombstone: metadata.header.tombstone,
                    route_only: true,
                    retiring: false,
                    continuity_lost: metadata.header.ttl_ms.is_some() && !metadata.header.tombstone,
                    protection: CustodyProtection::new(
                        false,
                        false,
                        metadata.header.tombstone,
                        false,
                    ),
                    accounted_bytes,
                    cumulative_age_ms: 0,
                    checkpoint: None,
                    continuity_generation: 0,
                    acceptance_order,
                    revision,
                },
            ));
        }
    }
    let item_count =
        u64::try_from(backfill.len()).map_err(|_| CustodyStoreError::CounterOverflow)?;
    let ordinary_item_count = u64::try_from(
        backfill
            .iter()
            .filter(|(_, record)| !record.tombstone)
            .count(),
    )
    .map_err(|_| CustodyStoreError::CounterOverflow)?;
    let ordinary_total_bytes = backfill
        .iter()
        .filter(|(_, record)| !record.tombstone)
        .try_fold(0u64, |total, (_, record)| {
            total
                .checked_add(record.accounted_bytes)
                .ok_or(CustodyStoreError::CounterOverflow)
        })?;
    let operation_metadata = write.open_table(METADATA)?;
    let tombstone_operation_items = operation_metadata
        .get(EVENT_TOMBSTONE_OPERATION_COUNT)?
        .map_or(0, |value| value.value());
    let tombstone_operation_bytes = operation_metadata
        .get(EVENT_TOMBSTONE_OPERATION_TOTAL_BYTES)?
        .map_or(0, |value| value.value());
    drop(operation_metadata);
    let tombstone_usage = CustodyUsage {
        items: item_count
            .checked_sub(ordinary_item_count)
            .and_then(|items| items.checked_add(tombstone_operation_items))
            .ok_or(CustodyStoreError::Invariant(
                "ordinary items exceed total custody items during migration",
            ))?,
        bytes: total_bytes
            .checked_sub(ordinary_total_bytes)
            .and_then(|bytes| bytes.checked_add(tombstone_operation_bytes))
            .ok_or(CustodyStoreError::Invariant(
                "ordinary bytes exceed total custody bytes during migration",
            ))?,
    };
    let (tombstone_max_items, tombstone_max_bytes) = custody_tombstone_allowance(limits);
    require_quota_capacity(
        tombstone_usage,
        &CustodyQuota {
            scope: None,
            max_items: tombstone_max_items,
            max_bytes: tombstone_max_bytes,
        },
        0,
        0,
    )?;
    let reserved_global = CustodyQuota::for_store_limits(limits)?;
    let custody_item_limit = reserved_global.max_items;
    let custody_byte_limit = reserved_global.max_bytes;
    if ordinary_item_count > custody_item_limit || ordinary_total_bytes > custody_byte_limit {
        return Err(CustodyStoreError::Invariant(
            "legacy Event usage leaves no bounded control/tombstone reserve",
        )
        .into());
    }
    if ordinary_item_count > MAX_CUSTODY_RETIREMENTS {
        return Err(CustodyStoreError::Invariant(
            "legacy Event usage exceeds the permanent retirement-fence reserve",
        )
        .into());
    }
    {
        let mut items = write.open_table(CUSTODY_ITEMS)?;
        for (key, record) in &backfill {
            let encoded = encode_item(record)?;
            if items
                .insert(key.encoded().as_slice(), encoded.as_slice())?
                .is_some()
            {
                return Err(CustodyStoreError::Invariant(
                    "legacy custody migration produced a duplicate transfer key",
                )
                .into());
            }
        }
    }
    write.open_table(CUSTODY_EXPIRATIONS)?;
    write.open_table(CUSTODY_RETIRING)?;
    write.open_table(CUSTODY_RETIREMENT_REFERENCES)?;
    let regular_tables = write
        .list_tables()?
        .map(|table| table.name().to_owned())
        .collect::<BTreeSet<_>>();
    if regular_tables.contains(EVENT_SUBSCRIPTION_PENDING.name()) {
        for row in write.open_table(EVENT_SUBSCRIPTION_PENDING)?.iter()? {
            let (key, value) = row?;
            let pending = decode_event_pending_delivery_record(value.value())?;
            insert_event_pending_retirement_reference_write(
                write,
                pending.semantic_id,
                key.value(),
            )?;
        }
    }
    if regular_tables.contains(EVENT_DELIVERY_ACKNOWLEDGEMENTS.name()) {
        for row in write.open_table(EVENT_DELIVERY_ACKNOWLEDGEMENTS)?.iter()? {
            let (key, value) = row?;
            let (_, semantic_id) = parse_event_acknowledgement_key(key.value())?;
            let _ = decode_event_acknowledgement_record(value.value())?;
            insert_event_acknowledgement_retirement_reference_write(
                write,
                semantic_id,
                key.value(),
            )?;
        }
    }
    for (key, record) in &backfill {
        replace_custody_maintenance_indexes_write(write, *key, None, Some(record))?;
    }
    write.open_table(CUSTODY_RETIREMENTS)?;
    write.open_table(CUSTODY_RETIRED_SEMANTICS)?;
    write.open_table(CUSTODY_LEASES)?;
    write.open_table(CUSTODY_PEER_RECEIPTS)?;
    write.open_table(CUSTODY_RETRIES)?;
    write.open_table(CUSTODY_CONTINUITY)?;
    {
        let mut scope_usages = BTreeMap::<String, CustodyUsage>::new();
        for (_, record) in &backfill {
            if record.tombstone {
                continue;
            }
            let usage = scope_usages
                .entry(record.scope.as_str().to_owned())
                .or_default();
            usage.items = next_counter(usage.items)?;
            usage.bytes = usage
                .bytes
                .checked_add(record.accounted_bytes)
                .ok_or(CustodyStoreError::CounterOverflow)?;
        }
        let mut table = write.open_table(CUSTODY_SCOPE_USAGE)?;
        for (scope, usage) in scope_usages {
            table.insert(scope.as_str(), encode_scope_usage(usage).as_slice())?;
        }
    }
    let global = reserved_global;
    write
        .open_table(CUSTODY_QUOTAS)?
        .insert(GLOBAL_QUOTA_KEY, encode_quota(&global).as_slice())?;
    if let Some(authority) = mission_authority {
        write
            .open_table(CUSTODY_DOMAIN)?
            .insert(CUSTODY_MISSION_AUTHORITY_KEY, authority.as_slice())?;
    } else {
        write.open_table(CUSTODY_DOMAIN)?;
    }
    let mut metadata = write.open_table(CUSTODY_METADATA)?;
    for (key, value) in [
        (CUSTODY_SCHEMA_VERSION_KEY, CUSTODY_SCHEMA_VERSION),
        (CUSTODY_POLICY_REVISION_KEY, 1),
        (CUSTODY_MUTATION_REVISION_KEY, revision),
        (CUSTODY_ITEM_COUNT_KEY, item_count),
        (CUSTODY_TOTAL_BYTES_KEY, total_bytes),
        (CUSTODY_ORDINARY_ITEM_COUNT_KEY, ordinary_item_count),
        (CUSTODY_ORDINARY_TOTAL_BYTES_KEY, ordinary_total_bytes),
        (CUSTODY_RETIREMENT_COUNT_KEY, 0),
        (CUSTODY_LEASE_COUNT_KEY, 0),
        (CUSTODY_RECEIPT_COUNT_KEY, 0),
        (CUSTODY_RETRY_COUNT_KEY, 0),
        (CUSTODY_QUOTA_COUNT_KEY, 1),
        (CUSTODY_NEXT_LEASE_KEY, 0),
        (CUSTODY_RETRY_SEQUENCE_KEY, 0),
    ] {
        metadata.insert(key, value)?;
    }
    drop(metadata);
    if mission_authority.is_some() {
        require_ordinary_aggregate_capacity(write, &write.open_table(METADATA)?, limits, 0, 0)?;
    }
    Ok(())
}

fn metadata_value(
    metadata: &impl ReadableTable<&'static str, u64>,
    key: &'static str,
) -> Result<u64, StoreError> {
    metadata
        .get(key)?
        .map(|value| value.value())
        .ok_or_else(|| CustodyStoreError::Invariant("custody metadata field is missing").into())
}

fn next_counter(value: u64) -> Result<u64, StoreError> {
    value
        .checked_add(1)
        .ok_or_else(|| CustodyStoreError::CounterOverflow.into())
}

fn advance_revision(
    write: &redb::WriteTransaction,
    policy: bool,
) -> Result<(u64, u64), StoreError> {
    let mut metadata = write.open_table(CUSTODY_METADATA)?;
    let policy_revision = metadata_value(&metadata, CUSTODY_POLICY_REVISION_KEY)?;
    let mutation_revision = metadata_value(&metadata, CUSTODY_MUTATION_REVISION_KEY)?;
    let next_policy = if policy {
        next_counter(policy_revision)?
    } else {
        policy_revision
    };
    let next_mutation = next_counter(mutation_revision)?;
    if policy {
        metadata.insert(CUSTODY_POLICY_REVISION_KEY, next_policy)?;
    }
    metadata.insert(CUSTODY_MUTATION_REVISION_KEY, next_mutation)?;
    Ok((next_policy, next_mutation))
}

fn require_policy_revision_write(
    write: &redb::WriteTransaction,
    expected: CustodyPolicyRevision,
) -> Result<(), StoreError> {
    let metadata = write.open_table(CUSTODY_METADATA)?;
    if metadata_value(&metadata, CUSTODY_POLICY_REVISION_KEY)? != expected.0 {
        return Err(CustodyStoreError::PolicyChanged.into());
    }
    Ok(())
}

pub(crate) fn require_policy_revision_read(
    read: &redb::ReadTransaction,
    expected: CustodyPolicyRevision,
) -> Result<(), StoreError> {
    let metadata = read.open_table(CUSTODY_METADATA)?;
    if metadata_value(&metadata, CUSTODY_POLICY_REVISION_KEY)? != expected.0 {
        return Err(CustodyStoreError::PolicyChanged.into());
    }
    Ok(())
}

pub(crate) fn policy_revision_write(
    write: &redb::WriteTransaction,
) -> Result<CustodyPolicyRevision, StoreError> {
    let metadata = write.open_table(CUSTODY_METADATA)?;
    Ok(CustodyPolicyRevision(metadata_value(
        &metadata,
        CUSTODY_POLICY_REVISION_KEY,
    )?))
}

fn custody_mission_write(write: &redb::WriteTransaction) -> Result<Option<NodeId>, StoreError> {
    let domain = write.open_table(CUSTODY_DOMAIN)?;
    domain
        .get(CUSTODY_MISSION_AUTHORITY_KEY)?
        .map(|value| {
            value.value().try_into().map_err(|_| {
                CustodyStoreError::Invariant("custody mission authority has invalid length").into()
            })
        })
        .transpose()
}

pub(crate) fn require_custody_mission_write(
    write: &redb::WriteTransaction,
    authority: NodeId,
) -> Result<(), StoreError> {
    match custody_mission_write(write)? {
        Some(bound) if bound == authority => Ok(()),
        Some(_) => Err(CustodyStoreError::MissionMismatch.into()),
        None => Err(CustodyStoreError::MissionNotBound.into()),
    }
}

fn continuity_write(
    write: &redb::WriteTransaction,
) -> Result<Option<ContinuityRecord>, StoreError> {
    write
        .open_table(CUSTODY_CONTINUITY)?
        .get(CUSTODY_CONTINUITY_KEY)?
        .map(|value| decode_continuity(value.value()).map_err(StoreError::from))
        .transpose()
}

/// Returns whether a maintenance pass must enter the single-writer queue to
/// preserve an observed local elapsed-clock continuity sample.
pub(crate) fn continuity_sample_requires_write_read(
    read: &redb::ReadTransaction,
    sample: Option<CustodySample>,
) -> Result<bool, StoreError> {
    let Some(sample) = sample else {
        return Ok(false);
    };
    let current = read
        .open_table(CUSTODY_CONTINUITY)?
        .get(CUSTODY_CONTINUITY_KEY)?
        .map(|value| decode_continuity(value.value()).map_err(StoreError::from))
        .transpose()?;
    Ok(current.is_none_or(|current| {
        current.sample.clock_id != sample.clock_id || sample.tick_ms > current.sample.tick_ms
    }))
}

/// Updates only the local elapsed-clock continuity domain. Same-clock samples
/// normalize to the durable tick high-water; only a changed clock ID advances
/// the generation and makes every prior finite row sticky-unknown.
pub(crate) fn observe_continuity_write(
    write: &redb::WriteTransaction,
    sample: CustodySample,
) -> Result<ContinuityRecord, StoreError> {
    let current = continuity_write(write)?;
    let (next, discontinuity) = match current {
        None => (
            ContinuityRecord {
                generation: 1,
                sample,
            },
            false,
        ),
        Some(current) if current.sample.clock_id == sample.clock_id => {
            (
                ContinuityRecord {
                    generation: current.generation,
                    // A delayed contact may have sampled before another
                    // writer advanced this same monotonic clock. Retain the
                    // durable high-water; same-domain arrival order is not a
                    // clock rollback and must not destroy continuity.
                    sample: CustodySample {
                        clock_id: sample.clock_id,
                        tick_ms: current.sample.tick_ms.max(sample.tick_ms),
                    },
                },
                false,
            )
        }
        Some(current) => (
            ContinuityRecord {
                generation: next_counter(current.generation)?,
                sample,
            },
            true,
        ),
    };
    if current != Some(next) {
        let encoded = encode_continuity(next);
        write
            .open_table(CUSTODY_CONTINUITY)?
            .insert(CUSTODY_CONTINUITY_KEY, encoded.as_slice())?;
        if discontinuity {
            let retry_keys = write
                .open_table(CUSTODY_RETRIES)?
                .iter()?
                .map(|row| row.map(|(key, _)| key.value().to_vec()))
                .collect::<Result<Vec<_>, redb::StorageError>>()?;
            if !retry_keys.is_empty() {
                let mut retries = write.open_table(CUSTODY_RETRIES)?;
                for key in &retry_keys {
                    retries.remove(key.as_slice())?;
                    remove_peer_retirement_reference_write(
                        write,
                        RETIREMENT_REFERENCE_RETRY,
                        key,
                        "discontinuity retry retirement reference disappeared",
                    )?;
                }
                drop(retries);
                write
                    .open_table(CUSTODY_METADATA)?
                    .insert(CUSTODY_RETRY_COUNT_KEY, 0)?;
            }
            advance_revision(write, true)?;
        }
    }
    Ok(next)
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct CustodyAgeEvaluation {
    status: CustodyAgeStatus,
    lower_bound_ms: u64,
    checkpoint: Option<CustodySample>,
    continuity_generation: u64,
    continuity_lost: bool,
    needs_write: bool,
}

fn evaluate_item_age(
    record: &CustodyItemRecord,
    continuity: Option<ContinuityRecord>,
    sample: Option<CustodySample>,
) -> Result<CustodyAgeEvaluation, StoreError> {
    let unchanged = |status| CustodyAgeEvaluation {
        status,
        lower_bound_ms: record.cumulative_age_ms,
        checkpoint: record.checkpoint,
        continuity_generation: record.continuity_generation,
        continuity_lost: record.continuity_lost,
        needs_write: false,
    };
    if record.tombstone || record.ttl_ms.is_none() {
        return Ok(unchanged(CustodyAgeStatus::Durable));
    }
    let ttl = record.ttl_ms.expect("finite branch");
    if record.cumulative_age_ms >= ttl {
        return Ok(unchanged(CustodyAgeStatus::Expired {
            age_ms: record.cumulative_age_ms,
        }));
    }

    let current = match (continuity, sample) {
        (Some(continuity), Some(sample)) if continuity.sample.clock_id == sample.clock_id => {
            Some((
                continuity.generation,
                if sample.tick_ms < continuity.sample.tick_ms {
                    continuity.sample
                } else {
                    sample
                },
            ))
        }
        _ => None,
    };
    let (lower_bound_ms, checkpoint, continuity_generation, continuity_lost) =
        if let Some((generation, current)) = current {
            let same_domain = record.checkpoint.is_some_and(|checkpoint| {
                record.continuity_generation == generation
                    && checkpoint.clock_id == current.clock_id
                    && current.tick_ms >= checkpoint.tick_ms
            });
            if same_domain {
                let checkpoint = record.checkpoint.expect("checked same-domain checkpoint");
                match record
                    .cumulative_age_ms
                    .checked_add(current.tick_ms - checkpoint.tick_ms)
                {
                    Some(age_ms) => (age_ms, Some(current), generation, record.continuity_lost),
                    None => (u64::MAX, Some(current), generation, true),
                }
            } else {
                (record.cumulative_age_ms, Some(current), generation, true)
            }
        } else {
            (record.cumulative_age_ms, None, 0, true)
        };
    let status = if lower_bound_ms >= ttl {
        CustodyAgeStatus::Expired {
            age_ms: lower_bound_ms,
        }
    } else if continuity_lost {
        CustodyAgeStatus::WithheldUnknownAge
    } else {
        CustodyAgeStatus::Forwardable {
            age_ms: lower_bound_ms,
            remaining_ms: ttl - lower_bound_ms,
        }
    };
    Ok(CustodyAgeEvaluation {
        status,
        lower_bound_ms,
        checkpoint,
        continuity_generation,
        continuity_lost,
        needs_write: lower_bound_ms != record.cumulative_age_ms
            || checkpoint != record.checkpoint
            || continuity_generation != record.continuity_generation
            || continuity_lost != record.continuity_lost,
    })
}

fn evaluate_item(
    record: &CustodyItemRecord,
    continuity: Option<ContinuityRecord>,
    sample: Option<CustodySample>,
) -> (CustodyAgeStatus, bool) {
    match evaluate_item_age(record, continuity, sample) {
        Ok(evaluation) => (
            evaluation.status,
            evaluation.continuity_lost && !record.continuity_lost,
        ),
        Err(_) => (
            CustodyAgeStatus::WithheldUnknownAge,
            !record.continuity_lost,
        ),
    }
}

fn checkpoint_item_age_write(
    write: &redb::WriteTransaction,
    key: CustodyObjectKey,
    mut record: CustodyItemRecord,
    evaluation: CustodyAgeEvaluation,
) -> Result<CustodyItemRecord, StoreError> {
    if !evaluation.needs_write {
        return Ok(record);
    }
    let original = record.clone();
    record.cumulative_age_ms = evaluation.lower_bound_ms;
    record.checkpoint = evaluation.checkpoint;
    record.continuity_generation = evaluation.continuity_generation;
    record.continuity_lost = evaluation.continuity_lost;
    replace_custody_maintenance_indexes_write(write, key, Some(&original), Some(&record))?;
    write
        .open_table(CUSTODY_ITEMS)?
        .insert(key.encoded().as_slice(), encode_item(&record)?.as_slice())?;
    advance_revision(
        write,
        evaluation.continuity_lost && !original.continuity_lost,
    )?;
    Ok(record)
}

fn normalize_read_sample(
    continuity: Option<ContinuityRecord>,
    sample: Option<CustodySample>,
) -> Option<CustodySample> {
    match (continuity, sample) {
        (Some(continuity), Some(sample))
            if continuity.sample.clock_id == sample.clock_id
                && continuity.sample.tick_ms > sample.tick_ms =>
        {
            Some(continuity.sample)
        }
        (_, sample) => sample,
    }
}

fn receiver_fence_authorized_read(
    read: &redb::ReadTransaction,
    policy: &EventReplicationPolicySnapshot,
    topic: &Topic,
    scope: &Scope,
    source_publisher: NodeId,
    key_epoch: u64,
) -> Result<bool, StoreError> {
    if policy.effective_mode(topic, scope).is_none()
        || control_principal_revoked_read(read, source_publisher)?
    {
        return Ok(false);
    }
    let current_epoch = read
        .open_table(CONTROL_SCOPE_EPOCHS)?
        .get(scope.as_str())?
        .map(|value| decode_scope_epoch_index(value.value()))
        .transpose()?
        .map_or(1, |(current, _)| current);
    Ok(key_epoch == current_epoch)
}

pub(crate) fn sender_row_live_read(
    read: &redb::ReadTransaction,
    key: CustodyObjectKey,
) -> Result<bool, StoreError> {
    if read
        .open_table(CUSTODY_RETIREMENTS)?
        .get(key.encoded().as_slice())?
        .is_some()
    {
        return Ok(false);
    }
    read.open_table(CUSTODY_ITEMS)?
        .get(key.encoded().as_slice())?
        .map(|value| decode_item(value.value()).map(|record| !record.retiring))
        .transpose()
        .map(|live| live.unwrap_or(false))
        .map_err(StoreError::from)
}

pub(crate) fn sender_status_read(
    read: &redb::ReadTransaction,
    key: CustodyObjectKey,
    sample: Option<CustodySample>,
) -> Result<Option<CustodySenderStatus>, StoreError> {
    if let Some(retired) = read
        .open_table(CUSTODY_RETIREMENTS)?
        .get(key.encoded().as_slice())?
        .map(|value| decode_retirement(value.value()))
        .transpose()?
    {
        return Ok(Some(CustodySenderStatus::Retired {
            age_ms: retired.cumulative_age_ms,
        }));
    }
    let Some(record) = read
        .open_table(CUSTODY_ITEMS)?
        .get(key.encoded().as_slice())?
        .map(|value| decode_item(value.value()))
        .transpose()?
    else {
        return Ok(None);
    };
    if record.retiring {
        return Ok(Some(CustodySenderStatus::Retiring));
    }
    let continuity = read
        .open_table(CUSTODY_CONTINUITY)?
        .get(CUSTODY_CONTINUITY_KEY)?
        .map(|value| decode_continuity(value.value()))
        .transpose()?;
    let sample = normalize_read_sample(continuity, sample);
    Ok(Some(CustodySenderStatus::Age(
        evaluate_item(&record, continuity, sample).0,
    )))
}

pub(crate) fn sender_event_projection_read(
    read: &redb::ReadTransaction,
    sample: Option<CustodySample>,
    max_items: u64,
) -> Result<Vec<CustodySenderProjection>, StoreError> {
    let items = read.open_table(CUSTODY_ITEMS)?;
    let item_count = items.len()?;
    if item_count > max_items {
        return Err(StoreError::ItemLimitExceeded {
            current: item_count,
            limit: max_items,
        });
    }
    let continuity = read
        .open_table(CUSTODY_CONTINUITY)?
        .get(CUSTODY_CONTINUITY_KEY)?
        .map(|value| decode_continuity(value.value()))
        .transpose()?;
    let sample = normalize_read_sample(continuity, sample);
    let retirements = read.open_table(CUSTODY_RETIREMENTS)?;
    let mut sendable = Vec::new();
    for row in items.iter()? {
        let (encoded_key, encoded_record) = row?;
        let key = CustodyObjectKey::decode(encoded_key.value())?;
        if !matches!(
            key.class,
            CustodyObjectClass::Event | CustodyObjectClass::RouteEvent
        ) {
            continue;
        }
        let record = decode_item(encoded_record.value())?;
        let opposite = opposite_event_key(key).expect("checked Event custody class");
        if items.get(opposite.encoded().as_slice())?.is_some()
            || retirements.get(key.encoded().as_slice())?.is_some()
            || retirements.get(opposite.encoded().as_slice())?.is_some()
        {
            return Err(StoreError::SemanticInvariant(
                "one Event transfer has custody state in both accepted and route namespaces",
            ));
        }
        if record.retiring {
            continue;
        }
        let status = evaluate_item(&record, continuity, sample).0;
        if CustodySenderStatus::Age(status).is_sendable() {
            sendable.push(CustodySenderProjection {
                object: key,
                semantic_id: record.semantic_id,
                source_publisher: record.source_publisher,
                topic: record.topic,
                scope: record.scope,
                key_epoch: record.key_epoch,
                priority: record.priority,
                ttl_ms: record.ttl_ms,
                tombstone: record.tombstone,
                accounted_bytes: record.accounted_bytes,
                acceptance_order: record.acceptance_order,
                status,
            });
        }
    }
    Ok(sendable)
}

/// Returns every retained Event/RouteEvent custody row, including rows which
/// are retiring, expired, or withheld because finite-age continuity is lost.
///
/// This is a source-authentication inventory, not sender authority.  Its caller
/// must structurally join and freshly verify the exact source representation
/// before any maintenance operation is allowed to retire the row.
pub(crate) fn retained_event_projection_read(
    read: &redb::ReadTransaction,
    max_items: u64,
) -> Result<Vec<CustodySenderProjection>, StoreError> {
    let items = read.open_table(CUSTODY_ITEMS)?;
    let item_count = items.len()?;
    if item_count > max_items {
        return Err(StoreError::ItemLimitExceeded {
            current: item_count,
            limit: max_items,
        });
    }
    let continuity = read
        .open_table(CUSTODY_CONTINUITY)?
        .get(CUSTODY_CONTINUITY_KEY)?
        .map(|value| decode_continuity(value.value()))
        .transpose()?;
    let retirements = read.open_table(CUSTODY_RETIREMENTS)?;
    let mut retained = Vec::new();
    for row in items.iter()? {
        let (encoded_key, encoded_record) = row?;
        let key = CustodyObjectKey::decode(encoded_key.value())?;
        if !matches!(
            key.class,
            CustodyObjectClass::Event | CustodyObjectClass::RouteEvent
        ) {
            continue;
        }
        let record = decode_item(encoded_record.value())?;
        let opposite = opposite_event_key(key).expect("checked Event custody class");
        if items.get(opposite.encoded().as_slice())?.is_some()
            || retirements.get(key.encoded().as_slice())?.is_some()
            || retirements.get(opposite.encoded().as_slice())?.is_some()
        {
            return Err(StoreError::SemanticInvariant(
                "one Event transfer has custody state in both accepted and route namespaces",
            ));
        }
        let status = evaluate_item(&record, continuity, None).0;
        retained.push(CustodySenderProjection {
            object: key,
            semantic_id: record.semantic_id,
            source_publisher: record.source_publisher,
            topic: record.topic,
            scope: record.scope,
            key_epoch: record.key_epoch,
            priority: record.priority,
            ttl_ms: record.ttl_ms,
            tombstone: record.tombstone,
            accounted_bytes: record.accounted_bytes,
            acceptance_order: record.acceptance_order,
            status,
        });
    }
    Ok(retained)
}

pub(crate) fn sender_row_live_write(
    write: &redb::WriteTransaction,
    key: CustodyObjectKey,
) -> Result<bool, StoreError> {
    if write
        .open_table(CUSTODY_RETIREMENTS)?
        .get(key.encoded().as_slice())?
        .is_some()
    {
        return Ok(false);
    }
    write
        .open_table(CUSTODY_ITEMS)?
        .get(key.encoded().as_slice())?
        .map(|value| decode_item(value.value()).map(|record| !record.retiring))
        .transpose()
        .map(|live| live.unwrap_or(false))
        .map_err(StoreError::from)
}

pub(crate) fn retiring_event_counts_read(
    read: &redb::ReadTransaction,
) -> Result<(u64, u64), StoreError> {
    if !custody_schema_present_read(read)? {
        return Ok((0, 0));
    }
    let mut events = 0u64;
    let mut routes = 0u64;
    for row in read.open_table(CUSTODY_RETIRING)?.iter()? {
        let (key, _) = row?;
        let (_, key) = decode_custody_retiring_key(key.value())?;
        match key.class {
            CustodyObjectClass::Event => events = next_counter(events)?,
            CustodyObjectClass::RouteEvent => routes = next_counter(routes)?,
            _ => {}
        }
    }
    Ok((events, routes))
}

/// Merges one authenticated arrival with the locally elapsed high-water before
/// moving or checkpointing a row. The original checkpoint is evaluated first;
/// otherwise a stale alternate-path age could erase local residence time (or
/// be incorrectly charged that time twice).
fn merge_authenticated_age(
    record: &mut CustodyItemRecord,
    continuity: Option<ContinuityRecord>,
    sample: Option<CustodySample>,
    authenticated_age_ms: u64,
) -> Result<(u64, bool, bool), StoreError> {
    let original = record.clone();
    let evaluation = evaluate_item_age(&original, continuity, sample)?;
    record.cumulative_age_ms = evaluation.lower_bound_ms.max(authenticated_age_ms);
    record.checkpoint = evaluation.checkpoint;
    record.continuity_generation = evaluation.continuity_generation;
    record.continuity_lost = evaluation.continuity_lost;
    let newly_lost = record.continuity_lost && !original.continuity_lost;
    let expired = !record.tombstone
        && record
            .ttl_ms
            .is_some_and(|ttl| record.cumulative_age_ms >= ttl);
    Ok((record.cumulative_age_ms, newly_lost, expired))
}

fn custody_usage_read(
    read: &redb::ReadTransaction,
    scope: Option<&Scope>,
) -> Result<CustodyUsage, StoreError> {
    if scope.is_none() {
        let metadata = read.open_table(CUSTODY_METADATA)?;
        return Ok(CustodyUsage {
            items: metadata_value(&metadata, CUSTODY_ORDINARY_ITEM_COUNT_KEY)?,
            bytes: metadata_value(&metadata, CUSTODY_ORDINARY_TOTAL_BYTES_KEY)?,
        });
    }
    read.open_table(CUSTODY_SCOPE_USAGE)?
        .get(scope.expect("checked scoped usage").as_str())?
        .map(|value| decode_scope_usage(value.value()).map_err(StoreError::from))
        .transpose()
        .map(|usage| usage.unwrap_or_default())
}

fn quota_read(
    read: &redb::ReadTransaction,
    scope: Option<&Scope>,
) -> Result<Option<CustodyQuota>, StoreError> {
    read.open_table(CUSTODY_QUOTAS)?
        .get(quota_key(scope))?
        .map(|value| decode_quota(quota_key(scope), value.value()).map_err(StoreError::from))
        .transpose()
}

fn custody_usage_write(
    write: &redb::WriteTransaction,
    scope: Option<&Scope>,
) -> Result<CustodyUsage, StoreError> {
    if scope.is_none() {
        let metadata = write.open_table(CUSTODY_METADATA)?;
        return Ok(CustodyUsage {
            items: metadata_value(&metadata, CUSTODY_ORDINARY_ITEM_COUNT_KEY)?,
            bytes: metadata_value(&metadata, CUSTODY_ORDINARY_TOTAL_BYTES_KEY)?,
        });
    }
    write
        .open_table(CUSTODY_SCOPE_USAGE)?
        .get(scope.expect("checked scoped usage").as_str())?
        .map(|value| decode_scope_usage(value.value()).map_err(StoreError::from))
        .transpose()
        .map(|usage| usage.unwrap_or_default())
}

fn quota_write(
    write: &redb::WriteTransaction,
    scope: Option<&Scope>,
) -> Result<Option<CustodyQuota>, StoreError> {
    write
        .open_table(CUSTODY_QUOTAS)?
        .get(quota_key(scope))?
        .map(|value| decode_quota(quota_key(scope), value.value()).map_err(StoreError::from))
        .transpose()
}

pub(crate) fn require_quota_capacity(
    usage: CustodyUsage,
    quota: &CustodyQuota,
    incoming_items: u64,
    incoming_bytes: u64,
) -> Result<(), StoreError> {
    let final_items = usage
        .items
        .checked_add(incoming_items)
        .ok_or(CustodyStoreError::CounterOverflow)?;
    if final_items > quota.max_items {
        return Err(CustodyStoreError::ItemQuotaExceeded {
            current: usage.items,
            incoming: incoming_items,
            limit: quota.max_items,
        }
        .into());
    }
    let final_bytes = usage
        .bytes
        .checked_add(incoming_bytes)
        .ok_or(CustodyStoreError::CounterOverflow)?;
    if final_bytes > quota.max_bytes {
        return Err(CustodyStoreError::ByteQuotaExceeded {
            current: usage.bytes,
            incoming: incoming_bytes,
            limit: quota.max_bytes,
        }
        .into());
    }
    Ok(())
}

pub(crate) fn selected_tombstone_payload_usage_write(
    write: &redb::WriteTransaction,
) -> Result<CustodyUsage, StoreError> {
    let custody = write.open_table(CUSTODY_METADATA)?;
    let total_items = metadata_value(&custody, CUSTODY_ITEM_COUNT_KEY)?;
    let total_bytes = metadata_value(&custody, CUSTODY_TOTAL_BYTES_KEY)?;
    let ordinary_items = metadata_value(&custody, CUSTODY_ORDINARY_ITEM_COUNT_KEY)?;
    let ordinary_bytes = metadata_value(&custody, CUSTODY_ORDINARY_TOTAL_BYTES_KEY)?;
    Ok(CustodyUsage {
        items: total_items
            .checked_sub(ordinary_items)
            .ok_or(CustodyStoreError::Invariant(
                "selected tombstone item accounting is invalid",
            ))?,
        bytes: total_bytes
            .checked_sub(ordinary_bytes)
            .ok_or(CustodyStoreError::Invariant(
                "selected tombstone byte accounting is invalid",
            ))?,
    })
}

pub(crate) fn selected_tombstone_payload_usage_read(
    read: &redb::ReadTransaction,
) -> Result<CustodyUsage, StoreError> {
    let custody = read.open_table(CUSTODY_METADATA)?;
    let total_items = metadata_value(&custody, CUSTODY_ITEM_COUNT_KEY)?;
    let total_bytes = metadata_value(&custody, CUSTODY_TOTAL_BYTES_KEY)?;
    let ordinary_items = metadata_value(&custody, CUSTODY_ORDINARY_ITEM_COUNT_KEY)?;
    let ordinary_bytes = metadata_value(&custody, CUSTODY_ORDINARY_TOTAL_BYTES_KEY)?;
    Ok(CustodyUsage {
        items: total_items
            .checked_sub(ordinary_items)
            .ok_or(CustodyStoreError::Invariant(
                "selected tombstone item accounting is invalid",
            ))?,
        bytes: total_bytes
            .checked_sub(ordinary_bytes)
            .ok_or(CustodyStoreError::Invariant(
                "selected tombstone byte accounting is invalid",
            ))?,
    })
}

fn selected_tombstone_usage_write(
    write: &redb::WriteTransaction,
) -> Result<CustodyUsage, StoreError> {
    let payload = selected_tombstone_payload_usage_write(write)?;
    let metadata = write.open_table(METADATA)?;
    let operation_items = metadata
        .get(EVENT_TOMBSTONE_OPERATION_COUNT)?
        .map_or(0, |value| value.value());
    let operation_bytes = metadata
        .get(EVENT_TOMBSTONE_OPERATION_TOTAL_BYTES)?
        .map_or(0, |value| value.value());
    Ok(CustodyUsage {
        items: payload
            .items
            .checked_add(operation_items)
            .ok_or(CustodyStoreError::Invariant(
                "selected tombstone item accounting is invalid",
            ))?,
        bytes: payload
            .bytes
            .checked_add(operation_bytes)
            .ok_or(CustodyStoreError::Invariant(
                "selected tombstone byte accounting is invalid",
            ))?,
    })
}

fn selected_tombstone_usage_read(
    read: &redb::ReadTransaction,
    item_count: u64,
    total_bytes: u64,
    ordinary_item_count: u64,
    ordinary_total_bytes: u64,
) -> Result<CustodyUsage, StoreError> {
    let metadata = read.open_table(METADATA)?;
    let operation_items = metadata
        .get(EVENT_TOMBSTONE_OPERATION_COUNT)?
        .map(|value| value.value());
    let operation_bytes = metadata
        .get(EVENT_TOMBSTONE_OPERATION_TOTAL_BYTES)?
        .map(|value| value.value());
    let (operation_items, operation_bytes) = match (operation_items, operation_bytes) {
        (Some(items), Some(bytes)) => (items, bytes),
        (None, None) => {
            let events = read.open_table(EVENTS)?;
            let mut items = 0u64;
            let mut bytes = 0u64;
            for row in read.open_table(EVENT_OPERATIONS)?.iter()? {
                let (key, value) = row?;
                let operation = decode_operation_record(value.value())?;
                let event = events
                    .get(operation.transfer_id.as_bytes().as_slice())?
                    .map(|value| decode_event_metadata(value.value()))
                    .transpose()?
                    .ok_or(CustodyStoreError::Invariant(
                        "Event operation points to missing tombstone metadata",
                    ))?;
                if event.header.tombstone {
                    items = next_counter(items)?;
                    bytes = bytes
                        .checked_add(
                            key.value()
                                .len()
                                .checked_add(value.value().len())
                                .and_then(|length| u64::try_from(length).ok())
                                .ok_or(CustodyStoreError::CounterOverflow)?,
                        )
                        .ok_or(CustodyStoreError::CounterOverflow)?;
                }
            }
            (items, bytes)
        }
        _ => {
            return Err(CustodyStoreError::Invariant(
                "Event tombstone-operation accounting metadata is incomplete",
            )
            .into());
        }
    };
    Ok(CustodyUsage {
        items: item_count
            .checked_sub(ordinary_item_count)
            .and_then(|items| items.checked_add(operation_items))
            .ok_or(CustodyStoreError::Invariant(
                "selected tombstone item accounting is invalid",
            ))?,
        bytes: total_bytes
            .checked_sub(ordinary_total_bytes)
            .and_then(|bytes| bytes.checked_add(operation_bytes))
            .ok_or(CustodyStoreError::Invariant(
                "selected tombstone byte accounting is invalid",
            ))?,
    })
}

fn check_admission_capacity(
    write: &redb::WriteTransaction,
    admission: &CustodyAdmission,
    limits: StoreLimits,
) -> Result<(), StoreError> {
    // Durable tombstones have a dedicated slice of the emergency reserve and
    // can never consume the full mission-control authority domain.
    if admission.tombstone {
        let (max_items, max_bytes) = custody_tombstone_allowance(limits);
        return require_quota_capacity(
            selected_tombstone_usage_write(write)?,
            &CustodyQuota {
                scope: None,
                max_items,
                max_bytes,
            },
            1,
            admission.accounted_bytes,
        );
    }
    let global = quota_write(write, None)?.ok_or(CustodyStoreError::Invariant(
        "custody schema is missing its global quota",
    ))?;
    require_quota_capacity(
        custody_usage_write(write, None)?,
        &global,
        1,
        admission.accounted_bytes,
    )?;
    if let Some(scope_quota) = quota_write(write, Some(&admission.scope))? {
        require_quota_capacity(
            custody_usage_write(write, Some(&admission.scope))?,
            &scope_quota,
            1,
            admission.accounted_bytes,
        )?;
    }
    Ok(())
}

fn require_retirement_reserve_write(
    write: &redb::WriteTransaction,
    incoming_fence_requiring: u64,
) -> Result<(), StoreError> {
    let metadata = write.open_table(CUSTODY_METADATA)?;
    let live = metadata_value(&metadata, CUSTODY_ORDINARY_ITEM_COUNT_KEY)?;
    let retired = metadata_value(&metadata, CUSTODY_RETIREMENT_COUNT_KEY)?;
    let reserved = live
        .checked_add(retired)
        .and_then(|value| value.checked_add(incoming_fence_requiring))
        .ok_or(CustodyStoreError::CounterOverflow)?;
    if reserved > MAX_CUSTODY_RETIREMENTS {
        return Err(CustodyStoreError::RetirementLimitExceeded {
            current: live
                .checked_add(retired)
                .ok_or(CustodyStoreError::CounterOverflow)?,
            limit: MAX_CUSTODY_RETIREMENTS,
        }
        .into());
    }
    Ok(())
}

#[derive(Clone, Debug)]
struct RankedRetirementCandidate<Order> {
    order: Order,
    key: CustodyObjectKey,
    item: CustodyItemRecord,
    age_ms: u64,
    expired: bool,
}

impl<Order: Ord> PartialEq for RankedRetirementCandidate<Order> {
    fn eq(&self, other: &Self) -> bool {
        self.order == other.order
    }
}

impl<Order: Ord> Eq for RankedRetirementCandidate<Order> {}

impl<Order: Ord> PartialOrd for RankedRetirementCandidate<Order> {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl<Order: Ord> Ord for RankedRetirementCandidate<Order> {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.order.cmp(&other.order)
    }
}

fn retain_best_retirement_candidate<Candidate: Ord>(
    candidates: &mut BinaryHeap<Candidate>,
    candidate: Candidate,
) {
    if candidates.len() < MAX_CUSTODY_PAGE {
        candidates.push(candidate);
    } else if candidates
        .peek()
        .is_some_and(|worst| candidate.cmp(worst).is_lt())
    {
        candidates.pop();
        candidates.push(candidate);
    }
}

#[cfg(test)]
pub(crate) fn retirement_candidate_heap_probe(orders: &[u64]) -> (usize, Vec<u64>) {
    let mut candidates = BinaryHeap::new();
    let mut peak_entries = 0usize;
    for order in orders {
        retain_best_retirement_candidate(&mut candidates, *order);
        peak_entries = peak_entries.max(candidates.len());
    }
    (peak_entries, candidates.into_sorted_vec())
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct RetirementScanWindow {
    completion_limit: usize,
    examined: usize,
    completed: usize,
}

impl RetirementScanWindow {
    fn new(completion_limit: usize) -> Self {
        Self {
            completion_limit,
            examined: 0,
            completed: 0,
        }
    }

    fn begin_row(&mut self) -> bool {
        if self.examined == MAX_CUSTODY_RETIREMENT_SCAN || self.completed == self.completion_limit {
            return false;
        }
        self.examined += 1;
        true
    }

    fn record_completion(&mut self) {
        self.completed += 1;
    }
}

#[cfg(test)]
pub(crate) fn retirement_scan_probe(
    lease_blocked: &[bool],
    completion_limit: usize,
) -> (usize, usize, bool) {
    let mut window = RetirementScanWindow::new(completion_limit);
    for blocked in lease_blocked {
        if !window.begin_row() {
            break;
        }
        if !blocked {
            window.record_completion();
        }
    }
    (
        window.examined,
        window.completed,
        window.examined < lease_blocked.len(),
    )
}

fn make_admission_capacity_write(
    write: &redb::WriteTransaction,
    admission: &CustodyAdmission,
    continuity: Option<ContinuityRecord>,
    limits: StoreLimits,
) -> Result<(), StoreError> {
    if check_admission_capacity(write, admission, limits).is_ok() {
        return Ok(());
    }
    if admission.tombstone {
        return check_admission_capacity(write, admission, limits);
    }
    let scope_quota = quota_write(write, Some(&admission.scope))?;
    let global_quota = quota_write(write, None)?.ok_or(CustodyStoreError::Invariant(
        "custody schema is missing its global quota",
    ))?;
    let scope_is_short = match &scope_quota {
        Some(quota) => require_quota_capacity(
            custody_usage_write(write, Some(&admission.scope))?,
            quota,
            1,
            admission.accounted_bytes,
        )
        .is_err(),
        None => false,
    };
    let mut candidates = BinaryHeap::new();
    let items = write.open_table(CUSTODY_ITEMS)?;
    for row in items.iter()? {
        let (encoded_key, encoded_item) = row?;
        let key = CustodyObjectKey::decode(encoded_key.value())?;
        let item = decode_item(encoded_item.value())?;
        if item.tombstone
            || item.retiring
            || !matches!(
                key.class,
                CustodyObjectClass::Event | CustodyObjectClass::RouteEvent
            )
        {
            continue;
        }
        let (status, _) = evaluate_item(&item, continuity, admission.sample);
        let (expired, age_ms, remaining) = match status {
            CustodyAgeStatus::Expired { age_ms } => (true, age_ms, 0),
            CustodyAgeStatus::Forwardable {
                age_ms,
                remaining_ms,
            } => (false, age_ms, remaining_ms),
            CustodyAgeStatus::Durable | CustodyAgeStatus::WithheldUnknownAge => {
                (false, item.cumulative_age_ms, u64::MAX)
            }
        };
        if !expired
            && (item.protection.protects_eviction()
                || retirement_reference_exists_write(
                    write,
                    RETIREMENT_REFERENCE_PENDING,
                    item.semantic_id.as_slice(),
                )?)
        {
            continue;
        }
        if !expired && item.priority >= admission.priority {
            continue;
        }
        retain_best_retirement_candidate(
            &mut candidates,
            RankedRetirementCandidate {
                order: (
                    scope_is_short && item.scope != admission.scope,
                    !expired,
                    !item.route_only,
                    item.priority,
                    remaining,
                    item.acceptance_order,
                    key,
                ),
                key,
                item,
                age_ms,
                expired,
            },
        );
    }
    drop(items);
    let mut budget = MaintenanceBudget::default();
    for candidate in candidates.into_sorted_vec() {
        let RankedRetirementCandidate {
            key,
            item,
            age_ms,
            expired,
            ..
        } = candidate;
        let marked = mark_retiring_write_indexed(write, key, item, age_ms)?;
        if retirement_reference_exists_write(
            write,
            RETIREMENT_REFERENCE_LEASE,
            key.encoded().as_slice(),
        )? {
            continue;
        }
        let reason = if expired {
            CustodyRetirementReason::Expired
        } else {
            CustodyRetirementReason::QuotaPressure
        };
        fence_retirement_write(write, key, &marked, reason)?;
        let cleanup_key = custody_retiring_key(key, &marked).expect("marked retirement key");
        let cleanup_value = write
            .open_table(CUSTODY_RETIRING)?
            .get(cleanup_key.as_slice())?
            .ok_or(CustodyStoreError::Invariant(
                "retirement cleanup disappeared",
            ))?
            .value()
            .to_vec();
        let mut cleanup = cleanup_record_for_row(&cleanup_value, Some(&marked))?;
        if cleanup_retirement_dependencies_write(write, key, &mut cleanup, &mut budget)?
            == RetirementCleanupProgress::Complete
        {
            write
                .open_table(CUSTODY_RETIRING)?
                .remove(cleanup_key.as_slice())?;
        }
        let global_fits = require_quota_capacity(
            custody_usage_write(write, None)?,
            &global_quota,
            1,
            admission.accounted_bytes,
        )
        .is_ok();
        let scope_fits = match &scope_quota {
            Some(quota) => require_quota_capacity(
                custody_usage_write(write, Some(&admission.scope))?,
                quota,
                1,
                admission.accounted_bytes,
            )
            .is_ok(),
            None => true,
        };
        if global_fits && scope_fits {
            return Ok(());
        }
    }
    // Any marks/retirements above remain in the same uncommitted source
    // transaction; this exact error rolls them all back.
    check_admission_capacity(write, admission, limits)
}

pub(crate) fn make_aggregate_capacity_write(
    write: &redb::WriteTransaction,
    limits: StoreLimits,
    request: AggregateCapacityRequest,
) -> Result<(), StoreError> {
    let fits = |write: &redb::WriteTransaction| -> Result<(), StoreError> {
        let metadata = write.open_table(METADATA)?;
        if request.emergency {
            require_aggregate_capacity(&metadata, limits, request.usage.items, request.usage.bytes)
        } else {
            require_ordinary_aggregate_capacity(
                write,
                &metadata,
                limits,
                request.usage.items,
                request.usage.bytes,
            )
        }
    };
    if fits(write).is_ok() {
        return Ok(());
    }
    let mut candidates = BinaryHeap::new();
    let items = write.open_table(CUSTODY_ITEMS)?;
    for row in items.iter()? {
        let (encoded_key, encoded_item) = row?;
        let key = CustodyObjectKey::decode(encoded_key.value())?;
        let item = decode_item(encoded_item.value())?;
        if item.tombstone
            || item.retiring
            || !matches!(
                key.class,
                CustodyObjectClass::Event | CustodyObjectClass::RouteEvent
            )
        {
            continue;
        }
        let (status, _) = evaluate_item(&item, request.continuity, request.sample);
        let (expired, age_ms, remaining) = match status {
            CustodyAgeStatus::Expired { age_ms } => (true, age_ms, 0),
            CustodyAgeStatus::Forwardable {
                age_ms,
                remaining_ms,
            } => (false, age_ms, remaining_ms),
            CustodyAgeStatus::Durable | CustodyAgeStatus::WithheldUnknownAge => {
                (false, item.cumulative_age_ms, u64::MAX)
            }
        };
        if !expired
            && (item.protection.protects_eviction()
                || retirement_reference_exists_write(
                    write,
                    RETIREMENT_REFERENCE_PENDING,
                    item.semantic_id.as_slice(),
                )?)
        {
            continue;
        }
        if !expired && !request.emergency && item.priority >= request.priority {
            continue;
        }
        retain_best_retirement_candidate(
            &mut candidates,
            RankedRetirementCandidate {
                order: (
                    !expired,
                    !item.route_only,
                    item.priority,
                    remaining,
                    item.acceptance_order,
                    key,
                ),
                key,
                item,
                age_ms,
                expired,
            },
        );
    }
    drop(items);
    let mut budget = MaintenanceBudget::default();
    for candidate in candidates.into_sorted_vec() {
        let RankedRetirementCandidate {
            key,
            item,
            age_ms,
            expired,
            ..
        } = candidate;
        let marked = mark_retiring_write_indexed(write, key, item, age_ms)?;
        if retirement_reference_exists_write(
            write,
            RETIREMENT_REFERENCE_LEASE,
            key.encoded().as_slice(),
        )? {
            continue;
        }
        let reason = if expired {
            CustodyRetirementReason::Expired
        } else {
            CustodyRetirementReason::QuotaPressure
        };
        fence_retirement_write(write, key, &marked, reason)?;
        let cleanup_key = custody_retiring_key(key, &marked).expect("marked retirement key");
        let cleanup_value = write
            .open_table(CUSTODY_RETIRING)?
            .get(cleanup_key.as_slice())?
            .ok_or(CustodyStoreError::Invariant(
                "retirement cleanup disappeared",
            ))?
            .value()
            .to_vec();
        let mut cleanup = cleanup_record_for_row(&cleanup_value, Some(&marked))?;
        if cleanup_retirement_dependencies_write(write, key, &mut cleanup, &mut budget)?
            == RetirementCleanupProgress::Complete
        {
            write
                .open_table(CUSTODY_RETIRING)?
                .remove(cleanup_key.as_slice())?;
        }
        if fits(write).is_ok() {
            return Ok(());
        }
    }
    fits(write)
}

fn immutable_admission_matches(record: &CustodyItemRecord, admission: &CustodyAdmission) -> bool {
    record.semantic_id == admission.semantic_id
        && record.topic == admission.topic
        && record.scope == admission.scope
        && record.source_publisher == admission.source_publisher
        && record.key_epoch == admission.key_epoch
        && record.priority == admission.priority
        && record.ttl_ms == admission.ttl_ms
        && record.tombstone == admission.tombstone
        && record.route_only == admission.route_only
        && record.accounted_bytes == admission.accounted_bytes
        && record.protection == admission.protection
}

fn insert_retirement_fence(
    write: &redb::WriteTransaction,
    key: CustodyObjectKey,
    record: RetirementRecord,
) -> Result<(), StoreError> {
    let metadata = write.open_table(CUSTODY_METADATA)?;
    let current = metadata_value(&metadata, CUSTODY_RETIREMENT_COUNT_KEY)?;
    drop(metadata);
    if current >= MAX_CUSTODY_RETIREMENTS {
        return Err(CustodyStoreError::RetirementLimitExceeded {
            current,
            limit: MAX_CUSTODY_RETIREMENTS,
        }
        .into());
    }
    let encoded = encode_retirement(&record)?;
    if write
        .open_table(CUSTODY_RETIREMENTS)?
        .insert(key.encoded().as_slice(), encoded.as_slice())?
        .is_some()
    {
        return Err(
            CustodyStoreError::Invariant("retirement fence was concurrently reused").into(),
        );
    }
    if key.class == CustodyObjectClass::RouteEvent {
        let encoded_key = key.encoded();
        let current = write
            .open_table(CUSTODY_RETIRED_SEMANTICS)?
            .get(record.semantic_id.as_slice())?
            .map(|value| value.value().to_vec());
        if current
            .as_deref()
            .is_none_or(|current| encoded_key.as_slice() < current)
        {
            write
                .open_table(CUSTODY_RETIRED_SEMANTICS)?
                .insert(record.semantic_id.as_slice(), encoded_key.as_slice())?;
        }
    }
    write
        .open_table(CUSTODY_METADATA)?
        .insert(CUSTODY_RETIREMENT_COUNT_KEY, next_counter(current)?)?;
    Ok(())
}

const RETIREMENT_REFERENCE_LEASE: u8 = 1;
const RETIREMENT_REFERENCE_RETRY: u8 = 2;
const RETIREMENT_REFERENCE_RECEIPT: u8 = 3;
const RETIREMENT_REFERENCE_PENDING: u8 = 4;
const RETIREMENT_REFERENCE_ACKNOWLEDGEMENT: u8 = 5;

fn retirement_reference_key(kind: u8, target: &[u8], primary: &[u8]) -> Vec<u8> {
    let mut encoded = Vec::with_capacity(1 + target.len() + primary.len());
    encoded.push(kind);
    encoded.extend_from_slice(target);
    encoded.extend_from_slice(primary);
    encoded
}

fn retirement_reference_bounds(kind: u8, target: &[u8]) -> Result<(Vec<u8>, Vec<u8>), StoreError> {
    let mut lower = Vec::with_capacity(1 + target.len());
    lower.push(kind);
    lower.extend_from_slice(target);
    let mut upper = lower.clone();
    for index in (0..upper.len()).rev() {
        if upper[index] != u8::MAX {
            upper[index] += 1;
            upper.truncate(index + 1);
            return Ok((lower, upper));
        }
    }
    Err(CustodyStoreError::CounterOverflow.into())
}

fn first_retirement_reference_write(
    write: &redb::WriteTransaction,
    kind: u8,
    target: &[u8],
) -> Result<Option<Vec<u8>>, StoreError> {
    let (lower, upper) = retirement_reference_bounds(kind, target)?;
    let table = write.open_table(CUSTODY_RETIREMENT_REFERENCES)?;
    let row = table
        .range::<&[u8]>((
            std::ops::Bound::Included(lower.as_slice()),
            std::ops::Bound::Excluded(upper.as_slice()),
        ))?
        .next()
        .transpose()?;
    row.map(|(key, value)| {
        if !value.value().is_empty() {
            return Err(CustodyStoreError::Invariant(
                "custody retirement reference value is invalid",
            )
            .into());
        }
        Ok(key.value()[lower.len()..].to_vec())
    })
    .transpose()
}

fn retirement_reference_exists_write(
    write: &redb::WriteTransaction,
    kind: u8,
    target: &[u8],
) -> Result<bool, StoreError> {
    Ok(first_retirement_reference_write(write, kind, target)?.is_some())
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub(crate) struct MaintenanceBudget {
    pub(crate) examined_dependencies: u64,
    pub(crate) removed_pairs: u64,
    pub(crate) examined_numbered_results: u64,
    pub(crate) rewritten_numbered_results: u64,
}

impl MaintenanceBudget {
    pub(crate) fn try_consume_dependency(&mut self) -> Result<bool, StoreError> {
        if self.examined_dependencies >= MAX_CUSTODY_MAINTENANCE_DEPENDENCIES_PER_PASS {
            return Ok(false);
        }
        self.examined_dependencies = next_counter(self.examined_dependencies)?;
        Ok(true)
    }

    pub(crate) fn record_removed_pair(&mut self) -> Result<(), StoreError> {
        self.removed_pairs = next_counter(self.removed_pairs)?;
        Ok(())
    }

    pub(crate) fn record_examined_numbered_result(
        &mut self,
        rewritten: bool,
    ) -> Result<(), StoreError> {
        self.examined_numbered_results = next_counter(self.examined_numbered_results)?;
        if rewritten {
            self.rewritten_numbered_results = next_counter(self.rewritten_numbered_results)?;
        }
        Ok(())
    }

    fn copy_into_report(self, report: &mut CustodyGcReport) {
        report.examined_dependencies = self.examined_dependencies;
        report.removed_pairs = self.removed_pairs;
        report.examined_numbered_results = self.examined_numbered_results;
        report.rewritten_numbered_results = self.rewritten_numbered_results;
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum RetirementCleanupProgress {
    Pending,
    Complete,
}

fn insert_retirement_reference_write(
    write: &redb::WriteTransaction,
    kind: u8,
    target: &[u8],
    primary: &[u8],
) -> Result<(), StoreError> {
    let key = retirement_reference_key(kind, target, primary);
    let empty: &[u8] = &[];
    write
        .open_table(CUSTODY_RETIREMENT_REFERENCES)?
        .insert(key.as_slice(), empty)?;
    Ok(())
}

fn remove_retirement_reference_write(
    write: &redb::WriteTransaction,
    kind: u8,
    target: &[u8],
    primary: &[u8],
    missing: &'static str,
) -> Result<(), StoreError> {
    let key = retirement_reference_key(kind, target, primary);
    if write
        .open_table(CUSTODY_RETIREMENT_REFERENCES)?
        .remove(key.as_slice())?
        .is_none()
    {
        return Err(CustodyStoreError::Invariant(missing).into());
    }
    Ok(())
}

fn insert_lease_retirement_reference_write(
    write: &redb::WriteTransaction,
    object: CustodyObjectKey,
    lease_id: u64,
) -> Result<(), StoreError> {
    insert_retirement_reference_write(
        write,
        RETIREMENT_REFERENCE_LEASE,
        object.encoded().as_slice(),
        &lease_id.to_be_bytes(),
    )
}

fn remove_lease_retirement_reference_write(
    write: &redb::WriteTransaction,
    object: CustodyObjectKey,
    lease_id: u64,
) -> Result<(), StoreError> {
    remove_retirement_reference_write(
        write,
        RETIREMENT_REFERENCE_LEASE,
        object.encoded().as_slice(),
        &lease_id.to_be_bytes(),
        "lease retirement reference disappeared",
    )
}

fn insert_peer_retirement_reference_write(
    write: &redb::WriteTransaction,
    kind: u8,
    primary: &[u8],
) -> Result<(), StoreError> {
    let (_, object) = parse_peer_object_key(primary)?;
    insert_retirement_reference_write(write, kind, object.encoded().as_slice(), primary)
}

fn remove_peer_retirement_reference_write(
    write: &redb::WriteTransaction,
    kind: u8,
    primary: &[u8],
    missing: &'static str,
) -> Result<(), StoreError> {
    let (_, object) = parse_peer_object_key(primary)?;
    remove_retirement_reference_write(write, kind, object.encoded().as_slice(), primary, missing)
}

pub(crate) fn insert_event_pending_retirement_reference_write(
    write: &redb::WriteTransaction,
    semantic_id: EventSemanticId,
    primary: &[u8],
) -> Result<(), StoreError> {
    insert_retirement_reference_write(
        write,
        RETIREMENT_REFERENCE_PENDING,
        semantic_id.as_bytes(),
        primary,
    )
}

pub(crate) fn event_pending_retirement_reference_exists_read(
    read: &redb::ReadTransaction,
    semantic_id: EventSemanticId,
    primary: &[u8],
) -> Result<bool, StoreError> {
    let key = retirement_reference_key(
        RETIREMENT_REFERENCE_PENDING,
        semantic_id.as_bytes(),
        primary,
    );
    Ok(read
        .open_table(CUSTODY_RETIREMENT_REFERENCES)?
        .get(key.as_slice())?
        .is_some())
}

pub(crate) fn event_pending_retirement_reference_exists_write(
    write: &redb::WriteTransaction,
    semantic_id: EventSemanticId,
    primary: &[u8],
) -> Result<bool, StoreError> {
    let key = retirement_reference_key(
        RETIREMENT_REFERENCE_PENDING,
        semantic_id.as_bytes(),
        primary,
    );
    Ok(write
        .open_table(CUSTODY_RETIREMENT_REFERENCES)?
        .get(key.as_slice())?
        .is_some())
}

pub(crate) fn event_acknowledgement_retirement_reference_exists_write(
    write: &redb::WriteTransaction,
    semantic_id: EventSemanticId,
    primary: &[u8],
) -> Result<bool, StoreError> {
    let key = retirement_reference_key(
        RETIREMENT_REFERENCE_ACKNOWLEDGEMENT,
        semantic_id.as_bytes(),
        primary,
    );
    Ok(write
        .open_table(CUSTODY_RETIREMENT_REFERENCES)?
        .get(key.as_slice())?
        .is_some())
}

pub(crate) fn event_acknowledgement_retirement_reference_exists_read(
    read: &redb::ReadTransaction,
    semantic_id: EventSemanticId,
    primary: &[u8],
) -> Result<bool, StoreError> {
    let key = retirement_reference_key(
        RETIREMENT_REFERENCE_ACKNOWLEDGEMENT,
        semantic_id.as_bytes(),
        primary,
    );
    Ok(read
        .open_table(CUSTODY_RETIREMENT_REFERENCES)?
        .get(key.as_slice())?
        .is_some())
}

pub(crate) fn remove_event_pending_retirement_reference_write(
    write: &redb::WriteTransaction,
    semantic_id: EventSemanticId,
    primary: &[u8],
) -> Result<(), StoreError> {
    remove_retirement_reference_write(
        write,
        RETIREMENT_REFERENCE_PENDING,
        semantic_id.as_bytes(),
        primary,
        "pending Event retirement reference disappeared",
    )
}

pub(crate) fn insert_event_acknowledgement_retirement_reference_write(
    write: &redb::WriteTransaction,
    semantic_id: EventSemanticId,
    primary: &[u8],
) -> Result<(), StoreError> {
    insert_retirement_reference_write(
        write,
        RETIREMENT_REFERENCE_ACKNOWLEDGEMENT,
        semantic_id.as_bytes(),
        primary,
    )
}

pub(crate) fn remove_event_acknowledgement_retirement_reference_write(
    write: &redb::WriteTransaction,
    semantic_id: EventSemanticId,
    primary: &[u8],
) -> Result<(), StoreError> {
    remove_retirement_reference_write(
        write,
        RETIREMENT_REFERENCE_ACKNOWLEDGEMENT,
        semantic_id.as_bytes(),
        primary,
        "Event acknowledgement retirement reference disappeared",
    )
}

fn decrement_custody_counter(
    write: &redb::WriteTransaction,
    field: &'static str,
    amount: u64,
    underflow: &'static str,
) -> Result<(), StoreError> {
    let metadata = write.open_table(CUSTODY_METADATA)?;
    let current = metadata_value(&metadata, field)?;
    drop(metadata);
    write.open_table(CUSTODY_METADATA)?.insert(
        field,
        current
            .checked_sub(amount)
            .ok_or(CustodyStoreError::Invariant(underflow))?,
    )?;
    Ok(())
}

fn active_lease_count(
    write: &redb::WriteTransaction,
    object: CustodyObjectKey,
) -> Result<u64, StoreError> {
    let mut count = 0u64;
    for row in write.open_table(CUSTODY_LEASES)?.iter()? {
        let (_, value) = row?;
        if decode_lease(value.value())?.object == object {
            count = count
                .checked_add(1)
                .ok_or(CustodyStoreError::CounterOverflow)?;
        }
    }
    Ok(count)
}

fn peer_object_has_lease(
    write: &redb::WriteTransaction,
    peer: NodeId,
    object: CustodyObjectKey,
) -> Result<bool, StoreError> {
    for row in write.open_table(CUSTODY_LEASES)?.iter()? {
        let (_, value) = row?;
        let lease = decode_lease(value.value())?;
        if lease.peer == peer && lease.object == object {
            return Ok(true);
        }
    }
    Ok(false)
}

fn replace_expendable_retry(
    write: &redb::WriteTransaction,
    incoming_peer: NodeId,
    incoming_priority: Priority,
) -> Result<bool, StoreError> {
    let active = write
        .open_table(CUSTODY_LEASES)?
        .iter()?
        .map(|row| {
            let (_, value) = row?;
            let lease = decode_lease(value.value())?;
            Ok::<_, StoreError>(peer_object_key(lease.peer, lease.object))
        })
        .collect::<Result<BTreeSet<_>, StoreError>>()?;
    let mut candidates = Vec::new();
    for row in write.open_table(CUSTODY_RETRIES)?.iter()? {
        let (key, value) = row?;
        let (peer, object) = parse_peer_object_key(key.value())?;
        let retry = decode_retry(value.value())?;
        if retry.priority <= incoming_priority && !active.contains(&peer_object_key(peer, object)) {
            candidates.push((
                retry.priority == incoming_priority,
                retry.priority,
                peer != incoming_peer,
                std::cmp::Reverse(retry.due_tick_ms),
                std::cmp::Reverse(retry.attempts),
                key.value().to_vec(),
            ));
        }
    }
    candidates.sort();
    let Some((_, _, _, _, _, victim)) = candidates.into_iter().next() else {
        return Ok(false);
    };
    if write
        .open_table(CUSTODY_RETRIES)?
        .remove(victim.as_slice())?
        .is_none()
    {
        return Err(CustodyStoreError::Invariant("retry replacement victim disappeared").into());
    }
    remove_peer_retirement_reference_write(
        write,
        RETIREMENT_REFERENCE_RETRY,
        victim.as_slice(),
        "retry replacement retirement reference disappeared",
    )?;
    Ok(true)
}

fn update_item_accounting_remove(
    write: &redb::WriteTransaction,
    record: &CustodyItemRecord,
) -> Result<(), StoreError> {
    let metadata = write.open_table(CUSTODY_METADATA)?;
    let items = metadata_value(&metadata, CUSTODY_ITEM_COUNT_KEY)?;
    let bytes = metadata_value(&metadata, CUSTODY_TOTAL_BYTES_KEY)?;
    let ordinary_items = metadata_value(&metadata, CUSTODY_ORDINARY_ITEM_COUNT_KEY)?;
    let ordinary_bytes = metadata_value(&metadata, CUSTODY_ORDINARY_TOTAL_BYTES_KEY)?;
    drop(metadata);
    let final_items = items.checked_sub(1).ok_or(CustodyStoreError::Invariant(
        "custody item accounting underflow",
    ))?;
    let final_bytes =
        bytes
            .checked_sub(record.accounted_bytes)
            .ok_or(CustodyStoreError::Invariant(
                "custody byte accounting underflow",
            ))?;
    let mut metadata = write.open_table(CUSTODY_METADATA)?;
    metadata.insert(CUSTODY_ITEM_COUNT_KEY, final_items)?;
    metadata.insert(CUSTODY_TOTAL_BYTES_KEY, final_bytes)?;
    if !record.tombstone {
        metadata.insert(
            CUSTODY_ORDINARY_ITEM_COUNT_KEY,
            ordinary_items
                .checked_sub(1)
                .ok_or(CustodyStoreError::Invariant(
                    "ordinary custody item accounting underflow",
                ))?,
        )?;
        metadata.insert(
            CUSTODY_ORDINARY_TOTAL_BYTES_KEY,
            ordinary_bytes.checked_sub(record.accounted_bytes).ok_or(
                CustodyStoreError::Invariant("ordinary custody byte accounting underflow"),
            )?,
        )?;
    }
    drop(metadata);
    if record.tombstone {
        return Ok(());
    }
    let scope_key = record.scope.as_str();
    let usage = write
        .open_table(CUSTODY_SCOPE_USAGE)?
        .get(scope_key)?
        .map(|value| decode_scope_usage(value.value()))
        .transpose()?
        .ok_or(CustodyStoreError::Invariant(
            "custody item scope usage is missing",
        ))?;
    let final_scope_items = usage
        .items
        .checked_sub(1)
        .ok_or(CustodyStoreError::Invariant(
            "custody scope item accounting underflow",
        ))?;
    let final_scope_bytes =
        usage
            .bytes
            .checked_sub(record.accounted_bytes)
            .ok_or(CustodyStoreError::Invariant(
                "custody scope byte accounting underflow",
            ))?;
    let mut scope_usage = write.open_table(CUSTODY_SCOPE_USAGE)?;
    if final_scope_items == 0 {
        if final_scope_bytes != 0 || scope_usage.remove(scope_key)?.is_none() {
            return Err(CustodyStoreError::Invariant(
                "custody scope usage did not drain atomically",
            )
            .into());
        }
    } else {
        if final_scope_bytes == 0 {
            return Err(CustodyStoreError::Invariant(
                "custody scope byte usage reached zero before its item count",
            )
            .into());
        }
        scope_usage.insert(
            scope_key,
            encode_scope_usage(CustodyUsage {
                items: final_scope_items,
                bytes: final_scope_bytes,
            })
            .as_slice(),
        )?;
    }
    Ok(())
}

fn update_item_accounting_add(
    write: &redb::WriteTransaction,
    record: &CustodyItemRecord,
) -> Result<(), StoreError> {
    let metadata = write.open_table(CUSTODY_METADATA)?;
    let current_items = metadata_value(&metadata, CUSTODY_ITEM_COUNT_KEY)?;
    let current_bytes = metadata_value(&metadata, CUSTODY_TOTAL_BYTES_KEY)?;
    let ordinary_items = metadata_value(&metadata, CUSTODY_ORDINARY_ITEM_COUNT_KEY)?;
    let ordinary_bytes = metadata_value(&metadata, CUSTODY_ORDINARY_TOTAL_BYTES_KEY)?;
    drop(metadata);
    let mut metadata = write.open_table(CUSTODY_METADATA)?;
    metadata.insert(CUSTODY_ITEM_COUNT_KEY, next_counter(current_items)?)?;
    metadata.insert(
        CUSTODY_TOTAL_BYTES_KEY,
        current_bytes
            .checked_add(record.accounted_bytes)
            .ok_or(CustodyStoreError::CounterOverflow)?,
    )?;
    if !record.tombstone {
        metadata.insert(
            CUSTODY_ORDINARY_ITEM_COUNT_KEY,
            next_counter(ordinary_items)?,
        )?;
        metadata.insert(
            CUSTODY_ORDINARY_TOTAL_BYTES_KEY,
            ordinary_bytes
                .checked_add(record.accounted_bytes)
                .ok_or(CustodyStoreError::CounterOverflow)?,
        )?;
    }
    drop(metadata);
    if record.tombstone {
        return Ok(());
    }
    let scope_key = record.scope.as_str();
    let usage = write
        .open_table(CUSTODY_SCOPE_USAGE)?
        .get(scope_key)?
        .map(|value| decode_scope_usage(value.value()))
        .transpose()?
        .unwrap_or_default();
    let usage = CustodyUsage {
        items: next_counter(usage.items)?,
        bytes: usage
            .bytes
            .checked_add(record.accounted_bytes)
            .ok_or(CustodyStoreError::CounterOverflow)?,
    };
    write
        .open_table(CUSTODY_SCOPE_USAGE)?
        .insert(scope_key, encode_scope_usage(usage).as_slice())?;
    Ok(())
}

fn decrement_shared_counter(
    write: &redb::WriteTransaction,
    field: &'static str,
    amount: u64,
) -> Result<(), StoreError> {
    let metadata = write.open_table(METADATA)?;
    let current = metadata
        .get(field)?
        .map(|value| value.value())
        .ok_or(StoreError::MissingAccountingMetadata { field })?;
    drop(metadata);
    let final_value = current
        .checked_sub(amount)
        .ok_or(StoreError::AccountingMismatch {
            field,
            durable: current,
            reconstructed: amount,
        })?;
    write.open_table(METADATA)?.insert(field, final_value)?;
    Ok(())
}

pub(crate) fn cleanup_retirement_dependencies_write(
    write: &redb::WriteTransaction,
    key: CustodyObjectKey,
    cleanup: &mut RetirementCleanupRecord,
    budget: &mut MaintenanceBudget,
) -> Result<RetirementCleanupProgress, StoreError> {
    let object = key.encoded();
    loop {
        let next = [
            (RETIREMENT_REFERENCE_RETRY, object.as_slice()),
            (RETIREMENT_REFERENCE_RECEIPT, object.as_slice()),
            (RETIREMENT_REFERENCE_PENDING, cleanup.semantic_id.as_slice()),
            (
                RETIREMENT_REFERENCE_ACKNOWLEDGEMENT,
                cleanup.semantic_id.as_slice(),
            ),
        ]
        .into_iter()
        .find_map(|(kind, target)| {
            first_retirement_reference_write(write, kind, target)
                .transpose()
                .map(|primary| primary.map(|primary| (kind, target.to_vec(), primary)))
        })
        .transpose()?;
        let Some((kind, target, primary)) = next else {
            break;
        };
        if !budget.try_consume_dependency()? {
            return Ok(RetirementCleanupProgress::Pending);
        }
        match kind {
            RETIREMENT_REFERENCE_RETRY => {
                let (_, referenced) = parse_peer_object_key(&primary)?;
                if referenced != key {
                    return Err(CustodyStoreError::Invariant(
                        "retry retirement reference targets a different object",
                    )
                    .into());
                }
                let retry = write
                    .open_table(CUSTODY_RETRIES)?
                    .remove(primary.as_slice())?
                    .map(|value| decode_retry(value.value()))
                    .transpose()?
                    .ok_or(CustodyStoreError::Invariant(
                        "retry retirement reference points to a missing row",
                    ))?;
                if retry.item_revision != cleanup.original_revision
                    || retry.priority != cleanup.priority
                {
                    return Err(CustodyStoreError::Invariant(
                        "retry cleanup differs from retirement authority",
                    )
                    .into());
                }
                decrement_custody_counter(
                    write,
                    CUSTODY_RETRY_COUNT_KEY,
                    1,
                    "retry accounting underflow",
                )?;
            }
            RETIREMENT_REFERENCE_RECEIPT => {
                let (_, referenced) = parse_peer_object_key(&primary)?;
                if referenced != key {
                    return Err(CustodyStoreError::Invariant(
                        "receipt retirement reference targets a different object",
                    )
                    .into());
                }
                let receipt = write
                    .open_table(CUSTODY_PEER_RECEIPTS)?
                    .remove(primary.as_slice())?
                    .map(|value| decode_receipt(value.value()))
                    .transpose()?
                    .ok_or(CustodyStoreError::Invariant(
                        "receipt retirement reference points to a missing row",
                    ))?;
                if receipt.item_revision != cleanup.original_revision {
                    return Err(CustodyStoreError::Invariant(
                        "receipt cleanup differs from retirement authority",
                    )
                    .into());
                }
                decrement_custody_counter(
                    write,
                    CUSTODY_RECEIPT_COUNT_KEY,
                    1,
                    "peer receipt accounting underflow",
                )?;
            }
            RETIREMENT_REFERENCE_PENDING => {
                let _ = parse_event_pending_delivery_key(&primary)?;
                let pending = write
                    .open_table(EVENT_SUBSCRIPTION_PENDING)?
                    .remove(primary.as_slice())?
                    .map(|value| decode_event_pending_delivery_record(value.value()))
                    .transpose()?
                    .ok_or(CustodyStoreError::Invariant(
                        "pending retirement reference points to a missing delivery",
                    ))?;
                if pending.semantic_id.as_bytes() != cleanup.semantic_id.as_slice() {
                    return Err(CustodyStoreError::Invariant(
                        "pending cleanup differs from retirement authority",
                    )
                    .into());
                }
                decrement_shared_counter(write, EVENT_PENDING_DELIVERY_COUNT, 1)?;
            }
            RETIREMENT_REFERENCE_ACKNOWLEDGEMENT => {
                let (_, semantic_id) = parse_event_acknowledgement_key(&primary)?;
                if semantic_id.as_bytes() != cleanup.semantic_id.as_slice() {
                    return Err(CustodyStoreError::Invariant(
                        "acknowledgement cleanup differs from retirement authority",
                    )
                    .into());
                }
                let _ = write
                    .open_table(EVENT_DELIVERY_ACKNOWLEDGEMENTS)?
                    .remove(primary.as_slice())?
                    .map(|value| decode_event_acknowledgement_record(value.value()))
                    .transpose()?
                    .ok_or(CustodyStoreError::Invariant(
                        "acknowledgement retirement reference points to a missing row",
                    ))?;
                decrement_shared_counter(write, EVENT_ACKNOWLEDGEMENT_COUNT, 1)?;
            }
            _ => unreachable!("selected cleanup dependency kind"),
        }
        remove_retirement_reference_write(
            write,
            kind,
            target.as_slice(),
            primary.as_slice(),
            "retirement cleanup reference disappeared",
        )?;
        budget.record_removed_pair()?;
    }
    if key.class == CustodyObjectClass::Event {
        match crate::event_operation::cleanup_retired_event_operations_write(
            write,
            EventTransferId::new(key.transfer_id),
            cleanup.reason,
            budget,
        )
        .map_err(crate::event_operation::classify_retirement_invariant)?
        {
            RetirementCleanupProgress::Pending => {
                return Ok(RetirementCleanupProgress::Pending);
            }
            RetirementCleanupProgress::Complete => {}
        }
        match crate::numbered_event_operation::cleanup_numbered_results_write(
            write,
            EventTransferId::new(key.transfer_id),
            cleanup.reason,
            &mut cleanup.numbered_cursor,
            budget,
        )? {
            RetirementCleanupProgress::Pending => {
                let cleanup_key = if let Some(item) = write
                    .open_table(CUSTODY_ITEMS)?
                    .get(key.encoded().as_slice())?
                    .map(|value| decode_item(value.value()))
                    .transpose()?
                {
                    retirement_cleanup_key_for_authority(key, item.acceptance_order)
                } else {
                    let fence = write
                        .open_table(CUSTODY_RETIREMENTS)?
                        .get(key.encoded().as_slice())?
                        .map(|value| decode_retirement(value.value()))
                        .transpose()?
                        .ok_or(CustodyStoreError::Invariant(
                            "retirement cleanup lost its item and fence authority",
                        ))?;
                    retirement_cleanup_key_for_authority(key, fence.acceptance_order)
                };
                let encoded = encode_retirement_cleanup(cleanup)?;
                write
                    .open_table(CUSTODY_RETIRING)?
                    .insert(cleanup_key.as_slice(), encoded.as_slice())?;
                return Ok(RetirementCleanupProgress::Pending);
            }
            RetirementCleanupProgress::Complete => {}
        }
    }
    Ok(RetirementCleanupProgress::Complete)
}

fn retire_event_payload_write(
    write: &redb::WriteTransaction,
    key: CustodyObjectKey,
    record: &CustodyItemRecord,
) -> Result<(), StoreError> {
    let transfer = key.transfer_id.as_slice();
    let encoded_metadata = write
        .open_table(EVENTS)?
        .get(transfer)?
        .map(|value| value.value().to_vec())
        .ok_or(CustodyStoreError::Invariant(
            "custody Event is missing durable metadata",
        ))?;
    let event_metadata = decode_event_metadata(&encoded_metadata)?;
    if event_metadata.semantic_id.as_bytes() != &record.semantic_id
        || event_metadata.header.topic != record.topic
        || event_metadata.header.scope != record.scope
        || event_metadata.header.stamp.dot.publisher != record.source_publisher
        || event_metadata.header.key_epoch != record.key_epoch
    {
        return Err(CustodyStoreError::Invariant(
            "custody Event semantic identity differs from durable metadata",
        )
        .into());
    }
    let exact_len = write
        .open_table(EVENT_BYTES)?
        .get(transfer)?
        .map(|value| u64::try_from(value.value().len()))
        .transpose()
        .map_err(|_| CustodyStoreError::CounterOverflow)?
        .ok_or(CustodyStoreError::Invariant(
            "custody Event is missing exact bytes",
        ))?;
    if exact_len != record.accounted_bytes {
        return Err(CustodyStoreError::Invariant(
            "custody Event accounted bytes differ from the exact representation",
        )
        .into());
    }
    if write.open_table(EVENT_BYTES)?.remove(transfer)?.is_none() {
        return Err(CustodyStoreError::Invariant(
            "custody Event bytes disappeared during retirement",
        )
        .into());
    }
    decrement_shared_counter(write, SEMANTIC_ITEM_COUNT, 1)?;
    decrement_shared_counter(write, SEMANTIC_TOTAL_BYTES, exact_len)?;
    Ok(())
}

fn retire_route_event_payload_write(
    write: &redb::WriteTransaction,
    key: CustodyObjectKey,
    record: &CustodyItemRecord,
) -> Result<(), StoreError> {
    let transfer = key.transfer_id.as_slice();
    let exact_len = write
        .open_table(ROUTE_CACHE)?
        .get(transfer)?
        .map(|value| u64::try_from(value.value().len()))
        .transpose()
        .map_err(|_| CustodyStoreError::CounterOverflow)?
        .ok_or(CustodyStoreError::Invariant(
            "custody route Event is missing exact bytes",
        ))?;
    if exact_len != record.accounted_bytes {
        return Err(CustodyStoreError::Invariant(
            "custody route Event accounted bytes differ from the exact representation",
        )
        .into());
    }
    let claim = write
        .open_table(ROUTE_CACHE_CLAIMS)?
        .get(transfer)?
        .map(|value| decode_event_metadata(value.value()))
        .transpose()?
        .ok_or(CustodyStoreError::Invariant(
            "custody route Event is missing its route claim",
        ))?;
    if claim.semantic_id.as_bytes() != &record.semantic_id
        || claim.header.topic != record.topic
        || claim.header.scope != record.scope
        || claim.header.stamp.dot.publisher != record.source_publisher
        || claim.header.key_epoch != record.key_epoch
    {
        return Err(CustodyStoreError::Invariant(
            "custody route Event semantic identity differs from its route claim",
        )
        .into());
    }
    if write.open_table(ROUTE_CACHE)?.remove(transfer)?.is_none()
        || write
            .open_table(ROUTE_CACHE_CLAIMS)?
            .remove(transfer)?
            .is_none()
    {
        return Err(
            CustodyStoreError::Invariant("route Event disappeared during retirement").into(),
        );
    }
    decrement_shared_counter(write, ROUTE_CACHE_ITEM_COUNT, 1)?;
    decrement_shared_counter(write, ROUTE_CACHE_TOTAL_BYTES, exact_len)?;
    Ok(())
}

fn retire_payload_write(
    write: &redb::WriteTransaction,
    key: CustodyObjectKey,
    record: &CustodyItemRecord,
) -> Result<(), StoreError> {
    match key.class {
        CustodyObjectClass::Event => retire_event_payload_write(write, key, record),
        CustodyObjectClass::RouteEvent => retire_route_event_payload_write(write, key, record),
        class => Err(CustodyStoreError::UnsupportedRetirementClass(class).into()),
    }
}

fn fence_retirement_write(
    write: &redb::WriteTransaction,
    key: CustodyObjectKey,
    record: &CustodyItemRecord,
    reason: CustodyRetirementReason,
) -> Result<(), StoreError> {
    if !record.retiring {
        return Err(CustodyStoreError::Invariant("retirement finalized before its mark").into());
    }
    if retirement_reference_exists_write(
        write,
        RETIREMENT_REFERENCE_LEASE,
        key.encoded().as_slice(),
    )? {
        return Err(CustodyStoreError::Retiring.into());
    }
    retire_payload_write(write, key, record)?;
    #[cfg(test)]
    event_operation::retirement_test_fault(4)?;
    let retired_revision = advance_revision(write, false)?.1;
    insert_retirement_fence(
        write,
        key,
        RetirementRecord {
            semantic_id: record.semantic_id,
            topic: record.topic.clone(),
            scope: record.scope.clone(),
            source_publisher: record.source_publisher,
            key_epoch: record.key_epoch,
            reason,
            cumulative_age_ms: record.cumulative_age_ms,
            accounted_bytes: record.accounted_bytes,
            acceptance_order: record.acceptance_order,
            retired_revision,
        },
    )?;
    if write
        .open_table(CUSTODY_ITEMS)?
        .remove(key.encoded().as_slice())?
        .is_none()
    {
        return Err(
            CustodyStoreError::Invariant("custody item disappeared during retirement").into(),
        );
    }
    update_item_accounting_remove(write, record)?;
    #[cfg(test)]
    event_operation::retirement_test_fault(5)?;
    Ok(())
}

#[cfg(test)]
pub(crate) fn fence_retirement_without_cleanup_write(
    write: &redb::WriteTransaction,
    key: CustodyObjectKey,
    age_ms: u64,
) -> Result<(), StoreError> {
    let encoded_key = key.encoded();
    let item = write
        .open_table(CUSTODY_ITEMS)?
        .get(encoded_key.as_slice())?
        .map(|value| decode_item(value.value()))
        .transpose()?
        .ok_or(CustodyStoreError::ItemNotFound)?;
    let marked = mark_retiring_write_indexed(write, key, item, age_ms)?;
    fence_retirement_write(write, key, &marked, deferred_retirement_reason(&marked))
}

fn deferred_retirement_reason(record: &CustodyItemRecord) -> CustodyRetirementReason {
    if !record.tombstone
        && record
            .ttl_ms
            .is_some_and(|ttl| record.cumulative_age_ms >= ttl)
    {
        CustodyRetirementReason::Expired
    } else {
        CustodyRetirementReason::QuotaPressure
    }
}

fn mark_retiring_write(
    write: &redb::WriteTransaction,
    key: CustodyObjectKey,
    record: CustodyItemRecord,
    age_ms: u64,
) -> Result<CustodyItemRecord, StoreError> {
    mark_retiring_write_indexed(write, key, record, age_ms)
}

fn mark_retiring_write_indexed(
    write: &redb::WriteTransaction,
    key: CustodyObjectKey,
    mut record: CustodyItemRecord,
    age_ms: u64,
) -> Result<CustodyItemRecord, StoreError> {
    if !record.retiring {
        let original = record.clone();
        record.retiring = true;
        record.cumulative_age_ms = record.cumulative_age_ms.max(age_ms);
        record.checkpoint = None;
        let encoded = encode_item(&record)?;
        write
            .open_table(CUSTODY_ITEMS)?
            .insert(key.encoded().as_slice(), encoded.as_slice())?;
        replace_custody_maintenance_indexes_write(write, key, Some(&original), Some(&record))?;
        advance_revision(write, true)?;
    }
    Ok(record)
}

/// Inserts or merges one already-derived custody row inside the caller's
/// source-envelope redb transaction. Authority and policy must be checked by
/// that caller before invoking this structural helper.
pub(crate) fn admit_custody_row_write(
    write: &redb::WriteTransaction,
    admission: &CustodyAdmission,
    continuity: Option<ContinuityRecord>,
    limits: StoreLimits,
) -> Result<CustodyAdmissionOutcome, StoreError> {
    let key = admission.key.encoded();
    let retired = write
        .open_table(CUSTODY_RETIREMENTS)?
        .get(key.as_slice())?
        .map(|value| value.value().to_vec());
    if let Some(encoded) = retired {
        let mut retirement = decode_retirement(&encoded)?;
        if retirement.semantic_id != admission.semantic_id {
            return Err(CustodyStoreError::InvalidAdmission(
                "retired transfer was replayed with another semantic identity",
            )
            .into());
        }
        let durable_age_ms = retirement
            .cumulative_age_ms
            .max(admission.authenticated_age_ms);
        if durable_age_ms != retirement.cumulative_age_ms {
            retirement.cumulative_age_ms = durable_age_ms;
            let encoded = encode_retirement(&retirement)?;
            write
                .open_table(CUSTODY_RETIREMENTS)?
                .insert(key.as_slice(), encoded.as_slice())?;
            advance_revision(write, false)?;
        }
        return Ok(CustodyAdmissionOutcome::AlreadyRetired { durable_age_ms });
    }
    let existing_item = write
        .open_table(CUSTODY_ITEMS)?
        .get(key.as_slice())?
        .map(|value| value.value().to_vec());
    if let Some(encoded) = existing_item {
        let mut record = decode_item(&encoded)?;
        if !immutable_admission_matches(&record, admission) {
            return Err(CustodyStoreError::InvalidAdmission(
                "exact transfer retry changed immutable custody metadata",
            )
            .into());
        }
        if record.retiring {
            return Err(CustodyStoreError::Retiring.into());
        }
        let original = record.clone();
        let (durable_age_ms, newly_lost, expired) = merge_authenticated_age(
            &mut record,
            continuity,
            admission.sample,
            admission.authenticated_age_ms,
        )?;
        if expired {
            if record != original {
                replace_custody_maintenance_indexes_write(
                    write,
                    admission.key,
                    Some(&original),
                    Some(&record),
                )?;
            }
            mark_retiring_write(write, admission.key, record, durable_age_ms)?;
        } else if record != original {
            replace_custody_maintenance_indexes_write(
                write,
                admission.key,
                Some(&original),
                Some(&record),
            )?;
            let encoded = encode_item(&record)?;
            write
                .open_table(CUSTODY_ITEMS)?
                .insert(key.as_slice(), encoded.as_slice())?;
            advance_revision(write, newly_lost)?;
        }
        return Ok(CustodyAdmissionOutcome::Duplicate { durable_age_ms });
    }

    if !admission.tombstone {
        // A direct already-expired route admission consumes the same permanent
        // fence budget as a live row would reserve. Check before either shape
        // so live + retired can never exceed the reopen-audited bound.
        require_retirement_reserve_write(write, 1)?;
    }
    if admission.ttl_ms.is_some()
        && !admission.tombstone
        && admission
            .ttl_ms
            .is_some_and(|ttl| admission.authenticated_age_ms >= ttl)
    {
        if admission.key.class == CustodyObjectClass::Event {
            return Err(CustodyStoreError::InvalidAdmission(
                "unaccepted expired Event requires a route-only retirement fence",
            )
            .into());
        }
        let retired_revision = advance_revision(write, false)?.1;
        insert_retirement_fence(
            write,
            admission.key,
            RetirementRecord {
                semantic_id: admission.semantic_id,
                topic: admission.topic.clone(),
                scope: admission.scope.clone(),
                source_publisher: admission.source_publisher,
                key_epoch: admission.key_epoch,
                reason: CustodyRetirementReason::Expired,
                cumulative_age_ms: admission.authenticated_age_ms,
                accounted_bytes: admission.accounted_bytes,
                acceptance_order: admission.acceptance_order,
                retired_revision,
            },
        )?;
        return Ok(CustodyAdmissionOutcome::AlreadyRetired {
            durable_age_ms: admission.authenticated_age_ms,
        });
    }
    make_admission_capacity_write(write, admission, continuity, limits)?;
    let revision = advance_revision(write, false)?.1;
    let finite = admission.ttl_ms.is_some() && !admission.tombstone;
    let record = CustodyItemRecord {
        semantic_id: admission.semantic_id,
        topic: admission.topic.clone(),
        scope: admission.scope.clone(),
        source_publisher: admission.source_publisher,
        key_epoch: admission.key_epoch,
        priority: admission.priority,
        ttl_ms: admission.ttl_ms,
        tombstone: admission.tombstone,
        route_only: admission.route_only,
        retiring: false,
        continuity_lost: false,
        protection: admission.protection,
        accounted_bytes: admission.accounted_bytes,
        cumulative_age_ms: admission.authenticated_age_ms,
        checkpoint: if finite { admission.sample } else { None },
        continuity_generation: if finite {
            continuity
                .ok_or(CustodyStoreError::ContinuityUnavailable)?
                .generation
        } else {
            0
        },
        acceptance_order: admission.acceptance_order,
        revision,
    };
    let encoded = encode_item(&record)?;
    write
        .open_table(CUSTODY_ITEMS)?
        .insert(key.as_slice(), encoded.as_slice())?;
    replace_custody_maintenance_indexes_write(write, admission.key, None, Some(&record))?;
    update_item_accounting_add(write, &record)?;
    Ok(CustodyAdmissionOutcome::Inserted)
}

/// Atomically promotes the same exact route-cached Event custody authority to
/// content-accepted custody, or performs an ordinary Event admission when no
/// route row exists. The one transfer is never double-accounted and an
/// authenticated shorter alternate path cannot lower the durable age.
pub(crate) fn admit_event_custody_row_write(
    write: &redb::WriteTransaction,
    admission: &CustodyAdmission,
    continuity: Option<ContinuityRecord>,
    limits: StoreLimits,
) -> Result<CustodyAdmissionOutcome, StoreError> {
    if admission.key.class != CustodyObjectClass::Event || admission.route_only {
        return Err(CustodyStoreError::InvalidAdmission(
            "Event promotion requires an accepted-Event custody key",
        )
        .into());
    }
    let route_key = CustodyObjectKey::route_event(EventTransferId::new(admission.key.transfer_id));
    let event_key = admission.key.encoded();
    let route_encoded = route_key.encoded();
    let route_retirement = write
        .open_table(CUSTODY_RETIREMENTS)?
        .get(route_encoded.as_slice())?
        .map(|value| value.value().to_vec());
    if let Some(encoded) = route_retirement {
        let mut retirement = decode_retirement(&encoded)?;
        if retirement.semantic_id != admission.semantic_id {
            return Err(CustodyStoreError::InvalidAdmission(
                "retired route transfer changed semantic identity on promotion",
            )
            .into());
        }
        retirement.cumulative_age_ms = retirement
            .cumulative_age_ms
            .max(admission.authenticated_age_ms);
        let encoded = encode_retirement(&retirement)?;
        write
            .open_table(CUSTODY_RETIREMENTS)?
            .insert(route_encoded.as_slice(), encoded.as_slice())?;
        advance_revision(write, false)?;
        return Ok(CustodyAdmissionOutcome::AlreadyRetired {
            durable_age_ms: retirement.cumulative_age_ms,
        });
    }

    let route_item = write
        .open_table(CUSTODY_ITEMS)?
        .get(route_encoded.as_slice())?
        .map(|value| value.value().to_vec());
    let Some(route_item) = route_item else {
        if admission
            .ttl_ms
            .is_some_and(|ttl| !admission.tombstone && admission.authenticated_age_ms >= ttl)
        {
            let mut refused = admission.clone();
            refused.key = route_key;
            refused.route_only = true;
            return admit_custody_row_write(write, &refused, continuity, limits);
        }
        return admit_custody_row_write(write, admission, continuity, limits);
    };
    if write
        .open_table(CUSTODY_ITEMS)?
        .get(event_key.as_slice())?
        .is_some()
    {
        return Err(CustodyStoreError::Invariant(
            "route and accepted custody rows coexist for one transfer",
        )
        .into());
    }
    if active_lease_count(write, route_key)? != 0 {
        return Err(CustodyStoreError::ItemChanged.into());
    }
    let mut record = decode_item(&route_item)?;
    let original_route_record = record.clone();
    if record.semantic_id != admission.semantic_id
        || record.topic != admission.topic
        || record.scope != admission.scope
        || record.source_publisher != admission.source_publisher
        || record.key_epoch != admission.key_epoch
        || record.priority != admission.priority
        || record.ttl_ms != admission.ttl_ms
        || record.tombstone != admission.tombstone
        || record.accounted_bytes != admission.accounted_bytes
        || !record.route_only
    {
        return Err(CustodyStoreError::InvalidAdmission(
            "route custody differs from content-verified Event promotion",
        )
        .into());
    }
    if record.retiring {
        return Err(CustodyStoreError::Retiring.into());
    }
    let (durable_age_ms, newly_lost, expired) = merge_authenticated_age(
        &mut record,
        continuity,
        admission.sample,
        admission.authenticated_age_ms,
    )?;
    if expired {
        if record != original_route_record {
            replace_custody_maintenance_indexes_write(
                write,
                route_key,
                Some(&original_route_record),
                Some(&record),
            )?;
        }
        let marked = mark_retiring_write_indexed(write, route_key, record, durable_age_ms)?;
        fence_retirement_write(write, route_key, &marked, CustodyRetirementReason::Expired)?;
        let cleanup_key = custody_retiring_key(route_key, &marked).expect("marked retirement key");
        let cleanup_value = write
            .open_table(CUSTODY_RETIRING)?
            .get(cleanup_key.as_slice())?
            .ok_or(CustodyStoreError::Invariant(
                "retirement cleanup disappeared",
            ))?
            .value()
            .to_vec();
        let mut cleanup = cleanup_record_for_row(&cleanup_value, Some(&marked))?;
        let mut budget = MaintenanceBudget::default();
        if cleanup_retirement_dependencies_write(write, route_key, &mut cleanup, &mut budget)?
            == RetirementCleanupProgress::Complete
        {
            write
                .open_table(CUSTODY_RETIRING)?
                .remove(cleanup_key.as_slice())?;
        }
        return Ok(CustodyAdmissionOutcome::AlreadyRetired { durable_age_ms });
    }
    record.route_only = false;
    record.acceptance_order = admission.acceptance_order;
    record.protection = admission.protection;
    let encoded = encode_item(&record)?;
    let mut items = write.open_table(CUSTODY_ITEMS)?;
    items.remove(route_encoded.as_slice())?;
    if items
        .insert(event_key.as_slice(), encoded.as_slice())?
        .is_some()
    {
        return Err(CustodyStoreError::Invariant(
            "accepted custody row appeared during route promotion",
        )
        .into());
    }
    drop(items);
    replace_custody_maintenance_indexes_write(
        write,
        route_key,
        Some(&original_route_record),
        None,
    )?;
    replace_custody_maintenance_indexes_write(write, admission.key, None, Some(&record))?;

    // A RouteEvent receipt proves only that the peer received a route-only
    // representation under the then-current selector. Promotion creates the
    // distinct accepted-Event delivery obligation, so neither that receipt nor
    // its retry cadence may be aliased into the Event class.
    let receipt_keys = write
        .open_table(CUSTODY_PEER_RECEIPTS)?
        .iter()?
        .filter_map(|row| match row {
            Ok((key, _)) => match parse_peer_object_key(key.value()) {
                Ok((_, object)) if object == route_key => Some(Ok(key.value().to_vec())),
                Ok((_, object)) if object == admission.key => Some(Err(StoreError::from(
                    CustodyStoreError::Invariant("accepted receipt exists before route promotion"),
                ))),
                Ok(_) => None,
                Err(error) => Some(Err(StoreError::from(error))),
            },
            Err(error) => Some(Err(StoreError::from(error))),
        })
        .collect::<Result<Vec<_>, StoreError>>()?;
    if !receipt_keys.is_empty() {
        let mut receipts = write.open_table(CUSTODY_PEER_RECEIPTS)?;
        for key in &receipt_keys {
            if receipts.remove(key.as_slice())?.is_none() {
                return Err(CustodyStoreError::Invariant(
                    "route receipt disappeared during promotion",
                )
                .into());
            }
            remove_peer_retirement_reference_write(
                write,
                RETIREMENT_REFERENCE_RECEIPT,
                key.as_slice(),
                "route receipt retirement reference disappeared during promotion",
            )?;
        }
        drop(receipts);
        decrement_custody_counter(
            write,
            CUSTODY_RECEIPT_COUNT_KEY,
            u64::try_from(receipt_keys.len()).map_err(|_| CustodyStoreError::CounterOverflow)?,
            "peer receipt accounting underflow during route promotion",
        )?;
    }
    let retry_keys = write
        .open_table(CUSTODY_RETRIES)?
        .iter()?
        .filter_map(|row| match row {
            Ok((key, _)) => match parse_peer_object_key(key.value()) {
                Ok((_, object)) if object == route_key => Some(Ok(key.value().to_vec())),
                Ok((_, object)) if object == admission.key => Some(Err(StoreError::from(
                    CustodyStoreError::Invariant("accepted retry exists before route promotion"),
                ))),
                Ok(_) => None,
                Err(error) => Some(Err(StoreError::from(error))),
            },
            Err(error) => Some(Err(StoreError::from(error))),
        })
        .collect::<Result<Vec<_>, StoreError>>()?;
    if !retry_keys.is_empty() {
        let mut retries = write.open_table(CUSTODY_RETRIES)?;
        for key in &retry_keys {
            if retries.remove(key.as_slice())?.is_none() {
                return Err(CustodyStoreError::Invariant(
                    "route retry disappeared during promotion",
                )
                .into());
            }
            remove_peer_retirement_reference_write(
                write,
                RETIREMENT_REFERENCE_RETRY,
                key.as_slice(),
                "route retry retirement reference disappeared during promotion",
            )?;
        }
        drop(retries);
        decrement_custody_counter(
            write,
            CUSTODY_RETRY_COUNT_KEY,
            u64::try_from(retry_keys.len()).map_err(|_| CustodyStoreError::CounterOverflow)?,
            "retry accounting underflow during route promotion",
        )?;
    }
    advance_revision(write, newly_lost)?;
    Ok(CustodyAdmissionOutcome::Duplicate { durable_age_ms })
}

impl Store {
    /// Returns the exact custody policy generation for race-safe plans.
    pub fn custody_policy_revision(&self) -> Result<CustodyPolicyRevision, StoreError> {
        self.require_live()?;
        self.require_bound_mission()?;
        let read = self.database.begin_read()?;
        if !custody_schema_present_read(&read)? {
            return Err(
                CustodyStoreError::Invariant("custody schema has not been migrated").into(),
            );
        }
        let metadata = read.open_table(CUSTODY_METADATA)?;
        Ok(CustodyPolicyRevision(metadata_value(
            &metadata,
            CUSTODY_POLICY_REVISION_KEY,
        )?))
    }

    /// Installs a durable global or exact-scope quota without silently placing
    /// already-retained data above the requested ceiling.
    pub fn set_custody_quota(
        &self,
        quota: CustodyQuota,
    ) -> Result<CustodyPolicyRevision, StoreError> {
        self.require_live()?;
        let authority = self.require_bound_mission()?;
        let write = self.database.begin_write()?;
        enforce_live_write(&write)?;
        require_custody_mission_write(&write, authority)?;
        if quota.scope.is_none() {
            let reserved = CustodyQuota::for_store_limits(self.limits)?;
            if quota.max_items > reserved.max_items || quota.max_bytes > reserved.max_bytes {
                return Err(CustodyStoreError::InvalidQuota.into());
            }
        }
        let usage = custody_usage_write(&write, quota.scope.as_ref())?;
        require_quota_capacity(usage, &quota, 0, 0)?;
        let key = quota_key(quota.scope.as_ref());
        let encoded = encode_quota(&quota);
        let existing = write
            .open_table(CUSTODY_QUOTAS)?
            .get(key)?
            .map(|value| value.value().to_vec());
        if existing.as_deref() == Some(encoded.as_slice()) {
            let metadata = write.open_table(CUSTODY_METADATA)?;
            return Ok(CustodyPolicyRevision(metadata_value(
                &metadata,
                CUSTODY_POLICY_REVISION_KEY,
            )?));
        }
        if existing.is_none() {
            let metadata = write.open_table(CUSTODY_METADATA)?;
            let current = metadata_value(&metadata, CUSTODY_QUOTA_COUNT_KEY)?;
            drop(metadata);
            if current >= MAX_CUSTODY_QUOTAS {
                return Err(CustodyStoreError::QuotaLimitExceeded {
                    current,
                    limit: MAX_CUSTODY_QUOTAS,
                }
                .into());
            }
            write
                .open_table(CUSTODY_METADATA)?
                .insert(CUSTODY_QUOTA_COUNT_KEY, next_counter(current)?)?;
        }
        write
            .open_table(CUSTODY_QUOTAS)?
            .insert(key, encoded.as_slice())?;
        let (policy_revision, _) = advance_revision(&write, true)?;
        write.commit()?;
        Ok(CustodyPolicyRevision(policy_revision))
    }

    /// Atomically replaces the complete configured quota projection.
    ///
    /// The first row must be global and every override must name one unique
    /// exact scope. Empty `exact_scopes` removes all stale overrides. One
    /// policy revision is allocated for the replacement and all process-local
    /// send authorities are revoked before commit.
    pub fn replace_custody_quotas(
        &self,
        global: CustodyQuota,
        exact_scopes: &[CustodyQuota],
    ) -> Result<CustodyPolicyRevision, StoreError> {
        self.require_live()?;
        let authority = self.require_bound_mission()?;
        if global.scope.is_some() {
            return Err(CustodyStoreError::InvalidQuota.into());
        }
        let reserved = CustodyQuota::for_store_limits(self.limits)?;
        if global.max_items > reserved.max_items || global.max_bytes > reserved.max_bytes {
            return Err(CustodyStoreError::InvalidQuota.into());
        }
        let projected_count = u64::try_from(exact_scopes.len())
            .map_err(|_| CustodyStoreError::CounterOverflow)?
            .checked_add(1)
            .ok_or(CustodyStoreError::CounterOverflow)?;
        if projected_count > MAX_CUSTODY_QUOTAS {
            return Err(CustodyStoreError::QuotaLimitExceeded {
                current: projected_count,
                limit: MAX_CUSTODY_QUOTAS,
            }
            .into());
        }
        let mut seen = BTreeSet::new();
        for quota in exact_scopes {
            let scope = quota
                .scope
                .as_ref()
                .ok_or(CustodyStoreError::InvalidQuota)?;
            if !seen.insert(scope.clone()) {
                return Err(CustodyStoreError::InvalidQuota.into());
            }
        }

        let write = self.database.begin_write()?;
        enforce_live_write(&write)?;
        require_custody_mission_write(&write, authority)?;
        require_quota_capacity(custody_usage_write(&write, None)?, &global, 0, 0)?;
        for quota in exact_scopes {
            require_quota_capacity(
                custody_usage_write(&write, quota.scope.as_ref())?,
                quota,
                0,
                0,
            )?;
        }
        let mut desired = BTreeMap::<String, Vec<u8>>::new();
        desired.insert(GLOBAL_QUOTA_KEY.to_owned(), encode_quota(&global));
        for quota in exact_scopes {
            desired.insert(
                quota_key(quota.scope.as_ref()).to_owned(),
                encode_quota(quota),
            );
        }
        let mut current = BTreeMap::<String, Vec<u8>>::new();
        for row in write.open_table(CUSTODY_QUOTAS)?.iter()? {
            let (key, value) = row?;
            let key = key.value().to_owned();
            let _ = decode_quota(&key, value.value())?;
            current.insert(key, value.value().to_vec());
        }
        if current == desired {
            return policy_revision_write(&write);
        }
        let old_keys = write
            .open_table(CUSTODY_QUOTAS)?
            .iter()?
            .map(|row| row.map(|(key, _)| key.value().to_owned()))
            .collect::<Result<Vec<_>, redb::StorageError>>()?;
        {
            let mut quotas = write.open_table(CUSTODY_QUOTAS)?;
            for key in old_keys {
                quotas.remove(key.as_str())?;
            }
            for (key, encoded) in &desired {
                quotas.insert(key.as_str(), encoded.as_slice())?;
            }
        }
        let retry_keys = write
            .open_table(CUSTODY_RETRIES)?
            .iter()?
            .map(|row| row.map(|(key, _)| key.value().to_vec()))
            .collect::<Result<Vec<_>, redb::StorageError>>()?;
        {
            let mut retries = write.open_table(CUSTODY_RETRIES)?;
            for key in &retry_keys {
                retries.remove(key.as_slice())?;
                remove_peer_retirement_reference_write(
                    &write,
                    RETIREMENT_REFERENCE_RETRY,
                    key.as_slice(),
                    "quota-change retry retirement reference disappeared",
                )?;
            }
        }
        let mut metadata = write.open_table(CUSTODY_METADATA)?;
        metadata.insert(CUSTODY_QUOTA_COUNT_KEY, projected_count)?;
        metadata.insert(CUSTODY_RETRY_COUNT_KEY, 0)?;
        drop(metadata);
        let (policy_revision, _) = advance_revision(&write, true)?;
        write.commit()?;
        Ok(CustodyPolicyRevision(policy_revision))
    }

    /// Returns exact global or exact-scope logical payload accounting.
    pub fn custody_usage(&self, scope: Option<&Scope>) -> Result<CustodyUsage, StoreError> {
        self.require_live()?;
        self.require_bound_mission()?;
        let read = self.database.begin_read()?;
        if scope.is_none() {
            let metadata = read.open_table(CUSTODY_METADATA)?;
            return Ok(CustodyUsage {
                items: metadata_value(&metadata, CUSTODY_ORDINARY_ITEM_COUNT_KEY)?,
                bytes: metadata_value(&metadata, CUSTODY_ORDINARY_TOTAL_BYTES_KEY)?,
            });
        }
        read.open_table(CUSTODY_SCOPE_USAGE)?
            .get(scope.expect("checked scoped usage").as_str())?
            .map(|value| decode_scope_usage(value.value()).map_err(StoreError::from))
            .transpose()
            .map(|usage| usage.unwrap_or_default())
    }

    /// Returns one object's current finite-lifetime status.  This read does not
    /// mutate a newly discovered discontinuity; every mutating/send path below
    /// performs the sticky write before returning.
    pub fn custody_age_status(
        &self,
        key: CustodyObjectKey,
        sample: Option<CustodySample>,
    ) -> Result<Option<CustodyAgeStatus>, StoreError> {
        self.require_live()?;
        self.require_bound_mission()?;
        let read = self.database.begin_read()?;
        if read
            .open_table(CUSTODY_RETIREMENTS)?
            .get(key.encoded().as_slice())?
            .is_some()
        {
            return Ok(Some(CustodyAgeStatus::Expired {
                age_ms: decode_retirement(
                    read.open_table(CUSTODY_RETIREMENTS)?
                        .get(key.encoded().as_slice())?
                        .expect("checked retirement")
                        .value(),
                )?
                .cumulative_age_ms,
            }));
        }
        let Some(record) = read
            .open_table(CUSTODY_ITEMS)?
            .get(key.encoded().as_slice())?
            .map(|value| decode_item(value.value()))
            .transpose()?
        else {
            return Ok(None);
        };
        let continuity = read
            .open_table(CUSTODY_CONTINUITY)?
            .get(CUSTODY_CONTINUITY_KEY)?
            .map(|value| decode_continuity(value.value()))
            .transpose()?;
        Ok(Some(
            evaluate_item(
                &record,
                continuity,
                normalize_read_sample(continuity, sample),
            )
            .0,
        ))
    }

    /// Returns the exact sender-facing status for one custody object.  Every
    /// semantic-version inventory and last-moment send path must treat only a
    /// status whose [`CustodySenderStatus::is_sendable`] is true as authority.
    pub fn custody_sender_status(
        &self,
        key: CustodyObjectKey,
        sample: Option<CustodySample>,
    ) -> Result<Option<CustodySenderStatus>, StoreError> {
        self.require_live()?;
        self.require_bound_mission()?;
        let read = self.database.begin_read()?;
        sender_status_read(&read, key, sample)
    }

    /// Returns an exclusive, class-separated page of receiver-only Event
    /// fences, including both marked retirement awaiting lease drain
    /// and permanent logical retirement. Current receive policy, interest,
    /// source revocation, and exact active scope epoch are rechecked in the
    /// snapshot. These records suppress exact re-offers and are never sender
    /// inventory.
    pub fn event_receiver_fences_with_policy(
        &self,
        policy: &EventReplicationPolicySnapshot,
        after: Option<CustodyObjectKey>,
        limit: usize,
    ) -> Result<Vec<CustodyReceiverFence>, StoreError> {
        if limit == 0 || limit > MAX_CUSTODY_PAGE {
            return Err(CustodyStoreError::PageLimitExceeded {
                requested: limit,
                maximum: MAX_CUSTODY_PAGE,
            }
            .into());
        }
        self.require_live()?;
        let authority = self.require_bound_mission()?;
        let read = self.database.begin_read()?;
        require_control_policy_read(&read, authority, policy.control_policy())?;
        let selector_revision = read
            .open_table(METADATA)?
            .get(EVENT_SELECTOR_REVISION)?
            .ok_or(StoreError::MissingAccountingMetadata {
                field: EVENT_SELECTOR_REVISION,
            })?
            .value();
        if selector_revision != policy.selector_revision()
            || canonical_event_replication_selectors_read(&read)? != policy.selectors
        {
            return Err(StoreError::EventSelectorRevisionChanged);
        }
        let after_encoded = after.map(CustodyObjectKey::encoded);
        let mut fences = BTreeMap::new();
        let retirements = read.open_table(CUSTODY_RETIREMENTS)?;
        let items = read.open_table(CUSTODY_ITEMS)?;
        let lower = after_encoded
            .as_ref()
            .map_or(std::ops::Bound::Unbounded, |encoded| {
                std::ops::Bound::Excluded(encoded.as_slice())
            });
        for row in retirements.range::<&[u8]>((lower, std::ops::Bound::Unbounded))? {
            let (key, value) = row?;
            let key = CustodyObjectKey::decode(key.value())?;
            let record = decode_retirement(value.value())?;
            if !matches!(
                key.class,
                CustodyObjectClass::Event | CustodyObjectClass::RouteEvent
            ) || !receiver_fence_authorized_read(
                &read,
                policy,
                &record.topic,
                &record.scope,
                record.source_publisher,
                record.key_epoch,
            )? {
                continue;
            }
            let opposite = opposite_event_key(key).expect("checked Event retirement class");
            if items.get(key.encoded().as_slice())?.is_some()
                || items.get(opposite.encoded().as_slice())?.is_some()
                || retirements.get(opposite.encoded().as_slice())?.is_some()
            {
                return Err(StoreError::SemanticInvariant(
                    "one Event transfer has custody state in both accepted and route namespaces",
                ));
            }
            fences.insert(
                key,
                CustodyReceiverFence {
                    object: key,
                    semantic_id: record.semantic_id,
                    topic: record.topic,
                    scope: record.scope,
                    source_publisher: record.source_publisher,
                    key_epoch: record.key_epoch,
                    reason: record.reason,
                },
            );
            if fences.len() == limit {
                break;
            }
        }
        // Marked rows and permanent fences are disjoint by invariant. Pulling
        // at most one page from each ordered table is sufficient to determine
        // the first page of their ordered union while keeping memory bounded.
        let lower = after_encoded
            .as_ref()
            .map_or(std::ops::Bound::Unbounded, |encoded| {
                std::ops::Bound::Excluded(encoded.as_slice())
            });
        let mut marked = 0usize;
        for row in items.range::<&[u8]>((lower, std::ops::Bound::Unbounded))? {
            let (key, value) = row?;
            let key = CustodyObjectKey::decode(key.value())?;
            let record = decode_item(value.value())?;
            if !record.retiring
                || !matches!(
                    key.class,
                    CustodyObjectClass::Event | CustodyObjectClass::RouteEvent
                )
                || !receiver_fence_authorized_read(
                    &read,
                    policy,
                    &record.topic,
                    &record.scope,
                    record.source_publisher,
                    record.key_epoch,
                )?
            {
                continue;
            }
            let opposite = opposite_event_key(key).expect("checked Event custody class");
            if items.get(opposite.encoded().as_slice())?.is_some()
                || retirements.get(key.encoded().as_slice())?.is_some()
                || retirements.get(opposite.encoded().as_slice())?.is_some()
            {
                return Err(StoreError::SemanticInvariant(
                    "one Event transfer has custody state in both accepted and route namespaces",
                ));
            }
            let reason = deferred_retirement_reason(&record);
            fences.insert(
                key,
                CustodyReceiverFence {
                    object: key,
                    semantic_id: record.semantic_id,
                    topic: record.topic,
                    scope: record.scope,
                    source_publisher: record.source_publisher,
                    key_epoch: record.key_epoch,
                    reason,
                },
            );
            marked += 1;
            if marked == limit {
                break;
            }
        }
        Ok(fences.into_values().take(limit).collect())
    }

    /// Compatibility alias for callers compiled against the initial custody
    /// projection. The projection now also includes marked receiver fences.
    pub fn retired_event_receiver_fences_with_policy(
        &self,
        policy: &EventReplicationPolicySnapshot,
        after: Option<CustodyObjectKey>,
        limit: usize,
    ) -> Result<Vec<CustodyReceiverFence>, StoreError> {
        self.event_receiver_fences_with_policy(policy, after, limit)
    }

    /// Selects bounded, unacknowledged outbound work in deterministic
    /// priority/expiry/acceptance order.  Unknown or expired finite rows are
    /// withheld; discontinuity is made sticky before the transaction returns.
    pub fn next_custody_outbound(
        &self,
        peer: NodeId,
        selection_policy: CustodyReconciliationSelection,
        budget: CustodyOutboundBudget,
        sample: Option<CustodySample>,
        expected_policy: CustodyPolicyRevision,
    ) -> Result<Vec<CustodyOutbound>, StoreError> {
        self.next_custody_outbound_inner(
            peer,
            selection_policy,
            None,
            budget,
            sample,
            expected_policy,
        )
    }

    /// Selects from an exact bounded reconciliation difference. Filtering the
    /// candidate set before ordering, item limits, and byte budgeting prevents
    /// unrelated locally-held rows from starving missing work.
    pub fn next_custody_outbound_from(
        &self,
        peer: NodeId,
        candidates: &[CustodyObjectKey],
        selection_policy: CustodyReconciliationSelection,
        budget: CustodyOutboundBudget,
        sample: Option<CustodySample>,
        expected_policy: CustodyPolicyRevision,
    ) -> Result<Vec<CustodyOutbound>, StoreError> {
        if candidates.len() > MAX_CUSTODY_PAGE {
            return Err(CustodyStoreError::PageLimitExceeded {
                requested: candidates.len(),
                maximum: MAX_CUSTODY_PAGE,
            }
            .into());
        }
        let candidates = candidates.iter().copied().collect::<BTreeSet<_>>();
        self.next_custody_outbound_inner(
            peer,
            selection_policy,
            Some(&candidates),
            budget,
            sample,
            expected_policy,
        )
    }

    /// Selects the globally best metadata-only outbound candidates from one
    /// authenticated, exact, strictly sorted peer reconciliation difference.
    ///
    /// With [`CustodyReconciliationEvidence::AuthenticatedPeerMissing`], an
    /// exact selected reoffer supersedes its older send-suppression receipt;
    /// unselected receipts remain durable. Blind scheduling honors only a
    /// receipt bound to the exact authenticated peer selector revision and
    /// atomically drops a selected stale or legacy hint. Retry cadence remains
    /// authoritative in both modes. The
    /// entire bounded difference is evaluated under one continuity and policy
    /// snapshot. The store direct-gets both Event classes for a small difference
    /// and otherwise scans its smaller custody table once, using binary search
    /// against `transfer_ids`. It retains only `max_items` rows in a worst-first
    /// heap. No sealed payload bytes are loaded or cloned. Per-send lease
    /// acquisition remains the final race-authoritative check.
    pub fn next_custody_outbound_bulk_from_transfers(
        &self,
        peer: NodeId,
        transfer_ids: &[EventTransferId],
        selection_policy: CustodyReconciliationSelection,
        max_items: usize,
        sample: Option<CustodySample>,
        expected_policy: CustodyPolicyRevision,
    ) -> Result<Vec<CustodyOutbound>, StoreError> {
        if transfer_ids.len() > MAX_CUSTODY_BULK_CANDIDATES {
            return Err(CustodyStoreError::PageLimitExceeded {
                requested: transfer_ids.len(),
                maximum: MAX_CUSTODY_BULK_CANDIDATES,
            }
            .into());
        }
        if max_items > MAX_CUSTODY_BULK_SELECTION {
            return Err(CustodyStoreError::PageLimitExceeded {
                requested: max_items,
                maximum: MAX_CUSTODY_BULK_SELECTION,
            }
            .into());
        }
        if transfer_ids.windows(2).any(|pair| pair[0] >= pair[1]) {
            return Err(CustodyStoreError::InvalidAdmission(
                "bulk Event transfer candidates must be strictly sorted and unique",
            )
            .into());
        }
        if transfer_ids.is_empty() || max_items == 0 {
            return Ok(Vec::new());
        }
        self.require_live()?;
        let authority = self.require_bound_mission()?;
        let write = self.database.begin_write()?;
        enforce_live_write(&write)?;
        require_custody_mission_write(&write, authority)?;
        if policy_revision_write(&write)? != expected_policy {
            write.commit()?;
            return Err(CustodyStoreError::PolicyChanged.into());
        }
        let continuity = sample
            .map(|sample| observe_continuity_write(&write, sample))
            .transpose()?;
        let sample = continuity.map(|record| record.sample).or(sample);
        if policy_revision_write(&write)? != expected_policy {
            write.commit()?;
            return Err(CustodyStoreError::PolicyChanged.into());
        }

        let items = write.open_table(CUSTODY_ITEMS)?;
        let item_count = items.len()?;
        let retirements = write.open_table(CUSTODY_RETIREMENTS)?;
        let receipts = write.open_table(CUSTODY_PEER_RECEIPTS)?;
        let retries = write.open_table(CUSTODY_RETRIES)?;
        let mut selection = BulkCustodySelection {
            receipts: &receipts,
            retries: &retries,
            best: std::collections::BinaryHeap::with_capacity(max_items.saturating_add(1)),
            max_items,
            peer,
            minimum_priority: selection_policy.minimum_priority(),
            continuity,
            sample,
            evidence: selection_policy.evidence(),
        };
        if bulk_custody_lookup_visits(transfer_ids.len(), item_count) < item_count {
            for transfer_id in transfer_ids {
                let event_key = CustodyObjectKey::event(*transfer_id);
                let route_key = CustodyObjectKey::route_event(*transfer_id);
                let event = items
                    .get(event_key.encoded().as_slice())?
                    .map(|value| decode_item(value.value()))
                    .transpose()?;
                let route = items
                    .get(route_key.encoded().as_slice())?
                    .map(|value| decode_item(value.value()))
                    .transpose()?;
                let states = usize::from(event.is_some())
                    + usize::from(route.is_some())
                    + usize::from(retirements.get(event_key.encoded().as_slice())?.is_some())
                    + usize::from(retirements.get(route_key.encoded().as_slice())?.is_some());
                if states > 1 {
                    return Err(StoreError::SemanticInvariant(
                        "one Event transfer appears in multiple live or retired custody states",
                    ));
                }
                if let Some(record) = event {
                    selection.consider(event_key, record)?;
                }
                if let Some(record) = route {
                    selection.consider(route_key, record)?;
                }
            }
        } else {
            for row in items.iter()? {
                let (encoded_key, encoded_record) = row?;
                let key = CustodyObjectKey::decode(encoded_key.value())?;
                let opposite = match key.class {
                    CustodyObjectClass::Event => {
                        CustodyObjectKey::route_event(EventTransferId::new(key.transfer_id))
                    }
                    CustodyObjectClass::RouteEvent => {
                        CustodyObjectKey::event(EventTransferId::new(key.transfer_id))
                    }
                    CustodyObjectClass::State
                    | CustodyObjectClass::Record
                    | CustodyObjectClass::Blob => continue,
                };
                if transfer_ids
                    .binary_search_by(|candidate| candidate.as_bytes().cmp(&key.transfer_id))
                    .is_err()
                {
                    continue;
                }
                let record = decode_item(encoded_record.value())?;
                if items.get(opposite.encoded().as_slice())?.is_some()
                    || retirements.get(key.encoded().as_slice())?.is_some()
                    || retirements.get(opposite.encoded().as_slice())?.is_some()
                {
                    return Err(StoreError::SemanticInvariant(
                        "one Event transfer appears in multiple live or retired custody states",
                    ));
                }
                selection.consider(key, record)?;
            }
        }
        let selected = selection.into_sorted();
        let receipt_keys = selected
            .iter()
            .filter_map(|candidate| {
                let object = candidate.candidate.object;
                let key = peer_object_key(peer, object);
                match receipts.get(key.as_slice()) {
                    Ok(Some(value)) => Some(
                        decode_receipt(value.value())
                            .map(|receipt| (key, object, receipt))
                            .map_err(StoreError::from),
                    ),
                    Ok(None) => None,
                    Err(error) => Some(Err(StoreError::from(error))),
                }
            })
            .collect::<Result<Vec<_>, StoreError>>()?
            .into_iter()
            .filter(|(_, _, receipt)| !selection_policy.evidence().receipt_suppresses(*receipt))
            .collect::<Vec<_>>();
        for (_, object, receipt) in &receipt_keys {
            let item = items
                .get(object.encoded().as_slice())?
                .map(|value| decode_item(value.value()))
                .transpose()?
                .ok_or(CustodyStoreError::Invariant(
                    "selected peer receipt references a missing custody item",
                ))?;
            if item.revision != receipt.item_revision {
                return Err(CustodyStoreError::Invariant(
                    "selected peer receipt differs from its custody item",
                )
                .into());
            }
        }
        drop(retries);
        drop(receipts);
        drop(retirements);
        drop(items);
        if !receipt_keys.is_empty() {
            let mut receipts = write.open_table(CUSTODY_PEER_RECEIPTS)?;
            for (key, _, _) in &receipt_keys {
                if receipts.remove(key.as_slice())?.is_none() {
                    return Err(CustodyStoreError::Invariant(
                        "selected peer receipt disappeared during reconciliation",
                    )
                    .into());
                }
                remove_peer_retirement_reference_write(
                    &write,
                    RETIREMENT_REFERENCE_RECEIPT,
                    key.as_slice(),
                    "reconciled peer receipt retirement reference disappeared",
                )?;
            }
            drop(receipts);
            decrement_custody_counter(
                &write,
                CUSTODY_RECEIPT_COUNT_KEY,
                u64::try_from(receipt_keys.len())
                    .map_err(|_| CustodyStoreError::CounterOverflow)?,
                "peer receipt accounting underflow during reconciliation",
            )?;
            advance_revision(&write, false)?;
        }
        write.commit()?;
        Ok(selected
            .into_iter()
            .map(|candidate| candidate.candidate)
            .collect())
    }

    /// Settles bounded retry rows that an authenticated normal reconciliation
    /// proves are already present in the peer's current receiver baseline.
    ///
    /// `local_sender_inventory` and `peer_missing` must be the exact sorted,
    /// unique inputs/results of the same authenticated reconciliation. A retry
    /// is settled only when its transfer remains in the local sender inventory
    /// and is absent from the peer-missing set. Receive-only or otherwise blind
    /// contacts must not call this method. Work is bounded by the 128-row retry
    /// table; the potentially large inventory slices are only binary-searched.
    pub fn settle_authenticated_peer_inventory(
        &self,
        peer: NodeId,
        local_sender_inventory: &[EventTransferId],
        peer_missing: &[EventTransferId],
        peer_selector_revision: CustodyPeerSelectorRevision,
        expected_policy: CustodyPolicyRevision,
    ) -> Result<u64, StoreError> {
        for candidates in [local_sender_inventory, peer_missing] {
            if candidates.len() > MAX_CUSTODY_BULK_CANDIDATES {
                return Err(CustodyStoreError::PageLimitExceeded {
                    requested: candidates.len(),
                    maximum: MAX_CUSTODY_BULK_CANDIDATES,
                }
                .into());
            }
            if candidates.windows(2).any(|pair| pair[0] >= pair[1]) {
                return Err(CustodyStoreError::InvalidAdmission(
                    "authenticated Event inventory must be strictly sorted and unique",
                )
                .into());
            }
        }
        if peer_missing
            .iter()
            .any(|missing| local_sender_inventory.binary_search(missing).is_err())
        {
            return Err(CustodyStoreError::InvalidAdmission(
                "peer-missing Event inventory is not a subset of the local sender inventory",
            )
            .into());
        }
        if local_sender_inventory.is_empty() {
            return Ok(0);
        }

        self.require_live()?;
        let authority = self.require_bound_mission()?;
        let write = self.database.begin_write()?;
        enforce_live_write(&write)?;
        require_custody_mission_write(&write, authority)?;
        require_policy_revision_write(&write, expected_policy)?;

        let active_objects = write
            .open_table(CUSTODY_LEASES)?
            .iter()?
            .filter_map(|row| match row {
                Ok((_, value)) => match decode_lease(value.value()) {
                    Ok(lease) if lease.peer == peer => Some(Ok(lease.object)),
                    Ok(_) => None,
                    Err(error) => Some(Err(StoreError::from(error))),
                },
                Err(error) => Some(Err(StoreError::from(error))),
            })
            .collect::<Result<BTreeSet<_>, StoreError>>()?;
        let retry_rows = write
            .open_table(CUSTODY_RETRIES)?
            .iter()?
            .filter_map(|row| match row {
                Ok((encoded_key, encoded_retry)) => {
                    let decoded = parse_peer_object_key(encoded_key.value()).and_then(
                        |(candidate_peer, object)| {
                            decode_retry(encoded_retry.value()).map(|retry| {
                                (candidate_peer, object, retry, encoded_key.value().to_vec())
                            })
                        },
                    );
                    match decoded {
                        Ok((candidate_peer, object, retry, encoded_key))
                            if candidate_peer == peer
                                && matches!(
                                    object.class(),
                                    CustodyObjectClass::Event | CustodyObjectClass::RouteEvent
                                )
                                && local_sender_inventory
                                    .binary_search(&EventTransferId::new(object.transfer_id()))
                                    .is_ok()
                                && peer_missing
                                    .binary_search(&EventTransferId::new(object.transfer_id()))
                                    .is_err()
                                && !active_objects.contains(&object) =>
                        {
                            Some(Ok((encoded_key, object, retry)))
                        }
                        Ok(_) => None,
                        Err(error) => Some(Err(StoreError::from(error))),
                    }
                }
                Err(error) => Some(Err(StoreError::from(error))),
            })
            .collect::<Result<Vec<_>, StoreError>>()?;
        if retry_rows.is_empty() {
            write.commit()?;
            return Ok(0);
        }

        let metadata = write.open_table(CUSTODY_METADATA)?;
        let mut retry_count = metadata_value(&metadata, CUSTODY_RETRY_COUNT_KEY)?;
        let mut receipt_count = metadata_value(&metadata, CUSTODY_RECEIPT_COUNT_KEY)?;
        drop(metadata);
        let items = write.open_table(CUSTODY_ITEMS)?;
        let mut retries = write.open_table(CUSTODY_RETRIES)?;
        let mut receipts = write.open_table(CUSTODY_PEER_RECEIPTS)?;
        for (encoded_key, object, retry) in &retry_rows {
            let item = items
                .get(object.encoded().as_slice())?
                .map(|value| decode_item(value.value()))
                .transpose()?;
            if let Some(item) = item {
                if item.revision != retry.item_revision {
                    return Err(CustodyStoreError::Invariant(
                        "authenticated peer-present retry differs from its custody item",
                    )
                    .into());
                }
                if item.retiring {
                    if item.priority != retry.priority {
                        return Err(CustodyStoreError::Invariant(
                            "authenticated peer-present retry priority differs from its marked item",
                        )
                        .into());
                    }
                } else {
                    let existing = receipts
                        .get(encoded_key.as_slice())?
                        .map(|value| decode_receipt(value.value()))
                        .transpose()?;
                    if existing.is_some() {
                        return Err(CustodyStoreError::Invariant(
                            "custody peer/object has both receipt and retry state",
                        )
                        .into());
                    }
                    if receipt_count == MAX_CUSTODY_PEER_RECEIPTS {
                        let replacement = receipts
                            .iter()?
                            .next()
                            .transpose()?
                            .map(|(key, value)| {
                                let _ = parse_peer_object_key(key.value())?;
                                let _ = decode_receipt(value.value())?;
                                Ok::<_, StoreError>(key.value().to_vec())
                            })
                            .transpose()?
                            .ok_or(CustodyStoreError::Invariant(
                                "peer receipt cap is nonzero but its table is empty",
                            ))?;
                        if receipts.remove(replacement.as_slice())?.is_none() {
                            return Err(CustodyStoreError::Invariant(
                                "peer receipt replacement target disappeared",
                            )
                            .into());
                        }
                        remove_peer_retirement_reference_write(
                            &write,
                            RETIREMENT_REFERENCE_RECEIPT,
                            replacement.as_slice(),
                            "peer receipt replacement retirement reference disappeared",
                        )?;
                    } else if receipt_count < MAX_CUSTODY_PEER_RECEIPTS {
                        receipt_count = next_counter(receipt_count)?;
                    } else {
                        return Err(CustodyStoreError::Invariant(
                            "peer receipt accounting exceeds its hard cap",
                        )
                        .into());
                    }
                    let receipt = ReceiptRecord {
                        cumulative_age_ms: item.cumulative_age_ms,
                        item_revision: item.revision,
                        peer_selector_revision: Some(peer_selector_revision.0),
                    };
                    let encoded_receipt = encode_receipt(receipt)?;
                    receipts.insert(encoded_key.as_slice(), encoded_receipt.as_slice())?;
                    insert_peer_retirement_reference_write(
                        &write,
                        RETIREMENT_REFERENCE_RECEIPT,
                        encoded_key.as_slice(),
                    )?;
                }
            } else {
                let cleanup = fenced_cleanup_record_write(&write, *object)?;
                if cleanup.original_revision != retry.item_revision
                    || cleanup.priority != retry.priority
                {
                    return Err(CustodyStoreError::Invariant(
                        "authenticated peer-present retry differs from fenced cleanup authority",
                    )
                    .into());
                }
            }
            if retries.remove(encoded_key.as_slice())?.is_none() {
                return Err(CustodyStoreError::Invariant(
                    "authenticated peer-present retry disappeared during settlement",
                )
                .into());
            }
            remove_peer_retirement_reference_write(
                &write,
                RETIREMENT_REFERENCE_RETRY,
                encoded_key.as_slice(),
                "settled retry retirement reference disappeared",
            )?;
            retry_count = retry_count
                .checked_sub(1)
                .ok_or(CustodyStoreError::Invariant(
                    "retry accounting underflow during peer-present settlement",
                ))?;
        }
        drop(receipts);
        drop(retries);
        drop(items);
        {
            let mut metadata = write.open_table(CUSTODY_METADATA)?;
            metadata.insert(CUSTODY_RETRY_COUNT_KEY, retry_count)?;
            metadata.insert(CUSTODY_RECEIPT_COUNT_KEY, receipt_count)?;
        }
        advance_revision(&write, false)?;
        write.commit()?;
        u64::try_from(retry_rows.len()).map_err(|_| CustodyStoreError::CounterOverflow.into())
    }

    fn next_custody_outbound_inner(
        &self,
        peer: NodeId,
        selection_policy: CustodyReconciliationSelection,
        exact_candidates: Option<&BTreeSet<CustodyObjectKey>>,
        budget: CustodyOutboundBudget,
        sample: Option<CustodySample>,
        expected_policy: CustodyPolicyRevision,
    ) -> Result<Vec<CustodyOutbound>, StoreError> {
        if budget.max_items > MAX_CUSTODY_PAGE {
            return Err(CustodyStoreError::PageLimitExceeded {
                requested: budget.max_items,
                maximum: MAX_CUSTODY_PAGE,
            }
            .into());
        }
        if budget.max_items == 0 || budget.max_bytes == 0 {
            return Ok(Vec::new());
        }
        self.require_live()?;
        let authority = self.require_bound_mission()?;
        let write = self.database.begin_write()?;
        enforce_live_write(&write)?;
        require_custody_mission_write(&write, authority)?;
        if policy_revision_write(&write)? != expected_policy {
            write.commit()?;
            return Err(CustodyStoreError::PolicyChanged.into());
        }
        let continuity = sample
            .map(|sample| observe_continuity_write(&write, sample))
            .transpose()?;
        let sample = continuity.map(|record| record.sample).or(sample);
        if policy_revision_write(&write)? != expected_policy {
            write.commit()?;
            return Err(CustodyStoreError::PolicyChanged.into());
        }
        let mut candidates = Vec::new();
        let rows = if let Some(exact_candidates) = exact_candidates {
            let items = write.open_table(CUSTODY_ITEMS)?;
            let mut rows = Vec::with_capacity(exact_candidates.len());
            for key in exact_candidates {
                if let Some(value) = items.get(key.encoded().as_slice())? {
                    rows.push((*key, value.value().to_vec()));
                }
            }
            rows
        } else {
            write
                .open_table(CUSTODY_ITEMS)?
                .iter()?
                .map(|row| {
                    let (key, value) = row?;
                    Ok((
                        CustodyObjectKey::decode(key.value()).map_err(StoreError::from)?,
                        value.value().to_vec(),
                    ))
                })
                .collect::<Result<Vec<_>, StoreError>>()?
        };
        for (key, encoded_record) in rows {
            let mut record = decode_item(&encoded_record)?;
            if record.retiring || record.priority < selection_policy.minimum_priority() {
                continue;
            }
            if let Some(receipt) = write
                .open_table(CUSTODY_PEER_RECEIPTS)?
                .get(peer_object_key(peer, key).as_slice())?
                .map(|value| decode_receipt(value.value()))
                .transpose()?
                && selection_policy.evidence().receipt_suppresses(receipt)
            {
                continue;
            }
            if let Some(retry) = write
                .open_table(CUSTODY_RETRIES)?
                .get(peer_object_key(peer, key).as_slice())?
                .map(|value| decode_retry(value.value()))
                .transpose()?
                && !sample.is_some_and(|sample| {
                    sample.clock_id == retry.clock_id && sample.tick_ms >= retry.due_tick_ms
                })
            {
                continue;
            }
            let evaluation = evaluate_item_age(&record, continuity, sample)?;
            record = checkpoint_item_age_write(&write, key, record, evaluation)?;
            let (age_ms, remaining_ms) = match evaluation.status {
                CustodyAgeStatus::Durable => (record.cumulative_age_ms, None),
                CustodyAgeStatus::Forwardable {
                    age_ms,
                    remaining_ms,
                } => (age_ms, Some(remaining_ms)),
                CustodyAgeStatus::Expired { .. } | CustodyAgeStatus::WithheldUnknownAge => {
                    continue;
                }
            };
            candidates.push(CustodyOutbound {
                object: key,
                semantic_id: record.semantic_id,
                priority: record.priority,
                age_ms,
                remaining_ms,
                accounted_bytes: record.accounted_bytes,
                acceptance_order: record.acceptance_order,
            });
        }
        candidates.sort_by_key(custody_outbound_order);
        let mut selected = Vec::new();
        let mut selected_bytes = 0u64;
        for candidate in candidates {
            if selected.len() == budget.max_items {
                break;
            }
            let Some(final_bytes) = selected_bytes.checked_add(candidate.accounted_bytes) else {
                break;
            };
            if final_bytes > budget.max_bytes {
                continue;
            }
            selected_bytes = final_bytes;
            selected.push(candidate);
        }
        let receipts = write.open_table(CUSTODY_PEER_RECEIPTS)?;
        let stale_receipt_keys = selected
            .iter()
            .filter_map(|candidate| {
                let key = peer_object_key(peer, candidate.object);
                match receipts.get(key.as_slice()) {
                    Ok(Some(value)) => Some(
                        decode_receipt(value.value())
                            .map(|receipt| (key, candidate.object, receipt))
                            .map_err(StoreError::from),
                    ),
                    Ok(None) => None,
                    Err(error) => Some(Err(StoreError::from(error))),
                }
            })
            .collect::<Result<Vec<_>, StoreError>>()?
            .into_iter()
            .filter(|(_, _, receipt)| !selection_policy.evidence().receipt_suppresses(*receipt))
            .collect::<Vec<_>>();
        drop(receipts);
        for (_, object, receipt) in &stale_receipt_keys {
            let item = write
                .open_table(CUSTODY_ITEMS)?
                .get(object.encoded().as_slice())?
                .map(|value| decode_item(value.value()))
                .transpose()?
                .ok_or(CustodyStoreError::Invariant(
                    "selected stale receipt references a missing custody item",
                ))?;
            if item.revision != receipt.item_revision {
                return Err(CustodyStoreError::Invariant(
                    "selected stale receipt differs from its custody item",
                )
                .into());
            }
        }
        if !stale_receipt_keys.is_empty() {
            let mut receipts = write.open_table(CUSTODY_PEER_RECEIPTS)?;
            for (key, _, _) in &stale_receipt_keys {
                if receipts.remove(key.as_slice())?.is_none() {
                    return Err(CustodyStoreError::Invariant(
                        "selected stale receipt disappeared during scheduling",
                    )
                    .into());
                }
                remove_peer_retirement_reference_write(
                    &write,
                    RETIREMENT_REFERENCE_RECEIPT,
                    key.as_slice(),
                    "stale peer receipt retirement reference disappeared",
                )?;
            }
            drop(receipts);
            decrement_custody_counter(
                &write,
                CUSTODY_RECEIPT_COUNT_KEY,
                u64::try_from(stale_receipt_keys.len())
                    .map_err(|_| CustodyStoreError::CounterOverflow)?,
                "peer receipt accounting underflow during scheduling",
            )?;
            advance_revision(&write, false)?;
        }
        write.commit()?;
        Ok(selected)
    }

    /// Creates a durable lease only after final policy, revision, peer-receipt,
    /// and finite-age rechecks in the same transaction.
    pub fn begin_custody_send(
        &self,
        peer: NodeId,
        key: CustodyObjectKey,
        peer_selector_revision: CustodyPeerSelectorRevision,
        sample: Option<CustodySample>,
        link_floor_ms: u64,
        expected_policy: CustodyPolicyRevision,
    ) -> Result<TransferLease, StoreError> {
        self.require_live()?;
        let authority = self.require_bound_mission()?;
        let write = self.database.begin_write()?;
        enforce_live_write(&write)?;
        require_custody_mission_write(&write, authority)?;
        if policy_revision_write(&write)? != expected_policy {
            write.commit()?;
            return Err(CustodyStoreError::PolicyChanged.into());
        }
        let continuity = sample
            .map(|sample| observe_continuity_write(&write, sample))
            .transpose()?;
        let sample = continuity.map(|record| record.sample).or(sample);
        if policy_revision_write(&write)? != expected_policy {
            write.commit()?;
            return Err(CustodyStoreError::PolicyChanged.into());
        }
        let encoded_key = key.encoded();
        let record = write
            .open_table(CUSTODY_ITEMS)?
            .get(encoded_key.as_slice())?
            .map(|value| decode_item(value.value()))
            .transpose()?
            .ok_or(CustodyStoreError::ItemNotFound)?;
        if record.retiring {
            return Err(CustodyStoreError::Retiring.into());
        }
        let receipt_key = peer_object_key(peer, key);
        let existing_receipt = write
            .open_table(CUSTODY_PEER_RECEIPTS)?
            .get(receipt_key.as_slice())?
            .map(|value| decode_receipt(value.value()))
            .transpose()?;
        if let Some(receipt) = existing_receipt {
            if receipt.peer_selector_revision == Some(peer_selector_revision.0) {
                return Err(CustodyStoreError::ItemChanged.into());
            }
            if write
                .open_table(CUSTODY_PEER_RECEIPTS)?
                .remove(receipt_key.as_slice())?
                .is_none()
            {
                return Err(CustodyStoreError::Invariant(
                    "stale peer receipt disappeared before lease admission",
                )
                .into());
            }
            remove_peer_retirement_reference_write(
                &write,
                RETIREMENT_REFERENCE_RECEIPT,
                receipt_key.as_slice(),
                "stale peer receipt retirement reference disappeared",
            )?;
            decrement_custody_counter(
                &write,
                CUSTODY_RECEIPT_COUNT_KEY,
                1,
                "peer receipt accounting underflow during lease admission",
            )?;
            advance_revision(&write, false)?;
        }
        if peer_object_has_lease(&write, peer, key)? {
            return Err(CustodyStoreError::ItemChanged.into());
        }
        let evaluation = evaluate_item_age(&record, continuity, sample)?;
        let record = checkpoint_item_age_write(&write, key, record, evaluation)?;
        let age_ms = match evaluation.status {
            CustodyAgeStatus::Durable => record.cumulative_age_ms,
            CustodyAgeStatus::Forwardable { age_ms, .. } => age_ms,
            CustodyAgeStatus::Expired { age_ms } => {
                mark_retiring_write(&write, key, record, age_ms)?;
                write.commit()?;
                return Err(CustodyStoreError::Expired.into());
            }
            CustodyAgeStatus::WithheldUnknownAge => {
                write.commit()?;
                return Err(CustodyStoreError::ContinuityLost.into());
            }
        };
        let metadata = write.open_table(CUSTODY_METADATA)?;
        let lease_count = metadata_value(&metadata, CUSTODY_LEASE_COUNT_KEY)?;
        let last_lease = metadata_value(&metadata, CUSTODY_NEXT_LEASE_KEY)?;
        drop(metadata);
        if lease_count >= MAX_CUSTODY_TRANSFER_LEASES {
            return Err(CustodyStoreError::LeaseLimitExceeded {
                current: lease_count,
                limit: MAX_CUSTODY_TRANSFER_LEASES,
            }
            .into());
        }
        let lease_id = next_counter(last_lease)?;
        let lease_record = LeaseRecord {
            object: key,
            peer,
            item_revision: record.revision,
            policy_revision: expected_policy.0,
            age_ms,
            priority: record.priority,
            peer_selector_revision: Some(peer_selector_revision.0),
        };
        let encoded = encode_lease(&lease_record)?;
        write
            .open_table(CUSTODY_LEASES)?
            .insert(lease_id, encoded.as_slice())?;
        insert_lease_retirement_reference_write(&write, key, lease_id)?;
        {
            let mut metadata = write.open_table(CUSTODY_METADATA)?;
            metadata.insert(CUSTODY_LEASE_COUNT_KEY, next_counter(lease_count)?)?;
            metadata.insert(CUSTODY_NEXT_LEASE_KEY, lease_id)?;
        }

        let retry_key = receipt_key;
        let scheduler_sample = sample.ok_or(CustodyStoreError::ContinuityUnavailable)?;
        let existing_retry = write
            .open_table(CUSTODY_RETRIES)?
            .get(retry_key.as_slice())?
            .map(|value| decode_retry(value.value()))
            .transpose()?;
        let attempts = existing_retry.map_or(Ok(1), |retry| next_counter(retry.attempts))?;
        if let Some(retry) = existing_retry
            && (retry.clock_id != scheduler_sample.clock_id
                || retry.due_tick_ms > scheduler_sample.tick_ms)
        {
            return Err(CustodyStoreError::RetryNotDue {
                current: scheduler_sample.tick_ms,
                due: retry.due_tick_ms,
            }
            .into());
        }
        if existing_retry.is_none() {
            let metadata = write.open_table(CUSTODY_METADATA)?;
            let retries = metadata_value(&metadata, CUSTODY_RETRY_COUNT_KEY)?;
            drop(metadata);
            if retries >= MAX_CUSTODY_RETRY_RECORDS {
                if !replace_expendable_retry(&write, peer, record.priority)? {
                    return Err(CustodyStoreError::RetryLimitExceeded {
                        current: retries,
                        limit: MAX_CUSTODY_RETRY_RECORDS,
                    }
                    .into());
                }
            } else {
                write
                    .open_table(CUSTODY_METADATA)?
                    .insert(CUSTODY_RETRY_COUNT_KEY, next_counter(retries)?)?;
            }
        }
        let completed_attempts = attempts.checked_sub(1).ok_or(CustodyStoreError::Invariant(
            "retry attempt counter is zero",
        ))?;
        let retry_attempt = u16::try_from(completed_attempts).unwrap_or(u16::MAX);
        let due_tick_ms = scheduler_sample
            .tick_ms
            .checked_add(retry_delay_ms(
                record.priority,
                retry_attempt,
                link_floor_ms,
            ))
            .ok_or(CustodyStoreError::CounterOverflow)?;
        let encoded_retry = encode_retry(RetryRecord {
            attempts,
            item_revision: record.revision,
            policy_revision: expected_policy.0,
            clock_id: scheduler_sample.clock_id,
            due_tick_ms,
            priority: record.priority,
        });
        write
            .open_table(CUSTODY_RETRIES)?
            .insert(retry_key.as_slice(), encoded_retry.as_slice())?;
        insert_peer_retirement_reference_write(
            &write,
            RETIREMENT_REFERENCE_RETRY,
            retry_key.as_slice(),
        )?;
        advance_revision(&write, false)?;
        write.commit()?;
        Ok(TransferLease {
            id: TransferLeaseId(lease_id),
            object: key,
            peer,
            age_ms,
            sample: scheduler_sample,
            priority: record.priority,
            policy_revision: expected_policy,
            peer_selector_revision,
        })
    }

    /// Last-moment durable recheck for an already-created async send lease.
    pub fn require_custody_send(
        &self,
        lease: &TransferLease,
        sample: Option<CustodySample>,
        expected_policy: CustodyPolicyRevision,
    ) -> Result<CustodySendAuthorization, StoreError> {
        self.require_live()?;
        let authority = self.require_bound_mission()?;
        let write = self.database.begin_write()?;
        enforce_live_write(&write)?;
        require_custody_mission_write(&write, authority)?;
        if policy_revision_write(&write)? != expected_policy {
            write.commit()?;
            return Err(CustodyStoreError::PolicyChanged.into());
        }
        if lease.policy_revision != expected_policy {
            return Err(CustodyStoreError::PolicyChanged.into());
        }
        let continuity = sample
            .map(|sample| observe_continuity_write(&write, sample))
            .transpose()?;
        let sample = continuity.map(|record| record.sample).or(sample);
        if policy_revision_write(&write)? != expected_policy {
            write.commit()?;
            return Err(CustodyStoreError::PolicyChanged.into());
        }
        let durable_lease = write
            .open_table(CUSTODY_LEASES)?
            .get(lease.id.0)?
            .map(|value| decode_lease(value.value()))
            .transpose()?
            .ok_or(CustodyStoreError::LeaseNotFound)?;
        if durable_lease.object != lease.object
            || durable_lease.peer != lease.peer
            || durable_lease.policy_revision != expected_policy.0
            || durable_lease.peer_selector_revision != Some(lease.peer_selector_revision.0)
        {
            return Err(CustodyStoreError::ItemChanged.into());
        }
        if write
            .open_table(CUSTODY_PEER_RECEIPTS)?
            .get(peer_object_key(lease.peer, lease.object).as_slice())?
            .is_some()
        {
            return Err(CustodyStoreError::ItemChanged.into());
        }
        let item = write
            .open_table(CUSTODY_ITEMS)?
            .get(lease.object.encoded().as_slice())?
            .map(|value| decode_item(value.value()))
            .transpose()?
            .ok_or(CustodyStoreError::ItemNotFound)?;
        if item.retiring || item.revision != durable_lease.item_revision {
            return Err(CustodyStoreError::ItemChanged.into());
        }
        let evaluation = evaluate_item_age(&item, continuity, sample)?;
        let item = checkpoint_item_age_write(&write, lease.object, item, evaluation)?;
        let age_ms = match evaluation.status {
            CustodyAgeStatus::Durable => item.cumulative_age_ms,
            CustodyAgeStatus::Forwardable { age_ms, .. } => age_ms,
            CustodyAgeStatus::Expired { age_ms } => {
                mark_retiring_write(&write, lease.object, item, age_ms)?;
                write.commit()?;
                return Err(CustodyStoreError::Expired.into());
            }
            CustodyAgeStatus::WithheldUnknownAge => {
                write.commit()?;
                return Err(CustodyStoreError::ContinuityLost.into());
            }
        };
        write.commit()?;
        Ok(CustodySendAuthorization {
            age_ms: age_ms.max(durable_lease.age_ms),
            sample,
        })
    }

    /// Returns ordered last-moment finite-age authority for a receipt-free page send.
    ///
    /// Unlike [`Store::begin_custody_send`], this operation creates no peer
    /// receipt, transfer lease, retry, or suppression state. It still performs
    /// the exact policy, continuity, retirement, and expiry checks for every
    /// requested object in one writer transaction so page transport cannot
    /// bypass local lifecycle authority. Results preserve the input order and
    /// share the same normalized clock sample.
    pub fn authorize_receipt_free_custody_sends(
        &self,
        keys: &[CustodyObjectKey],
        sample: Option<CustodySample>,
        expected_policy: CustodyPolicyRevision,
    ) -> Result<Vec<CustodySendAuthorization>, StoreError> {
        self.require_live()?;
        let authority = self.require_bound_mission()?;
        let write = self.database.begin_write()?;
        enforce_live_write(&write)?;
        require_custody_mission_write(&write, authority)?;
        if policy_revision_write(&write)? != expected_policy {
            write.commit()?;
            return Err(CustodyStoreError::PolicyChanged.into());
        }
        let continuity = sample
            .map(|sample| observe_continuity_write(&write, sample))
            .transpose()?;
        let sample = continuity.map(|record| record.sample).or(sample);
        if policy_revision_write(&write)? != expected_policy {
            write.commit()?;
            return Err(CustodyStoreError::PolicyChanged.into());
        }

        let mut authorized = Vec::with_capacity(keys.len());
        for key in keys {
            let record = write
                .open_table(CUSTODY_ITEMS)?
                .get(key.encoded().as_slice())?
                .map(|value| decode_item(value.value()))
                .transpose()?
                .ok_or(CustodyStoreError::ItemNotFound)?;
            if record.retiring {
                return Err(CustodyStoreError::Retiring.into());
            }
            let evaluation = evaluate_item_age(&record, continuity, sample)?;
            let record = checkpoint_item_age_write(&write, *key, record, evaluation)?;
            let age_ms = match evaluation.status {
                CustodyAgeStatus::Durable => record.cumulative_age_ms,
                CustodyAgeStatus::Forwardable { age_ms, .. } => age_ms,
                CustodyAgeStatus::Expired { age_ms } => {
                    mark_retiring_write(&write, *key, record, age_ms)?;
                    write.commit()?;
                    return Err(CustodyStoreError::Expired.into());
                }
                CustodyAgeStatus::WithheldUnknownAge => {
                    write.commit()?;
                    return Err(CustodyStoreError::ContinuityLost.into());
                }
            };
            authorized.push(CustodySendAuthorization { age_ms, sample });
        }
        write.commit()?;
        Ok(authorized)
    }

    /// Returns last-moment finite-age authority for one receipt-free send.
    pub fn authorize_receipt_free_custody_send(
        &self,
        key: CustodyObjectKey,
        sample: Option<CustodySample>,
        expected_policy: CustodyPolicyRevision,
    ) -> Result<CustodySendAuthorization, StoreError> {
        let mut authorized = self.authorize_receipt_free_custody_sends(
            std::slice::from_ref(&key),
            sample,
            expected_policy,
        )?;
        if authorized.len() != 1 {
            return Err(CustodyStoreError::Invariant(
                "single receipt-free custody authorization changed cardinality",
            )
            .into());
        }
        Ok(authorized.remove(0))
    }

    /// Releases one lease while retaining its bounded retry record.
    pub fn release_transfer_lease(&self, lease: TransferLeaseId) -> Result<(), StoreError> {
        self.require_live()?;
        let authority = self.require_bound_mission()?;
        let write = self.database.begin_write()?;
        enforce_live_write(&write)?;
        require_custody_mission_write(&write, authority)?;
        let removed = write
            .open_table(CUSTODY_LEASES)?
            .remove(lease.0)?
            .map(|value| decode_lease(value.value()))
            .transpose()?
            .ok_or(CustodyStoreError::LeaseNotFound)?;
        remove_lease_retirement_reference_write(&write, removed.object, lease.0)?;
        let metadata = write.open_table(CUSTODY_METADATA)?;
        let current = metadata_value(&metadata, CUSTODY_LEASE_COUNT_KEY)?;
        drop(metadata);
        write.open_table(CUSTODY_METADATA)?.insert(
            CUSTODY_LEASE_COUNT_KEY,
            current
                .checked_sub(1)
                .ok_or(CustodyStoreError::Invariant("lease accounting underflow"))?,
        )?;
        advance_revision(&write, false)?;
        write.commit()?;
        Ok(())
    }

    /// Atomically records a durable peer receipt, drains the exact lease and
    /// retry row, and merges authenticated age with max/nondecreasing semantics.
    pub fn record_peer_custody_receipt(
        &self,
        lease: &TransferLease,
        authenticated_age_ms: u64,
        sample: Option<CustodySample>,
        peer_selector_revision: CustodyPeerSelectorRevision,
        expected_policy: CustodyPolicyRevision,
    ) -> Result<(), StoreError> {
        self.settle_peer_custody_apply(
            lease,
            CustodyPeerApplyEvidence::new(
                CustodyPeerApplyDisposition::Satisfied,
                peer_selector_revision,
            ),
            authenticated_age_ms,
            sample,
            expected_policy,
        )
    }

    /// Atomically settles a receiver-authenticated semantic-v3 apply result.
    ///
    /// A satisfied receiver obtains a durable send-suppression receipt and
    /// drains retry state. A receiver that retained only route bytes drains the
    /// completed lease but preserves the already-scheduled bounded retry. This
    /// distinction prevents an authenticated Consume difference from either
    /// being suppressed forever or being reoffered on every contact.
    pub fn settle_peer_custody_apply(
        &self,
        lease: &TransferLease,
        apply: CustodyPeerApplyEvidence,
        authenticated_age_ms: u64,
        sample: Option<CustodySample>,
        expected_policy: CustodyPolicyRevision,
    ) -> Result<(), StoreError> {
        let disposition = apply.disposition();
        self.require_live()?;
        let authority = self.require_bound_mission()?;
        let write = self.database.begin_write()?;
        enforce_live_write(&write)?;
        require_custody_mission_write(&write, authority)?;
        if lease.policy_revision != expected_policy {
            return Err(CustodyStoreError::PolicyChanged.into());
        }
        // The peer ApplyResult is already an external committed effect. First
        // authenticate it against the exact durable lease; policy, protection,
        // and clock changes after bytes left may revoke future sends but must
        // not make settlement or retry drainage fail.
        let durable_lease = write
            .open_table(CUSTODY_LEASES)?
            .get(lease.id.0)?
            .map(|value| decode_lease(value.value()))
            .transpose()?
            .ok_or(CustodyStoreError::LeaseNotFound)?;
        if durable_lease.object != lease.object
            || durable_lease.peer != lease.peer
            || durable_lease.policy_revision != lease.policy_revision.0
            || durable_lease.age_ms != lease.age_ms
            || durable_lease.priority != lease.priority
            || durable_lease.peer_selector_revision != Some(lease.peer_selector_revision.0)
            || apply.selector_revision() != lease.peer_selector_revision
        {
            return Err(CustodyStoreError::ItemChanged.into());
        }
        let continuity = sample
            .map(|sample| observe_continuity_write(&write, sample))
            .transpose()?;
        let sample = continuity.map(|record| record.sample).or(sample);
        let item_key = lease.object.encoded();
        let item = write
            .open_table(CUSTODY_ITEMS)?
            .get(item_key.as_slice())?
            .map(|value| decode_item(value.value()))
            .transpose()?;
        let receipt_item = if let Some(mut item) = item {
            let original = item.clone();
            let merged_age = if item.retiring {
                item.cumulative_age_ms = item.cumulative_age_ms.max(authenticated_age_ms);
                item.cumulative_age_ms
            } else {
                let (merged_age, newly_lost, expired) =
                    merge_authenticated_age(&mut item, continuity, sample, authenticated_age_ms)?;
                if expired {
                    if item != original {
                        replace_custody_maintenance_indexes_write(
                            &write,
                            lease.object,
                            Some(&original),
                            Some(&item),
                        )?;
                    }
                    item = mark_retiring_write(&write, lease.object, item, merged_age)?;
                } else if item != original {
                    replace_custody_maintenance_indexes_write(
                        &write,
                        lease.object,
                        Some(&original),
                        Some(&item),
                    )?;
                    let encoded = encode_item(&item)?;
                    write
                        .open_table(CUSTODY_ITEMS)?
                        .insert(item_key.as_slice(), encoded.as_slice())?;
                    advance_revision(&write, newly_lost)?;
                }
                merged_age
            };
            if original.retiring && item != original {
                let encoded = encode_item(&item)?;
                write
                    .open_table(CUSTODY_ITEMS)?
                    .insert(item_key.as_slice(), encoded.as_slice())?;
                advance_revision(&write, false)?;
            }
            let retryable = !item.retiring
                && matches!(
                    evaluate_item(&item, continuity, sample).0,
                    CustodyAgeStatus::Durable | CustodyAgeStatus::Forwardable { .. }
                );
            Some((item.revision, merged_age, retryable))
        } else {
            let retirement_key = lease.object.encoded();
            let retirement = write
                .open_table(CUSTODY_RETIREMENTS)?
                .get(retirement_key.as_slice())?
                .map(|value| decode_retirement(value.value()))
                .transpose()?;
            let Some(mut retirement) = retirement else {
                return Err(CustodyStoreError::ItemNotFound.into());
            };
            let merged_age = retirement.cumulative_age_ms.max(authenticated_age_ms);
            if merged_age != retirement.cumulative_age_ms {
                retirement.cumulative_age_ms = merged_age;
                let encoded = encode_retirement(&retirement)?;
                write
                    .open_table(CUSTODY_RETIREMENTS)?
                    .insert(retirement_key.as_slice(), encoded.as_slice())?;
                advance_revision(&write, false)?;
            }
            None
        };

        let receipt_key = peer_object_key(lease.peer, lease.object);
        if disposition == CustodyPeerApplyDisposition::Satisfied
            && let Some((item_revision, merged_age, true)) = receipt_item
        {
            let existing_receipt = write
                .open_table(CUSTODY_PEER_RECEIPTS)?
                .get(receipt_key.as_slice())?
                .map(|value| decode_receipt(value.value()))
                .transpose()?;
            if existing_receipt.is_none() {
                let metadata = write.open_table(CUSTODY_METADATA)?;
                let receipts = metadata_value(&metadata, CUSTODY_RECEIPT_COUNT_KEY)?;
                drop(metadata);
                if receipts >= MAX_CUSTODY_PEER_RECEIPTS {
                    if receipts != MAX_CUSTODY_PEER_RECEIPTS {
                        return Err(CustodyStoreError::Invariant(
                            "peer receipt accounting exceeds its hard cap",
                        )
                        .into());
                    }
                    let replacement = write
                        .open_table(CUSTODY_PEER_RECEIPTS)?
                        .iter()?
                        .next()
                        .transpose()?
                        .map(|(key, value)| {
                            let _ = parse_peer_object_key(key.value())?;
                            let _ = decode_receipt(value.value())?;
                            Ok::<_, StoreError>(key.value().to_vec())
                        })
                        .transpose()?
                        .ok_or(CustodyStoreError::Invariant(
                            "peer receipt cap is nonzero but its table is empty",
                        ))?;
                    if write
                        .open_table(CUSTODY_PEER_RECEIPTS)?
                        .remove(replacement.as_slice())?
                        .is_none()
                    {
                        return Err(CustodyStoreError::Invariant(
                            "peer receipt replacement target disappeared",
                        )
                        .into());
                    }
                    remove_peer_retirement_reference_write(
                        &write,
                        RETIREMENT_REFERENCE_RECEIPT,
                        replacement.as_slice(),
                        "peer receipt replacement retirement reference disappeared",
                    )?;
                } else {
                    write
                        .open_table(CUSTODY_METADATA)?
                        .insert(CUSTODY_RECEIPT_COUNT_KEY, next_counter(receipts)?)?;
                }
            }
            let receipt = ReceiptRecord {
                cumulative_age_ms: existing_receipt.map_or(merged_age, |existing| {
                    existing.cumulative_age_ms.max(merged_age)
                }),
                item_revision,
                peer_selector_revision: Some(apply.selector_revision().0),
            };
            let encoded_receipt = encode_receipt(receipt)?;
            write
                .open_table(CUSTODY_PEER_RECEIPTS)?
                .insert(receipt_key.as_slice(), encoded_receipt.as_slice())?;
            insert_peer_retirement_reference_write(
                &write,
                RETIREMENT_REFERENCE_RECEIPT,
                receipt_key.as_slice(),
            )?;
        }

        let receipt_removed = disposition == CustodyPeerApplyDisposition::ContentAcceptancePending
            && write
                .open_table(CUSTODY_PEER_RECEIPTS)?
                .remove(receipt_key.as_slice())?
                .is_some();
        if receipt_removed {
            remove_peer_retirement_reference_write(
                &write,
                RETIREMENT_REFERENCE_RECEIPT,
                receipt_key.as_slice(),
                "removed peer receipt retirement reference disappeared",
            )?;
            let metadata = write.open_table(CUSTODY_METADATA)?;
            let receipts = metadata_value(&metadata, CUSTODY_RECEIPT_COUNT_KEY)?;
            drop(metadata);
            write.open_table(CUSTODY_METADATA)?.insert(
                CUSTODY_RECEIPT_COUNT_KEY,
                receipts
                    .checked_sub(1)
                    .ok_or(CustodyStoreError::Invariant("receipt accounting underflow"))?,
            )?;
        }
        let retain_retry = disposition == CustodyPeerApplyDisposition::ContentAcceptancePending
            && receipt_item.is_some_and(|(_, _, retryable)| retryable);
        let retry_exists = write
            .open_table(CUSTODY_RETRIES)?
            .get(receipt_key.as_slice())?
            .is_some();
        if retain_retry && !retry_exists {
            return Err(CustodyStoreError::Invariant(
                "content-pending settlement lacks its lease-created retry",
            )
            .into());
        }
        let retry_removed = !retain_retry
            && write
                .open_table(CUSTODY_RETRIES)?
                .remove(receipt_key.as_slice())?
                .is_some();
        if retry_removed {
            remove_peer_retirement_reference_write(
                &write,
                RETIREMENT_REFERENCE_RETRY,
                receipt_key.as_slice(),
                "removed retry retirement reference disappeared",
            )?;
            let metadata = write.open_table(CUSTODY_METADATA)?;
            let retries = metadata_value(&metadata, CUSTODY_RETRY_COUNT_KEY)?;
            drop(metadata);
            write.open_table(CUSTODY_METADATA)?.insert(
                CUSTODY_RETRY_COUNT_KEY,
                retries
                    .checked_sub(1)
                    .ok_or(CustodyStoreError::Invariant("retry accounting underflow"))?,
            )?;
        }
        let lease_ids = write
            .open_table(CUSTODY_LEASES)?
            .iter()?
            .filter_map(|row| match row {
                Ok((id, value)) => match decode_lease(value.value()) {
                    Ok(candidate)
                        if candidate.peer == lease.peer && candidate.object == lease.object =>
                    {
                        Some(Ok(id.value()))
                    }
                    Ok(_) => None,
                    Err(error) => Some(Err(StoreError::from(error))),
                },
                Err(error) => Some(Err(StoreError::from(error))),
            })
            .collect::<Result<Vec<_>, StoreError>>()?;
        if !lease_ids.contains(&lease.id.0) {
            return Err(CustodyStoreError::LeaseNotFound.into());
        }
        {
            let mut leases = write.open_table(CUSTODY_LEASES)?;
            for lease_id in &lease_ids {
                leases.remove(*lease_id)?;
                remove_lease_retirement_reference_write(&write, lease.object, *lease_id)?;
            }
        }
        let metadata = write.open_table(CUSTODY_METADATA)?;
        let leases = metadata_value(&metadata, CUSTODY_LEASE_COUNT_KEY)?;
        drop(metadata);
        let removed_leases =
            u64::try_from(lease_ids.len()).map_err(|_| CustodyStoreError::CounterOverflow)?;
        write.open_table(CUSTODY_METADATA)?.insert(
            CUSTODY_LEASE_COUNT_KEY,
            leases
                .checked_sub(removed_leases)
                .ok_or(CustodyStoreError::Invariant("lease accounting underflow"))?,
        )?;
        advance_revision(&write, false)?;
        write.commit()?;
        Ok(())
    }

    /// Replaces local eviction protections under an exact policy generation.
    pub fn set_custody_protection(
        &self,
        key: CustodyObjectKey,
        protection: CustodyProtection,
        expected_policy: CustodyPolicyRevision,
    ) -> Result<CustodyPolicyRevision, StoreError> {
        self.require_live()?;
        let authority = self.require_bound_mission()?;
        let write = self.database.begin_write()?;
        enforce_live_write(&write)?;
        require_custody_mission_write(&write, authority)?;
        require_policy_revision_write(&write, expected_policy)?;
        let encoded_key = key.encoded();
        let mut item = write
            .open_table(CUSTODY_ITEMS)?
            .get(encoded_key.as_slice())?
            .map(|value| decode_item(value.value()))
            .transpose()?
            .ok_or(CustodyStoreError::ItemNotFound)?;
        if item.retiring {
            return Err(CustodyStoreError::Retiring.into());
        }
        if item.protection == protection {
            return Ok(expected_policy);
        }
        item.protection = protection;
        let encoded = encode_item(&item)?;
        write
            .open_table(CUSTODY_ITEMS)?
            .insert(encoded_key.as_slice(), encoded.as_slice())?;
        let (revision, _) = advance_revision(&write, true)?;
        write.commit()?;
        Ok(CustodyPolicyRevision(revision))
    }

    /// Marks expired finite objects before consulting their leases, then
    /// removes the exact logical Event/route byte row only after every active lease
    /// drains.  Durable and tombstone rows never expire through this mechanism.
    pub fn collect_custody_garbage(
        &self,
        sample: Option<CustodySample>,
        expected_policy: CustodyPolicyRevision,
        limit: usize,
    ) -> Result<CustodyGcReport, StoreError> {
        self.collect_custody_garbage_observed(sample, expected_policy, limit)
            .into_result()
    }

    /// Runs one bounded garbage-collection attempt and reports every writer
    /// transaction that durably committed, including a continuity transition
    /// that invalidates the supplied policy revision.
    pub fn collect_custody_garbage_observed(
        &self,
        sample: Option<CustodySample>,
        expected_policy: CustodyPolicyRevision,
        limit: usize,
    ) -> CustodyCollectionAttempt {
        let mut writer_commits = 0u64;
        let result = self.collect_custody_garbage_counted(
            sample,
            expected_policy,
            limit,
            &mut writer_commits,
        );
        CustodyCollectionAttempt {
            result,
            writer_commits,
        }
    }

    fn collect_custody_garbage_counted(
        &self,
        sample: Option<CustodySample>,
        expected_policy: CustodyPolicyRevision,
        limit: usize,
        writer_commits: &mut u64,
    ) -> Result<CustodyGcReport, StoreError> {
        if limit == 0 || limit > MAX_CUSTODY_PAGE {
            return Err(CustodyStoreError::PageLimitExceeded {
                requested: limit,
                maximum: MAX_CUSTODY_PAGE,
            }
            .into());
        }
        self.require_live()?;
        let authority = self.require_bound_mission()?;
        {
            let read = self.database.begin_read()?;
            let bound: Option<NodeId> = read
                .open_table(CUSTODY_DOMAIN)?
                .get(CUSTODY_MISSION_AUTHORITY_KEY)?
                .map(|value| {
                    value.value().try_into().map_err(|_| {
                        StoreError::from(CustodyStoreError::Invariant(
                            "custody mission authority has invalid length",
                        ))
                    })
                })
                .transpose()?;
            match bound {
                Some(bound) if bound == authority => {}
                Some(_) => return Err(CustodyStoreError::MissionMismatch.into()),
                None => return Err(CustodyStoreError::MissionNotBound.into()),
            }
            require_policy_revision_read(&read, expected_policy)?;
            let continuity_write_required = continuity_sample_requires_write_read(&read, sample)?;
            let continuity = read
                .open_table(CUSTODY_CONTINUITY)?
                .get(CUSTODY_CONTINUITY_KEY)?
                .map(|value| decode_continuity(value.value()))
                .transpose()?;
            let reanchor_pending = match (continuity, sample) {
                (Some(current), Some(sample)) if current.sample.clock_id == sample.clock_id => read
                    .open_table(CUSTODY_EXPIRATIONS)?
                    .iter()?
                    .next()
                    .transpose()?
                    .map(|(key, _)| decode_custody_expiration_key(key.value()))
                    .transpose()?
                    .is_some_and(|(generation, _, _, _)| generation < current.generation),
                _ => false,
            };
            let due_expiration = match (continuity, sample) {
                (Some(current), Some(sample)) if current.sample.clock_id == sample.clock_id => {
                    let mut lower = Vec::with_capacity(CUSTODY_EXPIRATION_KEY_LEN);
                    lower.extend_from_slice(&current.generation.to_be_bytes());
                    lower.extend_from_slice(&current.sample.clock_id);
                    lower.extend_from_slice(&0u64.to_be_bytes());
                    lower.extend_from_slice(&[0; 33]);
                    let mut upper = Vec::with_capacity(CUSTODY_EXPIRATION_KEY_LEN);
                    upper.extend_from_slice(&current.generation.to_be_bytes());
                    upper.extend_from_slice(&current.sample.clock_id);
                    upper.extend_from_slice(
                        &current.sample.tick_ms.max(sample.tick_ms).to_be_bytes(),
                    );
                    upper.extend_from_slice(&[u8::MAX; 33]);
                    read.open_table(CUSTODY_EXPIRATIONS)?
                        .range::<&[u8]>(lower.as_slice()..=upper.as_slice())?
                        .next()
                        .transpose()?
                        .is_some()
                }
                _ => false,
            };
            let retiring = read
                .open_table(CUSTODY_RETIRING)?
                .iter()?
                .next()
                .transpose()?
                .is_some();
            if !continuity_write_required && !reanchor_pending && !due_expiration && !retiring {
                return Ok(CustodyGcReport::default());
            }
        }
        let write = self.database.begin_write()?;
        enforce_live_write(&write)?;
        require_custody_mission_write(&write, authority)?;
        require_policy_revision_write(&write, expected_policy)?;
        let prior_continuity = continuity_write(&write)?;
        let continuity = sample
            .map(|sample| observe_continuity_write(&write, sample))
            .transpose()?;
        let sample = continuity.map(|record| record.sample).or(sample);
        let policy_changed = policy_revision_write(&write)? != expected_policy;
        let mut report = CustodyGcReport::default();
        let due_expirations = if let Some(continuity) = continuity {
            let mut candidates = Vec::with_capacity(limit);
            for row in write.open_table(CUSTODY_EXPIRATIONS)?.iter()? {
                let (key, _) = row?;
                let encoded = key.value();
                let (generation, _, _, _) = decode_custody_expiration_key(encoded)?;
                if generation >= continuity.generation {
                    break;
                }
                candidates.push(encoded.to_vec());
                if candidates.len() == limit {
                    break;
                }
            }
            let remaining = limit - candidates.len();
            if remaining == 0 {
                candidates
            } else {
                let mut lower = Vec::with_capacity(CUSTODY_EXPIRATION_KEY_LEN);
                lower.extend_from_slice(&continuity.generation.to_be_bytes());
                lower.extend_from_slice(&continuity.sample.clock_id);
                lower.extend_from_slice(&0u64.to_be_bytes());
                lower.extend_from_slice(&[0; 33]);
                let mut upper = Vec::with_capacity(CUSTODY_EXPIRATION_KEY_LEN);
                upper.extend_from_slice(&continuity.generation.to_be_bytes());
                upper.extend_from_slice(&continuity.sample.clock_id);
                upper.extend_from_slice(&continuity.sample.tick_ms.to_be_bytes());
                upper.extend_from_slice(&[u8::MAX; 33]);
                candidates.extend(
                    write
                        .open_table(CUSTODY_EXPIRATIONS)?
                        .range::<&[u8]>(lower.as_slice()..=upper.as_slice())?
                        .take(remaining)
                        .map(|row| row.map(|(key, _)| key.value().to_vec()))
                        .collect::<Result<Vec<_>, redb::StorageError>>()?,
                );
                candidates
            }
        } else {
            Vec::new()
        };

        for encoded_expiration in &due_expirations {
            report.examined_expirations = report
                .examined_expirations
                .checked_add(1)
                .ok_or(CustodyStoreError::CounterOverflow)?;
            let (indexed_generation, _, _, key) =
                decode_custody_expiration_key(encoded_expiration)?;
            let encoded_key = key.encoded();
            let mut item = write
                .open_table(CUSTODY_ITEMS)?
                .get(encoded_key.as_slice())?
                .map(|value| decode_item(value.value()))
                .transpose()?
                .ok_or(CustodyStoreError::Invariant(
                    "custody expiration index references a missing item",
                ))?;
            if custody_expiration_key(key, &item)?.as_deref() != Some(encoded_expiration.as_slice())
            {
                return Err(CustodyStoreError::Invariant(
                    "custody expiration index differs from its item",
                )
                .into());
            }
            let current = continuity.expect("age candidates require continuity");
            if indexed_generation < current.generation
                && prior_continuity.is_some_and(|prior| {
                    item.continuity_generation == prior.generation
                        && item
                            .checkpoint
                            .is_some_and(|checkpoint| checkpoint.clock_id == prior.sample.clock_id)
                })
            {
                let prior = prior_continuity.expect("checked prior continuity");
                let evaluation = evaluate_item_age(&item, Some(prior), Some(prior.sample))?;
                item = checkpoint_item_age_write(&write, key, item, evaluation)?;
                if matches!(evaluation.status, CustodyAgeStatus::Expired { .. }) {
                    if !policy_changed
                        && let CustodyAgeStatus::Expired { age_ms } = evaluation.status
                    {
                        mark_retiring_write_indexed(&write, key, item, age_ms)?;
                        report.marked.push(key);
                    }
                    continue;
                }
            }
            let evaluation = evaluate_item_age(&item, Some(current), sample)?;
            item = checkpoint_item_age_write(&write, key, item, evaluation)?;
            if !policy_changed && let CustodyAgeStatus::Expired { age_ms } = evaluation.status {
                mark_retiring_write_indexed(&write, key, item, age_ms)?;
                report.marked.push(key);
            }
        }

        if policy_changed {
            write.commit()?;
            *writer_commits = (*writer_commits)
                .checked_add(1)
                .ok_or(CustodyStoreError::CounterOverflow)?;
            return Err(CustodyStoreError::PolicyChanged.into());
        }

        let retirement_scan_limit = MAX_CUSTODY_RETIREMENT_SCAN;
        let retiring_keys = write
            .open_table(CUSTODY_RETIRING)?
            .iter()?
            .take(retirement_scan_limit)
            .map(|row| row.map(|(key, _)| key.value().to_vec()))
            .collect::<Result<Vec<_>, redb::StorageError>>()?;

        if due_expirations.is_empty() && retiring_keys.is_empty() {
            write.commit()?;
            *writer_commits = (*writer_commits)
                .checked_add(1)
                .ok_or(CustodyStoreError::CounterOverflow)?;
            return Ok(report);
        }

        let retiring_keys = write
            .open_table(CUSTODY_RETIRING)?
            .iter()?
            .take(retirement_scan_limit)
            .map(|row| row.map(|(key, value)| (key.value().to_vec(), value.value().to_vec())))
            .collect::<Result<Vec<_>, redb::StorageError>>()?;
        let mut budget = MaintenanceBudget::default();
        let mut scan_window = RetirementScanWindow::new(limit);
        for (encoded_retiring, cleanup_value) in retiring_keys {
            if !scan_window.begin_row() {
                break;
            }
            report.examined_retirements = u64::try_from(scan_window.examined)
                .map_err(|_| CustodyStoreError::CounterOverflow)?;
            let (acceptance_order, key) = decode_custody_retiring_key(&encoded_retiring)?;
            let encoded_key = key.encoded();
            let item = write
                .open_table(CUSTODY_ITEMS)?
                .get(encoded_key.as_slice())?
                .map(|value| decode_item(value.value()))
                .transpose()?;
            if item
                .as_ref()
                .is_some_and(|item| item.acceptance_order != acceptance_order)
            {
                return Err(CustodyStoreError::Invariant(
                    "custody retiring index differs from its item",
                )
                .into());
            }
            let fence = write
                .open_table(CUSTODY_RETIREMENTS)?
                .get(encoded_key.as_slice())?
                .map(|value| decode_retirement(value.value()))
                .transpose()?;
            let mut cleanup = cleanup_record_for_row(&cleanup_value, item.as_ref())?;
            validate_cleanup_identity(&cleanup, item.as_ref(), fence.as_ref())?;
            if let Some(item) = item {
                report.lease_probes = next_counter(report.lease_probes)?;
                if retirement_reference_exists_write(
                    &write,
                    RETIREMENT_REFERENCE_LEASE,
                    encoded_key.as_slice(),
                )? {
                    report.blocked_by_leases = next_counter(report.blocked_by_leases)?;
                    continue;
                }
                if cleanup_value.is_empty() {
                    let encoded_cleanup = encode_retirement_cleanup(&cleanup)?;
                    write
                        .open_table(CUSTODY_RETIRING)?
                        .insert(encoded_retiring.as_slice(), encoded_cleanup.as_slice())?;
                }
                let bytes = item.accounted_bytes;
                fence_retirement_write(&write, key, &item, cleanup.reason)?;
                report.released_bytes = report
                    .released_bytes
                    .checked_add(bytes)
                    .ok_or(CustodyStoreError::CounterOverflow)?;
            }
            match cleanup_retirement_dependencies_write(&write, key, &mut cleanup, &mut budget)? {
                RetirementCleanupProgress::Pending => break,
                RetirementCleanupProgress::Complete => {
                    if write
                        .open_table(CUSTODY_RETIRING)?
                        .remove(encoded_retiring.as_slice())?
                        .is_none()
                    {
                        return Err(CustodyStoreError::Invariant(
                            "completed retirement cleanup disappeared",
                        )
                        .into());
                    }
                    report.retired.push(key);
                    scan_window.record_completion();
                }
            }
        }
        budget.copy_into_report(&mut report);
        write.commit()?;
        *writer_commits = (*writer_commits)
            .checked_add(1)
            .ok_or(CustodyStoreError::CounterOverflow)?;
        Ok(report)
    }

    /// Deterministically retires expendable objects to make the requested
    /// global/exact-scope logical capacity available.  Order is expired,
    /// route-only, ascending priority, nearest expiry, oldest acceptance.
    pub fn collect_custody_pressure(
        &self,
        scope: Option<&Scope>,
        demand: CustodyPressureDemand,
        sample: Option<CustodySample>,
        expected_policy: CustodyPolicyRevision,
        limit: usize,
    ) -> Result<CustodyGcReport, StoreError> {
        self.collect_custody_pressure_observed(scope, demand, sample, expected_policy, limit)
            .into_result()
    }

    /// Runs one bounded pressure-collection attempt and reports its exact
    /// durable writer count.
    pub fn collect_custody_pressure_observed(
        &self,
        scope: Option<&Scope>,
        demand: CustodyPressureDemand,
        sample: Option<CustodySample>,
        expected_policy: CustodyPolicyRevision,
        limit: usize,
    ) -> CustodyCollectionAttempt {
        let mut writer_commits = 0u64;
        let result = self.collect_custody_pressure_counted(
            scope,
            demand,
            sample,
            expected_policy,
            limit,
            &mut writer_commits,
        );
        CustodyCollectionAttempt {
            result,
            writer_commits,
        }
    }

    fn collect_custody_pressure_counted(
        &self,
        scope: Option<&Scope>,
        demand: CustodyPressureDemand,
        sample: Option<CustodySample>,
        expected_policy: CustodyPolicyRevision,
        limit: usize,
        writer_commits: &mut u64,
    ) -> Result<CustodyGcReport, StoreError> {
        if limit == 0 || limit > MAX_CUSTODY_PAGE {
            return Err(CustodyStoreError::PageLimitExceeded {
                requested: limit,
                maximum: MAX_CUSTODY_PAGE,
            }
            .into());
        }
        self.require_live()?;
        let authority = self.require_bound_mission()?;
        {
            let read = self.database.begin_read()?;
            let bound: Option<NodeId> = read
                .open_table(CUSTODY_DOMAIN)?
                .get(CUSTODY_MISSION_AUTHORITY_KEY)?
                .map(|value| {
                    value.value().try_into().map_err(|_| {
                        StoreError::from(CustodyStoreError::Invariant(
                            "custody mission authority has invalid length",
                        ))
                    })
                })
                .transpose()?;
            match bound {
                Some(bound) if bound == authority => {}
                Some(_) => return Err(CustodyStoreError::MissionMismatch.into()),
                None => return Err(CustodyStoreError::MissionNotBound.into()),
            }
            require_policy_revision_read(&read, expected_policy)?;
            let continuity_write_required = continuity_sample_requires_write_read(&read, sample)?;
            // Validate the continuity row before this capacity-fit fast-path
            // can return without entering the writer queue.
            read.open_table(CUSTODY_CONTINUITY)?
                .get(CUSTODY_CONTINUITY_KEY)?
                .map(|value| decode_continuity(value.value()))
                .transpose()?;
            let quota = match quota_read(&read, scope)? {
                Some(quota) => quota,
                None => quota_read(&read, None)?.ok_or(CustodyStoreError::Invariant(
                    "custody schema is missing its global quota",
                ))?,
            };
            let usage = custody_usage_read(&read, scope)?;
            if !continuity_write_required
                && require_quota_capacity(usage, &quota, demand.usage.items, demand.usage.bytes)
                    .is_ok()
            {
                return Ok(CustodyGcReport::default());
            }
        }
        let write = self.database.begin_write()?;
        enforce_live_write(&write)?;
        require_custody_mission_write(&write, authority)?;
        require_policy_revision_write(&write, expected_policy)?;
        let continuity = sample
            .map(|sample| observe_continuity_write(&write, sample))
            .transpose()?;
        let sample = continuity.map(|record| record.sample).or(sample);
        if policy_revision_write(&write)? != expected_policy {
            write.commit()?;
            *writer_commits = (*writer_commits)
                .checked_add(1)
                .ok_or(CustodyStoreError::CounterOverflow)?;
            return Err(CustodyStoreError::PolicyChanged.into());
        }
        let quota = match quota_write(&write, scope)? {
            Some(quota) => quota,
            None => quota_write(&write, None)?.ok_or(CustodyStoreError::Invariant(
                "custody schema is missing its global quota",
            ))?,
        };
        let usage = custody_usage_write(&write, scope)?;
        if require_quota_capacity(usage, &quota, demand.usage.items, demand.usage.bytes).is_ok() {
            write.commit()?;
            *writer_commits = (*writer_commits)
                .checked_add(1)
                .ok_or(CustodyStoreError::CounterOverflow)?;
            return Ok(CustodyGcReport::default());
        }
        let mut candidates = BinaryHeap::new();
        let mut examined_candidates = 0u64;
        let items = write.open_table(CUSTODY_ITEMS)?;
        for row in items.iter()? {
            let (encoded_key, encoded_item) = row?;
            examined_candidates = next_counter(examined_candidates)?;
            let key = CustodyObjectKey::decode(encoded_key.value())?;
            let item = decode_item(encoded_item.value())?;
            if scope.is_some_and(|scope| scope != &item.scope)
                || item.tombstone
                || item.retiring
                || !matches!(
                    key.class,
                    CustodyObjectClass::Event | CustodyObjectClass::RouteEvent
                )
            {
                continue;
            }
            let (status, _) = evaluate_item(&item, continuity, sample);
            let (expired, age_ms, remaining) = match status {
                CustodyAgeStatus::Expired { age_ms } => (true, age_ms, 0),
                CustodyAgeStatus::Forwardable {
                    age_ms,
                    remaining_ms,
                } => (false, age_ms, remaining_ms),
                CustodyAgeStatus::Durable | CustodyAgeStatus::WithheldUnknownAge => {
                    (false, item.cumulative_age_ms, u64::MAX)
                }
            };
            if !expired
                && (item.protection.protects_eviction()
                    || retirement_reference_exists_write(
                        &write,
                        RETIREMENT_REFERENCE_PENDING,
                        item.semantic_id.as_slice(),
                    )?)
            {
                continue;
            }
            // Expiry is an absolute lifetime decision. Live pressure victims,
            // however, must be strictly less important than the authenticated
            // incoming item; equal priority never displaces equal priority.
            if !expired && item.priority >= demand.priority {
                continue;
            }
            retain_best_retirement_candidate(
                &mut candidates,
                RankedRetirementCandidate {
                    order: (
                        !expired,
                        !item.route_only,
                        item.priority,
                        remaining,
                        item.acceptance_order,
                        key,
                    ),
                    key,
                    item,
                    age_ms,
                    expired,
                },
            );
        }
        drop(items);
        let mut report = CustodyGcReport {
            examined_candidates,
            ..CustodyGcReport::default()
        };
        let mut budget = MaintenanceBudget::default();
        let mut released_items = 0u64;
        for candidate in candidates.into_sorted_vec() {
            let RankedRetirementCandidate {
                key, item, age_ms, ..
            } = candidate;
            if report.marked.len() == limit {
                break;
            }
            let marked = mark_retiring_write_indexed(&write, key, item, age_ms)?;
            report.marked.push(key);
            report.lease_probes = next_counter(report.lease_probes)?;
            if retirement_reference_exists_write(
                &write,
                RETIREMENT_REFERENCE_LEASE,
                key.encoded().as_slice(),
            )? {
                report.blocked_by_leases = report
                    .blocked_by_leases
                    .checked_add(1)
                    .ok_or(CustodyStoreError::CounterOverflow)?;
                continue;
            }
            let bytes = marked.accounted_bytes;
            let reason = if marked.ttl_ms.is_some_and(|ttl| age_ms >= ttl) {
                CustodyRetirementReason::Expired
            } else {
                CustodyRetirementReason::QuotaPressure
            };
            fence_retirement_write(&write, key, &marked, reason)?;
            released_items = next_counter(released_items)?;
            report.released_bytes = report
                .released_bytes
                .checked_add(bytes)
                .ok_or(CustodyStoreError::CounterOverflow)?;
            let cleanup_key = custody_retiring_key(key, &marked).expect("marked retirement key");
            let cleanup_value = write
                .open_table(CUSTODY_RETIRING)?
                .get(cleanup_key.as_slice())?
                .ok_or(CustodyStoreError::Invariant(
                    "retirement cleanup disappeared",
                ))?
                .value()
                .to_vec();
            let mut cleanup = cleanup_record_for_row(&cleanup_value, Some(&marked))?;
            if cleanup_retirement_dependencies_write(&write, key, &mut cleanup, &mut budget)?
                == RetirementCleanupProgress::Complete
            {
                write
                    .open_table(CUSTODY_RETIRING)?
                    .remove(cleanup_key.as_slice())?;
                report.retired.push(key);
            }
            let final_usage = CustodyUsage {
                items: usage.items.checked_sub(released_items).ok_or(
                    CustodyStoreError::Invariant("pressure item accounting underflow"),
                )?,
                bytes: usage.bytes.checked_sub(report.released_bytes).ok_or(
                    CustodyStoreError::Invariant("pressure byte accounting underflow"),
                )?,
            };
            if require_quota_capacity(final_usage, &quota, demand.usage.items, demand.usage.bytes)
                .is_ok()
            {
                budget.copy_into_report(&mut report);
                write.commit()?;
                *writer_commits = (*writer_commits)
                    .checked_add(1)
                    .ok_or(CustodyStoreError::CounterOverflow)?;
                return Ok(report);
            }
        }
        // The marks themselves are policy-significant even when active leases
        // or protected rows prevent enough immediate capacity.  Commit them,
        // then report the still-exceeded bound to the caller.
        write.commit()?;
        budget.copy_into_report(&mut report);
        *writer_commits = (*writer_commits)
            .checked_add(1)
            .ok_or(CustodyStoreError::CounterOverflow)?;
        require_quota_capacity(
            CustodyUsage {
                items: usage.items.checked_sub(released_items).ok_or(
                    CustodyStoreError::Invariant("pressure item accounting underflow"),
                )?,
                bytes: usage.bytes.checked_sub(report.released_bytes).ok_or(
                    CustodyStoreError::Invariant("pressure byte accounting underflow"),
                )?,
            },
            &quota,
            demand.usage.items,
            demand.usage.bytes,
        )?;
        Ok(report)
    }
}

fn validate_item_backing_write(
    write: &redb::WriteTransaction,
    key: CustodyObjectKey,
    record: &CustodyItemRecord,
) -> Result<(), StoreError> {
    match key.class {
        CustodyObjectClass::Event => {
            let metadata = write
                .open_table(EVENTS)?
                .get(key.transfer_id.as_slice())?
                .map(|value| decode_event_metadata(value.value()))
                .transpose()?
                .ok_or(CustodyStoreError::Invariant(
                    "custody Event is missing semantic metadata",
                ))?;
            let bytes = write
                .open_table(EVENT_BYTES)?
                .get(key.transfer_id.as_slice())?
                .map(|value| u64::try_from(value.value().len()))
                .transpose()
                .map_err(|_| CustodyStoreError::CounterOverflow)?
                .ok_or(CustodyStoreError::Invariant(
                    "live custody Event is missing exact bytes",
                ))?;
            if metadata.semantic_id.as_bytes() != &record.semantic_id
                || metadata.header.topic != record.topic
                || metadata.header.scope != record.scope
                || metadata.header.stamp.dot.publisher != record.source_publisher
                || metadata.header.key_epoch != record.key_epoch
                || metadata.header.priority != record.priority
                || metadata.header.ttl_ms != record.ttl_ms
                || metadata.header.tombstone != record.tombstone
                || bytes != record.accounted_bytes
            {
                return Err(CustodyStoreError::Invariant(
                    "custody Event metadata differs from its accepted representation",
                )
                .into());
            }
        }
        CustodyObjectClass::RouteEvent => {
            let claim = write
                .open_table(ROUTE_CACHE_CLAIMS)?
                .get(key.transfer_id.as_slice())?
                .map(|value| decode_event_metadata(value.value()))
                .transpose()?
                .ok_or(CustodyStoreError::Invariant(
                    "custody route Event is missing its claim",
                ))?;
            let bytes = write
                .open_table(ROUTE_CACHE)?
                .get(key.transfer_id.as_slice())?
                .map(|value| u64::try_from(value.value().len()))
                .transpose()
                .map_err(|_| CustodyStoreError::CounterOverflow)?
                .ok_or(CustodyStoreError::Invariant(
                    "custody route Event is missing exact bytes",
                ))?;
            if claim.semantic_id.as_bytes() != &record.semantic_id
                || claim.header.topic != record.topic
                || claim.header.scope != record.scope
                || claim.header.stamp.dot.publisher != record.source_publisher
                || claim.header.key_epoch != record.key_epoch
                || claim.header.priority != record.priority
                || claim.header.ttl_ms != record.ttl_ms
                || claim.header.tombstone != record.tombstone
                || !record.route_only
                || bytes != record.accounted_bytes
            {
                return Err(CustodyStoreError::Invariant(
                    "custody route Event metadata differs from its route representation",
                )
                .into());
            }
        }
        CustodyObjectClass::State => {
            if write
                .open_table(STATES)?
                .get(key.transfer_id.as_slice())?
                .is_none()
            {
                return Err(CustodyStoreError::Invariant(
                    "custody State is missing its selected row",
                )
                .into());
            }
        }
        CustodyObjectClass::Record => {
            if write
                .open_table(RECORDS)?
                .get(key.transfer_id.as_slice())?
                .is_none()
            {
                return Err(CustodyStoreError::Invariant(
                    "custody Record is missing its selected row",
                )
                .into());
            }
        }
        CustodyObjectClass::Blob => {
            if write
                .open_table(blob::BLOB_PUBLICATIONS)?
                .get(key.transfer_id.as_slice())?
                .is_none()
            {
                return Err(CustodyStoreError::Invariant(
                    "custody Blob is missing its selected row",
                )
                .into());
            }
        }
    }
    Ok(())
}

fn validate_retirement_backing_write(
    write: &redb::WriteTransaction,
    key: CustodyObjectKey,
    record: &RetirementRecord,
) -> Result<(), StoreError> {
    match key.class {
        CustodyObjectClass::Event => {
            let metadata = write
                .open_table(EVENTS)?
                .get(key.transfer_id.as_slice())?
                .map(|value| decode_event_metadata(value.value()))
                .transpose()?
                .ok_or(CustodyStoreError::Invariant(
                    "retired Event lost its permanent metadata fence",
                ))?;
            if metadata.semantic_id.as_bytes() != &record.semantic_id
                || metadata.header.topic != record.topic
                || metadata.header.scope != record.scope
                || metadata.header.stamp.dot.publisher != record.source_publisher
                || metadata.header.key_epoch != record.key_epoch
                || write
                    .open_table(EVENT_BYTES)?
                    .get(key.transfer_id.as_slice())?
                    .is_some()
            {
                return Err(CustodyStoreError::Invariant(
                    "retired Event fence disagrees with payload retirement",
                )
                .into());
            }
            let marker = write
                .open_table(EVENT_ACCEPTANCE_MARKERS)?
                .get(key.transfer_id.as_slice())?
                .map(|value| value.value())
                .ok_or(CustodyStoreError::Invariant(
                    "retired Event lost its acceptance marker",
                ))?;
            if marker != record.acceptance_order
                || write
                    .open_table(EVENT_ACCEPTANCE_ORDER)?
                    .get(marker)?
                    .map(|value| value.value().to_vec())
                    != Some(key.transfer_id.to_vec())
            {
                return Err(CustodyStoreError::Invariant(
                    "retired Event acceptance fences changed",
                )
                .into());
            }
        }
        CustodyObjectClass::RouteEvent => {
            if write
                .open_table(ROUTE_CACHE)?
                .get(key.transfer_id.as_slice())?
                .is_some()
                || write
                    .open_table(ROUTE_CACHE_CLAIMS)?
                    .get(key.transfer_id.as_slice())?
                    .is_some()
            {
                return Err(CustodyStoreError::Invariant(
                    "retired route Event still retains payload state",
                )
                .into());
            }
        }
        class => return Err(CustodyStoreError::UnsupportedRetirementClass(class).into()),
    }
    Ok(())
}

fn require_audit_table_bound(
    current: u64,
    limit: u64,
    message: &'static str,
) -> Result<(), StoreError> {
    if current > limit {
        return Err(CustodyStoreError::Invariant(message).into());
    }
    Ok(())
}

fn require_unique_event_transfer_state(
    keys: impl IntoIterator<Item = CustodyObjectKey>,
) -> Result<(), StoreError> {
    let mut event_transfers = BTreeMap::<[u8; 32], CustodyObjectClass>::new();
    for key in keys {
        if !matches!(
            key.class,
            CustodyObjectClass::Event | CustodyObjectClass::RouteEvent
        ) {
            continue;
        }
        if event_transfers.insert(key.transfer_id, key.class).is_some() {
            return Err(CustodyStoreError::Invariant(
                "one Event transfer appears in multiple live or retired custody states",
            )
            .into());
        }
    }
    Ok(())
}

type CustodyMaintenanceIndexes = (BTreeSet<Vec<u8>>, BTreeSet<Vec<u8>>);

fn expected_custody_maintenance_indexes(
    items: &BTreeMap<CustodyObjectKey, CustodyItemRecord>,
) -> Result<CustodyMaintenanceIndexes, StoreError> {
    let mut expirations = BTreeSet::new();
    let mut retiring = BTreeSet::new();
    for (key, record) in items {
        if let Some(encoded) = custody_expiration_key(*key, record)? {
            expirations.insert(encoded);
        }
        if let Some(encoded) = custody_retiring_key(*key, record) {
            retiring.insert(encoded);
        }
    }
    Ok((expirations, retiring))
}

struct ParsedRetirementReference<'a> {
    kind: u8,
    target: &'a [u8],
    primary: &'a [u8],
}

fn parse_retirement_reference_key(
    encoded: &[u8],
) -> Result<ParsedRetirementReference<'_>, StoreError> {
    let (&kind, rest) = encoded.split_first().ok_or(CustodyStoreError::Invariant(
        "custody retirement reference key is empty",
    ))?;
    let target_len = match kind {
        RETIREMENT_REFERENCE_LEASE | RETIREMENT_REFERENCE_RETRY | RETIREMENT_REFERENCE_RECEIPT => {
            33
        }
        RETIREMENT_REFERENCE_PENDING | RETIREMENT_REFERENCE_ACKNOWLEDGEMENT => 32,
        _ => {
            return Err(CustodyStoreError::Invariant(
                "custody retirement reference kind is invalid",
            )
            .into());
        }
    };
    if rest.len() <= target_len {
        return Err(CustodyStoreError::Invariant(
            "custody retirement reference key has invalid length",
        )
        .into());
    }
    let (target, primary) = rest.split_at(target_len);
    match kind {
        RETIREMENT_REFERENCE_LEASE => {
            let _ = CustodyObjectKey::decode(target)?;
            let _: [u8; 8] = primary.try_into().map_err(|_| {
                CustodyStoreError::Invariant("lease retirement reference has invalid primary key")
            })?;
        }
        RETIREMENT_REFERENCE_RETRY | RETIREMENT_REFERENCE_RECEIPT => {
            let _ = CustodyObjectKey::decode(target)?;
            let _ = parse_peer_object_key(primary)?;
        }
        RETIREMENT_REFERENCE_PENDING => {
            let _: [u8; 32] = target.try_into().expect("checked semantic target length");
            let _ = parse_event_pending_delivery_key(primary)?;
        }
        RETIREMENT_REFERENCE_ACKNOWLEDGEMENT => {
            let _: [u8; 32] = target.try_into().expect("checked semantic target length");
            let _ = parse_event_acknowledgement_key(primary)?;
        }
        _ => unreachable!("validated retirement reference kind"),
    }
    Ok(ParsedRetirementReference {
        kind,
        target,
        primary,
    })
}

fn require_retirement_reference_write(
    write: &redb::WriteTransaction,
    kind: u8,
    target: &[u8],
    primary: &[u8],
) -> Result<(), StoreError> {
    let key = retirement_reference_key(kind, target, primary);
    let value = write
        .open_table(CUSTODY_RETIREMENT_REFERENCES)?
        .get(key.as_slice())?
        .map(|value| value.value().to_vec())
        .ok_or(CustodyStoreError::Invariant(
            "custody retirement reference is missing for its source row",
        ))?;
    if !value.is_empty() {
        return Err(
            CustodyStoreError::Invariant("custody retirement reference value is invalid").into(),
        );
    }
    Ok(())
}

fn require_retirement_reference_read(
    read: &redb::ReadTransaction,
    kind: u8,
    target: &[u8],
    primary: &[u8],
) -> Result<(), StoreError> {
    let key = retirement_reference_key(kind, target, primary);
    let value = read
        .open_table(CUSTODY_RETIREMENT_REFERENCES)?
        .get(key.as_slice())?
        .map(|value| value.value().to_vec())
        .ok_or(CustodyStoreError::Invariant(
            "custody retirement reference is missing for its source row",
        ))?;
    if !value.is_empty() {
        return Err(
            CustodyStoreError::Invariant("custody retirement reference value is invalid").into(),
        );
    }
    Ok(())
}

fn validate_dependency_authority_write(
    write: &redb::WriteTransaction,
    object: CustodyObjectKey,
    allow_fenced: bool,
    expected_semantic: Option<[u8; 32]>,
    expected_revision: Option<u64>,
    expected_priority: Option<Priority>,
) -> Result<(), StoreError> {
    let encoded = object.encoded();
    let item = write
        .open_table(CUSTODY_ITEMS)?
        .get(encoded.as_slice())?
        .map(|value| decode_item(value.value()))
        .transpose()?;
    let fence = write
        .open_table(CUSTODY_RETIREMENTS)?
        .get(encoded.as_slice())?
        .map(|value| decode_retirement(value.value()))
        .transpose()?;
    if item.is_some() && fence.is_some() {
        return Err(CustodyStoreError::Invariant(
            "custody dependency authority overlaps live and retired state",
        )
        .into());
    }
    if let Some(item) = item {
        if expected_semantic.is_some_and(|semantic| semantic != item.semantic_id)
            || expected_revision.is_some_and(|revision| revision != item.revision)
            || expected_priority.is_some_and(|priority| priority != item.priority)
        {
            return Err(CustodyStoreError::Invariant(
                "custody dependency differs from its live authority",
            )
            .into());
        }
        if item.retiring {
            let key = retirement_cleanup_key_for_authority(object, item.acceptance_order);
            let value = write
                .open_table(CUSTODY_RETIRING)?
                .get(key.as_slice())?
                .map(|value| value.value().to_vec())
                .ok_or(CustodyStoreError::Invariant(
                    "marked custody dependency lacks its cleanup authority",
                ))?;
            let cleanup = cleanup_record_for_row(&value, Some(&item))?;
            validate_cleanup_identity(&cleanup, Some(&item), None)?;
        }
        return Ok(());
    }
    let fence = fence.ok_or(CustodyStoreError::Invariant(
        "custody dependency references missing authority",
    ))?;
    if !allow_fenced {
        return Err(CustodyStoreError::Invariant("custody lease survived payload fencing").into());
    }
    if expected_semantic.is_some_and(|semantic| semantic != fence.semantic_id) {
        return Err(CustodyStoreError::Invariant(
            "custody dependency semantic identity differs from its fence",
        )
        .into());
    }
    let key = retirement_cleanup_key_for_authority(object, fence.acceptance_order);
    let value = write
        .open_table(CUSTODY_RETIRING)?
        .get(key.as_slice())?
        .map(|value| value.value().to_vec())
        .ok_or(CustodyStoreError::Invariant(
            "custody retirement reference targets a clean fence",
        ))?;
    let cleanup = cleanup_record_for_row(&value, None)?;
    validate_cleanup_identity(&cleanup, None, Some(&fence))?;
    if expected_revision.is_some_and(|revision| revision != cleanup.original_revision)
        || expected_priority.is_some_and(|priority| priority != cleanup.priority)
    {
        return Err(CustodyStoreError::Invariant(
            "custody dependency differs from its cleanup authority",
        )
        .into());
    }
    Ok(())
}

fn validate_dependency_authority_read(
    read: &redb::ReadTransaction,
    object: CustodyObjectKey,
    allow_fenced: bool,
    expected_semantic: Option<[u8; 32]>,
    expected_revision: Option<u64>,
    expected_priority: Option<Priority>,
) -> Result<(), StoreError> {
    let encoded = object.encoded();
    let item = read
        .open_table(CUSTODY_ITEMS)?
        .get(encoded.as_slice())?
        .map(|value| decode_item(value.value()))
        .transpose()?;
    let fence = read
        .open_table(CUSTODY_RETIREMENTS)?
        .get(encoded.as_slice())?
        .map(|value| decode_retirement(value.value()))
        .transpose()?;
    if item.is_some() && fence.is_some() {
        return Err(CustodyStoreError::Invariant(
            "custody dependency authority overlaps live and retired state",
        )
        .into());
    }
    if let Some(item) = item {
        if expected_semantic.is_some_and(|semantic| semantic != item.semantic_id)
            || expected_revision.is_some_and(|revision| revision != item.revision)
            || expected_priority.is_some_and(|priority| priority != item.priority)
        {
            return Err(CustodyStoreError::Invariant(
                "custody dependency differs from its live authority",
            )
            .into());
        }
        if item.retiring {
            let key = retirement_cleanup_key_for_authority(object, item.acceptance_order);
            let value = read
                .open_table(CUSTODY_RETIRING)?
                .get(key.as_slice())?
                .map(|value| value.value().to_vec())
                .ok_or(CustodyStoreError::Invariant(
                    "marked custody dependency lacks its cleanup authority",
                ))?;
            let cleanup = cleanup_record_for_row(&value, Some(&item))?;
            validate_cleanup_identity(&cleanup, Some(&item), None)?;
        }
        return Ok(());
    }
    let fence = fence.ok_or(CustodyStoreError::Invariant(
        "custody dependency references missing authority",
    ))?;
    if !allow_fenced {
        return Err(CustodyStoreError::Invariant("custody lease survived payload fencing").into());
    }
    if expected_semantic.is_some_and(|semantic| semantic != fence.semantic_id) {
        return Err(CustodyStoreError::Invariant(
            "custody dependency semantic identity differs from its fence",
        )
        .into());
    }
    let key = retirement_cleanup_key_for_authority(object, fence.acceptance_order);
    let value = read
        .open_table(CUSTODY_RETIRING)?
        .get(key.as_slice())?
        .map(|value| value.value().to_vec())
        .ok_or(CustodyStoreError::Invariant(
            "custody retirement reference targets a clean fence",
        ))?;
    let cleanup = cleanup_record_for_row(&value, None)?;
    validate_cleanup_identity(&cleanup, None, Some(&fence))?;
    if expected_revision.is_some_and(|revision| revision != cleanup.original_revision)
        || expected_priority.is_some_and(|priority| priority != cleanup.priority)
    {
        return Err(CustodyStoreError::Invariant(
            "custody dependency differs from its cleanup authority",
        )
        .into());
    }
    Ok(())
}

fn event_object_for_semantic_write(
    write: &redb::WriteTransaction,
    semantic_id: EventSemanticId,
) -> Result<CustodyObjectKey, StoreError> {
    let transfer = write
        .open_table(SEMANTIC_ITEMS)?
        .get(semantic_id.as_bytes().as_slice())?
        .map(|value| parse_transfer_id("semantic item table", value.value()))
        .transpose()?
        .ok_or(CustodyStoreError::Invariant(
            "Event delivery dependency lacks retained semantic metadata",
        ))?;
    let metadata = write
        .open_table(EVENTS)?
        .get(transfer.as_bytes().as_slice())?
        .map(|value| decode_event_metadata(value.value()))
        .transpose()?
        .ok_or(CustodyStoreError::Invariant(
            "Event delivery dependency lacks retained Event metadata",
        ))?;
    if metadata.semantic_id != semantic_id {
        return Err(CustodyStoreError::Invariant(
            "Event delivery dependency semantic index is inconsistent",
        )
        .into());
    }
    Ok(CustodyObjectKey::event(transfer))
}

fn event_object_for_semantic_read(
    read: &redb::ReadTransaction,
    semantic_id: EventSemanticId,
) -> Result<CustodyObjectKey, StoreError> {
    let transfer = read
        .open_table(SEMANTIC_ITEMS)?
        .get(semantic_id.as_bytes().as_slice())?
        .map(|value| parse_transfer_id("semantic item table", value.value()))
        .transpose()?
        .ok_or(CustodyStoreError::Invariant(
            "Event delivery dependency lacks retained semantic metadata",
        ))?;
    let metadata = read
        .open_table(EVENTS)?
        .get(transfer.as_bytes().as_slice())?
        .map(|value| decode_event_metadata(value.value()))
        .transpose()?
        .ok_or(CustodyStoreError::Invariant(
            "Event delivery dependency lacks retained Event metadata",
        ))?;
    if metadata.semantic_id != semantic_id {
        return Err(CustodyStoreError::Invariant(
            "Event delivery dependency semantic index is inconsistent",
        )
        .into());
    }
    Ok(CustodyObjectKey::event(transfer))
}

fn audit_event_retirement_reference_sources_write(
    write: &redb::WriteTransaction,
) -> Result<(), StoreError> {
    let tables = write
        .list_tables()?
        .map(|table| table.name().to_owned())
        .collect::<BTreeSet<_>>();
    if tables.contains(EVENT_SUBSCRIPTION_PENDING.name()) {
        for row in write.open_table(EVENT_SUBSCRIPTION_PENDING)?.iter()? {
            let (key, value) = row?;
            let pending = decode_event_pending_delivery_record(value.value())?;
            let object = event_object_for_semantic_write(write, pending.semantic_id)?;
            validate_dependency_authority_write(
                write,
                object,
                true,
                Some(*pending.semantic_id.as_bytes()),
                None,
                None,
            )?;
            require_retirement_reference_write(
                write,
                RETIREMENT_REFERENCE_PENDING,
                pending.semantic_id.as_bytes(),
                key.value(),
            )?;
        }
    }
    if tables.contains(EVENT_DELIVERY_ACKNOWLEDGEMENTS.name()) {
        for row in write.open_table(EVENT_DELIVERY_ACKNOWLEDGEMENTS)?.iter()? {
            let (key, value) = row?;
            let (_, semantic_id) = parse_event_acknowledgement_key(key.value())?;
            let _ = decode_event_acknowledgement_record(value.value())?;
            let object = event_object_for_semantic_write(write, semantic_id)?;
            validate_dependency_authority_write(
                write,
                object,
                true,
                Some(*semantic_id.as_bytes()),
                None,
                None,
            )?;
            require_retirement_reference_write(
                write,
                RETIREMENT_REFERENCE_ACKNOWLEDGEMENT,
                semantic_id.as_bytes(),
                key.value(),
            )?;
        }
    }
    Ok(())
}

fn audit_event_retirement_reference_sources_read(
    read: &redb::ReadTransaction,
) -> Result<(), StoreError> {
    let tables = read
        .list_tables()?
        .map(|table| table.name().to_owned())
        .collect::<BTreeSet<_>>();
    if tables.contains(EVENT_SUBSCRIPTION_PENDING.name()) {
        for row in read.open_table(EVENT_SUBSCRIPTION_PENDING)?.iter()? {
            let (key, value) = row?;
            let pending = decode_event_pending_delivery_record(value.value())?;
            let object = event_object_for_semantic_read(read, pending.semantic_id)?;
            validate_dependency_authority_read(
                read,
                object,
                true,
                Some(*pending.semantic_id.as_bytes()),
                None,
                None,
            )?;
            require_retirement_reference_read(
                read,
                RETIREMENT_REFERENCE_PENDING,
                pending.semantic_id.as_bytes(),
                key.value(),
            )?;
        }
    }
    if tables.contains(EVENT_DELIVERY_ACKNOWLEDGEMENTS.name()) {
        for row in read.open_table(EVENT_DELIVERY_ACKNOWLEDGEMENTS)?.iter()? {
            let (key, value) = row?;
            let (_, semantic_id) = parse_event_acknowledgement_key(key.value())?;
            let _ = decode_event_acknowledgement_record(value.value())?;
            let object = event_object_for_semantic_read(read, semantic_id)?;
            validate_dependency_authority_read(
                read,
                object,
                true,
                Some(*semantic_id.as_bytes()),
                None,
                None,
            )?;
            require_retirement_reference_read(
                read,
                RETIREMENT_REFERENCE_ACKNOWLEDGEMENT,
                semantic_id.as_bytes(),
                key.value(),
            )?;
        }
    }
    Ok(())
}

fn audit_retirement_references_write(write: &redb::WriteTransaction) -> Result<(), StoreError> {
    for row in write.open_table(CUSTODY_RETIREMENT_REFERENCES)?.iter()? {
        let (key, value) = row?;
        if !value.value().is_empty() {
            return Err(CustodyStoreError::Invariant(
                "custody retirement reference value is invalid",
            )
            .into());
        }
        let parsed = parse_retirement_reference_key(key.value())?;
        match parsed.kind {
            RETIREMENT_REFERENCE_LEASE => {
                let id =
                    u64::from_be_bytes(parsed.primary.try_into().expect("validated lease key"));
                let lease = write
                    .open_table(CUSTODY_LEASES)?
                    .get(id)?
                    .map(|value| decode_lease(value.value()))
                    .transpose()?
                    .ok_or(CustodyStoreError::Invariant(
                        "custody retirement reference points to a missing lease",
                    ))?;
                if lease.object.encoded().as_slice() != parsed.target {
                    return Err(CustodyStoreError::Invariant(
                        "lease retirement reference targets the wrong object",
                    )
                    .into());
                }
                validate_dependency_authority_write(
                    write,
                    lease.object,
                    false,
                    None,
                    Some(lease.item_revision),
                    None,
                )?;
            }
            RETIREMENT_REFERENCE_RETRY => {
                let retry = write
                    .open_table(CUSTODY_RETRIES)?
                    .get(parsed.primary)?
                    .map(|value| decode_retry(value.value()))
                    .transpose()?
                    .ok_or(CustodyStoreError::Invariant(
                        "custody retirement reference points to a missing retry",
                    ))?;
                let (_, object) = parse_peer_object_key(parsed.primary)?;
                if object.encoded().as_slice() != parsed.target {
                    return Err(CustodyStoreError::Invariant(
                        "retry retirement reference targets the wrong object",
                    )
                    .into());
                }
                validate_dependency_authority_write(
                    write,
                    object,
                    true,
                    None,
                    Some(retry.item_revision),
                    Some(retry.priority),
                )?;
            }
            RETIREMENT_REFERENCE_RECEIPT => {
                let receipt = write
                    .open_table(CUSTODY_PEER_RECEIPTS)?
                    .get(parsed.primary)?
                    .map(|value| decode_receipt(value.value()))
                    .transpose()?
                    .ok_or(CustodyStoreError::Invariant(
                        "custody retirement reference points to a missing receipt",
                    ))?;
                let (_, object) = parse_peer_object_key(parsed.primary)?;
                if object.encoded().as_slice() != parsed.target {
                    return Err(CustodyStoreError::Invariant(
                        "receipt retirement reference targets the wrong object",
                    )
                    .into());
                }
                validate_dependency_authority_write(
                    write,
                    object,
                    true,
                    None,
                    Some(receipt.item_revision),
                    None,
                )?;
            }
            RETIREMENT_REFERENCE_PENDING => {
                let pending = write
                    .open_table(EVENT_SUBSCRIPTION_PENDING)?
                    .get(parsed.primary)?
                    .map(|value| decode_event_pending_delivery_record(value.value()))
                    .transpose()?
                    .ok_or(CustodyStoreError::Invariant(
                        "custody retirement reference points to a missing pending delivery",
                    ))?;
                if pending.semantic_id.as_bytes() != parsed.target {
                    return Err(CustodyStoreError::Invariant(
                        "pending retirement reference targets the wrong Event",
                    )
                    .into());
                }
                let object = event_object_for_semantic_write(write, pending.semantic_id)?;
                validate_dependency_authority_write(
                    write,
                    object,
                    true,
                    Some(*pending.semantic_id.as_bytes()),
                    None,
                    None,
                )?;
            }
            RETIREMENT_REFERENCE_ACKNOWLEDGEMENT => {
                let (_, semantic_id) = parse_event_acknowledgement_key(parsed.primary)?;
                let _ = write
                    .open_table(EVENT_DELIVERY_ACKNOWLEDGEMENTS)?
                    .get(parsed.primary)?
                    .map(|value| decode_event_acknowledgement_record(value.value()))
                    .transpose()?
                    .ok_or(CustodyStoreError::Invariant(
                        "custody retirement reference points to a missing acknowledgement",
                    ))?;
                if semantic_id.as_bytes() != parsed.target {
                    return Err(CustodyStoreError::Invariant(
                        "acknowledgement retirement reference targets the wrong Event",
                    )
                    .into());
                }
                let object = event_object_for_semantic_write(write, semantic_id)?;
                validate_dependency_authority_write(
                    write,
                    object,
                    true,
                    Some(*semantic_id.as_bytes()),
                    None,
                    None,
                )?;
            }
            _ => unreachable!("validated retirement reference kind"),
        }
    }
    Ok(())
}

fn audit_retirement_references_read(read: &redb::ReadTransaction) -> Result<(), StoreError> {
    for row in read.open_table(CUSTODY_RETIREMENT_REFERENCES)?.iter()? {
        let (key, value) = row?;
        if !value.value().is_empty() {
            return Err(CustodyStoreError::Invariant(
                "custody retirement reference value is invalid",
            )
            .into());
        }
        let parsed = parse_retirement_reference_key(key.value())?;
        match parsed.kind {
            RETIREMENT_REFERENCE_LEASE => {
                let id =
                    u64::from_be_bytes(parsed.primary.try_into().expect("validated lease key"));
                let lease = read
                    .open_table(CUSTODY_LEASES)?
                    .get(id)?
                    .map(|value| decode_lease(value.value()))
                    .transpose()?
                    .ok_or(CustodyStoreError::Invariant(
                        "custody retirement reference points to a missing lease",
                    ))?;
                if lease.object.encoded().as_slice() != parsed.target {
                    return Err(CustodyStoreError::Invariant(
                        "lease retirement reference targets the wrong object",
                    )
                    .into());
                }
                validate_dependency_authority_read(
                    read,
                    lease.object,
                    false,
                    None,
                    Some(lease.item_revision),
                    None,
                )?;
            }
            RETIREMENT_REFERENCE_RETRY => {
                let retry = read
                    .open_table(CUSTODY_RETRIES)?
                    .get(parsed.primary)?
                    .map(|value| decode_retry(value.value()))
                    .transpose()?
                    .ok_or(CustodyStoreError::Invariant(
                        "custody retirement reference points to a missing retry",
                    ))?;
                let (_, object) = parse_peer_object_key(parsed.primary)?;
                if object.encoded().as_slice() != parsed.target {
                    return Err(CustodyStoreError::Invariant(
                        "retry retirement reference targets the wrong object",
                    )
                    .into());
                }
                validate_dependency_authority_read(
                    read,
                    object,
                    true,
                    None,
                    Some(retry.item_revision),
                    Some(retry.priority),
                )?;
            }
            RETIREMENT_REFERENCE_RECEIPT => {
                let receipt = read
                    .open_table(CUSTODY_PEER_RECEIPTS)?
                    .get(parsed.primary)?
                    .map(|value| decode_receipt(value.value()))
                    .transpose()?
                    .ok_or(CustodyStoreError::Invariant(
                        "custody retirement reference points to a missing receipt",
                    ))?;
                let (_, object) = parse_peer_object_key(parsed.primary)?;
                if object.encoded().as_slice() != parsed.target {
                    return Err(CustodyStoreError::Invariant(
                        "receipt retirement reference targets the wrong object",
                    )
                    .into());
                }
                validate_dependency_authority_read(
                    read,
                    object,
                    true,
                    None,
                    Some(receipt.item_revision),
                    None,
                )?;
            }
            RETIREMENT_REFERENCE_PENDING => {
                let pending = read
                    .open_table(EVENT_SUBSCRIPTION_PENDING)?
                    .get(parsed.primary)?
                    .map(|value| decode_event_pending_delivery_record(value.value()))
                    .transpose()?
                    .ok_or(CustodyStoreError::Invariant(
                        "custody retirement reference points to a missing pending delivery",
                    ))?;
                if pending.semantic_id.as_bytes() != parsed.target {
                    return Err(CustodyStoreError::Invariant(
                        "pending retirement reference targets the wrong Event",
                    )
                    .into());
                }
                let object = event_object_for_semantic_read(read, pending.semantic_id)?;
                validate_dependency_authority_read(
                    read,
                    object,
                    true,
                    Some(*pending.semantic_id.as_bytes()),
                    None,
                    None,
                )?;
            }
            RETIREMENT_REFERENCE_ACKNOWLEDGEMENT => {
                let (_, semantic_id) = parse_event_acknowledgement_key(parsed.primary)?;
                let _ = read
                    .open_table(EVENT_DELIVERY_ACKNOWLEDGEMENTS)?
                    .get(parsed.primary)?
                    .map(|value| decode_event_acknowledgement_record(value.value()))
                    .transpose()?
                    .ok_or(CustodyStoreError::Invariant(
                        "custody retirement reference points to a missing acknowledgement",
                    ))?;
                if semantic_id.as_bytes() != parsed.target {
                    return Err(CustodyStoreError::Invariant(
                        "acknowledgement retirement reference targets the wrong Event",
                    )
                    .into());
                }
                let object = event_object_for_semantic_read(read, semantic_id)?;
                validate_dependency_authority_read(
                    read,
                    object,
                    true,
                    Some(*semantic_id.as_bytes()),
                    None,
                    None,
                )?;
            }
            _ => unreachable!("validated retirement reference kind"),
        }
    }
    Ok(())
}

fn preflight_custody_cardinality_write(
    write: &redb::WriteTransaction,
    limits: StoreLimits,
) -> Result<(), StoreError> {
    let items = write.open_table(CUSTODY_ITEMS)?.len()?;
    let retirements = write.open_table(CUSTODY_RETIREMENTS)?.len()?;
    let retired_semantics = write.open_table(CUSTODY_RETIRED_SEMANTICS)?.len()?;
    require_audit_table_bound(
        items,
        limits.max_items(),
        "custody item table exceeds aggregate item bound",
    )?;
    require_audit_table_bound(
        retirements,
        MAX_CUSTODY_RETIREMENTS,
        "custody retirement cap is exceeded",
    )?;
    require_audit_table_bound(
        retired_semantics,
        retirements,
        "retired semantic index exceeds retirement rows",
    )?;
    require_audit_table_bound(
        write.open_table(CUSTODY_EXPIRATIONS)?.len()?,
        items,
        "custody expiration index exceeds live items",
    )?;
    require_audit_table_bound(
        write.open_table(CUSTODY_RETIRING)?.len()?,
        items
            .checked_add(retirements)
            .ok_or(CustodyStoreError::CounterOverflow)?,
        "custody retiring index exceeds marked items and retirement fences",
    )?;
    require_audit_table_bound(
        write.open_table(CUSTODY_LEASES)?.len()?,
        MAX_CUSTODY_TRANSFER_LEASES,
        "custody lease cap is exceeded",
    )?;
    require_audit_table_bound(
        write.open_table(CUSTODY_PEER_RECEIPTS)?.len()?,
        MAX_CUSTODY_PEER_RECEIPTS,
        "peer receipt cap is exceeded",
    )?;
    require_audit_table_bound(
        write.open_table(CUSTODY_RETRIES)?.len()?,
        MAX_CUSTODY_RETRY_RECORDS,
        "retry cap is exceeded",
    )?;
    require_audit_table_bound(
        write.open_table(CUSTODY_RETIREMENT_REFERENCES)?.len()?,
        MAX_CUSTODY_RETIREMENT_REFERENCES,
        "custody retirement reference cap is exceeded",
    )?;
    require_audit_table_bound(
        write.open_table(CUSTODY_QUOTAS)?.len()?,
        MAX_CUSTODY_QUOTAS,
        "custody quota cap is exceeded",
    )?;
    require_audit_table_bound(
        write.open_table(CUSTODY_SCOPE_USAGE)?.len()?,
        items,
        "custody scope usage exceeds live items",
    )?;
    Ok(())
}

fn preflight_custody_cardinality_read(
    read: &redb::ReadTransaction,
    aggregate_items: u64,
) -> Result<(), StoreError> {
    let items = read.open_table(CUSTODY_ITEMS)?.len()?;
    let retirements = read.open_table(CUSTODY_RETIREMENTS)?.len()?;
    let retired_semantics = read.open_table(CUSTODY_RETIRED_SEMANTICS)?.len()?;
    require_audit_table_bound(
        items,
        aggregate_items,
        "custody item table exceeds aggregate item bound",
    )?;
    require_audit_table_bound(
        retirements,
        MAX_CUSTODY_RETIREMENTS,
        "custody retirement cap is exceeded",
    )?;
    require_audit_table_bound(
        retired_semantics,
        retirements,
        "retired semantic index exceeds retirement rows",
    )?;
    require_audit_table_bound(
        read.open_table(CUSTODY_EXPIRATIONS)?.len()?,
        items,
        "custody expiration index exceeds live items",
    )?;
    require_audit_table_bound(
        read.open_table(CUSTODY_RETIRING)?.len()?,
        items
            .checked_add(retirements)
            .ok_or(CustodyStoreError::CounterOverflow)?,
        "custody retiring index exceeds marked items and retirement fences",
    )?;
    require_audit_table_bound(
        read.open_table(CUSTODY_LEASES)?.len()?,
        MAX_CUSTODY_TRANSFER_LEASES,
        "custody lease cap is exceeded",
    )?;
    require_audit_table_bound(
        read.open_table(CUSTODY_PEER_RECEIPTS)?.len()?,
        MAX_CUSTODY_PEER_RECEIPTS,
        "peer receipt cap is exceeded",
    )?;
    require_audit_table_bound(
        read.open_table(CUSTODY_RETRIES)?.len()?,
        MAX_CUSTODY_RETRY_RECORDS,
        "retry cap is exceeded",
    )?;
    require_audit_table_bound(
        read.open_table(CUSTODY_RETIREMENT_REFERENCES)?.len()?,
        MAX_CUSTODY_RETIREMENT_REFERENCES,
        "custody retirement reference cap is exceeded",
    )?;
    require_audit_table_bound(
        read.open_table(CUSTODY_QUOTAS)?.len()?,
        MAX_CUSTODY_QUOTAS,
        "custody quota cap is exceeded",
    )?;
    require_audit_table_bound(
        read.open_table(CUSTODY_SCOPE_USAGE)?.len()?,
        items,
        "custody scope usage exceeds live items",
    )?;
    Ok(())
}

pub(crate) fn audit_custody_tables_write(
    write: &redb::WriteTransaction,
    limits: StoreLimits,
    mission_authority: Option<NodeId>,
) -> Result<CustodyStoreStats, StoreError> {
    let existed = preflight_custody_schema_write(write)?;
    if !existed {
        initialize_custody_schema(write, limits, mission_authority)?;
    }
    let mut bound = custody_mission_write(write)?;
    if let Some(authority) = mission_authority {
        match bound {
            Some(bound) if bound != authority => {
                return Err(CustodyStoreError::MissionMismatch.into());
            }
            Some(_) => {}
            None => {
                let nonempty = write.open_table(CUSTODY_ITEMS)?.len()? != 0
                    || write.open_table(CUSTODY_RETIREMENTS)?.len()? != 0
                    || write.open_table(CUSTODY_LEASES)?.len()? != 0
                    || write.open_table(CUSTODY_PEER_RECEIPTS)?.len()? != 0
                    || write.open_table(CUSTODY_RETRIES)?.len()? != 0;
                if nonempty {
                    return Err(CustodyStoreError::MissionNotBound.into());
                }
                // Binding an already-created unbound store is also the point
                // at which the mission's emergency control/key/tombstone
                // reserve becomes mandatory. Refuse atomically if earlier
                // opaque ordinary rows consumed that reserve.
                require_ordinary_aggregate_capacity(
                    write,
                    &write.open_table(METADATA)?,
                    limits,
                    0,
                    0,
                )?;
                write
                    .open_table(CUSTODY_DOMAIN)?
                    .insert(CUSTODY_MISSION_AUTHORITY_KEY, authority.as_slice())?;
                bound = Some(authority);
            }
        }
    }
    if write.open_table(CUSTODY_DOMAIN)?.len()? != u64::from(bound.is_some()) {
        return Err(CustodyStoreError::Invariant("custody domain contains an orphan row").into());
    }

    let metadata = write.open_table(CUSTODY_METADATA)?;
    if metadata.len()? != 14
        || metadata_value(&metadata, CUSTODY_SCHEMA_VERSION_KEY)? != CUSTODY_SCHEMA_VERSION
    {
        return Err(CustodyStoreError::Invariant("custody metadata schema is incomplete").into());
    }
    let policy_revision = metadata_value(&metadata, CUSTODY_POLICY_REVISION_KEY)?;
    let mutation_revision = metadata_value(&metadata, CUSTODY_MUTATION_REVISION_KEY)?;
    let next_lease = metadata_value(&metadata, CUSTODY_NEXT_LEASE_KEY)?;
    if policy_revision == 0 || mutation_revision == 0 {
        return Err(CustodyStoreError::Invariant("custody revision is zero").into());
    }
    drop(metadata);

    preflight_custody_cardinality_write(write, limits)?;

    let continuity = continuity_write(write)?;
    if write.open_table(CUSTODY_CONTINUITY)?.len()? != u64::from(continuity.is_some()) {
        return Err(CustodyStoreError::Invariant(
            "custody continuity table contains an orphan row",
        )
        .into());
    }

    let mut item_count = 0u64;
    let mut total_bytes = 0u64;
    let mut ordinary_item_count = 0u64;
    let mut ordinary_total_bytes = 0u64;
    let mut items = BTreeMap::new();
    let mut scope_usages = BTreeMap::<String, CustodyUsage>::new();
    let mut legacy_item_repairs = Vec::new();
    for row in write.open_table(CUSTODY_ITEMS)?.iter()? {
        let (key, value) = row?;
        let encoded_key = key.value().to_vec();
        let key = CustodyObjectKey::decode(key.value())?;
        let mut record = decode_item(value.value())?;
        if record.route_only != (key.class == CustodyObjectClass::RouteEvent) {
            return Err(CustodyStoreError::Invariant(
                "custody route-only flag differs from its class",
            )
            .into());
        }
        if let Some(continuity) = continuity
            && record.continuity_generation > continuity.generation
        {
            return Err(CustodyStoreError::Invariant(
                "custody item generation is ahead of the store clock",
            )
            .into());
        }
        if is_unanchored_lost_finite(&record) && record.continuity_generation != 0 {
            record.continuity_generation = 0;
            legacy_item_repairs.push((encoded_key, encode_item(&record)?));
        }
        validate_item_backing_write(write, key, &record)?;
        item_count = next_counter(item_count)?;
        total_bytes = total_bytes
            .checked_add(record.accounted_bytes)
            .ok_or(CustodyStoreError::CounterOverflow)?;
        if !record.tombstone {
            ordinary_item_count = next_counter(ordinary_item_count)?;
            ordinary_total_bytes = ordinary_total_bytes
                .checked_add(record.accounted_bytes)
                .ok_or(CustodyStoreError::CounterOverflow)?;
            let usage = scope_usages
                .entry(record.scope.as_str().to_owned())
                .or_default();
            usage.items = next_counter(usage.items)?;
            usage.bytes = usage
                .bytes
                .checked_add(record.accounted_bytes)
                .ok_or(CustodyStoreError::CounterOverflow)?;
        }
        items.insert(key, record);
    }
    if !legacy_item_repairs.is_empty() {
        let mut item_table = write.open_table(CUSTODY_ITEMS)?;
        for (key, value) in &legacy_item_repairs {
            item_table.insert(key.as_slice(), value.as_slice())?;
        }
    }
    let (expected_expirations, expected_retiring) = expected_custody_maintenance_indexes(&items)?;
    let mut durable_expirations = BTreeSet::new();
    for row in write.open_table(CUSTODY_EXPIRATIONS)?.iter()? {
        let (key, value) = row?;
        if !value.value().is_empty() {
            return Err(CustodyStoreError::Invariant(
                "custody expiration index value is not empty",
            )
            .into());
        }
        let _ = decode_custody_expiration_key(key.value())?;
        durable_expirations.insert(key.value().to_vec());
    }
    let missing_expirations = expected_expirations
        .difference(&durable_expirations)
        .cloned()
        .collect::<Vec<_>>();
    let has_extra_expirations = durable_expirations
        .difference(&expected_expirations)
        .next()
        .is_some();
    let repairable_missing = missing_expirations
        .iter()
        .map(|encoded| is_canonical_lost_sentinel_for(encoded, &items))
        .collect::<Result<Vec<_>, _>>()?
        .into_iter()
        .all(|repairable| repairable);
    if has_extra_expirations || !repairable_missing {
        return Err(CustodyStoreError::Invariant(
            "custody expiration index differs from live items",
        )
        .into());
    }
    if !missing_expirations.is_empty() {
        let mut expirations = write.open_table(CUSTODY_EXPIRATIONS)?;
        for encoded in &missing_expirations {
            expirations.insert(encoded.as_slice(), &[][..])?;
        }
    }
    if !legacy_item_repairs.is_empty() || !missing_expirations.is_empty() {
        advance_revision(write, false)?;
    }
    let mut durable_retiring = BTreeSet::new();
    let mut retirement_cleanups = BTreeMap::new();
    for row in write.open_table(CUSTODY_RETIRING)?.iter()? {
        let (key, value) = row?;
        let (acceptance_order, object) = decode_custody_retiring_key(key.value())?;
        let cleanup = cleanup_record_for_row(value.value(), items.get(&object))?;
        if retirement_cleanups
            .insert(object, (acceptance_order, cleanup))
            .is_some()
        {
            return Err(CustodyStoreError::Invariant(
                "custody retirement cleanup contains duplicate objects",
            )
            .into());
        }
        durable_retiring.insert(key.value().to_vec());
    }
    if !expected_retiring.is_subset(&durable_retiring) {
        return Err(
            CustodyStoreError::Invariant("custody retiring index omits a marked item").into(),
        );
    }
    let mut durable_scope_usages = BTreeMap::new();
    for row in write.open_table(CUSTODY_SCOPE_USAGE)?.iter()? {
        let (scope, value) = row?;
        let scope = scope.value().to_owned();
        let _ = Scope::new(&scope)
            .map_err(|_| CustodyStoreError::Invariant("custody scope usage key is invalid"))?;
        durable_scope_usages.insert(scope, decode_scope_usage(value.value())?);
    }
    if durable_scope_usages != scope_usages {
        return Err(CustodyStoreError::Invariant(
            "custody scope usage differs from live item accounting",
        )
        .into());
    }

    let mut retirement_count = 0u64;
    let mut retirements = BTreeMap::new();
    let mut retired_route_semantics = BTreeMap::<[u8; 32], [u8; 33]>::new();
    for row in write.open_table(CUSTODY_RETIREMENTS)?.iter()? {
        let (key, value) = row?;
        let key = CustodyObjectKey::decode(key.value())?;
        let record = decode_retirement(value.value())?;
        if items.contains_key(&key) || retirements.insert(key, record.clone()).is_some() {
            return Err(CustodyStoreError::Invariant(
                "custody item and retirement namespaces overlap",
            )
            .into());
        }
        validate_retirement_backing_write(write, key, &record)?;
        if key.class == CustodyObjectClass::RouteEvent {
            retired_route_semantics
                .entry(record.semantic_id)
                .and_modify(|current| *current = (*current).min(key.encoded()))
                .or_insert_with(|| key.encoded());
        }
        retirement_count = next_counter(retirement_count)?;
    }
    for (object, (acceptance_order, cleanup)) in &retirement_cleanups {
        validate_cleanup_control_state(
            *object,
            *acceptance_order,
            cleanup,
            items.get(object),
            retirements.get(object),
        )?;
    }
    require_unique_event_transfer_state(items.keys().chain(retirements.keys()).copied())?;
    if retirement_count > MAX_CUSTODY_RETIREMENTS {
        return Err(CustodyStoreError::Invariant("custody retirement cap is exceeded").into());
    }
    if retirement_count
        .checked_add(ordinary_item_count)
        .ok_or(CustodyStoreError::CounterOverflow)?
        > MAX_CUSTODY_RETIREMENTS
    {
        return Err(CustodyStoreError::Invariant(
            "live Event rows exceed their permanent retirement-fence reserve",
        )
        .into());
    }
    let mut durable_retired_semantics = BTreeMap::new();
    for row in write.open_table(CUSTODY_RETIRED_SEMANTICS)?.iter()? {
        let (semantic, object) = row?;
        let semantic: [u8; 32] = semantic
            .value()
            .try_into()
            .map_err(|_| CustodyStoreError::Invariant("retired semantic key has invalid length"))?;
        let object = CustodyObjectKey::decode(object.value())?;
        if object.class != CustodyObjectClass::RouteEvent {
            return Err(CustodyStoreError::Invariant(
                "retired semantic index references a non-route object",
            )
            .into());
        }
        durable_retired_semantics.insert(semantic, object.encoded());
    }
    if durable_retired_semantics != retired_route_semantics {
        return Err(CustodyStoreError::Invariant(
            "retired route semantic index differs from permanent fences",
        )
        .into());
    }

    let mut lease_count = 0u64;
    let mut max_lease = 0u64;
    let mut lease_ids = Vec::new();
    for row in write.open_table(CUSTODY_LEASES)?.iter()? {
        let (id, value) = row?;
        let id = id.value();
        let lease = decode_lease(value.value())?;
        let item = items
            .get(&lease.object)
            .ok_or(CustodyStoreError::Invariant(
                "transfer lease references a missing custody item",
            ))?;
        if item.revision != lease.item_revision || lease.policy_revision > policy_revision {
            return Err(CustodyStoreError::Invariant(
                "transfer lease has a stale or future revision",
            )
            .into());
        }
        if id == 0 {
            return Err(CustodyStoreError::Invariant("transfer lease identifier is zero").into());
        }
        lease_count = next_counter(lease_count)?;
        max_lease = max_lease.max(id);
        lease_ids.push(id);
        require_retirement_reference_write(
            write,
            RETIREMENT_REFERENCE_LEASE,
            lease.object.encoded().as_slice(),
            &id.to_be_bytes(),
        )?;
    }
    if lease_count > MAX_CUSTODY_TRANSFER_LEASES || max_lease > next_lease {
        return Err(
            CustodyStoreError::Invariant("custody lease cap or high-water is invalid").into(),
        );
    }

    let mut receipt_count = 0u64;
    let mut legacy_receipt_keys = Vec::new();
    let receipts = write.open_table(CUSTODY_PEER_RECEIPTS)?;
    for row in receipts.iter()? {
        let (key, value) = row?;
        let (_, object) = parse_peer_object_key(key.value())?;
        let receipt = decode_receipt(value.value())?;
        let expected_revision = items.get(&object).map(|item| item.revision).or_else(|| {
            retirement_cleanups
                .get(&object)
                .map(|(_, cleanup)| cleanup.original_revision)
        });
        if receipt.item_revision
            != expected_revision.ok_or(CustodyStoreError::Invariant(
                "peer receipt references non-live custody history",
            ))?
        {
            return Err(CustodyStoreError::Invariant(
                "peer receipt revision differs from its custody item",
            )
            .into());
        }
        if receipt.peer_selector_revision.is_none() {
            legacy_receipt_keys.push(key.value().to_vec());
        }
        require_retirement_reference_write(
            write,
            RETIREMENT_REFERENCE_RECEIPT,
            object.encoded().as_slice(),
            key.value(),
        )?;
        receipt_count = next_counter(receipt_count)?;
    }
    if receipt_count > MAX_CUSTODY_PEER_RECEIPTS {
        return Err(CustodyStoreError::Invariant("peer receipt cap is exceeded").into());
    }

    let mut retry_count = 0u64;
    for row in write.open_table(CUSTODY_RETRIES)?.iter()? {
        let (key, value) = row?;
        let (_, object) = parse_peer_object_key(key.value())?;
        let retry = decode_retry(value.value())?;
        let expected = items
            .get(&object)
            .map(|item| (item.revision, item.priority))
            .or_else(|| {
                retirement_cleanups
                    .get(&object)
                    .map(|(_, cleanup)| (cleanup.original_revision, cleanup.priority))
            })
            .ok_or(CustodyStoreError::Invariant(
                "retry references missing custody history",
            ))?;
        if expected.0 != retry.item_revision
            || retry.policy_revision > policy_revision
            || expected.1 != retry.priority
            || receipts.get(key.value())?.is_some()
        {
            return Err(CustodyStoreError::Invariant(
                "retry state differs from its custody item or overlaps a receipt",
            )
            .into());
        }
        require_retirement_reference_write(
            write,
            RETIREMENT_REFERENCE_RETRY,
            object.encoded().as_slice(),
            key.value(),
        )?;
        retry_count = next_counter(retry_count)?;
    }
    if retry_count > MAX_CUSTODY_RETRY_RECORDS {
        return Err(CustodyStoreError::Invariant("retry cap is exceeded").into());
    }
    drop(receipts);
    audit_event_retirement_reference_sources_write(write)?;
    audit_retirement_references_write(write)?;

    let mut quota_count = 0u64;
    let mut quotas = BTreeMap::new();
    for row in write.open_table(CUSTODY_QUOTAS)?.iter()? {
        let (key, value) = row?;
        let key = key.value().to_owned();
        let quota = decode_quota(&key, value.value())?;
        quota_count = next_counter(quota_count)?;
        quotas.insert(key, quota);
    }
    if quota_count > MAX_CUSTODY_QUOTAS || !quotas.contains_key(GLOBAL_QUOTA_KEY) {
        return Err(CustodyStoreError::Invariant(
            "custody quota set is unbounded or lacks global policy",
        )
        .into());
    }
    require_quota_capacity(
        CustodyUsage {
            items: ordinary_item_count,
            bytes: ordinary_total_bytes,
        },
        quotas.get(GLOBAL_QUOTA_KEY).expect("checked global quota"),
        0,
        0,
    )?;
    let operation_metadata = write.open_table(METADATA)?;
    let tombstone_operation_items = operation_metadata
        .get(EVENT_TOMBSTONE_OPERATION_COUNT)?
        .map_or(0, |value| value.value());
    let tombstone_operation_bytes = operation_metadata
        .get(EVENT_TOMBSTONE_OPERATION_TOTAL_BYTES)?
        .map_or(0, |value| value.value());
    drop(operation_metadata);
    let tombstone_usage = CustodyUsage {
        items: item_count
            .checked_sub(ordinary_item_count)
            .and_then(|items| items.checked_add(tombstone_operation_items))
            .ok_or(CustodyStoreError::Invariant(
                "ordinary items exceed total custody items",
            ))?,
        bytes: total_bytes
            .checked_sub(ordinary_total_bytes)
            .and_then(|bytes| bytes.checked_add(tombstone_operation_bytes))
            .ok_or(CustodyStoreError::Invariant(
                "ordinary bytes exceed total custody bytes",
            ))?,
    };
    let (tombstone_max_items, tombstone_max_bytes) = custody_tombstone_allowance(limits);
    require_quota_capacity(
        tombstone_usage,
        &CustodyQuota {
            scope: None,
            max_items: tombstone_max_items,
            max_bytes: tombstone_max_bytes,
        },
        0,
        0,
    )?;
    for (scope, quota) in quotas.iter().filter(|(scope, _)| !scope.is_empty()) {
        let _ = Scope::new(scope)
            .map_err(|_| CustodyStoreError::Invariant("custody quota scope is invalid"))?;
        let usage = scope_usages.get(scope).copied().unwrap_or_default();
        require_quota_capacity(usage, quota, 0, 0)?;
    }

    let metadata = write.open_table(CUSTODY_METADATA)?;
    for (field, reconstructed) in [
        (CUSTODY_ITEM_COUNT_KEY, item_count),
        (CUSTODY_TOTAL_BYTES_KEY, total_bytes),
        (CUSTODY_ORDINARY_ITEM_COUNT_KEY, ordinary_item_count),
        (CUSTODY_ORDINARY_TOTAL_BYTES_KEY, ordinary_total_bytes),
        (CUSTODY_RETIREMENT_COUNT_KEY, retirement_count),
        (CUSTODY_LEASE_COUNT_KEY, lease_count),
        (CUSTODY_RECEIPT_COUNT_KEY, receipt_count),
        (CUSTODY_RETRY_COUNT_KEY, retry_count),
        (CUSTODY_QUOTA_COUNT_KEY, quota_count),
    ] {
        let durable = metadata_value(&metadata, field)?;
        if durable != reconstructed {
            return Err(StoreError::AccountingMismatch {
                field,
                durable,
                reconstructed,
            });
        }
    }
    drop(metadata);
    if mission_authority.is_some() {
        require_ordinary_aggregate_capacity(write, &write.open_table(METADATA)?, limits, 0, 0)?;
    }

    // Version-1 receipts predate authenticated peer selector generations and
    // cannot safely suppress even canonical revision zero. After exact audit,
    // writable reopen drops those bounded hints and repairs their counter.
    if !legacy_receipt_keys.is_empty() {
        let mut receipts = write.open_table(CUSTODY_PEER_RECEIPTS)?;
        for key in &legacy_receipt_keys {
            if receipts.remove(key.as_slice())?.is_none() {
                return Err(CustodyStoreError::Invariant(
                    "legacy custody receipt disappeared during migration",
                )
                .into());
            }
            remove_peer_retirement_reference_write(
                write,
                RETIREMENT_REFERENCE_RECEIPT,
                key.as_slice(),
                "legacy receipt retirement reference disappeared",
            )?;
        }
        drop(receipts);
        let removed = u64::try_from(legacy_receipt_keys.len())
            .map_err(|_| CustodyStoreError::CounterOverflow)?;
        receipt_count = receipt_count
            .checked_sub(removed)
            .ok_or(CustodyStoreError::Invariant(
                "legacy custody receipt accounting underflow",
            ))?;
        write
            .open_table(CUSTODY_METADATA)?
            .insert(CUSTODY_RECEIPT_COUNT_KEY, receipt_count)?;
        advance_revision(write, false)?;
    }

    // Leases coordinate one live process and cannot survive a crash as send
    // authority.  The exact writer lock makes writable reopen the recovery
    // boundary: audit every row above, then atomically clear the abandoned set.
    if !lease_ids.is_empty() {
        let mut leases = write.open_table(CUSTODY_LEASES)?;
        for lease_id in lease_ids {
            let lease = leases
                .remove(lease_id)?
                .map(|value| decode_lease(value.value()))
                .transpose()?
                .ok_or(CustodyStoreError::Invariant(
                    "lease disappeared during reopen recovery",
                ))?;
            remove_lease_retirement_reference_write(write, lease.object, lease_id)?;
        }
        write
            .open_table(CUSTODY_METADATA)?
            .insert(CUSTODY_LEASE_COUNT_KEY, 0)?;
        advance_revision(write, true)?;
        lease_count = 0;
    }

    Ok(CustodyStoreStats {
        items: item_count,
        bytes: total_bytes,
        retirements: retirement_count,
        transfer_leases: lease_count,
        peer_receipts: receipt_count,
        retries: retry_count,
        quotas: quota_count,
        policy_revision: CustodyPolicyRevision(if lease_count == 0 {
            metadata_value(
                &write.open_table(CUSTODY_METADATA)?,
                CUSTODY_POLICY_REVISION_KEY,
            )?
        } else {
            policy_revision
        }),
        mutation_revision: metadata_value(
            &write.open_table(CUSTODY_METADATA)?,
            CUSTODY_MUTATION_REVISION_KEY,
        )?,
    })
}

fn validate_item_backing_read(
    read: &redb::ReadTransaction,
    key: CustodyObjectKey,
    record: &CustodyItemRecord,
) -> Result<(), StoreError> {
    match key.class {
        CustodyObjectClass::Event => {
            let metadata = read
                .open_table(EVENTS)?
                .get(key.transfer_id.as_slice())?
                .map(|value| decode_event_metadata(value.value()))
                .transpose()?
                .ok_or(CustodyStoreError::Invariant(
                    "custody Event is missing semantic metadata",
                ))?;
            let bytes = read
                .open_table(EVENT_BYTES)?
                .get(key.transfer_id.as_slice())?
                .map(|value| u64::try_from(value.value().len()))
                .transpose()
                .map_err(|_| CustodyStoreError::CounterOverflow)?
                .ok_or(CustodyStoreError::Invariant(
                    "live custody Event is missing exact bytes",
                ))?;
            if metadata.semantic_id.as_bytes() != &record.semantic_id
                || metadata.header.topic != record.topic
                || metadata.header.scope != record.scope
                || metadata.header.stamp.dot.publisher != record.source_publisher
                || metadata.header.key_epoch != record.key_epoch
                || metadata.header.priority != record.priority
                || metadata.header.ttl_ms != record.ttl_ms
                || metadata.header.tombstone != record.tombstone
                || bytes != record.accounted_bytes
            {
                return Err(CustodyStoreError::Invariant(
                    "custody Event differs from durable metadata",
                )
                .into());
            }
        }
        CustodyObjectClass::RouteEvent => {
            let claim = read
                .open_table(ROUTE_CACHE_CLAIMS)?
                .get(key.transfer_id.as_slice())?
                .map(|value| decode_event_metadata(value.value()))
                .transpose()?
                .ok_or(CustodyStoreError::Invariant(
                    "custody route Event is missing its claim",
                ))?;
            let bytes = read
                .open_table(ROUTE_CACHE)?
                .get(key.transfer_id.as_slice())?
                .map(|value| u64::try_from(value.value().len()))
                .transpose()
                .map_err(|_| CustodyStoreError::CounterOverflow)?
                .ok_or(CustodyStoreError::Invariant(
                    "custody route Event is missing exact bytes",
                ))?;
            if claim.semantic_id.as_bytes() != &record.semantic_id
                || claim.header.topic != record.topic
                || claim.header.scope != record.scope
                || claim.header.stamp.dot.publisher != record.source_publisher
                || claim.header.key_epoch != record.key_epoch
                || claim.header.priority != record.priority
                || claim.header.ttl_ms != record.ttl_ms
                || claim.header.tombstone != record.tombstone
                || bytes != record.accounted_bytes
                || !record.route_only
            {
                return Err(CustodyStoreError::Invariant(
                    "custody route Event differs from durable metadata",
                )
                .into());
            }
        }
        CustodyObjectClass::State => {
            if read
                .open_table(STATES)?
                .get(key.transfer_id.as_slice())?
                .is_none()
            {
                return Err(CustodyStoreError::Invariant(
                    "custody State is missing its selected row",
                )
                .into());
            }
        }
        CustodyObjectClass::Record => {
            if read
                .open_table(RECORDS)?
                .get(key.transfer_id.as_slice())?
                .is_none()
            {
                return Err(CustodyStoreError::Invariant(
                    "custody Record is missing its selected row",
                )
                .into());
            }
        }
        CustodyObjectClass::Blob => {
            if read
                .open_table(blob::BLOB_PUBLICATIONS)?
                .get(key.transfer_id.as_slice())?
                .is_none()
            {
                return Err(CustodyStoreError::Invariant(
                    "custody Blob is missing its selected row",
                )
                .into());
            }
        }
    }
    Ok(())
}

fn validate_retirement_backing_read(
    read: &redb::ReadTransaction,
    key: CustodyObjectKey,
    record: &RetirementRecord,
) -> Result<(), StoreError> {
    match key.class {
        CustodyObjectClass::Event => {
            let metadata = read
                .open_table(EVENTS)?
                .get(key.transfer_id.as_slice())?
                .map(|value| decode_event_metadata(value.value()))
                .transpose()?
                .ok_or(CustodyStoreError::Invariant(
                    "retired Event lost permanent metadata",
                ))?;
            if metadata.semantic_id.as_bytes() != &record.semantic_id
                || metadata.header.topic != record.topic
                || metadata.header.scope != record.scope
                || metadata.header.stamp.dot.publisher != record.source_publisher
                || metadata.header.key_epoch != record.key_epoch
                || read
                    .open_table(EVENT_BYTES)?
                    .get(key.transfer_id.as_slice())?
                    .is_some()
            {
                return Err(CustodyStoreError::Invariant(
                    "retired Event still has payload or mismatched metadata",
                )
                .into());
            }
            let marker = read
                .open_table(EVENT_ACCEPTANCE_MARKERS)?
                .get(key.transfer_id.as_slice())?
                .map(|value| value.value())
                .ok_or(CustodyStoreError::Invariant(
                    "retired Event lost its acceptance marker",
                ))?;
            if marker != record.acceptance_order
                || read
                    .open_table(EVENT_ACCEPTANCE_ORDER)?
                    .get(marker)?
                    .map(|value| value.value().to_vec())
                    != Some(key.transfer_id.to_vec())
            {
                return Err(CustodyStoreError::Invariant(
                    "retired Event acceptance fences changed",
                )
                .into());
            }
        }
        CustodyObjectClass::RouteEvent => {
            if read
                .open_table(ROUTE_CACHE)?
                .get(key.transfer_id.as_slice())?
                .is_some()
                || read
                    .open_table(ROUTE_CACHE_CLAIMS)?
                    .get(key.transfer_id.as_slice())?
                    .is_some()
            {
                return Err(CustodyStoreError::Invariant(
                    "retired route Event still has payload state",
                )
                .into());
            }
        }
        class => return Err(CustodyStoreError::UnsupportedRetirementClass(class).into()),
    }
    Ok(())
}

pub(crate) fn inspect_custody_tables_read(
    read: &redb::ReadTransaction,
    mission_authority: Option<NodeId>,
    aggregate_items: u64,
) -> Result<CustodyStoreStats, StoreError> {
    if !custody_schema_present_read(read)? {
        return Ok(CustodyStoreStats::default());
    }
    let domain = read.open_table(CUSTODY_DOMAIN)?;
    let bound: Option<NodeId> = domain
        .get(CUSTODY_MISSION_AUTHORITY_KEY)?
        .map(|value| {
            value.value().try_into().map_err(|_| {
                CustodyStoreError::Invariant("custody mission authority has invalid length")
            })
        })
        .transpose()?;
    if domain.len()? != u64::from(bound.is_some()) {
        return Err(CustodyStoreError::Invariant("custody domain contains an orphan row").into());
    }
    match (bound, mission_authority) {
        (Some(bound), Some(authority)) if bound == authority => {}
        (None, None) => {}
        (Some(_), Some(_)) => return Err(CustodyStoreError::MissionMismatch.into()),
        _ => return Err(CustodyStoreError::MissionNotBound.into()),
    }
    let metadata = read.open_table(CUSTODY_METADATA)?;
    if metadata.len()? != 14
        || metadata_value(&metadata, CUSTODY_SCHEMA_VERSION_KEY)? != CUSTODY_SCHEMA_VERSION
    {
        return Err(CustodyStoreError::Invariant("custody metadata schema is incomplete").into());
    }
    let policy_revision = metadata_value(&metadata, CUSTODY_POLICY_REVISION_KEY)?;
    let mutation_revision = metadata_value(&metadata, CUSTODY_MUTATION_REVISION_KEY)?;
    let next_lease = metadata_value(&metadata, CUSTODY_NEXT_LEASE_KEY)?;
    if policy_revision == 0 || mutation_revision == 0 {
        return Err(CustodyStoreError::Invariant("custody revision is zero").into());
    }
    drop(metadata);
    preflight_custody_cardinality_read(read, aggregate_items)?;
    let continuity = read
        .open_table(CUSTODY_CONTINUITY)?
        .get(CUSTODY_CONTINUITY_KEY)?
        .map(|value| decode_continuity(value.value()))
        .transpose()?;
    if read.open_table(CUSTODY_CONTINUITY)?.len()? != u64::from(continuity.is_some()) {
        return Err(
            CustodyStoreError::Invariant("custody continuity contains an orphan row").into(),
        );
    }

    let mut items = BTreeMap::new();
    let mut item_count = 0u64;
    let mut total_bytes = 0u64;
    let mut ordinary_item_count = 0u64;
    let mut ordinary_total_bytes = 0u64;
    let mut scope_usages = BTreeMap::<String, CustodyUsage>::new();
    let mut legacy_item_encoding = false;
    for row in read.open_table(CUSTODY_ITEMS)?.iter()? {
        let (key, value) = row?;
        let key = CustodyObjectKey::decode(key.value())?;
        let mut record = decode_item(value.value())?;
        if record.route_only != (key.class == CustodyObjectClass::RouteEvent)
            || continuity.is_some_and(|clock| record.continuity_generation > clock.generation)
        {
            return Err(CustodyStoreError::Invariant(
                "custody item class or generation is invalid",
            )
            .into());
        }
        if is_unanchored_lost_finite(&record) && record.continuity_generation != 0 {
            record.continuity_generation = 0;
            legacy_item_encoding = true;
        }
        validate_item_backing_read(read, key, &record)?;
        item_count = next_counter(item_count)?;
        total_bytes = total_bytes
            .checked_add(record.accounted_bytes)
            .ok_or(CustodyStoreError::CounterOverflow)?;
        if !record.tombstone {
            ordinary_item_count = next_counter(ordinary_item_count)?;
            ordinary_total_bytes = ordinary_total_bytes
                .checked_add(record.accounted_bytes)
                .ok_or(CustodyStoreError::CounterOverflow)?;
            let usage = scope_usages
                .entry(record.scope.as_str().to_owned())
                .or_default();
            usage.items = next_counter(usage.items)?;
            usage.bytes = usage
                .bytes
                .checked_add(record.accounted_bytes)
                .ok_or(CustodyStoreError::CounterOverflow)?;
        }
        items.insert(key, record);
    }
    let (expected_expirations, expected_retiring) = expected_custody_maintenance_indexes(&items)?;
    let mut durable_expirations = BTreeSet::new();
    for row in read.open_table(CUSTODY_EXPIRATIONS)?.iter()? {
        let (key, value) = row?;
        if !value.value().is_empty() {
            return Err(CustodyStoreError::Invariant(
                "custody expiration index value is not empty",
            )
            .into());
        }
        let _ = decode_custody_expiration_key(key.value())?;
        durable_expirations.insert(key.value().to_vec());
    }
    let missing_expirations = expected_expirations
        .difference(&durable_expirations)
        .collect::<Vec<_>>();
    let has_extra_expirations = durable_expirations
        .difference(&expected_expirations)
        .next()
        .is_some();
    let repairable_missing = missing_expirations
        .iter()
        .map(|encoded| is_canonical_lost_sentinel_for(encoded, &items))
        .collect::<Result<Vec<_>, _>>()?
        .into_iter()
        .all(|repairable| repairable);
    if !has_extra_expirations
        && repairable_missing
        && (legacy_item_encoding || !missing_expirations.is_empty())
    {
        return Err(CustodyStoreError::LegacyCustodyMigrationRequired.into());
    }
    if has_extra_expirations || !missing_expirations.is_empty() {
        return Err(CustodyStoreError::Invariant(
            "custody expiration index differs from live items",
        )
        .into());
    }
    let mut durable_retiring = BTreeSet::new();
    let mut retirement_cleanups = BTreeMap::new();
    for row in read.open_table(CUSTODY_RETIRING)?.iter()? {
        let (key, value) = row?;
        let (acceptance_order, object) = decode_custody_retiring_key(key.value())?;
        let cleanup = cleanup_record_for_row(value.value(), items.get(&object))?;
        if retirement_cleanups
            .insert(object, (acceptance_order, cleanup))
            .is_some()
        {
            return Err(CustodyStoreError::Invariant(
                "custody retirement cleanup contains duplicate objects",
            )
            .into());
        }
        durable_retiring.insert(key.value().to_vec());
    }
    if !expected_retiring.is_subset(&durable_retiring) {
        return Err(
            CustodyStoreError::Invariant("custody retiring index omits a marked item").into(),
        );
    }
    let mut durable_scope_usages = BTreeMap::new();
    for row in read.open_table(CUSTODY_SCOPE_USAGE)?.iter()? {
        let (scope, value) = row?;
        let scope = scope.value().to_owned();
        let _ = Scope::new(&scope)
            .map_err(|_| CustodyStoreError::Invariant("custody scope usage key is invalid"))?;
        durable_scope_usages.insert(scope, decode_scope_usage(value.value())?);
    }
    if durable_scope_usages != scope_usages {
        return Err(CustodyStoreError::Invariant(
            "custody scope usage differs from live item accounting",
        )
        .into());
    }
    let mut retirements = BTreeMap::new();
    let mut retired_route_semantics = BTreeMap::<[u8; 32], [u8; 33]>::new();
    for row in read.open_table(CUSTODY_RETIREMENTS)?.iter()? {
        let (key, value) = row?;
        let key = CustodyObjectKey::decode(key.value())?;
        let record = decode_retirement(value.value())?;
        if items.contains_key(&key) {
            return Err(
                CustodyStoreError::Invariant("live and retired custody keys overlap").into(),
            );
        }
        validate_retirement_backing_read(read, key, &record)?;
        if key.class == CustodyObjectClass::RouteEvent {
            retired_route_semantics
                .entry(record.semantic_id)
                .and_modify(|current| *current = (*current).min(key.encoded()))
                .or_insert_with(|| key.encoded());
        }
        retirements.insert(key, record);
    }
    for (object, (acceptance_order, cleanup)) in &retirement_cleanups {
        validate_cleanup_control_state(
            *object,
            *acceptance_order,
            cleanup,
            items.get(object),
            retirements.get(object),
        )?;
    }
    require_unique_event_transfer_state(items.keys().chain(retirements.keys()).copied())?;
    let retirement_count =
        u64::try_from(retirements.len()).map_err(|_| CustodyStoreError::CounterOverflow)?;
    if retirement_count > MAX_CUSTODY_RETIREMENTS {
        return Err(CustodyStoreError::Invariant("custody retirement cap is exceeded").into());
    }
    if retirement_count
        .checked_add(ordinary_item_count)
        .ok_or(CustodyStoreError::CounterOverflow)?
        > MAX_CUSTODY_RETIREMENTS
    {
        return Err(CustodyStoreError::Invariant(
            "live Event rows exceed their permanent retirement-fence reserve",
        )
        .into());
    }
    let mut durable_retired_semantics = BTreeMap::new();
    for row in read.open_table(CUSTODY_RETIRED_SEMANTICS)?.iter()? {
        let (semantic, object) = row?;
        let semantic: [u8; 32] = semantic
            .value()
            .try_into()
            .map_err(|_| CustodyStoreError::Invariant("retired semantic key has invalid length"))?;
        let object = CustodyObjectKey::decode(object.value())?;
        if object.class != CustodyObjectClass::RouteEvent {
            return Err(CustodyStoreError::Invariant(
                "retired semantic index references a non-route object",
            )
            .into());
        }
        durable_retired_semantics.insert(semantic, object.encoded());
    }
    if durable_retired_semantics != retired_route_semantics {
        return Err(CustodyStoreError::Invariant(
            "retired route semantic index differs from permanent fences",
        )
        .into());
    }
    let mut lease_count = 0u64;
    let mut max_lease = 0u64;
    for row in read.open_table(CUSTODY_LEASES)?.iter()? {
        let (id, value) = row?;
        let lease = decode_lease(value.value())?;
        let item = items
            .get(&lease.object)
            .ok_or(CustodyStoreError::Invariant(
                "lease references a missing custody item",
            ))?;
        if item.revision != lease.item_revision || lease.policy_revision > policy_revision {
            return Err(
                CustodyStoreError::Invariant("lease revision differs from its item").into(),
            );
        }
        lease_count = next_counter(lease_count)?;
        max_lease = max_lease.max(id.value());
        require_retirement_reference_read(
            read,
            RETIREMENT_REFERENCE_LEASE,
            lease.object.encoded().as_slice(),
            &id.value().to_be_bytes(),
        )?;
    }
    if lease_count > MAX_CUSTODY_TRANSFER_LEASES || max_lease > next_lease {
        return Err(
            CustodyStoreError::Invariant("custody lease cap or high-water is invalid").into(),
        );
    }
    let mut receipt_count = 0u64;
    let receipts = read.open_table(CUSTODY_PEER_RECEIPTS)?;
    for row in receipts.iter()? {
        let (key, value) = row?;
        let (_, object) = parse_peer_object_key(key.value())?;
        let receipt = decode_receipt(value.value())?;
        let expected_revision = items.get(&object).map(|item| item.revision).or_else(|| {
            retirement_cleanups
                .get(&object)
                .map(|(_, cleanup)| cleanup.original_revision)
        });
        if receipt.item_revision
            != expected_revision.ok_or(CustodyStoreError::Invariant(
                "peer receipt references non-live custody history",
            ))?
        {
            return Err(CustodyStoreError::Invariant(
                "peer receipt revision differs from its custody item",
            )
            .into());
        }
        require_retirement_reference_read(
            read,
            RETIREMENT_REFERENCE_RECEIPT,
            object.encoded().as_slice(),
            key.value(),
        )?;
        receipt_count = next_counter(receipt_count)?;
    }
    if receipt_count > MAX_CUSTODY_PEER_RECEIPTS {
        return Err(CustodyStoreError::Invariant("peer receipt cap is exceeded").into());
    }
    let mut retry_count = 0u64;
    for row in read.open_table(CUSTODY_RETRIES)?.iter()? {
        let (key, value) = row?;
        let (_, object) = parse_peer_object_key(key.value())?;
        let retry = decode_retry(value.value())?;
        let expected = items
            .get(&object)
            .map(|item| (item.revision, item.priority))
            .or_else(|| {
                retirement_cleanups
                    .get(&object)
                    .map(|(_, cleanup)| (cleanup.original_revision, cleanup.priority))
            })
            .ok_or(CustodyStoreError::Invariant(
                "retry references missing custody history",
            ))?;
        if expected.0 != retry.item_revision
            || retry.policy_revision > policy_revision
            || expected.1 != retry.priority
            || receipts.get(key.value())?.is_some()
        {
            return Err(CustodyStoreError::Invariant(
                "retry differs from its custody item or overlaps a receipt",
            )
            .into());
        }
        require_retirement_reference_read(
            read,
            RETIREMENT_REFERENCE_RETRY,
            object.encoded().as_slice(),
            key.value(),
        )?;
        retry_count = next_counter(retry_count)?;
    }
    if retry_count > MAX_CUSTODY_RETRY_RECORDS {
        return Err(CustodyStoreError::Invariant("retry cap is exceeded").into());
    }
    audit_event_retirement_reference_sources_read(read)?;
    audit_retirement_references_read(read)?;
    let mut quotas = BTreeMap::new();
    for row in read.open_table(CUSTODY_QUOTAS)?.iter()? {
        let (key, value) = row?;
        quotas.insert(
            key.value().to_owned(),
            decode_quota(key.value(), value.value())?,
        );
    }
    if quotas.len() > usize::try_from(MAX_CUSTODY_QUOTAS).expect("small quota cap")
        || !quotas.contains_key(GLOBAL_QUOTA_KEY)
    {
        return Err(CustodyStoreError::Invariant("custody quota set is invalid").into());
    }
    require_quota_capacity(
        CustodyUsage {
            items: ordinary_item_count,
            bytes: ordinary_total_bytes,
        },
        quotas.get(GLOBAL_QUOTA_KEY).expect("checked global quota"),
        0,
        0,
    )?;
    let tombstone_usage = selected_tombstone_usage_read(
        read,
        item_count,
        total_bytes,
        ordinary_item_count,
        ordinary_total_bytes,
    )?;
    // Read-only inspection does not have a caller-selected StoreLimits value.
    // Every writable allowance is bounded by the fixed slack, so enforcing the
    // hard maximum still detects any store that could not have been admitted by
    // a valid writer. Writable reopen additionally enforces its exact limits.
    require_quota_capacity(
        tombstone_usage,
        &CustodyQuota {
            scope: None,
            max_items: CUSTODY_EMERGENCY_ITEM_RESERVE,
            max_bytes: CUSTODY_EMERGENCY_BYTE_RESERVE,
        },
        0,
        0,
    )?;
    for (scope, quota) in quotas.iter().filter(|(scope, _)| !scope.is_empty()) {
        let _ = Scope::new(scope)
            .map_err(|_| CustodyStoreError::Invariant("custody quota scope is invalid"))?;
        let usage = scope_usages.get(scope).copied().unwrap_or_default();
        require_quota_capacity(usage, quota, 0, 0)?;
    }
    let quota_count =
        u64::try_from(quotas.len()).map_err(|_| CustodyStoreError::CounterOverflow)?;
    let metadata = read.open_table(CUSTODY_METADATA)?;
    for (field, reconstructed) in [
        (CUSTODY_ITEM_COUNT_KEY, item_count),
        (CUSTODY_TOTAL_BYTES_KEY, total_bytes),
        (CUSTODY_ORDINARY_ITEM_COUNT_KEY, ordinary_item_count),
        (CUSTODY_ORDINARY_TOTAL_BYTES_KEY, ordinary_total_bytes),
        (CUSTODY_RETIREMENT_COUNT_KEY, retirement_count),
        (CUSTODY_LEASE_COUNT_KEY, lease_count),
        (CUSTODY_RECEIPT_COUNT_KEY, receipt_count),
        (CUSTODY_RETRY_COUNT_KEY, retry_count),
        (CUSTODY_QUOTA_COUNT_KEY, quota_count),
    ] {
        let durable = metadata_value(&metadata, field)?;
        if durable != reconstructed {
            return Err(StoreError::AccountingMismatch {
                field,
                durable,
                reconstructed,
            });
        }
    }
    Ok(CustodyStoreStats {
        items: item_count,
        bytes: total_bytes,
        retirements: retirement_count,
        transfer_leases: lease_count,
        peer_receipts: receipt_count,
        retries: retry_count,
        quotas: quota_count,
        policy_revision: CustodyPolicyRevision(policy_revision),
        mutation_revision,
    })
}

pub(crate) fn retired_event_write(
    write: &redb::WriteTransaction,
    transfer_id: EventTransferId,
) -> Result<Option<(EventSemanticId, u64)>, StoreError> {
    if !preflight_custody_schema_write(write)? {
        return Ok(None);
    }
    write
        .open_table(CUSTODY_RETIREMENTS)?
        .get(CustodyObjectKey::event(transfer_id).encoded().as_slice())?
        .map(|value| {
            let record = decode_retirement(value.value())?;
            Ok((
                EventSemanticId::new(record.semantic_id),
                record.acceptance_order,
            ))
        })
        .transpose()
}

pub(crate) fn retired_event_receipt_write(
    write: &redb::WriteTransaction,
    transfer_id: EventTransferId,
) -> Result<Option<(EventSemanticId, u64, CustodyRetirementReason)>, StoreError> {
    if !preflight_custody_schema_write(write)? {
        return Ok(None);
    }
    write
        .open_table(CUSTODY_RETIREMENTS)?
        .get(CustodyObjectKey::event(transfer_id).encoded().as_slice())?
        .map(|value| {
            let record = decode_retirement(value.value())?;
            Ok((
                EventSemanticId::new(record.semantic_id),
                record.acceptance_order,
                record.reason,
            ))
        })
        .transpose()
}

pub(crate) fn retired_event_read(
    read: &redb::ReadTransaction,
    transfer_id: EventTransferId,
) -> Result<Option<(EventSemanticId, u64)>, StoreError> {
    if !custody_schema_present_read(read)? {
        return Ok(None);
    }
    read.open_table(CUSTODY_RETIREMENTS)?
        .get(CustodyObjectKey::event(transfer_id).encoded().as_slice())?
        .map(|value| {
            let record = decode_retirement(value.value())?;
            Ok((
                EventSemanticId::new(record.semantic_id),
                record.acceptance_order,
            ))
        })
        .transpose()
}

pub(crate) fn retired_route_semantic_exists_write(
    write: &redb::WriteTransaction,
    semantic_id: &[u8; 32],
) -> Result<bool, StoreError> {
    if !preflight_custody_schema_write(write)? {
        return Ok(false);
    }
    Ok(write
        .open_table(CUSTODY_RETIRED_SEMANTICS)?
        .get(semantic_id.as_slice())?
        .is_some())
}

pub(crate) fn retired_route_semantic_write(
    write: &redb::WriteTransaction,
    semantic_id: &[u8; 32],
) -> Result<Option<CustodyObjectKey>, StoreError> {
    if !preflight_custody_schema_write(write)? {
        return Ok(None);
    }
    write
        .open_table(CUSTODY_RETIRED_SEMANTICS)?
        .get(semantic_id.as_slice())?
        .map(|value| CustodyObjectKey::decode(value.value()).map_err(StoreError::from))
        .transpose()
}

pub(crate) fn retired_event_receipt_read(
    read: &redb::ReadTransaction,
    transfer_id: EventTransferId,
) -> Result<Option<(EventSemanticId, u64, CustodyRetirementReason)>, StoreError> {
    if !custody_schema_present_read(read)? {
        return Ok(None);
    }
    read.open_table(CUSTODY_RETIREMENTS)?
        .get(CustodyObjectKey::event(transfer_id).encoded().as_slice())?
        .map(|value| {
            let record = decode_retirement(value.value())?;
            Ok((
                EventSemanticId::new(record.semantic_id),
                record.acceptance_order,
                record.reason,
            ))
        })
        .transpose()
}

#[cfg(test)]
mod lower_bound_index_tests {
    use super::*;

    const CLOCK_A: [u8; 16] = [0xa1; 16];
    const CLOCK_B: [u8; 16] = [0xb2; 16];

    fn finite_record(
        cumulative_age_ms: u64,
        checkpoint: Option<CustodySample>,
        continuity_generation: u64,
        continuity_lost: bool,
    ) -> CustodyItemRecord {
        CustodyItemRecord {
            semantic_id: [0x31; 32],
            topic: Topic::new("lower.bound").expect("topic"),
            scope: Scope::new("mission/lower-bound").expect("scope"),
            source_publisher: [0x32; 32],
            key_epoch: 1,
            priority: Priority::Routine,
            ttl_ms: Some(100),
            tombstone: false,
            route_only: false,
            retiring: false,
            continuity_lost,
            protection: CustodyProtection::NONE,
            accounted_bytes: 1,
            cumulative_age_ms,
            checkpoint,
            continuity_generation,
            acceptance_order: 1,
            revision: 1,
        }
    }

    fn apply_evaluation(record: &mut CustodyItemRecord, evaluation: CustodyAgeEvaluation) {
        record.cumulative_age_ms = evaluation.lower_bound_ms;
        record.checkpoint = evaluation.checkpoint;
        record.continuity_generation = evaluation.continuity_generation;
        record.continuity_lost = evaluation.continuity_lost;
    }

    #[test]
    fn custody_lower_bound_index_encodes_lost_anchor_and_sentinel_forms() {
        let key = CustodyObjectKey::new(CustodyObjectClass::Event, [0x41; 32]);

        let unanchored = finite_record(10, None, 0, true);
        let encoded = encode_item(&unanchored).expect("encode lost sentinel");
        assert_eq!(
            decode_item(&encoded).expect("decode lost sentinel"),
            unanchored
        );
        let index = custody_expiration_key(key, &unanchored)
            .expect("index")
            .expect("sentinel");
        assert_eq!(
            decode_custody_expiration_key(&index).expect("decode sentinel"),
            (0, [0; 16], 0, key)
        );

        let anchor = CustodySample {
            clock_id: CLOCK_A,
            tick_ms: 1_000,
        };
        let anchored = finite_record(10, Some(anchor), 7, true);
        let encoded = encode_item(&anchored).expect("encode lost anchor");
        assert_eq!(decode_item(&encoded).expect("decode lost anchor"), anchored);
        let index = custody_expiration_key(key, &anchored)
            .expect("index")
            .expect("deadline");
        assert_eq!(
            decode_custody_expiration_key(&index).expect("decode deadline"),
            (7, CLOCK_A, 1_090, key)
        );

        let mut saturated = anchored.clone();
        saturated.ttl_ms = Some(u64::MAX);
        saturated.cumulative_age_ms = 0;
        let index = custody_expiration_key(key, &saturated)
            .expect("index")
            .expect("saturated deadline");
        assert_eq!(
            decode_custody_expiration_key(&index)
                .expect("decode saturated deadline")
                .2,
            u64::MAX
        );

        let expired = finite_record(100, Some(anchor), 7, true);
        let index = custody_expiration_key(key, &expired)
            .expect("index")
            .expect("immediate deadline");
        assert_eq!(
            decode_custody_expiration_key(&index)
                .expect("decode immediate deadline")
                .2,
            anchor.tick_ms
        );
    }

    #[test]
    fn custody_lower_bound_index_evaluator_reanchors_and_accumulates() {
        let mut record = finite_record(
            10,
            Some(CustodySample {
                clock_id: CLOCK_A,
                tick_ms: 100,
            }),
            1,
            false,
        );
        let continuity = ContinuityRecord {
            generation: 2,
            sample: CustodySample {
                clock_id: CLOCK_B,
                tick_ms: 1_000,
            },
        };

        let evaluation = evaluate_item_age(&record, Some(continuity), Some(continuity.sample))
            .expect("re-anchor evaluation");
        assert_eq!(evaluation.status, CustodyAgeStatus::WithheldUnknownAge);
        assert_eq!(evaluation.lower_bound_ms, 10);
        assert_eq!(evaluation.checkpoint, Some(continuity.sample));
        assert_eq!(evaluation.continuity_generation, 2);
        assert!(evaluation.continuity_lost);
        assert!(evaluation.needs_write);
        apply_evaluation(&mut record, evaluation);

        let later = CustodySample {
            clock_id: CLOCK_B,
            tick_ms: 1_089,
        };
        let evaluation = evaluate_item_age(&record, Some(continuity), Some(later))
            .expect("same-domain evaluation");
        assert_eq!(evaluation.status, CustodyAgeStatus::WithheldUnknownAge);
        assert_eq!(evaluation.lower_bound_ms, 99);
        assert!(evaluation.continuity_lost);
        apply_evaluation(&mut record, evaluation);

        let expired = evaluate_item_age(
            &record,
            Some(continuity),
            Some(CustodySample {
                clock_id: CLOCK_B,
                tick_ms: 1_090,
            }),
        )
        .expect("expiry evaluation");
        assert_eq!(expired.status, CustodyAgeStatus::Expired { age_ms: 100 });
        assert!(expired.continuity_lost);
    }

    #[test]
    fn custody_reanchor_duplicate_merge_is_monotone() {
        let mut record = finite_record(
            10,
            Some(CustodySample {
                clock_id: CLOCK_B,
                tick_ms: 1_000,
            }),
            2,
            true,
        );
        let continuity_b = ContinuityRecord {
            generation: 2,
            sample: CustodySample {
                clock_id: CLOCK_B,
                tick_ms: 1_015,
            },
        };
        assert_eq!(
            merge_authenticated_age(
                &mut record,
                Some(continuity_b),
                Some(CustodySample {
                    clock_id: CLOCK_B,
                    tick_ms: 1_010,
                }),
                8,
            )
            .expect("younger duplicate"),
            (25, false, false)
        );
        assert_eq!(record.checkpoint, Some(continuity_b.sample));
        assert!(record.continuity_lost);

        assert_eq!(
            merge_authenticated_age(
                &mut record,
                Some(continuity_b),
                Some(CustodySample {
                    clock_id: CLOCK_B,
                    tick_ms: 1_014,
                }),
                50,
            )
            .expect("greater duplicate"),
            (50, false, false)
        );
        assert_eq!(record.checkpoint, Some(continuity_b.sample));

        assert_eq!(
            merge_authenticated_age(&mut record, Some(continuity_b), None, 7)
                .expect("missing sample"),
            (50, false, false)
        );
        assert_eq!(record.checkpoint, None);
        assert_eq!(record.continuity_generation, 0);

        let continuity_c = ContinuityRecord {
            generation: 3,
            sample: CustodySample {
                clock_id: [0xc3; 16],
                tick_ms: 5_000,
            },
        };
        merge_authenticated_age(
            &mut record,
            Some(continuity_c),
            Some(continuity_c.sample),
            7,
        )
        .expect("new anchor");
        assert_eq!(record.cumulative_age_ms, 50);
        assert_eq!(record.checkpoint, Some(continuity_c.sample));
        assert!(record.continuity_lost);
    }
}
