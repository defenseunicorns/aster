//! Durable immutable-publication Blob application subscriptions.
//!
//! The store owns only selector, retry, acknowledgement, and monotonic tenure
//! structure. Poll plans carry compact source projections, never sealed source
//! bytes or provider internals. `aster-node` rebinds every candidate to its
//! startup-authenticated projection and current policy, then exact-loads and
//! rechecks each deliverable source envelope and completed depot before
//! supplying the exhaustive deliverable/inactive partition committed here.

use std::collections::{BTreeMap, BTreeSet};

use aster_mesh::{BlobId, NodeId, Scope, Topic};
use redb::{
    MultimapTableHandle, ReadableDatabase, ReadableTable, ReadableTableMetadata, TableDefinition,
    TableHandle,
};
use sha2::{Digest, Sha256};

use super::{BLOB_ACCEPTANCE_MARKERS, BLOB_PUBLICATIONS, LAST_BLOB_ACCEPTANCE_MARKER};
use super::{
    BlobSemanticId, BlobSourceProjection, BlobSubscriptionIdentity, BlobTransferId,
    ControlPolicySnapshot, METADATA, MetadataCursor, Store, StoreError,
    blob_subscription_exact_source_matches_write, blob_subscription_identity_read,
    blob_subscription_identity_write, blob_subscription_projection_matches_write,
    blob_subscription_projection_read, blob_subscription_retirement_generation_read,
    blob_subscription_retirement_read, blob_subscription_retirement_write, enforce_live_write,
    read_mission_binding, read_mission_binding_read, require_blob_publication_visible_write,
    require_control_policy_read, require_control_policy_write,
};

/// Audited inverse of Blob forward acceptance markers used only for bounded scans.
pub(crate) const BLOB_ACCEPTANCE_ORDER: TableDefinition<u64, &[u8]> =
    TableDefinition::new("aster.semantic-blob-acceptance-order.v1");

pub(crate) const BLOB_SUBSCRIPTIONS: TableDefinition<&[u8], &[u8]> =
    TableDefinition::new("aster.semantic-blob-subscriptions.v1");
pub(crate) const BLOB_SUBSCRIPTION_PENDING: TableDefinition<&[u8], &[u8]> =
    TableDefinition::new("aster.semantic-blob-delivery-pending.v1");
pub(crate) const BLOB_DELIVERY_ACKNOWLEDGEMENTS: TableDefinition<&[u8], &[u8]> =
    TableDefinition::new("aster.semantic-blob-delivery-acknowledgements.v1");
pub(crate) const BLOB_DELIVERY_CURSORS: TableDefinition<&[u8], &[u8]> =
    TableDefinition::new("aster.semantic-blob-delivery-cursors.v1");
pub(crate) const BLOB_RETIREMENT_DELIVERIES: TableDefinition<&[u8], &[u8]> =
    TableDefinition::new("aster.semantic-blob-retirement-deliveries.v3");
pub(crate) const BLOB_RETIREMENT_DELIVERY_ORDER: TableDefinition<&[u8], &[u8]> =
    TableDefinition::new("aster.semantic-blob-retirement-delivery-order.v3");
pub(crate) const BLOB_RETIREMENT_ACKNOWLEDGEMENTS: TableDefinition<&[u8], &[u8]> =
    TableDefinition::new("aster.semantic-blob-retirement-acknowledgements.v3");
pub(crate) const BLOB_RETIREMENT_DELIVERY_OWNERS: TableDefinition<&[u8], &[u8]> =
    TableDefinition::new("aster.semantic-blob-retirement-delivery-owners.v3");

pub(crate) const BLOB_SUBSCRIPTION_COUNT: &str = "semantic_blob_subscription_count";
pub(crate) const BLOB_PENDING_DELIVERY_COUNT: &str = "semantic_blob_pending_delivery_count";
pub(crate) const BLOB_ACKNOWLEDGEMENT_COUNT: &str = "semantic_blob_acknowledgement_count";
pub(crate) const BLOB_DELIVERY_CURSOR_COUNT: &str = "semantic_blob_delivery_cursor_count";
pub(crate) const BLOB_SELECTOR_GENERATION: &str = "semantic_blob_selector_generation";
pub(crate) const BLOB_RETIREMENT_DELIVERY_COUNT: &str = "semantic_blob_retirement_delivery_count";
pub(crate) const BLOB_RETIREMENT_DELIVERY_ORDER_COUNT: &str =
    "semantic_blob_retirement_delivery_order_count";
pub(crate) const BLOB_RETIREMENT_ACKNOWLEDGEMENT_COUNT: &str =
    "semantic_blob_retirement_acknowledgement_count";
pub(crate) const BLOB_RETIREMENT_DELIVERY_OWNER_COUNT: &str =
    "semantic_blob_retirement_delivery_owner_count";

const BLOB_SUBSCRIPTION_VERSION: u8 = 1;
const BLOB_PENDING_DELIVERY_VERSION: u8 = 1;
const BLOB_RETIRED_DELIVERY_VERSION: u8 = 2;
const BLOB_ACKNOWLEDGEMENT_VERSION: u8 = 1;
const BLOB_DELIVERY_CURSOR_VERSION: u8 = 1;
const BLOB_DELIVERY_TOKEN_VERSION: u8 = 1;
const BLOB_RETIREMENT_DELIVERY_RECORD_VERSION: u8 = 3;
const BLOB_RETIREMENT_ACKNOWLEDGEMENT_VERSION: u8 = 3;
#[allow(dead_code)]
const BLOB_RETIREMENT_DELIVERY_TOKEN_VERSION: u8 = 2;
const BLOB_SUBSCRIPTION_ID_DOMAIN: &[u8] = b"aster/blob-subscription-id/v1";
const BLOB_DELIVERY_TOKEN_DOMAIN: &[u8] = b"aster/blob-delivery-token/v1";
#[allow(dead_code)]
const BLOB_RETIREMENT_DELIVERY_TOKEN_DOMAIN: &[u8] = b"aster/blob-retirement-delivery-token/v2";
const BLOB_DELIVERY_TOKEN_COUNTER_BYTES: usize = 1 + (3 * 8);
const BLOB_PENDING_DELIVERY_RECORD_BYTES: usize = 1 + 32 + (2 * 8);
const BLOB_RETIREMENT_DELIVERY_KEY_BYTES: usize = 32 + 32 + 8;
const BLOB_RETIREMENT_DELIVERY_ORDER_KEY_BYTES: usize = 32 + 8 + 32 + 8;
const BLOB_RETIREMENT_DELIVERY_RECORD_BYTES: usize = 1 + (3 * 8) + 1;
#[allow(dead_code)]
const BLOB_RETIREMENT_ACKNOWLEDGEMENT_BYTES: usize = 1 + (2 * 8);

/// Maximum byte length of one durable Blob subscription operation key.
pub const MAX_BLOB_SUBSCRIPTION_KEY_BYTES: usize = 256;
/// Maximum durable Blob application subscriptions in one mission-bound store.
pub const MAX_BLOB_SUBSCRIPTIONS: u64 = 256;
/// Maximum immutable Blob publication attempts returned by one poll.
pub const MAX_BLOB_POLL_DELIVERIES: usize = 128;
/// Maximum matching retained Blob versions freshly verified by one poll.
pub const MAX_BLOB_SUBSCRIPTION_SCAN: usize = 4_096;
/// Dedicated hard cap for unacknowledged Blob delivery attempts.
pub const MAX_BLOB_PENDING_DELIVERIES: u64 = 262_144;
/// Hard cap for durable idempotent Blob acknowledgement receipts.
pub const MAX_BLOB_ACKNOWLEDGEMENT_RECEIPTS: u64 = 262_144;
/// Hard cap for durable monotonic per-Blob delivery cursors.
pub const MAX_BLOB_DELIVERY_CURSORS: u64 = 262_144;
/// Canonical byte length of one opaque Blob delivery acknowledgement token.
pub const BLOB_DELIVERY_TOKEN_BYTES: usize = BLOB_DELIVERY_TOKEN_COUNTER_BYTES + 32;

/// Stable mission-local identity of one durable Blob application subscription.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct BlobSubscriptionId([u8; 32]);

impl BlobSubscriptionId {
    /// Constructs an identifier from complete durable bytes.
    pub const fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// Returns the complete durable identifier bytes.
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

/// Bounded application idempotency key for one Blob subscription.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct BlobSubscriptionKey(Vec<u8>);

impl BlobSubscriptionKey {
    /// Validates one nonempty durable subscription key.
    pub fn new(bytes: impl Into<Vec<u8>>) -> Result<Self, StoreError> {
        let bytes = bytes.into();
        if bytes.is_empty() || bytes.len() > MAX_BLOB_SUBSCRIPTION_KEY_BYTES {
            return Err(StoreError::InvalidBlobSubscriptionKey {
                length: bytes.len(),
            });
        }
        Ok(Self(bytes))
    }

    /// Returns the exact durable operation-key bytes.
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

/// One durable Blob application-delivery selector.
///
/// This is local intent, never route or content authority.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct BlobSubscriptionSpec {
    /// Exact selected topic.
    pub topic: Topic,
    /// Exact selected scope or ancestor scope when descendants are enabled.
    pub scope: Scope,
    /// Whether descendant scopes are included in addition to the exact scope.
    pub include_descendant_scopes: bool,
}

impl BlobSubscriptionSpec {
    pub(crate) fn matches(&self, projection: &BlobSourceProjection) -> bool {
        self.matches_topic_scope(&projection.topic, &projection.scope)
    }

    fn matches_topic_scope(&self, topic: &Topic, scope: &Scope) -> bool {
        &self.topic == topic
            && if self.include_descendant_scopes {
                self.scope.contains(scope)
            } else {
                &self.scope == scope
            }
    }

    fn matches_identity(&self, identity: &BlobSubscriptionIdentity) -> bool {
        self.matches_topic_scope(&identity.topic, &identity.scope)
    }
}

/// Result of idempotently creating one durable Blob subscription.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BlobSubscriptionCreateOutcome {
    /// Stable mission-local subscription identity.
    pub id: BlobSubscriptionId,
    /// True only when this call inserted the durable row.
    pub inserted: bool,
}

/// Result of idempotently removing one Blob selector and its ledgers.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BlobSubscriptionRemoveOutcome {
    /// Stable identity supplied by the caller.
    pub id: BlobSubscriptionId,
    /// True only when this call removed durable blob.
    pub removed: bool,
}

/// One complete-snapshot Blob candidate requiring fresh verification.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BlobSubscriptionCandidate {
    projection: BlobSourceProjection,
    acceptance_marker: u64,
    pending_attempt: Option<u64>,
    acknowledged_attempt: Option<u64>,
    delivery_cursor: Option<BlobDeliveryCursorRecord>,
}

impl BlobSubscriptionCandidate {
    /// Compact authenticated-source claim requiring exact privileged verification.
    pub const fn projection(&self) -> &BlobSourceProjection {
        &self.projection
    }

    /// Stable marker ordering this immutable publication.
    pub const fn acceptance_marker(&self) -> u64 {
        self.acceptance_marker
    }

    /// Previously committed unacknowledged attempt, when any.
    pub const fn pending_attempt(&self) -> Option<u64> {
        self.pending_attempt
    }

    /// Durable acknowledgement attempt, when this exact version was acknowledged.
    pub const fn acknowledged_attempt(&self) -> Option<u64> {
        self.acknowledged_attempt
    }

    /// Highest attempt committed in this publication's most recent visibility tenure.
    pub const fn last_delivery_attempt(&self) -> Option<u64> {
        match self.delivery_cursor {
            Some(cursor) => Some(cursor.last_attempt),
            None => None,
        }
    }

    /// Monotonic active-delivery tenure last allocated to this publication.
    pub const fn delivery_tenure(&self) -> Option<u64> {
        match self.delivery_cursor {
            Some(cursor) => Some(cursor.tenure),
            None => None,
        }
    }
}

/// Complete bounded matching-Blob snapshot prepared for privileged verification.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BlobSubscriptionPollPlan {
    policy: ControlPolicySnapshot,
    subscription: BlobSubscriptionId,
    spec: BlobSubscriptionSpec,
    incarnation: u64,
    selector_generation: u64,
    candidates: Vec<BlobSubscriptionCandidate>,
    delivery_limit: usize,
    scan_limit: usize,
}

impl BlobSubscriptionPollPlan {
    /// Stable identity of the planned subscription.
    pub const fn subscription(&self) -> BlobSubscriptionId {
        self.subscription
    }

    /// Exact durable selector observed by the plan transaction.
    pub const fn spec(&self) -> &BlobSubscriptionSpec {
        &self.spec
    }

    /// Durable selector mutation generation observed by the plan.
    pub const fn selector_generation(&self) -> u64 {
        self.selector_generation
    }

    /// Monotonic tenure of this stable subscription identity.
    pub const fn incarnation(&self) -> u64 {
        self.incarnation
    }

    /// Acceptance-marker ordered complete matching snapshot.
    pub fn candidates(&self) -> &[BlobSubscriptionCandidate] {
        &self.candidates
    }
}

/// Privileged freshly verified partition of one complete Blob poll snapshot.
///
/// Every candidate semantic ID must appear exactly once. The store rechecks
/// exact durable structure; `aster-node` owns source/content, settled-policy,
/// and completed-depot verification before constructing this value.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct BlobSubscriptionPollSelection {
    /// Freshly verified publications that are active and depot-complete.
    pub deliverable: Vec<BlobSemanticId>,
    /// Freshly verified revoked, stale-epoch, incomplete, or otherwise inactive publications.
    pub inactive: Vec<BlobSemanticId>,
}

/// One at-least-once immutable-publication delivery committed before application return.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BlobSubscriptionDelivery {
    /// Exact source-authenticated publication identity.
    pub semantic_id: BlobSemanticId,
    /// Stable acceptance marker for deterministic application ordering.
    pub acceptance_marker: u64,
    /// Nonzero durable delivery-attempt number.
    pub attempt: u64,
    /// Opaque durable acknowledgement token for this exact delivery tenure and attempt.
    pub token: BlobDeliveryToken,
}

/// Opaque activation-safe acknowledgement identity for one committed Blob delivery.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct BlobDeliveryToken([u8; BLOB_DELIVERY_TOKEN_BYTES]);

impl BlobDeliveryToken {
    /// Reconstructs one canonical opaque token transported by the application boundary.
    ///
    /// Its subscription and Blob binding is revalidated by acknowledgement.
    pub fn from_bytes(bytes: [u8; BLOB_DELIVERY_TOKEN_BYTES]) -> Result<Self, StoreError> {
        let token = Self(bytes);
        let counters_valid =
            token.incarnation() != 0 && token.tenure() != 0 && token.attempt() != 0;
        let version_valid = token.0[0] == BLOB_DELIVERY_TOKEN_VERSION
            || (token.0[0] == BLOB_RETIREMENT_DELIVERY_TOKEN_VERSION && token.attempt() >= 2);
        if !counters_valid || !version_valid {
            return Err(StoreError::InvalidBlobDeliveryToken);
        }
        Ok(token)
    }

    #[doc(hidden)]
    pub const fn is_retirement(self) -> bool {
        self.0[0] == BLOB_RETIREMENT_DELIVERY_TOKEN_VERSION
    }

    #[allow(dead_code)]
    pub(crate) fn from_retirement_bytes(
        bytes: [u8; BLOB_DELIVERY_TOKEN_BYTES],
    ) -> Result<Self, StoreError> {
        let token = Self(bytes);
        if token.0[0] != BLOB_RETIREMENT_DELIVERY_TOKEN_VERSION
            || token.incarnation() == 0
            || token.tenure() == 0
            || token.attempt() < 2
        {
            return Err(StoreError::InvalidBlobDeliveryToken);
        }
        Ok(token)
    }

    /// Returns the complete canonical opaque token bytes.
    pub const fn as_bytes(&self) -> &[u8; BLOB_DELIVERY_TOKEN_BYTES] {
        &self.0
    }

    pub(crate) fn incarnation(self) -> u64 {
        u64::from_be_bytes(
            self.0[1..9]
                .try_into()
                .expect("fixed Blob delivery-token incarnation"),
        )
    }

    pub(crate) fn tenure(self) -> u64 {
        u64::from_be_bytes(
            self.0[9..17]
                .try_into()
                .expect("fixed Blob delivery-token tenure"),
        )
    }

    pub(crate) fn attempt(self) -> u64 {
        u64::from_be_bytes(
            self.0[17..25]
                .try_into()
                .expect("fixed Blob delivery-token attempt"),
        )
    }
}

/// Result of one complete-snapshot Blob subscription poll commit.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct BlobSubscriptionDeliveryPage {
    /// Pending-first, marker-ordered attempts committed before return.
    pub deliveries: Vec<BlobSubscriptionDelivery>,
    /// True when additional unacknowledged deliverable publications remain.
    pub has_more: bool,
}

/// Stable public projection of one authenticated Blob retirement reason.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BlobRetirementReason {
    Expired,
    Invalidated,
    Evicted,
}

impl From<super::blob::lifecycle::RetirementReason> for BlobRetirementReason {
    fn from(reason: super::blob::lifecycle::RetirementReason) -> Self {
        match reason {
            super::blob::lifecycle::RetirementReason::Expired => Self::Expired,
            super::blob::lifecycle::RetirementReason::Invalidated => Self::Invalidated,
            super::blob::lifecycle::RetirementReason::Evicted => Self::Evicted,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
#[doc(hidden)]
pub struct BlobRetirementPollPlan {
    policy: ControlPolicySnapshot,
    subscription: BlobSubscriptionId,
    incarnation: u64,
    delivery_limit: usize,
    candidates: Vec<BlobRetirementPollCandidate>,
}

#[allow(dead_code)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct BlobRetirementPollCandidate {
    semantic_id: BlobSemanticId,
    retirement_generation: u64,
    acceptance_marker: u64,
    current_attempt: u64,
    reason: super::blob::lifecycle::RetirementReason,
}

#[derive(Clone, Debug, Eq, PartialEq)]
#[doc(hidden)]
pub struct BlobRetirementDelivery {
    pub(crate) semantic_id: BlobSemanticId,
    pub(crate) blob_id: BlobId,
    pub(crate) publisher: aster_mesh::NodeId,
    pub(crate) publisher_counter: u64,
    pub(crate) topic: aster_mesh::Topic,
    pub(crate) scope: aster_mesh::Scope,
    pub(crate) priority: aster_mesh::Priority,
    pub(crate) ttl_ms: Option<u64>,
    pub(crate) acceptance_marker: u64,
    pub(crate) subscription_incarnation: u64,
    pub(crate) retirement_generation: u64,
    pub(crate) attempt: u64,
    pub(crate) reason: super::blob::lifecycle::RetirementReason,
    pub(crate) token: BlobDeliveryToken,
}

impl BlobRetirementDelivery {
    pub const fn semantic_id(&self) -> BlobSemanticId {
        self.semantic_id
    }
    pub const fn blob_id(&self) -> BlobId {
        self.blob_id
    }
    pub const fn publisher(&self) -> aster_mesh::NodeId {
        self.publisher
    }
    pub const fn publisher_counter(&self) -> u64 {
        self.publisher_counter
    }
    pub const fn topic(&self) -> &aster_mesh::Topic {
        &self.topic
    }
    pub const fn scope(&self) -> &aster_mesh::Scope {
        &self.scope
    }
    pub const fn priority(&self) -> aster_mesh::Priority {
        self.priority
    }
    pub const fn ttl_ms(&self) -> Option<u64> {
        self.ttl_ms
    }
    pub const fn acceptance_marker(&self) -> u64 {
        self.acceptance_marker
    }
    pub const fn retirement_generation(&self) -> u64 {
        self.retirement_generation
    }
    pub const fn attempt(&self) -> u64 {
        self.attempt
    }
    pub fn reason(&self) -> BlobRetirementReason {
        self.reason.into()
    }
    pub const fn token(&self) -> BlobDeliveryToken {
        self.token
    }
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
#[doc(hidden)]
pub struct BlobRetirementDeliveryPage {
    pub deliveries: Vec<BlobRetirementDelivery>,
    pub has_more: bool,
}

/// Idempotent acknowledgement result for one semantic Blob delivery.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BlobDeliveryAck {
    /// This call atomically replaced a pending attempt with a receipt.
    Acknowledged,
    /// An exact durable acknowledgement receipt already exists.
    AlreadyAcknowledged,
}

/// Consistent durable counts for Blob selectors and deliveries.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct BlobSubscriptionStats {
    /// Durable Blob application selectors.
    pub subscriptions: u64,
    /// Unacknowledged attempted Blob publication deliveries.
    pub pending_deliveries: u64,
    /// Durable receipts for publications still active in their committed classification.
    pub acknowledged_deliveries: u64,
    /// Durable monotonic per-Blob delivery cursors, including retired tenures.
    pub delivery_cursors: u64,
    /// Mutation generation advanced by each actual insert or removal.
    pub selector_generation: u64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct BlobSubscriptionRecord {
    operation_key: BlobSubscriptionKey,
    spec: BlobSubscriptionSpec,
    incarnation: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct BlobPendingDeliveryRecord {
    semantic_id: BlobSemanticId,
    tenure: u64,
    attempts: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct BlobRetiredDeliveryRecord {
    semantic_id: BlobSemanticId,
    retirement_generation: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct BlobRetirementDeliveryRecord {
    subscription_incarnation: u64,
    acceptance_marker: u64,
    current_attempt: u64,
    reason: super::blob::lifecycle::RetirementReason,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct BlobRetirementAcknowledgementRecord {
    retirement_generation: u64,
    acknowledged_attempt: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum BlobDeliveryRecord {
    Pending(BlobPendingDeliveryRecord),
    Retired(BlobRetiredDeliveryRecord),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct BlobAcknowledgementRecord {
    acceptance_marker: u64,
    tenure: u64,
    attempts: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct BlobDeliveryCursorRecord {
    acceptance_marker: u64,
    tenure: u64,
    last_attempt: u64,
    last_acknowledged_tenure: u64,
    last_acknowledged_attempt: u64,
}

impl Store {
    /// Returns structurally audited Blob subscription counts.
    pub fn blob_subscription_stats(&self) -> Result<BlobSubscriptionStats, StoreError> {
        self.require_bound_mission()?;
        let read = self.database.begin_read()?;
        inspect_blob_subscription_tables(&read)
    }

    /// Idempotently creates one durable Blob application selector.
    pub fn create_blob_subscription_with_policy(
        &self,
        policy: &ControlPolicySnapshot,
        key: &BlobSubscriptionKey,
        spec: BlobSubscriptionSpec,
    ) -> Result<BlobSubscriptionCreateOutcome, StoreError> {
        self.require_live()?;
        let authority = self.require_bound_mission()?;
        let id = blob_subscription_id(authority, key);
        let write = self.database.begin_write()?;
        enforce_live_write(&write)?;
        require_control_policy_write(&write, authority, policy)?;
        let existing = write
            .open_table(BLOB_SUBSCRIPTIONS)?
            .get(id.as_bytes().as_slice())?
            .map(|value| decode_blob_subscription_record(value.value()))
            .transpose()?;
        if let Some(existing) = existing {
            if existing.operation_key != *key || existing.spec != spec {
                return Err(StoreError::BlobSubscriptionConflict);
            }
            return Ok(BlobSubscriptionCreateOutcome {
                id,
                inserted: false,
            });
        }

        let current_count = write.open_table(BLOB_SUBSCRIPTIONS)?.len()?;
        if current_count >= MAX_BLOB_SUBSCRIPTIONS {
            return Err(StoreError::BlobSubscriptionLimitExceeded {
                current: current_count,
                limit: MAX_BLOB_SUBSCRIPTIONS,
            });
        }
        let (durable_count, generation) = {
            let metadata = write.open_table(METADATA)?;
            let count = metadata
                .get(BLOB_SUBSCRIPTION_COUNT)?
                .ok_or(StoreError::MissingAccountingMetadata {
                    field: BLOB_SUBSCRIPTION_COUNT,
                })?
                .value();
            let generation = metadata
                .get(BLOB_SELECTOR_GENERATION)?
                .ok_or(StoreError::MissingAccountingMetadata {
                    field: BLOB_SELECTOR_GENERATION,
                })?
                .value();
            (count, generation)
        };
        if durable_count != current_count {
            return Err(StoreError::AccountingMismatch {
                field: BLOB_SUBSCRIPTION_COUNT,
                durable: durable_count,
                reconstructed: current_count,
            });
        }
        validate_blob_selector_generation(generation, current_count)?;
        let incarnation = generation
            .checked_add(1)
            .ok_or(StoreError::ItemCountAccountingOverflow)?;
        let record = BlobSubscriptionRecord {
            operation_key: key.clone(),
            spec,
            incarnation,
        };
        let encoded = encode_blob_subscription_record(&record)?;
        write
            .open_table(BLOB_SUBSCRIPTIONS)?
            .insert(id.as_bytes().as_slice(), encoded.as_slice())?;
        {
            let mut metadata = write.open_table(METADATA)?;
            metadata.insert(
                BLOB_SUBSCRIPTION_COUNT,
                current_count
                    .checked_add(1)
                    .ok_or(StoreError::ItemCountAccountingOverflow)?,
            )?;
            metadata.insert(BLOB_SELECTOR_GENERATION, incarnation)?;
        }
        write.commit()?;
        Ok(BlobSubscriptionCreateOutcome { id, inserted: true })
    }

    /// Idempotently removes one Blob selector and all delivery evidence.
    pub fn remove_blob_subscription_with_policy(
        &self,
        policy: &ControlPolicySnapshot,
        id: BlobSubscriptionId,
    ) -> Result<BlobSubscriptionRemoveOutcome, StoreError> {
        self.require_live()?;
        let authority = self.require_bound_mission()?;
        let write = self.database.begin_write()?;
        enforce_live_write(&write)?;
        require_control_policy_write(&write, authority, policy)?;
        let record = write
            .open_table(BLOB_SUBSCRIPTIONS)?
            .get(id.as_bytes().as_slice())?
            .map(|value| decode_blob_subscription_record(value.value()))
            .transpose()?;
        let Some(record) = record else {
            return Ok(BlobSubscriptionRemoveOutcome { id, removed: false });
        };
        if blob_subscription_id(authority, &record.operation_key) != id {
            return Err(StoreError::BlobInvariant(
                "Blob subscription identifier differs from its operation key",
            ));
        }

        let subscription_count = write.open_table(BLOB_SUBSCRIPTIONS)?.len()?;
        let pending_count = write.open_table(BLOB_SUBSCRIPTION_PENDING)?.len()?;
        let acknowledgement_count = write.open_table(BLOB_DELIVERY_ACKNOWLEDGEMENTS)?.len()?;
        let cursor_count = write.open_table(BLOB_DELIVERY_CURSORS)?.len()?;
        let generation = require_blob_subscription_accounting(
            &write,
            subscription_count,
            pending_count,
            acknowledgement_count,
            cursor_count,
        )?;

        let mut pending_removals = Vec::new();
        for row in write.open_table(BLOB_SUBSCRIPTION_PENDING)?.iter()? {
            let (key, value) = row?;
            let (row_subscription, _) = parse_blob_pending_delivery_key(key.value())?;
            if row_subscription == id {
                let delivery = decode_blob_delivery_record(value.value())?;
                let semantic_id = match delivery {
                    BlobDeliveryRecord::Pending(record) => record.semantic_id,
                    BlobDeliveryRecord::Retired(record) => record.semantic_id,
                };
                let owner = blob_subscription_identity_write(&write, semantic_id)?
                    .ok_or(StoreError::BlobInvariant(
                        "pending Blob delivery references a missing Blob",
                    ))?
                    .transfer_id;
                pending_removals.push((key.value().to_vec(), owner));
            }
        }
        let mut acknowledgement_removals = Vec::new();
        for row in write.open_table(BLOB_DELIVERY_ACKNOWLEDGEMENTS)?.iter()? {
            let (key, value) = row?;
            let (row_subscription, _) = parse_blob_acknowledgement_key(key.value())?;
            if row_subscription == id {
                decode_blob_acknowledgement_record(value.value())?;
                acknowledgement_removals.push(key.value().to_vec());
            }
        }
        let mut cursor_removals = Vec::new();
        for row in write.open_table(BLOB_DELIVERY_CURSORS)?.iter()? {
            let (key, value) = row?;
            let (row_subscription, _) = parse_blob_delivery_cursor_key(key.value())?;
            if row_subscription == id {
                decode_blob_delivery_cursor_record(value.value())?;
                cursor_removals.push(key.value().to_vec());
            }
        }
        let mut retirement_primary_removals = Vec::new();
        for row in write.open_table(BLOB_RETIREMENT_DELIVERIES)?.iter()? {
            let (key, value) = row?;
            let primary: [u8; 72] = key.value().try_into().map_err(|_| {
                StoreError::BlobInvariant("Blob retirement-delivery key has invalid length")
            })?;
            let (row_subscription, semantic, generation) =
                parse_blob_retirement_delivery_key(&primary)?;
            if row_subscription == id {
                let delivery = decode_blob_retirement_delivery_record(value.value())?;
                let identity = blob_subscription_identity_write(&write, semantic)?.ok_or(
                    StoreError::BlobInvariant(
                        "Blob retirement delivery references missing publication evidence",
                    ),
                )?;
                retirement_primary_removals.push((
                    primary,
                    blob_retirement_delivery_order_key(
                        id,
                        delivery.acceptance_marker,
                        semantic,
                        generation,
                    ),
                    blob_retirement_delivery_owner_key(identity.transfer_id, &primary),
                ));
            }
        }
        let mut retirement_receipt_removals = Vec::new();
        for row in write.open_table(BLOB_RETIREMENT_ACKNOWLEDGEMENTS)?.iter()? {
            let (key, value) = row?;
            let primary: [u8; 72] = key.value().try_into().map_err(|_| {
                StoreError::BlobInvariant("Blob retirement-acknowledgement key has invalid length")
            })?;
            let (row_subscription, semantic, _) = parse_blob_retirement_delivery_key(&primary)?;
            if row_subscription == id {
                decode_blob_retirement_acknowledgement_record(value.value())?;
                let identity = blob_subscription_identity_write(&write, semantic)?.ok_or(
                    StoreError::BlobInvariant(
                        "Blob retirement acknowledgement references missing publication evidence",
                    ),
                )?;
                retirement_receipt_removals.push((
                    primary,
                    blob_retirement_delivery_owner_key(identity.transfer_id, &primary),
                ));
            }
        }
        {
            let mut pending = write.open_table(BLOB_SUBSCRIPTION_PENDING)?;
            for (key, _) in &pending_removals {
                pending.remove(key.as_slice())?;
            }
        }
        for (key, owner) in &pending_removals {
            super::blob::lifecycle::remove_delivery_owner(&write, *owner, key)?;
        }
        {
            let mut acknowledgements = write.open_table(BLOB_DELIVERY_ACKNOWLEDGEMENTS)?;
            for key in &acknowledgement_removals {
                acknowledgements.remove(key.as_slice())?;
            }
        }
        {
            let mut cursors = write.open_table(BLOB_DELIVERY_CURSORS)?;
            for key in &cursor_removals {
                cursors.remove(key.as_slice())?;
            }
        }
        for (primary, order, owner) in &retirement_primary_removals {
            if write
                .open_table(BLOB_RETIREMENT_DELIVERIES)?
                .remove(primary.as_slice())?
                .is_none()
                || write
                    .open_table(BLOB_RETIREMENT_DELIVERY_ORDER)?
                    .remove(order.as_slice())?
                    .is_none()
                || write
                    .open_table(BLOB_RETIREMENT_DELIVERY_OWNERS)?
                    .remove(owner.as_slice())?
                    .is_none()
            {
                return Err(StoreError::BlobInvariant(
                    "Blob retirement delivery disappeared during subscription removal",
                ));
            }
        }
        for (receipt, owner) in &retirement_receipt_removals {
            if write
                .open_table(BLOB_RETIREMENT_ACKNOWLEDGEMENTS)?
                .remove(receipt.as_slice())?
                .is_none()
                || write
                    .open_table(BLOB_RETIREMENT_DELIVERY_OWNERS)?
                    .remove(owner.as_slice())?
                    .is_none()
            {
                return Err(StoreError::BlobInvariant(
                    "Blob retirement acknowledgement disappeared during subscription removal",
                ));
            }
        }
        if write
            .open_table(BLOB_SUBSCRIPTIONS)?
            .remove(id.as_bytes().as_slice())?
            .is_none()
        {
            return Err(StoreError::BlobInvariant(
                "Blob subscription disappeared during its write transaction",
            ));
        }
        let removed_cursors = u64::try_from(cursor_removals.len())
            .map_err(|_| StoreError::ItemCountAccountingOverflow)?;
        let retirement_after = blob_retirement_ledger_counts_write(&write)?;
        let pending_after = write.open_table(BLOB_SUBSCRIPTION_PENDING)?.len()?;
        let acknowledgements_after = write.open_table(BLOB_DELIVERY_ACKNOWLEDGEMENTS)?.len()?;
        {
            let mut metadata = write.open_table(METADATA)?;
            metadata.insert(
                BLOB_SUBSCRIPTION_COUNT,
                subscription_count
                    .checked_sub(1)
                    .ok_or(StoreError::BlobInvariant(
                        "Blob subscription counter underflow",
                    ))?,
            )?;
            metadata.insert(
                BLOB_PENDING_DELIVERY_COUNT,
                pending_after
                    .checked_add(retirement_after.deliveries)
                    .ok_or(StoreError::ItemCountAccountingOverflow)?,
            )?;
            metadata.insert(
                BLOB_ACKNOWLEDGEMENT_COUNT,
                acknowledgements_after
                    .checked_add(retirement_after.acknowledgements)
                    .ok_or(StoreError::ItemCountAccountingOverflow)?,
            )?;
            metadata.insert(
                BLOB_DELIVERY_CURSOR_COUNT,
                cursor_count
                    .checked_sub(removed_cursors)
                    .ok_or(StoreError::BlobInvariant(
                        "Blob delivery-cursor counter underflow",
                    ))?,
            )?;
            metadata.insert(
                BLOB_SELECTOR_GENERATION,
                generation
                    .checked_add(1)
                    .ok_or(StoreError::ItemCountAccountingOverflow)?,
            )?;
            metadata.insert(BLOB_RETIREMENT_DELIVERY_COUNT, retirement_after.deliveries)?;
            metadata.insert(BLOB_RETIREMENT_DELIVERY_ORDER_COUNT, retirement_after.order)?;
            metadata.insert(
                BLOB_RETIREMENT_ACKNOWLEDGEMENT_COUNT,
                retirement_after.acknowledgements,
            )?;
            metadata.insert(
                BLOB_RETIREMENT_DELIVERY_OWNER_COUNT,
                retirement_after.owners,
            )?;
        }
        write.commit()?;
        Ok(BlobSubscriptionRemoveOutcome { id, removed: true })
    }

    /// Prepares a complete bounded matching-Blob snapshot for fresh verification.
    pub fn prepare_blob_subscription_poll_with_policy(
        &self,
        policy: &ControlPolicySnapshot,
        subscription: BlobSubscriptionId,
        delivery_limit: usize,
        scan_limit: usize,
    ) -> Result<BlobSubscriptionPollPlan, StoreError> {
        self.require_live()?;
        let authority = self.require_bound_mission()?;
        validate_blob_poll_limits(delivery_limit, scan_limit)?;
        let read = self.database.begin_read()?;
        require_control_policy_read(&read, authority, policy)?;
        let record = read
            .open_table(BLOB_SUBSCRIPTIONS)?
            .get(subscription.as_bytes().as_slice())?
            .map(|value| decode_blob_subscription_record(value.value()))
            .transpose()?
            .ok_or(StoreError::BlobSubscriptionNotFound)?;
        let selector_generation = read
            .open_table(METADATA)?
            .get(BLOB_SELECTOR_GENERATION)?
            .ok_or(StoreError::MissingAccountingMetadata {
                field: BLOB_SELECTOR_GENERATION,
            })?
            .value();
        let subscription_count = read.open_table(BLOB_SUBSCRIPTIONS)?.len()?;
        validate_blob_selector_generation(selector_generation, subscription_count)?;
        let candidates =
            blob_subscription_candidates_read(&read, subscription, &record.spec, scan_limit)?;
        Ok(BlobSubscriptionPollPlan {
            policy: *policy,
            subscription,
            spec: record.spec,
            incarnation: record.incarnation,
            selector_generation,
            candidates,
            delivery_limit,
            scan_limit,
        })
    }

    /// Commits one exact freshly verified deliverable/inactive partition.
    pub fn commit_blob_subscription_poll_with_policy(
        &self,
        policy: &ControlPolicySnapshot,
        plan: &BlobSubscriptionPollPlan,
        selection: &BlobSubscriptionPollSelection,
    ) -> Result<BlobSubscriptionDeliveryPage, StoreError> {
        self.require_live()?;
        let authority = self.require_bound_mission()?;
        validate_blob_poll_limits(plan.delivery_limit, plan.scan_limit)?;
        if policy != &plan.policy || plan.candidates.len() > plan.scan_limit {
            return Err(StoreError::BlobSubscriptionPlanChanged);
        }
        let partition = validate_blob_selection(plan, selection)?;

        let write = self.database.begin_write()?;
        enforce_live_write(&write)?;
        require_control_policy_write(&write, authority, policy)?;
        let record = write
            .open_table(BLOB_SUBSCRIPTIONS)?
            .get(plan.subscription.as_bytes().as_slice())?
            .map(|value| decode_blob_subscription_record(value.value()))
            .transpose()?
            .ok_or(StoreError::BlobSubscriptionNotFound)?;
        let generation = write
            .open_table(METADATA)?
            .get(BLOB_SELECTOR_GENERATION)?
            .ok_or(StoreError::MissingAccountingMetadata {
                field: BLOB_SELECTOR_GENERATION,
            })?
            .value();
        if record.spec != plan.spec
            || record.incarnation != plan.incarnation
            || generation != plan.selector_generation
        {
            return Err(StoreError::BlobSelectorGenerationChanged);
        }
        let mut retirement_start = [0u8; BLOB_RETIREMENT_DELIVERY_ORDER_KEY_BYTES];
        retirement_start[..32].copy_from_slice(plan.subscription.as_bytes());
        let mut retirement_end = [0xff; BLOB_RETIREMENT_DELIVERY_ORDER_KEY_BYTES];
        retirement_end[..32].copy_from_slice(plan.subscription.as_bytes());
        let retirement_order = write.open_table(BLOB_RETIREMENT_DELIVERY_ORDER)?;
        let pending_retirement = {
            let mut rows = retirement_order.range::<&[u8]>((
                std::ops::Bound::Included(retirement_start.as_slice()),
                std::ops::Bound::Included(retirement_end.as_slice()),
            ))?;
            rows.next().transpose()?.map(|(key, value)| {
                if !value.value().is_empty() {
                    return Err(StoreError::BlobInvariant(
                        "Blob retirement-delivery order value is not empty",
                    ));
                }
                let (subscription, _, _, _) =
                    parse_blob_retirement_delivery_order_key(key.value())?;
                if subscription != plan.subscription {
                    return Err(StoreError::BlobInvariant(
                        "Blob retirement-delivery order escaped its subscription prefix",
                    ));
                }
                Ok(())
            })
        };
        if let Some(result) = pending_retirement {
            result?;
            return Err(StoreError::BlobSubscriptionPlanChanged);
        }
        drop(retirement_order);
        let durable_candidates = blob_subscription_candidates_write(
            &write,
            plan.subscription,
            &record.spec,
            plan.scan_limit,
            &plan.candidates,
        )?;
        if durable_candidates != plan.candidates {
            return Err(StoreError::BlobSubscriptionPlanChanged);
        }

        let subscription_count = write.open_table(BLOB_SUBSCRIPTIONS)?.len()?;
        let pending_count = write.open_table(BLOB_SUBSCRIPTION_PENDING)?.len()?;
        let acknowledgement_count = write.open_table(BLOB_DELIVERY_ACKNOWLEDGEMENTS)?.len()?;
        let cursor_count = write.open_table(BLOB_DELIVERY_CURSORS)?.len()?;
        require_blob_subscription_accounting(
            &write,
            subscription_count,
            pending_count,
            acknowledgement_count,
            cursor_count,
        )?;
        let retirement_counts = blob_retirement_ledger_counts_write(&write)?;

        let mut retire_pending = Vec::new();
        let mut retire_acknowledgements = Vec::new();
        let mut pending_deliverable = Vec::new();
        let mut new_deliverable = Vec::new();
        for candidate in &durable_candidates {
            let id = candidate.projection.semantic_id;
            if !partition.deliverable.contains(&id) {
                if candidate.pending_attempt.is_some() {
                    retire_pending.push(candidate);
                }
                if candidate.acknowledged_attempt.is_some() {
                    retire_acknowledgements.push(candidate);
                }
                continue;
            }
            if candidate.acknowledged_attempt.is_some() {
                continue;
            }
            if candidate.pending_attempt.is_some() {
                pending_deliverable.push(candidate);
            } else {
                new_deliverable.push(candidate);
            }
        }
        pending_deliverable.sort_by_key(|candidate| candidate.acceptance_marker);
        new_deliverable.sort_by_key(|candidate| candidate.acceptance_marker);
        let eligible_count = pending_deliverable
            .len()
            .checked_add(new_deliverable.len())
            .ok_or(StoreError::ItemCountAccountingOverflow)?;
        let chosen = pending_deliverable
            .into_iter()
            .chain(new_deliverable)
            .take(plan.delivery_limit)
            .collect::<Vec<_>>();
        for candidate in &chosen {
            if !blob_subscription_exact_source_matches_write(
                &write,
                candidate.projection.transfer_id,
            )? {
                return Err(StoreError::BlobSubscriptionPlanChanged);
            }
        }
        let new_delivery_count = chosen
            .iter()
            .filter(|candidate| candidate.pending_attempt.is_none())
            .count();
        let new_cursor_count = chosen
            .iter()
            .filter(|candidate| candidate.delivery_cursor.is_none())
            .count();
        let final_pending_count = pending_count
            .checked_sub(
                u64::try_from(retire_pending.len())
                    .map_err(|_| StoreError::ItemCountAccountingOverflow)?,
            )
            .ok_or(StoreError::BlobInvariant(
                "Blob pending retirement underflows accounting",
            ))?
            .checked_add(
                u64::try_from(new_delivery_count)
                    .map_err(|_| StoreError::ItemCountAccountingOverflow)?,
            )
            .ok_or(StoreError::ItemCountAccountingOverflow)?;
        let final_acknowledgement_count = acknowledgement_count
            .checked_sub(
                u64::try_from(retire_acknowledgements.len())
                    .map_err(|_| StoreError::ItemCountAccountingOverflow)?,
            )
            .ok_or(StoreError::BlobInvariant(
                "Blob acknowledgement retirement underflows accounting",
            ))?;
        let final_cursor_count = cursor_count
            .checked_add(
                u64::try_from(new_cursor_count)
                    .map_err(|_| StoreError::ItemCountAccountingOverflow)?,
            )
            .ok_or(StoreError::ItemCountAccountingOverflow)?;
        let combined_final_pending = final_pending_count
            .checked_add(retirement_counts.deliveries)
            .ok_or(StoreError::ItemCountAccountingOverflow)?;
        let combined_final_acknowledgements = final_acknowledgement_count
            .checked_add(retirement_counts.acknowledgements)
            .ok_or(StoreError::ItemCountAccountingOverflow)?;
        if combined_final_pending > MAX_BLOB_PENDING_DELIVERIES {
            return Err(StoreError::BlobPendingDeliveryLimitExceeded {
                current: combined_final_pending,
                limit: MAX_BLOB_PENDING_DELIVERIES,
            });
        }
        let combined = combined_final_pending
            .checked_add(combined_final_acknowledgements)
            .ok_or(StoreError::ItemCountAccountingOverflow)?;
        if combined > MAX_BLOB_ACKNOWLEDGEMENT_RECEIPTS {
            return Err(StoreError::BlobDeliveryLedgerLimitExceeded {
                current: combined,
                limit: MAX_BLOB_ACKNOWLEDGEMENT_RECEIPTS,
            });
        }
        if final_cursor_count > MAX_BLOB_DELIVERY_CURSORS {
            return Err(StoreError::BlobDeliveryLedgerLimitExceeded {
                current: final_cursor_count,
                limit: MAX_BLOB_DELIVERY_CURSORS,
            });
        }

        let mut tenures = Vec::with_capacity(chosen.len());
        let mut attempts = Vec::with_capacity(chosen.len());
        for candidate in &chosen {
            if candidate.pending_attempt.is_some() {
                let cursor = candidate.delivery_cursor.ok_or(StoreError::BlobInvariant(
                    "pending Blob delivery is missing its monotonic cursor",
                ))?;
                tenures.push(cursor.tenure);
                attempts.push(
                    cursor
                        .last_attempt
                        .checked_add(1)
                        .ok_or(StoreError::BlobDeliveryAttemptExhausted)?,
                );
            } else {
                tenures.push(match candidate.delivery_cursor {
                    Some(cursor) => cursor
                        .tenure
                        .checked_add(1)
                        .ok_or(StoreError::BlobDeliveryTenureExhausted)?,
                    None => 1,
                });
                attempts.push(1);
            }
        }
        {
            let mut pending = write.open_table(BLOB_SUBSCRIPTION_PENDING)?;
            for candidate in &retire_pending {
                let key = blob_pending_delivery_key(plan.subscription, candidate.acceptance_marker);
                if pending.remove(key.as_slice())?.is_none() {
                    return Err(StoreError::BlobSubscriptionPlanChanged);
                }
            }
            for ((candidate, tenure), attempt) in chosen.iter().zip(&tenures).zip(&attempts) {
                let key = blob_pending_delivery_key(plan.subscription, candidate.acceptance_marker);
                let encoded = encode_blob_pending_delivery_record(BlobPendingDeliveryRecord {
                    semantic_id: candidate.projection.semantic_id,
                    tenure: *tenure,
                    attempts: *attempt,
                });
                pending.insert(key.as_slice(), encoded.as_slice())?;
            }
        }
        for candidate in &retire_pending {
            let key = blob_pending_delivery_key(plan.subscription, candidate.acceptance_marker);
            super::blob::lifecycle::remove_delivery_owner(
                &write,
                candidate.projection.transfer_id,
                &key,
            )?;
        }
        for candidate in chosen
            .iter()
            .filter(|candidate| candidate.pending_attempt.is_none())
        {
            let key = blob_pending_delivery_key(plan.subscription, candidate.acceptance_marker);
            super::blob::lifecycle::insert_delivery_owner(
                &write,
                candidate.projection.transfer_id,
                &key,
            )?;
        }
        {
            let mut acknowledgements = write.open_table(BLOB_DELIVERY_ACKNOWLEDGEMENTS)?;
            for candidate in &retire_acknowledgements {
                let key =
                    blob_acknowledgement_key(plan.subscription, candidate.projection.semantic_id);
                if acknowledgements.remove(key.as_slice())?.is_none() {
                    return Err(StoreError::BlobSubscriptionPlanChanged);
                }
            }
        }
        {
            let mut cursors = write.open_table(BLOB_DELIVERY_CURSORS)?;
            for ((candidate, tenure), attempt) in chosen.iter().zip(&tenures).zip(&attempts) {
                let key =
                    blob_delivery_cursor_key(plan.subscription, candidate.projection.semantic_id);
                let encoded = encode_blob_delivery_cursor_record(BlobDeliveryCursorRecord {
                    acceptance_marker: candidate.acceptance_marker,
                    tenure: *tenure,
                    last_attempt: *attempt,
                    last_acknowledged_tenure: candidate
                        .delivery_cursor
                        .map_or(0, |cursor| cursor.last_acknowledged_tenure),
                    last_acknowledged_attempt: candidate
                        .delivery_cursor
                        .map_or(0, |cursor| cursor.last_acknowledged_attempt),
                });
                cursors.insert(key.as_slice(), encoded.as_slice())?;
            }
        }
        {
            let mut metadata = write.open_table(METADATA)?;
            metadata.insert(BLOB_PENDING_DELIVERY_COUNT, combined_final_pending)?;
            metadata.insert(BLOB_ACKNOWLEDGEMENT_COUNT, combined_final_acknowledgements)?;
            metadata.insert(BLOB_DELIVERY_CURSOR_COUNT, final_cursor_count)?;
        }
        write.commit()?;

        Ok(BlobSubscriptionDeliveryPage {
            deliveries: chosen
                .into_iter()
                .zip(tenures)
                .zip(attempts)
                .map(|((candidate, tenure), attempt)| BlobSubscriptionDelivery {
                    semantic_id: candidate.projection.semantic_id,
                    acceptance_marker: candidate.acceptance_marker,
                    attempt,
                    token: blob_delivery_token(
                        plan.subscription,
                        candidate.projection.semantic_id,
                        plan.incarnation,
                        tenure,
                        attempt,
                    ),
                })
                .collect(),
            has_more: eligible_count > plan.delivery_limit,
        })
    }

    /// Idempotently acknowledges one exact semantic Blob delivery.
    pub fn acknowledge_blob_delivery_with_policy(
        &self,
        policy: &ControlPolicySnapshot,
        subscription: BlobSubscriptionId,
        semantic_id: BlobSemanticId,
        token: BlobDeliveryToken,
    ) -> Result<BlobDeliveryAck, StoreError> {
        let token = BlobDeliveryToken::from_bytes(*token.as_bytes())?;
        if token.is_retirement() {
            return Err(StoreError::InvalidBlobDeliveryToken);
        }
        let token = validate_blob_delivery_token_binding(subscription, semantic_id, token)?;
        self.require_live()?;
        let authority = self.require_bound_mission()?;
        let write = self.database.begin_write()?;
        enforce_live_write(&write)?;
        require_control_policy_write(&write, authority, policy)?;
        let record = write
            .open_table(BLOB_SUBSCRIPTIONS)?
            .get(subscription.as_bytes().as_slice())?
            .map(|value| decode_blob_subscription_record(value.value()))
            .transpose()?
            .ok_or(StoreError::BlobSubscriptionNotFound)?;
        if token.incarnation != record.incarnation {
            return Err(StoreError::BlobSubscriptionIncarnationChanged {
                current: record.incarnation,
                received: token.incarnation,
            });
        }
        let blob = blob_subscription_identity_write(&write, semantic_id)?
            .ok_or(StoreError::BlobDeliveryNotFound)?;
        if !record.spec.matches_topic_scope(&blob.topic, &blob.scope) {
            return Err(StoreError::BlobDeliveryNotFound);
        }
        let retirement = blob_subscription_retirement_write(&write, blob.transfer_id)?;
        let cursor_key = blob_delivery_cursor_key(subscription, semantic_id);
        let cursor = write
            .open_table(BLOB_DELIVERY_CURSORS)?
            .get(cursor_key.as_slice())?
            .map(|value| decode_blob_delivery_cursor_record(value.value()))
            .transpose()?;
        let acknowledgement_key = blob_acknowledgement_key(subscription, semantic_id);
        let receipt = write
            .open_table(BLOB_DELIVERY_ACKNOWLEDGEMENTS)?
            .get(acknowledgement_key.as_slice())?
            .map(|value| decode_blob_acknowledgement_record(value.value()))
            .transpose()?;
        let pending_key = blob_pending_delivery_key(subscription, blob.acceptance_marker);
        let delivery_state = write
            .open_table(BLOB_SUBSCRIPTION_PENDING)?
            .get(pending_key.as_slice())?
            .map(|value| decode_blob_delivery_record(value.value()))
            .transpose()?;
        if receipt.is_some() && matches!(delivery_state, Some(BlobDeliveryRecord::Retired(_))) {
            return Err(StoreError::BlobInvariant(
                "Blob delivery is both retired and acknowledged",
            ));
        }
        let pending = match delivery_state {
            Some(BlobDeliveryRecord::Pending(record)) => Some(record),
            Some(BlobDeliveryRecord::Retired(_)) => None,
            None => None,
        };
        if receipt.is_some() && pending.is_some() {
            return Err(StoreError::BlobInvariant(
                "Blob delivery is both pending and acknowledged",
            ));
        }
        if let Some(receipt) = receipt {
            let cursor = cursor.ok_or(StoreError::BlobInvariant(
                "Blob acknowledgement is missing its monotonic cursor",
            ))?;
            if receipt.acceptance_marker != blob.acceptance_marker
                || receipt.tenure != cursor.tenure
                || receipt.tenure != cursor.last_acknowledged_tenure
                || receipt.attempts != cursor.last_acknowledged_attempt
                || receipt.attempts > cursor.last_attempt
            {
                return Err(StoreError::BlobInvariant(
                    "Blob acknowledgement differs from its delivery cursor",
                ));
            }
            if token.tenure != receipt.tenure {
                return Err(StoreError::BlobDeliveryTenureChanged {
                    current: receipt.tenure,
                    received: token.tenure,
                });
            }
            validate_blob_delivery_token_attempt(token.attempt, receipt.attempts)?;
            return Ok(BlobDeliveryAck::AlreadyAcknowledged);
        }
        require_blob_publication_visible_write(&write, blob.transfer_id)?;
        if retirement.is_some() || matches!(delivery_state, Some(BlobDeliveryRecord::Retired(_))) {
            return Err(StoreError::Blob(super::BlobStoreError::ExpiredOrRetired));
        }
        let mut cursor = cursor.ok_or(StoreError::BlobDeliveryNotFound)?;
        if cursor.acceptance_marker != blob.acceptance_marker {
            return Err(StoreError::BlobInvariant(
                "Blob delivery cursor differs from its accepted Blob",
            ));
        }
        let Some(pending) = pending else {
            return Err(StoreError::BlobDeliveryNotFound);
        };
        if pending.semantic_id != semantic_id
            || pending.tenure != cursor.tenure
            || pending.attempts != cursor.last_attempt
        {
            return Err(StoreError::BlobInvariant(
                "pending Blob delivery differs from its monotonic cursor",
            ));
        }
        if token.tenure != pending.tenure {
            return Err(StoreError::BlobDeliveryTenureChanged {
                current: pending.tenure,
                received: token.tenure,
            });
        }
        validate_blob_delivery_token_attempt(token.attempt, pending.attempts)?;

        let subscription_count = write.open_table(BLOB_SUBSCRIPTIONS)?.len()?;
        let pending_count = write.open_table(BLOB_SUBSCRIPTION_PENDING)?.len()?;
        let acknowledgement_count = write.open_table(BLOB_DELIVERY_ACKNOWLEDGEMENTS)?.len()?;
        let cursor_count = write.open_table(BLOB_DELIVERY_CURSORS)?.len()?;
        require_blob_subscription_accounting(
            &write,
            subscription_count,
            pending_count,
            acknowledgement_count,
            cursor_count,
        )?;
        let retirement_counts = blob_retirement_ledger_counts_write(&write)?;
        let combined_acknowledgements = acknowledgement_count
            .checked_add(retirement_counts.acknowledgements)
            .ok_or(StoreError::ItemCountAccountingOverflow)?;
        if combined_acknowledgements >= MAX_BLOB_ACKNOWLEDGEMENT_RECEIPTS {
            return Err(StoreError::BlobAcknowledgementReceiptLimitExceeded {
                current: combined_acknowledgements,
                limit: MAX_BLOB_ACKNOWLEDGEMENT_RECEIPTS,
            });
        }
        let encoded = encode_blob_acknowledgement_record(BlobAcknowledgementRecord {
            acceptance_marker: blob.acceptance_marker,
            tenure: pending.tenure,
            attempts: pending.attempts,
        });
        if write
            .open_table(BLOB_DELIVERY_ACKNOWLEDGEMENTS)?
            .insert(acknowledgement_key.as_slice(), encoded.as_slice())?
            .is_some()
        {
            return Err(StoreError::BlobSubscriptionPlanChanged);
        }
        if write
            .open_table(BLOB_SUBSCRIPTION_PENDING)?
            .remove(pending_key.as_slice())?
            .is_none()
        {
            return Err(StoreError::BlobSubscriptionPlanChanged);
        }
        super::blob::lifecycle::remove_delivery_owner(&write, blob.transfer_id, &pending_key)?;
        {
            cursor.last_acknowledged_tenure = pending.tenure;
            cursor.last_acknowledged_attempt = pending.attempts;
            let encoded = encode_blob_delivery_cursor_record(cursor);
            write
                .open_table(BLOB_DELIVERY_CURSORS)?
                .insert(cursor_key.as_slice(), encoded.as_slice())?;
        }
        {
            let mut metadata = write.open_table(METADATA)?;
            metadata.insert(
                BLOB_PENDING_DELIVERY_COUNT,
                pending_count
                    .checked_sub(1)
                    .ok_or(StoreError::BlobInvariant(
                        "Blob acknowledgement underflows pending accounting",
                    ))?
                    .checked_add(retirement_counts.deliveries)
                    .ok_or(StoreError::ItemCountAccountingOverflow)?,
            )?;
            metadata.insert(
                BLOB_ACKNOWLEDGEMENT_COUNT,
                acknowledgement_count
                    .checked_add(1)
                    .and_then(|count| count.checked_add(retirement_counts.acknowledgements))
                    .ok_or(StoreError::ItemCountAccountingOverflow)?,
            )?;
        }
        write.commit()?;
        Ok(BlobDeliveryAck::Acknowledged)
    }

    #[doc(hidden)]
    pub fn prepare_blob_retirement_poll_with_policy(
        &self,
        policy: &ControlPolicySnapshot,
        subscription: BlobSubscriptionId,
        delivery_limit: usize,
    ) -> Result<BlobRetirementPollPlan, StoreError> {
        self.require_live()?;
        let authority = self.require_bound_mission()?;
        if delivery_limit == 0 || delivery_limit > MAX_BLOB_POLL_DELIVERIES {
            return Err(StoreError::BlobSubscriptionPollLimitExceeded {
                requested: delivery_limit,
                maximum: MAX_BLOB_POLL_DELIVERIES,
            });
        }
        let read = self.database.begin_read()?;
        require_control_policy_read(&read, authority, policy)?;
        let record = read
            .open_table(BLOB_SUBSCRIPTIONS)?
            .get(subscription.as_bytes().as_slice())?
            .map(|value| decode_blob_subscription_record(value.value()))
            .transpose()?
            .ok_or(StoreError::BlobSubscriptionNotFound)?;
        let mut start = [0u8; BLOB_RETIREMENT_DELIVERY_ORDER_KEY_BYTES];
        start[..32].copy_from_slice(subscription.as_bytes());
        let mut end = [0xff; BLOB_RETIREMENT_DELIVERY_ORDER_KEY_BYTES];
        end[..32].copy_from_slice(subscription.as_bytes());
        let order = read.open_table(BLOB_RETIREMENT_DELIVERY_ORDER)?;
        let primary = read.open_table(BLOB_RETIREMENT_DELIVERIES)?;
        let mut candidates = Vec::new();
        for row in order.range::<&[u8]>((
            std::ops::Bound::Included(start.as_slice()),
            std::ops::Bound::Included(end.as_slice()),
        ))? {
            if candidates.len() == delivery_limit {
                break;
            }
            let (key, value) = row?;
            if !value.value().is_empty() {
                return Err(StoreError::BlobInvariant(
                    "Blob retirement-delivery order value is not empty",
                ));
            }
            let (ordered_subscription, marker, semantic_id, generation) =
                parse_blob_retirement_delivery_order_key(key.value())?;
            if ordered_subscription != subscription {
                return Err(StoreError::BlobInvariant(
                    "Blob retirement-delivery order escaped its subscription prefix",
                ));
            }
            let primary_key = blob_retirement_delivery_key(subscription, semantic_id, generation);
            let delivery = primary
                .get(primary_key.as_slice())?
                .map(|value| decode_blob_retirement_delivery_record(value.value()))
                .transpose()?
                .ok_or(StoreError::BlobInvariant(
                    "Blob retirement-delivery order references a missing primary row",
                ))?;
            if delivery.subscription_incarnation != record.incarnation
                || delivery.acceptance_marker != marker
            {
                return Err(StoreError::BlobInvariant(
                    "Blob retirement-delivery order differs from its primary row",
                ));
            }
            let identity = blob_subscription_identity_read(&read, semantic_id)?.ok_or(
                StoreError::BlobInvariant(
                    "Blob retirement delivery references missing publication evidence",
                ),
            )?;
            if identity.acceptance_marker != marker
                || !record.spec.matches_identity(&identity)
                || blob_subscription_retirement_read(&read, identity.transfer_id)?
                    != Some((delivery.reason, generation))
            {
                return Err(StoreError::BlobInvariant(
                    "Blob retirement delivery differs from publication evidence",
                ));
            }
            candidates.push(BlobRetirementPollCandidate {
                semantic_id,
                retirement_generation: generation,
                acceptance_marker: marker,
                current_attempt: delivery.current_attempt,
                reason: delivery.reason,
            });
        }
        Ok(BlobRetirementPollPlan {
            policy: *policy,
            subscription,
            incarnation: record.incarnation,
            delivery_limit,
            candidates,
        })
    }

    #[doc(hidden)]
    pub fn commit_blob_retirement_poll_with_policy(
        &self,
        policy: &ControlPolicySnapshot,
        plan: &BlobRetirementPollPlan,
    ) -> Result<BlobRetirementDeliveryPage, StoreError> {
        self.require_live()?;
        let authority = self.require_bound_mission()?;
        if policy != &plan.policy {
            return Err(StoreError::BlobSubscriptionPlanChanged);
        }
        let write = self.database.begin_write()?;
        enforce_live_write(&write)?;
        require_control_policy_write(&write, authority, policy)?;
        let subscription = write
            .open_table(BLOB_SUBSCRIPTIONS)?
            .get(plan.subscription.as_bytes().as_slice())?
            .map(|value| decode_blob_subscription_record(value.value()))
            .transpose()?
            .ok_or(StoreError::BlobSubscriptionNotFound)?;
        if subscription.incarnation != plan.incarnation {
            return Err(StoreError::BlobSubscriptionIncarnationChanged {
                current: subscription.incarnation,
                received: plan.incarnation,
            });
        }
        let mut start = [0u8; BLOB_RETIREMENT_DELIVERY_ORDER_KEY_BYTES];
        start[..32].copy_from_slice(plan.subscription.as_bytes());
        let mut end = [0xff; BLOB_RETIREMENT_DELIVERY_ORDER_KEY_BYTES];
        end[..32].copy_from_slice(plan.subscription.as_bytes());
        let order = write.open_table(BLOB_RETIREMENT_DELIVERY_ORDER)?;
        let mut observed = Vec::with_capacity(plan.candidates.len().saturating_add(1));
        for row in order
            .range::<&[u8]>((
                std::ops::Bound::Included(start.as_slice()),
                std::ops::Bound::Included(end.as_slice()),
            ))?
            .take(plan.candidates.len().saturating_add(1))
        {
            let (key, value) = row?;
            if !value.value().is_empty() {
                return Err(StoreError::BlobInvariant(
                    "Blob retirement-delivery order value is not empty",
                ));
            }
            let (ordered_subscription, marker, semantic, generation) =
                parse_blob_retirement_delivery_order_key(key.value())?;
            if ordered_subscription != plan.subscription {
                return Err(StoreError::BlobInvariant(
                    "Blob retirement-delivery order escaped its subscription prefix",
                ));
            }
            observed.push((marker, semantic, generation));
        }
        if observed.len() < plan.candidates.len()
            || !plan
                .candidates
                .iter()
                .zip(&observed)
                .all(|(candidate, observed)| {
                    observed
                        == &(
                            candidate.acceptance_marker,
                            candidate.semantic_id,
                            candidate.retirement_generation,
                        )
                })
        {
            return Err(StoreError::BlobSubscriptionPlanChanged);
        }
        if plan.candidates.len() < plan.delivery_limit && observed.len() != plan.candidates.len() {
            return Err(StoreError::BlobSubscriptionPlanChanged);
        }
        let has_more =
            plan.candidates.len() == plan.delivery_limit && observed.len() > plan.candidates.len();
        drop(order);
        let mut deliveries = Vec::with_capacity(plan.candidates.len());
        for candidate in &plan.candidates {
            let key = blob_retirement_delivery_key(
                plan.subscription,
                candidate.semantic_id,
                candidate.retirement_generation,
            );
            let current = write
                .open_table(BLOB_RETIREMENT_DELIVERIES)?
                .get(key.as_slice())?
                .map(|value| decode_blob_retirement_delivery_record(value.value()))
                .transpose()?
                .ok_or(StoreError::BlobSubscriptionPlanChanged)?;
            if current
                != (BlobRetirementDeliveryRecord {
                    subscription_incarnation: plan.incarnation,
                    acceptance_marker: candidate.acceptance_marker,
                    current_attempt: candidate.current_attempt,
                    reason: candidate.reason,
                })
            {
                return Err(StoreError::BlobSubscriptionPlanChanged);
            }
            let identity = blob_subscription_identity_write(&write, candidate.semantic_id)?
                .ok_or(StoreError::BlobSubscriptionPlanChanged)?;
            if blob_subscription_retirement_write(&write, identity.transfer_id)?
                != Some((candidate.reason, candidate.retirement_generation))
            {
                return Err(StoreError::BlobSubscriptionPlanChanged);
            }
            let attempt = current
                .current_attempt
                .checked_add(1)
                .ok_or(StoreError::BlobDeliveryAttemptExhausted)?;
            let encoded = encode_blob_retirement_delivery_record(BlobRetirementDeliveryRecord {
                current_attempt: attempt,
                ..current
            });
            write
                .open_table(BLOB_RETIREMENT_DELIVERIES)?
                .insert(key.as_slice(), encoded.as_slice())?;
            deliveries.push(BlobRetirementDelivery {
                semantic_id: candidate.semantic_id,
                blob_id: identity.blob_id,
                publisher: identity.publisher,
                publisher_counter: identity.publisher_counter,
                topic: identity.topic,
                scope: identity.scope,
                priority: identity.priority,
                ttl_ms: identity.ttl_ms,
                acceptance_marker: candidate.acceptance_marker,
                subscription_incarnation: plan.incarnation,
                retirement_generation: candidate.retirement_generation,
                attempt,
                reason: candidate.reason,
                token: blob_retirement_delivery_token(
                    plan.subscription,
                    candidate.semantic_id,
                    plan.incarnation,
                    candidate.retirement_generation,
                    attempt,
                ),
            });
        }
        write.commit()?;
        Ok(BlobRetirementDeliveryPage {
            deliveries,
            has_more,
        })
    }

    #[doc(hidden)]
    pub fn acknowledge_blob_retirement_with_policy(
        &self,
        policy: &ControlPolicySnapshot,
        subscription: BlobSubscriptionId,
        semantic_id: BlobSemanticId,
        token: BlobDeliveryToken,
    ) -> Result<BlobDeliveryAck, StoreError> {
        let token =
            validate_blob_retirement_delivery_token_binding(subscription, semantic_id, token)?;
        self.require_live()?;
        let authority = self.require_bound_mission()?;
        let write = self.database.begin_write()?;
        enforce_live_write(&write)?;
        require_control_policy_write(&write, authority, policy)?;
        let subscription_record = write
            .open_table(BLOB_SUBSCRIPTIONS)?
            .get(subscription.as_bytes().as_slice())?
            .map(|value| decode_blob_subscription_record(value.value()))
            .transpose()?
            .ok_or(StoreError::BlobSubscriptionNotFound)?;
        if token.subscription_incarnation != subscription_record.incarnation {
            return Err(StoreError::BlobSubscriptionIncarnationChanged {
                current: subscription_record.incarnation,
                received: token.subscription_incarnation,
            });
        }
        let primary_key =
            blob_retirement_delivery_key(subscription, semantic_id, token.retirement_generation);
        let active = write
            .open_table(BLOB_RETIREMENT_DELIVERIES)?
            .get(primary_key.as_slice())?
            .map(|value| decode_blob_retirement_delivery_record(value.value()))
            .transpose()?;
        let receipt = write
            .open_table(BLOB_RETIREMENT_ACKNOWLEDGEMENTS)?
            .get(primary_key.as_slice())?
            .map(|value| decode_blob_retirement_acknowledgement_record(value.value()))
            .transpose()?;
        if active.is_some() && receipt.is_some() {
            return Err(StoreError::BlobInvariant(
                "Blob retirement delivery is both active and acknowledged",
            ));
        }
        if let Some(receipt) = receipt {
            if receipt.retirement_generation != token.retirement_generation {
                return Err(StoreError::BlobInvariant(
                    "Blob retirement acknowledgement generation differs from its key",
                ));
            }
            validate_blob_retirement_attempt(
                token.retirement_attempt,
                receipt.acknowledged_attempt,
            )?;
            return Ok(BlobDeliveryAck::AlreadyAcknowledged);
        }
        let active = active.ok_or(StoreError::BlobDeliveryNotFound)?;
        if active.subscription_incarnation != subscription_record.incarnation {
            return Err(StoreError::BlobInvariant(
                "Blob retirement delivery incarnation differs from its subscription",
            ));
        }
        validate_blob_retirement_attempt(token.retirement_attempt, active.current_attempt)?;
        let identity = blob_subscription_identity_write(&write, semantic_id)?
            .ok_or(StoreError::BlobDeliveryNotFound)?;
        if !subscription_record.spec.matches_identity(&identity)
            || blob_subscription_retirement_write(&write, identity.transfer_id)?
                != Some((active.reason, token.retirement_generation))
        {
            return Err(StoreError::BlobDeliveryNotFound);
        }
        let counts = blob_retirement_ledger_counts_write(&write)?;
        require_blob_retirement_accounting(&write.open_table(METADATA)?, counts)?;
        let order_key = blob_retirement_delivery_order_key(
            subscription,
            active.acceptance_marker,
            semantic_id,
            token.retirement_generation,
        );
        if write
            .open_table(BLOB_RETIREMENT_DELIVERIES)?
            .remove(primary_key.as_slice())?
            .is_none()
            || write
                .open_table(BLOB_RETIREMENT_DELIVERY_ORDER)?
                .remove(order_key.as_slice())?
                .is_none()
        {
            return Err(StoreError::BlobSubscriptionPlanChanged);
        }
        let receipt =
            encode_blob_retirement_acknowledgement_record(BlobRetirementAcknowledgementRecord {
                retirement_generation: token.retirement_generation,
                acknowledged_attempt: active.current_attempt,
            });
        if write
            .open_table(BLOB_RETIREMENT_ACKNOWLEDGEMENTS)?
            .insert(primary_key.as_slice(), receipt.as_slice())?
            .is_some()
        {
            return Err(StoreError::BlobSubscriptionPlanChanged);
        }
        let mut metadata = write.open_table(METADATA)?;
        let combined_pending = metadata
            .get(BLOB_PENDING_DELIVERY_COUNT)?
            .ok_or(StoreError::MissingAccountingMetadata {
                field: BLOB_PENDING_DELIVERY_COUNT,
            })?
            .value();
        let combined_acknowledgements = metadata
            .get(BLOB_ACKNOWLEDGEMENT_COUNT)?
            .ok_or(StoreError::MissingAccountingMetadata {
                field: BLOB_ACKNOWLEDGEMENT_COUNT,
            })?
            .value();
        metadata.insert(
            BLOB_PENDING_DELIVERY_COUNT,
            combined_pending
                .checked_sub(1)
                .ok_or(StoreError::BlobInvariant(
                    "Blob pending-delivery accounting underflow on retirement acknowledgement",
                ))?,
        )?;
        metadata.insert(
            BLOB_ACKNOWLEDGEMENT_COUNT,
            combined_acknowledgements
                .checked_add(1)
                .ok_or(StoreError::ItemCountAccountingOverflow)?,
        )?;
        metadata.insert(
            BLOB_RETIREMENT_DELIVERY_COUNT,
            counts
                .deliveries
                .checked_sub(1)
                .ok_or(StoreError::BlobInvariant(
                    "Blob retirement-delivery accounting underflow",
                ))?,
        )?;
        metadata.insert(
            BLOB_RETIREMENT_DELIVERY_ORDER_COUNT,
            counts
                .order
                .checked_sub(1)
                .ok_or(StoreError::BlobInvariant(
                    "Blob retirement-delivery order accounting underflow",
                ))?,
        )?;
        metadata.insert(
            BLOB_RETIREMENT_ACKNOWLEDGEMENT_COUNT,
            counts
                .acknowledgements
                .checked_add(1)
                .ok_or(StoreError::ItemCountAccountingOverflow)?,
        )?;
        drop(metadata);
        write.commit()?;
        Ok(BlobDeliveryAck::Acknowledged)
    }
}

#[allow(dead_code)]
fn validate_blob_retirement_attempt(received: u64, maximum: u64) -> Result<(), StoreError> {
    if received < 2 || received > maximum {
        return Err(StoreError::BlobDeliveryAttemptChanged {
            current: maximum,
            received,
        });
    }
    Ok(())
}

fn validate_blob_delivery_token_attempt(received: u64, maximum: u64) -> Result<(), StoreError> {
    if received == 0 || received > maximum {
        return Err(StoreError::BlobDeliveryAttemptChanged {
            current: maximum,
            received,
        });
    }
    Ok(())
}

fn validate_blob_poll_limits(delivery_limit: usize, scan_limit: usize) -> Result<(), StoreError> {
    if delivery_limit == 0 || delivery_limit > MAX_BLOB_POLL_DELIVERIES {
        return Err(StoreError::BlobSubscriptionPollLimitExceeded {
            requested: delivery_limit,
            maximum: MAX_BLOB_POLL_DELIVERIES,
        });
    }
    if scan_limit == 0 || scan_limit > MAX_BLOB_SUBSCRIPTION_SCAN {
        return Err(StoreError::BlobSubscriptionPollLimitExceeded {
            requested: scan_limit,
            maximum: MAX_BLOB_SUBSCRIPTION_SCAN,
        });
    }
    Ok(())
}

fn validate_blob_selection(
    plan: &BlobSubscriptionPollPlan,
    selection: &BlobSubscriptionPollSelection,
) -> Result<BlobSelectionPartition, StoreError> {
    let deliverable = selection
        .deliverable
        .iter()
        .copied()
        .collect::<BTreeSet<_>>();
    let inactive = selection.inactive.iter().copied().collect::<BTreeSet<_>>();
    if deliverable.len() != selection.deliverable.len()
        || inactive.len() != selection.inactive.len()
        || !deliverable.is_disjoint(&inactive)
    {
        return Err(StoreError::BlobSubscriptionPlanChanged);
    }
    let expected = plan
        .candidates
        .iter()
        .map(|candidate| candidate.projection.semantic_id)
        .collect::<BTreeSet<_>>();
    let actual = deliverable
        .iter()
        .chain(&inactive)
        .copied()
        .collect::<BTreeSet<_>>();
    if expected != actual {
        return Err(StoreError::BlobSubscriptionPlanChanged);
    }
    Ok(BlobSelectionPartition { deliverable })
}

struct BlobSelectionPartition {
    deliverable: BTreeSet<BlobSemanticId>,
}

fn blob_subscription_candidates_read(
    read: &redb::ReadTransaction,
    subscription: BlobSubscriptionId,
    spec: &BlobSubscriptionSpec,
    scan_limit: usize,
) -> Result<Vec<BlobSubscriptionCandidate>, StoreError> {
    let order = read.open_table(BLOB_ACCEPTANCE_ORDER)?;
    let pending = read.open_table(BLOB_SUBSCRIPTION_PENDING)?;
    let acknowledgements = read.open_table(BLOB_DELIVERY_ACKNOWLEDGEMENTS)?;
    let cursors = read.open_table(BLOB_DELIVERY_CURSORS)?;
    let mut candidates = Vec::new();
    let mut expected_marker = 1u64;
    for row in order.iter()? {
        let (marker, transfer) = row?;
        let marker = marker.value();
        if marker < expected_marker {
            return Err(StoreError::BlobInvariant(
                "Blob acceptance-order snapshot is not strictly increasing",
            ));
        }
        expected_marker = marker
            .checked_add(1)
            .ok_or(StoreError::AcceptanceMarkerExhausted)?;
        let transfer = parse_blob_subscription_transfer_id(transfer.value())?;
        let Some((projection, acceptance_marker)) =
            blob_subscription_projection_read(read, transfer)?
        else {
            if super::blob_subscription_lifetime_hidden_read(read, transfer)? {
                continue;
            }
            return Err(StoreError::BlobInvariant(
                "Blob acceptance-order index points to a missing Blob",
            ));
        };
        if acceptance_marker != marker || !spec.matches(&projection) {
            if acceptance_marker != marker {
                return Err(StoreError::BlobInvariant(
                    "Blob acceptance-order index differs from its forward marker",
                ));
            }
            continue;
        }
        if candidates.len() == scan_limit {
            return Err(StoreError::BlobSubscriptionPollLimitExceeded {
                requested: scan_limit
                    .checked_add(1)
                    .ok_or(StoreError::ItemCountAccountingOverflow)?,
                maximum: scan_limit,
            });
        }
        let pending_key = blob_pending_delivery_key(subscription, marker);
        let pending_record = pending
            .get(pending_key.as_slice())?
            .map(|value| decode_blob_pending_delivery_record(value.value()))
            .transpose()?;
        let acknowledgement_key = blob_acknowledgement_key(subscription, projection.semantic_id);
        let acknowledgement_record = acknowledgements
            .get(acknowledgement_key.as_slice())?
            .map(|value| decode_blob_acknowledgement_record(value.value()))
            .transpose()?;
        let cursor_key = blob_delivery_cursor_key(subscription, projection.semantic_id);
        let delivery_cursor = cursors
            .get(cursor_key.as_slice())?
            .map(|value| decode_blob_delivery_cursor_record(value.value()))
            .transpose()?;
        validate_blob_candidate_delivery_ledger(
            projection.semantic_id,
            marker,
            pending_record,
            acknowledgement_record,
            delivery_cursor,
        )?;
        candidates.push(BlobSubscriptionCandidate {
            projection,
            acceptance_marker: marker,
            pending_attempt: pending_record.map(|record| record.attempts),
            acknowledged_attempt: acknowledgement_record.map(|record| record.attempts),
            delivery_cursor,
        });
    }
    require_complete_blob_acceptance_snapshot_read(read, expected_marker)?;
    Ok(candidates)
}

fn blob_subscription_candidates_write(
    write: &redb::WriteTransaction,
    subscription: BlobSubscriptionId,
    spec: &BlobSubscriptionSpec,
    scan_limit: usize,
    expected: &[BlobSubscriptionCandidate],
) -> Result<Vec<BlobSubscriptionCandidate>, StoreError> {
    let order = write.open_table(BLOB_ACCEPTANCE_ORDER)?;
    let pending = write.open_table(BLOB_SUBSCRIPTION_PENDING)?;
    let acknowledgements = write.open_table(BLOB_DELIVERY_ACKNOWLEDGEMENTS)?;
    let cursors = write.open_table(BLOB_DELIVERY_CURSORS)?;
    let mut candidates = Vec::new();
    let expected = expected
        .iter()
        .map(|candidate| (candidate.acceptance_marker, candidate))
        .collect::<BTreeMap<_, _>>();
    let mut expected_marker = 1u64;
    for row in order.iter()? {
        let (marker, transfer) = row?;
        let marker = marker.value();
        if marker < expected_marker {
            return Err(StoreError::BlobInvariant(
                "Blob acceptance-order snapshot is not strictly increasing",
            ));
        }
        expected_marker = marker
            .checked_add(1)
            .ok_or(StoreError::AcceptanceMarkerExhausted)?;
        let transfer = parse_blob_subscription_transfer_id(transfer.value())?;
        if super::blob_subscription_lifetime_hidden_write(write, transfer)? {
            continue;
        }
        let identity = super::blob_subscription_identity_for_transfer_write(write, transfer)?
            .ok_or(StoreError::BlobInvariant(
                "Blob acceptance-order index points to a missing Blob",
            ))?;
        if identity.acceptance_marker != marker
            || !spec.matches_topic_scope(&identity.topic, &identity.scope)
        {
            if identity.acceptance_marker != marker {
                return Err(StoreError::BlobInvariant(
                    "Blob acceptance-order index differs from its forward marker",
                ));
            }
            continue;
        }
        if candidates.len() == scan_limit {
            return Err(StoreError::BlobSubscriptionPollLimitExceeded {
                requested: scan_limit
                    .checked_add(1)
                    .ok_or(StoreError::ItemCountAccountingOverflow)?,
                maximum: scan_limit,
            });
        }
        let planned = expected
            .get(&marker)
            .copied()
            .ok_or(StoreError::BlobSubscriptionPlanChanged)?;
        if !blob_subscription_projection_matches_write(
            write,
            transfer,
            marker,
            &planned.projection,
        )? {
            return Err(StoreError::BlobSubscriptionPlanChanged);
        }
        let pending_key = blob_pending_delivery_key(subscription, marker);
        let pending_record = pending
            .get(pending_key.as_slice())?
            .map(|value| decode_blob_pending_delivery_record(value.value()))
            .transpose()?;
        let acknowledgement_key = blob_acknowledgement_key(subscription, identity.semantic_id);
        let acknowledgement_record = acknowledgements
            .get(acknowledgement_key.as_slice())?
            .map(|value| decode_blob_acknowledgement_record(value.value()))
            .transpose()?;
        let cursor_key = blob_delivery_cursor_key(subscription, identity.semantic_id);
        let delivery_cursor = cursors
            .get(cursor_key.as_slice())?
            .map(|value| decode_blob_delivery_cursor_record(value.value()))
            .transpose()?;
        validate_blob_candidate_delivery_ledger(
            identity.semantic_id,
            marker,
            pending_record,
            acknowledgement_record,
            delivery_cursor,
        )?;
        candidates.push(BlobSubscriptionCandidate {
            projection: planned.projection.clone(),
            acceptance_marker: marker,
            pending_attempt: pending_record.map(|record| record.attempts),
            acknowledged_attempt: acknowledgement_record.map(|record| record.attempts),
            delivery_cursor,
        });
    }
    require_complete_blob_acceptance_snapshot_write(write, expected_marker)?;
    Ok(candidates)
}

fn validate_blob_candidate_delivery_ledger(
    semantic_id: BlobSemanticId,
    acceptance_marker: u64,
    pending: Option<BlobPendingDeliveryRecord>,
    acknowledgement: Option<BlobAcknowledgementRecord>,
    cursor: Option<BlobDeliveryCursorRecord>,
) -> Result<(), StoreError> {
    if pending.is_some() && acknowledgement.is_some() {
        return Err(StoreError::BlobInvariant(
            "Blob delivery is both pending and acknowledged",
        ));
    }
    let Some(cursor) = cursor else {
        if pending.is_some() || acknowledgement.is_some() {
            return Err(StoreError::BlobInvariant(
                "active Blob delivery is missing its monotonic cursor",
            ));
        }
        return Ok(());
    };
    if cursor.acceptance_marker != acceptance_marker {
        return Err(StoreError::BlobInvariant(
            "Blob delivery cursor differs from its accepted Blob",
        ));
    }
    if let Some(pending) = pending
        && (pending.semantic_id != semantic_id
            || pending.tenure != cursor.tenure
            || pending.attempts != cursor.last_attempt)
    {
        return Err(StoreError::BlobInvariant(
            "pending Blob delivery differs from its monotonic cursor",
        ));
    }
    if let Some(acknowledgement) = acknowledgement
        && (acknowledgement.acceptance_marker != acceptance_marker
            || acknowledgement.tenure != cursor.tenure
            || acknowledgement.tenure != cursor.last_acknowledged_tenure
            || acknowledgement.attempts != cursor.last_acknowledged_attempt
            || acknowledgement.attempts > cursor.last_attempt)
    {
        return Err(StoreError::BlobInvariant(
            "Blob acknowledgement differs from its monotonic cursor",
        ));
    }
    Ok(())
}

fn require_complete_blob_acceptance_snapshot_read(
    read: &redb::ReadTransaction,
    next_marker: u64,
) -> Result<(), StoreError> {
    let high_water = read
        .open_table(METADATA)?
        .get(LAST_BLOB_ACCEPTANCE_MARKER)?
        .ok_or(StoreError::MissingAccountingMetadata {
            field: LAST_BLOB_ACCEPTANCE_MARKER,
        })?
        .value();
    if next_marker
        .checked_sub(1)
        .is_none_or(|last| last > high_water)
    {
        return Err(StoreError::BlobInvariant(
            "Blob acceptance-order snapshot ended before durable acceptance high-water",
        ));
    }
    Ok(())
}

fn require_complete_blob_acceptance_snapshot_write(
    write: &redb::WriteTransaction,
    next_marker: u64,
) -> Result<(), StoreError> {
    let high_water = write
        .open_table(METADATA)?
        .get(LAST_BLOB_ACCEPTANCE_MARKER)?
        .ok_or(StoreError::MissingAccountingMetadata {
            field: LAST_BLOB_ACCEPTANCE_MARKER,
        })?
        .value();
    if next_marker
        .checked_sub(1)
        .is_none_or(|last| last > high_water)
    {
        return Err(StoreError::BlobInvariant(
            "Blob acceptance-order snapshot ended before durable acceptance high-water",
        ));
    }
    Ok(())
}

fn blob_subscription_id(authority: NodeId, key: &BlobSubscriptionKey) -> BlobSubscriptionId {
    let mut digest = Sha256::new();
    digest.update(BLOB_SUBSCRIPTION_ID_DOMAIN);
    digest.update(authority);
    digest.update(
        u16::try_from(key.as_bytes().len())
            .expect("validated Blob subscription key fits u16")
            .to_be_bytes(),
    );
    digest.update(key.as_bytes());
    BlobSubscriptionId(digest.finalize().into())
}

#[derive(Clone, Copy)]
struct BlobDeliveryTokenParts {
    incarnation: u64,
    tenure: u64,
    attempt: u64,
}

#[allow(dead_code)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct BlobRetirementDeliveryTokenParts {
    subscription_incarnation: u64,
    retirement_generation: u64,
    retirement_attempt: u64,
}

fn blob_delivery_token(
    subscription: BlobSubscriptionId,
    semantic_id: BlobSemanticId,
    incarnation: u64,
    tenure: u64,
    attempt: u64,
) -> BlobDeliveryToken {
    debug_assert!(incarnation > 0 && tenure > 0 && attempt > 0);
    let mut bytes = [0u8; BLOB_DELIVERY_TOKEN_BYTES];
    bytes[0] = BLOB_DELIVERY_TOKEN_VERSION;
    bytes[1..9].copy_from_slice(&incarnation.to_be_bytes());
    bytes[9..17].copy_from_slice(&tenure.to_be_bytes());
    bytes[17..25].copy_from_slice(&attempt.to_be_bytes());
    let mut digest = Sha256::new();
    digest.update(BLOB_DELIVERY_TOKEN_DOMAIN);
    digest.update(subscription.as_bytes());
    digest.update(semantic_id.as_bytes());
    digest.update(&bytes[..BLOB_DELIVERY_TOKEN_COUNTER_BYTES]);
    bytes[BLOB_DELIVERY_TOKEN_COUNTER_BYTES..].copy_from_slice(&digest.finalize());
    BlobDeliveryToken(bytes)
}

fn validate_blob_delivery_token_binding(
    subscription: BlobSubscriptionId,
    semantic_id: BlobSemanticId,
    token: BlobDeliveryToken,
) -> Result<BlobDeliveryTokenParts, StoreError> {
    let parts = BlobDeliveryTokenParts {
        incarnation: token.incarnation(),
        tenure: token.tenure(),
        attempt: token.attempt(),
    };
    if token
        != blob_delivery_token(
            subscription,
            semantic_id,
            parts.incarnation,
            parts.tenure,
            parts.attempt,
        )
    {
        return Err(StoreError::BlobDeliveryTokenBindingMismatch);
    }
    Ok(parts)
}

#[allow(dead_code)]
pub(crate) fn blob_retirement_delivery_token(
    subscription: BlobSubscriptionId,
    semantic_id: BlobSemanticId,
    subscription_incarnation: u64,
    retirement_generation: u64,
    retirement_attempt: u64,
) -> BlobDeliveryToken {
    debug_assert!(
        subscription_incarnation > 0 && retirement_generation > 0 && retirement_attempt > 0
    );
    let mut bytes = [0u8; BLOB_DELIVERY_TOKEN_BYTES];
    bytes[0] = BLOB_RETIREMENT_DELIVERY_TOKEN_VERSION;
    bytes[1..9].copy_from_slice(&subscription_incarnation.to_be_bytes());
    bytes[9..17].copy_from_slice(&retirement_generation.to_be_bytes());
    bytes[17..25].copy_from_slice(&retirement_attempt.to_be_bytes());
    let mut digest = Sha256::new();
    digest.update(BLOB_RETIREMENT_DELIVERY_TOKEN_DOMAIN);
    digest.update(&bytes[..BLOB_DELIVERY_TOKEN_COUNTER_BYTES]);
    digest.update(subscription.as_bytes());
    digest.update(semantic_id.as_bytes());
    bytes[BLOB_DELIVERY_TOKEN_COUNTER_BYTES..].copy_from_slice(&digest.finalize());
    BlobDeliveryToken(bytes)
}

#[allow(dead_code)]
fn validate_blob_retirement_delivery_token_binding(
    subscription: BlobSubscriptionId,
    semantic_id: BlobSemanticId,
    token: BlobDeliveryToken,
) -> Result<BlobRetirementDeliveryTokenParts, StoreError> {
    let token = BlobDeliveryToken::from_retirement_bytes(*token.as_bytes())?;
    let parts = BlobRetirementDeliveryTokenParts {
        subscription_incarnation: token.incarnation(),
        retirement_generation: token.tenure(),
        retirement_attempt: token.attempt(),
    };
    if token
        != blob_retirement_delivery_token(
            subscription,
            semantic_id,
            parts.subscription_incarnation,
            parts.retirement_generation,
            parts.retirement_attempt,
        )
    {
        return Err(StoreError::BlobDeliveryTokenBindingMismatch);
    }
    Ok(parts)
}

fn encode_blob_subscription_record(record: &BlobSubscriptionRecord) -> Result<Vec<u8>, StoreError> {
    let key_length = u16::try_from(record.operation_key.as_bytes().len()).map_err(|_| {
        StoreError::BlobInvariant("Blob subscription operation key exceeds its bound")
    })?;
    let topic = record.spec.topic.as_str().as_bytes();
    let scope = record.spec.scope.as_str().as_bytes();
    let topic_length = u16::try_from(topic.len())
        .map_err(|_| StoreError::BlobInvariant("Blob subscription topic exceeds its bound"))?;
    let scope_length = u16::try_from(scope.len())
        .map_err(|_| StoreError::BlobInvariant("Blob subscription scope exceeds its bound"))?;
    let mut encoded = Vec::new();
    encoded.push(BLOB_SUBSCRIPTION_VERSION);
    encoded.push(u8::from(record.spec.include_descendant_scopes));
    encoded.extend_from_slice(&record.incarnation.to_be_bytes());
    encoded.extend_from_slice(&key_length.to_be_bytes());
    encoded.extend_from_slice(record.operation_key.as_bytes());
    encoded.extend_from_slice(&topic_length.to_be_bytes());
    encoded.extend_from_slice(topic);
    encoded.extend_from_slice(&scope_length.to_be_bytes());
    encoded.extend_from_slice(scope);
    Ok(encoded)
}

fn decode_blob_subscription_record(bytes: &[u8]) -> Result<BlobSubscriptionRecord, StoreError> {
    let mut cursor = MetadataCursor::new(bytes);
    if cursor.u8()? != BLOB_SUBSCRIPTION_VERSION {
        return Err(StoreError::BlobInvariant(
            "unknown Blob subscription encoding version",
        ));
    }
    let include_descendant_scopes = match cursor.u8()? {
        0 => false,
        1 => true,
        _ => {
            return Err(StoreError::BlobInvariant(
                "invalid Blob subscription descendant flag",
            ));
        }
    };
    let incarnation = cursor.u64()?;
    if incarnation == 0 {
        return Err(StoreError::BlobInvariant(
            "Blob subscription incarnation is zero",
        ));
    }
    let key_length = usize::from(cursor.u16()?);
    let operation_key = BlobSubscriptionKey::new(cursor.take(key_length)?.to_vec())
        .map_err(|_| StoreError::BlobInvariant("invalid Blob subscription operation key"))?;
    let topic = Topic::new(cursor.short_string()?)
        .map_err(|_| StoreError::BlobInvariant("invalid Blob subscription topic"))?;
    let scope = Scope::new(cursor.short_string()?)
        .map_err(|_| StoreError::BlobInvariant("invalid Blob subscription scope"))?;
    cursor.finish()?;
    let record = BlobSubscriptionRecord {
        operation_key,
        spec: BlobSubscriptionSpec {
            topic,
            scope,
            include_descendant_scopes,
        },
        incarnation,
    };
    if encode_blob_subscription_record(&record)?.as_slice() != bytes {
        return Err(StoreError::BlobInvariant(
            "Blob subscription encoding is not canonical",
        ));
    }
    Ok(record)
}

fn blob_pending_delivery_key(subscription: BlobSubscriptionId, marker: u64) -> [u8; 40] {
    let mut key = [0u8; 40];
    key[..32].copy_from_slice(subscription.as_bytes());
    key[32..].copy_from_slice(&marker.to_be_bytes());
    key
}

fn parse_blob_pending_delivery_key(bytes: &[u8]) -> Result<(BlobSubscriptionId, u64), StoreError> {
    let bytes: [u8; 40] = bytes
        .try_into()
        .map_err(|_| StoreError::BlobInvariant("Blob pending-delivery key has invalid length"))?;
    let subscription = BlobSubscriptionId::from_bytes(
        bytes[..32]
            .try_into()
            .expect("fixed Blob subscription prefix"),
    );
    let marker = u64::from_be_bytes(bytes[32..].try_into().expect("fixed marker suffix"));
    if marker == 0 {
        return Err(StoreError::BlobInvariant(
            "Blob pending-delivery key contains a zero marker",
        ));
    }
    Ok((subscription, marker))
}

fn encode_blob_pending_delivery_record(record: BlobPendingDeliveryRecord) -> Vec<u8> {
    let mut encoded = Vec::with_capacity(BLOB_PENDING_DELIVERY_RECORD_BYTES);
    encoded.push(BLOB_PENDING_DELIVERY_VERSION);
    encoded.extend_from_slice(record.semantic_id.as_bytes());
    encoded.extend_from_slice(&record.tenure.to_be_bytes());
    encoded.extend_from_slice(&record.attempts.to_be_bytes());
    encoded
}

fn decode_blob_pending_delivery_record(
    bytes: &[u8],
) -> Result<BlobPendingDeliveryRecord, StoreError> {
    match decode_blob_delivery_record(bytes)? {
        BlobDeliveryRecord::Pending(record) => Ok(record),
        BlobDeliveryRecord::Retired(_) => Err(StoreError::BlobInvariant(
            "retired Blob delivery has no live pending attempt",
        )),
    }
}

fn decode_blob_delivery_record(bytes: &[u8]) -> Result<BlobDeliveryRecord, StoreError> {
    let mut cursor = MetadataCursor::new(bytes);
    let version = cursor.u8()?;
    let semantic_id = BlobSemanticId::new(cursor.array()?);
    match version {
        BLOB_PENDING_DELIVERY_VERSION => {
            let tenure = cursor.u64()?;
            let attempts = cursor.u64()?;
            cursor.finish()?;
            if tenure == 0 || attempts == 0 {
                return Err(StoreError::BlobInvariant(
                    "Blob pending-delivery tenure or attempt count is zero",
                ));
            }
            Ok(BlobDeliveryRecord::Pending(BlobPendingDeliveryRecord {
                semantic_id,
                tenure,
                attempts,
            }))
        }
        BLOB_RETIRED_DELIVERY_VERSION => {
            let retirement_generation = cursor.u64()?;
            cursor.finish()?;
            if retirement_generation == 0 {
                return Err(StoreError::BlobInvariant(
                    "Blob retirement delivery generation is zero",
                ));
            }
            Ok(BlobDeliveryRecord::Retired(BlobRetiredDeliveryRecord {
                semantic_id,
                retirement_generation,
            }))
        }
        _ => Err(StoreError::BlobInvariant(
            "unknown Blob pending-delivery encoding version",
        )),
    }
}

fn blob_retirement_delivery_key(
    subscription: BlobSubscriptionId,
    semantic_id: BlobSemanticId,
    retirement_generation: u64,
) -> [u8; BLOB_RETIREMENT_DELIVERY_KEY_BYTES] {
    let mut key = [0u8; BLOB_RETIREMENT_DELIVERY_KEY_BYTES];
    key[..32].copy_from_slice(subscription.as_bytes());
    key[32..64].copy_from_slice(semantic_id.as_bytes());
    key[64..].copy_from_slice(&retirement_generation.to_be_bytes());
    key
}

fn parse_blob_retirement_delivery_key(
    bytes: &[u8],
) -> Result<(BlobSubscriptionId, BlobSemanticId, u64), StoreError> {
    let bytes: [u8; BLOB_RETIREMENT_DELIVERY_KEY_BYTES] = bytes.try_into().map_err(|_| {
        StoreError::BlobInvariant("Blob retirement-delivery key has invalid length")
    })?;
    let generation = u64::from_be_bytes(bytes[64..].try_into().expect("fixed generation"));
    if generation == 0 {
        return Err(StoreError::BlobInvariant(
            "Blob retirement-delivery key contains a zero generation",
        ));
    }
    Ok((
        BlobSubscriptionId::from_bytes(bytes[..32].try_into().expect("fixed subscription")),
        BlobSemanticId::new(bytes[32..64].try_into().expect("fixed semantic identity")),
        generation,
    ))
}

fn blob_retirement_delivery_order_key(
    subscription: BlobSubscriptionId,
    acceptance_marker: u64,
    semantic_id: BlobSemanticId,
    retirement_generation: u64,
) -> [u8; BLOB_RETIREMENT_DELIVERY_ORDER_KEY_BYTES] {
    let mut key = [0u8; BLOB_RETIREMENT_DELIVERY_ORDER_KEY_BYTES];
    key[..32].copy_from_slice(subscription.as_bytes());
    key[32..40].copy_from_slice(&acceptance_marker.to_be_bytes());
    key[40..72].copy_from_slice(semantic_id.as_bytes());
    key[72..].copy_from_slice(&retirement_generation.to_be_bytes());
    key
}

fn parse_blob_retirement_delivery_order_key(
    bytes: &[u8],
) -> Result<(BlobSubscriptionId, u64, BlobSemanticId, u64), StoreError> {
    let bytes: [u8; BLOB_RETIREMENT_DELIVERY_ORDER_KEY_BYTES] = bytes.try_into().map_err(|_| {
        StoreError::BlobInvariant("Blob retirement-delivery order key has invalid length")
    })?;
    let marker = u64::from_be_bytes(bytes[32..40].try_into().expect("fixed marker"));
    let generation = u64::from_be_bytes(bytes[72..].try_into().expect("fixed generation"));
    if marker == 0 || generation == 0 {
        return Err(StoreError::BlobInvariant(
            "Blob retirement-delivery order key contains a zero marker or generation",
        ));
    }
    Ok((
        BlobSubscriptionId::from_bytes(bytes[..32].try_into().expect("fixed subscription")),
        marker,
        BlobSemanticId::new(bytes[40..72].try_into().expect("fixed semantic identity")),
        generation,
    ))
}

fn blob_retirement_delivery_owner_key(
    transfer: BlobTransferId,
    primary_key: &[u8; BLOB_RETIREMENT_DELIVERY_KEY_BYTES],
) -> [u8; 64] {
    let mut key = [0u8; 64];
    key[..32].copy_from_slice(transfer.as_bytes());
    key[32..].copy_from_slice(&Sha256::digest(primary_key));
    key
}

fn encode_blob_retirement_delivery_record(record: BlobRetirementDeliveryRecord) -> Vec<u8> {
    let mut encoded = Vec::with_capacity(BLOB_RETIREMENT_DELIVERY_RECORD_BYTES);
    encoded.push(BLOB_RETIREMENT_DELIVERY_RECORD_VERSION);
    encoded.extend_from_slice(&record.subscription_incarnation.to_be_bytes());
    encoded.extend_from_slice(&record.acceptance_marker.to_be_bytes());
    encoded.extend_from_slice(&record.current_attempt.to_be_bytes());
    encoded.push(record.reason.encode());
    encoded
}

fn decode_blob_retirement_delivery_record(
    bytes: &[u8],
) -> Result<BlobRetirementDeliveryRecord, StoreError> {
    let mut cursor = MetadataCursor::new(bytes);
    if cursor.u8()? != BLOB_RETIREMENT_DELIVERY_RECORD_VERSION {
        return Err(StoreError::BlobInvariant(
            "unknown Blob retirement-delivery encoding version",
        ));
    }
    let record = BlobRetirementDeliveryRecord {
        subscription_incarnation: cursor.u64()?,
        acceptance_marker: cursor.u64()?,
        current_attempt: cursor.u64()?,
        reason: super::blob::lifecycle::RetirementReason::decode(cursor.u8()?).ok_or(
            StoreError::BlobInvariant("Blob retirement delivery has an unknown reason"),
        )?,
    };
    cursor.finish()?;
    if record.subscription_incarnation == 0
        || record.acceptance_marker == 0
        || record.current_attempt == 0
    {
        return Err(StoreError::BlobInvariant(
            "Blob retirement delivery contains a zero incarnation, marker, or attempt",
        ));
    }
    Ok(record)
}

#[allow(dead_code)]
fn encode_blob_retirement_acknowledgement_record(
    record: BlobRetirementAcknowledgementRecord,
) -> Vec<u8> {
    let mut encoded = Vec::with_capacity(BLOB_RETIREMENT_ACKNOWLEDGEMENT_BYTES);
    encoded.push(BLOB_RETIREMENT_ACKNOWLEDGEMENT_VERSION);
    encoded.extend_from_slice(&record.retirement_generation.to_be_bytes());
    encoded.extend_from_slice(&record.acknowledged_attempt.to_be_bytes());
    encoded
}

fn decode_blob_retirement_acknowledgement_record(
    bytes: &[u8],
) -> Result<BlobRetirementAcknowledgementRecord, StoreError> {
    let mut cursor = MetadataCursor::new(bytes);
    if cursor.u8()? != BLOB_RETIREMENT_ACKNOWLEDGEMENT_VERSION {
        return Err(StoreError::BlobInvariant(
            "unknown Blob retirement-acknowledgement encoding version",
        ));
    }
    let record = BlobRetirementAcknowledgementRecord {
        retirement_generation: cursor.u64()?,
        acknowledged_attempt: cursor.u64()?,
    };
    cursor.finish()?;
    if record.retirement_generation == 0 || record.acknowledged_attempt < 2 {
        return Err(StoreError::BlobInvariant(
            "Blob retirement acknowledgement has an invalid generation or issued attempt",
        ));
    }
    Ok(record)
}

pub(crate) struct BlobDeliveryRetirementPlan {
    rows: Vec<BlobDeliveryRetirementRow>,
    transfer: BlobTransferId,
    reason: super::blob::lifecycle::RetirementReason,
}

struct BlobDeliveryRetirementRow {
    pending_key: Vec<u8>,
    pending_value: Vec<u8>,
    cursor_key: [u8; 64],
    cursor_value: Vec<u8>,
    subscription: BlobSubscriptionId,
    subscription_incarnation: u64,
    acceptance_marker: u64,
}

pub(crate) fn apply_blob_delivery_retirement_plan_write(
    write: &redb::WriteTransaction,
    plan: BlobDeliveryRetirementPlan,
    semantic_id: BlobSemanticId,
    retirement_generation: u64,
) -> Result<(), StoreError> {
    let BlobDeliveryRetirementPlan {
        rows,
        transfer,
        reason,
    } = plan;
    let subscription_count = write.open_table(BLOB_SUBSCRIPTIONS)?.len()?;
    let pending_count = write.open_table(BLOB_SUBSCRIPTION_PENDING)?.len()?;
    let acknowledgement_count = write.open_table(BLOB_DELIVERY_ACKNOWLEDGEMENTS)?.len()?;
    let cursor_count = write.open_table(BLOB_DELIVERY_CURSORS)?.len()?;
    require_blob_subscription_accounting(
        write,
        subscription_count,
        pending_count,
        acknowledgement_count,
        cursor_count,
    )?;
    let before = blob_retirement_ledger_counts_write(write)?;
    let added = u64::try_from(rows.len()).map_err(|_| StoreError::ItemCountAccountingOverflow)?;
    for row in rows {
        let current = write
            .open_table(BLOB_SUBSCRIPTION_PENDING)?
            .get(row.pending_key.as_slice())?
            .map(|value| value.value().to_vec())
            .ok_or(StoreError::BlobInvariant(
                "planned Blob delivery row disappeared before retirement",
            ))?;
        if current != row.pending_value {
            return Err(StoreError::BlobInvariant(
                "planned Blob delivery row changed before retirement",
            ));
        }
        let cursor = write
            .open_table(BLOB_DELIVERY_CURSORS)?
            .get(row.cursor_key.as_slice())?
            .map(|value| value.value().to_vec())
            .ok_or(StoreError::BlobInvariant(
                "planned Blob delivery cursor disappeared before retirement",
            ))?;
        if cursor != row.cursor_value {
            return Err(StoreError::BlobInvariant(
                "planned Blob delivery cursor changed before retirement",
            ));
        }
        let primary_key =
            blob_retirement_delivery_key(row.subscription, semantic_id, retirement_generation);
        let order_key = blob_retirement_delivery_order_key(
            row.subscription,
            row.acceptance_marker,
            semantic_id,
            retirement_generation,
        );
        let pending = decode_blob_pending_delivery_record(&row.pending_value)?;
        if pending.semantic_id != semantic_id {
            return Err(StoreError::BlobInvariant(
                "planned Blob delivery belongs to another semantic publication",
            ));
        }
        // The publication row is changed immediately after this conversion in
        // the same transaction, so carry the already-planned reason below.
        let primary_value = encode_blob_retirement_delivery_record(BlobRetirementDeliveryRecord {
            subscription_incarnation: row.subscription_incarnation,
            acceptance_marker: row.acceptance_marker,
            current_attempt: 1,
            reason,
        });
        if write
            .open_table(BLOB_SUBSCRIPTION_PENDING)?
            .remove(row.pending_key.as_slice())?
            .is_none()
            || write
                .open_table(BLOB_DELIVERY_CURSORS)?
                .remove(row.cursor_key.as_slice())?
                .is_none()
        {
            return Err(StoreError::BlobSubscriptionPlanChanged);
        }
        super::blob::lifecycle::remove_delivery_owner(write, transfer, &row.pending_key)?;
        if write
            .open_table(BLOB_RETIREMENT_DELIVERIES)?
            .insert(primary_key.as_slice(), primary_value.as_slice())?
            .is_some()
            || write
                .open_table(BLOB_RETIREMENT_DELIVERY_ORDER)?
                .insert(order_key.as_slice(), &[][..])?
                .is_some()
            || write
                .open_table(BLOB_RETIREMENT_DELIVERY_OWNERS)?
                .insert(
                    blob_retirement_delivery_owner_key(transfer, &primary_key).as_slice(),
                    primary_key.as_slice(),
                )?
                .is_some()
        {
            return Err(StoreError::BlobInvariant(
                "Blob retirement delivery collides with existing authority",
            ));
        }
    }
    let mut metadata = write.open_table(METADATA)?;
    metadata.insert(
        BLOB_DELIVERY_CURSOR_COUNT,
        cursor_count
            .checked_sub(added)
            .ok_or(StoreError::BlobInvariant(
                "Blob delivery-cursor accounting underflows on retirement",
            ))?,
    )?;
    metadata.insert(
        BLOB_RETIREMENT_DELIVERY_COUNT,
        before
            .deliveries
            .checked_add(added)
            .ok_or(StoreError::ItemCountAccountingOverflow)?,
    )?;
    metadata.insert(
        BLOB_RETIREMENT_DELIVERY_ORDER_COUNT,
        before
            .order
            .checked_add(added)
            .ok_or(StoreError::ItemCountAccountingOverflow)?,
    )?;
    metadata.insert(
        BLOB_RETIREMENT_DELIVERY_OWNER_COUNT,
        before
            .owners
            .checked_add(added)
            .ok_or(StoreError::ItemCountAccountingOverflow)?,
    )?;
    Ok(())
}

/// Incrementally computes the unique-row charge for converting every live
/// delivery owned by one publication into retained retirement state. The
/// forward delivery and its audited inverse owner are each admitted and
/// charged once; unrelated acknowledgement and cursor rows are neither read
/// nor mutated here.
pub(crate) fn plan_blob_delivery_retirement_write(
    write: &redb::WriteTransaction,
    transfer: BlobTransferId,
    semantic_id: BlobSemanticId,
    reason: super::blob::lifecycle::RetirementReason,
    charge: &mut super::blob::MaintenanceCharge,
) -> Result<Option<BlobDeliveryRetirementPlan>, StoreError> {
    let (start, end) = super::blob::lifecycle::inverse_owner_bounds(transfer);
    let owners = write.open_table(super::blob::lifecycle::BLOB_DELIVERY_OWNERS)?;
    let pending_rows = write.open_table(BLOB_SUBSCRIPTION_PENDING)?;
    let mut owner_rows = 0u64;
    let mut rows = Vec::new();
    for row in owners.range::<&[u8]>((
        std::ops::Bound::Included(start.as_slice()),
        std::ops::Bound::Included(end.as_slice()),
    ))? {
        let (owner_key, delivery_key) = row?;
        if !charge.charge(owner_key.value(), delivery_key.value().len())? {
            return Ok(None);
        }
        if super::blob::lifecycle::inverse_owner_key(transfer, delivery_key.value()).as_slice()
            != owner_key.value()
        {
            return Err(StoreError::BlobInvariant(
                "Blob delivery inverse owner is not canonical",
            ));
        }
        owner_rows = owner_rows
            .checked_add(1)
            .ok_or(StoreError::ItemCountAccountingOverflow)?;
        if owner_rows > MAX_BLOB_SUBSCRIPTIONS {
            return Err(StoreError::BlobInvariant(
                "Blob delivery inverse-owner fan-out exceeds its structural bound",
            ));
        }
        if !charge.has_capacity_for_row() {
            return Ok(None);
        }
        if !charge.charge(delivery_key.value(), BLOB_PENDING_DELIVERY_RECORD_BYTES)? {
            return Ok(None);
        }
        let encoded = pending_rows
            .get(delivery_key.value())?
            .ok_or(StoreError::BlobInvariant(
                "Blob delivery owner points to a missing pending row",
            ))?;
        let BlobDeliveryRecord::Pending(pending) = decode_blob_delivery_record(encoded.value())?
        else {
            return Err(StoreError::BlobInvariant(
                "live Blob delivery owner points to retired delivery state",
            ));
        };
        if pending.semantic_id != semantic_id {
            return Err(StoreError::BlobInvariant(
                "Blob delivery owner points to another semantic publication",
            ));
        }
        let (subscription, acceptance_marker) =
            parse_blob_pending_delivery_key(delivery_key.value())?;
        let subscription_record = write
            .open_table(BLOB_SUBSCRIPTIONS)?
            .get(subscription.as_bytes().as_slice())?
            .map(|value| decode_blob_subscription_record(value.value()))
            .transpose()?
            .ok_or(StoreError::BlobInvariant(
                "Blob delivery owner references a missing subscription",
            ))?;
        let cursor_key = blob_delivery_cursor_key(subscription, semantic_id);
        if !charge.has_capacity_for_row()
            || !charge.charge(cursor_key.as_slice(), 41)?
            || !charge.has_capacity_for_row()
            || !charge.charge(
                &[0; BLOB_RETIREMENT_DELIVERY_KEY_BYTES],
                BLOB_RETIREMENT_DELIVERY_RECORD_BYTES,
            )?
            || !charge.has_capacity_for_row()
            || !charge.charge(&[0; BLOB_RETIREMENT_DELIVERY_ORDER_KEY_BYTES], 0)?
            || !charge.has_capacity_for_row()
            || !charge.charge(&[0; 64], BLOB_RETIREMENT_DELIVERY_KEY_BYTES)?
        {
            return Ok(None);
        }
        let cursor_value = write
            .open_table(BLOB_DELIVERY_CURSORS)?
            .get(cursor_key.as_slice())?
            .map(|value| value.value().to_vec())
            .ok_or(StoreError::BlobInvariant(
                "pending Blob delivery is missing its monotonic cursor",
            ))?;
        let cursor = decode_blob_delivery_cursor_record(&cursor_value)?;
        if cursor.acceptance_marker != acceptance_marker
            || cursor.tenure != pending.tenure
            || cursor.last_attempt != pending.attempts
        {
            return Err(StoreError::BlobInvariant(
                "pending Blob delivery differs from its monotonic cursor",
            ));
        }
        rows.push(BlobDeliveryRetirementRow {
            pending_key: delivery_key.value().to_vec(),
            pending_value: encoded.value().to_vec(),
            cursor_key,
            cursor_value,
            subscription,
            subscription_incarnation: subscription_record.incarnation,
            acceptance_marker,
        });
    }
    Ok(Some(BlobDeliveryRetirementPlan {
        rows,
        transfer,
        reason,
    }))
}

fn charge_retirement_delivery_expiry_entry(
    charge: &mut (u64, u64),
    key: &[u8],
    value: &[u8],
) -> Result<(), StoreError> {
    charge.0 = charge
        .0
        .checked_add(1)
        .ok_or(StoreError::ItemCountAccountingOverflow)?;
    charge.1 = charge
        .1
        .checked_add(
            u64::try_from(key.len())
                .ok()
                .and_then(|bytes| bytes.checked_add(u64::try_from(value.len()).ok()?))
                .ok_or(StoreError::PayloadByteAccountingOverflow)?,
        )
        .ok_or(StoreError::PayloadByteAccountingOverflow)?;
    Ok(())
}

/// Computes the exact bounded delivery-ledger rows that publication retirement
/// expiry must remove.  Its result is used before the first destructive
/// removal so a short maintenance budget cannot split a publication unit.
struct BlobRetirementDeliveryExpiryPlan {
    charge: (u64, u64),
    retirement_primary_removals: Vec<([u8; 72], [u8; 80], [u8; 64])>,
    retirement_receipt_removals: Vec<([u8; 72], [u8; 64])>,
    acknowledgement_removals: Vec<Vec<u8>>,
    cursor_removals: Vec<Vec<u8>>,
}

fn blob_retirement_delivery_expiry_plan_write(
    write: &redb::WriteTransaction,
    transfer: BlobTransferId,
    semantic_id: BlobSemanticId,
) -> Result<BlobRetirementDeliveryExpiryPlan, StoreError> {
    let pending_count = write.open_table(BLOB_SUBSCRIPTION_PENDING)?.len()?;
    let acknowledgement_count = write.open_table(BLOB_DELIVERY_ACKNOWLEDGEMENTS)?.len()?;
    let cursor_count = write.open_table(BLOB_DELIVERY_CURSORS)?.len()?;
    let subscription_count = write.open_table(BLOB_SUBSCRIPTIONS)?.len()?;
    if subscription_count > MAX_BLOB_SUBSCRIPTIONS {
        return Err(StoreError::BlobInvariant(
            "Blob subscription rows exceed the bounded selected profile",
        ));
    }
    require_blob_subscription_accounting(
        write,
        subscription_count,
        pending_count,
        acknowledgement_count,
        cursor_count,
    )?;

    let (retirement_reason, retirement_generation) =
        blob_subscription_retirement_write(write, transfer)?.ok_or(StoreError::BlobInvariant(
            "Blob retirement-delivery expiry requires retained publication evidence",
        ))?;
    let mut charge = (0u64, 0u64);
    let mut retirement_primary_removals = Vec::new();
    let mut retirement_receipt_removals = Vec::new();
    let mut owner_start = [0u8; 64];
    owner_start[..32].copy_from_slice(transfer.as_bytes());
    let mut owner_end = [0xff; 64];
    owner_end[..32].copy_from_slice(transfer.as_bytes());
    for row in write
        .open_table(BLOB_RETIREMENT_DELIVERY_OWNERS)?
        .range::<&[u8]>((
            std::ops::Bound::Included(owner_start.as_slice()),
            std::ops::Bound::Included(owner_end.as_slice()),
        ))?
    {
        let (owner_key, primary_key) = row?;
        let primary_key: [u8; 72] = primary_key.value().try_into().map_err(|_| {
            StoreError::BlobInvariant("Blob retirement-delivery owner value has invalid length")
        })?;
        if blob_retirement_delivery_owner_key(transfer, &primary_key).as_slice()
            != owner_key.value()
        {
            return Err(StoreError::BlobInvariant(
                "Blob retirement-delivery owner is not canonical",
            ));
        }
        let (subscription, owner_semantic, generation) =
            parse_blob_retirement_delivery_key(&primary_key)?;
        if owner_semantic != semantic_id || generation != retirement_generation {
            return Err(StoreError::BlobInvariant(
                "Blob retirement-delivery owner differs from publication evidence",
            ));
        }
        let active = match write
            .open_table(BLOB_RETIREMENT_DELIVERIES)?
            .get(primary_key.as_slice())?
        {
            Some(value) => Some((
                value.value().to_vec(),
                decode_blob_retirement_delivery_record(value.value())?,
            )),
            None => None,
        };
        let receipt = match write
            .open_table(BLOB_RETIREMENT_ACKNOWLEDGEMENTS)?
            .get(primary_key.as_slice())?
        {
            Some(value) => Some((
                value.value().to_vec(),
                decode_blob_retirement_acknowledgement_record(value.value())?,
            )),
            None => None,
        };
        match (active, receipt) {
            (Some((active_bytes, active)), None) => {
                if active.reason != retirement_reason {
                    return Err(StoreError::BlobInvariant(
                        "Blob retirement delivery reason differs from publication evidence",
                    ));
                }
                let order_key = blob_retirement_delivery_order_key(
                    subscription,
                    active.acceptance_marker,
                    semantic_id,
                    generation,
                );
                let order_table = write.open_table(BLOB_RETIREMENT_DELIVERY_ORDER)?;
                let order =
                    order_table
                        .get(order_key.as_slice())?
                        .ok_or(StoreError::BlobInvariant(
                            "active Blob retirement delivery is missing its order row",
                        ))?;
                if !order.value().is_empty() {
                    return Err(StoreError::BlobInvariant(
                        "Blob retirement-delivery order value is not empty",
                    ));
                }
                charge_retirement_delivery_expiry_entry(&mut charge, &primary_key, &active_bytes)?;
                charge_retirement_delivery_expiry_entry(&mut charge, &order_key, &[])?;
                charge_retirement_delivery_expiry_entry(
                    &mut charge,
                    owner_key.value(),
                    &primary_key,
                )?;
                retirement_primary_removals.push((
                    primary_key,
                    order_key,
                    owner_key.value().try_into().expect("fixed owner key"),
                ));
            }
            (None, Some((receipt_bytes, receipt))) => {
                if receipt.retirement_generation != generation {
                    return Err(StoreError::BlobInvariant(
                        "Blob retirement acknowledgement differs from publication evidence",
                    ));
                }
                charge_retirement_delivery_expiry_entry(&mut charge, &primary_key, &receipt_bytes)?;
                charge_retirement_delivery_expiry_entry(
                    &mut charge,
                    owner_key.value(),
                    &primary_key,
                )?;
                retirement_receipt_removals.push((
                    primary_key,
                    owner_key.value().try_into().expect("fixed owner key"),
                ));
            }
            _ => {
                return Err(StoreError::BlobInvariant(
                    "Blob retirement-delivery owner must reference exactly one ledger row",
                ));
            }
        }
    }

    let acknowledgements = write.open_table(BLOB_DELIVERY_ACKNOWLEDGEMENTS)?;
    let cursors = write.open_table(BLOB_DELIVERY_CURSORS)?;
    let mut acknowledgement_removals = Vec::new();
    let mut cursor_removals = Vec::new();
    for row in write.open_table(BLOB_SUBSCRIPTIONS)?.iter()? {
        let (key, value) = row?;
        let subscription = parse_blob_subscription_id(key.value())?;
        decode_blob_subscription_record(value.value())?;
        charge_retirement_delivery_expiry_entry(&mut charge, key.value(), value.value())?;

        let acknowledgement_key = blob_acknowledgement_key(subscription, semantic_id);
        if let Some(value) = acknowledgements.get(acknowledgement_key.as_slice())? {
            decode_blob_acknowledgement_record(value.value())?;
            charge_retirement_delivery_expiry_entry(
                &mut charge,
                acknowledgement_key.as_slice(),
                value.value(),
            )?;
            acknowledgement_removals.push(acknowledgement_key.to_vec());
        }

        let cursor_key = blob_delivery_cursor_key(subscription, semantic_id);
        if let Some(value) = cursors.get(cursor_key.as_slice())? {
            decode_blob_delivery_cursor_record(value.value())?;
            charge_retirement_delivery_expiry_entry(
                &mut charge,
                cursor_key.as_slice(),
                value.value(),
            )?;
            cursor_removals.push(cursor_key.to_vec());
        }
    }
    Ok(BlobRetirementDeliveryExpiryPlan {
        charge,
        retirement_primary_removals,
        retirement_receipt_removals,
        acknowledgement_removals,
        cursor_removals,
    })
}

pub(crate) fn blob_retirement_delivery_expiry_charge_write(
    write: &redb::WriteTransaction,
    transfer: BlobTransferId,
    semantic_id: BlobSemanticId,
) -> Result<(u64, u64), StoreError> {
    Ok(blob_retirement_delivery_expiry_plan_write(write, transfer, semantic_id)?.charge)
}

/// Removes the delivery ledger that is meaningful only while one compact
/// publication-retirement row remains addressable.  The caller keeps the
/// publication row available until this transaction has validated and removed
/// every dependent row.
pub(crate) fn expire_blob_retirement_deliveries_write(
    write: &redb::WriteTransaction,
    transfer: BlobTransferId,
    semantic_id: BlobSemanticId,
) -> Result<(u64, u64), StoreError> {
    let plan = blob_retirement_delivery_expiry_plan_write(write, transfer, semantic_id)?;
    let charge = plan.charge;
    let pending_count = write.open_table(BLOB_SUBSCRIPTION_PENDING)?.len()?;
    let acknowledgement_count = write.open_table(BLOB_DELIVERY_ACKNOWLEDGEMENTS)?.len()?;
    let cursor_count = write.open_table(BLOB_DELIVERY_CURSORS)?.len()?;
    let subscription_count = write.open_table(BLOB_SUBSCRIPTIONS)?.len()?;
    require_blob_subscription_accounting(
        write,
        subscription_count,
        pending_count,
        acknowledgement_count,
        cursor_count,
    )?;

    for (primary, order, owner) in &plan.retirement_primary_removals {
        if write
            .open_table(BLOB_RETIREMENT_DELIVERIES)?
            .remove(primary.as_slice())?
            .is_none()
            || write
                .open_table(BLOB_RETIREMENT_DELIVERY_ORDER)?
                .remove(order.as_slice())?
                .is_none()
            || write
                .open_table(BLOB_RETIREMENT_DELIVERY_OWNERS)?
                .remove(owner.as_slice())?
                .is_none()
        {
            return Err(StoreError::BlobInvariant(
                "active Blob retirement delivery disappeared during expiry",
            ));
        }
    }
    for (receipt, owner) in &plan.retirement_receipt_removals {
        if write
            .open_table(BLOB_RETIREMENT_ACKNOWLEDGEMENTS)?
            .remove(receipt.as_slice())?
            .is_none()
            || write
                .open_table(BLOB_RETIREMENT_DELIVERY_OWNERS)?
                .remove(owner.as_slice())?
                .is_none()
        {
            return Err(StoreError::BlobInvariant(
                "acknowledged Blob retirement delivery disappeared during expiry",
            ));
        }
    }
    {
        let mut acknowledgements = write.open_table(BLOB_DELIVERY_ACKNOWLEDGEMENTS)?;
        for key in &plan.acknowledgement_removals {
            if acknowledgements.remove(key.as_slice())?.is_none() {
                return Err(StoreError::BlobInvariant(
                    "Blob acknowledgement disappeared during retirement expiry",
                ));
            }
        }
    }
    {
        let mut cursors = write.open_table(BLOB_DELIVERY_CURSORS)?;
        for key in &plan.cursor_removals {
            if cursors.remove(key.as_slice())?.is_none() {
                return Err(StoreError::BlobInvariant(
                    "Blob delivery cursor disappeared during retirement expiry",
                ));
            }
        }
    }

    let removed_acknowledgements = u64::try_from(plan.acknowledgement_removals.len())
        .map_err(|_| StoreError::ItemCountAccountingOverflow)?;
    let removed_cursors = u64::try_from(plan.cursor_removals.len())
        .map_err(|_| StoreError::ItemCountAccountingOverflow)?;
    let after = blob_retirement_ledger_counts_write(write)?;
    let mut metadata = write.open_table(METADATA)?;
    metadata.insert(
        BLOB_PENDING_DELIVERY_COUNT,
        pending_count
            .checked_add(after.deliveries)
            .ok_or(StoreError::ItemCountAccountingOverflow)?,
    )?;
    metadata.insert(
        BLOB_ACKNOWLEDGEMENT_COUNT,
        acknowledgement_count
            .checked_sub(removed_acknowledgements)
            .ok_or(StoreError::BlobInvariant(
                "Blob acknowledgement accounting underflows on retirement expiry",
            ))?
            .checked_add(after.acknowledgements)
            .ok_or(StoreError::ItemCountAccountingOverflow)?,
    )?;
    metadata.insert(
        BLOB_DELIVERY_CURSOR_COUNT,
        cursor_count
            .checked_sub(removed_cursors)
            .ok_or(StoreError::BlobInvariant(
                "Blob delivery-cursor accounting underflows on retirement expiry",
            ))?,
    )?;
    metadata.insert(BLOB_RETIREMENT_DELIVERY_COUNT, after.deliveries)?;
    metadata.insert(BLOB_RETIREMENT_DELIVERY_ORDER_COUNT, after.order)?;
    metadata.insert(
        BLOB_RETIREMENT_ACKNOWLEDGEMENT_COUNT,
        after.acknowledgements,
    )?;
    metadata.insert(BLOB_RETIREMENT_DELIVERY_OWNER_COUNT, after.owners)?;
    Ok(charge)
}

fn blob_acknowledgement_key(
    subscription: BlobSubscriptionId,
    semantic_id: BlobSemanticId,
) -> [u8; 64] {
    let mut key = [0u8; 64];
    key[..32].copy_from_slice(subscription.as_bytes());
    key[32..].copy_from_slice(semantic_id.as_bytes());
    key
}

fn parse_blob_acknowledgement_key(
    bytes: &[u8],
) -> Result<(BlobSubscriptionId, BlobSemanticId), StoreError> {
    let bytes: [u8; 64] = bytes
        .try_into()
        .map_err(|_| StoreError::BlobInvariant("Blob acknowledgement key has invalid length"))?;
    Ok((
        BlobSubscriptionId::from_bytes(
            bytes[..32]
                .try_into()
                .expect("fixed Blob subscription prefix"),
        ),
        BlobSemanticId::new(bytes[32..].try_into().expect("fixed semantic suffix")),
    ))
}

fn blob_delivery_cursor_key(
    subscription: BlobSubscriptionId,
    semantic_id: BlobSemanticId,
) -> [u8; 64] {
    blob_acknowledgement_key(subscription, semantic_id)
}

fn parse_blob_delivery_cursor_key(
    bytes: &[u8],
) -> Result<(BlobSubscriptionId, BlobSemanticId), StoreError> {
    parse_blob_acknowledgement_key(bytes)
}

fn encode_blob_acknowledgement_record(record: BlobAcknowledgementRecord) -> Vec<u8> {
    let mut encoded = Vec::with_capacity(25);
    encoded.push(BLOB_ACKNOWLEDGEMENT_VERSION);
    encoded.extend_from_slice(&record.acceptance_marker.to_be_bytes());
    encoded.extend_from_slice(&record.tenure.to_be_bytes());
    encoded.extend_from_slice(&record.attempts.to_be_bytes());
    encoded
}

fn decode_blob_acknowledgement_record(
    bytes: &[u8],
) -> Result<BlobAcknowledgementRecord, StoreError> {
    let mut cursor = MetadataCursor::new(bytes);
    if cursor.u8()? != BLOB_ACKNOWLEDGEMENT_VERSION {
        return Err(StoreError::BlobInvariant(
            "unknown Blob acknowledgement encoding version",
        ));
    }
    let acceptance_marker = cursor.u64()?;
    let tenure = cursor.u64()?;
    let attempts = cursor.u64()?;
    cursor.finish()?;
    if acceptance_marker == 0 || tenure == 0 || attempts == 0 {
        return Err(StoreError::BlobInvariant(
            "Blob acknowledgement contains a zero marker, tenure, or attempt",
        ));
    }
    Ok(BlobAcknowledgementRecord {
        acceptance_marker,
        tenure,
        attempts,
    })
}

fn encode_blob_delivery_cursor_record(record: BlobDeliveryCursorRecord) -> Vec<u8> {
    let mut encoded = Vec::with_capacity(41);
    encoded.push(BLOB_DELIVERY_CURSOR_VERSION);
    encoded.extend_from_slice(&record.acceptance_marker.to_be_bytes());
    encoded.extend_from_slice(&record.tenure.to_be_bytes());
    encoded.extend_from_slice(&record.last_attempt.to_be_bytes());
    encoded.extend_from_slice(&record.last_acknowledged_tenure.to_be_bytes());
    encoded.extend_from_slice(&record.last_acknowledged_attempt.to_be_bytes());
    encoded
}

fn decode_blob_delivery_cursor_record(
    bytes: &[u8],
) -> Result<BlobDeliveryCursorRecord, StoreError> {
    let mut cursor = MetadataCursor::new(bytes);
    if cursor.u8()? != BLOB_DELIVERY_CURSOR_VERSION {
        return Err(StoreError::BlobInvariant(
            "unknown Blob delivery-cursor encoding version",
        ));
    }
    let record = BlobDeliveryCursorRecord {
        acceptance_marker: cursor.u64()?,
        tenure: cursor.u64()?,
        last_attempt: cursor.u64()?,
        last_acknowledged_tenure: cursor.u64()?,
        last_acknowledged_attempt: cursor.u64()?,
    };
    cursor.finish()?;
    if record.acceptance_marker == 0 || record.tenure == 0 || record.last_attempt == 0 {
        return Err(StoreError::BlobInvariant(
            "Blob delivery cursor contains a zero marker, tenure, or attempt",
        ));
    }
    if (record.last_acknowledged_tenure == 0) != (record.last_acknowledged_attempt == 0)
        || record.last_acknowledged_tenure > record.tenure
        || (record.last_acknowledged_tenure == record.tenure
            && record.last_acknowledged_attempt > record.last_attempt)
    {
        return Err(StoreError::BlobInvariant(
            "Blob delivery cursor contains an invalid acknowledgement high-water",
        ));
    }
    Ok(record)
}

fn load_blob_by_semantic_from_read(
    read: &redb::ReadTransaction,
    semantic_id: BlobSemanticId,
) -> Result<Option<BlobSubscriptionIdentity>, StoreError> {
    blob_subscription_identity_read(read, semantic_id)
}

fn load_blob_by_semantic_from_write(
    write: &redb::WriteTransaction,
    semantic_id: BlobSemanticId,
) -> Result<Option<BlobSubscriptionIdentity>, StoreError> {
    blob_subscription_identity_write(write, semantic_id)
}

fn validate_blob_selector_generation(
    generation: u64,
    subscription_count: u64,
) -> Result<(), StoreError> {
    if generation < subscription_count || !(generation - subscription_count).is_multiple_of(2) {
        return Err(StoreError::BlobInvariant(
            "Blob selector mutation generation is inconsistent with the live subscription count",
        ));
    }
    Ok(())
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
struct BlobRetirementLedgerCounts {
    deliveries: u64,
    order: u64,
    acknowledgements: u64,
    owners: u64,
}

fn blob_retirement_ledger_counts_write(
    write: &redb::WriteTransaction,
) -> Result<BlobRetirementLedgerCounts, StoreError> {
    Ok(BlobRetirementLedgerCounts {
        deliveries: write.open_table(BLOB_RETIREMENT_DELIVERIES)?.len()?,
        order: write.open_table(BLOB_RETIREMENT_DELIVERY_ORDER)?.len()?,
        acknowledgements: write.open_table(BLOB_RETIREMENT_ACKNOWLEDGEMENTS)?.len()?,
        owners: write.open_table(BLOB_RETIREMENT_DELIVERY_OWNERS)?.len()?,
    })
}

fn require_blob_retirement_accounting(
    metadata: &impl ReadableTable<&'static str, u64>,
    counts: BlobRetirementLedgerCounts,
) -> Result<(), StoreError> {
    for (field, reconstructed) in [
        (BLOB_RETIREMENT_DELIVERY_COUNT, counts.deliveries),
        (BLOB_RETIREMENT_DELIVERY_ORDER_COUNT, counts.order),
        (
            BLOB_RETIREMENT_ACKNOWLEDGEMENT_COUNT,
            counts.acknowledgements,
        ),
        (BLOB_RETIREMENT_DELIVERY_OWNER_COUNT, counts.owners),
    ] {
        let durable = metadata
            .get(field)?
            .ok_or(StoreError::MissingAccountingMetadata { field })?
            .value();
        if durable != reconstructed {
            return Err(StoreError::AccountingMismatch {
                field,
                durable,
                reconstructed,
            });
        }
    }
    Ok(())
}

fn require_blob_subscription_accounting(
    write: &redb::WriteTransaction,
    subscriptions: u64,
    pending: u64,
    acknowledgements: u64,
    cursors: u64,
) -> Result<u64, StoreError> {
    let retirement = blob_retirement_ledger_counts_write(write)?;
    let pending = pending
        .checked_add(retirement.deliveries)
        .ok_or(StoreError::ItemCountAccountingOverflow)?;
    let acknowledgements = acknowledgements
        .checked_add(retirement.acknowledgements)
        .ok_or(StoreError::ItemCountAccountingOverflow)?;
    let metadata = write.open_table(METADATA)?;
    require_blob_retirement_accounting(&metadata, retirement)?;
    for (field, reconstructed) in [
        (BLOB_SUBSCRIPTION_COUNT, subscriptions),
        (BLOB_PENDING_DELIVERY_COUNT, pending),
        (BLOB_ACKNOWLEDGEMENT_COUNT, acknowledgements),
        (BLOB_DELIVERY_CURSOR_COUNT, cursors),
    ] {
        let durable = metadata
            .get(field)?
            .ok_or(StoreError::MissingAccountingMetadata { field })?
            .value();
        if durable != reconstructed {
            return Err(StoreError::AccountingMismatch {
                field,
                durable,
                reconstructed,
            });
        }
    }
    let generation = metadata
        .get(BLOB_SELECTOR_GENERATION)?
        .ok_or(StoreError::MissingAccountingMetadata {
            field: BLOB_SELECTOR_GENERATION,
        })?
        .value();
    validate_blob_selector_generation(generation, subscriptions)?;
    Ok(generation)
}

fn is_blob_subscription_table(name: &str) -> bool {
    name == BLOB_ACCEPTANCE_ORDER.name()
        || name == BLOB_SUBSCRIPTIONS.name()
        || name == BLOB_SUBSCRIPTION_PENDING.name()
        || name == BLOB_DELIVERY_ACKNOWLEDGEMENTS.name()
        || name == BLOB_DELIVERY_CURSORS.name()
        || name == BLOB_RETIREMENT_DELIVERIES.name()
        || name == BLOB_RETIREMENT_DELIVERY_ORDER.name()
        || name == BLOB_RETIREMENT_ACKNOWLEDGEMENTS.name()
        || name == BLOB_RETIREMENT_DELIVERY_OWNERS.name()
}

pub(crate) fn audit_blob_subscription_tables(
    write: &redb::WriteTransaction,
) -> Result<BlobSubscriptionStats, StoreError> {
    if write
        .list_multimap_tables()?
        .any(|table| is_blob_subscription_table(table.name()))
    {
        return Err(StoreError::BlobInvariant(
            "Blob subscription schema has the wrong table kind",
        ));
    }
    let table_names = write
        .list_tables()?
        .map(|table| table.name().to_owned())
        .collect::<BTreeSet<_>>();
    let base_tables_present = [
        BLOB_ACCEPTANCE_ORDER.name(),
        BLOB_SUBSCRIPTIONS.name(),
        BLOB_SUBSCRIPTION_PENDING.name(),
        BLOB_DELIVERY_ACKNOWLEDGEMENTS.name(),
        BLOB_DELIVERY_CURSORS.name(),
    ]
    .into_iter()
    .filter(|name| table_names.contains(*name))
    .count();
    let retirement_tables_present = [
        BLOB_RETIREMENT_DELIVERIES.name(),
        BLOB_RETIREMENT_DELIVERY_ORDER.name(),
        BLOB_RETIREMENT_ACKNOWLEDGEMENTS.name(),
        BLOB_RETIREMENT_DELIVERY_OWNERS.name(),
    ]
    .into_iter()
    .filter(|name| table_names.contains(*name))
    .count();
    let (metadata_presence, retirement_metadata_presence) = {
        let metadata = write.open_table(METADATA)?;
        (
            [
                metadata.get(BLOB_SUBSCRIPTION_COUNT)?.is_some(),
                metadata.get(BLOB_PENDING_DELIVERY_COUNT)?.is_some(),
                metadata.get(BLOB_ACKNOWLEDGEMENT_COUNT)?.is_some(),
                metadata.get(BLOB_DELIVERY_CURSOR_COUNT)?.is_some(),
                metadata.get(BLOB_SELECTOR_GENERATION)?.is_some(),
            ],
            [
                metadata.get(BLOB_RETIREMENT_DELIVERY_COUNT)?.is_some(),
                metadata
                    .get(BLOB_RETIREMENT_DELIVERY_ORDER_COUNT)?
                    .is_some(),
                metadata
                    .get(BLOB_RETIREMENT_ACKNOWLEDGEMENT_COUNT)?
                    .is_some(),
                metadata
                    .get(BLOB_RETIREMENT_DELIVERY_OWNER_COUNT)?
                    .is_some(),
            ],
        )
    };
    let metadata_present = metadata_presence.iter().filter(|present| **present).count();
    let retirement_metadata_present = retirement_metadata_presence
        .iter()
        .filter(|present| **present)
        .count();
    if base_tables_present == 0
        && metadata_present == 0
        && retirement_tables_present == 0
        && retirement_metadata_present == 0
    {
        crate::require_new_store_write(write)?;
        write.open_table(BLOB_ACCEPTANCE_ORDER)?;
        write.open_table(BLOB_SUBSCRIPTIONS)?;
        write.open_table(BLOB_SUBSCRIPTION_PENDING)?;
        write.open_table(BLOB_DELIVERY_ACKNOWLEDGEMENTS)?;
        write.open_table(BLOB_DELIVERY_CURSORS)?;
        write.open_table(BLOB_RETIREMENT_DELIVERIES)?;
        write.open_table(BLOB_RETIREMENT_DELIVERY_ORDER)?;
        write.open_table(BLOB_RETIREMENT_ACKNOWLEDGEMENTS)?;
        write.open_table(BLOB_RETIREMENT_DELIVERY_OWNERS)?;
        let mut metadata = write.open_table(METADATA)?;
        metadata.insert(BLOB_SUBSCRIPTION_COUNT, 0)?;
        metadata.insert(BLOB_PENDING_DELIVERY_COUNT, 0)?;
        metadata.insert(BLOB_ACKNOWLEDGEMENT_COUNT, 0)?;
        metadata.insert(BLOB_DELIVERY_CURSOR_COUNT, 0)?;
        metadata.insert(BLOB_SELECTOR_GENERATION, 0)?;
        metadata.insert(BLOB_RETIREMENT_DELIVERY_COUNT, 0)?;
        metadata.insert(BLOB_RETIREMENT_DELIVERY_ORDER_COUNT, 0)?;
        metadata.insert(BLOB_RETIREMENT_ACKNOWLEDGEMENT_COUNT, 0)?;
        metadata.insert(BLOB_RETIREMENT_DELIVERY_OWNER_COUNT, 0)?;
        drop(metadata);
        audit_blob_acceptance_order_write(write)?;
        return audit_blob_subscription_rows_write(write);
    }
    if base_tables_present != 5 || metadata_presence.iter().any(|present| !present) {
        return Err(StoreError::BlobInvariant(
            "Blob subscription schema group is incomplete",
        ));
    }
    if retirement_tables_present != 4 || retirement_metadata_presence.iter().any(|present| !present)
    {
        return Err(StoreError::BlobInvariant(
            "Blob retirement-delivery schema group is incomplete",
        ));
    }
    audit_blob_acceptance_order_write(write)?;
    audit_blob_subscription_rows_write(write)
}

fn live_blob_publication_rows(
    publications: &impl ReadableTable<&'static [u8], &'static [u8]>,
) -> Result<u64, StoreError> {
    let mut live = 0u64;
    for row in publications.iter()? {
        let (_, value) = row?;
        if !crate::blob::lifecycle::publication_record_is_retired(value.value())
            .map_err(StoreError::Blob)?
        {
            live = live
                .checked_add(1)
                .ok_or(StoreError::ItemCountAccountingOverflow)?;
        }
    }
    Ok(live)
}

fn publication_is_live(
    publications: &impl ReadableTable<&'static [u8], &'static [u8]>,
    transfer: BlobTransferId,
) -> Result<bool, StoreError> {
    let Some(publication) = publications.get(transfer.as_bytes().as_slice())? else {
        return Ok(false);
    };
    crate::blob::lifecycle::publication_record_is_retired(publication.value())
        .map(|retired| !retired)
        .map_err(StoreError::Blob)
}

fn retired_acceptance_markers(
    publications: &impl ReadableTable<&'static [u8], &'static [u8]>,
) -> Result<BTreeSet<u64>, StoreError> {
    let mut markers = BTreeSet::new();
    for row in publications.iter()? {
        let (_, value) = row?;
        if let Some((marker, _)) =
            crate::blob::lifecycle::retired_publication_payload(value.value())
                .map_err(StoreError::Blob)?
            && !markers.insert(marker)
        {
            return Err(StoreError::BlobInvariant(
                "retired Blob acceptance marker is reused",
            ));
        }
    }
    Ok(markers)
}

fn audit_blob_acceptance_order_write(write: &redb::WriteTransaction) -> Result<(), StoreError> {
    let order = write.open_table(BLOB_ACCEPTANCE_ORDER)?;
    let markers = write.open_table(BLOB_ACCEPTANCE_MARKERS)?;
    let publications = write.open_table(BLOB_PUBLICATIONS)?;
    if order.len()? != markers.len()? || order.len()? != live_blob_publication_rows(&publications)?
    {
        return Err(StoreError::BlobInvariant(
            "Blob acceptance-order index has missing or orphan rows",
        ));
    }
    let mut all_markers = retired_acceptance_markers(&publications)?;
    for row in order.iter()? {
        let (marker, transfer) = row?;
        let marker = marker.value();
        let transfer = parse_blob_subscription_transfer_id(transfer.value())?;
        if !all_markers.insert(marker)
            || !publication_is_live(&publications, transfer)?
            || markers
                .get(transfer.as_bytes().as_slice())?
                .map(|value| value.value())
                != Some(marker)
        {
            return Err(StoreError::BlobInvariant(
                "Blob acceptance-order index differs from its forward authority",
            ));
        }
    }
    let high_water = write
        .open_table(METADATA)?
        .get(LAST_BLOB_ACCEPTANCE_MARKER)?
        .ok_or(StoreError::MissingAccountingMetadata {
            field: LAST_BLOB_ACCEPTANCE_MARKER,
        })?
        .value();
    if all_markers
        .iter()
        .any(|marker| *marker == 0 || *marker > high_water)
    {
        return Err(StoreError::BlobInvariant(
            "Blob acceptance history exceeds its durable high-water",
        ));
    }
    Ok(())
}

fn audit_blob_subscription_rows_write(
    write: &redb::WriteTransaction,
) -> Result<BlobSubscriptionStats, StoreError> {
    let authority = read_mission_binding(write)?;
    let mut subscriptions = BTreeMap::new();
    for row in write.open_table(BLOB_SUBSCRIPTIONS)?.iter()? {
        let (key, value) = row?;
        let id = parse_blob_subscription_id(key.value())?;
        let record = decode_blob_subscription_record(value.value())?;
        let authority = authority.ok_or(StoreError::BlobInvariant(
            "unbound store contains Blob subscriptions",
        ))?;
        if blob_subscription_id(authority, &record.operation_key) != id {
            return Err(StoreError::BlobInvariant(
                "Blob subscription identifier differs from its operation key",
            ));
        }
        subscriptions.insert(id, record);
    }
    let content_ids = audit_blob_subscription_ledgers_write(write, &subscriptions)?;
    let retirement_ids = audit_blob_retirement_ledgers_write(write, &subscriptions)?;
    require_blob_delivery_families_disjoint(&content_ids, &retirement_ids)?;
    let retirement = blob_retirement_ledger_counts_write(write)?;
    let stats = BlobSubscriptionStats {
        subscriptions: write.open_table(BLOB_SUBSCRIPTIONS)?.len()?,
        pending_deliveries: write
            .open_table(BLOB_SUBSCRIPTION_PENDING)?
            .len()?
            .checked_add(retirement.deliveries)
            .ok_or(StoreError::ItemCountAccountingOverflow)?,
        acknowledged_deliveries: write
            .open_table(BLOB_DELIVERY_ACKNOWLEDGEMENTS)?
            .len()?
            .checked_add(retirement.acknowledgements)
            .ok_or(StoreError::ItemCountAccountingOverflow)?,
        delivery_cursors: write.open_table(BLOB_DELIVERY_CURSORS)?.len()?,
        selector_generation: write
            .open_table(METADATA)?
            .get(BLOB_SELECTOR_GENERATION)?
            .ok_or(StoreError::MissingAccountingMetadata {
                field: BLOB_SELECTOR_GENERATION,
            })?
            .value(),
    };
    validate_blob_subscription_incarnations(&subscriptions, stats.selector_generation)?;
    validate_blob_subscription_stats(write, stats)?;
    Ok(stats)
}

fn validate_blob_subscription_incarnations(
    subscriptions: &BTreeMap<BlobSubscriptionId, BlobSubscriptionRecord>,
    selector_generation: u64,
) -> Result<(), StoreError> {
    let mut incarnations = BTreeSet::new();
    for record in subscriptions.values() {
        if record.incarnation == 0
            || record.incarnation > selector_generation
            || !incarnations.insert(record.incarnation)
        {
            return Err(StoreError::BlobInvariant(
                "Blob subscription incarnation is invalid or reused",
            ));
        }
    }
    Ok(())
}

fn audit_blob_subscription_ledgers_write(
    write: &redb::WriteTransaction,
    subscriptions: &BTreeMap<BlobSubscriptionId, BlobSubscriptionRecord>,
) -> Result<BTreeSet<(BlobSubscriptionId, BlobSemanticId)>, StoreError> {
    let mut pending_records = BTreeMap::new();
    for row in write.open_table(BLOB_SUBSCRIPTION_PENDING)?.iter()? {
        let (key, value) = row?;
        let (subscription, marker) = parse_blob_pending_delivery_key(key.value())?;
        let record = decode_blob_delivery_record(value.value())?;
        let semantic_id = match record {
            BlobDeliveryRecord::Pending(record) => record.semantic_id,
            BlobDeliveryRecord::Retired(record) => record.semantic_id,
        };
        let spec = &subscriptions
            .get(&subscription)
            .ok_or(StoreError::BlobInvariant(
                "pending Blob delivery references a missing subscription",
            ))?
            .spec;
        let blob = load_blob_by_semantic_from_write(write, semantic_id)?.ok_or(
            StoreError::BlobInvariant("pending Blob delivery references a missing Blob"),
        )?;
        if blob.acceptance_marker != marker || !spec.matches_identity(&blob) {
            return Err(StoreError::BlobInvariant(
                "pending Blob delivery differs from its subscription ledger",
            ));
        }
        let id = (subscription, semantic_id);
        match record {
            BlobDeliveryRecord::Pending(record) => {
                if pending_records.insert(id, record).is_some() {
                    return Err(StoreError::BlobInvariant(
                        "duplicate pending Blob semantic delivery",
                    ));
                }
            }
            BlobDeliveryRecord::Retired(record) => {
                let _ = record;
                return Err(StoreError::BlobInvariant(
                    "current Blob subscription ledger contains predecessor retirement state",
                ));
            }
        }
    }
    let mut acknowledgement_records = BTreeMap::new();
    for row in write.open_table(BLOB_DELIVERY_ACKNOWLEDGEMENTS)?.iter()? {
        let (key, value) = row?;
        let (subscription, semantic_id) = parse_blob_acknowledgement_key(key.value())?;
        let record = decode_blob_acknowledgement_record(value.value())?;
        let spec = &subscriptions
            .get(&subscription)
            .ok_or(StoreError::BlobInvariant(
                "Blob acknowledgement references a missing subscription",
            ))?
            .spec;
        let blob = load_blob_by_semantic_from_write(write, semantic_id)?.ok_or(
            StoreError::BlobInvariant("Blob acknowledgement references a missing Blob"),
        )?;
        if blob.acceptance_marker != record.acceptance_marker || !spec.matches_identity(&blob) {
            return Err(StoreError::BlobInvariant(
                "Blob acknowledgement differs from its subscription ledger",
            ));
        }
        if pending_records.contains_key(&(subscription, semantic_id)) {
            return Err(StoreError::BlobInvariant(
                "Blob delivery is both pending and acknowledged",
            ));
        }
        acknowledgement_records.insert((subscription, semantic_id), record);
    }
    let mut cursor_ids = BTreeSet::new();
    for row in write.open_table(BLOB_DELIVERY_CURSORS)?.iter()? {
        let (key, value) = row?;
        let (subscription, semantic_id) = parse_blob_delivery_cursor_key(key.value())?;
        let cursor = decode_blob_delivery_cursor_record(value.value())?;
        let spec = &subscriptions
            .get(&subscription)
            .ok_or(StoreError::BlobInvariant(
                "Blob delivery cursor references a missing subscription",
            ))?
            .spec;
        let blob = load_blob_by_semantic_from_write(write, semantic_id)?.ok_or(
            StoreError::BlobInvariant("Blob delivery cursor references a missing Blob"),
        )?;
        if !spec.matches_identity(&blob) {
            return Err(StoreError::BlobInvariant(
                "Blob delivery cursor differs from its subscription",
            ));
        }
        let id = (subscription, semantic_id);
        validate_blob_candidate_delivery_ledger(
            semantic_id,
            blob.acceptance_marker,
            pending_records.get(&id).copied(),
            acknowledgement_records.get(&id).copied(),
            Some(cursor),
        )?;
        cursor_ids.insert(id);
    }
    if pending_records
        .keys()
        .chain(acknowledgement_records.keys())
        .any(|id| !cursor_ids.contains(id))
    {
        return Err(StoreError::BlobInvariant(
            "active Blob delivery is missing its monotonic cursor",
        ));
    }
    Ok(cursor_ids)
}

fn audit_blob_retirement_ledgers_write(
    write: &redb::WriteTransaction,
    subscriptions: &BTreeMap<BlobSubscriptionId, BlobSubscriptionRecord>,
) -> Result<BTreeSet<(BlobSubscriptionId, BlobSemanticId)>, StoreError> {
    let deliveries = write.open_table(BLOB_RETIREMENT_DELIVERIES)?;
    let order = write.open_table(BLOB_RETIREMENT_DELIVERY_ORDER)?;
    let acknowledgements = write.open_table(BLOB_RETIREMENT_ACKNOWLEDGEMENTS)?;
    let owners = write.open_table(BLOB_RETIREMENT_DELIVERY_OWNERS)?;
    let mut retirement_ids = BTreeSet::new();
    for row in deliveries.iter()? {
        let (key, value) = row?;
        let primary: [u8; 72] = key.value().try_into().map_err(|_| {
            StoreError::BlobInvariant("Blob retirement-delivery key has invalid length")
        })?;
        let (subscription, semantic, generation) = parse_blob_retirement_delivery_key(&primary)?;
        if !retirement_ids.insert((subscription, semantic)) {
            return Err(StoreError::BlobInvariant(
                "Blob retirement delivery identity is duplicated",
            ));
        }
        let record = decode_blob_retirement_delivery_record(value.value())?;
        let subscription_record =
            subscriptions
                .get(&subscription)
                .ok_or(StoreError::BlobInvariant(
                    "Blob retirement delivery references a missing subscription",
                ))?;
        let identity =
            blob_subscription_identity_write(write, semantic)?.ok_or(StoreError::BlobInvariant(
                "Blob retirement delivery references missing publication evidence",
            ))?;
        if record.subscription_incarnation != subscription_record.incarnation
            || record.acceptance_marker != identity.acceptance_marker
            || !subscription_record.spec.matches_identity(&identity)
            || blob_subscription_retirement_write(write, identity.transfer_id)?
                != Some((record.reason, generation))
        {
            return Err(StoreError::BlobInvariant(
                "Blob retirement delivery differs from its authorities",
            ));
        }
        let order_key = blob_retirement_delivery_order_key(
            subscription,
            record.acceptance_marker,
            semantic,
            generation,
        );
        if order
            .get(order_key.as_slice())?
            .is_none_or(|value| !value.value().is_empty())
            || owners
                .get(blob_retirement_delivery_owner_key(identity.transfer_id, &primary).as_slice())?
                .is_none_or(|value| value.value() != primary.as_slice())
            || acknowledgements.get(primary.as_slice())?.is_some()
        {
            return Err(StoreError::BlobInvariant(
                "Blob retirement delivery is missing or conflicts with its inverse rows",
            ));
        }
    }
    for row in acknowledgements.iter()? {
        let (key, value) = row?;
        let primary: [u8; 72] = key.value().try_into().map_err(|_| {
            StoreError::BlobInvariant("Blob retirement-acknowledgement key has invalid length")
        })?;
        let (subscription, semantic, generation) = parse_blob_retirement_delivery_key(&primary)?;
        if !retirement_ids.insert((subscription, semantic)) {
            return Err(StoreError::BlobInvariant(
                "Blob retirement delivery identity is duplicated",
            ));
        }
        let receipt = decode_blob_retirement_acknowledgement_record(value.value())?;
        let subscription_record =
            subscriptions
                .get(&subscription)
                .ok_or(StoreError::BlobInvariant(
                    "Blob retirement acknowledgement references a missing subscription",
                ))?;
        let identity =
            blob_subscription_identity_write(write, semantic)?.ok_or(StoreError::BlobInvariant(
                "Blob retirement acknowledgement references missing publication evidence",
            ))?;
        if receipt.retirement_generation != generation
            || !subscription_record.spec.matches_identity(&identity)
            || blob_subscription_retirement_write(write, identity.transfer_id)?
                .is_none_or(|(_, current_generation)| current_generation != generation)
            || deliveries.get(primary.as_slice())?.is_some()
            || owners
                .get(blob_retirement_delivery_owner_key(identity.transfer_id, &primary).as_slice())?
                .is_none_or(|value| value.value() != primary.as_slice())
        {
            return Err(StoreError::BlobInvariant(
                "Blob retirement acknowledgement differs from its authorities",
            ));
        }
    }
    for row in order.iter()? {
        let (key, value) = row?;
        let (subscription, marker, semantic, generation) =
            parse_blob_retirement_delivery_order_key(key.value())?;
        let primary = blob_retirement_delivery_key(subscription, semantic, generation);
        let record = deliveries
            .get(primary.as_slice())?
            .map(|value| decode_blob_retirement_delivery_record(value.value()))
            .transpose()?
            .ok_or(StoreError::BlobInvariant(
                "Blob retirement-delivery order references a missing primary row",
            ))?;
        if !value.value().is_empty() || record.acceptance_marker != marker {
            return Err(StoreError::BlobInvariant(
                "Blob retirement-delivery order differs from its primary row",
            ));
        }
    }
    for row in owners.iter()? {
        let (key, value) = row?;
        let primary: [u8; 72] = value.value().try_into().map_err(|_| {
            StoreError::BlobInvariant("Blob retirement-delivery owner value has invalid length")
        })?;
        let (_, semantic, _) = parse_blob_retirement_delivery_key(&primary)?;
        let identity =
            blob_subscription_identity_write(write, semantic)?.ok_or(StoreError::BlobInvariant(
                "Blob retirement-delivery owner references missing publication evidence",
            ))?;
        if blob_retirement_delivery_owner_key(identity.transfer_id, &primary).as_slice()
            != key.value()
            || (deliveries.get(primary.as_slice())?.is_some()
                == acknowledgements.get(primary.as_slice())?.is_some())
        {
            return Err(StoreError::BlobInvariant(
                "Blob retirement-delivery owner differs from its primary or receipt",
            ));
        }
    }
    if deliveries.len()? != order.len()?
        || owners.len()?
            != deliveries
                .len()?
                .checked_add(acknowledgements.len()?)
                .ok_or(StoreError::ItemCountAccountingOverflow)?
    {
        return Err(StoreError::BlobInvariant(
            "Blob retirement-delivery ledgers are not one-for-one",
        ));
    }
    Ok(retirement_ids)
}

fn require_blob_delivery_families_disjoint(
    content_ids: &BTreeSet<(BlobSubscriptionId, BlobSemanticId)>,
    retirement_ids: &BTreeSet<(BlobSubscriptionId, BlobSemanticId)>,
) -> Result<(), StoreError> {
    if content_ids.is_disjoint(retirement_ids) {
        Ok(())
    } else {
        Err(StoreError::BlobInvariant(
            "Blob delivery identity exists in both content and retirement ledgers",
        ))
    }
}

fn validate_blob_subscription_stats(
    write: &redb::WriteTransaction,
    stats: BlobSubscriptionStats,
) -> Result<(), StoreError> {
    if stats.subscriptions > MAX_BLOB_SUBSCRIPTIONS
        || stats.pending_deliveries > MAX_BLOB_PENDING_DELIVERIES
        || stats.acknowledged_deliveries > MAX_BLOB_ACKNOWLEDGEMENT_RECEIPTS
        || stats
            .pending_deliveries
            .checked_add(stats.acknowledged_deliveries)
            .ok_or(StoreError::ItemCountAccountingOverflow)?
            > MAX_BLOB_ACKNOWLEDGEMENT_RECEIPTS
        || stats.delivery_cursors > MAX_BLOB_DELIVERY_CURSORS
    {
        return Err(StoreError::BlobInvariant(
            "Blob subscription tables exceed their bounded cardinality",
        ));
    }
    let retirement = blob_retirement_ledger_counts_write(write)?;
    require_blob_subscription_accounting(
        write,
        stats.subscriptions,
        stats
            .pending_deliveries
            .checked_sub(retirement.deliveries)
            .ok_or(StoreError::BlobInvariant(
                "Blob retirement pending count exceeds combined accounting",
            ))?,
        stats
            .acknowledged_deliveries
            .checked_sub(retirement.acknowledgements)
            .ok_or(StoreError::BlobInvariant(
                "Blob retirement acknowledgement count exceeds combined accounting",
            ))?,
        stats.delivery_cursors,
    )?;
    Ok(())
}

pub(crate) fn lifecycle_delivery_owners_write(
    write: &redb::WriteTransaction,
) -> Result<Vec<(BlobTransferId, Vec<u8>)>, StoreError> {
    let mut owners = Vec::new();
    for row in write.open_table(BLOB_SUBSCRIPTION_PENDING)?.iter()? {
        let (key, value) = row?;
        parse_blob_pending_delivery_key(key.value())?;
        let delivery = decode_blob_delivery_record(value.value())?;
        let semantic_id = match delivery {
            BlobDeliveryRecord::Pending(record) => record.semantic_id,
            BlobDeliveryRecord::Retired(record) => record.semantic_id,
        };
        let owner = blob_subscription_identity_write(write, semantic_id)?
            .ok_or(StoreError::BlobInvariant(
                "pending Blob delivery references a missing Blob",
            ))?
            .transfer_id;
        owners.push((owner, key.value().to_vec()));
    }
    Ok(owners)
}

pub(crate) fn lifecycle_delivery_owners_read(
    read: &redb::ReadTransaction,
) -> Result<Vec<(BlobTransferId, Vec<u8>)>, StoreError> {
    let table_names = read
        .list_tables()?
        .map(|table| table.name().to_owned())
        .collect::<BTreeSet<_>>();
    if !table_names.contains(BLOB_SUBSCRIPTION_PENDING.name()) {
        return Ok(Vec::new());
    }
    let mut owners = Vec::new();
    for row in read.open_table(BLOB_SUBSCRIPTION_PENDING)?.iter()? {
        let (key, value) = row?;
        parse_blob_pending_delivery_key(key.value())?;
        let delivery = decode_blob_delivery_record(value.value())?;
        let semantic_id = match delivery {
            BlobDeliveryRecord::Pending(record) => record.semantic_id,
            BlobDeliveryRecord::Retired(record) => record.semantic_id,
        };
        let owner = blob_subscription_identity_read(read, semantic_id)?
            .ok_or(StoreError::BlobInvariant(
                "pending Blob delivery references a missing Blob",
            ))?
            .transfer_id;
        owners.push((owner, key.value().to_vec()));
    }
    Ok(owners)
}

fn audit_blob_retirement_ledgers_read(
    read: &redb::ReadTransaction,
    subscriptions: &BTreeMap<BlobSubscriptionId, BlobSubscriptionRecord>,
) -> Result<BTreeSet<(BlobSubscriptionId, BlobSemanticId)>, StoreError> {
    let deliveries = read.open_table(BLOB_RETIREMENT_DELIVERIES)?;
    let order = read.open_table(BLOB_RETIREMENT_DELIVERY_ORDER)?;
    let acknowledgements = read.open_table(BLOB_RETIREMENT_ACKNOWLEDGEMENTS)?;
    let owners = read.open_table(BLOB_RETIREMENT_DELIVERY_OWNERS)?;
    let mut retirement_ids = BTreeSet::new();
    for row in deliveries.iter()? {
        let (key, value) = row?;
        let primary: [u8; 72] = key.value().try_into().map_err(|_| {
            StoreError::BlobInvariant("Blob retirement-delivery key has invalid length")
        })?;
        let (subscription, semantic, generation) = parse_blob_retirement_delivery_key(&primary)?;
        if !retirement_ids.insert((subscription, semantic)) {
            return Err(StoreError::BlobInvariant(
                "Blob retirement delivery identity is duplicated",
            ));
        }
        let record = decode_blob_retirement_delivery_record(value.value())?;
        let subscription_record =
            subscriptions
                .get(&subscription)
                .ok_or(StoreError::BlobInvariant(
                    "Blob retirement delivery references a missing subscription",
                ))?;
        let identity =
            blob_subscription_identity_read(read, semantic)?.ok_or(StoreError::BlobInvariant(
                "Blob retirement delivery references missing publication evidence",
            ))?;
        let order_key = blob_retirement_delivery_order_key(
            subscription,
            record.acceptance_marker,
            semantic,
            generation,
        );
        if record.subscription_incarnation != subscription_record.incarnation
            || record.acceptance_marker != identity.acceptance_marker
            || !subscription_record.spec.matches_identity(&identity)
            || blob_subscription_retirement_read(read, identity.transfer_id)?
                != Some((record.reason, generation))
            || order
                .get(order_key.as_slice())?
                .is_none_or(|value| !value.value().is_empty())
            || owners
                .get(blob_retirement_delivery_owner_key(identity.transfer_id, &primary).as_slice())?
                .is_none_or(|value| value.value() != primary.as_slice())
            || acknowledgements.get(primary.as_slice())?.is_some()
        {
            return Err(StoreError::BlobInvariant(
                "Blob retirement delivery differs from its authorities",
            ));
        }
    }
    for row in acknowledgements.iter()? {
        let (key, value) = row?;
        let primary: [u8; 72] = key.value().try_into().map_err(|_| {
            StoreError::BlobInvariant("Blob retirement-acknowledgement key has invalid length")
        })?;
        let (subscription, semantic, generation) = parse_blob_retirement_delivery_key(&primary)?;
        if !retirement_ids.insert((subscription, semantic)) {
            return Err(StoreError::BlobInvariant(
                "Blob retirement delivery identity is duplicated",
            ));
        }
        let receipt = decode_blob_retirement_acknowledgement_record(value.value())?;
        let subscription_record =
            subscriptions
                .get(&subscription)
                .ok_or(StoreError::BlobInvariant(
                    "Blob retirement acknowledgement references a missing subscription",
                ))?;
        let identity =
            blob_subscription_identity_read(read, semantic)?.ok_or(StoreError::BlobInvariant(
                "Blob retirement acknowledgement references missing publication evidence",
            ))?;
        if receipt.retirement_generation != generation
            || !subscription_record.spec.matches_identity(&identity)
            || blob_subscription_retirement_read(read, identity.transfer_id)?
                .is_none_or(|(_, current_generation)| current_generation != generation)
            || deliveries.get(primary.as_slice())?.is_some()
            || owners
                .get(blob_retirement_delivery_owner_key(identity.transfer_id, &primary).as_slice())?
                .is_none_or(|value| value.value() != primary.as_slice())
        {
            return Err(StoreError::BlobInvariant(
                "Blob retirement acknowledgement differs from its authorities",
            ));
        }
    }
    for row in order.iter()? {
        let (key, value) = row?;
        let (subscription, marker, semantic, generation) =
            parse_blob_retirement_delivery_order_key(key.value())?;
        let primary = blob_retirement_delivery_key(subscription, semantic, generation);
        let record = deliveries
            .get(primary.as_slice())?
            .map(|value| decode_blob_retirement_delivery_record(value.value()))
            .transpose()?
            .ok_or(StoreError::BlobInvariant(
                "Blob retirement-delivery order references a missing primary row",
            ))?;
        if !value.value().is_empty() || record.acceptance_marker != marker {
            return Err(StoreError::BlobInvariant(
                "Blob retirement-delivery order differs from its primary row",
            ));
        }
    }
    for row in owners.iter()? {
        let (key, value) = row?;
        let primary: [u8; 72] = value.value().try_into().map_err(|_| {
            StoreError::BlobInvariant("Blob retirement-delivery owner value has invalid length")
        })?;
        let (_, semantic, _) = parse_blob_retirement_delivery_key(&primary)?;
        let identity =
            blob_subscription_identity_read(read, semantic)?.ok_or(StoreError::BlobInvariant(
                "Blob retirement-delivery owner references missing publication evidence",
            ))?;
        if blob_retirement_delivery_owner_key(identity.transfer_id, &primary).as_slice()
            != key.value()
            || (deliveries.get(primary.as_slice())?.is_some()
                == acknowledgements.get(primary.as_slice())?.is_some())
        {
            return Err(StoreError::BlobInvariant(
                "Blob retirement-delivery owner differs from its primary or receipt",
            ));
        }
    }
    if deliveries.len()? != order.len()?
        || owners.len()?
            != deliveries
                .len()?
                .checked_add(acknowledgements.len()?)
                .ok_or(StoreError::ItemCountAccountingOverflow)?
    {
        return Err(StoreError::BlobInvariant(
            "Blob retirement-delivery ledgers are not one-for-one",
        ));
    }
    Ok(retirement_ids)
}

pub(crate) fn inspect_blob_subscription_tables(
    read: &redb::ReadTransaction,
) -> Result<BlobSubscriptionStats, StoreError> {
    if read
        .list_multimap_tables()?
        .any(|table| is_blob_subscription_table(table.name()))
    {
        return Err(StoreError::BlobInvariant(
            "Blob subscription schema has the wrong table kind",
        ));
    }
    let table_names = read
        .list_tables()?
        .map(|table| table.name().to_owned())
        .collect::<BTreeSet<_>>();
    let tables_present = [
        BLOB_ACCEPTANCE_ORDER.name(),
        BLOB_SUBSCRIPTIONS.name(),
        BLOB_SUBSCRIPTION_PENDING.name(),
        BLOB_DELIVERY_ACKNOWLEDGEMENTS.name(),
        BLOB_DELIVERY_CURSORS.name(),
    ]
    .into_iter()
    .filter(|name| table_names.contains(*name))
    .count();
    let retirement_tables_present = [
        BLOB_RETIREMENT_DELIVERIES.name(),
        BLOB_RETIREMENT_DELIVERY_ORDER.name(),
        BLOB_RETIREMENT_ACKNOWLEDGEMENTS.name(),
        BLOB_RETIREMENT_DELIVERY_OWNERS.name(),
    ]
    .into_iter()
    .filter(|name| table_names.contains(*name))
    .count();
    let metadata = read.open_table(METADATA)?;
    let metadata_presence = [
        metadata.get(BLOB_SUBSCRIPTION_COUNT)?.is_some(),
        metadata.get(BLOB_PENDING_DELIVERY_COUNT)?.is_some(),
        metadata.get(BLOB_ACKNOWLEDGEMENT_COUNT)?.is_some(),
        metadata.get(BLOB_DELIVERY_CURSOR_COUNT)?.is_some(),
        metadata.get(BLOB_SELECTOR_GENERATION)?.is_some(),
    ];
    let retirement_metadata_presence = [
        metadata.get(BLOB_RETIREMENT_DELIVERY_COUNT)?.is_some(),
        metadata
            .get(BLOB_RETIREMENT_DELIVERY_ORDER_COUNT)?
            .is_some(),
        metadata
            .get(BLOB_RETIREMENT_ACKNOWLEDGEMENT_COUNT)?
            .is_some(),
        metadata
            .get(BLOB_RETIREMENT_DELIVERY_OWNER_COUNT)?
            .is_some(),
    ];
    if tables_present != 5 || metadata_presence.iter().any(|present| !present) {
        return Err(StoreError::BlobInvariant(
            "Blob subscription schema group is incomplete",
        ));
    }
    let current_retirement_schema = match (
        retirement_tables_present,
        retirement_metadata_presence
            .iter()
            .filter(|present| **present)
            .count(),
    ) {
        (4, 4) => true,
        _ => {
            return Err(StoreError::BlobInvariant(
                "Blob retirement-delivery schema group is incomplete",
            ));
        }
    };
    audit_blob_acceptance_order_read(read)?;

    let authority = read_mission_binding_read(read)?;
    let mut subscriptions = BTreeMap::new();
    for row in read.open_table(BLOB_SUBSCRIPTIONS)?.iter()? {
        let (key, value) = row?;
        let id = parse_blob_subscription_id(key.value())?;
        let record = decode_blob_subscription_record(value.value())?;
        let authority = authority.ok_or(StoreError::BlobInvariant(
            "unbound store contains Blob subscriptions",
        ))?;
        if blob_subscription_id(authority, &record.operation_key) != id {
            return Err(StoreError::BlobInvariant(
                "Blob subscription identifier differs from its operation key",
            ));
        }
        subscriptions.insert(id, record);
    }
    let mut pending_records = BTreeMap::new();
    let mut retired_records = BTreeMap::new();
    for row in read.open_table(BLOB_SUBSCRIPTION_PENDING)?.iter()? {
        let (key, value) = row?;
        let (subscription, marker) = parse_blob_pending_delivery_key(key.value())?;
        let record = decode_blob_delivery_record(value.value())?;
        let semantic_id = match record {
            BlobDeliveryRecord::Pending(record) => record.semantic_id,
            BlobDeliveryRecord::Retired(record) => record.semantic_id,
        };
        let spec = &subscriptions
            .get(&subscription)
            .ok_or(StoreError::BlobInvariant(
                "pending Blob delivery references a missing subscription",
            ))?
            .spec;
        let blob = load_blob_by_semantic_from_read(read, semantic_id)?.ok_or(
            StoreError::BlobInvariant("pending Blob delivery references a missing Blob"),
        )?;
        if blob.acceptance_marker != marker || !spec.matches_identity(&blob) {
            return Err(StoreError::BlobInvariant(
                "pending Blob delivery differs from its subscription ledger",
            ));
        }
        let id = (subscription, semantic_id);
        match record {
            BlobDeliveryRecord::Pending(record) => {
                if pending_records.insert(id, record).is_some() {
                    return Err(StoreError::BlobInvariant(
                        "duplicate pending Blob semantic delivery",
                    ));
                }
            }
            BlobDeliveryRecord::Retired(record) => {
                if current_retirement_schema {
                    return Err(StoreError::BlobInvariant(
                        "current Blob subscription ledger contains predecessor retirement state",
                    ));
                }
                if blob_subscription_retirement_generation_read(read, blob.transfer_id)?
                    != Some(record.retirement_generation)
                    || retired_records.insert(id, record).is_some()
                {
                    return Err(StoreError::BlobInvariant(
                        "Blob retirement delivery differs from its publication retirement",
                    ));
                }
            }
        }
    }
    let mut acknowledgement_records = BTreeMap::new();
    for row in read.open_table(BLOB_DELIVERY_ACKNOWLEDGEMENTS)?.iter()? {
        let (key, value) = row?;
        let (subscription, semantic_id) = parse_blob_acknowledgement_key(key.value())?;
        let record = decode_blob_acknowledgement_record(value.value())?;
        let spec = &subscriptions
            .get(&subscription)
            .ok_or(StoreError::BlobInvariant(
                "Blob acknowledgement references a missing subscription",
            ))?
            .spec;
        let blob = load_blob_by_semantic_from_read(read, semantic_id)?.ok_or(
            StoreError::BlobInvariant("Blob acknowledgement references a missing Blob"),
        )?;
        if blob.acceptance_marker != record.acceptance_marker || !spec.matches_identity(&blob) {
            return Err(StoreError::BlobInvariant(
                "Blob acknowledgement differs from its subscription ledger",
            ));
        }
        if pending_records.contains_key(&(subscription, semantic_id)) {
            return Err(StoreError::BlobInvariant(
                "Blob delivery is both pending and acknowledged",
            ));
        }
        acknowledgement_records.insert((subscription, semantic_id), record);
    }
    let mut cursor_ids = BTreeSet::new();
    for row in read.open_table(BLOB_DELIVERY_CURSORS)?.iter()? {
        let (key, value) = row?;
        let (subscription, semantic_id) = parse_blob_delivery_cursor_key(key.value())?;
        let cursor = decode_blob_delivery_cursor_record(value.value())?;
        let spec = &subscriptions
            .get(&subscription)
            .ok_or(StoreError::BlobInvariant(
                "Blob delivery cursor references a missing subscription",
            ))?
            .spec;
        let blob = load_blob_by_semantic_from_read(read, semantic_id)?.ok_or(
            StoreError::BlobInvariant("Blob delivery cursor references a missing Blob"),
        )?;
        if !spec.matches_identity(&blob) {
            return Err(StoreError::BlobInvariant(
                "Blob delivery cursor differs from its subscription",
            ));
        }
        let id = (subscription, semantic_id);
        if retired_records.contains_key(&id) {
            if acknowledgement_records.contains_key(&id)
                || cursor.acceptance_marker != blob.acceptance_marker
            {
                return Err(StoreError::BlobInvariant(
                    "Blob retirement delivery differs from its monotonic cursor",
                ));
            }
        } else {
            validate_blob_candidate_delivery_ledger(
                semantic_id,
                blob.acceptance_marker,
                pending_records.get(&id).copied(),
                acknowledgement_records.get(&id).copied(),
                Some(cursor),
            )?;
        }
        cursor_ids.insert(id);
    }
    if pending_records
        .keys()
        .chain(retired_records.keys())
        .chain(acknowledgement_records.keys())
        .any(|id| !cursor_ids.contains(id))
    {
        return Err(StoreError::BlobInvariant(
            "active Blob delivery is missing its monotonic cursor",
        ));
    }
    if current_retirement_schema {
        let retirement_ids = audit_blob_retirement_ledgers_read(read, &subscriptions)?;
        require_blob_delivery_families_disjoint(&cursor_ids, &retirement_ids)?;
    }
    let retirement_pending = if current_retirement_schema {
        read.open_table(BLOB_RETIREMENT_DELIVERIES)?.len()?
    } else {
        0
    };
    let retirement_acknowledged = if current_retirement_schema {
        read.open_table(BLOB_RETIREMENT_ACKNOWLEDGEMENTS)?.len()?
    } else {
        0
    };
    let stats = BlobSubscriptionStats {
        subscriptions: read.open_table(BLOB_SUBSCRIPTIONS)?.len()?,
        pending_deliveries: read
            .open_table(BLOB_SUBSCRIPTION_PENDING)?
            .len()?
            .checked_add(retirement_pending)
            .ok_or(StoreError::ItemCountAccountingOverflow)?,
        acknowledged_deliveries: read
            .open_table(BLOB_DELIVERY_ACKNOWLEDGEMENTS)?
            .len()?
            .checked_add(retirement_acknowledged)
            .ok_or(StoreError::ItemCountAccountingOverflow)?,
        delivery_cursors: read.open_table(BLOB_DELIVERY_CURSORS)?.len()?,
        selector_generation: metadata
            .get(BLOB_SELECTOR_GENERATION)?
            .ok_or(StoreError::MissingAccountingMetadata {
                field: BLOB_SELECTOR_GENERATION,
            })?
            .value(),
    };
    validate_blob_subscription_incarnations(&subscriptions, stats.selector_generation)?;
    if stats.subscriptions > MAX_BLOB_SUBSCRIPTIONS
        || stats.pending_deliveries > MAX_BLOB_PENDING_DELIVERIES
        || stats.acknowledged_deliveries > MAX_BLOB_ACKNOWLEDGEMENT_RECEIPTS
        || stats
            .pending_deliveries
            .checked_add(stats.acknowledged_deliveries)
            .ok_or(StoreError::ItemCountAccountingOverflow)?
            > MAX_BLOB_ACKNOWLEDGEMENT_RECEIPTS
        || stats.delivery_cursors > MAX_BLOB_DELIVERY_CURSORS
    {
        return Err(StoreError::BlobInvariant(
            "Blob subscription tables exceed their bounded cardinality",
        ));
    }
    for (field, reconstructed) in [
        (BLOB_SUBSCRIPTION_COUNT, stats.subscriptions),
        (BLOB_PENDING_DELIVERY_COUNT, stats.pending_deliveries),
        (BLOB_ACKNOWLEDGEMENT_COUNT, stats.acknowledged_deliveries),
        (BLOB_DELIVERY_CURSOR_COUNT, stats.delivery_cursors),
    ] {
        let durable = metadata
            .get(field)?
            .ok_or(StoreError::MissingAccountingMetadata { field })?
            .value();
        if durable != reconstructed {
            return Err(StoreError::AccountingMismatch {
                field,
                durable,
                reconstructed,
            });
        }
    }
    if current_retirement_schema {
        for (field, reconstructed) in [
            (BLOB_RETIREMENT_DELIVERY_COUNT, retirement_pending),
            (
                BLOB_RETIREMENT_DELIVERY_ORDER_COUNT,
                read.open_table(BLOB_RETIREMENT_DELIVERY_ORDER)?.len()?,
            ),
            (
                BLOB_RETIREMENT_ACKNOWLEDGEMENT_COUNT,
                retirement_acknowledged,
            ),
            (
                BLOB_RETIREMENT_DELIVERY_OWNER_COUNT,
                read.open_table(BLOB_RETIREMENT_DELIVERY_OWNERS)?.len()?,
            ),
        ] {
            let durable = metadata
                .get(field)?
                .ok_or(StoreError::MissingAccountingMetadata { field })?
                .value();
            if durable != reconstructed {
                return Err(StoreError::AccountingMismatch {
                    field,
                    durable,
                    reconstructed,
                });
            }
        }
    }
    validate_blob_selector_generation(stats.selector_generation, stats.subscriptions)?;
    Ok(stats)
}

fn audit_blob_acceptance_order_read(read: &redb::ReadTransaction) -> Result<(), StoreError> {
    let order = read.open_table(BLOB_ACCEPTANCE_ORDER)?;
    let markers = read.open_table(BLOB_ACCEPTANCE_MARKERS)?;
    let publications = read.open_table(BLOB_PUBLICATIONS)?;
    if order.len()? != markers.len()? || order.len()? != live_blob_publication_rows(&publications)?
    {
        return Err(StoreError::BlobInvariant(
            "Blob acceptance-order index has missing or orphan rows",
        ));
    }
    let mut all_markers = retired_acceptance_markers(&publications)?;
    for row in order.iter()? {
        let (marker, transfer) = row?;
        let marker = marker.value();
        let transfer = parse_blob_subscription_transfer_id(transfer.value())?;
        if !all_markers.insert(marker)
            || !publication_is_live(&publications, transfer)?
            || markers
                .get(transfer.as_bytes().as_slice())?
                .map(|value| value.value())
                != Some(marker)
        {
            return Err(StoreError::BlobInvariant(
                "Blob acceptance-order index differs from its forward authority",
            ));
        }
    }
    let high_water = read
        .open_table(METADATA)?
        .get(LAST_BLOB_ACCEPTANCE_MARKER)?
        .ok_or(StoreError::MissingAccountingMetadata {
            field: LAST_BLOB_ACCEPTANCE_MARKER,
        })?
        .value();
    if all_markers
        .iter()
        .any(|marker| *marker == 0 || *marker > high_water)
    {
        return Err(StoreError::BlobInvariant(
            "Blob acceptance history exceeds its durable high-water",
        ));
    }
    Ok(())
}

fn parse_blob_subscription_id(bytes: &[u8]) -> Result<BlobSubscriptionId, StoreError> {
    let bytes: [u8; 32] = bytes.try_into().map_err(|_| {
        StoreError::BlobInvariant("Blob subscription identifier has invalid length")
    })?;
    Ok(BlobSubscriptionId::from_bytes(bytes))
}

fn parse_blob_subscription_transfer_id(bytes: &[u8]) -> Result<BlobTransferId, StoreError> {
    let bytes: [u8; 32] = bytes.try_into().map_err(|_| {
        StoreError::BlobInvariant("Blob acceptance-order transfer has invalid length")
    })?;
    Ok(BlobTransferId::new(bytes))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::blob::lifecycle::RetirementReason;

    #[test]
    fn retirement_delivery_v3_codecs_and_token_v2_are_strict() {
        // Production mutations caught: ambiguous key ordering, accepting the
        // seed attempt as issued, or sharing token dispatch with content would
        // make retirement acknowledgement replayable across ledger classes.
        let subscription = BlobSubscriptionId::from_bytes([0x31; 32]);
        let semantic_id = BlobSemanticId::new([0x32; 32]);
        let transfer = BlobTransferId::new([0x33; 32]);
        let generation = 7;
        let marker = 11;
        let primary = blob_retirement_delivery_key(subscription, semantic_id, generation);
        assert_eq!(primary.len(), 72);
        assert_eq!(
            parse_blob_retirement_delivery_key(&primary).unwrap(),
            (subscription, semantic_id, generation)
        );
        let order =
            blob_retirement_delivery_order_key(subscription, marker, semantic_id, generation);
        assert_eq!(order.len(), 80);
        assert_eq!(
            parse_blob_retirement_delivery_order_key(&order).unwrap(),
            (subscription, marker, semantic_id, generation)
        );
        let owner = blob_retirement_delivery_owner_key(transfer, &primary);
        assert_eq!(owner.len(), 64);
        assert_eq!(&owner[..32], transfer.as_bytes());

        let active = BlobRetirementDeliveryRecord {
            subscription_incarnation: 3,
            acceptance_marker: marker,
            current_attempt: 1,
            reason: RetirementReason::Expired,
        };
        assert_eq!(
            decode_blob_retirement_delivery_record(&encode_blob_retirement_delivery_record(active))
                .unwrap(),
            active
        );
        let receipt = BlobRetirementAcknowledgementRecord {
            retirement_generation: generation,
            acknowledged_attempt: 2,
        };
        assert_eq!(
            decode_blob_retirement_acknowledgement_record(
                &encode_blob_retirement_acknowledgement_record(receipt)
            )
            .unwrap(),
            receipt
        );
        let mut invalid_receipt = encode_blob_retirement_acknowledgement_record(receipt);
        invalid_receipt[9..17].copy_from_slice(&1u64.to_be_bytes());
        assert!(decode_blob_retirement_acknowledgement_record(&invalid_receipt).is_err());

        let attempt_two = blob_retirement_delivery_token(
            subscription,
            semantic_id,
            active.subscription_incarnation,
            generation,
            2,
        );
        assert_eq!(attempt_two.as_bytes().len(), BLOB_DELIVERY_TOKEN_BYTES);
        assert_eq!(
            attempt_two.as_bytes()[0],
            BLOB_RETIREMENT_DELIVERY_TOKEN_VERSION
        );
        assert_eq!(
            BlobDeliveryToken::from_bytes(*attempt_two.as_bytes()).unwrap(),
            attempt_two
        );
        assert_eq!(
            BlobDeliveryToken::from_retirement_bytes(*attempt_two.as_bytes()).unwrap(),
            attempt_two
        );
        let parts =
            validate_blob_retirement_delivery_token_binding(subscription, semantic_id, attempt_two)
                .unwrap();
        assert_eq!(parts.retirement_generation, generation);
        assert_eq!(parts.retirement_attempt, 2);
        assert!(
            validate_blob_retirement_delivery_token_binding(
                BlobSubscriptionId::from_bytes([0x41; 32]),
                semantic_id,
                attempt_two,
            )
            .is_err()
        );
        assert!(
            validate_blob_retirement_delivery_token_binding(
                subscription,
                BlobSemanticId::new([0x42; 32]),
                attempt_two,
            )
            .is_err()
        );
        let synthesized_seed = blob_retirement_delivery_token(
            subscription,
            semantic_id,
            active.subscription_incarnation,
            generation,
            1,
        );
        assert!(BlobDeliveryToken::from_retirement_bytes(*synthesized_seed.as_bytes()).is_err());
    }

    #[test]
    fn current_v3_rejects_every_content_retirement_identity_overlap() {
        let subscription = BlobSubscriptionId::from_bytes([0x51; 32]);
        let semantic = BlobSemanticId::new([0x52; 32]);
        let shared = (subscription, semantic);
        for (content, retirement) in [
            (BTreeSet::from([shared]), BTreeSet::from([shared])),
            (
                BTreeSet::from([shared, (subscription, BlobSemanticId::new([0x53; 32]))]),
                BTreeSet::from([shared]),
            ),
            (
                BTreeSet::from([shared]),
                BTreeSet::from([shared, (subscription, BlobSemanticId::new([0x54; 32]))]),
            ),
        ] {
            assert!(require_blob_delivery_families_disjoint(&content, &retirement).is_err());
        }
        assert!(
            require_blob_delivery_families_disjoint(
                &BTreeSet::from([shared]),
                &BTreeSet::from([(subscription, BlobSemanticId::new([0x55; 32]))]),
            )
            .is_ok()
        );
    }
}
