//! Durable whole-projection Record application subscriptions.
//!
//! One delivery represents the complete policy-active causal head set for one
//! exact `(topic, scope, logical_key)` group.  Conflicting siblings are never
//! split across delivery attempts.  `aster-node` freshly verifies every
//! retained candidate and decides whether the complete projection is currently
//! plaintext-deliverable; this store owns only durable selector, retry,
//! acknowledgement, and head-set-tenure structure.

use std::collections::{BTreeMap, BTreeSet};

use aster_mesh::{NodeId, Scope, Topic};
use redb::{
    MultimapTableHandle, ReadableDatabase, ReadableTable, ReadableTableMetadata, TableDefinition,
    TableHandle,
};
use sha2::{Digest, Sha256};

use super::{
    ControlPolicySnapshot, LAST_RECORD_ACCEPTANCE_MARKER, METADATA, MetadataCursor,
    RECORD_ACCEPTANCE_ORDER, RecordProjectionPlan, RecordSemanticId, Store, StoreError,
    StoredRecord, enforce_live_write, load_record_from_read, load_record_from_write,
    parse_record_transfer_id, read_mission_binding, read_mission_binding_read,
    record_projection_plan_read, record_projection_plan_write, require_control_policy_read,
    require_control_policy_write,
};

pub(crate) const RECORD_SUBSCRIPTIONS: TableDefinition<&[u8], &[u8]> =
    TableDefinition::new("aster.semantic-record-subscriptions.v1");
pub(crate) const RECORD_SUBSCRIPTION_PENDING: TableDefinition<&[u8], &[u8]> =
    TableDefinition::new("aster.semantic-record-delivery-pending.v1");
pub(crate) const RECORD_DELIVERY_ACKNOWLEDGEMENTS: TableDefinition<&[u8], &[u8]> =
    TableDefinition::new("aster.semantic-record-delivery-acknowledgements.v1");
pub(crate) const RECORD_DELIVERY_CURSORS: TableDefinition<&[u8], &[u8]> =
    TableDefinition::new("aster.semantic-record-delivery-cursors.v1");

pub(crate) const RECORD_SUBSCRIPTION_COUNT: &str = "semantic_record_subscription_count";
pub(crate) const RECORD_PENDING_DELIVERY_COUNT: &str = "semantic_record_pending_delivery_count";
pub(crate) const RECORD_ACKNOWLEDGEMENT_COUNT: &str = "semantic_record_acknowledgement_count";
pub(crate) const RECORD_DELIVERY_CURSOR_COUNT: &str = "semantic_record_delivery_cursor_count";
pub(crate) const RECORD_SELECTOR_GENERATION: &str = "semantic_record_selector_generation";

const RECORD_SUBSCRIPTION_VERSION: u8 = 1;
const RECORD_PENDING_DELIVERY_VERSION: u8 = 1;
const RECORD_ACKNOWLEDGEMENT_VERSION: u8 = 1;
const RECORD_DELIVERY_CURSOR_VERSION: u8 = 1;
const RECORD_DELIVERY_TOKEN_VERSION: u8 = 1;
const RECORD_SUBSCRIPTION_ID_DOMAIN: &[u8] = b"aster/record-subscription-id/v1";
const RECORD_PROJECTION_GROUP_DOMAIN: &[u8] = b"aster/record-projection-group/v1";
const RECORD_PROJECTION_ID_DOMAIN: &[u8] = b"aster/record-projection-id/v1";
const RECORD_DELIVERY_TOKEN_DOMAIN: &[u8] = b"aster/record-delivery-token/v1";
const RECORD_DELIVERY_TOKEN_HEADER_BYTES: usize = 1 + 32 + (3 * 8);

/// Maximum byte length of one durable Record subscription operation key.
pub const MAX_RECORD_SUBSCRIPTION_KEY_BYTES: usize = 256;
/// Maximum durable Record application subscriptions in one mission-bound store.
pub const MAX_RECORD_SUBSCRIPTIONS: u64 = 256;
/// Maximum whole-key Record projections returned by one poll.
pub const MAX_RECORD_POLL_DELIVERIES: usize = 128;
/// Maximum matching retained Record revisions freshly verified by one poll.
pub const MAX_RECORD_SUBSCRIPTION_SCAN: usize = 4_096;
/// Dedicated hard cap for unacknowledged Record projection attempts.
pub const MAX_RECORD_PENDING_DELIVERIES: u64 = 262_144;
/// Hard cap for durable idempotent Record projection acknowledgement receipts.
pub const MAX_RECORD_ACKNOWLEDGEMENT_RECEIPTS: u64 = 262_144;
/// Hard cap for durable monotonic per-key Record delivery cursors.
pub const MAX_RECORD_DELIVERY_CURSORS: u64 = 262_144;
/// Canonical byte length of one opaque Record projection acknowledgement token.
pub const RECORD_DELIVERY_TOKEN_BYTES: usize = RECORD_DELIVERY_TOKEN_HEADER_BYTES + 32;

/// Stable mission-local identity of one durable Record application subscription.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct RecordSubscriptionId([u8; 32]);

impl RecordSubscriptionId {
    pub const fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

/// Stable identity of one exact Record key and complete policy-active head set.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct RecordProjectionId([u8; 32]);

impl RecordProjectionId {
    pub const fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
struct RecordProjectionGroupId([u8; 32]);

impl RecordProjectionGroupId {
    const fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

/// Bounded application idempotency key for one Record subscription.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct RecordSubscriptionKey(Vec<u8>);

impl RecordSubscriptionKey {
    pub fn new(bytes: impl Into<Vec<u8>>) -> Result<Self, StoreError> {
        let bytes = bytes.into();
        if bytes.is_empty() || bytes.len() > MAX_RECORD_SUBSCRIPTION_KEY_BYTES {
            return Err(StoreError::InvalidRecordSubscriptionKey {
                length: bytes.len(),
            });
        }
        Ok(Self(bytes))
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

/// One durable Record application-delivery selector.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct RecordSubscriptionSpec {
    pub topic: Topic,
    pub scope: Scope,
    pub include_descendant_scopes: bool,
}

impl RecordSubscriptionSpec {
    fn matches_record(&self, record: &StoredRecord) -> bool {
        self.topic == record.header.topic
            && if self.include_descendant_scopes {
                self.scope.contains(&record.header.scope)
            } else {
                self.scope == record.header.scope
            }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RecordSubscriptionCreateOutcome {
    pub id: RecordSubscriptionId,
    pub inserted: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RecordSubscriptionRemoveOutcome {
    pub id: RecordSubscriptionId,
    pub removed: bool,
}

/// One complete exact-key Record projection requiring fresh privileged verification.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RecordSubscriptionCandidate {
    group_id: RecordProjectionGroupId,
    projection_id: RecordProjectionId,
    plan: RecordProjectionPlan,
    pending: Option<RecordPendingDeliveryRecord>,
    acknowledgement: Option<RecordAcknowledgementRecord>,
    delivery_cursor: Option<RecordDeliveryCursorRecord>,
}

impl RecordSubscriptionCandidate {
    pub const fn projection_id(&self) -> RecordProjectionId {
        self.projection_id
    }

    pub const fn plan(&self) -> &RecordProjectionPlan {
        &self.plan
    }

    pub fn pending_attempt(&self) -> Option<u64> {
        self.pending
            .filter(|record| record.projection_id == self.projection_id)
            .map(|record| record.attempts)
    }

    pub fn acknowledged_attempt(&self) -> Option<u64> {
        self.acknowledgement
            .filter(|record| record.projection_id == self.projection_id)
            .map(|record| record.attempts)
    }

    pub fn last_delivery_attempt(&self) -> Option<u64> {
        self.delivery_cursor
            .filter(|cursor| cursor.projection_id == self.projection_id)
            .map(|cursor| cursor.last_attempt)
            .filter(|attempt| *attempt != 0)
    }

    pub fn delivery_tenure(&self) -> Option<u64> {
        self.delivery_cursor
            .filter(|cursor| cursor.projection_id == self.projection_id)
            .map(|cursor| cursor.tenure)
    }
}

/// Complete bounded matching-Record snapshot prepared for privileged verification.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RecordSubscriptionPollPlan {
    policy: ControlPolicySnapshot,
    subscription: RecordSubscriptionId,
    spec: RecordSubscriptionSpec,
    incarnation: u64,
    selector_generation: u64,
    candidates: Vec<RecordSubscriptionCandidate>,
    delivery_limit: usize,
    scan_limit: usize,
}

impl RecordSubscriptionPollPlan {
    pub const fn subscription(&self) -> RecordSubscriptionId {
        self.subscription
    }

    pub const fn spec(&self) -> &RecordSubscriptionSpec {
        &self.spec
    }

    pub const fn selector_generation(&self) -> u64 {
        self.selector_generation
    }

    pub const fn incarnation(&self) -> u64 {
        self.incarnation
    }

    pub fn candidates(&self) -> &[RecordSubscriptionCandidate] {
        &self.candidates
    }
}

/// Privileged disposition of every complete projection in one poll snapshot.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct RecordSubscriptionPollSelection {
    pub deliverable: Vec<RecordProjectionId>,
    pub inactive: Vec<RecordProjectionId>,
}

/// One whole-key Record projection attempt committed before application return.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RecordSubscriptionDelivery {
    pub projection_id: RecordProjectionId,
    pub plan: RecordProjectionPlan,
    pub attempt: u64,
    pub token: RecordDeliveryToken,
}

/// Opaque acknowledgement identity for one complete Record projection attempt.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct RecordDeliveryToken([u8; RECORD_DELIVERY_TOKEN_BYTES]);

impl RecordDeliveryToken {
    pub fn from_bytes(bytes: [u8; RECORD_DELIVERY_TOKEN_BYTES]) -> Result<Self, StoreError> {
        let token = Self(bytes);
        if token.0[0] != RECORD_DELIVERY_TOKEN_VERSION
            || token.group_id().as_bytes().iter().all(|byte| *byte == 0)
            || token.incarnation() == 0
            || token.tenure() == 0
            || token.attempt() == 0
        {
            return Err(StoreError::InvalidRecordDeliveryToken);
        }
        Ok(token)
    }

    pub const fn as_bytes(&self) -> &[u8; RECORD_DELIVERY_TOKEN_BYTES] {
        &self.0
    }

    fn group_id(self) -> RecordProjectionGroupId {
        RecordProjectionGroupId::from_bytes(
            self.0[1..33]
                .try_into()
                .expect("fixed Record delivery-token group"),
        )
    }

    fn incarnation(self) -> u64 {
        u64::from_be_bytes(
            self.0[33..41]
                .try_into()
                .expect("fixed Record delivery-token incarnation"),
        )
    }

    fn tenure(self) -> u64 {
        u64::from_be_bytes(
            self.0[41..49]
                .try_into()
                .expect("fixed Record delivery-token tenure"),
        )
    }

    fn attempt(self) -> u64 {
        u64::from_be_bytes(
            self.0[49..57]
                .try_into()
                .expect("fixed Record delivery-token attempt"),
        )
    }
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct RecordSubscriptionDeliveryPage {
    pub deliveries: Vec<RecordSubscriptionDelivery>,
    pub has_more: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RecordDeliveryAck {
    Acknowledged,
    AlreadyAcknowledged,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct RecordSubscriptionStats {
    pub subscriptions: u64,
    pub pending_deliveries: u64,
    pub acknowledged_deliveries: u64,
    pub delivery_cursors: u64,
    pub selector_generation: u64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct RecordSubscriptionRecord {
    operation_key: RecordSubscriptionKey,
    spec: RecordSubscriptionSpec,
    incarnation: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct RecordPendingDeliveryRecord {
    projection_id: RecordProjectionId,
    tenure: u64,
    attempts: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct RecordAcknowledgementRecord {
    projection_id: RecordProjectionId,
    tenure: u64,
    attempts: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct RecordDeliveryCursorRecord {
    projection_id: RecordProjectionId,
    tenure: u64,
    last_attempt: u64,
    last_acknowledged_projection: Option<RecordProjectionId>,
    last_acknowledged_tenure: u64,
    last_acknowledged_attempt: u64,
}

impl Store {
    /// Returns structurally audited Record subscription counts.
    pub fn record_subscription_stats(&self) -> Result<RecordSubscriptionStats, StoreError> {
        self.require_bound_mission()?;
        let read = self.database.begin_read()?;
        inspect_record_subscription_tables(&read)
    }

    /// Idempotently creates one durable whole-projection Record selector.
    pub fn create_record_subscription_with_policy(
        &self,
        policy: &ControlPolicySnapshot,
        key: &RecordSubscriptionKey,
        spec: RecordSubscriptionSpec,
    ) -> Result<RecordSubscriptionCreateOutcome, StoreError> {
        self.require_live()?;
        let authority = self.require_bound_mission()?;
        let id = record_subscription_id(authority, key);
        let write = self.database.begin_write()?;
        enforce_live_write(&write)?;
        require_control_policy_write(&write, authority, policy)?;
        let existing = write
            .open_table(RECORD_SUBSCRIPTIONS)?
            .get(id.as_bytes().as_slice())?
            .map(|value| decode_record_subscription_record(value.value()))
            .transpose()?;
        if let Some(existing) = existing {
            if existing.operation_key != *key || existing.spec != spec {
                return Err(StoreError::RecordSubscriptionConflict);
            }
            return Ok(RecordSubscriptionCreateOutcome {
                id,
                inserted: false,
            });
        }

        let current_count = write.open_table(RECORD_SUBSCRIPTIONS)?.len()?;
        if current_count >= MAX_RECORD_SUBSCRIPTIONS {
            return Err(StoreError::RecordSubscriptionLimitExceeded {
                current: current_count,
                limit: MAX_RECORD_SUBSCRIPTIONS,
            });
        }
        let (durable_count, generation) = {
            let metadata = write.open_table(METADATA)?;
            let count = metadata
                .get(RECORD_SUBSCRIPTION_COUNT)?
                .ok_or(StoreError::MissingAccountingMetadata {
                    field: RECORD_SUBSCRIPTION_COUNT,
                })?
                .value();
            let generation = metadata
                .get(RECORD_SELECTOR_GENERATION)?
                .ok_or(StoreError::MissingAccountingMetadata {
                    field: RECORD_SELECTOR_GENERATION,
                })?
                .value();
            (count, generation)
        };
        if durable_count != current_count {
            return Err(StoreError::AccountingMismatch {
                field: RECORD_SUBSCRIPTION_COUNT,
                durable: durable_count,
                reconstructed: current_count,
            });
        }
        validate_record_selector_generation(generation, current_count)?;
        let incarnation = generation
            .checked_add(1)
            .ok_or(StoreError::ItemCountAccountingOverflow)?;
        let encoded = encode_record_subscription_record(&RecordSubscriptionRecord {
            operation_key: key.clone(),
            spec,
            incarnation,
        })?;
        write
            .open_table(RECORD_SUBSCRIPTIONS)?
            .insert(id.as_bytes().as_slice(), encoded.as_slice())?;
        {
            let mut metadata = write.open_table(METADATA)?;
            metadata.insert(
                RECORD_SUBSCRIPTION_COUNT,
                current_count
                    .checked_add(1)
                    .ok_or(StoreError::ItemCountAccountingOverflow)?,
            )?;
            metadata.insert(RECORD_SELECTOR_GENERATION, incarnation)?;
        }
        write.commit()?;
        Ok(RecordSubscriptionCreateOutcome { id, inserted: true })
    }

    /// Idempotently removes one Record selector and all of its delivery evidence.
    pub fn remove_record_subscription_with_policy(
        &self,
        policy: &ControlPolicySnapshot,
        id: RecordSubscriptionId,
    ) -> Result<RecordSubscriptionRemoveOutcome, StoreError> {
        self.require_live()?;
        let authority = self.require_bound_mission()?;
        let write = self.database.begin_write()?;
        enforce_live_write(&write)?;
        require_control_policy_write(&write, authority, policy)?;
        let record = write
            .open_table(RECORD_SUBSCRIPTIONS)?
            .get(id.as_bytes().as_slice())?
            .map(|value| decode_record_subscription_record(value.value()))
            .transpose()?;
        let Some(record) = record else {
            return Ok(RecordSubscriptionRemoveOutcome { id, removed: false });
        };
        if record_subscription_id(authority, &record.operation_key) != id {
            return Err(StoreError::RecordInvariant(
                "Record subscription identifier differs from its operation key",
            ));
        }

        let subscription_count = write.open_table(RECORD_SUBSCRIPTIONS)?.len()?;
        let pending_count = write.open_table(RECORD_SUBSCRIPTION_PENDING)?.len()?;
        let acknowledgement_count = write.open_table(RECORD_DELIVERY_ACKNOWLEDGEMENTS)?.len()?;
        let cursor_count = write.open_table(RECORD_DELIVERY_CURSORS)?.len()?;
        let generation = require_record_subscription_accounting(
            &write,
            subscription_count,
            pending_count,
            acknowledgement_count,
            cursor_count,
        )?;

        let pending_removals =
            record_ledger_keys_for_subscription_write(&write, RECORD_SUBSCRIPTION_PENDING, id)?;
        let acknowledgement_removals = record_ledger_keys_for_subscription_write(
            &write,
            RECORD_DELIVERY_ACKNOWLEDGEMENTS,
            id,
        )?;
        let cursor_removals =
            record_ledger_keys_for_subscription_write(&write, RECORD_DELIVERY_CURSORS, id)?;
        remove_record_ledger_keys(&write, RECORD_SUBSCRIPTION_PENDING, &pending_removals)?;
        remove_record_ledger_keys(
            &write,
            RECORD_DELIVERY_ACKNOWLEDGEMENTS,
            &acknowledgement_removals,
        )?;
        remove_record_ledger_keys(&write, RECORD_DELIVERY_CURSORS, &cursor_removals)?;
        if write
            .open_table(RECORD_SUBSCRIPTIONS)?
            .remove(id.as_bytes().as_slice())?
            .is_none()
        {
            return Err(StoreError::RecordInvariant(
                "Record subscription disappeared during its write transaction",
            ));
        }
        let removed_pending = u64::try_from(pending_removals.len())
            .map_err(|_| StoreError::ItemCountAccountingOverflow)?;
        let removed_acknowledgements = u64::try_from(acknowledgement_removals.len())
            .map_err(|_| StoreError::ItemCountAccountingOverflow)?;
        let removed_cursors = u64::try_from(cursor_removals.len())
            .map_err(|_| StoreError::ItemCountAccountingOverflow)?;
        {
            let mut metadata = write.open_table(METADATA)?;
            metadata.insert(
                RECORD_SUBSCRIPTION_COUNT,
                subscription_count
                    .checked_sub(1)
                    .ok_or(StoreError::RecordInvariant(
                        "Record subscription counter underflow",
                    ))?,
            )?;
            metadata.insert(
                RECORD_PENDING_DELIVERY_COUNT,
                pending_count
                    .checked_sub(removed_pending)
                    .ok_or(StoreError::RecordInvariant(
                        "Record pending-delivery counter underflow",
                    ))?,
            )?;
            metadata.insert(
                RECORD_ACKNOWLEDGEMENT_COUNT,
                acknowledgement_count
                    .checked_sub(removed_acknowledgements)
                    .ok_or(StoreError::RecordInvariant(
                        "Record acknowledgement counter underflow",
                    ))?,
            )?;
            metadata.insert(
                RECORD_DELIVERY_CURSOR_COUNT,
                cursor_count
                    .checked_sub(removed_cursors)
                    .ok_or(StoreError::RecordInvariant(
                        "Record delivery-cursor counter underflow",
                    ))?,
            )?;
            metadata.insert(
                RECORD_SELECTOR_GENERATION,
                generation
                    .checked_add(1)
                    .ok_or(StoreError::ItemCountAccountingOverflow)?,
            )?;
        }
        write.commit()?;
        Ok(RecordSubscriptionRemoveOutcome { id, removed: true })
    }

    /// Prepares every matching exact-key projection for fresh privileged verification.
    pub fn prepare_record_subscription_poll_with_policy(
        &self,
        policy: &ControlPolicySnapshot,
        subscription: RecordSubscriptionId,
        delivery_limit: usize,
        scan_limit: usize,
    ) -> Result<RecordSubscriptionPollPlan, StoreError> {
        self.require_live()?;
        let authority = self.require_bound_mission()?;
        validate_record_poll_limits(delivery_limit, scan_limit)?;
        let read = self.database.begin_read()?;
        require_control_policy_read(&read, authority, policy)?;
        let record = read
            .open_table(RECORD_SUBSCRIPTIONS)?
            .get(subscription.as_bytes().as_slice())?
            .map(|value| decode_record_subscription_record(value.value()))
            .transpose()?
            .ok_or(StoreError::RecordSubscriptionNotFound)?;
        let selector_generation = read
            .open_table(METADATA)?
            .get(RECORD_SELECTOR_GENERATION)?
            .ok_or(StoreError::MissingAccountingMetadata {
                field: RECORD_SELECTOR_GENERATION,
            })?
            .value();
        let subscription_count = read.open_table(RECORD_SUBSCRIPTIONS)?.len()?;
        validate_record_selector_generation(selector_generation, subscription_count)?;
        let candidates = record_subscription_candidates_read(
            &read,
            authority,
            *policy,
            subscription,
            &record.spec,
            scan_limit,
        )?;
        Ok(RecordSubscriptionPollPlan {
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

    /// Commits one exact freshly verified deliverable/inactive projection partition.
    pub fn commit_record_subscription_poll_with_policy(
        &self,
        policy: &ControlPolicySnapshot,
        plan: &RecordSubscriptionPollPlan,
        selection: &RecordSubscriptionPollSelection,
    ) -> Result<RecordSubscriptionDeliveryPage, StoreError> {
        self.require_live()?;
        let authority = self.require_bound_mission()?;
        validate_record_poll_limits(plan.delivery_limit, plan.scan_limit)?;
        if policy != &plan.policy {
            return Err(StoreError::RecordSubscriptionPlanChanged);
        }
        let deliverable = validate_record_selection(plan, selection)?;
        let write = self.database.begin_write()?;
        enforce_live_write(&write)?;
        require_control_policy_write(&write, authority, policy)?;
        let record = write
            .open_table(RECORD_SUBSCRIPTIONS)?
            .get(plan.subscription.as_bytes().as_slice())?
            .map(|value| decode_record_subscription_record(value.value()))
            .transpose()?
            .ok_or(StoreError::RecordSubscriptionNotFound)?;
        let generation = write
            .open_table(METADATA)?
            .get(RECORD_SELECTOR_GENERATION)?
            .ok_or(StoreError::MissingAccountingMetadata {
                field: RECORD_SELECTOR_GENERATION,
            })?
            .value();
        if record.spec != plan.spec
            || record.incarnation != plan.incarnation
            || generation != plan.selector_generation
        {
            return Err(StoreError::RecordSelectorGenerationChanged);
        }
        let durable_candidates = record_subscription_candidates_write(
            &write,
            authority,
            *policy,
            plan.subscription,
            &record.spec,
            plan.scan_limit,
        )?;
        if durable_candidates != plan.candidates {
            return Err(StoreError::RecordSubscriptionPlanChanged);
        }

        let subscription_count = write.open_table(RECORD_SUBSCRIPTIONS)?.len()?;
        let pending_count = write.open_table(RECORD_SUBSCRIPTION_PENDING)?.len()?;
        let acknowledgement_count = write.open_table(RECORD_DELIVERY_ACKNOWLEDGEMENTS)?.len()?;
        let cursor_count = write.open_table(RECORD_DELIVERY_CURSORS)?.len()?;
        require_record_subscription_accounting(
            &write,
            subscription_count,
            pending_count,
            acknowledgement_count,
            cursor_count,
        )?;

        let mut retire_pending = Vec::new();
        let mut retire_acknowledgements = Vec::new();
        let mut changed_cursors = BTreeMap::new();
        let mut retry_candidates = Vec::new();
        let mut new_candidates = Vec::new();
        for candidate in &durable_candidates {
            let changed = candidate
                .delivery_cursor
                .is_some_and(|cursor| cursor.projection_id != candidate.projection_id);
            let current_pending = candidate
                .pending
                .filter(|pending| !changed && pending.projection_id == candidate.projection_id);
            let current_acknowledgement = candidate
                .acknowledgement
                .filter(|ack| !changed && ack.projection_id == candidate.projection_id);
            if changed {
                if candidate.pending.is_some() {
                    retire_pending.push(candidate.group_id);
                }
                if candidate.acknowledgement.is_some() {
                    retire_acknowledgements.push(candidate.group_id);
                }
                let old = candidate.delivery_cursor.expect("changed cursor exists");
                changed_cursors.insert(
                    candidate.group_id,
                    RecordDeliveryCursorRecord {
                        projection_id: candidate.projection_id,
                        tenure: old
                            .tenure
                            .checked_add(1)
                            .ok_or(StoreError::RecordDeliveryTenureExhausted)?,
                        last_attempt: 0,
                        last_acknowledged_projection: old.last_acknowledged_projection,
                        last_acknowledged_tenure: old.last_acknowledged_tenure,
                        last_acknowledged_attempt: old.last_acknowledged_attempt,
                    },
                );
            }
            if !deliverable.contains(&candidate.projection_id) || current_acknowledgement.is_some()
            {
                continue;
            }
            if current_pending.is_some() {
                retry_candidates.push(candidate);
            } else {
                new_candidates.push(candidate);
            }
        }
        retry_candidates.sort_by_key(|candidate| {
            (
                candidate
                    .pending
                    .expect("retry candidate has a pending delivery")
                    .attempts,
                candidate.group_id,
            )
        });
        let eligible_count = retry_candidates
            .len()
            .checked_add(new_candidates.len())
            .ok_or(StoreError::ItemCountAccountingOverflow)?;
        let chosen = retry_candidates
            .into_iter()
            .chain(new_candidates)
            .take(plan.delivery_limit)
            .collect::<Vec<_>>();

        let new_pending = chosen
            .iter()
            .filter(|candidate| {
                candidate
                    .pending
                    .is_none_or(|pending| pending.projection_id != candidate.projection_id)
            })
            .count();
        let new_cursors = chosen
            .iter()
            .filter(|candidate| candidate.delivery_cursor.is_none())
            .count();
        let final_pending_count = pending_count
            .checked_sub(
                u64::try_from(retire_pending.len())
                    .map_err(|_| StoreError::ItemCountAccountingOverflow)?,
            )
            .ok_or(StoreError::RecordInvariant(
                "Record pending retirement underflows accounting",
            ))?
            .checked_add(
                u64::try_from(new_pending).map_err(|_| StoreError::ItemCountAccountingOverflow)?,
            )
            .ok_or(StoreError::ItemCountAccountingOverflow)?;
        let final_acknowledgement_count = acknowledgement_count
            .checked_sub(
                u64::try_from(retire_acknowledgements.len())
                    .map_err(|_| StoreError::ItemCountAccountingOverflow)?,
            )
            .ok_or(StoreError::RecordInvariant(
                "Record acknowledgement retirement underflows accounting",
            ))?;
        let final_cursor_count = cursor_count
            .checked_add(
                u64::try_from(new_cursors).map_err(|_| StoreError::ItemCountAccountingOverflow)?,
            )
            .ok_or(StoreError::ItemCountAccountingOverflow)?;
        validate_record_delivery_caps(
            final_pending_count,
            final_acknowledgement_count,
            final_cursor_count,
        )?;

        let mut attempts = Vec::with_capacity(chosen.len());
        let mut tenures = Vec::with_capacity(chosen.len());
        for candidate in &chosen {
            let cursor = changed_cursors
                .get(&candidate.group_id)
                .copied()
                .or(candidate.delivery_cursor);
            let tenure = cursor.map_or(1, |cursor| cursor.tenure);
            let attempt = candidate
                .pending
                .filter(|pending| pending.projection_id == candidate.projection_id)
                .map(|pending| {
                    pending
                        .attempts
                        .checked_add(1)
                        .ok_or(StoreError::RecordDeliveryAttemptExhausted)
                })
                .transpose()?
                .unwrap_or(1);
            tenures.push(tenure);
            attempts.push(attempt);
        }

        {
            let mut pending = write.open_table(RECORD_SUBSCRIPTION_PENDING)?;
            for group in &retire_pending {
                let key = record_ledger_key(plan.subscription, *group);
                if pending.remove(key.as_slice())?.is_none() {
                    return Err(StoreError::RecordSubscriptionPlanChanged);
                }
            }
            for ((candidate, tenure), attempt) in chosen.iter().zip(&tenures).zip(&attempts) {
                let key = record_ledger_key(plan.subscription, candidate.group_id);
                let encoded = encode_record_pending_delivery_record(RecordPendingDeliveryRecord {
                    projection_id: candidate.projection_id,
                    tenure: *tenure,
                    attempts: *attempt,
                });
                pending.insert(key.as_slice(), encoded.as_slice())?;
            }
        }
        {
            let mut acknowledgements = write.open_table(RECORD_DELIVERY_ACKNOWLEDGEMENTS)?;
            for group in &retire_acknowledgements {
                let key = record_ledger_key(plan.subscription, *group);
                if acknowledgements.remove(key.as_slice())?.is_none() {
                    return Err(StoreError::RecordSubscriptionPlanChanged);
                }
            }
        }
        {
            let mut cursors = write.open_table(RECORD_DELIVERY_CURSORS)?;
            for (group, cursor) in &changed_cursors {
                let key = record_ledger_key(plan.subscription, *group);
                let encoded = encode_record_delivery_cursor_record(*cursor);
                cursors.insert(key.as_slice(), encoded.as_slice())?;
            }
            for ((candidate, tenure), attempt) in chosen.iter().zip(&tenures).zip(&attempts) {
                let key = record_ledger_key(plan.subscription, candidate.group_id);
                let previous = changed_cursors
                    .get(&candidate.group_id)
                    .copied()
                    .or(candidate.delivery_cursor);
                let encoded = encode_record_delivery_cursor_record(RecordDeliveryCursorRecord {
                    projection_id: candidate.projection_id,
                    tenure: *tenure,
                    last_attempt: *attempt,
                    last_acknowledged_projection: previous
                        .and_then(|cursor| cursor.last_acknowledged_projection),
                    last_acknowledged_tenure: previous
                        .map_or(0, |cursor| cursor.last_acknowledged_tenure),
                    last_acknowledged_attempt: previous
                        .map_or(0, |cursor| cursor.last_acknowledged_attempt),
                });
                cursors.insert(key.as_slice(), encoded.as_slice())?;
            }
        }
        {
            let mut metadata = write.open_table(METADATA)?;
            metadata.insert(RECORD_PENDING_DELIVERY_COUNT, final_pending_count)?;
            metadata.insert(RECORD_ACKNOWLEDGEMENT_COUNT, final_acknowledgement_count)?;
            metadata.insert(RECORD_DELIVERY_CURSOR_COUNT, final_cursor_count)?;
        }
        write.commit()?;

        Ok(RecordSubscriptionDeliveryPage {
            deliveries: chosen
                .into_iter()
                .zip(tenures)
                .zip(attempts)
                .map(
                    |((candidate, tenure), attempt)| RecordSubscriptionDelivery {
                        projection_id: candidate.projection_id,
                        plan: candidate.plan.clone(),
                        attempt,
                        token: record_delivery_token(
                            plan.subscription,
                            candidate.group_id,
                            candidate.projection_id,
                            plan.incarnation,
                            tenure,
                            attempt,
                        ),
                    },
                )
                .collect(),
            has_more: eligible_count > plan.delivery_limit,
        })
    }

    /// Idempotently acknowledges one exact whole-projection Record delivery.
    pub fn acknowledge_record_delivery_with_policy(
        &self,
        policy: &ControlPolicySnapshot,
        subscription: RecordSubscriptionId,
        projection_id: RecordProjectionId,
        token: RecordDeliveryToken,
    ) -> Result<RecordDeliveryAck, StoreError> {
        let token = validate_record_delivery_token_binding(subscription, projection_id, token)?;
        self.require_live()?;
        let authority = self.require_bound_mission()?;
        let write = self.database.begin_write()?;
        enforce_live_write(&write)?;
        require_control_policy_write(&write, authority, policy)?;
        let subscription_record = write
            .open_table(RECORD_SUBSCRIPTIONS)?
            .get(subscription.as_bytes().as_slice())?
            .map(|value| decode_record_subscription_record(value.value()))
            .transpose()?
            .ok_or(StoreError::RecordSubscriptionNotFound)?;
        if token.incarnation != subscription_record.incarnation {
            return Err(StoreError::RecordSubscriptionIncarnationChanged {
                current: subscription_record.incarnation,
                received: token.incarnation,
            });
        }
        let candidates = record_subscription_candidates_write(
            &write,
            authority,
            *policy,
            subscription,
            &subscription_record.spec,
            MAX_RECORD_SUBSCRIPTION_SCAN,
        )?;
        let candidate = candidates
            .iter()
            .find(|candidate| candidate.group_id == token.group_id)
            .ok_or(StoreError::RecordDeliveryNotFound)?;
        let key = record_ledger_key(subscription, token.group_id);
        let mut cursor = candidate
            .delivery_cursor
            .ok_or(StoreError::RecordDeliveryNotFound)?;
        if candidate.projection_id != cursor.projection_id {
            if let Some(acknowledgement) = candidate.acknowledgement
                && acknowledgement.projection_id == projection_id
            {
                validate_record_acknowledgement_cursor(acknowledgement, cursor)?;
                if token.tenure != acknowledgement.tenure {
                    return Err(StoreError::RecordDeliveryTenureChanged {
                        current: acknowledgement.tenure,
                        received: token.tenure,
                    });
                }
                validate_record_delivery_token_attempt(token.attempt, acknowledgement.attempts)?;
                return Ok(RecordDeliveryAck::AlreadyAcknowledged);
            }
            return Err(StoreError::RecordSubscriptionPlanChanged);
        }
        if cursor.projection_id != projection_id {
            if cursor.last_acknowledged_projection == Some(projection_id)
                && token.tenure == cursor.last_acknowledged_tenure
                && token.attempt <= cursor.last_acknowledged_attempt
            {
                return Ok(RecordDeliveryAck::AlreadyAcknowledged);
            }
            return Err(StoreError::RecordDeliveryTenureChanged {
                current: cursor.tenure,
                received: token.tenure,
            });
        }
        let pending = candidate.pending;
        let acknowledgement = candidate.acknowledgement;
        if pending.is_some() && acknowledgement.is_some() {
            return Err(StoreError::RecordInvariant(
                "Record projection delivery is both pending and acknowledged",
            ));
        }
        if let Some(acknowledgement) = acknowledgement {
            validate_record_acknowledgement_cursor(acknowledgement, cursor)?;
            if token.tenure != acknowledgement.tenure {
                return Err(StoreError::RecordDeliveryTenureChanged {
                    current: acknowledgement.tenure,
                    received: token.tenure,
                });
            }
            validate_record_delivery_token_attempt(token.attempt, acknowledgement.attempts)?;
            return Ok(RecordDeliveryAck::AlreadyAcknowledged);
        }
        let Some(pending) = pending else {
            if cursor.last_acknowledged_projection == Some(projection_id)
                && token.tenure == cursor.last_acknowledged_tenure
                && token.attempt <= cursor.last_acknowledged_attempt
            {
                return Ok(RecordDeliveryAck::AlreadyAcknowledged);
            }
            return Err(StoreError::RecordDeliveryNotFound);
        };
        if pending.projection_id != projection_id
            || pending.tenure != cursor.tenure
            || pending.attempts != cursor.last_attempt
        {
            return Err(StoreError::RecordInvariant(
                "pending Record projection differs from its delivery cursor",
            ));
        }
        if token.tenure != pending.tenure {
            return Err(StoreError::RecordDeliveryTenureChanged {
                current: pending.tenure,
                received: token.tenure,
            });
        }
        validate_record_delivery_token_attempt(token.attempt, pending.attempts)?;

        let subscription_count = write.open_table(RECORD_SUBSCRIPTIONS)?.len()?;
        let pending_count = write.open_table(RECORD_SUBSCRIPTION_PENDING)?.len()?;
        let acknowledgement_count = write.open_table(RECORD_DELIVERY_ACKNOWLEDGEMENTS)?.len()?;
        let cursor_count = write.open_table(RECORD_DELIVERY_CURSORS)?.len()?;
        require_record_subscription_accounting(
            &write,
            subscription_count,
            pending_count,
            acknowledgement_count,
            cursor_count,
        )?;
        if acknowledgement_count >= MAX_RECORD_ACKNOWLEDGEMENT_RECEIPTS {
            return Err(StoreError::RecordAcknowledgementReceiptLimitExceeded {
                current: acknowledgement_count,
                limit: MAX_RECORD_ACKNOWLEDGEMENT_RECEIPTS,
            });
        }
        let encoded = encode_record_acknowledgement_record(RecordAcknowledgementRecord {
            projection_id,
            tenure: pending.tenure,
            attempts: pending.attempts,
        });
        if write
            .open_table(RECORD_DELIVERY_ACKNOWLEDGEMENTS)?
            .insert(key.as_slice(), encoded.as_slice())?
            .is_some()
        {
            return Err(StoreError::RecordSubscriptionPlanChanged);
        }
        if write
            .open_table(RECORD_SUBSCRIPTION_PENDING)?
            .remove(key.as_slice())?
            .is_none()
        {
            return Err(StoreError::RecordSubscriptionPlanChanged);
        }
        cursor.last_acknowledged_projection = Some(projection_id);
        cursor.last_acknowledged_tenure = pending.tenure;
        cursor.last_acknowledged_attempt = pending.attempts;
        let encoded = encode_record_delivery_cursor_record(cursor);
        write
            .open_table(RECORD_DELIVERY_CURSORS)?
            .insert(key.as_slice(), encoded.as_slice())?;
        {
            let mut metadata = write.open_table(METADATA)?;
            metadata.insert(
                RECORD_PENDING_DELIVERY_COUNT,
                pending_count
                    .checked_sub(1)
                    .ok_or(StoreError::RecordInvariant(
                        "Record acknowledgement underflows pending accounting",
                    ))?,
            )?;
            metadata.insert(
                RECORD_ACKNOWLEDGEMENT_COUNT,
                acknowledgement_count
                    .checked_add(1)
                    .ok_or(StoreError::ItemCountAccountingOverflow)?,
            )?;
        }
        write.commit()?;
        Ok(RecordDeliveryAck::Acknowledged)
    }
}

fn validate_record_poll_limits(delivery_limit: usize, scan_limit: usize) -> Result<(), StoreError> {
    if delivery_limit == 0 || delivery_limit > MAX_RECORD_POLL_DELIVERIES {
        return Err(StoreError::RecordSubscriptionPollLimitExceeded {
            requested: delivery_limit,
            maximum: MAX_RECORD_POLL_DELIVERIES,
        });
    }
    if scan_limit == 0 || scan_limit > MAX_RECORD_SUBSCRIPTION_SCAN {
        return Err(StoreError::RecordSubscriptionPollLimitExceeded {
            requested: scan_limit,
            maximum: MAX_RECORD_SUBSCRIPTION_SCAN,
        });
    }
    Ok(())
}

fn validate_record_selection(
    plan: &RecordSubscriptionPollPlan,
    selection: &RecordSubscriptionPollSelection,
) -> Result<BTreeSet<RecordProjectionId>, StoreError> {
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
        return Err(StoreError::RecordSubscriptionPlanChanged);
    }
    let expected = plan
        .candidates
        .iter()
        .map(|candidate| candidate.projection_id)
        .collect::<BTreeSet<_>>();
    let actual = deliverable
        .iter()
        .chain(&inactive)
        .copied()
        .collect::<BTreeSet<_>>();
    if expected.len() != plan.candidates.len() || expected != actual {
        return Err(StoreError::RecordSubscriptionPlanChanged);
    }
    for candidate in &plan.candidates {
        if deliverable.contains(&candidate.projection_id) && candidate.plan.heads().next().is_none()
        {
            return Err(StoreError::RecordSubscriptionPlanChanged);
        }
    }
    Ok(deliverable)
}

fn record_subscription_candidates_read(
    read: &redb::ReadTransaction,
    authority: NodeId,
    policy: ControlPolicySnapshot,
    subscription: RecordSubscriptionId,
    spec: &RecordSubscriptionSpec,
    scan_limit: usize,
) -> Result<Vec<RecordSubscriptionCandidate>, StoreError> {
    let order = read.open_table(RECORD_ACCEPTANCE_ORDER)?;
    let mut groups = BTreeMap::<RecordProjectionGroupId, (Topic, Scope, Vec<u8>, usize)>::new();
    let mut matching_versions = 0usize;
    let mut expected_marker = 1u64;
    for row in order.iter()? {
        let (marker, transfer) = row?;
        let marker = marker.value();
        if marker != expected_marker {
            return Err(StoreError::RecordInvariant(
                "Record acceptance-order snapshot is not consecutive",
            ));
        }
        expected_marker = marker
            .checked_add(1)
            .ok_or(StoreError::AcceptanceMarkerExhausted)?;
        let transfer = parse_record_transfer_id("Record acceptance-order table", transfer.value())?;
        let record = load_record_from_read(read, transfer)?.ok_or(StoreError::RecordInvariant(
            "Record acceptance-order index points to a missing Record",
        ))?;
        if record.acceptance_marker != marker {
            return Err(StoreError::RecordInvariant(
                "Record acceptance-order index differs from its forward marker",
            ));
        }
        if !spec.matches_record(&record) {
            continue;
        }
        if matching_versions == scan_limit {
            return Err(StoreError::RecordSubscriptionPollLimitExceeded {
                requested: scan_limit
                    .checked_add(1)
                    .ok_or(StoreError::ItemCountAccountingOverflow)?,
                maximum: scan_limit,
            });
        }
        matching_versions = matching_versions
            .checked_add(1)
            .ok_or(StoreError::ItemCountAccountingOverflow)?;
        let group_id = record_projection_group_id(
            authority,
            &record.header.topic,
            &record.header.scope,
            &record.header.logical_key,
        );
        let identity = (
            record.header.topic.clone(),
            record.header.scope.clone(),
            record.header.logical_key.clone(),
        );
        match groups.get_mut(&group_id) {
            Some((topic, scope, logical_key, count)) => {
                if (&*topic, &*scope, &*logical_key) != (&identity.0, &identity.1, &identity.2) {
                    return Err(StoreError::RecordInvariant(
                        "Record projection group digest collision",
                    ));
                }
                *count = count
                    .checked_add(1)
                    .ok_or(StoreError::ItemCountAccountingOverflow)?;
            }
            None => {
                groups.insert(group_id, (identity.0, identity.1, identity.2, 1));
            }
        }
    }
    require_complete_record_acceptance_snapshot_read(read, expected_marker)?;

    let pending = read.open_table(RECORD_SUBSCRIPTION_PENDING)?;
    let acknowledgements = read.open_table(RECORD_DELIVERY_ACKNOWLEDGEMENTS)?;
    let cursors = read.open_table(RECORD_DELIVERY_CURSORS)?;
    let mut candidates = Vec::with_capacity(groups.len());
    for (group_id, (topic, scope, logical_key, expected_versions)) in groups {
        let plan = record_projection_plan_read(read, policy, &topic, &scope, &logical_key)?;
        if plan.candidates().len() != expected_versions {
            return Err(StoreError::RecordInvariant(
                "Record projection group differs from acceptance-order snapshot",
            ));
        }
        let projection_id = record_projection_id(group_id, &plan)?;
        let key = record_ledger_key(subscription, group_id);
        let pending = pending
            .get(key.as_slice())?
            .map(|value| decode_record_pending_delivery_record(value.value()))
            .transpose()?;
        let acknowledgement = acknowledgements
            .get(key.as_slice())?
            .map(|value| decode_record_acknowledgement_record(value.value()))
            .transpose()?;
        let delivery_cursor = cursors
            .get(key.as_slice())?
            .map(|value| decode_record_delivery_cursor_record(value.value()))
            .transpose()?;
        validate_record_candidate_delivery_ledger(pending, acknowledgement, delivery_cursor)?;
        candidates.push(RecordSubscriptionCandidate {
            group_id,
            projection_id,
            plan,
            pending,
            acknowledgement,
            delivery_cursor,
        });
    }
    Ok(candidates)
}

fn record_subscription_candidates_write(
    write: &redb::WriteTransaction,
    authority: NodeId,
    policy: ControlPolicySnapshot,
    subscription: RecordSubscriptionId,
    spec: &RecordSubscriptionSpec,
    scan_limit: usize,
) -> Result<Vec<RecordSubscriptionCandidate>, StoreError> {
    let order = write.open_table(RECORD_ACCEPTANCE_ORDER)?;
    let mut groups = BTreeMap::<RecordProjectionGroupId, (Topic, Scope, Vec<u8>, usize)>::new();
    let mut matching_versions = 0usize;
    let mut expected_marker = 1u64;
    for row in order.iter()? {
        let (marker, transfer) = row?;
        let marker = marker.value();
        if marker != expected_marker {
            return Err(StoreError::RecordInvariant(
                "Record acceptance-order snapshot is not consecutive",
            ));
        }
        expected_marker = marker
            .checked_add(1)
            .ok_or(StoreError::AcceptanceMarkerExhausted)?;
        let transfer = parse_record_transfer_id("Record acceptance-order table", transfer.value())?;
        let record = load_record_from_write(write, transfer)?.ok_or(
            StoreError::RecordInvariant("Record acceptance-order index points to a missing Record"),
        )?;
        if record.acceptance_marker != marker {
            return Err(StoreError::RecordInvariant(
                "Record acceptance-order index differs from its forward marker",
            ));
        }
        if !spec.matches_record(&record) {
            continue;
        }
        if matching_versions == scan_limit {
            return Err(StoreError::RecordSubscriptionPollLimitExceeded {
                requested: scan_limit
                    .checked_add(1)
                    .ok_or(StoreError::ItemCountAccountingOverflow)?,
                maximum: scan_limit,
            });
        }
        matching_versions = matching_versions
            .checked_add(1)
            .ok_or(StoreError::ItemCountAccountingOverflow)?;
        let group_id = record_projection_group_id(
            authority,
            &record.header.topic,
            &record.header.scope,
            &record.header.logical_key,
        );
        let identity = (
            record.header.topic.clone(),
            record.header.scope.clone(),
            record.header.logical_key.clone(),
        );
        match groups.get_mut(&group_id) {
            Some((topic, scope, logical_key, count)) => {
                if (&*topic, &*scope, &*logical_key) != (&identity.0, &identity.1, &identity.2) {
                    return Err(StoreError::RecordInvariant(
                        "Record projection group digest collision",
                    ));
                }
                *count = count
                    .checked_add(1)
                    .ok_or(StoreError::ItemCountAccountingOverflow)?;
            }
            None => {
                groups.insert(group_id, (identity.0, identity.1, identity.2, 1));
            }
        }
    }
    require_complete_record_acceptance_snapshot_write(write, expected_marker)?;

    let pending = write.open_table(RECORD_SUBSCRIPTION_PENDING)?;
    let acknowledgements = write.open_table(RECORD_DELIVERY_ACKNOWLEDGEMENTS)?;
    let cursors = write.open_table(RECORD_DELIVERY_CURSORS)?;
    let mut candidates = Vec::with_capacity(groups.len());
    for (group_id, (topic, scope, logical_key, expected_versions)) in groups {
        let plan = record_projection_plan_write(write, policy, &topic, &scope, &logical_key)?;
        if plan.candidates().len() != expected_versions {
            return Err(StoreError::RecordInvariant(
                "Record projection group differs from acceptance-order snapshot",
            ));
        }
        let projection_id = record_projection_id(group_id, &plan)?;
        let key = record_ledger_key(subscription, group_id);
        let pending = pending
            .get(key.as_slice())?
            .map(|value| decode_record_pending_delivery_record(value.value()))
            .transpose()?;
        let acknowledgement = acknowledgements
            .get(key.as_slice())?
            .map(|value| decode_record_acknowledgement_record(value.value()))
            .transpose()?;
        let delivery_cursor = cursors
            .get(key.as_slice())?
            .map(|value| decode_record_delivery_cursor_record(value.value()))
            .transpose()?;
        validate_record_candidate_delivery_ledger(pending, acknowledgement, delivery_cursor)?;
        candidates.push(RecordSubscriptionCandidate {
            group_id,
            projection_id,
            plan,
            pending,
            acknowledgement,
            delivery_cursor,
        });
    }
    Ok(candidates)
}

fn validate_record_candidate_delivery_ledger(
    pending: Option<RecordPendingDeliveryRecord>,
    acknowledgement: Option<RecordAcknowledgementRecord>,
    cursor: Option<RecordDeliveryCursorRecord>,
) -> Result<(), StoreError> {
    if pending.is_some() && acknowledgement.is_some() {
        return Err(StoreError::RecordInvariant(
            "Record projection delivery is both pending and acknowledged",
        ));
    }
    let Some(cursor) = cursor else {
        if pending.is_some() || acknowledgement.is_some() {
            return Err(StoreError::RecordInvariant(
                "active Record projection delivery is missing its monotonic cursor",
            ));
        }
        return Ok(());
    };
    if let Some(pending) = pending
        && (pending.projection_id != cursor.projection_id
            || pending.tenure != cursor.tenure
            || pending.attempts != cursor.last_attempt)
    {
        return Err(StoreError::RecordInvariant(
            "pending Record projection differs from its delivery cursor",
        ));
    }
    if let Some(acknowledgement) = acknowledgement {
        validate_record_acknowledgement_cursor(acknowledgement, cursor)?;
    }
    if cursor.last_attempt == 0 && (pending.is_some() || acknowledgement.is_some()) {
        return Err(StoreError::RecordInvariant(
            "unopened Record projection tenure has active delivery evidence",
        ));
    }
    if cursor.last_attempt != 0 && pending.is_none() && acknowledgement.is_none() {
        return Err(StoreError::RecordInvariant(
            "attempted Record projection tenure has no delivery evidence",
        ));
    }
    Ok(())
}

fn validate_record_acknowledgement_cursor(
    acknowledgement: RecordAcknowledgementRecord,
    cursor: RecordDeliveryCursorRecord,
) -> Result<(), StoreError> {
    if acknowledgement.projection_id != cursor.projection_id
        || acknowledgement.tenure != cursor.tenure
        || cursor.last_acknowledged_projection != Some(acknowledgement.projection_id)
        || acknowledgement.tenure != cursor.last_acknowledged_tenure
        || acknowledgement.attempts != cursor.last_acknowledged_attempt
        || acknowledgement.attempts > cursor.last_attempt
    {
        return Err(StoreError::RecordInvariant(
            "Record acknowledgement differs from its delivery cursor",
        ));
    }
    Ok(())
}

fn require_complete_record_acceptance_snapshot_read(
    read: &redb::ReadTransaction,
    next_marker: u64,
) -> Result<(), StoreError> {
    let high_water = read
        .open_table(METADATA)?
        .get(LAST_RECORD_ACCEPTANCE_MARKER)?
        .ok_or(StoreError::MissingAccountingMetadata {
            field: LAST_RECORD_ACCEPTANCE_MARKER,
        })?
        .value();
    if next_marker.checked_sub(1) != Some(high_water) {
        return Err(StoreError::RecordInvariant(
            "Record acceptance-order snapshot ended before durable acceptance high-water",
        ));
    }
    Ok(())
}

fn require_complete_record_acceptance_snapshot_write(
    write: &redb::WriteTransaction,
    next_marker: u64,
) -> Result<(), StoreError> {
    let high_water = write
        .open_table(METADATA)?
        .get(LAST_RECORD_ACCEPTANCE_MARKER)?
        .ok_or(StoreError::MissingAccountingMetadata {
            field: LAST_RECORD_ACCEPTANCE_MARKER,
        })?
        .value();
    if next_marker.checked_sub(1) != Some(high_water) {
        return Err(StoreError::RecordInvariant(
            "Record acceptance-order snapshot ended before durable acceptance high-water",
        ));
    }
    Ok(())
}

fn record_subscription_id(authority: NodeId, key: &RecordSubscriptionKey) -> RecordSubscriptionId {
    let mut digest = Sha256::new();
    digest.update(RECORD_SUBSCRIPTION_ID_DOMAIN);
    digest.update(authority);
    digest.update(
        u16::try_from(key.as_bytes().len())
            .expect("validated Record subscription key fits u16")
            .to_be_bytes(),
    );
    digest.update(key.as_bytes());
    RecordSubscriptionId(digest.finalize().into())
}

fn record_projection_group_id(
    authority: NodeId,
    topic: &Topic,
    scope: &Scope,
    logical_key: &[u8],
) -> RecordProjectionGroupId {
    let mut digest = Sha256::new();
    digest.update(RECORD_PROJECTION_GROUP_DOMAIN);
    digest.update(authority);
    for bytes in [
        topic.as_str().as_bytes(),
        scope.as_str().as_bytes(),
        logical_key,
    ] {
        digest.update(
            u64::try_from(bytes.len())
                .expect("validated Record identity length fits u64")
                .to_be_bytes(),
        );
        digest.update(bytes);
    }
    RecordProjectionGroupId(digest.finalize().into())
}

fn record_projection_id(
    group_id: RecordProjectionGroupId,
    plan: &RecordProjectionPlan,
) -> Result<RecordProjectionId, StoreError> {
    let mut heads = plan
        .heads()
        .map(|candidate| candidate.record().semantic_id)
        .collect::<Vec<RecordSemanticId>>();
    heads.sort_unstable();
    if heads.windows(2).any(|pair| pair[0] == pair[1]) {
        return Err(StoreError::RecordInvariant(
            "Record projection contains a duplicate causal head",
        ));
    }
    let mut digest = Sha256::new();
    digest.update(RECORD_PROJECTION_ID_DOMAIN);
    digest.update(group_id.as_bytes());
    digest.update(
        u64::try_from(heads.len())
            .map_err(|_| StoreError::ItemCountAccountingOverflow)?
            .to_be_bytes(),
    );
    for head in heads {
        digest.update(head.as_bytes());
    }
    Ok(RecordProjectionId(digest.finalize().into()))
}

#[derive(Clone, Copy)]
struct RecordDeliveryTokenParts {
    group_id: RecordProjectionGroupId,
    incarnation: u64,
    tenure: u64,
    attempt: u64,
}

fn record_delivery_token(
    subscription: RecordSubscriptionId,
    group_id: RecordProjectionGroupId,
    projection_id: RecordProjectionId,
    incarnation: u64,
    tenure: u64,
    attempt: u64,
) -> RecordDeliveryToken {
    debug_assert!(incarnation > 0 && tenure > 0 && attempt > 0);
    let mut bytes = [0u8; RECORD_DELIVERY_TOKEN_BYTES];
    bytes[0] = RECORD_DELIVERY_TOKEN_VERSION;
    bytes[1..33].copy_from_slice(group_id.as_bytes());
    bytes[33..41].copy_from_slice(&incarnation.to_be_bytes());
    bytes[41..49].copy_from_slice(&tenure.to_be_bytes());
    bytes[49..57].copy_from_slice(&attempt.to_be_bytes());
    let mut digest = Sha256::new();
    digest.update(RECORD_DELIVERY_TOKEN_DOMAIN);
    digest.update(subscription.as_bytes());
    digest.update(projection_id.as_bytes());
    digest.update(&bytes[..RECORD_DELIVERY_TOKEN_HEADER_BYTES]);
    bytes[RECORD_DELIVERY_TOKEN_HEADER_BYTES..].copy_from_slice(&digest.finalize());
    RecordDeliveryToken(bytes)
}

fn validate_record_delivery_token_binding(
    subscription: RecordSubscriptionId,
    projection_id: RecordProjectionId,
    token: RecordDeliveryToken,
) -> Result<RecordDeliveryTokenParts, StoreError> {
    let parts = RecordDeliveryTokenParts {
        group_id: token.group_id(),
        incarnation: token.incarnation(),
        tenure: token.tenure(),
        attempt: token.attempt(),
    };
    if token
        != record_delivery_token(
            subscription,
            parts.group_id,
            projection_id,
            parts.incarnation,
            parts.tenure,
            parts.attempt,
        )
    {
        return Err(StoreError::RecordDeliveryTokenBindingMismatch);
    }
    Ok(parts)
}

fn validate_record_delivery_token_attempt(received: u64, maximum: u64) -> Result<(), StoreError> {
    if received == 0 || received > maximum {
        return Err(StoreError::RecordDeliveryAttemptChanged {
            current: maximum,
            received,
        });
    }
    Ok(())
}

fn encode_record_subscription_record(
    record: &RecordSubscriptionRecord,
) -> Result<Vec<u8>, StoreError> {
    let key_length = u16::try_from(record.operation_key.as_bytes().len()).map_err(|_| {
        StoreError::RecordInvariant("Record subscription operation key exceeds its bound")
    })?;
    let topic = record.spec.topic.as_str().as_bytes();
    let scope = record.spec.scope.as_str().as_bytes();
    let topic_length = u16::try_from(topic.len())
        .map_err(|_| StoreError::RecordInvariant("Record subscription topic exceeds its bound"))?;
    let scope_length = u16::try_from(scope.len())
        .map_err(|_| StoreError::RecordInvariant("Record subscription scope exceeds its bound"))?;
    let mut encoded = Vec::new();
    encoded.push(RECORD_SUBSCRIPTION_VERSION);
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

fn decode_record_subscription_record(bytes: &[u8]) -> Result<RecordSubscriptionRecord, StoreError> {
    let mut cursor = MetadataCursor::new(bytes);
    if cursor.u8()? != RECORD_SUBSCRIPTION_VERSION {
        return Err(StoreError::RecordInvariant(
            "unknown Record subscription encoding version",
        ));
    }
    let include_descendant_scopes = match cursor.u8()? {
        0 => false,
        1 => true,
        _ => {
            return Err(StoreError::RecordInvariant(
                "invalid Record subscription descendant flag",
            ));
        }
    };
    let incarnation = cursor.u64()?;
    if incarnation == 0 {
        return Err(StoreError::RecordInvariant(
            "Record subscription incarnation is zero",
        ));
    }
    let key_length = usize::from(cursor.u16()?);
    let operation_key = RecordSubscriptionKey::new(cursor.take(key_length)?.to_vec())
        .map_err(|_| StoreError::RecordInvariant("invalid Record subscription operation key"))?;
    let topic = Topic::new(cursor.short_string()?)
        .map_err(|_| StoreError::RecordInvariant("invalid Record subscription topic"))?;
    let scope = Scope::new(cursor.short_string()?)
        .map_err(|_| StoreError::RecordInvariant("invalid Record subscription scope"))?;
    cursor.finish()?;
    let record = RecordSubscriptionRecord {
        operation_key,
        spec: RecordSubscriptionSpec {
            topic,
            scope,
            include_descendant_scopes,
        },
        incarnation,
    };
    if encode_record_subscription_record(&record)?.as_slice() != bytes {
        return Err(StoreError::RecordInvariant(
            "Record subscription encoding is not canonical",
        ));
    }
    Ok(record)
}

fn record_ledger_key(
    subscription: RecordSubscriptionId,
    group_id: RecordProjectionGroupId,
) -> [u8; 64] {
    let mut key = [0u8; 64];
    key[..32].copy_from_slice(subscription.as_bytes());
    key[32..].copy_from_slice(group_id.as_bytes());
    key
}

fn parse_record_ledger_key(
    bytes: &[u8],
) -> Result<(RecordSubscriptionId, RecordProjectionGroupId), StoreError> {
    let bytes: [u8; 64] = bytes.try_into().map_err(|_| {
        StoreError::RecordInvariant("Record delivery-ledger key has invalid length")
    })?;
    Ok((
        RecordSubscriptionId::from_bytes(
            bytes[..32]
                .try_into()
                .expect("fixed Record subscription prefix"),
        ),
        RecordProjectionGroupId::from_bytes(
            bytes[32..]
                .try_into()
                .expect("fixed Record projection-group suffix"),
        ),
    ))
}

fn encode_record_pending_delivery_record(record: RecordPendingDeliveryRecord) -> Vec<u8> {
    let mut encoded = Vec::with_capacity(49);
    encoded.push(RECORD_PENDING_DELIVERY_VERSION);
    encoded.extend_from_slice(record.projection_id.as_bytes());
    encoded.extend_from_slice(&record.tenure.to_be_bytes());
    encoded.extend_from_slice(&record.attempts.to_be_bytes());
    encoded
}

fn decode_record_pending_delivery_record(
    bytes: &[u8],
) -> Result<RecordPendingDeliveryRecord, StoreError> {
    let mut cursor = MetadataCursor::new(bytes);
    if cursor.u8()? != RECORD_PENDING_DELIVERY_VERSION {
        return Err(StoreError::RecordInvariant(
            "unknown Record pending-delivery encoding version",
        ));
    }
    let projection_id = RecordProjectionId::from_bytes(cursor.array()?);
    let tenure = cursor.u64()?;
    let attempts = cursor.u64()?;
    cursor.finish()?;
    if tenure == 0 || attempts == 0 {
        return Err(StoreError::RecordInvariant(
            "Record pending-delivery tenure or attempt count is zero",
        ));
    }
    Ok(RecordPendingDeliveryRecord {
        projection_id,
        tenure,
        attempts,
    })
}

fn encode_record_acknowledgement_record(record: RecordAcknowledgementRecord) -> Vec<u8> {
    let mut encoded = Vec::with_capacity(49);
    encoded.push(RECORD_ACKNOWLEDGEMENT_VERSION);
    encoded.extend_from_slice(record.projection_id.as_bytes());
    encoded.extend_from_slice(&record.tenure.to_be_bytes());
    encoded.extend_from_slice(&record.attempts.to_be_bytes());
    encoded
}

fn decode_record_acknowledgement_record(
    bytes: &[u8],
) -> Result<RecordAcknowledgementRecord, StoreError> {
    let mut cursor = MetadataCursor::new(bytes);
    if cursor.u8()? != RECORD_ACKNOWLEDGEMENT_VERSION {
        return Err(StoreError::RecordInvariant(
            "unknown Record acknowledgement encoding version",
        ));
    }
    let projection_id = RecordProjectionId::from_bytes(cursor.array()?);
    let tenure = cursor.u64()?;
    let attempts = cursor.u64()?;
    cursor.finish()?;
    if tenure == 0 || attempts == 0 {
        return Err(StoreError::RecordInvariant(
            "Record acknowledgement tenure or attempt count is zero",
        ));
    }
    Ok(RecordAcknowledgementRecord {
        projection_id,
        tenure,
        attempts,
    })
}

fn encode_record_delivery_cursor_record(record: RecordDeliveryCursorRecord) -> Vec<u8> {
    let mut encoded = Vec::with_capacity(98);
    encoded.push(RECORD_DELIVERY_CURSOR_VERSION);
    encoded.extend_from_slice(record.projection_id.as_bytes());
    encoded.extend_from_slice(&record.tenure.to_be_bytes());
    encoded.extend_from_slice(&record.last_attempt.to_be_bytes());
    match record.last_acknowledged_projection {
        Some(projection) => {
            encoded.push(1);
            encoded.extend_from_slice(projection.as_bytes());
        }
        None => {
            encoded.push(0);
            encoded.extend_from_slice(&[0u8; 32]);
        }
    }
    encoded.extend_from_slice(&record.last_acknowledged_tenure.to_be_bytes());
    encoded.extend_from_slice(&record.last_acknowledged_attempt.to_be_bytes());
    encoded
}

fn decode_record_delivery_cursor_record(
    bytes: &[u8],
) -> Result<RecordDeliveryCursorRecord, StoreError> {
    let mut cursor = MetadataCursor::new(bytes);
    if cursor.u8()? != RECORD_DELIVERY_CURSOR_VERSION {
        return Err(StoreError::RecordInvariant(
            "unknown Record delivery-cursor encoding version",
        ));
    }
    let projection_id = RecordProjectionId::from_bytes(cursor.array()?);
    let tenure = cursor.u64()?;
    let last_attempt = cursor.u64()?;
    let acknowledgement_present = cursor.u8()?;
    let acknowledgement_bytes: [u8; 32] = cursor.array()?;
    let last_acknowledged_projection = match acknowledgement_present {
        0 if acknowledgement_bytes == [0; 32] => None,
        1 => Some(RecordProjectionId::from_bytes(acknowledgement_bytes)),
        _ => {
            return Err(StoreError::RecordInvariant(
                "Record delivery cursor has invalid acknowledgement presence",
            ));
        }
    };
    let last_acknowledged_tenure = cursor.u64()?;
    let last_acknowledged_attempt = cursor.u64()?;
    cursor.finish()?;
    let record = RecordDeliveryCursorRecord {
        projection_id,
        tenure,
        last_attempt,
        last_acknowledged_projection,
        last_acknowledged_tenure,
        last_acknowledged_attempt,
    };
    if tenure == 0
        || last_acknowledged_projection.is_some()
            != (last_acknowledged_tenure != 0 && last_acknowledged_attempt != 0)
        || last_acknowledged_tenure > tenure
        || (last_acknowledged_tenure == tenure
            && (last_acknowledged_projection != Some(projection_id)
                || last_acknowledged_attempt > last_attempt))
    {
        return Err(StoreError::RecordInvariant(
            "Record delivery cursor contains an invalid tenure or acknowledgement high-water",
        ));
    }
    if encode_record_delivery_cursor_record(record).as_slice() != bytes {
        return Err(StoreError::RecordInvariant(
            "Record delivery cursor encoding is not canonical",
        ));
    }
    Ok(record)
}

fn validate_record_selector_generation(
    generation: u64,
    subscription_count: u64,
) -> Result<(), StoreError> {
    if generation < subscription_count || !(generation - subscription_count).is_multiple_of(2) {
        return Err(StoreError::RecordInvariant(
            "Record selector mutation generation is inconsistent with the live subscription count",
        ));
    }
    Ok(())
}

fn require_record_subscription_accounting(
    write: &redb::WriteTransaction,
    subscriptions: u64,
    pending: u64,
    acknowledgements: u64,
    cursors: u64,
) -> Result<u64, StoreError> {
    let metadata = write.open_table(METADATA)?;
    for (field, reconstructed) in [
        (RECORD_SUBSCRIPTION_COUNT, subscriptions),
        (RECORD_PENDING_DELIVERY_COUNT, pending),
        (RECORD_ACKNOWLEDGEMENT_COUNT, acknowledgements),
        (RECORD_DELIVERY_CURSOR_COUNT, cursors),
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
        .get(RECORD_SELECTOR_GENERATION)?
        .ok_or(StoreError::MissingAccountingMetadata {
            field: RECORD_SELECTOR_GENERATION,
        })?
        .value();
    validate_record_selector_generation(generation, subscriptions)?;
    Ok(generation)
}

fn validate_record_delivery_caps(
    pending: u64,
    acknowledgements: u64,
    cursors: u64,
) -> Result<(), StoreError> {
    if pending > MAX_RECORD_PENDING_DELIVERIES {
        return Err(StoreError::RecordPendingDeliveryLimitExceeded {
            current: pending,
            limit: MAX_RECORD_PENDING_DELIVERIES,
        });
    }
    if acknowledgements > MAX_RECORD_ACKNOWLEDGEMENT_RECEIPTS {
        return Err(StoreError::RecordAcknowledgementReceiptLimitExceeded {
            current: acknowledgements,
            limit: MAX_RECORD_ACKNOWLEDGEMENT_RECEIPTS,
        });
    }
    let ledger = pending
        .checked_add(acknowledgements)
        .ok_or(StoreError::ItemCountAccountingOverflow)?;
    if ledger > MAX_RECORD_ACKNOWLEDGEMENT_RECEIPTS {
        return Err(StoreError::RecordDeliveryLedgerLimitExceeded {
            current: ledger,
            limit: MAX_RECORD_ACKNOWLEDGEMENT_RECEIPTS,
        });
    }
    if cursors > MAX_RECORD_DELIVERY_CURSORS {
        return Err(StoreError::RecordDeliveryLedgerLimitExceeded {
            current: cursors,
            limit: MAX_RECORD_DELIVERY_CURSORS,
        });
    }
    Ok(())
}

fn record_ledger_keys_for_subscription_write(
    write: &redb::WriteTransaction,
    definition: TableDefinition<&[u8], &[u8]>,
    subscription: RecordSubscriptionId,
) -> Result<Vec<[u8; 64]>, StoreError> {
    let mut keys = Vec::new();
    for row in write.open_table(definition)?.iter()? {
        let (key, _) = row?;
        let (candidate_subscription, _) = parse_record_ledger_key(key.value())?;
        if candidate_subscription == subscription {
            keys.push(
                key.value()
                    .try_into()
                    .expect("parsed Record ledger key is fixed length"),
            );
        }
    }
    Ok(keys)
}

fn remove_record_ledger_keys(
    write: &redb::WriteTransaction,
    definition: TableDefinition<&[u8], &[u8]>,
    keys: &[[u8; 64]],
) -> Result<(), StoreError> {
    let mut table = write.open_table(definition)?;
    for key in keys {
        if table.remove(key.as_slice())?.is_none() {
            return Err(StoreError::RecordInvariant(
                "Record delivery-ledger row disappeared during write transaction",
            ));
        }
    }
    Ok(())
}

fn is_record_subscription_table(name: &str) -> bool {
    name == RECORD_SUBSCRIPTIONS.name()
        || name == RECORD_SUBSCRIPTION_PENDING.name()
        || name == RECORD_DELIVERY_ACKNOWLEDGEMENTS.name()
        || name == RECORD_DELIVERY_CURSORS.name()
}

fn record_subscription_metadata_is_present(
    metadata: &impl ReadableTable<&'static str, u64>,
) -> Result<bool, StoreError> {
    for field in [
        RECORD_SUBSCRIPTION_COUNT,
        RECORD_PENDING_DELIVERY_COUNT,
        RECORD_ACKNOWLEDGEMENT_COUNT,
        RECORD_DELIVERY_CURSOR_COUNT,
        RECORD_SELECTOR_GENERATION,
    ] {
        if metadata.get(field)?.is_some() {
            return Ok(true);
        }
    }
    Ok(false)
}

pub(crate) fn record_subscription_schema_wholly_absent_write(
    write: &redb::WriteTransaction,
) -> Result<bool, StoreError> {
    let table_present = write
        .list_tables()?
        .any(|table| is_record_subscription_table(table.name()));
    let multimap_present = write
        .list_multimap_tables()?
        .any(|table| is_record_subscription_table(table.name()));
    let metadata_present = record_subscription_metadata_is_present(&write.open_table(METADATA)?)?;
    Ok(!table_present && !multimap_present && !metadata_present)
}

pub(crate) fn record_subscription_schema_wholly_absent_read(
    read: &redb::ReadTransaction,
) -> Result<bool, StoreError> {
    let table_present = read
        .list_tables()?
        .any(|table| is_record_subscription_table(table.name()));
    let multimap_present = read
        .list_multimap_tables()?
        .any(|table| is_record_subscription_table(table.name()));
    let metadata_present = record_subscription_metadata_is_present(&read.open_table(METADATA)?)?;
    Ok(!table_present && !multimap_present && !metadata_present)
}

pub(crate) fn audit_record_subscription_tables(
    write: &redb::WriteTransaction,
    initializing_record: bool,
) -> Result<RecordSubscriptionStats, StoreError> {
    if write
        .list_multimap_tables()?
        .any(|table| is_record_subscription_table(table.name()))
    {
        return Err(StoreError::RecordInvariant(
            "Record subscription schema has the wrong table kind",
        ));
    }
    let table_names = write
        .list_tables()?
        .map(|table| table.name().to_owned())
        .collect::<BTreeSet<_>>();
    let tables_present = [
        RECORD_SUBSCRIPTIONS.name(),
        RECORD_SUBSCRIPTION_PENDING.name(),
        RECORD_DELIVERY_ACKNOWLEDGEMENTS.name(),
        RECORD_DELIVERY_CURSORS.name(),
    ]
    .into_iter()
    .filter(|name| table_names.contains(*name))
    .count();
    let metadata_presence = {
        let metadata = write.open_table(METADATA)?;
        [
            metadata.get(RECORD_SUBSCRIPTION_COUNT)?.is_some(),
            metadata.get(RECORD_PENDING_DELIVERY_COUNT)?.is_some(),
            metadata.get(RECORD_ACKNOWLEDGEMENT_COUNT)?.is_some(),
            metadata.get(RECORD_DELIVERY_CURSOR_COUNT)?.is_some(),
            metadata.get(RECORD_SELECTOR_GENERATION)?.is_some(),
        ]
    };
    let metadata_present = metadata_presence.iter().filter(|present| **present).count();
    if tables_present == 0 && metadata_present == 0 {
        if !initializing_record {
            return Err(StoreError::RecordInvariant(
                "Record subscription schema group is incomplete",
            ));
        }
        write.open_table(RECORD_SUBSCRIPTIONS)?;
        write.open_table(RECORD_SUBSCRIPTION_PENDING)?;
        write.open_table(RECORD_DELIVERY_ACKNOWLEDGEMENTS)?;
        write.open_table(RECORD_DELIVERY_CURSORS)?;
        let mut metadata = write.open_table(METADATA)?;
        metadata.insert(RECORD_SUBSCRIPTION_COUNT, 0)?;
        metadata.insert(RECORD_PENDING_DELIVERY_COUNT, 0)?;
        metadata.insert(RECORD_ACKNOWLEDGEMENT_COUNT, 0)?;
        metadata.insert(RECORD_DELIVERY_CURSOR_COUNT, 0)?;
        metadata.insert(RECORD_SELECTOR_GENERATION, 0)?;
        return Ok(RecordSubscriptionStats::default());
    }
    if tables_present != 4 || metadata_presence.iter().any(|present| !present) {
        return Err(StoreError::RecordInvariant(
            "Record subscription schema group is incomplete",
        ));
    }
    audit_record_subscription_rows_write(write)
}

fn audit_record_subscription_rows_write(
    write: &redb::WriteTransaction,
) -> Result<RecordSubscriptionStats, StoreError> {
    let authority = read_mission_binding(write)?;
    let mut subscriptions = BTreeMap::new();
    for row in write.open_table(RECORD_SUBSCRIPTIONS)?.iter()? {
        let (key, value) = row?;
        let id = parse_record_subscription_id(key.value())?;
        let record = decode_record_subscription_record(value.value())?;
        let authority = authority.ok_or(StoreError::RecordInvariant(
            "unbound store contains Record subscriptions",
        ))?;
        if record_subscription_id(authority, &record.operation_key) != id
            || subscriptions.insert(id, record).is_some()
        {
            return Err(StoreError::RecordInvariant(
                "Record subscription identity is invalid or duplicated",
            ));
        }
    }
    audit_record_subscription_ledgers_write(write, &subscriptions)?;
    let stats = RecordSubscriptionStats {
        subscriptions: write.open_table(RECORD_SUBSCRIPTIONS)?.len()?,
        pending_deliveries: write.open_table(RECORD_SUBSCRIPTION_PENDING)?.len()?,
        acknowledged_deliveries: write.open_table(RECORD_DELIVERY_ACKNOWLEDGEMENTS)?.len()?,
        delivery_cursors: write.open_table(RECORD_DELIVERY_CURSORS)?.len()?,
        selector_generation: write
            .open_table(METADATA)?
            .get(RECORD_SELECTOR_GENERATION)?
            .ok_or(StoreError::MissingAccountingMetadata {
                field: RECORD_SELECTOR_GENERATION,
            })?
            .value(),
    };
    validate_record_subscription_incarnations(&subscriptions, stats.selector_generation)?;
    validate_record_subscription_stats_write(write, stats)?;
    Ok(stats)
}

fn validate_record_subscription_incarnations(
    subscriptions: &BTreeMap<RecordSubscriptionId, RecordSubscriptionRecord>,
    selector_generation: u64,
) -> Result<(), StoreError> {
    let mut incarnations = BTreeSet::new();
    for record in subscriptions.values() {
        if record.incarnation == 0
            || record.incarnation > selector_generation
            || !incarnations.insert(record.incarnation)
        {
            return Err(StoreError::RecordInvariant(
                "Record subscription incarnation is invalid or reused",
            ));
        }
    }
    Ok(())
}

fn record_group_matches_spec(
    authority: NodeId,
    spec: &RecordSubscriptionSpec,
    group: RecordProjectionGroupId,
    record: &StoredRecord,
) -> bool {
    spec.matches_record(record)
        && record_projection_group_id(
            authority,
            &record.header.topic,
            &record.header.scope,
            &record.header.logical_key,
        ) == group
}

fn record_groups_write(
    write: &redb::WriteTransaction,
    authority: NodeId,
) -> Result<BTreeMap<RecordProjectionGroupId, StoredRecord>, StoreError> {
    let mut groups = BTreeMap::<RecordProjectionGroupId, StoredRecord>::new();
    let mut expected_marker = 1u64;
    for row in write.open_table(RECORD_ACCEPTANCE_ORDER)?.iter()? {
        let (marker, transfer) = row?;
        if marker.value() != expected_marker {
            return Err(StoreError::RecordInvariant(
                "Record acceptance-order snapshot is not consecutive",
            ));
        }
        expected_marker = expected_marker
            .checked_add(1)
            .ok_or(StoreError::AcceptanceMarkerExhausted)?;
        let transfer = parse_record_transfer_id("Record acceptance-order table", transfer.value())?;
        let record = load_record_from_write(write, transfer)?.ok_or(
            StoreError::RecordInvariant("Record acceptance-order index points to a missing Record"),
        )?;
        if record.acceptance_marker != marker.value() {
            return Err(StoreError::RecordInvariant(
                "Record acceptance-order index differs from its forward marker",
            ));
        }
        let group = record_projection_group_id(
            authority,
            &record.header.topic,
            &record.header.scope,
            &record.header.logical_key,
        );
        if let Some(existing) = groups.get(&group) {
            if existing.header.topic != record.header.topic
                || existing.header.scope != record.header.scope
                || existing.header.logical_key != record.header.logical_key
            {
                return Err(StoreError::RecordInvariant(
                    "Record projection group digest collision",
                ));
            }
        } else {
            groups.insert(group, record);
        }
    }
    require_complete_record_acceptance_snapshot_write(write, expected_marker)?;
    Ok(groups)
}

fn audit_record_subscription_ledgers_write(
    write: &redb::WriteTransaction,
    subscriptions: &BTreeMap<RecordSubscriptionId, RecordSubscriptionRecord>,
) -> Result<(), StoreError> {
    if write.open_table(RECORD_SUBSCRIPTION_PENDING)?.is_empty()?
        && write
            .open_table(RECORD_DELIVERY_ACKNOWLEDGEMENTS)?
            .is_empty()?
        && write.open_table(RECORD_DELIVERY_CURSORS)?.is_empty()?
    {
        return Ok(());
    }
    let authority = read_mission_binding(write)?.ok_or(StoreError::RecordInvariant(
        "unbound store contains Record delivery ledgers",
    ))?;
    let groups = record_groups_write(write, authority)?;
    let require_key = |subscription: RecordSubscriptionId,
                       group: RecordProjectionGroupId|
     -> Result<(), StoreError> {
        let spec = &subscriptions
            .get(&subscription)
            .ok_or(StoreError::RecordInvariant(
                "Record delivery ledger references a missing subscription",
            ))?
            .spec;
        let record = groups.get(&group).ok_or(StoreError::RecordInvariant(
            "Record delivery ledger references a missing key group",
        ))?;
        if !record_group_matches_spec(authority, spec, group, record) {
            return Err(StoreError::RecordInvariant(
                "Record delivery ledger differs from its subscription",
            ));
        }
        Ok(())
    };
    let mut pending = BTreeMap::new();
    for row in write.open_table(RECORD_SUBSCRIPTION_PENDING)?.iter()? {
        let (key, value) = row?;
        let id = parse_record_ledger_key(key.value())?;
        require_key(id.0, id.1)?;
        if pending
            .insert(id, decode_record_pending_delivery_record(value.value())?)
            .is_some()
        {
            return Err(StoreError::RecordInvariant(
                "duplicate pending Record projection delivery",
            ));
        }
    }
    let mut acknowledgements = BTreeMap::new();
    for row in write.open_table(RECORD_DELIVERY_ACKNOWLEDGEMENTS)?.iter()? {
        let (key, value) = row?;
        let id = parse_record_ledger_key(key.value())?;
        require_key(id.0, id.1)?;
        if pending.contains_key(&id)
            || acknowledgements
                .insert(id, decode_record_acknowledgement_record(value.value())?)
                .is_some()
        {
            return Err(StoreError::RecordInvariant(
                "Record projection is duplicated or both pending and acknowledged",
            ));
        }
    }
    let mut cursor_ids = BTreeSet::new();
    for row in write.open_table(RECORD_DELIVERY_CURSORS)?.iter()? {
        let (key, value) = row?;
        let id = parse_record_ledger_key(key.value())?;
        require_key(id.0, id.1)?;
        let cursor = decode_record_delivery_cursor_record(value.value())?;
        validate_record_candidate_delivery_ledger(
            pending.get(&id).copied(),
            acknowledgements.get(&id).copied(),
            Some(cursor),
        )?;
        cursor_ids.insert(id);
    }
    if pending
        .keys()
        .chain(acknowledgements.keys())
        .any(|id| !cursor_ids.contains(id))
    {
        return Err(StoreError::RecordInvariant(
            "active Record delivery is missing its monotonic cursor",
        ));
    }
    Ok(())
}

fn validate_record_subscription_stats_write(
    write: &redb::WriteTransaction,
    stats: RecordSubscriptionStats,
) -> Result<(), StoreError> {
    if stats.subscriptions > MAX_RECORD_SUBSCRIPTIONS {
        return Err(StoreError::RecordInvariant(
            "Record subscription table exceeds its bounded cardinality",
        ));
    }
    validate_record_delivery_caps(
        stats.pending_deliveries,
        stats.acknowledged_deliveries,
        stats.delivery_cursors,
    )?;
    require_record_subscription_accounting(
        write,
        stats.subscriptions,
        stats.pending_deliveries,
        stats.acknowledged_deliveries,
        stats.delivery_cursors,
    )?;
    Ok(())
}

pub(crate) fn inspect_record_subscription_tables(
    read: &redb::ReadTransaction,
) -> Result<RecordSubscriptionStats, StoreError> {
    if read
        .list_multimap_tables()?
        .any(|table| is_record_subscription_table(table.name()))
    {
        return Err(StoreError::RecordInvariant(
            "Record subscription schema has the wrong table kind",
        ));
    }
    let table_names = read
        .list_tables()?
        .map(|table| table.name().to_owned())
        .collect::<BTreeSet<_>>();
    let tables_present = [
        RECORD_SUBSCRIPTIONS.name(),
        RECORD_SUBSCRIPTION_PENDING.name(),
        RECORD_DELIVERY_ACKNOWLEDGEMENTS.name(),
        RECORD_DELIVERY_CURSORS.name(),
    ]
    .into_iter()
    .filter(|name| table_names.contains(*name))
    .count();
    let metadata = read.open_table(METADATA)?;
    let metadata_presence = [
        metadata.get(RECORD_SUBSCRIPTION_COUNT)?.is_some(),
        metadata.get(RECORD_PENDING_DELIVERY_COUNT)?.is_some(),
        metadata.get(RECORD_ACKNOWLEDGEMENT_COUNT)?.is_some(),
        metadata.get(RECORD_DELIVERY_CURSOR_COUNT)?.is_some(),
        metadata.get(RECORD_SELECTOR_GENERATION)?.is_some(),
    ];
    if tables_present == 0 && metadata_presence.iter().all(|present| !present) {
        if table_names.contains(RECORD_ACCEPTANCE_ORDER.name()) {
            return Err(StoreError::RecordInvariant(
                "Record subscription schema group is incomplete",
            ));
        }
        return Ok(RecordSubscriptionStats::default());
    }
    if tables_present != 4 || metadata_presence.iter().any(|present| !present) {
        return Err(StoreError::RecordInvariant(
            "Record subscription schema group is incomplete",
        ));
    }
    let authority = read_mission_binding_read(read)?;
    let mut subscriptions = BTreeMap::new();
    for row in read.open_table(RECORD_SUBSCRIPTIONS)?.iter()? {
        let (key, value) = row?;
        let id = parse_record_subscription_id(key.value())?;
        let record = decode_record_subscription_record(value.value())?;
        let authority = authority.ok_or(StoreError::RecordInvariant(
            "unbound store contains Record subscriptions",
        ))?;
        if record_subscription_id(authority, &record.operation_key) != id
            || subscriptions.insert(id, record).is_some()
        {
            return Err(StoreError::RecordInvariant(
                "Record subscription identity is invalid or duplicated",
            ));
        }
    }
    audit_record_subscription_ledgers_read(read, authority, &subscriptions)?;
    let stats = RecordSubscriptionStats {
        subscriptions: read.open_table(RECORD_SUBSCRIPTIONS)?.len()?,
        pending_deliveries: read.open_table(RECORD_SUBSCRIPTION_PENDING)?.len()?,
        acknowledged_deliveries: read.open_table(RECORD_DELIVERY_ACKNOWLEDGEMENTS)?.len()?,
        delivery_cursors: read.open_table(RECORD_DELIVERY_CURSORS)?.len()?,
        selector_generation: metadata
            .get(RECORD_SELECTOR_GENERATION)?
            .ok_or(StoreError::MissingAccountingMetadata {
                field: RECORD_SELECTOR_GENERATION,
            })?
            .value(),
    };
    validate_record_subscription_incarnations(&subscriptions, stats.selector_generation)?;
    if stats.subscriptions > MAX_RECORD_SUBSCRIPTIONS {
        return Err(StoreError::RecordInvariant(
            "Record subscription table exceeds its bounded cardinality",
        ));
    }
    validate_record_delivery_caps(
        stats.pending_deliveries,
        stats.acknowledged_deliveries,
        stats.delivery_cursors,
    )?;
    for (field, reconstructed) in [
        (RECORD_SUBSCRIPTION_COUNT, stats.subscriptions),
        (RECORD_PENDING_DELIVERY_COUNT, stats.pending_deliveries),
        (RECORD_ACKNOWLEDGEMENT_COUNT, stats.acknowledged_deliveries),
        (RECORD_DELIVERY_CURSOR_COUNT, stats.delivery_cursors),
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
    validate_record_selector_generation(stats.selector_generation, stats.subscriptions)?;
    Ok(stats)
}

fn audit_record_subscription_ledgers_read(
    read: &redb::ReadTransaction,
    authority: Option<NodeId>,
    subscriptions: &BTreeMap<RecordSubscriptionId, RecordSubscriptionRecord>,
) -> Result<(), StoreError> {
    if read.open_table(RECORD_SUBSCRIPTION_PENDING)?.is_empty()?
        && read
            .open_table(RECORD_DELIVERY_ACKNOWLEDGEMENTS)?
            .is_empty()?
        && read.open_table(RECORD_DELIVERY_CURSORS)?.is_empty()?
    {
        return Ok(());
    }
    let authority = authority.ok_or(StoreError::RecordInvariant(
        "unbound store contains Record delivery ledgers",
    ))?;
    let mut groups = BTreeMap::<RecordProjectionGroupId, StoredRecord>::new();
    let mut expected_marker = 1u64;
    for row in read.open_table(RECORD_ACCEPTANCE_ORDER)?.iter()? {
        let (marker, transfer) = row?;
        if marker.value() != expected_marker {
            return Err(StoreError::RecordInvariant(
                "Record acceptance-order snapshot is not consecutive",
            ));
        }
        expected_marker = expected_marker
            .checked_add(1)
            .ok_or(StoreError::AcceptanceMarkerExhausted)?;
        let transfer = parse_record_transfer_id("Record acceptance-order table", transfer.value())?;
        let record = load_record_from_read(read, transfer)?.ok_or(StoreError::RecordInvariant(
            "Record acceptance-order index points to a missing Record",
        ))?;
        if record.acceptance_marker != marker.value() {
            return Err(StoreError::RecordInvariant(
                "Record acceptance-order index differs from its forward marker",
            ));
        }
        let group = record_projection_group_id(
            authority,
            &record.header.topic,
            &record.header.scope,
            &record.header.logical_key,
        );
        if let Some(existing) = groups.get(&group) {
            if existing.header.topic != record.header.topic
                || existing.header.scope != record.header.scope
                || existing.header.logical_key != record.header.logical_key
            {
                return Err(StoreError::RecordInvariant(
                    "Record projection group digest collision",
                ));
            }
        } else {
            groups.insert(group, record);
        }
    }
    require_complete_record_acceptance_snapshot_read(read, expected_marker)?;
    let require_key = |subscription: RecordSubscriptionId,
                       group: RecordProjectionGroupId|
     -> Result<(), StoreError> {
        let spec = &subscriptions
            .get(&subscription)
            .ok_or(StoreError::RecordInvariant(
                "Record delivery ledger references a missing subscription",
            ))?
            .spec;
        let record = groups.get(&group).ok_or(StoreError::RecordInvariant(
            "Record delivery ledger references a missing key group",
        ))?;
        if !record_group_matches_spec(authority, spec, group, record) {
            return Err(StoreError::RecordInvariant(
                "Record delivery ledger differs from its subscription",
            ));
        }
        Ok(())
    };
    let mut pending = BTreeMap::new();
    for row in read.open_table(RECORD_SUBSCRIPTION_PENDING)?.iter()? {
        let (key, value) = row?;
        let id = parse_record_ledger_key(key.value())?;
        require_key(id.0, id.1)?;
        if pending
            .insert(id, decode_record_pending_delivery_record(value.value())?)
            .is_some()
        {
            return Err(StoreError::RecordInvariant(
                "duplicate pending Record projection delivery",
            ));
        }
    }
    let mut acknowledgements = BTreeMap::new();
    for row in read.open_table(RECORD_DELIVERY_ACKNOWLEDGEMENTS)?.iter()? {
        let (key, value) = row?;
        let id = parse_record_ledger_key(key.value())?;
        require_key(id.0, id.1)?;
        if pending.contains_key(&id)
            || acknowledgements
                .insert(id, decode_record_acknowledgement_record(value.value())?)
                .is_some()
        {
            return Err(StoreError::RecordInvariant(
                "Record projection is duplicated or both pending and acknowledged",
            ));
        }
    }
    let mut cursor_ids = BTreeSet::new();
    for row in read.open_table(RECORD_DELIVERY_CURSORS)?.iter()? {
        let (key, value) = row?;
        let id = parse_record_ledger_key(key.value())?;
        require_key(id.0, id.1)?;
        validate_record_candidate_delivery_ledger(
            pending.get(&id).copied(),
            acknowledgements.get(&id).copied(),
            Some(decode_record_delivery_cursor_record(value.value())?),
        )?;
        cursor_ids.insert(id);
    }
    if pending
        .keys()
        .chain(acknowledgements.keys())
        .any(|id| !cursor_ids.contains(id))
    {
        return Err(StoreError::RecordInvariant(
            "active Record delivery is missing its monotonic cursor",
        ));
    }
    Ok(())
}

fn parse_record_subscription_id(bytes: &[u8]) -> Result<RecordSubscriptionId, StoreError> {
    let bytes: [u8; 32] = bytes.try_into().map_err(|_| {
        StoreError::RecordInvariant("Record subscription identifier has invalid length")
    })?;
    Ok(RecordSubscriptionId::from_bytes(bytes))
}
