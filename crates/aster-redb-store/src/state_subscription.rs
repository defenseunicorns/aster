//! Durable current-projection State application subscriptions.
//!
//! State delivery differs from Event delivery: one poll must reduce a complete
//! bounded matching snapshot so acknowledging a current head can never make an
//! unacknowledged ancestor visible again. The store owns durable selector,
//! pending-attempt, and acknowledgement structure. `aster-node` remains the
//! privileged source/content verifier and supplies the exact current,
//! noncurrent, and inactive partition before commit.

use std::collections::{BTreeMap, BTreeSet};

use aster_mesh::{NodeId, Scope, Topic};
use redb::{
    MultimapTableHandle, ReadableDatabase, ReadableTable, ReadableTableMetadata, TableDefinition,
    TableHandle,
};
use sha2::{Digest, Sha256};

use super::{
    ControlPolicySnapshot, LAST_STATE_ACCEPTANCE_MARKER, METADATA, MetadataCursor,
    STATE_ACCEPTANCE_ORDER, STATE_SEMANTIC_ITEMS, StateSemanticId, Store, StoreError, StoredState,
    enforce_live_write, load_state_from_read, load_state_from_write, parse_state_transfer_id,
    read_mission_binding, read_mission_binding_read, require_control_policy_read,
    require_control_policy_write,
};

pub(crate) const STATE_SUBSCRIPTIONS: TableDefinition<&[u8], &[u8]> =
    TableDefinition::new("aster.semantic-state-subscriptions.v1");
pub(crate) const STATE_SUBSCRIPTION_PENDING: TableDefinition<&[u8], &[u8]> =
    TableDefinition::new("aster.semantic-state-delivery-pending.v1");
pub(crate) const STATE_DELIVERY_ACKNOWLEDGEMENTS: TableDefinition<&[u8], &[u8]> =
    TableDefinition::new("aster.semantic-state-delivery-acknowledgements.v1");
pub(crate) const STATE_DELIVERY_CURSORS: TableDefinition<&[u8], &[u8]> =
    TableDefinition::new("aster.semantic-state-delivery-cursors.v1");

pub(crate) const STATE_SUBSCRIPTION_COUNT: &str = "semantic_state_subscription_count";
pub(crate) const STATE_PENDING_DELIVERY_COUNT: &str = "semantic_state_pending_delivery_count";
pub(crate) const STATE_ACKNOWLEDGEMENT_COUNT: &str = "semantic_state_acknowledgement_count";
pub(crate) const STATE_DELIVERY_CURSOR_COUNT: &str = "semantic_state_delivery_cursor_count";
pub(crate) const STATE_SELECTOR_GENERATION: &str = "semantic_state_selector_generation";

const STATE_SUBSCRIPTION_VERSION: u8 = 1;
const STATE_PENDING_DELIVERY_VERSION: u8 = 1;
const STATE_ACKNOWLEDGEMENT_VERSION: u8 = 1;
const STATE_DELIVERY_CURSOR_VERSION: u8 = 1;
const STATE_DELIVERY_TOKEN_VERSION: u8 = 1;
const STATE_SUBSCRIPTION_ID_DOMAIN: &[u8] = b"aster/state-subscription-id/v1";
const STATE_DELIVERY_TOKEN_DOMAIN: &[u8] = b"aster/state-delivery-token/v1";
const STATE_DELIVERY_TOKEN_COUNTER_BYTES: usize = 1 + (3 * 8);

/// Maximum byte length of one durable State subscription operation key.
pub const MAX_STATE_SUBSCRIPTION_KEY_BYTES: usize = 256;
/// Maximum durable State application subscriptions in one mission-bound store.
pub const MAX_STATE_SUBSCRIPTIONS: u64 = 256;
/// Maximum current State heads returned by one poll.
pub const MAX_STATE_POLL_DELIVERIES: usize = 128;
/// Maximum matching retained State versions freshly verified by one poll.
pub const MAX_STATE_SUBSCRIPTION_SCAN: usize = 4_096;
/// Dedicated hard cap for unacknowledged State delivery attempts.
pub const MAX_STATE_PENDING_DELIVERIES: u64 = 262_144;
/// Hard cap for durable idempotent State acknowledgement receipts.
pub const MAX_STATE_ACKNOWLEDGEMENT_RECEIPTS: u64 = 262_144;
/// Hard cap for durable monotonic per-State delivery cursors.
pub const MAX_STATE_DELIVERY_CURSORS: u64 = 262_144;
/// Canonical byte length of one opaque State delivery acknowledgement token.
pub const STATE_DELIVERY_TOKEN_BYTES: usize = STATE_DELIVERY_TOKEN_COUNTER_BYTES + 32;

/// Stable mission-local identity of one durable State application subscription.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct StateSubscriptionId([u8; 32]);

impl StateSubscriptionId {
    /// Constructs an identifier from complete durable bytes.
    pub const fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// Returns the complete durable identifier bytes.
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

/// Bounded application idempotency key for one State subscription.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct StateSubscriptionKey(Vec<u8>);

impl StateSubscriptionKey {
    /// Validates one nonempty durable subscription key.
    pub fn new(bytes: impl Into<Vec<u8>>) -> Result<Self, StoreError> {
        let bytes = bytes.into();
        if bytes.is_empty() || bytes.len() > MAX_STATE_SUBSCRIPTION_KEY_BYTES {
            return Err(StoreError::InvalidStateSubscriptionKey {
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

/// One durable State application-delivery selector.
///
/// This is local intent, never route or content authority.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct StateSubscriptionSpec {
    /// Exact selected topic.
    pub topic: Topic,
    /// Exact selected scope or ancestor scope when descendants are enabled.
    pub scope: Scope,
    /// Whether descendant scopes are included in addition to the exact scope.
    pub include_descendant_scopes: bool,
}

impl StateSubscriptionSpec {
    pub(crate) fn matches(&self, state: &StoredState) -> bool {
        self.topic == state.header.topic
            && if self.include_descendant_scopes {
                self.scope.contains(&state.header.scope)
            } else {
                self.scope == state.header.scope
            }
    }
}

/// Result of idempotently creating one durable State subscription.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct StateSubscriptionCreateOutcome {
    /// Stable mission-local subscription identity.
    pub id: StateSubscriptionId,
    /// True only when this call inserted the durable row.
    pub inserted: bool,
}

/// Result of idempotently removing one State selector and its ledgers.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct StateSubscriptionRemoveOutcome {
    /// Stable identity supplied by the caller.
    pub id: StateSubscriptionId,
    /// True only when this call removed durable state.
    pub removed: bool,
}

/// One complete-snapshot State candidate requiring fresh verification.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct StateSubscriptionCandidate {
    state: StoredState,
    pending_attempt: Option<u64>,
    acknowledged_attempt: Option<u64>,
    delivery_cursor: Option<StateDeliveryCursorRecord>,
}

impl StateSubscriptionCandidate {
    /// Exact retained source State requiring fresh verification.
    pub const fn state(&self) -> &StoredState {
        &self.state
    }

    /// Previously committed unacknowledged attempt, when any.
    pub const fn pending_attempt(&self) -> Option<u64> {
        self.pending_attempt
    }

    /// Durable acknowledgement attempt, when this exact version was acknowledged.
    pub const fn acknowledged_attempt(&self) -> Option<u64> {
        self.acknowledged_attempt
    }

    /// Highest attempt committed in this State's most recently allocated projection tenure.
    pub const fn last_delivery_attempt(&self) -> Option<u64> {
        match self.delivery_cursor {
            Some(cursor) => Some(cursor.last_attempt),
            None => None,
        }
    }

    /// Monotonic current-projection tenure last allocated to this State.
    pub const fn delivery_tenure(&self) -> Option<u64> {
        match self.delivery_cursor {
            Some(cursor) => Some(cursor.tenure),
            None => None,
        }
    }
}

/// Complete bounded matching-State snapshot prepared for privileged verification.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct StateSubscriptionPollPlan {
    policy: ControlPolicySnapshot,
    subscription: StateSubscriptionId,
    spec: StateSubscriptionSpec,
    incarnation: u64,
    selector_generation: u64,
    candidates: Vec<StateSubscriptionCandidate>,
    delivery_limit: usize,
    scan_limit: usize,
}

impl StateSubscriptionPollPlan {
    /// Stable identity of the planned subscription.
    pub const fn subscription(&self) -> StateSubscriptionId {
        self.subscription
    }

    /// Exact durable selector observed by the plan transaction.
    pub const fn spec(&self) -> &StateSubscriptionSpec {
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
    pub fn candidates(&self) -> &[StateSubscriptionCandidate] {
        &self.candidates
    }
}

/// Privileged freshly verified partition of one complete State poll snapshot.
///
/// Every candidate semantic ID must appear exactly once. The store rechecks
/// exact durable structure; `aster-node` owns source/content and current-lineage
/// verification before constructing this value.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct StateSubscriptionPollSelection {
    /// Freshly verified application-current State heads.
    pub current: Vec<StateSemanticId>,
    /// Freshly verified active concurrent or superseded versions.
    pub noncurrent: Vec<StateSemanticId>,
    /// Freshly verified revoked, stale-epoch, or historical-lineage versions.
    pub inactive: Vec<StateSemanticId>,
}

/// One at-least-once current-State delivery committed before application return.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct StateSubscriptionDelivery {
    /// Exact accepted current State for this committed attempt.
    pub state: StoredState,
    /// Nonzero durable delivery-attempt number.
    pub attempt: u64,
    /// Opaque durable acknowledgement token for this exact delivery tenure and attempt.
    pub token: StateDeliveryToken,
}

/// Opaque activation-safe acknowledgement identity for one committed State delivery.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct StateDeliveryToken([u8; STATE_DELIVERY_TOKEN_BYTES]);

impl StateDeliveryToken {
    /// Reconstructs one canonical opaque token transported by the application boundary.
    ///
    /// Its subscription and State binding is revalidated by acknowledgement.
    pub fn from_bytes(bytes: [u8; STATE_DELIVERY_TOKEN_BYTES]) -> Result<Self, StoreError> {
        let token = Self(bytes);
        if token.0[0] != STATE_DELIVERY_TOKEN_VERSION
            || token.incarnation() == 0
            || token.tenure() == 0
            || token.attempt() == 0
        {
            return Err(StoreError::InvalidStateDeliveryToken);
        }
        Ok(token)
    }

    /// Returns the complete canonical opaque token bytes.
    pub const fn as_bytes(&self) -> &[u8; STATE_DELIVERY_TOKEN_BYTES] {
        &self.0
    }

    pub(crate) fn incarnation(self) -> u64 {
        u64::from_be_bytes(
            self.0[1..9]
                .try_into()
                .expect("fixed State delivery-token incarnation"),
        )
    }

    pub(crate) fn tenure(self) -> u64 {
        u64::from_be_bytes(
            self.0[9..17]
                .try_into()
                .expect("fixed State delivery-token tenure"),
        )
    }

    pub(crate) fn attempt(self) -> u64 {
        u64::from_be_bytes(
            self.0[17..25]
                .try_into()
                .expect("fixed State delivery-token attempt"),
        )
    }
}

/// Result of one complete-snapshot State subscription poll commit.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct StateSubscriptionDeliveryPage {
    /// Pending-first, marker-ordered attempts committed before return.
    pub deliveries: Vec<StateSubscriptionDelivery>,
    /// True when additional unacknowledged current heads remain.
    pub has_more: bool,
}

/// Idempotent acknowledgement result for one semantic State delivery.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum StateDeliveryAck {
    /// This call atomically replaced a pending attempt with a receipt.
    Acknowledged,
    /// An exact durable acknowledgement receipt already exists.
    AlreadyAcknowledged,
}

/// Consistent durable counts for State selectors and deliveries.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct StateSubscriptionStats {
    /// Durable State application selectors.
    pub subscriptions: u64,
    /// Unacknowledged attempted current-State deliveries.
    pub pending_deliveries: u64,
    /// Durable receipts for States still current in their last committed classification.
    pub acknowledged_deliveries: u64,
    /// Durable monotonic per-State delivery cursors, including retired tenures.
    pub delivery_cursors: u64,
    /// Mutation generation advanced by each actual insert or removal.
    pub selector_generation: u64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct StateSubscriptionRecord {
    operation_key: StateSubscriptionKey,
    spec: StateSubscriptionSpec,
    incarnation: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct StatePendingDeliveryRecord {
    semantic_id: StateSemanticId,
    tenure: u64,
    attempts: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct StateAcknowledgementRecord {
    acceptance_marker: u64,
    tenure: u64,
    attempts: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct StateDeliveryCursorRecord {
    acceptance_marker: u64,
    tenure: u64,
    last_attempt: u64,
    last_acknowledged_tenure: u64,
    last_acknowledged_attempt: u64,
}

impl Store {
    /// Returns structurally audited State subscription counts.
    pub fn state_subscription_stats(&self) -> Result<StateSubscriptionStats, StoreError> {
        self.require_bound_mission()?;
        let read = self.database.begin_read()?;
        inspect_state_subscription_tables(&read)
    }

    /// Idempotently creates one durable State application selector.
    pub fn create_state_subscription_with_policy(
        &self,
        policy: &ControlPolicySnapshot,
        key: &StateSubscriptionKey,
        spec: StateSubscriptionSpec,
    ) -> Result<StateSubscriptionCreateOutcome, StoreError> {
        self.require_live()?;
        let authority = self.require_bound_mission()?;
        let id = state_subscription_id(authority, key);
        let write = self.database.begin_write()?;
        enforce_live_write(&write)?;
        require_control_policy_write(&write, authority, policy)?;
        let existing = write
            .open_table(STATE_SUBSCRIPTIONS)?
            .get(id.as_bytes().as_slice())?
            .map(|value| decode_state_subscription_record(value.value()))
            .transpose()?;
        if let Some(existing) = existing {
            if existing.operation_key != *key || existing.spec != spec {
                return Err(StoreError::StateSubscriptionConflict);
            }
            return Ok(StateSubscriptionCreateOutcome {
                id,
                inserted: false,
            });
        }

        let current_count = write.open_table(STATE_SUBSCRIPTIONS)?.len()?;
        if current_count >= MAX_STATE_SUBSCRIPTIONS {
            return Err(StoreError::StateSubscriptionLimitExceeded {
                current: current_count,
                limit: MAX_STATE_SUBSCRIPTIONS,
            });
        }
        let (durable_count, generation) = {
            let metadata = write.open_table(METADATA)?;
            let count = metadata
                .get(STATE_SUBSCRIPTION_COUNT)?
                .ok_or(StoreError::MissingAccountingMetadata {
                    field: STATE_SUBSCRIPTION_COUNT,
                })?
                .value();
            let generation = metadata
                .get(STATE_SELECTOR_GENERATION)?
                .ok_or(StoreError::MissingAccountingMetadata {
                    field: STATE_SELECTOR_GENERATION,
                })?
                .value();
            (count, generation)
        };
        if durable_count != current_count {
            return Err(StoreError::AccountingMismatch {
                field: STATE_SUBSCRIPTION_COUNT,
                durable: durable_count,
                reconstructed: current_count,
            });
        }
        validate_state_selector_generation(generation, current_count)?;
        let incarnation = generation
            .checked_add(1)
            .ok_or(StoreError::ItemCountAccountingOverflow)?;
        let record = StateSubscriptionRecord {
            operation_key: key.clone(),
            spec,
            incarnation,
        };
        let encoded = encode_state_subscription_record(&record)?;
        write
            .open_table(STATE_SUBSCRIPTIONS)?
            .insert(id.as_bytes().as_slice(), encoded.as_slice())?;
        {
            let mut metadata = write.open_table(METADATA)?;
            metadata.insert(
                STATE_SUBSCRIPTION_COUNT,
                current_count
                    .checked_add(1)
                    .ok_or(StoreError::ItemCountAccountingOverflow)?,
            )?;
            metadata.insert(STATE_SELECTOR_GENERATION, incarnation)?;
        }
        write.commit()?;
        Ok(StateSubscriptionCreateOutcome { id, inserted: true })
    }

    /// Idempotently removes one State selector and all delivery evidence.
    pub fn remove_state_subscription_with_policy(
        &self,
        policy: &ControlPolicySnapshot,
        id: StateSubscriptionId,
    ) -> Result<StateSubscriptionRemoveOutcome, StoreError> {
        self.require_live()?;
        let authority = self.require_bound_mission()?;
        let write = self.database.begin_write()?;
        enforce_live_write(&write)?;
        require_control_policy_write(&write, authority, policy)?;
        let record = write
            .open_table(STATE_SUBSCRIPTIONS)?
            .get(id.as_bytes().as_slice())?
            .map(|value| decode_state_subscription_record(value.value()))
            .transpose()?;
        let Some(record) = record else {
            return Ok(StateSubscriptionRemoveOutcome { id, removed: false });
        };
        if state_subscription_id(authority, &record.operation_key) != id {
            return Err(StoreError::StateInvariant(
                "State subscription identifier differs from its operation key",
            ));
        }

        let subscription_count = write.open_table(STATE_SUBSCRIPTIONS)?.len()?;
        let pending_count = write.open_table(STATE_SUBSCRIPTION_PENDING)?.len()?;
        let acknowledgement_count = write.open_table(STATE_DELIVERY_ACKNOWLEDGEMENTS)?.len()?;
        let cursor_count = write.open_table(STATE_DELIVERY_CURSORS)?.len()?;
        let generation = require_state_subscription_accounting(
            &write,
            subscription_count,
            pending_count,
            acknowledgement_count,
            cursor_count,
        )?;

        let mut pending_removals = Vec::new();
        for row in write.open_table(STATE_SUBSCRIPTION_PENDING)?.iter()? {
            let (key, value) = row?;
            let (row_subscription, _) = parse_state_pending_delivery_key(key.value())?;
            if row_subscription == id {
                decode_state_pending_delivery_record(value.value())?;
                pending_removals.push(key.value().to_vec());
            }
        }
        let mut acknowledgement_removals = Vec::new();
        for row in write.open_table(STATE_DELIVERY_ACKNOWLEDGEMENTS)?.iter()? {
            let (key, value) = row?;
            let (row_subscription, _) = parse_state_acknowledgement_key(key.value())?;
            if row_subscription == id {
                decode_state_acknowledgement_record(value.value())?;
                acknowledgement_removals.push(key.value().to_vec());
            }
        }
        let mut cursor_removals = Vec::new();
        for row in write.open_table(STATE_DELIVERY_CURSORS)?.iter()? {
            let (key, value) = row?;
            let (row_subscription, _) = parse_state_delivery_cursor_key(key.value())?;
            if row_subscription == id {
                decode_state_delivery_cursor_record(value.value())?;
                cursor_removals.push(key.value().to_vec());
            }
        }
        {
            let mut pending = write.open_table(STATE_SUBSCRIPTION_PENDING)?;
            for key in &pending_removals {
                pending.remove(key.as_slice())?;
            }
        }
        {
            let mut acknowledgements = write.open_table(STATE_DELIVERY_ACKNOWLEDGEMENTS)?;
            for key in &acknowledgement_removals {
                acknowledgements.remove(key.as_slice())?;
            }
        }
        {
            let mut cursors = write.open_table(STATE_DELIVERY_CURSORS)?;
            for key in &cursor_removals {
                cursors.remove(key.as_slice())?;
            }
        }
        if write
            .open_table(STATE_SUBSCRIPTIONS)?
            .remove(id.as_bytes().as_slice())?
            .is_none()
        {
            return Err(StoreError::StateInvariant(
                "State subscription disappeared during its write transaction",
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
                STATE_SUBSCRIPTION_COUNT,
                subscription_count
                    .checked_sub(1)
                    .ok_or(StoreError::StateInvariant(
                        "State subscription counter underflow",
                    ))?,
            )?;
            metadata.insert(
                STATE_PENDING_DELIVERY_COUNT,
                pending_count
                    .checked_sub(removed_pending)
                    .ok_or(StoreError::StateInvariant(
                        "State pending-delivery counter underflow",
                    ))?,
            )?;
            metadata.insert(
                STATE_ACKNOWLEDGEMENT_COUNT,
                acknowledgement_count
                    .checked_sub(removed_acknowledgements)
                    .ok_or(StoreError::StateInvariant(
                        "State acknowledgement counter underflow",
                    ))?,
            )?;
            metadata.insert(
                STATE_DELIVERY_CURSOR_COUNT,
                cursor_count
                    .checked_sub(removed_cursors)
                    .ok_or(StoreError::StateInvariant(
                        "State delivery-cursor counter underflow",
                    ))?,
            )?;
            metadata.insert(
                STATE_SELECTOR_GENERATION,
                generation
                    .checked_add(1)
                    .ok_or(StoreError::ItemCountAccountingOverflow)?,
            )?;
        }
        write.commit()?;
        Ok(StateSubscriptionRemoveOutcome { id, removed: true })
    }

    /// Prepares a complete bounded matching-State snapshot for fresh verification.
    pub fn prepare_state_subscription_poll_with_policy(
        &self,
        policy: &ControlPolicySnapshot,
        subscription: StateSubscriptionId,
        delivery_limit: usize,
        scan_limit: usize,
    ) -> Result<StateSubscriptionPollPlan, StoreError> {
        self.require_live()?;
        let authority = self.require_bound_mission()?;
        validate_state_poll_limits(delivery_limit, scan_limit)?;
        let read = self.database.begin_read()?;
        require_control_policy_read(&read, authority, policy)?;
        let record = read
            .open_table(STATE_SUBSCRIPTIONS)?
            .get(subscription.as_bytes().as_slice())?
            .map(|value| decode_state_subscription_record(value.value()))
            .transpose()?
            .ok_or(StoreError::StateSubscriptionNotFound)?;
        let selector_generation = read
            .open_table(METADATA)?
            .get(STATE_SELECTOR_GENERATION)?
            .ok_or(StoreError::MissingAccountingMetadata {
                field: STATE_SELECTOR_GENERATION,
            })?
            .value();
        let subscription_count = read.open_table(STATE_SUBSCRIPTIONS)?.len()?;
        validate_state_selector_generation(selector_generation, subscription_count)?;
        let candidates =
            state_subscription_candidates_read(&read, subscription, &record.spec, scan_limit)?;
        Ok(StateSubscriptionPollPlan {
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

    /// Commits one exact freshly verified current/noncurrent/inactive partition.
    pub fn commit_state_subscription_poll_with_policy(
        &self,
        policy: &ControlPolicySnapshot,
        plan: &StateSubscriptionPollPlan,
        selection: &StateSubscriptionPollSelection,
    ) -> Result<StateSubscriptionDeliveryPage, StoreError> {
        self.require_live()?;
        let authority = self.require_bound_mission()?;
        validate_state_poll_limits(plan.delivery_limit, plan.scan_limit)?;
        if policy != &plan.policy || plan.candidates.len() > plan.scan_limit {
            return Err(StoreError::StateSubscriptionPlanChanged);
        }
        let partition = validate_state_selection(plan, selection)?;

        let write = self.database.begin_write()?;
        enforce_live_write(&write)?;
        require_control_policy_write(&write, authority, policy)?;
        let record = write
            .open_table(STATE_SUBSCRIPTIONS)?
            .get(plan.subscription.as_bytes().as_slice())?
            .map(|value| decode_state_subscription_record(value.value()))
            .transpose()?
            .ok_or(StoreError::StateSubscriptionNotFound)?;
        let generation = write
            .open_table(METADATA)?
            .get(STATE_SELECTOR_GENERATION)?
            .ok_or(StoreError::MissingAccountingMetadata {
                field: STATE_SELECTOR_GENERATION,
            })?
            .value();
        if record.spec != plan.spec
            || record.incarnation != plan.incarnation
            || generation != plan.selector_generation
        {
            return Err(StoreError::StateSelectorGenerationChanged);
        }
        let durable_candidates = state_subscription_candidates_write(
            &write,
            plan.subscription,
            &record.spec,
            plan.scan_limit,
        )?;
        if durable_candidates != plan.candidates {
            return Err(StoreError::StateSubscriptionPlanChanged);
        }

        let subscription_count = write.open_table(STATE_SUBSCRIPTIONS)?.len()?;
        let pending_count = write.open_table(STATE_SUBSCRIPTION_PENDING)?.len()?;
        let acknowledgement_count = write.open_table(STATE_DELIVERY_ACKNOWLEDGEMENTS)?.len()?;
        let cursor_count = write.open_table(STATE_DELIVERY_CURSORS)?.len()?;
        require_state_subscription_accounting(
            &write,
            subscription_count,
            pending_count,
            acknowledgement_count,
            cursor_count,
        )?;

        let mut retire_pending = Vec::new();
        let mut retire_acknowledgements = Vec::new();
        let mut pending_current = Vec::new();
        let mut new_current = Vec::new();
        for candidate in &durable_candidates {
            let id = candidate.state.semantic_id;
            if !partition.current.contains(&id) {
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
                pending_current.push(candidate);
            } else {
                new_current.push(candidate);
            }
        }
        pending_current.sort_by_key(|candidate| candidate.state.acceptance_marker);
        new_current.sort_by_key(|candidate| candidate.state.acceptance_marker);
        let eligible_count = pending_current
            .len()
            .checked_add(new_current.len())
            .ok_or(StoreError::ItemCountAccountingOverflow)?;
        let chosen = pending_current
            .into_iter()
            .chain(new_current)
            .take(plan.delivery_limit)
            .collect::<Vec<_>>();
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
            .ok_or(StoreError::StateInvariant(
                "State pending retirement underflows accounting",
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
            .ok_or(StoreError::StateInvariant(
                "State acknowledgement retirement underflows accounting",
            ))?;
        let final_cursor_count = cursor_count
            .checked_add(
                u64::try_from(new_cursor_count)
                    .map_err(|_| StoreError::ItemCountAccountingOverflow)?,
            )
            .ok_or(StoreError::ItemCountAccountingOverflow)?;
        if final_pending_count > MAX_STATE_PENDING_DELIVERIES {
            return Err(StoreError::StatePendingDeliveryLimitExceeded {
                current: final_pending_count,
                limit: MAX_STATE_PENDING_DELIVERIES,
            });
        }
        let combined = final_pending_count
            .checked_add(final_acknowledgement_count)
            .ok_or(StoreError::ItemCountAccountingOverflow)?;
        if combined > MAX_STATE_ACKNOWLEDGEMENT_RECEIPTS {
            return Err(StoreError::StateDeliveryLedgerLimitExceeded {
                current: combined,
                limit: MAX_STATE_ACKNOWLEDGEMENT_RECEIPTS,
            });
        }
        if final_cursor_count > MAX_STATE_DELIVERY_CURSORS {
            return Err(StoreError::StateDeliveryLedgerLimitExceeded {
                current: final_cursor_count,
                limit: MAX_STATE_DELIVERY_CURSORS,
            });
        }

        let mut tenures = Vec::with_capacity(chosen.len());
        let mut attempts = Vec::with_capacity(chosen.len());
        for candidate in &chosen {
            if candidate.pending_attempt.is_some() {
                let cursor = candidate.delivery_cursor.ok_or(StoreError::StateInvariant(
                    "pending State delivery is missing its monotonic cursor",
                ))?;
                tenures.push(cursor.tenure);
                attempts.push(
                    cursor
                        .last_attempt
                        .checked_add(1)
                        .ok_or(StoreError::StateDeliveryAttemptExhausted)?,
                );
            } else {
                tenures.push(match candidate.delivery_cursor {
                    Some(cursor) => cursor
                        .tenure
                        .checked_add(1)
                        .ok_or(StoreError::StateDeliveryTenureExhausted)?,
                    None => 1,
                });
                attempts.push(1);
            }
        }
        {
            let mut pending = write.open_table(STATE_SUBSCRIPTION_PENDING)?;
            for candidate in &retire_pending {
                let key = state_pending_delivery_key(
                    plan.subscription,
                    candidate.state.acceptance_marker,
                );
                if pending.remove(key.as_slice())?.is_none() {
                    return Err(StoreError::StateSubscriptionPlanChanged);
                }
            }
            for ((candidate, tenure), attempt) in chosen.iter().zip(&tenures).zip(&attempts) {
                let key = state_pending_delivery_key(
                    plan.subscription,
                    candidate.state.acceptance_marker,
                );
                let encoded = encode_state_pending_delivery_record(StatePendingDeliveryRecord {
                    semantic_id: candidate.state.semantic_id,
                    tenure: *tenure,
                    attempts: *attempt,
                });
                pending.insert(key.as_slice(), encoded.as_slice())?;
            }
        }
        {
            let mut acknowledgements = write.open_table(STATE_DELIVERY_ACKNOWLEDGEMENTS)?;
            for candidate in &retire_acknowledgements {
                let key = state_acknowledgement_key(plan.subscription, candidate.state.semantic_id);
                if acknowledgements.remove(key.as_slice())?.is_none() {
                    return Err(StoreError::StateSubscriptionPlanChanged);
                }
            }
        }
        {
            let mut cursors = write.open_table(STATE_DELIVERY_CURSORS)?;
            for ((candidate, tenure), attempt) in chosen.iter().zip(&tenures).zip(&attempts) {
                let key = state_delivery_cursor_key(plan.subscription, candidate.state.semantic_id);
                let encoded = encode_state_delivery_cursor_record(StateDeliveryCursorRecord {
                    acceptance_marker: candidate.state.acceptance_marker,
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
            metadata.insert(STATE_PENDING_DELIVERY_COUNT, final_pending_count)?;
            metadata.insert(STATE_ACKNOWLEDGEMENT_COUNT, final_acknowledgement_count)?;
            metadata.insert(STATE_DELIVERY_CURSOR_COUNT, final_cursor_count)?;
        }
        write.commit()?;

        Ok(StateSubscriptionDeliveryPage {
            deliveries: chosen
                .into_iter()
                .zip(tenures)
                .zip(attempts)
                .map(|((candidate, tenure), attempt)| StateSubscriptionDelivery {
                    state: candidate.state.clone(),
                    attempt,
                    token: state_delivery_token(
                        plan.subscription,
                        candidate.state.semantic_id,
                        plan.incarnation,
                        tenure,
                        attempt,
                    ),
                })
                .collect(),
            has_more: eligible_count > plan.delivery_limit,
        })
    }

    /// Idempotently acknowledges one exact semantic State delivery.
    pub fn acknowledge_state_delivery_with_policy(
        &self,
        policy: &ControlPolicySnapshot,
        subscription: StateSubscriptionId,
        semantic_id: StateSemanticId,
        token: StateDeliveryToken,
    ) -> Result<StateDeliveryAck, StoreError> {
        let token = validate_state_delivery_token_binding(subscription, semantic_id, token)?;
        self.require_live()?;
        let authority = self.require_bound_mission()?;
        let write = self.database.begin_write()?;
        enforce_live_write(&write)?;
        require_control_policy_write(&write, authority, policy)?;
        let record = write
            .open_table(STATE_SUBSCRIPTIONS)?
            .get(subscription.as_bytes().as_slice())?
            .map(|value| decode_state_subscription_record(value.value()))
            .transpose()?
            .ok_or(StoreError::StateSubscriptionNotFound)?;
        if token.incarnation != record.incarnation {
            return Err(StoreError::StateSubscriptionIncarnationChanged {
                current: record.incarnation,
                received: token.incarnation,
            });
        }
        let state = load_state_by_semantic_from_write(&write, semantic_id)?
            .ok_or(StoreError::StateDeliveryNotFound)?;
        if !record.spec.matches(&state) {
            return Err(StoreError::StateDeliveryNotFound);
        }
        let cursor_key = state_delivery_cursor_key(subscription, semantic_id);
        let mut cursor = write
            .open_table(STATE_DELIVERY_CURSORS)?
            .get(cursor_key.as_slice())?
            .map(|value| decode_state_delivery_cursor_record(value.value()))
            .transpose()?
            .ok_or(StoreError::StateDeliveryNotFound)?;
        if cursor.acceptance_marker != state.acceptance_marker {
            return Err(StoreError::StateInvariant(
                "State delivery cursor differs from its accepted State",
            ));
        }
        let acknowledgement_key = state_acknowledgement_key(subscription, semantic_id);
        let receipt = write
            .open_table(STATE_DELIVERY_ACKNOWLEDGEMENTS)?
            .get(acknowledgement_key.as_slice())?
            .map(|value| decode_state_acknowledgement_record(value.value()))
            .transpose()?;
        let pending_key = state_pending_delivery_key(subscription, state.acceptance_marker);
        let pending = write
            .open_table(STATE_SUBSCRIPTION_PENDING)?
            .get(pending_key.as_slice())?
            .map(|value| decode_state_pending_delivery_record(value.value()))
            .transpose()?;
        if receipt.is_some() && pending.is_some() {
            return Err(StoreError::StateInvariant(
                "State delivery is both pending and acknowledged",
            ));
        }
        if let Some(receipt) = receipt {
            if receipt.acceptance_marker != state.acceptance_marker
                || receipt.tenure != cursor.tenure
                || receipt.tenure != cursor.last_acknowledged_tenure
                || receipt.attempts != cursor.last_acknowledged_attempt
                || receipt.attempts > cursor.last_attempt
            {
                return Err(StoreError::StateInvariant(
                    "State acknowledgement differs from its delivery cursor",
                ));
            }
            if token.tenure != receipt.tenure {
                return Err(StoreError::StateDeliveryTenureChanged {
                    current: receipt.tenure,
                    received: token.tenure,
                });
            }
            validate_state_delivery_token_attempt(token.attempt, receipt.attempts)?;
            return Ok(StateDeliveryAck::AlreadyAcknowledged);
        }
        let Some(pending) = pending else {
            if token.tenure == cursor.last_acknowledged_tenure
                && token.attempt > 0
                && token.attempt <= cursor.last_acknowledged_attempt
            {
                return Ok(StateDeliveryAck::AlreadyAcknowledged);
            }
            return Err(StoreError::StateDeliveryTenureChanged {
                current: cursor.tenure,
                received: token.tenure,
            });
        };
        if pending.semantic_id != semantic_id
            || pending.tenure != cursor.tenure
            || pending.attempts != cursor.last_attempt
        {
            return Err(StoreError::StateInvariant(
                "pending State delivery differs from its monotonic cursor",
            ));
        }
        if token.tenure != pending.tenure {
            if token.tenure == cursor.last_acknowledged_tenure
                && token.attempt > 0
                && token.attempt <= cursor.last_acknowledged_attempt
            {
                return Ok(StateDeliveryAck::AlreadyAcknowledged);
            }
            return Err(StoreError::StateDeliveryTenureChanged {
                current: pending.tenure,
                received: token.tenure,
            });
        }
        validate_state_delivery_token_attempt(token.attempt, pending.attempts)?;

        let subscription_count = write.open_table(STATE_SUBSCRIPTIONS)?.len()?;
        let pending_count = write.open_table(STATE_SUBSCRIPTION_PENDING)?.len()?;
        let acknowledgement_count = write.open_table(STATE_DELIVERY_ACKNOWLEDGEMENTS)?.len()?;
        let cursor_count = write.open_table(STATE_DELIVERY_CURSORS)?.len()?;
        require_state_subscription_accounting(
            &write,
            subscription_count,
            pending_count,
            acknowledgement_count,
            cursor_count,
        )?;
        if acknowledgement_count >= MAX_STATE_ACKNOWLEDGEMENT_RECEIPTS {
            return Err(StoreError::StateAcknowledgementReceiptLimitExceeded {
                current: acknowledgement_count,
                limit: MAX_STATE_ACKNOWLEDGEMENT_RECEIPTS,
            });
        }
        let encoded = encode_state_acknowledgement_record(StateAcknowledgementRecord {
            acceptance_marker: state.acceptance_marker,
            tenure: pending.tenure,
            attempts: pending.attempts,
        });
        if write
            .open_table(STATE_DELIVERY_ACKNOWLEDGEMENTS)?
            .insert(acknowledgement_key.as_slice(), encoded.as_slice())?
            .is_some()
        {
            return Err(StoreError::StateSubscriptionPlanChanged);
        }
        if write
            .open_table(STATE_SUBSCRIPTION_PENDING)?
            .remove(pending_key.as_slice())?
            .is_none()
        {
            return Err(StoreError::StateSubscriptionPlanChanged);
        }
        {
            cursor.last_acknowledged_tenure = pending.tenure;
            cursor.last_acknowledged_attempt = pending.attempts;
            let encoded = encode_state_delivery_cursor_record(cursor);
            write
                .open_table(STATE_DELIVERY_CURSORS)?
                .insert(cursor_key.as_slice(), encoded.as_slice())?;
        }
        {
            let mut metadata = write.open_table(METADATA)?;
            metadata.insert(
                STATE_PENDING_DELIVERY_COUNT,
                pending_count
                    .checked_sub(1)
                    .ok_or(StoreError::StateInvariant(
                        "State acknowledgement underflows pending accounting",
                    ))?,
            )?;
            metadata.insert(
                STATE_ACKNOWLEDGEMENT_COUNT,
                acknowledgement_count
                    .checked_add(1)
                    .ok_or(StoreError::ItemCountAccountingOverflow)?,
            )?;
        }
        write.commit()?;
        Ok(StateDeliveryAck::Acknowledged)
    }
}

fn validate_state_delivery_token_attempt(received: u64, maximum: u64) -> Result<(), StoreError> {
    if received == 0 || received > maximum {
        return Err(StoreError::StateDeliveryAttemptChanged {
            current: maximum,
            received,
        });
    }
    Ok(())
}

fn validate_state_poll_limits(delivery_limit: usize, scan_limit: usize) -> Result<(), StoreError> {
    if delivery_limit == 0 || delivery_limit > MAX_STATE_POLL_DELIVERIES {
        return Err(StoreError::StateSubscriptionPollLimitExceeded {
            requested: delivery_limit,
            maximum: MAX_STATE_POLL_DELIVERIES,
        });
    }
    if scan_limit == 0 || scan_limit > MAX_STATE_SUBSCRIPTION_SCAN {
        return Err(StoreError::StateSubscriptionPollLimitExceeded {
            requested: scan_limit,
            maximum: MAX_STATE_SUBSCRIPTION_SCAN,
        });
    }
    Ok(())
}

fn validate_state_selection(
    plan: &StateSubscriptionPollPlan,
    selection: &StateSubscriptionPollSelection,
) -> Result<StateSelectionPartition, StoreError> {
    let current = selection.current.iter().copied().collect::<BTreeSet<_>>();
    let noncurrent = selection
        .noncurrent
        .iter()
        .copied()
        .collect::<BTreeSet<_>>();
    let inactive = selection.inactive.iter().copied().collect::<BTreeSet<_>>();
    if current.len() != selection.current.len()
        || noncurrent.len() != selection.noncurrent.len()
        || inactive.len() != selection.inactive.len()
        || !current.is_disjoint(&noncurrent)
        || !current.is_disjoint(&inactive)
        || !noncurrent.is_disjoint(&inactive)
    {
        return Err(StoreError::StateSubscriptionPlanChanged);
    }
    let expected = plan
        .candidates
        .iter()
        .map(|candidate| candidate.state.semantic_id)
        .collect::<BTreeSet<_>>();
    let actual = current
        .iter()
        .chain(&noncurrent)
        .chain(&inactive)
        .copied()
        .collect::<BTreeSet<_>>();
    if expected != actual {
        return Err(StoreError::StateSubscriptionPlanChanged);
    }
    Ok(StateSelectionPartition { current })
}

struct StateSelectionPartition {
    current: BTreeSet<StateSemanticId>,
}

fn state_subscription_candidates_read(
    read: &redb::ReadTransaction,
    subscription: StateSubscriptionId,
    spec: &StateSubscriptionSpec,
    scan_limit: usize,
) -> Result<Vec<StateSubscriptionCandidate>, StoreError> {
    let order = read.open_table(STATE_ACCEPTANCE_ORDER)?;
    let pending = read.open_table(STATE_SUBSCRIPTION_PENDING)?;
    let acknowledgements = read.open_table(STATE_DELIVERY_ACKNOWLEDGEMENTS)?;
    let cursors = read.open_table(STATE_DELIVERY_CURSORS)?;
    let mut candidates = Vec::new();
    let mut expected_marker = 1u64;
    for row in order.iter()? {
        let (marker, transfer) = row?;
        let marker = marker.value();
        if marker != expected_marker {
            return Err(StoreError::StateInvariant(
                "State acceptance-order snapshot is not consecutive",
            ));
        }
        expected_marker = marker
            .checked_add(1)
            .ok_or(StoreError::AcceptanceMarkerExhausted)?;
        let transfer = parse_state_transfer_id("State acceptance-order table", transfer.value())?;
        let state = load_state_from_read(read, transfer)?.ok_or(StoreError::StateInvariant(
            "State acceptance-order index points to a missing State",
        ))?;
        if state.acceptance_marker != marker || !spec.matches(&state) {
            if state.acceptance_marker != marker {
                return Err(StoreError::StateInvariant(
                    "State acceptance-order index differs from its forward marker",
                ));
            }
            continue;
        }
        if candidates.len() == scan_limit {
            return Err(StoreError::StateSubscriptionPollLimitExceeded {
                requested: scan_limit
                    .checked_add(1)
                    .ok_or(StoreError::ItemCountAccountingOverflow)?,
                maximum: scan_limit,
            });
        }
        let pending_key = state_pending_delivery_key(subscription, marker);
        let pending_record = pending
            .get(pending_key.as_slice())?
            .map(|value| decode_state_pending_delivery_record(value.value()))
            .transpose()?;
        let acknowledgement_key = state_acknowledgement_key(subscription, state.semantic_id);
        let acknowledgement_record = acknowledgements
            .get(acknowledgement_key.as_slice())?
            .map(|value| decode_state_acknowledgement_record(value.value()))
            .transpose()?;
        let cursor_key = state_delivery_cursor_key(subscription, state.semantic_id);
        let delivery_cursor = cursors
            .get(cursor_key.as_slice())?
            .map(|value| decode_state_delivery_cursor_record(value.value()))
            .transpose()?;
        validate_state_candidate_delivery_ledger(
            &state,
            pending_record,
            acknowledgement_record,
            delivery_cursor,
        )?;
        candidates.push(StateSubscriptionCandidate {
            state,
            pending_attempt: pending_record.map(|record| record.attempts),
            acknowledged_attempt: acknowledgement_record.map(|record| record.attempts),
            delivery_cursor,
        });
    }
    require_complete_state_acceptance_snapshot_read(read, expected_marker)?;
    Ok(candidates)
}

fn state_subscription_candidates_write(
    write: &redb::WriteTransaction,
    subscription: StateSubscriptionId,
    spec: &StateSubscriptionSpec,
    scan_limit: usize,
) -> Result<Vec<StateSubscriptionCandidate>, StoreError> {
    let order = write.open_table(STATE_ACCEPTANCE_ORDER)?;
    let pending = write.open_table(STATE_SUBSCRIPTION_PENDING)?;
    let acknowledgements = write.open_table(STATE_DELIVERY_ACKNOWLEDGEMENTS)?;
    let cursors = write.open_table(STATE_DELIVERY_CURSORS)?;
    let mut candidates = Vec::new();
    let mut expected_marker = 1u64;
    for row in order.iter()? {
        let (marker, transfer) = row?;
        let marker = marker.value();
        if marker != expected_marker {
            return Err(StoreError::StateInvariant(
                "State acceptance-order snapshot is not consecutive",
            ));
        }
        expected_marker = marker
            .checked_add(1)
            .ok_or(StoreError::AcceptanceMarkerExhausted)?;
        let transfer = parse_state_transfer_id("State acceptance-order table", transfer.value())?;
        let state = load_state_from_write(write, transfer)?.ok_or(StoreError::StateInvariant(
            "State acceptance-order index points to a missing State",
        ))?;
        if state.acceptance_marker != marker || !spec.matches(&state) {
            if state.acceptance_marker != marker {
                return Err(StoreError::StateInvariant(
                    "State acceptance-order index differs from its forward marker",
                ));
            }
            continue;
        }
        if candidates.len() == scan_limit {
            return Err(StoreError::StateSubscriptionPollLimitExceeded {
                requested: scan_limit
                    .checked_add(1)
                    .ok_or(StoreError::ItemCountAccountingOverflow)?,
                maximum: scan_limit,
            });
        }
        let pending_key = state_pending_delivery_key(subscription, marker);
        let pending_record = pending
            .get(pending_key.as_slice())?
            .map(|value| decode_state_pending_delivery_record(value.value()))
            .transpose()?;
        let acknowledgement_key = state_acknowledgement_key(subscription, state.semantic_id);
        let acknowledgement_record = acknowledgements
            .get(acknowledgement_key.as_slice())?
            .map(|value| decode_state_acknowledgement_record(value.value()))
            .transpose()?;
        let cursor_key = state_delivery_cursor_key(subscription, state.semantic_id);
        let delivery_cursor = cursors
            .get(cursor_key.as_slice())?
            .map(|value| decode_state_delivery_cursor_record(value.value()))
            .transpose()?;
        validate_state_candidate_delivery_ledger(
            &state,
            pending_record,
            acknowledgement_record,
            delivery_cursor,
        )?;
        candidates.push(StateSubscriptionCandidate {
            state,
            pending_attempt: pending_record.map(|record| record.attempts),
            acknowledged_attempt: acknowledgement_record.map(|record| record.attempts),
            delivery_cursor,
        });
    }
    require_complete_state_acceptance_snapshot_write(write, expected_marker)?;
    Ok(candidates)
}

fn validate_state_candidate_delivery_ledger(
    state: &StoredState,
    pending: Option<StatePendingDeliveryRecord>,
    acknowledgement: Option<StateAcknowledgementRecord>,
    cursor: Option<StateDeliveryCursorRecord>,
) -> Result<(), StoreError> {
    if pending.is_some() && acknowledgement.is_some() {
        return Err(StoreError::StateInvariant(
            "State delivery is both pending and acknowledged",
        ));
    }
    let Some(cursor) = cursor else {
        if pending.is_some() || acknowledgement.is_some() {
            return Err(StoreError::StateInvariant(
                "active State delivery is missing its monotonic cursor",
            ));
        }
        return Ok(());
    };
    if cursor.acceptance_marker != state.acceptance_marker {
        return Err(StoreError::StateInvariant(
            "State delivery cursor differs from its accepted State",
        ));
    }
    if let Some(pending) = pending
        && (pending.semantic_id != state.semantic_id
            || pending.tenure != cursor.tenure
            || pending.attempts != cursor.last_attempt)
    {
        return Err(StoreError::StateInvariant(
            "pending State delivery differs from its monotonic cursor",
        ));
    }
    if let Some(acknowledgement) = acknowledgement
        && (acknowledgement.acceptance_marker != state.acceptance_marker
            || acknowledgement.tenure != cursor.tenure
            || acknowledgement.tenure != cursor.last_acknowledged_tenure
            || acknowledgement.attempts != cursor.last_acknowledged_attempt
            || acknowledgement.attempts > cursor.last_attempt)
    {
        return Err(StoreError::StateInvariant(
            "State acknowledgement differs from its monotonic cursor",
        ));
    }
    Ok(())
}

fn require_complete_state_acceptance_snapshot_read(
    read: &redb::ReadTransaction,
    next_marker: u64,
) -> Result<(), StoreError> {
    let high_water = read
        .open_table(METADATA)?
        .get(LAST_STATE_ACCEPTANCE_MARKER)?
        .ok_or(StoreError::MissingAccountingMetadata {
            field: LAST_STATE_ACCEPTANCE_MARKER,
        })?
        .value();
    if next_marker.checked_sub(1) != Some(high_water) {
        return Err(StoreError::StateInvariant(
            "State acceptance-order snapshot ended before durable acceptance high-water",
        ));
    }
    Ok(())
}

fn require_complete_state_acceptance_snapshot_write(
    write: &redb::WriteTransaction,
    next_marker: u64,
) -> Result<(), StoreError> {
    let high_water = write
        .open_table(METADATA)?
        .get(LAST_STATE_ACCEPTANCE_MARKER)?
        .ok_or(StoreError::MissingAccountingMetadata {
            field: LAST_STATE_ACCEPTANCE_MARKER,
        })?
        .value();
    if next_marker.checked_sub(1) != Some(high_water) {
        return Err(StoreError::StateInvariant(
            "State acceptance-order snapshot ended before durable acceptance high-water",
        ));
    }
    Ok(())
}

fn state_subscription_id(authority: NodeId, key: &StateSubscriptionKey) -> StateSubscriptionId {
    let mut digest = Sha256::new();
    digest.update(STATE_SUBSCRIPTION_ID_DOMAIN);
    digest.update(authority);
    digest.update(
        u16::try_from(key.as_bytes().len())
            .expect("validated State subscription key fits u16")
            .to_be_bytes(),
    );
    digest.update(key.as_bytes());
    StateSubscriptionId(digest.finalize().into())
}

#[derive(Clone, Copy)]
struct StateDeliveryTokenParts {
    incarnation: u64,
    tenure: u64,
    attempt: u64,
}

fn state_delivery_token(
    subscription: StateSubscriptionId,
    semantic_id: StateSemanticId,
    incarnation: u64,
    tenure: u64,
    attempt: u64,
) -> StateDeliveryToken {
    debug_assert!(incarnation > 0 && tenure > 0 && attempt > 0);
    let mut bytes = [0u8; STATE_DELIVERY_TOKEN_BYTES];
    bytes[0] = STATE_DELIVERY_TOKEN_VERSION;
    bytes[1..9].copy_from_slice(&incarnation.to_be_bytes());
    bytes[9..17].copy_from_slice(&tenure.to_be_bytes());
    bytes[17..25].copy_from_slice(&attempt.to_be_bytes());
    let mut digest = Sha256::new();
    digest.update(STATE_DELIVERY_TOKEN_DOMAIN);
    digest.update(subscription.as_bytes());
    digest.update(semantic_id.as_bytes());
    digest.update(&bytes[..STATE_DELIVERY_TOKEN_COUNTER_BYTES]);
    bytes[STATE_DELIVERY_TOKEN_COUNTER_BYTES..].copy_from_slice(&digest.finalize());
    StateDeliveryToken(bytes)
}

fn validate_state_delivery_token_binding(
    subscription: StateSubscriptionId,
    semantic_id: StateSemanticId,
    token: StateDeliveryToken,
) -> Result<StateDeliveryTokenParts, StoreError> {
    let parts = StateDeliveryTokenParts {
        incarnation: token.incarnation(),
        tenure: token.tenure(),
        attempt: token.attempt(),
    };
    if token
        != state_delivery_token(
            subscription,
            semantic_id,
            parts.incarnation,
            parts.tenure,
            parts.attempt,
        )
    {
        return Err(StoreError::StateDeliveryTokenBindingMismatch);
    }
    Ok(parts)
}

fn encode_state_subscription_record(
    record: &StateSubscriptionRecord,
) -> Result<Vec<u8>, StoreError> {
    let key_length = u16::try_from(record.operation_key.as_bytes().len()).map_err(|_| {
        StoreError::StateInvariant("State subscription operation key exceeds its bound")
    })?;
    let topic = record.spec.topic.as_str().as_bytes();
    let scope = record.spec.scope.as_str().as_bytes();
    let topic_length = u16::try_from(topic.len())
        .map_err(|_| StoreError::StateInvariant("State subscription topic exceeds its bound"))?;
    let scope_length = u16::try_from(scope.len())
        .map_err(|_| StoreError::StateInvariant("State subscription scope exceeds its bound"))?;
    let mut encoded = Vec::new();
    encoded.push(STATE_SUBSCRIPTION_VERSION);
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

fn decode_state_subscription_record(bytes: &[u8]) -> Result<StateSubscriptionRecord, StoreError> {
    let mut cursor = MetadataCursor::new(bytes);
    if cursor.u8()? != STATE_SUBSCRIPTION_VERSION {
        return Err(StoreError::StateInvariant(
            "unknown State subscription encoding version",
        ));
    }
    let include_descendant_scopes = match cursor.u8()? {
        0 => false,
        1 => true,
        _ => {
            return Err(StoreError::StateInvariant(
                "invalid State subscription descendant flag",
            ));
        }
    };
    let incarnation = cursor.u64()?;
    if incarnation == 0 {
        return Err(StoreError::StateInvariant(
            "State subscription incarnation is zero",
        ));
    }
    let key_length = usize::from(cursor.u16()?);
    let operation_key = StateSubscriptionKey::new(cursor.take(key_length)?.to_vec())
        .map_err(|_| StoreError::StateInvariant("invalid State subscription operation key"))?;
    let topic = Topic::new(cursor.short_string()?)
        .map_err(|_| StoreError::StateInvariant("invalid State subscription topic"))?;
    let scope = Scope::new(cursor.short_string()?)
        .map_err(|_| StoreError::StateInvariant("invalid State subscription scope"))?;
    cursor.finish()?;
    let record = StateSubscriptionRecord {
        operation_key,
        spec: StateSubscriptionSpec {
            topic,
            scope,
            include_descendant_scopes,
        },
        incarnation,
    };
    if encode_state_subscription_record(&record)?.as_slice() != bytes {
        return Err(StoreError::StateInvariant(
            "State subscription encoding is not canonical",
        ));
    }
    Ok(record)
}

fn state_pending_delivery_key(subscription: StateSubscriptionId, marker: u64) -> [u8; 40] {
    let mut key = [0u8; 40];
    key[..32].copy_from_slice(subscription.as_bytes());
    key[32..].copy_from_slice(&marker.to_be_bytes());
    key
}

fn parse_state_pending_delivery_key(
    bytes: &[u8],
) -> Result<(StateSubscriptionId, u64), StoreError> {
    let bytes: [u8; 40] = bytes
        .try_into()
        .map_err(|_| StoreError::StateInvariant("State pending-delivery key has invalid length"))?;
    let subscription = StateSubscriptionId::from_bytes(
        bytes[..32]
            .try_into()
            .expect("fixed State subscription prefix"),
    );
    let marker = u64::from_be_bytes(bytes[32..].try_into().expect("fixed marker suffix"));
    if marker == 0 {
        return Err(StoreError::StateInvariant(
            "State pending-delivery key contains a zero marker",
        ));
    }
    Ok((subscription, marker))
}

fn encode_state_pending_delivery_record(record: StatePendingDeliveryRecord) -> Vec<u8> {
    let mut encoded = Vec::with_capacity(49);
    encoded.push(STATE_PENDING_DELIVERY_VERSION);
    encoded.extend_from_slice(record.semantic_id.as_bytes());
    encoded.extend_from_slice(&record.tenure.to_be_bytes());
    encoded.extend_from_slice(&record.attempts.to_be_bytes());
    encoded
}

fn decode_state_pending_delivery_record(
    bytes: &[u8],
) -> Result<StatePendingDeliveryRecord, StoreError> {
    let mut cursor = MetadataCursor::new(bytes);
    if cursor.u8()? != STATE_PENDING_DELIVERY_VERSION {
        return Err(StoreError::StateInvariant(
            "unknown State pending-delivery encoding version",
        ));
    }
    let semantic_id = StateSemanticId::new(cursor.array()?);
    let tenure = cursor.u64()?;
    let attempts = cursor.u64()?;
    cursor.finish()?;
    if tenure == 0 || attempts == 0 {
        return Err(StoreError::StateInvariant(
            "State pending-delivery tenure or attempt count is zero",
        ));
    }
    Ok(StatePendingDeliveryRecord {
        semantic_id,
        tenure,
        attempts,
    })
}

fn state_acknowledgement_key(
    subscription: StateSubscriptionId,
    semantic_id: StateSemanticId,
) -> [u8; 64] {
    let mut key = [0u8; 64];
    key[..32].copy_from_slice(subscription.as_bytes());
    key[32..].copy_from_slice(semantic_id.as_bytes());
    key
}

fn parse_state_acknowledgement_key(
    bytes: &[u8],
) -> Result<(StateSubscriptionId, StateSemanticId), StoreError> {
    let bytes: [u8; 64] = bytes
        .try_into()
        .map_err(|_| StoreError::StateInvariant("State acknowledgement key has invalid length"))?;
    Ok((
        StateSubscriptionId::from_bytes(
            bytes[..32]
                .try_into()
                .expect("fixed State subscription prefix"),
        ),
        StateSemanticId::new(bytes[32..].try_into().expect("fixed semantic suffix")),
    ))
}

fn state_delivery_cursor_key(
    subscription: StateSubscriptionId,
    semantic_id: StateSemanticId,
) -> [u8; 64] {
    state_acknowledgement_key(subscription, semantic_id)
}

fn parse_state_delivery_cursor_key(
    bytes: &[u8],
) -> Result<(StateSubscriptionId, StateSemanticId), StoreError> {
    parse_state_acknowledgement_key(bytes)
}

fn encode_state_acknowledgement_record(record: StateAcknowledgementRecord) -> Vec<u8> {
    let mut encoded = Vec::with_capacity(25);
    encoded.push(STATE_ACKNOWLEDGEMENT_VERSION);
    encoded.extend_from_slice(&record.acceptance_marker.to_be_bytes());
    encoded.extend_from_slice(&record.tenure.to_be_bytes());
    encoded.extend_from_slice(&record.attempts.to_be_bytes());
    encoded
}

fn decode_state_acknowledgement_record(
    bytes: &[u8],
) -> Result<StateAcknowledgementRecord, StoreError> {
    let mut cursor = MetadataCursor::new(bytes);
    if cursor.u8()? != STATE_ACKNOWLEDGEMENT_VERSION {
        return Err(StoreError::StateInvariant(
            "unknown State acknowledgement encoding version",
        ));
    }
    let acceptance_marker = cursor.u64()?;
    let tenure = cursor.u64()?;
    let attempts = cursor.u64()?;
    cursor.finish()?;
    if acceptance_marker == 0 || tenure == 0 || attempts == 0 {
        return Err(StoreError::StateInvariant(
            "State acknowledgement contains a zero marker, tenure, or attempt",
        ));
    }
    Ok(StateAcknowledgementRecord {
        acceptance_marker,
        tenure,
        attempts,
    })
}

fn encode_state_delivery_cursor_record(record: StateDeliveryCursorRecord) -> Vec<u8> {
    let mut encoded = Vec::with_capacity(41);
    encoded.push(STATE_DELIVERY_CURSOR_VERSION);
    encoded.extend_from_slice(&record.acceptance_marker.to_be_bytes());
    encoded.extend_from_slice(&record.tenure.to_be_bytes());
    encoded.extend_from_slice(&record.last_attempt.to_be_bytes());
    encoded.extend_from_slice(&record.last_acknowledged_tenure.to_be_bytes());
    encoded.extend_from_slice(&record.last_acknowledged_attempt.to_be_bytes());
    encoded
}

fn decode_state_delivery_cursor_record(
    bytes: &[u8],
) -> Result<StateDeliveryCursorRecord, StoreError> {
    let mut cursor = MetadataCursor::new(bytes);
    if cursor.u8()? != STATE_DELIVERY_CURSOR_VERSION {
        return Err(StoreError::StateInvariant(
            "unknown State delivery-cursor encoding version",
        ));
    }
    let record = StateDeliveryCursorRecord {
        acceptance_marker: cursor.u64()?,
        tenure: cursor.u64()?,
        last_attempt: cursor.u64()?,
        last_acknowledged_tenure: cursor.u64()?,
        last_acknowledged_attempt: cursor.u64()?,
    };
    cursor.finish()?;
    if record.acceptance_marker == 0 || record.tenure == 0 || record.last_attempt == 0 {
        return Err(StoreError::StateInvariant(
            "State delivery cursor contains a zero marker, tenure, or attempt",
        ));
    }
    if (record.last_acknowledged_tenure == 0) != (record.last_acknowledged_attempt == 0)
        || record.last_acknowledged_tenure > record.tenure
        || (record.last_acknowledged_tenure == record.tenure
            && record.last_acknowledged_attempt > record.last_attempt)
    {
        return Err(StoreError::StateInvariant(
            "State delivery cursor contains an invalid acknowledgement high-water",
        ));
    }
    Ok(record)
}

fn load_state_by_semantic_from_read(
    read: &redb::ReadTransaction,
    semantic_id: StateSemanticId,
) -> Result<Option<StoredState>, StoreError> {
    let transfer = read
        .open_table(STATE_SEMANTIC_ITEMS)?
        .get(semantic_id.as_bytes().as_slice())?
        .map(|value| parse_state_transfer_id("State semantic item table", value.value()))
        .transpose()?;
    transfer
        .map(|transfer| load_state_from_read(read, transfer))
        .transpose()
        .map(Option::flatten)
}

fn load_state_by_semantic_from_write(
    write: &redb::WriteTransaction,
    semantic_id: StateSemanticId,
) -> Result<Option<StoredState>, StoreError> {
    let transfer = write
        .open_table(STATE_SEMANTIC_ITEMS)?
        .get(semantic_id.as_bytes().as_slice())?
        .map(|value| parse_state_transfer_id("State semantic item table", value.value()))
        .transpose()?;
    transfer
        .map(|transfer| load_state_from_write(write, transfer))
        .transpose()
        .map(Option::flatten)
}

fn validate_state_selector_generation(
    generation: u64,
    subscription_count: u64,
) -> Result<(), StoreError> {
    if generation < subscription_count || !(generation - subscription_count).is_multiple_of(2) {
        return Err(StoreError::StateInvariant(
            "State selector mutation generation is inconsistent with the live subscription count",
        ));
    }
    Ok(())
}

fn require_state_subscription_accounting(
    write: &redb::WriteTransaction,
    subscriptions: u64,
    pending: u64,
    acknowledgements: u64,
    cursors: u64,
) -> Result<u64, StoreError> {
    let metadata = write.open_table(METADATA)?;
    for (field, reconstructed) in [
        (STATE_SUBSCRIPTION_COUNT, subscriptions),
        (STATE_PENDING_DELIVERY_COUNT, pending),
        (STATE_ACKNOWLEDGEMENT_COUNT, acknowledgements),
        (STATE_DELIVERY_CURSOR_COUNT, cursors),
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
        .get(STATE_SELECTOR_GENERATION)?
        .ok_or(StoreError::MissingAccountingMetadata {
            field: STATE_SELECTOR_GENERATION,
        })?
        .value();
    validate_state_selector_generation(generation, subscriptions)?;
    Ok(generation)
}

fn is_state_subscription_table(name: &str) -> bool {
    name == STATE_SUBSCRIPTIONS.name()
        || name == STATE_SUBSCRIPTION_PENDING.name()
        || name == STATE_DELIVERY_ACKNOWLEDGEMENTS.name()
        || name == STATE_DELIVERY_CURSORS.name()
}

fn state_subscription_metadata_is_present(
    metadata: &impl ReadableTable<&'static str, u64>,
) -> Result<bool, StoreError> {
    for field in [
        STATE_SUBSCRIPTION_COUNT,
        STATE_PENDING_DELIVERY_COUNT,
        STATE_ACKNOWLEDGEMENT_COUNT,
        STATE_DELIVERY_CURSOR_COUNT,
        STATE_SELECTOR_GENERATION,
    ] {
        if metadata.get(field)?.is_some() {
            return Ok(true);
        }
    }
    Ok(false)
}

pub(crate) fn state_subscription_schema_wholly_absent_write(
    write: &redb::WriteTransaction,
) -> Result<bool, StoreError> {
    let table_present = write
        .list_tables()?
        .any(|table| is_state_subscription_table(table.name()));
    let multimap_present = write
        .list_multimap_tables()?
        .any(|table| is_state_subscription_table(table.name()));
    let metadata_present = state_subscription_metadata_is_present(&write.open_table(METADATA)?)?;
    Ok(!table_present && !multimap_present && !metadata_present)
}

pub(crate) fn state_subscription_schema_wholly_absent_read(
    read: &redb::ReadTransaction,
) -> Result<bool, StoreError> {
    let table_present = read
        .list_tables()?
        .any(|table| is_state_subscription_table(table.name()));
    let multimap_present = read
        .list_multimap_tables()?
        .any(|table| is_state_subscription_table(table.name()));
    let metadata_present = state_subscription_metadata_is_present(&read.open_table(METADATA)?)?;
    Ok(!table_present && !multimap_present && !metadata_present)
}

pub(crate) fn audit_state_subscription_tables(
    write: &redb::WriteTransaction,
    initializing_state: bool,
) -> Result<StateSubscriptionStats, StoreError> {
    if write.list_multimap_tables()?.any(|table| {
        table.name() == STATE_SUBSCRIPTIONS.name()
            || table.name() == STATE_SUBSCRIPTION_PENDING.name()
            || table.name() == STATE_DELIVERY_ACKNOWLEDGEMENTS.name()
            || table.name() == STATE_DELIVERY_CURSORS.name()
    }) {
        return Err(StoreError::StateInvariant(
            "State subscription schema has the wrong table kind",
        ));
    }
    let table_names = write
        .list_tables()?
        .map(|table| table.name().to_owned())
        .collect::<BTreeSet<_>>();
    let tables_present = [
        STATE_SUBSCRIPTIONS.name(),
        STATE_SUBSCRIPTION_PENDING.name(),
        STATE_DELIVERY_ACKNOWLEDGEMENTS.name(),
        STATE_DELIVERY_CURSORS.name(),
    ]
    .into_iter()
    .filter(|name| table_names.contains(*name))
    .count();
    let metadata_presence = {
        let metadata = write.open_table(METADATA)?;
        [
            metadata.get(STATE_SUBSCRIPTION_COUNT)?.is_some(),
            metadata.get(STATE_PENDING_DELIVERY_COUNT)?.is_some(),
            metadata.get(STATE_ACKNOWLEDGEMENT_COUNT)?.is_some(),
            metadata.get(STATE_DELIVERY_CURSOR_COUNT)?.is_some(),
            metadata.get(STATE_SELECTOR_GENERATION)?.is_some(),
        ]
    };
    let metadata_present = metadata_presence.iter().filter(|present| **present).count();
    if tables_present == 0 && metadata_present == 0 {
        if !initializing_state {
            return Err(StoreError::StateInvariant(
                "State subscription schema group is incomplete",
            ));
        }
        write.open_table(STATE_SUBSCRIPTIONS)?;
        write.open_table(STATE_SUBSCRIPTION_PENDING)?;
        write.open_table(STATE_DELIVERY_ACKNOWLEDGEMENTS)?;
        write.open_table(STATE_DELIVERY_CURSORS)?;
        let mut metadata = write.open_table(METADATA)?;
        metadata.insert(STATE_SUBSCRIPTION_COUNT, 0)?;
        metadata.insert(STATE_PENDING_DELIVERY_COUNT, 0)?;
        metadata.insert(STATE_ACKNOWLEDGEMENT_COUNT, 0)?;
        metadata.insert(STATE_DELIVERY_CURSOR_COUNT, 0)?;
        metadata.insert(STATE_SELECTOR_GENERATION, 0)?;
        return Ok(StateSubscriptionStats::default());
    }
    if tables_present != 4 || metadata_presence.iter().any(|present| !present) {
        return Err(StoreError::StateInvariant(
            "State subscription schema group is incomplete",
        ));
    }
    audit_state_subscription_rows_write(write)
}

fn audit_state_subscription_rows_write(
    write: &redb::WriteTransaction,
) -> Result<StateSubscriptionStats, StoreError> {
    let authority = read_mission_binding(write)?;
    let mut subscriptions = BTreeMap::new();
    for row in write.open_table(STATE_SUBSCRIPTIONS)?.iter()? {
        let (key, value) = row?;
        let id = parse_state_subscription_id(key.value())?;
        let record = decode_state_subscription_record(value.value())?;
        let authority = authority.ok_or(StoreError::StateInvariant(
            "unbound store contains State subscriptions",
        ))?;
        if state_subscription_id(authority, &record.operation_key) != id {
            return Err(StoreError::StateInvariant(
                "State subscription identifier differs from its operation key",
            ));
        }
        subscriptions.insert(id, record);
    }
    audit_state_subscription_ledgers_write(write, &subscriptions)?;
    let stats = StateSubscriptionStats {
        subscriptions: write.open_table(STATE_SUBSCRIPTIONS)?.len()?,
        pending_deliveries: write.open_table(STATE_SUBSCRIPTION_PENDING)?.len()?,
        acknowledged_deliveries: write.open_table(STATE_DELIVERY_ACKNOWLEDGEMENTS)?.len()?,
        delivery_cursors: write.open_table(STATE_DELIVERY_CURSORS)?.len()?,
        selector_generation: write
            .open_table(METADATA)?
            .get(STATE_SELECTOR_GENERATION)?
            .ok_or(StoreError::MissingAccountingMetadata {
                field: STATE_SELECTOR_GENERATION,
            })?
            .value(),
    };
    validate_state_subscription_incarnations(&subscriptions, stats.selector_generation)?;
    validate_state_subscription_stats(write, stats)?;
    Ok(stats)
}

fn validate_state_subscription_incarnations(
    subscriptions: &BTreeMap<StateSubscriptionId, StateSubscriptionRecord>,
    selector_generation: u64,
) -> Result<(), StoreError> {
    let mut incarnations = BTreeSet::new();
    for record in subscriptions.values() {
        if record.incarnation == 0
            || record.incarnation > selector_generation
            || !incarnations.insert(record.incarnation)
        {
            return Err(StoreError::StateInvariant(
                "State subscription incarnation is invalid or reused",
            ));
        }
    }
    Ok(())
}

fn audit_state_subscription_ledgers_write(
    write: &redb::WriteTransaction,
    subscriptions: &BTreeMap<StateSubscriptionId, StateSubscriptionRecord>,
) -> Result<(), StoreError> {
    let mut pending_records = BTreeMap::new();
    for row in write.open_table(STATE_SUBSCRIPTION_PENDING)?.iter()? {
        let (key, value) = row?;
        let (subscription, marker) = parse_state_pending_delivery_key(key.value())?;
        let record = decode_state_pending_delivery_record(value.value())?;
        let spec = &subscriptions
            .get(&subscription)
            .ok_or(StoreError::StateInvariant(
                "pending State delivery references a missing subscription",
            ))?
            .spec;
        let state = load_state_by_semantic_from_write(write, record.semantic_id)?.ok_or(
            StoreError::StateInvariant("pending State delivery references a missing State"),
        )?;
        if state.acceptance_marker != marker || !spec.matches(&state) {
            return Err(StoreError::StateInvariant(
                "pending State delivery differs from its subscription ledger",
            ));
        }
        if pending_records
            .insert((subscription, record.semantic_id), record)
            .is_some()
        {
            return Err(StoreError::StateInvariant(
                "duplicate pending State semantic delivery",
            ));
        }
    }
    let mut acknowledgement_records = BTreeMap::new();
    for row in write.open_table(STATE_DELIVERY_ACKNOWLEDGEMENTS)?.iter()? {
        let (key, value) = row?;
        let (subscription, semantic_id) = parse_state_acknowledgement_key(key.value())?;
        let record = decode_state_acknowledgement_record(value.value())?;
        let spec = &subscriptions
            .get(&subscription)
            .ok_or(StoreError::StateInvariant(
                "State acknowledgement references a missing subscription",
            ))?
            .spec;
        let state = load_state_by_semantic_from_write(write, semantic_id)?.ok_or(
            StoreError::StateInvariant("State acknowledgement references a missing State"),
        )?;
        if state.acceptance_marker != record.acceptance_marker || !spec.matches(&state) {
            return Err(StoreError::StateInvariant(
                "State acknowledgement differs from its subscription ledger",
            ));
        }
        if pending_records.contains_key(&(subscription, semantic_id)) {
            return Err(StoreError::StateInvariant(
                "State delivery is both pending and acknowledged",
            ));
        }
        acknowledgement_records.insert((subscription, semantic_id), record);
    }
    let mut cursor_ids = BTreeSet::new();
    for row in write.open_table(STATE_DELIVERY_CURSORS)?.iter()? {
        let (key, value) = row?;
        let (subscription, semantic_id) = parse_state_delivery_cursor_key(key.value())?;
        let cursor = decode_state_delivery_cursor_record(value.value())?;
        let spec = &subscriptions
            .get(&subscription)
            .ok_or(StoreError::StateInvariant(
                "State delivery cursor references a missing subscription",
            ))?
            .spec;
        let state = load_state_by_semantic_from_write(write, semantic_id)?.ok_or(
            StoreError::StateInvariant("State delivery cursor references a missing State"),
        )?;
        if !spec.matches(&state) {
            return Err(StoreError::StateInvariant(
                "State delivery cursor differs from its subscription",
            ));
        }
        let id = (subscription, semantic_id);
        validate_state_candidate_delivery_ledger(
            &state,
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
        return Err(StoreError::StateInvariant(
            "active State delivery is missing its monotonic cursor",
        ));
    }
    Ok(())
}

fn validate_state_subscription_stats(
    write: &redb::WriteTransaction,
    stats: StateSubscriptionStats,
) -> Result<(), StoreError> {
    if stats.subscriptions > MAX_STATE_SUBSCRIPTIONS
        || stats.pending_deliveries > MAX_STATE_PENDING_DELIVERIES
        || stats.acknowledged_deliveries > MAX_STATE_ACKNOWLEDGEMENT_RECEIPTS
        || stats
            .pending_deliveries
            .checked_add(stats.acknowledged_deliveries)
            .ok_or(StoreError::ItemCountAccountingOverflow)?
            > MAX_STATE_ACKNOWLEDGEMENT_RECEIPTS
        || stats.delivery_cursors > MAX_STATE_DELIVERY_CURSORS
    {
        return Err(StoreError::StateInvariant(
            "State subscription tables exceed their bounded cardinality",
        ));
    }
    require_state_subscription_accounting(
        write,
        stats.subscriptions,
        stats.pending_deliveries,
        stats.acknowledged_deliveries,
        stats.delivery_cursors,
    )?;
    Ok(())
}

pub(crate) fn inspect_state_subscription_tables(
    read: &redb::ReadTransaction,
) -> Result<StateSubscriptionStats, StoreError> {
    if read.list_multimap_tables()?.any(|table| {
        table.name() == STATE_SUBSCRIPTIONS.name()
            || table.name() == STATE_SUBSCRIPTION_PENDING.name()
            || table.name() == STATE_DELIVERY_ACKNOWLEDGEMENTS.name()
            || table.name() == STATE_DELIVERY_CURSORS.name()
    }) {
        return Err(StoreError::StateInvariant(
            "State subscription schema has the wrong table kind",
        ));
    }
    let table_names = read
        .list_tables()?
        .map(|table| table.name().to_owned())
        .collect::<BTreeSet<_>>();
    let tables_present = [
        STATE_SUBSCRIPTIONS.name(),
        STATE_SUBSCRIPTION_PENDING.name(),
        STATE_DELIVERY_ACKNOWLEDGEMENTS.name(),
        STATE_DELIVERY_CURSORS.name(),
    ]
    .into_iter()
    .filter(|name| table_names.contains(*name))
    .count();
    let metadata = read.open_table(METADATA)?;
    let metadata_presence = [
        metadata.get(STATE_SUBSCRIPTION_COUNT)?.is_some(),
        metadata.get(STATE_PENDING_DELIVERY_COUNT)?.is_some(),
        metadata.get(STATE_ACKNOWLEDGEMENT_COUNT)?.is_some(),
        metadata.get(STATE_DELIVERY_CURSOR_COUNT)?.is_some(),
        metadata.get(STATE_SELECTOR_GENERATION)?.is_some(),
    ];
    if tables_present == 0 && metadata_presence.iter().all(|present| !present) {
        if table_names.contains(STATE_ACCEPTANCE_ORDER.name()) {
            return Err(StoreError::StateInvariant(
                "State subscription schema group is incomplete",
            ));
        }
        return Ok(StateSubscriptionStats::default());
    }
    if tables_present != 4 || metadata_presence.iter().any(|present| !present) {
        return Err(StoreError::StateInvariant(
            "State subscription schema group is incomplete",
        ));
    }

    let authority = read_mission_binding_read(read)?;
    let mut subscriptions = BTreeMap::new();
    for row in read.open_table(STATE_SUBSCRIPTIONS)?.iter()? {
        let (key, value) = row?;
        let id = parse_state_subscription_id(key.value())?;
        let record = decode_state_subscription_record(value.value())?;
        let authority = authority.ok_or(StoreError::StateInvariant(
            "unbound store contains State subscriptions",
        ))?;
        if state_subscription_id(authority, &record.operation_key) != id {
            return Err(StoreError::StateInvariant(
                "State subscription identifier differs from its operation key",
            ));
        }
        subscriptions.insert(id, record);
    }
    let mut pending_records = BTreeMap::new();
    for row in read.open_table(STATE_SUBSCRIPTION_PENDING)?.iter()? {
        let (key, value) = row?;
        let (subscription, marker) = parse_state_pending_delivery_key(key.value())?;
        let record = decode_state_pending_delivery_record(value.value())?;
        let spec = &subscriptions
            .get(&subscription)
            .ok_or(StoreError::StateInvariant(
                "pending State delivery references a missing subscription",
            ))?
            .spec;
        let state = load_state_by_semantic_from_read(read, record.semantic_id)?.ok_or(
            StoreError::StateInvariant("pending State delivery references a missing State"),
        )?;
        if state.acceptance_marker != marker || !spec.matches(&state) {
            return Err(StoreError::StateInvariant(
                "pending State delivery differs from its subscription ledger",
            ));
        }
        if pending_records
            .insert((subscription, record.semantic_id), record)
            .is_some()
        {
            return Err(StoreError::StateInvariant(
                "duplicate pending State semantic delivery",
            ));
        }
    }
    let mut acknowledgement_records = BTreeMap::new();
    for row in read.open_table(STATE_DELIVERY_ACKNOWLEDGEMENTS)?.iter()? {
        let (key, value) = row?;
        let (subscription, semantic_id) = parse_state_acknowledgement_key(key.value())?;
        let record = decode_state_acknowledgement_record(value.value())?;
        let spec = &subscriptions
            .get(&subscription)
            .ok_or(StoreError::StateInvariant(
                "State acknowledgement references a missing subscription",
            ))?
            .spec;
        let state = load_state_by_semantic_from_read(read, semantic_id)?.ok_or(
            StoreError::StateInvariant("State acknowledgement references a missing State"),
        )?;
        if state.acceptance_marker != record.acceptance_marker || !spec.matches(&state) {
            return Err(StoreError::StateInvariant(
                "State acknowledgement differs from its subscription ledger",
            ));
        }
        if pending_records.contains_key(&(subscription, semantic_id)) {
            return Err(StoreError::StateInvariant(
                "State delivery is both pending and acknowledged",
            ));
        }
        acknowledgement_records.insert((subscription, semantic_id), record);
    }
    let mut cursor_ids = BTreeSet::new();
    for row in read.open_table(STATE_DELIVERY_CURSORS)?.iter()? {
        let (key, value) = row?;
        let (subscription, semantic_id) = parse_state_delivery_cursor_key(key.value())?;
        let cursor = decode_state_delivery_cursor_record(value.value())?;
        let spec = &subscriptions
            .get(&subscription)
            .ok_or(StoreError::StateInvariant(
                "State delivery cursor references a missing subscription",
            ))?
            .spec;
        let state = load_state_by_semantic_from_read(read, semantic_id)?.ok_or(
            StoreError::StateInvariant("State delivery cursor references a missing State"),
        )?;
        if !spec.matches(&state) {
            return Err(StoreError::StateInvariant(
                "State delivery cursor differs from its subscription",
            ));
        }
        let id = (subscription, semantic_id);
        validate_state_candidate_delivery_ledger(
            &state,
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
        return Err(StoreError::StateInvariant(
            "active State delivery is missing its monotonic cursor",
        ));
    }
    let stats = StateSubscriptionStats {
        subscriptions: read.open_table(STATE_SUBSCRIPTIONS)?.len()?,
        pending_deliveries: read.open_table(STATE_SUBSCRIPTION_PENDING)?.len()?,
        acknowledged_deliveries: read.open_table(STATE_DELIVERY_ACKNOWLEDGEMENTS)?.len()?,
        delivery_cursors: read.open_table(STATE_DELIVERY_CURSORS)?.len()?,
        selector_generation: metadata
            .get(STATE_SELECTOR_GENERATION)?
            .ok_or(StoreError::MissingAccountingMetadata {
                field: STATE_SELECTOR_GENERATION,
            })?
            .value(),
    };
    validate_state_subscription_incarnations(&subscriptions, stats.selector_generation)?;
    if stats.subscriptions > MAX_STATE_SUBSCRIPTIONS
        || stats.pending_deliveries > MAX_STATE_PENDING_DELIVERIES
        || stats.acknowledged_deliveries > MAX_STATE_ACKNOWLEDGEMENT_RECEIPTS
        || stats
            .pending_deliveries
            .checked_add(stats.acknowledged_deliveries)
            .ok_or(StoreError::ItemCountAccountingOverflow)?
            > MAX_STATE_ACKNOWLEDGEMENT_RECEIPTS
        || stats.delivery_cursors > MAX_STATE_DELIVERY_CURSORS
    {
        return Err(StoreError::StateInvariant(
            "State subscription tables exceed their bounded cardinality",
        ));
    }
    for (field, reconstructed) in [
        (STATE_SUBSCRIPTION_COUNT, stats.subscriptions),
        (STATE_PENDING_DELIVERY_COUNT, stats.pending_deliveries),
        (STATE_ACKNOWLEDGEMENT_COUNT, stats.acknowledged_deliveries),
        (STATE_DELIVERY_CURSOR_COUNT, stats.delivery_cursors),
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
    validate_state_selector_generation(stats.selector_generation, stats.subscriptions)?;
    Ok(stats)
}

fn parse_state_subscription_id(bytes: &[u8]) -> Result<StateSubscriptionId, StoreError> {
    let bytes: [u8; 32] = bytes.try_into().map_err(|_| {
        StoreError::StateInvariant("State subscription identifier has invalid length")
    })?;
    Ok(StateSubscriptionId::from_bytes(bytes))
}
