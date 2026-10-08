use std::{
    collections::{BTreeMap, BTreeSet},
    error::Error,
    fmt,
};

use redb::{ReadableDatabase, ReadableTable, ReadableTableMetadata, TableDefinition, TableHandle};
use sha2::{Digest, Sha256};

#[cfg(test)]
thread_local! {
    static RESULT_ROWS_VISITED: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
    static REVERSE_ROWS_VISITED: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
}

use crate::{
    CustodyRetirementReason, EventOperationLimits, EventSemanticId, EventTransferId, METADATA,
    Store, StoreError,
    event_operation::{ACTIVE_OPERATION_BY_EVENT_V1, EVENT_OPERATION_LEDGER_V3},
};

const APPLICATION_CHECKPOINTS: TableDefinition<&[u8], &[u8]> =
    TableDefinition::new("aster.application-publication-checkpoints.v1");

const CLIENTS: TableDefinition<&[u8], &[u8]> =
    TableDefinition::new("aster.numbered-event-clients.v1");
const RESULTS: TableDefinition<&[u8], &[u8]> =
    TableDefinition::new("aster.numbered-event-results.v1");
const RESULT_BY_EVENT: TableDefinition<&[u8], &[u8]> =
    TableDefinition::new("aster.numbered-event-result-by-event.v1");

const MODE: &str = "numbered_event_operation_mode_v1";
const COMMITTED_COUNT: &str = "numbered_event_operation_committed_total_v1";
const CLIENT_COUNT: &str = "numbered_event_operation_clients_v1";
const RESULT_COUNT: &str = "numbered_event_operation_results_v1";
const REVERSE_COUNT: &str = "numbered_event_operation_reverse_v1";
const LOGICAL_BYTES: &str = "numbered_event_operation_logical_bytes_v1";
const CLIENT_VERSION: u8 = 1;
const RESULT_VERSION: u8 = 1;
const CONTENT_AVAILABLE: u8 = 1;
const CONTENT_RETIRED: u8 = 2;
const CLAIM_DOMAIN: &[u8] = b"aster/numbered-event-session-claim/v1";

/// Maximum caller-supplied application client identifier length.
pub const MAX_EVENT_CLIENT_ID_BYTES: usize = 64;
/// Maximum caller-supplied idempotent takeover nonce length.
pub const MAX_EVENT_SESSION_CLAIM_NONCE_BYTES: usize = 64;
/// Fixed per-client bound on outstanding committed publication results.
pub const MAX_OUTSTANDING_EVENT_RESULTS_PER_CLIENT: u64 = 4_096;
/// Hard encoded-Protobuf response ceiling shared with the local agent.
pub const MAX_EVENT_RECOVERY_SNAPSHOT_PROTO_BYTES: usize = 2 * 1024 * 1024;
/// Hard global bound on durable numbered publication clients.
pub const MAX_NUMBERED_EVENT_CLIENTS: u64 = 1_024;

/// Stable configured application publisher identity.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct EventClientId(Vec<u8>);

impl EventClientId {
    pub fn new(bytes: impl Into<Vec<u8>>) -> Result<Self, NumberedEventOperationError> {
        let bytes = bytes.into();
        if bytes.is_empty() || bytes.len() > MAX_EVENT_CLIENT_ID_BYTES {
            return Err(NumberedEventOperationError::InvalidClientId);
        }
        Ok(Self(bytes))
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

/// Durable publication incarnation. Zero is reserved for the pre-claim state.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct EventPublicationSession(u64);

impl EventPublicationSession {
    pub fn new(value: u64) -> Result<Self, NumberedEventOperationError> {
        if value == 0 {
            return Err(NumberedEventOperationError::InvalidSession);
        }
        Ok(Self(value))
    }

    pub const fn get(self) -> u64 {
        self.0
    }
}

/// Positive, never-reused application publication sequence.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct EventOperationSequence(u64);

impl EventOperationSequence {
    pub fn new(value: u64) -> Result<Self, NumberedEventOperationError> {
        if value == 0 {
            return Err(NumberedEventOperationError::InvalidSequence);
        }
        Ok(Self(value))
    }

    pub const fn get(self) -> u64 {
        self.0
    }
}

/// Minimal immutable receipt proving that one Event committed.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CommittedEventReceipt {
    pub transfer_id: EventTransferId,
    pub semantic_id: EventSemanticId,
    pub acceptance_marker: u64,
}

/// Availability of Event content after the publication itself committed.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CommittedEventContent {
    Available,
    Retired(CustodyRetirementReason),
}

/// Recoverable committed publication result retained until SDK acknowledgement.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct NumberedEventResult {
    pub sequence: EventOperationSequence,
    pub receipt: CommittedEventReceipt,
    pub content: CommittedEventContent,
}

type StoredNumberedEventResultRow = (Vec<u8>, NumberedEventResult, [u8; 32]);

/// One bounded restart-recovery snapshot returned by session claim.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EventRecoverySnapshot {
    pub session: EventPublicationSession,
    pub allocated_through: u64,
    pub snapshot_revision: u64,
    pub outstanding: Vec<NumberedEventResult>,
}

/// Result acknowledgement is exactly repeatable while the sequence remains allocated.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EventResultAcknowledgement {
    Acknowledged,
    AlreadyAcknowledged,
}

/// Explicit abandonment advances the contiguous allocation frontier without an Event.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EventOperationAbandonment {
    Abandoned,
    AlreadyAbandoned,
}

/// Numbered publication/session failures with stable application meaning.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum NumberedEventOperationError {
    InvalidClientId,
    InvalidClaimNonce,
    InvalidSession,
    InvalidSequence,
    SequenceExhausted,
    SessionExhausted,
    RevisionExhausted,
    ClientLimitExceeded,
    OutstandingLimitExceeded,
    GlobalRecordLimitExceeded,
    GlobalByteLimitExceeded,
    RecoverySnapshotTooLarge,
    LegacyStoreRequiresFreshState,
    LegacyOperationDisabled,
    ClientNotFound,
    SessionFenced,
    RecoveryRequired,
    RecoveryRevisionChanged,
    SequenceGap,
    SequenceRetired,
    IntentConflict,
    ResultNotFound,
    Invariant(&'static str),
}

impl fmt::Display for NumberedEventOperationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::InvalidClientId => "publication client identifier is invalid",
            Self::InvalidClaimNonce => "publication session claim nonce is invalid",
            Self::InvalidSession => "publication session must be positive",
            Self::InvalidSequence => "publication operation sequence must be positive",
            Self::SequenceExhausted => "publication operation sequence is exhausted",
            Self::SessionExhausted => "publication session counter is exhausted",
            Self::RevisionExhausted => "publication recovery revision is exhausted",
            Self::ClientLimitExceeded => "publication client limit is exhausted",
            Self::OutstandingLimitExceeded => "client outstanding-result limit is exhausted",
            Self::GlobalRecordLimitExceeded => "global publication record limit is exhausted",
            Self::GlobalByteLimitExceeded => "global publication byte limit is exhausted",
            Self::RecoverySnapshotTooLarge => {
                "publication recovery snapshot exceeds its response bound"
            }
            Self::LegacyStoreRequiresFreshState => {
                "legacy Event operation state requires a fresh numbered-publication store"
            }
            Self::LegacyOperationDisabled => {
                "legacy Event operation publication is disabled for this store"
            }
            Self::ClientNotFound => "publication client was not found",
            Self::SessionFenced => "publication session was fenced by another claimant",
            Self::RecoveryRequired => "publication recovery must complete before mutation",
            Self::RecoveryRevisionChanged => "publication recovery snapshot revision changed",
            Self::SequenceGap => "publication operation sequence has a gap",
            Self::SequenceRetired => "publication operation sequence is permanently retired",
            Self::IntentConflict => "publication operation sequence was reused with another intent",
            Self::ResultNotFound => "publication result was not found",
            Self::Invariant(reason) => reason,
        })
    }
}

impl Error for NumberedEventOperationError {}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct NumberedEventOperationStats {
    pub clients: u64,
    pub outstanding_results: u64,
    pub reverse_edges: u64,
    pub logical_bytes: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct ClientRecord {
    session: u64,
    allocated_through: u64,
    snapshot_revision: u64,
    completed_session: u64,
    completed_revision: u64,
    last_claim_expected: u64,
    last_claim_digest: [u8; 32],
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct PendingNumberedEventOperation<'a> {
    pub client: &'a EventClientId,
    pub session: EventPublicationSession,
    pub sequence: EventOperationSequence,
    pub predecessor: Option<EventSemanticId>,
    pub intent_digest: [u8; 32],
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum NumberedOperationResolution {
    New,
    Existing(NumberedEventResult),
}

impl Store {
    /// Monotonic count of newly committed numbered operations, independent
    /// of session claims, result acknowledgement, and content retirement.
    pub fn committed_numbered_event_publication_count(&self) -> Result<u64, StoreError> {
        self.require_live()?;
        let read = self.database.begin_read()?;
        Ok(read
            .open_table(METADATA)?
            .get(COMMITTED_COUNT)?
            .map_or(0, |value| value.value()))
    }

    /// Reads bounded application-owned durable publication progress. The store
    /// never interprets this checkpoint as a publication operation or receipt.
    pub fn event_publication_checkpoint(
        &self,
        client: &EventClientId,
    ) -> Result<Option<Vec<u8>>, StoreError> {
        self.require_live()?;
        self.require_bound_mission()?;
        let read = self.database.begin_read()?;
        if !read
            .list_tables()?
            .any(|table| table.name() == APPLICATION_CHECKPOINTS.name())
        {
            return Ok(None);
        }
        Ok(read
            .open_table(APPLICATION_CHECKPOINTS)?
            .get(client.as_bytes())?
            .map(|value| value.value().to_vec()))
    }

    /// Replaces one bounded application checkpoint with immediate durability.
    /// A bounded client namespace prevents an application from creating an
    /// unbounded secondary operation-key ledger.
    pub fn save_event_publication_checkpoint(
        &self,
        client: &EventClientId,
        checkpoint: &[u8],
    ) -> Result<(), StoreError> {
        self.require_live()?;
        self.require_bound_mission()?;
        if checkpoint.is_empty() || checkpoint.len() > 16 * 1024 {
            return Err(StoreError::InvalidSemanticEvent(
                "application publication checkpoint exceeds its bound",
            ));
        }
        let write = self.database.begin_write()?;
        crate::enforce_live_write(&write)?;
        {
            let mut table = write.open_table(APPLICATION_CHECKPOINTS)?;
            if table.get(client.as_bytes())?.is_none() && table.len()? >= MAX_NUMBERED_EVENT_CLIENTS
            {
                return Err(StoreError::InvalidSemanticEvent(
                    "application publication checkpoint namespace is full",
                ));
            }
            table.insert(client.as_bytes(), checkpoint)?;
        }
        write.commit()?;
        Ok(())
    }

    /// Tests registration without creating or claiming a publication client.
    pub fn has_event_publication_client(&self, client: &EventClientId) -> Result<bool, StoreError> {
        self.require_live()?;
        let read = self.database.begin_read()?;
        if !read
            .list_tables()?
            .any(|table| table.name() == CLIENTS.name())
        {
            return Ok(false);
        }
        Ok(read.open_table(CLIENTS)?.get(client.as_bytes())?.is_some())
    }

    /// Atomically claims a new publication session or replays the same successful claim.
    pub fn begin_event_publication_session(
        &self,
        client: &EventClientId,
        expected_session: u64,
        claim_nonce: &[u8],
    ) -> Result<EventRecoverySnapshot, StoreError> {
        self.require_live()?;
        if claim_nonce.is_empty() || claim_nonce.len() > MAX_EVENT_SESSION_CLAIM_NONCE_BYTES {
            return Err(NumberedEventOperationError::InvalidClaimNonce.into());
        }
        let claim_digest = claim_digest(client, expected_session, claim_nonce);
        let write = self.database.begin_write()?;
        crate::enforce_live_write(&write)?;
        require_numbered_mode_write(&write, true)?;
        let existing = write
            .open_table(CLIENTS)?
            .get(client.as_bytes())?
            .map(|value| decode_client(value.value()))
            .transpose()?;
        let outstanding = if existing.is_some() {
            results_for_client_write(&write, client)?
        } else {
            Vec::new()
        };
        let existing = if existing.is_some() {
            Some(load_client_write(&write, client)?)
        } else {
            None
        };
        let record = match existing {
            Some(record)
                if record.last_claim_expected == expected_session
                    && record.last_claim_digest == claim_digest =>
            {
                record
            }
            Some(record) => {
                if record.session != expected_session {
                    return Err(NumberedEventOperationError::SessionFenced.into());
                }
                ClientRecord {
                    session: record
                        .session
                        .checked_add(1)
                        .ok_or(NumberedEventOperationError::SessionExhausted)?,
                    last_claim_expected: expected_session,
                    last_claim_digest: claim_digest,
                    ..record
                }
            }
            None => {
                if expected_session != 0 {
                    return Err(NumberedEventOperationError::SessionFenced.into());
                }
                let stats = read_stats_write(&write)?;
                if stats.clients >= MAX_NUMBERED_EVENT_CLIENTS {
                    return Err(NumberedEventOperationError::ClientLimitExceeded.into());
                }
                ClientRecord {
                    session: 1,
                    allocated_through: 0,
                    snapshot_revision: 1,
                    completed_session: 0,
                    completed_revision: 0,
                    last_claim_expected: 0,
                    last_claim_digest: claim_digest,
                }
            }
        };
        let creating = existing.is_none();
        let snapshot = snapshot(record, outstanding)?;
        if recovery_snapshot_proto_len(&snapshot) > MAX_EVENT_RECOVERY_SNAPSHOT_PROTO_BYTES {
            return Err(NumberedEventOperationError::RecoverySnapshotTooLarge.into());
        }
        if creating {
            let mut stats = read_stats_write(&write)?;
            let encoded = encode_client(record);
            charge_new_record(
                &mut stats,
                self.operation_limits,
                client.as_bytes().len() + encoded.len(),
                false,
            )?;
            stats.clients += 1;
            write_stats(&write, stats)?;
        }
        write
            .open_table(CLIENTS)?
            .insert(client.as_bytes(), encode_client(record).as_slice())?;
        write.commit()?;
        Ok(snapshot)
    }

    /// Completes restart recovery for exactly the claimed session and snapshot revision.
    pub fn complete_event_publication_recovery(
        &self,
        client: &EventClientId,
        session: EventPublicationSession,
        snapshot_revision: u64,
    ) -> Result<(), StoreError> {
        self.require_live()?;
        let write = self.database.begin_write()?;
        crate::enforce_live_write(&write)?;
        require_numbered_mode_write(&write, false)?;
        let _ = results_for_client_write(&write, client)?;
        let mut record = load_client_write(&write, client)?;
        require_session(record, session)?;
        if record.snapshot_revision != snapshot_revision {
            write.commit()?;
            return Err(NumberedEventOperationError::RecoveryRevisionChanged.into());
        }
        record.completed_session = record.session;
        record.completed_revision = record.snapshot_revision;
        write
            .open_table(CLIENTS)?
            .insert(client.as_bytes(), encode_client(record).as_slice())?;
        write.commit()?;
        Ok(())
    }

    /// Explicitly abandons exactly the next sequence so later work cannot create a gap.
    pub fn abandon_event_publication(
        &self,
        client: &EventClientId,
        session: EventPublicationSession,
        sequence: EventOperationSequence,
    ) -> Result<EventOperationAbandonment, StoreError> {
        self.require_live()?;
        let write = self.database.begin_write()?;
        crate::enforce_live_write(&write)?;
        require_numbered_mode_write(&write, false)?;
        let mut record = load_client_write(&write, client)?;
        require_mutating_session(record, session)?;
        if sequence.get() <= record.allocated_through {
            if load_result_write(&write, client, sequence)?.is_some() {
                return Err(NumberedEventOperationError::IntentConflict.into());
            }
            return Ok(EventOperationAbandonment::AlreadyAbandoned);
        }
        let expected = record
            .allocated_through
            .checked_add(1)
            .ok_or(NumberedEventOperationError::SequenceExhausted)?;
        if sequence.get() != expected {
            return Err(NumberedEventOperationError::SequenceGap.into());
        }
        record.allocated_through = sequence.get();
        advance_completed_revision(&mut record)?;
        write
            .open_table(CLIENTS)?
            .insert(client.as_bytes(), encode_client(record).as_slice())?;
        write.commit()?;
        Ok(EventOperationAbandonment::Abandoned)
    }

    /// Removes one individual committed result while preserving `allocated_through`.
    pub fn acknowledge_event_publication_result(
        &self,
        client: &EventClientId,
        session: EventPublicationSession,
        sequence: EventOperationSequence,
    ) -> Result<EventResultAcknowledgement, StoreError> {
        self.require_live()?;
        let write = self.database.begin_write()?;
        crate::enforce_live_write(&write)?;
        require_numbered_mode_write(&write, false)?;
        let mut client_record = load_client_write(&write, client)?;
        require_mutating_session(client_record, session)?;
        if sequence.get() > client_record.allocated_through {
            return Err(NumberedEventOperationError::ResultNotFound.into());
        }
        let key = result_key(client, sequence);
        let results = write.open_table(RESULTS)?;
        let Some(encoded) = results.get(key.as_slice())? else {
            return Ok(EventResultAcknowledgement::AlreadyAcknowledged);
        };
        let result = decode_result(sequence, encoded.value())?;
        let result_len = encoded.value().len();
        drop(encoded);
        drop(results);
        let reverse = reverse_key(result.receipt.transfer_id, client, sequence);
        if write.open_table(RESULTS)?.remove(key.as_slice())?.is_none()
            || write
                .open_table(RESULT_BY_EVENT)?
                .remove(reverse.as_slice())?
                .is_none()
        {
            return Err(NumberedEventOperationError::Invariant(
                "numbered Event result disappeared during acknowledgement",
            )
            .into());
        }
        let mut stats = read_stats_write(&write)?;
        stats.outstanding_results -= 1;
        stats.reverse_edges -= 1;
        stats.logical_bytes = stats
            .logical_bytes
            .checked_sub((key.len() + result_len + reverse.len()) as u64)
            .ok_or(NumberedEventOperationError::Invariant(
                "numbered Event result byte accounting underflowed",
            ))?;
        write_stats(&write, stats)?;
        advance_completed_revision(&mut client_record)?;
        write
            .open_table(CLIENTS)?
            .insert(client.as_bytes(), encode_client(client_record).as_slice())?;
        write.commit()?;
        Ok(EventResultAcknowledgement::Acknowledged)
    }

    pub fn numbered_event_operation_stats(
        &self,
    ) -> Result<NumberedEventOperationStats, StoreError> {
        let read = self.database.begin_read()?;
        read_stats_read(&read)
    }
}

pub(crate) fn canonical_numbered_result_write(
    write: &redb::WriteTransaction,
    mut result: NumberedEventResult,
) -> Result<(NumberedEventResult, bool), StoreError> {
    use crate::custody::EventCustodyAuthority;

    let authority =
        crate::custody::event_custody_authority_write(write, result.receipt.transfer_id)?;
    let (semantic_id, acceptance_marker) = match authority {
        EventCustodyAuthority::Live {
            semantic_id,
            acceptance_marker,
        }
        | EventCustodyAuthority::Retired {
            semantic_id,
            acceptance_marker,
            ..
        } => (semantic_id, acceptance_marker),
        EventCustodyAuthority::Missing => {
            return Err(NumberedEventOperationError::Invariant(
                "numbered Event result lacks custody authority",
            )
            .into());
        }
    };
    if result.receipt.semantic_id != semantic_id
        || result.receipt.acceptance_marker != acceptance_marker
    {
        return Err(NumberedEventOperationError::Invariant(
            "numbered Event result differs from custody authority",
        )
        .into());
    }
    match (result.content, authority) {
        (CommittedEventContent::Available, EventCustodyAuthority::Live { .. }) => {
            Ok((result, false))
        }
        (CommittedEventContent::Available, EventCustodyAuthority::Retired { reason, .. }) => {
            result.content = CommittedEventContent::Retired(reason);
            Ok((result, true))
        }
        (CommittedEventContent::Retired(stored), EventCustodyAuthority::Retired { reason, .. })
            if stored == reason =>
        {
            Ok((result, false))
        }
        (CommittedEventContent::Retired(_), EventCustodyAuthority::Live { .. }) => {
            Err(NumberedEventOperationError::Invariant(
                "retired numbered Event result has live custody authority",
            )
            .into())
        }
        (CommittedEventContent::Retired(_), EventCustodyAuthority::Retired { .. }) => {
            Err(NumberedEventOperationError::Invariant(
                "retired numbered Event result differs from custody authority",
            )
            .into())
        }
        (_, EventCustodyAuthority::Missing) => unreachable!("handled missing authority"),
    }
}

fn validate_numbered_result_authority(
    result: NumberedEventResult,
    authority: crate::custody::EventCustodyAuthority,
) -> Result<(), StoreError> {
    use crate::custody::EventCustodyAuthority;

    let (semantic_id, acceptance_marker) = match authority {
        EventCustodyAuthority::Live {
            semantic_id,
            acceptance_marker,
        }
        | EventCustodyAuthority::Retired {
            semantic_id,
            acceptance_marker,
            ..
        } => (semantic_id, acceptance_marker),
        EventCustodyAuthority::Missing => {
            return Err(NumberedEventOperationError::Invariant(
                "numbered Event result lacks custody authority",
            )
            .into());
        }
    };
    if result.receipt.semantic_id != semantic_id
        || result.receipt.acceptance_marker != acceptance_marker
    {
        return Err(NumberedEventOperationError::Invariant(
            "numbered Event result differs from custody authority",
        )
        .into());
    }
    match (result.content, authority) {
        (CommittedEventContent::Available, EventCustodyAuthority::Live { .. }) => Ok(()),
        (
            CommittedEventContent::Available,
            EventCustodyAuthority::Retired {
                cleanup_pending: true,
                ..
            },
        ) => Ok(()),
        (CommittedEventContent::Available, EventCustodyAuthority::Retired { .. }) => {
            Err(NumberedEventOperationError::Invariant(
                "available numbered Event result has clean retired custody authority",
            )
            .into())
        }
        (CommittedEventContent::Retired(_), EventCustodyAuthority::Live { .. }) => {
            Err(NumberedEventOperationError::Invariant(
                "retired numbered Event result has live custody authority",
            )
            .into())
        }
        (CommittedEventContent::Retired(stored), EventCustodyAuthority::Retired { reason, .. })
            if stored == reason =>
        {
            Ok(())
        }
        (CommittedEventContent::Retired(_), EventCustodyAuthority::Retired { .. }) => {
            Err(NumberedEventOperationError::Invariant(
                "retired numbered Event result differs from custody authority",
            )
            .into())
        }
        (_, EventCustodyAuthority::Missing) => unreachable!("handled missing authority"),
    }
}

fn validate_numbered_result_authority_write(
    write: &redb::WriteTransaction,
    result: NumberedEventResult,
) -> Result<(), StoreError> {
    validate_numbered_result_authority(
        result,
        crate::custody::event_custody_authority_write(write, result.receipt.transfer_id)?,
    )
}

fn validate_numbered_result_authority_read(
    read: &redb::ReadTransaction,
    result: NumberedEventResult,
) -> Result<(), StoreError> {
    validate_numbered_result_authority(
        result,
        crate::custody::event_custody_authority_read(read, result.receipt.transfer_id)?,
    )
}

fn validate_numbered_result_reverse_write(
    write: &redb::WriteTransaction,
    client: &EventClientId,
    result: NumberedEventResult,
) -> Result<(), StoreError> {
    let key = reverse_key(result.receipt.transfer_id, client, result.sequence);
    let reverse_table = write.open_table(RESULT_BY_EVENT)?;
    let reverse =
        reverse_table
            .get(key.as_slice())?
            .ok_or(NumberedEventOperationError::Invariant(
                "numbered Event result is missing its reverse edge",
            ))?;
    if !reverse.value().is_empty() {
        return Err(NumberedEventOperationError::Invariant(
            "numbered Event reverse value is not empty",
        )
        .into());
    }
    Ok(())
}

pub(crate) fn resolve_numbered_operation_write(
    write: &redb::WriteTransaction,
    operation: PendingNumberedEventOperation<'_>,
) -> Result<NumberedOperationResolution, StoreError> {
    require_numbered_mode_write(write, false)?;
    let record = load_client_write(write, operation.client)?;
    require_mutating_session(record, operation.session)?;
    if operation.sequence.get() <= record.allocated_through {
        let Some((stored, digest)) =
            load_result_with_digest_write(write, operation.client, operation.sequence)?
        else {
            return Err(NumberedEventOperationError::SequenceRetired.into());
        };
        if digest != operation.intent_digest {
            return Err(NumberedEventOperationError::IntentConflict.into());
        }
        validate_numbered_result_reverse_write(write, operation.client, stored)?;
        let (stored, rewritten) = canonical_numbered_result_write(write, stored)?;
        if rewritten {
            write.open_table(RESULTS)?.insert(
                result_key(operation.client, operation.sequence).as_slice(),
                encode_result(stored, digest).as_slice(),
            )?;
            let mut client_record = load_client_write(write, operation.client)?;
            advance_revision_preserving_recovery_state(&mut client_record)?;
            write.open_table(CLIENTS)?.insert(
                operation.client.as_bytes(),
                encode_client(client_record).as_slice(),
            )?;
        }
        return Ok(NumberedOperationResolution::Existing(stored));
    }
    let expected = record
        .allocated_through
        .checked_add(1)
        .ok_or(NumberedEventOperationError::SequenceExhausted)?;
    if operation.sequence.get() != expected {
        return Err(NumberedEventOperationError::SequenceGap.into());
    }
    Ok(NumberedOperationResolution::New)
}

pub(crate) fn admit_numbered_result_write(
    write: &redb::WriteTransaction,
    operation: PendingNumberedEventOperation<'_>,
    receipt: CommittedEventReceipt,
    content: CommittedEventContent,
    limits: EventOperationLimits,
    tombstone: bool,
) -> Result<NumberedEventResult, StoreError> {
    let outstanding = results_for_client_write(write, operation.client)?;
    let mut client_record = load_client_write(write, operation.client)?;
    require_mutating_session(client_record, operation.session)?;
    let expected = client_record
        .allocated_through
        .checked_add(1)
        .ok_or(NumberedEventOperationError::SequenceExhausted)?;
    if operation.sequence.get() != expected {
        return Err(NumberedEventOperationError::SequenceGap.into());
    }
    if outstanding.len() as u64 >= MAX_OUTSTANDING_EVENT_RESULTS_PER_CLIENT {
        return Err(NumberedEventOperationError::OutstandingLimitExceeded.into());
    }
    let result = NumberedEventResult {
        sequence: operation.sequence,
        receipt,
        content,
    };
    let encoded = encode_result(result, operation.intent_digest);
    let key = result_key(operation.client, operation.sequence);
    let reverse = reverse_key(receipt.transfer_id, operation.client, operation.sequence);
    let mut stats = read_stats_write(write)?;
    charge_new_record(
        &mut stats,
        limits,
        key.len() + encoded.len() + reverse.len(),
        tombstone,
    )?;
    let mut prospective = outstanding;
    prospective.push(result);
    let next_revision = client_record
        .snapshot_revision
        .checked_add(1)
        .ok_or(NumberedEventOperationError::RevisionExhausted)?;
    let prospective_snapshot = EventRecoverySnapshot {
        session: operation.session,
        allocated_through: operation.sequence.get(),
        snapshot_revision: next_revision,
        outstanding: prospective,
    };
    if recovery_snapshot_proto_len(&prospective_snapshot) > MAX_EVENT_RECOVERY_SNAPSHOT_PROTO_BYTES
    {
        return Err(NumberedEventOperationError::RecoverySnapshotTooLarge.into());
    }
    if write
        .open_table(RESULTS)?
        .insert(key.as_slice(), encoded.as_slice())?
        .is_some()
        || write
            .open_table(RESULT_BY_EVENT)?
            .insert(reverse.as_slice(), &[][..])?
            .is_some()
    {
        return Err(NumberedEventOperationError::Invariant(
            "numbered Event result key was already present",
        )
        .into());
    }
    {
        let mut metadata = write.open_table(METADATA)?;
        let count = metadata
            .get(COMMITTED_COUNT)?
            .map_or(0, |value| value.value());
        let next = count
            .checked_add(1)
            .ok_or(StoreError::AcceptanceMarkerExhausted)?;
        metadata.insert(COMMITTED_COUNT, next)?;
    }
    stats.outstanding_results += 1;
    stats.reverse_edges += 1;
    write_stats(write, stats)?;
    client_record.allocated_through = operation.sequence.get();
    advance_completed_revision(&mut client_record)?;
    write.open_table(CLIENTS)?.insert(
        operation.client.as_bytes(),
        encode_client(client_record).as_slice(),
    )?;
    Ok(result)
}

#[cfg(test)]
pub(crate) fn retire_numbered_results_write(
    write: &redb::WriteTransaction,
    transfer_id: EventTransferId,
    reason: CustodyRetirementReason,
) -> Result<(), StoreError> {
    let mut cursor = None;
    let mut budget = crate::custody::MaintenanceBudget::default();
    let _ = cleanup_numbered_results_write(write, transfer_id, reason, &mut cursor, &mut budget)?;
    Ok(())
}

pub(crate) fn cleanup_numbered_results_write(
    write: &redb::WriteTransaction,
    transfer_id: EventTransferId,
    reason: CustodyRetirementReason,
    cursor: &mut Option<Vec<u8>>,
    budget: &mut crate::custody::MaintenanceBudget,
) -> Result<crate::custody::RetirementCleanupProgress, StoreError> {
    if let Some(cursor) = cursor.as_deref() {
        validate_numbered_cleanup_cursor(transfer_id, cursor)?;
    }
    let prefix = transfer_id.as_bytes();
    let mut successor = *prefix;
    let upper = if let Some(index) = successor.iter().rposition(|byte| *byte != u8::MAX) {
        successor[index] += 1;
        successor[index + 1..].fill(0);
        std::ops::Bound::Excluded(successor.as_slice())
    } else {
        std::ops::Bound::Unbounded
    };
    loop {
        let lower = cursor.as_deref().map_or(
            std::ops::Bound::Included(prefix.as_slice()),
            std::ops::Bound::Excluded,
        );
        let next = write
            .open_table(RESULT_BY_EVENT)?
            .range::<&[u8]>((lower, upper))?
            .next()
            .transpose()?
            .map(|(key, value)| (key.value().to_vec(), value.value().to_vec()));
        let Some((reverse_key_bytes, reverse_value)) = next else {
            return Ok(crate::custody::RetirementCleanupProgress::Complete);
        };
        if !budget.try_consume_dependency()? {
            return Ok(crate::custody::RetirementCleanupProgress::Pending);
        }
        #[cfg(test)]
        REVERSE_ROWS_VISITED.with(|count| count.set(count.get() + 1));
        if !reverse_value.is_empty() {
            return Err(NumberedEventOperationError::Invariant(
                "numbered Event reverse value is not empty",
            )
            .into());
        }
        let (client, sequence) = decode_reverse_key(&reverse_key_bytes)?;
        if reverse_key_bytes.get(..32) != Some(prefix.as_slice()) {
            return Err(NumberedEventOperationError::Invariant(
                "numbered Event reverse edge targets another Event",
            )
            .into());
        }
        let key = result_key(&client, sequence);
        let results = write.open_table(RESULTS)?;
        let encoded =
            results
                .get(key.as_slice())?
                .ok_or(NumberedEventOperationError::Invariant(
                    "numbered Event reverse edge lost its result",
                ))?;
        let (result, intent_digest) = decode_result_with_digest(sequence, encoded.value())?;
        drop(encoded);
        drop(results);
        if result.receipt.transfer_id != transfer_id {
            return Err(NumberedEventOperationError::Invariant(
                "numbered Event reverse edge targets another Event",
            )
            .into());
        }
        let (result, rewritten) = canonical_numbered_result_write(write, result)?;
        match result.content {
            CommittedEventContent::Retired(stored) if stored == reason => {
                if rewritten {
                    write.open_table(RESULTS)?.insert(
                        key.as_slice(),
                        encode_result(result, intent_digest).as_slice(),
                    )?;
                    let mut client_record = load_client_write(write, &client)?;
                    advance_revision_preserving_recovery_state(&mut client_record)?;
                    write
                        .open_table(CLIENTS)?
                        .insert(client.as_bytes(), encode_client(client_record).as_slice())?;
                }
            }
            CommittedEventContent::Available => {
                return Err(NumberedEventOperationError::Invariant(
                    "numbered Event cleanup lacks retired custody authority",
                )
                .into());
            }
            CommittedEventContent::Retired(_) => {
                return Err(NumberedEventOperationError::Invariant(
                    "retired numbered Event result differs from cleanup authority",
                )
                .into());
            }
        }
        *cursor = Some(reverse_key_bytes);
        budget.record_examined_numbered_result(rewritten)?;
    }
}

pub(crate) fn validate_numbered_cleanup_cursor(
    transfer_id: EventTransferId,
    cursor: &[u8],
) -> Result<(), StoreError> {
    let valid = cursor.get(..32) == Some(transfer_id.as_bytes().as_slice())
        && decode_reverse_key(cursor)
            .is_ok_and(|(client, sequence)| reverse_key(transfer_id, &client, sequence) == cursor);
    if !valid {
        return Err(NumberedEventOperationError::Invariant(
            "numbered Event cleanup cursor key is invalid",
        )
        .into());
    }
    Ok(())
}

pub(crate) fn legacy_operation_allowed_write(
    write: &redb::WriteTransaction,
) -> Result<(), StoreError> {
    match write
        .open_table(METADATA)?
        .get(MODE)?
        .map(|value| value.value())
    {
        None => Ok(()),
        Some(1) => Err(NumberedEventOperationError::LegacyOperationDisabled.into()),
        Some(_) => Err(NumberedEventOperationError::Invariant(
            "numbered Event operation mode is unknown",
        )
        .into()),
    }
}

pub(crate) fn audit_numbered_tables_write(
    write: &redb::WriteTransaction,
) -> Result<NumberedEventOperationStats, StoreError> {
    let table_names = [
        "aster.numbered-event-clients.v1",
        "aster.numbered-event-results.v1",
        "aster.numbered-event-result-by-event.v1",
    ];
    let regular = write
        .list_tables()?
        .map(|table| table.name().to_owned())
        .collect::<BTreeSet<_>>();
    if regular.contains(APPLICATION_CHECKPOINTS.name()) {
        let checkpoints = write.open_table(APPLICATION_CHECKPOINTS)?;
        if checkpoints.len()? != 0 && crate::read_mission_binding(write)?.is_none() {
            return Err(StoreError::SemanticInvariant(
                "unbound store contains application publication checkpoints",
            ));
        }
        if checkpoints.len()? > MAX_NUMBERED_EVENT_CLIENTS {
            return Err(StoreError::SemanticInvariant(
                "application publication checkpoint namespace exceeds its bound",
            ));
        }
        for row in checkpoints.iter()? {
            let (client, checkpoint) = row?;
            EventClientId::new(client.value().to_vec())?;
            if checkpoint.value().is_empty() || checkpoint.value().len() > 16 * 1024 {
                return Err(StoreError::SemanticInvariant(
                    "application publication checkpoint exceeds its byte bound",
                ));
            }
        }
    }
    let present = table_names
        .iter()
        .filter(|name| regular.contains(**name))
        .count();
    if present != 0 && present != table_names.len() {
        return Err(NumberedEventOperationError::Invariant(
            "numbered Event operation schema group is incomplete",
        )
        .into());
    }
    let clients = write.open_table(CLIENTS)?;
    let results = write.open_table(RESULTS)?;
    let reverse = write.open_table(RESULT_BY_EVENT)?;
    let numbered_rows = clients.len()? != 0 || results.len()? != 0 || reverse.len()? != 0;
    let legacy_rows = write.open_table(EVENT_OPERATION_LEDGER_V3)?.len()? != 0
        || write.open_table(ACTIVE_OPERATION_BY_EVENT_V1)?.len()? != 0;
    let mode = write
        .open_table(METADATA)?
        .get(MODE)?
        .map(|value| value.value());
    if legacy_rows && (numbered_rows || mode == Some(1)) {
        return Err(NumberedEventOperationError::LegacyStoreRequiresFreshState.into());
    }
    match mode {
        None if numbered_rows => {
            return Err(NumberedEventOperationError::Invariant(
                "numbered Event rows lack numbered mode",
            )
            .into());
        }
        None | Some(1) => {}
        Some(_) => {
            return Err(NumberedEventOperationError::Invariant(
                "numbered Event operation mode is unknown",
            )
            .into());
        }
    }
    if clients.len()? > MAX_NUMBERED_EVENT_CLIENTS {
        return Err(NumberedEventOperationError::Invariant(
            "numbered Event client table exceeds its client limit",
        )
        .into());
    }
    let mut stats = NumberedEventOperationStats::default();
    let mut client_frontiers = BTreeMap::<EventClientId, (u64, u64)>::new();
    for row in clients.iter()? {
        let (key, value) = row?;
        let client = EventClientId::new(key.value().to_vec())?;
        let record = decode_client(value.value())?;
        client_frontiers.insert(client, (record.allocated_through, 0));
        checked_accounting_add(&mut stats.clients, 1)?;
        checked_accounting_add_lengths(
            &mut stats.logical_bytes,
            &[key.value().len(), value.value().len()],
        )?;
    }
    for row in results.iter()? {
        let (key, value) = row?;
        let (client, sequence) = decode_result_key(key.value())?;
        let (frontier, count) =
            client_frontiers
                .get_mut(&client)
                .ok_or(NumberedEventOperationError::Invariant(
                    "numbered Event result has no client",
                ))?;
        if sequence.get() > *frontier {
            return Err(NumberedEventOperationError::Invariant(
                "numbered Event result exceeds client frontier",
            )
            .into());
        }
        checked_accounting_add(count, 1)?;
        if *count > MAX_OUTSTANDING_EVENT_RESULTS_PER_CLIENT {
            return Err(NumberedEventOperationError::Invariant(
                "client exceeds its outstanding numbered Event result limit",
            )
            .into());
        }
        let (result, _) = decode_result_with_digest(sequence, value.value())?;
        let reverse_key = reverse_key(result.receipt.transfer_id, &client, sequence);
        if reverse.get(reverse_key.as_slice())?.is_none() {
            return Err(NumberedEventOperationError::Invariant(
                "numbered Event result is missing its reverse edge",
            )
            .into());
        }
        checked_accounting_add(&mut stats.outstanding_results, 1)?;
        checked_accounting_add_lengths(
            &mut stats.logical_bytes,
            &[key.value().len(), value.value().len()],
        )?;
    }
    for row in reverse.iter()? {
        let (key, value) = row?;
        if !value.value().is_empty() {
            return Err(NumberedEventOperationError::Invariant(
                "numbered Event reverse value is not empty",
            )
            .into());
        }
        let (client, sequence) = decode_reverse_key(key.value())?;
        let result_key = result_key(&client, sequence);
        let result_value =
            results
                .get(result_key.as_slice())?
                .ok_or(NumberedEventOperationError::Invariant(
                    "numbered Event reverse edge is orphaned",
                ))?;
        let result = decode_result(sequence, result_value.value())?;
        if &key.value()[..32] != result.receipt.transfer_id.as_bytes() {
            return Err(NumberedEventOperationError::Invariant(
                "numbered Event reverse edge targets another Event",
            )
            .into());
        }
        checked_accounting_add(&mut stats.reverse_edges, 1)?;
        checked_accounting_add_lengths(&mut stats.logical_bytes, &[key.value().len()])?;
    }
    let metadata = write.open_table(METADATA)?;
    let stored = (
        metadata.get(CLIENT_COUNT)?.map(|value| value.value()),
        metadata.get(RESULT_COUNT)?.map(|value| value.value()),
        metadata.get(REVERSE_COUNT)?.map(|value| value.value()),
        metadata.get(LOGICAL_BYTES)?.map(|value| value.value()),
    );
    drop(metadata);
    match stored {
        (None, None, None, None) => write_stats(write, stats)?,
        (Some(clients), Some(results), Some(reverse), Some(bytes)) => {
            let persisted = NumberedEventOperationStats {
                clients,
                outstanding_results: results,
                reverse_edges: reverse,
                logical_bytes: bytes,
            };
            if persisted != stats {
                return Err(NumberedEventOperationError::Invariant(
                    "numbered Event operation accounting differs from table truth",
                )
                .into());
            }
        }
        _ => {
            return Err(NumberedEventOperationError::Invariant(
                "numbered Event operation accounting group is incomplete",
            )
            .into());
        }
    }
    Ok(stats)
}

pub(crate) fn audit_numbered_result_authority_write(
    write: &redb::WriteTransaction,
) -> Result<(), StoreError> {
    for row in write.open_table(RESULTS)?.iter()? {
        let (key, value) = row?;
        let (_, sequence) = decode_result_key(key.value())?;
        let result = decode_result(sequence, value.value())?;
        validate_numbered_result_authority_write(write, result)?;
    }
    Ok(())
}

pub(crate) fn audit_numbered_tables_read(
    read: &redb::ReadTransaction,
) -> Result<NumberedEventOperationStats, StoreError> {
    let table_names = [
        "aster.numbered-event-clients.v1",
        "aster.numbered-event-results.v1",
        "aster.numbered-event-result-by-event.v1",
    ];
    let regular = read
        .list_tables()?
        .map(|table| table.name().to_owned())
        .collect::<BTreeSet<_>>();
    if regular.contains(APPLICATION_CHECKPOINTS.name()) {
        let checkpoints = read.open_table(APPLICATION_CHECKPOINTS)?;
        if checkpoints.len()? != 0 && crate::read_mission_binding_read(read)?.is_none() {
            return Err(StoreError::SemanticInvariant(
                "unbound store contains application publication checkpoints",
            ));
        }
        if checkpoints.len()? > MAX_NUMBERED_EVENT_CLIENTS {
            return Err(StoreError::SemanticInvariant(
                "application publication checkpoint namespace exceeds its bound",
            ));
        }
        for row in checkpoints.iter()? {
            let (client, checkpoint) = row?;
            EventClientId::new(client.value().to_vec())?;
            if checkpoint.value().is_empty() || checkpoint.value().len() > 16 * 1024 {
                return Err(StoreError::SemanticInvariant(
                    "application publication checkpoint exceeds its byte bound",
                ));
            }
        }
    }
    let present = table_names
        .iter()
        .filter(|name| regular.contains(**name))
        .count();
    if present != 0 && present != table_names.len() {
        return Err(NumberedEventOperationError::Invariant(
            "numbered Event operation schema group is incomplete",
        )
        .into());
    }
    let legacy_rows = (regular.contains(EVENT_OPERATION_LEDGER_V3.name())
        && read.open_table(EVENT_OPERATION_LEDGER_V3)?.len()? != 0)
        || (regular.contains(ACTIVE_OPERATION_BY_EVENT_V1.name())
            && read.open_table(ACTIVE_OPERATION_BY_EVENT_V1)?.len()? != 0);
    let mode = read
        .open_table(METADATA)?
        .get(MODE)?
        .map(|value| value.value());
    if present == 0 {
        if legacy_rows && mode == Some(1) {
            return Err(NumberedEventOperationError::LegacyStoreRequiresFreshState.into());
        }
        if let Some(value) = mode
            && value != 1
        {
            return Err(NumberedEventOperationError::Invariant(
                "numbered Event operation mode is unknown",
            )
            .into());
        }
        let metadata = read.open_table(METADATA)?;
        let stored = (
            metadata.get(CLIENT_COUNT)?.map(|value| value.value()),
            metadata.get(RESULT_COUNT)?.map(|value| value.value()),
            metadata.get(REVERSE_COUNT)?.map(|value| value.value()),
            metadata.get(LOGICAL_BYTES)?.map(|value| value.value()),
        );
        return match stored {
            (None, None, None, None) => Ok(NumberedEventOperationStats::default()),
            (Some(clients), Some(results), Some(reverse), Some(bytes)) => {
                let persisted = NumberedEventOperationStats {
                    clients,
                    outstanding_results: results,
                    reverse_edges: reverse,
                    logical_bytes: bytes,
                };
                if persisted != NumberedEventOperationStats::default() {
                    return Err(NumberedEventOperationError::Invariant(
                        "numbered Event operation accounting differs from table truth",
                    )
                    .into());
                }
                Ok(persisted)
            }
            _ => Err(NumberedEventOperationError::Invariant(
                "numbered Event operation accounting group is incomplete",
            )
            .into()),
        };
    }

    let clients = read.open_table(CLIENTS)?;
    let results = read.open_table(RESULTS)?;
    let reverse = read.open_table(RESULT_BY_EVENT)?;
    let numbered_rows = clients.len()? != 0 || results.len()? != 0 || reverse.len()? != 0;
    if legacy_rows && (numbered_rows || mode == Some(1)) {
        return Err(NumberedEventOperationError::LegacyStoreRequiresFreshState.into());
    }
    match mode {
        None if numbered_rows => {
            return Err(NumberedEventOperationError::Invariant(
                "numbered Event rows lack numbered mode",
            )
            .into());
        }
        None | Some(1) => {}
        Some(_) => {
            return Err(NumberedEventOperationError::Invariant(
                "numbered Event operation mode is unknown",
            )
            .into());
        }
    }
    if clients.len()? > MAX_NUMBERED_EVENT_CLIENTS {
        return Err(NumberedEventOperationError::Invariant(
            "numbered Event client table exceeds its client limit",
        )
        .into());
    }
    let mut stats = NumberedEventOperationStats::default();
    let mut client_frontiers = BTreeMap::<EventClientId, (u64, u64)>::new();
    for row in clients.iter()? {
        let (key, value) = row?;
        let client = EventClientId::new(key.value().to_vec())?;
        let record = decode_client(value.value())?;
        client_frontiers.insert(client, (record.allocated_through, 0));
        checked_accounting_add(&mut stats.clients, 1)?;
        checked_accounting_add_lengths(
            &mut stats.logical_bytes,
            &[key.value().len(), value.value().len()],
        )?;
    }
    for row in results.iter()? {
        let (key, value) = row?;
        let (client, sequence) = decode_result_key(key.value())?;
        let (frontier, count) =
            client_frontiers
                .get_mut(&client)
                .ok_or(NumberedEventOperationError::Invariant(
                    "numbered Event result has no client",
                ))?;
        if sequence.get() > *frontier {
            return Err(NumberedEventOperationError::Invariant(
                "numbered Event result exceeds client frontier",
            )
            .into());
        }
        checked_accounting_add(count, 1)?;
        if *count > MAX_OUTSTANDING_EVENT_RESULTS_PER_CLIENT {
            return Err(NumberedEventOperationError::Invariant(
                "client exceeds its outstanding numbered Event result limit",
            )
            .into());
        }
        let (result, _) = decode_result_with_digest(sequence, value.value())?;
        let reverse_key = reverse_key(result.receipt.transfer_id, &client, sequence);
        if reverse.get(reverse_key.as_slice())?.is_none() {
            return Err(NumberedEventOperationError::Invariant(
                "numbered Event result is missing its reverse edge",
            )
            .into());
        }
        checked_accounting_add(&mut stats.outstanding_results, 1)?;
        checked_accounting_add_lengths(
            &mut stats.logical_bytes,
            &[key.value().len(), value.value().len()],
        )?;
    }
    for row in reverse.iter()? {
        let (key, value) = row?;
        if !value.value().is_empty() {
            return Err(NumberedEventOperationError::Invariant(
                "numbered Event reverse value is not empty",
            )
            .into());
        }
        let (client, sequence) = decode_reverse_key(key.value())?;
        let result_key = result_key(&client, sequence);
        let result_value =
            results
                .get(result_key.as_slice())?
                .ok_or(NumberedEventOperationError::Invariant(
                    "numbered Event reverse edge is orphaned",
                ))?;
        let result = decode_result(sequence, result_value.value())?;
        if &key.value()[..32] != result.receipt.transfer_id.as_bytes() {
            return Err(NumberedEventOperationError::Invariant(
                "numbered Event reverse edge targets another Event",
            )
            .into());
        }
        checked_accounting_add(&mut stats.reverse_edges, 1)?;
        checked_accounting_add_lengths(&mut stats.logical_bytes, &[key.value().len()])?;
    }
    let metadata = read.open_table(METADATA)?;
    let stored = (
        metadata.get(CLIENT_COUNT)?.map(|value| value.value()),
        metadata.get(RESULT_COUNT)?.map(|value| value.value()),
        metadata.get(REVERSE_COUNT)?.map(|value| value.value()),
        metadata.get(LOGICAL_BYTES)?.map(|value| value.value()),
    );
    match stored {
        (None, None, None, None) => {}
        (Some(clients), Some(results), Some(reverse), Some(bytes)) => {
            let persisted = NumberedEventOperationStats {
                clients,
                outstanding_results: results,
                reverse_edges: reverse,
                logical_bytes: bytes,
            };
            if persisted != stats {
                return Err(NumberedEventOperationError::Invariant(
                    "numbered Event operation accounting differs from table truth",
                )
                .into());
            }
        }
        _ => {
            return Err(NumberedEventOperationError::Invariant(
                "numbered Event operation accounting group is incomplete",
            )
            .into());
        }
    }
    Ok(stats)
}

pub(crate) fn audit_numbered_result_authority_read(
    read: &redb::ReadTransaction,
) -> Result<(), StoreError> {
    let table_names = [
        "aster.numbered-event-clients.v1",
        "aster.numbered-event-results.v1",
        "aster.numbered-event-result-by-event.v1",
    ];
    let regular = read
        .list_tables()?
        .map(|table| table.name().to_owned())
        .collect::<BTreeSet<_>>();
    let present = table_names
        .iter()
        .filter(|name| regular.contains(**name))
        .count();
    if present == 0 {
        return Ok(());
    }
    if present != table_names.len() {
        return Err(NumberedEventOperationError::Invariant(
            "numbered Event operation schema group is incomplete",
        )
        .into());
    }
    for row in read.open_table(RESULTS)?.iter()? {
        let (key, value) = row?;
        let (_, sequence) = decode_result_key(key.value())?;
        let result = decode_result(sequence, value.value())?;
        validate_numbered_result_authority_read(read, result)?;
    }
    Ok(())
}

fn checked_accounting_add(total: &mut u64, amount: u64) -> Result<(), StoreError> {
    *total = total
        .checked_add(amount)
        .ok_or(NumberedEventOperationError::Invariant(
            "numbered Event operation accounting overflowed",
        ))?;
    Ok(())
}

fn checked_accounting_add_lengths(total: &mut u64, lengths: &[usize]) -> Result<(), StoreError> {
    for &length in lengths {
        let amount = u64::try_from(length).map_err(|_| {
            NumberedEventOperationError::Invariant("numbered Event operation accounting overflowed")
        })?;
        checked_accounting_add(total, amount)?;
    }
    Ok(())
}

fn require_numbered_mode_write(
    write: &redb::WriteTransaction,
    allow_initialize: bool,
) -> Result<(), StoreError> {
    let mode = write.open_table(METADATA)?.get(MODE)?.map(|v| v.value());
    match mode {
        Some(1) => return Ok(()),
        Some(_) => {
            return Err(NumberedEventOperationError::Invariant(
                "numbered Event operation mode is unknown",
            )
            .into());
        }
        None => {}
    }
    if !allow_initialize {
        return Err(NumberedEventOperationError::ClientNotFound.into());
    }
    if write.open_table(EVENT_OPERATION_LEDGER_V3)?.len()? != 0
        || write.open_table(ACTIVE_OPERATION_BY_EVENT_V1)?.len()? != 0
    {
        return Err(NumberedEventOperationError::LegacyStoreRequiresFreshState.into());
    }
    write.open_table(METADATA)?.insert(MODE, 1)?;
    Ok(())
}

fn claim_digest(client: &EventClientId, expected: u64, nonce: &[u8]) -> [u8; 32] {
    let mut digest = Sha256::new();
    digest.update(CLAIM_DOMAIN);
    digest.update([client.as_bytes().len() as u8]);
    digest.update(client.as_bytes());
    digest.update(expected.to_be_bytes());
    digest.update([nonce.len() as u8]);
    digest.update(nonce);
    digest.finalize().into()
}

fn require_session(
    record: ClientRecord,
    session: EventPublicationSession,
) -> Result<(), StoreError> {
    if record.session != session.get() {
        return Err(NumberedEventOperationError::SessionFenced.into());
    }
    Ok(())
}

fn require_mutating_session(
    record: ClientRecord,
    session: EventPublicationSession,
) -> Result<(), StoreError> {
    require_session(record, session)?;
    if record.completed_session != record.session
        || record.completed_revision != record.snapshot_revision
    {
        return Err(NumberedEventOperationError::RecoveryRequired.into());
    }
    Ok(())
}

fn advance_completed_revision(record: &mut ClientRecord) -> Result<(), StoreError> {
    record.snapshot_revision = record
        .snapshot_revision
        .checked_add(1)
        .ok_or(NumberedEventOperationError::RevisionExhausted)?;
    record.completed_session = record.session;
    record.completed_revision = record.snapshot_revision;
    Ok(())
}

fn advance_revision_preserving_recovery_state(record: &mut ClientRecord) -> Result<(), StoreError> {
    let was_complete = record.completed_session == record.session
        && record.completed_revision == record.snapshot_revision;
    record.snapshot_revision = record
        .snapshot_revision
        .checked_add(1)
        .ok_or(NumberedEventOperationError::RevisionExhausted)?;
    if was_complete {
        record.completed_revision = record.snapshot_revision;
    }
    Ok(())
}

fn snapshot(
    record: ClientRecord,
    outstanding: Vec<NumberedEventResult>,
) -> Result<EventRecoverySnapshot, StoreError> {
    Ok(EventRecoverySnapshot {
        session: EventPublicationSession::new(record.session)?,
        allocated_through: record.allocated_through,
        snapshot_revision: record.snapshot_revision,
        outstanding,
    })
}

fn load_client_write(
    write: &redb::WriteTransaction,
    client: &EventClientId,
) -> Result<ClientRecord, StoreError> {
    write
        .open_table(CLIENTS)?
        .get(client.as_bytes())?
        .map(|value| decode_client(value.value()))
        .transpose()?
        .ok_or_else(|| NumberedEventOperationError::ClientNotFound.into())
}

fn results_for_client_write(
    write: &redb::WriteTransaction,
    client: &EventClientId,
) -> Result<Vec<NumberedEventResult>, StoreError> {
    let rows = stored_results_for_client_write(write, client)?;
    let mut values = Vec::new();
    for (key, raw, digest) in rows {
        validate_numbered_result_reverse_write(write, client, raw)?;
        let (canonical, rewritten) = canonical_numbered_result_write(write, raw)?;
        if rewritten {
            write
                .open_table(RESULTS)?
                .insert(key.as_slice(), encode_result(canonical, digest).as_slice())?;
            let mut client_record = load_client_write(write, client)?;
            advance_revision_preserving_recovery_state(&mut client_record)?;
            write
                .open_table(CLIENTS)?
                .insert(client.as_bytes(), encode_client(client_record).as_slice())?;
        }
        values.push(canonical);
    }
    Ok(values)
}

fn stored_results_for_client_write(
    write: &redb::WriteTransaction,
    client: &EventClientId,
) -> Result<Vec<StoredNumberedEventResultRow>, StoreError> {
    let mut values: Vec<StoredNumberedEventResultRow> = Vec::new();
    let lower = result_key(client, EventOperationSequence(1));
    let upper = result_key(client, EventOperationSequence(u64::MAX));
    let rows = write
        .open_table(RESULTS)?
        .range(lower.as_slice()..=upper.as_slice())?
        .map(|row| row.map(|(key, value)| (key.value().to_vec(), value.value().to_vec())))
        .collect::<Result<Vec<_>, redb::StorageError>>()?;
    for (key, value) in rows {
        #[cfg(test)]
        RESULT_ROWS_VISITED.with(|count| count.set(count.get() + 1));
        let (stored_client, sequence) = decode_result_key(&key)?;
        if &stored_client != client {
            return Err(NumberedEventOperationError::Invariant(
                "numbered Event result range contains another client",
            )
            .into());
        }
        let (raw, digest) = decode_result_with_digest(sequence, &value)?;
        values.push((key, raw, digest));
    }
    if values.len() as u64 > MAX_OUTSTANDING_EVENT_RESULTS_PER_CLIENT {
        return Err(NumberedEventOperationError::Invariant(
            "client exceeds its outstanding numbered Event result limit",
        )
        .into());
    }
    Ok(values)
}

#[cfg(test)]
pub(crate) fn seed_numbered_result_fanout_write(
    write: &redb::WriteTransaction,
    client: &EventClientId,
    receipt: CommittedEventReceipt,
    additional: u64,
) -> Result<(), StoreError> {
    let mut record = load_client_write(write, client)?;
    let mut stats = read_stats_write(write)?;
    let start = record
        .allocated_through
        .checked_add(1)
        .ok_or(NumberedEventOperationError::SequenceExhausted)?;
    let end = record
        .allocated_through
        .checked_add(additional)
        .ok_or(NumberedEventOperationError::SequenceExhausted)?;
    for raw_sequence in start..=end {
        let sequence = EventOperationSequence::new(raw_sequence)?;
        let result = NumberedEventResult {
            sequence,
            receipt,
            content: CommittedEventContent::Available,
        };
        let key = result_key(client, sequence);
        let value = encode_result(result, [raw_sequence as u8; 32]);
        let reverse = reverse_key(receipt.transfer_id, client, sequence);
        write
            .open_table(RESULTS)?
            .insert(key.as_slice(), value.as_slice())?;
        write
            .open_table(RESULT_BY_EVENT)?
            .insert(reverse.as_slice(), &[][..])?;
        stats.outstanding_results += 1;
        stats.reverse_edges += 1;
        stats.logical_bytes = stats
            .logical_bytes
            .checked_add((key.len() + value.len() + reverse.len()) as u64)
            .ok_or(NumberedEventOperationError::Invariant(
                "numbered Event fixture accounting overflowed",
            ))?;
        record.allocated_through = raw_sequence;
        advance_revision_preserving_recovery_state(&mut record)?;
    }
    write_stats(write, stats)?;
    write
        .open_table(CLIENTS)?
        .insert(client.as_bytes(), encode_client(record).as_slice())?;
    Ok(())
}

#[cfg(test)]
pub(crate) fn client_snapshot_revision_for_test(
    store: &Store,
    client: &EventClientId,
) -> Result<u64, StoreError> {
    let write = store.database.begin_write()?;
    Ok(load_client_write(&write, client)?.snapshot_revision)
}

fn load_result_write(
    write: &redb::WriteTransaction,
    client: &EventClientId,
    sequence: EventOperationSequence,
) -> Result<Option<NumberedEventResult>, StoreError> {
    write
        .open_table(RESULTS)?
        .get(result_key(client, sequence).as_slice())?
        .map(|value| decode_result(sequence, value.value()))
        .transpose()
}

fn load_result_with_digest_write(
    write: &redb::WriteTransaction,
    client: &EventClientId,
    sequence: EventOperationSequence,
) -> Result<Option<(NumberedEventResult, [u8; 32])>, StoreError> {
    write
        .open_table(RESULTS)?
        .get(result_key(client, sequence).as_slice())?
        .map(|value| decode_result_with_digest(sequence, value.value()))
        .transpose()
}

fn result_key(client: &EventClientId, sequence: EventOperationSequence) -> Vec<u8> {
    let mut key = Vec::with_capacity(1 + client.as_bytes().len() + 8);
    key.push(client.as_bytes().len() as u8);
    key.extend_from_slice(client.as_bytes());
    key.extend_from_slice(&sequence.get().to_be_bytes());
    key
}

fn decode_result_key(bytes: &[u8]) -> Result<(EventClientId, EventOperationSequence), StoreError> {
    let (&length, rest) = bytes
        .split_first()
        .ok_or(NumberedEventOperationError::Invariant(
            "numbered Event result key is empty",
        ))?;
    let length = usize::from(length);
    if rest.len() != length + 8 {
        return Err(NumberedEventOperationError::Invariant(
            "numbered Event result key length is invalid",
        )
        .into());
    }
    let client = EventClientId::new(rest[..length].to_vec())?;
    let sequence = EventOperationSequence::new(u64::from_be_bytes(
        rest[length..].try_into().expect("checked sequence bytes"),
    ))?;
    Ok((client, sequence))
}

fn reverse_key(
    transfer_id: EventTransferId,
    client: &EventClientId,
    sequence: EventOperationSequence,
) -> Vec<u8> {
    let mut key = Vec::with_capacity(32 + 1 + client.as_bytes().len() + 8);
    key.extend_from_slice(transfer_id.as_bytes());
    key.extend_from_slice(&result_key(client, sequence));
    key
}

fn decode_reverse_key(bytes: &[u8]) -> Result<(EventClientId, EventOperationSequence), StoreError> {
    if bytes.len() < 32 {
        return Err(
            NumberedEventOperationError::Invariant("numbered Event reverse key is short").into(),
        );
    }
    decode_result_key(&bytes[32..])
}

fn encode_client(record: ClientRecord) -> [u8; 81] {
    let mut encoded = [0u8; 81];
    encoded[0] = CLIENT_VERSION;
    for (index, value) in [
        record.session,
        record.allocated_through,
        record.snapshot_revision,
        record.completed_session,
        record.completed_revision,
        record.last_claim_expected,
    ]
    .into_iter()
    .enumerate()
    {
        let offset = 1 + index * 8;
        encoded[offset..offset + 8].copy_from_slice(&value.to_be_bytes());
    }
    encoded[49..].copy_from_slice(&record.last_claim_digest);
    encoded
}

fn decode_client(bytes: &[u8]) -> Result<ClientRecord, StoreError> {
    let encoded: &[u8; 81] = bytes.try_into().map_err(|_| {
        NumberedEventOperationError::Invariant("numbered Event client record length is invalid")
    })?;
    if encoded[0] != CLIENT_VERSION {
        return Err(NumberedEventOperationError::Invariant(
            "numbered Event client record version is unknown",
        )
        .into());
    }
    let read = |index: usize| {
        let offset = 1 + index * 8;
        u64::from_be_bytes(encoded[offset..offset + 8].try_into().expect("fixed field"))
    };
    let record = ClientRecord {
        session: read(0),
        allocated_through: read(1),
        snapshot_revision: read(2),
        completed_session: read(3),
        completed_revision: read(4),
        last_claim_expected: read(5),
        last_claim_digest: encoded[49..].try_into().expect("fixed digest"),
    };
    if record.session == 0 || record.snapshot_revision == 0 {
        return Err(NumberedEventOperationError::Invariant(
            "numbered Event client counters are zero",
        )
        .into());
    }
    Ok(record)
}

fn encode_result(result: NumberedEventResult, intent_digest: [u8; 32]) -> [u8; 114] {
    let mut encoded = [0u8; 114];
    encoded[0] = RESULT_VERSION;
    encoded[1..33].copy_from_slice(&intent_digest);
    encoded[33..65].copy_from_slice(result.receipt.transfer_id.as_bytes());
    encoded[65..97].copy_from_slice(result.receipt.semantic_id.as_bytes());
    encoded[97..105].copy_from_slice(&result.receipt.acceptance_marker.to_be_bytes());
    match result.content {
        CommittedEventContent::Available => encoded[105] = CONTENT_AVAILABLE,
        CommittedEventContent::Retired(reason) => {
            encoded[105] = CONTENT_RETIRED;
            encoded[106] = reason as u8;
        }
    }
    encoded
}

fn decode_result(
    sequence: EventOperationSequence,
    bytes: &[u8],
) -> Result<NumberedEventResult, StoreError> {
    decode_result_with_digest(sequence, bytes).map(|(result, _)| result)
}

fn decode_result_with_digest(
    sequence: EventOperationSequence,
    bytes: &[u8],
) -> Result<(NumberedEventResult, [u8; 32]), StoreError> {
    let encoded: &[u8; 114] = bytes.try_into().map_err(|_| {
        NumberedEventOperationError::Invariant("numbered Event result length is invalid")
    })?;
    if encoded[0] != RESULT_VERSION || encoded[107..].iter().any(|byte| *byte != 0) {
        return Err(NumberedEventOperationError::Invariant(
            "numbered Event result encoding is noncanonical",
        )
        .into());
    }
    let content = match (encoded[105], encoded[106]) {
        (CONTENT_AVAILABLE, 0) => CommittedEventContent::Available,
        (CONTENT_RETIRED, 1) => CommittedEventContent::Retired(CustodyRetirementReason::Expired),
        (CONTENT_RETIRED, 2) => {
            CommittedEventContent::Retired(CustodyRetirementReason::QuotaPressure)
        }
        _ => {
            return Err(NumberedEventOperationError::Invariant(
                "numbered Event result content state is invalid",
            )
            .into());
        }
    };
    Ok((
        NumberedEventResult {
            sequence,
            receipt: CommittedEventReceipt {
                transfer_id: EventTransferId::new(encoded[33..65].try_into().expect("fixed id")),
                semantic_id: EventSemanticId::new(encoded[65..97].try_into().expect("fixed id")),
                acceptance_marker: u64::from_be_bytes(
                    encoded[97..105].try_into().expect("fixed marker"),
                ),
            },
            content,
        },
        encoded[1..33].try_into().expect("fixed digest"),
    ))
}

fn charge_new_record(
    stats: &mut NumberedEventOperationStats,
    limits: EventOperationLimits,
    incoming_bytes: usize,
    emergency: bool,
) -> Result<(), StoreError> {
    let next_records = stats
        .clients
        .checked_add(stats.outstanding_results)
        .and_then(|records| records.checked_add(1))
        .ok_or(NumberedEventOperationError::GlobalRecordLimitExceeded)?;
    let record_limit = if emergency {
        limits.max_records()
    } else {
        limits.ordinary_record_limit()
    };
    if next_records > record_limit {
        return Err(NumberedEventOperationError::GlobalRecordLimitExceeded.into());
    }
    let incoming = u64::try_from(incoming_bytes)
        .map_err(|_| NumberedEventOperationError::GlobalByteLimitExceeded)?;
    let byte_limit = if emergency {
        limits.max_logical_bytes()
    } else {
        limits.max_logical_bytes() - limits.emergency_byte_reserve()
    };
    let next_bytes = stats
        .logical_bytes
        .checked_add(incoming)
        .ok_or(NumberedEventOperationError::GlobalByteLimitExceeded)?;
    if next_bytes > byte_limit {
        return Err(NumberedEventOperationError::GlobalByteLimitExceeded.into());
    }
    stats.logical_bytes = next_bytes;
    Ok(())
}

fn read_stats_write(
    write: &redb::WriteTransaction,
) -> Result<NumberedEventOperationStats, StoreError> {
    let metadata = write.open_table(METADATA)?;
    Ok(NumberedEventOperationStats {
        clients: metadata.get(CLIENT_COUNT)?.map_or(0, |v| v.value()),
        outstanding_results: metadata.get(RESULT_COUNT)?.map_or(0, |v| v.value()),
        reverse_edges: metadata.get(REVERSE_COUNT)?.map_or(0, |v| v.value()),
        logical_bytes: metadata.get(LOGICAL_BYTES)?.map_or(0, |v| v.value()),
    })
}

fn read_stats_read(
    read: &redb::ReadTransaction,
) -> Result<NumberedEventOperationStats, StoreError> {
    let metadata = read.open_table(METADATA)?;
    Ok(NumberedEventOperationStats {
        clients: metadata.get(CLIENT_COUNT)?.map_or(0, |v| v.value()),
        outstanding_results: metadata.get(RESULT_COUNT)?.map_or(0, |v| v.value()),
        reverse_edges: metadata.get(REVERSE_COUNT)?.map_or(0, |v| v.value()),
        logical_bytes: metadata.get(LOGICAL_BYTES)?.map_or(0, |v| v.value()),
    })
}

fn write_stats(
    write: &redb::WriteTransaction,
    stats: NumberedEventOperationStats,
) -> Result<(), StoreError> {
    let mut metadata = write.open_table(METADATA)?;
    metadata.insert(CLIENT_COUNT, stats.clients)?;
    metadata.insert(RESULT_COUNT, stats.outstanding_results)?;
    metadata.insert(REVERSE_COUNT, stats.reverse_edges)?;
    metadata.insert(LOGICAL_BYTES, stats.logical_bytes)?;
    Ok(())
}

const fn varint_len(mut value: u64) -> usize {
    let mut length = 1;
    while value >= 0x80 {
        value >>= 7;
        length += 1;
    }
    length
}

const fn field_varint_len(field: u8, value: u64) -> usize {
    let _ = field;
    1 + varint_len(value)
}

const fn bytes_field_len(length: usize) -> usize {
    1 + varint_len(length as u64) + length
}

fn result_proto_len(result: NumberedEventResult) -> usize {
    let receipt_len = bytes_field_len(32)
        + bytes_field_len(32)
        + field_varint_len(3, result.receipt.acceptance_marker);
    field_varint_len(1, result.sequence.get())
        + 1
        + varint_len(receipt_len as u64)
        + receipt_len
        + field_varint_len(
            3,
            match result.content {
                CommittedEventContent::Available => 1,
                CommittedEventContent::Retired(_) => 2,
            },
        )
        + match result.content {
            CommittedEventContent::Available => 0,
            CommittedEventContent::Retired(reason) => field_varint_len(4, reason as u64),
        }
}

/// Exact protobuf body size for the additive recovery response schema.
pub fn recovery_snapshot_proto_len(snapshot: &EventRecoverySnapshot) -> usize {
    field_varint_len(1, snapshot.session.get())
        + field_varint_len(2, snapshot.allocated_through)
        + field_varint_len(3, snapshot.snapshot_revision)
        + snapshot
            .outstanding
            .iter()
            .map(|result| {
                let length = result_proto_len(*result);
                1 + varint_len(length as u64) + length
            })
            .sum::<usize>()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU64, Ordering};

    static NEXT_CORRUPTION_PATH: AtomicU64 = AtomicU64::new(0);
    const CORRUPTION_MISSION: [u8; 32] = [0x71; 32];

    struct CorruptionFile(std::path::PathBuf);

    impl CorruptionFile {
        fn new(name: &str) -> Self {
            let id = NEXT_CORRUPTION_PATH.fetch_add(1, Ordering::Relaxed);
            Self(std::env::temp_dir().join(format!(
                "aster-numbered-corruption-{name}-{}-{id}.redb",
                std::process::id()
            )))
        }

        fn open(&self) -> Store {
            Store::open_for_mission(&self.0, CORRUPTION_MISSION).expect("fixture store")
        }

        fn reopen_error(&self) -> StoreError {
            Store::open_for_mission(&self.0, CORRUPTION_MISSION)
                .err()
                .expect("corrupt store must not open")
        }

        fn inspect_error(&self) -> StoreError {
            Store::inspect_existing(&self.0).expect_err("corrupt store must not be inspectable")
        }
    }

    impl Drop for CorruptionFile {
        fn drop(&mut self) {
            let _ = std::fs::remove_file(&self.0);
        }
    }

    fn fixture_client(store: &Store) -> EventClientId {
        let client = EventClientId::new(b"corrupt-client".to_vec()).expect("client");
        store
            .begin_event_publication_session(&client, 0, b"fixture-claim")
            .expect("claim");
        client
    }

    fn capacity_client(store: &Store) -> EventClientId {
        let client = EventClientId::new(b"x".to_vec()).unwrap();
        let claim = store
            .begin_event_publication_session(&client, 0, b"capacity")
            .unwrap();
        store
            .complete_event_publication_recovery(&client, claim.session, claim.snapshot_revision)
            .unwrap();
        client
    }

    fn capacity_operation(
        client: &EventClientId,
        sequence: u64,
    ) -> PendingNumberedEventOperation<'_> {
        PendingNumberedEventOperation {
            client,
            session: EventPublicationSession::new(1).unwrap(),
            sequence: EventOperationSequence::new(sequence).unwrap(),
            predecessor: None,
            intent_digest: [sequence as u8; 32],
        }
    }

    fn capacity_admit(
        store: &Store,
        client: &EventClientId,
        sequence: u64,
        tombstone: bool,
        limits: EventOperationLimits,
    ) -> Result<NumberedEventResult, StoreError> {
        let write = store.database.begin_write()?;
        let receipt = CommittedEventReceipt {
            transfer_id: EventTransferId::new([sequence as u8; 32]),
            semantic_id: EventSemanticId::new([sequence as u8 + 10; 32]),
            acceptance_marker: sequence,
        };
        crate::custody::seed_event_custody_authority_for_numbered_test(&write, receipt)?;
        let result = crate::admit_pending_event_operation_write(
            &write,
            &[0x71; 32],
            crate::PendingEventOperation::Numbered(capacity_operation(client, sequence)),
            receipt,
            CommittedEventContent::Available,
            limits,
            tombstone,
        )?
        .expect("numbered result");
        write.commit()?;
        Ok(result)
    }

    #[test]
    fn numbered_tombstones_use_record_reserve_without_exceeding_hard_limit() {
        capacity_case(
            "record-capacity",
            EventOperationLimits::new(3, 1_000, 1).unwrap(),
            NumberedEventOperationError::GlobalRecordLimitExceeded,
        );
    }

    #[test]
    fn numbered_tombstones_use_byte_reserve_without_exceeding_hard_limit() {
        // Client is 82 bytes; each one-byte-client result is 166 bytes.
        // Ordinary ceiling is 414 - 162 = 252, and hard ceiling is 414.
        capacity_case(
            "byte-capacity",
            EventOperationLimits::new(10, 414, 1).unwrap(),
            NumberedEventOperationError::GlobalByteLimitExceeded,
        );
    }

    fn capacity_case(
        name: &str,
        limits: EventOperationLimits,
        expected: NumberedEventOperationError,
    ) {
        let file = CorruptionFile::new(name);
        let store = Store::open_with_limits_and_operation_limits_for_mission(
            &file.0,
            crate::StoreLimits::default(),
            crate::BlobDepotLimits::default(),
            limits,
            CORRUPTION_MISSION,
        )
        .unwrap();
        let client = capacity_client(&store);
        capacity_admit(&store, &client, 1, false, limits).expect("ordinary result");
        let before = store.numbered_event_operation_stats().unwrap();
        assert_eq!(before.logical_bytes, 248, "{name}");
        assert_eq!(
            numbered_error(&capacity_admit(&store, &client, 2, false, limits).unwrap_err()),
            Some(&expected),
            "{name}"
        );
        assert_eq!(
            store.numbered_event_operation_stats().unwrap(),
            before,
            "{name}"
        );
        let admitted =
            capacity_admit(&store, &client, 2, true, limits).expect("tombstone must use reserve");
        let full = store.numbered_event_operation_stats().unwrap();
        assert_eq!(full.logical_bytes, 414, "{name}");
        let write = store.database.begin_write().unwrap();
        assert_eq!(
            resolve_numbered_operation_write(&write, capacity_operation(&client, 2)).unwrap(),
            NumberedOperationResolution::Existing(admitted),
            "{name}"
        );
        drop(write);
        assert_eq!(
            store.numbered_event_operation_stats().unwrap(),
            full,
            "{name}"
        );
        assert_eq!(
            numbered_error(&capacity_admit(&store, &client, 3, true, limits).unwrap_err()),
            Some(&expected),
            "{name}"
        );
        assert_eq!(
            store.numbered_event_operation_stats().unwrap(),
            full,
            "{name}"
        );
        let write = store.database.begin_write().unwrap();
        assert_eq!(
            load_client_write(&write, &client)
                .unwrap()
                .allocated_through,
            2,
            "{name}"
        );
        assert!(
            load_result_write(&write, &client, EventOperationSequence::new(3).unwrap())
                .unwrap()
                .is_none(),
            "{name}"
        );
    }

    #[test]
    fn numbered_client_creation_stays_at_ordinary_record_limit() {
        let file = CorruptionFile::new("client-ordinary-capacity");
        let store = Store::open_with_limits_and_operation_limits_for_mission(
            &file.0,
            crate::StoreLimits::default(),
            crate::BlobDepotLimits::default(),
            EventOperationLimits::new(2, 1_000, 1).unwrap(),
            CORRUPTION_MISSION,
        )
        .unwrap();
        let first = EventClientId::new(b"a".to_vec()).unwrap();
        let second = EventClientId::new(b"b".to_vec()).unwrap();
        store
            .begin_event_publication_session(&first, 0, b"first")
            .unwrap();
        let before = store.numbered_event_operation_stats().unwrap();
        assert_eq!(before.clients, 1);
        assert_eq!(
            numbered_error(
                &store
                    .begin_event_publication_session(&second, 0, b"second")
                    .unwrap_err()
            ),
            Some(&NumberedEventOperationError::GlobalRecordLimitExceeded)
        );
        assert_eq!(store.numbered_event_operation_stats().unwrap(), before);
        assert!(
            store
                .database
                .begin_read()
                .unwrap()
                .open_table(CLIENTS)
                .unwrap()
                .get(second.as_bytes())
                .unwrap()
                .is_none()
        );
    }

    fn fixture_results(
        write: &redb::WriteTransaction,
        client: &EventClientId,
        count: u64,
        frontier: u64,
    ) {
        let mut record = load_client_write(write, client).expect("client record");
        record.allocated_through = frontier;
        write
            .open_table(CLIENTS)
            .expect("clients")
            .insert(client.as_bytes(), encode_client(record).as_slice())
            .expect("update client");
        let mut stats = read_stats_write(write).expect("stats");
        let receipt = CommittedEventReceipt {
            transfer_id: EventTransferId::new([0x72; 32]),
            semantic_id: EventSemanticId::new([0x73; 32]),
            acceptance_marker: 1,
        };
        crate::custody::seed_retired_event_custody_authority_for_numbered_test(
            write,
            receipt,
            CustodyRetirementReason::Expired,
        )
        .expect("retired custody authority");
        for sequence in 1..=count {
            let sequence = EventOperationSequence::new(sequence).expect("sequence");
            let result = NumberedEventResult {
                sequence,
                receipt,
                content: CommittedEventContent::Available,
            };
            let key = result_key(client, sequence);
            let value = encode_result(result, [0x74; 32]);
            let reverse = reverse_key(result.receipt.transfer_id, client, sequence);
            write
                .open_table(RESULTS)
                .expect("results")
                .insert(key.as_slice(), value.as_slice())
                .expect("insert result");
            write
                .open_table(RESULT_BY_EVENT)
                .expect("reverse")
                .insert(reverse.as_slice(), &[][..])
                .expect("insert reverse");
            stats.outstanding_results += 1;
            stats.reverse_edges += 1;
            stats.logical_bytes += (key.len() + value.len() + reverse.len()) as u64;
        }
        write_stats(write, stats).expect("exact fixture accounting");
    }

    fn insert_lookup_result(
        write: &redb::WriteTransaction,
        client: &EventClientId,
        sequence: u64,
        transfer_id: EventTransferId,
    ) {
        let sequence = EventOperationSequence::new(sequence).expect("sequence");
        let receipt = CommittedEventReceipt {
            transfer_id,
            semantic_id: EventSemanticId::new(*transfer_id.as_bytes()),
            acceptance_marker: 1,
        };
        crate::custody::seed_retired_event_custody_authority_for_numbered_test(
            write,
            receipt,
            CustodyRetirementReason::Expired,
        )
        .expect("retired custody authority");
        let result = NumberedEventResult {
            sequence,
            receipt,
            content: CommittedEventContent::Available,
        };
        write
            .open_table(RESULTS)
            .expect("results")
            .insert(
                result_key(client, sequence).as_slice(),
                encode_result(result, [0x94; 32]).as_slice(),
            )
            .expect("insert result");
        write
            .open_table(RESULT_BY_EVENT)
            .expect("reverse")
            .insert(
                reverse_key(transfer_id, client, sequence).as_slice(),
                &[][..],
            )
            .expect("insert reverse");
    }

    #[test]
    fn client_recovery_visits_only_exact_client_results_in_sequence_order() {
        let file = CorruptionFile::new("client-lookup-range");
        let store = file.open();
        let write = store.database.begin_write().expect("write");
        let clients = [b"a".as_slice(), b"b", b"ba", b"bb", b"c"]
            .map(|name| EventClientId::new(name.to_vec()).expect("client"));
        for (index, client) in clients.iter().enumerate() {
            insert_lookup_result(&write, client, 1, EventTransferId::new([index as u8; 32]));
        }
        insert_lookup_result(&write, &clients[1], 2, EventTransferId::new([0x82; 32]));

        RESULT_ROWS_VISITED.with(|count| count.set(0));
        let recovered = stored_results_for_client_write(&write, &clients[1])
            .expect("recovery")
            .into_iter()
            .map(|(_, result, _)| result)
            .collect::<Vec<_>>();
        assert_eq!(
            recovered
                .iter()
                .map(|result| result.sequence.get())
                .collect::<Vec<_>>(),
            vec![1, 2]
        );
        assert_eq!(
            recovered[0].receipt.transfer_id,
            EventTransferId::new([1; 32])
        );
        assert_eq!(
            recovered[1].receipt.transfer_id,
            EventTransferId::new([0x82; 32])
        );
        assert_eq!(RESULT_ROWS_VISITED.with(|count| count.get()), 2);
    }

    #[test]
    fn retirement_visits_only_exact_transfer_prefix_including_maximum_id() {
        for (name, target, other) in [
            ("middle", [0x80u8; 32], [0x81; 32]),
            ("maximum", [0xffu8; 32], [0xfe; 32]),
        ] {
            let file = CorruptionFile::new(name);
            let store = file.open();
            let client = fixture_client(&store);
            let write = store.database.begin_write().expect("write");
            let mut adjacent = target;
            adjacent[31] = target[31].wrapping_sub(1);
            for (sequence, transfer) in [other, adjacent, target, target, other]
                .into_iter()
                .enumerate()
            {
                insert_lookup_result(
                    &write,
                    &client,
                    sequence as u64 + 1,
                    EventTransferId::new(transfer),
                );
            }

            REVERSE_ROWS_VISITED.with(|count| count.set(0));
            retire_numbered_results_write(
                &write,
                EventTransferId::new(target),
                CustodyRetirementReason::Expired,
            )
            .expect("retire exact transfer");
            assert_eq!(REVERSE_ROWS_VISITED.with(|count| count.get()), 2, "{name}");
            for sequence in 1..=5 {
                let result = load_result_write(
                    &write,
                    &client,
                    EventOperationSequence::new(sequence).expect("sequence"),
                )
                .expect("read result")
                .expect("result present");
                let expected = if sequence == 3 || sequence == 4 {
                    CommittedEventContent::Retired(CustodyRetirementReason::Expired)
                } else {
                    CommittedEventContent::Available
                };
                assert_eq!(result.content, expected, "{name} sequence {sequence}");
            }
            REVERSE_ROWS_VISITED.with(|count| count.set(0));
            retire_numbered_results_write(
                &write,
                EventTransferId::new(target),
                CustodyRetirementReason::Expired,
            )
            .expect("idempotent retirement");
            assert_eq!(
                REVERSE_ROWS_VISITED.with(|count| count.get()),
                2,
                "{name} retry"
            );
        }
    }

    #[test]
    fn retirement_does_not_process_more_than_one_numbered_result_page() {
        let file = CorruptionFile::new("numbered-retirement-page");
        let store = file.open();
        let client = fixture_client(&store);
        let transfer = EventTransferId::new([0x72; 32]);
        let write = store.database.begin_write().expect("write");
        fixture_results(&write, &client, 1_025, 1_025);
        REVERSE_ROWS_VISITED.with(|count| count.set(0));
        retire_numbered_results_write(&write, transfer, CustodyRetirementReason::Expired)
            .expect("bounded retirement page");
        assert_eq!(REVERSE_ROWS_VISITED.with(|count| count.get()), 1_024);
    }

    #[test]
    fn bounded_lookups_still_reject_malformed_rows_within_the_prefix() {
        let file = CorruptionFile::new("malformed-lookup-range");
        let store = file.open();
        let client = fixture_client(&store);
        let write = store.database.begin_write().expect("write");
        let sequence = EventOperationSequence::new(1).expect("sequence");
        write
            .open_table(RESULTS)
            .expect("results")
            .insert(result_key(&client, sequence).as_slice(), &[0u8][..])
            .expect("insert malformed result");
        assert_invariant(
            &results_for_client_write(&write, &client).expect_err("malformed result value"),
            "numbered Event result length is invalid",
        );
        write
            .open_table(RESULTS)
            .expect("results")
            .remove(result_key(&client, sequence).as_slice())
            .expect("remove malformed result");
        let mut malformed_key = result_key(&client, sequence);
        malformed_key.push(0);
        write
            .open_table(RESULTS)
            .expect("results")
            .insert(malformed_key.as_slice(), &[0u8][..])
            .expect("insert malformed key");
        assert_invariant(
            &results_for_client_write(&write, &client).expect_err("malformed result key"),
            "numbered Event result key length is invalid",
        );
        write
            .open_table(RESULTS)
            .expect("results")
            .remove(malformed_key.as_slice())
            .expect("remove malformed key");

        let transfer = EventTransferId::new([0xa5; 32]);
        let mut malformed_reverse = transfer.as_bytes().to_vec();
        malformed_reverse.push(0);
        write
            .open_table(RESULT_BY_EVENT)
            .expect("reverse")
            .insert(malformed_reverse.as_slice(), &[][..])
            .expect("insert malformed reverse");
        assert_invariant(
            &retire_numbered_results_write(&write, transfer, CustodyRetirementReason::Expired)
                .expect_err("malformed reverse key"),
            "numbered Event result key length is invalid",
        );
    }

    fn fixture_legacy_row(write: &redb::WriteTransaction) {
        use crate::event_operation::{
            EVENT_OPERATION_LEDGER_V3, EventOperationLedgerRecord, EventOperationStats,
            encode_event_operation_ledger_record, write_event_operation_stats,
        };
        let encoded = encode_event_operation_ledger_record(EventOperationLedgerRecord::Retired {
            intent_digest: [0x75; 32],
            reason: CustodyRetirementReason::Expired,
        });
        write
            .open_table(EVENT_OPERATION_LEDGER_V3)
            .expect("legacy ledger")
            .insert([0x76; 32].as_slice(), encoded.as_slice())
            .expect("legacy row");
        write_event_operation_stats(
            &mut write.open_table(METADATA).expect("metadata"),
            EventOperationStats {
                records_total: 1,
                records_retired: 1,
                logical_bytes: 67,
                ..EventOperationStats::default()
            },
        )
        .expect("legacy accounting");
    }

    fn assert_invariant(error: &StoreError, message: &'static str) {
        assert_eq!(
            numbered_error(error),
            Some(&NumberedEventOperationError::Invariant(message))
        );
    }

    fn assert_reopen_and_inspect_invariant(file: &CorruptionFile, message: &'static str) {
        assert_invariant(&file.inspect_error(), message);
        assert_invariant(&file.reopen_error(), message);
    }

    #[test]
    fn live_claim_rejects_unknown_mode_without_repairing_marker() {
        let file = CorruptionFile::new("live-unknown-mode");
        let store = file.open();
        let write = store.database.begin_write().expect("write");
        write
            .open_table(METADATA)
            .expect("metadata")
            .insert(MODE, 2)
            .expect("unknown mode");
        write.commit().expect("commit");

        let client = EventClientId::new(b"live-corrupt-client".to_vec()).expect("client");
        assert_invariant(
            &store
                .begin_event_publication_session(&client, 0, b"claim")
                .expect_err("unknown mode must fail"),
            "numbered Event operation mode is unknown",
        );
        let read = store.database.begin_read().expect("read");
        assert_eq!(
            read.open_table(METADATA)
                .expect("metadata")
                .get(MODE)
                .expect("mode read")
                .map(|value| value.value()),
            Some(2)
        );
    }

    #[test]
    fn reopen_rejects_numbered_client_table_above_fixed_limit() {
        let file = CorruptionFile::new("client-overflow");
        let store = file.open();
        fixture_client(&store);
        let write = store.database.begin_write().expect("write");
        let mut stats = read_stats_write(&write).expect("stats");
        let record = ClientRecord {
            session: 1,
            allocated_through: 0,
            snapshot_revision: 1,
            completed_session: 0,
            completed_revision: 0,
            last_claim_expected: 0,
            last_claim_digest: [0x78; 32],
        };
        for index in 0..MAX_NUMBERED_EVENT_CLIENTS {
            let client = EventClientId::new(format!("overflow-client-{index}").into_bytes())
                .expect("client");
            write
                .open_table(CLIENTS)
                .expect("clients")
                .insert(client.as_bytes(), encode_client(record).as_slice())
                .expect("insert client");
            stats.clients += 1;
            stats.logical_bytes += (client.as_bytes().len() + 81) as u64;
        }
        write_stats(&write, stats).expect("exact accounting");
        write.commit().expect("commit");
        drop(store);
        assert_reopen_and_inspect_invariant(
            &file,
            "numbered Event client table exceeds its client limit",
        );
    }

    #[test]
    fn reopen_rejects_explicit_zero_accounting_over_numbered_rows() {
        let file = CorruptionFile::new("zero-accounting");
        let store = file.open();
        fixture_client(&store);
        let write = store.database.begin_write().expect("write");
        write_stats(&write, NumberedEventOperationStats::default()).expect("zero accounting");
        write.commit().expect("commit");
        drop(store);
        assert_reopen_and_inspect_invariant(
            &file,
            "numbered Event operation accounting differs from table truth",
        );
    }

    #[test]
    fn reopen_rejects_partial_numbered_accounting_group() {
        let file = CorruptionFile::new("partial-accounting");
        let store = file.open();
        fixture_client(&store);
        let write = store.database.begin_write().expect("write");
        write
            .open_table(METADATA)
            .expect("metadata")
            .remove(REVERSE_COUNT)
            .expect("remove counter");
        write.commit().expect("commit");
        drop(store);
        assert_reopen_and_inspect_invariant(
            &file,
            "numbered Event operation accounting group is incomplete",
        );
    }

    #[test]
    fn reopen_rejects_numbered_rows_without_mode() {
        let file = CorruptionFile::new("missing-mode");
        let store = file.open();
        fixture_client(&store);
        let write = store.database.begin_write().expect("write");
        write
            .open_table(METADATA)
            .expect("metadata")
            .remove(MODE)
            .expect("remove mode");
        write.commit().expect("commit");
        drop(store);
        assert_reopen_and_inspect_invariant(&file, "numbered Event rows lack numbered mode");
    }

    #[test]
    fn reopen_and_legacy_write_reject_unknown_mode() {
        let file = CorruptionFile::new("unknown-mode");
        let store = file.open();
        let write = store.database.begin_write().expect("write");
        write
            .open_table(METADATA)
            .expect("metadata")
            .insert(MODE, 2)
            .expect("unknown mode");
        assert_invariant(
            &legacy_operation_allowed_write(&write).expect_err("legacy write must reject"),
            "numbered Event operation mode is unknown",
        );
        write.commit().expect("commit");
        drop(store);
        assert_reopen_and_inspect_invariant(&file, "numbered Event operation mode is unknown");
    }

    #[test]
    fn reopen_rejects_mixed_ledgers_for_every_mode_marker() {
        for marker in [None, Some(1), Some(2)] {
            let file = CorruptionFile::new("mixed-ledgers");
            let store = file.open();
            fixture_client(&store);
            let write = store.database.begin_write().expect("write");
            fixture_legacy_row(&write);
            {
                let mut metadata = write.open_table(METADATA).expect("metadata");
                match marker {
                    Some(value) => {
                        metadata.insert(MODE, value).expect("mode");
                    }
                    None => {
                        metadata.remove(MODE).expect("remove mode");
                    }
                }
            }
            write.commit().expect("commit");
            drop(store);
            for error in [file.inspect_error(), file.reopen_error()] {
                assert_eq!(
                    numbered_error(&error),
                    Some(&NumberedEventOperationError::LegacyStoreRequiresFreshState),
                    "marker {marker:?}"
                );
            }
        }
    }

    #[test]
    fn reopen_rejects_result_without_client_owner() {
        let file = CorruptionFile::new("missing-owner");
        let store = file.open();
        let client = fixture_client(&store);
        let write = store.database.begin_write().expect("write");
        fixture_results(&write, &client, 1, 1);
        write
            .open_table(CLIENTS)
            .expect("clients")
            .remove(client.as_bytes())
            .expect("remove");
        let mut stats = read_stats_write(&write).expect("stats");
        stats.clients = 0;
        stats.logical_bytes -= client.as_bytes().len() as u64 + 81;
        write_stats(&write, stats).expect("accounting");
        write.commit().expect("commit");
        drop(store);
        assert_reopen_and_inspect_invariant(&file, "numbered Event result has no client");
    }

    #[test]
    fn reopen_rejects_result_beyond_client_frontier() {
        let file = CorruptionFile::new("beyond-frontier");
        let store = file.open();
        let client = fixture_client(&store);
        let write = store.database.begin_write().expect("write");
        fixture_results(&write, &client, 1, 0);
        write.commit().expect("commit");
        drop(store);
        assert_reopen_and_inspect_invariant(&file, "numbered Event result exceeds client frontier");
    }

    #[test]
    fn reopen_rejects_client_result_overflow() {
        let file = CorruptionFile::new("result-overflow");
        let store = file.open();
        let client = fixture_client(&store);
        let write = store.database.begin_write().expect("write");
        fixture_results(
            &write,
            &client,
            MAX_OUTSTANDING_EVENT_RESULTS_PER_CLIENT + 1,
            MAX_OUTSTANDING_EVENT_RESULTS_PER_CLIENT + 1,
        );
        write.commit().expect("commit");
        drop(store);
        assert_reopen_and_inspect_invariant(
            &file,
            "client exceeds its outstanding numbered Event result limit",
        );
    }

    #[test]
    fn reopen_rejects_result_with_wrong_reverse_prefix_only() {
        let file = CorruptionFile::new("wrong-reverse-only");
        let store = file.open();
        let client = fixture_client(&store);
        let write = store.database.begin_write().expect("write");
        fixture_results(&write, &client, 1, 1);
        let sequence = EventOperationSequence::new(1).expect("sequence");
        let correct = reverse_key(EventTransferId::new([0x72; 32]), &client, sequence);
        let wrong = reverse_key(EventTransferId::new([0x77; 32]), &client, sequence);
        write
            .open_table(RESULT_BY_EVENT)
            .expect("reverse")
            .remove(correct.as_slice())
            .expect("remove");
        write
            .open_table(RESULT_BY_EVENT)
            .expect("reverse")
            .insert(wrong.as_slice(), &[][..])
            .expect("insert");
        write.commit().expect("commit");
        drop(store);
        assert_reopen_and_inspect_invariant(
            &file,
            "numbered Event result is missing its reverse edge",
        );
    }

    #[test]
    fn reopen_rejects_reverse_prefix_different_from_receipt() {
        let file = CorruptionFile::new("wrong-reverse-extra");
        let store = file.open();
        let client = fixture_client(&store);
        let write = store.database.begin_write().expect("write");
        fixture_results(&write, &client, 1, 1);
        let wrong = reverse_key(
            EventTransferId::new([0x77; 32]),
            &client,
            EventOperationSequence::new(1).expect("sequence"),
        );
        write
            .open_table(RESULT_BY_EVENT)
            .expect("reverse")
            .insert(wrong.as_slice(), &[][..])
            .expect("insert");
        let mut stats = read_stats_write(&write).expect("stats");
        stats.reverse_edges += 1;
        stats.logical_bytes += wrong.len() as u64;
        write_stats(&write, stats).expect("accounting");
        write.commit().expect("commit");
        drop(store);
        assert_reopen_and_inspect_invariant(
            &file,
            "numbered Event reverse edge targets another Event",
        );
    }

    #[test]
    fn reopen_and_inspection_reject_nonempty_numbered_reverse_value() {
        let file = CorruptionFile::new("nonempty-reverse");
        let store = file.open();
        let client = fixture_client(&store);
        let write = store.database.begin_write().expect("write");
        fixture_results(&write, &client, 1, 1);
        let reverse = reverse_key(
            EventTransferId::new([0x72; 32]),
            &client,
            EventOperationSequence::new(1).expect("sequence"),
        );
        write
            .open_table(RESULT_BY_EVENT)
            .expect("reverse")
            .insert(reverse.as_slice(), &[1][..])
            .expect("replace reverse value");
        write.commit().expect("commit");
        drop(store);
        assert_reopen_and_inspect_invariant(&file, "numbered Event reverse value is not empty");
    }

    #[test]
    fn reopen_and_inspection_reject_orphaned_numbered_reverse_edge() {
        let file = CorruptionFile::new("orphaned-reverse");
        let store = file.open();
        let client = fixture_client(&store);
        let write = store.database.begin_write().expect("write");
        fixture_results(&write, &client, 1, 1);
        let orphan = reverse_key(
            EventTransferId::new([0x72; 32]),
            &client,
            EventOperationSequence::new(2).expect("sequence"),
        );
        write
            .open_table(RESULT_BY_EVENT)
            .expect("reverse")
            .insert(orphan.as_slice(), &[][..])
            .expect("insert orphaned reverse");
        let mut stats = read_stats_write(&write).expect("stats");
        stats.reverse_edges += 1;
        stats.logical_bytes += orphan.len() as u64;
        write_stats(&write, stats).expect("accounting");
        write.commit().expect("commit");
        drop(store);
        assert_reopen_and_inspect_invariant(&file, "numbered Event reverse edge is orphaned");
    }

    fn store_path(name: &str) -> std::path::PathBuf {
        std::env::temp_dir().join(format!(
            "aster-numbered-operations-{name}-{}-{:?}.redb",
            std::process::id(),
            std::thread::current().id()
        ))
    }

    fn numbered_error(error: &StoreError) -> Option<&NumberedEventOperationError> {
        match error {
            StoreError::NumberedEventOperation(error) => Some(error),
            _ => None,
        }
    }

    #[test]
    fn sessions_are_independent_restart_safe_and_fence_stale_mutations() {
        let path = store_path("sessions");
        let _ = std::fs::remove_file(&path);
        let mission = [0x42; 32];
        let first = EventClientId::new(b"publisher-a".to_vec()).expect("client");
        let second = EventClientId::new(b"publisher-b".to_vec()).expect("client");
        let first_session;
        {
            let store = Store::open_for_mission(&path, mission).expect("store");
            let claimed = store
                .begin_event_publication_session(&first, 0, b"first-claim")
                .expect("first claim");
            first_session = claimed.session;
            assert_eq!(claimed.allocated_through, 0);
            assert_eq!(
                store
                    .begin_event_publication_session(&first, 0, b"first-claim")
                    .expect("idempotent claim")
                    .session,
                first_session
            );
            let competing = store
                .begin_event_publication_session(&first, 0, b"different-claim")
                .expect_err("stale CAS");
            assert_eq!(
                numbered_error(&competing),
                Some(&NumberedEventOperationError::SessionFenced)
            );
            let second_claim = store
                .begin_event_publication_session(&second, 0, b"second-claim")
                .expect("independent client");
            assert_eq!(second_claim.session.get(), 1);
            assert_eq!(
                store
                    .numbered_event_operation_stats()
                    .expect("stats")
                    .clients,
                2
            );
        }
        {
            let store = Store::open_for_mission(&path, mission).expect("reopen");
            let takeover = store
                .begin_event_publication_session(&first, first_session.get(), b"takeover")
                .expect("takeover");
            assert_eq!(takeover.session.get(), first_session.get() + 1);
            let before_recovery = store
                .abandon_event_publication(
                    &first,
                    takeover.session,
                    EventOperationSequence::new(1).expect("sequence"),
                )
                .expect_err("recovery gate");
            assert_eq!(
                numbered_error(&before_recovery),
                Some(&NumberedEventOperationError::RecoveryRequired)
            );
            store
                .complete_event_publication_recovery(
                    &first,
                    takeover.session,
                    takeover.snapshot_revision,
                )
                .expect("complete recovery");
            store
                .complete_event_publication_recovery(
                    &first,
                    takeover.session,
                    takeover.snapshot_revision,
                )
                .expect("idempotent completion");
            let stale = store
                .abandon_event_publication(
                    &first,
                    first_session,
                    EventOperationSequence::new(1).expect("sequence"),
                )
                .expect_err("stale mutation");
            assert_eq!(
                numbered_error(&stale),
                Some(&NumberedEventOperationError::SessionFenced)
            );
            assert_eq!(
                store
                    .abandon_event_publication(
                        &first,
                        takeover.session,
                        EventOperationSequence::new(1).expect("sequence"),
                    )
                    .expect("abandon"),
                EventOperationAbandonment::Abandoned
            );
            assert_eq!(
                store
                    .abandon_event_publication(
                        &first,
                        takeover.session,
                        EventOperationSequence::new(1).expect("sequence"),
                    )
                    .expect("idempotent abandon"),
                EventOperationAbandonment::AlreadyAbandoned
            );
            let gap = store
                .abandon_event_publication(
                    &first,
                    takeover.session,
                    EventOperationSequence::new(3).expect("sequence"),
                )
                .expect_err("gap");
            assert_eq!(
                numbered_error(&gap),
                Some(&NumberedEventOperationError::SequenceGap)
            );
        }
        std::fs::remove_file(path).expect("remove store");
    }

    #[test]
    fn maximum_outstanding_snapshot_fits_the_two_mib_wire_limit() {
        let result = NumberedEventResult {
            sequence: EventOperationSequence::new(u64::MAX).expect("sequence"),
            receipt: CommittedEventReceipt {
                transfer_id: EventTransferId::new([0xff; 32]),
                semantic_id: EventSemanticId::new([0xff; 32]),
                acceptance_marker: u64::MAX,
            },
            content: CommittedEventContent::Retired(CustodyRetirementReason::Expired),
        };
        let snapshot = EventRecoverySnapshot {
            session: EventPublicationSession::new(u64::MAX).expect("session"),
            allocated_through: u64::MAX,
            snapshot_revision: u64::MAX,
            outstanding: vec![result; MAX_OUTSTANDING_EVENT_RESULTS_PER_CLIENT as usize],
        };
        assert!(
            recovery_snapshot_proto_len(&snapshot) <= MAX_EVENT_RECOVERY_SNAPSHOT_PROTO_BYTES,
            "the fixed per-client record cap must fit one recovery response"
        );
    }
}
