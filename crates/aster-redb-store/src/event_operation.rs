use crate::{
    CustodyRetirementReason, EVENT_OPERATION_COUNT, EVENT_OPERATION_TOTAL_BYTES,
    EVENT_OPERATION_WITNESSES, EVENT_OPERATIONS, EVENT_TOMBSTONE_OPERATION_COUNT,
    EVENT_TOMBSTONE_OPERATION_TOTAL_BYTES, EVENTS, EventTransferId, MAX_EVENT_OPERATION_KEY_BYTES,
    MAX_EVENT_OPERATIONS, METADATA, StoreError, custody, decode_event_metadata,
    decode_operation_record, event_operation_intent_digest, event_operation_intent_from_header,
    event_operation_witness_write, read_mission_binding,
};
use redb::{
    MultimapTableHandle, ReadableDatabase, ReadableTable, ReadableTableMetadata, TableDefinition,
    TableHandle,
};
use sha2::{Digest, Sha256};

pub(crate) const EVENT_OPERATION_LEDGER_V3: TableDefinition<&[u8], &[u8]> =
    TableDefinition::new("aster.event-operation-ledger.v3");
pub(crate) const ACTIVE_OPERATION_BY_EVENT_V1: TableDefinition<&[u8], &[u8]> =
    TableDefinition::new("aster.active-operation-by-event.v1");

pub(crate) const EVENT_OPERATION_RECORDS_TOTAL: &str = "semantic_event_operation_v3_records_total";
pub(crate) const EVENT_OPERATION_RECORDS_ACTIVE: &str =
    "semantic_event_operation_v3_records_active";
pub(crate) const EVENT_OPERATION_RECORDS_RETIRED: &str =
    "semantic_event_operation_v3_records_retired";
pub(crate) const EVENT_OPERATION_REVERSE_ROWS: &str = "semantic_event_operation_v3_reverse_rows";
pub(crate) const EVENT_OPERATION_LOGICAL_BYTES: &str = "semantic_event_operation_v3_logical_bytes";
const EVENT_OPERATION_ACCOUNTING_FIELDS: [&str; 5] = [
    EVENT_OPERATION_RECORDS_TOTAL,
    EVENT_OPERATION_RECORDS_ACTIVE,
    EVENT_OPERATION_RECORDS_RETIRED,
    EVENT_OPERATION_REVERSE_ROWS,
    EVENT_OPERATION_LOGICAL_BYTES,
];

pub(crate) const EVENT_OPERATION_ACTIVE_LOGICAL_BYTES: u64 = 98;
pub(crate) const EVENT_OPERATION_RETIRED_LOGICAL_BYTES: u64 = 67;
pub(crate) const ACTIVE_OPERATION_BY_EVENT_LOGICAL_BYTES: u64 = 64;
const EVENT_OPERATION_EMERGENCY_RECORD_LOGICAL_BYTES: u64 =
    EVENT_OPERATION_ACTIVE_LOGICAL_BYTES + ACTIVE_OPERATION_BY_EVENT_LOGICAL_BYTES;
const EVENT_OPERATION_LEDGER_VERSION: u8 = 1;
const EVENT_OPERATION_LEDGER_ACTIVE: u8 = 1;
const EVENT_OPERATION_LEDGER_RETIRED: u8 = 2;
const EVENT_OPERATION_KEY_DOMAIN: &[u8] = b"aster/event-operation-key/v1";

/// Maximum distinct active operation keys that may refer to one Event.
pub const MAX_EVENT_OPERATION_ALIASES: u64 = 64;

/// Lifecycle of one complete, snapshot-consistent operation ledger audit.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum EventOperationAuditState {
    #[default]
    Pending,
    Running,
    Complete,
    Failed,
}

/// Sanitized actor-owned audit observation; counts include both table passes.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct EventOperationAuditStatus {
    pub state: EventOperationAuditState,
    pub scanned: u64,
    pub total: u64,
}

/// Validated traversal rows (ledger plus reverse index) in one fixed snapshot.
/// `total` never changes within a run. `scanned == total` is only a traversal
/// observation: success also requires the final accounting checks to pass.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct EventOperationAuditProgress {
    pub scanned: u64,
    pub total: u64,
}

impl crate::Store {
    /// Audits every v3 operation and reverse row using ONE consistent read
    /// snapshot. Concurrent commits belong to the next run. Callbacks occur
    /// initially and after at most `min(page_size, 1024)` traversal rows, without
    /// collecting a ledger-sized image. A zero page size is invalid.
    /// Admission quotas do not invalidate retained rows after a lower-limit
    /// reopen; this audit verifies structure and accounting independently.
    pub fn audit_event_operations<F>(
        &self,
        page_size: usize,
        on_progress: F,
    ) -> Result<EventOperationAuditProgress, StoreError>
    where
        F: FnMut(EventOperationAuditProgress),
    {
        self.audit_event_operations_cancellable(page_size, on_progress, || false)
    }

    /// The same complete audit, with cooperative cancellation at each page
    /// boundary. Cancellation returns `EventOperationAuditCancelled`, never a
    /// successful partial result, and drops the snapshot before returning.
    pub fn audit_event_operations_cancellable<F, C>(
        &self,
        page_size: usize,
        on_progress: F,
        is_cancelled: C,
    ) -> Result<EventOperationAuditProgress, StoreError>
    where
        F: FnMut(EventOperationAuditProgress),
        C: FnMut() -> bool,
    {
        let read = self.database.begin_read()?;
        audit_event_operations_read(&read, page_size, on_progress, is_cancelled)
    }

    /// Offline complete operation audit of an existing v3 store. This uses a
    /// read-only redb handle and never creates, migrates, repairs, or reopens a
    /// writer. Run the ordinary inspection separately for other schema groups.
    /// This checks integrity, not qualification against an admission quota.
    pub fn audit_existing_event_operations<F>(
        path: impl AsRef<std::path::Path>,
        page_size: usize,
        on_progress: F,
    ) -> Result<EventOperationAuditProgress, StoreError>
    where
        F: FnMut(EventOperationAuditProgress),
    {
        let path = std::path::absolute(path).map_err(StoreError::StorePath)?;
        let before = crate::open_read_only_store_backing(&path)?.identity;
        let database = redb::Builder::new().open_read_only(&path)?;
        if before != crate::open_read_only_store_backing(&path)?.identity {
            return Err(StoreError::StoreBackingInvariant(
                "backing path changed during read-only audit",
            ));
        }
        let read = database.begin_read()?;
        audit_event_operations_read(&read, page_size, on_progress, || false)
    }
}

fn audit_event_operations_read<F, C>(
    read: &redb::ReadTransaction,
    page_size: usize,
    mut on_progress: F,
    mut is_cancelled: C,
) -> Result<EventOperationAuditProgress, StoreError>
where
    F: FnMut(EventOperationAuditProgress),
    C: FnMut() -> bool,
{
    if page_size == 0 {
        return Err(StoreError::SemanticInvariant(
            "Event operation audit page size is zero",
        ));
    }
    let page_size = page_size.min(1_024) as u64;
    if crate::read_mission_binding_read(read)?.is_none() {
        return Err(StoreError::EventOperationMigrationMissingMissionBinding);
    }
    let stats = inspect_event_operation_accounting_read(read)?;
    // Opening both tables also rejects a wholly absent v3 schema: an offline
    // complete audit must not silently claim to have audited a legacy ledger.
    let ledger = read.open_table(EVENT_OPERATION_LEDGER_V3)?;
    let reverse = read.open_table(ACTIVE_OPERATION_BY_EVENT_V1)?;
    if read.open_table(EVENT_OPERATIONS)?.len()? != 0
        || read.open_table(EVENT_OPERATION_WITNESSES)?.len()? != 0
    {
        return Err(StoreError::SemanticInvariant(
            "Event operation ledger coexists with legacy rows",
        ));
    }
    let mut progress = EventOperationAuditProgress {
        scanned: 0,
        total: stats
            .records_total
            .checked_add(stats.reverse_rows)
            .ok_or(StoreError::ItemCountAccountingOverflow)?,
    };
    let mut checkpoint = |progress| {
        on_progress(progress);
        if is_cancelled() {
            Err(StoreError::EventOperationAuditCancelled)
        } else {
            Ok(())
        }
    };
    checkpoint(progress)?;
    let mut actual = EventOperationStats::default();
    for row in ledger.iter()? {
        let (key, value) = row?;
        let fingerprint: EventOperationFingerprint = key.value().try_into().map_err(|_| {
            StoreError::SemanticInvariant("invalid Event operation fingerprint length")
        })?;
        match decode_event_operation_ledger_record(value.value())? {
            EventOperationLedgerRecord::Active { transfer_id, .. } => {
                let key = encode_active_operation_by_event_key(transfer_id, fingerprint);
                let edge = reverse
                    .get(key.as_slice())?
                    .ok_or(StoreError::SemanticInvariant(
                        "active Event operation is missing its reverse edge",
                    ))?;
                if !edge.value().is_empty() {
                    return Err(StoreError::SemanticInvariant(
                        "Event operation reverse value is not empty",
                    ));
                }
                let event = crate::load_event_from_read(read, transfer_id)?.ok_or(
                    StoreError::SemanticInvariant(
                        "active Event operation is missing its retained Event",
                    ),
                )?;
                if event.acceptance_marker == 0
                    || read
                        .open_table(crate::SEMANTIC_ITEMS)?
                        .get(event.semantic_id.as_bytes().as_slice())?
                        .is_none_or(|value| value.value() != transfer_id.as_bytes())
                {
                    return Err(StoreError::SemanticInvariant(
                        "active Event operation has an inconsistent Event relationship",
                    ));
                }
                actual.records_active += 1;
            }
            EventOperationLedgerRecord::Retired { .. } => actual.records_retired += 1,
        }
        actual.records_total += 1;
        progress.scanned += 1;
        if progress.scanned.is_multiple_of(page_size) {
            checkpoint(progress)?;
        }
    }
    // Every reverse row must name its exact active ledger record. Together
    // with the first pass, this proves that retired rows have NO reverse edge
    // without either O(n²) per-retired scans or O(n) auxiliary memory.
    let mut previous_event = None;
    let mut aliases = 0;
    for row in reverse.iter()? {
        let (key, value) = row?;
        let (transfer_id, fingerprint) = decode_active_operation_by_event_key(key.value())?;
        if !value.value().is_empty() {
            return Err(StoreError::SemanticInvariant(
                "Event operation reverse value is not empty",
            ));
        }
        let record = ledger
            .get(fingerprint.as_slice())?
            .ok_or(StoreError::SemanticInvariant(
                "Event operation reverse target is missing",
            ))?;
        if !matches!(decode_event_operation_ledger_record(record.value())?, EventOperationLedgerRecord::Active { transfer_id: target, .. } if target == transfer_id)
        {
            return Err(StoreError::SemanticInvariant(
                "Event operation reverse target is not the exact active record",
            ));
        }
        aliases = if previous_event == Some(transfer_id) {
            aliases + 1
        } else {
            1
        };
        previous_event = Some(transfer_id);
        if aliases > MAX_EVENT_OPERATION_ALIASES {
            return Err(StoreError::SemanticInvariant(
                "Event operation audit exceeds the alias limit",
            ));
        }
        actual.reverse_rows += 1;
        progress.scanned += 1;
        if progress.scanned.is_multiple_of(page_size) {
            checkpoint(progress)?;
        }
    }
    actual.logical_bytes = checked_event_operation_logical_bytes(
        actual.records_active,
        actual.records_retired,
        actual.reverse_rows,
    )?;
    validate_event_operation_stats(actual)?;
    for (field, durable, reconstructed) in [
        (
            EVENT_OPERATION_RECORDS_TOTAL,
            stats.records_total,
            actual.records_total,
        ),
        (
            EVENT_OPERATION_RECORDS_ACTIVE,
            stats.records_active,
            actual.records_active,
        ),
        (
            EVENT_OPERATION_RECORDS_RETIRED,
            stats.records_retired,
            actual.records_retired,
        ),
        (
            EVENT_OPERATION_REVERSE_ROWS,
            stats.reverse_rows,
            actual.reverse_rows,
        ),
        (
            EVENT_OPERATION_LOGICAL_BYTES,
            stats.logical_bytes,
            actual.logical_bytes,
        ),
    ] {
        if durable != reconstructed {
            return Err(StoreError::AccountingMismatch {
                field,
                durable,
                reconstructed,
            });
        }
    }
    if !progress.scanned.is_multiple_of(page_size) {
        checkpoint(progress)?;
    }
    Ok(progress)
}

/// Exact logical usage of the permanent mission-bound Event operation ledger.
///
/// Logical bytes include each ledger key and value plus active reverse-index
/// keys. They intentionally exclude redb and filesystem amplification.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct EventOperationStats {
    /// Permanent active plus retired operation records.
    pub records_total: u64,
    /// Active records that still resolve to retained Events.
    pub records_active: u64,
    /// Permanent compact fences for retired Events.
    pub records_retired: u64,
    /// Active reverse-index rows; exactly one per active record.
    pub reverse_rows: u64,
    /// Exact fixed-size ledger plus reverse-index logical bytes.
    pub logical_bytes: u64,
}

/// A bounded, application-defined idempotency key for one local Event operation.
///
/// Its mission-bound fingerprint permanently names one publication intent. A caller
/// should namespace the bytes by application and operation kind. Reactive work
/// can append the authenticated predecessor's semantic item identifier.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct EventOperationKey(Vec<u8>);

impl EventOperationKey {
    /// Validates a nonempty bounded operation key.
    pub fn new(bytes: impl Into<Vec<u8>>) -> Result<Self, StoreError> {
        let bytes = bytes.into();
        if bytes.is_empty() || bytes.len() > MAX_EVENT_OPERATION_KEY_BYTES {
            return Err(StoreError::InvalidEventOperationKey {
                length: bytes.len(),
            });
        }
        Ok(Self(bytes))
    }

    /// Returns the exact caller-provided key bytes; durable records store only a fingerprint.
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct EventOperationLimits {
    max_records: u64,
    max_logical_bytes: u64,
    emergency_reserve: u64,
}

impl EventOperationLimits {
    pub const DEFAULT: Self = Self {
        max_records: 1_000_000,
        max_logical_bytes: 201_326_592,
        emergency_reserve: 10_000,
    };

    pub fn new(
        max_records: u64,
        max_logical_bytes: u64,
        emergency_reserve: u64,
    ) -> Result<Self, StoreError> {
        if max_records == 0 || max_logical_bytes == 0 || emergency_reserve == 0 {
            return Err(StoreError::SemanticInvariant(
                "Event operation limits must be nonzero",
            ));
        }
        if emergency_reserve >= max_records {
            return Err(StoreError::SemanticInvariant(
                "Event operation emergency reserve must be below the record limit",
            ));
        }
        let required_emergency_bytes = emergency_reserve
            .checked_mul(EVENT_OPERATION_EMERGENCY_RECORD_LOGICAL_BYTES)
            .ok_or(StoreError::PayloadByteAccountingOverflow)?;
        if max_logical_bytes < required_emergency_bytes {
            return Err(StoreError::SemanticInvariant(
                "Event operation byte limit cannot retain the emergency reserve",
            ));
        }
        Ok(Self {
            max_records,
            max_logical_bytes,
            emergency_reserve,
        })
    }

    pub const fn max_records(self) -> u64 {
        self.max_records
    }

    pub const fn max_logical_bytes(self) -> u64 {
        self.max_logical_bytes
    }

    pub const fn emergency_reserve(self) -> u64 {
        self.emergency_reserve
    }

    pub const fn ordinary_record_limit(self) -> u64 {
        self.max_records - self.emergency_reserve
    }

    pub const fn emergency_byte_reserve(self) -> u64 {
        self.emergency_reserve * EVENT_OPERATION_EMERGENCY_RECORD_LOGICAL_BYTES
    }
}

pub(crate) type EventOperationFingerprint = [u8; 32];

#[cfg(test)]
thread_local! {
    pub(crate) static MIGRATION_TEST_FAULT: std::cell::Cell<u8> = const { std::cell::Cell::new(0) };
    pub(crate) static RETIREMENT_TEST_FAULT: std::cell::Cell<u8> = const { std::cell::Cell::new(0) };
}

#[cfg(test)]
pub(crate) fn retirement_test_fault(point: u8) -> Result<(), StoreError> {
    if RETIREMENT_TEST_FAULT.get() == point {
        return Err(StoreError::SemanticInvariant(
            "injected Event operation retirement failure",
        ));
    }
    Ok(())
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum EventOperationLedgerRecord {
    Active {
        intent_digest: [u8; 32],
        transfer_id: EventTransferId,
    },
    Retired {
        intent_digest: [u8; 32],
        reason: CustodyRetirementReason,
    },
}

pub(crate) fn event_operation_fingerprint(
    mission_authority: &[u8; 32],
    operation: &EventOperationKey,
) -> EventOperationFingerprint {
    let mut digest = Sha256::new();
    digest.update(EVENT_OPERATION_KEY_DOMAIN);
    digest.update(mission_authority);
    digest.update(
        u16::try_from(operation.as_bytes().len())
            .expect("EventOperationKey is bounded to u16 length")
            .to_be_bytes(),
    );
    digest.update(operation.as_bytes());
    digest.finalize().into()
}

pub(crate) fn encode_event_operation_ledger_record(record: EventOperationLedgerRecord) -> Vec<u8> {
    match record {
        EventOperationLedgerRecord::Active {
            intent_digest,
            transfer_id,
        } => {
            let mut encoded = Vec::with_capacity(66);
            encoded.extend_from_slice(&[
                EVENT_OPERATION_LEDGER_VERSION,
                EVENT_OPERATION_LEDGER_ACTIVE,
            ]);
            encoded.extend_from_slice(&intent_digest);
            encoded.extend_from_slice(transfer_id.as_bytes());
            encoded
        }
        EventOperationLedgerRecord::Retired {
            intent_digest,
            reason,
        } => {
            let mut encoded = Vec::with_capacity(35);
            encoded.extend_from_slice(&[
                EVENT_OPERATION_LEDGER_VERSION,
                EVENT_OPERATION_LEDGER_RETIRED,
            ]);
            encoded.extend_from_slice(&intent_digest);
            encoded.push(reason as u8);
            encoded
        }
    }
}

pub(crate) fn decode_event_operation_ledger_record(
    bytes: &[u8],
) -> Result<EventOperationLedgerRecord, StoreError> {
    let Some((&version, rest)) = bytes.split_first() else {
        return Err(StoreError::SemanticInvariant(
            "missing Event operation ledger version",
        ));
    };
    if version != EVENT_OPERATION_LEDGER_VERSION {
        return Err(StoreError::SemanticInvariant(
            "unknown Event operation ledger version",
        ));
    }
    let Some((&state, _)) = rest.split_first() else {
        return Err(StoreError::SemanticInvariant(
            "missing Event operation ledger state",
        ));
    };
    match state {
        EVENT_OPERATION_LEDGER_ACTIVE => {
            let encoded: &[u8; 66] = bytes.try_into().map_err(|_| {
                StoreError::SemanticInvariant("invalid active Event operation ledger length")
            })?;
            Ok(EventOperationLedgerRecord::Active {
                intent_digest: encoded[2..34]
                    .try_into()
                    .expect("fixed active Event operation intent slice"),
                transfer_id: EventTransferId::new(
                    encoded[34..66]
                        .try_into()
                        .expect("fixed active Event operation transfer slice"),
                ),
            })
        }
        EVENT_OPERATION_LEDGER_RETIRED => {
            let encoded: &[u8; 35] = bytes.try_into().map_err(|_| {
                StoreError::SemanticInvariant("invalid retired Event operation ledger length")
            })?;
            let reason = match encoded[34] {
                1 => CustodyRetirementReason::Expired,
                2 => CustodyRetirementReason::QuotaPressure,
                _ => {
                    return Err(StoreError::SemanticInvariant(
                        "unknown Event operation retirement reason",
                    ));
                }
            };
            Ok(EventOperationLedgerRecord::Retired {
                intent_digest: encoded[2..34]
                    .try_into()
                    .expect("fixed retired Event operation intent slice"),
                reason,
            })
        }
        _ => Err(StoreError::SemanticInvariant(
            "unknown Event operation ledger state",
        )),
    }
}

pub(crate) fn encode_active_operation_by_event_key(
    transfer_id: EventTransferId,
    fingerprint: EventOperationFingerprint,
) -> [u8; 64] {
    let mut encoded = [0u8; 64];
    encoded[..32].copy_from_slice(transfer_id.as_bytes());
    encoded[32..].copy_from_slice(&fingerprint);
    encoded
}

pub(crate) fn decode_active_operation_by_event_key(
    bytes: &[u8],
) -> Result<(EventTransferId, EventOperationFingerprint), StoreError> {
    let encoded: &[u8; 64] = bytes.try_into().map_err(|_| {
        StoreError::SemanticInvariant("invalid active Event operation reverse key length")
    })?;
    Ok((
        EventTransferId::new(
            encoded[..32]
                .try_into()
                .expect("fixed reverse Event operation transfer slice"),
        ),
        encoded[32..]
            .try_into()
            .expect("fixed reverse Event operation fingerprint slice"),
    ))
}

pub(crate) fn checked_event_operation_logical_bytes(
    active_records: u64,
    retired_records: u64,
    reverse_rows: u64,
) -> Result<u64, StoreError> {
    active_records
        .checked_mul(EVENT_OPERATION_ACTIVE_LOGICAL_BYTES)
        .and_then(|bytes| {
            retired_records
                .checked_mul(EVENT_OPERATION_RETIRED_LOGICAL_BYTES)
                .and_then(|retired_bytes| bytes.checked_add(retired_bytes))
        })
        .and_then(|bytes| {
            reverse_rows
                .checked_mul(ACTIVE_OPERATION_BY_EVENT_LOGICAL_BYTES)
                .and_then(|reverse_bytes| bytes.checked_add(reverse_bytes))
        })
        .ok_or(StoreError::PayloadByteAccountingOverflow)
}

pub(crate) fn validate_event_operation_stats(stats: EventOperationStats) -> Result<(), StoreError> {
    let reconstructed_total = stats
        .records_active
        .checked_add(stats.records_retired)
        .ok_or(StoreError::ItemCountAccountingOverflow)?;
    if stats.records_total != reconstructed_total {
        return Err(StoreError::AccountingMismatch {
            field: EVENT_OPERATION_RECORDS_TOTAL,
            durable: stats.records_total,
            reconstructed: reconstructed_total,
        });
    }
    if stats.reverse_rows != stats.records_active {
        return Err(StoreError::AccountingMismatch {
            field: EVENT_OPERATION_REVERSE_ROWS,
            durable: stats.reverse_rows,
            reconstructed: stats.records_active,
        });
    }
    let reconstructed_bytes = checked_event_operation_logical_bytes(
        stats.records_active,
        stats.records_retired,
        stats.reverse_rows,
    )?;
    if stats.logical_bytes != reconstructed_bytes {
        return Err(StoreError::AccountingMismatch {
            field: EVENT_OPERATION_LOGICAL_BYTES,
            durable: stats.logical_bytes,
            reconstructed: reconstructed_bytes,
        });
    }
    Ok(())
}

pub(crate) fn checked_admit_event_operation_record(
    current: EventOperationStats,
    limits: EventOperationLimits,
    emergency: bool,
) -> Result<EventOperationStats, StoreError> {
    checked_admit_event_operation_record_kind(current, limits, emergency, false)
}

fn checked_admit_event_operation_record_kind(
    current: EventOperationStats,
    limits: EventOperationLimits,
    emergency: bool,
    retired: bool,
) -> Result<EventOperationStats, StoreError> {
    validate_event_operation_stats(current)?;
    let record_limit = if emergency {
        limits.max_records()
    } else {
        limits.ordinary_record_limit()
    };
    let next_total = current
        .records_total
        .checked_add(1)
        .ok_or(StoreError::ItemCountAccountingOverflow)?;
    if next_total > record_limit {
        return Err(StoreError::EventOperationLimitExceeded {
            current: current.records_total,
            limit: record_limit,
        });
    }

    let byte_limit = if emergency {
        limits.max_logical_bytes()
    } else {
        limits
            .max_logical_bytes()
            .checked_sub(limits.emergency_byte_reserve())
            .ok_or(StoreError::PayloadByteAccountingOverflow)?
    };
    let incoming = if retired {
        EVENT_OPERATION_RETIRED_LOGICAL_BYTES
    } else {
        EVENT_OPERATION_EMERGENCY_RECORD_LOGICAL_BYTES
    };
    let next_bytes = current
        .logical_bytes
        .checked_add(incoming)
        .ok_or(StoreError::PayloadByteAccountingOverflow)?;
    if next_bytes > byte_limit {
        return Err(StoreError::EventOperationByteLimitExceeded {
            current: current.logical_bytes,
            incoming,
            limit: byte_limit,
        });
    }

    let next = EventOperationStats {
        records_total: next_total,
        records_active: current
            .records_active
            .checked_add(u64::from(!retired))
            .ok_or(StoreError::ItemCountAccountingOverflow)?,
        records_retired: current
            .records_retired
            .checked_add(u64::from(retired))
            .ok_or(StoreError::ItemCountAccountingOverflow)?,
        reverse_rows: current
            .reverse_rows
            .checked_add(u64::from(!retired))
            .ok_or(StoreError::ItemCountAccountingOverflow)?,
        logical_bytes: next_bytes,
    };
    validate_event_operation_stats(next)?;
    Ok(next)
}

pub(crate) fn checked_retire_event_operation_records(
    current: EventOperationStats,
    records: u64,
) -> Result<EventOperationStats, StoreError> {
    validate_event_operation_stats(current)?;
    let records_active =
        current
            .records_active
            .checked_sub(records)
            .ok_or(StoreError::SemanticInvariant(
                "Event operation active-record accounting underflow",
            ))?;
    let reverse_rows =
        current
            .reverse_rows
            .checked_sub(records)
            .ok_or(StoreError::SemanticInvariant(
                "Event operation reverse-row accounting underflow",
            ))?;
    let records_retired = current
        .records_retired
        .checked_add(records)
        .ok_or(StoreError::ItemCountAccountingOverflow)?;
    let logical_bytes =
        checked_event_operation_logical_bytes(records_active, records_retired, reverse_rows)?;
    let next = EventOperationStats {
        records_total: current.records_total,
        records_active,
        records_retired,
        reverse_rows,
        logical_bytes,
    };
    validate_event_operation_stats(next)?;
    Ok(next)
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct EventOperationRetirementDelta {
    pub(crate) records_retired: u64,
    pub(crate) logical_bytes_released: u64,
}

/// Only the ledger compaction boundary may label these otherwise shared
/// logical errors as operation-specific. Storage-engine errors must propagate
/// unchanged, even when the selected runtime has quarantined a failed audit.
pub(crate) fn classify_retirement_invariant(error: StoreError) -> StoreError {
    match error {
        StoreError::SemanticInvariant(_)
        | StoreError::AccountingMismatch { .. }
        | StoreError::MissingAccountingMetadata { .. }
        | StoreError::ItemCountAccountingOverflow
        | StoreError::PayloadByteAccountingOverflow => {
            StoreError::EventOperationRetirementInvariant(Box::new(error))
        }
        other => other,
    }
}

/// Compacts every alias in the final custody-retirement transaction. Validate
/// the entire bounded prefix and its accounting before changing any row; no
/// admission quota applies because conversion only releases logical bytes.
pub(crate) fn retire_event_operations_write(
    write: &redb::WriteTransaction,
    transfer_id: EventTransferId,
    reason: CustodyRetirementReason,
) -> Result<EventOperationRetirementDelta, StoreError> {
    let mut ledger = write.open_table(EVENT_OPERATION_LEDGER_V3)?;
    let mut reverse = write.open_table(ACTIVE_OPERATION_BY_EVENT_V1)?;
    let mut metadata = write.open_table(METADATA)?;
    let current = read_event_operation_stats(&metadata)?.ok_or(StoreError::SemanticInvariant(
        "Event operation accounting is missing during retirement",
    ))?;
    audit_event_operation_cardinalities(current, ledger.len()?, reverse.len()?)?;

    // Range the complete transfer prefix, including malformed short/long keys.
    // A fixed 64-byte lower/upper pair would silently omit such corrupt edges.
    let mut successor = *transfer_id.as_bytes();
    let upper = if let Some(index) = successor.iter().rposition(|byte| *byte != u8::MAX) {
        successor[index] += 1;
        successor[index + 1..].fill(0);
        std::ops::Bound::Excluded(successor.as_slice())
    } else {
        std::ops::Bound::Unbounded
    };
    let mut aliases = Vec::new();
    for row in reverse.range::<&[u8]>((
        std::ops::Bound::Included(transfer_id.as_bytes().as_slice()),
        upper,
    ))? {
        let (key, value) = row?;
        if aliases.len() == MAX_EVENT_OPERATION_ALIASES as usize {
            return Err(StoreError::SemanticInvariant(
                "Event operation retirement exceeds the alias cap",
            ));
        }
        let (indexed_transfer, fingerprint) = decode_active_operation_by_event_key(key.value())?;
        if indexed_transfer != transfer_id || !value.value().is_empty() {
            return Err(StoreError::SemanticInvariant(
                "Event operation retirement has an invalid reverse edge",
            ));
        }
        let record = ledger
            .get(fingerprint.as_slice())?
            .ok_or(StoreError::SemanticInvariant(
                "Event operation reverse edge has no ledger target",
            ))?;
        let EventOperationLedgerRecord::Active {
            intent_digest,
            transfer_id: target,
        } = decode_event_operation_ledger_record(record.value())?
        else {
            return Err(StoreError::SemanticInvariant(
                "retired Event operation still has a reverse edge",
            ));
        };
        if target != transfer_id {
            return Err(StoreError::SemanticInvariant(
                "Event operation reverse edge targets a different Event",
            ));
        }
        aliases.push((fingerprint, intent_digest));
    }
    let records_retired = aliases.len() as u64; // Bounded above by 64.
    let next = checked_retire_event_operation_records(current, records_retired)?;
    let logical_bytes_released = current
        .logical_bytes
        .checked_sub(next.logical_bytes)
        .ok_or(StoreError::PayloadByteAccountingOverflow)?;
    #[cfg(test)]
    retirement_test_fault(1)?;
    for (fingerprint, intent_digest) in aliases {
        let retired = encode_event_operation_ledger_record(EventOperationLedgerRecord::Retired {
            intent_digest,
            reason,
        });
        ledger.insert(fingerprint.as_slice(), retired.as_slice())?;
        let key = encode_active_operation_by_event_key(transfer_id, fingerprint);
        if reverse.remove(key.as_slice())?.is_none() {
            return Err(StoreError::SemanticInvariant(
                "Event operation reverse edge disappeared during retirement",
            ));
        }
        #[cfg(test)]
        retirement_test_fault(2)?;
    }
    write_event_operation_stats(&mut metadata, next)?;
    #[cfg(test)]
    retirement_test_fault(3)?;
    Ok(EventOperationRetirementDelta {
        records_retired,
        logical_bytes_released,
    })
}

/// Adds one previously unseen operation and its bounded reverse edge in the
/// caller's Event transaction. No ordinary Event-storage quota is charged.
pub(crate) fn admit_active_event_operation_write(
    write: &redb::WriteTransaction,
    authority: &[u8; 32],
    operation: &EventOperationKey,
    intent_digest: [u8; 32],
    transfer_id: EventTransferId,
    limits: EventOperationLimits,
    emergency: bool,
) -> Result<(), StoreError> {
    let fingerprint = event_operation_fingerprint(authority, operation);
    let mut ledger = write.open_table(EVENT_OPERATION_LEDGER_V3)?;
    if ledger.get(fingerprint.as_slice())?.is_some() {
        return Err(StoreError::SemanticInvariant(
            "Event operation appeared during admission",
        ));
    }
    let mut reverse = write.open_table(ACTIVE_OPERATION_BY_EVENT_V1)?;
    let lower = encode_active_operation_by_event_key(transfer_id, [0; 32]);
    let upper = encode_active_operation_by_event_key(transfer_id, [u8::MAX; 32]);
    let mut aliases = 0u64;
    for row in reverse.range(lower.as_slice()..=upper.as_slice())? {
        let (key, value) = row?;
        decode_active_operation_by_event_key(key.value())?;
        if !value.value().is_empty() {
            return Err(StoreError::SemanticInvariant(
                "Event operation reverse value is not empty",
            ));
        }
        aliases += 1;
        if aliases >= MAX_EVENT_OPERATION_ALIASES {
            return Err(StoreError::EventOperationLimitExceeded {
                current: aliases,
                limit: MAX_EVENT_OPERATION_ALIASES,
            });
        }
    }
    let mut metadata = write.open_table(METADATA)?;
    let current = read_event_operation_stats(&metadata)?.ok_or(StoreError::SemanticInvariant(
        "Event operation accounting is missing during publication",
    ))?;
    let next = checked_admit_event_operation_record(current, limits, emergency)?;
    let encoded = encode_event_operation_ledger_record(EventOperationLedgerRecord::Active {
        intent_digest,
        transfer_id,
    });
    ledger.insert(fingerprint.as_slice(), encoded.as_slice())?;
    let key = encode_active_operation_by_event_key(transfer_id, fingerprint);
    if reverse.insert(key.as_slice(), &[][..])?.is_some() {
        return Err(StoreError::SemanticInvariant(
            "Event operation reverse edge already exists",
        ));
    }
    write_event_operation_stats(&mut metadata, next)
}

/// Fences a previously unseen key replaying an already-retired Event. This is
/// ordinary publication admission and adds no Event pointer or reverse edge.
pub(crate) fn admit_retired_event_operation_write(
    write: &redb::WriteTransaction,
    authority: &[u8; 32],
    operation: &EventOperationKey,
    intent_digest: [u8; 32],
    reason: CustodyRetirementReason,
    limits: EventOperationLimits,
) -> Result<(), StoreError> {
    let fingerprint = event_operation_fingerprint(authority, operation);
    let mut ledger = write.open_table(EVENT_OPERATION_LEDGER_V3)?;
    if ledger.get(fingerprint.as_slice())?.is_some() {
        return Err(StoreError::SemanticInvariant(
            "Event operation appeared during retired admission",
        ));
    }
    let mut metadata = write.open_table(METADATA)?;
    let current = read_event_operation_stats(&metadata)?.ok_or(StoreError::SemanticInvariant(
        "Event operation accounting is missing during publication",
    ))?;
    let next = checked_admit_event_operation_record_kind(current, limits, false, true)?;
    let encoded = encode_event_operation_ledger_record(EventOperationLedgerRecord::Retired {
        intent_digest,
        reason,
    });
    ledger.insert(fingerprint.as_slice(), encoded.as_slice())?;
    write_event_operation_stats(&mut metadata, next)
}

fn read_event_operation_stats<T>(metadata: &T) -> Result<Option<EventOperationStats>, StoreError>
where
    T: ReadableTable<&'static str, u64>,
{
    let values = [
        metadata
            .get(EVENT_OPERATION_RECORDS_TOTAL)?
            .map(|value| value.value()),
        metadata
            .get(EVENT_OPERATION_RECORDS_ACTIVE)?
            .map(|value| value.value()),
        metadata
            .get(EVENT_OPERATION_RECORDS_RETIRED)?
            .map(|value| value.value()),
        metadata
            .get(EVENT_OPERATION_REVERSE_ROWS)?
            .map(|value| value.value()),
        metadata
            .get(EVENT_OPERATION_LOGICAL_BYTES)?
            .map(|value| value.value()),
    ];
    let present = values.iter().filter(|value| value.is_some()).count();
    if present == 0 {
        return Ok(None);
    }
    if present != values.len() {
        let field = EVENT_OPERATION_ACCOUNTING_FIELDS
            .into_iter()
            .zip(values)
            .find_map(|(field, value)| value.is_none().then_some(field))
            .expect("partial accounting has a missing field");
        return Err(StoreError::MissingAccountingMetadata { field });
    }
    let stats = EventOperationStats {
        records_total: values[0].expect("checked total counter"),
        records_active: values[1].expect("checked active counter"),
        records_retired: values[2].expect("checked retired counter"),
        reverse_rows: values[3].expect("checked reverse counter"),
        logical_bytes: values[4].expect("checked logical byte counter"),
    };
    validate_event_operation_stats(stats)?;
    Ok(Some(stats))
}

pub(crate) fn write_event_operation_stats(
    metadata: &mut redb::Table<'_, &str, u64>,
    stats: EventOperationStats,
) -> Result<(), StoreError> {
    validate_event_operation_stats(stats)?;
    metadata.insert(EVENT_OPERATION_RECORDS_TOTAL, stats.records_total)?;
    metadata.insert(EVENT_OPERATION_RECORDS_ACTIVE, stats.records_active)?;
    metadata.insert(EVENT_OPERATION_RECORDS_RETIRED, stats.records_retired)?;
    metadata.insert(EVENT_OPERATION_REVERSE_ROWS, stats.reverse_rows)?;
    metadata.insert(EVENT_OPERATION_LOGICAL_BYTES, stats.logical_bytes)?;
    Ok(())
}

fn audit_event_operation_cardinalities(
    stats: EventOperationStats,
    ledger_rows: u64,
    reverse_rows: u64,
) -> Result<(), StoreError> {
    if stats.records_total != ledger_rows {
        return Err(StoreError::AccountingMismatch {
            field: EVENT_OPERATION_RECORDS_TOTAL,
            durable: stats.records_total,
            reconstructed: ledger_rows,
        });
    }
    if stats.reverse_rows != reverse_rows {
        return Err(StoreError::AccountingMismatch {
            field: EVENT_OPERATION_REVERSE_ROWS,
            durable: stats.reverse_rows,
            reconstructed: reverse_rows,
        });
    }
    Ok(())
}

fn existing_event_operation_stats_write(
    write: &redb::WriteTransaction,
) -> Result<Option<EventOperationStats>, StoreError> {
    if write.list_multimap_tables()?.any(|table| {
        table.name() == EVENT_OPERATION_LEDGER_V3.name()
            || table.name() == ACTIVE_OPERATION_BY_EVENT_V1.name()
    }) {
        return Err(StoreError::SemanticInvariant(
            "Event operation ledger schema has the wrong table kind",
        ));
    }
    let table_names = write
        .list_tables()?
        .map(|table| table.name().to_owned())
        .collect::<std::collections::BTreeSet<_>>();
    let ledger_present = table_names.contains(EVENT_OPERATION_LEDGER_V3.name());
    let reverse_present = table_names.contains(ACTIVE_OPERATION_BY_EVENT_V1.name());
    let metadata = write.open_table(METADATA)?;
    let stats = read_event_operation_stats(&metadata)?;
    match (ledger_present, reverse_present, stats) {
        (false, false, None) => Ok(None),
        (true, true, Some(stats)) => {
            drop(metadata);
            audit_event_operation_cardinalities(
                stats,
                write.open_table(EVENT_OPERATION_LEDGER_V3)?.len()?,
                write.open_table(ACTIVE_OPERATION_BY_EVENT_V1)?.len()?,
            )?;
            Ok(Some(stats))
        }
        _ => Err(StoreError::SemanticInvariant(
            "Event operation ledger schema group is incomplete",
        )),
    }
}

pub(crate) fn audit_event_operation_accounting_write(
    write: &redb::WriteTransaction,
) -> Result<EventOperationStats, StoreError> {
    if let Some(stats) = existing_event_operation_stats_write(write)? {
        return Ok(stats);
    }
    write.open_table(EVENT_OPERATION_LEDGER_V3)?;
    write.open_table(ACTIVE_OPERATION_BY_EVENT_V1)?;
    let stats = EventOperationStats::default();
    write_event_operation_stats(&mut write.open_table(METADATA)?, stats)?;
    Ok(stats)
}

/// A bounded image prepared while the legacy rows are still authoritative.
/// The caller must audit the complete legacy semantic image before applying it
/// in the same writer transaction. No raw application key is retained here.
pub(crate) struct LegacyEventOperationMigration {
    records: std::collections::BTreeMap<EventOperationFingerprint, EventOperationLedgerRecord>,
    stats: EventOperationStats,
}

pub(crate) fn stage_legacy_event_operations_write(
    write: &redb::WriteTransaction,
    limits: EventOperationLimits,
) -> Result<Option<LegacyEventOperationMigration>, StoreError> {
    // Inspect before initialization: any partial v3 group must fail closed.
    let existing = existing_event_operation_stats_write(write)?;
    if write
        .list_multimap_tables()?
        .any(|table| table.name() == EVENT_OPERATION_WITNESSES.name())
    {
        return Err(StoreError::SemanticInvariant(
            "Event operation-witness index has the wrong table kind",
        ));
    }
    let operations = write.open_table(EVENT_OPERATIONS)?;
    let witnesses = write.open_table(EVENT_OPERATION_WITNESSES)?;
    if existing.is_some() {
        if operations.len()? != 0 || witnesses.len()? != 0 {
            return Err(StoreError::SemanticInvariant(
                "Event operation ledger coexists with legacy rows",
            ));
        }
        return Ok(None);
    }
    let count = operations.len()?;
    if count > MAX_EVENT_OPERATIONS || witnesses.len()? > count {
        return Err(StoreError::SemanticInvariant(
            "Event operation or witness table exceeds its bounded cardinality",
        ));
    }
    drop(witnesses);
    if count == 0 {
        return Ok(None);
    }
    // A caller-supplied mission cannot authenticate an unbound legacy image.
    let mission = read_mission_binding(write)?
        .ok_or(StoreError::EventOperationMigrationMissingMissionBinding)?;
    let events = write.open_table(EVENTS)?;
    let mut records = std::collections::BTreeMap::new();
    let mut aliases = std::collections::BTreeMap::<EventTransferId, u64>::new();
    let mut stats = EventOperationStats::default();
    for row in operations.iter()? {
        let (key, value) = row?;
        let operation = EventOperationKey::new(key.value().to_vec())?;
        let legacy = decode_operation_record(value.value())?;
        let metadata = events
            .get(legacy.transfer_id.as_bytes().as_slice())?
            .map(|value| decode_event_metadata(value.value()))
            .transpose()?
            .ok_or(StoreError::EventOperationMigrationMissingAuthenticatedIntent)?;
        let intent_digest = if legacy.legacy_unbound {
            let payload_digest = event_operation_witness_write(write, legacy.transfer_id)?
                .ok_or(StoreError::EventOperationMigrationMissingAuthenticatedIntent)?;
            let intent = event_operation_intent_from_header(&metadata.header, payload_digest);
            event_operation_intent_digest(&intent, legacy.predecessor)?
        } else {
            // The full legacy audit checks this against retained accepted
            // metadata and the stored predecessor before any v3 row is written.
            legacy.intent_digest
        };
        let aliases = aliases.entry(legacy.transfer_id).or_default();
        *aliases += 1; // At most MAX_EVENT_OPERATIONS rows have been admitted.
        if *aliases > MAX_EVENT_OPERATION_ALIASES {
            return Err(StoreError::EventOperationMigrationAliasOverflow);
        }
        let record = match custody::retired_event_receipt_write(write, legacy.transfer_id)? {
            Some((semantic_id, _, reason)) => {
                if semantic_id != metadata.semantic_id {
                    return Err(StoreError::SemanticInvariant(
                        "Event operation retirement differs from accepted metadata",
                    ));
                }
                stats.records_retired += 1;
                EventOperationLedgerRecord::Retired {
                    intent_digest,
                    reason,
                }
            }
            None => {
                stats.records_active += 1;
                EventOperationLedgerRecord::Active {
                    intent_digest,
                    transfer_id: legacy.transfer_id,
                }
            }
        };
        let fingerprint = event_operation_fingerprint(&mission, &operation);
        #[cfg(test)]
        let fingerprint = if MIGRATION_TEST_FAULT.get() == 1 {
            [0; 32]
        } else {
            fingerprint
        };
        // redb's raw-key map already guarantees distinct input keys; even
        // aliases with identical intent must not silently merge on collision.
        if records.insert(fingerprint, record).is_some() {
            return Err(StoreError::EventOperationMigrationFingerprintCollision);
        }
    }
    stats.records_total = count;
    stats.reverse_rows = stats.records_active;
    stats.logical_bytes = checked_event_operation_logical_bytes(
        stats.records_active,
        stats.records_retired,
        stats.reverse_rows,
    )?;
    validate_event_operation_stats(stats)?;
    // Migration preserves already accepted work, including emergency records;
    // the destination's hard limits, rather than its ordinary reserve, apply.
    if stats.records_total > limits.max_records()
        || stats.logical_bytes > limits.max_logical_bytes()
    {
        return Err(StoreError::EventOperationMigrationDestinationCapacity);
    }
    Ok(Some(LegacyEventOperationMigration { records, stats }))
}

impl LegacyEventOperationMigration {
    pub(crate) fn apply(&self, write: &redb::WriteTransaction) -> Result<(), StoreError> {
        let mut ledger = write.open_table(EVENT_OPERATION_LEDGER_V3)?;
        let mut reverse = write.open_table(ACTIVE_OPERATION_BY_EVENT_V1)?;
        for (&fingerprint, &record) in &self.records {
            let encoded = encode_event_operation_ledger_record(record);
            ledger.insert(fingerprint.as_slice(), encoded.as_slice())?;
            if let EventOperationLedgerRecord::Active { transfer_id, .. } = record {
                let key = encode_active_operation_by_event_key(transfer_id, fingerprint);
                reverse.insert(key.as_slice(), &[][..])?;
            }
        }
        drop((ledger, reverse));
        let mut metadata = write.open_table(METADATA)?;
        write_event_operation_stats(&mut metadata, self.stats)?;
        // Remove the legacy ordinary/quota contribution in this same commit.
        for field in [
            EVENT_OPERATION_COUNT,
            EVENT_OPERATION_TOTAL_BYTES,
            EVENT_TOMBSTONE_OPERATION_COUNT,
            EVENT_TOMBSTONE_OPERATION_TOTAL_BYTES,
        ] {
            metadata.insert(field, 0)?;
        }
        drop(metadata);
        // Retain empty tables for the legacy source-compatible read surfaces.
        write.delete_table(EVENT_OPERATIONS)?;
        write.delete_table(EVENT_OPERATION_WITNESSES)?;
        write.open_table(EVENT_OPERATIONS)?;
        write.open_table(EVENT_OPERATION_WITNESSES)?;
        Ok(())
    }
}

pub(crate) fn inspect_event_operation_accounting_read(
    read: &redb::ReadTransaction,
) -> Result<EventOperationStats, StoreError> {
    if read.list_multimap_tables()?.any(|table| {
        table.name() == EVENT_OPERATION_LEDGER_V3.name()
            || table.name() == ACTIVE_OPERATION_BY_EVENT_V1.name()
    }) {
        return Err(StoreError::SemanticInvariant(
            "Event operation ledger schema has the wrong table kind",
        ));
    }
    let table_names = read
        .list_tables()?
        .map(|table| table.name().to_owned())
        .collect::<std::collections::BTreeSet<_>>();
    let ledger_present = table_names.contains(EVENT_OPERATION_LEDGER_V3.name());
    let reverse_present = table_names.contains(ACTIVE_OPERATION_BY_EVENT_V1.name());
    let metadata = read.open_table(METADATA)?;
    let stats = read_event_operation_stats(&metadata)?;
    if !ledger_present && !reverse_present && stats.is_none() {
        return Ok(EventOperationStats::default());
    }
    if !ledger_present || !reverse_present || stats.is_none() {
        return Err(StoreError::SemanticInvariant(
            "Event operation ledger schema group is incomplete",
        ));
    }
    let stats = stats.expect("complete accounting has stats");
    audit_event_operation_cardinalities(
        stats,
        read.open_table(EVENT_OPERATION_LEDGER_V3)?.len()?,
        read.open_table(ACTIVE_OPERATION_BY_EVENT_V1)?.len()?,
    )?;
    Ok(stats)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        AggregateStoreUsage, BlobDepotLimits, CustodyRetirementReason, EventStoreStats,
        EventTransferId, Store, StoreLimits,
    };
    use std::sync::atomic::{AtomicU64, Ordering};

    static NEXT_ACCOUNTING_TEST_PATH: AtomicU64 = AtomicU64::new(0);

    struct AccountingTestFile(std::path::PathBuf);

    impl AccountingTestFile {
        fn new(name: &str) -> Self {
            let sequence = NEXT_ACCOUNTING_TEST_PATH.fetch_add(1, Ordering::Relaxed);
            Self(std::env::temp_dir().join(format!(
                "aster-event-operation-{name}-{}-{sequence}.redb",
                std::process::id()
            )))
        }
    }

    impl Drop for AccountingTestFile {
        fn drop(&mut self) {
            let _ = std::fs::remove_file(&self.0);
        }
    }

    const MISSION_A: [u8; 32] = [
        0xa0, 0xa1, 0xa2, 0xa3, 0xa4, 0xa5, 0xa6, 0xa7, 0xa8, 0xa9, 0xaa, 0xab, 0xac, 0xad, 0xae,
        0xaf, 0xb0, 0xb1, 0xb2, 0xb3, 0xb4, 0xb5, 0xb6, 0xb7, 0xb8, 0xb9, 0xba, 0xbb, 0xbc, 0xbd,
        0xbe, 0xbf,
    ];
    const MISSION_B: [u8; 32] = [
        0xc0, 0xc1, 0xc2, 0xc3, 0xc4, 0xc5, 0xc6, 0xc7, 0xc8, 0xc9, 0xca, 0xcb, 0xcc, 0xcd, 0xce,
        0xcf, 0xd0, 0xd1, 0xd2, 0xd3, 0xd4, 0xd5, 0xd6, 0xd7, 0xd8, 0xd9, 0xda, 0xdb, 0xdc, 0xdd,
        0xde, 0xdf,
    ];

    fn operation_key(bytes: &[u8]) -> EventOperationKey {
        EventOperationKey::new(bytes).expect("valid operation key")
    }

    #[test]
    fn crate_root_exports_the_fixed_event_operation_alias_limit() {
        assert_eq!(crate::MAX_EVENT_OPERATION_ALIASES, 64);
    }

    #[test]
    fn fingerprint_uses_the_exact_domain_mission_length_and_raw_key() {
        let fingerprint =
            event_operation_fingerprint(&MISSION_A, &operation_key(&[0x01, 0x02, 0x03]));

        assert_eq!(
            fingerprint,
            [
                0xa0, 0x55, 0x15, 0x40, 0x96, 0x38, 0x73, 0x1f, 0x96, 0x7f, 0x03, 0x1f, 0x4f, 0x18,
                0xaf, 0x62, 0xf5, 0x65, 0x67, 0xa8, 0x36, 0x6a, 0xad, 0xe4, 0xa6, 0x31, 0x41, 0xdd,
                0x2f, 0xcd, 0xd4, 0x80,
            ]
        );
    }

    #[test]
    fn fingerprint_separates_operation_key_lengths() {
        let short = event_operation_fingerprint(&MISSION_A, &operation_key(&[0x01]));
        let long = event_operation_fingerprint(&MISSION_A, &operation_key(&[0x01, 0x00]));

        assert_eq!(
            short,
            [
                0xe0, 0xf2, 0x51, 0xa6, 0xeb, 0xd3, 0x67, 0x0d, 0xaa, 0x5a, 0xf5, 0xeb, 0x0a, 0x59,
                0x0a, 0xd4, 0xca, 0x3c, 0x59, 0xae, 0x75, 0xb8, 0xd5, 0xe7, 0x01, 0x54, 0xb0, 0x5e,
                0xa5, 0x61, 0xe1, 0xc6,
            ]
        );
        assert_eq!(
            long,
            [
                0x3e, 0xb1, 0x2c, 0x7d, 0x93, 0x78, 0x81, 0x90, 0x43, 0xba, 0xa0, 0x03, 0x6d, 0x20,
                0x9a, 0x5e, 0xf8, 0x55, 0x3f, 0x7e, 0x81, 0x7d, 0xdf, 0xb7, 0x05, 0x37, 0x32, 0x63,
                0x49, 0xea, 0xa1, 0x47,
            ]
        );
    }

    #[test]
    fn fingerprint_separates_missions() {
        let first = event_operation_fingerprint(&MISSION_A, &operation_key(&[0x01, 0x02, 0x03]));
        let second = event_operation_fingerprint(&MISSION_B, &operation_key(&[0x01, 0x02, 0x03]));

        assert_eq!(
            first,
            [
                0xa0, 0x55, 0x15, 0x40, 0x96, 0x38, 0x73, 0x1f, 0x96, 0x7f, 0x03, 0x1f, 0x4f, 0x18,
                0xaf, 0x62, 0xf5, 0x65, 0x67, 0xa8, 0x36, 0x6a, 0xad, 0xe4, 0xa6, 0x31, 0x41, 0xdd,
                0x2f, 0xcd, 0xd4, 0x80,
            ]
        );
        assert_eq!(
            second,
            [
                0xbd, 0x1b, 0xa9, 0x07, 0x08, 0x2d, 0xa9, 0xa6, 0x2c, 0xcb, 0x53, 0x67, 0x53, 0xd3,
                0xba, 0x0f, 0xd1, 0xb2, 0xfd, 0x75, 0xae, 0x82, 0xa2, 0xc4, 0xb3, 0x94, 0xbf, 0x6d,
                0x37, 0x66, 0x05, 0xab,
            ]
        );
    }

    #[test]
    fn active_record_round_trips_to_its_canonical_bytes() {
        let record = EventOperationLedgerRecord::Active {
            intent_digest: [0x11; 32],
            transfer_id: EventTransferId::new([0x22; 32]),
        };

        assert_eq!(
            encode_event_operation_ledger_record(record).as_slice(),
            [
                1, 1, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11,
                0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11,
                0x11, 0x11, 0x11, 0x11, 0x11, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22,
                0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22,
                0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22,
            ]
        );
        assert_eq!(
            decode_event_operation_ledger_record(&encode_event_operation_ledger_record(record))
                .expect("canonical active record"),
            record
        );
    }

    #[test]
    fn retired_record_round_trips_to_its_canonical_bytes() {
        let record = EventOperationLedgerRecord::Retired {
            intent_digest: [0x33; 32],
            reason: CustodyRetirementReason::QuotaPressure,
        };

        assert_eq!(
            encode_event_operation_ledger_record(record).as_slice(),
            [
                1, 2, 0x33, 0x33, 0x33, 0x33, 0x33, 0x33, 0x33, 0x33, 0x33, 0x33, 0x33, 0x33, 0x33,
                0x33, 0x33, 0x33, 0x33, 0x33, 0x33, 0x33, 0x33, 0x33, 0x33, 0x33, 0x33, 0x33, 0x33,
                0x33, 0x33, 0x33, 0x33, 0x33, 2,
            ]
        );
        assert_eq!(
            decode_event_operation_ledger_record(&encode_event_operation_ledger_record(record))
                .expect("canonical retired record"),
            record
        );
    }

    #[test]
    fn ledger_decoder_rejects_each_malformed_version_state_length_and_reason() {
        assert!(decode_event_operation_ledger_record(&[]).is_err());
        assert!(decode_event_operation_ledger_record(&[1]).is_err());
        assert!(decode_event_operation_ledger_record(&[9, 1]).is_err());
        assert!(decode_event_operation_ledger_record(&[1, 9]).is_err());
        assert!(decode_event_operation_ledger_record(&[1, 1]).is_err());
        assert!(decode_event_operation_ledger_record(&[1, 2]).is_err());
        let mut overlong_active = [0u8; 67];
        overlong_active[0] = 1;
        overlong_active[1] = 1;
        assert!(decode_event_operation_ledger_record(&overlong_active).is_err());
        let mut overlong_retired = [0u8; 36];
        overlong_retired[0] = 1;
        overlong_retired[1] = 2;
        assert!(decode_event_operation_ledger_record(&overlong_retired).is_err());
        let mut unknown_reason = [0u8; 35];
        unknown_reason[0] = 1;
        unknown_reason[1] = 2;
        unknown_reason[34] = 9;
        assert!(decode_event_operation_ledger_record(&unknown_reason).is_err());
    }

    #[test]
    fn reverse_key_round_trips_to_the_transfer_then_fingerprint_bytes() {
        let transfer_id = EventTransferId::new([0x44; 32]);
        let fingerprint = [0x55; 32];

        assert_eq!(
            encode_active_operation_by_event_key(transfer_id, fingerprint),
            [
                0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44,
                0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44,
                0x44, 0x44, 0x44, 0x44, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55,
                0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55,
                0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55,
            ]
        );
        assert_eq!(
            decode_active_operation_by_event_key(&encode_active_operation_by_event_key(
                transfer_id,
                fingerprint,
            ))
            .expect("canonical reverse key"),
            (transfer_id, fingerprint)
        );
        assert!(decode_active_operation_by_event_key(&[0; 63]).is_err());
    }

    #[test]
    fn limits_validate_reserve_and_derive_ordinary_capacity() {
        assert!(EventOperationLimits::new(0, 162, 1).is_err());
        assert!(EventOperationLimits::new(10, 1_620, 10).is_err());
        assert!(EventOperationLimits::new(11, 1_619, 10).is_err());

        let limits = EventOperationLimits::new(100, 20_000, 10).expect("valid limits");
        assert_eq!(limits.max_records(), 100);
        assert_eq!(limits.max_logical_bytes(), 20_000);
        assert_eq!(limits.emergency_reserve(), 10);
        assert_eq!(limits.ordinary_record_limit(), 90);
        assert_eq!(limits.emergency_byte_reserve(), 1_620);
    }

    #[test]
    fn logical_byte_accounting_uses_fixed_rows_and_rejects_overflow() {
        assert_eq!(
            checked_event_operation_logical_bytes(1, 2, 3).expect("finite logical usage"),
            424
        );
        assert!(checked_event_operation_logical_bytes(u64::MAX, 1, 1).is_err());
    }

    #[test]
    fn mission_open_retains_explicit_operation_limits_and_reports_empty_defaults() {
        let file = AccountingTestFile::new("empty-defaults");
        let operation_limits =
            EventOperationLimits::new(100, 20_000, 10).expect("valid operation limits");
        let store = Store::open_with_limits_and_operation_limits_for_mission(
            &file.0,
            StoreLimits::default(),
            BlobDepotLimits::default(),
            operation_limits,
            MISSION_A,
        )
        .expect("open with explicit operation limits");

        assert_eq!(store.operation_limits(), operation_limits);
        assert_eq!(
            store.event_stats().expect("empty Event stats"),
            EventStoreStats {
                operation_stats: EventOperationStats::default(),
                ..EventStoreStats::default()
            }
        );
    }

    #[test]
    fn invalid_custom_limits_and_counter_arithmetic_fail_closed() {
        assert!(EventOperationLimits::new(0, 162, 1).is_err());
        assert!(EventOperationLimits::new(2, 161, 1).is_err());

        assert!(matches!(
            validate_event_operation_stats(EventOperationStats {
                records_total: u64::MAX,
                records_active: u64::MAX,
                records_retired: 1,
                reverse_rows: u64::MAX,
                logical_bytes: u64::MAX,
            }),
            Err(StoreError::ItemCountAccountingOverflow)
        ));
        assert!(matches!(
            checked_retire_event_operation_records(EventOperationStats::default(), 1),
            Err(StoreError::SemanticInvariant(
                "Event operation active-record accounting underflow"
            ))
        ));
    }

    #[test]
    fn active_increment_and_retirement_preserve_exact_ledger_invariants() {
        let limits = EventOperationLimits::new(3, 486, 1).expect("limits");
        let first =
            checked_admit_event_operation_record(EventOperationStats::default(), limits, false)
                .expect("first ordinary operation");
        assert_eq!(
            first,
            EventOperationStats {
                records_total: 1,
                records_active: 1,
                records_retired: 0,
                reverse_rows: 1,
                logical_bytes: 162,
            }
        );
        let second = checked_admit_event_operation_record(first, limits, false)
            .expect("last ordinary operation");
        assert!(matches!(
            checked_admit_event_operation_record(second, limits, false),
            Err(StoreError::EventOperationLimitExceeded {
                current: 2,
                limit: 2,
            })
        ));
        let emergency = checked_admit_event_operation_record(second, limits, true)
            .expect("reserved emergency operation");
        assert_eq!(emergency.records_total, 3);
        assert_eq!(emergency.logical_bytes, 486);

        let retired = checked_retire_event_operation_records(emergency, 2)
            .expect("compact two active records");
        assert_eq!(
            retired,
            EventOperationStats {
                records_total: 3,
                records_active: 1,
                records_retired: 2,
                reverse_rows: 1,
                logical_bytes: 296,
            }
        );
    }

    fn write_single_active_operation_fixture(
        file: &AccountingTestFile,
        limits: EventOperationLimits,
        stats: EventOperationStats,
        include_reverse_row: bool,
    ) {
        {
            let store = Store::open_with_limits_and_operation_limits_for_mission(
                &file.0,
                StoreLimits::default(),
                BlobDepotLimits::default(),
                limits,
                MISSION_A,
            )
            .expect("create operation store");
            let write = store.database.begin_write().expect("begin ledger fixture");
            {
                let fingerprint = [0x61; 32];
                let transfer_id = EventTransferId::new([0x62; 32]);
                write
                    .open_table(EVENT_OPERATION_LEDGER_V3)
                    .expect("ledger")
                    .insert(
                        fingerprint.as_slice(),
                        encode_event_operation_ledger_record(EventOperationLedgerRecord::Active {
                            intent_digest: [0x63; 32],
                            transfer_id,
                        })
                        .as_slice(),
                    )
                    .expect("insert ledger row");
                if include_reverse_row {
                    write
                        .open_table(ACTIVE_OPERATION_BY_EVENT_V1)
                        .expect("reverse")
                        .insert(
                            encode_active_operation_by_event_key(transfer_id, fingerprint)
                                .as_slice(),
                            [].as_slice(),
                        )
                        .expect("insert reverse row");
                }
                let mut metadata = write.open_table(crate::METADATA).expect("metadata");
                write_event_operation_stats(&mut metadata, stats).expect("write exact counters");
            }
            write.commit().expect("commit ledger fixture");
        }
    }

    #[test]
    fn reopen_rejects_ledger_cardinality_mismatch_after_counter_validation() {
        let file = AccountingTestFile::new("ledger-cardinality-mismatch");
        let limits = EventOperationLimits::new(100, 20_000, 10).expect("limits");
        write_single_active_operation_fixture(
            &file,
            limits,
            EventOperationStats {
                records_total: 2,
                records_active: 1,
                records_retired: 1,
                reverse_rows: 1,
                logical_bytes: 229,
            },
            true,
        );

        assert!(matches!(
            Store::open_with_limits_and_operation_limits_for_mission(
                &file.0,
                StoreLimits::default(),
                BlobDepotLimits::default(),
                limits,
                MISSION_A,
            ),
            Err(StoreError::AccountingMismatch {
                field: EVENT_OPERATION_RECORDS_TOTAL,
                durable: 2,
                reconstructed: 1,
            })
        ));
    }

    #[test]
    fn reopen_rejects_reverse_cardinality_mismatch_after_ledger_cardinality_passes() {
        let file = AccountingTestFile::new("reverse-cardinality-mismatch");
        let limits = EventOperationLimits::new(100, 20_000, 10).expect("limits");
        write_single_active_operation_fixture(
            &file,
            limits,
            EventOperationStats {
                records_total: 1,
                records_active: 1,
                records_retired: 0,
                reverse_rows: 1,
                logical_bytes: 162,
            },
            false,
        );

        assert!(matches!(
            Store::open_with_limits_and_operation_limits_for_mission(
                &file.0,
                StoreLimits::default(),
                BlobDepotLimits::default(),
                limits,
                MISSION_A,
            ),
            Err(StoreError::AccountingMismatch {
                field: EVENT_OPERATION_REVERSE_ROWS,
                durable: 1,
                reconstructed: 0,
            })
        ));
    }

    #[test]
    fn v3_operation_rows_do_not_consume_aggregate_store_limits() {
        let file = AccountingTestFile::new("dedicated-aggregate");
        let store = Store::open_with_limits_and_operation_limits_for_mission(
            &file.0,
            StoreLimits::new(1, 1).expect("ordinary limits"),
            BlobDepotLimits::default(),
            EventOperationLimits::new(100, 20_000, 10).expect("operation limits"),
            MISSION_A,
        )
        .expect("create operation store");
        let write = store.database.begin_write().expect("begin ledger fixture");
        {
            let fingerprint = [0x71; 32];
            let transfer_id = EventTransferId::new([0x72; 32]);
            write
                .open_table(EVENT_OPERATION_LEDGER_V3)
                .expect("ledger")
                .insert(
                    fingerprint.as_slice(),
                    encode_event_operation_ledger_record(EventOperationLedgerRecord::Active {
                        intent_digest: [0x73; 32],
                        transfer_id,
                    })
                    .as_slice(),
                )
                .expect("insert ledger row");
            write
                .open_table(ACTIVE_OPERATION_BY_EVENT_V1)
                .expect("reverse")
                .insert(
                    encode_active_operation_by_event_key(transfer_id, fingerprint).as_slice(),
                    [].as_slice(),
                )
                .expect("insert reverse row");
            let mut metadata = write.open_table(crate::METADATA).expect("metadata");
            write_event_operation_stats(
                &mut metadata,
                EventOperationStats {
                    records_total: 1,
                    records_active: 1,
                    records_retired: 0,
                    reverse_rows: 1,
                    logical_bytes: 162,
                },
            )
            .expect("write exact counters");
        }
        write.commit().expect("commit ledger fixture");

        assert_eq!(
            store.aggregate_usage().expect("ordinary aggregate usage"),
            AggregateStoreUsage::default()
        );
        let stats = store.event_stats().expect("Event stats");
        assert_eq!(stats.operation_stats.records_total, 1);
        assert_eq!(stats.operation_stats.logical_bytes, 162);
        assert_eq!(stats.operations, 1);
        assert_eq!(stats.operation_bytes, 162);
    }
}
