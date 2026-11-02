use std::collections::{BTreeMap, BTreeSet};

use aster_mesh::{CustodyAge, CustodyContinuity, CustodyError, CustodySample};
use redb::{
    MultimapTableHandle, ReadableTable, ReadableTableMetadata, TableDefinition, TableHandle,
};
use sha2::{Digest, Sha256};

use super::{BlobSemanticId, BlobStoreError, BlobStoreStats, BlobTransferId, StoreError, depot};
use crate::custody;

#[cfg(test)]
thread_local! {
    pub(crate) static TEST_BLOB_LIFECYCLE_MIGRATION_FAULT: std::cell::Cell<bool> = const {
        std::cell::Cell::new(false)
    };
    pub(crate) static TEST_BLOB_LIFECYCLE_MIGRATION_DISABLED: std::cell::Cell<bool> = const {
        std::cell::Cell::new(false)
    };
    static TEST_BLOB_LIFECYCLE_SCHEMA_ENUMERATIONS: std::cell::Cell<u64> = const {
        std::cell::Cell::new(0)
    };
}

#[cfg(test)]
pub(crate) fn reset_lifecycle_schema_enumerations_for_test() {
    TEST_BLOB_LIFECYCLE_SCHEMA_ENUMERATIONS.set(0);
}

#[cfg(test)]
pub(crate) fn take_lifecycle_schema_enumerations_for_test() -> u64 {
    TEST_BLOB_LIFECYCLE_SCHEMA_ENUMERATIONS.replace(0)
}

/// Default permanent physical-lineage fence count cap.
pub const DEFAULT_MAX_BLOB_LINEAGE_FENCE_ROWS: u64 = 65_536;
/// Default permanent physical-lineage fence encoded-byte cap (16 MiB).
pub const DEFAULT_MAX_BLOB_LINEAGE_FENCE_BYTES: u64 = 16 * 1024 * 1024;
/// Default permanent accepted-publication replay fence count cap.
pub const DEFAULT_MAX_BLOB_REPLAY_FENCE_ROWS: u64 = 65_536;
/// Default permanent accepted-publication replay fence encoded-byte cap (16 MiB).
pub const DEFAULT_MAX_BLOB_REPLAY_FENCE_BYTES: u64 = 16 * 1024 * 1024;
/// Default combined live and retained Blob-publication lifecycle row cap.
pub const DEFAULT_MAX_BLOB_PUBLICATION_LIFECYCLE_ROWS: u64 = 65_536;
/// Default operation/publication retirement evidence retention (45 days).
pub(crate) const DEFAULT_BLOB_RETIREMENT_RETENTION_MS: u64 = 45 * 24 * 60 * 60 * 1_000;

/// Dedicated non-evictable Blob lifecycle authority limits.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BlobLifecycleLimits {
    max_lineage_rows: u64,
    max_lineage_bytes: u64,
    max_replay_rows: u64,
    max_replay_bytes: u64,
    max_publication_rows: u64,
    retain_for_ms: u64,
}

impl BlobLifecycleLimits {
    /// Conservative selected-profile lifecycle authority limits.
    pub const DEFAULT: Self = Self {
        max_lineage_rows: DEFAULT_MAX_BLOB_LINEAGE_FENCE_ROWS,
        max_lineage_bytes: DEFAULT_MAX_BLOB_LINEAGE_FENCE_BYTES,
        max_replay_rows: DEFAULT_MAX_BLOB_REPLAY_FENCE_ROWS,
        max_replay_bytes: DEFAULT_MAX_BLOB_REPLAY_FENCE_BYTES,
        max_publication_rows: DEFAULT_MAX_BLOB_PUBLICATION_LIFECYCLE_ROWS,
        retain_for_ms: DEFAULT_BLOB_RETIREMENT_RETENTION_MS,
    };

    /// Constructs nonzero security-fence and publication-lifecycle limits.
    pub const fn new(
        max_lineage_rows: u64,
        max_lineage_bytes: u64,
        max_replay_rows: u64,
        max_replay_bytes: u64,
        max_publication_rows: u64,
    ) -> Result<Self, BlobStoreError> {
        if max_lineage_rows == 0
            || max_lineage_bytes == 0
            || max_replay_rows == 0
            || max_replay_bytes == 0
            || max_publication_rows == 0
        {
            return Err(BlobStoreError::InvalidLifecycleLimits);
        }
        Ok(Self {
            max_lineage_rows,
            max_lineage_bytes,
            max_replay_rows,
            max_replay_bytes,
            max_publication_rows,
            retain_for_ms: DEFAULT_BLOB_RETIREMENT_RETENTION_MS,
        })
    }

    /// Maximum permanent physical-lineage fence rows.
    pub const fn max_lineage_rows(self) -> u64 {
        self.max_lineage_rows
    }

    /// Maximum encoded bytes across permanent physical-lineage fences.
    pub const fn max_lineage_bytes(self) -> u64 {
        self.max_lineage_bytes
    }

    /// Maximum permanent accepted-publication replay fence rows.
    pub const fn max_replay_rows(self) -> u64 {
        self.max_replay_rows
    }

    /// Maximum encoded bytes across permanent accepted-publication replay fences.
    pub const fn max_replay_bytes(self) -> u64 {
        self.max_replay_bytes
    }

    /// Maximum combined live and retained Blob-publication lifecycle rows.
    pub const fn max_publication_rows(self) -> u64 {
        self.max_publication_rows
    }

    /// Conservative lower-bound age retained for retirement evidence.
    pub(crate) const fn retain_for_ms(self) -> u64 {
        self.retain_for_ms
    }
}

impl Default for BlobLifecycleLimits {
    fn default() -> Self {
        Self::DEFAULT
    }
}

pub(crate) const BLOB_LIFECYCLE_METADATA: TableDefinition<&str, u64> =
    TableDefinition::new("aster.blob-lifecycle-metadata.v1");
pub(crate) const BLOB_VARIANT_REFERENCES: TableDefinition<&[u8], &[u8]> =
    TableDefinition::new("aster.blob-variant-references.v1");
pub(crate) const BLOB_LINEAGE_FENCES: TableDefinition<&[u8], &[u8]> =
    TableDefinition::new("aster.blob-lineage-fences.v1");
pub(crate) const BLOB_REPLAY_FENCES: TableDefinition<&[u8], &[u8]> =
    TableDefinition::new("aster.blob-replay-fences.v1");
// Expiry removes the bounded publication record but not the causal frontier it
// established.  This fixed-width binding lets startup audit prove which
// remaining frontier row belongs to an expired permanent replay fence without
// retaining topic/scope lookup metadata.
pub(crate) const BLOB_REPLAY_CAUSAL_FENCES: TableDefinition<&[u8], &[u8]> =
    TableDefinition::new("aster.blob-replay-causal-fences.v1");
pub(crate) const BLOB_MAINTENANCE_CURSORS: TableDefinition<u8, &[u8]> =
    TableDefinition::new("aster.blob-maintenance-cursors.v1");
pub(crate) const BLOB_OPERATION_OWNERS: TableDefinition<&[u8], &[u8]> =
    TableDefinition::new("aster.blob-operation-owners.v1");
pub(crate) const BLOB_DELIVERY_OWNERS: TableDefinition<&[u8], &[u8]> =
    TableDefinition::new("aster.blob-delivery-owners.v1");
pub(crate) const BLOB_RETENTION_DEADLINES: TableDefinition<&[u8], &[u8]> =
    TableDefinition::new("aster.blob-retention-deadlines.v1");
pub(crate) const BLOB_TTL_DEADLINES: TableDefinition<&[u8], &[u8]> =
    TableDefinition::new("aster.blob-ttl-deadlines.v1");
pub(crate) const BLOB_TTL_EXPIRY_CURSORS: TableDefinition<u8, &[u8]> =
    TableDefinition::new("aster.blob-ttl-expiry-cursors.v1");
/// Exact point-resolution authority for every retained publication and
/// operation, including records created before a custody clock is available.
pub(crate) const BLOB_RETIREMENT_RESOLVERS: TableDefinition<&[u8], &[u8]> =
    TableDefinition::new("aster.blob-retirement-resolvers.v1");

const BLOB_LIFECYCLE_SCHEMA_VERSION_FIELD: &str = "schema_version";
// Ordinary store opens remain on the fully maintained v4 authority until all
// Task-4 mutation, retirement and maintenance paths can maintain v5 atomically.
const ACTIVE_BLOB_LIFECYCLE_SCHEMA_VERSION: u64 = 5;
const PREVIOUS_BLOB_LIFECYCLE_SCHEMA_VERSION: u64 = 4;
const BLOB_LIFECYCLE_SCHEMA_VERSION: u64 = 5;
const BLOB_LINEAGE_ROWS: &str = "lineage_rows";
const BLOB_LINEAGE_BYTES: &str = "lineage_bytes";
const BLOB_REPLAY_ROWS: &str = "replay_rows";
const BLOB_REPLAY_BYTES: &str = "replay_bytes";
const BLOB_PUBLICATION_ROWS: &str = "publication_rows";
const BLOB_REFERENCE_ROWS: &str = "reference_rows";
const BLOB_OPERATION_OWNER_ROWS: &str = "operation_owner_rows";
const BLOB_DELIVERY_OWNER_ROWS: &str = "delivery_owner_rows";
const BLOB_DEADLINE_ROWS: &str = "deadline_rows";
const BLOB_TTL_DEADLINE_ROWS: &str = "ttl_deadline_rows";
const BLOB_RETIREMENT_RESOLVER_ROWS: &str = "retirement_resolver_rows";
const BLOB_RETIRED_PUBLICATION_ROWS: &str = "retired_publication_rows";
const BLOB_RETIRED_OPERATION_ROWS: &str = "retired_operation_rows";
const BLOB_NEXT_RETIREMENT_GENERATION: &str = "next_retirement_generation";
const BLOB_LIFECYCLE_V4_METADATA_FIELDS: [&str; 14] = [
    BLOB_LIFECYCLE_SCHEMA_VERSION_FIELD,
    BLOB_LINEAGE_ROWS,
    BLOB_LINEAGE_BYTES,
    BLOB_REPLAY_ROWS,
    BLOB_REPLAY_BYTES,
    BLOB_PUBLICATION_ROWS,
    BLOB_REFERENCE_ROWS,
    BLOB_OPERATION_OWNER_ROWS,
    BLOB_DELIVERY_OWNER_ROWS,
    BLOB_DEADLINE_ROWS,
    BLOB_RETIREMENT_RESOLVER_ROWS,
    BLOB_RETIRED_PUBLICATION_ROWS,
    BLOB_RETIRED_OPERATION_ROWS,
    BLOB_NEXT_RETIREMENT_GENERATION,
];
const BLOB_LIFECYCLE_METADATA_FIELDS: [&str; 15] = [
    BLOB_LIFECYCLE_SCHEMA_VERSION_FIELD,
    BLOB_LINEAGE_ROWS,
    BLOB_LINEAGE_BYTES,
    BLOB_REPLAY_ROWS,
    BLOB_REPLAY_BYTES,
    BLOB_PUBLICATION_ROWS,
    BLOB_REFERENCE_ROWS,
    BLOB_OPERATION_OWNER_ROWS,
    BLOB_DELIVERY_OWNER_ROWS,
    BLOB_DEADLINE_ROWS,
    BLOB_TTL_DEADLINE_ROWS,
    BLOB_RETIREMENT_RESOLVER_ROWS,
    BLOB_RETIRED_PUBLICATION_ROWS,
    BLOB_RETIRED_OPERATION_ROWS,
    BLOB_NEXT_RETIREMENT_GENERATION,
];

pub(crate) const PREDECESSOR_PUBLICATION_RECORD_VERSION: u8 = 4;
const CURRENT_PUBLICATION_RECORD_VERSION: u8 = 5;
pub(crate) const LIFECYCLE_V1_PUBLICATION_RECORD_VERSION: u8 = 3;
const CURRENT_OPERATION_RECORD_VERSION: u8 = 2;

const RECORD_VERSION: u8 = 1;
const RECLAIMED_LINEAGE_FENCE_VERSION: u8 = 2;
pub(crate) const PUBLICATION_STATE_LIVE_TAG: u8 = 1;
pub(crate) const PUBLICATION_STATE_RETIRED_TAG: u8 = 2;
const OPERATION_STATE_ACTIVE_TAG: u8 = 1;
const OPERATION_STATE_RETIRED_TAG: u8 = 2;
const VARIANT_REFERENCE_PUBLICATION_TAG: u8 = 1;
const VARIANT_REFERENCE_PENDING_SOURCE_TAG: u8 = 2;
const MAINTENANCE_NEXT_CLASS_KEY: u8 = 0;
const MAINTENANCE_CURSOR_VERSION: u8 = 1;
const MAINTENANCE_CURSOR_UNSET_TAG: u8 = 0;
const MAINTENANCE_CURSOR_POSITION_TAG: u8 = 1;
const MAINTENANCE_PUBLICATION_SOURCE_TAG: u8 = 1;
const MAINTENANCE_PENDING_SOURCE_TAG: u8 = 2;
const MAINTENANCE_INVALID_PENDING_SOURCE_TAG: u8 = 1;
const MAINTENANCE_CARRIER_SOURCE_TAG: u8 = 2;
const MAINTENANCE_DELETION_MANIFEST_TAG: u8 = 1;
const MAINTENANCE_DELETION_CHUNK_TAG: u8 = 2;
const MAINTENANCE_DELETION_CHUNK_RESUME_TAG: u8 = 3;
const MAINTENANCE_DELETION_MANIFEST_RESUME_TAG: u8 = 4;

pub(crate) fn deletion_manifest_cursor_position(variant: super::BlobVariantId) -> [u8; 33] {
    let mut position = [0u8; 33];
    position[0] = MAINTENANCE_DELETION_MANIFEST_TAG;
    position[1..].copy_from_slice(variant.as_bytes());
    position
}

pub(crate) fn deletion_chunk_cursor_position(
    variant: super::BlobVariantId,
    index: u64,
) -> [u8; 41] {
    let mut position = [0u8; 41];
    position[0] = MAINTENANCE_DELETION_CHUNK_TAG;
    position[1..33].copy_from_slice(variant.as_bytes());
    position[33..].copy_from_slice(&index.to_be_bytes());
    position
}

pub(crate) fn deletion_chunk_resume_position(
    variant: super::BlobVariantId,
    index: u64,
) -> [u8; 41] {
    let mut position = deletion_chunk_cursor_position(variant, index);
    position[0] = MAINTENANCE_DELETION_CHUNK_RESUME_TAG;
    position
}

pub(crate) fn deletion_manifest_resume_position(variant: super::BlobVariantId) -> [u8; 33] {
    let mut position = deletion_manifest_cursor_position(variant);
    position[0] = MAINTENANCE_DELETION_MANIFEST_RESUME_TAG;
    position
}

const RETIREMENT_AGE_VERSION: u8 = 1;
pub(crate) const RETIREMENT_AGE_ENCODED_BYTES: usize = 43;
const RETIRED_PUBLICATION_STATE_BYTES: usize = 2 + 8 + RETIREMENT_AGE_ENCODED_BYTES;

/// Stable reason retained after one Blob publication leaves live state.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum RetirementReason {
    Expired,
    Invalidated,
    Evicted,
}

const TTL_DEADLINE_VERSION: u8 = 1;
const TTL_DEADLINE_KEY_BYTES: usize = 1 + 8 + 16 + 1 + 8 + 32;
const TTL_EXPIRY_CYCLE_VERSION: u8 = 1;
const TTL_EXPIRY_CYCLE_IDLE: u8 = 0;
const TTL_EXPIRY_CYCLE_ACTIVE: u8 = 1;
const TTL_EXPIRY_CYCLE_NO_POSITION: u8 = 0;
const TTL_EXPIRY_CYCLE_POSITION: u8 = 1;
const TTL_EXPIRY_NEXT_PHASE_KEY: u8 = 0;
const TTL_EXPIRY_LIVE_CYCLE_KEY: u8 = 1;
const TTL_EXPIRY_PENDING_CYCLE_KEY: u8 = 2;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum TtlDeadlineKind {
    LivePublication,
    PendingSource,
}

impl TtlDeadlineKind {
    pub(crate) const fn tag(self) -> u8 {
        match self {
            Self::LivePublication => 1,
            Self::PendingSource => 2,
        }
    }

    fn decode(tag: u8) -> Result<Self, StoreError> {
        match tag {
            1 => Ok(Self::LivePublication),
            2 => Ok(Self::PendingSource),
            _ => Err(cursor_invariant(
                "Blob TTL deadline has an unknown root kind",
            )),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct TtlDeadline {
    pub(crate) generation: u64,
    pub(crate) deadline: CustodySample,
    pub(crate) kind: TtlDeadlineKind,
    pub(crate) transfer: BlobTransferId,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct TtlExpiryCycle {
    pub(crate) end_key: [u8; TTL_DEADLINE_KEY_BYTES],
    pub(crate) position: Option<[u8; TTL_DEADLINE_KEY_BYTES]>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum TtlExpiryPhase {
    Live,
    Pending,
}

impl TtlExpiryPhase {
    const fn tag(self) -> u8 {
        match self {
            Self::Live => 1,
            Self::Pending => 2,
        }
    }

    const fn cycle_key(self) -> u8 {
        match self {
            Self::Live => TTL_EXPIRY_LIVE_CYCLE_KEY,
            Self::Pending => TTL_EXPIRY_PENDING_CYCLE_KEY,
        }
    }

    const fn next(self) -> Self {
        match self {
            Self::Live => Self::Pending,
            Self::Pending => Self::Live,
        }
    }

    fn decode(tag: u8) -> Result<Self, StoreError> {
        match tag {
            1 => Ok(Self::Live),
            2 => Ok(Self::Pending),
            _ => Err(cursor_invariant("Blob TTL expiry phase is unknown")),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct TtlExpiryState {
    pub(crate) next_phase: TtlExpiryPhase,
    pub(crate) live: Option<TtlExpiryCycle>,
    pub(crate) pending: Option<TtlExpiryCycle>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct TtlExpiryTurn {
    pub(crate) deadline: Option<TtlDeadline>,
    captured_end_key: Option<[u8; TTL_DEADLINE_KEY_BYTES]>,
    observed_other_cycle: bool,
    other_probe_key: Option<[u8; TTL_DEADLINE_KEY_BYTES]>,
    phase: TtlExpiryPhase,
    next_cycle: Option<TtlExpiryCycle>,
}

pub(crate) fn ttl_deadline_key(
    deadline: TtlDeadline,
) -> Result<[u8; TTL_DEADLINE_KEY_BYTES], StoreError> {
    if deadline.generation == 0 || deadline.deadline.clock_id == [0; 16] {
        return Err(cursor_invariant(
            "Blob TTL deadline has invalid continuity authority",
        ));
    }
    let mut key = [0u8; TTL_DEADLINE_KEY_BYTES];
    key[0] = TTL_DEADLINE_VERSION;
    key[1..9].copy_from_slice(&deadline.generation.to_be_bytes());
    key[9..25].copy_from_slice(&deadline.deadline.clock_id);
    key[25] = deadline.kind.tag();
    key[26..34].copy_from_slice(&deadline.deadline.tick_ms.to_be_bytes());
    key[34..].copy_from_slice(deadline.transfer.as_bytes());
    Ok(key)
}

pub(crate) fn ttl_deadline_for_lifetime(
    transfer: BlobTransferId,
    kind: TtlDeadlineKind,
    lifetime: super::BlobLifetime,
    continuity: Option<super::custody::LowerBoundContinuity>,
    sample: Option<CustodySample>,
) -> Result<Option<TtlDeadline>, StoreError> {
    let deadline = match super::evaluate_blob_lifetime(lifetime, continuity, sample)? {
        super::BlobLifetimeEvaluation::Durable
        | super::BlobLifetimeEvaluation::FiniteExpired { .. } => None,
        super::BlobLifetimeEvaluation::FiniteLive { deadline, .. } => Some(deadline),
        super::BlobLifetimeEvaluation::FiniteIndeterminate { deadline, .. } => deadline,
    };
    deadline
        .map(|deadline| {
            let continuity = continuity
                .ok_or_else(|| cursor_invariant("Blob TTL deadline lacks continuity authority"))?;
            if deadline.clock_id != continuity.sample.clock_id {
                return Err(cursor_invariant(
                    "Blob TTL deadline differs from its continuity authority",
                ));
            }
            Ok(TtlDeadline {
                generation: continuity.generation,
                deadline,
                kind,
                transfer,
            })
        })
        .transpose()
}

fn project_lifetime_for_v5(
    lifetime: super::BlobLifetime,
    continuity: Option<custody::LowerBoundContinuity>,
) -> Result<super::BlobLifetime, StoreError> {
    let super::BlobLifetime::Finite {
        ttl_ms,
        age,
        provenance,
    } = lifetime
    else {
        return Ok(super::BlobLifetime::Durable);
    };
    let sample = continuity.map(|authority| authority.sample);
    // Keep the shared evaluator as the overflow/canonicality authority, then
    // persist the exact checkpoint projection from which v5 indexes derive.
    let _ = super::evaluate_blob_lifetime(lifetime, continuity, sample)?;
    Ok(super::BlobLifetime::Finite {
        ttl_ms,
        age: custody::project_lower_bound_age(age, continuity, sample),
        provenance,
    })
}

fn lifecycle_v5_enabled_write(write: &redb::WriteTransaction) -> Result<bool, StoreError> {
    #[cfg(test)]
    if TEST_BLOB_LIFECYCLE_MIGRATION_DISABLED.get() {
        return Ok(false);
    }
    let version = write
        .open_table(BLOB_LIFECYCLE_METADATA)?
        .get(BLOB_LIFECYCLE_SCHEMA_VERSION_FIELD)?
        .map(|value| value.value())
        .ok_or_else(|| cursor_invariant("Blob lifecycle schema version is missing"))?;
    match version {
        BLOB_LIFECYCLE_SCHEMA_VERSION => Ok(true),
        1 | 2 | 3 | PREVIOUS_BLOB_LIFECYCLE_SCHEMA_VERSION => Ok(false),
        _ => Err(cursor_invariant("Blob lifecycle schema version is unknown")),
    }
}

pub(crate) fn project_lifetime_for_policy_write(
    write: &redb::WriteTransaction,
    lifetime: super::BlobLifetime,
) -> Result<super::BlobLifetime, StoreError> {
    if !lifecycle_v5_enabled_write(write)? {
        return Ok(lifetime);
    }
    project_lifetime_for_v5(lifetime, custody::lower_bound_continuity_write(write)?)
}

pub(crate) fn project_lifetime_for_policy_read(
    read: &redb::ReadTransaction,
    lifetime: super::BlobLifetime,
) -> Result<super::BlobLifetime, StoreError> {
    let version = read
        .open_table(BLOB_LIFECYCLE_METADATA)?
        .get(BLOB_LIFECYCLE_SCHEMA_VERSION_FIELD)?
        .map(|value| value.value())
        .ok_or_else(|| cursor_invariant("Blob lifecycle schema version is missing"))?;
    if version != BLOB_LIFECYCLE_SCHEMA_VERSION {
        return Ok(lifetime);
    }
    project_lifetime_for_v5(lifetime, custody::lower_bound_continuity_read(read)?)
}

pub(crate) fn replace_policy_ttl_deadline_write(
    write: &redb::WriteTransaction,
    transfer: BlobTransferId,
    kind: TtlDeadlineKind,
    old_lifetime: Option<super::BlobLifetime>,
    new_lifetime: Option<super::BlobLifetime>,
    limits: BlobLifecycleLimits,
) -> Result<(), StoreError> {
    if !lifecycle_v5_enabled_write(write)? {
        return Ok(());
    }
    let max_rows = limits
        .max_publication_rows()
        .checked_add(super::MAX_BLOB_NETWORK_STAGING_ROWS)
        .ok_or(StoreError::ItemCountAccountingOverflow)?;
    replace_ttl_deadline_write(write, transfer, kind, old_lifetime, new_lifetime, max_rows)
}

/// Atomically moves one finite deadline between pending and live root classes
/// without transiently consuming a second row at the exact combined cap.
pub(crate) fn move_policy_ttl_deadline_kind_write(
    write: &redb::WriteTransaction,
    transfer: BlobTransferId,
    lifetime: super::BlobLifetime,
    from: TtlDeadlineKind,
    to: TtlDeadlineKind,
) -> Result<(), StoreError> {
    if !lifecycle_v5_enabled_write(write)? || from == to {
        return Ok(());
    }
    let old = stored_ttl_deadline(transfer, from, lifetime)?;
    let new = stored_ttl_deadline(transfer, to, lifetime)?;
    match (old, new) {
        (None, None) => Ok(()),
        (Some(old), Some(new)) => {
            let old_key = ttl_deadline_key(old)?;
            let new_key = ttl_deadline_key(new)?;
            let deadlines = write.open_table(BLOB_TTL_DEADLINES)?;
            let old_value = deadlines
                .get(old_key.as_slice())?
                .ok_or_else(|| cursor_invariant("Blob TTL deadline predecessor is missing"))?;
            if !old_value.value().is_empty() || deadlines.get(new_key.as_slice())?.is_some() {
                return Err(cursor_invariant(
                    "Blob TTL deadline kind move is contradictory",
                ));
            }
            drop(old_value);
            drop(deadlines);
            let mut deadlines = write.open_table(BLOB_TTL_DEADLINES)?;
            deadlines.remove(old_key.as_slice())?;
            deadlines.insert(new_key.as_slice(), &[] as &[u8])?;
            Ok(())
        }
        _ => Err(cursor_invariant(
            "Blob TTL deadline kind move changed finite indexability",
        )),
    }
}

/// Preflights every dedicated TTL authority row changed by one lifetime
/// replacement.  Successor keys are charged separately because inserting the
/// new ordered row is an independent bounded write.
pub(crate) fn charge_policy_ttl_deadline_write(
    transfer: BlobTransferId,
    kind: TtlDeadlineKind,
    old_lifetime: Option<super::BlobLifetime>,
    new_lifetime: Option<super::BlobLifetime>,
    charge: &mut super::MaintenanceCharge,
) -> Result<bool, StoreError> {
    charge_policy_ttl_deadline_write_with_counter(
        transfer,
        kind,
        old_lifetime,
        new_lifetime,
        true,
        charge,
    )
}

pub(crate) fn charge_policy_ttl_deadline_write_with_counter(
    transfer: BlobTransferId,
    kind: TtlDeadlineKind,
    old_lifetime: Option<super::BlobLifetime>,
    new_lifetime: Option<super::BlobLifetime>,
    charge_counter: bool,
    charge: &mut super::MaintenanceCharge,
) -> Result<bool, StoreError> {
    let old_key = old_lifetime
        .map(|lifetime| stored_ttl_deadline(transfer, kind, lifetime))
        .transpose()?
        .flatten()
        .map(ttl_deadline_key)
        .transpose()?;
    let new_key = new_lifetime
        .map(|lifetime| stored_ttl_deadline(transfer, kind, lifetime))
        .transpose()?
        .flatten()
        .map(ttl_deadline_key)
        .transpose()?;
    if old_key == new_key {
        return Ok(true);
    }
    if let Some(old_key) = old_key
        && !charge.charge_row(
            super::MaintenanceRowIdentity::new("aster.blob-ttl-deadlines.v1", old_key.as_slice()),
            0,
        )?
    {
        return Ok(false);
    }
    if let Some(new_key) = new_key
        && !charge.charge_row(
            super::MaintenanceRowIdentity::new("aster.blob-ttl-deadlines.v1", new_key.as_slice()),
            0,
        )?
    {
        return Ok(false);
    }
    if charge_counter {
        charge_ttl_deadline_counter(charge)
    } else {
        Ok(true)
    }
}

pub(crate) fn charge_ttl_deadline_counter(
    charge: &mut super::MaintenanceCharge,
) -> Result<bool, StoreError> {
    charge.charge_row(
        super::MaintenanceRowIdentity::new(
            "aster.blob-lifecycle-metadata.v1",
            BLOB_TTL_DEADLINE_ROWS.as_bytes(),
        ),
        std::mem::size_of::<u64>(),
    )
}

/// Preflights the selected cycle row and alternating-phase row advanced by a
/// completed expiry unit.
pub(crate) fn charge_ttl_expiry_turn_write(
    write: &redb::WriteTransaction,
    turn: TtlExpiryTurn,
    charge: &mut super::MaintenanceCharge,
) -> Result<bool, StoreError> {
    let cursors = write.open_table(BLOB_TTL_EXPIRY_CURSORS)?;
    let cycle = cursors
        .get(turn.phase.cycle_key())?
        .ok_or_else(|| cursor_invariant("Blob TTL expiry cycle is missing"))?;
    if !charge.charge_row(
        super::MaintenanceRowIdentity::new(
            "aster.blob-ttl-expiry-cursors.v1",
            [turn.phase.cycle_key()],
        ),
        cycle.value().len(),
    )? {
        return Ok(false);
    }
    let phase = cursors
        .get(TTL_EXPIRY_NEXT_PHASE_KEY)?
        .ok_or_else(|| cursor_invariant("Blob TTL expiry phase is missing"))?;
    if !charge.charge_row(
        super::MaintenanceRowIdentity::new(
            "aster.blob-ttl-expiry-cursors.v1",
            [TTL_EXPIRY_NEXT_PHASE_KEY],
        ),
        phase.value().len(),
    )? {
        return Ok(false);
    }
    if turn.observed_other_cycle {
        let other = cursors
            .get(turn.phase.next().cycle_key())?
            .ok_or_else(|| cursor_invariant("Blob TTL other expiry cycle is missing"))?;
        if !charge.charge_row(
            super::MaintenanceRowIdentity::new(
                "aster.blob-ttl-expiry-cursors.v1",
                [turn.phase.next().cycle_key()],
            ),
            other.value().len(),
        )? {
            return Ok(false);
        }
    }
    if let Some(key) = turn.other_probe_key
        && !charge.charge_row(
            super::MaintenanceRowIdentity::new("aster.blob-ttl-deadlines.v1", key),
            0,
        )?
    {
        return Ok(false);
    }
    turn.captured_end_key.map_or(Ok(true), |key| {
        charge.charge_row(
            super::MaintenanceRowIdentity::new("aster.blob-ttl-deadlines.v1", key),
            0,
        )
    })
}

pub(crate) fn charge_ttl_expiry_sync_state_write(
    write: &redb::WriteTransaction,
    charge: &mut super::MaintenanceCharge,
) -> Result<bool, StoreError> {
    let cursors = write.open_table(BLOB_TTL_EXPIRY_CURSORS)?;
    for key in [
        TTL_EXPIRY_NEXT_PHASE_KEY,
        TTL_EXPIRY_LIVE_CYCLE_KEY,
        TTL_EXPIRY_PENDING_CYCLE_KEY,
    ] {
        let value = cursors
            .get(key)?
            .ok_or_else(|| cursor_invariant("Blob TTL expiry synchronization row is missing"))?;
        if !charge.charge_row(
            super::MaintenanceRowIdentity::new("aster.blob-ttl-expiry-cursors.v1", [key]),
            value.value().len(),
        )? {
            return Ok(false);
        }
    }
    Ok(true)
}

pub(crate) fn decode_ttl_deadline_key(key: &[u8]) -> Result<TtlDeadline, StoreError> {
    let key: [u8; TTL_DEADLINE_KEY_BYTES] = key
        .try_into()
        .map_err(|_| cursor_invariant("Blob TTL deadline key has an invalid length"))?;
    if key[0] != TTL_DEADLINE_VERSION {
        return Err(cursor_invariant(
            "Blob TTL deadline key has an unknown version",
        ));
    }
    let deadline = TtlDeadline {
        generation: u64::from_be_bytes(key[1..9].try_into().expect("generation bytes")),
        deadline: CustodySample {
            clock_id: key[9..25].try_into().expect("clock bytes"),
            tick_ms: u64::from_be_bytes(key[26..34].try_into().expect("tick bytes")),
        },
        kind: TtlDeadlineKind::decode(key[25])?,
        transfer: BlobTransferId::new(key[34..].try_into().expect("transfer bytes")),
    };
    if deadline.generation == 0 || deadline.deadline.clock_id == [0; 16] {
        return Err(cursor_invariant(
            "Blob TTL deadline key has invalid continuity authority",
        ));
    }
    if ttl_deadline_key(deadline)? != key {
        return Err(cursor_invariant("Blob TTL deadline key is not canonical"));
    }
    Ok(deadline)
}

pub(crate) fn insert_ttl_deadline_write(
    write: &redb::WriteTransaction,
    deadline: TtlDeadline,
) -> Result<(), StoreError> {
    let key = ttl_deadline_key(deadline)?;
    let empty: &[u8] = &[];
    let mut deadlines = write.open_table(BLOB_TTL_DEADLINES)?;
    let previous = deadlines.insert(key.as_slice(), empty)?;
    if previous.is_some_and(|value| !value.value().is_empty()) {
        return Err(cursor_invariant("Blob TTL deadline value is not empty"));
    }
    Ok(())
}

fn stored_ttl_deadline(
    transfer: BlobTransferId,
    kind: TtlDeadlineKind,
    lifetime: super::BlobLifetime,
) -> Result<Option<TtlDeadline>, StoreError> {
    super::validate_blob_lifetime(lifetime)?;
    let super::BlobLifetime::Finite { ttl_ms, age, .. } = lifetime else {
        return Ok(None);
    };
    let Some(checkpoint) = age.checkpoint else {
        return Ok(None);
    };
    // Every active finite root with trusted clock authority remains indexed,
    // including one already due but not yet retired by its bounded
    // maintenance unit. A predecessor migration can discover an already-due
    // root; anchoring that case at its persisted checkpoint makes it
    // immediately selectable without inventing cross-domain elapsed time.
    let tick_ms = if age.cumulative_age_ms >= ttl_ms {
        checkpoint.tick_ms
    } else {
        checkpoint
            .tick_ms
            .saturating_add(ttl_ms - age.cumulative_age_ms)
    };
    Ok(Some(TtlDeadline {
        generation: age.continuity_generation,
        deadline: CustodySample {
            clock_id: checkpoint.clock_id,
            tick_ms,
        },
        kind,
        transfer,
    }))
}

/// Atomically replaces the exact dedicated TTL deadline derived from one
/// authoritative root lifetime and maintains its bounded metadata count.
pub(crate) fn replace_ttl_deadline_write(
    write: &redb::WriteTransaction,
    transfer: BlobTransferId,
    kind: TtlDeadlineKind,
    old_lifetime: Option<super::BlobLifetime>,
    new_lifetime: Option<super::BlobLifetime>,
    max_rows: u64,
) -> Result<(), StoreError> {
    let old = old_lifetime
        .map(|lifetime| stored_ttl_deadline(transfer, kind, lifetime))
        .transpose()?
        .flatten();
    let new = new_lifetime
        .map(|lifetime| stored_ttl_deadline(transfer, kind, lifetime))
        .transpose()?
        .flatten();
    let old_key = old.map(ttl_deadline_key).transpose()?;
    let new_key = new.map(ttl_deadline_key).transpose()?;

    let metadata = write.open_table(BLOB_LIFECYCLE_METADATA)?;
    let current = metadata
        .get(BLOB_TTL_DEADLINE_ROWS)?
        .map(|value| value.value())
        .ok_or_else(|| cursor_invariant("Blob TTL deadline row count is missing"))?;
    drop(metadata);
    let next = current
        .checked_sub(u64::from(old_key.is_some() && old_key != new_key))
        .and_then(|count| count.checked_add(u64::from(new_key.is_some() && old_key != new_key)))
        .ok_or_else(|| cursor_invariant("Blob TTL deadline row count underflows or overflows"))?;
    if next > max_rows {
        return Err(cursor_invariant("Blob TTL deadline row limit is exceeded"));
    }

    let deadlines = write.open_table(BLOB_TTL_DEADLINES)?;
    if let Some(old_key) = old_key {
        let old_value = deadlines
            .get(old_key.as_slice())?
            .ok_or_else(|| cursor_invariant("Blob TTL deadline predecessor is missing"))?;
        if !old_value.value().is_empty() {
            return Err(cursor_invariant("Blob TTL deadline value is not empty"));
        }
    }
    if old_key != new_key
        && let Some(new_key) = new_key
        && deadlines.get(new_key.as_slice())?.is_some()
    {
        return Err(cursor_invariant(
            "Blob TTL deadline successor already exists",
        ));
    }
    drop(deadlines);

    if old_key != new_key {
        let mut deadlines = write.open_table(BLOB_TTL_DEADLINES)?;
        if let Some(old_key) = old_key {
            deadlines.remove(old_key.as_slice())?;
        }
        if let Some(new_key) = new_key {
            deadlines.insert(new_key.as_slice(), &[] as &[u8])?;
        }
        drop(deadlines);
        write
            .open_table(BLOB_LIFECYCLE_METADATA)?
            .insert(BLOB_TTL_DEADLINE_ROWS, next)?;
    }
    Ok(())
}

fn ttl_deadline_range_key(
    generation: u64,
    sample: CustodySample,
    kind: TtlDeadlineKind,
    transfer: [u8; 32],
) -> Result<[u8; TTL_DEADLINE_KEY_BYTES], StoreError> {
    ttl_deadline_key(TtlDeadline {
        generation,
        deadline: sample,
        kind,
        transfer: BlobTransferId::new(transfer),
    })
}

pub(crate) fn capture_ttl_due_end_write(
    write: &redb::WriteTransaction,
    generation: u64,
    sample: CustodySample,
    kind: TtlDeadlineKind,
) -> Result<Option<[u8; TTL_DEADLINE_KEY_BYTES]>, StoreError> {
    use std::ops::Bound::Included;

    let start = ttl_deadline_range_key(
        generation,
        CustodySample {
            clock_id: sample.clock_id,
            tick_ms: 0,
        },
        kind,
        [0; 32],
    )?;
    let end = ttl_deadline_range_key(generation, sample, kind, [0xff; 32])?;
    let table = write.open_table(BLOB_TTL_DEADLINES)?;
    let row = table
        .range::<&[u8]>((Included(start.as_slice()), Included(end.as_slice())))?
        .next_back()
        .transpose()?;
    row.map(|(key, value)| {
        if !value.value().is_empty() {
            return Err(cursor_invariant("Blob TTL deadline value is not empty"));
        }
        let key: [u8; TTL_DEADLINE_KEY_BYTES] = key
            .value()
            .try_into()
            .map_err(|_| cursor_invariant("Blob TTL deadline key has an invalid length"))?;
        decode_ttl_deadline_key(&key)?;
        Ok(key)
    })
    .transpose()
}

pub(crate) fn nearest_ttl_deadline_read(
    read: &redb::ReadTransaction,
    continuity: super::custody::LowerBoundContinuity,
) -> Result<Option<CustodySample>, StoreError> {
    use std::ops::Bound::Included;

    let version = read
        .open_table(BLOB_LIFECYCLE_METADATA)?
        .get(BLOB_LIFECYCLE_SCHEMA_VERSION_FIELD)?
        .map(|value| value.value())
        .ok_or_else(|| cursor_invariant("Blob lifecycle schema version is missing"))?;
    if version != BLOB_LIFECYCLE_SCHEMA_VERSION {
        return Ok(None);
    }
    let deadlines = read.open_table(BLOB_TTL_DEADLINES)?;
    let mut nearest = None;
    for kind in [
        TtlDeadlineKind::LivePublication,
        TtlDeadlineKind::PendingSource,
    ] {
        let start = ttl_deadline_range_key(
            continuity.generation,
            CustodySample {
                clock_id: continuity.sample.clock_id,
                tick_ms: 0,
            },
            kind,
            [0; 32],
        )?;
        let end = ttl_deadline_range_key(
            continuity.generation,
            CustodySample {
                clock_id: continuity.sample.clock_id,
                tick_ms: u64::MAX,
            },
            kind,
            [0xff; 32],
        )?;
        if let Some((key, value)) = deadlines
            .range::<&[u8]>((Included(start.as_slice()), Included(end.as_slice())))?
            .next()
            .transpose()?
        {
            if !value.value().is_empty() {
                return Err(cursor_invariant("Blob TTL deadline value is not empty"));
            }
            let deadline = decode_ttl_deadline_key(key.value())?;
            nearest = Some(nearest.map_or(deadline.deadline, |current: CustodySample| {
                if deadline.deadline.tick_ms < current.tick_ms {
                    deadline.deadline
                } else {
                    current
                }
            }));
        }
    }
    Ok(nearest)
}

pub(crate) fn next_ttl_due_in_cycle_write(
    write: &redb::WriteTransaction,
    cycle: &TtlExpiryCycle,
) -> Result<Option<TtlDeadline>, StoreError> {
    use std::ops::Bound::{Excluded, Included};

    let end = decode_ttl_deadline_key(&cycle.end_key)?;
    if let Some(position) = cycle.position {
        let position_deadline = decode_ttl_deadline_key(&position)?;
        if position_deadline.generation != end.generation
            || position_deadline.deadline.clock_id != end.deadline.clock_id
            || position_deadline.kind != end.kind
            || position > cycle.end_key
        {
            return Err(cursor_invariant(
                "Blob TTL expiry cycle position exceeds or crosses its fence",
            ));
        }
    }
    let start = ttl_deadline_range_key(
        end.generation,
        CustodySample {
            clock_id: end.deadline.clock_id,
            tick_ms: 0,
        },
        end.kind,
        [0; 32],
    )?;
    let table = write.open_table(BLOB_TTL_DEADLINES)?;
    let row = match cycle.position.as_ref() {
        Some(position) => table
            .range::<&[u8]>((
                Excluded(position.as_slice()),
                Included(cycle.end_key.as_slice()),
            ))?
            .next()
            .transpose()?,
        None => table
            .range::<&[u8]>((
                Included(start.as_slice()),
                Included(cycle.end_key.as_slice()),
            ))?
            .next()
            .transpose()?,
    };
    row.map(|(key, value)| {
        if !value.value().is_empty() {
            return Err(cursor_invariant("Blob TTL deadline value is not empty"));
        }
        decode_ttl_deadline_key(key.value())
    })
    .transpose()
}

pub(crate) fn encode_ttl_expiry_cycle(cycle: Option<&TtlExpiryCycle>) -> Vec<u8> {
    let Some(cycle) = cycle else {
        return vec![TTL_EXPIRY_CYCLE_VERSION, TTL_EXPIRY_CYCLE_IDLE];
    };
    let mut encoded = Vec::with_capacity(
        3 + TTL_DEADLINE_KEY_BYTES + cycle.position.map_or(0, |_| TTL_DEADLINE_KEY_BYTES),
    );
    encoded.push(TTL_EXPIRY_CYCLE_VERSION);
    encoded.push(TTL_EXPIRY_CYCLE_ACTIVE);
    encoded.extend_from_slice(&cycle.end_key);
    encoded.push(if cycle.position.is_some() {
        TTL_EXPIRY_CYCLE_POSITION
    } else {
        TTL_EXPIRY_CYCLE_NO_POSITION
    });
    if let Some(position) = cycle.position {
        encoded.extend_from_slice(&position);
    }
    encoded
}

pub(crate) fn decode_ttl_expiry_cycle(
    encoded: &[u8],
) -> Result<Option<TtlExpiryCycle>, StoreError> {
    if encoded == [TTL_EXPIRY_CYCLE_VERSION, TTL_EXPIRY_CYCLE_IDLE] {
        return Ok(None);
    }
    if encoded.len() < 3 + TTL_DEADLINE_KEY_BYTES
        || encoded[0] != TTL_EXPIRY_CYCLE_VERSION
        || encoded[1] != TTL_EXPIRY_CYCLE_ACTIVE
    {
        return Err(cursor_invariant(
            "Blob TTL expiry cycle has a noncanonical encoding",
        ));
    }
    let end_key: [u8; TTL_DEADLINE_KEY_BYTES] = encoded[2..2 + TTL_DEADLINE_KEY_BYTES]
        .try_into()
        .expect("checked TTL cycle end length");
    let end = decode_ttl_deadline_key(&end_key)?;
    let position: Option<[u8; TTL_DEADLINE_KEY_BYTES]> = match encoded[2 + TTL_DEADLINE_KEY_BYTES] {
        TTL_EXPIRY_CYCLE_NO_POSITION if encoded.len() == 3 + TTL_DEADLINE_KEY_BYTES => None,
        TTL_EXPIRY_CYCLE_POSITION if encoded.len() == 3 + (2 * TTL_DEADLINE_KEY_BYTES) => Some(
            encoded[3 + TTL_DEADLINE_KEY_BYTES..]
                .try_into()
                .expect("checked TTL cycle position length"),
        ),
        _ => {
            return Err(cursor_invariant(
                "Blob TTL expiry cycle has a noncanonical position",
            ));
        }
    };
    if let Some(position) = position {
        let decoded = decode_ttl_deadline_key(&position)?;
        if decoded.generation != end.generation
            || decoded.deadline.clock_id != end.deadline.clock_id
            || decoded.kind != end.kind
            || position > end_key
        {
            return Err(cursor_invariant(
                "Blob TTL expiry cycle position exceeds or crosses its fence",
            ));
        }
    }
    Ok(Some(TtlExpiryCycle { end_key, position }))
}

fn decode_ttl_expiry_phase(encoded: &[u8]) -> Result<TtlExpiryPhase, StoreError> {
    let [version, phase] = encoded else {
        return Err(cursor_invariant(
            "Blob TTL expiry phase has an invalid length",
        ));
    };
    if *version != TTL_EXPIRY_CYCLE_VERSION {
        return Err(cursor_invariant(
            "Blob TTL expiry phase has an unknown version",
        ));
    }
    TtlExpiryPhase::decode(*phase)
}

fn load_ttl_expiry_state(
    cursors: &impl ReadableTable<u8, &'static [u8]>,
) -> Result<TtlExpiryState, StoreError> {
    if cursors.len()? != 3 {
        return Err(cursor_invariant(
            "Blob TTL expiry cursor set is incomplete or contains unknown rows",
        ));
    }
    let next_phase = cursors
        .get(TTL_EXPIRY_NEXT_PHASE_KEY)?
        .ok_or_else(|| cursor_invariant("Blob TTL expiry phase is missing"))?;
    let live = cursors
        .get(TTL_EXPIRY_LIVE_CYCLE_KEY)?
        .ok_or_else(|| cursor_invariant("Blob TTL live cycle is missing"))?;
    let pending = cursors
        .get(TTL_EXPIRY_PENDING_CYCLE_KEY)?
        .ok_or_else(|| cursor_invariant("Blob TTL pending cycle is missing"))?;
    let state = TtlExpiryState {
        next_phase: decode_ttl_expiry_phase(next_phase.value())?,
        live: decode_ttl_expiry_cycle(live.value())?,
        pending: decode_ttl_expiry_cycle(pending.value())?,
    };
    for (phase, cycle) in [
        (TtlExpiryPhase::Live, state.live),
        (TtlExpiryPhase::Pending, state.pending),
    ] {
        if cycle.is_some_and(|cycle| {
            decode_ttl_deadline_key(&cycle.end_key)
                .is_ok_and(|deadline| deadline.kind.tag() != phase.tag())
        }) {
            return Err(cursor_invariant(
                "Blob TTL expiry cycle belongs to the wrong phase",
            ));
        }
    }
    Ok(state)
}

pub(crate) fn initialize_ttl_expiry_cursors(
    write: &redb::WriteTransaction,
) -> Result<(), StoreError> {
    let mut cursors = write.open_table(BLOB_TTL_EXPIRY_CURSORS)?;
    if cursors.len()? != 0 {
        load_ttl_expiry_state(&cursors)?;
        return Ok(());
    }
    cursors.insert(
        TTL_EXPIRY_NEXT_PHASE_KEY,
        [TTL_EXPIRY_CYCLE_VERSION, TtlExpiryPhase::Live.tag()].as_slice(),
    )?;
    let idle = encode_ttl_expiry_cycle(None);
    cursors.insert(TTL_EXPIRY_LIVE_CYCLE_KEY, idle.as_slice())?;
    cursors.insert(TTL_EXPIRY_PENDING_CYCLE_KEY, idle.as_slice())?;
    Ok(())
}

pub(crate) fn load_ttl_expiry_state_write(
    write: &redb::WriteTransaction,
) -> Result<TtlExpiryState, StoreError> {
    load_ttl_expiry_state(&write.open_table(BLOB_TTL_EXPIRY_CURSORS)?)
}

/// Invalidates both fenced due cycles when custody continuity moves to a new
/// generation or clock domain.  Resetting the pair atomically prevents one
/// class from continuing a stale scan after the other observes the restart.
pub(crate) fn synchronize_ttl_expiry_cycles_write(
    write: &redb::WriteTransaction,
    generation: u64,
    sample: CustodySample,
) -> Result<(), StoreError> {
    if !lifecycle_v5_enabled_write(write)? {
        return Ok(());
    }
    if ttl_expiry_cycles_need_sync_write(write, generation, sample)? {
        let idle = encode_ttl_expiry_cycle(None);
        let mut cursors = write.open_table(BLOB_TTL_EXPIRY_CURSORS)?;
        cursors.insert(TTL_EXPIRY_LIVE_CYCLE_KEY, idle.as_slice())?;
        cursors.insert(TTL_EXPIRY_PENDING_CYCLE_KEY, idle.as_slice())?;
    }
    Ok(())
}

pub(crate) fn ttl_expiry_cycles_need_sync_write(
    write: &redb::WriteTransaction,
    generation: u64,
    sample: CustodySample,
) -> Result<bool, StoreError> {
    if !lifecycle_v5_enabled_write(write)? {
        return Ok(false);
    }
    let state = load_ttl_expiry_state_write(write)?;
    [state.live, state.pending]
        .into_iter()
        .flatten()
        .try_fold(false, |stale, cycle| {
            let end = decode_ttl_deadline_key(&cycle.end_key)?;
            Ok::<_, StoreError>(
                stale || end.generation != generation || end.deadline.clock_id != sample.clock_id,
            )
        })
}

pub(crate) fn store_ttl_expiry_turn(
    write: &redb::WriteTransaction,
    selected: TtlExpiryPhase,
    cycle: Option<&TtlExpiryCycle>,
) -> Result<(), StoreError> {
    let cursors = write.open_table(BLOB_TTL_EXPIRY_CURSORS)?;
    let current_phase = decode_ttl_expiry_phase(
        cursors
            .get(TTL_EXPIRY_NEXT_PHASE_KEY)?
            .ok_or_else(|| cursor_invariant("Blob TTL expiry phase is missing"))?
            .value(),
    )?;
    if current_phase != selected {
        return Err(cursor_invariant(
            "Blob TTL expiry turn does not match its persisted phase",
        ));
    }
    decode_ttl_expiry_cycle(
        cursors
            .get(selected.cycle_key())?
            .ok_or_else(|| cursor_invariant("Blob TTL selected expiry cycle is missing"))?
            .value(),
    )?;
    drop(cursors);
    if let Some(cycle) = cycle {
        let deadline = decode_ttl_deadline_key(&cycle.end_key)?;
        let expected = match selected {
            TtlExpiryPhase::Live => TtlDeadlineKind::LivePublication,
            TtlExpiryPhase::Pending => TtlDeadlineKind::PendingSource,
        };
        if deadline.kind != expected {
            return Err(cursor_invariant(
                "Blob TTL expiry turn stores a cross-phase cycle",
            ));
        }
        decode_ttl_expiry_cycle(&encode_ttl_expiry_cycle(Some(cycle)))?;
    }
    let mut cursors = write.open_table(BLOB_TTL_EXPIRY_CURSORS)?;
    cursors.insert(
        selected.cycle_key(),
        encode_ttl_expiry_cycle(cycle).as_slice(),
    )?;
    cursors.insert(
        TTL_EXPIRY_NEXT_PHASE_KEY,
        [TTL_EXPIRY_CYCLE_VERSION, selected.next().tag()].as_slice(),
    )?;
    Ok(())
}

/// Selects at most one already-due finite root from the persisted fenced
/// cycle for the next alternating live/pending phase. An empty phase still
/// advances the alternating scheduler in this transaction.
pub(crate) fn plan_ttl_expiry_turn_write(
    write: &redb::WriteTransaction,
    generation: u64,
    sample: CustodySample,
) -> Result<Option<TtlExpiryTurn>, StoreError> {
    if !lifecycle_v5_enabled_write(write)? {
        return Ok(None);
    }
    let cursors = write.open_table(BLOB_TTL_EXPIRY_CURSORS)?;
    let phase = decode_ttl_expiry_phase(
        cursors
            .get(TTL_EXPIRY_NEXT_PHASE_KEY)?
            .ok_or_else(|| cursor_invariant("Blob TTL expiry phase is missing"))?
            .value(),
    )?;
    let kind = match phase {
        TtlExpiryPhase::Live => TtlDeadlineKind::LivePublication,
        TtlExpiryPhase::Pending => TtlDeadlineKind::PendingSource,
    };
    let persisted_cycle = decode_ttl_expiry_cycle(
        cursors
            .get(phase.cycle_key())?
            .ok_or_else(|| cursor_invariant("Blob TTL selected expiry cycle is missing"))?
            .value(),
    )?;
    drop(cursors);
    let cycle = match persisted_cycle {
        Some(cycle) => Some(cycle),
        None => capture_ttl_due_end_write(write, generation, sample, kind)?.map(|end_key| {
            TtlExpiryCycle {
                end_key,
                position: None,
            }
        }),
    };
    let Some(cycle) = cycle else {
        let other_phase = phase.next();
        let other_kind = match other_phase {
            TtlExpiryPhase::Live => TtlDeadlineKind::LivePublication,
            TtlExpiryPhase::Pending => TtlDeadlineKind::PendingSource,
        };
        let other_cycle = decode_ttl_expiry_cycle(
            write
                .open_table(BLOB_TTL_EXPIRY_CURSORS)?
                .get(other_phase.cycle_key())?
                .ok_or_else(|| cursor_invariant("Blob TTL other expiry cycle is missing"))?
                .value(),
        )?;
        let other_probe_key = match other_cycle {
            Some(cycle) => next_ttl_due_in_cycle_write(write, &cycle)?
                .map(ttl_deadline_key)
                .transpose()?,
            None => capture_ttl_due_end_write(write, generation, sample, other_kind)?,
        };
        if other_probe_key.is_none() {
            return Ok(None);
        }
        return Ok(Some(TtlExpiryTurn {
            deadline: None,
            captured_end_key: None,
            observed_other_cycle: true,
            other_probe_key,
            phase,
            next_cycle: None,
        }));
    };
    let Some(deadline) = next_ttl_due_in_cycle_write(write, &cycle)? else {
        return Ok(Some(TtlExpiryTurn {
            deadline: None,
            captured_end_key: None,
            observed_other_cycle: false,
            other_probe_key: None,
            phase,
            next_cycle: None,
        }));
    };
    let selected_key = ttl_deadline_key(deadline)?;
    let next_cycle = (selected_key != cycle.end_key).then_some(TtlExpiryCycle {
        end_key: cycle.end_key,
        position: Some(selected_key),
    });
    Ok(Some(TtlExpiryTurn {
        deadline: Some(deadline),
        captured_end_key: (persisted_cycle.is_none() && selected_key != cycle.end_key)
            .then_some(cycle.end_key),
        observed_other_cycle: false,
        other_probe_key: None,
        phase,
        next_cycle,
    }))
}

/// Commits the cursor half of an expiry unit after the caller has atomically
/// retired or removed the selected root in the same write transaction.
pub(crate) fn finish_ttl_expiry_turn_write(
    write: &redb::WriteTransaction,
    turn: TtlExpiryTurn,
) -> Result<(), StoreError> {
    store_ttl_expiry_turn(write, turn.phase, turn.next_cycle.as_ref())
}

impl RetirementReason {
    pub(crate) const fn encode(self) -> u8 {
        match self {
            Self::Expired => 1,
            Self::Invalidated => 2,
            Self::Evicted => 3,
        }
    }

    pub(crate) const fn decode(value: u8) -> Option<Self> {
        match value {
            1 => Some(Self::Expired),
            2 => Some(Self::Invalidated),
            3 => Some(Self::Evicted),
            _ => None,
        }
    }
}

/// Durable conservative age of one retained retirement record.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct RetirementAge {
    age: CustodyAge,
    retain_for_ms: u64,
}

impl RetirementAge {
    pub(crate) const fn new(
        cumulative_age_ms: u64,
        checkpoint: CustodySample,
        retain_for_ms: u64,
    ) -> Result<Self, BlobStoreError> {
        if retain_for_ms == 0 {
            return Err(BlobStoreError::InvalidLifecycleLimits);
        }
        Ok(Self {
            age: CustodyAge::new(cumulative_age_ms, checkpoint),
            retain_for_ms,
        })
    }

    pub(crate) const fn unknown(retain_for_ms: u64) -> Result<Self, BlobStoreError> {
        if retain_for_ms == 0 {
            return Err(BlobStoreError::InvalidLifecycleLimits);
        }
        Ok(Self {
            age: CustodyAge::unknown(0),
            retain_for_ms,
        })
    }

    pub(crate) const fn cumulative_age_ms(self) -> u64 {
        self.age.cumulative_age_ms()
    }

    pub(crate) const fn checkpoint_sample(self) -> Option<CustodySample> {
        self.age.checkpoint_sample()
    }

    pub(crate) const fn is_lower_bound(self) -> bool {
        !self.age.is_continuous()
    }

    pub(crate) const fn retain_for_ms(self) -> u64 {
        self.retain_for_ms
    }

    pub(crate) fn encode(self) -> [u8; RETIREMENT_AGE_ENCODED_BYTES] {
        let mut encoded = [0u8; RETIREMENT_AGE_ENCODED_BYTES];
        encoded[0] = RETIREMENT_AGE_VERSION;
        encoded[1..9].copy_from_slice(&self.retain_for_ms.to_be_bytes());
        encoded[9..17].copy_from_slice(&self.age.cumulative_age_ms().to_be_bytes());
        encoded[17] = self.age.continuity().to_wire();
        if let Some(sample) = self.age.checkpoint_sample() {
            encoded[18] = 1;
            encoded[19..35].copy_from_slice(&sample.clock_id);
            encoded[35..43].copy_from_slice(&sample.tick_ms.to_be_bytes());
        }
        encoded
    }

    pub(crate) fn decode(bytes: &[u8]) -> Result<Self, BlobStoreError> {
        let bytes: [u8; RETIREMENT_AGE_ENCODED_BYTES] = bytes.try_into().map_err(|_| {
            BlobStoreError::SchemaInvariant("Blob retirement age has an invalid canonical length")
        })?;
        if bytes[0] != RETIREMENT_AGE_VERSION {
            return Err(BlobStoreError::SchemaInvariant(
                "Blob retirement age has an unknown encoding version",
            ));
        }
        let retain_for_ms = u64::from_be_bytes(bytes[1..9].try_into().expect("fixed retention"));
        if retain_for_ms == 0 {
            return Err(BlobStoreError::SchemaInvariant(
                "Blob retirement retention is zero",
            ));
        }
        let continuity = CustodyContinuity::from_wire(bytes[17]).ok_or(
            BlobStoreError::SchemaInvariant("Blob retirement age has unknown continuity"),
        )?;
        let checkpoint = match bytes[18] {
            0 if bytes[19..].iter().all(|byte| *byte == 0) => None,
            1 => Some(CustodySample {
                clock_id: bytes[19..35]
                    .try_into()
                    .expect("fixed retirement clock identifier"),
                tick_ms: u64::from_be_bytes(
                    bytes[35..43]
                        .try_into()
                        .expect("fixed retirement clock tick"),
                ),
            }),
            _ => {
                return Err(BlobStoreError::SchemaInvariant(
                    "Blob retirement age has a noncanonical checkpoint",
                ));
            }
        };
        CustodyAge::from_parts(
            u64::from_be_bytes(bytes[9..17].try_into().expect("fixed retirement age")),
            checkpoint,
            continuity,
        )
        .map(|age| Self { age, retain_for_ms })
        .map_err(|_| BlobStoreError::SchemaInvariant("Blob retirement age state is invalid"))
    }

    pub(crate) fn project(
        self,
        current: Option<CustodySample>,
    ) -> Result<RetirementClockProjection, BlobStoreError> {
        let mut age = self.age;
        if age.cumulative_age_ms() < self.retain_for_ms {
            match age.effective_age(current) {
                Ok(_) | Err(CustodyError::ContinuityUnavailable | CustodyError::AgeOverflow) => {}
                Err(CustodyError::InvalidState) => {
                    return Err(BlobStoreError::SchemaInvariant(
                        "Blob retirement age state is invalid",
                    ));
                }
                Err(CustodyError::InvalidClaims | CustodyError::ContextMismatch) => {
                    return Err(BlobStoreError::SchemaInvariant(
                        "Blob retirement clock returned an unrelated custody error",
                    ));
                }
            }
        }
        let age = Self {
            age,
            retain_for_ms: self.retain_for_ms,
        };
        let retention_elapsed = age.cumulative_age_ms() >= self.retain_for_ms;
        let deadline = if retention_elapsed {
            None
        } else {
            age.checkpoint_sample().and_then(|checkpoint| {
                checkpoint
                    .tick_ms
                    .checked_add(self.retain_for_ms - age.cumulative_age_ms())
                    .map(|tick_ms| CustodySample {
                        clock_id: checkpoint.clock_id,
                        tick_ms,
                    })
            })
        };
        Ok(RetirementClockProjection {
            age,
            is_lower_bound: age.is_lower_bound(),
            retention_elapsed,
            deadline,
        })
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct RetirementClockProjection {
    pub(crate) age: RetirementAge,
    pub(crate) is_lower_bound: bool,
    pub(crate) retention_elapsed: bool,
    pub(crate) deadline: Option<CustodySample>,
}

/// Canonical lifecycle state for a publication row.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum PublicationState {
    Live,
    Retired {
        reason: RetirementReason,
        generation: u64,
        age: RetirementAge,
    },
}

impl PublicationState {
    pub(crate) fn encode(self) -> Vec<u8> {
        match self {
            Self::Live => vec![PUBLICATION_STATE_LIVE_TAG],
            Self::Retired {
                reason,
                generation,
                age,
            } => {
                let mut encoded = Vec::with_capacity(2 + 8 + RETIREMENT_AGE_ENCODED_BYTES);
                encoded.push(PUBLICATION_STATE_RETIRED_TAG);
                encoded.push(reason.encode());
                encoded.extend_from_slice(&generation.to_be_bytes());
                encoded.extend_from_slice(&age.encode());
                encoded
            }
        }
    }

    pub(crate) fn decode(bytes: &[u8]) -> Result<Self, BlobStoreError> {
        match bytes {
            [PUBLICATION_STATE_LIVE_TAG] => Ok(Self::Live),
            [PUBLICATION_STATE_RETIRED_TAG, reason, body @ ..]
                if body.len() == 8 + RETIREMENT_AGE_ENCODED_BYTES =>
            {
                let generation =
                    u64::from_be_bytes(body[..8].try_into().expect("fixed retirement generation"));
                if generation == 0 {
                    return Err(BlobStoreError::SchemaInvariant(
                        "Blob publication retirement generation is zero",
                    ));
                }
                Ok(Self::Retired {
                    reason: RetirementReason::decode(*reason).ok_or(
                        BlobStoreError::SchemaInvariant(
                            "Blob publication retirement reason is unknown",
                        ),
                    )?,
                    generation,
                    age: RetirementAge::decode(&body[8..])?,
                })
            }
            _ => Err(BlobStoreError::SchemaInvariant(
                "Blob publication lifecycle state is not canonical",
            )),
        }
    }
}

/// Canonical lifecycle state for an idempotent Blob operation row.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum OperationState {
    Active,
    Retired {
        reason: RetirementReason,
        generation: u64,
        operation_key_digest: [u8; 32],
        intent_digest: [u8; 32],
        age: RetirementAge,
    },
}

impl OperationState {
    pub(crate) fn encode(self) -> Vec<u8> {
        match self {
            Self::Active => vec![OPERATION_STATE_ACTIVE_TAG],
            Self::Retired {
                reason,
                generation,
                operation_key_digest,
                intent_digest,
                age,
            } => {
                let mut encoded =
                    Vec::with_capacity(2 + 8 + 32 + 32 + RETIREMENT_AGE_ENCODED_BYTES);
                encoded.push(OPERATION_STATE_RETIRED_TAG);
                encoded.push(reason.encode());
                encoded.extend_from_slice(&generation.to_be_bytes());
                encoded.extend_from_slice(&operation_key_digest);
                encoded.extend_from_slice(&intent_digest);
                encoded.extend_from_slice(&age.encode());
                encoded
            }
        }
    }

    pub(crate) fn decode(bytes: &[u8]) -> Result<Self, BlobStoreError> {
        match bytes {
            [OPERATION_STATE_ACTIVE_TAG] => Ok(Self::Active),
            [OPERATION_STATE_RETIRED_TAG, reason, body @ ..]
                if body.len() == 8 + 32 + 32 + RETIREMENT_AGE_ENCODED_BYTES =>
            {
                let generation =
                    u64::from_be_bytes(body[..8].try_into().expect("fixed retirement generation"));
                if generation == 0 {
                    return Err(BlobStoreError::SchemaInvariant(
                        "Blob operation retirement generation is zero",
                    ));
                }
                Ok(Self::Retired {
                    reason: RetirementReason::decode(*reason).ok_or(
                        BlobStoreError::SchemaInvariant(
                            "Blob operation retirement reason is unknown",
                        ),
                    )?,
                    generation,
                    operation_key_digest: body[8..40]
                        .try_into()
                        .expect("fixed operation-key digest"),
                    intent_digest: body[40..72]
                        .try_into()
                        .expect("fixed operation-intent digest"),
                    age: RetirementAge::decode(&body[72..])?,
                })
            }
            _ => Err(BlobStoreError::SchemaInvariant(
                "Blob operation lifecycle state is not canonical",
            )),
        }
    }
}

/// Exact durable root kind for a variant reference.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum VariantReferenceOwner {
    Publication,
    PendingSource,
}

impl VariantReferenceOwner {
    pub(crate) const fn encode(self) -> [u8; 1] {
        match self {
            Self::Publication => [VARIANT_REFERENCE_PUBLICATION_TAG],
            Self::PendingSource => [VARIANT_REFERENCE_PENDING_SOURCE_TAG],
        }
    }

    pub(crate) fn decode(bytes: &[u8]) -> Result<Self, BlobStoreError> {
        match bytes {
            [VARIANT_REFERENCE_PUBLICATION_TAG] => Ok(Self::Publication),
            [VARIANT_REFERENCE_PENDING_SOURCE_TAG] => Ok(Self::PendingSource),
            _ => Err(BlobStoreError::SchemaInvariant(
                "Blob variant-reference owner is not canonical",
            )),
        }
    }
}

/// Fixed-width permanent evidence for one accepted physical Blob lineage.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct LineageFence {
    physical_lineage: [u8; 32],
    owner_binding: [u8; 32],
    bulk_reclamation_observed: bool,
}

impl LineageFence {
    const ENCODED_BYTES: usize = 65;

    pub(crate) const fn new(physical_lineage: [u8; 32], owner_binding: [u8; 32]) -> Self {
        Self {
            physical_lineage,
            owner_binding,
            bulk_reclamation_observed: false,
        }
    }

    const fn with_bulk_reclamation_observed(mut self) -> Self {
        self.bulk_reclamation_observed = true;
        self
    }

    fn same_authority(self, other: Self) -> bool {
        self.physical_lineage == other.physical_lineage && self.owner_binding == other.owner_binding
    }

    pub(crate) const fn bulk_reclamation_observed(self) -> bool {
        self.bulk_reclamation_observed
    }

    pub(crate) const fn encode(self) -> [u8; Self::ENCODED_BYTES] {
        let mut bytes = [0; Self::ENCODED_BYTES];
        bytes[0] = if self.bulk_reclamation_observed {
            RECLAIMED_LINEAGE_FENCE_VERSION
        } else {
            RECORD_VERSION
        };
        let mut index = 0;
        while index < 32 {
            bytes[1 + index] = self.physical_lineage[index];
            bytes[33 + index] = self.owner_binding[index];
            index += 1;
        }
        bytes
    }

    pub(crate) fn decode(bytes: &[u8]) -> Result<Self, BlobStoreError> {
        let bytes: [u8; Self::ENCODED_BYTES] = bytes.try_into().map_err(|_| {
            BlobStoreError::SchemaInvariant("Blob lineage fence has an invalid canonical length")
        })?;
        let bulk_reclamation_observed = match bytes[0] {
            RECORD_VERSION => false,
            RECLAIMED_LINEAGE_FENCE_VERSION => true,
            _ => {
                return Err(BlobStoreError::SchemaInvariant(
                    "Blob lineage fence has an unknown encoding version",
                ));
            }
        };
        Ok(Self {
            physical_lineage: bytes[1..33].try_into().expect("fixed lineage fence slice"),
            owner_binding: bytes[33..].try_into().expect("fixed lineage fence slice"),
            bulk_reclamation_observed,
        })
    }
}

/// Fixed-width permanent evidence for one accepted publisher dot.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct ReplayFence {
    publisher: [u8; 32],
    counter: u64,
    semantic_id: BlobSemanticId,
    transfer_id: BlobTransferId,
    source_len: u64,
    source_digest: [u8; 32],
}

impl ReplayFence {
    const ENCODED_BYTES: usize = 145;

    pub(crate) const fn new(
        publisher: [u8; 32],
        counter: u64,
        semantic_id: BlobSemanticId,
        transfer_id: BlobTransferId,
        source_len: u64,
        source_digest: [u8; 32],
    ) -> Self {
        Self {
            publisher,
            counter,
            semantic_id,
            transfer_id,
            source_len,
            source_digest,
        }
    }

    pub(crate) fn encode(self) -> [u8; Self::ENCODED_BYTES] {
        let mut bytes = [0; Self::ENCODED_BYTES];
        bytes[0] = RECORD_VERSION;
        bytes[1..33].copy_from_slice(&self.publisher);
        bytes[33..41].copy_from_slice(&self.counter.to_be_bytes());
        bytes[41..73].copy_from_slice(self.semantic_id.as_bytes());
        bytes[73..105].copy_from_slice(self.transfer_id.as_bytes());
        bytes[105..113].copy_from_slice(&self.source_len.to_be_bytes());
        bytes[113..].copy_from_slice(&self.source_digest);
        bytes
    }

    pub(crate) fn decode(bytes: &[u8]) -> Result<Self, BlobStoreError> {
        let bytes: [u8; Self::ENCODED_BYTES] = bytes.try_into().map_err(|_| {
            BlobStoreError::SchemaInvariant("Blob replay fence has an invalid canonical length")
        })?;
        if bytes[0] != RECORD_VERSION {
            return Err(BlobStoreError::SchemaInvariant(
                "Blob replay fence has an unknown encoding version",
            ));
        }
        Ok(Self::new(
            bytes[1..33].try_into().expect("fixed replay fence slice"),
            u64::from_be_bytes(
                bytes[33..41]
                    .try_into()
                    .expect("fixed replay fence counter slice"),
            ),
            BlobSemanticId::new(
                bytes[41..73]
                    .try_into()
                    .expect("fixed replay fence semantic ID slice"),
            ),
            BlobTransferId::new(
                bytes[73..105]
                    .try_into()
                    .expect("fixed replay fence transfer ID slice"),
            ),
            u64::from_be_bytes(
                bytes[105..113]
                    .try_into()
                    .expect("fixed replay fence source length slice"),
            ),
            bytes[113..]
                .try_into()
                .expect("fixed replay fence digest slice"),
        ))
    }

    pub(crate) const fn dot(self) -> crate::Dot {
        crate::Dot {
            publisher: self.publisher,
            counter: self.counter,
        }
    }

    pub(crate) const fn semantic_id(self) -> BlobSemanticId {
        self.semantic_id
    }

    pub(crate) const fn transfer_id(self) -> BlobTransferId {
        self.transfer_id
    }
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub(crate) struct BlobLifecycleUsage {
    pub(crate) lineage_rows: u64,
    pub(crate) lineage_bytes: u64,
    pub(crate) replay_rows: u64,
    pub(crate) replay_bytes: u64,
    pub(crate) publication_rows: u64,
    pub(crate) reference_rows: u64,
    pub(crate) operation_owner_rows: u64,
    pub(crate) delivery_owner_rows: u64,
    pub(crate) deadline_rows: u64,
    pub(crate) ttl_deadline_rows: u64,
    pub(crate) retirement_resolver_rows: u64,
    pub(crate) retired_publication_rows: u64,
    pub(crate) retired_operation_rows: u64,
    pub(crate) next_retirement_generation: u64,
}

impl BlobLifecycleUsage {
    pub(crate) fn apply_to_stats(self, stats: &mut BlobStoreStats) {
        stats.lineage_fences = self.lineage_rows;
        stats.lineage_fence_bytes = self.lineage_bytes;
        stats.replay_fences = self.replay_rows;
        stats.replay_fence_bytes = self.replay_bytes;
        stats.publication_lifecycle_rows = self.publication_rows;
        stats.variant_references = self.reference_rows;
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum LifecycleSchemaState {
    Legacy,
    V1,
    V2,
    V3,
    V4,
    Current,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum PublicationEncodingGeneration {
    RawPredecessor,
    RawCurrent,
    LifecycleV1,
    LifecycleV2OrV3,
    Current,
}

#[derive(Debug)]
struct ExpectedLifecycleImage {
    publications: BTreeMap<Vec<u8>, Vec<u8>>,
    pending_sources: BTreeMap<Vec<u8>, Vec<u8>>,
    live_publications: BTreeSet<Vec<u8>>,
    retired_publications: BTreeSet<Vec<u8>>,
    operations: BTreeMap<Vec<u8>, Vec<u8>>,
    references: BTreeMap<Vec<u8>, Vec<u8>>,
    lineages: BTreeMap<Vec<u8>, Vec<u8>>,
    replays: BTreeMap<Vec<u8>, Vec<u8>>,
    operation_owners: BTreeMap<Vec<u8>, Vec<u8>>,
    delivery_owners: BTreeMap<Vec<u8>, Vec<u8>>,
    deadlines: BTreeMap<Vec<u8>, Vec<u8>>,
    ttl_deadlines: BTreeMap<Vec<u8>, Vec<u8>>,
    retirement_resolvers: BTreeMap<Vec<u8>, Vec<u8>>,
    operation_bytes: u64,
    usage: BlobLifecycleUsage,
}

/// Fully preflighted predecessor-to-current lifecycle migration.
pub(crate) struct BlobLifecycleMigration {
    image: ExpectedLifecycleImage,
}

fn predecessor_lifecycle_table_names() -> [&'static str; 5] {
    [
        BLOB_LIFECYCLE_METADATA.name(),
        BLOB_VARIANT_REFERENCES.name(),
        BLOB_LINEAGE_FENCES.name(),
        BLOB_REPLAY_FENCES.name(),
        BLOB_MAINTENANCE_CURSORS.name(),
    ]
}

fn lifecycle_v2_table_names() -> [&'static str; 8] {
    [
        BLOB_LIFECYCLE_METADATA.name(),
        BLOB_VARIANT_REFERENCES.name(),
        BLOB_LINEAGE_FENCES.name(),
        BLOB_REPLAY_FENCES.name(),
        BLOB_MAINTENANCE_CURSORS.name(),
        BLOB_OPERATION_OWNERS.name(),
        BLOB_DELIVERY_OWNERS.name(),
        BLOB_RETENTION_DEADLINES.name(),
    ]
}

fn lifecycle_v4_table_names() -> [&'static str; 9] {
    [
        BLOB_LIFECYCLE_METADATA.name(),
        BLOB_VARIANT_REFERENCES.name(),
        BLOB_LINEAGE_FENCES.name(),
        BLOB_REPLAY_FENCES.name(),
        BLOB_MAINTENANCE_CURSORS.name(),
        BLOB_OPERATION_OWNERS.name(),
        BLOB_DELIVERY_OWNERS.name(),
        BLOB_RETENTION_DEADLINES.name(),
        BLOB_RETIREMENT_RESOLVERS.name(),
    ]
}

fn lifecycle_table_names() -> [&'static str; 11] {
    [
        BLOB_LIFECYCLE_METADATA.name(),
        BLOB_VARIANT_REFERENCES.name(),
        BLOB_LINEAGE_FENCES.name(),
        BLOB_REPLAY_FENCES.name(),
        BLOB_MAINTENANCE_CURSORS.name(),
        BLOB_OPERATION_OWNERS.name(),
        BLOB_DELIVERY_OWNERS.name(),
        BLOB_RETENTION_DEADLINES.name(),
        BLOB_RETIREMENT_RESOLVERS.name(),
        BLOB_TTL_DEADLINES.name(),
        BLOB_TTL_EXPIRY_CURSORS.name(),
    ]
}

fn lifecycle_schema_state(
    normal: &BTreeSet<String>,
    multimap: &BTreeSet<String>,
) -> Result<LifecycleSchemaState, StoreError> {
    let names = lifecycle_table_names();
    if multimap.iter().any(|name| names.contains(&name.as_str())) {
        return Err(StoreError::Blob(BlobStoreError::SchemaInvariant(
            "Blob lifecycle schema has the wrong table kind",
        )));
    }
    let present = names.iter().filter(|name| normal.contains(**name)).count();
    match present {
        0 => Ok(LifecycleSchemaState::Legacy),
        count
            if count == predecessor_lifecycle_table_names().len()
                && predecessor_lifecycle_table_names()
                    .iter()
                    .all(|name| normal.contains(*name)) =>
        {
            Ok(LifecycleSchemaState::V1)
        }
        count
            if count == lifecycle_v2_table_names().len()
                && lifecycle_v2_table_names()
                    .iter()
                    .all(|name| normal.contains(*name)) =>
        {
            Ok(LifecycleSchemaState::V2)
        }
        count
            if count == lifecycle_v4_table_names().len()
                && lifecycle_v4_table_names()
                    .iter()
                    .all(|name| normal.contains(*name)) =>
        {
            Ok(LifecycleSchemaState::V4)
        }
        count if count == names.len() => Ok(LifecycleSchemaState::Current),
        _ => Err(StoreError::Blob(BlobStoreError::SchemaInvariant(
            "Blob lifecycle schema group is incomplete",
        ))),
    }
}

fn lifecycle_schema_state_write(
    write: &redb::WriteTransaction,
) -> Result<LifecycleSchemaState, StoreError> {
    #[cfg(test)]
    TEST_BLOB_LIFECYCLE_SCHEMA_ENUMERATIONS.set(
        TEST_BLOB_LIFECYCLE_SCHEMA_ENUMERATIONS
            .get()
            .saturating_add(1),
    );
    lifecycle_schema_state(
        &write
            .list_tables()?
            .map(|table| table.name().to_owned())
            .collect(),
        &write
            .list_multimap_tables()?
            .map(|table| table.name().to_owned())
            .collect(),
    )
}

fn lifecycle_schema_state_read(
    read: &redb::ReadTransaction,
) -> Result<LifecycleSchemaState, StoreError> {
    #[cfg(test)]
    TEST_BLOB_LIFECYCLE_SCHEMA_ENUMERATIONS.set(
        TEST_BLOB_LIFECYCLE_SCHEMA_ENUMERATIONS
            .get()
            .saturating_add(1),
    );
    lifecycle_schema_state(
        &read
            .list_tables()?
            .map(|table| table.name().to_owned())
            .collect(),
        &read
            .list_multimap_tables()?
            .map(|table| table.name().to_owned())
            .collect(),
    )
}

pub(crate) fn require_blob_lifecycle_absent_write(
    write: &redb::WriteTransaction,
) -> Result<(), StoreError> {
    if lifecycle_schema_state_write(write)? != LifecycleSchemaState::Legacy
        || write
            .list_tables()?
            .any(|table| table.name() == BLOB_REPLAY_CAUSAL_FENCES.name())
        || write
            .list_multimap_tables()?
            .any(|table| table.name() == BLOB_REPLAY_CAUSAL_FENCES.name())
    {
        return Err(StoreError::Blob(BlobStoreError::SchemaInvariant(
            "Blob lifecycle authority exists without its base schema",
        )));
    }
    Ok(())
}

pub(crate) fn require_blob_lifecycle_absent_read(
    read: &redb::ReadTransaction,
) -> Result<(), StoreError> {
    if lifecycle_schema_state_read(read)? != LifecycleSchemaState::Legacy
        || read
            .list_tables()?
            .any(|table| table.name() == BLOB_REPLAY_CAUSAL_FENCES.name())
        || read
            .list_multimap_tables()?
            .any(|table| table.name() == BLOB_REPLAY_CAUSAL_FENCES.name())
    {
        return Err(StoreError::Blob(BlobStoreError::SchemaInvariant(
            "Blob lifecycle authority exists without its base schema",
        )));
    }
    Ok(())
}

pub(crate) fn publication_payload(bytes: &[u8]) -> Result<&[u8], BlobStoreError> {
    match bytes.first().copied() {
        Some(1..=3) => Ok(bytes),
        Some(PREDECESSOR_PUBLICATION_RECORD_VERSION | CURRENT_PUBLICATION_RECORD_VERSION) => {
            if bytes.len() < 3 {
                return Err(BlobStoreError::SchemaInvariant(
                    "Blob publication lifecycle wrapper is truncated",
                ));
            }
            if PublicationState::decode(&bytes[1..2])? != PublicationState::Live {
                return Err(BlobStoreError::SchemaInvariant(
                    "retired Blob publication has no live metadata payload",
                ));
            }
            if !matches!(bytes[2], 1..=3) {
                return Err(BlobStoreError::SchemaInvariant(
                    "Blob publication lifecycle wrapper has a noncanonical payload",
                ));
            }
            Ok(&bytes[2..])
        }
        _ => Err(BlobStoreError::SchemaInvariant(
            "Blob publication lifecycle wrapper has an unknown version",
        )),
    }
}

pub(crate) fn publication_payload_for_encoding(
    bytes: &[u8],
    generation: PublicationEncodingGeneration,
) -> Result<&[u8], BlobStoreError> {
    match generation {
        PublicationEncodingGeneration::RawPredecessor if matches!(bytes.first(), Some(1 | 2)) => {
            Ok(bytes)
        }
        PublicationEncodingGeneration::RawCurrent if bytes.first().copied() == Some(3) => Ok(bytes),
        PublicationEncodingGeneration::LifecycleV1
            if bytes.len() >= 3
                && bytes[0] == LIFECYCLE_V1_PUBLICATION_RECORD_VERSION
                && PublicationState::decode(&bytes[1..2])? == PublicationState::Live
                && matches!(bytes[2], 1 | 2) =>
        {
            Ok(&bytes[2..])
        }
        PublicationEncodingGeneration::LifecycleV2OrV3
            if bytes.first().copied() == Some(PREDECESSOR_PUBLICATION_RECORD_VERSION) =>
        {
            let payload = publication_payload(bytes)?;
            if !matches!(payload.first(), Some(1 | 2)) {
                return Err(BlobStoreError::SchemaInvariant(
                    "Blob publication payload contradicts its lifecycle schema",
                ));
            }
            Ok(payload)
        }
        PublicationEncodingGeneration::Current
            if bytes.first().copied() == Some(CURRENT_PUBLICATION_RECORD_VERSION) =>
        {
            let payload = publication_payload(bytes)?;
            if payload.first().copied() != Some(3) {
                return Err(BlobStoreError::SchemaInvariant(
                    "Blob publication payload contradicts its lifecycle schema",
                ));
            }
            Ok(payload)
        }
        _ => Err(BlobStoreError::SchemaInvariant(
            "Blob publication encoding contradicts its lifecycle schema",
        )),
    }
}

fn publication_encoding_from_schema(schema: LifecycleSchemaState) -> PublicationEncodingGeneration {
    match schema {
        LifecycleSchemaState::Legacy => PublicationEncodingGeneration::RawPredecessor,
        LifecycleSchemaState::V1 => PublicationEncodingGeneration::LifecycleV1,
        LifecycleSchemaState::V2 | LifecycleSchemaState::V3 => {
            PublicationEncodingGeneration::LifecycleV2OrV3
        }
        LifecycleSchemaState::V4 | LifecycleSchemaState::Current => {
            PublicationEncodingGeneration::Current
        }
    }
}

fn resolve_lifecycle_schema_version(
    table_state: LifecycleSchemaState,
    version: u64,
) -> Result<LifecycleSchemaState, StoreError> {
    match (table_state, version) {
        (LifecycleSchemaState::V4, 3) => Ok(LifecycleSchemaState::V3),
        (LifecycleSchemaState::V4, PREVIOUS_BLOB_LIFECYCLE_SCHEMA_VERSION) => {
            Ok(LifecycleSchemaState::V4)
        }
        (LifecycleSchemaState::Current, BLOB_LIFECYCLE_SCHEMA_VERSION) => {
            Ok(LifecycleSchemaState::Current)
        }
        _ => Err(StoreError::Blob(BlobStoreError::SchemaInvariant(
            "Blob lifecycle schema version contradicts its table group",
        ))),
    }
}

pub(crate) fn publication_encoding_write(
    write: &redb::WriteTransaction,
) -> Result<PublicationEncodingGeneration, StoreError> {
    #[cfg(test)]
    if TEST_BLOB_LIFECYCLE_MIGRATION_DISABLED.get() {
        return publication_encoding_migration_write(write);
    }
    match write
        .open_table(BLOB_LIFECYCLE_METADATA)?
        .get(BLOB_LIFECYCLE_SCHEMA_VERSION_FIELD)?
        .map(|value| value.value())
    {
        Some(3) => Ok(PublicationEncodingGeneration::LifecycleV2OrV3),
        Some(BLOB_LIFECYCLE_SCHEMA_VERSION) => Ok(PublicationEncodingGeneration::Current),
        _ => Err(StoreError::Blob(BlobStoreError::SchemaInvariant(
            "Blob lifecycle schema version is unknown",
        ))),
    }
}

pub(crate) fn publication_encoding_migration_read(
    read: &redb::ReadTransaction,
) -> Result<PublicationEncodingGeneration, StoreError> {
    let mut schema = lifecycle_schema_state_read(read)?;
    #[cfg(test)]
    if schema == LifecycleSchemaState::Legacy
        && TEST_BLOB_LIFECYCLE_MIGRATION_DISABLED.with(|disabled| disabled.get())
    {
        return Ok(PublicationEncodingGeneration::RawCurrent);
    }
    if matches!(
        schema,
        LifecycleSchemaState::V4 | LifecycleSchemaState::Current
    ) {
        let version = read
            .open_table(BLOB_LIFECYCLE_METADATA)?
            .get(BLOB_LIFECYCLE_SCHEMA_VERSION_FIELD)?
            .map(|value| value.value())
            .ok_or(StoreError::Blob(BlobStoreError::SchemaInvariant(
                "Blob lifecycle metadata lacks its schema version",
            )))?;
        schema = resolve_lifecycle_schema_version(schema, version)?;
    }
    Ok(publication_encoding_from_schema(schema))
}

pub(crate) fn publication_encoding_migration_write(
    write: &redb::WriteTransaction,
) -> Result<PublicationEncodingGeneration, StoreError> {
    let mut schema = lifecycle_schema_state_write(write)?;
    #[cfg(test)]
    if schema == LifecycleSchemaState::Legacy && TEST_BLOB_LIFECYCLE_MIGRATION_DISABLED.get() {
        return Ok(PublicationEncodingGeneration::RawCurrent);
    }
    if matches!(
        schema,
        LifecycleSchemaState::V4 | LifecycleSchemaState::Current
    ) {
        let version = write
            .open_table(BLOB_LIFECYCLE_METADATA)?
            .get(BLOB_LIFECYCLE_SCHEMA_VERSION_FIELD)?
            .map(|value| value.value())
            .ok_or(StoreError::Blob(BlobStoreError::SchemaInvariant(
                "Blob lifecycle metadata lacks its schema version",
            )))?;
        schema = resolve_lifecycle_schema_version(schema, version)?;
    }
    Ok(publication_encoding_from_schema(schema))
}

pub(crate) fn publication_encoding_read(
    read: &redb::ReadTransaction,
) -> Result<PublicationEncodingGeneration, StoreError> {
    #[cfg(test)]
    if TEST_BLOB_LIFECYCLE_MIGRATION_DISABLED.with(|disabled| disabled.get()) {
        return publication_encoding_migration_read(read);
    }
    match read
        .open_table(BLOB_LIFECYCLE_METADATA)?
        .get(BLOB_LIFECYCLE_SCHEMA_VERSION_FIELD)?
        .map(|value| value.value())
    {
        Some(3) => Ok(PublicationEncodingGeneration::LifecycleV2OrV3),
        Some(BLOB_LIFECYCLE_SCHEMA_VERSION) => Ok(PublicationEncodingGeneration::Current),
        _ => Err(StoreError::Blob(BlobStoreError::SchemaInvariant(
            "Blob lifecycle schema version is unknown",
        ))),
    }
}

pub(crate) fn lifecycle_generation_is_current_read(
    read: &redb::ReadTransaction,
) -> Result<bool, StoreError> {
    if !read
        .list_tables()?
        .any(|table| table.name() == BLOB_LIFECYCLE_METADATA.name())
    {
        return Ok(false);
    }
    Ok(matches!(
        read.open_table(BLOB_LIFECYCLE_METADATA)?
            .get(BLOB_LIFECYCLE_SCHEMA_VERSION_FIELD)?
            .map(|value| value.value()),
        Some(BLOB_LIFECYCLE_SCHEMA_VERSION)
    ))
}

pub(crate) fn publication_record_is_retired(bytes: &[u8]) -> Result<bool, BlobStoreError> {
    if !matches!(
        bytes.first().copied(),
        Some(PREDECESSOR_PUBLICATION_RECORD_VERSION | CURRENT_PUBLICATION_RECORD_VERSION)
    ) {
        return Ok(false);
    }
    match bytes.get(1).copied() {
        Some(PUBLICATION_STATE_LIVE_TAG) => {
            PublicationState::decode(&bytes[1..2])?;
            Ok(false)
        }
        Some(PUBLICATION_STATE_RETIRED_TAG) => {
            publication_retirement(bytes)?;
            Ok(true)
        }
        _ => Err(BlobStoreError::SchemaInvariant(
            "Blob publication lifecycle state is not canonical",
        )),
    }
}

pub(crate) fn publication_record_is_retired_for_encoding(
    bytes: &[u8],
    generation: PublicationEncodingGeneration,
) -> Result<bool, BlobStoreError> {
    match generation {
        PublicationEncodingGeneration::RawPredecessor
        | PublicationEncodingGeneration::RawCurrent
        | PublicationEncodingGeneration::LifecycleV1 => {
            publication_payload_for_encoding(bytes, generation)?;
            Ok(false)
        }
        PublicationEncodingGeneration::LifecycleV2OrV3 | PublicationEncodingGeneration::Current => {
            let expected = match generation {
                PublicationEncodingGeneration::LifecycleV2OrV3 => {
                    PREDECESSOR_PUBLICATION_RECORD_VERSION
                }
                PublicationEncodingGeneration::Current => CURRENT_PUBLICATION_RECORD_VERSION,
                PublicationEncodingGeneration::RawPredecessor
                | PublicationEncodingGeneration::RawCurrent
                | PublicationEncodingGeneration::LifecycleV1 => {
                    unreachable!("predecessor/current branch")
                }
            };
            if bytes.first().copied() != Some(expected) {
                return Err(BlobStoreError::SchemaInvariant(
                    "Blob publication encoding contradicts its lifecycle schema",
                ));
            }
            match bytes.get(1).copied() {
                Some(PUBLICATION_STATE_LIVE_TAG) => {
                    publication_payload_for_encoding(bytes, generation)?;
                    Ok(false)
                }
                Some(PUBLICATION_STATE_RETIRED_TAG) => {
                    publication_retirement(bytes)?;
                    Ok(true)
                }
                _ => Err(BlobStoreError::SchemaInvariant(
                    "Blob publication lifecycle state is unknown",
                )),
            }
        }
    }
}

pub(crate) fn publication_retirement(
    bytes: &[u8],
) -> Result<Option<(RetirementReason, u64, RetirementAge)>, BlobStoreError> {
    if !matches!(
        bytes.first().copied(),
        Some(PREDECESSOR_PUBLICATION_RECORD_VERSION | CURRENT_PUBLICATION_RECORD_VERSION)
    ) {
        return Ok(None);
    }
    match bytes.get(1).copied() {
        Some(PUBLICATION_STATE_LIVE_TAG) => {
            PublicationState::decode(&bytes[1..2])?;
            Ok(None)
        }
        Some(PUBLICATION_STATE_RETIRED_TAG) => {
            if bytes.len() != 1 + RETIRED_PUBLICATION_STATE_BYTES
                && bytes.len() < 1 + RETIRED_PUBLICATION_STATE_BYTES + 8
            {
                return Err(BlobStoreError::SchemaInvariant(
                    "retired Blob publication record is truncated",
                ));
            }
            match PublicationState::decode(&bytes[1..1 + RETIRED_PUBLICATION_STATE_BYTES])? {
                PublicationState::Retired {
                    reason,
                    generation,
                    age,
                } => Ok(Some((reason, generation, age))),
                PublicationState::Live => unreachable!("retired tag decoded as live"),
            }
        }
        _ => Err(BlobStoreError::SchemaInvariant(
            "Blob publication lifecycle state is not canonical",
        )),
    }
}

pub(crate) fn retired_publication_record(
    live: &[u8],
    acceptance_marker: u64,
    reason: RetirementReason,
    generation: u64,
    age: RetirementAge,
) -> Result<Vec<u8>, StoreError> {
    if acceptance_marker == 0 {
        return Err(StoreError::Blob(BlobStoreError::SchemaInvariant(
            "retired Blob publication has a zero acceptance marker",
        )));
    }
    let payload = publication_payload(live).map_err(StoreError::Blob)?;
    let mut encoded = vec![CURRENT_PUBLICATION_RECORD_VERSION];
    encoded.extend_from_slice(
        &PublicationState::Retired {
            reason,
            generation,
            age,
        }
        .encode(),
    );
    encoded.extend_from_slice(&acceptance_marker.to_be_bytes());
    encoded.extend_from_slice(payload);
    Ok(encoded)
}

pub(crate) fn reanchored_retired_publication_record(
    encoded: &[u8],
    age: RetirementAge,
) -> Result<Vec<u8>, StoreError> {
    let (reason, generation, _) = publication_retirement(encoded)
        .map_err(StoreError::Blob)?
        .ok_or(StoreError::Blob(BlobStoreError::SchemaInvariant(
            "Blob retirement reanchor points to a live publication",
        )))?;
    let (marker, payload) = retired_publication_payload(encoded)
        .map_err(StoreError::Blob)?
        .ok_or(StoreError::Blob(BlobStoreError::SchemaInvariant(
            "retired Blob publication lacks lookup metadata during reanchor",
        )))?;
    let mut reanchored = vec![CURRENT_PUBLICATION_RECORD_VERSION];
    reanchored.extend_from_slice(
        &PublicationState::Retired {
            reason,
            generation,
            age,
        }
        .encode(),
    );
    reanchored.extend_from_slice(&marker.to_be_bytes());
    reanchored.extend_from_slice(payload);
    Ok(reanchored)
}

pub(crate) fn retired_publication_payload(
    bytes: &[u8],
) -> Result<Option<(u64, &[u8])>, BlobStoreError> {
    if publication_retirement(bytes)?.is_none() {
        return Ok(None);
    }
    let marker_offset = 1 + RETIRED_PUBLICATION_STATE_BYTES;
    if bytes.len() == marker_offset {
        return Ok(None);
    }
    let marker = u64::from_be_bytes(
        bytes[marker_offset..marker_offset + 8]
            .try_into()
            .expect("checked retired marker"),
    );
    if marker == 0 || !matches!(bytes.get(marker_offset + 8), Some(1..=3)) {
        return Err(BlobStoreError::SchemaInvariant(
            "retired Blob publication lookup payload is not canonical",
        ));
    }
    Ok(Some((marker, &bytes[marker_offset + 8..])))
}

fn publication_is_current(bytes: &[u8]) -> bool {
    bytes.first().copied() == Some(CURRENT_PUBLICATION_RECORD_VERSION)
}

fn wrap_publication(bytes: &[u8]) -> Result<Vec<u8>, StoreError> {
    let payload = publication_payload(bytes).map_err(StoreError::Blob)?;
    if publication_is_current(bytes) || !matches!(payload.first(), Some(1..=3)) {
        return Err(StoreError::Blob(BlobStoreError::SchemaInvariant(
            "Blob predecessor publication is not canonical",
        )));
    }
    let payload = super::encode_blob_metadata(super::decode_blob_metadata(payload)?)?;
    let mut wrapped = Vec::with_capacity(payload.len() + 2);
    wrapped.push(CURRENT_PUBLICATION_RECORD_VERSION);
    wrapped.extend_from_slice(&PublicationState::Live.encode());
    wrapped.extend_from_slice(&payload);
    Ok(wrapped)
}

fn wrap_v1_publication(bytes: &[u8]) -> Result<Vec<u8>, StoreError> {
    if bytes.len() < 3
        || bytes[0] != LIFECYCLE_V1_PUBLICATION_RECORD_VERSION
        || PublicationState::decode(&bytes[1..2])? != PublicationState::Live
    {
        return Err(StoreError::Blob(BlobStoreError::SchemaInvariant(
            "Blob lifecycle-v1 publication wrapper is not canonical",
        )));
    }
    let payload = super::encode_blob_metadata(super::decode_blob_metadata(&bytes[2..])?)?;
    let mut wrapped = Vec::with_capacity(payload.len() + 2);
    wrapped.push(CURRENT_PUBLICATION_RECORD_VERSION);
    wrapped.extend_from_slice(&PublicationState::Live.encode());
    wrapped.extend_from_slice(&payload);
    Ok(wrapped)
}

pub(crate) fn replace_live_publication_payload(
    encoded: &[u8],
    payload: &[u8],
) -> Result<Vec<u8>, StoreError> {
    if publication_record_is_retired(encoded)?
        || encoded.first().copied() != Some(CURRENT_PUBLICATION_RECORD_VERSION)
        || !matches!(payload.first(), Some(1..=3))
    {
        return Err(StoreError::Blob(BlobStoreError::SchemaInvariant(
            "Blob publication lifetime update is not a current live record",
        )));
    }
    let mut wrapped = Vec::with_capacity(payload.len() + 2);
    wrapped.push(CURRENT_PUBLICATION_RECORD_VERSION);
    wrapped.extend_from_slice(&PublicationState::Live.encode());
    wrapped.extend_from_slice(payload);
    Ok(wrapped)
}

fn upgrade_v3_publication(encoded: &[u8]) -> Result<Vec<u8>, StoreError> {
    if encoded.first().copied() != Some(PREDECESSOR_PUBLICATION_RECORD_VERSION) {
        return Err(StoreError::Blob(BlobStoreError::SchemaInvariant(
            "Blob lifecycle-v3 publication wrapper is missing",
        )));
    }
    if publication_record_is_retired(encoded)? {
        let state_end = 1 + RETIRED_PUBLICATION_STATE_BYTES;
        let Some((marker, payload)) = retired_publication_payload(encoded)? else {
            let mut upgraded = Vec::with_capacity(state_end);
            upgraded.push(CURRENT_PUBLICATION_RECORD_VERSION);
            upgraded.extend_from_slice(&encoded[1..state_end]);
            return Ok(upgraded);
        };
        let metadata = super::decode_blob_metadata(payload)?;
        let payload = super::encode_blob_metadata(metadata)?;
        let mut upgraded = Vec::with_capacity(state_end + 8 + payload.len());
        upgraded.push(CURRENT_PUBLICATION_RECORD_VERSION);
        upgraded.extend_from_slice(&encoded[1..state_end]);
        upgraded.extend_from_slice(&marker.to_be_bytes());
        upgraded.extend_from_slice(&payload);
        return Ok(upgraded);
    }
    let metadata = super::decode_blob_metadata(encoded)?;
    let payload = super::encode_blob_metadata(metadata)?;
    let mut upgraded = Vec::with_capacity(payload.len() + 2);
    upgraded.push(CURRENT_PUBLICATION_RECORD_VERSION);
    upgraded.extend_from_slice(&PublicationState::Live.encode());
    upgraded.extend_from_slice(&payload);
    Ok(upgraded)
}

fn admission_schema_is_current(write: &redb::WriteTransaction) -> Result<bool, StoreError> {
    #[cfg(test)]
    if TEST_BLOB_LIFECYCLE_MIGRATION_DISABLED.get() {
        return Ok(false);
    }
    let metadata = write.open_table(BLOB_LIFECYCLE_METADATA)?;
    if metadata
        .get(BLOB_LIFECYCLE_SCHEMA_VERSION_FIELD)?
        .map(|value| value.value())
        == Some(ACTIVE_BLOB_LIFECYCLE_SCHEMA_VERSION)
    {
        Ok(true)
    } else {
        Err(StoreError::Blob(BlobStoreError::SchemaInvariant(
            "Blob lifecycle authority is absent or unknown on an admission path",
        )))
    }
}

pub(crate) fn require_import_lineage(
    write: &redb::WriteTransaction,
    physical_lineage: Option<[u8; 32]>,
) -> Result<(), StoreError> {
    if admission_schema_is_current(write)? && physical_lineage.is_none() {
        return Err(StoreError::Blob(
            BlobStoreError::PhysicalLineageMigrationRequired,
        ));
    }
    Ok(())
}

fn lifecycle_counter(
    write: &redb::WriteTransaction,
    field: &'static str,
) -> Result<u64, StoreError> {
    let metadata = write.open_table(BLOB_LIFECYCLE_METADATA)?;
    if metadata
        .get(BLOB_LIFECYCLE_SCHEMA_VERSION_FIELD)?
        .map(|value| value.value())
        != Some(ACTIVE_BLOB_LIFECYCLE_SCHEMA_VERSION)
    {
        return Err(StoreError::Blob(BlobStoreError::SchemaInvariant(
            "Blob lifecycle schema version is missing or unknown",
        )));
    }
    metadata
        .get(field)?
        .map(|value| value.value())
        .ok_or(StoreError::Blob(BlobStoreError::SchemaInvariant(
            "Blob lifecycle accounting metadata is incomplete",
        )))
}

fn active_operation_count_from_metadata(
    metadata: &impl ReadableTable<&'static str, u64>,
    total_operations: u64,
) -> Result<u64, StoreError> {
    let schema = metadata
        .get(BLOB_LIFECYCLE_SCHEMA_VERSION_FIELD)?
        .map(|value| value.value())
        .ok_or(StoreError::Blob(BlobStoreError::SchemaInvariant(
            "Blob lifecycle schema version is missing or unknown",
        )))?;
    if schema != ACTIVE_BLOB_LIFECYCLE_SCHEMA_VERSION {
        return Err(StoreError::Blob(BlobStoreError::SchemaInvariant(
            "Blob lifecycle schema cannot account for retired operations",
        )));
    }
    let retired_operations = metadata
        .get(BLOB_RETIRED_OPERATION_ROWS)?
        .map(|value| value.value())
        .ok_or(StoreError::Blob(BlobStoreError::SchemaInvariant(
            "Blob lifecycle retired-operation accounting is missing",
        )))?;
    total_operations
        .checked_sub(retired_operations)
        .ok_or(StoreError::Blob(BlobStoreError::SchemaInvariant(
            "Blob retired-operation accounting exceeds total operations",
        )))
}

pub(crate) fn active_operation_count_write(
    write: &redb::WriteTransaction,
    total_operations: u64,
) -> Result<u64, StoreError> {
    #[cfg(test)]
    if TEST_BLOB_LIFECYCLE_MIGRATION_DISABLED.get() {
        return Ok(total_operations);
    }
    active_operation_count_from_metadata(
        &write.open_table(BLOB_LIFECYCLE_METADATA)?,
        total_operations,
    )
}

pub(crate) fn active_operation_count_read(
    read: &redb::ReadTransaction,
    total_operations: u64,
) -> Result<u64, StoreError> {
    #[cfg(test)]
    if TEST_BLOB_LIFECYCLE_MIGRATION_DISABLED.get() {
        return Ok(total_operations);
    }
    active_operation_count_from_metadata(
        &read.open_table(BLOB_LIFECYCLE_METADATA)?,
        total_operations,
    )
}

fn set_lifecycle_counter(
    write: &redb::WriteTransaction,
    field: &'static str,
    value: u64,
) -> Result<(), StoreError> {
    write
        .open_table(BLOB_LIFECYCLE_METADATA)?
        .insert(field, value)?;
    Ok(())
}

/// Returns a current live-publication encoding without accepting a predecessor
/// row on an ordinary current-schema write path.
pub(crate) fn live_publication_record(
    write: &redb::WriteTransaction,
    bytes: &[u8],
) -> Result<Vec<u8>, StoreError> {
    if admission_schema_is_current(write)? {
        wrap_publication(bytes)
    } else {
        Ok(bytes.to_vec())
    }
}

/// Point-checks one exact retained physical-lineage fence.
pub(crate) fn require_lineage_fence(
    write: &redb::WriteTransaction,
    variant: super::BlobVariantId,
    physical_lineage: [u8; 32],
    owner_binding: [u8; 32],
) -> Result<(), StoreError> {
    if !admission_schema_is_current(write)? {
        return Ok(());
    }
    let encoded = write
        .open_table(BLOB_LINEAGE_FENCES)?
        .get(variant.as_bytes().as_slice())?
        .map(|value| value.value().to_vec())
        .ok_or(StoreError::Blob(BlobStoreError::SchemaInvariant(
            "retained Blob variant is missing its lineage fence",
        )))?;
    let fence = LineageFence::decode(&encoded).map_err(StoreError::Blob)?;
    if !fence.same_authority(LineageFence::new(physical_lineage, owner_binding)) {
        return Err(StoreError::Blob(BlobStoreError::PhysicalLineageConflict));
    }
    if lifecycle_counter(write, BLOB_LINEAGE_ROWS)? == 0
        || lifecycle_counter(write, BLOB_LINEAGE_BYTES)?
            < entry_bytes(variant.as_bytes(), &encoded)?
    {
        return Err(StoreError::Blob(BlobStoreError::SchemaInvariant(
            "Blob lineage-fence accounting cannot cover the retained fence",
        )));
    }
    Ok(())
}

pub(crate) fn charge_variant_reference_counter(
    charge: &mut super::MaintenanceCharge,
) -> Result<bool, StoreError> {
    charge.charge_row(
        super::MaintenanceRowIdentity::new(
            "aster.blob-lifecycle-metadata.v1",
            BLOB_REFERENCE_ROWS.as_bytes(),
        ),
        std::mem::size_of::<u64>(),
    )
}

pub(crate) fn charge_lineage_fence_authority_write(
    write: &redb::WriteTransaction,
    variant: super::BlobVariantId,
    charge: &mut super::MaintenanceCharge,
) -> Result<bool, StoreError> {
    let fences = write.open_table(BLOB_LINEAGE_FENCES)?;
    let encoded = fences
        .get(variant.as_bytes().as_slice())?
        .ok_or(StoreError::Blob(BlobStoreError::SchemaInvariant(
            "retained Blob variant is missing its lineage fence",
        )))?;
    if !charge.charge_row(
        super::MaintenanceRowIdentity::new("aster.blob-lineage-fences.v1", variant.as_bytes()),
        encoded.value().len(),
    )? {
        return Ok(false);
    }
    for field in [BLOB_LINEAGE_ROWS, BLOB_LINEAGE_BYTES] {
        if !charge.charge_row(
            super::MaintenanceRowIdentity::new(
                "aster.blob-lifecycle-metadata.v1",
                field.as_bytes(),
            ),
            std::mem::size_of::<u64>(),
        )? {
            return Ok(false);
        }
    }
    Ok(true)
}

/// Point-checks or installs one permanent physical-lineage fence in the
/// caller's transaction. An exact fence is idempotent even at configured
/// capacity; only a new key consumes the separate security resource.
pub(crate) fn ensure_lineage_fence(
    write: &redb::WriteTransaction,
    limits: BlobLifecycleLimits,
    variant: super::BlobVariantId,
    physical_lineage: [u8; 32],
    owner_binding: [u8; 32],
) -> Result<(), StoreError> {
    if !admission_schema_is_current(write)? {
        return Ok(());
    }
    let key = variant.as_bytes().as_slice();
    let expected = LineageFence::new(physical_lineage, owner_binding);
    let existing = {
        let fences = write.open_table(BLOB_LINEAGE_FENCES)?;
        fences.get(key)?.map(|value| value.value().to_vec())
    };
    if let Some(encoded) = existing {
        let existing = LineageFence::decode(&encoded).map_err(StoreError::Blob)?;
        if !existing.same_authority(expected) {
            return Err(StoreError::Blob(BlobStoreError::PhysicalLineageConflict));
        }
        return require_lineage_fence(write, variant, physical_lineage, owner_binding);
    }

    let encoded = expected.encode();
    let current_rows = lifecycle_counter(write, BLOB_LINEAGE_ROWS)?;
    let current_bytes = lifecycle_counter(write, BLOB_LINEAGE_BYTES)?;
    let required_rows = current_rows
        .checked_add(1)
        .ok_or(StoreError::ItemCountAccountingOverflow)?;
    let required_bytes = current_bytes
        .checked_add(entry_bytes(key, &encoded)?)
        .ok_or(StoreError::PayloadByteAccountingOverflow)?;
    if required_rows > limits.max_lineage_rows() || required_bytes > limits.max_lineage_bytes() {
        return Err(StoreError::Blob(BlobStoreError::LineageFenceCapacity {
            required_rows,
            required_bytes,
            max_rows: limits.max_lineage_rows(),
            max_bytes: limits.max_lineage_bytes(),
        }));
    }
    if write
        .open_table(BLOB_LINEAGE_FENCES)?
        .insert(key, encoded.as_slice())?
        .is_some()
    {
        return Err(StoreError::Blob(BlobStoreError::SchemaInvariant(
            "Blob lineage fence changed during one writer transaction",
        )));
    }
    set_lifecycle_counter(write, BLOB_LINEAGE_ROWS, required_rows)?;
    set_lifecycle_counter(write, BLOB_LINEAGE_BYTES, required_bytes)
}

/// Marks the exact retained fence after its protected bulk state reaches the
/// final reclamation transaction. The fixed-width state change preserves the
/// existing row and byte accounting and is idempotent across recovery.
pub(crate) fn mark_lineage_bulk_reclamation_observed(
    write: &redb::WriteTransaction,
    variant: super::BlobVariantId,
    expected_evidence: &[u8],
) -> Result<(), StoreError> {
    if !admission_schema_is_current(write)? {
        return Err(StoreError::Blob(BlobStoreError::SchemaInvariant(
            "Blob lineage reclamation requires current lifecycle authority",
        )));
    }
    let expected = LineageFence::decode(expected_evidence).map_err(StoreError::Blob)?;
    let key = variant.as_bytes().as_slice();
    let encoded = write
        .open_table(BLOB_LINEAGE_FENCES)?
        .get(key)?
        .map(|value| value.value().to_vec())
        .ok_or(StoreError::Blob(BlobStoreError::SchemaInvariant(
            "reclaimed Blob variant is missing its lineage fence",
        )))?;
    let current = LineageFence::decode(&encoded).map_err(StoreError::Blob)?;
    if !current.same_authority(expected) {
        return Err(StoreError::Blob(BlobStoreError::PhysicalLineageConflict));
    }
    if current.bulk_reclamation_observed() {
        return Ok(());
    }
    let reclaimed = current.with_bulk_reclamation_observed().encode();
    write
        .open_table(BLOB_LINEAGE_FENCES)?
        .insert(key, reclaimed.as_slice())?;
    Ok(())
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ReplayFenceStatus {
    Absent,
    Exact,
}

/// Point-classifies one publisher dot against permanent replay authority.
pub(crate) fn check_replay_fence(
    write: &redb::WriteTransaction,
    expected: ReplayFence,
) -> Result<ReplayFenceStatus, StoreError> {
    if !admission_schema_is_current(write)? {
        return Ok(ReplayFenceStatus::Absent);
    }
    let key = super::accepted_dot_key(crate::Dot {
        publisher: expected.publisher,
        counter: expected.counter,
    });
    let Some(encoded) = write
        .open_table(BLOB_REPLAY_FENCES)?
        .get(key.as_slice())?
        .map(|value| value.value().to_vec())
    else {
        return Ok(ReplayFenceStatus::Absent);
    };
    let existing = ReplayFence::decode(&encoded).map_err(StoreError::Blob)?;
    if existing.publisher != expected.publisher || existing.counter != expected.counter {
        return Err(StoreError::Blob(BlobStoreError::SchemaInvariant(
            "Blob replay fence key differs from its publisher dot",
        )));
    }
    if existing.semantic_id != expected.semantic_id {
        return Err(StoreError::CausalEquivocation {
            publisher: expected.publisher,
            counter: expected.counter,
        });
    }
    if existing.transfer_id != expected.transfer_id
        || existing.source_len != expected.source_len
        || existing.source_digest != expected.source_digest
    {
        return Err(StoreError::Blob(
            BlobStoreError::SourceRepresentationConflict,
        ));
    }
    if lifecycle_counter(write, BLOB_REPLAY_ROWS)? == 0
        || lifecycle_counter(write, BLOB_REPLAY_BYTES)? < entry_bytes(&key, &encoded)?
    {
        return Err(StoreError::Blob(BlobStoreError::SchemaInvariant(
            "Blob replay-fence accounting cannot cover the retained fence",
        )));
    }
    Ok(ReplayFenceStatus::Exact)
}

/// Persists the exact causal-frontier commitment that remains after a bounded
/// publication retirement row expires.  The row is keyed by the same
/// permanent publisher dot as the replay fence and contains only a fixed
/// digest of its complete frontier key.
pub(crate) fn record_expired_replay_causal_fence(
    write: &redb::WriteTransaction,
    dot: crate::Dot,
    frontier_key: &[u8],
) -> Result<(), StoreError> {
    if !admission_schema_is_current(write)? {
        return Err(StoreError::Blob(BlobStoreError::SchemaInvariant(
            "expired Blob replay causal evidence requires current lifecycle authority",
        )));
    }
    let key = super::accepted_dot_key(dot);
    let digest: [u8; 32] = Sha256::digest(frontier_key).into();
    let mut fences = write.open_table(BLOB_REPLAY_CAUSAL_FENCES)?;
    if let Some(existing) = fences.get(key.as_slice())? {
        if existing.value() != digest {
            return Err(StoreError::Blob(BlobStoreError::SchemaInvariant(
                "expired Blob replay causal fence differs from its frontier authority",
            )));
        }
        return Ok(());
    }
    fences.insert(key.as_slice(), digest.as_slice())?;
    Ok(())
}

/// Returns whether an exact replay fence has the durable causal binding that
/// proves its bounded publication record expired normally.  An arbitrary
/// detached replay fence is still corrupt and must not be treated as a
/// duplicate merely because its source bytes happen to match.
pub(crate) fn expired_replay_causal_fence_matches(
    write: &redb::WriteTransaction,
    dot: crate::Dot,
    frontier_key: &[u8],
) -> Result<bool, StoreError> {
    let tables = write
        .list_tables()?
        .map(|table| table.name().to_owned())
        .collect::<BTreeSet<_>>();
    if !tables.contains(BLOB_REPLAY_CAUSAL_FENCES.name()) {
        return Ok(false);
    }
    if write
        .list_multimap_tables()?
        .any(|table| table.name() == BLOB_REPLAY_CAUSAL_FENCES.name())
    {
        return Err(StoreError::Blob(BlobStoreError::SchemaInvariant(
            "Blob replay causal-fence table has the wrong table kind",
        )));
    }
    let key = super::accepted_dot_key(dot);
    let fences = write.open_table(BLOB_REPLAY_CAUSAL_FENCES)?;
    let Some(actual) = fences.get(key.as_slice())? else {
        return Ok(false);
    };
    let expected: [u8; 32] = Sha256::digest(frontier_key).into();
    if actual.value() != expected {
        return Err(StoreError::Blob(BlobStoreError::SchemaInvariant(
            "expired Blob replay causal fence differs from its frontier authority",
        )));
    }
    Ok(true)
}

/// Installs a new replay fence or accepts an exact existing fence without
/// consuming capacity.
pub(crate) fn ensure_replay_fence(
    write: &redb::WriteTransaction,
    limits: BlobLifecycleLimits,
    expected: ReplayFence,
) -> Result<(), StoreError> {
    match check_replay_fence(write, expected)? {
        ReplayFenceStatus::Exact => return Ok(()),
        ReplayFenceStatus::Absent if !admission_schema_is_current(write)? => return Ok(()),
        ReplayFenceStatus::Absent => {}
    }
    let key = super::accepted_dot_key(crate::Dot {
        publisher: expected.publisher,
        counter: expected.counter,
    });
    let encoded = expected.encode();
    let current_rows = lifecycle_counter(write, BLOB_REPLAY_ROWS)?;
    let current_bytes = lifecycle_counter(write, BLOB_REPLAY_BYTES)?;
    let required_rows = current_rows
        .checked_add(1)
        .ok_or(StoreError::ItemCountAccountingOverflow)?;
    let required_bytes = current_bytes
        .checked_add(entry_bytes(&key, &encoded)?)
        .ok_or(StoreError::PayloadByteAccountingOverflow)?;
    if required_rows > limits.max_replay_rows() || required_bytes > limits.max_replay_bytes() {
        return Err(StoreError::Blob(BlobStoreError::ReplayFenceCapacity {
            required_rows,
            required_bytes,
            max_rows: limits.max_replay_rows(),
            max_bytes: limits.max_replay_bytes(),
        }));
    }
    if write
        .open_table(BLOB_REPLAY_FENCES)?
        .insert(key.as_slice(), encoded.as_slice())?
        .is_some()
    {
        return Err(StoreError::Blob(BlobStoreError::SchemaInvariant(
            "Blob replay fence changed during one writer transaction",
        )));
    }
    set_lifecycle_counter(write, BLOB_REPLAY_ROWS, required_rows)?;
    set_lifecycle_counter(write, BLOB_REPLAY_BYTES, required_bytes)
}

fn reference_key(
    variant: super::BlobVariantId,
    owner: VariantReferenceOwner,
    transfer: BlobTransferId,
) -> Vec<u8> {
    variant_reference_key(variant, owner, transfer)
}

pub(crate) fn require_variant_reference(
    write: &redb::WriteTransaction,
    variant: super::BlobVariantId,
    owner: VariantReferenceOwner,
    transfer: BlobTransferId,
) -> Result<(), StoreError> {
    if !admission_schema_is_current(write)? {
        return Ok(());
    }
    super::deletion::require_variant_available_write(write, variant)?;
    let key = reference_key(variant, owner, transfer);
    let value = write
        .open_table(BLOB_VARIANT_REFERENCES)?
        .get(key.as_slice())?
        .map(|value| value.value().to_vec())
        .ok_or(StoreError::Blob(BlobStoreError::SchemaInvariant(
            "Blob root is missing its exact variant reference",
        )))?;
    if !value.is_empty() || lifecycle_counter(write, BLOB_REFERENCE_ROWS)? == 0 {
        return Err(StoreError::Blob(BlobStoreError::SchemaInvariant(
            "Blob variant reference or its accounting is not canonical",
        )));
    }
    Ok(())
}

pub(crate) fn insert_variant_reference(
    write: &redb::WriteTransaction,
    variant: super::BlobVariantId,
    owner: VariantReferenceOwner,
    transfer: BlobTransferId,
) -> Result<(), StoreError> {
    if !admission_schema_is_current(write)? {
        return Ok(());
    }
    super::deletion::require_variant_available_write(write, variant)?;
    let key = reference_key(variant, owner, transfer);
    if write
        .open_table(BLOB_VARIANT_REFERENCES)?
        .get(key.as_slice())?
        .is_some()
    {
        return Err(StoreError::Blob(BlobStoreError::SchemaInvariant(
            "new Blob root already has a variant reference",
        )));
    }
    let current = lifecycle_counter(write, BLOB_REFERENCE_ROWS)?;
    let next = current
        .checked_add(1)
        .ok_or(StoreError::ItemCountAccountingOverflow)?;
    write
        .open_table(BLOB_VARIANT_REFERENCES)?
        .insert(key.as_slice(), &[][..])?;
    set_lifecycle_counter(write, BLOB_REFERENCE_ROWS, next)
}

pub(crate) fn remove_variant_reference(
    write: &redb::WriteTransaction,
    variant: super::BlobVariantId,
    owner: VariantReferenceOwner,
    transfer: BlobTransferId,
) -> Result<(), StoreError> {
    if !admission_schema_is_current(write)? {
        return Ok(());
    }
    require_variant_reference(write, variant, owner, transfer)?;
    let current = lifecycle_counter(write, BLOB_REFERENCE_ROWS)?;
    let next = current
        .checked_sub(1)
        .ok_or(StoreError::Blob(BlobStoreError::SchemaInvariant(
            "Blob variant-reference counter underflows",
        )))?;
    let key = reference_key(variant, owner, transfer);
    let removed = write
        .open_table(BLOB_VARIANT_REFERENCES)?
        .remove(key.as_slice())?
        .map(|value| value.value().to_vec());
    if removed.as_deref() != Some(&[][..]) {
        return Err(StoreError::Blob(BlobStoreError::SchemaInvariant(
            "Blob variant reference changed during one writer transaction",
        )));
    }
    set_lifecycle_counter(write, BLOB_REFERENCE_ROWS, next)
}

pub(crate) fn move_variant_reference(
    write: &redb::WriteTransaction,
    variant: super::BlobVariantId,
    transfer: BlobTransferId,
    from: VariantReferenceOwner,
    to: VariantReferenceOwner,
) -> Result<(), StoreError> {
    if !admission_schema_is_current(write)? {
        return Ok(());
    }
    super::deletion::require_variant_available_write(write, variant)?;
    require_variant_reference(write, variant, from, transfer)?;
    let from_key = reference_key(variant, from, transfer);
    let to_key = reference_key(variant, to, transfer);
    if write
        .open_table(BLOB_VARIANT_REFERENCES)?
        .get(to_key.as_slice())?
        .is_some()
    {
        return Err(StoreError::Blob(BlobStoreError::SchemaInvariant(
            "Blob reference move would create a second owner",
        )));
    }
    let mut references = write.open_table(BLOB_VARIANT_REFERENCES)?;
    references.remove(from_key.as_slice())?;
    references.insert(to_key.as_slice(), &[][..])?;
    Ok(())
}

pub(crate) fn admit_publication_row(
    write: &redb::WriteTransaction,
    limits: BlobLifecycleLimits,
) -> Result<(), StoreError> {
    if !admission_schema_is_current(write)? {
        return Ok(());
    }
    let current = lifecycle_counter(write, BLOB_PUBLICATION_ROWS)?;
    let required_rows = current
        .checked_add(1)
        .ok_or(StoreError::ItemCountAccountingOverflow)?;
    if required_rows > limits.max_publication_rows() {
        return Err(StoreError::Blob(
            BlobStoreError::PublicationLifecycleCapacity {
                required_rows,
                max_rows: limits.max_publication_rows(),
            },
        ));
    }
    set_lifecycle_counter(write, BLOB_PUBLICATION_ROWS, required_rows)
}

/// Reserves publication-lifecycle headroom before a new upload is admitted.
///
/// Provisional uploads do not increment the live-publication counter, but
/// every one can promote into exactly one publication. Counting those rows in
/// the preflight prevents a caller from consuming a source only to discover at
/// promotion that lifecycle capacity was already exhausted.
pub(crate) fn require_publication_reservation_capacity(
    write: &redb::WriteTransaction,
    limits: BlobLifecycleLimits,
) -> Result<(), StoreError> {
    if !admission_schema_is_current(write)? {
        return Ok(());
    }
    let current = lifecycle_counter(write, BLOB_PUBLICATION_ROWS)?;
    let provisional = write.open_table(super::BLOB_UPLOADS)?.len()?;
    let required_rows = current
        .checked_add(provisional)
        .and_then(|rows| rows.checked_add(1))
        .ok_or(StoreError::ItemCountAccountingOverflow)?;
    if required_rows > limits.max_publication_rows() {
        return Err(StoreError::Blob(
            BlobStoreError::PublicationLifecycleCapacity {
                required_rows,
                max_rows: limits.max_publication_rows(),
            },
        ));
    }
    Ok(())
}

pub(crate) fn require_publication_row(write: &redb::WriteTransaction) -> Result<(), StoreError> {
    if admission_schema_is_current(write)? && lifecycle_counter(write, BLOB_PUBLICATION_ROWS)? == 0
    {
        return Err(StoreError::Blob(BlobStoreError::SchemaInvariant(
            "live Blob publication is missing lifecycle accounting",
        )));
    }
    Ok(())
}

pub(crate) fn operation_payload(bytes: &[u8]) -> Result<&[u8], BlobStoreError> {
    if bytes.is_empty() {
        return Err(BlobStoreError::SchemaInvariant(
            "Blob operation lifecycle wrapper is truncated",
        ));
    }
    if bytes[0] == super::BLOB_OPERATION_VERSION {
        return Ok(bytes);
    }
    if bytes.len() < 3 || bytes[0] != CURRENT_OPERATION_RECORD_VERSION {
        return Err(BlobStoreError::SchemaInvariant(
            "Blob operation lifecycle wrapper has an unknown version",
        ));
    }
    if OperationState::decode(&bytes[1..2])? != OperationState::Active {
        return Err(BlobStoreError::SchemaInvariant(
            "retired Blob operation has no active operation payload",
        ));
    }
    Ok(&bytes[2..])
}

pub(crate) fn operation_record_is_retired(bytes: &[u8]) -> Result<bool, BlobStoreError> {
    if bytes.first().copied() != Some(CURRENT_OPERATION_RECORD_VERSION) {
        return Ok(false);
    }
    match bytes.get(1).copied() {
        Some(OPERATION_STATE_ACTIVE_TAG) => {
            OperationState::decode(&bytes[1..2])?;
            Ok(false)
        }
        Some(OPERATION_STATE_RETIRED_TAG) => {
            OperationState::decode(&bytes[1..])?;
            Ok(true)
        }
        _ => Err(BlobStoreError::SchemaInvariant(
            "Blob operation lifecycle state is not canonical",
        )),
    }
}

pub(crate) type OperationRetirement = (RetirementReason, u64, [u8; 32], [u8; 32], RetirementAge);

pub(crate) fn operation_retirement(
    bytes: &[u8],
) -> Result<Option<OperationRetirement>, BlobStoreError> {
    if bytes.first().copied() != Some(CURRENT_OPERATION_RECORD_VERSION) {
        return Ok(None);
    }
    match bytes.get(1).copied() {
        Some(OPERATION_STATE_ACTIVE_TAG) => {
            OperationState::decode(&bytes[1..2])?;
            Ok(None)
        }
        Some(OPERATION_STATE_RETIRED_TAG) => match OperationState::decode(&bytes[1..])? {
            OperationState::Retired {
                reason,
                generation,
                operation_key_digest,
                intent_digest,
                age,
            } => Ok(Some((
                reason,
                generation,
                operation_key_digest,
                intent_digest,
                age,
            ))),
            OperationState::Active => unreachable!("retired tag decoded as active"),
        },
        _ => Err(BlobStoreError::SchemaInvariant(
            "Blob operation lifecycle state is not canonical",
        )),
    }
}

pub(crate) fn retired_operation_record(
    reason: RetirementReason,
    generation: u64,
    operation_key_digest: [u8; 32],
    intent_digest: [u8; 32],
    age: RetirementAge,
) -> Vec<u8> {
    let mut encoded = vec![CURRENT_OPERATION_RECORD_VERSION];
    encoded.extend_from_slice(
        &OperationState::Retired {
            reason,
            generation,
            operation_key_digest,
            intent_digest,
            age,
        }
        .encode(),
    );
    encoded
}

pub(crate) fn reanchored_retired_operation_record(
    encoded: &[u8],
    age: RetirementAge,
) -> Result<Vec<u8>, StoreError> {
    let (reason, generation, operation_key_digest, intent_digest, _) =
        operation_retirement(encoded)
            .map_err(StoreError::Blob)?
            .ok_or(StoreError::Blob(BlobStoreError::SchemaInvariant(
                "Blob retirement reanchor points to an active operation",
            )))?;
    Ok(retired_operation_record(
        reason,
        generation,
        operation_key_digest,
        intent_digest,
        age,
    ))
}

fn wrap_operation(bytes: &[u8]) -> Result<Vec<u8>, StoreError> {
    let payload = operation_payload(bytes).map_err(StoreError::Blob)?;
    if payload.first().copied() != Some(super::BLOB_OPERATION_VERSION) {
        return Err(StoreError::Blob(BlobStoreError::SchemaInvariant(
            "Blob predecessor operation is not canonical",
        )));
    }
    let mut wrapped = Vec::with_capacity(payload.len() + 2);
    wrapped.push(CURRENT_OPERATION_RECORD_VERSION);
    wrapped.extend_from_slice(&OperationState::Active.encode());
    wrapped.extend_from_slice(payload);
    Ok(wrapped)
}

pub(crate) fn active_operation_record(
    write: &redb::WriteTransaction,
    bytes: &[u8],
) -> Result<Vec<u8>, StoreError> {
    if admission_schema_is_current(write)? {
        wrap_operation(bytes)
    } else {
        Ok(bytes.to_vec())
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum RetentionDeadlineOwner {
    Publication(BlobTransferId),
    Operation([u8; 32]),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum RetentionDeadlineKind {
    Publication,
    Operation,
}

impl RetentionDeadlineKind {
    const fn tag(self) -> u8 {
        match self {
            Self::Publication => 1,
            Self::Operation => 2,
        }
    }
}

impl RetentionDeadlineOwner {
    const fn kind(self) -> RetentionDeadlineKind {
        match self {
            Self::Publication(_) => RetentionDeadlineKind::Publication,
            Self::Operation(_) => RetentionDeadlineKind::Operation,
        }
    }
}

fn retirement_resolver_key(owner: RetentionDeadlineOwner) -> [u8; 33] {
    let mut key = [0u8; 33];
    match owner {
        RetentionDeadlineOwner::Publication(transfer) => {
            key[0] = 1;
            key[1..].copy_from_slice(transfer.as_bytes());
        }
        RetentionDeadlineOwner::Operation(digest) => {
            key[0] = 2;
            key[1..].copy_from_slice(&digest);
        }
    }
    key
}

fn decode_retirement_resolver_key(key: &[u8]) -> Result<RetentionDeadlineOwner, StoreError> {
    let key: [u8; 33] = key.try_into().map_err(|_| {
        StoreError::Blob(BlobStoreError::SchemaInvariant(
            "Blob retirement resolver key has an invalid length",
        ))
    })?;
    let identity: [u8; 32] = key[1..].try_into().expect("fixed retirement owner");
    match key[0] {
        1 => Ok(RetentionDeadlineOwner::Publication(BlobTransferId::new(
            identity,
        ))),
        2 => Ok(RetentionDeadlineOwner::Operation(identity)),
        _ => Err(StoreError::Blob(BlobStoreError::SchemaInvariant(
            "Blob retirement resolver owner is unknown",
        ))),
    }
}

fn validate_retirement_resolver(
    owner: RetentionDeadlineOwner,
    value: &[u8],
) -> Result<(), StoreError> {
    match owner {
        RetentionDeadlineOwner::Publication(_) if value.is_empty() => Ok(()),
        RetentionDeadlineOwner::Operation(digest)
            if !value.is_empty() && Sha256::digest(value).as_slice() == digest =>
        {
            super::validate_blob_operation_storage_key(value)?;
            Ok(())
        }
        _ => Err(StoreError::Blob(BlobStoreError::SchemaInvariant(
            "Blob retirement resolver is not canonical",
        ))),
    }
}

pub(crate) fn insert_retirement_resolver(
    write: &redb::WriteTransaction,
    limits: BlobLifecycleLimits,
    owner: RetentionDeadlineOwner,
    operation_key: Option<&[u8]>,
) -> Result<(), StoreError> {
    let value = match (owner, operation_key) {
        (RetentionDeadlineOwner::Publication(_), None) => &[][..],
        (RetentionDeadlineOwner::Operation(_), Some(key)) => key,
        _ => {
            return Err(StoreError::Blob(BlobStoreError::SchemaInvariant(
                "Blob retirement resolver owner and value disagree",
            )));
        }
    };
    validate_retirement_resolver(owner, value)?;
    let rows = lifecycle_counter(write, BLOB_RETIREMENT_RESOLVER_ROWS)?
        .checked_add(1)
        .ok_or(StoreError::ItemCountAccountingOverflow)?;
    let maximum = limits
        .max_publication_rows()
        .checked_add(super::MAX_BLOB_OPERATIONS)
        .ok_or(StoreError::ItemCountAccountingOverflow)?;
    if rows > maximum {
        return Err(StoreError::Blob(BlobStoreError::SchemaInvariant(
            "Blob retirement resolver rows exceed their structural bound",
        )));
    }
    let key = retirement_resolver_key(owner);
    if write
        .open_table(BLOB_RETIREMENT_RESOLVERS)?
        .insert(key.as_slice(), value)?
        .is_some()
    {
        return Err(StoreError::Blob(BlobStoreError::SchemaInvariant(
            "Blob retirement resolver already exists",
        )));
    }
    set_lifecycle_counter(write, BLOB_RETIREMENT_RESOLVER_ROWS, rows)
}

pub(crate) fn remove_retirement_resolver(
    write: &redb::WriteTransaction,
    owner: RetentionDeadlineOwner,
) -> Result<Vec<u8>, StoreError> {
    let rows = lifecycle_counter(write, BLOB_RETIREMENT_RESOLVER_ROWS)?
        .checked_sub(1)
        .ok_or(StoreError::Blob(BlobStoreError::SchemaInvariant(
            "Blob retirement resolver counter underflows",
        )))?;
    let key = retirement_resolver_key(owner);
    let value = write
        .open_table(BLOB_RETIREMENT_RESOLVERS)?
        .remove(key.as_slice())?
        .map(|value| value.value().to_vec())
        .ok_or(StoreError::Blob(BlobStoreError::SchemaInvariant(
            "Blob retirement resolver is missing",
        )))?;
    validate_retirement_resolver(owner, &value)?;
    set_lifecycle_counter(write, BLOB_RETIREMENT_RESOLVER_ROWS, rows)?;
    Ok(value)
}

pub(crate) fn retirement_operation_key_write(
    write: &redb::WriteTransaction,
    digest: [u8; 32],
) -> Result<Vec<u8>, StoreError> {
    let owner = RetentionDeadlineOwner::Operation(digest);
    let value = write
        .open_table(BLOB_RETIREMENT_RESOLVERS)?
        .get(retirement_resolver_key(owner).as_slice())?
        .map(|value| value.value().to_vec())
        .ok_or(StoreError::Blob(BlobStoreError::SchemaInvariant(
            "Blob operation retirement resolver is missing",
        )))?;
    validate_retirement_resolver(owner, &value)?;
    Ok(value)
}

pub(crate) fn replace_operation_retirement_authority(
    write: &redb::WriteTransaction,
    old_digest: [u8; 32],
    old_operation_key: &[u8],
    new_digest: [u8; 32],
    new_operation_key: &[u8],
    deadline: Option<CustodySample>,
) -> Result<(), StoreError> {
    let old_owner = RetentionDeadlineOwner::Operation(old_digest);
    let new_owner = RetentionDeadlineOwner::Operation(new_digest);
    validate_retirement_resolver(old_owner, old_operation_key)?;
    validate_retirement_resolver(new_owner, new_operation_key)?;
    let old_resolver_key = retirement_resolver_key(old_owner);
    let new_resolver_key = retirement_resolver_key(new_owner);
    let mut resolvers = write.open_table(BLOB_RETIREMENT_RESOLVERS)?;
    let removed = resolvers
        .remove(old_resolver_key.as_slice())?
        .map(|value| value.value().to_vec())
        .ok_or(StoreError::Blob(BlobStoreError::SchemaInvariant(
            "Blob operation retirement resolver is missing",
        )))?;
    if removed != old_operation_key {
        return Err(StoreError::Blob(BlobStoreError::SchemaInvariant(
            "retired Blob operation resolver differs from its predecessor key",
        )));
    }
    if resolvers
        .insert(new_resolver_key.as_slice(), new_operation_key)?
        .is_some()
    {
        return Err(StoreError::Blob(BlobStoreError::SchemaInvariant(
            "Blob operation retirement resolver replacement collides",
        )));
    }
    drop(resolvers);

    if let Some(deadline) = deadline {
        let old_deadline_key = retention_deadline_key(deadline, old_owner);
        let new_deadline_key = retention_deadline_key(deadline, new_owner);
        let mut deadlines = write.open_table(BLOB_RETENTION_DEADLINES)?;
        if deadlines.remove(old_deadline_key.as_slice())?.is_none() {
            return Err(StoreError::Blob(BlobStoreError::SchemaInvariant(
                "Blob retention deadline is missing",
            )));
        }
        if deadlines
            .insert(new_deadline_key.as_slice(), &[][..])?
            .is_some()
        {
            return Err(StoreError::Blob(BlobStoreError::SchemaInvariant(
                "Blob operation retention deadline replacement collides",
            )));
        }
    }
    Ok(())
}

pub(crate) fn require_publication_retirement_resolver_write(
    write: &redb::WriteTransaction,
    transfer: BlobTransferId,
) -> Result<(), StoreError> {
    let owner = RetentionDeadlineOwner::Publication(transfer);
    let value = write
        .open_table(BLOB_RETIREMENT_RESOLVERS)?
        .get(retirement_resolver_key(owner).as_slice())?
        .map(|value| value.value().to_vec())
        .ok_or(StoreError::Blob(BlobStoreError::SchemaInvariant(
            "Blob publication retirement resolver is missing",
        )))?;
    validate_retirement_resolver(owner, &value)
}

pub(crate) struct RetirementResolver {
    pub(crate) position: Vec<u8>,
    pub(crate) owner: RetentionDeadlineOwner,
    pub(crate) value: Vec<u8>,
}

pub(crate) fn next_retirement_resolver_write(
    write: &redb::WriteTransaction,
    position: Option<&[u8]>,
) -> Result<Option<RetirementResolver>, StoreError> {
    use std::ops::Bound::{Excluded, Unbounded};

    let resolvers = write.open_table(BLOB_RETIREMENT_RESOLVERS)?;
    let next = match position {
        Some(position) => resolvers
            .range::<&[u8]>((Excluded(position), Unbounded))?
            .next()
            .transpose()?,
        None => resolvers.iter()?.next().transpose()?,
    };
    let row = match (next, position) {
        (Some(row), _) => Some(row),
        (None, Some(_)) => resolvers.iter()?.next().transpose()?,
        (None, None) => None,
    };
    let Some((key, value)) = row else {
        return Ok(None);
    };
    let position = key.value().to_vec();
    let owner = decode_retirement_resolver_key(&position)?;
    let value = value.value().to_vec();
    validate_retirement_resolver(owner, &value)?;
    Ok(Some(RetirementResolver {
        position,
        owner,
        value,
    }))
}

fn retention_deadline_key(deadline: CustodySample, owner: RetentionDeadlineOwner) -> [u8; 57] {
    let mut key = [0u8; 57];
    key[..16].copy_from_slice(&deadline.clock_id);
    key[16] = owner.kind().tag();
    key[17..25].copy_from_slice(&deadline.tick_ms.to_be_bytes());
    match owner {
        RetentionDeadlineOwner::Publication(transfer) => {
            key[25..].copy_from_slice(transfer.as_bytes());
        }
        RetentionDeadlineOwner::Operation(digest) => {
            key[25..].copy_from_slice(&digest);
        }
    }
    key
}

fn retention_deadline_key_v2(deadline: CustodySample, owner: RetentionDeadlineOwner) -> [u8; 57] {
    let mut key = [0u8; 57];
    key[..16].copy_from_slice(&deadline.clock_id);
    key[16..24].copy_from_slice(&deadline.tick_ms.to_be_bytes());
    key[24] = owner.kind().tag();
    match owner {
        RetentionDeadlineOwner::Publication(transfer) => {
            key[25..].copy_from_slice(transfer.as_bytes());
        }
        RetentionDeadlineOwner::Operation(digest) => {
            key[25..].copy_from_slice(&digest);
        }
    }
    key
}

fn decode_retention_deadline_key(
    key: &[u8],
) -> Result<(CustodySample, RetentionDeadlineOwner), StoreError> {
    let key: [u8; 57] = key.try_into().map_err(|_| {
        StoreError::Blob(BlobStoreError::SchemaInvariant(
            "Blob retention deadline key has an invalid length",
        ))
    })?;
    let sample = CustodySample {
        clock_id: key[..16].try_into().expect("fixed deadline clock ID"),
        tick_ms: u64::from_be_bytes(key[17..25].try_into().expect("fixed deadline tick")),
    };
    let identity: [u8; 32] = key[25..].try_into().expect("fixed deadline owner");
    let owner = match key[16] {
        1 => RetentionDeadlineOwner::Publication(BlobTransferId::new(identity)),
        2 => RetentionDeadlineOwner::Operation(identity),
        _ => {
            return Err(StoreError::Blob(BlobStoreError::SchemaInvariant(
                "Blob retention deadline owner is unknown",
            )));
        }
    };
    Ok((sample, owner))
}

fn decode_retention_deadline_key_v2(
    key: &[u8],
) -> Result<(CustodySample, RetentionDeadlineOwner), StoreError> {
    let key: [u8; 57] = key.try_into().map_err(|_| {
        StoreError::Blob(BlobStoreError::SchemaInvariant(
            "Blob retention deadline key has an invalid length",
        ))
    })?;
    let sample = CustodySample {
        clock_id: key[..16].try_into().expect("fixed deadline clock ID"),
        tick_ms: u64::from_be_bytes(key[16..24].try_into().expect("fixed deadline tick")),
    };
    let identity: [u8; 32] = key[25..].try_into().expect("fixed deadline owner");
    let owner = match key[24] {
        1 => RetentionDeadlineOwner::Publication(BlobTransferId::new(identity)),
        2 => RetentionDeadlineOwner::Operation(identity),
        _ => {
            return Err(StoreError::Blob(BlobStoreError::SchemaInvariant(
                "Blob retention deadline owner is unknown",
            )));
        }
    };
    Ok((sample, owner))
}

fn nearest_retention_deadline_in_table(
    deadlines: &impl ReadableTable<&'static [u8], &'static [u8]>,
    clock_id: [u8; 16],
    kind: RetentionDeadlineKind,
) -> Result<Option<(CustodySample, RetentionDeadlineOwner)>, StoreError> {
    let mut start = [0u8; 57];
    start[..16].copy_from_slice(&clock_id);
    start[16] = kind.tag();
    let Some((key, value)) = deadlines.range(start.as_slice()..)?.next().transpose()? else {
        return Ok(None);
    };
    if key.value()[..16] != clock_id || key.value()[16] != kind.tag() {
        return Ok(None);
    }
    if !value.value().is_empty() {
        return Err(StoreError::Blob(BlobStoreError::SchemaInvariant(
            "Blob retention deadline value is not empty",
        )));
    }
    decode_retention_deadline_key(key.value()).map(Some)
}

pub(crate) fn nearest_retention_deadline_read(
    read: &redb::ReadTransaction,
    clock_id: [u8; 16],
) -> Result<Option<(CustodySample, RetentionDeadlineOwner)>, StoreError> {
    let deadlines = read.open_table(BLOB_RETENTION_DEADLINES)?;
    let publication = nearest_retention_deadline_in_table(
        &deadlines,
        clock_id,
        RetentionDeadlineKind::Publication,
    )?;
    let operation = nearest_retention_deadline_in_table(
        &deadlines,
        clock_id,
        RetentionDeadlineKind::Operation,
    )?;
    Ok([publication, operation]
        .into_iter()
        .flatten()
        .min_by_key(|(deadline, owner)| (deadline.tick_ms, owner.kind().tag())))
}

pub(crate) fn nearest_retention_deadline_write(
    write: &redb::WriteTransaction,
    clock_id: [u8; 16],
) -> Result<Option<(CustodySample, RetentionDeadlineOwner)>, StoreError> {
    let deadlines = write.open_table(BLOB_RETENTION_DEADLINES)?;
    let publication = nearest_retention_deadline_in_table(
        &deadlines,
        clock_id,
        RetentionDeadlineKind::Publication,
    )?;
    let operation = nearest_retention_deadline_in_table(
        &deadlines,
        clock_id,
        RetentionDeadlineKind::Operation,
    )?;
    Ok([publication, operation]
        .into_iter()
        .flatten()
        .min_by_key(|(deadline, owner)| (deadline.tick_ms, owner.kind().tag())))
}

pub(crate) fn nearest_retention_deadline_for_kind_write(
    write: &redb::WriteTransaction,
    clock_id: [u8; 16],
    kind: RetentionDeadlineKind,
) -> Result<Option<(CustodySample, RetentionDeadlineOwner)>, StoreError> {
    let deadlines = write.open_table(BLOB_RETENTION_DEADLINES)?;
    nearest_retention_deadline_in_table(&deadlines, clock_id, kind)
}

pub(crate) fn next_retention_deadline_write(
    write: &redb::WriteTransaction,
    position: Option<&[u8]>,
) -> Result<Option<(Vec<u8>, CustodySample, RetentionDeadlineOwner)>, StoreError> {
    use std::ops::Bound::{Excluded, Unbounded};

    let deadlines = write.open_table(BLOB_RETENTION_DEADLINES)?;
    let next = match position {
        Some(position) => deadlines
            .range::<&[u8]>((Excluded(position), Unbounded))?
            .next()
            .transpose()?,
        None => deadlines.iter()?.next().transpose()?,
    };
    let row = match (next, position) {
        (Some(row), _) => Some(row),
        (None, Some(_)) => deadlines.iter()?.next().transpose()?,
        (None, None) => None,
    };
    let Some((key, value)) = row else {
        return Ok(None);
    };
    if !value.value().is_empty() {
        return Err(StoreError::Blob(BlobStoreError::SchemaInvariant(
            "Blob retention deadline value is not empty",
        )));
    }
    let position = key.value().to_vec();
    let (deadline, owner) = decode_retention_deadline_key(&position)?;
    Ok(Some((position, deadline, owner)))
}

pub(crate) fn insert_retention_deadline(
    write: &redb::WriteTransaction,
    limits: BlobLifecycleLimits,
    deadline: CustodySample,
    owner: RetentionDeadlineOwner,
) -> Result<(), StoreError> {
    let current = lifecycle_counter(write, BLOB_DEADLINE_ROWS)?;
    let rows = current
        .checked_add(1)
        .ok_or(StoreError::ItemCountAccountingOverflow)?;
    let maximum = limits
        .max_publication_rows()
        .checked_add(super::MAX_BLOB_OPERATIONS)
        .ok_or(StoreError::ItemCountAccountingOverflow)?;
    if rows > maximum {
        return Err(StoreError::Blob(BlobStoreError::SchemaInvariant(
            "Blob retention deadline rows exceed their structural bound",
        )));
    }
    let key = retention_deadline_key(deadline, owner);
    if write
        .open_table(BLOB_RETENTION_DEADLINES)?
        .insert(key.as_slice(), &[][..])?
        .is_some()
    {
        return Err(StoreError::Blob(BlobStoreError::SchemaInvariant(
            "Blob retention deadline already exists",
        )));
    }
    set_lifecycle_counter(write, BLOB_DEADLINE_ROWS, rows)
}

pub(crate) fn insert_reanchored_retention_deadline(
    write: &redb::WriteTransaction,
    deadline: CustodySample,
    owner: RetentionDeadlineOwner,
) -> Result<(), StoreError> {
    let rows = lifecycle_counter(write, BLOB_DEADLINE_ROWS)?
        .checked_add(1)
        .ok_or(StoreError::ItemCountAccountingOverflow)?;
    if rows > lifecycle_counter(write, BLOB_RETIREMENT_RESOLVER_ROWS)? {
        return Err(StoreError::Blob(BlobStoreError::SchemaInvariant(
            "Blob retention deadline has no retirement resolver",
        )));
    }
    let key = retention_deadline_key(deadline, owner);
    if write
        .open_table(BLOB_RETENTION_DEADLINES)?
        .insert(key.as_slice(), &[][..])?
        .is_some()
    {
        return Err(StoreError::Blob(BlobStoreError::SchemaInvariant(
            "Blob retention deadline already exists",
        )));
    }
    set_lifecycle_counter(write, BLOB_DEADLINE_ROWS, rows)
}

pub(crate) fn remove_retention_deadline(
    write: &redb::WriteTransaction,
    deadline: CustodySample,
    owner: RetentionDeadlineOwner,
) -> Result<(), StoreError> {
    let key = retention_deadline_key(deadline, owner);
    let rows = lifecycle_counter(write, BLOB_DEADLINE_ROWS)?
        .checked_sub(1)
        .ok_or(StoreError::Blob(BlobStoreError::SchemaInvariant(
            "Blob retention deadline counter underflows",
        )))?;
    if write
        .open_table(BLOB_RETENTION_DEADLINES)?
        .remove(key.as_slice())?
        .is_none()
    {
        return Err(StoreError::Blob(BlobStoreError::SchemaInvariant(
            "Blob retention deadline is missing",
        )));
    }
    set_lifecycle_counter(write, BLOB_DEADLINE_ROWS, rows)
}

pub(crate) fn replace_retention_deadline(
    write: &redb::WriteTransaction,
    old_deadline: CustodySample,
    new_deadline: CustodySample,
    owner: RetentionDeadlineOwner,
) -> Result<(), StoreError> {
    let old_key = retention_deadline_key(old_deadline, owner);
    let new_key = retention_deadline_key(new_deadline, owner);
    if old_key == new_key {
        let deadlines = write.open_table(BLOB_RETENTION_DEADLINES)?;
        let value = deadlines.get(old_key.as_slice())?.ok_or(StoreError::Blob(
            BlobStoreError::SchemaInvariant("Blob retention deadline is missing"),
        ))?;
        if !value.value().is_empty() {
            return Err(StoreError::Blob(BlobStoreError::SchemaInvariant(
                "Blob retention deadline value is not empty",
            )));
        }
        return Ok(());
    }
    let mut deadlines = write.open_table(BLOB_RETENTION_DEADLINES)?;
    if deadlines.remove(old_key.as_slice())?.is_none() {
        return Err(StoreError::Blob(BlobStoreError::SchemaInvariant(
            "Blob retention deadline is missing",
        )));
    }
    if deadlines.insert(new_key.as_slice(), &[][..])?.is_some() {
        return Err(StoreError::Blob(BlobStoreError::SchemaInvariant(
            "multiple Blob retirements claim one exact deadline key",
        )));
    }
    Ok(())
}

pub(crate) fn allocate_retirement_generation(
    write: &redb::WriteTransaction,
) -> Result<u64, StoreError> {
    let current = lifecycle_counter(write, BLOB_NEXT_RETIREMENT_GENERATION)?;
    let generation = current
        .checked_add(1)
        .ok_or(StoreError::ItemCountAccountingOverflow)?;
    set_lifecycle_counter(write, BLOB_NEXT_RETIREMENT_GENERATION, generation)?;
    Ok(generation)
}

/// Preflights and charges each distinct lifecycle-accounting row updated by
/// one policy-invalidation retirement. Repeated reads or writes of the same
/// metadata field count once, matching retained-record expiry's unique-row
/// accounting model.
pub(crate) fn policy_retirement_accounting_charge_write(
    write: &redb::WriteTransaction,
    limits: BlobLifecycleLimits,
    operation_rows: u64,
    has_deadline: bool,
    charge: &mut super::MaintenanceCharge,
) -> Result<bool, StoreError> {
    fn charged_counter(
        write: &redb::WriteTransaction,
        field: &'static str,
        charge: &mut super::MaintenanceCharge,
    ) -> Result<Option<u64>, StoreError> {
        if !charge.charge_row(
            super::MaintenanceRowIdentity::new(
                "aster.blob-lifecycle-metadata.v1",
                field.as_bytes(),
            ),
            std::mem::size_of::<u64>(),
        )? {
            return Ok(None);
        }
        lifecycle_counter(write, field).map(Some)
    }

    let Some(next_generation) = charged_counter(write, BLOB_NEXT_RETIREMENT_GENERATION, charge)?
    else {
        return Ok(false);
    };
    next_generation
        .checked_add(1)
        .ok_or(StoreError::ItemCountAccountingOverflow)?;
    let Some(retired_publications) = charged_counter(write, BLOB_RETIRED_PUBLICATION_ROWS, charge)?
    else {
        return Ok(false);
    };
    retired_publications
        .checked_add(1)
        .ok_or(StoreError::ItemCountAccountingOverflow)?;
    let Some(resolver_rows) = charged_counter(write, BLOB_RETIREMENT_RESOLVER_ROWS, charge)? else {
        return Ok(false);
    };

    let inserted = operation_rows
        .checked_add(1)
        .ok_or(StoreError::ItemCountAccountingOverflow)?;
    let maximum = limits
        .max_publication_rows()
        .checked_add(super::MAX_BLOB_OPERATIONS)
        .ok_or(StoreError::ItemCountAccountingOverflow)?;
    if resolver_rows
        .checked_add(inserted)
        .ok_or(StoreError::ItemCountAccountingOverflow)?
        > maximum
    {
        return Err(StoreError::Blob(BlobStoreError::SchemaInvariant(
            "Blob retirement authority exceeds its structural bound",
        )));
    }
    if has_deadline {
        let Some(deadline_rows) = charged_counter(write, BLOB_DEADLINE_ROWS, charge)? else {
            return Ok(false);
        };
        if deadline_rows
            .checked_add(inserted)
            .ok_or(StoreError::ItemCountAccountingOverflow)?
            > maximum
        {
            return Err(StoreError::Blob(BlobStoreError::SchemaInvariant(
                "Blob retirement authority exceeds its structural bound",
            )));
        }
    }
    if operation_rows != 0 {
        let Some(operation_owner_rows) = charged_counter(write, BLOB_OPERATION_OWNER_ROWS, charge)?
        else {
            return Ok(false);
        };
        operation_owner_rows
            .checked_sub(operation_rows)
            .ok_or(StoreError::Blob(BlobStoreError::SchemaInvariant(
                "Blob operation-owner accounting cannot cover retirement",
            )))?;
        let Some(retired_operations) = charged_counter(write, BLOB_RETIRED_OPERATION_ROWS, charge)?
        else {
            return Ok(false);
        };
        retired_operations
            .checked_add(operation_rows)
            .ok_or(StoreError::ItemCountAccountingOverflow)?;
    }
    Ok(true)
}

/// Incrementally preflights and charges one resolver plus its optional
/// deadline before any retirement mutation begins.
pub(crate) fn policy_retirement_authority_charge_write(
    write: &redb::WriteTransaction,
    owner: RetentionDeadlineOwner,
    value: &[u8],
    deadline: Option<aster_mesh::CustodySample>,
    charge: &mut super::MaintenanceCharge,
) -> Result<bool, StoreError> {
    let resolver_key = retirement_resolver_key(owner);
    if !charge.charge_row(
        super::MaintenanceRowIdentity::new(
            "aster.blob-retirement-resolvers.v1",
            resolver_key.as_slice(),
        ),
        value.len(),
    )? {
        return Ok(false);
    }
    if write
        .open_table(BLOB_RETIREMENT_RESOLVERS)?
        .get(resolver_key.as_slice())?
        .is_some()
    {
        return Err(StoreError::Blob(BlobStoreError::SchemaInvariant(
            "Blob retirement resolver already exists",
        )));
    }
    if let Some(deadline) = deadline {
        let deadline_key = retention_deadline_key(deadline, owner);
        if !charge.charge_row(
            super::MaintenanceRowIdentity::new(
                "aster.blob-retention-deadlines.v1",
                deadline_key.as_slice(),
            ),
            0,
        )? {
            return Ok(false);
        }
        if write
            .open_table(BLOB_RETENTION_DEADLINES)?
            .get(deadline_key.as_slice())?
            .is_some()
        {
            return Err(StoreError::Blob(BlobStoreError::SchemaInvariant(
                "Blob retention deadline already exists",
            )));
        }
    }
    Ok(true)
}

pub(crate) fn record_publication_retirement(
    write: &redb::WriteTransaction,
) -> Result<(), StoreError> {
    let retired = lifecycle_counter(write, BLOB_RETIRED_PUBLICATION_ROWS)?
        .checked_add(1)
        .ok_or(StoreError::ItemCountAccountingOverflow)?;
    set_lifecycle_counter(write, BLOB_RETIRED_PUBLICATION_ROWS, retired)
}

pub(crate) fn record_operation_retirement(
    write: &redb::WriteTransaction,
) -> Result<(), StoreError> {
    let retired = lifecycle_counter(write, BLOB_RETIRED_OPERATION_ROWS)?
        .checked_add(1)
        .ok_or(StoreError::ItemCountAccountingOverflow)?;
    set_lifecycle_counter(write, BLOB_RETIRED_OPERATION_ROWS, retired)
}

pub(crate) fn remove_publication_retirement(
    write: &redb::WriteTransaction,
) -> Result<(), StoreError> {
    let publications = lifecycle_counter(write, BLOB_PUBLICATION_ROWS)?
        .checked_sub(1)
        .ok_or(StoreError::Blob(BlobStoreError::SchemaInvariant(
            "Blob publication lifecycle counter underflows on retirement expiry",
        )))?;
    let retired = lifecycle_counter(write, BLOB_RETIRED_PUBLICATION_ROWS)?
        .checked_sub(1)
        .ok_or(StoreError::Blob(BlobStoreError::SchemaInvariant(
            "Blob retired-publication counter underflows on retirement expiry",
        )))?;
    set_lifecycle_counter(write, BLOB_PUBLICATION_ROWS, publications)?;
    set_lifecycle_counter(write, BLOB_RETIRED_PUBLICATION_ROWS, retired)
}

pub(crate) fn remove_operation_retirement(
    write: &redb::WriteTransaction,
) -> Result<(), StoreError> {
    let retired = lifecycle_counter(write, BLOB_RETIRED_OPERATION_ROWS)?
        .checked_sub(1)
        .ok_or(StoreError::Blob(BlobStoreError::SchemaInvariant(
            "Blob retired-operation counter underflows on retirement expiry",
        )))?;
    set_lifecycle_counter(write, BLOB_RETIRED_OPERATION_ROWS, retired)
}

pub(crate) fn inverse_owner_key(owner: BlobTransferId, forward_key: &[u8]) -> Vec<u8> {
    let mut key = Vec::with_capacity(64);
    key.extend_from_slice(owner.as_bytes());
    key.extend_from_slice(&Sha256::digest(forward_key));
    key
}

pub(crate) fn inverse_owner_bounds(owner: BlobTransferId) -> ([u8; 64], [u8; 64]) {
    let mut start = [0u8; 64];
    start[..32].copy_from_slice(owner.as_bytes());
    let mut end = [0xffu8; 64];
    end[..32].copy_from_slice(owner.as_bytes());
    (start, end)
}

fn insert_inverse_owner(
    write: &redb::WriteTransaction,
    table: TableDefinition<&[u8], &[u8]>,
    counter: &'static str,
    owner: BlobTransferId,
    forward_key: &[u8],
    limit: u64,
) -> Result<(), StoreError> {
    if !admission_schema_is_current(write)? {
        return Ok(());
    }
    let rows = lifecycle_counter(write, counter)?
        .checked_add(1)
        .ok_or(StoreError::ItemCountAccountingOverflow)?;
    if rows > limit {
        return Err(StoreError::Blob(BlobStoreError::SchemaInvariant(
            "Blob inverse-owner rows exceed their forward authority bound",
        )));
    }
    let key = inverse_owner_key(owner, forward_key);
    if write
        .open_table(table)?
        .insert(key.as_slice(), forward_key)?
        .is_some()
    {
        return Err(StoreError::Blob(BlobStoreError::SchemaInvariant(
            "Blob inverse owner already exists",
        )));
    }
    set_lifecycle_counter(write, counter, rows)
}

fn remove_inverse_owner(
    write: &redb::WriteTransaction,
    table: TableDefinition<&[u8], &[u8]>,
    counter: &'static str,
    owner: BlobTransferId,
    forward_key: &[u8],
) -> Result<(), StoreError> {
    if !admission_schema_is_current(write)? {
        return Ok(());
    }
    let key = inverse_owner_key(owner, forward_key);
    let rows = lifecycle_counter(write, counter)?
        .checked_sub(1)
        .ok_or(StoreError::Blob(BlobStoreError::SchemaInvariant(
            "Blob inverse-owner counter underflows",
        )))?;
    if write.open_table(table)?.remove(key.as_slice())?.is_none() {
        return Err(StoreError::Blob(BlobStoreError::SchemaInvariant(
            "Blob inverse owner is missing",
        )));
    }
    set_lifecycle_counter(write, counter, rows)
}

pub(crate) fn insert_operation_owner(
    write: &redb::WriteTransaction,
    owner: BlobTransferId,
    operation_key: &[u8],
) -> Result<(), StoreError> {
    insert_inverse_owner(
        write,
        BLOB_OPERATION_OWNERS,
        BLOB_OPERATION_OWNER_ROWS,
        owner,
        operation_key,
        super::MAX_BLOB_OPERATIONS,
    )
}

pub(crate) fn remove_operation_owner(
    write: &redb::WriteTransaction,
    owner: BlobTransferId,
    operation_key: &[u8],
) -> Result<(), StoreError> {
    remove_inverse_owner(
        write,
        BLOB_OPERATION_OWNERS,
        BLOB_OPERATION_OWNER_ROWS,
        owner,
        operation_key,
    )
}

type InverseOwnerEntry = (Vec<u8>, Vec<u8>);

fn inverse_owner_entries(
    write: &redb::WriteTransaction,
    table: TableDefinition<&'static [u8], &'static [u8]>,
    owner: BlobTransferId,
    limit: u64,
) -> Result<Vec<InverseOwnerEntry>, StoreError> {
    let (start, end) = inverse_owner_bounds(owner);
    let rows = write.open_table(table)?;
    let mut keys = Vec::new();
    for row in rows.range::<&[u8]>((
        std::ops::Bound::Included(start.as_slice()),
        std::ops::Bound::Included(end.as_slice()),
    ))? {
        let (key, value) = row?;
        if key.value().len() != 64 || &key.value()[..32] != owner.as_bytes() {
            return Err(StoreError::Blob(BlobStoreError::SchemaInvariant(
                "Blob inverse-owner range escaped its exact owner",
            )));
        }
        if u64::try_from(keys.len()).map_err(|_| StoreError::ItemCountAccountingOverflow)? >= limit
        {
            return Err(StoreError::Blob(BlobStoreError::SchemaInvariant(
                "Blob inverse-owner fan-out exceeds its structural bound",
            )));
        }
        let forward = value.value().to_vec();
        if inverse_owner_key(owner, &forward).as_slice() != key.value() {
            return Err(StoreError::Blob(BlobStoreError::SchemaInvariant(
                "Blob inverse-owner key differs from its forward authority",
            )));
        }
        keys.push((key.value().to_vec(), forward));
    }
    Ok(keys)
}

pub(crate) fn operation_owner_entries_for_owner(
    write: &redb::WriteTransaction,
    owner: BlobTransferId,
) -> Result<Vec<InverseOwnerEntry>, StoreError> {
    inverse_owner_entries(
        write,
        BLOB_OPERATION_OWNERS,
        owner,
        super::MAX_BLOB_OPERATIONS,
    )
}

pub(crate) fn delivery_owner_entries_for_owner(
    write: &redb::WriteTransaction,
    owner: BlobTransferId,
) -> Result<Vec<InverseOwnerEntry>, StoreError> {
    inverse_owner_entries(
        write,
        BLOB_DELIVERY_OWNERS,
        owner,
        crate::blob_subscription::MAX_BLOB_SUBSCRIPTIONS,
    )
}

pub(crate) fn operation_keys_for_owner(
    write: &redb::WriteTransaction,
    owner: BlobTransferId,
) -> Result<Vec<Vec<u8>>, StoreError> {
    operation_owner_entries_for_owner(write, owner)
        .map(|entries| entries.into_iter().map(|(_, forward)| forward).collect())
}

pub(crate) fn delivery_keys_for_owner(
    write: &redb::WriteTransaction,
    owner: BlobTransferId,
) -> Result<Vec<Vec<u8>>, StoreError> {
    delivery_owner_entries_for_owner(write, owner)
        .map(|entries| entries.into_iter().map(|(_, forward)| forward).collect())
}

pub(crate) fn insert_delivery_owner(
    write: &redb::WriteTransaction,
    owner: BlobTransferId,
    delivery_key: &[u8],
) -> Result<(), StoreError> {
    insert_inverse_owner(
        write,
        BLOB_DELIVERY_OWNERS,
        BLOB_DELIVERY_OWNER_ROWS,
        owner,
        delivery_key,
        crate::blob_subscription::MAX_BLOB_PENDING_DELIVERIES,
    )
}

pub(crate) fn remove_delivery_owner(
    write: &redb::WriteTransaction,
    owner: BlobTransferId,
    delivery_key: &[u8],
) -> Result<(), StoreError> {
    remove_inverse_owner(
        write,
        BLOB_DELIVERY_OWNERS,
        BLOB_DELIVERY_OWNER_ROWS,
        owner,
        delivery_key,
    )
}

fn inverse_owner_rows(
    rows: impl IntoIterator<Item = (BlobTransferId, Vec<u8>)>,
    conflict: &'static str,
) -> Result<BTreeMap<Vec<u8>, Vec<u8>>, StoreError> {
    let mut inverse = BTreeMap::new();
    for (owner, forward_key) in rows {
        insert_unique(
            &mut inverse,
            inverse_owner_key(owner, &forward_key),
            forward_key,
            conflict,
        )?;
    }
    Ok(inverse)
}

fn variant_reference_key(
    variant: super::BlobVariantId,
    owner: VariantReferenceOwner,
    transfer: BlobTransferId,
) -> Vec<u8> {
    let mut key = Vec::with_capacity(65);
    key.extend_from_slice(variant.as_bytes());
    key.extend_from_slice(&owner.encode());
    key.extend_from_slice(transfer.as_bytes());
    key
}

fn entry_bytes(key: &[u8], value: &[u8]) -> Result<u64, StoreError> {
    key.len()
        .checked_add(value.len())
        .and_then(|length| u64::try_from(length).ok())
        .ok_or(StoreError::PayloadByteAccountingOverflow)
}

fn insert_unique(
    rows: &mut BTreeMap<Vec<u8>, Vec<u8>>,
    key: Vec<u8>,
    value: Vec<u8>,
    conflict: &'static str,
) -> Result<(), StoreError> {
    if rows.insert(key, value).is_some() {
        return Err(StoreError::Blob(BlobStoreError::SchemaInvariant(conflict)));
    }
    Ok(())
}

fn reconstruct_retirement_authority(
    expected: &mut ExpectedLifecycleImage,
    schema: LifecycleSchemaState,
    generation: u64,
    age: RetirementAge,
    owner: RetentionDeadlineOwner,
    operation_key: Option<&[u8]>,
) -> Result<(), StoreError> {
    expected.usage.next_retirement_generation =
        expected.usage.next_retirement_generation.max(generation);
    let projection = age
        .project(age.checkpoint_sample())
        .map_err(StoreError::Blob)?;
    if let Some(deadline) = projection.deadline {
        let key = if schema == LifecycleSchemaState::V2 {
            retention_deadline_key_v2(deadline, owner)
        } else {
            retention_deadline_key(deadline, owner)
        };
        insert_unique(
            &mut expected.deadlines,
            key.to_vec(),
            Vec::new(),
            "multiple Blob retirements claim one exact deadline key",
        )?;
    }
    let resolver_value = match (owner, operation_key) {
        (RetentionDeadlineOwner::Publication(_), None) => Vec::new(),
        (RetentionDeadlineOwner::Operation(_), Some(key)) => key.to_vec(),
        _ => {
            return Err(StoreError::Blob(BlobStoreError::SchemaInvariant(
                "Blob retirement resolver reconstruction disagrees with its owner",
            )));
        }
    };
    validate_retirement_resolver(owner, &resolver_value)?;
    insert_unique(
        &mut expected.retirement_resolvers,
        retirement_resolver_key(owner).to_vec(),
        resolver_value,
        "multiple Blob retirements claim one exact resolver",
    )?;
    Ok(())
}

#[allow(clippy::too_many_arguments)] // One audit seam receives independent durable authorities.
fn reconstruct_expected_image(
    publications: &impl ReadableTable<&'static [u8], &'static [u8]>,
    source_bytes: &impl ReadableTable<&'static [u8], &'static [u8]>,
    operations: &impl ReadableTable<&'static [u8], &'static [u8]>,
    pending_sources: Vec<(Vec<u8>, Vec<u8>)>,
    delivery_owner_rows: Vec<(BlobTransferId, Vec<u8>)>,
    imports: Vec<depot::AuditedLifecycleImport>,
    owner_binding: [u8; 32],
    schema: LifecycleSchemaState,
    continuity: Option<custody::LowerBoundContinuity>,
    project_lifetimes_for_v5: bool,
) -> Result<ExpectedLifecycleImage, StoreError> {
    let mut expected = ExpectedLifecycleImage {
        publications: BTreeMap::new(),
        pending_sources: BTreeMap::new(),
        live_publications: BTreeSet::new(),
        retired_publications: BTreeSet::new(),
        operations: BTreeMap::new(),
        references: BTreeMap::new(),
        lineages: BTreeMap::new(),
        replays: BTreeMap::new(),
        operation_owners: BTreeMap::new(),
        delivery_owners: inverse_owner_rows(
            delivery_owner_rows,
            "multiple Blob deliveries claim one inverse owner key",
        )?,
        deadlines: BTreeMap::new(),
        ttl_deadlines: BTreeMap::new(),
        retirement_resolvers: BTreeMap::new(),
        operation_bytes: 0,
        usage: BlobLifecycleUsage::default(),
    };
    let mut import_lineages = BTreeMap::new();
    let mut publication_intents = BTreeMap::<BlobTransferId, [u8; 32]>::new();
    for import in imports {
        if import_lineages
            .insert(import.variant_id, import.physical_lineage)
            .is_some()
        {
            return Err(StoreError::Blob(BlobStoreError::SchemaInvariant(
                "multiple Blob imports claim one exact variant identity",
            )));
        }
        let key = import.variant_id.as_bytes().to_vec();
        let value = LineageFence::new(import.physical_lineage, owner_binding)
            .encode()
            .to_vec();
        expected.usage.lineage_bytes = expected
            .usage
            .lineage_bytes
            .checked_add(entry_bytes(&key, &value)?)
            .ok_or(StoreError::PayloadByteAccountingOverflow)?;
        insert_unique(
            &mut expected.lineages,
            key,
            value,
            "multiple lineage fences claim one exact variant",
        )?;
    }
    expected.usage.lineage_rows = u64::try_from(expected.lineages.len())
        .map_err(|_| StoreError::ItemCountAccountingOverflow)?;

    for row in publications.iter()? {
        let (key, value) = row?;
        let transfer = super::parse_blob_transfer_id("Blob publication table", key.value())?;
        let encoded = value.value();
        match schema {
            LifecycleSchemaState::Legacy if matches!(encoded.first().copied(), Some(4 | 5)) => {
                return Err(StoreError::Blob(BlobStoreError::SchemaInvariant(
                    "Blob predecessor contains a current publication wrapper",
                )));
            }
            LifecycleSchemaState::V1
                if encoded.first().copied() != Some(LIFECYCLE_V1_PUBLICATION_RECORD_VERSION) =>
            {
                return Err(StoreError::Blob(BlobStoreError::SchemaInvariant(
                    "Blob lifecycle-v1 publication wrapper is missing",
                )));
            }
            LifecycleSchemaState::V2 | LifecycleSchemaState::V3
                if encoded.first().copied() != Some(PREDECESSOR_PUBLICATION_RECORD_VERSION) =>
            {
                return Err(StoreError::Blob(BlobStoreError::SchemaInvariant(
                    "predecessor Blob publication is missing its lifecycle wrapper",
                )));
            }
            LifecycleSchemaState::V4 | LifecycleSchemaState::Current
                if !publication_is_current(encoded) =>
            {
                return Err(StoreError::Blob(BlobStoreError::SchemaInvariant(
                    "current Blob publication is missing its lifecycle wrapper",
                )));
            }
            _ => {}
        }
        if schema == LifecycleSchemaState::V3
            && encoded.first().copied() != Some(PREDECESSOR_PUBLICATION_RECORD_VERSION)
        {
            return Err(StoreError::Blob(BlobStoreError::SchemaInvariant(
                "Blob lifecycle-v3 publication wrapper is missing",
            )));
        }
        if matches!(
            schema,
            LifecycleSchemaState::V2
                | LifecycleSchemaState::V3
                | LifecycleSchemaState::V4
                | LifecycleSchemaState::Current
        ) && encoded.get(1).copied() == Some(PUBLICATION_STATE_RETIRED_TAG)
        {
            if let Some((_, payload)) =
                retired_publication_payload(encoded).map_err(StoreError::Blob)?
            {
                let metadata = super::decode_blob_metadata(payload)?;
                if metadata.header.ttl_ms.is_some() {
                    let intent = super::BlobPublicationIntent::new_with_ttl(
                        metadata.header.stamp.dot.publisher,
                        metadata.header.topic.clone(),
                        metadata.header.scope.clone(),
                        metadata.header.priority,
                        metadata.blob_id,
                        metadata.header.ttl_ms,
                    )?;
                    publication_intents.insert(transfer, intent.digest());
                }
            }
            let Some((_, generation, age)) =
                publication_retirement(encoded).map_err(StoreError::Blob)?
            else {
                unreachable!("retired publication tag decoded as live");
            };
            retired_publication_payload(encoded).map_err(StoreError::Blob)?;
            if source_bytes.get(key.value())?.is_some() {
                return Err(StoreError::Blob(BlobStoreError::SchemaInvariant(
                    "retired Blob publication still has source bytes",
                )));
            }
            reconstruct_retirement_authority(
                &mut expected,
                schema,
                generation,
                age,
                RetentionDeadlineOwner::Publication(transfer),
                None,
            )?;
            expected.usage.retired_publication_rows = expected
                .usage
                .retired_publication_rows
                .checked_add(1)
                .ok_or(StoreError::ItemCountAccountingOverflow)?;
            expected
                .retired_publications
                .insert(transfer.as_bytes().to_vec());
            let retained = if matches!(schema, LifecycleSchemaState::V2 | LifecycleSchemaState::V3)
            {
                upgrade_v3_publication(encoded)?
            } else {
                encoded.to_vec()
            };
            insert_unique(
                &mut expected.publications,
                key.value().to_vec(),
                retained,
                "multiple Blob publication rows claim one transfer identity",
            )?;
            continue;
        }
        let publication_payload = if schema == LifecycleSchemaState::V1 {
            &encoded[2..]
        } else {
            encoded
        };
        let mut publication = super::decode_blob_metadata(publication_payload)?;
        if project_lifetimes_for_v5 {
            publication.lifetime = project_lifetime_for_v5(publication.lifetime, continuity)?;
        }
        if let Some(deadline) = stored_ttl_deadline(
            transfer,
            TtlDeadlineKind::LivePublication,
            publication.lifetime,
        )? {
            insert_unique(
                &mut expected.ttl_deadlines,
                ttl_deadline_key(deadline)?.to_vec(),
                Vec::new(),
                "multiple live Blob publications claim one TTL deadline",
            )?;
        }
        let intent = super::BlobPublicationIntent::new_with_ttl(
            publication.header.stamp.dot.publisher,
            publication.header.topic.clone(),
            publication.header.scope.clone(),
            publication.header.priority,
            publication.blob_id,
            publication.header.ttl_ms,
        )?;
        if publication.header.ttl_ms.is_some() {
            publication_intents.insert(transfer, intent.digest());
        }
        expected
            .live_publications
            .insert(transfer.as_bytes().to_vec());
        let physical_lineage = publication.physical_lineage.ok_or_else(|| {
            StoreError::Blob(BlobStoreError::SchemaInvariant(
                "accepted Blob publication is missing authenticated physical lineage",
            ))
        })?;
        if import_lineages.get(&publication.variant_id) != Some(&physical_lineage) {
            return Err(StoreError::Blob(BlobStoreError::SchemaInvariant(
                "accepted Blob publication conflicts with its physical lineage",
            )));
        }
        let exact = source_bytes.get(key.value())?.ok_or_else(|| {
            StoreError::Blob(BlobStoreError::SchemaInvariant(
                "Blob publication is missing exact source bytes during lifecycle audit",
            ))
        })?;
        let source_len = u64::try_from(exact.value().len())
            .map_err(|_| StoreError::PayloadByteAccountingOverflow)?;
        let dot = publication.header.stamp.dot;
        let replay_key = super::accepted_dot_key(dot).to_vec();
        let replay_value = ReplayFence::new(
            dot.publisher,
            dot.counter,
            publication.semantic_id,
            transfer,
            source_len,
            Sha256::digest(exact.value()).into(),
        )
        .encode()
        .to_vec();
        expected.usage.replay_bytes = expected
            .usage
            .replay_bytes
            .checked_add(entry_bytes(&replay_key, &replay_value)?)
            .ok_or(StoreError::PayloadByteAccountingOverflow)?;
        insert_unique(
            &mut expected.replays,
            replay_key,
            replay_value,
            "multiple Blob publications claim one replay-fence publisher dot",
        )?;
        insert_unique(
            &mut expected.references,
            variant_reference_key(
                publication.variant_id,
                VariantReferenceOwner::Publication,
                transfer,
            ),
            Vec::new(),
            "multiple Blob publications claim one variant reference",
        )?;
        let mut wrapped = match schema {
            LifecycleSchemaState::Legacy => wrap_publication(encoded)?,
            LifecycleSchemaState::V1 => wrap_v1_publication(encoded)?,
            LifecycleSchemaState::V2 | LifecycleSchemaState::V3 => upgrade_v3_publication(encoded)?,
            LifecycleSchemaState::V4 | LifecycleSchemaState::Current => encoded.to_vec(),
        };
        if project_lifetimes_for_v5 {
            let payload = super::encode_blob_metadata(publication)?;
            wrapped = replace_live_publication_payload(&wrapped, &payload)?;
        }
        insert_unique(
            &mut expected.publications,
            key.value().to_vec(),
            wrapped,
            "multiple Blob publication rows claim one transfer identity",
        )?;
    }
    expected.usage.replay_rows = u64::try_from(expected.replays.len())
        .map_err(|_| StoreError::ItemCountAccountingOverflow)?;
    expected.usage.publication_rows = u64::try_from(expected.publications.len())
        .map_err(|_| StoreError::ItemCountAccountingOverflow)?;

    let mut saw_pending_without_order = false;
    let mut saw_pending_with_order = false;
    let mut next_pending_order = 1u64;
    for (key, value) in pending_sources {
        let transfer = super::parse_blob_transfer_id("pending Blob source table", &key)?;
        let mut pending = super::decode_pending_blob_source_for_encoding(
            &value,
            if matches!(
                schema,
                LifecycleSchemaState::V4 | LifecycleSchemaState::Current
            ) {
                super::PendingBlobEncodingGeneration::Current
            } else {
                super::PendingBlobEncodingGeneration::Predecessor
            },
        )?;
        if pending.pending_acceptance_order == 0 {
            saw_pending_without_order = true;
            pending.pending_acceptance_order = next_pending_order;
            next_pending_order = next_pending_order.checked_add(1).ok_or_else(|| {
                StoreError::Blob(BlobStoreError::SchemaInvariant(
                    "pending Blob acceptance order overflows during migration",
                ))
            })?;
        } else {
            saw_pending_with_order = true;
        }
        if saw_pending_without_order && saw_pending_with_order {
            return Err(StoreError::Blob(BlobStoreError::SchemaInvariant(
                "pending Blob sources mix ordered and unordered predecessor generations",
            )));
        }
        if pending.metadata.transfer_id != transfer
            || import_lineages.get(&pending.metadata.variant_id) != Some(&pending.physical_lineage)
        {
            return Err(StoreError::Blob(BlobStoreError::SchemaInvariant(
                "pending Blob source conflicts with its physical lineage",
            )));
        }
        if project_lifetimes_for_v5 {
            pending.metadata.lifetime =
                project_lifetime_for_v5(pending.metadata.lifetime, continuity)?;
            pending.authenticated_source_binding =
                super::pending_blob_authenticated_source_binding(
                    &pending.metadata,
                    &pending.sealed,
                )?;
        }
        if let Some(deadline) = stored_ttl_deadline(
            transfer,
            TtlDeadlineKind::PendingSource,
            pending.metadata.lifetime,
        )? {
            insert_unique(
                &mut expected.ttl_deadlines,
                ttl_deadline_key(deadline)?.to_vec(),
                Vec::new(),
                "multiple pending Blob sources claim one TTL deadline",
            )?;
        }
        insert_unique(
            &mut expected.references,
            variant_reference_key(
                pending.metadata.variant_id,
                VariantReferenceOwner::PendingSource,
                transfer,
            ),
            Vec::new(),
            "multiple pending Blob sources claim one variant reference",
        )?;
        let upgraded = if !project_lifetimes_for_v5
            && matches!(
                schema,
                LifecycleSchemaState::V4 | LifecycleSchemaState::Current
            ) {
            value
        } else {
            super::encode_pending_blob_source(&pending)?
        };
        insert_unique(
            &mut expected.pending_sources,
            key,
            upgraded,
            "multiple pending Blob source rows claim one transfer identity",
        )?;
    }
    expected.usage.reference_rows = u64::try_from(expected.references.len())
        .map_err(|_| StoreError::ItemCountAccountingOverflow)?;

    for row in operations.iter()? {
        let (key, value) = row?;
        let encoded = value.value();
        super::validate_blob_operation_storage_key(key.value())?;
        if matches!(
            schema,
            LifecycleSchemaState::V2
                | LifecycleSchemaState::V3
                | LifecycleSchemaState::V4
                | LifecycleSchemaState::Current
        ) && encoded.get(1).copied() == Some(OPERATION_STATE_RETIRED_TAG)
        {
            if encoded.first().copied() != Some(CURRENT_OPERATION_RECORD_VERSION) {
                return Err(StoreError::Blob(BlobStoreError::SchemaInvariant(
                    "current Blob operation is missing its lifecycle wrapper",
                )));
            }
            let OperationState::Retired {
                generation,
                operation_key_digest,
                age,
                ..
            } = OperationState::decode(&encoded[1..]).map_err(StoreError::Blob)?
            else {
                unreachable!("retired operation tag decoded as active");
            };
            if operation_key_digest != Sha256::digest(key.value()).as_slice() {
                return Err(StoreError::Blob(BlobStoreError::SchemaInvariant(
                    "retired Blob operation digest differs from its operation key",
                )));
            }
            reconstruct_retirement_authority(
                &mut expected,
                schema,
                generation,
                age,
                RetentionDeadlineOwner::Operation(operation_key_digest),
                Some(key.value()),
            )?;
            expected.usage.retired_operation_rows = expected
                .usage
                .retired_operation_rows
                .checked_add(1)
                .ok_or(StoreError::ItemCountAccountingOverflow)?;
            expected.operation_bytes = expected
                .operation_bytes
                .checked_add(entry_bytes(key.value(), encoded)?)
                .ok_or(StoreError::PayloadByteAccountingOverflow)?;
            insert_unique(
                &mut expected.operations,
                key.value().to_vec(),
                encoded.to_vec(),
                "multiple Blob operation rows claim one operation key",
            )?;
            continue;
        }
        let operation = super::decode_blob_operation_record(encoded)?;
        if !expected
            .live_publications
            .contains(operation.transfer_id.as_bytes().as_slice())
        {
            return Err(StoreError::Blob(BlobStoreError::SchemaInvariant(
                "active Blob lifecycle operation points to a missing or retired publication",
            )));
        }
        if publication_intents
            .get(&operation.transfer_id)
            .is_some_and(|digest| digest != &operation.intent_digest)
        {
            return Err(StoreError::Blob(BlobStoreError::SchemaInvariant(
                "Blob operation intent digest contradicts its publication lifetime",
            )));
        }
        match schema {
            LifecycleSchemaState::Legacy | LifecycleSchemaState::V1
                if encoded.first().copied() != Some(super::BLOB_OPERATION_VERSION) =>
            {
                return Err(StoreError::Blob(BlobStoreError::SchemaInvariant(
                    "Blob predecessor operation is not canonical",
                )));
            }
            LifecycleSchemaState::V2
            | LifecycleSchemaState::V3
            | LifecycleSchemaState::V4
            | LifecycleSchemaState::Current
                if encoded.first().copied() != Some(CURRENT_OPERATION_RECORD_VERSION) =>
            {
                return Err(StoreError::Blob(BlobStoreError::SchemaInvariant(
                    "current Blob operation is missing its lifecycle wrapper",
                )));
            }
            _ => {}
        }
        let wrapped = match schema {
            LifecycleSchemaState::Legacy | LifecycleSchemaState::V1 => wrap_operation(encoded)?,
            LifecycleSchemaState::V2
            | LifecycleSchemaState::V3
            | LifecycleSchemaState::V4
            | LifecycleSchemaState::Current => encoded.to_vec(),
        };
        expected.operation_bytes = expected
            .operation_bytes
            .checked_add(entry_bytes(key.value(), &wrapped)?)
            .ok_or(StoreError::PayloadByteAccountingOverflow)?;
        insert_unique(
            &mut expected.operations,
            key.value().to_vec(),
            wrapped,
            "multiple Blob operation rows claim one operation key",
        )?;
        insert_unique(
            &mut expected.operation_owners,
            inverse_owner_key(operation.transfer_id, key.value()),
            key.value().to_vec(),
            "multiple Blob operations claim one inverse owner key",
        )?;
    }
    expected.usage.operation_owner_rows = u64::try_from(expected.operation_owners.len())
        .map_err(|_| StoreError::ItemCountAccountingOverflow)?;
    expected.usage.delivery_owner_rows = u64::try_from(expected.delivery_owners.len())
        .map_err(|_| StoreError::ItemCountAccountingOverflow)?;
    expected.usage.deadline_rows = u64::try_from(expected.deadlines.len())
        .map_err(|_| StoreError::ItemCountAccountingOverflow)?;
    expected.usage.ttl_deadline_rows = u64::try_from(expected.ttl_deadlines.len())
        .map_err(|_| StoreError::ItemCountAccountingOverflow)?;
    expected.usage.retirement_resolver_rows = u64::try_from(expected.retirement_resolvers.len())
        .map_err(|_| StoreError::ItemCountAccountingOverflow)?;
    Ok(expected)
}

fn audit_metadata(
    metadata: &impl ReadableTable<&'static str, u64>,
    mut usage: BlobLifecycleUsage,
    schema_version: u64,
) -> Result<BlobLifecycleUsage, StoreError> {
    let expected_fields = if schema_version != BLOB_LIFECYCLE_SCHEMA_VERSION {
        BLOB_LIFECYCLE_V4_METADATA_FIELDS.len()
    } else {
        BLOB_LIFECYCLE_METADATA_FIELDS.len()
    };
    if metadata.len()? != expected_fields as u64 {
        return Err(StoreError::Blob(BlobStoreError::SchemaInvariant(
            "Blob lifecycle accounting metadata is incomplete",
        )));
    }
    for (field, expected) in [
        (BLOB_LIFECYCLE_SCHEMA_VERSION_FIELD, schema_version),
        (BLOB_LINEAGE_ROWS, usage.lineage_rows),
        (BLOB_LINEAGE_BYTES, usage.lineage_bytes),
        (BLOB_REPLAY_ROWS, usage.replay_rows),
        (BLOB_REPLAY_BYTES, usage.replay_bytes),
        (BLOB_PUBLICATION_ROWS, usage.publication_rows),
        (BLOB_REFERENCE_ROWS, usage.reference_rows),
        (BLOB_OPERATION_OWNER_ROWS, usage.operation_owner_rows),
        (BLOB_DELIVERY_OWNER_ROWS, usage.delivery_owner_rows),
        (BLOB_DEADLINE_ROWS, usage.deadline_rows),
        (
            BLOB_RETIREMENT_RESOLVER_ROWS,
            usage.retirement_resolver_rows,
        ),
        (
            BLOB_RETIRED_PUBLICATION_ROWS,
            usage.retired_publication_rows,
        ),
        (BLOB_RETIRED_OPERATION_ROWS, usage.retired_operation_rows),
    ] {
        if metadata.get(field)?.map(|value| value.value()) != Some(expected) {
            return Err(StoreError::Blob(BlobStoreError::SchemaInvariant(
                "Blob lifecycle accounting metadata disagrees with exact rows",
            )));
        }
    }
    if schema_version == BLOB_LIFECYCLE_SCHEMA_VERSION
        && metadata
            .get(BLOB_TTL_DEADLINE_ROWS)?
            .map(|value| value.value())
            != Some(usage.ttl_deadline_rows)
    {
        return Err(StoreError::Blob(BlobStoreError::SchemaInvariant(
            "Blob lifecycle TTL deadline accounting disagrees with exact rows",
        )));
    }
    let allocated_generation = metadata
        .get(BLOB_NEXT_RETIREMENT_GENERATION)?
        .map(|value| value.value())
        .ok_or(StoreError::Blob(BlobStoreError::SchemaInvariant(
            "Blob lifecycle retirement generation high-water is missing",
        )))?;
    if allocated_generation < usage.next_retirement_generation {
        return Err(StoreError::Blob(BlobStoreError::SchemaInvariant(
            "Blob lifecycle retirement generation high-water is below a durable retirement",
        )));
    }
    usage.next_retirement_generation = allocated_generation;
    Ok(usage)
}

fn audit_v2_metadata(
    metadata: &impl ReadableTable<&'static str, u64>,
    mut usage: BlobLifecycleUsage,
) -> Result<BlobLifecycleUsage, StoreError> {
    if metadata.len()? != 13 {
        return Err(StoreError::Blob(BlobStoreError::SchemaInvariant(
            "Blob lifecycle-v2 accounting metadata is incomplete",
        )));
    }
    for (field, expected) in [
        (BLOB_LIFECYCLE_SCHEMA_VERSION_FIELD, 2),
        (BLOB_LINEAGE_ROWS, usage.lineage_rows),
        (BLOB_LINEAGE_BYTES, usage.lineage_bytes),
        (BLOB_REPLAY_ROWS, usage.replay_rows),
        (BLOB_REPLAY_BYTES, usage.replay_bytes),
        (BLOB_PUBLICATION_ROWS, usage.publication_rows),
        (BLOB_REFERENCE_ROWS, usage.reference_rows),
        (BLOB_OPERATION_OWNER_ROWS, usage.operation_owner_rows),
        (BLOB_DELIVERY_OWNER_ROWS, usage.delivery_owner_rows),
        (BLOB_DEADLINE_ROWS, usage.deadline_rows),
        (
            BLOB_RETIRED_PUBLICATION_ROWS,
            usage.retired_publication_rows,
        ),
        (BLOB_RETIRED_OPERATION_ROWS, usage.retired_operation_rows),
    ] {
        if metadata.get(field)?.map(|value| value.value()) != Some(expected) {
            return Err(StoreError::Blob(BlobStoreError::SchemaInvariant(
                "Blob lifecycle-v2 accounting differs from exact rows",
            )));
        }
    }
    let allocated_generation = metadata
        .get(BLOB_NEXT_RETIREMENT_GENERATION)?
        .map(|value| value.value())
        .ok_or(StoreError::Blob(BlobStoreError::SchemaInvariant(
            "Blob lifecycle-v2 retirement generation high-water is missing",
        )))?;
    if allocated_generation < usage.next_retirement_generation {
        return Err(StoreError::Blob(BlobStoreError::SchemaInvariant(
            "Blob lifecycle-v2 retirement generation high-water is below a durable retirement",
        )));
    }
    usage.next_retirement_generation = allocated_generation;
    Ok(usage)
}

fn collect_retirement_resolvers(
    table: &impl ReadableTable<&'static [u8], &'static [u8]>,
) -> Result<BTreeMap<Vec<u8>, Vec<u8>>, StoreError> {
    let mut rows = BTreeMap::new();
    for row in table.iter()? {
        let (key, value) = row?;
        let owner = decode_retirement_resolver_key(key.value())?;
        validate_retirement_resolver(owner, value.value())?;
        if rows
            .insert(key.value().to_vec(), value.value().to_vec())
            .is_some()
        {
            return Err(StoreError::Blob(BlobStoreError::SchemaInvariant(
                "multiple Blob retirement resolvers claim one owner",
            )));
        }
    }
    Ok(rows)
}

fn collect_inverse_owners(
    table: &impl ReadableTable<&'static [u8], &'static [u8]>,
) -> Result<BTreeMap<Vec<u8>, Vec<u8>>, StoreError> {
    let mut rows = BTreeMap::new();
    for row in table.iter()? {
        let (key, value) = row?;
        if key.value().len() != 64 || value.value().is_empty() {
            return Err(StoreError::Blob(BlobStoreError::SchemaInvariant(
                "Blob inverse owner row is not canonical",
            )));
        }
        if key.value()[32..] != Sha256::digest(value.value())[..] {
            return Err(StoreError::Blob(BlobStoreError::SchemaInvariant(
                "Blob inverse owner digest differs from its forward key",
            )));
        }
        rows.insert(key.value().to_vec(), value.value().to_vec());
    }
    Ok(rows)
}

fn merge_v1_retained_lineages(
    lineages: &impl ReadableTable<&'static [u8], &'static [u8]>,
    expected: &mut ExpectedLifecycleImage,
    owner_binding: [u8; 32],
) -> Result<(), StoreError> {
    let required = expected.lineages.clone();
    let mut retained = BTreeMap::new();
    let mut lineage_bytes = 0u64;
    for row in lineages.iter()? {
        let (key, value) = row?;
        if key.value().len() != 32 {
            return Err(StoreError::Blob(BlobStoreError::SchemaInvariant(
                "Blob lifecycle-v1 lineage fence has an invalid variant key",
            )));
        }
        let fence = LineageFence::decode(value.value()).map_err(StoreError::Blob)?;
        if fence.owner_binding != owner_binding {
            return Err(StoreError::Blob(BlobStoreError::SchemaInvariant(
                "Blob lifecycle-v1 lineage authority has the wrong owner binding",
            )));
        }
        if let Some(required_value) = required.get(key.value()) {
            if !fence
                .same_authority(LineageFence::decode(required_value).map_err(StoreError::Blob)?)
            {
                return Err(StoreError::Blob(BlobStoreError::SchemaInvariant(
                    "Blob lifecycle-v1 lineage authority differs",
                )));
            }
        } else if !fence.bulk_reclamation_observed() {
            return Err(StoreError::Blob(BlobStoreError::SchemaInvariant(
                "Blob lifecycle-v1 orphan lineage lacks finalized reclamation authority",
            )));
        }
        lineage_bytes = lineage_bytes
            .checked_add(entry_bytes(key.value(), value.value())?)
            .ok_or(StoreError::PayloadByteAccountingOverflow)?;
        retained.insert(key.value().to_vec(), value.value().to_vec());
    }
    if required.keys().any(|key| !retained.contains_key(key)) {
        return Err(StoreError::Blob(BlobStoreError::SchemaInvariant(
            "Blob lifecycle-v1 lineage fence is missing",
        )));
    }
    expected.usage.lineage_rows =
        u64::try_from(retained.len()).map_err(|_| StoreError::ItemCountAccountingOverflow)?;
    expected.usage.lineage_bytes = lineage_bytes;
    expected.lineages = retained;
    Ok(())
}

fn audit_v1_before_migration(
    write_metadata: &impl ReadableTable<&'static str, u64>,
    references: &impl ReadableTable<&'static [u8], &'static [u8]>,
    lineages: &impl ReadableTable<&'static [u8], &'static [u8]>,
    replays: &impl ReadableTable<&'static [u8], &'static [u8]>,
    cursors: &impl ReadableTable<u8, &'static [u8]>,
    expected: &ExpectedLifecycleImage,
    owner_binding: [u8; 32],
) -> Result<(), StoreError> {
    const V1_FIELDS: [&str; 7] = [
        BLOB_LIFECYCLE_SCHEMA_VERSION_FIELD,
        BLOB_LINEAGE_ROWS,
        BLOB_LINEAGE_BYTES,
        BLOB_REPLAY_ROWS,
        BLOB_REPLAY_BYTES,
        BLOB_PUBLICATION_ROWS,
        BLOB_REFERENCE_ROWS,
    ];
    if write_metadata.len()? != V1_FIELDS.len() as u64 {
        return Err(StoreError::Blob(BlobStoreError::SchemaInvariant(
            "Blob lifecycle-v1 accounting metadata is incomplete",
        )));
    }
    for (field, expected_value) in [
        (BLOB_LIFECYCLE_SCHEMA_VERSION_FIELD, 1),
        (BLOB_LINEAGE_ROWS, expected.usage.lineage_rows),
        (BLOB_LINEAGE_BYTES, expected.usage.lineage_bytes),
        (BLOB_REPLAY_ROWS, expected.usage.replay_rows),
        (BLOB_REPLAY_BYTES, expected.usage.replay_bytes),
        (BLOB_PUBLICATION_ROWS, expected.usage.publication_rows),
        (BLOB_REFERENCE_ROWS, expected.usage.reference_rows),
    ] {
        if write_metadata.get(field)?.map(|value| value.value()) != Some(expected_value) {
            return Err(StoreError::Blob(BlobStoreError::SchemaInvariant(
                "Blob lifecycle-v1 accounting differs from exact rows",
            )));
        }
    }
    validate_maintenance_cursors(cursors)?;
    let actual_references = references
        .iter()?
        .map(|row| {
            let (key, value) = row?;
            Ok((key.value().to_vec(), value.value().to_vec()))
        })
        .collect::<Result<BTreeMap<_, _>, redb::StorageError>>()?;
    let actual_replays = replays
        .iter()?
        .map(|row| {
            let (key, value) = row?;
            ReplayFence::decode(value.value()).map_err(StoreError::Blob)?;
            Ok((key.value().to_vec(), value.value().to_vec()))
        })
        .collect::<Result<BTreeMap<_, _>, StoreError>>()?;
    if actual_references != expected.references || actual_replays != expected.replays {
        return Err(StoreError::Blob(BlobStoreError::SchemaInvariant(
            "Blob lifecycle-v1 relations are incomplete or mismatched",
        )));
    }
    let mut actual_lineages = BTreeMap::new();
    for row in lineages.iter()? {
        let (key, value) = row?;
        let fence = LineageFence::decode(value.value()).map_err(StoreError::Blob)?;
        if fence.owner_binding != owner_binding
            || (!expected.lineages.contains_key(key.value()) && !fence.bulk_reclamation_observed())
        {
            return Err(StoreError::Blob(BlobStoreError::SchemaInvariant(
                "Blob lifecycle-v1 lineage authority is invalid",
            )));
        }
        actual_lineages.insert(key.value().to_vec(), value.value().to_vec());
    }
    for (key, expected_value) in &expected.lineages {
        let actual =
            actual_lineages
                .get(key)
                .ok_or(StoreError::Blob(BlobStoreError::SchemaInvariant(
                    "Blob lifecycle-v1 lineage fence is missing",
                )))?;
        if !LineageFence::decode(actual)
            .map_err(StoreError::Blob)?
            .same_authority(LineageFence::decode(expected_value).map_err(StoreError::Blob)?)
        {
            return Err(StoreError::Blob(BlobStoreError::SchemaInvariant(
                "Blob lifecycle-v1 lineage authority differs",
            )));
        }
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)] // Exact bidirectional audit spans every lifecycle table.
fn audit_current_rows(
    metadata: &impl ReadableTable<&'static str, u64>,
    references: &impl ReadableTable<&'static [u8], &'static [u8]>,
    lineages: &impl ReadableTable<&'static [u8], &'static [u8]>,
    replays: &impl ReadableTable<&'static [u8], &'static [u8]>,
    cursors: &impl ReadableTable<u8, &'static [u8]>,
    operation_owners: &impl ReadableTable<&'static [u8], &'static [u8]>,
    delivery_owners: &impl ReadableTable<&'static [u8], &'static [u8]>,
    deadlines: &impl ReadableTable<&'static [u8], &'static [u8]>,
    ttl_deadlines: Option<BTreeMap<Vec<u8>, Vec<u8>>>,
    retirement_resolvers: Option<BTreeMap<Vec<u8>, Vec<u8>>>,
    expected: &ExpectedLifecycleImage,
    owner_binding: [u8; 32],
    schema_version: u64,
) -> Result<BlobLifecycleUsage, StoreError> {
    validate_maintenance_cursors(cursors)?;

    let mut actual_lineages = BTreeMap::new();
    let mut actual_usage = expected.usage;
    actual_usage.lineage_bytes = 0;
    for row in lineages.iter()? {
        let (key, value) = row?;
        if key.value().len() != 32 {
            return Err(StoreError::Blob(BlobStoreError::SchemaInvariant(
                "Blob lineage fence has an invalid variant key",
            )));
        }
        let fence = LineageFence::decode(value.value()).map_err(StoreError::Blob)?;
        if fence.owner_binding != owner_binding {
            return Err(StoreError::Blob(BlobStoreError::SchemaInvariant(
                "Blob lineage fence has the wrong depot owner binding",
            )));
        }
        actual_usage.lineage_bytes = actual_usage
            .lineage_bytes
            .checked_add(entry_bytes(key.value(), value.value())?)
            .ok_or(StoreError::PayloadByteAccountingOverflow)?;
        if !expected.lineages.contains_key(key.value()) && !fence.bulk_reclamation_observed() {
            return Err(StoreError::Blob(BlobStoreError::SchemaInvariant(
                "orphan Blob lineage fence lacks finalized reclamation authority",
            )));
        }
        actual_lineages.insert(key.value().to_vec(), value.value().to_vec());
    }
    actual_usage.lineage_rows = u64::try_from(actual_lineages.len())
        .map_err(|_| StoreError::ItemCountAccountingOverflow)?;
    let mut actual_replays = BTreeMap::new();
    let mut retired_replays = BTreeMap::<Vec<u8>, u64>::new();
    actual_usage.replay_bytes = 0;
    for row in replays.iter()? {
        let (key, value) = row?;
        if key.value().len() != 40 {
            return Err(StoreError::Blob(BlobStoreError::SchemaInvariant(
                "Blob replay fence has an invalid publisher-dot key",
            )));
        }
        let fence = ReplayFence::decode(value.value()).map_err(StoreError::Blob)?;
        if key.value()[..32] != fence.publisher || key.value()[32..] != fence.counter.to_be_bytes()
        {
            return Err(StoreError::Blob(BlobStoreError::SchemaInvariant(
                "Blob replay fence key differs from its publisher dot",
            )));
        }
        actual_usage.replay_bytes = actual_usage
            .replay_bytes
            .checked_add(entry_bytes(key.value(), value.value())?)
            .ok_or(StoreError::PayloadByteAccountingOverflow)?;
        if expected
            .retired_publications
            .contains(fence.transfer_id.as_bytes().as_slice())
        {
            let count = retired_replays
                .entry(fence.transfer_id.as_bytes().to_vec())
                .or_default();
            *count = count
                .checked_add(1)
                .ok_or(StoreError::ItemCountAccountingOverflow)?;
        } else if expected
            .live_publications
            .contains(fence.transfer_id.as_bytes().as_slice())
            && expected.replays.get(key.value()).map(Vec::as_slice) != Some(value.value())
        {
            return Err(StoreError::Blob(BlobStoreError::SchemaInvariant(
                "live Blob publication has a noncanonical extra replay fence",
            )));
        }
        actual_replays.insert(key.value().to_vec(), value.value().to_vec());
    }
    actual_usage.replay_rows =
        u64::try_from(actual_replays.len()).map_err(|_| StoreError::ItemCountAccountingOverflow)?;
    let mut actual_references = BTreeMap::new();
    for row in references.iter()? {
        let (key, value) = row?;
        if key.value().len() != 65 || !value.value().is_empty() {
            return Err(StoreError::Blob(BlobStoreError::SchemaInvariant(
                "Blob variant reference is not canonical",
            )));
        }
        VariantReferenceOwner::decode(&key.value()[32..33]).map_err(StoreError::Blob)?;
        actual_references.insert(key.value().to_vec(), value.value().to_vec());
    }
    let actual_operation_owners = collect_inverse_owners(operation_owners)?;
    let actual_delivery_owners = collect_inverse_owners(delivery_owners)?;
    let mut actual_deadlines = BTreeMap::new();
    for row in deadlines.iter()? {
        let (key, value) = row?;
        if schema_version == 2 {
            decode_retention_deadline_key_v2(key.value())?;
        } else {
            decode_retention_deadline_key(key.value())?;
        }
        if !value.value().is_empty() {
            return Err(StoreError::Blob(BlobStoreError::SchemaInvariant(
                "Blob retention deadline value is not empty",
            )));
        }
        actual_deadlines.insert(key.value().to_vec(), value.value().to_vec());
    }
    actual_usage.operation_owner_rows = u64::try_from(actual_operation_owners.len())
        .map_err(|_| StoreError::ItemCountAccountingOverflow)?;
    actual_usage.delivery_owner_rows = u64::try_from(actual_delivery_owners.len())
        .map_err(|_| StoreError::ItemCountAccountingOverflow)?;
    actual_usage.deadline_rows = u64::try_from(actual_deadlines.len())
        .map_err(|_| StoreError::ItemCountAccountingOverflow)?;
    if let Some(ttl_deadlines) = ttl_deadlines.as_ref() {
        for (key, value) in ttl_deadlines {
            decode_ttl_deadline_key(key)?;
            if !value.is_empty() {
                return Err(StoreError::Blob(BlobStoreError::SchemaInvariant(
                    "Blob TTL deadline value is not empty",
                )));
            }
        }
        actual_usage.ttl_deadline_rows = u64::try_from(ttl_deadlines.len())
            .map_err(|_| StoreError::ItemCountAccountingOverflow)?;
    }
    if let Some(resolvers) = retirement_resolvers.as_ref() {
        actual_usage.retirement_resolver_rows =
            u64::try_from(resolvers.len()).map_err(|_| StoreError::ItemCountAccountingOverflow)?;
    }
    if expected
        .retired_publications
        .iter()
        .any(|transfer| retired_replays.get(transfer) != Some(&1))
        || retired_replays.len() != expected.retired_publications.len()
        || expected
            .replays
            .iter()
            .any(|(key, value)| actual_replays.get(key) != Some(value))
        || actual_references != expected.references
        || actual_operation_owners != expected.operation_owners
        || actual_delivery_owners != expected.delivery_owners
        || actual_deadlines != expected.deadlines
        || ttl_deadlines
            .as_ref()
            .is_some_and(|actual| actual != &expected.ttl_deadlines)
        || retirement_resolvers
            .as_ref()
            .is_some_and(|actual| actual != &expected.retirement_resolvers)
    {
        return Err(StoreError::Blob(BlobStoreError::SchemaInvariant(
            "Blob lifecycle authority relations are incomplete or mismatched",
        )));
    }
    for (key, value) in &expected.lineages {
        let Some(actual) = actual_lineages.get(key) else {
            return Err(StoreError::Blob(BlobStoreError::SchemaInvariant(
                "Blob lifecycle authority relations are incomplete or mismatched",
            )));
        };
        let actual = LineageFence::decode(actual).map_err(StoreError::Blob)?;
        let expected = LineageFence::decode(value).map_err(StoreError::Blob)?;
        if !actual.same_authority(expected) {
            return Err(StoreError::Blob(BlobStoreError::SchemaInvariant(
                "Blob lifecycle authority relations are incomplete or mismatched",
            )));
        }
    }
    match schema_version {
        2 => audit_v2_metadata(metadata, actual_usage),
        3 => audit_metadata(metadata, actual_usage, 3),
        PREVIOUS_BLOB_LIFECYCLE_SCHEMA_VERSION => audit_metadata(
            metadata,
            actual_usage,
            PREVIOUS_BLOB_LIFECYCLE_SCHEMA_VERSION,
        ),
        BLOB_LIFECYCLE_SCHEMA_VERSION => {
            audit_metadata(metadata, actual_usage, BLOB_LIFECYCLE_SCHEMA_VERSION)
        }
        _ => Err(StoreError::Blob(BlobStoreError::SchemaInvariant(
            "Blob lifecycle schema version is unknown",
        ))),
    }
}

fn table_map(
    table: &impl ReadableTable<&'static [u8], &'static [u8]>,
) -> Result<BTreeMap<Vec<u8>, Vec<u8>>, StoreError> {
    table
        .iter()?
        .map(|row| {
            let (key, value) = row?;
            Ok((key.value().to_vec(), value.value().to_vec()))
        })
        .collect::<Result<_, redb::StorageError>>()
        .map_err(StoreError::from)
}

fn preflight_migration_limits(
    usage: BlobLifecycleUsage,
    limits: BlobLifecycleLimits,
) -> Result<(), StoreError> {
    if usage.lineage_rows > limits.max_lineage_rows()
        || usage.lineage_bytes > limits.max_lineage_bytes()
    {
        return Err(StoreError::Blob(BlobStoreError::LineageFenceCapacity {
            required_rows: usage.lineage_rows,
            required_bytes: usage.lineage_bytes,
            max_rows: limits.max_lineage_rows(),
            max_bytes: limits.max_lineage_bytes(),
        }));
    }
    if usage.replay_rows > limits.max_replay_rows()
        || usage.replay_bytes > limits.max_replay_bytes()
    {
        return Err(StoreError::Blob(BlobStoreError::ReplayFenceCapacity {
            required_rows: usage.replay_rows,
            required_bytes: usage.replay_bytes,
            max_rows: limits.max_replay_rows(),
            max_bytes: limits.max_replay_bytes(),
        }));
    }
    if usage.publication_rows > limits.max_publication_rows() {
        return Err(StoreError::Blob(
            BlobStoreError::PublicationLifecycleCapacity {
                required_rows: usage.publication_rows,
                max_rows: limits.max_publication_rows(),
            },
        ));
    }
    Ok(())
}

fn finalize_v5_migration_image(
    mut image: ExpectedLifecycleImage,
    continuity: Option<custody::LowerBoundContinuity>,
) -> Result<ExpectedLifecycleImage, StoreError> {
    image.ttl_deadlines.clear();
    for (key, encoded) in &mut image.publications {
        if publication_record_is_retired(encoded).map_err(StoreError::Blob)? {
            continue;
        }
        let transfer = super::parse_blob_transfer_id("Blob publication table", key)?;
        let mut metadata = super::decode_blob_metadata(encoded)?;
        metadata.lifetime = project_lifetime_for_v5(metadata.lifetime, continuity)?;
        if let Some(deadline) = stored_ttl_deadline(
            transfer,
            TtlDeadlineKind::LivePublication,
            metadata.lifetime,
        )? {
            insert_unique(
                &mut image.ttl_deadlines,
                ttl_deadline_key(deadline)?.to_vec(),
                Vec::new(),
                "multiple live Blob publications claim one TTL deadline",
            )?;
        }
        let payload = super::encode_blob_metadata(metadata)?;
        *encoded = replace_live_publication_payload(encoded, &payload)?;
    }
    for (key, encoded) in &mut image.pending_sources {
        let transfer = super::parse_blob_transfer_id("Blob pending source table", key)?;
        let mut pending = super::decode_pending_blob_source(encoded)?;
        pending.metadata.lifetime = project_lifetime_for_v5(pending.metadata.lifetime, continuity)?;
        if let Some(deadline) = stored_ttl_deadline(
            transfer,
            TtlDeadlineKind::PendingSource,
            pending.metadata.lifetime,
        )? {
            insert_unique(
                &mut image.ttl_deadlines,
                ttl_deadline_key(deadline)?.to_vec(),
                Vec::new(),
                "multiple pending Blob sources claim one TTL deadline",
            )?;
        }
        *encoded = super::encode_pending_blob_source(&pending)?;
    }
    image.usage.ttl_deadline_rows = u64::try_from(image.ttl_deadlines.len())
        .map_err(|_| StoreError::ItemCountAccountingOverflow)?;
    Ok(image)
}

/// Reconstructs and preflights a complete predecessor image, or strictly
/// audits an already-current lifecycle schema without repairing it.
pub(crate) fn stage_blob_lifecycle_migration_write(
    write: &redb::WriteTransaction,
    limits: BlobLifecycleLimits,
    owner_binding: [u8; 32],
    stats: &mut BlobStoreStats,
) -> Result<Option<BlobLifecycleMigration>, StoreError> {
    let mut schema = lifecycle_schema_state_write(write)?;
    if matches!(
        schema,
        LifecycleSchemaState::V4 | LifecycleSchemaState::Current
    ) {
        let version = write
            .open_table(BLOB_LIFECYCLE_METADATA)?
            .get(BLOB_LIFECYCLE_SCHEMA_VERSION_FIELD)?
            .map(|value| value.value())
            .ok_or(StoreError::Blob(BlobStoreError::SchemaInvariant(
                "Blob lifecycle metadata lacks its schema version",
            )))?;
        schema = resolve_lifecycle_schema_version(schema, version)?;
    }
    #[cfg(test)]
    if schema == LifecycleSchemaState::Legacy && TEST_BLOB_LIFECYCLE_MIGRATION_DISABLED.get() {
        return Ok(None);
    }
    let delivery_owners = crate::blob_subscription::lifecycle_delivery_owners_write(write)?;
    let publications = write.open_table(super::BLOB_PUBLICATIONS)?;
    let source_bytes = write.open_table(super::BLOB_BYTES)?;
    let operations = write.open_table(super::BLOB_OPERATIONS)?;
    let pending = write.open_table(super::BLOB_PENDING_SOURCES)?;
    let pending_rows = pending
        .iter()?
        .map(|row| {
            let (key, value) = row?;
            Ok((key.value().to_vec(), value.value().to_vec()))
        })
        .collect::<Result<Vec<_>, redb::StorageError>>()?;
    let continuity = custody::lower_bound_continuity_write(write)?;
    let mut expected = reconstruct_expected_image(
        &publications,
        &source_bytes,
        &operations,
        pending_rows,
        delivery_owners,
        depot::audited_lifecycle_imports_write(write)?,
        owner_binding,
        schema,
        continuity,
        false,
    )?;
    if schema == LifecycleSchemaState::V1 {
        merge_v1_retained_lineages(
            &write.open_table(BLOB_LINEAGE_FENCES)?,
            &mut expected,
            owner_binding,
        )?;
        audit_v1_before_migration(
            &write.open_table(BLOB_LIFECYCLE_METADATA)?,
            &write.open_table(BLOB_VARIANT_REFERENCES)?,
            &write.open_table(BLOB_LINEAGE_FENCES)?,
            &write.open_table(BLOB_REPLAY_FENCES)?,
            &write.open_table(BLOB_MAINTENANCE_CURSORS)?,
            &expected,
            owner_binding,
        )?;
    }
    match schema {
        LifecycleSchemaState::Legacy | LifecycleSchemaState::V1 => {
            preflight_migration_limits(expected.usage, limits)?;
            let operation_rows = u64::try_from(expected.operations.len())
                .map_err(|_| StoreError::ItemCountAccountingOverflow)?;
            if operation_rows > super::MAX_BLOB_OPERATIONS
                || expected.operation_bytes > super::MAX_BLOB_OWNED_OPERATION_BYTES
            {
                return Err(StoreError::Blob(BlobStoreError::SchemaInvariant(
                    "wrapped Blob operation usage exceeds its durable safety caps",
                )));
            }
            expected.usage.apply_to_stats(stats);
            let image = finalize_v5_migration_image(expected, continuity)?;
            Ok(Some(BlobLifecycleMigration { image }))
        }
        LifecycleSchemaState::V2 => {
            let upgraded_publications = std::mem::take(&mut expected.publications);
            expected.publications = publications
                .iter()?
                .map(|row| {
                    let (key, value) = row?;
                    Ok((key.value().to_vec(), value.value().to_vec()))
                })
                .collect::<Result<BTreeMap<_, _>, redb::StorageError>>()?;
            let actual_usage = audit_current_rows(
                &write.open_table(BLOB_LIFECYCLE_METADATA)?,
                &write.open_table(BLOB_VARIANT_REFERENCES)?,
                &write.open_table(BLOB_LINEAGE_FENCES)?,
                &write.open_table(BLOB_REPLAY_FENCES)?,
                &write.open_table(BLOB_MAINTENANCE_CURSORS)?,
                &write.open_table(BLOB_OPERATION_OWNERS)?,
                &write.open_table(BLOB_DELIVERY_OWNERS)?,
                &write.open_table(BLOB_RETENTION_DEADLINES)?,
                None,
                None,
                &expected,
                owner_binding,
                2,
            )?;
            preflight_migration_limits(actual_usage, limits)?;
            expected.publications = upgraded_publications;
            expected.deadlines = expected
                .deadlines
                .keys()
                .map(|key| {
                    let (deadline, owner) = decode_retention_deadline_key_v2(key)?;
                    Ok((retention_deadline_key(deadline, owner).to_vec(), Vec::new()))
                })
                .collect::<Result<BTreeMap<_, _>, StoreError>>()?;
            // The exact v2 audit includes permanent replay and finalized
            // lineage fences that are intentionally retained after their
            // publication is retired.  Carry that audited accounting into
            // v3 instead of replacing it with only the rows reconstructible
            // from the retired wrapper.
            expected.usage = actual_usage;
            expected.usage.retirement_resolver_rows =
                u64::try_from(expected.retirement_resolvers.len())
                    .map_err(|_| StoreError::ItemCountAccountingOverflow)?;
            expected.usage.apply_to_stats(stats);
            let image = finalize_v5_migration_image(expected, continuity)?;
            Ok(Some(BlobLifecycleMigration { image }))
        }
        LifecycleSchemaState::V3 => {
            let upgraded_publications = std::mem::take(&mut expected.publications);
            expected.publications = publications
                .iter()?
                .map(|row| {
                    let (key, value) = row?;
                    Ok((key.value().to_vec(), value.value().to_vec()))
                })
                .collect::<Result<BTreeMap<_, _>, redb::StorageError>>()?;
            let actual_usage = audit_current_rows(
                &write.open_table(BLOB_LIFECYCLE_METADATA)?,
                &write.open_table(BLOB_VARIANT_REFERENCES)?,
                &write.open_table(BLOB_LINEAGE_FENCES)?,
                &write.open_table(BLOB_REPLAY_FENCES)?,
                &write.open_table(BLOB_MAINTENANCE_CURSORS)?,
                &write.open_table(BLOB_OPERATION_OWNERS)?,
                &write.open_table(BLOB_DELIVERY_OWNERS)?,
                &write.open_table(BLOB_RETENTION_DEADLINES)?,
                None,
                Some(collect_retirement_resolvers(
                    &write.open_table(BLOB_RETIREMENT_RESOLVERS)?,
                )?),
                &expected,
                owner_binding,
                3,
            )?;
            preflight_migration_limits(actual_usage, limits)?;
            expected.publications = upgraded_publications;
            expected.usage = actual_usage;
            expected.usage.apply_to_stats(stats);
            let image = finalize_v5_migration_image(expected, continuity)?;
            Ok(Some(BlobLifecycleMigration { image }))
        }
        LifecycleSchemaState::V4 => {
            if u64::try_from(expected.publications.len())
                .map_err(|_| StoreError::ItemCountAccountingOverflow)?
                != publications.len()?
                || u64::try_from(expected.operations.len())
                    .map_err(|_| StoreError::ItemCountAccountingOverflow)?
                    != operations.len()?
            {
                return Err(StoreError::Blob(BlobStoreError::SchemaInvariant(
                    "Blob lifecycle wrappers are not bidirectionally complete",
                )));
            }
            let actual_usage = audit_current_rows(
                &write.open_table(BLOB_LIFECYCLE_METADATA)?,
                &write.open_table(BLOB_VARIANT_REFERENCES)?,
                &write.open_table(BLOB_LINEAGE_FENCES)?,
                &write.open_table(BLOB_REPLAY_FENCES)?,
                &write.open_table(BLOB_MAINTENANCE_CURSORS)?,
                &write.open_table(BLOB_OPERATION_OWNERS)?,
                &write.open_table(BLOB_DELIVERY_OWNERS)?,
                &write.open_table(BLOB_RETENTION_DEADLINES)?,
                None,
                Some(collect_retirement_resolvers(
                    &write.open_table(BLOB_RETIREMENT_RESOLVERS)?,
                )?),
                &expected,
                owner_binding,
                PREVIOUS_BLOB_LIFECYCLE_SCHEMA_VERSION,
            )?;
            preflight_migration_limits(actual_usage, limits)?;
            actual_usage.apply_to_stats(stats);
            let image = finalize_v5_migration_image(expected, continuity)?;
            Ok(Some(BlobLifecycleMigration { image }))
        }
        LifecycleSchemaState::Current => {
            if u64::try_from(expected.publications.len())
                .map_err(|_| StoreError::ItemCountAccountingOverflow)?
                != publications.len()?
                || u64::try_from(expected.operations.len())
                    .map_err(|_| StoreError::ItemCountAccountingOverflow)?
                    != operations.len()?
            {
                return Err(StoreError::Blob(BlobStoreError::SchemaInvariant(
                    "Blob lifecycle wrappers are not bidirectionally complete",
                )));
            }
            load_ttl_expiry_state_write(write)?;
            let actual_usage = audit_current_rows(
                &write.open_table(BLOB_LIFECYCLE_METADATA)?,
                &write.open_table(BLOB_VARIANT_REFERENCES)?,
                &write.open_table(BLOB_LINEAGE_FENCES)?,
                &write.open_table(BLOB_REPLAY_FENCES)?,
                &write.open_table(BLOB_MAINTENANCE_CURSORS)?,
                &write.open_table(BLOB_OPERATION_OWNERS)?,
                &write.open_table(BLOB_DELIVERY_OWNERS)?,
                &write.open_table(BLOB_RETENTION_DEADLINES)?,
                Some(table_map(&write.open_table(BLOB_TTL_DEADLINES)?)?),
                Some(collect_retirement_resolvers(
                    &write.open_table(BLOB_RETIREMENT_RESOLVERS)?,
                )?),
                &expected,
                owner_binding,
                BLOB_LIFECYCLE_SCHEMA_VERSION,
            )?;
            preflight_migration_limits(actual_usage, limits)?;
            actual_usage.apply_to_stats(stats);
            Ok(None)
        }
    }
}

/// Strict read-only predecessor/current audit. A complete predecessor is
/// reconstructed in memory only; current authority must match bidirectionally.
pub(crate) fn inspect_blob_lifecycle_read(
    read: &redb::ReadTransaction,
) -> Result<BlobLifecycleUsage, StoreError> {
    let normal = read
        .list_tables()?
        .map(|table| table.name().to_owned())
        .collect::<BTreeSet<_>>();
    let mut schema = lifecycle_schema_state_read(read)?;
    if matches!(
        schema,
        LifecycleSchemaState::V4 | LifecycleSchemaState::Current
    ) {
        let version = read
            .open_table(BLOB_LIFECYCLE_METADATA)?
            .get(BLOB_LIFECYCLE_SCHEMA_VERSION_FIELD)?
            .map(|value| value.value())
            .ok_or(StoreError::Blob(BlobStoreError::SchemaInvariant(
                "Blob lifecycle metadata lacks its schema version",
            )))?;
        schema = resolve_lifecycle_schema_version(schema, version)?;
    }
    let pending_rows = if normal.contains(super::BLOB_PENDING_SOURCES.name()) {
        read.open_table(super::BLOB_PENDING_SOURCES)?
            .iter()?
            .map(|row| {
                let (key, value) = row?;
                Ok((key.value().to_vec(), value.value().to_vec()))
            })
            .collect::<Result<Vec<_>, redb::StorageError>>()?
    } else {
        Vec::new()
    };
    let owner_binding = depot::depot_owner_binding_read(read)?;
    let mut expected = reconstruct_expected_image(
        &read.open_table(super::BLOB_PUBLICATIONS)?,
        &read.open_table(super::BLOB_BYTES)?,
        &read.open_table(super::BLOB_OPERATIONS)?,
        pending_rows,
        crate::blob_subscription::lifecycle_delivery_owners_read(read)?,
        depot::audited_lifecycle_imports_read(read)?,
        owner_binding,
        schema,
        custody::lower_bound_continuity_read(read)?,
        false,
    )?;
    if schema == LifecycleSchemaState::V1 {
        merge_v1_retained_lineages(
            &read.open_table(BLOB_LINEAGE_FENCES)?,
            &mut expected,
            owner_binding,
        )?;
        audit_v1_before_migration(
            &read.open_table(BLOB_LIFECYCLE_METADATA)?,
            &read.open_table(BLOB_VARIANT_REFERENCES)?,
            &read.open_table(BLOB_LINEAGE_FENCES)?,
            &read.open_table(BLOB_REPLAY_FENCES)?,
            &read.open_table(BLOB_MAINTENANCE_CURSORS)?,
            &expected,
            owner_binding,
        )?;
    }
    if matches!(
        schema,
        LifecycleSchemaState::V2
            | LifecycleSchemaState::V3
            | LifecycleSchemaState::V4
            | LifecycleSchemaState::Current
    ) {
        if schema == LifecycleSchemaState::Current {
            load_ttl_expiry_state(&read.open_table(BLOB_TTL_EXPIRY_CURSORS)?)?;
        }
        if matches!(schema, LifecycleSchemaState::V2 | LifecycleSchemaState::V3) {
            expected.publications = read
                .open_table(super::BLOB_PUBLICATIONS)?
                .iter()?
                .map(|row| {
                    let (key, value) = row?;
                    Ok((key.value().to_vec(), value.value().to_vec()))
                })
                .collect::<Result<BTreeMap<_, _>, redb::StorageError>>()?;
        }
        return audit_current_rows(
            &read.open_table(BLOB_LIFECYCLE_METADATA)?,
            &read.open_table(BLOB_VARIANT_REFERENCES)?,
            &read.open_table(BLOB_LINEAGE_FENCES)?,
            &read.open_table(BLOB_REPLAY_FENCES)?,
            &read.open_table(BLOB_MAINTENANCE_CURSORS)?,
            &read.open_table(BLOB_OPERATION_OWNERS)?,
            &read.open_table(BLOB_DELIVERY_OWNERS)?,
            &read.open_table(BLOB_RETENTION_DEADLINES)?,
            if schema == LifecycleSchemaState::Current {
                Some(table_map(&read.open_table(BLOB_TTL_DEADLINES)?)?)
            } else {
                None
            },
            if matches!(
                schema,
                LifecycleSchemaState::V3 | LifecycleSchemaState::V4 | LifecycleSchemaState::Current
            ) {
                Some(collect_retirement_resolvers(
                    &read.open_table(BLOB_RETIREMENT_RESOLVERS)?,
                )?)
            } else {
                None
            },
            &expected,
            owner_binding,
            if schema == LifecycleSchemaState::Current {
                BLOB_LIFECYCLE_SCHEMA_VERSION
            } else if schema == LifecycleSchemaState::V4 {
                PREVIOUS_BLOB_LIFECYCLE_SCHEMA_VERSION
            } else if schema == LifecycleSchemaState::V3 {
                3
            } else {
                2
            },
        );
    }
    Ok(expected.usage)
}

impl BlobLifecycleMigration {
    pub(crate) fn apply(&self, write: &redb::WriteTransaction) -> Result<(), StoreError> {
        let mut metadata = write.open_table(BLOB_LIFECYCLE_METADATA)?;
        for (field, value) in [
            (
                BLOB_LIFECYCLE_SCHEMA_VERSION_FIELD,
                ACTIVE_BLOB_LIFECYCLE_SCHEMA_VERSION,
            ),
            (BLOB_LINEAGE_ROWS, self.image.usage.lineage_rows),
            (BLOB_LINEAGE_BYTES, self.image.usage.lineage_bytes),
            (BLOB_REPLAY_ROWS, self.image.usage.replay_rows),
            (BLOB_REPLAY_BYTES, self.image.usage.replay_bytes),
            (BLOB_PUBLICATION_ROWS, self.image.usage.publication_rows),
            (BLOB_REFERENCE_ROWS, self.image.usage.reference_rows),
            (
                BLOB_OPERATION_OWNER_ROWS,
                self.image.usage.operation_owner_rows,
            ),
            (
                BLOB_DELIVERY_OWNER_ROWS,
                self.image.usage.delivery_owner_rows,
            ),
            (BLOB_DEADLINE_ROWS, self.image.usage.deadline_rows),
            (BLOB_TTL_DEADLINE_ROWS, self.image.usage.ttl_deadline_rows),
            (
                BLOB_RETIREMENT_RESOLVER_ROWS,
                self.image.usage.retirement_resolver_rows,
            ),
            (
                BLOB_RETIRED_PUBLICATION_ROWS,
                self.image.usage.retired_publication_rows,
            ),
            (
                BLOB_RETIRED_OPERATION_ROWS,
                self.image.usage.retired_operation_rows,
            ),
            (
                BLOB_NEXT_RETIREMENT_GENERATION,
                self.image.usage.next_retirement_generation,
            ),
        ] {
            metadata.insert(field, value)?;
        }
        drop(metadata);
        initialize_maintenance_cursors(write)?;
        initialize_ttl_expiry_cursors(write)?;

        let mut lineages = write.open_table(BLOB_LINEAGE_FENCES)?;
        for (key, value) in &self.image.lineages {
            lineages.insert(key.as_slice(), value.as_slice())?;
        }
        drop(lineages);
        let mut replays = write.open_table(BLOB_REPLAY_FENCES)?;
        for (key, value) in &self.image.replays {
            replays.insert(key.as_slice(), value.as_slice())?;
        }
        drop(replays);
        let mut references = write.open_table(BLOB_VARIANT_REFERENCES)?;
        for (key, value) in &self.image.references {
            references.insert(key.as_slice(), value.as_slice())?;
        }
        drop(references);
        let mut operation_owners = write.open_table(BLOB_OPERATION_OWNERS)?;
        for (key, value) in &self.image.operation_owners {
            operation_owners.insert(key.as_slice(), value.as_slice())?;
        }
        drop(operation_owners);
        let mut delivery_owners = write.open_table(BLOB_DELIVERY_OWNERS)?;
        for (key, value) in &self.image.delivery_owners {
            delivery_owners.insert(key.as_slice(), value.as_slice())?;
        }
        drop(delivery_owners);
        let existing_deadline_keys = write
            .open_table(BLOB_RETENTION_DEADLINES)?
            .iter()?
            .map(|row| row.map(|(key, _)| key.value().to_vec()))
            .collect::<Result<Vec<_>, redb::StorageError>>()?;
        let mut deadlines = write.open_table(BLOB_RETENTION_DEADLINES)?;
        for key in existing_deadline_keys {
            deadlines.remove(key.as_slice())?;
        }
        for (key, value) in &self.image.deadlines {
            deadlines.insert(key.as_slice(), value.as_slice())?;
        }
        drop(deadlines);
        let existing_ttl_deadline_keys = write
            .open_table(BLOB_TTL_DEADLINES)?
            .iter()?
            .map(|row| row.map(|(key, _)| key.value().to_vec()))
            .collect::<Result<Vec<_>, redb::StorageError>>()?;
        let mut ttl_deadlines = write.open_table(BLOB_TTL_DEADLINES)?;
        for key in existing_ttl_deadline_keys {
            ttl_deadlines.remove(key.as_slice())?;
        }
        for (key, value) in &self.image.ttl_deadlines {
            ttl_deadlines.insert(key.as_slice(), value.as_slice())?;
        }
        drop(ttl_deadlines);
        let mut resolvers = write.open_table(BLOB_RETIREMENT_RESOLVERS)?;
        for (key, value) in &self.image.retirement_resolvers {
            resolvers.insert(key.as_slice(), value.as_slice())?;
        }
        drop(resolvers);
        let mut publications = write.open_table(super::BLOB_PUBLICATIONS)?;
        for (key, value) in &self.image.publications {
            publications.insert(key.as_slice(), value.as_slice())?;
        }
        drop(publications);
        let mut operations = write.open_table(super::BLOB_OPERATIONS)?;
        for (key, value) in &self.image.operations {
            operations.insert(key.as_slice(), value.as_slice())?;
        }
        drop(operations);
        let mut pending = write.open_table(super::BLOB_PENDING_SOURCES)?;
        for (key, value) in &self.image.pending_sources {
            pending.insert(key.as_slice(), value.as_slice())?;
        }
        drop(pending);
        let pending_bytes =
            self.image
                .pending_sources
                .iter()
                .try_fold(0u64, |total, (key, value)| {
                    total
                        .checked_add(super::staging_entry_bytes(key.len(), value.len())?)
                        .ok_or(StoreError::PayloadByteAccountingOverflow)
                })?;
        let mut network_metadata = write.open_table(super::BLOB_NETWORK_METADATA)?;
        network_metadata.insert(
            super::BLOB_NETWORK_STAGING_ROWS,
            u64::try_from(self.image.pending_sources.len())
                .map_err(|_| StoreError::ItemCountAccountingOverflow)?,
        )?;
        network_metadata.insert(super::BLOB_NETWORK_STAGING_BYTES, pending_bytes)?;
        write.open_table(super::METADATA)?.insert(
            super::BLOB_OPERATION_TOTAL_BYTES,
            self.image.operation_bytes,
        )?;
        Ok(())
    }
}

#[cfg(test)]
pub(crate) fn downgrade_lifecycle_v5_to_v4_for_test(
    write: &redb::WriteTransaction,
) -> Result<(), StoreError> {
    write.delete_table(BLOB_TTL_DEADLINES)?;
    write.delete_table(BLOB_TTL_EXPIRY_CURSORS)?;
    let mut metadata = write.open_table(BLOB_LIFECYCLE_METADATA)?;
    metadata.insert(
        BLOB_LIFECYCLE_SCHEMA_VERSION_FIELD,
        PREVIOUS_BLOB_LIFECYCLE_SCHEMA_VERSION,
    )?;
    metadata.remove(BLOB_TTL_DEADLINE_ROWS)?;
    Ok(())
}

/// Durable maintenance classes in the approved eligibility order.
#[doc(hidden)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BlobMaintenanceClass {
    ExpiredPublicationsAndPendingSources,
    InvalidPendingWork,
    UnreferencedLocalImportStaging,
    UnreferencedCompletedVariants,
    ExpiredRetirementRecords,
    ManifestBackedPhysicalDeletion,
}

impl BlobMaintenanceClass {
    pub const ALL: [Self; 6] = [
        Self::ExpiredPublicationsAndPendingSources,
        Self::InvalidPendingWork,
        Self::UnreferencedLocalImportStaging,
        Self::UnreferencedCompletedVariants,
        Self::ExpiredRetirementRecords,
        Self::ManifestBackedPhysicalDeletion,
    ];

    pub const fn cursor_key(self) -> u8 {
        match self {
            Self::ExpiredPublicationsAndPendingSources => 1,
            Self::InvalidPendingWork => 2,
            Self::UnreferencedLocalImportStaging => 3,
            Self::UnreferencedCompletedVariants => 4,
            Self::ExpiredRetirementRecords => 5,
            Self::ManifestBackedPhysicalDeletion => 6,
        }
    }

    pub(crate) const fn from_cursor_key(key: u8) -> Option<Self> {
        match key {
            1 => Some(Self::ExpiredPublicationsAndPendingSources),
            2 => Some(Self::InvalidPendingWork),
            3 => Some(Self::UnreferencedLocalImportStaging),
            4 => Some(Self::UnreferencedCompletedVariants),
            5 => Some(Self::ExpiredRetirementRecords),
            6 => Some(Self::ManifestBackedPhysicalDeletion),
            _ => None,
        }
    }

    pub(crate) const fn next(self) -> Self {
        match self {
            Self::ExpiredPublicationsAndPendingSources => Self::InvalidPendingWork,
            Self::InvalidPendingWork => Self::UnreferencedLocalImportStaging,
            Self::UnreferencedLocalImportStaging => Self::UnreferencedCompletedVariants,
            Self::UnreferencedCompletedVariants => Self::ExpiredRetirementRecords,
            Self::ExpiredRetirementRecords => Self::ManifestBackedPhysicalDeletion,
            Self::ManifestBackedPhysicalDeletion => Self::ExpiredPublicationsAndPendingSources,
        }
    }
}

/// Independent bounds for one internal Blob maintenance turn.
#[doc(hidden)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BlobMaintenanceBudget {
    pub(crate) rows: u64,
    pub(crate) files: u64,
    pub(crate) bytes: u64,
}

impl BlobMaintenanceBudget {
    /// Constructs a maintenance budget with every bound enabled.
    pub const fn new(rows: u64, files: u64, bytes: u64) -> Result<Self, BlobStoreError> {
        if rows == 0 || files == 0 || bytes == 0 {
            return Err(BlobStoreError::InvalidMaintenanceBudget);
        }
        Ok(Self { rows, files, bytes })
    }

    pub const fn rows(self) -> u64 {
        self.rows
    }

    pub const fn files(self) -> u64 {
        self.files
    }

    pub const fn bytes(self) -> u64 {
        self.bytes
    }
}

/// A bounded destructive discovery which deliberately remains pending until a
/// later retention/deletion handler is available.
#[doc(hidden)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BlobMaintenanceCandidate {
    UnreferencedLocalImport {
        staging_variant: super::BlobVariantId,
    },
    UnreferencedCompletedVariant {
        variant: super::BlobVariantId,
    },
}

/// Observable result of one bounded internal maintenance scheduling turn.
#[doc(hidden)]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BlobMaintenanceProgress {
    pub class: BlobMaintenanceClass,
    pub rows_examined: u64,
    pub files_examined: u64,
    pub bytes_examined: u64,
    pub candidates: Vec<BlobMaintenanceCandidate>,
    pub class_has_more_work: bool,
    pub awaiting_later_handler: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct BlobMaintenanceCursor {
    pub(crate) class: BlobMaintenanceClass,
    pub(crate) position: Option<Vec<u8>>,
}

fn cursor_invariant(reason: &'static str) -> StoreError {
    StoreError::Blob(BlobStoreError::SchemaInvariant(reason))
}

fn encode_class_cursor(position: Option<&[u8]>) -> Vec<u8> {
    let mut encoded = vec![
        MAINTENANCE_CURSOR_VERSION,
        if position.is_some() {
            MAINTENANCE_CURSOR_POSITION_TAG
        } else {
            MAINTENANCE_CURSOR_UNSET_TAG
        },
    ];
    if let Some(position) = position {
        encoded.extend_from_slice(position);
    }
    encoded
}

fn validate_class_position(class: BlobMaintenanceClass, position: &[u8]) -> Result<(), StoreError> {
    let canonical = match class {
        BlobMaintenanceClass::ExpiredPublicationsAndPendingSources => {
            position.len() == 33
                && matches!(
                    position[0],
                    MAINTENANCE_PUBLICATION_SOURCE_TAG | MAINTENANCE_PENDING_SOURCE_TAG
                )
        }
        BlobMaintenanceClass::InvalidPendingWork => {
            (position.len() == 33 && position[0] == MAINTENANCE_INVALID_PENDING_SOURCE_TAG)
                || (position.len() == 66
                    && position[0] == MAINTENANCE_CARRIER_SOURCE_TAG
                    && position[33] == 2)
        }
        BlobMaintenanceClass::UnreferencedLocalImportStaging
        | BlobMaintenanceClass::UnreferencedCompletedVariants => position.len() == 32,
        BlobMaintenanceClass::ExpiredRetirementRecords => {
            !position.is_empty() && position.len() <= super::MAX_BLOB_OPERATION_STORAGE_KEY_BYTES
        }
        BlobMaintenanceClass::ManifestBackedPhysicalDeletion => {
            (position.len() == 33
                && matches!(
                    position[0],
                    MAINTENANCE_DELETION_MANIFEST_TAG | MAINTENANCE_DELETION_MANIFEST_RESUME_TAG
                ))
                || (position.len() == 41
                    && matches!(
                        position[0],
                        MAINTENANCE_DELETION_CHUNK_TAG | MAINTENANCE_DELETION_CHUNK_RESUME_TAG
                    ))
        }
    };
    if canonical {
        Ok(())
    } else {
        Err(cursor_invariant(
            "Blob maintenance cursor has a malformed class position",
        ))
    }
}

fn decode_class_cursor(
    class: BlobMaintenanceClass,
    encoded: &[u8],
) -> Result<Option<Vec<u8>>, StoreError> {
    if encoded.len() < 2 || encoded[0] != MAINTENANCE_CURSOR_VERSION {
        return Err(cursor_invariant(
            "Blob maintenance cursor has an unknown encoding version",
        ));
    }
    match encoded[1] {
        MAINTENANCE_CURSOR_UNSET_TAG if encoded.len() == 2 => Ok(None),
        MAINTENANCE_CURSOR_POSITION_TAG if encoded.len() > 2 => {
            let position = encoded[2..].to_vec();
            validate_class_position(class, &position)?;
            Ok(Some(position))
        }
        _ => Err(cursor_invariant(
            "Blob maintenance cursor has a noncanonical position encoding",
        )),
    }
}

fn decode_next_class(encoded: &[u8]) -> Result<BlobMaintenanceClass, StoreError> {
    let [version, class] = encoded else {
        return Err(cursor_invariant(
            "Blob maintenance next-class cursor has an invalid length",
        ));
    };
    if *version != MAINTENANCE_CURSOR_VERSION {
        return Err(cursor_invariant(
            "Blob maintenance next-class cursor has an unknown encoding version",
        ));
    }
    BlobMaintenanceClass::from_cursor_key(*class).ok_or_else(|| {
        cursor_invariant("Blob maintenance next-class cursor names an unknown class")
    })
}

fn validate_maintenance_cursors(
    cursors: &impl ReadableTable<u8, &'static [u8]>,
) -> Result<(), StoreError> {
    if cursors.len()? != 1 + BlobMaintenanceClass::ALL.len() as u64 {
        return Err(cursor_invariant(
            "Blob maintenance cursor set is incomplete or contains unknown rows",
        ));
    }
    let next = cursors
        .get(MAINTENANCE_NEXT_CLASS_KEY)?
        .ok_or_else(|| cursor_invariant("Blob maintenance next-class cursor is missing"))?;
    decode_next_class(next.value())?;
    for class in BlobMaintenanceClass::ALL {
        let encoded = cursors
            .get(class.cursor_key())?
            .ok_or_else(|| cursor_invariant("Blob maintenance class cursor is missing"))?;
        decode_class_cursor(class, encoded.value())?;
    }
    Ok(())
}

fn initialize_maintenance_cursors(write: &redb::WriteTransaction) -> Result<(), StoreError> {
    let mut cursors = write.open_table(BLOB_MAINTENANCE_CURSORS)?;
    if cursors.len()? != 0 {
        return validate_maintenance_cursors(&cursors);
    }
    cursors.insert(
        MAINTENANCE_NEXT_CLASS_KEY,
        [
            MAINTENANCE_CURSOR_VERSION,
            BlobMaintenanceClass::ALL[0].cursor_key(),
        ]
        .as_slice(),
    )?;
    let unset = encode_class_cursor(None);
    for class in BlobMaintenanceClass::ALL {
        cursors.insert(class.cursor_key(), unset.as_slice())?;
    }
    Ok(())
}

pub(crate) fn load_maintenance_cursor(
    write: &redb::WriteTransaction,
) -> Result<BlobMaintenanceCursor, StoreError> {
    let cursors = write.open_table(BLOB_MAINTENANCE_CURSORS)?;
    validate_maintenance_cursors(&cursors)?;
    let next = cursors
        .get(MAINTENANCE_NEXT_CLASS_KEY)?
        .ok_or_else(|| cursor_invariant("Blob maintenance next-class cursor is missing"))?;
    let class = decode_next_class(next.value())?;
    let position = cursors
        .get(class.cursor_key())?
        .ok_or_else(|| cursor_invariant("Blob maintenance class cursor is missing"))?;
    Ok(BlobMaintenanceCursor {
        class,
        position: decode_class_cursor(class, position.value())?,
    })
}

pub(crate) fn load_maintenance_cursor_read(
    read: &redb::ReadTransaction,
) -> Result<BlobMaintenanceCursor, StoreError> {
    let cursors = read.open_table(BLOB_MAINTENANCE_CURSORS)?;
    validate_maintenance_cursors(&cursors)?;
    let next = cursors
        .get(MAINTENANCE_NEXT_CLASS_KEY)?
        .ok_or_else(|| cursor_invariant("Blob maintenance next-class cursor is missing"))?;
    let class = decode_next_class(next.value())?;
    let position = cursors
        .get(class.cursor_key())?
        .ok_or_else(|| cursor_invariant("Blob maintenance class cursor is missing"))?;
    Ok(BlobMaintenanceCursor {
        class,
        position: decode_class_cursor(class, position.value())?,
    })
}

pub(crate) fn charge_maintenance_cursor_write(
    write: &redb::WriteTransaction,
    selected: BlobMaintenanceClass,
    charge: &mut super::MaintenanceCharge,
) -> Result<bool, StoreError> {
    let cursors = write.open_table(BLOB_MAINTENANCE_CURSORS)?;
    for key in [selected.cursor_key(), MAINTENANCE_NEXT_CLASS_KEY] {
        let value = cursors
            .get(key)?
            .ok_or_else(|| cursor_invariant("Blob maintenance cursor is missing"))?;
        if !charge.charge_row(
            super::MaintenanceRowIdentity::new("aster.blob-maintenance-cursors.v1", [key]),
            value.value().len(),
        )? {
            return Ok(false);
        }
    }
    Ok(true)
}

pub(crate) fn advance_maintenance_cursor(
    write: &redb::WriteTransaction,
    selected: BlobMaintenanceClass,
    position: Option<&[u8]>,
) -> Result<(), StoreError> {
    if let Some(position) = position {
        validate_class_position(selected, position)?;
    }
    let mut cursors = write.open_table(BLOB_MAINTENANCE_CURSORS)?;
    cursors.insert(
        selected.cursor_key(),
        encode_class_cursor(position).as_slice(),
    )?;
    super::deletion::manifest_admission_mutation_boundary()?;
    cursors.insert(
        MAINTENANCE_NEXT_CLASS_KEY,
        [MAINTENANCE_CURSOR_VERSION, selected.next().cursor_key()].as_slice(),
    )?;
    super::deletion::manifest_admission_mutation_boundary()?;
    Ok(())
}

/// Performs only constant-time table-metadata/accounting checks needed before
/// a bounded turn. Full row validation remains bounded by the selected page.
pub(crate) fn require_maintenance_accounting(
    write: &redb::WriteTransaction,
) -> Result<(), StoreError> {
    let metadata = write.open_table(BLOB_LIFECYCLE_METADATA)?;
    if metadata.len()? != BLOB_LIFECYCLE_METADATA_FIELDS.len() as u64
        || metadata
            .get(BLOB_LIFECYCLE_SCHEMA_VERSION_FIELD)?
            .map(|value| value.value())
            != Some(ACTIVE_BLOB_LIFECYCLE_SCHEMA_VERSION)
    {
        return Err(cursor_invariant(
            "Blob lifecycle accounting metadata is incomplete or unknown",
        ));
    }
    let counter = |field| {
        metadata
            .get(field)
            .map_err(StoreError::from)?
            .map(|value| value.value())
            .ok_or_else(|| cursor_invariant("Blob lifecycle accounting field is missing"))
    };
    let lineage_rows = counter(BLOB_LINEAGE_ROWS)?;
    let replay_rows = counter(BLOB_REPLAY_ROWS)?;
    let publication_rows = counter(BLOB_PUBLICATION_ROWS)?;
    let reference_rows = counter(BLOB_REFERENCE_ROWS)?;
    let operation_owner_rows = counter(BLOB_OPERATION_OWNER_ROWS)?;
    let delivery_owner_rows = counter(BLOB_DELIVERY_OWNER_ROWS)?;
    let deadline_rows = counter(BLOB_DEADLINE_ROWS)?;
    let retirement_resolver_rows = counter(BLOB_RETIREMENT_RESOLVER_ROWS)?;
    let lineage_bytes = lineage_rows
        .checked_mul(32 + LineageFence::ENCODED_BYTES as u64)
        .ok_or(StoreError::PayloadByteAccountingOverflow)?;
    let replay_bytes = replay_rows
        .checked_mul(40 + ReplayFence::ENCODED_BYTES as u64)
        .ok_or(StoreError::PayloadByteAccountingOverflow)?;
    if counter(BLOB_LINEAGE_BYTES)? != lineage_bytes
        || counter(BLOB_REPLAY_BYTES)? != replay_bytes
        || write.open_table(BLOB_LINEAGE_FENCES)?.len()? != lineage_rows
        || write.open_table(BLOB_REPLAY_FENCES)?.len()? != replay_rows
        || write.open_table(BLOB_VARIANT_REFERENCES)?.len()? != reference_rows
        || write.open_table(super::BLOB_PUBLICATIONS)?.len()? != publication_rows
        || write.open_table(BLOB_OPERATION_OWNERS)?.len()? != operation_owner_rows
        || write.open_table(BLOB_DELIVERY_OWNERS)?.len()? != delivery_owner_rows
        || write.open_table(BLOB_RETENTION_DEADLINES)?.len()? != deadline_rows
        || write.open_table(BLOB_RETIREMENT_RESOLVERS)?.len()? != retirement_resolver_rows
    {
        return Err(cursor_invariant(
            "Blob lifecycle accounting cannot describe the durable rows",
        ));
    }
    Ok(())
}

pub(crate) fn variant_has_reference(
    write: &redb::WriteTransaction,
    variant: super::BlobVariantId,
) -> Result<bool, StoreError> {
    let references = write.open_table(BLOB_VARIANT_REFERENCES)?;
    let start = variant.as_bytes().as_slice();
    let Some((key, value)) = references.range(start..)?.next().transpose()? else {
        return Ok(false);
    };
    if key.value().starts_with(start) {
        if key.value().len() != 65 || !value.value().is_empty() {
            return Err(cursor_invariant("Blob variant reference is not canonical"));
        }
        VariantReferenceOwner::decode(&key.value()[32..33]).map_err(StoreError::Blob)?;
        Ok(true)
    } else {
        Ok(false)
    }
}

pub(crate) fn validate_maintenance_lineage_evidence(
    physical_lineage: [u8; 32],
    owner_binding: [u8; 32],
    encoded: &[u8],
) -> Result<(), StoreError> {
    let fence = LineageFence::decode(encoded).map_err(StoreError::Blob)?;
    if !fence.same_authority(LineageFence::new(physical_lineage, owner_binding)) {
        return Err(cursor_invariant(
            "retained Blob import conflicts with its lineage fence",
        ));
    }
    Ok(())
}

pub(crate) fn validate_maintenance_replay_evidence(
    expected: ReplayFence,
    encoded: &[u8],
) -> Result<(), StoreError> {
    let fence = ReplayFence::decode(encoded).map_err(StoreError::Blob)?;
    if fence != expected {
        return Err(cursor_invariant(
            "live Blob publication conflicts with its replay fence",
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicU64, Ordering};

    use aster_mesh::CustodySample;
    use redb::{Database, ReadableDatabase};

    use crate::{BlobSemanticId, BlobTransferId};

    use super::*;

    static NEXT_RETIREMENT_AUDIT_DB: AtomicU64 = AtomicU64::new(1);

    #[test]
    fn expired_replay_causal_evidence_cannot_exist_without_blob_lifecycle_schema() {
        let path = std::env::temp_dir().join(format!(
            "aster-blob-orphan-causal-fence-{}-{}",
            std::process::id(),
            NEXT_RETIREMENT_AUDIT_DB.fetch_add(1, Ordering::Relaxed)
        ));
        let database = Database::create(&path).expect("create orphan causal-fence database");
        let write = database.begin_write().expect("orphan causal-fence write");
        write
            .open_table(BLOB_REPLAY_CAUSAL_FENCES)
            .expect("orphan causal-fence table")
            .insert([0x91; 40].as_slice(), [0x92; 32].as_slice())
            .expect("insert orphan causal-fence row");
        assert!(matches!(
            require_blob_lifecycle_absent_write(&write),
            Err(StoreError::Blob(BlobStoreError::SchemaInvariant(_)))
        ));
        write.commit().expect("commit orphan causal-fence fixture");
        let read = database.begin_read().expect("orphan causal-fence read");
        assert!(matches!(
            require_blob_lifecycle_absent_read(&read),
            Err(StoreError::Blob(BlobStoreError::SchemaInvariant(_)))
        ));
        drop(read);
        drop(database);
        std::fs::remove_file(path).expect("remove orphan causal-fence database");
    }

    fn audit_retired_test_image(
        write: &redb::WriteTransaction,
        expected: &ExpectedLifecycleImage,
    ) -> Result<BlobLifecycleUsage, StoreError> {
        audit_current_rows(
            &write.open_table(BLOB_LIFECYCLE_METADATA)?,
            &write.open_table(BLOB_VARIANT_REFERENCES)?,
            &write.open_table(BLOB_LINEAGE_FENCES)?,
            &write.open_table(BLOB_REPLAY_FENCES)?,
            &write.open_table(BLOB_MAINTENANCE_CURSORS)?,
            &write.open_table(BLOB_OPERATION_OWNERS)?,
            &write.open_table(BLOB_DELIVERY_OWNERS)?,
            &write.open_table(BLOB_RETENTION_DEADLINES)?,
            Some(table_map(&write.open_table(BLOB_TTL_DEADLINES)?)?),
            Some(collect_retirement_resolvers(
                &write.open_table(BLOB_RETIREMENT_RESOLVERS)?,
            )?),
            expected,
            [0x73; 32],
            BLOB_LIFECYCLE_SCHEMA_VERSION,
        )
    }

    #[test]
    fn blob_lifecycle_limits_reject_zero_and_preserve_exact_defaults() {
        assert_eq!(
            BlobLifecycleLimits::default(),
            BlobLifecycleLimits::new(65_536, 16 * 1024 * 1024, 65_536, 16 * 1024 * 1024, 65_536,)
                .expect("documented defaults are valid"),
        );
        assert_eq!(BlobLifecycleLimits::default().max_lineage_rows(), 65_536);
        assert_eq!(
            BlobLifecycleLimits::default().max_lineage_bytes(),
            16 * 1024 * 1024
        );
        assert_eq!(BlobLifecycleLimits::default().max_replay_rows(), 65_536);
        assert_eq!(
            BlobLifecycleLimits::default().max_replay_bytes(),
            16 * 1024 * 1024
        );
        assert_eq!(
            BlobLifecycleLimits::default().max_publication_rows(),
            65_536
        );
        assert_eq!(
            BlobLifecycleLimits::default().retain_for_ms(),
            3_888_000_000
        );

        for limits in [
            (0, 1, 1, 1, 1),
            (1, 0, 1, 1, 1),
            (1, 1, 0, 1, 1),
            (1, 1, 1, 0, 1),
            (1, 1, 1, 1, 0),
        ] {
            assert!(
                BlobLifecycleLimits::new(limits.0, limits.1, limits.2, limits.3, limits.4).is_err()
            );
        }
    }

    #[test]
    fn blob_ttl_deadline_index_orders_due_roots_by_kind_tick_identity_and_fences_cycle() {
        // Mutations caught: reusing the retention index, ordering tick before
        // root kind, scanning a transfer table, or letting a later insertion
        // extend an already captured due cycle.
        let sequence = NEXT_RETIREMENT_AUDIT_DB.fetch_add(1, Ordering::Relaxed);
        let path = std::env::temp_dir().join(format!(
            "aster-blob-ttl-deadline-index-{}-{sequence}.redb",
            std::process::id()
        ));
        let database = Database::create(&path).expect("create TTL deadline database");
        let clock_id = [0x61; 16];
        let generation = 7;
        let live_early = TtlDeadline {
            generation,
            deadline: CustodySample {
                clock_id,
                tick_ms: 100,
            },
            kind: TtlDeadlineKind::LivePublication,
            transfer: BlobTransferId::new([0x10; 32]),
        };
        let live_fence = TtlDeadline {
            generation,
            deadline: CustodySample {
                clock_id,
                tick_ms: 110,
            },
            kind: TtlDeadlineKind::LivePublication,
            transfer: BlobTransferId::new([0x20; 32]),
        };
        let pending_due = TtlDeadline {
            generation,
            deadline: CustodySample {
                clock_id,
                tick_ms: 90,
            },
            kind: TtlDeadlineKind::PendingSource,
            transfer: BlobTransferId::new([0x30; 32]),
        };
        let live_later = TtlDeadline {
            generation,
            deadline: CustodySample {
                clock_id,
                tick_ms: 120,
            },
            kind: TtlDeadlineKind::LivePublication,
            transfer: BlobTransferId::new([0x40; 32]),
        };

        let write = database.begin_write().expect("deadline write");
        for deadline in [live_early, live_fence, pending_due, live_later] {
            insert_ttl_deadline_write(&write, deadline).expect("insert deadline");
        }
        let fence = capture_ttl_due_end_write(
            &write,
            generation,
            CustodySample {
                clock_id,
                tick_ms: 115,
            },
            TtlDeadlineKind::LivePublication,
        )
        .expect("capture live fence")
        .expect("live due fence");
        assert_eq!(decode_ttl_deadline_key(&fence).unwrap(), live_fence);
        let cycle = TtlExpiryCycle {
            end_key: fence,
            position: None,
        };
        assert_eq!(
            next_ttl_due_in_cycle_write(&write, &cycle)
                .expect("first due")
                .expect("live due row"),
            live_early
        );

        let after_first = TtlExpiryCycle {
            end_key: fence,
            position: Some(ttl_deadline_key(live_early).expect("early key")),
        };
        let inserted_after_capture = TtlDeadline {
            generation,
            deadline: CustodySample {
                clock_id,
                tick_ms: 112,
            },
            kind: TtlDeadlineKind::LivePublication,
            transfer: BlobTransferId::new([0x50; 32]),
        };
        insert_ttl_deadline_write(&write, inserted_after_capture).expect("insert after fence");
        assert_eq!(
            next_ttl_due_in_cycle_write(&write, &after_first)
                .expect("second due")
                .expect("fenced due row"),
            live_fence,
            "a greater key inserted after capture must wait for the next cycle"
        );
        assert_eq!(
            capture_ttl_due_end_write(
                &write,
                generation,
                CustodySample {
                    clock_id,
                    tick_ms: 115,
                },
                TtlDeadlineKind::PendingSource,
            )
            .unwrap()
            .map(|key| decode_ttl_deadline_key(&key).unwrap()),
            Some(pending_due),
            "pending has an independent due range"
        );
        write.commit().expect("commit deadline fixture");
        drop(database);
        std::fs::remove_file(path).expect("remove TTL deadline database");
    }

    #[test]
    fn blob_ttl_expiry_cycle_codec_rejects_cross_prefix_and_position_after_fence() {
        // Mutations caught: a restart must not resume a live cursor in the
        // pending/generation/clock range or beyond its captured end fence.
        let base = TtlDeadline {
            generation: 9,
            deadline: CustodySample {
                clock_id: [0x71; 16],
                tick_ms: 200,
            },
            kind: TtlDeadlineKind::LivePublication,
            transfer: BlobTransferId::new([0x20; 32]),
        };
        let end_key = ttl_deadline_key(base).expect("end key");
        let position = ttl_deadline_key(TtlDeadline {
            deadline: CustodySample {
                tick_ms: 190,
                ..base.deadline
            },
            transfer: BlobTransferId::new([0x10; 32]),
            ..base
        })
        .expect("position key");
        let cycle = TtlExpiryCycle {
            end_key,
            position: Some(position),
        };
        let encoded = encode_ttl_expiry_cycle(Some(&cycle));
        assert_eq!(decode_ttl_expiry_cycle(&encoded).unwrap(), Some(cycle));
        assert_eq!(decode_ttl_expiry_cycle(&[1, 0]).unwrap(), None);

        let mut cross_kind = encoded.clone();
        cross_kind[2 + 25] = TtlDeadlineKind::PendingSource.tag();
        assert!(decode_ttl_expiry_cycle(&cross_kind).is_err());
        let mut after_fence = encoded;
        let position_offset = 2 + 66 + 1;
        after_fence[position_offset + 26..position_offset + 34]
            .copy_from_slice(&201u64.to_be_bytes());
        assert!(decode_ttl_expiry_cycle(&after_fence).is_err());
    }

    #[test]
    fn blob_ttl_expiry_cursor_persists_independent_fenced_cycles_and_alternating_phase() {
        // Mutations caught: one composite cursor can starve pending work, and
        // an in-memory phase reset can repeatedly favor live work after reopen.
        let sequence = NEXT_RETIREMENT_AUDIT_DB.fetch_add(1, Ordering::Relaxed);
        let path = std::env::temp_dir().join(format!(
            "aster-blob-ttl-expiry-cursor-{}-{sequence}.redb",
            std::process::id()
        ));
        let database = Database::create(&path).expect("create TTL cursor database");
        let write = database.begin_write().expect("TTL cursor initialize");
        initialize_ttl_expiry_cursors(&write).expect("initialize TTL cursors");
        let initial = load_ttl_expiry_state_write(&write).expect("initial TTL cursor state");
        assert_eq!(initial.next_phase, TtlExpiryPhase::Live);
        assert_eq!(initial.live, None);
        assert_eq!(initial.pending, None);

        let live_end = ttl_deadline_key(TtlDeadline {
            generation: 3,
            deadline: CustodySample {
                clock_id: [0x81; 16],
                tick_ms: 100,
            },
            kind: TtlDeadlineKind::LivePublication,
            transfer: BlobTransferId::new([0x31; 32]),
        })
        .unwrap();
        let live = TtlExpiryCycle {
            end_key: live_end,
            position: None,
        };
        store_ttl_expiry_turn(&write, TtlExpiryPhase::Live, Some(&live))
            .expect("persist live cycle");
        let after_live = load_ttl_expiry_state_write(&write).unwrap();
        assert_eq!(after_live.next_phase, TtlExpiryPhase::Pending);
        assert_eq!(after_live.live, Some(live));
        assert_eq!(after_live.pending, None);
        write.commit().expect("commit live cursor");

        let write = database.begin_write().expect("TTL cursor reopen write");
        let reopened = load_ttl_expiry_state_write(&write).expect("reopened TTL cursor state");
        assert_eq!(
            reopened, after_live,
            "restart must preserve phase and live fence"
        );
        let pending_end = ttl_deadline_key(TtlDeadline {
            generation: 3,
            deadline: CustodySample {
                clock_id: [0x81; 16],
                tick_ms: 90,
            },
            kind: TtlDeadlineKind::PendingSource,
            transfer: BlobTransferId::new([0x41; 32]),
        })
        .unwrap();
        let pending = TtlExpiryCycle {
            end_key: pending_end,
            position: Some(pending_end),
        };
        store_ttl_expiry_turn(&write, TtlExpiryPhase::Pending, Some(&pending))
            .expect("persist pending cycle");
        let after_pending = load_ttl_expiry_state_write(&write).unwrap();
        assert_eq!(after_pending.next_phase, TtlExpiryPhase::Live);
        assert_eq!(after_pending.live, Some(live));
        assert_eq!(after_pending.pending, Some(pending));
        assert!(store_ttl_expiry_turn(&write, TtlExpiryPhase::Pending, None).is_err());
        write.commit().expect("commit pending cursor");
        drop(database);
        std::fs::remove_file(path).expect("remove TTL cursor database");
    }

    #[test]
    fn blob_ttl_expiry_turn_selects_only_fenced_due_roots_and_alternates_kind() {
        // Mutations caught: selecting arbitrary transfer order instead of the
        // dedicated due index, resetting the fence after every root, or
        // allowing a continuously nonempty live class to starve pending work.
        let sequence = NEXT_RETIREMENT_AUDIT_DB.fetch_add(1, Ordering::Relaxed);
        let path = std::env::temp_dir().join(format!(
            "aster-blob-ttl-expiry-turn-{}-{sequence}.redb",
            std::process::id()
        ));
        let database = Database::create(&path).expect("create TTL turn database");
        let generation = 5;
        let clock_id = [0x85; 16];
        let sample = CustodySample {
            clock_id,
            tick_ms: 100,
        };
        let live_first = TtlDeadline {
            generation,
            deadline: CustodySample {
                clock_id,
                tick_ms: 80,
            },
            kind: TtlDeadlineKind::LivePublication,
            transfer: BlobTransferId::new([0x10; 32]),
        };
        let live_fence = TtlDeadline {
            deadline: CustodySample {
                clock_id,
                tick_ms: 90,
            },
            transfer: BlobTransferId::new([0x20; 32]),
            ..live_first
        };
        let pending = TtlDeadline {
            deadline: CustodySample {
                clock_id,
                tick_ms: 70,
            },
            kind: TtlDeadlineKind::PendingSource,
            transfer: BlobTransferId::new([0x30; 32]),
            ..live_first
        };

        let write = database.begin_write().unwrap();
        write
            .open_table(BLOB_LIFECYCLE_METADATA)
            .unwrap()
            .insert(
                BLOB_LIFECYCLE_SCHEMA_VERSION_FIELD,
                BLOB_LIFECYCLE_SCHEMA_VERSION,
            )
            .unwrap();
        initialize_ttl_expiry_cursors(&write).unwrap();
        for deadline in [live_first, live_fence, pending] {
            insert_ttl_deadline_write(&write, deadline).unwrap();
        }
        let first = plan_ttl_expiry_turn_write(&write, generation, sample)
            .unwrap()
            .expect("first live due root");
        assert_eq!(first.deadline, Some(live_first));
        let mut exact_charge = super::super::MaintenanceCharge {
            budget: BlobMaintenanceBudget::new(3, 1, 72).unwrap(),
            rows: 0,
            bytes: 0,
            identities: std::collections::BTreeMap::new(),
        };
        assert!(charge_ttl_expiry_turn_write(&write, first, &mut exact_charge).unwrap());
        assert_eq!((exact_charge.rows, exact_charge.bytes), (3, 72));
        let mut short_charge = super::super::MaintenanceCharge {
            budget: BlobMaintenanceBudget::new(2, 1, 72).unwrap(),
            rows: 0,
            bytes: 0,
            identities: std::collections::BTreeMap::new(),
        };
        assert!(!charge_ttl_expiry_turn_write(&write, first, &mut short_charge).unwrap());
        finish_ttl_expiry_turn_write(&write, first).unwrap();

        let second = plan_ttl_expiry_turn_write(&write, generation, sample)
            .unwrap()
            .expect("pending due root");
        assert_eq!(second.deadline, Some(pending));
        finish_ttl_expiry_turn_write(&write, second).unwrap();

        let third = plan_ttl_expiry_turn_write(&write, generation, sample)
            .unwrap()
            .expect("second fenced live root");
        assert_eq!(third.deadline, Some(live_fence));
        finish_ttl_expiry_turn_write(&write, third).unwrap();
        assert_eq!(
            load_ttl_expiry_state_write(&write).unwrap().next_phase,
            TtlExpiryPhase::Pending
        );
        drop(write);
        drop(database);
        std::fs::remove_file(path).unwrap();
    }

    #[test]
    fn blob_ttl_empty_phase_charges_other_cycle_and_due_probe_before_progress() {
        let sequence = NEXT_RETIREMENT_AUDIT_DB.fetch_add(1, Ordering::Relaxed);
        let path = std::env::temp_dir().join(format!(
            "aster-blob-ttl-empty-phase-charge-{}-{sequence}.redb",
            std::process::id()
        ));
        let database = Database::create(&path).unwrap();
        let generation = 11;
        let sample = CustodySample {
            clock_id: [0x8f; 16],
            tick_ms: 100,
        };
        let pending = TtlDeadline {
            generation,
            deadline: CustodySample {
                clock_id: sample.clock_id,
                tick_ms: 90,
            },
            kind: TtlDeadlineKind::PendingSource,
            transfer: BlobTransferId::new([0x44; 32]),
        };
        let write = database.begin_write().unwrap();
        write
            .open_table(BLOB_LIFECYCLE_METADATA)
            .unwrap()
            .insert(
                BLOB_LIFECYCLE_SCHEMA_VERSION_FIELD,
                BLOB_LIFECYCLE_SCHEMA_VERSION,
            )
            .unwrap();
        initialize_ttl_expiry_cursors(&write).unwrap();
        insert_ttl_deadline_write(&write, pending).unwrap();
        let turn = plan_ttl_expiry_turn_write(&write, generation, sample)
            .unwrap()
            .expect("empty live phase advances toward due pending work");
        assert_eq!(turn.deadline, None);
        let before = load_ttl_expiry_state_write(&write).unwrap();
        let (exact_rows, exact_bytes) = {
            let mut charge = super::super::MaintenanceCharge::new(
                BlobMaintenanceBudget::new(u64::MAX, 1, u64::MAX).unwrap(),
                0,
                0,
            );
            assert!(charge_ttl_expiry_turn_write(&write, turn, &mut charge).unwrap());
            assert_eq!(
                charge.rows, 4,
                "phase, both cycle rows, and the other phase due probe are authoritative"
            );
            (charge.rows, charge.bytes)
        };
        for budget in [
            BlobMaintenanceBudget::new(exact_rows - 1, 1, exact_bytes).unwrap(),
            BlobMaintenanceBudget::new(exact_rows, 1, exact_bytes - 1).unwrap(),
        ] {
            let mut charge = super::super::MaintenanceCharge::new(budget, 0, 0);
            assert!(!charge_ttl_expiry_turn_write(&write, turn, &mut charge).unwrap());
            assert_eq!(load_ttl_expiry_state_write(&write).unwrap(), before);
        }
        finish_ttl_expiry_turn_write(&write, turn).unwrap();
        assert_eq!(
            plan_ttl_expiry_turn_write(&write, generation, sample)
                .unwrap()
                .unwrap()
                .deadline,
            Some(pending)
        );
        drop(write);
        drop(database);
        std::fs::remove_file(path).unwrap();
    }

    #[test]
    fn blob_ttl_persisted_cycle_eof_charges_only_selected_cycle_and_phase() {
        let sequence = NEXT_RETIREMENT_AUDIT_DB.fetch_add(1, Ordering::Relaxed);
        let path = std::env::temp_dir().join(format!(
            "aster-blob-ttl-persisted-eof-charge-{}-{sequence}.redb",
            std::process::id()
        ));
        let database = Database::create(&path).unwrap();
        let generation = 12;
        let sample = CustodySample {
            clock_id: [0x9f; 16],
            tick_ms: 100,
        };
        let first = TtlDeadline {
            generation,
            deadline: CustodySample {
                clock_id: sample.clock_id,
                tick_ms: 80,
            },
            kind: TtlDeadlineKind::LivePublication,
            transfer: BlobTransferId::new([0x10; 32]),
        };
        let fence = TtlDeadline {
            deadline: CustodySample {
                clock_id: sample.clock_id,
                tick_ms: 90,
            },
            transfer: BlobTransferId::new([0x20; 32]),
            ..first
        };
        let write = database.begin_write().unwrap();
        write
            .open_table(BLOB_LIFECYCLE_METADATA)
            .unwrap()
            .insert(
                BLOB_LIFECYCLE_SCHEMA_VERSION_FIELD,
                BLOB_LIFECYCLE_SCHEMA_VERSION,
            )
            .unwrap();
        initialize_ttl_expiry_cursors(&write).unwrap();
        insert_ttl_deadline_write(&write, first).unwrap();
        insert_ttl_deadline_write(&write, fence).unwrap();
        let first_turn = plan_ttl_expiry_turn_write(&write, generation, sample)
            .unwrap()
            .unwrap();
        assert_eq!(first_turn.deadline, Some(first));
        finish_ttl_expiry_turn_write(&write, first_turn).unwrap();
        store_ttl_expiry_turn(&write, TtlExpiryPhase::Pending, None).unwrap();
        write
            .open_table(BLOB_TTL_DEADLINES)
            .unwrap()
            .remove(ttl_deadline_key(fence).unwrap().as_slice())
            .unwrap();

        let eof = plan_ttl_expiry_turn_write(&write, generation, sample)
            .unwrap()
            .expect("persisted live cycle reaches fenced EOF");
        assert_eq!(eof.deadline, None);
        let before = load_ttl_expiry_state_write(&write).unwrap();
        let (exact_rows, exact_bytes) = {
            let mut charge = super::super::MaintenanceCharge::new(
                BlobMaintenanceBudget::new(u64::MAX, 1, u64::MAX).unwrap(),
                0,
                0,
            );
            assert!(charge_ttl_expiry_turn_write(&write, eof, &mut charge).unwrap());
            assert_eq!(charge.rows, 2, "selected cycle and phase only");
            (charge.rows, charge.bytes)
        };
        for budget in [
            BlobMaintenanceBudget::new(exact_rows - 1, 1, exact_bytes).unwrap(),
            BlobMaintenanceBudget::new(exact_rows, 1, exact_bytes - 1).unwrap(),
        ] {
            let mut charge = super::super::MaintenanceCharge::new(budget, 0, 0);
            assert!(!charge_ttl_expiry_turn_write(&write, eof, &mut charge).unwrap());
            assert_eq!(load_ttl_expiry_state_write(&write).unwrap(), before);
        }
        finish_ttl_expiry_turn_write(&write, eof).unwrap();
        assert_ne!(load_ttl_expiry_state_write(&write).unwrap(), before);
        drop(write);
        drop(database);
        std::fs::remove_file(path).unwrap();
    }

    #[test]
    fn blob_ttl_expiry_generation_change_invalidates_both_fenced_cycles() {
        // Mutations caught: retaining either prior-generation fence after a
        // continuity restart, selecting stale due work, or resetting only the
        // phase selected by the current turn.
        let sequence = NEXT_RETIREMENT_AUDIT_DB.fetch_add(1, Ordering::Relaxed);
        let path = std::env::temp_dir().join(format!(
            "aster-blob-ttl-expiry-generation-{}-{sequence}.redb",
            std::process::id()
        ));
        let database = Database::create(&path).expect("create TTL generation database");
        let old_generation = 5;
        let old_clock = [0x91; 16];
        let current_generation = 6;
        let current_sample = CustodySample {
            clock_id: [0x92; 16],
            tick_ms: 200,
        };
        let live = TtlDeadline {
            generation: old_generation,
            deadline: CustodySample {
                clock_id: old_clock,
                tick_ms: 80,
            },
            kind: TtlDeadlineKind::LivePublication,
            transfer: BlobTransferId::new([0x93; 32]),
        };
        let pending = TtlDeadline {
            kind: TtlDeadlineKind::PendingSource,
            transfer: BlobTransferId::new([0x94; 32]),
            ..live
        };

        let write = database.begin_write().unwrap();
        write
            .open_table(BLOB_LIFECYCLE_METADATA)
            .unwrap()
            .insert(
                BLOB_LIFECYCLE_SCHEMA_VERSION_FIELD,
                BLOB_LIFECYCLE_SCHEMA_VERSION,
            )
            .unwrap();
        initialize_ttl_expiry_cursors(&write).unwrap();
        for deadline in [live, pending] {
            insert_ttl_deadline_write(&write, deadline).unwrap();
        }
        {
            let mut cursors = write.open_table(BLOB_TTL_EXPIRY_CURSORS).unwrap();
            for (key, deadline) in [
                (TTL_EXPIRY_LIVE_CYCLE_KEY, live),
                (TTL_EXPIRY_PENDING_CYCLE_KEY, pending),
            ] {
                let cycle = TtlExpiryCycle {
                    end_key: ttl_deadline_key(deadline).unwrap(),
                    position: None,
                };
                cursors
                    .insert(key, encode_ttl_expiry_cycle(Some(&cycle)).as_slice())
                    .unwrap();
            }
        }

        synchronize_ttl_expiry_cycles_write(&write, current_generation, current_sample).unwrap();
        assert!(
            plan_ttl_expiry_turn_write(&write, current_generation, current_sample)
                .unwrap()
                .is_none(),
            "a prior-generation due row must not survive cycle synchronization"
        );
        let state = load_ttl_expiry_state_write(&write).unwrap();
        assert!(state.live.is_none() && state.pending.is_none());
        assert_eq!(state.next_phase, TtlExpiryPhase::Live);
        drop(write);
        drop(database);
        std::fs::remove_file(path).unwrap();
    }

    #[test]
    fn blob_ttl_deadline_mutation_rekeys_exact_root_and_counter_atomically() {
        // Mutations caught: leaving the prior deadline behind after an age
        // checkpoint update, inserting the successor without updating the
        // bounded counter, or silently repairing a missing predecessor row.
        let sequence = NEXT_RETIREMENT_AUDIT_DB.fetch_add(1, Ordering::Relaxed);
        let path = std::env::temp_dir().join(format!(
            "aster-blob-ttl-deadline-mutation-{}-{sequence}.redb",
            std::process::id()
        ));
        let database = Database::create(&path).expect("create TTL mutation database");
        let transfer = BlobTransferId::new([0x51; 32]);
        let first = super::super::BlobLifetime::Finite {
            ttl_ms: 1_000,
            age: custody::LowerBoundAgeCheckpoint {
                cumulative_age_ms: 100,
                checkpoint: Some(CustodySample {
                    clock_id: [0x52; 16],
                    tick_ms: 200,
                }),
                continuity_generation: 7,
                continuity_lost: false,
            },
            provenance: super::super::BlobFiniteProvenance::Local,
        };
        let second = super::super::BlobLifetime::Finite {
            ttl_ms: 1_000,
            age: custody::LowerBoundAgeCheckpoint {
                cumulative_age_ms: 400,
                checkpoint: Some(CustodySample {
                    clock_id: [0x52; 16],
                    tick_ms: 500,
                }),
                continuity_generation: 7,
                continuity_lost: false,
            },
            provenance: super::super::BlobFiniteProvenance::Local,
        };

        let write = database.begin_write().expect("TTL mutation writer");
        write
            .open_table(BLOB_LIFECYCLE_METADATA)
            .unwrap()
            .insert(BLOB_TTL_DEADLINE_ROWS, 0)
            .unwrap();
        replace_ttl_deadline_write(
            &write,
            transfer,
            TtlDeadlineKind::LivePublication,
            None,
            Some(first),
            4,
        )
        .expect("insert first deadline");
        assert_eq!(
            write.open_table(BLOB_TTL_DEADLINES).unwrap().len().unwrap(),
            1
        );
        assert_eq!(
            write
                .open_table(BLOB_LIFECYCLE_METADATA)
                .unwrap()
                .get(BLOB_TTL_DEADLINE_ROWS)
                .unwrap()
                .unwrap()
                .value(),
            1
        );

        replace_ttl_deadline_write(
            &write,
            transfer,
            TtlDeadlineKind::LivePublication,
            Some(first),
            Some(second),
            4,
        )
        .expect("re-key exact deadline");
        let rows = write
            .open_table(BLOB_TTL_DEADLINES)
            .unwrap()
            .iter()
            .unwrap()
            .map(|row| decode_ttl_deadline_key(row.unwrap().0.value()))
            .collect::<Result<Vec<_>, _>>()
            .unwrap();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].deadline.tick_ms, 1_100);
        assert_eq!(rows[0].generation, 7);

        replace_ttl_deadline_write(
            &write,
            transfer,
            TtlDeadlineKind::LivePublication,
            Some(second),
            None,
            4,
        )
        .expect("remove deadline");
        assert_eq!(
            write.open_table(BLOB_TTL_DEADLINES).unwrap().len().unwrap(),
            0
        );
        assert_eq!(
            write
                .open_table(BLOB_LIFECYCLE_METADATA)
                .unwrap()
                .get(BLOB_TTL_DEADLINE_ROWS)
                .unwrap()
                .unwrap()
                .value(),
            0
        );

        assert!(
            replace_ttl_deadline_write(
                &write,
                transfer,
                TtlDeadlineKind::LivePublication,
                Some(second),
                None,
                4,
            )
            .is_err(),
            "a missing predecessor deadline must fail instead of repairing accounting"
        );
        write.commit().expect("commit TTL mutation fixture");
        drop(database);
        std::fs::remove_file(path).expect("remove TTL mutation database");
    }

    #[test]
    fn blob_ttl_deadline_policy_hook_is_v5_only_and_projects_before_indexing() {
        // Mutations caught: creating v5 authority while a v4 store is active,
        // or indexing a fresh continuity generation without persisting the
        // matching projected lifetime.
        let sequence = NEXT_RETIREMENT_AUDIT_DB.fetch_add(1, Ordering::Relaxed);
        let path = std::env::temp_dir().join(format!(
            "aster-blob-ttl-policy-hook-{}-{sequence}.redb",
            std::process::id()
        ));
        let database = Database::create(&path).expect("create TTL policy database");
        let lifetime = super::super::BlobLifetime::Finite {
            ttl_ms: 1_000,
            age: custody::LowerBoundAgeCheckpoint {
                cumulative_age_ms: 100,
                checkpoint: Some(CustodySample {
                    clock_id: [0x62; 16],
                    tick_ms: 200,
                }),
                continuity_generation: 2,
                continuity_lost: false,
            },
            provenance: super::super::BlobFiniteProvenance::Local,
        };
        let continuity = custody::LowerBoundContinuity {
            generation: 1,
            sample: CustodySample {
                clock_id: [0x63; 16],
                tick_ms: 50,
            },
        };
        let write = database.begin_write().unwrap();
        write.open_table(custody::CUSTODY_CONTINUITY).unwrap();
        custody::observe_continuity_write(&write, continuity.sample).unwrap();
        write
            .open_table(BLOB_LIFECYCLE_METADATA)
            .unwrap()
            .insert(BLOB_LIFECYCLE_SCHEMA_VERSION_FIELD, 4)
            .unwrap();
        assert_eq!(
            project_lifetime_for_policy_write(&write, lifetime).unwrap(),
            lifetime
        );
        replace_policy_ttl_deadline_write(
            &write,
            BlobTransferId::new([0x64; 32]),
            TtlDeadlineKind::PendingSource,
            None,
            Some(lifetime),
            BlobLifecycleLimits::DEFAULT,
        )
        .unwrap();
        assert!(
            !write
                .list_tables()
                .unwrap()
                .any(|table| table.name() == BLOB_TTL_DEADLINES.name())
        );

        {
            let mut metadata = write.open_table(BLOB_LIFECYCLE_METADATA).unwrap();
            metadata
                .insert(BLOB_LIFECYCLE_SCHEMA_VERSION_FIELD, 5)
                .unwrap();
            metadata.insert(BLOB_TTL_DEADLINE_ROWS, 0).unwrap();
        }
        let projected = project_lifetime_for_policy_write(&write, lifetime).unwrap();
        let super::super::BlobLifetime::Finite { age, .. } = projected else {
            panic!("finite policy lifetime became durable");
        };
        assert_eq!(age.checkpoint, Some(continuity.sample));
        assert_eq!(age.continuity_generation, continuity.generation);
        replace_policy_ttl_deadline_write(
            &write,
            BlobTransferId::new([0x64; 32]),
            TtlDeadlineKind::PendingSource,
            None,
            Some(projected),
            BlobLifecycleLimits::DEFAULT,
        )
        .unwrap();
        let deadline = {
            let deadlines = write.open_table(BLOB_TTL_DEADLINES).unwrap();
            let deadline = deadlines.iter().unwrap().next().unwrap().unwrap();
            decode_ttl_deadline_key(deadline.0.value()).unwrap()
        };
        assert_eq!(deadline.generation, 1);
        drop(write);
        drop(database);
        std::fs::remove_file(path).unwrap();
    }

    #[test]
    fn blob_v5_projection_persists_cross_generation_age_authority_used_by_deadline() {
        // Mutation caught: deriving a v5 deadline from a projected lifetime
        // while retaining the stale source lifetime allows every reopen to
        // re-anchor from the old continuity generation.
        let lifetime = super::super::BlobLifetime::Finite {
            ttl_ms: 1_000,
            age: custody::LowerBoundAgeCheckpoint {
                cumulative_age_ms: 200,
                checkpoint: Some(CustodySample {
                    clock_id: [0x91; 16],
                    tick_ms: 50,
                }),
                continuity_generation: 3,
                continuity_lost: false,
            },
            provenance: super::super::BlobFiniteProvenance::Local,
        };
        let continuity = custody::LowerBoundContinuity {
            generation: 4,
            sample: CustodySample {
                clock_id: [0x92; 16],
                tick_ms: 80,
            },
        };
        let projected = project_lifetime_for_v5(lifetime, Some(continuity))
            .expect("cross-generation v5 projection");
        let super::super::BlobLifetime::Finite { age, .. } = projected else {
            panic!("finite lifetime became durable");
        };
        assert_eq!(age.cumulative_age_ms, 200);
        assert_eq!(age.checkpoint, Some(continuity.sample));
        assert_eq!(age.continuity_generation, continuity.generation);
        assert!(age.continuity_lost);
        let deadline = ttl_deadline_for_lifetime(
            BlobTransferId::new([0x93; 32]),
            TtlDeadlineKind::LivePublication,
            projected,
            Some(continuity),
            Some(continuity.sample),
        )
        .expect("deadline from persisted projection")
        .expect("sticky lower-bound deadline");
        assert_eq!(deadline.generation, continuity.generation);
        assert_eq!(deadline.deadline.tick_ms, 880);
    }

    #[test]
    fn blob_lifecycle_codecs_reject_noncanonical_records() {
        assert_eq!(PublicationState::Live.encode(), [1]);
        assert_eq!(OperationState::Active.encode(), [1]);
        assert_eq!(VariantReferenceOwner::Publication.encode(), [1]);
        assert_eq!(VariantReferenceOwner::PendingSource.encode(), [2]);
        assert!(PublicationState::decode(&[0]).is_err());
        assert!(PublicationState::decode(&[1, 0]).is_err());
        assert!(OperationState::decode(&[2]).is_err());
        assert!(OperationState::decode(&[1, 0]).is_err());
        assert!(VariantReferenceOwner::decode(&[0]).is_err());
        assert!(VariantReferenceOwner::decode(&[1, 0]).is_err());

        let lineage = LineageFence::new([0x11; 32], [0x22; 32]);
        let mut expected_lineage = [0u8; 65];
        expected_lineage[0] = 1;
        expected_lineage[1..33].fill(0x11);
        expected_lineage[33..].fill(0x22);
        assert_eq!(lineage.encode(), expected_lineage);
        assert_eq!(
            LineageFence::decode(&expected_lineage).expect("canonical lineage"),
            lineage
        );
        assert!(LineageFence::decode(&expected_lineage[..64]).is_err());
        let mut reclaimed_lineage = expected_lineage;
        reclaimed_lineage[0] = RECLAIMED_LINEAGE_FENCE_VERSION;
        assert!(
            LineageFence::decode(&reclaimed_lineage)
                .expect("canonical reclaimed lineage")
                .bulk_reclamation_observed()
        );
        let mut lineage_with_unknown_version = expected_lineage;
        lineage_with_unknown_version[0] = 3;
        assert!(LineageFence::decode(&lineage_with_unknown_version).is_err());
        let mut lineage_with_trailing = expected_lineage.to_vec();
        lineage_with_trailing.push(0);
        assert!(LineageFence::decode(&lineage_with_trailing).is_err());

        let replay = ReplayFence::new(
            [0x33; 32],
            9,
            BlobSemanticId::new([0x44; 32]),
            BlobTransferId::new([0x55; 32]),
            123,
            [0x66; 32],
        );
        let mut expected_replay = [0u8; 145];
        expected_replay[0] = 1;
        expected_replay[1..33].fill(0x33);
        expected_replay[33..41].copy_from_slice(&9u64.to_be_bytes());
        expected_replay[41..73].fill(0x44);
        expected_replay[73..105].fill(0x55);
        expected_replay[105..113].copy_from_slice(&123u64.to_be_bytes());
        expected_replay[113..].fill(0x66);
        assert_eq!(replay.encode(), expected_replay);
        assert_eq!(
            ReplayFence::decode(&expected_replay).expect("canonical replay"),
            replay
        );
        assert!(ReplayFence::decode(&expected_replay[..144]).is_err());
        let mut replay_with_unknown_version = expected_replay;
        replay_with_unknown_version[0] = 2;
        assert!(ReplayFence::decode(&replay_with_unknown_version).is_err());
        let mut replay_with_trailing = expected_replay.to_vec();
        replay_with_trailing.push(0);
        assert!(ReplayFence::decode(&replay_with_trailing).is_err());
    }

    #[test]
    fn publication_v3_collision_is_resolved_only_by_trusted_schema_generation() {
        let metadata_like = [3, 1, 3, 0xaa, 0xbb];
        // Mutation caught: content sniffing would unwrap this valid metadata-v3
        // prefix merely because its transfer bytes resemble a v1 wrapper.
        assert_eq!(
            publication_payload_for_encoding(
                &metadata_like,
                PublicationEncodingGeneration::RawCurrent,
            )
            .unwrap(),
            metadata_like
        );
        assert!(
            publication_payload_for_encoding(
                &metadata_like,
                PublicationEncodingGeneration::LifecycleV1,
            )
            .is_err(),
            "historical lifecycle-v1 authority cannot admit a metadata-v3 payload"
        );

        let malformed_wrapper_that_starts_like_metadata = [3, 0, 3, 0xcc];
        // Mutation caught: fallback parse order must not reinterpret malformed
        // lifecycle-v1 state as current metadata under a v1 schema authority.
        assert!(
            publication_payload_for_encoding(
                &malformed_wrapper_that_starts_like_metadata,
                PublicationEncodingGeneration::LifecycleV1,
            )
            .is_err()
        );
        assert_eq!(
            publication_payload_for_encoding(
                &malformed_wrapper_that_starts_like_metadata,
                PublicationEncodingGeneration::RawCurrent,
            )
            .unwrap(),
            malformed_wrapper_that_starts_like_metadata
        );
    }

    #[test]
    fn blob_retirement_codecs_bind_reason_generation_digest_and_age_canonically() {
        // Break caught: retirement evidence must not admit an ambiguous reason,
        // generation, operation-key digest, clock sample, or trailing bytes.
        let sample = CustodySample {
            clock_id: [0x31; 16],
            tick_ms: 44,
        };
        let age = RetirementAge::new(55, sample, 123).expect("nonzero record retention");
        let publication = PublicationState::Retired {
            reason: RetirementReason::Evicted,
            generation: 66,
            age,
        };
        let operation = OperationState::Retired {
            reason: RetirementReason::Expired,
            generation: 77,
            operation_key_digest: [0x41; 32],
            intent_digest: [0x42; 32],
            age,
        };

        let publication_bytes = publication.encode();
        let operation_bytes = operation.encode();
        assert_eq!(
            PublicationState::decode(&publication_bytes).expect("publication retirement"),
            publication
        );
        assert_eq!(
            OperationState::decode(&operation_bytes).expect("operation retirement"),
            operation
        );
        assert_eq!(RetirementReason::decode(1), Some(RetirementReason::Expired));
        assert_eq!(
            RetirementReason::decode(2),
            Some(RetirementReason::Invalidated)
        );
        assert_eq!(RetirementReason::decode(3), Some(RetirementReason::Evicted));
        assert_eq!(RetirementReason::decode(0), None);
        assert_eq!(RetirementReason::decode(4), None);
        assert_eq!(age.retain_for_ms(), 123);
        assert!(RetirementAge::new(55, sample, 0).is_err());

        let mut trailing = publication_bytes.clone();
        trailing.push(0);
        assert!(PublicationState::decode(&trailing).is_err());
        let mut unknown_reason = operation_bytes;
        unknown_reason[1] = 0;
        assert!(OperationState::decode(&unknown_reason).is_err());
    }

    #[test]
    fn blob_retirement_clock_projects_same_domain_restart_and_known_deadline() {
        // Break caught: reopening in the same suspend-inclusive domain must
        // include elapsed restart time and retain an exact deadline.
        let accepted = CustodySample {
            clock_id: [0x51; 16],
            tick_ms: 100,
        };
        let projection = RetirementAge::new(40, accepted, 200)
            .expect("nonzero record retention")
            .project(Some(CustodySample {
                clock_id: accepted.clock_id,
                tick_ms: 160,
            }))
            .expect("same-domain projection");
        assert_eq!(projection.age.cumulative_age_ms(), 100);
        assert!(!projection.is_lower_bound);
        assert!(!projection.retention_elapsed);
        assert_eq!(
            projection.deadline,
            Some(CustodySample {
                clock_id: accepted.clock_id,
                tick_ms: 260,
            })
        );
    }

    #[test]
    fn blob_retirement_clock_loss_accumulates_lower_bound_across_domains_to_45_days() {
        // Break caught: a changed domain, rollback, or missing sample must not
        // invent freshness, and later measurable domains must still prove the
        // exact 45-day retirement bound.
        let retain_for_ms = DEFAULT_BLOB_RETIREMENT_RETENTION_MS;
        let domain_a = CustodySample {
            clock_id: [0xa1; 16],
            tick_ms: 10,
        };
        let first = RetirementAge::new(retain_for_ms - 30, domain_a, retain_for_ms)
            .expect("nonzero record retention")
            .project(Some(CustodySample {
                clock_id: domain_a.clock_id,
                tick_ms: 20,
            }))
            .expect("domain A interval");
        assert_eq!(first.age.cumulative_age_ms(), retain_for_ms - 20);
        assert!(!first.is_lower_bound);

        let domain_b = CustodySample {
            clock_id: [0xb2; 16],
            tick_ms: 500,
        };
        let changed = first.age.project(Some(domain_b)).expect("changed domain");
        assert!(changed.is_lower_bound);
        assert_eq!(changed.age.cumulative_age_ms(), retain_for_ms - 20);

        let rollback = changed
            .age
            .project(Some(CustodySample {
                clock_id: domain_b.clock_id,
                tick_ms: 400,
            }))
            .expect("rollback installs a conservative anchor");
        assert!(rollback.is_lower_bound);
        let missing = rollback
            .age
            .project(None)
            .expect("missing sample preserves lower bound");
        assert!(missing.is_lower_bound);
        assert_eq!(missing.deadline, None);

        let domain_c = CustodySample {
            clock_id: [0xc3; 16],
            tick_ms: 1_000,
        };
        let anchored = missing
            .age
            .project(Some(domain_c))
            .expect("new lower-bound anchor");
        let elapsed = anchored
            .age
            .project(Some(CustodySample {
                clock_id: domain_c.clock_id,
                tick_ms: 1_020,
            }))
            .expect("new measurable interval");
        assert_eq!(elapsed.age.cumulative_age_ms(), retain_for_ms);
        assert!(elapsed.is_lower_bound);
        assert!(elapsed.retention_elapsed);
        assert_eq!(elapsed.deadline, None);
    }

    #[test]
    fn blob_retirement_clock_overflow_fails_closed_as_elapsed() {
        // Break caught: checked-age overflow must never retain a retry fence as
        // apparently young or synthesize a wrapping deadline.
        let sample = CustodySample {
            clock_id: [0xf1; 16],
            tick_ms: 1,
        };
        let projection = RetirementAge::new(u64::MAX - 1, sample, u64::MAX)
            .expect("nonzero record retention")
            .project(Some(CustodySample {
                clock_id: sample.clock_id,
                tick_ms: 3,
            }))
            .expect("overflow is a conservative elapsed result");
        assert_eq!(projection.age.cumulative_age_ms(), u64::MAX);
        assert!(projection.is_lower_bound);
        assert!(projection.retention_elapsed);
        assert_eq!(projection.deadline, None);
    }

    #[test]
    fn blob_retired_rows_reconstruct_deadlines_counters_and_generation_across_reopen() {
        // Break caught: canonical retired rows and their exact deadline index
        // must be self-auditing; a restart must not reinterpret them as live or
        // require the retirement counters/high-water to remain zero.
        let sequence = NEXT_RETIREMENT_AUDIT_DB.fetch_add(1, Ordering::Relaxed);
        let path = std::env::temp_dir().join(format!(
            "aster-blob-retirement-audit-{}-{sequence}.redb",
            std::process::id()
        ));
        let transfer = BlobTransferId::new([0x71; 32]);
        let operation_key = b"retired-operation";
        let operation_digest: [u8; 32] = Sha256::digest(operation_key).into();
        let clock_id = [0x72; 16];
        let replay = ReplayFence::new(
            [0x74; 32],
            4,
            BlobSemanticId::new([0x75; 32]),
            transfer,
            321,
            [0x76; 32],
        );
        let replay_key = super::super::accepted_dot_key(crate::Dot {
            publisher: replay.publisher,
            counter: replay.counter,
        });
        let replay_value = replay.encode();
        let replay_bytes = entry_bytes(&replay_key, &replay_value).expect("replay bytes");
        let publication_age = RetirementAge::new(
            50,
            CustodySample {
                clock_id,
                tick_ms: 100,
            },
            200,
        )
        .expect("publication retention");
        let operation_age = RetirementAge::new(
            25,
            CustodySample {
                clock_id,
                tick_ms: 100,
            },
            200,
        )
        .expect("operation retention");
        let publication_state = PublicationState::Retired {
            reason: RetirementReason::Evicted,
            generation: 7,
            age: publication_age,
        };
        let operation_state = OperationState::Retired {
            reason: RetirementReason::Expired,
            generation: 9,
            operation_key_digest: operation_digest,
            intent_digest: [0x5a; 32],
            age: operation_age,
        };
        let mut publication_record = vec![CURRENT_PUBLICATION_RECORD_VERSION];
        publication_record.extend_from_slice(&publication_state.encode());
        let mut operation_record = vec![CURRENT_OPERATION_RECORD_VERSION];
        operation_record.extend_from_slice(&operation_state.encode());

        let database = Database::create(&path).expect("create retirement audit database");
        let write = database.begin_write().expect("retirement audit write");
        write
            .open_table(super::super::BLOB_PUBLICATIONS)
            .expect("publications")
            .insert(
                transfer.as_bytes().as_slice(),
                publication_record.as_slice(),
            )
            .expect("retired publication");
        write
            .open_table(super::super::BLOB_BYTES)
            .expect("source bytes");
        write
            .open_table(super::super::BLOB_OPERATIONS)
            .expect("operations")
            .insert(operation_key.as_slice(), operation_record.as_slice())
            .expect("retired operation");
        for table in [
            BLOB_VARIANT_REFERENCES,
            BLOB_LINEAGE_FENCES,
            BLOB_REPLAY_FENCES,
            BLOB_OPERATION_OWNERS,
            BLOB_DELIVERY_OWNERS,
            BLOB_RETENTION_DEADLINES,
            BLOB_RETIREMENT_RESOLVERS,
        ] {
            write.open_table(table).expect("lifecycle table");
        }
        write
            .open_table(BLOB_REPLAY_FENCES)
            .expect("replays")
            .insert(replay_key.as_slice(), replay_value.as_slice())
            .expect("permanent replay fence");
        initialize_maintenance_cursors(&write).expect("maintenance cursors");
        let publication_deadline = CustodySample {
            clock_id,
            tick_ms: 250,
        };
        let operation_deadline = CustodySample {
            clock_id,
            tick_ms: 275,
        };
        {
            let mut deadlines = write
                .open_table(BLOB_RETENTION_DEADLINES)
                .expect("retention deadlines");
            deadlines
                .insert(
                    retention_deadline_key(
                        publication_deadline,
                        RetentionDeadlineOwner::Publication(transfer),
                    )
                    .as_slice(),
                    &[][..],
                )
                .expect("publication deadline");
            deadlines
                .insert(
                    retention_deadline_key(
                        operation_deadline,
                        RetentionDeadlineOwner::Operation(operation_digest),
                    )
                    .as_slice(),
                    &[][..],
                )
                .expect("operation deadline");
        }
        {
            let mut resolvers = write
                .open_table(BLOB_RETIREMENT_RESOLVERS)
                .expect("retirement resolvers");
            resolvers
                .insert(
                    retirement_resolver_key(RetentionDeadlineOwner::Publication(transfer))
                        .as_slice(),
                    &[][..],
                )
                .expect("publication resolver");
            resolvers
                .insert(
                    retirement_resolver_key(RetentionDeadlineOwner::Operation(operation_digest))
                        .as_slice(),
                    operation_key.as_slice(),
                )
                .expect("operation resolver");
        }
        {
            let mut metadata = write
                .open_table(BLOB_LIFECYCLE_METADATA)
                .expect("lifecycle metadata");
            for (field, value) in [
                (
                    BLOB_LIFECYCLE_SCHEMA_VERSION_FIELD,
                    BLOB_LIFECYCLE_SCHEMA_VERSION,
                ),
                (BLOB_LINEAGE_ROWS, 0),
                (BLOB_LINEAGE_BYTES, 0),
                (BLOB_REPLAY_ROWS, 1),
                (BLOB_REPLAY_BYTES, replay_bytes),
                (BLOB_PUBLICATION_ROWS, 1),
                (BLOB_REFERENCE_ROWS, 0),
                (BLOB_OPERATION_OWNER_ROWS, 0),
                (BLOB_DELIVERY_OWNER_ROWS, 0),
                (BLOB_DEADLINE_ROWS, 2),
                (BLOB_TTL_DEADLINE_ROWS, 0),
                (BLOB_RETIREMENT_RESOLVER_ROWS, 2),
                (BLOB_RETIRED_PUBLICATION_ROWS, 1),
                (BLOB_RETIRED_OPERATION_ROWS, 1),
                (BLOB_NEXT_RETIREMENT_GENERATION, 11),
            ] {
                metadata.insert(field, value).expect("metadata field");
            }
        }

        let expected = reconstruct_expected_image(
            &write
                .open_table(super::super::BLOB_PUBLICATIONS)
                .expect("publications"),
            &write
                .open_table(super::super::BLOB_BYTES)
                .expect("source bytes"),
            &write
                .open_table(super::super::BLOB_OPERATIONS)
                .expect("operations"),
            Vec::new(),
            Vec::new(),
            Vec::new(),
            [0x73; 32],
            LifecycleSchemaState::Current,
            None,
            true,
        )
        .expect("reconstruct retired authority");
        assert_eq!(expected.usage.retired_publication_rows, 1);
        assert_eq!(expected.usage.retired_operation_rows, 1);
        assert_eq!(expected.usage.deadline_rows, 2);
        assert_eq!(expected.usage.next_retirement_generation, 9);
        let audited = audit_retired_test_image(&write, &expected).expect("audit retired authority");
        assert_eq!(audited.next_retirement_generation, 11);
        assert_eq!(audited.replay_rows, 1);
        assert_eq!(audited.replay_bytes, replay_bytes);

        write
            .open_table(BLOB_LIFECYCLE_METADATA)
            .expect("metadata")
            .insert(BLOB_NEXT_RETIREMENT_GENERATION, 8)
            .expect("lower generation high-water");
        assert!(audit_retired_test_image(&write, &expected).is_err());
        write
            .open_table(BLOB_LIFECYCLE_METADATA)
            .expect("metadata")
            .insert(BLOB_NEXT_RETIREMENT_GENERATION, 11)
            .expect("restore generation high-water");

        let publication_deadline_key = retention_deadline_key(
            publication_deadline,
            RetentionDeadlineOwner::Publication(transfer),
        );
        write
            .open_table(BLOB_RETENTION_DEADLINES)
            .expect("deadlines")
            .remove(publication_deadline_key.as_slice())
            .expect("remove deadline");
        assert!(audit_retired_test_image(&write, &expected).is_err());
        write
            .open_table(BLOB_RETENTION_DEADLINES)
            .expect("deadlines")
            .insert(publication_deadline_key.as_slice(), &[][..])
            .expect("restore deadline");

        let publication_resolver_key =
            retirement_resolver_key(RetentionDeadlineOwner::Publication(transfer));
        write
            .open_table(BLOB_RETIREMENT_RESOLVERS)
            .expect("retirement resolvers")
            .remove(publication_resolver_key.as_slice())
            .expect("remove publication resolver");
        assert!(
            audit_retired_test_image(&write, &expected).is_err(),
            "every retired record must remain exactly discoverable"
        );
        write
            .open_table(BLOB_RETIREMENT_RESOLVERS)
            .expect("retirement resolvers")
            .insert(publication_resolver_key.as_slice(), &[][..])
            .expect("restore publication resolver");
        write.commit().expect("commit retirement authority");
        drop(database);

        let database = Database::open(&path).expect("reopen retirement audit database");
        let read = database.begin_read().expect("retirement audit read");
        let expected = reconstruct_expected_image(
            &read
                .open_table(super::super::BLOB_PUBLICATIONS)
                .expect("publications"),
            &read
                .open_table(super::super::BLOB_BYTES)
                .expect("source bytes"),
            &read
                .open_table(super::super::BLOB_OPERATIONS)
                .expect("operations"),
            Vec::new(),
            Vec::new(),
            Vec::new(),
            [0x73; 32],
            LifecycleSchemaState::Current,
            None,
            true,
        )
        .expect("reconstruct reopened retired authority");
        assert_eq!(expected.usage.deadline_rows, 2);
        audit_current_rows(
            &read.open_table(BLOB_LIFECYCLE_METADATA).expect("metadata"),
            &read
                .open_table(BLOB_VARIANT_REFERENCES)
                .expect("references"),
            &read.open_table(BLOB_LINEAGE_FENCES).expect("lineages"),
            &read.open_table(BLOB_REPLAY_FENCES).expect("replays"),
            &read.open_table(BLOB_MAINTENANCE_CURSORS).expect("cursors"),
            &read.open_table(BLOB_OPERATION_OWNERS).expect("owners"),
            &read
                .open_table(BLOB_DELIVERY_OWNERS)
                .expect("delivery owners"),
            &read
                .open_table(BLOB_RETENTION_DEADLINES)
                .expect("deadlines"),
            Some(
                table_map(&read.open_table(BLOB_TTL_DEADLINES).expect("TTL deadlines"))
                    .expect("collect TTL deadlines"),
            ),
            Some(
                collect_retirement_resolvers(
                    &read
                        .open_table(BLOB_RETIREMENT_RESOLVERS)
                        .expect("retirement resolvers"),
                )
                .expect("collect retirement resolvers"),
            ),
            &expected,
            [0x73; 32],
            BLOB_LIFECYCLE_SCHEMA_VERSION,
        )
        .expect("audit reopened retired authority");
        drop(read);
        drop(database);
        std::fs::remove_file(path).expect("remove retirement audit database");
    }

    #[test]
    fn blob_maintenance_class_order_keys_reverse_mapping_and_wraparound_are_stable() {
        use BlobMaintenanceClass::{
            ExpiredPublicationsAndPendingSources, ExpiredRetirementRecords, InvalidPendingWork,
            ManifestBackedPhysicalDeletion, UnreferencedCompletedVariants,
            UnreferencedLocalImportStaging,
        };

        assert_eq!(
            BlobMaintenanceClass::ALL,
            [
                ExpiredPublicationsAndPendingSources,
                InvalidPendingWork,
                UnreferencedLocalImportStaging,
                UnreferencedCompletedVariants,
                ExpiredRetirementRecords,
                ManifestBackedPhysicalDeletion,
            ]
        );
        for (class, key, next) in [
            (ExpiredPublicationsAndPendingSources, 1, InvalidPendingWork),
            (InvalidPendingWork, 2, UnreferencedLocalImportStaging),
            (
                UnreferencedLocalImportStaging,
                3,
                UnreferencedCompletedVariants,
            ),
            (UnreferencedCompletedVariants, 4, ExpiredRetirementRecords),
            (ExpiredRetirementRecords, 5, ManifestBackedPhysicalDeletion),
            (
                ManifestBackedPhysicalDeletion,
                6,
                ExpiredPublicationsAndPendingSources,
            ),
        ] {
            assert_eq!(class.cursor_key(), key);
            assert_eq!(BlobMaintenanceClass::from_cursor_key(key), Some(class));
            assert_eq!(class.next(), next);
        }
        assert_eq!(BlobMaintenanceClass::from_cursor_key(0), None);
        assert_eq!(BlobMaintenanceClass::from_cursor_key(7), None);
        assert_eq!(BlobMaintenanceClass::from_cursor_key(u8::MAX), None);
    }

    #[test]
    fn blob_manifest_deletion_cursor_accepts_canonical_work_and_resume_positions() {
        let class = BlobMaintenanceClass::ManifestBackedPhysicalDeletion;
        let mut manifest = [0x11; 33];
        manifest[0] = MAINTENANCE_DELETION_MANIFEST_TAG;
        let mut chunk = [0x22; 41];
        chunk[0] = MAINTENANCE_DELETION_CHUNK_TAG;
        let mut manifest_resume = manifest;
        manifest_resume[0] = MAINTENANCE_DELETION_MANIFEST_RESUME_TAG;
        let mut chunk_resume = chunk;
        chunk_resume[0] = MAINTENANCE_DELETION_CHUNK_RESUME_TAG;

        assert_eq!(
            decode_class_cursor(class, &encode_class_cursor(Some(&manifest)))
                .expect("canonical manifest cursor"),
            Some(manifest.to_vec())
        );
        assert_eq!(
            decode_class_cursor(class, &encode_class_cursor(Some(&chunk)))
                .expect("canonical chunk cursor"),
            Some(chunk.to_vec())
        );
        assert!(validate_class_position(class, &manifest_resume).is_ok());
        assert!(validate_class_position(class, &chunk_resume).is_ok());

        manifest[0] = MAINTENANCE_DELETION_CHUNK_TAG;
        chunk[0] = MAINTENANCE_DELETION_MANIFEST_TAG;
        assert!(validate_class_position(class, &manifest).is_err());
        assert!(validate_class_position(class, &chunk).is_err());
        assert!(validate_class_position(class, &[MAINTENANCE_DELETION_MANIFEST_TAG; 32]).is_err());
        assert!(validate_class_position(class, &[MAINTENANCE_DELETION_CHUNK_TAG; 40]).is_err());
    }

    #[test]
    fn blob_lifecycle_v5_shape_distinguishes_v4_and_current_without_losing_history() {
        let v4 = lifecycle_v4_table_names()
            .into_iter()
            .map(str::to_owned)
            .collect::<BTreeSet<_>>();
        let v5 = lifecycle_table_names()
            .into_iter()
            .map(str::to_owned)
            .collect::<BTreeSet<_>>();

        assert_eq!(PREVIOUS_BLOB_LIFECYCLE_SCHEMA_VERSION, 4);
        assert_eq!(BLOB_LIFECYCLE_SCHEMA_VERSION, 5);
        assert_eq!(BLOB_LIFECYCLE_V4_METADATA_FIELDS.len(), 14);
        assert!(BLOB_LIFECYCLE_METADATA_FIELDS.contains(&BLOB_TTL_DEADLINE_ROWS));
        assert!(v5.contains(BLOB_TTL_DEADLINES.name()));
        assert!(v5.contains(BLOB_TTL_EXPIRY_CURSORS.name()));
        assert!(!v4.contains(BLOB_TTL_DEADLINES.name()));
        assert!(!v4.contains(BLOB_TTL_EXPIRY_CURSORS.name()));
    }

    mod blob_lifecycle_budget {
        use super::*;

        #[test]
        fn blob_maintenance_budget_requires_each_nonzero_bound() {
            assert_eq!(
                BlobMaintenanceBudget::new(5, 6, 7).expect("nonzero budget"),
                BlobMaintenanceBudget {
                    rows: 5,
                    files: 6,
                    bytes: 7,
                }
            );
            assert!(BlobMaintenanceBudget::new(0, 1, 1).is_err());
            assert!(BlobMaintenanceBudget::new(1, 0, 1).is_err());
            assert!(BlobMaintenanceBudget::new(1, 1, 0).is_err());
        }
    }
}
