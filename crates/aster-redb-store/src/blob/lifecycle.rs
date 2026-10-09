use std::collections::{BTreeMap, BTreeSet};

use redb::{
    MultimapTableHandle, ReadableTable, ReadableTableMetadata, TableDefinition, TableHandle,
};
use sha2::{Digest, Sha256};

use super::{BlobSemanticId, BlobStoreError, BlobStoreStats, BlobTransferId, StoreError, depot};

#[cfg(test)]
thread_local! {
    pub(crate) static TEST_BLOB_LIFECYCLE_MIGRATION_FAULT: std::cell::Cell<bool> = const {
        std::cell::Cell::new(false)
    };
    pub(crate) static TEST_BLOB_LIFECYCLE_MIGRATION_DISABLED: std::cell::Cell<bool> = const {
        std::cell::Cell::new(false)
    };
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

/// Dedicated non-evictable Blob lifecycle authority limits.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BlobLifecycleLimits {
    max_lineage_rows: u64,
    max_lineage_bytes: u64,
    max_replay_rows: u64,
    max_replay_bytes: u64,
    max_publication_rows: u64,
}

impl BlobLifecycleLimits {
    /// Conservative selected-profile lifecycle authority limits.
    pub const DEFAULT: Self = Self {
        max_lineage_rows: DEFAULT_MAX_BLOB_LINEAGE_FENCE_ROWS,
        max_lineage_bytes: DEFAULT_MAX_BLOB_LINEAGE_FENCE_BYTES,
        max_replay_rows: DEFAULT_MAX_BLOB_REPLAY_FENCE_ROWS,
        max_replay_bytes: DEFAULT_MAX_BLOB_REPLAY_FENCE_BYTES,
        max_publication_rows: DEFAULT_MAX_BLOB_PUBLICATION_LIFECYCLE_ROWS,
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
pub(crate) const BLOB_MAINTENANCE_CURSORS: TableDefinition<u8, &[u8]> =
    TableDefinition::new("aster.blob-maintenance-cursors.v1");

const BLOB_LIFECYCLE_SCHEMA_VERSION_FIELD: &str = "schema_version";
const BLOB_LIFECYCLE_SCHEMA_VERSION: u64 = 1;
const BLOB_LINEAGE_ROWS: &str = "lineage_rows";
const BLOB_LINEAGE_BYTES: &str = "lineage_bytes";
const BLOB_REPLAY_ROWS: &str = "replay_rows";
const BLOB_REPLAY_BYTES: &str = "replay_bytes";
const BLOB_PUBLICATION_ROWS: &str = "publication_rows";
const BLOB_REFERENCE_ROWS: &str = "reference_rows";
const BLOB_LIFECYCLE_METADATA_FIELDS: [&str; 7] = [
    BLOB_LIFECYCLE_SCHEMA_VERSION_FIELD,
    BLOB_LINEAGE_ROWS,
    BLOB_LINEAGE_BYTES,
    BLOB_REPLAY_ROWS,
    BLOB_REPLAY_BYTES,
    BLOB_PUBLICATION_ROWS,
    BLOB_REFERENCE_ROWS,
];

const CURRENT_PUBLICATION_RECORD_VERSION: u8 = 3;

const RECORD_VERSION: u8 = 1;
const PUBLICATION_STATE_LIVE_TAG: u8 = 1;
const OPERATION_STATE_ACTIVE_TAG: u8 = 1;
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

/// Canonical lifecycle state for a publication row.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum PublicationState {
    Live,
}

impl PublicationState {
    pub(crate) const fn encode(self) -> [u8; 1] {
        match self {
            Self::Live => [PUBLICATION_STATE_LIVE_TAG],
        }
    }

    pub(crate) fn decode(bytes: &[u8]) -> Result<Self, BlobStoreError> {
        match bytes {
            [PUBLICATION_STATE_LIVE_TAG] => Ok(Self::Live),
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
}

impl OperationState {
    pub(crate) const fn encode(self) -> [u8; 1] {
        match self {
            Self::Active => [OPERATION_STATE_ACTIVE_TAG],
        }
    }

    pub(crate) fn decode(bytes: &[u8]) -> Result<Self, BlobStoreError> {
        match bytes {
            [OPERATION_STATE_ACTIVE_TAG] => Ok(Self::Active),
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
}

impl LineageFence {
    const ENCODED_BYTES: usize = 65;

    pub(crate) const fn new(physical_lineage: [u8; 32], owner_binding: [u8; 32]) -> Self {
        Self {
            physical_lineage,
            owner_binding,
        }
    }

    pub(crate) const fn encode(self) -> [u8; Self::ENCODED_BYTES] {
        let mut bytes = [0; Self::ENCODED_BYTES];
        bytes[0] = RECORD_VERSION;
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
        if bytes[0] != RECORD_VERSION {
            return Err(BlobStoreError::SchemaInvariant(
                "Blob lineage fence has an unknown encoding version",
            ));
        }
        Ok(Self::new(
            bytes[1..33].try_into().expect("fixed lineage fence slice"),
            bytes[33..].try_into().expect("fixed lineage fence slice"),
        ))
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
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub(crate) struct BlobLifecycleUsage {
    pub(crate) lineage_rows: u64,
    pub(crate) lineage_bytes: u64,
    pub(crate) replay_rows: u64,
    pub(crate) replay_bytes: u64,
    pub(crate) publication_rows: u64,
    pub(crate) reference_rows: u64,
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
    Predecessor,
    Current,
}

#[derive(Debug)]
struct ExpectedLifecycleImage {
    publications: BTreeMap<Vec<u8>, Vec<u8>>,
    operations: BTreeMap<Vec<u8>, Vec<u8>>,
    references: BTreeMap<Vec<u8>, Vec<u8>>,
    lineages: BTreeMap<Vec<u8>, Vec<u8>>,
    replays: BTreeMap<Vec<u8>, Vec<u8>>,
    operation_bytes: u64,
    usage: BlobLifecycleUsage,
}

/// Fully preflighted predecessor-to-current lifecycle migration.
pub(crate) struct BlobLifecycleMigration {
    image: ExpectedLifecycleImage,
}

fn lifecycle_table_names() -> [&'static str; 5] {
    [
        BLOB_LIFECYCLE_METADATA.name(),
        BLOB_VARIANT_REFERENCES.name(),
        BLOB_LINEAGE_FENCES.name(),
        BLOB_REPLAY_FENCES.name(),
        BLOB_MAINTENANCE_CURSORS.name(),
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
        0 => Ok(LifecycleSchemaState::Predecessor),
        count if count == names.len() => Ok(LifecycleSchemaState::Current),
        _ => Err(StoreError::Blob(BlobStoreError::SchemaInvariant(
            "Blob lifecycle schema group is incomplete",
        ))),
    }
}

fn lifecycle_schema_state_write(
    write: &redb::WriteTransaction,
) -> Result<LifecycleSchemaState, StoreError> {
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
    if lifecycle_schema_state_write(write)? == LifecycleSchemaState::Current {
        return Err(StoreError::Blob(BlobStoreError::SchemaInvariant(
            "Blob lifecycle authority exists without its base schema",
        )));
    }
    Ok(())
}

pub(crate) fn require_blob_lifecycle_absent_read(
    read: &redb::ReadTransaction,
) -> Result<(), StoreError> {
    if lifecycle_schema_state_read(read)? == LifecycleSchemaState::Current {
        return Err(StoreError::Blob(BlobStoreError::SchemaInvariant(
            "Blob lifecycle authority exists without its base schema",
        )));
    }
    Ok(())
}

pub(crate) fn publication_payload(bytes: &[u8]) -> Result<&[u8], BlobStoreError> {
    if bytes.first().copied() != Some(CURRENT_PUBLICATION_RECORD_VERSION) {
        return Ok(bytes);
    }
    if bytes.len() < 3 {
        return Err(BlobStoreError::SchemaInvariant(
            "Blob publication lifecycle wrapper is truncated",
        ));
    }
    PublicationState::decode(&bytes[1..2])?;
    if !matches!(bytes[2], 1 | 2) {
        return Err(BlobStoreError::SchemaInvariant(
            "Blob publication lifecycle wrapper has a noncanonical payload",
        ));
    }
    Ok(&bytes[2..])
}

fn publication_is_current(bytes: &[u8]) -> bool {
    bytes.first().copied() == Some(CURRENT_PUBLICATION_RECORD_VERSION)
}

fn wrap_publication(bytes: &[u8]) -> Result<Vec<u8>, StoreError> {
    if publication_is_current(bytes) || !matches!(bytes.first(), Some(1 | 2)) {
        return Err(StoreError::Blob(BlobStoreError::SchemaInvariant(
            "Blob predecessor publication is not canonical",
        )));
    }
    let mut wrapped = Vec::with_capacity(bytes.len() + 2);
    wrapped.push(CURRENT_PUBLICATION_RECORD_VERSION);
    wrapped.extend_from_slice(&PublicationState::Live.encode());
    wrapped.extend_from_slice(bytes);
    Ok(wrapped)
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
        == Some(BLOB_LIFECYCLE_SCHEMA_VERSION)
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
        != Some(BLOB_LIFECYCLE_SCHEMA_VERSION)
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
    if fence != LineageFence::new(physical_lineage, owner_binding) {
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
        if existing != expected {
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
    OperationState::decode(&bytes[..1])?;
    Ok(bytes)
}

fn wrap_operation(bytes: &[u8]) -> Result<Vec<u8>, StoreError> {
    operation_payload(bytes).map_err(StoreError::Blob)?;
    Ok(bytes.to_vec())
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

fn reconstruct_expected_image(
    publications: &impl ReadableTable<&'static [u8], &'static [u8]>,
    source_bytes: &impl ReadableTable<&'static [u8], &'static [u8]>,
    operations: &impl ReadableTable<&'static [u8], &'static [u8]>,
    pending_sources: Vec<(Vec<u8>, Vec<u8>)>,
    imports: Vec<depot::AuditedLifecycleImport>,
    owner_binding: [u8; 32],
    schema: LifecycleSchemaState,
) -> Result<ExpectedLifecycleImage, StoreError> {
    let mut expected = ExpectedLifecycleImage {
        publications: BTreeMap::new(),
        operations: BTreeMap::new(),
        references: BTreeMap::new(),
        lineages: BTreeMap::new(),
        replays: BTreeMap::new(),
        operation_bytes: 0,
        usage: BlobLifecycleUsage::default(),
    };
    let mut import_lineages = BTreeMap::new();
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
            LifecycleSchemaState::Predecessor if publication_is_current(encoded) => {
                return Err(StoreError::Blob(BlobStoreError::SchemaInvariant(
                    "Blob predecessor contains a current publication wrapper",
                )));
            }
            LifecycleSchemaState::Current if !publication_is_current(encoded) => {
                return Err(StoreError::Blob(BlobStoreError::SchemaInvariant(
                    "current Blob publication is missing its lifecycle wrapper",
                )));
            }
            _ => {}
        }
        let publication = super::decode_blob_metadata(encoded)?;
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
        let wrapped = match schema {
            LifecycleSchemaState::Predecessor => wrap_publication(encoded)?,
            LifecycleSchemaState::Current => encoded.to_vec(),
        };
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

    for (key, value) in pending_sources {
        let transfer = super::parse_blob_transfer_id("pending Blob source table", &key)?;
        let pending = super::decode_pending_blob_source(&value)?;
        if pending.metadata.transfer_id != transfer
            || import_lineages.get(&pending.metadata.variant_id) != Some(&pending.physical_lineage)
        {
            return Err(StoreError::Blob(BlobStoreError::SchemaInvariant(
                "pending Blob source conflicts with its physical lineage",
            )));
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
    }
    expected.usage.reference_rows = u64::try_from(expected.references.len())
        .map_err(|_| StoreError::ItemCountAccountingOverflow)?;

    for row in operations.iter()? {
        let (key, value) = row?;
        let encoded = value.value();
        super::BlobOperationKey::new(key.value().to_vec())?;
        let operation = super::decode_blob_operation_record(encoded)?;
        if !expected
            .publications
            .contains_key(operation.transfer_id.as_bytes().as_slice())
        {
            return Err(StoreError::Blob(BlobStoreError::SchemaInvariant(
                "Blob lifecycle operation points to a missing publication",
            )));
        }
        let wrapped = match schema {
            LifecycleSchemaState::Predecessor => wrap_operation(encoded)?,
            LifecycleSchemaState::Current => encoded.to_vec(),
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
    }
    Ok(expected)
}

fn audit_metadata(
    metadata: &impl ReadableTable<&'static str, u64>,
    usage: BlobLifecycleUsage,
) -> Result<(), StoreError> {
    if metadata.len()? != BLOB_LIFECYCLE_METADATA_FIELDS.len() as u64 {
        return Err(StoreError::Blob(BlobStoreError::SchemaInvariant(
            "Blob lifecycle accounting metadata is incomplete",
        )));
    }
    for (field, expected) in [
        (
            BLOB_LIFECYCLE_SCHEMA_VERSION_FIELD,
            BLOB_LIFECYCLE_SCHEMA_VERSION,
        ),
        (BLOB_LINEAGE_ROWS, usage.lineage_rows),
        (BLOB_LINEAGE_BYTES, usage.lineage_bytes),
        (BLOB_REPLAY_ROWS, usage.replay_rows),
        (BLOB_REPLAY_BYTES, usage.replay_bytes),
        (BLOB_PUBLICATION_ROWS, usage.publication_rows),
        (BLOB_REFERENCE_ROWS, usage.reference_rows),
    ] {
        if metadata.get(field)?.map(|value| value.value()) != Some(expected) {
            return Err(StoreError::Blob(BlobStoreError::SchemaInvariant(
                "Blob lifecycle accounting metadata disagrees with exact rows",
            )));
        }
    }
    Ok(())
}

fn audit_current_rows(
    metadata: &impl ReadableTable<&'static str, u64>,
    references: &impl ReadableTable<&'static [u8], &'static [u8]>,
    lineages: &impl ReadableTable<&'static [u8], &'static [u8]>,
    replays: &impl ReadableTable<&'static [u8], &'static [u8]>,
    cursors: &impl ReadableTable<u8, &'static [u8]>,
    expected: &ExpectedLifecycleImage,
) -> Result<(), StoreError> {
    audit_metadata(metadata, expected.usage)?;
    validate_maintenance_cursors(cursors)?;

    let mut actual_lineages = BTreeMap::new();
    for row in lineages.iter()? {
        let (key, value) = row?;
        if key.value().len() != 32 {
            return Err(StoreError::Blob(BlobStoreError::SchemaInvariant(
                "Blob lineage fence has an invalid variant key",
            )));
        }
        LineageFence::decode(value.value()).map_err(StoreError::Blob)?;
        actual_lineages.insert(key.value().to_vec(), value.value().to_vec());
    }
    let mut actual_replays = BTreeMap::new();
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
        actual_replays.insert(key.value().to_vec(), value.value().to_vec());
    }
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
    if actual_lineages != expected.lineages
        || actual_replays != expected.replays
        || actual_references != expected.references
    {
        return Err(StoreError::Blob(BlobStoreError::SchemaInvariant(
            "Blob lifecycle authority relations are incomplete or mismatched",
        )));
    }
    Ok(())
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

/// Reconstructs and preflights a complete predecessor image, or strictly
/// audits an already-current lifecycle schema without repairing it.
pub(crate) fn stage_blob_lifecycle_migration_write(
    write: &redb::WriteTransaction,
    limits: BlobLifecycleLimits,
    owner_binding: [u8; 32],
    stats: &mut BlobStoreStats,
) -> Result<Option<BlobLifecycleMigration>, StoreError> {
    let schema = lifecycle_schema_state_write(write)?;
    #[cfg(test)]
    if schema == LifecycleSchemaState::Predecessor && TEST_BLOB_LIFECYCLE_MIGRATION_DISABLED.get() {
        return Ok(None);
    }
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
    let expected = reconstruct_expected_image(
        &publications,
        &source_bytes,
        &operations,
        pending_rows,
        depot::audited_lifecycle_imports_write(write)?,
        owner_binding,
        schema,
    )?;
    match schema {
        LifecycleSchemaState::Predecessor => {
            preflight_migration_limits(expected.usage, limits)?;
            let operation_rows = u64::try_from(expected.operations.len())
                .map_err(|_| StoreError::ItemCountAccountingOverflow)?;
            if operation_rows > super::MAX_BLOB_OPERATIONS
                || expected.operation_bytes > super::MAX_BLOB_OPERATION_BYTES
            {
                return Err(StoreError::Blob(BlobStoreError::SchemaInvariant(
                    "wrapped Blob operation usage exceeds its durable safety caps",
                )));
            }
            expected.usage.apply_to_stats(stats);
            Ok(Some(BlobLifecycleMigration { image: expected }))
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
            audit_current_rows(
                &write.open_table(BLOB_LIFECYCLE_METADATA)?,
                &write.open_table(BLOB_VARIANT_REFERENCES)?,
                &write.open_table(BLOB_LINEAGE_FENCES)?,
                &write.open_table(BLOB_REPLAY_FENCES)?,
                &write.open_table(BLOB_MAINTENANCE_CURSORS)?,
                &expected,
            )?;
            expected.usage.apply_to_stats(stats);
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
    let schema = lifecycle_schema_state_read(read)?;
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
    let expected = reconstruct_expected_image(
        &read.open_table(super::BLOB_PUBLICATIONS)?,
        &read.open_table(super::BLOB_BYTES)?,
        &read.open_table(super::BLOB_OPERATIONS)?,
        pending_rows,
        depot::audited_lifecycle_imports_read(read)?,
        depot::depot_owner_binding_read(read)?,
        schema,
    )?;
    if schema == LifecycleSchemaState::Current {
        audit_current_rows(
            &read.open_table(BLOB_LIFECYCLE_METADATA)?,
            &read.open_table(BLOB_VARIANT_REFERENCES)?,
            &read.open_table(BLOB_LINEAGE_FENCES)?,
            &read.open_table(BLOB_REPLAY_FENCES)?,
            &read.open_table(BLOB_MAINTENANCE_CURSORS)?,
            &expected,
        )?;
    }
    Ok(expected.usage)
}

impl BlobLifecycleMigration {
    pub(crate) fn apply(&self, write: &redb::WriteTransaction) -> Result<(), StoreError> {
        let mut metadata = write.open_table(BLOB_LIFECYCLE_METADATA)?;
        for (field, value) in [
            (
                BLOB_LIFECYCLE_SCHEMA_VERSION_FIELD,
                BLOB_LIFECYCLE_SCHEMA_VERSION,
            ),
            (BLOB_LINEAGE_ROWS, self.image.usage.lineage_rows),
            (BLOB_LINEAGE_BYTES, self.image.usage.lineage_bytes),
            (BLOB_REPLAY_ROWS, self.image.usage.replay_rows),
            (BLOB_REPLAY_BYTES, self.image.usage.replay_bytes),
            (BLOB_PUBLICATION_ROWS, self.image.usage.publication_rows),
            (BLOB_REFERENCE_ROWS, self.image.usage.reference_rows),
        ] {
            metadata.insert(field, value)?;
        }
        drop(metadata);
        initialize_maintenance_cursors(write)?;

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
        write.open_table(super::METADATA)?.insert(
            super::BLOB_OPERATION_TOTAL_BYTES,
            self.image.operation_bytes,
        )?;
        Ok(())
    }
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
            !position.is_empty() && position.len() <= super::MAX_BLOB_OPERATION_KEY_BYTES
        }
        BlobMaintenanceClass::ManifestBackedPhysicalDeletion => false,
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
        return Err(cursor_invariant(
            "Blob maintenance cursors already exist during schema initialization",
        ));
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
    cursors.insert(
        MAINTENANCE_NEXT_CLASS_KEY,
        [MAINTENANCE_CURSOR_VERSION, selected.next().cursor_key()].as_slice(),
    )?;
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
            != Some(BLOB_LIFECYCLE_SCHEMA_VERSION)
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
    if fence != LineageFence::new(physical_lineage, owner_binding) {
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
    use crate::{BlobSemanticId, BlobTransferId};

    use super::*;

    #[test]
    fn blob_lifecycle_limits_reject_zero_and_preserve_exact_defaults() {
        assert_eq!(
            BlobLifecycleLimits::default(),
            BlobLifecycleLimits::new(65_536, 16 * 1024 * 1024, 65_536, 16 * 1024 * 1024, 65_536)
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
        let mut lineage_with_unknown_version = expected_lineage;
        lineage_with_unknown_version[0] = 2;
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
