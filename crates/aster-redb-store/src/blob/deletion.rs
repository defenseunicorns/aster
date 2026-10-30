use std::collections::{BTreeMap, BTreeSet};

use aster_mesh::{BlobId, CustodySample};
use redb::{
    MultimapTableHandle, ReadableTable, ReadableTableMetadata, TableDefinition, TableHandle,
};

use super::{BlobStoreError, BlobVariantId, MAX_SELECTED_BLOB_CHUNKS, MaintenanceCharge};
use crate::StoreError;
use crate::custody::{LowerBoundAgeCheckpoint, LowerBoundContinuity, project_lower_bound_age};

pub(crate) const BLOB_DELETION_METADATA: TableDefinition<&str, u64> =
    TableDefinition::new("aster.blob-deletion-metadata.v1");
pub(crate) const BLOB_DELETION_MANIFESTS: TableDefinition<&[u8], &[u8]> =
    TableDefinition::new("aster.blob-deletion-manifests.v1");
pub(crate) const BLOB_DELETION_CHUNKS: TableDefinition<&[u8], &[u8]> =
    TableDefinition::new("aster.blob-deletion-chunks.v1");
pub(crate) const BLOB_DELETION_CONTINUITY: TableDefinition<u8, &[u8]> =
    TableDefinition::new("aster.blob-deletion-continuity.v1");

pub(crate) const BLOB_DELETION_SCHEMA_VERSION_FIELD: &str = "schema_version";
pub(crate) const BLOB_DELETION_MAINTENANCE_TURN: &str = "maintenance_turn";
pub(crate) const BLOB_DELETION_MANIFEST_ROWS: &str = "manifest_rows";
pub(crate) const BLOB_DELETION_MANIFEST_BYTES: &str = "manifest_bytes";
pub(crate) const BLOB_DELETION_CHUNK_ROWS: &str = "chunk_rows";
pub(crate) const BLOB_DELETION_CHUNK_BYTES: &str = "chunk_bytes";
pub(crate) const BLOB_DELETION_QUEUED_CHUNKS: &str = "queued_chunks";
pub(crate) const BLOB_DELETION_DELETED_CHUNKS: &str = "deleted_chunks";
pub(crate) const BLOB_DELETION_CHARGED_VARIANTS: &str = "charged_variants";
pub(crate) const BLOB_DELETION_CHARGED_FILES: &str = "charged_files";
pub(crate) const BLOB_DELETION_CHARGED_RESERVED_BYTES: &str = "charged_reserved_bytes";
pub(crate) const BLOB_DELETION_CHARGED_COMMITTED_BYTES: &str = "charged_committed_bytes";
pub(crate) const BLOB_DELETION_SCHEMA_VERSION: u64 = 1;

const DELETION_METADATA_FIELDS: [&str; 12] = [
    BLOB_DELETION_SCHEMA_VERSION_FIELD,
    BLOB_DELETION_MAINTENANCE_TURN,
    BLOB_DELETION_MANIFEST_ROWS,
    BLOB_DELETION_MANIFEST_BYTES,
    BLOB_DELETION_CHUNK_ROWS,
    BLOB_DELETION_CHUNK_BYTES,
    BLOB_DELETION_QUEUED_CHUNKS,
    BLOB_DELETION_DELETED_CHUNKS,
    BLOB_DELETION_CHARGED_VARIANTS,
    BLOB_DELETION_CHARGED_FILES,
    BLOB_DELETION_CHARGED_RESERVED_BYTES,
    BLOB_DELETION_CHARGED_COMMITTED_BYTES,
];

const MANIFEST_VERSION: u8 = 1;
const CHUNK_VERSION: u8 = 1;
const CONTINUITY_VERSION: u8 = 1;
const PREVIOUS_CONTINUITY_STATE_VERSION: u8 = 2;
const PENDING_CONTINUITY_STATE_VERSION: u8 = 3;
const CONTINUITY_STATE_VERSION: u8 = 4;
const CONTINUITY_KEY: u8 = 0;
const MAX_LINEAGE_FENCE_EVIDENCE_BYTES: usize = 256;
const MAX_IMPORT_EVIDENCE_BYTES: usize = 1024 * 1024;
const MAX_CHUNK_EVIDENCE_BYTES: usize = 256;
const MAX_MANIFEST_ROW_BYTES: u64 = 32
    + MANIFEST_FIXED_BYTES as u64
    + MAX_LINEAGE_FENCE_EVIDENCE_BYTES as u64
    + MAX_IMPORT_EVIDENCE_BYTES as u64;
const MAX_CHUNK_ROW_BYTES: u64 = 40 + CHUNK_FIXED_BYTES as u64 + MAX_CHUNK_EVIDENCE_BYTES as u64;

#[cfg(test)]
const MANIFEST_PHASE_OFFSET: usize = 1;
#[cfg(test)]
const MANIFEST_RESERVED_OFFSET: usize = 2;
#[cfg(test)]
const MANIFEST_CHUNK_COUNT_OFFSET: usize = 208;
#[cfg(test)]
const MANIFEST_QUEUED_COUNT_OFFSET: usize = 216;
#[cfg(test)]
const MANIFEST_FAILURE_OFFSET: usize = 264;
const MANIFEST_FIXED_BYTES: usize = 330;
#[cfg(test)]
const CHUNK_STATE_OFFSET: usize = 1;
#[cfg(test)]
const CHUNK_RESERVED_OFFSET: usize = 2;
const CHUNK_FIXED_BYTES: usize = 32;

const PHASE_DELETING_CHUNKS: u8 = 1;
const PHASE_DIRECTORY_DELETE_PENDING: u8 = 2;
const CHUNK_DELETE_QUEUED: u8 = 1;
const CHUNK_DELETED_DURABLE: u8 = 2;

#[cfg(test)]
thread_local! {
    static TEST_MANIFEST_ADMISSION_FAULT_ORDINAL: std::cell::Cell<Option<u64>> = const {
        std::cell::Cell::new(None)
    };
    static TEST_MANIFEST_ADMISSION_MUTATIONS: std::cell::Cell<u64> = const {
        std::cell::Cell::new(0)
    };
    static TEST_MANIFEST_ADMISSION_DISCOVERY_FORBIDDEN: std::cell::Cell<bool> = const {
        std::cell::Cell::new(false)
    };
    static TEST_MANIFEST_FINALIZATION_FAULT_ORDINAL: std::cell::Cell<Option<u64>> = const {
        std::cell::Cell::new(None)
    };
    static TEST_MANIFEST_FINALIZATION_MUTATIONS: std::cell::Cell<u64> = const {
        std::cell::Cell::new(0)
    };
    static TEST_DISCOVERY_ROWS_VISITED: std::cell::Cell<u64> = const {
        std::cell::Cell::new(0)
    };
    static TEST_DISCOVERY_BYTES_VISITED: std::cell::Cell<u64> = const {
        std::cell::Cell::new(0)
    };
}

#[cfg(test)]
fn reset_discovery_observation() {
    TEST_DISCOVERY_ROWS_VISITED.set(0);
    TEST_DISCOVERY_BYTES_VISITED.set(0);
}

#[cfg(not(test))]
fn reset_discovery_observation() {}

#[cfg(test)]
fn observe_discovery_row(bytes: u64) {
    TEST_DISCOVERY_ROWS_VISITED.set(
        TEST_DISCOVERY_ROWS_VISITED
            .get()
            .checked_add(1)
            .expect("test discovery row observation overflow"),
    );
    TEST_DISCOVERY_BYTES_VISITED.set(
        TEST_DISCOVERY_BYTES_VISITED
            .get()
            .checked_add(bytes)
            .expect("test discovery byte observation overflow"),
    );
}

#[cfg(not(test))]
fn observe_discovery_row(_bytes: u64) {}

#[cfg(test)]
pub(crate) fn take_discovery_observation_for_test() -> (u64, u64) {
    let observed = (
        TEST_DISCOVERY_ROWS_VISITED.get(),
        TEST_DISCOVERY_BYTES_VISITED.get(),
    );
    reset_discovery_observation();
    observed
}

fn invariant(reason: &'static str) -> StoreError {
    StoreError::Blob(BlobStoreError::SchemaInvariant(reason))
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum BlobDeletionPhase {
    DeletingChunks,
    DirectoryDeletePending,
}

impl BlobDeletionPhase {
    #[allow(dead_code)]
    const fn encode(self) -> u8 {
        match self {
            Self::DeletingChunks => PHASE_DELETING_CHUNKS,
            Self::DirectoryDeletePending => PHASE_DIRECTORY_DELETE_PENDING,
        }
    }

    fn decode(value: u8) -> Result<Self, StoreError> {
        match value {
            PHASE_DELETING_CHUNKS => Ok(Self::DeletingChunks),
            PHASE_DIRECTORY_DELETE_PENDING => Ok(Self::DirectoryDeletePending),
            _ => Err(invariant("Blob deletion manifest phase is not canonical")),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum BlobDeletionChunkState {
    DeleteQueued,
    DeletedDurable,
}

impl BlobDeletionChunkState {
    #[allow(dead_code)]
    const fn encode(self) -> u8 {
        match self {
            Self::DeleteQueued => CHUNK_DELETE_QUEUED,
            Self::DeletedDurable => CHUNK_DELETED_DURABLE,
        }
    }

    fn decode(value: u8) -> Result<Self, StoreError> {
        match value {
            CHUNK_DELETE_QUEUED => Ok(Self::DeleteQueued),
            CHUNK_DELETED_DURABLE => Ok(Self::DeletedDurable),
            _ => Err(invariant("Blob deletion chunk state is not canonical")),
        }
    }
}

/// Sanitized durable failure class. No path or operating-system text enters
/// this record.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum BlobDeletionFailureCategory {
    VariantDirectoryAccess,
    ChunkUnlink,
    ChunkDirectorySync,
    VariantDirectoryRemove,
    DepotDirectorySync,
}

impl BlobDeletionFailureCategory {
    #[allow(dead_code)]
    const fn encode(self) -> u8 {
        match self {
            Self::VariantDirectoryAccess => 1,
            Self::ChunkUnlink => 2,
            Self::ChunkDirectorySync => 3,
            Self::VariantDirectoryRemove => 4,
            Self::DepotDirectorySync => 5,
        }
    }

    fn decode(value: u8) -> Result<Option<Self>, StoreError> {
        match value {
            0 => Ok(None),
            1 => Ok(Some(Self::VariantDirectoryAccess)),
            2 => Ok(Some(Self::ChunkUnlink)),
            3 => Ok(Some(Self::ChunkDirectorySync)),
            4 => Ok(Some(Self::VariantDirectoryRemove)),
            5 => Ok(Some(Self::DepotDirectorySync)),
            _ => Err(invariant("Blob deletion failure category is not canonical")),
        }
    }
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub(crate) struct BlobDeletionRetry {
    pub(crate) category: Option<BlobDeletionFailureCategory>,
    pub(crate) attempts: u32,
    pub(crate) next_retry_turn: u64,
}

impl BlobDeletionRetry {
    fn validate(self) -> Result<(), StoreError> {
        match self.category {
            None if self.attempts == 0 && self.next_retry_turn == 0 => Ok(()),
            Some(_)
                if self.attempts != 0
                    && self.next_retry_turn != 0
                    && self.failure_turn().is_some() =>
            {
                Ok(())
            }
            _ => Err(invariant("Blob deletion retry state is not canonical")),
        }
    }

    pub(crate) fn failure_turn(self) -> Option<u64> {
        let exponent = self.attempts.checked_sub(1)?.min(6);
        self.next_retry_turn
            .checked_sub(1u64.checked_shl(exponent)?)
    }

    /// Returns the next durable retry checkpoint using bounded exponential
    /// turn-based backoff. No wall-clock value enters deletion authority.
    #[allow(dead_code)]
    pub(crate) fn after_failure(
        self,
        current_turn: u64,
        category: BlobDeletionFailureCategory,
    ) -> Result<Self, StoreError> {
        let attempts = self
            .attempts
            .checked_add(1)
            .ok_or(StoreError::ItemCountAccountingOverflow)?;
        let exponent = attempts.saturating_sub(1).min(6);
        let delay = 1u64
            .checked_shl(exponent)
            .ok_or(StoreError::ItemCountAccountingOverflow)?;
        let next_retry_turn = current_turn
            .checked_add(delay)
            .ok_or(StoreError::ItemCountAccountingOverflow)?;
        Ok(Self {
            category: Some(category),
            attempts,
            next_retry_turn,
        })
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct BlobDeletionAge {
    pub(crate) cumulative_age_ms: u64,
    pub(crate) checkpoint: Option<CustodySample>,
    pub(crate) continuity_generation: u64,
    pub(crate) continuity_lost: bool,
}

impl BlobDeletionAge {
    fn validate(self) -> Result<(), StoreError> {
        match self.checkpoint {
            None if self.continuity_generation == 0 => Ok(()),
            None if self.continuity_lost => Ok(()),
            Some(_) if self.continuity_generation != 0 => Ok(()),
            _ => Err(invariant("Blob deletion age checkpoint is not canonical")),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct BlobDeletionContinuity {
    pub(crate) generation: u64,
    pub(crate) last_sample: CustodySample,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct BlobDeletionContinuityTransition {
    previous: BlobDeletionContinuity,
    anchor: CustodySample,
    after: Option<BlobVariantId>,
    remaining: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct BlobDeletionPendingContinuity {
    current: BlobDeletionContinuity,
    anchor: CustodySample,
    remaining: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct BlobDeletionContinuityState {
    /// Newest authority whose transition is actively checkpointing.
    current: BlobDeletionContinuity,
    /// Fixed membership moving from `previous` to `current`.
    transition: Option<BlobDeletionContinuityTransition>,
    /// At most one fixed next transition; further domains remain deferred.
    pending: Option<BlobDeletionPendingContinuity>,
    /// Exact unanchored rows admitted at the newest current/pending generation.
    /// These rows do not join either frozen membership.
    deferred: u64,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub(crate) struct BlobDeletionAgeMaintenanceProgress {
    pub(crate) rows_examined: u64,
    pub(crate) bytes_examined: u64,
    pub(crate) has_more: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct BlobDeletionTotals {
    pub(crate) chunks: u64,
    pub(crate) queued: u64,
    pub(crate) deleted: u64,
    pub(crate) charged_variants: u64,
    pub(crate) charged_files: u64,
    pub(crate) charged_reserved_bytes: u64,
    pub(crate) charged_committed_bytes: u64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct BlobDeletionChunk {
    pub(crate) index: u64,
    pub(crate) state: BlobDeletionChunkState,
    pub(crate) original_chunk: Vec<u8>,
    pub(crate) charged_reserved_bytes: u64,
    pub(crate) charged_committed_bytes: u64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct BlobDeletionManifest {
    pub(crate) variant_id: BlobVariantId,
    pub(crate) blob_id: BlobId,
    pub(crate) content_group: [u8; 32],
    pub(crate) epoch: u64,
    pub(crate) physical_lineage: [u8; 32],
    pub(crate) owner_binding: [u8; 32],
    pub(crate) lineage_fence: Vec<u8>,
    pub(crate) original_import: Vec<u8>,
    pub(crate) finalized_root: Option<[u8; 32]>,
    pub(crate) phase: BlobDeletionPhase,
    pub(crate) retry: BlobDeletionRetry,
    pub(crate) age: BlobDeletionAge,
    pub(crate) totals: BlobDeletionTotals,
    pub(crate) chunks: Vec<BlobDeletionChunk>,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub(crate) struct BlobDeletionStats {
    pub(crate) manifests: u64,
    pub(crate) manifest_bytes: u64,
    pub(crate) chunks: u64,
    pub(crate) chunk_bytes: u64,
    pub(crate) queued_chunks: u64,
    pub(crate) deleted_chunks: u64,
    pub(crate) charged_variants: u64,
    pub(crate) charged_files: u64,
    pub(crate) charged_reserved_bytes: u64,
    pub(crate) charged_committed_bytes: u64,
    pub(crate) maintenance_turn: u64,
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub(crate) struct BlobDeletionAudit {
    pub(crate) manifests: BTreeMap<BlobVariantId, BlobDeletionManifest>,
    pub(crate) stats: BlobDeletionStats,
}

impl BlobDeletionManifest {
    fn validate(&self) -> Result<(), StoreError> {
        if self.epoch == 0
            || self.variant_id
                != BlobVariantId::for_content(self.blob_id, &self.content_group, self.epoch)
            || self.owner_binding == [0; 32]
            || self.lineage_fence.is_empty()
            || self.lineage_fence.len() > MAX_LINEAGE_FENCE_EVIDENCE_BYTES
            || self.original_import.is_empty()
            || self.original_import.len() > MAX_IMPORT_EVIDENCE_BYTES
        {
            return Err(invariant(
                "Blob deletion manifest identity is not canonical",
            ));
        }
        self.retry.validate()?;
        self.age.validate()?;
        if self.totals.chunks > MAX_SELECTED_BLOB_CHUNKS
            || self.totals.charged_variants
                != u64::from(!super::pack_lifecycle::is_pack_evidence(
                    &self.original_import,
                ))
            || self.totals.charged_files > self.totals.chunks
            || self.totals.charged_committed_bytes > self.totals.charged_reserved_bytes
            || u64::try_from(self.chunks.len()).ok() != Some(self.totals.chunks)
            || (self.finalized_root.is_some()
                && !super::pack_lifecycle::is_pack_evidence(&self.original_import)
                && (self.totals.chunks == 0 || self.totals.charged_files != self.totals.chunks))
        {
            return Err(invariant("Blob deletion manifest totals are not canonical"));
        }
        let mut queued = 0u64;
        let mut deleted = 0u64;
        let mut charged_files = 0u64;
        let mut reserved_bytes = 0u64;
        let mut committed_bytes = 0u64;
        let mut previous_index = None;
        for chunk in &self.chunks {
            if previous_index.is_some_and(|previous| previous >= chunk.index)
                || chunk.original_chunk.is_empty()
                || chunk.original_chunk.len() > MAX_CHUNK_EVIDENCE_BYTES
                || chunk.charged_committed_bytes > chunk.charged_reserved_bytes
            {
                return Err(invariant("Blob deletion chunk is not canonical"));
            }
            previous_index = Some(chunk.index);
            match chunk.state {
                BlobDeletionChunkState::DeleteQueued => {
                    queued = queued
                        .checked_add(1)
                        .ok_or(StoreError::ItemCountAccountingOverflow)?;
                }
                BlobDeletionChunkState::DeletedDurable => {
                    deleted = deleted
                        .checked_add(1)
                        .ok_or(StoreError::ItemCountAccountingOverflow)?;
                }
            }
            charged_files = charged_files
                .checked_add(u64::from(chunk.charged_committed_bytes != 0))
                .ok_or(StoreError::ItemCountAccountingOverflow)?;
            reserved_bytes = reserved_bytes
                .checked_add(chunk.charged_reserved_bytes)
                .ok_or(StoreError::PayloadByteAccountingOverflow)?;
            committed_bytes = committed_bytes
                .checked_add(chunk.charged_committed_bytes)
                .ok_or(StoreError::PayloadByteAccountingOverflow)?;
        }
        if queued != self.totals.queued
            || deleted != self.totals.deleted
            || queued
                .checked_add(deleted)
                .ok_or(StoreError::ItemCountAccountingOverflow)?
                != self.totals.chunks
            || charged_files != self.totals.charged_files
            || reserved_bytes != self.totals.charged_reserved_bytes
            || committed_bytes != self.totals.charged_committed_bytes
            || (self.phase == BlobDeletionPhase::DirectoryDeletePending && queued != 0)
        {
            return Err(invariant(
                "Blob deletion phase and chunk totals do not agree",
            ));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct BlobDeletionManifestHeader {
    pub(crate) variant_id: BlobVariantId,
    pub(crate) blob_id: BlobId,
    pub(crate) content_group: [u8; 32],
    pub(crate) epoch: u64,
    pub(crate) physical_lineage: [u8; 32],
    pub(crate) owner_binding: [u8; 32],
    pub(crate) lineage_fence: Vec<u8>,
    pub(crate) original_import: Vec<u8>,
    pub(crate) finalized_root: Option<[u8; 32]>,
    pub(crate) phase: BlobDeletionPhase,
    pub(crate) retry: BlobDeletionRetry,
    pub(crate) age: BlobDeletionAge,
    pub(crate) totals: BlobDeletionTotals,
}

#[allow(dead_code)]
fn encode_manifest_record(manifest: &BlobDeletionManifest) -> Result<Vec<u8>, StoreError> {
    manifest.validate()?;
    encode_manifest_header(&BlobDeletionManifestHeader {
        variant_id: manifest.variant_id,
        blob_id: manifest.blob_id,
        content_group: manifest.content_group,
        epoch: manifest.epoch,
        physical_lineage: manifest.physical_lineage,
        owner_binding: manifest.owner_binding,
        lineage_fence: manifest.lineage_fence.clone(),
        original_import: manifest.original_import.clone(),
        finalized_root: manifest.finalized_root,
        phase: manifest.phase,
        retry: manifest.retry,
        age: manifest.age,
        totals: manifest.totals,
    })
}

fn encode_manifest_header(header: &BlobDeletionManifestHeader) -> Result<Vec<u8>, StoreError> {
    header.retry.validate()?;
    header.age.validate()?;
    if header.totals.chunks > MAX_SELECTED_BLOB_CHUNKS
        || header.totals.queued.checked_add(header.totals.deleted) != Some(header.totals.chunks)
    {
        return Err(invariant(
            "Blob deletion manifest header totals are not canonical",
        ));
    }
    let lineage_len = u16::try_from(header.lineage_fence.len())
        .map_err(|_| invariant("Blob deletion lineage evidence exceeds its bound"))?;
    let import_len = u32::try_from(header.original_import.len())
        .map_err(|_| invariant("Blob deletion import evidence exceeds its bound"))?;
    let capacity = MANIFEST_FIXED_BYTES
        .checked_add(header.lineage_fence.len())
        .and_then(|value| value.checked_add(header.original_import.len()))
        .ok_or(StoreError::PayloadByteAccountingOverflow)?;
    let mut output = Vec::with_capacity(capacity);
    output.push(MANIFEST_VERSION);
    output.push(header.phase.encode());
    output.extend_from_slice(&[0; 2]);
    output.extend_from_slice(header.variant_id.as_bytes());
    output.extend_from_slice(header.blob_id.as_bytes());
    output.extend_from_slice(&header.content_group);
    output.extend_from_slice(&header.epoch.to_be_bytes());
    output.extend_from_slice(&header.physical_lineage);
    output.extend_from_slice(&header.owner_binding);
    output.push(u8::from(header.finalized_root.is_some()));
    output.extend_from_slice(&[0; 3]);
    output.extend_from_slice(&header.finalized_root.unwrap_or([0; 32]));
    for value in [
        header.totals.chunks,
        header.totals.queued,
        header.totals.deleted,
        header.totals.charged_variants,
        header.totals.charged_files,
        header.totals.charged_reserved_bytes,
        header.totals.charged_committed_bytes,
    ] {
        output.extend_from_slice(&value.to_be_bytes());
    }
    output.push(
        header
            .retry
            .category
            .map_or(0, |category| category.encode()),
    );
    output.extend_from_slice(&[0; 3]);
    output.extend_from_slice(&header.retry.attempts.to_be_bytes());
    output.extend_from_slice(&header.retry.next_retry_turn.to_be_bytes());
    output.extend_from_slice(&header.age.cumulative_age_ms.to_be_bytes());
    output.push(u8::from(header.age.checkpoint.is_some()));
    output.push(u8::from(header.age.continuity_lost));
    output.extend_from_slice(&[0; 2]);
    output.extend_from_slice(&header.age.continuity_generation.to_be_bytes());
    if let Some(checkpoint) = header.age.checkpoint {
        output.extend_from_slice(&checkpoint.clock_id);
        output.extend_from_slice(&checkpoint.tick_ms.to_be_bytes());
    } else {
        output.extend_from_slice(&[0; 24]);
    }
    output.extend_from_slice(&lineage_len.to_be_bytes());
    output.extend_from_slice(&import_len.to_be_bytes());
    output.extend_from_slice(&header.lineage_fence);
    output.extend_from_slice(&header.original_import);
    debug_assert_eq!(output.len(), capacity);
    Ok(output)
}

#[allow(dead_code)]
fn encode_chunk_record(chunk: &BlobDeletionChunk) -> Result<Vec<u8>, StoreError> {
    if chunk.original_chunk.is_empty()
        || chunk.original_chunk.len() > MAX_CHUNK_EVIDENCE_BYTES
        || chunk.charged_committed_bytes > chunk.charged_reserved_bytes
    {
        return Err(invariant("Blob deletion chunk is not canonical"));
    }
    let evidence_len = u16::try_from(chunk.original_chunk.len())
        .map_err(|_| invariant("Blob deletion chunk evidence exceeds its bound"))?;
    let mut output = Vec::with_capacity(CHUNK_FIXED_BYTES + chunk.original_chunk.len());
    output.push(CHUNK_VERSION);
    output.push(chunk.state.encode());
    output.extend_from_slice(&[0; 2]);
    output.extend_from_slice(&chunk.index.to_be_bytes());
    output.extend_from_slice(&chunk.charged_reserved_bytes.to_be_bytes());
    output.extend_from_slice(&chunk.charged_committed_bytes.to_be_bytes());
    output.extend_from_slice(&evidence_len.to_be_bytes());
    output.extend_from_slice(&[0; 2]);
    output.extend_from_slice(&chunk.original_chunk);
    Ok(output)
}

struct SliceCursor<'a> {
    bytes: &'a [u8],
    offset: usize,
}

impl<'a> SliceCursor<'a> {
    const fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, offset: 0 }
    }

    fn take(&mut self, length: usize) -> Result<&'a [u8], StoreError> {
        let end = self
            .offset
            .checked_add(length)
            .ok_or(StoreError::PayloadByteAccountingOverflow)?;
        let output = self
            .bytes
            .get(self.offset..end)
            .ok_or_else(|| invariant("Blob deletion record is truncated"))?;
        self.offset = end;
        Ok(output)
    }

    fn u8(&mut self) -> Result<u8, StoreError> {
        Ok(self.take(1)?[0])
    }

    fn u16(&mut self) -> Result<u16, StoreError> {
        Ok(u16::from_be_bytes(self.take(2)?.try_into().map_err(
            |_| invariant("Blob deletion u16 is malformed"),
        )?))
    }

    fn u32(&mut self) -> Result<u32, StoreError> {
        Ok(u32::from_be_bytes(self.take(4)?.try_into().map_err(
            |_| invariant("Blob deletion u32 is malformed"),
        )?))
    }

    fn u64(&mut self) -> Result<u64, StoreError> {
        Ok(u64::from_be_bytes(self.take(8)?.try_into().map_err(
            |_| invariant("Blob deletion u64 is malformed"),
        )?))
    }

    fn array<const N: usize>(&mut self) -> Result<[u8; N], StoreError> {
        self.take(N)?
            .try_into()
            .map_err(|_| invariant("Blob deletion fixed field is malformed"))
    }

    fn finish(self) -> Result<(), StoreError> {
        if self.offset == self.bytes.len() {
            Ok(())
        } else {
            Err(invariant("Blob deletion record has trailing bytes"))
        }
    }
}

fn decode_manifest_header(bytes: &[u8]) -> Result<BlobDeletionManifestHeader, StoreError> {
    if bytes.len() < MANIFEST_FIXED_BYTES {
        return Err(invariant("Blob deletion manifest is truncated"));
    }
    let mut cursor = SliceCursor::new(bytes);
    if cursor.u8()? != MANIFEST_VERSION {
        return Err(invariant(
            "Blob deletion manifest has an unknown encoding version",
        ));
    }
    let phase = BlobDeletionPhase::decode(cursor.u8()?)?;
    if cursor.take(2)? != [0; 2] {
        return Err(invariant(
            "Blob deletion manifest reserved bytes are nonzero",
        ));
    }
    let variant_id = BlobVariantId::from_bytes(cursor.array()?);
    let blob_id = BlobId::from_bytes(cursor.array()?);
    let content_group = cursor.array()?;
    let epoch = cursor.u64()?;
    let physical_lineage = cursor.array()?;
    let owner_binding = cursor.array()?;
    let finalized_root_present = match cursor.u8()? {
        0 => false,
        1 => true,
        _ => return Err(invariant("Blob deletion root-presence flag is invalid")),
    };
    if cursor.take(3)? != [0; 3] {
        return Err(invariant("Blob deletion root reserved bytes are nonzero"));
    }
    let finalized_root_bytes = cursor.array()?;
    let finalized_root = if finalized_root_present {
        Some(finalized_root_bytes)
    } else {
        if finalized_root_bytes != [0; 32] {
            return Err(invariant(
                "Blob deletion absent root retains nonzero evidence",
            ));
        }
        None
    };
    let totals = BlobDeletionTotals {
        chunks: cursor.u64()?,
        queued: cursor.u64()?,
        deleted: cursor.u64()?,
        charged_variants: cursor.u64()?,
        charged_files: cursor.u64()?,
        charged_reserved_bytes: cursor.u64()?,
        charged_committed_bytes: cursor.u64()?,
    };
    if totals.chunks > MAX_SELECTED_BLOB_CHUNKS {
        return Err(invariant(
            "Blob deletion manifest chunk count exceeds its bound",
        ));
    }
    let category = BlobDeletionFailureCategory::decode(cursor.u8()?)?;
    if cursor.take(3)? != [0; 3] {
        return Err(invariant("Blob deletion retry reserved bytes are nonzero"));
    }
    let retry = BlobDeletionRetry {
        category,
        attempts: cursor.u32()?,
        next_retry_turn: cursor.u64()?,
    };
    retry.validate()?;
    let cumulative_age_ms = cursor.u64()?;
    let checkpoint_present = match cursor.u8()? {
        0 => false,
        1 => true,
        _ => return Err(invariant("Blob deletion age checkpoint flag is invalid")),
    };
    let continuity_lost = match cursor.u8()? {
        0 => false,
        1 => true,
        _ => return Err(invariant("Blob deletion continuity-loss flag is invalid")),
    };
    if cursor.take(2)? != [0; 2] {
        return Err(invariant("Blob deletion age reserved bytes are nonzero"));
    }
    let continuity_generation = cursor.u64()?;
    let checkpoint_clock = cursor.array()?;
    let checkpoint_tick = cursor.u64()?;
    let checkpoint = if checkpoint_present {
        Some(CustodySample {
            clock_id: checkpoint_clock,
            tick_ms: checkpoint_tick,
        })
    } else {
        if checkpoint_clock != [0; 16] || checkpoint_tick != 0 {
            return Err(invariant(
                "Blob deletion absent checkpoint retains nonzero fields",
            ));
        }
        None
    };
    let age = BlobDeletionAge {
        cumulative_age_ms,
        checkpoint,
        continuity_generation,
        continuity_lost,
    };
    age.validate()?;
    let lineage_len = usize::from(cursor.u16()?);
    let import_len = usize::try_from(cursor.u32()?)
        .map_err(|_| invariant("Blob deletion import length cannot be represented"))?;
    if lineage_len == 0
        || lineage_len > MAX_LINEAGE_FENCE_EVIDENCE_BYTES
        || import_len == 0
        || import_len > MAX_IMPORT_EVIDENCE_BYTES
    {
        return Err(invariant(
            "Blob deletion embedded evidence exceeds its bound",
        ));
    }
    let remaining = bytes
        .len()
        .checked_sub(cursor.offset)
        .ok_or_else(|| invariant("Blob deletion manifest length is invalid"))?;
    if remaining
        != lineage_len
            .checked_add(import_len)
            .ok_or(StoreError::PayloadByteAccountingOverflow)?
    {
        return Err(invariant(
            "Blob deletion embedded evidence length is not canonical",
        ));
    }
    let lineage_fence = cursor.take(lineage_len)?.to_vec();
    let original_import = cursor.take(import_len)?.to_vec();
    cursor.finish()?;
    Ok(BlobDeletionManifestHeader {
        variant_id,
        blob_id,
        content_group,
        epoch,
        physical_lineage,
        owner_binding,
        lineage_fence,
        original_import,
        finalized_root,
        phase,
        retry,
        age,
        totals,
    })
}

fn decode_chunk_record(bytes: &[u8]) -> Result<BlobDeletionChunk, StoreError> {
    if bytes.len() < CHUNK_FIXED_BYTES {
        return Err(invariant("Blob deletion chunk record is truncated"));
    }
    let mut cursor = SliceCursor::new(bytes);
    if cursor.u8()? != CHUNK_VERSION {
        return Err(invariant(
            "Blob deletion chunk has an unknown encoding version",
        ));
    }
    let state = BlobDeletionChunkState::decode(cursor.u8()?)?;
    if cursor.take(2)? != [0; 2] {
        return Err(invariant("Blob deletion chunk reserved bytes are nonzero"));
    }
    let index = cursor.u64()?;
    let charged_reserved_bytes = cursor.u64()?;
    let charged_committed_bytes = cursor.u64()?;
    let evidence_len = usize::from(cursor.u16()?);
    if cursor.take(2)? != [0; 2] {
        return Err(invariant(
            "Blob deletion chunk evidence reserved bytes are nonzero",
        ));
    }
    if evidence_len == 0 || evidence_len > MAX_CHUNK_EVIDENCE_BYTES {
        return Err(invariant("Blob deletion chunk evidence exceeds its bound"));
    }
    let original_chunk = cursor.take(evidence_len)?.to_vec();
    cursor.finish()?;
    let chunk = BlobDeletionChunk {
        index,
        state,
        original_chunk,
        charged_reserved_bytes,
        charged_committed_bytes,
    };
    if chunk.charged_committed_bytes > chunk.charged_reserved_bytes {
        return Err(invariant("Blob deletion chunk charge is not canonical"));
    }
    Ok(chunk)
}

fn decode_manifest_record(
    bytes: &[u8],
    encoded_chunks: &[Vec<u8>],
) -> Result<BlobDeletionManifest, StoreError> {
    let header = decode_manifest_header(bytes)?;
    if u64::try_from(encoded_chunks.len()).ok() != Some(header.totals.chunks) {
        return Err(invariant(
            "Blob deletion manifest chunk cardinality is incomplete",
        ));
    }
    let mut chunks = Vec::with_capacity(encoded_chunks.len());
    for encoded in encoded_chunks {
        chunks.push(decode_chunk_record(encoded)?);
    }
    let manifest = BlobDeletionManifest {
        variant_id: header.variant_id,
        blob_id: header.blob_id,
        content_group: header.content_group,
        epoch: header.epoch,
        physical_lineage: header.physical_lineage,
        owner_binding: header.owner_binding,
        lineage_fence: header.lineage_fence,
        original_import: header.original_import,
        finalized_root: header.finalized_root,
        phase: header.phase,
        retry: header.retry,
        age: header.age,
        totals: header.totals,
        chunks,
    };
    manifest.validate()?;
    Ok(manifest)
}

fn deletion_table_names() -> [&'static str; 4] {
    [
        BLOB_DELETION_METADATA.name(),
        BLOB_DELETION_MANIFESTS.name(),
        BLOB_DELETION_CHUNKS.name(),
        BLOB_DELETION_CONTINUITY.name(),
    ]
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum DeletionSchemaState {
    Predecessor,
    Current,
}

fn deletion_schema_state(
    normal: &BTreeSet<String>,
    multimap: &BTreeSet<String>,
) -> Result<DeletionSchemaState, StoreError> {
    let names = deletion_table_names();
    if multimap.iter().any(|name| names.contains(&name.as_str())) {
        return Err(invariant("Blob deletion schema has the wrong table kind"));
    }
    let present = names.iter().filter(|name| normal.contains(**name)).count();
    match present {
        0 => Ok(DeletionSchemaState::Predecessor),
        count if count == names.len() => Ok(DeletionSchemaState::Current),
        _ => Err(invariant("Blob deletion schema group is incomplete")),
    }
}

fn deletion_schema_state_write(
    write: &redb::WriteTransaction,
) -> Result<DeletionSchemaState, StoreError> {
    deletion_schema_state(
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

fn deletion_schema_state_read(
    read: &redb::ReadTransaction,
) -> Result<DeletionSchemaState, StoreError> {
    deletion_schema_state(
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

pub(crate) fn require_blob_deletion_absent_write(
    write: &redb::WriteTransaction,
) -> Result<(), StoreError> {
    if deletion_schema_state_write(write)? == DeletionSchemaState::Current {
        return Err(invariant(
            "Blob deletion authority exists without its base schema",
        ));
    }
    Ok(())
}

pub(crate) fn require_blob_deletion_absent_read(
    read: &redb::ReadTransaction,
) -> Result<(), StoreError> {
    if deletion_schema_state_read(read)? == DeletionSchemaState::Current {
        return Err(invariant(
            "Blob deletion authority exists without its base schema",
        ));
    }
    Ok(())
}

pub(crate) fn require_variant_available_read(
    read: &redb::ReadTransaction,
    variant: BlobVariantId,
) -> Result<(), StoreError> {
    let manifests = read.open_table(BLOB_DELETION_MANIFESTS)?;
    let Some(encoded) = manifests.get(variant.as_bytes().as_slice())? else {
        return Ok(());
    };
    let header = decode_manifest_header(encoded.value())?;
    if header.variant_id != variant {
        return Err(invariant(
            "Blob deletion manifest key differs from its identity",
        ));
    }
    Err(StoreError::Blob(BlobStoreError::VariantDeleting))
}

pub(crate) fn require_variant_available_write(
    write: &redb::WriteTransaction,
    variant: BlobVariantId,
) -> Result<(), StoreError> {
    let manifests = write.open_table(BLOB_DELETION_MANIFESTS)?;
    let Some(encoded) = manifests.get(variant.as_bytes().as_slice())? else {
        return Ok(());
    };
    let header = decode_manifest_header(encoded.value())?;
    if header.variant_id != variant {
        return Err(invariant(
            "Blob deletion manifest key differs from its identity",
        ));
    }
    Err(StoreError::Blob(BlobStoreError::VariantDeleting))
}

pub(crate) fn variant_has_deletion_manifest_read(
    read: &redb::ReadTransaction,
    variant: BlobVariantId,
) -> Result<bool, StoreError> {
    let manifests = read.open_table(BLOB_DELETION_MANIFESTS)?;
    let Some(encoded) = manifests.get(variant.as_bytes().as_slice())? else {
        return Ok(false);
    };
    if decode_manifest_header(encoded.value())?.variant_id != variant {
        return Err(invariant(
            "Blob deletion manifest key differs from its identity",
        ));
    }
    Ok(true)
}

pub(crate) fn variant_has_deletion_manifest_write(
    write: &redb::WriteTransaction,
    variant: BlobVariantId,
) -> Result<bool, StoreError> {
    let manifests = write.open_table(BLOB_DELETION_MANIFESTS)?;
    let Some(encoded) = manifests.get(variant.as_bytes().as_slice())? else {
        return Ok(false);
    };
    if decode_manifest_header(encoded.value())?.variant_id != variant {
        return Err(invariant(
            "Blob deletion manifest key differs from its identity",
        ));
    }
    Ok(true)
}

pub(crate) fn bounded_variant_has_deletion_manifest_write(
    write: &redb::WriteTransaction,
    variant: BlobVariantId,
    charge: &mut MaintenanceCharge,
) -> Result<Option<bool>, StoreError> {
    let manifests = write.open_table(BLOB_DELETION_MANIFESTS)?;
    let Some(encoded) = manifests.get(variant.as_bytes().as_slice())? else {
        return Ok(Some(false));
    };
    if !charge.charge(variant.as_bytes(), encoded.value().len())? {
        return Ok(None);
    }
    if decode_manifest_header(encoded.value())?.variant_id != variant {
        return Err(invariant(
            "Blob deletion manifest key differs from its identity",
        ));
    }
    Ok(Some(true))
}

#[cfg(test)]
pub(crate) fn set_manifest_admission_fault_ordinal_for_test(ordinal: Option<u64>) {
    TEST_MANIFEST_ADMISSION_FAULT_ORDINAL.set(ordinal);
    TEST_MANIFEST_ADMISSION_MUTATIONS.set(0);
}

#[cfg(test)]
pub(crate) fn manifest_admission_mutations_for_test() -> u64 {
    TEST_MANIFEST_ADMISSION_MUTATIONS.get()
}

#[cfg(test)]
pub(crate) fn set_manifest_admission_discovery_forbidden_for_test(forbidden: bool) {
    TEST_MANIFEST_ADMISSION_DISCOVERY_FORBIDDEN.set(forbidden);
}

fn manifest_admission_discovery_boundary() -> Result<(), StoreError> {
    #[cfg(test)]
    if TEST_MANIFEST_ADMISSION_DISCOVERY_FORBIDDEN.get() {
        return Err(invariant(
            "injected Blob manifest admission discovery failure",
        ));
    }
    Ok(())
}

pub(crate) fn begin_manifest_admission_mutations() {
    #[cfg(test)]
    TEST_MANIFEST_ADMISSION_MUTATIONS.set(0);
}

pub(crate) fn manifest_admission_mutation_boundary() -> Result<(), StoreError> {
    #[cfg(test)]
    {
        let ordinal = TEST_MANIFEST_ADMISSION_MUTATIONS
            .get()
            .checked_add(1)
            .ok_or(StoreError::ItemCountAccountingOverflow)?;
        TEST_MANIFEST_ADMISSION_MUTATIONS.set(ordinal);
        if TEST_MANIFEST_ADMISSION_FAULT_ORDINAL.get() == Some(ordinal) {
            return Err(invariant(
                "injected Blob manifest admission mutation failure",
            ));
        }
    }
    Ok(())
}

#[cfg(test)]
pub(crate) fn set_manifest_finalization_fault_ordinal_for_test(ordinal: Option<u64>) {
    TEST_MANIFEST_FINALIZATION_FAULT_ORDINAL.set(ordinal);
    TEST_MANIFEST_FINALIZATION_MUTATIONS.set(0);
}

#[cfg(test)]
pub(crate) fn manifest_finalization_mutations_for_test() -> u64 {
    TEST_MANIFEST_FINALIZATION_MUTATIONS.get()
}

pub(crate) fn begin_manifest_finalization_mutations() {
    #[cfg(test)]
    TEST_MANIFEST_FINALIZATION_MUTATIONS.set(0);
}

pub(crate) fn manifest_finalization_mutation_boundary() -> Result<(), StoreError> {
    #[cfg(test)]
    {
        let ordinal = TEST_MANIFEST_FINALIZATION_MUTATIONS
            .get()
            .checked_add(1)
            .ok_or(StoreError::ItemCountAccountingOverflow)?;
        TEST_MANIFEST_FINALIZATION_MUTATIONS.set(ordinal);
        if TEST_MANIFEST_FINALIZATION_FAULT_ORDINAL.get() == Some(ordinal) {
            return Err(invariant(
                "injected Blob manifest finalization mutation failure",
            ));
        }
    }
    Ok(())
}

fn require_admission_accounting(
    write: &redb::WriteTransaction,
) -> Result<BlobDeletionStats, StoreError> {
    let metadata = write.open_table(BLOB_DELETION_METADATA)?;
    if metadata.len()? != DELETION_METADATA_FIELDS.len() as u64
        || required_deletion_counter(&metadata, BLOB_DELETION_SCHEMA_VERSION_FIELD)?
            != BLOB_DELETION_SCHEMA_VERSION
    {
        return Err(invariant(
            "Blob deletion metadata is incomplete or has an unknown version",
        ));
    }
    let stats = BlobDeletionStats {
        manifests: required_deletion_counter(&metadata, BLOB_DELETION_MANIFEST_ROWS)?,
        manifest_bytes: required_deletion_counter(&metadata, BLOB_DELETION_MANIFEST_BYTES)?,
        chunks: required_deletion_counter(&metadata, BLOB_DELETION_CHUNK_ROWS)?,
        chunk_bytes: required_deletion_counter(&metadata, BLOB_DELETION_CHUNK_BYTES)?,
        queued_chunks: required_deletion_counter(&metadata, BLOB_DELETION_QUEUED_CHUNKS)?,
        deleted_chunks: required_deletion_counter(&metadata, BLOB_DELETION_DELETED_CHUNKS)?,
        charged_variants: required_deletion_counter(&metadata, BLOB_DELETION_CHARGED_VARIANTS)?,
        charged_files: required_deletion_counter(&metadata, BLOB_DELETION_CHARGED_FILES)?,
        charged_reserved_bytes: required_deletion_counter(
            &metadata,
            BLOB_DELETION_CHARGED_RESERVED_BYTES,
        )?,
        charged_committed_bytes: required_deletion_counter(
            &metadata,
            BLOB_DELETION_CHARGED_COMMITTED_BYTES,
        )?,
        maintenance_turn: required_deletion_counter(&metadata, BLOB_DELETION_MAINTENANCE_TURN)?,
    };
    if write.open_table(BLOB_DELETION_MANIFESTS)?.len()? != stats.manifests
        || write.open_table(BLOB_DELETION_CHUNKS)?.len()? != stats.chunks
    {
        return Err(invariant(
            "Blob deletion table cardinality disagrees with durable accounting",
        ));
    }
    Ok(stats)
}

/// Atomically replaces one exact variant's ordinary chunk authority with its
/// durable deletion-manifest authority. The caller owns the surrounding write
/// transaction, the depot coordination lock, and the provisional lease fence.
fn charge_pressure_admission_row(
    charge: &mut Option<&mut MaintenanceCharge>,
    key: &[u8],
    value_len: usize,
) -> Result<bool, StoreError> {
    match charge.as_deref_mut() {
        Some(charge) => charge.charge(key, value_len),
        None => Ok(true),
    }
}

#[derive(Debug)]
struct BlobDeletionAdmissionChunkPlan {
    key: [u8; 40],
    expected_active: Vec<u8>,
    encoded_deletion: Vec<u8>,
}

/// An owned, transaction-local admission plan. Every discovered byte needed
/// by apply is retained here, so applying the plan performs point mutations
/// only and never repeats range discovery or record decoding.
#[derive(Debug)]
pub(crate) struct BlobDeletionAdmissionPlan {
    variant: BlobVariantId,
    chunks: Vec<BlobDeletionAdmissionChunkPlan>,
    pack_active: Option<Vec<u8>>,
    encoded_manifest: Vec<u8>,
    encoded_continuity: Option<Vec<u8>>,
    metadata_updates: Vec<(&'static str, u64)>,
}

pub(crate) fn plan_variant_admission_write(
    write: &redb::WriteTransaction,
    variant: BlobVariantId,
    expected_import: &[u8],
    expected_lineage: &[u8],
    owner_binding: [u8; 32],
    custody_sample: Option<CustodySample>,
    mut pressure_charge: Option<&mut MaintenanceCharge>,
) -> Result<Option<BlobDeletionAdmissionPlan>, StoreError> {
    manifest_admission_discovery_boundary()?;
    if let Some(reference) = super::upload::pending_pack_reference(
        &write.open_table(super::upload::BLOB_UPLOAD_PACK_REFERENCES)?,
        variant,
    )? {
        let _ = charge_pressure_admission_row(&mut pressure_charge, &reference, 0)?;
        return Ok(None);
    }
    for field in DELETION_METADATA_FIELDS {
        if !charge_pressure_admission_row(
            &mut pressure_charge,
            field.as_bytes(),
            std::mem::size_of::<u64>(),
        )? {
            return Ok(None);
        }
    }
    let existing_stats = require_admission_accounting(write)?;
    let manifests = write.open_table(BLOB_DELETION_MANIFESTS)?;
    if let Some(encoded) = manifests.get(variant.as_bytes().as_slice())? {
        if !charge_pressure_admission_row(
            &mut pressure_charge,
            variant.as_bytes(),
            encoded.value().len(),
        )? {
            return Ok(None);
        }
        if decode_manifest_header(encoded.value())?.variant_id != variant {
            return Err(invariant(
                "Blob deletion manifest key differs from its identity",
            ));
        }
        return Ok(None);
    }
    drop(manifests);
    let pack_active = if super::pack_lifecycle::is_pack_evidence(expected_import) {
        let encoded = super::pack_lifecycle::encoded_active_write(write, variant)?
            .ok_or_else(|| invariant("Blob pack manifest admission authority is missing"))?;
        if !charge_pressure_admission_row(&mut pressure_charge, variant.as_bytes(), encoded.len())?
        {
            return Ok(None);
        }
        Some(encoded)
    } else {
        None
    };
    let original_import = if let Some(encoded) = pack_active.as_ref() {
        encoded.clone()
    } else {
        let imports = write.open_table(super::BLOB_IMPORTS)?;
        let original_import = imports
            .get(variant.as_bytes().as_slice())?
            .ok_or_else(|| invariant("Blob manifest admission import is missing"))?;
        if !charge_pressure_admission_row(
            &mut pressure_charge,
            variant.as_bytes(),
            original_import.value().len(),
        )? {
            return Ok(None);
        }
        original_import.value().to_vec()
    };
    if original_import != expected_import {
        return Err(invariant(
            "Blob manifest admission import changed after discovery",
        ));
    }
    let import = super::depot::deletion_import_projection(variant.as_bytes(), &original_import)?;
    for field in [
        super::DEPOT_OWNER_BINDING_0,
        super::DEPOT_OWNER_BINDING_1,
        super::DEPOT_OWNER_BINDING_2,
        super::DEPOT_OWNER_BINDING_3,
    ] {
        if !charge_pressure_admission_row(
            &mut pressure_charge,
            field.as_bytes(),
            std::mem::size_of::<u64>(),
        )? {
            return Ok(None);
        }
    }
    let actual_owner = super::depot::depot_owner_binding_if_present_write(write)?
        .ok_or_else(|| invariant("Blob manifest admission owner binding is missing"))?;
    if actual_owner != owner_binding {
        return Err(invariant("Blob manifest admission owner binding changed"));
    }
    let lineage_fences = write.open_table(super::lifecycle::BLOB_LINEAGE_FENCES)?;
    let lineage_fence = lineage_fences
        .get(variant.as_bytes().as_slice())?
        .ok_or_else(|| invariant("Blob manifest admission lineage fence is missing"))?;
    if !charge_pressure_admission_row(
        &mut pressure_charge,
        variant.as_bytes(),
        lineage_fence.value().len(),
    )? {
        return Ok(None);
    }
    let encoded_lineage_fence = lineage_fence.value().to_vec();
    drop(lineage_fence);
    drop(lineage_fences);
    let lineage_fence = encoded_lineage_fence;
    if lineage_fence != expected_lineage {
        return Err(invariant(
            "Blob manifest admission lineage changed after discovery",
        ));
    }
    super::lifecycle::validate_maintenance_lineage_evidence(
        import.physical_lineage,
        owner_binding,
        &lineage_fence,
    )?;

    let first = chunk_key(variant, 0);
    let last = chunk_key(variant, u64::MAX);
    if let Some(row) = write
        .open_table(BLOB_DELETION_CHUNKS)?
        .range::<&[u8]>((
            std::ops::Bound::Included(first.as_slice()),
            std::ops::Bound::Included(last.as_slice()),
        ))?
        .next()
        .transpose()?
    {
        let (key, value) = row;
        if !charge_pressure_admission_row(&mut pressure_charge, key.value(), value.value().len())? {
            return Ok(None);
        }
        return Err(invariant(
            "Blob manifest admission found pre-existing deletion chunk authority",
        ));
    }
    let active_chunks = write.open_table(super::BLOB_CHUNKS)?;
    let mut originals = Vec::new();
    for row in active_chunks.range::<&[u8]>((
        std::ops::Bound::Included(first.as_slice()),
        std::ops::Bound::Included(last.as_slice()),
    ))? {
        let (key, value) = row?;
        if !charge_pressure_admission_row(&mut pressure_charge, key.value(), value.value().len())? {
            return Ok(None);
        }
        let (actual_variant, index) = parse_chunk_key(key.value())?;
        if actual_variant != variant {
            return Err(invariant(
                "Blob manifest admission chunk range escaped its variant",
            ));
        }
        if u64::try_from(originals.len()).ok() == Some(MAX_SELECTED_BLOB_CHUNKS) {
            return Err(invariant(
                "Blob manifest admission chunk set exceeds its structural bound",
            ));
        }
        originals.push((index, value.value().to_vec()));
    }
    drop(active_chunks);

    let mut chunks = Vec::with_capacity(originals.len());
    let mut queued = 0u64;
    let mut deleted = 0u64;
    let mut charged_files = 0u64;
    let mut charged_reserved_bytes = 0u64;
    let mut charged_committed_bytes = 0u64;
    let mut committed_records = Vec::new();
    for (index, original_chunk) in &originals {
        let projected =
            super::depot::deletion_chunk_projection(&original_import, *index, original_chunk)?;
        if !charge_pressure_admission_row(
            &mut pressure_charge,
            chunk_key(variant, *index).as_slice(),
            original_chunk.len(),
        )? {
            return Ok(None);
        }
        let encoded_chunk_len = CHUNK_FIXED_BYTES
            .checked_add(original_chunk.len())
            .ok_or(StoreError::PayloadByteAccountingOverflow)?;
        if !charge_pressure_admission_row(
            &mut pressure_charge,
            chunk_key(variant, *index).as_slice(),
            encoded_chunk_len,
        )? {
            return Ok(None);
        }
        charged_reserved_bytes = charged_reserved_bytes
            .checked_add(projected.charged_reserved_bytes)
            .ok_or(StoreError::PayloadByteAccountingOverflow)?;
        charged_committed_bytes = charged_committed_bytes
            .checked_add(projected.charged_committed_bytes)
            .ok_or(StoreError::PayloadByteAccountingOverflow)?;
        let state = if let Some(record) = projected.record {
            queued = queued
                .checked_add(1)
                .ok_or(StoreError::ItemCountAccountingOverflow)?;
            charged_files = charged_files
                .checked_add(1)
                .ok_or(StoreError::ItemCountAccountingOverflow)?;
            committed_records.push(record);
            BlobDeletionChunkState::DeleteQueued
        } else {
            deleted = deleted
                .checked_add(1)
                .ok_or(StoreError::ItemCountAccountingOverflow)?;
            BlobDeletionChunkState::DeletedDurable
        };
        chunks.push(BlobDeletionChunk {
            index: *index,
            state,
            original_chunk: original_chunk.clone(),
            charged_reserved_bytes: projected.charged_reserved_bytes,
            charged_committed_bytes: projected.charged_committed_bytes,
        });
    }
    if import.finalized_root.is_some()
        && u64::try_from(chunks.len()).ok() != Some(import.chunk_count)
    {
        return Err(invariant(
            "finalized Blob manifest admission has an incomplete chunk set",
        ));
    }
    super::depot::validate_deletion_manifest_root(
        &original_import,
        &committed_records,
        import.finalized_root,
    )?;
    let chunk_count =
        u64::try_from(chunks.len()).map_err(|_| StoreError::ItemCountAccountingOverflow)?;
    let continuity = write.open_table(BLOB_DELETION_CONTINUITY)?;
    let encoded_continuity_before = match continuity.get(CONTINUITY_KEY)? {
        Some(encoded) => {
            if !charge_pressure_admission_row(
                &mut pressure_charge,
                &[CONTINUITY_KEY],
                encoded.value().len(),
            )? {
                return Ok(None);
            }
            Some(encoded.value().to_vec())
        }
        None => None,
    };
    drop(continuity);
    let previous_continuity = encoded_continuity_before
        .as_deref()
        .map(decode_continuity_state)
        .transpose()?;
    let (observed_continuity, initial_age) = match custody_sample {
        Some(sample) => {
            let (state, observed) = project_observed_blob_deletion_continuity(
                previous_continuity,
                sample,
                existing_stats.manifests,
            )?;
            let age = if observed.last_sample.clock_id == sample.clock_id
                && observed.last_sample.tick_ms == sample.tick_ms
            {
                BlobDeletionAge {
                    cumulative_age_ms: 0,
                    checkpoint: Some(sample),
                    continuity_generation: observed.generation,
                    continuity_lost: false,
                }
            } else {
                BlobDeletionAge {
                    cumulative_age_ms: 0,
                    checkpoint: None,
                    continuity_generation: observed.generation,
                    continuity_lost: true,
                }
            };
            (Some(state), age)
        }
        None => {
            let continuity = previous_continuity.map(newest_blob_deletion_continuity);
            (
                previous_continuity,
                BlobDeletionAge {
                    cumulative_age_ms: 0,
                    checkpoint: None,
                    continuity_generation: continuity.map_or(0, |continuity| continuity.generation),
                    continuity_lost: continuity.is_some(),
                },
            )
        }
    };
    let encoded_manifest_len = MANIFEST_FIXED_BYTES
        .checked_add(lineage_fence.len())
        .and_then(|length| length.checked_add(original_import.len()))
        .ok_or(StoreError::PayloadByteAccountingOverflow)?;
    if !charge_pressure_admission_row(
        &mut pressure_charge,
        variant.as_bytes(),
        encoded_manifest_len,
    )? {
        return Ok(None);
    }
    let manifest = BlobDeletionManifest {
        variant_id: variant,
        blob_id: import.blob_id,
        content_group: import.content_group,
        epoch: import.epoch,
        physical_lineage: import.physical_lineage,
        owner_binding,
        lineage_fence,
        original_import,
        finalized_root: import.finalized_root,
        phase: BlobDeletionPhase::DeletingChunks,
        retry: BlobDeletionRetry::default(),
        age: initial_age,
        totals: BlobDeletionTotals {
            chunks: chunk_count,
            queued,
            deleted,
            charged_variants: u64::from(pack_active.is_none()),
            charged_files,
            charged_reserved_bytes,
            charged_committed_bytes,
        },
        chunks,
    };
    manifest.validate()?;
    let encoded_manifest = encode_manifest_record(&manifest)?;
    if encoded_manifest.len() != encoded_manifest_len {
        return Err(invariant(
            "Blob deletion manifest encoding differs from its planned length",
        ));
    }
    let encoded_chunks = manifest
        .chunks
        .iter()
        .map(encode_chunk_record)
        .collect::<Result<Vec<_>, _>>()?;
    let manifest_bytes = encoded_row_bytes(variant.as_bytes(), &encoded_manifest)?;
    let mut chunk_bytes = 0u64;
    for (chunk, encoded) in manifest.chunks.iter().zip(&encoded_chunks) {
        chunk_bytes = chunk_bytes
            .checked_add(encoded_row_bytes(
                &chunk_key(variant, chunk.index),
                encoded,
            )?)
            .ok_or(StoreError::PayloadByteAccountingOverflow)?;
    }
    let admitted_continuity =
        project_admitted_manifest_in_continuity_transition(observed_continuity, manifest.age)?;
    let encoded_continuity = if admitted_continuity != previous_continuity {
        let state = admitted_continuity.ok_or_else(|| {
            invariant("Blob manifest admission removed deletion continuity authority")
        })?;
        let encoded_len = continuity_state_encoded_len(state)?;
        if !charge_pressure_admission_row(&mut pressure_charge, &[CONTINUITY_KEY], encoded_len)? {
            return Ok(None);
        }
        let encoded = encode_continuity_state(state)?;
        if encoded.len() != encoded_len {
            return Err(invariant(
                "Blob deletion continuity encoding differs from its planned length",
            ));
        }
        Some(encoded)
    } else {
        None
    };
    let count_updates = [
        (
            BLOB_DELETION_MANIFEST_ROWS,
            existing_stats
                .manifests
                .checked_add(1)
                .ok_or(StoreError::ItemCountAccountingOverflow)?,
        ),
        (
            BLOB_DELETION_CHUNK_ROWS,
            existing_stats
                .chunks
                .checked_add(chunk_count)
                .ok_or(StoreError::ItemCountAccountingOverflow)?,
        ),
        (
            BLOB_DELETION_QUEUED_CHUNKS,
            existing_stats
                .queued_chunks
                .checked_add(queued)
                .ok_or(StoreError::ItemCountAccountingOverflow)?,
        ),
        (
            BLOB_DELETION_DELETED_CHUNKS,
            existing_stats
                .deleted_chunks
                .checked_add(deleted)
                .ok_or(StoreError::ItemCountAccountingOverflow)?,
        ),
        (
            BLOB_DELETION_CHARGED_VARIANTS,
            existing_stats
                .charged_variants
                .checked_add(manifest.totals.charged_variants)
                .ok_or(StoreError::ItemCountAccountingOverflow)?,
        ),
        (
            BLOB_DELETION_CHARGED_FILES,
            existing_stats
                .charged_files
                .checked_add(charged_files)
                .ok_or(StoreError::ItemCountAccountingOverflow)?,
        ),
    ];
    let byte_updates = [
        (
            BLOB_DELETION_MANIFEST_BYTES,
            existing_stats
                .manifest_bytes
                .checked_add(manifest_bytes)
                .ok_or(StoreError::PayloadByteAccountingOverflow)?,
        ),
        (
            BLOB_DELETION_CHUNK_BYTES,
            existing_stats
                .chunk_bytes
                .checked_add(chunk_bytes)
                .ok_or(StoreError::PayloadByteAccountingOverflow)?,
        ),
        (
            BLOB_DELETION_CHARGED_RESERVED_BYTES,
            existing_stats
                .charged_reserved_bytes
                .checked_add(charged_reserved_bytes)
                .ok_or(StoreError::PayloadByteAccountingOverflow)?,
        ),
        (
            BLOB_DELETION_CHARGED_COMMITTED_BYTES,
            existing_stats
                .charged_committed_bytes
                .checked_add(charged_committed_bytes)
                .ok_or(StoreError::PayloadByteAccountingOverflow)?,
        ),
    ];
    for (field, _) in count_updates.iter().chain(byte_updates.iter()) {
        if !charge_pressure_admission_row(
            &mut pressure_charge,
            field.as_bytes(),
            std::mem::size_of::<u64>(),
        )? {
            return Ok(None);
        }
    }
    let mut metadata_updates = Vec::with_capacity(10);
    metadata_updates.extend(count_updates);
    metadata_updates.extend(byte_updates);
    let chunks = originals
        .into_iter()
        .zip(encoded_chunks)
        .map(
            |((index, expected_active), encoded_deletion)| BlobDeletionAdmissionChunkPlan {
                key: chunk_key(variant, index),
                expected_active,
                encoded_deletion,
            },
        )
        .collect();
    Ok(Some(BlobDeletionAdmissionPlan {
        variant,
        chunks,
        pack_active,
        encoded_manifest,
        encoded_continuity,
        metadata_updates,
    }))
}

pub(crate) fn apply_variant_admission_plan_write(
    write: &redb::WriteTransaction,
    plan: BlobDeletionAdmissionPlan,
) -> Result<(), StoreError> {
    begin_manifest_admission_mutations();
    if let Some(expected) = plan.pack_active.as_deref() {
        super::pack_lifecycle::mark_deletion_pending_write(write, plan.variant, expected)?;
        manifest_admission_mutation_boundary()?;
    }
    let mut active_chunks = write.open_table(super::BLOB_CHUNKS)?;
    for chunk in &plan.chunks {
        let removed = active_chunks
            .remove(chunk.key.as_slice())?
            .ok_or_else(|| invariant("Blob manifest admission lost ordinary chunk authority"))?;
        if removed.value() != chunk.expected_active.as_slice() {
            return Err(invariant(
                "Blob manifest admission ordinary chunk changed after planning",
            ));
        }
        manifest_admission_mutation_boundary()?;
    }
    drop(active_chunks);
    write.open_table(BLOB_DELETION_MANIFESTS)?.insert(
        plan.variant.as_bytes().as_slice(),
        plan.encoded_manifest.as_slice(),
    )?;
    if let Some(encoded) = &plan.encoded_continuity {
        write
            .open_table(BLOB_DELETION_CONTINUITY)?
            .insert(CONTINUITY_KEY, encoded.as_slice())?;
    }
    manifest_admission_mutation_boundary()?;
    let mut deletion_chunks = write.open_table(BLOB_DELETION_CHUNKS)?;
    for chunk in &plan.chunks {
        deletion_chunks.insert(chunk.key.as_slice(), chunk.encoded_deletion.as_slice())?;
        manifest_admission_mutation_boundary()?;
    }
    drop(deletion_chunks);
    let mut metadata = write.open_table(BLOB_DELETION_METADATA)?;
    for (field, value) in plan.metadata_updates {
        metadata.insert(field, value)?;
        manifest_admission_mutation_boundary()?;
    }
    Ok(())
}

pub(crate) fn admit_variant_write(
    write: &redb::WriteTransaction,
    variant: BlobVariantId,
    expected_import: &[u8],
    expected_lineage: &[u8],
    owner_binding: [u8; 32],
    custody_sample: Option<CustodySample>,
) -> Result<bool, StoreError> {
    let Some(plan) = plan_variant_admission_write(
        write,
        variant,
        expected_import,
        expected_lineage,
        owner_binding,
        custody_sample,
        None,
    )?
    else {
        return Ok(false);
    };
    apply_variant_admission_plan_write(write, plan)?;
    Ok(true)
}

fn initialize_blob_deletion_schema(write: &redb::WriteTransaction) -> Result<(), StoreError> {
    let _ = write.open_table(BLOB_DELETION_MANIFESTS)?;
    let _ = write.open_table(BLOB_DELETION_CHUNKS)?;
    let _ = write.open_table(BLOB_DELETION_CONTINUITY)?;
    let mut metadata = write.open_table(BLOB_DELETION_METADATA)?;
    if metadata.len()? != 0 {
        return Err(invariant(
            "Blob deletion metadata exists during empty migration",
        ));
    }
    for (field, value) in DELETION_METADATA_FIELDS.into_iter().zip([
        BLOB_DELETION_SCHEMA_VERSION,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
    ]) {
        metadata.insert(field, value)?;
    }
    Ok(())
}

/// Advances the durable sequence exactly once for a caller-owned bounded
/// maintenance turn. Later maintenance tasks use the returned value for
/// retry eligibility and never derive it from wall-clock time.
#[allow(dead_code)]
pub(crate) fn advance_blob_deletion_maintenance_turn(
    write: &redb::WriteTransaction,
) -> Result<u64, StoreError> {
    if deletion_schema_state_write(write)? != DeletionSchemaState::Current {
        return Err(invariant("Blob deletion schema is not current"));
    }
    let mut metadata = write.open_table(BLOB_DELETION_METADATA)?;
    if metadata.len()? != DELETION_METADATA_FIELDS.len() as u64
        || metadata
            .get(BLOB_DELETION_SCHEMA_VERSION_FIELD)?
            .map(|value| value.value())
            != Some(BLOB_DELETION_SCHEMA_VERSION)
    {
        return Err(invariant(
            "Blob deletion metadata is incomplete or has an unknown version",
        ));
    }
    let current = metadata
        .get(BLOB_DELETION_MAINTENANCE_TURN)?
        .ok_or_else(|| invariant("Blob deletion maintenance turn is missing"))?
        .value();
    let next = current
        .checked_add(1)
        .ok_or(StoreError::ItemCountAccountingOverflow)?;
    metadata.insert(BLOB_DELETION_MAINTENANCE_TURN, next)?;
    Ok(next)
}

fn audit_metadata(
    metadata: &impl ReadableTable<&'static str, u64>,
    stats: BlobDeletionStats,
) -> Result<(), StoreError> {
    if metadata.len()? != DELETION_METADATA_FIELDS.len() as u64 {
        return Err(invariant("Blob deletion accounting metadata is incomplete"));
    }
    for (field, expected) in [
        (
            BLOB_DELETION_SCHEMA_VERSION_FIELD,
            BLOB_DELETION_SCHEMA_VERSION,
        ),
        (BLOB_DELETION_MAINTENANCE_TURN, stats.maintenance_turn),
        (BLOB_DELETION_MANIFEST_ROWS, stats.manifests),
        (BLOB_DELETION_MANIFEST_BYTES, stats.manifest_bytes),
        (BLOB_DELETION_CHUNK_ROWS, stats.chunks),
        (BLOB_DELETION_CHUNK_BYTES, stats.chunk_bytes),
        (BLOB_DELETION_QUEUED_CHUNKS, stats.queued_chunks),
        (BLOB_DELETION_DELETED_CHUNKS, stats.deleted_chunks),
        (BLOB_DELETION_CHARGED_VARIANTS, stats.charged_variants),
        (BLOB_DELETION_CHARGED_FILES, stats.charged_files),
        (
            BLOB_DELETION_CHARGED_RESERVED_BYTES,
            stats.charged_reserved_bytes,
        ),
        (
            BLOB_DELETION_CHARGED_COMMITTED_BYTES,
            stats.charged_committed_bytes,
        ),
    ] {
        if metadata.get(field)?.map(|value| value.value()) != Some(expected) {
            return Err(invariant(
                "Blob deletion accounting metadata disagrees with durable rows",
            ));
        }
    }
    Ok(())
}

fn encoded_row_bytes(key: &[u8], value: &[u8]) -> Result<u64, StoreError> {
    key.len()
        .checked_add(value.len())
        .and_then(|length| u64::try_from(length).ok())
        .ok_or(StoreError::PayloadByteAccountingOverflow)
}

#[derive(Clone, Copy)]
struct BlobDeletionAllocationBounds {
    manifest_rows: u64,
    manifest_bytes: u64,
    chunk_rows: u64,
    chunk_bytes: u64,
}

fn required_deletion_counter(
    metadata: &impl ReadableTable<&'static str, u64>,
    field: &'static str,
) -> Result<u64, StoreError> {
    metadata
        .get(field)?
        .map(|value| value.value())
        .ok_or_else(|| invariant("Blob deletion accounting metadata is incomplete"))
}

fn preflight_allocation_bounds(
    metadata: &impl ReadableTable<&'static str, u64>,
    manifests: &impl ReadableTable<&'static [u8], &'static [u8]>,
    deletion_chunks: &impl ReadableTable<&'static [u8], &'static [u8]>,
    imports: &impl ReadableTable<&'static [u8], &'static [u8]>,
    packs: &impl ReadableTable<&'static [u8], &'static [u8]>,
) -> Result<BlobDeletionAllocationBounds, StoreError> {
    if metadata.len()? != DELETION_METADATA_FIELDS.len() as u64
        || required_deletion_counter(metadata, BLOB_DELETION_SCHEMA_VERSION_FIELD)?
            != BLOB_DELETION_SCHEMA_VERSION
    {
        return Err(invariant(
            "Blob deletion metadata is incomplete or has an unknown version",
        ));
    }
    let bounds = BlobDeletionAllocationBounds {
        manifest_rows: required_deletion_counter(metadata, BLOB_DELETION_MANIFEST_ROWS)?,
        manifest_bytes: required_deletion_counter(metadata, BLOB_DELETION_MANIFEST_BYTES)?,
        chunk_rows: required_deletion_counter(metadata, BLOB_DELETION_CHUNK_ROWS)?,
        chunk_bytes: required_deletion_counter(metadata, BLOB_DELETION_CHUNK_BYTES)?,
    };
    if manifests.len()? != bounds.manifest_rows || deletion_chunks.len()? != bounds.chunk_rows {
        return Err(invariant(
            "Blob deletion table cardinality disagrees with durable accounting",
        ));
    }
    let mut deletion_pack_rows = 0u64;
    let mut deletion_pack_manifest_bytes = 0u64;
    for row in packs.iter()? {
        let (key, value) = row?;
        if let Some((variant, evidence_len)) =
            super::pack_lifecycle::deletion_pending_projection(value.value())?
        {
            if key.value() != variant.as_bytes() {
                return Err(invariant("Blob deletion pack key is not canonical"));
            }
            deletion_pack_rows = deletion_pack_rows
                .checked_add(1)
                .ok_or(StoreError::ItemCountAccountingOverflow)?;
            deletion_pack_manifest_bytes = deletion_pack_manifest_bytes
                .checked_add(
                    u64::try_from(
                        32usize
                            .checked_add(MANIFEST_FIXED_BYTES)
                            .and_then(|bytes| bytes.checked_add(MAX_LINEAGE_FENCE_EVIDENCE_BYTES))
                            .and_then(|bytes| bytes.checked_add(evidence_len))
                            .ok_or(StoreError::PayloadByteAccountingOverflow)?,
                    )
                    .map_err(|_| StoreError::PayloadByteAccountingOverflow)?,
                )
                .ok_or(StoreError::PayloadByteAccountingOverflow)?;
        }
    }
    if bounds.manifest_rows
        > imports
            .len()?
            .checked_add(deletion_pack_rows)
            .ok_or(StoreError::ItemCountAccountingOverflow)?
    {
        return Err(invariant(
            "Blob deletion manifest rows exceed their exact import bound",
        ));
    }

    let mut max_manifest_bytes = 0u64;
    let mut max_chunk_rows = 0u64;
    for row in imports.iter()? {
        let (key, value) = row?;
        let import = super::depot::deletion_import_projection(key.value(), value.value())?;
        max_manifest_bytes = max_manifest_bytes
            .checked_add(
                u64::try_from(
                    32usize
                        .checked_add(MANIFEST_FIXED_BYTES)
                        .and_then(|bytes| bytes.checked_add(MAX_LINEAGE_FENCE_EVIDENCE_BYTES))
                        .and_then(|bytes| bytes.checked_add(value.value().len()))
                        .ok_or(StoreError::PayloadByteAccountingOverflow)?,
                )
                .map_err(|_| StoreError::PayloadByteAccountingOverflow)?,
            )
            .ok_or(StoreError::PayloadByteAccountingOverflow)?;
        max_chunk_rows = max_chunk_rows
            .checked_add(import.chunk_count)
            .ok_or(StoreError::ItemCountAccountingOverflow)?;
    }
    max_manifest_bytes = max_manifest_bytes
        .checked_add(deletion_pack_manifest_bytes)
        .ok_or(StoreError::PayloadByteAccountingOverflow)?;
    if bounds.manifest_bytes > max_manifest_bytes {
        return Err(invariant(
            "Blob deletion manifest bytes exceed their exact import bound",
        ));
    }
    if bounds.chunk_rows > max_chunk_rows {
        return Err(invariant(
            "Blob deletion chunk rows exceed their exact import bound",
        ));
    }
    let max_chunk_bytes = max_chunk_rows
        .checked_mul(
            u64::try_from(40 + CHUNK_FIXED_BYTES + MAX_CHUNK_EVIDENCE_BYTES)
                .map_err(|_| StoreError::PayloadByteAccountingOverflow)?,
        )
        .ok_or(StoreError::PayloadByteAccountingOverflow)?;
    if bounds.chunk_bytes > max_chunk_bytes {
        return Err(invariant(
            "Blob deletion chunk bytes exceed their exact import bound",
        ));
    }
    Ok(bounds)
}

fn parse_variant_key(bytes: &[u8]) -> Result<BlobVariantId, StoreError> {
    Ok(BlobVariantId::from_bytes(bytes.try_into().map_err(
        |_| invariant("Blob deletion manifest variant key has invalid length"),
    )?))
}

fn parse_chunk_key(bytes: &[u8]) -> Result<(BlobVariantId, u64), StoreError> {
    if bytes.len() != 40 {
        return Err(invariant("Blob deletion chunk key has invalid length"));
    }
    let variant = BlobVariantId::from_bytes(
        bytes[..32]
            .try_into()
            .map_err(|_| invariant("Blob deletion chunk variant key is malformed"))?,
    );
    let index = u64::from_be_bytes(
        bytes[32..]
            .try_into()
            .map_err(|_| invariant("Blob deletion chunk index key is malformed"))?,
    );
    Ok((variant, index))
}

#[allow(dead_code)]
fn chunk_key(variant: BlobVariantId, index: u64) -> [u8; 40] {
    let mut key = [0u8; 40];
    key[..32].copy_from_slice(variant.as_bytes());
    key[32..].copy_from_slice(&index.to_be_bytes());
    key
}

#[allow(clippy::too_many_arguments)]
fn audit_blob_deletion_rows(
    metadata: &impl ReadableTable<&'static str, u64>,
    manifests: &impl ReadableTable<&'static [u8], &'static [u8]>,
    deletion_chunks: &impl ReadableTable<&'static [u8], &'static [u8]>,
    continuity: &impl ReadableTable<u8, &'static [u8]>,
    imports: &impl ReadableTable<&'static [u8], &'static [u8]>,
    packs: &impl ReadableTable<&'static [u8], &'static [u8]>,
    active_chunks: &impl ReadableTable<&'static [u8], &'static [u8]>,
    variant_references: &impl ReadableTable<&'static [u8], &'static [u8]>,
    lineage_fences: &impl ReadableTable<&'static [u8], &'static [u8]>,
    owner_binding: Option<[u8; 32]>,
) -> Result<BlobDeletionAudit, StoreError> {
    let allocation =
        preflight_allocation_bounds(metadata, manifests, deletion_chunks, imports, packs)?;
    let continuity_state = audited_continuity_state(continuity)?;
    let maintenance_turn = metadata
        .get(BLOB_DELETION_MAINTENANCE_TURN)?
        .map(|value| value.value())
        .ok_or_else(|| invariant("Blob deletion maintenance turn is missing"))?;
    let mut headers = BTreeMap::<BlobVariantId, BlobDeletionManifestHeader>::new();
    let mut manifest_rows = 0u64;
    let mut manifest_bytes = 0u64;
    let mut transition_remaining = 0u64;
    let mut pending_remaining = 0u64;
    let mut deferred = 0u64;
    for row in manifests.iter()? {
        let (key, value) = row?;
        manifest_rows = manifest_rows
            .checked_add(1)
            .ok_or(StoreError::ItemCountAccountingOverflow)?;
        manifest_bytes = manifest_bytes
            .checked_add(encoded_row_bytes(key.value(), value.value())?)
            .ok_or(StoreError::PayloadByteAccountingOverflow)?;
        if manifest_rows > allocation.manifest_rows || manifest_bytes > allocation.manifest_bytes {
            return Err(invariant(
                "Blob deletion manifest rows exceed their durable allocation bound",
            ));
        }
        let variant = parse_variant_key(key.value())?;
        let header = decode_manifest_header(value.value())?;
        validate_age_against_continuity(header.age, continuity_state)?;
        if header.variant_id != variant || headers.contains_key(&variant) {
            return Err(invariant(
                "Blob deletion manifest key differs from its exact variant",
            ));
        }
        if owner_binding != Some(header.owner_binding) {
            return Err(invariant(
                "Blob deletion manifest owner binding is unavailable or mismatched",
            ));
        }
        if let Some(state) = continuity_state
            && let Some(transition) = state.transition
            && header.age.continuity_generation < state.current.generation
        {
            if transition.after.is_some_and(|after| variant <= after) {
                return Err(invariant(
                    "Blob deletion continuity position precedes an uncheckpointed manifest",
                ));
            }
            transition_remaining = transition_remaining
                .checked_add(1)
                .ok_or(StoreError::ItemCountAccountingOverflow)?;
        }
        if let Some(state) = continuity_state
            && let Some(pending) = state.pending
            && header.age.continuity_generation < pending.current.generation
        {
            pending_remaining = pending_remaining
                .checked_add(1)
                .ok_or(StoreError::ItemCountAccountingOverflow)?;
        }
        if let Some(state) = continuity_state {
            let newest_generation = state.pending.map_or(state.current.generation, |pending| {
                pending.current.generation
            });
            if header.age.checkpoint.is_none()
                && header.age.continuity_generation == newest_generation
            {
                if header.age.cumulative_age_ms != 0 {
                    return Err(invariant("Blob deletion deferred age is not canonical"));
                }
                deferred = deferred
                    .checked_add(1)
                    .ok_or(StoreError::ItemCountAccountingOverflow)?;
            }
        }
        headers.insert(variant, header);
    }
    if let Some(state) = continuity_state
        && let Some(transition) = state.transition
        && transition_remaining != transition.remaining
    {
        return Err(invariant(
            "Blob deletion continuity remaining count is not exact",
        ));
    }
    if let Some(state) = continuity_state
        && let Some(pending) = state.pending
        && pending_remaining != pending.remaining
    {
        return Err(invariant(
            "Blob deletion pending continuity remaining count is not exact",
        ));
    }
    if let Some(state) = continuity_state
        && deferred != state.deferred
    {
        return Err(invariant(
            "Blob deletion deferred continuity count is not exact",
        ));
    }

    for row in variant_references.iter()? {
        let (key, value) = row?;
        if key.value().len() != 65 || !value.value().is_empty() {
            return Err(invariant("Blob variant reference is not canonical"));
        }
        let variant = BlobVariantId::from_bytes(
            key.value()[..32]
                .try_into()
                .map_err(|_| invariant("Blob variant reference key is malformed"))?,
        );
        if headers.contains_key(&variant) {
            return Err(invariant(
                "Blob deletion manifest retains a live variant reference",
            ));
        }
    }

    for row in active_chunks.iter()? {
        let (key, _) = row?;
        if key.value().len() == 40 {
            let (variant, _) = parse_chunk_key(key.value())?;
            if headers.contains_key(&variant) {
                return Err(invariant(
                    "Blob variant has duplicate active and deletion chunk authority",
                ));
            }
        }
    }

    let mut grouped_chunks = BTreeMap::<BlobVariantId, Vec<BlobDeletionChunk>>::new();
    let mut chunk_rows = 0u64;
    let mut chunk_bytes = 0u64;
    for row in deletion_chunks.iter()? {
        let (key, value) = row?;
        chunk_rows = chunk_rows
            .checked_add(1)
            .ok_or(StoreError::ItemCountAccountingOverflow)?;
        chunk_bytes = chunk_bytes
            .checked_add(encoded_row_bytes(key.value(), value.value())?)
            .ok_or(StoreError::PayloadByteAccountingOverflow)?;
        if chunk_rows > allocation.chunk_rows || chunk_bytes > allocation.chunk_bytes {
            return Err(invariant(
                "Blob deletion chunk rows exceed their durable allocation bound",
            ));
        }
        let (variant, index) = parse_chunk_key(key.value())?;
        let expected_chunks = headers
            .get(&variant)
            .ok_or_else(|| invariant("Blob deletion chunk references a missing manifest"))?
            .totals
            .chunks;
        let grouped = grouped_chunks.entry(variant).or_default();
        let grouped_len =
            u64::try_from(grouped.len()).map_err(|_| StoreError::ItemCountAccountingOverflow)?;
        if grouped_len >= expected_chunks {
            return Err(invariant(
                "Blob deletion chunk rows exceed their manifest bound",
            ));
        }
        let chunk = decode_chunk_record(value.value())?;
        if chunk.index != index {
            return Err(invariant(
                "Blob deletion chunk key differs from its retained index",
            ));
        }
        grouped.push(chunk);
    }

    let mut audited = BlobDeletionAudit {
        manifests: BTreeMap::new(),
        stats: BlobDeletionStats {
            manifest_bytes,
            chunk_bytes,
            maintenance_turn,
            ..BlobDeletionStats::default()
        },
    };
    for (variant, header) in headers {
        let import_bytes = if super::pack_lifecycle::is_pack_evidence(&header.original_import) {
            let pack = packs
                .get(variant.as_bytes().as_slice())?
                .ok_or_else(|| invariant("Blob deletion manifest pack is missing"))?;
            super::pack_lifecycle::validate_deletion_pending(
                pack.value(),
                &header.original_import,
            )?;
            header.original_import.clone()
        } else {
            let import = imports
                .get(variant.as_bytes().as_slice())?
                .ok_or_else(|| invariant("Blob deletion manifest import is missing"))?;
            if import.value() != header.original_import.as_slice() {
                return Err(invariant(
                    "Blob deletion manifest import evidence is not exact",
                ));
            }
            import.value().to_vec()
        };
        let import_projection =
            super::depot::deletion_import_projection(variant.as_bytes(), &import_bytes)?;
        if import_projection.variant_id != variant
            || import_projection.blob_id != header.blob_id
            || import_projection.content_group != header.content_group
            || import_projection.epoch != header.epoch
            || import_projection.physical_lineage != header.physical_lineage
            || import_projection.finalized_root != header.finalized_root
            || header.totals.chunks > import_projection.chunk_count
        {
            return Err(invariant(
                "Blob deletion manifest differs from its exact import",
            ));
        }
        let lineage = lineage_fences
            .get(variant.as_bytes().as_slice())?
            .ok_or_else(|| invariant("Blob deletion manifest lineage fence is missing"))?;
        if lineage.value() != header.lineage_fence.as_slice() {
            return Err(invariant(
                "Blob deletion manifest lineage evidence is not exact",
            ));
        }
        super::lifecycle::validate_maintenance_lineage_evidence(
            header.physical_lineage,
            header.owner_binding,
            lineage.value(),
        )?;

        let chunks = grouped_chunks.remove(&variant).unwrap_or_default();
        if u64::try_from(chunks.len()).ok() != Some(header.totals.chunks) {
            return Err(invariant("Blob deletion manifest chunk set is incomplete"));
        }
        let manifest = BlobDeletionManifest {
            variant_id: header.variant_id,
            blob_id: header.blob_id,
            content_group: header.content_group,
            epoch: header.epoch,
            physical_lineage: header.physical_lineage,
            owner_binding: header.owner_binding,
            lineage_fence: header.lineage_fence,
            original_import: header.original_import,
            finalized_root: header.finalized_root,
            phase: header.phase,
            retry: header.retry,
            age: header.age,
            totals: header.totals,
            chunks,
        };
        manifest.validate()?;
        let mut records = Vec::with_capacity(manifest.chunks.len());
        for chunk in &manifest.chunks {
            let projected = super::depot::deletion_chunk_projection(
                &manifest.original_import,
                chunk.index,
                &chunk.original_chunk,
            )?;
            if projected.charged_reserved_bytes != chunk.charged_reserved_bytes
                || projected.charged_committed_bytes != chunk.charged_committed_bytes
            {
                return Err(invariant(
                    "Blob deletion chunk charge differs from its original row",
                ));
            }
            if let Some(record) = projected.record {
                records.push(record);
            }
        }
        super::depot::validate_deletion_manifest_root(
            &manifest.original_import,
            &records,
            manifest.finalized_root,
        )?;
        audited.stats.manifests = audited
            .stats
            .manifests
            .checked_add(1)
            .ok_or(StoreError::ItemCountAccountingOverflow)?;
        audited.stats.chunks = audited
            .stats
            .chunks
            .checked_add(manifest.totals.chunks)
            .ok_or(StoreError::ItemCountAccountingOverflow)?;
        audited.stats.queued_chunks = audited
            .stats
            .queued_chunks
            .checked_add(manifest.totals.queued)
            .ok_or(StoreError::ItemCountAccountingOverflow)?;
        audited.stats.deleted_chunks = audited
            .stats
            .deleted_chunks
            .checked_add(manifest.totals.deleted)
            .ok_or(StoreError::ItemCountAccountingOverflow)?;
        audited.stats.charged_variants = audited
            .stats
            .charged_variants
            .checked_add(manifest.totals.charged_variants)
            .ok_or(StoreError::ItemCountAccountingOverflow)?;
        audited.stats.charged_files = audited
            .stats
            .charged_files
            .checked_add(manifest.totals.charged_files)
            .ok_or(StoreError::ItemCountAccountingOverflow)?;
        audited.stats.charged_reserved_bytes = audited
            .stats
            .charged_reserved_bytes
            .checked_add(manifest.totals.charged_reserved_bytes)
            .ok_or(StoreError::PayloadByteAccountingOverflow)?;
        audited.stats.charged_committed_bytes = audited
            .stats
            .charged_committed_bytes
            .checked_add(manifest.totals.charged_committed_bytes)
            .ok_or(StoreError::PayloadByteAccountingOverflow)?;
        audited.manifests.insert(variant, manifest);
    }
    if !grouped_chunks.is_empty() {
        return Err(invariant(
            "Blob deletion chunk set contains orphan variant rows",
        ));
    }
    audit_metadata(metadata, audited.stats)?;
    Ok(audited)
}

pub(crate) fn audit_blob_deletion_write(
    write: &redb::WriteTransaction,
    owner_binding: Option<[u8; 32]>,
) -> Result<BlobDeletionAudit, StoreError> {
    let metadata = write.open_table(BLOB_DELETION_METADATA)?;
    let manifests = write.open_table(BLOB_DELETION_MANIFESTS)?;
    let chunks = write.open_table(BLOB_DELETION_CHUNKS)?;
    let continuity = write.open_table(BLOB_DELETION_CONTINUITY)?;
    if manifests.is_empty()? && chunks.is_empty()? {
        let maintenance_turn = metadata
            .get(BLOB_DELETION_MAINTENANCE_TURN)?
            .map(|value| value.value())
            .ok_or_else(|| invariant("Blob deletion maintenance turn is missing"))?;
        let audit = BlobDeletionAudit {
            manifests: BTreeMap::new(),
            stats: BlobDeletionStats {
                maintenance_turn,
                ..BlobDeletionStats::default()
            },
        };
        audit_metadata(&metadata, audit.stats)?;
        audit_continuity_table(&continuity)?;
        return Ok(audit);
    }
    audit_blob_deletion_rows(
        &metadata,
        &manifests,
        &chunks,
        &continuity,
        &write.open_table(super::BLOB_IMPORTS)?,
        &write.open_table(super::pack_lifecycle::BLOB_PROFILE5_PACKS)?,
        &write.open_table(super::BLOB_CHUNKS)?,
        &write.open_table(super::lifecycle::BLOB_VARIANT_REFERENCES)?,
        &write.open_table(super::lifecycle::BLOB_LINEAGE_FENCES)?,
        owner_binding,
    )
}

pub(crate) fn audit_blob_deletion_read(
    read: &redb::ReadTransaction,
    owner_binding: Option<[u8; 32]>,
) -> Result<BlobDeletionAudit, StoreError> {
    let metadata = read.open_table(BLOB_DELETION_METADATA)?;
    let manifests = read.open_table(BLOB_DELETION_MANIFESTS)?;
    let chunks = read.open_table(BLOB_DELETION_CHUNKS)?;
    let continuity = read.open_table(BLOB_DELETION_CONTINUITY)?;
    if manifests.is_empty()? && chunks.is_empty()? {
        let maintenance_turn = metadata
            .get(BLOB_DELETION_MAINTENANCE_TURN)?
            .map(|value| value.value())
            .ok_or_else(|| invariant("Blob deletion maintenance turn is missing"))?;
        let audit = BlobDeletionAudit {
            manifests: BTreeMap::new(),
            stats: BlobDeletionStats {
                maintenance_turn,
                ..BlobDeletionStats::default()
            },
        };
        audit_metadata(&metadata, audit.stats)?;
        audit_continuity_table(&continuity)?;
        return Ok(audit);
    }
    audit_blob_deletion_rows(
        &metadata,
        &manifests,
        &chunks,
        &continuity,
        &read.open_table(super::BLOB_IMPORTS)?,
        &read.open_table(super::pack_lifecycle::BLOB_PROFILE5_PACKS)?,
        &read.open_table(super::BLOB_CHUNKS)?,
        &read.open_table(super::lifecycle::BLOB_VARIANT_REFERENCES)?,
        &read.open_table(super::lifecycle::BLOB_LINEAGE_FENCES)?,
        owner_binding,
    )
}

/// Creates only an empty deletion authority when wholly absent. Existing
/// current state is audited and is never repaired.
pub(crate) fn audit_or_migrate_blob_deletion_write(
    write: &redb::WriteTransaction,
    owner_binding: Option<[u8; 32]>,
) -> Result<(bool, BlobDeletionAudit), StoreError> {
    match deletion_schema_state_write(write)? {
        DeletionSchemaState::Predecessor => {
            initialize_blob_deletion_schema(write)?;
            Ok((true, audit_blob_deletion_write(write, owner_binding)?))
        }
        DeletionSchemaState::Current => {
            Ok((false, audit_blob_deletion_write(write, owner_binding)?))
        }
    }
}

pub(crate) fn inspect_blob_deletion_read(
    read: &redb::ReadTransaction,
    owner_binding: Option<[u8; 32]>,
) -> Result<BlobDeletionAudit, StoreError> {
    match deletion_schema_state_read(read)? {
        DeletionSchemaState::Predecessor => Ok(BlobDeletionAudit::default()),
        DeletionSchemaState::Current => audit_blob_deletion_read(read, owner_binding),
    }
}

#[cfg(test)]
fn set_metadata_for_test(
    metadata: &mut redb::Table<'_, &str, u64>,
    field: &'static str,
    value: u64,
) -> Result<(), StoreError> {
    metadata.insert(field, value)?;
    Ok(())
}

fn load_manifest_write(
    write: &redb::WriteTransaction,
    variant: BlobVariantId,
) -> Result<BlobDeletionManifest, StoreError> {
    let manifests = write.open_table(BLOB_DELETION_MANIFESTS)?;
    let encoded_manifest = manifests
        .get(variant.as_bytes().as_slice())?
        .ok_or_else(|| invariant("Blob deletion manifest is missing"))?
        .value()
        .to_vec();
    drop(manifests);
    let first = chunk_key(variant, 0);
    let last = chunk_key(variant, u64::MAX);
    let chunks = write.open_table(BLOB_DELETION_CHUNKS)?;
    let mut encoded_chunks = Vec::new();
    for row in chunks.range::<&[u8]>((
        std::ops::Bound::Included(first.as_slice()),
        std::ops::Bound::Included(last.as_slice()),
    ))? {
        let (_, value) = row?;
        encoded_chunks.push(value.value().to_vec());
    }
    decode_manifest_record(&encoded_manifest, &encoded_chunks)
}

fn manifest_header(manifest: &BlobDeletionManifest) -> BlobDeletionManifestHeader {
    BlobDeletionManifestHeader {
        variant_id: manifest.variant_id,
        blob_id: manifest.blob_id,
        content_group: manifest.content_group,
        epoch: manifest.epoch,
        physical_lineage: manifest.physical_lineage,
        owner_binding: manifest.owner_binding,
        lineage_fence: manifest.lineage_fence.clone(),
        original_import: manifest.original_import.clone(),
        finalized_root: manifest.finalized_root,
        phase: manifest.phase,
        retry: manifest.retry,
        age: manifest.age,
        totals: manifest.totals,
    }
}

fn load_manifest_header_write(
    write: &redb::WriteTransaction,
    variant: BlobVariantId,
) -> Result<BlobDeletionManifestHeader, StoreError> {
    let manifests = write.open_table(BLOB_DELETION_MANIFESTS)?;
    let value = manifests
        .get(variant.as_bytes().as_slice())?
        .ok_or_else(|| invariant("Blob deletion manifest is missing"))?;
    decode_manifest_header(value.value())
}

fn load_chunk_write(
    write: &redb::WriteTransaction,
    variant: BlobVariantId,
    index: u64,
) -> Result<BlobDeletionChunk, StoreError> {
    let key = chunk_key(variant, index);
    let chunks = write.open_table(BLOB_DELETION_CHUNKS)?;
    let value = chunks
        .get(key.as_slice())?
        .ok_or_else(|| invariant("Blob deletion chunk is missing"))?;
    let chunk = decode_chunk_record(value.value())?;
    if chunk.index != index {
        return Err(invariant(
            "Blob deletion chunk key differs from its identity",
        ));
    }
    Ok(chunk)
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum BlobDeletionWorkKind {
    Chunk(BlobDeletionChunk),
    ReconcileUnmarkedChunk(BlobDeletionChunk),
    AdvanceDirectoryPhase,
    RemoveDirectoryAndFinalize,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct BlobDeletionWork {
    pub(crate) manifest: BlobDeletionManifestHeader,
    pub(crate) kind: BlobDeletionWorkKind,
    pub(crate) position: Vec<u8>,
    pub(crate) rows_examined: u64,
    pub(crate) bytes_examined: u64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum BlobDeletionSelection {
    Work(Box<BlobDeletionWork>),
    Continue {
        position: Option<Vec<u8>>,
        rows_examined: u64,
        bytes_examined: u64,
    },
    Complete {
        rows_examined: u64,
        bytes_examined: u64,
    },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum BlobDeletionPosition {
    Start,
    ManifestWork(BlobVariantId),
    ChunkAfter(BlobVariantId, u64),
    ChunkResume(BlobVariantId, u64),
    ManifestResume(BlobVariantId),
}

fn deletion_position_start(position: Option<&[u8]>) -> Result<BlobDeletionPosition, StoreError> {
    let Some(position) = position else {
        return Ok(BlobDeletionPosition::Start);
    };
    match position {
        [1, variant @ ..] if variant.len() == 32 => Ok(BlobDeletionPosition::ManifestWork(
            BlobVariantId::from_bytes(
                variant
                    .try_into()
                    .map_err(|_| invariant("Blob deletion manifest cursor is malformed"))?,
            ),
        )),
        [2, rest @ ..] if rest.len() == 40 => Ok(BlobDeletionPosition::ChunkAfter(
            BlobVariantId::from_bytes(
                rest[..32]
                    .try_into()
                    .map_err(|_| invariant("Blob deletion chunk cursor variant is malformed"))?,
            ),
            u64::from_be_bytes(
                rest[32..]
                    .try_into()
                    .map_err(|_| invariant("Blob deletion chunk cursor index is malformed"))?,
            ),
        )),
        [3, rest @ ..] if rest.len() == 40 => Ok(BlobDeletionPosition::ChunkResume(
            BlobVariantId::from_bytes(
                rest[..32]
                    .try_into()
                    .map_err(|_| invariant("Blob deletion resume cursor variant is malformed"))?,
            ),
            u64::from_be_bytes(
                rest[32..]
                    .try_into()
                    .map_err(|_| invariant("Blob deletion resume cursor index is malformed"))?,
            ),
        )),
        [4, variant @ ..] if variant.len() == 32 => Ok(BlobDeletionPosition::ManifestResume(
            BlobVariantId::from_bytes(
                variant
                    .try_into()
                    .map_err(|_| invariant("Blob deletion manifest resume cursor is malformed"))?,
            ),
        )),
        _ => Err(invariant("Blob deletion maintenance cursor is malformed")),
    }
}

/// Selects one exact structurally bounded manifest unit. The row/byte budget
/// applies to discovery evidence; finalization remains one atomic exact-
/// manifest transaction as required by the deletion protocol.
pub(crate) fn select_physical_work_read(
    read: &redb::ReadTransaction,
    position: Option<&[u8]>,
    rows_budget: u64,
    bytes_budget: u64,
) -> Result<BlobDeletionSelection, StoreError> {
    select_physical_work_read_inner(read, None, position, rows_budget, bytes_budget)
}

/// Selects physical work only for one previously admitted exact manifest.
/// Missing or retry-delayed authority stops this pass; it never falls through
/// to another manifest in the global deletion order.
pub(crate) fn select_exact_physical_work_read(
    read: &redb::ReadTransaction,
    variant: BlobVariantId,
    position: Option<&[u8]>,
    rows_budget: u64,
    bytes_budget: u64,
) -> Result<BlobDeletionSelection, StoreError> {
    select_physical_work_read_inner(read, Some(variant), position, rows_budget, bytes_budget)
}

fn select_physical_work_read_inner(
    read: &redb::ReadTransaction,
    exact_variant: Option<BlobVariantId>,
    position: Option<&[u8]>,
    rows_budget: u64,
    bytes_budget: u64,
) -> Result<BlobDeletionSelection, StoreError> {
    reset_discovery_observation();
    let start = deletion_position_start(position)?;
    let start_variant = match start {
        BlobDeletionPosition::Start => None,
        BlobDeletionPosition::ManifestWork(variant)
        | BlobDeletionPosition::ChunkAfter(variant, _)
        | BlobDeletionPosition::ChunkResume(variant, _)
        | BlobDeletionPosition::ManifestResume(variant) => Some(variant),
    };
    if let (Some(exact), Some(position_variant)) = (exact_variant, start_variant)
        && exact != position_variant
    {
        return Err(invariant(
            "Exact Blob deletion cursor belongs to another variant",
        ));
    }
    let turn = read
        .open_table(BLOB_DELETION_METADATA)?
        .get(BLOB_DELETION_MAINTENANCE_TURN)?
        .ok_or_else(|| invariant("Blob deletion maintenance turn is missing"))?
        .value();
    let manifests = read.open_table(BLOB_DELETION_MANIFESTS)?;
    let mut selected = None;
    let range_start = start_variant.or(exact_variant);
    let lower = range_start
        .as_ref()
        .map_or(std::ops::Bound::Unbounded, |variant| match start {
            BlobDeletionPosition::ManifestResume(_) => {
                std::ops::Bound::Excluded(variant.as_bytes().as_slice())
            }
            _ => std::ops::Bound::Included(variant.as_bytes().as_slice()),
        });
    let upper = exact_variant
        .as_ref()
        .map_or(std::ops::Bound::Unbounded, |variant| {
            std::ops::Bound::Included(variant.as_bytes().as_slice())
        });
    let mut rows_examined = 0u64;
    let mut bytes_examined = 0u64;
    let mut last_scanned = None;
    let mut exhausted_budget = false;
    let mut manifest_rows = manifests.range::<&[u8]>((lower, upper))?;
    loop {
        if rows_examined >= rows_budget
            || bytes_examined
                .checked_add(MAX_MANIFEST_ROW_BYTES)
                .ok_or(StoreError::PayloadByteAccountingOverflow)?
                > bytes_budget
        {
            exhausted_budget = true;
            break;
        }
        let Some(row) = manifest_rows.next() else {
            break;
        };
        let (key, value) = row?;
        let variant = parse_variant_key(key.value())?;
        if exact_variant.is_some_and(|exact| exact != variant) {
            return Err(invariant(
                "Exact Blob deletion selection escaped its variant",
            ));
        }
        let header = decode_manifest_header(value.value())?;
        if header.variant_id != variant {
            return Err(invariant(
                "Blob deletion manifest key differs from its identity",
            ));
        }
        let row_bytes = encoded_row_bytes(key.value(), value.value())?;
        observe_discovery_row(row_bytes);
        rows_examined = rows_examined
            .checked_add(1)
            .ok_or(StoreError::ItemCountAccountingOverflow)?;
        bytes_examined = bytes_examined
            .checked_add(row_bytes)
            .ok_or(StoreError::PayloadByteAccountingOverflow)?;
        if header.retry.category.is_some() && header.retry.next_retry_turn > turn.saturating_add(1)
        {
            last_scanned =
                Some(super::lifecycle::deletion_manifest_cursor_position(variant).to_vec());
            continue;
        }
        last_scanned = Some(super::lifecycle::deletion_manifest_resume_position(variant).to_vec());
        selected = Some((variant, header));
        break;
    }
    drop(manifests);
    let Some((variant, manifest)) = selected else {
        return if exhausted_budget {
            Ok(BlobDeletionSelection::Continue {
                position: last_scanned,
                rows_examined,
                bytes_examined,
            })
        } else {
            Ok(BlobDeletionSelection::Complete {
                rows_examined,
                bytes_examined,
            })
        };
    };
    let same_chunk_cursor = match start {
        BlobDeletionPosition::ChunkAfter(start, index)
        | BlobDeletionPosition::ChunkResume(start, index)
            if start == variant =>
        {
            Some(index)
        }
        _ => None,
    };
    let inclusive_chunk_cursor = matches!(
        start,
        BlobDeletionPosition::ChunkResume(start, _) if start == variant
    );
    let retry_same_chunk = manifest.retry.category.is_some() && same_chunk_cursor.is_some();
    let kind = match manifest.phase {
        BlobDeletionPhase::DeletingChunks => {
            let mut selected_chunk = None;
            let first = chunk_key(variant, same_chunk_cursor.unwrap_or(0));
            let last = chunk_key(variant, u64::MAX);
            let lower = if retry_same_chunk || inclusive_chunk_cursor || same_chunk_cursor.is_none()
            {
                std::ops::Bound::Included(first.as_slice())
            } else {
                std::ops::Bound::Excluded(first.as_slice())
            };
            let mut next_index =
                if retry_same_chunk || inclusive_chunk_cursor || same_chunk_cursor.is_none() {
                    same_chunk_cursor.unwrap_or(0)
                } else {
                    same_chunk_cursor
                        .unwrap_or(0)
                        .checked_add(1)
                        .ok_or(StoreError::ItemCountAccountingOverflow)?
                };
            let chunks = read.open_table(BLOB_DELETION_CHUNKS)?;
            let mut chunk_rows =
                chunks.range::<&[u8]>((lower, std::ops::Bound::Included(last.as_slice())))?;
            loop {
                if rows_examined >= rows_budget
                    || bytes_examined
                        .checked_add(MAX_CHUNK_ROW_BYTES)
                        .ok_or(StoreError::PayloadByteAccountingOverflow)?
                        > bytes_budget
                {
                    return Ok(BlobDeletionSelection::Continue {
                        position: Some(
                            super::lifecycle::deletion_chunk_resume_position(variant, next_index)
                                .to_vec(),
                        ),
                        rows_examined,
                        bytes_examined,
                    });
                }
                let Some(row) = chunk_rows.next() else {
                    break;
                };
                let (key, value) = row?;
                let (chunk_variant, index) = parse_chunk_key(key.value())?;
                if chunk_variant != variant {
                    return Err(invariant("Blob deletion chunk range escaped its variant"));
                }
                let row_bytes = encoded_row_bytes(key.value(), value.value())?;
                observe_discovery_row(row_bytes);
                rows_examined = rows_examined
                    .checked_add(1)
                    .ok_or(StoreError::ItemCountAccountingOverflow)?;
                bytes_examined = bytes_examined
                    .checked_add(row_bytes)
                    .ok_or(StoreError::PayloadByteAccountingOverflow)?;
                let chunk = decode_chunk_record(value.value())?;
                if chunk.index != index {
                    return Err(invariant(
                        "Blob deletion chunk key differs from its identity",
                    ));
                }
                last_scanned =
                    Some(super::lifecycle::deletion_chunk_cursor_position(variant, index).to_vec());
                next_index = index
                    .checked_add(1)
                    .ok_or(StoreError::ItemCountAccountingOverflow)?;
                let projection = super::depot::deletion_chunk_projection(
                    &manifest.original_import,
                    chunk.index,
                    &chunk.original_chunk,
                )?;
                if chunk.state == BlobDeletionChunkState::DeleteQueued {
                    selected_chunk = Some(BlobDeletionWorkKind::Chunk(chunk));
                    break;
                }
                if projection.record.is_none() {
                    selected_chunk = Some(BlobDeletionWorkKind::ReconcileUnmarkedChunk(chunk));
                    break;
                }
            }
            selected_chunk.unwrap_or(BlobDeletionWorkKind::AdvanceDirectoryPhase)
        }
        BlobDeletionPhase::DirectoryDeletePending => {
            BlobDeletionWorkKind::RemoveDirectoryAndFinalize
        }
    };
    let position = match &kind {
        BlobDeletionWorkKind::Chunk(chunk)
        | BlobDeletionWorkKind::ReconcileUnmarkedChunk(chunk) => {
            super::lifecycle::deletion_chunk_cursor_position(variant, chunk.index).to_vec()
        }
        BlobDeletionWorkKind::AdvanceDirectoryPhase
        | BlobDeletionWorkKind::RemoveDirectoryAndFinalize => {
            super::lifecycle::deletion_manifest_cursor_position(variant).to_vec()
        }
    };
    let physical_bytes = match &kind {
        BlobDeletionWorkKind::Chunk(chunk) => chunk.charged_committed_bytes,
        BlobDeletionWorkKind::ReconcileUnmarkedChunk(chunk) => {
            super::depot::deletion_chunk_projection(
                &manifest.original_import,
                chunk.index,
                &chunk.original_chunk,
            )?
            .authorized_file_bytes
        }
        BlobDeletionWorkKind::AdvanceDirectoryPhase
        | BlobDeletionWorkKind::RemoveDirectoryAndFinalize => 0,
    };
    if bytes_examined
        .checked_add(physical_bytes)
        .ok_or(StoreError::PayloadByteAccountingOverflow)?
        > bytes_budget
    {
        return Ok(BlobDeletionSelection::Continue {
            position: match &kind {
                BlobDeletionWorkKind::Chunk(chunk)
                | BlobDeletionWorkKind::ReconcileUnmarkedChunk(chunk) => Some(
                    super::lifecycle::deletion_chunk_resume_position(variant, chunk.index).to_vec(),
                ),
                BlobDeletionWorkKind::AdvanceDirectoryPhase
                | BlobDeletionWorkKind::RemoveDirectoryAndFinalize => last_scanned,
            },
            rows_examined,
            bytes_examined,
        });
    }
    Ok(BlobDeletionSelection::Work(Box::new(BlobDeletionWork {
        manifest,
        kind,
        position,
        rows_examined,
        bytes_examined,
    })))
}

pub(crate) fn revalidate_physical_work_write(
    write: &redb::WriteTransaction,
    work: &BlobDeletionWork,
) -> Result<(), StoreError> {
    let current = load_manifest_header_write(write, work.manifest.variant_id)?;
    if current != work.manifest {
        return Err(invariant("Blob deletion work changed after discovery"));
    }
    if let BlobDeletionWorkKind::Chunk(chunk) | BlobDeletionWorkKind::ReconcileUnmarkedChunk(chunk) =
        &work.kind
        && load_chunk_write(write, work.manifest.variant_id, chunk.index)? != *chunk
    {
        return Err(invariant("Blob deletion chunk changed after discovery"));
    }
    Ok(())
}

fn rewrite_manifest_header(
    write: &redb::WriteTransaction,
    manifest: &BlobDeletionManifestHeader,
) -> Result<(), StoreError> {
    let encoded = encode_manifest_header(manifest)?;
    write.open_table(BLOB_DELETION_MANIFESTS)?.insert(
        manifest.variant_id.as_bytes().as_slice(),
        encoded.as_slice(),
    )?;
    Ok(())
}

pub(crate) fn mark_chunk_deleted_write(
    write: &redb::WriteTransaction,
    work: &BlobDeletionWork,
) -> Result<(), StoreError> {
    let BlobDeletionWorkKind::Chunk(selected) = &work.kind else {
        return Err(invariant("Blob deletion work is not a chunk unit"));
    };
    let mut manifest = load_manifest_header_write(write, work.manifest.variant_id)?;
    if manifest != work.manifest {
        return Err(invariant(
            "Blob deletion chunk changed during filesystem work",
        ));
    }
    let mut chunk = load_chunk_write(write, manifest.variant_id, selected.index)?;
    if chunk != *selected || chunk.state != BlobDeletionChunkState::DeleteQueued {
        return Err(invariant("Blob deletion chunk is no longer queued"));
    }
    chunk.state = BlobDeletionChunkState::DeletedDurable;
    let encoded_chunk = encode_chunk_record(&chunk)?;
    manifest.totals.queued = manifest
        .totals
        .queued
        .checked_sub(1)
        .ok_or_else(|| invariant("Blob deletion queued count underflows"))?;
    manifest.totals.deleted = manifest
        .totals
        .deleted
        .checked_add(1)
        .ok_or(StoreError::ItemCountAccountingOverflow)?;
    manifest.retry = BlobDeletionRetry::default();
    manifest.retry.validate()?;
    write.open_table(BLOB_DELETION_CHUNKS)?.insert(
        chunk_key(manifest.variant_id, selected.index).as_slice(),
        encoded_chunk.as_slice(),
    )?;
    let mut metadata = write.open_table(BLOB_DELETION_METADATA)?;
    let queued = required_deletion_counter(&metadata, BLOB_DELETION_QUEUED_CHUNKS)?
        .checked_sub(1)
        .ok_or_else(|| invariant("Blob deletion queued accounting underflows"))?;
    let deleted = required_deletion_counter(&metadata, BLOB_DELETION_DELETED_CHUNKS)?
        .checked_add(1)
        .ok_or(StoreError::ItemCountAccountingOverflow)?;
    metadata.insert(BLOB_DELETION_QUEUED_CHUNKS, queued)?;
    metadata.insert(BLOB_DELETION_DELETED_CHUNKS, deleted)?;
    drop(metadata);
    rewrite_manifest_header(write, &manifest)
}

pub(crate) fn mark_unmarked_reconciled_write(
    write: &redb::WriteTransaction,
    work: &BlobDeletionWork,
) -> Result<(), StoreError> {
    let BlobDeletionWorkKind::ReconcileUnmarkedChunk(_) = &work.kind else {
        return Err(invariant(
            "Blob deletion work is not an unmarked reconciliation unit",
        ));
    };
    let mut manifest = load_manifest_header_write(write, work.manifest.variant_id)?;
    if manifest != work.manifest {
        return Err(invariant(
            "Blob deletion unmarked authority changed during filesystem work",
        ));
    }
    manifest.retry = BlobDeletionRetry::default();
    let BlobDeletionWorkKind::ReconcileUnmarkedChunk(selected) = &work.kind else {
        unreachable!();
    };
    if load_chunk_write(write, manifest.variant_id, selected.index)? != *selected {
        return Err(invariant(
            "Blob deletion unmarked chunk changed during filesystem work",
        ));
    }
    rewrite_manifest_header(write, &manifest)
}

pub(crate) fn advance_directory_phase_write(
    write: &redb::WriteTransaction,
    work: &BlobDeletionWork,
) -> Result<(), StoreError> {
    if work.kind != BlobDeletionWorkKind::AdvanceDirectoryPhase {
        return Err(invariant("Blob deletion work is not a phase transition"));
    }
    let mut manifest = load_manifest_header_write(write, work.manifest.variant_id)?;
    if manifest != work.manifest
        || manifest.phase != BlobDeletionPhase::DeletingChunks
        || manifest.totals.queued != 0
        || manifest.totals.deleted != manifest.totals.chunks
    {
        return Err(invariant("Blob deletion directory phase is not ready"));
    }
    manifest.phase = BlobDeletionPhase::DirectoryDeletePending;
    manifest.retry = BlobDeletionRetry::default();
    rewrite_manifest_header(write, &manifest)
}

pub(crate) fn record_physical_failure_write(
    write: &redb::WriteTransaction,
    work: &BlobDeletionWork,
    turn: u64,
    category: BlobDeletionFailureCategory,
) -> Result<(), StoreError> {
    let mut manifest = load_manifest_header_write(write, work.manifest.variant_id)?;
    if manifest != work.manifest {
        return Err(invariant(
            "Blob deletion work changed before retry recording",
        ));
    }
    manifest.retry = manifest.retry.after_failure(turn, category)?;
    rewrite_manifest_header(write, &manifest)
}

pub(crate) fn finalize_manifest_write(
    write: &redb::WriteTransaction,
    work: &BlobDeletionWork,
) -> Result<(), StoreError> {
    if work.kind != BlobDeletionWorkKind::RemoveDirectoryAndFinalize {
        return Err(invariant("Blob deletion work is not a finalization unit"));
    }
    let manifest = load_manifest_write(write, work.manifest.variant_id)?;
    if manifest_header(&manifest) != work.manifest
        || manifest.phase != BlobDeletionPhase::DirectoryDeletePending
        || manifest.totals.queued != 0
        || manifest.totals.deleted != manifest.totals.chunks
        || manifest
            .chunks
            .iter()
            .any(|chunk| chunk.state != BlobDeletionChunkState::DeletedDurable)
    {
        return Err(invariant(
            "Blob deletion finalization authority is incomplete",
        ));
    }
    if write
        .open_table(super::BLOB_CHUNKS)?
        .range::<&[u8]>((
            std::ops::Bound::Included(chunk_key(manifest.variant_id, 0).as_slice()),
            std::ops::Bound::Included(chunk_key(manifest.variant_id, u64::MAX).as_slice()),
        ))?
        .next()
        .transpose()?
        .is_some()
    {
        return Err(invariant(
            "Blob deletion finalization found active chunk authority",
        ));
    }
    begin_manifest_finalization_mutations();
    super::lifecycle::mark_lineage_bulk_reclamation_observed(
        write,
        manifest.variant_id,
        &manifest.lineage_fence,
    )?;
    manifest_finalization_mutation_boundary()?;
    let removed_import = if super::pack_lifecycle::is_pack_evidence(&manifest.original_import) {
        super::pack_lifecycle::finalize_deletion_write(
            write,
            manifest.variant_id,
            &manifest.original_import,
        )?;
        manifest.original_import.clone()
    } else {
        write
            .open_table(super::BLOB_IMPORTS)?
            .remove(manifest.variant_id.as_bytes().as_slice())?
            .ok_or_else(|| invariant("Blob deletion finalization import is missing"))?
            .value()
            .to_vec()
    };
    manifest_finalization_mutation_boundary()?;
    if removed_import != manifest.original_import {
        return Err(invariant("Blob deletion finalization import changed"));
    }
    let encoded_manifest = write
        .open_table(BLOB_DELETION_MANIFESTS)?
        .remove(manifest.variant_id.as_bytes().as_slice())?
        .ok_or_else(|| invariant("Blob deletion finalization manifest is missing"))?
        .value()
        .to_vec();
    account_finalized_manifest_in_continuity_transition(write, manifest.variant_id, manifest.age)?;
    manifest_finalization_mutation_boundary()?;
    let manifest_bytes = encoded_row_bytes(manifest.variant_id.as_bytes(), &encoded_manifest)?;
    let mut chunk_bytes = 0u64;
    let mut deletion_chunks = write.open_table(BLOB_DELETION_CHUNKS)?;
    for chunk in &manifest.chunks {
        let key = chunk_key(manifest.variant_id, chunk.index);
        let encoded = deletion_chunks
            .remove(key.as_slice())?
            .ok_or_else(|| invariant("Blob deletion finalization chunk is missing"))?
            .value()
            .to_vec();
        manifest_finalization_mutation_boundary()?;
        chunk_bytes = chunk_bytes
            .checked_add(encoded_row_bytes(&key, &encoded)?)
            .ok_or(StoreError::PayloadByteAccountingOverflow)?;
    }
    drop(deletion_chunks);

    let mut depot = write.open_table(super::BLOB_DEPOT_METADATA)?;
    for (field, delta) in [
        (super::DEPOT_VARIANT_COUNT, manifest.totals.charged_variants),
        (
            super::DEPOT_COMMITTED_CHUNK_COUNT,
            manifest.totals.charged_files,
        ),
        (
            super::DEPOT_COMMITTED_FILE_BYTES,
            manifest.totals.charged_committed_bytes,
        ),
        (
            super::DEPOT_RESERVED_FILE_BYTES,
            manifest.totals.charged_reserved_bytes,
        ),
    ] {
        let next = depot
            .get(field)?
            .ok_or_else(|| invariant("Blob depot finalization counter is missing"))?
            .value()
            .checked_sub(delta)
            .ok_or_else(|| invariant("Blob depot finalization counter underflows"))?;
        depot.insert(field, next)?;
        manifest_finalization_mutation_boundary()?;
    }
    drop(depot);

    let mut metadata = write.open_table(BLOB_DELETION_METADATA)?;
    for (field, delta) in [
        (BLOB_DELETION_MANIFEST_ROWS, 1),
        (BLOB_DELETION_CHUNK_ROWS, manifest.totals.chunks),
        (BLOB_DELETION_DELETED_CHUNKS, manifest.totals.deleted),
        (
            BLOB_DELETION_CHARGED_VARIANTS,
            manifest.totals.charged_variants,
        ),
        (BLOB_DELETION_CHARGED_FILES, manifest.totals.charged_files),
    ] {
        let next = required_deletion_counter(&metadata, field)?
            .checked_sub(delta)
            .ok_or_else(|| invariant("Blob deletion finalization counter underflows"))?;
        metadata.insert(field, next)?;
        manifest_finalization_mutation_boundary()?;
    }
    for (field, delta) in [
        (BLOB_DELETION_MANIFEST_BYTES, manifest_bytes),
        (BLOB_DELETION_CHUNK_BYTES, chunk_bytes),
        (
            BLOB_DELETION_CHARGED_RESERVED_BYTES,
            manifest.totals.charged_reserved_bytes,
        ),
        (
            BLOB_DELETION_CHARGED_COMMITTED_BYTES,
            manifest.totals.charged_committed_bytes,
        ),
    ] {
        let next = required_deletion_counter(&metadata, field)?
            .checked_sub(delta)
            .ok_or_else(|| invariant("Blob deletion finalization byte counter underflows"))?;
        metadata.insert(field, next)?;
        manifest_finalization_mutation_boundary()?;
    }
    Ok(())
}

/// Builds deletion authority from one unreferenced variant for exact-audit
/// tests. Production admission belongs to the bounded maintenance path.
#[cfg(test)]
pub(crate) fn move_variant_to_manifest_for_test(
    write: &redb::WriteTransaction,
    variant: BlobVariantId,
) -> Result<BlobDeletionManifest, StoreError> {
    let imports = write.open_table(super::BLOB_IMPORTS)?;
    let original_import = imports
        .get(variant.as_bytes().as_slice())?
        .ok_or_else(|| invariant("Blob deletion test import is missing"))?
        .value()
        .to_vec();
    drop(imports);
    let import = super::depot::deletion_import_projection(variant.as_bytes(), &original_import)?;
    let owner_binding = super::depot::depot_owner_binding_if_present_write(write)?
        .ok_or_else(|| invariant("Blob deletion test owner binding is missing"))?;
    let fences = write.open_table(super::lifecycle::BLOB_LINEAGE_FENCES)?;
    let lineage_fence = fences
        .get(variant.as_bytes().as_slice())?
        .ok_or_else(|| invariant("Blob deletion test lineage fence is missing"))?
        .value()
        .to_vec();
    drop(fences);

    let first = chunk_key(variant, 0);
    let last = chunk_key(variant, u64::MAX);
    let active_chunks = write.open_table(super::BLOB_CHUNKS)?;
    let mut originals = Vec::new();
    for row in active_chunks.range::<&[u8]>((
        std::ops::Bound::Included(first.as_slice()),
        std::ops::Bound::Included(last.as_slice()),
    ))? {
        let (key, value) = row?;
        let (_, index) = parse_chunk_key(key.value())?;
        originals.push((index, value.value().to_vec()));
    }
    drop(active_chunks);
    let mut chunks = Vec::with_capacity(originals.len());
    let mut charged_files = 0u64;
    let mut charged_reserved_bytes = 0u64;
    let mut charged_committed_bytes = 0u64;
    for (index, original_chunk) in &originals {
        let projected =
            super::depot::deletion_chunk_projection(&original_import, *index, original_chunk)?;
        charged_reserved_bytes = charged_reserved_bytes
            .checked_add(projected.charged_reserved_bytes)
            .ok_or(StoreError::PayloadByteAccountingOverflow)?;
        charged_committed_bytes = charged_committed_bytes
            .checked_add(projected.charged_committed_bytes)
            .ok_or(StoreError::PayloadByteAccountingOverflow)?;
        charged_files = charged_files
            .checked_add(u64::from(projected.charged_committed_bytes != 0))
            .ok_or(StoreError::ItemCountAccountingOverflow)?;
        chunks.push(BlobDeletionChunk {
            index: *index,
            state: BlobDeletionChunkState::DeleteQueued,
            original_chunk: original_chunk.clone(),
            charged_reserved_bytes: projected.charged_reserved_bytes,
            charged_committed_bytes: projected.charged_committed_bytes,
        });
    }
    let chunk_count =
        u64::try_from(chunks.len()).map_err(|_| StoreError::ItemCountAccountingOverflow)?;
    let manifest = BlobDeletionManifest {
        variant_id: variant,
        blob_id: import.blob_id,
        content_group: import.content_group,
        epoch: import.epoch,
        physical_lineage: import.physical_lineage,
        owner_binding,
        lineage_fence,
        original_import,
        finalized_root: import.finalized_root,
        phase: BlobDeletionPhase::DeletingChunks,
        retry: BlobDeletionRetry::default(),
        age: BlobDeletionAge {
            cumulative_age_ms: 0,
            checkpoint: None,
            continuity_generation: 0,
            continuity_lost: false,
        },
        totals: BlobDeletionTotals {
            chunks: chunk_count,
            queued: chunk_count,
            deleted: 0,
            charged_variants: 1,
            charged_files,
            charged_reserved_bytes,
            charged_committed_bytes,
        },
        chunks,
    };
    manifest.validate()?;
    let encoded_manifest = encode_manifest_record(&manifest)?;
    let encoded_chunks = manifest
        .chunks
        .iter()
        .map(encode_chunk_record)
        .collect::<Result<Vec<_>, _>>()?;

    let mut active_chunks = write.open_table(super::BLOB_CHUNKS)?;
    for (index, _) in &originals {
        active_chunks
            .remove(chunk_key(variant, *index).as_slice())?
            .ok_or_else(|| invariant("Blob deletion test chunk move lost authority"))?;
    }
    drop(active_chunks);
    write
        .open_table(BLOB_DELETION_MANIFESTS)?
        .insert(variant.as_bytes().as_slice(), encoded_manifest.as_slice())?;
    let mut deletion_chunks = write.open_table(BLOB_DELETION_CHUNKS)?;
    let mut encoded_chunk_bytes = 0u64;
    for (chunk, encoded) in manifest.chunks.iter().zip(&encoded_chunks) {
        let key = chunk_key(variant, chunk.index);
        encoded_chunk_bytes = encoded_chunk_bytes
            .checked_add(encoded_row_bytes(&key, encoded)?)
            .ok_or(StoreError::PayloadByteAccountingOverflow)?;
        deletion_chunks.insert(key.as_slice(), encoded.as_slice())?;
    }
    drop(deletion_chunks);

    let mut metadata = write.open_table(BLOB_DELETION_METADATA)?;
    let manifest_bytes = encoded_row_bytes(variant.as_bytes(), &encoded_manifest)?;
    for (field, delta) in [
        (BLOB_DELETION_MANIFEST_ROWS, 1),
        (BLOB_DELETION_MANIFEST_BYTES, manifest_bytes),
        (BLOB_DELETION_CHUNK_ROWS, chunk_count),
        (BLOB_DELETION_CHUNK_BYTES, encoded_chunk_bytes),
        (BLOB_DELETION_QUEUED_CHUNKS, chunk_count),
        (BLOB_DELETION_CHARGED_VARIANTS, 1),
        (BLOB_DELETION_CHARGED_FILES, charged_files),
        (BLOB_DELETION_CHARGED_RESERVED_BYTES, charged_reserved_bytes),
        (
            BLOB_DELETION_CHARGED_COMMITTED_BYTES,
            charged_committed_bytes,
        ),
    ] {
        let current = metadata
            .get(field)?
            .ok_or_else(|| invariant("Blob deletion test metadata is missing"))?
            .value();
        set_metadata_for_test(
            &mut metadata,
            field,
            current
                .checked_add(delta)
                .ok_or(StoreError::PayloadByteAccountingOverflow)?,
        )?;
    }
    Ok(manifest)
}

#[cfg(test)]
pub(crate) fn move_finalized_variant_to_manifest_for_test(
    write: &redb::WriteTransaction,
    variant: BlobVariantId,
) -> Result<BlobDeletionManifest, StoreError> {
    let manifest = move_variant_to_manifest_for_test(write, variant)?;
    if manifest.finalized_root.is_none()
        || manifest.totals.chunks
            != super::depot::deletion_import_projection(
                variant.as_bytes(),
                &manifest.original_import,
            )?
            .chunk_count
    {
        return Err(invariant(
            "Blob deletion test fixture lacks exact committed chunk rows",
        ));
    }
    Ok(manifest)
}

#[cfg(test)]
pub(crate) fn corrupt_blob_deletion_for_test(
    write: &redb::WriteTransaction,
    variant: BlobVariantId,
    corruption: &str,
) -> Result<(), StoreError> {
    if corruption == "live-reference" {
        let mut key = [0xa5; 65];
        key[..32].copy_from_slice(variant.as_bytes());
        key[32] = 1;
        write
            .open_table(super::lifecycle::BLOB_VARIANT_REFERENCES)?
            .insert(key.as_slice(), &[][..])?;
        return Ok(());
    }
    if corruption == "accounting" {
        let mut metadata = write.open_table(BLOB_DELETION_METADATA)?;
        let current = metadata
            .get(BLOB_DELETION_CHARGED_COMMITTED_BYTES)?
            .ok_or_else(|| invariant("Blob deletion test accounting is missing"))?
            .value();
        return set_metadata_for_test(
            &mut metadata,
            BLOB_DELETION_CHARGED_COMMITTED_BYTES,
            current
                .checked_add(1)
                .ok_or(StoreError::PayloadByteAccountingOverflow)?,
        );
    }
    let mut manifest = load_manifest_write(write, variant)?;
    match corruption {
        "root" => {
            manifest
                .finalized_root
                .as_mut()
                .ok_or_else(|| invariant("Blob deletion test manifest root is missing"))?[0] ^= 1;
        }
        "deleted-file-present" => {
            let first = manifest
                .chunks
                .first_mut()
                .ok_or_else(|| invariant("Blob deletion test manifest has no chunks"))?;
            first.state = BlobDeletionChunkState::DeletedDurable;
            manifest.totals.queued = manifest
                .totals
                .queued
                .checked_sub(1)
                .ok_or_else(|| invariant("Blob deletion queued total underflows"))?;
            manifest.totals.deleted = manifest
                .totals
                .deleted
                .checked_add(1)
                .ok_or(StoreError::ItemCountAccountingOverflow)?;
            let mut metadata = write.open_table(BLOB_DELETION_METADATA)?;
            set_metadata_for_test(
                &mut metadata,
                BLOB_DELETION_QUEUED_CHUNKS,
                manifest.totals.queued,
            )?;
            set_metadata_for_test(
                &mut metadata,
                BLOB_DELETION_DELETED_CHUNKS,
                manifest.totals.deleted,
            )?;
        }
        _ => return Err(invariant("Blob deletion test corruption is unknown")),
    }
    manifest.validate()?;
    let encoded_manifest = encode_manifest_record(&manifest)?;
    write
        .open_table(BLOB_DELETION_MANIFESTS)?
        .insert(variant.as_bytes().as_slice(), encoded_manifest.as_slice())?;
    if corruption == "deleted-file-present" {
        let first = manifest
            .chunks
            .first()
            .ok_or_else(|| invariant("Blob deletion test manifest has no chunks"))?;
        let encoded_chunk = encode_chunk_record(first)?;
        write.open_table(BLOB_DELETION_CHUNKS)?.insert(
            chunk_key(variant, first.index).as_slice(),
            encoded_chunk.as_slice(),
        )?;
    }
    Ok(())
}

#[cfg(test)]
pub(crate) fn set_blob_deletion_phase_for_test(
    write: &redb::WriteTransaction,
    variant: BlobVariantId,
    phase: BlobDeletionPhase,
    retry: BlobDeletionRetry,
) -> Result<(), StoreError> {
    let mut manifest = load_manifest_write(write, variant)?;
    let previous_queued = manifest.totals.queued;
    let previous_deleted = manifest.totals.deleted;
    if phase == BlobDeletionPhase::DirectoryDeletePending {
        for chunk in &mut manifest.chunks {
            chunk.state = BlobDeletionChunkState::DeletedDurable;
            let encoded = encode_chunk_record(chunk)?;
            write.open_table(BLOB_DELETION_CHUNKS)?.insert(
                chunk_key(variant, chunk.index).as_slice(),
                encoded.as_slice(),
            )?;
        }
        manifest.totals.queued = 0;
        manifest.totals.deleted = manifest.totals.chunks;
    }
    manifest.phase = phase;
    manifest.retry = retry;
    manifest.validate()?;
    let mut metadata = write.open_table(BLOB_DELETION_METADATA)?;
    let queued = metadata
        .get(BLOB_DELETION_QUEUED_CHUNKS)?
        .ok_or_else(|| invariant("Blob deletion queued total is missing"))?
        .value()
        .checked_sub(previous_queued)
        .and_then(|value| value.checked_add(manifest.totals.queued))
        .ok_or_else(|| invariant("Blob deletion queued total cannot be updated"))?;
    let deleted = metadata
        .get(BLOB_DELETION_DELETED_CHUNKS)?
        .ok_or_else(|| invariant("Blob deletion deleted total is missing"))?
        .value()
        .checked_sub(previous_deleted)
        .and_then(|value| value.checked_add(manifest.totals.deleted))
        .ok_or_else(|| invariant("Blob deletion deleted total cannot be updated"))?;
    set_metadata_for_test(&mut metadata, BLOB_DELETION_QUEUED_CHUNKS, queued)?;
    set_metadata_for_test(&mut metadata, BLOB_DELETION_DELETED_CHUNKS, deleted)?;
    drop(metadata);
    let encoded = encode_manifest_record(&manifest)?;
    write
        .open_table(BLOB_DELETION_MANIFESTS)?
        .insert(variant.as_bytes().as_slice(), encoded.as_slice())?;
    Ok(())
}

#[cfg(test)]
pub(crate) fn set_blob_deletion_age_for_test(
    write: &redb::WriteTransaction,
    variant: BlobVariantId,
    age: BlobDeletionAge,
    continuity: Option<BlobDeletionContinuity>,
) -> Result<(), StoreError> {
    let mut manifest = load_manifest_write(write, variant)?;
    manifest.age = age;
    manifest.validate()?;
    let encoded = encode_manifest_record(&manifest)?;
    write
        .open_table(BLOB_DELETION_MANIFESTS)?
        .insert(variant.as_bytes().as_slice(), encoded.as_slice())?;
    let mut continuity_table = write.open_table(BLOB_DELETION_CONTINUITY)?;
    match continuity {
        Some(continuity) => {
            let encoded = encode_continuity(continuity);
            continuity_table.insert(CONTINUITY_KEY, encoded.as_slice())?;
        }
        None => {
            continuity_table.remove(CONTINUITY_KEY)?;
        }
    }
    Ok(())
}

#[cfg(test)]
pub(crate) fn set_blob_deletion_deferred_count_for_test(
    write: &redb::WriteTransaction,
    deferred: u64,
) -> Result<(), StoreError> {
    let mut state = blob_deletion_continuity_state_write(write)?
        .ok_or_else(|| invariant("Blob deletion test continuity state is missing"))?;
    state.deferred = deferred;
    store_blob_deletion_continuity_state(write, state)
}

#[cfg(test)]
pub(crate) fn corrupt_blob_deletion_cumulative_age_for_test(
    write: &redb::WriteTransaction,
    variant: BlobVariantId,
    cumulative_age_ms: u64,
) -> Result<(), StoreError> {
    let mut manifest = load_manifest_write(write, variant)?;
    manifest.age.cumulative_age_ms = cumulative_age_ms;
    manifest.validate()?;
    let encoded = encode_manifest_record(&manifest)?;
    write
        .open_table(BLOB_DELETION_MANIFESTS)?
        .insert(variant.as_bytes().as_slice(), encoded.as_slice())?;
    Ok(())
}

#[cfg(test)]
pub(crate) fn set_blob_deletion_continuity_transition_for_test(
    write: &redb::WriteTransaction,
    previous: BlobDeletionContinuity,
    current: BlobDeletionContinuity,
    anchor: CustodySample,
    after: Option<BlobVariantId>,
    remaining: u64,
) -> Result<(), StoreError> {
    store_blob_deletion_continuity_state(
        write,
        BlobDeletionContinuityState {
            current,
            transition: Some(BlobDeletionContinuityTransition {
                previous,
                anchor,
                after,
                remaining,
            }),
            pending: None,
            deferred: 0,
        },
    )
}

#[allow(dead_code)]
fn encode_continuity(continuity: BlobDeletionContinuity) -> [u8; 33] {
    let mut encoded = [0u8; 33];
    encoded[0] = CONTINUITY_VERSION;
    encoded[1..9].copy_from_slice(&continuity.generation.to_be_bytes());
    encoded[9..25].copy_from_slice(&continuity.last_sample.clock_id);
    encoded[25..].copy_from_slice(&continuity.last_sample.tick_ms.to_be_bytes());
    encoded
}

fn decode_legacy_continuity(bytes: &[u8]) -> Result<BlobDeletionContinuity, StoreError> {
    let bytes: [u8; 33] = bytes
        .try_into()
        .map_err(|_| invariant("Blob deletion continuity record has invalid length"))?;
    if bytes[0] != CONTINUITY_VERSION {
        return Err(invariant(
            "Blob deletion continuity record has unknown version",
        ));
    }
    let generation = u64::from_be_bytes(
        bytes[1..9]
            .try_into()
            .map_err(|_| invariant("Blob deletion continuity generation is malformed"))?,
    );
    if generation == 0 {
        return Err(invariant(
            "Blob deletion continuity generation must be nonzero",
        ));
    }
    Ok(BlobDeletionContinuity {
        generation,
        last_sample: CustodySample {
            clock_id: bytes[9..25]
                .try_into()
                .map_err(|_| invariant("Blob deletion continuity clock is malformed"))?,
            tick_ms: u64::from_be_bytes(
                bytes[25..]
                    .try_into()
                    .map_err(|_| invariant("Blob deletion continuity tick is malformed"))?,
            ),
        },
    })
}

fn validate_continuity_state(state: BlobDeletionContinuityState) -> Result<(), StoreError> {
    if state.current.generation == 0 {
        return Err(invariant(
            "Blob deletion continuity generation must be nonzero",
        ));
    }
    if let Some(transition) = state.transition
        && (transition.remaining == 0
            || transition
                .previous
                .generation
                .checked_add(1)
                .is_none_or(|generation| generation != state.current.generation)
            || transition.anchor.clock_id != state.current.last_sample.clock_id
            || transition.anchor.tick_ms > state.current.last_sample.tick_ms)
    {
        return Err(invariant(
            "Blob deletion continuity transition is not canonical",
        ));
    }
    if let Some(pending) = state.pending
        && (state.transition.is_none()
            || pending.remaining == 0
            || state
                .current
                .generation
                .checked_add(1)
                .is_none_or(|generation| generation != pending.current.generation)
            || pending.anchor.clock_id != pending.current.last_sample.clock_id
            || pending.anchor.tick_ms > pending.current.last_sample.tick_ms)
    {
        return Err(invariant(
            "Blob deletion pending continuity is not canonical",
        ));
    }
    Ok(())
}

fn continuity_state_encoded_len(state: BlobDeletionContinuityState) -> Result<usize, StoreError> {
    validate_continuity_state(state)?;
    43usize
        .checked_add(usize::from(state.transition.is_some()) * 97)
        .and_then(|length| length.checked_add(usize::from(state.pending.is_some()) * 64))
        .ok_or(StoreError::PayloadByteAccountingOverflow)
}

fn encode_continuity_state(state: BlobDeletionContinuityState) -> Result<Vec<u8>, StoreError> {
    validate_continuity_state(state)?;
    let mut encoded = Vec::with_capacity(continuity_state_encoded_len(state)?);
    encoded.push(CONTINUITY_STATE_VERSION);
    encoded.extend_from_slice(&state.current.generation.to_be_bytes());
    encoded.extend_from_slice(&state.current.last_sample.clock_id);
    encoded.extend_from_slice(&state.current.last_sample.tick_ms.to_be_bytes());
    match state.transition {
        None => encoded.push(0),
        Some(transition) => {
            encoded.push(1);
            encoded.extend_from_slice(&transition.previous.generation.to_be_bytes());
            encoded.extend_from_slice(&transition.previous.last_sample.clock_id);
            encoded.extend_from_slice(&transition.previous.last_sample.tick_ms.to_be_bytes());
            encoded.extend_from_slice(&transition.anchor.clock_id);
            encoded.extend_from_slice(&transition.anchor.tick_ms.to_be_bytes());
            encoded.extend_from_slice(&transition.remaining.to_be_bytes());
            encoded.push(u8::from(transition.after.is_some()));
            encoded.extend_from_slice(
                transition
                    .after
                    .map_or([0; 32], |variant| *variant.as_bytes())
                    .as_slice(),
            );
        }
    }
    match state.pending {
        None => encoded.push(0),
        Some(pending) => {
            encoded.push(1);
            encoded.extend_from_slice(&pending.current.generation.to_be_bytes());
            encoded.extend_from_slice(&pending.current.last_sample.clock_id);
            encoded.extend_from_slice(&pending.current.last_sample.tick_ms.to_be_bytes());
            encoded.extend_from_slice(&pending.anchor.clock_id);
            encoded.extend_from_slice(&pending.anchor.tick_ms.to_be_bytes());
            encoded.extend_from_slice(&pending.remaining.to_be_bytes());
        }
    }
    encoded.extend_from_slice(&state.deferred.to_be_bytes());
    Ok(encoded)
}

fn decode_continuity_state(bytes: &[u8]) -> Result<BlobDeletionContinuityState, StoreError> {
    if bytes.first() == Some(&CONTINUITY_VERSION) {
        return Ok(BlobDeletionContinuityState {
            current: decode_legacy_continuity(bytes)?,
            transition: None,
            pending: None,
            deferred: 0,
        });
    }
    let mut cursor = SliceCursor::new(bytes);
    let version = cursor.u8()?;
    if !matches!(
        version,
        PREVIOUS_CONTINUITY_STATE_VERSION
            | PENDING_CONTINUITY_STATE_VERSION
            | CONTINUITY_STATE_VERSION
    ) {
        return Err(invariant(
            "Blob deletion continuity record has unknown version",
        ));
    }
    let current = BlobDeletionContinuity {
        generation: cursor.u64()?,
        last_sample: CustodySample {
            clock_id: cursor.array()?,
            tick_ms: cursor.u64()?,
        },
    };
    let transition = match cursor.u8()? {
        0 => None,
        1 => {
            let previous = BlobDeletionContinuity {
                generation: cursor.u64()?,
                last_sample: CustodySample {
                    clock_id: cursor.array()?,
                    tick_ms: cursor.u64()?,
                },
            };
            let anchor = CustodySample {
                clock_id: cursor.array()?,
                tick_ms: cursor.u64()?,
            };
            let remaining = cursor.u64()?;
            let after_present = match cursor.u8()? {
                0 => false,
                1 => true,
                _ => {
                    return Err(invariant(
                        "Blob deletion continuity position flag is invalid",
                    ));
                }
            };
            let after_bytes: [u8; 32] = cursor.array()?;
            let after = if after_present {
                Some(BlobVariantId::from_bytes(after_bytes))
            } else {
                if after_bytes != [0; 32] {
                    return Err(invariant(
                        "Blob deletion absent continuity position retains evidence",
                    ));
                }
                None
            };
            Some(BlobDeletionContinuityTransition {
                previous,
                anchor,
                after,
                remaining,
            })
        }
        _ => {
            return Err(invariant(
                "Blob deletion continuity transition flag is invalid",
            ));
        }
    };
    let pending = if version == PREVIOUS_CONTINUITY_STATE_VERSION {
        None
    } else {
        match cursor.u8()? {
            0 => None,
            1 => Some(BlobDeletionPendingContinuity {
                current: BlobDeletionContinuity {
                    generation: cursor.u64()?,
                    last_sample: CustodySample {
                        clock_id: cursor.array()?,
                        tick_ms: cursor.u64()?,
                    },
                },
                anchor: CustodySample {
                    clock_id: cursor.array()?,
                    tick_ms: cursor.u64()?,
                },
                remaining: cursor.u64()?,
            }),
            _ => {
                return Err(invariant(
                    "Blob deletion pending continuity flag is invalid",
                ));
            }
        }
    };
    let deferred = if version == CONTINUITY_STATE_VERSION {
        cursor.u64()?
    } else {
        0
    };
    cursor.finish()?;
    let state = BlobDeletionContinuityState {
        current,
        transition,
        pending,
        deferred,
    };
    validate_continuity_state(state)?;
    Ok(state)
}

fn audited_continuity_state(
    table: &impl ReadableTable<u8, &'static [u8]>,
) -> Result<Option<BlobDeletionContinuityState>, StoreError> {
    if table.len()? > 1 {
        return Err(invariant(
            "Blob deletion continuity table contains unknown rows",
        ));
    }
    let mut continuity = None;
    for row in table.iter()? {
        let (key, value) = row?;
        if key.value() != CONTINUITY_KEY {
            return Err(invariant("Blob deletion continuity key is not canonical"));
        }
        continuity = Some(decode_continuity_state(value.value())?);
    }
    Ok(continuity)
}

fn audit_continuity_table(table: &impl ReadableTable<u8, &'static [u8]>) -> Result<(), StoreError> {
    match audited_continuity_state(table)? {
        Some(state)
            if state.transition.is_some() || state.pending.is_some() || state.deferred != 0 =>
        {
            Err(invariant(
                "Blob deletion continuity transition has no pending manifests",
            ))
        }
        _ => Ok(()),
    }
}

fn validate_age_against_continuity(
    age: BlobDeletionAge,
    state: Option<BlobDeletionContinuityState>,
) -> Result<(), StoreError> {
    age.validate()?;
    let Some(checkpoint) = age.checkpoint else {
        if age.continuity_generation == 0 {
            return Ok(());
        }
        let state = state.ok_or_else(|| {
            invariant("Blob deletion deferred age has no durable continuity authority")
        })?;
        let matches_current = age.continuity_generation == state.current.generation;
        let matches_previous = state
            .transition
            .is_some_and(|transition| age.continuity_generation == transition.previous.generation);
        let matches_pending = state
            .pending
            .is_some_and(|pending| age.continuity_generation == pending.current.generation);
        if !(matches_current || matches_previous || matches_pending) {
            return Err(invariant(
                "Blob deletion deferred age generation is not reachable",
            ));
        }
        return Ok(());
    };
    let state = state.ok_or_else(|| {
        invariant("Blob deletion age checkpoint has no durable continuity authority")
    })?;
    let continuity = state
        .pending
        .filter(|pending| age.continuity_generation == pending.current.generation)
        .map_or(state.current, |pending| pending.current);
    if age.continuity_generation > continuity.generation {
        return Err(invariant(
            "Blob deletion age generation is ahead of durable continuity",
        ));
    }
    if age.continuity_generation == continuity.generation
        && (checkpoint.clock_id != continuity.last_sample.clock_id
            || checkpoint.tick_ms > continuity.last_sample.tick_ms)
    {
        return Err(invariant(
            "Blob deletion age checkpoint exceeds current durable continuity",
        ));
    }
    Ok(())
}

#[allow(dead_code)]
fn blob_deletion_continuity_write(
    write: &redb::WriteTransaction,
) -> Result<Option<BlobDeletionContinuity>, StoreError> {
    Ok(blob_deletion_continuity_state_write(write)?.map(|state| state.current))
}

fn blob_deletion_continuity_state_write(
    write: &redb::WriteTransaction,
) -> Result<Option<BlobDeletionContinuityState>, StoreError> {
    write
        .open_table(BLOB_DELETION_CONTINUITY)?
        .get(CONTINUITY_KEY)?
        .map(|value| decode_continuity_state(value.value()))
        .transpose()
}

fn store_blob_deletion_continuity_state(
    write: &redb::WriteTransaction,
    state: BlobDeletionContinuityState,
) -> Result<(), StoreError> {
    let encoded = encode_continuity_state(state)?;
    write
        .open_table(BLOB_DELETION_CONTINUITY)?
        .insert(CONTINUITY_KEY, encoded.as_slice())?;
    Ok(())
}

fn newest_blob_deletion_continuity(state: BlobDeletionContinuityState) -> BlobDeletionContinuity {
    state
        .pending
        .map_or(state.current, |pending| pending.current)
}

fn promote_pending_blob_deletion_continuity_if_ready(state: &mut BlobDeletionContinuityState) {
    if !state
        .transition
        .is_some_and(|transition| transition.remaining == 0)
    {
        return;
    }
    let Some(pending) = state.pending.take() else {
        state.transition = None;
        return;
    };
    let previous = state.current;
    state.current = pending.current;
    state.transition = (pending.remaining != 0).then_some(BlobDeletionContinuityTransition {
        previous,
        anchor: pending.anchor,
        after: None,
        remaining: pending.remaining,
    });
}

fn account_finalized_manifest_in_continuity_transition(
    write: &redb::WriteTransaction,
    variant: BlobVariantId,
    age: BlobDeletionAge,
) -> Result<(), StoreError> {
    let Some(mut state) = blob_deletion_continuity_state_write(write)? else {
        return Ok(());
    };
    let newest_generation = newest_blob_deletion_continuity(state).generation;
    let mut changed = false;
    if let Some(mut transition) = state.transition
        && age.continuity_generation < state.current.generation
    {
        if transition.after.is_some_and(|after| variant <= after) {
            return Err(invariant(
                "Blob deletion finalization found a stale continuity position",
            ));
        }
        transition.remaining = transition
            .remaining
            .checked_sub(1)
            .ok_or_else(|| invariant("Blob deletion continuity transition count underflowed"))?;
        state.transition = Some(transition);
        changed = true;
    }
    if let Some(mut pending) = state.pending
        && age.continuity_generation < pending.current.generation
    {
        pending.remaining = pending
            .remaining
            .checked_sub(1)
            .ok_or_else(|| invariant("Blob deletion pending continuity count underflowed"))?;
        state.pending = Some(pending);
        changed = true;
    }
    if age.checkpoint.is_none() && age.continuity_generation == newest_generation {
        state.deferred = state
            .deferred
            .checked_sub(1)
            .ok_or_else(|| invariant("Blob deletion deferred continuity count underflowed"))?;
        changed = true;
    }
    if !changed {
        return Ok(());
    }
    promote_pending_blob_deletion_continuity_if_ready(&mut state);
    store_blob_deletion_continuity_state(write, state)
}

#[cfg(test)]
fn account_admitted_manifest_in_continuity_transition(
    write: &redb::WriteTransaction,
    _variant: BlobVariantId,
    age: BlobDeletionAge,
) -> Result<(), StoreError> {
    let previous = blob_deletion_continuity_state_write(write)?;
    let projected = project_admitted_manifest_in_continuity_transition(previous, age)?;
    if projected != previous
        && let Some(state) = projected
    {
        store_blob_deletion_continuity_state(write, state)?;
    }
    Ok(())
}

fn project_admitted_manifest_in_continuity_transition(
    state: Option<BlobDeletionContinuityState>,
    age: BlobDeletionAge,
) -> Result<Option<BlobDeletionContinuityState>, StoreError> {
    let Some(mut state) = state else {
        return Ok(None);
    };
    let newest_generation = newest_blob_deletion_continuity(state).generation;
    if let Some(mut transition) = state.transition
        && age.continuity_generation < state.current.generation
    {
        transition.remaining = transition
            .remaining
            .checked_add(1)
            .ok_or(StoreError::ItemCountAccountingOverflow)?;
        // A newly admitted variant can sort before the private transition
        // position. Restart the bounded scan; already checkpointed rows are
        // idempotent and do not consume `remaining` again.
        transition.after = None;
        state.transition = Some(transition);
    }
    if let Some(mut pending) = state.pending
        && age.continuity_generation < pending.current.generation
    {
        pending.remaining = pending
            .remaining
            .checked_add(1)
            .ok_or(StoreError::ItemCountAccountingOverflow)?;
        state.pending = Some(pending);
    }
    if age.checkpoint.is_none() && age.continuity_generation == newest_generation {
        state.deferred = state
            .deferred
            .checked_add(1)
            .ok_or(StoreError::ItemCountAccountingOverflow)?;
    }
    Ok(Some(state))
}

fn project_observed_blob_deletion_continuity(
    previous_state: Option<BlobDeletionContinuityState>,
    sample: CustodySample,
    manifest_count: u64,
) -> Result<(BlobDeletionContinuityState, BlobDeletionContinuity), StoreError> {
    let (state, observed) = match previous_state {
        None => {
            let current = BlobDeletionContinuity {
                generation: 1,
                last_sample: sample,
            };
            (
                BlobDeletionContinuityState {
                    current,
                    transition: None,
                    pending: None,
                    deferred: 0,
                },
                current,
            )
        }
        Some(mut state) if state.pending.is_some() => {
            let mut pending = state.pending.expect("matched pending continuity");
            if pending.current.last_sample.clock_id != sample.clock_id
                || sample.tick_ms < pending.current.last_sample.tick_ms
            {
                // Keep draining the two frozen memberships. The caller uses
                // the returned mismatch to admit this later-domain row as an
                // age-zero deferred member instead of extending old work.
                (state, pending.current)
            } else {
                pending.current.last_sample = sample;
                state.pending = Some(pending);
                (state, pending.current)
            }
        }
        Some(mut state)
            if state.current.last_sample.clock_id == sample.clock_id
                && sample.tick_ms >= state.current.last_sample.tick_ms =>
        {
            state.current.last_sample = sample;
            let observed = state.current;
            (state, observed)
        }
        Some(mut state) if state.transition.is_some() => {
            let next =
                BlobDeletionContinuity {
                    generation: state.current.generation.checked_add(1).ok_or_else(|| {
                        invariant("Blob deletion continuity generation overflowed")
                    })?,
                    last_sample: sample,
                };
            if manifest_count == 0 {
                return Err(invariant(
                    "Blob deletion continuity transition lost its manifest membership",
                ));
            }
            state.pending = Some(BlobDeletionPendingContinuity {
                current: next,
                anchor: sample,
                remaining: manifest_count,
            });
            state.deferred = 0;
            (state, next)
        }
        Some(state) => {
            let next =
                BlobDeletionContinuity {
                    generation: state.current.generation.checked_add(1).ok_or_else(|| {
                        invariant("Blob deletion continuity generation overflowed")
                    })?,
                    last_sample: sample,
                };
            (
                BlobDeletionContinuityState {
                    current: next,
                    transition: (manifest_count != 0).then_some(BlobDeletionContinuityTransition {
                        previous: state.current,
                        anchor: sample,
                        after: None,
                        remaining: manifest_count,
                    }),
                    pending: None,
                    deferred: 0,
                },
                next,
            )
        }
    };
    Ok((state, observed))
}

#[allow(dead_code)]
pub(crate) fn observe_blob_deletion_continuity_write(
    write: &redb::WriteTransaction,
    sample: CustodySample,
) -> Result<BlobDeletionContinuity, StoreError> {
    let previous_state = blob_deletion_continuity_state_write(write)?;
    let manifest_count = write.open_table(BLOB_DELETION_MANIFESTS)?.len()?;
    let (state, observed) =
        project_observed_blob_deletion_continuity(previous_state, sample, manifest_count)?;
    if previous_state != Some(state) {
        store_blob_deletion_continuity_state(write, state)?;
    }
    Ok(observed)
}

fn project_blob_deletion_age_with_state(
    mut age: BlobDeletionAge,
    state: Option<BlobDeletionContinuityState>,
    sample: Option<CustodySample>,
) -> Result<BlobDeletionAge, StoreError> {
    let Some(state) = state else {
        return project_blob_deletion_age(age, None, sample);
    };
    if age.checkpoint.is_none() {
        let deferred_generation = age.continuity_generation;
        let (continuity, effective_sample) =
            if state.transition.is_some() && age.continuity_generation < state.current.generation {
                (state.current, Some(state.current.last_sample))
            } else {
                (newest_blob_deletion_continuity(state), sample)
            };
        let mut projected = project_blob_deletion_age(age, Some(continuity), effective_sample)?;
        if projected.checkpoint.is_none() && deferred_generation != 0 {
            projected.continuity_generation = deferred_generation;
            projected.continuity_lost = true;
        }
        return Ok(projected);
    }
    if let Some(pending) = state.pending
        && age.continuity_generation == pending.current.generation
    {
        let pending_sample = sample
            .filter(|sample| sample.clock_id == pending.current.last_sample.clock_id)
            .or(Some(pending.current.last_sample));
        return project_blob_deletion_age(age, Some(pending.current), pending_sample);
    }
    if let Some(transition) = state.transition
        && age.continuity_generation < state.current.generation
    {
        age = project_blob_deletion_age(
            age,
            Some(transition.previous),
            Some(transition.previous.last_sample),
        )?;
        age = project_blob_deletion_age(
            age,
            Some(BlobDeletionContinuity {
                generation: state.current.generation,
                last_sample: transition.anchor,
            }),
            Some(transition.anchor),
        )?;
    }
    let current_sample = state
        .pending
        .map_or(sample, |_| Some(state.current.last_sample));
    project_blob_deletion_age(age, Some(state.current), current_sample)
}

pub(crate) fn checkpoint_blob_deletion_ages_write(
    write: &redb::WriteTransaction,
    sample: CustodySample,
    rows_budget: u64,
    bytes_budget: u64,
) -> Result<BlobDeletionAgeMaintenanceProgress, StoreError> {
    observe_blob_deletion_continuity_write(write, sample)?;
    let Some(mut state) = blob_deletion_continuity_state_write(write)? else {
        return Err(invariant("Blob deletion continuity update disappeared"));
    };
    let Some(mut transition) = state.transition else {
        return Ok(BlobDeletionAgeMaintenanceProgress::default());
    };
    let mut rows = Vec::new();
    let mut rows_examined = 0u64;
    let mut bytes_examined = 0u64;
    let mut range_exhausted = false;
    {
        let manifests = write.open_table(BLOB_DELETION_MANIFESTS)?;
        let after_bytes = transition.after.map(|variant| *variant.as_bytes());
        let lower = after_bytes
            .as_ref()
            .map_or(std::ops::Bound::Unbounded, |variant| {
                std::ops::Bound::Excluded(variant.as_slice())
            });
        let mut range = manifests.range::<&[u8]>((lower, std::ops::Bound::Unbounded))?;
        while rows_examined < rows_budget {
            let Some(row) = range.next() else {
                range_exhausted = true;
                break;
            };
            let (key, value) = row?;
            let row_bytes = encoded_row_bytes(key.value(), value.value())?;
            let next_bytes = bytes_examined
                .checked_add(row_bytes)
                .ok_or(StoreError::PayloadByteAccountingOverflow)?;
            if next_bytes > bytes_budget {
                break;
            }
            let variant = BlobVariantId::from_bytes(key.value().try_into().map_err(|_| {
                invariant("Blob deletion manifest key is not a variant identifier")
            })?);
            let mut header = decode_manifest_header(value.value())?;
            if header.variant_id != variant {
                return Err(invariant(
                    "Blob deletion manifest key does not match its record",
                ));
            }
            let was_previous = header.age.continuity_generation < state.current.generation;
            let was_pending = state.pending.is_some_and(|pending| {
                header.age.continuity_generation < pending.current.generation
            });
            let was_deferred = header.age.checkpoint.is_none()
                && header.age.continuity_generation
                    == newest_blob_deletion_continuity(state).generation;
            header.age =
                project_blob_deletion_age_with_state(header.age, Some(state), Some(sample))?;
            let completed_pending = was_pending
                && state.pending.is_some_and(|pending| {
                    header.age.continuity_generation >= pending.current.generation
                });
            let completed_deferred = was_deferred && header.age.checkpoint.is_some();
            rows.push((
                variant,
                encode_manifest_header(&header)?,
                was_previous,
                completed_pending,
                completed_deferred,
            ));
            rows_examined = rows_examined
                .checked_add(1)
                .ok_or(StoreError::ItemCountAccountingOverflow)?;
            bytes_examined = next_bytes;
            transition.after = Some(variant);
        }
    }
    if rows.is_empty() && transition.remaining != 0 {
        if range_exhausted {
            return Err(invariant(
                "Blob deletion continuity transition exhausted before its remaining count",
            ));
        }
        return Ok(BlobDeletionAgeMaintenanceProgress {
            rows_examined,
            bytes_examined,
            has_more: true,
        });
    }
    {
        let mut manifests = write.open_table(BLOB_DELETION_MANIFESTS)?;
        for (variant, encoded, was_previous, completed_pending, completed_deferred) in rows {
            manifests.insert(variant.as_bytes().as_slice(), encoded.as_slice())?;
            if was_previous {
                transition.remaining = transition.remaining.checked_sub(1).ok_or_else(|| {
                    invariant("Blob deletion continuity transition count underflowed")
                })?;
            }
            if completed_pending {
                let mut pending = state
                    .pending
                    .ok_or_else(|| invariant("Blob deletion pending continuity disappeared"))?;
                pending.remaining = pending.remaining.checked_sub(1).ok_or_else(|| {
                    invariant("Blob deletion pending continuity count underflowed")
                })?;
                state.pending = Some(pending);
            }
            if completed_deferred {
                state.deferred = state.deferred.checked_sub(1).ok_or_else(|| {
                    invariant("Blob deletion deferred continuity count underflowed")
                })?;
            }
        }
    }
    if range_exhausted && transition.remaining != 0 {
        return Err(invariant(
            "Blob deletion continuity transition exhausted before its remaining count",
        ));
    }
    state.transition = Some(transition);
    promote_pending_blob_deletion_continuity_if_ready(&mut state);
    store_blob_deletion_continuity_state(write, state)?;
    Ok(BlobDeletionAgeMaintenanceProgress {
        rows_examined,
        bytes_examined,
        has_more: state.transition.is_some(),
    })
}

#[allow(dead_code)]
pub(crate) fn project_blob_deletion_age(
    age: BlobDeletionAge,
    continuity: Option<BlobDeletionContinuity>,
    sample: Option<CustodySample>,
) -> Result<BlobDeletionAge, StoreError> {
    age.validate()?;
    let Some(sample) = sample else {
        return Ok(age);
    };
    let projected = project_lower_bound_age(
        LowerBoundAgeCheckpoint {
            cumulative_age_ms: age.cumulative_age_ms,
            checkpoint: age.checkpoint,
            continuity_generation: age.continuity_generation,
            continuity_lost: age.continuity_lost,
        },
        continuity.map(|continuity| LowerBoundContinuity {
            generation: continuity.generation,
            sample: continuity.last_sample,
        }),
        Some(sample),
    );
    Ok(BlobDeletionAge {
        cumulative_age_ms: projected.cumulative_age_ms,
        checkpoint: projected.checkpoint,
        continuity_generation: projected.continuity_generation,
        continuity_lost: projected.continuity_lost,
    })
}

pub(crate) fn project_blob_deletion_age_read(
    read: &redb::ReadTransaction,
    age: BlobDeletionAge,
    sample: Option<CustodySample>,
) -> Result<BlobDeletionAge, StoreError> {
    let table = read.open_table(BLOB_DELETION_CONTINUITY)?;
    let state = if table.len()? == 0 {
        None
    } else {
        let value = table
            .get(CONTINUITY_KEY)?
            .ok_or_else(|| invariant("Blob deletion continuity key is not canonical"))?;
        Some(decode_continuity_state(value.value())?)
    };
    project_blob_deletion_age_with_state(age, state, sample)
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicU64, Ordering};

    use aster_mesh::{BlobId, CustodySample};
    use redb::{Database, ReadableDatabase, ReadableTableMetadata, TableHandle};

    use super::*;
    use crate::{BlobVariantId, MAX_SELECTED_BLOB_CHUNKS, Store};

    static NEXT_DELETION_TEST: AtomicU64 = AtomicU64::new(1);

    struct DeletionTestFile(PathBuf);

    impl DeletionTestFile {
        fn new(label: &str) -> Self {
            let sequence = NEXT_DELETION_TEST.fetch_add(1, Ordering::Relaxed);
            Self(std::env::temp_dir().join(format!(
                "aster-redb-blob-deletion-{label}-{}-{sequence}.redb",
                std::process::id()
            )))
        }
    }

    impl Drop for DeletionTestFile {
        fn drop(&mut self) {
            let _ = std::fs::remove_file(&self.0);
        }
    }

    fn sample_manifest() -> BlobDeletionManifest {
        let blob_id = BlobId::from_bytes([0x22; 32]);
        let content_group = [0x33; 32];
        let checkpoint = CustodySample {
            clock_id: [0x71; 16],
            tick_ms: 900,
        };
        BlobDeletionManifest {
            variant_id: BlobVariantId::for_content(blob_id, &content_group, 7),
            blob_id,
            content_group,
            epoch: 7,
            physical_lineage: [0x44; 32],
            owner_binding: [0x55; 32],
            lineage_fence: vec![0x66; 65],
            original_import: vec![0x77; 128],
            finalized_root: Some([0x88; 32]),
            phase: BlobDeletionPhase::DeletingChunks,
            retry: BlobDeletionRetry::default(),
            age: BlobDeletionAge {
                cumulative_age_ms: 25,
                checkpoint: Some(checkpoint),
                continuity_generation: 3,
                continuity_lost: false,
            },
            totals: BlobDeletionTotals {
                chunks: 1,
                queued: 1,
                deleted: 0,
                charged_variants: 1,
                charged_files: 1,
                charged_reserved_bytes: 211,
                charged_committed_bytes: 211,
            },
            chunks: vec![BlobDeletionChunk {
                index: 0,
                state: BlobDeletionChunkState::DeleteQueued,
                original_chunk: vec![0x99; 186],
                charged_reserved_bytes: 211,
                charged_committed_bytes: 211,
            }],
        }
    }

    fn assert_schema_reason(error: &StoreError, expected: &'static str) {
        assert!(matches!(
            error,
            StoreError::Blob(BlobStoreError::SchemaInvariant(reason)) if *reason == expected
        ));
    }

    #[test]
    fn blob_deletion_schema_migrates_empty_without_inventing_work() {
        let file = DeletionTestFile::new("empty-migration");
        drop(Store::open(&file.0).expect("create current store"));

        {
            let database = Database::open(&file.0).expect("open deletion predecessor");
            let write = database.begin_write().expect("begin deletion predecessor");
            write
                .delete_table(BLOB_DELETION_METADATA)
                .expect("delete deletion metadata");
            write
                .delete_table(BLOB_DELETION_MANIFESTS)
                .expect("delete deletion manifests");
            write
                .delete_table(BLOB_DELETION_CHUNKS)
                .expect("delete deletion chunks");
            write
                .delete_table(BLOB_DELETION_CONTINUITY)
                .expect("delete deletion continuity");
            write.commit().expect("commit whole-absent predecessor");
        }

        Store::inspect_existing(&file.0).expect("whole-absent deletion schema is inspectable");
        drop(Store::open(&file.0).expect("migrate empty deletion schema"));

        let database = redb::Builder::new()
            .open_read_only(&file.0)
            .expect("inspect migrated deletion schema");
        let read = database
            .begin_read()
            .expect("read migrated deletion schema");
        let metadata = read
            .open_table(BLOB_DELETION_METADATA)
            .expect("deletion metadata");
        assert_eq!(metadata.len().expect("metadata length"), 12);
        for (field, expected) in [
            (
                BLOB_DELETION_SCHEMA_VERSION_FIELD,
                BLOB_DELETION_SCHEMA_VERSION,
            ),
            (BLOB_DELETION_MAINTENANCE_TURN, 0),
            (BLOB_DELETION_MANIFEST_ROWS, 0),
            (BLOB_DELETION_MANIFEST_BYTES, 0),
            (BLOB_DELETION_CHUNK_ROWS, 0),
            (BLOB_DELETION_CHUNK_BYTES, 0),
            (BLOB_DELETION_QUEUED_CHUNKS, 0),
            (BLOB_DELETION_DELETED_CHUNKS, 0),
            (BLOB_DELETION_CHARGED_VARIANTS, 0),
            (BLOB_DELETION_CHARGED_FILES, 0),
            (BLOB_DELETION_CHARGED_RESERVED_BYTES, 0),
            (BLOB_DELETION_CHARGED_COMMITTED_BYTES, 0),
        ] {
            assert_eq!(
                metadata
                    .get(field)
                    .expect("read deletion metadata field")
                    .map(|value| value.value()),
                Some(expected),
                "unexpected deletion metadata field {field}",
            );
        }
        assert_eq!(
            read.open_table(BLOB_DELETION_MANIFESTS)
                .expect("deletion manifests")
                .len()
                .expect("manifest length"),
            0
        );
        assert_eq!(
            read.open_table(BLOB_DELETION_CHUNKS)
                .expect("deletion chunks")
                .len()
                .expect("chunk length"),
            0
        );
        assert_eq!(
            read.open_table(BLOB_DELETION_CONTINUITY)
                .expect("deletion continuity")
                .len()
                .expect("continuity length"),
            0
        );
    }

    #[test]
    fn blob_deletion_codecs_reject_noncanonical_phase_chunk_failure_and_totals() {
        let manifest = sample_manifest();
        let encoded = encode_manifest_record(&manifest).expect("encode canonical manifest");
        let encoded_chunks = manifest
            .chunks
            .iter()
            .map(|chunk| encode_chunk_record(chunk).expect("encode canonical chunk"))
            .collect::<Vec<_>>();
        assert_eq!(
            decode_manifest_record(&encoded, &encoded_chunks).expect("decode canonical manifest"),
            manifest
        );

        let mut staging = manifest.clone();
        staging.finalized_root = None;
        staging.totals = BlobDeletionTotals {
            chunks: 2,
            queued: 2,
            deleted: 0,
            charged_variants: 1,
            charged_files: 0,
            charged_reserved_bytes: 211,
            charged_committed_bytes: 0,
        };
        staging.chunks = vec![
            BlobDeletionChunk {
                index: 1,
                state: BlobDeletionChunkState::DeleteQueued,
                original_chunk: vec![0xa1; 90],
                charged_reserved_bytes: 211,
                charged_committed_bytes: 0,
            },
            BlobDeletionChunk {
                index: 3,
                state: BlobDeletionChunkState::DeleteQueued,
                original_chunk: vec![0xa2; 34],
                charged_reserved_bytes: 0,
                charged_committed_bytes: 0,
            },
        ];
        let staging_encoded =
            encode_manifest_record(&staging).expect("encode sparse staging manifest");
        let staging_chunks = staging
            .chunks
            .iter()
            .map(|chunk| encode_chunk_record(chunk).expect("encode staging chunk"))
            .collect::<Vec<_>>();
        assert_eq!(
            decode_manifest_record(&staging_encoded, &staging_chunks)
                .expect("decode sparse staging manifest"),
            staging,
        );

        let mut unknown_phase = encoded.clone();
        unknown_phase[MANIFEST_PHASE_OFFSET] = 0xff;
        assert!(decode_manifest_record(&unknown_phase, &encoded_chunks).is_err());

        let mut reserved_manifest = encoded.clone();
        reserved_manifest[MANIFEST_RESERVED_OFFSET] = 1;
        assert!(decode_manifest_record(&reserved_manifest, &encoded_chunks).is_err());

        let mut unknown_failure = encoded.clone();
        unknown_failure[MANIFEST_FAILURE_OFFSET] = 0xff;
        assert!(decode_manifest_record(&unknown_failure, &encoded_chunks).is_err());

        let mut wrong_totals = encoded.clone();
        wrong_totals[MANIFEST_QUEUED_COUNT_OFFSET..MANIFEST_QUEUED_COUNT_OFFSET + 8]
            .copy_from_slice(&0u64.to_be_bytes());
        assert!(decode_manifest_record(&wrong_totals, &encoded_chunks).is_err());

        let mut unknown_chunk_state = encoded_chunks[0].clone();
        unknown_chunk_state[CHUNK_STATE_OFFSET] = 0xff;
        assert!(decode_manifest_record(&encoded, &[unknown_chunk_state]).is_err());

        let mut reserved_chunk = encoded_chunks[0].clone();
        reserved_chunk[CHUNK_RESERVED_OFFSET] = 1;
        assert!(decode_manifest_record(&encoded, &[reserved_chunk]).is_err());

        let mut phase_mismatch = manifest.clone();
        phase_mismatch.phase = BlobDeletionPhase::DirectoryDeletePending;
        assert!(encode_manifest_record(&phase_mismatch).is_err());

        let mut over_limit = encoded;
        over_limit[MANIFEST_CHUNK_COUNT_OFFSET..MANIFEST_CHUNK_COUNT_OFFSET + 8]
            .copy_from_slice(&(MAX_SELECTED_BLOB_CHUNKS + 1).to_be_bytes());
        assert!(decode_manifest_header(&over_limit).is_err());

        let first_retry = BlobDeletionRetry::default()
            .after_failure(7, BlobDeletionFailureCategory::ChunkUnlink)
            .expect("schedule first retry from durable turn");
        assert_eq!(first_retry.attempts, 1);
        assert_eq!(first_retry.next_retry_turn, 8);
        let second_retry = first_retry
            .after_failure(8, BlobDeletionFailureCategory::ChunkDirectorySync)
            .expect("schedule bounded exponential retry");
        assert_eq!(second_retry.attempts, 2);
        assert_eq!(second_retry.next_retry_turn, 10);
    }

    #[test]
    fn blob_deletion_partial_current_schema_fails_without_repair() {
        let file = DeletionTestFile::new("partial-current");
        drop(Store::open(&file.0).expect("create current deletion schema"));
        {
            let database = Database::open(&file.0).expect("open current deletion schema");
            let write = database.begin_write().expect("begin deletion corruption");
            write
                .delete_table(BLOB_DELETION_CHUNKS)
                .expect("remove one deletion table");
            write.commit().expect("commit partial deletion schema");
        }

        assert!(Store::inspect_existing(&file.0).is_err());
        assert!(Store::open(&file.0).is_err());

        let database = redb::Builder::new()
            .open_read_only(&file.0)
            .expect("inspect unrepaired partial deletion schema");
        let read = database.begin_read().expect("read partial deletion schema");
        let tables = read
            .list_tables()
            .expect("list partial deletion schema")
            .map(|table| table.name().to_owned())
            .collect::<std::collections::BTreeSet<_>>();
        assert!(!tables.contains(BLOB_DELETION_CHUNKS.name()));
        assert!(tables.contains(BLOB_DELETION_METADATA.name()));
        assert!(tables.contains(BLOB_DELETION_MANIFESTS.name()));
        assert!(tables.contains(BLOB_DELETION_CONTINUITY.name()));
    }

    #[test]
    fn blob_deletion_audit_bounds_corrupt_rows_before_large_evidence_allocation() {
        // Break caught: table cardinality and exact import bounds must reject
        // impossible authority before audit clones or decodes hostile 1 MiB rows.
        let oversized = vec![0xa5; MAX_IMPORT_EVIDENCE_BYTES];

        let file = DeletionTestFile::new("durable-cardinality-bound");
        drop(Store::open(&file.0).expect("create durable-bound store"));
        let database = Database::open(&file.0).expect("open durable-bound store");
        let write = database
            .begin_write()
            .expect("begin durable-bound corruption");
        write
            .open_table(BLOB_DELETION_MANIFESTS)
            .expect("durable-bound manifests")
            .insert(&[0x11; 32][..], oversized.as_slice())
            .expect("insert large unaccounted manifest");
        assert_schema_reason(
            &audit_blob_deletion_write(&write, None)
                .expect_err("durable row count must be checked before decoding"),
            "Blob deletion table cardinality disagrees with durable accounting",
        );

        for (label, manifest_row) in [("manifest", true), ("chunk", false)] {
            let file = DeletionTestFile::new(&format!("exact-{label}-bound"));
            drop(Store::open(&file.0).expect("create exact-bound store"));
            let database = Database::open(&file.0).expect("open exact-bound store");
            let write = database
                .begin_write()
                .expect("begin exact-bound corruption");
            let (rows_field, bytes_field, key_len) = if manifest_row {
                (
                    BLOB_DELETION_MANIFEST_ROWS,
                    BLOB_DELETION_MANIFEST_BYTES,
                    32usize,
                )
            } else {
                (BLOB_DELETION_CHUNK_ROWS, BLOB_DELETION_CHUNK_BYTES, 40usize)
            };
            let encoded_bytes =
                u64::try_from(key_len + oversized.len()).expect("adversarial encoded bytes");
            {
                let mut metadata = write
                    .open_table(BLOB_DELETION_METADATA)
                    .expect("exact-bound metadata");
                metadata
                    .insert(rows_field, 1)
                    .expect("set exact-bound rows");
                metadata
                    .insert(bytes_field, encoded_bytes)
                    .expect("set exact-bound bytes");
            }
            if manifest_row {
                write
                    .open_table(BLOB_DELETION_MANIFESTS)
                    .expect("exact-bound manifests")
                    .insert(&[0x22; 32][..], oversized.as_slice())
                    .expect("insert exact-bound manifest");
            } else {
                write
                    .open_table(BLOB_DELETION_CHUNKS)
                    .expect("exact-bound chunks")
                    .insert(&[0x33; 40][..], oversized.as_slice())
                    .expect("insert exact-bound chunk");
            }
            assert_schema_reason(
                &audit_blob_deletion_write(&write, None)
                    .expect_err("exact import bounds must precede decoding"),
                if manifest_row {
                    "Blob deletion manifest rows exceed their exact import bound"
                } else {
                    "Blob deletion chunk rows exceed their exact import bound"
                },
            );
        }
    }

    #[test]
    fn blob_deletion_age_lower_bound_advances_same_domain_and_survives_domain_loss() {
        let file = DeletionTestFile::new("age-continuity");
        drop(Store::open(&file.0).expect("create deletion continuity schema"));
        let clock_a = [0xa1; 16];
        let first_sample = CustodySample {
            clock_id: clock_a,
            tick_ms: 100,
        };

        let database = Database::open(&file.0).expect("open deletion continuity database");
        let write = database.begin_write().expect("begin first age observation");
        let first = observe_blob_deletion_continuity_write(&write, first_sample)
            .expect("anchor first deletion clock");
        assert_eq!(first.generation, 1);
        let age = BlobDeletionAge {
            cumulative_age_ms: 40,
            checkpoint: Some(first_sample),
            continuity_generation: first.generation,
            continuity_lost: false,
        };
        write.commit().expect("commit first deletion clock");

        let write = database
            .begin_write()
            .expect("begin same-domain observation");
        let same_domain = observe_blob_deletion_continuity_write(
            &write,
            CustodySample {
                clock_id: clock_a,
                tick_ms: 175,
            },
        )
        .expect("advance same deletion clock");
        assert_eq!(same_domain.generation, 1);
        let advanced =
            project_blob_deletion_age(age, Some(same_domain), Some(same_domain.last_sample))
                .expect("project same-domain deletion age");
        assert_eq!(advanced.cumulative_age_ms, 115);
        assert!(!advanced.continuity_lost);
        write.commit().expect("commit same-domain deletion clock");

        let write = database.begin_write().expect("begin regressed observation");
        let regressed = observe_blob_deletion_continuity_write(
            &write,
            CustodySample {
                clock_id: clock_a,
                tick_ms: 10,
            },
        )
        .expect("reanchor regressed deletion clock");
        assert_eq!(regressed.generation, 2);
        let after_regression =
            project_blob_deletion_age(advanced, Some(regressed), Some(regressed.last_sample))
                .expect("preserve age across clock regression");
        assert_eq!(after_regression.cumulative_age_ms, 115);
        assert!(after_regression.continuity_lost);
        write.commit().expect("commit regressed deletion clock");

        drop(database);
        let reopened = Database::open(&file.0).expect("reopen deletion continuity database");
        let write = reopened
            .begin_write()
            .expect("begin new-domain observation");
        let new_domain = observe_blob_deletion_continuity_write(
            &write,
            CustodySample {
                clock_id: [0xb2; 16],
                tick_ms: 5,
            },
        )
        .expect("reanchor new deletion clock domain");
        assert_eq!(new_domain.generation, 3);
        let after_domain_loss = project_blob_deletion_age(
            after_regression,
            Some(new_domain),
            Some(new_domain.last_sample),
        )
        .expect("preserve lower bound across domain loss");
        assert_eq!(after_domain_loss.cumulative_age_ms, 115);
        assert!(after_domain_loss.continuity_lost);
        assert_eq!(after_domain_loss.checkpoint, Some(new_domain.last_sample));

        let overflowed = project_blob_deletion_age(
            BlobDeletionAge {
                cumulative_age_ms: u64::MAX - 4,
                checkpoint: Some(CustodySample {
                    clock_id: new_domain.last_sample.clock_id,
                    tick_ms: 0,
                }),
                continuity_generation: new_domain.generation,
                continuity_lost: false,
            },
            Some(new_domain),
            Some(CustodySample {
                clock_id: new_domain.last_sample.clock_id,
                tick_ms: 5,
            }),
        )
        .expect("saturate deletion age overflow");
        assert_eq!(overflowed.cumulative_age_ms, u64::MAX);
        assert!(overflowed.continuity_lost);

        let exhausted = BlobDeletionContinuity {
            generation: u64::MAX,
            last_sample: new_domain.last_sample,
        };
        let exhausted_encoded = encode_continuity(exhausted);
        write
            .open_table(BLOB_DELETION_CONTINUITY)
            .expect("exhausted continuity table")
            .insert(CONTINUITY_KEY, exhausted_encoded.as_slice())
            .expect("install exhausted continuity generation");
        assert!(
            observe_blob_deletion_continuity_write(
                &write,
                CustodySample {
                    clock_id: [0xc3; 16],
                    tick_ms: 0,
                },
            )
            .is_err(),
            "continuity generation overflow must fail closed",
        );
        assert_eq!(
            advance_blob_deletion_maintenance_turn(&write)
                .expect("advance durable deletion maintenance turn"),
            1
        );
        write.commit().expect("commit new deletion clock domain");
    }

    #[test]
    fn blob_deletion_continuity_v2_v3_decode_and_upgrade_canonically_to_v4() {
        let previous = BlobDeletionContinuity {
            generation: 1,
            last_sample: CustodySample {
                clock_id: [0x81; 16],
                tick_ms: 40,
            },
        };
        let current = BlobDeletionContinuity {
            generation: 2,
            last_sample: CustodySample {
                clock_id: [0x82; 16],
                tick_ms: 9,
            },
        };
        let transition = BlobDeletionContinuityTransition {
            previous,
            anchor: CustodySample {
                clock_id: current.last_sample.clock_id,
                tick_ms: 3,
            },
            after: Some(BlobVariantId::from_bytes([0x55; 32])),
            remaining: 2,
        };
        let expected = BlobDeletionContinuityState {
            current,
            transition: Some(transition),
            pending: None,
            deferred: 0,
        };
        let mut encoded = Vec::new();
        encoded.push(PREVIOUS_CONTINUITY_STATE_VERSION);
        encoded.extend_from_slice(&current.generation.to_be_bytes());
        encoded.extend_from_slice(&current.last_sample.clock_id);
        encoded.extend_from_slice(&current.last_sample.tick_ms.to_be_bytes());
        encoded.push(1);
        encoded.extend_from_slice(&previous.generation.to_be_bytes());
        encoded.extend_from_slice(&previous.last_sample.clock_id);
        encoded.extend_from_slice(&previous.last_sample.tick_ms.to_be_bytes());
        encoded.extend_from_slice(&transition.anchor.clock_id);
        encoded.extend_from_slice(&transition.anchor.tick_ms.to_be_bytes());
        encoded.extend_from_slice(&transition.remaining.to_be_bytes());
        encoded.push(1);
        encoded.extend_from_slice(transition.after.expect("v2 cursor").as_bytes().as_slice());

        assert_eq!(
            decode_continuity_state(&encoded).expect("decode v2 continuity"),
            expected
        );
        let upgraded = encode_continuity_state(expected).expect("encode v4 continuity");
        assert_eq!(upgraded[0], CONTINUITY_STATE_VERSION);
        assert_eq!(
            decode_continuity_state(&upgraded).expect("decode upgraded continuity"),
            expected
        );

        let pending = BlobDeletionPendingContinuity {
            current: BlobDeletionContinuity {
                generation: 3,
                last_sample: CustodySample {
                    clock_id: [0x83; 16],
                    tick_ms: 17,
                },
            },
            anchor: CustodySample {
                clock_id: [0x83; 16],
                tick_ms: 11,
            },
            remaining: 4,
        };
        let expected_v3 = BlobDeletionContinuityState {
            current,
            transition: Some(transition),
            pending: Some(pending),
            deferred: 0,
        };
        let mut encoded_v3 = encoded;
        encoded_v3[0] = PENDING_CONTINUITY_STATE_VERSION;
        encoded_v3.push(1);
        encoded_v3.extend_from_slice(&pending.current.generation.to_be_bytes());
        encoded_v3.extend_from_slice(&pending.current.last_sample.clock_id);
        encoded_v3.extend_from_slice(&pending.current.last_sample.tick_ms.to_be_bytes());
        encoded_v3.extend_from_slice(&pending.anchor.clock_id);
        encoded_v3.extend_from_slice(&pending.anchor.tick_ms.to_be_bytes());
        encoded_v3.extend_from_slice(&pending.remaining.to_be_bytes());
        let decoded_v3 = decode_continuity_state(&encoded_v3).expect("decode v3 continuity");
        assert_eq!(decoded_v3, expected_v3);
        let upgraded_v3 = encode_continuity_state(decoded_v3).expect("upgrade v3 continuity to v4");
        assert_eq!(upgraded_v3[0], CONTINUITY_STATE_VERSION);
        assert_eq!(
            decode_continuity_state(&upgraded_v3).expect("decode upgraded v3 continuity"),
            expected_v3
        );

        let expected_v4 = BlobDeletionContinuityState {
            deferred: 5,
            ..expected_v3
        };
        let encoded_v4 = encode_continuity_state(expected_v4).expect("encode v4 continuity");
        assert_eq!(encoded_v4[0], CONTINUITY_STATE_VERSION);
        assert_eq!(
            decode_continuity_state(&encoded_v4).expect("decode v4 continuity"),
            expected_v4
        );
        assert!(decode_continuity_state(&encoded_v4[..encoded_v4.len() - 1]).is_err());
        let mut trailing_v4 = encoded_v4;
        trailing_v4.push(0);
        assert!(decode_continuity_state(&trailing_v4).is_err());
    }

    #[test]
    fn blob_deletion_age_transition_accounts_concurrent_admission_and_finalization() {
        let file = DeletionTestFile::new("age-transition-membership");
        drop(Store::open(&file.0).expect("create deletion continuity schema"));
        let database = Database::open(&file.0).expect("open deletion continuity database");
        let write = database.begin_write().expect("begin transition membership");
        let previous = BlobDeletionContinuity {
            generation: 1,
            last_sample: CustodySample {
                clock_id: [0xc1; 16],
                tick_ms: 40,
            },
        };
        let current = BlobDeletionContinuity {
            generation: 2,
            last_sample: CustodySample {
                clock_id: [0xc2; 16],
                tick_ms: 5,
            },
        };
        let pending = BlobDeletionPendingContinuity {
            current: BlobDeletionContinuity {
                generation: 3,
                last_sample: CustodySample {
                    clock_id: [0xc3; 16],
                    tick_ms: 7,
                },
            },
            anchor: CustodySample {
                clock_id: [0xc3; 16],
                tick_ms: 2,
            },
            remaining: 2,
        };
        store_blob_deletion_continuity_state(
            &write,
            BlobDeletionContinuityState {
                current,
                transition: Some(BlobDeletionContinuityTransition {
                    previous,
                    anchor: current.last_sample,
                    after: Some(BlobVariantId::from_bytes([0xfe; 32])),
                    remaining: 2,
                }),
                pending: Some(pending),
                deferred: 0,
            },
        )
        .expect("store active transition");
        let variant = BlobVariantId::from_bytes([0x01; 32]);
        let unanchored = BlobDeletionAge {
            cumulative_age_ms: 0,
            checkpoint: None,
            continuity_generation: 0,
            continuity_lost: true,
        };
        account_admitted_manifest_in_continuity_transition(&write, variant, unanchored)
            .expect("account concurrent admission");
        let after_admission = blob_deletion_continuity_state_write(&write)
            .expect("read transition after admission")
            .expect("transition state");
        assert_eq!(after_admission.transition.expect("active").remaining, 3);
        assert_eq!(after_admission.transition.expect("active").after, None);
        assert_eq!(after_admission.pending.expect("pending").remaining, 3);

        account_finalized_manifest_in_continuity_transition(&write, variant, unanchored)
            .expect("account concurrent finalization");
        let after_finalization = blob_deletion_continuity_state_write(&write)
            .expect("read transition after finalization")
            .expect("transition state");
        assert_eq!(after_finalization.transition.expect("active").remaining, 2);
        assert_eq!(after_finalization.transition.expect("active").after, None);
        assert_eq!(after_finalization.pending.expect("pending").remaining, 2);

        let deferred = BlobDeletionAge {
            cumulative_age_ms: 0,
            checkpoint: None,
            continuity_generation: pending.current.generation,
            continuity_lost: true,
        };
        account_admitted_manifest_in_continuity_transition(&write, variant, deferred)
            .expect("account admission beyond the queued domain");
        let after_deferred_admission = blob_deletion_continuity_state_write(&write)
            .expect("read transition after deferred admission")
            .expect("transition state");
        assert_eq!(
            after_deferred_admission
                .transition
                .expect("active")
                .remaining,
            2
        );
        assert_eq!(
            after_deferred_admission.transition.expect("active").after,
            None
        );
        assert_eq!(
            after_deferred_admission.pending.expect("pending").remaining,
            2
        );
        assert_eq!(after_deferred_admission.deferred, 1);

        account_finalized_manifest_in_continuity_transition(&write, variant, deferred)
            .expect("account finalization beyond the queued domain");
        let after_deferred_finalization = blob_deletion_continuity_state_write(&write)
            .expect("read transition after deferred finalization")
            .expect("transition state");
        assert_eq!(
            after_deferred_finalization
                .transition
                .expect("active")
                .remaining,
            2
        );
        assert_eq!(
            after_deferred_finalization
                .pending
                .expect("pending")
                .remaining,
            2
        );
        assert_eq!(after_deferred_finalization.deferred, 0);
    }
}
