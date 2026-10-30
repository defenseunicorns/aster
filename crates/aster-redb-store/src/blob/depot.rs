//! Ciphertext file depot paired with the mission-bound redb authority.
//!
//! One fixed depot root is owned by exactly one Store database in its parent
//! directory. Its private marker contains the database-persisted random token
//! and a domain-separated binding. On Unix that binding covers the canonical
//! absolute database path plus the exact device/inode, so copy/restore to a new
//! inode, path move/rename, and same-path replacement fail closed; there is no
//! implicit rebind migration. On non-Unix platforms it covers only the random
//! token plus canonical path: path moves still fail, but same-path copied-DB
//! replacement or rollback resistance is explicitly not proved.

use std::collections::{BTreeMap, BTreeSet};
use std::fs::File;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, RwLockReadGuard, RwLockWriteGuard};

use aster_mesh::{
    BlobChunkRecord, BlobManifest, BlobMetadata as CoreBlobMetadata, BlobPhysicalLineage,
    BlobStore as CoreBlobStore, ContentVerifiedBlobEnvelope,
};
use redb::{ReadableTable, ReadableTableMetadata};

use super::*;

const DEPOT_DIRECTORY: &str = "blob-depot-v1";
const BLOB_PACK_DIRECTORY: &str = "stream-packs-v2";
const DEPOT_OWNER_FILE: &str = ".aster-store-owner-v1";
const DEPOT_OWNER_TEMP_PREFIX: &str = ".aster-store-owner-tmp-";
const DEPOT_PENDING_PREFIX: &str = ".aster-blob-depot-pending-v1-";
const DEPOT_OWNER_MAGIC: &[u8; 8] = b"ASTROWN1";
const DEPOT_OWNER_DOMAIN: &[u8] = b"aster/blob-depot-owner/v1";
// magic || database-persisted owner token || exact path/backing binding digest
const DEPOT_OWNER_FILE_LEN: usize = 72;
const IMPORT_VERSION_V1: u8 = 1;
const IMPORT_VERSION: u8 = 2;
const DEPOT_SCHEMA_VERSION_V1: u64 = 1;
const CHUNK_STATE_VERSION: u8 = 1;
const CHUNK_FILE_VERSION: u8 = 1;
const CHUNK_FILE_MAGIC: &[u8; 8] = b"ASTRDP01";
const CHUNK_FILE_HEADER_LEN: usize = 153;
const CHUNK_FILE_HEADER_BYTES: u64 = CHUNK_FILE_HEADER_LEN as u64;
const BLOB_CHUNK_TAG_BYTES: u32 = 16;
const CANONICAL_MANIFEST_MAGIC: &[u8; 8] = b"ASTRBM01";
const CANONICAL_MANIFEST_VERSION: u16 = 1;
const CANONICAL_PROTOCOL_VERSION: u16 = 1;
const CANONICAL_SUITE_ID: u16 = 1;
const CANONICAL_MANIFEST_DIGEST_DOMAIN: &[u8] = b"aster/blob-manifest/v1";
const CANONICAL_ROUTE_LEAF_DOMAIN: &[u8] = b"aster/blob-route-leaf/v1";
const CANONICAL_ROUTE_NODE_DOMAIN: &[u8] = b"aster/blob-route-node/v1";
const CANONICAL_ROUTE_EMPTY_DOMAIN: &[u8] = b"aster/blob-route-empty/v1";
const CANONICAL_TRANSFER_ID_DOMAIN: &[u8] = b"aster/blob-transfer-object/v1";
const CANONICAL_TRANSFER_FIXED_LEN: u64 = (8 + 2 + 32 + 32 + 8 + 32 + 4 + 1) as u64;
const TEMP_PREFIX: &str = ".aster-blob-tmp-";
const CHUNK_SUFFIX: &str = ".chunk";
const MAX_CHUNK_FILE_BYTES: u64 =
    CHUNK_FILE_HEADER_BYTES + MAX_BLOB_CHUNK_SIZE as u64 + BLOB_CHUNK_TAG_BYTES as u64;
static TEMP_SEQUENCE: AtomicU64 = AtomicU64::new(1);

#[cfg(test)]
thread_local! {
    static TEST_COMPLETION_CHUNK_ROWS_VISITED: std::cell::Cell<u64> = const {
        std::cell::Cell::new(0)
    };
    static TEST_MANIFEST_DELETION_BYTES_READ: std::cell::Cell<u64> = const {
        std::cell::Cell::new(0)
    };
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum DepotFaultPoint {
    TempSynced,
    Renamed,
    DirectorySynced,
    OwnerRootSynced,
    OwnerStagingCreated,
    OwnerTempCreated,
    OwnerTempPartiallyWritten,
    OwnerTempSynced,
    OwnerMarkerRenamed,
    OwnerMarkerDirectorySynced,
    OwnerRenamed,
    OwnerDirectorySynced,
    ManifestChunkBeforeUnlink,
    ManifestChunkUnlinked,
    ManifestChunkDirectorySynced,
    ManifestVariantDirectoryAccess,
    ManifestVariantDirectoryRemove,
    ManifestVariantRemoved,
    ManifestParentSynced,
}

pub(super) struct ManifestDeletionError {
    pub(super) error: Box<StoreError>,
    pub(super) retry: Option<super::deletion::BlobDeletionFailureCategory>,
    pub(super) files_examined: u64,
    pub(super) bytes_examined: u64,
}

struct ManifestFileReadError {
    error: StoreError,
    bytes_read: u64,
}

impl ManifestFileReadError {
    fn before_read(error: StoreError) -> Self {
        Self {
            error,
            bytes_read: 0,
        }
    }
}

impl From<StoreError> for ManifestDeletionError {
    fn from(error: StoreError) -> Self {
        Self {
            error: Box::new(error),
            retry: None,
            files_examined: 0,
            bytes_examined: 0,
        }
    }
}

fn deletion_stage<T>(
    result: Result<T, StoreError>,
    category: super::deletion::BlobDeletionFailureCategory,
) -> Result<T, ManifestDeletionError> {
    result.map_err(|error| {
        let retry = matches!(error, StoreError::Blob(BlobStoreError::Io(_))).then_some(category);
        ManifestDeletionError {
            error: Box::new(error),
            retry,
            files_examined: 1,
            bytes_examined: 0,
        }
    })
}

fn deletion_stage_progress<T>(
    result: Result<T, StoreError>,
    category: super::deletion::BlobDeletionFailureCategory,
    files_examined: u64,
    bytes_examined: u64,
) -> Result<T, ManifestDeletionError> {
    result.map_err(|error| {
        let retry = matches!(error, StoreError::Blob(BlobStoreError::Io(_))).then_some(category);
        ManifestDeletionError {
            error: Box::new(error),
            retry,
            files_examined,
            bytes_examined,
        }
    })
}

#[cfg(test)]
static TEST_DEPOT_FAULTS: std::sync::Mutex<Vec<(PathBuf, DepotFaultPoint)>> =
    std::sync::Mutex::new(Vec::new());

#[cfg(test)]
static TEST_MANIFEST_DELETION_READ_FAULTS: std::sync::Mutex<Vec<(PathBuf, u64)>> =
    std::sync::Mutex::new(Vec::new());

#[cfg(test)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct DepotIoCounts {
    pub full_open_audits: u64,
    pub begin_write_transactions: u64,
    pub root_creations: u64,
    pub authenticated_read_opens: u64,
    pub full_completion_rechecks: u64,
    pub completion_chunk_rows_visited: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct BlobSourceShape {
    pub total_len: u64,
    pub chunk_size: u32,
    pub chunk_count: u64,
}

#[cfg(test)]
pub(super) fn test_depot_io_counts(store: &Store) -> DepotIoCounts {
    DepotIoCounts {
        full_open_audits: store
            .blob_depot_test_counters
            .full_open_audits
            .load(Ordering::Relaxed),
        begin_write_transactions: store
            .blob_depot_test_counters
            .begin_write_transactions
            .load(Ordering::Relaxed),
        root_creations: store
            .blob_depot_test_counters
            .root_creations
            .load(Ordering::Relaxed),
        authenticated_read_opens: store
            .blob_depot_test_counters
            .authenticated_read_opens
            .load(Ordering::Relaxed),
        full_completion_rechecks: store
            .blob_depot_test_counters
            .full_completion_rechecks
            .load(Ordering::Relaxed),
        completion_chunk_rows_visited: TEST_COMPLETION_CHUNK_ROWS_VISITED
            .with(std::cell::Cell::get),
    }
}

pub(super) fn committed_pending_plan_chunks_read(
    read: &redb::ReadTransaction,
    plan: &VerifiedBlobTransferPlan,
) -> Result<BTreeSet<u64>, StoreError> {
    let manifest = plan.manifest();
    let variant_id = blob_variant_id(
        manifest.id(),
        manifest.content_group(),
        manifest.content_epoch(),
    );
    let import = load_import_read(read, variant_id)?
        .ok_or_else(|| blob_error(BlobStoreError::PendingSourceConflict))?;
    if !import.matches_manifest(manifest)
        || import.variant_id != variant_id
        || import.physical_lineage != Some(*plan.physical_lineage().binding())
        || import
            .finalized_manifest_digest
            .is_some_and(|digest| digest != *plan.manifest_digest())
    {
        return Err(blob_error(BlobStoreError::PendingSourceConflict));
    }
    let mut committed = BTreeSet::new();
    for (index, record) in plan.chunk_records().iter().copied().enumerate() {
        let index = u64::try_from(index).map_err(|_| StoreError::ItemCountAccountingOverflow)?;
        let state = load_chunk_read(read, variant_id, index)?
            .ok_or_else(|| blob_error(BlobStoreError::PendingSourceConflict))?;
        if state.plaintext_digest != Some(*record.plaintext_sha256())
            || state.expected != Some(record)
            || state.committed.is_some_and(|committed| committed != record)
            || (state.committed == Some(record)
                && state.committed_file_bytes != chunk_file_len(record)?)
            || (state.committed.is_none() && state.committed_file_bytes != 0)
        {
            return Err(blob_error(BlobStoreError::PendingSourceConflict));
        }
        if state.committed == Some(record) {
            committed.insert(index);
        }
    }
    Ok(committed)
}

#[allow(clippy::too_many_arguments)]
pub(super) fn blob_source_shape_read(
    read: &redb::ReadTransaction,
    variant_id: BlobVariantId,
    blob_id: BlobId,
    epoch: u64,
    physical_lineage: [u8; 32],
    manifest_digest: [u8; 32],
    route_chunk_count: u64,
    completed: bool,
) -> Result<BlobSourceShape, StoreError> {
    if let Some(encoded) = read
        .open_table(super::pack_lifecycle::BLOB_PROFILE5_PACKS)?
        .get(variant_id.as_bytes().as_slice())?
        .map(|value| value.value().to_vec())
    {
        if !completed {
            return Err(blob_error(BlobStoreError::SchemaInvariant(
                "provisional retained source cannot reference an active Profile-5 pack",
            )));
        }
        let owner_binding = depot_owner_binding_if_present_read(read)?.ok_or_else(|| {
            blob_error(BlobStoreError::SchemaInvariant(
                "Profile-5 pack exists without depot owner binding",
            ))
        })?;
        let (total_len, segment_count) = super::pack_lifecycle::source_shape_evidence(
            &encoded,
            variant_id,
            blob_id,
            epoch,
            manifest_digest,
            route_chunk_count,
            physical_lineage,
            owner_binding,
        )?;
        return Ok(BlobSourceShape {
            total_len,
            chunk_size: aster_mesh::BLOB_STREAM_SEGMENT_BYTES as u32,
            chunk_count: segment_count,
        });
    }
    let import = load_import_read(read, variant_id)?.ok_or_else(|| {
        blob_error(BlobStoreError::SchemaInvariant(
            "retained Blob source is missing its exact depot import",
        ))
    })?;
    let expected_chunks = (import.chunk_size != 0)
        .then(|| {
            import
                .total_len
                .checked_add(u64::from(import.chunk_size) - 1)
                .map(|bytes| bytes / u64::from(import.chunk_size))
        })
        .flatten();
    if import.variant_id != variant_id
        || import.variant_id != blob_variant_id(blob_id, &import.content_group, epoch)
        || import.blob_id != blob_id
        || import.epoch != epoch
        || import.physical_lineage != Some(physical_lineage)
        || import.chunk_size != SELECTED_BLOB_CHUNK_SIZE
        || import.chunk_count != route_chunk_count
        || expected_chunks != Some(import.chunk_count)
        || (completed && import.finalized_manifest_digest != Some(manifest_digest))
        || (!completed
            && import
                .finalized_manifest_digest
                .is_some_and(|digest| digest != manifest_digest))
    {
        return Err(blob_error(BlobStoreError::SchemaInvariant(
            "retained Blob source differs from its exact depot shape",
        )));
    }
    Ok(BlobSourceShape {
        total_len: import.total_len,
        chunk_size: import.chunk_size,
        chunk_count: import.chunk_count,
    })
}

#[allow(clippy::too_many_arguments)]
pub(super) fn blob_source_shape_write(
    write: &redb::WriteTransaction,
    variant_id: BlobVariantId,
    blob_id: BlobId,
    epoch: u64,
    physical_lineage: [u8; 32],
    manifest_digest: [u8; 32],
    route_chunk_count: u64,
    completed: bool,
) -> Result<BlobSourceShape, StoreError> {
    if let Some(encoded) = write
        .open_table(super::pack_lifecycle::BLOB_PROFILE5_PACKS)?
        .get(variant_id.as_bytes().as_slice())?
        .map(|value| value.value().to_vec())
    {
        if !completed {
            return Err(blob_error(BlobStoreError::SchemaInvariant(
                "provisional retained source cannot reference an active Profile-5 pack",
            )));
        }
        let owner_binding = depot_owner_binding_if_present_write(write)?.ok_or_else(|| {
            blob_error(BlobStoreError::SchemaInvariant(
                "Profile-5 pack exists without depot owner binding",
            ))
        })?;
        let (total_len, segment_count) = super::pack_lifecycle::source_shape_evidence(
            &encoded,
            variant_id,
            blob_id,
            epoch,
            manifest_digest,
            route_chunk_count,
            physical_lineage,
            owner_binding,
        )?;
        return Ok(BlobSourceShape {
            total_len,
            chunk_size: aster_mesh::BLOB_STREAM_SEGMENT_BYTES as u32,
            chunk_count: segment_count,
        });
    }
    let import = load_import_write(write, variant_id)?.ok_or_else(|| {
        blob_error(BlobStoreError::SchemaInvariant(
            "retained Blob source is missing its exact depot import",
        ))
    })?;
    let expected_chunks = (import.chunk_size != 0)
        .then(|| {
            import
                .total_len
                .checked_add(u64::from(import.chunk_size) - 1)
                .map(|bytes| bytes / u64::from(import.chunk_size))
        })
        .flatten();
    if import.variant_id != variant_id
        || import.variant_id != blob_variant_id(blob_id, &import.content_group, epoch)
        || import.blob_id != blob_id
        || import.epoch != epoch
        || import.physical_lineage != Some(physical_lineage)
        || import.chunk_size != SELECTED_BLOB_CHUNK_SIZE
        || import.chunk_count != route_chunk_count
        || expected_chunks != Some(import.chunk_count)
        || (completed && import.finalized_manifest_digest != Some(manifest_digest))
        || (!completed
            && import
                .finalized_manifest_digest
                .is_some_and(|digest| digest != manifest_digest))
    {
        return Err(blob_error(BlobStoreError::SchemaInvariant(
            "retained Blob source differs from its exact depot shape",
        )));
    }
    Ok(BlobSourceShape {
        total_len: import.total_len,
        chunk_size: import.chunk_size,
        chunk_count: import.chunk_count,
    })
}

#[cfg(test)]
pub(super) fn inject_test_fault(state_root: &Path, point: DepotFaultPoint) {
    TEST_DEPOT_FAULTS
        .lock()
        .expect("Blob test fault lock")
        .push((state_root.to_path_buf(), point));
}

#[cfg(test)]
pub(super) fn inject_manifest_deletion_read_fault_for_test(path: &Path, after_bytes: u64) {
    TEST_MANIFEST_DELETION_READ_FAULTS
        .lock()
        .expect("Blob manifest deletion read fault lock")
        .push((path.to_path_buf(), after_bytes));
}

#[cfg(test)]
pub(super) fn reset_manifest_deletion_read_observation_for_test() {
    TEST_MANIFEST_DELETION_BYTES_READ.set(0);
}

#[cfg(test)]
pub(super) fn take_manifest_deletion_read_observation_for_test() -> u64 {
    let bytes = TEST_MANIFEST_DELETION_BYTES_READ.get();
    TEST_MANIFEST_DELETION_BYTES_READ.set(0);
    bytes
}

#[cfg(test)]
fn manifest_deletion_read_limit_for_test(
    path: &Path,
    bytes_read: u64,
) -> Result<Option<usize>, StoreError> {
    let mut faults = TEST_MANIFEST_DELETION_READ_FAULTS.lock().map_err(|_| {
        blob_error(BlobStoreError::DepotIntegrity(
            "Blob manifest deletion read fault lock is poisoned",
        ))
    })?;
    let Some(index) = faults.iter().position(|(expected, _)| expected == path) else {
        return Ok(None);
    };
    let after_bytes = faults[index].1;
    if bytes_read >= after_bytes {
        faults.swap_remove(index);
        return Err(blob_error(BlobStoreError::Io(std::io::Error::other(
            "injected Blob manifest deletion read failure",
        ))));
    }
    Ok(Some(
        usize::try_from(after_bytes - bytes_read)
            .unwrap_or(usize::MAX)
            .min(8 * 1024),
    ))
}

#[cfg(not(test))]
fn manifest_deletion_read_limit_for_test(
    _path: &Path,
    _bytes_read: u64,
) -> Result<Option<usize>, StoreError> {
    Ok(None)
}

#[cfg(test)]
fn observe_manifest_deletion_read(bytes: u64) {
    TEST_MANIFEST_DELETION_BYTES_READ.set(
        TEST_MANIFEST_DELETION_BYTES_READ
            .get()
            .checked_add(bytes)
            .expect("Blob manifest deletion read observation overflow"),
    );
}

#[cfg(not(test))]
fn observe_manifest_deletion_read(_bytes: u64) {}

#[cfg(test)]
fn maybe_inject_fault(path: &Path, point: DepotFaultPoint) -> Result<(), StoreError> {
    let mut faults = TEST_DEPOT_FAULTS.lock().map_err(|_| {
        blob_error(BlobStoreError::DepotIntegrity(
            "Blob test fault lock is poisoned",
        ))
    })?;
    let matching = faults.iter().position(|(root, expected)| {
        let fixed = path.starts_with(root.join(DEPOT_DIRECTORY));
        let pending = path.parent() == Some(root.as_path())
            && path
                .file_name()
                .and_then(|name| name.to_str())
                .is_some_and(|name| name.starts_with(DEPOT_PENDING_PREFIX));
        (fixed || pending) && *expected == point
    });
    if let Some(index) = matching {
        faults.swap_remove(index);
        return Err(blob_error(BlobStoreError::Io(std::io::Error::other(
            "injected Blob depot crash boundary",
        ))));
    }
    Ok(())
}

#[cfg(not(test))]
fn maybe_inject_fault(_path: &Path, _point: DepotFaultPoint) -> Result<(), StoreError> {
    Ok(())
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct ImportRecord {
    variant_id: BlobVariantId,
    blob_id: BlobId,
    content_group: [u8; 32],
    epoch: u64,
    total_len: u64,
    chunk_size: u32,
    chunk_count: u64,
    whole_plaintext_sha256: [u8; 32],
    media_type: Option<String>,
    schema_id: Vec<u8>,
    physical_lineage: Option<[u8; 32]>,
    finalized_manifest_digest: Option<[u8; 32]>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct AuditedLifecycleImport {
    pub(super) variant_id: BlobVariantId,
    pub(super) physical_lineage: [u8; 32],
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct MaintenanceImportProjection {
    pub(super) variant_id: BlobVariantId,
    pub(super) physical_lineage: [u8; 32],
    pub(super) finalized: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct DeletionImportProjection {
    pub(super) variant_id: BlobVariantId,
    pub(super) blob_id: BlobId,
    pub(super) content_group: [u8; 32],
    pub(super) epoch: u64,
    pub(super) total_len: u64,
    pub(super) chunk_count: u64,
    pub(super) physical_lineage: [u8; 32],
    pub(super) finalized_root: Option<[u8; 32]>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct DeletionChunkProjection {
    pub(super) record: Option<BlobChunkRecord>,
    pub(super) cleanup: DeletionChunkCleanupAuthority,
    pub(super) authorized_file_bytes: u64,
    pub(super) charged_reserved_bytes: u64,
    pub(super) charged_committed_bytes: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum DeletionChunkCleanupAuthority {
    Committed(BlobChunkRecord),
    Expected(BlobChunkRecord),
    Digest([u8; 32]),
    Absent,
}

impl ImportRecord {
    fn from_manifest(
        manifest: &BlobManifest,
        physical_lineage: Option<BlobPhysicalLineage>,
    ) -> Result<Self, StoreError> {
        if manifest.chunk_size() != SELECTED_BLOB_CHUNK_SIZE
            || manifest.chunk_count() > MAX_SELECTED_BLOB_CHUNKS
            || manifest.content_epoch() == 0
        {
            return Err(blob_error(BlobStoreError::InvalidPublication(
                "depot manifest violates the selected fixed-chunk profile",
            )));
        }
        let blob_id = manifest.id();
        let content_group = *manifest.content_group();
        let epoch = manifest.content_epoch();
        Ok(Self {
            variant_id: blob_variant_id(blob_id, &content_group, epoch),
            blob_id,
            content_group,
            epoch,
            total_len: manifest.total_len(),
            chunk_size: manifest.chunk_size(),
            chunk_count: manifest.chunk_count(),
            whole_plaintext_sha256: *manifest.whole_plaintext_sha256(),
            media_type: manifest.metadata().media_type().map(str::to_owned),
            schema_id: manifest.metadata().schema_id().to_vec(),
            physical_lineage: physical_lineage.map(|lineage| *lineage.binding()),
            finalized_manifest_digest: None,
        })
    }

    fn matches_manifest(&self, manifest: &BlobManifest) -> bool {
        self.blob_id == manifest.id()
            && self.content_group == *manifest.content_group()
            && self.epoch == manifest.content_epoch()
            && self.total_len == manifest.total_len()
            && self.chunk_size == manifest.chunk_size()
            && self.chunk_count == manifest.chunk_count()
            && self.whole_plaintext_sha256 == *manifest.whole_plaintext_sha256()
            && self.media_type.as_deref() == manifest.metadata().media_type()
            && self.schema_id == manifest.metadata().schema_id()
            && self.variant_id
                == blob_variant_id(
                    manifest.id(),
                    manifest.content_group(),
                    manifest.content_epoch(),
                )
    }
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
struct ChunkState {
    plaintext_digest: Option<[u8; 32]>,
    expected: Option<BlobChunkRecord>,
    committed: Option<BlobChunkRecord>,
    committed_file_bytes: u64,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub(super) struct DepotStats {
    pub variants: u64,
    pub finalized_variants: u64,
    pub committed_chunks: u64,
    pub committed_file_bytes: u64,
    pub reserved_file_bytes: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct ActiveImport {
    variant_id: BlobVariantId,
    blob_id: BlobId,
    content_group: [u8; 32],
    epoch: u64,
    total_len: u64,
    chunk_count: u64,
    physical_lineage: Option<[u8; 32]>,
}

/// Nonconstructible proof that every chunk in one exact depot variant is marked and intact.
#[derive(Clone, Debug)]
pub struct BlobDepotCompletion {
    pub(super) authority: Arc<()>,
    pub(super) backing_identity: StoreBackingIdentity,
    pub(super) variant_id: BlobVariantId,
    pub(super) blob_id: BlobId,
    pub(super) content_group: [u8; 32],
    pub(super) epoch: u64,
    pub(super) physical_lineage: [u8; 32],
    pub(super) manifest_digest: [u8; 32],
    pub(super) total_len: u64,
    pub(super) chunk_size: u32,
    pub(super) chunk_count: u64,
    pub(super) import_fingerprint: [u8; 32],
}

impl PartialEq for BlobDepotCompletion {
    fn eq(&self, other: &Self) -> bool {
        Arc::ptr_eq(&self.authority, &other.authority)
            && self.backing_identity == other.backing_identity
            && self.variant_id == other.variant_id
            && self.blob_id == other.blob_id
            && self.content_group == other.content_group
            && self.epoch == other.epoch
            && self.physical_lineage == other.physical_lineage
            && self.manifest_digest == other.manifest_digest
            && self.total_len == other.total_len
            && self.chunk_size == other.chunk_size
            && self.chunk_count == other.chunk_count
            && self.import_fingerprint == other.import_fingerprint
    }
}

impl Eq for BlobDepotCompletion {}

impl BlobDepotCompletion {
    pub const fn variant_id(&self) -> BlobVariantId {
        self.variant_id
    }

    pub const fn blob_id(&self) -> BlobId {
        self.blob_id
    }

    pub const fn content_epoch(&self) -> u64 {
        self.epoch
    }

    pub const fn manifest_digest(&self) -> &[u8; 32] {
        &self.manifest_digest
    }

    pub const fn total_len(&self) -> u64 {
        self.total_len
    }

    pub const fn chunk_size(&self) -> u32 {
        self.chunk_size
    }

    pub const fn chunk_count(&self) -> u64 {
        self.chunk_count
    }

    /// Opaque provider-owned identity of the physical content-key lineage.
    pub const fn physical_lineage(&self) -> &[u8; 32] {
        &self.physical_lineage
    }
}

/// Borrowed, single-owner adapter from the generic core Blob engine to this Store.
#[allow(dead_code)] // Variant payloads are held solely for their RAII lock lifetime.
enum BlobDepotGuard<'a> {
    Read(RwLockReadGuard<'a, ()>),
    Write(RwLockWriteGuard<'a, ()>),
}

pub struct BlobDepot<'a> {
    store: &'a Store,
    _guard: BlobDepotGuard<'a>,
    _lease: Option<Arc<super::lease::BlobLeaseHandle>>,
    root: OwnedDirectory,
    active: Option<ActiveImport>,
    read_authorized_variant: Option<BlobVariantId>,
    upload_credit: Option<super::upload::BlobUploadCreditClaim>,
}

/// Capability-gated, mutation-incapable adapter for one finalized Blob variant.
///
/// This deliberately implements the generic core store seam so authenticated
/// range reads can reuse the core engine, but every mutating trait operation
/// fails closed before entering redb or touching the depot filesystem.
pub struct AuthenticatedBlobReadDepot<'a> {
    depot: BlobDepot<'a>,
}

impl AuthenticatedBlobReadDepot<'_> {
    pub(super) fn owned_lease_guard(
        &self,
    ) -> Result<Arc<super::lease::BlobLeaseHandle>, StoreError> {
        self.depot._lease.as_ref().map(Arc::clone).ok_or_else(|| {
            blob_error(BlobStoreError::SchemaInvariant(
                "authenticated Blob read adapter is missing its lease",
            ))
        })
    }

    /// Rechecks the complete exact finalized variant authorized by the
    /// nonconstructible completion capability.
    pub fn recheck_completion(
        &mut self,
        completion: &BlobDepotCompletion,
    ) -> Result<(), StoreError> {
        self.depot.recheck_completion(completion)
    }

    /// Rechecks only the exact chunk files intersecting one bounded range.
    pub fn recheck_completion_range(
        &mut self,
        completion: &BlobDepotCompletion,
        first_chunk: u64,
        chunk_count: u64,
    ) -> Result<(), StoreError> {
        self.depot
            .recheck_completion_range(completion, first_chunk, chunk_count)
    }
}

fn authenticated_read_mutation_error() -> StoreError {
    blob_error(BlobStoreError::CompletionMismatch)
}

impl CoreBlobStore for AuthenticatedBlobReadDepot<'_> {
    type StoreError = StoreError;

    fn begin_blob(&mut self, _manifest: &BlobManifest) -> Result<(), Self::StoreError> {
        Err(authenticated_read_mutation_error())
    }

    fn begin_blob_with_lineage(
        &mut self,
        _manifest: &BlobManifest,
        _lineage: BlobPhysicalLineage,
    ) -> Result<(), Self::StoreError> {
        Err(authenticated_read_mutation_error())
    }

    fn select_blob_for_read_with_lineage(
        &mut self,
        manifest: &BlobManifest,
        lineage: BlobPhysicalLineage,
    ) -> Result<(), Self::StoreError> {
        CoreBlobStore::select_blob_for_read_with_lineage(&mut self.depot, manifest, lineage)
    }

    fn put_plaintext_digest(
        &mut self,
        _id: BlobId,
        _index: u64,
        _digest: [u8; 32],
    ) -> Result<(), Self::StoreError> {
        Err(authenticated_read_mutation_error())
    }

    fn plaintext_digest(
        &mut self,
        id: BlobId,
        index: u64,
    ) -> Result<Option<[u8; 32]>, Self::StoreError> {
        CoreBlobStore::plaintext_digest(&mut self.depot, id, index)
    }

    fn chunk_record(
        &mut self,
        id: BlobId,
        index: u64,
    ) -> Result<Option<BlobChunkRecord>, Self::StoreError> {
        CoreBlobStore::chunk_record(&mut self.depot, id, index)
    }

    fn put_expected_chunk_record(
        &mut self,
        _id: BlobId,
        _index: u64,
        _record: BlobChunkRecord,
    ) -> Result<(), Self::StoreError> {
        Err(authenticated_read_mutation_error())
    }

    fn expected_chunk_record(
        &mut self,
        id: BlobId,
        index: u64,
    ) -> Result<Option<BlobChunkRecord>, Self::StoreError> {
        CoreBlobStore::expected_chunk_record(&mut self.depot, id, index)
    }

    fn commit_verified_chunk(
        &mut self,
        _id: BlobId,
        _index: u64,
        _record: BlobChunkRecord,
        _ciphertext: &[u8],
    ) -> Result<(), Self::StoreError> {
        Err(authenticated_read_mutation_error())
    }

    fn read_verified_chunk(
        &mut self,
        id: BlobId,
        index: u64,
        output: &mut Vec<u8>,
    ) -> Result<bool, Self::StoreError> {
        CoreBlobStore::read_verified_chunk(&mut self.depot, id, index, output)
    }

    fn finalize_blob(
        &mut self,
        _id: BlobId,
        _manifest_digest: [u8; 32],
    ) -> Result<(), Self::StoreError> {
        Err(authenticated_read_mutation_error())
    }

    fn finalized_manifest_digest(
        &mut self,
        id: BlobId,
    ) -> Result<Option<[u8; 32]>, Self::StoreError> {
        CoreBlobStore::finalized_manifest_digest(&mut self.depot, id)
    }
}

impl<'a> BlobDepot<'a> {
    pub(super) fn acquire_local_import_attempt(
        &mut self,
        staging: BlobTransferId,
    ) -> Result<super::lease::BlobLocalImportLease, StoreError> {
        if self._lease.is_some() {
            return Err(blob_error(BlobStoreError::SchemaInvariant(
                "Blob local-import attempt already has a lease",
            )));
        }
        let guard = self
            .store
            .blob_lease_registry
            .acquire(
                self.store.blob_depot_owner_binding,
                super::lease::BlobLeaseTarget::Staging(staging),
                super::lease::BlobLeaseKind::LocalImport,
            )
            .map_err(super::lease::store_error)?;
        let handle = Arc::new(super::lease::BlobLeaseHandle::new(guard));
        self._lease = Some(Arc::clone(&handle));
        Ok(super::lease::BlobLocalImportLease::new(handle))
    }

    fn ensure_variant_lease(
        &mut self,
        variant: BlobVariantId,
        kind: super::lease::BlobLeaseKind,
    ) -> Result<(), StoreError> {
        let target = super::lease::BlobLeaseTarget::Variant(variant);
        if let Some(existing) = self._lease.as_ref() {
            let existing_target = existing.target().map_err(super::lease::store_error)?;
            let existing_kind = existing.kind().map_err(super::lease::store_error)?;
            if matches!(existing_target, super::lease::BlobLeaseTarget::Staging(_))
                && existing_kind == super::lease::BlobLeaseKind::LocalImport
                && kind == super::lease::BlobLeaseKind::LocalImport
            {
                self.store.require_live()?;
                let read = self.store.database.begin_read()?;
                super::deletion::require_variant_available_read(&read, variant)?;
                drop(read);
                existing
                    .rebind_target(target)
                    .map_err(super::lease::store_error)?;
                return Ok(());
            }
            if existing_target == target && existing_kind.can_reuse_as(kind) {
                return Ok(());
            }
            if existing_target == target {
                return Err(blob_error(BlobStoreError::SchemaInvariant(
                    "Blob depot lease class cannot authorize this operation",
                )));
            }
            return Err(blob_error(BlobStoreError::SchemaInvariant(
                "Blob depot lease target changed while the adapter remained active",
            )));
        }
        self.store.require_live()?;
        let read = self.store.database.begin_read()?;
        super::deletion::require_variant_available_read(&read, variant)?;
        drop(read);
        let guard = self
            .store
            .blob_lease_registry
            .acquire(self.store.blob_depot_owner_binding, target, kind)
            .map_err(super::lease::store_error)?;
        self._lease = Some(Arc::new(super::lease::BlobLeaseHandle::new(guard)));
        Ok(())
    }

    pub(super) fn acquire_internal_chunk_work_lease(
        &mut self,
        variant: BlobVariantId,
    ) -> Result<(), StoreError> {
        self.ensure_variant_lease(variant, super::lease::BlobLeaseKind::InternalChunkWork)
    }

    pub(super) fn open(store: &'a Store) -> Result<Self, StoreError> {
        let guard = store
            .blob_depot_lock
            .write()
            .map_err(|_| blob_error(BlobStoreError::DepotIntegrity("depot lock is poisoned")))?;
        // Close the precheck/lock race with terminal entry, which flips the
        // live gate before waiting for this same adapter lock.
        store.require_live()?;
        #[cfg(test)]
        store
            .blob_depot_test_counters
            .full_open_audits
            .fetch_add(1, Ordering::Relaxed);
        let read = store.database.begin_read()?;
        let stats = inspect_blob_tables_read(&read)?.stats;
        let depot_empty =
            stats.variants == 0 && stats.committed_chunks == 0 && stats.committed_file_bytes == 0;
        drop(read);
        let root = match OwnedDirectory::open_root_if_present(&store.path)? {
            Some(root) => match root.read_owner_marker()? {
                Some(_) => {
                    root.require_store_binding(
                        &store.path,
                        store.backing_identity,
                        store.blob_depot_owner_token,
                    )?;
                    root
                }
                None => {
                    return Err(blob_error(BlobStoreError::DepotIntegrity(
                        "fixed Blob depot root is missing its owner marker",
                    )));
                }
            },
            None if depot_empty => Self::create_bound_root(store)?,
            None => {
                return Err(blob_error(BlobStoreError::DepotIntegrity(
                    "populated Blob depot root is missing",
                )));
            }
        };
        Ok(Self {
            store,
            _guard: BlobDepotGuard::Write(guard),
            _lease: None,
            root,
            active: None,
            read_authorized_variant: None,
            upload_credit: None,
        })
    }

    /// Opens the depot for one authenticated network-plan mutation without a
    /// global Blob-table audit. Store open already established global schema
    /// truth; this hot path reacquires the common owner lock, rechecks terminal
    /// state and exact database/filesystem ownership, and either opens the
    /// existing root or creates it only from canonical empty depot counters.
    pub(super) fn open_network_mutation(
        store: &'a Store,
        allow_empty_root_creation: bool,
    ) -> Result<Self, StoreError> {
        let guard = store
            .blob_depot_lock
            .write()
            .map_err(|_| blob_error(BlobStoreError::DepotIntegrity("depot lock is poisoned")))?;
        store.require_live()?;
        let read = store.database.begin_read()?;
        require_depot_owner_binding_read(
            &read,
            &store.path,
            store.backing_identity,
            store.blob_depot_owner_token,
        )?;
        let root = match OwnedDirectory::open_root_if_present(&store.path)? {
            Some(root) => {
                root.require_store_binding_read_only(
                    &store.path,
                    store.backing_identity,
                    store.blob_depot_owner_token,
                )?;
                root
            }
            None if allow_empty_root_creation && depot_is_canonical_empty_read(&read)? => {
                drop(read);
                Self::create_bound_root(store)?
            }
            None => {
                return Err(blob_error(BlobStoreError::DepotIntegrity(
                    "populated Blob depot root is missing",
                )));
            }
        };
        Ok(Self {
            store,
            _guard: BlobDepotGuard::Write(guard),
            _lease: None,
            root,
            active: None,
            read_authorized_variant: None,
            upload_credit: None,
        })
    }

    pub(super) fn open_upload_mutation(
        store: &'a Store,
        reservation: &super::upload::BlobUploadReservation,
    ) -> Result<Self, StoreError> {
        let claim = super::upload::upload_credit_claim(store, reservation)?;
        let mut depot = Self::open_network_mutation(store, true)?;
        depot.upload_credit = Some(claim);
        Ok(depot)
    }

    /// Opens an exact finalized variant for a capability-authorized read
    /// without a global Blob-table audit, write transaction, or root creation.
    pub(super) fn open_authenticated_read(
        store: &'a Store,
        completion: &BlobDepotCompletion,
    ) -> Result<AuthenticatedBlobReadDepot<'a>, StoreError> {
        Self::open_authenticated_read_with_kind(
            store,
            completion,
            super::lease::BlobLeaseKind::ApplicationPageRead,
        )
    }

    pub(super) fn open_authenticated_read_with_kind(
        store: &'a Store,
        completion: &BlobDepotCompletion,
        lease_kind: super::lease::BlobLeaseKind,
    ) -> Result<AuthenticatedBlobReadDepot<'a>, StoreError> {
        Self::open_authenticated_read_internal(store, completion, Some(lease_kind), None, None)
    }

    /// Opens the same mutation-denying authenticated adapter without consuming
    /// an application-page slot. The only caller is pending full-content
    /// verification, whose durable pending reference and held depot lock
    /// already exclude deletion for the adapter's complete lifetime.
    pub(super) fn open_authenticated_read_without_lease(
        store: &'a Store,
        source: BlobTransferId,
        completion: &BlobDepotCompletion,
    ) -> Result<AuthenticatedBlobReadDepot<'a>, StoreError> {
        Self::open_authenticated_read_internal(store, completion, None, Some(source), None)
    }

    fn open_authenticated_read_internal(
        store: &'a Store,
        completion: &BlobDepotCompletion,
        lease_kind: Option<super::lease::BlobLeaseKind>,
        required_pending: Option<BlobTransferId>,
        existing_lease: Option<Arc<super::lease::BlobLeaseHandle>>,
    ) -> Result<AuthenticatedBlobReadDepot<'a>, StoreError> {
        let guard = if lease_kind.is_some() || existing_lease.is_some() {
            BlobDepotGuard::Read(store.blob_depot_lock.read().map_err(|_| {
                blob_error(BlobStoreError::DepotIntegrity("depot lock is poisoned"))
            })?)
        } else {
            BlobDepotGuard::Write(store.blob_depot_lock.write().map_err(|_| {
                blob_error(BlobStoreError::DepotIntegrity("depot lock is poisoned"))
            })?)
        };
        store.require_live()?;
        if !Arc::ptr_eq(&completion.authority, &store.blob_completion_authority)
            || completion.backing_identity != store.backing_identity
        {
            return Err(blob_error(BlobStoreError::CompletionMismatch));
        }
        let read = store.database.begin_read()?;
        require_depot_owner_binding_read(
            &read,
            &store.path,
            store.backing_identity,
            store.blob_depot_owner_token,
        )?;
        if let Some(source) = required_pending {
            let pending = read
                .open_table(super::BLOB_PENDING_SOURCES)?
                .get(source.as_bytes().as_slice())?
                .map(|value| super::decode_pending_blob_source(value.value()))
                .transpose()?
                .ok_or_else(|| blob_error(BlobStoreError::PendingSourceMissing))?;
            if pending.metadata.transfer_id != source
                || pending.metadata.variant_id != completion.variant_id
            {
                return Err(blob_error(BlobStoreError::CompletionMismatch));
            }
        }
        let root = OwnedDirectory::open_root_if_present(&store.path)?.ok_or_else(|| {
            blob_error(BlobStoreError::DepotIntegrity(
                "completed Blob depot root is missing",
            ))
        })?;
        root.require_store_binding_read_only(
            &store.path,
            store.backing_identity,
            store.blob_depot_owner_token,
        )?;
        let mut depot = Self {
            store,
            _guard: guard,
            _lease: None,
            root,
            active: None,
            read_authorized_variant: Some(completion.variant_id),
            upload_credit: None,
        };
        let import = depot.exact_completion_import(&read, completion)?;
        super::deletion::require_variant_available_read(&read, completion.variant_id)?;
        drop(read);
        depot._lease = if let Some(existing) = existing_lease {
            Some(existing)
        } else {
            lease_kind
                .map(|kind| {
                    store
                        .blob_lease_registry
                        .acquire(
                            store.blob_depot_owner_binding,
                            super::lease::BlobLeaseTarget::Variant(completion.variant_id),
                            kind,
                        )
                        .map(|guard| Arc::new(super::lease::BlobLeaseHandle::new(guard)))
                        .map_err(super::lease::store_error)
                })
                .transpose()?
        };
        depot.active = Some(active_from_import(&import));
        #[cfg(test)]
        store
            .blob_depot_test_counters
            .authenticated_read_opens
            .fetch_add(1, Ordering::Relaxed);
        Ok(AuthenticatedBlobReadDepot { depot })
    }

    fn create_bound_root(store: &Store) -> Result<OwnedDirectory, StoreError> {
        #[cfg(test)]
        store
            .blob_depot_test_counters
            .root_creations
            .fetch_add(1, Ordering::Relaxed);
        OwnedDirectory::create_bound_root(
            &store.path,
            store.backing_identity,
            store.blob_depot_owner_token,
        )
    }

    /// Mints a completion capability only after rechecking every durable marker and file.
    pub fn completed_blob(
        &mut self,
        blob: &ContentVerifiedBlobEnvelope,
        manifest_bytes: &[u8],
    ) -> Result<BlobDepotCompletion, StoreError> {
        self.store.require_live()?;
        let blob_id = blob.blob_id();
        let content_group = *blob.manifest().content_group();
        let epoch = blob.key_epoch();
        let manifest_digest = *blob.manifest_digest();
        let variant_id = blob_variant_id(blob_id, &content_group, epoch);
        let read = self.store.database.begin_read()?;
        super::deletion::require_variant_available_read(&read, variant_id)?;
        let import = load_import_read(&read, variant_id)?
            .ok_or_else(|| blob_error(BlobStoreError::CompletionMismatch))?;
        if !import.matches_manifest(blob.manifest())
            || import.blob_id != blob_id
            || import.content_group != content_group
            || import.epoch != epoch
            || import.physical_lineage != Some(*blob.physical_lineage().binding())
            || import.finalized_manifest_digest != Some(manifest_digest)
        {
            return Err(blob_error(BlobStoreError::CompletionMismatch));
        }
        let previous_active = self.active.replace(active_from_import(&import));
        let result = (|| {
            blob.verify_store_completion(manifest_bytes, self)
                .map_err(|_| blob_error(BlobStoreError::CompletionMismatch))?;
            verify_import_files_read(&read, &self.root, &import)?;
            let import_fingerprint = Sha256::digest(encode_import(&import)?).into();
            Ok(BlobDepotCompletion {
                authority: Arc::clone(&self.store.blob_completion_authority),
                backing_identity: self.store.backing_identity,
                variant_id,
                blob_id,
                content_group,
                epoch,
                physical_lineage: *blob.physical_lineage().binding(),
                manifest_digest,
                total_len: import.total_len,
                chunk_size: import.chunk_size,
                chunk_count: import.chunk_count,
                import_fingerprint,
            })
        })();
        self.active = previous_active;
        result
    }

    /// Mints physical completion for canonical content before its semantic
    /// source envelope receives a final causal identity.
    pub fn completed_prepared_blob(
        &mut self,
        manifest: &BlobManifest,
        manifest_digest: [u8; 32],
    ) -> Result<BlobDepotCompletion, StoreError> {
        self.store.require_live()?;
        let variant_id = blob_variant_id(
            manifest.id(),
            manifest.content_group(),
            manifest.content_epoch(),
        );
        let read = self.store.database.begin_read()?;
        super::deletion::require_variant_available_read(&read, variant_id)?;
        let import = load_import_read(&read, variant_id)?
            .ok_or_else(|| blob_error(BlobStoreError::CompletionMismatch))?;
        let physical_lineage = import
            .physical_lineage
            .ok_or_else(|| blob_error(BlobStoreError::CompletionMismatch))?;
        if !import.matches_manifest(manifest)
            || import.blob_id != manifest.id()
            || import.content_group != *manifest.content_group()
            || import.epoch != manifest.content_epoch()
            || import.finalized_manifest_digest != Some(manifest_digest)
        {
            return Err(blob_error(BlobStoreError::CompletionMismatch));
        }
        verify_import_files_read(&read, &self.root, &import)?;
        let import_fingerprint = Sha256::digest(encode_import(&import)?).into();
        Ok(BlobDepotCompletion {
            authority: Arc::clone(&self.store.blob_completion_authority),
            backing_identity: self.store.backing_identity,
            variant_id,
            blob_id: manifest.id(),
            content_group: *manifest.content_group(),
            epoch: manifest.content_epoch(),
            physical_lineage,
            manifest_digest,
            total_len: manifest.total_len(),
            chunk_size: manifest.chunk_size(),
            chunk_count: manifest.chunk_count(),
            import_fingerprint,
        })
    }

    /// Rechecks a previously minted exact completion against the current
    /// mission-bound depot, including every durable marker and chunk file.
    ///
    /// A completion is an in-memory authenticated capability, not a timeless
    /// assertion about mutable storage. Callers use this method immediately
    /// before returning plaintext or an idempotent publication receipt so a
    /// later missing, replaced, or corrupted depot artifact still fails
    /// closed.
    pub fn recheck_completion(
        &mut self,
        completion: &BlobDepotCompletion,
    ) -> Result<(), StoreError> {
        self.store.require_live()?;
        let read = self.store.database.begin_read()?;
        let import = self.exact_completion_import(&read, completion)?;
        verify_import_files_read(&read, &self.root, &import)
    }

    /// Rechecks the exact finalized import plus only the chunk files needed by
    /// one bounded plaintext range.
    ///
    /// The capability was minted by a complete depot audit. This narrower
    /// freshness check preserves that exact import/finalization authority while
    /// avoiding a whole-Blob file scan before every independently authenticated
    /// page. Missing or corrupt files outside the requested range are detected
    /// when their own range is read or by [`Self::recheck_completion`].
    pub fn recheck_completion_range(
        &mut self,
        completion: &BlobDepotCompletion,
        first_chunk: u64,
        chunk_count: u64,
    ) -> Result<(), StoreError> {
        self.store.require_live()?;
        let last_chunk = first_chunk
            .checked_add(chunk_count)
            .filter(|last| chunk_count > 0 && *last <= completion.chunk_count)
            .ok_or_else(|| blob_error(BlobStoreError::CompletionMismatch))?;
        let read = self.store.database.begin_read()?;
        let import = self.exact_completion_import(&read, completion)?;
        let variant = self
            .root
            .open_child_directory(&hex32(import.variant_id.as_bytes()), false)
            .map_err(|_| blob_error(BlobStoreError::CompletionMismatch))?;
        let active = active_from_import(&import);
        for index in first_chunk..last_chunk {
            let state = load_chunk_read(&read, import.variant_id, index)?
                .ok_or_else(|| blob_error(BlobStoreError::CompletionMismatch))?;
            let record = state
                .committed
                .ok_or_else(|| blob_error(BlobStoreError::CompletionMismatch))?;
            verify_chunk_file(
                &variant,
                &chunk_file_name(index),
                active,
                index,
                record,
                state.committed_file_bytes,
            )?;
        }
        Ok(())
    }

    fn exact_completion_import(
        &self,
        read: &redb::ReadTransaction,
        completion: &BlobDepotCompletion,
    ) -> Result<ImportRecord, StoreError> {
        if !Arc::ptr_eq(&completion.authority, &self.store.blob_completion_authority)
            || completion.backing_identity != self.store.backing_identity
        {
            return Err(blob_error(BlobStoreError::CompletionMismatch));
        }
        let import = load_import_read(read, completion.variant_id)?
            .ok_or_else(|| blob_error(BlobStoreError::CompletionMismatch))?;
        let import_fingerprint = <[u8; 32]>::from(Sha256::digest(encode_import(&import)?));
        if import.variant_id != completion.variant_id
            || import.blob_id != completion.blob_id
            || import.content_group != completion.content_group
            || import.epoch != completion.epoch
            || import.total_len != completion.total_len
            || import.chunk_size != completion.chunk_size
            || import.chunk_count != completion.chunk_count
            || import.physical_lineage != Some(completion.physical_lineage)
            || import.finalized_manifest_digest != Some(completion.manifest_digest)
            || import_fingerprint != completion.import_fingerprint
        {
            return Err(blob_error(BlobStoreError::CompletionMismatch));
        }
        Ok(import)
    }

    fn require_active(&self, blob_id: BlobId) -> Result<ActiveImport, StoreError> {
        self.active
            .filter(|active| active.blob_id == blob_id)
            .ok_or_else(|| {
                blob_error(BlobStoreError::DepotIntegrity(
                    "Blob depot adapter has no matching active import",
                ))
            })
    }

    fn ensure_chunk_index(&self, active: ActiveImport, index: u64) -> Result<(), StoreError> {
        if index >= active.chunk_count {
            return Err(blob_error(BlobStoreError::InvalidPublication(
                "Blob chunk index is outside the manifest",
            )));
        }
        Ok(())
    }

    fn ensure_chunk_record(
        &self,
        active: ActiveImport,
        index: u64,
        record: BlobChunkRecord,
    ) -> Result<(), StoreError> {
        self.ensure_chunk_index(active, index)?;
        validate_chunk_record_lengths(active.total_len, active.chunk_count, index, record).map_err(
            |_| {
                blob_error(BlobStoreError::InvalidPublication(
                    "Blob chunk record lengths differ from the selected manifest",
                ))
            },
        )
    }

    fn load_chunk(
        &self,
        active: ActiveImport,
        index: u64,
    ) -> Result<Option<ChunkState>, StoreError> {
        let read = self.store.database.begin_read()?;
        load_chunk_read(&read, active.variant_id, index)
    }

    fn mutate_chunk(
        &self,
        active: ActiveImport,
        index: u64,
        mutation: impl FnOnce(ChunkState) -> Result<ChunkState, StoreError>,
    ) -> Result<(), StoreError> {
        self.ensure_chunk_index(active, index)?;
        let write = self.store.database.begin_write()?;
        enforce_live_write(&write)?;
        let import = load_import_write(&write, active.variant_id)?
            .ok_or_else(|| blob_error(BlobStoreError::DepotIntegrity("Blob import disappeared")))?;
        if import.blob_id != active.blob_id
            || import.content_group != active.content_group
            || import.epoch != active.epoch
            || import.total_len != active.total_len
            || import.chunk_count != active.chunk_count
            || import.physical_lineage != active.physical_lineage
        {
            return Err(blob_error(BlobStoreError::DepotIntegrity(
                "active Blob import changed",
            )));
        }
        let key = chunk_key(active.variant_id, index);
        let existing = write
            .open_table(BLOB_CHUNKS)?
            .get(key.as_slice())?
            .map(|value| decode_chunk_state(value.value()))
            .transpose()?;
        let admission_usage = depot_admission_usage_write(&write)?;
        let incoming_chunk = u64::from(existing.is_none());
        let previous = existing.unwrap_or_default();
        let next = mutation(previous)?;
        let previous_reserved = previous
            .expected
            .map(chunk_file_len)
            .transpose()?
            .unwrap_or(0);
        let next_reserved = next.expected.map(chunk_file_len).transpose()?.unwrap_or(0);
        let incoming_bytes = next_reserved
            .checked_sub(previous_reserved)
            .ok_or_else(|| {
                blob_error(BlobStoreError::SchemaInvariant(
                    "Blob depot mutation unexpectedly releases reserved bytes",
                ))
            })?;
        let consumed = if let Some(claim) = self.upload_credit.as_ref() {
            let consume = super::upload::BlobUploadCapacity {
                bytes: incoming_bytes,
                chunks: incoming_chunk,
                variants: 0,
            };
            super::upload::bind_and_consume_upload_credit_write(
                &write,
                self.store,
                claim,
                active.variant_id,
                None,
                consume,
            )?;
            consume
        } else {
            super::upload::BlobUploadCapacity::default()
        };
        let updated_chunks = admission_usage
            .chunks
            .checked_sub(consumed.chunks)
            .and_then(|value| value.checked_add(incoming_chunk))
            .ok_or(StoreError::ItemCountAccountingOverflow)?;
        if updated_chunks > self.store.blob_depot_limits.max_chunks {
            return Err(blob_error(BlobStoreError::DepotChunkLimitExceeded {
                current: admission_usage.chunks,
                limit: self.store.blob_depot_limits.max_chunks,
            }));
        }
        if previous_reserved != next_reserved {
            let mut depot = write.open_table(BLOB_DEPOT_METADATA)?;
            let durable_reserved = depot
                .get(DEPOT_RESERVED_FILE_BYTES)?
                .map(|value| value.value())
                .ok_or_else(|| {
                    blob_error(BlobStoreError::SchemaInvariant(
                        "Blob depot reserved-byte counter is missing",
                    ))
                })?;
            let without_previous =
                durable_reserved
                    .checked_sub(previous_reserved)
                    .ok_or_else(|| {
                        blob_error(BlobStoreError::SchemaInvariant(
                            "Blob depot reserved-byte counter underflows",
                        ))
                    })?;
            let updated_physical = without_previous
                .checked_add(next_reserved)
                .ok_or(StoreError::PayloadByteAccountingOverflow)?;
            let updated_admission = admission_usage
                .reserved_bytes
                .checked_sub(consumed.bytes)
                .and_then(|value| value.checked_add(incoming_bytes))
                .ok_or_else(|| {
                    blob_error(BlobStoreError::SchemaInvariant(
                        "Blob depot admission-byte counter cannot cover its active chunk",
                    ))
                })?;
            if updated_admission > self.store.blob_depot_limits.max_bytes {
                return Err(blob_error(BlobStoreError::DepotByteLimitExceeded {
                    current: admission_usage.reserved_bytes,
                    incoming: incoming_bytes,
                    limit: self.store.blob_depot_limits.max_bytes,
                }));
            }
            depot.insert(DEPOT_RESERVED_FILE_BYTES, updated_physical)?;
        }
        let encoded = encode_chunk_state(next);
        write
            .open_table(BLOB_CHUNKS)?
            .insert(key.as_slice(), encoded.as_slice())?;
        write.commit()?;
        Ok(())
    }

    fn begin_blob_internal(
        &mut self,
        manifest: &BlobManifest,
        physical_lineage: Option<BlobPhysicalLineage>,
    ) -> Result<(), StoreError> {
        self.store.require_live()?;
        let incoming = ImportRecord::from_manifest(manifest, physical_lineage)?;
        // Explicit publish/chunk entrypoints install bounded leases because
        // their exclusion claim can outlive this adapter. A generic depot is
        // itself protected by the exclusive depot lock for its whole lifetime,
        // so acquiring another worker lease here would turn a stopped whole-
        // Blob read into unbounded worker work. The write-transaction check
        // below remains the durable DeletePending fence for both cases.
        if self._lease.is_some() {
            self.ensure_variant_lease(
                incoming.variant_id,
                super::lease::BlobLeaseKind::LocalImport,
            )?;
        }
        #[cfg(test)]
        self.store
            .blob_depot_test_counters
            .begin_write_transactions
            .fetch_add(1, Ordering::Relaxed);
        let write = self.store.database.begin_write()?;
        enforce_live_write(&write)?;
        super::deletion::require_variant_available_write(&write, incoming.variant_id)?;
        super::lifecycle::require_import_lineage(&write, incoming.physical_lineage)?;
        let owner_binding = incoming
            .physical_lineage
            .map(|_| {
                require_depot_owner_binding_write(
                    &write,
                    &self.store.path,
                    self.store.backing_identity,
                    self.store.blob_depot_owner_token,
                )
            })
            .transpose()?;
        let existing = load_import_write(&write, incoming.variant_id)?;
        match existing {
            Some(existing) if !existing.matches_manifest(manifest) => {
                return Err(blob_error(BlobStoreError::DepotIntegrity(
                    "Blob variant identity is bound to another manifest",
                )));
            }
            Some(existing) if existing.physical_lineage != incoming.physical_lineage => {
                return Err(blob_error(
                    match (existing.physical_lineage, incoming.physical_lineage) {
                        (Some(_), Some(_)) => BlobStoreError::PhysicalLineageConflict,
                        _ => BlobStoreError::PhysicalLineageMigrationRequired,
                    },
                ));
            }
            Some(_) => {
                if let Some(claim) = self.upload_credit.as_ref() {
                    super::upload::bind_upload_credit_to_existing_write(
                        &write,
                        self.store,
                        claim,
                        incoming.variant_id,
                        manifest,
                    )?;
                }
                if let (Some(physical_lineage), Some(owner_binding)) =
                    (incoming.physical_lineage, owner_binding)
                {
                    super::lifecycle::require_lineage_fence(
                        &write,
                        incoming.variant_id,
                        physical_lineage,
                        owner_binding,
                    )?;
                }
            }
            None => {
                let usage = depot_admission_usage_write(&write)?;
                let consumed = if let Some(claim) = self.upload_credit.as_ref() {
                    let consume = super::upload::BlobUploadCapacity {
                        bytes: 0,
                        chunks: 0,
                        variants: 1,
                    };
                    super::upload::bind_and_consume_upload_credit_write(
                        &write,
                        self.store,
                        claim,
                        incoming.variant_id,
                        Some(manifest),
                        consume,
                    )?;
                    consume
                } else {
                    super::upload::BlobUploadCapacity::default()
                };
                let updated = usage
                    .variants
                    .checked_sub(consumed.variants)
                    .and_then(|value| value.checked_add(1))
                    .ok_or(StoreError::ItemCountAccountingOverflow)?;
                if updated > self.store.blob_depot_limits.max_variants {
                    return Err(blob_error(BlobStoreError::DepotVariantLimitExceeded {
                        current: usage.variants,
                        limit: self.store.blob_depot_limits.max_variants,
                    }));
                }
                if let (Some(physical_lineage), Some(owner_binding)) =
                    (incoming.physical_lineage, owner_binding)
                {
                    super::lifecycle::ensure_lineage_fence(
                        &write,
                        self.store.blob_lifecycle_limits,
                        incoming.variant_id,
                        physical_lineage,
                        owner_binding,
                    )?;
                }
                let encoded = encode_import(&incoming)?;
                write.open_table(BLOB_IMPORTS)?.insert(
                    incoming.variant_id.as_bytes().as_slice(),
                    encoded.as_slice(),
                )?;
                let mut depot = write.open_table(BLOB_DEPOT_METADATA)?;
                let variants = depot
                    .get(DEPOT_VARIANT_COUNT)?
                    .map_or(0, |value| value.value());
                depot.insert(
                    DEPOT_VARIANT_COUNT,
                    variants
                        .checked_add(1)
                        .ok_or(StoreError::ItemCountAccountingOverflow)?,
                )?;
            }
        }
        write.commit()?;
        self.root
            .open_child_directory(&hex32(incoming.variant_id.as_bytes()), true)?;
        self.active = Some(active_from_import(&incoming));
        Ok(())
    }
}

/// Opens the owner-bound directory used by append-only stream packs.
/// The returned capability remains descriptor-backed on Unix.
pub(super) fn open_blob_pack_root(store: &Store) -> Result<OwnedDirectory, StoreError> {
    let depot = BlobDepot::open_network_mutation(store, true)?;
    depot.root.open_child_directory(BLOB_PACK_DIRECTORY, true)
}

impl CoreBlobStore for BlobDepot<'_> {
    type StoreError = StoreError;

    fn begin_blob(&mut self, manifest: &BlobManifest) -> Result<(), Self::StoreError> {
        self.begin_blob_internal(manifest, None)
    }

    fn begin_blob_with_lineage(
        &mut self,
        manifest: &BlobManifest,
        lineage: BlobPhysicalLineage,
    ) -> Result<(), Self::StoreError> {
        self.begin_blob_internal(manifest, Some(lineage))
    }

    fn select_blob_for_read_with_lineage(
        &mut self,
        manifest: &BlobManifest,
        lineage: BlobPhysicalLineage,
    ) -> Result<(), Self::StoreError> {
        self.store.require_live()?;
        let expected = ImportRecord::from_manifest(manifest, Some(lineage))?;
        if self
            .read_authorized_variant
            .is_some_and(|variant| variant != expected.variant_id)
        {
            return Err(blob_error(BlobStoreError::CompletionMismatch));
        }
        let read = self.store.database.begin_read()?;
        super::deletion::require_variant_available_read(&read, expected.variant_id)?;
        let existing = load_import_read(&read, expected.variant_id)?
            .ok_or_else(|| blob_error(BlobStoreError::CompletionMismatch))?;
        if !existing.matches_manifest(manifest)
            || existing.variant_id != expected.variant_id
            || existing.physical_lineage != expected.physical_lineage
            || existing.finalized_manifest_digest.is_none()
        {
            return Err(blob_error(BlobStoreError::CompletionMismatch));
        }
        self.active = Some(active_from_import(&existing));
        Ok(())
    }

    fn put_plaintext_digest(
        &mut self,
        id: BlobId,
        index: u64,
        digest: [u8; 32],
    ) -> Result<(), Self::StoreError> {
        self.store.require_live()?;
        let active = self.require_active(id)?;
        self.mutate_chunk(active, index, |mut state| {
            if state
                .plaintext_digest
                .is_some_and(|existing| existing != digest)
            {
                return Err(blob_error(BlobStoreError::DepotIntegrity(
                    "Blob plaintext digest conflicts with durable staging",
                )));
            }
            state.plaintext_digest = Some(digest);
            Ok(state)
        })
    }

    fn plaintext_digest(
        &mut self,
        id: BlobId,
        index: u64,
    ) -> Result<Option<[u8; 32]>, Self::StoreError> {
        self.store.require_live()?;
        let active = self.require_active(id)?;
        self.ensure_chunk_index(active, index)?;
        Ok(self
            .load_chunk(active, index)?
            .and_then(|state| state.plaintext_digest))
    }

    fn chunk_record(
        &mut self,
        id: BlobId,
        index: u64,
    ) -> Result<Option<BlobChunkRecord>, Self::StoreError> {
        self.store.require_live()?;
        let active = self.require_active(id)?;
        self.ensure_chunk_index(active, index)?;
        Ok(self
            .load_chunk(active, index)?
            .and_then(|state| state.committed))
    }

    fn put_expected_chunk_record(
        &mut self,
        id: BlobId,
        index: u64,
        record: BlobChunkRecord,
    ) -> Result<(), Self::StoreError> {
        self.store.require_live()?;
        let active = self.require_active(id)?;
        self.ensure_chunk_record(active, index, record)?;
        self.mutate_chunk(active, index, |mut state| {
            if state.expected.is_some_and(|existing| existing != record)
                || state.committed.is_some_and(|existing| existing != record)
                || state
                    .plaintext_digest
                    .is_some_and(|digest| digest != *record.plaintext_sha256())
            {
                return Err(blob_error(BlobStoreError::DepotIntegrity(
                    "Blob expected chunk record conflicts with durable staging",
                )));
            }
            state.plaintext_digest = Some(*record.plaintext_sha256());
            state.expected = Some(record);
            Ok(state)
        })
    }

    fn expected_chunk_record(
        &mut self,
        id: BlobId,
        index: u64,
    ) -> Result<Option<BlobChunkRecord>, Self::StoreError> {
        self.store.require_live()?;
        let active = self.require_active(id)?;
        self.ensure_chunk_index(active, index)?;
        Ok(self
            .load_chunk(active, index)?
            .and_then(|state| state.expected))
    }

    fn commit_verified_chunk(
        &mut self,
        id: BlobId,
        index: u64,
        record: BlobChunkRecord,
        ciphertext: &[u8],
    ) -> Result<(), Self::StoreError> {
        self.store.require_live()?;
        let active = self.require_active(id)?;
        self.ensure_chunk_record(active, index, record)?;
        if usize::try_from(record.ciphertext_len()).ok() != Some(ciphertext.len())
            || <[u8; 32]>::from(Sha256::digest(ciphertext)) != *record.ciphertext_sha256()
        {
            return Err(blob_error(BlobStoreError::DepotIntegrity(
                "verified Blob chunk bytes differ from their record",
            )));
        }
        // Local publication derives the authenticated record immediately before
        // committing the ciphertext, whereas verified-manifest installation
        // stages it through `put_expected_chunk_record`. Bind the local record
        // durably before publishing the file while retaining the same conflict
        // checks for both paths.
        self.mutate_chunk(active, index, |mut state| {
            if state.plaintext_digest != Some(*record.plaintext_sha256())
                || state.expected.is_some_and(|existing| existing != record)
                || state.committed.is_some_and(|existing| existing != record)
            {
                return Err(blob_error(BlobStoreError::DepotIntegrity(
                    "verified Blob chunk differs from durable expected metadata",
                )));
            }
            state.expected = Some(record);
            Ok(state)
        })?;
        let state = self.load_chunk(active, index)?.ok_or_else(|| {
            blob_error(BlobStoreError::DepotIntegrity(
                "verified Blob chunk has no durable expected record",
            ))
        })?;
        if state.expected != Some(record)
            || state.plaintext_digest != Some(*record.plaintext_sha256())
        {
            return Err(blob_error(BlobStoreError::DepotIntegrity(
                "verified Blob chunk differs from durable expected metadata",
            )));
        }
        let variant = self
            .root
            .open_child_directory(&hex32(active.variant_id.as_bytes()), true)?;
        let file_name = chunk_file_name(index);
        if state.committed == Some(record) {
            verify_chunk_file(
                &variant,
                &file_name,
                active,
                index,
                record,
                state.committed_file_bytes,
            )?;
            return Ok(());
        }
        if state.committed.is_some() {
            return Err(blob_error(BlobStoreError::DepotIntegrity(
                "Blob chunk marker conflicts with a second record",
            )));
        }
        // A final pathname without a redb marker is never authority. It is
        // reclaimed before retrying the full sync/rename/dir-sync/marker sequence.
        variant.remove_if_exists(&file_name, false)?;
        let encoded = encode_chunk_file(active, index, record, ciphertext)?;
        let incoming =
            u64::try_from(encoded.len()).map_err(|_| StoreError::PayloadByteAccountingOverflow)?;
        // Expected-record admission already reserved the exact canonical file
        // bytes and active chunk row. Committing that reservation must not be
        // rejected by physical files retained under deletion-manifest
        // authority, which remain in the physical counters until unlink.
        variant.write_atomic(&file_name, &encoded)?;

        let write = self.store.database.begin_write()?;
        enforce_live_write(&write)?;
        super::pressure::require_variant_write(&write, active.variant_id)?;
        let key = chunk_key(active.variant_id, index);
        let mut durable = write
            .open_table(BLOB_CHUNKS)?
            .get(key.as_slice())?
            .map(|value| decode_chunk_state(value.value()))
            .transpose()?
            .ok_or_else(|| {
                blob_error(BlobStoreError::DepotIntegrity(
                    "Blob chunk staging disappeared before marker commit",
                ))
            })?;
        if durable.expected != Some(record) || durable.committed.is_some() {
            return Err(blob_error(BlobStoreError::DepotIntegrity(
                "Blob chunk staging changed before marker commit",
            )));
        }
        let mut depot = write.open_table(BLOB_DEPOT_METADATA)?;
        let durable_bytes = depot
            .get(DEPOT_COMMITTED_FILE_BYTES)?
            .map_or(0, |value| value.value());
        let durable_chunks = depot
            .get(DEPOT_COMMITTED_CHUNK_COUNT)?
            .map_or(0, |value| value.value());
        durable.committed = Some(record);
        durable.committed_file_bytes = incoming;
        let encoded_state = encode_chunk_state(durable);
        write
            .open_table(BLOB_CHUNKS)?
            .insert(key.as_slice(), encoded_state.as_slice())?;
        depot.insert(
            DEPOT_COMMITTED_FILE_BYTES,
            durable_bytes
                .checked_add(incoming)
                .ok_or(StoreError::PayloadByteAccountingOverflow)?,
        )?;
        depot.insert(
            DEPOT_COMMITTED_CHUNK_COUNT,
            durable_chunks
                .checked_add(1)
                .ok_or(StoreError::ItemCountAccountingOverflow)?,
        )?;
        drop(depot);
        super::pressure::reconcile_variant_write(&write, active.variant_id)?;
        write.commit()?;
        Ok(())
    }

    fn read_verified_chunk(
        &mut self,
        id: BlobId,
        index: u64,
        output: &mut Vec<u8>,
    ) -> Result<bool, Self::StoreError> {
        self.store.require_live()?;
        let active = self.require_active(id)?;
        self.ensure_chunk_index(active, index)?;
        let Some(state) = self.load_chunk(active, index)? else {
            return Ok(false);
        };
        let Some(record) = state.committed else {
            return Ok(false);
        };
        let variant = self
            .root
            .open_child_directory(&hex32(active.variant_id.as_bytes()), false)?;
        read_and_verify_chunk_file_into(
            &variant,
            &chunk_file_name(index),
            active,
            index,
            record,
            state.committed_file_bytes,
            output,
        )?;
        Ok(true)
    }

    fn finalize_blob(
        &mut self,
        id: BlobId,
        manifest_digest: [u8; 32],
    ) -> Result<(), Self::StoreError> {
        self.store.require_live()?;
        let active = self.require_active(id)?;
        let read = self.store.database.begin_read()?;
        let import = load_import_read(&read, active.variant_id)?
            .ok_or_else(|| blob_error(BlobStoreError::DepotIntegrity("Blob import disappeared")))?;
        if let Some(existing) = import.finalized_manifest_digest {
            if existing != manifest_digest {
                return Err(blob_error(BlobStoreError::DepotIntegrity(
                    "Blob manifest finalization digest conflicts",
                )));
            }
            verify_import_files_read(&read, &self.root, &import)?;
            return Ok(());
        }
        verify_import_files_read(&read, &self.root, &import)?;
        drop(read);
        let write = self.store.database.begin_write()?;
        enforce_live_write(&write)?;
        super::pressure::require_variant_write(&write, active.variant_id)?;
        let mut import = load_import_write(&write, active.variant_id)?
            .ok_or_else(|| blob_error(BlobStoreError::DepotIntegrity("Blob import disappeared")))?;
        if import
            .finalized_manifest_digest
            .is_some_and(|value| value != manifest_digest)
        {
            return Err(blob_error(BlobStoreError::DepotIntegrity(
                "Blob manifest finalization digest conflicts",
            )));
        }
        import.finalized_manifest_digest = Some(manifest_digest);
        let encoded = encode_import(&import)?;
        write
            .open_table(BLOB_IMPORTS)?
            .insert(active.variant_id.as_bytes().as_slice(), encoded.as_slice())?;
        super::pressure::reconcile_variant_write(&write, active.variant_id)?;
        write.commit()?;
        Ok(())
    }

    fn finalized_manifest_digest(
        &mut self,
        id: BlobId,
    ) -> Result<Option<[u8; 32]>, Self::StoreError> {
        self.store.require_live()?;
        let active = self.require_active(id)?;
        let read = self.store.database.begin_read()?;
        Ok(load_import_read(&read, active.variant_id)?
            .and_then(|import| import.finalized_manifest_digest))
    }
}

pub(super) fn audit_depot_metadata_write(
    write: &redb::WriteTransaction,
    deletion: &super::deletion::BlobDeletionAudit,
) -> Result<DepotStats, StoreError> {
    let _owner_token = depot_owner_token_write(write)?;
    let imports = write.open_table(BLOB_IMPORTS)?;
    let chunks = write.open_table(BLOB_CHUNKS)?;
    let mut stats = DepotStats::default();
    let mut imported = BTreeMap::new();
    for row in imports.iter()? {
        let (key, value) = row?;
        let variant = parse_variant_id(key.value())?;
        let import = decode_import(value.value())?;
        if import.variant_id != variant
            || import.variant_id
                != blob_variant_id(import.blob_id, &import.content_group, import.epoch)
        {
            return Err(blob_error(BlobStoreError::SchemaInvariant(
                "Blob import key differs from its exact variant identity",
            )));
        }
        stats.variants = stats
            .variants
            .checked_add(1)
            .ok_or(StoreError::ItemCountAccountingOverflow)?;
        stats.finalized_variants += u64::from(import.finalized_manifest_digest.is_some());
        imported.insert(variant, import);
    }
    let mut per_variant = BTreeMap::<BlobVariantId, u64>::new();
    for row in chunks.iter()? {
        let (key, value) = row?;
        let (variant, index) = parse_chunk_key(key.value())?;
        let import = imported.get(&variant).ok_or_else(|| {
            blob_error(BlobStoreError::SchemaInvariant(
                "Blob chunk metadata references a missing import",
            ))
        })?;
        if index >= import.chunk_count {
            return Err(blob_error(BlobStoreError::SchemaInvariant(
                "Blob chunk metadata index is outside its manifest",
            )));
        }
        let state = decode_chunk_state(value.value())?;
        validate_chunk_state_lengths(import, index, state)?;
        if let Some(expected) = state.expected {
            stats.reserved_file_bytes = stats
                .reserved_file_bytes
                .checked_add(chunk_file_len(expected)?)
                .ok_or(StoreError::PayloadByteAccountingOverflow)?;
        }
        if let Some(record) = state.committed {
            if state.expected != Some(record)
                || state.plaintext_digest != Some(*record.plaintext_sha256())
                || state.committed_file_bytes != chunk_file_len(record)?
            {
                return Err(blob_error(BlobStoreError::SchemaInvariant(
                    "committed Blob chunk marker is internally inconsistent",
                )));
            }
            stats.committed_chunks += 1;
            stats.committed_file_bytes = stats
                .committed_file_bytes
                .checked_add(state.committed_file_bytes)
                .ok_or(StoreError::PayloadByteAccountingOverflow)?;
            *per_variant.entry(variant).or_default() += 1;
        } else if state.committed_file_bytes != 0 {
            return Err(blob_error(BlobStoreError::SchemaInvariant(
                "uncommitted Blob chunk retains committed byte accounting",
            )));
        }
    }
    for manifest in deletion.manifests.values() {
        if per_variant
            .insert(manifest.variant_id, manifest.totals.charged_files)
            .is_some()
        {
            return Err(blob_error(BlobStoreError::SchemaInvariant(
                "Blob variant has duplicate active and deletion chunk charge",
            )));
        }
    }
    stats.committed_chunks = stats
        .committed_chunks
        .checked_add(deletion.stats.charged_files)
        .ok_or(StoreError::ItemCountAccountingOverflow)?;
    stats.committed_file_bytes = stats
        .committed_file_bytes
        .checked_add(deletion.stats.charged_committed_bytes)
        .ok_or(StoreError::PayloadByteAccountingOverflow)?;
    stats.reserved_file_bytes = stats
        .reserved_file_bytes
        .checked_add(deletion.stats.charged_reserved_bytes)
        .ok_or(StoreError::PayloadByteAccountingOverflow)?;
    for import in imported.values() {
        if import.finalized_manifest_digest.is_some()
            && per_variant.get(&import.variant_id).copied().unwrap_or(0) != import.chunk_count
        {
            return Err(blob_error(BlobStoreError::SchemaInvariant(
                "finalized Blob import does not have every committed chunk marker",
            )));
        }
    }
    let mut depot = write.open_table(BLOB_DEPOT_METADATA)?;
    let schema = depot
        .get(DEPOT_SCHEMA_VERSION)?
        .map(|value| value.value())
        .ok_or_else(|| {
            blob_error(BlobStoreError::SchemaInvariant(
                "Blob depot schema version is missing",
            ))
        })?;
    if schema != DEPOT_SCHEMA_VERSION_V1 && schema != BLOB_DEPOT_SCHEMA_VERSION {
        return Err(blob_error(BlobStoreError::SchemaInvariant(
            "Blob depot schema version is unsupported",
        )));
    }
    audit_depot_counter(&mut depot, DEPOT_VARIANT_COUNT, stats.variants)?;
    audit_depot_counter(
        &mut depot,
        DEPOT_COMMITTED_CHUNK_COUNT,
        stats.committed_chunks,
    )?;
    audit_depot_counter(
        &mut depot,
        DEPOT_COMMITTED_FILE_BYTES,
        stats.committed_file_bytes,
    )?;
    if schema == DEPOT_SCHEMA_VERSION_V1 {
        depot.insert(DEPOT_RESERVED_FILE_BYTES, stats.reserved_file_bytes)?;
        depot.insert(DEPOT_SCHEMA_VERSION, BLOB_DEPOT_SCHEMA_VERSION)?;
    } else {
        audit_depot_counter(
            &mut depot,
            DEPOT_RESERVED_FILE_BYTES,
            stats.reserved_file_bytes,
        )?;
    }
    Ok(stats)
}

pub(super) fn inspect_depot_metadata_read(
    read: &redb::ReadTransaction,
    deletion: &super::deletion::BlobDeletionAudit,
) -> Result<DepotStats, StoreError> {
    let _owner_token = depot_owner_token_read(read)?;
    let imports = read.open_table(BLOB_IMPORTS)?;
    let chunks = read.open_table(BLOB_CHUNKS)?;
    let mut stats = DepotStats::default();
    let mut imported = BTreeMap::new();
    for row in imports.iter()? {
        let (key, value) = row?;
        let variant = parse_variant_id(key.value())?;
        let import = decode_import(value.value())?;
        if import.variant_id != variant
            || import.variant_id
                != blob_variant_id(import.blob_id, &import.content_group, import.epoch)
        {
            return Err(blob_error(BlobStoreError::SchemaInvariant(
                "Blob import key differs from its exact variant identity",
            )));
        }
        stats.variants += 1;
        stats.finalized_variants += u64::from(import.finalized_manifest_digest.is_some());
        imported.insert(variant, import);
    }
    let mut per_variant = BTreeMap::<BlobVariantId, u64>::new();
    for row in chunks.iter()? {
        let (key, value) = row?;
        let (variant, index) = parse_chunk_key(key.value())?;
        let import = imported.get(&variant).ok_or_else(|| {
            blob_error(BlobStoreError::SchemaInvariant(
                "Blob chunk metadata references a missing import",
            ))
        })?;
        if index >= import.chunk_count {
            return Err(blob_error(BlobStoreError::SchemaInvariant(
                "Blob chunk metadata index is outside its manifest",
            )));
        }
        let state = decode_chunk_state(value.value())?;
        validate_chunk_state_lengths(import, index, state)?;
        if let Some(expected) = state.expected {
            stats.reserved_file_bytes = stats
                .reserved_file_bytes
                .checked_add(chunk_file_len(expected)?)
                .ok_or(StoreError::PayloadByteAccountingOverflow)?;
        }
        if let Some(record) = state.committed {
            if state.expected != Some(record)
                || state.plaintext_digest != Some(*record.plaintext_sha256())
                || state.committed_file_bytes != chunk_file_len(record)?
            {
                return Err(blob_error(BlobStoreError::SchemaInvariant(
                    "committed Blob chunk marker is internally inconsistent",
                )));
            }
            stats.committed_chunks += 1;
            stats.committed_file_bytes = stats
                .committed_file_bytes
                .checked_add(state.committed_file_bytes)
                .ok_or(StoreError::PayloadByteAccountingOverflow)?;
            *per_variant.entry(variant).or_default() += 1;
        } else if state.committed_file_bytes != 0 {
            return Err(blob_error(BlobStoreError::SchemaInvariant(
                "uncommitted Blob chunk retains committed byte accounting",
            )));
        }
    }
    for manifest in deletion.manifests.values() {
        if per_variant
            .insert(manifest.variant_id, manifest.totals.charged_files)
            .is_some()
        {
            return Err(blob_error(BlobStoreError::SchemaInvariant(
                "Blob variant has duplicate active and deletion chunk charge",
            )));
        }
    }
    stats.committed_chunks = stats
        .committed_chunks
        .checked_add(deletion.stats.charged_files)
        .ok_or(StoreError::ItemCountAccountingOverflow)?;
    stats.committed_file_bytes = stats
        .committed_file_bytes
        .checked_add(deletion.stats.charged_committed_bytes)
        .ok_or(StoreError::PayloadByteAccountingOverflow)?;
    stats.reserved_file_bytes = stats
        .reserved_file_bytes
        .checked_add(deletion.stats.charged_reserved_bytes)
        .ok_or(StoreError::PayloadByteAccountingOverflow)?;
    for import in imported.values() {
        if import.finalized_manifest_digest.is_some()
            && per_variant.get(&import.variant_id).copied().unwrap_or(0) != import.chunk_count
        {
            return Err(blob_error(BlobStoreError::SchemaInvariant(
                "finalized Blob import does not have every committed chunk marker",
            )));
        }
    }
    let depot = read.open_table(BLOB_DEPOT_METADATA)?;
    let schema = depot
        .get(DEPOT_SCHEMA_VERSION)?
        .map(|value| value.value())
        .ok_or_else(|| {
            blob_error(BlobStoreError::SchemaInvariant(
                "Blob depot schema version is missing",
            ))
        })?;
    if schema != DEPOT_SCHEMA_VERSION_V1 && schema != BLOB_DEPOT_SCHEMA_VERSION {
        return Err(blob_error(BlobStoreError::SchemaInvariant(
            "Blob depot schema version is unsupported",
        )));
    }
    for (field, reconstructed) in [
        (DEPOT_VARIANT_COUNT, stats.variants),
        (DEPOT_COMMITTED_CHUNK_COUNT, stats.committed_chunks),
        (DEPOT_COMMITTED_FILE_BYTES, stats.committed_file_bytes),
    ] {
        let durable = depot
            .get(field)?
            .ok_or_else(|| {
                blob_error(BlobStoreError::SchemaInvariant(
                    "Blob depot accounting field is missing",
                ))
            })?
            .value();
        if durable != reconstructed {
            return Err(StoreError::AccountingMismatch {
                field,
                durable,
                reconstructed,
            });
        }
    }
    if schema == BLOB_DEPOT_SCHEMA_VERSION {
        let durable = depot
            .get(DEPOT_RESERVED_FILE_BYTES)?
            .ok_or_else(|| {
                blob_error(BlobStoreError::SchemaInvariant(
                    "Blob depot reserved-byte field is missing",
                ))
            })?
            .value();
        if durable != stats.reserved_file_bytes {
            return Err(StoreError::AccountingMismatch {
                field: DEPOT_RESERVED_FILE_BYTES,
                durable,
                reconstructed: stats.reserved_file_bytes,
            });
        }
    }
    Ok(stats)
}

fn lifecycle_import_from_record(
    variant: BlobVariantId,
    import: ImportRecord,
) -> Result<AuditedLifecycleImport, StoreError> {
    if import.variant_id != variant
        || import.variant_id != blob_variant_id(import.blob_id, &import.content_group, import.epoch)
    {
        return Err(blob_error(BlobStoreError::SchemaInvariant(
            "Blob import key differs from its exact variant identity",
        )));
    }
    let physical_lineage = import.physical_lineage.ok_or_else(|| {
        blob_error(BlobStoreError::SchemaInvariant(
            "retained Blob import is missing authenticated physical lineage",
        ))
    })?;
    Ok(AuditedLifecycleImport {
        variant_id: variant,
        physical_lineage,
    })
}

/// Decodes only the durable import facts needed by bounded maintenance. It
/// does not inspect chunk metadata or touch the filesystem.
pub(super) fn maintenance_import_projection(
    key: &[u8],
    value: &[u8],
) -> Result<MaintenanceImportProjection, StoreError> {
    let import = decode_import(value)?;
    let finalized = import.finalized_manifest_digest.is_some();
    let audited = lifecycle_import_from_record(parse_variant_id(key)?, import)?;
    Ok(MaintenanceImportProjection {
        variant_id: audited.variant_id,
        physical_lineage: audited.physical_lineage,
        finalized,
    })
}

/// Decodes the exact import evidence retained by a deletion
/// manifest. This is a read-only projection and cannot admit deletion work.
pub(super) fn deletion_import_projection(
    key: &[u8],
    value: &[u8],
) -> Result<DeletionImportProjection, StoreError> {
    if super::pack_lifecycle::is_pack_evidence(value) {
        return super::pack_lifecycle::deletion_projection(key, value);
    }
    let variant = parse_variant_id(key)?;
    let import = decode_import(value)?;
    let audited = lifecycle_import_from_record(variant, import.clone())?;
    Ok(DeletionImportProjection {
        variant_id: audited.variant_id,
        blob_id: import.blob_id,
        content_group: import.content_group,
        epoch: import.epoch,
        total_len: import.total_len,
        chunk_count: import.chunk_count,
        physical_lineage: audited.physical_lineage,
        finalized_root: import.finalized_manifest_digest,
    })
}

/// Validates one exact original chunk row retained by a deletion manifest and
/// returns its optional physical identity plus its existing quota charge.
pub(super) fn deletion_chunk_projection(
    import_value: &[u8],
    index: u64,
    chunk_value: &[u8],
) -> Result<DeletionChunkProjection, StoreError> {
    let import = decode_import(import_value)?;
    if index >= import.chunk_count {
        return Err(blob_error(BlobStoreError::SchemaInvariant(
            "Blob deletion chunk index is outside its import",
        )));
    }
    let state = decode_chunk_state(chunk_value)?;
    validate_chunk_state_lengths(&import, index, state)?;
    let charged_reserved_bytes = state.expected.map(chunk_file_len).transpose()?.unwrap_or(0);
    let charged_committed_bytes = state
        .committed
        .map(chunk_file_len)
        .transpose()?
        .unwrap_or(0);
    let authorized_file_bytes = match (state.committed, state.expected) {
        (Some(record), _) | (None, Some(record)) => chunk_file_len(record)?,
        (None, None) if state.plaintext_digest.is_some() => CHUNK_FILE_HEADER_BYTES
            .checked_add(u64::from(expected_import_plaintext_len(
                import.total_len,
                import.chunk_count,
                index,
            )?))
            .and_then(|bytes| bytes.checked_add(u64::from(BLOB_CHUNK_TAG_BYTES)))
            .ok_or(StoreError::PayloadByteAccountingOverflow)?,
        (None, None) => 0,
    };
    if state.committed.is_some_and(|record| {
        state.expected != Some(record) || state.plaintext_digest != Some(*record.plaintext_sha256())
    }) || state.committed_file_bytes != charged_committed_bytes
    {
        return Err(blob_error(BlobStoreError::SchemaInvariant(
            "Blob deletion chunk evidence is not a canonical original row",
        )));
    }
    Ok(DeletionChunkProjection {
        record: state.committed,
        cleanup: match (state.committed, state.expected, state.plaintext_digest) {
            (Some(record), _, _) => DeletionChunkCleanupAuthority::Committed(record),
            (None, Some(record), _) => DeletionChunkCleanupAuthority::Expected(record),
            (None, None, Some(digest)) => DeletionChunkCleanupAuthority::Digest(digest),
            (None, None, None) => DeletionChunkCleanupAuthority::Absent,
        },
        authorized_file_bytes,
        charged_reserved_bytes,
        charged_committed_bytes,
    })
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct DepotAdmissionUsage {
    pub(super) variants: u64,
    pub(super) chunks: u64,
    pub(super) reserved_bytes: u64,
}

fn blob_upload_capacity_with_staging(
    total_len: u64,
    staging: u64,
) -> Result<super::upload::BlobUploadCapacity, StoreError> {
    let chunks = if total_len == 0 {
        0
    } else {
        total_len
            .checked_add(u64::from(super::SELECTED_BLOB_CHUNK_SIZE) - 1)
            .ok_or(StoreError::PayloadByteAccountingOverflow)?
            / u64::from(super::SELECTED_BLOB_CHUNK_SIZE)
    };
    if chunks > super::MAX_SELECTED_BLOB_CHUNKS {
        return Err(blob_error(BlobStoreError::InvalidPublication(
            "Blob upload exceeds the selected manifest chunk bound",
        )));
    }
    let conversion_overhead = chunks
        .checked_mul(
            CHUNK_FILE_HEADER_BYTES
                .checked_add(u64::from(BLOB_CHUNK_TAG_BYTES))
                .ok_or(StoreError::PayloadByteAccountingOverflow)?,
        )
        .ok_or(StoreError::PayloadByteAccountingOverflow)?;
    Ok(super::upload::BlobUploadCapacity {
        bytes: staging
            .checked_add(total_len)
            .and_then(|value| value.checked_add(conversion_overhead))
            .ok_or(StoreError::PayloadByteAccountingOverflow)?,
        chunks,
        variants: 1,
    })
}

pub(super) fn blob_upload_capacity(
    total_len: u64,
) -> Result<super::upload::BlobUploadCapacity, StoreError> {
    blob_upload_capacity_with_staging(total_len, blob_upload_staging_charge(total_len)?)
}

pub(super) fn legacy_blob_upload_capacity(
    total_len: u64,
) -> Result<super::upload::BlobUploadCapacity, StoreError> {
    blob_upload_capacity_with_staging(total_len, legacy_blob_upload_staging_charge(total_len)?)
}

pub(super) fn blob_upload_staging_charge(total_len: u64) -> Result<u64, StoreError> {
    super::pack::reserved_upload_pack_bytes(total_len)?
        .checked_add(super::pack::upload_digest_reserved_bytes(total_len)?)
        .ok_or(StoreError::PayloadByteAccountingOverflow)
}

pub(super) fn legacy_blob_upload_staging_charge(total_len: u64) -> Result<u64, StoreError> {
    super::pack::reserved_upload_pack_bytes(total_len)
}

pub(super) fn blob_upload_conversion_overhead(total_len: u64) -> Result<u64, StoreError> {
    let total = blob_upload_capacity(total_len)?.bytes;
    total
        .checked_sub(blob_upload_staging_charge(total_len)?)
        .and_then(|value| value.checked_sub(total_len))
        .ok_or(StoreError::PayloadByteAccountingOverflow)
}

fn reconstruct_upload_capacity_tables(
    imports: &impl ReadableTable<&'static [u8], &'static [u8]>,
    chunks: &impl ReadableTable<&'static [u8], &'static [u8]>,
    variant: super::BlobVariantId,
    total_len: u64,
    epoch: u64,
    media_type: Option<&str>,
    schema_id: &[u8],
) -> Result<super::upload::BlobUploadCapacity, StoreError> {
    let import = imports
        .get(variant.as_bytes().as_slice())?
        .map(|value| decode_import(value.value()))
        .transpose()?
        .ok_or_else(|| {
            blob_error(BlobStoreError::SchemaInvariant(
                "Blob upload credit is bound to a missing canonical import",
            ))
        })?;
    if import.variant_id != variant
        || import.total_len != total_len
        || import.epoch != epoch
        || import.media_type.as_deref() != media_type
        || import.schema_id != schema_id
    {
        return Err(blob_error(BlobStoreError::SchemaInvariant(
            "Blob upload credit differs from its canonical import",
        )));
    }
    let mut capacity = super::upload::BlobUploadCapacity {
        bytes: 0,
        chunks: 0,
        variants: 1,
    };
    for row in chunks.iter()? {
        let (key, value) = row?;
        let (chunk_variant, index) = parse_chunk_key(key.value())?;
        if chunk_variant != variant {
            continue;
        }
        if index >= import.chunk_count {
            return Err(blob_error(BlobStoreError::SchemaInvariant(
                "Blob upload credit chunk lies outside its canonical import",
            )));
        }
        let state = decode_chunk_state(value.value())?;
        validate_chunk_state_lengths(&import, index, state)?;
        capacity.chunks = capacity
            .chunks
            .checked_add(1)
            .ok_or(StoreError::ItemCountAccountingOverflow)?;
        capacity.bytes = capacity
            .bytes
            .checked_add(state.expected.map(chunk_file_len).transpose()?.unwrap_or(0))
            .ok_or(StoreError::PayloadByteAccountingOverflow)?;
    }
    Ok(capacity)
}

pub(super) fn reconstruct_upload_capacity_write(
    write: &redb::WriteTransaction,
    variant: super::BlobVariantId,
    total_len: u64,
    epoch: u64,
    media_type: Option<&str>,
    schema_id: &[u8],
) -> Result<super::upload::BlobUploadCapacity, StoreError> {
    reconstruct_upload_capacity_tables(
        &write.open_table(BLOB_IMPORTS)?,
        &write.open_table(BLOB_CHUNKS)?,
        variant,
        total_len,
        epoch,
        media_type,
        schema_id,
    )
}

pub(super) fn reconstruct_upload_capacity_read(
    read: &redb::ReadTransaction,
    variant: super::BlobVariantId,
    total_len: u64,
    epoch: u64,
    media_type: Option<&str>,
    schema_id: &[u8],
) -> Result<super::upload::BlobUploadCapacity, StoreError> {
    reconstruct_upload_capacity_tables(
        &read.open_table(BLOB_IMPORTS)?,
        &read.open_table(BLOB_CHUNKS)?,
        variant,
        total_len,
        epoch,
        media_type,
        schema_id,
    )
}

/// Capacity admission retains every physical resource through resumable
/// unlink and deletion-manifest finalization.
pub(super) fn depot_admission_usage_write(
    write: &redb::WriteTransaction,
) -> Result<DepotAdmissionUsage, StoreError> {
    let imports = write.open_table(BLOB_IMPORTS)?.len()?;
    let active_chunks = write.open_table(BLOB_CHUNKS)?.len()?;
    let reserved_bytes = write
        .open_table(BLOB_DEPOT_METADATA)?
        .get(DEPOT_RESERVED_FILE_BYTES)?
        .map(|value| value.value())
        .ok_or_else(|| {
            blob_error(BlobStoreError::SchemaInvariant(
                "Blob depot reserved-byte counter is missing",
            ))
        })?;
    let deletion = write.open_table(super::deletion::BLOB_DELETION_METADATA)?;
    let deletion_chunks = deletion
        .get(super::deletion::BLOB_DELETION_CHUNK_ROWS)?
        .map(|value| value.value())
        .ok_or_else(|| {
            blob_error(BlobStoreError::SchemaInvariant(
                "Blob deletion chunk-row counter is missing",
            ))
        })?;
    let upload = super::upload::upload_capacity_usage_write(write)?;
    let packs = super::pack_lifecycle::active_capacity_usage_write(write)?;
    Ok(DepotAdmissionUsage {
        variants: imports
            .checked_add(packs.variants)
            .and_then(|value| value.checked_add(upload.variants))
            .ok_or(StoreError::ItemCountAccountingOverflow)?,
        chunks: active_chunks
            .checked_add(deletion_chunks)
            .and_then(|value| value.checked_add(packs.chunks))
            .and_then(|value| value.checked_add(upload.chunks))
            .ok_or(StoreError::ItemCountAccountingOverflow)?,
        reserved_bytes: reserved_bytes
            .checked_add(packs.bytes)
            .and_then(|value| value.checked_add(upload.bytes))
            .ok_or(StoreError::PayloadByteAccountingOverflow)?,
    })
}

pub(super) fn depot_admission_usage_read(
    read: &redb::ReadTransaction,
) -> Result<DepotAdmissionUsage, StoreError> {
    let imports = read.open_table(BLOB_IMPORTS)?.len()?;
    let active_chunks = read.open_table(BLOB_CHUNKS)?.len()?;
    let reserved_bytes = read
        .open_table(BLOB_DEPOT_METADATA)?
        .get(DEPOT_RESERVED_FILE_BYTES)?
        .map(|value| value.value())
        .ok_or_else(|| {
            blob_error(BlobStoreError::SchemaInvariant(
                "Blob depot reserved-byte counter is missing",
            ))
        })?;
    let deletion = read.open_table(super::deletion::BLOB_DELETION_METADATA)?;
    let deletion_chunks = deletion
        .get(super::deletion::BLOB_DELETION_CHUNK_ROWS)?
        .map(|value| value.value())
        .ok_or_else(|| {
            blob_error(BlobStoreError::SchemaInvariant(
                "Blob deletion chunk-row counter is missing",
            ))
        })?;
    let upload = super::upload::upload_capacity_usage_read(read)?;
    let packs = super::pack_lifecycle::active_capacity_usage_read(read)?;
    Ok(DepotAdmissionUsage {
        variants: imports
            .checked_add(packs.variants)
            .and_then(|value| value.checked_add(upload.variants))
            .ok_or(StoreError::ItemCountAccountingOverflow)?,
        chunks: active_chunks
            .checked_add(deletion_chunks)
            .and_then(|value| value.checked_add(packs.chunks))
            .and_then(|value| value.checked_add(upload.chunks))
            .ok_or(StoreError::ItemCountAccountingOverflow)?,
        reserved_bytes: reserved_bytes
            .checked_add(packs.bytes)
            .and_then(|value| value.checked_add(upload.bytes))
            .ok_or(StoreError::PayloadByteAccountingOverflow)?,
    })
}

/// Reconstructs the finalized canonical manifest digest from the exact
/// retained import and ordered committed chunk records.
pub(super) fn validate_deletion_manifest_root(
    import_value: &[u8],
    records: &[BlobChunkRecord],
    expected: Option<[u8; 32]>,
) -> Result<(), StoreError> {
    if super::pack_lifecycle::is_pack_evidence(import_value) {
        let projection = super::pack_lifecycle::deletion_projection(
            // The exact key is already validated by deletion admission; the
            // variant is encoded in the retained row and reconstructed here.
            super::pack_lifecycle::encoded_variant_id(import_value)?.as_bytes(),
            import_value,
        )?;
        if !records.is_empty() || projection.finalized_root != expected {
            return Err(blob_error(BlobStoreError::SchemaInvariant(
                "Blob pack deletion commitment differs from retained evidence",
            )));
        }
        return Ok(());
    }
    let import = decode_import(import_value)?;
    if import.finalized_manifest_digest != expected {
        return Err(blob_error(BlobStoreError::SchemaInvariant(
            "Blob deletion manifest root differs from its exact retained import",
        )));
    }
    if let Some(expected) = expected
        && (u64::try_from(records.len()).ok() != Some(import.chunk_count)
            || exact_pending_manifest_digest(&import, records)? != expected)
    {
        return Err(blob_error(BlobStoreError::SchemaInvariant(
            "Blob deletion manifest root differs from its exact retained chunks",
        )));
    }
    Ok(())
}

/// Returns only the audited import identity and authenticated lineage needed
/// to construct permanent lifecycle fences.
pub(super) fn audited_lifecycle_imports_write(
    write: &redb::WriteTransaction,
) -> Result<Vec<AuditedLifecycleImport>, StoreError> {
    let imports = write.open_table(BLOB_IMPORTS)?;
    let mut audited = imports
        .iter()?
        .map(|row| {
            let (key, value) = row?;
            lifecycle_import_from_record(
                parse_variant_id(key.value())?,
                decode_import(value.value())?,
            )
        })
        .collect::<Result<Vec<_>, StoreError>>()?;
    audited.extend(super::pack_lifecycle::audited_lifecycle_imports_write(
        write,
    )?);
    Ok(audited)
}

/// Read-only counterpart to [`audited_lifecycle_imports_write`].
pub(super) fn audited_lifecycle_imports_read(
    read: &redb::ReadTransaction,
) -> Result<Vec<AuditedLifecycleImport>, StoreError> {
    let imports = read.open_table(BLOB_IMPORTS)?;
    let mut audited = imports
        .iter()?
        .map(|row| {
            let (key, value) = row?;
            lifecycle_import_from_record(
                parse_variant_id(key.value())?,
                decode_import(value.value())?,
            )
        })
        .collect::<Result<Vec<_>, StoreError>>()?;
    audited.extend(super::pack_lifecycle::audited_lifecycle_imports_read(read)?);
    Ok(audited)
}

pub(crate) fn depot_owner_token_write(
    write: &redb::WriteTransaction,
) -> Result<[u8; 32], StoreError> {
    let table = write.open_table(BLOB_DEPOT_METADATA)?;
    decode_depot_owner_token(|field| {
        table
            .get(field)
            .map(|value| value.map(|value| value.value()))
            .map_err(StoreError::from)
    })
}

/// Performs the only safe owner-token migration before the Blob schema audit.
///
/// A wholly absent Blob group may be initialized later by the ordinary additive
/// migration, but only when the fixed depot root is absent. An exact pre-token
/// Blob group may receive a token only when every Blob row/counter is canonical
/// empty and that root is absent. Partial token fields, any logical Blob state,
/// or any fixed depot root fail without repair. Populated pre-marker depots are
/// deliberately rejected because their files cannot be attributed safely.
pub(crate) fn prepare_depot_owner_token_write(
    write: &redb::WriteTransaction,
    store_path: &Path,
) -> Result<(), StoreError> {
    let blob_tables = blob_table_names();
    let multimap_tables = write
        .list_multimap_tables()?
        .map(|table| table.name().to_owned())
        .collect::<BTreeSet<_>>();
    if multimap_tables.contains(OBSOLETE_PROFILE5_RECEIPT_TABLE_NAME) {
        return Err(blob_error(
            BlobStoreError::UnsupportedLegacyProfile5ReceiptSchema,
        ));
    }
    if multimap_tables
        .iter()
        .any(|table| blob_tables.contains(&table.as_str()))
    {
        return Err(blob_error(BlobStoreError::SchemaInvariant(
            "mission-scoped Blob schema has the wrong table kind",
        )));
    }
    let existing = write
        .list_tables()?
        .map(|table| table.name().to_owned())
        .collect::<BTreeSet<_>>();
    if existing.contains(OBSOLETE_PROFILE5_RECEIPT_TABLE_NAME) {
        return Err(blob_error(
            BlobStoreError::UnsupportedLegacyProfile5ReceiptSchema,
        ));
    }
    if !existing.contains(BLOB_DEPOT_METADATA.name()) {
        if OwnedDirectory::open_root_if_present(store_path)?.is_some() {
            return Err(blob_error(BlobStoreError::DepotIntegrity(
                "an unbound Blob depot root blocks whole-absent schema migration",
            )));
        }
        return Ok(());
    }
    let legacy = legacy_blob_table_names();
    let network = network_blob_table_names();
    let network_present = network
        .iter()
        .filter(|table| existing.contains(**table))
        .count();
    let network_current = network_present == network.len();
    if legacy.iter().any(|table| !existing.contains(*table))
        || !(network_present == 0 || network_current)
    {
        return Err(blob_error(BlobStoreError::SchemaInvariant(
            "mission-scoped Blob schema group is incomplete",
        )));
    }

    let mut depot = write.open_table(BLOB_DEPOT_METADATA)?;
    let fields = depot_owner_token_fields();
    let present = fields
        .iter()
        .map(|field| depot.get(*field).map(|value| value.is_some()))
        .collect::<Result<Vec<_>, _>>()?;
    if present.iter().all(|present| *present) {
        drop(depot);
        let _ = depot_owner_token_write(write)?;
        return Ok(());
    }
    if present.iter().any(|present| *present) {
        return Err(blob_error(BlobStoreError::SchemaInvariant(
            "Blob depot owner token is incomplete",
        )));
    }

    let populated = write.open_table(BLOB_PUBLICATIONS)?.len()? != 0
        || write.open_table(BLOB_BYTES)?.len()? != 0
        || write.open_table(BLOB_SEMANTIC_ITEMS)?.len()? != 0
        || write.open_table(BLOB_CONTENT_INDEX)?.len()? != 0
        || write.open_table(BLOB_ACCEPTANCE_MARKERS)?.len()? != 0
        || write.open_table(BLOB_OPERATIONS)?.len()? != 0
        || write.open_table(BLOB_IMPORTS)?.len()? != 0
        || write.open_table(BLOB_CHUNKS)?.len()? != 0
        || (network_current
            && (write.open_table(BLOB_PENDING_SOURCES)?.len()? != 0
                || write.open_table(BLOB_CARRIER_PREFIXES)?.len()? != 0
                || write.open_table(BLOB_CARRIER_FETCH_CURSORS)?.len()? != 0));
    if populated {
        return Err(blob_error(BlobStoreError::SchemaInvariant(
            "populated pre-marker Blob schema cannot acquire depot ownership",
        )));
    }
    let schema = depot.get(DEPOT_SCHEMA_VERSION)?.map(|value| value.value());
    let canonical_header = (depot.len()? == 4 && schema == Some(DEPOT_SCHEMA_VERSION_V1))
        || (depot.len()? == 5 && schema == Some(BLOB_DEPOT_SCHEMA_VERSION));
    let mut canonical_counters = true;
    for field in [
        DEPOT_VARIANT_COUNT,
        DEPOT_COMMITTED_CHUNK_COUNT,
        DEPOT_COMMITTED_FILE_BYTES,
    ] {
        canonical_counters &= depot.get(field)?.map(|value| value.value()) == Some(0);
    }
    if schema == Some(BLOB_DEPOT_SCHEMA_VERSION) {
        canonical_counters &= depot
            .get(DEPOT_RESERVED_FILE_BYTES)?
            .map(|value| value.value())
            == Some(0);
    }
    if !canonical_header || !canonical_counters {
        return Err(blob_error(BlobStoreError::SchemaInvariant(
            "pre-marker Blob depot metadata is not canonical empty state",
        )));
    }
    if schema == Some(DEPOT_SCHEMA_VERSION_V1) {
        depot.insert(DEPOT_RESERVED_FILE_BYTES, 0)?;
        depot.insert(DEPOT_SCHEMA_VERSION, BLOB_DEPOT_SCHEMA_VERSION)?;
    }
    let metadata = write.open_table(METADATA)?;
    for field in blob_global_metadata_fields() {
        if metadata.get(field)?.map(|value| value.value()) != Some(0) {
            return Err(blob_error(BlobStoreError::SchemaInvariant(
                "pre-marker Blob aggregate metadata is not canonical empty state",
            )));
        }
    }
    if OwnedDirectory::open_root_if_present(store_path)?.is_some() {
        return Err(blob_error(BlobStoreError::DepotIntegrity(
            "a pre-marker Blob depot root cannot be attributed safely",
        )));
    }

    let token = generate_depot_owner_token()?;
    for (field, chunk) in fields.into_iter().zip(token.chunks_exact(8)) {
        depot.insert(
            field,
            u64::from_be_bytes(chunk.try_into().map_err(|_| {
                blob_error(BlobStoreError::SchemaInvariant(
                    "Blob depot owner token chunk has invalid length",
                ))
            })?),
        )?;
    }
    Ok(())
}

pub(crate) fn depot_owner_token_read(read: &redb::ReadTransaction) -> Result<[u8; 32], StoreError> {
    let table = read.open_table(BLOB_DEPOT_METADATA)?;
    decode_depot_owner_token(|field| {
        table
            .get(field)
            .map(|value| value.map(|value| value.value()))
            .map_err(StoreError::from)
    })
}

fn decode_depot_owner_token(
    mut read: impl FnMut(&'static str) -> Result<Option<u64>, StoreError>,
) -> Result<[u8; 32], StoreError> {
    let mut token = [0u8; 32];
    for (index, field) in depot_owner_token_fields().into_iter().enumerate() {
        let value = read(field)?.ok_or_else(|| {
            blob_error(BlobStoreError::SchemaInvariant(
                "Blob depot owner token is incomplete",
            ))
        })?;
        token[index * 8..(index + 1) * 8].copy_from_slice(&value.to_be_bytes());
    }
    if token == [0; 32] {
        return Err(blob_error(BlobStoreError::SchemaInvariant(
            "Blob depot owner token is invalid",
        )));
    }
    Ok(token)
}

pub(crate) fn bind_depot_owner_write(
    write: &redb::WriteTransaction,
    store_path: &Path,
    backing_identity: StoreBackingIdentity,
    owner_token: [u8; 32],
    stats: BlobStoreStats,
) -> Result<[u8; 32], StoreError> {
    let expected = depot_owner_binding(store_path, backing_identity, owner_token)?;
    let mut depot = write.open_table(BLOB_DEPOT_METADATA)?;
    let fields = depot_owner_binding_fields();
    let values = fields
        .iter()
        .map(|field| {
            depot
                .get(*field)
                .map(|value| value.map(|value| value.value()))
                .map_err(StoreError::from)
        })
        .collect::<Result<Vec<_>, _>>()?;
    if values.iter().all(Option::is_none) {
        if stats != BlobStoreStats::default()
            || OwnedDirectory::open_root_if_present(store_path)?.is_some()
        {
            return Err(blob_error(BlobStoreError::DepotIntegrity(
                "logical Blob state or a fixed Blob depot root cannot acquire a new owner binding",
            )));
        }
        for (field, chunk) in fields.into_iter().zip(expected.chunks_exact(8)) {
            depot.insert(
                field,
                u64::from_be_bytes(chunk.try_into().map_err(|_| {
                    blob_error(BlobStoreError::SchemaInvariant(
                        "Blob depot owner binding chunk has invalid length",
                    ))
                })?),
            )?;
        }
        return Ok(expected);
    }
    if values.iter().any(Option::is_none) {
        return Err(blob_error(BlobStoreError::SchemaInvariant(
            "Blob depot owner binding is incomplete",
        )));
    }
    let mut durable = [0u8; 32];
    for (index, value) in values.into_iter().enumerate() {
        let value = value.ok_or_else(|| {
            blob_error(BlobStoreError::SchemaInvariant(
                "Blob depot owner binding is incomplete",
            ))
        })?;
        durable[index * 8..(index + 1) * 8].copy_from_slice(&value.to_be_bytes());
    }
    if durable != expected {
        return Err(blob_error(BlobStoreError::DepotIntegrity(
            "database-persisted Blob owner binding differs from its exact path/backing",
        )));
    }
    Ok(expected)
}

/// Returns the already persisted derived owner/backing binding. The caller
/// receives no path material and cannot supply a path to a durable record.
pub(super) fn depot_owner_binding_read(
    read: &redb::ReadTransaction,
) -> Result<[u8; 32], StoreError> {
    let table = read.open_table(BLOB_DEPOT_METADATA)?;
    let mut binding = [0u8; 32];
    for (index, field) in depot_owner_binding_fields().into_iter().enumerate() {
        let value = table
            .get(field)?
            .ok_or_else(|| {
                blob_error(BlobStoreError::SchemaInvariant(
                    "Blob depot owner binding is incomplete",
                ))
            })?
            .value();
        binding[index * 8..(index + 1) * 8].copy_from_slice(&value.to_be_bytes());
    }
    Ok(binding)
}

fn optional_depot_owner_binding(
    mut read: impl FnMut(&'static str) -> Result<Option<u64>, StoreError>,
) -> Result<Option<[u8; 32]>, StoreError> {
    let values = depot_owner_binding_fields()
        .into_iter()
        .map(&mut read)
        .collect::<Result<Vec<_>, _>>()?;
    if values.iter().all(Option::is_none) {
        return Ok(None);
    }
    if values.iter().any(Option::is_none) {
        return Err(blob_error(BlobStoreError::SchemaInvariant(
            "Blob depot owner binding is incomplete",
        )));
    }
    let mut binding = [0u8; 32];
    for (index, value) in values.into_iter().enumerate() {
        binding[index * 8..(index + 1) * 8]
            .copy_from_slice(&value.expect("all binding fields checked").to_be_bytes());
    }
    if binding == [0; 32] {
        return Err(blob_error(BlobStoreError::SchemaInvariant(
            "Blob depot owner binding is invalid",
        )));
    }
    Ok(Some(binding))
}

pub(super) fn depot_owner_binding_if_present_write(
    write: &redb::WriteTransaction,
) -> Result<Option<[u8; 32]>, StoreError> {
    let table = write.open_table(BLOB_DEPOT_METADATA)?;
    optional_depot_owner_binding(|field| {
        table
            .get(field)
            .map(|value| value.map(|value| value.value()))
            .map_err(StoreError::from)
    })
}

pub(super) fn depot_owner_binding_if_present_read(
    read: &redb::ReadTransaction,
) -> Result<Option<[u8; 32]>, StoreError> {
    let table = read.open_table(BLOB_DEPOT_METADATA)?;
    optional_depot_owner_binding(|field| {
        table
            .get(field)
            .map(|value| value.map(|value| value.value()))
            .map_err(StoreError::from)
    })
}

pub(super) fn require_depot_owner_binding_write(
    write: &redb::WriteTransaction,
    store_path: &Path,
    backing_identity: StoreBackingIdentity,
    owner_token: [u8; 32],
) -> Result<[u8; 32], StoreError> {
    let table = write.open_table(BLOB_DEPOT_METADATA)?;
    require_depot_owner_binding(
        |field| {
            table
                .get(field)
                .map(|value| value.map(|value| value.value()))
                .map_err(StoreError::from)
        },
        store_path,
        backing_identity,
        owner_token,
    )
}

fn require_depot_owner_binding_read(
    read: &redb::ReadTransaction,
    store_path: &Path,
    backing_identity: StoreBackingIdentity,
    owner_token: [u8; 32],
) -> Result<[u8; 32], StoreError> {
    let table = read.open_table(BLOB_DEPOT_METADATA)?;
    require_depot_owner_binding(
        |field| {
            table
                .get(field)
                .map(|value| value.map(|value| value.value()))
                .map_err(StoreError::from)
        },
        store_path,
        backing_identity,
        owner_token,
    )
}

fn depot_is_canonical_empty_read(read: &redb::ReadTransaction) -> Result<bool, StoreError> {
    if read.open_table(BLOB_IMPORTS)?.len()? != 0 || read.open_table(BLOB_CHUNKS)?.len()? != 0 {
        return Ok(false);
    }
    let metadata = read.open_table(BLOB_DEPOT_METADATA)?;
    if metadata
        .get(DEPOT_SCHEMA_VERSION)?
        .map(|value| value.value())
        != Some(BLOB_DEPOT_SCHEMA_VERSION)
    {
        return Err(blob_error(BlobStoreError::SchemaInvariant(
            "Blob depot metadata schema is incomplete or unknown",
        )));
    }
    for field in [
        DEPOT_VARIANT_COUNT,
        DEPOT_COMMITTED_CHUNK_COUNT,
        DEPOT_COMMITTED_FILE_BYTES,
        DEPOT_RESERVED_FILE_BYTES,
    ] {
        if metadata.get(field)?.map(|value| value.value()) != Some(0) {
            return Ok(false);
        }
    }
    Ok(true)
}

fn require_depot_owner_binding(
    mut read: impl FnMut(&'static str) -> Result<Option<u64>, StoreError>,
    store_path: &Path,
    backing_identity: StoreBackingIdentity,
    owner_token: [u8; 32],
) -> Result<[u8; 32], StoreError> {
    let expected = depot_owner_binding(store_path, backing_identity, owner_token)?;
    let mut durable = [0u8; 32];
    for (index, field) in depot_owner_binding_fields().into_iter().enumerate() {
        let value = read(field)?.ok_or_else(|| {
            blob_error(BlobStoreError::SchemaInvariant(
                "Blob depot owner binding is incomplete",
            ))
        })?;
        durable[index * 8..(index + 1) * 8].copy_from_slice(&value.to_be_bytes());
    }
    if durable != expected {
        return Err(blob_error(BlobStoreError::DepotIntegrity(
            "database-persisted Blob owner binding differs from its exact path/backing",
        )));
    }
    Ok(expected)
}

pub(crate) fn audit_depot_write(
    write: &redb::WriteTransaction,
    store_path: &Path,
    backing_identity: StoreBackingIdentity,
    owner_token: [u8; 32],
    expected: BlobStoreStats,
) -> Result<(), StoreError> {
    let owner_binding =
        require_depot_owner_binding_write(write, store_path, backing_identity, owner_token)?;
    let deletion = super::deletion::audit_blob_deletion_write(write, Some(owner_binding))?;
    let mut upload_packs = super::upload::upload_pack_expectations_write(write)?;
    upload_packs.extend(super::pack_lifecycle::active_pack_expectations_write(
        write,
    )?);
    if expected == BlobStoreStats::default() {
        if let Some(root) = OwnedDirectory::open_root_if_present(store_path)? {
            match root.read_owner_marker()? {
                Some(_) => {
                    root.require_store_binding(store_path, backing_identity, owner_token)?;
                    let completed = super::pack::audit_upload_packs_write(&root, &upload_packs)?;
                    if !completed.is_empty() {
                        return Err(blob_error(BlobStoreError::DepotIntegrity(
                            "Blob upload cleanup was not recovered before accounting audit",
                        )));
                    }
                    reclaim_unmarked_artifacts(write, &root, &BTreeMap::new(), &deletion)?;
                }
                None => {
                    return Err(blob_error(BlobStoreError::DepotIntegrity(
                        "fixed Blob depot root is missing its owner marker",
                    )));
                }
            }
        } else if !upload_packs.is_empty() {
            return Err(blob_error(BlobStoreError::DepotIntegrity(
                "durable Blob upload depot root is missing",
            )));
        }
        return Ok(());
    }
    let root = OwnedDirectory::open_root_if_present(store_path)?.ok_or_else(|| {
        blob_error(BlobStoreError::DepotIntegrity(
            "populated Blob depot root is missing",
        ))
    })?;
    root.require_store_binding(store_path, backing_identity, owner_token)?;
    let completed = super::pack::audit_upload_packs_write(&root, &upload_packs)?;
    if !completed.is_empty() {
        return Err(blob_error(BlobStoreError::DepotIntegrity(
            "Blob upload cleanup was not recovered before accounting audit",
        )));
    }
    audit_deletion_storage(&root, &deletion, false)?;
    let mut committed = committed_chunk_map_write(write)?;
    let deletion_variants = protect_queued_deletion_chunks(&mut committed, &deletion)?;
    verify_all_marked_files_write(write, &root, &committed, &deletion_variants)?;
    reclaim_unmarked_artifacts(write, &root, &committed, &deletion)?;
    audit_deletion_storage(&root, &deletion, true)
}

pub(crate) fn recover_upload_pack_transitions_write(
    write: &redb::WriteTransaction,
    store_path: &Path,
    backing_identity: StoreBackingIdentity,
) -> Result<(), StoreError> {
    if !write
        .list_tables()?
        .any(|table| table.name() == super::BLOB_UPLOADS.name())
    {
        return Ok(());
    }
    let mut expected = super::upload::upload_pack_expectations_write(write)?;
    expected.extend(super::pack_lifecycle::active_pack_expectations_write(
        write,
    )?);
    let Some(root) = OwnedDirectory::open_root_if_present(store_path)? else {
        if expected.is_empty() {
            return Ok(());
        }
        return Err(blob_error(BlobStoreError::DepotIntegrity(
            "durable Blob upload depot root is missing",
        )));
    };
    let owner_token = depot_owner_token_write(write)?;
    root.require_store_binding(store_path, backing_identity, owner_token)?;
    let completed = super::pack::audit_upload_packs_write(&root, &expected)?;
    super::upload::finish_upload_cleanups_write(write, &completed)
}

pub(crate) fn reclaim_upload_cleanup_markers_after_commit(
    write: &redb::WriteTransaction,
    store_path: &Path,
    backing_identity: StoreBackingIdentity,
    owner_token: [u8; 32],
) -> Result<(), StoreError> {
    if !write
        .list_tables()?
        .any(|table| table.name() == super::BLOB_UPLOADS.name())
    {
        return Ok(());
    }
    let mut expected = super::upload::upload_pack_expectations_write(write)?;
    expected.extend(super::pack_lifecycle::active_pack_expectations_write(
        write,
    )?);
    let Some(root) = OwnedDirectory::open_root_if_present(store_path)? else {
        return if expected.is_empty() {
            Ok(())
        } else {
            Err(blob_error(BlobStoreError::DepotIntegrity(
                "durable Blob upload depot root is missing",
            )))
        };
    };
    root.require_store_binding(store_path, backing_identity, owner_token)?;
    super::pack::reclaim_row_absent_cleanup_markers(&root, &expected)
}

pub(crate) fn audit_depot_read(
    read: &redb::ReadTransaction,
    store_path: &Path,
    backing_identity: StoreBackingIdentity,
    owner_token: [u8; 32],
    expected: BlobStoreStats,
) -> Result<(), StoreError> {
    let owner_binding =
        require_depot_owner_binding_read(read, store_path, backing_identity, owner_token)?;
    let deletion = super::deletion::inspect_blob_deletion_read(read, Some(owner_binding))?;
    let mut upload_packs = super::upload::upload_pack_expectations_read(read)?;
    upload_packs.extend(super::pack_lifecycle::active_pack_expectations_read(read)?);
    let Some(root) = OwnedDirectory::open_root_if_present(store_path)? else {
        if expected.variants == 0 && upload_packs.is_empty() {
            return Ok(());
        }
        return Err(blob_error(BlobStoreError::DepotIntegrity(
            "marked Blob chunks exist but the depot root is missing",
        )));
    };
    root.require_store_binding(store_path, backing_identity, owner_token)?;
    super::pack::audit_upload_packs_read(&root, &upload_packs)?;
    audit_deletion_storage(&root, &deletion, true)?;
    let mut committed = committed_chunk_map_read(read)?;
    let deletion_variants = protect_queued_deletion_chunks(&mut committed, &deletion)?;
    verify_all_marked_files_read(read, &root, &committed, &deletion_variants)?;
    audit_unmarked_artifacts_read(read, &root, &committed, &deletion)
}

pub(super) fn verify_completion(
    store: &Store,
    completion: &BlobDepotCompletion,
) -> Result<(), StoreError> {
    store.require_live()?;
    #[cfg(test)]
    store
        .blob_depot_test_counters
        .full_completion_rechecks
        .fetch_add(1, Ordering::Relaxed);
    if !Arc::ptr_eq(&completion.authority, &store.blob_completion_authority)
        || completion.backing_identity != store.backing_identity
    {
        return Err(blob_error(BlobStoreError::CompletionMismatch));
    }
    let read = store.database.begin_read()?;
    super::deletion::require_variant_available_read(&read, completion.variant_id)?;
    let root = OwnedDirectory::open_root_if_present(&store.path)?.ok_or_else(|| {
        blob_error(BlobStoreError::DepotIntegrity(
            "completed Blob depot root is missing",
        ))
    })?;
    root.require_store_binding(
        &store.path,
        store.backing_identity,
        store.blob_depot_owner_token,
    )?;
    let import = load_import_read(&read, completion.variant_id)?
        .ok_or_else(|| blob_error(BlobStoreError::CompletionMismatch))?;
    let import_fingerprint = <[u8; 32]>::from(Sha256::digest(encode_import(&import)?));
    if import.variant_id != completion.variant_id
        || import.blob_id != completion.blob_id
        || import.content_group != completion.content_group
        || import.epoch != completion.epoch
        || import.total_len != completion.total_len
        || import.chunk_size != completion.chunk_size
        || import.physical_lineage != Some(completion.physical_lineage)
        || import.chunk_count != completion.chunk_count
        || import.finalized_manifest_digest != Some(completion.manifest_digest)
        || import_fingerprint != completion.import_fingerprint
    {
        return Err(blob_error(BlobStoreError::CompletionMismatch));
    }
    verify_import_files_read(&read, &root, &import)
}

pub(super) fn audit_publication_import_write(
    write: &redb::WriteTransaction,
    variant_id: BlobVariantId,
    blob_id: BlobId,
    epoch: u64,
    manifest_digest: [u8; 32],
    chunk_count: u64,
    physical_lineage: Option<[u8; 32]>,
) -> Result<(), StoreError> {
    if let Some(pack) = write
        .open_table(super::pack_lifecycle::BLOB_PROFILE5_PACKS)?
        .get(variant_id.as_bytes().as_slice())?
        .map(|value| value.value().to_vec())
    {
        let owner_binding = depot_owner_binding_if_present_write(write)?.ok_or_else(|| {
            blob_error(BlobStoreError::SchemaInvariant(
                "Profile-5 pack exists without depot owner binding",
            ))
        })?;
        return super::pack_lifecycle::audit_publication_evidence(
            &pack,
            variant_id,
            blob_id,
            epoch,
            manifest_digest,
            chunk_count,
            physical_lineage,
            owner_binding,
        );
    }
    let import = load_import_write(write, variant_id)?.ok_or_else(|| {
        blob_error(BlobStoreError::SchemaInvariant(
            "accepted Blob publication is missing its depot import",
        ))
    })?;
    audit_publication_import_record(
        &import,
        variant_id,
        blob_id,
        epoch,
        manifest_digest,
        chunk_count,
        physical_lineage,
    )
}

pub(super) fn audit_publication_import_evidence(
    encoded: &[u8],
    variant_id: BlobVariantId,
    blob_id: BlobId,
    epoch: u64,
    manifest_digest: [u8; 32],
    chunk_count: u64,
    physical_lineage: Option<[u8; 32]>,
) -> Result<(), StoreError> {
    let import = decode_import(encoded)?;
    audit_publication_import_record(
        &import,
        variant_id,
        blob_id,
        epoch,
        manifest_digest,
        chunk_count,
        physical_lineage,
    )
}

pub(super) fn audit_publication_import_read(
    read: &redb::ReadTransaction,
    variant_id: BlobVariantId,
    blob_id: BlobId,
    epoch: u64,
    manifest_digest: [u8; 32],
    chunk_count: u64,
    physical_lineage: Option<[u8; 32]>,
) -> Result<(), StoreError> {
    if let Some(pack) = read
        .open_table(super::pack_lifecycle::BLOB_PROFILE5_PACKS)?
        .get(variant_id.as_bytes().as_slice())?
        .map(|value| value.value().to_vec())
    {
        let owner_binding = depot_owner_binding_if_present_read(read)?.ok_or_else(|| {
            blob_error(BlobStoreError::SchemaInvariant(
                "Profile-5 pack exists without depot owner binding",
            ))
        })?;
        return super::pack_lifecycle::audit_publication_evidence(
            &pack,
            variant_id,
            blob_id,
            epoch,
            manifest_digest,
            chunk_count,
            physical_lineage,
            owner_binding,
        );
    }
    let import = load_import_read(read, variant_id)?.ok_or_else(|| {
        blob_error(BlobStoreError::SchemaInvariant(
            "accepted Blob publication is missing its depot import",
        ))
    })?;
    audit_publication_import_record(
        &import,
        variant_id,
        blob_id,
        epoch,
        manifest_digest,
        chunk_count,
        physical_lineage,
    )
}

fn audit_publication_import_record(
    import: &ImportRecord,
    variant_id: BlobVariantId,
    blob_id: BlobId,
    epoch: u64,
    manifest_digest: [u8; 32],
    chunk_count: u64,
    physical_lineage: Option<[u8; 32]>,
) -> Result<(), StoreError> {
    if import.variant_id != variant_id
        || import.variant_id != BlobVariantId::for_content(blob_id, &import.content_group, epoch)
        || import.blob_id != blob_id
        || import.epoch != epoch
        || import.chunk_count != chunk_count
        || physical_lineage.is_some_and(|lineage| import.physical_lineage != Some(lineage))
        || import.finalized_manifest_digest != Some(manifest_digest)
    {
        return Err(blob_error(BlobStoreError::SchemaInvariant(
            "accepted Blob publication differs from its finalized depot import",
        )));
    }
    Ok(())
}

/// Proves that one network-pending source still has the exact physical plan
/// installed atomically with it. Imports may be shared by several signed
/// sources, but every pending source requires the matching lineage-bound import
/// and one durable expected chunk record for every authenticated carrier index.
// Every argument is one independently authenticated or durable component of
// the pending source-to-depot plan reconstructed during strict open audit.
#[allow(clippy::too_many_arguments)]
pub(super) fn audit_pending_network_plan(
    imports: &impl ReadableTable<&'static [u8], &'static [u8]>,
    chunks: &impl ReadableTable<&'static [u8], &'static [u8]>,
    source: BlobTransferId,
    variant_id: BlobVariantId,
    blob_id: BlobId,
    epoch: u64,
    manifest_digest: [u8; 32],
    physical_lineage: [u8; 32],
    route: BlobRouteCommitment,
    carriers: &[PendingBlobCarrierRecord],
) -> Result<(), StoreError> {
    let chunk_count =
        u64::try_from(carriers.len()).map_err(|_| StoreError::ItemCountAccountingOverflow)?;
    let import = imports
        .get(variant_id.as_bytes().as_slice())?
        .map(|value| decode_import(value.value()))
        .transpose()?
        .ok_or_else(|| {
            blob_error(BlobStoreError::SchemaInvariant(
                "pending Blob source is missing its exact depot import",
            ))
        })?;
    if import.variant_id != variant_id
        || import.variant_id != BlobVariantId::for_content(blob_id, &import.content_group, epoch)
        || import.blob_id != blob_id
        || import.epoch != epoch
        || import.physical_lineage != Some(physical_lineage)
        || import.chunk_count != chunk_count
        || route.blob_id() != blob_id
        || route.chunk_count() != chunk_count
        || import
            .finalized_manifest_digest
            .is_some_and(|digest| digest != manifest_digest)
    {
        return Err(blob_error(BlobStoreError::SchemaInvariant(
            "pending Blob source differs from its exact depot import",
        )));
    }
    let mut records = Vec::with_capacity(carriers.len());
    for index in 0..chunk_count {
        let key = chunk_key(variant_id, index);
        let state = chunks
            .get(key.as_slice())?
            .map(|value| decode_chunk_state(value.value()))
            .transpose()?
            .ok_or_else(|| {
                blob_error(BlobStoreError::SchemaInvariant(
                    "pending Blob source is missing an expected depot chunk",
                ))
            })?;
        validate_chunk_state_lengths(&import, index, state)?;
        records.push(state.expected.ok_or_else(|| {
            blob_error(BlobStoreError::SchemaInvariant(
                "pending Blob source has an unreserved depot chunk",
            ))
        })?);
    }
    if exact_pending_manifest_digest(&import, &records)? != manifest_digest {
        return Err(blob_error(BlobStoreError::SchemaInvariant(
            "pending Blob source differs from its exact canonical manifest",
        )));
    }
    let levels = exact_pending_route_levels(blob_id, &records)?;
    let exact_root = if records.is_empty() {
        let mut digest = audit_domain_hasher(CANONICAL_ROUTE_EMPTY_DOMAIN);
        digest.update(CANONICAL_PROTOCOL_VERSION.to_be_bytes());
        digest.update(blob_id.as_bytes());
        digest.update(0_u64.to_be_bytes());
        digest.finalize().into()
    } else {
        *levels
            .last()
            .and_then(|level| level.first())
            .ok_or_else(|| {
                blob_error(BlobStoreError::SchemaInvariant(
                    "pending Blob route tree is empty",
                ))
            })?
    };
    if &exact_root != route.root() {
        return Err(blob_error(BlobStoreError::SchemaInvariant(
            "pending Blob source differs from its exact route commitment",
        )));
    }
    let mut expected_carriers = Vec::with_capacity(records.len());
    for (index, record) in records.iter().copied().enumerate() {
        let index = u64::try_from(index).map_err(|_| StoreError::ItemCountAccountingOverflow)?;
        let proof = exact_pending_route_proof(&levels, index)?;
        let object = exact_pending_carrier_object(source, blob_id, index, record, &proof);
        let total_len = CANONICAL_TRANSFER_FIXED_LEN
            .checked_add(
                u64::try_from(proof.len())
                    .map_err(|_| StoreError::PayloadByteAccountingOverflow)?
                    .checked_mul(32)
                    .ok_or(StoreError::PayloadByteAccountingOverflow)?,
            )
            .and_then(|length| length.checked_add(u64::from(record.ciphertext_len())))
            .ok_or(StoreError::PayloadByteAccountingOverflow)?;
        expected_carriers.push(PendingBlobCarrierRecord {
            object,
            total_len,
            index,
        });
    }
    expected_carriers.sort_unstable_by_key(|carrier| carrier.object);
    if expected_carriers != carriers {
        return Err(blob_error(BlobStoreError::SchemaInvariant(
            "pending Blob source differs from its exact carrier plan",
        )));
    }
    Ok(())
}

fn exact_pending_manifest_digest(
    import: &ImportRecord,
    records: &[BlobChunkRecord],
) -> Result<[u8; 32], StoreError> {
    let media_len = import
        .media_type
        .as_ref()
        .map(|value| u16::try_from(value.len()))
        .transpose()
        .map_err(|_| {
            blob_error(BlobStoreError::SchemaInvariant(
                "pending Blob import media type exceeds its canonical bound",
            ))
        })?;
    let schema_len = u16::try_from(import.schema_id.len()).map_err(|_| {
        blob_error(BlobStoreError::SchemaInvariant(
            "pending Blob import schema exceeds its canonical bound",
        ))
    })?;
    let mut digest = audit_domain_hasher(CANONICAL_MANIFEST_DIGEST_DOMAIN);
    digest.update(CANONICAL_MANIFEST_MAGIC);
    digest.update(CANONICAL_MANIFEST_VERSION.to_be_bytes());
    digest.update(CANONICAL_PROTOCOL_VERSION.to_be_bytes());
    digest.update(CANONICAL_SUITE_ID.to_be_bytes());
    digest.update(import.blob_id.as_bytes());
    digest.update(import.total_len.to_be_bytes());
    digest.update(import.chunk_size.to_be_bytes());
    digest.update(import.chunk_count.to_be_bytes());
    digest.update(import.content_group);
    digest.update(import.epoch.to_be_bytes());
    match (&import.media_type, media_len) {
        (Some(value), Some(length)) => {
            digest.update([1]);
            digest.update(length.to_be_bytes());
            digest.update(value.as_bytes());
        }
        (None, None) => digest.update([0]),
        _ => unreachable!("media length follows media presence"),
    }
    digest.update(schema_len.to_be_bytes());
    digest.update(&import.schema_id);
    for record in records {
        digest.update(record.plaintext_sha256());
        digest.update(record.ciphertext_sha256());
        digest.update(record.plaintext_len().to_be_bytes());
        digest.update(record.ciphertext_len().to_be_bytes());
    }
    digest.update(import.whole_plaintext_sha256);
    Ok(digest.finalize().into())
}

fn exact_pending_route_levels(
    blob_id: BlobId,
    records: &[BlobChunkRecord],
) -> Result<Vec<Vec<[u8; 32]>>, StoreError> {
    let leaves = records
        .iter()
        .copied()
        .enumerate()
        .map(|(index, record)| {
            let index =
                u64::try_from(index).map_err(|_| StoreError::ItemCountAccountingOverflow)?;
            let mut digest = audit_domain_hasher(CANONICAL_ROUTE_LEAF_DOMAIN);
            digest.update(CANONICAL_PROTOCOL_VERSION.to_be_bytes());
            digest.update(blob_id.as_bytes());
            digest.update(index.to_be_bytes());
            digest.update(record.ciphertext_sha256());
            digest.update(record.ciphertext_len().to_be_bytes());
            Ok(digest.finalize().into())
        })
        .collect::<Result<Vec<[u8; 32]>, StoreError>>()?;
    let mut levels = vec![leaves];
    let mut level = 0u16;
    while levels.last().is_some_and(|current| current.len() > 1) {
        let current = levels.last().ok_or_else(|| {
            blob_error(BlobStoreError::SchemaInvariant(
                "pending Blob route tree is empty",
            ))
        })?;
        let mut next = Vec::with_capacity(current.len().div_ceil(2));
        for pair in current.chunks(2) {
            next.push(if pair.len() == 2 {
                let mut digest = audit_domain_hasher(CANONICAL_ROUTE_NODE_DOMAIN);
                digest.update(CANONICAL_PROTOCOL_VERSION.to_be_bytes());
                digest.update(level.to_be_bytes());
                digest.update(pair[0]);
                digest.update(pair[1]);
                digest.finalize().into()
            } else {
                pair[0]
            });
        }
        levels.push(next);
        level = level
            .checked_add(1)
            .ok_or(StoreError::ItemCountAccountingOverflow)?;
    }
    Ok(levels)
}

fn exact_pending_route_proof(
    levels: &[Vec<[u8; 32]>],
    index: u64,
) -> Result<Vec<[u8; 32]>, StoreError> {
    let mut position =
        usize::try_from(index).map_err(|_| StoreError::ItemCountAccountingOverflow)?;
    if levels.first().is_none_or(|leaves| position >= leaves.len()) {
        return Err(blob_error(BlobStoreError::SchemaInvariant(
            "pending Blob carrier index is outside its exact route",
        )));
    }
    let mut proof = Vec::with_capacity(levels.len().saturating_sub(1));
    for current in levels.iter().take(levels.len().saturating_sub(1)) {
        let sibling = if position & 1 == 0 {
            position
                .checked_add(1)
                .filter(|sibling| *sibling < current.len())
        } else {
            Some(position - 1)
        };
        if let Some(sibling) = sibling {
            proof.push(current[sibling]);
        }
        position /= 2;
    }
    Ok(proof)
}

fn exact_pending_carrier_object(
    source: BlobTransferId,
    blob_id: BlobId,
    index: u64,
    record: BlobChunkRecord,
    proof: &[[u8; 32]],
) -> BlobCarrierObjectId {
    let mut digest = audit_domain_hasher(CANONICAL_TRANSFER_ID_DOMAIN);
    digest.update(CANONICAL_PROTOCOL_VERSION.to_be_bytes());
    digest.update(source.as_bytes());
    digest.update(blob_id.as_bytes());
    digest.update(index.to_be_bytes());
    digest.update(record.ciphertext_sha256());
    digest.update(record.ciphertext_len().to_be_bytes());
    digest.update([proof.len() as u8]);
    for sibling in proof {
        digest.update(sibling);
    }
    let mut bytes = [0u8; BLOB_CARRIER_OBJECT_ID_BYTES];
    bytes[0] = 2;
    bytes[1..].copy_from_slice(&<[u8; 32]>::from(digest.finalize()));
    BlobCarrierObjectId(bytes)
}

fn audit_domain_hasher(domain: &[u8]) -> Sha256 {
    let mut digest = Sha256::new();
    digest.update((domain.len() as u64).to_be_bytes());
    digest.update(domain);
    digest
}

fn audit_deletion_storage(
    root: &OwnedDirectory,
    deletion: &super::deletion::BlobDeletionAudit,
    require_pending_directory_empty: bool,
) -> Result<(), StoreError> {
    let root_entries = root.entry_names()?.into_iter().collect::<BTreeSet<_>>();
    for manifest in deletion.manifests.values() {
        let directory_name = hex32(manifest.variant_id.as_bytes());
        let directory_present = root_entries.contains(&directory_name);
        if !directory_present {
            if manifest.phase == super::deletion::BlobDeletionPhase::DeletingChunks
                && manifest.chunks.iter().try_fold(false, |committed, chunk| {
                    Ok::<_, StoreError>(
                        committed
                            || deletion_chunk_projection(
                                &manifest.original_import,
                                chunk.index,
                                &chunk.original_chunk,
                            )?
                            .record
                            .is_some(),
                    )
                })?
            {
                return Err(blob_error(BlobStoreError::DepotIntegrity(
                    "deleting Blob variant directory is missing despite committed-file authority",
                )));
            }
            continue;
        }
        let directory = root
            .open_child_directory(&directory_name, false)
            .map_err(|_| {
                blob_error(BlobStoreError::DepotIntegrity(
                    "Blob deletion variant is not an owned directory",
                ))
            })?;
        let names = directory
            .entry_names()?
            .into_iter()
            .collect::<BTreeSet<_>>();
        for name in &names {
            if name.starts_with(TEMP_PREFIX) {
                continue;
            }
            if !manifest
                .chunks
                .iter()
                .any(|chunk| *name == chunk_file_name(chunk.index))
            {
                return Err(blob_error(BlobStoreError::DepotIntegrity(
                    "deleting Blob variant contains an unexpected artifact",
                )));
            }
        }
        if require_pending_directory_empty
            && manifest.phase == super::deletion::BlobDeletionPhase::DirectoryDeletePending
            && !names.is_empty()
        {
            return Err(blob_error(BlobStoreError::DepotIntegrity(
                "directory-pending Blob variant directory is not empty",
            )));
        }
        let import = decode_import(&manifest.original_import)?;
        for chunk in &manifest.chunks {
            let name = chunk_file_name(chunk.index);
            let present = names.contains(&name);
            let projected = deletion_chunk_projection(
                &manifest.original_import,
                chunk.index,
                &chunk.original_chunk,
            )?;
            match (chunk.state, projected.record, present) {
                (super::deletion::BlobDeletionChunkState::DeleteQueued, _, true) => {
                    verify_deletion_file_if_present(
                        &directory,
                        &import,
                        chunk.index,
                        projected.cleanup,
                        projected.authorized_file_bytes,
                    )
                    .map_err(|failure| failure.error)?;
                }
                (super::deletion::BlobDeletionChunkState::DeletedDurable, Some(_), true) => {
                    return Err(blob_error(BlobStoreError::DepotIntegrity(
                        "durably deleted Blob chunk file is still present",
                    )));
                }
                (super::deletion::BlobDeletionChunkState::DeletedDurable, None, true) => {
                    verify_deletion_file_if_present(
                        &directory,
                        &import,
                        chunk.index,
                        projected.cleanup,
                        projected.authorized_file_bytes,
                    )
                    .map_err(|failure| failure.error)?;
                }
                _ => {}
            }
        }
    }
    Ok(())
}

fn verify_deletion_file_if_present(
    directory: &OwnedDirectory,
    import: &ImportRecord,
    index: u64,
    authority: DeletionChunkCleanupAuthority,
    authorized_file_bytes: u64,
) -> Result<Option<u64>, ManifestFileReadError> {
    let name = chunk_file_name(index);
    let Some(bytes) = directory.read_private_regular_file_if_present(
        &name,
        authorized_file_bytes.max(CHUNK_FILE_HEADER_BYTES),
    )?
    else {
        return Ok(None);
    };
    let bytes_read = u64::try_from(bytes.len()).map_err(|_| ManifestFileReadError {
        error: StoreError::PayloadByteAccountingOverflow,
        bytes_read: u64::MAX,
    })?;
    let verified = (|| -> Result<(), StoreError> {
        if bytes_read != authorized_file_bytes || bytes.len() < CHUNK_FILE_HEADER_LEN {
            return Err(blob_error(BlobStoreError::DepotIntegrity(
                "manifest-authorized Blob chunk length mismatches",
            )));
        }
        let (header, ciphertext) = bytes.split_at(CHUNK_FILE_HEADER_LEN);
        let mut cursor = MetadataCursor::new(header);
        if cursor.take(8)? != CHUNK_FILE_MAGIC
            || cursor.u8()? != CHUNK_FILE_VERSION
            || cursor.array::<32>()? != *import.variant_id.as_bytes()
            || cursor.array::<32>()? != *import.blob_id.as_bytes()
            || cursor.u64()? != index
        {
            return Err(blob_error(BlobStoreError::DepotIntegrity(
                "manifest-authorized Blob chunk identity header mismatches",
            )));
        }
        let plaintext_sha256 = cursor.array::<32>()?;
        let ciphertext_sha256 = cursor.array::<32>()?;
        let plaintext_len = cursor.u32()?;
        let ciphertext_len = cursor.u32()?;
        cursor.finish()?;
        let canonical_plaintext_len =
            expected_import_plaintext_len(import.total_len, import.chunk_count, index)?;
        if plaintext_len != canonical_plaintext_len
            || ciphertext_len
                != plaintext_len
                    .checked_add(BLOB_CHUNK_TAG_BYTES)
                    .ok_or(StoreError::PayloadByteAccountingOverflow)?
            || usize::try_from(ciphertext_len).ok() != Some(ciphertext.len())
            || <[u8; 32]>::from(Sha256::digest(ciphertext)) != ciphertext_sha256
        {
            return Err(blob_error(BlobStoreError::DepotIntegrity(
                "manifest-authorized Blob chunk lengths or ciphertext digest mismatch",
            )));
        }
        match authority {
            DeletionChunkCleanupAuthority::Committed(record)
                if plaintext_sha256 == *record.plaintext_sha256()
                    && ciphertext_sha256 == *record.ciphertext_sha256()
                    && plaintext_len == record.plaintext_len()
                    && ciphertext_len == record.ciphertext_len() => {}
            DeletionChunkCleanupAuthority::Expected(record)
                if plaintext_sha256 == *record.plaintext_sha256()
                    && ciphertext_sha256 == *record.ciphertext_sha256()
                    && plaintext_len == record.plaintext_len()
                    && ciphertext_len == record.ciphertext_len() => {}
            DeletionChunkCleanupAuthority::Digest(digest) if plaintext_sha256 == digest => {}
            DeletionChunkCleanupAuthority::Committed(_) => {
                return Err(blob_error(BlobStoreError::DepotIntegrity(
                    "manifest-authorized Blob chunk differs from its committed record",
                )));
            }
            DeletionChunkCleanupAuthority::Expected(_) => {
                return Err(blob_error(BlobStoreError::DepotIntegrity(
                    "manifest-authorized Blob chunk differs from its expected record",
                )));
            }
            DeletionChunkCleanupAuthority::Digest(_) => {
                return Err(blob_error(BlobStoreError::DepotIntegrity(
                    "manifest-authorized Blob chunk plaintext digest differs from digest authority",
                )));
            }
            DeletionChunkCleanupAuthority::Absent => {
                return Err(blob_error(BlobStoreError::DepotIntegrity(
                    "unmarked Blob chunk has no exact cleanup authority",
                )));
            }
        }
        Ok(())
    })();
    verified.map_err(|error| ManifestFileReadError { error, bytes_read })?;
    Ok(Some(bytes_read))
}

/// Deletes one exact manifest-owned chunk using only typed identity beneath
/// the already owner-bound depot root. The caller holds the depot lock and has
/// revalidated the durable manifest immediately before this call.
pub(super) fn delete_manifest_chunk(
    store_path: &Path,
    backing_identity: StoreBackingIdentity,
    owner_token: [u8; 32],
    manifest: &super::deletion::BlobDeletionManifestHeader,
    target: &super::deletion::BlobDeletionChunk,
) -> Result<u64, ManifestDeletionError> {
    if manifest.variant_id
        != BlobVariantId::for_content(manifest.blob_id, &manifest.content_group, manifest.epoch)
        || target.index
            >= super::depot::deletion_import_projection(
                manifest.variant_id.as_bytes(),
                &manifest.original_import,
            )?
            .chunk_count
    {
        return Err(blob_error(BlobStoreError::SchemaInvariant(
            "Blob deletion target is not canonical",
        ))
        .into());
    }
    let root = deletion_stage(
        OwnedDirectory::open_root_if_present(store_path),
        super::deletion::BlobDeletionFailureCategory::VariantDirectoryAccess,
    )?
    .ok_or_else(|| {
        blob_error(BlobStoreError::DepotIntegrity(
            "manifest-backed Blob depot root is missing",
        ))
    })?;
    deletion_stage(
        root.require_store_binding(store_path, backing_identity, owner_token),
        super::deletion::BlobDeletionFailureCategory::VariantDirectoryAccess,
    )?;
    let directory_name = hex32(manifest.variant_id.as_bytes());
    deletion_stage(
        maybe_inject_fault(&root.path, DepotFaultPoint::ManifestVariantDirectoryAccess),
        super::deletion::BlobDeletionFailureCategory::VariantDirectoryAccess,
    )?;
    let directory = match root.open_child_directory(&directory_name, false) {
        Ok(directory) => directory,
        Err(StoreError::Blob(BlobStoreError::Io(error)))
            if error.kind() == std::io::ErrorKind::NotFound =>
        {
            let projected = deletion_chunk_projection(
                &manifest.original_import,
                target.index,
                &target.original_chunk,
            )?;
            if projected.record.is_some() {
                return Err(blob_error(BlobStoreError::DepotIntegrity(
                    "deleting Blob variant directory disappeared before directory phase",
                ))
                .into());
            }
            deletion_stage(
                root.sync(),
                super::deletion::BlobDeletionFailureCategory::DepotDirectorySync,
            )?;
            return Ok(0);
        }
        Err(error @ StoreError::Blob(BlobStoreError::Io(_))) => {
            return Err(ManifestDeletionError {
                error: Box::new(error),
                retry: Some(super::deletion::BlobDeletionFailureCategory::VariantDirectoryAccess),
                files_examined: 1,
                bytes_examined: 0,
            });
        }
        Err(error) => return Err(error.into()),
    };
    let import = decode_import(&manifest.original_import)?;
    let projected = deletion_chunk_projection(
        &manifest.original_import,
        target.index,
        &target.original_chunk,
    )?;
    let verified_file_bytes = verify_deletion_file_if_present(
        &directory,
        &import,
        target.index,
        projected.cleanup,
        projected.authorized_file_bytes,
    )
    .map_err(|failure| ManifestDeletionError {
        retry: matches!(failure.error, StoreError::Blob(BlobStoreError::Io(_)))
            .then_some(super::deletion::BlobDeletionFailureCategory::ChunkUnlink),
        error: Box::new(failure.error),
        files_examined: 1,
        bytes_examined: failure.bytes_read,
    })?
    .unwrap_or(0);
    let target_present = verified_file_bytes != 0;
    deletion_stage_progress(
        maybe_inject_fault(&directory.path, DepotFaultPoint::ManifestChunkBeforeUnlink),
        super::deletion::BlobDeletionFailureCategory::ChunkUnlink,
        1,
        verified_file_bytes,
    )?;
    if target_present {
        deletion_stage_progress(
            directory.unlink_file_if_exists_no_sync(&chunk_file_name(target.index)),
            super::deletion::BlobDeletionFailureCategory::ChunkUnlink,
            1,
            verified_file_bytes,
        )?;
        deletion_stage_progress(
            maybe_inject_fault(&directory.path, DepotFaultPoint::ManifestChunkUnlinked),
            super::deletion::BlobDeletionFailureCategory::ChunkDirectorySync,
            1,
            verified_file_bytes,
        )?;
    }
    // An exact DeleteQueued row authorizes absence after a crash, but the
    // containing directory is unconditionally made durable before phase advance.
    deletion_stage_progress(
        directory.sync(),
        super::deletion::BlobDeletionFailureCategory::ChunkDirectorySync,
        1,
        verified_file_bytes,
    )?;
    deletion_stage_progress(
        maybe_inject_fault(
            &directory.path,
            DepotFaultPoint::ManifestChunkDirectorySynced,
        ),
        super::deletion::BlobDeletionFailureCategory::ChunkDirectorySync,
        1,
        verified_file_bytes,
    )?;
    Ok(verified_file_bytes)
}

/// Removes one exact empty manifest-owned variant directory and always syncs
/// the depot root, including interrupted retries where the directory is gone.
pub(super) fn delete_manifest_variant_directory(
    store_path: &Path,
    backing_identity: StoreBackingIdentity,
    owner_token: [u8; 32],
    manifest: &super::deletion::BlobDeletionManifestHeader,
) -> Result<(), ManifestDeletionError> {
    if super::pack_lifecycle::is_pack_evidence(&manifest.original_import) {
        let identity = super::pack_lifecycle::deletion_identity(&manifest.original_import)?;
        deletion_stage(
            super::pack::remove_lifecycle_pack(
                store_path,
                backing_identity,
                owner_token,
                &identity,
            ),
            super::deletion::BlobDeletionFailureCategory::VariantDirectoryRemove,
        )?;
        return Ok(());
    }
    let variant = manifest.variant_id;
    let root = deletion_stage(
        OwnedDirectory::open_root_if_present(store_path),
        super::deletion::BlobDeletionFailureCategory::VariantDirectoryAccess,
    )?
    .ok_or_else(|| {
        blob_error(BlobStoreError::DepotIntegrity(
            "manifest-backed Blob depot root is missing",
        ))
    })?;
    deletion_stage(
        root.require_store_binding(store_path, backing_identity, owner_token),
        super::deletion::BlobDeletionFailureCategory::VariantDirectoryAccess,
    )?;
    let name = hex32(variant.as_bytes());
    deletion_stage(
        maybe_inject_fault(&root.path, DepotFaultPoint::ManifestVariantDirectoryAccess),
        super::deletion::BlobDeletionFailureCategory::VariantDirectoryAccess,
    )?;
    match root.open_child_directory(&name, false) {
        Ok(directory) => {
            if !deletion_stage(
                directory.is_empty(),
                super::deletion::BlobDeletionFailureCategory::VariantDirectoryAccess,
            )? {
                return Err(blob_error(BlobStoreError::DepotIntegrity(
                    "directory-pending Blob variant is not empty",
                ))
                .into());
            }
            drop(directory);
            deletion_stage(
                maybe_inject_fault(&root.path, DepotFaultPoint::ManifestVariantDirectoryRemove),
                super::deletion::BlobDeletionFailureCategory::VariantDirectoryRemove,
            )?;
            deletion_stage(
                root.unlink_directory_if_exists_no_sync(&name),
                super::deletion::BlobDeletionFailureCategory::VariantDirectoryRemove,
            )?;
            deletion_stage(
                maybe_inject_fault(&root.path, DepotFaultPoint::ManifestVariantRemoved),
                super::deletion::BlobDeletionFailureCategory::DepotDirectorySync,
            )?;
            deletion_stage(
                root.sync(),
                super::deletion::BlobDeletionFailureCategory::DepotDirectorySync,
            )?;
            deletion_stage(
                maybe_inject_fault(&root.path, DepotFaultPoint::ManifestParentSynced),
                super::deletion::BlobDeletionFailureCategory::DepotDirectorySync,
            )?;
        }
        Err(StoreError::Blob(BlobStoreError::Io(error)))
            if error.kind() == std::io::ErrorKind::NotFound =>
        {
            deletion_stage(
                root.sync(),
                super::deletion::BlobDeletionFailureCategory::DepotDirectorySync,
            )?;
            deletion_stage(
                maybe_inject_fault(&root.path, DepotFaultPoint::ManifestParentSynced),
                super::deletion::BlobDeletionFailureCategory::DepotDirectorySync,
            )?;
        }
        Err(error @ StoreError::Blob(BlobStoreError::Io(_))) => {
            return Err(ManifestDeletionError {
                error: Box::new(error),
                retry: Some(super::deletion::BlobDeletionFailureCategory::VariantDirectoryAccess),
                files_examined: 1,
                bytes_examined: 0,
            });
        }
        Err(error) => return Err(error.into()),
    }
    Ok(())
}

fn protect_queued_deletion_chunks(
    committed: &mut BTreeMap<BlobVariantId, Vec<(u64, ChunkState)>>,
    deletion: &super::deletion::BlobDeletionAudit,
) -> Result<BTreeSet<BlobVariantId>, StoreError> {
    let mut variants = BTreeSet::new();
    for manifest in deletion.manifests.values() {
        if committed.contains_key(&manifest.variant_id) {
            return Err(blob_error(BlobStoreError::SchemaInvariant(
                "Blob variant has duplicate active and deletion file authority",
            )));
        }
        variants.insert(manifest.variant_id);
        let mut queued = Vec::new();
        for chunk in &manifest.chunks {
            if chunk.state == super::deletion::BlobDeletionChunkState::DeleteQueued {
                let state = decode_chunk_state(&chunk.original_chunk)?;
                if state.committed.is_some() {
                    queued.push((chunk.index, state));
                }
            }
        }
        committed.insert(manifest.variant_id, queued);
    }
    Ok(variants)
}

fn verify_all_marked_files_write(
    write: &redb::WriteTransaction,
    root: &OwnedDirectory,
    committed: &BTreeMap<BlobVariantId, Vec<(u64, ChunkState)>>,
    deletion_variants: &BTreeSet<BlobVariantId>,
) -> Result<(), StoreError> {
    for row in write.open_table(BLOB_IMPORTS)?.iter()? {
        let (_, value) = row?;
        let import = decode_import(value.value())?;
        if deletion_variants.contains(&import.variant_id) {
            continue;
        }
        verify_import_files_from_rows(
            root,
            &import,
            committed.get(&import.variant_id).map_or(&[], Vec::as_slice),
        )?;
    }
    Ok(())
}

fn verify_all_marked_files_read(
    read: &redb::ReadTransaction,
    root: &OwnedDirectory,
    committed: &BTreeMap<BlobVariantId, Vec<(u64, ChunkState)>>,
    deletion_variants: &BTreeSet<BlobVariantId>,
) -> Result<(), StoreError> {
    for row in read.open_table(BLOB_IMPORTS)?.iter()? {
        let (_, value) = row?;
        let import = decode_import(value.value())?;
        if deletion_variants.contains(&import.variant_id) {
            continue;
        }
        verify_import_files_from_rows(
            root,
            &import,
            committed.get(&import.variant_id).map_or(&[], Vec::as_slice),
        )?;
    }
    Ok(())
}

fn verify_import_files_from_rows(
    root: &OwnedDirectory,
    import: &ImportRecord,
    committed: &[(u64, ChunkState)],
) -> Result<(), StoreError> {
    if import.finalized_manifest_digest.is_some()
        && u64::try_from(committed.len()).ok() != Some(import.chunk_count)
    {
        return Err(blob_error(BlobStoreError::DepotIntegrity(
            "finalized Blob import is missing committed markers",
        )));
    }
    if committed.is_empty() {
        return Ok(());
    }
    let variant = root
        .open_child_directory(&hex32(import.variant_id.as_bytes()), false)
        .map_err(|_| {
            blob_error(BlobStoreError::DepotIntegrity(
                "marked Blob variant directory is missing",
            ))
        })?;
    let active = active_from_import(import);
    for (index, state) in committed {
        let record = state.committed.ok_or_else(|| {
            blob_error(BlobStoreError::SchemaInvariant(
                "committed Blob state is absent",
            ))
        })?;
        verify_chunk_file(
            &variant,
            &chunk_file_name(*index),
            active,
            *index,
            record,
            state.committed_file_bytes,
        )?;
    }
    Ok(())
}

fn verify_import_files_read(
    read: &redb::ReadTransaction,
    root: &OwnedDirectory,
    import: &ImportRecord,
) -> Result<(), StoreError> {
    let committed = committed_chunks_for_variant_read(read, import.variant_id)?;
    if u64::try_from(committed.len()).ok() != Some(import.chunk_count) {
        return Err(blob_error(BlobStoreError::DepotIntegrity(
            "Blob finalization requires every committed chunk marker",
        )));
    }
    if committed.is_empty() {
        return Ok(());
    }
    let variant = root
        .open_child_directory(&hex32(import.variant_id.as_bytes()), false)
        .map_err(|_| {
            blob_error(BlobStoreError::DepotIntegrity(
                "marked Blob variant directory is missing",
            ))
        })?;
    let active = active_from_import(import);
    for (index, state) in committed {
        let record = state.committed.ok_or_else(|| {
            blob_error(BlobStoreError::SchemaInvariant(
                "committed Blob state is absent",
            ))
        })?;
        verify_chunk_file(
            &variant,
            &chunk_file_name(index),
            active,
            index,
            record,
            state.committed_file_bytes,
        )?;
    }
    Ok(())
}

fn reclaim_unmarked_artifacts(
    write: &redb::WriteTransaction,
    root: &OwnedDirectory,
    committed_map: &BTreeMap<BlobVariantId, Vec<(u64, ChunkState)>>,
    deletion: &super::deletion::BlobDeletionAudit,
) -> Result<(), StoreError> {
    let imports = write.open_table(BLOB_IMPORTS)?;
    let imported = imports
        .iter()?
        .map(|row| {
            let (key, value) = row?;
            let variant = parse_variant_id(key.value())?;
            Ok((variant, decode_import(value.value())?))
        })
        .collect::<Result<BTreeMap<_, _>, StoreError>>()?;
    drop(imports);
    let mut known = all_chunk_map_write(write)?;
    for manifest in deletion.manifests.values() {
        let entries = known.entry(manifest.variant_id).or_default();
        if !entries.is_empty() {
            return Err(blob_error(BlobStoreError::SchemaInvariant(
                "Blob variant has duplicate active and deletion cleanup authority",
            )));
        }
        for chunk in &manifest.chunks {
            let state = decode_chunk_state(&chunk.original_chunk)?;
            // A committed artifact remains protected only while its exact
            // deletion row is queued. Metadata-only rows keep their expected
            // record as the existing typed crash-gap cleanup authority.
            if chunk.state == super::deletion::BlobDeletionChunkState::DeleteQueued
                || state.committed.is_none()
            {
                entries.push((chunk.index, state));
            }
        }
    }
    for name in root.entry_names()? {
        if name == "." || name == ".." || name == DEPOT_OWNER_FILE {
            continue;
        }
        if name == BLOB_PACK_DIRECTORY {
            // Packs have separate redb reservation/publication authority and
            // must never be interpreted or reclaimed as legacy variants.
            continue;
        }
        let Some(raw) = decode_hex32(&name) else {
            // Only known temporary files are reclaimable at the root. Unknown
            // artifacts fail closed rather than broadening cleanup authority.
            if name.starts_with(TEMP_PREFIX) || name.starts_with(DEPOT_OWNER_TEMP_PREFIX) {
                root.remove_if_exists(&name, false)?;
                continue;
            }
            return Err(blob_error(BlobStoreError::DepotIntegrity(
                "Blob depot root contains an unexpected artifact",
            )));
        };
        let variant_id = BlobVariantId::from_bytes(raw);
        let variant = root.open_child_directory(&name, false)?;
        let committed = committed_map
            .get(&variant_id)
            .into_iter()
            .flatten()
            .map(|(index, _)| chunk_file_name(*index))
            .collect::<BTreeSet<_>>();
        let import = imported.get(&variant_id);
        let known_chunks = known.get(&variant_id).map_or(&[][..], Vec::as_slice);
        for child in variant.entry_names()? {
            if child == "." || child == ".." || committed.contains(&child) {
                continue;
            }
            if child.starts_with(TEMP_PREFIX) {
                variant.remove_if_exists(&child, false)?;
                continue;
            }
            let Some((index, state)) = known_chunks
                .iter()
                .find(|(index, _)| child == chunk_file_name(*index))
            else {
                return Err(blob_error(BlobStoreError::DepotIntegrity(
                    "Blob variant directory contains an unexpected artifact",
                )));
            };
            if state.committed.is_some() {
                return Err(blob_error(BlobStoreError::DepotIntegrity(
                    "committed Blob chunk lacks active or deletion protection",
                )));
            }
            let projection = deletion_chunk_projection(
                &encode_import(import.ok_or_else(|| {
                    blob_error(BlobStoreError::DepotIntegrity(
                        "unmarked Blob chunk has no exact import authority",
                    ))
                })?)?,
                *index,
                &encode_chunk_state(*state),
            )?;
            verify_deletion_file_if_present(
                &variant,
                import.expect("checked unmarked import authority"),
                *index,
                projection.cleanup,
                projection.authorized_file_bytes,
            )
            .map_err(|failure| failure.error)?;
            variant.remove_if_exists(&child, false)?;
        }
        variant.sync()?;
        if !imported.contains_key(&variant_id) && variant.entry_names()?.is_empty() {
            drop(variant);
            root.remove_if_exists(&name, true)?;
        }
    }
    root.sync()?;
    Ok(())
}

fn audit_unmarked_artifacts_read(
    read: &redb::ReadTransaction,
    root: &OwnedDirectory,
    committed_map: &BTreeMap<BlobVariantId, Vec<(u64, ChunkState)>>,
    deletion: &super::deletion::BlobDeletionAudit,
) -> Result<(), StoreError> {
    let imported = read
        .open_table(BLOB_IMPORTS)?
        .iter()?
        .map(|row| {
            let (key, value) = row?;
            Ok((
                parse_variant_id(key.value())?,
                decode_import(value.value())?,
            ))
        })
        .collect::<Result<BTreeMap<_, _>, StoreError>>()?;
    let mut known = all_chunk_map_read(read)?;
    for manifest in deletion.manifests.values() {
        let entries = known.entry(manifest.variant_id).or_default();
        if !entries.is_empty() {
            return Err(blob_error(BlobStoreError::SchemaInvariant(
                "Blob variant has duplicate active and deletion inspection authority",
            )));
        }
        for chunk in &manifest.chunks {
            let state = decode_chunk_state(&chunk.original_chunk)?;
            if chunk.state == super::deletion::BlobDeletionChunkState::DeleteQueued
                || state.committed.is_none()
            {
                entries.push((chunk.index, state));
            }
        }
    }
    for name in root.entry_names()? {
        if name == DEPOT_OWNER_FILE
            || name == BLOB_PACK_DIRECTORY
            || name.starts_with(TEMP_PREFIX)
            || name.starts_with(DEPOT_OWNER_TEMP_PREFIX)
        {
            continue;
        }
        let Some(raw) = decode_hex32(&name) else {
            return Err(blob_error(BlobStoreError::DepotIntegrity(
                "Blob depot root contains an unexpected artifact",
            )));
        };
        let variant_id = BlobVariantId::from_bytes(raw);
        let import = imported.get(&variant_id).ok_or_else(|| {
            blob_error(BlobStoreError::DepotIntegrity(
                "Blob depot variant has no exact import authority",
            ))
        })?;
        let directory = root.open_child_directory(&name, false)?;
        let committed = committed_map
            .get(&variant_id)
            .into_iter()
            .flatten()
            .map(|(index, _)| chunk_file_name(*index))
            .collect::<BTreeSet<_>>();
        let known_chunks = known.get(&variant_id).map_or(&[][..], Vec::as_slice);
        for child in directory.entry_names()? {
            if child.starts_with(TEMP_PREFIX) || committed.contains(&child) {
                continue;
            }
            let Some((index, state)) = known_chunks
                .iter()
                .find(|(index, _)| child == chunk_file_name(*index))
            else {
                return Err(blob_error(BlobStoreError::DepotIntegrity(
                    "Blob variant directory contains an unexpected artifact",
                )));
            };
            if state.committed.is_some() {
                return Err(blob_error(BlobStoreError::DepotIntegrity(
                    "committed Blob chunk lacks exact read-only protection",
                )));
            }
            let projection = deletion_chunk_projection(
                &encode_import(import)?,
                *index,
                &encode_chunk_state(*state),
            )?;
            verify_deletion_file_if_present(
                &directory,
                import,
                *index,
                projection.cleanup,
                projection.authorized_file_bytes,
            )
            .map_err(|failure| failure.error)?;
        }
    }
    Ok(())
}

fn all_chunk_map_write(
    write: &redb::WriteTransaction,
) -> Result<BTreeMap<BlobVariantId, Vec<(u64, ChunkState)>>, StoreError> {
    let chunks = write.open_table(BLOB_CHUNKS)?;
    let mut output = BTreeMap::<BlobVariantId, Vec<(u64, ChunkState)>>::new();
    for row in chunks.iter()? {
        let (key, value) = row?;
        let (variant, index) = parse_chunk_key(key.value())?;
        output
            .entry(variant)
            .or_default()
            .push((index, decode_chunk_state(value.value())?));
    }
    Ok(output)
}

fn all_chunk_map_read(
    read: &redb::ReadTransaction,
) -> Result<BTreeMap<BlobVariantId, Vec<(u64, ChunkState)>>, StoreError> {
    let chunks = read.open_table(BLOB_CHUNKS)?;
    let mut output = BTreeMap::<BlobVariantId, Vec<(u64, ChunkState)>>::new();
    for row in chunks.iter()? {
        let (key, value) = row?;
        let (variant, index) = parse_chunk_key(key.value())?;
        output
            .entry(variant)
            .or_default()
            .push((index, decode_chunk_state(value.value())?));
    }
    Ok(output)
}

fn committed_chunk_map_write(
    write: &redb::WriteTransaction,
) -> Result<BTreeMap<BlobVariantId, Vec<(u64, ChunkState)>>, StoreError> {
    let chunks = write.open_table(BLOB_CHUNKS)?;
    let mut output = BTreeMap::<BlobVariantId, Vec<(u64, ChunkState)>>::new();
    for row in chunks.iter()? {
        let (key, value) = row?;
        let (variant, index) = parse_chunk_key(key.value())?;
        let state = decode_chunk_state(value.value())?;
        if state.committed.is_some() {
            output.entry(variant).or_default().push((index, state));
        }
    }
    Ok(output)
}

fn committed_chunk_map_read(
    read: &redb::ReadTransaction,
) -> Result<BTreeMap<BlobVariantId, Vec<(u64, ChunkState)>>, StoreError> {
    let chunks = read.open_table(BLOB_CHUNKS)?;
    let mut output = BTreeMap::<BlobVariantId, Vec<(u64, ChunkState)>>::new();
    for row in chunks.iter()? {
        let (key, value) = row?;
        let (variant, index) = parse_chunk_key(key.value())?;
        let state = decode_chunk_state(value.value())?;
        if state.committed.is_some() {
            output.entry(variant).or_default().push((index, state));
        }
    }
    Ok(output)
}

fn committed_chunks_for_variant_read(
    read: &redb::ReadTransaction,
    variant: BlobVariantId,
) -> Result<Vec<(u64, ChunkState)>, StoreError> {
    let first = chunk_key(variant, 0);
    let last = chunk_key(variant, u64::MAX);
    let chunks = read.open_table(BLOB_CHUNKS)?;
    let mut output = Vec::new();
    for row in chunks.range::<&[u8]>((
        std::ops::Bound::<&[u8]>::Included(first.as_slice()),
        std::ops::Bound::<&[u8]>::Included(last.as_slice()),
    ))? {
        let (key, value) = row?;
        #[cfg(test)]
        TEST_COMPLETION_CHUNK_ROWS_VISITED.with(|counter| {
            counter.set(counter.get().saturating_add(1));
        });
        let (actual_variant, index) = parse_chunk_key(key.value())?;
        if actual_variant != variant {
            return Err(blob_error(BlobStoreError::SchemaInvariant(
                "Blob chunk range escaped its exact variant",
            )));
        }
        let state = decode_chunk_state(value.value())?;
        if state.committed.is_some() {
            output.push((index, state));
        }
    }
    Ok(output)
}

fn active_from_import(import: &ImportRecord) -> ActiveImport {
    ActiveImport {
        variant_id: import.variant_id,
        blob_id: import.blob_id,
        content_group: import.content_group,
        epoch: import.epoch,
        total_len: import.total_len,
        chunk_count: import.chunk_count,
        physical_lineage: import.physical_lineage,
    }
}

fn legacy_import_can_bind_write(
    write: &redb::WriteTransaction,
    import: &ImportRecord,
    plan: &VerifiedBlobTransferPlan,
) -> Result<bool, StoreError> {
    if import.finalized_manifest_digest != Some(*plan.manifest_digest()) {
        return Ok(false);
    }
    let mut exact_chunks = 0u64;
    for row in write.open_table(BLOB_CHUNKS)?.iter()? {
        let (key, value) = row?;
        if !key.value().starts_with(import.variant_id.as_bytes()) {
            continue;
        }
        let (_, index) = parse_chunk_key(key.value())?;
        let Some(expected) = usize::try_from(index)
            .ok()
            .and_then(|index| plan.chunk_records().get(index))
            .copied()
        else {
            return Ok(false);
        };
        let state = decode_chunk_state(value.value())?;
        if state.expected != Some(expected)
            || state.committed != Some(expected)
            || state.committed_file_bytes == 0
        {
            return Ok(false);
        }
        exact_chunks = exact_chunks
            .checked_add(1)
            .ok_or(StoreError::ItemCountAccountingOverflow)?;
    }
    if exact_chunks != import.chunk_count {
        return Ok(false);
    }

    let source = BlobTransferId::new(plan.source_envelope().into_bytes());
    let mut exact_publication = false;
    for row in write.open_table(BLOB_PUBLICATIONS)?.iter()? {
        let (_, value) = row?;
        let publication = decode_blob_metadata(value.value())?;
        if publication.variant_id != import.variant_id {
            continue;
        }
        if publication.transfer_id != source
            || publication.blob_id != import.blob_id
            || publication.manifest_digest != *plan.manifest_digest()
            || publication.header.key_epoch != import.epoch
            || publication.physical_lineage.is_some()
        {
            return Ok(false);
        }
        exact_publication = true;
    }
    Ok(exact_publication)
}

/// Atomically preflights and installs one exact provider-authenticated manifest
/// import plus every expected chunk record. No row is mutated until all variant,
/// lineage, record, and capacity checks have succeeded.
pub(super) fn stage_verified_plan_write(
    write: &redb::WriteTransaction,
    limits: BlobDepotLimits,
    plan: &VerifiedBlobTransferPlan,
    max_total_len: u64,
    max_chunks: u64,
) -> Result<(), StoreError> {
    let manifest = plan.manifest();
    let mut incoming = ImportRecord::from_manifest(manifest, Some(plan.physical_lineage()))?;
    if incoming.total_len > max_total_len
        || incoming.chunk_count > max_chunks
        || usize::try_from(incoming.chunk_count).ok() != Some(plan.chunk_records().len())
    {
        return Err(blob_error(BlobStoreError::NetworkBlobTooLarge {
            total_len: incoming.total_len,
            chunk_count: incoming.chunk_count,
            max_total_len,
            max_chunks,
        }));
    }
    if incoming.chunk_count == 0 {
        // The canonical empty Blob has no DATA carrier whose commit could
        // otherwise finalize the import. The authenticated manifest plan is
        // itself the complete physical proof for the exact `(0, 0)` shape.
        incoming.finalized_manifest_digest = Some(*plan.manifest_digest());
    }

    let existing_import = load_import_write(write, incoming.variant_id)?;
    let (durable_import, insert_import) = match existing_import {
        Some(existing) if !existing.matches_manifest(manifest) => {
            return Err(blob_error(BlobStoreError::DepotIntegrity(
                "Blob variant identity is bound to another manifest",
            )));
        }
        Some(existing)
            if existing.physical_lineage.is_some()
                && existing.physical_lineage != incoming.physical_lineage =>
        {
            return Err(blob_error(BlobStoreError::PhysicalLineageConflict));
        }
        Some(mut existing) if existing.physical_lineage.is_none() => {
            if !legacy_import_can_bind_write(write, &existing, plan)? {
                return Err(blob_error(BlobStoreError::PhysicalLineageMigrationRequired));
            }
            existing.physical_lineage = incoming.physical_lineage;
            (existing, false)
        }
        Some(existing) => (existing, false),
        None => (incoming, true),
    };
    if durable_import
        .finalized_manifest_digest
        .is_some_and(|digest| digest != *plan.manifest_digest())
    {
        return Err(blob_error(BlobStoreError::DepotIntegrity(
            "Blob import was finalized for another manifest digest",
        )));
    }

    let mut prepared_chunks = Vec::with_capacity(plan.chunk_records().len());
    let mut missing_chunks = 0u64;
    let mut incoming_reserved = 0u64;
    for (index, expected) in plan.chunk_records().iter().copied().enumerate() {
        let index = u64::try_from(index).map_err(|_| StoreError::ItemCountAccountingOverflow)?;
        validate_chunk_record_lengths(
            durable_import.total_len,
            durable_import.chunk_count,
            index,
            expected,
        )?;
        let key = chunk_key(durable_import.variant_id, index);
        let existing = write
            .open_table(BLOB_CHUNKS)?
            .get(key.as_slice())?
            .map(|value| decode_chunk_state(value.value()))
            .transpose()?;
        let mut state = existing.unwrap_or_default();
        if state.expected.is_some_and(|record| record != expected)
            || state.committed.is_some_and(|record| record != expected)
            || state
                .plaintext_digest
                .is_some_and(|digest| digest != *expected.plaintext_sha256())
        {
            return Err(blob_error(BlobStoreError::DepotIntegrity(
                "Blob chunk staging conflicts with authenticated manifest",
            )));
        }
        if existing.is_none() {
            missing_chunks = missing_chunks
                .checked_add(1)
                .ok_or(StoreError::ItemCountAccountingOverflow)?;
        }
        state.plaintext_digest = Some(*expected.plaintext_sha256());
        if state.expected.is_none() {
            incoming_reserved = incoming_reserved
                .checked_add(chunk_file_len(expected)?)
                .ok_or(StoreError::PayloadByteAccountingOverflow)?;
        }
        state.expected = Some(expected);
        prepared_chunks.push((key, encode_chunk_state(state)));
    }

    let current_usage = depot_admission_usage_write(write)?;
    if insert_import && current_usage.variants >= limits.max_variants {
        return Err(blob_error(BlobStoreError::DepotVariantLimitExceeded {
            current: current_usage.variants,
            limit: limits.max_variants,
        }));
    }
    if current_usage
        .chunks
        .checked_add(missing_chunks)
        .ok_or(StoreError::ItemCountAccountingOverflow)?
        > limits.max_chunks
    {
        return Err(blob_error(BlobStoreError::DepotChunkLimitExceeded {
            current: current_usage.chunks,
            limit: limits.max_chunks,
        }));
    }
    let physical_reserved = write
        .open_table(BLOB_DEPOT_METADATA)?
        .get(DEPOT_RESERVED_FILE_BYTES)?
        .map(|value| value.value())
        .ok_or_else(|| {
            blob_error(BlobStoreError::SchemaInvariant(
                "Blob depot reserved-byte counter is missing",
            ))
        })?;
    if current_usage
        .reserved_bytes
        .checked_add(incoming_reserved)
        .ok_or(StoreError::PayloadByteAccountingOverflow)?
        > limits.max_bytes
    {
        return Err(blob_error(BlobStoreError::DepotByteLimitExceeded {
            current: current_usage.reserved_bytes,
            incoming: incoming_reserved,
            limit: limits.max_bytes,
        }));
    }

    let encoded_import = encode_import(&durable_import)?;
    write.open_table(BLOB_IMPORTS)?.insert(
        durable_import.variant_id.as_bytes().as_slice(),
        encoded_import.as_slice(),
    )?;
    if insert_import {
        let mut depot = write.open_table(BLOB_DEPOT_METADATA)?;
        let variants = depot
            .get(DEPOT_VARIANT_COUNT)?
            .map_or(0, |value| value.value());
        depot.insert(
            DEPOT_VARIANT_COUNT,
            variants
                .checked_add(1)
                .ok_or(StoreError::ItemCountAccountingOverflow)?,
        )?;
    }
    if incoming_reserved != 0 {
        write.open_table(BLOB_DEPOT_METADATA)?.insert(
            DEPOT_RESERVED_FILE_BYTES,
            physical_reserved
                .checked_add(incoming_reserved)
                .ok_or(StoreError::PayloadByteAccountingOverflow)?,
        )?;
    }
    let mut chunks = write.open_table(BLOB_CHUNKS)?;
    for (key, encoded) in prepared_chunks {
        chunks.insert(key.as_slice(), encoded.as_slice())?;
    }
    Ok(())
}

fn load_import_read(
    read: &redb::ReadTransaction,
    variant: BlobVariantId,
) -> Result<Option<ImportRecord>, StoreError> {
    read.open_table(BLOB_IMPORTS)?
        .get(variant.as_bytes().as_slice())?
        .map(|value| decode_import(value.value()))
        .transpose()
}

fn load_import_write(
    write: &redb::WriteTransaction,
    variant: BlobVariantId,
) -> Result<Option<ImportRecord>, StoreError> {
    write
        .open_table(BLOB_IMPORTS)?
        .get(variant.as_bytes().as_slice())?
        .map(|value| decode_import(value.value()))
        .transpose()
}

fn load_chunk_read(
    read: &redb::ReadTransaction,
    variant: BlobVariantId,
    index: u64,
) -> Result<Option<ChunkState>, StoreError> {
    let key = chunk_key(variant, index);
    read.open_table(BLOB_CHUNKS)?
        .get(key.as_slice())?
        .map(|value| decode_chunk_state(value.value()))
        .transpose()
}

pub(super) fn pending_chunk_is_committed_read(
    read: &redb::ReadTransaction,
    variant: BlobVariantId,
    index: u64,
) -> Result<bool, StoreError> {
    let import = load_import_read(read, variant)?
        .ok_or_else(|| blob_error(BlobStoreError::PendingSourceConflict))?;
    let state = load_chunk_read(read, variant, index)?
        .ok_or_else(|| blob_error(BlobStoreError::PendingSourceConflict))?;
    validate_chunk_state_lengths(&import, index, state)?;
    let expected = state
        .expected
        .ok_or_else(|| blob_error(BlobStoreError::PendingSourceConflict))?;
    if state
        .committed
        .is_some_and(|committed| committed != expected)
        || (state.committed == Some(expected)
            && state.committed_file_bytes != chunk_file_len(expected)?)
        || (state.committed.is_none() && state.committed_file_bytes != 0)
    {
        return Err(blob_error(BlobStoreError::PendingSourceConflict));
    }
    Ok(state.committed == Some(expected))
}

#[cfg(test)]
pub(super) fn remove_completion_chunk_state_for_test(
    write: &redb::WriteTransaction,
    variant: BlobVariantId,
    index: u64,
) -> Result<(), StoreError> {
    let key = chunk_key(variant, index);
    if write
        .open_table(BLOB_CHUNKS)?
        .remove(key.as_slice())?
        .is_none()
    {
        return Err(blob_error(BlobStoreError::SchemaInvariant(
            "test Blob completion chunk state is missing",
        )));
    }
    Ok(())
}

#[cfg(test)]
pub(super) fn set_expected_chunk_for_test(
    write: &redb::WriteTransaction,
    variant: BlobVariantId,
    index: u64,
    record: BlobChunkRecord,
) -> Result<(), StoreError> {
    let import = load_import_write(write, variant)?.ok_or_else(|| {
        blob_error(BlobStoreError::SchemaInvariant(
            "test Blob import is missing",
        ))
    })?;
    validate_chunk_record_lengths(import.total_len, import.chunk_count, index, record)?;
    let key = chunk_key(variant, index);
    let mut state = write
        .open_table(BLOB_CHUNKS)?
        .get(key.as_slice())?
        .map(|value| decode_chunk_state(value.value()))
        .transpose()?
        .ok_or_else(|| {
            blob_error(BlobStoreError::SchemaInvariant(
                "test Blob chunk state is missing",
            ))
        })?;
    if state.plaintext_digest != Some(*record.plaintext_sha256())
        || state.expected.is_some()
        || state.committed.is_some()
    {
        return Err(blob_error(BlobStoreError::SchemaInvariant(
            "test Blob chunk is not digest-only",
        )));
    }
    state.expected = Some(record);
    let charge = chunk_file_len(record)?;
    let mut metadata = write.open_table(BLOB_DEPOT_METADATA)?;
    let reserved = metadata
        .get(DEPOT_RESERVED_FILE_BYTES)?
        .ok_or_else(|| {
            blob_error(BlobStoreError::SchemaInvariant(
                "Blob depot reserved-byte counter is missing",
            ))
        })?
        .value();
    metadata.insert(
        DEPOT_RESERVED_FILE_BYTES,
        reserved
            .checked_add(charge)
            .ok_or(StoreError::PayloadByteAccountingOverflow)?,
    )?;
    drop(metadata);
    write
        .open_table(BLOB_CHUNKS)?
        .insert(key.as_slice(), encode_chunk_state(state).as_slice())?;
    Ok(())
}

#[cfg(test)]
pub(super) fn downgrade_expected_chunk_to_digest_for_test(
    write: &redb::WriteTransaction,
    variant: BlobVariantId,
    index: u64,
) -> Result<(), StoreError> {
    let key = chunk_key(variant, index);
    let mut state = write
        .open_table(BLOB_CHUNKS)?
        .get(key.as_slice())?
        .map(|value| decode_chunk_state(value.value()))
        .transpose()?
        .ok_or_else(|| {
            blob_error(BlobStoreError::SchemaInvariant(
                "test Blob chunk is missing",
            ))
        })?;
    if state.committed.is_some() {
        return Err(blob_error(BlobStoreError::SchemaInvariant(
            "test Blob chunk is already committed",
        )));
    }
    let expected = state.expected.take().ok_or_else(|| {
        blob_error(BlobStoreError::SchemaInvariant(
            "test Blob expected chunk record is missing",
        ))
    })?;
    let charge = chunk_file_len(expected)?;
    let mut metadata = write.open_table(BLOB_DEPOT_METADATA)?;
    let reserved = metadata
        .get(DEPOT_RESERVED_FILE_BYTES)?
        .ok_or_else(|| {
            blob_error(BlobStoreError::SchemaInvariant(
                "reserved bytes are missing",
            ))
        })?
        .value()
        .checked_sub(charge)
        .ok_or(StoreError::PayloadByteAccountingOverflow)?;
    metadata.insert(DEPOT_RESERVED_FILE_BYTES, reserved)?;
    drop(metadata);
    let encoded = encode_chunk_state(state);
    write
        .open_table(BLOB_CHUNKS)?
        .insert(key.as_slice(), encoded.as_slice())?;
    Ok(())
}

#[cfg(test)]
pub(super) fn corrupt_digest_only_plaintext_digest_for_test(
    write: &redb::WriteTransaction,
    variant: BlobVariantId,
    index: u64,
) -> Result<(), StoreError> {
    let key = chunk_key(variant, index);
    let mut state = write
        .open_table(BLOB_CHUNKS)?
        .get(key.as_slice())?
        .map(|value| decode_chunk_state(value.value()))
        .transpose()?
        .ok_or_else(|| {
            blob_error(BlobStoreError::SchemaInvariant(
                "test Blob chunk is missing",
            ))
        })?;
    if state.expected.is_some() || state.committed.is_some() {
        return Err(blob_error(BlobStoreError::SchemaInvariant(
            "test Blob chunk is not digest-only",
        )));
    }
    let digest = state.plaintext_digest.as_mut().ok_or_else(|| {
        blob_error(BlobStoreError::SchemaInvariant(
            "test Blob plaintext digest is missing",
        ))
    })?;
    digest[0] ^= 0x80;
    write
        .open_table(BLOB_CHUNKS)?
        .insert(key.as_slice(), encode_chunk_state(state).as_slice())?;
    Ok(())
}

#[cfg(test)]
pub(super) fn corrupt_import_profile_for_test(
    write: &redb::WriteTransaction,
    variant: BlobVariantId,
    media_len: Option<usize>,
    schema_len: Option<usize>,
    chunk_count: Option<u64>,
) -> Result<(), StoreError> {
    let mut import = load_import_write(write, variant)?.ok_or_else(|| {
        blob_error(BlobStoreError::SchemaInvariant(
            "test Blob import is missing",
        ))
    })?;
    if let Some(length) = media_len {
        import.media_type = Some("x".repeat(length));
    }
    if let Some(length) = schema_len {
        import.schema_id = vec![0x5a; length];
    }
    if let Some(count) = chunk_count {
        import.chunk_count = count;
    }
    let encoded = encode_import(&import)?;
    write
        .open_table(BLOB_IMPORTS)?
        .insert(variant.as_bytes().as_slice(), encoded.as_slice())?;
    Ok(())
}

#[cfg(test)]
pub(super) fn corrupt_completion_import_for_test(
    write: &redb::WriteTransaction,
    variant: BlobVariantId,
    field: &str,
) -> Result<(), StoreError> {
    let mut import = load_import_write(write, variant)?.ok_or_else(|| {
        blob_error(BlobStoreError::SchemaInvariant(
            "test Blob import is missing",
        ))
    })?;
    match field {
        "whole_plaintext_sha256" => import.whole_plaintext_sha256[0] ^= 0x80,
        "media_type" => import.media_type = Some("forged/type".into()),
        "schema_id" => import.schema_id.push(0x5a),
        "total_len" => {
            import.total_len = import
                .total_len
                .checked_add(1)
                .ok_or(StoreError::PayloadByteAccountingOverflow)?;
        }
        "chunk_size" => import.chunk_size ^= 1,
        "physical_lineage" => {
            import.physical_lineage.as_mut().ok_or_else(|| {
                blob_error(BlobStoreError::SchemaInvariant(
                    "test Blob completion import has no physical lineage",
                ))
            })?[0] ^= 0x80
        }
        "finalized_manifest_digest" => {
            import.finalized_manifest_digest.as_mut().ok_or_else(|| {
                blob_error(BlobStoreError::SchemaInvariant(
                    "test Blob completion import is not finalized",
                ))
            })?[0] ^= 0x80
        }
        "chunk_count" => {
            import.chunk_count = import
                .chunk_count
                .checked_add(1)
                .ok_or(StoreError::PayloadByteAccountingOverflow)?;
        }
        _ => {
            return Err(blob_error(BlobStoreError::SchemaInvariant(
                "unknown test Blob completion corruption field",
            )));
        }
    }
    let encoded = encode_import(&import)?;
    write
        .open_table(BLOB_IMPORTS)?
        .insert(variant.as_bytes().as_slice(), encoded.as_slice())?;
    Ok(())
}

#[cfg(test)]
pub(super) fn remove_import_physical_lineage_for_test(
    write: &redb::WriteTransaction,
    variant: BlobVariantId,
) -> Result<(), StoreError> {
    let mut import = load_import_write(write, variant)?.ok_or_else(|| {
        blob_error(BlobStoreError::SchemaInvariant(
            "test Blob import is missing",
        ))
    })?;
    import.physical_lineage = None;
    let encoded = encode_import(&import)?;
    write
        .open_table(BLOB_IMPORTS)?
        .insert(variant.as_bytes().as_slice(), encoded.as_slice())?;
    Ok(())
}

#[cfg(test)]
pub(super) fn corrupt_expected_chunk_lengths_for_test(
    write: &redb::WriteTransaction,
    variant: BlobVariantId,
    index: u64,
    plaintext_len: u32,
    ciphertext_len: u32,
) -> Result<(), StoreError> {
    let key = chunk_key(variant, index);
    let mut state = write
        .open_table(BLOB_CHUNKS)?
        .get(key.as_slice())?
        .map(|value| decode_chunk_state(value.value()))
        .transpose()?
        .ok_or_else(|| {
            blob_error(BlobStoreError::SchemaInvariant(
                "test Blob chunk state is missing",
            ))
        })?;
    if state.committed.is_some() {
        return Err(blob_error(BlobStoreError::SchemaInvariant(
            "test Blob chunk state is already committed",
        )));
    }
    let expected = state.expected.ok_or_else(|| {
        blob_error(BlobStoreError::SchemaInvariant(
            "test Blob expected chunk record is missing",
        ))
    })?;
    state.expected = Some(
        BlobChunkRecord::from_parts(
            *expected.plaintext_sha256(),
            *expected.ciphertext_sha256(),
            plaintext_len,
            ciphertext_len,
        )
        .map_err(|_| {
            blob_error(BlobStoreError::SchemaInvariant(
                "test Blob chunk lengths are not context-free valid",
            ))
        })?,
    );
    let encoded = encode_chunk_state(state);
    write
        .open_table(BLOB_CHUNKS)?
        .insert(key.as_slice(), encoded.as_slice())?;
    Ok(())
}

#[cfg(test)]
pub(super) fn corrupt_expected_chunk_ciphertext_digest_for_test(
    write: &redb::WriteTransaction,
    variant: BlobVariantId,
    index: u64,
) -> Result<(), StoreError> {
    let key = chunk_key(variant, index);
    let mut state = write
        .open_table(BLOB_CHUNKS)?
        .get(key.as_slice())?
        .map(|value| decode_chunk_state(value.value()))
        .transpose()?
        .ok_or_else(|| {
            blob_error(BlobStoreError::SchemaInvariant(
                "test Blob chunk state is missing",
            ))
        })?;
    if state.committed.is_some() {
        return Err(blob_error(BlobStoreError::SchemaInvariant(
            "test Blob chunk state is already committed",
        )));
    }
    let expected = state.expected.ok_or_else(|| {
        blob_error(BlobStoreError::SchemaInvariant(
            "test Blob expected chunk record is missing",
        ))
    })?;
    let mut ciphertext_digest = *expected.ciphertext_sha256();
    ciphertext_digest[0] ^= 0x80;
    state.expected = Some(
        BlobChunkRecord::from_parts(
            *expected.plaintext_sha256(),
            ciphertext_digest,
            expected.plaintext_len(),
            expected.ciphertext_len(),
        )
        .map_err(|_| {
            blob_error(BlobStoreError::SchemaInvariant(
                "test Blob chunk record is not context-free valid",
            ))
        })?,
    );
    let encoded = encode_chunk_state(state);
    write
        .open_table(BLOB_CHUNKS)?
        .insert(key.as_slice(), encoded.as_slice())?;
    Ok(())
}

fn encode_import(import: &ImportRecord) -> Result<Vec<u8>, StoreError> {
    let media_len = import
        .media_type
        .as_ref()
        .map(|value| u16::try_from(value.len()))
        .transpose()
        .map_err(|_| {
            blob_error(BlobStoreError::InvalidPublication(
                "Blob media type exceeds durable encoding bound",
            ))
        })?;
    let schema_len = u16::try_from(import.schema_id.len()).map_err(|_| {
        blob_error(BlobStoreError::InvalidPublication(
            "Blob schema identity exceeds durable encoding bound",
        ))
    })?;
    let mut output = Vec::new();
    output.push(IMPORT_VERSION);
    output.extend_from_slice(import.variant_id.as_bytes());
    output.extend_from_slice(import.blob_id.as_bytes());
    output.extend_from_slice(&import.content_group);
    output.extend_from_slice(&import.epoch.to_be_bytes());
    output.extend_from_slice(&import.total_len.to_be_bytes());
    output.extend_from_slice(&import.chunk_size.to_be_bytes());
    output.extend_from_slice(&import.chunk_count.to_be_bytes());
    output.extend_from_slice(&import.whole_plaintext_sha256);
    output.push(u8::from(import.physical_lineage.is_some()));
    if let Some(lineage) = import.physical_lineage {
        output.extend_from_slice(&lineage);
    }
    output.push(u8::from(import.finalized_manifest_digest.is_some()));
    if let Some(digest) = import.finalized_manifest_digest {
        output.extend_from_slice(&digest);
    }
    match (&import.media_type, media_len) {
        (Some(media), Some(length)) => {
            output.extend_from_slice(&length.to_be_bytes());
            output.extend_from_slice(media.as_bytes());
        }
        (None, None) => output.extend_from_slice(&u16::MAX.to_be_bytes()),
        _ => unreachable!("media length follows media presence"),
    }
    output.extend_from_slice(&schema_len.to_be_bytes());
    output.extend_from_slice(&import.schema_id);
    Ok(output)
}

fn decode_import(bytes: &[u8]) -> Result<ImportRecord, StoreError> {
    let mut cursor = MetadataCursor::new(bytes);
    let version = cursor.u8()?;
    if version != IMPORT_VERSION_V1 && version != IMPORT_VERSION {
        return Err(blob_error(BlobStoreError::SchemaInvariant(
            "unknown Blob import encoding version",
        )));
    }
    let variant_id = BlobVariantId::from_bytes(cursor.array()?);
    let blob_id = BlobId::from_bytes(cursor.array()?);
    let content_group = cursor.array()?;
    let epoch = cursor.u64()?;
    let total_len = cursor.u64()?;
    let chunk_size = cursor.u32()?;
    let chunk_count = cursor.u64()?;
    let whole_plaintext_sha256 = cursor.array()?;
    let physical_lineage = if version == IMPORT_VERSION_V1 {
        None
    } else {
        match cursor.u8()? {
            0 => None,
            1 => Some(cursor.array()?),
            _ => {
                return Err(blob_error(BlobStoreError::SchemaInvariant(
                    "invalid Blob import physical-lineage flag",
                )));
            }
        }
    };
    let finalized_manifest_digest = match cursor.u8()? {
        0 => None,
        1 => Some(cursor.array()?),
        _ => {
            return Err(blob_error(BlobStoreError::SchemaInvariant(
                "invalid Blob import finalization flag",
            )));
        }
    };
    let media_len = cursor.u16()?;
    let media_type = if media_len == u16::MAX {
        None
    } else {
        Some(
            std::str::from_utf8(cursor.take(usize::from(media_len))?)
                .map_err(|_| {
                    blob_error(BlobStoreError::SchemaInvariant(
                        "Blob import media type is not UTF-8",
                    ))
                })?
                .to_owned(),
        )
    };
    let schema_len = usize::from(cursor.u16()?);
    let schema_id = cursor.take(schema_len)?.to_vec();
    cursor.finish()?;
    let canonical_chunk_count = Some(total_len.div_ceil(u64::from(SELECTED_BLOB_CHUNK_SIZE)));
    let metadata_valid = CoreBlobMetadata::new(media_type.clone(), schema_id.clone()).is_ok();
    if chunk_size != SELECTED_BLOB_CHUNK_SIZE
        || Some(chunk_count) != canonical_chunk_count
        || chunk_count > MAX_SELECTED_BLOB_CHUNKS
        || epoch == 0
        || physical_lineage.is_some_and(|lineage| lineage == [0; 32])
        || !metadata_valid
    {
        return Err(blob_error(BlobStoreError::SchemaInvariant(
            "decoded Blob import violates the selected manifest profile",
        )));
    }
    Ok(ImportRecord {
        variant_id,
        blob_id,
        content_group,
        epoch,
        total_len,
        chunk_size,
        chunk_count,
        whole_plaintext_sha256,
        media_type,
        schema_id,
        physical_lineage,
        finalized_manifest_digest,
    })
}

fn expected_import_plaintext_len(
    total_len: u64,
    chunk_count: u64,
    index: u64,
) -> Result<u32, StoreError> {
    if index >= chunk_count {
        return Err(blob_error(BlobStoreError::SchemaInvariant(
            "Blob chunk metadata index is outside its manifest",
        )));
    }
    let offset = index
        .checked_mul(u64::from(SELECTED_BLOB_CHUNK_SIZE))
        .ok_or(StoreError::PayloadByteAccountingOverflow)?;
    let remaining = total_len.checked_sub(offset).ok_or_else(|| {
        blob_error(BlobStoreError::SchemaInvariant(
            "Blob chunk metadata offset exceeds its import length",
        ))
    })?;
    u32::try_from(remaining.min(u64::from(SELECTED_BLOB_CHUNK_SIZE)))
        .map_err(|_| StoreError::PayloadByteAccountingOverflow)
}

fn validate_chunk_record_lengths(
    total_len: u64,
    chunk_count: u64,
    index: u64,
    record: BlobChunkRecord,
) -> Result<(), StoreError> {
    let plaintext_len = expected_import_plaintext_len(total_len, chunk_count, index)?;
    let ciphertext_len = plaintext_len
        .checked_add(BLOB_CHUNK_TAG_BYTES)
        .ok_or(StoreError::PayloadByteAccountingOverflow)?;
    if record.plaintext_len() != plaintext_len || record.ciphertext_len() != ciphertext_len {
        return Err(blob_error(BlobStoreError::SchemaInvariant(
            "Blob chunk record lengths differ from its exact import position",
        )));
    }
    Ok(())
}

fn validate_chunk_state_lengths(
    import: &ImportRecord,
    index: u64,
    state: ChunkState,
) -> Result<(), StoreError> {
    for record in [state.expected, state.committed].into_iter().flatten() {
        validate_chunk_record_lengths(import.total_len, import.chunk_count, index, record)?;
    }
    Ok(())
}

fn encode_chunk_state(state: ChunkState) -> Vec<u8> {
    let mut flags = 0u8;
    flags |= u8::from(state.plaintext_digest.is_some());
    flags |= u8::from(state.expected.is_some()) << 1;
    flags |= u8::from(state.committed.is_some()) << 2;
    let mut output = Vec::new();
    output.push(CHUNK_STATE_VERSION);
    output.push(flags);
    if let Some(digest) = state.plaintext_digest {
        output.extend_from_slice(&digest);
    }
    if let Some(record) = state.expected {
        encode_chunk_record(&mut output, record);
    }
    if let Some(record) = state.committed {
        encode_chunk_record(&mut output, record);
        output.extend_from_slice(&state.committed_file_bytes.to_be_bytes());
    }
    output
}

fn decode_chunk_state(bytes: &[u8]) -> Result<ChunkState, StoreError> {
    let mut cursor = MetadataCursor::new(bytes);
    if cursor.u8()? != CHUNK_STATE_VERSION {
        return Err(blob_error(BlobStoreError::SchemaInvariant(
            "unknown Blob chunk-state encoding version",
        )));
    }
    let flags = cursor.u8()?;
    if flags & !7 != 0 || flags & 4 != 0 && flags & 2 == 0 {
        return Err(blob_error(BlobStoreError::SchemaInvariant(
            "Blob chunk state contains invalid flags",
        )));
    }
    let plaintext_digest = (flags & 1 != 0).then(|| cursor.array()).transpose()?;
    let expected = (flags & 2 != 0)
        .then(|| decode_chunk_record(&mut cursor))
        .transpose()?;
    let (committed, committed_file_bytes) = if flags & 4 != 0 {
        (Some(decode_chunk_record(&mut cursor)?), cursor.u64()?)
    } else {
        (None, 0)
    };
    cursor.finish()?;
    if expected.is_some_and(|record| plaintext_digest != Some(*record.plaintext_sha256()))
        || committed.is_some_and(|record| expected != Some(record))
    {
        return Err(blob_error(BlobStoreError::SchemaInvariant(
            "Blob chunk state has conflicting integrity records",
        )));
    }
    Ok(ChunkState {
        plaintext_digest,
        expected,
        committed,
        committed_file_bytes,
    })
}

fn encode_chunk_record(output: &mut Vec<u8>, record: BlobChunkRecord) {
    output.extend_from_slice(record.plaintext_sha256());
    output.extend_from_slice(record.ciphertext_sha256());
    output.extend_from_slice(&record.plaintext_len().to_be_bytes());
    output.extend_from_slice(&record.ciphertext_len().to_be_bytes());
}

fn decode_chunk_record(cursor: &mut MetadataCursor<'_>) -> Result<BlobChunkRecord, StoreError> {
    BlobChunkRecord::from_parts(
        cursor.array()?,
        cursor.array()?,
        cursor.u32()?,
        cursor.u32()?,
    )
    .map_err(|_| {
        blob_error(BlobStoreError::SchemaInvariant(
            "Blob chunk record is invalid",
        ))
    })
}

fn chunk_key(variant: BlobVariantId, index: u64) -> [u8; 40] {
    let mut key = [0u8; 40];
    key[..32].copy_from_slice(variant.as_bytes());
    key[32..].copy_from_slice(&index.to_be_bytes());
    key
}

#[cfg(test)]
pub(super) fn test_chunk_key(variant: BlobVariantId, index: u64) -> [u8; 40] {
    chunk_key(variant, index)
}

fn parse_chunk_key(bytes: &[u8]) -> Result<(BlobVariantId, u64), StoreError> {
    if bytes.len() != 40 {
        return Err(blob_error(BlobStoreError::SchemaInvariant(
            "Blob chunk key has invalid length",
        )));
    }
    let variant = BlobVariantId::from_bytes(bytes[..32].try_into().map_err(|_| {
        blob_error(BlobStoreError::SchemaInvariant(
            "Blob chunk variant key is invalid",
        ))
    })?);
    let index = u64::from_be_bytes(bytes[32..].try_into().map_err(|_| {
        blob_error(BlobStoreError::SchemaInvariant(
            "Blob chunk index key is invalid",
        ))
    })?);
    Ok((variant, index))
}

fn parse_variant_id(bytes: &[u8]) -> Result<BlobVariantId, StoreError> {
    Ok(BlobVariantId::from_bytes(bytes.try_into().map_err(
        |_| {
            blob_error(BlobStoreError::SchemaInvariant(
                "Blob variant identifier has invalid length",
            ))
        },
    )?))
}

fn chunk_file_name(index: u64) -> String {
    format!("{index:020}{CHUNK_SUFFIX}")
}

fn chunk_file_len(record: BlobChunkRecord) -> Result<u64, StoreError> {
    CHUNK_FILE_HEADER_BYTES
        .checked_add(u64::from(record.ciphertext_len()))
        .ok_or(StoreError::PayloadByteAccountingOverflow)
}

fn encode_chunk_file(
    active: ActiveImport,
    index: u64,
    record: BlobChunkRecord,
    ciphertext: &[u8],
) -> Result<Vec<u8>, StoreError> {
    let length = chunk_file_len(record)?;
    let mut output = Vec::with_capacity(
        usize::try_from(length).map_err(|_| StoreError::PayloadByteAccountingOverflow)?,
    );
    output.extend_from_slice(CHUNK_FILE_MAGIC);
    output.push(CHUNK_FILE_VERSION);
    output.extend_from_slice(active.variant_id.as_bytes());
    output.extend_from_slice(active.blob_id.as_bytes());
    output.extend_from_slice(&index.to_be_bytes());
    output.extend_from_slice(record.plaintext_sha256());
    output.extend_from_slice(record.ciphertext_sha256());
    output.extend_from_slice(&record.plaintext_len().to_be_bytes());
    output.extend_from_slice(&record.ciphertext_len().to_be_bytes());
    output.extend_from_slice(ciphertext);
    if u64::try_from(output.len()).ok() != Some(length) {
        return Err(StoreError::PayloadByteAccountingOverflow);
    }
    Ok(output)
}

fn verify_chunk_file(
    directory: &OwnedDirectory,
    name: &str,
    active: ActiveImport,
    index: u64,
    record: BlobChunkRecord,
    expected_len: u64,
) -> Result<(), StoreError> {
    let mut ciphertext = Vec::with_capacity(
        usize::try_from(record.ciphertext_len())
            .map_err(|_| StoreError::PayloadByteAccountingOverflow)?,
    );
    read_and_verify_chunk_file_into(
        directory,
        name,
        active,
        index,
        record,
        expected_len,
        &mut ciphertext,
    )
}

fn read_and_verify_chunk_file_into(
    directory: &OwnedDirectory,
    name: &str,
    active: ActiveImport,
    index: u64,
    record: BlobChunkRecord,
    expected_len: u64,
    ciphertext: &mut Vec<u8>,
) -> Result<(), StoreError> {
    if expected_len != chunk_file_len(record)? || expected_len > MAX_CHUNK_FILE_BYTES {
        return Err(blob_error(BlobStoreError::DepotIntegrity(
            "marked Blob chunk length is invalid",
        )));
    }
    let mut header = [0u8; CHUNK_FILE_HEADER_LEN];
    directory.read_file_into(
        name,
        expected_len,
        record.ciphertext_len(),
        &mut header,
        ciphertext,
    )?;
    let mut cursor = MetadataCursor::new(&header);
    if cursor.take(8)? != CHUNK_FILE_MAGIC
        || cursor.u8()? != CHUNK_FILE_VERSION
        || cursor.array::<32>()? != *active.variant_id.as_bytes()
        || cursor.array::<32>()? != *active.blob_id.as_bytes()
        || cursor.u64()? != index
        || cursor.array::<32>()? != *record.plaintext_sha256()
        || cursor.array::<32>()? != *record.ciphertext_sha256()
        || cursor.u32()? != record.plaintext_len()
        || cursor.u32()? != record.ciphertext_len()
    {
        return Err(blob_error(BlobStoreError::DepotIntegrity(
            "marked Blob chunk header differs from its redb marker",
        )));
    }
    cursor.finish()?;
    if <[u8; 32]>::from(Sha256::digest(ciphertext.as_slice())) != *record.ciphertext_sha256() {
        return Err(blob_error(BlobStoreError::DepotIntegrity(
            "marked Blob chunk ciphertext hash mismatches",
        )));
    }
    Ok(())
}

fn audit_depot_counter(
    table: &mut redb::Table<'_, &str, u64>,
    field: &'static str,
    reconstructed: u64,
) -> Result<(), StoreError> {
    let durable = table
        .get(field)?
        .map(|value| value.value())
        .ok_or_else(|| {
            blob_error(BlobStoreError::SchemaInvariant(
                "Blob depot accounting field is missing",
            ))
        })?;
    if durable != reconstructed {
        return Err(StoreError::AccountingMismatch {
            field,
            durable,
            reconstructed,
        });
    }
    Ok(())
}

fn hex32(bytes: &[u8; 32]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(64);
    for byte in bytes {
        output.push(char::from(HEX[usize::from(byte >> 4)]));
        output.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    output
}

fn decode_hex32(value: &str) -> Option<[u8; 32]> {
    if value.len() != 64 {
        return None;
    }
    let mut output = [0u8; 32];
    for (index, pair) in value.as_bytes().chunks_exact(2).enumerate() {
        let high = hex_nibble(pair[0])?;
        let low = hex_nibble(pair[1])?;
        output[index] = (high << 4) | low;
    }
    Some(output)
}

fn hex_nibble(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        _ => None,
    }
}

pub(super) struct OwnedDirectory {
    path: PathBuf,
    created_by_open: bool,
    #[cfg(unix)]
    file: File,
}

#[derive(Clone, Copy)]
struct OwnerMarkerRead {
    bytes: [u8; DEPOT_OWNER_FILE_LEN],
    #[cfg(unix)]
    links: u64,
}

fn depot_owner_marker(
    store_path: &Path,
    backing_identity: StoreBackingIdentity,
    owner_token: [u8; 32],
) -> Result<[u8; DEPOT_OWNER_FILE_LEN], StoreError> {
    if owner_token == [0; 32] {
        return Err(blob_error(BlobStoreError::SchemaInvariant(
            "Blob depot owner token is invalid",
        )));
    }
    let binding = depot_owner_binding(store_path, backing_identity, owner_token)?;
    let mut marker = [0u8; DEPOT_OWNER_FILE_LEN];
    marker[..8].copy_from_slice(DEPOT_OWNER_MAGIC);
    marker[8..40].copy_from_slice(&owner_token);
    marker[40..].copy_from_slice(&binding);
    Ok(marker)
}

fn depot_owner_binding(
    store_path: &Path,
    backing_identity: StoreBackingIdentity,
    owner_token: [u8; 32],
) -> Result<[u8; 32], StoreError> {
    let canonical =
        std::fs::canonicalize(store_path).map_err(|error| blob_error(BlobStoreError::Io(error)))?;
    validate_canonical_store_identity(&canonical, backing_identity)?;
    let mut digest = Sha256::new();
    digest.update(DEPOT_OWNER_DOMAIN);
    digest.update(owner_token);
    update_owner_path_digest(&mut digest, &canonical)?;
    match backing_identity.unix_device_inode() {
        Some((device, inode)) => {
            digest.update([1]);
            digest.update(device.to_be_bytes());
            digest.update(inode.to_be_bytes());
        }
        None => {
            // The database-specific random token remains the portable owner
            // authority. Platforms without exact descriptor identity use a
            // deliberately lower-assurance canonical-path binding here.
            digest.update([0]);
            digest.update(0u64.to_be_bytes());
            digest.update(0u64.to_be_bytes());
        }
    }
    Ok(digest.finalize().into())
}

#[cfg(unix)]
fn validate_canonical_store_identity(
    canonical: &Path,
    backing_identity: StoreBackingIdentity,
) -> Result<(), StoreError> {
    use std::os::unix::fs::MetadataExt as _;

    let metadata =
        std::fs::metadata(canonical).map_err(|error| blob_error(BlobStoreError::Io(error)))?;
    if backing_identity.unix_device_inode() != Some((metadata.dev(), metadata.ino())) {
        return Err(blob_error(BlobStoreError::DepotIntegrity(
            "Blob depot owner path differs from the exact Store backing",
        )));
    }
    Ok(())
}

#[cfg(not(unix))]
fn validate_canonical_store_identity(
    _canonical: &Path,
    _backing_identity: StoreBackingIdentity,
) -> Result<(), StoreError> {
    Ok(())
}

#[cfg(unix)]
fn update_owner_path_digest(digest: &mut Sha256, path: &Path) -> Result<(), StoreError> {
    use std::os::unix::ffi::OsStrExt as _;

    let bytes = path.as_os_str().as_bytes();
    let length =
        u64::try_from(bytes.len()).map_err(|_| StoreError::PayloadByteAccountingOverflow)?;
    digest.update(length.to_be_bytes());
    digest.update(bytes);
    Ok(())
}

#[cfg(windows)]
fn update_owner_path_digest(digest: &mut Sha256, path: &Path) -> Result<(), StoreError> {
    use std::os::windows::ffi::OsStrExt as _;

    let units = path.as_os_str().encode_wide().collect::<Vec<_>>();
    let length =
        u64::try_from(units.len()).map_err(|_| StoreError::PayloadByteAccountingOverflow)?;
    digest.update(length.to_be_bytes());
    for unit in units {
        digest.update(unit.to_be_bytes());
    }
    Ok(())
}

#[cfg(not(any(unix, windows)))]
fn update_owner_path_digest(digest: &mut Sha256, path: &Path) -> Result<(), StoreError> {
    let value = path.to_string_lossy();
    let bytes = value.as_bytes();
    let length =
        u64::try_from(bytes.len()).map_err(|_| StoreError::PayloadByteAccountingOverflow)?;
    digest.update(length.to_be_bytes());
    digest.update(bytes);
    Ok(())
}

fn read_manifest_deletion_file(
    file: &mut File,
    path: &Path,
    expected_len: u64,
) -> Result<Vec<u8>, ManifestFileReadError> {
    let capacity = usize::try_from(expected_len).map_err(|_| {
        ManifestFileReadError::before_read(StoreError::PayloadByteAccountingOverflow)
    })?;
    let mut bytes = Vec::with_capacity(capacity);
    let mut buffer = [0u8; 8 * 1024];
    while bytes.len() < capacity {
        let bytes_read = u64::try_from(bytes.len()).map_err(|_| ManifestFileReadError {
            error: StoreError::PayloadByteAccountingOverflow,
            bytes_read: u64::MAX,
        })?;
        let injected_limit = manifest_deletion_read_limit_for_test(path, bytes_read)
            .map_err(|error| ManifestFileReadError { error, bytes_read })?;
        let remaining = capacity - bytes.len();
        let read_len = remaining
            .min(buffer.len())
            .min(injected_limit.unwrap_or(usize::MAX));
        let count = file
            .read(&mut buffer[..read_len])
            .map_err(|error| ManifestFileReadError {
                error: blob_error(BlobStoreError::Io(error)),
                bytes_read,
            })?;
        if count == 0 {
            break;
        }
        bytes.extend_from_slice(&buffer[..count]);
        observe_manifest_deletion_read(u64::try_from(count).map_err(|_| {
            ManifestFileReadError {
                error: StoreError::PayloadByteAccountingOverflow,
                bytes_read,
            }
        })?);
    }
    Ok(bytes)
}

impl OwnedDirectory {
    #[cfg(test)]
    pub(super) fn path(&self) -> &Path {
        &self.path
    }

    pub(super) fn read_private_file_if_present(
        &self,
        name: &str,
        max_len: u64,
    ) -> Result<Option<Vec<u8>>, StoreError> {
        self.read_private_regular_file_if_present(name, max_len)
            .map_err(|error| error.error)
    }

    pub(super) fn open_root_if_present(store_path: &Path) -> Result<Option<Self>, StoreError> {
        Self::open_root_internal(store_path)
    }

    #[cfg(all(
        unix,
        any(
            target_vendor = "apple",
            target_os = "linux",
            target_os = "android",
            target_os = "redox"
        )
    ))]
    fn create_bound_root(
        store_path: &Path,
        backing_identity: StoreBackingIdentity,
        owner_token: [u8; 32],
    ) -> Result<Self, StoreError> {
        let expected = depot_owner_marker(store_path, backing_identity, owner_token)?;
        let binding: [u8; 32] = expected[40..]
            .try_into()
            .map_err(|_| blob_error(BlobStoreError::DepotIntegrity("owner binding is invalid")))?;
        let pending_name = format!("{DEPOT_PENDING_PREFIX}{}", hex32(&binding));
        let parent = store_path.parent().ok_or_else(|| {
            blob_error(BlobStoreError::DepotIntegrity(
                "store path has no state-root directory",
            ))
        })?;
        let parent_descriptor = rustix::fs::open(
            parent,
            rustix::fs::OFlags::RDONLY
                | rustix::fs::OFlags::DIRECTORY
                | rustix::fs::OFlags::CLOEXEC,
            rustix::fs::Mode::empty(),
        )
        .map_err(|error| blob_error(BlobStoreError::Io(error.into())))?;
        let parent_file = File::from(parent_descriptor);

        match rustix::fs::openat(
            &parent_file,
            DEPOT_DIRECTORY,
            rustix::fs::OFlags::RDONLY
                | rustix::fs::OFlags::DIRECTORY
                | rustix::fs::OFlags::NOFOLLOW
                | rustix::fs::OFlags::CLOEXEC,
            rustix::fs::Mode::empty(),
        ) {
            Ok(descriptor) => {
                let file = File::from(descriptor);
                validate_directory(&file)?;
                let root = Self {
                    path: parent.join(DEPOT_DIRECTORY),
                    created_by_open: false,
                    file,
                };
                root.require_store_binding(store_path, backing_identity, owner_token)?;
                return Ok(root);
            }
            Err(error) if error == rustix::io::Errno::NOENT => {}
            Err(error)
                if error == rustix::io::Errno::LOOP || error == rustix::io::Errno::NOTDIR =>
            {
                return Err(blob_error(BlobStoreError::DepotIntegrity(
                    "Blob variant was replaced by another filesystem type",
                )));
            }
            Err(error) => return Err(blob_error(BlobStoreError::Io(error.into()))),
        }

        match rustix::fs::mkdirat(
            &parent_file,
            &pending_name,
            rustix::fs::Mode::RUSR | rustix::fs::Mode::WUSR | rustix::fs::Mode::XUSR,
        ) {
            Ok(()) => {}
            Err(error) if error == rustix::io::Errno::EXIST => {}
            Err(error) => return Err(blob_error(BlobStoreError::Io(error.into()))),
        }
        let pending_descriptor = rustix::fs::openat(
            &parent_file,
            &pending_name,
            rustix::fs::OFlags::RDONLY
                | rustix::fs::OFlags::DIRECTORY
                | rustix::fs::OFlags::NOFOLLOW
                | rustix::fs::OFlags::CLOEXEC,
            rustix::fs::Mode::empty(),
        )
        .map_err(|error| blob_error(BlobStoreError::Io(error.into())))?;
        let pending_file = File::from(pending_descriptor);
        validate_directory(&pending_file)?;
        // The pending name commits the exact database binding, so an existing
        // empty pending directory is recoverable only by this same token/path/
        // backing tuple. It is never an authoritative depot until renamed.
        let pending = Self {
            path: parent.join(&pending_name),
            created_by_open: true,
            file: pending_file,
        };
        maybe_inject_fault(&pending.path, DepotFaultPoint::OwnerStagingCreated)?;
        match pending.read_owner_marker()? {
            Some(marker) => pending.require_matching_owner_marker(marker, &expected, true)?,
            None => pending.elect_store_binding(store_path, backing_identity, owner_token)?,
        }
        pending.sync()?;
        maybe_inject_fault(&pending.path, DepotFaultPoint::OwnerRootSynced)?;

        match rustix::fs::renameat_with(
            &parent_file,
            &pending_name,
            &parent_file,
            DEPOT_DIRECTORY,
            rustix::fs::RenameFlags::NOREPLACE,
        ) {
            Ok(()) => {
                maybe_inject_fault(&parent.join(DEPOT_DIRECTORY), DepotFaultPoint::OwnerRenamed)?;
                parent_file
                    .sync_all()
                    .map_err(|error| blob_error(BlobStoreError::Io(error)))?;
                maybe_inject_fault(
                    &parent.join(DEPOT_DIRECTORY),
                    DepotFaultPoint::OwnerDirectorySynced,
                )?;
            }
            Err(error) if error == rustix::io::Errno::EXIST => {}
            Err(error) => return Err(blob_error(BlobStoreError::Io(error.into()))),
        }
        drop(pending);
        let root = Self::open_root_if_present(store_path)?.ok_or_else(|| {
            blob_error(BlobStoreError::DepotIntegrity(
                "Blob depot root disappeared during owner election",
            ))
        })?;
        root.require_store_binding(store_path, backing_identity, owner_token)?;
        Ok(root)
    }

    #[cfg(all(
        unix,
        not(any(
            target_vendor = "apple",
            target_os = "linux",
            target_os = "android",
            target_os = "redox"
        ))
    ))]
    fn create_bound_root(
        _store_path: &Path,
        _backing_identity: StoreBackingIdentity,
        _owner_token: [u8; 32],
    ) -> Result<Self, StoreError> {
        Err(blob_error(BlobStoreError::DepotIntegrity(
            "atomic no-replace Blob depot publication is unavailable on this Unix target",
        )))
    }

    #[cfg(not(unix))]
    fn create_bound_root(
        store_path: &Path,
        backing_identity: StoreBackingIdentity,
        owner_token: [u8; 32],
    ) -> Result<Self, StoreError> {
        let expected = depot_owner_marker(store_path, backing_identity, owner_token)?;
        let binding: [u8; 32] = expected[40..]
            .try_into()
            .map_err(|_| blob_error(BlobStoreError::DepotIntegrity("owner binding is invalid")))?;
        let parent = store_path.parent().ok_or_else(|| {
            blob_error(BlobStoreError::DepotIntegrity(
                "store path has no state-root directory",
            ))
        })?;
        let final_path = parent.join(DEPOT_DIRECTORY);
        if final_path.exists() {
            let root = Self::open_root_if_present(store_path)?.ok_or_else(|| {
                blob_error(BlobStoreError::DepotIntegrity(
                    "Blob depot root disappeared",
                ))
            })?;
            root.require_store_binding(store_path, backing_identity, owner_token)?;
            return Ok(root);
        }
        let pending_path = parent.join(format!("{DEPOT_PENDING_PREFIX}{}", hex32(&binding)));
        match std::fs::create_dir(&pending_path) {
            Ok(()) => {}
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
            Err(error) => return Err(blob_error(BlobStoreError::Io(error))),
        }
        let pending = Self {
            path: pending_path.clone(),
            created_by_open: true,
        };
        maybe_inject_fault(&pending.path, DepotFaultPoint::OwnerStagingCreated)?;
        match pending.read_owner_marker()? {
            Some(marker) => pending.require_matching_owner_marker(marker, &expected, true)?,
            None => pending.elect_store_binding(store_path, backing_identity, owner_token)?,
        }
        pending.sync()?;
        maybe_inject_fault(&pending.path, DepotFaultPoint::OwnerRootSynced)?;
        match std::fs::rename(&pending_path, &final_path) {
            Ok(()) => {
                maybe_inject_fault(&final_path, DepotFaultPoint::OwnerRenamed)?;
                File::open(parent)?.sync_all()?;
                maybe_inject_fault(&final_path, DepotFaultPoint::OwnerDirectorySynced)?;
            }
            Err(error)
                if matches!(
                    error.kind(),
                    std::io::ErrorKind::AlreadyExists | std::io::ErrorKind::DirectoryNotEmpty
                ) => {}
            Err(error) => return Err(blob_error(BlobStoreError::Io(error))),
        }
        let root = Self::open_root_if_present(store_path)?.ok_or_else(|| {
            blob_error(BlobStoreError::DepotIntegrity(
                "Blob depot root disappeared during owner election",
            ))
        })?;
        root.require_store_binding(store_path, backing_identity, owner_token)?;
        Ok(root)
    }

    pub(super) fn require_store_binding(
        &self,
        store_path: &Path,
        backing_identity: StoreBackingIdentity,
        owner_token: [u8; 32],
    ) -> Result<(), StoreError> {
        let expected = depot_owner_marker(store_path, backing_identity, owner_token)?;
        let marker = self.read_owner_marker()?.ok_or_else(|| {
            blob_error(BlobStoreError::DepotIntegrity(
                "Blob depot owner marker is missing",
            ))
        })?;
        self.require_matching_owner_marker(marker, &expected, true)?;

        // Only an already authenticated marker authorizes enumeration. This
        // removes crash-left temp names only when their full bytes prove they
        // belong to this same database binding.
        self.cleanup_owner_marker_temps(&expected)?;
        let marker = self.read_owner_marker()?.ok_or_else(|| {
            blob_error(BlobStoreError::DepotIntegrity(
                "Blob depot owner marker disappeared during validation",
            ))
        })?;
        self.require_matching_owner_marker(marker, &expected, true)?;
        Ok(())
    }

    fn require_store_binding_read_only(
        &self,
        store_path: &Path,
        backing_identity: StoreBackingIdentity,
        owner_token: [u8; 32],
    ) -> Result<(), StoreError> {
        let expected = depot_owner_marker(store_path, backing_identity, owner_token)?;
        let marker = self.read_owner_marker()?.ok_or_else(|| {
            blob_error(BlobStoreError::DepotIntegrity(
                "Blob depot owner marker is missing",
            ))
        })?;
        self.require_matching_owner_marker(marker, &expected, true)
    }

    fn elect_store_binding(
        &self,
        store_path: &Path,
        backing_identity: StoreBackingIdentity,
        owner_token: [u8; 32],
    ) -> Result<(), StoreError> {
        let expected = depot_owner_marker(store_path, backing_identity, owner_token)?;
        if self.read_owner_marker()?.is_none() && self.is_binding_pending_directory(&expected) {
            self.recover_incomplete_pending_temps(&expected)?;
        }
        // Missing-marker election is authorized only by the caller's audited
        // empty database. Before writing, stream a bounded root and require it
        // to be empty or contain only exact private temps for this same owner.
        let exact_temps = self.validate_owner_election_artifacts(&expected)?;
        if let Some(marker) = self.read_owner_marker()? {
            self.require_matching_owner_marker(marker, &expected, true)?;
        } else {
            if !self.created_by_open && exact_temps == 0 {
                return Err(blob_error(BlobStoreError::DepotIntegrity(
                    "an existing unmarked Blob depot has no exact owner-election proof",
                )));
            }
            self.install_owner_marker(&expected)?;
        }
        self.require_store_binding(store_path, backing_identity, owner_token)
    }

    fn is_binding_pending_directory(&self, expected: &[u8; DEPOT_OWNER_FILE_LEN]) -> bool {
        let binding = <[u8; 32]>::try_from(&expected[40..]).ok();
        self.path.file_name().and_then(|name| name.to_str())
            == binding
                .as_ref()
                .map(|binding| format!("{DEPOT_PENDING_PREFIX}{}", hex32(binding)))
                .as_deref()
    }

    fn recover_incomplete_pending_temps(
        &self,
        expected: &[u8; DEPOT_OWNER_FILE_LEN],
    ) -> Result<(), StoreError> {
        if !self.is_binding_pending_directory(expected) {
            return Err(blob_error(BlobStoreError::DepotIntegrity(
                "incomplete owner-temp recovery is restricted to the exact pending directory",
            )));
        }
        let names = self.incomplete_pending_temp_names(expected)?;
        for name in names {
            self.remove_if_exists(&name, false)?;
        }
        self.sync()
    }

    fn require_matching_owner_marker(
        &self,
        marker: OwnerMarkerRead,
        expected: &[u8; DEPOT_OWNER_FILE_LEN],
        require_single_link: bool,
    ) -> Result<(), StoreError> {
        if marker.bytes != *expected {
            return Err(blob_error(BlobStoreError::DepotIntegrity(
                "Blob depot owner marker differs from the exact Store binding",
            )));
        }
        #[cfg(unix)]
        if require_single_link && marker.links != 1 {
            return Err(blob_error(BlobStoreError::DepotIntegrity(
                "Blob depot owner marker has an unexpected link count",
            )));
        }
        #[cfg(not(unix))]
        let _ = require_single_link;
        Ok(())
    }

    fn cleanup_owner_marker_temps(
        &self,
        expected: &[u8; DEPOT_OWNER_FILE_LEN],
    ) -> Result<(), StoreError> {
        let names = self.validated_owner_temp_names(expected, true)?;
        for name in names {
            self.remove_if_exists(&name, false)?;
        }
        Ok(())
    }

    fn validate_owner_election_artifacts(
        &self,
        expected: &[u8; DEPOT_OWNER_FILE_LEN],
    ) -> Result<usize, StoreError> {
        Ok(self.validated_owner_temp_names(expected, false)?.len())
    }

    #[cfg(unix)]
    fn validated_owner_temp_names(
        &self,
        expected: &[u8; DEPOT_OWNER_FILE_LEN],
        owner_already_bound: bool,
    ) -> Result<Vec<String>, StoreError> {
        let directory = rustix::fs::Dir::read_from(&self.file)
            .map_err(|error| blob_error(BlobStoreError::Io(error.into())))?;
        let mut temps = Vec::new();
        for entry in directory {
            let entry = entry.map_err(|error| blob_error(BlobStoreError::Io(error.into())))?;
            let name = entry.file_name().to_str().map_err(|_| {
                blob_error(BlobStoreError::DepotIntegrity(
                    "Blob depot owner-election filename is not UTF-8",
                ))
            })?;
            if name == "." || name == ".." {
                continue;
            }
            if name == DEPOT_OWNER_FILE {
                let marker = self.read_owner_marker_named(name)?.ok_or_else(|| {
                    blob_error(BlobStoreError::DepotIntegrity(
                        "Blob depot owner marker changed during election",
                    ))
                })?;
                self.require_matching_owner_marker(marker, expected, true)?;
                continue;
            }
            if name.starts_with(DEPOT_OWNER_TEMP_PREFIX) {
                if temps.len() == 64 {
                    return Err(blob_error(BlobStoreError::DepotIntegrity(
                        "Blob depot owner-temp count exceeds its election cap",
                    )));
                }
                let marker = self.read_owner_marker_named(name)?.ok_or_else(|| {
                    blob_error(BlobStoreError::DepotIntegrity(
                        "Blob depot owner temp changed during election",
                    ))
                })?;
                self.require_matching_owner_marker(marker, expected, true)?;
                temps.push(name.to_owned());
                continue;
            }
            if !owner_already_bound {
                return Err(blob_error(BlobStoreError::DepotIntegrity(
                    "unbound Blob depot root contains a foreign artifact",
                )));
            }
        }
        Ok(temps)
    }

    #[cfg(unix)]
    fn incomplete_pending_temp_names(
        &self,
        expected: &[u8; DEPOT_OWNER_FILE_LEN],
    ) -> Result<Vec<String>, StoreError> {
        let directory = rustix::fs::Dir::read_from(&self.file)
            .map_err(|error| blob_error(BlobStoreError::Io(error.into())))?;
        let mut temps = Vec::new();
        for entry in directory {
            let entry = entry.map_err(|error| blob_error(BlobStoreError::Io(error.into())))?;
            let name = entry.file_name().to_str().map_err(|_| {
                blob_error(BlobStoreError::DepotIntegrity(
                    "Blob depot pending filename is not UTF-8",
                ))
            })?;
            if name == "." || name == ".." {
                continue;
            }
            if name == DEPOT_OWNER_FILE {
                let marker = self.read_owner_marker_named(name)?.ok_or_else(|| {
                    blob_error(BlobStoreError::DepotIntegrity(
                        "Blob depot owner marker changed during pending recovery",
                    ))
                })?;
                self.require_matching_owner_marker(marker, expected, true)?;
                continue;
            }
            if !name.starts_with(DEPOT_OWNER_TEMP_PREFIX) || temps.len() == 64 {
                return Err(blob_error(BlobStoreError::DepotIntegrity(
                    "Blob depot pending directory contains a foreign or excessive artifact",
                )));
            }
            self.validate_incomplete_owner_temp(name)?;
            temps.push(name.to_owned());
        }
        Ok(temps)
    }

    #[cfg(unix)]
    fn validate_incomplete_owner_temp(&self, name: &str) -> Result<(), StoreError> {
        use std::os::unix::fs::MetadataExt as _;

        let descriptor = rustix::fs::openat(
            &self.file,
            name,
            rustix::fs::OFlags::RDONLY | rustix::fs::OFlags::NOFOLLOW | rustix::fs::OFlags::CLOEXEC,
            rustix::fs::Mode::empty(),
        )
        .map_err(|error| blob_error(BlobStoreError::Io(error.into())))?;
        let metadata = File::from(descriptor)
            .metadata()
            .map_err(|error| blob_error(BlobStoreError::Io(error)))?;
        if !metadata.is_file()
            || metadata.uid() != rustix::process::geteuid().as_raw()
            || metadata.mode() & 0o777 != 0o600
            || metadata.nlink() != 1
            || metadata.len() > DEPOT_OWNER_FILE_LEN as u64
        {
            return Err(blob_error(BlobStoreError::DepotIntegrity(
                "Blob depot incomplete owner temp is not a bounded private owner file",
            )));
        }
        Ok(())
    }

    #[cfg(not(unix))]
    fn validated_owner_temp_names(
        &self,
        expected: &[u8; DEPOT_OWNER_FILE_LEN],
        owner_already_bound: bool,
    ) -> Result<Vec<String>, StoreError> {
        let mut temps = Vec::new();
        for entry in std::fs::read_dir(&self.path)? {
            let name = entry
                .map_err(|error| blob_error(BlobStoreError::Io(error)))?
                .file_name()
                .into_string()
                .map_err(|_| {
                    blob_error(BlobStoreError::DepotIntegrity(
                        "Blob depot owner-election filename is not UTF-8",
                    ))
                })?;
            if name == DEPOT_OWNER_FILE {
                let marker = self.read_owner_marker_named(&name)?.ok_or_else(|| {
                    blob_error(BlobStoreError::DepotIntegrity(
                        "Blob depot owner marker changed during election",
                    ))
                })?;
                self.require_matching_owner_marker(marker, expected, true)?;
                continue;
            }
            if name.starts_with(DEPOT_OWNER_TEMP_PREFIX) {
                if temps.len() == 64 {
                    return Err(blob_error(BlobStoreError::DepotIntegrity(
                        "Blob depot owner-temp count exceeds its election cap",
                    )));
                }
                let marker = self.read_owner_marker_named(&name)?.ok_or_else(|| {
                    blob_error(BlobStoreError::DepotIntegrity(
                        "Blob depot owner temp changed during election",
                    ))
                })?;
                self.require_matching_owner_marker(marker, expected, true)?;
                temps.push(name);
                continue;
            }
            if !owner_already_bound {
                return Err(blob_error(BlobStoreError::DepotIntegrity(
                    "unbound Blob depot root contains a foreign artifact",
                )));
            }
        }
        Ok(temps)
    }

    #[cfg(not(unix))]
    fn incomplete_pending_temp_names(
        &self,
        expected: &[u8; DEPOT_OWNER_FILE_LEN],
    ) -> Result<Vec<String>, StoreError> {
        let mut temps = Vec::new();
        for entry in std::fs::read_dir(&self.path)? {
            let name = entry
                .map_err(|error| blob_error(BlobStoreError::Io(error)))?
                .file_name()
                .into_string()
                .map_err(|_| {
                    blob_error(BlobStoreError::DepotIntegrity(
                        "Blob depot pending filename is not UTF-8",
                    ))
                })?;
            if name == DEPOT_OWNER_FILE {
                let marker = self.read_owner_marker_named(&name)?.ok_or_else(|| {
                    blob_error(BlobStoreError::DepotIntegrity(
                        "Blob depot owner marker changed during pending recovery",
                    ))
                })?;
                self.require_matching_owner_marker(marker, expected, true)?;
                continue;
            }
            if !name.starts_with(DEPOT_OWNER_TEMP_PREFIX) || temps.len() == 64 {
                return Err(blob_error(BlobStoreError::DepotIntegrity(
                    "Blob depot pending directory contains a foreign or excessive artifact",
                )));
            }
            let metadata = std::fs::symlink_metadata(self.path.join(&name))
                .map_err(|error| blob_error(BlobStoreError::Io(error)))?;
            if !metadata.is_file() || metadata.len() > DEPOT_OWNER_FILE_LEN as u64 {
                return Err(blob_error(BlobStoreError::DepotIntegrity(
                    "Blob depot incomplete owner temp is not a bounded regular file",
                )));
            }
            temps.push(name);
        }
        Ok(temps)
    }

    #[cfg(unix)]
    fn open_root_internal(store_path: &Path) -> Result<Option<Self>, StoreError> {
        let parent = store_path.parent().ok_or_else(|| {
            blob_error(BlobStoreError::DepotIntegrity(
                "store path has no state-root directory",
            ))
        })?;
        let parent_fd = rustix::fs::open(
            parent,
            rustix::fs::OFlags::RDONLY
                | rustix::fs::OFlags::DIRECTORY
                | rustix::fs::OFlags::CLOEXEC,
            rustix::fs::Mode::empty(),
        )
        .map_err(|error| blob_error(BlobStoreError::Io(error.into())))?;
        let descriptor = match rustix::fs::openat(
            &parent_fd,
            DEPOT_DIRECTORY,
            rustix::fs::OFlags::RDONLY
                | rustix::fs::OFlags::DIRECTORY
                | rustix::fs::OFlags::NOFOLLOW
                | rustix::fs::OFlags::CLOEXEC,
            rustix::fs::Mode::empty(),
        ) {
            Ok(descriptor) => descriptor,
            Err(error) if error == rustix::io::Errno::NOENT => return Ok(None),
            Err(error)
                if error == rustix::io::Errno::LOOP || error == rustix::io::Errno::NOTDIR =>
            {
                return Err(blob_error(BlobStoreError::DepotIntegrity(
                    "Blob variant was replaced by another filesystem type",
                )));
            }
            Err(error) => return Err(blob_error(BlobStoreError::Io(error.into()))),
        };
        let file = File::from(descriptor);
        validate_directory(&file)?;
        drop(parent_fd);
        Ok(Some(Self {
            path: parent.join(DEPOT_DIRECTORY),
            created_by_open: false,
            file,
        }))
    }

    #[cfg(not(unix))]
    fn open_root_internal(store_path: &Path) -> Result<Option<Self>, StoreError> {
        let path = store_path
            .parent()
            .ok_or_else(|| {
                blob_error(BlobStoreError::DepotIntegrity(
                    "store path has no state-root directory",
                ))
            })?
            .join(DEPOT_DIRECTORY);
        match std::fs::symlink_metadata(&path) {
            Ok(metadata) if !metadata.is_dir() => {
                return Err(blob_error(BlobStoreError::DepotIntegrity(
                    "Blob depot root is not a directory",
                )));
            }
            Ok(_) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                return Ok(None);
            }
            Err(error) => return Err(blob_error(BlobStoreError::Io(error))),
        }
        Ok(Some(Self {
            path,
            created_by_open: false,
        }))
    }

    #[cfg(unix)]
    fn read_owner_marker(&self) -> Result<Option<OwnerMarkerRead>, StoreError> {
        self.read_owner_marker_named(DEPOT_OWNER_FILE)
    }

    #[cfg(unix)]
    fn read_owner_marker_named(&self, name: &str) -> Result<Option<OwnerMarkerRead>, StoreError> {
        use std::os::unix::fs::MetadataExt as _;

        let descriptor = match rustix::fs::openat(
            &self.file,
            name,
            rustix::fs::OFlags::RDONLY | rustix::fs::OFlags::NOFOLLOW | rustix::fs::OFlags::CLOEXEC,
            rustix::fs::Mode::empty(),
        ) {
            Ok(descriptor) => descriptor,
            Err(error) if error == rustix::io::Errno::NOENT => return Ok(None),
            Err(error) => return Err(blob_error(BlobStoreError::Io(error.into()))),
        };
        let mut file = File::from(descriptor);
        let metadata = file
            .metadata()
            .map_err(|error| blob_error(BlobStoreError::Io(error)))?;
        if !metadata.is_file()
            || metadata.uid() != rustix::process::geteuid().as_raw()
            || metadata.mode() & 0o777 != 0o600
            || metadata.len() != DEPOT_OWNER_FILE_LEN as u64
            || metadata.nlink() == 0
        {
            return Err(blob_error(BlobStoreError::DepotIntegrity(
                "Blob depot owner marker is not an exact private owner file",
            )));
        }
        let mut bytes = [0u8; DEPOT_OWNER_FILE_LEN];
        file.read_exact(&mut bytes).map_err(|error| {
            if error.kind() == std::io::ErrorKind::UnexpectedEof {
                blob_error(BlobStoreError::DepotIntegrity(
                    "Blob depot owner marker is truncated",
                ))
            } else {
                blob_error(BlobStoreError::Io(error))
            }
        })?;
        let mut trailing = [0u8; 1];
        if file
            .read(&mut trailing)
            .map_err(|error| blob_error(BlobStoreError::Io(error)))?
            != 0
        {
            return Err(blob_error(BlobStoreError::DepotIntegrity(
                "Blob depot owner marker is oversized",
            )));
        }
        Ok(Some(OwnerMarkerRead {
            bytes,
            links: metadata.nlink(),
        }))
    }

    #[cfg(not(unix))]
    fn read_owner_marker(&self) -> Result<Option<OwnerMarkerRead>, StoreError> {
        self.read_owner_marker_named(DEPOT_OWNER_FILE)
    }

    #[cfg(not(unix))]
    fn read_owner_marker_named(&self, name: &str) -> Result<Option<OwnerMarkerRead>, StoreError> {
        let path = self.path.join(name);
        let link_metadata = match std::fs::symlink_metadata(&path) {
            Ok(metadata) => metadata,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(error) => return Err(blob_error(BlobStoreError::Io(error))),
        };
        if !link_metadata.is_file() || link_metadata.len() != DEPOT_OWNER_FILE_LEN as u64 {
            return Err(blob_error(BlobStoreError::DepotIntegrity(
                "Blob depot owner marker is not an exact regular file",
            )));
        }
        let mut file = File::open(&path).map_err(|error| blob_error(BlobStoreError::Io(error)))?;
        let metadata = file
            .metadata()
            .map_err(|error| blob_error(BlobStoreError::Io(error)))?;
        if !metadata.is_file() || metadata.len() != DEPOT_OWNER_FILE_LEN as u64 {
            return Err(blob_error(BlobStoreError::DepotIntegrity(
                "Blob depot owner marker changed during validation",
            )));
        }
        let mut bytes = [0u8; DEPOT_OWNER_FILE_LEN];
        file.read_exact(&mut bytes).map_err(|error| {
            if error.kind() == std::io::ErrorKind::UnexpectedEof {
                blob_error(BlobStoreError::DepotIntegrity(
                    "Blob depot owner marker is truncated",
                ))
            } else {
                blob_error(BlobStoreError::Io(error))
            }
        })?;
        let mut trailing = [0u8; 1];
        if file
            .read(&mut trailing)
            .map_err(|error| blob_error(BlobStoreError::Io(error)))?
            != 0
        {
            return Err(blob_error(BlobStoreError::DepotIntegrity(
                "Blob depot owner marker is oversized",
            )));
        }
        Ok(Some(OwnerMarkerRead { bytes }))
    }

    #[cfg(all(
        unix,
        any(
            target_vendor = "apple",
            target_os = "linux",
            target_os = "android",
            target_os = "redox"
        )
    ))]
    fn install_owner_marker(
        &self,
        expected: &[u8; DEPOT_OWNER_FILE_LEN],
    ) -> Result<(), StoreError> {
        let (temp_name, descriptor) = self.create_owner_marker_temp()?;
        let mut file = File::from(descriptor);
        maybe_inject_fault(&self.path, DepotFaultPoint::OwnerTempCreated)?;
        let split = DEPOT_OWNER_FILE_LEN / 2;
        if let Err(error) = file
            .write_all(&expected[..split])
            .and_then(|()| file.sync_all())
        {
            let _ = rustix::fs::unlinkat(&self.file, &temp_name, rustix::fs::AtFlags::empty());
            return Err(blob_error(BlobStoreError::Io(error)));
        }
        maybe_inject_fault(&self.path, DepotFaultPoint::OwnerTempPartiallyWritten)?;
        if let Err(error) = file
            .write_all(&expected[split..])
            .and_then(|()| file.sync_all())
        {
            let _ = rustix::fs::unlinkat(&self.file, &temp_name, rustix::fs::AtFlags::empty());
            return Err(blob_error(BlobStoreError::Io(error)));
        }
        // Fault exits retain the exact durable election artifact a process
        // crash would leave. Empty-database retry authenticates it before use.
        maybe_inject_fault(&self.path, DepotFaultPoint::OwnerTempSynced)?;
        match rustix::fs::renameat_with(
            &self.file,
            &temp_name,
            &self.file,
            DEPOT_OWNER_FILE,
            rustix::fs::RenameFlags::NOREPLACE,
        ) {
            Ok(()) => {
                maybe_inject_fault(&self.path, DepotFaultPoint::OwnerMarkerRenamed)?;
                // The no-replace rename installs a single-link final name. Its
                // directory entry is durable before any physical scan begins.
                self.sync()?;
                maybe_inject_fault(&self.path, DepotFaultPoint::OwnerMarkerDirectorySynced)?;
                return Ok(());
            }
            Err(error) if error == rustix::io::Errno::EXIST => {}
            Err(error) => {
                let _ = rustix::fs::unlinkat(&self.file, &temp_name, rustix::fs::AtFlags::empty());
                return Err(blob_error(BlobStoreError::Io(error.into())));
            }
        }
        rustix::fs::unlinkat(&self.file, &temp_name, rustix::fs::AtFlags::empty())
            .map_err(|error| blob_error(BlobStoreError::Io(error.into())))?;
        self.sync()
    }

    #[cfg(all(
        unix,
        not(any(
            target_vendor = "apple",
            target_os = "linux",
            target_os = "android",
            target_os = "redox"
        ))
    ))]
    fn install_owner_marker(
        &self,
        _expected: &[u8; DEPOT_OWNER_FILE_LEN],
    ) -> Result<(), StoreError> {
        Err(blob_error(BlobStoreError::DepotIntegrity(
            "atomic no-replace Blob owner election is unavailable on this Unix target",
        )))
    }

    #[cfg(unix)]
    fn create_owner_marker_temp(&self) -> Result<(String, rustix::fd::OwnedFd), StoreError> {
        for _ in 0..64 {
            let name = format!(
                "{DEPOT_OWNER_TEMP_PREFIX}{}-{}",
                std::process::id(),
                TEMP_SEQUENCE.fetch_add(1, Ordering::Relaxed)
            );
            match rustix::fs::openat(
                &self.file,
                &name,
                rustix::fs::OFlags::WRONLY
                    | rustix::fs::OFlags::CREATE
                    | rustix::fs::OFlags::EXCL
                    | rustix::fs::OFlags::NOFOLLOW
                    | rustix::fs::OFlags::CLOEXEC,
                rustix::fs::Mode::RUSR | rustix::fs::Mode::WUSR,
            ) {
                Ok(descriptor) => return Ok((name, descriptor)),
                Err(error) if error == rustix::io::Errno::EXIST => {}
                Err(error) => return Err(blob_error(BlobStoreError::Io(error.into()))),
            }
        }
        Err(blob_error(BlobStoreError::DepotIntegrity(
            "Blob depot owner temp-name retry bound is exhausted",
        )))
    }

    #[cfg(not(unix))]
    fn install_owner_marker(
        &self,
        expected: &[u8; DEPOT_OWNER_FILE_LEN],
    ) -> Result<(), StoreError> {
        let (temp, mut file) = self.create_owner_marker_temp()?;
        maybe_inject_fault(&self.path, DepotFaultPoint::OwnerTempCreated)?;
        let split = DEPOT_OWNER_FILE_LEN / 2;
        if let Err(error) = file
            .write_all(&expected[..split])
            .and_then(|()| file.sync_all())
        {
            drop(file);
            let _ = std::fs::remove_file(&temp);
            return Err(blob_error(BlobStoreError::Io(error)));
        }
        maybe_inject_fault(&self.path, DepotFaultPoint::OwnerTempPartiallyWritten)?;
        if let Err(error) = file
            .write_all(&expected[split..])
            .and_then(|()| file.sync_all())
        {
            drop(file);
            let _ = std::fs::remove_file(&temp);
            return Err(blob_error(BlobStoreError::Io(error)));
        }
        maybe_inject_fault(&self.path, DepotFaultPoint::OwnerTempSynced)?;
        drop(file);
        let final_path = self.path.join(DEPOT_OWNER_FILE);
        let linked = match std::fs::hard_link(&temp, &final_path) {
            Ok(()) => {
                maybe_inject_fault(&self.path, DepotFaultPoint::OwnerMarkerRenamed)?;
                true
            }
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => false,
            Err(error) => {
                let _ = std::fs::remove_file(&temp);
                return Err(blob_error(BlobStoreError::Io(error)));
            }
        };
        if linked {
            self.sync()?;
            maybe_inject_fault(&self.path, DepotFaultPoint::OwnerMarkerDirectorySynced)?;
        }
        std::fs::remove_file(&temp).map_err(|error| blob_error(BlobStoreError::Io(error)))?;
        self.sync()
    }

    #[cfg(not(unix))]
    fn create_owner_marker_temp(&self) -> Result<(PathBuf, File), StoreError> {
        for _ in 0..64 {
            let path = self.path.join(format!(
                "{DEPOT_OWNER_TEMP_PREFIX}{}-{}",
                std::process::id(),
                TEMP_SEQUENCE.fetch_add(1, Ordering::Relaxed)
            ));
            match std::fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(&path)
            {
                Ok(file) => return Ok((path, file)),
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
                Err(error) => return Err(blob_error(BlobStoreError::Io(error))),
            }
        }
        Err(blob_error(BlobStoreError::DepotIntegrity(
            "Blob depot owner temp-name retry bound is exhausted",
        )))
    }

    #[cfg(unix)]
    pub(super) fn open_child_directory(
        &self,
        name: &str,
        create: bool,
    ) -> Result<Self, StoreError> {
        self.open_child_directory_observed(name, create, None)
    }

    #[cfg(unix)]
    fn open_child_directory_observed(
        &self,
        name: &str,
        create: bool,
        _observed_store: Option<&Store>,
    ) -> Result<Self, StoreError> {
        let mut created = false;
        let descriptor = match rustix::fs::openat(
            &self.file,
            name,
            rustix::fs::OFlags::RDONLY
                | rustix::fs::OFlags::DIRECTORY
                | rustix::fs::OFlags::NOFOLLOW
                | rustix::fs::OFlags::CLOEXEC,
            rustix::fs::Mode::empty(),
        ) {
            Ok(descriptor) => descriptor,
            Err(error) if error == rustix::io::Errno::NOENT && create => {
                rustix::fs::mkdirat(
                    &self.file,
                    name,
                    rustix::fs::Mode::RUSR | rustix::fs::Mode::WUSR | rustix::fs::Mode::XUSR,
                )
                .map_err(|error| blob_error(BlobStoreError::Io(error.into())))?;
                created = true;
                rustix::fs::openat(
                    &self.file,
                    name,
                    rustix::fs::OFlags::RDONLY
                        | rustix::fs::OFlags::DIRECTORY
                        | rustix::fs::OFlags::NOFOLLOW
                        | rustix::fs::OFlags::CLOEXEC,
                    rustix::fs::Mode::empty(),
                )
                .map_err(|error| blob_error(BlobStoreError::Io(error.into())))?
            }
            Err(error)
                if error == rustix::io::Errno::LOOP || error == rustix::io::Errno::NOTDIR =>
            {
                return Err(blob_error(BlobStoreError::DepotIntegrity(
                    "Blob variant was replaced by another filesystem type",
                )));
            }
            Err(error) => return Err(blob_error(BlobStoreError::Io(error.into()))),
        };
        let file = File::from(descriptor);
        validate_directory(&file)?;
        if created {
            self.sync()?;
        }
        Ok(Self {
            path: self.path.join(name),
            created_by_open: false,
            file,
        })
    }

    #[cfg(not(unix))]
    pub(super) fn open_child_directory(
        &self,
        name: &str,
        create: bool,
    ) -> Result<Self, StoreError> {
        let path = self.path.join(name);
        match std::fs::symlink_metadata(&path) {
            Ok(metadata) if !metadata.is_dir() => {
                return Err(blob_error(BlobStoreError::DepotIntegrity(
                    "Blob variant is not a directory",
                )));
            }
            Ok(_) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound && create => {
                std::fs::create_dir(&path)?
            }
            Err(error) => return Err(blob_error(BlobStoreError::Io(error))),
        }
        Ok(Self {
            path,
            created_by_open: false,
        })
    }

    pub(super) fn open_child_directory_if_present(
        &self,
        name: &str,
    ) -> Result<Option<Self>, StoreError> {
        match self.open_child_directory(name, false) {
            Ok(directory) => Ok(Some(directory)),
            Err(StoreError::Blob(BlobStoreError::Io(error)))
                if error.kind() == std::io::ErrorKind::NotFound =>
            {
                Ok(None)
            }
            Err(error) => Err(error),
        }
    }

    #[cfg(unix)]
    pub(super) fn write_atomic(&self, final_name: &str, bytes: &[u8]) -> Result<(), StoreError> {
        self.write_atomic_observed(final_name, bytes, None)
    }

    #[cfg(unix)]
    fn write_atomic_observed(
        &self,
        final_name: &str,
        bytes: &[u8],
        _observed_store: Option<&Store>,
    ) -> Result<(), StoreError> {
        let temp_name = format!(
            "{TEMP_PREFIX}{}-{}",
            std::process::id(),
            TEMP_SEQUENCE.fetch_add(1, Ordering::Relaxed)
        );
        let descriptor = rustix::fs::openat(
            &self.file,
            &temp_name,
            rustix::fs::OFlags::WRONLY
                | rustix::fs::OFlags::CREATE
                | rustix::fs::OFlags::EXCL
                | rustix::fs::OFlags::NOFOLLOW
                | rustix::fs::OFlags::CLOEXEC,
            rustix::fs::Mode::RUSR | rustix::fs::Mode::WUSR,
        )
        .map_err(|error| blob_error(BlobStoreError::Io(error.into())))?;
        let mut file = File::from(descriptor);
        if let Err(error) = file.write_all(bytes).and_then(|()| file.sync_all()) {
            let _ = rustix::fs::unlinkat(&self.file, &temp_name, rustix::fs::AtFlags::empty());
            return Err(blob_error(BlobStoreError::Io(error)));
        }
        // Fault exits intentionally retain the exact artifact a process crash
        // would leave; writable reopen treats it as non-authoritative and
        // reclaims it before a retry.
        maybe_inject_fault(&self.path, DepotFaultPoint::TempSynced)?;
        if let Err(error) = rustix::fs::renameat(&self.file, &temp_name, &self.file, final_name) {
            let _ = rustix::fs::unlinkat(&self.file, &temp_name, rustix::fs::AtFlags::empty());
            return Err(blob_error(BlobStoreError::Io(error.into())));
        }
        maybe_inject_fault(&self.path, DepotFaultPoint::Renamed)?;
        self.file
            .sync_all()
            .map_err(|error| blob_error(BlobStoreError::Io(error)))?;
        maybe_inject_fault(&self.path, DepotFaultPoint::DirectorySynced)?;
        Ok(())
    }

    #[cfg(not(unix))]
    pub(super) fn write_atomic(&self, final_name: &str, bytes: &[u8]) -> Result<(), StoreError> {
        self.write_atomic_observed(final_name, bytes, None)
    }

    #[cfg(not(unix))]
    fn write_atomic_observed(
        &self,
        final_name: &str,
        bytes: &[u8],
        _observed_store: Option<&Store>,
    ) -> Result<(), StoreError> {
        let temp = self.path.join(format!(
            "{TEMP_PREFIX}{}-{}",
            std::process::id(),
            TEMP_SEQUENCE.fetch_add(1, Ordering::Relaxed)
        ));
        let final_path = self.path.join(final_name);
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&temp)?;
        file.write_all(bytes)?;
        file.sync_all()?;
        maybe_inject_fault(&self.path, DepotFaultPoint::TempSynced)?;
        std::fs::rename(&temp, &final_path)?;
        maybe_inject_fault(&self.path, DepotFaultPoint::Renamed)?;
        File::open(&self.path)?.sync_all()?;
        maybe_inject_fault(&self.path, DepotFaultPoint::DirectorySynced)?;
        Ok(())
    }

    pub(super) fn open_private_rw_file(
        &self,
        name: &str,
        create_new: bool,
    ) -> Result<File, StoreError> {
        require_relative_leaf_name(name)?;
        #[cfg(unix)]
        {
            let mut flags = rustix::fs::OFlags::RDWR
                | rustix::fs::OFlags::NOFOLLOW
                | rustix::fs::OFlags::CLOEXEC;
            if create_new {
                flags |= rustix::fs::OFlags::CREATE | rustix::fs::OFlags::EXCL;
            }
            let descriptor = rustix::fs::openat(
                &self.file,
                name,
                flags,
                rustix::fs::Mode::RUSR | rustix::fs::Mode::WUSR,
            )
            .map_err(|error| {
                if error == rustix::io::Errno::LOOP
                    || error == rustix::io::Errno::ISDIR
                    || error == rustix::io::Errno::NOTDIR
                {
                    blob_error(BlobStoreError::DepotIntegrity(
                        "Blob pack file was replaced by another filesystem type",
                    ))
                } else {
                    blob_error(BlobStoreError::Io(error.into()))
                }
            })?;
            let file = File::from(descriptor);
            validate_private_pack_file(&file)?;
            Ok(file)
        }
        #[cfg(not(unix))]
        {
            let path = self.path.join(name);
            let mut options = std::fs::OpenOptions::new();
            options.read(true).write(true).create_new(create_new);
            let file = options.open(path)?;
            if !file.metadata()?.is_file() {
                return Err(blob_error(BlobStoreError::DepotIntegrity(
                    "Blob pack file is not regular",
                )));
            }
            Ok(file)
        }
    }

    pub(super) fn open_private_rw_file_if_present(
        &self,
        name: &str,
    ) -> Result<Option<File>, StoreError> {
        require_relative_leaf_name(name)?;
        #[cfg(unix)]
        {
            let descriptor = match rustix::fs::openat(
                &self.file,
                name,
                rustix::fs::OFlags::RDWR
                    | rustix::fs::OFlags::NOFOLLOW
                    | rustix::fs::OFlags::CLOEXEC,
                rustix::fs::Mode::empty(),
            ) {
                Ok(descriptor) => descriptor,
                Err(error) if error == rustix::io::Errno::NOENT => return Ok(None),
                Err(error)
                    if error == rustix::io::Errno::LOOP
                        || error == rustix::io::Errno::ISDIR
                        || error == rustix::io::Errno::NOTDIR =>
                {
                    return Err(blob_error(BlobStoreError::DepotIntegrity(
                        "Blob pack file was replaced by another filesystem type",
                    )));
                }
                Err(error) => return Err(blob_error(BlobStoreError::Io(error.into()))),
            };
            let file = File::from(descriptor);
            validate_private_pack_file(&file)?;
            Ok(Some(file))
        }
        #[cfg(not(unix))]
        {
            let path = self.path.join(name);
            let file = match std::fs::OpenOptions::new()
                .read(true)
                .write(true)
                .open(path)
            {
                Ok(file) => file,
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
                Err(error) => return Err(blob_error(BlobStoreError::Io(error))),
            };
            if !file.metadata()?.is_file() {
                return Err(blob_error(BlobStoreError::DepotIntegrity(
                    "Blob pack file is not regular",
                )));
            }
            Ok(Some(file))
        }
    }

    pub(super) fn open_private_read_file_if_present(
        &self,
        name: &str,
    ) -> Result<Option<File>, StoreError> {
        require_relative_leaf_name(name)?;
        #[cfg(unix)]
        {
            let descriptor = match rustix::fs::openat(
                &self.file,
                name,
                rustix::fs::OFlags::RDONLY
                    | rustix::fs::OFlags::NOFOLLOW
                    | rustix::fs::OFlags::CLOEXEC,
                rustix::fs::Mode::empty(),
            ) {
                Ok(descriptor) => descriptor,
                Err(error) if error == rustix::io::Errno::NOENT => return Ok(None),
                Err(error)
                    if error == rustix::io::Errno::LOOP
                        || error == rustix::io::Errno::ISDIR
                        || error == rustix::io::Errno::NOTDIR =>
                {
                    return Err(blob_error(BlobStoreError::DepotIntegrity(
                        "Blob pack file was replaced by another filesystem type",
                    )));
                }
                Err(error) => return Err(blob_error(BlobStoreError::Io(error.into()))),
            };
            let file = File::from(descriptor);
            validate_private_pack_file(&file)?;
            Ok(Some(file))
        }
        #[cfg(not(unix))]
        {
            match File::open(self.path.join(name)) {
                Ok(file) => {
                    if !file.metadata()?.is_file() {
                        return Err(blob_error(BlobStoreError::DepotIntegrity(
                            "Blob pack file is not regular",
                        )));
                    }
                    Ok(Some(file))
                }
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
                Err(error) => Err(blob_error(BlobStoreError::Io(error))),
            }
        }
    }

    #[cfg(unix)]
    fn read_private_regular_file_if_present(
        &self,
        name: &str,
        max_len: u64,
    ) -> Result<Option<Vec<u8>>, ManifestFileReadError> {
        let path = self.path.join(name);
        let descriptor = match rustix::fs::openat(
            &self.file,
            name,
            rustix::fs::OFlags::RDONLY | rustix::fs::OFlags::NOFOLLOW | rustix::fs::OFlags::CLOEXEC,
            rustix::fs::Mode::empty(),
        ) {
            Ok(descriptor) => descriptor,
            Err(error) if error == rustix::io::Errno::NOENT => return Ok(None),
            Err(error)
                if error == rustix::io::Errno::LOOP
                    || error == rustix::io::Errno::ISDIR
                    || error == rustix::io::Errno::NOTDIR =>
            {
                return Err(ManifestFileReadError::before_read(blob_error(
                    BlobStoreError::DepotIntegrity(
                        "manifest-authorized Blob chunk was replaced by another filesystem type",
                    ),
                )));
            }
            Err(error) => {
                return Err(ManifestFileReadError::before_read(blob_error(
                    BlobStoreError::Io(error.into()),
                )));
            }
        };
        let mut file = File::from(descriptor);
        let metadata = file.metadata().map_err(|error| {
            ManifestFileReadError::before_read(blob_error(BlobStoreError::Io(error)))
        })?;
        use std::os::unix::fs::MetadataExt as _;
        if !metadata.is_file()
            || metadata.len() > max_len
            || metadata.uid() != rustix::process::geteuid().as_raw()
            || metadata.mode() & 0o777 != 0o600
            || metadata.nlink() != 1
        {
            return Err(ManifestFileReadError::before_read(blob_error(
                BlobStoreError::DepotIntegrity(
                    "manifest-authorized Blob chunk type, ownership, mode, link count, or length mismatches",
                ),
            )));
        }
        let bytes = read_manifest_deletion_file(&mut file, &path, metadata.len())?;
        let bytes_read = u64::try_from(bytes.len()).map_err(|_| ManifestFileReadError {
            error: StoreError::PayloadByteAccountingOverflow,
            bytes_read: u64::MAX,
        })?;
        let after = file.metadata().map_err(|error| ManifestFileReadError {
            error: blob_error(BlobStoreError::Io(error)),
            bytes_read,
        })?;
        if bytes_read != metadata.len() || after.len() != metadata.len() {
            return Err(ManifestFileReadError {
                error: blob_error(BlobStoreError::DepotIntegrity(
                    "manifest-authorized Blob chunk changed while it was read",
                )),
                bytes_read,
            });
        }
        Ok(Some(bytes))
    }

    #[cfg(not(unix))]
    fn read_private_regular_file_if_present(
        &self,
        name: &str,
        max_len: u64,
    ) -> Result<Option<Vec<u8>>, ManifestFileReadError> {
        let path = self.path.join(name);
        let metadata = match std::fs::symlink_metadata(&path) {
            Ok(metadata) => metadata,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(error) => {
                return Err(ManifestFileReadError::before_read(blob_error(
                    BlobStoreError::Io(error),
                )));
            }
        };
        if !metadata.is_file() || metadata.len() > max_len {
            return Err(ManifestFileReadError::before_read(blob_error(
                BlobStoreError::DepotIntegrity(
                    "manifest-authorized Blob chunk type or length mismatches",
                ),
            )));
        }
        let mut file = File::open(&path).map_err(|error| {
            ManifestFileReadError::before_read(blob_error(BlobStoreError::Io(error)))
        })?;
        let bytes = read_manifest_deletion_file(&mut file, &path, metadata.len())?;
        let bytes_read = u64::try_from(bytes.len()).map_err(|_| ManifestFileReadError {
            error: StoreError::PayloadByteAccountingOverflow,
            bytes_read: u64::MAX,
        })?;
        let after = file.metadata().map_err(|error| ManifestFileReadError {
            error: blob_error(BlobStoreError::Io(error)),
            bytes_read,
        })?;
        if bytes_read != metadata.len() || after.len() != metadata.len() {
            return Err(ManifestFileReadError {
                error: blob_error(BlobStoreError::DepotIntegrity(
                    "manifest-authorized Blob chunk changed while it was read",
                )),
                bytes_read,
            });
        }
        Ok(Some(bytes))
    }

    #[cfg(unix)]
    fn read_file_into(
        &self,
        name: &str,
        expected_len: u64,
        ciphertext_len: u32,
        header: &mut [u8; CHUNK_FILE_HEADER_LEN],
        ciphertext: &mut Vec<u8>,
    ) -> Result<(), StoreError> {
        let descriptor = rustix::fs::openat(
            &self.file,
            name,
            rustix::fs::OFlags::RDONLY | rustix::fs::OFlags::NOFOLLOW | rustix::fs::OFlags::CLOEXEC,
            rustix::fs::Mode::empty(),
        )
        .map_err(|error| {
            if error == rustix::io::Errno::NOENT {
                blob_error(BlobStoreError::DepotIntegrity(
                    "marked Blob chunk is missing",
                ))
            } else if error == rustix::io::Errno::LOOP
                || error == rustix::io::Errno::ISDIR
                || error == rustix::io::Errno::NOTDIR
            {
                blob_error(BlobStoreError::DepotIntegrity(
                    "marked Blob chunk was replaced by another filesystem type",
                ))
            } else {
                blob_error(BlobStoreError::Io(error.into()))
            }
        })?;
        let mut file = File::from(descriptor);
        let metadata = file
            .metadata()
            .map_err(|error| blob_error(BlobStoreError::Io(error)))?;
        use std::os::unix::fs::MetadataExt as _;
        if !metadata.is_file()
            || metadata.len() != expected_len
            || metadata.uid() != rustix::process::geteuid().as_raw()
            || metadata.mode() & 0o777 != 0o600
            || metadata.nlink() != 1
        {
            return Err(blob_error(BlobStoreError::DepotIntegrity(
                "marked Blob chunk type, ownership, mode, link count, or length mismatches",
            )));
        }
        read_exact_chunk_file_parts(&mut file, ciphertext_len, header, ciphertext)
    }

    #[cfg(not(unix))]
    fn read_file_into(
        &self,
        name: &str,
        expected_len: u64,
        ciphertext_len: u32,
        header: &mut [u8; CHUNK_FILE_HEADER_LEN],
        ciphertext: &mut Vec<u8>,
    ) -> Result<(), StoreError> {
        let path = self.path.join(name);
        let mut file = File::open(path).map_err(|error| {
            if error.kind() == std::io::ErrorKind::NotFound {
                blob_error(BlobStoreError::DepotIntegrity(
                    "marked Blob chunk is missing",
                ))
            } else {
                blob_error(BlobStoreError::Io(error))
            }
        })?;
        let metadata = file
            .metadata()
            .map_err(|error| blob_error(BlobStoreError::Io(error)))?;
        if !metadata.is_file() || metadata.len() != expected_len {
            return Err(blob_error(BlobStoreError::DepotIntegrity(
                "marked Blob chunk type or length mismatches",
            )));
        }
        read_exact_chunk_file_parts(&mut file, ciphertext_len, header, ciphertext)
    }

    #[cfg(unix)]
    fn is_empty(&self) -> Result<bool, StoreError> {
        let mut directory = rustix::fs::Dir::read_from(&self.file)
            .map_err(|error| blob_error(BlobStoreError::Io(error.into())))?;
        for entry in &mut directory {
            let entry = entry.map_err(|error| blob_error(BlobStoreError::Io(error.into())))?;
            let name = entry.file_name().to_bytes();
            if name != b"." && name != b".." {
                return Ok(false);
            }
        }
        Ok(true)
    }

    #[cfg(not(unix))]
    fn is_empty(&self) -> Result<bool, StoreError> {
        Ok(std::fs::read_dir(&self.path)?.next().is_none())
    }

    #[cfg(unix)]
    pub(super) fn entry_names(&self) -> Result<Vec<String>, StoreError> {
        let directory = rustix::fs::Dir::read_from(&self.file)
            .map_err(|error| blob_error(BlobStoreError::Io(error.into())))?;
        directory
            .map(|entry| {
                let entry = entry.map_err(|error| blob_error(BlobStoreError::Io(error.into())))?;
                entry.file_name().to_str().map(str::to_owned).map_err(|_| {
                    blob_error(BlobStoreError::DepotIntegrity(
                        "Blob depot filename is not UTF-8",
                    ))
                })
            })
            .filter(|entry| !matches!(entry, Ok(name) if name == "." || name == ".."))
            .collect()
    }

    #[cfg(not(unix))]
    pub(super) fn entry_names(&self) -> Result<Vec<String>, StoreError> {
        std::fs::read_dir(&self.path)?
            .map(|entry| {
                entry
                    .map_err(|error| blob_error(BlobStoreError::Io(error)))?
                    .file_name()
                    .into_string()
                    .map_err(|_| {
                        blob_error(BlobStoreError::DepotIntegrity(
                            "Blob depot filename is not UTF-8",
                        ))
                    })
            })
            .collect()
    }

    #[cfg(unix)]
    pub(super) fn entry_names_bounded(&self, limit: usize) -> Result<Vec<String>, StoreError> {
        let directory = rustix::fs::Dir::read_from(&self.file)
            .map_err(|error| blob_error(BlobStoreError::Io(error.into())))?;
        directory
            .map(|entry| {
                let entry = entry.map_err(|error| blob_error(BlobStoreError::Io(error.into())))?;
                entry.file_name().to_str().map(str::to_owned).map_err(|_| {
                    blob_error(BlobStoreError::DepotIntegrity(
                        "Blob depot filename is not UTF-8",
                    ))
                })
            })
            .filter(|entry| !matches!(entry, Ok(name) if name == "." || name == ".."))
            .take(limit)
            .collect()
    }

    #[cfg(not(unix))]
    pub(super) fn entry_names_bounded(&self, limit: usize) -> Result<Vec<String>, StoreError> {
        std::fs::read_dir(&self.path)?
            .map(|entry| {
                entry
                    .map_err(|error| blob_error(BlobStoreError::Io(error)))?
                    .file_name()
                    .into_string()
                    .map_err(|_| {
                        blob_error(BlobStoreError::DepotIntegrity(
                            "Blob depot filename is not UTF-8",
                        ))
                    })
            })
            .take(limit)
            .collect()
    }

    /// Returns authoritative entries while treating interrupted atomic-write
    /// temporaries as non-authoritative crash artifacts. Writable recovery
    /// removes each temporary durably before callers interpret the namespace.
    pub(super) fn entry_names_reclaiming_atomic_temporaries(
        &self,
        recover: bool,
    ) -> Result<Vec<String>, StoreError> {
        let mut authoritative = Vec::new();
        for name in self.entry_names()? {
            if name.starts_with(TEMP_PREFIX) {
                if recover {
                    self.remove_if_exists(&name, false)?;
                }
            } else {
                authoritative.push(name);
            }
        }
        Ok(authoritative)
    }

    #[cfg(unix)]
    pub(super) fn remove_if_exists(&self, name: &str, directory: bool) -> Result<(), StoreError> {
        let flags = if directory {
            rustix::fs::AtFlags::REMOVEDIR
        } else {
            rustix::fs::AtFlags::empty()
        };
        match rustix::fs::unlinkat(&self.file, name, flags) {
            Ok(()) => {
                self.sync()?;
                Ok(())
            }
            Err(error) if error == rustix::io::Errno::NOENT => Ok(()),
            Err(error) => Err(blob_error(BlobStoreError::Io(error.into()))),
        }
    }

    #[cfg(unix)]
    fn unlink_file_if_exists_no_sync(&self, name: &str) -> Result<bool, StoreError> {
        match rustix::fs::unlinkat(&self.file, name, rustix::fs::AtFlags::empty()) {
            Ok(()) => Ok(true),
            Err(error) if error == rustix::io::Errno::NOENT => Ok(false),
            Err(error) => Err(blob_error(BlobStoreError::Io(error.into()))),
        }
    }

    #[cfg(not(unix))]
    fn unlink_file_if_exists_no_sync(&self, name: &str) -> Result<bool, StoreError> {
        match std::fs::remove_file(self.path.join(name)) {
            Ok(()) => Ok(true),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(false),
            Err(error) => Err(blob_error(BlobStoreError::Io(error))),
        }
    }

    #[cfg(unix)]
    fn unlink_directory_if_exists_no_sync(&self, name: &str) -> Result<bool, StoreError> {
        match rustix::fs::unlinkat(&self.file, name, rustix::fs::AtFlags::REMOVEDIR) {
            Ok(()) => Ok(true),
            Err(error) if error == rustix::io::Errno::NOENT => Ok(false),
            Err(error) => Err(blob_error(BlobStoreError::Io(error.into()))),
        }
    }

    #[cfg(not(unix))]
    fn unlink_directory_if_exists_no_sync(&self, name: &str) -> Result<bool, StoreError> {
        match std::fs::remove_dir(self.path.join(name)) {
            Ok(()) => Ok(true),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(false),
            Err(error) => Err(blob_error(BlobStoreError::Io(error))),
        }
    }

    #[cfg(not(unix))]
    pub(super) fn remove_if_exists(&self, name: &str, directory: bool) -> Result<(), StoreError> {
        let result = if directory {
            std::fs::remove_dir(self.path.join(name))
        } else {
            std::fs::remove_file(self.path.join(name))
        };
        match result {
            Ok(()) => self.sync(),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(error) => Err(blob_error(BlobStoreError::Io(error))),
        }
    }

    pub(super) fn sync(&self) -> Result<(), StoreError> {
        #[cfg(unix)]
        self.file
            .sync_all()
            .map_err(|error| blob_error(BlobStoreError::Io(error)))?;
        #[cfg(not(unix))]
        File::open(&self.path)?.sync_all()?;
        Ok(())
    }
}

fn require_relative_leaf_name(name: &str) -> Result<(), StoreError> {
    if name.is_empty() || name == "." || name == ".." || name.contains(['/', '\\']) {
        return Err(blob_error(BlobStoreError::DepotIntegrity(
            "Blob pack filename is not a relative leaf",
        )));
    }
    Ok(())
}

#[cfg(unix)]
fn validate_private_pack_file(file: &File) -> Result<(), StoreError> {
    use std::os::unix::fs::MetadataExt as _;

    let metadata = file
        .metadata()
        .map_err(|error| blob_error(BlobStoreError::Io(error)))?;
    if !metadata.is_file()
        || metadata.uid() != rustix::process::geteuid().as_raw()
        || metadata.mode() & 0o777 != 0o600
        || metadata.nlink() != 1
    {
        return Err(blob_error(BlobStoreError::DepotIntegrity(
            "Blob pack type, ownership, mode, or link count mismatches",
        )));
    }
    Ok(())
}

fn read_exact_chunk_file_parts(
    file: &mut File,
    ciphertext_len: u32,
    header: &mut [u8; CHUNK_FILE_HEADER_LEN],
    ciphertext: &mut Vec<u8>,
) -> Result<(), StoreError> {
    let ciphertext_len =
        usize::try_from(ciphertext_len).map_err(|_| StoreError::PayloadByteAccountingOverflow)?;
    ciphertext.clear();
    ciphertext.resize(ciphertext_len, 0);
    file.read_exact(header)
        .and_then(|()| file.read_exact(ciphertext.as_mut_slice()))
        .map_err(|error| {
            if error.kind() == std::io::ErrorKind::UnexpectedEof {
                blob_error(BlobStoreError::DepotIntegrity(
                    "marked Blob chunk is truncated",
                ))
            } else {
                blob_error(BlobStoreError::Io(error))
            }
        })?;
    let mut trailing = [0u8; 1];
    if file
        .read(&mut trailing)
        .map_err(|error| blob_error(BlobStoreError::Io(error)))?
        != 0
    {
        return Err(blob_error(BlobStoreError::DepotIntegrity(
            "marked Blob chunk is oversized",
        )));
    }
    Ok(())
}

#[cfg(unix)]
fn validate_directory(file: &File) -> Result<(), StoreError> {
    use std::os::unix::fs::MetadataExt as _;

    let metadata = file
        .metadata()
        .map_err(|error| blob_error(BlobStoreError::Io(error)))?;
    if !metadata.is_dir()
        || metadata.uid() != rustix::process::geteuid().as_raw()
        || metadata.mode() & 0o077 != 0
    {
        return Err(blob_error(BlobStoreError::DepotIntegrity(
            "Blob depot directory is not private and owner-controlled",
        )));
    }
    Ok(())
}
