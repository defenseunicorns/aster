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
use std::sync::{Arc, MutexGuard};

use aster_mesh::{
    BlobChunkRecord, BlobManifest, BlobMetadata as CoreBlobMetadata, BlobPhysicalLineage,
    BlobStore as CoreBlobStore, ContentVerifiedBlobEnvelope,
};
use redb::{ReadableTable, ReadableTableMetadata};

use super::*;

const DEPOT_DIRECTORY: &str = "blob-depot-v1";
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
}

#[cfg(test)]
static TEST_DEPOT_FAULTS: std::sync::Mutex<Vec<(PathBuf, DepotFaultPoint)>> =
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
        || import.total_len == 0
        || import.chunk_size != SELECTED_BLOB_CHUNK_SIZE
        || import.chunk_count == 0
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
        || import.total_len == 0
        || import.chunk_size != SELECTED_BLOB_CHUNK_SIZE
        || import.chunk_count == 0
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

impl ImportRecord {
    fn from_manifest(
        manifest: &BlobManifest,
        physical_lineage: Option<BlobPhysicalLineage>,
    ) -> Result<Self, StoreError> {
        if manifest.total_len() == 0
            || manifest.chunk_size() != SELECTED_BLOB_CHUNK_SIZE
            || manifest.chunk_count() == 0
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
pub struct BlobDepot<'a> {
    store: &'a Store,
    _guard: MutexGuard<'a, ()>,
    root: OwnedDirectory,
    active: Option<ActiveImport>,
    read_authorized_variant: Option<BlobVariantId>,
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
    pub(super) fn open(store: &'a Store) -> Result<Self, StoreError> {
        let guard = store
            .blob_depot_lock
            .lock()
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
            _guard: guard,
            root,
            active: None,
            read_authorized_variant: None,
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
            .lock()
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
            _guard: guard,
            root,
            active: None,
            read_authorized_variant: None,
        })
    }

    /// Opens an exact finalized variant for a capability-authorized read
    /// without a global Blob-table audit, write transaction, or root creation.
    pub(super) fn open_authenticated_read(
        store: &'a Store,
        completion: &BlobDepotCompletion,
    ) -> Result<AuthenticatedBlobReadDepot<'a>, StoreError> {
        let guard = store
            .blob_depot_lock
            .lock()
            .map_err(|_| blob_error(BlobStoreError::DepotIntegrity("depot lock is poisoned")))?;
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
            root,
            active: None,
            read_authorized_variant: Some(completion.variant_id),
        };
        let import = depot.exact_completion_import(&read, completion)?;
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
        if existing.is_none()
            && write.open_table(BLOB_CHUNKS)?.len()? >= self.store.blob_depot_limits.max_chunks
        {
            return Err(blob_error(BlobStoreError::DepotChunkLimitExceeded {
                current: write.open_table(BLOB_CHUNKS)?.len()?,
                limit: self.store.blob_depot_limits.max_chunks,
            }));
        }
        let previous = existing.unwrap_or_default();
        let next = mutation(previous)?;
        let previous_reserved = previous
            .expected
            .map(chunk_file_len)
            .transpose()?
            .unwrap_or(0);
        let next_reserved = next.expected.map(chunk_file_len).transpose()?.unwrap_or(0);
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
            let updated = without_previous
                .checked_add(next_reserved)
                .ok_or(StoreError::PayloadByteAccountingOverflow)?;
            if updated > self.store.blob_depot_limits.max_bytes {
                return Err(blob_error(BlobStoreError::DepotByteLimitExceeded {
                    current: durable_reserved,
                    incoming: next_reserved.saturating_sub(previous_reserved),
                    limit: self.store.blob_depot_limits.max_bytes,
                }));
            }
            depot.insert(DEPOT_RESERVED_FILE_BYTES, updated)?;
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
        #[cfg(test)]
        self.store
            .blob_depot_test_counters
            .begin_write_transactions
            .fetch_add(1, Ordering::Relaxed);
        let write = self.store.database.begin_write()?;
        enforce_live_write(&write)?;
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
                let current = write.open_table(BLOB_IMPORTS)?.len()?;
                if current >= self.store.blob_depot_limits.max_variants {
                    return Err(blob_error(BlobStoreError::DepotVariantLimitExceeded {
                        current,
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
        let read = self.store.database.begin_read()?;
        let depot = read.open_table(BLOB_DEPOT_METADATA)?;
        let current_bytes = depot
            .get(DEPOT_COMMITTED_FILE_BYTES)?
            .map_or(0, |value| value.value());
        let current_chunks = depot
            .get(DEPOT_COMMITTED_CHUNK_COUNT)?
            .map_or(0, |value| value.value());
        if current_bytes
            .checked_add(incoming)
            .ok_or(StoreError::PayloadByteAccountingOverflow)?
            > self.store.blob_depot_limits.max_bytes
        {
            return Err(blob_error(BlobStoreError::DepotByteLimitExceeded {
                current: current_bytes,
                incoming,
                limit: self.store.blob_depot_limits.max_bytes,
            }));
        }
        if current_chunks >= self.store.blob_depot_limits.max_chunks {
            return Err(blob_error(BlobStoreError::DepotChunkLimitExceeded {
                current: current_chunks,
                limit: self.store.blob_depot_limits.max_chunks,
            }));
        }
        drop(depot);
        drop(read);
        variant.write_atomic(&file_name, &encoded)?;

        let write = self.store.database.begin_write()?;
        enforce_live_write(&write)?;
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
        if durable_bytes
            .checked_add(incoming)
            .ok_or(StoreError::PayloadByteAccountingOverflow)?
            > self.store.blob_depot_limits.max_bytes
            || durable_chunks >= self.store.blob_depot_limits.max_chunks
        {
            return Err(blob_error(BlobStoreError::DepotIntegrity(
                "Blob depot quota changed after synchronized file publication",
            )));
        }
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

/// Returns only the audited import identity and authenticated lineage needed
/// to construct permanent lifecycle fences.
pub(super) fn audited_lifecycle_imports_write(
    write: &redb::WriteTransaction,
) -> Result<Vec<AuditedLifecycleImport>, StoreError> {
    let imports = write.open_table(BLOB_IMPORTS)?;
    imports
        .iter()?
        .map(|row| {
            let (key, value) = row?;
            lifecycle_import_from_record(
                parse_variant_id(key.value())?,
                decode_import(value.value())?,
            )
        })
        .collect()
}

/// Read-only counterpart to [`audited_lifecycle_imports_write`].
pub(super) fn audited_lifecycle_imports_read(
    read: &redb::ReadTransaction,
) -> Result<Vec<AuditedLifecycleImport>, StoreError> {
    let imports = read.open_table(BLOB_IMPORTS)?;
    imports
        .iter()?
        .map(|row| {
            let (key, value) = row?;
            lifecycle_import_from_record(
                parse_variant_id(key.value())?,
                decode_import(value.value())?,
            )
        })
        .collect()
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
    if write
        .list_multimap_tables()?
        .any(|table| blob_tables.contains(&table.name()))
    {
        return Err(blob_error(BlobStoreError::SchemaInvariant(
            "mission-scoped Blob schema has the wrong table kind",
        )));
    }
    let existing = write
        .list_tables()?
        .map(|table| table.name().to_owned())
        .collect::<BTreeSet<_>>();
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
    if legacy.iter().any(|table| !existing.contains(*table)) || !matches!(network_present, 0 | 4) {
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
        || (network_present == network.len()
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
    require_depot_owner_binding_write(write, store_path, backing_identity, owner_token)?;
    if expected == BlobStoreStats::default() {
        if let Some(root) = OwnedDirectory::open_root_if_present(store_path)? {
            match root.read_owner_marker()? {
                Some(_) => {
                    root.require_store_binding(store_path, backing_identity, owner_token)?;
                    reclaim_unmarked_artifacts(write, &root, &BTreeMap::new())?;
                }
                None => {
                    return Err(blob_error(BlobStoreError::DepotIntegrity(
                        "fixed Blob depot root is missing its owner marker",
                    )));
                }
            }
        }
        return Ok(());
    }
    let root = OwnedDirectory::open_root_if_present(store_path)?.ok_or_else(|| {
        blob_error(BlobStoreError::DepotIntegrity(
            "populated Blob depot root is missing",
        ))
    })?;
    root.require_store_binding(store_path, backing_identity, owner_token)?;
    let committed = committed_chunk_map_write(write)?;
    verify_all_marked_files_write(write, &root, &committed)?;
    reclaim_unmarked_artifacts(write, &root, &committed)
}

pub(crate) fn audit_depot_read(
    read: &redb::ReadTransaction,
    store_path: &Path,
    backing_identity: StoreBackingIdentity,
    owner_token: [u8; 32],
    expected: BlobStoreStats,
) -> Result<(), StoreError> {
    require_depot_owner_binding_read(read, store_path, backing_identity, owner_token)?;
    let Some(root) = OwnedDirectory::open_root_if_present(store_path)? else {
        if expected.variants == 0 {
            return Ok(());
        }
        return Err(blob_error(BlobStoreError::DepotIntegrity(
            "marked Blob chunks exist but the depot root is missing",
        )));
    };
    root.require_store_binding(store_path, backing_identity, owner_token)?;
    if expected.committed_chunks == 0 {
        return Ok(());
    }
    let committed = committed_chunk_map_read(read)?;
    verify_all_marked_files_read(read, &root, &committed)
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
    let read = store.database.begin_read()?;
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
    if levels
        .last()
        .and_then(|level| level.first())
        .is_none_or(|root| root != route.root())
    {
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

fn verify_all_marked_files_write(
    write: &redb::WriteTransaction,
    root: &OwnedDirectory,
    committed: &BTreeMap<BlobVariantId, Vec<(u64, ChunkState)>>,
) -> Result<(), StoreError> {
    for row in write.open_table(BLOB_IMPORTS)?.iter()? {
        let (_, value) = row?;
        let import = decode_import(value.value())?;
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
) -> Result<(), StoreError> {
    for row in read.open_table(BLOB_IMPORTS)?.iter()? {
        let (_, value) = row?;
        let import = decode_import(value.value())?;
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
) -> Result<(), StoreError> {
    let imports = write.open_table(BLOB_IMPORTS)?;
    let import_ids = imports
        .iter()?
        .map(|row| {
            let (key, _) = row?;
            parse_variant_id(key.value())
        })
        .collect::<Result<BTreeSet<_>, StoreError>>()?;
    drop(imports);
    for name in root.entry_names()? {
        if name == "." || name == ".." || name == DEPOT_OWNER_FILE {
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
        for child in variant.entry_names()? {
            if child == "." || child == ".." || committed.contains(&child) {
                continue;
            }
            if child.starts_with(TEMP_PREFIX) || child.ends_with(CHUNK_SUFFIX) {
                variant.remove_if_exists(&child, false)?;
            } else {
                return Err(blob_error(BlobStoreError::DepotIntegrity(
                    "Blob variant directory contains an unexpected artifact",
                )));
            }
        }
        variant.sync()?;
        if !import_ids.contains(&variant_id) && variant.entry_names()?.is_empty() {
            drop(variant);
            root.remove_if_exists(&name, true)?;
        }
    }
    root.sync()?;
    Ok(())
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
) -> Result<(), StoreError> {
    let manifest = plan.manifest();
    let incoming = ImportRecord::from_manifest(manifest, Some(plan.physical_lineage()))?;
    if incoming.total_len > MAX_NETWORK_BLOB_BYTES
        || incoming.chunk_count > MAX_NETWORK_BLOB_CHUNKS
        || usize::try_from(incoming.chunk_count).ok() != Some(plan.chunk_records().len())
    {
        return Err(blob_error(BlobStoreError::NetworkBlobTooLarge {
            total_len: incoming.total_len,
            chunk_count: incoming.chunk_count,
        }));
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

    let current_variants = write.open_table(BLOB_IMPORTS)?.len()?;
    if insert_import && current_variants >= limits.max_variants {
        return Err(blob_error(BlobStoreError::DepotVariantLimitExceeded {
            current: current_variants,
            limit: limits.max_variants,
        }));
    }
    let current_chunks = write.open_table(BLOB_CHUNKS)?.len()?;
    if current_chunks
        .checked_add(missing_chunks)
        .ok_or(StoreError::ItemCountAccountingOverflow)?
        > limits.max_chunks
    {
        return Err(blob_error(BlobStoreError::DepotChunkLimitExceeded {
            current: current_chunks,
            limit: limits.max_chunks,
        }));
    }
    let current_reserved = write
        .open_table(BLOB_DEPOT_METADATA)?
        .get(DEPOT_RESERVED_FILE_BYTES)?
        .map(|value| value.value())
        .ok_or_else(|| {
            blob_error(BlobStoreError::SchemaInvariant(
                "Blob depot reserved-byte counter is missing",
            ))
        })?;
    if current_reserved
        .checked_add(incoming_reserved)
        .ok_or(StoreError::PayloadByteAccountingOverflow)?
        > limits.max_bytes
    {
        return Err(blob_error(BlobStoreError::DepotByteLimitExceeded {
            current: current_reserved,
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
            current_reserved
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
    let canonical_chunk_count = total_len
        .checked_sub(1)
        .map(|last| 1 + last / u64::from(SELECTED_BLOB_CHUNK_SIZE));
    let metadata_valid = CoreBlobMetadata::new(media_type.clone(), schema_id.clone()).is_ok();
    if total_len == 0
        || chunk_size != SELECTED_BLOB_CHUNK_SIZE
        || chunk_count == 0
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

struct OwnedDirectory {
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

impl OwnedDirectory {
    fn open_root_if_present(store_path: &Path) -> Result<Option<Self>, StoreError> {
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

    fn require_store_binding(
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
        match std::fs::metadata(&path) {
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
    fn open_child_directory(&self, name: &str, create: bool) -> Result<Self, StoreError> {
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
    fn open_child_directory(&self, name: &str, create: bool) -> Result<Self, StoreError> {
        let path = self.path.join(name);
        match std::fs::metadata(&path) {
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

    #[cfg(unix)]
    fn write_atomic(&self, final_name: &str, bytes: &[u8]) -> Result<(), StoreError> {
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
    fn write_atomic(&self, final_name: &str, bytes: &[u8]) -> Result<(), StoreError> {
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
            } else {
                blob_error(BlobStoreError::Io(error.into()))
            }
        })?;
        let mut file = File::from(descriptor);
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
    fn entry_names(&self) -> Result<Vec<String>, StoreError> {
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
    fn entry_names(&self) -> Result<Vec<String>, StoreError> {
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
    fn remove_if_exists(&self, name: &str, directory: bool) -> Result<(), StoreError> {
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

    #[cfg(not(unix))]
    fn remove_if_exists(&self, name: &str, directory: bool) -> Result<(), StoreError> {
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

    fn sync(&self) -> Result<(), StoreError> {
        #[cfg(unix)]
        self.file
            .sync_all()
            .map_err(|error| blob_error(BlobStoreError::Io(error)))?;
        #[cfg(not(unix))]
        File::open(&self.path)?.sync_all()?;
        Ok(())
    }
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
