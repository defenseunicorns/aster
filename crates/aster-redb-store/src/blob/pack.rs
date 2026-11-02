//! Sequential encrypted stream pack with alternating durable checkpoints.

use aster_mesh::{
    BLOB_STREAM_SEGMENT_BYTES, BLOB_STREAM_SEGMENT_ENCODED_OVERHEAD_BYTES, BlobId,
    BlobPublicationStreamId, BlobStreamCheckpoint, BlobStreamFrontier, BlobStreamOpen,
    BlobStreamSegmentLeaves, BlobStreamSubtree, EncryptedBlobStreamSegment, MAX_BLOB_CHUNKS,
    SELECTED_BLOB_CHUNK_SIZE, VerifiedBlobStreamFinalCommitment,
};
use sha2::digest::common::hazmat::{SerializableState, SerializedState};
use sha2::{Digest, Sha256};
use std::{
    error::Error,
    fmt::{self, Display, Formatter},
    fs::{self, File, OpenOptions},
    io::{Read, Seek, SeekFrom, Write},
    path::{Path, PathBuf},
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
};

use super::depot::{OwnedDirectory, open_blob_pack_root};
use super::{BlobStoreError, blob_error};
use crate::{Store, StoreError};

const PACK_MAGIC: &[u8; 8] = b"ASTRPK02";
const CHECKPOINT_MAGIC: &[u8; 8] = b"ASTRCP02";
const PACK_VERSION: u16 = 2;
const CHECKPOINT_VERSION: u16 = 3;
const PACK_FILE: &str = "segments.pack";
const UPLOAD_DIGEST_FILE: &str = "canonical-digests-v1.bin";
const UPLOAD_DIGEST_MAGIC: &[u8; 8] = b"ASTRCD01";
const UPLOAD_DIGEST_VERSION: u16 = 1;
pub(super) const UPLOAD_DIGEST_HEADER_LEN: u64 = 8 + 2 + 32 + 32 + 8 + 4;
const SHA256_SERIALIZED_STATE_LEN: usize = 105;
const CHECKPOINT_ZERO: &str = "checkpoint.0";
const CHECKPOINT_ONE: &str = "checkpoint.1";
const COMPLETION_FILE: &str = "completion.v2";
const COMPLETION_MAGIC: &[u8; 8] = b"ASTRCM02";
const COMPLETION_VERSION: u16 = 2;
pub(super) const PACK_HEADER_LEN: u64 = 8 + 2 + 32 + 32 + 8;
const MAX_RECORD_BYTES: usize = 2 * 1024 * 1024;
const PACK_FIXED_RESERVATION_BYTES: u64 = 64 * 1024;
const UPLOAD_MARKER: &str = ".aster-upload-v1";
const UPLOAD_MARKER_MAGIC: &[u8; 8] = b"ASTRUM01";
const UPLOAD_CLEANUP_MAGIC: &[u8; 8] = b"ASTRUC01";
const UPLOAD_CLEANUP_PREFIX: &str = ".aster-upload-cleanup-";
const UPLOAD_RESERVATION_MAGIC: &[u8; 8] = b"ASTRUR01";
const UPLOAD_RESERVATION_PREFIX: &str = ".aster-upload-reservation-";
const PACK_TEMP_PREFIX: &str = ".aster-blob-tmp-";
const PACK_DIRECTORY: &str = "stream-packs-v2";
static PACK_TEMP_SEQUENCE: AtomicU64 = AtomicU64::new(1);

#[cfg(test)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum BlobPackFaultPoint {
    DataSynced,
    CheckpointZeroSynced,
    CheckpointOneSynced,
    CleanupEntryRemoved,
    CleanupDurable,
}

#[cfg(test)]
static TEST_PACK_FAULTS: std::sync::Mutex<Vec<(PathBuf, BlobPackFaultPoint)>> =
    std::sync::Mutex::new(Vec::new());

#[cfg(test)]
pub(super) fn inject_test_fault(root: &PinnedBlobPackRoot, point: BlobPackFaultPoint) {
    TEST_PACK_FAULTS
        .lock()
        .expect("Blob pack test fault lock")
        .push((root.directory.path().to_owned(), point));
}

#[cfg(test)]
fn maybe_inject_fault(path: &Path, point: BlobPackFaultPoint) -> Result<(), BlobPackError> {
    let mut faults = TEST_PACK_FAULTS
        .lock()
        .map_err(|_| BlobPackError::Invalid("Blob pack test fault lock is poisoned"))?;
    if let Some(index) = faults.iter().position(|(expected, expected_point)| {
        (expected == path || path.parent() == Some(expected.as_path())) && *expected_point == point
    }) {
        faults.swap_remove(index);
        return Err(BlobPackError::Io(std::io::Error::other(
            "injected Blob pack crash boundary",
        )));
    }
    Ok(())
}

pub(crate) fn reserved_upload_pack_bytes(total_len: u64) -> Result<u64, StoreError> {
    let segments = total_len
        .checked_add(BLOB_STREAM_SEGMENT_BYTES as u64 - 1)
        .ok_or(StoreError::PayloadByteAccountingOverflow)?
        / BLOB_STREAM_SEGMENT_BYTES as u64;
    let overhead = segments
        .checked_mul(BLOB_STREAM_SEGMENT_ENCODED_OVERHEAD_BYTES as u64 + 4)
        .ok_or(StoreError::PayloadByteAccountingOverflow)?;
    total_len
        .checked_add(overhead)
        .and_then(|value| value.checked_add(PACK_FIXED_RESERVATION_BYTES))
        .ok_or(StoreError::PayloadByteAccountingOverflow)
}

pub(crate) fn upload_digest_reserved_bytes(total_len: u64) -> Result<u64, StoreError> {
    let count = total_len
        .checked_add(u64::from(SELECTED_BLOB_CHUNK_SIZE) - 1)
        .ok_or(StoreError::PayloadByteAccountingOverflow)?
        / u64::from(SELECTED_BLOB_CHUNK_SIZE);
    count
        .checked_mul(32)
        .and_then(|bytes| bytes.checked_add(UPLOAD_DIGEST_HEADER_LEN))
        .ok_or(StoreError::PayloadByteAccountingOverflow)
}

#[derive(Debug)]
pub enum BlobPackError {
    Io(std::io::Error),
    Store(StoreError),
    Invalid(&'static str),
}

impl Display for BlobPackError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(error) => Display::fmt(error, formatter),
            Self::Store(error) => Display::fmt(error, formatter),
            Self::Invalid(message) => formatter.write_str(message),
        }
    }
}

impl Error for BlobPackError {}

impl From<std::io::Error> for BlobPackError {
    fn from(error: std::io::Error) -> Self {
        Self::Io(error)
    }
}

impl From<StoreError> for BlobPackError {
    fn from(error: StoreError) -> Self {
        Self::Store(error)
    }
}

fn acquire_pack_writer_lock(data: &File) -> Result<(), BlobPackError> {
    match data.try_lock() {
        Ok(()) => Ok(()),
        Err(std::fs::TryLockError::WouldBlock) => Err(BlobPackError::Invalid(
            "another Blob pack writer already owns this pack",
        )),
        Err(std::fs::TryLockError::Error(error)) => Err(error.into()),
    }
}

/// Store-owned capability for Blob pack placement. The directory remains
/// descriptor-pinned on Unix so stream reopen never follows a replaced path.
#[doc(hidden)]
pub struct PinnedBlobPackRoot {
    directory: OwnedDirectory,
    authority: Arc<()>,
}

impl PinnedBlobPackRoot {
    pub fn open(store: &Store) -> Result<Self, StoreError> {
        Ok(Self {
            directory: open_blob_pack_root(store)?,
            authority: Arc::clone(&store.blob_completion_authority),
        })
    }

    #[cfg(test)]
    pub(super) fn test_upload_path(&self, identity: &BlobPackIdentity) -> PathBuf {
        self.directory
            .path()
            .join(hex32(identity.upload_id.as_bytes()))
    }

    fn stream_id(
        &self,
        stream_id: BlobPublicationStreamId,
        create: bool,
    ) -> Result<BlobPackRoot, BlobPackError> {
        Ok(BlobPackRoot::Pinned(
            self.directory
                .open_child_directory(&hex32(stream_id.as_bytes()), create)?,
            Arc::clone(&self.authority),
        ))
    }

    fn stream(&self, open: &BlobStreamOpen, create: bool) -> Result<BlobPackRoot, BlobPackError> {
        self.stream_id(open.stream_id(), create)
    }

    fn upload(
        &self,
        identity: &BlobPackIdentity,
        create: bool,
    ) -> Result<BlobPackRoot, BlobPackError> {
        let root = self.stream_id(identity.upload_id, create)?;
        let BlobPackRoot::Pinned(directory, _) = &root else {
            unreachable!("pinned upload root")
        };
        let expected = encode_upload_marker(*identity);
        match directory.read_private_file_if_present(UPLOAD_MARKER, 82)? {
            Some(marker) if marker == expected => {}
            Some(_) => return Err(BlobPackError::Invalid("Blob upload pack marker mismatch")),
            None if create => directory.write_atomic(UPLOAD_MARKER, &expected)?,
            None => return Err(BlobPackError::Invalid("Blob upload pack marker is missing")),
        }
        Ok(root)
    }
}

fn encode_upload_marker(identity: BlobPackIdentity) -> [u8; 80] {
    let mut marker = [0_u8; 80];
    marker[..8].copy_from_slice(UPLOAD_MARKER_MAGIC);
    marker[8..40].copy_from_slice(identity.upload_id.as_bytes());
    marker[40..72].copy_from_slice(&identity.request_digest);
    marker[72..].copy_from_slice(&identity.total_len.to_be_bytes());
    marker
}

fn cleanup_marker_name(identity: BlobPackIdentity) -> String {
    format!(
        "{UPLOAD_CLEANUP_PREFIX}{}",
        hex32(identity.upload_id.as_bytes())
    )
}

fn encode_cleanup_marker(identity: BlobPackIdentity) -> [u8; 80] {
    let mut marker = encode_upload_marker(identity);
    marker[..8].copy_from_slice(UPLOAD_CLEANUP_MAGIC);
    marker
}

fn reservation_marker_name(identity: BlobPackIdentity) -> String {
    format!(
        "{UPLOAD_RESERVATION_PREFIX}{}",
        hex32(identity.upload_id.as_bytes())
    )
}

fn encode_reservation_marker(identity: BlobPackIdentity) -> [u8; 80] {
    let mut marker = encode_upload_marker(identity);
    marker[..8].copy_from_slice(UPLOAD_RESERVATION_MAGIC);
    marker
}

fn decode_reservation_marker(marker: &[u8]) -> Result<BlobPackIdentity, BlobPackError> {
    if marker.len() != 80 || &marker[..8] != UPLOAD_RESERVATION_MAGIC {
        return Err(BlobPackError::Invalid(
            "Blob upload reservation marker is invalid",
        ));
    }
    let mut upload_marker = marker.to_vec();
    upload_marker[..8].copy_from_slice(UPLOAD_MARKER_MAGIC);
    decode_upload_marker(&upload_marker)
}

pub(super) fn stage_upload_pack_reservation(
    root: &PinnedBlobPackRoot,
    identity: &BlobPackIdentity,
) -> Result<(), BlobPackError> {
    // The filename is keyed by stream ID, while its contents bind the entire
    // physical identity. Reject a conflicting existing directory before making
    // recovery authority durable. The caller holds the Store depot write lock.
    if let Some(directory) = root
        .directory
        .open_child_directory_if_present(&hex32(identity.upload_id.as_bytes()))?
    {
        let marker = directory.read_private_file_if_present(UPLOAD_MARKER, 80)?;
        if marker
            .as_deref()
            .is_some_and(|marker| marker != encode_upload_marker(*identity))
        {
            return Err(BlobPackError::Invalid("Blob upload pack marker mismatch"));
        }
    }
    let name = reservation_marker_name(*identity);
    let expected = encode_reservation_marker(*identity);
    match root.directory.read_private_file_if_present(&name, 80)? {
        Some(marker) if marker == expected => Ok(()),
        Some(_) => Err(BlobPackError::Invalid(
            "Blob upload reservation marker mismatch",
        )),
        None => root
            .directory
            .write_atomic(&name, &expected)
            .map_err(Into::into),
    }
}

pub(super) fn finish_upload_pack_reservation(
    root: &PinnedBlobPackRoot,
    identity: &BlobPackIdentity,
) -> Result<(), BlobPackError> {
    root.directory
        .remove_if_exists(&reservation_marker_name(*identity), false)?;
    Ok(())
}

fn decode_cleanup_marker(marker: &[u8]) -> Result<BlobPackIdentity, BlobPackError> {
    if marker.len() != 80 || &marker[..8] != UPLOAD_CLEANUP_MAGIC {
        return Err(BlobPackError::Invalid(
            "Blob upload cleanup marker is invalid",
        ));
    }
    let mut upload_marker = marker.to_vec();
    upload_marker[..8].copy_from_slice(UPLOAD_MARKER_MAGIC);
    decode_upload_marker(&upload_marker)
}

pub(super) fn stage_upload_pack_cleanup(
    root: &PinnedBlobPackRoot,
    identity: &BlobPackIdentity,
) -> Result<(), BlobPackError> {
    let name = cleanup_marker_name(*identity);
    let expected = encode_cleanup_marker(*identity);
    match root.directory.read_private_file_if_present(&name, 80)? {
        Some(marker) if marker == expected => Ok(()),
        Some(_) => Err(BlobPackError::Invalid(
            "Blob upload cleanup marker mismatch",
        )),
        None => root
            .directory
            .write_atomic(&name, &expected)
            .map_err(Into::into),
    }
}

/// The existing marker is also a fence against reopening a retiring writer.
pub(super) fn upload_cleanup_started(
    root: &PinnedBlobPackRoot,
    identity: &BlobPackIdentity,
) -> Result<bool, BlobPackError> {
    match root
        .directory
        .read_private_file_if_present(&cleanup_marker_name(*identity), 80)?
    {
        Some(marker) if marker == encode_cleanup_marker(*identity) => Ok(true),
        Some(_) => Err(BlobPackError::Invalid(
            "Blob upload cleanup marker mismatch",
        )),
        None => Ok(false),
    }
}

/// One physical entry per turn, with no payload reads or unbounded directory
/// scan. The caller precharges 1024 bytes for markers and at most two names,
/// holds the depot writer lock and retains the exact durable upload row until
/// this returns complete. A complete unit reserves its one file for removing
/// the cleanup marker after the redb commit.
pub(super) fn remove_upload_pack_maintenance_unit(
    root: &PinnedBlobPackRoot,
    identity: &BlobPackIdentity,
) -> Result<(u64, bool), BlobPackError> {
    let started = upload_cleanup_started(root, identity)?;
    let name = hex32(identity.upload_id.as_bytes());
    let directory = root.directory.open_child_directory_if_present(&name)?;
    let mut writer_guard = None;
    if let Some(directory) = &directory {
        let marker = directory.read_private_file_if_present(UPLOAD_MARKER, 80)?;
        if marker.as_deref() != Some(encode_upload_marker(*identity).as_slice())
            && !(started && marker.is_none() && directory.entry_names_bounded(1)?.is_empty())
        {
            return Err(BlobPackError::Invalid("Blob upload pack marker mismatch"));
        }
        if let Some(data) = directory.open_private_rw_file_if_present(PACK_FILE)? {
            match data.try_lock() {
                Ok(()) => writer_guard = Some(data),
                Err(std::fs::TryLockError::WouldBlock) => return Ok((0, false)),
                Err(std::fs::TryLockError::Error(error)) => return Err(error.into()),
            }
        }
    }
    if !started {
        stage_upload_pack_cleanup(root, identity)?;
        return Ok((1, false));
    }
    let Some(directory) = directory else {
        #[cfg(test)]
        maybe_inject_fault(root.directory.path(), BlobPackFaultPoint::CleanupDurable)?;
        return Ok((1, true));
    };
    let entries = directory.entry_names_bounded(2)?;
    if let Some(entry) = entries.iter().find(|name| name.as_str() != UPLOAD_MARKER) {
        if entry != PACK_FILE
            && entry != UPLOAD_DIGEST_FILE
            && entry != CHECKPOINT_ZERO
            && entry != CHECKPOINT_ONE
            && entry != COMPLETION_FILE
            && !entry.starts_with(PACK_TEMP_PREFIX)
        {
            return Err(BlobPackError::Invalid(
                "Blob upload pack contains a foreign artifact",
            ));
        }
        directory.remove_if_exists(entry, false)?;
        #[cfg(test)]
        maybe_inject_fault(
            root.directory.path(),
            BlobPackFaultPoint::CleanupEntryRemoved,
        )?;
    } else if !entries.is_empty() {
        directory.remove_if_exists(UPLOAD_MARKER, false)?;
    } else {
        drop(directory);
        root.directory.remove_if_exists(&name, true)?;
    }
    drop(writer_guard);
    Ok((1, false))
}

pub(super) fn finish_upload_pack_cleanup(
    root: &PinnedBlobPackRoot,
    identity: &BlobPackIdentity,
) -> Result<(), BlobPackError> {
    if let Some(marker) = root
        .directory
        .read_private_file_if_present(&cleanup_marker_name(*identity), 80)?
        && marker != encode_cleanup_marker(*identity)
    {
        return Err(BlobPackError::Invalid(
            "Blob upload cleanup marker mismatch",
        ));
    }
    root.directory
        .remove_if_exists(&cleanup_marker_name(*identity), false)?;
    Ok(())
}

fn decode_upload_marker(marker: &[u8]) -> Result<BlobPackIdentity, BlobPackError> {
    if marker.len() != 80 || &marker[..8] != UPLOAD_MARKER_MAGIC {
        return Err(BlobPackError::Invalid("Blob upload pack marker is invalid"));
    }
    let upload_id = BlobPublicationStreamId::from_bytes(
        marker[8..40]
            .try_into()
            .map_err(|_| BlobPackError::Invalid("Blob upload pack marker is invalid"))?,
    )
    .map_err(|_| BlobPackError::Invalid("Blob upload pack marker is invalid"))?;
    let request_digest = marker[40..72]
        .try_into()
        .map_err(|_| BlobPackError::Invalid("Blob upload pack marker is invalid"))?;
    let total_len = u64::from_be_bytes(
        marker[72..80]
            .try_into()
            .map_err(|_| BlobPackError::Invalid("Blob upload pack marker is invalid"))?,
    );
    Ok(BlobPackIdentity::new(upload_id, request_digest, total_len))
}

/// Removes exactly one authenticated provisional-upload pack. Every unlink is
/// directory-synchronized, and callers retain the redb reservation until this
/// function has durably removed the final directory entry.
pub(super) fn remove_upload_pack(
    root: &PinnedBlobPackRoot,
    identity: &BlobPackIdentity,
) -> Result<(), BlobPackError> {
    remove_upload_pack_directory(&root.directory, identity)?;
    #[cfg(test)]
    maybe_inject_fault(root.directory.path(), BlobPackFaultPoint::CleanupDurable)?;
    Ok(())
}

/// Idempotently removes a lifecycle-owned pack directory. The exact identity
/// comes from authenticated deletion evidence; absence is valid after a crash
/// between durable unlink and redb manifest finalization.
pub(super) fn remove_lifecycle_pack(
    store_path: &Path,
    backing_identity: crate::StoreBackingIdentity,
    owner_token: [u8; 32],
    identity: &BlobPackIdentity,
) -> Result<(), StoreError> {
    let Some(depot_root) = OwnedDirectory::open_root_if_present(store_path)? else {
        return Ok(());
    };
    depot_root.require_store_binding(store_path, backing_identity, owner_token)?;
    let Some(pack_root) = depot_root.open_child_directory_if_present(PACK_DIRECTORY)? else {
        depot_root.sync()?;
        return Ok(());
    };
    remove_upload_pack_directory(&pack_root, identity)?;
    pack_root.sync()?;
    #[cfg(test)]
    maybe_inject_fault(pack_root.path(), BlobPackFaultPoint::CleanupDurable)
        .map_err(pack_marker_store_error)?;
    Ok(())
}

fn remove_upload_pack_directory(
    parent: &OwnedDirectory,
    identity: &BlobPackIdentity,
) -> Result<(), StoreError> {
    let name = hex32(identity.upload_id.as_bytes());
    let Some(directory) = parent.open_child_directory_if_present(&name)? else {
        return Ok(());
    };
    let entries = directory.entry_names_reclaiming_atomic_temporaries(true)?;
    let Some(marker) = directory.read_private_file_if_present(UPLOAD_MARKER, 80)? else {
        if entries.is_empty() {
            drop(directory);
            parent.remove_if_exists(&name, true)?;
            return Ok(());
        }
        return Err(blob_error(BlobStoreError::DepotIntegrity(
            "Blob upload pack marker is missing",
        )));
    };
    if decode_upload_marker(&marker).map_err(pack_marker_store_error)? != *identity {
        return Err(blob_error(BlobStoreError::DepotIntegrity(
            "Blob upload pack marker mismatch",
        )));
    }
    for entry in &entries {
        if entry != PACK_FILE
            && entry != UPLOAD_DIGEST_FILE
            && entry != CHECKPOINT_ZERO
            && entry != CHECKPOINT_ONE
            && entry != COMPLETION_FILE
            && entry != UPLOAD_MARKER
            && !entry.starts_with(PACK_TEMP_PREFIX)
        {
            return Err(blob_error(BlobStoreError::DepotIntegrity(
                "Blob upload pack contains a foreign artifact",
            )));
        }
    }
    // The marker is the durable cleanup authority. Remove every other entry
    // first; a crash while doing so leaves the marker for exact retry. Once
    // only the marker remains, removing it leaves an empty directory that the
    // same exact identity may safely finish deleting on retry.
    for entry in entries
        .iter()
        .filter(|entry| entry.as_str() != UPLOAD_MARKER)
    {
        directory.remove_if_exists(entry, false)?;
        #[cfg(test)]
        maybe_inject_fault(parent.path(), BlobPackFaultPoint::CleanupEntryRemoved)
            .map_err(pack_marker_store_error)?;
    }
    directory.remove_if_exists(UPLOAD_MARKER, false)?;
    drop(directory);
    parent.remove_if_exists(&name, true)?;
    Ok(())
}

fn pack_marker_store_error(error: BlobPackError) -> StoreError {
    match error {
        BlobPackError::Store(error) => error,
        BlobPackError::Io(error) => blob_error(BlobStoreError::Io(error)),
        BlobPackError::Invalid(message) => blob_error(BlobStoreError::DepotIntegrity(message)),
    }
}

#[derive(Clone, Debug)]
pub(super) struct ExpectedBlobUploadPack {
    pub(super) identity: BlobPackIdentity,
    pub(super) checkpoint: Option<BlobPackCheckpoint>,
    /// Deletion owns the durable identity while the physical directory may
    /// already be absent after a crash between unlink and redb finalization.
    pub(super) may_be_absent: bool,
    /// A durable upload completion selected another pack. Remove only this
    /// redundant candidate, keeping its pending semantic publication intact.
    pub(super) discard_candidate: bool,
}

fn audit_expected_upload_pack(
    directory: &OwnedDirectory,
    expected: &ExpectedBlobUploadPack,
) -> Result<(), StoreError> {
    let mut data = directory
        .open_private_read_file_if_present(PACK_FILE)?
        .ok_or_else(|| {
            blob_error(BlobStoreError::DepotIntegrity(
                "Blob upload pack data is unavailable",
            ))
        })?;
    validate_header(&mut data, expected.identity).map_err(pack_marker_store_error)?;
    let data_len = data
        .metadata()
        .map_err(BlobStoreError::Io)
        .map_err(blob_error)?
        .len();
    let mut checkpoints = Vec::new();
    for name in [CHECKPOINT_ZERO, CHECKPOINT_ONE] {
        let Some(bytes) = directory.read_private_file_if_present(name, 16 * 1024)? else {
            continue;
        };
        let Ok(checkpoint) = BlobPackCheckpoint::decode(&bytes) else {
            continue;
        };
        if checkpoint.open_digest == expected.identity.request_digest
            && checkpoint.stream_id == expected.identity.upload_id
            && checkpoint.total_len == expected.identity.total_len
            && checkpoint.pack_len <= data_len
        {
            checkpoints.push(checkpoint);
        }
    }
    let projected = match expected.checkpoint.as_ref() {
        Some(projected) => checkpoints.iter().find(|candidate| *candidate == projected),
        None => checkpoints.iter().find(|candidate| {
            candidate.next_index() == 0
                && candidate.plaintext_offset() == 0
                && candidate.pack_len() == PACK_HEADER_LEN
        }),
    }
    .ok_or_else(|| {
        blob_error(BlobStoreError::DepotIntegrity(
            "store-projected Blob upload checkpoint is unavailable",
        ))
    })?;
    match projected.upload_digests.as_ref() {
        Some(_) => {
            let mut digests = directory
                .open_private_read_file_if_present(UPLOAD_DIGEST_FILE)?
                .ok_or_else(|| {
                    blob_error(BlobStoreError::DepotIntegrity(
                        "Blob upload digest artifact is unavailable",
                    ))
                })?;
            validate_upload_digest_file(&mut digests, expected.identity, projected)
                .map_err(pack_marker_store_error)?;
        }
        None => {
            // No digest projection means this file has no authority. Opening
            // it still enforces the private regular-file/no-follow contract;
            // genuine v2 resume may atomically replace a torn artifact.
            _ = directory.open_private_read_file_if_present(UPLOAD_DIGEST_FILE)?;
        }
    }
    data.seek(SeekFrom::Start(PACK_HEADER_LEN))
        .map_err(BlobStoreError::Io)
        .map_err(blob_error)?;
    let mut index = 0_u64;
    let mut plaintext_offset = 0_u64;
    let mut frontier = BlobStreamFrontier::new();
    let mut projected_verified = projected.next_index() == 0
        && projected.pack_len() == PACK_HEADER_LEN
        && projected.frontier().ciphertext_commitment()
            == frontier.checkpoint().ciphertext_commitment();
    // Bytes after the store-authoritative checkpoint are an unacknowledged
    // append, which may have torn anywhere in its record. Resume truncates
    // that tail; even a read-only audit must not give it durable authority.
    while data
        .stream_position()
        .map_err(BlobStoreError::Io)
        .map_err(blob_error)?
        < projected.pack_len()
    {
        let mut length = [0; 4];
        data.read_exact(&mut length)
            .map_err(BlobStoreError::Io)
            .map_err(blob_error)?;
        let length = u32::from_be_bytes(length) as usize;
        if length == 0 || length > MAX_RECORD_BYTES {
            return Err(blob_error(BlobStoreError::DepotIntegrity(
                "Blob upload pack contains an invalid record length",
            )));
        }
        let mut encoded = vec![0; length];
        data.read_exact(&mut encoded)
            .map_err(BlobStoreError::Io)
            .map_err(blob_error)?;
        let segment = EncryptedBlobStreamSegment::decode(&encoded).map_err(|_| {
            blob_error(BlobStoreError::DepotIntegrity(
                "Blob upload pack contains an invalid segment",
            ))
        })?;
        let header = segment.header();
        if header.index() != index
            || header.stream_id() != expected.identity.upload_id.as_bytes()
            || header.open_digest() != &expected.identity.request_digest
            || header.offset() != plaintext_offset
            || header.total_len() != expected.identity.total_len
        {
            return Err(blob_error(BlobStoreError::DepotIntegrity(
                "Blob upload pack segment differs from its durable checkpoint",
            )));
        }
        plaintext_offset = plaintext_offset
            .checked_add(u64::from(header.plaintext_len()))
            .ok_or(StoreError::PayloadByteAccountingOverflow)?;
        frontier
            .append(BlobStreamSubtree::leaf(
                index,
                segment.ciphertext_audit_leaves(),
            ))
            .map_err(|_| {
                blob_error(BlobStoreError::DepotIntegrity(
                    "Blob upload pack ciphertext frontier is invalid",
                ))
            })?;
        index += 1;
        if index == projected.next_index() {
            let boundary = data
                .stream_position()
                .map_err(BlobStoreError::Io)
                .map_err(blob_error)?;
            projected_verified = boundary == projected.pack_len()
                && plaintext_offset == projected.plaintext_offset()
                && frontier.checkpoint().ciphertext_commitment()
                    == projected.frontier().ciphertext_commitment();
        }
    }
    if !projected_verified || plaintext_offset > expected.identity.total_len {
        return Err(blob_error(BlobStoreError::DepotIntegrity(
            "Blob upload pack content differs from its durable checkpoint",
        )));
    }
    Ok(())
}

fn audit_upload_packs(
    depot_root: &OwnedDirectory,
    expected: &[ExpectedBlobUploadPack],
    recover: bool,
) -> Result<Vec<BlobPackIdentity>, StoreError> {
    let Some(pack_root) = depot_root.open_child_directory_if_present(PACK_DIRECTORY)? else {
        return if expected.iter().all(|expected| expected.may_be_absent) {
            Ok(Vec::new())
        } else {
            Err(blob_error(BlobStoreError::DepotIntegrity(
                "durable Blob upload pack root is missing",
            )))
        };
    };
    let entries = pack_root.entry_names_reclaiming_atomic_temporaries(recover)?;
    let mut cleanup = std::collections::BTreeMap::new();
    for name in entries
        .iter()
        .filter(|name| name.starts_with(UPLOAD_CLEANUP_PREFIX))
    {
        let marker = pack_root
            .read_private_file_if_present(name, 80)?
            .ok_or_else(|| {
                blob_error(BlobStoreError::DepotIntegrity(
                    "Blob upload cleanup marker disappeared during audit",
                ))
            })?;
        let identity = decode_cleanup_marker(&marker).map_err(pack_marker_store_error)?;
        if *name != cleanup_marker_name(identity)
            || cleanup
                .insert(*identity.upload_id.as_bytes(), identity)
                .is_some()
        {
            return Err(blob_error(BlobStoreError::DepotIntegrity(
                "Blob upload cleanup marker identity is inconsistent",
            )));
        }
    }
    let mut reservations = std::collections::BTreeMap::new();
    for name in entries
        .iter()
        .filter(|name| name.starts_with(UPLOAD_RESERVATION_PREFIX))
    {
        let marker = pack_root
            .read_private_file_if_present(name, 80)?
            .ok_or_else(|| {
                blob_error(BlobStoreError::DepotIntegrity(
                    "Blob upload reservation marker disappeared during audit",
                ))
            })?;
        let identity = decode_reservation_marker(&marker).map_err(pack_marker_store_error)?;
        if *name != reservation_marker_name(identity)
            || reservations
                .insert(*identity.upload_id.as_bytes(), identity)
                .is_some()
        {
            return Err(blob_error(BlobStoreError::DepotIntegrity(
                "Blob upload reservation marker identity is inconsistent",
            )));
        }
    }
    let mut seen = std::collections::BTreeSet::new();
    let mut completed = Vec::new();
    for name in entries.into_iter().filter(|name| {
        !name.starts_with(UPLOAD_CLEANUP_PREFIX) && !name.starts_with(UPLOAD_RESERVATION_PREFIX)
    }) {
        let directory = pack_root.open_child_directory(&name, false)?;
        let directory_entries = directory.entry_names_reclaiming_atomic_temporaries(recover)?;
        let Some(marker) = directory.read_private_file_if_present(UPLOAD_MARKER, 80)? else {
            // mkdir precedes the initial marker; cleanup unlinks the marker
            // before rmdir. Only an empty directory and exact external
            // transition authority can identify either interrupted operation.
            let durable = expected
                .iter()
                .find(|expected| name == hex32(expected.identity.upload_id.as_bytes()));
            let transition = cleanup
                .values()
                .chain(reservations.values())
                .find(|identity| name == hex32(identity.upload_id.as_bytes()));
            let identity = transition
                .copied()
                .or_else(|| {
                    durable
                        .filter(|pack| pack.may_be_absent)
                        .map(|pack| pack.identity)
                })
                .ok_or_else(|| {
                    blob_error(BlobStoreError::DepotIntegrity(
                        "Blob upload pack marker is missing",
                    ))
                })?;
            let cleaning = cleanup.get(identity.upload_id.as_bytes()) == Some(&identity);
            let reserving = reservations.get(identity.upload_id.as_bytes()) == Some(&identity);
            if !directory_entries.is_empty()
                || durable.is_some_and(|pack| pack.identity != identity)
                || cleanup
                    .get(identity.upload_id.as_bytes())
                    .is_some_and(|marker| marker != &identity)
                || reservations
                    .get(identity.upload_id.as_bytes())
                    .is_some_and(|marker| marker != &identity)
                || !(cleaning
                    || (reserving && durable.is_none())
                    || durable.is_some_and(|pack| pack.may_be_absent))
            {
                return Err(blob_error(BlobStoreError::DepotIntegrity(
                    "markerless Blob upload directory lacks exact transition authority",
                )));
            }
            if recover {
                drop(directory);
                remove_upload_pack_directory(&pack_root, &identity)?;
            }
            if durable.is_some() {
                seen.insert(*identity.upload_id.as_bytes());
                if cleaning {
                    completed.push(identity);
                }
            }
            continue;
        };
        let identity = decode_upload_marker(&marker).map_err(pack_marker_store_error)?;
        if name != hex32(identity.upload_id.as_bytes()) {
            return Err(blob_error(BlobStoreError::DepotIntegrity(
                "Blob upload pack directory differs from its marker",
            )));
        }
        if cleanup
            .get(identity.upload_id.as_bytes())
            .is_some_and(|marker| marker != &identity)
            || reservations
                .get(identity.upload_id.as_bytes())
                .is_some_and(|marker| marker != &identity)
        {
            return Err(blob_error(BlobStoreError::DepotIntegrity(
                "Blob upload transition marker differs from its pack identity",
            )));
        }
        let expected_pack = expected
            .iter()
            .find(|expected| expected.identity == identity)
            .cloned();
        let Some(expected_pack) = expected_pack else {
            if reservations.get(identity.upload_id.as_bytes()) == Some(&identity) {
                if recover {
                    drop(directory);
                    remove_upload_pack_directory(&pack_root, &identity)?;
                    pack_root.remove_if_exists(&reservation_marker_name(identity), false)?;
                }
                continue;
            }
            return Err(blob_error(BlobStoreError::DepotIntegrity(
                "unexpected Blob upload pack has no durable authority",
            )));
        };
        if !seen.insert(*identity.upload_id.as_bytes()) {
            return Err(blob_error(BlobStoreError::DepotIntegrity(
                "duplicate Blob upload pack identity",
            )));
        }
        if cleanup.get(identity.upload_id.as_bytes()) == Some(&identity) {
            if recover {
                drop(directory);
                remove_upload_pack_directory(&pack_root, &identity)?;
            }
            completed.push(identity);
        } else if expected_pack.discard_candidate {
            if recover {
                drop(directory);
                remove_upload_pack_directory(&pack_root, &identity)?;
            }
        } else {
            audit_expected_upload_pack(&directory, &expected_pack)?;
            if recover && reservations.get(identity.upload_id.as_bytes()) == Some(&identity) {
                pack_root.remove_if_exists(&reservation_marker_name(identity), false)?;
            }
        }
    }
    for expected in expected {
        if seen.contains(expected.identity.upload_id.as_bytes()) {
            continue;
        }
        if cleanup.get(expected.identity.upload_id.as_bytes()) == Some(&expected.identity) {
            completed.push(expected.identity);
            continue;
        }
        if expected.may_be_absent {
            continue;
        }
        return Err(blob_error(BlobStoreError::DepotIntegrity(
            "durable Blob upload pack is missing",
        )));
    }
    if recover {
        for identity in reservations.values() {
            if !seen.contains(identity.upload_id.as_bytes())
                && !expected
                    .iter()
                    .any(|expected| expected.identity == *identity)
            {
                pack_root.remove_if_exists(&reservation_marker_name(*identity), false)?;
            }
        }
    }
    Ok(completed)
}

pub(super) fn audit_upload_packs_write(
    depot_root: &OwnedDirectory,
    expected: &[ExpectedBlobUploadPack],
) -> Result<Vec<BlobPackIdentity>, StoreError> {
    audit_upload_packs(depot_root, expected, true)
}

pub(super) fn audit_upload_packs_read(
    depot_root: &OwnedDirectory,
    expected: &[ExpectedBlobUploadPack],
) -> Result<(), StoreError> {
    audit_upload_packs(depot_root, expected, false).map(|_| ())
}

/// Reclaims cleanup tombstones only after the transaction which removed their
/// upload rows has committed. The caller holds a fresh database writer while
/// this runs, so a new reservation cannot make a row present between the
/// absence check and physical marker removal.
pub(super) fn reclaim_row_absent_cleanup_markers(
    depot_root: &OwnedDirectory,
    expected: &[ExpectedBlobUploadPack],
) -> Result<(), StoreError> {
    let Some(pack_root) = depot_root.open_child_directory_if_present(PACK_DIRECTORY)? else {
        return Ok(());
    };
    reclaim_cleanup_markers_in_pack_root(&pack_root, expected)
}

fn reclaim_cleanup_markers_in_pack_root(
    pack_root: &OwnedDirectory,
    expected: &[ExpectedBlobUploadPack],
) -> Result<(), StoreError> {
    let names = pack_root
        .entry_names()?
        .into_iter()
        .filter(|name| name.starts_with(UPLOAD_CLEANUP_PREFIX))
        .collect::<Vec<_>>();
    reclaim_cleanup_markers_in_order(pack_root, expected, &names)
}

fn reclaim_cleanup_markers_in_order(
    pack_root: &OwnedDirectory,
    expected: &[ExpectedBlobUploadPack],
    names: &[String],
) -> Result<(), StoreError> {
    let mut reclaim = Vec::new();
    for name in names {
        let marker = pack_root
            .read_private_file_if_present(name, 80)?
            .ok_or_else(|| {
                blob_error(BlobStoreError::DepotIntegrity(
                    "Blob upload cleanup marker disappeared during reclaim",
                ))
            })?;
        let identity = decode_cleanup_marker(&marker).map_err(pack_marker_store_error)?;
        if *name != cleanup_marker_name(identity) {
            return Err(blob_error(BlobStoreError::DepotIntegrity(
                "Blob upload cleanup marker identity is inconsistent",
            )));
        }
        match expected
            .iter()
            .find(|expected| expected.identity.upload_id == identity.upload_id)
        {
            Some(expected) if expected.identity == identity => continue,
            Some(_) => {
                return Err(blob_error(BlobStoreError::DepotIntegrity(
                    "Blob upload cleanup marker differs from durable upload identity",
                )));
            }
            None => reclaim.push(name),
        }
    }
    for name in reclaim {
        pack_root.remove_if_exists(name, false)?;
    }
    Ok(())
}

#[cfg(test)]
pub(super) fn reclaim_cleanup_markers_from_pinned_root_for_test(
    root: &PinnedBlobPackRoot,
    expected: &[ExpectedBlobUploadPack],
    names: &[String],
) -> Result<(), StoreError> {
    reclaim_cleanup_markers_in_order(&root.directory, expected, names)
}

#[cfg(test)]
pub(super) fn cleanup_marker_name_for_test(identity: BlobPackIdentity) -> String {
    cleanup_marker_name(identity)
}

enum BlobPackRoot {
    Path(PathBuf),
    Pinned(OwnedDirectory, Arc<()>),
}

impl BlobPackRoot {
    fn install_upload_digests_atomic(&self, bytes: &[u8]) -> Result<File, BlobPackError> {
        match self {
            Self::Pinned(root, _) => root.write_atomic(UPLOAD_DIGEST_FILE, bytes)?,
            Self::Path(root) => {
                let temp_name = format!(
                    "{PACK_TEMP_PREFIX}digest-{}-{}",
                    std::process::id(),
                    PACK_TEMP_SEQUENCE.fetch_add(1, Ordering::Relaxed)
                );
                let temp = root.join(&temp_name);
                let mut options = OpenOptions::new();
                options.write(true).create_new(true);
                #[cfg(unix)]
                {
                    use std::os::unix::fs::OpenOptionsExt;
                    options.mode(0o600);
                }
                let mut file = options.open(&temp)?;
                if let Err(error) = file.write_all(bytes).and_then(|()| file.sync_all()) {
                    let _ = fs::remove_file(&temp);
                    return Err(error.into());
                }
                fs::rename(&temp, root.join(UPLOAD_DIGEST_FILE))?;
                File::open(root)?.sync_all()?;
            }
        }
        self.open_upload_digests(false)
    }

    fn remove_upload_digests(&self) -> Result<(), BlobPackError> {
        match self {
            Self::Pinned(root, _) => root.remove_if_exists(UPLOAD_DIGEST_FILE, false)?,
            Self::Path(root) => match fs::remove_file(root.join(UPLOAD_DIGEST_FILE)) {
                Ok(()) => File::open(root)?.sync_all()?,
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                Err(error) => return Err(error.into()),
            },
        }
        Ok(())
    }

    fn open_data(&self, create_new: bool) -> Result<File, BlobPackError> {
        match self {
            Self::Path(root) => Ok(OpenOptions::new()
                .read(true)
                .write(true)
                .create_new(create_new)
                .open(root.join(PACK_FILE))?),
            Self::Pinned(root, _) => Ok(root.open_private_rw_file(PACK_FILE, create_new)?),
        }
    }

    fn open_existing_data(&self) -> Result<Option<File>, BlobPackError> {
        match self {
            Self::Path(root) => match OpenOptions::new()
                .read(true)
                .write(true)
                .open(root.join(PACK_FILE))
            {
                Ok(file) => Ok(Some(file)),
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
                Err(error) => Err(error.into()),
            },
            Self::Pinned(root, _) => Ok(root.open_private_rw_file_if_present(PACK_FILE)?),
        }
    }

    fn open_upload_digests(&self, create_new: bool) -> Result<File, BlobPackError> {
        match self {
            Self::Path(root) => Ok(OpenOptions::new()
                .read(true)
                .write(true)
                .create_new(create_new)
                .open(root.join(UPLOAD_DIGEST_FILE))?),
            Self::Pinned(root, _) => Ok(root.open_private_rw_file(UPLOAD_DIGEST_FILE, create_new)?),
        }
    }

    fn open_existing_upload_digests(&self) -> Result<Option<File>, BlobPackError> {
        match self {
            Self::Path(root) => match OpenOptions::new()
                .read(true)
                .write(true)
                .open(root.join(UPLOAD_DIGEST_FILE))
            {
                Ok(file) => Ok(Some(file)),
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
                Err(error) => Err(error.into()),
            },
            Self::Pinned(root, _) => Ok(root.open_private_rw_file_if_present(UPLOAD_DIGEST_FILE)?),
        }
    }

    fn read_checkpoint(&self, name: &str) -> Result<Option<Vec<u8>>, BlobPackError> {
        match self {
            Self::Path(root) => match fs::read(root.join(name)) {
                Ok(bytes) => Ok(Some(bytes)),
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
                Err(error) => Err(error.into()),
            },
            Self::Pinned(root, _) => Ok(root.read_private_file_if_present(name, 16 * 1024)?),
        }
    }

    fn write_checkpoint(&self, name: &str, bytes: &[u8]) -> Result<(), BlobPackError> {
        match self {
            Self::Path(root) => {
                let mut journal = OpenOptions::new()
                    .write(true)
                    .create(true)
                    .truncate(true)
                    .open(root.join(name))?;
                journal.write_all(bytes)?;
                journal.sync_all()?;
                Ok(())
            }
            Self::Pinned(root, _) => Ok(root.write_atomic(name, bytes)?),
        }
    }

    fn authority(&self) -> Option<Arc<()>> {
        match self {
            Self::Path(_) => None,
            Self::Pinned(_, authority) => Some(Arc::clone(authority)),
        }
    }

    #[cfg(test)]
    fn path(&self) -> &Path {
        match self {
            Self::Path(path) => path,
            Self::Pinned(root, _) => root.path(),
        }
    }
}

/// Non-semantic identity for one node-protected provisional Blob upload pack.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BlobPackIdentity {
    upload_id: BlobPublicationStreamId,
    request_digest: [u8; 32],
    total_len: u64,
}

impl BlobPackIdentity {
    pub(crate) const fn new(
        upload_id: BlobPublicationStreamId,
        request_digest: [u8; 32],
        total_len: u64,
    ) -> Self {
        Self {
            upload_id,
            request_digest,
            total_len,
        }
    }

    fn from_stream(open: &BlobStreamOpen) -> Self {
        Self::new(open.stream_id(), open.digest(), open.total_len())
    }

    pub const fn upload_id(&self) -> BlobPublicationStreamId {
        self.upload_id
    }

    pub const fn request_digest(&self) -> &[u8; 32] {
        &self.request_digest
    }

    pub const fn total_len(&self) -> u64 {
        self.total_len
    }
}

#[derive(Clone, Debug)]
pub struct BlobPackCheckpoint {
    format_version: u16,
    generation: u64,
    open_digest: [u8; 32],
    stream_id: BlobPublicationStreamId,
    total_len: u64,
    next_index: u64,
    plaintext_offset: u64,
    pack_len: u64,
    frontier: BlobStreamCheckpoint,
    upload_digests: Option<BlobUploadDigestCheckpoint>,
    authority: Option<Arc<()>>,
}

/// Nonconstructible proof that one exact Profile-5 pack is complete and bound
/// to its authenticated final commitment. The descriptor is synchronized in
/// the pack directory before lifecycle promotion can reference it.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BlobPackCompletion {
    identity: BlobPackIdentity,
    checkpoint: BlobPackCheckpoint,
    plaintext_root: [u8; 32],
    ciphertext_root: [u8; 32],
    blob_id: BlobId,
    commitment_digest: [u8; 32],
    authenticated_commitment_digest: [u8; 32],
    descriptor_digest: [u8; 32],
}

impl BlobPackCompletion {
    pub const fn identity(&self) -> BlobPackIdentity {
        self.identity
    }

    pub const fn checkpoint(&self) -> &BlobPackCheckpoint {
        &self.checkpoint
    }

    pub const fn segment_count(&self) -> u64 {
        self.checkpoint.next_index
    }

    pub const fn pack_len(&self) -> u64 {
        self.checkpoint.pack_len
    }

    pub const fn plaintext_root(&self) -> &[u8; 32] {
        &self.plaintext_root
    }

    pub const fn ciphertext_root(&self) -> &[u8; 32] {
        &self.ciphertext_root
    }

    pub const fn blob_id(&self) -> BlobId {
        self.blob_id
    }

    pub const fn commitment_digest(&self) -> &[u8; 32] {
        &self.commitment_digest
    }

    pub const fn authenticated_commitment_digest(&self) -> &[u8; 32] {
        &self.authenticated_commitment_digest
    }

    pub const fn descriptor_digest(&self) -> &[u8; 32] {
        &self.descriptor_digest
    }

    pub(crate) fn bind_authority(&mut self, authority: Arc<()>) {
        self.checkpoint.bind_authority(authority);
    }

    pub(crate) fn is_bound_to(&self, authority: &Arc<()>) -> bool {
        self.checkpoint.is_bound_to(authority)
    }

    pub(crate) fn encode(&self) -> Result<Vec<u8>, BlobPackError> {
        let (encoded, digest) = encode_completion_descriptor(self)?;
        if self.descriptor_digest != digest {
            return Err(BlobPackError::Invalid(
                "Blob pack completion descriptor digest mismatch",
            ));
        }
        Ok(encoded)
    }

    pub(crate) fn decode(encoded: &[u8], authority: Arc<()>) -> Result<Self, BlobPackError> {
        let mut completion = decode_completion_descriptor(encoded)?;
        completion.bind_authority(authority);
        Ok(completion)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct BlobUploadDigestCheckpoint {
    count: u64,
    file_len: u64,
    commitment: zeroize::Zeroizing<[u8; 32]>,
    whole_sha256_state: zeroize::Zeroizing<[u8; SHA256_SERIALIZED_STATE_LEN]>,
}

impl PartialEq for BlobPackCheckpoint {
    fn eq(&self, other: &Self) -> bool {
        self.format_version == other.format_version
            && self.generation == other.generation
            && self.open_digest == other.open_digest
            && self.stream_id == other.stream_id
            && self.total_len == other.total_len
            && self.next_index == other.next_index
            && self.plaintext_offset == other.plaintext_offset
            && self.pack_len == other.pack_len
            && self.frontier == other.frontier
            && self.upload_digests == other.upload_digests
    }
}

impl Eq for BlobPackCheckpoint {}

impl BlobPackCheckpoint {
    pub const fn generation(&self) -> u64 {
        self.generation
    }
    pub const fn next_index(&self) -> u64 {
        self.next_index
    }
    pub const fn plaintext_offset(&self) -> u64 {
        self.plaintext_offset
    }
    pub const fn pack_len(&self) -> u64 {
        self.pack_len
    }
    pub const fn payload_len(&self) -> u64 {
        self.pack_len - PACK_HEADER_LEN
    }
    pub const fn frontier(&self) -> &BlobStreamCheckpoint {
        &self.frontier
    }

    pub const fn open_digest(&self) -> &[u8; 32] {
        &self.open_digest
    }

    /// Exact immutable provisional-upload request digest.
    pub const fn request_digest(&self) -> &[u8; 32] {
        &self.open_digest
    }

    pub const fn stream_id(&self) -> BlobPublicationStreamId {
        self.stream_id
    }

    /// Opaque node-local provisional-upload identity.
    pub const fn upload_id(&self) -> BlobPublicationStreamId {
        self.stream_id
    }

    pub const fn total_len(&self) -> u64 {
        self.total_len
    }

    pub const fn canonical_digest_count(&self) -> Option<u64> {
        match &self.upload_digests {
            Some(checkpoint) => Some(checkpoint.count),
            None => None,
        }
    }

    pub(crate) fn bind_authority(&mut self, authority: Arc<()>) {
        self.authority = Some(authority);
    }

    pub(crate) fn is_bound_to(&self, authority: &Arc<()>) -> bool {
        self.authority
            .as_ref()
            .is_some_and(|bound| Arc::ptr_eq(bound, authority))
    }

    pub(crate) fn encode(&self) -> Vec<u8> {
        debug_assert!(
            self.format_version == PACK_VERSION || self.format_version == CHECKPOINT_VERSION
        );
        debug_assert!(
            self.format_version == CHECKPOINT_VERSION || self.upload_digests.is_none(),
            "v2 checkpoints cannot carry the canonical digest projection"
        );
        let frontier = self.frontier.encode();
        let mut out = Vec::with_capacity(150 + frontier.len());
        out.extend_from_slice(CHECKPOINT_MAGIC);
        out.extend_from_slice(&self.format_version.to_be_bytes());
        out.extend_from_slice(&self.generation.to_be_bytes());
        out.extend_from_slice(&self.open_digest);
        out.extend_from_slice(self.stream_id.as_bytes());
        out.extend_from_slice(&self.total_len.to_be_bytes());
        out.extend_from_slice(&self.next_index.to_be_bytes());
        out.extend_from_slice(&self.plaintext_offset.to_be_bytes());
        out.extend_from_slice(&self.pack_len.to_be_bytes());
        out.extend_from_slice(&(frontier.len() as u32).to_be_bytes());
        out.extend_from_slice(&frontier);
        if self.format_version == CHECKPOINT_VERSION {
            match &self.upload_digests {
                None => out.push(0),
                Some(digests) => {
                    out.push(1);
                    out.extend_from_slice(&UPLOAD_DIGEST_VERSION.to_be_bytes());
                    out.extend_from_slice(&digests.count.to_be_bytes());
                    out.extend_from_slice(&digests.file_len.to_be_bytes());
                    out.extend_from_slice(&digests.commitment[..]);
                    out.extend_from_slice(&digests.whole_sha256_state[..]);
                }
            }
        }
        let checksum = Sha256::digest(&out);
        out.extend_from_slice(&checksum);
        out
    }

    pub(crate) fn decode(bytes: &[u8]) -> Result<Self, BlobPackError> {
        let minimum = 8 + 2 + 8 + 32 + 32 + 8 * 4 + 4 + 32;
        if bytes.len() < minimum || &bytes[..8] != CHECKPOINT_MAGIC {
            return Err(BlobPackError::Invalid("invalid Blob pack checkpoint"));
        }
        let checksum_at = bytes.len() - 32;
        if Sha256::digest(&bytes[..checksum_at]).as_slice() != &bytes[checksum_at..] {
            return Err(BlobPackError::Invalid(
                "invalid Blob pack checkpoint checksum",
            ));
        }
        let mut reader = Reader::new(&bytes[..checksum_at]);
        if reader.take(8)? != CHECKPOINT_MAGIC {
            return Err(BlobPackError::Invalid("unsupported Blob pack checkpoint"));
        }
        let version = reader.u16()?;
        if version != PACK_VERSION && version != CHECKPOINT_VERSION {
            return Err(BlobPackError::Invalid("unsupported Blob pack checkpoint"));
        }
        let generation = reader.u64()?;
        let open_digest = reader.array()?;
        let stream_id = BlobPublicationStreamId::from_bytes(reader.array()?)
            .map_err(|_| BlobPackError::Invalid("invalid stream ID"))?;
        let total_len = reader.u64()?;
        let next_index = reader.u64()?;
        let plaintext_offset = reader.u64()?;
        let pack_len = reader.u64()?;
        let frontier_len = reader.u32()? as usize;
        let frontier = BlobStreamCheckpoint::decode(reader.take(frontier_len)?)
            .map_err(|_| BlobPackError::Invalid("invalid Blob frontier"))?;
        let upload_digests = if version == PACK_VERSION {
            None
        } else {
            match reader.u8()? {
                0 => None,
                1 if reader.u16()? == UPLOAD_DIGEST_VERSION => Some(BlobUploadDigestCheckpoint {
                    count: reader.u64()?,
                    file_len: reader.u64()?,
                    commitment: zeroize::Zeroizing::new(reader.array()?),
                    whole_sha256_state: zeroize::Zeroizing::new(
                        reader
                            .take(SHA256_SERIALIZED_STATE_LEN)?
                            .try_into()
                            .map_err(|_| BlobPackError::Invalid("invalid SHA-256 state"))?,
                    ),
                }),
                _ => {
                    return Err(BlobPackError::Invalid(
                        "unsupported Blob upload digest checkpoint",
                    ));
                }
            }
        };
        reader.finish()?;
        if generation == 0
            || open_digest == [0; 32]
            || plaintext_offset > total_len
            || pack_len < PACK_HEADER_LEN
            || frontier.next_index() != next_index
            || frontier.plaintext_len() != plaintext_offset
            || (version == CHECKPOINT_VERSION && upload_digests.is_none())
            || upload_digests.as_ref().is_some_and(|digests| {
                validate_upload_digest_checkpoint(digests, plaintext_offset, total_len).is_err()
            })
        {
            return Err(BlobPackError::Invalid("invalid Blob pack checkpoint state"));
        }
        Ok(Self {
            format_version: version,
            generation,
            open_digest,
            stream_id,
            total_len,
            next_index,
            plaintext_offset,
            pack_len,
            frontier,
            upload_digests,
            authority: None,
        })
    }
}

fn expected_canonical_digest_count(
    plaintext_offset: u64,
    total_len: u64,
) -> Result<u64, BlobPackError> {
    if plaintext_offset > total_len
        || (plaintext_offset != total_len
            && !plaintext_offset.is_multiple_of(u64::from(SELECTED_BLOB_CHUNK_SIZE)))
    {
        return Err(BlobPackError::Invalid(
            "Blob upload digest offset is not canonical",
        ));
    }
    Ok(if plaintext_offset == 0 {
        0
    } else {
        plaintext_offset.div_ceil(u64::from(SELECTED_BLOB_CHUNK_SIZE))
    })
}

fn validate_upload_digest_checkpoint(
    checkpoint: &BlobUploadDigestCheckpoint,
    plaintext_offset: u64,
    total_len: u64,
) -> Result<(), BlobPackError> {
    let expected_count = expected_canonical_digest_count(plaintext_offset, total_len)?;
    let expected_len = UPLOAD_DIGEST_HEADER_LEN
        .checked_add(
            expected_count
                .checked_mul(32)
                .ok_or(BlobPackError::Invalid("Blob upload digest length overflow"))?,
        )
        .ok_or(BlobPackError::Invalid("Blob upload digest length overflow"))?;
    if checkpoint.count != expected_count
        || checkpoint.count > MAX_BLOB_CHUNKS
        || checkpoint.file_len != expected_len
    {
        return Err(BlobPackError::Invalid(
            "Blob upload digest checkpoint is inconsistent",
        ));
    }
    restore_sha256_state(&checkpoint.whole_sha256_state, plaintext_offset).map(|_| ())
}

fn sha256_state(hasher: &Sha256) -> [u8; SHA256_SERIALIZED_STATE_LEN] {
    // Artifact codec v1 is our own stable representation rather than the
    // dependency's in-memory/serialized representation: eight chaining words
    // in network order, a network-order count of compressed 64-byte blocks,
    // one buffered-byte count, then a zero-padded 64-byte partial block.
    let dependency = hasher.serialize();
    let dependency = dependency.as_slice();
    assert_eq!(dependency.len(), 104, "pinned sha2 0.11 adapter size");
    let mut canonical = [0_u8; SHA256_SERIALIZED_STATE_LEN];
    for word in 0..8 {
        let at = word * 4;
        let value = u32::from_le_bytes(
            dependency[at..at + 4]
                .try_into()
                .expect("SHA-256 state word"),
        );
        canonical[at..at + 4].copy_from_slice(&value.to_be_bytes());
    }
    let blocks = u64::from_le_bytes(dependency[32..40].try_into().expect("SHA-256 block count"));
    canonical[32..40].copy_from_slice(&blocks.to_be_bytes());
    let buffered = usize::from(dependency[40]);
    assert!(buffered < 64, "sha2 eager buffer invariant");
    canonical[40] = buffered as u8;
    canonical[41..41 + buffered].copy_from_slice(&dependency[41..41 + buffered]);
    canonical
}

fn restore_sha256_state(
    bytes: &[u8; SHA256_SERIALIZED_STATE_LEN],
    plaintext_offset: u64,
) -> Result<Sha256, BlobPackError> {
    // Validate the stable artifact representation before adapting it to the
    // pinned sha2 implementation. Impossible state/length combinations never
    // reach deserialization or any caller-side truncation.
    let blocks = u64::from_be_bytes(
        bytes[32..40]
            .try_into()
            .map_err(|_| BlobPackError::Invalid("invalid SHA-256 block count"))?,
    );
    let buffered = u64::from(bytes[40]);
    if buffered >= 64
        || bytes[41 + buffered as usize..]
            .iter()
            .any(|byte| *byte != 0)
        || blocks
            .checked_mul(64)
            .and_then(|value| value.checked_add(buffered))
            != Some(plaintext_offset)
    {
        return Err(BlobPackError::Invalid(
            "SHA-256 state length differs from upload checkpoint",
        ));
    }
    let mut dependency = [0_u8; 104];
    for word in 0..8 {
        let at = word * 4;
        let value = u32::from_be_bytes(
            bytes[at..at + 4]
                .try_into()
                .map_err(|_| BlobPackError::Invalid("invalid SHA-256 state word"))?,
        );
        dependency[at..at + 4].copy_from_slice(&value.to_le_bytes());
    }
    dependency[32..40].copy_from_slice(&blocks.to_le_bytes());
    dependency[40] = buffered as u8;
    dependency[41..41 + buffered as usize].copy_from_slice(&bytes[41..41 + buffered as usize]);
    let serialized = SerializedState::<Sha256>::try_from(dependency.as_slice())
        .map_err(|_| BlobPackError::Invalid("invalid SHA-256 state size"))?;
    let restored = Sha256::deserialize(&serialized)
        .map_err(|_| BlobPackError::Invalid("invalid SHA-256 state"))?;
    if sha256_state(&restored) != *bytes {
        return Err(BlobPackError::Invalid("non-canonical SHA-256 state"));
    }
    Ok(restored)
}

fn upload_digest_header(identity: BlobPackIdentity) -> [u8; UPLOAD_DIGEST_HEADER_LEN as usize] {
    let mut header = [0_u8; UPLOAD_DIGEST_HEADER_LEN as usize];
    header[..8].copy_from_slice(UPLOAD_DIGEST_MAGIC);
    header[8..10].copy_from_slice(&UPLOAD_DIGEST_VERSION.to_be_bytes());
    header[10..42].copy_from_slice(identity.upload_id.as_bytes());
    header[42..74].copy_from_slice(&identity.request_digest);
    header[74..82].copy_from_slice(&identity.total_len.to_be_bytes());
    header[82..86].copy_from_slice(&SELECTED_BLOB_CHUNK_SIZE.to_be_bytes());
    header
}

fn validate_upload_digest_header(
    data: &mut File,
    identity: BlobPackIdentity,
) -> Result<(), BlobPackError> {
    data.seek(SeekFrom::Start(0))?;
    let mut header = [0_u8; UPLOAD_DIGEST_HEADER_LEN as usize];
    data.read_exact(&mut header)?;
    if header != upload_digest_header(identity) {
        return Err(BlobPackError::Invalid(
            "Blob upload digest identity mismatch",
        ));
    }
    Ok(())
}

fn validate_upload_digest_file(
    data: &mut File,
    identity: BlobPackIdentity,
    pack_checkpoint: &BlobPackCheckpoint,
) -> Result<(Sha256, Sha256), BlobPackError> {
    let checkpoint = pack_checkpoint
        .upload_digests
        .as_ref()
        .ok_or(BlobPackError::Invalid(
            "Blob upload digest checkpoint is missing",
        ))?;
    validate_upload_digest_checkpoint(
        checkpoint,
        pack_checkpoint.plaintext_offset,
        pack_checkpoint.total_len,
    )?;
    validate_upload_digest_header(data, identity)?;
    let file_len = data.metadata()?.len();
    if file_len < checkpoint.file_len {
        return Err(BlobPackError::Invalid(
            "Blob upload digest artifact is truncated",
        ));
    }
    data.seek(SeekFrom::Start(0))?;
    let mut commitment = Sha256::new();
    let mut remaining = checkpoint.file_len;
    let mut buffer = [0_u8; 8192];
    while remaining > 0 {
        let take = usize::try_from(remaining.min(buffer.len() as u64))
            .map_err(|_| BlobPackError::Invalid("Blob upload digest length overflow"))?;
        data.read_exact(&mut buffer[..take])?;
        commitment.update(&buffer[..take]);
        remaining -= take as u64;
    }
    if commitment.clone().finalize().as_slice() != &checkpoint.commitment[..] {
        return Err(BlobPackError::Invalid(
            "Blob upload digest commitment mismatch",
        ));
    }
    let whole = restore_sha256_state(
        &checkpoint.whole_sha256_state,
        pack_checkpoint.plaintext_offset,
    )?;
    Ok((commitment, whole))
}

/// Durable fixed-stride canonical digest artifact for one owner-qualified
/// provisional upload. Its combined checkpoint lives in the alternating pack
/// journal and is projected atomically with that pack checkpoint.
/// Durable local-private upload metadata.
///
/// The sidecar intentionally contains raw unkeyed plaintext SHA-256 material.
/// It is not cryptographically protected at rest: the Store layer has no
/// node/mission content-grant key without introducing a second authority.
/// Pinned owner directories, O_NOFOLLOW, regular-file/same-UID checks, mode
/// 0600, and link-count one protect the supported live access boundary, but a
/// same-account or offline-disk reader can perform equality/dictionary tests.
pub struct BlobUploadDigestWriter {
    data: File,
    identity: BlobPackIdentity,
    plaintext_offset: u64,
    count: u64,
    pending_digest: Sha256,
    pending_len: usize,
    commitment: Sha256,
    whole_plaintext: Sha256,
    legacy_rebuild_allowed: bool,
}

impl BlobUploadDigestWriter {
    pub fn open_projected_upload_pinned(
        root: &PinnedBlobPackRoot,
        identity: &BlobPackIdentity,
        projected: Option<&BlobPackCheckpoint>,
    ) -> Result<Self, BlobPackError> {
        if projected.is_some_and(|checkpoint| !checkpoint.is_bound_to(&root.authority)) {
            return Err(BlobPackError::Invalid(
                "Blob upload digest checkpoint belongs to another Store",
            ));
        }
        let pack_root = root.upload(identity, false)?;
        Self::open_pack_root(pack_root, *identity, projected)
    }

    fn open_pack_root(
        pack_root: BlobPackRoot,
        identity: BlobPackIdentity,
        projected: Option<&BlobPackCheckpoint>,
    ) -> Result<Self, BlobPackError> {
        let legacy_rebuild_allowed = projected.is_none()
            || projected.is_some_and(|checkpoint| {
                checkpoint.format_version == PACK_VERSION && checkpoint.upload_digests.is_none()
            });
        let header = upload_digest_header(identity);
        let mut data = match pack_root.open_existing_upload_digests()? {
            Some(mut data) => match validate_upload_digest_header(&mut data, identity) {
                Ok(()) => data,
                Err(_) if legacy_rebuild_allowed => {
                    drop(data);
                    pack_root.remove_upload_digests()?;
                    pack_root.install_upload_digests_atomic(&header)?
                }
                Err(error) => return Err(error),
            },
            None => pack_root.install_upload_digests_atomic(&header)?,
        };
        let (plaintext_offset, count, commitment, whole_plaintext, file_len) = match projected
            .and_then(|checkpoint| {
                checkpoint
                    .upload_digests
                    .as_ref()
                    .map(|digests| (checkpoint, digests))
            }) {
            Some((checkpoint, digests)) => {
                let (commitment, whole) =
                    validate_upload_digest_file(&mut data, identity, checkpoint)?;
                (
                    checkpoint.plaintext_offset,
                    digests.count,
                    commitment,
                    whole,
                    digests.file_len,
                )
            }
            None => {
                let header = upload_digest_header(identity);
                let mut commitment = Sha256::new();
                commitment.update(header);
                (0, 0, commitment, Sha256::new(), UPLOAD_DIGEST_HEADER_LEN)
            }
        };
        // Validate every projected field before mutating an unprojected tail.
        data.set_len(file_len)?;
        data.sync_data()?;
        data.seek(SeekFrom::Start(file_len))?;
        Ok(Self {
            data,
            identity,
            plaintext_offset,
            count,
            pending_digest: Sha256::new(),
            pending_len: 0,
            commitment,
            whole_plaintext,
            legacy_rebuild_allowed,
        })
    }

    pub const fn plaintext_offset(&self) -> u64 {
        self.plaintext_offset
    }

    /// Exact one-time plaintext bytes which a pre-artifact checkpoint must
    /// replay to establish the v1 digest sidecar. A v3 projected frontier
    /// always returns zero; a partial/misaligned artifact fails closed.
    pub fn migration_rebuild_bytes(
        &self,
        durable_plaintext_offset: u64,
    ) -> Result<u64, BlobPackError> {
        if self.plaintext_offset == durable_plaintext_offset {
            Ok(0)
        } else if self.plaintext_offset == 0 && self.legacy_rebuild_allowed {
            Ok(durable_plaintext_offset)
        } else {
            Err(BlobPackError::Invalid(
                "Blob upload digest artifact differs from durable frontier",
            ))
        }
    }

    pub fn append(&mut self, bytes: &[u8]) -> Result<(), BlobPackError> {
        let end = self
            .plaintext_offset
            .checked_add(bytes.len() as u64)
            .ok_or(BlobPackError::Invalid("Blob upload digest offset overflow"))?;
        if bytes.is_empty() || end > self.identity.total_len {
            return Err(BlobPackError::Invalid(
                "Blob upload digest bytes are outside the reservation",
            ));
        }
        self.whole_plaintext.update(bytes);
        let mut remaining = bytes;
        while !remaining.is_empty() {
            let available = SELECTED_BLOB_CHUNK_SIZE as usize - self.pending_len;
            let take = available.min(remaining.len());
            self.pending_digest.update(&remaining[..take]);
            self.pending_len += take;
            remaining = &remaining[take..];
            let reaches_end = self
                .plaintext_offset
                .checked_add((bytes.len() - remaining.len()) as u64)
                == Some(self.identity.total_len);
            if self.pending_len == SELECTED_BLOB_CHUNK_SIZE as usize || reaches_end {
                let digest: [u8; 32] = self.pending_digest.clone().finalize().into();
                self.data.write_all(&digest)?;
                self.commitment.update(digest);
                self.count = self
                    .count
                    .checked_add(1)
                    .ok_or(BlobPackError::Invalid("Blob upload digest count overflow"))?;
                self.pending_digest = Sha256::new();
                self.pending_len = 0;
            }
        }
        self.plaintext_offset = end;
        Ok(())
    }

    fn checkpoint(
        &mut self,
        expected_plaintext_offset: u64,
    ) -> Result<BlobUploadDigestCheckpoint, BlobPackError> {
        if self.plaintext_offset != expected_plaintext_offset || self.pending_len != 0 {
            return Err(BlobPackError::Invalid(
                "Blob upload digest frontier differs from pack frontier",
            ));
        }
        self.data.sync_data()?;
        let checkpoint = BlobUploadDigestCheckpoint {
            count: self.count,
            file_len: self.data.stream_position()?,
            commitment: zeroize::Zeroizing::new(self.commitment.clone().finalize().into()),
            whole_sha256_state: zeroize::Zeroizing::new(sha256_state(&self.whole_plaintext)),
        };
        validate_upload_digest_checkpoint(
            &checkpoint,
            self.plaintext_offset,
            self.identity.total_len,
        )?;
        Ok(checkpoint)
    }
}

pub struct BlobUploadDigestMaterial {
    plaintext_digests: zeroize::Zeroizing<Vec<[u8; 32]>>,
    whole_plaintext_sha256: zeroize::Zeroizing<[u8; 32]>,
}

impl BlobUploadDigestMaterial {
    pub fn into_parts(
        self,
    ) -> (
        zeroize::Zeroizing<Vec<[u8; 32]>>,
        zeroize::Zeroizing<[u8; 32]>,
    ) {
        (self.plaintext_digests, self.whole_plaintext_sha256)
    }
}

pub fn load_upload_digest_material(
    root: &PinnedBlobPackRoot,
    identity: &BlobPackIdentity,
    checkpoint: &BlobPackCheckpoint,
) -> Result<BlobUploadDigestMaterial, BlobPackError> {
    if !checkpoint.is_bound_to(&root.authority)
        || checkpoint.upload_id() != identity.upload_id
        || checkpoint.request_digest() != &identity.request_digest
        || checkpoint.total_len() != identity.total_len
        || checkpoint.plaintext_offset() != identity.total_len
    {
        return Err(BlobPackError::Invalid(
            "Blob upload digest material is not Store-bound and complete",
        ));
    }
    let pack_root = root.upload(identity, false)?;
    let mut data = pack_root
        .open_existing_upload_digests()?
        .ok_or(BlobPackError::Invalid(
            "Blob upload digest artifact is unavailable",
        ))?;
    let (_, whole) = validate_upload_digest_file(&mut data, *identity, checkpoint)?;
    let digest_checkpoint = checkpoint
        .upload_digests
        .as_ref()
        .ok_or(BlobPackError::Invalid(
            "Blob upload digest checkpoint is missing",
        ))?;
    data.seek(SeekFrom::Start(UPLOAD_DIGEST_HEADER_LEN))?;
    let capacity = usize::try_from(digest_checkpoint.count)
        .map_err(|_| BlobPackError::Invalid("Blob upload digest count overflow"))?;
    let mut plaintext_digests = zeroize::Zeroizing::new(Vec::with_capacity(capacity));
    for _ in 0..digest_checkpoint.count {
        let mut digest = zeroize::Zeroizing::new([0_u8; 32]);
        data.read_exact(&mut *digest)?;
        plaintext_digests.push(*digest);
    }
    Ok(BlobUploadDigestMaterial {
        plaintext_digests,
        whole_plaintext_sha256: zeroize::Zeroizing::new(whole.finalize().into()),
    })
}

pub struct BlobPackWriter {
    root: BlobPackRoot,
    data: File,
    open_digest: [u8; 32],
    stream_id: BlobPublicationStreamId,
    total_len: u64,
    next_index: u64,
    plaintext_offset: u64,
    pack_len: u64,
    generation: u64,
    frontier: BlobStreamFrontier,
}

impl BlobPackWriter {
    pub const fn next_index(&self) -> u64 {
        self.next_index
    }

    pub const fn plaintext_offset(&self) -> u64 {
        self.plaintext_offset
    }

    pub fn create(root: &Path, open: &BlobStreamOpen) -> Result<Self, BlobPackError> {
        fs::create_dir_all(root)?;
        Self::create_in(
            BlobPackRoot::Path(root.to_owned()),
            BlobPackIdentity::from_stream(open),
        )
    }

    pub fn create_pinned(
        root: &PinnedBlobPackRoot,
        open: &BlobStreamOpen,
    ) -> Result<Self, BlobPackError> {
        Self::create_in(
            root.stream(open, true)?,
            BlobPackIdentity::from_stream(open),
        )
    }

    /// Creates a node-protected pack for a provisional application upload.
    pub fn create_upload_pinned(
        root: &PinnedBlobPackRoot,
        identity: &BlobPackIdentity,
    ) -> Result<Self, BlobPackError> {
        Self::create_in(root.upload(identity, true)?, *identity)
    }

    fn create_in(root: BlobPackRoot, identity: BlobPackIdentity) -> Result<Self, BlobPackError> {
        let mut data = root.open_data(true)?;
        acquire_pack_writer_lock(&data)?;
        let open_digest = identity.request_digest;
        data.write_all(PACK_MAGIC)?;
        data.write_all(&PACK_VERSION.to_be_bytes())?;
        data.write_all(&open_digest)?;
        data.write_all(identity.upload_id.as_bytes())?;
        data.write_all(&identity.total_len.to_be_bytes())?;
        data.sync_all()?;
        let mut writer = Self {
            root,
            data,
            open_digest,
            stream_id: identity.upload_id,
            total_len: identity.total_len,
            next_index: 0,
            plaintext_offset: 0,
            pack_len: PACK_HEADER_LEN,
            generation: 0,
            frontier: BlobStreamFrontier::new(),
        };
        writer.checkpoint()?;
        Ok(writer)
    }

    pub fn resume(root: &Path, open: &BlobStreamOpen) -> Result<Self, BlobPackError> {
        Self::resume_in(
            BlobPackRoot::Path(root.to_owned()),
            BlobPackIdentity::from_stream(open),
        )
    }

    pub fn resume_pinned(
        root: &PinnedBlobPackRoot,
        open: &BlobStreamOpen,
    ) -> Result<Self, BlobPackError> {
        Self::resume_in(
            root.stream(open, false)?,
            BlobPackIdentity::from_stream(open),
        )
    }

    fn resume_in(root: BlobPackRoot, identity: BlobPackIdentity) -> Result<Self, BlobPackError> {
        let mut data = root.open_data(false)?;
        acquire_pack_writer_lock(&data)?;
        validate_header(&mut data, identity)?;
        let checkpoint = recover_checkpoint(&root, identity, data.metadata()?.len())?;
        Self::restore(root, identity, data, checkpoint)
    }

    /// Opens the pack at the exact checkpoint already projected into the store.
    ///
    /// A pack checkpoint is made durable before its store projection. After a
    /// crash, the newest pack journal can therefore contain unacknowledged data.
    /// This method deliberately selects the store-authoritative journal instead
    /// of the newest journal and truncates any later tail.
    pub fn open_projected(
        root: &Path,
        open: &BlobStreamOpen,
        generation: u64,
        next_index: u64,
        plaintext_offset: u64,
        pack_len: u64,
        payload_len: u64,
    ) -> Result<Self, BlobPackError> {
        Self::open_projected_in(
            BlobPackRoot::Path(root.to_owned()),
            BlobPackIdentity::from_stream(open),
            generation,
            next_index,
            plaintext_offset,
            pack_len,
            payload_len,
        )
    }

    pub fn open_projected_pinned(
        root: &PinnedBlobPackRoot,
        open: &BlobStreamOpen,
        generation: u64,
        next_index: u64,
        plaintext_offset: u64,
        pack_len: u64,
        payload_len: u64,
    ) -> Result<Self, BlobPackError> {
        let root = root.stream(open, generation == 0)?;
        Self::open_projected_in(
            root,
            BlobPackIdentity::from_stream(open),
            generation,
            next_index,
            plaintext_offset,
            pack_len,
            payload_len,
        )
    }

    /// Reopens a provisional upload at exactly the checkpoint already
    /// projected into redb, discarding any later unprojected pack tail.
    /// The caller must serialize projection validation and acquisition; live
    /// callers use Store::open_blob_upload_writer.
    pub(crate) fn open_projected_upload_pinned(
        root: &PinnedBlobPackRoot,
        identity: &BlobPackIdentity,
        projected: Option<&BlobPackCheckpoint>,
    ) -> Result<Self, BlobPackError> {
        if projected.is_some_and(|checkpoint| !checkpoint.is_bound_to(&root.authority)) {
            return Err(BlobPackError::Invalid(
                "Blob upload checkpoint belongs to another Store",
            ));
        }
        let root = root.upload(identity, projected.is_none())?;
        let (generation, next_index, plaintext_offset, pack_len, payload_len) =
            projected.map_or((0, 0, 0, 0, 0), |checkpoint| {
                (
                    checkpoint.generation(),
                    checkpoint.next_index(),
                    checkpoint.plaintext_offset(),
                    checkpoint.pack_len(),
                    checkpoint.payload_len(),
                )
            });
        Self::open_projected_in(
            root,
            *identity,
            generation,
            next_index,
            plaintext_offset,
            pack_len,
            payload_len,
        )
    }

    fn open_projected_in(
        root: BlobPackRoot,
        identity: BlobPackIdentity,
        generation: u64,
        next_index: u64,
        plaintext_offset: u64,
        pack_len: u64,
        payload_len: u64,
    ) -> Result<Self, BlobPackError> {
        let mut data = match root.open_existing_data()? {
            Some(data) => data,
            None if generation == 0 => {
                if next_index != 0 || plaintext_offset != 0 || pack_len != 0 || payload_len != 0 {
                    return Err(BlobPackError::Invalid(
                        "non-empty Blob projection has zero generation",
                    ));
                }
                return Self::create_in(root, identity);
            }
            None => return Err(BlobPackError::Invalid("Blob pack data is unavailable")),
        };
        acquire_pack_writer_lock(&data)?;
        validate_header(&mut data, identity)?;
        let data_len = data.metadata()?.len();
        let checkpoint = recover_checkpoints(&root, identity, data_len)?
            .into_iter()
            .filter(|checkpoint| {
                if generation == 0 {
                    checkpoint.next_index == 0
                        && checkpoint.plaintext_offset == 0
                        && checkpoint.payload_len() == 0
                } else {
                    checkpoint.generation == generation
                        && checkpoint.next_index == next_index
                        && checkpoint.plaintext_offset == plaintext_offset
                        && checkpoint.pack_len == pack_len
                        && checkpoint.payload_len() == payload_len
                }
            })
            .max_by_key(|checkpoint| checkpoint.generation)
            .ok_or(BlobPackError::Invalid(
                "store-projected Blob pack checkpoint is unavailable",
            ))?;
        Self::restore(root, identity, data, checkpoint)
    }

    fn restore(
        root: BlobPackRoot,
        identity: BlobPackIdentity,
        mut data: File,
        checkpoint: BlobPackCheckpoint,
    ) -> Result<Self, BlobPackError> {
        data.set_len(checkpoint.pack_len)?;
        data.sync_data()?;
        data.seek(SeekFrom::Start(checkpoint.pack_len))?;
        Ok(Self {
            root,
            data,
            open_digest: identity.request_digest,
            stream_id: identity.upload_id,
            total_len: identity.total_len,
            next_index: checkpoint.next_index,
            plaintext_offset: checkpoint.plaintext_offset,
            pack_len: checkpoint.pack_len,
            generation: checkpoint.generation,
            frontier: BlobStreamFrontier::restore(checkpoint.frontier)
                .map_err(|_| BlobPackError::Invalid("invalid restored frontier"))?,
        })
    }

    pub fn append(
        &mut self,
        segment: &EncryptedBlobStreamSegment,
        leaves: BlobStreamSegmentLeaves,
    ) -> Result<(), BlobPackError> {
        let encoded = segment.encode();
        self.append_encoded(&encoded, segment.header(), leaves)
    }

    pub fn append_record(
        &mut self,
        encoded: &[u8],
        leaves: BlobStreamSegmentLeaves,
    ) -> Result<(), BlobPackError> {
        let header = EncryptedBlobStreamSegment::inspect_encoded(encoded)
            .map_err(|_| BlobPackError::Invalid("invalid Blob pack segment"))?;
        self.append_encoded(encoded, header, leaves)
    }

    fn append_encoded(
        &mut self,
        encoded: &[u8],
        header: aster_mesh::EncryptedBlobStreamSegmentHeader,
        leaves: BlobStreamSegmentLeaves,
    ) -> Result<(), BlobPackError> {
        if header.index() != self.next_index
            || header.stream_id() != self.stream_id.as_bytes()
            || header.open_digest() != &self.open_digest
            || header.offset() != self.plaintext_offset
            || header.total_len() != self.total_len
        {
            return Err(BlobPackError::Invalid(
                "Blob segment is outside pack sequence",
            ));
        }
        if encoded.len() > MAX_RECORD_BYTES {
            return Err(BlobPackError::Invalid(
                "Blob segment record exceeds pack bound",
            ));
        }
        self.data.write_all(&(encoded.len() as u32).to_be_bytes())?;
        self.data.write_all(encoded)?;
        self.frontier
            .append(BlobStreamSubtree::leaf(self.next_index, leaves))
            .map_err(|_| BlobPackError::Invalid("invalid Blob segment frontier"))?;
        self.next_index += 1;
        self.plaintext_offset = self
            .plaintext_offset
            .checked_add(u64::from(header.plaintext_len()))
            .ok_or(BlobPackError::Invalid("Blob pack offset overflow"))?;
        self.pack_len = self
            .pack_len
            .checked_add(4 + encoded.len() as u64)
            .ok_or(BlobPackError::Invalid("Blob pack length overflow"))?;
        Ok(())
    }

    pub fn checkpoint(&mut self) -> Result<BlobPackCheckpoint, BlobPackError> {
        self.checkpoint_inner(None)
    }

    pub fn checkpoint_upload(
        &mut self,
        digests: &mut BlobUploadDigestWriter,
    ) -> Result<BlobPackCheckpoint, BlobPackError> {
        let digest_checkpoint = digests.checkpoint(self.plaintext_offset)?;
        self.checkpoint_inner(Some(digest_checkpoint))
    }

    /// Returns the final ordered roots without consuming or rewriting the
    /// completed pack. This is used to authenticate the final commitment
    /// before installing the completion descriptor.
    pub fn final_roots(&self) -> Result<([u8; 32], [u8; 32]), BlobPackError> {
        if self.plaintext_offset != self.total_len {
            return Err(BlobPackError::Invalid("Blob pack is incomplete"));
        }
        self.frontier
            .clone()
            .finish(self.total_len)
            .map_err(|_| BlobPackError::Invalid("invalid final Blob roots"))
    }

    fn checkpoint_inner(
        &mut self,
        upload_digests: Option<BlobUploadDigestCheckpoint>,
    ) -> Result<BlobPackCheckpoint, BlobPackError> {
        self.data.sync_data()?;
        #[cfg(test)]
        maybe_inject_fault(self.root.path(), BlobPackFaultPoint::DataSynced)?;
        let generation = self
            .generation
            .checked_add(1)
            .ok_or(BlobPackError::Invalid("checkpoint generation exhausted"))?;
        let checkpoint = BlobPackCheckpoint {
            format_version: if upload_digests.is_some() {
                CHECKPOINT_VERSION
            } else {
                PACK_VERSION
            },
            generation,
            open_digest: self.open_digest,
            stream_id: self.stream_id,
            total_len: self.total_len,
            next_index: self.next_index,
            plaintext_offset: self.plaintext_offset,
            pack_len: self.pack_len,
            frontier: self.frontier.checkpoint(),
            upload_digests,
            authority: self.root.authority(),
        };
        let name = if generation % 2 == 0 {
            CHECKPOINT_ZERO
        } else {
            CHECKPOINT_ONE
        };
        self.root.write_checkpoint(name, &checkpoint.encode())?;
        #[cfg(test)]
        maybe_inject_fault(
            self.root.path(),
            if generation % 2 == 0 {
                BlobPackFaultPoint::CheckpointZeroSynced
            } else {
                BlobPackFaultPoint::CheckpointOneSynced
            },
        )?;
        self.generation = generation;
        Ok(checkpoint)
    }

    pub fn finish(mut self) -> Result<([u8; 32], [u8; 32]), BlobPackError> {
        if self.plaintext_offset != self.total_len {
            return Err(BlobPackError::Invalid("Blob pack is incomplete"));
        }
        self.checkpoint()?;
        self.frontier
            .finish(self.total_len)
            .map_err(|_| BlobPackError::Invalid("invalid final Blob roots"))
    }

    /// Completes the exact Profile-5 pack in place. No segment is decrypted,
    /// split, copied, or re-encrypted; the synchronized descriptor binds the
    /// final checkpoint and both ordered roots to the signed commitment.
    pub fn finish_profile5(
        mut self,
        commitment: &VerifiedBlobStreamFinalCommitment,
    ) -> Result<BlobPackCompletion, BlobPackError> {
        let (plaintext_root, ciphertext_root) = self.final_roots()?;
        let checkpoint = self.checkpoint()?;
        let final_commitment = commitment.commitment();
        if final_commitment.open_digest() != &self.open_digest
            || final_commitment.stream_id() != self.stream_id
            || final_commitment.total_len() != self.total_len
            || final_commitment.segment_count() != self.next_index
            || final_commitment.plaintext_root() != &plaintext_root
            || final_commitment.ciphertext_root() != &ciphertext_root
            || checkpoint.plaintext_offset() != self.total_len
            || checkpoint.next_index() != self.next_index
            || checkpoint.pack_len() != self.pack_len
        {
            return Err(BlobPackError::Invalid(
                "Blob pack final commitment does not match durable bytes",
            ));
        }
        let commitment_digest = Sha256::digest(final_commitment.encode()).into();
        let authenticated_commitment_digest =
            Sha256::digest(commitment.authenticated_bytes()).into();
        let mut completion = BlobPackCompletion {
            identity: BlobPackIdentity::new(self.stream_id, self.open_digest, self.total_len),
            checkpoint,
            plaintext_root,
            ciphertext_root,
            blob_id: final_commitment.blob_id(),
            commitment_digest,
            authenticated_commitment_digest,
            descriptor_digest: [0; 32],
        };
        let (descriptor, descriptor_digest) = encode_completion_descriptor(&completion)?;
        completion.descriptor_digest = descriptor_digest;
        self.root.write_checkpoint(COMPLETION_FILE, &descriptor)?;
        Ok(completion)
    }
}

pub struct BlobPackReader {
    data: File,
    checkpoint: BlobPackCheckpoint,
    next_index: u64,
}

/// One structurally validated canonical pack record, including its four-byte
/// length prefix. Ownership can move directly into transport framing without
/// decoding and re-encoding the encrypted segment.
pub struct BlobPackRecord {
    bytes: Vec<u8>,
}

impl BlobPackRecord {
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }

    pub fn into_bytes(self) -> Vec<u8> {
        self.bytes
    }
}

impl BlobPackReader {
    pub fn open(root: &Path, open: &BlobStreamOpen) -> Result<Self, BlobPackError> {
        Self::open_in(BlobPackRoot::Path(root.to_owned()), open)
    }

    pub fn open_pinned(
        root: &PinnedBlobPackRoot,
        open: &BlobStreamOpen,
    ) -> Result<Self, BlobPackError> {
        Self::open_in(root.stream(open, false)?, open)
    }

    /// Opens an immutable completed pack only through the exact Store-bound
    /// completion capability installed by [`BlobPackWriter::finish_profile5`].
    pub fn open_completed_upload_pinned(
        root: &PinnedBlobPackRoot,
        completion: &BlobPackCompletion,
    ) -> Result<Self, BlobPackError> {
        if !completion.is_bound_to(&root.authority) {
            return Err(BlobPackError::Invalid(
                "Blob pack completion belongs to another Store",
            ));
        }
        Self::open_completed_in(root.upload(&completion.identity, false)?, completion)
    }

    /// Opens a completed canonical pack at one independently readable fixed
    /// segment boundary. All records preceding the final segment have the
    /// protocol-fixed encoded size, so this remains O(1) in the Blob offset.
    pub fn open_completed_upload_pinned_at_segment(
        root: &PinnedBlobPackRoot,
        completion: &BlobPackCompletion,
        index: u64,
    ) -> Result<Self, BlobPackError> {
        let reader = Self::open_completed_upload_pinned(root, completion)?;
        let record_bytes = 4_u64
            .checked_add(BLOB_STREAM_SEGMENT_BYTES as u64)
            .and_then(|bytes| bytes.checked_add(BLOB_STREAM_SEGMENT_ENCODED_OVERHEAD_BYTES as u64))
            .ok_or(BlobPackError::Invalid("Blob pack record offset overflow"))?;
        let payload_offset = index
            .checked_mul(record_bytes)
            .ok_or(BlobPackError::Invalid("Blob pack record offset overflow"))?;
        Self::open_at_payload_offset_in(reader, index, payload_offset)
    }

    /// Path-backed completion reader used by pack-level validation and tools.
    pub fn open_completed(
        root: &Path,
        completion: &BlobPackCompletion,
    ) -> Result<Self, BlobPackError> {
        Self::open_completed_in(BlobPackRoot::Path(root.to_owned()), completion)
    }

    fn open_completed_in(
        root: BlobPackRoot,
        completion: &BlobPackCompletion,
    ) -> Result<Self, BlobPackError> {
        let descriptor = root
            .read_checkpoint(COMPLETION_FILE)?
            .ok_or(BlobPackError::Invalid(
                "Blob pack completion descriptor is missing",
            ))?;
        let mut durable = decode_completion_descriptor(&descriptor)?;
        if durable != *completion {
            return Err(BlobPackError::Invalid(
                "Blob pack completion descriptor identity mismatch",
            ));
        }
        if let Some(authority) = root.authority() {
            durable.bind_authority(authority);
        }
        let mut data = root
            .open_existing_data()?
            .ok_or(BlobPackError::Invalid("Blob pack data is unavailable"))?;
        validate_header(&mut data, completion.identity)?;
        if data.metadata()?.len() < completion.pack_len() {
            return Err(BlobPackError::Invalid("completed Blob pack is truncated"));
        }
        let recovered = recover_checkpoints(&root, completion.identity, data.metadata()?.len())?;
        if !recovered
            .iter()
            .any(|candidate| candidate == completion.checkpoint())
        {
            return Err(BlobPackError::Invalid(
                "completed Blob pack checkpoint is unavailable",
            ));
        }
        data.seek(SeekFrom::Start(PACK_HEADER_LEN))?;
        Ok(Self {
            data,
            checkpoint: durable.checkpoint,
            next_index: 0,
        })
    }

    /// Opens exactly the Store-projected provisional upload checkpoint. Later
    /// journal progress is intentionally invisible to canonical conversion.
    pub fn open_projected_upload_pinned(
        root: &PinnedBlobPackRoot,
        identity: &BlobPackIdentity,
        checkpoint: &BlobPackCheckpoint,
    ) -> Result<Self, BlobPackError> {
        if !checkpoint.is_bound_to(&root.authority)
            || checkpoint.upload_id() != identity.upload_id
            || checkpoint.request_digest() != &identity.request_digest
            || checkpoint.total_len() != identity.total_len
        {
            return Err(BlobPackError::Invalid(
                "Blob upload reader checkpoint is not Store-bound",
            ));
        }
        let root = root.upload(identity, false)?;
        let mut data = root
            .open_existing_data()?
            .ok_or(BlobPackError::Invalid("Blob pack data is unavailable"))?;
        validate_header(&mut data, *identity)?;
        let data_len = data.metadata()?.len();
        let recovered = recover_checkpoints(&root, *identity, data_len)?;
        if !recovered.iter().any(|candidate| candidate == checkpoint) {
            return Err(BlobPackError::Invalid(
                "store-projected Blob pack checkpoint is unavailable",
            ));
        }
        data.seek(SeekFrom::Start(PACK_HEADER_LEN))?;
        Ok(Self {
            data,
            checkpoint: checkpoint.clone(),
            next_index: 0,
        })
    }

    /// Opens one independently readable provisional segment at its fixed
    /// record boundary within the exact Store-projected checkpoint.
    pub fn open_projected_upload_pinned_at_segment(
        root: &PinnedBlobPackRoot,
        identity: &BlobPackIdentity,
        checkpoint: &BlobPackCheckpoint,
        index: u64,
    ) -> Result<Self, BlobPackError> {
        let reader = Self::open_projected_upload_pinned(root, identity, checkpoint)?;
        let record_bytes = 4_u64
            .checked_add(BLOB_STREAM_SEGMENT_BYTES as u64)
            .and_then(|bytes| bytes.checked_add(BLOB_STREAM_SEGMENT_ENCODED_OVERHEAD_BYTES as u64))
            .ok_or(BlobPackError::Invalid("Blob pack record offset overflow"))?;
        let payload_offset = index
            .checked_mul(record_bytes)
            .ok_or(BlobPackError::Invalid("Blob pack record offset overflow"))?;
        Self::open_at_payload_offset_in(reader, index, payload_offset)
    }

    fn open_in(root: BlobPackRoot, open: &BlobStreamOpen) -> Result<Self, BlobPackError> {
        let identity = BlobPackIdentity::from_stream(open);
        let mut data = root
            .open_existing_data()?
            .ok_or(BlobPackError::Invalid("Blob pack data is unavailable"))?;
        validate_header(&mut data, identity)?;
        let checkpoint = recover_checkpoint(&root, identity, data.metadata()?.len())?;
        data.seek(SeekFrom::Start(PACK_HEADER_LEN))?;
        Ok(Self {
            data,
            checkpoint,
            next_index: 0,
        })
    }

    pub fn open_at_payload_offset(
        root: &Path,
        open: &BlobStreamOpen,
        next_index: u64,
        payload_offset: u64,
    ) -> Result<Self, BlobPackError> {
        Self::open_at_payload_offset_in(Self::open(root, open)?, next_index, payload_offset)
    }

    pub fn open_pinned_at_payload_offset(
        root: &PinnedBlobPackRoot,
        open: &BlobStreamOpen,
        next_index: u64,
        payload_offset: u64,
    ) -> Result<Self, BlobPackError> {
        Self::open_at_payload_offset_in(Self::open_pinned(root, open)?, next_index, payload_offset)
    }

    fn open_at_payload_offset_in(
        mut reader: Self,
        next_index: u64,
        payload_offset: u64,
    ) -> Result<Self, BlobPackError> {
        if next_index > reader.checkpoint.next_index
            || payload_offset > reader.checkpoint.payload_len()
            || (next_index == 0) != (payload_offset == 0)
            || (next_index == reader.checkpoint.next_index)
                != (payload_offset == reader.checkpoint.payload_len())
        {
            return Err(BlobPackError::Invalid(
                "Blob pack resume position is outside its durable checkpoint",
            ));
        }
        let position = PACK_HEADER_LEN
            .checked_add(payload_offset)
            .ok_or(BlobPackError::Invalid("Blob pack resume offset overflow"))?;
        reader.data.seek(SeekFrom::Start(position))?;
        reader.next_index = next_index;
        Ok(reader)
    }

    pub fn next_segment(&mut self) -> Result<Option<EncryptedBlobStreamSegment>, BlobPackError> {
        self.next_segment_observing_owned_bytes(|_| {})
    }

    /// Decodes one segment while reporting actual live heap capacities before
    /// and after the encoded record is released.
    pub fn next_segment_observing_owned_bytes(
        &mut self,
        mut observe: impl FnMut(usize),
    ) -> Result<Option<EncryptedBlobStreamSegment>, BlobPackError> {
        let Some(record) = self.next_record()? else {
            return Ok(None);
        };
        let segment = EncryptedBlobStreamSegment::decode(&record.as_bytes()[4..])
            .map_err(|_| BlobPackError::Invalid("invalid Blob pack segment"))?;
        observe(
            record
                .bytes
                .capacity()
                .saturating_add(segment.owned_bytes()),
        );
        drop(record);
        observe(segment.owned_bytes());
        Ok(Some(segment))
    }

    pub fn next_record(&mut self) -> Result<Option<BlobPackRecord>, BlobPackError> {
        if self.next_index >= self.checkpoint.next_index {
            return Ok(None);
        }
        let mut len = [0; 4];
        self.data.read_exact(&mut len)?;
        let len = u32::from_be_bytes(len) as usize;
        if len == 0 || len > MAX_RECORD_BYTES {
            return Err(BlobPackError::Invalid("invalid Blob pack record length"));
        }
        let mut bytes = vec![0; 4 + len];
        bytes[..4].copy_from_slice(&(len as u32).to_be_bytes());
        self.data.read_exact(&mut bytes[4..])?;
        let header = EncryptedBlobStreamSegment::inspect_encoded(&bytes[4..])
            .map_err(|_| BlobPackError::Invalid("invalid Blob pack segment"))?;
        if header.index() != self.next_index
            || header.stream_id() != self.checkpoint.stream_id.as_bytes()
            || header.open_digest() != &self.checkpoint.open_digest
            || header.offset() != self.checkpoint_segment_offset(self.next_index)?
            || header.total_len() != self.checkpoint.total_len
        {
            return Err(BlobPackError::Invalid("non-contiguous Blob pack segment"));
        }
        self.next_index += 1;
        Ok(Some(BlobPackRecord { bytes }))
    }

    pub const fn checkpoint(&self) -> &BlobPackCheckpoint {
        &self.checkpoint
    }

    fn checkpoint_segment_offset(&self, index: u64) -> Result<u64, BlobPackError> {
        index
            .checked_mul(aster_mesh::BLOB_STREAM_SEGMENT_BYTES as u64)
            .ok_or(BlobPackError::Invalid("Blob pack segment offset overflow"))
    }
}

fn validate_header(data: &mut File, identity: BlobPackIdentity) -> Result<(), BlobPackError> {
    data.seek(SeekFrom::Start(0))?;
    let mut header = [0; PACK_HEADER_LEN as usize];
    data.read_exact(&mut header)?;
    if &header[..8] != PACK_MAGIC
        || u16::from_be_bytes(header[8..10].try_into().expect("version")) != PACK_VERSION
        || header[10..42] != identity.request_digest
        || header[42..74] != *identity.upload_id.as_bytes()
        || u64::from_be_bytes(header[74..82].try_into().expect("length")) != identity.total_len
    {
        return Err(BlobPackError::Invalid("Blob pack header identity mismatch"));
    }
    Ok(())
}

fn recover_checkpoint(
    root: &BlobPackRoot,
    identity: BlobPackIdentity,
    data_len: u64,
) -> Result<BlobPackCheckpoint, BlobPackError> {
    recover_checkpoints(root, identity, data_len)?
        .into_iter()
        .max_by_key(|checkpoint| checkpoint.generation)
        .ok_or(BlobPackError::Invalid("no valid Blob pack checkpoint"))
}

fn recover_checkpoints(
    root: &BlobPackRoot,
    identity: BlobPackIdentity,
    data_len: u64,
) -> Result<Vec<BlobPackCheckpoint>, BlobPackError> {
    let mut valid = Vec::new();
    for name in [CHECKPOINT_ZERO, CHECKPOINT_ONE] {
        let Some(bytes) = root.read_checkpoint(name)? else {
            continue;
        };
        let Ok(checkpoint) = BlobPackCheckpoint::decode(&bytes) else {
            continue;
        };
        if checkpoint.open_digest == identity.request_digest
            && checkpoint.stream_id == identity.upload_id
            && checkpoint.total_len == identity.total_len
            && checkpoint.pack_len <= data_len
        {
            valid.push(checkpoint);
        }
    }
    if valid.is_empty() {
        Err(BlobPackError::Invalid("no valid Blob pack checkpoint"))
    } else {
        Ok(valid)
    }
}

fn encode_completion_descriptor(
    completion: &BlobPackCompletion,
) -> Result<(Vec<u8>, [u8; 32]), BlobPackError> {
    let checkpoint = completion.checkpoint.encode();
    let checkpoint_len = u32::try_from(checkpoint.len())
        .map_err(|_| BlobPackError::Invalid("Blob pack completion checkpoint is oversized"))?;
    let mut encoded = Vec::with_capacity(8 + 2 + 4 + checkpoint.len() + 32 * 6 + 32);
    encoded.extend_from_slice(COMPLETION_MAGIC);
    encoded.extend_from_slice(&COMPLETION_VERSION.to_be_bytes());
    encoded.extend_from_slice(&checkpoint_len.to_be_bytes());
    encoded.extend_from_slice(&checkpoint);
    encoded.extend_from_slice(&completion.plaintext_root);
    encoded.extend_from_slice(&completion.ciphertext_root);
    encoded.extend_from_slice(completion.blob_id.as_bytes());
    encoded.extend_from_slice(&completion.commitment_digest);
    encoded.extend_from_slice(&completion.authenticated_commitment_digest);
    let digest: [u8; 32] = Sha256::digest(&encoded).into();
    encoded.extend_from_slice(&digest);
    Ok((encoded, digest))
}

fn decode_completion_descriptor(encoded: &[u8]) -> Result<BlobPackCompletion, BlobPackError> {
    if encoded.len() < 8 + 2 + 4 + 32 * 6
        || &encoded[..8] != COMPLETION_MAGIC
        || u16::from_be_bytes(encoded[8..10].try_into().expect("completion version"))
            != COMPLETION_VERSION
    {
        return Err(BlobPackError::Invalid(
            "invalid Blob pack completion descriptor",
        ));
    }
    let checksum_at = encoded.len() - 32;
    let descriptor_digest: [u8; 32] = Sha256::digest(&encoded[..checksum_at]).into();
    if encoded[checksum_at..] != descriptor_digest {
        return Err(BlobPackError::Invalid(
            "invalid Blob pack completion checksum",
        ));
    }
    let mut reader = Reader::new(&encoded[..checksum_at]);
    if reader.take(8)? != COMPLETION_MAGIC || reader.u16()? != COMPLETION_VERSION {
        return Err(BlobPackError::Invalid(
            "unsupported Blob pack completion descriptor",
        ));
    }
    let checkpoint_len = usize::try_from(reader.u32()?)
        .map_err(|_| BlobPackError::Invalid("invalid completion checkpoint length"))?;
    let checkpoint = BlobPackCheckpoint::decode(reader.take(checkpoint_len)?)?;
    let plaintext_root = reader.array()?;
    let ciphertext_root = reader.array()?;
    let blob_id = BlobId::from_bytes(reader.array()?);
    let commitment_digest = reader.array()?;
    let authenticated_commitment_digest = reader.array()?;
    reader.finish()?;
    if checkpoint.plaintext_offset() != checkpoint.total_len()
        || plaintext_root == [0; 32]
        || ciphertext_root == [0; 32]
        || commitment_digest == [0; 32]
        || authenticated_commitment_digest == [0; 32]
    {
        return Err(BlobPackError::Invalid("invalid completed Blob pack state"));
    }
    Ok(BlobPackCompletion {
        identity: BlobPackIdentity::new(
            checkpoint.stream_id(),
            *checkpoint.open_digest(),
            checkpoint.total_len(),
        ),
        checkpoint,
        plaintext_root,
        ciphertext_root,
        blob_id,
        commitment_digest,
        authenticated_commitment_digest,
        descriptor_digest,
    })
}

struct Reader<'a> {
    bytes: &'a [u8],
    position: usize,
}
impl<'a> Reader<'a> {
    const fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, position: 0 }
    }
    fn take(&mut self, len: usize) -> Result<&'a [u8], BlobPackError> {
        let end = self
            .position
            .checked_add(len)
            .ok_or(BlobPackError::Invalid("length overflow"))?;
        let value = self
            .bytes
            .get(self.position..end)
            .ok_or(BlobPackError::Invalid("truncated record"))?;
        self.position = end;
        Ok(value)
    }
    fn u8(&mut self) -> Result<u8, BlobPackError> {
        Ok(self.take(1)?[0])
    }
    fn array<const N: usize>(&mut self) -> Result<[u8; N], BlobPackError> {
        self.take(N)?
            .try_into()
            .map_err(|_| BlobPackError::Invalid("invalid field"))
    }
    fn u16(&mut self) -> Result<u16, BlobPackError> {
        Ok(u16::from_be_bytes(self.array()?))
    }
    fn u32(&mut self) -> Result<u32, BlobPackError> {
        Ok(u32::from_be_bytes(self.array()?))
    }
    fn u64(&mut self) -> Result<u64, BlobPackError> {
        Ok(u64::from_be_bytes(self.array()?))
    }
    fn finish(self) -> Result<(), BlobPackError> {
        if self.position == self.bytes.len() {
            Ok(())
        } else {
            Err(BlobPackError::Invalid("trailing record bytes"))
        }
    }
}

fn hex32(value: &[u8; 32]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(64);
    for byte in value {
        output.push(HEX[(byte >> 4) as usize] as char);
        output.push(HEX[(byte & 0x0f) as usize] as char);
    }
    output
}

#[cfg(test)]
mod tests {
    use super::*;
    use aster_mesh::{
        BLOB_STREAM_SEGMENT_BYTES, BlobMetadata, BlobStreamFinalCommitment,
        BlobStreamPlainPartition, BlobStreamSegmentSealer, Priority, ProvisioningAccess,
        ReferenceEnvelopeSealer, ReferenceProvisioner, Scope, Topic, VerifiedBlobStreamOpen,
        VersionVector,
    };
    use std::sync::atomic::{AtomicU64, Ordering};

    static TEMP_SEQUENCE: AtomicU64 = AtomicU64::new(1);

    struct TempRoot(PathBuf);
    impl TempRoot {
        fn new() -> Self {
            let path = std::env::temp_dir().join(format!(
                "aster-pack-test-{}-{}",
                std::process::id(),
                TEMP_SEQUENCE.fetch_add(1, Ordering::Relaxed)
            ));
            fs::create_dir(&path).expect("create temp root");
            Self(path)
        }
    }
    impl Drop for TempRoot {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    fn open(total_len: u64) -> BlobStreamOpen {
        BlobStreamOpen::new(
            BlobPublicationStreamId::from_bytes([0x11; 32]).expect("stream"),
            [0x21; 32],
            b"pack-test".to_vec(),
            [0x31; 32],
            1,
            VersionVector::default(),
            Topic::new("imagery").expect("topic"),
            Scope::new("mission/alpha").expect("scope"),
            BlobMetadata::new(Some("image/tiff".into()), Vec::new()).expect("metadata"),
            Priority::Immediate,
            None,
            None,
            total_len,
            1,
            1,
            [0x41; 32],
            [0x51; 32],
        )
        .expect("open")
    }

    fn segments(
        open: &BlobStreamOpen,
        count: u64,
    ) -> Vec<(EncryptedBlobStreamSegment, BlobStreamSegmentLeaves)> {
        let sealer = BlobStreamSegmentSealer::from_test_key(
            *open.stream_id().as_bytes(),
            open.digest(),
            open.content_epoch(),
            [0x61; 32],
            [0x71; 12],
        );
        (0..count)
            .map(|index| {
                let offset = index * BLOB_STREAM_SEGMENT_BYTES as u64;
                let len =
                    (open.total_len() - offset).min(BLOB_STREAM_SEGMENT_BYTES as u64) as usize;
                sealer
                    .seal(
                        BlobStreamPlainPartition::new(
                            *open.stream_id().as_bytes(),
                            open.digest(),
                            open.content_epoch(),
                            index,
                            offset,
                            open.total_len(),
                            vec![index as u8 + 1; len],
                        )
                        .expect("partition"),
                    )
                    .expect("seal")
            })
            .collect()
    }

    fn authenticated_open(
        total_len: u64,
    ) -> (
        BlobStreamOpen,
        VerifiedBlobStreamOpen,
        ReferenceEnvelopeSealer,
        ReferenceEnvelopeSealer,
    ) {
        let topic = Topic::new("imagery").expect("topic");
        let scope = Scope::new("mission/alpha").expect("scope");
        let access = ProvisioningAccess::member(scope.clone(), vec![1], vec![topic.clone()])
            .expect("access");
        let mut provisioner = ReferenceProvisioner::from_seed([0x91; 32]).expect("provisioner");
        let publisher = provisioner
            .issue_control_authority(1, std::slice::from_ref(&access))
            .and_then(ReferenceEnvelopeSealer::open)
            .expect("publisher");
        let reader = provisioner
            .issue_node(2, &[access])
            .and_then(ReferenceEnvelopeSealer::open)
            .expect("reader");
        let open = BlobStreamOpen::new(
            BlobPublicationStreamId::from_bytes([0x11; 32]).expect("stream"),
            publisher.identity(),
            b"pack-test".to_vec(),
            publisher.mission_authority_id(),
            1,
            VersionVector::default(),
            topic,
            scope.clone(),
            BlobMetadata::new(Some("image/tiff".into()), Vec::new()).expect("metadata"),
            Priority::Immediate,
            None,
            None,
            total_len,
            1,
            1,
            publisher
                .blob_stream_authorization_digest(&scope, 1)
                .expect("authorization"),
            [0x51; 32],
        )
        .expect("open");
        let authenticated = publisher.seal_blob_stream_open(&open).expect("sign open");
        let verified = reader
            .verify_blob_stream_open(&authenticated)
            .expect("verify open");
        (open, verified, publisher, reader)
    }

    #[test]
    fn canonical_sha256_snapshot_round_trips_and_rejects_impossible_state() {
        fn assert_zeroize_on_drop<T: zeroize::ZeroizeOnDrop>() {}
        assert_zeroize_on_drop::<Sha256>();
        for len in [0_usize, 1, 63, 64, 65, 64 * 1024 + 19] {
            let bytes = (0..len)
                .map(|index| (index % 251) as u8)
                .collect::<Vec<_>>();
            let mut hasher = Sha256::new();
            hasher.update(&bytes);
            let snapshot = sha256_state(&hasher);
            let restored = restore_sha256_state(&snapshot, len as u64).expect("restore state");
            assert_eq!(restored.finalize(), Sha256::digest(&bytes));
        }

        let mut hasher = Sha256::new();
        hasher.update(b"partial-state");
        let snapshot = sha256_state(&hasher);
        assert!(restore_sha256_state(&snapshot, 12).is_err());
        let mut impossible_buffer = snapshot;
        impossible_buffer[40] = 64;
        assert!(restore_sha256_state(&impossible_buffer, 13).is_err());
        let mut noncanonical_tail = snapshot;
        noncanonical_tail[104] = 1;
        assert!(restore_sha256_state(&noncanonical_tail, 13).is_err());
    }

    #[test]
    fn upload_digest_resume_separates_normal_v3_from_one_time_legacy_rebuild() {
        let root = TempRoot::new();
        let total_len = 2 * BLOB_STREAM_SEGMENT_BYTES as u64;
        let open = open(total_len);
        let identity = BlobPackIdentity::from_stream(&open);
        let segments = segments(&open, 2);
        let mut writer = BlobPackWriter::create(&root.0, &open).expect("create pack");
        let mut digests = BlobUploadDigestWriter::open_pack_root(
            BlobPackRoot::Path(root.0.clone()),
            identity,
            None,
        )
        .expect("create digest artifact");
        let plaintext = vec![1_u8; BLOB_STREAM_SEGMENT_BYTES];
        writer
            .append(&segments[0].0, segments[0].1)
            .expect("append first segment");
        digests.append(&plaintext).expect("digest first segment");
        let projected = writer
            .checkpoint_upload(&mut digests)
            .expect("combined checkpoint");
        assert_eq!(projected.format_version, CHECKPOINT_VERSION);
        drop(digests);

        let normal = BlobUploadDigestWriter::open_pack_root(
            BlobPackRoot::Path(root.0.clone()),
            identity,
            Some(&projected),
        )
        .expect("resume v3 artifact");
        assert_eq!(
            normal
                .migration_rebuild_bytes(projected.plaintext_offset())
                .expect("normal resume count"),
            0,
            "normal v3 resume must never replay staged plaintext"
        );
        drop(normal);

        let legacy = writer
            .checkpoint()
            .expect("legacy checkpoint without sidecar");
        assert_eq!(legacy.format_version, PACK_VERSION);
        let mut migrated = BlobUploadDigestWriter::open_pack_root(
            BlobPackRoot::Path(root.0.clone()),
            identity,
            Some(&legacy),
        )
        .expect("open pre-sidecar checkpoint");
        assert_eq!(
            migrated
                .migration_rebuild_bytes(legacy.plaintext_offset())
                .expect("legacy rebuild count"),
            BLOB_STREAM_SEGMENT_BYTES as u64,
            "legacy migration replays exactly the durable prefix once"
        );
        migrated.append(&plaintext).expect("rebuild legacy digests");
        let migrated_digest = migrated
            .checkpoint(legacy.plaintext_offset())
            .expect("checkpoint migrated artifact");
        drop(migrated);
        let mut migrated_projection = legacy.clone();
        migrated_projection.upload_digests = Some(migrated_digest);
        let normal_after_migration = BlobUploadDigestWriter::open_pack_root(
            BlobPackRoot::Path(root.0.clone()),
            identity,
            Some(&migrated_projection),
        )
        .expect("resume migrated artifact");
        assert_eq!(
            normal_after_migration
                .migration_rebuild_bytes(migrated_projection.plaintext_offset())
                .expect("post-migration resume count"),
            0
        );
        drop(normal_after_migration);

        let digest_path = root.0.join(UPLOAD_DIGEST_FILE);
        let mut bytes = fs::read(&digest_path).expect("read digest artifact");
        *bytes.last_mut().expect("nonempty artifact") ^= 0x40;
        fs::write(&digest_path, &bytes).expect("corrupt digest artifact");
        let len_before = fs::metadata(&digest_path).expect("artifact metadata").len();
        let error = match BlobUploadDigestWriter::open_pack_root(
            BlobPackRoot::Path(root.0.clone()),
            identity,
            Some(&migrated_projection),
        ) {
            Ok(_) => panic!("corrupt artifact resumed"),
            Err(error) => error,
        };
        assert!(matches!(error, BlobPackError::Invalid(_)));
        assert_eq!(
            fs::metadata(&digest_path)
                .expect("artifact after failure")
                .len(),
            len_before,
            "validation failure must precede truncation"
        );
    }

    #[test]
    fn upload_digest_v2_resume_recreates_a_torn_unprojected_sidecar() {
        let root = TempRoot::new();
        let total_len = BLOB_STREAM_SEGMENT_BYTES as u64;
        let open = open(total_len);
        let identity = BlobPackIdentity::from_stream(&open);
        let mut writer = BlobPackWriter::create(&root.0, &open).expect("create pack");
        let (segment, leaves) = segments(&open, 1).remove(0);
        writer.append(&segment, leaves).expect("append segment");
        let legacy = writer.checkpoint().expect("v2 checkpoint");
        assert_eq!(legacy.format_version, PACK_VERSION);

        fs::write(root.0.join(UPLOAD_DIGEST_FILE), b"ASTR")
            .expect("leave a torn pre-projection sidecar");
        let digests = BlobUploadDigestWriter::open_pack_root(
            BlobPackRoot::Path(root.0.clone()),
            identity,
            Some(&legacy),
        )
        .expect("genuine v2 state recovers a torn unprojected sidecar");
        assert_eq!(
            digests
                .migration_rebuild_bytes(legacy.plaintext_offset())
                .expect("legacy rebuild size"),
            total_len
        );
        assert_eq!(
            fs::metadata(root.0.join(UPLOAD_DIGEST_FILE))
                .expect("recreated sidecar")
                .len(),
            UPLOAD_DIGEST_HEADER_LEN
        );
    }

    #[test]
    fn upload_digest_atomic_creation_ignores_a_partial_private_temp() {
        let root = TempRoot::new();
        let open = open(4_096);
        let identity = BlobPackIdentity::from_stream(&open);
        drop(BlobPackWriter::create(&root.0, &open).expect("create pack"));
        let partial = root.0.join(format!("{PACK_TEMP_PREFIX}digest-crash"));
        fs::write(&partial, b"ASTR").expect("partial private temp");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            fs::set_permissions(&partial, fs::Permissions::from_mode(0o600))
                .expect("make temp private");
        }
        drop(
            BlobUploadDigestWriter::open_pack_root(
                BlobPackRoot::Path(root.0.clone()),
                identity,
                None,
            )
            .expect("partial temp is non-authoritative"),
        );
        assert_eq!(
            fs::metadata(root.0.join(UPLOAD_DIGEST_FILE))
                .expect("installed sidecar")
                .len(),
            UPLOAD_DIGEST_HEADER_LEN
        );
        assert!(
            partial.exists(),
            "crash temp remains safely non-authoritative"
        );
    }

    #[test]
    fn checkpoint_v3_rejects_missing_digest_projection() {
        let open = open(0);
        let mut checkpoint = BlobPackCheckpoint {
            format_version: CHECKPOINT_VERSION,
            generation: 1,
            open_digest: open.digest(),
            stream_id: open.stream_id(),
            total_len: 0,
            next_index: 0,
            plaintext_offset: 0,
            pack_len: PACK_HEADER_LEN,
            frontier: BlobStreamFrontier::new().checkpoint(),
            upload_digests: None,
            authority: None,
        };
        let encoded = checkpoint.encode();
        assert!(BlobPackCheckpoint::decode(&encoded).is_err());

        checkpoint.total_len = 1;
        let encoded = checkpoint.encode();
        assert!(BlobPackCheckpoint::decode(&encoded).is_err());
    }

    #[test]
    fn blob_pack_discards_uncheckpointed_tail_and_restores_frontier() {
        let root = TempRoot::new();
        let total_len = BLOB_STREAM_SEGMENT_BYTES as u64 * 2 + 17;
        let open = open(total_len);
        let segments = segments(&open, 3);
        let mut writer = BlobPackWriter::create(&root.0, &open).expect("create");
        writer
            .append(&segments[0].0, segments[0].1)
            .expect("append 0");
        let durable = writer.checkpoint().expect("checkpoint");
        writer
            .append(&segments[1].0, segments[1].1)
            .expect("append 1");
        drop(writer);

        let mut resumed = BlobPackWriter::resume(&root.0, &open).expect("resume");
        assert_eq!(resumed.next_index, 1);
        assert_eq!(resumed.pack_len, durable.pack_len());
        resumed
            .append(&segments[1].0, segments[1].1)
            .expect("reappend 1");
        resumed
            .append(&segments[2].0, segments[2].1)
            .expect("append 2");
        let roots = resumed.finish().expect("finish");

        let mut expected = BlobStreamFrontier::new();
        for (index, (_, leaves)) in segments.iter().enumerate() {
            expected
                .append(BlobStreamSubtree::leaf(index as u64, *leaves))
                .expect("frontier");
        }
        assert_eq!(roots, expected.finish(total_len).expect("expected roots"));
        let mut reader = BlobPackReader::open(&root.0, &open).expect("reader");
        for index in 0..3 {
            assert_eq!(
                reader
                    .next_segment()
                    .expect("read")
                    .expect("segment")
                    .index(),
                index
            );
        }
        assert!(reader.next_segment().expect("eof").is_none());
        let mut resumed_reader =
            BlobPackReader::open_at_payload_offset(&root.0, &open, 1, durable.payload_len())
                .expect("resume reader");
        assert_eq!(
            resumed_reader
                .next_segment()
                .expect("read resumed")
                .expect("resumed segment")
                .index(),
            1
        );
    }

    #[test]
    fn blob_pack_raw_reader_preserves_the_canonical_record() {
        let root = TempRoot::new();
        let open = open(BLOB_STREAM_SEGMENT_BYTES as u64);
        let segments = segments(&open, 1);
        let mut writer = BlobPackWriter::create(&root.0, &open).expect("create");
        writer
            .append(&segments[0].0, segments[0].1)
            .expect("append");
        writer.finish().expect("finish");

        let encoded = segments[0].0.encode();
        let mut expected = Vec::with_capacity(4 + encoded.len());
        expected.extend_from_slice(&(encoded.len() as u32).to_be_bytes());
        expected.extend_from_slice(&encoded);
        let mut reader = BlobPackReader::open(&root.0, &open).expect("reader");
        let record = reader.next_record().expect("read").expect("record");
        assert_eq!(record.as_bytes(), expected);
        assert!(reader.next_record().expect("eof").is_none());
    }

    #[test]
    fn completed_profile5_pack_is_exactly_the_uploaded_pack() {
        let root = TempRoot::new();
        let total_len = BLOB_STREAM_SEGMENT_BYTES as u64 + 17;
        let (open, verified, publisher, reader) = authenticated_open(total_len);
        let segments = segments(&open, 2);
        let mut writer = BlobPackWriter::create(&root.0, &open).expect("create pack");
        for (segment, leaves) in &segments {
            writer.append(segment, *leaves).expect("append segment");
        }
        writer.checkpoint().expect("checkpoint uploaded pack");
        let pack_before = fs::read(root.0.join(PACK_FILE)).expect("read uploaded pack");
        let roots = writer.final_roots().expect("final roots");
        let commitment = BlobStreamFinalCommitment::new(
            &verified,
            roots.0,
            roots.1,
            segments.len() as u64,
            None,
        )
        .expect("final commitment");
        let authenticated_commitment = publisher
            .seal_blob_stream_commitment(&commitment)
            .expect("sign commitment");
        let verified_commitment = reader
            .verify_blob_stream_commitment(&verified, &authenticated_commitment)
            .expect("verify commitment");

        let completion = writer
            .finish_profile5(&verified_commitment)
            .expect("complete pack");
        assert_eq!(
            fs::read(root.0.join(PACK_FILE)).expect("read completed pack"),
            pack_before,
            "completion must not rewrite or convert encrypted segment bytes"
        );
        assert_eq!(completion.segment_count(), 2);
        assert_eq!(completion.plaintext_root(), &roots.0);
        assert_eq!(completion.ciphertext_root(), &roots.1);
        assert_eq!(completion.blob_id(), commitment.blob_id());

        let mut completed =
            BlobPackReader::open_completed(&root.0, &completion).expect("open completed pack");
        for (segment, _) in &segments {
            let record = completed
                .next_record()
                .expect("read record")
                .expect("record");
            assert_eq!(&record.as_bytes()[4..], segment.encode());
        }
        assert!(completed.next_record().expect("completed eof").is_none());
    }

    #[test]
    fn blob_pack_reader_observes_encoded_and_decoded_capacity_overlap() {
        let root = TempRoot::new();
        let open = open(BLOB_STREAM_SEGMENT_BYTES as u64);
        let segments = segments(&open, 1);
        let mut writer = BlobPackWriter::create(&root.0, &open).expect("create");
        writer
            .append(&segments[0].0, segments[0].1)
            .expect("append");
        writer.finish().expect("finish");

        let mut observed = Vec::new();
        let mut reader = BlobPackReader::open(&root.0, &open).expect("reader");
        let segment = reader
            .next_segment_observing_owned_bytes(|bytes| observed.push(bytes))
            .expect("read")
            .expect("segment");
        assert_eq!(observed.len(), 2);
        assert_eq!(observed[1], segment.owned_bytes());
        assert!(observed[0] > observed[1]);
        assert!(observed[0] >= 2 * BLOB_STREAM_SEGMENT_BYTES);
    }

    #[test]
    fn blob_pack_uses_older_complete_checkpoint_when_newest_is_corrupt() {
        let root = TempRoot::new();
        let total_len = BLOB_STREAM_SEGMENT_BYTES as u64 * 2;
        let open = open(total_len);
        let segments = segments(&open, 2);
        let mut writer = BlobPackWriter::create(&root.0, &open).expect("create");
        writer
            .append(&segments[0].0, segments[0].1)
            .expect("append 0");
        let older = writer.checkpoint().expect("older checkpoint");
        writer
            .append(&segments[1].0, segments[1].1)
            .expect("append 1");
        let newest = writer.checkpoint().expect("newest checkpoint");
        assert!(newest.generation() > older.generation());
        drop(writer);
        let newest_path = root.0.join(if newest.generation().is_multiple_of(2) {
            CHECKPOINT_ZERO
        } else {
            CHECKPOINT_ONE
        });
        let mut bytes = fs::read(&newest_path).expect("read newest");
        bytes[32] ^= 1;
        fs::write(newest_path, bytes).expect("corrupt newest");
        let resumed = BlobPackWriter::resume(&root.0, &open).expect("resume older");
        assert_eq!(resumed.generation, older.generation());
        assert_eq!(resumed.next_index, older.next_index());
        assert_eq!(resumed.pack_len, older.pack_len());
    }

    #[test]
    fn blob_pack_resumes_from_store_projected_checkpoint_not_newest_journal() {
        let root = TempRoot::new();
        let total_len = BLOB_STREAM_SEGMENT_BYTES as u64 * 2;
        let open = open(total_len);
        let segments = segments(&open, 2);
        let mut writer = BlobPackWriter::create(&root.0, &open).expect("create");
        writer
            .append(&segments[0].0, segments[0].1)
            .expect("append 0");
        let projected = writer.checkpoint().expect("projected checkpoint");
        writer
            .append(&segments[1].0, segments[1].1)
            .expect("append 1");
        let unprojected = writer.checkpoint().expect("unprojected checkpoint");
        assert!(unprojected.generation() > projected.generation());
        drop(writer);

        let mut resumed = BlobPackWriter::open_projected(
            &root.0,
            &open,
            projected.generation(),
            projected.next_index(),
            projected.plaintext_offset(),
            projected.pack_len(),
            projected.payload_len(),
        )
        .expect("resume projected");
        assert_eq!(resumed.generation, projected.generation());
        assert_eq!(resumed.next_index, 1);
        assert_eq!(resumed.pack_len, projected.pack_len());
        resumed
            .append(&segments[1].0, segments[1].1)
            .expect("replace unprojected segment");
    }

    #[test]
    fn blob_pack_resumes_empty_projection_over_existing_unprojected_pack() {
        let root = TempRoot::new();
        let total_len = BLOB_STREAM_SEGMENT_BYTES as u64;
        let open = open(total_len);
        let segments = segments(&open, 1);
        let mut writer = BlobPackWriter::create(&root.0, &open).expect("create");
        writer
            .append(&segments[0].0, segments[0].1)
            .expect("append 0");
        writer.checkpoint().expect("unprojected checkpoint");
        drop(writer);

        let mut resumed =
            BlobPackWriter::open_projected(&root.0, &open, 0, 0, 0, 0, 0).expect("resume empty");
        assert_eq!(resumed.next_index, 0);
        assert_eq!(resumed.plaintext_offset, 0);
        assert_eq!(resumed.pack_len, PACK_HEADER_LEN);
        resumed
            .append(&segments[0].0, segments[0].1)
            .expect("replace unprojected segment");
    }
}
