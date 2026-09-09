use crate::provider_generation;
use aster_mesh::{ProvisioningLoadId, ProvisioningSecretRef, ProvisioningSecretStoreError};
use rustix::fd::OwnedFd;
use std::{
    collections::BTreeSet,
    fs::File,
    io::{Read as _, Write as _},
    path::{Component, Path},
};
use zeroize::Zeroizing;

const MANIFEST_MAGIC: &[u8; 8] = b"ASTRSDM1";
const MANIFEST_VERSION: u16 = 2;
const MANIFEST_HEADER_BYTES: usize = 8 + 2 + 2 + 8 + 32 + 32 + 4;
const MAX_MANIFEST_BYTES: usize =
    MANIFEST_HEADER_BYTES + aster_mesh::MAX_PROVISIONING_SECRET_REF_BYTES;
const MAX_HOST_KEY_BYTES: usize = 64 * 1024;
const EXT4_SUPER_MAGIC: i64 = 0xef53;

pub(super) const ACTIVE_DIRECTORY: &str = "active";
pub(super) const PREVIOUS_DIRECTORY: &str = "previous";
pub(super) const STAGED_DIRECTORY: &str = "staged";
pub(super) const CIPHERTEXT_FILE: &str = "credential.cred";
pub(super) const REFERENCE_FILE: &str = "reference";
pub(super) const MANIFEST_FILE: &str = "manifest";
pub(super) const TOMBSTONE_FILE: &str = "tombstone";
pub(super) const LEDGER_FILE: &str = "ledger";
pub(super) const LEDGER_NEXT_FILE: &str = "ledger.next";
pub(super) const LOCK_FILE: &str = "lock";

#[allow(dead_code)] // Later lifecycle operations select the task-specific points.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum FaultPoint {
    StageCiphertextSynced,
    StageReferenceSynced,
    StageManifestSynced,
    StageDirectorySynced,
    StageParentSynced,
    StagedTombstoneSynced,
    IntentFileSynced,
    IntentRenamed,
    IntentParentSynced,
    IntentParentReplayed,
    PendingLedgerFileSyncFailed,
    PendingLedgerFileSynced,
    ActiveRenamed,
    ActiveParentSynced,
    ActiveExchanged,
    PreviousExchanged,
    PreviousRenamed,
    CleanupGenerationRenamed,
    CleanupParentSynced,
    CleanupContentDeleted,
    CleanupReferenceDeleted,
    CleanupManifestDeleted,
    CleanupContentsDeleted,
    CleanupDirectoryDeleted,
    CleanupRemovalParentSynced,
    ReplacedGenerationDeleted,
    ProvisioningParentSynced,
    RecoveredActiveParentSyncFailed,
    CompleteFileSynced,
    CompleteRenamed,
    CompleteParentSynced,
    CompletedLedgerParentSynced,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum LedgerWrite {
    Intent,
    Complete,
}

#[derive(Debug, Default)]
pub(super) struct FaultInjector {
    point: Option<FaultPoint>,
}

impl FaultInjector {
    pub(super) const fn disabled() -> Self {
        Self { point: None }
    }

    #[cfg(test)]
    pub(super) const fn at(point: FaultPoint) -> Self {
        Self { point: Some(point) }
    }

    pub(super) fn hit(&mut self, point: FaultPoint) -> Result<(), ProvisioningSecretStoreError> {
        if self.point == Some(point) {
            self.point = None;
            Err(ProvisioningSecretStoreError::Unavailable)
        } else {
            Ok(())
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) struct GenerationManifest {
    pub(super) generation: u64,
    pub(super) load: ProvisioningLoadId,
    pub(super) secret_ref: ProvisioningSecretRef,
    pub(super) ciphertext_digest: [u8; 32],
    pub(super) content: GenerationContent,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum GenerationContent {
    Credential,
    Tombstone,
}

pub(super) fn encode_manifest(manifest: &GenerationManifest) -> Vec<u8> {
    let reference = Zeroizing::new(manifest.secret_ref.to_bytes());
    let reference_len =
        u32::try_from(reference.len()).expect("bounded provisioning reference fits in u32");
    let mut encoded = Vec::with_capacity(MANIFEST_HEADER_BYTES + reference.len());
    encoded.extend_from_slice(MANIFEST_MAGIC);
    encoded.extend_from_slice(&MANIFEST_VERSION.to_be_bytes());
    encoded.push(match manifest.content {
        GenerationContent::Credential => 0,
        GenerationContent::Tombstone => 1,
    });
    encoded.push(0);
    encoded.extend_from_slice(&manifest.generation.to_be_bytes());
    encoded.extend_from_slice(manifest.load.as_bytes());
    encoded.extend_from_slice(&manifest.ciphertext_digest);
    encoded.extend_from_slice(&reference_len.to_be_bytes());
    encoded.extend_from_slice(&reference);
    encoded
}

pub(super) fn decode_manifest(
    encoded: &[u8],
) -> Result<GenerationManifest, ProvisioningSecretStoreError> {
    if encoded.len() < MANIFEST_HEADER_BYTES
        || &encoded[..8] != MANIFEST_MAGIC
        || read_u16(&encoded[8..10])? != MANIFEST_VERSION
        || encoded[11] != 0
    {
        return Err(ProvisioningSecretStoreError::Rejected);
    }
    let content = match encoded[10] {
        0 => GenerationContent::Credential,
        1 => GenerationContent::Tombstone,
        _ => return Err(ProvisioningSecretStoreError::Rejected),
    };
    let generation = read_u64(&encoded[12..20])?;
    if generation == 0 {
        return Err(ProvisioningSecretStoreError::Rejected);
    }
    let load = ProvisioningLoadId::new(read_array(&encoded[20..52])?);
    let ciphertext_digest = read_array(&encoded[52..84])?;
    let reference_len = usize::try_from(read_u32(&encoded[84..88])?)
        .map_err(|_| ProvisioningSecretStoreError::Rejected)?;
    if MANIFEST_HEADER_BYTES.checked_add(reference_len) != Some(encoded.len()) {
        return Err(ProvisioningSecretStoreError::Rejected);
    }
    let secret_ref = ProvisioningSecretRef::from_bytes(&encoded[MANIFEST_HEADER_BYTES..])
        .map_err(|_| ProvisioningSecretStoreError::Rejected)?;
    if provider_generation(&secret_ref).map_err(|_| ProvisioningSecretStoreError::Rejected)?
        != generation
    {
        return Err(ProvisioningSecretStoreError::Rejected);
    }
    if content == GenerationContent::Tombstone && ciphertext_digest != [0; 32] {
        return Err(ProvisioningSecretStoreError::Rejected);
    }
    Ok(GenerationManifest {
        generation,
        load,
        secret_ref,
        ciphertext_digest,
        content,
    })
}

fn read_array<const N: usize>(bytes: &[u8]) -> Result<[u8; N], ProvisioningSecretStoreError> {
    bytes
        .try_into()
        .map_err(|_| ProvisioningSecretStoreError::Rejected)
}

fn read_u16(bytes: &[u8]) -> Result<u16, ProvisioningSecretStoreError> {
    read_array(bytes).map(u16::from_be_bytes)
}

fn read_u32(bytes: &[u8]) -> Result<u32, ProvisioningSecretStoreError> {
    read_array(bytes).map(u32::from_be_bytes)
}

fn read_u64(bytes: &[u8]) -> Result<u64, ProvisioningSecretStoreError> {
    read_array(bytes).map(u64::from_be_bytes)
}

pub(super) fn open_secure_root(
    path: &Path,
    require_ext4: bool,
) -> Result<OwnedFd, ProvisioningSecretStoreError> {
    if !path.is_absolute()
        || path
            .components()
            .any(|component| matches!(component, Component::CurDir | Component::ParentDir))
    {
        return Err(ProvisioningSecretStoreError::Rejected);
    }
    let directory = rustix::fs::openat2(
        rustix::fs::CWD,
        path,
        rustix::fs::OFlags::RDONLY
            | rustix::fs::OFlags::DIRECTORY
            | rustix::fs::OFlags::CLOEXEC
            | rustix::fs::OFlags::NOFOLLOW,
        rustix::fs::Mode::empty(),
        rustix::fs::ResolveFlags::NO_SYMLINKS | rustix::fs::ResolveFlags::NO_MAGICLINKS,
    )
    .map_err(|error| {
        if error == rustix::io::Errno::NOENT {
            ProvisioningSecretStoreError::Unavailable
        } else {
            ProvisioningSecretStoreError::Rejected
        }
    })?;
    validate_directory(&directory, require_ext4)?;
    Ok(directory)
}

fn validate_directory(
    directory: &OwnedFd,
    require_ext4: bool,
) -> Result<(), ProvisioningSecretStoreError> {
    let stat =
        rustix::fs::fstat(directory).map_err(|_| ProvisioningSecretStoreError::Unavailable)?;
    if rustix::fs::FileType::from_raw_mode(stat.st_mode) != rustix::fs::FileType::Directory
        || stat.st_uid != rustix::process::geteuid().as_raw()
        || stat.st_mode & 0o7777 != 0o700
    {
        return Err(ProvisioningSecretStoreError::Rejected);
    }
    if require_ext4 {
        let filesystem = rustix::fs::fstatfs(directory)
            .map_err(|_| ProvisioningSecretStoreError::Unavailable)?;
        if filesystem.f_type as i64 != EXT4_SUPER_MAGIC {
            return Err(ProvisioningSecretStoreError::Rejected);
        }
    }
    Ok(())
}

pub(super) fn open_namespace_lock(
    ledger_root: &OwnedFd,
) -> Result<OwnedFd, ProvisioningSecretStoreError> {
    let lock = rustix::fs::openat(
        ledger_root,
        LOCK_FILE,
        rustix::fs::OFlags::RDWR
            | rustix::fs::OFlags::CREATE
            | rustix::fs::OFlags::CLOEXEC
            | rustix::fs::OFlags::NOFOLLOW,
        rustix::fs::Mode::RUSR | rustix::fs::Mode::WUSR,
    )
    .map_err(|error| {
        if error == rustix::io::Errno::LOOP {
            ProvisioningSecretStoreError::Rejected
        } else {
            ProvisioningSecretStoreError::Unavailable
        }
    })?;
    validate_regular(&lock, 0o600)?;
    rustix::fs::flock(&lock, rustix::fs::FlockOperation::NonBlockingLockExclusive)
        .map_err(|_| ProvisioningSecretStoreError::Unavailable)?;
    Ok(lock)
}

fn validate_regular(descriptor: &OwnedFd, mode: u32) -> Result<(), ProvisioningSecretStoreError> {
    let stat =
        rustix::fs::fstat(descriptor).map_err(|_| ProvisioningSecretStoreError::Unavailable)?;
    if rustix::fs::FileType::from_raw_mode(stat.st_mode) != rustix::fs::FileType::RegularFile
        || stat.st_uid != rustix::process::geteuid().as_raw()
        || stat.st_mode & 0o7777 != mode
        || stat.st_nlink != 1
    {
        return Err(ProvisioningSecretStoreError::Rejected);
    }
    Ok(())
}

pub(super) fn read_host_key_identity(
    path: &Path,
) -> Result<[u8; 32], ProvisioningSecretStoreError> {
    if !path.is_absolute()
        || path
            .components()
            .any(|component| matches!(component, Component::CurDir | Component::ParentDir))
    {
        return Err(ProvisioningSecretStoreError::Rejected);
    }
    let parent = path
        .parent()
        .ok_or(ProvisioningSecretStoreError::Rejected)?;
    let name = path
        .file_name()
        .ok_or(ProvisioningSecretStoreError::Rejected)?;
    let directory = rustix::fs::openat2(
        rustix::fs::CWD,
        parent,
        rustix::fs::OFlags::RDONLY
            | rustix::fs::OFlags::DIRECTORY
            | rustix::fs::OFlags::CLOEXEC
            | rustix::fs::OFlags::NOFOLLOW,
        rustix::fs::Mode::empty(),
        rustix::fs::ResolveFlags::NO_SYMLINKS | rustix::fs::ResolveFlags::NO_MAGICLINKS,
    )
    .map_err(|error| match error {
        rustix::io::Errno::NOENT | rustix::io::Errno::ACCESS => {
            ProvisioningSecretStoreError::Unavailable
        }
        _ => ProvisioningSecretStoreError::Rejected,
    })?;
    let descriptor = rustix::fs::openat(
        &directory,
        name,
        rustix::fs::OFlags::RDONLY
            | rustix::fs::OFlags::CLOEXEC
            | rustix::fs::OFlags::NOFOLLOW
            | rustix::fs::OFlags::NONBLOCK,
        rustix::fs::Mode::empty(),
    )
    .map_err(|error| match error {
        rustix::io::Errno::LOOP => ProvisioningSecretStoreError::Rejected,
        _ => ProvisioningSecretStoreError::Unavailable,
    })?;
    let stat =
        rustix::fs::fstat(&descriptor).map_err(|_| ProvisioningSecretStoreError::Unavailable)?;
    if rustix::fs::FileType::from_raw_mode(stat.st_mode) != rustix::fs::FileType::RegularFile
        || stat.st_uid != rustix::process::geteuid().as_raw()
        || stat.st_mode & 0o077 != 0
        || stat.st_nlink != 1
    {
        return Err(ProvisioningSecretStoreError::Rejected);
    }
    let size = usize::try_from(stat.st_size).map_err(|_| ProvisioningSecretStoreError::TooLarge)?;
    if size == 0 || size > MAX_HOST_KEY_BYTES {
        return Err(if size == 0 {
            ProvisioningSecretStoreError::Rejected
        } else {
            ProvisioningSecretStoreError::TooLarge
        });
    }
    let mut key = Zeroizing::new(Vec::with_capacity(size));
    File::from(descriptor)
        .take((MAX_HOST_KEY_BYTES + 1) as u64)
        .read_to_end(&mut key)
        .map_err(|_| ProvisioningSecretStoreError::Unavailable)?;
    if key.is_empty() || key.len() > MAX_HOST_KEY_BYTES {
        return Err(if key.is_empty() {
            ProvisioningSecretStoreError::Rejected
        } else {
            ProvisioningSecretStoreError::TooLarge
        });
    }
    Ok(crate::admin::digest(&key))
}

pub(super) fn read_optional_file(
    directory: &OwnedFd,
    name: &str,
    maximum: usize,
) -> Result<Option<Zeroizing<Vec<u8>>>, ProvisioningSecretStoreError> {
    let descriptor = match rustix::fs::openat(
        directory,
        name,
        rustix::fs::OFlags::RDONLY
            | rustix::fs::OFlags::CLOEXEC
            | rustix::fs::OFlags::NOFOLLOW
            | rustix::fs::OFlags::NONBLOCK,
        rustix::fs::Mode::empty(),
    ) {
        Ok(descriptor) => descriptor,
        Err(rustix::io::Errno::NOENT) => return Ok(None),
        Err(_) => return Err(ProvisioningSecretStoreError::Unavailable),
    };
    validate_regular(&descriptor, 0o600)?;
    let stat =
        rustix::fs::fstat(&descriptor).map_err(|_| ProvisioningSecretStoreError::Unavailable)?;
    let size = usize::try_from(stat.st_size).map_err(|_| ProvisioningSecretStoreError::TooLarge)?;
    if size > maximum {
        return Err(ProvisioningSecretStoreError::TooLarge);
    }
    let mut bytes = Zeroizing::new(Vec::with_capacity(size));
    File::from(descriptor)
        .take((maximum + 1) as u64)
        .read_to_end(&mut bytes)
        .map_err(|_| ProvisioningSecretStoreError::Unavailable)?;
    if bytes.len() > maximum {
        return Err(ProvisioningSecretStoreError::TooLarge);
    }
    Ok(Some(bytes))
}

pub(super) fn read_ledger(
    ledger_root: &OwnedFd,
) -> Result<Option<Zeroizing<Vec<u8>>>, ProvisioningSecretStoreError> {
    read_optional_file(ledger_root, LEDGER_FILE, super::ledger::MAX_LEDGER_BYTES)
}

pub(super) fn read_pending_ledger(
    ledger_root: &OwnedFd,
) -> Result<Option<Zeroizing<Vec<u8>>>, ProvisioningSecretStoreError> {
    read_optional_file(
        ledger_root,
        LEDGER_NEXT_FILE,
        super::ledger::MAX_LEDGER_BYTES,
    )
}

pub(super) fn publish_pending_ledger(
    ledger_root: &OwnedFd,
    expected: &[u8],
    faults: &mut FaultInjector,
) -> Result<(), ProvisioningSecretStoreError> {
    // Read and synchronize the same secure descriptor: ledger.next may contain
    // complete bytes from a write interrupted before its original file sync.
    let descriptor = rustix::fs::openat(
        ledger_root,
        LEDGER_NEXT_FILE,
        rustix::fs::OFlags::RDONLY
            | rustix::fs::OFlags::CLOEXEC
            | rustix::fs::OFlags::NOFOLLOW
            | rustix::fs::OFlags::NONBLOCK,
        rustix::fs::Mode::empty(),
    )
    .map_err(|_| ProvisioningSecretStoreError::Rejected)?;
    validate_regular(&descriptor, 0o600)?;
    let stat =
        rustix::fs::fstat(&descriptor).map_err(|_| ProvisioningSecretStoreError::Unavailable)?;
    let size = usize::try_from(stat.st_size).map_err(|_| ProvisioningSecretStoreError::TooLarge)?;
    let maximum = super::ledger::MAX_LEDGER_BYTES;
    if size > maximum {
        return Err(ProvisioningSecretStoreError::TooLarge);
    }
    let file = File::from(descriptor);
    let mut pending = Zeroizing::new(Vec::with_capacity(size));
    (&file)
        .take((maximum + 1) as u64)
        .read_to_end(&mut pending)
        .map_err(|_| ProvisioningSecretStoreError::Unavailable)?;
    if pending.len() > maximum {
        return Err(ProvisioningSecretStoreError::TooLarge);
    }
    if pending.as_slice() != expected {
        return Err(ProvisioningSecretStoreError::Rejected);
    }
    faults.hit(FaultPoint::PendingLedgerFileSyncFailed)?;
    file.sync_all()
        .map_err(|_| ProvisioningSecretStoreError::Unavailable)?;
    faults.hit(FaultPoint::PendingLedgerFileSynced)?;
    rustix::fs::renameat(ledger_root, LEDGER_NEXT_FILE, ledger_root, LEDGER_FILE)
        .map_err(|_| ProvisioningSecretStoreError::Unavailable)?;
    faults.hit(FaultPoint::IntentRenamed)?;
    sync_directory(ledger_root)?;
    faults.hit(FaultPoint::IntentParentSynced)
}

pub(super) fn write_ledger_atomically(
    ledger_root: &OwnedFd,
    bytes: &[u8],
    write: LedgerWrite,
    faults: &mut FaultInjector,
) -> Result<(), ProvisioningSecretStoreError> {
    remove_optional_file(ledger_root, LEDGER_NEXT_FILE)?;
    write_new_file(ledger_root, LEDGER_NEXT_FILE, bytes)?;
    faults.hit(match write {
        LedgerWrite::Intent => FaultPoint::IntentFileSynced,
        LedgerWrite::Complete => FaultPoint::CompleteFileSynced,
    })?;
    rustix::fs::renameat(ledger_root, LEDGER_NEXT_FILE, ledger_root, LEDGER_FILE)
        .map_err(|_| ProvisioningSecretStoreError::Unavailable)?;
    faults.hit(match write {
        LedgerWrite::Intent => FaultPoint::IntentRenamed,
        LedgerWrite::Complete => FaultPoint::CompleteRenamed,
    })?;
    sync_directory(ledger_root)?;
    faults.hit(match write {
        LedgerWrite::Intent => FaultPoint::IntentParentSynced,
        LedgerWrite::Complete => FaultPoint::CompleteParentSynced,
    })
}

pub(super) fn write_staged_generation(
    provisioning_root: &OwnedFd,
    ciphertext: &[u8],
    reference: &[u8],
    manifest: &[u8],
    faults: &mut FaultInjector,
) -> Result<(), ProvisioningSecretStoreError> {
    rustix::fs::mkdirat(provisioning_root, STAGED_DIRECTORY, rustix::fs::Mode::RWXU)
        .map_err(|_| ProvisioningSecretStoreError::Unavailable)?;
    let staged = open_child_directory(provisioning_root, STAGED_DIRECTORY)?;
    write_new_file(&staged, CIPHERTEXT_FILE, ciphertext)?;
    faults.hit(FaultPoint::StageCiphertextSynced)?;
    write_new_file(&staged, REFERENCE_FILE, reference)?;
    faults.hit(FaultPoint::StageReferenceSynced)?;
    write_new_file(&staged, MANIFEST_FILE, manifest)?;
    faults.hit(FaultPoint::StageManifestSynced)?;
    sync_directory(&staged)?;
    faults.hit(FaultPoint::StageDirectorySynced)?;
    sync_directory(provisioning_root)?;
    faults.hit(FaultPoint::StageParentSynced)
}

pub(super) fn promote_staged_generation(
    provisioning_root: &OwnedFd,
    faults: &mut FaultInjector,
) -> Result<(), ProvisioningSecretStoreError> {
    rustix::fs::renameat(
        provisioning_root,
        STAGED_DIRECTORY,
        provisioning_root,
        ACTIVE_DIRECTORY,
    )
    .map_err(|_| ProvisioningSecretStoreError::Unavailable)?;
    faults.hit(FaultPoint::ActiveRenamed)?;
    sync_directory(provisioning_root)?;
    faults.hit(FaultPoint::ActiveParentSynced)
}

pub(super) fn sync_recovered_active_parent(
    provisioning_root: &OwnedFd,
    faults: &mut FaultInjector,
) -> Result<(), ProvisioningSecretStoreError> {
    faults.hit(FaultPoint::RecoveredActiveParentSyncFailed)?;
    sync_directory(provisioning_root)
}

pub(super) fn remove_staged_generation(
    provisioning_root: &OwnedFd,
) -> Result<(), ProvisioningSecretStoreError> {
    let Some(staged) = open_optional_child_directory(provisioning_root, STAGED_DIRECTORY)? else {
        return Ok(());
    };
    for name in [CIPHERTEXT_FILE, REFERENCE_FILE, MANIFEST_FILE] {
        remove_optional_file(&staged, name)?;
    }
    drop(staged);
    rustix::fs::unlinkat(
        provisioning_root,
        STAGED_DIRECTORY,
        rustix::fs::AtFlags::REMOVEDIR,
    )
    .map_err(|_| ProvisioningSecretStoreError::Unavailable)?;
    sync_directory(provisioning_root)
}

pub(super) fn read_generation_manifest(
    provisioning_root: &OwnedFd,
    name: &str,
) -> Result<Option<GenerationManifest>, ProvisioningSecretStoreError> {
    let directory = match open_optional_child_directory(provisioning_root, name)? {
        Some(directory) => directory,
        None => return Ok(None),
    };
    let manifest = read_optional_file(&directory, MANIFEST_FILE, MAX_MANIFEST_BYTES)?
        .ok_or(ProvisioningSecretStoreError::Rejected)?;
    decode_manifest(&manifest).map(Some)
}

pub(super) fn child_directory_exists(
    provisioning_root: &OwnedFd,
    name: &str,
) -> Result<bool, ProvisioningSecretStoreError> {
    open_optional_child_directory(provisioning_root, name).map(|directory| directory.is_some())
}

pub(super) fn generation_matches(
    provisioning_root: &OwnedFd,
    name: &str,
    expected: &GenerationManifest,
) -> Result<bool, ProvisioningSecretStoreError> {
    if !generation_identity_matches(provisioning_root, name, expected)? {
        return Ok(false);
    }
    let Some(directory) = open_optional_child_directory(provisioning_root, name)? else {
        return Ok(false);
    };
    match expected.content {
        GenerationContent::Credential => {
            if read_optional_file(&directory, TOMBSTONE_FILE, 0)?.is_some() {
                return Ok(false);
            }
            let ciphertext = read_optional_file(
                &directory,
                CIPHERTEXT_FILE,
                aster_mesh::MAX_PROTECTED_PROVISIONING_BYTES,
            )?
            .ok_or(ProvisioningSecretStoreError::Rejected)?;
            Ok(crate::admin::digest(&ciphertext) == expected.ciphertext_digest)
        }
        GenerationContent::Tombstone => {
            if read_optional_file(
                &directory,
                CIPHERTEXT_FILE,
                aster_mesh::MAX_PROTECTED_PROVISIONING_BYTES,
            )?
            .is_some()
            {
                return Ok(false);
            }
            Ok(read_optional_file(&directory, TOMBSTONE_FILE, 0)?.is_some())
        }
    }
}

pub(super) fn read_exact_generation_ciphertext(
    provisioning_root: &OwnedFd,
    name: &str,
    expected: &GenerationManifest,
) -> Result<Zeroizing<Vec<u8>>, ProvisioningSecretStoreError> {
    if expected.content != GenerationContent::Credential
        || !generation_identity_matches(provisioning_root, name, expected)?
    {
        return Err(ProvisioningSecretStoreError::Rejected);
    }
    let directory = open_child_directory(provisioning_root, name)?;
    let ciphertext = read_optional_file(
        &directory,
        CIPHERTEXT_FILE,
        aster_mesh::MAX_PROTECTED_PROVISIONING_BYTES,
    )?
    .ok_or(ProvisioningSecretStoreError::Rejected)?;
    if super::digest(&ciphertext) != expected.ciphertext_digest {
        return Err(ProvisioningSecretStoreError::Rejected);
    }
    Ok(ciphertext)
}

pub(super) fn generation_identity_matches(
    provisioning_root: &OwnedFd,
    name: &str,
    expected: &GenerationManifest,
) -> Result<bool, ProvisioningSecretStoreError> {
    let Some(directory) = open_optional_child_directory(provisioning_root, name)? else {
        return Ok(false);
    };
    let manifest = read_optional_file(&directory, MANIFEST_FILE, MAX_MANIFEST_BYTES)?
        .ok_or(ProvisioningSecretStoreError::Rejected)?;
    if decode_manifest(&manifest)? != *expected {
        return Ok(false);
    }
    let reference = read_optional_file(
        &directory,
        REFERENCE_FILE,
        aster_mesh::MAX_PROVISIONING_SECRET_REF_BYTES,
    )?
    .ok_or(ProvisioningSecretStoreError::Rejected)?;
    let expected_reference = Zeroizing::new(expected.secret_ref.to_bytes());
    if reference.as_slice() != expected_reference.as_slice() {
        return Ok(false);
    }
    let expected_entries = match expected.content {
        GenerationContent::Credential => [CIPHERTEXT_FILE, REFERENCE_FILE, MANIFEST_FILE],
        GenerationContent::Tombstone => [TOMBSTONE_FILE, REFERENCE_FILE, MANIFEST_FILE],
    };
    if !directory_has_exact_entries(&directory, &expected_entries)? {
        return Ok(false);
    }
    match expected.content {
        GenerationContent::Credential => Ok(read_optional_file(
            &directory,
            CIPHERTEXT_FILE,
            aster_mesh::MAX_PROTECTED_PROVISIONING_BYTES,
        )?
        .is_some()
            && read_optional_file(&directory, TOMBSTONE_FILE, 0)?.is_none()),
        GenerationContent::Tombstone => Ok(read_optional_file(
            &directory,
            CIPHERTEXT_FILE,
            aster_mesh::MAX_PROTECTED_PROVISIONING_BYTES,
        )?
        .is_none()
            && read_optional_file(&directory, TOMBSTONE_FILE, 0)?.is_some()),
    }
}

pub(super) fn directory_has_exact_entries(
    directory: &OwnedFd,
    expected: &[&str],
) -> Result<bool, ProvisioningSecretStoreError> {
    let mut entries = BTreeSet::new();
    let mut reader = rustix::fs::Dir::read_from(directory)
        .map_err(|_| ProvisioningSecretStoreError::Unavailable)?;
    while let Some(entry) = reader.read() {
        let entry = entry.map_err(|_| ProvisioningSecretStoreError::Unavailable)?;
        let name = entry.file_name().to_bytes();
        if name != b"." && name != b".." {
            entries.insert(name.to_vec());
        }
    }
    let expected = expected
        .iter()
        .map(|name| name.as_bytes().to_vec())
        .collect::<BTreeSet<_>>();
    Ok(entries == expected)
}

pub(super) fn open_child_directory(
    parent: &OwnedFd,
    name: &str,
) -> Result<OwnedFd, ProvisioningSecretStoreError> {
    let directory = rustix::fs::openat(
        parent,
        name,
        rustix::fs::OFlags::RDONLY
            | rustix::fs::OFlags::DIRECTORY
            | rustix::fs::OFlags::CLOEXEC
            | rustix::fs::OFlags::NOFOLLOW,
        rustix::fs::Mode::empty(),
    )
    .map_err(|_| ProvisioningSecretStoreError::Unavailable)?;
    validate_directory(&directory, false)?;
    Ok(directory)
}

fn open_optional_child_directory(
    parent: &OwnedFd,
    name: &str,
) -> Result<Option<OwnedFd>, ProvisioningSecretStoreError> {
    match rustix::fs::openat(
        parent,
        name,
        rustix::fs::OFlags::RDONLY
            | rustix::fs::OFlags::DIRECTORY
            | rustix::fs::OFlags::CLOEXEC
            | rustix::fs::OFlags::NOFOLLOW,
        rustix::fs::Mode::empty(),
    ) {
        Ok(directory) => {
            validate_directory(&directory, false)?;
            Ok(Some(directory))
        }
        Err(rustix::io::Errno::NOENT) => Ok(None),
        Err(_) => Err(ProvisioningSecretStoreError::Unavailable),
    }
}

pub(super) fn write_new_file(
    directory: &OwnedFd,
    name: &str,
    bytes: &[u8],
) -> Result<(), ProvisioningSecretStoreError> {
    let descriptor = rustix::fs::openat(
        directory,
        name,
        rustix::fs::OFlags::WRONLY
            | rustix::fs::OFlags::CREATE
            | rustix::fs::OFlags::EXCL
            | rustix::fs::OFlags::CLOEXEC
            | rustix::fs::OFlags::NOFOLLOW,
        rustix::fs::Mode::RUSR | rustix::fs::Mode::WUSR,
    )
    .map_err(|_| ProvisioningSecretStoreError::Unavailable)?;
    validate_regular(&descriptor, 0o600)?;
    let mut file = File::from(descriptor);
    file.write_all(bytes)
        .and_then(|()| file.sync_all())
        .map_err(|_| ProvisioningSecretStoreError::Unavailable)
}

pub(super) fn remove_optional_file(
    directory: &OwnedFd,
    name: &str,
) -> Result<(), ProvisioningSecretStoreError> {
    match rustix::fs::unlinkat(directory, name, rustix::fs::AtFlags::empty()) {
        Ok(()) | Err(rustix::io::Errno::NOENT) => Ok(()),
        Err(_) => Err(ProvisioningSecretStoreError::Unavailable),
    }
}

pub(super) fn sync_directory(directory: &OwnedFd) -> Result<(), ProvisioningSecretStoreError> {
    rustix::fs::fsync(directory).map_err(|_| ProvisioningSecretStoreError::Unavailable)
}

#[cfg(test)]
mod tests {
    use super::{GenerationManifest, decode_manifest, encode_manifest, read_host_key_identity};
    use crate::{PROVIDER_REFERENCE_ID_BYTES, provisioning_secret_ref};
    use aster_mesh::{ProvisioningLoadId, ProvisioningSecretStoreError};
    use std::{
        fs,
        os::unix::fs::{PermissionsExt as _, symlink},
        sync::atomic::{AtomicU64, Ordering},
    };

    static NEXT_HOST_KEY_FIXTURE: AtomicU64 = AtomicU64::new(0);

    fn fixture_manifest() -> GenerationManifest {
        GenerationManifest {
            generation: 1,
            load: ProvisioningLoadId::new([0x22; 32]),
            secret_ref: provisioning_secret_ref(1, [0x33; PROVIDER_REFERENCE_ID_BYTES])
                .expect("fixture reference"),
            ciphertext_digest: [0x55; 32],
            content: super::GenerationContent::Credential,
        }
    }

    #[test]
    fn manifest_round_trip_preserves_runtime_generation_binding() {
        // Break caught: losing the load, reference, generation, or ciphertext
        // digest would let reconciliation activate an unrelated stage.
        let manifest = fixture_manifest();
        let encoded = encode_manifest(&manifest);
        assert_eq!(&encoded[..8], b"ASTRSDM1");
        assert_eq!(&encoded[8..10], &2_u16.to_be_bytes());
        assert_eq!(
            decode_manifest(&encoded).expect("canonical manifest"),
            manifest
        );
    }

    #[test]
    fn manifest_rejects_extensions_and_cross_generation_reference() {
        // Break caught: accepting trailing state or a reference from another
        // generation makes an apparently exact stage ambiguous.
        let manifest = fixture_manifest();
        let mut trailing = encode_manifest(&manifest);
        trailing.push(0);
        assert_eq!(
            decode_manifest(&trailing).expect_err("trailing manifest byte"),
            ProvisioningSecretStoreError::Rejected
        );

        let mut v1_version = encode_manifest(&manifest);
        v1_version[8..10].copy_from_slice(&1_u16.to_be_bytes());
        assert_eq!(
            decode_manifest(&v1_version).expect_err("v1 manifest version"),
            ProvisioningSecretStoreError::Rejected
        );

        let mut mismatched = manifest;
        mismatched.secret_ref = provisioning_secret_ref(2, [0x33; PROVIDER_REFERENCE_ID_BYTES])
            .expect("second generation reference");
        assert_eq!(
            decode_manifest(&encode_manifest(&mismatched)).expect_err("cross-generation manifest"),
            ProvisioningSecretStoreError::Rejected
        );
    }

    #[test]
    fn host_key_identity_hashes_only_a_secure_bounded_regular_file() {
        // Break caught: reading by path without descriptor-relative no-follow
        // and metadata checks could bind the ledger to attacker-selected key
        // bytes or retain those bytes outside zeroizing memory.
        let serial = NEXT_HOST_KEY_FIXTURE.fetch_add(1, Ordering::Relaxed);
        let root = std::env::temp_dir().join(format!(
            "aster-systemd-host-key-test-{}-{serial}",
            std::process::id()
        ));
        fs::create_dir(&root).expect("create host-key fixture root");
        fs::set_permissions(&root, fs::Permissions::from_mode(0o700))
            .expect("protect host-key fixture root");
        let key = root.join("credential.secret");
        fs::write(&key, [0x5a; 32]).expect("write host-key fixture");
        fs::set_permissions(&key, fs::Permissions::from_mode(0o600))
            .expect("protect host-key fixture");
        assert_eq!(
            read_host_key_identity(&key).expect("secure host-key identity"),
            [
                0x60, 0xbf, 0x07, 0xc4, 0x88, 0xaa, 0xd1, 0x8f, 0xda, 0x33, 0x9d, 0xf0, 0x7e, 0x4f,
                0xbc, 0x47, 0xb4, 0xf0, 0x0b, 0xe7, 0x17, 0x11, 0x93, 0x6f, 0x18, 0xd0, 0x4d, 0x35,
                0x2a, 0xd0, 0x18, 0x90,
            ]
        );

        fs::set_permissions(&key, fs::Permissions::from_mode(0o640))
            .expect("broaden host-key fixture");
        assert_eq!(
            read_host_key_identity(&key).expect_err("group-readable host key"),
            ProvisioningSecretStoreError::Rejected
        );
        fs::set_permissions(&key, fs::Permissions::from_mode(0o600))
            .expect("restore host-key fixture");
        let link = root.join("credential-link");
        symlink(&key, &link).expect("create host-key symlink");
        assert_eq!(
            read_host_key_identity(&link).expect_err("symlinked host key"),
            ProvisioningSecretStoreError::Rejected
        );
        fs::remove_dir_all(&root).expect("remove host-key fixture");
        assert_eq!(
            read_host_key_identity(&key).expect_err("missing host key"),
            ProvisioningSecretStoreError::Unavailable
        );
    }
}
