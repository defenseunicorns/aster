use aster_mesh::{
    ProvisioningLoadId, ProvisioningSecretLoader, ProvisioningSecretRef, load_provisioning_secret,
};
use hmac::{Hmac, KeyInit, Mac};
use sha2::{Digest, Sha256};
use std::{
    fmt,
    fs::{self, File, OpenOptions},
    io::{Read, Write},
    os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt},
    path::{Path, PathBuf},
    time::Instant,
};
use zeroize::Zeroizing;

const ARTIFACT_MAGIC: &[u8; 8] = b"ASTRBD02";
const ONE_ENTRY_BYTES: usize = 109;
const TWO_ENTRY_BYTES: usize = 145;
const MAX_LEASE_SECONDS: u64 = 7 * 24 * 60 * 60;
const BINDING_DOMAIN: &[u8] = b"aster/ble-l2cap/discovery-key-binding/v1\0";
const CHECKPOINT_MAGIC: &[u8; 8] = b"ASTRDC01";
const CHECKPOINT_BYTES: usize = 165;
const CHECKPOINT_FILE: &str = "discovery-checkpoint";
const CHECKPOINT_NEXT_FILE: &str = "discovery-checkpoint.next";
type ActiveCredentialState = (u32, [u8; 32], Option<(u32, [u8; 32])>);
/// Move-only parts passed once from the authority into the Linux adapter.
pub type DiscoveryCredentialMaterialParts = (
    (u32, Zeroizing<[u8; 32]>),
    Option<(u32, Zeroizing<[u8; 32]>)>,
    Instant,
);

/// Closed authenticated discovery-credential authority failures.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DiscoveryCredentialError {
    /// Artifact bytes are noncanonical or outside their validity interval.
    InvalidArtifact,
    /// Artifact does not belong to the expected deployment scope.
    WrongScope,
    /// Artifact would roll back or violate the rotation state machine.
    InvalidTransition,
    /// The durable authority checkpoint could not be loaded or replaced.
    CheckpointUnavailable,
    /// Existing checkpoint bytes or custody metadata are invalid.
    CheckpointCorrupt,
    /// Trusted wall and monotonic clocks diverged beyond the fixed tolerance.
    ClockDiscontinuity,
    /// Lease conversion overflowed the monotonic clock representation.
    TimeOverflow,
    /// Explicit evaluator-only file failed descriptor custody validation.
    UnprotectedReferenceRejected,
    /// Authenticated provisioning source could not produce the exact artifact.
    ProvisioningUnavailable,
}

struct CredentialEntry {
    generation: u32,
    secret: Zeroizing<[u8; 32]>,
}

/// Parsed canonical credential artifact retained only for one authority load.
struct ParsedDiscoveryArtifact {
    manifest_sequence: u64,
    lease_not_after: u64,
    overlap_not_after: u64,
    deployment_scope_id: [u8; 32],
    emitting: CredentialEntry,
    overlap: Option<CredentialEntry>,
    digest: [u8; 32],
}

impl ParsedDiscoveryArtifact {
    fn parse(
        bytes: &[u8],
        expected_scope: [u8; 32],
        wall_now: u64,
    ) -> Result<Self, DiscoveryCredentialError> {
        if bytes.len() < 17 || &bytes[..8] != ARTIFACT_MAGIC {
            return Err(DiscoveryCredentialError::InvalidArtifact);
        }
        let manifest_sequence = read_u64(bytes, 8)?;
        let entry_count = bytes[16];
        let expected_len = match entry_count {
            1 => ONE_ENTRY_BYTES,
            2 => TWO_ENTRY_BYTES,
            _ => return Err(DiscoveryCredentialError::InvalidArtifact),
        };
        if bytes.len() != expected_len || manifest_sequence == 0 {
            return Err(DiscoveryCredentialError::InvalidArtifact);
        }
        let issued_at = read_u64(bytes, 17)?;
        let lease_not_after = read_u64(bytes, 25)?;
        let overlap_not_after = read_u64(bytes, 33)?;
        if issued_at == 0
            || wall_now < issued_at
            || wall_now >= lease_not_after
            || lease_not_after <= issued_at
            || lease_not_after - issued_at > MAX_LEASE_SECONDS
        {
            return Err(DiscoveryCredentialError::InvalidArtifact);
        }
        let deployment_scope_id: [u8; 32] = bytes[41..73]
            .try_into()
            .map_err(|_| DiscoveryCredentialError::InvalidArtifact)?;
        if expected_scope == [0; 32] || deployment_scope_id != expected_scope {
            return Err(DiscoveryCredentialError::WrongScope);
        }
        let emitting = read_entry(bytes, 73)?;
        let overlap = if entry_count == 2 {
            if overlap_not_after <= issued_at
                || overlap_not_after > lease_not_after
                || overlap_not_after - issued_at > MAX_LEASE_SECONDS
            {
                return Err(DiscoveryCredentialError::InvalidArtifact);
            }
            Some(read_entry(bytes, 109)?)
        } else {
            if overlap_not_after != 0 {
                return Err(DiscoveryCredentialError::InvalidArtifact);
            }
            None
        };
        if let Some(overlap) = overlap.as_ref()
            && (emitting.secret.as_ref() == overlap.secret.as_ref()
                || emitting.generation.abs_diff(overlap.generation) != 1)
        {
            return Err(DiscoveryCredentialError::InvalidArtifact);
        }
        let digest = Sha256::digest(bytes).into();
        Ok(Self {
            manifest_sequence,
            lease_not_after,
            overlap_not_after,
            deployment_scope_id,
            emitting,
            overlap,
            digest,
        })
    }

    #[cfg(test)]
    const fn manifest_sequence(&self) -> u64 {
        self.manifest_sequence
    }

    #[cfg(test)]
    const fn emitting_generation(&self) -> u32 {
        self.emitting.generation
    }

    fn overlap_generation(&self) -> Option<u32> {
        self.overlap.as_ref().map(|entry| entry.generation)
    }
}

fn read_u64(bytes: &[u8], offset: usize) -> Result<u64, DiscoveryCredentialError> {
    bytes
        .get(offset..offset + 8)
        .and_then(|value| value.try_into().ok())
        .map(u64::from_be_bytes)
        .ok_or(DiscoveryCredentialError::InvalidArtifact)
}

fn read_entry(bytes: &[u8], offset: usize) -> Result<CredentialEntry, DiscoveryCredentialError> {
    let generation = bytes
        .get(offset..offset + 4)
        .and_then(|value| value.try_into().ok())
        .map(u32::from_be_bytes)
        .ok_or(DiscoveryCredentialError::InvalidArtifact)?;
    let secret: [u8; 32] = bytes
        .get(offset + 4..offset + 36)
        .and_then(|value| value.try_into().ok())
        .ok_or(DiscoveryCredentialError::InvalidArtifact)?;
    if generation == 0 || secret == [0; 32] {
        return Err(DiscoveryCredentialError::InvalidArtifact);
    }
    Ok(CredentialEntry {
        generation,
        secret: Zeroizing::new(secret),
    })
}

fn fingerprint(entry: &CredentialEntry, scope: &[u8; 32]) -> [u8; 32] {
    let mut mac = <Hmac<Sha256> as KeyInit>::new_from_slice(entry.secret.as_ref())
        .expect("SHA-256 HMAC accepts every 32-byte key");
    mac.update(BINDING_DOMAIN);
    mac.update(scope);
    mac.update(&entry.generation.to_be_bytes());
    mac.finalize().into_bytes().into()
}

#[derive(Clone, Eq, PartialEq)]
struct DiscoveryCheckpoint {
    manifest_sequence: u64,
    artifact_digest: [u8; 32],
    deployment_scope_id: [u8; 32],
    emitting_generation: u32,
    emitting_fingerprint: [u8; 32],
    overlap_generation: Option<u32>,
    overlap_fingerprint: Option<[u8; 32]>,
    retired_through: u32,
    original_overlap_deadline: Option<u64>,
}

impl fmt::Debug for DiscoveryCheckpoint {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("DiscoveryCheckpoint")
            .field("manifest_sequence", &self.manifest_sequence)
            .field("emitting_generation", &self.emitting_generation)
            .field("overlap_generation", &self.overlap_generation)
            .field("retired_through", &self.retired_through)
            .field("binding_material", &"[REDACTED]")
            .finish()
    }
}

impl DiscoveryCheckpoint {
    fn transition(
        previous: Option<&Self>,
        artifact: &ParsedDiscoveryArtifact,
    ) -> Result<Self, DiscoveryCredentialError> {
        let candidate = Self::from_artifact(artifact);
        let Some(previous) = previous else {
            if artifact.overlap.is_some() {
                return Err(DiscoveryCredentialError::InvalidTransition);
            }
            return Ok(candidate);
        };
        if artifact.deployment_scope_id != previous.deployment_scope_id
            || artifact.manifest_sequence < previous.manifest_sequence
        {
            return Err(DiscoveryCredentialError::InvalidTransition);
        }
        if artifact.manifest_sequence == previous.manifest_sequence {
            return if artifact.digest == previous.artifact_digest {
                Ok(previous.clone())
            } else {
                Err(DiscoveryCredentialError::InvalidTransition)
            };
        }

        let previous_state = previous.active_state();
        let candidate_state = candidate.active_state();
        let renewed = previous_state == candidate_state;
        let staged = previous.overlap_generation.is_none()
            && candidate.emitting_generation == previous.emitting_generation
            && candidate.overlap_generation == previous.emitting_generation.checked_add(1);
        let activated = previous.overlap_generation.is_some()
            && candidate.overlap_generation == Some(previous.emitting_generation)
            && Some(candidate.emitting_generation) == previous.overlap_generation;
        let retired = previous
            .overlap_generation
            .is_some_and(|old| previous.emitting_generation > old)
            && candidate.overlap_generation.is_none()
            && candidate.emitting_generation == previous.emitting_generation;

        if !(renewed || staged || activated || retired) {
            return Err(DiscoveryCredentialError::InvalidTransition);
        }
        if !bindings_preserved(previous, &candidate) {
            return Err(DiscoveryCredentialError::InvalidTransition);
        }
        let original_overlap_deadline = if staged {
            Some(artifact.overlap_not_after)
        } else if renewed || activated {
            previous.original_overlap_deadline
        } else {
            None
        };
        if let Some(original) = previous.original_overlap_deadline
            && candidate.overlap_generation.is_some()
            && artifact.overlap_not_after > original
        {
            return Err(DiscoveryCredentialError::InvalidTransition);
        }
        let retired_through = if retired {
            previous.emitting_generation - 1
        } else {
            previous.retired_through
        };
        if candidate.emitting_generation <= retired_through
            || candidate
                .overlap_generation
                .is_some_and(|generation| generation <= retired_through)
        {
            return Err(DiscoveryCredentialError::InvalidTransition);
        }
        Ok(Self {
            original_overlap_deadline,
            retired_through,
            ..candidate
        })
    }

    fn from_artifact(artifact: &ParsedDiscoveryArtifact) -> Self {
        Self {
            manifest_sequence: artifact.manifest_sequence,
            artifact_digest: artifact.digest,
            deployment_scope_id: artifact.deployment_scope_id,
            emitting_generation: artifact.emitting.generation,
            emitting_fingerprint: fingerprint(&artifact.emitting, &artifact.deployment_scope_id),
            overlap_generation: artifact.overlap_generation(),
            overlap_fingerprint: artifact
                .overlap
                .as_ref()
                .map(|entry| fingerprint(entry, &artifact.deployment_scope_id)),
            retired_through: artifact.emitting.generation.saturating_sub(1),
            original_overlap_deadline: None,
        }
    }

    fn active_state(&self) -> ActiveCredentialState {
        (
            self.emitting_generation,
            self.emitting_fingerprint,
            self.overlap_generation.zip(self.overlap_fingerprint),
        )
    }

    #[cfg(test)]
    const fn emitting_generation(&self) -> u32 {
        self.emitting_generation
    }

    #[cfg(test)]
    const fn retired_through(&self) -> u32 {
        self.retired_through
    }
}

fn bindings_preserved(previous: &DiscoveryCheckpoint, candidate: &DiscoveryCheckpoint) -> bool {
    let valid = |generation, fingerprint| {
        if previous.emitting_generation == generation {
            return previous.emitting_fingerprint == fingerprint;
        }
        if previous.overlap_generation == Some(generation) {
            return previous.overlap_fingerprint == Some(fingerprint);
        }
        previous.overlap_generation.is_none()
            && previous.emitting_generation.checked_add(1) == Some(generation)
    };
    valid(
        candidate.emitting_generation,
        candidate.emitting_fingerprint,
    ) && candidate
        .overlap_generation
        .zip(candidate.overlap_fingerprint)
        .is_none_or(|(generation, fingerprint)| valid(generation, fingerprint))
}

/// One checked wall/monotonic sample supplied by the embedding process.
#[derive(Clone, Copy, Debug)]
pub struct TrustedClockSample {
    wall_unix_seconds: u64,
    monotonic: Instant,
}

impl TrustedClockSample {
    /// Creates an exact paired sample from a trusted clock provider.
    pub const fn new(wall_unix_seconds: u64, monotonic: Instant) -> Self {
        Self {
            wall_unix_seconds,
            monotonic,
        }
    }
}

trait DiscoveryCheckpointStore {
    fn load(&mut self) -> Result<Option<DiscoveryCheckpoint>, DiscoveryCredentialError>;

    fn replace(&mut self, checkpoint: &DiscoveryCheckpoint)
    -> Result<(), DiscoveryCredentialError>;
}

struct FileDiscoveryCheckpointStore {
    root: PathBuf,
}

impl FileDiscoveryCheckpointStore {
    fn new(root: &Path) -> Result<Self, DiscoveryCredentialError> {
        let metadata = fs::symlink_metadata(root)
            .map_err(|_| DiscoveryCredentialError::CheckpointUnavailable)?;
        if !metadata.file_type().is_dir()
            || metadata.uid() != rustix::process::geteuid().as_raw()
            || metadata.permissions().mode() & 0o077 != 0
        {
            return Err(DiscoveryCredentialError::CheckpointCorrupt);
        }
        let store = Self {
            root: root.to_path_buf(),
        };
        store.cleanup_next()?;
        Ok(store)
    }

    fn checkpoint_path(&self) -> PathBuf {
        self.root.join(CHECKPOINT_FILE)
    }

    fn next_path(&self) -> PathBuf {
        self.root.join(CHECKPOINT_NEXT_FILE)
    }

    fn cleanup_next(&self) -> Result<(), DiscoveryCredentialError> {
        let next = self.next_path();
        let metadata = match fs::symlink_metadata(&next) {
            Ok(metadata) => metadata,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
            Err(_) => return Err(DiscoveryCredentialError::CheckpointUnavailable),
        };
        if !metadata.file_type().is_file()
            || metadata.uid() != rustix::process::geteuid().as_raw()
            || metadata.permissions().mode() & 0o077 != 0
            || metadata.nlink() != 1
            || metadata.len() > CHECKPOINT_BYTES as u64
        {
            return Err(DiscoveryCredentialError::CheckpointCorrupt);
        }
        fs::remove_file(next).map_err(|_| DiscoveryCredentialError::CheckpointUnavailable)?;
        File::open(&self.root)
            .and_then(|directory| directory.sync_all())
            .map_err(|_| DiscoveryCredentialError::CheckpointUnavailable)
    }
}

impl DiscoveryCheckpointStore for FileDiscoveryCheckpointStore {
    fn load(&mut self) -> Result<Option<DiscoveryCheckpoint>, DiscoveryCredentialError> {
        let path = self.checkpoint_path();
        let mut file = match OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW)
            .open(path)
        {
            Ok(file) => file,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(_) => return Err(DiscoveryCredentialError::CheckpointCorrupt),
        };
        validate_checkpoint_metadata(&file)?;
        let mut bytes = [0_u8; CHECKPOINT_BYTES];
        file.read_exact(&mut bytes)
            .map_err(|_| DiscoveryCredentialError::CheckpointCorrupt)?;
        let mut trailing = [0_u8; 1];
        if file
            .read(&mut trailing)
            .map_err(|_| DiscoveryCredentialError::CheckpointCorrupt)?
            != 0
        {
            return Err(DiscoveryCredentialError::CheckpointCorrupt);
        }
        validate_checkpoint_metadata(&file)?;
        decode_checkpoint(&bytes).map(Some)
    }

    fn replace(
        &mut self,
        checkpoint: &DiscoveryCheckpoint,
    ) -> Result<(), DiscoveryCredentialError> {
        self.cleanup_next()?;
        let next = self.next_path();
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW)
            .open(&next)
            .map_err(|_| DiscoveryCredentialError::CheckpointUnavailable)?;
        let bytes = encode_checkpoint(checkpoint);
        file.write_all(&bytes)
            .and_then(|()| file.sync_all())
            .map_err(|_| DiscoveryCredentialError::CheckpointUnavailable)?;
        fs::rename(&next, self.checkpoint_path())
            .map_err(|_| DiscoveryCredentialError::CheckpointUnavailable)?;
        File::open(&self.root)
            .and_then(|directory| directory.sync_all())
            .map_err(|_| DiscoveryCredentialError::CheckpointUnavailable)
    }
}

fn validate_checkpoint_metadata(file: &File) -> Result<(), DiscoveryCredentialError> {
    let metadata = file
        .metadata()
        .map_err(|_| DiscoveryCredentialError::CheckpointCorrupt)?;
    if !metadata.file_type().is_file()
        || metadata.uid() != rustix::process::geteuid().as_raw()
        || metadata.permissions().mode() & 0o077 != 0
        || metadata.nlink() != 1
        || metadata.len() != CHECKPOINT_BYTES as u64
    {
        return Err(DiscoveryCredentialError::CheckpointCorrupt);
    }
    Ok(())
}

fn encode_checkpoint(checkpoint: &DiscoveryCheckpoint) -> [u8; CHECKPOINT_BYTES] {
    let mut bytes = [0_u8; CHECKPOINT_BYTES];
    bytes[..8].copy_from_slice(CHECKPOINT_MAGIC);
    bytes[8..40].copy_from_slice(&checkpoint.deployment_scope_id);
    bytes[40..48].copy_from_slice(&checkpoint.manifest_sequence.to_be_bytes());
    bytes[48..80].copy_from_slice(&checkpoint.artifact_digest);
    bytes[80..84].copy_from_slice(&checkpoint.emitting_generation.to_be_bytes());
    bytes[84..116].copy_from_slice(&checkpoint.emitting_fingerprint);
    if let (Some(generation), Some(fingerprint), Some(deadline)) = (
        checkpoint.overlap_generation,
        checkpoint.overlap_fingerprint,
        checkpoint.original_overlap_deadline,
    ) {
        bytes[116] = 1;
        bytes[117..121].copy_from_slice(&generation.to_be_bytes());
        bytes[121..153].copy_from_slice(&fingerprint);
        bytes[157..165].copy_from_slice(&deadline.to_be_bytes());
    }
    bytes[153..157].copy_from_slice(&checkpoint.retired_through.to_be_bytes());
    bytes
}

fn decode_checkpoint(
    bytes: &[u8; CHECKPOINT_BYTES],
) -> Result<DiscoveryCheckpoint, DiscoveryCredentialError> {
    if &bytes[..8] != CHECKPOINT_MAGIC || !matches!(bytes[116], 0 | 1) {
        return Err(DiscoveryCredentialError::CheckpointCorrupt);
    }
    let deployment_scope_id = bytes[8..40].try_into().unwrap();
    let manifest_sequence = u64::from_be_bytes(bytes[40..48].try_into().unwrap());
    let artifact_digest = bytes[48..80].try_into().unwrap();
    let emitting_generation = u32::from_be_bytes(bytes[80..84].try_into().unwrap());
    let emitting_fingerprint = bytes[84..116].try_into().unwrap();
    let retired_through = u32::from_be_bytes(bytes[153..157].try_into().unwrap());
    let has_overlap = bytes[116] == 1;
    let raw_overlap_generation = u32::from_be_bytes(bytes[117..121].try_into().unwrap());
    let raw_overlap_fingerprint: [u8; 32] = bytes[121..153].try_into().unwrap();
    let raw_deadline = u64::from_be_bytes(bytes[157..165].try_into().unwrap());
    if deployment_scope_id == [0; 32]
        || manifest_sequence == 0
        || artifact_digest == [0; 32]
        || emitting_generation == 0
        || emitting_fingerprint == [0; 32]
        || emitting_generation <= retired_through
        || (!has_overlap
            && (raw_overlap_generation != 0
                || raw_overlap_fingerprint != [0; 32]
                || raw_deadline != 0))
        || (has_overlap
            && (raw_overlap_generation == 0
                || raw_overlap_generation <= retired_through
                || raw_overlap_fingerprint == [0; 32]
                || raw_deadline == 0))
    {
        return Err(DiscoveryCredentialError::CheckpointCorrupt);
    }
    Ok(DiscoveryCheckpoint {
        manifest_sequence,
        artifact_digest,
        deployment_scope_id,
        emitting_generation,
        emitting_fingerprint,
        overlap_generation: has_overlap.then_some(raw_overlap_generation),
        overlap_fingerprint: has_overlap.then_some(raw_overlap_fingerprint),
        retired_through,
        original_overlap_deadline: has_overlap.then_some(raw_deadline),
    })
}

fn read_unprotected_reference_artifact(
    parent: &Path,
    basename: &str,
) -> Result<Zeroizing<Vec<u8>>, DiscoveryCredentialError> {
    read_unprotected_reference_artifact_after_stat(parent, basename, || {})
}

fn read_unprotected_reference_artifact_after_stat<F>(
    parent: &Path,
    basename: &str,
    after_stat: F,
) -> Result<Zeroizing<Vec<u8>>, DiscoveryCredentialError>
where
    F: FnOnce(),
{
    use std::path::Component;

    if !parent.is_absolute()
        || parent
            .components()
            .any(|component| matches!(component, Component::CurDir | Component::ParentDir))
        || Path::new(basename).components().count() != 1
        || !matches!(
            Path::new(basename).components().next(),
            Some(Component::Normal(_))
        )
    {
        return Err(DiscoveryCredentialError::UnprotectedReferenceRejected);
    }
    let relative_parent = parent
        .strip_prefix("/")
        .map_err(|_| DiscoveryCredentialError::UnprotectedReferenceRejected)?;
    let slash = rustix::fs::openat(
        rustix::fs::CWD,
        "/",
        rustix::fs::OFlags::RDONLY
            | rustix::fs::OFlags::DIRECTORY
            | rustix::fs::OFlags::CLOEXEC
            | rustix::fs::OFlags::NOFOLLOW,
        rustix::fs::Mode::empty(),
    )
    .map_err(|_| DiscoveryCredentialError::UnprotectedReferenceRejected)?;
    let resolve = rustix::fs::ResolveFlags::BENEATH
        | rustix::fs::ResolveFlags::NO_SYMLINKS
        | rustix::fs::ResolveFlags::NO_MAGICLINKS;
    let parent_descriptor = rustix::fs::openat2(
        slash,
        relative_parent,
        rustix::fs::OFlags::RDONLY
            | rustix::fs::OFlags::DIRECTORY
            | rustix::fs::OFlags::CLOEXEC
            | rustix::fs::OFlags::NOFOLLOW,
        rustix::fs::Mode::empty(),
        resolve,
    )
    .map_err(|_| DiscoveryCredentialError::UnprotectedReferenceRejected)?;
    let descriptor = rustix::fs::openat2(
        &parent_descriptor,
        basename,
        rustix::fs::OFlags::RDONLY
            | rustix::fs::OFlags::CLOEXEC
            | rustix::fs::OFlags::NOFOLLOW
            | rustix::fs::OFlags::NONBLOCK,
        rustix::fs::Mode::empty(),
        resolve,
    )
    .map_err(|_| DiscoveryCredentialError::UnprotectedReferenceRejected)?;
    let before = rustix::fs::fstat(&descriptor)
        .map_err(|_| DiscoveryCredentialError::UnprotectedReferenceRejected)?;
    validate_unprotected_reference_stat(&before)?;
    after_stat();
    let declared = usize::try_from(before.st_size)
        .map_err(|_| DiscoveryCredentialError::UnprotectedReferenceRejected)?;
    let mut file = File::from(descriptor);
    let mut bytes = Zeroizing::new(Vec::with_capacity(declared));
    (&mut file)
        .take((TWO_ENTRY_BYTES + 1) as u64)
        .read_to_end(&mut bytes)
        .map_err(|_| DiscoveryCredentialError::UnprotectedReferenceRejected)?;
    let after = rustix::fs::fstat(&file)
        .map_err(|_| DiscoveryCredentialError::UnprotectedReferenceRejected)?;
    validate_unprotected_reference_stat(&after)?;
    if bytes.len() != declared
        || before.st_dev != after.st_dev
        || before.st_ino != after.st_ino
        || before.st_size != after.st_size
        || before.st_mode != after.st_mode
        || before.st_nlink != after.st_nlink
        || before.st_uid != after.st_uid
        || before.st_mtime != after.st_mtime
        || before.st_mtime_nsec != after.st_mtime_nsec
        || before.st_ctime != after.st_ctime
        || before.st_ctime_nsec != after.st_ctime_nsec
    {
        return Err(DiscoveryCredentialError::UnprotectedReferenceRejected);
    }
    Ok(bytes)
}

fn validate_unprotected_reference_stat(
    stat: &rustix::fs::Stat,
) -> Result<(), DiscoveryCredentialError> {
    validate_unprotected_reference_stat_for_owner(stat, rustix::process::geteuid().as_raw())
}

fn validate_unprotected_reference_stat_for_owner(
    stat: &rustix::fs::Stat,
    expected_uid: libc::uid_t,
) -> Result<(), DiscoveryCredentialError> {
    let size = usize::try_from(stat.st_size)
        .map_err(|_| DiscoveryCredentialError::UnprotectedReferenceRejected)?;
    if stat.st_mode & libc::S_IFMT != libc::S_IFREG
        || stat.st_uid != expected_uid
        || stat.st_mode & 0o077 != 0
        || stat.st_nlink != 1
        || !matches!(size, ONE_ENTRY_BYTES | TWO_ENTRY_BYTES)
    {
        return Err(DiscoveryCredentialError::UnprotectedReferenceRejected);
    }
    Ok(())
}

/// Zeroizing host-owned lease ready for one explicit adapter composition step.
pub struct LeasedDiscoveryCredentialMaterial {
    emitting: CredentialEntry,
    overlap: Option<CredentialEntry>,
    expires_at: Instant,
}

impl LeasedDiscoveryCredentialMaterial {
    /// Emitting credential generation.
    pub const fn emitting_generation(&self) -> u32 {
        self.emitting.generation
    }

    /// Optional accepted overlap generation.
    pub fn overlap_generation(&self) -> Option<u32> {
        self.overlap.as_ref().map(|entry| entry.generation)
    }

    /// Monotonic instant at which the adapter must tear down discovery.
    pub const fn expires_at(&self) -> Instant {
        self.expires_at
    }

    /// Moves zeroizing material into the Linux adapter composition boundary
    /// without cloning it.
    pub fn into_parts(self) -> DiscoveryCredentialMaterialParts {
        (
            (self.emitting.generation, self.emitting.secret),
            self.overlap.map(|entry| (entry.generation, entry.secret)),
            self.expires_at,
        )
    }
}

impl fmt::Debug for LeasedDiscoveryCredentialMaterial {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("LeasedDiscoveryCredentialMaterial")
            .field("emitting_generation", &self.emitting.generation)
            .field("overlap_generation", &self.overlap_generation())
            .field("secret_material", &"[REDACTED]")
            .field("expires_at", &self.expires_at)
            .finish()
    }
}

struct DiscoveryCredentialAuthorityCore<S> {
    expected_scope: [u8; 32],
    checkpoint_store: S,
    last_clock_sample: Option<TrustedClockSample>,
}

impl<S> DiscoveryCredentialAuthorityCore<S>
where
    S: DiscoveryCheckpointStore,
{
    fn new(
        expected_scope: [u8; 32],
        checkpoint_store: S,
    ) -> Result<Self, DiscoveryCredentialError> {
        if expected_scope == [0; 32] {
            return Err(DiscoveryCredentialError::WrongScope);
        }
        Ok(Self {
            expected_scope,
            checkpoint_store,
            last_clock_sample: None,
        })
    }

    fn accept_authenticated(
        &mut self,
        bytes: &[u8],
        sample: TrustedClockSample,
    ) -> Result<LeasedDiscoveryCredentialMaterial, DiscoveryCredentialError> {
        self.validate_clock(sample)?;
        let artifact =
            ParsedDiscoveryArtifact::parse(bytes, self.expected_scope, sample.wall_unix_seconds)?;
        let previous = self.checkpoint_store.load()?;
        let next = DiscoveryCheckpoint::transition(previous.as_ref(), &artifact)?;
        self.checkpoint_store.replace(&next)?;

        let effective_not_after = if artifact.overlap.is_some() {
            artifact.lease_not_after.min(artifact.overlap_not_after)
        } else {
            artifact.lease_not_after
        };
        let remaining = effective_not_after
            .checked_sub(sample.wall_unix_seconds)
            .ok_or(DiscoveryCredentialError::InvalidArtifact)?;
        let expires_at = sample
            .monotonic
            .checked_add(std::time::Duration::from_secs(remaining))
            .ok_or(DiscoveryCredentialError::TimeOverflow)?;
        self.last_clock_sample = Some(sample);
        Ok(LeasedDiscoveryCredentialMaterial {
            emitting: artifact.emitting,
            overlap: artifact.overlap,
            expires_at,
        })
    }

    fn validate_clock(&self, sample: TrustedClockSample) -> Result<(), DiscoveryCredentialError> {
        let Some(previous) = self.last_clock_sample else {
            return Ok(());
        };
        let monotonic_elapsed = sample
            .monotonic
            .checked_duration_since(previous.monotonic)
            .ok_or(DiscoveryCredentialError::ClockDiscontinuity)?
            .as_secs();
        let wall_elapsed = sample
            .wall_unix_seconds
            .checked_sub(previous.wall_unix_seconds)
            .ok_or(DiscoveryCredentialError::ClockDiscontinuity)?;
        if wall_elapsed.abs_diff(monotonic_elapsed) > 5 * 60 {
            return Err(DiscoveryCredentialError::ClockDiscontinuity);
        }
        Ok(())
    }

    fn observe_clock(
        &mut self,
        sample: TrustedClockSample,
    ) -> Result<(), DiscoveryCredentialError> {
        self.validate_clock(sample)?;
        self.last_clock_sample = Some(sample);
        Ok(())
    }

    #[cfg(test)]
    const fn checkpoint_store(&self) -> &S {
        &self.checkpoint_store
    }
}

/// Trusted paired wall/monotonic clock used for credential leases.
pub trait TrustedClock {
    /// Returns one checked sample or a closed clock failure.
    fn sample(&mut self) -> Result<TrustedClockSample, DiscoveryCredentialError>;
}

/// Authenticated provisioning-backed discovery credential authority.
pub struct DiscoveryCredentialAuthority<L, C> {
    loader: L,
    load_operation: ProvisioningLoadId,
    secret_ref: ProvisioningSecretRef,
    clock: C,
    core: DiscoveryCredentialAuthorityCore<FileDiscoveryCheckpointStore>,
}

impl<L, C> DiscoveryCredentialAuthority<L, C>
where
    L: ProvisioningSecretLoader,
    C: TrustedClock,
{
    /// Binds the authenticated source, trusted clock, deployment scope, and
    /// owner-protected durable checkpoint directory.
    pub fn new(
        loader: L,
        load_operation: ProvisioningLoadId,
        secret_ref: ProvisioningSecretRef,
        clock: C,
        expected_scope: [u8; 32],
        checkpoint_root: &Path,
    ) -> Result<Self, DiscoveryCredentialError> {
        let checkpoint_store = FileDiscoveryCheckpointStore::new(checkpoint_root)?;
        Ok(Self {
            loader,
            load_operation,
            secret_ref,
            clock,
            core: DiscoveryCredentialAuthorityCore::new(expected_scope, checkpoint_store)?,
        })
    }

    /// Commits the next authority checkpoint before exposing leased material.
    pub fn load(&mut self) -> Result<LeasedDiscoveryCredentialMaterial, DiscoveryCredentialError> {
        let sample = self.clock.sample()?;
        let receipt =
            load_provisioning_secret(self.load_operation, &self.secret_ref, &mut self.loader)
                .map_err(|_| DiscoveryCredentialError::ProvisioningUnavailable)?;
        self.core
            .accept_authenticated(receipt.plaintext().expose(), sample)
    }

    /// Resamples the trusted clock at the fixed authority cadence. Failure
    /// invalidates the active lease and requires a fresh authenticated load.
    pub fn resample_clock(&mut self) -> Result<(), DiscoveryCredentialError> {
        let sample = self.clock.sample()?;
        self.core.observe_clock(sample)
    }
}

/// Loads the explicitly non-production evaluator artifact through the same
/// parser, transition machine, and durable checkpoint authority.
pub fn load_unprotected_reference_discovery_credentials(
    expected_scope: [u8; 32],
    checkpoint_root: &Path,
    artifact_parent: &Path,
    artifact_basename: &str,
    sample: TrustedClockSample,
) -> Result<LeasedDiscoveryCredentialMaterial, DiscoveryCredentialError> {
    let bytes = read_unprotected_reference_artifact(artifact_parent, artifact_basename)?;
    let store = FileDiscoveryCheckpointStore::new(checkpoint_root)?;
    DiscoveryCredentialAuthorityCore::new(expected_scope, store)?
        .accept_authenticated(&bytes, sample)
}

#[cfg(test)]
mod tests {
    use super::*;
    use aster_mesh::{
        ProvisioningLoadId, ProvisioningLoadReceipt, ProvisioningSecretLoader,
        ProvisioningSecretRef, ProvisioningSecretStoreError, UnprotectedProvisioning,
    };
    use std::{
        fs,
        os::unix::fs::PermissionsExt,
        time::{Duration, Instant},
    };

    const SCOPE: [u8; 32] = [0x42; 32];
    const OLD_SECRET: [u8; 32] = [0x11; 32];
    const NEW_SECRET: [u8; 32] = [0x22; 32];
    const ISSUED: u64 = 1_800_000_000;

    #[derive(Default)]
    struct MemoryCheckpointStore {
        checkpoint: Option<DiscoveryCheckpoint>,
        replacements: usize,
        fail_replace: bool,
    }

    struct StaticClock(TrustedClockSample);

    impl TrustedClock for StaticClock {
        fn sample(&mut self) -> Result<TrustedClockSample, DiscoveryCredentialError> {
            Ok(self.0)
        }
    }

    struct StaticLoader {
        bytes: Vec<u8>,
    }

    impl ProvisioningSecretLoader for StaticLoader {
        fn load(
            &mut self,
            operation: ProvisioningLoadId,
            secret_ref: &ProvisioningSecretRef,
        ) -> Result<ProvisioningLoadReceipt, ProvisioningSecretStoreError> {
            Ok(ProvisioningLoadReceipt::new(
                operation,
                secret_ref.clone(),
                UnprotectedProvisioning::new(self.bytes.clone()).unwrap(),
            ))
        }
    }

    impl DiscoveryCheckpointStore for MemoryCheckpointStore {
        fn load(&mut self) -> Result<Option<DiscoveryCheckpoint>, DiscoveryCredentialError> {
            Ok(self.checkpoint.clone())
        }

        fn replace(
            &mut self,
            checkpoint: &DiscoveryCheckpoint,
        ) -> Result<(), DiscoveryCredentialError> {
            if self.fail_replace {
                return Err(DiscoveryCredentialError::CheckpointUnavailable);
            }
            self.checkpoint = Some(checkpoint.clone());
            self.replacements += 1;
            Ok(())
        }
    }

    enum ArtifactMutation {
        WrongMagic,
        ZeroSequence,
        WrongCount,
        WrongScope,
        ZeroGeneration,
        ZeroSecret,
        TrailingByte,
    }

    impl ArtifactMutation {
        fn apply(self, bytes: &mut Vec<u8>) {
            match self {
                Self::WrongMagic => bytes[0] ^= 1,
                Self::ZeroSequence => bytes[8..16].fill(0),
                Self::WrongCount => bytes[16] = 3,
                Self::WrongScope => bytes[41] ^= 1,
                Self::ZeroGeneration => bytes[73..77].fill(0),
                Self::ZeroSecret => bytes[77..109].fill(0),
                Self::TrailingByte => bytes.push(0),
            }
        }
    }

    fn artifact(
        sequence: u64,
        lease_not_after: u64,
        overlap_not_after: u64,
        emitting: (u32, [u8; 32]),
        overlap: Option<(u32, [u8; 32])>,
    ) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(if overlap.is_some() { 145 } else { 109 });
        bytes.extend_from_slice(b"ASTRBD02");
        bytes.extend_from_slice(&sequence.to_be_bytes());
        bytes.push(if overlap.is_some() { 2 } else { 1 });
        bytes.extend_from_slice(&ISSUED.to_be_bytes());
        bytes.extend_from_slice(&lease_not_after.to_be_bytes());
        bytes.extend_from_slice(&overlap_not_after.to_be_bytes());
        bytes.extend_from_slice(&SCOPE);
        bytes.extend_from_slice(&emitting.0.to_be_bytes());
        bytes.extend_from_slice(&emitting.1);
        if let Some((generation, secret)) = overlap {
            bytes.extend_from_slice(&generation.to_be_bytes());
            bytes.extend_from_slice(&secret);
        }
        bytes
    }

    fn parse(bytes: &[u8]) -> ParsedDiscoveryArtifact {
        ParsedDiscoveryArtifact::parse(bytes, SCOPE, ISSUED + 1).unwrap()
    }

    #[test]
    fn discovery_credentials_parse_exact_one_and_two_entry_artifacts() {
        let one = parse(&artifact(1, ISSUED + 60, 0, (7, OLD_SECRET), None));
        assert_eq!(one.manifest_sequence(), 1);
        assert_eq!(one.emitting_generation(), 7);
        assert_eq!(one.overlap_generation(), None);

        let two = parse(&artifact(
            2,
            ISSUED + 120,
            ISSUED + 90,
            (7, OLD_SECRET),
            Some((8, NEW_SECRET)),
        ));
        assert_eq!(two.emitting_generation(), 7);
        assert_eq!(two.overlap_generation(), Some(8));
    }

    #[test]
    fn discovery_credentials_reject_noncanonical_or_expired_artifacts() {
        let valid = artifact(1, ISSUED + 60, 0, (7, OLD_SECRET), None);
        for mutation in [
            ArtifactMutation::WrongMagic,
            ArtifactMutation::ZeroSequence,
            ArtifactMutation::WrongCount,
            ArtifactMutation::WrongScope,
            ArtifactMutation::ZeroGeneration,
            ArtifactMutation::ZeroSecret,
            ArtifactMutation::TrailingByte,
        ] {
            let mut invalid = valid.clone();
            mutation.apply(&mut invalid);
            assert!(ParsedDiscoveryArtifact::parse(&invalid, SCOPE, ISSUED + 1).is_err());
        }
        assert!(ParsedDiscoveryArtifact::parse(&valid, SCOPE, ISSUED + 61).is_err());
        assert!(
            ParsedDiscoveryArtifact::parse(
                &artifact(1, ISSUED + 7 * 24 * 60 * 60 + 1, 0, (7, OLD_SECRET), None),
                SCOPE,
                ISSUED + 1,
            )
            .is_err()
        );
        assert!(
            ParsedDiscoveryArtifact::parse(
                &artifact(
                    1,
                    ISSUED + 60,
                    ISSUED + 61,
                    (7, OLD_SECRET),
                    Some((8, NEW_SECRET)),
                ),
                SCOPE,
                ISSUED + 1,
            )
            .is_err()
        );
    }

    #[test]
    fn discovery_credentials_accept_only_initialize_renew_stage_activate_retire() {
        let initial = parse(&artifact(1, ISSUED + 60, 0, (7, OLD_SECRET), None));
        let checkpoint = DiscoveryCheckpoint::transition(None, &initial).unwrap();

        let renewal = parse(&artifact(2, ISSUED + 120, 0, (7, OLD_SECRET), None));
        let checkpoint = DiscoveryCheckpoint::transition(Some(&checkpoint), &renewal).unwrap();

        let staged = parse(&artifact(
            3,
            ISSUED + 120,
            ISSUED + 90,
            (7, OLD_SECRET),
            Some((8, NEW_SECRET)),
        ));
        let checkpoint = DiscoveryCheckpoint::transition(Some(&checkpoint), &staged).unwrap();
        assert_eq!(checkpoint.retired_through(), 6);

        let activated = parse(&artifact(
            4,
            ISSUED + 120,
            ISSUED + 90,
            (8, NEW_SECRET),
            Some((7, OLD_SECRET)),
        ));
        let checkpoint = DiscoveryCheckpoint::transition(Some(&checkpoint), &activated).unwrap();

        let retired = parse(&artifact(5, ISSUED + 120, 0, (8, NEW_SECRET), None));
        let checkpoint = DiscoveryCheckpoint::transition(Some(&checkpoint), &retired).unwrap();
        assert_eq!(checkpoint.emitting_generation(), 8);
        assert_eq!(checkpoint.retired_through(), 7);
    }

    #[test]
    fn discovery_credentials_reject_rollback_skip_and_secret_substitution() {
        let initial = parse(&artifact(10, ISSUED + 60, 0, (7, OLD_SECRET), None));
        let checkpoint = DiscoveryCheckpoint::transition(None, &initial).unwrap();

        for rejected in [
            artifact(9, ISSUED + 60, 0, (7, OLD_SECRET), None),
            artifact(11, ISSUED + 60, 0, (9, NEW_SECRET), None),
            artifact(11, ISSUED + 60, 0, (7, NEW_SECRET), None),
            artifact(
                11,
                ISSUED + 60,
                ISSUED + 50,
                (7, OLD_SECRET),
                Some((9, NEW_SECRET)),
            ),
        ] {
            match ParsedDiscoveryArtifact::parse(&rejected, SCOPE, ISSUED + 1) {
                Ok(parsed) => {
                    assert!(DiscoveryCheckpoint::transition(Some(&checkpoint), &parsed).is_err())
                }
                Err(DiscoveryCredentialError::InvalidArtifact) => {}
                Err(other) => panic!("unexpected rejection category: {other:?}"),
            }
        }
    }

    #[test]
    fn discovery_credentials_same_sequence_requires_exact_digest() {
        let initial_bytes = artifact(10, ISSUED + 60, 0, (7, OLD_SECRET), None);
        let initial = parse(&initial_bytes);
        let checkpoint = DiscoveryCheckpoint::transition(None, &initial).unwrap();
        assert_eq!(
            DiscoveryCheckpoint::transition(Some(&checkpoint), &parse(&initial_bytes)).unwrap(),
            checkpoint
        );

        let changed = artifact(10, ISSUED + 61, 0, (7, OLD_SECRET), None);
        assert!(DiscoveryCheckpoint::transition(Some(&checkpoint), &parse(&changed)).is_err());
    }

    #[test]
    fn discovery_authority_persists_checkpoint_before_exposing_lease() {
        let monotonic = Instant::now();
        let mut authority =
            DiscoveryCredentialAuthorityCore::new(SCOPE, MemoryCheckpointStore::default()).unwrap();
        let lease = authority
            .accept_authenticated(
                &artifact(1, ISSUED + 60, 0, (7, OLD_SECRET), None),
                TrustedClockSample::new(ISSUED + 10, monotonic),
            )
            .unwrap();
        assert_eq!(lease.emitting_generation(), 7);
        assert_eq!(lease.overlap_generation(), None);
        assert_eq!(lease.expires_at(), monotonic + Duration::from_secs(50));
        assert_eq!(authority.checkpoint_store().replacements, 1);

        let mut unavailable = DiscoveryCredentialAuthorityCore::new(
            SCOPE,
            MemoryCheckpointStore {
                fail_replace: true,
                ..MemoryCheckpointStore::default()
            },
        )
        .unwrap();
        assert_eq!(
            unavailable
                .accept_authenticated(
                    &artifact(1, ISSUED + 60, 0, (7, OLD_SECRET), None),
                    TrustedClockSample::new(ISSUED + 10, monotonic),
                )
                .unwrap_err(),
            DiscoveryCredentialError::CheckpointUnavailable
        );
    }

    #[test]
    fn discovery_authority_caps_overlap_lease_and_rejects_clock_discontinuity() {
        let monotonic = Instant::now();
        let mut authority =
            DiscoveryCredentialAuthorityCore::new(SCOPE, MemoryCheckpointStore::default()).unwrap();
        authority
            .accept_authenticated(
                &artifact(1, ISSUED + 120, 0, (7, OLD_SECRET), None),
                TrustedClockSample::new(ISSUED + 10, monotonic),
            )
            .unwrap();
        let staged = authority
            .accept_authenticated(
                &artifact(
                    2,
                    ISSUED + 120,
                    ISSUED + 70,
                    (7, OLD_SECRET),
                    Some((8, NEW_SECRET)),
                ),
                TrustedClockSample::new(ISSUED + 20, monotonic + Duration::from_secs(10)),
            )
            .unwrap();
        assert_eq!(staged.expires_at(), monotonic + Duration::from_secs(60));

        assert_eq!(
            authority
                .accept_authenticated(
                    &artifact(
                        3,
                        ISSUED + 120,
                        ISSUED + 70,
                        (7, OLD_SECRET),
                        Some((8, NEW_SECRET)),
                    ),
                    TrustedClockSample::new(
                        ISSUED + 20 + 302,
                        monotonic + Duration::from_secs(11),
                    ),
                )
                .unwrap_err(),
            DiscoveryCredentialError::ClockDiscontinuity
        );
    }

    #[test]
    fn discovery_checkpoint_file_store_round_trips_and_rejects_corruption() {
        let root = std::env::temp_dir().join(format!(
            "aster-discovery-checkpoint-{}-{}",
            std::process::id(),
            ISSUED
        ));
        let _ = fs::remove_dir_all(&root);
        fs::create_dir(&root).unwrap();
        fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).unwrap();

        let initial = parse(&artifact(1, ISSUED + 60, 0, (7, OLD_SECRET), None));
        let checkpoint = DiscoveryCheckpoint::transition(None, &initial).unwrap();
        let mut store = FileDiscoveryCheckpointStore::new(&root).unwrap();
        assert_eq!(store.load().unwrap(), None);
        store.replace(&checkpoint).unwrap();
        assert_eq!(store.load().unwrap(), Some(checkpoint));
        assert!(!root.join("discovery-checkpoint.next").exists());

        fs::write(root.join("discovery-checkpoint"), b"corrupt").unwrap();
        assert_eq!(
            store.load().unwrap_err(),
            DiscoveryCredentialError::CheckpointCorrupt
        );
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn discovery_checkpoint_store_cleans_only_valid_bounded_next_file() {
        let root = std::env::temp_dir().join(format!(
            "aster-discovery-checkpoint-next-{}-{}",
            std::process::id(),
            ISSUED
        ));
        let _ = fs::remove_dir_all(&root);
        fs::create_dir(&root).unwrap();
        fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).unwrap();
        let next = root.join("discovery-checkpoint.next");
        fs::write(&next, [0x55; 32]).unwrap();
        fs::set_permissions(&next, fs::Permissions::from_mode(0o600)).unwrap();
        FileDiscoveryCheckpointStore::new(&root).unwrap();
        assert!(!next.exists());

        std::os::unix::fs::symlink(root.join("missing"), &next).unwrap();
        assert!(matches!(
            FileDiscoveryCheckpointStore::new(&root),
            Err(DiscoveryCredentialError::CheckpointCorrupt)
        ));
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn discovery_unprotected_reference_loader_validates_open_descriptor() {
        let root = std::env::temp_dir().join(format!(
            "aster-discovery-reference-{}-{}",
            std::process::id(),
            ISSUED
        ));
        let _ = fs::remove_dir_all(&root);
        fs::create_dir(&root).unwrap();
        fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).unwrap();
        let path = root.join("credential.bin");
        let bytes = artifact(1, ISSUED + 60, 0, (7, OLD_SECRET), None);
        fs::write(&path, &bytes).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
        assert_eq!(
            read_unprotected_reference_artifact(&root, "credential.bin")
                .unwrap()
                .as_slice(),
            bytes
        );

        fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();
        assert_eq!(
            read_unprotected_reference_artifact(&root, "credential.bin").unwrap_err(),
            DiscoveryCredentialError::UnprotectedReferenceRejected
        );
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
        let descriptor = File::open(&path).unwrap();
        let stat = rustix::fs::fstat(descriptor).unwrap();
        assert_eq!(
            validate_unprotected_reference_stat_for_owner(
                &stat,
                rustix::process::geteuid().as_raw().wrapping_add(1),
            )
            .unwrap_err(),
            DiscoveryCredentialError::UnprotectedReferenceRejected
        );

        let trailing_path = root.join("trailing.bin");
        let mut trailing = bytes.clone();
        trailing.push(0);
        fs::write(&trailing_path, trailing).unwrap();
        fs::set_permissions(&trailing_path, fs::Permissions::from_mode(0o600)).unwrap();
        assert_eq!(
            read_unprotected_reference_artifact(&root, "trailing.bin").unwrap_err(),
            DiscoveryCredentialError::UnprotectedReferenceRejected
        );

        std::os::unix::fs::symlink(&path, root.join("link.bin")).unwrap();
        assert_eq!(
            read_unprotected_reference_artifact(&root, "link.bin").unwrap_err(),
            DiscoveryCredentialError::UnprotectedReferenceRejected
        );
        fs::hard_link(&path, root.join("hard.bin")).unwrap();
        assert_eq!(
            read_unprotected_reference_artifact(&root, "credential.bin").unwrap_err(),
            DiscoveryCredentialError::UnprotectedReferenceRejected
        );
        fs::remove_file(root.join("hard.bin")).unwrap();

        let moved = root.join("moved.bin");
        assert_eq!(
            read_unprotected_reference_artifact_after_stat(&root, "credential.bin", || {
                fs::rename(&path, &moved).unwrap();
                fs::write(&path, [0x99; ONE_ENTRY_BYTES]).unwrap();
                fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
            })
            .unwrap_err(),
            DiscoveryCredentialError::UnprotectedReferenceRejected
        );

        assert_eq!(
            read_unprotected_reference_artifact_after_stat(&root, "moved.bin", || {
                let mut changed = bytes.clone();
                changed[80] ^= 1;
                fs::write(&moved, changed).unwrap();
            })
            .unwrap_err(),
            DiscoveryCredentialError::UnprotectedReferenceRejected
        );
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn discovery_authority_loads_authenticated_provisioning_source() {
        let root = std::env::temp_dir().join(format!(
            "aster-discovery-authority-{}-{}",
            std::process::id(),
            ISSUED
        ));
        let _ = fs::remove_dir_all(&root);
        fs::create_dir(&root).unwrap();
        fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).unwrap();
        let monotonic = Instant::now();
        let mut authority = DiscoveryCredentialAuthority::new(
            StaticLoader {
                bytes: artifact(1, ISSUED + 60, 0, (7, OLD_SECRET), None),
            },
            ProvisioningLoadId::new([0x33; 32]),
            ProvisioningSecretRef::from_opaque(vec![0x44]).unwrap(),
            StaticClock(TrustedClockSample::new(ISSUED + 10, monotonic)),
            SCOPE,
            &root,
        )
        .unwrap();
        let lease = authority.load().unwrap();
        assert_eq!(lease.emitting_generation(), 7);
        assert_eq!(lease.expires_at(), monotonic + Duration::from_secs(50));
        fs::remove_dir_all(root).unwrap();
    }
}
