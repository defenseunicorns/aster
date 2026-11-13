use hmac::{Hmac, KeyInit, Mac};
use sha2::{Digest, Sha256};
use std::{
    ffi::{OsStr, OsString},
    fmt,
    fs::File,
    io::{Read, Write},
    os::unix::fs::{MetadataExt, PermissionsExt},
    path::Path,
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
/// Fixed root-controlled process-wide namespace anchor for the BTLE authority.
///
/// Task 6 provisions this file and its exact custody profile. It is
/// intentionally not configurable and is outside the service-writable state
/// tree so replacing that tree cannot fork credential history.
pub const BTLE_AUTHORITY_LOCK_PATH: &str = "/run/aster-agent/btle-authority.lock";
const POSIX_ACL_ACCESS: &str = "system.posix_acl_access";
type ActiveCredentialState = (u32, [u8; 32], Option<(u32, [u8; 32])>);
/// Final move-only tuple accepted by the Linux adapter composition boundary.
pub type DiscoveryCredentialAdapterParts = (
    (u32, Zeroizing<[u8; 32]>),
    Option<(u32, Zeroizing<[u8; 32]>)>,
    Instant,
);

/// Move-only credential parts passed once into the Linux adapter.
///
/// Callers can only obtain this value together with an active authority guard;
/// its fields are private so it cannot be constructed independently.
pub struct DiscoveryCredentialMaterialParts {
    emitting: (u32, Zeroizing<[u8; 32]>),
    overlap: Option<(u32, Zeroizing<[u8; 32]>)>,
    expires_at: Instant,
}

impl DiscoveryCredentialMaterialParts {
    /// Moves the credential values into the adapter composition boundary.
    pub fn into_adapter_parts(self) -> DiscoveryCredentialAdapterParts {
        (self.emitting, self.overlap, self.expires_at)
    }
}

impl fmt::Debug for DiscoveryCredentialMaterialParts {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("DiscoveryCredentialMaterialParts([REDACTED])")
    }
}

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
    /// Authenticated artifact source could not produce the exact credential.
    ArtifactUnavailable,
}

/// Fixed-capacity, move-only ownership of one candidate ASTRBD02 artifact.
///
/// This value enforces only the host allocation boundary. Authenticating the
/// source is a provider precondition and is not claimed or repeated here.
pub struct BoundedDiscoveryCredentialArtifact {
    bytes: Zeroizing<[u8; TWO_ENTRY_BYTES]>,
    len: usize,
}

impl BoundedDiscoveryCredentialArtifact {
    /// Copies a provider-authenticated, zeroizing allocation into fixed host
    /// storage and rejects any value beyond the canonical artifact maximum.
    pub fn from_zeroizing(bytes: Zeroizing<Vec<u8>>) -> Result<Self, DiscoveryCredentialError> {
        if bytes.len() > TWO_ENTRY_BYTES {
            return Err(DiscoveryCredentialError::InvalidArtifact);
        }
        let len = bytes.len();
        let mut bounded = Zeroizing::new([0_u8; TWO_ENTRY_BYTES]);
        bounded[..len].copy_from_slice(&bytes);
        Ok(Self {
            bytes: bounded,
            len,
        })
    }

    /// Borrows only the initialized candidate artifact bytes.
    fn as_bytes(&self) -> &[u8] {
        &self.bytes[..self.len]
    }
}

impl fmt::Debug for BoundedDiscoveryCredentialArtifact {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("BoundedDiscoveryCredentialArtifact([REDACTED])")
    }
}

/// Move-only provider of one bounded ASTRBD02 artifact candidate.
///
/// Implementations must authenticate the source before constructing the
/// bounded value and must not parse, clone, cache, or expose discovery secrets.
/// Parsing and durable replacement remain solely owned by
/// [`PreparedDiscoveryCredential`].
pub trait DiscoveryCredentialArtifactProvider {
    /// Moves one source-authenticated candidate into the host authority.
    fn load_bounded_artifact(
        &mut self,
    ) -> Result<BoundedDiscoveryCredentialArtifact, DiscoveryCredentialError>;
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

/// Continuity guard for a lease derived from paired wall and monotonic time.
pub struct TrustedClockLeaseGuard {
    last_sample: TrustedClockSample,
}

impl TrustedClockLeaseGuard {
    /// Starts continuity tracking from the sample used to derive the lease.
    pub const fn new(initial_sample: TrustedClockSample) -> Self {
        Self {
            last_sample: initial_sample,
        }
    }

    /// Accepts the next sample or invalidates continuity on clock divergence.
    pub fn resample(&mut self, sample: TrustedClockSample) -> Result<(), DiscoveryCredentialError> {
        validate_clock_continuity(self.last_sample, sample)?;
        self.last_sample = sample;
        Ok(())
    }
}

fn validate_clock_continuity(
    previous: TrustedClockSample,
    sample: TrustedClockSample,
) -> Result<(), DiscoveryCredentialError> {
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

trait DiscoveryCheckpointStore {
    fn load(&mut self) -> Result<Option<DiscoveryCheckpoint>, DiscoveryCredentialError>;

    fn replace(&mut self, checkpoint: &DiscoveryCheckpoint)
    -> Result<(), DiscoveryCredentialError>;

    fn revalidate_namespace(&self) -> Result<(), DiscoveryCredentialError>;
}

struct FileDiscoveryCheckpointStore {
    state: PinnedStateRoot,
}

impl FileDiscoveryCheckpointStore {
    fn new(state: PinnedStateRoot) -> Result<Self, DiscoveryCredentialError> {
        state.revalidate()?;
        let store = Self { state };
        store.cleanup_next()?;
        Ok(store)
    }

    #[cfg(test)]
    fn new_for_test(root: &Path) -> Result<Self, DiscoveryCredentialError> {
        Self::new(PinnedStateRoot::open_for_test(root)?)
    }

    fn cleanup_next(&self) -> Result<(), DiscoveryCredentialError> {
        self.state.revalidate()?;
        let descriptor = match rustix::fs::openat(
            self.state.root(),
            CHECKPOINT_NEXT_FILE,
            rustix::fs::OFlags::RDONLY
                | rustix::fs::OFlags::CLOEXEC
                | rustix::fs::OFlags::NOFOLLOW
                | rustix::fs::OFlags::NONBLOCK,
            rustix::fs::Mode::empty(),
        ) {
            Ok(descriptor) => descriptor,
            Err(rustix::io::Errno::NOENT) => return Ok(()),
            Err(_) => return Err(DiscoveryCredentialError::CheckpointCorrupt),
        };
        let file = File::from(descriptor);
        let metadata = file
            .metadata()
            .map_err(|_| DiscoveryCredentialError::CheckpointCorrupt)?;
        if !metadata.file_type().is_file()
            || metadata.uid() != rustix::process::geteuid().as_raw()
            || metadata.permissions().mode() & 0o077 != 0
            || metadata.nlink() != 1
            || metadata.len() > CHECKPOINT_BYTES as u64
        {
            return Err(DiscoveryCredentialError::CheckpointCorrupt);
        }
        rustix::fs::unlinkat(
            self.state.root(),
            CHECKPOINT_NEXT_FILE,
            rustix::fs::AtFlags::empty(),
        )
        .map_err(|_| DiscoveryCredentialError::CheckpointUnavailable)?;
        self.state
            .root()
            .sync_all()
            .map_err(|_| DiscoveryCredentialError::CheckpointUnavailable)
    }

    fn replace_with_before_rename<F>(
        &mut self,
        checkpoint: &DiscoveryCheckpoint,
        before_rename: F,
    ) -> Result<(), DiscoveryCredentialError>
    where
        F: FnOnce(),
    {
        self.cleanup_next()?;
        self.state.revalidate()?;
        let mut file = File::from(
            rustix::fs::openat(
                self.state.root(),
                CHECKPOINT_NEXT_FILE,
                rustix::fs::OFlags::WRONLY
                    | rustix::fs::OFlags::CREATE
                    | rustix::fs::OFlags::EXCL
                    | rustix::fs::OFlags::CLOEXEC
                    | rustix::fs::OFlags::NOFOLLOW,
                rustix::fs::Mode::RUSR | rustix::fs::Mode::WUSR,
            )
            .map_err(|_| DiscoveryCredentialError::CheckpointUnavailable)?,
        );
        let bytes = encode_checkpoint(checkpoint);
        file.write_all(&bytes)
            .and_then(|()| file.sync_all())
            .map_err(|_| DiscoveryCredentialError::CheckpointUnavailable)?;
        validate_checkpoint_metadata(&file)?;
        before_rename();
        self.state.revalidate()?;
        rustix::fs::renameat(
            self.state.root(),
            CHECKPOINT_NEXT_FILE,
            self.state.root(),
            CHECKPOINT_FILE,
        )
        .map_err(|_| DiscoveryCredentialError::CheckpointUnavailable)?;
        self.state
            .root()
            .sync_all()
            .map_err(|_| DiscoveryCredentialError::CheckpointUnavailable)
    }

    #[cfg(test)]
    fn replace_after_write_for_test<F>(
        &mut self,
        checkpoint: &DiscoveryCheckpoint,
        before_rename: F,
    ) -> Result<(), DiscoveryCredentialError>
    where
        F: FnOnce(),
    {
        self.replace_with_before_rename(checkpoint, before_rename)
    }
}

struct PinnedStateRoot {
    ancestors: Vec<File>,
    parent: File,
    basename: OsString,
    root: File,
    device: u64,
    inode: u64,
    service_uid: libc::uid_t,
    enforce_production_custody: bool,
}

impl PinnedStateRoot {
    fn open_production(path: &Path) -> Result<Self, DiscoveryCredentialError> {
        Self::open(path, true)
    }

    #[cfg(any(test, feature = "test-support"))]
    fn open_for_test(path: &Path) -> Result<Self, DiscoveryCredentialError> {
        Self::open(path, false)
    }

    fn open(
        path: &Path,
        enforce_production_custody: bool,
    ) -> Result<Self, DiscoveryCredentialError> {
        let components = absolute_normal_components(path)?;
        let (basename, parent_components) = components
            .split_last()
            .ok_or(DiscoveryCredentialError::CheckpointUnavailable)?;
        let flags = directory_open_flags();
        let mut directory = open_root_directory()?;
        let mut ancestors = Vec::with_capacity(parent_components.len() + 1);
        if enforce_production_custody {
            validate_root_owned_ancestor(&directory)?;
        }
        ancestors.push(
            directory
                .try_clone()
                .map_err(|_| DiscoveryCredentialError::CheckpointUnavailable)?,
        );
        for component in parent_components {
            directory = open_child_directory(&directory, component)?;
            if enforce_production_custody {
                validate_root_owned_ancestor(&directory)?;
            }
            ancestors.push(
                directory
                    .try_clone()
                    .map_err(|_| DiscoveryCredentialError::CheckpointUnavailable)?,
            );
        }
        let parent = directory;
        let root = File::from(
            rustix::fs::openat(&parent, basename, flags, rustix::fs::Mode::empty())
                .map_err(|_| DiscoveryCredentialError::CheckpointUnavailable)?,
        );
        let service_uid = rustix::process::geteuid().as_raw();
        if enforce_production_custody {
            validate_service_state_root(&root, service_uid)?;
        } else {
            validate_test_state_root(&root)?;
        }
        let metadata = root
            .metadata()
            .map_err(|_| DiscoveryCredentialError::CheckpointUnavailable)?;
        let pinned = Self {
            ancestors,
            parent,
            basename: basename.clone(),
            root,
            device: metadata.dev(),
            inode: metadata.ino(),
            service_uid,
            enforce_production_custody,
        };
        pinned.revalidate()?;
        Ok(pinned)
    }

    fn root(&self) -> &File {
        &self.root
    }

    fn revalidate(&self) -> Result<(), DiscoveryCredentialError> {
        if self.enforce_production_custody {
            for ancestor in &self.ancestors {
                validate_root_owned_ancestor(ancestor)?;
            }
            validate_service_state_root(&self.root, self.service_uid)?;
        } else {
            validate_test_state_root(&self.root)?;
        }
        let current = File::from(
            rustix::fs::openat(
                &self.parent,
                &self.basename,
                directory_open_flags(),
                rustix::fs::Mode::empty(),
            )
            .map_err(|_| DiscoveryCredentialError::CheckpointUnavailable)?,
        );
        if self.enforce_production_custody {
            validate_service_state_root(&current, self.service_uid)?;
        } else {
            validate_test_state_root(&current)?;
        }
        let metadata = current
            .metadata()
            .map_err(|_| DiscoveryCredentialError::CheckpointUnavailable)?;
        if metadata.dev() != self.device || metadata.ino() != self.inode {
            return Err(DiscoveryCredentialError::CheckpointUnavailable);
        }
        Ok(())
    }

    fn matches_path(&self, path: &Path) -> Result<bool, DiscoveryCredentialError> {
        self.revalidate()?;
        let candidate = Self::open(path, self.enforce_production_custody)?;
        Ok(candidate.device == self.device && candidate.inode == self.inode)
    }

    fn matches_pinned_path(&self, path: &Path) -> Result<bool, DiscoveryCredentialError> {
        self.revalidate()?;
        let metadata = path
            .metadata()
            .map_err(|_| DiscoveryCredentialError::CheckpointUnavailable)?;
        Ok(metadata.is_dir() && metadata.dev() == self.device && metadata.ino() == self.inode)
    }
}

fn directory_open_flags() -> rustix::fs::OFlags {
    rustix::fs::OFlags::RDONLY
        | rustix::fs::OFlags::DIRECTORY
        | rustix::fs::OFlags::CLOEXEC
        | rustix::fs::OFlags::NOFOLLOW
        | rustix::fs::OFlags::NONBLOCK
}

fn absolute_normal_components(path: &Path) -> Result<Vec<OsString>, DiscoveryCredentialError> {
    use std::path::Component;

    if !path.is_absolute() {
        return Err(DiscoveryCredentialError::CheckpointUnavailable);
    }
    path.components()
        .filter_map(|component| match component {
            Component::RootDir => None,
            Component::Normal(name) => Some(Ok(name.to_owned())),
            Component::CurDir | Component::ParentDir | Component::Prefix(_) => {
                Some(Err(DiscoveryCredentialError::CheckpointUnavailable))
            }
        })
        .collect()
}

fn open_root_directory() -> Result<File, DiscoveryCredentialError> {
    rustix::fs::open("/", directory_open_flags(), rustix::fs::Mode::empty())
        .map(File::from)
        .map_err(|_| DiscoveryCredentialError::CheckpointUnavailable)
}

fn open_child_directory(parent: &File, name: &OsStr) -> Result<File, DiscoveryCredentialError> {
    rustix::fs::openat(
        parent,
        name,
        directory_open_flags(),
        rustix::fs::Mode::empty(),
    )
    .map(File::from)
    .map_err(|_| DiscoveryCredentialError::CheckpointUnavailable)
}

fn open_absolute_nofollow(path: &Path) -> Result<(File, Vec<File>), DiscoveryCredentialError> {
    let components = absolute_normal_components(path)?;
    let (final_component, parent_components) = components
        .split_last()
        .ok_or(DiscoveryCredentialError::CheckpointUnavailable)?;
    let mut directory = open_root_directory()?;
    let mut ancestors = Vec::new();
    validate_root_owned_ancestor(&directory)?;
    ancestors.push(
        directory
            .try_clone()
            .map_err(|_| DiscoveryCredentialError::CheckpointUnavailable)?,
    );
    for component in parent_components {
        directory = open_child_directory(&directory, component)?;
        validate_root_owned_ancestor(&directory)?;
        ancestors.push(
            directory
                .try_clone()
                .map_err(|_| DiscoveryCredentialError::CheckpointUnavailable)?,
        );
    }
    let file = File::from(
        rustix::fs::openat(
            &directory,
            final_component,
            rustix::fs::OFlags::RDONLY
                | rustix::fs::OFlags::CLOEXEC
                | rustix::fs::OFlags::NOFOLLOW
                | rustix::fs::OFlags::NONBLOCK,
            rustix::fs::Mode::empty(),
        )
        .map_err(|_| DiscoveryCredentialError::CheckpointUnavailable)?,
    );
    Ok((file, ancestors))
}

fn validate_root_owned_ancestor(directory: &File) -> Result<(), DiscoveryCredentialError> {
    validate_root_owned_ancestor_metadata(&custody_metadata(directory)?)
}

fn validate_service_state_root(
    root: &File,
    expected_uid: libc::uid_t,
) -> Result<(), DiscoveryCredentialError> {
    validate_service_state_root_metadata(&custody_metadata(root)?, expected_uid)
}

fn validate_test_state_root(root: &File) -> Result<(), DiscoveryCredentialError> {
    let metadata = root
        .metadata()
        .map_err(|_| DiscoveryCredentialError::CheckpointUnavailable)?;
    if !metadata.file_type().is_dir()
        || metadata.uid() != rustix::process::geteuid().as_raw()
        || metadata.permissions().mode() & 0o077 != 0
    {
        return Err(DiscoveryCredentialError::CheckpointCorrupt);
    }
    Ok(())
}

struct AuthorityLock {
    _file: File,
}

impl AuthorityLock {
    fn acquire_production() -> Result<Self, DiscoveryCredentialError> {
        let service_uid = rustix::process::geteuid().as_raw();
        let (lock, ancestors) = open_absolute_nofollow(Path::new(BTLE_AUTHORITY_LOCK_PATH))?;
        for ancestor in &ancestors {
            validate_root_owned_ancestor(ancestor)?;
        }
        validate_authority_lock(&lock, service_uid)?;
        Self::acquire(lock, Some(service_uid))
    }

    #[cfg(any(test, feature = "test-support"))]
    fn acquire_for_test(lock: File) -> Result<Self, DiscoveryCredentialError> {
        Self::acquire(lock, None)
    }

    fn acquire(
        lock: File,
        production_service_uid: Option<libc::uid_t>,
    ) -> Result<Self, DiscoveryCredentialError> {
        if let Some(service_uid) = production_service_uid {
            validate_authority_lock(&lock, service_uid)?;
        }
        match rustix::fs::flock(&lock, rustix::fs::FlockOperation::NonBlockingLockExclusive) {
            Ok(()) => {}
            Err(rustix::io::Errno::WOULDBLOCK) => {
                return Err(DiscoveryCredentialError::CheckpointUnavailable);
            }
            Err(_) => return Err(DiscoveryCredentialError::CheckpointUnavailable),
        }
        if let Some(service_uid) = production_service_uid {
            validate_authority_lock(&lock, service_uid)?;
        }
        Ok(Self { _file: lock })
    }
}

fn validate_authority_lock(
    lock: &File,
    service_uid: libc::uid_t,
) -> Result<(), DiscoveryCredentialError> {
    validate_authority_lock_metadata(&custody_metadata(lock)?, service_uid)
}

#[derive(Clone)]
struct CustodyMetadata {
    is_file: bool,
    is_directory: bool,
    uid: libc::uid_t,
    gid: libc::gid_t,
    mode: u32,
    links: u64,
    length: u64,
    access_acl: Option<Vec<u8>>,
}

fn custody_metadata(file: &File) -> Result<CustodyMetadata, DiscoveryCredentialError> {
    let metadata = file
        .metadata()
        .map_err(|_| DiscoveryCredentialError::CheckpointCorrupt)?;
    Ok(CustodyMetadata {
        is_file: metadata.file_type().is_file(),
        is_directory: metadata.file_type().is_dir(),
        uid: metadata.uid(),
        gid: metadata.gid(),
        mode: metadata.permissions().mode() & 0o777,
        links: metadata.nlink(),
        length: metadata.len(),
        access_acl: read_access_acl(file)?,
    })
}

fn validate_root_owned_ancestor_metadata(
    metadata: &CustodyMetadata,
) -> Result<(), DiscoveryCredentialError> {
    if !metadata.is_directory
        || metadata.uid != 0
        || metadata.mode & 0o022 != 0
        || metadata.access_acl.is_some()
    {
        return Err(DiscoveryCredentialError::CheckpointCorrupt);
    }
    Ok(())
}

fn validate_service_state_root_metadata(
    metadata: &CustodyMetadata,
    service_uid: libc::uid_t,
) -> Result<(), DiscoveryCredentialError> {
    if !metadata.is_directory
        || metadata.uid != service_uid
        || metadata.mode & 0o077 != 0
        || metadata.access_acl.is_some()
    {
        return Err(DiscoveryCredentialError::CheckpointCorrupt);
    }
    Ok(())
}

fn validate_authority_lock_metadata(
    metadata: &CustodyMetadata,
    service_uid: libc::uid_t,
) -> Result<(), DiscoveryCredentialError> {
    if !metadata.is_file
        || metadata.uid != 0
        || metadata.gid != 0
        || metadata.mode != 0o440
        || metadata.links != 1
        || metadata.length != 0
        || metadata.access_acl.as_deref()
            != Some(expected_authority_lock_acl(service_uid).as_slice())
    {
        return Err(DiscoveryCredentialError::CheckpointCorrupt);
    }
    Ok(())
}

fn read_access_acl(file: &File) -> Result<Option<Vec<u8>>, DiscoveryCredentialError> {
    let mut bytes = [0_u8; 128];
    match rustix::fs::fgetxattr(file, POSIX_ACL_ACCESS, &mut bytes) {
        Ok(length) => Ok(Some(bytes[..length].to_vec())),
        Err(rustix::io::Errno::NODATA) => Ok(None),
        Err(_) => Err(DiscoveryCredentialError::CheckpointCorrupt),
    }
}

fn expected_authority_lock_acl(service_uid: libc::uid_t) -> [u8; 44] {
    const ACL_UNDEFINED_ID: u32 = u32::MAX;
    let entries = [
        (0x01_u16, 0o4_u16, ACL_UNDEFINED_ID),
        (0x02_u16, 0o4_u16, service_uid),
        (0x04_u16, 0_u16, ACL_UNDEFINED_ID),
        (0x10_u16, 0o4_u16, ACL_UNDEFINED_ID),
        (0x20_u16, 0_u16, ACL_UNDEFINED_ID),
    ];
    let mut acl = [0_u8; 44];
    acl[..4].copy_from_slice(&2_u32.to_le_bytes());
    for (index, (tag, permissions, id)) in entries.into_iter().enumerate() {
        let offset = 4 + index * 8;
        acl[offset..offset + 2].copy_from_slice(&tag.to_le_bytes());
        acl[offset + 2..offset + 4].copy_from_slice(&permissions.to_le_bytes());
        acl[offset + 4..offset + 8].copy_from_slice(&id.to_le_bytes());
    }
    acl
}

impl DiscoveryCheckpointStore for FileDiscoveryCheckpointStore {
    fn load(&mut self) -> Result<Option<DiscoveryCheckpoint>, DiscoveryCredentialError> {
        self.state.revalidate()?;
        let descriptor = match rustix::fs::openat(
            self.state.root(),
            CHECKPOINT_FILE,
            rustix::fs::OFlags::RDONLY
                | rustix::fs::OFlags::CLOEXEC
                | rustix::fs::OFlags::NOFOLLOW
                | rustix::fs::OFlags::NONBLOCK,
            rustix::fs::Mode::empty(),
        ) {
            Ok(descriptor) => descriptor,
            Err(rustix::io::Errno::NOENT) => return Ok(None),
            Err(_) => return Err(DiscoveryCredentialError::CheckpointCorrupt),
        };
        let mut file = File::from(descriptor);
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
        self.replace_with_before_rename(checkpoint, || {})
    }

    fn revalidate_namespace(&self) -> Result<(), DiscoveryCredentialError> {
        self.state.revalidate()
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

#[cfg(target_os = "linux")]
fn read_unprotected_reference_artifact(
    parent: &Path,
    basename: &str,
) -> Result<Zeroizing<Vec<u8>>, DiscoveryCredentialError> {
    read_unprotected_reference_artifact_after_stat(parent, basename, || {})
}

#[cfg(target_os = "linux")]
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

#[cfg(target_os = "linux")]
fn validate_unprotected_reference_stat(
    stat: &rustix::fs::Stat,
) -> Result<(), DiscoveryCredentialError> {
    validate_unprotected_reference_stat_for_owner(stat, rustix::process::geteuid().as_raw())
}

#[cfg(target_os = "linux")]
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

/// Zeroizing host-owned lease retained inside a prepared authority value.
struct LeasedDiscoveryCredentialMaterial {
    emitting: CredentialEntry,
    overlap: Option<CredentialEntry>,
    expires_at: Instant,
}

impl LeasedDiscoveryCredentialMaterial {
    #[cfg(test)]
    const fn emitting_generation(&self) -> u32 {
        self.emitting.generation
    }

    fn overlap_generation(&self) -> Option<u32> {
        self.overlap.as_ref().map(|entry| entry.generation)
    }

    #[cfg(test)]
    const fn expires_at(&self) -> Instant {
        self.expires_at
    }

    fn into_parts(self) -> DiscoveryCredentialMaterialParts {
        DiscoveryCredentialMaterialParts {
            emitting: (self.emitting.generation, self.emitting.secret),
            overlap: self.overlap.map(|entry| (entry.generation, entry.secret)),
            expires_at: self.expires_at,
        }
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

    fn accept_provider_artifact(
        &mut self,
        bytes: &[u8],
        sample: TrustedClockSample,
    ) -> Result<LeasedDiscoveryCredentialMaterial, DiscoveryCredentialError> {
        self.accept_provider_artifact_with_expiry(bytes, sample, |instant, duration| {
            instant.checked_add(duration)
        })
    }

    fn accept_provider_artifact_with_expiry<F>(
        &mut self,
        bytes: &[u8],
        sample: TrustedClockSample,
        derive_expiry: F,
    ) -> Result<LeasedDiscoveryCredentialMaterial, DiscoveryCredentialError>
    where
        F: FnOnce(Instant, std::time::Duration) -> Option<Instant>,
    {
        self.accept_provider_artifact_with_hooks(bytes, sample, derive_expiry, || {})
    }

    fn accept_provider_artifact_with_hooks<F, H>(
        &mut self,
        bytes: &[u8],
        sample: TrustedClockSample,
        derive_expiry: F,
        after_checkpoint: H,
    ) -> Result<LeasedDiscoveryCredentialMaterial, DiscoveryCredentialError>
    where
        F: FnOnce(Instant, std::time::Duration) -> Option<Instant>,
        H: FnOnce(),
    {
        self.validate_clock(sample)?;
        let artifact =
            ParsedDiscoveryArtifact::parse(bytes, self.expected_scope, sample.wall_unix_seconds)?;
        let previous = self.checkpoint_store.load()?;
        let next = DiscoveryCheckpoint::transition(previous.as_ref(), &artifact)?;
        let effective_not_after = if artifact.overlap.is_some() {
            artifact.lease_not_after.min(artifact.overlap_not_after)
        } else {
            artifact.lease_not_after
        };
        let remaining = effective_not_after
            .checked_sub(sample.wall_unix_seconds)
            .ok_or(DiscoveryCredentialError::InvalidArtifact)?;
        let expires_at = derive_expiry(sample.monotonic, std::time::Duration::from_secs(remaining))
            .ok_or(DiscoveryCredentialError::TimeOverflow)?;
        let prepared = LeasedDiscoveryCredentialMaterial {
            emitting: artifact.emitting,
            overlap: artifact.overlap,
            expires_at,
        };
        self.checkpoint_store.replace(&next)?;
        after_checkpoint();
        self.checkpoint_store.revalidate_namespace()?;
        self.last_clock_sample = Some(sample);
        Ok(prepared)
    }

    fn validate_clock(&self, sample: TrustedClockSample) -> Result<(), DiscoveryCredentialError> {
        let Some(previous) = self.last_clock_sample else {
            return Ok(());
        };
        validate_clock_continuity(previous, sample)
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

struct DiscoveryCredentialAuthority<L, C> {
    loader: L,
    clock: C,
    core: DiscoveryCredentialAuthorityCore<FileDiscoveryCheckpointStore>,
    _authority_lock: AuthorityLock,
}

impl<L, C> DiscoveryCredentialAuthority<L, C>
where
    L: DiscoveryCredentialArtifactProvider,
    C: TrustedClock,
{
    fn new(
        loader: L,
        clock: C,
        expected_scope: [u8; 32],
        checkpoint_root: &Path,
    ) -> Result<Self, DiscoveryCredentialError> {
        let state = PinnedStateRoot::open_production(checkpoint_root)?;
        let authority_lock = AuthorityLock::acquire_production()?;
        state.revalidate()?;
        let checkpoint_store = FileDiscoveryCheckpointStore::new(state)?;
        Ok(Self {
            loader,
            clock,
            core: DiscoveryCredentialAuthorityCore::new(expected_scope, checkpoint_store)?,
            _authority_lock: authority_lock,
        })
    }

    #[cfg(any(test, feature = "test-support"))]
    fn new_for_test(
        loader: L,
        clock: C,
        expected_scope: [u8; 32],
        checkpoint_root: &Path,
        authority_lock: File,
    ) -> Result<Self, DiscoveryCredentialError> {
        let state = PinnedStateRoot::open_for_test(checkpoint_root)?;
        let authority_lock = AuthorityLock::acquire_for_test(authority_lock)?;
        state.revalidate()?;
        let checkpoint_store = FileDiscoveryCheckpointStore::new(state)?;
        Ok(Self {
            loader,
            clock,
            core: DiscoveryCredentialAuthorityCore::new(expected_scope, checkpoint_store)?,
            _authority_lock: authority_lock,
        })
    }

    fn prepare_once(
        mut self,
    ) -> Result<PreparedDiscoveryCredential<L, C>, DiscoveryCredentialError> {
        let sample = self.clock.sample()?;
        let artifact = self.loader.load_bounded_artifact()?;
        let material = self
            .core
            .accept_provider_artifact(artifact.as_bytes(), sample)?;
        Ok(PreparedDiscoveryCredential {
            material,
            authority: self,
        })
    }

    fn resample_clock(&mut self) -> Result<(), DiscoveryCredentialError> {
        let sample = self.clock.sample()?;
        self.core.observe_clock(sample)
    }

    fn matches_binding(
        &self,
        expected_scope: [u8; 32],
        checkpoint_root: &Path,
    ) -> Result<bool, DiscoveryCredentialError> {
        if self.core.expected_scope != expected_scope {
            return Ok(false);
        }
        self.core
            .checkpoint_store
            .state
            .matches_path(checkpoint_root)
    }
}

/// One prepared production discovery credential and its exclusive authority.
///
/// Construction performs exactly one provider load and commits the authority
/// checkpoint before returning. The material cannot be separated from the
/// authority without also receiving an active must-use guard that retains the
/// fixed external lock.
pub struct PreparedDiscoveryCredential<L, C> {
    material: LeasedDiscoveryCredentialMaterial,
    authority: DiscoveryCredentialAuthority<L, C>,
}

impl<L, C> PreparedDiscoveryCredential<L, C>
where
    L: DiscoveryCredentialArtifactProvider,
    C: TrustedClock,
{
    /// Checks the non-secret deployment scope and pinned state-root identity
    /// that were used to prepare this authority.
    pub fn matches_binding(
        &self,
        expected_scope: [u8; 32],
        checkpoint_root: &Path,
    ) -> Result<bool, DiscoveryCredentialError> {
        self.authority
            .matches_binding(expected_scope, checkpoint_root)
    }

    /// Zeroizes credential material that will not be provisioned into an
    /// adapter while retaining the exclusive authority and rollback custody.
    pub fn retire_material(self) -> ActiveDiscoveryCredentialAuthority<L, C> {
        let Self {
            material,
            authority,
        } = self;
        drop(material);
        ActiveDiscoveryCredentialAuthority { authority }
    }

    /// Moves the adapter credential parts together with the authority guard
    /// that must remain alive for their full active lifetime.
    pub fn into_parts(
        self,
    ) -> (
        DiscoveryCredentialMaterialParts,
        ActiveDiscoveryCredentialAuthority<L, C>,
    ) {
        (
            self.material.into_parts(),
            ActiveDiscoveryCredentialAuthority {
                authority: self.authority,
            },
        )
    }
}

/// Active production discovery authority retained after adapter provisioning.
#[must_use = "retain active authority for credential lifetime or exclusive custody"]
pub struct ActiveDiscoveryCredentialAuthority<L, C> {
    authority: DiscoveryCredentialAuthority<L, C>,
}

impl<L, C> ActiveDiscoveryCredentialAuthority<L, C>
where
    L: DiscoveryCredentialArtifactProvider,
    C: TrustedClock,
{
    /// Checks that the retained authority still names the expected scope and
    /// the state root pinned by the running node.
    pub fn matches_binding(
        &self,
        expected_scope: [u8; 32],
        checkpoint_root: &Path,
    ) -> Result<bool, DiscoveryCredentialError> {
        self.authority
            .matches_binding(expected_scope, checkpoint_root)
    }

    /// Checks the retained scope and state-root identity against a directory
    /// path already pinned by the running node. Unlike [`Self::matches_binding`],
    /// this accepts a descriptor-backed path while preserving the original
    /// configured-path custody revalidation.
    pub fn matches_pinned_binding(
        &self,
        expected_scope: [u8; 32],
        pinned_checkpoint_root: &Path,
    ) -> Result<bool, DiscoveryCredentialError> {
        if self.authority.core.expected_scope != expected_scope {
            return Ok(false);
        }
        self.authority
            .core
            .checkpoint_store
            .state
            .matches_pinned_path(pinned_checkpoint_root)
    }

    /// Resamples the trusted clock without loading another credential artifact.
    pub fn resample_clock(&mut self) -> Result<(), DiscoveryCredentialError> {
        self.authority.resample_clock()
    }
}

/// Authenticates and prepares exactly one production discovery credential.
pub fn prepare_discovery_credential<L, C>(
    loader: L,
    clock: C,
    expected_scope: [u8; 32],
    checkpoint_root: &Path,
) -> Result<PreparedDiscoveryCredential<L, C>, DiscoveryCredentialError>
where
    L: DiscoveryCredentialArtifactProvider,
    C: TrustedClock,
{
    DiscoveryCredentialAuthority::new(loader, clock, expected_scope, checkpoint_root)?
        .prepare_once()
}

/// Test-only preparation seam using an explicit already-open authority anchor.
#[cfg(any(test, feature = "test-support"))]
#[doc(hidden)]
pub fn prepare_discovery_credential_for_test<L, C>(
    loader: L,
    clock: C,
    expected_scope: [u8; 32],
    checkpoint_root: &Path,
    authority_lock: File,
) -> Result<PreparedDiscoveryCredential<L, C>, DiscoveryCredentialError>
where
    L: DiscoveryCredentialArtifactProvider,
    C: TrustedClock,
{
    DiscoveryCredentialAuthority::new_for_test(
        loader,
        clock,
        expected_scope,
        checkpoint_root,
        authority_lock,
    )?
    .prepare_once()
}

#[cfg(target_os = "linux")]
#[derive(Default)]
struct UnprotectedReferenceCheckpointStore {
    checkpoint: Option<DiscoveryCheckpoint>,
}

#[cfg(target_os = "linux")]
impl DiscoveryCheckpointStore for UnprotectedReferenceCheckpointStore {
    fn load(&mut self) -> Result<Option<DiscoveryCheckpoint>, DiscoveryCredentialError> {
        Ok(self.checkpoint.clone())
    }

    fn replace(
        &mut self,
        checkpoint: &DiscoveryCheckpoint,
    ) -> Result<(), DiscoveryCredentialError> {
        self.checkpoint = Some(checkpoint.clone());
        Ok(())
    }

    fn revalidate_namespace(&self) -> Result<(), DiscoveryCredentialError> {
        Ok(())
    }
}

/// Evaluator-only material owner retaining its explicitly non-production
/// in-memory authority until the caller moves out the lease and guard.
#[cfg(target_os = "linux")]
pub struct UnprotectedReferenceDiscoveryCredentials {
    material: LeasedDiscoveryCredentialMaterial,
    authority: DiscoveryCredentialAuthorityCore<UnprotectedReferenceCheckpointStore>,
}

/// Lifetime guard for evaluator-only leased discovery credentials.
///
/// This guard intentionally does not claim production exclusivity or durable
/// rollback protection; the evaluator authority is process-local and
/// in-memory. Production callers use [`prepare_discovery_credential`].
#[cfg(target_os = "linux")]
#[must_use = "the evaluator authority guard must live as long as its leased credentials"]
pub struct UnprotectedReferenceAuthorityGuard {
    _authority: DiscoveryCredentialAuthorityCore<UnprotectedReferenceCheckpointStore>,
}

#[cfg(target_os = "linux")]
impl UnprotectedReferenceDiscoveryCredentials {
    /// Moves the lease parts out while returning the authority guard that must
    /// remain alive for the evaluator credential lifetime.
    pub fn into_parts(
        self,
    ) -> (
        DiscoveryCredentialMaterialParts,
        UnprotectedReferenceAuthorityGuard,
    ) {
        (
            self.material.into_parts(),
            UnprotectedReferenceAuthorityGuard {
                _authority: self.authority,
            },
        )
    }
}

/// Loads the explicitly non-production evaluator artifact through the shared
/// parser and transition machine with a process-local in-memory authority.
#[cfg(target_os = "linux")]
pub fn load_unprotected_reference_discovery_credentials(
    expected_scope: [u8; 32],
    artifact_parent: &Path,
    artifact_basename: &str,
    sample: TrustedClockSample,
) -> Result<UnprotectedReferenceDiscoveryCredentials, DiscoveryCredentialError> {
    let bytes = read_unprotected_reference_artifact(artifact_parent, artifact_basename)?;
    let mut authority = DiscoveryCredentialAuthorityCore::new(
        expected_scope,
        UnprotectedReferenceCheckpointStore::default(),
    )?;
    let material = authority.accept_provider_artifact(&bytes, sample)?;
    Ok(UnprotectedReferenceDiscoveryCredentials {
        material,
        authority,
    })
}

/// Exercises the exact credential artifact parser without exposing it to
/// production callers.
#[cfg(feature = "fuzzing")]
#[doc(hidden)]
pub fn fuzz_parse_discovery_credential_artifact(bytes: &[u8]) {
    let mut expected_scope = bytes
        .get(41..73)
        .and_then(|value| value.try_into().ok())
        .unwrap_or([1; 32]);
    if expected_scope == [0; 32] {
        expected_scope[0] = 1;
    }
    let wall_now = bytes
        .get(17..25)
        .and_then(|value| value.try_into().ok())
        .map(u64::from_be_bytes)
        .unwrap_or(1);
    let _ = ParsedDiscoveryArtifact::parse(bytes, expected_scope, wall_now);
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{
        cell::Cell,
        fs::{self, OpenOptions},
        os::unix::fs::PermissionsExt,
        rc::Rc,
        time::{Duration, Instant},
    };

    const SCOPE: [u8; 32] = [0x42; 32];
    const OLD_SECRET: [u8; 32] = [0x11; 32];
    const NEW_SECRET: [u8; 32] = [0x22; 32];
    const ISSUED: u64 = 1_800_000_000;

    fn open_test_anchor(path: &Path) -> File {
        OpenOptions::new()
            .read(true)
            .write(true)
            .open(path)
            .unwrap()
    }

    #[derive(Default)]
    struct MemoryCheckpointStore {
        checkpoint: Option<DiscoveryCheckpoint>,
        replacements: usize,
        fail_replace: bool,
        fail_revalidate: bool,
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

    struct CountingLoader {
        bytes: Vec<u8>,
        loads: Rc<Cell<usize>>,
    }

    impl DiscoveryCredentialArtifactProvider for StaticLoader {
        fn load_bounded_artifact(
            &mut self,
        ) -> Result<BoundedDiscoveryCredentialArtifact, DiscoveryCredentialError> {
            BoundedDiscoveryCredentialArtifact::from_zeroizing(Zeroizing::new(std::mem::take(
                &mut self.bytes,
            )))
        }
    }

    impl DiscoveryCredentialArtifactProvider for CountingLoader {
        fn load_bounded_artifact(
            &mut self,
        ) -> Result<BoundedDiscoveryCredentialArtifact, DiscoveryCredentialError> {
            self.loads.set(self.loads.get() + 1);
            BoundedDiscoveryCredentialArtifact::from_zeroizing(Zeroizing::new(std::mem::take(
                &mut self.bytes,
            )))
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

        fn revalidate_namespace(&self) -> Result<(), DiscoveryCredentialError> {
            if self.fail_revalidate {
                Err(DiscoveryCredentialError::CheckpointUnavailable)
            } else {
                Ok(())
            }
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
    fn bounded_discovery_artifact_owns_only_canonical_maximum_capacity() {
        // Break caught: a provider implementation must not transfer an
        // attacker-sized allocation across the host authority boundary.
        let one = artifact(1, ISSUED + 60, 0, (7, OLD_SECRET), None);
        let bounded =
            BoundedDiscoveryCredentialArtifact::from_zeroizing(Zeroizing::new(one.clone()))
                .unwrap();
        assert_eq!(bounded.as_bytes(), one);
        assert_eq!(
            format!("{bounded:?}"),
            "BoundedDiscoveryCredentialArtifact([REDACTED])"
        );
        assert_eq!(
            BoundedDiscoveryCredentialArtifact::from_zeroizing(Zeroizing::new(vec![
                0x42;
                TWO_ENTRY_BYTES
                    + 1
            ]))
            .unwrap_err(),
            DiscoveryCredentialError::InvalidArtifact
        );
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
            .accept_provider_artifact(
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
                .accept_provider_artifact(
                    &artifact(1, ISSUED + 60, 0, (7, OLD_SECRET), None),
                    TrustedClockSample::new(ISSUED + 10, monotonic),
                )
                .unwrap_err(),
            DiscoveryCredentialError::CheckpointUnavailable
        );

        let mut namespace_swapped = DiscoveryCredentialAuthorityCore::new(
            SCOPE,
            MemoryCheckpointStore {
                fail_revalidate: true,
                ..MemoryCheckpointStore::default()
            },
        )
        .unwrap();
        assert_eq!(
            namespace_swapped
                .accept_provider_artifact(
                    &artifact(1, ISSUED + 60, 0, (7, OLD_SECRET), None),
                    TrustedClockSample::new(ISSUED + 10, monotonic),
                )
                .unwrap_err(),
            DiscoveryCredentialError::CheckpointUnavailable
        );
        assert_eq!(namespace_swapped.checkpoint_store().replacements, 1);
    }

    #[test]
    fn discovery_authority_derivation_failure_leaves_checkpoint_unchanged() {
        // Break caught: publishing the next checkpoint before fallible lease
        // derivation can consume a rotation sequence without issuing a lease.
        let monotonic = Instant::now();
        let mut authority =
            DiscoveryCredentialAuthorityCore::new(SCOPE, MemoryCheckpointStore::default()).unwrap();
        authority
            .accept_provider_artifact(
                &artifact(1, ISSUED + 60, 0, (7, OLD_SECRET), None),
                TrustedClockSample::new(ISSUED + 10, monotonic),
            )
            .unwrap();
        let before = authority.checkpoint_store().checkpoint.clone();
        let replacements = authority.checkpoint_store().replacements;

        let error = authority
            .accept_provider_artifact_with_expiry(
                &artifact(2, ISSUED + 120, 0, (7, OLD_SECRET), None),
                TrustedClockSample::new(ISSUED + 20, monotonic + Duration::from_secs(10)),
                |_, _| None,
            )
            .unwrap_err();
        assert_eq!(error, DiscoveryCredentialError::TimeOverflow);
        assert_eq!(authority.checkpoint_store().checkpoint, before);
        assert_eq!(authority.checkpoint_store().replacements, replacements);
    }

    #[test]
    fn discovery_authority_caps_overlap_lease_and_rejects_clock_discontinuity() {
        let monotonic = Instant::now();
        let mut authority =
            DiscoveryCredentialAuthorityCore::new(SCOPE, MemoryCheckpointStore::default()).unwrap();
        authority
            .accept_provider_artifact(
                &artifact(1, ISSUED + 120, 0, (7, OLD_SECRET), None),
                TrustedClockSample::new(ISSUED + 10, monotonic),
            )
            .unwrap();
        let staged = authority
            .accept_provider_artifact(
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
                .accept_provider_artifact(
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
    fn trusted_clock_lease_guard_reuses_authority_continuity_rules() {
        let monotonic = Instant::now();
        let mut guard = TrustedClockLeaseGuard::new(TrustedClockSample::new(ISSUED, monotonic));

        guard
            .resample(TrustedClockSample::new(
                ISSUED + 60,
                monotonic + Duration::from_secs(60),
            ))
            .unwrap();
        assert_eq!(
            guard
                .resample(TrustedClockSample::new(
                    ISSUED + 60 + 302,
                    monotonic + Duration::from_secs(61),
                ))
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
        let mut store = FileDiscoveryCheckpointStore::new_for_test(&root).unwrap();
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
        FileDiscoveryCheckpointStore::new_for_test(&root).unwrap();
        assert!(!next.exists());

        std::os::unix::fs::symlink(root.join("missing"), &next).unwrap();
        assert!(matches!(
            FileDiscoveryCheckpointStore::new_for_test(&root),
            Err(DiscoveryCredentialError::CheckpointCorrupt)
        ));
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn discovery_checkpoint_store_rejects_ancestor_and_final_symlinks() {
        // Break caught: validating only the final pathname lets an ancestor
        // symlink redirect the durable rollback authority.
        let parent = std::env::temp_dir().join(format!(
            "aster-discovery-checkpoint-links-{}-{}",
            std::process::id(),
            ISSUED
        ));
        let _ = fs::remove_dir_all(&parent);
        fs::create_dir(&parent).unwrap();
        fs::set_permissions(&parent, fs::Permissions::from_mode(0o700)).unwrap();
        let real = parent.join("real");
        fs::create_dir(&real).unwrap();
        fs::set_permissions(&real, fs::Permissions::from_mode(0o700)).unwrap();
        let nested = real.join("checkpoint-root");
        fs::create_dir(&nested).unwrap();
        fs::set_permissions(&nested, fs::Permissions::from_mode(0o700)).unwrap();
        std::os::unix::fs::symlink(&real, parent.join("ancestor-link")).unwrap();
        assert!(matches!(
            FileDiscoveryCheckpointStore::new_for_test(
                &parent.join("ancestor-link/checkpoint-root")
            ),
            Err(DiscoveryCredentialError::CheckpointUnavailable)
                | Err(DiscoveryCredentialError::CheckpointCorrupt)
        ));
        std::os::unix::fs::symlink(&real, parent.join("final-link")).unwrap();
        assert!(matches!(
            FileDiscoveryCheckpointStore::new_for_test(&parent.join("final-link")),
            Err(DiscoveryCredentialError::CheckpointUnavailable)
                | Err(DiscoveryCredentialError::CheckpointCorrupt)
        ));
        fs::remove_dir_all(parent).unwrap();
    }

    #[test]
    fn discovery_checkpoint_store_fails_closed_after_root_rename_and_replacement() {
        // Break caught: descriptor-relative writes alone are insufficient;
        // the configured namespace must still resolve to the pinned inode.
        let parent = std::env::temp_dir().join(format!(
            "aster-discovery-checkpoint-swap-{}-{}",
            std::process::id(),
            ISSUED
        ));
        let _ = fs::remove_dir_all(&parent);
        fs::create_dir(&parent).unwrap();
        fs::set_permissions(&parent, fs::Permissions::from_mode(0o700)).unwrap();
        let root = parent.join("state");
        let moved = parent.join("original-state");
        fs::create_dir(&root).unwrap();
        fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).unwrap();
        let mut store = FileDiscoveryCheckpointStore::new_for_test(&root).unwrap();
        fs::rename(&root, &moved).unwrap();
        fs::create_dir(&root).unwrap();
        fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).unwrap();

        let initial = parse(&artifact(1, ISSUED + 60, 0, (7, OLD_SECRET), None));
        let checkpoint = DiscoveryCheckpoint::transition(None, &initial).unwrap();
        assert_eq!(
            store.replace(&checkpoint).unwrap_err(),
            DiscoveryCredentialError::CheckpointUnavailable
        );
        assert!(!moved.join(CHECKPOINT_FILE).exists());
        assert!(!root.join(CHECKPOINT_FILE).exists());

        drop(store);
        fs::remove_dir_all(parent).unwrap();
    }

    #[test]
    fn discovery_checkpoint_store_revalidates_namespace_immediately_before_rename() {
        let parent = std::env::temp_dir().join(format!(
            "aster-discovery-checkpoint-pre-rename-swap-{}-{}",
            std::process::id(),
            ISSUED
        ));
        let _ = fs::remove_dir_all(&parent);
        fs::create_dir(&parent).unwrap();
        fs::set_permissions(&parent, fs::Permissions::from_mode(0o700)).unwrap();
        let root = parent.join("state");
        let moved = parent.join("original-state");
        fs::create_dir(&root).unwrap();
        fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).unwrap();
        let mut store = FileDiscoveryCheckpointStore::new_for_test(&root).unwrap();
        let initial = parse(&artifact(1, ISSUED + 60, 0, (7, OLD_SECRET), None));
        let checkpoint = DiscoveryCheckpoint::transition(None, &initial).unwrap();

        assert_eq!(
            store
                .replace_after_write_for_test(&checkpoint, || {
                    fs::rename(&root, &moved).unwrap();
                    fs::create_dir(&root).unwrap();
                    fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).unwrap();
                })
                .unwrap_err(),
            DiscoveryCredentialError::CheckpointUnavailable
        );
        assert!(!moved.join(CHECKPOINT_FILE).exists());
        assert!(!root.join(CHECKPOINT_FILE).exists());
        assert!(fs::read_dir(&root).unwrap().next().is_none());

        drop(store);
        fs::remove_dir_all(parent).unwrap();
    }

    #[test]
    fn discovery_authority_revalidates_namespace_after_commit_before_lease() {
        // A checkpoint may already be durable at this crash boundary, but a
        // renamed authority namespace must never receive active material.
        let parent = std::env::temp_dir().join(format!(
            "aster-discovery-pre-lease-swap-{}-{}",
            std::process::id(),
            ISSUED
        ));
        let _ = fs::remove_dir_all(&parent);
        fs::create_dir(&parent).unwrap();
        fs::set_permissions(&parent, fs::Permissions::from_mode(0o700)).unwrap();
        let root = parent.join("state");
        let moved = parent.join("original-state");
        fs::create_dir(&root).unwrap();
        fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).unwrap();
        let store = FileDiscoveryCheckpointStore::new_for_test(&root).unwrap();
        let mut authority = DiscoveryCredentialAuthorityCore::new(SCOPE, store).unwrap();

        assert_eq!(
            authority
                .accept_provider_artifact_with_hooks(
                    &artifact(1, ISSUED + 60, 0, (7, OLD_SECRET), None),
                    TrustedClockSample::new(ISSUED + 10, Instant::now()),
                    |instant, duration| instant.checked_add(duration),
                    || {
                        fs::rename(&root, &moved).unwrap();
                        fs::create_dir(&root).unwrap();
                        fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).unwrap();
                    },
                )
                .unwrap_err(),
            DiscoveryCredentialError::CheckpointUnavailable
        );
        assert!(moved.join(CHECKPOINT_FILE).is_file());
        assert!(fs::read_dir(&root).unwrap().next().is_none());

        drop(authority);
        fs::remove_dir_all(parent).unwrap();
    }

    #[test]
    fn discovery_authority_exclusively_owns_checkpoint_until_drop() {
        // Break caught: two authorities sharing an unlocked checkpoint can
        // validate from the same old state and both expose successor leases.
        let parent = std::env::temp_dir().join(format!(
            "aster-discovery-checkpoint-lock-{}-{}",
            std::process::id(),
            ISSUED
        ));
        let _ = fs::remove_dir_all(&parent);
        fs::create_dir(&parent).unwrap();
        fs::set_permissions(&parent, fs::Permissions::from_mode(0o700)).unwrap();
        let root = parent.join("state");
        fs::create_dir(&root).unwrap();
        fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).unwrap();
        let anchor = parent.join("authority.lock");
        fs::write(&anchor, []).unwrap();
        fs::set_permissions(&anchor, fs::Permissions::from_mode(0o600)).unwrap();
        let sample = TrustedClockSample::new(ISSUED + 10, Instant::now());
        let first = prepare_discovery_credential_for_test(
            StaticLoader {
                bytes: artifact(1, ISSUED + 60, 0, (7, OLD_SECRET), None),
            },
            StaticClock(sample),
            SCOPE,
            &root,
            open_test_anchor(&anchor),
        )
        .unwrap();
        let (parts, first_guard) = first.into_parts();
        let (emitting, overlap, _expires_at) = parts.into_adapter_parts();
        assert_eq!(emitting.0, 7);
        assert!(overlap.is_none());

        let moved = parent.join("original-state");
        fs::rename(&root, &moved).unwrap();
        fs::create_dir(&root).unwrap();
        fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).unwrap();
        let locked = prepare_discovery_credential_for_test(
            StaticLoader {
                bytes: artifact(2, ISSUED + 60, 0, (7, OLD_SECRET), None),
            },
            StaticClock(sample),
            SCOPE,
            &root,
            open_test_anchor(&anchor),
        )
        .err()
        .expect("second live authority must fail closed");
        assert_eq!(locked, DiscoveryCredentialError::CheckpointUnavailable);
        assert_eq!(format!("{locked:?}"), "CheckpointUnavailable");
        assert!(!format!("{locked:?}").contains(root.to_str().unwrap()));
        assert!(!root.join(CHECKPOINT_FILE).exists());
        drop(emitting);
        drop(overlap);
        drop(first_guard);

        fs::remove_dir(&root).unwrap();
        fs::rename(&moved, &root).unwrap();
        let restarted = prepare_discovery_credential_for_test(
            StaticLoader {
                bytes: artifact(2, ISSUED + 60, 0, (7, OLD_SECRET), None),
            },
            StaticClock(sample),
            SCOPE,
            &root,
            open_test_anchor(&anchor),
        )
        .unwrap();
        let (parts, restarted_guard) = restarted.into_parts();
        let (restarted_emitting, _, _) = parts.into_adapter_parts();
        assert_eq!(restarted_emitting.0, 7);
        drop(restarted_guard);
        fs::remove_dir_all(parent).unwrap();
    }

    #[test]
    fn authority_lock_and_state_custody_reject_unsafe_profiles() {
        // Break caught: the fixed external anchor and trusted ancestry must
        // reject type, ownership, mode, link, length, and ACL weakening.
        let service_uid = 12_345;
        let valid_acl = expected_authority_lock_acl(service_uid).to_vec();
        let valid_lock = CustodyMetadata {
            is_file: true,
            is_directory: false,
            uid: 0,
            gid: 0,
            mode: 0o440,
            links: 1,
            length: 0,
            access_acl: Some(valid_acl.clone()),
        };
        assert!(validate_authority_lock_metadata(&valid_lock, service_uid).is_ok());
        let invalid = vec![
            CustodyMetadata {
                is_file: false,
                ..valid_lock.clone()
            },
            CustodyMetadata {
                uid: service_uid,
                ..valid_lock.clone()
            },
            CustodyMetadata {
                mode: 0o660,
                ..valid_lock.clone()
            },
            CustodyMetadata {
                links: 2,
                ..valid_lock.clone()
            },
            CustodyMetadata {
                length: 1,
                ..valid_lock.clone()
            },
            CustodyMetadata {
                access_acl: None,
                ..valid_lock.clone()
            },
            CustodyMetadata {
                access_acl: Some(vec![0x42]),
                ..valid_lock
            },
        ];
        for metadata in invalid {
            assert_eq!(
                validate_authority_lock_metadata(&metadata, service_uid).unwrap_err(),
                DiscoveryCredentialError::CheckpointCorrupt
            );
        }

        let valid_ancestor = CustodyMetadata {
            is_file: false,
            is_directory: true,
            uid: 0,
            gid: 0,
            mode: 0o755,
            links: 2,
            length: 0,
            access_acl: None,
        };
        assert!(validate_root_owned_ancestor_metadata(&valid_ancestor).is_ok());
        for metadata in [
            CustodyMetadata {
                uid: service_uid,
                ..valid_ancestor.clone()
            },
            CustodyMetadata {
                mode: 0o775,
                ..valid_ancestor.clone()
            },
            CustodyMetadata {
                access_acl: Some(vec![0x42]),
                ..valid_ancestor.clone()
            },
        ] {
            assert_eq!(
                validate_root_owned_ancestor_metadata(&metadata).unwrap_err(),
                DiscoveryCredentialError::CheckpointCorrupt
            );
        }

        let service_root = CustodyMetadata {
            uid: service_uid,
            mode: 0o700,
            ..valid_ancestor
        };
        assert!(validate_service_state_root_metadata(&service_root, service_uid).is_ok());
        assert_eq!(
            validate_service_state_root_metadata(&service_root, service_uid + 1).unwrap_err(),
            DiscoveryCredentialError::CheckpointCorrupt
        );
    }

    #[cfg(target_os = "linux")]
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
    fn discovery_preparation_loads_provider_exactly_once_and_guard_only_resamples_clock() {
        let parent = std::env::temp_dir().join(format!(
            "aster-discovery-authority-{}-{}",
            std::process::id(),
            ISSUED
        ));
        let _ = fs::remove_dir_all(&parent);
        fs::create_dir(&parent).unwrap();
        fs::set_permissions(&parent, fs::Permissions::from_mode(0o700)).unwrap();
        let root = parent.join("state");
        fs::create_dir(&root).unwrap();
        fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).unwrap();
        let anchor = parent.join("authority.lock");
        fs::write(&anchor, []).unwrap();
        let monotonic = Instant::now();
        let loads = Rc::new(Cell::new(0));
        let prepared = prepare_discovery_credential_for_test(
            CountingLoader {
                bytes: artifact(1, ISSUED + 60, 0, (7, OLD_SECRET), None),
                loads: Rc::clone(&loads),
            },
            StaticClock(TrustedClockSample::new(ISSUED + 10, monotonic)),
            SCOPE,
            &root,
            open_test_anchor(&anchor),
        )
        .unwrap();
        assert_eq!(loads.get(), 1);
        let (parts, mut guard) = prepared.into_parts();
        let (emitting, overlap, expires_at) = parts.into_adapter_parts();
        assert_eq!(emitting.0, 7);
        assert!(overlap.is_none());
        assert_eq!(expires_at, monotonic + Duration::from_secs(50));
        guard.resample_clock().unwrap();
        assert_eq!(loads.get(), 1);
        drop(guard);
        fs::remove_dir_all(parent).unwrap();
    }

    #[test]
    fn prepared_discovery_credential_rejects_cross_scope_and_state_bindings() {
        let parent = std::env::temp_dir().join(format!(
            "aster-discovery-binding-{}-{}",
            std::process::id(),
            ISSUED
        ));
        let _ = fs::remove_dir_all(&parent);
        fs::create_dir(&parent).unwrap();
        fs::set_permissions(&parent, fs::Permissions::from_mode(0o700)).unwrap();
        let root = parent.join("state");
        let foreign_root = parent.join("foreign-state");
        for path in [&root, &foreign_root] {
            fs::create_dir(path).unwrap();
            fs::set_permissions(path, fs::Permissions::from_mode(0o700)).unwrap();
        }
        let anchor = parent.join("authority.lock");
        fs::write(&anchor, []).unwrap();
        let prepared = prepare_discovery_credential_for_test(
            StaticLoader {
                bytes: artifact(1, ISSUED + 60, 0, (7, OLD_SECRET), None),
            },
            StaticClock(TrustedClockSample::new(ISSUED + 10, Instant::now())),
            SCOPE,
            &root,
            open_test_anchor(&anchor),
        )
        .unwrap();

        assert!(prepared.matches_binding(SCOPE, &root).unwrap());
        assert!(!prepared.matches_binding([0x7f; 32], &root).unwrap());
        assert!(!prepared.matches_binding(SCOPE, &foreign_root).unwrap());

        let authority = prepared.retire_material();
        let pinned_root = File::open(&root).unwrap();
        #[cfg(target_os = "linux")]
        let pinned_path = {
            use std::os::fd::AsRawFd as _;
            let pinned_path =
                std::path::PathBuf::from(format!("/proc/self/fd/{}", pinned_root.as_raw_fd()));
            assert!(
                authority
                    .matches_pinned_binding(SCOPE, &pinned_path)
                    .unwrap()
            );
            pinned_path
        };
        let retired_root = parent.join("retired-state");
        fs::rename(&root, &retired_root).unwrap();
        fs::create_dir(&root).unwrap();
        fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).unwrap();
        assert!(authority.matches_binding(SCOPE, &root).is_err());
        #[cfg(target_os = "linux")]
        assert!(
            authority
                .matches_pinned_binding(SCOPE, &pinned_path)
                .is_err()
        );

        drop(authority);
        fs::remove_dir_all(parent).unwrap();
    }

    #[test]
    fn discovery_authority_restart_reuses_checkpoint_and_rejects_rollback_without_replacement() {
        // Break caught: a process restart must retain manifest/generation/
        // secret binding, and a rejected older replacement must not rewrite
        // the current durable authority.
        let parent = std::env::temp_dir().join(format!(
            "aster-discovery-restart-{}-{}",
            std::process::id(),
            ISSUED
        ));
        let _ = fs::remove_dir_all(&parent);
        fs::create_dir(&parent).unwrap();
        fs::set_permissions(&parent, fs::Permissions::from_mode(0o700)).unwrap();
        let root = parent.join("state");
        fs::create_dir(&root).unwrap();
        fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).unwrap();
        let anchor = parent.join("authority.lock");
        fs::write(&anchor, []).unwrap();
        let monotonic = Instant::now();

        let current_artifact = artifact(2, ISSUED + 90, 0, (7, OLD_SECRET), None);
        let initial = prepare_discovery_credential_for_test(
            StaticLoader {
                bytes: current_artifact.clone(),
            },
            StaticClock(TrustedClockSample::new(ISSUED + 10, monotonic)),
            SCOPE,
            &root,
            open_test_anchor(&anchor),
        )
        .unwrap();
        let (parts, initial_guard) = initial.into_parts();
        let (initial_emitting, _, _) = parts.into_adapter_parts();
        assert_eq!(initial_emitting.0, 7);
        let checkpoint_before = fs::read(root.join(CHECKPOINT_FILE)).unwrap();
        drop(initial_guard);

        // A later mission/runtime startup failure occurs after the credential
        // checkpoint. A controlled restart must accept the identical artifact
        // rather than requiring a new generation.
        let exact_restart = prepare_discovery_credential_for_test(
            StaticLoader {
                bytes: current_artifact,
            },
            StaticClock(TrustedClockSample::new(
                ISSUED + 20,
                monotonic + Duration::from_secs(10),
            )),
            SCOPE,
            &root,
            open_test_anchor(&anchor),
        )
        .unwrap();
        let (parts, restart_guard) = exact_restart.into_parts();
        let (restart_emitting, _, _) = parts.into_adapter_parts();
        assert_eq!(restart_emitting.0, 7);
        assert_eq!(
            fs::read(root.join(CHECKPOINT_FILE)).unwrap(),
            checkpoint_before
        );
        drop(restart_guard);

        let rollback = prepare_discovery_credential_for_test(
            StaticLoader {
                bytes: artifact(1, ISSUED + 80, 0, (6, [0x33; 32]), None),
            },
            StaticClock(TrustedClockSample::new(
                ISSUED + 30,
                monotonic + Duration::from_secs(20),
            )),
            SCOPE,
            &root,
            open_test_anchor(&anchor),
        )
        .err()
        .expect("rollback must fail before a prepared credential returns");
        assert_eq!(rollback, DiscoveryCredentialError::InvalidTransition);
        assert_eq!(
            fs::read(root.join(CHECKPOINT_FILE)).unwrap(),
            checkpoint_before
        );
        fs::remove_dir_all(parent).unwrap();
    }
}
