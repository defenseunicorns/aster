//! Mission-authenticated session boundary above the Iroh carrier.
//!
//! An Iroh endpoint identity authenticates the carrier connection. It does not
//! establish Aster mission membership. This module either binds an observed
//! carrier peer to a separately provisioned, expected mission [`NodeId`], or
//! admits a discovered peer only after its credential authenticates under the
//! local mission authority. It preserves the complete hybrid handshake and
//! record layer while also exposing an exact classical mission handshake bound
//! to an `IrohQuicV1` TLS exporter.
//!
//! The handshake state types intentionally expose no application-frame API.
//! Only [`MissionSession`] or [`CarrierBoundClassicalMissionSession`], produced
//! after the fourth flight and the selected peer-admission check, can expose
//! their profile's protected application path.

use aster_iroh::{
    CarrierError, CarrierSecurityProfile, ChannelBindingContext as IrohChannelBindingContext,
    Connection, EndpointId, SecretKey,
};
use aster_mesh::{
    ApplicationProtection, AuthenticatedChannelBinding, ClassicalAuthenticatedSession,
    ClassicalProvisioningBundle, ClassicalSessionInitiator, ClassicalSessionResponder,
    CustodyClaims, CustodyExpectation, MAX_PROTECTED_PROVISIONING_BYTES,
    MAX_UNPROTECTED_PROVISIONING_BYTES, NodeId, ProvisioningBundle, ProvisioningLoadId,
    ProvisioningProtectionError, ProvisioningSecretLoader, ProvisioningSecretRef,
    ProvisioningSecretStoreError, ProvisioningUnprotector, ReferenceAuthenticatedSession,
    ReferenceEnvelopeSealer, ReferenceSessionAwaitingFinished, ReferenceSessionInitiator,
    ReferenceSessionResponder, ReferenceSessionResponderPending, SecurityProfileId,
    UnprotectedProvisioning, VerifiedCustodyClaims, VerifiedSecurityProfile, engine::EnvelopeError,
    load_provisioning_secret, unprotect_provisioning_artifact,
};
use std::{
    error::Error,
    fmt,
    fs::File,
    io::{self, Read},
    path::{Path, PathBuf},
    sync::{Arc, Mutex},
};
#[cfg(unix)]
use std::{
    ffi::OsString,
    fs::OpenOptions,
    io::{Seek, SeekFrom, Write},
    os::unix::{ffi::OsStringExt as _, fs::MetadataExt as _},
};
use zeroize::Zeroize as _;

const SOFTWARE_ERASURE_DESCRIPTOR_MAGIC: &[u8; 8] = b"ASTRZE01";
/// Maximum canonical descriptor bytes, aligned with the terminal redb record bound.
pub const MAX_SOFTWARE_ERASURE_DESCRIPTOR_BYTES: usize = 8 * 1024;
const SOFTWARE_ERASURE_DESCRIPTOR_HEADER_BYTES: usize = 37;
const MAX_SOFTWARE_ERASURE_PATH_BYTES: usize =
    MAX_SOFTWARE_ERASURE_DESCRIPTOR_BYTES - SOFTWARE_ERASURE_DESCRIPTOR_HEADER_BYTES;
const ERASE_BUFFER_BYTES: usize = 8 * 1024;
const CLASSICAL_CHANNEL_BINDING_CONTEXT_MAGIC: &[u8; 8] = b"ASTRCB01";
/// Exact bytes in a canonical carrier-bound classical mission context.
pub const CLASSICAL_CHANNEL_BINDING_CONTEXT_BYTES: usize = 8 + 2 + 8 + 32 * 6;

/// Kind of local plaintext secret named by a software-erasure descriptor.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum SoftwareSecretArtifact {
    /// Authority-issued hybrid mission provisioning bundle.
    MissionBundle = 1,
    /// Persisted Iroh carrier signing key.
    CarrierIdentity = 2,
}

impl SoftwareSecretArtifact {
    const fn from_byte(byte: u8) -> Option<Self> {
        match byte {
            1 => Some(Self::MissionBundle),
            2 => Some(Self::CarrierIdentity),
            _ => None,
        }
    }
}

/// Durable, non-secret identity of one exact local secret artifact.
///
/// The descriptor is safe to persist in the terminal zeroization record. It
/// deliberately contains no credential bytes. A pending crash recovery may
/// reopen only a regular, owner-only, uniquely linked pathname whose device
/// and inode still match this descriptor. Missing or replaced paths remain
/// indeterminate and are never inferred to have been erased. This API does not
/// unlink secret pathnames: the zero-length tombstone is retained so a
/// pathname race cannot delete replacement data. Any later operator cleanup is
/// outside the software-erasure proof.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SoftwareErasureTarget {
    artifact: SoftwareSecretArtifact,
    path: PathBuf,
    device: u64,
    inode: u64,
    original_len: u64,
}

impl SoftwareErasureTarget {
    /// Artifact class bound into this descriptor.
    pub const fn artifact(&self) -> SoftwareSecretArtifact {
        self.artifact
    }

    /// Absolute pathname observed when the exact retained inode was opened.
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Unix device number of the exact retained inode.
    pub const fn device(&self) -> u64 {
        self.device
    }

    /// Unix inode number of the exact retained inode.
    pub const fn inode(&self) -> u64 {
        self.inode
    }

    /// Secret artifact length captured before the terminal marker.
    pub const fn original_len(&self) -> u64 {
        self.original_len
    }

    /// Encodes the bounded descriptor without credential bytes.
    #[cfg(unix)]
    pub fn to_bytes(&self) -> Vec<u8> {
        use std::os::unix::ffi::OsStrExt as _;

        let path = self.path.as_os_str().as_bytes();
        debug_assert!(path.len() <= MAX_SOFTWARE_ERASURE_PATH_BYTES);
        let path_len = u32::try_from(path.len()).expect("bounded erasure path fits in u32");
        let mut encoded = Vec::with_capacity(SOFTWARE_ERASURE_DESCRIPTOR_HEADER_BYTES + path.len());
        encoded.extend_from_slice(SOFTWARE_ERASURE_DESCRIPTOR_MAGIC);
        encoded.push(self.artifact as u8);
        encoded.extend_from_slice(&self.device.to_be_bytes());
        encoded.extend_from_slice(&self.inode.to_be_bytes());
        encoded.extend_from_slice(&self.original_len.to_be_bytes());
        encoded.extend_from_slice(&path_len.to_be_bytes());
        encoded.extend_from_slice(path);
        encoded
    }

    /// Decodes one canonical bounded descriptor without opening its pathname.
    #[cfg(unix)]
    pub fn from_bytes(encoded: &[u8]) -> Result<Self, SoftwareErasureError> {
        const HEADER: usize = SOFTWARE_ERASURE_DESCRIPTOR_HEADER_BYTES;
        if encoded.len() < HEADER || &encoded[..8] != SOFTWARE_ERASURE_DESCRIPTOR_MAGIC {
            return Err(SoftwareErasureError::InvalidDescriptor);
        }
        let artifact = SoftwareSecretArtifact::from_byte(encoded[8])
            .ok_or(SoftwareErasureError::InvalidDescriptor)?;
        let device = u64::from_be_bytes(
            encoded[9..17]
                .try_into()
                .map_err(|_| SoftwareErasureError::InvalidDescriptor)?,
        );
        let inode = u64::from_be_bytes(
            encoded[17..25]
                .try_into()
                .map_err(|_| SoftwareErasureError::InvalidDescriptor)?,
        );
        let original_len = u64::from_be_bytes(
            encoded[25..33]
                .try_into()
                .map_err(|_| SoftwareErasureError::InvalidDescriptor)?,
        );
        let valid_length = match artifact {
            SoftwareSecretArtifact::MissionBundle => {
                original_len != 0
                    && original_len
                        <= u64::try_from(MAX_UNPROTECTED_PROVISIONING_BYTES)
                            .expect("provisioning bound fits u64")
            }
            SoftwareSecretArtifact::CarrierIdentity => original_len == 32,
        };
        if !valid_length {
            return Err(SoftwareErasureError::InvalidDescriptor);
        }
        let path_len = u32::from_be_bytes(
            encoded[33..37]
                .try_into()
                .map_err(|_| SoftwareErasureError::InvalidDescriptor)?,
        ) as usize;
        if path_len == 0
            || path_len > MAX_SOFTWARE_ERASURE_PATH_BYTES
            || encoded.len() != HEADER + path_len
        {
            return Err(SoftwareErasureError::InvalidDescriptor);
        }
        let path = PathBuf::from(OsString::from_vec(encoded[HEADER..].to_vec()));
        if !path.is_absolute() {
            return Err(SoftwareErasureError::InvalidDescriptor);
        }
        Ok(Self {
            artifact,
            path,
            device,
            inode,
            original_len,
        })
    }

    /// Reopens an unflagged pending artifact after a crash.
    ///
    /// A missing pathname, a replacement inode, a symlink, a hard link, unsafe
    /// ownership or permissions, or another live advisory lock is terminally
    /// indeterminate. This method never parses or copies credential bytes.
    #[cfg(unix)]
    pub fn resume_pending(&self) -> Result<ResumedSoftwareErasure, SoftwareErasureError> {
        let mut artifact = RetainedSecretArtifact::open_existing(&self.path, self.artifact)
            .map_err(|error| SoftwareErasureError::indeterminate(self.path.clone(), error))?;
        if artifact.target.artifact != self.artifact
            || artifact.target.path != self.path
            || artifact.target.device != self.device
            || artifact.target.inode != self.inode
            || artifact.target.original_len > self.original_len
        {
            return Err(SoftwareErasureError::Indeterminate(self.path.clone()));
        }
        // A crash may occur after truncation but before the runtime records the
        // per-artifact destroyed phase. Retain the original bound while
        // accepting any same-inode prefix length, including zero, then repeat
        // the idempotent FD destruction before advancing the durable phase.
        artifact.target = self.clone();
        Ok(ResumedSoftwareErasure { artifact })
    }
}

/// Receipt for destruction of secret contents through an exact retained FD.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SoftwareErasureReceipt {
    target: SoftwareErasureTarget,
    bytes_overwritten: u64,
    already_destroyed: bool,
}

impl SoftwareErasureReceipt {
    /// Durable descriptor whose per-artifact destroyed flag may now be set.
    pub fn target(&self) -> &SoftwareErasureTarget {
        &self.target
    }

    /// Bytes overwritten before the exact inode was truncated and synchronized.
    pub const fn bytes_overwritten(&self) -> u64 {
        self.bytes_overwritten
    }

    /// Whether this retained handle had already completed destruction.
    pub const fn already_destroyed(&self) -> bool {
        self.already_destroyed
    }

    /// The receipt proves only bounded local software erasure.
    pub const fn bounded_software_erasure(&self) -> bool {
        true
    }

    /// Software erasure does not prove physical flash, snapshot, swap, or backup sanitization.
    pub const fn physical_media_sanitized(&self) -> bool {
        false
    }
}

/// Prepared mission-bundle destruction token acquired before terminal commit.
pub struct PreparedMissionErasure {
    encoded: Arc<Mutex<UnprotectedProvisioning>>,
    artifact: Arc<Mutex<RetainedSecretArtifact>>,
    target: SoftwareErasureTarget,
    mission_authority: NodeId,
}

impl PreparedMissionErasure {
    /// Descriptor to persist before invoking the irreversible operation.
    pub const fn target(&self) -> &SoftwareErasureTarget {
        &self.target
    }

    /// Stable authority identity cached from the validated source bundle.
    pub const fn mission_authority_id(&self) -> NodeId {
        self.mission_authority
    }

    /// Invalidates all wrapper clones and destroys the exact retained inode's contents.
    ///
    /// Callers must first zeroize and drop sessions, sealers, and provisioning
    /// objects already derived from the shared wrapper.
    pub fn destroy_contents(&mut self) -> Result<SoftwareErasureReceipt, SoftwareErasureError> {
        self.encoded
            .lock()
            .map_err(|_| SoftwareErasureError::StatePoisoned)?
            .zeroize();
        self.artifact
            .lock()
            .map_err(|_| SoftwareErasureError::StatePoisoned)?
            .destroy_contents()
    }
}

/// Prepared Iroh identity destruction token acquired before terminal commit.
pub struct PreparedIdentityErasure {
    secret: Arc<Mutex<Option<SecretKey>>>,
    artifact: Arc<Mutex<RetainedSecretArtifact>>,
    target: SoftwareErasureTarget,
}

impl PreparedIdentityErasure {
    pub(crate) fn new(
        secret: Arc<Mutex<Option<SecretKey>>>,
        artifact: Arc<Mutex<RetainedSecretArtifact>>,
    ) -> Result<Self, SoftwareErasureError> {
        let target = artifact
            .lock()
            .map_err(|_| SoftwareErasureError::StatePoisoned)?
            .preflight()?;
        Ok(Self {
            secret,
            artifact,
            target,
        })
    }

    /// Descriptor to persist before invoking the irreversible operation.
    pub const fn target(&self) -> &SoftwareErasureTarget {
        &self.target
    }

    /// Invalidates all wrapper clones and destroys the exact retained inode's contents.
    ///
    /// Callers must first close and drop every endpoint that received an
    /// independent provider copy from [`crate::NodeIdentity::secret`].
    pub fn destroy_contents(&mut self) -> Result<SoftwareErasureReceipt, SoftwareErasureError> {
        self.secret
            .lock()
            .map_err(|_| SoftwareErasureError::StatePoisoned)?
            .take();
        self.artifact
            .lock()
            .map_err(|_| SoftwareErasureError::StatePoisoned)?
            .destroy_contents()
    }
}

/// Crash-recovered exact-FD destruction token for an unflagged artifact.
pub struct ResumedSoftwareErasure {
    artifact: RetainedSecretArtifact,
}

impl ResumedSoftwareErasure {
    /// Destroys the pending artifact contents without parsing credential bytes.
    pub fn destroy_contents(&mut self) -> Result<SoftwareErasureReceipt, SoftwareErasureError> {
        self.artifact.destroy_contents()
    }
}

/// Fail-closed local software-erasure error.
#[derive(Debug)]
pub enum SoftwareErasureError {
    /// Filesystem operation failed.
    Io(io::Error),
    /// The artifact is not a regular file.
    NotRegular(PathBuf),
    /// The pathname no longer names the exact retained inode.
    Changed(PathBuf),
    /// Group or world permission bits are present.
    UnsafePermissions(PathBuf),
    /// The file owner is not the effective process owner.
    WrongOwner {
        path: PathBuf,
        owner: u32,
        effective: u32,
    },
    /// More than one hard link names the artifact.
    SharedLinks { path: PathBuf, links: u64 },
    /// Another live open-file description holds the exclusive advisory lock.
    InUse(PathBuf),
    /// The wrapper was constructed from memory and has no retained file.
    NoPersistedArtifact,
    /// A pending crash recovery cannot prove that the original inode remains.
    Indeterminate(PathBuf),
    /// Descriptor bytes are noncanonical or out of bounds.
    InvalidDescriptor,
    /// Shared secret state was poisoned by a panic.
    StatePoisoned,
    /// Secret content destruction has already invalidated the live capability.
    SecretDestroyed,
    /// This platform cannot enforce the Unix retained-inode contract.
    PlatformUnavailable,
}

impl SoftwareErasureError {
    fn indeterminate(path: PathBuf, _cause: Self) -> Self {
        Self::Indeterminate(path)
    }
}

impl fmt::Display for SoftwareErasureError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(error) => write!(formatter, "secret artifact I/O: {error}"),
            Self::NotRegular(path) => write!(
                formatter,
                "secret artifact is not a regular file: {}",
                path.display()
            ),
            Self::Changed(path) => write!(
                formatter,
                "secret artifact pathname or inode changed: {}",
                path.display()
            ),
            Self::UnsafePermissions(path) => write!(
                formatter,
                "secret artifact is accessible beyond its owner: {}",
                path.display()
            ),
            Self::WrongOwner {
                path,
                owner,
                effective,
            } => write!(
                formatter,
                "secret artifact {} is owned by uid {owner}, effective uid is {effective}",
                path.display()
            ),
            Self::SharedLinks { path, links } => write!(
                formatter,
                "secret artifact {} has {links} hard links; exactly one is required",
                path.display()
            ),
            Self::InUse(path) => write!(
                formatter,
                "secret artifact is already held by another live loader: {}",
                path.display()
            ),
            Self::NoPersistedArtifact => {
                formatter.write_str("in-memory secret has no retained artifact")
            }
            Self::Indeterminate(path) => write!(
                formatter,
                "pending secret erasure is indeterminate; original inode cannot be proven at {}",
                path.display()
            ),
            Self::InvalidDescriptor => {
                formatter.write_str("invalid software-erasure target descriptor")
            }
            Self::StatePoisoned => formatter.write_str("shared secret state is poisoned"),
            Self::SecretDestroyed => formatter.write_str("secret key material has been destroyed"),
            Self::PlatformUnavailable => formatter
                .write_str("retained-inode software erasure is unavailable on this platform"),
        }
    }
}

impl Error for SoftwareErasureError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Io(error) => Some(error),
            _ => None,
        }
    }
}

impl From<io::Error> for SoftwareErasureError {
    fn from(error: io::Error) -> Self {
        Self::Io(error)
    }
}

pub(crate) struct RetainedSecretArtifact {
    pub(crate) file: File,
    #[cfg(unix)]
    lock_owner_pid: u32,
    target: SoftwareErasureTarget,
    destroyed: bool,
}

impl RetainedSecretArtifact {
    #[cfg(unix)]
    pub(crate) fn open_existing(
        path: &Path,
        artifact: SoftwareSecretArtifact,
    ) -> Result<Self, SoftwareErasureError> {
        let path = absolute_artifact_path(path)?;
        let path_metadata = std::fs::symlink_metadata(&path)?;
        if !path_metadata.file_type().is_file() {
            return Err(SoftwareErasureError::NotRegular(path));
        }
        let mut options = OpenOptions::new();
        options.read(true).write(true);
        use std::os::unix::fs::OpenOptionsExt as _;
        options.custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK);
        let file = options.open(&path)?;
        Self::from_open_file(file, path, artifact, Some(path_metadata))
    }

    #[cfg(unix)]
    pub(crate) fn from_open_file(
        file: File,
        path: PathBuf,
        artifact: SoftwareSecretArtifact,
        path_metadata: Option<std::fs::Metadata>,
    ) -> Result<Self, SoftwareErasureError> {
        let path = absolute_artifact_path(&path)?;
        let metadata = file.metadata()?;
        validate_artifact_metadata(&path, &metadata)?;
        if let Some(path_metadata) = path_metadata
            && (path_metadata.dev() != metadata.dev() || path_metadata.ino() != metadata.ino())
        {
            return Err(SoftwareErasureError::Changed(path));
        }
        acquire_artifact_lock(&file, &path)?;
        use std::os::unix::ffi::OsStrExt as _;
        let path_bytes = path.as_os_str().as_bytes();
        if path_bytes.is_empty() || path_bytes.len() > MAX_SOFTWARE_ERASURE_PATH_BYTES {
            return Err(SoftwareErasureError::InvalidDescriptor);
        }
        Ok(Self {
            file,
            lock_owner_pid: std::process::id(),
            target: SoftwareErasureTarget {
                artifact,
                path,
                device: metadata.dev(),
                inode: metadata.ino(),
                original_len: metadata.len(),
            },
            destroyed: false,
        })
    }

    #[cfg(unix)]
    fn preflight(&self) -> Result<SoftwareErasureTarget, SoftwareErasureError> {
        let metadata = self.file.metadata()?;
        validate_artifact_metadata(&self.target.path, &metadata)?;
        if metadata.dev() != self.target.device
            || metadata.ino() != self.target.inode
            || metadata.len() != self.target.original_len
        {
            return Err(SoftwareErasureError::Changed(self.target.path.clone()));
        }
        let path_metadata = std::fs::symlink_metadata(&self.target.path)?;
        validate_artifact_metadata(&self.target.path, &path_metadata)?;
        if path_metadata.dev() != self.target.device || path_metadata.ino() != self.target.inode {
            return Err(SoftwareErasureError::Changed(self.target.path.clone()));
        }
        Ok(self.target.clone())
    }

    #[cfg(not(unix))]
    fn preflight(&self) -> Result<SoftwareErasureTarget, SoftwareErasureError> {
        Err(SoftwareErasureError::PlatformUnavailable)
    }

    #[cfg(unix)]
    fn destroy_contents(&mut self) -> Result<SoftwareErasureReceipt, SoftwareErasureError> {
        if self.destroyed {
            return Ok(SoftwareErasureReceipt {
                target: self.target.clone(),
                bytes_overwritten: 0,
                already_destroyed: true,
            });
        }
        let metadata = self.file.metadata()?;
        if !metadata.is_file()
            || metadata.dev() != self.target.device
            || metadata.ino() != self.target.inode
        {
            return Err(SoftwareErasureError::Changed(self.target.path.clone()));
        }
        let bytes_to_overwrite = metadata.len().min(self.target.original_len);
        self.file.seek(SeekFrom::Start(0))?;
        let zeros = [0u8; ERASE_BUFFER_BYTES];
        let mut remaining = bytes_to_overwrite;
        while remaining != 0 {
            let count = usize::try_from(remaining.min(ERASE_BUFFER_BYTES as u64))
                .expect("erasure chunk fits usize");
            self.file.write_all(&zeros[..count])?;
            remaining -= count as u64;
        }
        self.file.sync_all()?;
        self.file.set_len(0)?;
        self.file.sync_all()?;
        self.destroyed = true;
        Ok(SoftwareErasureReceipt {
            target: self.target.clone(),
            bytes_overwritten: bytes_to_overwrite,
            already_destroyed: false,
        })
    }

    #[cfg(not(unix))]
    fn destroy_contents(&mut self) -> Result<SoftwareErasureReceipt, SoftwareErasureError> {
        Err(SoftwareErasureError::PlatformUnavailable)
    }
}

impl Drop for RetainedSecretArtifact {
    fn drop(&mut self) {
        #[cfg(unix)]
        if self.lock_owner_pid == std::process::id() {
            // Arc ownership has ended, but a concurrently spawned child may
            // still hold an inherited descriptor. Closing our descriptor alone
            // does not release that shared flock. A forked child's cleanup must
            // not explicitly unlock the originating process's live artifact.
            // If unlock fails, closing the file remains the fallback; Drop
            // cannot report an error and must not panic during unwinding.
            let _ = rustix::fs::flock(&self.file, rustix::fs::FlockOperation::Unlock);
        }
    }
}

#[cfg(unix)]
pub(crate) fn acquire_artifact_lock(file: &File, path: &Path) -> Result<(), SoftwareErasureError> {
    use rustix::fs::{FlockOperation, flock};

    match flock(file, FlockOperation::NonBlockingLockExclusive) {
        Ok(()) => Ok(()),
        Err(error) if error == rustix::io::Errno::WOULDBLOCK => {
            Err(SoftwareErasureError::InUse(path.to_path_buf()))
        }
        Err(error) => Err(io::Error::from(error).into()),
    }
}

#[cfg(not(unix))]
pub(crate) fn acquire_artifact_lock(
    _file: &File,
    _path: &Path,
) -> Result<(), SoftwareErasureError> {
    Err(SoftwareErasureError::PlatformUnavailable)
}

#[cfg(unix)]
fn validate_artifact_metadata(
    path: &Path,
    metadata: &std::fs::Metadata,
) -> Result<(), SoftwareErasureError> {
    use std::os::unix::fs::PermissionsExt as _;

    if !metadata.is_file() {
        return Err(SoftwareErasureError::NotRegular(path.to_path_buf()));
    }
    if metadata.permissions().mode() & 0o077 != 0 {
        return Err(SoftwareErasureError::UnsafePermissions(path.to_path_buf()));
    }
    let effective = rustix::process::geteuid().as_raw();
    if metadata.uid() != effective {
        return Err(SoftwareErasureError::WrongOwner {
            path: path.to_path_buf(),
            owner: metadata.uid(),
            effective,
        });
    }
    if metadata.nlink() != 1 {
        return Err(SoftwareErasureError::SharedLinks {
            path: path.to_path_buf(),
            links: metadata.nlink(),
        });
    }
    Ok(())
}

#[cfg(unix)]
fn absolute_artifact_path(path: &Path) -> io::Result<PathBuf> {
    if path.is_absolute() {
        Ok(path.to_path_buf())
    } else {
        Ok(std::env::current_dir()?.join(path))
    }
}

/// Coarse, non-identifying source of one authenticated mission provision.
///
/// These variants deliberately do not retain a provider name, path, operation
/// identifier, or opaque reference in operator-facing receipts.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum MissionProvisioningOrigin {
    /// Explicit plaintext compatibility path or caller-supplied plaintext bytes.
    UnprotectedReference,
    /// Provider-authenticated artifact, whether supplied by path or as bytes.
    ProtectedArtifact,
    /// Provider-persisted opaque secret reference.
    SecretReference,
}

impl MissionProvisioningOrigin {
    /// Stable, non-identifying spelling for operator receipts.
    pub const fn receipt_label(self) -> &'static str {
        match self {
            Self::UnprotectedReference => "unprotected-reference",
            Self::ProtectedArtifact => "provider-protected-artifact",
            Self::SecretReference => "provider-secret-reference",
        }
    }
}

/// Parsed mission credentials retained as zeroizing plaintext reference bytes.
///
/// This is intentionally named `UnprotectedReferenceMission` because recovered
/// canonical bytes remain in zeroizing process memory even when their source
/// artifact was provider-protected. The source origin distinguishes that
/// custody boundary without exposing provider or artifact identifiers.
#[derive(Clone)]
pub struct UnprotectedReferenceMission {
    encoded: Arc<Mutex<UnprotectedProvisioning>>,
    identity: NodeId,
    mission_authority: NodeId,
    artifact: Option<Arc<Mutex<RetainedSecretArtifact>>>,
    secret_ref: Option<ProvisioningSecretRef>,
    provisioning_origin: MissionProvisioningOrigin,
    protected_state_witness: Option<PathBuf>,
}

impl UnprotectedReferenceMission {
    /// Validates and owns canonical unprotected reference bundle bytes.
    pub fn from_bytes(bytes: Vec<u8>) -> Result<Self, MissionProvisioningError> {
        let encoded = UnprotectedProvisioning::new(bytes)?;
        Self::from_unprotected(encoded)
    }

    /// Authenticates one bounded provider-protected artifact and owns its
    /// recovered canonical bundle in zeroizing process memory.
    ///
    /// Empty, oversized, or raw `ASTRPB03` input is rejected before provider
    /// invocation. Passing preflight invokes `unprotector` exactly once and
    /// never falls back to interpreting the outer bytes as plaintext. This is
    /// a protected bootstrap seam, not persistent secret custody: the provider
    /// identity remains caller-owned and this value has no destroyable
    /// provider handle for the selected software-zeroization workflow.
    pub(crate) fn from_protected_bytes<P>(
        protected: &[u8],
        unprotector: &mut P,
    ) -> Result<Self, MissionProvisioningError>
    where
        P: ProvisioningUnprotector + ?Sized,
    {
        let encoded = unprotect_provisioning_artifact(protected, unprotector)?;
        let mut mission = Self::from_unprotected(encoded)?;
        mission.provisioning_origin = MissionProvisioningOrigin::ProtectedArtifact;
        Ok(mission)
    }

    /// Loads and authenticates one bounded regular protected artifact.
    ///
    /// Local file-kind and size checks finish before the provider is invoked.
    /// The protected file need not be owner-only because it contains only the
    /// provider's authenticated ciphertext. An observed symlink or non-regular
    /// file is rejected; Unix additionally binds the no-follow opened inode to
    /// preflight metadata, while non-Unix path-swap assurance remains open.
    /// Recovered plaintext is retained only in this zeroizing value; deleting
    /// the ciphertext is explicitly not a key-destruction receipt.
    pub(crate) fn load_protected<P>(
        path: impl AsRef<Path>,
        unprotector: &mut P,
    ) -> Result<Self, MissionProvisioningError>
    where
        P: ProvisioningUnprotector + ?Sized,
    {
        let mut protected = read_bounded_protected_artifact(path.as_ref())?;
        let result = Self::from_protected_bytes(&protected, unprotector);
        protected.zeroize();
        result
    }

    /// Loads one authenticated, provider-persisted provisioning reference.
    ///
    /// The exact caller-chosen operation and opaque reference are rechecked on
    /// the returned receipt before its zeroizing plaintext is parsed. The
    /// caller retains the provider and reference needed for later coordinated
    /// destruction; this method alone makes no runtime-drain or physical-media
    /// erasure claim.
    pub(crate) fn load_from_secret_store<L>(
        secret_ref: &ProvisioningSecretRef,
        operation: ProvisioningLoadId,
        loader: &mut L,
    ) -> Result<Self, MissionProvisioningError>
    where
        L: ProvisioningSecretLoader + ?Sized,
    {
        let receipt = load_provisioning_secret(operation, secret_ref, loader)
            .map_err(secret_store_provisioning_error)?;
        let mut mission = Self::from_unprotected(receipt.into_plaintext())?;
        mission.secret_ref = Some(secret_ref.clone());
        mission.provisioning_origin = MissionProvisioningOrigin::SecretReference;
        Ok(mission)
    }

    fn from_unprotected(
        encoded: UnprotectedProvisioning,
    ) -> Result<Self, MissionProvisioningError> {
        let bundle = ProvisioningBundle::from_bytes(encoded.expose())?;
        let sealer = ReferenceEnvelopeSealer::open(bundle)?;
        let identity = sealer.identity();
        let mission_authority = sealer.mission_authority_id();
        Ok(Self {
            encoded: Arc::new(Mutex::new(encoded)),
            identity,
            mission_authority,
            artifact: None,
            secret_ref: None,
            provisioning_origin: MissionProvisioningOrigin::UnprotectedReference,
            protected_state_witness: None,
        })
    }

    /// Loads one bounded regular owner-only unprotected reference bundle.
    ///
    /// The already-open file is inspected before reading so a missing, loose,
    /// oversized, or non-regular artifact fails before node state or sockets
    /// are created.
    pub fn load(path: impl AsRef<Path>) -> Result<Self, MissionProvisioningError> {
        load_owner_only_bundle(path.as_ref())
    }

    /// Persists newly issued demo/test credentials with owner-only permissions.
    pub fn persist(
        path: impl AsRef<Path>,
        bytes: Vec<u8>,
    ) -> Result<Self, MissionProvisioningError> {
        persist_owner_only_bundle(path.as_ref(), bytes)
    }

    /// Authority-authenticated Aster mission identity in this bundle.
    pub const fn identity(&self) -> NodeId {
        self.identity
    }

    /// Stable authority identity authenticated by this validated mission bundle.
    pub const fn mission_authority_id(&self) -> NodeId {
        self.mission_authority
    }

    /// Coarse provisioning source suitable for operator-visible receipts.
    ///
    /// This value never identifies a path, provider, operation, or opaque
    /// secret reference. Protected in-memory bytes and protected files share
    /// one origin because both cross the same authenticated provider boundary.
    pub const fn provisioning_origin(&self) -> MissionProvisioningOrigin {
        self.provisioning_origin
    }

    /// Opaque provider-persisted reference used to load this mission, if any.
    ///
    /// The reference contains no credential plaintext but remains redacted in
    /// Debug output and should be handed only to the configured backend.
    pub const fn persistent_secret_ref(&self) -> Option<&ProvisioningSecretRef> {
        self.secret_ref.as_ref()
    }

    /// Binds the lexical state root checked before protected provisioning.
    ///
    /// The selected runtime uses this crate-private witness to reject a later
    /// mutation of public `NodeConfig::state` without invoking the provider a
    /// second time. Callers must supply the already-normalized path checked
    /// before the protected credential source was accessed.
    pub(crate) fn with_protected_state_witness(mut self, state: PathBuf) -> Self {
        self.protected_state_witness = Some(state);
        self
    }

    /// Lexical state root checked before protected provisioning, if retained.
    pub(crate) fn protected_state_witness(&self) -> Option<&Path> {
        self.protected_state_witness.as_deref()
    }

    /// Side-effect-free validation and retention before terminal zeroization commit.
    pub fn prepare_software_erasure(
        &self,
    ) -> Result<PreparedMissionErasure, MissionProvisioningError> {
        let artifact = self
            .artifact
            .as_ref()
            .ok_or(SoftwareErasureError::NoPersistedArtifact)?;
        let target = artifact
            .lock()
            .map_err(|_| SoftwareErasureError::StatePoisoned)?
            .preflight()?;
        Ok(PreparedMissionErasure {
            encoded: Arc::clone(&self.encoded),
            artifact: Arc::clone(artifact),
            target,
            mission_authority: self.mission_authority,
        })
    }

    pub(crate) fn fresh_bundle(&self) -> Result<ProvisioningBundle, MissionSessionError> {
        let encoded = self.encoded.lock().map_err(|_| {
            MissionSessionError::Authentication(EnvelopeError(
                "mission provisioning state is poisoned".into(),
            ))
        })?;
        if encoded.is_zeroized() {
            return Err(MissionSessionError::Authentication(EnvelopeError(
                "mission provisioning has been zeroized".into(),
            )));
        }
        ProvisioningBundle::from_bytes(encoded.expose()).map_err(Into::into)
    }
}

/// Parsed profile-`0x0002` credentials retained as zeroizing plaintext bytes.
///
/// This type is intentionally explicit about its unprotected in-process
/// custody. It validates the complete authority-signed classical profile and
/// owns canonical bytes so each contact receives a fresh, single-use core
/// handshake bundle without retaining duplicate decoded private keys.
#[derive(Clone)]
pub struct UnprotectedClassicalMission {
    encoded: Arc<Mutex<UnprotectedProvisioning>>,
    identity: NodeId,
    security_profile: VerifiedSecurityProfile,
}

impl UnprotectedClassicalMission {
    /// Validates and owns canonical unprotected profile-`0x0002` bundle bytes.
    pub fn from_bytes(bytes: Vec<u8>) -> Result<Self, MissionProvisioningError> {
        let encoded = UnprotectedProvisioning::new(bytes)?;
        let bundle = ClassicalProvisioningBundle::from_bytes(encoded.expose())?;
        let identity = bundle.node_principal();
        let security_profile = bundle.verified_security_profile();
        if security_profile.profile_id() != SecurityProfileId::ClassicalP256IrohQuicV1
            || security_profile.required_profile_id() != security_profile.profile_id()
            || security_profile.profile().application_protection()
                != ApplicationProtection::AuthenticatedCarrierRequired
        {
            return Err(MissionProvisioningError::Invalid(EnvelopeError(
                "classical mission requires the exact Iroh-QUIC security profile".into(),
            )));
        }
        drop(bundle);
        Ok(Self {
            encoded: Arc::new(Mutex::new(encoded)),
            identity,
            security_profile,
        })
    }

    /// Authority-authenticated classical mission node principal.
    pub const fn identity(&self) -> NodeId {
        self.identity
    }

    /// Exact authority-authenticated security-profile policy.
    pub const fn verified_security_profile(&self) -> VerifiedSecurityProfile {
        self.security_profile
    }

    fn fresh_bundle(&self) -> Result<ClassicalProvisioningBundle, MissionSessionError> {
        let encoded = self.encoded.lock().map_err(|_| {
            MissionSessionError::Authentication(EnvelopeError(
                "classical mission provisioning state is poisoned".into(),
            ))
        })?;
        let bundle = ClassicalProvisioningBundle::from_bytes(encoded.expose())?;
        if bundle.node_principal() != self.identity
            || bundle.verified_security_profile() != self.security_profile
        {
            return Err(MissionSessionError::Authentication(EnvelopeError(
                "classical mission provisioning changed after validation".into(),
            )));
        }
        Ok(bundle)
    }
}

impl fmt::Debug for UnprotectedClassicalMission {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("UnprotectedClassicalMission")
            .field("identity", &"[REDACTED]")
            .field("profile", &self.security_profile.profile_id())
            .field(
                "policy_generation",
                &self.security_profile.policy_generation(),
            )
            .field("credential_bytes", &"[REDACTED]")
            .finish()
    }
}

fn read_bounded_protected_artifact(path: &Path) -> Result<Vec<u8>, MissionProvisioningError> {
    let path_metadata = std::fs::symlink_metadata(path)?;
    if !path_metadata.file_type().is_file() {
        return Err(MissionProvisioningError::NotRegular(path.to_path_buf()));
    }
    let maximum = u64::try_from(MAX_PROTECTED_PROVISIONING_BYTES)
        .expect("protected provisioning bound fits in u64");
    if path_metadata.len() > maximum {
        return Err(MissionProvisioningError::TooLarge {
            path: path.to_path_buf(),
            actual: path_metadata.len(),
            maximum,
        });
    }

    #[cfg(unix)]
    let file = {
        use std::os::unix::fs::OpenOptionsExt as _;

        let mut options = OpenOptions::new();
        options.read(true);
        options.custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK);
        options.open(path)?
    };
    #[cfg(not(unix))]
    let file = File::open(path)?;

    let metadata = file.metadata()?;
    if !metadata.is_file() {
        return Err(MissionProvisioningError::NotRegular(path.to_path_buf()));
    }
    #[cfg(unix)]
    if path_metadata.dev() != metadata.dev() || path_metadata.ino() != metadata.ino() {
        return Err(MissionProvisioningError::Changed(path.to_path_buf()));
    }
    if metadata.len() > maximum {
        return Err(MissionProvisioningError::TooLarge {
            path: path.to_path_buf(),
            actual: metadata.len(),
            maximum,
        });
    }

    let capacity = usize::try_from(metadata.len()).unwrap_or(0);
    let mut protected = Vec::with_capacity(capacity);
    if let Err(error) = file
        .take(maximum.saturating_add(1))
        .read_to_end(&mut protected)
    {
        protected.zeroize();
        return Err(error.into());
    }
    let actual = u64::try_from(protected.len()).expect("vector length fits in u64");
    if actual > maximum {
        protected.zeroize();
        return Err(MissionProvisioningError::TooLarge {
            path: path.to_path_buf(),
            actual,
            maximum,
        });
    }
    Ok(protected)
}

#[cfg(unix)]
fn load_owner_only_bundle(
    path: &Path,
) -> Result<UnprotectedReferenceMission, MissionProvisioningError> {
    let path_metadata = std::fs::symlink_metadata(path)?;
    if !path_metadata.file_type().is_file() {
        return Err(MissionProvisioningError::NotRegular(path.to_path_buf()));
    }
    let retained =
        RetainedSecretArtifact::open_existing(path, SoftwareSecretArtifact::MissionBundle)
            .map_err(MissionProvisioningError::from_artifact)?;
    let metadata = retained.file.metadata()?;
    let maximum =
        u64::try_from(MAX_UNPROTECTED_PROVISIONING_BYTES).expect("provisioning bound fits in u64");
    if metadata.len() > maximum {
        return Err(MissionProvisioningError::TooLarge {
            path: path.to_path_buf(),
            actual: metadata.len(),
            maximum,
        });
    }
    let capacity = usize::try_from(metadata.len()).unwrap_or(0);
    let mut bytes = Vec::with_capacity(capacity);
    let reader = &retained.file;
    if let Err(error) = reader
        .take(maximum.saturating_add(1))
        .read_to_end(&mut bytes)
    {
        bytes.zeroize();
        return Err(error.into());
    }
    if u64::try_from(bytes.len()).expect("vector length fits in u64") > maximum {
        bytes.zeroize();
        return Err(MissionProvisioningError::TooLarge {
            path: path.to_path_buf(),
            actual: maximum.saturating_add(1),
            maximum,
        });
    }
    let mut mission = UnprotectedReferenceMission::from_bytes(bytes)?;
    mission.artifact = Some(Arc::new(Mutex::new(retained)));
    Ok(mission)
}

#[cfg(not(unix))]
fn load_owner_only_bundle(
    path: &Path,
) -> Result<UnprotectedReferenceMission, MissionProvisioningError> {
    Err(MissionProvisioningError::OwnerOnlyPermissionsUnavailable(
        path.to_path_buf(),
    ))
}

#[cfg(unix)]
fn persist_owner_only_bundle(
    path: &Path,
    bytes: Vec<u8>,
) -> Result<UnprotectedReferenceMission, MissionProvisioningError> {
    let mut credentials = UnprotectedReferenceMission::from_bytes(bytes)?;
    let mut options = OpenOptions::new();
    options.read(true).write(true).create_new(true);
    use std::os::unix::fs::OpenOptionsExt as _;
    options.mode(0o600);
    let mut file = options.open(path)?;
    acquire_artifact_lock(&file, path)?;
    let encoded = credentials
        .encoded
        .lock()
        .map_err(|_| SoftwareErasureError::StatePoisoned)?;
    file.write_all(encoded.expose())?;
    file.sync_all()?;
    drop(encoded);
    sync_parent_directory(path)?;
    let path = absolute_artifact_path(path)?;
    let path_metadata = std::fs::symlink_metadata(&path)?;
    let retained = RetainedSecretArtifact::from_open_file(
        file,
        path,
        SoftwareSecretArtifact::MissionBundle,
        Some(path_metadata),
    )
    .map_err(MissionProvisioningError::from_artifact)?;
    credentials.artifact = Some(Arc::new(Mutex::new(retained)));
    Ok(credentials)
}

#[cfg(unix)]
fn sync_parent_directory(path: &Path) -> io::Result<()> {
    let parent = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    File::open(parent)?.sync_all()
}

#[cfg(not(unix))]
fn persist_owner_only_bundle(
    path: &Path,
    mut bytes: Vec<u8>,
) -> Result<UnprotectedReferenceMission, MissionProvisioningError> {
    bytes.zeroize();
    Err(MissionProvisioningError::OwnerOnlyPermissionsUnavailable(
        path.to_path_buf(),
    ))
}

impl fmt::Debug for UnprotectedReferenceMission {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let encoded_len = self.encoded.lock().map_or(0, |encoded| encoded.len());
        formatter
            .debug_struct("UnprotectedReferenceMission")
            .field("identity", &self.identity)
            .field("mission_authority", &self.mission_authority)
            .field("encoded_len", &encoded_len)
            .field("persisted", &self.artifact.is_some())
            .field("provider_persisted", &self.secret_ref.is_some())
            .field("provisioning_origin", &self.provisioning_origin)
            .field(
                "protected_state_witness_present",
                &self.protected_state_witness.is_some(),
            )
            .field("provisioning", &"[UNPROTECTED REFERENCE BYTES REDACTED]")
            .finish()
    }
}

/// Fail-closed reference provisioning artifact error.
#[derive(Debug)]
pub enum MissionProvisioningError {
    /// Filesystem operation failed.
    Io(io::Error),
    /// The supplied artifact is not a regular file.
    NotRegular(PathBuf),
    /// The path changed between validation and opening.
    Changed(PathBuf),
    /// The supplied artifact is readable beyond its owner.
    UnsafePermissions(PathBuf),
    /// This platform cannot enforce the reference bundle's owner-only contract.
    OwnerOnlyPermissionsUnavailable(PathBuf),
    /// The artifact exceeds the aster-core reference bound.
    TooLarge {
        path: PathBuf,
        actual: u64,
        maximum: u64,
    },
    /// The zeroizing plaintext wrapper rejected the artifact.
    Protection(ProvisioningProtectionError),
    /// `aster-core` rejected the bundle or could not open its identity.
    Invalid(EnvelopeError),
    /// The retained local artifact failed the software-erasure safety contract.
    Artifact(SoftwareErasureError),
}

impl fmt::Display for MissionProvisioningError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(error) => write!(formatter, "mission provisioning I/O: {error}"),
            Self::NotRegular(path) => write!(
                formatter,
                "mission provisioning artifact is not a regular file: {}",
                path.display()
            ),
            Self::Changed(path) => write!(
                formatter,
                "mission provisioning artifact changed while opening: {}",
                path.display()
            ),
            Self::UnsafePermissions(path) => write!(
                formatter,
                "unprotected reference mission bundle is accessible beyond its owner: {}",
                path.display()
            ),
            Self::OwnerOnlyPermissionsUnavailable(path) => write!(
                formatter,
                "owner-only permissions cannot be verified for unprotected reference mission bundle on this platform: {}",
                path.display()
            ),
            Self::TooLarge {
                path,
                actual,
                maximum,
            } => write!(
                formatter,
                "mission provisioning artifact {} is {actual} bytes; maximum is {maximum}",
                path.display()
            ),
            Self::Protection(error) => write!(formatter, "mission provisioning: {error}"),
            Self::Invalid(error) => write!(formatter, "invalid reference mission bundle: {error}"),
            Self::Artifact(error) => write!(formatter, "mission provisioning artifact: {error}"),
        }
    }
}

impl Error for MissionProvisioningError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Io(error) => Some(error),
            Self::Protection(error) => Some(error),
            Self::Invalid(error) => Some(error),
            Self::Artifact(error) => Some(error),
            Self::NotRegular(_)
            | Self::Changed(_)
            | Self::UnsafePermissions(_)
            | Self::OwnerOnlyPermissionsUnavailable(_)
            | Self::TooLarge { .. } => None,
        }
    }
}

impl From<io::Error> for MissionProvisioningError {
    fn from(error: io::Error) -> Self {
        Self::Io(error)
    }
}

impl From<ProvisioningProtectionError> for MissionProvisioningError {
    fn from(error: ProvisioningProtectionError) -> Self {
        Self::Protection(error)
    }
}

impl From<EnvelopeError> for MissionProvisioningError {
    fn from(error: EnvelopeError) -> Self {
        Self::Invalid(error)
    }
}

impl From<SoftwareErasureError> for MissionProvisioningError {
    fn from(error: SoftwareErasureError) -> Self {
        Self::Artifact(error)
    }
}

fn secret_store_provisioning_error(
    error: ProvisioningSecretStoreError,
) -> MissionProvisioningError {
    let error = match error {
        ProvisioningSecretStoreError::Unavailable => ProvisioningProtectionError::Unavailable,
        ProvisioningSecretStoreError::TooLarge => ProvisioningProtectionError::TooLarge,
        _ => ProvisioningProtectionError::Rejected,
    };
    MissionProvisioningError::Protection(error)
}

impl MissionProvisioningError {
    fn from_artifact(error: SoftwareErasureError) -> Self {
        match error {
            SoftwareErasureError::NotRegular(path) => Self::NotRegular(path),
            SoftwareErasureError::Changed(path) => Self::Changed(path),
            SoftwareErasureError::UnsafePermissions(path) => Self::UnsafePermissions(path),
            other => Self::Artifact(other),
        }
    }
}

/// Carrier and mission identities associated with one peer contact.
///
/// `carrier_id` is the Iroh identity authenticated by QUIC. `mission_id` is the
/// authority-provisioned Aster identity authenticated by the selected mission
/// handshake. They are deliberately different fields and different types. The
/// exact-roster path checks this pair against configuration; the discovered
/// hybrid path records two independently authenticated observations and does
/// not prove that one principal controls both identities.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct MissionPeerBinding {
    carrier_id: EndpointId,
    mission_id: NodeId,
}

impl MissionPeerBinding {
    /// Creates one carrier-and-mission identity pair.
    ///
    /// Exact-roster APIs treat this pair as an expectation. A discovered
    /// hybrid session constructs it only as two same-contact observations.
    pub const fn new(carrier_id: EndpointId, mission_id: NodeId) -> Self {
        Self {
            carrier_id,
            mission_id,
        }
    }

    /// Iroh endpoint identity in this pair.
    ///
    /// It is expected configuration for an exact-roster session and the
    /// authenticated connection observation for a discovered session.
    pub const fn carrier_id(&self) -> EndpointId {
        self.carrier_id
    }

    /// Aster mission identity in this pair.
    ///
    /// It is expected configuration for an exact-roster session and the
    /// authority-authenticated handshake result for a discovered session.
    pub const fn mission_id(&self) -> NodeId {
        self.mission_id
    }

    fn verify_observed_carrier(self, observed: EndpointId) -> Result<Self, MissionSessionError> {
        if observed != self.carrier_id {
            return Err(MissionSessionError::CarrierIdentityMismatch {
                expected: self.carrier_id,
                observed,
            });
        }
        Ok(self)
    }
}

/// Peer-admission decision retained across the hybrid handshake typestate.
///
/// A discovered carrier is not mission authorization. Its mission identity is
/// populated only from a completed [`ReferenceAuthenticatedSession`], whose
/// credential has already authenticated under the local bundle's exact mission
/// authority. The exact-roster variant preserves the additional configured
/// mission-identity comparison.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum HybridPeerAdmission {
    Exact(MissionPeerBinding),
    DiscoveredCarrier(EndpointId),
}

impl HybridPeerAdmission {
    fn exact(
        peer: MissionPeerBinding,
        observed_carrier: EndpointId,
    ) -> Result<Self, MissionSessionError> {
        Ok(Self::Exact(peer.verify_observed_carrier(observed_carrier)?))
    }

    const fn discovered(observed_carrier: EndpointId) -> Self {
        Self::DiscoveredCarrier(observed_carrier)
    }

    fn bind(
        self,
        mut inner: ReferenceAuthenticatedSession,
    ) -> Result<MissionSession, MissionSessionError> {
        let authenticated = inner.peer_identity();
        let peer = match self {
            Self::Exact(peer) if authenticated != peer.mission_id => {
                inner.zeroize();
                return Err(MissionSessionError::MissionIdentityMismatch {
                    expected: peer.mission_id,
                    authenticated,
                });
            }
            Self::Exact(peer) => peer,
            Self::DiscoveredCarrier(carrier_id) => {
                MissionPeerBinding::new(carrier_id, authenticated)
            }
        };
        Ok(MissionSession { inner, peer })
    }
}

/// Canonical role-ordered context supplied to the Iroh TLS exporter.
///
/// The exact `ASTRCB01` encoding is:
///
/// `magic || profile_u16 || generation_u64 || policy_authority[32] ||
/// mission_principal[32] || initiator_carrier[32] || initiator_mission[32] ||
/// responder_carrier[32] || responder_mission[32]`.
///
/// Initiator and responder order is semantic, never lexical. Reversing roles,
/// changing either identity, or changing the authenticated policy therefore
/// yields a different TLS exporter binding.
#[derive(Clone, Eq, PartialEq)]
pub struct ClassicalChannelBindingContext([u8; CLASSICAL_CHANNEL_BINDING_CONTEXT_BYTES]);

impl ClassicalChannelBindingContext {
    /// Encodes one exact classical profile and both role-bound identities.
    pub fn new(
        profile: VerifiedSecurityProfile,
        initiator: MissionPeerBinding,
        responder: MissionPeerBinding,
    ) -> Result<Self, MissionSessionError> {
        if profile.profile_id() != SecurityProfileId::ClassicalP256IrohQuicV1
            || profile.required_profile_id() != profile.profile_id()
            || profile.profile().application_protection()
                != ApplicationProtection::AuthenticatedCarrierRequired
        {
            return Err(MissionSessionError::Authentication(EnvelopeError(
                "channel-binding context requires the exact classical Iroh-QUIC profile".into(),
            )));
        }
        let mut encoded = [0u8; CLASSICAL_CHANNEL_BINDING_CONTEXT_BYTES];
        encoded[..8].copy_from_slice(CLASSICAL_CHANNEL_BINDING_CONTEXT_MAGIC);
        encoded[8..10].copy_from_slice(&profile.profile_id_u16().to_be_bytes());
        encoded[10..18].copy_from_slice(&profile.policy_generation().to_be_bytes());
        encoded[18..50].copy_from_slice(&profile.policy_authority_id());
        encoded[50..82].copy_from_slice(&profile.mission_principal());
        encoded[82..114].copy_from_slice(initiator.carrier_id().as_bytes());
        encoded[114..146].copy_from_slice(&initiator.mission_id());
        encoded[146..178].copy_from_slice(responder.carrier_id().as_bytes());
        encoded[178..210].copy_from_slice(&responder.mission_id());
        Ok(Self(encoded))
    }

    /// Borrows the exact canonical exporter-context bytes.
    pub fn as_bytes(&self) -> &[u8; CLASSICAL_CHANNEL_BINDING_CONTEXT_BYTES] {
        &self.0
    }
}

impl fmt::Debug for ClassicalChannelBindingContext {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ClassicalChannelBindingContext")
            .field("encoded_len", &self.0.len())
            .field("identities", &"[REDACTED]")
            .finish()
    }
}

/// Fail-closed error from carrier checks, mission authentication, or protected frames.
#[derive(Debug)]
pub enum MissionSessionError {
    /// The bounded Iroh carrier failed while exchanging an opaque flight.
    Carrier(CarrierError),
    /// The connection's authenticated Iroh identity did not match configuration.
    CarrierIdentityMismatch {
        expected: EndpointId,
        observed: EndpointId,
    },
    /// A carrier-bound profile was attempted over the wrong exact ALPN profile.
    CarrierSecurityProfileMismatch {
        required: CarrierSecurityProfile,
        observed: CarrierSecurityProfile,
    },
    /// The mission-handshake-authenticated Aster identity did not match configuration.
    MissionIdentityMismatch {
        expected: NodeId,
        authenticated: NodeId,
    },
    /// `aster-core` rejected a handshake flight or protected application frame.
    Authentication(EnvelopeError),
}

impl fmt::Display for MissionSessionError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Carrier(error) => write!(formatter, "mission carrier: {error}"),
            Self::CarrierIdentityMismatch { expected, observed } => write!(
                formatter,
                "carrier identity mismatch: expected {expected}, observed {observed}"
            ),
            Self::CarrierSecurityProfileMismatch { required, observed } => write!(
                formatter,
                "carrier security profile mismatch: required {required:?}, observed {observed:?}"
            ),
            Self::MissionIdentityMismatch {
                expected,
                authenticated,
            } => {
                formatter.write_str("mission identity mismatch: expected ")?;
                write_node_id(formatter, expected)?;
                formatter.write_str(", authenticated ")?;
                write_node_id(formatter, authenticated)
            }
            Self::Authentication(error) => write!(formatter, "mission authentication: {error}"),
        }
    }
}

impl Error for MissionSessionError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Carrier(error) => Some(error),
            Self::Authentication(error) => Some(error),
            Self::CarrierIdentityMismatch { .. }
            | Self::CarrierSecurityProfileMismatch { .. }
            | Self::MissionIdentityMismatch { .. } => None,
        }
    }
}

impl From<EnvelopeError> for MissionSessionError {
    fn from(error: EnvelopeError) -> Self {
        Self::Authentication(error)
    }
}

impl From<CarrierError> for MissionSessionError {
    fn from(error: CarrierError) -> Self {
        Self::Carrier(error)
    }
}

fn write_node_id(formatter: &mut fmt::Formatter<'_>, identity: &NodeId) -> fmt::Result {
    for byte in identity {
        write!(formatter, "{byte:02x}")?;
    }
    Ok(())
}

/// One opaque flight of the `aster-core` four-flight mission handshake.
///
/// The adapter adds no competing framing or cryptographic semantics. The
/// current typestate determines which flight is expected.
pub struct MissionHandshakeFlight(Vec<u8>);

impl MissionHandshakeFlight {
    fn new(bytes: Vec<u8>) -> Self {
        Self(bytes)
    }

    /// Borrows the opaque bytes for a bounded carrier exchange.
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    /// Consumes the flight for an API that owns its outbound buffer.
    pub fn into_bytes(self) -> Vec<u8> {
        self.0
    }

    /// Reports the exact encoded size for carrier-bound checks and metrics.
    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// Reports whether the underlying implementation produced no bytes.
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

impl fmt::Debug for MissionHandshakeFlight {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("MissionHandshakeFlight")
            .field("encoded_len", &self.0.len())
            .field("contents", &"[OPAQUE]")
            .finish()
    }
}

/// Wire accounting released only after all four mission flights authenticate.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct MissionHandshakeReceipt {
    /// Exactly four authenticated handshake flights.
    pub(crate) frames: usize,
    /// Encoded bytes across those four flights.
    pub(crate) bytes: usize,
}

impl MissionHandshakeReceipt {
    fn from_flights(lengths: [usize; 4]) -> Self {
        Self {
            frames: lengths.len(),
            bytes: lengths.into_iter().sum(),
        }
    }
}

/// Initiator waiting for the responder's second handshake flight.
pub struct MissionSessionInitiator {
    inner: ReferenceSessionInitiator,
    admission: HybridPeerAdmission,
}

impl MissionSessionInitiator {
    /// Starts the hybrid handshake after checking the carrier identity.
    ///
    /// `observed_carrier` must come from the authenticated Iroh connection,
    /// normally `aster_iroh::Connection::remote_id()`.
    pub fn start(
        bundle: ProvisioningBundle,
        peer: MissionPeerBinding,
        observed_carrier: EndpointId,
    ) -> Result<(Self, MissionHandshakeFlight), MissionSessionError> {
        Self::start_with_admission(bundle, HybridPeerAdmission::exact(peer, observed_carrier)?)
    }

    fn start_discovered(
        bundle: ProvisioningBundle,
        observed_carrier: EndpointId,
    ) -> Result<(Self, MissionHandshakeFlight), MissionSessionError> {
        Self::start_with_admission(bundle, HybridPeerAdmission::discovered(observed_carrier))
    }

    fn start_with_admission(
        bundle: ProvisioningBundle,
        admission: HybridPeerAdmission,
    ) -> Result<(Self, MissionHandshakeFlight), MissionSessionError> {
        let (inner, flight) = ReferenceSessionInitiator::start(bundle)?;
        Ok((
            Self { inner, admission },
            MissionHandshakeFlight::new(flight),
        ))
    }

    /// Authenticates the responder's second flight and creates the third.
    pub fn receive_server(
        self,
        flight: &[u8],
    ) -> Result<(MissionSessionAwaitingFinished, MissionHandshakeFlight), MissionSessionError> {
        let (inner, response) = self.inner.receive_server(flight)?;
        Ok((
            MissionSessionAwaitingFinished {
                inner,
                admission: self.admission,
            },
            MissionHandshakeFlight::new(response),
        ))
    }
}

/// Runs the initiator side of the four-flight mission handshake over one
/// authenticated Iroh connection.
///
/// The carrier performs two independently bounded request/response exchanges:
/// flights one/two and flights three/four. Any failure closes the connection;
/// a session is returned only after the independently authenticated carrier and
/// mission identities both match the exact configured expectation.
pub async fn initiate_over_iroh(
    connection: &Connection,
    bundle: ProvisioningBundle,
    peer: MissionPeerBinding,
) -> Result<MissionSession, MissionSessionError> {
    initiate_over_iroh_metered(connection, bundle, peer)
        .await
        .map(|(session, _receipt)| session)
}

/// Runs the initiator handshake and receipts its flights only on full success.
pub(crate) async fn initiate_over_iroh_metered(
    connection: &Connection,
    bundle: ProvisioningBundle,
    peer: MissionPeerBinding,
) -> Result<(MissionSession, MissionHandshakeReceipt), MissionSessionError> {
    initiate_over_iroh_metered_with_admission(connection, bundle, Some(peer)).await
}

/// Runs a discovered-peer initiator handshake and receipts it only on full success.
///
/// No expected carrier or mission identity is supplied to this mission layer.
/// The returned binding pairs the carrier identity authenticated by Iroh with
/// the mission identity authenticated under the local bundle's authority. It
/// does not promote that observed pair into a durable trust statement.
#[cfg_attr(not(feature = "nearby-discovery"), allow(dead_code))]
pub(crate) async fn initiate_discovered_over_iroh_metered(
    connection: &Connection,
    bundle: ProvisioningBundle,
) -> Result<(MissionSession, MissionHandshakeReceipt), MissionSessionError> {
    initiate_over_iroh_metered_with_admission(connection, bundle, None).await
}

async fn initiate_over_iroh_metered_with_admission(
    connection: &Connection,
    bundle: ProvisioningBundle,
    exact_peer: Option<MissionPeerBinding>,
) -> Result<(MissionSession, MissionHandshakeReceipt), MissionSessionError> {
    let result = async {
        let (initiator, first) = match exact_peer {
            Some(peer) => MissionSessionInitiator::start(bundle, peer, connection.remote_id())?,
            None => MissionSessionInitiator::start_discovered(bundle, connection.remote_id())?,
        };
        let second = connection.request(first.as_bytes()).await?;
        let (pending, third) = initiator.receive_server(&second)?;
        let fourth = connection.request(third.as_bytes()).await?;
        let receipt = MissionHandshakeReceipt::from_flights([
            first.len(),
            second.len(),
            third.len(),
            fourth.len(),
        ]);
        Ok((pending.receive_finished(&fourth)?, receipt))
    }
    .await;
    if result.is_err() {
        connection.close();
    }
    result
}

/// Initiator waiting for fourth-flight key confirmation.
///
/// This type has no application-frame methods. It becomes usable only after
/// both key confirmation and the selected peer-admission check succeed.
pub struct MissionSessionAwaitingFinished {
    inner: ReferenceSessionAwaitingFinished,
    admission: HybridPeerAdmission,
}

impl MissionSessionAwaitingFinished {
    /// Authenticates the fourth flight and applies the selected peer admission.
    pub fn receive_finished(self, flight: &[u8]) -> Result<MissionSession, MissionSessionError> {
        self.admission.bind(self.inner.receive_finished(flight)?)
    }
}

/// Responder waiting for the initiator's first handshake flight.
pub struct MissionSessionResponder {
    inner: ReferenceSessionResponder,
    admission: HybridPeerAdmission,
}

impl MissionSessionResponder {
    /// Opens the responder after checking the carrier identity.
    ///
    /// `observed_carrier` must come from the authenticated Iroh connection,
    /// normally `aster_iroh::Connection::remote_id()`.
    pub fn open(
        bundle: ProvisioningBundle,
        peer: MissionPeerBinding,
        observed_carrier: EndpointId,
    ) -> Result<Self, MissionSessionError> {
        Self::open_with_admission(bundle, HybridPeerAdmission::exact(peer, observed_carrier)?)
    }

    fn open_discovered(
        bundle: ProvisioningBundle,
        observed_carrier: EndpointId,
    ) -> Result<Self, MissionSessionError> {
        Self::open_with_admission(bundle, HybridPeerAdmission::discovered(observed_carrier))
    }

    fn open_with_admission(
        bundle: ProvisioningBundle,
        admission: HybridPeerAdmission,
    ) -> Result<Self, MissionSessionError> {
        Ok(Self {
            inner: ReferenceSessionResponder::open(bundle)?,
            admission,
        })
    }

    /// Authenticates the initiator's first flight and creates the second.
    pub fn receive_client(
        self,
        flight: &[u8],
    ) -> Result<(MissionSessionResponderPending, MissionHandshakeFlight), MissionSessionError> {
        let (inner, response) = self.inner.receive_client(flight)?;
        Ok((
            MissionSessionResponderPending {
                inner,
                admission: self.admission,
            },
            MissionHandshakeFlight::new(response),
        ))
    }
}

/// Responder waiting for the initiator's third handshake flight.
///
/// This type has no application-frame methods. The selected peer admission is
/// applied before the fourth flight is returned to the carrier.
pub struct MissionSessionResponderPending {
    inner: ReferenceSessionResponderPending,
    admission: HybridPeerAdmission,
}

impl MissionSessionResponderPending {
    /// Authenticates the third flight, applies the selected peer admission, and
    /// returns the completed responder session plus fourth flight.
    pub fn receive_client_auth(
        self,
        flight: &[u8],
    ) -> Result<(MissionSession, MissionHandshakeFlight), MissionSessionError> {
        let (inner, response) = self.inner.receive_client_auth(flight)?;
        let session = self.admission.bind(inner)?;
        Ok((session, MissionHandshakeFlight::new(response)))
    }
}

/// Runs the responder side of the four-flight mission handshake over one
/// authenticated Iroh connection.
///
/// The carrier accepts two independently bounded request/response exchanges:
/// flights one/two and flights three/four. A handshake or expected-identity error is
/// retained as a mission error rather than being relabeled as a transport
/// failure. Any failure closes the connection.
pub async fn respond_over_iroh(
    connection: &Connection,
    bundle: ProvisioningBundle,
    peer: MissionPeerBinding,
) -> Result<MissionSession, MissionSessionError> {
    respond_over_iroh_metered(connection, bundle, peer)
        .await
        .map(|(session, _receipt)| session)
}

/// Runs the responder handshake and receipts its flights only on full success.
pub(crate) async fn respond_over_iroh_metered(
    connection: &Connection,
    bundle: ProvisioningBundle,
    peer: MissionPeerBinding,
) -> Result<(MissionSession, MissionHandshakeReceipt), MissionSessionError> {
    respond_over_iroh_metered_with_admission(connection, bundle, Some(peer)).await
}

/// Runs a discovered-peer responder handshake and receipts it only on full success.
///
/// The remote mission identity is not accepted from discovery or application
/// bytes. It is learned only from the completed authority-authenticated core
/// handshake and then paired with the Iroh-authenticated carrier identity for
/// this contact; the pair is not a proof of common key ownership.
#[cfg_attr(not(feature = "nearby-discovery"), allow(dead_code))]
pub(crate) async fn respond_discovered_over_iroh_metered(
    connection: &Connection,
    bundle: ProvisioningBundle,
) -> Result<(MissionSession, MissionHandshakeReceipt), MissionSessionError> {
    respond_over_iroh_metered_with_admission(connection, bundle, None).await
}

async fn respond_over_iroh_metered_with_admission(
    connection: &Connection,
    bundle: ProvisioningBundle,
    exact_peer: Option<MissionPeerBinding>,
) -> Result<(MissionSession, MissionHandshakeReceipt), MissionSessionError> {
    let result = respond_over_iroh_inner(connection, bundle, exact_peer).await;
    if result.is_err() {
        connection.close();
    }
    result
}

async fn respond_over_iroh_inner(
    connection: &Connection,
    bundle: ProvisioningBundle,
    exact_peer: Option<MissionPeerBinding>,
) -> Result<(MissionSession, MissionHandshakeReceipt), MissionSessionError> {
    let responder = match exact_peer {
        Some(peer) => MissionSessionResponder::open(bundle, peer, connection.remote_id())?,
        None => MissionSessionResponder::open_discovered(bundle, connection.remote_id())?,
    };
    let mut first_transition = None;
    let mut first_lengths = None;
    let first_exchange = connection
        .respond_once(|first| match responder.receive_client(first) {
            Ok((pending, second)) => {
                first_lengths = Some((first.len(), second.len()));
                first_transition = Some(Ok(pending));
                Ok((second.into_bytes(), false))
            }
            Err(error) => {
                first_transition = Some(Err(error));
                Err(CarrierError::Transport(
                    "mission handshake rejected before flight two".into(),
                ))
            }
        })
        .await;
    let pending = match (first_exchange, first_transition) {
        (_, Some(Err(error))) => return Err(error),
        (Err(error), _) => return Err(error.into()),
        (Ok(false), Some(Ok(pending))) => pending,
        (Ok(true), Some(Ok(_))) => {
            return Err(CarrierError::Transport(
                "mission carrier reported early handshake completion".into(),
            )
            .into());
        }
        (Ok(_), None) => {
            return Err(CarrierError::Transport(
                "mission carrier skipped the first handshake transition".into(),
            )
            .into());
        }
    };

    let mut second_transition = None;
    let mut second_lengths = None;
    let second_exchange = connection
        .respond_once(|third| match pending.receive_client_auth(third) {
            Ok((session, fourth)) => {
                second_lengths = Some((third.len(), fourth.len()));
                second_transition = Some(Ok(session));
                Ok((fourth.into_bytes(), true))
            }
            Err(error) => {
                second_transition = Some(Err(error));
                Err(CarrierError::Transport(
                    "mission handshake rejected before flight four".into(),
                ))
            }
        })
        .await;
    match (second_exchange, second_transition) {
        (_, Some(Err(error))) => Err(error),
        (Err(error), _) => Err(error.into()),
        (Ok(true), Some(Ok(session))) => {
            let (first, second) = first_lengths.ok_or_else(|| {
                CarrierError::Transport("mission carrier omitted first-flight accounting".into())
            })?;
            let (third, fourth) = second_lengths.ok_or_else(|| {
                CarrierError::Transport("mission carrier omitted second-flight accounting".into())
            })?;
            Ok((
                session,
                MissionHandshakeReceipt::from_flights([first, second, third, fourth]),
            ))
        }
        (Ok(false), Some(Ok(_))) => Err(CarrierError::Transport(
            "mission carrier did not report completed handshake".into(),
        )
        .into()),
        (Ok(_), None) => Err(CarrierError::Transport(
            "mission carrier skipped the second handshake transition".into(),
        )
        .into()),
    }
}

fn classical_channel_binding(
    connection: &Connection,
    mission: &UnprotectedClassicalMission,
    peer: MissionPeerBinding,
    local_is_initiator: bool,
) -> Result<AuthenticatedChannelBinding, MissionSessionError> {
    if connection.security_profile() != CarrierSecurityProfile::IrohQuicV1 {
        return Err(MissionSessionError::CarrierSecurityProfileMismatch {
            required: CarrierSecurityProfile::IrohQuicV1,
            observed: connection.security_profile(),
        });
    }
    let peer = peer.verify_observed_carrier(connection.remote_id())?;
    let local = MissionPeerBinding::new(connection.local_id(), mission.identity());
    let (initiator, responder) = if local_is_initiator {
        (local, peer)
    } else {
        (peer, local)
    };
    let context = ClassicalChannelBindingContext::new(
        mission.verified_security_profile(),
        initiator,
        responder,
    )?;
    let exporter_context = IrohChannelBindingContext::new(context.as_bytes())?;
    let binding = connection.channel_binding(exporter_context)?;
    AuthenticatedChannelBinding::new(binding.as_bytes().to_vec()).map_err(Into::into)
}

struct ClassicalConnectionGuard(Option<Connection>);

impl ClassicalConnectionGuard {
    fn new(connection: Connection) -> Self {
        Self(Some(connection))
    }

    fn connection(&self) -> &Connection {
        self.0
            .as_ref()
            .expect("classical connection guard is armed until session construction")
    }

    fn into_connection(mut self) -> Connection {
        self.0
            .take()
            .expect("classical connection guard is armed until session construction")
    }
}

impl Drop for ClassicalConnectionGuard {
    fn drop(&mut self) {
        if let Some(connection) = self.0.as_ref() {
            connection.close();
        }
    }
}

/// Runs the initiator side of the carrier-bound classical four-flight handshake.
///
/// This function takes ownership of the exact `IrohQuicV1` connection. No
/// application access is returned until flight four, the authority-authenticated
/// profile policy, the TLS exporter, and the configured carrier/mission peer
/// binding all authenticate. Every failure closes the owned connection.
pub async fn initiate_classical_over_iroh(
    connection: Connection,
    mission: &UnprotectedClassicalMission,
    peer: MissionPeerBinding,
) -> Result<CarrierBoundClassicalMissionSession, MissionSessionError> {
    let connection = ClassicalConnectionGuard::new(connection);
    let handshake = async {
        let channel_binding =
            classical_channel_binding(connection.connection(), mission, peer, true)?;
        let (initiator, first) =
            ClassicalSessionInitiator::start(mission.fresh_bundle()?, channel_binding)?;
        let second = connection.connection().request(&first).await?;
        let (pending, third) = initiator.receive_server(&second)?;
        let fourth = connection.connection().request(&third).await?;
        pending.receive_finished(&fourth).map_err(Into::into)
    }
    .await;
    match handshake {
        Ok(inner) => CarrierBoundClassicalMissionSession::bind(
            inner,
            connection.into_connection(),
            mission.identity(),
            peer,
            mission.verified_security_profile(),
        ),
        Err(error) => Err(error),
    }
}

/// Runs the responder side of the carrier-bound classical four-flight handshake.
///
/// The returned session owns the exact exporter-bound connection. Rejected
/// policy, context, carrier identity, mission identity, or flight bytes close
/// that connection and never enter the legacy hybrid path.
pub async fn respond_classical_over_iroh(
    connection: Connection,
    mission: &UnprotectedClassicalMission,
    peer: MissionPeerBinding,
) -> Result<CarrierBoundClassicalMissionSession, MissionSessionError> {
    let connection = ClassicalConnectionGuard::new(connection);
    let handshake = respond_classical_over_iroh_inner(connection.connection(), mission, peer).await;
    match handshake {
        Ok(inner) => CarrierBoundClassicalMissionSession::bind(
            inner,
            connection.into_connection(),
            mission.identity(),
            peer,
            mission.verified_security_profile(),
        ),
        Err(error) => Err(error),
    }
}

async fn respond_classical_over_iroh_inner(
    connection: &Connection,
    mission: &UnprotectedClassicalMission,
    peer: MissionPeerBinding,
) -> Result<ClassicalAuthenticatedSession, MissionSessionError> {
    let channel_binding = classical_channel_binding(connection, mission, peer, false)?;
    let responder = ClassicalSessionResponder::open(mission.fresh_bundle()?, channel_binding)?;
    let mut first_transition = None;
    let first_exchange = connection
        .respond_once(|first| match responder.receive_client(first) {
            Ok((pending, second)) => {
                first_transition = Some(Ok(pending));
                Ok((second, false))
            }
            Err(error) => {
                first_transition = Some(Err(MissionSessionError::from(error)));
                Err(CarrierError::Transport(
                    "classical mission handshake rejected before flight two".into(),
                ))
            }
        })
        .await;
    let pending = match (first_exchange, first_transition) {
        (_, Some(Err(error))) => return Err(error),
        (Err(error), _) => return Err(error.into()),
        (Ok(false), Some(Ok(pending))) => pending,
        (Ok(true), Some(Ok(_))) => {
            return Err(CarrierError::Transport(
                "classical mission carrier reported early handshake completion".into(),
            )
            .into());
        }
        (Ok(_), None) => {
            return Err(CarrierError::Transport(
                "classical mission carrier skipped the first handshake transition".into(),
            )
            .into());
        }
    };

    let expected_profile = mission.verified_security_profile();
    let mut second_transition = None;
    let second_exchange = connection
        .respond_once(|third| match pending.receive_client_auth(third) {
            Ok((mut session, fourth)) => {
                match validate_classical_authenticated_session(&mut session, peer, expected_profile)
                {
                    Ok(()) => {
                        second_transition = Some(Ok(session));
                        Ok((fourth, true))
                    }
                    Err(error) => {
                        second_transition = Some(Err(error));
                        Err(CarrierError::Transport(
                            "classical mission authorization rejected before flight four".into(),
                        ))
                    }
                }
            }
            Err(error) => {
                second_transition = Some(Err(MissionSessionError::from(error)));
                Err(CarrierError::Transport(
                    "classical mission handshake rejected before flight four".into(),
                ))
            }
        })
        .await;
    match (second_exchange, second_transition) {
        (_, Some(Err(error))) => Err(error),
        (Err(error), _) => Err(error.into()),
        (Ok(true), Some(Ok(session))) => Ok(session),
        (Ok(false), Some(Ok(_))) => Err(CarrierError::Transport(
            "classical mission carrier did not report completed handshake".into(),
        )
        .into()),
        (Ok(_), None) => Err(CarrierError::Transport(
            "classical mission carrier skipped the second handshake transition".into(),
        )
        .into()),
    }
}

fn validate_classical_authenticated_session(
    inner: &mut ClassicalAuthenticatedSession,
    peer: MissionPeerBinding,
    expected_profile: VerifiedSecurityProfile,
) -> Result<(), MissionSessionError> {
    let authenticated = inner.peer_identity();
    if authenticated != peer.mission_id() {
        inner.zeroize();
        return Err(MissionSessionError::MissionIdentityMismatch {
            expected: peer.mission_id(),
            authenticated,
        });
    }
    if inner.verified_security_profile() != expected_profile
        || inner.application_protection() != ApplicationProtection::AuthenticatedCarrierRequired
    {
        inner.zeroize();
        return Err(MissionSessionError::Authentication(EnvelopeError(
            "authenticated classical session changed its required profile".into(),
        )));
    }
    Ok(())
}

/// Fully authenticated classical mission authorization owning one exact QUIC connection.
///
/// Ordinary application bytes must use [`Self::connection`] directly and are
/// therefore protected once by Iroh QUIC. This type deliberately exposes no
/// `ASTRFR01` sealing or opening API.
pub struct CarrierBoundClassicalMissionSession {
    inner: ClassicalAuthenticatedSession,
    connection: Connection,
    local_identity: NodeId,
    peer: MissionPeerBinding,
    security_profile: VerifiedSecurityProfile,
}

impl CarrierBoundClassicalMissionSession {
    fn bind(
        mut inner: ClassicalAuthenticatedSession,
        connection: Connection,
        local_identity: NodeId,
        peer: MissionPeerBinding,
        expected_profile: VerifiedSecurityProfile,
    ) -> Result<Self, MissionSessionError> {
        if connection.security_profile() != CarrierSecurityProfile::IrohQuicV1 {
            inner.zeroize();
            connection.close();
            return Err(MissionSessionError::CarrierSecurityProfileMismatch {
                required: CarrierSecurityProfile::IrohQuicV1,
                observed: connection.security_profile(),
            });
        }
        if let Err(error) =
            validate_classical_authenticated_session(&mut inner, peer, expected_profile)
        {
            connection.close();
            return Err(error);
        }
        Ok(Self {
            inner,
            connection,
            local_identity,
            peer,
            security_profile: expected_profile,
        })
    }

    /// Local authority-authenticated mission node identity for this adjacency.
    pub const fn local_identity(&self) -> NodeId {
        self.local_identity
    }

    /// Exact carrier-to-mission peer binding authenticated for this adjacency.
    pub const fn peer(&self) -> MissionPeerBinding {
        self.peer
    }

    /// Authority-authenticated complete profile and policy generation.
    pub const fn verified_security_profile(&self) -> VerifiedSecurityProfile {
        self.security_profile
    }

    /// Authenticated semantic protocol version selected by the classical core profile.
    pub const fn semantic_version(&self) -> u16 {
        self.inner.semantic_version()
    }

    /// Authority-signed route-grant commitments authenticated for the peer.
    pub fn peer_route_grant_commitments(&self) -> &[[u8; 32]] {
        self.inner.peer_route_grant_commitments()
    }

    /// Non-secret identifier for this completed authenticated mission session.
    pub const fn session_id(&self) -> [u8; 32] {
        self.inner.session_id()
    }

    /// Exact Iroh connection whose TLS exporter is authenticated by this session.
    ///
    /// Use its bounded request/respond operations for ordinary raw application
    /// bytes. No Aster record-encryption layer is added in this profile.
    pub const fn connection(&self) -> &Connection {
        &self.connection
    }

    /// Closes the owned connection and erases session-derived authentication state.
    pub fn close(&mut self) {
        self.connection.close();
        self.inner.zeroize();
    }
}

impl fmt::Debug for CarrierBoundClassicalMissionSession {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CarrierBoundClassicalMissionSession")
            .field("profile", &self.security_profile.profile_id())
            .field(
                "policy_generation",
                &self.security_profile.policy_generation(),
            )
            .field("identities", &"[REDACTED]")
            .field("session_state", &"[REDACTED]")
            .finish()
    }
}

impl Drop for CarrierBoundClassicalMissionSession {
    fn drop(&mut self) {
        self.close();
    }
}

/// Hybrid-authenticated mission session associated with one carrier peer.
pub struct MissionSession {
    inner: ReferenceAuthenticatedSession,
    peer: MissionPeerBinding,
}

impl MissionSession {
    /// Carrier and mission identities authenticated independently for this session.
    ///
    /// Exact-roster sessions additionally checked the pair against
    /// configuration. Discovered hybrid sessions make no common-key-ownership
    /// claim about the two identities.
    pub const fn peer(&self) -> MissionPeerBinding {
        self.peer
    }

    /// Authenticated semantic protocol version selected by `aster-core`.
    pub fn semantic_version(&self) -> u16 {
        self.inner.semantic_version()
    }

    /// Authority-signed route-grant commitments authenticated in the peer's
    /// mission credential by the completed handshake.
    ///
    /// The values remain opaque and are only valid as provider authorization
    /// input; they are never learned from application frames.
    pub fn peer_route_grant_commitments(&self) -> &[[u8; 32]] {
        self.inner.peer_route_grant_commitments()
    }

    /// Encrypts, authenticates, and sequences one application frame.
    pub fn seal_application_frame(
        &mut self,
        plaintext: &[u8],
    ) -> Result<Vec<u8>, MissionSessionError> {
        self.inner.seal_frame(plaintext).map_err(Into::into)
    }

    /// Authenticates, decrypts, and replay-checks one application frame.
    pub fn open_application_frame(&mut self, frame: &[u8]) -> Result<Vec<u8>, MissionSessionError> {
        self.inner.open_frame(frame).map_err(Into::into)
    }

    /// Protects one exact semantic-v3 custody claim in its dedicated record domain.
    pub fn seal_custody_wrapper(
        &mut self,
        claims: &CustodyClaims,
    ) -> Result<Vec<u8>, MissionSessionError> {
        self.inner.seal_custody_wrapper(claims).map_err(Into::into)
    }

    /// Opens and exact-context-checks one semantic-v3 custody claim.
    pub fn open_custody_wrapper(
        &mut self,
        wrapper: &[u8],
        expected: CustodyExpectation,
    ) -> Result<VerifiedCustodyClaims, MissionSessionError> {
        self.inner
            .open_custody_wrapper(wrapper, expected)
            .map_err(Into::into)
    }

    /// Rapidly erases the directional traffic keys.
    pub fn zeroize(&mut self) {
        self.inner.zeroize();
    }
}

impl fmt::Debug for MissionSession {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("MissionSession")
            .field("peer", &self.peer)
            .field("semantic_version", &self.inner.semantic_version())
            .field("key_material", &"[REDACTED]")
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::frame::{EventDirection, Frame};
    use aster_iroh::{CarrierSecurityProfile, Endpoint, EndpointConfig, ExpectedPeer, SecretKey};
    use aster_mesh::{
        ClassicalProvisioner, ClassicalProvisioningAccess, ProvisioningAccess,
        ProvisioningLoadReceipt, ReferenceEnvelopeSealer, ReferenceProvisioner, Scope, Topic,
    };
    use std::{collections::BTreeSet, net::SocketAddr, time::Duration};

    struct IssuedNode {
        bundle: Vec<u8>,
        identity: NodeId,
        carrier: EndpointId,
    }

    impl IssuedNode {
        fn bundle(&self) -> ProvisioningBundle {
            ProvisioningBundle::from_bytes(&self.bundle).expect("parse issued bundle")
        }
    }

    struct TestProvisioningUnprotector {
        calls: usize,
        maximum_plaintext_len: Option<usize>,
        plaintext: Option<Vec<u8>>,
    }

    impl TestProvisioningUnprotector {
        fn new(plaintext: Vec<u8>) -> Self {
            Self {
                calls: 0,
                maximum_plaintext_len: None,
                plaintext: Some(plaintext),
            }
        }
    }

    impl ProvisioningUnprotector for TestProvisioningUnprotector {
        fn unprotect(
            &mut self,
            _protected: &[u8],
            maximum_plaintext_len: usize,
        ) -> Result<UnprotectedProvisioning, ProvisioningProtectionError> {
            self.calls += 1;
            self.maximum_plaintext_len = Some(maximum_plaintext_len);
            UnprotectedProvisioning::new(
                self.plaintext
                    .take()
                    .ok_or(ProvisioningProtectionError::Unavailable)?,
            )
        }
    }

    struct TestProvisioningSecretLoader {
        calls: usize,
        expected_operation: ProvisioningLoadId,
        expected_ref: ProvisioningSecretRef,
        returned_operation: ProvisioningLoadId,
        returned_ref: ProvisioningSecretRef,
        plaintext: Option<Vec<u8>>,
    }

    impl ProvisioningSecretLoader for TestProvisioningSecretLoader {
        fn load(
            &mut self,
            operation: ProvisioningLoadId,
            secret_ref: &ProvisioningSecretRef,
        ) -> Result<ProvisioningLoadReceipt, ProvisioningSecretStoreError> {
            self.calls += 1;
            assert_eq!(operation, self.expected_operation);
            assert_eq!(secret_ref, &self.expected_ref);
            let plaintext = UnprotectedProvisioning::new(
                self.plaintext
                    .take()
                    .ok_or(ProvisioningSecretStoreError::Unavailable)?,
            )
            .map_err(|_| ProvisioningSecretStoreError::Rejected)?;
            Ok(ProvisioningLoadReceipt::new(
                self.returned_operation,
                self.returned_ref.clone(),
                plaintext,
            ))
        }
    }

    fn access() -> ProvisioningAccess {
        ProvisioningAccess::member(
            Scope::new("test/mission").expect("scope"),
            vec![1],
            vec![Topic::new("mesh").expect("topic")],
        )
        .expect("access")
    }

    fn issue(provisioner: &mut ReferenceProvisioner, serial: u64) -> IssuedNode {
        let bundle = provisioner
            .issue_node(serial, &[access()])
            .expect("issue node");
        let encoded = bundle.to_bytes().expect("encode bundle");
        let identity = ReferenceEnvelopeSealer::open(
            ProvisioningBundle::from_bytes(&encoded).expect("identity bundle"),
        )
        .expect("open identity service")
        .identity();
        IssuedNode {
            bundle: encoded,
            identity,
            carrier: SecretKey::generate().public(),
        }
    }

    fn binding(peer: &IssuedNode) -> MissionPeerBinding {
        MissionPeerBinding::new(peer.carrier, peer.identity)
    }

    #[test]
    fn provisioning_origins_have_stable_nonidentifying_receipt_labels() {
        assert_eq!(
            MissionProvisioningOrigin::UnprotectedReference.receipt_label(),
            "unprotected-reference"
        );
        assert_eq!(
            MissionProvisioningOrigin::ProtectedArtifact.receipt_label(),
            "provider-protected-artifact"
        );
        assert_eq!(
            MissionProvisioningOrigin::SecretReference.receipt_label(),
            "provider-secret-reference"
        );
    }

    #[test]
    fn protected_state_witness_is_lexical_and_clone_local() {
        let mut provisioner = ReferenceProvisioner::from_seed([0x63; 32]).expect("provisioner");
        let issued = issue(&mut provisioner, 1);
        let mission = UnprotectedReferenceMission::from_bytes(issued.bundle)
            .expect("parse unprotected reference mission");
        let witnessed = mission
            .clone()
            .with_protected_state_witness(PathBuf::from("/exact/lexical/state"));

        assert_eq!(
            mission.provisioning_origin(),
            MissionProvisioningOrigin::UnprotectedReference
        );
        assert_eq!(mission.protected_state_witness(), None);
        assert_eq!(
            witnessed.protected_state_witness(),
            Some(Path::new("/exact/lexical/state"))
        );
        assert!(Arc::ptr_eq(&mission.encoded, &witnessed.encoded));
    }

    fn establish(
        initiator: &IssuedNode,
        responder: &IssuedNode,
    ) -> Result<(MissionSession, MissionSession), MissionSessionError> {
        let (initiator_state, first) = MissionSessionInitiator::start(
            initiator.bundle(),
            binding(responder),
            responder.carrier,
        )?;
        let responder_state = MissionSessionResponder::open(
            responder.bundle(),
            binding(initiator),
            initiator.carrier,
        )?;
        let (responder_pending, second) = responder_state.receive_client(first.as_bytes())?;
        let (initiator_pending, third) = initiator_state.receive_server(second.as_bytes())?;
        let (responder_session, fourth) =
            responder_pending.receive_client_auth(third.as_bytes())?;
        let initiator_session = initiator_pending.receive_finished(fourth.as_bytes())?;
        Ok((initiator_session, responder_session))
    }

    fn loopback(endpoint: &Endpoint) -> SocketAddr {
        endpoint
            .bound_sockets()
            .into_iter()
            .find(SocketAddr::is_ipv4)
            .expect("IPv4 loopback binding")
    }

    fn classical_access() -> ClassicalProvisioningAccess {
        ClassicalProvisioningAccess::member(
            Scope::new("test/classical-mission").expect("scope"),
            vec![1],
            vec![Topic::new("mesh").expect("topic")],
        )
        .expect("classical access")
    }

    fn issue_classical(
        provisioner: &mut ClassicalProvisioner,
        serial: u64,
    ) -> UnprotectedClassicalMission {
        let bundle = provisioner
            .issue_node(serial, &[classical_access()])
            .expect("issue classical node");
        UnprotectedClassicalMission::from_bytes(bundle.to_bytes().expect("encode classical bundle"))
            .expect("parse classical mission")
    }

    async fn bind_carrier(profile: CarrierSecurityProfile) -> Endpoint {
        Endpoint::bind_with_security_profile(
            SecretKey::generate(),
            EndpointConfig::direct("127.0.0.1:0".parse().expect("carrier address")),
            profile,
        )
        .await
        .expect("bind carrier")
    }

    #[test]
    fn classical_channel_binding_context_is_exact_role_ordered_and_redacted() {
        let provisioner = ClassicalProvisioner::from_seed([0x81; 32], 17).expect("provisioner");
        let profile = provisioner.verified_security_profile();
        let initiator = MissionPeerBinding::new(SecretKey::generate().public(), [0x11; 32]);
        let responder = MissionPeerBinding::new(SecretKey::generate().public(), [0x22; 32]);
        let context =
            ClassicalChannelBindingContext::new(profile, initiator, responder).expect("context");
        assert_eq!(
            context.as_bytes().len(),
            CLASSICAL_CHANNEL_BINDING_CONTEXT_BYTES
        );
        assert_eq!(&context.as_bytes()[..8], b"ASTRCB01");
        assert_eq!(
            &context.as_bytes()[8..10],
            &SecurityProfileId::ClassicalP256IrohQuicV1
                .as_u16()
                .to_be_bytes()
        );
        assert_eq!(&context.as_bytes()[10..18], &17u64.to_be_bytes());
        assert_eq!(&context.as_bytes()[18..50], &profile.policy_authority_id());
        assert_eq!(&context.as_bytes()[50..82], &profile.mission_principal());
        assert_eq!(
            &context.as_bytes()[82..114],
            initiator.carrier_id().as_bytes()
        );
        assert_eq!(&context.as_bytes()[114..146], &initiator.mission_id());
        assert_eq!(
            &context.as_bytes()[146..178],
            responder.carrier_id().as_bytes()
        );
        assert_eq!(&context.as_bytes()[178..210], &responder.mission_id());
        assert_ne!(
            context,
            ClassicalChannelBindingContext::new(profile, responder, initiator)
                .expect("reversed context")
        );
        let debug = format!("{context:?}");
        assert!(!debug.contains(&initiator.carrier_id().to_string()));
        assert!(!debug.contains("11111111"));
    }

    #[test]
    fn responder_authorization_rejects_peer_and_profile_before_flight_four_release() {
        fn binding() -> AuthenticatedChannelBinding {
            AuthenticatedChannelBinding::new(vec![0x91; 32]).expect("channel binding")
        }

        fn responder_session(
            initiator: &UnprotectedClassicalMission,
            responder: &UnprotectedClassicalMission,
        ) -> (ClassicalAuthenticatedSession, Vec<u8>) {
            let (initiator_state, first) = ClassicalSessionInitiator::start(
                initiator.fresh_bundle().expect("initiator"),
                binding(),
            )
            .expect("start initiator");
            let responder_state = ClassicalSessionResponder::open(
                responder.fresh_bundle().expect("responder"),
                binding(),
            )
            .expect("open responder");
            let (responder_pending, second) = responder_state
                .receive_client(&first)
                .expect("receive first");
            let (_initiator_pending, third) = initiator_state
                .receive_server(&second)
                .expect("receive second");
            responder_pending
                .receive_client_auth(&third)
                .expect("receive third")
        }

        let mut provisioner = ClassicalProvisioner::from_seed([0x92; 32], 51).expect("provisioner");
        let initiator = issue_classical(&mut provisioner, 1);
        let responder = issue_classical(&mut provisioner, 2);
        let exact_profile = responder.verified_security_profile();
        let correct_peer =
            MissionPeerBinding::new(SecretKey::generate().public(), initiator.identity());

        let (mut wrong_peer_session, fourth) = responder_session(&initiator, &responder);
        assert!(!fourth.is_empty());
        let wrong_peer = MissionPeerBinding::new(correct_peer.carrier_id(), [0x93; 32]);
        assert!(matches!(
            validate_classical_authenticated_session(
                &mut wrong_peer_session,
                wrong_peer,
                exact_profile,
            ),
            Err(MissionSessionError::MissionIdentityMismatch { .. })
        ));
        assert!(wrong_peer_session.is_zeroized());

        let wrong_profile = ClassicalProvisioner::from_seed([0x92; 32], 52)
            .expect("new generation")
            .verified_security_profile();
        let (mut wrong_profile_session, fourth) = responder_session(&initiator, &responder);
        assert!(!fourth.is_empty());
        assert!(matches!(
            validate_classical_authenticated_session(
                &mut wrong_profile_session,
                correct_peer,
                wrong_profile,
            ),
            Err(MissionSessionError::Authentication(_))
        ));
        assert!(wrong_profile_session.is_zeroized());
    }

    #[tokio::test]
    async fn real_iroh_classical_mission_binds_both_identities_and_raw_exchange() {
        let server = bind_carrier(CarrierSecurityProfile::IrohQuicV1).await;
        let client = bind_carrier(CarrierSecurityProfile::IrohQuicV1).await;
        let mut provisioner = ClassicalProvisioner::from_seed([0x82; 32], 23).expect("provisioner");
        let initiator = issue_classical(&mut provisioner, 1);
        let responder = issue_classical(&mut provisioner, 2);
        let profile = provisioner.verified_security_profile();
        let initiator_peer = MissionPeerBinding::new(server.id(), responder.identity());
        let responder_peer = MissionPeerBinding::new(client.id(), initiator.identity());
        let allowed = BTreeSet::from([client.id()]);
        let server_task = tokio::spawn({
            let server = server.clone();
            let responder = responder.clone();
            async move {
                let connection = server.accept(&allowed).await.expect("accept carrier");
                let mut session =
                    respond_classical_over_iroh(connection, &responder, responder_peer)
                        .await
                        .expect("respond classical");
                assert_eq!(session.local_identity(), responder.identity());
                assert_eq!(session.peer(), responder_peer);
                assert_eq!(session.verified_security_profile(), profile);
                assert_eq!(session.verified_security_profile().policy_generation(), 23);
                assert_eq!(
                    session.connection().security_profile(),
                    CarrierSecurityProfile::IrohQuicV1
                );
                assert!(
                    session
                        .connection()
                        .respond_once(|raw| {
                            assert_eq!(raw, b"raw-quic-ping");
                            Ok((b"raw-quic-pong".to_vec(), true))
                        })
                        .await
                        .expect("raw QUIC response")
                );
                let session_id = session.session_id();
                session.close();
                session_id
            }
        });

        let connection = client
            .connect(ExpectedPeer {
                id: server.id(),
                address: loopback(&server),
            })
            .await
            .expect("connect carrier");
        let mut session = initiate_classical_over_iroh(connection, &initiator, initiator_peer)
            .await
            .expect("initiate classical");
        assert_eq!(session.local_identity(), initiator.identity());
        assert_eq!(session.peer(), initiator_peer);
        assert_eq!(session.verified_security_profile(), profile);
        let session_id = session.session_id();
        assert_eq!(
            session
                .connection()
                .request(b"raw-quic-ping")
                .await
                .expect("raw QUIC request"),
            b"raw-quic-pong"
        );
        session.close();
        assert_eq!(server_task.await.expect("server task"), session_id);
        client.close().await;
        server.close().await;
    }

    async fn assert_classical_handshake_fails(
        initiator: UnprotectedClassicalMission,
        responder: UnprotectedClassicalMission,
        initiator_expected_mission: NodeId,
    ) {
        let mut config = EndpointConfig::direct("127.0.0.1:0".parse().expect("address"));
        config.connect_timeout = Duration::from_secs(2);
        config.exchange_timeout = Duration::from_secs(2);
        let server = Endpoint::bind_with_security_profile(
            SecretKey::generate(),
            config,
            CarrierSecurityProfile::IrohQuicV1,
        )
        .await
        .expect("server");
        let client = Endpoint::bind_with_security_profile(
            SecretKey::generate(),
            config,
            CarrierSecurityProfile::IrohQuicV1,
        )
        .await
        .expect("client");
        let allowed = BTreeSet::from([client.id()]);
        let responder_peer = MissionPeerBinding::new(client.id(), initiator.identity());
        let server_task = tokio::spawn({
            let server = server.clone();
            async move {
                let connection = server.accept(&allowed).await.expect("accept carrier");
                respond_classical_over_iroh(connection, &responder, responder_peer).await
            }
        });
        let connection = client
            .connect(ExpectedPeer {
                id: server.id(),
                address: loopback(&server),
            })
            .await
            .expect("connect carrier");
        let initiator_result = initiate_classical_over_iroh(
            connection,
            &initiator,
            MissionPeerBinding::new(server.id(), initiator_expected_mission),
        )
        .await;
        assert!(initiator_result.is_err());
        assert!(server_task.await.expect("server task").is_err());
        client.close().await;
        server.close().await;
    }

    #[tokio::test]
    async fn classical_channel_binding_rejects_policy_generation_and_peer_context_tamper() {
        let mut generation_31 =
            ClassicalProvisioner::from_seed([0x83; 32], 31).expect("generation 31");
        let mut generation_32 =
            ClassicalProvisioner::from_seed([0x83; 32], 32).expect("generation 32");
        let initiator = issue_classical(&mut generation_31, 1);
        let responder_wrong_generation = issue_classical(&mut generation_32, 2);
        let wrong_generation_identity = responder_wrong_generation.identity();
        assert_classical_handshake_fails(
            initiator.clone(),
            responder_wrong_generation,
            wrong_generation_identity,
        )
        .await;

        let responder = issue_classical(&mut generation_31, 2);
        assert_classical_handshake_fails(initiator, responder, [0x56; 32]).await;
    }

    #[tokio::test]
    async fn classical_mission_refuses_legacy_carrier_without_mixed_fallback() {
        let server = bind_carrier(CarrierSecurityProfile::HybridAsterRecordV1).await;
        let client = bind_carrier(CarrierSecurityProfile::HybridAsterRecordV1).await;
        let mut provisioner = ClassicalProvisioner::from_seed([0x84; 32], 41).expect("provisioner");
        let initiator = issue_classical(&mut provisioner, 1);
        let responder = issue_classical(&mut provisioner, 2);
        let initiator_peer = MissionPeerBinding::new(server.id(), responder.identity());
        let allowed = BTreeSet::from([client.id()]);
        let responder_peer = MissionPeerBinding::new(client.id(), initiator.identity());
        let server_task = tokio::spawn({
            let server = server.clone();
            async move {
                let connection = server
                    .accept(&allowed)
                    .await
                    .expect("accept legacy carrier");
                respond_classical_over_iroh(connection, &responder, responder_peer).await
            }
        });
        let connection = client
            .connect(ExpectedPeer {
                id: server.id(),
                address: loopback(&server),
            })
            .await
            .expect("connect legacy carrier");
        let initiator_result =
            initiate_classical_over_iroh(connection, &initiator, initiator_peer).await;
        assert!(matches!(
            initiator_result,
            Err(MissionSessionError::CarrierSecurityProfileMismatch {
                required: CarrierSecurityProfile::IrohQuicV1,
                observed: CarrierSecurityProfile::HybridAsterRecordV1,
            })
        ));
        assert!(matches!(
            server_task.await.expect("server task"),
            Err(MissionSessionError::CarrierSecurityProfileMismatch {
                required: CarrierSecurityProfile::IrohQuicV1,
                observed: CarrierSecurityProfile::HybridAsterRecordV1,
            })
        ));
        client.close().await;
        server.close().await;
    }

    #[tokio::test]
    async fn discovered_hybrid_peers_bind_observed_carriers_to_authority_authenticated_identities()
    {
        let server = Endpoint::bind(
            SecretKey::generate(),
            EndpointConfig::direct("127.0.0.1:0".parse().expect("server address")),
        )
        .await
        .expect("server endpoint");
        let client = Endpoint::bind(
            SecretKey::generate(),
            EndpointConfig::direct("127.0.0.1:0".parse().expect("client address")),
        )
        .await
        .expect("client endpoint");

        let mut provisioner = ReferenceProvisioner::from_seed([0x85; 32]).expect("provisioner");
        let initiator = issue(&mut provisioner, 1);
        let responder = issue(&mut provisioner, 2);
        let initiator_identity = initiator.identity;
        let responder_identity = responder.identity;
        let client_id = client.id();
        let allowed = BTreeSet::from([client_id]);
        let server_task = tokio::spawn({
            let server = server.clone();
            async move {
                let connection = server.accept(&allowed).await.expect("accept carrier");
                let (mut session, receipt) =
                    respond_discovered_over_iroh_metered(&connection, responder.bundle())
                        .await
                        .expect("discovered responder handshake");
                assert_eq!(receipt.frames, 4);
                assert_eq!(
                    session.peer(),
                    MissionPeerBinding::new(client_id, initiator_identity)
                );
                assert!(
                    connection
                        .respond_once(|protected_ping| {
                            let ping = session
                                .open_application_frame(protected_ping)
                                .map_err(|error| CarrierError::Transport(error.to_string()))?;
                            assert_eq!(ping, b"discovered ping");
                            let protected_pong = session
                                .seal_application_frame(b"discovered pong")
                                .map_err(|error| CarrierError::Transport(error.to_string()))?;
                            Ok((protected_pong, true))
                        })
                        .await
                        .expect("discovered protected response")
                );
            }
        });

        let connection = client
            .connect(ExpectedPeer {
                id: server.id(),
                address: loopback(&server),
            })
            .await
            .expect("connect carrier");
        let (mut session, receipt) =
            initiate_discovered_over_iroh_metered(&connection, initiator.bundle())
                .await
                .expect("discovered initiator handshake");
        assert_eq!(receipt.frames, 4);
        assert_eq!(
            session.peer(),
            MissionPeerBinding::new(server.id(), responder_identity)
        );
        let protected_ping = session
            .seal_application_frame(b"discovered ping")
            .expect("protect discovered ping");
        let protected_pong = connection
            .request(&protected_ping)
            .await
            .expect("exchange discovered ping");
        assert_eq!(
            session
                .open_application_frame(&protected_pong)
                .expect("authenticate discovered pong"),
            b"discovered pong"
        );

        server_task.await.expect("server task");
        client.close().await;
        server.close().await;
    }

    #[tokio::test]
    async fn discovered_hybrid_peer_from_different_authority_is_rejected() {
        let server = Endpoint::bind(
            SecretKey::generate(),
            EndpointConfig::direct("127.0.0.1:0".parse().expect("server address")),
        )
        .await
        .expect("server endpoint");
        let client = Endpoint::bind(
            SecretKey::generate(),
            EndpointConfig::direct("127.0.0.1:0".parse().expect("client address")),
        )
        .await
        .expect("client endpoint");

        let mut initiator_authority =
            ReferenceProvisioner::from_seed([0x86; 32]).expect("initiator authority");
        let mut responder_authority =
            ReferenceProvisioner::from_seed([0x87; 32]).expect("responder authority");
        let initiator = issue(&mut initiator_authority, 1);
        let responder = issue(&mut responder_authority, 1);
        let allowed = BTreeSet::from([client.id()]);
        let server_task = tokio::spawn({
            let server = server.clone();
            async move {
                let connection = server.accept(&allowed).await.expect("accept carrier");
                respond_discovered_over_iroh_metered(&connection, responder.bundle()).await
            }
        });

        let connection = client
            .connect(ExpectedPeer {
                id: server.id(),
                address: loopback(&server),
            })
            .await
            .expect("connect carrier");
        assert!(
            initiate_discovered_over_iroh_metered(&connection, initiator.bundle())
                .await
                .is_err(),
            "a different mission authority must not yield an initiator session"
        );
        assert!(matches!(
            server_task.await.expect("server task"),
            Err(MissionSessionError::Authentication(_))
        ));

        client.close().await;
        server.close().await;
    }

    #[tokio::test]
    async fn real_iroh_connection_rejects_plaintext_and_replayed_post_handshake_frames() {
        let server = Endpoint::bind(
            SecretKey::generate(),
            EndpointConfig::direct("127.0.0.1:0".parse().expect("server address")),
        )
        .await
        .expect("server endpoint");
        let client = Endpoint::bind(
            SecretKey::generate(),
            EndpointConfig::direct("127.0.0.1:0".parse().expect("client address")),
        )
        .await
        .expect("client endpoint");

        let mut provisioner = ReferenceProvisioner::from_seed([0x40; 32]).expect("provisioner");
        let mut initiator = issue(&mut provisioner, 1);
        let mut responder = issue(&mut provisioner, 2);
        initiator.carrier = client.id();
        responder.carrier = server.id();

        let initiator_binding = binding(&initiator);
        let responder_binding = binding(&responder);
        let responder_bundle = responder.bundle();
        let allowed = BTreeSet::from([client.id()]);
        let server_task = tokio::spawn({
            let server = server.clone();
            async move {
                let connection = server.accept(&allowed).await.expect("accept carrier");
                let mut mission =
                    respond_over_iroh(&connection, responder_bundle, initiator_binding)
                        .await
                        .expect("responder mission handshake");
                assert_eq!(mission.peer(), initiator_binding);
                assert!(
                    !connection
                        .respond_once(|protected_ping| {
                            let ping = mission
                                .open_application_frame(protected_ping)
                                .map_err(|error| CarrierError::Transport(error.to_string()))?;
                            if ping != b"ping" {
                                return Err(CarrierError::Transport(
                                    "unexpected protected application request".into(),
                                ));
                            }
                            let protected_pong = mission
                                .seal_application_frame(b"pong")
                                .map_err(|error| CarrierError::Transport(error.to_string()))?;
                            Ok((protected_pong, false))
                        })
                        .await
                        .expect("protected response")
                );
                let plaintext_error = connection
                    .respond_once(|plaintext_mechanics| {
                        assert!(matches!(
                            mission.open_application_frame(plaintext_mechanics),
                            Err(MissionSessionError::Authentication(_))
                        ));
                        Err(CarrierError::Transport(
                            "plaintext mechanics frame rejected".into(),
                        ))
                    })
                    .await
                    .expect_err("plaintext must not receive a response");
                assert!(matches!(plaintext_error, CarrierError::Transport(_)));
                let replay_error = connection
                    .respond_once(|replayed_ping| {
                        assert!(matches!(
                            mission.open_application_frame(replayed_ping),
                            Err(MissionSessionError::Authentication(_))
                        ));
                        Err(CarrierError::Transport(
                            "replayed mission frame rejected".into(),
                        ))
                    })
                    .await
                    .expect_err("replay must not receive a response");
                assert!(matches!(replay_error, CarrierError::Transport(_)));
                connection.close();
            }
        });

        let connection = client
            .connect(ExpectedPeer {
                id: server.id(),
                address: loopback(&server),
            })
            .await
            .expect("connect carrier");
        let mut mission = initiate_over_iroh(&connection, initiator.bundle(), responder_binding)
            .await
            .expect("initiator mission handshake");
        assert_eq!(mission.peer(), responder_binding);
        let protected_ping = mission
            .seal_application_frame(b"ping")
            .expect("protect ping");
        let protected_pong = connection
            .request(&protected_ping)
            .await
            .expect("exchange protected ping");
        assert_eq!(
            mission
                .open_application_frame(&protected_pong)
                .expect("authenticate pong"),
            b"pong"
        );
        let plaintext_finish = Frame::Finish {
            direction: EventDirection::ToSessionResponder,
        }
        .encode()
        .expect("encode plaintext mechanics");
        if let Ok(response) = connection.request(&plaintext_finish).await {
            assert!(
                mission.open_application_frame(&response).is_err(),
                "plaintext mechanics unexpectedly received an authenticated response"
            );
        }
        if let Ok(response) = connection.request(&protected_ping).await {
            assert!(
                mission.open_application_frame(&response).is_err(),
                "replayed application frame unexpectedly received an authenticated response"
            );
        }

        server_task.await.expect("server task");
        client.close().await;
        server.close().await;
    }

    #[test]
    fn four_flights_gate_bidirectional_replay_protected_application_frames() {
        let mut provisioner = ReferenceProvisioner::from_seed([0x41; 32]).expect("provisioner");
        let initiator = issue(&mut provisioner, 1);
        let responder = issue(&mut provisioner, 2);
        let (mut initiator_session, mut responder_session) =
            establish(&initiator, &responder).expect("establish session");

        assert_eq!(initiator_session.peer(), binding(&responder));
        assert_eq!(responder_session.peer(), binding(&initiator));
        assert_eq!(
            initiator_session.semantic_version(),
            responder_session.semantic_version()
        );

        let frame = initiator_session
            .seal_application_frame(b"ping")
            .expect("seal ping");
        assert_eq!(
            responder_session
                .open_application_frame(&frame)
                .expect("open ping"),
            b"ping"
        );
        assert!(matches!(
            responder_session.open_application_frame(&frame),
            Err(MissionSessionError::Authentication(_))
        ));

        let reverse = responder_session
            .seal_application_frame(b"pong")
            .expect("seal pong");
        let mut tampered = reverse.clone();
        let last = tampered.last_mut().expect("protected frame is nonempty");
        *last ^= 1;
        assert!(matches!(
            initiator_session.open_application_frame(&tampered),
            Err(MissionSessionError::Authentication(_))
        ));
        assert_eq!(
            initiator_session
                .open_application_frame(&reverse)
                .expect("valid frame remains acceptable after tamper"),
            b"pong"
        );
    }

    #[test]
    fn carrier_and_mission_identities_are_independent_exact_checks() {
        let mut provisioner = ReferenceProvisioner::from_seed([0x42; 32]).expect("provisioner");
        let initiator = issue(&mut provisioner, 1);
        let responder = issue(&mut provisioner, 2);
        let other = issue(&mut provisioner, 3);

        let wrong_carrier =
            MissionSessionInitiator::start(initiator.bundle(), binding(&responder), other.carrier);
        assert!(matches!(
            wrong_carrier,
            Err(MissionSessionError::CarrierIdentityMismatch { .. })
        ));

        let wrong_mission_binding = MissionPeerBinding::new(responder.carrier, other.identity);
        let (initiator_state, first) = MissionSessionInitiator::start(
            initiator.bundle(),
            wrong_mission_binding,
            responder.carrier,
        )
        .expect("carrier identity is independently correct");
        let responder_state = MissionSessionResponder::open(
            responder.bundle(),
            binding(&initiator),
            initiator.carrier,
        )
        .expect("responder open");
        let (responder_pending, second) = responder_state
            .receive_client(first.as_bytes())
            .expect("first flight");
        let (initiator_pending, third) = initiator_state
            .receive_server(second.as_bytes())
            .expect("second flight");
        let (_responder_session, fourth) = responder_pending
            .receive_client_auth(third.as_bytes())
            .expect("third flight");
        assert!(matches!(
            initiator_pending.receive_finished(fourth.as_bytes()),
            Err(MissionSessionError::MissionIdentityMismatch {
                expected,
                authenticated,
            }) if expected == other.identity && authenticated == responder.identity
        ));

        let (initiator_state, first) = MissionSessionInitiator::start(
            initiator.bundle(),
            binding(&responder),
            responder.carrier,
        )
        .expect("initiator start");
        let responder_state = MissionSessionResponder::open(
            responder.bundle(),
            MissionPeerBinding::new(initiator.carrier, other.identity),
            initiator.carrier,
        )
        .expect("carrier identity is independently correct");
        let (responder_pending, second) = responder_state
            .receive_client(first.as_bytes())
            .expect("first flight");
        let (_initiator_pending, third) = initiator_state
            .receive_server(second.as_bytes())
            .expect("second flight");
        assert!(matches!(
            responder_pending.receive_client_auth(third.as_bytes()),
            Err(MissionSessionError::MissionIdentityMismatch {
                expected,
                authenticated,
            }) if expected == other.identity && authenticated == initiator.identity
        ));
    }

    #[test]
    fn different_mission_and_handshake_tamper_fail_closed() {
        let mut mission_a = ReferenceProvisioner::from_seed([0x43; 32]).expect("mission A");
        let mut mission_b = ReferenceProvisioner::from_seed([0x44; 32]).expect("mission B");
        let initiator = issue(&mut mission_a, 1);
        let responder = issue(&mut mission_b, 1);

        let (initiator_state, first) = MissionSessionInitiator::start(
            initiator.bundle(),
            binding(&responder),
            responder.carrier,
        )
        .expect("initiator start");
        let responder_state = MissionSessionResponder::open(
            responder.bundle(),
            binding(&initiator),
            initiator.carrier,
        )
        .expect("responder open");
        assert!(matches!(
            responder_state.receive_client(first.as_bytes()),
            Err(MissionSessionError::Authentication(_))
        ));
        drop(initiator_state);

        let mut same_mission = ReferenceProvisioner::from_seed([0x45; 32]).expect("mission");
        let initiator = issue(&mut same_mission, 1);
        let responder = issue(&mut same_mission, 2);
        let (_initiator_state, first) = MissionSessionInitiator::start(
            initiator.bundle(),
            binding(&responder),
            responder.carrier,
        )
        .expect("initiator start");
        let responder_state = MissionSessionResponder::open(
            responder.bundle(),
            binding(&initiator),
            initiator.carrier,
        )
        .expect("responder open");
        let mut damaged = first.into_bytes();
        *damaged.last_mut().expect("flight is nonempty") ^= 1;
        assert!(matches!(
            responder_state.receive_client(&damaged),
            Err(MissionSessionError::Authentication(_))
        ));
    }

    #[test]
    fn protected_reference_bundle_invokes_provider_once_without_plaintext_fallback() {
        let mut provisioner = ReferenceProvisioner::from_seed([0x66; 32]).expect("provisioner");
        let issued = issue(&mut provisioner, 1);
        let expected_identity = issued.identity;
        let mut unprotector = TestProvisioningUnprotector::new(issued.bundle.clone());

        let mission = UnprotectedReferenceMission::from_protected_bytes(
            b"provider-authenticated-envelope",
            &mut unprotector,
        )
        .expect("open protected reference bundle");
        assert_eq!(mission.identity(), expected_identity);
        assert_eq!(
            mission.provisioning_origin(),
            MissionProvisioningOrigin::ProtectedArtifact
        );
        assert_eq!(unprotector.calls, 1);
        assert_eq!(
            unprotector.maximum_plaintext_len,
            Some(MAX_UNPROTECTED_PROVISIONING_BYTES)
        );
        assert!(matches!(
            mission.prepare_software_erasure(),
            Err(MissionProvisioningError::Artifact(
                SoftwareErasureError::NoPersistedArtifact
            ))
        ));

        let mut rejected = TestProvisioningUnprotector::new(issued.bundle.clone());
        assert!(matches!(
            UnprotectedReferenceMission::from_protected_bytes(&[], &mut rejected),
            Err(MissionProvisioningError::Protection(
                ProvisioningProtectionError::Rejected
            ))
        ));
        assert_eq!(rejected.calls, 0);
        assert!(matches!(
            UnprotectedReferenceMission::from_protected_bytes(&issued.bundle, &mut rejected),
            Err(MissionProvisioningError::Protection(
                ProvisioningProtectionError::Rejected
            ))
        ));
        assert_eq!(rejected.calls, 0);
        assert!(matches!(
            UnprotectedReferenceMission::from_protected_bytes(
                &vec![0x55; MAX_PROTECTED_PROVISIONING_BYTES + 1],
                &mut rejected,
            ),
            Err(MissionProvisioningError::Protection(
                ProvisioningProtectionError::TooLarge
            ))
        ));
        assert_eq!(rejected.calls, 0);
    }

    #[test]
    fn persistent_secret_reference_is_exactly_bound_and_not_software_erasure() {
        let mut provisioner = ReferenceProvisioner::from_seed([0x69; 32]).expect("provisioner");
        let issued = issue(&mut provisioner, 1);
        let operation = ProvisioningLoadId::new([0x6a; 32]);
        let secret_ref =
            ProvisioningSecretRef::from_opaque(b"provider-secret-handle-canary".to_vec())
                .expect("secret ref");
        let mut loader = TestProvisioningSecretLoader {
            calls: 0,
            expected_operation: operation,
            expected_ref: secret_ref.clone(),
            returned_operation: operation,
            returned_ref: secret_ref.clone(),
            plaintext: Some(issued.bundle.clone()),
        };

        let mission = UnprotectedReferenceMission::load_from_secret_store(
            &secret_ref,
            operation,
            &mut loader,
        )
        .expect("load exact persistent secret");
        assert_eq!(loader.calls, 1);
        assert_eq!(mission.identity(), issued.identity);
        assert_eq!(mission.persistent_secret_ref(), Some(&secret_ref));
        assert_eq!(
            mission.provisioning_origin(),
            MissionProvisioningOrigin::SecretReference
        );
        let clone = mission.clone();
        assert_eq!(clone.persistent_secret_ref(), Some(&secret_ref));
        assert!(Arc::ptr_eq(&mission.encoded, &clone.encoded));
        drop(clone);
        assert_eq!(mission.persistent_secret_ref(), Some(&secret_ref));
        assert!(!format!("{mission:?}").contains("provider-secret-handle-canary"));
        assert!(matches!(
            mission.prepare_software_erasure(),
            Err(MissionProvisioningError::Artifact(
                SoftwareErasureError::NoPersistedArtifact
            ))
        ));

        let other_ref =
            ProvisioningSecretRef::from_opaque(b"another-handle".to_vec()).expect("other ref");
        let mut mismatched = TestProvisioningSecretLoader {
            calls: 0,
            expected_operation: operation,
            expected_ref: secret_ref.clone(),
            returned_operation: operation,
            returned_ref: other_ref,
            plaintext: Some(issued.bundle),
        };
        assert!(matches!(
            UnprotectedReferenceMission::load_from_secret_store(
                &secret_ref,
                operation,
                &mut mismatched,
            ),
            Err(MissionProvisioningError::Protection(
                ProvisioningProtectionError::Rejected
            ))
        ));
        assert_eq!(mismatched.calls, 1);
    }

    #[cfg(unix)]
    #[test]
    fn protected_reference_file_preflight_is_bounded_regular_and_provider_first() {
        use std::os::unix::fs::{PermissionsExt as _, symlink};

        let root = std::env::temp_dir().join(format!(
            "aster-protected-mission-provisioning-{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(&root).expect("create root");

        let mut provisioner = ReferenceProvisioner::from_seed([0x67; 32]).expect("provisioner");
        let issued = issue(&mut provisioner, 1);
        let mut unprotector = TestProvisioningUnprotector::new(issued.bundle.clone());

        assert!(matches!(
            UnprotectedReferenceMission::load_protected(&root, &mut unprotector),
            Err(MissionProvisioningError::NotRegular(path)) if path == root
        ));
        assert_eq!(unprotector.calls, 0);

        let oversized = root.join("oversized.protected");
        std::fs::write(&oversized, vec![0x55; MAX_PROTECTED_PROVISIONING_BYTES + 1])
            .expect("write oversized protected artifact");
        assert!(matches!(
            UnprotectedReferenceMission::load_protected(&oversized, &mut unprotector),
            Err(MissionProvisioningError::TooLarge { .. })
        ));
        assert_eq!(unprotector.calls, 0);

        let protected = root.join("mission.protected");
        std::fs::write(&protected, b"provider-authenticated-envelope")
            .expect("write protected artifact");
        std::fs::set_permissions(&protected, std::fs::Permissions::from_mode(0o644))
            .expect("set ciphertext permissions");
        let symlink_path = root.join("mission-link.protected");
        symlink(&protected, &symlink_path).expect("create protected artifact symlink");
        assert!(matches!(
            UnprotectedReferenceMission::load_protected(&symlink_path, &mut unprotector),
            Err(MissionProvisioningError::NotRegular(path)) if path == symlink_path
        ));
        assert_eq!(unprotector.calls, 0);

        let expected_identity = issued.identity;
        let mission = UnprotectedReferenceMission::load_protected(&protected, &mut unprotector)
            .expect("load protected artifact");
        assert_eq!(mission.identity(), expected_identity);
        assert_eq!(unprotector.calls, 1);
        assert!(matches!(
            mission.prepare_software_erasure(),
            Err(MissionProvisioningError::Artifact(
                SoftwareErasureError::NoPersistedArtifact
            ))
        ));

        drop(mission);
        std::fs::remove_dir_all(root).expect("cleanup");
    }

    #[cfg(unix)]
    #[test]
    fn mission_lock_release_waits_for_clones_and_erasure_but_not_duplicate_descriptors() {
        let root = std::env::temp_dir().join(format!(
            "aster-mission-lock-lifetime-{}",
            std::process::id()
        ));
        std::fs::create_dir_all(&root).expect("create root");
        let path = root.join("mission.bundle");
        let mut provisioner = ReferenceProvisioner::from_seed([0x47; 32]).expect("provisioner");
        let mission =
            UnprotectedReferenceMission::persist(&path, issue(&mut provisioner, 1).bundle)
                .expect("persist mission");
        let identity = mission.identity();
        let clone = mission.clone();
        let duplicate = mission
            .artifact
            .as_ref()
            .expect("artifact")
            .lock()
            .expect("artifact mutex")
            .file
            .try_clone()
            .expect("duplicate descriptor");
        let assert_in_use = || {
            assert!(matches!(
                UnprotectedReferenceMission::load(&path),
                Err(MissionProvisioningError::Artifact(
                    SoftwareErasureError::InUse(_)
                ))
            ));
        };
        drop(mission);
        assert_in_use();
        let prepared = clone.prepare_software_erasure().expect("prepare erasure");
        drop(clone);
        assert_in_use();
        drop(prepared);
        // A duplicate models the shared open-file description inherited during
        // process creation, without a timing-dependent spawn race.
        let reopened = UnprotectedReferenceMission::load(&path)
            .expect("last owner releases lock despite duplicate descriptor");
        assert_eq!(reopened.identity(), identity);
        drop(duplicate);
        assert_in_use();
        drop(reopened);
        drop(UnprotectedReferenceMission::load(&path).expect("reopen again"));
        std::fs::remove_dir_all(root).expect("cleanup");
    }

    #[cfg(unix)]
    #[test]
    fn inherited_artifact_cleanup_preserves_originating_owner_lock() {
        use std::os::unix::fs::OpenOptionsExt as _;
        let path = std::env::temp_dir().join(format!(
            "aster-artifact-inherited-lock-{}",
            std::process::id()
        ));
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&path)
            .expect("create artifact");
        let owner = RetainedSecretArtifact::from_open_file(
            file,
            path.clone(),
            SoftwareSecretArtifact::CarrierIdentity,
            None,
        )
        .expect("lock artifact");
        // Model cleanup of an inherited artifact in a different process. No
        // unsafe fork is needed in the multithreaded test harness.
        let inherited = RetainedSecretArtifact {
            file: owner
                .file
                .try_clone()
                .expect("duplicate inherited descriptor"),
            lock_owner_pid: std::process::id().wrapping_add(1),
            target: owner.target.clone(),
            destroyed: false,
        };
        drop(inherited);
        assert!(matches!(
            RetainedSecretArtifact::open_existing(&path, SoftwareSecretArtifact::CarrierIdentity),
            Err(SoftwareErasureError::InUse(_))
        ));
        drop(owner);
        drop(
            RetainedSecretArtifact::open_existing(&path, SoftwareSecretArtifact::CarrierIdentity)
                .expect("reopen after owning process cleanup"),
        );
        std::fs::remove_file(path).expect("cleanup");
    }

    #[cfg(unix)]
    #[test]
    fn unprotected_reference_bundle_loader_is_bounded_regular_and_owner_only() {
        let root =
            std::env::temp_dir().join(format!("aster-mission-provisioning-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(&root).expect("create root");

        assert!(matches!(
            UnprotectedReferenceMission::load(root.join("missing.bundle")),
            Err(MissionProvisioningError::Io(error))
                if error.kind() == io::ErrorKind::NotFound
        ));
        assert!(matches!(
            UnprotectedReferenceMission::load(&root),
            Err(MissionProvisioningError::NotRegular(path)) if path == root
        ));

        let oversized = root.join("oversized.bundle");
        std::fs::write(
            &oversized,
            vec![0x55; MAX_UNPROTECTED_PROVISIONING_BYTES + 1],
        )
        .expect("write oversized");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            std::fs::set_permissions(&oversized, std::fs::Permissions::from_mode(0o600))
                .expect("chmod oversized");
        }
        assert!(matches!(
            UnprotectedReferenceMission::load(&oversized),
            Err(MissionProvisioningError::TooLarge { .. })
        ));

        let mut provisioner = ReferenceProvisioner::from_seed([0x46; 32]).expect("provisioner");
        let issued = issue(&mut provisioner, 1);
        let persisted = root.join("valid.bundle");
        let expected = UnprotectedReferenceMission::persist(&persisted, issued.bundle)
            .expect("persist owner-only bundle");
        let expected_identity = expected.identity();
        assert!(matches!(
            UnprotectedReferenceMission::load(&persisted),
            Err(MissionProvisioningError::Artifact(
                SoftwareErasureError::InUse(_)
            ))
        ));
        drop(expected);
        let loaded = UnprotectedReferenceMission::load(&persisted)
            .expect("load owner-only bundle after prior holder drops");
        assert_eq!(loaded.identity(), expected_identity);
        drop(loaded);

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            use std::os::unix::fs::symlink;
            let symlink_path = root.join("symlink.bundle");
            symlink(&persisted, &symlink_path).expect("create bundle symlink");
            assert!(matches!(
                UnprotectedReferenceMission::load(&symlink_path),
                Err(MissionProvisioningError::NotRegular(path)) if path == symlink_path
            ));
            std::fs::set_permissions(&persisted, std::fs::Permissions::from_mode(0o644))
                .expect("loosen permissions");
            assert!(matches!(
                UnprotectedReferenceMission::load(&persisted),
                Err(MissionProvisioningError::UnsafePermissions(path)) if path == persisted
            ));
        }

        std::fs::remove_dir_all(root).expect("cleanup");
    }

    #[cfg(unix)]
    #[test]
    fn mission_erasure_is_inode_bound_idempotent_and_invalidates_clones() {
        let root =
            std::env::temp_dir().join(format!("aster-mission-erasure-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(&root).expect("create root");
        let mut provisioner = ReferenceProvisioner::from_seed([0x47; 32]).expect("provisioner");
        let issued = issue(&mut provisioner, 7);
        let path = root.join("mission.bundle");
        let mission =
            UnprotectedReferenceMission::persist(&path, issued.bundle).expect("persist mission");
        let clone = mission.clone();
        let moved = root.join("mission.original");
        let replacement = b"operator replacement must survive";
        let mut prepared = mission
            .prepare_software_erasure()
            .expect("prepare mission erasure");
        let target = prepared.target().clone();
        let encoded = target.to_bytes();
        assert!(encoded.len() <= MAX_SOFTWARE_ERASURE_DESCRIPTOR_BYTES);
        assert_eq!(
            SoftwareErasureTarget::from_bytes(&encoded).expect("decode descriptor"),
            target
        );

        std::fs::rename(&path, &moved).expect("move exact original inode");
        std::fs::write(&path, replacement).expect("write replacement");
        let first = prepared.destroy_contents().expect("destroy exact inode");
        assert!(first.bounded_software_erasure());
        assert!(!first.physical_media_sanitized());
        assert_eq!(first.bytes_overwritten(), target.original_len());
        assert!(!first.already_destroyed());
        assert!(
            prepared
                .destroy_contents()
                .expect("repeat destruction")
                .already_destroyed()
        );
        assert_eq!(std::fs::metadata(&moved).expect("moved inode").len(), 0);
        assert_eq!(std::fs::read(&path).expect("replacement"), replacement);
        assert!(clone.fresh_bundle().is_err());

        drop(prepared);
        drop(clone);
        drop(mission);
        std::fs::remove_dir_all(root).expect("cleanup");
    }

    #[cfg(unix)]
    #[test]
    fn pending_erasure_resumes_same_zero_length_inode_without_parsing_credentials() {
        let root =
            std::env::temp_dir().join(format!("aster-mission-resume-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(&root).expect("create root");
        let mut provisioner = ReferenceProvisioner::from_seed([0x48; 32]).expect("provisioner");
        let path = root.join("mission.bundle");
        let mission =
            UnprotectedReferenceMission::persist(&path, issue(&mut provisioner, 8).bundle)
                .expect("persist mission");
        let mut prepared = mission.prepare_software_erasure().expect("prepare");
        let target = prepared.target().clone();
        let mut truncated_descriptor = target.to_bytes();
        truncated_descriptor.pop();
        assert!(matches!(
            SoftwareErasureTarget::from_bytes(&truncated_descriptor),
            Err(SoftwareErasureError::InvalidDescriptor)
        ));
        prepared
            .destroy_contents()
            .expect("simulate destroy before phase flag");
        drop(prepared);
        drop(mission);

        let mut resumed = target
            .resume_pending()
            .expect("same zero-length inode resumes");
        let receipt = resumed
            .destroy_contents()
            .expect("repeat exact destruction");
        assert_eq!(receipt.bytes_overwritten(), 0);
        drop(resumed);
        assert_eq!(
            std::fs::metadata(&path).expect("retained tombstone").len(),
            0
        );
        std::fs::remove_file(&path).expect("simulate external pathname removal");
        assert!(matches!(
            target.resume_pending(),
            Err(SoftwareErasureError::Indeterminate(_))
        ));
        std::fs::remove_dir_all(root).expect("cleanup");
    }

    #[cfg(unix)]
    #[test]
    fn mission_preflight_rejects_hardlinks_permissions_and_path_replacement() {
        use std::os::unix::fs::PermissionsExt as _;

        let root =
            std::env::temp_dir().join(format!("aster-mission-preflight-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(&root).expect("create root");
        let mut provisioner = ReferenceProvisioner::from_seed([0x49; 32]).expect("provisioner");
        let path = root.join("mission.bundle");
        let mission =
            UnprotectedReferenceMission::persist(&path, issue(&mut provisioner, 9).bundle)
                .expect("persist mission");

        let hardlink = root.join("mission.hardlink");
        std::fs::hard_link(&path, &hardlink).expect("hardlink");
        assert!(matches!(
            mission.prepare_software_erasure(),
            Err(MissionProvisioningError::Artifact(
                SoftwareErasureError::SharedLinks { links: 2, .. }
            ))
        ));
        std::fs::remove_file(hardlink).expect("remove hardlink");

        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o640))
            .expect("loose permissions");
        assert!(matches!(
            mission.prepare_software_erasure(),
            Err(MissionProvisioningError::Artifact(
                SoftwareErasureError::UnsafePermissions(_)
            ))
        ));
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))
            .expect("restore permissions");

        let prepared = mission
            .prepare_software_erasure()
            .expect("safe preflight before replacement");
        let target = prepared.target().clone();
        drop(prepared);
        let original = root.join("mission.original");
        std::fs::rename(&path, &original).expect("replace path");
        std::fs::write(&path, b"replacement").expect("replacement");
        assert!(mission.prepare_software_erasure().is_err());
        assert!(matches!(
            target.resume_pending(),
            Err(SoftwareErasureError::Indeterminate(_))
        ));
        assert_eq!(
            std::fs::read(&path).expect("replacement retained"),
            b"replacement"
        );

        drop(mission);
        std::fs::remove_dir_all(root).expect("cleanup");
    }

    #[cfg(unix)]
    #[test]
    fn basename_provisioning_path_syncs_the_current_directory() {
        sync_parent_directory(Path::new("mission.bundle"))
            .expect("basename path must resolve its parent to the current directory");
        let absolute = absolute_artifact_path(Path::new("mission.bundle"))
            .expect("basename path becomes durable absolute descriptor path");
        assert!(absolute.is_absolute());
        assert!(absolute.ends_with("mission.bundle"));
    }

    #[cfg(not(unix))]
    #[test]
    fn unprotected_reference_bundle_files_fail_closed_without_owner_only_permissions() {
        let path = PathBuf::from("mission.bundle");
        assert!(matches!(
            UnprotectedReferenceMission::load(&path),
            Err(MissionProvisioningError::OwnerOnlyPermissionsUnavailable(error_path))
                if error_path == path
        ));
        assert!(matches!(
            UnprotectedReferenceMission::persist(&path, Vec::new()),
            Err(MissionProvisioningError::OwnerOnlyPermissionsUnavailable(error_path))
                if error_path == path
        ));
    }
}
