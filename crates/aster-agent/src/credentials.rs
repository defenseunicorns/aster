use std::{
    error::Error,
    fmt,
    io::Read as _,
    path::Path,
    sync::{Arc, PoisonError, RwLock},
};

use aster_mesh::{
    MAX_PROVISIONING_SECRET_REF_BYTES, ProvisioningLoadId, ProvisioningSecretLoader,
    ProvisioningSecretRef,
};
use aster_node::{NodeBootstrapError, NodeConfig};
use zeroize::Zeroizing;

use crate::config::{CredentialPaths, ValidatedAgentConfig};

const MIN_CLIENT_TOKEN_BYTES: usize = 32;
const MAX_CLIENT_TOKEN_BYTES: usize = 256;
const MAX_CLIENT_TOKEN_FILE_BYTES: usize = MAX_CLIENT_TOKEN_BYTES + 2;
const BEARER_PREFIX: &[u8] = b"Bearer ";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CredentialReason {
    Changed,
    FileAccess,
    FinalSymlink,
    InvalidMissionReference,
    InvalidToken,
    NotRegular,
    Ownership,
    Permissions,
    TooLarge,
    UnsupportedPlatform,
}

impl CredentialReason {
    const fn message(self) -> &'static str {
        match self {
            Self::Changed => "credential file changed while it was read",
            Self::FileAccess => "credential file cannot be read",
            Self::FinalSymlink => "credential file must not be a final symlink",
            Self::InvalidMissionReference => "mission reference is invalid",
            Self::InvalidToken => "client token is invalid",
            Self::NotRegular => "credential file must be regular",
            Self::Ownership => "credential file ownership is invalid",
            Self::Permissions => "credential file permissions are invalid",
            Self::TooLarge => "credential file exceeds its bound",
            Self::UnsupportedPlatform => {
                "secure credential file loading is unsupported on this platform"
            }
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CredentialError {
    reason: CredentialReason,
}

impl CredentialError {
    const fn new(reason: CredentialReason) -> Self {
        Self { reason }
    }

    pub const fn reason(&self) -> CredentialReason {
        self.reason
    }
}

impl fmt::Display for CredentialError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.reason.message())
    }
}

impl Error for CredentialError {}

#[derive(Clone, Copy)]
enum CredentialFileKind {
    ClientToken,
    MissionReference,
}

#[cfg(unix)]
#[derive(Clone, Copy, Eq, PartialEq)]
struct CredentialFileMetadata {
    regular: bool,
    owner: u32,
    group: u32,
    mode: u32,
    device: u64,
    inode: u64,
    links: u64,
    size: u64,
    modified_seconds: i64,
    modified_nanoseconds: i64,
    changed_seconds: i64,
    changed_nanoseconds: i64,
}

#[cfg(unix)]
impl CredentialFileMetadata {
    fn from_metadata(metadata: &std::fs::Metadata) -> Self {
        use std::os::unix::{fs::MetadataExt as _, fs::PermissionsExt as _};

        Self {
            regular: metadata.file_type().is_file(),
            owner: metadata.uid(),
            group: metadata.gid(),
            mode: metadata.permissions().mode() & 0o7777,
            device: metadata.dev(),
            inode: metadata.ino(),
            links: metadata.nlink(),
            size: metadata.size(),
            modified_seconds: metadata.mtime(),
            modified_nanoseconds: metadata.mtime_nsec(),
            changed_seconds: metadata.ctime(),
            changed_nanoseconds: metadata.ctime_nsec(),
        }
    }
}

/// Owner-provisioned credential required on every application RPC.
///
/// The credential is retained in zeroizing storage and compared in constant
/// time. Clones share one backing allocation rather than duplicating secret
/// bytes.
#[derive(Clone)]
pub struct ClientToken(Arc<Zeroizing<Vec<u8>>>);

impl ClientToken {
    pub fn from_bytes(bytes: Vec<u8>) -> Result<Self, CredentialError> {
        let bytes = Zeroizing::new(bytes);
        if !(MIN_CLIENT_TOKEN_BYTES..=MAX_CLIENT_TOKEN_BYTES).contains(&bytes.len())
            || !bytes
                .iter()
                .all(|byte| byte.is_ascii_alphanumeric() || b"-._~".contains(byte))
        {
            return Err(CredentialError::new(CredentialReason::InvalidToken));
        }

        let mut authorization =
            Zeroizing::new(Vec::with_capacity(BEARER_PREFIX.len() + bytes.len()));
        authorization.extend_from_slice(BEARER_PREFIX);
        authorization.extend_from_slice(&bytes);
        Ok(Self(Arc::new(authorization)))
    }

    pub fn load(path: impl AsRef<Path>) -> Result<Self, CredentialError> {
        let mut bytes = read_owner_only_bounded(
            path.as_ref(),
            MAX_CLIENT_TOKEN_FILE_BYTES,
            CredentialFileKind::ClientToken,
        )?;
        while matches!(bytes.last(), Some(b'\n' | b'\r')) {
            bytes.pop();
        }
        Self::from_bytes(std::mem::take(&mut *bytes))
    }

    pub(crate) fn authorizes(&self, provided: Option<&[u8]>) -> bool {
        use subtle::ConstantTimeEq as _;

        let Some(provided) = provided else {
            return false;
        };
        provided.len() == self.0.len() && self.0.as_slice().ct_eq(provided).into()
    }
}

#[derive(Clone)]
pub struct ReloadableClientToken(Arc<RwLock<ClientToken>>);

impl ReloadableClientToken {
    pub fn new(token: ClientToken) -> Self {
        Self(Arc::new(RwLock::new(token)))
    }

    pub fn authorizes(&self, provided: Option<&[u8]>) -> bool {
        self.0
            .read()
            .unwrap_or_else(PoisonError::into_inner)
            .authorizes(provided)
    }

    pub fn reload_from(&self, path: &Path) -> Result<(), CredentialError> {
        let replacement = ClientToken::load(path)?;
        *self.0.write().unwrap_or_else(PoisonError::into_inner) = replacement;
        Ok(())
    }
}

pub struct StartupCredentials {
    pub token: ReloadableClientToken,
    pub mission_ref: ProvisioningSecretRef,
    pub mission_load: ProvisioningLoadId,
}

pub fn load_startup_credentials(
    paths: &CredentialPaths,
) -> Result<StartupCredentials, CredentialError> {
    let token = ReloadableClientToken::new(ClientToken::load(paths.client_token_file())?);
    let mission_ref = load_mission_reference(paths.mission_secret_ref_file())?;
    Ok(StartupCredentials {
        token,
        mission_ref,
        mission_load: paths.mission_load_id(),
    })
}

pub fn open_node_config<L>(
    config: &ValidatedAgentConfig,
    credentials: &StartupCredentials,
    loader: &mut L,
) -> Result<NodeConfig, NodeBootstrapError>
where
    L: ProvisioningSecretLoader + ?Sized,
{
    NodeConfig::open_secret_ref(
        config.state(),
        &credentials.mission_ref,
        credentials.mission_load,
        config.node_options(),
        loader,
    )
}

fn load_mission_reference(path: &Path) -> Result<ProvisioningSecretRef, CredentialError> {
    let bytes = read_owner_only_bounded(
        path,
        MAX_PROVISIONING_SECRET_REF_BYTES,
        CredentialFileKind::MissionReference,
    )?;
    ProvisioningSecretRef::from_bytes(&bytes)
        .map_err(|_| CredentialError::new(CredentialReason::InvalidMissionReference))
}

#[cfg(unix)]
fn read_owner_only_bounded(
    path: &Path,
    maximum: usize,
    _kind: CredentialFileKind,
) -> Result<Zeroizing<Vec<u8>>, CredentialError> {
    use std::os::unix::fs::OpenOptionsExt as _;

    let file = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(path)
        .map_err(|error| {
            if error.raw_os_error() == Some(libc::ELOOP) {
                CredentialError::new(CredentialReason::FinalSymlink)
            } else {
                CredentialError::new(CredentialReason::FileAccess)
            }
        })?;
    let before = CredentialFileMetadata::from_metadata(
        &file
            .metadata()
            .map_err(|_| CredentialError::new(CredentialReason::FileAccess))?,
    );
    validate_owner_only_metadata(&before)?;
    let declared = usize::try_from(before.size)
        .map_err(|_| CredentialError::new(CredentialReason::TooLarge))?;
    if declared > maximum {
        return Err(CredentialError::new(CredentialReason::TooLarge));
    }

    let mut bytes = Zeroizing::new(Vec::with_capacity(declared));
    (&file)
        .take((maximum + 1) as u64)
        .read_to_end(&mut bytes)
        .map_err(|_| CredentialError::new(CredentialReason::FileAccess))?;
    if bytes.len() > maximum {
        return Err(CredentialError::new(CredentialReason::TooLarge));
    }
    let after = CredentialFileMetadata::from_metadata(
        &file
            .metadata()
            .map_err(|_| CredentialError::new(CredentialReason::FileAccess))?,
    );
    validate_owner_only_metadata(&after)?;
    if !metadata_is_stable(&before, &after) {
        return Err(CredentialError::new(CredentialReason::Changed));
    }
    Ok(bytes)
}

#[cfg(unix)]
fn validate_owner_only_metadata(metadata: &CredentialFileMetadata) -> Result<(), CredentialError> {
    if !metadata.regular {
        return Err(CredentialError::new(CredentialReason::NotRegular));
    }
    if metadata.owner != rustix::process::geteuid().as_raw() {
        return Err(CredentialError::new(CredentialReason::Ownership));
    }
    if metadata.mode & !0o600 != 0 {
        return Err(CredentialError::new(CredentialReason::Permissions));
    }
    Ok(())
}

#[cfg(unix)]
fn metadata_is_stable(before: &CredentialFileMetadata, after: &CredentialFileMetadata) -> bool {
    before == after
}

#[cfg(not(unix))]
fn read_owner_only_bounded(
    _path: &Path,
    _maximum: usize,
    _kind: CredentialFileKind,
) -> Result<Zeroizing<Vec<u8>>, CredentialError> {
    Err(CredentialError::new(CredentialReason::UnsupportedPlatform))
}

#[cfg(test)]
mod tests {
    use std::{
        fs,
        path::{Path, PathBuf},
        sync::atomic::{AtomicU64, Ordering},
    };

    use super::{ClientToken, CredentialReason, ReloadableClientToken, load_mission_reference};
    #[cfg(unix)]
    use super::{CredentialFileMetadata, metadata_is_stable, validate_owner_only_metadata};
    use aster_mesh::{MAX_PROVISIONING_SECRET_REF_BYTES, ProvisioningSecretRef};

    static NEXT_FIXTURE: AtomicU64 = AtomicU64::new(0);

    #[cfg(unix)]
    #[test]
    fn mission_reference_rejects_unsafe_noncanonical_and_oversized_files() {
        // Break caught: accepting a group-readable file or final symlink would
        // allow credential substitution or disclosure outside the owner.
        let fixture = OwnerOnlyFixture::canonical_secret_ref();
        assert!(load_mission_reference(fixture.path()).is_ok());

        fs::write(
            fixture.path(),
            vec![0u8; MAX_PROVISIONING_SECRET_REF_BYTES + 1],
        )
        .expect("write oversized reference");
        assert_eq!(
            load_mission_reference(fixture.path())
                .expect_err("oversized reference must be rejected")
                .reason(),
            CredentialReason::TooLarge
        );

        let reference = ProvisioningSecretRef::from_opaque(b"customer-reference".to_vec())
            .expect("valid opaque reference")
            .to_bytes();
        let mut noncanonical = reference.clone();
        noncanonical.push(0);
        fs::write(fixture.path(), noncanonical).expect("write noncanonical reference");
        assert_eq!(
            load_mission_reference(fixture.path())
                .expect_err("noncanonical reference must be rejected")
                .reason(),
            CredentialReason::InvalidMissionReference
        );
        fs::write(fixture.path(), reference).expect("restore canonical reference");

        fixture.chmod(0o640);
        assert_eq!(
            load_mission_reference(fixture.path())
                .expect_err("group-readable reference must be rejected")
                .reason(),
            CredentialReason::Permissions
        );

        fixture.replace_with_symlink();
        assert_eq!(
            load_mission_reference(fixture.path())
                .expect_err("final symlink must be rejected")
                .reason(),
            CredentialReason::FinalSymlink
        );
    }

    #[test]
    fn failed_reload_keeps_the_old_token() {
        // Break caught: assigning an unvalidated replacement before loading
        // completes would deauthenticate all requests after a bad reload.
        let active = ReloadableClientToken::new(token(b'a'));
        let invalid = invalid_token_file();

        assert!(active.reload_from(invalid.path()).is_err());
        assert!(active.authorizes(Some(b"Bearer aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")));
    }

    #[cfg(unix)]
    #[test]
    fn credential_files_allow_only_owner_read_write_mode_and_regular_files() {
        use std::os::unix::fs::PermissionsExt as _;

        // Break caught: accepting owner-executable files violates the exact
        // 0600-or-stricter policy for either credential type.
        let reference = OwnerOnlyFixture::canonical_secret_ref();
        let token = OwnerOnlyFixture::valid_token();

        for mode in [0o700, 0o500] {
            reference.chmod(mode);
            assert_eq!(
                load_mission_reference(reference.path())
                    .expect_err("owner-executable reference must be rejected")
                    .reason(),
                CredentialReason::Permissions,
                "reference mode {mode:o}"
            );
            token.chmod(mode);
            let Err(error) = ClientToken::load(token.path()) else {
                panic!("owner-executable token must be rejected");
            };
            assert_eq!(
                error.reason(),
                CredentialReason::Permissions,
                "token mode {mode:o}"
            );
        }

        reference.chmod(0o100);
        token.chmod(0o100);
        assert!(load_mission_reference(reference.path()).is_err());
        assert!(ClientToken::load(token.path()).is_err());

        reference.chmod(0o400);
        token.chmod(0o400);
        assert!(load_mission_reference(reference.path()).is_ok());
        assert!(ClientToken::load(token.path()).is_ok());

        let directory = reference.root.join("not-a-credential-file");
        fs::create_dir(&directory).expect("create non-regular fixture");
        fs::set_permissions(&directory, fs::Permissions::from_mode(0o700))
            .expect("protect non-regular fixture");
        assert_eq!(
            load_mission_reference(&directory)
                .expect_err("directory must not be accepted as a reference")
                .reason(),
            CredentialReason::NotRegular
        );
    }

    #[test]
    fn credential_errors_redact_the_path_and_reference_bytes() {
        // Break caught: returning raw filesystem or reference-parser errors
        // would disclose a provider capability through an operator-facing log.
        let fixture = OwnerOnlyFixture::new("redaction-canary");
        let canary = b"reference-canary-must-not-escape";
        fs::write(fixture.path(), canary).expect("write malformed reference");
        #[cfg(unix)]
        fixture.chmod(0o600);

        let error = load_mission_reference(fixture.path()).expect_err("malformed reference");
        let rendered = format!("{error:?} {error}");
        assert_eq!(error.reason(), CredentialReason::InvalidMissionReference);
        assert!(!rendered.contains("reference-canary-must-not-escape"));
        assert!(!rendered.contains(&fixture.path().display().to_string()));
    }

    #[cfg(unix)]
    #[test]
    fn metadata_policy_rejects_wrong_owner_and_detects_each_stable_field_change() {
        // Break caught: omitting an ownership or before/after metadata field
        // permits a credential to be swapped or altered during secure loading.
        let before = CredentialFileMetadata {
            regular: true,
            owner: rustix::process::geteuid().as_raw(),
            group: 41,
            mode: 0o600,
            device: 1,
            inode: 2,
            links: 1,
            size: 32,
            modified_seconds: 3,
            modified_nanoseconds: 4,
            changed_seconds: 5,
            changed_nanoseconds: 6,
        };
        assert!(validate_owner_only_metadata(&before).is_ok());
        assert_eq!(
            validate_owner_only_metadata(&CredentialFileMetadata {
                owner: before.owner.wrapping_add(1),
                ..before
            })
            .expect_err("different effective owner must be rejected")
            .reason(),
            CredentialReason::Ownership
        );
        assert_eq!(
            validate_owner_only_metadata(&CredentialFileMetadata {
                regular: false,
                ..before
            })
            .expect_err("non-regular metadata must be rejected")
            .reason(),
            CredentialReason::NotRegular
        );
        for mode in [0o700, 0o500, 0o100, 0o640] {
            assert_eq!(
                validate_owner_only_metadata(&CredentialFileMetadata { mode, ..before })
                    .expect_err("mode outside the 0600 subset must be rejected")
                    .reason(),
                CredentialReason::Permissions,
                "mode {mode:o}"
            );
        }

        let changes = [
            CredentialFileMetadata {
                regular: false,
                ..before
            },
            CredentialFileMetadata {
                owner: before.owner.wrapping_add(1),
                ..before
            },
            CredentialFileMetadata {
                group: before.group + 1,
                ..before
            },
            CredentialFileMetadata {
                mode: 0o400,
                ..before
            },
            CredentialFileMetadata {
                device: before.device + 1,
                ..before
            },
            CredentialFileMetadata {
                inode: before.inode + 1,
                ..before
            },
            CredentialFileMetadata {
                links: before.links + 1,
                ..before
            },
            CredentialFileMetadata {
                size: before.size + 1,
                ..before
            },
            CredentialFileMetadata {
                modified_seconds: before.modified_seconds + 1,
                ..before
            },
            CredentialFileMetadata {
                modified_nanoseconds: before.modified_nanoseconds + 1,
                ..before
            },
            CredentialFileMetadata {
                changed_seconds: before.changed_seconds + 1,
                ..before
            },
            CredentialFileMetadata {
                changed_nanoseconds: before.changed_nanoseconds + 1,
                ..before
            },
        ];
        assert!(metadata_is_stable(&before, &before));
        for after in changes {
            assert!(!metadata_is_stable(&before, &after));
        }
    }

    fn token(byte: u8) -> ClientToken {
        ClientToken::from_bytes(vec![byte; 32]).expect("valid token")
    }

    struct OwnerOnlyFixture {
        root: PathBuf,
        path: PathBuf,
    }

    impl OwnerOnlyFixture {
        #[cfg(unix)]
        fn canonical_secret_ref() -> Self {
            use std::os::unix::fs::PermissionsExt as _;

            let fixture = Self::new("mission-reference");
            let reference = ProvisioningSecretRef::from_opaque(b"customer-reference".to_vec())
                .expect("valid opaque reference");
            fs::write(&fixture.path, reference.to_bytes()).expect("write reference fixture");
            fs::set_permissions(&fixture.path, fs::Permissions::from_mode(0o600))
                .expect("protect reference fixture");
            fixture
        }

        #[cfg(unix)]
        fn valid_token() -> Self {
            use std::os::unix::fs::PermissionsExt as _;

            let fixture = Self::new("client-token");
            fs::write(&fixture.path, b"0123456789abcdef0123456789abcdef\n")
                .expect("write token fixture");
            fs::set_permissions(&fixture.path, fs::Permissions::from_mode(0o600))
                .expect("protect token fixture");
            fixture
        }

        #[cfg(unix)]
        fn chmod(&self, mode: u32) {
            use std::os::unix::fs::PermissionsExt as _;

            fs::set_permissions(&self.path, fs::Permissions::from_mode(mode))
                .expect("change fixture permissions");
        }

        #[cfg(unix)]
        fn replace_with_symlink(&self) {
            use std::os::unix::fs::symlink;

            let target = self.root.join("reference-target");
            fs::rename(&self.path, &target).expect("move reference target");
            symlink(&target, &self.path).expect("replace reference with final symlink");
        }
    }

    impl OwnerOnlyFixture {
        fn new(label: &str) -> Self {
            let sequence = NEXT_FIXTURE.fetch_add(1, Ordering::Relaxed);
            let root = std::env::temp_dir().join(format!(
                "aster-agent-credentials-{label}-{}-{sequence}",
                std::process::id()
            ));
            fs::create_dir(&root).expect("create credential fixture root");
            Self {
                path: root.join("credential"),
                root,
            }
        }

        fn path(&self) -> &Path {
            &self.path
        }
    }

    impl Drop for OwnerOnlyFixture {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.root);
        }
    }

    fn invalid_token_file() -> OwnerOnlyFixture {
        #[cfg(unix)]
        use std::os::unix::fs::PermissionsExt as _;

        let fixture = OwnerOnlyFixture::new("invalid-token");
        fs::write(&fixture.path, b"not a valid local token").expect("write invalid token fixture");
        #[cfg(unix)]
        fs::set_permissions(&fixture.path, fs::Permissions::from_mode(0o600))
            .expect("protect invalid token fixture");
        fixture
    }
}
