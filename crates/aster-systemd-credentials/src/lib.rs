//! Ubuntu systemd credential store provider for Aster provisioning.

#![forbid(unsafe_code)]

use aster_mesh::{
    MAX_UNPROTECTED_PROVISIONING_BYTES, ProfileProvisioningBundle, ProvisioningLoadId,
    ProvisioningLoadReceipt, ProvisioningSecretLoader, ProvisioningSecretRef,
    ProvisioningSecretStoreError, UnprotectedProvisioning,
};
use zeroize::Zeroizing;

#[cfg(target_os = "linux")]
use std::{
    env,
    fs::File,
    io::Read as _,
    os::fd::OwnedFd,
    path::{Component, Path},
};

/// Stable identity of the selected D06 provider contract.
pub const PROVIDER_CONTRACT: &str = "aster-systemd-credential-store/v1";

/// Fixed systemd service credential consumed by the Aster agent.
pub const CREDENTIAL_NAME: &str = "aster-provisioning.bundle";

/// Exact size of the random identity in a v1 provider reference.
pub const PROVIDER_REFERENCE_ID_BYTES: usize = 32;

const PROVIDER_REFERENCE_MAGIC: &[u8; 8] = b"ASTRSDRF";
const PROVIDER_REFERENCE_VERSION: u16 = 1;
const PROVIDER_REFERENCE_HEADER_BYTES: usize = 8 + 2 + 2 + 8;
const PROVIDER_REFERENCE_OPAQUE_BYTES: usize =
    PROVIDER_REFERENCE_HEADER_BYTES + PROVIDER_REFERENCE_ID_BYTES;
const ASTER_REFERENCE_HEADER_BYTES: usize = 8 + 2 + 4;
const PROVIDER_SECRET_REF_BYTES: usize =
    ASTER_REFERENCE_HEADER_BYTES + PROVIDER_REFERENCE_OPAQUE_BYTES;

const CREDENTIAL_ENVELOPE_MAGIC: &[u8; 8] = b"ASTRSDCE";
const CREDENTIAL_ENVELOPE_VERSION: u16 = 1;
const CREDENTIAL_ENVELOPE_HEADER_BYTES: usize = 8 + 2 + 2 + 8 + 32 + 4 + 4;

/// Maximum exact v1 provider-envelope size accepted from systemd.
pub const MAX_CREDENTIAL_ENVELOPE_BYTES: usize = CREDENTIAL_ENVELOPE_HEADER_BYTES
    + PROVIDER_SECRET_REF_BYTES
    + MAX_UNPROTECTED_PROVISIONING_BYTES;

#[cfg(target_os = "linux")]
const CREDENTIALS_DIRECTORY_ENV: &str = "CREDENTIALS_DIRECTORY";

#[cfg(target_os = "linux")]
const RAMFS_MAGIC: i64 = 0x8584_58f6;

#[cfg(target_os = "linux")]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum CredentialSourceError {
    Directory,
    File,
    Insecure,
    Weak,
    Changed,
    TooLarge,
}

#[cfg(target_os = "linux")]
#[derive(Clone, Copy, Eq, PartialEq)]
struct CredentialFileMetadata {
    regular: bool,
    owner: u32,
    mode: u32,
    links: u64,
    device: u64,
    inode: u64,
    size: i64,
    modified_seconds: i64,
    modified_nanoseconds: u64,
    changed_seconds: i64,
    changed_nanoseconds: u64,
}

#[cfg(target_os = "linux")]
impl CredentialFileMetadata {
    fn from_stat(stat: &rustix::fs::Stat) -> Self {
        Self {
            regular: rustix::fs::FileType::from_raw_mode(stat.st_mode)
                == rustix::fs::FileType::RegularFile,
            owner: stat.st_uid,
            mode: stat.st_mode & 0o7777,
            links: stat.st_nlink,
            device: stat.st_dev,
            inode: stat.st_ino,
            size: stat.st_size,
            modified_seconds: stat.st_mtime,
            modified_nanoseconds: stat.st_mtime_nsec,
            changed_seconds: stat.st_ctime,
            changed_nanoseconds: stat.st_ctime_nsec,
        }
    }
}

#[cfg(target_os = "linux")]
enum CredentialSource {
    Runtime(OwnedFd),
    #[cfg(test)]
    Test(Option<Zeroizing<Vec<u8>>>),
}

/// Runtime loader for the selected Ubuntu systemd service credential.
///
/// Construction and loading retain only open descriptors and fixed error
/// categories. The credential path, envelope, reference, operation identity,
/// and plaintext are never included in diagnostics.
#[cfg(target_os = "linux")]
pub struct SystemdCredentialLoader {
    source: CredentialSource,
    consumed: bool,
}

#[cfg(target_os = "linux")]
impl SystemdCredentialLoader {
    /// Opens the exact directory supplied by PID 1 in
    /// `CREDENTIALS_DIRECTORY`, refusing absent, relative, traversing, or
    /// symlinked paths.
    pub fn from_environment() -> Result<Self, ProvisioningSecretStoreError> {
        let path = env::var_os(CREDENTIALS_DIRECTORY_ENV)
            .ok_or(ProvisioningSecretStoreError::Unavailable)?;
        let directory =
            open_credential_directory(Path::new(&path)).map_err(map_credential_source_error)?;
        Ok(Self {
            source: CredentialSource::Runtime(directory),
            consumed: false,
        })
    }

    #[cfg(test)]
    fn from_test_envelope(encoded: Zeroizing<Vec<u8>>) -> Self {
        Self {
            source: CredentialSource::Test(Some(encoded)),
            consumed: false,
        }
    }

    #[cfg(test)]
    fn from_directory_for_test(path: &Path) -> Result<Self, ProvisioningSecretStoreError> {
        let directory = open_credential_directory(path).map_err(map_credential_source_error)?;
        Ok(Self {
            source: CredentialSource::Runtime(directory),
            consumed: false,
        })
    }

    fn read_once(&mut self) -> Result<Zeroizing<Vec<u8>>, ProvisioningSecretStoreError> {
        if self.consumed {
            return Err(ProvisioningSecretStoreError::OperationConflict);
        }
        self.consumed = true;
        match &mut self.source {
            CredentialSource::Runtime(directory) => {
                read_runtime_credential(directory).map_err(map_credential_source_error)
            }
            #[cfg(test)]
            CredentialSource::Test(encoded) => encoded
                .take()
                .ok_or(ProvisioningSecretStoreError::OperationConflict),
        }
    }
}

#[cfg(not(target_os = "linux"))]
impl ProvisioningSecretLoader for SystemdCredentialLoader {
    fn load(
        &mut self,
        _operation: ProvisioningLoadId,
        _secret_ref: &ProvisioningSecretRef,
    ) -> Result<ProvisioningLoadReceipt, ProvisioningSecretStoreError> {
        Err(ProvisioningSecretStoreError::Unavailable)
    }
}

#[cfg(target_os = "linux")]
impl ProvisioningSecretLoader for SystemdCredentialLoader {
    fn load(
        &mut self,
        operation: ProvisioningLoadId,
        secret_ref: &ProvisioningSecretRef,
    ) -> Result<ProvisioningLoadReceipt, ProvisioningSecretStoreError> {
        let encoded = self.read_once()?;
        decode_credential_envelope(encoded, operation, secret_ref)
    }
}

#[cfg(target_os = "linux")]
fn open_credential_directory(path: &Path) -> Result<OwnedFd, CredentialSourceError> {
    if !path.is_absolute()
        || path
            .components()
            .any(|component| matches!(component, Component::CurDir | Component::ParentDir))
    {
        return Err(CredentialSourceError::Directory);
    }
    rustix::fs::openat2(
        rustix::fs::CWD,
        path,
        rustix::fs::OFlags::RDONLY
            | rustix::fs::OFlags::DIRECTORY
            | rustix::fs::OFlags::CLOEXEC
            | rustix::fs::OFlags::NOFOLLOW,
        rustix::fs::Mode::empty(),
        rustix::fs::ResolveFlags::NO_SYMLINKS | rustix::fs::ResolveFlags::NO_MAGICLINKS,
    )
    .map_err(|_| CredentialSourceError::Directory)
}

#[cfg(target_os = "linux")]
fn read_runtime_credential(
    directory: &OwnedFd,
) -> Result<Zeroizing<Vec<u8>>, CredentialSourceError> {
    let descriptor = rustix::fs::openat(
        directory,
        CREDENTIAL_NAME,
        rustix::fs::OFlags::RDONLY
            | rustix::fs::OFlags::CLOEXEC
            | rustix::fs::OFlags::NOFOLLOW
            | rustix::fs::OFlags::NONBLOCK,
        rustix::fs::Mode::empty(),
    )
    .map_err(|error| {
        if error == rustix::io::Errno::LOOP {
            CredentialSourceError::Insecure
        } else {
            CredentialSourceError::File
        }
    })?;
    let mut file = File::from(descriptor);
    let before = CredentialFileMetadata::from_stat(
        &rustix::fs::fstat(&file).map_err(|_| CredentialSourceError::File)?,
    );
    let filesystem = rustix::fs::fstatfs(&file).map_err(|_| CredentialSourceError::File)?;
    validate_credential_metadata(
        &before,
        rustix::process::geteuid().as_raw(),
        filesystem.f_type as i64,
    )?;
    let declared = usize::try_from(before.size).map_err(|_| CredentialSourceError::TooLarge)?;
    if declared > MAX_CREDENTIAL_ENVELOPE_BYTES {
        return Err(CredentialSourceError::TooLarge);
    }

    let mut encoded = Zeroizing::new(Vec::with_capacity(declared));
    (&mut file)
        .take((MAX_CREDENTIAL_ENVELOPE_BYTES + 1) as u64)
        .read_to_end(&mut encoded)
        .map_err(|_| CredentialSourceError::File)?;
    if encoded.len() > MAX_CREDENTIAL_ENVELOPE_BYTES {
        return Err(CredentialSourceError::TooLarge);
    }

    let after = CredentialFileMetadata::from_stat(
        &rustix::fs::fstat(&file).map_err(|_| CredentialSourceError::File)?,
    );
    let filesystem_after = rustix::fs::fstatfs(&file).map_err(|_| CredentialSourceError::File)?;
    validate_credential_metadata(
        &after,
        rustix::process::geteuid().as_raw(),
        filesystem_after.f_type as i64,
    )?;
    if filesystem.f_type != filesystem_after.f_type || !metadata_is_stable(&before, &after) {
        return Err(CredentialSourceError::Changed);
    }
    Ok(encoded)
}

#[cfg(target_os = "linux")]
fn validate_credential_metadata(
    metadata: &CredentialFileMetadata,
    expected_owner: u32,
    filesystem_type: i64,
) -> Result<(), CredentialSourceError> {
    if !metadata.regular
        || metadata.owner != expected_owner
        || metadata.mode != 0o400
        || metadata.links != 1
    {
        return Err(CredentialSourceError::Insecure);
    }
    if filesystem_type != RAMFS_MAGIC {
        return Err(CredentialSourceError::Weak);
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn metadata_is_stable(before: &CredentialFileMetadata, after: &CredentialFileMetadata) -> bool {
    before == after
}

#[cfg(target_os = "linux")]
const fn map_credential_source_error(error: CredentialSourceError) -> ProvisioningSecretStoreError {
    match error {
        CredentialSourceError::TooLarge => ProvisioningSecretStoreError::TooLarge,
        CredentialSourceError::Directory | CredentialSourceError::File => {
            ProvisioningSecretStoreError::Unavailable
        }
        CredentialSourceError::Insecure
        | CredentialSourceError::Weak
        | CredentialSourceError::Changed => ProvisioningSecretStoreError::Rejected,
    }
}

/// Non-Linux builds are outside the selected D06 profile and always fail
/// closed before attempting to load a credential.
#[cfg(not(target_os = "linux"))]
pub struct SystemdCredentialLoader;

#[cfg(not(target_os = "linux"))]
impl SystemdCredentialLoader {
    /// Reports the unsupported platform through the fixed store taxonomy.
    pub fn from_environment() -> Result<Self, ProvisioningSecretStoreError> {
        Err(ProvisioningSecretStoreError::Unavailable)
    }
}

/// Constructs the canonical opaque reference for one provider generation.
///
/// The reference identity is caller-generated by the administration lane. A
/// zero generation is invalid and no random material is generated at runtime.
pub fn provisioning_secret_ref(
    generation: u64,
    reference_id: [u8; PROVIDER_REFERENCE_ID_BYTES],
) -> Result<ProvisioningSecretRef, ProvisioningSecretStoreError> {
    if generation == 0 {
        return Err(ProvisioningSecretStoreError::InvalidReference);
    }
    let mut opaque = Vec::with_capacity(PROVIDER_REFERENCE_OPAQUE_BYTES);
    opaque.extend_from_slice(PROVIDER_REFERENCE_MAGIC);
    opaque.extend_from_slice(&PROVIDER_REFERENCE_VERSION.to_be_bytes());
    opaque.extend_from_slice(&0_u16.to_be_bytes());
    opaque.extend_from_slice(&generation.to_be_bytes());
    opaque.extend_from_slice(&reference_id);
    ProvisioningSecretRef::from_opaque(opaque)
}

/// Encodes one canonical provider envelope for piping directly to
/// `systemd-creds encrypt` by the administration lane.
///
/// The returned buffer contains provisioning plaintext and zeroizes on drop.
pub fn encode_credential_envelope(
    secret_ref: &ProvisioningSecretRef,
    operation: ProvisioningLoadId,
    plaintext: &UnprotectedProvisioning,
) -> Result<Zeroizing<Vec<u8>>, ProvisioningSecretStoreError> {
    let generation = provider_generation(secret_ref)?;
    ProfileProvisioningBundle::from_bytes(plaintext.expose())
        .map_err(|_| ProvisioningSecretStoreError::Rejected)?;
    let encoded_ref = Zeroizing::new(secret_ref.to_bytes());
    let reference_len =
        u32::try_from(encoded_ref.len()).map_err(|_| ProvisioningSecretStoreError::TooLarge)?;
    let plaintext_len =
        u32::try_from(plaintext.len()).map_err(|_| ProvisioningSecretStoreError::TooLarge)?;
    let total_len = CREDENTIAL_ENVELOPE_HEADER_BYTES
        .checked_add(encoded_ref.len())
        .and_then(|length| length.checked_add(plaintext.len()))
        .ok_or(ProvisioningSecretStoreError::TooLarge)?;
    if total_len > MAX_CREDENTIAL_ENVELOPE_BYTES {
        return Err(ProvisioningSecretStoreError::TooLarge);
    }

    let mut encoded = Zeroizing::new(Vec::with_capacity(total_len));
    encoded.extend_from_slice(CREDENTIAL_ENVELOPE_MAGIC);
    encoded.extend_from_slice(&CREDENTIAL_ENVELOPE_VERSION.to_be_bytes());
    encoded.extend_from_slice(&0_u16.to_be_bytes());
    encoded.extend_from_slice(&generation.to_be_bytes());
    encoded.extend_from_slice(operation.as_bytes());
    encoded.extend_from_slice(&reference_len.to_be_bytes());
    encoded.extend_from_slice(&plaintext_len.to_be_bytes());
    encoded.extend_from_slice(&encoded_ref);
    encoded.extend_from_slice(plaintext.expose());
    Ok(encoded)
}

fn decode_credential_envelope(
    encoded: Zeroizing<Vec<u8>>,
    expected_operation: ProvisioningLoadId,
    expected_ref: &ProvisioningSecretRef,
) -> Result<ProvisioningLoadReceipt, ProvisioningSecretStoreError> {
    if encoded.len() > MAX_CREDENTIAL_ENVELOPE_BYTES {
        return Err(ProvisioningSecretStoreError::TooLarge);
    }
    if encoded.len() < CREDENTIAL_ENVELOPE_HEADER_BYTES
        || &encoded[..8] != CREDENTIAL_ENVELOPE_MAGIC
        || read_u16(&encoded[8..10])? != CREDENTIAL_ENVELOPE_VERSION
        || read_u16(&encoded[10..12])? != 0
    {
        return Err(ProvisioningSecretStoreError::Rejected);
    }

    let generation = read_u64(&encoded[12..20])?;
    if generation == 0 || &encoded[20..52] != expected_operation.as_bytes() {
        return Err(ProvisioningSecretStoreError::Rejected);
    }
    let reference_len = usize::try_from(read_u32(&encoded[52..56])?)
        .map_err(|_| ProvisioningSecretStoreError::Rejected)?;
    let plaintext_len = usize::try_from(read_u32(&encoded[56..60])?)
        .map_err(|_| ProvisioningSecretStoreError::Rejected)?;
    if reference_len != PROVIDER_SECRET_REF_BYTES {
        return Err(ProvisioningSecretStoreError::Rejected);
    }
    if plaintext_len > MAX_UNPROTECTED_PROVISIONING_BYTES {
        return Err(ProvisioningSecretStoreError::TooLarge);
    }
    if plaintext_len == 0 {
        return Err(ProvisioningSecretStoreError::Rejected);
    }
    let reference_end = CREDENTIAL_ENVELOPE_HEADER_BYTES
        .checked_add(reference_len)
        .ok_or(ProvisioningSecretStoreError::Rejected)?;
    let envelope_end = reference_end
        .checked_add(plaintext_len)
        .ok_or(ProvisioningSecretStoreError::Rejected)?;
    if envelope_end != encoded.len() {
        return Err(ProvisioningSecretStoreError::Rejected);
    }

    let envelope_ref = ProvisioningSecretRef::from_bytes(
        &encoded[CREDENTIAL_ENVELOPE_HEADER_BYTES..reference_end],
    )
    .map_err(|_| ProvisioningSecretStoreError::Rejected)?;
    if &envelope_ref != expected_ref
        || provider_generation(&envelope_ref)? != generation
        || provider_generation(expected_ref)? != generation
    {
        return Err(ProvisioningSecretStoreError::Rejected);
    }
    let plaintext_bytes = &encoded[reference_end..];
    ProfileProvisioningBundle::from_bytes(plaintext_bytes)
        .map_err(|_| ProvisioningSecretStoreError::Rejected)?;
    let plaintext = UnprotectedProvisioning::new(plaintext_bytes.to_vec())
        .map_err(|_| ProvisioningSecretStoreError::Rejected)?;
    Ok(ProvisioningLoadReceipt::new(
        expected_operation,
        expected_ref.clone(),
        plaintext,
    ))
}

/// Exercises the exact production envelope decoder for hostile-input testing.
#[cfg(feature = "fuzzing")]
#[doc(hidden)]
pub fn fuzz_decode_credential_envelope(
    encoded: &[u8],
    expected_operation: ProvisioningLoadId,
    expected_ref: &ProvisioningSecretRef,
) -> bool {
    decode_credential_envelope(
        Zeroizing::new(encoded.to_vec()),
        expected_operation,
        expected_ref,
    )
    .is_ok()
}

fn provider_generation(
    secret_ref: &ProvisioningSecretRef,
) -> Result<u64, ProvisioningSecretStoreError> {
    let opaque = secret_ref.expose_opaque();
    if opaque.len() != PROVIDER_REFERENCE_OPAQUE_BYTES
        || &opaque[..8] != PROVIDER_REFERENCE_MAGIC
        || read_u16(&opaque[8..10])? != PROVIDER_REFERENCE_VERSION
        || read_u16(&opaque[10..12])? != 0
    {
        return Err(ProvisioningSecretStoreError::InvalidReference);
    }
    let generation = read_u64(&opaque[12..20])?;
    if generation == 0 {
        return Err(ProvisioningSecretStoreError::InvalidReference);
    }
    Ok(generation)
}

fn read_u16(bytes: &[u8]) -> Result<u16, ProvisioningSecretStoreError> {
    bytes
        .try_into()
        .map(u16::from_be_bytes)
        .map_err(|_| ProvisioningSecretStoreError::Rejected)
}

fn read_u32(bytes: &[u8]) -> Result<u32, ProvisioningSecretStoreError> {
    bytes
        .try_into()
        .map(u32::from_be_bytes)
        .map_err(|_| ProvisioningSecretStoreError::Rejected)
}

fn read_u64(bytes: &[u8]) -> Result<u64, ProvisioningSecretStoreError> {
    bytes
        .try_into()
        .map(u64::from_be_bytes)
        .map_err(|_| ProvisioningSecretStoreError::Rejected)
}

#[cfg(all(test, target_os = "linux"))]
mod tests {
    use std::{
        fs,
        os::unix::fs::{PermissionsExt as _, symlink},
        path::Path,
        sync::atomic::{AtomicU64, Ordering},
    };

    use aster_mesh::{
        ProvisioningLoadId, ProvisioningSecretLoader, ProvisioningSecretStoreError,
        UnprotectedProvisioning,
    };
    use zeroize::Zeroizing;

    use super::{
        CredentialFileMetadata, CredentialSourceError, MAX_CREDENTIAL_ENVELOPE_BYTES,
        PROVIDER_REFERENCE_ID_BYTES, RAMFS_MAGIC, SystemdCredentialLoader,
        decode_credential_envelope, encode_credential_envelope, metadata_is_stable,
        open_credential_directory, provisioning_secret_ref, validate_credential_metadata,
    };

    const GENERATION: u64 = 7;
    const OPERATION: ProvisioningLoadId = ProvisioningLoadId::new([0x2a; 32]);
    static NEXT_FIXTURE: AtomicU64 = AtomicU64::new(0);

    #[test]
    fn envelope_round_trip_is_canonical_and_exact() {
        // Break caught: changing the provider reference/envelope layout or
        // failing to echo the exact operation/reference would make installed
        // ciphertext incompatible with the selected v1 provider contract.
        let secret_ref = provisioning_secret_ref(GENERATION, [0x5a; PROVIDER_REFERENCE_ID_BYTES])
            .expect("valid provider reference");
        let mut expected_opaque = b"ASTRSDRF".to_vec();
        expected_opaque.extend_from_slice(&1_u16.to_be_bytes());
        expected_opaque.extend_from_slice(&0_u16.to_be_bytes());
        expected_opaque.extend_from_slice(&GENERATION.to_be_bytes());
        expected_opaque.extend_from_slice(&[0x5a; PROVIDER_REFERENCE_ID_BYTES]);
        assert_eq!(secret_ref.expose_opaque(), expected_opaque);

        let bundle =
            include_bytes!("../../../bindings/testdata/non-production-provisioning.bundle");
        let plaintext = UnprotectedProvisioning::new(bundle.to_vec()).expect("test bundle");
        let encoded = encode_credential_envelope(&secret_ref, OPERATION, &plaintext)
            .expect("encode provider envelope");

        assert_eq!(&encoded[..8], b"ASTRSDCE");
        assert_eq!(&encoded[8..10], &1_u16.to_be_bytes());
        assert_eq!(&encoded[10..12], &0_u16.to_be_bytes());
        assert_eq!(&encoded[12..20], &GENERATION.to_be_bytes());
        assert_eq!(&encoded[20..52], OPERATION.as_bytes());
        assert_eq!(
            u32::from_be_bytes(encoded[52..56].try_into().expect("reference length")),
            u32::try_from(secret_ref.encoded_len()).expect("bounded reference")
        );
        assert_eq!(
            u32::from_be_bytes(encoded[56..60].try_into().expect("inner length")),
            u32::try_from(bundle.len()).expect("bounded bundle")
        );

        let receipt = decode_credential_envelope(encoded, OPERATION, &secret_ref)
            .expect("decode provider envelope");
        assert_eq!(receipt.operation(), OPERATION);
        assert_eq!(receipt.secret_ref(), &secret_ref);
        assert_eq!(receipt.plaintext().expose(), bundle);
    }

    #[test]
    fn envelope_rejects_every_noncanonical_or_mismatched_boundary() {
        // Break caught: accepting one malformed header, length, reference,
        // generation, operation, or inner bundle would release unbound or
        // noncanonical provisioning plaintext to the node.
        let secret_ref = provisioning_secret_ref(GENERATION, [0x5a; PROVIDER_REFERENCE_ID_BYTES])
            .expect("valid provider reference");
        let other_ref =
            provisioning_secret_ref(GENERATION + 1, [0x6b; PROVIDER_REFERENCE_ID_BYTES])
                .expect("other provider reference");
        let bundle =
            include_bytes!("../../../bindings/testdata/non-production-provisioning.bundle");
        let plaintext = UnprotectedProvisioning::new(bundle.to_vec()).expect("test bundle");
        let canonical = encode_credential_envelope(&secret_ref, OPERATION, &plaintext)
            .expect("canonical envelope");

        let mut cases: Vec<(&str, Zeroizing<Vec<u8>>, ProvisioningLoadId, &_)> = Vec::new();

        let mut wrong_magic = canonical.clone();
        wrong_magic[0] ^= 1;
        cases.push(("wrong magic", wrong_magic, OPERATION, &secret_ref));

        let mut wrong_version = canonical.clone();
        wrong_version[9] = 2;
        cases.push(("wrong version", wrong_version, OPERATION, &secret_ref));

        let mut reserved = canonical.clone();
        reserved[11] = 1;
        cases.push(("reserved field", reserved, OPERATION, &secret_ref));

        let mut zero_generation = canonical.clone();
        zero_generation[12..20].fill(0);
        cases.push(("zero generation", zero_generation, OPERATION, &secret_ref));

        cases.push((
            "reference mismatch",
            canonical.clone(),
            OPERATION,
            &other_ref,
        ));
        cases.push((
            "operation mismatch",
            canonical.clone(),
            ProvisioningLoadId::new([0x33; 32]),
            &secret_ref,
        ));

        let mut malformed_reference = canonical.clone();
        malformed_reference[60] ^= 1;
        cases.push((
            "noncanonical reference",
            malformed_reference,
            OPERATION,
            &secret_ref,
        ));

        let mut wrong_reference_length = canonical.clone();
        wrong_reference_length[52..56].copy_from_slice(&1_u32.to_be_bytes());
        cases.push((
            "reference length",
            wrong_reference_length,
            OPERATION,
            &secret_ref,
        ));

        let mut wrong_inner_length = canonical.clone();
        wrong_inner_length[56..60].copy_from_slice(&1_u32.to_be_bytes());
        cases.push(("inner length", wrong_inner_length, OPERATION, &secret_ref));

        let mut corrupt_inner = canonical.clone();
        let last = corrupt_inner.len() - 1;
        corrupt_inner[last] ^= 1;
        cases.push((
            "invalid inner bundle",
            corrupt_inner,
            OPERATION,
            &secret_ref,
        ));

        let mut trailing = canonical.clone();
        trailing.push(0);
        cases.push(("trailing byte", trailing, OPERATION, &secret_ref));

        for (name, encoded, operation, expected_ref) in cases {
            assert_eq!(
                decode_credential_envelope(encoded, operation, expected_ref).expect_err(name),
                ProvisioningSecretStoreError::Rejected,
                "case {name}"
            );
        }

        let oversized = Zeroizing::new(vec![0; MAX_CREDENTIAL_ENVELOPE_BYTES + 1]);
        assert_eq!(
            decode_credential_envelope(oversized, OPERATION, &secret_ref)
                .expect_err("oversized envelope"),
            ProvisioningSecretStoreError::TooLarge
        );
        assert_eq!(
            provisioning_secret_ref(0, [0x5a; PROVIDER_REFERENCE_ID_BYTES])
                .expect_err("zero generation"),
            ProvisioningSecretStoreError::InvalidReference
        );
    }

    #[test]
    fn loader_returns_the_exact_receipt_from_one_validated_credential() {
        // Break caught: bypassing the provider decoder or constructing a
        // receipt with caller-independent values would defeat the core echo
        // checks and could bind plaintext to the wrong startup request.
        let secret_ref = provisioning_secret_ref(GENERATION, [0x5a; PROVIDER_REFERENCE_ID_BYTES])
            .expect("valid provider reference");
        let bundle =
            include_bytes!("../../../bindings/testdata/non-production-provisioning.bundle");
        let plaintext = UnprotectedProvisioning::new(bundle.to_vec()).expect("test bundle");
        let encoded = encode_credential_envelope(&secret_ref, OPERATION, &plaintext)
            .expect("canonical envelope");
        let mut loader = SystemdCredentialLoader::from_test_envelope(encoded);

        let receipt = loader
            .load(OPERATION, &secret_ref)
            .expect("validated credential loads");
        assert_eq!(receipt.operation(), OPERATION);
        assert_eq!(receipt.secret_ref(), &secret_ref);
        assert_eq!(receipt.plaintext().expose(), bundle);
    }

    #[test]
    fn runtime_metadata_accepts_only_systemd_secure_classification() {
        // Break caught: accepting tmpfs, another filesystem, broader mode,
        // another owner, a non-regular inode, or a hard link would downgrade
        // systemd's `secure` credential classification.
        let valid = CredentialFileMetadata {
            regular: true,
            owner: 1001,
            mode: 0o400,
            links: 1,
            device: 2,
            inode: 3,
            size: 64,
            modified_seconds: 4,
            modified_nanoseconds: 5,
            changed_seconds: 6,
            changed_nanoseconds: 7,
        };
        validate_credential_metadata(&valid, 1001, RAMFS_MAGIC).expect("secure credential");

        let invalid = [
            CredentialFileMetadata {
                regular: false,
                ..valid
            },
            CredentialFileMetadata {
                owner: 1002,
                ..valid
            },
            CredentialFileMetadata {
                mode: 0o600,
                ..valid
            },
            CredentialFileMetadata { links: 2, ..valid },
        ];
        for metadata in invalid {
            assert_eq!(
                validate_credential_metadata(&metadata, 1001, RAMFS_MAGIC)
                    .expect_err("unsafe metadata"),
                CredentialSourceError::Insecure
            );
        }
        for filesystem in [0x0102_1994_i64, 0x794c_7630_i64] {
            assert_eq!(
                validate_credential_metadata(&valid, 1001, filesystem)
                    .expect_err("weak filesystem"),
                CredentialSourceError::Weak
            );
        }

        assert!(metadata_is_stable(&valid, &valid));
        for changed in [
            CredentialFileMetadata {
                mode: 0o000,
                ..valid
            },
            CredentialFileMetadata { device: 8, ..valid },
            CredentialFileMetadata { inode: 9, ..valid },
            CredentialFileMetadata { size: 65, ..valid },
            CredentialFileMetadata {
                modified_seconds: 10,
                ..valid
            },
            CredentialFileMetadata {
                modified_nanoseconds: 11,
                ..valid
            },
            CredentialFileMetadata {
                changed_seconds: 12,
                ..valid
            },
            CredentialFileMetadata {
                changed_nanoseconds: 13,
                ..valid
            },
        ] {
            assert!(!metadata_is_stable(&valid, &changed));
        }
    }

    #[test]
    fn credential_directory_rejects_non_absolute_traversal_and_symlinks() {
        // Break caught: ordinary path opening would let an attacker redirect
        // an ancestor or use traversal instead of the PID-1 supplied exact
        // credential directory.
        assert_eq!(
            open_credential_directory(Path::new("relative/credentials"))
                .expect_err("relative directory"),
            CredentialSourceError::Directory
        );
        assert_eq!(
            open_credential_directory(Path::new("/run/../tmp/credentials"))
                .expect_err("traversing directory"),
            CredentialSourceError::Directory
        );

        let fixture = RuntimeFixture::new();
        let link = fixture.root.with_extension("link");
        symlink(&fixture.root, &link).expect("credential directory symlink");
        assert_eq!(
            open_credential_directory(&link).expect_err("directory symlink"),
            CredentialSourceError::Directory
        );
        fs::remove_file(link).expect("remove directory symlink");
    }

    #[test]
    fn runtime_source_rejects_ordinary_or_unsafe_credential_files() {
        // Break caught: using an ordinary file as a successful credential
        // would silently accept systemd's `weak` classification on tmpfs/ext4.
        let fixture = RuntimeFixture::new();
        fixture.write_credential(&[0; 64], 0o400);
        let mut loader = SystemdCredentialLoader::from_directory_for_test(&fixture.root)
            .expect("open fixture directory");
        let secret_ref = provisioning_secret_ref(GENERATION, [0x5a; PROVIDER_REFERENCE_ID_BYTES])
            .expect("valid provider reference");
        assert_eq!(
            loader
                .load(OPERATION, &secret_ref)
                .expect_err("weak storage"),
            ProvisioningSecretStoreError::Rejected
        );

        fixture.replace_credential_with_symlink();
        let mut loader = SystemdCredentialLoader::from_directory_for_test(&fixture.root)
            .expect("open fixture directory");
        assert_eq!(
            loader
                .load(OPERATION, &secret_ref)
                .expect_err("final symlink"),
            ProvisioningSecretStoreError::Rejected
        );

        fixture.replace_credential_with_directory();
        let mut loader = SystemdCredentialLoader::from_directory_for_test(&fixture.root)
            .expect("open fixture directory");
        assert_eq!(
            loader
                .load(OPERATION, &secret_ref)
                .expect_err("non-regular"),
            ProvisioningSecretStoreError::Rejected
        );
    }

    struct RuntimeFixture {
        root: std::path::PathBuf,
    }

    impl RuntimeFixture {
        fn new() -> Self {
            let serial = NEXT_FIXTURE.fetch_add(1, Ordering::Relaxed);
            let root = std::env::temp_dir().join(format!(
                "aster-systemd-credential-test-{}-{serial}",
                std::process::id()
            ));
            fs::create_dir(&root).expect("create credential fixture");
            fs::set_permissions(&root, fs::Permissions::from_mode(0o700))
                .expect("protect credential fixture");
            Self { root }
        }

        fn credential(&self) -> std::path::PathBuf {
            self.root.join(super::CREDENTIAL_NAME)
        }

        fn write_credential(&self, bytes: &[u8], mode: u32) {
            fs::write(self.credential(), bytes).expect("write credential");
            fs::set_permissions(self.credential(), fs::Permissions::from_mode(mode))
                .expect("set credential mode");
        }

        fn replace_credential_with_symlink(&self) {
            fs::remove_file(self.credential()).expect("remove credential");
            let target = self.root.join("credential-target");
            fs::write(&target, [0; 64]).expect("write target");
            symlink(target, self.credential()).expect("credential symlink");
        }

        fn replace_credential_with_directory(&self) {
            fs::remove_file(self.credential()).expect("remove credential symlink");
            fs::create_dir(self.credential()).expect("credential directory");
        }
    }

    impl Drop for RuntimeFixture {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.root);
        }
    }
}
