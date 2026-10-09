use crate::{
    ComposeCredentialGeneration, ComposeCredentialReason, PROVIDER_CONTRACT, encode_activation,
    encode_client_token, encode_provisioning_envelope, provisioning_secret_ref,
};
use aster_mesh::{MAX_UNPROTECTED_PROVISIONING_BYTES, ProvisioningLoadId, UnprotectedProvisioning};
use serde::Serialize;
use sha2::{Digest as _, Sha256};
use std::{
    collections::BTreeMap,
    error::Error,
    fmt,
    fs::File,
    io::{Read as _, Write as _},
    path::{Component, Path},
    time::{SystemTime, UNIX_EPOCH},
};
use zeroize::{Zeroize as _, Zeroizing};

#[cfg(test)]
use std::sync::{
    Arc,
    atomic::{AtomicBool, Ordering},
};

const MANIFEST_SCHEMA: &str = "aster-compose-secret-generation/v1";
const TOKEN_FILE: &str = "aster-client-token";
const ACTIVATION_FILE: &str = "aster-mission-activation";
const ENVELOPE_FILE: &str = "aster-provisioning-bundle";
const MANIFEST_FILE: &str = "manifest.json";
const MAX_MANIFEST_BYTES: usize = 4 * 1024;
const MAX_CLIENT_TOKEN_INPUT_BYTES: usize = 258;

/// Fixed, non-sensitive reason for generation creation failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum GenerationCreateReason {
    UnsupportedPlatform,
    RootExecution,
    InvalidInput,
    TooLarge,
    InvalidBundle,
    InvalidParent,
    AlreadyExists,
    StagingIncomplete,
    Publication,
}

/// Sanitized administration error carrying no path or credential data.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct GenerationCreateError {
    reason: GenerationCreateReason,
}

impl GenerationCreateError {
    /// Returns the fixed public reason.
    pub const fn reason(&self) -> GenerationCreateReason {
        self.reason
    }
}

impl fmt::Display for GenerationCreateError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self.reason {
            GenerationCreateReason::UnsupportedPlatform => "unsupported administration platform",
            GenerationCreateReason::RootExecution => "administrator must run as non-root",
            GenerationCreateReason::InvalidInput => "credential input is invalid",
            GenerationCreateReason::TooLarge => "credential input exceeds its size limit",
            GenerationCreateReason::InvalidBundle => "credential bundle is invalid",
            GenerationCreateReason::InvalidParent => "generation parent is invalid",
            GenerationCreateReason::AlreadyExists => "credential generation already exists",
            GenerationCreateReason::StagingIncomplete => {
                "credential generation staging is incomplete"
            }
            GenerationCreateReason::Publication => "credential generation publication failed",
        })
    }
}

impl Error for GenerationCreateError {}

/// Public result of one durable immutable generation publication.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct GenerationCreateReceipt {
    generation: ComposeCredentialGeneration,
}

impl GenerationCreateReceipt {
    /// Returns the published public generation identity.
    pub const fn generation(&self) -> ComposeCredentialGeneration {
        self.generation
    }

    /// Returns the generation as 64 lowercase hexadecimal characters.
    pub fn generation_hex(&self) -> String {
        hex(self.generation.as_bytes())
    }
}

/// Creates and durably publishes one immutable credential generation.
pub fn create_generation(
    output_parent: &Path,
    token_file: &Path,
    bundle_input: impl std::io::Read,
) -> Result<GenerationCreateReceipt, GenerationCreateError> {
    #[cfg(target_os = "linux")]
    {
        create_generation_linux(output_parent, token_file, bundle_input)
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = (output_parent, token_file, bundle_input);
        Err(error(GenerationCreateReason::UnsupportedPlatform))
    }
}

#[cfg(target_os = "linux")]
fn create_generation_linux(
    output_parent: &Path,
    token_file: &Path,
    bundle_input: impl std::io::Read,
) -> Result<GenerationCreateReceipt, GenerationCreateError> {
    let effective_uid = rustix::process::geteuid().as_raw();
    let effective_gid = rustix::process::getegid().as_raw();
    if effective_uid == 0 || effective_gid == 0 {
        return Err(error(GenerationCreateReason::RootExecution));
    }
    let parameters = CreationParameters {
        effective_uid,
        effective_gid,
        generation: random_nonzero()?,
        reference: random_nonzero()?,
        operation: random_nonzero()?,
        created_at_unix_seconds: SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| error(GenerationCreateReason::Publication))?
            .as_secs(),
    };
    create_generation_with(output_parent, token_file, bundle_input, parameters, None)
}

#[cfg(target_os = "linux")]
#[derive(Clone, Copy)]
struct CreationParameters {
    effective_uid: u32,
    effective_gid: u32,
    generation: [u8; 32],
    reference: [u8; 32],
    operation: [u8; 32],
    created_at_unix_seconds: u64,
}

#[cfg(target_os = "linux")]
impl CreationParameters {
    const fn identity(self) -> EffectiveIdentity {
        EffectiveIdentity {
            uid: self.effective_uid,
            gid: self.effective_gid,
        }
    }
}

#[cfg(target_os = "linux")]
#[derive(Clone, Copy)]
struct EffectiveIdentity {
    uid: u32,
    gid: u32,
}

#[cfg(target_os = "linux")]
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
enum Boundary {
    TokenWritten,
    TokenSynced,
    ActivationWritten,
    ActivationSynced,
    EnvelopeWritten,
    EnvelopeSynced,
    ManifestWritten,
    ManifestSynced,
    StagingDirectorySynced,
    GenerationRenamed,
    ParentSynced,
}

#[cfg(target_os = "linux")]
struct FaultInjector {
    point: Option<Boundary>,
}

#[cfg(target_os = "linux")]
impl FaultInjector {
    const fn new(point: Option<Boundary>) -> Self {
        Self { point }
    }

    fn hit(
        &mut self,
        point: Boundary,
        reason: GenerationCreateReason,
    ) -> Result<(), GenerationCreateError> {
        if self.point == Some(point) {
            self.point = None;
            Err(error(reason))
        } else {
            Ok(())
        }
    }
}

#[cfg(target_os = "linux")]
fn create_generation_with(
    output_parent: &Path,
    token_file: &Path,
    bundle_input: impl std::io::Read,
    parameters: CreationParameters,
    fault: Option<Boundary>,
) -> Result<GenerationCreateReceipt, GenerationCreateError> {
    if parameters.effective_uid == 0 || parameters.effective_gid == 0 {
        return Err(error(GenerationCreateReason::RootExecution));
    }
    let mut faults = FaultInjector::new(fault);
    let parent = open_directory(output_parent, GenerationCreateReason::InvalidParent)?;
    let parent_stat =
        validate_generation_parent(&parent, parameters.effective_uid, parameters.effective_gid)?;
    let mut token_input = read_protected_input(
        token_file,
        parameters.effective_uid,
        parameters.effective_gid,
        MAX_CLIENT_TOKEN_INPUT_BYTES,
    )?;
    let bundle = read_bundle(bundle_input)?;
    let generation_bytes = parameters.generation;
    let reference_id = parameters.reference;
    let operation = ProvisioningLoadId::new(parameters.operation);
    let generation = ComposeCredentialGeneration::new(generation_bytes);
    while matches!(token_input.last(), Some(b'\n' | b'\r')) {
        token_input.pop();
    }
    let token = encode_client_token(generation, &token_input).map_err(|error| {
        if error.reason() == ComposeCredentialReason::TooLarge {
            self::error(GenerationCreateReason::TooLarge)
        } else {
            self::error(GenerationCreateReason::InvalidInput)
        }
    })?;
    let secret_ref = provisioning_secret_ref(generation, reference_id)
        .map_err(|_| error(GenerationCreateReason::InvalidBundle))?;
    let activation = encode_activation(generation, operation, &secret_ref)
        .map_err(|_| error(GenerationCreateReason::InvalidBundle))?;
    let envelope = encode_provisioning_envelope(generation, operation, &secret_ref, &bundle)
        .map_err(|_| error(GenerationCreateReason::InvalidBundle))?;

    let created_at_unix_seconds = parameters.created_at_unix_seconds;
    let generation_hex = hex(&generation_bytes);
    let staging_name = format!(".staging-{generation_hex}");
    let final_name = format!("generation-{generation_hex}");
    rustix::fs::mkdirat(&parent, staging_name.as_str(), rustix::fs::Mode::RWXU)
        .map_err(map_staging_error)?;
    let staging = open_child_directory(
        &parent,
        &staging_name,
        parameters.effective_uid,
        parameters.effective_gid,
        parent_stat.st_dev,
    )?;

    let mut files = BTreeMap::new();
    write_immutable_file(
        &staging,
        TOKEN_FILE,
        &token,
        parameters.identity(),
        Boundary::TokenWritten,
        Boundary::TokenSynced,
        &mut faults,
    )?;
    files.insert(TOKEN_FILE, evidence(&token));
    write_immutable_file(
        &staging,
        ACTIVATION_FILE,
        &activation,
        parameters.identity(),
        Boundary::ActivationWritten,
        Boundary::ActivationSynced,
        &mut faults,
    )?;
    files.insert(ACTIVATION_FILE, evidence(&activation));
    write_immutable_file(
        &staging,
        ENVELOPE_FILE,
        &envelope,
        parameters.identity(),
        Boundary::EnvelopeWritten,
        Boundary::EnvelopeSynced,
        &mut faults,
    )?;
    files.insert(ENVELOPE_FILE, evidence(&envelope));

    let manifest = GenerationManifest {
        schema: MANIFEST_SCHEMA,
        provider_contract: PROVIDER_CONTRACT,
        generation: &generation_hex,
        created_at_utc: utc_timestamp(created_at_unix_seconds)?,
        created_at_unix_seconds,
        files,
    };
    let mut manifest_bytes =
        serde_json::to_vec(&manifest).map_err(|_| error(GenerationCreateReason::Publication))?;
    manifest_bytes.push(b'\n');
    if manifest_bytes.len() > MAX_MANIFEST_BYTES {
        return Err(error(GenerationCreateReason::Publication));
    }
    write_immutable_file(
        &staging,
        MANIFEST_FILE,
        &manifest_bytes,
        parameters.identity(),
        Boundary::ManifestWritten,
        Boundary::ManifestSynced,
        &mut faults,
    )?;
    rustix::fs::fsync(&staging).map_err(|_| error(GenerationCreateReason::StagingIncomplete))?;
    rustix::fs::fchmod(&staging, rustix::fs::Mode::RUSR | rustix::fs::Mode::XUSR)
        .map_err(|_| error(GenerationCreateReason::StagingIncomplete))?;
    validate_directory(
        &staging,
        parameters.effective_uid,
        parameters.effective_gid,
        0o500,
        parent_stat.st_dev,
    )?;
    rustix::fs::fsync(&staging).map_err(|_| error(GenerationCreateReason::StagingIncomplete))?;
    faults.hit(
        Boundary::StagingDirectorySynced,
        GenerationCreateReason::StagingIncomplete,
    )?;

    rustix::fs::renameat_with(
        &parent,
        staging_name.as_str(),
        &parent,
        final_name.as_str(),
        rustix::fs::RenameFlags::NOREPLACE,
    )
    .map_err(map_publication_error)?;
    faults.hit(
        Boundary::GenerationRenamed,
        GenerationCreateReason::Publication,
    )?;
    rustix::fs::fsync(&parent).map_err(|_| error(GenerationCreateReason::Publication))?;
    faults.hit(Boundary::ParentSynced, GenerationCreateReason::Publication)?;
    Ok(GenerationCreateReceipt { generation })
}

#[cfg(target_os = "linux")]
fn validate_generation_parent(
    descriptor: &rustix::fd::OwnedFd,
    effective_uid: u32,
    effective_gid: u32,
) -> Result<rustix::fs::Stat, GenerationCreateError> {
    let stat =
        rustix::fs::fstat(descriptor).map_err(|_| error(GenerationCreateReason::InvalidParent))?;
    if rustix::fs::FileType::from_raw_mode(stat.st_mode) != rustix::fs::FileType::Directory
        || stat.st_uid != effective_uid
        || stat.st_gid != effective_gid
        || stat.st_mode & 0o7777 != 0o700
    {
        return Err(error(GenerationCreateReason::InvalidParent));
    }
    Ok(stat)
}

#[derive(Serialize)]
struct GenerationManifest<'a> {
    schema: &'static str,
    provider_contract: &'static str,
    generation: &'a str,
    created_at_utc: String,
    created_at_unix_seconds: u64,
    files: BTreeMap<&'static str, FileEvidence>,
}

#[derive(Serialize)]
struct FileEvidence {
    size: usize,
    sha256: String,
}

fn evidence(bytes: &[u8]) -> FileEvidence {
    FileEvidence {
        size: bytes.len(),
        sha256: hex(&Sha256::digest(bytes)),
    }
}

fn read_bundle(
    mut input: impl std::io::Read,
) -> Result<UnprotectedProvisioning, GenerationCreateError> {
    read_bundle_inner(
        &mut input,
        #[cfg(test)]
        None,
    )
}

#[cfg(test)]
fn read_bundle_with_observer(
    mut input: impl std::io::Read,
    observer: Arc<SecretDropObserver>,
) -> Result<UnprotectedProvisioning, GenerationCreateError> {
    read_bundle_inner(&mut input, Some(observer))
}

fn read_bundle_inner(
    mut input: impl std::io::Read,
    #[cfg(test)] observer: Option<Arc<SecretDropObserver>>,
) -> Result<UnprotectedProvisioning, GenerationCreateError> {
    let mut buffer = SensitiveInputBuffer::new(
        MAX_UNPROTECTED_PROVISIONING_BYTES + 1,
        #[cfg(test)]
        observer,
    );
    input
        .by_ref()
        .take((MAX_UNPROTECTED_PROVISIONING_BYTES + 1) as u64)
        .read_to_end(&mut buffer.bytes)
        .map_err(|_| error(GenerationCreateReason::InvalidInput))?;
    if buffer.bytes.len() > MAX_UNPROTECTED_PROVISIONING_BYTES {
        return Err(error(GenerationCreateReason::TooLarge));
    }
    UnprotectedProvisioning::new(buffer.take())
        .map_err(|_| error(GenerationCreateReason::InvalidBundle))
}

struct SensitiveInputBuffer {
    bytes: Vec<u8>,
    #[cfg(test)]
    observer: Option<Arc<SecretDropObserver>>,
}

impl SensitiveInputBuffer {
    fn new(capacity: usize, #[cfg(test)] observer: Option<Arc<SecretDropObserver>>) -> Self {
        Self {
            bytes: Vec::with_capacity(capacity),
            #[cfg(test)]
            observer,
        }
    }

    fn take(&mut self) -> Vec<u8> {
        std::mem::take(&mut self.bytes)
    }
}

impl Drop for SensitiveInputBuffer {
    fn drop(&mut self) {
        #[cfg(test)]
        let contained_plaintext = !self.bytes.is_empty();
        self.bytes.as_mut_slice().zeroize();
        #[cfg(test)]
        if let Some(observer) = &self.observer {
            observer.zeroized.store(
                contained_plaintext && self.bytes.iter().all(|byte| *byte == 0),
                Ordering::SeqCst,
            );
            observer.allocation_stable.store(
                self.bytes.capacity() == MAX_UNPROTECTED_PROVISIONING_BYTES + 1,
                Ordering::SeqCst,
            );
        }
        self.bytes.clear();
    }
}

#[cfg(test)]
#[derive(Default)]
struct SecretDropObserver {
    zeroized: AtomicBool,
    allocation_stable: AtomicBool,
}

#[cfg(target_os = "linux")]
fn read_protected_input(
    path: &Path,
    effective_uid: u32,
    effective_gid: u32,
    maximum: usize,
) -> Result<Zeroizing<Vec<u8>>, GenerationCreateError> {
    validate_absolute_path(path)?;
    let parent_path = path
        .parent()
        .ok_or_else(|| error(GenerationCreateReason::InvalidInput))?;
    let name = path
        .file_name()
        .ok_or_else(|| error(GenerationCreateReason::InvalidInput))?;
    let parent = open_directory(parent_path, GenerationCreateReason::InvalidInput)?;
    let descriptor = rustix::fs::openat(
        &parent,
        name,
        rustix::fs::OFlags::RDONLY
            | rustix::fs::OFlags::CLOEXEC
            | rustix::fs::OFlags::NOFOLLOW
            | rustix::fs::OFlags::NONBLOCK,
        rustix::fs::Mode::empty(),
    )
    .map_err(|_| error(GenerationCreateReason::InvalidInput))?;
    let before =
        rustix::fs::fstat(&descriptor).map_err(|_| error(GenerationCreateReason::InvalidInput))?;
    validate_input_metadata(&before, effective_uid, effective_gid, maximum)?;
    let declared =
        usize::try_from(before.st_size).map_err(|_| error(GenerationCreateReason::TooLarge))?;
    let mut bytes = Zeroizing::new(Vec::with_capacity(declared));
    let mut file = File::from(descriptor);
    (&mut file)
        .take((maximum + 1) as u64)
        .read_to_end(&mut bytes)
        .map_err(|_| error(GenerationCreateReason::InvalidInput))?;
    if bytes.len() > maximum {
        return Err(error(GenerationCreateReason::TooLarge));
    }
    let after =
        rustix::fs::fstat(&file).map_err(|_| error(GenerationCreateReason::InvalidInput))?;
    validate_input_metadata(&after, effective_uid, effective_gid, maximum)?;
    if metadata_identity(&before) != metadata_identity(&after) || bytes.len() != declared {
        return Err(error(GenerationCreateReason::InvalidInput));
    }
    Ok(bytes)
}

#[cfg(target_os = "linux")]
fn validate_input_metadata(
    stat: &rustix::fs::Stat,
    effective_uid: u32,
    effective_gid: u32,
    maximum: usize,
) -> Result<(), GenerationCreateError> {
    if rustix::fs::FileType::from_raw_mode(stat.st_mode) != rustix::fs::FileType::RegularFile
        || stat.st_uid != effective_uid
        || stat.st_gid != effective_gid
        || stat.st_nlink != 1
        || !matches!(stat.st_mode & 0o7777, 0o400 | 0o600)
    {
        return Err(error(GenerationCreateReason::InvalidInput));
    }
    if stat.st_size < 0 || usize::try_from(stat.st_size).map_or(true, |size| size > maximum) {
        return Err(error(GenerationCreateReason::TooLarge));
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn metadata_identity(
    stat: &rustix::fs::Stat,
) -> (u64, u64, u32, u32, u32, u64, i64, i64, u64, i64, u64) {
    (
        stat.st_dev,
        stat.st_ino,
        stat.st_uid,
        stat.st_gid,
        stat.st_mode,
        crate::secret_file::normalize_link_count(stat.st_nlink),
        stat.st_size,
        stat.st_mtime,
        stat.st_mtime_nsec,
        stat.st_ctime,
        stat.st_ctime_nsec,
    )
}

#[cfg(target_os = "linux")]
fn open_directory(
    path: &Path,
    reason: GenerationCreateReason,
) -> Result<rustix::fd::OwnedFd, GenerationCreateError> {
    validate_absolute_path(path).map_err(|_| error(reason))?;
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
    .map_err(|_| error(reason))
}

#[cfg(target_os = "linux")]
fn open_child_directory(
    parent: &rustix::fd::OwnedFd,
    name: &str,
    effective_uid: u32,
    effective_gid: u32,
    device: u64,
) -> Result<rustix::fd::OwnedFd, GenerationCreateError> {
    let descriptor = rustix::fs::openat(
        parent,
        name,
        rustix::fs::OFlags::RDONLY
            | rustix::fs::OFlags::DIRECTORY
            | rustix::fs::OFlags::CLOEXEC
            | rustix::fs::OFlags::NOFOLLOW,
        rustix::fs::Mode::empty(),
    )
    .map_err(|_| error(GenerationCreateReason::StagingIncomplete))?;
    validate_directory(&descriptor, effective_uid, effective_gid, 0o700, device)?;
    Ok(descriptor)
}

#[cfg(target_os = "linux")]
fn validate_directory(
    descriptor: &rustix::fd::OwnedFd,
    effective_uid: u32,
    effective_gid: u32,
    mode: u32,
    device: u64,
) -> Result<(), GenerationCreateError> {
    let stat = rustix::fs::fstat(descriptor)
        .map_err(|_| error(GenerationCreateReason::StagingIncomplete))?;
    if rustix::fs::FileType::from_raw_mode(stat.st_mode) != rustix::fs::FileType::Directory
        || stat.st_uid != effective_uid
        || stat.st_gid != effective_gid
        || stat.st_mode & 0o7777 != mode
        || stat.st_dev != device
    {
        return Err(error(GenerationCreateReason::StagingIncomplete));
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn write_immutable_file(
    directory: &rustix::fd::OwnedFd,
    name: &str,
    bytes: &[u8],
    identity: EffectiveIdentity,
    written: Boundary,
    synced: Boundary,
    faults: &mut FaultInjector,
) -> Result<(), GenerationCreateError> {
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
    .map_err(|_| error(GenerationCreateReason::StagingIncomplete))?;
    validate_file(&descriptor, identity.uid, identity.gid, 0o600)?;
    let mut file = File::from(descriptor);
    file.write_all(bytes)
        .map_err(|_| error(GenerationCreateReason::StagingIncomplete))?;
    faults.hit(written, GenerationCreateReason::StagingIncomplete)?;
    rustix::fs::fchmod(&file, rustix::fs::Mode::RUSR)
        .map_err(|_| error(GenerationCreateReason::StagingIncomplete))?;
    validate_file(&file, identity.uid, identity.gid, 0o400)?;
    file.sync_all()
        .map_err(|_| error(GenerationCreateReason::StagingIncomplete))?;
    faults.hit(synced, GenerationCreateReason::StagingIncomplete)
}

#[cfg(target_os = "linux")]
fn validate_file(
    descriptor: &impl std::os::fd::AsFd,
    effective_uid: u32,
    effective_gid: u32,
    mode: u32,
) -> Result<(), GenerationCreateError> {
    let stat = rustix::fs::fstat(descriptor)
        .map_err(|_| error(GenerationCreateReason::StagingIncomplete))?;
    if rustix::fs::FileType::from_raw_mode(stat.st_mode) != rustix::fs::FileType::RegularFile
        || stat.st_uid != effective_uid
        || stat.st_gid != effective_gid
        || stat.st_nlink != 1
        || stat.st_mode & 0o7777 != mode
    {
        return Err(error(GenerationCreateReason::StagingIncomplete));
    }
    Ok(())
}

fn validate_absolute_path(path: &Path) -> Result<(), GenerationCreateError> {
    if !path.is_absolute()
        || path
            .components()
            .any(|component| matches!(component, Component::CurDir | Component::ParentDir))
    {
        return Err(error(GenerationCreateReason::InvalidInput));
    }
    Ok(())
}

fn random_nonzero() -> Result<[u8; 32], GenerationCreateError> {
    loop {
        let mut bytes = [0_u8; 32];
        getrandom::fill(&mut bytes).map_err(|_| error(GenerationCreateReason::Publication))?;
        if bytes != [0; 32] {
            return Ok(bytes);
        }
    }
}

fn utc_timestamp(seconds: u64) -> Result<String, GenerationCreateError> {
    let seconds = i64::try_from(seconds).map_err(|_| error(GenerationCreateReason::Publication))?;
    let days = seconds.div_euclid(86_400);
    let day_seconds = seconds.rem_euclid(86_400);
    let (year, month, day) = civil_from_days(days);
    if !(0..=9999).contains(&year) {
        return Err(error(GenerationCreateReason::Publication));
    }
    let hour = day_seconds / 3_600;
    let minute = day_seconds % 3_600 / 60;
    let second = day_seconds % 60;
    Ok(format!(
        "{year:04}-{month:02}-{day:02}T{hour:02}:{minute:02}:{second:02}Z"
    ))
}

fn civil_from_days(days_since_epoch: i64) -> (i64, i64, i64) {
    let shifted = days_since_epoch + 719_468;
    let era = shifted.div_euclid(146_097);
    let day_of_era = shifted - era * 146_097;
    let year_of_era =
        (day_of_era - day_of_era / 1_460 + day_of_era / 36_524 - day_of_era / 146_096) / 365;
    let mut year = year_of_era + era * 400;
    let day_of_year = day_of_era - (365 * year_of_era + year_of_era / 4 - year_of_era / 100);
    let month_prime = (5 * day_of_year + 2) / 153;
    let day = day_of_year - (153 * month_prime + 2) / 5 + 1;
    let month = month_prime + if month_prime < 10 { 3 } else { -9 };
    year += i64::from(month <= 2);
    (year, month, day)
}

fn hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut encoded = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        encoded.push(char::from(DIGITS[usize::from(byte >> 4)]));
        encoded.push(char::from(DIGITS[usize::from(byte & 0x0f)]));
    }
    encoded
}

#[cfg(target_os = "linux")]
fn map_staging_error(_errno: rustix::io::Errno) -> GenerationCreateError {
    error(GenerationCreateReason::StagingIncomplete)
}

#[cfg(target_os = "linux")]
fn map_publication_error(errno: rustix::io::Errno) -> GenerationCreateError {
    if errno == rustix::io::Errno::EXIST {
        error(GenerationCreateReason::AlreadyExists)
    } else {
        error(GenerationCreateReason::Publication)
    }
}

const fn error(reason: GenerationCreateReason) -> GenerationCreateError {
    GenerationCreateError { reason }
}

#[cfg(all(test, target_os = "linux"))]
mod tests {
    use super::{
        Boundary, CreationParameters, GenerationCreateReason, SecretDropObserver,
        create_generation_with, open_directory, read_bundle_with_observer, validate_directory,
        validate_file,
    };
    use std::{
        fs,
        io::{self, Cursor, Read},
        os::unix::fs::PermissionsExt as _,
        path::{Path, PathBuf},
        sync::{
            Arc,
            atomic::{AtomicU64, Ordering},
        },
    };

    const BUNDLE: &[u8] =
        include_bytes!("../../../bindings/testdata/non-production-provisioning.bundle");
    const TOKEN: &[u8] = b"generation-unit-token-canary\n";
    static NEXT_FIXTURE: AtomicU64 = AtomicU64::new(0);

    struct Fixture {
        root: PathBuf,
        parent: PathBuf,
        token: PathBuf,
    }

    impl Fixture {
        fn new() -> Self {
            let serial = NEXT_FIXTURE.fetch_add(1, Ordering::Relaxed);
            let root = std::env::temp_dir().join(format!(
                "aster-compose-generation-unit-{}-{serial}",
                std::process::id()
            ));
            fs::create_dir(&root).expect("fixture root");
            let parent = root.join("generations");
            fs::create_dir(&parent).expect("generation parent");
            fs::set_permissions(&parent, fs::Permissions::from_mode(0o700))
                .expect("protect generation parent");
            let token = root.join("token");
            fs::write(&token, TOKEN).expect("token fixture");
            fs::set_permissions(&token, fs::Permissions::from_mode(0o400))
                .expect("protect token fixture");
            Self {
                root,
                parent,
                token,
            }
        }

        fn entries(&self) -> Vec<PathBuf> {
            let mut entries = fs::read_dir(&self.parent)
                .expect("read parent")
                .map(|entry| entry.expect("entry").path())
                .collect::<Vec<_>>();
            entries.sort();
            entries
        }
    }

    #[test]
    fn insecure_parent_is_rejected_before_secret_input_or_staging() {
        for mode in [0o750, 0o770, 0o777] {
            let fixture = Fixture::new();
            fs::set_permissions(&fixture.parent, fs::Permissions::from_mode(mode))
                .expect("weaken generation parent");
            let error = create_generation_with(
                &fixture.parent,
                &fixture.root.join("missing-token"),
                std::io::Cursor::new(BUNDLE),
                parameters(),
                None,
            )
            .expect_err("insecure parent must fail before token access");
            assert_eq!(error.reason(), GenerationCreateReason::InvalidParent);
            assert!(
                fixture.entries().is_empty(),
                "mode {mode:o} created staging state"
            );
        }

        for mismatch in ["uid", "gid"] {
            let fixture = Fixture::new();
            let mut mismatched = parameters();
            if mismatch == "uid" {
                mismatched.effective_uid = different_id(mismatched.effective_uid);
            } else {
                mismatched.effective_gid = different_id(mismatched.effective_gid);
            }
            let error = create_generation_with(
                &fixture.parent,
                &fixture.root.join("missing-token"),
                std::io::Cursor::new(BUNDLE),
                mismatched,
                None,
            )
            .expect_err("wrong-owner parent must fail before token access");
            assert_eq!(error.reason(), GenerationCreateReason::InvalidParent);
            assert!(
                fixture.entries().is_empty(),
                "{mismatch} created staging state"
            );
        }
    }

    impl Drop for Fixture {
        fn drop(&mut self) {
            for entry in self.entries() {
                if entry.is_dir() {
                    fs::set_permissions(&entry, fs::Permissions::from_mode(0o700))
                        .expect("make directory removable");
                }
            }
            fs::set_permissions(&self.token, fs::Permissions::from_mode(0o600))
                .expect("make token removable");
            fs::remove_dir_all(&self.root).expect("remove fixture");
        }
    }

    fn parameters() -> CreationParameters {
        CreationParameters {
            effective_uid: rustix::process::geteuid().as_raw(),
            effective_gid: rustix::process::getegid().as_raw(),
            generation: [0x11; 32],
            reference: [0x22; 32],
            operation: [0x33; 32],
            created_at_unix_seconds: 1_797_249_600,
        }
    }

    #[test]
    fn every_interruption_boundary_withholds_a_success_receipt_and_never_activates_a_stage() {
        // Break caught: a write/sync/rename failure can publish a partial
        // directory or return success before the parent rename is durable.
        let boundaries = [
            Boundary::TokenWritten,
            Boundary::TokenSynced,
            Boundary::ActivationWritten,
            Boundary::ActivationSynced,
            Boundary::EnvelopeWritten,
            Boundary::EnvelopeSynced,
            Boundary::ManifestWritten,
            Boundary::ManifestSynced,
            Boundary::StagingDirectorySynced,
            Boundary::GenerationRenamed,
            Boundary::ParentSynced,
        ];
        for boundary in boundaries {
            let fixture = Fixture::new();
            let error = create_generation_with(
                &fixture.parent,
                &fixture.token,
                Cursor::new(BUNDLE),
                parameters(),
                Some(boundary),
            )
            .expect_err("injected boundary must withhold receipt");
            assert!(
                matches!(
                    error.reason(),
                    GenerationCreateReason::StagingIncomplete | GenerationCreateReason::Publication
                ),
                "boundary {boundary:?}"
            );
            let names = fixture
                .entries()
                .iter()
                .map(|path| path.file_name().unwrap().to_string_lossy().into_owned())
                .collect::<Vec<_>>();
            if boundary < Boundary::GenerationRenamed {
                assert_eq!(names.len(), 1, "boundary {boundary:?}");
                assert!(names[0].starts_with(".staging-"), "boundary {boundary:?}");
            } else {
                assert_eq!(names.len(), 1, "boundary {boundary:?}");
                assert!(names[0].starts_with("generation-"), "boundary {boundary:?}");
            }
        }
    }

    #[test]
    fn an_existing_final_name_is_refused_without_changing_its_bytes() {
        // Break caught: rename can replace an existing empty destination or a
        // retry can edit files in an immutable published generation.
        let fixture = Fixture::new();
        create_generation_with(
            &fixture.parent,
            &fixture.token,
            Cursor::new(BUNDLE),
            parameters(),
            None,
        )
        .expect("first publication");
        let final_directory = fixture.entries().pop().expect("final generation");
        let before = snapshot(&final_directory);

        let error = create_generation_with(
            &fixture.parent,
            &fixture.token,
            Cursor::new(BUNDLE),
            parameters(),
            None,
        )
        .expect_err("same final name must be refused");
        assert_eq!(error.reason(), GenerationCreateReason::AlreadyExists);
        assert_eq!(snapshot(&final_directory), before);
    }

    #[test]
    fn an_existing_staging_name_reports_the_fixed_recovery_category() {
        // Break caught: treating an interrupted stage as a completed
        // generation collision hides the operator recovery action.
        let fixture = Fixture::new();
        create_generation_with(
            &fixture.parent,
            &fixture.token,
            Cursor::new(BUNDLE),
            parameters(),
            Some(Boundary::TokenWritten),
        )
        .expect_err("leave interrupted stage");
        let error = create_generation_with(
            &fixture.parent,
            &fixture.token,
            Cursor::new(BUNDLE),
            parameters(),
            None,
        )
        .expect_err("stale stage must require recovery");
        assert_eq!(error.reason(), GenerationCreateReason::StagingIncomplete);
    }

    #[test]
    fn effective_root_is_rejected_before_creating_a_stage() {
        // Break caught: root execution would create host files with ownership
        // that the selected non-root runtime identity cannot consume.
        let fixture = Fixture::new();
        let mut root = parameters();
        root.effective_uid = 0;
        let error = create_generation_with(
            &fixture.parent,
            &fixture.token,
            Cursor::new(BUNDLE),
            root,
            None,
        )
        .expect_err("root must fail");
        assert_eq!(error.reason(), GenerationCreateReason::RootExecution);
        assert!(fixture.entries().is_empty());
    }

    #[test]
    fn effective_root_group_is_rejected_before_creating_a_stage() {
        // Break caught: a non-root UID paired with GID 0 can otherwise publish
        // root-group-owned artifacts that do not match the runtime identity.
        let fixture = Fixture::new();
        let mut root_group = parameters();
        root_group.effective_gid = 0;
        let error = create_generation_with(
            &fixture.parent,
            &fixture.token,
            Cursor::new(BUNDLE),
            root_group,
            None,
        )
        .expect_err("root group must fail");
        assert_eq!(error.reason(), GenerationCreateReason::RootExecution);
        assert!(fixture.entries().is_empty());
    }

    #[test]
    fn directory_with_wrong_group_is_rejected() {
        // Break caught: directory ownership validation can accept a matching
        // UID even when the directory belongs to a different group.
        let fixture = Fixture::new();
        fs::set_permissions(&fixture.parent, fs::Permissions::from_mode(0o700))
            .expect("protect parent");
        let directory = open_directory(&fixture.parent, GenerationCreateReason::InvalidParent)
            .expect("open fixture directory");
        let stat = rustix::fs::fstat(&directory).expect("directory metadata");
        let error = validate_directory(
            &directory,
            stat.st_uid,
            different_id(stat.st_gid),
            0o700,
            stat.st_dev,
        )
        .expect_err("wrong directory group must fail");
        assert_eq!(error.reason(), GenerationCreateReason::StagingIncomplete);
    }

    #[test]
    fn file_with_wrong_group_is_rejected() {
        // Break caught: generated-file validation can accept a matching UID
        // even when the file belongs to a different group.
        let fixture = Fixture::new();
        let file = fs::File::open(&fixture.token).expect("open fixture file");
        let stat = rustix::fs::fstat(&file).expect("file metadata");
        let error = validate_file(&file, stat.st_uid, different_id(stat.st_gid), 0o400)
            .expect_err("wrong file group must fail");
        assert_eq!(error.reason(), GenerationCreateReason::StagingIncomplete);
    }

    #[test]
    fn partial_and_oversized_stdin_buffers_are_zeroized_in_place() {
        // Break caught: early stdin failures can release plaintext allocations
        // without overwriting the bytes first.
        let partial = Arc::new(SecretDropObserver::default());
        let error = read_bundle_with_observer(
            PartialFailure::new(b"partial-bundle-canary"),
            Arc::clone(&partial),
        )
        .expect_err("partial read must fail");
        assert_eq!(error.reason(), GenerationCreateReason::InvalidInput);
        assert!(partial.zeroized.load(Ordering::SeqCst));
        assert!(partial.allocation_stable.load(Ordering::SeqCst));

        let oversized = Arc::new(SecretDropObserver::default());
        let error = read_bundle_with_observer(
            Cursor::new(vec![
                0x5a;
                aster_mesh::MAX_UNPROTECTED_PROVISIONING_BYTES + 1
            ]),
            Arc::clone(&oversized),
        )
        .expect_err("oversized read must fail");
        assert_eq!(error.reason(), GenerationCreateReason::TooLarge);
        assert!(oversized.zeroized.load(Ordering::SeqCst));
        assert!(oversized.allocation_stable.load(Ordering::SeqCst));
    }

    fn snapshot(directory: &Path) -> Vec<(String, Vec<u8>)> {
        let mut snapshot = fs::read_dir(directory)
            .expect("read generation")
            .map(|entry| {
                let entry = entry.expect("generation entry");
                (
                    entry.file_name().into_string().expect("UTF-8 name"),
                    fs::read(entry.path()).expect("generation bytes"),
                )
            })
            .collect::<Vec<_>>();
        snapshot.sort_by(|left, right| left.0.cmp(&right.0));
        snapshot
    }

    fn different_id(id: u32) -> u32 {
        if id == u32::MAX { id - 1 } else { id + 1 }
    }

    struct PartialFailure {
        bytes: Cursor<Vec<u8>>,
        failed: bool,
    }

    impl PartialFailure {
        fn new(bytes: &[u8]) -> Self {
            Self {
                bytes: Cursor::new(bytes.to_vec()),
                failed: false,
            }
        }
    }

    impl Read for PartialFailure {
        fn read(&mut self, output: &mut [u8]) -> io::Result<usize> {
            if self.failed {
                Err(io::Error::other("injected read failure"))
            } else {
                self.failed = true;
                self.bytes.read(output)
            }
        }
    }
}
