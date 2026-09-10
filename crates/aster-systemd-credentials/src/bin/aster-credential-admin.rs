//! Root-operated administration command for the selected systemd provider.

#[cfg(target_os = "linux")]
use aster_mesh::{
    MAX_PROVISIONING_SECRET_REF_BYTES, MAX_UNPROTECTED_PROVISIONING_BYTES,
    ProvisioningDestroyDisposition, ProvisioningDestroyId, ProvisioningInstallDisposition,
    ProvisioningInstallId, ProvisioningLoadId, ProvisioningProtectionError, ProvisioningSecretRef,
    ProvisioningSecretStoreError, UnprotectedProvisioning,
};
#[cfg(target_os = "linux")]
use aster_systemd_credentials::{
    PROVIDER_REFERENCE_ID_BYTES,
    admin::{
        BackupOperationId, MAX_BACKUP_ARTIFACT_BYTES, ProtectedBackupArtifact, RecoveryDisposition,
        RecoveryOperationId, SystemdCredentialAdmin,
    },
    provisioning_secret_ref,
};
#[cfg(target_os = "linux")]
use std::{env, io::Read as _, process::ExitCode};
#[cfg(target_os = "linux")]
use zeroize::{Zeroize as _, Zeroizing};

#[cfg(all(test, target_os = "linux"))]
use std::sync::{
    Arc,
    atomic::{AtomicBool, Ordering},
};

#[cfg(all(test, target_os = "linux"))]
#[derive(Default)]
struct SecretDropObserver {
    zeroized: AtomicBool,
    allocation_stable: AtomicBool,
}

#[cfg(all(test, target_os = "linux"))]
#[derive(Default)]
struct ArtifactDropObserver {
    zeroized: AtomicBool,
    allocation_stable: AtomicBool,
}

#[cfg(target_os = "linux")]
#[derive(Debug)]
enum Command {
    Install {
        operation: ProvisioningInstallId,
        load: ProvisioningLoadId,
    },
    Rotate {
        operation: ProvisioningInstallId,
        load: ProvisioningLoadId,
    },
    Backup {
        operation: BackupOperationId,
    },
    Recover {
        operation: RecoveryOperationId,
    },
    Destroy {
        operation: ProvisioningDestroyId,
        reference: ProvisioningSecretRef,
    },
}

#[cfg(target_os = "linux")]
impl Command {
    fn parse_os(
        arguments: impl IntoIterator<Item = std::ffi::OsString>,
    ) -> Result<Self, ProvisioningSecretStoreError> {
        let arguments = arguments
            .into_iter()
            .map(|argument| {
                argument
                    .into_string()
                    .map_err(|_| ProvisioningSecretStoreError::Rejected)
            })
            .collect::<Result<Vec<_>, _>>()?;
        Self::parse(arguments)
    }

    fn parse(
        arguments: impl IntoIterator<Item = String>,
    ) -> Result<Self, ProvisioningSecretStoreError> {
        let arguments = arguments.into_iter().collect::<Vec<_>>();
        match arguments.as_slice() {
            [command, operation_flag, operation, load_flag, load]
                if (command == "install" || command == "rotate")
                    && operation_flag == "--operation"
                    && load_flag == "--load-operation" =>
            {
                let operation = ProvisioningInstallId::new(parse_operation_id(operation)?);
                let load = ProvisioningLoadId::new(parse_operation_id(load)?);
                if command == "install" {
                    Ok(Self::Install { operation, load })
                } else {
                    Ok(Self::Rotate { operation, load })
                }
            }
            [command, operation_flag, operation]
                if (command == "backup" || command == "recover")
                    && operation_flag == "--operation" =>
            {
                let operation = parse_operation_id(operation)?;
                if command == "backup" {
                    Ok(Self::Backup {
                        operation: BackupOperationId::new(operation),
                    })
                } else {
                    Ok(Self::Recover {
                        operation: RecoveryOperationId::new(operation),
                    })
                }
            }
            [
                command,
                operation_flag,
                operation,
                reference_flag,
                reference,
            ] if command == "destroy"
                && operation_flag == "--operation"
                && reference_flag == "--reference" =>
            {
                Ok(Self::Destroy {
                    operation: ProvisioningDestroyId::new(parse_operation_id(operation)?),
                    reference: parse_reference(reference)?,
                })
            }
            _ => Err(ProvisioningSecretStoreError::Rejected),
        }
    }
}

#[cfg(target_os = "linux")]
fn parse_operation_id(value: &str) -> Result<[u8; 32], ProvisioningSecretStoreError> {
    let bytes = value.as_bytes();
    if bytes.len() != 64
        || bytes
            .iter()
            .any(|byte| !byte.is_ascii_digit() && !(b'a'..=b'f').contains(byte))
    {
        return Err(ProvisioningSecretStoreError::Rejected);
    }
    let mut decoded = [0_u8; 32];
    for (index, pair) in bytes.chunks_exact(2).enumerate() {
        decoded[index] = decode_nibble(pair[0])? << 4 | decode_nibble(pair[1])?;
    }
    Ok(decoded)
}

#[cfg(target_os = "linux")]
fn decode_nibble(value: u8) -> Result<u8, ProvisioningSecretStoreError> {
    match value {
        b'0'..=b'9' => Ok(value - b'0'),
        b'a'..=b'f' => Ok(value - b'a' + 10),
        _ => Err(ProvisioningSecretStoreError::Rejected),
    }
}

#[cfg(target_os = "linux")]
fn parse_reference(value: &str) -> Result<ProvisioningSecretRef, ProvisioningSecretStoreError> {
    let bytes = value.as_bytes();
    if bytes.len() > MAX_PROVISIONING_SECRET_REF_BYTES.saturating_mul(2) {
        return Err(ProvisioningSecretStoreError::TooLarge);
    }
    if bytes.is_empty()
        || !bytes.len().is_multiple_of(2)
        || bytes
            .iter()
            .any(|byte| !byte.is_ascii_digit() && !(b'a'..=b'f').contains(byte))
    {
        return Err(ProvisioningSecretStoreError::Rejected);
    }
    let mut decoded = Zeroizing::new(Vec::with_capacity(bytes.len() / 2));
    for pair in bytes.chunks_exact(2) {
        decoded.push(decode_nibble(pair[0])? << 4 | decode_nibble(pair[1])?);
    }
    let reference = ProvisioningSecretRef::from_bytes(&decoded)?;
    let _ = provider_reference_generation(&reference)?;
    Ok(reference)
}

#[cfg(target_os = "linux")]
fn provider_reference_generation(
    reference: &ProvisioningSecretRef,
) -> Result<u64, ProvisioningSecretStoreError> {
    const PROVIDER_REFERENCE_BYTES: usize = 8 + 2 + 2 + 8 + PROVIDER_REFERENCE_ID_BYTES;
    let opaque = reference.expose_opaque();
    if opaque.len() != PROVIDER_REFERENCE_BYTES
        || &opaque[..8] != b"ASTRSDRF"
        || &opaque[8..10] != 2_u16.to_be_bytes().as_slice()
        || &opaque[10..12] != 0_u16.to_be_bytes().as_slice()
    {
        return Err(ProvisioningSecretStoreError::InvalidReference);
    }
    let generation = u64::from_be_bytes(
        opaque[12..20]
            .try_into()
            .map_err(|_| ProvisioningSecretStoreError::InvalidReference)?,
    );
    if generation == 0 {
        return Err(ProvisioningSecretStoreError::InvalidReference);
    }
    let reference_id: [u8; PROVIDER_REFERENCE_ID_BYTES] = opaque[20..]
        .try_into()
        .map_err(|_| ProvisioningSecretStoreError::InvalidReference)?;
    if provisioning_secret_ref(generation, reference_id)? != *reference {
        return Err(ProvisioningSecretStoreError::InvalidReference);
    }
    Ok(generation)
}

#[cfg(target_os = "linux")]
fn read_secret(
    input: impl std::io::Read,
) -> Result<UnprotectedProvisioning, ProvisioningSecretStoreError> {
    #[cfg(test)]
    {
        read_secret_inner(input, None)
    }
    #[cfg(not(test))]
    {
        read_secret_inner(input)
    }
}

#[cfg(all(test, target_os = "linux"))]
fn read_secret_with_observer(
    input: impl std::io::Read,
    observer: Arc<SecretDropObserver>,
) -> Result<UnprotectedProvisioning, ProvisioningSecretStoreError> {
    read_secret_inner(input, Some(observer))
}

#[cfg(target_os = "linux")]
fn read_secret_inner(
    mut input: impl std::io::Read,
    #[cfg(test)] observer: Option<Arc<SecretDropObserver>>,
) -> Result<UnprotectedProvisioning, ProvisioningSecretStoreError> {
    #[cfg(test)]
    let mut buffer = SecretInputBuffer::new(observer);
    #[cfg(not(test))]
    let mut buffer = SecretInputBuffer::new();
    input
        .by_ref()
        .take((MAX_UNPROTECTED_PROVISIONING_BYTES + 1) as u64)
        .read_to_end(&mut buffer.bytes)
        .map_err(|_| ProvisioningSecretStoreError::Unavailable)?;
    if buffer.bytes.len() > MAX_UNPROTECTED_PROVISIONING_BYTES {
        return Err(ProvisioningSecretStoreError::TooLarge);
    }
    UnprotectedProvisioning::new(buffer.take()).map_err(|error| match error {
        ProvisioningProtectionError::TooLarge => ProvisioningSecretStoreError::TooLarge,
        ProvisioningProtectionError::Unavailable => ProvisioningSecretStoreError::Unavailable,
        ProvisioningProtectionError::Rejected => ProvisioningSecretStoreError::Rejected,
        _ => ProvisioningSecretStoreError::Rejected,
    })
}

#[cfg(target_os = "linux")]
struct SecretInputBuffer {
    bytes: Vec<u8>,
    #[cfg(test)]
    observer: Option<Arc<SecretDropObserver>>,
}

#[cfg(target_os = "linux")]
impl SecretInputBuffer {
    fn new(#[cfg(test)] observer: Option<Arc<SecretDropObserver>>) -> Self {
        Self {
            bytes: Vec::with_capacity(MAX_UNPROTECTED_PROVISIONING_BYTES + 1),
            #[cfg(test)]
            observer,
        }
    }

    fn take(&mut self) -> Vec<u8> {
        std::mem::take(&mut self.bytes)
    }
}

#[cfg(target_os = "linux")]
impl Drop for SecretInputBuffer {
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

#[cfg(target_os = "linux")]
fn read_protected_artifact(
    input: impl std::io::Read,
) -> Result<ProtectedBackupArtifact, ProvisioningSecretStoreError> {
    #[cfg(test)]
    {
        read_protected_artifact_inner(input, None)
    }
    #[cfg(not(test))]
    {
        read_protected_artifact_inner(input)
    }
}

#[cfg(all(test, target_os = "linux"))]
fn read_protected_artifact_with_observer(
    input: impl std::io::Read,
    observer: Arc<ArtifactDropObserver>,
) -> Result<ProtectedBackupArtifact, ProvisioningSecretStoreError> {
    read_protected_artifact_inner(input, Some(observer))
}

#[cfg(target_os = "linux")]
fn read_protected_artifact_inner(
    mut input: impl std::io::Read,
    #[cfg(test)] observer: Option<Arc<ArtifactDropObserver>>,
) -> Result<ProtectedBackupArtifact, ProvisioningSecretStoreError> {
    #[cfg(test)]
    let mut buffer = ProtectedArtifactInputBuffer::new(observer);
    #[cfg(not(test))]
    let mut buffer = ProtectedArtifactInputBuffer::new();
    input
        .by_ref()
        .take((MAX_BACKUP_ARTIFACT_BYTES + 1) as u64)
        .read_to_end(&mut buffer.bytes)
        .map_err(|_| ProvisioningSecretStoreError::Unavailable)?;
    if buffer.bytes.len() > MAX_BACKUP_ARTIFACT_BYTES {
        return Err(ProvisioningSecretStoreError::TooLarge);
    }
    ProtectedBackupArtifact::from_bytes(&buffer.bytes)
}

#[cfg(target_os = "linux")]
struct ProtectedArtifactInputBuffer {
    bytes: Vec<u8>,
    #[cfg(test)]
    observer: Option<Arc<ArtifactDropObserver>>,
}

#[cfg(target_os = "linux")]
impl ProtectedArtifactInputBuffer {
    fn new(#[cfg(test)] observer: Option<Arc<ArtifactDropObserver>>) -> Self {
        Self {
            bytes: Vec::with_capacity(MAX_BACKUP_ARTIFACT_BYTES + 1),
            #[cfg(test)]
            observer,
        }
    }
}

#[cfg(target_os = "linux")]
impl Drop for ProtectedArtifactInputBuffer {
    fn drop(&mut self) {
        #[cfg(test)]
        let contained_artifact = !self.bytes.is_empty();
        self.bytes.as_mut_slice().zeroize();
        #[cfg(test)]
        if let Some(observer) = &self.observer {
            observer.zeroized.store(
                contained_artifact && self.bytes.iter().all(|byte| *byte == 0),
                Ordering::SeqCst,
            );
            observer.allocation_stable.store(
                self.bytes.capacity() == MAX_BACKUP_ARTIFACT_BYTES + 1,
                Ordering::SeqCst,
            );
        }
        self.bytes.clear();
    }
}

#[cfg(target_os = "linux")]
enum PreparedCommand {
    Install {
        operation: ProvisioningInstallId,
        load: ProvisioningLoadId,
        plaintext: UnprotectedProvisioning,
    },
    Rotate {
        operation: ProvisioningInstallId,
        load: ProvisioningLoadId,
        plaintext: UnprotectedProvisioning,
    },
    Backup {
        operation: BackupOperationId,
    },
    Recover {
        operation: RecoveryOperationId,
        artifact: ProtectedBackupArtifact,
    },
    Destroy {
        operation: ProvisioningDestroyId,
        reference: ProvisioningSecretRef,
    },
}

#[cfg(target_os = "linux")]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum OpenMode {
    Normal,
    Recovery,
}

#[cfg(target_os = "linux")]
enum CommandOutcome {
    Install {
        disposition: ProvisioningInstallDisposition,
        generation: u64,
        reference: ProvisioningSecretRef,
    },
    Rotate {
        disposition: ProvisioningInstallDisposition,
        generation: u64,
        reference: ProvisioningSecretRef,
    },
    Backup {
        generation: u64,
        artifact: Zeroizing<Vec<u8>>,
    },
    Recover {
        disposition: RecoveryDisposition,
        generation: u64,
    },
    Destroy(ProvisioningDestroyDisposition),
}

#[cfg(target_os = "linux")]
fn prepare_command(
    command: Command,
    input: impl std::io::Read,
) -> Result<(OpenMode, PreparedCommand), ProvisioningSecretStoreError> {
    match command {
        Command::Install { operation, load } => Ok((
            OpenMode::Normal,
            PreparedCommand::Install {
                operation,
                load,
                plaintext: read_secret(input)?,
            },
        )),
        Command::Rotate { operation, load } => Ok((
            OpenMode::Normal,
            PreparedCommand::Rotate {
                operation,
                load,
                plaintext: read_secret(input)?,
            },
        )),
        Command::Backup { operation } => {
            Ok((OpenMode::Normal, PreparedCommand::Backup { operation }))
        }
        Command::Recover { operation } => Ok((
            OpenMode::Recovery,
            PreparedCommand::Recover {
                operation,
                artifact: read_protected_artifact(input)?,
            },
        )),
        Command::Destroy {
            operation,
            reference,
        } => Ok((
            OpenMode::Normal,
            PreparedCommand::Destroy {
                operation,
                reference,
            },
        )),
    }
}

#[cfg(target_os = "linux")]
fn open_and_execute(
    mode: OpenMode,
    command: PreparedCommand,
) -> Result<CommandOutcome, ProvisioningSecretStoreError> {
    let mut admin = match mode {
        OpenMode::Normal => SystemdCredentialAdmin::open()?,
        OpenMode::Recovery => SystemdCredentialAdmin::open_for_recovery()?,
    };
    match command {
        PreparedCommand::Install {
            operation,
            load,
            plaintext,
        } if mode == OpenMode::Normal => {
            let receipt = admin.install(operation, load, plaintext)?;
            Ok(CommandOutcome::Install {
                disposition: receipt.disposition(),
                generation: provider_reference_generation(receipt.secret_ref())?,
                reference: receipt.into_secret_ref(),
            })
        }
        PreparedCommand::Rotate {
            operation,
            load,
            plaintext,
        } if mode == OpenMode::Normal => {
            let receipt = admin.rotate(operation, load, plaintext)?;
            Ok(CommandOutcome::Rotate {
                disposition: receipt.disposition(),
                generation: provider_reference_generation(receipt.secret_ref())?,
                reference: receipt.into_secret_ref(),
            })
        }
        PreparedCommand::Backup { operation } if mode == OpenMode::Normal => {
            let receipt = admin.backup(operation)?;
            Ok(CommandOutcome::Backup {
                generation: receipt.generation(),
                artifact: Zeroizing::new(receipt.artifact().as_bytes().to_vec()),
            })
        }
        PreparedCommand::Recover {
            operation,
            artifact,
        } if mode == OpenMode::Recovery => {
            let receipt = admin.recover(operation, &artifact)?;
            Ok(CommandOutcome::Recover {
                disposition: receipt.disposition(),
                generation: receipt.generation(),
            })
        }
        PreparedCommand::Destroy {
            operation,
            reference,
        } if mode == OpenMode::Normal => {
            let receipt = admin.destroy(operation, &reference)?;
            Ok(CommandOutcome::Destroy(receipt.disposition()))
        }
        _ => Err(ProvisioningSecretStoreError::Rejected),
    }
}

#[cfg(target_os = "linux")]
fn encode_reference(reference: &ProvisioningSecretRef) -> Zeroizing<String> {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let bytes = Zeroizing::new(reference.to_bytes());
    let mut encoded = Zeroizing::new(String::with_capacity(bytes.len() * 2));
    for &byte in bytes.iter() {
        encoded.push(char::from(HEX[usize::from(byte >> 4)]));
        encoded.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    encoded
}

#[cfg(target_os = "linux")]
/// Writes directly to the caller's output transports. Parser, input, and
/// provider failures occur before this function and therefore emit no stdout.
/// Once a write starts, output is nontransactional: a later write, flush, or
/// broken-pipe failure returns `Unavailable`, and the nonzero invocation's
/// partial or complete stdout must be discarded. Backup status is deliberately
/// written only after its artifact bytes have successfully flushed.
fn write_success(
    outcome: CommandOutcome,
    stdout: &mut impl std::io::Write,
    stderr: &mut impl std::io::Write,
) -> Result<(), ProvisioningSecretStoreError> {
    let unavailable = |_| ProvisioningSecretStoreError::Unavailable;
    match outcome {
        CommandOutcome::Install {
            disposition,
            generation,
            reference,
        } => {
            let reference = encode_reference(&reference);
            writeln!(
                stdout,
                "INSTALL disposition={} generation={generation} reference={}",
                install_disposition(disposition),
                reference.as_str()
            )
            .map_err(unavailable)
        }
        CommandOutcome::Rotate {
            disposition,
            generation,
            reference,
        } => {
            let reference = encode_reference(&reference);
            writeln!(
                stdout,
                "ROTATE disposition={} generation={generation} reference={}",
                install_disposition(disposition),
                reference.as_str()
            )
            .map_err(unavailable)
        }
        CommandOutcome::Backup {
            generation,
            artifact,
        } => {
            stdout.write_all(&artifact).map_err(unavailable)?;
            stdout.flush().map_err(unavailable)?;
            writeln!(
                stderr,
                "BACKUP disposition=available generation={generation}"
            )
            .map_err(unavailable)
        }
        CommandOutcome::Recover {
            disposition,
            generation,
        } => writeln!(
            stdout,
            "RECOVER disposition={} generation={generation}",
            recovery_disposition(disposition)
        )
        .map_err(unavailable),
        CommandOutcome::Destroy(disposition) => writeln!(
            stdout,
            "DESTROY disposition={}",
            destroy_disposition(disposition)
        )
        .map_err(unavailable),
    }
}

#[cfg(target_os = "linux")]
const fn install_disposition(disposition: ProvisioningInstallDisposition) -> &'static str {
    match disposition {
        ProvisioningInstallDisposition::Installed => "installed",
        ProvisioningInstallDisposition::Existing => "existing",
    }
}

#[cfg(target_os = "linux")]
const fn recovery_disposition(disposition: RecoveryDisposition) -> &'static str {
    match disposition {
        RecoveryDisposition::Restored => "restored",
        RecoveryDisposition::Existing => "existing",
    }
}

#[cfg(target_os = "linux")]
const fn destroy_disposition(disposition: ProvisioningDestroyDisposition) -> &'static str {
    match disposition {
        ProvisioningDestroyDisposition::Destroyed => "destroyed",
        ProvisioningDestroyDisposition::AlreadyDestroyed => "already-destroyed",
    }
}

#[cfg(target_os = "linux")]
/// Runs one invocation and returns a process status. A nonzero status always
/// invalidates stdout, including any prefix written before an output transport
/// failure; stdout is guaranteed empty only for failures before output starts.
fn execute_with<A, R, O, E, F>(
    arguments: A,
    input: R,
    stdout: &mut O,
    stderr: &mut E,
    execute: F,
) -> i32
where
    A: IntoIterator,
    A::Item: Into<std::ffi::OsString>,
    R: std::io::Read,
    O: std::io::Write,
    E: std::io::Write,
    F: FnOnce(OpenMode, PreparedCommand) -> Result<CommandOutcome, ProvisioningSecretStoreError>,
{
    let result = Command::parse_os(arguments.into_iter().map(Into::into))
        .and_then(|command| prepare_command(command, input))
        .and_then(|(mode, command)| execute(mode, command))
        .and_then(|outcome| write_success(outcome, stdout, stderr));
    match result {
        Ok(()) => 0,
        Err(error) => {
            let _ = writeln!(stderr, "ERROR {error}");
            1
        }
    }
}

#[cfg(target_os = "linux")]
fn main() -> ExitCode {
    let mut stdout = std::io::stdout().lock();
    let mut stderr = std::io::stderr().lock();
    ExitCode::from(execute_with(
        env::args_os().skip(1),
        std::io::stdin().lock(),
        &mut stdout,
        &mut stderr,
        open_and_execute,
    ) as u8)
}

#[cfg(not(target_os = "linux"))]
fn main() -> std::process::ExitCode {
    eprintln!("ERROR provisioning secret store is unavailable");
    std::process::ExitCode::FAILURE
}

#[cfg(all(test, target_os = "linux"))]
mod tests {
    use super::{
        ArtifactDropObserver, Command, CommandOutcome, OpenMode, PreparedCommand,
        SecretDropObserver, execute_with, read_protected_artifact,
        read_protected_artifact_with_observer, read_secret, read_secret_with_observer,
    };
    use aster_mesh::{
        MAX_PROVISIONING_SECRET_REF_BYTES, MAX_UNPROTECTED_PROVISIONING_BYTES,
        ProvisioningDestroyDisposition, ProvisioningInstallDisposition,
        ProvisioningSecretStoreError,
    };
    use aster_systemd_credentials::{
        admin::{MAX_BACKUP_ARTIFACT_BYTES, RecoveryDisposition},
        provisioning_secret_ref,
    };
    use std::os::unix::ffi::OsStringExt as _;
    use std::{
        fs,
        io::{self, Cursor, Read, Write},
        path::PathBuf,
        process::Command as ProcessCommand,
        sync::{Arc, atomic::Ordering},
    };
    use zeroize::Zeroizing;

    const OPERATION: [u8; 32] = [0x11; 32];
    const LOAD_OPERATION: [u8; 32] = [0x22; 32];

    fn install_arguments(command: &str) -> Vec<String> {
        vec![
            command.to_owned(),
            "--operation".to_owned(),
            hex(&OPERATION),
            "--load-operation".to_owned(),
            hex(&LOAD_OPERATION),
        ]
    }

    fn operation_arguments(command: &str) -> Vec<String> {
        vec![
            command.to_owned(),
            "--operation".to_owned(),
            hex(&OPERATION),
        ]
    }

    fn reference() -> aster_mesh::ProvisioningSecretRef {
        provisioning_secret_ref(7, [0xab; 32]).expect("canonical provider reference")
    }

    fn destroy_arguments() -> Vec<String> {
        let mut arguments = operation_arguments("destroy");
        arguments.extend(["--reference".to_owned(), hex(&reference().to_bytes())]);
        arguments
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

    #[test]
    fn parser_accepts_only_the_five_exact_command_shapes() {
        // Break caught: collapsing commands into one flexible argument bag can
        // dispatch an operation with missing, reordered, or unrelated fields.
        for command_name in ["install", "rotate"] {
            match Command::parse(install_arguments(command_name)).expect("install-like command") {
                Command::Install { operation, load } if command_name == "install" => {
                    assert_eq!(operation.as_bytes(), &OPERATION);
                    assert_eq!(load.as_bytes(), &LOAD_OPERATION);
                }
                Command::Rotate { operation, load } if command_name == "rotate" => {
                    assert_eq!(operation.as_bytes(), &OPERATION);
                    assert_eq!(load.as_bytes(), &LOAD_OPERATION);
                }
                _ => panic!("wrong install-like command variant"),
            }
        }
        assert!(matches!(
            Command::parse(operation_arguments("backup")).expect("backup command"),
            Command::Backup { operation } if operation.as_bytes() == &OPERATION
        ));
        assert!(matches!(
            Command::parse(operation_arguments("recover")).expect("recover command"),
            Command::Recover { operation } if operation.as_bytes() == &OPERATION
        ));
        assert!(matches!(
            Command::parse(destroy_arguments()).expect("destroy command"),
            Command::Destroy { operation, reference: parsed }
                if operation.as_bytes() == &OPERATION && parsed == reference()
        ));
    }

    #[test]
    fn parser_rejects_noncanonical_ids_and_references() {
        // Break caught: case-folding or accepting an arbitrary opaque Aster
        // reference makes durable operation/reference binding ambiguous.
        for replacement in ["11".to_owned(), "AA".repeat(32), "gg".repeat(32)] {
            let mut arguments = install_arguments("install");
            arguments[2] = replacement;
            assert_eq!(
                Command::parse(arguments).expect_err("noncanonical operation"),
                ProvisioningSecretStoreError::Rejected
            );
        }

        let canonical = hex(&reference().to_bytes());
        let mut uppercase = destroy_arguments();
        uppercase[4] = canonical.to_uppercase();
        assert!(Command::parse(uppercase).is_err());

        let mut odd = destroy_arguments();
        odd[4].pop();
        assert!(Command::parse(odd).is_err());

        let mut too_large = destroy_arguments();
        too_large[4] = "aa".repeat(MAX_PROVISIONING_SECRET_REF_BYTES + 1);
        assert_eq!(
            Command::parse(too_large).expect_err("oversized reference"),
            ProvisioningSecretStoreError::TooLarge
        );

        let arbitrary = aster_mesh::ProvisioningSecretRef::from_opaque(b"not-provider-v2".to_vec())
            .expect("bounded arbitrary reference");
        let mut non_provider = destroy_arguments();
        non_provider[4] = hex(&arbitrary.to_bytes());
        assert_eq!(
            Command::parse(non_provider).expect_err("non-provider reference"),
            ProvisioningSecretStoreError::InvalidReference
        );
    }

    #[test]
    fn parser_rejects_duplicates_unknown_arguments_reordering_and_secret_sources() {
        // Break caught: flexible flag parsing can admit secret paths,
        // environment sources, duplicates, or order-dependent interpretation.
        let mut cases = vec![
            Vec::new(),
            vec!["INSTALL".to_owned()],
            vec![
                "install".to_owned(),
                "--input".to_owned(),
                "/tmp/bundle".to_owned(),
            ],
            vec![
                "recover".to_owned(),
                "--input-env".to_owned(),
                "SECRET".to_owned(),
            ],
        ];
        let mut unknown = install_arguments("install");
        unknown.push("--verbose".to_owned());
        cases.push(unknown);
        let mut reordered = install_arguments("rotate");
        reordered.swap(1, 3);
        cases.push(reordered);
        let mut duplicate = operation_arguments("backup");
        duplicate.extend(["--operation".to_owned(), hex(&OPERATION)]);
        cases.push(duplicate);
        let mut destroy_reordered = destroy_arguments();
        destroy_reordered.swap(1, 3);
        destroy_reordered.swap(2, 4);
        cases.push(destroy_reordered);

        for arguments in cases {
            assert_eq!(
                Command::parse(arguments).expect_err("invalid exact grammar"),
                ProvisioningSecretStoreError::Rejected
            );
        }
    }

    #[test]
    fn non_utf8_arguments_are_rejected_without_a_panic() {
        // Break caught: `env::args` panics on non-UTF-8 input before the
        // command can return its fixed sanitized rejection category.
        let arguments = vec![std::ffi::OsString::from_vec(vec![0xff])];
        assert_eq!(
            Command::parse_os(arguments).expect_err("non-UTF-8 argument"),
            ProvisioningSecretStoreError::Rejected
        );
    }

    #[test]
    fn stdin_secret_reader_is_bounded_and_rejects_empty_input() {
        // Break caught: an unbounded stdin read permits memory exhaustion;
        // accepting empty input invokes the provider without a secret.
        assert_eq!(
            read_secret(Cursor::new(Vec::<u8>::new())).expect_err("empty stdin"),
            ProvisioningSecretStoreError::Rejected
        );
        assert_eq!(
            read_secret(Cursor::new(vec![0; MAX_UNPROTECTED_PROVISIONING_BYTES + 1]))
                .expect_err("oversized stdin"),
            ProvisioningSecretStoreError::TooLarge
        );
        assert_eq!(
            read_secret(Cursor::new(b"bounded".to_vec()))
                .expect("bounded stdin")
                .len(),
            7
        );
    }

    #[test]
    fn recovery_artifact_reader_has_its_own_bound_and_zeroizing_buffer() {
        // Break caught: reusing the plaintext bound or plaintext buffer for a
        // protected artifact can truncate valid backup data or mix lifetimes.
        assert_eq!(
            read_protected_artifact(Cursor::new(Vec::<u8>::new()))
                .expect_err("missing protected artifact"),
            ProvisioningSecretStoreError::Rejected
        );
        assert_eq!(
            read_protected_artifact(Cursor::new(vec![0; MAX_BACKUP_ARTIFACT_BYTES + 1]))
                .expect_err("oversized protected artifact"),
            ProvisioningSecretStoreError::TooLarge
        );

        let partial_observer = Arc::new(ArtifactDropObserver::default());
        assert_eq!(
            read_protected_artifact_with_observer(
                PartialFailure::new(b"partial-protected-artifact"),
                Arc::clone(&partial_observer),
            )
            .expect_err("partial protected-artifact read failure"),
            ProvisioningSecretStoreError::Unavailable
        );
        assert!(partial_observer.zeroized.load(Ordering::SeqCst));
        assert!(partial_observer.allocation_stable.load(Ordering::SeqCst));

        let oversized_observer = Arc::new(ArtifactDropObserver::default());
        assert_eq!(
            read_protected_artifact_with_observer(
                Cursor::new(vec![0x5a; MAX_BACKUP_ARTIFACT_BYTES + 1]),
                Arc::clone(&oversized_observer),
            )
            .expect_err("oversized protected-artifact read"),
            ProvisioningSecretStoreError::TooLarge
        );
        assert!(oversized_observer.zeroized.load(Ordering::SeqCst));
        assert!(oversized_observer.allocation_stable.load(Ordering::SeqCst));
    }

    #[test]
    fn partial_and_oversized_stdin_are_zeroized_on_failure() {
        // Break caught: returning early from a failed or oversized stdin read
        // must not drop a plaintext allocation without first overwriting it.
        let partial_observer = Arc::new(SecretDropObserver::default());
        assert_eq!(
            read_secret_with_observer(
                PartialFailure::new(b"partial-secret"),
                Arc::clone(&partial_observer),
            )
            .expect_err("partial read failure"),
            ProvisioningSecretStoreError::Unavailable
        );
        assert!(partial_observer.zeroized.load(Ordering::SeqCst));
        assert!(partial_observer.allocation_stable.load(Ordering::SeqCst));

        let oversized_observer = Arc::new(SecretDropObserver::default());
        assert_eq!(
            read_secret_with_observer(
                Cursor::new(vec![0x5a; MAX_UNPROTECTED_PROVISIONING_BYTES + 1]),
                Arc::clone(&oversized_observer),
            )
            .expect_err("oversized read"),
            ProvisioningSecretStoreError::TooLarge
        );
        assert!(oversized_observer.zeroized.load(Ordering::SeqCst));
        assert!(oversized_observer.allocation_stable.load(Ordering::SeqCst));
    }

    #[test]
    fn exact_success_schema_exposes_only_each_commands_allowed_fields() {
        // Break caught: status rendering can leak operation IDs or references
        // on commands whose schema deliberately excludes them.
        let reference = reference();
        let reference_hex = hex(&reference.to_bytes());
        let cases = [
            (
                CommandOutcome::Install {
                    disposition: ProvisioningInstallDisposition::Installed,
                    generation: 7,
                    reference: reference.clone(),
                },
                format!("INSTALL disposition=installed generation=7 reference={reference_hex}\n"),
            ),
            (
                CommandOutcome::Rotate {
                    disposition: ProvisioningInstallDisposition::Existing,
                    generation: 7,
                    reference,
                },
                format!("ROTATE disposition=existing generation=7 reference={reference_hex}\n"),
            ),
            (
                CommandOutcome::Recover {
                    disposition: RecoveryDisposition::Restored,
                    generation: 7,
                },
                "RECOVER disposition=restored generation=7\n".to_owned(),
            ),
            (
                CommandOutcome::Recover {
                    disposition: RecoveryDisposition::Existing,
                    generation: 7,
                },
                "RECOVER disposition=existing generation=7\n".to_owned(),
            ),
            (
                CommandOutcome::Destroy(ProvisioningDestroyDisposition::Destroyed),
                "DESTROY disposition=destroyed\n".to_owned(),
            ),
            (
                CommandOutcome::Destroy(ProvisioningDestroyDisposition::AlreadyDestroyed),
                "DESTROY disposition=already-destroyed\n".to_owned(),
            ),
        ];
        for (outcome, expected_stdout) in cases {
            let mut stdout = Vec::new();
            let mut stderr = Vec::new();
            super::write_success(outcome, &mut stdout, &mut stderr).expect("render success");
            assert_eq!(stdout, expected_stdout.as_bytes());
            assert!(stderr.is_empty());
        }
    }

    #[test]
    fn backup_success_keeps_stdout_binary_and_uses_one_neutral_stderr_line() {
        // Break caught: writing status text to stdout corrupts a redirected
        // protected artifact, while claiming creation misstates exact retries.
        let artifact = b"\0ASTRSDB1\nnot-status-text\xff".to_vec();
        let mut stdout = Vec::new();
        let mut stderr = Vec::new();
        super::write_success(
            CommandOutcome::Backup {
                generation: 7,
                artifact: Zeroizing::new(artifact.clone()),
            },
            &mut stdout,
            &mut stderr,
        )
        .expect("render backup success");
        assert_eq!(stdout, artifact);
        assert_eq!(stderr, b"BACKUP disposition=available generation=7\n");
    }

    #[test]
    fn partial_backup_stdout_write_returns_unavailable_and_a_binary_prefix() {
        // Break caught: treating a short artifact write as success could emit a
        // corrupt backup followed by a misleading success status.
        let artifact = backup_output_fixture();
        let mut stdout = FailingWriter::after(5, io::ErrorKind::Other);
        let mut stderr = Vec::new();
        assert_eq!(
            super::write_success(backup_outcome(), &mut stdout, &mut stderr)
                .expect_err("partial stdout write"),
            ProvisioningSecretStoreError::Unavailable
        );
        assert_eq!(stdout.bytes, artifact[..5]);
        assert!(stderr.is_empty());

        let (status, stdout, stderr) =
            execute_backup_with_writers(FailingWriter::after(5, io::ErrorKind::Other), Vec::new());
        assert_eq!(status, 1);
        assert_eq!(stdout.bytes, artifact[..5]);
        assert_eq!(stderr, b"ERROR provisioning secret store is unavailable\n");
    }

    #[test]
    fn backup_stdout_flush_failure_returns_unavailable_after_the_full_artifact() {
        // Break caught: reporting success before stdout flush can bless an
        // artifact whose final transport operation failed.
        let artifact = backup_output_fixture();
        let mut stdout = FailingWriter::on_flush();
        let mut stderr = Vec::new();
        assert_eq!(
            super::write_success(backup_outcome(), &mut stdout, &mut stderr)
                .expect_err("stdout flush failure"),
            ProvisioningSecretStoreError::Unavailable
        );
        assert_eq!(stdout.bytes, artifact);
        assert!(stderr.is_empty());

        let (status, stdout, stderr) =
            execute_backup_with_writers(FailingWriter::on_flush(), Vec::new());
        assert_eq!(status, 1);
        assert_eq!(stdout.bytes, artifact);
        assert_eq!(stderr, b"ERROR provisioning secret store is unavailable\n");
    }

    #[test]
    fn backup_stderr_status_failure_returns_unavailable_after_artifact_flush() {
        // Break caught: moving the status write before the artifact flush can
        // claim availability while stdout is incomplete.
        let artifact = backup_output_fixture();
        let mut stdout = Vec::new();
        let mut stderr = FailingWriter::after(7, io::ErrorKind::Other);
        assert_eq!(
            super::write_success(backup_outcome(), &mut stdout, &mut stderr)
                .expect_err("stderr status failure"),
            ProvisioningSecretStoreError::Unavailable
        );
        assert_eq!(stdout, artifact);
        assert_eq!(stderr.bytes, b"BACKUP ");

        let (status, stdout, stderr) =
            execute_backup_with_writers(Vec::new(), FailingWriter::after(7, io::ErrorKind::Other));
        assert_eq!(status, 1);
        assert_eq!(stdout, artifact);
        assert_eq!(stderr.bytes, b"BACKUP ");
    }

    #[test]
    fn backup_broken_pipe_returns_unavailable_without_status_or_stdout_text() {
        // Break caught: a broken output pipe must produce a nonzero result and
        // must never redirect the textual backup status into stdout.
        let mut stdout = FailingWriter::after(0, io::ErrorKind::BrokenPipe);
        let mut stderr = Vec::new();
        assert_eq!(
            super::write_success(backup_outcome(), &mut stdout, &mut stderr)
                .expect_err("broken stdout pipe"),
            ProvisioningSecretStoreError::Unavailable
        );
        assert!(stdout.bytes.is_empty());
        assert!(stderr.is_empty());

        let (status, stdout, stderr) = execute_backup_with_writers(
            FailingWriter::after(0, io::ErrorKind::BrokenPipe),
            Vec::new(),
        );
        assert_eq!(status, 1);
        assert!(stdout.bytes.is_empty());
        assert_eq!(stderr, b"ERROR provisioning secret store is unavailable\n");
    }

    fn backup_output_fixture() -> Vec<u8> {
        vec![0x00, 0xff, b'A', b'S', b'T', b'R', 0x01, b'\n', 0x80]
    }

    fn backup_outcome() -> CommandOutcome {
        CommandOutcome::Backup {
            generation: 9,
            artifact: Zeroizing::new(backup_output_fixture()),
        }
    }

    fn execute_backup_with_writers<O: Write, E: Write>(
        mut stdout: O,
        mut stderr: E,
    ) -> (i32, O, E) {
        let status = execute_with(
            operation_arguments("backup"),
            Cursor::new(Vec::<u8>::new()),
            &mut stdout,
            &mut stderr,
            |mode, prepared| {
                assert_eq!(mode, OpenMode::Normal);
                assert!(matches!(prepared, PreparedCommand::Backup { .. }));
                Ok(backup_outcome())
            },
        );
        (status, stdout, stderr)
    }

    struct FailingWriter {
        bytes: Vec<u8>,
        remaining: usize,
        error_kind: io::ErrorKind,
        flush_fails: bool,
    }

    impl FailingWriter {
        fn after(remaining: usize, error_kind: io::ErrorKind) -> Self {
            Self {
                bytes: Vec::new(),
                remaining,
                error_kind,
                flush_fails: false,
            }
        }

        fn on_flush() -> Self {
            Self {
                bytes: Vec::new(),
                remaining: usize::MAX,
                error_kind: io::ErrorKind::Other,
                flush_fails: true,
            }
        }
    }

    impl Write for FailingWriter {
        fn write(&mut self, input: &[u8]) -> io::Result<usize> {
            if self.remaining == 0 {
                return Err(io::Error::from(self.error_kind));
            }
            let written = input.len().min(self.remaining);
            self.bytes.extend_from_slice(&input[..written]);
            self.remaining -= written;
            Ok(written)
        }

        fn flush(&mut self) -> io::Result<()> {
            if self.flush_fails {
                Err(io::Error::from(self.error_kind))
            } else {
                Ok(())
            }
        }
    }

    #[test]
    fn process_boundary_orders_validation_and_sanitizes_provider_failures_and_backup_output() {
        // Break caught: refactoring main can open the provider before complete
        // validation, expose backend detail, or mix backup status into stdout.
        for scenario in [
            "secret-path-before-open",
            "secret-env-before-open",
            "missing-install-before-open",
            "oversized-install-before-open",
            "missing-recover-before-open",
            "oversized-recover-before-open",
            "provider-unavailable",
            "provider-rejected",
            "provider-invalid-reference",
            "provider-too-large",
            "provider-operation-conflict",
            "provider-not-found",
            "provider-destroyed",
            "backup-success",
        ] {
            let root = ProcessFixture::new(scenario);
            let output = ProcessCommand::new(std::env::current_exe().expect("test executable"))
                .args([
                    "--exact",
                    "tests::cli_process_worker",
                    "--nocapture",
                    "--quiet",
                    "--test-threads=1",
                ])
                .env("ASTER_ADMIN_CLI_PROCESS_SCENARIO", scenario)
                .env("ASTER_ADMIN_CLI_PROCESS_STDOUT", root.stdout())
                .env("ASTER_ADMIN_CLI_PROCESS_STDERR", root.stderr())
                .output()
                .expect("run CLI process worker");
            assert!(
                output.status.success(),
                "worker failed: stdout={} stderr={}",
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr)
            );
            let stdout = fs::read(root.stdout()).expect("read captured CLI stdout");
            let stderr = fs::read(root.stderr()).expect("read captured CLI stderr");
            if scenario == "backup-success" {
                assert_eq!(stdout, b"\0protected\nartifact\xff");
                assert_eq!(stderr, b"BACKUP disposition=available generation=9\n");
            } else {
                assert!(stdout.is_empty());
                assert_eq!(stderr, expected_process_error(scenario));
            }
        }
    }

    fn expected_process_error(scenario: &str) -> &'static [u8] {
        match scenario {
            "secret-path-before-open"
            | "secret-env-before-open"
            | "missing-install-before-open"
            | "missing-recover-before-open"
            | "provider-rejected" => b"ERROR provisioning secret store rejected the request\n",
            "oversized-install-before-open"
            | "oversized-recover-before-open"
            | "provider-too-large" => b"ERROR provisioning secret value exceeds its size limit\n",
            "provider-unavailable" => b"ERROR provisioning secret store is unavailable\n",
            "provider-invalid-reference" => b"ERROR provisioning secret reference is invalid\n",
            "provider-operation-conflict" => {
                b"ERROR provisioning secret operation conflicts with its durable record\n"
            }
            "provider-not-found" => b"ERROR provisioning secret reference was not found\n",
            "provider-destroyed" => {
                b"ERROR provisioning secret store reports the secret destroyed\n"
            }
            _ => panic!("scenario does not produce an error"),
        }
    }

    #[test]
    fn cli_process_worker() {
        let Some(scenario) = std::env::var_os("ASTER_ADMIN_CLI_PROCESS_SCENARIO") else {
            return;
        };
        let scenario = scenario.into_string().expect("UTF-8 scenario");
        let stdout_path =
            std::env::var_os("ASTER_ADMIN_CLI_PROCESS_STDOUT").expect("stdout capture path");
        let stderr_path =
            std::env::var_os("ASTER_ADMIN_CLI_PROCESS_STDERR").expect("stderr capture path");
        let mut stdout = fs::File::create(stdout_path).expect("create stdout capture");
        let mut stderr = fs::File::create(stderr_path).expect("create stderr capture");
        let (arguments, input) = match scenario.as_str() {
            "secret-path-before-open" => (
                vec![
                    "install".to_owned(),
                    "--input".to_owned(),
                    "/tmp/secret".to_owned(),
                ],
                Vec::new(),
            ),
            "secret-env-before-open" => (
                vec![
                    "rotate".to_owned(),
                    "--input-env".to_owned(),
                    "ASTER_SECRET".to_owned(),
                ],
                Vec::new(),
            ),
            "missing-install-before-open" => (install_arguments("install"), Vec::new()),
            "oversized-install-before-open" => (
                install_arguments("install"),
                vec![0; MAX_UNPROTECTED_PROVISIONING_BYTES + 1],
            ),
            "missing-recover-before-open" => (operation_arguments("recover"), Vec::new()),
            "oversized-recover-before-open" => (
                operation_arguments("recover"),
                vec![0; MAX_BACKUP_ARTIFACT_BYTES + 1],
            ),
            "provider-unavailable"
            | "provider-rejected"
            | "provider-invalid-reference"
            | "provider-too-large"
            | "provider-operation-conflict"
            | "provider-not-found"
            | "provider-destroyed"
            | "backup-success" => (operation_arguments("backup"), Vec::new()),
            _ => panic!("unknown process scenario"),
        };
        let mut called = false;
        let status = execute_with(
            arguments,
            Cursor::new(input),
            &mut stdout,
            &mut stderr,
            |mode, prepared| {
                called = true;
                assert_eq!(mode, OpenMode::Normal);
                assert!(matches!(prepared, PreparedCommand::Backup { .. }));
                match scenario.as_str() {
                    "provider-unavailable" => Err(ProvisioningSecretStoreError::Unavailable),
                    "provider-rejected" => Err(ProvisioningSecretStoreError::Rejected),
                    "provider-invalid-reference" => {
                        Err(ProvisioningSecretStoreError::InvalidReference)
                    }
                    "provider-too-large" => Err(ProvisioningSecretStoreError::TooLarge),
                    "provider-operation-conflict" => {
                        Err(ProvisioningSecretStoreError::OperationConflict)
                    }
                    "provider-not-found" => Err(ProvisioningSecretStoreError::NotFound),
                    "provider-destroyed" => Err(ProvisioningSecretStoreError::Destroyed),
                    "backup-success" => Ok(CommandOutcome::Backup {
                        generation: 9,
                        artifact: Zeroizing::new(b"\0protected\nartifact\xff".to_vec()),
                    }),
                    _ => Err(ProvisioningSecretStoreError::Unavailable),
                }
            },
        );
        assert_eq!(
            called,
            scenario.starts_with("provider-") || scenario == "backup-success"
        );
        assert_eq!(
            status,
            if called && scenario == "backup-success" {
                0
            } else {
                1
            }
        );
    }

    #[test]
    fn recover_prepares_artifact_before_requesting_the_recovery_open_mode() {
        // Break caught: opening through the ordinary constructor or before
        // bounded artifact validation prevents the supported repair path.
        let mut opened = false;
        let mut stdout = Vec::new();
        let mut stderr = Vec::new();
        let status = execute_with(
            operation_arguments("recover"),
            Cursor::new(canonical_backup_artifact()),
            &mut stdout,
            &mut stderr,
            |mode, prepared| {
                opened = true;
                assert_eq!(mode, OpenMode::Recovery);
                assert!(matches!(prepared, PreparedCommand::Recover { .. }));
                Ok(CommandOutcome::Recover {
                    disposition: RecoveryDisposition::Existing,
                    generation: 7,
                })
            },
        );
        assert_eq!(status, 0);
        assert!(opened);
        assert_eq!(stdout, b"RECOVER disposition=existing generation=7\n");
        assert!(stderr.is_empty());

        opened = false;
        stdout.clear();
        let status = execute_with(
            operation_arguments("recover"),
            Cursor::new(Vec::<u8>::new()),
            &mut stdout,
            &mut stderr,
            |_, _| {
                opened = true;
                Err(ProvisioningSecretStoreError::Unavailable)
            },
        );
        assert_eq!(status, 1);
        assert!(!opened);
    }

    fn canonical_backup_artifact() -> Vec<u8> {
        use sha2::{Digest as _, Sha256};

        let reference = reference().to_bytes();
        let ciphertext = b"protected-fixture";
        let ciphertext_digest: [u8; 32] = Sha256::digest(ciphertext).into();
        let mut manifest = Vec::new();
        manifest.extend_from_slice(b"ASTRSDM1\x00\x02\x00\x00");
        manifest.extend_from_slice(&7_u64.to_be_bytes());
        manifest.extend_from_slice(&LOAD_OPERATION);
        manifest.extend_from_slice(&ciphertext_digest);
        manifest.extend_from_slice(&(reference.len() as u32).to_be_bytes());
        manifest.extend_from_slice(&reference);
        let manifest_digest: [u8; 32] = Sha256::digest(&manifest).into();

        let mut artifact = Vec::new();
        artifact.extend_from_slice(b"ASTRSDB1\x00\x02\x00\x00");
        artifact.extend_from_slice(&OPERATION);
        artifact.extend_from_slice(&[0xa0; 32]);
        artifact.extend_from_slice(&7_u64.to_be_bytes());
        artifact.extend_from_slice(&LOAD_OPERATION);
        artifact.extend_from_slice(&(reference.len() as u32).to_be_bytes());
        artifact.extend_from_slice(&reference);
        artifact.extend_from_slice(&manifest_digest);
        artifact.extend_from_slice(&ciphertext_digest);
        artifact.extend_from_slice(&(ciphertext.len() as u32).to_be_bytes());
        artifact.extend_from_slice(ciphertext);
        artifact
    }

    struct ProcessFixture {
        root: PathBuf,
    }

    impl ProcessFixture {
        fn new(label: &str) -> Self {
            let root = std::env::temp_dir()
                .join(format!("aster-admin-cli-{label}-{}", std::process::id()));
            let _ = fs::remove_dir_all(&root);
            fs::create_dir(&root).expect("create process fixture");
            Self { root }
        }

        fn stdout(&self) -> PathBuf {
            self.root.join("stdout")
        }

        fn stderr(&self) -> PathBuf {
            self.root.join("stderr")
        }
    }

    impl Drop for ProcessFixture {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.root);
        }
    }

    struct PartialFailure {
        bytes: &'static [u8],
        delivered: bool,
    }

    impl PartialFailure {
        const fn new(bytes: &'static [u8]) -> Self {
            Self {
                bytes,
                delivered: false,
            }
        }
    }

    impl Read for PartialFailure {
        fn read(&mut self, output: &mut [u8]) -> io::Result<usize> {
            if self.delivered {
                return Err(io::Error::other("injected read failure"));
            }
            self.delivered = true;
            output[..self.bytes.len()].copy_from_slice(self.bytes);
            Ok(self.bytes.len())
        }
    }
}
