//! Root-operated administration command for the selected systemd provider.

#[cfg(target_os = "linux")]
use aster_mesh::{
    MAX_UNPROTECTED_PROVISIONING_BYTES, ProvisioningInstallDisposition, ProvisioningInstallId,
    ProvisioningLoadId, ProvisioningProtectionError, ProvisioningSecretStoreError,
    UnprotectedProvisioning,
};
#[cfg(target_os = "linux")]
use aster_systemd_credentials::admin::SystemdCredentialAdmin;
#[cfg(target_os = "linux")]
use std::{env, io::Read as _, process::ExitCode};

#[cfg(target_os = "linux")]
struct Invocation {
    install: ProvisioningInstallId,
    load: ProvisioningLoadId,
}

#[cfg(target_os = "linux")]
impl Invocation {
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
        if arguments.len() != 5
            || arguments[0] != "install"
            || arguments[1] != "--operation"
            || arguments[3] != "--load-operation"
        {
            return Err(ProvisioningSecretStoreError::Rejected);
        }
        Ok(Self {
            install: ProvisioningInstallId::new(parse_operation_id(&arguments[2])?),
            load: ProvisioningLoadId::new(parse_operation_id(&arguments[4])?),
        })
    }

    #[cfg(test)]
    const fn install_bytes(&self) -> [u8; 32] {
        *self.install.as_bytes()
    }

    #[cfg(test)]
    const fn load_bytes(&self) -> [u8; 32] {
        *self.load.as_bytes()
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
fn read_secret(
    mut input: impl std::io::Read,
) -> Result<UnprotectedProvisioning, ProvisioningSecretStoreError> {
    let mut bytes = Vec::new();
    input
        .by_ref()
        .take((MAX_UNPROTECTED_PROVISIONING_BYTES + 1) as u64)
        .read_to_end(&mut bytes)
        .map_err(|_| ProvisioningSecretStoreError::Unavailable)?;
    if bytes.len() > MAX_UNPROTECTED_PROVISIONING_BYTES {
        return Err(ProvisioningSecretStoreError::TooLarge);
    }
    UnprotectedProvisioning::new(bytes).map_err(|error| match error {
        ProvisioningProtectionError::TooLarge => ProvisioningSecretStoreError::TooLarge,
        ProvisioningProtectionError::Unavailable => ProvisioningSecretStoreError::Unavailable,
        ProvisioningProtectionError::Rejected => ProvisioningSecretStoreError::Rejected,
        _ => ProvisioningSecretStoreError::Rejected,
    })
}

#[cfg(target_os = "linux")]
fn run() -> Result<ProvisioningInstallDisposition, ProvisioningSecretStoreError> {
    let invocation = Invocation::parse_os(env::args_os().skip(1))?;
    let mut admin = SystemdCredentialAdmin::open()?;
    let plaintext = read_secret(std::io::stdin().lock())?;
    admin
        .install(invocation.install, invocation.load, plaintext)
        .map(|receipt| receipt.disposition())
}

#[cfg(target_os = "linux")]
fn main() -> ExitCode {
    match run() {
        Ok(ProvisioningInstallDisposition::Installed) => {
            println!("INSTALL disposition=installed");
            ExitCode::SUCCESS
        }
        Ok(ProvisioningInstallDisposition::Existing) => {
            println!("INSTALL disposition=existing");
            ExitCode::SUCCESS
        }
        Err(error) => {
            eprintln!("ERROR {error}");
            ExitCode::FAILURE
        }
    }
}

#[cfg(not(target_os = "linux"))]
fn main() -> std::process::ExitCode {
    eprintln!("ERROR provisioning secret store is unavailable");
    std::process::ExitCode::FAILURE
}

#[cfg(test)]
mod tests {
    use super::{Invocation, read_secret};
    use aster_mesh::{MAX_UNPROTECTED_PROVISIONING_BYTES, ProvisioningSecretStoreError};
    use std::io::Cursor;
    use std::os::unix::ffi::OsStringExt as _;

    fn valid_arguments() -> Vec<String> {
        vec![
            "install".to_owned(),
            "--operation".to_owned(),
            "11".repeat(32),
            "--load-operation".to_owned(),
            "22".repeat(32),
        ]
    }

    #[test]
    fn install_parser_accepts_only_two_exact_lowercase_operation_ids() {
        // Break caught: ambiguous or noncanonical identifiers could bind a
        // retry differently across administrators or parser versions.
        let invocation = Invocation::parse(valid_arguments()).expect("exact install invocation");
        assert_eq!(invocation.install_bytes(), [0x11; 32]);
        assert_eq!(invocation.load_bytes(), [0x22; 32]);

        for replacement in ["11".to_owned(), "AA".repeat(32), "gg".repeat(32)] {
            let mut arguments = valid_arguments();
            arguments[2] = replacement;
            assert!(Invocation::parse(arguments).is_err());
        }
    }

    #[test]
    fn parser_rejects_secret_paths_unknown_arguments_and_reordering() {
        // Break caught: accepting an input pathname or flexible trailing
        // arguments creates an unsupported plaintext or ambiguity surface.
        assert!(
            Invocation::parse(vec![
                "install".to_owned(),
                "--input".to_owned(),
                "/tmp/bundle".to_owned(),
            ])
            .is_err()
        );
        let mut unknown = valid_arguments();
        unknown.push("--verbose".to_owned());
        assert!(Invocation::parse(unknown).is_err());
        let mut reordered = valid_arguments();
        reordered.swap(1, 3);
        assert!(Invocation::parse(reordered).is_err());
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
    fn non_utf8_arguments_are_rejected_without_a_panic() {
        // Break caught: `env::args` panics on non-UTF-8 input before the
        // command can return its fixed sanitized rejection category.
        let arguments = vec![std::ffi::OsString::from_vec(vec![0xff])];
        let error = Invocation::parse_os(arguments)
            .err()
            .expect("non-UTF-8 argument must fail");
        assert_eq!(error, ProvisioningSecretStoreError::Rejected);
    }
}
