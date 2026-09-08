use aster_mesh::{MAX_PROTECTED_PROVISIONING_BYTES, ProvisioningSecretStoreError};
use std::{
    io::{Read as _, Write as _},
    path::PathBuf,
    process::{Command, Stdio},
    thread,
};
use zeroize::Zeroizing;

#[derive(Debug)]
pub(super) struct SystemdCredsEncryptor {
    program: PathBuf,
}

impl SystemdCredsEncryptor {
    pub(super) fn new() -> Self {
        Self {
            program: PathBuf::from("/usr/bin/systemd-creds"),
        }
    }

    #[cfg(test)]
    pub(super) fn at(program: PathBuf) -> Self {
        Self { program }
    }

    pub(super) fn encrypt(
        &mut self,
        envelope: Zeroizing<Vec<u8>>,
    ) -> Result<Vec<u8>, ProvisioningSecretStoreError> {
        let mut child = Command::new(&self.program)
            .args([
                "encrypt",
                "--with-key=host",
                "--name=aster-provisioning.bundle",
                "-",
                "-",
            ])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .map_err(|_| ProvisioningSecretStoreError::Unavailable)?;
        let stdout = child
            .stdout
            .take()
            .ok_or(ProvisioningSecretStoreError::Unavailable)?;
        let reader = thread::spawn(move || {
            let mut ciphertext = Vec::new();
            stdout
                .take((MAX_PROTECTED_PROVISIONING_BYTES + 1) as u64)
                .read_to_end(&mut ciphertext)
                .map(|_| ciphertext)
        });

        let write_result = child
            .stdin
            .take()
            .ok_or(ProvisioningSecretStoreError::Unavailable)
            .and_then(|mut input| {
                input
                    .write_all(&envelope)
                    .map_err(|_| ProvisioningSecretStoreError::Unavailable)
            });
        drop(envelope);
        let status = child
            .wait()
            .map_err(|_| ProvisioningSecretStoreError::Unavailable)?;
        let ciphertext = reader
            .join()
            .map_err(|_| ProvisioningSecretStoreError::Unavailable)?
            .map_err(|_| ProvisioningSecretStoreError::Unavailable)?;
        if !status.success() {
            return Err(ProvisioningSecretStoreError::Rejected);
        }
        write_result?;
        if ciphertext.len() > MAX_PROTECTED_PROVISIONING_BYTES {
            return Err(ProvisioningSecretStoreError::TooLarge);
        }
        if ciphertext.is_empty() {
            return Err(ProvisioningSecretStoreError::Rejected);
        }
        Ok(ciphertext)
    }
}

#[cfg(test)]
mod tests {
    use super::{super::TEST_PROCESS_SPAWN_LOCK, SystemdCredsEncryptor};
    use aster_mesh::ProvisioningSecretStoreError;
    use std::{
        fs,
        os::unix::fs::PermissionsExt as _,
        path::PathBuf,
        sync::atomic::{AtomicU64, Ordering},
    };
    use zeroize::Zeroizing;

    static NEXT_FIXTURE: AtomicU64 = AtomicU64::new(0);

    #[test]
    fn encryptor_pipes_input_through_the_fixed_host_key_command() {
        // Break caught: adding a secret argument/path, omitting host-only key
        // selection, or changing the credential name fails in the executable.
        let _process_spawn_lock = TEST_PROCESS_SPAWN_LOCK
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let fixture = EncryptFixture::new(
            "test \"$#\" = 5\n\
             test \"$1\" = encrypt\n\
             test \"$2\" = --with-key=host\n\
             test \"$3\" = --name=aster-provisioning.bundle\n\
             test \"$4\" = -\n\
             test \"$5\" = -\n\
             printf cipher:\n\
             exec cat",
        );
        let mut encryptor = SystemdCredsEncryptor::at(fixture.program.clone());
        let ciphertext = encryptor
            .encrypt(Zeroizing::new(b"test-envelope".to_vec()))
            .expect("fixed encryption command");
        assert_eq!(ciphertext, b"cipher:test-envelope");
    }

    #[test]
    fn encryptor_rejects_failure_and_oversized_output() {
        // Break caught: accepting a failed child or buffering provider output
        // past the public protected-artifact bound weakens the admin boundary.
        let _process_spawn_lock = TEST_PROCESS_SPAWN_LOCK
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let failed = EncryptFixture::new("exit 9");
        assert_eq!(
            SystemdCredsEncryptor::at(failed.program.clone())
                .encrypt(Zeroizing::new(b"test-envelope".to_vec()))
                .expect_err("failed provider"),
            ProvisioningSecretStoreError::Rejected
        );

        let oversized = EncryptFixture::new("dd if=/dev/zero bs=1048577 count=1 2>/dev/null");
        assert_eq!(
            SystemdCredsEncryptor::at(oversized.program.clone())
                .encrypt(Zeroizing::new(b"test-envelope".to_vec()))
                .expect_err("oversized provider output"),
            ProvisioningSecretStoreError::TooLarge
        );
    }

    struct EncryptFixture {
        root: PathBuf,
        program: PathBuf,
    }

    impl EncryptFixture {
        fn new(body: &str) -> Self {
            let serial = NEXT_FIXTURE.fetch_add(1, Ordering::Relaxed);
            let root = std::env::temp_dir().join(format!(
                "aster-systemd-encrypt-test-{}-{serial}",
                std::process::id()
            ));
            fs::create_dir(&root).expect("create encryption fixture");
            let program = root.join("systemd-creds-test");
            fs::write(&program, format!("#!/bin/sh\n{body}\n")).expect("write fake provider");
            fs::set_permissions(&program, fs::Permissions::from_mode(0o700))
                .expect("make fake provider executable");
            Self { root, program }
        }
    }

    impl Drop for EncryptFixture {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.root);
        }
    }
}
