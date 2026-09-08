mod encrypt;
mod files;
mod ledger;

use crate::{PROVIDER_REFERENCE_ID_BYTES, encode_credential_envelope, provisioning_secret_ref};
use aster_mesh::{
    ProfileProvisioningBundle, ProvisioningInstallId, ProvisioningInstallReceipt,
    ProvisioningLoadId, ProvisioningSecretStoreError, UnprotectedProvisioning,
};
use encrypt::SystemdCredsEncryptor;
#[cfg(test)]
use files::FaultPoint;
use files::{
    ACTIVE_DIRECTORY, FaultInjector, GenerationManifest, LedgerWrite, STAGED_DIRECTORY,
    child_directory_exists, generation_matches, open_namespace_lock, open_secure_root,
    promote_staged_generation, read_generation_manifest, read_ledger, remove_staged_generation,
    write_ledger_atomically, write_staged_generation,
};
use ledger::{InstallPhase, InstallRecord, Retry, classify_retry, decode_record, encode_record};
use rustix::fd::OwnedFd;
use sha2::{Digest as _, Sha256};
use std::path::Path;
#[cfg(test)]
use std::path::PathBuf;
use zeroize::Zeroizing;

const PROVISIONING_ROOT: &str = "/etc/aster/provisioning";
const LEDGER_ROOT: &str = "/var/lib/aster/provisioning-systemd";

/// Root-operated administration capability for the selected systemd provider.
#[derive(Debug)]
pub struct SystemdCredentialAdmin {
    provisioning_root: OwnedFd,
    ledger_root: OwnedFd,
    _namespace_lock: OwnedFd,
    encryptor: SystemdCredsEncryptor,
    faults: FaultInjector,
}

impl SystemdCredentialAdmin {
    /// Opens the fixed Ubuntu provider namespace and acquires its exclusive lock.
    pub fn open() -> Result<Self, ProvisioningSecretStoreError> {
        if !rustix::process::geteuid().is_root() {
            return Err(ProvisioningSecretStoreError::Unavailable);
        }
        Self::open_paths(
            Path::new(PROVISIONING_ROOT),
            Path::new(LEDGER_ROOT),
            true,
            SystemdCredsEncryptor::new(),
            FaultInjector::disabled(),
        )
    }

    #[cfg(test)]
    fn open_for_test(
        provisioning_root: &Path,
        ledger_root: &Path,
        program: &Path,
    ) -> Result<Self, ProvisioningSecretStoreError> {
        Self::open_paths(
            provisioning_root,
            ledger_root,
            false,
            SystemdCredsEncryptor::at(PathBuf::from(program)),
            FaultInjector::disabled(),
        )
    }

    #[cfg(test)]
    fn open_for_test_with_fault(
        provisioning_root: &Path,
        ledger_root: &Path,
        program: &Path,
        point: FaultPoint,
    ) -> Result<Self, ProvisioningSecretStoreError> {
        Self::open_paths(
            provisioning_root,
            ledger_root,
            false,
            SystemdCredsEncryptor::at(PathBuf::from(program)),
            FaultInjector::at(point),
        )
    }

    fn open_paths(
        provisioning_path: &Path,
        ledger_path: &Path,
        require_ext4: bool,
        encryptor: SystemdCredsEncryptor,
        faults: FaultInjector,
    ) -> Result<Self, ProvisioningSecretStoreError> {
        let provisioning_root = open_secure_root(provisioning_path, require_ext4)?;
        let ledger_root = open_secure_root(ledger_path, require_ext4)?;
        let namespace_lock = open_namespace_lock(&ledger_root)?;
        let mut admin = Self {
            provisioning_root,
            ledger_root,
            _namespace_lock: namespace_lock,
            encryptor,
            faults,
        };
        admin.reconcile_namespace()?;
        Ok(admin)
    }

    fn reconcile_namespace(&mut self) -> Result<(), ProvisioningSecretStoreError> {
        let Some(encoded) = read_ledger(&self.ledger_root)? else {
            let staged = child_directory_exists(&self.provisioning_root, STAGED_DIRECTORY)?;
            let active = child_directory_exists(&self.provisioning_root, ACTIVE_DIRECTORY)?;
            let action = reconcile_action(
                None,
                if staged {
                    GenerationMatch::Unbound
                } else {
                    GenerationMatch::Absent
                },
                if active {
                    GenerationMatch::Unbound
                } else {
                    GenerationMatch::Absent
                },
            )?;
            if action == ReconcileAction::DiscardOrphanStage {
                remove_staged_generation(&self.provisioning_root)?;
            }
            return Ok(());
        };

        let record = decode_record(&encoded)?;
        let manifest = manifest_from_record(&record);
        let staged = generation_match(&self.provisioning_root, STAGED_DIRECTORY, &manifest)?;
        let active = generation_match(&self.provisioning_root, ACTIVE_DIRECTORY, &manifest)?;
        match reconcile_action(Some(record.phase), staged, active)? {
            ReconcileAction::PromoteStage => {
                promote_staged_generation(&self.provisioning_root, &mut self.faults)?;
                complete_record(&self.ledger_root, record, &mut self.faults)?;
            }
            ReconcileAction::CompleteActive => {
                if staged == GenerationMatch::Exact {
                    remove_staged_generation(&self.provisioning_root)?;
                }
                complete_record(&self.ledger_root, record, &mut self.faults)?;
            }
            ReconcileAction::Existing => {}
            ReconcileAction::Fresh | ReconcileAction::DiscardOrphanStage => {
                return Err(ProvisioningSecretStoreError::Rejected);
            }
        }
        Ok(())
    }

    /// Installs generation one or returns the exact committed operation.
    pub fn install(
        &mut self,
        operation: ProvisioningInstallId,
        load: ProvisioningLoadId,
        plaintext: UnprotectedProvisioning,
    ) -> Result<ProvisioningInstallReceipt, ProvisioningSecretStoreError> {
        ProfileProvisioningBundle::from_bytes(plaintext.expose())
            .map_err(|_| ProvisioningSecretStoreError::Rejected)?;

        if let Some(encoded) = read_ledger(&self.ledger_root)? {
            let record = decode_record(&encoded)?;
            let envelope = encode_credential_envelope(&record.secret_ref, load, &plaintext)?;
            let envelope_commitment = digest(&envelope);
            match classify_retry(&record, operation, load, envelope_commitment)? {
                Retry::Existing => {
                    let manifest = manifest_from_record(&record);
                    if !generation_matches(&self.provisioning_root, ACTIVE_DIRECTORY, &manifest)? {
                        return Err(ProvisioningSecretStoreError::Rejected);
                    }
                    return Ok(ProvisioningInstallReceipt::existing(
                        operation,
                        record.secret_ref,
                    ));
                }
            }
        }

        if read_generation_manifest(&self.provisioning_root, ACTIVE_DIRECTORY)?.is_some()
            || read_generation_manifest(&self.provisioning_root, STAGED_DIRECTORY)?.is_some()
        {
            return Err(ProvisioningSecretStoreError::Rejected);
        }

        let generation = 1;
        let mut reference_id = Zeroizing::new([0_u8; PROVIDER_REFERENCE_ID_BYTES]);
        getrandom::fill(&mut *reference_id)
            .map_err(|_| ProvisioningSecretStoreError::Unavailable)?;
        let secret_ref = provisioning_secret_ref(generation, *reference_id)?;
        let envelope = encode_credential_envelope(&secret_ref, load, &plaintext)?;
        let envelope_commitment = digest(&envelope);
        let ciphertext = self.encryptor.encrypt(envelope)?;
        let ciphertext_digest = digest(&ciphertext);
        let manifest = GenerationManifest {
            generation,
            load,
            secret_ref: secret_ref.clone(),
            ciphertext_digest,
        };
        let intent = InstallRecord {
            phase: InstallPhase::Intent,
            install: operation,
            load,
            secret_ref: secret_ref.clone(),
            generation,
            envelope_commitment,
            ciphertext_digest,
        };

        let encoded_manifest = Zeroizing::new(files::encode_manifest(&manifest));
        let encoded_reference = Zeroizing::new(secret_ref.to_bytes());
        write_staged_generation(
            &self.provisioning_root,
            &ciphertext,
            &encoded_reference,
            &encoded_manifest,
            &mut self.faults,
        )?;
        let encoded_intent = Zeroizing::new(encode_record(&intent));
        write_ledger_atomically(
            &self.ledger_root,
            &encoded_intent,
            LedgerWrite::Intent,
            &mut self.faults,
        )?;
        promote_staged_generation(&self.provisioning_root, &mut self.faults)?;
        let complete = InstallRecord {
            phase: InstallPhase::Complete,
            ..intent
        };
        let encoded_complete = Zeroizing::new(encode_record(&complete));
        write_ledger_atomically(
            &self.ledger_root,
            &encoded_complete,
            LedgerWrite::Complete,
            &mut self.faults,
        )?;
        Ok(ProvisioningInstallReceipt::installed(operation, secret_ref))
    }
}

fn manifest_from_record(record: &InstallRecord) -> GenerationManifest {
    GenerationManifest {
        generation: record.generation,
        load: record.load,
        secret_ref: record.secret_ref.clone(),
        ciphertext_digest: record.ciphertext_digest,
    }
}

fn generation_match(
    provisioning_root: &OwnedFd,
    name: &str,
    expected: &GenerationManifest,
) -> Result<GenerationMatch, ProvisioningSecretStoreError> {
    if read_generation_manifest(provisioning_root, name)?.is_none() {
        return Ok(GenerationMatch::Absent);
    }
    if generation_matches(provisioning_root, name, expected)? {
        Ok(GenerationMatch::Exact)
    } else {
        Ok(GenerationMatch::Mismatch)
    }
}

fn complete_record(
    ledger_root: &OwnedFd,
    record: InstallRecord,
    faults: &mut FaultInjector,
) -> Result<(), ProvisioningSecretStoreError> {
    let complete = InstallRecord {
        phase: InstallPhase::Complete,
        ..record
    };
    let encoded = Zeroizing::new(encode_record(&complete));
    write_ledger_atomically(ledger_root, &encoded, LedgerWrite::Complete, faults)
}

pub(super) fn digest(bytes: &[u8]) -> [u8; 32] {
    Sha256::digest(bytes).into()
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum GenerationMatch {
    Absent,
    Unbound,
    Exact,
    Mismatch,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ReconcileAction {
    Fresh,
    DiscardOrphanStage,
    PromoteStage,
    CompleteActive,
    Existing,
}

fn reconcile_action(
    phase: Option<InstallPhase>,
    staged: GenerationMatch,
    active: GenerationMatch,
) -> Result<ReconcileAction, ProvisioningSecretStoreError> {
    match (phase, staged, active) {
        (None, GenerationMatch::Absent, GenerationMatch::Absent) => Ok(ReconcileAction::Fresh),
        (None, GenerationMatch::Unbound, GenerationMatch::Absent) => {
            Ok(ReconcileAction::DiscardOrphanStage)
        }
        (Some(InstallPhase::Intent), GenerationMatch::Exact, GenerationMatch::Absent) => {
            Ok(ReconcileAction::PromoteStage)
        }
        (
            Some(InstallPhase::Intent),
            GenerationMatch::Absent | GenerationMatch::Exact,
            GenerationMatch::Exact,
        ) => Ok(ReconcileAction::CompleteActive),
        (Some(InstallPhase::Complete), GenerationMatch::Absent, GenerationMatch::Exact) => {
            Ok(ReconcileAction::Existing)
        }
        _ => Err(ProvisioningSecretStoreError::Rejected),
    }
}

/// Exercises the durable administration record decoders for hostile-input testing.
#[cfg(feature = "fuzzing")]
#[doc(hidden)]
pub fn fuzz_decode_admin_records(encoded: &[u8]) -> (bool, bool) {
    (
        ledger::decode_record(encoded).is_ok(),
        files::decode_manifest(encoded).is_ok(),
    )
}

#[cfg(test)]
mod tests {
    use super::{GenerationMatch, ReconcileAction, SystemdCredentialAdmin, reconcile_action};
    use crate::admin::{
        files::{FaultPoint, decode_manifest},
        ledger::{InstallPhase, decode_record, encode_record},
    };
    use aster_mesh::{
        ProvisioningInstallDisposition, ProvisioningInstallId, ProvisioningLoadId,
        ProvisioningSecretStoreError, UnprotectedProvisioning,
    };
    use std::{
        fs,
        os::unix::fs::{PermissionsExt as _, symlink},
        path::{Path, PathBuf},
        sync::atomic::{AtomicU64, Ordering},
    };

    const INSTALL: ProvisioningInstallId = ProvisioningInstallId::new([0x11; 32]);
    const LOAD: ProvisioningLoadId = ProvisioningLoadId::new([0x22; 32]);
    static NEXT_FIXTURE: AtomicU64 = AtomicU64::new(0);

    #[test]
    fn reconciliation_promotes_or_completes_only_an_exact_generation() {
        // Break caught: recovering from presence alone could activate a
        // partial or unrelated credential after a crash.
        assert_eq!(
            reconcile_action(
                Some(InstallPhase::Intent),
                GenerationMatch::Exact,
                GenerationMatch::Absent
            )
            .expect("matching stage"),
            ReconcileAction::PromoteStage
        );
        assert_eq!(
            reconcile_action(
                Some(InstallPhase::Intent),
                GenerationMatch::Absent,
                GenerationMatch::Exact
            )
            .expect("matching active"),
            ReconcileAction::CompleteActive
        );
        assert_eq!(
            reconcile_action(
                Some(InstallPhase::Complete),
                GenerationMatch::Absent,
                GenerationMatch::Exact
            )
            .expect("complete active"),
            ReconcileAction::Existing
        );
    }

    #[test]
    fn reconciliation_discards_only_an_orphan_stage_without_a_ledger() {
        // Break caught: deleting staged state while an intent exists loses the
        // only recoverable copy; trusting a stage without an intent invents a
        // durable operation binding.
        assert_eq!(
            reconcile_action(None, GenerationMatch::Unbound, GenerationMatch::Absent)
                .expect("orphan stage"),
            ReconcileAction::DiscardOrphanStage
        );
        assert_eq!(
            reconcile_action(None, GenerationMatch::Absent, GenerationMatch::Absent)
                .expect("empty namespace"),
            ReconcileAction::Fresh
        );
        for state in [GenerationMatch::Unbound, GenerationMatch::Mismatch] {
            assert_eq!(
                reconcile_action(Some(InstallPhase::Intent), state, GenerationMatch::Absent)
                    .expect_err("mismatched intent"),
                ProvisioningSecretStoreError::Rejected
            );
        }
    }

    #[test]
    fn initial_install_commits_one_exact_active_generation() {
        // Break caught: returning success before the ciphertext, reference,
        // manifest, and complete ledger agree exposes a partial generation.
        let fixture = AdminFixture::new();
        let receipt = fixture
            .admin()
            .expect("open admin")
            .install(INSTALL, LOAD, fixture.bundle())
            .expect("install fixture");
        assert_eq!(
            receipt.disposition(),
            ProvisioningInstallDisposition::Installed
        );
        assert_eq!(
            fs::read(fixture.provisioning.join("active/reference")).expect("active reference"),
            receipt.secret_ref().to_bytes()
        );
        let manifest = decode_manifest(
            &fs::read(fixture.provisioning.join("active/manifest")).expect("active manifest"),
        )
        .expect("canonical active manifest");
        assert_eq!(manifest.secret_ref, *receipt.secret_ref());
        assert_eq!(manifest.generation, 1);
        assert_eq!(manifest.load, LOAD);
        assert_eq!(fixture.encrypt_calls(), 1);
        assert!(!fixture.provisioning.join("staged").exists());
    }

    #[test]
    fn reopen_returns_existing_without_a_second_encryption() {
        // Break caught: retrying a committed operation through the provider
        // again creates new ciphertext and defeats exact idempotency.
        let fixture = AdminFixture::new();
        let first_ref = {
            let receipt = fixture
                .admin()
                .expect("first admin")
                .install(INSTALL, LOAD, fixture.bundle())
                .expect("first install");
            receipt.secret_ref().clone()
        };
        let replay = fixture
            .admin()
            .expect("reopen admin")
            .install(INSTALL, LOAD, fixture.bundle())
            .expect("exact retry");
        assert_eq!(
            replay.disposition(),
            ProvisioningInstallDisposition::Existing
        );
        assert_eq!(replay.secret_ref(), &first_ref);
        assert_eq!(fixture.encrypt_calls(), 1);

        assert_eq!(
            fixture
                .admin()
                .expect("conflict admin")
                .install(
                    INSTALL,
                    ProvisioningLoadId::new([0x77; 32]),
                    fixture.bundle(),
                )
                .expect_err("changed load operation"),
            ProvisioningSecretStoreError::OperationConflict
        );
        assert_eq!(fixture.encrypt_calls(), 1);
    }

    #[test]
    fn invalid_bundle_and_concurrent_admin_fail_before_encryption() {
        // Break caught: reading/provider work before validation or namespace
        // serialization permits mutations that have no durable operation.
        let fixture = AdminFixture::new();
        let first = fixture.admin().expect("first admin holds lock");
        assert_eq!(
            fixture.admin().expect_err("concurrent admin"),
            ProvisioningSecretStoreError::Unavailable
        );
        drop(first);

        assert_eq!(
            fixture
                .admin()
                .expect("validated admin")
                .install(
                    INSTALL,
                    LOAD,
                    UnprotectedProvisioning::new(b"not-a-canonical-bundle".to_vec())
                        .expect("bounded invalid fixture"),
                )
                .expect_err("invalid bundle"),
            ProvisioningSecretStoreError::Rejected
        );
        assert_eq!(fixture.encrypt_calls(), 0);
        assert!(!fixture.provisioning.join("active").exists());
    }

    #[test]
    fn reopen_completes_an_intent_with_an_exact_active_generation() {
        // Break caught: a crash after active rename but before ledger
        // completion must not force re-encryption or strand a valid install.
        let fixture = AdminFixture::new();
        fixture.install_once();
        fixture.set_ledger_phase(InstallPhase::Intent);

        let replay = fixture
            .admin()
            .expect("reconcile active intent")
            .install(INSTALL, LOAD, fixture.bundle())
            .expect("replay reconciled install");
        assert_eq!(
            replay.disposition(),
            ProvisioningInstallDisposition::Existing
        );
        assert_eq!(fixture.ledger_phase(), InstallPhase::Complete);
        assert_eq!(fixture.encrypt_calls(), 1);
    }

    #[test]
    fn reopen_promotes_an_exact_staged_intent_without_reencrypting() {
        // Break caught: a crash after durable intent but before active rename
        // must promote the exact staged ciphertext rather than regenerate it.
        let fixture = AdminFixture::new();
        fixture.install_once();
        fixture.set_ledger_phase(InstallPhase::Intent);
        fs::rename(
            fixture.provisioning.join("active"),
            fixture.provisioning.join("staged"),
        )
        .expect("simulate pre-rename crash");

        let replay = fixture
            .admin()
            .expect("reconcile staged intent")
            .install(INSTALL, LOAD, fixture.bundle())
            .expect("replay promoted install");
        assert_eq!(
            replay.disposition(),
            ProvisioningInstallDisposition::Existing
        );
        assert!(fixture.provisioning.join("active").is_dir());
        assert!(!fixture.provisioning.join("staged").exists());
        assert_eq!(fixture.ledger_phase(), InstallPhase::Complete);
        assert_eq!(fixture.encrypt_calls(), 1);
    }

    #[test]
    fn reopen_discards_only_an_orphan_stage_before_a_fresh_install() {
        // Break caught: trusting a stage without its durable intent invents an
        // operation; leaving it in place permanently blocks a safe reinstall.
        let fixture = AdminFixture::new();
        fixture.install_once();
        fs::rename(
            fixture.provisioning.join("active"),
            fixture.provisioning.join("staged"),
        )
        .expect("create orphan stage");
        fs::remove_file(fixture.ledger.join("ledger")).expect("remove ledger fixture");

        let receipt = fixture
            .admin()
            .expect("discard orphan")
            .install(INSTALL, LOAD, fixture.bundle())
            .expect("fresh install");
        assert_eq!(
            receipt.disposition(),
            ProvisioningInstallDisposition::Installed
        );
        assert!(fixture.provisioning.join("active").is_dir());
        assert!(!fixture.provisioning.join("staged").exists());
        assert_eq!(fixture.encrypt_calls(), 2);
    }

    #[test]
    fn reopen_discards_a_partial_orphan_stage_without_an_intent() {
        // Break caught: a crash during stage preparation must not leave a
        // partial unbound directory that permanently blocks future installs.
        let fixture = AdminFixture::new();
        let staged = fixture.provisioning.join("staged");
        fs::create_dir(&staged).expect("create partial stage");
        fs::set_permissions(&staged, fs::Permissions::from_mode(0o700))
            .expect("protect partial stage");
        let ciphertext = staged.join("credential.cred");
        fs::write(&ciphertext, b"partial").expect("write partial ciphertext");
        fs::set_permissions(&ciphertext, fs::Permissions::from_mode(0o600))
            .expect("protect partial ciphertext");

        let receipt = fixture
            .admin()
            .expect("discard partial stage")
            .install(INSTALL, LOAD, fixture.bundle())
            .expect("fresh install after partial stage");
        assert_eq!(
            receipt.disposition(),
            ProvisioningInstallDisposition::Installed
        );
        assert!(!fixture.provisioning.join("staged").exists());
        assert_eq!(fixture.encrypt_calls(), 1);
    }

    #[test]
    fn every_install_durability_boundary_recovers_from_the_actual_interruption() {
        // Break caught: recovery tests assembled from an already successful
        // install do not prove what the real syscall sequence leaves behind.
        let cases = [
            (
                FaultPoint::StageCiphertextSynced,
                None,
                None,
                true,
                false,
                2,
            ),
            (FaultPoint::StageReferenceSynced, None, None, true, false, 2),
            (FaultPoint::StageManifestSynced, None, None, true, false, 2),
            (FaultPoint::StageDirectorySynced, None, None, true, false, 2),
            (FaultPoint::StageParentSynced, None, None, true, false, 2),
            (
                FaultPoint::IntentFileSynced,
                None,
                Some(InstallPhase::Intent),
                true,
                false,
                2,
            ),
            (
                FaultPoint::IntentRenamed,
                Some(InstallPhase::Intent),
                None,
                true,
                false,
                1,
            ),
            (
                FaultPoint::IntentParentSynced,
                Some(InstallPhase::Intent),
                None,
                true,
                false,
                1,
            ),
            (
                FaultPoint::ActiveRenamed,
                Some(InstallPhase::Intent),
                None,
                false,
                true,
                1,
            ),
            (
                FaultPoint::ActiveParentSynced,
                Some(InstallPhase::Intent),
                None,
                false,
                true,
                1,
            ),
            (
                FaultPoint::CompleteFileSynced,
                Some(InstallPhase::Intent),
                Some(InstallPhase::Complete),
                false,
                true,
                1,
            ),
            (
                FaultPoint::CompleteRenamed,
                Some(InstallPhase::Complete),
                None,
                false,
                true,
                1,
            ),
            (
                FaultPoint::CompleteParentSynced,
                Some(InstallPhase::Complete),
                None,
                false,
                true,
                1,
            ),
        ];

        for (point, committed_phase, pending_phase, has_staged, has_active, expected_encryptions) in
            cases
        {
            let fixture = AdminFixture::new();
            let mut interrupted = fixture
                .admin_with_fault(point)
                .expect("open fault-injected admin");
            assert_eq!(
                interrupted
                    .install(INSTALL, LOAD, fixture.bundle())
                    .expect_err("injected durability failure"),
                ProvisioningSecretStoreError::Unavailable,
                "fault point {point:?}"
            );
            drop(interrupted);

            assert_eq!(
                fixture.optional_ledger_phase("ledger"),
                committed_phase,
                "committed ledger phase at {point:?}"
            );
            assert_eq!(
                fixture.optional_ledger_phase("ledger.next"),
                pending_phase,
                "pending ledger phase at {point:?}"
            );
            assert_eq!(
                fixture.provisioning.join("staged").exists(),
                has_staged,
                "staged generation at {point:?}"
            );
            assert_eq!(
                fixture.provisioning.join("active").exists(),
                has_active,
                "active generation at {point:?}"
            );

            let replay = fixture
                .admin()
                .expect("reconcile interrupted install")
                .install(INSTALL, LOAD, fixture.bundle())
                .expect("retry interrupted install");
            let expected_disposition = if committed_phase.is_some() {
                ProvisioningInstallDisposition::Existing
            } else {
                ProvisioningInstallDisposition::Installed
            };
            assert_eq!(replay.disposition(), expected_disposition, "{point:?}");
            assert_eq!(fixture.ledger_phase(), InstallPhase::Complete, "{point:?}");
            assert!(fixture.provisioning.join("active").is_dir(), "{point:?}");
            assert!(!fixture.provisioning.join("staged").exists(), "{point:?}");
            assert_eq!(fixture.encrypt_calls(), expected_encryptions, "{point:?}");
        }
    }

    #[test]
    fn unsafe_roots_and_lock_are_rejected_before_encryption() {
        // Break caught: following a root or lock symlink lets another pathname
        // redirect the supposedly fixed provider namespace.
        let fixture = AdminFixture::new();
        let linked = fixture.root.join("linked-provisioning");
        symlink(&fixture.provisioning, &linked).expect("create root symlink");
        assert_eq!(
            SystemdCredentialAdmin::open_for_test(&linked, &fixture.ledger, &fixture.program)
                .expect_err("symlinked root"),
            ProvisioningSecretStoreError::Rejected
        );

        fs::set_permissions(&fixture.provisioning, fs::Permissions::from_mode(0o755))
            .expect("broaden root mode");
        assert_eq!(
            fixture.admin().expect_err("broad root mode"),
            ProvisioningSecretStoreError::Rejected
        );
        fs::set_permissions(&fixture.provisioning, fs::Permissions::from_mode(0o700))
            .expect("restore root mode");

        let lock = fixture.ledger.join("lock");
        fs::write(fixture.root.join("lock-target"), []).expect("write lock target");
        symlink(fixture.root.join("lock-target"), &lock).expect("create lock symlink");
        assert_eq!(
            fixture.admin().expect_err("symlinked lock"),
            ProvisioningSecretStoreError::Rejected
        );
        assert_eq!(fixture.encrypt_calls(), 0);
    }

    #[test]
    fn mismatched_intent_is_rejected_and_retained() {
        // Break caught: completing or deleting a mismatched crash record hides
        // corruption and may bind the ledger to changed ciphertext.
        let fixture = AdminFixture::new();
        fixture.install_once();
        fixture.set_ledger_phase(InstallPhase::Intent);
        let ciphertext = fixture.provisioning.join("active/credential.cred");
        let mut changed = fs::read(&ciphertext).expect("read ciphertext fixture");
        changed[0] ^= 1;
        fs::write(&ciphertext, &changed).expect("corrupt ciphertext fixture");

        assert_eq!(
            fixture.admin().expect_err("mismatched active generation"),
            ProvisioningSecretStoreError::Rejected
        );
        assert_eq!(fixture.ledger_phase(), InstallPhase::Intent);
        assert_eq!(fs::read(ciphertext).expect("retained ciphertext"), changed);
        assert_eq!(fixture.encrypt_calls(), 1);
    }

    struct AdminFixture {
        root: PathBuf,
        provisioning: PathBuf,
        ledger: PathBuf,
        program: PathBuf,
        calls: PathBuf,
    }

    impl AdminFixture {
        fn new() -> Self {
            let serial = NEXT_FIXTURE.fetch_add(1, Ordering::Relaxed);
            let root = std::env::temp_dir().join(format!(
                "aster-systemd-admin-test-{}-{serial}",
                std::process::id()
            ));
            let provisioning = root.join("provisioning");
            let ledger = root.join("ledger");
            fs::create_dir_all(&provisioning).expect("create provisioning root");
            fs::create_dir_all(&ledger).expect("create ledger root");
            fs::set_permissions(&provisioning, fs::Permissions::from_mode(0o700))
                .expect("protect provisioning root");
            fs::set_permissions(&ledger, fs::Permissions::from_mode(0o700))
                .expect("protect ledger root");
            let calls = root.join("encrypt.calls");
            let program = root.join("systemd-creds-test");
            fs::write(
                &program,
                format!(
                    "#!/bin/sh\ntest \"$#\" = 5 || exit 91\nprintf x >> {}\nprintf cipher:\nexec cat\n",
                    calls.display()
                ),
            )
            .expect("write fake encryptor");
            fs::set_permissions(&program, fs::Permissions::from_mode(0o700))
                .expect("make fake encryptor executable");
            Self {
                root,
                provisioning,
                ledger,
                program,
                calls,
            }
        }

        fn admin(&self) -> Result<SystemdCredentialAdmin, ProvisioningSecretStoreError> {
            SystemdCredentialAdmin::open_for_test(&self.provisioning, &self.ledger, &self.program)
        }

        fn admin_with_fault(
            &self,
            point: FaultPoint,
        ) -> Result<SystemdCredentialAdmin, ProvisioningSecretStoreError> {
            SystemdCredentialAdmin::open_for_test_with_fault(
                &self.provisioning,
                &self.ledger,
                &self.program,
                point,
            )
        }

        fn bundle(&self) -> UnprotectedProvisioning {
            UnprotectedProvisioning::new(
                include_bytes!("../../../bindings/testdata/non-production-provisioning.bundle")
                    .to_vec(),
            )
            .expect("canonical fixture bundle")
        }

        fn encrypt_calls(&self) -> usize {
            fs::read(&self.calls).map_or(0, |calls| calls.len())
        }

        fn install_once(&self) {
            self.admin()
                .expect("fixture admin")
                .install(INSTALL, LOAD, self.bundle())
                .expect("fixture install");
        }

        fn set_ledger_phase(&self, phase: InstallPhase) {
            let path = self.ledger.join("ledger");
            let mut record = decode_record(&fs::read(&path).expect("read fixture ledger"))
                .expect("decode fixture ledger");
            record.phase = phase;
            fs::write(path, encode_record(&record)).expect("write fixture ledger");
        }

        fn ledger_phase(&self) -> InstallPhase {
            decode_record(&fs::read(self.ledger.join("ledger")).expect("read fixture ledger phase"))
                .expect("decode fixture ledger phase")
                .phase
        }

        fn optional_ledger_phase(&self, name: &str) -> Option<InstallPhase> {
            let path = self.ledger.join(name);
            path.exists().then(|| {
                decode_record(&fs::read(path).expect("read optional fixture ledger"))
                    .expect("decode optional fixture ledger")
                    .phase
            })
        }
    }

    impl Drop for AdminFixture {
        fn drop(&mut self) {
            let _ = remove_fixture(&self.root);
        }
    }

    fn remove_fixture(path: &Path) -> std::io::Result<()> {
        fs::remove_dir_all(path)
    }
}
