mod encrypt;
mod files;
mod ledger;
#[allow(dead_code)] // Shared lifecycle primitives are consumed by Tasks 3-5.
mod lifecycle;

#[cfg(test)]
pub(super) static TEST_PROCESS_SPAWN_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

use crate::{PROVIDER_REFERENCE_ID_BYTES, encode_credential_envelope, provisioning_secret_ref};
use aster_mesh::{
    ProfileProvisioningBundle, ProvisioningInstallId, ProvisioningInstallReceipt,
    ProvisioningLoadId, ProvisioningSecretStoreError, UnprotectedProvisioning,
};
use encrypt::SystemdCredsEncryptor;
#[cfg(test)]
use files::FaultPoint;
use files::{
    ACTIVE_DIRECTORY, FaultInjector, GenerationContent, GenerationManifest, LedgerWrite,
    STAGED_DIRECTORY, child_directory_exists, generation_matches, open_namespace_lock,
    open_secure_root, promote_staged_generation, read_generation_manifest, read_host_key_identity,
    read_ledger, remove_staged_generation, sync_recovered_active_parent, write_ledger_atomically,
    write_staged_generation,
};
use ledger::{
    GenerationRecord, GenerationState, LifecycleIntent, LifecycleIntentKind, ProviderLedger,
    decode_ledger, encode_ledger,
};
use rustix::fd::OwnedFd;
use sha2::{Digest as _, Sha256};
use std::path::Path;
#[cfg(test)]
use std::path::PathBuf;
use zeroize::Zeroizing;

const PROVISIONING_ROOT: &str = "/etc/aster/provisioning";
const LEDGER_ROOT: &str = "/var/lib/aster/provisioning-systemd";
const HOST_KEY_PATH: &str = "/var/lib/systemd/credential.secret";

/// Root-operated administration capability for the selected systemd provider.
#[derive(Debug)]
pub struct SystemdCredentialAdmin {
    provisioning_root: OwnedFd,
    ledger_root: OwnedFd,
    host_key_identity: [u8; 32],
    _namespace_lock: OwnedFd,
    encryptor: SystemdCredsEncryptor,
    faults: FaultInjector,
}

impl SystemdCredentialAdmin {
    /// Opens the fixed Raspberry Pi provider namespace and acquires its exclusive lock.
    pub fn open() -> Result<Self, ProvisioningSecretStoreError> {
        if !rustix::process::geteuid().is_root() {
            return Err(ProvisioningSecretStoreError::Unavailable);
        }
        Self::open_paths(
            Path::new(PROVISIONING_ROOT),
            Path::new(LEDGER_ROOT),
            Path::new(HOST_KEY_PATH),
            true,
            SystemdCredsEncryptor::new(),
            FaultInjector::disabled(),
        )
    }

    #[cfg(test)]
    fn open_for_test(
        provisioning_root: &Path,
        ledger_root: &Path,
        host_key_path: &Path,
        program: &Path,
    ) -> Result<Self, ProvisioningSecretStoreError> {
        Self::open_paths(
            provisioning_root,
            ledger_root,
            host_key_path,
            false,
            SystemdCredsEncryptor::at(PathBuf::from(program)),
            FaultInjector::disabled(),
        )
    }

    #[cfg(test)]
    fn open_for_test_with_fault(
        provisioning_root: &Path,
        ledger_root: &Path,
        host_key_path: &Path,
        program: &Path,
        point: FaultPoint,
    ) -> Result<Self, ProvisioningSecretStoreError> {
        Self::open_paths(
            provisioning_root,
            ledger_root,
            host_key_path,
            false,
            SystemdCredsEncryptor::at(PathBuf::from(program)),
            FaultInjector::at(point),
        )
    }

    fn open_paths(
        provisioning_path: &Path,
        ledger_path: &Path,
        host_key_path: &Path,
        require_ext4: bool,
        encryptor: SystemdCredsEncryptor,
        faults: FaultInjector,
    ) -> Result<Self, ProvisioningSecretStoreError> {
        let provisioning_root = open_secure_root(provisioning_path, require_ext4)?;
        let ledger_root = open_secure_root(ledger_path, require_ext4)?;
        let namespace_lock = open_namespace_lock(&ledger_root)?;
        let host_key_identity = read_host_key_identity(host_key_path)?;
        let mut admin = Self {
            provisioning_root,
            ledger_root,
            host_key_identity,
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

        let ledger = decode_ledger(&encoded)?;
        if ledger.host_key_identity != self.host_key_identity {
            return Err(ProvisioningSecretStoreError::Rejected);
        }
        if ledger.intent.is_none() {
            lifecycle::validate_completed_generations(&self.provisioning_root, &ledger)?;
            return Ok(());
        }
        let phase = if ledger.intent.is_some() {
            LedgerPhase::Intent
        } else {
            LedgerPhase::Complete
        };
        let manifest = manifest_from_ledger(&ledger)?;
        let staged = generation_match(&self.provisioning_root, STAGED_DIRECTORY, &manifest)?;
        let active = generation_match(&self.provisioning_root, ACTIVE_DIRECTORY, &manifest)?;
        match reconcile_action(Some(phase), staged, active)? {
            ReconcileAction::PromoteStage => {
                promote_staged_generation(&self.provisioning_root, &mut self.faults)?;
                complete_ledger(&self.ledger_root, ledger, &mut self.faults)?;
            }
            ReconcileAction::CompleteActive => {
                // The active rename may have reached this separate filesystem
                // without its parent fsync. Make it durable before committing
                // the operation in the ledger filesystem.
                sync_recovered_active_parent(&self.provisioning_root, &mut self.faults)?;
                if staged == GenerationMatch::Exact {
                    remove_staged_generation(&self.provisioning_root)?;
                }
                complete_ledger(&self.ledger_root, ledger, &mut self.faults)?;
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
            let ledger = decode_ledger(&encoded)?;
            let record = ledger
                .generations
                .iter()
                .find(|record| record.install == operation)
                .ok_or(ProvisioningSecretStoreError::OperationConflict)?;
            let envelope = encode_credential_envelope(&record.secret_ref, load, &plaintext)?;
            let envelope_commitment = digest(&envelope);
            if record.load != load || record.envelope_commitment != envelope_commitment {
                return Err(ProvisioningSecretStoreError::OperationConflict);
            }
            if record.state == GenerationState::Destroyed {
                return Err(ProvisioningSecretStoreError::Destroyed);
            }
            if record.state != GenerationState::Active {
                return Err(ProvisioningSecretStoreError::Rejected);
            }
            let manifest = manifest_from_record(record);
            if !generation_matches(&self.provisioning_root, ACTIVE_DIRECTORY, &manifest)? {
                return Err(ProvisioningSecretStoreError::Rejected);
            }
            return Ok(ProvisioningInstallReceipt::existing(
                operation,
                record.secret_ref.clone(),
            ));
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
            content: GenerationContent::Credential,
        };
        let intent = LifecycleIntent {
            kind: LifecycleIntentKind::Install,
            operation: *operation.as_bytes(),
            load: Some(load),
            target_ref: secret_ref.clone(),
            target_generation: generation,
            source_ref: None,
            envelope_commitment: Some(envelope_commitment),
            expected_ciphertext_digest: Some(ciphertext_digest),
            expected_artifact_digest: None,
            pre_mutation_ledger_revision: [0; 32],
        };
        let ledger = ProviderLedger {
            host_key_identity: self.host_key_identity,
            intent: Some(intent),
            generations: Vec::new(),
            backups: Vec::new(),
            recoveries: Vec::new(),
            destroys: Vec::new(),
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
        let encoded_intent = Zeroizing::new(encode_ledger(&ledger)?);
        write_ledger_atomically(
            &self.ledger_root,
            &encoded_intent,
            LedgerWrite::Intent,
            &mut self.faults,
        )?;
        promote_staged_generation(&self.provisioning_root, &mut self.faults)?;
        complete_ledger(&self.ledger_root, ledger, &mut self.faults)?;
        Ok(ProvisioningInstallReceipt::installed(operation, secret_ref))
    }
}

fn manifest_from_record(record: &GenerationRecord) -> GenerationManifest {
    GenerationManifest {
        generation: record.generation,
        load: record.load,
        secret_ref: record.secret_ref.clone(),
        ciphertext_digest: record.ciphertext_digest,
        content: if record.state == GenerationState::Destroyed {
            GenerationContent::Tombstone
        } else {
            GenerationContent::Credential
        },
    }
}

fn manifest_from_ledger(
    ledger: &ProviderLedger,
) -> Result<GenerationManifest, ProvisioningSecretStoreError> {
    if let Some(intent) = &ledger.intent {
        validate_install_intent(ledger, intent)?;
        return Ok(GenerationManifest {
            generation: intent.target_generation,
            load: intent.load.ok_or(ProvisioningSecretStoreError::Rejected)?,
            secret_ref: intent.target_ref.clone(),
            ciphertext_digest: intent
                .expected_ciphertext_digest
                .ok_or(ProvisioningSecretStoreError::Rejected)?,
            content: GenerationContent::Credential,
        });
    }
    let mut active = ledger
        .generations
        .iter()
        .filter(|record| record.state == GenerationState::Active);
    let record = active
        .next()
        .ok_or(ProvisioningSecretStoreError::Rejected)?;
    if active.next().is_some() {
        return Err(ProvisioningSecretStoreError::Rejected);
    }
    Ok(manifest_from_record(record))
}

fn validate_install_intent(
    ledger: &ProviderLedger,
    intent: &LifecycleIntent,
) -> Result<(), ProvisioningSecretStoreError> {
    if intent.kind != LifecycleIntentKind::Install
        || intent.target_generation != 1
        || intent.load.is_none()
        || intent.source_ref.is_some()
        || intent.envelope_commitment.is_none()
        || intent.expected_ciphertext_digest.is_none()
        || intent.expected_artifact_digest.is_some()
        || intent.pre_mutation_ledger_revision != [0; 32]
        || !ledger.generations.is_empty()
        || !ledger.backups.is_empty()
        || !ledger.recoveries.is_empty()
        || !ledger.destroys.is_empty()
    {
        return Err(ProvisioningSecretStoreError::Rejected);
    }
    Ok(())
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

fn complete_ledger(
    ledger_root: &OwnedFd,
    mut ledger: ProviderLedger,
    faults: &mut FaultInjector,
) -> Result<(), ProvisioningSecretStoreError> {
    let intent = ledger
        .intent
        .as_ref()
        .ok_or(ProvisioningSecretStoreError::Rejected)?;
    validate_install_intent(&ledger, intent)?;
    let intent = ledger
        .intent
        .take()
        .ok_or(ProvisioningSecretStoreError::Rejected)?;
    let record = GenerationRecord {
        install: ProvisioningInstallId::new(intent.operation),
        load: intent.load.ok_or(ProvisioningSecretStoreError::Rejected)?,
        secret_ref: intent.target_ref,
        generation: intent.target_generation,
        envelope_commitment: intent
            .envelope_commitment
            .ok_or(ProvisioningSecretStoreError::Rejected)?,
        ciphertext_digest: intent
            .expected_ciphertext_digest
            .ok_or(ProvisioningSecretStoreError::Rejected)?,
        state: GenerationState::Active,
    };
    ledger.generations.push(record);
    let encoded = Zeroizing::new(encode_ledger(&ledger)?);
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
enum LedgerPhase {
    Intent,
    Complete,
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
    phase: Option<LedgerPhase>,
    staged: GenerationMatch,
    active: GenerationMatch,
) -> Result<ReconcileAction, ProvisioningSecretStoreError> {
    match (phase, staged, active) {
        (None, GenerationMatch::Absent, GenerationMatch::Absent) => Ok(ReconcileAction::Fresh),
        (None, GenerationMatch::Unbound, GenerationMatch::Absent) => {
            Ok(ReconcileAction::DiscardOrphanStage)
        }
        (Some(LedgerPhase::Intent), GenerationMatch::Exact, GenerationMatch::Absent) => {
            Ok(ReconcileAction::PromoteStage)
        }
        (
            Some(LedgerPhase::Intent),
            GenerationMatch::Absent | GenerationMatch::Exact,
            GenerationMatch::Exact,
        ) => Ok(ReconcileAction::CompleteActive),
        (Some(LedgerPhase::Complete), GenerationMatch::Absent, GenerationMatch::Exact) => {
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
        ledger::decode_ledger(encoded).is_ok(),
        files::decode_manifest(encoded).is_ok(),
    )
}

#[cfg(test)]
mod tests {
    use super::{
        GenerationMatch, LedgerPhase, ReconcileAction, SystemdCredentialAdmin, reconcile_action,
    };
    use crate::admin::{
        files::{FaultPoint, decode_manifest},
        ledger::{
            GenerationRecord, GenerationState, LifecycleIntent, LifecycleIntentKind, decode_ledger,
            encode_ledger,
        },
    };
    use crate::provisioning_secret_ref;
    use aster_mesh::{
        ProvisioningInstallDisposition, ProvisioningInstallId, ProvisioningLoadId,
        ProvisioningSecretStoreError, UnprotectedProvisioning,
    };
    use std::{
        fs,
        os::unix::fs::{PermissionsExt as _, symlink},
        path::{Path, PathBuf},
        sync::{
            MutexGuard,
            atomic::{AtomicU64, Ordering},
        },
    };

    const INSTALL: ProvisioningInstallId = ProvisioningInstallId::new([0x11; 32]);
    const LOAD: ProvisioningLoadId = ProvisioningLoadId::new([0x22; 32]);
    const HOST_ID: [u8; 32] = [
        0x60, 0xbf, 0x07, 0xc4, 0x88, 0xaa, 0xd1, 0x8f, 0xda, 0x33, 0x9d, 0xf0, 0x7e, 0x4f, 0xbc,
        0x47, 0xb4, 0xf0, 0x0b, 0xe7, 0x17, 0x11, 0x93, 0x6f, 0x18, 0xd0, 0x4d, 0x35, 0x2a, 0xd0,
        0x18, 0x90,
    ];
    static NEXT_FIXTURE: AtomicU64 = AtomicU64::new(0);

    #[test]
    fn reconciliation_promotes_or_completes_only_an_exact_generation() {
        // Break caught: recovering from presence alone could activate a
        // partial or unrelated credential after a crash.
        assert_eq!(
            reconcile_action(
                Some(LedgerPhase::Intent),
                GenerationMatch::Exact,
                GenerationMatch::Absent
            )
            .expect("matching stage"),
            ReconcileAction::PromoteStage
        );
        assert_eq!(
            reconcile_action(
                Some(LedgerPhase::Intent),
                GenerationMatch::Absent,
                GenerationMatch::Exact
            )
            .expect("matching active"),
            ReconcileAction::CompleteActive
        );
        assert_eq!(
            reconcile_action(
                Some(LedgerPhase::Complete),
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
                reconcile_action(Some(LedgerPhase::Intent), state, GenerationMatch::Absent)
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
        let ledger =
            decode_ledger(&fs::read(fixture.ledger.join("ledger")).expect("read lifecycle ledger"))
                .expect("canonical lifecycle ledger");
        assert_eq!(ledger.host_key_identity, HOST_ID);
        assert!(ledger.intent.is_none());
        assert_eq!(ledger.generations.len(), 1);
        assert_eq!(ledger.generations[0].state, GenerationState::Active);
        assert_eq!(ledger.generations[0].secret_ref, *receipt.secret_ref());
        assert!(ledger.backups.is_empty());
        assert!(ledger.recoveries.is_empty());
        assert!(ledger.destroys.is_empty());
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
        fixture.set_ledger_phase(LedgerPhase::Intent);

        let replay = fixture
            .admin()
            .expect("reconcile active intent")
            .install(INSTALL, LOAD, fixture.bundle())
            .expect("replay reconciled install");
        assert_eq!(
            replay.disposition(),
            ProvisioningInstallDisposition::Existing
        );
        assert_eq!(fixture.ledger_phase(), LedgerPhase::Complete);
        assert_eq!(fixture.encrypt_calls(), 1);
    }

    #[test]
    fn recovered_active_intent_stays_pending_when_parent_sync_fails() {
        // Break caught: completing the ledger before the recovered active
        // rename is durable can expose a committed operation whose generation
        // disappears after a crash, including when the two roots differ.
        let fixture = AdminFixture::new();
        fixture.install_once();
        fixture.set_ledger_phase(LedgerPhase::Intent);

        assert_eq!(
            fixture
                .admin_with_fault(FaultPoint::RecoveredActiveParentSyncFailed)
                .expect_err("recovered active parent sync failure"),
            ProvisioningSecretStoreError::Unavailable
        );
        assert_eq!(fixture.ledger_phase(), LedgerPhase::Intent);
        assert!(fixture.provisioning.join("active").is_dir());
        assert!(!fixture.ledger.join("ledger.next").exists());
    }

    #[test]
    fn reopen_promotes_an_exact_staged_intent_without_reencrypting() {
        // Break caught: a crash after durable intent but before active rename
        // must promote the exact staged ciphertext rather than regenerate it.
        let fixture = AdminFixture::new();
        fixture.install_once();
        fixture.set_ledger_phase(LedgerPhase::Intent);
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
        assert_eq!(fixture.ledger_phase(), LedgerPhase::Complete);
        assert_eq!(fixture.encrypt_calls(), 1);
    }

    #[test]
    fn malformed_install_intent_preserves_duplicate_staged_generation() {
        // Break caught: validating the envelope commitment only after
        // reconciliation lets a malformed intent delete an exact staged copy
        // before the ledger is rejected.
        let fixture = AdminFixture::new();
        fixture.install_once();
        fixture.set_ledger_phase(LedgerPhase::Intent);
        fixture.copy_active_to_staged();
        let ledger_path = fixture.ledger.join("ledger");
        let mut ledger = decode_ledger(&fs::read(&ledger_path).expect("read fixture ledger"))
            .expect("decode fixture ledger");
        ledger
            .intent
            .as_mut()
            .expect("fixture intent")
            .envelope_commitment = None;
        let ledger_before = encode_ledger(&ledger).expect("encode malformed fixture ledger");
        fs::write(&ledger_path, &ledger_before).expect("write malformed fixture ledger");
        let active_before = fixture.generation_bytes("active");
        let staged_before = fixture.generation_bytes("staged");

        assert_eq!(
            fixture.admin().expect_err("missing envelope commitment"),
            ProvisioningSecretStoreError::Rejected
        );
        assert_eq!(
            fs::read(&ledger_path).expect("retained ledger"),
            ledger_before
        );
        assert_eq!(fixture.generation_bytes("active"), active_before);
        assert_eq!(fixture.generation_bytes("staged"), staged_before);
    }

    #[test]
    fn install_intent_with_retained_generation_preserves_staged_generation() {
        // Break caught: checking the empty-generation prerequisite only after
        // promotion can move staged ciphertext into Active before rejecting a
        // contradictory Install intent.
        let fixture = AdminFixture::new();
        fixture.install_once();
        fixture.set_ledger_phase(LedgerPhase::Intent);
        fs::rename(
            fixture.provisioning.join("active"),
            fixture.provisioning.join("staged"),
        )
        .expect("simulate pre-rename crash");
        let ledger_path = fixture.ledger.join("ledger");
        let mut ledger = decode_ledger(&fs::read(&ledger_path).expect("read fixture ledger"))
            .expect("decode fixture ledger");
        ledger.generations.push(GenerationRecord {
            install: ProvisioningInstallId::new([0x91; 32]),
            load: ProvisioningLoadId::new([0x92; 32]),
            secret_ref: provisioning_secret_ref(9, [0x93; 32])
                .expect("unexpected retained reference"),
            generation: 9,
            envelope_commitment: [0x94; 32],
            ciphertext_digest: [0; 32],
            state: GenerationState::Destroyed,
        });
        let ledger_before = encode_ledger(&ledger).expect("encode contradictory fixture ledger");
        fs::write(&ledger_path, &ledger_before).expect("write contradictory fixture ledger");
        let staged_before = fixture.generation_bytes("staged");

        assert_eq!(
            fixture.admin().expect_err("unexpected retained generation"),
            ProvisioningSecretStoreError::Rejected
        );
        assert_eq!(
            fs::read(&ledger_path).expect("retained ledger"),
            ledger_before
        );
        assert!(!fixture.provisioning.join("active").exists());
        assert_eq!(fixture.generation_bytes("staged"), staged_before);
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
                Some(LedgerPhase::Intent),
                true,
                false,
                2,
            ),
            (
                FaultPoint::IntentRenamed,
                Some(LedgerPhase::Intent),
                None,
                true,
                false,
                1,
            ),
            (
                FaultPoint::IntentParentSynced,
                Some(LedgerPhase::Intent),
                None,
                true,
                false,
                1,
            ),
            (
                FaultPoint::ActiveRenamed,
                Some(LedgerPhase::Intent),
                None,
                false,
                true,
                1,
            ),
            (
                FaultPoint::ActiveParentSynced,
                Some(LedgerPhase::Intent),
                None,
                false,
                true,
                1,
            ),
            (
                FaultPoint::CompleteFileSynced,
                Some(LedgerPhase::Intent),
                Some(LedgerPhase::Complete),
                false,
                true,
                1,
            ),
            (
                FaultPoint::CompleteRenamed,
                Some(LedgerPhase::Complete),
                None,
                false,
                true,
                1,
            ),
            (
                FaultPoint::CompleteParentSynced,
                Some(LedgerPhase::Complete),
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
            assert_eq!(fixture.ledger_phase(), LedgerPhase::Complete, "{point:?}");
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
            SystemdCredentialAdmin::open_for_test(
                &linked,
                &fixture.ledger,
                &fixture.host_key,
                &fixture.program,
            )
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
    fn existing_ledger_rejects_a_changed_host_key_identity() {
        // Break caught: accepting an intact ledger under another systemd host
        // key could let later recovery reach provider decrypt on the wrong host.
        let fixture = AdminFixture::new();
        fixture.install_once();
        fs::write(&fixture.host_key, [0x6b; 32]).expect("replace host-key fixture");
        assert_eq!(
            fixture.admin().expect_err("changed host key"),
            ProvisioningSecretStoreError::Rejected
        );
        assert_eq!(fixture.encrypt_calls(), 1);
    }

    #[test]
    fn missing_host_key_is_unavailable_before_install() {
        // Break caught: treating a missing identity as an empty/default key
        // would create a ledger that cannot prove same-host recovery.
        let fixture = AdminFixture::new();
        fs::remove_file(&fixture.host_key).expect("remove host-key fixture");
        assert_eq!(
            fixture.admin().expect_err("missing host key"),
            ProvisioningSecretStoreError::Unavailable
        );
        assert_eq!(fixture.encrypt_calls(), 0);
    }

    #[test]
    fn mismatched_intent_is_rejected_and_retained() {
        // Break caught: completing or deleting a mismatched crash record hides
        // corruption and may bind the ledger to changed ciphertext.
        let fixture = AdminFixture::new();
        fixture.install_once();
        fixture.set_ledger_phase(LedgerPhase::Intent);
        let ciphertext = fixture.provisioning.join("active/credential.cred");
        let mut changed = fs::read(&ciphertext).expect("read ciphertext fixture");
        changed[0] ^= 1;
        fs::write(&ciphertext, &changed).expect("corrupt ciphertext fixture");

        assert_eq!(
            fixture.admin().expect_err("mismatched active generation"),
            ProvisioningSecretStoreError::Rejected
        );
        assert_eq!(fixture.ledger_phase(), LedgerPhase::Intent);
        assert_eq!(fs::read(ciphertext).expect("retained ciphertext"), changed);
        assert_eq!(fixture.encrypt_calls(), 1);
    }

    struct AdminFixture {
        _process_spawn_lock: MutexGuard<'static, ()>,
        root: PathBuf,
        provisioning: PathBuf,
        ledger: PathBuf,
        host_key: PathBuf,
        program: PathBuf,
        calls: PathBuf,
    }

    impl AdminFixture {
        fn new() -> Self {
            let process_spawn_lock = super::TEST_PROCESS_SPAWN_LOCK
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
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
            let host_key = root.join("credential.secret");
            fs::write(&host_key, [0x5a; 32]).expect("write host-key fixture");
            fs::set_permissions(&host_key, fs::Permissions::from_mode(0o600))
                .expect("protect host-key fixture");
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
                _process_spawn_lock: process_spawn_lock,
                root,
                provisioning,
                ledger,
                host_key,
                program,
                calls,
            }
        }

        fn admin(&self) -> Result<SystemdCredentialAdmin, ProvisioningSecretStoreError> {
            SystemdCredentialAdmin::open_for_test(
                &self.provisioning,
                &self.ledger,
                &self.host_key,
                &self.program,
            )
        }

        fn admin_with_fault(
            &self,
            point: FaultPoint,
        ) -> Result<SystemdCredentialAdmin, ProvisioningSecretStoreError> {
            SystemdCredentialAdmin::open_for_test_with_fault(
                &self.provisioning,
                &self.ledger,
                &self.host_key,
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

        fn copy_active_to_staged(&self) {
            let staged = self.provisioning.join("staged");
            fs::create_dir(&staged).expect("create staged fixture");
            fs::set_permissions(&staged, fs::Permissions::from_mode(0o700))
                .expect("protect staged fixture");
            for name in ["credential.cred", "reference", "manifest"] {
                fs::copy(
                    self.provisioning.join("active").join(name),
                    staged.join(name),
                )
                .expect("copy staged fixture file");
                fs::set_permissions(staged.join(name), fs::Permissions::from_mode(0o600))
                    .expect("protect staged fixture file");
            }
        }

        fn generation_bytes(&self, name: &str) -> Vec<(String, Vec<u8>)> {
            ["credential.cred", "reference", "manifest"]
                .into_iter()
                .map(|file| {
                    (
                        file.to_owned(),
                        fs::read(self.provisioning.join(name).join(file))
                            .expect("read generation fixture file"),
                    )
                })
                .collect()
        }

        fn set_ledger_phase(&self, phase: LedgerPhase) {
            let path = self.ledger.join("ledger");
            let mut ledger = decode_ledger(&fs::read(&path).expect("read fixture ledger"))
                .expect("decode fixture ledger");
            match phase {
                LedgerPhase::Intent if ledger.intent.is_none() => {
                    let record = ledger.generations.remove(0);
                    ledger.intent = Some(LifecycleIntent {
                        kind: LifecycleIntentKind::Install,
                        operation: *record.install.as_bytes(),
                        load: Some(record.load),
                        target_ref: record.secret_ref,
                        target_generation: record.generation,
                        source_ref: None,
                        envelope_commitment: Some(record.envelope_commitment),
                        expected_ciphertext_digest: Some(record.ciphertext_digest),
                        expected_artifact_digest: None,
                        pre_mutation_ledger_revision: [0; 32],
                    });
                }
                LedgerPhase::Complete if ledger.intent.is_some() => {
                    let intent = ledger.intent.take().expect("fixture intent");
                    ledger.generations.push(super::GenerationRecord {
                        install: ProvisioningInstallId::new(intent.operation),
                        load: intent.load.expect("fixture load"),
                        secret_ref: intent.target_ref,
                        generation: intent.target_generation,
                        envelope_commitment: intent
                            .envelope_commitment
                            .expect("fixture commitment"),
                        ciphertext_digest: intent
                            .expected_ciphertext_digest
                            .expect("fixture ciphertext digest"),
                        state: GenerationState::Active,
                    });
                }
                _ => {}
            }
            fs::write(path, encode_ledger(&ledger).expect("encode fixture ledger"))
                .expect("write fixture ledger");
        }

        fn ledger_phase(&self) -> LedgerPhase {
            let ledger = decode_ledger(
                &fs::read(self.ledger.join("ledger")).expect("read fixture ledger phase"),
            )
            .expect("decode fixture ledger phase");
            if ledger.intent.is_some() {
                LedgerPhase::Intent
            } else {
                LedgerPhase::Complete
            }
        }

        fn optional_ledger_phase(&self, name: &str) -> Option<LedgerPhase> {
            let path = self.ledger.join(name);
            path.exists().then(|| {
                let ledger = decode_ledger(&fs::read(path).expect("read optional fixture ledger"))
                    .expect("decode optional fixture ledger");
                if ledger.intent.is_some() {
                    LedgerPhase::Intent
                } else {
                    LedgerPhase::Complete
                }
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
