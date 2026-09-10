use super::{
    digest,
    files::{GenerationContent, GenerationManifest, encode_manifest},
};
use aster_mesh::{
    MAX_PROTECTED_PROVISIONING_BYTES, MAX_PROVISIONING_SECRET_REF_BYTES, ProvisioningLoadId,
    ProvisioningSecretRef, ProvisioningSecretStoreError,
};
use zeroize::Zeroizing;

const FIXED_BYTES: usize = 188;
/// Maximum canonical backup size, including bounded ciphertext and metadata.
pub const MAX_BACKUP_ARTIFACT_BYTES: usize =
    FIXED_BYTES + MAX_PROVISIONING_SECRET_REF_BYTES + MAX_PROTECTED_PROVISIONING_BYTES;

/// Caller-selected permanent backup binding identifier.
#[derive(Clone, Copy, Eq, PartialEq)]
pub struct BackupOperationId([u8; 32]);

impl BackupOperationId {
    pub const fn new(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl std::fmt::Debug for BackupOperationId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("BackupOperationId([REDACTED])")
    }
}

/// Canonical ciphertext backup. Its host commitment and bytes are never formatted.
pub struct ProtectedBackupArtifact(Zeroizing<Vec<u8>>);

impl ProtectedBackupArtifact {
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, ProvisioningSecretStoreError> {
        let _ = decode_backup(bytes)?;
        Ok(Self(Zeroizing::new(bytes.to_vec())))
    }

    /// Exposes protected artifact bytes for bounded binary output.
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

impl std::fmt::Debug for ProtectedBackupArtifact {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("ProtectedBackupArtifact([REDACTED])")
    }
}

pub(super) struct DecodedBackup<'a> {
    pub(super) operation: BackupOperationId,
    pub(super) host_key_identity: [u8; 32],
    pub(super) manifest: GenerationManifest,
    pub(super) ciphertext: &'a [u8],
}

pub(super) fn decode_backup(
    bytes: &[u8],
) -> Result<DecodedBackup<'_>, ProvisioningSecretStoreError> {
    if bytes.len() > MAX_BACKUP_ARTIFACT_BYTES {
        return Err(ProvisioningSecretStoreError::TooLarge);
    }
    if bytes.len() < FIXED_BYTES || &bytes[..12] != b"ASTRSDB1\x00\x02\x00\x00" {
        return Err(ProvisioningSecretStoreError::Rejected);
    }
    let reference_len = u32::from_be_bytes(array(&bytes[116..120])?) as usize;
    let metadata_end = FIXED_BYTES
        .checked_add(reference_len)
        .ok_or(ProvisioningSecretStoreError::Rejected)?;
    if reference_len > MAX_PROVISIONING_SECRET_REF_BYTES || metadata_end > bytes.len() {
        return Err(ProvisioningSecretStoreError::Rejected);
    }
    let reference_end = 120 + reference_len;
    let secret_ref = ProvisioningSecretRef::from_bytes(&bytes[120..reference_end])
        .map_err(|_| ProvisioningSecretStoreError::Rejected)?;
    let generation = u64::from_be_bytes(array(&bytes[76..84])?);
    if generation == 0 || crate::provider_generation(&secret_ref)? != generation {
        return Err(ProvisioningSecretStoreError::Rejected);
    }
    let length = u32::from_be_bytes(array(&bytes[metadata_end - 4..metadata_end])?) as usize;
    if length > MAX_PROTECTED_PROVISIONING_BYTES {
        return Err(ProvisioningSecretStoreError::TooLarge);
    }
    if length == 0 || metadata_end.checked_add(length) != Some(bytes.len()) {
        return Err(ProvisioningSecretStoreError::Rejected);
    }
    let ciphertext = &bytes[metadata_end..];
    let manifest = GenerationManifest {
        generation,
        load: ProvisioningLoadId::new(array(&bytes[84..116])?),
        secret_ref,
        ciphertext_digest: array(&bytes[reference_end + 32..reference_end + 64])?,
        content: GenerationContent::Credential,
    };
    let manifest_bytes = Zeroizing::new(encode_manifest(&manifest));
    if digest(ciphertext) != manifest.ciphertext_digest
        || digest(&manifest_bytes) != array(&bytes[reference_end..reference_end + 32])?
    {
        return Err(ProvisioningSecretStoreError::Rejected);
    }
    Ok(DecodedBackup {
        operation: BackupOperationId::new(array(&bytes[12..44])?),
        host_key_identity: array(&bytes[44..76])?,
        manifest,
        ciphertext,
    })
}

pub(super) fn encode_backup(
    operation: BackupOperationId,
    host_key_identity: [u8; 32],
    manifest: &GenerationManifest,
    ciphertext: &[u8],
) -> Result<ProtectedBackupArtifact, ProvisioningSecretStoreError> {
    if ciphertext.len() > MAX_PROTECTED_PROVISIONING_BYTES {
        return Err(ProvisioningSecretStoreError::TooLarge);
    }
    if manifest.content != GenerationContent::Credential {
        return Err(ProvisioningSecretStoreError::Rejected);
    }
    let reference = Zeroizing::new(manifest.secret_ref.to_bytes());
    let manifest_bytes = Zeroizing::new(encode_manifest(manifest));
    let mut bytes = Zeroizing::new(Vec::with_capacity(
        FIXED_BYTES + reference.len() + ciphertext.len(),
    ));
    bytes.extend_from_slice(b"ASTRSDB1\x00\x02\x00\x00");
    bytes.extend_from_slice(operation.as_bytes());
    bytes.extend_from_slice(&host_key_identity);
    bytes.extend_from_slice(&manifest.generation.to_be_bytes());
    bytes.extend_from_slice(manifest.load.as_bytes());
    bytes.extend_from_slice(&(reference.len() as u32).to_be_bytes());
    bytes.extend_from_slice(&reference);
    bytes.extend_from_slice(&digest(&manifest_bytes));
    bytes.extend_from_slice(&manifest.ciphertext_digest);
    bytes.extend_from_slice(&(ciphertext.len() as u32).to_be_bytes());
    bytes.extend_from_slice(ciphertext);
    let _ = decode_backup(&bytes)?;
    Ok(ProtectedBackupArtifact(bytes))
}

fn array<const N: usize>(bytes: &[u8]) -> Result<[u8; N], ProvisioningSecretStoreError> {
    bytes
        .try_into()
        .map_err(|_| ProvisioningSecretStoreError::Rejected)
}

/// Sanitized backup metadata with explicitly exposed protected output.
#[derive(Debug)]
pub struct BackupReceipt {
    operation: BackupOperationId,
    secret_ref: ProvisioningSecretRef,
    generation: u64,
    artifact: ProtectedBackupArtifact,
}

impl BackupReceipt {
    pub const fn operation(&self) -> BackupOperationId {
        self.operation
    }
    pub fn secret_ref(&self) -> &ProvisioningSecretRef {
        &self.secret_ref
    }
    pub const fn generation(&self) -> u64 {
        self.generation
    }
    pub fn artifact(&self) -> &ProtectedBackupArtifact {
        &self.artifact
    }
}

impl super::SystemdCredentialAdmin {
    /// Binds an exact Active ciphertext backup before exposing its protected bytes.
    /// Retries re-emit the original bytes while the bound generation remains live.
    pub fn backup(
        &mut self,
        operation: BackupOperationId,
    ) -> Result<BackupReceipt, ProvisioningSecretStoreError> {
        use super::{
            files,
            ledger::{BackupBinding, GenerationState, decode_ledger, encode_ledger},
        };
        let mut ledger = self
            .read_completed_ledger(false)?
            .ok_or(ProvisioningSecretStoreError::Rejected)?;
        let binding = ledger
            .backups
            .iter()
            .find(|binding| binding.operation == *operation.as_bytes());
        let record = if let Some(binding) = binding {
            ledger
                .generations
                .iter()
                .find(|record| {
                    record.secret_ref == binding.secret_ref
                        && record.generation == binding.generation
                })
                .ok_or(ProvisioningSecretStoreError::OperationConflict)?
        } else {
            ledger
                .generations
                .iter()
                .find(|record| record.state == GenerationState::Active)
                .ok_or(ProvisioningSecretStoreError::Rejected)?
        };
        let slot = match record.state {
            GenerationState::Active => files::ACTIVE_DIRECTORY,
            GenerationState::Previous => files::PREVIOUS_DIRECTORY,
            GenerationState::Destroyed => return Err(ProvisioningSecretStoreError::Destroyed),
        };
        let manifest = super::manifest_from_record(record);
        let ciphertext =
            files::read_exact_generation_ciphertext(&self.provisioning_root, slot, &manifest)?;
        let artifact = encode_backup(operation, ledger.host_key_identity, &manifest, &ciphertext)?;
        let artifact_digest = digest(artifact.as_bytes());
        let receipt = BackupReceipt {
            operation,
            secret_ref: record.secret_ref.clone(),
            generation: record.generation,
            artifact,
        };
        if let Some(binding) = binding {
            if binding.artifact_digest != artifact_digest {
                return Err(ProvisioningSecretStoreError::OperationConflict);
            }
        } else {
            ledger.backups.push(BackupBinding {
                operation: *operation.as_bytes(),
                secret_ref: receipt.secret_ref.clone(),
                generation: receipt.generation,
                artifact_digest,
            });
            let encoded = Zeroizing::new(encode_ledger(&ledger)?);
            if decode_ledger(&encoded)? != ledger {
                return Err(ProvisioningSecretStoreError::Rejected);
            }
            files::write_ledger_atomically(
                &self.ledger_root,
                &encoded,
                files::LedgerWrite::Complete,
                &mut self.faults,
            )?;
        }
        Ok(receipt)
    }
}

pub(super) fn validate_pending_backup(
    provisioning_root: &rustix::fd::OwnedFd,
    current: &super::ledger::ProviderLedger,
    pending: &super::ledger::ProviderLedger,
) -> Result<(), ProvisioningSecretStoreError> {
    use super::{files, ledger::GenerationState, lifecycle};
    if current.intent.is_some()
        || pending.intent.is_some()
        || pending.backups.len() != current.backups.len() + 1
    {
        return Err(ProvisioningSecretStoreError::Rejected);
    }
    let mut predecessor = pending.clone();
    let binding = predecessor
        .backups
        .pop()
        .ok_or(ProvisioningSecretStoreError::Rejected)?;
    if predecessor != *current {
        return Err(ProvisioningSecretStoreError::Rejected);
    }
    lifecycle::validate_completed_generations(provisioning_root, current)?;
    let record = current
        .generations
        .iter()
        .find(|record| {
            record.state == GenerationState::Active
                && record.secret_ref == binding.secret_ref
                && record.generation == binding.generation
        })
        .ok_or(ProvisioningSecretStoreError::Rejected)?;
    let manifest = super::manifest_from_record(record);
    let ciphertext = files::read_exact_generation_ciphertext(
        provisioning_root,
        files::ACTIVE_DIRECTORY,
        &manifest,
    )?;
    let artifact = encode_backup(
        BackupOperationId::new(binding.operation),
        current.host_key_identity,
        &manifest,
        &ciphertext,
    )?;
    if digest(artifact.as_bytes()) != binding.artifact_digest {
        return Err(ProvisioningSecretStoreError::Rejected);
    }
    Ok(())
}

/// Caller-selected permanent recovery binding identifier.
#[derive(Clone, Copy, Eq, PartialEq)]
pub struct RecoveryOperationId([u8; 32]);

impl RecoveryOperationId {
    pub const fn new(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl std::fmt::Debug for RecoveryOperationId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("RecoveryOperationId([REDACTED])")
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RecoveryDisposition {
    Restored,
    Existing,
}

/// Sanitized current-generation recovery result; contains no artifact or host commitment.
#[derive(Debug)]
pub struct RecoveryReceipt {
    operation: RecoveryOperationId,
    secret_ref: ProvisioningSecretRef,
    generation: u64,
    disposition: RecoveryDisposition,
}

impl RecoveryReceipt {
    pub const fn operation(&self) -> RecoveryOperationId {
        self.operation
    }
    pub fn secret_ref(&self) -> &ProvisioningSecretRef {
        &self.secret_ref
    }
    pub const fn generation(&self) -> u64 {
        self.generation
    }
    pub const fn disposition(&self) -> RecoveryDisposition {
        self.disposition
    }
}

impl super::SystemdCredentialAdmin {
    /// Repairs only the exact ledger-recorded Active ciphertext on this host.
    /// The artifact must match a prior backup binding; no provider is invoked.
    pub fn recover(
        &mut self,
        operation: RecoveryOperationId,
        artifact: &ProtectedBackupArtifact,
    ) -> Result<RecoveryReceipt, ProvisioningSecretStoreError> {
        use super::{
            files,
            ledger::{
                GenerationState, LifecycleIntent, LifecycleIntentKind, decode_ledger, encode_ledger,
            },
            lifecycle,
        };
        let decoded = decode_backup(artifact.as_bytes())?;
        let artifact_digest = digest(artifact.as_bytes());
        let mut ledger = self
            .read_completed_ledger(true)?
            .ok_or(ProvisioningSecretStoreError::Rejected)?;
        if decoded.host_key_identity != self.host_key_identity {
            return Err(ProvisioningSecretStoreError::Rejected);
        }
        let existing = ledger
            .recoveries
            .iter()
            .find(|binding| binding.operation == *operation.as_bytes());
        if let Some(binding) = existing
            && (binding.backup_operation != *decoded.operation.as_bytes()
                || binding.secret_ref != decoded.manifest.secret_ref
                || binding.generation != decoded.manifest.generation
                || binding.artifact_digest != artifact_digest)
        {
            return Err(ProvisioningSecretStoreError::OperationConflict);
        }
        if !ledger.backups.iter().any(|binding| {
            binding.operation == *decoded.operation.as_bytes()
                && binding.secret_ref == decoded.manifest.secret_ref
                && binding.generation == decoded.manifest.generation
                && binding.artifact_digest == artifact_digest
        }) {
            return Err(ProvisioningSecretStoreError::Rejected);
        }
        let target = ledger
            .generations
            .iter()
            .find(|record| {
                record.secret_ref == decoded.manifest.secret_ref
                    && record.generation == decoded.manifest.generation
            })
            .ok_or(ProvisioningSecretStoreError::Rejected)?;
        if target.state == GenerationState::Destroyed {
            return Err(ProvisioningSecretStoreError::Destroyed);
        }
        if target.state != GenerationState::Active
            || super::manifest_from_record(target) != decoded.manifest
        {
            return Err(ProvisioningSecretStoreError::Rejected);
        }
        lifecycle::validate_recovery_generations(&self.provisioning_root, &ledger)?;
        let exact = files::generation_matches(
            &self.provisioning_root,
            files::ACTIVE_DIRECTORY,
            &decoded.manifest,
        )?;
        let mut receipt = RecoveryReceipt {
            operation,
            secret_ref: target.secret_ref.clone(),
            generation: target.generation,
            disposition: RecoveryDisposition::Existing,
        };
        if existing.is_some() {
            if !exact {
                return Err(ProvisioningSecretStoreError::Rejected);
            }
            files::sync_directory(&self.provisioning_root)?;
            return Ok(receipt);
        }
        let pre_mutation_ledger_revision = digest(&encode_ledger(&ledger)?);
        ledger.intent = Some(LifecycleIntent {
            kind: LifecycleIntentKind::Recover,
            operation: *operation.as_bytes(),
            backup_operation: Some(*decoded.operation.as_bytes()),
            load: Some(decoded.manifest.load),
            target_ref: decoded.manifest.secret_ref.clone(),
            target_generation: decoded.manifest.generation,
            source_ref: None,
            envelope_commitment: None,
            expected_ciphertext_digest: Some(decoded.manifest.ciphertext_digest),
            expected_artifact_digest: Some(artifact_digest),
            pre_mutation_ledger_revision,
        });
        // Both exact snapshots must fit and validate before creating staged files.
        let intent_bytes = Zeroizing::new(encode_ledger(&ledger)?);
        if decode_ledger(&intent_bytes)? != ledger {
            return Err(ProvisioningSecretStoreError::Rejected);
        }
        let completed = lifecycle::completed_from_intent(&ledger)?;
        let complete_bytes = Zeroizing::new(encode_ledger(&completed)?);
        if decode_ledger(&complete_bytes)? != completed {
            return Err(ProvisioningSecretStoreError::Rejected);
        }
        if !exact {
            let manifest = Zeroizing::new(encode_manifest(&decoded.manifest));
            let reference = Zeroizing::new(decoded.manifest.secret_ref.to_bytes());
            files::write_staged_generation(
                &self.provisioning_root,
                decoded.ciphertext,
                &reference,
                &manifest,
                &mut self.faults,
            )?;
            receipt.disposition = RecoveryDisposition::Restored;
        }
        lifecycle::commit_lifecycle_intent(&self.ledger_root, &ledger, &mut self.faults)?;
        lifecycle::reconcile_lifecycle(
            &self.provisioning_root,
            &self.ledger_root,
            ledger,
            &completed,
            &mut self.faults,
        )?;
        Ok(receipt)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::admin::digest;

    fn literal_artifact() -> Vec<u8> {
        let reference = crate::provisioning_secret_ref(2, [0x33; 32])
            .unwrap()
            .to_bytes();
        let ciphertext = b"protected ciphertext fixture";
        let ciphertext_digest = digest(ciphertext);
        let mut manifest = b"ASTRSDM1\x00\x02\x00\x00".to_vec();
        manifest.extend_from_slice(&2_u64.to_be_bytes());
        manifest.extend_from_slice(&[0x22; 32]);
        manifest.extend_from_slice(&ciphertext_digest);
        manifest.extend_from_slice(&(reference.len() as u32).to_be_bytes());
        manifest.extend_from_slice(&reference);
        let mut bytes = b"ASTRSDB1\x00\x02\x00\x00".to_vec();
        bytes.extend_from_slice(&[0x11; 32]);
        bytes.extend_from_slice(&[0xa0; 32]);
        bytes.extend_from_slice(&2_u64.to_be_bytes());
        bytes.extend_from_slice(&[0x22; 32]);
        bytes.extend_from_slice(&(reference.len() as u32).to_be_bytes());
        bytes.extend_from_slice(&reference);
        bytes.extend_from_slice(&digest(&manifest));
        bytes.extend_from_slice(&ciphertext_digest);
        bytes.extend_from_slice(&(ciphertext.len() as u32).to_be_bytes());
        bytes.extend_from_slice(ciphertext);
        bytes
    }

    #[test]
    fn canonical_backup_round_trip_preserves_the_protected_generation() {
        // Break caught: silently changing or dropping a bound field changes retry bytes.
        let bytes = literal_artifact();
        let artifact = ProtectedBackupArtifact::from_bytes(&bytes).unwrap();
        assert_eq!(artifact.as_bytes(), bytes);
        let decoded = decode_backup(artifact.as_bytes()).unwrap();
        assert_eq!(decoded.operation, BackupOperationId::new([0x11; 32]));
        assert_eq!(decoded.host_key_identity, [0xa0; 32]);
        assert_eq!(decoded.manifest.generation, 2);
        assert_eq!(
            decoded.manifest.load,
            aster_mesh::ProvisioningLoadId::new([0x22; 32])
        );
        assert_eq!(decoded.ciphertext, b"protected ciphertext fixture");
        assert_eq!(
            encode_backup(
                decoded.operation,
                decoded.host_key_identity,
                &decoded.manifest,
                decoded.ciphertext
            )
            .unwrap()
            .as_bytes(),
            bytes
        );
        assert!(!format!("{artifact:?}").contains("160"));
    }

    #[test]
    fn backup_codec_rejects_noncanonical_or_unbound_inputs() {
        // Break caught: accepting malformed lengths, generations or unauthenticated payloads.
        let bytes = literal_artifact();
        let reference_len = u32::from_be_bytes(bytes[116..120].try_into().unwrap()) as usize;
        let manifest_offset = 120 + reference_len;
        for offset in [
            0,
            9,
            10,
            11,
            83,
            84,
            119,
            manifest_offset,
            manifest_offset + 32,
            bytes.len() - 1,
        ] {
            let mut changed = bytes.clone();
            changed[offset] ^= 1;
            assert!(
                ProtectedBackupArtifact::from_bytes(&changed).is_err(),
                "offset {offset}"
            );
        }
        for length in 0..bytes.len() {
            assert!(ProtectedBackupArtifact::from_bytes(&bytes[..length]).is_err());
        }
        let mut changed = bytes.clone();
        changed.push(0);
        assert!(ProtectedBackupArtifact::from_bytes(&changed).is_err());
        let mut v1 = bytes.clone();
        v1[9] = 1;
        assert!(ProtectedBackupArtifact::from_bytes(&v1).is_err());
        for range in [116..120, manifest_offset + 64..manifest_offset + 68] {
            let mut changed = bytes.clone();
            changed[range].fill(0xff);
            assert!(ProtectedBackupArtifact::from_bytes(&changed).is_err());
        }
        let mut changed = bytes;
        changed[76..84].fill(0);
        assert!(ProtectedBackupArtifact::from_bytes(&changed).is_err());
        assert_eq!(
            ProtectedBackupArtifact::from_bytes(&vec![0; MAX_BACKUP_ARTIFACT_BYTES + 1])
                .unwrap_err(),
            aster_mesh::ProvisioningSecretStoreError::TooLarge
        );
    }

    #[test]
    fn backup_codec_bounds_ciphertext_independently_of_metadata() {
        // Break caught: limiting only the outer artifact accepts an oversized protected payload.
        let bytes = literal_artifact();
        let decoded = decode_backup(&bytes).unwrap();
        let mut manifest = decoded.manifest;
        for length in [
            0,
            MAX_PROTECTED_PROVISIONING_BYTES,
            MAX_PROTECTED_PROVISIONING_BYTES + 1,
        ] {
            let ciphertext = Zeroizing::new(vec![0xa5; length]);
            manifest.ciphertext_digest = digest(&ciphertext);
            let result = encode_backup(
                decoded.operation,
                decoded.host_key_identity,
                &manifest,
                &ciphertext,
            );
            if length == MAX_PROTECTED_PROVISIONING_BYTES {
                let artifact = result.unwrap();
                assert_eq!(
                    decode_backup(artifact.as_bytes()).unwrap().ciphertext.len(),
                    length
                );
            } else {
                assert!(result.is_err());
            }
        }
    }
}
