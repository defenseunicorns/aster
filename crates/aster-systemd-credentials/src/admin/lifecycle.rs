use super::files::{
    ACTIVE_DIRECTORY, CIPHERTEXT_FILE, FaultInjector, FaultPoint, GenerationContent,
    GenerationManifest, LedgerWrite, MANIFEST_FILE, PREVIOUS_DIRECTORY, REFERENCE_FILE,
    STAGED_DIRECTORY, TOMBSTONE_FILE, child_directory_exists, directory_has_exact_entries,
    encode_manifest, generation_identity_matches, generation_matches, open_child_directory,
    promote_staged_generation, sync_directory, write_ledger_atomically, write_new_file,
};
use super::ledger::{
    GenerationRecord, GenerationState, LifecycleIntent, LifecycleIntentKind, ProviderLedger,
    decode_ledger, encode_ledger,
};
use aster_mesh::ProvisioningSecretStoreError;
use rustix::fd::OwnedFd;
use zeroize::Zeroizing;

pub(super) fn select_lifecycle_ledger(
    current: ProviderLedger,
    pending: Option<ProviderLedger>,
) -> Result<ProviderLedger, ProvisioningSecretStoreError> {
    let Some(pending) = pending else {
        return Ok(current);
    };
    if current.intent.is_some() {
        return Ok(current);
    }
    let intent = pending
        .intent
        .as_ref()
        .ok_or(ProvisioningSecretStoreError::Rejected)?;
    validate_intent_revision(&pending, intent)?;
    let mut pending_predecessor = pending.clone();
    pending_predecessor.intent = None;
    if pending_predecessor != current {
        return Err(ProvisioningSecretStoreError::Rejected);
    }
    Ok(pending)
}

pub(super) fn commit_lifecycle_intent(
    ledger_root: &OwnedFd,
    ledger: &ProviderLedger,
    faults: &mut FaultInjector,
) -> Result<(), ProvisioningSecretStoreError> {
    let intent = ledger
        .intent
        .as_ref()
        .ok_or(ProvisioningSecretStoreError::Rejected)?;
    validate_intent_revision(ledger, intent)?;
    let encoded = Zeroizing::new(encode_ledger(ledger)?);
    if decode_ledger(&encoded)? != *ledger {
        return Err(ProvisioningSecretStoreError::Rejected);
    }
    write_ledger_atomically(ledger_root, &encoded, LedgerWrite::Intent, faults)
}

pub(super) fn reconcile_lifecycle(
    provisioning_root: &OwnedFd,
    ledger_root: &OwnedFd,
    ledger: ProviderLedger,
    completed: &ProviderLedger,
    faults: &mut FaultInjector,
) -> Result<(), ProvisioningSecretStoreError> {
    let intent = ledger
        .intent
        .as_ref()
        .ok_or(ProvisioningSecretStoreError::Rejected)?;
    validate_intent_revision(&ledger, intent)?;
    validate_completed_snapshot(&ledger, completed, intent)?;
    let target = target_manifest(completed, intent)?;
    let source = source_manifest(&ledger, intent)?;

    for _ in 0..4 {
        let slots = inspect_generation_slots(provisioning_root, intent, &target, source.as_ref())?;
        match lifecycle_step(intent.kind, slots)? {
            LifecycleStep::ExchangeStagedWithActive => {
                exchange_staged_with_active(provisioning_root, faults)?;
            }
            LifecycleStep::ExchangeStagedWithPrevious => {
                exchange_staged_with_previous(provisioning_root, faults)?;
            }
            LifecycleStep::ParkStagedAsPrevious => {
                rustix::fs::renameat(
                    provisioning_root,
                    STAGED_DIRECTORY,
                    provisioning_root,
                    PREVIOUS_DIRECTORY,
                )
                .map_err(|_| ProvisioningSecretStoreError::Unavailable)?;
                faults.hit(FaultPoint::PreviousRenamed)?;
                sync_directory(provisioning_root)?;
                faults.hit(FaultPoint::ProvisioningParentSynced)?;
            }
            LifecycleStep::PromoteStagedToActive => {
                promote_staged_generation(provisioning_root, faults)?;
            }
            step @ (LifecycleStep::RemoveSourceStage | LifecycleStep::RemoveReplacedStage) => {
                remove_bound_staged_generation(
                    provisioning_root,
                    source
                        .as_ref()
                        .ok_or(ProvisioningSecretStoreError::Rejected)?,
                    step == LifecycleStep::RemoveSourceStage,
                    faults,
                )?;
            }
            LifecycleStep::Complete => {
                validate_completed_generations(provisioning_root, completed)?;
                sync_directory(provisioning_root)?;
                faults.hit(FaultPoint::ProvisioningParentSynced)?;
                let encoded = Zeroizing::new(encode_ledger(completed)?);
                return write_ledger_atomically(
                    ledger_root,
                    &encoded,
                    LedgerWrite::Complete,
                    faults,
                );
            }
        }
    }
    Err(ProvisioningSecretStoreError::Rejected)
}

fn validate_intent_revision(
    ledger: &ProviderLedger,
    intent: &LifecycleIntent,
) -> Result<(), ProvisioningSecretStoreError> {
    let mut previous = ledger.clone();
    previous.intent = None;
    let encoded = encode_ledger(&previous)?;
    if super::digest(&encoded) != intent.pre_mutation_ledger_revision {
        return Err(ProvisioningSecretStoreError::Rejected);
    }
    Ok(())
}

fn validate_completed_snapshot(
    ledger: &ProviderLedger,
    completed: &ProviderLedger,
    intent: &LifecycleIntent,
) -> Result<(), ProvisioningSecretStoreError> {
    if completed.intent.is_some() || completed.host_key_identity != ledger.host_key_identity {
        return Err(ProvisioningSecretStoreError::Rejected);
    }
    let encoded = encode_ledger(completed)?;
    if decode_ledger(&encoded)? != *completed {
        return Err(ProvisioningSecretStoreError::Rejected);
    }
    match intent.kind {
        LifecycleIntentKind::Rotate => validate_rotate_completion(ledger, completed, intent)?,
        LifecycleIntentKind::Recover => validate_recovery_completion(ledger, completed, intent)?,
        LifecycleIntentKind::DestroyActive | LifecycleIntentKind::DestroyPrevious => {
            validate_destroy_completion(ledger, completed, intent)?;
        }
        LifecycleIntentKind::Install => return Err(ProvisioningSecretStoreError::Rejected),
    }
    Ok(())
}

fn validate_recovery_completion(
    ledger: &ProviderLedger,
    completed: &ProviderLedger,
    intent: &LifecycleIntent,
) -> Result<(), ProvisioningSecretStoreError> {
    let target = ledger
        .generations
        .iter()
        .find(|record| {
            record.secret_ref == intent.target_ref
                && record.generation == intent.target_generation
                && record.state == GenerationState::Active
        })
        .ok_or(ProvisioningSecretStoreError::Rejected)?;
    if intent.load != Some(target.load)
        || intent.source_ref.is_some()
        || intent.envelope_commitment.is_some()
        || intent.expected_ciphertext_digest != Some(target.ciphertext_digest)
        || intent.expected_artifact_digest.is_none()
        || completed.generations != ledger.generations
        || completed.backups != ledger.backups
        || completed.destroys != ledger.destroys
        || completed.recoveries.len() != ledger.recoveries.len() + 1
        || completed.recoveries[..ledger.recoveries.len()] != ledger.recoveries
    {
        return Err(ProvisioningSecretStoreError::Rejected);
    }
    let binding = completed
        .recoveries
        .last()
        .ok_or(ProvisioningSecretStoreError::Rejected)?;
    if binding.operation != intent.operation
        || binding.secret_ref != intent.target_ref
        || binding.generation != intent.target_generation
        || Some(binding.artifact_digest) != intent.expected_artifact_digest
    {
        return Err(ProvisioningSecretStoreError::Rejected);
    }
    Ok(())
}

fn validate_destroy_completion(
    ledger: &ProviderLedger,
    completed: &ProviderLedger,
    intent: &LifecycleIntent,
) -> Result<(), ProvisioningSecretStoreError> {
    let expected_state = if intent.kind == LifecycleIntentKind::DestroyActive {
        GenerationState::Active
    } else {
        GenerationState::Previous
    };
    let source = ledger
        .generations
        .iter()
        .find(|record| {
            record.secret_ref == intent.target_ref
                && record.generation == intent.target_generation
                && record.state == expected_state
        })
        .ok_or(ProvisioningSecretStoreError::Rejected)?;
    let completed_target = completed
        .generations
        .iter()
        .find(|record| record.secret_ref == intent.target_ref)
        .ok_or(ProvisioningSecretStoreError::Rejected)?;
    let mut expected_target = source.clone();
    expected_target.state = GenerationState::Destroyed;
    expected_target.ciphertext_digest = [0; 32];
    let unchanged = ledger
        .generations
        .iter()
        .filter(|record| record.secret_ref != intent.target_ref)
        .all(|record| completed.generations.contains(record));
    if completed_target != &expected_target
        || !unchanged
        || completed.generations.len() != ledger.generations.len()
        || intent.load.is_some()
        || intent.source_ref.is_some()
        || intent.envelope_commitment.is_some()
        || intent.expected_ciphertext_digest.is_some()
        || intent.expected_artifact_digest.is_some()
        || completed.backups != ledger.backups
        || completed.recoveries != ledger.recoveries
        || completed.destroys.len() != ledger.destroys.len() + 1
        || completed.destroys[..ledger.destroys.len()] != ledger.destroys
    {
        return Err(ProvisioningSecretStoreError::Rejected);
    }
    let binding = completed
        .destroys
        .last()
        .ok_or(ProvisioningSecretStoreError::Rejected)?;
    if binding.operation.as_bytes() != &intent.operation
        || binding.secret_ref != intent.target_ref
        || binding.generation != intent.target_generation
        || binding.outcome != super::ledger::DestroyBindingOutcome::Destroyed
    {
        return Err(ProvisioningSecretStoreError::Rejected);
    }
    Ok(())
}

fn validate_rotate_completion(
    ledger: &ProviderLedger,
    completed: &ProviderLedger,
    intent: &LifecycleIntent,
) -> Result<(), ProvisioningSecretStoreError> {
    let source_ref = intent
        .source_ref
        .as_ref()
        .ok_or(ProvisioningSecretStoreError::Rejected)?;
    let source = ledger
        .generations
        .iter()
        .find(|record| record.secret_ref == *source_ref && record.state == GenerationState::Active)
        .ok_or(ProvisioningSecretStoreError::Rejected)?;
    let completed_source = completed
        .generations
        .iter()
        .find(|record| record.secret_ref == *source_ref)
        .ok_or(ProvisioningSecretStoreError::Rejected)?;
    let target = completed
        .generations
        .iter()
        .find(|record| {
            record.secret_ref == intent.target_ref
                && record.generation == intent.target_generation
                && record.state == GenerationState::Active
        })
        .ok_or(ProvisioningSecretStoreError::Rejected)?;
    let mut expected_source = source.clone();
    expected_source.state = GenerationState::Previous;
    if completed_source != &expected_source
        || intent.operation != *target.install.as_bytes()
        || intent.load != Some(target.load)
        || intent.envelope_commitment != Some(target.envelope_commitment)
        || intent.expected_ciphertext_digest != Some(target.ciphertext_digest)
        || intent.expected_artifact_digest.is_some()
        || intent.target_generation
            != source
                .generation
                .checked_add(1)
                .ok_or(ProvisioningSecretStoreError::Rejected)?
        || ledger.backups != completed.backups
        || ledger.recoveries != completed.recoveries
        || ledger.destroys != completed.destroys
        || completed.generations.len() != ledger.generations.len() + 1
    {
        return Err(ProvisioningSecretStoreError::Rejected);
    }
    Ok(())
}

fn target_manifest(
    completed: &ProviderLedger,
    intent: &LifecycleIntent,
) -> Result<GenerationManifest, ProvisioningSecretStoreError> {
    let record = completed
        .generations
        .iter()
        .find(|record| {
            record.secret_ref == intent.target_ref && record.generation == intent.target_generation
        })
        .ok_or(ProvisioningSecretStoreError::Rejected)?;
    Ok(manifest_from_record(record))
}

fn source_manifest(
    ledger: &ProviderLedger,
    intent: &LifecycleIntent,
) -> Result<Option<GenerationManifest>, ProvisioningSecretStoreError> {
    let reference = match intent.kind {
        LifecycleIntentKind::Rotate => intent.source_ref.as_ref(),
        LifecycleIntentKind::Recover
        | LifecycleIntentKind::DestroyActive
        | LifecycleIntentKind::DestroyPrevious => Some(&intent.target_ref),
        LifecycleIntentKind::Install => None,
    };
    reference
        .map(|reference| {
            ledger
                .generations
                .iter()
                .find(|record| record.secret_ref == *reference)
                .map(manifest_from_record)
                .ok_or(ProvisioningSecretStoreError::Rejected)
        })
        .transpose()
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

fn inspect_generation_slots(
    provisioning_root: &OwnedFd,
    intent: &LifecycleIntent,
    target: &GenerationManifest,
    source: Option<&GenerationManifest>,
) -> Result<GenerationSlots, ProvisioningSecretStoreError> {
    Ok(GenerationSlots {
        active: inspect_slot(provisioning_root, ACTIVE_DIRECTORY, intent, target, source)?,
        previous: inspect_slot(
            provisioning_root,
            PREVIOUS_DIRECTORY,
            intent,
            target,
            source,
        )?,
        staged: inspect_slot(provisioning_root, STAGED_DIRECTORY, intent, target, source)?,
    })
}

fn inspect_slot(
    provisioning_root: &OwnedFd,
    slot: &str,
    intent: &LifecycleIntent,
    target: &GenerationManifest,
    source: Option<&GenerationManifest>,
) -> Result<SlotIdentity, ProvisioningSecretStoreError> {
    if !child_directory_exists(provisioning_root, slot)? {
        return Ok(SlotIdentity::Absent);
    }
    if generation_matches(provisioning_root, slot, target)? {
        return Ok(if target.content == GenerationContent::Tombstone {
            SlotIdentity::Tombstone
        } else {
            SlotIdentity::Target
        });
    }
    if let Some(source) = source
        && generation_matches(provisioning_root, slot, source)?
    {
        return Ok(SlotIdentity::Source);
    }
    if intent.kind == LifecycleIntentKind::Recover
        && generation_identity_matches(provisioning_root, slot, target)?
    {
        return Ok(SlotIdentity::Replaced);
    }
    Ok(SlotIdentity::Unbound)
}

fn remove_bound_staged_generation(
    provisioning_root: &OwnedFd,
    expected: &GenerationManifest,
    require_digest: bool,
    faults: &mut FaultInjector,
) -> Result<(), ProvisioningSecretStoreError> {
    let matches = if require_digest {
        generation_matches(provisioning_root, STAGED_DIRECTORY, expected)?
    } else {
        generation_identity_matches(provisioning_root, STAGED_DIRECTORY, expected)?
    };
    if !matches {
        return Err(ProvisioningSecretStoreError::Rejected);
    }
    let staged = open_child_directory(provisioning_root, STAGED_DIRECTORY)?;
    let entries = match expected.content {
        GenerationContent::Credential => [CIPHERTEXT_FILE, REFERENCE_FILE, MANIFEST_FILE],
        GenerationContent::Tombstone => [TOMBSTONE_FILE, REFERENCE_FILE, MANIFEST_FILE],
    };
    if !directory_has_exact_entries(&staged, &entries)? {
        return Err(ProvisioningSecretStoreError::Rejected);
    }
    for name in entries {
        rustix::fs::unlinkat(&staged, name, rustix::fs::AtFlags::empty())
            .map_err(|_| ProvisioningSecretStoreError::Unavailable)?;
    }
    drop(staged);
    rustix::fs::unlinkat(
        provisioning_root,
        STAGED_DIRECTORY,
        rustix::fs::AtFlags::REMOVEDIR,
    )
    .map_err(|_| ProvisioningSecretStoreError::Unavailable)?;
    faults.hit(FaultPoint::ReplacedGenerationDeleted)?;
    sync_directory(provisioning_root)?;
    faults.hit(FaultPoint::ProvisioningParentSynced)
}

pub(super) fn validate_completed_generations(
    provisioning_root: &OwnedFd,
    ledger: &ProviderLedger,
) -> Result<(), ProvisioningSecretStoreError> {
    if ledger.intent.is_some() {
        return Err(ProvisioningSecretStoreError::Rejected);
    }
    let active_destroyed = validate_completed_slot(
        provisioning_root,
        ACTIVE_DIRECTORY,
        ledger,
        ledger
            .generations
            .iter()
            .find(|record| record.state == GenerationState::Active),
    )?;
    let previous_destroyed = validate_completed_slot(
        provisioning_root,
        PREVIOUS_DIRECTORY,
        ledger,
        ledger
            .generations
            .iter()
            .find(|record| record.state == GenerationState::Previous),
    )?;
    if active_destroyed.is_some() && active_destroyed == previous_destroyed {
        return Err(ProvisioningSecretStoreError::Rejected);
    }
    if super::files::child_directory_exists(provisioning_root, STAGED_DIRECTORY)? {
        return Err(ProvisioningSecretStoreError::Rejected);
    }
    Ok(())
}

fn validate_completed_slot(
    provisioning_root: &OwnedFd,
    slot: &str,
    ledger: &ProviderLedger,
    record: Option<&GenerationRecord>,
) -> Result<Option<usize>, ProvisioningSecretStoreError> {
    let Some(record) = record else {
        if !super::files::child_directory_exists(provisioning_root, slot)? {
            return Ok(None);
        }
        let mut exact_destroyed = None;
        for (index, record) in ledger
            .generations
            .iter()
            .enumerate()
            .filter(|(_, record)| record.state == GenerationState::Destroyed)
        {
            if super::files::generation_matches(
                provisioning_root,
                slot,
                &manifest_from_record(record),
            )? && exact_destroyed.replace(index).is_some()
            {
                return Err(ProvisioningSecretStoreError::Rejected);
            }
        }
        return exact_destroyed
            .ok_or(ProvisioningSecretStoreError::Rejected)
            .map(Some);
    };
    let manifest = manifest_from_record(record);
    if super::files::generation_matches(provisioning_root, slot, &manifest)? {
        Ok(None)
    } else {
        Err(ProvisioningSecretStoreError::Rejected)
    }
}

pub(super) fn write_staged_tombstone(
    provisioning_root: &OwnedFd,
    manifest: &GenerationManifest,
    faults: &mut FaultInjector,
) -> Result<(), ProvisioningSecretStoreError> {
    if manifest.content != super::files::GenerationContent::Tombstone
        || manifest.ciphertext_digest != [0; 32]
    {
        return Err(ProvisioningSecretStoreError::Rejected);
    }
    rustix::fs::mkdirat(provisioning_root, STAGED_DIRECTORY, rustix::fs::Mode::RWXU)
        .map_err(|_| ProvisioningSecretStoreError::Unavailable)?;
    let staged = open_child_directory(provisioning_root, STAGED_DIRECTORY)?;
    let reference = Zeroizing::new(manifest.secret_ref.to_bytes());
    let encoded_manifest = Zeroizing::new(encode_manifest(manifest));
    write_new_file(&staged, REFERENCE_FILE, &reference)?;
    write_new_file(&staged, MANIFEST_FILE, &encoded_manifest)?;
    write_new_file(&staged, TOMBSTONE_FILE, &[])?;
    faults.hit(FaultPoint::StagedTombstoneSynced)?;
    sync_directory(&staged)?;
    sync_directory(provisioning_root)?;
    faults.hit(FaultPoint::StageParentSynced)
}

pub(super) fn exchange_staged_with_active(
    provisioning_root: &OwnedFd,
    faults: &mut FaultInjector,
) -> Result<(), ProvisioningSecretStoreError> {
    exchange_staged_with(
        provisioning_root,
        ACTIVE_DIRECTORY,
        faults,
        FaultPoint::ActiveExchanged,
    )
}

pub(super) fn exchange_staged_with_previous(
    provisioning_root: &OwnedFd,
    faults: &mut FaultInjector,
) -> Result<(), ProvisioningSecretStoreError> {
    exchange_staged_with(
        provisioning_root,
        PREVIOUS_DIRECTORY,
        faults,
        FaultPoint::PreviousExchanged,
    )
}

fn exchange_staged_with(
    provisioning_root: &OwnedFd,
    slot: &str,
    faults: &mut FaultInjector,
    point: FaultPoint,
) -> Result<(), ProvisioningSecretStoreError> {
    rustix::fs::renameat_with(
        provisioning_root,
        STAGED_DIRECTORY,
        provisioning_root,
        slot,
        rustix::fs::RenameFlags::EXCHANGE,
    )
    .map_err(|_| ProvisioningSecretStoreError::Unavailable)?;
    faults.hit(point)?;
    sync_directory(provisioning_root)?;
    faults.hit(FaultPoint::ProvisioningParentSynced)
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct GenerationSlots {
    pub(super) active: SlotIdentity,
    pub(super) previous: SlotIdentity,
    pub(super) staged: SlotIdentity,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum SlotIdentity {
    Absent,
    Source,
    Target,
    Tombstone,
    Replaced,
    Mismatch,
    Partial,
    Duplicate,
    Unbound,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum LifecycleStep {
    ExchangeStagedWithActive,
    ExchangeStagedWithPrevious,
    ParkStagedAsPrevious,
    PromoteStagedToActive,
    RemoveSourceStage,
    RemoveReplacedStage,
    Complete,
}

pub(super) fn lifecycle_step(
    kind: LifecycleIntentKind,
    slots: GenerationSlots,
) -> Result<LifecycleStep, ProvisioningSecretStoreError> {
    use LifecycleIntentKind::{DestroyActive, DestroyPrevious, Recover, Rotate};
    use LifecycleStep::{
        Complete, ExchangeStagedWithActive, ExchangeStagedWithPrevious, ParkStagedAsPrevious,
        PromoteStagedToActive, RemoveReplacedStage, RemoveSourceStage,
    };
    use SlotIdentity::{Absent, Replaced, Source, Target, Tombstone};

    let step = match (kind, slots.active, slots.previous, slots.staged) {
        (Rotate, Source, Absent, Target) => ExchangeStagedWithActive,
        (Rotate, Target, Absent, Source) => ParkStagedAsPrevious,
        (Rotate, Target, Source, Absent) => Complete,
        (Recover, Absent, Absent, Target) => PromoteStagedToActive,
        (Recover, Replaced, Absent, Target) => ExchangeStagedWithActive,
        (Recover, Target, Absent, Replaced) => RemoveReplacedStage,
        (Recover, Target, Absent, Absent) => Complete,
        (DestroyActive, Source, Absent, Tombstone) => ExchangeStagedWithActive,
        (DestroyActive, Tombstone, Absent, Source) => RemoveSourceStage,
        (DestroyActive, Tombstone, Absent, Absent) => Complete,
        (DestroyPrevious, Absent, Source, Tombstone) => ExchangeStagedWithPrevious,
        (DestroyPrevious, Absent, Tombstone, Source) => RemoveSourceStage,
        (DestroyPrevious, Absent, Tombstone, Absent) => Complete,
        _ => return Err(ProvisioningSecretStoreError::Rejected),
    };
    Ok(step)
}

#[cfg(test)]
mod tests {
    use super::{
        GenerationSlots, LifecycleStep, SlotIdentity, commit_lifecycle_intent, lifecycle_step,
        reconcile_lifecycle, select_lifecycle_ledger,
    };
    use super::{
        exchange_staged_with_active, exchange_staged_with_previous, write_staged_tombstone,
    };
    use crate::admin::{
        SystemdCredentialAdmin,
        files::{
            ACTIVE_DIRECTORY, FaultInjector, FaultPoint, GenerationContent, GenerationManifest,
            PREVIOUS_DIRECTORY, STAGED_DIRECTORY, TOMBSTONE_FILE, generation_matches,
            open_secure_root,
        },
        ledger::{
            BackupBinding, DestroyBinding, DestroyBindingOutcome, GenerationRecord,
            GenerationState, LifecycleIntent, LifecycleIntentKind, ProviderLedger, RecoveryBinding,
            decode_ledger, encode_ledger,
        },
    };
    use crate::{PROVIDER_REFERENCE_ID_BYTES, provisioning_secret_ref};
    use aster_mesh::{
        ProvisioningDestroyId, ProvisioningInstallId, ProvisioningLoadId,
        ProvisioningSecretStoreError,
    };
    use std::{
        fs,
        os::unix::fs::PermissionsExt as _,
        path::{Path, PathBuf},
        sync::atomic::{AtomicU64, Ordering},
    };

    static NEXT_FIXTURE: AtomicU64 = AtomicU64::new(0);

    #[test]
    fn intent_tables_select_only_the_next_exact_filesystem_step() {
        // Break caught: selecting a transition from directory presence rather
        // than the intent-bound source and target identities can activate or
        // delete unrelated provisioning material.
        let cases = [
            (
                LifecycleIntentKind::Rotate,
                slots(
                    SlotIdentity::Source,
                    SlotIdentity::Absent,
                    SlotIdentity::Target,
                ),
                LifecycleStep::ExchangeStagedWithActive,
            ),
            (
                LifecycleIntentKind::Rotate,
                slots(
                    SlotIdentity::Target,
                    SlotIdentity::Absent,
                    SlotIdentity::Source,
                ),
                LifecycleStep::ParkStagedAsPrevious,
            ),
            (
                LifecycleIntentKind::Rotate,
                slots(
                    SlotIdentity::Target,
                    SlotIdentity::Source,
                    SlotIdentity::Absent,
                ),
                LifecycleStep::Complete,
            ),
            (
                LifecycleIntentKind::Recover,
                slots(
                    SlotIdentity::Absent,
                    SlotIdentity::Absent,
                    SlotIdentity::Target,
                ),
                LifecycleStep::PromoteStagedToActive,
            ),
            (
                LifecycleIntentKind::Recover,
                slots(
                    SlotIdentity::Replaced,
                    SlotIdentity::Absent,
                    SlotIdentity::Target,
                ),
                LifecycleStep::ExchangeStagedWithActive,
            ),
            (
                LifecycleIntentKind::Recover,
                slots(
                    SlotIdentity::Target,
                    SlotIdentity::Absent,
                    SlotIdentity::Replaced,
                ),
                LifecycleStep::RemoveReplacedStage,
            ),
            (
                LifecycleIntentKind::Recover,
                slots(
                    SlotIdentity::Target,
                    SlotIdentity::Absent,
                    SlotIdentity::Absent,
                ),
                LifecycleStep::Complete,
            ),
            (
                LifecycleIntentKind::DestroyActive,
                slots(
                    SlotIdentity::Source,
                    SlotIdentity::Absent,
                    SlotIdentity::Tombstone,
                ),
                LifecycleStep::ExchangeStagedWithActive,
            ),
            (
                LifecycleIntentKind::DestroyActive,
                slots(
                    SlotIdentity::Tombstone,
                    SlotIdentity::Absent,
                    SlotIdentity::Source,
                ),
                LifecycleStep::RemoveSourceStage,
            ),
            (
                LifecycleIntentKind::DestroyActive,
                slots(
                    SlotIdentity::Tombstone,
                    SlotIdentity::Absent,
                    SlotIdentity::Absent,
                ),
                LifecycleStep::Complete,
            ),
            (
                LifecycleIntentKind::DestroyPrevious,
                slots(
                    SlotIdentity::Absent,
                    SlotIdentity::Source,
                    SlotIdentity::Tombstone,
                ),
                LifecycleStep::ExchangeStagedWithPrevious,
            ),
            (
                LifecycleIntentKind::DestroyPrevious,
                slots(
                    SlotIdentity::Absent,
                    SlotIdentity::Tombstone,
                    SlotIdentity::Source,
                ),
                LifecycleStep::RemoveSourceStage,
            ),
            (
                LifecycleIntentKind::DestroyPrevious,
                slots(
                    SlotIdentity::Absent,
                    SlotIdentity::Tombstone,
                    SlotIdentity::Absent,
                ),
                LifecycleStep::Complete,
            ),
        ];

        for (kind, slots, expected) in cases {
            assert_eq!(
                lifecycle_step(kind, slots).expect("exact lifecycle state"),
                expected,
                "intent {kind:?} with slots {slots:?}",
            );
        }
    }

    #[test]
    fn mismatched_partial_duplicate_and_unbound_slots_are_never_actionable() {
        // Break caught: deleting or exchanging a slot that is not exactly
        // bound to the retained ledger loses evidence of corruption and may
        // discard the only valid credential.
        for invalid in [
            SlotIdentity::Mismatch,
            SlotIdentity::Partial,
            SlotIdentity::Duplicate,
            SlotIdentity::Unbound,
        ] {
            for kind in [
                LifecycleIntentKind::Rotate,
                LifecycleIntentKind::Recover,
                LifecycleIntentKind::DestroyActive,
                LifecycleIntentKind::DestroyPrevious,
            ] {
                for slots in [
                    slots(invalid, SlotIdentity::Absent, SlotIdentity::Target),
                    slots(SlotIdentity::Target, invalid, SlotIdentity::Absent),
                    slots(SlotIdentity::Target, SlotIdentity::Absent, invalid),
                ] {
                    assert_eq!(
                        lifecycle_step(kind, slots).expect_err("untrusted slot state"),
                        ProvisioningSecretStoreError::Rejected,
                        "intent {kind:?} with slots {slots:?}",
                    );
                }
            }
        }
    }

    #[test]
    fn tombstone_stage_has_only_exact_identity_files_and_no_credential_bytes() {
        // Break caught: reusing credential-generation preparation for a
        // tombstone can retain ciphertext in a logically destroyed slot.
        let fixture = LifecycleFixture::new();
        let manifest = GenerationManifest {
            generation: 2,
            load: ProvisioningLoadId::new([0x22; 32]),
            secret_ref: provisioning_secret_ref(2, [0x33; PROVIDER_REFERENCE_ID_BYTES])
                .expect("fixture reference"),
            ciphertext_digest: [0; 32],
            content: GenerationContent::Tombstone,
        };
        write_staged_tombstone(&fixture.root_fd, &manifest, &mut FaultInjector::disabled())
            .expect("prepare tombstone stage");

        let mut names = fs::read_dir(fixture.path.join(STAGED_DIRECTORY))
            .expect("read staged tombstone")
            .map(|entry| {
                entry
                    .expect("staged entry")
                    .file_name()
                    .into_string()
                    .expect("ASCII fixture name")
            })
            .collect::<Vec<_>>();
        names.sort();
        assert_eq!(names, ["manifest", "reference", TOMBSTONE_FILE]);
        assert!(
            generation_matches(&fixture.root_fd, STAGED_DIRECTORY, &manifest)
                .expect("validate tombstone stage")
        );
    }

    #[test]
    fn directory_exchange_swaps_only_the_named_sibling_generation_slots() {
        // Break caught: sequential renames create a missing-slot window and
        // can move a generation outside the descriptor-relative namespace.
        let fixture = LifecycleFixture::new();
        fixture.directory_with_marker(ACTIVE_DIRECTORY, b"active");
        fixture.directory_with_marker(STAGED_DIRECTORY, b"staged");
        exchange_staged_with_active(&fixture.root_fd, &mut FaultInjector::disabled())
            .expect("exchange active");
        assert_eq!(fixture.marker(ACTIVE_DIRECTORY), b"staged");
        assert_eq!(fixture.marker(STAGED_DIRECTORY), b"active");

        fs::rename(
            fixture.path.join(STAGED_DIRECTORY),
            fixture.path.join(PREVIOUS_DIRECTORY),
        )
        .expect("park fixture previous");
        fixture.directory_with_marker(STAGED_DIRECTORY, b"tombstone");
        exchange_staged_with_previous(&fixture.root_fd, &mut FaultInjector::disabled())
            .expect("exchange previous");
        assert_eq!(fixture.marker(PREVIOUS_DIRECTORY), b"tombstone");
        assert_eq!(fixture.marker(STAGED_DIRECTORY), b"active");
    }

    #[test]
    fn completed_ledger_open_validates_exact_active_and_previous_identities() {
        // Break caught: validating only that Active exists lets a corrupt or
        // substituted retained Previous generation pass ordinary open.
        let fixture = AdminLifecycleFixture::new();
        let previous = generation_record(1, 0x31, GenerationState::Previous, b"previous");
        let active = generation_record(2, 0x41, GenerationState::Active, b"active");
        fixture.write_generation(PREVIOUS_DIRECTORY, &previous, b"previous");
        fixture.write_generation(ACTIVE_DIRECTORY, &active, b"active");
        fixture.write_ledger(ProviderLedger {
            host_key_identity: fixture.host_identity,
            intent: None,
            generations: vec![previous.clone(), active],
            backups: vec![],
            recoveries: vec![],
            destroys: vec![],
        });

        drop(fixture.admin().expect("open exact completed ledger"));
        let previous_ciphertext = fixture
            .provisioning
            .join(PREVIOUS_DIRECTORY)
            .join("credential.cred");
        fs::write(&previous_ciphertext, b"substituted").expect("corrupt previous fixture");
        assert_eq!(
            fixture.admin().expect_err("mismatched previous generation"),
            ProvisioningSecretStoreError::Rejected
        );
        assert_eq!(
            fs::read(previous_ciphertext).expect("retained mismatched previous"),
            b"substituted"
        );
    }

    #[test]
    fn completed_ledger_rejects_a_duplicate_destroyed_generation_without_deletion() {
        // Break caught: validating each retained slot independently could
        // accept two filesystem copies for one destroyed ledger identity.
        let fixture = AdminLifecycleFixture::new();
        let mut destroyed =
            generation_record(1, 0x31, GenerationState::Destroyed, b"unused-ciphertext");
        destroyed.ciphertext_digest = [0; 32];
        fixture.write_tombstone_slot(ACTIVE_DIRECTORY, &destroyed);
        fixture.write_tombstone_slot(PREVIOUS_DIRECTORY, &destroyed);
        fixture.write_ledger(ProviderLedger {
            host_key_identity: fixture.host_identity,
            intent: None,
            generations: vec![destroyed],
            backups: vec![],
            recoveries: vec![],
            destroys: vec![],
        });
        let active_before = fs::read(fixture.provisioning.join("active/manifest"))
            .expect("read duplicate active tombstone");
        let previous_before = fs::read(fixture.provisioning.join("previous/manifest"))
            .expect("read duplicate previous tombstone");

        assert_eq!(
            fixture.admin().expect_err("duplicate destroyed slot"),
            ProvisioningSecretStoreError::Rejected
        );
        assert_eq!(
            fs::read(fixture.provisioning.join("active/manifest"))
                .expect("retained active tombstone"),
            active_before
        );
        assert_eq!(
            fs::read(fixture.provisioning.join("previous/manifest"))
                .expect("retained previous tombstone"),
            previous_before
        );
    }

    #[test]
    fn rotate_reconciliation_exchanges_parks_and_commits_the_exact_snapshot() {
        // Break caught: completing Rotate after only one rename can lose the
        // previous credential or publish a ledger that disagrees with slots.
        let fixture = ReconcileFixture::new();
        let source = generation_record(1, 0x31, GenerationState::Active, b"old");
        let target = generation_record(2, 0x41, GenerationState::Active, b"new");
        let (intent_ledger, completed) = rotate_ledgers(&source, &target);
        fixture.write_generation(ACTIVE_DIRECTORY, &source, b"old");
        fixture.write_generation(STAGED_DIRECTORY, &target, b"new");
        fixture.write_ledger(&intent_ledger);

        reconcile_lifecycle(
            &fixture.provisioning_fd,
            &fixture.ledger_fd,
            intent_ledger,
            &completed,
            &mut FaultInjector::disabled(),
        )
        .expect("reconcile exact rotation");

        assert!(fixture.generation_matches(ACTIVE_DIRECTORY, &target));
        let mut previous = source;
        previous.state = GenerationState::Previous;
        assert!(fixture.generation_matches(PREVIOUS_DIRECTORY, &previous));
        assert!(!fixture.provisioning.join(STAGED_DIRECTORY).exists());
        assert_eq!(fixture.read_ledger(), completed);
    }

    #[test]
    fn rotate_reconciliation_rejects_mismatched_stage_without_mutation() {
        // Break caught: a target manifest with different ciphertext must not
        // cause the source Active generation to be exchanged or removed.
        let fixture = ReconcileFixture::new();
        let source = generation_record(1, 0x31, GenerationState::Active, b"old");
        let target = generation_record(2, 0x41, GenerationState::Active, b"new");
        let wrong = generation_record(2, 0x51, GenerationState::Active, b"wrong");
        let (intent_ledger, completed) = rotate_ledgers(&source, &target);
        fixture.write_generation(ACTIVE_DIRECTORY, &source, b"old");
        fixture.write_generation(STAGED_DIRECTORY, &wrong, b"wrong");
        fixture.write_ledger(&intent_ledger);
        let before = fixture.namespace_bytes();

        assert_eq!(
            reconcile_lifecycle(
                &fixture.provisioning_fd,
                &fixture.ledger_fd,
                intent_ledger,
                &completed,
                &mut FaultInjector::disabled(),
            )
            .expect_err("mismatched staged rotation"),
            ProvisioningSecretStoreError::Rejected
        );
        assert_eq!(fixture.namespace_bytes(), before);
    }

    #[test]
    fn real_partial_duplicate_mismatch_and_unbound_slots_are_preserved_on_rejection() {
        // Break caught: classification must reject before the first rename or
        // unlink for every non-exact on-disk representation.
        for scenario in ["partial", "duplicate", "mismatch", "unbound", "extra"] {
            let fixture = ReconcileFixture::new();
            let source = generation_record(1, 0x31, GenerationState::Active, b"old");
            let target = generation_record(2, 0x41, GenerationState::Active, b"new");
            let (intent_ledger, completed) = rotate_ledgers(&source, &target);
            fixture.write_generation(ACTIVE_DIRECTORY, &source, b"old");
            match scenario {
                "partial" => fixture.write_partial_stage(),
                "duplicate" => fixture.write_generation(STAGED_DIRECTORY, &source, b"old"),
                "mismatch" => fixture.write_generation(STAGED_DIRECTORY, &target, b"corrupt"),
                "unbound" => {
                    let wrong = generation_record(2, 0x51, GenerationState::Active, b"unbound");
                    fixture.write_generation(STAGED_DIRECTORY, &wrong, b"unbound");
                }
                "extra" => {
                    fixture.write_generation(STAGED_DIRECTORY, &target, b"new");
                    let extra = fixture
                        .provisioning
                        .join(STAGED_DIRECTORY)
                        .join("unexpected");
                    fs::write(&extra, b"extra").expect("write unexpected generation file");
                    fs::set_permissions(extra, fs::Permissions::from_mode(0o600))
                        .expect("protect unexpected generation file");
                }
                _ => unreachable!(),
            }
            fixture.write_ledger(&intent_ledger);
            let before = fixture.namespace_bytes();

            assert_eq!(
                reconcile_lifecycle(
                    &fixture.provisioning_fd,
                    &fixture.ledger_fd,
                    intent_ledger,
                    &completed,
                    &mut FaultInjector::disabled(),
                )
                .expect_err("non-exact lifecycle slot"),
                ProvisioningSecretStoreError::Rejected,
                "scenario {scenario}",
            );
            assert_eq!(fixture.namespace_bytes(), before, "scenario {scenario}");
        }
    }

    #[test]
    fn recovery_reconciliation_promotes_missing_and_replaces_corrupt_active_exactly() {
        // Break caught: recovery must continue the recorded exact generation,
        // never generate/select another reference or restore an older one.
        for corrupt_active in [false, true] {
            let fixture = ReconcileFixture::new();
            let target = generation_record(2, 0x41, GenerationState::Active, b"exact");
            let (intent_ledger, completed) = recovery_ledgers(&target);
            if corrupt_active {
                fixture.write_generation(ACTIVE_DIRECTORY, &target, b"corrupt");
            }
            fixture.write_generation(STAGED_DIRECTORY, &target, b"exact");
            fixture.write_ledger(&intent_ledger);

            reconcile_lifecycle(
                &fixture.provisioning_fd,
                &fixture.ledger_fd,
                intent_ledger,
                &completed,
                &mut FaultInjector::disabled(),
            )
            .expect("reconcile exact recovery");

            assert!(fixture.generation_matches(ACTIVE_DIRECTORY, &target));
            assert!(!fixture.provisioning.join(STAGED_DIRECTORY).exists());
            assert_eq!(fixture.read_ledger(), completed);
        }
    }

    #[test]
    fn recovery_completion_without_the_intent_bound_record_is_rejected_before_mutation() {
        // Break caught: clearing Recover intent without retaining its exact
        // operation/artifact binding would make retries indeterminate.
        let fixture = ReconcileFixture::new();
        let target = generation_record(2, 0x41, GenerationState::Active, b"exact");
        let (intent_ledger, mut completed_without_binding) = recovery_ledgers(&target);
        completed_without_binding.recoveries.clear();
        fixture.write_generation(STAGED_DIRECTORY, &target, b"exact");
        fixture.write_ledger(&intent_ledger);
        let before = fixture.namespace_bytes();

        assert_eq!(
            reconcile_lifecycle(
                &fixture.provisioning_fd,
                &fixture.ledger_fd,
                intent_ledger,
                &completed_without_binding,
                &mut FaultInjector::disabled(),
            )
            .expect_err("missing recovery completion binding"),
            ProvisioningSecretStoreError::Rejected
        );
        assert_eq!(fixture.namespace_bytes(), before);
    }

    #[test]
    fn destroy_reconciliation_exchanges_tombstone_and_removes_only_exact_source() {
        // Break caught: completing destruction before removal can leave the
        // exact target ciphertext in a provider generation slot.
        for state in [GenerationState::Active, GenerationState::Previous] {
            let fixture = ReconcileFixture::new();
            let source = generation_record(1, 0x31, state, b"secret-ciphertext");
            let (intent_ledger, completed) = destroy_ledgers(&source);
            let source_slot = if state == GenerationState::Active {
                ACTIVE_DIRECTORY
            } else {
                PREVIOUS_DIRECTORY
            };
            fixture.write_generation(source_slot, &source, b"secret-ciphertext");
            fixture.write_tombstone(&completed.generations[0]);
            fixture.write_ledger(&intent_ledger);

            reconcile_lifecycle(
                &fixture.provisioning_fd,
                &fixture.ledger_fd,
                intent_ledger,
                &completed,
                &mut FaultInjector::disabled(),
            )
            .expect("reconcile exact destroy");

            assert!(!fixture.provisioning.join(STAGED_DIRECTORY).exists());
            assert_eq!(fixture.read_ledger(), completed);
            let tombstone_slot = fixture.provisioning.join(source_slot);
            assert!(!tombstone_slot.join("credential.cred").exists());
            assert!(tombstone_slot.join(TOMBSTONE_FILE).is_file());
        }
    }

    #[test]
    fn lifecycle_fault_boundaries_reopen_to_one_exact_completed_rotation() {
        // Break caught: a failure after an exchange, park, parent sync, or
        // ledger write must be resumable from the exact persisted intent and
        // must never select or reconstruct a generation.
        for point in [
            FaultPoint::IntentFileSynced,
            FaultPoint::IntentRenamed,
            FaultPoint::IntentParentSynced,
            FaultPoint::ActiveExchanged,
            FaultPoint::ProvisioningParentSynced,
            FaultPoint::PreviousRenamed,
            FaultPoint::CompleteFileSynced,
            FaultPoint::CompleteRenamed,
            FaultPoint::CompleteParentSynced,
        ] {
            let fixture = ReconcileFixture::new();
            let source = generation_record(1, 0x31, GenerationState::Active, b"old");
            let target = generation_record(2, 0x41, GenerationState::Active, b"new");
            let (intent_ledger, completed) = rotate_ledgers(&source, &target);
            fixture.write_generation(ACTIVE_DIRECTORY, &source, b"old");
            fixture.write_generation(STAGED_DIRECTORY, &target, b"new");
            fixture.write_ledger_without_intent(&intent_ledger);

            if matches!(
                point,
                FaultPoint::IntentFileSynced
                    | FaultPoint::IntentRenamed
                    | FaultPoint::IntentParentSynced
            ) {
                assert_eq!(
                    commit_lifecycle_intent(
                        &fixture.ledger_fd,
                        &intent_ledger,
                        &mut FaultInjector::at(point),
                    )
                    .expect_err("injected intent durability fault"),
                    ProvisioningSecretStoreError::Unavailable,
                    "fault {point:?}",
                );
            } else {
                fixture.write_ledger(&intent_ledger);
                assert_eq!(
                    reconcile_lifecycle(
                        &fixture.provisioning_fd,
                        &fixture.ledger_fd,
                        intent_ledger.clone(),
                        &completed,
                        &mut FaultInjector::at(point),
                    )
                    .expect_err("injected lifecycle durability fault"),
                    ProvisioningSecretStoreError::Unavailable,
                    "fault {point:?}",
                );
            }

            let persisted = fixture.read_reconciliation_ledger();
            if persisted.intent.is_some() {
                let (provisioning_fd, ledger_fd) = fixture.reopen();
                reconcile_lifecycle(
                    &provisioning_fd,
                    &ledger_fd,
                    persisted,
                    &completed,
                    &mut FaultInjector::disabled(),
                )
                .expect("reconcile from fresh descriptors");
            }
            assert_eq!(fixture.read_ledger(), completed, "fault {point:?}");
            assert!(fixture.generation_matches(ACTIVE_DIRECTORY, &target));
            let mut previous = source;
            previous.state = GenerationState::Previous;
            assert!(fixture.generation_matches(PREVIOUS_DIRECTORY, &previous));
            assert!(!fixture.provisioning.join(STAGED_DIRECTORY).exists());
        }
    }

    #[test]
    fn tombstone_previous_exchange_and_replaced_deletion_faults_reopen_exactly() {
        // Break caught: the three non-rotation durability boundaries must
        // retain enough exact intent-bound state for a fresh reconciler.
        {
            let fixture = ReconcileFixture::new();
            let source = generation_record(1, 0x31, GenerationState::Active, b"secret");
            let (intent_ledger, completed) = destroy_ledgers(&source);
            fixture.write_generation(ACTIVE_DIRECTORY, &source, b"secret");
            let tombstone = manifest_for(&completed.generations[0]);
            assert_eq!(
                write_staged_tombstone(
                    &fixture.provisioning_fd,
                    &tombstone,
                    &mut FaultInjector::at(FaultPoint::StagedTombstoneSynced),
                )
                .expect_err("injected staged tombstone fault"),
                ProvisioningSecretStoreError::Unavailable
            );
            assert!(
                generation_matches(&fixture.provisioning_fd, STAGED_DIRECTORY, &tombstone)
                    .expect("exact interrupted tombstone")
            );
            assert!(
                !fixture
                    .provisioning
                    .join(STAGED_DIRECTORY)
                    .join("credential.cred")
                    .exists()
            );
            fixture.write_ledger(&intent_ledger);
            let (provisioning_fd, ledger_fd) = fixture.reopen();
            reconcile_lifecycle(
                &provisioning_fd,
                &ledger_fd,
                fixture.read_ledger(),
                &completed,
                &mut FaultInjector::disabled(),
            )
            .expect("reopen interrupted tombstone preparation");
            assert_eq!(fixture.read_ledger(), completed);
        }

        {
            let fixture = ReconcileFixture::new();
            let source = generation_record(1, 0x31, GenerationState::Previous, b"old");
            let (intent_ledger, completed) = destroy_ledgers(&source);
            fixture.write_generation(PREVIOUS_DIRECTORY, &source, b"old");
            fixture.write_tombstone(&completed.generations[0]);
            fixture.write_ledger(&intent_ledger);
            assert_eq!(
                reconcile_lifecycle(
                    &fixture.provisioning_fd,
                    &fixture.ledger_fd,
                    intent_ledger,
                    &completed,
                    &mut FaultInjector::at(FaultPoint::PreviousExchanged),
                )
                .expect_err("injected previous exchange fault"),
                ProvisioningSecretStoreError::Unavailable
            );
            let (provisioning_fd, ledger_fd) = fixture.reopen();
            reconcile_lifecycle(
                &provisioning_fd,
                &ledger_fd,
                fixture.read_ledger(),
                &completed,
                &mut FaultInjector::disabled(),
            )
            .expect("reopen previous exchange");
            assert_eq!(fixture.read_ledger(), completed);
        }

        {
            let fixture = ReconcileFixture::new();
            let target = generation_record(2, 0x41, GenerationState::Active, b"exact");
            let (intent_ledger, completed) = recovery_ledgers(&target);
            fixture.write_generation(ACTIVE_DIRECTORY, &target, b"corrupt");
            fixture.write_generation(STAGED_DIRECTORY, &target, b"exact");
            fixture.write_ledger(&intent_ledger);
            assert_eq!(
                reconcile_lifecycle(
                    &fixture.provisioning_fd,
                    &fixture.ledger_fd,
                    intent_ledger,
                    &completed,
                    &mut FaultInjector::at(FaultPoint::ReplacedGenerationDeleted),
                )
                .expect_err("injected replaced deletion fault"),
                ProvisioningSecretStoreError::Unavailable
            );
            assert!(fixture.generation_matches(ACTIVE_DIRECTORY, &target));
            assert!(!fixture.provisioning.join(STAGED_DIRECTORY).exists());
            let (provisioning_fd, ledger_fd) = fixture.reopen();
            reconcile_lifecycle(
                &provisioning_fd,
                &ledger_fd,
                fixture.read_ledger(),
                &completed,
                &mut FaultInjector::disabled(),
            )
            .expect("reopen replaced deletion");
            assert_eq!(fixture.read_ledger(), completed);
        }
    }

    fn slots(
        active: SlotIdentity,
        previous: SlotIdentity,
        staged: SlotIdentity,
    ) -> GenerationSlots {
        GenerationSlots {
            active,
            previous,
            staged,
        }
    }

    struct LifecycleFixture {
        path: PathBuf,
        root_fd: rustix::fd::OwnedFd,
    }

    impl LifecycleFixture {
        fn new() -> Self {
            let serial = NEXT_FIXTURE.fetch_add(1, Ordering::Relaxed);
            let path = std::env::temp_dir().join(format!(
                "aster-systemd-lifecycle-test-{}-{serial}",
                std::process::id()
            ));
            fs::create_dir(&path).expect("create lifecycle fixture");
            fs::set_permissions(&path, fs::Permissions::from_mode(0o700))
                .expect("protect lifecycle fixture");
            let root_fd = open_secure_root(&path, false).expect("open lifecycle fixture");
            Self { path, root_fd }
        }

        fn directory_with_marker(&self, name: &str, marker: &[u8]) {
            let directory = self.path.join(name);
            fs::create_dir(&directory).expect("create generation fixture");
            fs::set_permissions(&directory, fs::Permissions::from_mode(0o700))
                .expect("protect generation fixture");
            fs::write(directory.join("marker"), marker).expect("write generation marker");
        }

        fn marker(&self, name: &str) -> Vec<u8> {
            fs::read(self.path.join(name).join("marker")).expect("read generation marker")
        }
    }

    impl Drop for LifecycleFixture {
        fn drop(&mut self) {
            let _ = remove_fixture(&self.path);
        }
    }

    struct AdminLifecycleFixture {
        path: PathBuf,
        provisioning: PathBuf,
        ledger: PathBuf,
        host_key: PathBuf,
        program: PathBuf,
        host_identity: [u8; 32],
    }

    impl AdminLifecycleFixture {
        fn new() -> Self {
            let serial = NEXT_FIXTURE.fetch_add(1, Ordering::Relaxed);
            let path = std::env::temp_dir().join(format!(
                "aster-systemd-completed-lifecycle-test-{}-{serial}",
                std::process::id()
            ));
            let provisioning = path.join("provisioning");
            let ledger = path.join("ledger");
            fs::create_dir_all(&provisioning).expect("create provisioning fixture");
            fs::create_dir_all(&ledger).expect("create ledger fixture");
            fs::set_permissions(&provisioning, fs::Permissions::from_mode(0o700))
                .expect("protect provisioning fixture");
            fs::set_permissions(&ledger, fs::Permissions::from_mode(0o700))
                .expect("protect ledger fixture");
            let host_key = path.join("credential.secret");
            fs::write(&host_key, [0x5a; 32]).expect("write host-key fixture");
            fs::set_permissions(&host_key, fs::Permissions::from_mode(0o600))
                .expect("protect host-key fixture");
            let host_identity = crate::admin::digest(&[0x5a; 32]);
            let program = path.join("unused-systemd-creds");
            fs::write(&program, "#!/bin/sh\nexit 99\n").expect("write unused provider fixture");
            fs::set_permissions(&program, fs::Permissions::from_mode(0o700))
                .expect("make provider fixture executable");
            Self {
                path,
                provisioning,
                ledger,
                host_key,
                program,
                host_identity,
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

        fn write_ledger(&self, ledger: ProviderLedger) {
            let path = self.ledger.join("ledger");
            fs::write(
                &path,
                encode_ledger(&ledger).expect("encode lifecycle fixture ledger"),
            )
            .expect("write lifecycle fixture ledger");
            fs::set_permissions(path, fs::Permissions::from_mode(0o600))
                .expect("protect lifecycle fixture ledger");
        }

        fn write_generation(&self, slot: &str, record: &GenerationRecord, ciphertext: &[u8]) {
            let directory = self.provisioning.join(slot);
            fs::create_dir(&directory).expect("create generation slot");
            fs::set_permissions(&directory, fs::Permissions::from_mode(0o700))
                .expect("protect generation slot");
            let manifest = GenerationManifest {
                generation: record.generation,
                load: record.load,
                secret_ref: record.secret_ref.clone(),
                ciphertext_digest: record.ciphertext_digest,
                content: GenerationContent::Credential,
            };
            for (name, bytes) in [
                ("credential.cred", ciphertext.to_vec()),
                ("reference", record.secret_ref.to_bytes()),
                ("manifest", crate::admin::files::encode_manifest(&manifest)),
            ] {
                let path = directory.join(name);
                fs::write(&path, bytes).expect("write generation file");
                fs::set_permissions(&path, fs::Permissions::from_mode(0o600))
                    .expect("protect generation file");
            }
        }

        fn write_tombstone_slot(&self, slot: &str, record: &GenerationRecord) {
            let directory = self.provisioning.join(slot);
            fs::create_dir(&directory).expect("create tombstone slot");
            fs::set_permissions(&directory, fs::Permissions::from_mode(0o700))
                .expect("protect tombstone slot");
            let manifest = manifest_for(record);
            for (name, bytes) in [
                ("reference", record.secret_ref.to_bytes()),
                ("manifest", crate::admin::files::encode_manifest(&manifest)),
                (TOMBSTONE_FILE, Vec::new()),
            ] {
                let path = directory.join(name);
                fs::write(&path, bytes).expect("write tombstone file");
                fs::set_permissions(&path, fs::Permissions::from_mode(0o600))
                    .expect("protect tombstone file");
            }
        }
    }

    impl Drop for AdminLifecycleFixture {
        fn drop(&mut self) {
            let _ = remove_fixture(&self.path);
        }
    }

    struct ReconcileFixture {
        path: PathBuf,
        provisioning: PathBuf,
        ledger: PathBuf,
        provisioning_fd: rustix::fd::OwnedFd,
        ledger_fd: rustix::fd::OwnedFd,
    }

    impl ReconcileFixture {
        fn new() -> Self {
            let serial = NEXT_FIXTURE.fetch_add(1, Ordering::Relaxed);
            let path = std::env::temp_dir().join(format!(
                "aster-systemd-reconcile-test-{}-{serial}",
                std::process::id()
            ));
            let provisioning = path.join("provisioning");
            let ledger = path.join("ledger");
            fs::create_dir_all(&provisioning).expect("create reconciliation provisioning root");
            fs::create_dir_all(&ledger).expect("create reconciliation ledger root");
            fs::set_permissions(&provisioning, fs::Permissions::from_mode(0o700))
                .expect("protect reconciliation provisioning root");
            fs::set_permissions(&ledger, fs::Permissions::from_mode(0o700))
                .expect("protect reconciliation ledger root");
            let provisioning_fd =
                open_secure_root(&provisioning, false).expect("open reconciliation root");
            let ledger_fd = open_secure_root(&ledger, false).expect("open ledger root");
            Self {
                path,
                provisioning,
                ledger,
                provisioning_fd,
                ledger_fd,
            }
        }

        fn write_generation(&self, slot: &str, record: &GenerationRecord, ciphertext: &[u8]) {
            write_generation(&self.provisioning, slot, record, ciphertext);
        }

        fn write_tombstone(&self, record: &GenerationRecord) {
            write_staged_tombstone(
                &self.provisioning_fd,
                &GenerationManifest {
                    generation: record.generation,
                    load: record.load,
                    secret_ref: record.secret_ref.clone(),
                    ciphertext_digest: [0; 32],
                    content: GenerationContent::Tombstone,
                },
                &mut FaultInjector::disabled(),
            )
            .expect("write reconciliation tombstone");
        }

        fn write_partial_stage(&self) {
            let staged = self.provisioning.join(STAGED_DIRECTORY);
            fs::create_dir(&staged).expect("create partial lifecycle stage");
            fs::set_permissions(&staged, fs::Permissions::from_mode(0o700))
                .expect("protect partial lifecycle stage");
            let ciphertext = staged.join("credential.cred");
            fs::write(&ciphertext, b"partial").expect("write partial lifecycle ciphertext");
            fs::set_permissions(ciphertext, fs::Permissions::from_mode(0o600))
                .expect("protect partial lifecycle ciphertext");
        }

        fn write_ledger(&self, ledger: &ProviderLedger) {
            let path = self.ledger.join("ledger");
            fs::write(
                &path,
                encode_ledger(ledger).expect("encode reconciliation ledger"),
            )
            .expect("write reconciliation ledger");
            fs::set_permissions(path, fs::Permissions::from_mode(0o600))
                .expect("protect reconciliation ledger");
        }

        fn write_ledger_without_intent(&self, ledger: &ProviderLedger) {
            let mut completed = ledger.clone();
            completed.intent = None;
            self.write_ledger(&completed);
        }

        fn reopen(&self) -> (rustix::fd::OwnedFd, rustix::fd::OwnedFd) {
            (
                open_secure_root(&self.provisioning, false)
                    .expect("reopen reconciliation provisioning root"),
                open_secure_root(&self.ledger, false).expect("reopen reconciliation ledger root"),
            )
        }

        fn read_ledger(&self) -> ProviderLedger {
            decode_ledger(&fs::read(self.ledger.join("ledger")).expect("read reconciled ledger"))
                .expect("decode reconciled ledger")
        }

        fn read_reconciliation_ledger(&self) -> ProviderLedger {
            let current = self.read_ledger();
            let pending_path = self.ledger.join("ledger.next");
            let pending = pending_path.exists().then(|| {
                decode_ledger(&fs::read(pending_path).expect("read pending reconciliation ledger"))
                    .expect("decode pending reconciliation ledger")
            });
            select_lifecycle_ledger(current, pending).expect("select exact reconciliation ledger")
        }

        fn generation_matches(&self, slot: &str, record: &GenerationRecord) -> bool {
            generation_matches(
                &self.provisioning_fd,
                slot,
                &GenerationManifest {
                    generation: record.generation,
                    load: record.load,
                    secret_ref: record.secret_ref.clone(),
                    ciphertext_digest: record.ciphertext_digest,
                    content: if record.state == GenerationState::Destroyed {
                        GenerationContent::Tombstone
                    } else {
                        GenerationContent::Credential
                    },
                },
            )
            .expect("validate reconciliation generation")
        }

        fn namespace_bytes(&self) -> Vec<(String, Vec<u8>)> {
            let mut bytes = Vec::new();
            for slot in [ACTIVE_DIRECTORY, PREVIOUS_DIRECTORY, STAGED_DIRECTORY] {
                let directory = self.provisioning.join(slot);
                if !directory.exists() {
                    continue;
                }
                let mut names = fs::read_dir(&directory)
                    .expect("read reconciliation slot")
                    .map(|entry| {
                        entry
                            .expect("read reconciliation entry")
                            .file_name()
                            .into_string()
                            .expect("ASCII reconciliation entry")
                    })
                    .collect::<Vec<_>>();
                names.sort();
                for name in names {
                    bytes.push((
                        format!("{slot}/{name}"),
                        fs::read(directory.join(&name)).expect("read reconciliation bytes"),
                    ));
                }
            }
            bytes.push((
                "ledger".to_owned(),
                fs::read(self.ledger.join("ledger")).expect("read reconciliation ledger bytes"),
            ));
            bytes
        }
    }

    impl Drop for ReconcileFixture {
        fn drop(&mut self) {
            let _ = remove_fixture(&self.path);
        }
    }

    fn rotate_ledgers(
        source: &GenerationRecord,
        target: &GenerationRecord,
    ) -> (ProviderLedger, ProviderLedger) {
        let completed_pre = ProviderLedger {
            host_key_identity: [0xa0; 32],
            intent: None,
            generations: vec![source.clone()],
            backups: vec![],
            recoveries: vec![],
            destroys: vec![],
        };
        let mut intent_ledger = completed_pre.clone();
        intent_ledger.intent = Some(LifecycleIntent {
            kind: LifecycleIntentKind::Rotate,
            operation: *target.install.as_bytes(),
            load: Some(target.load),
            target_ref: target.secret_ref.clone(),
            target_generation: target.generation,
            source_ref: Some(source.secret_ref.clone()),
            envelope_commitment: Some(target.envelope_commitment),
            expected_ciphertext_digest: Some(target.ciphertext_digest),
            expected_artifact_digest: None,
            pre_mutation_ledger_revision: crate::admin::digest(
                &encode_ledger(&completed_pre).expect("encode pre-rotation ledger"),
            ),
        });
        let mut previous = source.clone();
        previous.state = GenerationState::Previous;
        let completed = ProviderLedger {
            host_key_identity: completed_pre.host_key_identity,
            intent: None,
            generations: vec![previous, target.clone()],
            backups: vec![],
            recoveries: vec![],
            destroys: vec![],
        };
        (intent_ledger, completed)
    }

    fn recovery_ledgers(target: &GenerationRecord) -> (ProviderLedger, ProviderLedger) {
        let completed_pre = ProviderLedger {
            host_key_identity: [0xa0; 32],
            intent: None,
            generations: vec![target.clone()],
            backups: vec![BackupBinding {
                operation: [0x70; 32],
                secret_ref: target.secret_ref.clone(),
                generation: target.generation,
                artifact_digest: [0x72; 32],
            }],
            recoveries: vec![],
            destroys: vec![],
        };
        let mut intent_ledger = completed_pre.clone();
        intent_ledger.intent = Some(LifecycleIntent {
            kind: LifecycleIntentKind::Recover,
            operation: [0x71; 32],
            load: Some(target.load),
            target_ref: target.secret_ref.clone(),
            target_generation: target.generation,
            source_ref: None,
            envelope_commitment: None,
            expected_ciphertext_digest: Some(target.ciphertext_digest),
            expected_artifact_digest: Some([0x72; 32]),
            pre_mutation_ledger_revision: crate::admin::digest(
                &encode_ledger(&completed_pre).expect("encode pre-recovery ledger"),
            ),
        });
        let mut completed = completed_pre;
        completed.recoveries.push(RecoveryBinding {
            operation: [0x71; 32],
            backup_operation: [0x70; 32],
            secret_ref: target.secret_ref.clone(),
            generation: target.generation,
            artifact_digest: [0x72; 32],
        });
        (intent_ledger, completed)
    }

    fn destroy_ledgers(source: &GenerationRecord) -> (ProviderLedger, ProviderLedger) {
        let completed_pre = ProviderLedger {
            host_key_identity: [0xa0; 32],
            intent: None,
            generations: vec![source.clone()],
            backups: vec![],
            recoveries: vec![],
            destroys: vec![],
        };
        let mut intent_ledger = completed_pre.clone();
        intent_ledger.intent = Some(LifecycleIntent {
            kind: if source.state == GenerationState::Active {
                LifecycleIntentKind::DestroyActive
            } else {
                LifecycleIntentKind::DestroyPrevious
            },
            operation: [0x81; 32],
            load: None,
            target_ref: source.secret_ref.clone(),
            target_generation: source.generation,
            source_ref: None,
            envelope_commitment: None,
            expected_ciphertext_digest: None,
            expected_artifact_digest: None,
            pre_mutation_ledger_revision: crate::admin::digest(
                &encode_ledger(&completed_pre).expect("encode pre-destroy ledger"),
            ),
        });
        let mut destroyed = source.clone();
        destroyed.state = GenerationState::Destroyed;
        destroyed.ciphertext_digest = [0; 32];
        let completed = ProviderLedger {
            host_key_identity: completed_pre.host_key_identity,
            intent: None,
            generations: vec![destroyed],
            backups: vec![],
            recoveries: vec![],
            destroys: vec![DestroyBinding {
                operation: ProvisioningDestroyId::new([0x81; 32]),
                secret_ref: source.secret_ref.clone(),
                generation: source.generation,
                outcome: DestroyBindingOutcome::Destroyed,
            }],
        };
        (intent_ledger, completed)
    }

    fn generation_record(
        generation: u64,
        reference_byte: u8,
        state: GenerationState,
        ciphertext: &[u8],
    ) -> GenerationRecord {
        GenerationRecord {
            install: ProvisioningInstallId::new([reference_byte.wrapping_add(1); 32]),
            load: ProvisioningLoadId::new([reference_byte.wrapping_add(2); 32]),
            secret_ref: provisioning_secret_ref(
                generation,
                [reference_byte; PROVIDER_REFERENCE_ID_BYTES],
            )
            .expect("fixture generation reference"),
            generation,
            envelope_commitment: [reference_byte.wrapping_add(3); 32],
            ciphertext_digest: crate::admin::digest(ciphertext),
            state,
        }
    }

    fn write_generation(
        provisioning: &Path,
        slot: &str,
        record: &GenerationRecord,
        ciphertext: &[u8],
    ) {
        let directory = provisioning.join(slot);
        fs::create_dir(&directory).expect("create generation slot");
        fs::set_permissions(&directory, fs::Permissions::from_mode(0o700))
            .expect("protect generation slot");
        let manifest = GenerationManifest {
            generation: record.generation,
            load: record.load,
            secret_ref: record.secret_ref.clone(),
            ciphertext_digest: record.ciphertext_digest,
            content: GenerationContent::Credential,
        };
        for (name, bytes) in [
            ("credential.cred", ciphertext.to_vec()),
            ("reference", record.secret_ref.to_bytes()),
            ("manifest", crate::admin::files::encode_manifest(&manifest)),
        ] {
            let path = directory.join(name);
            fs::write(&path, bytes).expect("write generation file");
            fs::set_permissions(&path, fs::Permissions::from_mode(0o600))
                .expect("protect generation file");
        }
    }

    fn manifest_for(record: &GenerationRecord) -> GenerationManifest {
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

    fn remove_fixture(path: &Path) -> std::io::Result<()> {
        fs::remove_dir_all(path)
    }
}
