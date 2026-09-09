use super::files::{
    ACTIVE_DIRECTORY, CIPHERTEXT_FILE, FaultInjector, FaultPoint, GenerationContent,
    GenerationManifest, LedgerWrite, MANIFEST_FILE, PREVIOUS_DIRECTORY, REFERENCE_FILE,
    STAGED_DIRECTORY, TOMBSTONE_FILE, child_directory_exists, decode_manifest,
    directory_has_exact_entries, encode_manifest, generation_identity_matches, generation_matches,
    open_child_directory, promote_staged_generation, publish_pending_ledger, read_optional_file,
    remove_optional_file, sync_directory, write_ledger_atomically, write_new_file,
};
use super::ledger::{
    GenerationRecord, GenerationState, LifecycleIntent, LifecycleIntentKind, ProviderLedger,
    decode_ledger, encode_ledger,
};
use aster_mesh::ProvisioningSecretStoreError;
use rustix::fd::OwnedFd;
use std::collections::BTreeSet;
use zeroize::Zeroizing;

const CLEANUP_DIRECTORY: &str = "cleanup";

pub(super) fn select_lifecycle_ledger(
    current: ProviderLedger,
    pending: Option<ProviderLedger>,
) -> Result<ProviderLedger, ProvisioningSecretStoreError> {
    let Some(pending) = pending else {
        return Ok(current);
    };
    if current
        .intent
        .as_ref()
        .is_some_and(|intent| intent.kind == LifecycleIntentKind::Install)
    {
        return Ok(current);
    }
    if current.intent.is_some() {
        if pending != completed_from_intent(&current)? {
            return Err(ProvisioningSecretStoreError::Rejected);
        }
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
    if intent.kind != LifecycleIntentKind::Install {
        let _ = completed_from_intent(ledger)?;
    }
    let encoded = Zeroizing::new(encode_ledger(ledger)?);
    if decode_ledger(&encoded)? != *ledger {
        return Err(ProvisioningSecretStoreError::Rejected);
    }
    write_ledger_atomically(ledger_root, &encoded, LedgerWrite::Intent, faults)
}

pub(super) fn publish_pending_lifecycle_intent(
    provisioning_root: &OwnedFd,
    ledger_root: &OwnedFd,
    ledger: &ProviderLedger,
    faults: &mut FaultInjector,
) -> Result<(), ProvisioningSecretStoreError> {
    let _ = validate_lifecycle_phase(provisioning_root, ledger)?;
    let intent = ledger
        .intent
        .as_ref()
        .ok_or(ProvisioningSecretStoreError::Rejected)?;
    validate_intent_revision(ledger, intent)?;
    let encoded = Zeroizing::new(encode_ledger(ledger)?);
    if decode_ledger(&encoded)? != *ledger {
        return Err(ProvisioningSecretStoreError::Rejected);
    }
    publish_pending_ledger(ledger_root, &encoded, faults)
}

/// Validates that an intent's semantic completion and current filesystem phase
/// are exact without changing either namespace.
pub(super) fn validate_lifecycle_phase(
    provisioning_root: &OwnedFd,
    ledger: &ProviderLedger,
) -> Result<ProviderLedger, ProvisioningSecretStoreError> {
    let intent = ledger
        .intent
        .as_ref()
        .ok_or(ProvisioningSecretStoreError::Rejected)?;
    if intent.kind == LifecycleIntentKind::Install {
        return Err(ProvisioningSecretStoreError::Rejected);
    }
    let completed = completed_from_intent(ledger)?;
    let target = target_manifest(&completed, intent)?;
    let source = source_manifest(ledger, intent)?;
    let slots =
        inspect_generation_slots(provisioning_root, ledger, intent, &target, source.as_ref())?;
    let _ = lifecycle_step(intent.kind, slots)?;
    Ok(completed)
}

/// Replays the ledger-root durability prerequisite before any provisioning
/// namespace mutation resumes from a persisted intent.
pub(super) fn sync_intent_parent_before_mutation(
    ledger_root: &OwnedFd,
    ledger: &ProviderLedger,
    faults: &mut FaultInjector,
) -> Result<(), ProvisioningSecretStoreError> {
    if ledger.intent.is_none() {
        return Err(ProvisioningSecretStoreError::Rejected);
    }
    sync_directory(ledger_root)?;
    faults.hit(FaultPoint::IntentParentReplayed)
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
    validate_completed_snapshot(&ledger, completed)?;
    let target = target_manifest(completed, intent)?;
    let source = source_manifest(&ledger, intent)?;

    for _ in 0..8 {
        let slots =
            inspect_generation_slots(provisioning_root, &ledger, intent, &target, source.as_ref())?;
        match lifecycle_step(intent.kind, slots)? {
            LifecycleStep::ExchangeStagedWithActive => {
                sync_staged_before_namespace_switch(provisioning_root, faults)?;
                exchange_staged_with_active(provisioning_root, faults)?;
            }
            LifecycleStep::ExchangeStagedWithPrevious => {
                sync_staged_before_namespace_switch(provisioning_root, faults)?;
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
                sync_staged_before_namespace_switch(provisioning_root, faults)?;
                promote_staged_generation(provisioning_root, faults)?;
            }
            LifecycleStep::RemovePreviousTombstone => {
                move_bound_generation_to_cleanup(
                    provisioning_root,
                    PREVIOUS_DIRECTORY,
                    &target,
                    true,
                    faults,
                )?;
            }
            step @ (LifecycleStep::RemoveSourceStage | LifecycleStep::RemoveReplacedStage) => {
                move_bound_generation_to_cleanup(
                    provisioning_root,
                    STAGED_DIRECTORY,
                    source
                        .as_ref()
                        .ok_or(ProvisioningSecretStoreError::Rejected)?,
                    step == LifecycleStep::RemoveSourceStage,
                    faults,
                )?;
            }
            step @ (LifecycleStep::DeleteSourceCleanup
            | LifecycleStep::DeleteReplacedCleanup
            | LifecycleStep::DeletePreviousTombstoneCleanup) => {
                sync_directory(provisioning_root)?;
                faults.hit(FaultPoint::CleanupParentSynced)?;
                let (expected, require_digest) = match step {
                    LifecycleStep::DeletePreviousTombstoneCleanup => (&target, true),
                    LifecycleStep::DeleteSourceCleanup => (
                        source
                            .as_ref()
                            .ok_or(ProvisioningSecretStoreError::Rejected)?,
                        true,
                    ),
                    LifecycleStep::DeleteReplacedCleanup => (
                        source
                            .as_ref()
                            .ok_or(ProvisioningSecretStoreError::Rejected)?,
                        false,
                    ),
                    _ => return Err(ProvisioningSecretStoreError::Rejected),
                };
                delete_bound_cleanup_contents(provisioning_root, expected, require_digest, faults)?;
            }
            LifecycleStep::RemoveEmptyCleanup => {
                delete_empty_cleanup(provisioning_root, faults)?;
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
) -> Result<(), ProvisioningSecretStoreError> {
    if completed.intent.is_some() || completed.host_key_identity != ledger.host_key_identity {
        return Err(ProvisioningSecretStoreError::Rejected);
    }
    let encoded = encode_ledger(completed)?;
    if decode_ledger(&encoded)? != *completed || completed_from_intent(ledger)? != *completed {
        return Err(ProvisioningSecretStoreError::Rejected);
    }
    Ok(())
}

pub(super) fn completed_from_intent(
    ledger: &ProviderLedger,
) -> Result<ProviderLedger, ProvisioningSecretStoreError> {
    let intent = ledger
        .intent
        .as_ref()
        .ok_or(ProvisioningSecretStoreError::Rejected)?;
    validate_intent_revision(ledger, intent)?;
    let mut completed = ledger.clone();
    completed.intent = None;
    match intent.kind {
        LifecycleIntentKind::Rotate => {
            let source_ref = intent
                .source_ref
                .as_ref()
                .ok_or(ProvisioningSecretStoreError::Rejected)?;
            let source_index = ledger
                .generations
                .iter()
                .position(|record| {
                    record.secret_ref == *source_ref && record.state == GenerationState::Active
                })
                .ok_or(ProvisioningSecretStoreError::Rejected)?;
            let source = &ledger.generations[source_index];
            if ledger
                .generations
                .iter()
                .any(|record| record.state == GenerationState::Previous)
                || intent.backup_operation.is_some()
                || intent.load.is_none()
                || intent.envelope_commitment.is_none()
                || intent.expected_ciphertext_digest.is_none()
                || intent.expected_artifact_digest.is_some()
                || intent.target_generation
                    != source
                        .generation
                        .checked_add(1)
                        .ok_or(ProvisioningSecretStoreError::Rejected)?
            {
                return Err(ProvisioningSecretStoreError::Rejected);
            }
            completed.generations[source_index].state = GenerationState::Previous;
            completed.generations.push(GenerationRecord {
                install: aster_mesh::ProvisioningInstallId::new(intent.operation),
                load: intent.load.ok_or(ProvisioningSecretStoreError::Rejected)?,
                secret_ref: intent.target_ref.clone(),
                generation: intent.target_generation,
                envelope_commitment: intent
                    .envelope_commitment
                    .ok_or(ProvisioningSecretStoreError::Rejected)?,
                ciphertext_digest: intent
                    .expected_ciphertext_digest
                    .ok_or(ProvisioningSecretStoreError::Rejected)?,
                state: GenerationState::Active,
            });
        }
        LifecycleIntentKind::Recover => {
            let target = ledger
                .generations
                .iter()
                .find(|record| {
                    record.secret_ref == intent.target_ref
                        && record.generation == intent.target_generation
                        && record.state == GenerationState::Active
                })
                .ok_or(ProvisioningSecretStoreError::Rejected)?;
            let backup_operation = intent
                .backup_operation
                .ok_or(ProvisioningSecretStoreError::Rejected)?;
            let artifact_digest = intent
                .expected_artifact_digest
                .ok_or(ProvisioningSecretStoreError::Rejected)?;
            if intent.load != Some(target.load)
                || intent.source_ref.is_some()
                || intent.envelope_commitment.is_some()
                || intent.expected_ciphertext_digest != Some(target.ciphertext_digest)
                || !ledger.backups.iter().any(|binding| {
                    binding.operation == backup_operation
                        && binding.secret_ref == intent.target_ref
                        && binding.generation == intent.target_generation
                        && binding.artifact_digest == artifact_digest
                })
            {
                return Err(ProvisioningSecretStoreError::Rejected);
            }
            completed.recoveries.push(super::ledger::RecoveryBinding {
                operation: intent.operation,
                backup_operation,
                secret_ref: intent.target_ref.clone(),
                generation: intent.target_generation,
                artifact_digest,
            });
        }
        LifecycleIntentKind::DestroyActive | LifecycleIntentKind::DestroyPrevious => {
            let expected_state = if intent.kind == LifecycleIntentKind::DestroyActive {
                GenerationState::Active
            } else {
                GenerationState::Previous
            };
            let source_index = ledger
                .generations
                .iter()
                .position(|record| {
                    record.secret_ref == intent.target_ref
                        && record.generation == intent.target_generation
                        && record.state == expected_state
                })
                .ok_or(ProvisioningSecretStoreError::Rejected)?;
            if intent.backup_operation.is_some()
                || intent.load.is_some()
                || intent.source_ref.is_some()
                || intent.envelope_commitment.is_some()
                || intent.expected_ciphertext_digest.is_some()
                || intent.expected_artifact_digest.is_some()
            {
                return Err(ProvisioningSecretStoreError::Rejected);
            }
            completed.generations[source_index].state = GenerationState::Destroyed;
            completed.generations[source_index].ciphertext_digest = [0; 32];
            completed.destroys.push(super::ledger::DestroyBinding {
                operation: aster_mesh::ProvisioningDestroyId::new(intent.operation),
                secret_ref: intent.target_ref.clone(),
                generation: intent.target_generation,
                outcome: super::ledger::DestroyBindingOutcome::Destroyed,
            });
        }
        LifecycleIntentKind::Install => return Err(ProvisioningSecretStoreError::Rejected),
    }
    let encoded = encode_ledger(&completed)?;
    if decode_ledger(&encoded)? != completed {
        return Err(ProvisioningSecretStoreError::Rejected);
    }
    Ok(completed)
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
    ledger: &ProviderLedger,
    intent: &LifecycleIntent,
    target: &GenerationManifest,
    source: Option<&GenerationManifest>,
) -> Result<GenerationSlots, ProvisioningSecretStoreError> {
    Ok(GenerationSlots {
        active: inspect_slot(
            provisioning_root,
            ACTIVE_DIRECTORY,
            intent,
            target,
            source,
            retained_manifest(ledger, intent, GenerationState::Active).as_ref(),
        )?,
        previous: inspect_slot(
            provisioning_root,
            PREVIOUS_DIRECTORY,
            intent,
            target,
            source,
            retained_manifest(ledger, intent, GenerationState::Previous).as_ref(),
        )?,
        staged: inspect_slot(
            provisioning_root,
            STAGED_DIRECTORY,
            intent,
            target,
            source,
            None,
        )?,
        cleanup: inspect_cleanup_slot(provisioning_root, intent, target, source)?,
    })
}

fn retained_manifest(
    ledger: &ProviderLedger,
    intent: &LifecycleIntent,
    state: GenerationState,
) -> Option<GenerationManifest> {
    let retained = matches!(
        (intent.kind, state),
        (
            LifecycleIntentKind::DestroyPrevious,
            GenerationState::Active
        ) | (
            LifecycleIntentKind::Recover | LifecycleIntentKind::DestroyActive,
            GenerationState::Previous
        )
    );
    retained
        .then(|| {
            ledger
                .generations
                .iter()
                .find(|record| record.state == state)
                .or_else(|| {
                    // Once Active is destroyed its latest generation remains
                    // the exact Active tombstone while Previous is removed.
                    // Historical ledger-only tombstones are never candidates.
                    if intent.kind != LifecycleIntentKind::DestroyPrevious
                        || state != GenerationState::Active
                    {
                        return None;
                    }
                    ledger
                        .generations
                        .iter()
                        .max_by_key(|record| record.generation)
                        .filter(|record| record.state == GenerationState::Destroyed)
                })
                .map(manifest_from_record)
        })
        .flatten()
}

pub(super) fn validate_retained_before_staging(
    provisioning_root: &OwnedFd,
    ledger: &ProviderLedger,
) -> Result<(), ProvisioningSecretStoreError> {
    let intent = ledger
        .intent
        .as_ref()
        .ok_or(ProvisioningSecretStoreError::Rejected)?;
    for (slot, state) in [
        (ACTIVE_DIRECTORY, GenerationState::Active),
        (PREVIOUS_DIRECTORY, GenerationState::Previous),
    ] {
        if let Some(manifest) = retained_manifest(ledger, intent, state)
            && !generation_matches(provisioning_root, slot, &manifest)?
        {
            return Err(ProvisioningSecretStoreError::Rejected);
        }
    }
    Ok(())
}

fn inspect_slot(
    provisioning_root: &OwnedFd,
    slot: &str,
    intent: &LifecycleIntent,
    target: &GenerationManifest,
    source: Option<&GenerationManifest>,
    retained: Option<&GenerationManifest>,
) -> Result<SlotIdentity, ProvisioningSecretStoreError> {
    if !child_directory_exists(provisioning_root, slot)? {
        return Ok(if retained.is_some() {
            SlotIdentity::MissingRetained
        } else {
            SlotIdentity::Absent
        });
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
    if let Some(retained) = retained
        && generation_matches(provisioning_root, slot, retained)?
    {
        return Ok(SlotIdentity::Retained);
    }
    if intent.kind == LifecycleIntentKind::Recover
        && generation_identity_matches(provisioning_root, slot, target)?
    {
        return Ok(SlotIdentity::Replaced);
    }
    Ok(SlotIdentity::Unbound)
}

fn move_bound_generation_to_cleanup(
    provisioning_root: &OwnedFd,
    slot: &str,
    expected: &GenerationManifest,
    require_digest: bool,
    faults: &mut FaultInjector,
) -> Result<(), ProvisioningSecretStoreError> {
    let matches = if require_digest {
        generation_matches(provisioning_root, slot, expected)?
    } else {
        generation_identity_matches(provisioning_root, slot, expected)?
    };
    if !matches || child_directory_exists(provisioning_root, CLEANUP_DIRECTORY)? {
        return Err(ProvisioningSecretStoreError::Rejected);
    }
    rustix::fs::renameat(
        provisioning_root,
        slot,
        provisioning_root,
        CLEANUP_DIRECTORY,
    )
    .map_err(|_| ProvisioningSecretStoreError::Unavailable)?;
    faults.hit(FaultPoint::CleanupGenerationRenamed)?;
    sync_directory(provisioning_root)?;
    faults.hit(FaultPoint::CleanupParentSynced)?;
    Ok(())
}

fn inspect_cleanup_slot(
    provisioning_root: &OwnedFd,
    intent: &LifecycleIntent,
    target: &GenerationManifest,
    source: Option<&GenerationManifest>,
) -> Result<CleanupSlotIdentity, ProvisioningSecretStoreError> {
    if !child_directory_exists(provisioning_root, CLEANUP_DIRECTORY)? {
        return Ok(CleanupSlotIdentity::Absent);
    }
    let cleanup = open_child_directory(provisioning_root, CLEANUP_DIRECTORY)?;
    if directory_has_exact_entries(&cleanup, &[])? {
        return Ok(CleanupSlotIdentity::Empty);
    }
    let Some(manifest) = read_optional_file(&cleanup, MANIFEST_FILE, 64 * 1024)? else {
        return Ok(CleanupSlotIdentity::Unbound);
    };
    let Ok(manifest) = decode_manifest(&manifest) else {
        return Ok(CleanupSlotIdentity::Unbound);
    };
    if manifest == *target
        && intent.kind == LifecycleIntentKind::DestroyPrevious
        && target.content == GenerationContent::Tombstone
    {
        return if bound_cleanup_matches(&cleanup, target, true)? {
            Ok(CleanupSlotIdentity::PreviousTombstone)
        } else {
            Ok(CleanupSlotIdentity::Unbound)
        };
    }
    let Some(source) = source.filter(|source| manifest == **source) else {
        return Ok(CleanupSlotIdentity::Unbound);
    };
    let require_digest = intent.kind != LifecycleIntentKind::Recover;
    if !bound_cleanup_matches(&cleanup, source, require_digest)? {
        return Ok(CleanupSlotIdentity::Unbound);
    }
    Ok(if require_digest {
        CleanupSlotIdentity::Source
    } else {
        CleanupSlotIdentity::Replaced
    })
}

fn bound_cleanup_matches(
    cleanup: &OwnedFd,
    expected: &GenerationManifest,
    require_digest: bool,
) -> Result<bool, ProvisioningSecretStoreError> {
    let expected_names = match expected.content {
        GenerationContent::Credential => [CIPHERTEXT_FILE, REFERENCE_FILE, MANIFEST_FILE],
        GenerationContent::Tombstone => [TOMBSTONE_FILE, REFERENCE_FILE, MANIFEST_FILE],
    };
    let mut entries = BTreeSet::new();
    let mut reader = rustix::fs::Dir::read_from(cleanup)
        .map_err(|_| ProvisioningSecretStoreError::Unavailable)?;
    while let Some(entry) = reader.read() {
        let entry = entry.map_err(|_| ProvisioningSecretStoreError::Unavailable)?;
        let name = entry.file_name().to_bytes();
        if name != b"." && name != b".." {
            entries.insert(name.to_vec());
        }
    }
    if !entries.iter().all(|name| {
        expected_names
            .iter()
            .any(|expected| name == expected.as_bytes())
    }) || !entries.contains(MANIFEST_FILE.as_bytes())
    {
        return Ok(false);
    }
    let manifest = read_optional_file(cleanup, MANIFEST_FILE, 64 * 1024)?
        .ok_or(ProvisioningSecretStoreError::Rejected)?;
    if decode_manifest(&manifest)? != *expected {
        return Ok(false);
    }
    if let Some(reference) = read_optional_file(
        cleanup,
        REFERENCE_FILE,
        aster_mesh::MAX_PROVISIONING_SECRET_REF_BYTES,
    )? && reference.as_slice() != expected.secret_ref.to_bytes()
    {
        return Ok(false);
    }
    let content_name = match expected.content {
        GenerationContent::Credential => CIPHERTEXT_FILE,
        GenerationContent::Tombstone => TOMBSTONE_FILE,
    };
    if let Some(content) = read_optional_file(
        cleanup,
        content_name,
        aster_mesh::MAX_PROTECTED_PROVISIONING_BYTES,
    )? && require_digest
    {
        match expected.content {
            GenerationContent::Credential
                if super::digest(&content) != expected.ciphertext_digest =>
            {
                return Ok(false);
            }
            GenerationContent::Tombstone if !content.is_empty() => {
                return Ok(false);
            }
            _ => {}
        }
    }
    Ok(true)
}

fn delete_bound_cleanup_contents(
    provisioning_root: &OwnedFd,
    expected: &GenerationManifest,
    require_digest: bool,
    faults: &mut FaultInjector,
) -> Result<(), ProvisioningSecretStoreError> {
    let cleanup = open_child_directory(provisioning_root, CLEANUP_DIRECTORY)?;
    if !bound_cleanup_matches(&cleanup, expected, require_digest)? {
        return Err(ProvisioningSecretStoreError::Rejected);
    }
    let content_name = match expected.content {
        GenerationContent::Credential => CIPHERTEXT_FILE,
        GenerationContent::Tombstone => TOMBSTONE_FILE,
    };
    remove_optional_file(&cleanup, content_name)?;
    faults.hit(FaultPoint::CleanupContentDeleted)?;
    remove_optional_file(&cleanup, REFERENCE_FILE)?;
    faults.hit(FaultPoint::CleanupReferenceDeleted)?;
    remove_optional_file(&cleanup, MANIFEST_FILE)?;
    faults.hit(FaultPoint::CleanupManifestDeleted)?;
    sync_directory(&cleanup)?;
    faults.hit(FaultPoint::CleanupContentsDeleted)?;
    Ok(())
}

fn delete_empty_cleanup(
    provisioning_root: &OwnedFd,
    faults: &mut FaultInjector,
) -> Result<(), ProvisioningSecretStoreError> {
    rustix::fs::unlinkat(
        provisioning_root,
        CLEANUP_DIRECTORY,
        rustix::fs::AtFlags::REMOVEDIR,
    )
    .map_err(|_| ProvisioningSecretStoreError::Unavailable)?;
    faults.hit(FaultPoint::CleanupDirectoryDeleted)?;
    faults.hit(FaultPoint::ReplacedGenerationDeleted)?;
    sync_directory(provisioning_root)?;
    faults.hit(FaultPoint::CleanupRemovalParentSynced)?;
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
    if super::files::child_directory_exists(provisioning_root, STAGED_DIRECTORY)?
        || super::files::child_directory_exists(provisioning_root, CLEANUP_DIRECTORY)?
    {
        return Err(ProvisioningSecretStoreError::Rejected);
    }
    Ok(())
}

/// Recovery defers only the current Active ciphertext integrity check. All
/// metadata, retained slots, and absence of transaction debris remain required.
pub(super) fn validate_recovery_generations(
    provisioning_root: &OwnedFd,
    ledger: &ProviderLedger,
) -> Result<(), ProvisioningSecretStoreError> {
    if ledger.intent.is_some() {
        return Err(ProvisioningSecretStoreError::Rejected);
    }
    let active = ledger
        .generations
        .iter()
        .find(|record| record.state == GenerationState::Active)
        .ok_or(ProvisioningSecretStoreError::Rejected)?;
    if child_directory_exists(provisioning_root, ACTIVE_DIRECTORY)?
        && !generation_identity_matches(
            provisioning_root,
            ACTIVE_DIRECTORY,
            &manifest_from_record(active),
        )?
    {
        return Err(ProvisioningSecretStoreError::Rejected);
    }
    let previous = ledger
        .generations
        .iter()
        .find(|record| record.state == GenerationState::Previous);
    if let Some(previous) = previous {
        if !generation_matches(
            provisioning_root,
            PREVIOUS_DIRECTORY,
            &manifest_from_record(previous),
        )? {
            return Err(ProvisioningSecretStoreError::Rejected);
        }
    } else if child_directory_exists(provisioning_root, PREVIOUS_DIRECTORY)? {
        return Err(ProvisioningSecretStoreError::Rejected);
    }
    if child_directory_exists(provisioning_root, STAGED_DIRECTORY)?
        || child_directory_exists(provisioning_root, CLEANUP_DIRECTORY)?
    {
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
    faults.hit(FaultPoint::StageReferenceSynced)?;
    write_new_file(&staged, MANIFEST_FILE, &encoded_manifest)?;
    faults.hit(FaultPoint::StageManifestSynced)?;
    write_new_file(&staged, TOMBSTONE_FILE, &[])?;
    faults.hit(FaultPoint::StagedTombstoneSynced)?;
    sync_directory(&staged)?;
    faults.hit(FaultPoint::StageDirectorySynced)?;
    sync_directory(provisioning_root)?;
    faults.hit(FaultPoint::StageParentSynced)
}

fn sync_staged_before_namespace_switch(
    provisioning_root: &OwnedFd,
    faults: &mut FaultInjector,
) -> Result<(), ProvisioningSecretStoreError> {
    let staged = open_child_directory(provisioning_root, STAGED_DIRECTORY)?;
    sync_directory(&staged)?;
    faults.hit(FaultPoint::StageDirectorySynced)?;
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
    pub(super) cleanup: CleanupSlotIdentity,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum CleanupSlotIdentity {
    Absent,
    Source,
    Replaced,
    PreviousTombstone,
    Empty,
    Unbound,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum SlotIdentity {
    Absent,
    Source,
    Target,
    Tombstone,
    Replaced,
    Retained,
    MissingRetained,
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
    RemovePreviousTombstone,
    DeleteSourceCleanup,
    DeleteReplacedCleanup,
    DeletePreviousTombstoneCleanup,
    RemoveEmptyCleanup,
    Complete,
}

pub(super) fn lifecycle_step(
    kind: LifecycleIntentKind,
    slots: GenerationSlots,
) -> Result<LifecycleStep, ProvisioningSecretStoreError> {
    use CleanupSlotIdentity::{
        Absent as CleanupAbsent, Empty as CleanupEmpty, PreviousTombstone as CleanupTombstone,
        Replaced as CleanupReplaced, Source as CleanupSource,
    };
    use LifecycleIntentKind::{DestroyActive, DestroyPrevious, Recover, Rotate};
    use LifecycleStep::{
        Complete, DeletePreviousTombstoneCleanup, DeleteReplacedCleanup, DeleteSourceCleanup,
        ExchangeStagedWithActive, ExchangeStagedWithPrevious, ParkStagedAsPrevious,
        PromoteStagedToActive, RemoveEmptyCleanup, RemovePreviousTombstone, RemoveReplacedStage,
        RemoveSourceStage,
    };
    use SlotIdentity::{Absent, Replaced, Retained, Source, Target, Tombstone};

    let step = match (
        kind,
        slots.active,
        slots.previous,
        slots.staged,
        slots.cleanup,
    ) {
        (Rotate, Source, Absent, Target, CleanupAbsent) => ExchangeStagedWithActive,
        (Rotate, Target, Absent, Source, CleanupAbsent) => ParkStagedAsPrevious,
        (Rotate, Target, Source, Absent, CleanupAbsent) => Complete,
        (Recover, Absent, Absent | Retained, Target, CleanupAbsent) => PromoteStagedToActive,
        (Recover, Replaced, Absent | Retained, Target, CleanupAbsent) => ExchangeStagedWithActive,
        (Recover, Target, Absent | Retained, Replaced, CleanupAbsent) => RemoveReplacedStage,
        (Recover, Target, Absent | Retained, Absent, CleanupReplaced) => DeleteReplacedCleanup,
        (Recover, Target, Absent | Retained, Absent, CleanupEmpty) => RemoveEmptyCleanup,
        (Recover, Target, Absent | Retained, Absent, CleanupAbsent) => Complete,
        (DestroyActive, Source, Absent | Retained, Tombstone, CleanupAbsent) => {
            ExchangeStagedWithActive
        }
        (DestroyActive, Tombstone, Absent | Retained, Source, CleanupAbsent) => RemoveSourceStage,
        (DestroyActive, Tombstone, Absent | Retained, Absent, CleanupSource) => DeleteSourceCleanup,
        (DestroyActive, Tombstone, Absent | Retained, Absent, CleanupEmpty) => RemoveEmptyCleanup,
        (DestroyActive, Tombstone, Absent | Retained, Absent, CleanupAbsent) => Complete,
        (DestroyPrevious, Absent | Retained, Source, Tombstone, CleanupAbsent) => {
            ExchangeStagedWithPrevious
        }
        (DestroyPrevious, Absent | Retained, Tombstone, Source, CleanupAbsent) => RemoveSourceStage,
        (DestroyPrevious, Absent | Retained, Tombstone, Absent, CleanupSource) => {
            DeleteSourceCleanup
        }
        (DestroyPrevious, Absent | Retained, Tombstone, Absent, CleanupEmpty) => RemoveEmptyCleanup,
        (DestroyPrevious, Absent | Retained, Tombstone, Absent, CleanupAbsent) => {
            RemovePreviousTombstone
        }
        (DestroyPrevious, Absent | Retained, Absent, Absent, CleanupTombstone) => {
            DeletePreviousTombstoneCleanup
        }
        (DestroyPrevious, Absent | Retained, Absent, Absent, CleanupEmpty) => RemoveEmptyCleanup,
        (DestroyPrevious, Absent | Retained, Absent, Absent, CleanupAbsent) => Complete,
        _ => return Err(ProvisioningSecretStoreError::Rejected),
    };
    Ok(step)
}

#[cfg(test)]
mod tests {
    use super::{
        CLEANUP_DIRECTORY, CleanupSlotIdentity, GenerationSlots, LifecycleStep, SlotIdentity,
        commit_lifecycle_intent, completed_from_intent, lifecycle_step, reconcile_lifecycle,
        select_lifecycle_ledger,
    };
    use super::{
        exchange_staged_with_active, exchange_staged_with_previous, write_staged_tombstone,
    };
    use crate::admin::{
        SystemdCredentialAdmin,
        files::{
            ACTIVE_DIRECTORY, FaultInjector, FaultPoint, GenerationContent, GenerationManifest,
            PREVIOUS_DIRECTORY, REFERENCE_FILE, STAGED_DIRECTORY, TOMBSTONE_FILE,
            generation_matches, open_secure_root,
        },
        ledger::{
            BackupBinding, DestroyBinding, DestroyBindingOutcome, GenerationRecord,
            GenerationState, LifecycleIntent, LifecycleIntentKind, MAX_LEDGER_BYTES,
            ProviderLedger, RecoveryBinding, decode_ledger, encode_ledger,
        },
    };
    use crate::{
        PROVIDER_REFERENCE_ID_BYTES, SystemdCredentialLoader, provider_generation,
        provisioning_secret_ref,
    };
    use aster_mesh::{
        ProvisioningAccess, ProvisioningDestroyId, ProvisioningInstallDisposition,
        ProvisioningInstallId, ProvisioningLoadId, ProvisioningSecretLoader,
        ProvisioningSecretStoreError, ReferenceProvisioner, Scope, Topic, UnprotectedProvisioning,
    };
    use std::{
        fs,
        os::unix::fs::PermissionsExt as _,
        path::{Path, PathBuf},
        sync::atomic::{AtomicU64, Ordering},
    };
    use zeroize::Zeroizing;

    static NEXT_FIXTURE: AtomicU64 = AtomicU64::new(0);

    #[test]
    fn destroy_public_active_and_previous_commit_exact_tombstones_and_retry_bindings() {
        // Break caught: the public destroy capability acknowledges before exact
        // source removal, drops its operation binding, or destroys the other slot.
        use aster_mesh::{ProvisioningDestroyDisposition, ProvisioningSecretDestroyer};
        let _guard = crate::admin::TEST_PROCESS_SPAWN_LOCK
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        for previous in [false, true] {
            let fixture = AdminLifecycleFixture::new();
            fixture.install_once();
            fixture
                .admin()
                .unwrap()
                .rotate(
                    ProvisioningInstallId::new([0x61; 32]),
                    ProvisioningLoadId::new([0x62; 32]),
                    fixture.alternate_bundle(),
                )
                .unwrap();
            let before = read_fixture_ledger(&fixture);
            let index = usize::from(!previous);
            let target = &before.generations[index];
            let retained = &before.generations[1 - index];
            let slot = if previous { "previous" } else { "active" };
            let other_slot = if previous { "active" } else { "previous" };
            let ciphertext =
                fs::read(fixture.provisioning.join(slot).join("credential.cred")).unwrap();
            let other = fs::read(
                fixture
                    .provisioning
                    .join(other_slot)
                    .join("credential.cred"),
            )
            .unwrap();
            let operation = ProvisioningDestroyId::new([0x81; 32]);
            let receipt = ProvisioningSecretDestroyer::destroy(
                &mut fixture.admin().unwrap(),
                operation,
                &target.secret_ref,
            )
            .unwrap();
            assert_eq!(
                receipt.disposition(),
                ProvisioningDestroyDisposition::Destroyed
            );
            assert_eq!(receipt.operation(), operation);
            assert_eq!(receipt.secret_ref(), &target.secret_ref);
            assert!(!receipt.claims_physical_media_erasure());
            assert!(
                !provisioning_bytes(&fixture.provisioning)
                    .iter()
                    .any(|(_, bytes)| bytes == &ciphertext)
            );
            assert_eq!(
                fs::read(
                    fixture
                        .provisioning
                        .join(other_slot)
                        .join("credential.cred")
                )
                .unwrap(),
                other
            );
            assert!(!fixture.provisioning.join("previous").exists() || !previous);
            if !previous {
                assert!(fixture.provisioning.join("active/tombstone").is_file());
                assert!(!fixture.provisioning.join("active/credential.cred").exists());
            }
            let after = read_fixture_ledger(&fixture);
            assert!(after.intent.is_none());
            assert_eq!(after.generations[index].state, GenerationState::Destroyed);
            assert_eq!(after.generations[index].ciphertext_digest, [0; 32]);
            assert_eq!(&after.generations[1 - index], retained);
            assert_eq!(after.destroys.len(), 1);
            assert_eq!(
                fixture
                    .admin()
                    .unwrap()
                    .destroy(operation, &target.secret_ref)
                    .unwrap()
                    .disposition(),
                ProvisioningDestroyDisposition::AlreadyDestroyed
            );
            assert_eq!(
                fixture
                    .admin()
                    .unwrap()
                    .destroy(operation, &retained.secret_ref)
                    .unwrap_err(),
                ProvisioningSecretStoreError::OperationConflict
            );
            assert_eq!(
                fixture
                    .admin()
                    .unwrap()
                    .destroy(ProvisioningDestroyId::new([0x82; 32]), &target.secret_ref)
                    .unwrap()
                    .disposition(),
                ProvisioningDestroyDisposition::AlreadyDestroyed
            );
            assert_eq!(read_fixture_ledger(&fixture).destroys.len(), 2);
            assert_eq!(fixture.encrypt_calls(), 2);
            if previous {
                let next = fixture
                    .admin()
                    .unwrap()
                    .rotate(
                        ProvisioningInstallId::new([0x71; 32]),
                        ProvisioningLoadId::new([0x72; 32]),
                        fixture.bundle(),
                    )
                    .unwrap();
                assert_eq!(provider_generation(next.secret_ref()).unwrap(), 3);
            }
        }
    }

    #[test]
    fn destroy_unknown_reference_permanently_binds_not_found_without_a_tombstone() {
        // Break caught: an unknown reference is acknowledged as destroyed or a
        // retry reuses its operation for a different, live reference.
        let _guard = crate::admin::TEST_PROCESS_SPAWN_LOCK
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let fixture = AdminLifecycleFixture::new();
        fixture.install_once();
        let before = read_fixture_ledger(&fixture);
        let namespace = provisioning_bytes(&fixture.provisioning);
        let unknown = provisioning_secret_ref(4, [0xe1; PROVIDER_REFERENCE_ID_BYTES]).unwrap();
        let operation = ProvisioningDestroyId::new([0x81; 32]);
        for _ in 0..2 {
            assert_eq!(
                fixture
                    .admin()
                    .unwrap()
                    .destroy(operation, &unknown)
                    .unwrap_err(),
                ProvisioningSecretStoreError::NotFound
            );
        }
        let after = read_fixture_ledger(&fixture);
        assert_eq!(after.generations, before.generations);
        assert_eq!(
            after.destroys,
            vec![DestroyBinding {
                operation,
                secret_ref: unknown,
                generation: 4,
                outcome: DestroyBindingOutcome::NotFound
            }]
        );
        assert_eq!(
            fixture
                .admin()
                .unwrap()
                .destroy(operation, &before.generations[0].secret_ref)
                .unwrap_err(),
            ProvisioningSecretStoreError::OperationConflict
        );
        assert_eq!(provisioning_bytes(&fixture.provisioning), namespace);
    }

    #[test]
    fn destroy_exact_retry_replays_completed_ledger_parent_sync_before_outcome() {
        // Break caught: CompleteRenamed can leave a completed ledger visible
        // without a durable rename; exact retry must synchronize before output.
        let _guard = crate::admin::TEST_PROCESS_SPAWN_LOCK
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        for unknown in [false, true] {
            let fixture = AdminLifecycleFixture::new();
            fixture.install_once();
            let target = if unknown {
                provisioning_secret_ref(4, [0xe1; PROVIDER_REFERENCE_ID_BYTES]).unwrap()
            } else {
                read_fixture_ledger(&fixture).generations[0]
                    .secret_ref
                    .clone()
            };
            let operation = ProvisioningDestroyId::new([0x81; 32]);
            assert_eq!(
                fixture
                    .admin_with_fault(FaultPoint::CompleteRenamed)
                    .unwrap()
                    .destroy(operation, &target)
                    .unwrap_err(),
                ProvisioningSecretStoreError::Unavailable
            );
            let before = fixture.namespace_bytes();
            assert_eq!(
                fixture
                    .admin_with_fault(FaultPoint::CompletedLedgerParentSynced)
                    .and_then(|mut admin| admin.destroy(operation, &target))
                    .unwrap_err(),
                ProvisioningSecretStoreError::Unavailable
            );
            assert_eq!(fixture.namespace_bytes(), before);
            let result = fixture.admin().unwrap().destroy(operation, &target);
            if unknown {
                assert_eq!(result.unwrap_err(), ProvisioningSecretStoreError::NotFound);
            } else {
                assert_eq!(
                    result.unwrap().disposition(),
                    aster_mesh::ProvisioningDestroyDisposition::AlreadyDestroyed
                );
            }
        }
    }

    #[test]
    fn completed_open_replays_ledger_parent_before_install_backup_or_destroyed_outcomes() {
        // Break caught: a visible completed rename is treated as a durable
        // install/backup/tombstone operation before its ledger parent is synced.
        use crate::admin::BackupOperationId;
        let _guard = crate::admin::TEST_PROCESS_SPAWN_LOCK
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        for case in 0..3 {
            let fixture = AdminLifecycleFixture::new();
            let install = ProvisioningInstallId::new([0x11; 32]);
            let load = ProvisioningLoadId::new([0x22; 32]);
            if case == 0 {
                assert_eq!(
                    fixture
                        .admin_with_fault(FaultPoint::CompleteRenamed)
                        .unwrap()
                        .install(install, load, fixture.bundle())
                        .unwrap_err(),
                    ProvisioningSecretStoreError::Unavailable
                );
            } else {
                fixture.install_once();
            }
            if case == 1 {
                assert_eq!(
                    fixture
                        .admin_with_fault(FaultPoint::CompleteRenamed)
                        .unwrap()
                        .backup(BackupOperationId::new([0x91; 32]))
                        .unwrap_err(),
                    ProvisioningSecretStoreError::Unavailable
                );
            }
            if case == 2 {
                let target = read_fixture_ledger(&fixture).generations[0]
                    .secret_ref
                    .clone();
                assert_eq!(
                    fixture
                        .admin_with_fault(FaultPoint::CompleteRenamed)
                        .unwrap()
                        .destroy(ProvisioningDestroyId::new([0x81; 32]), &target)
                        .unwrap_err(),
                    ProvisioningSecretStoreError::Unavailable
                );
            }
            let before = fixture.namespace_bytes();
            let result = fixture
                .admin_with_fault(FaultPoint::CompletedLedgerParentSynced)
                .and_then(|mut admin| {
                    if case == 1 {
                        admin.backup(BackupOperationId::new([0x91; 32])).map(|_| ())
                    } else {
                        admin.install(install, load, fixture.bundle()).map(|_| ())
                    }
                });
            assert_eq!(
                result.unwrap_err(),
                ProvisioningSecretStoreError::Unavailable,
                "{case}"
            );
            assert_eq!(fixture.namespace_bytes(), before);
            let mut admin = fixture.admin().unwrap();
            if case == 1 {
                admin.backup(BackupOperationId::new([0x91; 32])).unwrap();
            } else if case == 2 {
                assert_eq!(
                    admin.install(install, load, fixture.bundle()).unwrap_err(),
                    ProvisioningSecretStoreError::Destroyed
                );
            } else {
                assert_eq!(
                    admin
                        .install(install, load, fixture.bundle())
                        .unwrap()
                        .disposition(),
                    ProvisioningInstallDisposition::Existing
                );
            }
            assert_eq!(fixture.encrypt_calls(), 1);
        }
    }

    #[test]
    fn completed_same_admin_retry_replays_parent_before_all_existing_outcomes() {
        // Break caught: keeping an admin after CompleteRenamed can bypass the
        // fresh-open durability replay and expose an unsynchronized operation.
        use crate::admin::{BackupOperationId, RecoveryOperationId};
        let _guard = crate::admin::TEST_PROCESS_SPAWN_LOCK
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        for case in 0..6 {
            let fixture = AdminLifecycleFixture::new();
            if case != 0 {
                fixture.install_once();
            }
            let backup = if case == 4 {
                Some(
                    fixture
                        .admin()
                        .unwrap()
                        .backup(BackupOperationId::new([0x91; 32]))
                        .unwrap(),
                )
            } else {
                None
            };
            let target = if case == 2 {
                read_fixture_ledger(&fixture).generations[0]
                    .secret_ref
                    .clone()
            } else {
                provisioning_secret_ref(4, [0xe1; PROVIDER_REFERENCE_ID_BYTES]).unwrap()
            };
            let mut admin = fixture
                .admin_with_fault(FaultPoint::CompleteRenamed)
                .unwrap();
            let invoke =
                |admin: &mut SystemdCredentialAdmin| -> Result<(), ProvisioningSecretStoreError> {
                    match case {
                        0 => admin
                            .install(
                                ProvisioningInstallId::new([0x11; 32]),
                                ProvisioningLoadId::new([0x22; 32]),
                                fixture.bundle(),
                            )
                            .map(|_| ()),
                        1 => admin.backup(BackupOperationId::new([0x91; 32])).map(|_| ()),
                        2 | 3 => admin
                            .destroy(ProvisioningDestroyId::new([0x81; 32]), &target)
                            .map(|_| ()),
                        4 => admin
                            .recover(
                                RecoveryOperationId::new([0x92; 32]),
                                backup.as_ref().unwrap().artifact(),
                            )
                            .map(|_| ()),
                        5 => admin
                            .rotate(
                                ProvisioningInstallId::new([0x61; 32]),
                                ProvisioningLoadId::new([0x62; 32]),
                                fixture.bundle(),
                            )
                            .map(|_| ()),
                        _ => unreachable!(),
                    }
                };
            assert_eq!(
                invoke(&mut admin).unwrap_err(),
                ProvisioningSecretStoreError::Unavailable
            );
            let before = fixture.namespace_bytes();
            admin.faults = FaultInjector::at(FaultPoint::CompletedLedgerParentSynced);
            assert_eq!(
                invoke(&mut admin).unwrap_err(),
                ProvisioningSecretStoreError::Unavailable,
                "{case}"
            );
            assert_eq!(fixture.namespace_bytes(), before);
            let retry = invoke(&mut admin);
            if case == 3 {
                assert_eq!(retry.unwrap_err(), ProvisioningSecretStoreError::NotFound);
            } else {
                retry.unwrap();
            }
            assert_eq!(fixture.namespace_bytes(), before);
            assert_eq!(fixture.encrypt_calls(), if case == 5 { 2 } else { 1 });
        }
    }

    #[test]
    fn destroy_ledger_only_completion_crashes_reopen_to_exact_bound_outcome() {
        // Break caught: a NotFound/AlreadyDestroyed binding is lost at pending
        // publication or replaced by a second write from the interrupted admin.
        let _guard = crate::admin::TEST_PROCESS_SPAWN_LOCK
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        for destroyed in [false, true] {
            for point in [
                FaultPoint::CompleteFileSynced,
                FaultPoint::CompleteRenamed,
                FaultPoint::CompleteParentSynced,
            ] {
                let fixture = AdminLifecycleFixture::new();
                fixture.install_once();
                let target = if destroyed {
                    let target = read_fixture_ledger(&fixture).generations[0]
                        .secret_ref
                        .clone();
                    fixture
                        .admin()
                        .unwrap()
                        .destroy(ProvisioningDestroyId::new([0x80; 32]), &target)
                        .unwrap();
                    target
                } else {
                    provisioning_secret_ref(4, [0xe1; PROVIDER_REFERENCE_ID_BYTES]).unwrap()
                };
                let operation = ProvisioningDestroyId::new([0x81; 32]);
                let namespace = provisioning_bytes(&fixture.provisioning);
                let mut admin = fixture.admin_with_fault(point).unwrap();
                assert_eq!(
                    admin.destroy(operation, &target).unwrap_err(),
                    ProvisioningSecretStoreError::Unavailable,
                    "{point:?}"
                );
                if point == FaultPoint::CompleteFileSynced {
                    assert_eq!(
                        admin
                            .destroy(ProvisioningDestroyId::new([0x82; 32]), &target)
                            .unwrap_err(),
                        ProvisioningSecretStoreError::Rejected
                    );
                }
                drop(admin);
                let mut fresh = fixture.admin().unwrap();
                let result = fresh.destroy(operation, &target);
                if destroyed {
                    assert_eq!(
                        result.unwrap().disposition(),
                        aster_mesh::ProvisioningDestroyDisposition::AlreadyDestroyed
                    );
                } else {
                    assert_eq!(result.unwrap_err(), ProvisioningSecretStoreError::NotFound);
                }
                assert_eq!(
                    read_fixture_ledger(&fixture).destroys.len(),
                    if destroyed { 2 } else { 1 }
                );
                assert!(!fixture.ledger.join("ledger.next").exists());
                assert_eq!(provisioning_bytes(&fixture.provisioning), namespace);
            }
        }
    }

    #[test]
    fn destroy_pending_completion_replays_file_durability_before_publication() {
        // Break caught: a fully written but unsynced ledger-only destroy binding
        // can be published without replaying its own file synchronization.
        let _guard = crate::admin::TEST_PROCESS_SPAWN_LOCK
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        for destroyed in [false, true] {
            for point in [
                FaultPoint::PendingLedgerFileSyncFailed,
                FaultPoint::PendingLedgerFileSynced,
                FaultPoint::IntentRenamed,
                FaultPoint::IntentParentSynced,
            ] {
                let fixture = AdminLifecycleFixture::new();
                fixture.install_once();
                let target = if destroyed {
                    let target = read_fixture_ledger(&fixture).generations[0]
                        .secret_ref
                        .clone();
                    fixture
                        .admin()
                        .unwrap()
                        .destroy(ProvisioningDestroyId::new([0x80; 32]), &target)
                        .unwrap();
                    target
                } else {
                    provisioning_secret_ref(4, [0xe1; PROVIDER_REFERENCE_ID_BYTES]).unwrap()
                };
                let predecessor = read_fixture_ledger(&fixture);
                let mut pending = predecessor.clone();
                let operation = ProvisioningDestroyId::new([0x81; 32]);
                pending.destroys.push(DestroyBinding {
                    operation,
                    secret_ref: target.clone(),
                    generation: provider_generation(&target).unwrap(),
                    outcome: if destroyed {
                        DestroyBindingOutcome::Destroyed
                    } else {
                        DestroyBindingOutcome::NotFound
                    },
                });
                // Fixture write deliberately has no file or parent fsync.
                fixture.write_pending_ledger(&pending);
                let before = fixture.namespace_bytes();
                assert_eq!(
                    fixture.admin_with_fault(point).unwrap_err(),
                    ProvisioningSecretStoreError::Unavailable,
                    "{point:?}"
                );
                if matches!(
                    point,
                    FaultPoint::PendingLedgerFileSyncFailed | FaultPoint::PendingLedgerFileSynced
                ) {
                    assert_eq!(fixture.namespace_bytes(), before);
                    assert_eq!(read_fixture_ledger(&fixture), predecessor);
                    // A second interruption cannot consume or rewrite the pending binding.
                    assert_eq!(
                        fixture.admin_with_fault(point).unwrap_err(),
                        ProvisioningSecretStoreError::Unavailable
                    );
                    assert_eq!(fixture.namespace_bytes(), before);
                } else {
                    assert_eq!(read_fixture_ledger(&fixture), pending);
                }
                let mut admin = fixture.admin().unwrap();
                if destroyed {
                    admin.destroy(operation, &target).unwrap();
                } else {
                    assert_eq!(
                        admin.destroy(operation, &target).unwrap_err(),
                        ProvisioningSecretStoreError::NotFound
                    );
                }
                assert_eq!(read_fixture_ledger(&fixture), pending);
                assert!(!fixture.ledger.join("ledger.next").exists());
            }
        }
    }

    #[test]
    fn destroy_pending_completion_rejects_unbound_or_rewritten_state_without_mutation() {
        // Break caught: treating any DestroyBinding append as authority can
        // destroy a live generation, rewrite unrelated history, or skip slots.
        let _guard = crate::admin::TEST_PROCESS_SPAWN_LOCK
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        for case in 0..8 {
            let fixture = AdminLifecycleFixture::new();
            fixture.install_once();
            let predecessor = read_fixture_ledger(&fixture);
            let mut pending = predecessor.clone();
            pending.destroys.push(DestroyBinding {
                operation: ProvisioningDestroyId::new([0x81; 32]),
                secret_ref: provisioning_secret_ref(4, [0xe1; PROVIDER_REFERENCE_ID_BYTES])
                    .unwrap(),
                generation: 4,
                outcome: DestroyBindingOutcome::NotFound,
            });
            match case {
                0 => {
                    let mut extra = pending.destroys[0].clone();
                    extra.operation = ProvisioningDestroyId::new([0x82; 32]);
                    pending.destroys.push(extra);
                }
                1 => pending.generations[0].envelope_commitment[0] ^= 1,
                2 => pending.host_key_identity[0] ^= 1,
                3 => {
                    pending.generations[0].state = GenerationState::Destroyed;
                    pending.generations[0].ciphertext_digest = [0; 32];
                    pending.destroys[0].secret_ref = pending.generations[0].secret_ref.clone();
                    pending.destroys[0].generation = 1;
                    pending.destroys[0].outcome = DestroyBindingOutcome::Destroyed;
                }
                4..=7 => {}
                _ => unreachable!(),
            }
            fixture.write_pending_ledger(&pending);
            if case == 4 {
                let path = fixture.ledger.join("ledger.next");
                let mut bytes = fs::read(&path).unwrap();
                bytes.push(0);
                fs::write(path, bytes).unwrap();
            }
            if case == 5 {
                // Corrupt a retained slot; valid pending metadata cannot hide it.
                fs::write(
                    fixture.provisioning.join("active/credential.cred"),
                    b"corrupt",
                )
                .unwrap();
            }
            if case == 6 || case == 7 {
                let path = fixture.ledger.join("ledger.next");
                let mut bytes = fs::read(&path).unwrap();
                // The appended destroy is the final record. Change its outcome
                // or reference generation without repairing any other binding.
                let destroy_start = encode_ledger(&predecessor).unwrap().len();
                if case == 6 {
                    bytes[destroy_start] = 1;
                } else {
                    bytes[destroy_start + 43] ^= 1;
                }
                fs::write(path, bytes).unwrap();
            }
            let before = fixture.namespace_bytes();
            assert_eq!(
                fixture.admin().unwrap_err(),
                ProvisioningSecretStoreError::Rejected,
                "{case}"
            );
            assert_eq!(fixture.namespace_bytes(), before);
        }
    }

    #[test]
    fn destroy_pre_intent_tombstone_faults_preserve_old_runtime_and_unbound_evidence() {
        // Break caught: an unsafely unbound tombstone can activate, be silently
        // deleted, or lack an injectable reference/manifest durability boundary.
        let _guard = crate::admin::TEST_PROCESS_SPAWN_LOCK
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        for previous in [false, true] {
            for point in [
                FaultPoint::StageReferenceSynced,
                FaultPoint::StageManifestSynced,
                FaultPoint::StagedTombstoneSynced,
                FaultPoint::StageDirectorySynced,
                FaultPoint::StageParentSynced,
            ] {
                let fixture = AdminLifecycleFixture::new();
                fixture.install_once();
                if previous {
                    fixture
                        .admin()
                        .unwrap()
                        .rotate(
                            ProvisioningInstallId::new([0x61; 32]),
                            ProvisioningLoadId::new([0x62; 32]),
                            fixture.bundle(),
                        )
                        .unwrap();
                }
                let before = read_fixture_ledger(&fixture);
                let target = &before.generations[0];
                let active = before.generations.last().unwrap();
                let active_bytes =
                    fs::read(fixture.provisioning.join("active/credential.cred")).unwrap();
                assert_eq!(
                    fixture
                        .admin_with_fault(point)
                        .unwrap()
                        .destroy(ProvisioningDestroyId::new([0x81; 32]), &target.secret_ref)
                        .unwrap_err(),
                    ProvisioningSecretStoreError::Unavailable,
                    "{point:?}"
                );
                assert_eq!(read_fixture_ledger(&fixture), before);
                assert_eq!(
                    fs::read(fixture.provisioning.join("active/credential.cred")).unwrap(),
                    active_bytes
                );
                let interrupted = fixture.namespace_bytes();
                assert_eq!(
                    fixture.admin().unwrap_err(),
                    ProvisioningSecretStoreError::Rejected
                );
                assert_eq!(fixture.namespace_bytes(), interrupted);
                fixture.assert_active_runtime_loads(
                    active.load,
                    &active.secret_ref,
                    fixture.bundle(),
                );
            }
        }
    }

    #[test]
    fn destroy_public_crashes_reopen_at_every_intent_exchange_cleanup_and_completion_boundary() {
        // Break caught: public intent construction or receipt ordering differs
        // from the synthetic engine and leaves a credential behind on restart.
        let _guard = crate::admin::TEST_PROCESS_SPAWN_LOCK
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        for previous in [false, true] {
            for point in [
                FaultPoint::IntentFileSynced,
                FaultPoint::IntentRenamed,
                FaultPoint::IntentParentSynced,
                if previous {
                    FaultPoint::PreviousExchanged
                } else {
                    FaultPoint::ActiveExchanged
                },
                FaultPoint::CleanupGenerationRenamed,
                FaultPoint::CleanupParentSynced,
                FaultPoint::CleanupContentDeleted,
                FaultPoint::CleanupReferenceDeleted,
                FaultPoint::CleanupManifestDeleted,
                FaultPoint::CleanupContentsDeleted,
                FaultPoint::CleanupDirectoryDeleted,
                FaultPoint::CleanupRemovalParentSynced,
                FaultPoint::ReplacedGenerationDeleted,
                FaultPoint::ProvisioningParentSynced,
                FaultPoint::CompleteFileSynced,
                FaultPoint::CompleteRenamed,
                FaultPoint::CompleteParentSynced,
            ] {
                let fixture = AdminLifecycleFixture::new();
                fixture.install_once();
                fixture
                    .admin()
                    .unwrap()
                    .rotate(
                        ProvisioningInstallId::new([0x61; 32]),
                        ProvisioningLoadId::new([0x62; 32]),
                        fixture.bundle(),
                    )
                    .unwrap();
                let before = read_fixture_ledger(&fixture);
                let index = usize::from(!previous);
                let target = &before.generations[index];
                let target_slot = if previous { "previous" } else { "active" };
                let retained_slot = if previous { "active" } else { "previous" };
                let ciphertext = fs::read(
                    fixture
                        .provisioning
                        .join(target_slot)
                        .join("credential.cred"),
                )
                .unwrap();
                let retained = fs::read(
                    fixture
                        .provisioning
                        .join(retained_slot)
                        .join("credential.cred"),
                )
                .unwrap();
                let operation = ProvisioningDestroyId::new([0x81; 32]);
                assert_eq!(
                    fixture
                        .admin_with_fault(point)
                        .unwrap()
                        .destroy(operation, &target.secret_ref)
                        .unwrap_err(),
                    ProvisioningSecretStoreError::Unavailable,
                    "{previous}/{point:?}"
                );
                let interrupted = read_fixture_ledger(&fixture);
                if point == FaultPoint::IntentFileSynced {
                    assert_eq!(interrupted, before);
                } else if matches!(
                    point,
                    FaultPoint::CompleteRenamed | FaultPoint::CompleteParentSynced
                ) {
                    assert!(interrupted.intent.is_none());
                    assert_eq!(
                        interrupted.generations[index].state,
                        GenerationState::Destroyed
                    );
                } else {
                    assert!(interrupted.intent.is_some(), "{point:?}");
                }
                let mut admin = fixture
                    .admin()
                    .unwrap_or_else(|error| panic!("reopen {previous}/{point:?}: {error:?}"));
                let receipt = admin.destroy(operation, &target.secret_ref).unwrap();
                assert_eq!(
                    receipt.disposition(),
                    aster_mesh::ProvisioningDestroyDisposition::AlreadyDestroyed
                );
                assert_eq!(receipt.secret_ref(), &target.secret_ref);
                assert!(
                    !provisioning_bytes(&fixture.provisioning)
                        .iter()
                        .any(|(_, bytes)| bytes == &ciphertext)
                );
                assert_eq!(
                    fs::read(
                        fixture
                            .provisioning
                            .join(retained_slot)
                            .join("credential.cred")
                    )
                    .unwrap(),
                    retained
                );
                assert!(!fixture.provisioning.join("staged").exists());
                assert!(!fixture.provisioning.join("cleanup").exists());
                assert!(!fixture.ledger.join("ledger.next").exists());
                assert_eq!(read_fixture_ledger(&fixture).destroys.len(), 1);
                if previous {
                    assert!(!fixture.provisioning.join("previous").exists());
                } else {
                    assert!(fixture.provisioning.join("active/tombstone").is_file());
                }
                assert_eq!(fixture.encrypt_calls(), 2);
            }
        }
    }

    #[test]
    fn destroy_repeated_pending_intent_and_stage_replay_crashes_converge() {
        // Break caught: a pending destroy intent advances the filesystem before
        // durable publication or loses identity across a second interruption.
        let _guard = crate::admin::TEST_PROCESS_SPAWN_LOCK
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        for previous in [false, true] {
            for point in [
                FaultPoint::PendingLedgerFileSyncFailed,
                FaultPoint::PendingLedgerFileSynced,
                FaultPoint::IntentRenamed,
                FaultPoint::IntentParentSynced,
                FaultPoint::IntentParentReplayed,
                FaultPoint::StageDirectorySynced,
                FaultPoint::StageParentSynced,
                FaultPoint::CompleteFileSynced,
            ] {
                let fixture = AdminLifecycleFixture::new();
                fixture.install_once();
                if previous {
                    fixture
                        .admin()
                        .unwrap()
                        .rotate(
                            ProvisioningInstallId::new([0x61; 32]),
                            ProvisioningLoadId::new([0x62; 32]),
                            fixture.bundle(),
                        )
                        .unwrap();
                }
                let target = read_fixture_ledger(&fixture).generations[0]
                    .secret_ref
                    .clone();
                let operation = ProvisioningDestroyId::new([0x81; 32]);
                assert_eq!(
                    fixture
                        .admin_with_fault(FaultPoint::IntentFileSynced)
                        .unwrap()
                        .destroy(operation, &target)
                        .unwrap_err(),
                    ProvisioningSecretStoreError::Unavailable
                );
                let provisioning = provisioning_bytes(&fixture.provisioning);
                assert_eq!(
                    fixture.admin_with_fault(point).unwrap_err(),
                    ProvisioningSecretStoreError::Unavailable,
                    "{point:?}"
                );
                if point != FaultPoint::CompleteFileSynced {
                    assert_eq!(provisioning_bytes(&fixture.provisioning), provisioning);
                }
                assert_eq!(
                    fixture
                        .admin_with_fault(FaultPoint::IntentParentReplayed)
                        .unwrap_err(),
                    ProvisioningSecretStoreError::Unavailable
                );
                let mut admin = fixture.admin().unwrap();
                assert_eq!(
                    admin.destroy(operation, &target).unwrap().disposition(),
                    aster_mesh::ProvisioningDestroyDisposition::AlreadyDestroyed
                );
                assert_eq!(read_fixture_ledger(&fixture).destroys.len(), 1);
                assert!(!fixture.provisioning.join("staged").exists());
                assert!(!fixture.provisioning.join("cleanup").exists());
            }
        }
    }

    #[test]
    fn destroy_previous_tombstone_cleanup_survives_each_second_cleanup_boundary() {
        // Break caught: the Previous tombstone's second cleanup is not covered
        // by the first (credential) cleanup's identical fault point names.
        let _guard = crate::admin::TEST_PROCESS_SPAWN_LOCK
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        for point in [
            FaultPoint::CleanupGenerationRenamed,
            FaultPoint::CleanupParentSynced,
            FaultPoint::CleanupContentDeleted,
            FaultPoint::CleanupReferenceDeleted,
            FaultPoint::CleanupManifestDeleted,
            FaultPoint::CleanupContentsDeleted,
            FaultPoint::CleanupDirectoryDeleted,
            FaultPoint::ReplacedGenerationDeleted,
            FaultPoint::CleanupRemovalParentSynced,
            FaultPoint::ProvisioningParentSynced,
        ] {
            let fixture = AdminLifecycleFixture::new();
            fixture.install_once();
            fixture
                .admin()
                .unwrap()
                .rotate(
                    ProvisioningInstallId::new([0x61; 32]),
                    ProvisioningLoadId::new([0x62; 32]),
                    fixture.bundle(),
                )
                .unwrap();
            let target = read_fixture_ledger(&fixture).generations[0]
                .secret_ref
                .clone();
            let operation = ProvisioningDestroyId::new([0x81; 32]);
            assert_eq!(
                fixture
                    .admin_with_fault(FaultPoint::ReplacedGenerationDeleted)
                    .unwrap()
                    .destroy(operation, &target)
                    .unwrap_err(),
                ProvisioningSecretStoreError::Unavailable
            );
            assert!(!fixture.provisioning.join("cleanup").exists());
            assert!(fixture.provisioning.join("previous/tombstone").exists());
            let active = fs::read(fixture.provisioning.join("active/credential.cred")).unwrap();
            assert_eq!(
                fixture.admin_with_fault(point).unwrap_err(),
                ProvisioningSecretStoreError::Unavailable,
                "{point:?}"
            );
            assert_eq!(
                fixture
                    .admin_with_fault(FaultPoint::IntentParentReplayed)
                    .unwrap_err(),
                ProvisioningSecretStoreError::Unavailable
            );
            let mut admin = fixture.admin().unwrap();
            admin.destroy(operation, &target).unwrap();
            assert!(!fixture.provisioning.join("previous").exists());
            assert!(!fixture.provisioning.join("cleanup").exists());
            assert_eq!(
                fs::read(fixture.provisioning.join("active/credential.cred")).unwrap(),
                active
            );
            assert_eq!(read_fixture_ledger(&fixture).destroys.len(), 1);
        }
    }

    #[test]
    fn destroy_capacity_and_missing_ledger_fail_before_namespace_mutation() {
        // Break caught: deterministic ledger exhaustion leaves an unbound stage,
        // or an absent ledger is treated as proof that a reference never existed.
        let _guard = crate::admin::TEST_PROCESS_SPAWN_LOCK
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let empty = AdminLifecycleFixture::new();
        let unknown = provisioning_secret_ref(4, [0xe1; PROVIDER_REFERENCE_ID_BYTES]).unwrap();
        let mut admin = empty.admin().unwrap();
        let before = empty.namespace_bytes();
        assert_eq!(
            admin
                .destroy(ProvisioningDestroyId::new([0x81; 32]), &unknown)
                .unwrap_err(),
            ProvisioningSecretStoreError::Rejected
        );
        assert_eq!(empty.namespace_bytes(), before);
        for previous in [false, true] {
            let fixture = AdminLifecycleFixture::new();
            fixture.install_once();
            if previous {
                fixture
                    .admin()
                    .unwrap()
                    .rotate(
                        ProvisioningInstallId::new([0x61; 32]),
                        ProvisioningLoadId::new([0x62; 32]),
                        fixture.bundle(),
                    )
                    .unwrap();
            }
            let mut ledger = read_fixture_ledger(&fixture);
            let target = ledger.generations[0].secret_ref.clone();
            for id in 1_u64..1000 {
                let mut operation = [0; 32];
                operation[..8].copy_from_slice(&id.to_be_bytes());
                ledger.destroys.push(DestroyBinding {
                    operation: ProvisioningDestroyId::new(operation),
                    secret_ref: unknown.clone(),
                    generation: 4,
                    outcome: DestroyBindingOutcome::NotFound,
                });
                if encode_ledger(&ledger).is_err() {
                    ledger.destroys.pop();
                    break;
                }
            }
            assert!(encode_ledger(&ledger).unwrap().len() > MAX_LEDGER_BYTES - 256);
            fixture.write_ledger(ledger);
            let before = fixture.namespace_bytes();
            let mut admin = fixture.admin().unwrap();
            assert_eq!(
                admin
                    .destroy(ProvisioningDestroyId::new([0x81; 32]), &target)
                    .unwrap_err(),
                ProvisioningSecretStoreError::TooLarge
            );
            assert_eq!(fixture.namespace_bytes(), before);
            assert_eq!(fixture.encrypt_calls(), if previous { 2 } else { 1 });
        }
    }

    #[test]
    fn destroy_public_tombstone_cannot_be_resurrected_by_any_lifecycle_entry() {
        // Break caught: real destruction differs from a synthetic ledger edit,
        // so install/rotate/backup/recover or the runtime may reuse old material.
        use crate::admin::{BackupOperationId, RecoveryOperationId};
        let _guard = crate::admin::TEST_PROCESS_SPAWN_LOCK
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        for previous in [false, true] {
            let fixture = AdminLifecycleFixture::new();
            fixture.install_once();
            let backup = fixture
                .admin()
                .unwrap()
                .backup(BackupOperationId::new([0x91; 32]))
                .unwrap();
            let target = read_fixture_ledger(&fixture).generations[0].clone();
            if previous {
                fixture
                    .admin()
                    .unwrap()
                    .rotate(
                        ProvisioningInstallId::new([0x61; 32]),
                        ProvisioningLoadId::new([0x62; 32]),
                        fixture.bundle(),
                    )
                    .unwrap();
            }
            fixture
                .admin()
                .unwrap()
                .destroy(ProvisioningDestroyId::new([0x81; 32]), &target.secret_ref)
                .unwrap();
            let before = fixture.namespace_bytes();
            let mut admin = fixture.admin().unwrap();
            assert_eq!(
                admin
                    .install(target.install, target.load, fixture.bundle())
                    .unwrap_err(),
                ProvisioningSecretStoreError::Destroyed
            );
            assert_eq!(
                admin
                    .rotate(target.install, target.load, fixture.bundle())
                    .unwrap_err(),
                ProvisioningSecretStoreError::Destroyed
            );
            assert_eq!(
                admin
                    .backup(BackupOperationId::new([0x91; 32]))
                    .unwrap_err(),
                ProvisioningSecretStoreError::Destroyed
            );
            assert_eq!(
                admin
                    .recover(RecoveryOperationId::new([0x92; 32]), backup.artifact())
                    .unwrap_err(),
                ProvisioningSecretStoreError::Destroyed
            );
            if previous {
                let bytes = fs::read(fixture.provisioning.join("active/credential.cred")).unwrap();
                let mut loader = SystemdCredentialLoader::from_test_envelope(Zeroizing::new(
                    bytes.strip_prefix(b"cipher:").unwrap().to_vec(),
                ));
                assert!(loader.load(target.load, &target.secret_ref).is_err());
            } else {
                let mut loader = SystemdCredentialLoader::from_directory_for_test(
                    &fixture.provisioning.join("active"),
                )
                .unwrap();
                assert!(loader.load(target.load, &target.secret_ref).is_err());
                assert!(!fixture.provisioning.join("active/credential.cred").exists());
            }
            assert_eq!(fixture.namespace_bytes(), before);
            assert_eq!(fixture.encrypt_calls(), if previous { 2 } else { 1 });
        }
    }

    #[test]
    fn destroy_previous_after_active_preserves_the_exact_active_tombstone() {
        // Break caught: retained-slot inspection recognizes only live Active,
        // stranding an intent when Previous is destroyed after Active.
        let _guard = crate::admin::TEST_PROCESS_SPAWN_LOCK
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        for point in [
            None,
            Some(FaultPoint::IntentFileSynced),
            Some(FaultPoint::PreviousExchanged),
            Some(FaultPoint::CleanupContentDeleted),
        ] {
            let fixture = AdminLifecycleFixture::new();
            fixture.install_once();
            fixture
                .admin()
                .unwrap()
                .rotate(
                    ProvisioningInstallId::new([0x61; 32]),
                    ProvisioningLoadId::new([0x62; 32]),
                    fixture.bundle(),
                )
                .unwrap();
            let ledger = read_fixture_ledger(&fixture);
            fixture
                .admin()
                .unwrap()
                .destroy(
                    ProvisioningDestroyId::new([0x81; 32]),
                    &ledger.generations[1].secret_ref,
                )
                .unwrap();
            let tombstone = fs::read(fixture.provisioning.join("active/manifest")).unwrap();
            let operation = ProvisioningDestroyId::new([0x82; 32]);
            if let Some(point) = point {
                assert_eq!(
                    fixture
                        .admin_with_fault(point)
                        .unwrap()
                        .destroy(operation, &ledger.generations[0].secret_ref)
                        .unwrap_err(),
                    ProvisioningSecretStoreError::Unavailable
                );
                assert_eq!(
                    fixture
                        .admin_with_fault(FaultPoint::IntentParentReplayed)
                        .unwrap_err(),
                    ProvisioningSecretStoreError::Unavailable
                );
            }
            fixture
                .admin()
                .unwrap()
                .destroy(operation, &ledger.generations[0].secret_ref)
                .unwrap();
            drop(fixture.admin().unwrap());
            assert_eq!(
                fs::read(fixture.provisioning.join("active/manifest")).unwrap(),
                tombstone
            );
            assert!(!fixture.provisioning.join("previous").exists());
            assert!(
                read_fixture_ledger(&fixture)
                    .generations
                    .iter()
                    .all(|record| record.state == GenerationState::Destroyed)
            );
        }
    }

    #[test]
    fn destroy_previous_rejects_missing_or_wrong_retained_active_tombstone_before_staging() {
        // Break caught: completed slot validation permits ledger-only Destroyed
        // history, but destroying Previous must retain the latest Active tombstone.
        let _guard = crate::admin::TEST_PROCESS_SPAWN_LOCK
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        for case in 0..4 {
            let fixture = AdminLifecycleFixture::new();
            fixture.install_once();
            fixture
                .admin()
                .unwrap()
                .rotate(
                    ProvisioningInstallId::new([0x61; 32]),
                    ProvisioningLoadId::new([0x62; 32]),
                    fixture.bundle(),
                )
                .unwrap();
            let original = read_fixture_ledger(&fixture);
            fixture
                .admin()
                .unwrap()
                .destroy(
                    ProvisioningDestroyId::new([0x80; 32]),
                    &original.generations[0].secret_ref,
                )
                .unwrap();
            fixture
                .admin()
                .unwrap()
                .rotate(
                    ProvisioningInstallId::new([0x71; 32]),
                    ProvisioningLoadId::new([0x72; 32]),
                    fixture.bundle(),
                )
                .unwrap();
            let ledger = read_fixture_ledger(&fixture);
            fixture
                .admin()
                .unwrap()
                .destroy(
                    ProvisioningDestroyId::new([0x81; 32]),
                    &ledger.generations[2].secret_ref,
                )
                .unwrap();
            let mut admin = fixture.admin().unwrap();
            match case {
                0 => fs::remove_dir_all(fixture.provisioning.join("active")).unwrap(),
                1 => {
                    fs::remove_dir_all(fixture.provisioning.join("active")).unwrap();
                    fixture.write_tombstone_slot("active", &ledger.generations[0]);
                }
                2 => {
                    let path = fixture.provisioning.join("active/credential.cred");
                    fs::write(&path, b"unexpected credential").unwrap();
                    fs::set_permissions(path, fs::Permissions::from_mode(0o600)).unwrap();
                }
                3 => fixture
                    .write_tombstone_slot("staged", &read_fixture_ledger(&fixture).generations[2]),
                _ => unreachable!(),
            }
            let before = fixture.namespace_bytes();
            assert_eq!(
                admin
                    .destroy(
                        ProvisioningDestroyId::new([0x82; 32]),
                        &ledger.generations[1].secret_ref
                    )
                    .unwrap_err(),
                ProvisioningSecretStoreError::Rejected,
                "{case}"
            );
            assert_eq!(
                fixture.namespace_bytes(),
                before,
                "must reject before staging: {case}"
            );
        }
    }

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
                    SlotIdentity::Retained,
                    SlotIdentity::Target,
                ),
                LifecycleStep::PromoteStagedToActive,
            ),
            (
                LifecycleIntentKind::Recover,
                slots(
                    SlotIdentity::Replaced,
                    SlotIdentity::Retained,
                    SlotIdentity::Target,
                ),
                LifecycleStep::ExchangeStagedWithActive,
            ),
            (
                LifecycleIntentKind::Recover,
                slots(
                    SlotIdentity::Target,
                    SlotIdentity::Retained,
                    SlotIdentity::Replaced,
                ),
                LifecycleStep::RemoveReplacedStage,
            ),
            (
                LifecycleIntentKind::Recover,
                slots(
                    SlotIdentity::Target,
                    SlotIdentity::Retained,
                    SlotIdentity::Absent,
                ),
                LifecycleStep::Complete,
            ),
            (
                LifecycleIntentKind::DestroyActive,
                slots(
                    SlotIdentity::Source,
                    SlotIdentity::Retained,
                    SlotIdentity::Tombstone,
                ),
                LifecycleStep::ExchangeStagedWithActive,
            ),
            (
                LifecycleIntentKind::DestroyActive,
                slots(
                    SlotIdentity::Tombstone,
                    SlotIdentity::Retained,
                    SlotIdentity::Source,
                ),
                LifecycleStep::RemoveSourceStage,
            ),
            (
                LifecycleIntentKind::DestroyActive,
                slots(
                    SlotIdentity::Tombstone,
                    SlotIdentity::Retained,
                    SlotIdentity::Absent,
                ),
                LifecycleStep::Complete,
            ),
            (
                LifecycleIntentKind::DestroyPrevious,
                slots(
                    SlotIdentity::Retained,
                    SlotIdentity::Source,
                    SlotIdentity::Tombstone,
                ),
                LifecycleStep::ExchangeStagedWithPrevious,
            ),
            (
                LifecycleIntentKind::DestroyPrevious,
                slots(
                    SlotIdentity::Retained,
                    SlotIdentity::Tombstone,
                    SlotIdentity::Source,
                ),
                LifecycleStep::RemoveSourceStage,
            ),
            (
                LifecycleIntentKind::DestroyPrevious,
                slots(
                    SlotIdentity::Retained,
                    SlotIdentity::Tombstone,
                    SlotIdentity::Absent,
                ),
                LifecycleStep::RemovePreviousTombstone,
            ),
            (
                LifecycleIntentKind::DestroyPrevious,
                slots(
                    SlotIdentity::Retained,
                    SlotIdentity::Absent,
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
    fn cleanup_is_an_explicit_intent_bound_lifecycle_phase() {
        // Break caught: cleanup must be selected only from the full exact
        // lifecycle state, never as an unconditional pre-inspection action.
        let cases = [
            (
                LifecycleIntentKind::Recover,
                slots_with_cleanup(
                    SlotIdentity::Target,
                    SlotIdentity::Retained,
                    SlotIdentity::Absent,
                    CleanupSlotIdentity::Replaced,
                ),
                LifecycleStep::DeleteReplacedCleanup,
            ),
            (
                LifecycleIntentKind::DestroyActive,
                slots_with_cleanup(
                    SlotIdentity::Tombstone,
                    SlotIdentity::Retained,
                    SlotIdentity::Absent,
                    CleanupSlotIdentity::Source,
                ),
                LifecycleStep::DeleteSourceCleanup,
            ),
            (
                LifecycleIntentKind::DestroyPrevious,
                slots_with_cleanup(
                    SlotIdentity::Retained,
                    SlotIdentity::Tombstone,
                    SlotIdentity::Absent,
                    CleanupSlotIdentity::Source,
                ),
                LifecycleStep::DeleteSourceCleanup,
            ),
            (
                LifecycleIntentKind::DestroyPrevious,
                slots_with_cleanup(
                    SlotIdentity::Retained,
                    SlotIdentity::Absent,
                    SlotIdentity::Absent,
                    CleanupSlotIdentity::PreviousTombstone,
                ),
                LifecycleStep::DeletePreviousTombstoneCleanup,
            ),
        ];
        for (kind, slots, expected) in cases {
            assert_eq!(
                lifecycle_step(kind, slots).expect("bound cleanup"),
                expected
            );
        }
        for kind in [
            LifecycleIntentKind::Recover,
            LifecycleIntentKind::DestroyActive,
            LifecycleIntentKind::DestroyPrevious,
        ] {
            assert_eq!(
                lifecycle_step(
                    kind,
                    slots_with_cleanup(
                        SlotIdentity::Unbound,
                        SlotIdentity::Absent,
                        SlotIdentity::Absent,
                        CleanupSlotIdentity::Empty,
                    ),
                )
                .expect_err("empty cleanup outside exact final cleanup phase"),
                ProvisioningSecretStoreError::Rejected,
            );
        }
    }

    #[test]
    fn intent_ledger_selects_only_its_exact_pending_completion() {
        // Break caught: blindly ignoring ledger.next once ledger contains an
        // intent can overwrite a valid but contradictory pending snapshot.
        let source = generation_record(1, 0x31, GenerationState::Active, b"old");
        let target = generation_record(2, 0x41, GenerationState::Active, b"new");
        let (intent_ledger, mut completed) = rotate_ledgers(&source, &target);
        completed.generations[0].envelope_commitment = [0xee; 32];

        assert_eq!(
            select_lifecycle_ledger(intent_ledger, Some(completed))
                .expect_err("contradictory pending completion"),
            ProvisioningSecretStoreError::Rejected,
        );
    }

    #[test]
    fn mismatched_partial_duplicate_and_unbound_slots_are_never_actionable() {
        // Break caught: deleting or exchanging a slot that is not exactly
        // bound to the retained ledger loses evidence of corruption and may
        // discard the only valid credential.
        for invalid in [
            SlotIdentity::MissingRetained,
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
    fn recover_intent_commit_requires_an_exact_persisted_backup_binding() {
        // Break caught: presence of backup_operation alone is not enough to
        // persist a resumable Recover intent; it must identify the exact
        // ledger binding already authenticated by Task 4.
        let fixture = ReconcileFixture::new();
        let target = generation_record(2, 0x41, GenerationState::Active, b"exact");
        let (mut intent_ledger, _) = recovery_ledgers(&target);
        intent_ledger
            .intent
            .as_mut()
            .expect("Recover intent")
            .backup_operation = Some([0x99; 32]);
        fixture.write_ledger_without_intent(&intent_ledger);
        let before = fs::read(fixture.ledger.join("ledger")).expect("read predecessor ledger");

        assert_eq!(
            commit_lifecycle_intent(
                &fixture.ledger_fd,
                &intent_ledger,
                &mut FaultInjector::disabled(),
            )
            .expect_err("unbound Recover backup operation"),
            ProvisioningSecretStoreError::Rejected,
        );
        assert_eq!(
            fs::read(fixture.ledger.join("ledger")).expect("retained predecessor ledger"),
            before,
        );
        assert!(!fixture.ledger.join("ledger.next").exists());
    }

    #[test]
    fn completion_preserves_the_exact_generation_collection_except_declared_transition() {
        // Break caught: validating only source/target records lets a caller
        // rewrite unrelated destroyed history, and set-style comparison lets
        // destroy silently reorder canonical generation history.
        {
            let fixture = ReconcileFixture::new();
            let source = generation_record(2, 0x31, GenerationState::Active, b"old");
            let target = generation_record(3, 0x41, GenerationState::Active, b"new");
            let mut historical =
                generation_record(1, 0x21, GenerationState::Destroyed, b"discarded");
            historical.ciphertext_digest = [0; 32];
            let (mut intent_ledger, mut completed) = rotate_ledgers(&source, &target);
            add_retained_generation(&mut intent_ledger, &mut completed, historical.clone());
            completed
                .generations
                .iter_mut()
                .find(|record| record.secret_ref == historical.secret_ref)
                .expect("completed historical generation")
                .envelope_commitment = [0xee; 32];
            fixture.write_generation(ACTIVE_DIRECTORY, &target, b"new");
            let mut previous = source;
            previous.state = GenerationState::Previous;
            fixture.write_generation(PREVIOUS_DIRECTORY, &previous, b"old");
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
                .expect_err("mutated unrelated history"),
                ProvisioningSecretStoreError::Rejected,
            );
            assert_eq!(fixture.namespace_bytes(), before);
        }

        {
            let fixture = ReconcileFixture::new();
            let active = generation_record(1, 0x31, GenerationState::Active, b"current");
            let previous = generation_record(2, 0x41, GenerationState::Previous, b"old");
            let (mut intent_ledger, mut completed) = destroy_ledgers(&active);
            add_retained_generation(&mut intent_ledger, &mut completed, previous.clone());
            completed.generations.swap(0, 1);
            fixture.write_tombstone(&completed.generations[1]);
            fs::rename(
                fixture.provisioning.join(STAGED_DIRECTORY),
                fixture.provisioning.join(ACTIVE_DIRECTORY),
            )
            .expect("install active tombstone fixture");
            fixture.write_generation(PREVIOUS_DIRECTORY, &previous, b"old");
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
                .expect_err("reordered canonical generation history"),
                ProvisioningSecretStoreError::Rejected,
            );
            assert_eq!(fixture.namespace_bytes(), before);
        }
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
            if state == GenerationState::Active {
                assert!(tombstone_slot.join(TOMBSTONE_FILE).is_file());
            } else {
                assert!(!tombstone_slot.exists());
            }
        }
    }

    #[test]
    fn destroy_previous_preserves_active_and_leaves_destroyed_generation_ledger_only() {
        // Break caught: requiring Active to be absent makes the normal
        // Active+Previous state impossible to reconcile, while retaining the
        // Previous tombstone directory permanently blocks the next rotation.
        let fixture = ReconcileFixture::new();
        let previous = generation_record(1, 0x31, GenerationState::Previous, b"old");
        let active = generation_record(2, 0x41, GenerationState::Active, b"current");
        let (mut intent_ledger, mut completed) = destroy_ledgers(&previous);
        intent_ledger.generations.push(active.clone());
        let mut predecessor = intent_ledger.clone();
        predecessor.intent = None;
        intent_ledger
            .intent
            .as_mut()
            .expect("destroy intent")
            .pre_mutation_ledger_revision = crate::admin::digest(
            &encode_ledger(&predecessor).expect("encode composed destroy predecessor"),
        );
        completed.generations.push(active.clone());

        fixture.write_generation(ACTIVE_DIRECTORY, &active, b"current");
        fixture.write_generation(PREVIOUS_DIRECTORY, &previous, b"old");
        fixture.write_tombstone(&completed.generations[0]);
        fixture.write_ledger(&intent_ledger);

        reconcile_lifecycle(
            &fixture.provisioning_fd,
            &fixture.ledger_fd,
            intent_ledger,
            &completed,
            &mut FaultInjector::disabled(),
        )
        .expect("destroy exact Previous beside retained Active");

        assert!(fixture.generation_matches(ACTIVE_DIRECTORY, &active));
        assert!(!fixture.provisioning.join(PREVIOUS_DIRECTORY).exists());
        assert!(!fixture.provisioning.join(STAGED_DIRECTORY).exists());
        assert_eq!(fixture.read_ledger(), completed);

        let target = generation_record(3, 0x51, GenerationState::Active, b"next");
        let mut rotate_intent = completed.clone();
        rotate_intent.intent = Some(LifecycleIntent {
            kind: LifecycleIntentKind::Rotate,
            operation: *target.install.as_bytes(),
            backup_operation: None,
            load: Some(target.load),
            target_ref: target.secret_ref.clone(),
            target_generation: target.generation,
            source_ref: Some(active.secret_ref.clone()),
            envelope_commitment: Some(target.envelope_commitment),
            expected_ciphertext_digest: Some(target.ciphertext_digest),
            expected_artifact_digest: None,
            pre_mutation_ledger_revision: crate::admin::digest(
                &encode_ledger(&completed).expect("encode post-destroy ledger"),
            ),
        });
        let mut rotated = completed.clone();
        rotated
            .generations
            .iter_mut()
            .find(|record| record.secret_ref == active.secret_ref)
            .expect("retained Active")
            .state = GenerationState::Previous;
        rotated.generations.push(target.clone());
        fixture.write_generation(STAGED_DIRECTORY, &target, b"next");
        fixture.write_ledger(&rotate_intent);

        reconcile_lifecycle(
            &fixture.provisioning_fd,
            &fixture.ledger_fd,
            rotate_intent,
            &rotated,
            &mut FaultInjector::disabled(),
        )
        .expect("rotate after Previous destruction is ledger-only");
        assert!(fixture.generation_matches(ACTIVE_DIRECTORY, &target));
        let mut current_as_previous = active;
        current_as_previous.state = GenerationState::Previous;
        assert!(fixture.generation_matches(PREVIOUS_DIRECTORY, &current_as_previous));
        assert_eq!(fixture.read_ledger(), rotated);
    }

    #[test]
    fn recover_and_destroy_active_preserve_an_exact_unrelated_previous() {
        // Break caught: reconciliation must classify an unrelated retained
        // Previous from the decoded ledger, not reject or modify it merely
        // because the target operation acts on Active.
        {
            let fixture = ReconcileFixture::new();
            let previous = generation_record(1, 0x31, GenerationState::Previous, b"old");
            let active = generation_record(2, 0x41, GenerationState::Active, b"exact");
            let (mut intent_ledger, mut completed) = recovery_ledgers(&active);
            add_retained_generation(&mut intent_ledger, &mut completed, previous.clone());
            fixture.write_generation(ACTIVE_DIRECTORY, &active, b"corrupt");
            fixture.write_generation(PREVIOUS_DIRECTORY, &previous, b"old");
            fixture.write_generation(STAGED_DIRECTORY, &active, b"exact");
            fixture.write_ledger(&intent_ledger);

            reconcile_lifecycle(
                &fixture.provisioning_fd,
                &fixture.ledger_fd,
                intent_ledger,
                &completed,
                &mut FaultInjector::disabled(),
            )
            .expect("recover Active beside retained Previous");
            assert!(fixture.generation_matches(ACTIVE_DIRECTORY, &active));
            assert!(fixture.generation_matches(PREVIOUS_DIRECTORY, &previous));
        }

        {
            let fixture = ReconcileFixture::new();
            let active = generation_record(1, 0x31, GenerationState::Active, b"current");
            let previous = generation_record(2, 0x41, GenerationState::Previous, b"old");
            let (mut intent_ledger, mut completed) = destroy_ledgers(&active);
            add_retained_generation(&mut intent_ledger, &mut completed, previous.clone());
            fixture.write_generation(ACTIVE_DIRECTORY, &active, b"current");
            fixture.write_generation(PREVIOUS_DIRECTORY, &previous, b"old");
            fixture.write_tombstone(&completed.generations[0]);
            fixture.write_ledger(&intent_ledger);

            reconcile_lifecycle(
                &fixture.provisioning_fd,
                &fixture.ledger_fd,
                intent_ledger,
                &completed,
                &mut FaultInjector::disabled(),
            )
            .expect("destroy Active beside retained Previous");
            assert!(fixture.generation_matches(ACTIVE_DIRECTORY, &completed.generations[0]));
            assert!(fixture.generation_matches(PREVIOUS_DIRECTORY, &previous));
        }
    }

    #[test]
    fn missing_ledger_required_retained_slots_reject_before_any_mutation() {
        // Break caught: treating a recorded unchanged Active or Previous as
        // optional lets reconciliation destroy its operation target while a
        // ledger-required retained generation is already missing.
        {
            let fixture = ReconcileFixture::new();
            let previous = generation_record(1, 0x31, GenerationState::Previous, b"old");
            let active = generation_record(2, 0x41, GenerationState::Active, b"current");
            let (mut intent_ledger, mut completed) = destroy_ledgers(&previous);
            add_retained_generation(&mut intent_ledger, &mut completed, active);
            fixture.write_generation(PREVIOUS_DIRECTORY, &previous, b"old");
            fixture.write_tombstone(&completed.generations[0]);
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
                .expect_err("missing retained Active"),
                ProvisioningSecretStoreError::Rejected,
            );
            assert_eq!(fixture.namespace_bytes(), before);
        }

        {
            let fixture = ReconcileFixture::new();
            let previous = generation_record(1, 0x31, GenerationState::Previous, b"old");
            let active = generation_record(2, 0x41, GenerationState::Active, b"exact");
            let (mut intent_ledger, mut completed) = recovery_ledgers(&active);
            add_retained_generation(&mut intent_ledger, &mut completed, previous);
            fixture.write_generation(ACTIVE_DIRECTORY, &active, b"corrupt");
            fixture.write_generation(STAGED_DIRECTORY, &active, b"exact");
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
                .expect_err("missing retained Previous during Recover"),
                ProvisioningSecretStoreError::Rejected,
            );
            assert_eq!(fixture.namespace_bytes(), before);
        }

        {
            let fixture = ReconcileFixture::new();
            let active = generation_record(1, 0x31, GenerationState::Active, b"current");
            let previous = generation_record(2, 0x41, GenerationState::Previous, b"old");
            let (mut intent_ledger, mut completed) = destroy_ledgers(&active);
            add_retained_generation(&mut intent_ledger, &mut completed, previous);
            fixture.write_generation(ACTIVE_DIRECTORY, &active, b"current");
            fixture.write_tombstone(&completed.generations[0]);
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
                .expect_err("missing retained Previous during DestroyActive"),
                ProvisioningSecretStoreError::Rejected,
            );
            assert_eq!(fixture.namespace_bytes(), before);
        }
    }

    #[test]
    fn cleanup_deletion_requires_the_exact_full_intent_phase() {
        // Break caught: recognizing cleanup before the other lifecycle slots
        // lets a bound or empty cleanup be deleted even when the target or a
        // ledger-required retained generation is missing.
        for scenario in [
            "missing-retained",
            "wrong-target",
            "empty-wrong-target",
            "origin-present",
            "cleanup-mismatch",
            "cleanup-partial",
            "cleanup-unbound",
        ] {
            let fixture = ReconcileFixture::new();
            let target = generation_record(2, 0x41, GenerationState::Active, b"exact");
            let (mut intent_ledger, mut completed) = recovery_ledgers(&target);
            if scenario == "missing-retained" {
                let previous = generation_record(1, 0x31, GenerationState::Previous, b"old");
                add_retained_generation(&mut intent_ledger, &mut completed, previous);
                fixture.write_generation(ACTIVE_DIRECTORY, &target, b"exact");
            } else if scenario == "wrong-target" || scenario == "empty-wrong-target" {
                let wrong = generation_record(2, 0x51, GenerationState::Active, b"wrong");
                fixture.write_generation(ACTIVE_DIRECTORY, &wrong, b"wrong");
            } else {
                fixture.write_generation(ACTIVE_DIRECTORY, &target, b"exact");
            }
            match scenario {
                "empty-wrong-target" => {
                    let cleanup = fixture.provisioning.join(CLEANUP_DIRECTORY);
                    fs::create_dir(&cleanup).expect("create empty cleanup");
                    fs::set_permissions(&cleanup, fs::Permissions::from_mode(0o700))
                        .expect("protect empty cleanup");
                }
                "origin-present" => {
                    fixture.write_generation(CLEANUP_DIRECTORY, &target, b"corrupt");
                    fixture.write_generation(STAGED_DIRECTORY, &target, b"corrupt");
                }
                "cleanup-mismatch" => {
                    fixture.write_generation(CLEANUP_DIRECTORY, &target, b"corrupt");
                    fs::write(
                        fixture
                            .provisioning
                            .join(CLEANUP_DIRECTORY)
                            .join(REFERENCE_FILE),
                        b"mismatched reference",
                    )
                    .expect("replace cleanup reference");
                }
                "cleanup-partial" => {
                    let cleanup = fixture.provisioning.join(CLEANUP_DIRECTORY);
                    fs::create_dir(&cleanup).expect("create partial cleanup");
                    fs::set_permissions(&cleanup, fs::Permissions::from_mode(0o700))
                        .expect("protect partial cleanup");
                    let reference = cleanup.join(REFERENCE_FILE);
                    fs::write(&reference, target.secret_ref.to_bytes())
                        .expect("write partial cleanup reference");
                    fs::set_permissions(reference, fs::Permissions::from_mode(0o600))
                        .expect("protect partial cleanup reference");
                }
                "cleanup-unbound" => {
                    let wrong = generation_record(3, 0x51, GenerationState::Active, b"wrong");
                    fixture.write_generation(CLEANUP_DIRECTORY, &wrong, b"wrong");
                }
                _ => fixture.write_generation(CLEANUP_DIRECTORY, &target, b"corrupt"),
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
                .expect_err("invalid cleanup phase"),
                ProvisioningSecretStoreError::Rejected,
                "scenario {scenario}",
            );
            assert_eq!(fixture.namespace_bytes(), before, "scenario {scenario}");
        }
    }

    #[test]
    fn completed_open_rejects_every_cleanup_directory_without_mutation() {
        // Break caught: cleanup is never part of a completed ledger snapshot;
        // even an empty, partial, bound, or unrelated cleanup must remain as
        // evidence and make ordinary open fail closed.
        for scenario in ["empty", "partial", "bound", "unbound"] {
            let fixture = AdminLifecycleFixture::new();
            let active = generation_record(1, 0x31, GenerationState::Active, b"current");
            let wrong = generation_record(2, 0x41, GenerationState::Active, b"wrong");
            let completed = ProviderLedger {
                host_key_identity: fixture.host_identity,
                intent: None,
                generations: vec![active.clone()],
                backups: vec![],
                recoveries: vec![],
                destroys: vec![],
            };
            fixture.write_generation(ACTIVE_DIRECTORY, &active, b"current");
            match scenario {
                "empty" => {
                    let cleanup = fixture.provisioning.join(CLEANUP_DIRECTORY);
                    fs::create_dir(&cleanup).expect("create empty cleanup");
                    fs::set_permissions(&cleanup, fs::Permissions::from_mode(0o700))
                        .expect("protect empty cleanup");
                }
                "partial" => {
                    let cleanup = fixture.provisioning.join(CLEANUP_DIRECTORY);
                    fs::create_dir(&cleanup).expect("create partial cleanup");
                    fs::set_permissions(&cleanup, fs::Permissions::from_mode(0o700))
                        .expect("protect partial cleanup");
                    let marker = cleanup.join(REFERENCE_FILE);
                    fs::write(&marker, active.secret_ref.to_bytes())
                        .expect("write partial cleanup");
                    fs::set_permissions(marker, fs::Permissions::from_mode(0o600))
                        .expect("protect partial cleanup file");
                }
                "bound" => fixture.write_generation(CLEANUP_DIRECTORY, &active, b"current"),
                "unbound" => fixture.write_generation(CLEANUP_DIRECTORY, &wrong, b"wrong"),
                _ => unreachable!(),
            }
            fixture.write_ledger(completed);
            let before = fixture.namespace_bytes();

            assert_eq!(
                fixture.admin().expect_err("completed ledger with cleanup"),
                ProvisioningSecretStoreError::Rejected,
                "scenario {scenario}",
            );
            assert_eq!(fixture.namespace_bytes(), before, "scenario {scenario}");
        }
    }

    #[test]
    fn lifecycle_fault_boundaries_reopen_to_one_exact_completed_rotation() {
        // Break caught: a failure after an exchange, park, parent sync, or
        // ledger write must be resumable by a fresh admin from the exact
        // persisted intent and must never select or regenerate a generation.
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
            let fixture = AdminLifecycleFixture::new();
            let source = generation_record(1, 0x31, GenerationState::Active, b"old");
            let target = generation_record(2, 0x41, GenerationState::Active, b"new");
            let (mut intent_ledger, mut completed) = rotate_ledgers(&source, &target);
            bind_fixture_host(&mut intent_ledger, &mut completed, fixture.host_identity);
            fixture.write_generation(ACTIVE_DIRECTORY, &source, b"old");
            fixture.write_generation(STAGED_DIRECTORY, &target, b"new");
            let mut predecessor = intent_ledger.clone();
            predecessor.intent = None;
            fixture.write_ledger(predecessor);
            let provisioning_fd =
                open_secure_root(&fixture.provisioning, false).expect("open provisioning fixture");
            let ledger_fd = open_secure_root(&fixture.ledger, false).expect("open ledger fixture");

            if matches!(
                point,
                FaultPoint::IntentFileSynced
                    | FaultPoint::IntentRenamed
                    | FaultPoint::IntentParentSynced
            ) {
                assert_eq!(
                    commit_lifecycle_intent(
                        &ledger_fd,
                        &intent_ledger,
                        &mut FaultInjector::at(point),
                    )
                    .expect_err("injected intent durability fault"),
                    ProvisioningSecretStoreError::Unavailable,
                    "fault {point:?}",
                );
            } else {
                fixture.write_ledger(intent_ledger.clone());
                assert_eq!(
                    reconcile_lifecycle(
                        &provisioning_fd,
                        &ledger_fd,
                        intent_ledger.clone(),
                        &completed,
                        &mut FaultInjector::at(point),
                    )
                    .expect_err("injected lifecycle durability fault"),
                    ProvisioningSecretStoreError::Unavailable,
                    "fault {point:?}",
                );
            }
            drop(provisioning_fd);
            drop(ledger_fd);

            drop(fixture.admin().expect("fresh admin resumes exact Rotate"));
            assert_eq!(
                decode_ledger(&fs::read(fixture.ledger.join("ledger")).expect("read final ledger"))
                    .expect("decode final ledger"),
                completed,
                "fault {point:?}",
            );
            let provisioning_fd =
                open_secure_root(&fixture.provisioning, false).expect("reopen provisioning");
            assert!(
                generation_matches(&provisioning_fd, ACTIVE_DIRECTORY, &manifest_for(&target),)
                    .expect("exact Active")
            );
            let mut previous = source;
            previous.state = GenerationState::Previous;
            assert!(
                generation_matches(
                    &provisioning_fd,
                    PREVIOUS_DIRECTORY,
                    &manifest_for(&previous),
                )
                .expect("exact Previous")
            );
            assert!(!fixture.provisioning.join(STAGED_DIRECTORY).exists());
        }
    }

    #[test]
    fn rotation_commits_one_new_active_generation_and_retains_the_exact_previous() {
        // Break caught: a public rotation path that bypasses the shared
        // reconciler can publish a receipt without the exact Active/Previous
        // filesystem and ledger transition.
        let fixture = AdminLifecycleFixture::new();
        fixture.install_once();
        let predecessor = read_fixture_ledger(&fixture);
        let source = predecessor.generations[0].clone();
        let source_ciphertext = fs::read(fixture.provisioning.join("active/credential.cred"))
            .expect("read source ciphertext");
        let operation = ProvisioningInstallId::new([0x61; 32]);
        let load = ProvisioningLoadId::new([0x62; 32]);

        let receipt = fixture
            .admin()
            .expect("open rotation admin")
            .rotate(operation, load, fixture.bundle())
            .expect("rotate provider generation");

        assert_eq!(
            receipt.disposition(),
            ProvisioningInstallDisposition::Installed
        );
        assert_eq!(provider_generation(receipt.secret_ref()).unwrap(), 2);
        let completed = read_fixture_ledger(&fixture);
        assert!(completed.intent.is_none());
        assert_eq!(completed.generations.len(), 2);
        let previous = &completed.generations[0];
        let active = &completed.generations[1];
        assert_eq!(previous.secret_ref, source.secret_ref);
        assert_eq!(previous.state, GenerationState::Previous);
        assert_eq!(active.install, operation);
        assert_eq!(active.load, load);
        assert_eq!(active.secret_ref, *receipt.secret_ref());
        assert_eq!(active.state, GenerationState::Active);
        assert_eq!(
            fs::read(fixture.provisioning.join("previous/credential.cred"))
                .expect("read retained previous ciphertext"),
            source_ciphertext
        );
        let provisioning = open_secure_root(&fixture.provisioning, false).unwrap();
        assert!(
            generation_matches(&provisioning, ACTIVE_DIRECTORY, &manifest_for(active)).unwrap()
        );
        assert!(
            generation_matches(&provisioning, PREVIOUS_DIRECTORY, &manifest_for(previous)).unwrap()
        );
        assert!(!fixture.provisioning.join(STAGED_DIRECTORY).exists());
        assert_eq!(fixture.encrypt_calls(), 2);
    }

    #[test]
    fn rotation_exact_retry_is_existing_without_encryption_and_changed_inputs_conflict() {
        // Break caught: retrying through the encryptor or comparing only the
        // operation/load rather than the canonical provider envelope breaks
        // permanent operation binding.
        let fixture = AdminLifecycleFixture::new();
        fixture.install_once();
        let operation = ProvisioningInstallId::new([0x63; 32]);
        let load = ProvisioningLoadId::new([0x64; 32]);
        let installed = fixture
            .admin()
            .unwrap()
            .rotate(operation, load, fixture.bundle())
            .expect("initial rotation");

        let replay = fixture
            .admin()
            .unwrap()
            .rotate(operation, load, fixture.bundle())
            .expect("exact rotation retry");
        assert_eq!(
            replay.disposition(),
            ProvisioningInstallDisposition::Existing
        );
        assert_eq!(replay.secret_ref(), installed.secret_ref());
        assert_eq!(fixture.encrypt_calls(), 2);

        assert_eq!(
            fixture
                .admin()
                .unwrap()
                .rotate(
                    operation,
                    ProvisioningLoadId::new([0x65; 32]),
                    fixture.bundle(),
                )
                .expect_err("changed rotation load"),
            ProvisioningSecretStoreError::OperationConflict
        );
        assert_eq!(
            fixture
                .admin()
                .unwrap()
                .rotate(operation, load, fixture.alternate_bundle())
                .expect_err("changed rotation plaintext"),
            ProvisioningSecretStoreError::OperationConflict
        );
        assert_eq!(fixture.encrypt_calls(), 2);
    }

    #[test]
    fn rotation_and_install_share_previous_and_destroyed_operation_retry_classification() {
        // Break caught: install and rotate are two entry points to the same
        // permanent install-operation binding. Once rotation parks I1 as
        // Previous, its exact install retry must remain Existing; only its
        // later tombstone changes that classification to Destroyed.
        let fixture = AdminLifecycleFixture::new();
        let install_operation = ProvisioningInstallId::new([0x11; 32]);
        let install_load = ProvisioningLoadId::new([0x22; 32]);
        let installed = fixture
            .admin()
            .unwrap()
            .install(install_operation, install_load, fixture.bundle())
            .expect("initial install");
        fixture
            .admin()
            .unwrap()
            .rotate(
                ProvisioningInstallId::new([0x7a; 32]),
                ProvisioningLoadId::new([0x7b; 32]),
                fixture.bundle(),
            )
            .expect("park initial install as Previous");

        let retry = fixture
            .admin()
            .unwrap()
            .install(install_operation, install_load, fixture.bundle())
            .expect("exact Previous install retry");
        assert_eq!(
            retry.disposition(),
            ProvisioningInstallDisposition::Existing
        );
        assert_eq!(retry.secret_ref(), installed.secret_ref());
        assert_eq!(
            fixture
                .admin()
                .unwrap()
                .install(
                    install_operation,
                    ProvisioningLoadId::new([0x7c; 32]),
                    fixture.bundle(),
                )
                .expect_err("changed Previous install retry"),
            ProvisioningSecretStoreError::OperationConflict,
        );
        assert_eq!(
            fixture
                .admin()
                .unwrap()
                .install(install_operation, install_load, fixture.alternate_bundle(),)
                .expect_err("changed Previous plaintext"),
            ProvisioningSecretStoreError::OperationConflict,
        );
        assert_eq!(fixture.encrypt_calls(), 2);

        let mut ledger = read_fixture_ledger(&fixture);
        let previous = ledger
            .generations
            .iter_mut()
            .find(|record| record.install == install_operation)
            .expect("Previous operation record");
        let destroyed_ref = previous.secret_ref.clone();
        let destroyed_generation = previous.generation;
        previous.state = GenerationState::Destroyed;
        previous.ciphertext_digest = [0; 32];
        ledger.destroys.push(DestroyBinding {
            operation: ProvisioningDestroyId::new([0x7f; 32]),
            secret_ref: destroyed_ref,
            generation: destroyed_generation,
            outcome: DestroyBindingOutcome::Destroyed,
        });
        fs::remove_dir_all(fixture.provisioning.join(PREVIOUS_DIRECTORY))
            .expect("model completed Previous tombstone cleanup");
        fixture.write_ledger(ledger);

        assert_eq!(
            fixture
                .admin()
                .unwrap()
                .install(install_operation, install_load, fixture.bundle())
                .expect_err("exact tombstoned install retry"),
            ProvisioningSecretStoreError::Destroyed,
        );
        assert_eq!(
            fixture
                .admin()
                .unwrap()
                .install(
                    install_operation,
                    ProvisioningLoadId::new([0x7c; 32]),
                    fixture.bundle(),
                )
                .expect_err("changed tombstoned install retry"),
            ProvisioningSecretStoreError::OperationConflict,
        );
        assert_eq!(fixture.encrypt_calls(), 2);
    }

    #[test]
    fn rotation_rejects_invalid_plaintext_previous_and_generation_exhaustion_before_encryption() {
        // Break caught: plaintext validation, the single-Previous gate, and
        // checked generation allocation must all precede reference creation,
        // staging, or provider invocation.
        let fixture = AdminLifecycleFixture::new();
        fixture.install_once();
        let operation = ProvisioningInstallId::new([0x66; 32]);
        let load = ProvisioningLoadId::new([0x67; 32]);
        let before = fixture.namespace_bytes();
        assert_eq!(
            fixture
                .admin()
                .unwrap()
                .rotate(
                    operation,
                    load,
                    UnprotectedProvisioning::new(b"not-a-canonical-bundle".to_vec()).unwrap(),
                )
                .expect_err("invalid rotation plaintext"),
            ProvisioningSecretStoreError::Rejected
        );
        assert_eq!(fixture.namespace_bytes(), before);
        assert_eq!(fixture.encrypt_calls(), 1);

        fixture
            .admin()
            .unwrap()
            .rotate(operation, load, fixture.bundle())
            .expect("first rotation");
        let before_second = fixture.namespace_bytes();
        assert_eq!(
            fixture
                .admin()
                .unwrap()
                .rotate(
                    ProvisioningInstallId::new([0x68; 32]),
                    ProvisioningLoadId::new([0x69; 32]),
                    fixture.bundle(),
                )
                .expect_err("second rotation while Previous is retained"),
            ProvisioningSecretStoreError::Rejected
        );
        assert_eq!(fixture.namespace_bytes(), before_second);
        assert_eq!(fixture.encrypt_calls(), 2);

        let exhausted = AdminLifecycleFixture::new();
        let record = generation_record(u64::MAX, 0x71, GenerationState::Active, b"max");
        exhausted.write_generation(ACTIVE_DIRECTORY, &record, b"max");
        exhausted.write_ledger(ProviderLedger {
            host_key_identity: exhausted.host_identity,
            intent: None,
            generations: vec![record],
            backups: vec![],
            recoveries: vec![],
            destroys: vec![],
        });
        let exhausted_before = exhausted.namespace_bytes();
        assert_eq!(
            exhausted
                .admin()
                .unwrap()
                .rotate(
                    ProvisioningInstallId::new([0x78; 32]),
                    ProvisioningLoadId::new([0x73; 32]),
                    exhausted.bundle(),
                )
                .expect_err("generation overflow"),
            ProvisioningSecretStoreError::Rejected
        );
        assert_eq!(exhausted.namespace_bytes(), exhausted_before);
        assert_eq!(exhausted.encrypt_calls(), 0);
    }

    #[test]
    fn rotation_mismatched_or_v1_state_never_becomes_active() {
        // Break caught: rotation must not use a v1 ledger or manifest and must
        // not promote a mismatched durable generation as a fallback.
        for corrupt in ["ledger", "manifest"] {
            let fixture = AdminLifecycleFixture::new();
            fixture.install_once();
            let path = if corrupt == "ledger" {
                fixture.ledger.join("ledger")
            } else {
                fixture.provisioning.join("active/manifest")
            };
            let mut bytes = fs::read(&path).expect("read versioned state");
            bytes[9] = 1;
            fs::write(&path, bytes).expect("write v1 state");
            let before = fixture.namespace_bytes();

            assert_eq!(
                fixture.admin().expect_err("v1 state must fail closed"),
                ProvisioningSecretStoreError::Rejected,
                "corrupt {corrupt}",
            );
            assert_eq!(fixture.namespace_bytes(), before, "corrupt {corrupt}");
            assert_eq!(fixture.encrypt_calls(), 1, "corrupt {corrupt}");
        }

        let fixture = AdminLifecycleFixture::new();
        fixture.install_once();
        let active_before = generation_bytes(&fixture.provisioning, ACTIVE_DIRECTORY);
        assert_eq!(
            fixture
                .admin_with_fault(FaultPoint::IntentFileSynced)
                .unwrap()
                .rotate(
                    ProvisioningInstallId::new([0x6a; 32]),
                    ProvisioningLoadId::new([0x6b; 32]),
                    fixture.bundle(),
                )
                .expect_err("leave pending Rotate intent"),
            ProvisioningSecretStoreError::Unavailable,
        );
        fs::write(
            fixture.provisioning.join("staged/credential.cred"),
            b"mismatched ciphertext",
        )
        .expect("corrupt staged ciphertext");
        let before_reopen = fixture.namespace_bytes();
        assert_eq!(
            fixture
                .admin()
                .expect_err("mismatched staged generation must not activate"),
            ProvisioningSecretStoreError::Rejected,
        );
        assert_eq!(fixture.namespace_bytes(), before_reopen);
        assert_eq!(
            generation_bytes(&fixture.provisioning, ACTIVE_DIRECTORY),
            active_before,
        );
        assert!(!fixture.provisioning.join(PREVIOUS_DIRECTORY).exists());
        assert_eq!(fixture.encrypt_calls(), 2);
    }

    #[test]
    fn rotation_intent_and_namespace_faults_reopen_without_reencryption_or_fallback() {
        // Break caught: every persisted Rotate phase must be completed by the
        // shared fresh-admin reconciler using the exact ciphertext generated
        // once, never by restoring the old Active generation.
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
            let fixture = AdminLifecycleFixture::new();
            fixture.install_once();
            let source = read_fixture_ledger(&fixture).generations[0].clone();
            let operation = ProvisioningInstallId::new([0x74; 32]);
            let load = ProvisioningLoadId::new([0x75; 32]);

            assert_eq!(
                fixture
                    .admin_with_fault(point)
                    .unwrap()
                    .rotate(operation, load, fixture.bundle())
                    .expect_err("injected public rotation fault"),
                ProvisioningSecretStoreError::Unavailable,
                "fault {point:?}",
            );
            assert_eq!(fixture.encrypt_calls(), 2, "fault {point:?}");

            drop(fixture.admin().expect("fresh admin converges rotation"));
            let completed = read_fixture_ledger(&fixture);
            let previous = completed
                .generations
                .iter()
                .find(|record| record.secret_ref == source.secret_ref)
                .expect("retained source generation");
            let active = completed
                .generations
                .iter()
                .find(|record| record.install == operation)
                .expect("committed target generation");
            assert_eq!(previous.state, GenerationState::Previous, "{point:?}");
            assert_eq!(active.state, GenerationState::Active, "{point:?}");
            assert_eq!(active.generation, 2, "{point:?}");
            assert!(!fixture.provisioning.join(STAGED_DIRECTORY).exists());
            assert_eq!(fixture.encrypt_calls(), 2, "fault {point:?}");

            let replay = fixture
                .admin()
                .unwrap()
                .rotate(operation, load, fixture.bundle())
                .expect("exact retry after recovery");
            assert_eq!(
                replay.disposition(),
                ProvisioningInstallDisposition::Existing,
                "{point:?}",
            );
            assert_eq!(replay.secret_ref(), &active.secret_ref);
            assert_eq!(fixture.encrypt_calls(), 2, "fault {point:?}");
        }
    }

    #[test]
    fn rotation_pre_intent_stage_faults_preserve_old_active_and_fail_closed_on_reopen() {
        // Break caught: before a Rotate intent is durable there is no trusted
        // operation binding that authorizes a fresh admin to activate or
        // delete staged bytes. The committed old generation remains the only
        // runtime generation and the unbound stage is retained as evidence.
        for point in [
            FaultPoint::StageCiphertextSynced,
            FaultPoint::StageReferenceSynced,
            FaultPoint::StageManifestSynced,
            FaultPoint::StageDirectorySynced,
            FaultPoint::StageParentSynced,
        ] {
            let fixture = AdminLifecycleFixture::new();
            fixture.install_once();
            let ledger_before = fs::read(fixture.ledger.join("ledger")).unwrap();
            let active_before = generation_bytes(&fixture.provisioning, ACTIVE_DIRECTORY);

            assert_eq!(
                fixture
                    .admin_with_fault(point)
                    .unwrap()
                    .rotate(
                        ProvisioningInstallId::new([0x76; 32]),
                        ProvisioningLoadId::new([0x77; 32]),
                        fixture.bundle(),
                    )
                    .expect_err("injected pre-intent stage fault"),
                ProvisioningSecretStoreError::Unavailable,
                "fault {point:?}",
            );
            assert_eq!(
                fs::read(fixture.ledger.join("ledger")).unwrap(),
                ledger_before,
                "fault {point:?}",
            );
            assert_eq!(
                generation_bytes(&fixture.provisioning, ACTIVE_DIRECTORY),
                active_before,
                "fault {point:?}",
            );
            assert!(fixture.provisioning.join(STAGED_DIRECTORY).is_dir());
            assert!(!fixture.provisioning.join(PREVIOUS_DIRECTORY).exists());
            assert_eq!(fixture.encrypt_calls(), 2, "fault {point:?}");
            let source = read_fixture_ledger(&fixture).generations[0].clone();
            fixture.assert_active_runtime_loads(source.load, &source.secret_ref, fixture.bundle());
            let stranded = fixture.namespace_bytes();

            assert_eq!(
                fixture
                    .admin()
                    .expect_err("unbound stage requires operator remediation"),
                ProvisioningSecretStoreError::Rejected,
                "fault {point:?}",
            );
            assert_eq!(fixture.namespace_bytes(), stranded, "fault {point:?}");
        }
    }

    #[test]
    fn rotation_preflights_oversized_intent_before_encryption_or_staging() {
        // Break caught: a completed snapshot can fit under MAX_LEDGER_BYTES
        // while its larger Rotate intent does not. Discovering this only at
        // intent commit strands an unbound, already-encrypted stage.
        let fixture = AdminLifecycleFixture::new();
        fixture.install_once();
        let operation = ProvisioningInstallId::new([0x7d; 32]);
        let load = ProvisioningLoadId::new([0x7e; 32]);
        let mut predecessor = read_fixture_ledger(&fixture);
        let (intent, completed) = loop {
            let candidate = capacity_rotation_ledgers(&predecessor, operation, load);
            if encode_ledger(&candidate.1).is_ok()
                && encode_ledger(&candidate.0) == Err(ProvisioningSecretStoreError::TooLarge)
            {
                break candidate;
            }
            let index = u64::try_from(predecessor.backups.len() + 1).unwrap();
            let mut backup_operation = [0_u8; 32];
            backup_operation[24..].copy_from_slice(&index.to_be_bytes());
            predecessor.backups.push(BackupBinding {
                operation: backup_operation,
                secret_ref: predecessor.generations[0].secret_ref.clone(),
                generation: predecessor.generations[0].generation,
                artifact_digest: crate::admin::digest(&index.to_be_bytes()),
            });
        };
        assert!(
            encode_ledger(&predecessor).unwrap().len() > MAX_LEDGER_BYTES - 1024,
            "capacity fixture must exercise the ledger ceiling",
        );
        assert!(encode_ledger(&completed).unwrap().len() <= MAX_LEDGER_BYTES);
        assert_eq!(
            encode_ledger(&intent).expect_err("intent must exceed ledger bound"),
            ProvisioningSecretStoreError::TooLarge,
        );
        fixture.write_ledger(predecessor);
        let before = fixture.namespace_bytes();
        let mut admin = fixture.admin().expect("open near-capacity ledger");

        assert_eq!(
            admin
                .rotate(operation, load, fixture.bundle())
                .expect_err("oversized Rotate intent"),
            ProvisioningSecretStoreError::TooLarge,
        );
        assert!(fixture.namespace_bytes() == before);
        assert_eq!(fixture.encrypt_calls(), 1);
        let retry = admin
            .install(
                ProvisioningInstallId::new([0x11; 32]),
                ProvisioningLoadId::new([0x22; 32]),
                fixture.bundle(),
            )
            .expect("same admin remains usable");
        assert_eq!(
            retry.disposition(),
            ProvisioningInstallDisposition::Existing
        );
        assert!(fixture.namespace_bytes() == before);
    }

    #[test]
    fn fresh_admin_selects_pending_rotate_intent_and_derives_exact_completion() {
        // Break caught: an intent synced into ledger.next before rename is a
        // real persisted operation state; ignoring it or routing every intent
        // through install-only recovery strands an exact staged rotation.
        let fixture = AdminLifecycleFixture::new();
        let source = generation_record(1, 0x31, GenerationState::Active, b"old");
        let target = generation_record(2, 0x41, GenerationState::Active, b"new");
        let (mut intent_ledger, mut completed) = rotate_ledgers(&source, &target);
        bind_fixture_host(&mut intent_ledger, &mut completed, fixture.host_identity);
        fixture.write_generation(ACTIVE_DIRECTORY, &source, b"old");
        fixture.write_generation(STAGED_DIRECTORY, &target, b"new");
        let mut predecessor = intent_ledger.clone();
        predecessor.intent = None;
        fixture.write_ledger(predecessor);
        let ledger_fd = open_secure_root(&fixture.ledger, false).expect("open ledger fixture");

        assert_eq!(
            commit_lifecycle_intent(
                &ledger_fd,
                &intent_ledger,
                &mut FaultInjector::at(FaultPoint::IntentFileSynced),
            )
            .expect_err("interrupt exact pending intent"),
            ProvisioningSecretStoreError::Unavailable,
        );
        drop(ledger_fd);

        drop(
            fixture
                .admin()
                .expect("fresh admin reconciles pending Rotate"),
        );
        assert_eq!(
            decode_ledger(&fs::read(fixture.ledger.join("ledger")).expect("read final ledger"))
                .expect("decode final ledger"),
            completed,
        );
        assert!(!fixture.ledger.join("ledger.next").exists());
    }

    #[test]
    fn invalid_pending_recover_semantics_preserve_both_ledger_files() {
        // Break caught: promoting a canonical pending Recover intent before
        // checking its exact persisted BackupBinding destroys the durable
        // predecessor/pending evidence even though completion is impossible.
        let fixture = AdminLifecycleFixture::new();
        let target = generation_record(2, 0x41, GenerationState::Active, b"exact");
        let (mut intent_ledger, mut completed) = recovery_ledgers(&target);
        bind_fixture_host(&mut intent_ledger, &mut completed, fixture.host_identity);
        intent_ledger
            .intent
            .as_mut()
            .expect("Recover intent")
            .backup_operation = Some([0x99; 32]);
        let mut predecessor = intent_ledger.clone();
        predecessor.intent = None;
        fixture.write_generation(ACTIVE_DIRECTORY, &target, b"corrupt");
        fixture.write_generation(STAGED_DIRECTORY, &target, b"exact");
        fixture.write_ledger(predecessor);
        fixture.write_pending_ledger(&intent_ledger);
        let before = fixture.namespace_bytes();

        assert_eq!(
            fixture
                .admin()
                .expect_err("pending Recover with unbound backup operation"),
            ProvisioningSecretStoreError::Rejected,
        );
        assert_eq!(fixture.namespace_bytes(), before);
    }

    #[test]
    fn invalid_pending_filesystem_phases_preserve_both_ledger_files() {
        // Break caught: a pending intent must not become current until every
        // on-disk slot is an exact allowed lifecycle phase; partial,
        // mismatched, and unbound stages retain both ledger snapshots.
        for scenario in ["mismatched", "partial", "unbound"] {
            let fixture = AdminLifecycleFixture::new();
            let source = generation_record(1, 0x31, GenerationState::Active, b"old");
            let target = generation_record(2, 0x41, GenerationState::Active, b"new");
            let (mut intent_ledger, mut completed) = rotate_ledgers(&source, &target);
            bind_fixture_host(&mut intent_ledger, &mut completed, fixture.host_identity);
            fixture.write_generation(ACTIVE_DIRECTORY, &source, b"old");
            match scenario {
                "mismatched" => fixture.write_generation(STAGED_DIRECTORY, &target, b"corrupt"),
                "partial" => fixture.write_partial_stage(),
                "unbound" => {
                    let wrong = generation_record(3, 0x51, GenerationState::Active, b"wrong");
                    fixture.write_generation(STAGED_DIRECTORY, &wrong, b"wrong");
                }
                _ => unreachable!(),
            }
            let mut predecessor = intent_ledger.clone();
            predecessor.intent = None;
            fixture.write_ledger(predecessor);
            fixture.write_pending_ledger(&intent_ledger);
            let before = fixture.namespace_bytes();

            assert_eq!(
                fixture
                    .admin()
                    .expect_err("invalid pending filesystem phase"),
                ProvisioningSecretStoreError::Rejected,
                "scenario {scenario}",
            );
            assert_eq!(fixture.namespace_bytes(), before, "scenario {scenario}");
        }
    }

    #[test]
    fn pending_intent_is_published_before_mutation_and_survives_two_interruptions() {
        // Break caught: reconciling directly from ledger.next can switch the
        // provisioning namespace and then leave only the predecessor ledger
        // when completion publication is interrupted.
        let fixture = AdminLifecycleFixture::new();
        let source = generation_record(1, 0x31, GenerationState::Active, b"old");
        let target = generation_record(2, 0x41, GenerationState::Active, b"new");
        let (mut intent_ledger, mut completed) = rotate_ledgers(&source, &target);
        bind_fixture_host(&mut intent_ledger, &mut completed, fixture.host_identity);
        fixture.write_generation(ACTIVE_DIRECTORY, &source, b"old");
        fixture.write_generation(STAGED_DIRECTORY, &target, b"new");
        let mut predecessor = intent_ledger.clone();
        predecessor.intent = None;
        fixture.write_ledger(predecessor);
        let ledger_fd = open_secure_root(&fixture.ledger, false).expect("open ledger fixture");
        assert_eq!(
            commit_lifecycle_intent(
                &ledger_fd,
                &intent_ledger,
                &mut FaultInjector::at(FaultPoint::IntentFileSynced),
            )
            .expect_err("leave exact intent in ledger.next"),
            ProvisioningSecretStoreError::Unavailable,
        );
        drop(ledger_fd);

        assert_eq!(
            fixture
                .admin_with_fault(FaultPoint::CompleteFileSynced)
                .expect_err("interrupt completion after namespace switch"),
            ProvisioningSecretStoreError::Unavailable,
        );
        assert_eq!(read_fixture_ledger(&fixture), intent_ledger);
        assert_eq!(
            decode_ledger(
                &fs::read(fixture.ledger.join("ledger.next")).expect("pending completion ledger")
            )
            .expect("decode pending completion ledger"),
            completed,
        );

        drop(fixture.admin().expect("second fresh admin converges"));
        assert_eq!(read_fixture_ledger(&fixture), completed);
        assert!(!fixture.ledger.join("ledger.next").exists());
    }

    #[test]
    fn pending_intent_publication_faults_before_provisioning_mutation() {
        // Break caught: publication faults must occur while the exact Active
        // and staged generations are still untouched, with the intent either
        // retained as pending or atomically installed as current.
        for point in [FaultPoint::IntentRenamed, FaultPoint::IntentParentSynced] {
            let fixture = AdminLifecycleFixture::new();
            let source = generation_record(1, 0x31, GenerationState::Active, b"old");
            let target = generation_record(2, 0x41, GenerationState::Active, b"new");
            let (mut intent_ledger, mut completed) = rotate_ledgers(&source, &target);
            bind_fixture_host(&mut intent_ledger, &mut completed, fixture.host_identity);
            fixture.write_generation(ACTIVE_DIRECTORY, &source, b"old");
            fixture.write_generation(STAGED_DIRECTORY, &target, b"new");
            let mut predecessor = intent_ledger.clone();
            predecessor.intent = None;
            fixture.write_ledger(predecessor);
            let ledger_fd = open_secure_root(&fixture.ledger, false).expect("open ledger fixture");
            assert_eq!(
                commit_lifecycle_intent(
                    &ledger_fd,
                    &intent_ledger,
                    &mut FaultInjector::at(FaultPoint::IntentFileSynced),
                )
                .expect_err("leave exact pending intent"),
                ProvisioningSecretStoreError::Unavailable,
            );
            drop(ledger_fd);
            let before_provisioning = provisioning_bytes(&fixture.provisioning);

            assert_eq!(
                fixture
                    .admin_with_fault(point)
                    .expect_err("interrupt pending intent publication"),
                ProvisioningSecretStoreError::Unavailable,
                "fault {point:?}",
            );
            assert_eq!(
                provisioning_bytes(&fixture.provisioning),
                before_provisioning,
                "fault {point:?}",
            );
            assert_eq!(read_fixture_ledger(&fixture), intent_ledger);
            assert!(!fixture.ledger.join("ledger.next").exists());

            drop(
                fixture
                    .admin()
                    .expect("fresh admin resumes published intent"),
            );
            assert_eq!(read_fixture_ledger(&fixture), completed);
        }
    }

    #[test]
    fn current_intent_replays_ledger_parent_sync_before_provisioning_mutation() {
        // Break caught: after IntentRenamed, a crash can leave the exact intent
        // current without a durable ledger-parent rename; the next admin must
        // replay that fsync before touching Active or staged.
        let fixture = AdminLifecycleFixture::new();
        let source = generation_record(1, 0x31, GenerationState::Active, b"old");
        let target = generation_record(2, 0x41, GenerationState::Active, b"new");
        let (mut intent_ledger, mut completed) = rotate_ledgers(&source, &target);
        bind_fixture_host(&mut intent_ledger, &mut completed, fixture.host_identity);
        fixture.write_generation(ACTIVE_DIRECTORY, &source, b"old");
        fixture.write_generation(STAGED_DIRECTORY, &target, b"new");
        let mut predecessor = intent_ledger.clone();
        predecessor.intent = None;
        fixture.write_ledger(predecessor);
        fixture.write_pending_ledger(&intent_ledger);
        let before_provisioning = provisioning_bytes(&fixture.provisioning);

        assert_eq!(
            fixture
                .admin_with_fault(FaultPoint::IntentRenamed)
                .expect_err("interrupt after intent rename"),
            ProvisioningSecretStoreError::Unavailable,
        );
        assert_eq!(read_fixture_ledger(&fixture), intent_ledger);
        assert!(!fixture.ledger.join("ledger.next").exists());
        assert_eq!(
            provisioning_bytes(&fixture.provisioning),
            before_provisioning,
        );
        let after_rename = fixture.namespace_bytes();

        assert_eq!(
            fixture
                .admin_with_fault(FaultPoint::IntentParentReplayed)
                .expect_err("interrupt after replayed ledger-parent sync"),
            ProvisioningSecretStoreError::Unavailable,
        );
        assert_eq!(fixture.namespace_bytes(), after_rename);

        drop(fixture.admin().expect("later fresh admin converges"));
        assert_eq!(read_fixture_ledger(&fixture), completed);
    }

    #[test]
    fn fresh_admin_resumes_recover_and_both_destroy_kinds_from_persisted_intent() {
        // Break caught: fresh-open dispatch that handles only Rotate still
        // strands authenticated Recover and composed destroy states after a
        // real filesystem boundary.
        {
            let fixture = AdminLifecycleFixture::new();
            let previous = generation_record(1, 0x31, GenerationState::Previous, b"old");
            let target = generation_record(2, 0x41, GenerationState::Active, b"exact");
            let (mut intent_ledger, mut completed) = recovery_ledgers(&target);
            add_retained_generation(&mut intent_ledger, &mut completed, previous.clone());
            bind_fixture_host(&mut intent_ledger, &mut completed, fixture.host_identity);
            fixture.write_generation(ACTIVE_DIRECTORY, &target, b"corrupt");
            fixture.write_generation(PREVIOUS_DIRECTORY, &previous, b"old");
            fixture.write_generation(STAGED_DIRECTORY, &target, b"exact");
            fixture.write_ledger(intent_ledger.clone());
            interrupt_reconciliation(
                &fixture,
                intent_ledger,
                &completed,
                FaultPoint::ActiveExchanged,
            );

            drop(fixture.admin().expect("fresh admin resumes Recover"));
            assert_eq!(read_fixture_ledger(&fixture), completed);
            let provisioning_fd = open_secure_root(&fixture.provisioning, false)
                .expect("reopen recovery provisioning");
            assert!(
                generation_matches(
                    &provisioning_fd,
                    PREVIOUS_DIRECTORY,
                    &manifest_for(&previous),
                )
                .expect("retained recovery Previous")
            );
        }

        {
            let fixture = AdminLifecycleFixture::new();
            let active = generation_record(1, 0x31, GenerationState::Active, b"current");
            let previous = generation_record(2, 0x41, GenerationState::Previous, b"old");
            let (mut intent_ledger, mut completed) = destroy_ledgers(&active);
            add_retained_generation(&mut intent_ledger, &mut completed, previous.clone());
            bind_fixture_host(&mut intent_ledger, &mut completed, fixture.host_identity);
            fixture.write_generation(ACTIVE_DIRECTORY, &active, b"current");
            fixture.write_generation(PREVIOUS_DIRECTORY, &previous, b"old");
            fixture.write_tombstone_slot(STAGED_DIRECTORY, &completed.generations[0]);
            fixture.write_ledger(intent_ledger.clone());
            interrupt_reconciliation(
                &fixture,
                intent_ledger,
                &completed,
                FaultPoint::CleanupContentDeleted,
            );

            drop(fixture.admin().expect("fresh admin resumes DestroyActive"));
            assert_eq!(read_fixture_ledger(&fixture), completed);
        }

        {
            let fixture = AdminLifecycleFixture::new();
            let previous = generation_record(1, 0x31, GenerationState::Previous, b"old");
            let active = generation_record(2, 0x41, GenerationState::Active, b"current");
            let (mut intent_ledger, mut completed) = destroy_ledgers(&previous);
            add_retained_generation(&mut intent_ledger, &mut completed, active.clone());
            bind_fixture_host(&mut intent_ledger, &mut completed, fixture.host_identity);
            fixture.write_generation(ACTIVE_DIRECTORY, &active, b"current");
            fixture.write_generation(PREVIOUS_DIRECTORY, &previous, b"old");
            fixture.write_tombstone_slot(STAGED_DIRECTORY, &completed.generations[0]);
            fixture.write_ledger(intent_ledger.clone());
            interrupt_reconciliation(
                &fixture,
                intent_ledger,
                &completed,
                FaultPoint::PreviousExchanged,
            );

            drop(
                fixture
                    .admin()
                    .expect("fresh admin resumes DestroyPrevious"),
            );
            assert_eq!(read_fixture_ledger(&fixture), completed);
            assert!(!fixture.provisioning.join(PREVIOUS_DIRECTORY).exists());
        }
    }

    #[test]
    fn tombstone_previous_exchange_and_replaced_deletion_faults_reopen_exactly() {
        // Break caught: the three non-rotation durability boundaries must
        // retain enough exact intent-bound state for a fresh reconciler.
        {
            let fixture = AdminLifecycleFixture::new();
            let source = generation_record(1, 0x31, GenerationState::Active, b"secret");
            let (mut intent_ledger, mut completed) = destroy_ledgers(&source);
            bind_fixture_host(&mut intent_ledger, &mut completed, fixture.host_identity);
            fixture.write_generation(ACTIVE_DIRECTORY, &source, b"secret");
            fixture.write_ledger(intent_ledger);
            let provisioning_fd = open_secure_root(&fixture.provisioning, false)
                .expect("open tombstone provisioning fixture");
            let tombstone = manifest_for(&completed.generations[0]);
            assert_eq!(
                write_staged_tombstone(
                    &provisioning_fd,
                    &tombstone,
                    &mut FaultInjector::at(FaultPoint::StagedTombstoneSynced),
                )
                .expect_err("injected staged tombstone fault"),
                ProvisioningSecretStoreError::Unavailable
            );
            assert!(
                generation_matches(&provisioning_fd, STAGED_DIRECTORY, &tombstone)
                    .expect("exact interrupted tombstone")
            );
            assert!(
                !fixture
                    .provisioning
                    .join(STAGED_DIRECTORY)
                    .join("credential.cred")
                    .exists()
            );
            drop(provisioning_fd);
            drop(
                fixture
                    .admin()
                    .expect("fresh admin resumes tombstone preparation"),
            );
            assert_eq!(read_fixture_ledger(&fixture), completed);
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

    #[test]
    fn resumed_tombstone_syncs_its_directory_before_exchange() {
        // Break caught: an exact tombstone whose file writes completed but
        // directory fsync did not must not be exchanged into Active until a
        // fresh admin replays both staged-directory and parent durability.
        let fixture = AdminLifecycleFixture::new();
        let source = generation_record(1, 0x31, GenerationState::Active, b"secret");
        let (mut intent_ledger, mut completed) = destroy_ledgers(&source);
        bind_fixture_host(&mut intent_ledger, &mut completed, fixture.host_identity);
        fixture.write_generation(ACTIVE_DIRECTORY, &source, b"secret");
        fixture.write_ledger(intent_ledger.clone());
        let provisioning_fd =
            open_secure_root(&fixture.provisioning, false).expect("open provisioning fixture");
        assert_eq!(
            write_staged_tombstone(
                &provisioning_fd,
                &manifest_for(&completed.generations[0]),
                &mut FaultInjector::at(FaultPoint::StagedTombstoneSynced),
            )
            .expect_err("interrupt before staged-directory sync"),
            ProvisioningSecretStoreError::Unavailable,
        );
        drop(provisioning_fd);
        let before = fixture.namespace_bytes();

        assert_eq!(
            fixture
                .admin_with_fault(FaultPoint::StageDirectorySynced)
                .expect_err("interrupt after replayed staged-directory sync"),
            ProvisioningSecretStoreError::Unavailable,
        );
        assert_eq!(fixture.namespace_bytes(), before);

        drop(
            fixture
                .admin()
                .expect("fresh admin resumes durable tombstone"),
        );
        assert_eq!(read_fixture_ledger(&fixture), completed);
    }

    #[test]
    fn resumed_cleanup_syncs_rename_parent_before_any_unlink() {
        // Break caught: after a cleanup rename interruption, deleting its
        // files before replaying the provisioning-parent fsync can lose both
        // the origin name and cleanup binding across a crash.
        let fixture = AdminLifecycleFixture::new();
        let target = generation_record(2, 0x41, GenerationState::Active, b"exact");
        let (mut intent_ledger, mut completed) = recovery_ledgers(&target);
        bind_fixture_host(&mut intent_ledger, &mut completed, fixture.host_identity);
        fixture.write_generation(ACTIVE_DIRECTORY, &target, b"corrupt");
        fixture.write_generation(STAGED_DIRECTORY, &target, b"exact");
        fixture.write_ledger(intent_ledger.clone());
        interrupt_reconciliation(
            &fixture,
            intent_ledger,
            &completed,
            FaultPoint::CleanupGenerationRenamed,
        );
        let before = fixture.namespace_bytes();

        assert_eq!(
            fixture
                .admin_with_fault(FaultPoint::CleanupParentSynced)
                .expect_err("interrupt after replayed cleanup-parent sync"),
            ProvisioningSecretStoreError::Unavailable,
        );
        assert_eq!(fixture.namespace_bytes(), before);

        drop(
            fixture
                .admin()
                .expect("fresh admin resumes durable cleanup"),
        );
        assert_eq!(read_fixture_ledger(&fixture), completed);
        assert!(!fixture.provisioning.join(CLEANUP_DIRECTORY).exists());
    }

    #[test]
    fn cleanup_faults_never_leave_a_partial_provider_slot_and_resume_only_bound_work() {
        // Break caught: unlinking staged files in place can strand a partial
        // provider slot that no exact intent state can safely authorize for a
        // later deletion.
        for point in [
            FaultPoint::CleanupGenerationRenamed,
            FaultPoint::CleanupParentSynced,
            FaultPoint::CleanupContentDeleted,
            FaultPoint::CleanupReferenceDeleted,
            FaultPoint::CleanupManifestDeleted,
            FaultPoint::CleanupContentsDeleted,
            FaultPoint::CleanupDirectoryDeleted,
            FaultPoint::ReplacedGenerationDeleted,
            FaultPoint::CleanupRemovalParentSynced,
        ] {
            let fixture = AdminLifecycleFixture::new();
            let target = generation_record(2, 0x41, GenerationState::Active, b"exact");
            let (mut intent_ledger, mut completed) = recovery_ledgers(&target);
            bind_fixture_host(&mut intent_ledger, &mut completed, fixture.host_identity);
            fixture.write_generation(ACTIVE_DIRECTORY, &target, b"corrupt");
            fixture.write_generation(STAGED_DIRECTORY, &target, b"exact");
            fixture.write_ledger(intent_ledger.clone());
            interrupt_reconciliation(&fixture, intent_ledger, &completed, point);
            assert!(!fixture.provisioning.join(STAGED_DIRECTORY).exists());

            drop(
                fixture
                    .admin()
                    .expect("fresh admin resumes exact bound cleanup"),
            );
            assert_eq!(read_fixture_ledger(&fixture), completed, "fault {point:?}");
            let provisioning_fd = open_secure_root(&fixture.provisioning, false)
                .expect("reopen cleanup provisioning");
            assert!(
                generation_matches(&provisioning_fd, ACTIVE_DIRECTORY, &manifest_for(&target),)
                    .expect("exact recovered Active")
            );
            assert!(!fixture.provisioning.join(CLEANUP_DIRECTORY).exists());
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
            cleanup: CleanupSlotIdentity::Absent,
        }
    }

    fn slots_with_cleanup(
        active: SlotIdentity,
        previous: SlotIdentity,
        staged: SlotIdentity,
        cleanup: CleanupSlotIdentity,
    ) -> GenerationSlots {
        GenerationSlots {
            active,
            previous,
            staged,
            cleanup,
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

    #[test]
    fn backup_binds_before_output_and_retries_the_original_active_or_previous_bytes() {
        // Break caught: a retry selecting the new Active silently changes the backup binding.
        use crate::admin::{BackupOperationId, backup::decode_backup};
        let _guard = crate::admin::TEST_PROCESS_SPAWN_LOCK
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let fixture = AdminLifecycleFixture::new();
        fixture.install_once();
        let operation = BackupOperationId::new([0x91; 32]);
        let receipt = fixture.admin().unwrap().backup(operation).unwrap();
        let bytes = receipt.artifact().as_bytes().to_vec();
        let decoded = decode_backup(&bytes).unwrap();
        assert_eq!(
            decoded.ciphertext,
            fs::read(fixture.provisioning.join("active/credential.cred")).unwrap()
        );
        let ledger = decode_ledger(&fs::read(fixture.ledger.join("ledger")).unwrap()).unwrap();
        assert_eq!(ledger.backups.len(), 1);
        assert_eq!(ledger.backups[0].operation, [0x91; 32]);
        assert_eq!(
            ledger.backups[0].artifact_digest,
            crate::admin::digest(&bytes)
        );
        assert_eq!(receipt.operation(), operation);
        assert_eq!(receipt.secret_ref(), &decoded.manifest.secret_ref);
        assert_eq!(receipt.generation(), 1);
        fixture
            .admin()
            .unwrap()
            .rotate(
                ProvisioningInstallId::new([0x92; 32]),
                ProvisioningLoadId::new([0x93; 32]),
                fixture.bundle(),
            )
            .unwrap();
        assert_eq!(
            fixture
                .admin()
                .unwrap()
                .backup(operation)
                .unwrap()
                .artifact()
                .as_bytes(),
            bytes
        );
        let next = fixture
            .admin()
            .unwrap()
            .backup(BackupOperationId::new([0x94; 32]))
            .unwrap();
        assert_eq!(next.generation(), 2);
        assert_ne!(next.artifact().as_bytes(), bytes);
        assert_eq!(fixture.encrypt_calls(), 2);

        let mut ledger = decode_ledger(&fs::read(fixture.ledger.join("ledger")).unwrap()).unwrap();
        ledger.backups[0].artifact_digest[0] ^= 1;
        fixture.write_ledger(ledger);
        let before = fixture.namespace_bytes();
        assert_eq!(
            fixture.admin().unwrap().backup(operation).unwrap_err(),
            ProvisioningSecretStoreError::OperationConflict
        );
        assert_eq!(fixture.namespace_bytes(), before);
    }

    #[test]
    fn backup_commit_faults_reopen_to_exact_identical_output() {
        // Break caught: a ledger-only backup completion pending at crash strands administration.
        use crate::admin::BackupOperationId;
        let _guard = crate::admin::TEST_PROCESS_SPAWN_LOCK
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        for point in [
            FaultPoint::CompleteFileSynced,
            FaultPoint::CompleteRenamed,
            FaultPoint::CompleteParentSynced,
        ] {
            let fixture = AdminLifecycleFixture::new();
            fixture.install_once();
            assert_eq!(
                fixture
                    .admin_with_fault(point)
                    .unwrap()
                    .backup(BackupOperationId::new([0x91; 32]))
                    .unwrap_err(),
                ProvisioningSecretStoreError::Unavailable
            );
            let receipt = fixture
                .admin()
                .unwrap()
                .backup(BackupOperationId::new([0x91; 32]))
                .unwrap();
            let ledger = decode_ledger(&fs::read(fixture.ledger.join("ledger")).unwrap()).unwrap();
            assert_eq!(ledger.backups.len(), 1, "{point:?}");
            assert_eq!(
                ledger.backups[0].artifact_digest,
                crate::admin::digest(receipt.artifact().as_bytes())
            );
            assert!(!fixture.ledger.join("ledger.next").exists());
            assert_eq!(fixture.encrypt_calls(), 1);
        }
    }

    #[test]
    fn backup_pending_publication_replays_file_sync_before_rename_and_output() {
        // Break caught: a complete ledger.next left before its original file sync
        // is renamed and acknowledged without durable binding-file contents.
        use crate::admin::{BackupOperationId, backup::encode_backup};
        let _guard = crate::admin::TEST_PROCESS_SPAWN_LOCK
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        for point in [
            FaultPoint::PendingLedgerFileSyncFailed,
            FaultPoint::PendingLedgerFileSynced,
            FaultPoint::IntentRenamed,
            FaultPoint::IntentParentSynced,
        ] {
            let fixture = AdminLifecycleFixture::new();
            fixture.install_once();
            let predecessor = read_fixture_ledger(&fixture);
            let record = &predecessor.generations[0];
            let operation = BackupOperationId::new([0x91; 32]);
            let ciphertext = fs::read(fixture.provisioning.join("active/credential.cred")).unwrap();
            let artifact = encode_backup(
                operation,
                fixture.host_identity,
                &manifest_for(record),
                &ciphertext,
            )
            .unwrap();
            let mut pending = predecessor.clone();
            pending.backups.push(BackupBinding {
                operation: *operation.as_bytes(),
                secret_ref: record.secret_ref.clone(),
                generation: record.generation,
                artifact_digest: crate::admin::digest(artifact.as_bytes()),
            });
            // Explicit pre-file-sync crash fixture: write_pending_ledger uses
            // fs::write and never syncs either file or parent directory.
            fixture.write_pending_ledger(&pending);
            let before = fixture.namespace_bytes();
            let before_provisioning = provisioning_bytes(&fixture.provisioning);
            let result = fixture
                .admin_with_fault(point)
                .and_then(|mut admin| admin.backup(operation));
            assert_eq!(
                result.unwrap_err(),
                ProvisioningSecretStoreError::Unavailable,
                "{point:?}"
            );
            if matches!(
                point,
                FaultPoint::PendingLedgerFileSyncFailed | FaultPoint::PendingLedgerFileSynced
            ) {
                assert_eq!(
                    fixture.namespace_bytes(),
                    before,
                    "no rename before file sync at {point:?}"
                );
                assert_eq!(read_fixture_ledger(&fixture), predecessor);
                assert_eq!(
                    decode_ledger(&fs::read(fixture.ledger.join("ledger.next")).unwrap()).unwrap(),
                    pending
                );
            } else {
                assert_eq!(read_fixture_ledger(&fixture), pending);
                assert!(!fixture.ledger.join("ledger.next").exists());
            }
            assert_eq!(
                provisioning_bytes(&fixture.provisioning),
                before_provisioning
            );
            let receipt = fixture.admin().unwrap().backup(operation).unwrap();
            assert_eq!(receipt.artifact().as_bytes(), artifact.as_bytes());
            assert_eq!(read_fixture_ledger(&fixture), pending);
            assert!(!fixture.ledger.join("ledger.next").exists());
            assert_eq!(fixture.encrypt_calls(), 1);
        }
    }

    #[test]
    fn backup_pending_completion_rejects_changed_or_unbound_snapshots_without_mutation() {
        // Break caught: publishing an arbitrary completed ledger.next rewrites trusted history.
        use crate::admin::BackupOperationId;
        let _guard = crate::admin::TEST_PROCESS_SPAWN_LOCK
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        for case in 0..5 {
            let fixture = AdminLifecycleFixture::new();
            fixture.install_once();
            let _ = fixture
                .admin_with_fault(FaultPoint::CompleteFileSynced)
                .unwrap()
                .backup(BackupOperationId::new([0x91; 32]));
            let mut pending =
                decode_ledger(&fs::read(fixture.ledger.join("ledger.next")).unwrap()).unwrap();
            match case {
                0 => pending.backups[0].artifact_digest[0] ^= 1,
                1 => {
                    let mut second = pending.backups[0].clone();
                    second.operation = [0x92; 32];
                    pending.backups.push(second);
                }
                2 => pending.generations[0].envelope_commitment[0] ^= 1,
                3 => pending.backups[0].operation = [0x93; 32],
                4 => pending.host_key_identity[0] ^= 1,
                _ => unreachable!(),
            }
            fixture.write_pending_ledger(&pending);
            let before = fixture.namespace_bytes();
            assert_eq!(
                fixture.admin().unwrap_err(),
                ProvisioningSecretStoreError::Rejected,
                "{case}"
            );
            assert_eq!(fixture.namespace_bytes(), before);
        }
    }

    #[test]
    fn recovery_restores_only_exact_current_missing_or_corrupt_active_and_retries_existing() {
        // Break caught: recovery cannot be reached after a process restart or re-encrypts the backup.
        use crate::admin::{BackupOperationId, RecoveryDisposition, RecoveryOperationId};
        let _guard = crate::admin::TEST_PROCESS_SPAWN_LOCK
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        for corrupt in [false, true] {
            let fixture = AdminLifecycleFixture::new();
            fixture.install_once();
            let backup = fixture
                .admin()
                .unwrap()
                .backup(BackupOperationId::new([0x91; 32]))
                .unwrap();
            let active_before = namespace_bytes(&fixture.provisioning, &fixture.ledger)
                .into_iter()
                .filter(|(name, _)| name.starts_with("active/"))
                .collect::<Vec<_>>();
            assert_eq!(active_before.len(), 3);
            if corrupt {
                fs::write(
                    fixture.provisioning.join("active/credential.cred"),
                    b"corrupt ciphertext",
                )
                .unwrap();
            } else {
                fs::remove_dir_all(fixture.provisioning.join("active")).unwrap();
            }
            assert_eq!(
                fixture.admin().unwrap_err(),
                ProvisioningSecretStoreError::Rejected
            );
            let operation = RecoveryOperationId::new([0x92; 32]);
            let receipt = fixture
                .recovery_admin(None)
                .unwrap()
                .recover(operation, backup.artifact())
                .unwrap();
            assert_eq!(receipt.disposition(), RecoveryDisposition::Restored);
            assert_eq!(receipt.operation(), operation);
            assert_eq!(receipt.secret_ref(), backup.secret_ref());
            assert_eq!(receipt.generation(), 1);
            let retry = fixture
                .admin()
                .unwrap()
                .recover(operation, backup.artifact())
                .unwrap();
            assert_eq!(retry.disposition(), RecoveryDisposition::Existing);
            let active_after = namespace_bytes(&fixture.provisioning, &fixture.ledger)
                .into_iter()
                .filter(|(name, _)| name.starts_with("active/"))
                .collect::<Vec<_>>();
            assert_eq!(active_after, active_before);
            assert!(!fixture.provisioning.join("staged").exists());
            assert!(!fixture.provisioning.join("cleanup").exists());
            assert_eq!(fixture.encrypt_calls(), 1);
        }
    }

    #[test]
    fn recovery_open_and_other_operations_preserve_every_unrelated_namespace_defect() {
        // Break caught: relaxing open for recovery also permits install/rotation or unrelated bad slots.
        use crate::admin::BackupOperationId;
        let _guard = crate::admin::TEST_PROCESS_SPAWN_LOCK
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        for defect in 0..8 {
            let fixture = AdminLifecycleFixture::new();
            fixture.install_once();
            if defect == 6 {
                fixture
                    .admin()
                    .unwrap()
                    .rotate(
                        ProvisioningInstallId::new([0x94; 32]),
                        ProvisioningLoadId::new([0x95; 32]),
                        fixture.bundle(),
                    )
                    .unwrap();
                fs::remove_dir_all(fixture.provisioning.join("previous")).unwrap();
            }
            if defect == 0 {
                fs::remove_dir_all(fixture.provisioning.join("active")).unwrap();
                let mut admin = fixture.recovery_admin(None).unwrap();
                let before = fixture.namespace_bytes();
                assert_eq!(
                    admin
                        .install(
                            ProvisioningInstallId::new([0x11; 32]),
                            ProvisioningLoadId::new([0x22; 32]),
                            fixture.bundle()
                        )
                        .unwrap_err(),
                    ProvisioningSecretStoreError::Rejected
                );
                assert_eq!(
                    admin
                        .rotate(
                            ProvisioningInstallId::new([0x94; 32]),
                            ProvisioningLoadId::new([0x95; 32]),
                            fixture.bundle()
                        )
                        .unwrap_err(),
                    ProvisioningSecretStoreError::Rejected
                );
                assert_eq!(
                    admin
                        .backup(BackupOperationId::new([0x91; 32]))
                        .unwrap_err(),
                    ProvisioningSecretStoreError::Rejected
                );
                assert_eq!(fixture.namespace_bytes(), before);
                continue;
            }
            match defect {
                1 => fs::remove_file(fixture.provisioning.join("active/reference")).unwrap(),
                2 => fs::write(fixture.provisioning.join("active/extra"), b"unbound").unwrap(),
                3..=5 => {
                    let name = ["staged", "cleanup", "previous"][defect - 3];
                    fs::create_dir(fixture.provisioning.join(name)).unwrap();
                    fs::set_permissions(
                        fixture.provisioning.join(name),
                        fs::Permissions::from_mode(0o700),
                    )
                    .unwrap();
                }
                6 => {}
                7 => fs::write(
                    fixture.provisioning.join("active/manifest"),
                    b"corrupt manifest",
                )
                .unwrap(),
                _ => unreachable!(),
            }
            let before = fixture.namespace_bytes();
            assert_eq!(
                fixture.recovery_admin(None).unwrap_err(),
                ProvisioningSecretStoreError::Rejected,
                "defect {defect}"
            );
            assert_eq!(fixture.namespace_bytes(), before);
        }
    }

    #[test]
    fn recovery_rejects_wrong_host_backup_binding_digest_and_history_without_mutation() {
        // Break caught: trusting a merely well-formed artifact permits rollback or new unrecorded backups.
        use crate::admin::{BackupOperationId, ProtectedBackupArtifact, RecoveryOperationId};
        let _guard = crate::admin::TEST_PROCESS_SPAWN_LOCK
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        for case in 0..7 {
            let fixture = AdminLifecycleFixture::new();
            fixture.install_once();
            let backup = fixture
                .admin()
                .unwrap()
                .backup(BackupOperationId::new([0x91; 32]))
                .unwrap();
            let mut bytes = backup.artifact().as_bytes().to_vec();
            match case {
                0 => bytes[44] ^= 1,
                1 => bytes[12] ^= 1,
                2 => {
                    let mut ledger =
                        decode_ledger(&fs::read(fixture.ledger.join("ledger")).unwrap()).unwrap();
                    ledger.backups[0].artifact_digest[0] ^= 1;
                    fixture.write_ledger(ledger);
                }
                3 => fs::remove_file(fixture.ledger.join("ledger")).unwrap(),
                4 => {
                    fixture
                        .admin()
                        .unwrap()
                        .rotate(
                            ProvisioningInstallId::new([0x94; 32]),
                            ProvisioningLoadId::new([0x95; 32]),
                            fixture.bundle(),
                        )
                        .unwrap();
                }
                5 => fs::write(&fixture.host_key, [0x6b; 32]).unwrap(),
                6 => {
                    let mut ledger =
                        decode_ledger(&fs::read(fixture.ledger.join("ledger")).unwrap()).unwrap();
                    ledger.generations[0].state = GenerationState::Destroyed;
                    ledger.generations[0].ciphertext_digest = [0; 32];
                    fixture.write_ledger(ledger);
                    fs::remove_dir_all(fixture.provisioning.join("active")).unwrap();
                }
                _ => unreachable!(),
            }
            let artifact = ProtectedBackupArtifact::from_bytes(&bytes).unwrap();
            let before = fixture.namespace_bytes();
            let result = fixture.recovery_admin(None).and_then(|mut admin| {
                admin.recover(RecoveryOperationId::new([0x92; 32]), &artifact)
            });
            assert!(result.is_err(), "case {case}");
            assert_eq!(fixture.namespace_bytes(), before, "case {case}");
            assert_eq!(fixture.encrypt_calls(), if case == 4 { 2 } else { 1 });
        }
    }

    #[test]
    fn recovery_public_faults_resume_through_fresh_admin_and_every_cleanup_boundary() {
        // Break caught: only synthetic engine tests miss unpersisted public recovery bindings.
        use crate::admin::{BackupOperationId, RecoveryDisposition, RecoveryOperationId};
        let _guard = crate::admin::TEST_PROCESS_SPAWN_LOCK
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let common = [
            FaultPoint::IntentFileSynced,
            FaultPoint::IntentRenamed,
            FaultPoint::IntentParentSynced,
            FaultPoint::ProvisioningParentSynced,
            FaultPoint::CompleteFileSynced,
            FaultPoint::CompleteRenamed,
            FaultPoint::CompleteParentSynced,
        ];
        let cleanup = [
            FaultPoint::ActiveExchanged,
            FaultPoint::CleanupGenerationRenamed,
            FaultPoint::CleanupParentSynced,
            FaultPoint::CleanupContentDeleted,
            FaultPoint::CleanupReferenceDeleted,
            FaultPoint::CleanupManifestDeleted,
            FaultPoint::CleanupContentsDeleted,
            FaultPoint::CleanupDirectoryDeleted,
            FaultPoint::CleanupRemovalParentSynced,
            FaultPoint::ReplacedGenerationDeleted,
        ];
        for corrupt in [false, true] {
            let points = common.into_iter().chain(if corrupt {
                cleanup.to_vec()
            } else {
                vec![FaultPoint::ActiveRenamed, FaultPoint::ActiveParentSynced]
            });
            for point in points {
                let fixture = AdminLifecycleFixture::new();
                fixture.install_once();
                let backup = fixture
                    .admin()
                    .unwrap()
                    .backup(BackupOperationId::new([0x91; 32]))
                    .unwrap();
                if corrupt {
                    fs::write(
                        fixture.provisioning.join("active/credential.cred"),
                        b"corrupt ciphertext",
                    )
                    .unwrap();
                } else {
                    fs::remove_dir_all(fixture.provisioning.join("active")).unwrap();
                }
                let operation = RecoveryOperationId::new([0x92; 32]);
                assert_eq!(
                    fixture
                        .recovery_admin(Some(point))
                        .unwrap()
                        .recover(operation, backup.artifact())
                        .unwrap_err(),
                    ProvisioningSecretStoreError::Unavailable,
                    "{point:?}"
                );
                let receipt = fixture
                    .admin()
                    .unwrap()
                    .recover(operation, backup.artifact())
                    .unwrap();
                assert_eq!(
                    receipt.disposition(),
                    RecoveryDisposition::Existing,
                    "{point:?}"
                );
                let ledger =
                    decode_ledger(&fs::read(fixture.ledger.join("ledger")).unwrap()).unwrap();
                assert!(ledger.intent.is_none());
                assert_eq!(ledger.recoveries.len(), 1);
                assert_eq!(ledger.recoveries[0].backup_operation, [0x91; 32]);
                assert!(!fixture.provisioning.join("cleanup").exists());
                assert!(!fixture.provisioning.join("staged").exists());
                assert_eq!(fixture.encrypt_calls(), 1);
            }
        }
    }

    #[test]
    fn recovery_pre_intent_faults_preserve_unbound_stage_for_operator_remediation() {
        // Break caught: recovery auto-deletes or activates ciphertext before a bound intent exists.
        use crate::admin::{BackupOperationId, RecoveryOperationId};
        let _guard = crate::admin::TEST_PROCESS_SPAWN_LOCK
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        for point in [
            FaultPoint::StageCiphertextSynced,
            FaultPoint::StageReferenceSynced,
            FaultPoint::StageManifestSynced,
            FaultPoint::StageDirectorySynced,
            FaultPoint::StageParentSynced,
        ] {
            let fixture = AdminLifecycleFixture::new();
            fixture.install_once();
            let backup = fixture
                .admin()
                .unwrap()
                .backup(BackupOperationId::new([0x91; 32]))
                .unwrap();
            fs::write(
                fixture.provisioning.join("active/credential.cred"),
                b"corrupt ciphertext",
            )
            .unwrap();
            let ledger_before = fs::read(fixture.ledger.join("ledger")).unwrap();
            assert_eq!(
                fixture
                    .recovery_admin(Some(point))
                    .unwrap()
                    .recover(RecoveryOperationId::new([0x92; 32]), backup.artifact())
                    .unwrap_err(),
                ProvisioningSecretStoreError::Unavailable
            );
            let before = fixture.namespace_bytes();
            assert_eq!(
                fixture.admin().unwrap_err(),
                ProvisioningSecretStoreError::Rejected
            );
            assert_eq!(
                fixture.recovery_admin(None).unwrap_err(),
                ProvisioningSecretStoreError::Rejected
            );
            assert_eq!(fixture.namespace_bytes(), before);
            assert_eq!(
                fs::read(fixture.ledger.join("ledger")).unwrap(),
                ledger_before
            );
            assert_eq!(
                fs::read(fixture.provisioning.join("active/credential.cred")).unwrap(),
                b"corrupt ciphertext"
            );
            assert_eq!(fixture.encrypt_calls(), 1);
        }
    }

    #[test]
    fn recovery_retry_conflicts_on_another_valid_backup_and_rejects_later_damage() {
        // Break caught: an existing operation accepts different valid input or silently repairs twice.
        use crate::admin::{BackupOperationId, RecoveryDisposition, RecoveryOperationId};
        let _guard = crate::admin::TEST_PROCESS_SPAWN_LOCK
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let fixture = AdminLifecycleFixture::new();
        fixture.install_once();
        let first = fixture
            .admin()
            .unwrap()
            .backup(BackupOperationId::new([0x91; 32]))
            .unwrap();
        let second = fixture
            .admin()
            .unwrap()
            .backup(BackupOperationId::new([0x93; 32]))
            .unwrap();
        let operation = RecoveryOperationId::new([0x92; 32]);
        assert_eq!(
            fixture
                .admin()
                .unwrap()
                .recover(operation, first.artifact())
                .unwrap()
                .disposition(),
            RecoveryDisposition::Existing
        );
        let before = fixture.namespace_bytes();
        assert_eq!(
            fixture
                .admin()
                .unwrap()
                .recover(operation, second.artifact())
                .unwrap_err(),
            ProvisioningSecretStoreError::OperationConflict
        );
        assert_eq!(fixture.namespace_bytes(), before);
        fs::remove_dir_all(fixture.provisioning.join("active")).unwrap();
        let before = fixture.namespace_bytes();
        assert_eq!(
            fixture
                .recovery_admin(None)
                .unwrap()
                .recover(operation, first.artifact())
                .unwrap_err(),
            ProvisioningSecretStoreError::Rejected
        );
        assert_eq!(fixture.namespace_bytes(), before);
    }

    #[test]
    fn recovery_and_backup_preflight_capacity_without_staging_or_namespace_mutation() {
        // Break caught: deterministic ledger exhaustion strands unbound recovery ciphertext.
        use crate::admin::{BackupOperationId, RecoveryOperationId};
        let _guard = crate::admin::TEST_PROCESS_SPAWN_LOCK
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let fixture = AdminLifecycleFixture::new();
        fixture.install_once();
        let backup = fixture
            .admin()
            .unwrap()
            .backup(BackupOperationId::new([0x91; 32]))
            .unwrap();
        let mut ledger = read_fixture_ledger(&fixture);
        loop {
            let index = u64::try_from(ledger.backups.len() + 1).unwrap();
            let mut operation = [0; 32];
            operation[24..].copy_from_slice(&index.to_be_bytes());
            ledger.backups.push(BackupBinding {
                operation,
                secret_ref: ledger.generations[0].secret_ref.clone(),
                generation: 1,
                artifact_digest: [0; 32],
            });
            if encode_ledger(&ledger).is_err() {
                ledger.backups.pop();
                break;
            }
        }
        fixture.write_ledger(ledger);
        let before = fixture.namespace_bytes();
        assert_eq!(
            fixture
                .admin()
                .unwrap()
                .backup(BackupOperationId::new([0x93; 32]))
                .unwrap_err(),
            ProvisioningSecretStoreError::TooLarge
        );
        assert_eq!(fixture.namespace_bytes(), before);
        fs::remove_dir_all(fixture.provisioning.join("active")).unwrap();
        let before = fixture.namespace_bytes();
        assert_eq!(
            fixture
                .recovery_admin(None)
                .unwrap()
                .recover(RecoveryOperationId::new([0x92; 32]), backup.artifact())
                .unwrap_err(),
            ProvisioningSecretStoreError::TooLarge
        );
        assert_eq!(fixture.namespace_bytes(), before);
        assert_eq!(fixture.encrypt_calls(), 1);
    }

    #[test]
    fn backup_exact_tombstone_returns_destroyed_and_recovery_never_resurrects_it() {
        // Break caught: live backup bytes survive in the provider or can restore a tombstoned reference.
        use crate::admin::{BackupOperationId, RecoveryOperationId};
        let _guard = crate::admin::TEST_PROCESS_SPAWN_LOCK
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let fixture = AdminLifecycleFixture::new();
        fixture.install_once();
        let operation = BackupOperationId::new([0x91; 32]);
        let backup = fixture.admin().unwrap().backup(operation).unwrap();
        let mut ledger = read_fixture_ledger(&fixture);
        ledger.generations[0].state = GenerationState::Destroyed;
        ledger.generations[0].ciphertext_digest = [0; 32];
        fs::remove_dir_all(fixture.provisioning.join("active")).unwrap();
        fixture.write_tombstone_slot("active", &ledger.generations[0]);
        fixture.write_ledger(ledger);
        let before = fixture.namespace_bytes();
        assert_eq!(
            fixture.admin().unwrap().backup(operation).unwrap_err(),
            ProvisioningSecretStoreError::Destroyed
        );
        assert_eq!(
            fixture
                .admin()
                .unwrap()
                .recover(RecoveryOperationId::new([0x92; 32]), backup.artifact())
                .unwrap_err(),
            ProvisioningSecretStoreError::Destroyed
        );
        assert_eq!(fixture.namespace_bytes(), before);
    }

    #[test]
    fn recovery_repairs_current_generation_two_and_preserves_exact_previous() {
        // Break caught: recovery drops Previous or restores an older backup into the active slot.
        use crate::admin::{BackupOperationId, RecoveryDisposition, RecoveryOperationId};
        let _guard = crate::admin::TEST_PROCESS_SPAWN_LOCK
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let fixture = AdminLifecycleFixture::new();
        fixture.install_once();
        let old = fixture
            .admin()
            .unwrap()
            .backup(BackupOperationId::new([0x90; 32]))
            .unwrap();
        fixture
            .admin()
            .unwrap()
            .rotate(
                ProvisioningInstallId::new([0x94; 32]),
                ProvisioningLoadId::new([0x95; 32]),
                fixture.bundle(),
            )
            .unwrap();
        let backup = fixture
            .admin()
            .unwrap()
            .backup(BackupOperationId::new([0x91; 32]))
            .unwrap();
        let previous = fixture
            .namespace_bytes()
            .into_iter()
            .filter(|(name, _)| name.starts_with("previous/"))
            .collect::<Vec<_>>();
        assert_eq!(previous.len(), 3);
        fs::write(
            fixture.provisioning.join("active/credential.cred"),
            b"corrupt current",
        )
        .unwrap();
        let before = fixture.namespace_bytes();
        assert_eq!(
            fixture
                .recovery_admin(None)
                .unwrap()
                .recover(RecoveryOperationId::new([0x92; 32]), old.artifact())
                .unwrap_err(),
            ProvisioningSecretStoreError::Rejected
        );
        assert_eq!(fixture.namespace_bytes(), before);
        let receipt = fixture
            .recovery_admin(None)
            .unwrap()
            .recover(RecoveryOperationId::new([0x92; 32]), backup.artifact())
            .unwrap();
        assert_eq!(receipt.disposition(), RecoveryDisposition::Restored);
        assert_eq!(receipt.generation(), 2);
        assert_eq!(
            fixture
                .namespace_bytes()
                .into_iter()
                .filter(|(name, _)| name.starts_with("previous/"))
                .collect::<Vec<_>>(),
            previous
        );
        fixture.assert_active_runtime_loads(
            ProvisioningLoadId::new([0x95; 32]),
            receipt.secret_ref(),
            fixture.bundle(),
        );
        assert_eq!(fixture.encrypt_calls(), 2);
    }

    #[test]
    fn backup_pending_commit_cannot_be_overwritten_by_another_live_admin_operation() {
        // Break caught: retrying on the same object overwrites a durable unacknowledged backup binding.
        use crate::admin::{BackupOperationId, RecoveryOperationId};
        let _guard = crate::admin::TEST_PROCESS_SPAWN_LOCK
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        for operation in 0..3 {
            let fixture = AdminLifecycleFixture::new();
            fixture.install_once();
            let backup = fixture
                .admin()
                .unwrap()
                .backup(BackupOperationId::new([0x90; 32]))
                .unwrap();
            let mut admin = fixture
                .admin_with_fault(FaultPoint::CompleteFileSynced)
                .unwrap();
            assert_eq!(
                admin
                    .backup(BackupOperationId::new([0x91; 32]))
                    .unwrap_err(),
                ProvisioningSecretStoreError::Unavailable
            );
            let before = fixture.namespace_bytes();
            let rejected = match operation {
                0 => admin.backup(BackupOperationId::new([0x92; 32])).is_err(),
                1 => admin
                    .rotate(
                        ProvisioningInstallId::new([0x94; 32]),
                        ProvisioningLoadId::new([0x95; 32]),
                        fixture.bundle(),
                    )
                    .is_err(),
                2 => admin
                    .recover(RecoveryOperationId::new([0x92; 32]), backup.artifact())
                    .is_err(),
                _ => unreachable!(),
            };
            assert!(rejected, "operation {operation}");
            assert_eq!(fixture.namespace_bytes(), before, "operation {operation}");
        }
    }

    struct AdminLifecycleFixture {
        path: PathBuf,
        provisioning: PathBuf,
        ledger: PathBuf,
        host_key: PathBuf,
        program: PathBuf,
        calls: PathBuf,
        host_identity: [u8; 32],
    }

    impl AdminLifecycleFixture {
        fn recovery_admin(
            &self,
            point: Option<FaultPoint>,
        ) -> Result<SystemdCredentialAdmin, ProvisioningSecretStoreError> {
            SystemdCredentialAdmin::open_paths_for_recovery(
                &self.provisioning,
                &self.ledger,
                &self.host_key,
                false,
                crate::admin::encrypt::SystemdCredsEncryptor::at(self.program.clone()),
                point.map_or_else(FaultInjector::disabled, FaultInjector::at),
            )
        }
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
            let calls = path.join("encrypt.calls");
            let program = path.join("systemd-creds-test");
            fs::write(
                &program,
                format!(
                    "#!/bin/sh\ntest \"$#\" = 5 || exit 91\nprintf x >> {}\nprintf cipher:\nexec cat\n",
                    calls.display()
                ),
            )
            .expect("write provider fixture");
            fs::set_permissions(&program, fs::Permissions::from_mode(0o700))
                .expect("make provider fixture executable");
            Self {
                path,
                provisioning,
                ledger,
                host_key,
                program,
                calls,
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

        fn namespace_bytes(&self) -> Vec<(String, Vec<u8>)> {
            namespace_bytes(&self.provisioning, &self.ledger)
        }

        fn bundle(&self) -> UnprotectedProvisioning {
            UnprotectedProvisioning::new(
                include_bytes!("../../../../bindings/testdata/non-production-provisioning.bundle")
                    .to_vec(),
            )
            .expect("canonical fixture bundle")
        }

        fn alternate_bundle(&self) -> UnprotectedProvisioning {
            let mut authority =
                ReferenceProvisioner::from_seed([0xb6; 32]).expect("alternate provisioner");
            let access = ProvisioningAccess::member(
                Scope::new("mission/team/rotation").expect("alternate scope"),
                vec![0, 1],
                vec![Topic::new("rotation.events").expect("alternate topic")],
            )
            .expect("alternate access");
            let bundle = authority
                .issue_node(7, &[access])
                .expect("issue alternate bundle")
                .to_bytes()
                .expect("encode alternate bundle");
            UnprotectedProvisioning::new(bundle).expect("bounded alternate bundle")
        }

        fn encrypt_calls(&self) -> usize {
            fs::read(&self.calls).map_or(0, |calls| calls.len())
        }

        fn install_once(&self) {
            self.admin()
                .expect("fixture install admin")
                .install(
                    ProvisioningInstallId::new([0x11; 32]),
                    ProvisioningLoadId::new([0x22; 32]),
                    self.bundle(),
                )
                .expect("fixture install");
        }

        fn assert_active_runtime_loads(
            &self,
            operation: ProvisioningLoadId,
            secret_ref: &aster_mesh::ProvisioningSecretRef,
            expected: UnprotectedProvisioning,
        ) {
            let ciphertext = fs::read(self.provisioning.join("active/credential.cred"))
                .expect("read active test ciphertext");
            let envelope = ciphertext
                .strip_prefix(b"cipher:")
                .expect("test provider ciphertext contains exact envelope");
            let mut loader =
                SystemdCredentialLoader::from_test_envelope(Zeroizing::new(envelope.to_vec()));
            let receipt = loader
                .load(operation, secret_ref)
                .expect("production runtime loader accepts retained Active envelope");
            assert_eq!(receipt.operation(), operation);
            assert_eq!(receipt.secret_ref(), secret_ref);
            assert_eq!(receipt.plaintext().expose(), expected.expose());
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

        fn write_pending_ledger(&self, ledger: &ProviderLedger) {
            let path = self.ledger.join("ledger.next");
            fs::write(
                &path,
                encode_ledger(ledger).expect("encode pending lifecycle fixture ledger"),
            )
            .expect("write pending lifecycle fixture ledger");
            fs::set_permissions(path, fs::Permissions::from_mode(0o600))
                .expect("protect pending lifecycle fixture ledger");
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
            namespace_bytes(&self.provisioning, &self.ledger)
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
            backup_operation: None,
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

    fn capacity_rotation_ledgers(
        predecessor: &ProviderLedger,
        operation: ProvisioningInstallId,
        load: ProvisioningLoadId,
    ) -> (ProviderLedger, ProviderLedger) {
        let source = predecessor
            .generations
            .iter()
            .find(|record| record.state == GenerationState::Active)
            .expect("capacity Active generation");
        let generation = source.generation.checked_add(1).unwrap();
        let mut intent = predecessor.clone();
        intent.intent = Some(LifecycleIntent {
            kind: LifecycleIntentKind::Rotate,
            operation: *operation.as_bytes(),
            backup_operation: None,
            load: Some(load),
            target_ref: provisioning_secret_ref(generation, [0xf1; PROVIDER_REFERENCE_ID_BYTES])
                .expect("capacity target reference"),
            target_generation: generation,
            source_ref: Some(source.secret_ref.clone()),
            envelope_commitment: Some([0xf2; 32]),
            expected_ciphertext_digest: Some([0xf3; 32]),
            expected_artifact_digest: None,
            pre_mutation_ledger_revision: crate::admin::digest(
                &encode_ledger(predecessor).expect("bounded capacity predecessor"),
            ),
        });
        let completed = completed_from_intent(&intent).expect("bounded capacity completion");
        (intent, completed)
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
            backup_operation: Some([0x70; 32]),
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
            backup_operation: None,
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

    fn add_retained_generation(
        intent_ledger: &mut ProviderLedger,
        completed: &mut ProviderLedger,
        retained: GenerationRecord,
    ) {
        intent_ledger.generations.push(retained.clone());
        let mut predecessor = intent_ledger.clone();
        predecessor.intent = None;
        intent_ledger
            .intent
            .as_mut()
            .expect("lifecycle intent")
            .pre_mutation_ledger_revision = crate::admin::digest(
            &encode_ledger(&predecessor).expect("encode composed predecessor"),
        );
        completed.generations.push(retained);
    }

    fn bind_fixture_host(
        intent_ledger: &mut ProviderLedger,
        completed: &mut ProviderLedger,
        host_key_identity: [u8; 32],
    ) {
        intent_ledger.host_key_identity = host_key_identity;
        completed.host_key_identity = host_key_identity;
        let mut predecessor = intent_ledger.clone();
        predecessor.intent = None;
        intent_ledger
            .intent
            .as_mut()
            .expect("lifecycle intent")
            .pre_mutation_ledger_revision = crate::admin::digest(
            &encode_ledger(&predecessor).expect("encode host-bound predecessor"),
        );
    }

    fn interrupt_reconciliation(
        fixture: &AdminLifecycleFixture,
        intent_ledger: ProviderLedger,
        completed: &ProviderLedger,
        point: FaultPoint,
    ) {
        let provisioning_fd =
            open_secure_root(&fixture.provisioning, false).expect("open provisioning fixture");
        let ledger_fd = open_secure_root(&fixture.ledger, false).expect("open ledger fixture");
        assert_eq!(
            reconcile_lifecycle(
                &provisioning_fd,
                &ledger_fd,
                intent_ledger,
                completed,
                &mut FaultInjector::at(point),
            )
            .expect_err("interrupt reconciliation fixture"),
            ProvisioningSecretStoreError::Unavailable,
            "fault {point:?}",
        );
    }

    fn read_fixture_ledger(fixture: &AdminLifecycleFixture) -> ProviderLedger {
        decode_ledger(&fs::read(fixture.ledger.join("ledger")).expect("read fixture ledger"))
            .expect("decode fixture ledger")
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

    fn namespace_bytes(provisioning: &Path, ledger: &Path) -> Vec<(String, Vec<u8>)> {
        let mut bytes = provisioning_bytes(provisioning);
        for name in ["ledger", "ledger.next"] {
            let path = ledger.join(name);
            if path.exists() {
                bytes.push((
                    name.to_owned(),
                    fs::read(path).expect("read lifecycle ledger bytes"),
                ));
            }
        }
        bytes
    }

    fn provisioning_bytes(provisioning: &Path) -> Vec<(String, Vec<u8>)> {
        let mut bytes = Vec::new();
        for slot in [
            ACTIVE_DIRECTORY,
            PREVIOUS_DIRECTORY,
            STAGED_DIRECTORY,
            CLEANUP_DIRECTORY,
        ] {
            let directory = provisioning.join(slot);
            if !directory.exists() {
                continue;
            }
            let mut names = fs::read_dir(&directory)
                .expect("read lifecycle slot")
                .map(|entry| {
                    entry
                        .expect("read lifecycle entry")
                        .file_name()
                        .into_string()
                        .expect("ASCII lifecycle entry")
                })
                .collect::<Vec<_>>();
            names.sort();
            if names.is_empty() {
                bytes.push((format!("{slot}/"), Vec::new()));
            }
            for name in names {
                bytes.push((
                    format!("{slot}/{name}"),
                    fs::read(directory.join(&name)).expect("read lifecycle bytes"),
                ));
            }
        }
        bytes
    }

    fn generation_bytes(provisioning: &Path, slot: &str) -> Vec<(String, Vec<u8>)> {
        provisioning_bytes(provisioning)
            .into_iter()
            .filter(|(name, _)| name.starts_with(&format!("{slot}/")))
            .collect()
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
