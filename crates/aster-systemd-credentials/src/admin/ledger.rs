use crate::provider_generation;
use aster_mesh::{
    ProvisioningDestroyId, ProvisioningInstallId, ProvisioningLoadId, ProvisioningSecretRef,
    ProvisioningSecretStoreError,
};
use std::collections::HashSet;
use zeroize::Zeroizing;

const LEDGER_MAGIC: &[u8; 8] = b"ASTRSDL1";
const LEDGER_VERSION: u16 = 2;
const LEDGER_HEADER_BYTES: usize = 8 + 2 + 1 + 1 + 32 + 4 + 4 + 4 + 4;
const GENERATION_FIXED_BYTES: usize = 1 + 3 + 8 + 32 + 32 + 32 + 32 + 4;
const BACKUP_FIXED_BYTES: usize = 32 + 8 + 32 + 4;
const RECOVERY_FIXED_BYTES: usize = 32 + 32 + 8 + 32 + 4;
const DESTROY_FIXED_BYTES: usize = 1 + 3 + 32 + 8 + 4;
const INTENT_FIXED_BYTES: usize = 1 + 1 + 2 + 32 + 8 + 32 + 4;
const INTENT_OPTION_LOAD: u8 = 1 << 0;
const INTENT_OPTION_SOURCE: u8 = 1 << 1;
const INTENT_OPTION_ENVELOPE: u8 = 1 << 2;
const INTENT_OPTION_CIPHERTEXT: u8 = 1 << 3;
const INTENT_OPTION_ARTIFACT: u8 = 1 << 4;
const INTENT_OPTION_BACKUP_OPERATION: u8 = 1 << 5;
const INTENT_OPTION_MASK: u8 = INTENT_OPTION_LOAD
    | INTENT_OPTION_SOURCE
    | INTENT_OPTION_ENVELOPE
    | INTENT_OPTION_CIPHERTEXT
    | INTENT_OPTION_ARTIFACT
    | INTENT_OPTION_BACKUP_OPERATION;

pub(super) const MAX_LEDGER_BYTES: usize = 64 * 1024;

#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) struct ProviderLedger {
    pub(super) host_key_identity: [u8; 32],
    pub(super) intent: Option<LifecycleIntent>,
    pub(super) generations: Vec<GenerationRecord>,
    pub(super) backups: Vec<BackupBinding>,
    pub(super) recoveries: Vec<RecoveryBinding>,
    pub(super) destroys: Vec<DestroyBinding>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) struct GenerationRecord {
    pub(super) install: ProvisioningInstallId,
    pub(super) load: ProvisioningLoadId,
    pub(super) secret_ref: ProvisioningSecretRef,
    pub(super) generation: u64,
    pub(super) envelope_commitment: [u8; 32],
    pub(super) ciphertext_digest: [u8; 32],
    pub(super) state: GenerationState,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum GenerationState {
    Active = 1,
    Previous = 2,
    Destroyed = 3,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) struct LifecycleIntent {
    pub(super) kind: LifecycleIntentKind,
    pub(super) operation: [u8; 32],
    pub(super) backup_operation: Option<[u8; 32]>,
    pub(super) load: Option<ProvisioningLoadId>,
    pub(super) target_ref: ProvisioningSecretRef,
    pub(super) target_generation: u64,
    pub(super) source_ref: Option<ProvisioningSecretRef>,
    pub(super) envelope_commitment: Option<[u8; 32]>,
    pub(super) expected_ciphertext_digest: Option<[u8; 32]>,
    pub(super) expected_artifact_digest: Option<[u8; 32]>,
    pub(super) pre_mutation_ledger_revision: [u8; 32],
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum LifecycleIntentKind {
    Install = 1,
    Rotate = 2,
    Recover = 3,
    DestroyActive = 4,
    DestroyPrevious = 5,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) struct BackupBinding {
    pub(super) operation: [u8; 32],
    pub(super) secret_ref: ProvisioningSecretRef,
    pub(super) generation: u64,
    pub(super) artifact_digest: [u8; 32],
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) struct RecoveryBinding {
    pub(super) operation: [u8; 32],
    pub(super) backup_operation: [u8; 32],
    pub(super) secret_ref: ProvisioningSecretRef,
    pub(super) generation: u64,
    pub(super) artifact_digest: [u8; 32],
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) struct DestroyBinding {
    pub(super) operation: ProvisioningDestroyId,
    pub(super) secret_ref: ProvisioningSecretRef,
    pub(super) generation: u64,
    pub(super) outcome: DestroyBindingOutcome,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum DestroyBindingOutcome {
    Destroyed = 1,
    NotFound = 2,
}

pub(super) fn encode_ledger(
    ledger: &ProviderLedger,
) -> Result<Vec<u8>, ProvisioningSecretStoreError> {
    let mut encoded = Vec::with_capacity(MAX_LEDGER_BYTES);
    append(&mut encoded, LEDGER_MAGIC)?;
    append(&mut encoded, &LEDGER_VERSION.to_be_bytes())?;
    append(&mut encoded, &[u8::from(ledger.intent.is_some()), 0])?;
    append(&mut encoded, &ledger.host_key_identity)?;
    append_count(&mut encoded, ledger.generations.len())?;
    append_count(&mut encoded, ledger.backups.len())?;
    append_count(&mut encoded, ledger.recoveries.len())?;
    append_count(&mut encoded, ledger.destroys.len())?;

    for generation in &ledger.generations {
        append(&mut encoded, &[generation.state as u8, 0, 0, 0])?;
        append(&mut encoded, &generation.generation.to_be_bytes())?;
        append(&mut encoded, generation.install.as_bytes())?;
        append(&mut encoded, generation.load.as_bytes())?;
        append(&mut encoded, &generation.envelope_commitment)?;
        append(&mut encoded, &generation.ciphertext_digest)?;
        append_reference(&mut encoded, &generation.secret_ref)?;
    }
    for backup in &ledger.backups {
        append(&mut encoded, &backup.operation)?;
        append(&mut encoded, &backup.generation.to_be_bytes())?;
        append(&mut encoded, &backup.artifact_digest)?;
        append_reference(&mut encoded, &backup.secret_ref)?;
    }
    for recovery in &ledger.recoveries {
        append(&mut encoded, &recovery.operation)?;
        append(&mut encoded, &recovery.backup_operation)?;
        append(&mut encoded, &recovery.generation.to_be_bytes())?;
        append(&mut encoded, &recovery.artifact_digest)?;
        append_reference(&mut encoded, &recovery.secret_ref)?;
    }
    for destroy in &ledger.destroys {
        append(&mut encoded, &[destroy.outcome as u8, 0, 0, 0])?;
        append(&mut encoded, destroy.operation.as_bytes())?;
        append(&mut encoded, &destroy.generation.to_be_bytes())?;
        append_reference(&mut encoded, &destroy.secret_ref)?;
    }
    if let Some(intent) = &ledger.intent {
        encode_intent(&mut encoded, intent)?;
    }
    Ok(encoded)
}

pub(super) fn decode_ledger(
    encoded: &[u8],
) -> Result<ProviderLedger, ProvisioningSecretStoreError> {
    if encoded.len() > MAX_LEDGER_BYTES {
        return Err(ProvisioningSecretStoreError::TooLarge);
    }
    if encoded.len() < LEDGER_HEADER_BYTES
        || &encoded[..8] != LEDGER_MAGIC
        || u16::from_be_bytes(read_array(&encoded[8..10])?) != LEDGER_VERSION
        || encoded[10] > 1
        || encoded[11] != 0
    {
        return Err(ProvisioningSecretStoreError::Rejected);
    }

    let has_intent = encoded[10] == 1;
    let host_key_identity = read_array(&encoded[12..44])?;
    let generation_count = read_count(&encoded[44..48])?;
    let backup_count = read_count(&encoded[48..52])?;
    let recovery_count = read_count(&encoded[52..56])?;
    let destroy_count = read_count(&encoded[56..60])?;
    let remaining = encoded.len() - LEDGER_HEADER_BYTES;
    validate_count::<GenerationRecord>(generation_count, GENERATION_FIXED_BYTES, remaining)?;
    validate_count::<BackupBinding>(backup_count, BACKUP_FIXED_BYTES, remaining)?;
    validate_count::<RecoveryBinding>(recovery_count, RECOVERY_FIXED_BYTES, remaining)?;
    validate_count::<DestroyBinding>(destroy_count, DESTROY_FIXED_BYTES, remaining)?;
    let minimum_records = checked_sum([
        generation_count.checked_mul(GENERATION_FIXED_BYTES),
        backup_count.checked_mul(BACKUP_FIXED_BYTES),
        recovery_count.checked_mul(RECOVERY_FIXED_BYTES),
        destroy_count.checked_mul(DESTROY_FIXED_BYTES),
        Some(if has_intent { INTENT_FIXED_BYTES } else { 0 }),
    ])?;
    let vector_allocation = checked_sum([
        generation_count.checked_mul(std::mem::size_of::<GenerationRecord>()),
        backup_count.checked_mul(std::mem::size_of::<BackupBinding>()),
        recovery_count.checked_mul(std::mem::size_of::<RecoveryBinding>()),
        destroy_count.checked_mul(std::mem::size_of::<DestroyBinding>()),
        Some(0),
    ])?;
    if minimum_records > remaining || vector_allocation > MAX_LEDGER_BYTES {
        return Err(ProvisioningSecretStoreError::Rejected);
    }

    let mut decoder = Decoder {
        encoded,
        offset: LEDGER_HEADER_BYTES,
    };
    let mut generations = Vec::with_capacity(generation_count);
    for _ in 0..generation_count {
        generations.push(decoder.generation()?);
    }
    let mut backups = Vec::with_capacity(backup_count);
    for _ in 0..backup_count {
        backups.push(decoder.backup()?);
    }
    let mut recoveries = Vec::with_capacity(recovery_count);
    for _ in 0..recovery_count {
        recoveries.push(decoder.recovery()?);
    }
    let mut destroys = Vec::with_capacity(destroy_count);
    for _ in 0..destroy_count {
        destroys.push(decoder.destroy()?);
    }
    let intent = has_intent.then(|| decoder.intent()).transpose()?;
    if decoder.offset != encoded.len() {
        return Err(ProvisioningSecretStoreError::Rejected);
    }

    let ledger = ProviderLedger {
        host_key_identity,
        intent,
        generations,
        backups,
        recoveries,
        destroys,
    };
    validate_ledger(&ledger)?;
    Ok(ledger)
}

fn encode_intent(
    encoded: &mut Vec<u8>,
    intent: &LifecycleIntent,
) -> Result<(), ProvisioningSecretStoreError> {
    let options = (u8::from(intent.load.is_some()) * INTENT_OPTION_LOAD)
        | (u8::from(intent.source_ref.is_some()) * INTENT_OPTION_SOURCE)
        | (u8::from(intent.envelope_commitment.is_some()) * INTENT_OPTION_ENVELOPE)
        | (u8::from(intent.expected_ciphertext_digest.is_some()) * INTENT_OPTION_CIPHERTEXT)
        | (u8::from(intent.expected_artifact_digest.is_some()) * INTENT_OPTION_ARTIFACT)
        | (u8::from(intent.backup_operation.is_some()) * INTENT_OPTION_BACKUP_OPERATION);
    append(encoded, &[intent.kind as u8, options, 0, 0])?;
    append(encoded, &intent.operation)?;
    append(encoded, &intent.target_generation.to_be_bytes())?;
    append(encoded, &intent.pre_mutation_ledger_revision)?;
    append_reference(encoded, &intent.target_ref)?;
    if let Some(load) = intent.load {
        append(encoded, load.as_bytes())?;
    }
    if let Some(source_ref) = &intent.source_ref {
        append_reference(encoded, source_ref)?;
    }
    if let Some(commitment) = intent.envelope_commitment {
        append(encoded, &commitment)?;
    }
    if let Some(digest) = intent.expected_ciphertext_digest {
        append(encoded, &digest)?;
    }
    if let Some(digest) = intent.expected_artifact_digest {
        append(encoded, &digest)?;
    }
    if let Some(operation) = intent.backup_operation {
        append(encoded, &operation)?;
    }
    Ok(())
}

fn append_count(encoded: &mut Vec<u8>, count: usize) -> Result<(), ProvisioningSecretStoreError> {
    let count = u32::try_from(count).map_err(|_| ProvisioningSecretStoreError::TooLarge)?;
    append(encoded, &count.to_be_bytes())
}

fn append_reference(
    encoded: &mut Vec<u8>,
    secret_ref: &ProvisioningSecretRef,
) -> Result<(), ProvisioningSecretStoreError> {
    let reference = Zeroizing::new(secret_ref.to_bytes());
    append_count(encoded, reference.len())?;
    append(encoded, &reference)
}

fn append(encoded: &mut Vec<u8>, bytes: &[u8]) -> Result<(), ProvisioningSecretStoreError> {
    let new_len = encoded
        .len()
        .checked_add(bytes.len())
        .filter(|length| *length <= MAX_LEDGER_BYTES)
        .ok_or(ProvisioningSecretStoreError::TooLarge)?;
    encoded.reserve(new_len - encoded.len());
    encoded.extend_from_slice(bytes);
    Ok(())
}

fn read_array<const N: usize>(bytes: &[u8]) -> Result<[u8; N], ProvisioningSecretStoreError> {
    bytes
        .try_into()
        .map_err(|_| ProvisioningSecretStoreError::Rejected)
}

fn read_count(bytes: &[u8]) -> Result<usize, ProvisioningSecretStoreError> {
    usize::try_from(u32::from_be_bytes(read_array(bytes)?))
        .map_err(|_| ProvisioningSecretStoreError::Rejected)
}

fn validate_count<T>(
    count: usize,
    fixed_record_bytes: usize,
    remaining: usize,
) -> Result<(), ProvisioningSecretStoreError> {
    let required = count
        .checked_mul(fixed_record_bytes)
        .ok_or(ProvisioningSecretStoreError::Rejected)?;
    let allocation = count
        .checked_mul(std::mem::size_of::<T>())
        .ok_or(ProvisioningSecretStoreError::Rejected)?;
    if required > remaining || required > MAX_LEDGER_BYTES || allocation > MAX_LEDGER_BYTES {
        return Err(ProvisioningSecretStoreError::Rejected);
    }
    Ok(())
}

fn checked_sum(values: [Option<usize>; 5]) -> Result<usize, ProvisioningSecretStoreError> {
    values.into_iter().try_fold(0_usize, |sum, value| {
        sum.checked_add(value.ok_or(ProvisioningSecretStoreError::Rejected)?)
            .ok_or(ProvisioningSecretStoreError::Rejected)
    })
}

struct Decoder<'a> {
    encoded: &'a [u8],
    offset: usize,
}

impl<'a> Decoder<'a> {
    fn take(&mut self, length: usize) -> Result<&'a [u8], ProvisioningSecretStoreError> {
        let end = self
            .offset
            .checked_add(length)
            .filter(|end| *end <= self.encoded.len())
            .ok_or(ProvisioningSecretStoreError::Rejected)?;
        let bytes = &self.encoded[self.offset..end];
        self.offset = end;
        Ok(bytes)
    }

    fn array<const N: usize>(&mut self) -> Result<[u8; N], ProvisioningSecretStoreError> {
        read_array(self.take(N)?)
    }

    fn u64(&mut self) -> Result<u64, ProvisioningSecretStoreError> {
        self.array().map(u64::from_be_bytes)
    }

    fn reference(&mut self) -> Result<ProvisioningSecretRef, ProvisioningSecretStoreError> {
        let length = usize::try_from(u32::from_be_bytes(self.array()?))
            .map_err(|_| ProvisioningSecretStoreError::Rejected)?;
        if length > aster_mesh::MAX_PROVISIONING_SECRET_REF_BYTES {
            return Err(ProvisioningSecretStoreError::Rejected);
        }
        ProvisioningSecretRef::from_bytes(self.take(length)?)
            .map_err(|_| ProvisioningSecretStoreError::Rejected)
    }

    fn generation(&mut self) -> Result<GenerationRecord, ProvisioningSecretStoreError> {
        let state = match self.take(1)?[0] {
            1 => GenerationState::Active,
            2 => GenerationState::Previous,
            3 => GenerationState::Destroyed,
            _ => return Err(ProvisioningSecretStoreError::Rejected),
        };
        if self.take(3)? != [0, 0, 0] {
            return Err(ProvisioningSecretStoreError::Rejected);
        }
        Ok(GenerationRecord {
            generation: self.u64()?,
            install: ProvisioningInstallId::new(self.array()?),
            load: ProvisioningLoadId::new(self.array()?),
            envelope_commitment: self.array()?,
            ciphertext_digest: self.array()?,
            secret_ref: self.reference()?,
            state,
        })
    }

    fn backup(&mut self) -> Result<BackupBinding, ProvisioningSecretStoreError> {
        Ok(BackupBinding {
            operation: self.array()?,
            generation: self.u64()?,
            artifact_digest: self.array()?,
            secret_ref: self.reference()?,
        })
    }

    fn recovery(&mut self) -> Result<RecoveryBinding, ProvisioningSecretStoreError> {
        Ok(RecoveryBinding {
            operation: self.array()?,
            backup_operation: self.array()?,
            generation: self.u64()?,
            artifact_digest: self.array()?,
            secret_ref: self.reference()?,
        })
    }

    fn destroy(&mut self) -> Result<DestroyBinding, ProvisioningSecretStoreError> {
        let outcome = match self.take(1)?[0] {
            1 => DestroyBindingOutcome::Destroyed,
            2 => DestroyBindingOutcome::NotFound,
            _ => return Err(ProvisioningSecretStoreError::Rejected),
        };
        if self.take(3)? != [0, 0, 0] {
            return Err(ProvisioningSecretStoreError::Rejected);
        }
        Ok(DestroyBinding {
            operation: ProvisioningDestroyId::new(self.array()?),
            generation: self.u64()?,
            secret_ref: self.reference()?,
            outcome,
        })
    }

    fn intent(&mut self) -> Result<LifecycleIntent, ProvisioningSecretStoreError> {
        let kind = match self.take(1)?[0] {
            1 => LifecycleIntentKind::Install,
            2 => LifecycleIntentKind::Rotate,
            3 => LifecycleIntentKind::Recover,
            4 => LifecycleIntentKind::DestroyActive,
            5 => LifecycleIntentKind::DestroyPrevious,
            _ => return Err(ProvisioningSecretStoreError::Rejected),
        };
        let options = self.take(1)?[0];
        if options & !INTENT_OPTION_MASK != 0 || self.take(2)? != [0, 0] {
            return Err(ProvisioningSecretStoreError::Rejected);
        }
        let operation = self.array()?;
        let target_generation = self.u64()?;
        let pre_mutation_ledger_revision = self.array()?;
        let target_ref = self.reference()?;
        let load = (options & INTENT_OPTION_LOAD != 0)
            .then(|| self.array().map(ProvisioningLoadId::new))
            .transpose()?;
        let source_ref = (options & INTENT_OPTION_SOURCE != 0)
            .then(|| self.reference())
            .transpose()?;
        let envelope_commitment = (options & INTENT_OPTION_ENVELOPE != 0)
            .then(|| self.array())
            .transpose()?;
        let expected_ciphertext_digest = (options & INTENT_OPTION_CIPHERTEXT != 0)
            .then(|| self.array())
            .transpose()?;
        let expected_artifact_digest = (options & INTENT_OPTION_ARTIFACT != 0)
            .then(|| self.array())
            .transpose()?;
        let backup_operation = (options & INTENT_OPTION_BACKUP_OPERATION != 0)
            .then(|| self.array())
            .transpose()?;
        Ok(LifecycleIntent {
            kind,
            operation,
            backup_operation,
            load,
            target_ref,
            target_generation,
            source_ref,
            envelope_commitment,
            expected_ciphertext_digest,
            expected_artifact_digest,
            pre_mutation_ledger_revision,
        })
    }
}

fn validate_ledger(ledger: &ProviderLedger) -> Result<(), ProvisioningSecretStoreError> {
    let mut installs = HashSet::new();
    let mut loads = HashSet::new();
    let mut references = HashSet::new();
    let mut generation_numbers = HashSet::new();
    let mut active = 0_usize;
    let mut previous = 0_usize;
    for record in &ledger.generations {
        validate_reference_generation(&record.secret_ref, record.generation)?;
        if !installs.insert(*record.install.as_bytes())
            || !loads.insert(*record.load.as_bytes())
            || !references.insert(record.secret_ref.to_bytes())
            || !generation_numbers.insert(record.generation)
        {
            return Err(ProvisioningSecretStoreError::Rejected);
        }
        match record.state {
            GenerationState::Active => active += 1,
            GenerationState::Previous => previous += 1,
            GenerationState::Destroyed if record.ciphertext_digest != [0; 32] => {
                return Err(ProvisioningSecretStoreError::Rejected);
            }
            GenerationState::Destroyed => {}
        }
    }
    if active > 1 || previous > 1 {
        return Err(ProvisioningSecretStoreError::Rejected);
    }

    validate_unique_operations(ledger.backups.iter().map(|binding| binding.operation))?;
    validate_unique_operations(ledger.recoveries.iter().map(|binding| binding.operation))?;
    validate_unique_operations(
        ledger
            .destroys
            .iter()
            .map(|binding| *binding.operation.as_bytes()),
    )?;
    for binding in &ledger.backups {
        validate_reference_generation(&binding.secret_ref, binding.generation)?;
    }
    for binding in &ledger.recoveries {
        validate_reference_generation(&binding.secret_ref, binding.generation)?;
    }
    for binding in &ledger.destroys {
        validate_reference_generation(&binding.secret_ref, binding.generation)?;
        let retained = ledger.generations.iter().find(|record| {
            record.generation == binding.generation && record.secret_ref == binding.secret_ref
        });
        match (binding.outcome, retained.map(|record| record.state)) {
            (DestroyBindingOutcome::NotFound, None)
            | (DestroyBindingOutcome::Destroyed, Some(GenerationState::Destroyed)) => {}
            _ => return Err(ProvisioningSecretStoreError::Rejected),
        }
    }
    if let Some(intent) = &ledger.intent {
        if (intent.kind == LifecycleIntentKind::Recover) != intent.backup_operation.is_some() {
            return Err(ProvisioningSecretStoreError::Rejected);
        }
        validate_reference_generation(&intent.target_ref, intent.target_generation)?;
        if let Some(source) = &intent.source_ref {
            provider_generation(source).map_err(|_| ProvisioningSecretStoreError::Rejected)?;
        }
        let operation_exists = match intent.kind {
            LifecycleIntentKind::Install | LifecycleIntentKind::Rotate => {
                installs.contains(&intent.operation)
            }
            LifecycleIntentKind::Recover => ledger
                .recoveries
                .iter()
                .any(|binding| binding.operation == intent.operation),
            LifecycleIntentKind::DestroyActive | LifecycleIntentKind::DestroyPrevious => ledger
                .destroys
                .iter()
                .any(|binding| binding.operation.as_bytes() == &intent.operation),
        };
        if operation_exists {
            return Err(ProvisioningSecretStoreError::Rejected);
        }
    }
    Ok(())
}

fn validate_unique_operations(
    operations: impl IntoIterator<Item = [u8; 32]>,
) -> Result<(), ProvisioningSecretStoreError> {
    let mut unique = HashSet::new();
    if operations
        .into_iter()
        .any(|operation| !unique.insert(operation))
    {
        return Err(ProvisioningSecretStoreError::Rejected);
    }
    Ok(())
}

fn validate_reference_generation(
    secret_ref: &ProvisioningSecretRef,
    generation: u64,
) -> Result<(), ProvisioningSecretStoreError> {
    if generation == 0
        || provider_generation(secret_ref).map_err(|_| ProvisioningSecretStoreError::Rejected)?
            != generation
    {
        return Err(ProvisioningSecretStoreError::Rejected);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{
        BackupBinding, DestroyBinding, DestroyBindingOutcome, GENERATION_FIXED_BYTES,
        GenerationRecord, GenerationState, LEDGER_HEADER_BYTES, LifecycleIntent,
        LifecycleIntentKind, MAX_LEDGER_BYTES, ProviderLedger, RecoveryBinding, decode_ledger,
        encode_ledger,
    };
    use crate::{PROVIDER_REFERENCE_ID_BYTES, provisioning_secret_ref};
    use aster_mesh::{
        ProvisioningDestroyId, ProvisioningInstallId, ProvisioningLoadId,
        ProvisioningSecretStoreError,
    };

    const INSTALL: ProvisioningInstallId = ProvisioningInstallId::new([0x11; 32]);
    const LOAD: ProvisioningLoadId = ProvisioningLoadId::new([0x22; 32]);

    fn generation_record(
        generation: u64,
        reference_id: u8,
        operation_id: u8,
        state: GenerationState,
    ) -> GenerationRecord {
        GenerationRecord {
            install: ProvisioningInstallId::new([operation_id; 32]),
            load: ProvisioningLoadId::new([operation_id.wrapping_add(1); 32]),
            secret_ref: provisioning_secret_ref(
                generation,
                [reference_id; PROVIDER_REFERENCE_ID_BYTES],
            )
            .expect("fixture reference"),
            generation,
            envelope_commitment: [operation_id.wrapping_add(2); 32],
            ciphertext_digest: if state == GenerationState::Destroyed {
                [0; 32]
            } else {
                [operation_id.wrapping_add(3); 32]
            },
            state,
        }
    }

    fn fixture_ledger() -> ProviderLedger {
        ProviderLedger {
            host_key_identity: [0xa0; 32],
            intent: None,
            generations: vec![GenerationRecord {
                install: INSTALL,
                load: LOAD,
                secret_ref: provisioning_secret_ref(2, [0x33; PROVIDER_REFERENCE_ID_BYTES])
                    .expect("fixture reference"),
                generation: 2,
                envelope_commitment: [0x44; 32],
                ciphertext_digest: [0x55; 32],
                state: GenerationState::Active,
            }],
            backups: vec![],
            recoveries: vec![],
            destroys: vec![],
        }
    }

    #[test]
    fn lifecycle_ledger_round_trip_preserves_the_canonical_generation() {
        // Break caught: a lifecycle codec that loses the host identity or any
        // generation binding could select a credential from another host,
        // operation, reference, or ciphertext.
        let ledger = fixture_ledger();
        let encoded = encode_ledger(&ledger).expect("bounded canonical ledger");
        assert_eq!(&encoded[..8], b"ASTRSDL1");
        assert_eq!(&encoded[8..10], &2_u16.to_be_bytes());
        assert_eq!(encoded[10], 0);
        assert_eq!(encoded[11], 0);
        assert_eq!(&encoded[12..44], &[0xa0; 32]);
        assert_eq!(&encoded[44..48], &1_u32.to_be_bytes());
        assert_eq!(
            decode_ledger(&encoded).expect("canonical lifecycle ledger"),
            ledger
        );
    }

    #[test]
    fn lifecycle_ledger_round_trip_preserves_intent_and_completed_history() {
        // Break caught: dropping an intent field or completed binding prevents
        // exact crash reconciliation and retry/conflict classification.
        let mut ledger = fixture_ledger();
        let target = ledger.generations[0].secret_ref.clone();
        ledger.intent = Some(LifecycleIntent {
            kind: LifecycleIntentKind::Rotate,
            operation: [0x60; 32],
            backup_operation: None,
            load: Some(ProvisioningLoadId::new([0x61; 32])),
            target_ref: provisioning_secret_ref(3, [0x62; 32]).expect("target reference"),
            target_generation: 3,
            source_ref: Some(target.clone()),
            envelope_commitment: Some([0x63; 32]),
            expected_ciphertext_digest: Some([0x64; 32]),
            expected_artifact_digest: None,
            pre_mutation_ledger_revision: [0x65; 32],
        });
        ledger.backups.push(BackupBinding {
            operation: [0x70; 32],
            secret_ref: target.clone(),
            generation: 2,
            artifact_digest: [0x71; 32],
        });
        ledger.recoveries.push(RecoveryBinding {
            operation: [0x72; 32],
            backup_operation: [0x70; 32],
            secret_ref: target.clone(),
            generation: 2,
            artifact_digest: [0x71; 32],
        });
        ledger.destroys.push(DestroyBinding {
            operation: ProvisioningDestroyId::new([0x73; 32]),
            secret_ref: provisioning_secret_ref(9, [0x74; 32]).expect("unknown reference"),
            generation: 9,
            outcome: DestroyBindingOutcome::NotFound,
        });

        assert_eq!(
            decode_ledger(&encode_ledger(&ledger).expect("bounded ledger"))
                .expect("canonical lifecycle history"),
            ledger
        );
    }

    #[test]
    fn recover_intent_canonically_requires_the_authenticated_backup_operation() {
        // Break caught: without the already-authenticated backup operation in
        // the durable intent, a fresh reconciler cannot reconstruct the exact
        // RecoveryBinding and must either invent identity or strand intent.
        let mut ledger = fixture_ledger();
        let target = ledger.generations[0].clone();
        ledger.backups.push(BackupBinding {
            operation: [0x70; 32],
            secret_ref: target.secret_ref.clone(),
            generation: target.generation,
            artifact_digest: [0x72; 32],
        });
        ledger.intent = Some(LifecycleIntent {
            kind: LifecycleIntentKind::Recover,
            operation: [0x71; 32],
            backup_operation: Some([0x70; 32]),
            load: Some(target.load),
            target_ref: target.secret_ref,
            target_generation: target.generation,
            source_ref: None,
            envelope_commitment: None,
            expected_ciphertext_digest: Some(target.ciphertext_digest),
            expected_artifact_digest: Some([0x72; 32]),
            pre_mutation_ledger_revision: [0x73; 32],
        });

        let encoded = encode_ledger(&ledger).expect("encode Recover intent");
        assert_eq!(
            decode_ledger(&encoded).expect("decode Recover intent"),
            ledger
        );

        let mut missing = ledger.clone();
        missing
            .intent
            .as_mut()
            .expect("Recover intent")
            .backup_operation = None;
        assert_eq!(
            decode_ledger(&encode_ledger(&missing).expect("encode missing backup operation"))
                .expect_err("Recover without backup operation"),
            ProvisioningSecretStoreError::Rejected,
        );

        let mut forbidden = ledger;
        let intent = forbidden.intent.as_mut().expect("Recover intent");
        intent.kind = LifecycleIntentKind::Rotate;
        assert_eq!(
            decode_ledger(&encode_ledger(&forbidden).expect("encode forbidden backup operation"))
                .expect_err("non-Recover backup operation"),
            ProvisioningSecretStoreError::Rejected,
        );
    }

    #[test]
    fn lifecycle_ledger_rejects_install_only_v2_extensions_and_invalid_enums() {
        // Break caught: accepting the draft install-only v2 layout, extension
        // bytes, or an unknown state would make one version noncanonical.
        let reference = provisioning_secret_ref(1, [0x33; 32])
            .expect("install-only reference")
            .to_bytes();
        let mut install_only_v2 = Vec::new();
        install_only_v2.extend_from_slice(b"ASTRSDL1");
        install_only_v2.extend_from_slice(&2_u16.to_be_bytes());
        install_only_v2.extend_from_slice(&[2, 0]);
        install_only_v2.extend_from_slice(&1_u64.to_be_bytes());
        install_only_v2.extend_from_slice(&[0x11; 32]);
        install_only_v2.extend_from_slice(&[0x22; 32]);
        install_only_v2.extend_from_slice(&[0x44; 32]);
        install_only_v2.extend_from_slice(&[0x55; 32]);
        install_only_v2.extend_from_slice(&(reference.len() as u32).to_be_bytes());
        install_only_v2.extend_from_slice(&reference);

        let canonical = encode_ledger(&fixture_ledger()).expect("canonical ledger");
        let mut extension = canonical.clone();
        extension.push(0);
        let mut invalid_state = canonical;
        invalid_state[60] = 9;
        let mut intent_ledger = fixture_ledger();
        intent_ledger.intent = Some(LifecycleIntent {
            kind: LifecycleIntentKind::Rotate,
            operation: [0x60; 32],
            backup_operation: None,
            load: Some(ProvisioningLoadId::new([0x61; 32])),
            target_ref: provisioning_secret_ref(3, [0x62; 32]).expect("target reference"),
            target_generation: 3,
            source_ref: Some(intent_ledger.generations[0].secret_ref.clone()),
            envelope_commitment: Some([0x63; 32]),
            expected_ciphertext_digest: Some([0x64; 32]),
            expected_artifact_digest: None,
            pre_mutation_ledger_revision: [0x65; 32],
        });
        let mut invalid_intent_kind =
            encode_ledger(&intent_ledger).expect("valid intent ledger fixture");
        assert_eq!(
            decode_ledger(&invalid_intent_kind).expect("complete valid intent fixture"),
            intent_ledger
        );
        let intent_offset = LEDGER_HEADER_BYTES
            + GENERATION_FIXED_BYTES
            + intent_ledger.generations[0].secret_ref.to_bytes().len();
        invalid_intent_kind[intent_offset] = 9;

        let mut destroy_ledger = fixture_ledger();
        destroy_ledger.generations[0].state = GenerationState::Destroyed;
        destroy_ledger.generations[0].ciphertext_digest = [0; 32];
        destroy_ledger.destroys.push(DestroyBinding {
            operation: ProvisioningDestroyId::new([0x73; 32]),
            secret_ref: destroy_ledger.generations[0].secret_ref.clone(),
            generation: destroy_ledger.generations[0].generation,
            outcome: DestroyBindingOutcome::Destroyed,
        });
        let mut invalid_destroy_outcome =
            encode_ledger(&destroy_ledger).expect("valid destroy ledger fixture");
        assert_eq!(
            decode_ledger(&invalid_destroy_outcome).expect("complete valid destroy fixture"),
            destroy_ledger
        );
        let destroy_offset = LEDGER_HEADER_BYTES
            + GENERATION_FIXED_BYTES
            + destroy_ledger.generations[0].secret_ref.to_bytes().len();
        invalid_destroy_outcome[destroy_offset] = 9;
        for encoded in [
            install_only_v2,
            extension,
            invalid_state,
            invalid_intent_kind,
            invalid_destroy_outcome,
        ] {
            assert_eq!(
                decode_ledger(&encoded).expect_err("noncanonical lifecycle ledger"),
                ProvisioningSecretStoreError::Rejected
            );
        }
    }

    #[test]
    fn lifecycle_ledger_rejects_duplicate_operations_and_references() {
        // Break caught: ambiguous durable operation or reference ownership can
        // classify a retry against the wrong completed generation.
        let mut duplicate_install = fixture_ledger();
        let mut second = generation_record(3, 0x66, 0x77, GenerationState::Previous);
        second.install = INSTALL;
        duplicate_install.generations.push(second);
        assert_eq!(
            decode_ledger(&encode_ledger(&duplicate_install).expect("encoded duplicate"))
                .expect_err("duplicate install operation"),
            ProvisioningSecretStoreError::Rejected
        );

        let mut duplicate_reference = fixture_ledger();
        let mut second = generation_record(3, 0x66, 0x77, GenerationState::Previous);
        second.secret_ref = duplicate_reference.generations[0].secret_ref.clone();
        second.generation = 2;
        duplicate_reference.generations.push(second);
        assert_eq!(
            decode_ledger(&encode_ledger(&duplicate_reference).expect("encoded duplicate"))
                .expect_err("duplicate generation reference"),
            ProvisioningSecretStoreError::Rejected
        );
    }

    #[test]
    fn lifecycle_ledger_rejects_invalid_generation_state_sets() {
        // Break caught: multiple live filesystem owners, cross-generation
        // references, or ciphertext-bearing tombstones make state ambiguous.
        let mut two_active = fixture_ledger();
        two_active
            .generations
            .push(generation_record(3, 0x66, 0x77, GenerationState::Active));
        let mut two_previous = fixture_ledger();
        two_previous.generations.extend([
            generation_record(3, 0x66, 0x77, GenerationState::Previous),
            generation_record(4, 0x88, 0x99, GenerationState::Previous),
        ]);
        let mut cross_generation = fixture_ledger();
        cross_generation.generations[0].secret_ref =
            provisioning_secret_ref(3, [0x33; PROVIDER_REFERENCE_ID_BYTES])
                .expect("cross-generation reference");
        let mut ciphertext_tombstone = fixture_ledger();
        ciphertext_tombstone.generations[0].state = GenerationState::Destroyed;

        for ledger in [
            two_active,
            two_previous,
            cross_generation,
            ciphertext_tombstone,
        ] {
            assert_eq!(
                decode_ledger(&encode_ledger(&ledger).expect("bounded invalid ledger"))
                    .expect_err("invalid generation state"),
                ProvisioningSecretStoreError::Rejected
            );
        }
    }

    #[test]
    fn lifecycle_ledger_rejects_destroy_bindings_that_contradict_generation_state() {
        // Break caught: recording NotFound for a retained reference, or
        // Destroyed without its exact tombstone, would make the durable destroy
        // answer contradict the same ledger's generation state.
        let mut not_found_active = fixture_ledger();
        not_found_active.destroys.push(DestroyBinding {
            operation: ProvisioningDestroyId::new([0x73; 32]),
            secret_ref: not_found_active.generations[0].secret_ref.clone(),
            generation: not_found_active.generations[0].generation,
            outcome: DestroyBindingOutcome::NotFound,
        });
        let mut destroyed_active = fixture_ledger();
        destroyed_active.destroys.push(DestroyBinding {
            operation: ProvisioningDestroyId::new([0x74; 32]),
            secret_ref: destroyed_active.generations[0].secret_ref.clone(),
            generation: destroyed_active.generations[0].generation,
            outcome: DestroyBindingOutcome::Destroyed,
        });
        let mut destroyed_unknown = fixture_ledger();
        destroyed_unknown.destroys.push(DestroyBinding {
            operation: ProvisioningDestroyId::new([0x75; 32]),
            secret_ref: provisioning_secret_ref(9, [0x76; 32]).expect("unknown reference"),
            generation: 9,
            outcome: DestroyBindingOutcome::Destroyed,
        });
        for ledger in [not_found_active, destroyed_active, destroyed_unknown] {
            assert_eq!(
                decode_ledger(&encode_ledger(&ledger).expect("bounded invalid ledger"))
                    .expect_err("contradictory destroy binding"),
                ProvisioningSecretStoreError::Rejected
            );
        }
    }

    #[test]
    fn lifecycle_ledger_rejects_overflowed_counts_and_oversized_input() {
        // Break caught: allocating from an unchecked count or accepting an
        // oversized snapshot enables hostile durable input to exhaust memory.
        for count_offset in [44, 48, 52, 56] {
            let mut overflowed_count = vec![0_u8; 60];
            overflowed_count[..8].copy_from_slice(b"ASTRSDL1");
            overflowed_count[8..10].copy_from_slice(&2_u16.to_be_bytes());
            overflowed_count[12..44].copy_from_slice(&[0xa0; 32]);
            overflowed_count[count_offset..count_offset + 4]
                .copy_from_slice(&u32::MAX.to_be_bytes());
            assert_eq!(
                decode_ledger(&overflowed_count).expect_err("overflowed record count"),
                ProvisioningSecretStoreError::Rejected
            );
        }
        assert_eq!(
            decode_ledger(&vec![0; MAX_LEDGER_BYTES + 1]).expect_err("oversized ledger"),
            ProvisioningSecretStoreError::TooLarge
        );

        let sample = generation_record(3, 0x66, 0x77, GenerationState::Destroyed);
        let encoded_record_bytes = GENERATION_FIXED_BYTES + sample.secret_ref.to_bytes().len();
        let over_capacity_count =
            (MAX_LEDGER_BYTES - LEDGER_HEADER_BYTES) / encoded_record_bytes + 1;
        let mut exhausted = fixture_ledger();
        exhausted.generations.clear();
        for generation in 1..=over_capacity_count as u64 {
            exhausted.generations.push(generation_record(
                generation,
                generation as u8,
                generation as u8,
                GenerationState::Destroyed,
            ));
        }
        assert_eq!(
            encode_ledger(&exhausted).expect_err("exhausted ledger capacity"),
            ProvisioningSecretStoreError::TooLarge
        );
    }
}
