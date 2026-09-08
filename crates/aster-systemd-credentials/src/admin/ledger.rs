use crate::provider_generation;
use aster_mesh::{
    ProvisioningInstallId, ProvisioningLoadId, ProvisioningSecretRef, ProvisioningSecretStoreError,
};
use zeroize::Zeroizing;

const LEDGER_MAGIC: &[u8; 8] = b"ASTRSDL1";
const LEDGER_VERSION: u16 = 1;
const LEDGER_HEADER_BYTES: usize = 8 + 2 + 1 + 1 + 8 + 32 + 32 + 32 + 32 + 4;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum InstallPhase {
    Intent = 1,
    Complete = 2,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) struct InstallRecord {
    pub(super) phase: InstallPhase,
    pub(super) install: ProvisioningInstallId,
    pub(super) load: ProvisioningLoadId,
    pub(super) secret_ref: ProvisioningSecretRef,
    pub(super) generation: u64,
    pub(super) envelope_commitment: [u8; 32],
    pub(super) ciphertext_digest: [u8; 32],
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum Retry {
    Existing,
}

pub(super) fn encode_record(record: &InstallRecord) -> Vec<u8> {
    let reference = Zeroizing::new(record.secret_ref.to_bytes());
    let reference_len =
        u32::try_from(reference.len()).expect("bounded provisioning reference fits in u32");
    let mut encoded = Vec::with_capacity(LEDGER_HEADER_BYTES + reference.len());
    encoded.extend_from_slice(LEDGER_MAGIC);
    encoded.extend_from_slice(&LEDGER_VERSION.to_be_bytes());
    encoded.push(record.phase as u8);
    encoded.push(0);
    encoded.extend_from_slice(&record.generation.to_be_bytes());
    encoded.extend_from_slice(record.install.as_bytes());
    encoded.extend_from_slice(record.load.as_bytes());
    encoded.extend_from_slice(&record.envelope_commitment);
    encoded.extend_from_slice(&record.ciphertext_digest);
    encoded.extend_from_slice(&reference_len.to_be_bytes());
    encoded.extend_from_slice(&reference);
    encoded
}

pub(super) fn decode_record(encoded: &[u8]) -> Result<InstallRecord, ProvisioningSecretStoreError> {
    if encoded.len() < LEDGER_HEADER_BYTES
        || &encoded[..8] != LEDGER_MAGIC
        || read_u16(&encoded[8..10])? != LEDGER_VERSION
        || encoded[11] != 0
    {
        return Err(ProvisioningSecretStoreError::Rejected);
    }
    let phase = match encoded[10] {
        1 => InstallPhase::Intent,
        2 => InstallPhase::Complete,
        _ => return Err(ProvisioningSecretStoreError::Rejected),
    };
    let generation = read_u64(&encoded[12..20])?;
    if generation == 0 {
        return Err(ProvisioningSecretStoreError::Rejected);
    }
    let install = ProvisioningInstallId::new(read_array(&encoded[20..52])?);
    let load = ProvisioningLoadId::new(read_array(&encoded[52..84])?);
    let envelope_commitment = read_array(&encoded[84..116])?;
    let ciphertext_digest = read_array(&encoded[116..148])?;
    let reference_len = usize::try_from(read_u32(&encoded[148..152])?)
        .map_err(|_| ProvisioningSecretStoreError::Rejected)?;
    let expected_len = LEDGER_HEADER_BYTES
        .checked_add(reference_len)
        .ok_or(ProvisioningSecretStoreError::Rejected)?;
    if expected_len != encoded.len() {
        return Err(ProvisioningSecretStoreError::Rejected);
    }
    let secret_ref = ProvisioningSecretRef::from_bytes(&encoded[LEDGER_HEADER_BYTES..])
        .map_err(|_| ProvisioningSecretStoreError::Rejected)?;
    if provider_generation(&secret_ref).map_err(|_| ProvisioningSecretStoreError::Rejected)?
        != generation
    {
        return Err(ProvisioningSecretStoreError::Rejected);
    }
    Ok(InstallRecord {
        phase,
        install,
        load,
        secret_ref,
        generation,
        envelope_commitment,
        ciphertext_digest,
    })
}

pub(super) fn classify_retry(
    record: &InstallRecord,
    operation: ProvisioningInstallId,
    load: ProvisioningLoadId,
    envelope_commitment: [u8; 32],
) -> Result<Retry, ProvisioningSecretStoreError> {
    if record.phase != InstallPhase::Complete {
        return Err(ProvisioningSecretStoreError::Unavailable);
    }
    if record.install != operation
        || record.load != load
        || record.envelope_commitment != envelope_commitment
    {
        return Err(ProvisioningSecretStoreError::OperationConflict);
    }
    Ok(Retry::Existing)
}

fn read_array<const N: usize>(bytes: &[u8]) -> Result<[u8; N], ProvisioningSecretStoreError> {
    bytes
        .try_into()
        .map_err(|_| ProvisioningSecretStoreError::Rejected)
}

fn read_u16(bytes: &[u8]) -> Result<u16, ProvisioningSecretStoreError> {
    read_array(bytes).map(u16::from_be_bytes)
}

fn read_u32(bytes: &[u8]) -> Result<u32, ProvisioningSecretStoreError> {
    read_array(bytes).map(u32::from_be_bytes)
}

fn read_u64(bytes: &[u8]) -> Result<u64, ProvisioningSecretStoreError> {
    read_array(bytes).map(u64::from_be_bytes)
}

#[cfg(test)]
mod tests {
    use super::{InstallPhase, InstallRecord, Retry, classify_retry, decode_record, encode_record};
    use crate::{PROVIDER_REFERENCE_ID_BYTES, provisioning_secret_ref};
    use aster_mesh::{ProvisioningInstallId, ProvisioningLoadId, ProvisioningSecretStoreError};

    const INSTALL: ProvisioningInstallId = ProvisioningInstallId::new([0x11; 32]);
    const LOAD: ProvisioningLoadId = ProvisioningLoadId::new([0x22; 32]);

    fn fixture_record(phase: InstallPhase) -> InstallRecord {
        InstallRecord {
            phase,
            install: INSTALL,
            load: LOAD,
            secret_ref: provisioning_secret_ref(1, [0x33; PROVIDER_REFERENCE_ID_BYTES])
                .expect("fixture reference"),
            generation: 1,
            envelope_commitment: [0x44; 32],
            ciphertext_digest: [0x55; 32],
        }
    }

    #[test]
    fn ledger_round_trip_preserves_exact_install_binding() {
        // Break caught: a ledger codec that loses or rewrites any binding can
        // replay an install against the wrong operation, reference, or bytes.
        for phase in [InstallPhase::Intent, InstallPhase::Complete] {
            let record = fixture_record(phase);
            assert_eq!(
                decode_record(&encode_record(&record)).expect("canonical record"),
                record
            );
        }
    }

    #[test]
    fn exact_retry_is_existing_and_changed_input_conflicts() {
        // Break caught: comparing only the operation ID would treat changed
        // provisioning plaintext or a changed startup load as an exact retry.
        let record = fixture_record(InstallPhase::Complete);
        assert_eq!(
            classify_retry(
                &record,
                record.install,
                record.load,
                record.envelope_commitment,
            )
            .expect("exact retry"),
            Retry::Existing
        );
        assert_eq!(
            classify_retry(&record, record.install, record.load, [0x66; 32])
                .expect_err("changed input"),
            ProvisioningSecretStoreError::OperationConflict
        );
        assert_eq!(
            classify_retry(
                &record,
                record.install,
                ProvisioningLoadId::new([0x77; 32]),
                record.envelope_commitment,
            )
            .expect_err("changed load"),
            ProvisioningSecretStoreError::OperationConflict
        );
    }

    #[test]
    fn ledger_rejects_noncanonical_or_cross_generation_records() {
        // Break caught: accepting partial, extended, or cross-generation
        // records would let corrupt durable state select the wrong credential.
        let record = fixture_record(InstallPhase::Complete);
        let canonical = encode_record(&record);
        assert_eq!(&canonical[..8], b"ASTRSDL1");
        assert_eq!(&canonical[8..10], &1_u16.to_be_bytes());
        assert_eq!(canonical[10], 2);
        assert_eq!(canonical[11], 0);
        assert_eq!(&canonical[12..20], &1_u64.to_be_bytes());

        let mut cases = Vec::new();
        let mut wrong_magic = canonical.clone();
        wrong_magic[0] ^= 1;
        cases.push(wrong_magic);
        let mut wrong_version = canonical.clone();
        wrong_version[9] = 2;
        cases.push(wrong_version);
        let mut wrong_phase = canonical.clone();
        wrong_phase[10] = 3;
        cases.push(wrong_phase);
        let mut reserved = canonical.clone();
        reserved[11] = 1;
        cases.push(reserved);
        let mut zero_generation = canonical.clone();
        zero_generation[12..20].fill(0);
        cases.push(zero_generation);
        let mut truncated = canonical.clone();
        truncated.pop();
        cases.push(truncated);
        let mut trailing = canonical.clone();
        trailing.push(0);
        cases.push(trailing);

        for encoded in cases {
            assert_eq!(
                decode_record(&encoded).expect_err("noncanonical ledger"),
                ProvisioningSecretStoreError::Rejected
            );
        }

        let mut cross_generation = record;
        cross_generation.secret_ref =
            provisioning_secret_ref(2, [0x33; PROVIDER_REFERENCE_ID_BYTES])
                .expect("second generation reference");
        assert_eq!(
            decode_record(&encode_record(&cross_generation))
                .expect_err("cross-generation reference"),
            ProvisioningSecretStoreError::Rejected
        );
    }
}
