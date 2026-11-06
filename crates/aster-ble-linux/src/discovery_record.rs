use bluer::l2cap::{PSM_LE_DYN_START, PSM_LE_MAX};
use hmac::{Hmac, KeyInit, Mac};
use sha2::Sha256;
use std::{fmt, num::NonZeroU32, time::Instant};
use subtle::ConstantTimeEq;
use zeroize::{Zeroize, ZeroizeOnDrop};

/// Canonical private UUID bytes for the rostered LE L2CAP carrier.
pub const ASTER_ROSTER_SERVICE_UUID: [u8; 16] = [
    0x6a, 0xa1, 0xcf, 0xed, 0x2c, 0xe3, 0x46, 0xd4, 0x9c, 0x69, 0xa3, 0x3d, 0x1d, 0xd5, 0x4e, 0xe5,
];
/// Exact encoded size of one revision-one roster beacon.
pub const ASTER_ROSTER_BEACON_V1_BYTES: usize = 40;

const REVISION: u8 = 1;
const SESSION_COC_AVAILABLE: u8 = 1;
const HEADER_BYTES: usize = 24;
const PROOF_BYTES: usize = 16;
const PROOF_DOMAIN: &[u8] = b"aster/ble-l2cap/rostered-discovery/v1\0";

/// Closed discovery-credential construction failures.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DiscoveryCredentialError {
    /// Generation zero is reserved.
    ZeroGeneration,
    /// An all-zero generation secret is forbidden.
    ZeroSecret,
    /// Emitting and overlap entries must have distinct generations.
    DuplicateGeneration,
}

/// Nonzero deployment-local discovery credential generation.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct DiscoveryGeneration(NonZeroU32);

impl DiscoveryGeneration {
    /// Validates a wire generation number.
    pub fn new(value: u32) -> Result<Self, DiscoveryCredentialError> {
        NonZeroU32::new(value)
            .map(Self)
            .ok_or(DiscoveryCredentialError::ZeroGeneration)
    }

    /// Returns the nonzero wire value.
    pub const fn get(self) -> u32 {
        self.0.get()
    }
}

/// Zeroize-on-drop 32-byte discovery proof secret.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct DiscoverySecret([u8; 32]);

impl DiscoverySecret {
    /// Adopts a provisioned random secret, rejecting the reserved zero value.
    pub fn new(bytes: [u8; 32]) -> Result<Self, DiscoveryCredentialError> {
        if bytes == [0; 32] {
            return Err(DiscoveryCredentialError::ZeroSecret);
        }
        Ok(Self(bytes))
    }

    fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl fmt::Debug for DiscoverySecret {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("[REDACTED]")
    }
}

/// One generation-to-secret binding held by a leased credential set.
pub struct DiscoveryCredential {
    generation: DiscoveryGeneration,
    secret: DiscoverySecret,
}

impl DiscoveryCredential {
    /// Binds an already-validated generation and secret.
    pub const fn new(generation: DiscoveryGeneration, secret: DiscoverySecret) -> Self {
        Self { generation, secret }
    }

    /// Returns the non-secret generation.
    pub const fn generation(&self) -> DiscoveryGeneration {
        self.generation
    }
}

impl fmt::Debug for DiscoveryCredential {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("DiscoveryCredential")
            .field("generation", &self.generation)
            .field("secret", &self.secret)
            .finish()
    }
}

/// Short-lived emitting and optional overlap discovery credentials.
pub struct LeasedDiscoveryCredentialSet {
    emitting: DiscoveryCredential,
    overlap: Option<DiscoveryCredential>,
    expires_at: Instant,
}

impl LeasedDiscoveryCredentialSet {
    /// Constructs one adapter lease with distinct active generations.
    pub fn new(
        emitting: DiscoveryCredential,
        overlap: Option<DiscoveryCredential>,
        expires_at: Instant,
    ) -> Result<Self, DiscoveryCredentialError> {
        if overlap
            .as_ref()
            .is_some_and(|entry| entry.generation == emitting.generation)
        {
            return Err(DiscoveryCredentialError::DuplicateGeneration);
        }
        Ok(Self {
            emitting,
            overlap,
            expires_at,
        })
    }

    /// Emitting generation number, without exposing its secret.
    pub const fn emitting_generation(&self) -> DiscoveryGeneration {
        self.emitting.generation
    }

    /// Lease expiry on the authority's checked monotonic clock.
    pub const fn expires_at(&self) -> Instant {
        self.expires_at
    }

    fn emitting(&self, now: Instant) -> Result<&DiscoveryCredential, DiscoveryRecordError> {
        self.ensure_live(now)?;
        Ok(&self.emitting)
    }

    fn credential(
        &self,
        generation: DiscoveryGeneration,
        now: Instant,
    ) -> Result<&DiscoveryCredential, DiscoveryRecordError> {
        self.ensure_live(now)?;
        if self.emitting.generation == generation {
            return Ok(&self.emitting);
        }
        self.overlap
            .as_ref()
            .filter(|entry| entry.generation == generation)
            .ok_or(DiscoveryRecordError::UnknownGeneration)
    }

    fn ensure_live(&self, now: Instant) -> Result<(), DiscoveryRecordError> {
        if now >= self.expires_at {
            return Err(DiscoveryRecordError::CredentialExpired);
        }
        Ok(())
    }
}

impl fmt::Debug for LeasedDiscoveryCredentialSet {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("LeasedDiscoveryCredentialSet")
            .field("emitting", &self.emitting)
            .field("overlap", &self.overlap)
            .field("expires_at", &self.expires_at)
            .finish()
    }
}

/// Closed roster-beacon validation failures.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DiscoveryRecordError {
    /// Encoded record is not exactly 40 bytes.
    WrongLength,
    /// Carrier record revision is unsupported.
    UnsupportedRevision,
    /// A reserved flags bit is nonzero.
    ReservedFlags,
    /// Required CoC availability is absent.
    Unavailable,
    /// Listener PSM is outside the dynamic LE range.
    InvalidPsm,
    /// Credential generation is zero or not active.
    UnknownGeneration,
    /// Credential lease is no longer live.
    CredentialExpired,
    /// Truncated HMAC proof did not verify.
    InvalidProof,
}

/// Authenticated, transient roster-beacon fields.
#[derive(Clone, Copy, Eq, PartialEq)]
pub struct AsterRosterBeaconV1 {
    listener_psm: u16,
    generation: DiscoveryGeneration,
    nonce: [u8; 16],
}

impl AsterRosterBeaconV1 {
    /// Encodes the current emitting generation into the frozen 40-byte record.
    pub fn encode(
        listener_psm: u16,
        nonce: [u8; 16],
        credentials: &LeasedDiscoveryCredentialSet,
        now: Instant,
    ) -> Result<[u8; ASTER_ROSTER_BEACON_V1_BYTES], DiscoveryRecordError> {
        let emitting = credentials.emitting(now)?;
        Self::encode_with_generation(listener_psm, nonce, emitting.generation, &emitting.secret)
    }

    fn encode_with_generation(
        listener_psm: u16,
        nonce: [u8; 16],
        generation: DiscoveryGeneration,
        secret: &DiscoverySecret,
    ) -> Result<[u8; ASTER_ROSTER_BEACON_V1_BYTES], DiscoveryRecordError> {
        validate_psm(listener_psm)?;
        let mut record = [0_u8; ASTER_ROSTER_BEACON_V1_BYTES];
        record[0] = REVISION;
        record[1] = SESSION_COC_AVAILABLE;
        record[2..4].copy_from_slice(&listener_psm.to_be_bytes());
        record[4..8].copy_from_slice(&generation.get().to_be_bytes());
        record[8..HEADER_BYTES].copy_from_slice(&nonce);
        let proof = proof_tag(secret, &record[..HEADER_BYTES]);
        record[HEADER_BYTES..].copy_from_slice(&proof);
        Ok(record)
    }

    /// Parses, structurally validates, and authenticates one complete record.
    pub fn decode_and_verify(
        record: &[u8],
        credentials: &LeasedDiscoveryCredentialSet,
        now: Instant,
    ) -> Result<Self, DiscoveryRecordError> {
        if record.len() != ASTER_ROSTER_BEACON_V1_BYTES {
            return Err(DiscoveryRecordError::WrongLength);
        }
        if record[0] != REVISION {
            return Err(DiscoveryRecordError::UnsupportedRevision);
        }
        if record[1] & !SESSION_COC_AVAILABLE != 0 {
            return Err(DiscoveryRecordError::ReservedFlags);
        }
        if record[1] & SESSION_COC_AVAILABLE == 0 {
            return Err(DiscoveryRecordError::Unavailable);
        }
        let listener_psm = u16::from_be_bytes([record[2], record[3]]);
        validate_psm(listener_psm)?;
        let generation = DiscoveryGeneration::new(u32::from_be_bytes([
            record[4], record[5], record[6], record[7],
        ]))
        .map_err(|_| DiscoveryRecordError::UnknownGeneration)?;
        let credential = credentials.credential(generation, now)?;
        let expected = proof_tag(&credential.secret, &record[..HEADER_BYTES]);
        let supplied: &[u8; PROOF_BYTES] = record[HEADER_BYTES..]
            .try_into()
            .map_err(|_| DiscoveryRecordError::WrongLength)?;
        if !bool::from(expected.ct_eq(supplied)) {
            return Err(DiscoveryRecordError::InvalidProof);
        }
        let mut nonce = [0_u8; 16];
        nonce.copy_from_slice(&record[8..HEADER_BYTES]);
        Ok(Self {
            listener_psm,
            generation,
            nonce,
        })
    }

    /// Transient listener PSM authenticated by the proof.
    pub const fn listener_psm(self) -> u16 {
        self.listener_psm
    }

    /// Credential generation that authenticated this record.
    pub const fn generation(self) -> DiscoveryGeneration {
        self.generation
    }

    /// Replay token nonce.
    pub const fn nonce(self) -> [u8; 16] {
        self.nonce
    }
}

impl fmt::Debug for AsterRosterBeaconV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AsterRosterBeaconV1")
            .field("generation", &self.generation)
            .field("transient", &"[REDACTED]")
            .finish()
    }
}

fn validate_psm(listener_psm: u16) -> Result<(), DiscoveryRecordError> {
    if !(PSM_LE_DYN_START..=PSM_LE_MAX).contains(&listener_psm) {
        return Err(DiscoveryRecordError::InvalidPsm);
    }
    Ok(())
}

fn proof_tag(secret: &DiscoverySecret, header: &[u8]) -> [u8; PROOF_BYTES] {
    let mut mac = <Hmac<Sha256> as KeyInit>::new_from_slice(secret.as_bytes())
        .expect("SHA-256 HMAC accepts every 32-byte key");
    mac.update(PROOF_DOMAIN);
    mac.update(&ASTER_ROSTER_SERVICE_UUID);
    mac.update(header);
    let output = mac.finalize().into_bytes();
    let mut tag = [0_u8; PROOF_BYTES];
    tag.copy_from_slice(&output[..PROOF_BYTES]);
    tag
}

#[cfg(test)]
fn hmac_sha256(key: &[u8], message: &[u8]) -> [u8; 32] {
    let mut mac =
        <Hmac<Sha256> as KeyInit>::new_from_slice(key).expect("HMAC accepts keys of every length");
    mac.update(message);
    mac.finalize().into_bytes().into()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{Duration, Instant};

    const SECRET_BYTES: [u8; 32] = [
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e,
        0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d,
        0x1e, 0x1f,
    ];
    const NONCE: [u8; 16] = [
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e,
        0x0f,
    ];
    const EXPECTED_RECORD: [u8; 40] = [
        0x01, 0x01, 0x00, 0x81, 0x00, 0x00, 0x00, 0x07, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06,
        0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x5f, 0xb8, 0x96, 0xd4, 0x78, 0x3e,
        0xc8, 0x29, 0xc7, 0xc9, 0x75, 0x29, 0x6c, 0xa1, 0xc4, 0x39,
    ];

    fn credentials(overlap: Option<(u32, [u8; 32])>) -> (LeasedDiscoveryCredentialSet, Instant) {
        let now = Instant::now();
        let emitting = DiscoveryCredential::new(
            DiscoveryGeneration::new(7).unwrap(),
            DiscoverySecret::new(SECRET_BYTES).unwrap(),
        );
        let overlap = overlap.map(|(generation, secret)| {
            DiscoveryCredential::new(
                DiscoveryGeneration::new(generation).unwrap(),
                DiscoverySecret::new(secret).unwrap(),
            )
        });
        (
            LeasedDiscoveryCredentialSet::new(emitting, overlap, now + Duration::from_secs(30))
                .unwrap(),
            now,
        )
    }

    #[test]
    fn discovery_record_rfc_4231_hmac_sanity_vector() {
        let key = [0x0b; 20];
        assert_eq!(
            hmac_sha256(&key, b"Hi There"),
            [
                0xb0, 0x34, 0x4c, 0x61, 0xd8, 0xdb, 0x38, 0x53, 0x5c, 0xa8, 0xaf, 0xce, 0xaf, 0x0b,
                0xf1, 0x2b, 0x88, 0x1d, 0xc2, 0x00, 0xc9, 0x83, 0x3d, 0xa7, 0x26, 0xe9, 0x37, 0x6c,
                0x2e, 0x32, 0xcf, 0xf7,
            ]
        );
    }

    #[test]
    fn discovery_record_matches_frozen_independent_vector() {
        let (credentials, now) = credentials(None);
        let encoded = AsterRosterBeaconV1::encode(0x0081, NONCE, &credentials, now).unwrap();
        assert_eq!(encoded, EXPECTED_RECORD);
        assert_eq!(
            include_str!("../tests/fixtures/roster_beacon_v1.txt").trim(),
            "0101008100000007000102030405060708090a0b0c0d0e0f5fb896d4783ec829c7c975296ca1c439"
        );

        let decoded = AsterRosterBeaconV1::decode_and_verify(&encoded, &credentials, now).unwrap();
        assert_eq!(decoded.listener_psm(), 0x0081);
        assert_eq!(decoded.generation().get(), 7);
        assert_eq!(decoded.nonce(), NONCE);
    }

    #[test]
    fn discovery_record_verifies_emitting_and_overlap_generations() {
        let overlap_secret = [0x55; 32];
        let (credentials, now) = credentials(Some((8, overlap_secret)));
        let emitting = AsterRosterBeaconV1::encode(0x0081, NONCE, &credentials, now).unwrap();
        assert!(AsterRosterBeaconV1::decode_and_verify(&emitting, &credentials, now).is_ok());

        let overlap = AsterRosterBeaconV1::encode_with_generation(
            0x0081,
            NONCE,
            DiscoveryGeneration::new(8).unwrap(),
            &DiscoverySecret::new(overlap_secret).unwrap(),
        )
        .unwrap();
        assert!(AsterRosterBeaconV1::decode_and_verify(&overlap, &credentials, now).is_ok());
    }

    #[test]
    fn discovery_record_rejects_every_structural_and_proof_class() {
        let (credentials, now) = credentials(None);
        let valid = AsterRosterBeaconV1::encode(0x0081, NONCE, &credentials, now).unwrap();

        assert_eq!(
            AsterRosterBeaconV1::decode_and_verify(&valid[..39], &credentials, now).unwrap_err(),
            DiscoveryRecordError::WrongLength
        );
        let mut oversized = valid.to_vec();
        oversized.push(0);
        assert_eq!(
            AsterRosterBeaconV1::decode_and_verify(&oversized, &credentials, now).unwrap_err(),
            DiscoveryRecordError::WrongLength
        );

        for (offset, value, expected) in [
            (0, 2, DiscoveryRecordError::UnsupportedRevision),
            (1, 3, DiscoveryRecordError::ReservedFlags),
            (1, 0, DiscoveryRecordError::Unavailable),
        ] {
            let mut invalid = valid;
            invalid[offset] = value;
            assert_eq!(
                AsterRosterBeaconV1::decode_and_verify(&invalid, &credentials, now).unwrap_err(),
                expected
            );
        }

        for psm in [0_u16, bluer::l2cap::PSM_LE_DYN_START - 1] {
            let mut invalid = valid;
            invalid[2..4].copy_from_slice(&psm.to_be_bytes());
            assert_eq!(
                AsterRosterBeaconV1::decode_and_verify(&invalid, &credentials, now).unwrap_err(),
                DiscoveryRecordError::InvalidPsm
            );
        }

        let mut zero_generation = valid;
        zero_generation[4..8].fill(0);
        assert_eq!(
            AsterRosterBeaconV1::decode_and_verify(&zero_generation, &credentials, now)
                .unwrap_err(),
            DiscoveryRecordError::UnknownGeneration
        );

        let mut unknown_generation = valid;
        unknown_generation[4..8].copy_from_slice(&9_u32.to_be_bytes());
        assert_eq!(
            AsterRosterBeaconV1::decode_and_verify(&unknown_generation, &credentials, now)
                .unwrap_err(),
            DiscoveryRecordError::UnknownGeneration
        );

        for offset in 2..24 {
            let mut mutated = valid;
            mutated[offset] ^= 1;
            let result = AsterRosterBeaconV1::decode_and_verify(&mutated, &credentials, now);
            assert!(
                matches!(
                    result,
                    Err(DiscoveryRecordError::InvalidPsm
                        | DiscoveryRecordError::UnknownGeneration
                        | DiscoveryRecordError::InvalidProof)
                ),
                "authenticated header mutation at {offset} was accepted"
            );
        }

        let mut bad_tag = valid;
        bad_tag[39] ^= 1;
        assert_eq!(
            AsterRosterBeaconV1::decode_and_verify(&bad_tag, &credentials, now).unwrap_err(),
            DiscoveryRecordError::InvalidProof
        );

        assert_eq!(
            AsterRosterBeaconV1::decode_and_verify(
                &valid,
                &credentials,
                now + Duration::from_secs(31),
            )
            .unwrap_err(),
            DiscoveryRecordError::CredentialExpired
        );
    }

    #[test]
    fn discovery_record_accepts_maximum_dynamic_psm() {
        let (credentials, now) = credentials(None);
        let record =
            AsterRosterBeaconV1::encode(bluer::l2cap::PSM_LE_MAX, NONCE, &credentials, now)
                .unwrap();
        assert_eq!(
            AsterRosterBeaconV1::decode_and_verify(&record, &credentials, now)
                .unwrap()
                .listener_psm(),
            bluer::l2cap::PSM_LE_MAX
        );
    }

    #[test]
    fn discovery_credentials_reject_invalid_values_and_redact_debug() {
        assert!(DiscoveryGeneration::new(0).is_err());
        assert!(DiscoverySecret::new([0; 32]).is_err());

        let (credentials, _) = credentials(None);
        let debug = format!("{credentials:?}");
        assert!(debug.contains("[REDACTED]"));
        assert!(!debug.contains("00010203"));
        assert!(!debug.contains("listener_psm"));

        let duplicate = DiscoveryCredential::new(
            DiscoveryGeneration::new(7).unwrap(),
            DiscoverySecret::new([9; 32]).unwrap(),
        );
        let emitting = DiscoveryCredential::new(
            DiscoveryGeneration::new(7).unwrap(),
            DiscoverySecret::new(SECRET_BYTES).unwrap(),
        );
        assert!(
            LeasedDiscoveryCredentialSet::new(
                emitting,
                Some(duplicate),
                Instant::now() + Duration::from_secs(1),
            )
            .is_err()
        );
    }
}
