//! Canonical semantic-v9 Blob custody claims and linear record capabilities.

use crate::{
    BlobCustodyDirectionV1, BlobCustodyError, BlobCustodyTransferId, BlobId,
    ContentVerifiedBlobEnvelope, CustodySample, Priority,
};
use sha2::{Digest, Sha256};

pub const BLOB_CUSTODY_CLAIM_V2_BYTES: usize = 208;

const MAGIC: &[u8; 8] = b"ASTRBL09";
const FORMAT_VERSION: u16 = 2;
const SEMANTIC_VERSION: u16 = 9;
const PROFILE_ID: u16 = 5;
const BLOB_LANE_ID: u16 = 4;
const V9_LANE_RECORD_DOMAIN: &[u8] = b"ASTER/v9-lane-record/v1\0";
const CONTACT_ID_DOMAIN: &[u8] = b"ASTER/v9-blob-custody-contact/v2\0";

/// Exact authenticated context of one semantic-v9 application record.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ApplicationRecordContext {
    semantic_version: u16,
    transfer_profile_digest: [u8; 32],
    lane: u16,
    profile: u16,
    direction: BlobCustodyDirectionV1,
    attempt_nonce: [u8; 32],
    record_sequence: u64,
}

impl ApplicationRecordContext {
    pub fn new_v9_blob(
        transfer_profile_digest: [u8; 32],
        direction: BlobCustodyDirectionV1,
        attempt_nonce: [u8; 32],
        record_sequence: u64,
    ) -> Result<Self, BlobCustodyError> {
        if attempt_nonce.iter().all(|byte| *byte == 0) {
            return Err(BlobCustodyError::ContextMismatch);
        }
        Ok(Self {
            semantic_version: SEMANTIC_VERSION,
            transfer_profile_digest,
            lane: BLOB_LANE_ID,
            profile: PROFILE_ID,
            direction,
            attempt_nonce,
            record_sequence,
        })
    }

    pub fn aad(&self) -> Vec<u8> {
        let mut aad = Vec::with_capacity(V9_LANE_RECORD_DOMAIN.len() + 79);
        aad.extend_from_slice(V9_LANE_RECORD_DOMAIN);
        aad.extend_from_slice(&self.semantic_version.to_be_bytes());
        aad.extend_from_slice(&self.transfer_profile_digest);
        aad.extend_from_slice(&self.lane.to_be_bytes());
        aad.extend_from_slice(&self.profile.to_be_bytes());
        aad.push(self.direction as u8);
        aad.extend_from_slice(&self.attempt_nonce);
        aad.extend_from_slice(&self.record_sequence.to_be_bytes());
        aad
    }

    pub const fn semantic_version(&self) -> u16 {
        self.semantic_version
    }
    pub const fn transfer_profile_digest(&self) -> [u8; 32] {
        self.transfer_profile_digest
    }
    pub const fn lane(&self) -> u16 {
        self.lane
    }
    pub const fn profile(&self) -> u16 {
        self.profile
    }
    pub const fn direction(&self) -> BlobCustodyDirectionV1 {
        self.direction
    }
    pub const fn attempt_nonce(&self) -> [u8; 32] {
        self.attempt_nonce
    }
    pub const fn record_sequence(&self) -> u64 {
        self.record_sequence
    }
}

/// Non-clone proof that one v9/profile-5 record was authenticated and replay checked.
#[derive(Debug, Eq, PartialEq)]
pub struct AuthenticatedBlobCustodyContactV2 {
    session_transcript: [u8; 32],
    context: ApplicationRecordContext,
    claim_digest: [u8; 32],
    contact_identity: [u8; 32],
}

impl AuthenticatedBlobCustodyContactV2 {
    pub(crate) fn from_opened_record(
        session_transcript: [u8; 32],
        context: ApplicationRecordContext,
        claim_digest: [u8; 32],
    ) -> Self {
        let mut hasher = Sha256::new();
        hasher.update(CONTACT_ID_DOMAIN);
        hasher.update(session_transcript);
        hasher.update(context.aad());
        hasher.update(claim_digest);
        Self {
            session_transcript,
            context,
            claim_digest,
            contact_identity: hasher.finalize().into(),
        }
    }

    pub const fn session_transcript(&self) -> [u8; 32] {
        self.session_transcript
    }
    pub const fn context(&self) -> ApplicationRecordContext {
        self.context
    }
    pub const fn claim_digest(&self) -> [u8; 32] {
        self.claim_digest
    }
    pub const fn contact_identity(&self) -> [u8; 32] {
        self.contact_identity
    }
}

/// Non-clone outbound authority minted from one authenticated v9/profile-5 record.
#[derive(Debug, Eq, PartialEq)]
pub struct AuthenticatedBlobCustodySendContextV2 {
    session_transcript: [u8; 32],
    exchange_id: u64,
    context: ApplicationRecordContext,
    finalization_charge_ms: u64,
}

impl AuthenticatedBlobCustodySendContextV2 {
    pub(crate) const fn from_authenticated_record(
        session_transcript: [u8; 32],
        exchange_id: u64,
        context: ApplicationRecordContext,
        finalization_charge_ms: u64,
    ) -> Self {
        Self {
            session_transcript,
            exchange_id,
            context,
            finalization_charge_ms,
        }
    }

    pub const fn session_transcript(&self) -> [u8; 32] {
        self.session_transcript
    }
    pub const fn exchange_id(&self) -> u64 {
        self.exchange_id
    }
    pub const fn context(&self) -> ApplicationRecordContext {
        self.context
    }
    pub const fn finalization_charge_ms(&self) -> u64 {
        self.finalization_charge_ms
    }
}

/// Canonically decoded, not-yet-authoritative v9 custody claim.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BlobCustodyClaimV2 {
    session_transcript: [u8; 32],
    exchange_id: u64,
    direction: BlobCustodyDirectionV1,
    source_transfer_id: BlobCustodyTransferId,
    source_len: u64,
    publication_id: [u8; 32],
    blob_id: BlobId,
    priority: Priority,
    ttl_ms: u64,
    prior_cumulative_age_ms: u64,
    sender_sample: CustodySample,
    hop_delta_ms: u64,
    forwarding_age_ms: u64,
}

impl BlobCustodyClaimV2 {
    #[allow(clippy::too_many_arguments)]
    pub fn from_authenticated_source(
        authority: AuthenticatedBlobCustodySendContextV2,
        source_transfer_id: BlobCustodyTransferId,
        source: &ContentVerifiedBlobEnvelope,
        exact_source_bytes: &[u8],
        prior_cumulative_age_ms: u64,
        sender_sample: CustodySample,
    ) -> Result<Self, BlobCustodyError> {
        source
            .verify_exact_sealed(exact_source_bytes)
            .map_err(|_| BlobCustodyError::ContextMismatch)?;
        if source_transfer_id.as_bytes() != &source.envelope_id() {
            return Err(BlobCustodyError::ContextMismatch);
        }
        let source_len =
            u64::try_from(exact_source_bytes.len()).map_err(|_| BlobCustodyError::InvalidClaim)?;
        let ttl_ms = source.ttl_ms().ok_or(BlobCustodyError::InvalidClaim)?;
        if source_len == 0 || ttl_ms == 0 {
            return Err(BlobCustodyError::InvalidClaim);
        }
        Self::from_authenticated_profile5_source(
            authority,
            source_transfer_id,
            source_len,
            source.item_id(),
            source.blob_id(),
            source.priority(),
            ttl_ms,
            prior_cumulative_age_ms,
            sender_sample,
        )
    }

    /// Constructs a custody claim for the native Profile-5 source grammar.
    /// The caller must hold the unforgeable session authority and must have
    /// already authenticated the signed stream open and retained pack source.
    #[allow(clippy::too_many_arguments)]
    pub fn from_authenticated_profile5_source(
        authority: AuthenticatedBlobCustodySendContextV2,
        source_transfer_id: BlobCustodyTransferId,
        source_len: u64,
        publication_id: [u8; 32],
        blob_id: BlobId,
        priority: Priority,
        ttl_ms: u64,
        prior_cumulative_age_ms: u64,
        sender_sample: CustodySample,
    ) -> Result<Self, BlobCustodyError> {
        if source_len == 0 || publication_id == [0; 32] || ttl_ms == 0 {
            return Err(BlobCustodyError::InvalidClaim);
        }
        let hop_delta_ms = authority.finalization_charge_ms;
        let forwarding_age_ms = prior_cumulative_age_ms
            .checked_add(hop_delta_ms)
            .ok_or(BlobCustodyError::AgeOverflow)?;
        Ok(Self {
            session_transcript: authority.session_transcript,
            exchange_id: authority.exchange_id,
            direction: authority.context.direction,
            source_transfer_id,
            source_len,
            publication_id,
            blob_id,
            priority,
            ttl_ms,
            prior_cumulative_age_ms,
            sender_sample,
            hop_delta_ms,
            forwarding_age_ms,
        })
    }

    #[allow(clippy::too_many_arguments)]
    pub fn verify_authenticated_source(
        &self,
        contact: AuthenticatedBlobCustodyContactV2,
        exchange_id: u64,
        source_transfer_id: BlobCustodyTransferId,
        source: &ContentVerifiedBlobEnvelope,
        exact_source_bytes: &[u8],
        minimum_cumulative_age_ms: u64,
    ) -> Result<VerifiedBlobCustodyClaimV2, BlobCustodyError> {
        source
            .verify_exact_sealed(exact_source_bytes)
            .map_err(|_| BlobCustodyError::ContextMismatch)?;
        let expected_len =
            u64::try_from(exact_source_bytes.len()).map_err(|_| BlobCustodyError::InvalidClaim)?;
        self.verify_authenticated_profile5_source(
            contact,
            exchange_id,
            source_transfer_id,
            expected_len,
            source.item_id(),
            source.blob_id(),
            source.priority(),
            source.ttl_ms().ok_or(BlobCustodyError::InvalidClaim)?,
            minimum_cumulative_age_ms,
        )
    }

    /// Verifies custody against identities derived from a signed native
    /// Profile-5 open and final commitment.
    #[allow(clippy::too_many_arguments)]
    pub fn verify_authenticated_profile5_source(
        &self,
        contact: AuthenticatedBlobCustodyContactV2,
        exchange_id: u64,
        source_transfer_id: BlobCustodyTransferId,
        source_len: u64,
        publication_id: [u8; 32],
        blob_id: BlobId,
        priority: Priority,
        ttl_ms: u64,
        minimum_cumulative_age_ms: u64,
    ) -> Result<VerifiedBlobCustodyClaimV2, BlobCustodyError> {
        if contact.context.semantic_version != SEMANTIC_VERSION
            || contact.context.profile != PROFILE_ID
            || contact.context.lane != BLOB_LANE_ID
            || self.digest() != contact.claim_digest
            || self.session_transcript != contact.session_transcript
            || self.direction != contact.context.direction
            || self.exchange_id != exchange_id
            || self.source_transfer_id != source_transfer_id
            || source_len == 0
            || publication_id == [0; 32]
            || ttl_ms == 0
            || self.source_len != source_len
            || self.publication_id != publication_id
            || self.blob_id != blob_id
            || self.priority != priority
            || self.ttl_ms != ttl_ms
            || self.forwarding_age_ms < minimum_cumulative_age_ms
        {
            return Err(BlobCustodyError::ContextMismatch);
        }
        Ok(VerifiedBlobCustodyClaimV2 {
            claim: *self,
            digest: self.digest(),
            contact,
        })
    }

    pub fn decode(encoded: &[u8]) -> Result<Self, BlobCustodyError> {
        if encoded.len() != BLOB_CUSTODY_CLAIM_V2_BYTES {
            return Err(BlobCustodyError::InvalidClaim);
        }
        let mut reader = ClaimReader::new(encoded);
        if reader.take::<8>()? != *MAGIC
            || reader.u16()? != FORMAT_VERSION
            || reader.u16()? != SEMANTIC_VERSION
            || reader.u16()? != PROFILE_ID
        {
            return Err(BlobCustodyError::InvalidClaim);
        }
        let session_transcript = reader.take::<32>()?;
        let exchange_id = reader.u64()?;
        let direction = match reader.u8()? {
            1 => BlobCustodyDirectionV1::ToSessionInitiator,
            2 => BlobCustodyDirectionV1::ToSessionResponder,
            _ => return Err(BlobCustodyError::InvalidClaim),
        };
        let source_transfer_id = BlobCustodyTransferId::from_exact_hash(reader.take::<32>()?);
        let source_len = reader.u64()?;
        let publication_id = reader.take::<32>()?;
        let blob_id = BlobId::from_bytes(reader.take::<32>()?);
        let priority = Priority::from_wire(reader.u8()?).ok_or(BlobCustodyError::InvalidClaim)?;
        let ttl_ms = reader.u64()?;
        let prior_cumulative_age_ms = reader.u64()?;
        let sender_sample = CustodySample {
            clock_id: reader.take::<16>()?,
            tick_ms: reader.u64()?,
        };
        let hop_delta_ms = reader.u64()?;
        reader.finish()?;
        if source_len == 0 || ttl_ms == 0 {
            return Err(BlobCustodyError::InvalidClaim);
        }
        let forwarding_age_ms = prior_cumulative_age_ms
            .checked_add(hop_delta_ms)
            .ok_or(BlobCustodyError::AgeOverflow)?;
        Ok(Self {
            session_transcript,
            exchange_id,
            direction,
            source_transfer_id,
            source_len,
            publication_id,
            blob_id,
            priority,
            ttl_ms,
            prior_cumulative_age_ms,
            sender_sample,
            hop_delta_ms,
            forwarding_age_ms,
        })
    }

    pub fn encode(&self) -> [u8; BLOB_CUSTODY_CLAIM_V2_BYTES] {
        let mut output = [0u8; BLOB_CUSTODY_CLAIM_V2_BYTES];
        let mut offset = 0usize;
        macro_rules! append {
            ($bytes:expr) => {{
                let bytes = $bytes;
                let end = offset + bytes.len();
                output[offset..end].copy_from_slice(bytes);
                offset = end;
            }};
        }
        append!(MAGIC);
        append!(&FORMAT_VERSION.to_be_bytes());
        append!(&SEMANTIC_VERSION.to_be_bytes());
        append!(&PROFILE_ID.to_be_bytes());
        append!(&self.session_transcript);
        append!(&self.exchange_id.to_be_bytes());
        append!(&[self.direction as u8]);
        append!(self.source_transfer_id.as_bytes());
        append!(&self.source_len.to_be_bytes());
        append!(&self.publication_id);
        append!(self.blob_id.as_bytes());
        append!(&[self.priority as u8]);
        append!(&self.ttl_ms.to_be_bytes());
        append!(&self.prior_cumulative_age_ms.to_be_bytes());
        append!(&self.sender_sample.clock_id);
        append!(&self.sender_sample.tick_ms.to_be_bytes());
        append!(&self.hop_delta_ms.to_be_bytes());
        debug_assert_eq!(offset, BLOB_CUSTODY_CLAIM_V2_BYTES);
        output
    }

    pub fn digest(&self) -> [u8; 32] {
        Sha256::digest(self.encode()).into()
    }
    pub const fn session_transcript(&self) -> [u8; 32] {
        self.session_transcript
    }
    pub const fn exchange_id(&self) -> u64 {
        self.exchange_id
    }
    pub const fn direction(&self) -> BlobCustodyDirectionV1 {
        self.direction
    }
    pub const fn source_transfer_id(&self) -> BlobCustodyTransferId {
        self.source_transfer_id
    }
    pub const fn source_len(&self) -> u64 {
        self.source_len
    }
    pub const fn publication_id(&self) -> [u8; 32] {
        self.publication_id
    }
    pub const fn blob_id(&self) -> BlobId {
        self.blob_id
    }
    pub const fn priority(&self) -> Priority {
        self.priority
    }
    pub const fn ttl_ms(&self) -> u64 {
        self.ttl_ms
    }
    pub const fn prior_cumulative_age_ms(&self) -> u64 {
        self.prior_cumulative_age_ms
    }
    pub const fn sender_sample(&self) -> CustodySample {
        self.sender_sample
    }
    pub const fn hop_delta_ms(&self) -> u64 {
        self.hop_delta_ms
    }
    pub const fn forwarding_age_ms(&self) -> u64 {
        self.forwarding_age_ms
    }
}

#[derive(Debug, Eq, PartialEq)]
pub struct VerifiedBlobCustodyClaimV2 {
    claim: BlobCustodyClaimV2,
    digest: [u8; 32],
    contact: AuthenticatedBlobCustodyContactV2,
}
impl VerifiedBlobCustodyClaimV2 {
    pub const fn digest(&self) -> [u8; 32] {
        self.digest
    }
    pub const fn source_transfer_id(&self) -> BlobCustodyTransferId {
        self.claim.source_transfer_id
    }
    pub const fn source_len(&self) -> u64 {
        self.claim.source_len
    }
    pub const fn publication_id(&self) -> [u8; 32] {
        self.claim.publication_id
    }
    pub const fn blob_id(&self) -> BlobId {
        self.claim.blob_id
    }
    pub const fn priority(&self) -> Priority {
        self.claim.priority
    }
    pub const fn ttl_ms(&self) -> u64 {
        self.claim.ttl_ms
    }
    pub const fn forwarding_age_ms(&self) -> u64 {
        self.claim.forwarding_age_ms
    }
    pub const fn contact_identity(&self) -> [u8; 32] {
        self.contact.contact_identity
    }
}

struct ClaimReader<'a> {
    bytes: &'a [u8],
    offset: usize,
}
impl<'a> ClaimReader<'a> {
    const fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, offset: 0 }
    }
    fn take<const N: usize>(&mut self) -> Result<[u8; N], BlobCustodyError> {
        let end = self
            .offset
            .checked_add(N)
            .ok_or(BlobCustodyError::InvalidClaim)?;
        let value = self
            .bytes
            .get(self.offset..end)
            .ok_or(BlobCustodyError::InvalidClaim)?
            .try_into()
            .map_err(|_| BlobCustodyError::InvalidClaim)?;
        self.offset = end;
        Ok(value)
    }
    fn u8(&mut self) -> Result<u8, BlobCustodyError> {
        Ok(self.take::<1>()?[0])
    }
    fn u16(&mut self) -> Result<u16, BlobCustodyError> {
        Ok(u16::from_be_bytes(self.take::<2>()?))
    }
    fn u64(&mut self) -> Result<u64, BlobCustodyError> {
        Ok(u64::from_be_bytes(self.take::<8>()?))
    }
    fn finish(self) -> Result<(), BlobCustodyError> {
        (self.offset == self.bytes.len())
            .then_some(())
            .ok_or(BlobCustodyError::InvalidClaim)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    const MINIMUM_HEX: &str = "41535452424c30390002000900051111111111111111111111111111111111111111111111111111111111111111000000000000000001222222222222222222222222222222222222222222222222222222222222222200000000000000013333333333333333333333333333333333333333333333333333333333333333444444444444444444444444444444444444444444444444444444444444444400000000000000000100000000000000005555555555555555555555555555555500000000000000000000000000000000";
    fn literal_hex<const N: usize>(encoded: &str) -> [u8; N] {
        assert_eq!(encoded.len(), N * 2);
        let mut output = [0u8; N];
        for (index, byte) in output.iter_mut().enumerate() {
            *byte = u8::from_str_radix(&encoded[index * 2..index * 2 + 2], 16).unwrap();
        }
        output
    }

    #[test]
    fn blob_custody_v2_canonical_vector_is_exactly_208_bytes() {
        let encoded = literal_hex::<BLOB_CUSTODY_CLAIM_V2_BYTES>(MINIMUM_HEX);
        let claim = BlobCustodyClaimV2::decode(&encoded).expect("canonical v2 claim");
        assert_eq!(claim.encode(), encoded);
        assert_eq!(claim.forwarding_age_ms(), 0);
        assert_eq!(claim.source_len(), 1);
    }

    #[test]
    fn native_profile5_custody_binds_derived_source_identities() {
        let transcript = [0x11; 32];
        let nonce = [0x22; 32];
        let context = ApplicationRecordContext::new_v9_blob(
            [0x33; 32],
            BlobCustodyDirectionV1::ToSessionResponder,
            nonce,
            0,
        )
        .unwrap();
        let authority = AuthenticatedBlobCustodySendContextV2::from_authenticated_record(
            transcript, 1, context, 7,
        );
        let transfer = BlobCustodyTransferId::from_exact_hash([0x44; 32]);
        let publication = [0x55; 32];
        let blob = BlobId::from_bytes([0x66; 32]);
        let claim = BlobCustodyClaimV2::from_authenticated_profile5_source(
            authority,
            transfer,
            4096,
            publication,
            blob,
            Priority::Immediate,
            60_000,
            11,
            CustodySample {
                clock_id: [0x77; 16],
                tick_ms: 23,
            },
        )
        .unwrap();
        let contact = AuthenticatedBlobCustodyContactV2::from_opened_record(
            transcript,
            context,
            claim.digest(),
        );
        let verified = claim
            .verify_authenticated_profile5_source(
                contact,
                1,
                transfer,
                4096,
                publication,
                blob,
                Priority::Immediate,
                60_000,
                11,
            )
            .unwrap();
        assert_eq!(verified.forwarding_age_ms(), 18);
        assert_eq!(verified.publication_id(), publication);
        assert_eq!(verified.source_transfer_id(), transfer);
    }

    #[test]
    fn blob_custody_v2_rejects_v1_and_field_substitution() {
        let canonical = literal_hex::<BLOB_CUSTODY_CLAIM_V2_BYTES>(MINIMUM_HEX);
        for (offset, replacement) in [
            (7, b'8'),
            (9, 1),
            (11, 8),
            (13, 4),
            (54, 0),
            (54, 3),
            (159, 4),
        ] {
            let mut changed = canonical;
            changed[offset] = replacement;
            assert!(
                BlobCustodyClaimV2::decode(&changed).is_err(),
                "offset {offset}"
            );
        }
        assert!(BlobCustodyClaimV2::decode(&canonical[..207]).is_err());
        let mut overflow = canonical;
        overflow[168..176].copy_from_slice(&u64::MAX.to_be_bytes());
        overflow[200..208].copy_from_slice(&1u64.to_be_bytes());
        assert_eq!(
            BlobCustodyClaimV2::decode(&overflow),
            Err(BlobCustodyError::AgeOverflow)
        );
    }

    #[test]
    fn blob_custody_v2_record_context_binds_every_ordering_field() {
        let base = ApplicationRecordContext::new_v9_blob(
            [0x22; 32],
            BlobCustodyDirectionV1::ToSessionResponder,
            [0x33; 32],
            7,
        )
        .unwrap();
        assert!(
            ApplicationRecordContext::new_v9_blob(
                [0x22; 32],
                BlobCustodyDirectionV1::ToSessionResponder,
                [0; 32],
                7
            )
            .is_err()
        );
        let mut expected = b"ASTER/v9-lane-record/v1\0".to_vec();
        expected.extend_from_slice(&9u16.to_be_bytes());
        expected.extend_from_slice(&[0x22; 32]);
        expected.extend_from_slice(&4u16.to_be_bytes());
        expected.extend_from_slice(&5u16.to_be_bytes());
        expected.push(2);
        expected.extend_from_slice(&[0x33; 32]);
        expected.extend_from_slice(&7u64.to_be_bytes());
        assert_eq!(base.aad(), expected);
    }
}
