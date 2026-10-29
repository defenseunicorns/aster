//! Durable provisional application-Blob upload authority.

use super::pack::{
    BlobPackCheckpoint, BlobPackCompletion, BlobPackError, BlobPackIdentity, BlobPackReader,
    PinnedBlobPackRoot, remove_upload_pack,
};
use super::{
    BLOB_OPERATIONS, BLOB_PUBLICATIONS, BlobOperationOwner, BlobReservation, BlobReservationInputs,
    BlobStoreError, BlobTransferId, PUBLISHER_HIGH_WATER, Store, blob_error,
    blob_operation_owner_key, decode_blob_metadata, decode_blob_operation_record,
    synchronize_blob_policy_generation_write,
};
use crate::{
    CONTROL_SCOPE_EPOCHS, ControlPolicySnapshot, Priority, Scope, StoreError, Topic,
    control_principal_revoked_write, decode_scope_epoch_index, enforce_live_write,
    require_control_policy_write,
};
use aster_mesh::{
    BlobManifest, BlobMetadata, BlobPublicationStreamId, BlobStreamFinalCommitment,
    BlobStreamLineage, BlobStreamOpen, NodeId, VerifiedBlobCustodyClaimV2,
    VerifiedBlobStreamFinalCommitment, VerifiedBlobStreamOpen, VerifiedBlobStreamPublication,
    VerifiedBlobStreamPublicationSource, local_blob_publication_stream_id,
};
use redb::{Durability, ReadableDatabase, ReadableTable, ReadableTableMetadata, TableHandle};
use sha2::{Digest, Sha256};
use std::sync::Arc;

#[cfg(test)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum UploadFaultPoint {
    CheckpointBeforeCommit,
    ReservationIntentSynced,
    ReservationPackSynced,
}

#[cfg(test)]
static TEST_UPLOAD_FAULTS: std::sync::Mutex<Vec<(std::path::PathBuf, UploadFaultPoint)>> =
    std::sync::Mutex::new(Vec::new());

#[cfg(test)]
fn inject_test_fault(store: &Store, point: UploadFaultPoint) {
    TEST_UPLOAD_FAULTS
        .lock()
        .expect("upload test fault lock")
        .push((store.path.clone(), point));
}

#[cfg(test)]
fn maybe_inject_test_fault(store: &Store, point: UploadFaultPoint) -> Result<(), StoreError> {
    let mut faults = TEST_UPLOAD_FAULTS.lock().map_err(|_| schema_error())?;
    if let Some(index) = faults
        .iter()
        .position(|(path, expected)| path == &store.path && *expected == point)
    {
        faults.swap_remove(index);
        return Err(blob_error(BlobStoreError::Io(std::io::Error::other(
            "injected upload projection crash boundary",
        ))));
    }
    Ok(())
}

const UPLOAD_MAGIC: &[u8; 8] = b"ASTRUP01";
const LEGACY_UPLOAD_VERSION: u8 = 1;
const UPLOAD_VERSION: u8 = 2;
const PROFILE5_UPLOAD_VERSION: u8 = 4;
const UPLOAD_ID_DOMAIN: &[u8] = b"aster/blob-upload-id/v1\0";
const UPLOAD_REQUEST_DOMAIN: &[u8] = b"aster/blob-upload-request/v1\0";
const MAX_UPLOADS: u64 = super::MAX_BLOB_OPERATIONS;

enum Profile5PromotionLifetime {
    Local(Option<aster_mesh::CustodySample>),
    NetworkDurable,
    Network(super::VerifiedFiniteBlobAdmission),
}

/// Authenticated finite-lifetime authority for one received Profile-5 pack
/// promotion. Keeping the verified claim and both receiver-local samples
/// together prevents call sites from reordering lifetime inputs.
#[doc(hidden)]
pub struct ReceivedProfile5FinitePromotion {
    verified: VerifiedBlobCustodyClaimV2,
    received_sample: aster_mesh::CustodySample,
    promotion_sample: aster_mesh::CustodySample,
}

impl ReceivedProfile5FinitePromotion {
    pub const fn new(
        verified: VerifiedBlobCustodyClaimV2,
        received_sample: aster_mesh::CustodySample,
        promotion_sample: aster_mesh::CustodySample,
    ) -> Self {
        Self {
            verified,
            received_sample,
            promotion_sample,
        }
    }
}

type Profile5OpenBuilder<'a> = dyn FnMut(&BlobReservation, Option<&DurableProfile5Open>) -> Result<DurableProfile5Open, StoreError>
    + 'a;
type Profile5Reservation<'a> = (
    Option<aster_mesh::CustodySample>,
    Option<BlobReservation>,
    &'a mut Profile5OpenBuilder<'a>,
);

fn profile5_upload_capacity(total_len: u64) -> Result<BlobUploadCapacity, StoreError> {
    let segments = total_len
        .checked_add(aster_mesh::BLOB_STREAM_SEGMENT_BYTES as u64 - 1)
        .ok_or(StoreError::PayloadByteAccountingOverflow)?
        / aster_mesh::BLOB_STREAM_SEGMENT_BYTES as u64;
    Ok(BlobUploadCapacity {
        bytes: super::pack::reserved_upload_pack_bytes(total_len)?,
        chunks: segments,
        variants: 1,
    })
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BlobUploadRequest {
    pub owner: BlobOperationOwner,
    pub topic: Topic,
    pub scope: Scope,
    pub priority: Priority,
    pub ttl_ms: Option<u64>,
    pub media_type: Option<String>,
    pub schema_id: Vec<u8>,
    pub total_len: u64,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub(super) struct BlobUploadCapacity {
    pub(super) bytes: u64,
    pub(super) chunks: u64,
    pub(super) variants: u64,
}

impl BlobUploadCapacity {
    pub(super) fn checked_add(self, other: Self) -> Result<Self, StoreError> {
        Ok(Self {
            bytes: self
                .bytes
                .checked_add(other.bytes)
                .ok_or(StoreError::PayloadByteAccountingOverflow)?,
            chunks: self
                .chunks
                .checked_add(other.chunks)
                .ok_or(StoreError::ItemCountAccountingOverflow)?,
            variants: self
                .variants
                .checked_add(other.variants)
                .ok_or(StoreError::ItemCountAccountingOverflow)?,
        })
    }

    fn checked_sub(self, other: Self) -> Result<Self, StoreError> {
        Ok(Self {
            bytes: self
                .bytes
                .checked_sub(other.bytes)
                .ok_or_else(schema_error)?,
            chunks: self
                .chunks
                .checked_sub(other.chunks)
                .ok_or_else(schema_error)?,
            variants: self
                .variants
                .checked_sub(other.variants)
                .ok_or_else(schema_error)?,
        })
    }
}

#[derive(Clone, Debug)]
pub struct BlobUploadReservation {
    request: BlobUploadRequest,
    control_policy: ControlPolicySnapshot,
    content_epoch: u64,
    request_digest: [u8; 32],
    upload_id: BlobPublicationStreamId,
    pack_identity: BlobPackIdentity,
    staging_charge_bytes: u64,
    conversion_overhead_bytes: u64,
    total_capacity: BlobUploadCapacity,
    authority: Arc<()>,
}

impl PartialEq for BlobUploadReservation {
    fn eq(&self, other: &Self) -> bool {
        self.request == other.request
            && self.control_policy == other.control_policy
            && self.content_epoch == other.content_epoch
            && self.request_digest == other.request_digest
            && self.upload_id == other.upload_id
            && self.pack_identity == other.pack_identity
            && self.staging_charge_bytes == other.staging_charge_bytes
            && self.conversion_overhead_bytes == other.conversion_overhead_bytes
            && self.total_capacity == other.total_capacity
    }
}

impl Eq for BlobUploadReservation {}

impl BlobUploadReservation {
    pub const fn request(&self) -> &BlobUploadRequest {
        &self.request
    }

    pub const fn control_policy(&self) -> &ControlPolicySnapshot {
        &self.control_policy
    }

    pub const fn content_epoch(&self) -> u64 {
        self.content_epoch
    }

    pub const fn staging_charge_bytes(&self) -> u64 {
        self.staging_charge_bytes
    }

    pub const fn conversion_overhead_bytes(&self) -> u64 {
        self.conversion_overhead_bytes
    }

    pub const fn reserved_bytes(&self) -> u64 {
        self.total_capacity.bytes
    }

    pub const fn reserved_chunks(&self) -> u64 {
        self.total_capacity.chunks
    }

    pub const fn reserved_variants(&self) -> u64 {
        self.total_capacity.variants
    }

    pub const fn pack_identity(&self) -> BlobPackIdentity {
        self.pack_identity
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BlobUploadCheckpoint {
    durable: Option<BlobPackCheckpoint>,
    profile5_completion: Option<BlobProfile5UploadCompletion>,
    consumed: BlobUploadCapacity,
    remaining: BlobUploadCapacity,
}

/// Durable, exact authenticated finish authority for a completed provisional
/// Profile-5 upload. It remains invisible until the lifecycle promotion
/// transaction consumes it.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BlobProfile5UploadCompletion {
    candidate_pack: BlobPackCompletion,
    pack: BlobPackCompletion,
    commitment: BlobStreamFinalCommitment,
    authenticated_commitment: Vec<u8>,
}

impl BlobProfile5UploadCompletion {
    pub const fn candidate_pack(&self) -> &BlobPackCompletion {
        &self.candidate_pack
    }

    pub const fn pack(&self) -> &BlobPackCompletion {
        &self.pack
    }

    pub const fn commitment(&self) -> &BlobStreamFinalCommitment {
        &self.commitment
    }

    pub fn authenticated_commitment(&self) -> &[u8] {
        &self.authenticated_commitment
    }

    pub fn reuses_existing_pack(&self) -> bool {
        self.candidate_pack != self.pack
    }
}

impl BlobUploadCheckpoint {
    /// Exact pack journal state projected durably into redb, if any.
    pub const fn durable_pack_checkpoint(&self) -> Option<&BlobPackCheckpoint> {
        self.durable.as_ref()
    }

    pub const fn profile5_completion(&self) -> Option<&BlobProfile5UploadCompletion> {
        self.profile5_completion.as_ref()
    }

    pub fn generation(&self) -> u64 {
        self.durable
            .as_ref()
            .map_or(0, BlobPackCheckpoint::generation)
    }

    pub fn durable_pack_len(&self) -> u64 {
        self.durable
            .as_ref()
            .map_or(0, BlobPackCheckpoint::pack_len)
    }

    pub fn durable_plaintext_offset(&self) -> u64 {
        self.durable
            .as_ref()
            .map_or(0, BlobPackCheckpoint::plaintext_offset)
    }

    pub const fn credit_consumed_bytes(&self) -> u64 {
        self.consumed.bytes
    }

    pub const fn credit_consumed_chunks(&self) -> u64 {
        self.consumed.chunks
    }

    pub const fn credit_consumed_variants(&self) -> u64 {
        self.consumed.variants
    }

    pub const fn credit_remaining_bytes(&self) -> u64 {
        self.remaining.bytes
    }

    pub const fn credit_remaining_chunks(&self) -> u64 {
        self.remaining.chunks
    }

    pub const fn credit_remaining_variants(&self) -> u64 {
        self.remaining.variants
    }
}

#[derive(Clone, Debug)]
pub(super) struct BlobUploadCreditClaim {
    owner_key: Vec<u8>,
    request_digest: [u8; 32],
}

#[derive(Clone, Debug)]
struct DurableBlobUpload {
    format_version: u8,
    reservation: BlobUploadReservation,
    checkpoint: Option<BlobPackCheckpoint>,
    consumed: BlobUploadCapacity,
    bound_variant: Option<super::BlobVariantId>,
    profile5_open: Option<DurableProfile5Open>,
    profile5_completion: Option<BlobProfile5UploadCompletion>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct DurableProfile5Open {
    /// Semantic publication authority: owner, dot, policy, priority, and TTL.
    open: BlobStreamOpen,
    /// Signed OPEN for local uploads; signed publication for received uploads.
    authenticated: Vec<u8>,
    /// Physical pack authority used for checkpoints, DATA, FINISH, and decrypt.
    pack_open: BlobStreamOpen,
    pack_authenticated: Vec<u8>,
    authenticated_is_publication: bool,
}

impl DurableBlobUpload {
    fn remaining(&self) -> Result<BlobUploadCapacity, StoreError> {
        self.reservation.total_capacity.checked_sub(self.consumed)
    }

    fn projection(&self) -> Result<BlobUploadCheckpoint, StoreError> {
        Ok(BlobUploadCheckpoint {
            durable: self.checkpoint.clone(),
            profile5_completion: self.profile5_completion.clone(),
            consumed: self.consumed,
            remaining: self.remaining()?,
        })
    }

    fn encode(&self) -> Result<Vec<u8>, StoreError> {
        let owner_key = blob_operation_owner_key(&self.reservation.request.owner)?;
        let topic = self.reservation.request.topic.as_str().as_bytes();
        let scope = self.reservation.request.scope.as_str().as_bytes();
        let media = self
            .reservation
            .request
            .media_type
            .as_deref()
            .map(str::as_bytes);
        let checkpoint = self
            .checkpoint
            .as_ref()
            .map(BlobPackCheckpoint::encode)
            .unwrap_or_default();
        let mut output = Vec::new();
        output.extend_from_slice(UPLOAD_MAGIC);
        output.push(self.format_version);
        push_u16_bytes(&mut output, &owner_key)?;
        output.extend_from_slice(&self.reservation.control_policy.authority());
        match self.reservation.control_policy.head() {
            None => output.push(0),
            Some((revision, transfer)) => {
                output.push(1);
                output.extend_from_slice(&revision.to_be_bytes());
                output.extend_from_slice(transfer.as_bytes());
            }
        }
        output.extend_from_slice(&self.reservation.content_epoch.to_be_bytes());
        output.push(self.reservation.request.priority as u8);
        match self.reservation.request.ttl_ms {
            None => output.push(0),
            Some(ttl) => {
                output.push(1);
                output.extend_from_slice(&ttl.to_be_bytes());
            }
        }
        push_u16_bytes(&mut output, topic)?;
        push_u16_bytes(&mut output, scope)?;
        match media {
            None => output.extend_from_slice(&u16::MAX.to_be_bytes()),
            Some(media) => push_u16_bytes(&mut output, media)?,
        }
        push_u16_bytes(&mut output, &self.reservation.request.schema_id)?;
        output.extend_from_slice(&self.reservation.request.total_len.to_be_bytes());
        output.extend_from_slice(&self.reservation.request_digest);
        output.extend_from_slice(self.reservation.upload_id.as_bytes());
        output.extend_from_slice(&self.reservation.staging_charge_bytes.to_be_bytes());
        output.extend_from_slice(&self.reservation.conversion_overhead_bytes.to_be_bytes());
        encode_capacity(&mut output, self.reservation.total_capacity);
        encode_capacity(&mut output, self.consumed);
        match self.bound_variant {
            None => output.push(0),
            Some(variant) => {
                output.push(1);
                output.extend_from_slice(variant.as_bytes());
            }
        }
        if self.format_version == PROFILE5_UPLOAD_VERSION {
            let profile5 = self.profile5_open.as_ref().ok_or_else(schema_error)?;
            let open = profile5.open.encode();
            let open_len = u32::try_from(open.len()).map_err(|_| schema_error())?;
            let authenticated_len =
                u32::try_from(profile5.authenticated.len()).map_err(|_| schema_error())?;
            output.extend_from_slice(&open_len.to_be_bytes());
            output.extend_from_slice(&open);
            output.extend_from_slice(&authenticated_len.to_be_bytes());
            output.extend_from_slice(&profile5.authenticated);
            let pack_open = profile5.pack_open.encode();
            let pack_open_len = u32::try_from(pack_open.len()).map_err(|_| schema_error())?;
            let pack_authenticated_len =
                u32::try_from(profile5.pack_authenticated.len()).map_err(|_| schema_error())?;
            output.extend_from_slice(&pack_open_len.to_be_bytes());
            output.extend_from_slice(&pack_open);
            output.extend_from_slice(&pack_authenticated_len.to_be_bytes());
            output.extend_from_slice(&profile5.pack_authenticated);
            output.push(u8::from(profile5.authenticated_is_publication));
            match &self.profile5_completion {
                None => output.push(0),
                Some(completion) => {
                    output.push(1);
                    let commitment = completion.commitment.encode();
                    let candidate_pack = completion
                        .candidate_pack
                        .encode()
                        .map_err(upload_pack_store_error)?;
                    let pack = completion.pack.encode().map_err(upload_pack_store_error)?;
                    for bytes in [
                        commitment.as_slice(),
                        completion.authenticated_commitment.as_slice(),
                        candidate_pack.as_slice(),
                        pack.as_slice(),
                    ] {
                        let len = u32::try_from(bytes.len())
                            .map_err(|_| StoreError::PayloadByteAccountingOverflow)?;
                        output.extend_from_slice(&len.to_be_bytes());
                        output.extend_from_slice(bytes);
                    }
                }
            }
        } else if self.profile5_open.is_some() || self.profile5_completion.is_some() {
            return Err(schema_error());
        }
        let checkpoint_len = u32::try_from(checkpoint.len())
            .map_err(|_| StoreError::PayloadByteAccountingOverflow)?;
        output.extend_from_slice(&checkpoint_len.to_be_bytes());
        output.extend_from_slice(&checkpoint);
        Ok(output)
    }

    fn decode(authority_capability: Arc<()>, encoded: &[u8]) -> Result<Self, StoreError> {
        let mut cursor = UploadCursor::new(encoded);
        if cursor.take(8)? != UPLOAD_MAGIC {
            return Err(schema_error());
        }
        let format_version = cursor.u8()?;
        if format_version != LEGACY_UPLOAD_VERSION
            && format_version != UPLOAD_VERSION
            && format_version != PROFILE5_UPLOAD_VERSION
        {
            return Err(schema_error());
        }
        let owner_key = cursor.short()?.to_vec();
        let owner = super::decode_blob_operation_owner_key(&owner_key)?;
        let authority = cursor.array()?;
        let head = match cursor.u8()? {
            0 => None,
            1 => Some((
                cursor.u64()?,
                crate::ControlTransferId::new(cursor.array()?),
            )),
            _ => return Err(schema_error()),
        };
        let control_policy = ControlPolicySnapshot { authority, head };
        let content_epoch = cursor.u64()?;
        let priority = Priority::from_wire(cursor.u8()?).ok_or_else(schema_error)?;
        let ttl_ms = match cursor.u8()? {
            0 => None,
            1 => Some(cursor.u64()?),
            _ => return Err(schema_error()),
        };
        let topic = Topic::new(std::str::from_utf8(cursor.short()?).map_err(|_| schema_error())?)
            .map_err(|_| schema_error())?;
        let scope = Scope::new(std::str::from_utf8(cursor.short()?).map_err(|_| schema_error())?)
            .map_err(|_| schema_error())?;
        let media_len = cursor.u16()?;
        let media_type = if media_len == u16::MAX {
            None
        } else {
            Some(
                std::str::from_utf8(cursor.take(usize::from(media_len))?)
                    .map_err(|_| schema_error())?
                    .to_owned(),
            )
        };
        let schema_id = cursor.short()?.to_vec();
        let total_len = cursor.u64()?;
        let request_digest = cursor.array()?;
        let upload_id =
            BlobPublicationStreamId::from_bytes(cursor.array()?).map_err(|_| schema_error())?;
        let staging_charge_bytes = cursor.u64()?;
        let conversion_overhead_bytes = cursor.u64()?;
        let total_capacity = decode_capacity(&mut cursor)?;
        let consumed = decode_capacity(&mut cursor)?;
        let bound_variant = match cursor.u8()? {
            0 => None,
            1 => Some(super::BlobVariantId::from_bytes(cursor.array()?)),
            _ => return Err(schema_error()),
        };
        let (profile5_open, profile5_completion) = if format_version == PROFILE5_UPLOAD_VERSION {
            let open_len = usize::try_from(cursor.u32()?).map_err(|_| schema_error())?;
            let open =
                BlobStreamOpen::decode(cursor.take(open_len)?).map_err(|_| schema_error())?;
            let authenticated_len = usize::try_from(cursor.u32()?).map_err(|_| schema_error())?;
            let authenticated = cursor.take(authenticated_len)?.to_vec();
            if authenticated.is_empty() {
                return Err(schema_error());
            }
            let pack_open_len = usize::try_from(cursor.u32()?).map_err(|_| schema_error())?;
            let pack_open =
                BlobStreamOpen::decode(cursor.take(pack_open_len)?).map_err(|_| schema_error())?;
            let pack_authenticated_len =
                usize::try_from(cursor.u32()?).map_err(|_| schema_error())?;
            let pack_authenticated = cursor.take(pack_authenticated_len)?.to_vec();
            if pack_authenticated.is_empty() {
                return Err(schema_error());
            }
            let authenticated_is_publication = match cursor.u8()? {
                0 => false,
                1 => true,
                _ => return Err(schema_error()),
            };
            let profile5_open = DurableProfile5Open {
                open,
                authenticated,
                pack_open,
                pack_authenticated,
                authenticated_is_publication,
            };
            let completion = match cursor.u8()? {
                0 => None,
                1 => {
                    let commitment_len =
                        usize::try_from(cursor.u32()?).map_err(|_| schema_error())?;
                    let commitment =
                        BlobStreamFinalCommitment::decode(cursor.take(commitment_len)?)
                            .map_err(|_| schema_error())?;
                    let authenticated_len =
                        usize::try_from(cursor.u32()?).map_err(|_| schema_error())?;
                    let authenticated_commitment = cursor.take(authenticated_len)?.to_vec();
                    let candidate_pack_len =
                        usize::try_from(cursor.u32()?).map_err(|_| schema_error())?;
                    let candidate_pack = BlobPackCompletion::decode(
                        cursor.take(candidate_pack_len)?,
                        Arc::clone(&authority_capability),
                    )
                    .map_err(upload_pack_store_error)?;
                    let pack_len = usize::try_from(cursor.u32()?).map_err(|_| schema_error())?;
                    let pack = BlobPackCompletion::decode(
                        cursor.take(pack_len)?,
                        Arc::clone(&authority_capability),
                    )
                    .map_err(upload_pack_store_error)?;
                    if authenticated_commitment.is_empty() {
                        return Err(schema_error());
                    }
                    Some(BlobProfile5UploadCompletion {
                        candidate_pack,
                        pack,
                        commitment,
                        authenticated_commitment,
                    })
                }
                _ => return Err(schema_error()),
            };
            (Some(profile5_open), completion)
        } else {
            (None, None)
        };
        let checkpoint_len = usize::try_from(cursor.u32()?).map_err(|_| schema_error())?;
        let mut checkpoint = if checkpoint_len == 0 {
            None
        } else {
            Some(
                BlobPackCheckpoint::decode(cursor.take(checkpoint_len)?)
                    .map_err(|_| schema_error())?,
            )
        };
        if let Some(checkpoint) = checkpoint.as_mut() {
            checkpoint.bind_authority(Arc::clone(&authority_capability));
        }
        cursor.finish()?;
        let request = BlobUploadRequest {
            owner,
            topic,
            scope,
            priority,
            ttl_ms,
            media_type,
            schema_id,
            total_len,
        };
        validate_request(&request)?;
        if let Some(profile5) = profile5_open.as_ref() {
            validate_profile5_open_shape(&request, &control_policy, content_epoch, &profile5.open)?;
            if profile5.pack_open.total_len() != profile5.open.total_len()
                || profile5.pack_open.content_epoch() != profile5.open.content_epoch()
                || profile5.pack_open.metadata() != profile5.open.metadata()
                || profile5.pack_open.content_group() != profile5.open.content_group()
                || (!profile5.authenticated_is_publication
                    && (profile5.pack_open != profile5.open
                        || profile5.pack_authenticated != profile5.authenticated))
            {
                return Err(schema_error());
            }
        }
        let (expected_capacity, expected_staging, expected_conversion) =
            if format_version == LEGACY_UPLOAD_VERSION {
                (
                    super::depot::legacy_blob_upload_capacity(total_len)?,
                    super::depot::legacy_blob_upload_staging_charge(total_len)?,
                    super::depot::blob_upload_conversion_overhead(total_len)?,
                )
            } else if format_version == PROFILE5_UPLOAD_VERSION {
                let capacity = profile5_upload_capacity(total_len)?;
                (capacity, capacity.bytes, 0)
            } else {
                (
                    super::depot::blob_upload_capacity(total_len)?,
                    super::depot::blob_upload_staging_charge(total_len)?,
                    super::depot::blob_upload_conversion_overhead(total_len)?,
                )
            };
        let pack_identity = profile5_open.as_ref().map_or_else(
            || BlobPackIdentity::new(upload_id, request_digest, total_len),
            |profile5| {
                BlobPackIdentity::new(
                    profile5.pack_open.stream_id(),
                    profile5.pack_open.digest(),
                    total_len,
                )
            },
        );
        if request_digest_for(&request)? != request_digest
            || upload_id_for(&request.owner, request_digest)? != upload_id
            || staging_charge_bytes != expected_staging
            || conversion_overhead_bytes != expected_conversion
            || total_capacity != expected_capacity
            || consumed.checked_add(total_capacity.checked_sub(consumed)?)? != total_capacity
            || checkpoint.as_ref().is_some_and(|checkpoint| {
                checkpoint.upload_id() != pack_identity.upload_id()
                    || checkpoint.request_digest() != pack_identity.request_digest()
                    || checkpoint.total_len() != pack_identity.total_len()
            })
            || profile5_completion.as_ref().is_some_and(|completion| {
                let Some(profile5) = profile5_open.as_ref() else {
                    return true;
                };
                let Some(checkpoint) = checkpoint.as_ref() else {
                    return true;
                };
                completion.commitment.open_digest() != &profile5.pack_open.digest()
                    || completion.commitment.stream_id() != profile5.pack_open.stream_id()
                    || completion.commitment.total_len() != profile5.pack_open.total_len()
                    || completion.commitment.segment_count() != checkpoint.next_index()
                    || completion.commitment.plaintext_root()
                        != completion.candidate_pack.plaintext_root()
                    || completion.commitment.ciphertext_root()
                        != completion.candidate_pack.ciphertext_root()
                    || completion.commitment.blob_id() != completion.candidate_pack.blob_id()
                    || completion.candidate_pack.checkpoint() != checkpoint
                    || completion.candidate_pack.identity() != pack_identity
                    || Sha256::digest(completion.commitment.encode()).as_slice()
                        != completion.candidate_pack.commitment_digest()
                    || Sha256::digest(&completion.authenticated_commitment).as_slice()
                        != completion.candidate_pack.authenticated_commitment_digest()
                    || completion.pack.blob_id() != completion.commitment.blob_id()
            })
        {
            return Err(schema_error());
        }
        Ok(Self {
            format_version,
            reservation: BlobUploadReservation {
                request,
                control_policy,
                content_epoch,
                request_digest,
                upload_id,
                pack_identity,
                staging_charge_bytes,
                conversion_overhead_bytes,
                total_capacity,
                authority: authority_capability,
            },
            checkpoint,
            consumed,
            bound_variant,
            profile5_open,
            profile5_completion,
        })
    }
}

fn validate_request(request: &BlobUploadRequest) -> Result<(), StoreError> {
    if request.ttl_ms == Some(0) {
        return Err(blob_error(BlobStoreError::InvalidPublication(
            "finite Blob TTL must be positive",
        )));
    }
    BlobMetadata::new(request.media_type.clone(), request.schema_id.clone()).map_err(|_| {
        blob_error(BlobStoreError::InvalidPublication(
            "invalid Blob upload metadata",
        ))
    })?;
    super::depot::blob_upload_capacity(request.total_len)?;
    Ok(())
}

fn request_digest_for(request: &BlobUploadRequest) -> Result<[u8; 32], StoreError> {
    let owner_key = blob_operation_owner_key(&request.owner)?;
    let mut digest = Sha256::new();
    digest.update(UPLOAD_REQUEST_DOMAIN);
    digest.update((owner_key.len() as u64).to_be_bytes());
    digest.update(&owner_key);
    digest.update((request.topic.as_str().len() as u64).to_be_bytes());
    digest.update(request.topic.as_str().as_bytes());
    digest.update((request.scope.as_str().len() as u64).to_be_bytes());
    digest.update(request.scope.as_str().as_bytes());
    digest.update([request.priority as u8]);
    match request.ttl_ms {
        None => digest.update([0]),
        Some(ttl) => {
            digest.update([1]);
            digest.update(ttl.to_be_bytes());
        }
    }
    match request.media_type.as_deref() {
        None => digest.update(u64::MAX.to_be_bytes()),
        Some(media) => {
            digest.update((media.len() as u64).to_be_bytes());
            digest.update(media.as_bytes());
        }
    }
    digest.update((request.schema_id.len() as u64).to_be_bytes());
    digest.update(&request.schema_id);
    digest.update(request.total_len.to_be_bytes());
    Ok(digest.finalize().into())
}

fn upload_id_for(
    owner: &BlobOperationOwner,
    request_digest: [u8; 32],
) -> Result<BlobPublicationStreamId, StoreError> {
    let owner_key = blob_operation_owner_key(owner)?;
    let mut digest = Sha256::new();
    digest.update(UPLOAD_ID_DOMAIN);
    digest.update((owner_key.len() as u64).to_be_bytes());
    digest.update(owner_key);
    digest.update(request_digest);
    BlobPublicationStreamId::from_bytes(digest.finalize().into()).map_err(|_| schema_error())
}

fn current_scope_epoch_write(
    write: &redb::WriteTransaction,
    scope: &Scope,
) -> Result<u64, StoreError> {
    write
        .open_table(CONTROL_SCOPE_EPOCHS)?
        .get(scope.as_str())?
        .map(|value| decode_scope_epoch_index(value.value()))
        .transpose()
        .map(|value| value.map_or(1, |(epoch, _)| epoch))
}

fn require_upload_policy_write(
    write: &redb::WriteTransaction,
    authority: NodeId,
    policy: &ControlPolicySnapshot,
    request: &BlobUploadRequest,
    expected_epoch: Option<u64>,
) -> Result<u64, StoreError> {
    require_control_policy_write(write, authority, policy)?;
    if request.owner.publisher == [0; 32] {
        return Err(blob_error(BlobStoreError::InvalidPublication(
            "Blob upload publisher is invalid",
        )));
    }
    if control_principal_revoked_write(write, request.owner.publisher)? {
        return Err(blob_error(BlobStoreError::PublisherRevoked(
            request.owner.publisher,
        )));
    }
    let epoch = current_scope_epoch_write(write, &request.scope)?;
    if expected_epoch.is_some_and(|expected| expected != epoch) {
        return Err(blob_error(BlobStoreError::KeyEpochStale {
            current: epoch,
            received: expected_epoch.expect("checked"),
        }));
    }
    Ok(epoch)
}

fn profile5_reservation_from_open(
    policy: &ControlPolicySnapshot,
    request: &BlobUploadRequest,
    initial_custody: Option<aster_mesh::CustodySample>,
    open: &BlobStreamOpen,
) -> Result<BlobReservation, StoreError> {
    if open.publisher_counter() == 0 {
        return Err(schema_error());
    }
    Ok(BlobReservation {
        control_policy: *policy,
        publisher: request.owner.publisher,
        topic: request.topic.clone(),
        scope: request.scope.clone(),
        ttl_ms: request.ttl_ms,
        local_initial_sample: initial_custody,
        previous_counter: open.publisher_counter() - 1,
        counter: open.publisher_counter(),
        context: open.causal_context().clone(),
        durable_counter: true,
    })
}

fn validate_profile5_open_shape(
    request: &BlobUploadRequest,
    policy: &ControlPolicySnapshot,
    content_epoch: u64,
    open: &BlobStreamOpen,
) -> Result<(), StoreError> {
    let metadata = BlobMetadata::new(request.media_type.clone(), request.schema_id.clone())
        .map_err(|_| schema_error())?;
    let expected_stream = local_blob_publication_stream_id(
        request.owner.publisher,
        request.owner.operation.as_bytes(),
    );
    let policy_revision = policy.head().map_or(1, |(revision, _)| revision);
    if open.stream_id() != expected_stream
        || open.publisher() != request.owner.publisher
        || open.operation_key() != request.owner.operation.as_bytes()
        || open.mission_id() != &policy.authority()
        || open.topic() != &request.topic
        || open.scope() != &request.scope
        || open.metadata() != &metadata
        || open.priority() != request.priority
        || open.ttl_ms() != request.ttl_ms
        || open.ttl_ms().is_some() != open.initial_custody().is_some()
        || open.total_len() != request.total_len
        || open.content_epoch() != content_epoch
        || open.policy_revision() != policy_revision
    {
        return Err(schema_error());
    }
    Ok(())
}

fn validate_durable_profile5_authority(
    request: &BlobUploadRequest,
    policy: &ControlPolicySnapshot,
    content_epoch: u64,
    reservation: &BlobReservation,
    durable: &DurableProfile5Open,
) -> Result<(), StoreError> {
    validate_profile5_open_shape(request, policy, content_epoch, &durable.open)?;
    if durable.authenticated.is_empty()
        || durable.pack_authenticated.is_empty()
        || durable.open.publisher_counter() != reservation.counter()
        || durable.open.causal_context() != reservation.context()
        || durable.open.initial_custody() != reservation.initial_custody()
        || durable.pack_open.total_len() != durable.open.total_len()
        || durable.pack_open.content_epoch() != durable.open.content_epoch()
        || durable.pack_open.metadata() != durable.open.metadata()
        || durable.pack_open.content_group() != durable.open.content_group()
        || (!durable.authenticated_is_publication
            && (durable.pack_open != durable.open
                || durable.pack_authenticated != durable.authenticated))
    {
        return Err(blob_error(BlobStoreError::OperationConflict));
    }
    Ok(())
}

fn reservation_for_store(store: &Store, upload: &DurableBlobUpload) -> BlobUploadReservation {
    let mut reservation = upload.reservation.clone();
    reservation.authority = Arc::clone(&store.blob_completion_authority);
    reservation
}

fn validate_reservation_capability(
    store: &Store,
    reservation: &BlobUploadReservation,
) -> Result<Vec<u8>, StoreError> {
    if !Arc::ptr_eq(&reservation.authority, &store.blob_completion_authority) {
        return Err(blob_error(BlobStoreError::ReservationChanged));
    }
    blob_operation_owner_key(&reservation.request.owner)
}

pub(super) fn upload_credit_claim(
    store: &Store,
    reservation: &BlobUploadReservation,
) -> Result<BlobUploadCreditClaim, StoreError> {
    Ok(BlobUploadCreditClaim {
        owner_key: validate_reservation_capability(store, reservation)?,
        request_digest: reservation.request_digest,
    })
}

pub(super) fn upload_capacity_usage_write(
    write: &redb::WriteTransaction,
) -> Result<BlobUploadCapacity, StoreError> {
    upload_capacity_usage_table(&write.open_table(super::BLOB_UPLOADS)?)
}

pub(super) fn upload_capacity_usage_read(
    read: &redb::ReadTransaction,
) -> Result<BlobUploadCapacity, StoreError> {
    if !read
        .list_tables()?
        .any(|table| table.name() == super::BLOB_UPLOADS.name())
    {
        return Ok(BlobUploadCapacity::default());
    }
    upload_capacity_usage_table(&read.open_table(super::BLOB_UPLOADS)?)
}

pub(super) fn upload_pack_expectations_write(
    write: &redb::WriteTransaction,
) -> Result<Vec<super::pack::ExpectedBlobUploadPack>, StoreError> {
    upload_pack_expectations_table(&write.open_table(super::BLOB_UPLOADS)?)
}

pub(super) fn upload_pack_expectations_read(
    read: &redb::ReadTransaction,
) -> Result<Vec<super::pack::ExpectedBlobUploadPack>, StoreError> {
    if !read
        .list_tables()?
        .any(|table| table.name() == super::BLOB_UPLOADS.name())
    {
        return Ok(Vec::new());
    }
    upload_pack_expectations_table(&read.open_table(super::BLOB_UPLOADS)?)
}

fn upload_pack_expectations_table(
    uploads: &impl ReadableTable<&'static [u8], &'static [u8]>,
) -> Result<Vec<super::pack::ExpectedBlobUploadPack>, StoreError> {
    uploads
        .iter()?
        .map(|row| {
            let (_, value) = row?;
            let upload = DurableBlobUpload::decode(Arc::new(()), value.value())?;
            let discard_candidate = upload
                .profile5_completion
                .as_ref()
                .is_some_and(BlobProfile5UploadCompletion::reuses_existing_pack);
            Ok(super::pack::ExpectedBlobUploadPack {
                identity: upload.reservation.pack_identity(),
                checkpoint: upload.checkpoint,
                may_be_absent: discard_candidate,
                discard_candidate,
            })
        })
        .collect()
}

pub(super) fn finish_upload_cleanups_write(
    write: &redb::WriteTransaction,
    completed: &[BlobPackIdentity],
) -> Result<(), StoreError> {
    if completed.is_empty() {
        return Ok(());
    }
    let completed = completed
        .iter()
        .map(|identity| *identity.upload_id().as_bytes())
        .collect::<std::collections::BTreeSet<_>>();
    let mut remove = Vec::new();
    {
        let uploads = write.open_table(super::BLOB_UPLOADS)?;
        for row in uploads.iter()? {
            let (key, value) = row?;
            let upload = DurableBlobUpload::decode(Arc::new(()), value.value())?;
            if completed.contains(upload.reservation.pack_identity().upload_id().as_bytes()) {
                remove.push((key.value().to_vec(), upload));
            }
        }
    }
    if remove.len() != completed.len() {
        return Err(schema_error());
    }
    let mut uploads = write.open_table(super::BLOB_UPLOADS)?;
    for (key, upload) in remove {
        remove_profile5_pack_write(write, &upload)?;
        uploads.remove(key.as_slice())?;
    }
    Ok(())
}

fn remove_profile5_pack_write(
    write: &redb::WriteTransaction,
    upload: &DurableBlobUpload,
) -> Result<(), StoreError> {
    let Some(completion) = upload.profile5_completion.as_ref() else {
        return Ok(());
    };
    if completion.reuses_existing_pack() {
        return Ok(());
    }
    let open = upload.profile5_open.as_ref().ok_or_else(schema_error)?;
    let variant = super::blob_variant_id(
        completion.commitment.blob_id(),
        &open.pack_open.content_group(),
        open.pack_open.content_epoch(),
    );
    super::pack_lifecycle::remove_provisional_write(write, variant, &completion.pack)
}

fn upload_capacity_usage_table(
    uploads: &impl ReadableTable<&'static [u8], &'static [u8]>,
) -> Result<BlobUploadCapacity, StoreError> {
    let mut usage = BlobUploadCapacity::default();
    for row in uploads.iter()? {
        let (_, value) = row?;
        usage = usage
            .checked_add(DurableBlobUpload::decode(Arc::new(()), value.value())?.remaining()?)?;
    }
    Ok(usage)
}

pub(super) fn bind_and_consume_upload_credit_write(
    write: &redb::WriteTransaction,
    store: &Store,
    claim: &BlobUploadCreditClaim,
    variant: super::BlobVariantId,
    manifest: Option<&BlobManifest>,
    consume: BlobUploadCapacity,
) -> Result<(), StoreError> {
    let encoded = write
        .open_table(super::BLOB_UPLOADS)?
        .get(claim.owner_key.as_slice())?
        .map(|value| value.value().to_vec())
        .ok_or_else(|| blob_error(BlobStoreError::ReservationChanged))?;
    let mut upload =
        DurableBlobUpload::decode(Arc::clone(&store.blob_completion_authority), &encoded)?;
    require_upload_policy_write(
        write,
        store.require_bound_mission()?,
        &upload.reservation.control_policy,
        &upload.reservation.request,
        Some(upload.reservation.content_epoch),
    )?;
    if let Some(manifest) = manifest {
        let expected_metadata = BlobMetadata::new(
            upload.reservation.request.media_type.clone(),
            upload.reservation.request.schema_id.clone(),
        )
        .map_err(|_| schema_error())?;
        if manifest.total_len() != upload.reservation.request.total_len
            || manifest.content_epoch() != upload.reservation.content_epoch
            || manifest.metadata() != &expected_metadata
        {
            return Err(blob_error(BlobStoreError::ReservationChanged));
        }
    } else if upload.bound_variant.is_none() {
        return Err(blob_error(BlobStoreError::ReservationChanged));
    }
    if upload.reservation.request_digest != claim.request_digest
        || upload.bound_variant.is_some_and(|bound| bound != variant)
        || upload.remaining()?.checked_sub(consume).is_err()
    {
        return Err(blob_error(BlobStoreError::ReservationChanged));
    }
    upload.bound_variant = Some(variant);
    upload.consumed = upload.consumed.checked_add(consume)?;
    write
        .open_table(super::BLOB_UPLOADS)?
        .insert(claim.owner_key.as_slice(), upload.encode()?.as_slice())?;
    Ok(())
}

pub(super) fn bind_upload_credit_to_existing_write(
    write: &redb::WriteTransaction,
    store: &Store,
    claim: &BlobUploadCreditClaim,
    variant: super::BlobVariantId,
    manifest: &BlobManifest,
) -> Result<(), StoreError> {
    let encoded = write
        .open_table(super::BLOB_UPLOADS)?
        .get(claim.owner_key.as_slice())?
        .map(|value| value.value().to_vec())
        .ok_or_else(|| blob_error(BlobStoreError::ReservationChanged))?;
    let mut upload =
        DurableBlobUpload::decode(Arc::clone(&store.blob_completion_authority), &encoded)?;
    require_upload_policy_write(
        write,
        store.require_bound_mission()?,
        &upload.reservation.control_policy,
        &upload.reservation.request,
        Some(upload.reservation.content_epoch),
    )?;
    let expected_metadata = BlobMetadata::new(
        upload.reservation.request.media_type.clone(),
        upload.reservation.request.schema_id.clone(),
    )
    .map_err(|_| schema_error())?;
    if upload.reservation.request_digest != claim.request_digest
        || upload.bound_variant.is_some_and(|bound| bound != variant)
        || manifest.total_len() != upload.reservation.request.total_len
        || manifest.content_epoch() != upload.reservation.content_epoch
        || manifest.metadata() != &expected_metadata
    {
        return Err(blob_error(BlobStoreError::ReservationChanged));
    }
    let reconstructed = super::depot::reconstruct_upload_capacity_write(
        write,
        variant,
        upload.reservation.request.total_len,
        upload.reservation.content_epoch,
        upload.reservation.request.media_type.as_deref(),
        &upload.reservation.request.schema_id,
    )?;
    let additional = reconstructed.checked_sub(upload.consumed)?;
    upload.remaining()?.checked_sub(additional)?;
    upload.bound_variant = Some(variant);
    upload.consumed = reconstructed;
    write
        .open_table(super::BLOB_UPLOADS)?
        .insert(claim.owner_key.as_slice(), upload.encode()?.as_slice())?;
    Ok(())
}

pub(super) fn bind_profile5_promotion_write(
    write: &redb::WriteTransaction,
    store: &Store,
    owner_key: &[u8],
    variant: super::BlobVariantId,
    owner_binding: [u8; 32],
) -> Result<(), StoreError> {
    let encoded = write
        .open_table(super::BLOB_UPLOADS)?
        .get(owner_key)?
        .map(|value| value.value().to_vec())
        .ok_or_else(|| blob_error(BlobStoreError::ReservationChanged))?;
    let mut upload =
        DurableBlobUpload::decode(Arc::clone(&store.blob_completion_authority), &encoded)?;
    let profile5 = upload.profile5_open.as_ref().ok_or_else(schema_error)?;
    let completion = upload
        .profile5_completion
        .as_ref()
        .ok_or_else(schema_error)?;
    let expected_variant = super::blob_variant_id(
        completion.commitment.blob_id(),
        &profile5.pack_open.content_group(),
        profile5.pack_open.content_epoch(),
    );
    if variant != expected_variant
        || upload.bound_variant.is_some_and(|bound| bound != variant)
        || upload.consumed != BlobUploadCapacity::default()
    {
        return Err(blob_error(BlobStoreError::ReservationChanged));
    }
    let pack = super::pack_lifecycle::load_write(
        write,
        variant,
        Arc::clone(&store.blob_completion_authority),
    )?
    .ok_or_else(schema_error)?;
    if pack.owner_binding() != &owner_binding
        || pack.completion() != &completion.pack
        || (!completion.reuses_existing_pack() && pack.open() != &profile5.pack_open)
    {
        return Err(blob_error(BlobStoreError::CompletionMismatch));
    }
    super::lifecycle::ensure_lineage_fence(
        write,
        store.blob_lifecycle_limits,
        variant,
        *pack.physical_lineage(),
        owner_binding,
    )?;
    let capacity = super::pack_lifecycle::promote_write(
        write,
        variant,
        &completion.pack,
        Arc::clone(&store.blob_completion_authority),
    )?;
    if capacity != upload.reservation.total_capacity {
        return Err(schema_error());
    }
    upload.bound_variant = Some(variant);
    upload.consumed = capacity;
    write
        .open_table(super::BLOB_UPLOADS)?
        .insert(owner_key, upload.encode()?.as_slice())?;
    Ok(())
}

pub(super) fn finish_profile5_promotion_write(
    write: &redb::WriteTransaction,
    owner_key: &[u8],
) -> Result<(), StoreError> {
    let encoded = write
        .open_table(super::BLOB_UPLOADS)?
        .get(owner_key)?
        .map(|value| value.value().to_vec())
        .ok_or_else(schema_error)?;
    let upload = DurableBlobUpload::decode(Arc::new(()), &encoded)?;
    if upload.profile5_completion.is_none()
        || upload.bound_variant.is_none()
        || upload.consumed != upload.reservation.total_capacity
    {
        return Err(schema_error());
    }
    write.open_table(super::BLOB_UPLOADS)?.remove(owner_key)?;
    Ok(())
}

pub(super) fn audit_blob_uploads_write(write: &redb::WriteTransaction) -> Result<(), StoreError> {
    let uploads = write.open_table(super::BLOB_UPLOADS)?;
    if uploads.len()? > MAX_UPLOADS {
        return Err(schema_error());
    }
    for row in uploads.iter()? {
        let (key, value) = row?;
        let upload = DurableBlobUpload::decode(Arc::new(()), value.value())?;
        if key.value() != blob_operation_owner_key(&upload.reservation.request.owner)? {
            return Err(schema_error());
        }
        let reconstructed = match upload.bound_variant {
            Some(variant) => {
                match super::pack_lifecycle::reconstruct_capacity_write(write, variant)? {
                    Some(capacity) => capacity,
                    None => super::depot::reconstruct_upload_capacity_write(
                        write,
                        variant,
                        upload.reservation.request.total_len,
                        upload.reservation.content_epoch,
                        upload.reservation.request.media_type.as_deref(),
                        &upload.reservation.request.schema_id,
                    )?,
                }
            }
            None => BlobUploadCapacity::default(),
        };
        if upload.consumed != reconstructed {
            return Err(schema_error());
        }
        if let Some(profile5) = upload.profile5_open.as_ref() {
            let high_water = write
                .open_table(PUBLISHER_HIGH_WATER)?
                .get(upload.reservation.request.owner.publisher.as_slice())?
                .map_or(0, |value| value.value());
            if high_water < profile5.open.publisher_counter() {
                return Err(schema_error());
            }
            if let Some(completion) = upload.profile5_completion.as_ref() {
                let variant = super::blob_variant_id(
                    completion.commitment.blob_id(),
                    &profile5.pack_open.content_group(),
                    profile5.pack_open.content_epoch(),
                );
                let pack = super::pack_lifecycle::load_write(write, variant, Arc::new(()))?
                    .ok_or_else(schema_error)?;
                if pack.completion() != &completion.pack
                    || pack.commitment().blob_id() != completion.commitment.blob_id()
                    || pack.open().content_group() != profile5.pack_open.content_group()
                    || pack.open().content_epoch() != profile5.pack_open.content_epoch()
                    || pack.open().total_len() != profile5.pack_open.total_len()
                    || pack.open().metadata() != profile5.pack_open.metadata()
                    || (!completion.reuses_existing_pack()
                        && (pack.open() != &profile5.pack_open
                            || pack.authenticated_open() != profile5.pack_authenticated
                            || pack.commitment() != &completion.commitment
                            || pack.authenticated_commitment()
                                != completion.authenticated_commitment))
                {
                    return Err(schema_error());
                }
            }
        }
        if let Some(operation) = write.open_table(BLOB_OPERATIONS)?.get(key.value())? {
            let operation = decode_blob_operation_record(operation.value())?;
            let publication = write
                .open_table(BLOB_PUBLICATIONS)?
                .get(operation.transfer_id.as_bytes().as_slice())?
                .map(|value| decode_blob_metadata(value.value()))
                .transpose()?
                .ok_or_else(schema_error)?;
            if upload.bound_variant != Some(publication.variant_id) {
                return Err(schema_error());
            }
        }
    }
    Ok(())
}

pub(super) fn audit_blob_uploads_read(read: &redb::ReadTransaction) -> Result<(), StoreError> {
    let uploads = read.open_table(super::BLOB_UPLOADS)?;
    if uploads.len()? > MAX_UPLOADS {
        return Err(schema_error());
    }
    for row in uploads.iter()? {
        let (key, value) = row?;
        let upload = DurableBlobUpload::decode(Arc::new(()), value.value())?;
        if key.value() != blob_operation_owner_key(&upload.reservation.request.owner)? {
            return Err(schema_error());
        }
        let reconstructed = match upload.bound_variant {
            Some(variant) => match super::pack_lifecycle::reconstruct_capacity_read(read, variant)?
            {
                Some(capacity) => capacity,
                None => super::depot::reconstruct_upload_capacity_read(
                    read,
                    variant,
                    upload.reservation.request.total_len,
                    upload.reservation.content_epoch,
                    upload.reservation.request.media_type.as_deref(),
                    &upload.reservation.request.schema_id,
                )?,
            },
            None => BlobUploadCapacity::default(),
        };
        if upload.consumed != reconstructed {
            return Err(schema_error());
        }
        if let Some(profile5) = upload.profile5_open.as_ref() {
            let high_water = read
                .open_table(PUBLISHER_HIGH_WATER)?
                .get(upload.reservation.request.owner.publisher.as_slice())?
                .map_or(0, |value| value.value());
            if high_water < profile5.open.publisher_counter() {
                return Err(schema_error());
            }
            if let Some(completion) = upload.profile5_completion.as_ref() {
                let variant = super::blob_variant_id(
                    completion.commitment.blob_id(),
                    &profile5.pack_open.content_group(),
                    profile5.pack_open.content_epoch(),
                );
                let pack = super::pack_lifecycle::load_read(read, variant, Arc::new(()))?
                    .ok_or_else(schema_error)?;
                if pack.completion() != &completion.pack
                    || pack.commitment().blob_id() != completion.commitment.blob_id()
                    || pack.open().content_group() != profile5.pack_open.content_group()
                    || pack.open().content_epoch() != profile5.pack_open.content_epoch()
                    || pack.open().total_len() != profile5.pack_open.total_len()
                    || pack.open().metadata() != profile5.pack_open.metadata()
                    || (!completion.reuses_existing_pack()
                        && (pack.open() != &profile5.pack_open
                            || pack.authenticated_open() != profile5.pack_authenticated
                            || pack.commitment() != &completion.commitment
                            || pack.authenticated_commitment()
                                != completion.authenticated_commitment))
                {
                    return Err(schema_error());
                }
            }
        }
        if let Some(operation) = read.open_table(BLOB_OPERATIONS)?.get(key.value())? {
            let operation = decode_blob_operation_record(operation.value())?;
            let publication = read
                .open_table(BLOB_PUBLICATIONS)?
                .get(operation.transfer_id.as_bytes().as_slice())?
                .map(|value| decode_blob_metadata(value.value()))
                .transpose()?
                .ok_or_else(schema_error)?;
            if upload.bound_variant != Some(publication.variant_id) {
                return Err(schema_error());
            }
        }
    }
    Ok(())
}

pub(super) fn extend_profile5_reserved_publisher_high_write(
    write: &redb::WriteTransaction,
    expected: &mut std::collections::BTreeMap<Vec<u8>, u64>,
) -> Result<(), StoreError> {
    extend_profile5_reserved_publisher_high(&write.open_table(super::BLOB_UPLOADS)?, expected)
}

pub(super) fn extend_profile5_reserved_publisher_high_read(
    read: &redb::ReadTransaction,
    expected: &mut std::collections::BTreeMap<Vec<u8>, u64>,
) -> Result<(), StoreError> {
    extend_profile5_reserved_publisher_high(&read.open_table(super::BLOB_UPLOADS)?, expected)
}

fn extend_profile5_reserved_publisher_high(
    uploads: &impl ReadableTable<&'static [u8], &'static [u8]>,
    expected: &mut std::collections::BTreeMap<Vec<u8>, u64>,
) -> Result<(), StoreError> {
    for row in uploads.iter()? {
        let (_, value) = row?;
        let upload = DurableBlobUpload::decode(Arc::new(()), value.value())?;
        if let Some(profile5) = upload.profile5_open {
            expected
                .entry(upload.reservation.request.owner.publisher.to_vec())
                .and_modify(|current| *current = (*current).max(profile5.open.publisher_counter()))
                .or_insert(profile5.open.publisher_counter());
        }
    }
    Ok(())
}

fn received_profile5_lifetime_write(
    write: &redb::WriteTransaction,
    publication: &VerifiedBlobStreamPublication,
    source: &[u8],
    admission: super::VerifiedFiniteBlobAdmission,
) -> Result<super::BlobLifetime, StoreError> {
    let open = publication.publication().open();
    if admission.source_transfer_id
        != *BlobTransferId::new(Sha256::digest(source).into()).as_bytes()
        || admission.source_len
            != u64::try_from(source.len()).map_err(|_| StoreError::PayloadByteAccountingOverflow)?
        || admission.publication_id.as_slice()
            != Sha256::digest(publication.authenticated_bytes()).as_slice()
        || admission.blob_id != publication.publication().blob_id()
        || admission.priority != open.priority()
        || open.ttl_ms() != Some(admission.ttl_ms)
    {
        return Err(blob_error(BlobStoreError::PendingSourceConflict));
    }
    let origin_age_ms = match (
        open.initial_custody(),
        publication.publication().final_custody(),
    ) {
        (Some(initial), Some(final_sample))
            if initial.clock_id == final_sample.clock_id
                && final_sample.tick_ms >= initial.tick_ms =>
        {
            final_sample.tick_ms - initial.tick_ms
        }
        _ => return Err(blob_error(BlobStoreError::PendingSourceConflict)),
    };
    if admission.forwarding_age_ms < origin_age_ms {
        return Err(blob_error(BlobStoreError::PendingSourceConflict));
    }
    if admission.forwarding_age_ms >= admission.ttl_ms {
        return Err(blob_error(BlobStoreError::ExpiredOrRetired));
    }
    let continuity = super::custody::observe_continuity_write(write, admission.receiver_sample)?;
    let forwarding_age_ms = admission.forwarding_age_at(continuity.sample())?;
    if forwarding_age_ms >= admission.ttl_ms {
        return Err(blob_error(BlobStoreError::ExpiredOrRetired));
    }
    Ok(super::BlobLifetime::Finite {
        ttl_ms: admission.ttl_ms,
        age: super::custody::LowerBoundAgeCheckpoint {
            cumulative_age_ms: forwarding_age_ms,
            checkpoint: Some(continuity.sample()),
            continuity_generation: continuity.generation(),
            continuity_lost: false,
        },
        provenance: admission.provenance,
    })
}

impl Store {
    pub fn reserve_blob_upload_with_policy(
        &self,
        policy: &ControlPolicySnapshot,
        request: &BlobUploadRequest,
    ) -> Result<(BlobUploadReservation, BlobUploadCheckpoint), StoreError> {
        let (reservation, checkpoint, profile5_open) =
            self.reserve_blob_upload_with_policy_impl(policy, request, None)?;
        debug_assert!(profile5_open.is_none());
        Ok((reservation, checkpoint))
    }

    /// Reserves the exact authenticated Profile-5 open and its publisher dot
    /// together with the provisional pack. The dot is exclusive immediately,
    /// but remains absent from accepted-dot/frontier/publication indexes until
    /// final atomic promotion.
    pub fn reserve_profile5_upload_with_policy<F>(
        &self,
        policy: &ControlPolicySnapshot,
        request: &BlobUploadRequest,
        initial_custody: Option<aster_mesh::CustodySample>,
        build: F,
    ) -> Result<
        (
            BlobUploadReservation,
            BlobUploadCheckpoint,
            VerifiedBlobStreamOpen,
        ),
        StoreError,
    >
    where
        F: FnOnce(
            &BlobReservation,
            Option<&[u8]>,
        ) -> Result<(VerifiedBlobStreamOpen, Vec<u8>), StoreError>,
    {
        if request.ttl_ms.is_some() != initial_custody.is_some() {
            return Err(blob_error(BlobStoreError::InvalidPublication(
                "Profile-5 finite upload requires one initial custody sample",
            )));
        }
        let mut build = Some(build);
        let mut returned = None;
        let mut adapter = |reservation: &BlobReservation,
                           existing: Option<&DurableProfile5Open>| {
            let (verified, authenticated) = build
                .take()
                .expect("Profile-5 open builder is called exactly once")(
                reservation,
                existing.map(|durable| durable.authenticated.as_slice()),
            )?;
            if existing.is_some_and(|durable| durable.authenticated_is_publication) {
                return Err(blob_error(BlobStoreError::OperationConflict));
            }
            returned = Some(verified.clone());
            Ok(DurableProfile5Open {
                open: verified.open().clone(),
                authenticated: authenticated.clone(),
                pack_open: verified.open().clone(),
                pack_authenticated: authenticated,
                authenticated_is_publication: false,
            })
        };
        let (reservation, checkpoint, durable) = self.reserve_blob_upload_with_policy_impl(
            policy,
            request,
            Some((initial_custody, None, &mut adapter)),
        )?;
        debug_assert!(durable.is_some());
        Ok((
            reservation,
            checkpoint,
            returned.expect("Profile-5 reservation returns an authenticated open"),
        ))
    }

    /// Reserves a receiver-side pack for an already authenticated remote
    /// Profile-5 open. The exact publisher dot/open bytes become durable and
    /// retryable before DATA admission; no local identity is minted.
    pub fn reserve_received_profile5_upload_with_policy(
        &self,
        policy: &ControlPolicySnapshot,
        publication: &VerifiedBlobStreamPublication,
        physical_open: &VerifiedBlobStreamOpen,
    ) -> Result<
        (
            BlobUploadReservation,
            BlobUploadCheckpoint,
            VerifiedBlobStreamOpen,
        ),
        StoreError,
    > {
        let open = publication.publication().open();
        let request = BlobUploadRequest {
            owner: super::BlobOperationOwner::new(
                open.publisher(),
                super::BlobOperationKey::new(open.operation_key().to_vec())?,
            ),
            topic: open.topic().clone(),
            scope: open.scope().clone(),
            priority: open.priority(),
            ttl_ms: open.ttl_ms(),
            media_type: open.metadata().media_type().map(str::to_owned),
            schema_id: open.metadata().schema_id().to_vec(),
            total_len: open.total_len(),
        };
        let durable = DurableProfile5Open {
            open: open.clone(),
            authenticated: publication.authenticated_bytes().to_vec(),
            pack_open: physical_open.open().clone(),
            pack_authenticated: physical_open.authenticated_bytes().to_vec(),
            authenticated_is_publication: true,
        };
        let authenticated_reservation =
            profile5_reservation_from_open(policy, &request, open.initial_custody(), open)?;
        let mut adapter = |reservation: &BlobReservation,
                           existing: Option<&DurableProfile5Open>| {
            if reservation.counter() != open.publisher_counter()
                || reservation.context() != open.causal_context()
                || reservation.initial_custody() != open.initial_custody()
                || existing.is_some_and(|existing| existing != &durable)
            {
                return Err(blob_error(BlobStoreError::OperationConflict));
            }
            Ok(durable.clone())
        };
        let (reservation, checkpoint, restored) = self.reserve_blob_upload_with_policy_impl(
            policy,
            &request,
            Some((
                open.initial_custody(),
                Some(authenticated_reservation),
                &mut adapter,
            )),
        )?;
        let restored = restored.expect("received Profile-5 reservation returns durable authority");
        if restored != durable {
            return Err(blob_error(BlobStoreError::OperationConflict));
        }
        Ok((reservation, checkpoint, physical_open.clone()))
    }

    fn reserve_blob_upload_with_policy_impl(
        &self,
        policy: &ControlPolicySnapshot,
        request: &BlobUploadRequest,
        mut profile5: Option<Profile5Reservation<'_>>,
    ) -> Result<
        (
            BlobUploadReservation,
            BlobUploadCheckpoint,
            Option<DurableProfile5Open>,
        ),
        StoreError,
    > {
        self.require_live()?;
        validate_request(request)?;
        let authority = self.require_bound_mission()?;
        if request.owner.publisher == [0; 32] {
            return Err(blob_error(BlobStoreError::InvalidPublication(
                "Blob upload publisher is invalid",
            )));
        }
        let owner_key = blob_operation_owner_key(&request.owner)?;
        let request_digest = request_digest_for(request)?;
        let (total_capacity, staging_charge_bytes, conversion_overhead_bytes) =
            if profile5.is_some() {
                let capacity = profile5_upload_capacity(request.total_len)?;
                (capacity, capacity.bytes, 0)
            } else {
                (
                    super::depot::blob_upload_capacity(request.total_len)?,
                    super::depot::blob_upload_staging_charge(request.total_len)?,
                    super::depot::blob_upload_conversion_overhead(request.total_len)?,
                )
            };
        let pack_root = PinnedBlobPackRoot::open(self)?;
        let _depot_guard = self
            .blob_depot_lock
            .write()
            .map_err(|_| blob_error(BlobStoreError::DepotIntegrity("depot lock is poisoned")))?;
        self.require_live()?;
        let mut write = self.database.begin_write()?;
        write.set_durability(Durability::Immediate)?;
        enforce_live_write(&write)?;
        synchronize_blob_policy_generation_write(&write)?;
        let content_epoch = require_upload_policy_write(&write, authority, policy, request, None)?;
        let existing_encoded = {
            let uploads = write.open_table(super::BLOB_UPLOADS)?;
            uploads
                .get(owner_key.as_slice())?
                .map(|value| value.value().to_vec())
        };
        if let Some(encoded) = existing_encoded {
            let mut existing =
                DurableBlobUpload::decode(Arc::clone(&self.blob_completion_authority), &encoded)?;
            if existing.reservation.request != *request
                || existing.reservation.request_digest != request_digest
            {
                return Err(blob_error(BlobStoreError::OperationConflict));
            }
            if existing.reservation.control_policy != *policy {
                return Err(blob_error(BlobStoreError::ReservationChanged));
            }
            if existing.format_version == LEGACY_UPLOAD_VERSION {
                let upgraded_capacity = super::depot::blob_upload_capacity(request.total_len)?;
                let upgraded_staging = super::depot::blob_upload_staging_charge(request.total_len)?;
                let additional = upgraded_capacity
                    .bytes
                    .checked_sub(existing.reservation.total_capacity.bytes)
                    .ok_or_else(schema_error)?;
                let current = super::depot::depot_admission_usage_write(&write)?;
                if current
                    .reserved_bytes
                    .checked_add(additional)
                    .ok_or(StoreError::PayloadByteAccountingOverflow)?
                    > self.blob_depot_limits.max_bytes()
                {
                    return Err(blob_error(BlobStoreError::DepotByteLimitExceeded {
                        current: current.reserved_bytes,
                        incoming: additional,
                        limit: self.blob_depot_limits.max_bytes(),
                    }));
                }
                existing.format_version = UPLOAD_VERSION;
                existing.reservation.staging_charge_bytes = upgraded_staging;
                existing.reservation.total_capacity = upgraded_capacity;
                write
                    .open_table(super::BLOB_UPLOADS)?
                    .insert(owner_key.as_slice(), existing.encode()?.as_slice())?;
                write.commit()?;
            }
            let verified = if let Some((_, _, build)) = profile5.as_mut() {
                if existing.format_version != PROFILE5_UPLOAD_VERSION {
                    return Err(blob_error(BlobStoreError::OperationConflict));
                }
                let durable = existing.profile5_open.as_ref().ok_or_else(schema_error)?;
                // A retry observes a later clock sample, but the reservation
                // must retain the initial sample authenticated by its OPEN.
                // Promotion separately checks current custody and expiry.
                let semantic = profile5_reservation_from_open(
                    policy,
                    request,
                    durable.open.initial_custody(),
                    &durable.open,
                )?;
                let restored = build(&semantic, Some(durable))?;
                validate_durable_profile5_authority(
                    request,
                    policy,
                    content_epoch,
                    &semantic,
                    &restored,
                )?;
                if &restored != durable {
                    return Err(blob_error(BlobStoreError::OperationConflict));
                }
                Some(restored)
            } else {
                None
            };
            return Ok((
                reservation_for_store(self, &existing),
                existing.projection()?,
                verified,
            ));
        }
        if write
            .open_table(BLOB_OPERATIONS)?
            .get(owner_key.as_slice())?
            .is_some()
        {
            return Err(blob_error(BlobStoreError::OperationConflict));
        }
        super::lifecycle::require_publication_reservation_capacity(
            &write,
            self.blob_lifecycle_limits,
        )?;
        let current = super::depot::depot_admission_usage_write(&write)?;
        let rows = write.open_table(super::BLOB_UPLOADS)?.len()?;
        if rows >= MAX_UPLOADS {
            return Err(blob_error(BlobStoreError::DepotVariantLimitExceeded {
                current: rows,
                limit: MAX_UPLOADS,
            }));
        }
        if current
            .reserved_bytes
            .checked_add(total_capacity.bytes)
            .ok_or(StoreError::PayloadByteAccountingOverflow)?
            > self.blob_depot_limits.max_bytes()
        {
            return Err(blob_error(BlobStoreError::DepotByteLimitExceeded {
                current: current.reserved_bytes,
                incoming: total_capacity.bytes,
                limit: self.blob_depot_limits.max_bytes(),
            }));
        }
        if current
            .chunks
            .checked_add(total_capacity.chunks)
            .ok_or(StoreError::ItemCountAccountingOverflow)?
            > self.blob_depot_limits.max_chunks()
        {
            return Err(blob_error(BlobStoreError::DepotChunkLimitExceeded {
                current: current.chunks,
                limit: self.blob_depot_limits.max_chunks(),
            }));
        }
        if current
            .variants
            .checked_add(total_capacity.variants)
            .ok_or(StoreError::ItemCountAccountingOverflow)?
            > self.blob_depot_limits.max_variants()
        {
            return Err(blob_error(BlobStoreError::DepotVariantLimitExceeded {
                current: current.variants,
                limit: self.blob_depot_limits.max_variants(),
            }));
        }
        let upload_id = upload_id_for(&request.owner, request_digest)?;
        let mut reservation = BlobUploadReservation {
            request: request.clone(),
            control_policy: *policy,
            content_epoch,
            request_digest,
            upload_id,
            pack_identity: BlobPackIdentity::new(upload_id, request_digest, request.total_len),
            staging_charge_bytes,
            conversion_overhead_bytes,
            total_capacity,
            authority: Arc::clone(&self.blob_completion_authority),
        };
        let (format_version, profile5_open, verified) =
            if let Some((initial_custody, authenticated_reservation, build)) = profile5.as_mut() {
                let mut semantic = if let Some(authenticated) = authenticated_reservation.as_ref() {
                    authenticated.clone()
                } else {
                    self.reserve_blob_with_lifetime_and_sample_write(
                        &write,
                        policy,
                        BlobReservationInputs {
                            publisher: request.owner.publisher,
                            topic: &request.topic,
                            scope: &request.scope,
                            ttl_ms: request.ttl_ms,
                            local_initial_sample: *initial_custody,
                        },
                    )?
                };
                semantic.durable_counter = true;
                let publisher_high = write
                    .open_table(PUBLISHER_HIGH_WATER)?
                    .get(request.owner.publisher.as_slice())?
                    .map_or(0, |value| value.value())
                    .max(semantic.counter());
                write
                    .open_table(PUBLISHER_HIGH_WATER)?
                    .insert(request.owner.publisher.as_slice(), publisher_high)?;
                let durable = build(&semantic, None)?;
                validate_durable_profile5_authority(
                    request,
                    policy,
                    content_epoch,
                    &semantic,
                    &durable,
                )?;
                reservation.pack_identity = BlobPackIdentity::new(
                    durable.pack_open.stream_id(),
                    durable.pack_open.digest(),
                    request.total_len,
                );
                (
                    PROFILE5_UPLOAD_VERSION,
                    Some(durable.clone()),
                    Some(durable),
                )
            } else {
                (UPLOAD_VERSION, None, None)
            };
        let upload = DurableBlobUpload {
            format_version,
            reservation: reservation.clone(),
            checkpoint: None,
            consumed: BlobUploadCapacity::default(),
            bound_variant: None,
            profile5_open,
            profile5_completion: None,
        };
        // A previous crash may have committed removal of this deterministic
        // upload while leaving only its physical cleanup tombstone.  The row
        // absence checked above makes removing that tombstone safe before the
        // same immutable request creates a new pack.
        super::pack::finish_upload_pack_cleanup(&pack_root, &reservation.pack_identity())
            .map_err(upload_pack_store_error)?;
        super::pack::stage_upload_pack_reservation(&pack_root, &reservation.pack_identity())
            .map_err(upload_pack_store_error)?;
        #[cfg(test)]
        maybe_inject_test_fault(self, UploadFaultPoint::ReservationIntentSynced)?;
        drop(
            super::pack::BlobPackWriter::create_upload_pinned(
                &pack_root,
                &reservation.pack_identity(),
            )
            .map_err(upload_pack_store_error)?,
        );
        #[cfg(test)]
        maybe_inject_test_fault(self, UploadFaultPoint::ReservationPackSynced)?;
        write
            .open_table(super::BLOB_UPLOADS)?
            .insert(owner_key.as_slice(), upload.encode()?.as_slice())?;
        write.commit()?;
        super::pack::finish_upload_pack_reservation(&pack_root, &reservation.pack_identity())
            .map_err(upload_pack_store_error)?;
        Ok((reservation, upload.projection()?, verified))
    }

    pub fn checkpoint_blob_upload(
        &self,
        policy: &ControlPolicySnapshot,
        reservation: &BlobUploadReservation,
        expected: BlobUploadCheckpoint,
        durable: BlobPackCheckpoint,
    ) -> Result<BlobUploadCheckpoint, StoreError> {
        self.require_live()?;
        let authority = self.require_bound_mission()?;
        let owner_key = validate_reservation_capability(self, reservation)?;
        let mut write = self.database.begin_write()?;
        write.set_durability(Durability::Immediate)?;
        enforce_live_write(&write)?;
        synchronize_blob_policy_generation_write(&write)?;
        if reservation.control_policy != *policy {
            return Err(blob_error(BlobStoreError::ReservationChanged));
        }
        require_upload_policy_write(
            &write,
            authority,
            policy,
            &reservation.request,
            Some(reservation.content_epoch),
        )?;
        let encoded = write
            .open_table(super::BLOB_UPLOADS)?
            .get(owner_key.as_slice())?
            .map(|value| value.value().to_vec())
            .ok_or_else(|| blob_error(BlobStoreError::ReservationChanged))?;
        let mut upload =
            DurableBlobUpload::decode(Arc::clone(&self.blob_completion_authority), &encoded)?;
        if reservation_for_store(self, &upload) != *reservation
            || upload.projection()? != expected
            || durable.upload_id() != reservation.pack_identity.upload_id()
            || durable.request_digest() != reservation.pack_identity.request_digest()
            || durable.total_len() != reservation.pack_identity.total_len()
            || !durable.is_bound_to(&self.blob_completion_authority)
        {
            return Err(blob_error(BlobStoreError::ReservationChanged));
        }
        if let Some(current) = upload.checkpoint.as_ref() {
            if current == &durable {
                return upload.projection();
            }
            if durable.generation()
                != current
                    .generation()
                    .checked_add(1)
                    .ok_or_else(schema_error)?
                || durable.next_index() < current.next_index()
                || durable.plaintext_offset() < current.plaintext_offset()
                || durable.pack_len() < current.pack_len()
            {
                return Err(blob_error(BlobStoreError::ReservationChanged));
            }
        }
        upload.checkpoint = Some(durable);
        let projection = upload.projection()?;
        write
            .open_table(super::BLOB_UPLOADS)?
            .insert(owner_key.as_slice(), upload.encode()?.as_slice())?;
        #[cfg(test)]
        maybe_inject_test_fault(self, UploadFaultPoint::CheckpointBeforeCommit)?;
        write.commit()?;
        Ok(projection)
    }

    /// Installs the authenticated final commitment for the exact completed
    /// Profile-5 upload pack. The pack remains provisional and invisible; a
    /// later lifecycle transaction promotes this same physical representation.
    pub fn complete_profile5_upload_pack(
        &self,
        policy: &ControlPolicySnapshot,
        reservation: &BlobUploadReservation,
        expected: BlobUploadCheckpoint,
        completion: BlobPackCompletion,
        commitment: &VerifiedBlobStreamFinalCommitment,
        lineage: BlobStreamLineage,
    ) -> Result<BlobUploadCheckpoint, StoreError> {
        self.require_live()?;
        let authority = self.require_bound_mission()?;
        let owner_key = validate_reservation_capability(self, reservation)?;
        if !completion.is_bound_to(&self.blob_completion_authority) {
            return Err(blob_error(BlobStoreError::CompletionMismatch));
        }
        let pack_root = PinnedBlobPackRoot::open(self)?;
        drop(
            BlobPackReader::open_completed_upload_pinned(&pack_root, &completion)
                .map_err(upload_pack_store_error)?,
        );
        let _depot_guard = self
            .blob_depot_lock
            .write()
            .map_err(|_| blob_error(BlobStoreError::DepotIntegrity("depot lock is poisoned")))?;
        self.require_live()?;
        let mut write = self.database.begin_write()?;
        write.set_durability(Durability::Immediate)?;
        enforce_live_write(&write)?;
        synchronize_blob_policy_generation_write(&write)?;
        if reservation.control_policy != *policy {
            return Err(blob_error(BlobStoreError::ReservationChanged));
        }
        require_upload_policy_write(
            &write,
            authority,
            policy,
            &reservation.request,
            Some(reservation.content_epoch),
        )?;
        let encoded = write
            .open_table(super::BLOB_UPLOADS)?
            .get(owner_key.as_slice())?
            .map(|value| value.value().to_vec())
            .ok_or_else(|| blob_error(BlobStoreError::ReservationChanged))?;
        let mut upload =
            DurableBlobUpload::decode(Arc::clone(&self.blob_completion_authority), &encoded)?;
        if reservation_for_store(self, &upload) != *reservation {
            return Err(blob_error(BlobStoreError::ReservationChanged));
        }
        let profile5 = upload.profile5_open.as_ref().ok_or_else(schema_error)?;
        let final_commitment = commitment.commitment();
        let durable = upload
            .checkpoint
            .as_ref()
            .ok_or_else(|| blob_error(BlobStoreError::CompletionMismatch))?;
        let mut candidate = BlobProfile5UploadCompletion {
            candidate_pack: completion.clone(),
            pack: completion,
            commitment: final_commitment.clone(),
            authenticated_commitment: commitment.authenticated_bytes().to_vec(),
        };
        if upload.projection()? != expected
            || candidate.authenticated_commitment.is_empty()
            || candidate.candidate_pack.identity() != reservation.pack_identity
            || candidate.candidate_pack.checkpoint() != durable
            || final_commitment.open_digest() != &profile5.pack_open.digest()
            || final_commitment.stream_id() != profile5.pack_open.stream_id()
            || final_commitment.total_len() != profile5.pack_open.total_len()
            || final_commitment.content_epoch() != profile5.pack_open.content_epoch()
            || final_commitment.ttl_ms() != profile5.pack_open.ttl_ms()
            || final_commitment.segment_count() != durable.next_index()
            || durable.plaintext_offset() != profile5.pack_open.total_len()
            || final_commitment.plaintext_root() != candidate.candidate_pack.plaintext_root()
            || final_commitment.ciphertext_root() != candidate.candidate_pack.ciphertext_root()
            || final_commitment.blob_id() != candidate.candidate_pack.blob_id()
            || Sha256::digest(final_commitment.encode()).as_slice()
                != candidate.candidate_pack.commitment_digest()
            || Sha256::digest(&candidate.authenticated_commitment).as_slice()
                != candidate.candidate_pack.authenticated_commitment_digest()
        {
            return Err(blob_error(BlobStoreError::CompletionMismatch));
        }
        let owner_binding = super::depot::require_depot_owner_binding_write(
            &write,
            &self.path,
            self.backing_identity,
            self.blob_depot_owner_token,
        )?;
        let pack = super::pack_lifecycle::BlobPackVariant::new(
            lineage.route(),
            lineage.physical(),
            owner_binding,
            profile5.pack_open.clone(),
            profile5.pack_authenticated.clone(),
            final_commitment.clone(),
            candidate.authenticated_commitment.clone(),
            candidate.candidate_pack.clone(),
            reservation.total_capacity,
            Arc::clone(&self.blob_completion_authority),
        )?;
        let existing = super::pack_lifecycle::load_write(
            &write,
            pack.variant_id(),
            Arc::clone(&self.blob_completion_authority),
        )?;
        let reused = if let Some(existing) = existing {
            if !existing.lifecycle_owned()
                || existing.physical_lineage() != pack.physical_lineage()
                || existing.commitment().blob_id() != final_commitment.blob_id()
                || existing.open().content_group() != profile5.pack_open.content_group()
                || existing.open().content_epoch() != profile5.pack_open.content_epoch()
                || existing.open().total_len() != profile5.pack_open.total_len()
                || existing.open().metadata() != profile5.pack_open.metadata()
            {
                return Err(blob_error(BlobStoreError::PhysicalLineageConflict));
            }
            candidate.pack = existing.completion().clone();
            true
        } else {
            super::pack_lifecycle::insert_write(&write, &pack)?;
            false
        };
        if upload
            .profile5_completion
            .as_ref()
            .is_some_and(|existing| existing != &candidate)
        {
            return Err(blob_error(BlobStoreError::CompletionMismatch));
        }
        upload.profile5_completion = Some(candidate);
        let projection = upload.projection()?;
        write
            .open_table(super::BLOB_UPLOADS)?
            .insert(owner_key.as_slice(), upload.encode()?.as_slice())?;
        write.commit()?;
        if reused {
            // The committed reuse completion authorizes candidate removal.
            // An upload-cleanup marker would instead authorize recovery to
            // delete the still-pending semantic publication and its reservation.
            remove_upload_pack(&pack_root, &reservation.pack_identity())
                .map_err(upload_pack_store_error)?;
        }
        Ok(projection)
    }

    /// Returns the physical lineage selected for a completed semantic
    /// publication. Exact physical bytes remain nested transfer authority and
    /// are deliberately not part of the semantic publication binding.
    pub fn profile5_upload_publication_binding(
        &self,
        reservation: &BlobUploadReservation,
        expected: &BlobUploadCheckpoint,
    ) -> Result<[u8; 32], StoreError> {
        self.require_live()?;
        let owner_key = validate_reservation_capability(self, reservation)?;
        let read = self.database.begin_read()?;
        let encoded = read
            .open_table(super::BLOB_UPLOADS)?
            .get(owner_key.as_slice())?
            .map(|value| value.value().to_vec())
            .ok_or_else(|| blob_error(BlobStoreError::ReservationChanged))?;
        let upload =
            DurableBlobUpload::decode(Arc::clone(&self.blob_completion_authority), &encoded)?;
        if reservation_for_store(self, &upload) != *reservation || upload.projection()? != *expected
        {
            return Err(blob_error(BlobStoreError::ReservationChanged));
        }
        let profile5 = upload.profile5_open.as_ref().ok_or_else(schema_error)?;
        let completion = upload
            .profile5_completion
            .as_ref()
            .ok_or_else(schema_error)?;
        let variant = super::blob_variant_id(
            completion.commitment.blob_id(),
            &profile5.pack_open.content_group(),
            profile5.pack_open.content_epoch(),
        );
        let pack = super::pack_lifecycle::load_read(
            &read,
            variant,
            Arc::clone(&self.blob_completion_authority),
        )?
        .ok_or_else(schema_error)?;
        Ok(*pack.physical_lineage())
    }

    pub fn resume_blob_upload(
        &self,
        owner: &BlobOperationOwner,
    ) -> Result<Option<(BlobUploadReservation, BlobUploadCheckpoint)>, StoreError> {
        self.require_live()?;
        self.require_bound_mission()?;
        let owner_key = blob_operation_owner_key(owner)?;
        let read = self.database.begin_read()?;
        let encoded = read
            .open_table(super::BLOB_UPLOADS)?
            .get(owner_key.as_slice())?
            .map(|value| value.value().to_vec());
        encoded
            .map(|encoded| {
                let upload = DurableBlobUpload::decode(
                    Arc::clone(&self.blob_completion_authority),
                    &encoded,
                )?;
                Ok((reservation_for_store(self, &upload), upload.projection()?))
            })
            .transpose()
    }

    /// Resolves one in-progress upload by its stable local application token.
    /// The bounded upload table remains the sole durable provisional authority.
    pub fn resume_blob_upload_by_publication_id(
        &self,
        publication_id: BlobPublicationStreamId,
    ) -> Result<Option<(BlobUploadReservation, BlobUploadCheckpoint)>, StoreError> {
        self.require_live()?;
        self.require_bound_mission()?;
        let read = self.database.begin_read()?;
        let mut matched = None;
        for row in read.open_table(super::BLOB_UPLOADS)?.iter()? {
            let (_, value) = row?;
            let upload = DurableBlobUpload::decode(
                Arc::clone(&self.blob_completion_authority),
                value.value(),
            )?;
            let owner = &upload.reservation.request.owner;
            if local_blob_publication_stream_id(owner.publisher, owner.operation.as_bytes())
                != publication_id
            {
                continue;
            }
            if matched.is_some() {
                return Err(schema_error());
            }
            matched = Some((reservation_for_store(self, &upload), upload.projection()?));
        }
        Ok(matched)
    }

    pub fn commit_profile5_publication_once_with_policy(
        &self,
        policy: &ControlPolicySnapshot,
        reservation: &BlobUploadReservation,
        expected: &BlobUploadCheckpoint,
        publication: &VerifiedBlobStreamPublication,
        precommit_sample: Option<aster_mesh::CustodySample>,
    ) -> Result<super::BlobOnceOutcome, StoreError> {
        self.commit_profile5_upload_once_with_lifetime(
            policy,
            reservation,
            expected,
            publication,
            Profile5PromotionLifetime::Local(precommit_sample),
        )
    }

    /// Promotes a received finite native pack using only authenticated v9
    /// custody authority and a receiver-local monotonic clock sample.
    #[doc(hidden)]
    pub fn commit_received_profile5_upload_once_with_policy(
        &self,
        policy: &ControlPolicySnapshot,
        reservation: &BlobUploadReservation,
        expected: &BlobUploadCheckpoint,
        publication: &VerifiedBlobStreamPublication,
        lifetime: ReceivedProfile5FinitePromotion,
    ) -> Result<super::BlobOnceOutcome, StoreError> {
        self.commit_profile5_upload_once_with_lifetime(
            policy,
            reservation,
            expected,
            publication,
            Profile5PromotionLifetime::Network(
                super::VerifiedFiniteBlobAdmission::from_verified_v2_elapsed(
                    lifetime.verified,
                    lifetime.received_sample,
                    lifetime.promotion_sample,
                )?,
            ),
        )
    }

    /// Promotes a received durable native pack using its authenticated remote
    /// semantic publication. Unlike local publication, the remote dot and
    /// causal context were reserved from the signed OPEN rather than allocated
    /// by this store.
    #[doc(hidden)]
    pub fn commit_received_durable_profile5_upload_once_with_policy(
        &self,
        policy: &ControlPolicySnapshot,
        reservation: &BlobUploadReservation,
        expected: &BlobUploadCheckpoint,
        publication: &VerifiedBlobStreamPublication,
    ) -> Result<super::BlobOnceOutcome, StoreError> {
        self.commit_profile5_upload_once_with_lifetime(
            policy,
            reservation,
            expected,
            publication,
            Profile5PromotionLifetime::NetworkDurable,
        )
    }

    fn commit_profile5_upload_once_with_lifetime(
        &self,
        policy: &ControlPolicySnapshot,
        reservation: &BlobUploadReservation,
        expected: &BlobUploadCheckpoint,
        publication: &VerifiedBlobStreamPublication,
        lifetime_authority: Profile5PromotionLifetime,
    ) -> Result<super::BlobOnceOutcome, StoreError> {
        self.require_live()?;
        let authority = self.require_bound_mission()?;
        let owner_key = validate_reservation_capability(self, reservation)?;
        let lifetime_shape_matches = match &lifetime_authority {
            Profile5PromotionLifetime::Local(precommit_sample) => {
                reservation.request.ttl_ms.is_some() == precommit_sample.is_some()
            }
            Profile5PromotionLifetime::NetworkDurable => reservation.request.ttl_ms.is_none(),
            Profile5PromotionLifetime::Network(admission) => {
                reservation.request.ttl_ms == Some(admission.ttl_ms)
            }
        };
        if reservation.control_policy != *policy || !lifetime_shape_matches {
            return Err(blob_error(BlobStoreError::ReservationChanged));
        }
        let completion = expected
            .profile5_completion()
            .ok_or_else(|| blob_error(BlobStoreError::CompletionMismatch))?;
        let pack_root = PinnedBlobPackRoot::open(self)?;
        drop(
            BlobPackReader::open_completed_upload_pinned(&pack_root, completion.pack())
                .map_err(upload_pack_store_error)?,
        );
        let _depot_guard = self
            .blob_depot_lock
            .write()
            .map_err(|_| blob_error(BlobStoreError::DepotIntegrity("depot lock is poisoned")))?;
        self.require_live()?;
        let mut write = self.database.begin_write()?;
        write.set_durability(Durability::Immediate)?;
        enforce_live_write(&write)?;
        synchronize_blob_policy_generation_write(&write)?;
        require_upload_policy_write(
            &write,
            authority,
            policy,
            &reservation.request,
            Some(reservation.content_epoch),
        )?;
        let encoded = write
            .open_table(super::BLOB_UPLOADS)?
            .get(owner_key.as_slice())?
            .map(|value| value.value().to_vec());
        let Some(encoded) = encoded else {
            drop(write);
            let blob = self
                .blob_for_owner_with_policy(policy, &reservation.request.owner)?
                .ok_or_else(|| blob_error(BlobStoreError::ReservationChanged))?;
            let read = self.database.begin_read()?;
            let pack = super::pack_lifecycle::load_read(
                &read,
                blob.variant_id,
                Arc::clone(&self.blob_completion_authority),
            )?
            .ok_or_else(|| blob_error(BlobStoreError::CompletionMismatch))?;
            let (transfer_id, semantic_id, variant_id, expected_source) =
                super::profile5_publication_identities(publication, &pack)?;
            if blob.transfer_id != transfer_id
                || blob.semantic_id != semantic_id
                || blob.variant_id != variant_id
            {
                return Err(blob_error(BlobStoreError::OperationConflict));
            }
            if pack.completion() != completion.pack()
                || blob.blob_id != completion.commitment().blob_id()
                || blob.header.stamp.dot.publisher != reservation.request.owner.publisher
                || blob.header.topic != reservation.request.topic
                || blob.header.scope != reservation.request.scope
                || blob.header.priority != reservation.request.priority
                || blob.header.ttl_ms != reservation.request.ttl_ms
                || blob.header.key_epoch != reservation.content_epoch
                || pack.open().total_len() != reservation.request.total_len
                || pack.open().metadata()
                    != &BlobMetadata::new(
                        reservation.request.media_type.clone(),
                        reservation.request.schema_id.clone(),
                    )
                    .map_err(|_| schema_error())?
                || blob.sealed != expected_source
            {
                return Err(blob_error(BlobStoreError::OperationConflict));
            }
            return Ok(super::BlobOnceOutcome::Existing { blob });
        };
        let upload =
            DurableBlobUpload::decode(Arc::clone(&self.blob_completion_authority), &encoded)?;
        if reservation_for_store(self, &upload) != *reservation || upload.projection()? != *expected
        {
            return Err(blob_error(BlobStoreError::ReservationChanged));
        }
        let profile5 = upload.profile5_open.as_ref().ok_or_else(schema_error)?;
        match &lifetime_authority {
            Profile5PromotionLifetime::Local(precommit_sample) => {
                if profile5.authenticated_is_publication
                    || publication.publication().open() != &profile5.open
                    || publication.publication().final_custody() != *precommit_sample
                {
                    return Err(blob_error(BlobStoreError::CompletionMismatch));
                }
            }
            Profile5PromotionLifetime::NetworkDurable => {
                if !profile5.authenticated_is_publication
                    || publication.authenticated_bytes() != profile5.authenticated
                {
                    return Err(blob_error(BlobStoreError::CompletionMismatch));
                }
            }
            Profile5PromotionLifetime::Network(_) => {
                if !profile5.authenticated_is_publication
                    || publication.authenticated_bytes() != profile5.authenticated
                {
                    return Err(blob_error(BlobStoreError::CompletionMismatch));
                }
            }
        }
        let blob_reservation = profile5_reservation_from_open(
            policy,
            &reservation.request,
            profile5.open.initial_custody(),
            &profile5.open,
        )?;
        let variant = super::blob_variant_id(
            completion.commitment().blob_id(),
            &profile5.pack_open.content_group(),
            profile5.pack_open.content_epoch(),
        );
        let pack = super::pack_lifecycle::load_write(
            &write,
            variant,
            Arc::clone(&self.blob_completion_authority),
        )?
        .ok_or_else(schema_error)?;
        if pack.completion() != completion.pack()
            || completion.reuses_existing_pack() != pack.lifecycle_owned()
            || (!completion.reuses_existing_pack() && pack.open() != &profile5.pack_open)
        {
            return Err(blob_error(BlobStoreError::CompletionMismatch));
        }
        let (lifetime, local_samples) = match lifetime_authority {
            Profile5PromotionLifetime::Local(precommit_sample) => {
                let lifetime = match profile5.open.ttl_ms() {
                    None => super::BlobLifetime::Durable,
                    Some(ttl_ms) => super::BlobLifetime::Finite {
                        ttl_ms,
                        age: super::custody::LowerBoundAgeCheckpoint {
                            cumulative_age_ms: 0,
                            checkpoint: None,
                            continuity_generation: 0,
                            continuity_lost: true,
                        },
                        provenance: super::BlobFiniteProvenance::Local,
                    },
                };
                (
                    lifetime,
                    profile5.open.initial_custody().zip(precommit_sample),
                )
            }
            Profile5PromotionLifetime::NetworkDurable => (super::BlobLifetime::Durable, None),
            Profile5PromotionLifetime::Network(admission) => {
                let (_, _, _, source) = super::profile5_publication_source_identities(
                    publication,
                    &profile5.pack_open,
                    &profile5.pack_authenticated,
                    completion.commitment(),
                    completion.authenticated_commitment(),
                )?;
                (
                    received_profile5_lifetime_write(&write, publication, &source, admission)?,
                    None,
                )
            }
        };
        if publication.publication().open() != &profile5.open
            || publication.publication().blob_id() != completion.commitment().blob_id()
        {
            return Err(blob_error(BlobStoreError::CompletionMismatch));
        }
        let prepared = super::PreparedBlobPublication::from_profile5_publication(
            &pack,
            publication,
            lifetime,
        )?;
        let intent = super::BlobPublicationIntent::new_with_ttl(
            reservation.request.owner.publisher,
            reservation.request.topic.clone(),
            reservation.request.scope.clone(),
            reservation.request.priority,
            completion.commitment().blob_id(),
            reservation.request.ttl_ms,
        )?;
        let request =
            super::BlobOperationRequest::new(&reservation.request.owner.operation, &intent);
        super::validate_blob_reservation(&blob_reservation, &prepared)?;
        super::validate_blob_publication_intent(&intent, &prepared)?;
        self.commit_prepared_blob_once_with_lifetime_write(
            write,
            policy,
            &request,
            &blob_reservation,
            prepared,
            local_samples,
            true,
        )
    }

    /// Accepts a new received publication using an already retained, leased
    /// native pack. No duplicate upload, file, or capacity reservation is made.
    #[doc(hidden)]
    pub fn commit_received_existing_profile5_pack_with_policy(
        &self,
        policy: &ControlPolicySnapshot,
        inbound: &VerifiedBlobStreamPublicationSource,
        retained: &super::Profile5PackReadSession,
        finite: Option<ReceivedProfile5FinitePromotion>,
    ) -> Result<super::BlobOnceOutcome, StoreError> {
        self.require_live()?;
        let authority = self.require_bound_mission()?;
        if !retained.is_bound_to(&self.blob_completion_authority) {
            return Err(blob_error(BlobStoreError::CompletionMismatch));
        }
        let publication = inbound.publication();
        let open = publication.publication().open();
        let request = BlobUploadRequest {
            owner: super::BlobOperationOwner::new(
                open.publisher(),
                super::BlobOperationKey::new(open.operation_key().to_vec())?,
            ),
            topic: open.topic().clone(),
            scope: open.scope().clone(),
            priority: open.priority(),
            ttl_ms: open.ttl_ms(),
            media_type: open.metadata().media_type().map(str::to_owned),
            schema_id: open.metadata().schema_id().to_vec(),
            total_len: open.total_len(),
        };
        validate_request(&request)?;
        let owner_key = blob_operation_owner_key(&request.owner)?;
        let (_, _, variant, source) = super::profile5_publication_source_identities(
            publication,
            inbound.physical_open().open(),
            inbound.physical_open().authenticated_bytes(),
            inbound.physical_commitment().commitment(),
            inbound.physical_commitment().authenticated_bytes(),
        )?;
        let _depot_guard = self
            .blob_depot_lock
            .write()
            .map_err(|_| blob_error(BlobStoreError::DepotIntegrity("depot lock is poisoned")))?;
        let mut write = self.database.begin_write()?;
        write.set_durability(Durability::Immediate)?;
        enforce_live_write(&write)?;
        let epoch = require_upload_policy_write(
            &write,
            authority,
            policy,
            &request,
            Some(open.content_epoch()),
        )?;
        validate_profile5_open_shape(&request, policy, epoch, open)?;
        if write
            .open_table(super::BLOB_UPLOADS)?
            .get(owner_key.as_slice())?
            .is_some()
        {
            return Err(blob_error(BlobStoreError::ReservationChanged));
        }
        let pack = super::pack_lifecycle::load_write(
            &write,
            variant,
            Arc::clone(&self.blob_completion_authority),
        )?
        .ok_or_else(|| blob_error(BlobStoreError::NotFound))?;
        if !pack.lifecycle_owned()
            || pack.open() != retained.open()
            || pack.authenticated_open() != retained.authenticated_open()
            || pack.commitment() != retained.commitment()
            || pack.authenticated_commitment() != retained.authenticated_commitment()
            || pack.physical_lineage() != retained.physical_lineage()
        {
            return Err(blob_error(BlobStoreError::CompletionMismatch));
        }
        let lifetime = match (open.ttl_ms(), finite) {
            (None, None) => super::BlobLifetime::Durable,
            (Some(_), Some(finite)) => received_profile5_lifetime_write(
                &write,
                publication,
                &source,
                super::VerifiedFiniteBlobAdmission::from_verified_v2_elapsed(
                    finite.verified,
                    finite.received_sample,
                    finite.promotion_sample,
                )?,
            )?,
            _ => return Err(blob_error(BlobStoreError::CompletionMismatch)),
        };
        let prepared = super::PreparedBlobPublication::from_profile5_publication(
            &pack,
            publication,
            lifetime,
        )?;
        if let Some(existing) = write
            .open_table(BLOB_OPERATIONS)?
            .get(owner_key.as_slice())?
            .map(|value| decode_blob_operation_record(value.value()))
            .transpose()?
            && existing.transfer_id != prepared.transfer_id
        {
            return Err(blob_error(BlobStoreError::OperationConflict));
        }
        let intent = super::BlobPublicationIntent::new_with_ttl(
            open.publisher(),
            open.topic().clone(),
            open.scope().clone(),
            open.priority(),
            publication.publication().blob_id(),
            open.ttl_ms(),
        )?;
        let operation = super::BlobOperationRequest::new(&request.owner.operation, &intent);
        let reservation =
            profile5_reservation_from_open(policy, &request, open.initial_custody(), open)?;
        super::validate_blob_reservation(&reservation, &prepared)?;
        super::validate_blob_publication_intent(&intent, &prepared)?;
        let high_water = write
            .open_table(PUBLISHER_HIGH_WATER)?
            .get(open.publisher().as_slice())?
            .map_or(0, |value| value.value())
            .max(open.publisher_counter());
        write
            .open_table(PUBLISHER_HIGH_WATER)?
            .insert(open.publisher().as_slice(), high_water)?;
        self.commit_prepared_blob_once_with_lifetime_write(
            write,
            policy,
            &operation,
            &reservation,
            prepared,
            None,
            false,
        )
    }

    pub fn complete_blob_upload(
        &self,
        reservation: &BlobUploadReservation,
        publication: BlobTransferId,
    ) -> Result<(), StoreError> {
        self.require_live()?;
        let owner_key = validate_reservation_capability(self, reservation)?;
        let pack_root = PinnedBlobPackRoot::open(self)?;
        let _depot_guard = self
            .blob_depot_lock
            .write()
            .map_err(|_| blob_error(BlobStoreError::DepotIntegrity("depot lock is poisoned")))?;
        self.require_live()?;
        let mut write = self.database.begin_write()?;
        write.set_durability(Durability::Immediate)?;
        enforce_live_write(&write)?;
        let encoded = write
            .open_table(super::BLOB_UPLOADS)?
            .get(owner_key.as_slice())?
            .map(|value| value.value().to_vec());
        let Some(encoded) = encoded else {
            let operation = write
                .open_table(BLOB_OPERATIONS)?
                .get(owner_key.as_slice())?
                .map(|value| decode_blob_operation_record(value.value()))
                .transpose()?;
            return if operation.is_some_and(|operation| operation.transfer_id == publication) {
                super::pack::finish_upload_pack_cleanup(&pack_root, &reservation.pack_identity())
                    .map_err(upload_pack_store_error)
            } else {
                Err(blob_error(BlobStoreError::ReservationChanged))
            };
        };
        let upload =
            DurableBlobUpload::decode(Arc::clone(&self.blob_completion_authority), &encoded)?;
        if reservation_for_store(self, &upload) != *reservation {
            return Err(blob_error(BlobStoreError::ReservationChanged));
        }
        let operation = write
            .open_table(BLOB_OPERATIONS)?
            .get(owner_key.as_slice())?
            .map(|value| decode_blob_operation_record(value.value()))
            .transpose()?
            .ok_or_else(|| blob_error(BlobStoreError::CompletionMismatch))?;
        let metadata = write
            .open_table(BLOB_PUBLICATIONS)?
            .get(publication.as_bytes().as_slice())?
            .map(|value| decode_blob_metadata(value.value()))
            .transpose()?
            .ok_or_else(|| blob_error(BlobStoreError::CompletionMismatch))?;
        if operation.transfer_id != publication
            || metadata.header.stamp.dot.publisher != reservation.request.owner.publisher
            || metadata.header.topic != reservation.request.topic
            || metadata.header.scope != reservation.request.scope
            || metadata.header.priority != reservation.request.priority
            || metadata.header.ttl_ms != reservation.request.ttl_ms
            || metadata.header.key_epoch != reservation.content_epoch
            || upload.bound_variant != Some(metadata.variant_id)
        {
            return Err(blob_error(BlobStoreError::CompletionMismatch));
        }
        super::pack::stage_upload_pack_cleanup(&pack_root, &reservation.pack_identity())
            .map_err(upload_pack_store_error)?;
        remove_upload_pack(&pack_root, &reservation.pack_identity())
            .map_err(upload_pack_store_error)?;
        remove_profile5_pack_write(&write, &upload)?;
        write
            .open_table(super::BLOB_UPLOADS)?
            .remove(owner_key.as_slice())?;
        write.commit()?;
        super::pack::finish_upload_pack_cleanup(&pack_root, &reservation.pack_identity())
            .map_err(upload_pack_store_error)
    }

    pub fn abort_blob_upload(
        &self,
        reservation: &BlobUploadReservation,
    ) -> Result<bool, StoreError> {
        self.require_live()?;
        let owner_key = validate_reservation_capability(self, reservation)?;
        let pack_root = PinnedBlobPackRoot::open(self)?;
        let _depot_guard = self
            .blob_depot_lock
            .write()
            .map_err(|_| blob_error(BlobStoreError::DepotIntegrity("depot lock is poisoned")))?;
        self.require_live()?;
        let mut write = self.database.begin_write()?;
        write.set_durability(Durability::Immediate)?;
        enforce_live_write(&write)?;
        let encoded = write
            .open_table(super::BLOB_UPLOADS)?
            .get(owner_key.as_slice())?
            .map(|value| value.value().to_vec());
        let Some(encoded) = encoded else {
            super::pack::finish_upload_pack_cleanup(&pack_root, &reservation.pack_identity())
                .map_err(upload_pack_store_error)?;
            return Ok(false);
        };
        let upload =
            DurableBlobUpload::decode(Arc::clone(&self.blob_completion_authority), &encoded)?;
        if reservation_for_store(self, &upload) != *reservation {
            return Err(blob_error(BlobStoreError::ReservationChanged));
        }
        super::pack::stage_upload_pack_cleanup(&pack_root, &reservation.pack_identity())
            .map_err(upload_pack_store_error)?;
        remove_upload_pack(&pack_root, &reservation.pack_identity())
            .map_err(upload_pack_store_error)?;
        remove_profile5_pack_write(&write, &upload)?;
        write
            .open_table(super::BLOB_UPLOADS)?
            .remove(owner_key.as_slice())?;
        write.commit()?;
        super::pack::finish_upload_pack_cleanup(&pack_root, &reservation.pack_identity())
            .map_err(upload_pack_store_error)?;
        Ok(true)
    }
}

fn encode_capacity(output: &mut Vec<u8>, capacity: BlobUploadCapacity) {
    output.extend_from_slice(&capacity.bytes.to_be_bytes());
    output.extend_from_slice(&capacity.chunks.to_be_bytes());
    output.extend_from_slice(&capacity.variants.to_be_bytes());
}

fn decode_capacity(cursor: &mut UploadCursor<'_>) -> Result<BlobUploadCapacity, StoreError> {
    Ok(BlobUploadCapacity {
        bytes: cursor.u64()?,
        chunks: cursor.u64()?,
        variants: cursor.u64()?,
    })
}

fn push_u16_bytes(output: &mut Vec<u8>, bytes: &[u8]) -> Result<(), StoreError> {
    let len = u16::try_from(bytes.len()).map_err(|_| schema_error())?;
    output.extend_from_slice(&len.to_be_bytes());
    output.extend_from_slice(bytes);
    Ok(())
}

struct UploadCursor<'a> {
    bytes: &'a [u8],
    offset: usize,
}

impl<'a> UploadCursor<'a> {
    const fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, offset: 0 }
    }

    fn take(&mut self, len: usize) -> Result<&'a [u8], StoreError> {
        let end = self.offset.checked_add(len).ok_or_else(schema_error)?;
        let value = self.bytes.get(self.offset..end).ok_or_else(schema_error)?;
        self.offset = end;
        Ok(value)
    }

    fn array<const N: usize>(&mut self) -> Result<[u8; N], StoreError> {
        self.take(N)?.try_into().map_err(|_| schema_error())
    }

    fn u8(&mut self) -> Result<u8, StoreError> {
        Ok(self.array::<1>()?[0])
    }

    fn u16(&mut self) -> Result<u16, StoreError> {
        Ok(u16::from_be_bytes(self.array()?))
    }

    fn u32(&mut self) -> Result<u32, StoreError> {
        Ok(u32::from_be_bytes(self.array()?))
    }

    fn u64(&mut self) -> Result<u64, StoreError> {
        Ok(u64::from_be_bytes(self.array()?))
    }

    fn short(&mut self) -> Result<&'a [u8], StoreError> {
        let len = usize::from(self.u16()?);
        self.take(len)
    }

    fn finish(self) -> Result<(), StoreError> {
        if self.offset == self.bytes.len() {
            Ok(())
        } else {
            Err(schema_error())
        }
    }
}

fn schema_error() -> StoreError {
    blob_error(BlobStoreError::SchemaInvariant(
        "provisional Blob upload row is malformed",
    ))
}

fn upload_pack_store_error(error: BlobPackError) -> StoreError {
    match error {
        BlobPackError::Store(error) => error,
        BlobPackError::Io(error) => blob_error(BlobStoreError::Io(error)),
        BlobPackError::Invalid(message) => blob_error(BlobStoreError::DepotIntegrity(message)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::blob::pack::{BlobPackError, BlobPackReader, BlobPackWriter, PinnedBlobPackRoot};
    use crate::{
        BlobDeliveryAck, BlobDepotLimits, BlobOperationKey, BlobOperationOwner,
        BlobOperationRequest, BlobPublicationIntent, BlobSubscriptionKey,
        BlobSubscriptionPollSelection, BlobSubscriptionSpec, Store, StoreLimits, StoredBlob,
    };
    use aster_mesh::{
        BLOB_STREAM_SEGMENT_ENCODED_OVERHEAD_BYTES, BlobContentVerification, BlobMetadata,
        BlobStreamFrontier, BlobStreamOpen, BlobStreamPlainPartition, BlobStreamPublication,
        BlobStreamSegmentLeaves, BlobStreamSegmentOpener, BlobStreamSegmentSealer,
        BlobStreamSubtree, CustodySample, EncryptedBlobStreamSegment, EventContentVerification,
        Priority, ProvisioningAccess, ReferenceEnvelopeSealer, ReferenceProvisioner, Scope, Topic,
        VerifiedBlobStreamFinalCommitment, VerifiedBlobStreamPublication, VersionVector,
        prepare_blob,
    };
    use std::fs::{self, OpenOptions};
    use std::io::{Cursor, Read, Seek, SeekFrom, Write};
    use std::path::{Path, PathBuf};
    use std::sync::atomic::{AtomicU64, Ordering};

    type UploadPackTreeSnapshot = Option<Vec<(String, Option<Vec<u8>>)>>;

    static NEXT_ROOT: AtomicU64 = AtomicU64::new(1);

    struct UploadPackPlainReader {
        root: PinnedBlobPackRoot,
        identity: BlobPackIdentity,
        checkpoint: BlobPackCheckpoint,
        pack: BlobPackReader,
        opener: BlobStreamSegmentOpener,
        plaintext: Cursor<Vec<u8>>,
        position: u64,
        total_len: u64,
    }

    impl Read for UploadPackPlainReader {
        fn read(&mut self, output: &mut [u8]) -> std::io::Result<usize> {
            loop {
                let read = self.plaintext.read(output)?;
                if read != 0 || output.is_empty() {
                    self.position = self
                        .position
                        .checked_add(read as u64)
                        .ok_or_else(|| std::io::Error::other("upload pack position overflow"))?;
                    return Ok(read);
                }
                let Some(segment) = self.pack.next_segment().map_err(std::io::Error::other)? else {
                    return Ok(0);
                };
                let (plaintext, _) = self.opener.open(&segment).map_err(std::io::Error::other)?;
                self.plaintext = Cursor::new(plaintext.to_vec());
            }
        }
    }

    impl Seek for UploadPackPlainReader {
        fn seek(&mut self, position: SeekFrom) -> std::io::Result<u64> {
            let target = match position {
                SeekFrom::Start(position) => Some(position),
                SeekFrom::End(delta) => self.total_len.checked_add_signed(delta),
                SeekFrom::Current(delta) => self.position.checked_add_signed(delta),
            }
            .filter(|position| *position <= self.total_len)
            .ok_or_else(|| std::io::Error::other("upload pack seek is out of bounds"))?;
            if target == self.position {
                return Ok(target);
            }
            self.pack = BlobPackReader::open_projected_upload_pinned(
                &self.root,
                &self.identity,
                &self.checkpoint,
            )
            .map_err(std::io::Error::other)?;
            self.plaintext = Cursor::new(Vec::new());
            self.position = 0;
            while self.position < target {
                let segment = self
                    .pack
                    .next_segment()
                    .map_err(std::io::Error::other)?
                    .ok_or_else(|| std::io::Error::other("upload pack ended during seek"))?;
                let (plaintext, _) = self.opener.open(&segment).map_err(std::io::Error::other)?;
                let segment_len = plaintext.len() as u64;
                if self.position + segment_len <= target {
                    self.position += segment_len;
                    continue;
                }
                let within = target - self.position;
                self.plaintext = Cursor::new(plaintext.to_vec());
                self.plaintext.set_position(within);
                self.position = target;
            }
            Ok(target)
        }
    }

    struct TestRoot(PathBuf);

    impl TestRoot {
        fn new(label: &str) -> Self {
            let path = std::env::temp_dir().join(format!(
                "aster-upload-{label}-{}-{}",
                std::process::id(),
                NEXT_ROOT.fetch_add(1, Ordering::Relaxed)
            ));
            std::fs::create_dir(&path).expect("create upload test root");
            Self(path)
        }

        fn database(&self) -> PathBuf {
            self.0.join("state.redb")
        }
    }

    impl Drop for TestRoot {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    struct Fixture {
        root: TestRoot,
        store: Store,
        publisher: ReferenceEnvelopeSealer,
        other: ReferenceEnvelopeSealer,
        reader: ReferenceEnvelopeSealer,
        topic: Topic,
        scope: Scope,
    }

    fn fixture(label: &str, seed: u8, limits: BlobDepotLimits) -> Fixture {
        let topic = Topic::new("upload-imagery").expect("topic");
        let scope = Scope::new("mission/upload-imagery").expect("scope");
        let access = ProvisioningAccess::member(scope.clone(), vec![1], vec![topic.clone()])
            .expect("member access");
        let mut provisioner = ReferenceProvisioner::from_seed([seed; 32]).expect("provisioner");
        let publisher = provisioner
            .issue_control_authority(1, std::slice::from_ref(&access))
            .and_then(ReferenceEnvelopeSealer::open)
            .expect("publisher");
        let other = provisioner
            .issue_node(3, std::slice::from_ref(&access))
            .and_then(ReferenceEnvelopeSealer::open)
            .expect("other publisher");
        let reader = provisioner
            .issue_node(2, &[access])
            .and_then(ReferenceEnvelopeSealer::open)
            .expect("reader");
        let root = TestRoot::new(label);
        let store = Store::open_with_limits_and_blob_depot_limits_for_mission(
            root.database(),
            StoreLimits::default(),
            limits,
            publisher.mission_authority_id(),
        )
        .expect("store");
        Fixture {
            root,
            store,
            publisher,
            other,
            reader,
            topic,
            scope,
        }
    }

    fn request(fixture: &Fixture, operation: &[u8], total_len: u64) -> BlobUploadRequest {
        BlobUploadRequest {
            owner: BlobOperationOwner::new(
                fixture.publisher.identity(),
                BlobOperationKey::new(operation.to_vec()).expect("operation"),
            ),
            topic: fixture.topic.clone(),
            scope: fixture.scope.clone(),
            priority: Priority::Immediate,
            ttl_ms: Some(90_000),
            media_type: Some("image/tiff".into()),
            schema_id: b"geo-v4".to_vec(),
            total_len,
        }
    }

    fn reserve_profile5(
        fixture: &Fixture,
        request: &BlobUploadRequest,
    ) -> (
        BlobUploadReservation,
        BlobUploadCheckpoint,
        VerifiedBlobStreamOpen,
    ) {
        reserve_profile5_on(&fixture.store, &fixture.publisher, &fixture.reader, request)
    }

    fn reserve_profile5_on(
        store: &Store,
        publisher: &ReferenceEnvelopeSealer,
        reader: &ReferenceEnvelopeSealer,
        request: &BlobUploadRequest,
    ) -> (
        BlobUploadReservation,
        BlobUploadCheckpoint,
        VerifiedBlobStreamOpen,
    ) {
        try_reserve_profile5_on(store, publisher, reader, request)
            .expect("reserve Profile-5 upload")
    }

    fn try_reserve_profile5_on(
        store: &Store,
        publisher: &ReferenceEnvelopeSealer,
        reader: &ReferenceEnvelopeSealer,
        request: &BlobUploadRequest,
    ) -> Result<
        (
            BlobUploadReservation,
            BlobUploadCheckpoint,
            VerifiedBlobStreamOpen,
        ),
        StoreError,
    > {
        let policy = store.control_policy_snapshot().expect("policy");
        let initial = CustodySample {
            clock_id: [0x31; 16],
            tick_ms: 10,
        };
        store.reserve_profile5_upload_with_policy(
            &policy,
            request,
            Some(initial),
            |reservation, existing| {
                if let Some(existing) = existing {
                    let verified = reader
                        .verify_blob_stream_open(existing)
                        .map_err(|_| schema_error())?;
                    return Ok((verified, existing.to_vec()));
                }
                let revision = policy.head().map_or(1, |(revision, _)| revision);
                let authorization = publisher
                    .blob_stream_authorization_digest(&request.scope, 1)
                    .expect("stream authorization");
                let open = BlobStreamOpen::new(
                    local_blob_publication_stream_id(
                        request.owner.publisher,
                        request.owner.operation.as_bytes(),
                    ),
                    request.owner.publisher,
                    request.owner.operation.as_bytes().to_vec(),
                    publisher.mission_authority_id(),
                    reservation.counter(),
                    reservation.context().clone(),
                    request.topic.clone(),
                    request.scope.clone(),
                    BlobMetadata::new(request.media_type.clone(), request.schema_id.clone())
                        .expect("metadata"),
                    request.priority,
                    request.ttl_ms,
                    Some(initial),
                    request.total_len,
                    1,
                    revision,
                    authorization,
                    [0x71; 32],
                )
                .expect("Profile-5 open");
                let authenticated = publisher
                    .seal_blob_stream_open(&open)
                    .map_err(|_| schema_error())?;
                let verified = reader
                    .verify_blob_stream_open(&authenticated)
                    .map_err(|_| schema_error())?;
                Ok((verified, authenticated))
            },
        )
    }

    fn complete_profile5_pack(
        fixture: &Fixture,
        policy: &ControlPolicySnapshot,
        reservation: &BlobUploadReservation,
        initial: BlobUploadCheckpoint,
        verified_open: &VerifiedBlobStreamOpen,
        fill: u8,
    ) -> BlobUploadCheckpoint {
        try_complete_profile5_pack(fixture, policy, reservation, initial, verified_open, fill)
            .expect("install completion")
    }

    fn try_complete_profile5_pack(
        fixture: &Fixture,
        policy: &ControlPolicySnapshot,
        reservation: &BlobUploadReservation,
        initial: BlobUploadCheckpoint,
        verified_open: &VerifiedBlobStreamOpen,
        fill: u8,
    ) -> Result<BlobUploadCheckpoint, StoreError> {
        let root = PinnedBlobPackRoot::open(&fixture.store).expect("pack root");
        let mut writer = BlobPackWriter::open_projected_upload_pinned(
            &root,
            &reservation.pack_identity(),
            initial.durable_pack_checkpoint(),
        )
        .expect("open upload pack");
        let sealer = fixture
            .publisher
            .blob_stream_segment_sealer(verified_open)
            .expect("segment sealer");
        let total_len = verified_open.open().total_len();
        let plaintext_len = usize::try_from(total_len).expect("test pack length");
        let (segment, leaves) = sealer
            .seal(
                BlobStreamPlainPartition::new(
                    *verified_open.open().stream_id().as_bytes(),
                    verified_open.open().digest(),
                    verified_open.open().content_epoch(),
                    0,
                    0,
                    total_len,
                    vec![fill; plaintext_len],
                )
                .expect("partition"),
            )
            .expect("seal segment");
        writer.append(&segment, leaves).expect("append segment");
        let roots = writer.final_roots().expect("roots");
        let commitment = BlobStreamFinalCommitment::new(
            verified_open,
            roots.0,
            roots.1,
            1,
            Some(CustodySample {
                clock_id: [0x31; 16],
                tick_ms: 20,
            }),
        )
        .expect("commitment");
        let authenticated = fixture
            .publisher
            .seal_blob_stream_commitment(&commitment)
            .expect("sign commitment");
        let verified_commitment = fixture
            .reader
            .verify_blob_stream_commitment(verified_open, &authenticated)
            .expect("verify commitment");
        let completion = writer
            .finish_profile5(&verified_commitment)
            .expect("finish pack");
        let projected = fixture
            .store
            .checkpoint_blob_upload(
                policy,
                reservation,
                initial,
                completion.checkpoint().clone(),
            )
            .expect("project final checkpoint");
        fixture.store.complete_profile5_upload_pack(
            policy,
            reservation,
            projected,
            completion,
            &verified_commitment,
            fixture
                .publisher
                .blob_stream_lineage(verified_open)
                .expect("stream lineage"),
        )
    }

    fn assert_profile5_abort_preserves_counter_across_reopen(
        fault: Option<super::super::pack::BlobPackFaultPoint>,
    ) {
        let mut fixture = fixture("profile5-abort-counter", 0x66, BlobDepotLimits::DEFAULT);
        let request = request(&fixture, b"profile5/abort-retry", 4096);
        let (reservation, _, open) = reserve_profile5(&fixture, &request);
        assert_eq!(open.open().publisher_counter(), 1);
        if let Some(fault) = fault {
            let root = PinnedBlobPackRoot::open(&fixture.store).expect("pack root");
            super::super::pack::inject_test_fault(&root, fault);
        }
        let aborted = fixture.store.abort_blob_upload(&reservation);
        if fault.is_some() {
            assert!(aborted.is_err(), "interrupt the durable abort cleanup");
        } else {
            assert!(aborted.expect("abort publication"));
        }
        let authority = fixture.publisher.mission_authority_id();
        drop(fixture.store);
        Store::inspect_existing(fixture.root.database()).expect("inspect aborted publication");
        fixture.store = Store::open_for_mission(fixture.root.database(), authority)
            .expect("recover aborted publication");
        assert!(
            fixture
                .store
                .resume_blob_upload(&request.owner)
                .expect("inspect recovered upload")
                .is_none()
        );

        // The aborted dot stays allocated, even when no publication retains it.
        let (retry, initial, open) = reserve_profile5(&fixture, &request);
        assert_eq!(open.open().publisher_counter(), 2);
        let policy = fixture.store.control_policy_snapshot().expect("policy");
        let completed = complete_profile5_pack(&fixture, &policy, &retry, initial, &open, 0x55);
        let publication = profile5_publication(&fixture, &open, &completed);
        let outcome = fixture
            .store
            .commit_profile5_publication_once_with_policy(
                &policy,
                &retry,
                &completed,
                &publication,
                publication.publication().final_custody(),
            )
            .expect("publish after abort and restart");
        assert!(outcome.inserted());
        drop(fixture.store);
        Store::inspect_existing(fixture.root.database()).expect("inspect publication after gap");
        let reopened = Store::open_for_mission(fixture.root.database(), authority)
            .expect("reopen publication after gap");
        assert!(
            reopened
                .get_blob(outcome.blob().transfer_id)
                .expect("read publication after gap")
                .is_some()
        );
    }

    #[test]
    fn profile5_abort_preserves_counter_across_reopen() {
        assert_profile5_abort_preserves_counter_across_reopen(None);
    }

    #[test]
    fn profile5_interrupted_abort_preserves_counter_across_reopen() {
        use super::super::pack::BlobPackFaultPoint;
        for fault in [
            BlobPackFaultPoint::CleanupEntryRemoved,
            BlobPackFaultPoint::CleanupDurable,
        ] {
            assert_profile5_abort_preserves_counter_across_reopen(Some(fault));
        }
    }

    #[test]
    fn profile5_upload_audit_rejects_missing_or_regressed_publisher_counter() {
        for replacement in [None, Some(0), Some(1)] {
            let fixture = fixture("profile5-counter-floor", 0x67, BlobDepotLimits::DEFAULT);
            let first = request(&fixture, b"counter/first", 4096);
            reserve_profile5(&fixture, &first);
            let second = request(&fixture, b"counter/second", 4096);
            let (_, _, open) = reserve_profile5(&fixture, &second);
            assert_eq!(open.open().publisher_counter(), 2);
            let write = fixture.store.database.begin_write().expect("write counter");
            {
                let mut table = write.open_table(PUBLISHER_HIGH_WATER).expect("counters");
                match replacement {
                    Some(value) => {
                        table
                            .insert(first.owner.publisher.as_slice(), value)
                            .expect("regress counter");
                    }
                    None => {
                        table
                            .remove(first.owner.publisher.as_slice())
                            .expect("remove counter");
                    }
                }
            }
            write.commit().expect("commit corrupted counter");
            let authority = fixture.publisher.mission_authority_id();
            drop(fixture.store);
            Store::inspect_existing(fixture.root.database())
                .expect_err("inspection must reject a missing or regressed allocation");
            assert!(
                Store::open_for_mission(fixture.root.database(), authority).is_err(),
                "open must reject a missing or regressed allocation"
            );
        }
    }

    #[test]
    fn reused_pack_cleanup_preserves_pending_publication_across_reopen() {
        use super::super::pack::BlobPackFaultPoint;
        for fault in [
            None,
            Some(BlobPackFaultPoint::CleanupEntryRemoved),
            Some(BlobPackFaultPoint::CleanupDurable),
        ] {
            let fixture = fixture("reused-pack-cleanup", 0x65, BlobDepotLimits::DEFAULT);
            let policy = fixture.store.control_policy_snapshot().expect("policy");
            let first_request = request(&fixture, b"reused/first", 4096);
            let (first, initial, open) = reserve_profile5(&fixture, &first_request);
            let completed = complete_profile5_pack(&fixture, &policy, &first, initial, &open, 0x55);
            let publication = profile5_publication(&fixture, &open, &completed);
            fixture
                .store
                .commit_profile5_publication_once_with_policy(
                    &policy,
                    &first,
                    &completed,
                    &publication,
                    publication.publication().final_custody(),
                )
                .expect("promote first publication");

            let second_request = request(&fixture, b"reused/second", 4096);
            let (second, initial, open) = reserve_profile5(&fixture, &second_request);
            if let Some(fault) = fault {
                let root = PinnedBlobPackRoot::open(&fixture.store).expect("root");
                super::super::pack::inject_test_fault(&root, fault);
            }
            let completion =
                try_complete_profile5_pack(&fixture, &policy, &second, initial, &open, 0x55);
            assert_eq!(completion.is_err(), fault.is_some());
            let (_, before) = fixture
                .store
                .resume_blob_upload(&second_request.owner)
                .unwrap()
                .expect("pending publication");
            assert!(before.profile5_completion().unwrap().reuses_existing_pack());
            assert_eq!(before.durable_plaintext_offset(), 4096);
            assert!(
                fixture
                    .store
                    .blob_for_owner_with_policy(&policy, &second_request.owner)
                    .unwrap()
                    .is_none()
            );
            let publication = profile5_publication(&fixture, &open, &before);
            let authority = fixture.publisher.mission_authority_id();
            drop(fixture.store);

            let snapshot = upload_pack_tree_snapshot(&fixture.root);
            Store::inspect_existing(fixture.root.database())
                .expect("inspect interrupted candidate cleanup");
            assert_eq!(upload_pack_tree_snapshot(&fixture.root), snapshot);
            let reopened = Store::open_for_mission(fixture.root.database(), authority)
                .expect("reopen preserves pending publication");
            let (reservation, checkpoint) = reopened
                .resume_blob_upload(&second_request.owner)
                .unwrap()
                .expect("resume exact publication");
            assert_eq!(checkpoint, before);
            let root = PinnedBlobPackRoot::open(&reopened).unwrap();
            assert!(!root.test_upload_path(&reservation.pack_identity()).exists());
            let outcome = reopened
                .commit_profile5_publication_once_with_policy(
                    &policy,
                    &reservation,
                    &checkpoint,
                    &publication,
                    publication.publication().final_custody(),
                )
                .expect("promote recovered publication");
            assert!(outcome.inserted());
            drop(root);
            drop(reopened);
            Store::open_for_mission(fixture.root.database(), authority)
                .expect("reopen after promotion");
        }
    }

    fn profile5_publication(
        fixture: &Fixture,
        open: &VerifiedBlobStreamOpen,
        completed: &BlobUploadCheckpoint,
    ) -> VerifiedBlobStreamPublication {
        let completion = completed
            .profile5_completion()
            .expect("completed Profile-5 pack");
        let lineage = fixture
            .publisher
            .blob_stream_lineage(open)
            .expect("Profile-5 lineage");
        let publication = BlobStreamPublication::new(
            open.open().clone(),
            completion.commitment().blob_id(),
            completion.commitment().final_custody(),
            *lineage.physical().binding(),
        )
        .expect("semantic Profile-5 publication");
        let authenticated = fixture
            .publisher
            .seal_blob_stream_publication(&publication)
            .expect("seal semantic Profile-5 publication");
        fixture
            .reader
            .verify_blob_stream_publication(&authenticated)
            .expect("verify semantic Profile-5 publication")
    }

    struct RemoteProfile5Pack {
        publication: VerifiedBlobStreamPublication,
        open: VerifiedBlobStreamOpen,
        commitment: VerifiedBlobStreamFinalCommitment,
        segment: EncryptedBlobStreamSegment,
        leaves: BlobStreamSegmentLeaves,
    }

    fn remote_profile5_pack(
        fixture: &Fixture,
        publisher: &ReferenceEnvelopeSealer,
        operation: &[u8],
        fill: u8,
    ) -> RemoteProfile5Pack {
        const TOTAL_LEN: u64 = 4_096;
        let policy = fixture.store.control_policy_snapshot().expect("policy");
        let open = BlobStreamOpen::new(
            local_blob_publication_stream_id(publisher.identity(), operation),
            publisher.identity(),
            operation.to_vec(),
            publisher.mission_authority_id(),
            1,
            VersionVector::default(),
            fixture.topic.clone(),
            fixture.scope.clone(),
            BlobMetadata::new(Some("image/tiff".into()), b"geo-v4".to_vec())
                .expect("remote metadata"),
            Priority::Immediate,
            None,
            None,
            TOTAL_LEN,
            1,
            policy.head().map_or(1, |(revision, _)| revision),
            publisher
                .blob_stream_authorization_digest(&fixture.scope, 1)
                .expect("remote stream authorization"),
            [fill; 32],
        )
        .expect("remote Profile-5 open");
        let authenticated_open = publisher
            .seal_blob_stream_open(&open)
            .expect("seal remote Profile-5 open");
        let open = fixture
            .reader
            .verify_blob_stream_open(&authenticated_open)
            .expect("verify remote Profile-5 open");
        let sealer = publisher
            .blob_stream_segment_sealer(&open)
            .expect("remote segment sealer");
        let (segment, leaves) = sealer
            .seal(
                BlobStreamPlainPartition::new(
                    *open.open().stream_id().as_bytes(),
                    open.open().digest(),
                    open.open().content_epoch(),
                    0,
                    0,
                    TOTAL_LEN,
                    vec![fill; TOTAL_LEN as usize],
                )
                .expect("remote partition"),
            )
            .expect("seal remote segment");
        let mut frontier = BlobStreamFrontier::new();
        frontier
            .append(BlobStreamSubtree::leaf(0, leaves))
            .expect("append remote segment leaves");
        let roots = frontier.finish(TOTAL_LEN).expect("remote roots");
        let commitment = BlobStreamFinalCommitment::new(&open, roots.0, roots.1, 1, None)
            .expect("remote commitment");
        let authenticated_commitment = publisher
            .seal_blob_stream_commitment(&commitment)
            .expect("seal remote commitment");
        let commitment = fixture
            .reader
            .verify_blob_stream_commitment(&open, &authenticated_commitment)
            .expect("verify remote commitment");
        let lineage = publisher
            .blob_stream_lineage(&open)
            .expect("remote physical lineage");
        let publication = BlobStreamPublication::new(
            open.open().clone(),
            commitment.commitment().blob_id(),
            None,
            *lineage.physical().binding(),
        )
        .expect("remote semantic publication");
        let authenticated_publication = publisher
            .seal_blob_stream_publication(&publication)
            .expect("seal remote semantic publication");
        let publication = fixture
            .reader
            .verify_blob_stream_publication(&authenticated_publication)
            .expect("verify remote semantic publication");
        RemoteProfile5Pack {
            publication,
            open,
            commitment,
            segment,
            leaves,
        }
    }

    fn complete_received_profile5_pack(
        fixture: &Fixture,
        publisher: &ReferenceEnvelopeSealer,
        policy: &ControlPolicySnapshot,
        reservation: &BlobUploadReservation,
        initial: BlobUploadCheckpoint,
        pack: &RemoteProfile5Pack,
    ) -> BlobUploadCheckpoint {
        let root = PinnedBlobPackRoot::open(&fixture.store).expect("remote pack root");
        let mut writer = BlobPackWriter::open_projected_upload_pinned(
            &root,
            &reservation.pack_identity(),
            initial.durable_pack_checkpoint(),
        )
        .expect("open remote upload pack");
        writer
            .append(&pack.segment, pack.leaves)
            .expect("append remote segment");
        let completion = writer
            .finish_profile5(&pack.commitment)
            .expect("finish remote pack");
        let projected = fixture
            .store
            .checkpoint_blob_upload(
                policy,
                reservation,
                initial,
                completion.checkpoint().clone(),
            )
            .expect("project remote final checkpoint");
        fixture
            .store
            .complete_profile5_upload_pack(
                policy,
                reservation,
                projected,
                completion,
                &pack.commitment,
                publisher
                    .blob_stream_lineage(&pack.open)
                    .expect("remote stream lineage"),
            )
            .expect("install remote completion")
    }

    fn promote_received_profile5_pack(
        fixture: &Fixture,
        publisher: &ReferenceEnvelopeSealer,
        policy: &ControlPolicySnapshot,
        reservation: &BlobUploadReservation,
        checkpoint: BlobUploadCheckpoint,
        pack: &RemoteProfile5Pack,
    ) -> StoredBlob {
        let completed = complete_received_profile5_pack(
            fixture,
            publisher,
            policy,
            reservation,
            checkpoint,
            pack,
        );
        match fixture
            .store
            .commit_received_durable_profile5_upload_once_with_policy(
                policy,
                reservation,
                &completed,
                &pack.publication,
            )
            .expect("promote received Profile-5 pack")
        {
            super::super::BlobOnceOutcome::Inserted { blob } => blob,
            _ => panic!("new received Profile-5 pack must insert"),
        }
    }

    #[test]
    fn received_profile5_reuse_preserves_capacity_and_exact_operation() {
        let mut fixture = fixture("received-reuse-admission", 0x72, BlobDepotLimits::DEFAULT);
        let policy = fixture.store.control_policy_snapshot().unwrap();
        let first = remote_profile5_pack(&fixture, &fixture.publisher, b"reuse/first", 0x53);
        let (reservation, initial, _) = fixture
            .store
            .reserve_received_profile5_upload_with_policy(&policy, &first.publication, &first.open)
            .unwrap();
        let stored = promote_received_profile5_pack(
            &fixture,
            &fixture.publisher,
            &policy,
            &reservation,
            initial,
            &first,
        );
        let second = remote_profile5_pack(&fixture, &fixture.other, b"reuse/second", 0x53);
        let source_for = |publication: &VerifiedBlobStreamPublication| {
            let encoded = aster_mesh::BlobStreamPublicationSource::new(
                publication.authenticated_bytes().to_vec(),
                second.open.authenticated_bytes().to_vec(),
                second.commitment.authenticated_bytes().to_vec(),
            )
            .unwrap()
            .encode()
            .unwrap();
            fixture
                .reader
                .verify_blob_stream_publication_source(&encoded)
                .unwrap()
        };
        let source = source_for(&second.publication);
        let mut changed_open = second.publication.publication().open().encode();
        let last = changed_open.len() - 1;
        changed_open[last] ^= 1;
        let changed_publication = aster_mesh::BlobStreamPublication::new(
            BlobStreamOpen::decode(&changed_open).unwrap(),
            second.publication.publication().blob_id(),
            None,
            *second.publication.publication().physical_lineage(),
        )
        .unwrap();
        let changed_publication = fixture
            .reader
            .verify_blob_stream_publication(
                &fixture
                    .other
                    .seal_blob_stream_publication(&changed_publication)
                    .unwrap(),
            )
            .unwrap();
        let changed_source = source_for(&changed_publication);
        let before = fixture.store.blob_stats().unwrap();
        // No spare room for a second file: reuse must not reserve one.
        fixture.store.blob_depot_limits =
            BlobDepotLimits::new(before.reserved_file_bytes, 1, 1).unwrap();
        let retained = fixture
            .store
            .open_profile5_pack_transfer_read(stored.variant_id)
            .unwrap();
        let outcome = fixture
            .store
            .commit_received_existing_profile5_pack_with_policy(&policy, &source, &retained, None)
            .unwrap();
        assert!(outcome.inserted());
        let after = fixture.store.blob_stats().unwrap();
        assert_eq!(after.reserved_file_bytes, before.reserved_file_bytes);
        assert_eq!(after.variants, before.variants);
        let retry = fixture
            .store
            .commit_received_existing_profile5_pack_with_policy(&policy, &source, &retained, None)
            .unwrap();
        assert!(!retry.inserted());
        assert_eq!(retry.blob().transfer_id, outcome.blob().transfer_id);
        let conflicting = fixture
            .store
            .commit_received_existing_profile5_pack_with_policy(
                &policy,
                &changed_source,
                &retained,
                None,
            );
        assert!(
            matches!(
                conflicting,
                Err(StoreError::Blob(BlobStoreError::OperationConflict))
            ),
            "a different signed publication cannot replay the same operation"
        );
        assert_eq!(fixture.store.blob_stats().unwrap(), after);
        let foreign = self::fixture("received-reuse-foreign", 0x72, BlobDepotLimits::DEFAULT);
        assert!(matches!(
            foreign
                .store
                .commit_received_existing_profile5_pack_with_policy(
                    &foreign.store.control_policy_snapshot().unwrap(),
                    &source,
                    &retained,
                    None,
                ),
            Err(StoreError::Blob(BlobStoreError::CompletionMismatch))
        ));
    }

    #[test]
    fn received_profile5_same_operation_is_qualified_by_remote_publisher() {
        let fixture = fixture(
            "profile5-two-remote-same-operation",
            0x35,
            BlobDepotLimits::DEFAULT,
        );
        let policy = fixture.store.control_policy_snapshot().expect("policy");
        let operation = b"profile5/shared-remote-operation";
        let first_pack = remote_profile5_pack(&fixture, &fixture.publisher, operation, 0x51);
        let second_pack = remote_profile5_pack(&fixture, &fixture.other, operation, 0x52);
        let first = fixture
            .store
            .reserve_received_profile5_upload_with_policy(
                &policy,
                &first_pack.publication,
                &first_pack.open,
            )
            .expect("reserve first remote publication");
        let second = fixture
            .store
            .reserve_received_profile5_upload_with_policy(
                &policy,
                &second_pack.publication,
                &second_pack.open,
            )
            .expect("reserve second remote publication");
        assert_ne!(first.0.request().owner, second.0.request().owner);
        assert_eq!(
            first.0.request().owner.operation,
            second.0.request().owner.operation
        );
        assert_eq!(
            fixture
                .store
                .reserve_received_profile5_upload_with_policy(
                    &policy,
                    &first_pack.publication,
                    &first_pack.open,
                )
                .expect("retry first remote publication"),
            first
        );
        assert_eq!(
            fixture
                .store
                .reserve_received_profile5_upload_with_policy(
                    &policy,
                    &second_pack.publication,
                    &second_pack.open,
                )
                .expect("retry second remote publication"),
            second
        );

        let second_blob = promote_received_profile5_pack(
            &fixture,
            &fixture.other,
            &policy,
            &second.0,
            second.1,
            &second_pack,
        );
        let first_blob = promote_received_profile5_pack(
            &fixture,
            &fixture.publisher,
            &policy,
            &first.0,
            first.1,
            &first_pack,
        );
        assert_ne!(first_blob.transfer_id, second_blob.transfer_id);
        assert_eq!(
            fixture
                .store
                .blob_for_owner_with_policy(&policy, &first.0.request().owner)
                .expect("first remote owner lookup")
                .expect("first remote publication")
                .transfer_id,
            first_blob.transfer_id
        );
        assert_eq!(
            fixture
                .store
                .blob_for_owner_with_policy(&policy, &second.0.request().owner)
                .expect("second remote owner lookup")
                .expect("second remote publication")
                .transfer_id,
            second_blob.transfer_id
        );

        let database = fixture.root.database();
        let authority = fixture.publisher.mission_authority_id();
        let first_owner = first.0.request().owner.clone();
        let second_owner = second.0.request().owner.clone();
        drop(fixture.store);
        let reopened = Store::open_for_mission(database, authority).expect("reopen remote store");
        let reopened_policy = reopened.control_policy_snapshot().expect("reopened policy");
        assert_eq!(
            reopened
                .blob_for_owner_with_policy(&reopened_policy, &first_owner)
                .expect("reopened first remote lookup")
                .expect("reopened first remote publication")
                .transfer_id,
            first_blob.transfer_id
        );
        assert_eq!(
            reopened
                .blob_for_owner_with_policy(&reopened_policy, &second_owner)
                .expect("reopened second remote lookup")
                .expect("reopened second remote publication")
                .transfer_id,
            second_blob.transfer_id
        );
    }

    #[test]
    fn profile5_same_operation_is_independent_for_local_and_remote_publishers() {
        let fixture = fixture(
            "profile5-local-remote-same-operation",
            0x36,
            BlobDepotLimits::DEFAULT,
        );
        let policy = fixture.store.control_policy_snapshot().expect("policy");
        let operation = b"profile5/shared-local-remote-operation";
        let local_request = request(&fixture, operation, 4_096);
        let local = reserve_profile5(&fixture, &local_request);
        let remote_pack = remote_profile5_pack(&fixture, &fixture.other, operation, 0x62);
        let remote = fixture
            .store
            .reserve_received_profile5_upload_with_policy(
                &policy,
                &remote_pack.publication,
                &remote_pack.open,
            )
            .expect("reserve colliding remote publication");
        assert_ne!(local.0.request().owner, remote.0.request().owner);
        assert_eq!(
            local.0.request().owner.operation,
            remote.0.request().owner.operation
        );

        let remote_blob = promote_received_profile5_pack(
            &fixture,
            &fixture.other,
            &policy,
            &remote.0,
            remote.1,
            &remote_pack,
        );
        let local_completed =
            complete_profile5_pack(&fixture, &policy, &local.0, local.1, &local.2, 0x61);
        let local_publication = profile5_publication(&fixture, &local.2, &local_completed);
        let local_blob = match fixture
            .store
            .commit_profile5_publication_once_with_policy(
                &policy,
                &local.0,
                &local_completed,
                &local_publication,
                local_publication.publication().final_custody(),
            )
            .expect("promote local Profile-5 publication")
        {
            super::super::BlobOnceOutcome::Inserted { blob } => blob,
            _ => panic!("new local Profile-5 publication must insert"),
        };
        assert_ne!(local_blob.transfer_id, remote_blob.transfer_id);
        for (owner, expected) in [
            (&local.0.request().owner, local_blob.transfer_id),
            (&remote.0.request().owner, remote_blob.transfer_id),
        ] {
            assert_eq!(
                fixture
                    .store
                    .blob_for_owner_with_policy(&policy, owner)
                    .expect("qualified local/remote lookup")
                    .expect("qualified local/remote publication")
                    .transfer_id,
                expected
            );
        }

        let database = fixture.root.database();
        let authority = fixture.publisher.mission_authority_id();
        let local_owner = local.0.request().owner.clone();
        let remote_owner = remote.0.request().owner.clone();
        drop(fixture.store);
        let reopened = Store::open_for_mission(database, authority).expect("reopen mixed store");
        let reopened_policy = reopened.control_policy_snapshot().expect("reopened policy");
        assert_eq!(
            reopened
                .blob_for_owner_with_policy(&reopened_policy, &local_owner)
                .expect("reopened local lookup")
                .expect("reopened local publication")
                .transfer_id,
            local_blob.transfer_id
        );
        assert_eq!(
            reopened
                .blob_for_owner_with_policy(&reopened_policy, &remote_owner)
                .expect("reopened remote lookup")
                .expect("reopened remote publication")
                .transfer_id,
            remote_blob.transfer_id
        );
    }

    #[test]
    fn profile5_open_reservation_is_invisible_until_atomic_promotion() {
        let fixture = fixture("profile5-open-invisible", 0x2a, BlobDepotLimits::DEFAULT);
        let request = request(&fixture, b"profile5/invisible", 4_096);
        let (reservation, checkpoint, verified) = reserve_profile5(&fixture, &request);
        assert_eq!(checkpoint.durable_plaintext_offset(), 0);
        assert_eq!(
            reservation.pack_identity().upload_id(),
            verified.open().stream_id()
        );
        assert_eq!(
            reservation.pack_identity().request_digest(),
            &verified.open().digest()
        );

        let read = fixture.store.database.begin_read().expect("read");
        assert!(
            read.open_table(BLOB_OPERATIONS)
                .expect("operations")
                .is_empty()
                .unwrap()
        );
        assert!(
            read.open_table(BLOB_PUBLICATIONS)
                .expect("publications")
                .is_empty()
                .unwrap()
        );
        assert!(
            read.open_table(super::super::ACCEPTED_DOTS)
                .expect("dots")
                .is_empty()
                .unwrap()
        );
        assert!(
            read.open_table(super::super::CAUSAL_FRONTIER)
                .expect("frontier")
                .is_empty()
                .unwrap()
        );
        assert_eq!(
            read.open_table(PUBLISHER_HIGH_WATER)
                .expect("high-water")
                .get(request.owner.publisher.as_slice())
                .expect("read high-water")
                .expect("reserved counter")
                .value(),
            verified.open().publisher_counter()
        );
    }

    #[test]
    fn profile5_pack_promotion_updates_all_blob_indexes_atomically() {
        let fixture = fixture("profile5-pack-complete", 0x29, BlobDepotLimits::DEFAULT);
        let total_len = aster_mesh::BLOB_STREAM_SEGMENT_BYTES as u64 + 17;
        let request = request(&fixture, b"profile5/pack-complete", total_len);
        let policy = fixture.store.control_policy_snapshot().expect("policy");
        let (reservation, initial, verified_open) = reserve_profile5(&fixture, &request);
        let root = PinnedBlobPackRoot::open(&fixture.store).expect("pack root");
        let mut writer = BlobPackWriter::open_projected_upload_pinned(
            &root,
            &reservation.pack_identity(),
            initial.durable_pack_checkpoint(),
        )
        .expect("open upload pack");
        let sealer = fixture
            .publisher
            .blob_stream_segment_sealer(&verified_open)
            .expect("segment sealer");
        for (index, len) in [aster_mesh::BLOB_STREAM_SEGMENT_BYTES, 17]
            .into_iter()
            .enumerate()
        {
            let offset = index as u64 * aster_mesh::BLOB_STREAM_SEGMENT_BYTES as u64;
            let (segment, leaves) = sealer
                .seal(
                    BlobStreamPlainPartition::new(
                        *verified_open.open().stream_id().as_bytes(),
                        verified_open.open().digest(),
                        verified_open.open().content_epoch(),
                        index as u64,
                        offset,
                        total_len,
                        vec![index as u8 + 1; len],
                    )
                    .expect("partition"),
                )
                .expect("seal segment");
            writer.append(&segment, leaves).expect("append segment");
        }
        let roots = writer.final_roots().expect("roots");
        let final_sample = CustodySample {
            clock_id: [0x31; 16],
            tick_ms: 20,
        };
        let commitment = aster_mesh::BlobStreamFinalCommitment::new(
            &verified_open,
            roots.0,
            roots.1,
            2,
            Some(final_sample),
        )
        .expect("commitment");
        let authenticated = fixture
            .publisher
            .seal_blob_stream_commitment(&commitment)
            .expect("sign commitment");
        let verified_commitment = fixture
            .reader
            .verify_blob_stream_commitment(&verified_open, &authenticated)
            .expect("verify commitment");
        let lineage = fixture
            .publisher
            .blob_stream_lineage(&verified_open)
            .expect("stream lineage");
        let completion = writer
            .finish_profile5(&verified_commitment)
            .expect("finish pack");
        let projected = fixture
            .store
            .checkpoint_blob_upload(
                &policy,
                &reservation,
                initial,
                completion.checkpoint().clone(),
            )
            .expect("project final checkpoint");
        let completed = fixture
            .store
            .complete_profile5_upload_pack(
                &policy,
                &reservation,
                projected,
                completion,
                &verified_commitment,
                lineage,
            )
            .expect("install completion");
        assert_eq!(
            completed
                .profile5_completion()
                .expect("completed profile-5 pack")
                .commitment(),
            &commitment
        );
        let expected_variant = super::super::blob_variant_id(
            commitment.blob_id(),
            &verified_open.open().content_group(),
            verified_open.open().content_epoch(),
        );

        let (_, retry, retry_open) = reserve_profile5(&fixture, &request);
        assert_eq!(retry_open, verified_open);
        assert_eq!(retry, completed);
        let read = fixture.store.database.begin_read().expect("read");
        assert!(
            read.open_table(BLOB_PUBLICATIONS)
                .expect("publications")
                .is_empty()
                .expect("publication count")
        );
        assert!(
            read.open_table(super::super::BLOB_CHUNKS)
                .expect("legacy chunks")
                .is_empty()
                .expect("chunk count")
        );
        let pack = super::super::pack_lifecycle::load_read(
            &read,
            expected_variant,
            Arc::clone(&fixture.store.blob_completion_authority),
        )
        .expect("read lifecycle pack")
        .expect("completed upload owns one lifecycle pack");
        assert_eq!(pack.variant_id(), expected_variant);
        assert_eq!(pack.open(), verified_open.open());
        assert_eq!(pack.commitment(), &commitment);
        assert!(pack.is_bound_to(&fixture.store.blob_completion_authority));
        drop(read);
        let publication = profile5_publication(&fixture, &verified_open, &completed);
        let Fixture {
            root,
            store,
            publisher,
            reader,
            ..
        } = fixture;
        drop(store);
        let reopened = Store::open_with_limits_and_blob_depot_limits_for_mission(
            root.database(),
            StoreLimits::default(),
            BlobDepotLimits::DEFAULT,
            publisher.mission_authority_id(),
        )
        .expect("reopen Store");
        let reopened_policy = reopened.control_policy_snapshot().expect("policy");
        let subscription = reopened
            .create_blob_subscription_with_policy(
                &reopened_policy,
                &BlobSubscriptionKey::new(b"native-profile5-promotion".to_vec())
                    .expect("subscription key"),
                BlobSubscriptionSpec {
                    topic: request.topic.clone(),
                    scope: request.scope.clone(),
                    include_descendant_scopes: false,
                },
            )
            .expect("create native Profile-5 subscription");
        let (restarted_reservation, restarted, restarted_open) =
            reserve_profile5_on(&reopened, &publisher, &reader, &request);
        assert_eq!(restarted_open, verified_open);
        assert_eq!(restarted, completed);
        let outcome = reopened
            .commit_profile5_publication_once_with_policy(
                &reopened_policy,
                &restarted_reservation,
                &restarted,
                &publication,
                publication.publication().final_custody(),
            )
            .expect("promote exact pack");
        let blob = match outcome {
            super::super::BlobOnceOutcome::Inserted { blob } => blob,
            _ => panic!("first pack promotion must insert"),
        };
        assert_eq!(blob.blob_id, commitment.blob_id());
        assert_eq!(blob.variant_id, expected_variant);
        let exact_retry = reopened
            .commit_profile5_publication_once_with_policy(
                &reopened.control_policy_snapshot().expect("retry policy"),
                &restarted_reservation,
                &restarted,
                &publication,
                publication.publication().final_custody(),
            )
            .expect("retry exact promoted pack");
        assert!(matches!(
            exact_retry,
            super::super::BlobOnceOutcome::Existing { blob: ref retried }
                if retried == &blob
        ));
        assert!(
            reopened
                .resume_blob_upload(&request.owner)
                .expect("resume after promotion")
                .is_none()
        );
        let read = reopened.database.begin_read().expect("read promoted pack");
        assert_eq!(
            read.open_table(BLOB_PUBLICATIONS)
                .expect("publications")
                .len()
                .expect("publication count"),
            1
        );
        assert!(
            read.open_table(super::super::BLOB_IMPORTS)
                .expect("legacy imports")
                .is_empty()
                .expect("import count")
        );
        assert!(
            read.open_table(super::super::BLOB_CHUNKS)
                .expect("legacy chunks")
                .is_empty()
                .expect("chunk count")
        );
        let promoted = super::super::pack_lifecycle::load_read(
            &read,
            expected_variant,
            Arc::clone(&reopened.blob_completion_authority),
        )
        .expect("load promoted pack")
        .expect("promoted pack row");
        assert!(promoted.lifecycle_owned());
        drop(read);
        let delivery_plan = reopened
            .prepare_blob_subscription_poll_with_policy(&reopened_policy, subscription.id, 1, 8)
            .expect("plan native Profile-5 delivery");
        assert_eq!(delivery_plan.candidates().len(), 1);
        let candidate = &delivery_plan.candidates()[0];
        assert_eq!(candidate.projection().semantic_id, blob.semantic_id);
        assert_eq!(candidate.projection().transfer_id, blob.transfer_id);
        assert_eq!(candidate.projection().blob_id, blob.blob_id);
        assert_eq!(candidate.acceptance_marker(), blob.acceptance_marker);
        let delivery_page = reopened
            .commit_blob_subscription_poll_with_policy(
                &reopened_policy,
                &delivery_plan,
                &BlobSubscriptionPollSelection {
                    deliverable: vec![blob.semantic_id],
                    inactive: Vec::new(),
                },
            )
            .expect("deliver native Profile-5 promotion");
        assert_eq!(delivery_page.deliveries.len(), 1);
        assert_eq!(delivery_page.deliveries[0].semantic_id, blob.semantic_id);
        assert_eq!(
            delivery_page.deliveries[0].acceptance_marker,
            blob.acceptance_marker
        );
        assert_eq!(
            reopened
                .acknowledge_blob_delivery_with_policy(
                    &reopened_policy,
                    subscription.id,
                    blob.semantic_id,
                    delivery_page.deliveries[0].token,
                )
                .expect("acknowledge native Profile-5 delivery"),
            BlobDeliveryAck::Acknowledged
        );
        let acknowledged_plan = reopened
            .prepare_blob_subscription_poll_with_policy(&reopened_policy, subscription.id, 1, 8)
            .expect("plan after native Profile-5 acknowledgement");
        let acknowledged_page = reopened
            .commit_blob_subscription_poll_with_policy(
                &reopened_policy,
                &acknowledged_plan,
                &BlobSubscriptionPollSelection {
                    deliverable: vec![blob.semantic_id],
                    inactive: Vec::new(),
                },
            )
            .expect("commit after native Profile-5 acknowledgement");
        assert!(acknowledged_page.deliveries.is_empty());
        let promoted_root = PinnedBlobPackRoot::open(&reopened).expect("promoted pack root");
        drop(
            BlobPackReader::open_completed_upload_pinned(
                &promoted_root,
                restarted.profile5_completion().expect("completion").pack(),
            )
            .expect("open exact promoted pack"),
        );
        drop(reopened);
        let reopened = Store::open_with_limits_and_blob_depot_limits_for_mission(
            root.database(),
            StoreLimits::default(),
            BlobDepotLimits::DEFAULT,
            publisher.mission_authority_id(),
        )
        .expect("reopen promoted Store");
        assert!(
            reopened
                .blob_for_owner_with_policy(
                    &reopened.control_policy_snapshot().expect("policy"),
                    &request.owner,
                )
                .expect("lookup promoted operation")
                .is_some()
        );
        let application_read = reopened
            .open_profile5_pack_application_read(expected_variant)
            .expect("lease canonical pack for application read");
        let transfer_read = reopened
            .open_profile5_pack_transfer_read(expected_variant)
            .expect("lease canonical pack for transfer");

        let maintenance_budget =
            super::super::lifecycle::BlobMaintenanceBudget::new(256, 8, 32 * 1024 * 1024)
                .expect("maintenance budget");
        let expired_sample = CustodySample {
            clock_id: [0x31; 16],
            tick_ms: 100_100,
        };
        let mut retired = false;
        for turn in 0..64 {
            reopened
                .run_blob_maintenance_turn_with_sample(
                    maintenance_budget,
                    (turn == 0).then_some(expired_sample),
                )
                .expect("retire finite pack");
            if matches!(
                reopened.blob_for_owner_with_policy(
                    &reopened.control_policy_snapshot().expect("lookup policy"),
                    &request.owner,
                ),
                Err(StoreError::Blob(BlobStoreError::ExpiredOrRetired))
            ) {
                retired = true;
                break;
            }
        }
        assert!(retired, "finite Profile-5 publication must retire");
        assert!(matches!(
            reopened.test_admit_blob_deletion_manifest(expected_variant),
            Err(StoreError::Blob(BlobStoreError::VariantDeleting))
        ));
        drop(application_read);
        assert!(matches!(
            reopened.test_admit_blob_deletion_manifest(expected_variant),
            Err(StoreError::Blob(BlobStoreError::VariantDeleting))
        ));
        drop(transfer_read);
        reopened
            .test_admit_blob_deletion_manifest(expected_variant)
            .expect("admit retired pack deletion");
        let read = reopened.database.begin_read().expect("retired pack read");
        let retiring = super::super::pack_lifecycle::load_read(
            &read,
            expected_variant,
            Arc::clone(&reopened.blob_completion_authority),
        )
        .expect("load retiring pack")
        .expect("deletion retains pack authority");
        assert!(retiring.deletion_pending());
        assert!(
            read.open_table(super::super::deletion::BLOB_DELETION_MANIFESTS)
                .expect("deletion manifests")
                .get(expected_variant.as_bytes().as_slice())
                .expect("read deletion manifest")
                .is_some()
        );
        let charged_before_failure =
            super::super::depot::depot_admission_usage_read(&read).expect("retiring pack quota");
        drop(read);
        let pack_root = PinnedBlobPackRoot::open(&reopened).expect("retiring pack root");
        super::super::pack::inject_test_fault(
            &pack_root,
            super::super::pack::BlobPackFaultPoint::CleanupDurable,
        );
        drop(pack_root);
        let one_file_budget =
            super::super::lifecycle::BlobMaintenanceBudget::new(256, 1, 32 * 1024 * 1024)
                .expect("one-file maintenance budget");
        let failed = reopened
            .run_blob_capacity_gc(one_file_budget, None)
            .expect("record deletion failure");
        assert_eq!(failed.manifests_finalized, 0);
        let read = reopened
            .database
            .begin_read()
            .expect("failed deletion read");
        assert_eq!(
            super::super::depot::depot_admission_usage_read(&read).expect("failed deletion quota"),
            charged_before_failure,
            "failed physical deletion must not release pack quota"
        );
        drop(read);
        drop(reopened);
        let reopened = Store::open_with_limits_and_blob_depot_limits_for_mission(
            root.database(),
            StoreLimits::default(),
            BlobDepotLimits::DEFAULT,
            publisher.mission_authority_id(),
        )
        .expect("reopen after physical-delete crash gap");
        let read = reopened
            .database
            .begin_read()
            .expect("restart deletion read");
        assert_eq!(
            super::super::depot::depot_admission_usage_read(&read).expect("restart deletion quota"),
            charged_before_failure
        );
        drop(read);
        for _ in 0..8 {
            reopened
                .run_blob_capacity_gc(maintenance_budget, None)
                .expect("delete retired pack");
            let read = reopened
                .database
                .begin_read()
                .expect("deletion progress read");
            let removed = super::super::pack_lifecycle::load_read(
                &read,
                expected_variant,
                Arc::clone(&reopened.blob_completion_authority),
            )
            .expect("load deletion progress")
            .is_none();
            drop(read);
            if removed {
                return;
            }
        }
        panic!("retired Profile-5 pack was not physically finalized");
    }

    #[test]
    fn profile5_open_retry_reuses_identity_and_counter() {
        let fixture = fixture("profile5-open-retry", 0x2b, BlobDepotLimits::DEFAULT);
        let request = request(&fixture, b"profile5/retry", 8_192);
        let first = reserve_profile5(&fixture, &request);
        let second = reserve_profile5(&fixture, &request);
        assert_eq!(first.0, second.0);
        assert_eq!(first.1, second.1);
        assert_eq!(first.2, second.2);
        assert_eq!(
            first.2.authenticated_bytes(),
            second.2.authenticated_bytes(),
            "exact retry restores the byte-identical signed open"
        );
    }

    #[test]
    fn profile5_open_operation_conflict_does_not_mutate_state() {
        let fixture = fixture("profile5-open-conflict", 0x2f, BlobDepotLimits::DEFAULT);
        let first_request = request(&fixture, b"profile5/conflict", 8_192);
        let first = reserve_profile5(&fixture, &first_request);
        let conflicting = request(&fixture, b"profile5/conflict", 16_384);
        assert!(
            matches!(
                try_reserve_profile5_on(
                    &fixture.store,
                    &fixture.publisher,
                    &fixture.reader,
                    &conflicting,
                ),
                Err(StoreError::Blob(BlobStoreError::OperationConflict))
            ),
            "same owner/operation with different immutable intent must conflict"
        );
        let read = fixture.store.database.begin_read().expect("conflict read");
        assert_eq!(
            read.open_table(super::super::BLOB_UPLOADS)
                .expect("uploads")
                .len()
                .expect("upload rows"),
            1
        );
        assert_eq!(
            read.open_table(PUBLISHER_HIGH_WATER)
                .expect("high-water")
                .get(first_request.owner.publisher.as_slice())
                .expect("read high-water")
                .expect("reserved counter")
                .value(),
            first.2.open().publisher_counter()
        );
    }

    #[test]
    fn profile5_open_restart_restores_exact_authenticated_authority() {
        let fixture = fixture("profile5-open-restart", 0x2d, BlobDepotLimits::DEFAULT);
        let request = request(&fixture, b"profile5/restart", 12_288);
        let first = reserve_profile5(&fixture, &request);
        let database = fixture.root.database();
        let authority = fixture.publisher.mission_authority_id();
        drop(fixture.store);

        let reopened = Store::open_for_mission(database, authority).expect("reopen store");
        let restored =
            reserve_profile5_on(&reopened, &fixture.publisher, &fixture.reader, &request);
        assert_eq!(restored.0, first.0);
        assert_eq!(restored.1, first.1);
        assert_eq!(restored.2, first.2);
        assert_eq!(
            restored.2.authenticated_bytes(),
            first.2.authenticated_bytes()
        );
    }

    #[test]
    fn profile5_open_crash_before_commit_leaves_no_authority() {
        let fixture = fixture("profile5-open-crash", 0x2e, BlobDepotLimits::DEFAULT);
        let request = request(&fixture, b"profile5/crash", 16_384);
        inject_test_fault(&fixture.store, UploadFaultPoint::ReservationPackSynced);
        assert!(
            try_reserve_profile5_on(
                &fixture.store,
                &fixture.publisher,
                &fixture.reader,
                &request,
            )
            .is_err()
        );
        {
            let read = fixture
                .store
                .database
                .begin_read()
                .expect("read failed reservation");
            assert!(
                read.open_table(super::super::BLOB_UPLOADS)
                    .expect("uploads")
                    .is_empty()
                    .unwrap()
            );
            assert!(
                read.open_table(PUBLISHER_HIGH_WATER)
                    .expect("high-water")
                    .get(request.owner.publisher.as_slice())
                    .expect("read high-water")
                    .is_none()
            );
        }

        let database = fixture.root.database();
        let authority = fixture.publisher.mission_authority_id();
        drop(fixture.store);
        let reopened = Store::open_for_mission(database, authority).expect("recover store");
        let recovered =
            reserve_profile5_on(&reopened, &fixture.publisher, &fixture.reader, &request);
        assert_eq!(recovered.2.open().publisher_counter(), 1);
    }

    #[test]
    fn profile5_reserved_counters_promote_out_of_order_after_event_commit() {
        let mut fixture = fixture("profile5-two-opens", 0x2c, BlobDepotLimits::DEFAULT);
        let policy = fixture.store.control_policy_snapshot().expect("policy");
        let first_request = request(&fixture, b"profile5/first", 4_096);
        let second_request = request(&fixture, b"profile5/second", 4_096);
        let first = reserve_profile5(&fixture, &first_request);
        let second = reserve_profile5(&fixture, &second_request);
        assert_eq!(
            second.2.open().publisher_counter(),
            first.2.open().publisher_counter() + 1
        );
        assert_ne!(first.2.open().stream_id(), second.2.open().stream_id());
        assert_eq!(reserve_profile5(&fixture, &first_request).2, first.2);
        assert_eq!(reserve_profile5(&fixture, &second_request).2, second.2);

        let event_payload = b"cross-class allocation after native reservations";
        let event_reservation = fixture
            .store
            .reserve_event_with_policy(
                &policy,
                fixture.publisher.identity(),
                &fixture.topic,
                &fixture.scope,
            )
            .expect("reserve interleaved Event");
        assert_eq!(
            event_reservation.counter(),
            second.2.open().publisher_counter() + 1
        );
        let event_header = event_reservation
            .header(
                Priority::Immediate,
                b"profile5/interleaved-event".to_vec(),
                None,
                event_payload.len() as u64,
                false,
                1,
            )
            .expect("interleaved Event header");
        let sealed_event = fixture
            .publisher
            .seal_event(&event_header, event_payload)
            .expect("seal interleaved Event");
        let route = fixture
            .reader
            .verify_event(&sealed_event.bytes)
            .expect("verify interleaved Event route");
        let EventContentVerification::ContentVerified { event, .. } = fixture
            .reader
            .verify_event_content(route, &sealed_event.bytes)
            .expect("verify interleaved Event content")
        else {
            panic!("member fixture must open interleaved Event content")
        };
        fixture
            .store
            .commit_reserved_event_with_policy(
                &policy,
                &event_reservation,
                &event,
                &sealed_event.bytes,
            )
            .expect("commit interleaved Event");

        let first_completed =
            complete_profile5_pack(&fixture, &policy, &first.0, first.1, &first.2, 0x41);
        let second_completed =
            complete_profile5_pack(&fixture, &policy, &second.0, second.1, &second.2, 0x42);
        let first_publication = profile5_publication(&fixture, &first.2, &first_completed);
        let second_publication = profile5_publication(&fixture, &second.2, &second_completed);
        let sample = first_publication.publication().final_custody();
        assert_eq!(sample, second_publication.publication().final_custody());
        let second_blob = match fixture
            .store
            .commit_profile5_publication_once_with_policy(
                &policy,
                &second.0,
                &second_completed,
                &second_publication,
                sample,
            )
            .expect("promote newer reserved counter first")
        {
            super::super::BlobOnceOutcome::Inserted { blob } => blob,
            _ => panic!("newer reserved counter must insert"),
        };
        {
            let read = fixture
                .store
                .database
                .begin_read()
                .expect("newer promotion causal read");
            assert_eq!(
                read.open_table(PUBLISHER_HIGH_WATER)
                    .expect("publisher high-water")
                    .get(fixture.publisher.identity().as_slice())
                    .expect("read publisher high-water")
                    .expect("publisher high-water exists")
                    .value(),
                3
            );
        }
        let first_blob = match fixture
            .store
            .commit_profile5_publication_once_with_policy(
                &policy,
                &first.0,
                &first_completed,
                &first_publication,
                sample,
            )
            .expect("promote older reserved counter after newer durable work")
        {
            super::super::BlobOnceOutcome::Inserted { blob } => blob,
            _ => panic!("older reserved counter must insert"),
        };
        assert_eq!(first_blob.header.stamp.dot.counter, 1);
        assert_eq!(second_blob.header.stamp.dot.counter, 2);
        assert_eq!(
            fixture
                .store
                .get_blob(first_blob.transfer_id)
                .expect("lookup older reserved promotion"),
            Some(first_blob.clone())
        );
        assert_eq!(
            fixture
                .store
                .get_blob(second_blob.transfer_id)
                .expect("lookup newer reserved promotion"),
            Some(second_blob.clone())
        );

        let read = fixture
            .store
            .database
            .begin_read()
            .expect("causal audit read");
        assert_eq!(
            read.open_table(PUBLISHER_HIGH_WATER)
                .expect("publisher high-water")
                .get(fixture.publisher.identity().as_slice())
                .expect("read publisher high-water")
                .expect("publisher high-water exists")
                .value(),
            3
        );
        assert_eq!(
            read.open_table(super::super::ACCEPTED_DOTS)
                .expect("accepted dots")
                .len()
                .expect("accepted dot count"),
            3
        );
        assert!(
            read.open_table(super::super::CAUSAL_FRONTIER)
                .expect("causal frontier")
                .iter()
                .expect("frontier rows")
                .any(|row| row.expect("frontier row").1.value() == 3),
            "older Profile-5 promotions must not regress the causal high-water"
        );
    }

    fn append_real_upload_pack(
        fixture: &Fixture,
        reservation: &BlobUploadReservation,
        plaintext: &[u8],
    ) -> BlobPackCheckpoint {
        let identity = reservation.pack_identity();
        let root = PinnedBlobPackRoot::open(&fixture.store).expect("pack root");
        let mut writer = BlobPackWriter::open_projected_upload_pinned(&root, &identity, None)
            .expect("open initial upload pack");
        let sealer = BlobStreamSegmentSealer::from_test_key(
            *identity.upload_id().as_bytes(),
            *identity.request_digest(),
            reservation.content_epoch(),
            [0x91; 32],
            [0x92; 12],
        );
        let (segment, leaves) = sealer
            .seal(
                BlobStreamPlainPartition::new(
                    *identity.upload_id().as_bytes(),
                    *identity.request_digest(),
                    reservation.content_epoch(),
                    0,
                    0,
                    plaintext.len() as u64,
                    plaintext.to_vec(),
                )
                .expect("upload partition"),
            )
            .expect("seal upload segment");
        writer.append(&segment, leaves).expect("append upload pack");
        writer.checkpoint().expect("checkpoint upload pack")
    }

    fn upload_pack_plain_reader(
        fixture: &Fixture,
        reservation: &BlobUploadReservation,
        checkpoint: &BlobUploadCheckpoint,
    ) -> UploadPackPlainReader {
        let identity = reservation.pack_identity();
        let root = PinnedBlobPackRoot::open(&fixture.store).expect("pack root");
        let durable = checkpoint
            .durable_pack_checkpoint()
            .expect("projected durable upload pack");
        let pack = BlobPackReader::open_projected_upload_pinned(&root, &identity, durable)
            .expect("open projected upload pack reader");
        UploadPackPlainReader {
            root,
            identity,
            checkpoint: durable.clone(),
            pack,
            opener: BlobStreamSegmentOpener::from_test_key(
                *identity.upload_id().as_bytes(),
                *identity.request_digest(),
                reservation.content_epoch(),
                [0x91; 32],
                [0x92; 12],
            ),
            plaintext: Cursor::new(Vec::new()),
            position: 0,
            total_len: identity.total_len(),
        }
    }

    fn upload_artifact_snapshot(path: &PathBuf) -> Option<Vec<(String, Vec<u8>)>> {
        if !path.exists() {
            return None;
        }
        let mut rows = fs::read_dir(path)
            .expect("read upload artifact directory")
            .map(|entry| {
                let entry = entry.expect("upload artifact entry");
                let name = entry
                    .file_name()
                    .into_string()
                    .expect("UTF-8 artifact name");
                let bytes = fs::read(entry.path()).expect("read upload artifact");
                (name, bytes)
            })
            .collect::<Vec<_>>();
        rows.sort_by(|left, right| left.0.cmp(&right.0));
        Some(rows)
    }

    fn upload_pack_root_snapshot(root: &TestRoot) -> UploadPackTreeSnapshot {
        let path = root.0.join("blob-depot-v1").join("stream-packs-v2");
        if !path.exists() {
            return None;
        }
        let mut rows = fs::read_dir(path)
            .expect("read upload pack root")
            .map(|entry| {
                let entry = entry.expect("upload pack root entry");
                let name = entry
                    .file_name()
                    .into_string()
                    .expect("UTF-8 pack root artifact name");
                let bytes = entry
                    .file_type()
                    .expect("pack root artifact type")
                    .is_file()
                    .then(|| fs::read(entry.path()).expect("read pack root artifact"));
                (name, bytes)
            })
            .collect::<Vec<_>>();
        rows.sort_by(|left, right| left.0.cmp(&right.0));
        Some(rows)
    }

    fn upload_pack_tree_snapshot(root: &TestRoot) -> UploadPackTreeSnapshot {
        fn visit(base: &Path, directory: &Path, rows: &mut Vec<(String, Option<Vec<u8>>)>) {
            for entry in fs::read_dir(directory).expect("read upload pack tree") {
                let entry = entry.expect("upload pack tree entry");
                let path = entry.path();
                let relative = path
                    .strip_prefix(base)
                    .expect("upload pack path is below root")
                    .to_str()
                    .expect("UTF-8 upload pack path")
                    .to_owned();
                let file_type = entry.file_type().expect("upload pack tree entry type");
                if file_type.is_dir() {
                    rows.push((relative, None));
                    visit(base, &path, rows);
                } else {
                    assert!(file_type.is_file(), "upload pack tree contains only files");
                    rows.push((
                        relative,
                        Some(fs::read(path).expect("read upload pack tree file")),
                    ));
                }
            }
        }

        let path = root.0.join("blob-depot-v1").join("stream-packs-v2");
        if !path.exists() {
            return None;
        }
        let mut rows = Vec::new();
        visit(&path, &path, &mut rows);
        rows.sort_by(|left, right| left.0.cmp(&right.0));
        Some(rows)
    }

    fn cleanup_marker_count(snapshot: &UploadPackTreeSnapshot) -> usize {
        snapshot.as_ref().map_or(0, |rows| {
            rows.iter()
                .filter(|(name, _)| name.starts_with(".aster-upload-cleanup-"))
                .count()
        })
    }

    #[test]
    fn upload_reopen_discards_torn_unprojected_pack_tails() {
        // Audit must stop at durable progress; the next append may have torn at
        // either its length prefix or ciphertext, before any new checkpoint.
        for projected in [false, true] {
            for tail in [&[0][..], &[0, 0, 0][..], &[0, 0, 0, 64, 1, 2][..]] {
                let fixture = fixture("torn-pack-tail", 0x61, BlobDepotLimits::DEFAULT);
                let request = request(&fixture, b"torn-pack-tail", 2_097_152);
                let policy = fixture.store.control_policy_snapshot().expect("policy");
                let (reservation, initial) = fixture
                    .store
                    .reserve_blob_upload_with_policy(&policy, &request)
                    .expect("reserve");
                let identity = reservation.pack_identity();
                let root = PinnedBlobPackRoot::open(&fixture.store).expect("pack root");
                let checkpoint = if projected {
                    let mut writer =
                        BlobPackWriter::open_projected_upload_pinned(&root, &identity, None)
                            .expect("initial writer");
                    let sealer = BlobStreamSegmentSealer::from_test_key(
                        *identity.upload_id().as_bytes(),
                        *identity.request_digest(),
                        reservation.content_epoch(),
                        [0x91; 32],
                        [0x92; 12],
                    );
                    let (segment, leaves) = sealer
                        .seal(
                            BlobStreamPlainPartition::new(
                                *identity.upload_id().as_bytes(),
                                *identity.request_digest(),
                                reservation.content_epoch(),
                                0,
                                0,
                                request.total_len,
                                vec![0x5a; aster_mesh::BLOB_STREAM_SEGMENT_BYTES],
                            )
                            .expect("first full partition"),
                        )
                        .expect("seal first segment");
                    writer
                        .append(&segment, leaves)
                        .expect("append first segment");
                    let durable = writer.checkpoint().expect("sync first segment");
                    fixture
                        .store
                        .checkpoint_blob_upload(&policy, &reservation, initial, durable)
                        .expect("project first segment")
                } else {
                    initial
                };
                let pack_path = root.test_upload_path(&identity);
                let data_path = pack_path.join("segments.pack");
                let prefix = fs::read(&data_path).expect("committed prefix");
                let mut data = OpenOptions::new()
                    .append(true)
                    .open(&data_path)
                    .expect("pack");
                data.write_all(tail).expect("torn append");
                data.sync_all().expect("sync torn tail");
                drop(data);
                drop(root);
                let authority = fixture.publisher.mission_authority_id();
                drop(fixture.store);
                let before = upload_artifact_snapshot(&pack_path);
                Store::inspect_existing(fixture.root.database())
                    .expect("read-only audit ignores unprojected torn tail");
                assert_eq!(upload_artifact_snapshot(&pack_path), before);
                let reopened = Store::open_for_mission(fixture.root.database(), authority)
                    .expect("torn unprojected append cannot prevent reopen");
                let (resumed, exact) = reopened
                    .resume_blob_upload(&request.owner)
                    .expect("resume")
                    .expect("durable upload remains");
                assert_eq!(
                    exact, checkpoint,
                    "tail cannot invent acknowledged progress"
                );
                let root = PinnedBlobPackRoot::open(&reopened).expect("reopened root");
                let writer = BlobPackWriter::open_projected_upload_pinned(
                    &root,
                    &resumed.pack_identity(),
                    exact.durable_pack_checkpoint(),
                )
                .expect("resume truncates only unprojected tail");
                assert_eq!(
                    writer.plaintext_offset(),
                    checkpoint.durable_plaintext_offset()
                );
                assert_eq!(fs::read(data_path).expect("resumed pack"), prefix);
            }
        }
    }

    fn empty_upload_pack_directory(path: &Path) {
        for entry in fs::read_dir(path).expect("pack entries") {
            fs::remove_file(entry.expect("entry").path()).expect("unlink pack artifact");
        }
        fs::File::open(path)
            .expect("directory")
            .sync_all()
            .expect("sync empty directory");
    }

    #[test]
    fn upload_reopen_recovers_empty_cleanup_directory() {
        let fixture = fixture("empty-cleanup-directory", 0x62, BlobDepotLimits::DEFAULT);
        let request = request(&fixture, b"empty-cleanup-directory", 1_024);
        let policy = fixture.store.control_policy_snapshot().expect("policy");
        let (reservation, _) = fixture
            .store
            .reserve_blob_upload_with_policy(&policy, &request)
            .expect("reserve");
        let root = PinnedBlobPackRoot::open(&fixture.store).expect("pack root");
        let identity = reservation.pack_identity();
        let pack_path = root.test_upload_path(&identity);
        super::super::pack::stage_upload_pack_cleanup(&root, &identity)
            .expect("durable abort cleanup intent");
        // Crash after the last synced unlink, before rmdir/row removal.
        empty_upload_pack_directory(&pack_path);
        drop(root);
        let authority = fixture.publisher.mission_authority_id();
        drop(fixture.store);
        let before = upload_pack_tree_snapshot(&fixture.root);
        Store::inspect_existing(fixture.root.database()).expect("inspect cleanup gap");
        assert_eq!(upload_pack_tree_snapshot(&fixture.root), before);
        let reopened = Store::open_for_mission(fixture.root.database(), authority)
            .expect("exact cleanup intent recovers empty directory");
        assert!(!pack_path.exists());
        assert!(
            reopened
                .resume_blob_upload(&request.owner)
                .expect("resume")
                .is_none()
        );
        assert_eq!(
            cleanup_marker_count(&upload_pack_root_snapshot(&fixture.root)),
            0
        );
        reopened
            .reserve_blob_upload_with_policy(&policy, &request)
            .expect("same operation can reserve a fresh pack after completed abort");
    }

    #[test]
    fn upload_reopen_recovers_empty_reservation_directory() {
        let fixture = fixture(
            "empty-reservation-directory",
            0x63,
            BlobDepotLimits::DEFAULT,
        );
        let request = request(&fixture, b"empty-reservation-directory", 1_024);
        let policy = fixture.store.control_policy_snapshot().expect("policy");
        inject_test_fault(&fixture.store, UploadFaultPoint::ReservationPackSynced);
        fixture
            .store
            .reserve_blob_upload_with_policy(&policy, &request)
            .expect_err("crash before upload row commits");
        let digest = request_digest_for(&request).expect("request digest");
        let identity = BlobPackIdentity::new(
            upload_id_for(&request.owner, digest).expect("upload ID"),
            digest,
            request.total_len,
        );
        let root = PinnedBlobPackRoot::open(&fixture.store).expect("pack root");
        let pack_path = root.test_upload_path(&identity);
        // Same physical state as a crash after mkdir and before marker install.
        empty_upload_pack_directory(&pack_path);
        drop(root);
        let authority = fixture.publisher.mission_authority_id();
        drop(fixture.store);
        let before = upload_pack_tree_snapshot(&fixture.root);
        Store::inspect_existing(fixture.root.database()).expect("inspect reservation gap");
        assert_eq!(upload_pack_tree_snapshot(&fixture.root), before);
        let reopened = Store::open_for_mission(fixture.root.database(), authority)
            .expect("exact reservation intent recovers empty directory");
        assert!(!pack_path.exists());
        let (reservation, _) = reopened
            .reserve_blob_upload_with_policy(&policy, &request)
            .expect("reservation retry succeeds");
        assert_eq!(reservation.pack_identity(), identity);
    }

    #[test]
    fn upload_reopen_accepts_empty_lifecycle_deletion_directory() {
        let fixture = fixture("empty-lifecycle-directory", 0x65, BlobDepotLimits::DEFAULT);
        let request = request(&fixture, b"empty-lifecycle-directory", 1_024);
        let policy = fixture.store.control_policy_snapshot().expect("policy");
        let (reservation, initial, open) = reserve_profile5(&fixture, &request);
        let completed =
            complete_profile5_pack(&fixture, &policy, &reservation, initial, &open, 0x5a);
        let publication = profile5_publication(&fixture, &open, &completed);
        let outcome = fixture
            .store
            .commit_profile5_publication_once_with_policy(
                &policy,
                &reservation,
                &completed,
                &publication,
                publication.publication().final_custody(),
            )
            .expect("promote native pack");
        let variant = outcome.blob().variant_id;
        let budget = super::super::lifecycle::BlobMaintenanceBudget::new(256, 8, 32 * 1024 * 1024)
            .expect("maintenance budget");
        for turn in 0..64 {
            fixture
                .store
                .run_blob_maintenance_turn_with_sample(
                    budget,
                    (turn == 0).then_some(CustodySample {
                        clock_id: [0x31; 16],
                        tick_ms: 100_100,
                    }),
                )
                .expect("retire finite publication");
            if matches!(
                fixture
                    .store
                    .blob_for_owner_with_policy(&policy, &request.owner),
                Err(StoreError::Blob(BlobStoreError::ExpiredOrRetired))
            ) {
                break;
            }
        }
        fixture
            .store
            .test_admit_blob_deletion_manifest(variant)
            .expect("admit native pack deletion");
        let root = PinnedBlobPackRoot::open(&fixture.store).expect("pack root");
        let pack_path = root.test_upload_path(&reservation.pack_identity());
        empty_upload_pack_directory(&pack_path);
        drop(root);
        let authority = fixture.publisher.mission_authority_id();
        drop(fixture.store);
        let before = upload_pack_tree_snapshot(&fixture.root);
        Store::inspect_existing(fixture.root.database()).expect("inspect lifecycle deletion gap");
        assert_eq!(upload_pack_tree_snapshot(&fixture.root), before);
        let reopened = Store::open_for_mission(fixture.root.database(), authority)
            .expect("durable deletion manifest authorizes empty pack directory");
        // Deletion keeps its exact durable evidence until maintenance finalizes.
        let report = reopened
            .run_blob_capacity_gc(budget, None)
            .expect("finish physical deletion");
        assert_eq!(report.manifests_finalized, 1);
        assert!(!pack_path.exists());
    }

    #[test]
    fn upload_reopen_rejects_unauthorized_markerless_directories() {
        for damage in [
            "no-authority",
            "wrong-cleanup",
            "wrong-reservation",
            "foreign-file",
            "live-reservation",
        ] {
            let fixture = fixture(damage, 0x64, BlobDepotLimits::DEFAULT);
            let request = request(&fixture, damage.as_bytes(), 1_024);
            let policy = fixture.store.control_policy_snapshot().expect("policy");
            let (reservation, _) = fixture
                .store
                .reserve_blob_upload_with_policy(&policy, &request)
                .expect("reserve");
            let root = PinnedBlobPackRoot::open(&fixture.store).expect("pack root");
            let identity = reservation.pack_identity();
            let pack_path = root.test_upload_path(&identity);
            empty_upload_pack_directory(&pack_path);
            match damage {
                "no-authority" => {}
                "wrong-cleanup" => {
                    let wrong =
                        BlobPackIdentity::new(identity.upload_id(), [0x99; 32], request.total_len);
                    super::super::pack::stage_upload_pack_cleanup(&root, &wrong)
                        .expect("wrong cleanup");
                }
                "wrong-reservation" => {
                    let wrong =
                        BlobPackIdentity::new(identity.upload_id(), [0x99; 32], request.total_len);
                    super::super::pack::stage_upload_pack_reservation(&root, &wrong)
                        .expect("wrong reservation");
                }
                "foreign-file" => {
                    super::super::pack::stage_upload_pack_cleanup(&root, &identity)
                        .expect("cleanup");
                    fs::write(pack_path.join("foreign"), b"preserve").expect("foreign file");
                }
                "live-reservation" => {
                    super::super::pack::stage_upload_pack_reservation(&root, &identity)
                        .expect("reservation");
                }
                _ => unreachable!(),
            }
            drop(root);
            let authority = fixture.publisher.mission_authority_id();
            drop(fixture.store);
            let before = upload_pack_tree_snapshot(&fixture.root);
            assert!(
                Store::inspect_existing(fixture.root.database()).is_err(),
                "{damage}"
            );
            assert!(
                Store::open_for_mission(fixture.root.database(), authority).is_err(),
                "{damage}"
            );
            assert_eq!(upload_pack_tree_snapshot(&fixture.root), before, "{damage}");
        }
    }

    #[test]
    fn upload_pack_audit_is_bidirectional_exact_and_non_mutating() {
        for damage in [
            "absent-directory",
            "missing-marker",
            "missing-journals",
            "truncated-data",
            "replaced-data",
            "checkpoint-mismatch",
        ] {
            let fixture = fixture(
                &format!("pack-audit-{damage}"),
                0x48,
                BlobDepotLimits::DEFAULT,
            );
            let plaintext = vec![0x5a; 4_096];
            let request = request(&fixture, damage.as_bytes(), plaintext.len() as u64);
            let policy = fixture.store.control_policy_snapshot().expect("policy");
            let (reservation, initial) = fixture
                .store
                .reserve_blob_upload_with_policy(&policy, &request)
                .expect("reserve audited upload");
            let durable = append_real_upload_pack(&fixture, &reservation, &plaintext);
            fixture
                .store
                .checkpoint_blob_upload(&policy, &reservation, initial, durable.clone())
                .expect("project audited upload checkpoint");
            let pack_root = PinnedBlobPackRoot::open(&fixture.store).expect("pack root");
            let pack_path = pack_root.test_upload_path(&reservation.pack_identity());
            drop(pack_root);
            let authority = fixture.publisher.mission_authority_id();
            drop(fixture.store);

            match damage {
                "absent-directory" => fs::remove_dir_all(&pack_path).expect("remove upload pack"),
                "missing-marker" => fs::remove_file(pack_path.join(".aster-upload-v1"))
                    .expect("remove upload marker"),
                "missing-journals" => {
                    for name in ["checkpoint.0", "checkpoint.1"] {
                        if pack_path.join(name).exists() {
                            fs::remove_file(pack_path.join(name)).expect("remove checkpoint");
                        }
                    }
                }
                "truncated-data" => OpenOptions::new()
                    .write(true)
                    .open(pack_path.join("segments.pack"))
                    .expect("open pack for truncation")
                    .set_len(durable.pack_len() - 1)
                    .expect("truncate pack"),
                "replaced-data" => {
                    let mut pack = OpenOptions::new()
                        .read(true)
                        .write(true)
                        .open(pack_path.join("segments.pack"))
                        .expect("open pack for replacement");
                    let ciphertext_offset = super::super::pack::PACK_HEADER_LEN
                        + 4
                        + (BLOB_STREAM_SEGMENT_ENCODED_OVERHEAD_BYTES - 16) as u64;
                    pack.seek(SeekFrom::Start(ciphertext_offset))
                        .expect("seek first ciphertext byte");
                    let mut byte = [0];
                    pack.read_exact(&mut byte).expect("read ciphertext byte");
                    byte[0] ^= 0x80;
                    pack.seek(SeekFrom::Start(ciphertext_offset))
                        .expect("rewind ciphertext byte");
                    pack.write_all(&byte).expect("replace ciphertext byte");
                    pack.sync_all().expect("sync replacement");
                }
                "checkpoint-mismatch" => {
                    let projected = if durable.generation().is_multiple_of(2) {
                        "checkpoint.0"
                    } else {
                        "checkpoint.1"
                    };
                    fs::remove_file(pack_path.join(projected))
                        .expect("remove exact projected checkpoint");
                }
                _ => unreachable!(),
            }
            let before = upload_artifact_snapshot(&pack_path);
            let database_before = fs::read(fixture.root.database()).expect("database bytes");
            assert!(
                Store::inspect_existing(fixture.root.database()).is_err(),
                "{damage}"
            );
            assert_eq!(upload_artifact_snapshot(&pack_path), before, "{damage} RO");
            assert_eq!(
                fs::read(fixture.root.database()).expect("database after RO"),
                database_before,
                "{damage} RO database"
            );
            assert!(
                Store::open_for_mission(fixture.root.database(), authority).is_err(),
                "{damage}"
            );
            assert_eq!(upload_artifact_snapshot(&pack_path), before, "{damage} RW");
        }
    }

    #[test]
    fn upload_restart_restores_exact_request_and_checkpoint() {
        // Break caught: reconstructing an upload from current policy loses its
        // immutable request or advances beyond the store-projected journal.
        let mut fixture = fixture("restart", 0x31, BlobDepotLimits::DEFAULT);
        let request = request(&fixture, b"restart-owner", 4_096);
        let policy = fixture.store.control_policy_snapshot().expect("policy");
        let (reservation, initial) = fixture
            .store
            .reserve_blob_upload_with_policy(&policy, &request)
            .expect("reserve upload");
        assert_eq!(reservation.request(), &request);
        assert_eq!(reservation.control_policy(), &policy);
        assert_eq!(reservation.content_epoch(), 1);
        assert!(reservation.staging_charge_bytes() > request.total_len);
        assert!(reservation.conversion_overhead_bytes() > 0);
        assert_eq!(
            reservation.reserved_bytes(),
            reservation
                .staging_charge_bytes()
                .checked_add(request.total_len)
                .and_then(|value| value.checked_add(reservation.conversion_overhead_bytes()))
                .expect("bounded upload charge")
        );
        assert_eq!(initial.credit_consumed_bytes(), 0);
        assert_eq!(
            initial.credit_remaining_bytes(),
            reservation.reserved_bytes()
        );

        let pack_root = PinnedBlobPackRoot::open(&fixture.store).expect("pack root");
        let mut writer = BlobPackWriter::open_projected_upload_pinned(
            &pack_root,
            &reservation.pack_identity(),
            None,
        )
        .expect("open initial upload pack");
        let durable = writer.checkpoint().expect("durable pack checkpoint");

        // The journal may lead redb, but restart must not invent that progress.
        drop(writer);
        let authority = fixture.publisher.mission_authority_id();
        drop(fixture.store);
        fixture.store = Store::open_for_mission(fixture.root.database(), authority)
            .expect("reopen before projection");
        let (restarted, checkpoint) = fixture
            .store
            .resume_blob_upload(&request.owner)
            .expect("resume before projection")
            .expect("upload remains");
        assert_eq!(restarted.request(), &request);
        assert_eq!(checkpoint, initial);

        assert!(
            fixture
                .store
                .checkpoint_blob_upload(&policy, &restarted, checkpoint.clone(), durable)
                .is_err(),
            "pre-restart checkpoint capability must not cross Stores"
        );
        let pack_root = PinnedBlobPackRoot::open(&fixture.store).expect("reopened pack root");
        let mut writer = BlobPackWriter::open_projected_upload_pinned(
            &pack_root,
            &restarted.pack_identity(),
            checkpoint.durable_pack_checkpoint(),
        )
        .expect("restore exact projected pack");
        let durable = writer.checkpoint().expect("rebound durable checkpoint");
        let projected = fixture
            .store
            .checkpoint_blob_upload(&policy, &restarted, checkpoint, durable.clone())
            .expect("project durable checkpoint");
        assert_eq!(projected.generation(), durable.generation());
        assert_eq!(projected.durable_pack_len(), durable.pack_len());

        drop(writer);
        drop(fixture.store);
        fixture.store = Store::open_for_mission(fixture.root.database(), authority)
            .expect("reopen projected upload");
        let (restarted, exact) = fixture
            .store
            .resume_blob_upload(&request.owner)
            .expect("resume projected")
            .expect("upload remains projected");
        assert_eq!(restarted.request(), &request);
        assert_eq!(restarted.control_policy(), &policy);
        assert_eq!(exact, projected);
        let pack_root = PinnedBlobPackRoot::open(&fixture.store).expect("reopen pack root");
        let writer = BlobPackWriter::open_projected_upload_pinned(
            &pack_root,
            &restarted.pack_identity(),
            exact.durable_pack_checkpoint(),
        )
        .expect("reopen exact projected pack");
        assert_eq!(writer.next_index(), durable.next_index());
        assert_eq!(writer.plaintext_offset(), durable.plaintext_offset());
    }

    #[test]
    fn upload_capacity_charges_the_exact_canonical_digest_artifact() {
        let fixture = fixture("digest-capacity", 0x30, BlobDepotLimits::DEFAULT);
        let total_len = u64::from(aster_mesh::SELECTED_BLOB_CHUNK_SIZE) * 2 + 1;
        let request = request(&fixture, b"digest-capacity", total_len);
        let policy = fixture.store.control_policy_snapshot().expect("policy");
        let (reservation, _) = fixture
            .store
            .reserve_blob_upload_with_policy(&policy, &request)
            .expect("reserve upload");
        let pack_bytes =
            super::super::pack::reserved_upload_pack_bytes(total_len).expect("pack reservation");
        let digest_bytes = 86 + 3 * 32;
        assert_eq!(
            reservation.staging_charge_bytes(),
            pack_bytes + digest_bytes,
            "every durable sidecar byte must be reserved before creation"
        );
    }

    #[test]
    fn legacy_upload_capacity_upgrade_is_atomic_under_pressure_and_reopen() {
        let mut fixture = fixture("legacy-digest-capacity", 0x2f, BlobDepotLimits::DEFAULT);
        let total_len = u64::from(aster_mesh::SELECTED_BLOB_CHUNK_SIZE) * 2 + 1;
        let request = request(&fixture, b"legacy-digest-capacity", total_len);
        let policy = fixture.store.control_policy_snapshot().expect("policy");
        fixture
            .store
            .reserve_blob_upload_with_policy(&policy, &request)
            .expect("seed current upload");
        let owner_key = blob_operation_owner_key(&request.owner).expect("owner key");
        let write = fixture.store.database.begin_write().expect("write");
        let encoded = {
            let uploads = write
                .open_table(super::super::BLOB_UPLOADS)
                .expect("uploads");
            uploads
                .get(owner_key.as_slice())
                .expect("read upload")
                .expect("upload row")
                .value()
                .to_vec()
        };
        let mut upload = DurableBlobUpload::decode(
            Arc::clone(&fixture.store.blob_completion_authority),
            &encoded,
        )
        .expect("decode upload");
        upload.format_version = LEGACY_UPLOAD_VERSION;
        upload.reservation.staging_charge_bytes =
            super::super::depot::legacy_blob_upload_staging_charge(total_len)
                .expect("legacy staging");
        upload.reservation.total_capacity =
            super::super::depot::legacy_blob_upload_capacity(total_len).expect("legacy capacity");
        write
            .open_table(super::super::BLOB_UPLOADS)
            .expect("uploads")
            .insert(
                owner_key.as_slice(),
                upload.encode().expect("encode legacy").as_slice(),
            )
            .expect("downgrade upload");
        write.commit().expect("commit legacy row");

        let authority = fixture.publisher.mission_authority_id();
        let legacy_bytes = upload.reservation.total_capacity.bytes;
        let current_bytes = super::super::depot::blob_upload_capacity(total_len)
            .expect("current capacity")
            .bytes;
        drop(fixture.store);
        fixture.store = Store::open_with_limits_and_blob_depot_limits_for_mission(
            fixture.root.database(),
            StoreLimits::default(),
            BlobDepotLimits::new(legacy_bytes, 16, 2).expect("legacy exact limit"),
            authority,
        )
        .expect("reopen legacy upload");
        let database_before = fs::read(fixture.root.database()).expect("database snapshot");
        let artifacts_before = upload_pack_tree_snapshot(&fixture.root);
        let error = fixture
            .store
            .reserve_blob_upload_with_policy(&policy, &request)
            .expect_err("upgrade must fail under exact legacy pressure");
        assert!(matches!(
            error,
            StoreError::Blob(BlobStoreError::DepotByteLimitExceeded { .. })
        ));
        assert_eq!(
            fs::read(fixture.root.database()).expect("database after pressure"),
            database_before
        );
        assert_eq!(upload_pack_tree_snapshot(&fixture.root), artifacts_before);

        drop(fixture.store);
        fixture.store = Store::open_with_limits_and_blob_depot_limits_for_mission(
            fixture.root.database(),
            StoreLimits::default(),
            BlobDepotLimits::new(current_bytes, 16, 2).expect("upgraded exact limit"),
            authority,
        )
        .expect("reopen for upgrade");
        let (upgraded, _) = fixture
            .store
            .reserve_blob_upload_with_policy(&policy, &request)
            .expect("atomically upgrade legacy row");
        assert_eq!(upgraded.reserved_bytes(), current_bytes);
        assert_eq!(
            upgraded.staging_charge_bytes(),
            super::super::depot::blob_upload_staging_charge(total_len).expect("current staging")
        );
    }

    #[test]
    fn store_reopen_accepts_and_new_upload_recreates_torn_unprojected_sidecar() {
        let mut fixture = fixture("torn-unprojected-sidecar", 0x2e, BlobDepotLimits::DEFAULT);
        let request = request(&fixture, b"torn-unprojected-sidecar", 4_096);
        let policy = fixture.store.control_policy_snapshot().expect("policy");
        let (reservation, checkpoint) = fixture
            .store
            .reserve_blob_upload_with_policy(&policy, &request)
            .expect("reserve upload");
        let upload_name = reservation
            .pack_identity()
            .upload_id()
            .as_bytes()
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>();
        let sidecar = fixture
            .root
            .0
            .join("blob-depot-v1")
            .join("stream-packs-v2")
            .join(upload_name)
            .join("canonical-digests-v1.bin");
        fs::write(&sidecar, b"ASTR").expect("write torn final-name sidecar");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            fs::set_permissions(&sidecar, fs::Permissions::from_mode(0o600))
                .expect("make torn artifact private");
        }
        let authority = fixture.publisher.mission_authority_id();
        drop(fixture.store);
        fixture.store = Store::open_for_mission(fixture.root.database(), authority)
            .expect("unprojected torn sidecar cannot prevent Store reopen");
        let root = PinnedBlobPackRoot::open(&fixture.store).expect("pack root");
        drop(
            super::super::pack::BlobUploadDigestWriter::open_projected_upload_pinned(
                &root,
                &reservation.pack_identity(),
                checkpoint.durable_pack_checkpoint(),
            )
            .expect("new upload recreates torn sidecar atomically"),
        );
        assert_eq!(
            fs::metadata(sidecar).expect("recreated sidecar").len(),
            super::super::pack::UPLOAD_DIGEST_HEADER_LEN
        );
    }

    #[cfg(unix)]
    #[test]
    fn digest_sidecar_enforces_the_documented_local_private_boundary() {
        use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _, symlink};

        let fixture = fixture("digest-private-boundary", 0x2d, BlobDepotLimits::DEFAULT);
        let request = request(&fixture, b"digest-private-boundary", 4_096);
        let policy = fixture.store.control_policy_snapshot().expect("policy");
        let (reservation, checkpoint) = fixture
            .store
            .reserve_blob_upload_with_policy(&policy, &request)
            .expect("reserve upload");
        let root = PinnedBlobPackRoot::open(&fixture.store).expect("pack root");
        drop(
            super::super::pack::BlobUploadDigestWriter::open_projected_upload_pinned(
                &root,
                &reservation.pack_identity(),
                checkpoint.durable_pack_checkpoint(),
            )
            .expect("create sidecar"),
        );
        let upload_name = reservation
            .pack_identity()
            .upload_id()
            .as_bytes()
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>();
        let sidecar = fixture
            .root
            .0
            .join("blob-depot-v1")
            .join("stream-packs-v2")
            .join(upload_name)
            .join("canonical-digests-v1.bin");
        let metadata = fs::metadata(&sidecar).expect("sidecar metadata");
        assert_eq!(metadata.permissions().mode() & 0o777, 0o600);
        assert_eq!(metadata.nlink(), 1);

        let target = fixture.root.0.join("digest-sidecar-target");
        fs::write(
            &target,
            vec![0_u8; super::super::pack::UPLOAD_DIGEST_HEADER_LEN as usize],
        )
        .expect("symlink target");
        fs::remove_file(&sidecar).expect("remove sidecar");
        symlink(&target, &sidecar).expect("install hostile symlink");
        assert!(
            super::super::pack::BlobUploadDigestWriter::open_projected_upload_pinned(
                &root,
                &reservation.pack_identity(),
                checkpoint.durable_pack_checkpoint(),
            )
            .is_err(),
            "O_NOFOLLOW must reject a sidecar symlink even without a projection"
        );
    }

    #[test]
    fn upload_retry_and_checkpoint_reject_immutable_policy_mismatch() {
        // Break caught: retry and checkpoint must not accept a live
        // caller-supplied policy when the durable upload is bound to different
        // immutable policy bytes.
        let fixture = fixture("policy-mismatch", 0x30, BlobDepotLimits::DEFAULT);
        let request = request(&fixture, b"policy-mismatch", 1_024);
        let policy = fixture.store.control_policy_snapshot().expect("policy");
        fixture
            .store
            .reserve_blob_upload_with_policy(&policy, &request)
            .expect("reserve upload");

        let owner_key = blob_operation_owner_key(&request.owner).expect("owner key");
        let write = fixture
            .store
            .database
            .begin_write()
            .expect("policy mismatch write");
        let encoded = write
            .open_table(super::super::BLOB_UPLOADS)
            .expect("uploads")
            .get(owner_key.as_slice())
            .expect("read upload")
            .expect("upload exists")
            .value()
            .to_vec();
        let mut upload = DurableBlobUpload::decode(
            Arc::clone(&fixture.store.blob_completion_authority),
            &encoded,
        )
        .expect("decode upload");
        upload.reservation.control_policy = ControlPolicySnapshot {
            authority: [0xee; 32],
            head: None,
        };
        write
            .open_table(super::super::BLOB_UPLOADS)
            .expect("uploads")
            .insert(
                owner_key.as_slice(),
                upload.encode().expect("encode upload").as_slice(),
            )
            .expect("replace upload");
        write.commit().expect("commit mismatch");

        let error = fixture
            .store
            .reserve_blob_upload_with_policy(&policy, &request)
            .expect_err("retry must bind the immutable reservation policy");
        assert!(matches!(
            error,
            StoreError::Blob(BlobStoreError::ReservationChanged)
        ));

        let (corrupted, checkpoint) = fixture
            .store
            .resume_blob_upload(&request.owner)
            .expect("resume corrupted reservation")
            .expect("corrupted reservation remains durable");
        let durable = append_real_upload_pack(&fixture, &corrupted, &[0x42; 1_024]);
        let error = fixture
            .store
            .checkpoint_blob_upload(&policy, &corrupted, checkpoint, durable)
            .expect_err("checkpoint must bind the immutable reservation policy");
        assert!(matches!(
            error,
            StoreError::Blob(BlobStoreError::ReservationChanged)
        ));
    }

    #[test]
    fn upload_capacity_remains_charged_through_canonical_promotion() {
        // One selected 1-KiB chunk occupies plaintext + the canonical 153-byte
        // file header + 16-byte AEAD tag.
        let plaintext = vec![0x71; 1_024];
        let canonical_bytes = 1_024 + 153 + 16;
        let pack_bytes = super::super::pack::reserved_upload_pack_bytes(plaintext.len() as u64)
            .expect("pack reservation");
        let digest_sidecar_bytes =
            super::super::pack::upload_digest_reserved_bytes(plaintext.len() as u64)
                .expect("digest sidecar reservation");
        assert_eq!(digest_sidecar_bytes, 118);
        let staging_bytes = pack_bytes + digest_sidecar_bytes;
        let exact_bytes = staging_bytes + canonical_bytes;
        let mut fixture = fixture(
            "promotion",
            0x32,
            BlobDepotLimits::new(exact_bytes, 1, 1).expect("exact limits"),
        );
        let mut request = request(&fixture, b"exact-limit", plaintext.len() as u64);
        request.ttl_ms = None;
        let policy = fixture.store.control_policy_snapshot().expect("policy");
        let (reservation, _) = fixture
            .store
            .reserve_blob_upload_with_policy(&policy, &request)
            .expect("reserve exact capacity");
        assert_eq!(reservation.reserved_bytes(), exact_bytes);
        let durable = append_real_upload_pack(&fixture, &reservation, &plaintext);
        let initial = fixture
            .store
            .resume_blob_upload(&request.owner)
            .expect("load upload")
            .expect("reserved upload")
            .1;
        let projected = fixture
            .store
            .checkpoint_blob_upload(&policy, &reservation, initial, durable)
            .expect("project real upload pack");

        let mut prepared_source = upload_pack_plain_reader(&fixture, &reservation, &projected);
        let prepared = prepare_blob(
            &mut prepared_source,
            crate::SELECTED_BLOB_CHUNK_SIZE,
            BlobMetadata::new(request.media_type.clone(), request.schema_id.clone())
                .expect("metadata"),
        )
        .expect("prepare upload");
        let mut encryption_source = upload_pack_plain_reader(&fixture, &reservation, &projected);
        let mut service = fixture
            .publisher
            .blob_service_with_store(
                &fixture.scope,
                &fixture.topic,
                1,
                fixture
                    .store
                    .blob_depot_for_upload(&reservation)
                    .expect("upload-bound depot"),
            )
            .expect("upload service");
        let manifest = service
            .install_prepared(&prepared)
            .expect("install prepared");
        let progress = service
            .encrypt_some(&mut encryption_source, &manifest, u64::MAX)
            .expect("encrypt exact upload");
        assert!(progress.complete);
        let finished = service.finish_manifest(&manifest).expect("finish manifest");
        drop(service);

        let (_, converted) = fixture
            .store
            .resume_blob_upload(&request.owner)
            .expect("resume converted")
            .expect("converted upload remains provisional");
        assert_eq!(converted.credit_remaining_bytes(), staging_bytes);
        assert_eq!(converted.credit_remaining_chunks(), 0);
        assert_eq!(converted.credit_remaining_variants(), 0);
        assert_eq!(converted.credit_consumed_bytes(), canonical_bytes);

        let intent = BlobPublicationIntent::new_with_ttl(
            request.owner.publisher,
            request.topic.clone(),
            request.scope.clone(),
            request.priority,
            prepared.id(),
            request.ttl_ms,
        )
        .expect("publication intent");
        let operation = BlobOperationRequest::new(&request.owner.operation, &intent);
        let publication_reservation = fixture
            .store
            .reserve_blob_with_policy(
                &policy,
                request.owner.publisher,
                &request.topic,
                &request.scope,
            )
            .expect("publication reservation");
        assert_eq!(publication_reservation.counter(), 1);
        let header = publication_reservation
            .header(
                request.priority,
                finished.route_commitment(),
                u64::try_from(finished.manifest_bytes().len()).expect("manifest length"),
                reservation.content_epoch(),
            )
            .expect("publication header");
        let sealed = fixture
            .publisher
            .seal_blob_manifest(&header, finished.manifest_bytes())
            .expect("seal manifest")
            .bytes;
        let route = fixture.reader.verify_blob(&sealed).expect("verify route");
        let (blob, manifest_bytes) = match fixture
            .reader
            .verify_blob_content(route, &sealed)
            .expect("verify content")
        {
            BlobContentVerification::ContentVerified {
                blob,
                manifest_bytes,
            } => (blob, manifest_bytes),
            BlobContentVerification::RouteOnly(_) => panic!("member unexpectedly route-only"),
        };
        let completion = fixture
            .store
            .completed_local_blob(&blob, &manifest_bytes)
            .expect("completed upload proof");
        let outcome = fixture
            .store
            .commit_reserved_blob_once_with_policy(
                &policy,
                &operation,
                &publication_reservation,
                &blob,
                &sealed,
                &completion,
            )
            .expect("canonical promotion");
        assert!(outcome.inserted());
        let pack_root = PinnedBlobPackRoot::open(&fixture.store).expect("post-commit pack root");
        super::super::pack::inject_test_fault(
            &pack_root,
            super::super::pack::BlobPackFaultPoint::CleanupDurable,
        );
        fixture
            .store
            .complete_blob_upload(&reservation, outcome.blob().transfer_id)
            .expect_err("inject crash after durable pack removal");
        assert!(
            fixture
                .store
                .resume_blob_upload(&request.owner)
                .expect("resume cleanup gap")
                .is_some(),
            "redb authority remains charged across cleanup crash"
        );
        let authority = fixture.publisher.mission_authority_id();
        drop(fixture.store);
        let cleanup_gap = upload_pack_root_snapshot(&fixture.root);
        assert_eq!(cleanup_marker_count(&cleanup_gap), 1);
        Store::inspect_existing(fixture.root.database())
            .expect("read-only open accepts completed cleanup gap");
        assert_eq!(
            upload_pack_root_snapshot(&fixture.root),
            cleanup_gap,
            "read-only open must not remove the completion marker"
        );
        let reopened = Store::open_with_limits_and_blob_depot_limits_for_mission(
            fixture.root.database(),
            StoreLimits::default(),
            BlobDepotLimits::new(exact_bytes, 1, 1).expect("cleanup-gap reopen limits"),
            authority,
        )
        .expect("cleanup marker converges completed upload on reopen");
        assert!(
            reopened
                .resume_blob_upload(&request.owner)
                .expect("read converged completion")
                .is_none(),
            "canonical authority remains while provisional charge is released"
        );
        assert_eq!(
            cleanup_marker_count(&upload_pack_root_snapshot(&fixture.root)),
            0,
            "writable recovery must reclaim the completion marker without retry"
        );
        drop(reopened);
        Store::open_with_limits_and_blob_depot_limits_for_mission(
            fixture.root.database(),
            StoreLimits::default(),
            BlobDepotLimits::new(exact_bytes, 1, 1).expect("repeat-open limits"),
            authority,
        )
        .expect("repeated completion recovery is idempotent");
        assert_eq!(
            cleanup_marker_count(&upload_pack_root_snapshot(&fixture.root)),
            0
        );
    }

    #[test]
    fn upload_crash_boundaries_reopen_to_one_authority() {
        // Break caught: capacity credit projected separately from canonical
        // import/chunk rows can be lost, duplicated, or spent by another import.
        let plaintext = vec![0x81; 1_024];
        let exact_bytes = super::super::depot::blob_upload_capacity(plaintext.len() as u64)
            .expect("upload capacity")
            .bytes;
        let mut fixture = fixture(
            "crash-boundaries",
            0x33,
            BlobDepotLimits::new(exact_bytes, 1, 1).expect("exact limits"),
        );
        let request = request(&fixture, b"credit-owner", plaintext.len() as u64);
        let policy = fixture.store.control_policy_snapshot().expect("policy");
        let (reservation, initial) = fixture
            .store
            .reserve_blob_upload_with_policy(&policy, &request)
            .expect("reserve credit");
        let unrelated = prepare_blob(
            &mut Cursor::new(vec![0x82; plaintext.len()]),
            crate::SELECTED_BLOB_CHUNK_SIZE,
            BlobMetadata::new(Some("image/tiff".into()), b"geo-v4".to_vec()).expect("metadata"),
        )
        .expect("prepare unrelated");
        let mut unrelated_service = fixture
            .publisher
            .blob_service_with_store(
                &fixture.scope,
                &fixture.topic,
                1,
                fixture
                    .store
                    .blob_depot_for_local_publish()
                    .expect("normal depot"),
            )
            .expect("unrelated service");
        assert!(unrelated_service.install_prepared(&unrelated).is_err());
        drop(unrelated_service);

        let authority = fixture.publisher.mission_authority_id();
        drop(fixture.store);
        fixture.store = Store::open_with_limits_and_blob_depot_limits_for_mission(
            fixture.root.database(),
            StoreLimits::default(),
            BlobDepotLimits::new(exact_bytes, 1, 1).expect("reopen limits"),
            authority,
        )
        .expect("reopen reserved credit");
        let (restarted, checkpoint) = fixture
            .store
            .resume_blob_upload(&request.owner)
            .expect("resume credit")
            .expect("credit survives");
        assert_eq!(checkpoint, initial);
        assert!(fixture.store.blob_depot_for_upload(&reservation).is_err());

        let prepared = prepare_blob(
            &mut Cursor::new(&plaintext),
            crate::SELECTED_BLOB_CHUNK_SIZE,
            BlobMetadata::new(request.media_type.clone(), request.schema_id.clone())
                .expect("metadata"),
        )
        .expect("prepare matching");
        let mut service = fixture
            .publisher
            .blob_service_with_store(
                &fixture.scope,
                &fixture.topic,
                1,
                fixture
                    .store
                    .blob_depot_for_upload(&restarted)
                    .expect("matching credit"),
            )
            .expect("matching service");
        let _manifest = service
            .install_prepared(&prepared)
            .expect("consume variant/chunk credit");
        drop(service);

        // Import and digest rows consume variant/chunk units atomically, while
        // the byte credit remains until the expected canonical record exists.
        drop(fixture.store);
        fixture.store = Store::open_with_limits_and_blob_depot_limits_for_mission(
            fixture.root.database(),
            StoreLimits::default(),
            BlobDepotLimits::new(exact_bytes, 1, 1).expect("second reopen limits"),
            authority,
        )
        .expect("reopen partial conversion");
        let (restarted, partial) = fixture
            .store
            .resume_blob_upload(&request.owner)
            .expect("resume partial")
            .expect("partial upload remains");
        assert_eq!(partial.credit_consumed_variants(), 1);
        assert_eq!(partial.credit_consumed_chunks(), 1);
        assert_eq!(partial.credit_consumed_bytes(), 0);
        assert_eq!(partial.credit_remaining_bytes(), exact_bytes);
        assert!(
            fixture
                .store
                .abort_blob_upload(&restarted)
                .expect("abort partial")
        );
        assert!(
            fixture
                .store
                .resume_blob_upload(&request.owner)
                .expect("resume aborted")
                .is_none()
        );
    }

    #[test]
    fn upload_abort_removes_pack_before_releasing_credit_and_retry_converges() {
        // Break caught: deleting only the redb upload row leaks the deterministic
        // pack directory and makes the same immutable request impossible to retry.
        let fixture = fixture("abort-cleanup", 0x34, BlobDepotLimits::DEFAULT);
        let request = request(&fixture, b"abort-cleanup", 1_024);
        let policy = fixture.store.control_policy_snapshot().expect("policy");
        let (reservation, _) = fixture
            .store
            .reserve_blob_upload_with_policy(&policy, &request)
            .expect("reserve upload");
        append_real_upload_pack(&fixture, &reservation, &vec![0xa1; 1_024]);

        let pack_root = PinnedBlobPackRoot::open(&fixture.store).expect("pack root");
        super::super::pack::inject_test_fault(
            &pack_root,
            super::super::pack::BlobPackFaultPoint::CleanupDurable,
        );
        assert!(fixture.store.abort_blob_upload(&reservation).is_err());

        let authority = fixture.publisher.mission_authority_id();
        drop(fixture.store);
        let cleanup_gap = upload_pack_root_snapshot(&fixture.root);
        assert_eq!(cleanup_marker_count(&cleanup_gap), 1);
        Store::inspect_existing(fixture.root.database())
            .expect("read-only open accepts aborted cleanup gap");
        assert_eq!(
            upload_pack_root_snapshot(&fixture.root),
            cleanup_gap,
            "read-only open must not remove the abort marker"
        );
        let reopened = Store::open_for_mission(fixture.root.database(), authority)
            .expect("cleanup marker converges aborted upload on reopen");
        assert!(
            reopened
                .resume_blob_upload(&request.owner)
                .expect("read converged abort")
                .is_none()
        );
        assert_eq!(
            cleanup_marker_count(&upload_pack_root_snapshot(&fixture.root)),
            0,
            "writable recovery must reclaim the abort marker before retry"
        );
        let (retry, initial) = reopened
            .reserve_blob_upload_with_policy(&policy, &request)
            .expect("deterministic retry removes stale cleanup marker");
        assert_eq!(retry.upload_id, reservation.upload_id);
        assert_eq!(initial.durable_plaintext_offset(), 0);
        let root = PinnedBlobPackRoot::open(&reopened).expect("retry pack root");
        BlobPackWriter::open_projected_upload_pinned(&root, &retry.pack_identity(), None)
            .expect("retry has exactly one usable initial pack");
    }

    #[test]
    fn upload_row_absent_cleanup_marker_is_reclaimed_by_writable_open() {
        let fixture = fixture("orphan-cleanup-marker", 0x3b, BlobDepotLimits::DEFAULT);
        let request = request(&fixture, b"orphan-cleanup-marker", 1_024);
        let policy = fixture.store.control_policy_snapshot().expect("policy");
        let (reservation, _) = fixture
            .store
            .reserve_blob_upload_with_policy(&policy, &request)
            .expect("reserve upload");
        assert!(
            fixture
                .store
                .abort_blob_upload(&reservation)
                .expect("remove upload row and pack")
        );
        let root = PinnedBlobPackRoot::open(&fixture.store).expect("pack root");
        super::super::pack::stage_upload_pack_cleanup(&root, &reservation.pack_identity())
            .expect("stage pre-existing row-absent cleanup marker");
        drop(root);
        let authority = fixture.publisher.mission_authority_id();
        drop(fixture.store);
        let before = upload_pack_root_snapshot(&fixture.root);
        assert_eq!(cleanup_marker_count(&before), 1);
        Store::inspect_existing(fixture.root.database())
            .expect("read-only open accepts row-absent cleanup marker");
        assert_eq!(upload_pack_root_snapshot(&fixture.root), before);
        drop(
            Store::open_for_mission(fixture.root.database(), authority)
                .expect("writable open reclaims row-absent cleanup marker"),
        );
        assert_eq!(
            cleanup_marker_count(&upload_pack_root_snapshot(&fixture.root)),
            0
        );
        drop(
            Store::open_for_mission(fixture.root.database(), authority)
                .expect("repeated cleanup marker recovery is idempotent"),
        );
        assert_eq!(
            cleanup_marker_count(&upload_pack_root_snapshot(&fixture.root)),
            0
        );
    }

    #[test]
    fn upload_malformed_cleanup_marker_still_fails_closed_without_mutation() {
        let fixture = fixture("malformed-cleanup-marker", 0x3c, BlobDepotLimits::DEFAULT);
        let root = PinnedBlobPackRoot::open(&fixture.store).expect("pack root");
        drop(root);
        let pack_root = fixture.root.0.join("blob-depot-v1").join("stream-packs-v2");
        fs::write(
            pack_root.join(format!(".aster-upload-cleanup-{}", "00".repeat(32))),
            [0x5a; 80],
        )
        .expect("write malformed cleanup marker");
        let authority = fixture.publisher.mission_authority_id();
        drop(fixture.store);
        let before = upload_pack_root_snapshot(&fixture.root);
        assert!(Store::inspect_existing(fixture.root.database()).is_err());
        assert_eq!(upload_pack_root_snapshot(&fixture.root), before);
        assert!(Store::open_for_mission(fixture.root.database(), authority).is_err());
        assert_eq!(upload_pack_root_snapshot(&fixture.root), before);
    }

    #[test]
    fn upload_reclaim_validates_all_markers_before_mixed_malformed_cleanup() {
        // Break caught: reclaiming a valid marker before validating a later
        // malformed marker makes a failed writable open mutate physical state.
        let fixture = fixture("mixed-malformed-cleanup", 0x3d, BlobDepotLimits::DEFAULT);
        let request = request(&fixture, b"mixed-malformed-cleanup", 1_024);
        let policy = fixture.store.control_policy_snapshot().expect("policy");
        let (reservation, _) = fixture
            .store
            .reserve_blob_upload_with_policy(&policy, &request)
            .expect("reserve upload");
        assert!(
            fixture
                .store
                .abort_blob_upload(&reservation)
                .expect("remove upload row and pack")
        );
        let root = PinnedBlobPackRoot::open(&fixture.store).expect("pack root");
        super::super::pack::stage_upload_pack_cleanup(&root, &reservation.pack_identity())
            .expect("stage valid row-absent cleanup marker");
        let pack_root = fixture.root.0.join("blob-depot-v1").join("stream-packs-v2");
        fs::write(
            pack_root.join(format!(".aster-upload-cleanup-{}", "ff".repeat(32))),
            [0x5a; 80],
        )
        .expect("write later malformed cleanup marker");
        let before_reclaim = upload_pack_tree_snapshot(&fixture.root);
        let reclaim_order = [
            super::super::pack::cleanup_marker_name_for_test(reservation.pack_identity()),
            format!(".aster-upload-cleanup-{}", "ff".repeat(32)),
        ];
        assert!(
            super::super::pack::reclaim_cleanup_markers_from_pinned_root_for_test(
                &root,
                &[],
                &reclaim_order,
            )
            .is_err()
        );
        assert_eq!(
            upload_pack_tree_snapshot(&fixture.root),
            before_reclaim,
            "failed reclamation must preserve every marker"
        );
        drop(root);
        let authority = fixture.publisher.mission_authority_id();
        drop(fixture.store);
        let before_open = upload_pack_tree_snapshot(&fixture.root);
        assert!(Store::inspect_existing(fixture.root.database()).is_err());
        assert_eq!(upload_pack_tree_snapshot(&fixture.root), before_open);
        assert!(Store::open_for_mission(fixture.root.database(), authority).is_err());
        assert_eq!(upload_pack_tree_snapshot(&fixture.root), before_open);
    }

    #[test]
    fn upload_reclaim_validates_all_markers_before_mixed_identity_conflict() {
        // Break caught: reclaiming a row-absent marker before validating a
        // marker which conflicts with a durable row makes failure destructive.
        let fixture = fixture("mixed-conflicting-cleanup", 0x3e, BlobDepotLimits::DEFAULT);
        let policy = fixture.store.control_policy_snapshot().expect("policy");
        let active_request = request(&fixture, b"active-conflicting-cleanup", 1_024);
        let (active, _) = fixture
            .store
            .reserve_blob_upload_with_policy(&policy, &active_request)
            .expect("reserve durable upload");
        let orphan_request = request(&fixture, b"orphan-before-conflict", 1_024);
        let (orphan, _) = fixture
            .store
            .reserve_blob_upload_with_policy(&policy, &orphan_request)
            .expect("reserve row-absent upload");
        assert!(
            fixture
                .store
                .abort_blob_upload(&orphan)
                .expect("remove orphan upload row and pack")
        );
        let root = PinnedBlobPackRoot::open(&fixture.store).expect("pack root");
        super::super::pack::stage_upload_pack_cleanup(&root, &orphan.pack_identity())
            .expect("stage valid row-absent cleanup marker");
        let mut wrong_digest = *active.pack_identity().request_digest();
        wrong_digest[0] ^= 0x80;
        let conflicting = BlobPackIdentity::new(
            active.pack_identity().upload_id(),
            wrong_digest,
            active.pack_identity().total_len(),
        );
        super::super::pack::stage_upload_pack_cleanup(&root, &conflicting)
            .expect("stage cleanup marker conflicting with durable upload");
        let expected = [super::super::pack::ExpectedBlobUploadPack {
            identity: active.pack_identity(),
            checkpoint: None,
            may_be_absent: false,
            discard_candidate: false,
        }];
        let before_reclaim = upload_pack_tree_snapshot(&fixture.root);
        let reclaim_order = [
            super::super::pack::cleanup_marker_name_for_test(orphan.pack_identity()),
            super::super::pack::cleanup_marker_name_for_test(conflicting),
        ];
        assert!(
            super::super::pack::reclaim_cleanup_markers_from_pinned_root_for_test(
                &root,
                &expected,
                &reclaim_order,
            )
            .is_err()
        );
        assert_eq!(
            upload_pack_tree_snapshot(&fixture.root),
            before_reclaim,
            "identity conflict must preserve every marker"
        );
        drop(root);
        let authority = fixture.publisher.mission_authority_id();
        drop(fixture.store);
        let before_open = upload_pack_tree_snapshot(&fixture.root);
        assert!(Store::inspect_existing(fixture.root.database()).is_err());
        assert_eq!(upload_pack_tree_snapshot(&fixture.root), before_open);
        assert!(Store::open_for_mission(fixture.root.database(), authority).is_err());
        assert_eq!(upload_pack_tree_snapshot(&fixture.root), before_open);
    }

    #[test]
    fn upload_checkpoint_capability_is_store_bound_but_restart_rebinds() {
        // Break caught: deterministic identity alone lets another Store project
        // a checkpoint that its pinned root never made durable.
        let fixture_a = fixture("checkpoint-store-a", 0x35, BlobDepotLimits::DEFAULT);
        let mut fixture_b = fixture("checkpoint-store-b", 0x35, BlobDepotLimits::DEFAULT);
        let request_a = request(&fixture_a, b"store-bound-checkpoint", 1_024);
        let request_b = request(&fixture_b, b"store-bound-checkpoint", 1_024);
        let policy_a = fixture_a.store.control_policy_snapshot().expect("policy A");
        let policy_b = fixture_b.store.control_policy_snapshot().expect("policy B");
        let (reservation_a, _) = fixture_a
            .store
            .reserve_blob_upload_with_policy(&policy_a, &request_a)
            .expect("reserve A");
        let foreign = append_real_upload_pack(&fixture_a, &reservation_a, &vec![0xb1; 1_024]);
        let (reservation_b, checkpoint_b) = fixture_b
            .store
            .reserve_blob_upload_with_policy(&policy_b, &request_b)
            .expect("reserve B");
        assert!(
            fixture_b
                .store
                .checkpoint_blob_upload(&policy_b, &reservation_b, checkpoint_b.clone(), foreign,)
                .is_err()
        );

        let local = append_real_upload_pack(&fixture_b, &reservation_b, &vec![0xb1; 1_024]);
        let projected = fixture_b
            .store
            .checkpoint_blob_upload(&policy_b, &reservation_b, checkpoint_b, local)
            .expect("project local checkpoint");
        let authority = fixture_b.publisher.mission_authority_id();
        drop(fixture_b.store);
        fixture_b.store = Store::open_for_mission(fixture_b.root.database(), authority)
            .expect("reopen local checkpoint");
        assert_eq!(
            fixture_b
                .store
                .resume_blob_upload(&request_b.owner)
                .expect("resume")
                .expect("upload")
                .1,
            projected
        );
    }

    #[test]
    fn upload_audit_reconstructs_consumed_credit_from_canonical_rows() {
        // Break caught: an overstated consumed byte total reduces admission usage
        // unless audit derives it from the bound import and chunk rows.
        let fixture = fixture("audit-consumed", 0x36, BlobDepotLimits::DEFAULT);
        let plaintext = vec![0xc1; 1_024];
        let request = request(&fixture, b"audit-consumed", plaintext.len() as u64);
        let policy = fixture.store.control_policy_snapshot().expect("policy");
        let (reservation, _) = fixture
            .store
            .reserve_blob_upload_with_policy(&policy, &request)
            .expect("reserve upload");
        let prepared = prepare_blob(
            &mut Cursor::new(&plaintext),
            crate::SELECTED_BLOB_CHUNK_SIZE,
            BlobMetadata::new(request.media_type.clone(), request.schema_id.clone())
                .expect("metadata"),
        )
        .expect("prepare");
        let mut service = fixture
            .publisher
            .blob_service_with_store(
                &fixture.scope,
                &fixture.topic,
                1,
                fixture
                    .store
                    .blob_depot_for_upload(&reservation)
                    .expect("upload depot"),
            )
            .expect("service");
        service
            .install_prepared(&prepared)
            .expect("install prepared");
        drop(service);

        let owner_key = blob_operation_owner_key(&request.owner).expect("owner key");
        let write = fixture.store.database.begin_write().expect("corrupt write");
        let encoded = write
            .open_table(super::super::BLOB_UPLOADS)
            .expect("uploads")
            .get(owner_key.as_slice())
            .expect("row read")
            .expect("upload row")
            .value()
            .to_vec();
        let mut upload = DurableBlobUpload::decode(
            Arc::clone(&fixture.store.blob_completion_authority),
            &encoded,
        )
        .expect("decode upload");
        upload.consumed.bytes += 1;
        write
            .open_table(super::super::BLOB_UPLOADS)
            .expect("uploads")
            .insert(
                owner_key.as_slice(),
                upload.encode().expect("encode").as_slice(),
            )
            .expect("corrupt upload");
        write.commit().expect("commit corruption");
        let authority = fixture.publisher.mission_authority_id();
        let path = fixture.root.database();
        drop(fixture.store);
        assert!(Store::open_for_mission(path, authority).is_err());
    }

    #[test]
    fn upload_sync_and_projection_faults_reopen_without_invented_progress() {
        // Break caught: data/journal durability or redb projection failures can
        // otherwise advance one authority without the other.
        let mut fixture = fixture("sync-faults", 0x37, BlobDepotLimits::DEFAULT);
        let plaintext = vec![0xd1; 1_024];
        let request = request(&fixture, b"sync-faults", plaintext.len() as u64);
        let policy = fixture.store.control_policy_snapshot().expect("policy");
        let (reservation, initial) = fixture
            .store
            .reserve_blob_upload_with_policy(&policy, &request)
            .expect("reserve upload");
        let identity = reservation.pack_identity();
        let root = PinnedBlobPackRoot::open(&fixture.store).expect("pack root");
        let mut writer = BlobPackWriter::open_projected_upload_pinned(&root, &identity, None)
            .expect("open initial pack");
        let mut digest_writer =
            super::super::pack::BlobUploadDigestWriter::open_projected_upload_pinned(
                &root, &identity, None,
            )
            .expect("open initial digest artifact");
        let sealer = BlobStreamSegmentSealer::from_test_key(
            *identity.upload_id().as_bytes(),
            *identity.request_digest(),
            reservation.content_epoch(),
            [0xd2; 32],
            [0xd3; 12],
        );
        let (segment, leaves) = sealer
            .seal(
                BlobStreamPlainPartition::new(
                    *identity.upload_id().as_bytes(),
                    *identity.request_digest(),
                    reservation.content_epoch(),
                    0,
                    0,
                    plaintext.len() as u64,
                    plaintext.clone(),
                )
                .expect("partition"),
            )
            .expect("segment");
        writer.append(&segment, leaves).expect("append");
        digest_writer
            .append(&plaintext)
            .expect("append canonical digest material");
        super::super::pack::inject_test_fault(
            &root,
            super::super::pack::BlobPackFaultPoint::DataSynced,
        );
        assert!(writer.checkpoint_upload(&mut digest_writer).is_err());
        drop(writer);
        drop(digest_writer);
        let authority = fixture.publisher.mission_authority_id();
        drop(fixture.store);
        fixture.store = Store::open_for_mission(fixture.root.database(), authority)
            .expect("unprojected durable tail is a recoverable lifecycle window");
        let (restarted, exact) = fixture
            .store
            .resume_blob_upload(&request.owner)
            .expect("resume after physical lead")
            .expect("upload remains");
        assert_eq!(exact, initial, "redb must not invent physical progress");
        let root = PinnedBlobPackRoot::open(&fixture.store).expect("reopened root");
        let mut writer = BlobPackWriter::open_projected_upload_pinned(
            &root,
            &identity,
            exact.durable_pack_checkpoint(),
        )
        .expect("truncate physical lead to projected boundary");
        assert_eq!(writer.plaintext_offset(), 0);
        let digest_writer =
            super::super::pack::BlobUploadDigestWriter::open_projected_upload_pinned(
                &root,
                &identity,
                exact.durable_pack_checkpoint(),
            )
            .expect("truncate digest lead to projected boundary");
        assert_eq!(digest_writer.plaintext_offset(), 0);
        drop(digest_writer);
        writer
            .append(&segment, leaves)
            .expect("append after recovery");
        let durable = writer.checkpoint().expect("durable checkpoint");
        drop(writer);

        inject_test_fault(&fixture.store, UploadFaultPoint::CheckpointBeforeCommit);
        assert!(
            fixture
                .store
                .checkpoint_blob_upload(&policy, &restarted, exact.clone(), durable)
                .is_err(),
            "injected failure leaves redb projection unchanged"
        );
        assert_eq!(
            fixture
                .store
                .resume_blob_upload(&request.owner)
                .expect("resume after projection fault")
                .expect("upload remains")
                .1,
            exact
        );
        drop(fixture.store);
        fixture.store = Store::open_for_mission(fixture.root.database(), authority)
            .expect("physical checkpoint lead converges on reopen");
        let (_, reopened) = fixture
            .store
            .resume_blob_upload(&request.owner)
            .expect("resume final")
            .expect("upload remains final");
        assert_eq!(reopened, initial);
    }

    #[test]
    fn upload_reservation_pack_sync_before_row_converges_on_reopen() {
        let mut fixture = fixture("reservation-pack-lead", 0x38, BlobDepotLimits::DEFAULT);
        let request = request(&fixture, b"reservation-pack-lead", 1_024);
        let policy = fixture.store.control_policy_snapshot().expect("policy");
        inject_test_fault(&fixture.store, UploadFaultPoint::ReservationPackSynced);
        assert!(
            fixture
                .store
                .reserve_blob_upload_with_policy(&policy, &request)
                .is_err(),
            "injected failure leaves only an orphan initial pack"
        );
        let authority = fixture.publisher.mission_authority_id();
        drop(fixture.store);
        let database_before = fs::read(fixture.root.database()).expect("database before RO");
        Store::inspect_existing(fixture.root.database())
            .expect("read-only open accepts the provable reservation crash window");
        assert_eq!(
            fs::read(fixture.root.database()).expect("database after RO"),
            database_before,
            "read-only convergence audit must not mutate redb"
        );
        fixture.store = Store::open_for_mission(fixture.root.database(), authority)
            .expect("writable reopen reclaims orphan reservation pack");
        assert!(
            fixture
                .store
                .resume_blob_upload(&request.owner)
                .expect("read reservation")
                .is_none()
        );
        let (reservation, initial) = fixture
            .store
            .reserve_blob_upload_with_policy(&policy, &request)
            .expect("retry creates one coherent row and pack");
        assert_eq!(initial.durable_plaintext_offset(), 0);
        let root = PinnedBlobPackRoot::open(&fixture.store).expect("retry root");
        BlobPackWriter::open_projected_upload_pinned(
            &root,
            &reservation.pack_identity(),
            initial.durable_pack_checkpoint(),
        )
        .expect("retry pack matches projection");
    }

    #[test]
    fn upload_reservation_intent_before_initial_pack_converges_on_reopen() {
        let mut fixture = fixture("reservation-intent-lead", 0x3a, BlobDepotLimits::DEFAULT);
        let request = request(&fixture, b"reservation-intent-lead", 1_024);
        let policy = fixture.store.control_policy_snapshot().expect("policy");
        inject_test_fault(&fixture.store, UploadFaultPoint::ReservationIntentSynced);
        assert!(
            fixture
                .store
                .reserve_blob_upload_with_policy(&policy, &request)
                .is_err(),
            "injected failure leaves the intent marker before initial pack creation"
        );
        let authority = fixture.publisher.mission_authority_id();
        drop(fixture.store);
        Store::inspect_existing(fixture.root.database())
            .expect("read-only open accepts a durable intent without pack or row");
        fixture.store = Store::open_for_mission(fixture.root.database(), authority)
            .expect("writable reopen reclaims the incomplete intent");
        assert!(
            fixture
                .store
                .resume_blob_upload(&request.owner)
                .expect("read upload")
                .is_none()
        );
        fixture
            .store
            .reserve_blob_upload_with_policy(&policy, &request)
            .expect("reservation retry succeeds after intent cleanup");
    }

    #[test]
    fn upload_unexpected_pack_without_reservation_intent_still_fails_closed() {
        let fixture = fixture("unexpected-pack", 0x39, BlobDepotLimits::DEFAULT);
        let request = request(&fixture, b"unexpected-pack", 1_024);
        let policy = fixture.store.control_policy_snapshot().expect("policy");
        inject_test_fault(&fixture.store, UploadFaultPoint::ReservationPackSynced);
        assert!(
            fixture
                .store
                .reserve_blob_upload_with_policy(&policy, &request)
                .is_err()
        );
        let digest = request_digest_for(&request).expect("request digest");
        let identity = BlobPackIdentity::new(
            upload_id_for(&request.owner, digest).expect("upload id"),
            digest,
            request.total_len,
        );
        let root = PinnedBlobPackRoot::open(&fixture.store).expect("pack root");
        super::super::pack::finish_upload_pack_reservation(&root, &identity)
            .expect("remove reservation intent to model an unexpected pack");
        let pack_path = root.test_upload_path(&identity);
        let before = upload_artifact_snapshot(&pack_path);
        let authority = fixture.publisher.mission_authority_id();
        drop(root);
        drop(fixture.store);
        assert!(Store::inspect_existing(fixture.root.database()).is_err());
        assert_eq!(upload_artifact_snapshot(&pack_path), before);
        assert!(Store::open_for_mission(fixture.root.database(), authority).is_err());
        assert_eq!(upload_artifact_snapshot(&pack_path), before);
    }

    fn promote_profile5_fixture(
        fixture: &Fixture,
        operation: &[u8],
    ) -> (BlobUploadRequest, StoredBlob) {
        let request = request(fixture, operation, 4_096);
        let policy = fixture.store.control_policy_snapshot().expect("policy");
        let (reservation, initial, open) = reserve_profile5(fixture, &request);
        let completed =
            complete_profile5_pack(fixture, &policy, &reservation, initial, &open, 0x55);
        let publication = profile5_publication(fixture, &open, &completed);
        let outcome = fixture
            .store
            .commit_profile5_publication_once_with_policy(
                &policy,
                &reservation,
                &completed,
                &publication,
                publication.publication().final_custody(),
            )
            .expect("promote Profile-5 fixture");
        (request, outcome.blob().clone())
    }

    #[test]
    fn regression_duplicate_received_profile5_attempts_cannot_corrupt_the_shared_pack() {
        let fixture = fixture(
            "duplicate-received-profile5-writers",
            0x72,
            BlobDepotLimits::DEFAULT,
        );
        let policy = fixture.store.control_policy_snapshot().expect("policy");
        let remote = remote_profile5_pack(
            &fixture,
            &fixture.publisher,
            b"duplicate-received-profile5-writers",
            0x53,
        );
        let (first, first_checkpoint, _) = fixture
            .store
            .reserve_received_profile5_upload_with_policy(
                &policy,
                &remote.publication,
                &remote.open,
            )
            .expect("reserve first receiver");
        let (second, second_checkpoint, _) = fixture
            .store
            .reserve_received_profile5_upload_with_policy(
                &policy,
                &remote.publication,
                &remote.open,
            )
            .expect("resume duplicate receiver");
        assert_eq!(first.pack_identity(), second.pack_identity());
        assert_eq!(first_checkpoint, second_checkpoint);

        let root = PinnedBlobPackRoot::open(&fixture.store).expect("pack root");
        let mut first_writer = BlobPackWriter::open_projected_upload_pinned(
            &root,
            &first.pack_identity(),
            first_checkpoint.durable_pack_checkpoint(),
        )
        .expect("open first writer");
        first_writer
            .append(&remote.segment, remote.leaves)
            .expect("append first receiver segment");

        // A duplicate attempt reopens the same durable checkpoint while the
        // first writer owns uncheckpointed bytes. It must not truncate them.
        assert!(matches!(
            BlobPackWriter::open_projected_upload_pinned(
                &root,
                &second.pack_identity(),
                second_checkpoint.durable_pack_checkpoint(),
            ),
            Err(BlobPackError::Invalid(
                "another Blob pack writer already owns this pack"
            ))
        ));

        let completion = first_writer
            .finish_profile5(&remote.commitment)
            .expect("finish first receiver");
        let mut reader = BlobPackReader::open_completed_upload_pinned(&root, &completion)
            .expect("open completed pack");
        assert!(
            reader
                .next_record()
                .expect("completed pack must contain a valid first record")
                .is_some()
        );
    }

    #[test]
    fn regression_expired_native_profile5_pack_releases_capacity_for_next_publication() {
        let fixture = fixture(
            "expired-native-profile5-reclamation",
            0x73,
            BlobDepotLimits::new(1_000_000, 4, 1).expect("one-variant depot"),
        );
        let (request, _) =
            promote_profile5_fixture(&fixture, b"expired-native-profile5-reclamation");
        let budget =
            super::super::lifecycle::BlobMaintenanceBudget::new(4_096, 8, 32 * 1024 * 1024)
                .expect("maintenance budget");
        let expired = CustodySample {
            clock_id: [0x31; 16],
            tick_ms: 100_100,
        };

        for turn in 0..128 {
            fixture
                .store
                .run_blob_maintenance_turn_with_sample(budget, (turn == 0).then_some(expired))
                .expect("run expiry maintenance");
            fixture
                .store
                .run_blob_capacity_gc(budget, None)
                .expect("run physical maintenance");
        }

        assert!(matches!(
            fixture.store.blob_for_owner_with_policy(
                &fixture.store.control_policy_snapshot().expect("policy"),
                &request.owner,
            ),
            Err(StoreError::Blob(BlobStoreError::ExpiredOrRetired))
        ));
        let policy = fixture.store.control_policy_snapshot().expect("policy");
        let replacement = remote_profile5_pack(
            &fixture,
            &fixture.other,
            b"replacement-after-expired-native-profile5-reclamation",
            0x62,
        );
        let (reservation, checkpoint, _) = fixture
            .store
            .reserve_received_profile5_upload_with_policy(
                &policy,
                &replacement.publication,
                &replacement.open,
            )
            .expect("expired native pack must release depot capacity");
        promote_received_profile5_pack(
            &fixture,
            &fixture.other,
            &policy,
            &reservation,
            checkpoint,
            &replacement,
        );
    }

    #[test]
    fn regression_maximum_valid_operation_key_survives_blob_maintenance() {
        let fixture = fixture(
            "maximum-operation-key-maintenance",
            0x74,
            BlobDepotLimits::DEFAULT,
        );
        promote_profile5_fixture(&fixture, &[b'x'; 256]);
        let budget =
            super::super::lifecycle::BlobMaintenanceBudget::new(4_096, 8, 32 * 1024 * 1024)
                .expect("maintenance budget");

        for turn in 0..64 {
            fixture
                .store
                .run_blob_maintenance_turn(budget)
                .unwrap_or_else(|error| {
                    panic!("valid 256-byte operation key failed maintenance turn {turn}: {error}")
                });
        }
    }
}
