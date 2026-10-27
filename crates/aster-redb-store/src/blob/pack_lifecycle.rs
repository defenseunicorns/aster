//! PR #95 lifecycle ownership for canonical Profile-5 pack variants.

use super::pack::{BlobPackCompletion, BlobPackError};
use super::upload::BlobUploadCapacity;
use super::{BlobStoreError, BlobVariantId, StoreError, blob_error, blob_variant_id};
use aster_mesh::{
    BlobPhysicalLineage, BlobStreamFinalCommitment, BlobStreamOpen, SourceRouteLineage,
};
use redb::{ReadableDatabase, ReadableTable, TableDefinition};
use sha2::{Digest, Sha256};
use std::sync::Arc;

/// Lease-backed reader for one lifecycle-owned canonical Profile-5 pack.
/// Dropping the session releases deletion exclusion.
pub struct Profile5PackReadSession {
    reader: super::pack::BlobPackReader,
    open: BlobStreamOpen,
    authenticated_open: Vec<u8>,
    commitment: BlobStreamFinalCommitment,
    authenticated_commitment: Vec<u8>,
    route_lineage: [u8; 32],
    physical_lineage: [u8; 32],
    _lease: Arc<super::lease::BlobLeaseHandle>,
}

impl Profile5PackReadSession {
    pub const fn open(&self) -> &BlobStreamOpen {
        &self.open
    }

    pub fn authenticated_open(&self) -> &[u8] {
        &self.authenticated_open
    }

    pub const fn commitment(&self) -> &BlobStreamFinalCommitment {
        &self.commitment
    }

    pub fn authenticated_commitment(&self) -> &[u8] {
        &self.authenticated_commitment
    }

    pub const fn route_lineage(&self) -> &[u8; 32] {
        &self.route_lineage
    }

    pub const fn physical_lineage(&self) -> &[u8; 32] {
        &self.physical_lineage
    }

    pub const fn wire_len(&self) -> u64 {
        self.reader.checkpoint().payload_len()
    }

    pub fn next_segment(
        &mut self,
    ) -> Result<Option<aster_mesh::EncryptedBlobStreamSegment>, StoreError> {
        self.reader.next_segment().map_err(pack_store_error)
    }

    pub fn next_record(&mut self) -> Result<Option<super::pack::BlobPackRecord>, StoreError> {
        self.reader.next_record().map_err(pack_store_error)
    }
}

pub(crate) const BLOB_PROFILE5_PACKS: TableDefinition<&[u8], &[u8]> =
    TableDefinition::new("aster.blob-profile5-packs.v1");

const PACK_VARIANT_MAGIC: &[u8; 8] = b"ASTRPV01";
const PACK_VARIANT_VERSION: u16 = 2;
pub(super) fn profile5_publication_source_record(
    authenticated_publication: &[u8],
    authenticated_open: &[u8],
    authenticated_commitment: &[u8],
) -> Result<Vec<u8>, StoreError> {
    aster_mesh::BlobStreamPublicationSource::new(
        authenticated_publication.to_vec(),
        authenticated_open.to_vec(),
        authenticated_commitment.to_vec(),
    )
    .and_then(|source| source.encode())
    .map_err(|_| pack_schema_error())
}

/// Nonconstructible Store-bound projection of one lifecycle-owned Profile-5
/// physical variant.
#[derive(Clone, Debug)]
pub struct BlobPackVariant {
    variant_id: BlobVariantId,
    route_lineage: [u8; 32],
    physical_lineage: [u8; 32],
    owner_binding: [u8; 32],
    authenticated_open_digest: [u8; 32],
    open: BlobStreamOpen,
    authenticated_open: Vec<u8>,
    commitment: BlobStreamFinalCommitment,
    authenticated_commitment: Vec<u8>,
    completion: BlobPackCompletion,
    capacity: BlobUploadCapacity,
    state: PackLifecycleState,
    authority: Arc<()>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum PackLifecycleState {
    Provisional,
    Active,
    DeletionPending,
}

impl PackLifecycleState {
    const fn encode(self) -> u8 {
        match self {
            Self::Provisional => 0,
            Self::Active => 1,
            Self::DeletionPending => 2,
        }
    }

    fn decode(value: u8) -> Result<Self, StoreError> {
        match value {
            0 => Ok(Self::Provisional),
            1 => Ok(Self::Active),
            2 => Ok(Self::DeletionPending),
            _ => Err(pack_schema_error()),
        }
    }
}

impl PartialEq for BlobPackVariant {
    fn eq(&self, other: &Self) -> bool {
        self.variant_id == other.variant_id
            && self.route_lineage == other.route_lineage
            && self.physical_lineage == other.physical_lineage
            && self.owner_binding == other.owner_binding
            && self.authenticated_open_digest == other.authenticated_open_digest
            && self.open == other.open
            && self.authenticated_open == other.authenticated_open
            && self.commitment == other.commitment
            && self.authenticated_commitment == other.authenticated_commitment
            && self.completion == other.completion
            && self.capacity == other.capacity
            && self.state == other.state
    }
}

impl Eq for BlobPackVariant {}

impl BlobPackVariant {
    pub(super) const fn variant_id(&self) -> BlobVariantId {
        self.variant_id
    }

    #[allow(clippy::too_many_arguments)]
    pub(super) fn new(
        route_lineage: SourceRouteLineage,
        physical_lineage: BlobPhysicalLineage,
        owner_binding: [u8; 32],
        open: BlobStreamOpen,
        authenticated_open: Vec<u8>,
        commitment: BlobStreamFinalCommitment,
        authenticated_commitment: Vec<u8>,
        completion: BlobPackCompletion,
        capacity: BlobUploadCapacity,
        authority: Arc<()>,
    ) -> Result<Self, StoreError> {
        let variant_id = blob_variant_id(
            commitment.blob_id(),
            &open.content_group(),
            open.content_epoch(),
        );
        let variant = Self {
            variant_id,
            route_lineage: *route_lineage.binding(),
            physical_lineage: *physical_lineage.binding(),
            owner_binding,
            authenticated_open_digest: Sha256::digest(&authenticated_open).into(),
            open,
            authenticated_open,
            commitment,
            authenticated_commitment,
            completion,
            capacity,
            state: PackLifecycleState::Provisional,
            authority,
        };
        variant.validate()?;
        Ok(variant)
    }

    pub const fn open(&self) -> &BlobStreamOpen {
        &self.open
    }

    pub const fn commitment(&self) -> &BlobStreamFinalCommitment {
        &self.commitment
    }

    pub fn authenticated_open(&self) -> &[u8] {
        &self.authenticated_open
    }

    pub fn authenticated_commitment(&self) -> &[u8] {
        &self.authenticated_commitment
    }

    pub const fn completion(&self) -> &BlobPackCompletion {
        &self.completion
    }

    pub const fn physical_lineage(&self) -> &[u8; 32] {
        &self.physical_lineage
    }

    pub(super) const fn capacity(&self) -> BlobUploadCapacity {
        self.capacity
    }

    pub(super) const fn lifecycle_owned(&self) -> bool {
        matches!(self.state, PackLifecycleState::Active)
    }

    pub(super) const fn deletion_pending(&self) -> bool {
        matches!(self.state, PackLifecycleState::DeletionPending)
    }

    pub(super) const fn owner_binding(&self) -> &[u8; 32] {
        &self.owner_binding
    }

    pub(super) fn is_bound_to(&self, authority: &Arc<()>) -> bool {
        Arc::ptr_eq(&self.authority, authority) && self.completion.is_bound_to(authority)
    }

    fn validate(&self) -> Result<(), StoreError> {
        if self.route_lineage == [0; 32]
            || self.physical_lineage == [0; 32]
            || self.owner_binding == [0; 32]
            || self.authenticated_open.is_empty()
            || self.authenticated_commitment.is_empty()
            || self.variant_id
                != blob_variant_id(
                    self.commitment.blob_id(),
                    &self.open.content_group(),
                    self.open.content_epoch(),
                )
            || self.commitment.open_digest() != &self.open.digest()
            || self.commitment.stream_id() != self.open.stream_id()
            || self.commitment.total_len() != self.open.total_len()
            || self.commitment.content_epoch() != self.open.content_epoch()
            || self.commitment.ttl_ms() != self.open.ttl_ms()
            || self.completion.identity().upload_id() != self.open.stream_id()
            || self.completion.identity().request_digest() != &self.open.digest()
            || self.completion.identity().total_len() != self.open.total_len()
            || self.completion.segment_count() != self.commitment.segment_count()
            || self.completion.plaintext_root() != self.commitment.plaintext_root()
            || self.completion.ciphertext_root() != self.commitment.ciphertext_root()
            || self.completion.blob_id() != self.commitment.blob_id()
            || Sha256::digest(&self.authenticated_open).as_slice() != self.authenticated_open_digest
            || Sha256::digest(self.commitment.encode()).as_slice()
                != self.completion.commitment_digest()
            || Sha256::digest(&self.authenticated_commitment).as_slice()
                != self.completion.authenticated_commitment_digest()
            || self.capacity.bytes
                != super::pack::reserved_upload_pack_bytes(self.open.total_len())?
            || self.capacity.chunks != self.commitment.segment_count()
            || self.capacity.variants != 1
        {
            return Err(pack_schema_error());
        }
        Ok(())
    }

    fn encode(&self) -> Result<Vec<u8>, StoreError> {
        self.validate()?;
        let open = self.open.encode();
        let commitment = self.commitment.encode();
        let completion = self.completion.encode().map_err(pack_store_error)?;
        let mut output = Vec::new();
        output.extend_from_slice(PACK_VARIANT_MAGIC);
        output.extend_from_slice(&PACK_VARIANT_VERSION.to_be_bytes());
        output.extend_from_slice(self.variant_id.as_bytes());
        output.extend_from_slice(&self.route_lineage);
        output.extend_from_slice(&self.physical_lineage);
        output.extend_from_slice(&self.owner_binding);
        output.extend_from_slice(&self.authenticated_open_digest);
        output.extend_from_slice(&self.capacity.bytes.to_be_bytes());
        output.extend_from_slice(&self.capacity.chunks.to_be_bytes());
        output.extend_from_slice(&self.capacity.variants.to_be_bytes());
        output.push(self.state.encode());
        for bytes in [
            open.as_slice(),
            self.authenticated_open.as_slice(),
            commitment.as_slice(),
            self.authenticated_commitment.as_slice(),
            completion.as_slice(),
        ] {
            let len = u32::try_from(bytes.len())
                .map_err(|_| StoreError::PayloadByteAccountingOverflow)?;
            output.extend_from_slice(&len.to_be_bytes());
            output.extend_from_slice(bytes);
        }
        Ok(output)
    }

    fn decode(encoded: &[u8], authority: Arc<()>) -> Result<Self, StoreError> {
        let expected_version = PACK_VARIANT_VERSION.to_be_bytes();
        if encoded.get(..8) != Some(PACK_VARIANT_MAGIC.as_slice())
            || encoded.get(8..10) != Some(expected_version.as_slice())
        {
            return Err(blob_error(BlobStoreError::UnsupportedProfile5PackSchema));
        }
        let mut cursor = Cursor::new(encoded);
        let _ = cursor.take(8)?;
        let _ = cursor.u16()?;
        let variant_id = BlobVariantId::from_bytes(cursor.array()?);
        let route_lineage = cursor.array()?;
        let physical_lineage = cursor.array()?;
        let owner_binding = cursor.array()?;
        let authenticated_open_digest = cursor.array()?;
        let capacity = BlobUploadCapacity {
            bytes: cursor.u64()?,
            chunks: cursor.u64()?,
            variants: cursor.u64()?,
        };
        let state = PackLifecycleState::decode(cursor.u8()?)?;
        let open = BlobStreamOpen::decode(cursor.long()?).map_err(|_| pack_schema_error())?;
        let authenticated_open = cursor.long()?.to_vec();
        let commitment =
            BlobStreamFinalCommitment::decode(cursor.long()?).map_err(|_| pack_schema_error())?;
        let authenticated_commitment = cursor.long()?.to_vec();
        let completion = BlobPackCompletion::decode(cursor.long()?, Arc::clone(&authority))
            .map_err(pack_store_error)?;
        cursor.finish()?;
        let variant = Self {
            variant_id,
            route_lineage,
            physical_lineage,
            owner_binding,
            authenticated_open_digest,
            open,
            authenticated_open,
            commitment,
            authenticated_commitment,
            completion,
            capacity,
            state,
            authority,
        };
        variant.validate()?;
        Ok(variant)
    }
}

pub(super) fn insert_write(
    write: &redb::WriteTransaction,
    variant: &BlobPackVariant,
) -> Result<(), StoreError> {
    require_owner_binding(
        super::depot::depot_owner_binding_if_present_write(write)?,
        variant.owner_binding,
    )?;
    let key = variant.variant_id.as_bytes().as_slice();
    let encoded = variant.encode()?;
    let mut packs = write.open_table(BLOB_PROFILE5_PACKS)?;
    if let Some(existing) = packs.get(key)? {
        let existing = BlobPackVariant::decode(existing.value(), Arc::new(()))?;
        if existing != *variant {
            return Err(blob_error(BlobStoreError::PhysicalLineageConflict));
        }
        return Ok(());
    }
    if write.open_table(super::BLOB_IMPORTS)?.get(key)?.is_some() {
        return Err(blob_error(BlobStoreError::PhysicalLineageConflict));
    }
    packs.insert(key, encoded.as_slice())?;
    Ok(())
}

pub(super) fn load_write(
    write: &redb::WriteTransaction,
    variant: BlobVariantId,
    authority: Arc<()>,
) -> Result<Option<BlobPackVariant>, StoreError> {
    let owner_binding = super::depot::depot_owner_binding_if_present_write(write)?;
    write
        .open_table(BLOB_PROFILE5_PACKS)?
        .get(variant.as_bytes().as_slice())?
        .map(|value| {
            let expected_authority = Arc::clone(&authority);
            let pack = BlobPackVariant::decode(value.value(), authority)?;
            require_owner_binding(owner_binding, pack.owner_binding)?;
            if !pack.is_bound_to(&expected_authority) {
                return Err(pack_schema_error());
            }
            Ok(pack)
        })
        .transpose()
}

pub(super) fn load_read(
    read: &redb::ReadTransaction,
    variant: BlobVariantId,
    authority: Arc<()>,
) -> Result<Option<BlobPackVariant>, StoreError> {
    let owner_binding = super::depot::depot_owner_binding_if_present_read(read)?;
    read.open_table(BLOB_PROFILE5_PACKS)?
        .get(variant.as_bytes().as_slice())?
        .map(|value| {
            let expected_authority = Arc::clone(&authority);
            let pack = BlobPackVariant::decode(value.value(), authority)?;
            require_owner_binding(owner_binding, pack.owner_binding)?;
            if !pack.is_bound_to(&expected_authority) {
                return Err(pack_schema_error());
            }
            Ok(pack)
        })
        .transpose()
}

pub(super) fn reconstruct_capacity_write(
    write: &redb::WriteTransaction,
    variant: BlobVariantId,
) -> Result<Option<BlobUploadCapacity>, StoreError> {
    load_write(write, variant, Arc::new(())).map(|value| value.map(|value| value.capacity))
}

pub(super) fn remove_provisional_write(
    write: &redb::WriteTransaction,
    variant: BlobVariantId,
    expected: &BlobPackCompletion,
) -> Result<(), StoreError> {
    let pack = load_write(write, variant, Arc::new(()))?.ok_or_else(pack_schema_error)?;
    if pack.state != PackLifecycleState::Provisional || pack.completion() != expected {
        return Err(pack_schema_error());
    }
    write
        .open_table(BLOB_PROFILE5_PACKS)?
        .remove(variant.as_bytes().as_slice())?;
    Ok(())
}

pub(super) fn promote_write(
    write: &redb::WriteTransaction,
    variant: BlobVariantId,
    expected: &BlobPackCompletion,
    authority: Arc<()>,
) -> Result<BlobUploadCapacity, StoreError> {
    let mut pack = load_write(write, variant, authority)?.ok_or_else(pack_schema_error)?;
    if pack.completion() != expected {
        return Err(pack_schema_error());
    }
    if pack.state == PackLifecycleState::Provisional {
        pack.state = PackLifecycleState::Active;
        let encoded = pack.encode()?;
        write
            .open_table(BLOB_PROFILE5_PACKS)?
            .insert(variant.as_bytes().as_slice(), encoded.as_slice())?;
    }
    if pack.state != PackLifecycleState::Active {
        return Err(pack_schema_error());
    }
    Ok(pack.capacity)
}

pub(super) fn active_capacity_usage_write(
    write: &redb::WriteTransaction,
) -> Result<BlobUploadCapacity, StoreError> {
    capacity_usage(&write.open_table(BLOB_PROFILE5_PACKS)?)
}

pub(super) fn active_capacity_usage_read(
    read: &redb::ReadTransaction,
) -> Result<BlobUploadCapacity, StoreError> {
    capacity_usage(&read.open_table(BLOB_PROFILE5_PACKS)?)
}

pub(super) fn active_committed_file_bytes_write(
    write: &redb::WriteTransaction,
) -> Result<u64, StoreError> {
    committed_file_bytes(&write.open_table(BLOB_PROFILE5_PACKS)?)
}

pub(super) fn active_committed_file_bytes_read(
    read: &redb::ReadTransaction,
) -> Result<u64, StoreError> {
    committed_file_bytes(&read.open_table(BLOB_PROFILE5_PACKS)?)
}

fn capacity_usage(
    packs: &impl ReadableTable<&'static [u8], &'static [u8]>,
) -> Result<BlobUploadCapacity, StoreError> {
    let mut usage = BlobUploadCapacity::default();
    for row in packs.iter()? {
        let (_, value) = row?;
        let pack = BlobPackVariant::decode(value.value(), Arc::new(()))?;
        if pack.state != PackLifecycleState::Provisional {
            usage = usage.checked_add(pack.capacity())?;
        }
    }
    Ok(usage)
}

fn committed_file_bytes(
    packs: &impl ReadableTable<&'static [u8], &'static [u8]>,
) -> Result<u64, StoreError> {
    let mut bytes = 0_u64;
    for row in packs.iter()? {
        let (_, value) = row?;
        let pack = BlobPackVariant::decode(value.value(), Arc::new(()))?;
        if pack.state != PackLifecycleState::Provisional {
            bytes = bytes
                .checked_add(pack.completion().pack_len())
                .ok_or(StoreError::PayloadByteAccountingOverflow)?;
        }
    }
    Ok(bytes)
}

pub(super) fn active_pack_expectations_write(
    write: &redb::WriteTransaction,
) -> Result<Vec<super::pack::ExpectedBlobUploadPack>, StoreError> {
    active_pack_expectations(&write.open_table(BLOB_PROFILE5_PACKS)?)
}

pub(super) fn active_pack_expectations_read(
    read: &redb::ReadTransaction,
) -> Result<Vec<super::pack::ExpectedBlobUploadPack>, StoreError> {
    active_pack_expectations(&read.open_table(BLOB_PROFILE5_PACKS)?)
}

fn active_pack_expectations(
    packs: &impl ReadableTable<&'static [u8], &'static [u8]>,
) -> Result<Vec<super::pack::ExpectedBlobUploadPack>, StoreError> {
    let mut expected = Vec::new();
    for row in packs.iter()? {
        let (_, value) = row?;
        let pack = BlobPackVariant::decode(value.value(), Arc::new(()))?;
        if pack.state != PackLifecycleState::Provisional {
            expected.push(super::pack::ExpectedBlobUploadPack {
                identity: pack.completion.identity(),
                checkpoint: Some(pack.completion.checkpoint().clone()),
                may_be_absent: pack.deletion_pending(),
                discard_candidate: false,
            });
        }
    }
    Ok(expected)
}

pub(super) fn reconstruct_capacity_read(
    read: &redb::ReadTransaction,
    variant: BlobVariantId,
) -> Result<Option<BlobUploadCapacity>, StoreError> {
    load_read(read, variant, Arc::new(())).map(|value| value.map(|value| value.capacity))
}

pub(super) fn variant_progress_write(
    write: &redb::WriteTransaction,
    variant: BlobVariantId,
) -> Result<Option<(u64, u64)>, StoreError> {
    Ok(load_write(write, variant, Arc::new(()))?
        .map(|pack| (pack.open.total_len(), pack.open.total_len())))
}

pub(super) fn audit_write(write: &redb::WriteTransaction) -> Result<(), StoreError> {
    let packs = write.open_table(BLOB_PROFILE5_PACKS)?;
    let owner_binding = super::depot::depot_owner_binding_if_present_write(write)?;
    for row in packs.iter()? {
        let (key, value) = row?;
        let pack = BlobPackVariant::decode(value.value(), Arc::new(()))?;
        if key.value() != pack.variant_id.as_bytes()
            || write
                .open_table(super::BLOB_IMPORTS)?
                .get(key.value())?
                .is_some()
        {
            return Err(pack_schema_error());
        }
        require_owner_binding(owner_binding, pack.owner_binding)?;
    }
    Ok(())
}

pub(super) fn audit_read(read: &redb::ReadTransaction) -> Result<(), StoreError> {
    let packs = read.open_table(BLOB_PROFILE5_PACKS)?;
    let imports = read.open_table(super::BLOB_IMPORTS)?;
    let owner_binding = super::depot::depot_owner_binding_if_present_read(read)?;
    for row in packs.iter()? {
        let (key, value) = row?;
        let pack = BlobPackVariant::decode(value.value(), Arc::new(()))?;
        if key.value() != pack.variant_id.as_bytes() || imports.get(key.value())?.is_some() {
            return Err(pack_schema_error());
        }
        require_owner_binding(owner_binding, pack.owner_binding)?;
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
pub(super) fn audit_publication_evidence(
    encoded: &[u8],
    variant: BlobVariantId,
    blob_id: aster_mesh::BlobId,
    epoch: u64,
    manifest_digest: [u8; 32],
    segment_count: u64,
    physical_lineage: Option<[u8; 32]>,
    owner_binding: [u8; 32],
) -> Result<(), StoreError> {
    let pack = BlobPackVariant::decode(encoded, Arc::new(()))?;
    if pack.state != PackLifecycleState::Active
        || pack.variant_id != variant
        || pack.commitment.blob_id() != blob_id
        || pack.open.content_epoch() != epoch
        || pack.completion.commitment_digest() != &manifest_digest
        || pack.commitment.segment_count() != segment_count
        || physical_lineage != Some(pack.physical_lineage)
        || pack.owner_binding != owner_binding
    {
        return Err(pack_schema_error());
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
pub(super) fn source_shape_evidence(
    encoded: &[u8],
    variant: BlobVariantId,
    blob_id: aster_mesh::BlobId,
    epoch: u64,
    manifest_digest: [u8; 32],
    segment_count: u64,
    physical_lineage: [u8; 32],
    owner_binding: [u8; 32],
) -> Result<(u64, u64), StoreError> {
    audit_publication_evidence(
        encoded,
        variant,
        blob_id,
        epoch,
        manifest_digest,
        segment_count,
        Some(physical_lineage),
        owner_binding,
    )?;
    let pack = BlobPackVariant::decode(encoded, Arc::new(()))?;
    Ok((pack.open.total_len(), pack.commitment.segment_count()))
}

pub(super) fn pressure_projection(
    encoded: &[u8],
) -> Result<Option<(BlobVariantId, u64)>, StoreError> {
    let pack = BlobPackVariant::decode(encoded, Arc::new(()))?;
    Ok(pack
        .lifecycle_owned()
        .then_some((pack.variant_id, pack.open.total_len())))
}

pub(super) fn is_pack_evidence(encoded: &[u8]) -> bool {
    encoded.starts_with(PACK_VARIANT_MAGIC)
}

pub(super) fn encoded_variant_id(encoded: &[u8]) -> Result<BlobVariantId, StoreError> {
    Ok(BlobPackVariant::decode(encoded, Arc::new(()))?.variant_id)
}

pub(super) fn deletion_projection(
    key: &[u8],
    encoded: &[u8],
) -> Result<super::depot::DeletionImportProjection, StoreError> {
    let pack = BlobPackVariant::decode(encoded, Arc::new(()))?;
    if key != pack.variant_id.as_bytes() || pack.state != PackLifecycleState::Active {
        return Err(pack_schema_error());
    }
    Ok(super::depot::DeletionImportProjection {
        variant_id: pack.variant_id,
        blob_id: pack.commitment.blob_id(),
        content_group: pack.open.content_group(),
        epoch: pack.open.content_epoch(),
        total_len: pack.open.total_len(),
        chunk_count: 0,
        physical_lineage: pack.physical_lineage,
        finalized_root: Some(*pack.completion.commitment_digest()),
    })
}

pub(super) fn encoded_active_write(
    write: &redb::WriteTransaction,
    variant: BlobVariantId,
) -> Result<Option<Vec<u8>>, StoreError> {
    write
        .open_table(BLOB_PROFILE5_PACKS)?
        .get(variant.as_bytes().as_slice())?
        .map(|value| {
            let encoded = value.value().to_vec();
            let pack = BlobPackVariant::decode(&encoded, Arc::new(()))?;
            if pack.variant_id != variant || pack.state != PackLifecycleState::Active {
                return Err(pack_schema_error());
            }
            Ok(encoded)
        })
        .transpose()
}

pub(super) fn mark_deletion_pending_write(
    write: &redb::WriteTransaction,
    variant: BlobVariantId,
    expected_active: &[u8],
) -> Result<(), StoreError> {
    let mut packs = write.open_table(BLOB_PROFILE5_PACKS)?;
    let current = packs
        .get(variant.as_bytes().as_slice())?
        .map(|value| value.value().to_vec())
        .ok_or_else(pack_schema_error)?;
    if current != expected_active {
        return Err(pack_schema_error());
    }
    let mut pack = BlobPackVariant::decode(&current, Arc::new(()))?;
    if pack.state != PackLifecycleState::Active {
        return Err(pack_schema_error());
    }
    pack.state = PackLifecycleState::DeletionPending;
    let encoded = pack.encode()?;
    packs.insert(variant.as_bytes().as_slice(), encoded.as_slice())?;
    Ok(())
}

pub(super) fn finalize_deletion_write(
    write: &redb::WriteTransaction,
    variant: BlobVariantId,
    expected_active: &[u8],
) -> Result<(), StoreError> {
    let mut packs = write.open_table(BLOB_PROFILE5_PACKS)?;
    let current = packs
        .get(variant.as_bytes().as_slice())?
        .map(|value| value.value().to_vec())
        .ok_or_else(pack_schema_error)?;
    let current = BlobPackVariant::decode(&current, Arc::new(()))?;
    let expected = BlobPackVariant::decode(expected_active, Arc::new(()))?;
    if current.variant_id != variant
        || current.state != PackLifecycleState::DeletionPending
        || expected.state != PackLifecycleState::Active
        || current.completion != expected.completion
        || current.open != expected.open
        || current.commitment != expected.commitment
        || current.owner_binding != expected.owner_binding
    {
        return Err(pack_schema_error());
    }
    packs.remove(variant.as_bytes().as_slice())?;
    Ok(())
}

pub(super) fn validate_deletion_pending(
    current: &[u8],
    expected_active: &[u8],
) -> Result<(), StoreError> {
    let current = BlobPackVariant::decode(current, Arc::new(()))?;
    let expected = BlobPackVariant::decode(expected_active, Arc::new(()))?;
    if current.state != PackLifecycleState::DeletionPending
        || expected.state != PackLifecycleState::Active
        || current.variant_id != expected.variant_id
        || current.route_lineage != expected.route_lineage
        || current.physical_lineage != expected.physical_lineage
        || current.owner_binding != expected.owner_binding
        || current.authenticated_open_digest != expected.authenticated_open_digest
        || current.open != expected.open
        || current.authenticated_open != expected.authenticated_open
        || current.commitment != expected.commitment
        || current.authenticated_commitment != expected.authenticated_commitment
        || current.completion != expected.completion
        || current.capacity != expected.capacity
    {
        return Err(pack_schema_error());
    }
    Ok(())
}

pub(super) fn deletion_pending_projection(
    encoded: &[u8],
) -> Result<Option<(BlobVariantId, usize)>, StoreError> {
    let pack = BlobPackVariant::decode(encoded, Arc::new(()))?;
    Ok((pack.state == PackLifecycleState::DeletionPending)
        .then_some((pack.variant_id, encoded.len())))
}

pub(super) fn deletion_identity(
    encoded: &[u8],
) -> Result<super::pack::BlobPackIdentity, StoreError> {
    let pack = BlobPackVariant::decode(encoded, Arc::new(()))?;
    if pack.state != PackLifecycleState::Active {
        return Err(pack_schema_error());
    }
    Ok(pack.completion.identity())
}

pub(super) fn audited_lifecycle_imports_write(
    write: &redb::WriteTransaction,
) -> Result<Vec<super::depot::AuditedLifecycleImport>, StoreError> {
    let owner_binding = super::depot::depot_owner_binding_if_present_write(write)?;
    audited_lifecycle_imports(&write.open_table(BLOB_PROFILE5_PACKS)?, owner_binding)
}

pub(super) fn audited_lifecycle_imports_read(
    read: &redb::ReadTransaction,
) -> Result<Vec<super::depot::AuditedLifecycleImport>, StoreError> {
    let owner_binding = super::depot::depot_owner_binding_if_present_read(read)?;
    audited_lifecycle_imports(&read.open_table(BLOB_PROFILE5_PACKS)?, owner_binding)
}

fn audited_lifecycle_imports(
    packs: &impl ReadableTable<&'static [u8], &'static [u8]>,
    owner_binding: Option<[u8; 32]>,
) -> Result<Vec<super::depot::AuditedLifecycleImport>, StoreError> {
    let mut audited = Vec::new();
    for row in packs.iter()? {
        let (key, value) = row?;
        let pack = BlobPackVariant::decode(value.value(), Arc::new(()))?;
        require_owner_binding(owner_binding, pack.owner_binding)?;
        if key.value() != pack.variant_id.as_bytes() {
            return Err(pack_schema_error());
        }
        // A completed upload pack remains provisional authority owned solely
        // by BLOB_UPLOADS until the atomic publication transaction promotes
        // it. Treating it as a lifecycle import here invents publication
        // references/lineage and makes a valid resumable store fail reopen.
        if pack.state == PackLifecycleState::Provisional {
            continue;
        }
        audited.push(super::depot::AuditedLifecycleImport {
            variant_id: pack.variant_id,
            physical_lineage: pack.physical_lineage,
        });
    }
    Ok(audited)
}

impl super::Store {
    /// Opens one application plaintext session over the canonical pack while
    /// excluding lifecycle deletion for the complete session lifetime.
    #[doc(hidden)]
    pub fn open_profile5_pack_application_read(
        &self,
        variant: BlobVariantId,
    ) -> Result<Profile5PackReadSession, StoreError> {
        self.open_profile5_pack_read(variant, super::lease::BlobLeaseKind::ApplicationPageRead, 0)
    }

    /// Opens an application reader at the fixed boundary for `segment`.
    #[doc(hidden)]
    pub fn open_profile5_pack_application_read_at_segment(
        &self,
        variant: BlobVariantId,
        segment: u64,
    ) -> Result<Profile5PackReadSession, StoreError> {
        self.open_profile5_pack_read(
            variant,
            super::lease::BlobLeaseKind::ApplicationPageRead,
            segment,
        )
    }

    /// Opens one transport session over exact canonical pack records while
    /// excluding lifecycle deletion for the complete session lifetime.
    #[doc(hidden)]
    pub fn open_profile5_pack_transfer_read(
        &self,
        variant: BlobVariantId,
    ) -> Result<Profile5PackReadSession, StoreError> {
        self.open_profile5_pack_read(variant, super::lease::BlobLeaseKind::CarrierRange, 0)
    }

    /// Opens a transfer reader at one canonical segment boundary.
    #[doc(hidden)]
    pub fn open_profile5_pack_transfer_read_at_segment(
        &self,
        variant: BlobVariantId,
        segment: u64,
    ) -> Result<Profile5PackReadSession, StoreError> {
        self.open_profile5_pack_read(variant, super::lease::BlobLeaseKind::CarrierRange, segment)
    }

    fn open_profile5_pack_read(
        &self,
        variant: BlobVariantId,
        kind: super::lease::BlobLeaseKind,
        first_segment: u64,
    ) -> Result<Profile5PackReadSession, StoreError> {
        let _depot = self
            .blob_depot_lock
            .read()
            .map_err(|_| blob_error(BlobStoreError::DepotIntegrity("depot lock is poisoned")))?;
        self.require_live()?;
        let read = self.database.begin_read()?;
        super::deletion::require_variant_available_read(&read, variant)?;
        let pack = load_read(&read, variant, Arc::clone(&self.blob_completion_authority))?
            .ok_or_else(|| blob_error(BlobStoreError::NotFound))?;
        if !pack.lifecycle_owned() {
            return Err(blob_error(BlobStoreError::VariantDeleting));
        }
        let lease = self
            .blob_lease_registry
            .acquire(
                self.blob_depot_owner_binding,
                super::lease::BlobLeaseTarget::Variant(variant),
                kind,
            )
            .map(|guard| Arc::new(super::lease::BlobLeaseHandle::new(guard)))
            .map_err(super::lease::store_error)?;
        drop(read);
        drop(_depot);
        let root = super::pack::PinnedBlobPackRoot::open(self)?;
        let reader = super::pack::BlobPackReader::open_completed_upload_pinned_at_segment(
            &root,
            pack.completion(),
            first_segment,
        )
        .map_err(pack_store_error)?;
        Ok(Profile5PackReadSession {
            reader,
            open: pack.open.clone(),
            authenticated_open: pack.authenticated_open.clone(),
            commitment: pack.commitment.clone(),
            authenticated_commitment: pack.authenticated_commitment.clone(),
            route_lineage: pack.route_lineage,
            physical_lineage: pack.physical_lineage,
            _lease: lease,
        })
    }
}

fn require_owner_binding(durable: Option<[u8; 32]>, actual: [u8; 32]) -> Result<(), StoreError> {
    if durable == Some(actual) {
        Ok(())
    } else {
        Err(blob_error(BlobStoreError::PhysicalLineageConflict))
    }
}

fn pack_schema_error() -> StoreError {
    blob_error(BlobStoreError::SchemaInvariant(
        "Profile-5 pack lifecycle row is malformed",
    ))
}

fn pack_store_error(error: BlobPackError) -> StoreError {
    match error {
        BlobPackError::Store(error) => error,
        BlobPackError::Io(error) => blob_error(BlobStoreError::Io(error)),
        BlobPackError::Invalid(message) => blob_error(BlobStoreError::DepotIntegrity(message)),
    }
}

struct Cursor<'a> {
    bytes: &'a [u8],
    offset: usize,
}

impl<'a> Cursor<'a> {
    const fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, offset: 0 }
    }

    fn take(&mut self, len: usize) -> Result<&'a [u8], StoreError> {
        let end = self.offset.checked_add(len).ok_or_else(pack_schema_error)?;
        let value = self
            .bytes
            .get(self.offset..end)
            .ok_or_else(pack_schema_error)?;
        self.offset = end;
        Ok(value)
    }

    fn array<const N: usize>(&mut self) -> Result<[u8; N], StoreError> {
        self.take(N)?.try_into().map_err(|_| pack_schema_error())
    }

    fn u16(&mut self) -> Result<u16, StoreError> {
        Ok(u16::from_be_bytes(self.array()?))
    }

    fn u8(&mut self) -> Result<u8, StoreError> {
        Ok(self.array::<1>()?[0])
    }

    fn u32(&mut self) -> Result<u32, StoreError> {
        Ok(u32::from_be_bytes(self.array()?))
    }

    fn u64(&mut self) -> Result<u64, StoreError> {
        Ok(u64::from_be_bytes(self.array()?))
    }

    fn long(&mut self) -> Result<&'a [u8], StoreError> {
        let len = usize::try_from(self.u32()?).map_err(|_| pack_schema_error())?;
        self.take(len)
    }

    fn finish(self) -> Result<(), StoreError> {
        if self.offset == self.bytes.len() {
            Ok(())
        } else {
            Err(pack_schema_error())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn incompatible_pack_encoding_requires_development_depot_reset_or_reimport() {
        let error = BlobPackVariant::decode(b"ASTRPV01\0\x01", Arc::new(()))
            .expect_err("pre-native pack encoding must fail closed");

        assert!(matches!(
            error,
            StoreError::Blob(BlobStoreError::UnsupportedProfile5PackSchema)
        ));
        assert!(
            error
                .to_string()
                .contains("reset the development depot or reimport")
        );
    }
}
