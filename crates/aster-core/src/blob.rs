//! Streaming encrypted Blob profile.
//!
//! Blob payloads are never collected into one `Vec`. A two-pass seekable writer first computes the
//! content-addressed identity and ordered plaintext digests, then encrypts each chunk independently
//! into an atomic [`BlobStore`] commit. The reader verifies the ciphertext digest, AEAD tag,
//! plaintext digest, and whole-content digest incrementally.
//!
//! Construction from a content grant is crate-private. Applications receive writers/readers from
//! the high-level node integration and never see key material or algorithm controls.

use crate::model::{NodeId, Scope, Topic};
use crate::wire::{EnvelopeId, ObjectId};
use aes_gcm::{
    Aes256Gcm,
    aead::{AeadInOut, KeyInit, array::Array},
};
use hkdf::Hkdf;
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::error::Error;
use std::fmt::{self, Display, Formatter};
use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::sync::{
    Arc,
    atomic::{AtomicU64, Ordering},
};
use zeroize::{Zeroize, Zeroizing};

/// Smallest interoperable chunk size.
pub const MIN_BLOB_CHUNK_SIZE: u32 = 4 * 1024;
/// Largest interoperable chunk size.
pub const MAX_BLOB_CHUNK_SIZE: u32 = 64 * 1024;
/// Canonical chunk size required by the selected Blob application profile.
pub const SELECTED_BLOB_CHUNK_SIZE: u32 = MAX_BLOB_CHUNK_SIZE;
const MANIFEST_RECORD_LEN: u64 = 72;
const MANIFEST_FIXED_LEN: u64 = 141;
const MAX_ENCODED_METADATA_LEN: u64 = 2 + MAX_MEDIA_TYPE_LEN as u64 + MAX_SCHEMA_ID_LEN as u64;
/// Maximum selected chunk count needed by the public 8-GiB streaming ceiling.
///
/// `8 GiB / 64 KiB = 131,072` canonical chunks. The manifest remains bounded,
/// but the bound follows that existing public payload ceiling rather than an
/// unrelated 1-MiB carrier size.
pub const MAX_BLOB_CHUNKS: u64 = (8 * 1024 * 1024 * 1024) / MAX_BLOB_CHUNK_SIZE as u64;
/// Maximum exact canonical manifest size, including fixed framing, maximum
/// metadata, and all 131,072 encoded 72-byte chunk records.
pub const MAX_BLOB_MANIFEST_BYTES: u64 =
    MANIFEST_FIXED_LEN + MAX_ENCODED_METADATA_LEN + MAX_BLOB_CHUNKS * MANIFEST_RECORD_LEN;
const MAX_MEDIA_TYPE_LEN: usize = 255;
const MAX_SCHEMA_ID_LEN: usize = 1024;
/// Maximum UTF-8 bytes in selected Blob media-type identity metadata.
pub const MAX_BLOB_MEDIA_TYPE_BYTES: usize = MAX_MEDIA_TYPE_LEN;
/// Maximum bytes in selected Blob schema identity metadata.
pub const MAX_BLOB_SCHEMA_ID_BYTES: usize = MAX_SCHEMA_ID_LEN;
const GCM_TAG_LEN: usize = 16;
const NONCE_LEN: usize = 12;
const MANIFEST_VERSION: u16 = 1;
const PROTOCOL_VERSION: u16 = 1;
const SUITE_ID: u16 = 0x0001;
const MANIFEST_MAGIC: &[u8; 8] = b"ASTRBM01";
const BLOB_ID_DOMAIN: &[u8] = b"aster/blob-id/v1";
const CONTENT_GROUP_DOMAIN: &[u8] = b"aster/content-group/v1";
const CHUNK_KEY_LABEL: &[u8] = b"aster/blob-chunk-key/v1";
const CHUNK_NONCE_LABEL: &[u8] = b"aster/blob-chunk-nonce/v1";
const CHUNK_AAD_DOMAIN: &[u8] = b"aster/blob-chunk-aad/v1";
const MANIFEST_DIGEST_DOMAIN: &[u8] = b"aster/blob-manifest/v1";
const BLOB_KDF_SALT: &[u8] = b"aster/blob-kdf/v1";
const CHUNK_FILE_MAGIC: &[u8; 8] = b"ASTRBC01";
const STORE_SUMMARY_MAGIC: &[u8; 8] = b"ASTRBS01";
const TRANSFER_MAGIC: &[u8; 8] = b"ASTRBT01";
const BLOB_ROUTE_LEAF_DOMAIN: &[u8] = b"aster/blob-route-leaf/v1";
const BLOB_ROUTE_NODE_DOMAIN: &[u8] = b"aster/blob-route-node/v1";
const BLOB_ROUTE_EMPTY_DOMAIN: &[u8] = b"aster/blob-route-empty/v1";
const BLOB_TRANSFER_ID_DOMAIN: &[u8] = b"aster/blob-transfer-object/v1";
const ROUTE_TREE_MAGIC: &[u8; 8] = b"ASTRRT01";
const ROUTE_TREE_FILE: &str = "route-tree.bin";
const TRANSFER_FIXED_LEN: usize = 8 + 2 + 32 + 32 + 8 + 32 + 4 + 1;
const MAX_ROUTE_PROOF_HASHES: usize = 17;
/// Exact maximum encoded size of one canonical `ASTRBT01` Blob transfer object.
///
/// This is a carrier bound, not a transport-frame recommendation. Ranged transports
/// should generally select a smaller fixed payload budget and resume by the complete
/// typed [`ObjectId`].
pub const MAX_BLOB_TRANSFER_OBJECT_BYTES: usize =
    TRANSFER_FIXED_LEN + MAX_ROUTE_PROOF_HASHES * 32 + MAX_BLOB_CHUNK_SIZE as usize + GCM_TAG_LEN;
const MAX_ROUTE_TREE_BYTES: u64 =
    8 + 2 + 32 + 8 + 1 + ((MAX_ROUTE_PROOF_HASHES as u64 + 1) * 8) + (MAX_BLOB_CHUNKS * 2 * 32);
const TRANSFER_DIRECTORY: &str = "transfer-objects";
const MAX_STORE_SUMMARY_BYTES: u64 = 2048;
static STORE_TEMP_SEQUENCE: AtomicU64 = AtomicU64::new(1);

const BLOB_PHYSICAL_LINEAGE_DOMAIN: &[u8] = b"aster/blob-physical-lineage/v1";

/// Opaque, provider-minted identity of the exact content grant which produced
/// one physical encrypted Blob variant.
///
/// `(BlobId, content group, epoch)` is insufficient when a committed rekey
/// replaces content-key material at the same epoch. This one-way binding lets a
/// durable adapter distinguish those physical variants without receiving key
/// material or an algorithm handle.
#[derive(Clone, Copy, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct BlobPhysicalLineage([u8; 32]);

impl BlobPhysicalLineage {
    pub(crate) fn from_content_grant(
        mission_authority_id: NodeId,
        scope: &Scope,
        topic: &Topic,
        epoch: u64,
        epoch_seed: &[u8; 32],
    ) -> Self {
        let mut hasher = domain_hasher(BLOB_PHYSICAL_LINEAGE_DOMAIN);
        hasher.update(mission_authority_id);
        hasher.update((scope.as_str().len() as u64).to_be_bytes());
        hasher.update(scope.as_str().as_bytes());
        hasher.update((topic.as_str().len() as u64).to_be_bytes());
        hasher.update(topic.as_str().as_bytes());
        hasher.update(epoch.to_be_bytes());
        hasher.update(epoch_seed);
        Self(finalize_sha256(hasher))
    }

    /// Stable one-way persistence binding. This is not content-key material.
    pub const fn binding(&self) -> &[u8; 32] {
        &self.0
    }
}

impl fmt::Debug for BlobPhysicalLineage {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter.write_str("BlobPhysicalLineage([PROVIDER-OWNED])")
    }
}

/// Hard local byte and committed-chunk quotas for the concrete Blob store.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BlobStoreConfig {
    /// Maximum bytes occupied by all durable objects below the store root.
    pub max_bytes: u64,
    /// Maximum number of committed encrypted chunk objects.
    pub max_chunks: u64,
}

impl Default for BlobStoreConfig {
    fn default() -> Self {
        Self {
            max_bytes: 512 * 1024 * 1024,
            max_chunks: 100_000,
        }
    }
}

/// Stable Blob identifier committing exact content bytes, the canonical chunk profile,
/// and media/schema identity metadata.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct BlobId([u8; 32]);

impl BlobId {
    /// Constructs an identifier from its complete fixed-width representation.
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// Returns the full collision-resistant identifier.
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

/// Validated application metadata committed by the Blob identifier.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BlobMetadata {
    media_type: Option<String>,
    schema_id: Vec<u8>,
}

impl BlobMetadata {
    /// Creates bounded metadata. Media type is descriptive and schema bytes are opaque.
    pub fn new(media_type: Option<String>, schema_id: Vec<u8>) -> Result<Self, BlobError> {
        if media_type
            .as_ref()
            .is_some_and(|value| value.is_empty() || value.len() > MAX_MEDIA_TYPE_LEN)
            || schema_id.len() > MAX_SCHEMA_ID_LEN
        {
            return Err(BlobError::InvalidMetadata);
        }
        Ok(Self {
            media_type,
            schema_id,
        })
    }

    pub fn media_type(&self) -> Option<&str> {
        self.media_type.as_deref()
    }

    pub fn schema_id(&self) -> &[u8] {
        &self.schema_id
    }
}

/// Bounded content preparation result awaiting provider-owned group/epoch binding.
///
/// This value contains ordered plaintext digests, but never plaintext or a content
/// encryption key. Its fields are private so only the Blob engine can install the
/// exact preparation result into a durable [`BlobStore`].
pub struct PreparedBlob {
    id: BlobId,
    total_len: u64,
    chunk_size: u32,
    chunk_count: u64,
    whole_plaintext_sha256: [u8; 32],
    metadata: BlobMetadata,
    plaintext_digests: Arc<Zeroizing<Vec<[u8; 32]>>>,
}

impl fmt::Debug for PreparedBlob {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PreparedBlob")
            .field("id", &self.id)
            .field("total_len", &self.total_len)
            .field("chunk_size", &self.chunk_size)
            .field("chunk_count", &self.chunk_count)
            .field("metadata", &self.metadata)
            .field("plaintext_digests", &"[REDACTED]")
            .finish()
    }
}

impl PreparedBlob {
    /// Stable identifier for the exact bytes, selected chunking, and identity metadata.
    pub const fn id(&self) -> BlobId {
        self.id
    }

    /// Exact plaintext byte length observed during preparation.
    pub const fn total_len(&self) -> u64 {
        self.total_len
    }

    /// Chunk size committed by this preparation result.
    pub const fn chunk_size(&self) -> u32 {
        self.chunk_size
    }

    /// Number of ordered chunks committed by this preparation result.
    pub const fn chunk_count(&self) -> u64 {
        self.chunk_count
    }

    /// Identity metadata committed by [`Self::id`].
    pub const fn metadata(&self) -> &BlobMetadata {
        &self.metadata
    }

    /// Reconstructs the canonical preparation result from a durable ordered
    /// digest artifact and its incrementally retained whole-plaintext digest.
    /// No plaintext is retained by this value.
    pub fn from_retained_digests(
        total_len: u64,
        chunk_size: u32,
        metadata: BlobMetadata,
        whole_plaintext_sha256: Zeroizing<[u8; 32]>,
        plaintext_digests: Zeroizing<Vec<[u8; 32]>>,
    ) -> Result<Self, BlobError> {
        validate_chunk_size(chunk_size)?;
        let chunk_count = chunk_count(total_len, chunk_size)?;
        if chunk_count > MAX_BLOB_CHUNKS
            || usize::try_from(chunk_count).ok() != Some(plaintext_digests.len())
        {
            return Err(BlobError::InvalidManifest);
        }
        let mut id_hasher = domain_hasher(BLOB_ID_DOMAIN);
        encode_blob_identity_prefix(
            &mut id_hasher,
            total_len,
            chunk_size,
            chunk_count,
            &metadata,
        );
        for digest in plaintext_digests.iter() {
            id_hasher.update(digest);
        }
        id_hasher.update(*whole_plaintext_sha256);
        Ok(Self {
            id: BlobId(finalize_sha256(id_hasher)),
            total_len,
            chunk_size,
            chunk_count,
            whole_plaintext_sha256: *whole_plaintext_sha256,
            metadata,
            plaintext_digests: Arc::new(plaintext_digests),
        })
    }

    /// Shares the single zeroizing digest allocation with bounded map workers.
    pub fn retained_digests(&self) -> Arc<Zeroizing<Vec<[u8; 32]>>> {
        Arc::clone(&self.plaintext_digests)
    }
}

impl Drop for PreparedBlob {
    fn drop(&mut self) {
        self.whole_plaintext_sha256.zeroize();
    }
}

/// Performs the bounded, store-independent first pass of Blob preparation.
///
/// The caller's original seek position is restored after success and after every
/// preparation failure. The result retains at most the manifest-bounded ordered
/// digest set and does not retain plaintext.
pub fn prepare_blob<R: Read + Seek>(
    source: &mut R,
    chunk_size: u32,
    metadata: BlobMetadata,
) -> Result<PreparedBlob, BlobError> {
    validate_chunk_size(chunk_size)?;
    let original = source.stream_position()?;
    let prepared = (|| {
        let total_len = source.seek(SeekFrom::End(0))?;
        source.seek(SeekFrom::Start(0))?;
        let chunk_count = chunk_count(total_len, chunk_size)?;
        if chunk_count > MAX_BLOB_CHUNKS {
            return Err(BlobError::InvalidManifest);
        }
        let digest_capacity =
            usize::try_from(chunk_count).map_err(|_| BlobError::LengthOverflow)?;
        let mut plaintext_digests = Zeroizing::new(Vec::with_capacity(digest_capacity));
        let mut id_hasher = domain_hasher(BLOB_ID_DOMAIN);
        encode_blob_identity_prefix(
            &mut id_hasher,
            total_len,
            chunk_size,
            chunk_count,
            &metadata,
        );
        let mut whole_hasher = Sha256::new();
        let buffer_capacity = usize::try_from(chunk_size).map_err(|_| BlobError::LengthOverflow)?;
        let mut buffer = Zeroizing::new(Vec::with_capacity(buffer_capacity));
        for index in 0..chunk_count {
            let expected = expected_plaintext_len(total_len, chunk_size, chunk_count, index)?;
            read_exact_chunk(source, &mut buffer, expected)?;
            whole_hasher.update(&buffer);
            let mut digest = sha256(&buffer);
            id_hasher.update(digest);
            plaintext_digests.push(digest);
            digest.zeroize();
            buffer.zeroize();
        }
        let mut trailing = Zeroizing::new([0u8; 1]);
        if source.read(&mut trailing[..])? != 0 {
            buffer.zeroize();
            return Err(BlobError::SourceChanged);
        }
        buffer.zeroize();
        let whole_plaintext_sha256 = finalize_sha256(whole_hasher);
        id_hasher.update(whole_plaintext_sha256);
        let id = BlobId(finalize_sha256(id_hasher));
        Ok(PreparedBlob {
            id,
            total_len,
            chunk_size,
            chunk_count,
            whole_plaintext_sha256,
            metadata,
            plaintext_digests: Arc::new(plaintext_digests),
        })
    })();
    let restored = source.seek(SeekFrom::Start(original));
    match (prepared, restored) {
        (Ok(prepared), Ok(_)) => Ok(prepared),
        (Err(error), Ok(_)) => Err(error),
        (_, Err(error)) => Err(BlobError::Io(error)),
    }
}

/// Fixed-size portion of the authenticated Blob manifest.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BlobManifest {
    id: BlobId,
    total_len: u64,
    chunk_size: u32,
    chunk_count: u64,
    whole_plaintext_sha256: [u8; 32],
    metadata: BlobMetadata,
    content_group: [u8; 32],
    content_epoch: u64,
}

impl BlobManifest {
    pub fn id(&self) -> BlobId {
        self.id
    }

    pub fn total_len(&self) -> u64 {
        self.total_len
    }

    pub fn chunk_size(&self) -> u32 {
        self.chunk_size
    }

    pub fn chunk_count(&self) -> u64 {
        self.chunk_count
    }

    pub fn whole_plaintext_sha256(&self) -> &[u8; 32] {
        &self.whole_plaintext_sha256
    }

    pub fn metadata(&self) -> &BlobMetadata {
        &self.metadata
    }

    pub fn content_epoch(&self) -> u64 {
        self.content_epoch
    }

    /// Stable content-group commitment for the manifest's exact scope/topic.
    pub const fn content_group(&self) -> &[u8; 32] {
        &self.content_group
    }

    fn plaintext_len(&self, index: u64) -> Result<usize, BlobError> {
        if index >= self.chunk_count {
            return Err(BlobError::InvalidChunkIndex);
        }
        let chunk_size = u64::from(self.chunk_size);
        let offset = index
            .checked_mul(chunk_size)
            .ok_or(BlobError::LengthOverflow)?;
        let remaining = self
            .total_len
            .checked_sub(offset)
            .ok_or(BlobError::LengthOverflow)?;
        usize::try_from(remaining.min(chunk_size)).map_err(|_| BlobError::LengthOverflow)
    }
}

/// Ordered integrity record stored beside one independently protected chunk.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BlobChunkRecord {
    plaintext_sha256: [u8; 32],
    ciphertext_sha256: [u8; 32],
    plaintext_len: u32,
    ciphertext_len: u32,
}

impl BlobChunkRecord {
    /// Reconstructs one persisted record after checking its context-free length bounds.
    ///
    /// A reader additionally validates these lengths against the exact authenticated
    /// manifest and verifies both digests before releasing plaintext.
    pub fn from_parts(
        plaintext_sha256: [u8; 32],
        ciphertext_sha256: [u8; 32],
        plaintext_len: u32,
        ciphertext_len: u32,
    ) -> Result<Self, BlobError> {
        if plaintext_len == 0
            || plaintext_len > MAX_BLOB_CHUNK_SIZE
            || plaintext_len.checked_add(GCM_TAG_LEN as u32) != Some(ciphertext_len)
        {
            return Err(BlobError::InvalidManifest);
        }
        Ok(Self {
            plaintext_sha256,
            ciphertext_sha256,
            plaintext_len,
            ciphertext_len,
        })
    }

    pub fn plaintext_sha256(&self) -> &[u8; 32] {
        &self.plaintext_sha256
    }

    pub fn ciphertext_sha256(&self) -> &[u8; 32] {
        &self.ciphertext_sha256
    }

    pub fn plaintext_len(&self) -> u32 {
        self.plaintext_len
    }

    pub fn ciphertext_len(&self) -> u32 {
        self.ciphertext_len
    }
}

/// Source-authenticated, route-protected commitment for all encrypted chunks
/// of one Blob. It contains no plaintext digest or application metadata.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BlobRouteCommitment {
    blob_id: BlobId,
    chunk_count: u64,
    root: [u8; 32],
}

impl BlobRouteCommitment {
    /// Reconstructs a persisted selected route commitment.
    ///
    /// Source authenticity still requires a [`crate::ContentVerifiedBlobEnvelope`];
    /// this constructor checks only context-free structural bounds.
    pub fn from_parts(
        blob_id: BlobId,
        chunk_count: u64,
        root: [u8; 32],
    ) -> Result<Self, BlobError> {
        if chunk_count > MAX_BLOB_CHUNKS || root == [0_u8; 32] {
            return Err(BlobError::InvalidManifest);
        }
        Ok(Self {
            blob_id,
            chunk_count,
            root,
        })
    }

    pub(crate) const fn from_authenticated_header(
        blob_id: BlobId,
        chunk_count: u64,
        root: [u8; 32],
    ) -> Self {
        Self {
            blob_id,
            chunk_count,
            root,
        }
    }

    pub const fn blob_id(&self) -> BlobId {
        self.blob_id
    }

    pub const fn chunk_count(&self) -> u64 {
        self.chunk_count
    }

    pub const fn root(&self) -> &[u8; 32] {
        &self.root
    }
}

/// Route commitment bound to the exact source envelope that authenticated it.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AuthenticatedBlobRoute {
    source_envelope: EnvelopeId,
    commitment: BlobRouteCommitment,
}

impl AuthenticatedBlobRoute {
    /// This constructor is restricted to the authenticated envelope layer.
    pub(crate) const fn new(source_envelope: EnvelopeId, commitment: BlobRouteCommitment) -> Self {
        Self {
            source_envelope,
            commitment,
        }
    }

    pub const fn source_envelope(&self) -> EnvelopeId {
        self.source_envelope
    }

    pub const fn commitment(&self) -> BlobRouteCommitment {
        self.commitment
    }
}

/// Parsed canonical transfer carrier. The plaintext digest remains only in
/// the encrypted source-authenticated manifest and is intentionally absent.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BlobTransferObject {
    object_id: ObjectId,
    source_envelope: EnvelopeId,
    blob_id: BlobId,
    index: u64,
    ciphertext_sha256: [u8; 32],
    ciphertext_len: u32,
    proof: Vec<[u8; 32]>,
    ciphertext: Vec<u8>,
}

impl BlobTransferObject {
    pub const fn object_id(&self) -> ObjectId {
        self.object_id
    }

    pub const fn source_envelope(&self) -> EnvelopeId {
        self.source_envelope
    }

    pub const fn blob_id(&self) -> BlobId {
        self.blob_id
    }

    pub const fn index(&self) -> u64 {
        self.index
    }

    pub fn ciphertext(&self) -> &[u8] {
        &self.ciphertext
    }

    pub const fn ciphertext_len(&self) -> u32 {
        self.ciphertext_len
    }

    pub const fn ciphertext_sha256(&self) -> &[u8; 32] {
        &self.ciphertext_sha256
    }
}

/// Opaque canonical identity of one source-bound Blob carrier.
///
/// The only public representation is the exact 33-byte typed wire form. A
/// caller cannot turn arbitrary bytes into this type without an exact verified
/// transfer plan.
#[derive(Clone, Copy, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct BlobCarrierId(ObjectId);

impl BlobCarrierId {
    pub const WIRE_LEN: usize = ObjectId::WIRE_LEN;

    /// Exact `kind=BlobChunk || digest` representation used on the wire and as
    /// a durable peer-neutral staging key.
    pub fn wire_bytes(self) -> [u8; Self::WIRE_LEN] {
        self.0.to_wire_bytes()
    }
}

impl fmt::Debug for BlobCarrierId {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter.write_str("BlobCarrierId([SOURCE-BOUND])")
    }
}

/// Canonical carrier bytes built from one exact verified transfer plan and a
/// matching durable encrypted chunk.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BuiltBlobTransferObject {
    object_id: BlobCarrierId,
    bytes: Vec<u8>,
}

impl BuiltBlobTransferObject {
    pub const fn object_id(&self) -> BlobCarrierId {
        self.object_id
    }

    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }

    pub fn into_bytes(self) -> Vec<u8> {
        self.bytes
    }
}

/// One complete carrier authenticated against an exact source and canonical
/// manifest plan.
///
/// Fields and construction are private so parsing a structurally valid
/// `ASTRBT01` object alone cannot mint this capability.
#[derive(Clone, Debug)]
pub struct VerifiedBlobTransferObject {
    object: BlobTransferObject,
    expected_record: BlobChunkRecord,
    #[cfg(any(test, feature = "test-utils"))]
    zeroize_observer: Option<std::sync::Arc<std::sync::atomic::AtomicUsize>>,
}

impl PartialEq for VerifiedBlobTransferObject {
    fn eq(&self, other: &Self) -> bool {
        self.object == other.object && self.expected_record == other.expected_record
    }
}

impl Eq for VerifiedBlobTransferObject {}

impl VerifiedBlobTransferObject {
    pub const fn object_id(&self) -> BlobCarrierId {
        BlobCarrierId(self.object.object_id)
    }

    pub const fn source_envelope(&self) -> EnvelopeId {
        self.object.source_envelope
    }

    pub const fn blob_id(&self) -> BlobId {
        self.object.blob_id
    }

    pub const fn index(&self) -> u64 {
        self.object.index
    }

    pub const fn record(&self) -> BlobChunkRecord {
        self.expected_record
    }

    pub fn ciphertext(&self) -> &[u8] {
        &self.object.ciphertext
    }

    #[cfg(any(test, feature = "test-utils"))]
    #[doc(hidden)]
    pub fn observe_zeroize_for_test(
        mut self,
        observer: std::sync::Arc<std::sync::atomic::AtomicUsize>,
    ) -> Self {
        self.zeroize_observer = Some(observer);
        self
    }
}

impl Drop for VerifiedBlobTransferObject {
    fn drop(&mut self) {
        #[cfg(any(test, feature = "test-utils"))]
        let had_ciphertext = !self.object.ciphertext.is_empty();
        self.object.ciphertext.zeroize();
        #[cfg(any(test, feature = "test-utils"))]
        if had_ciphertext && let Some(observer) = self.zeroize_observer.take() {
            observer.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        }
    }
}

/// Nonconstructible exact transfer plan derived from a provider-authenticated
/// source Blob and its complete canonical manifest bytes.
pub struct VerifiedBlobTransferPlan {
    route: AuthenticatedBlobRoute,
    manifest: BlobManifest,
    manifest_bytes: Vec<u8>,
    manifest_digest: [u8; 32],
    physical_lineage: BlobPhysicalLineage,
    tree: BlobRouteTree,
    carrier_indexes: BTreeMap<ObjectId, u64>,
}

impl fmt::Debug for VerifiedBlobTransferPlan {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("VerifiedBlobTransferPlan")
            .field("source_envelope", &self.route.source_envelope)
            .field("blob_id", &self.manifest.id)
            .field("chunk_count", &self.manifest.chunk_count)
            .field("manifest_len", &self.manifest_bytes.len())
            .field("manifest_bytes", &"[REDACTED]")
            .field("manifest_digest", &"[REDACTED]")
            .field("physical_lineage", &self.physical_lineage)
            .finish()
    }
}

/// Proof that a provider-bound reader freshly authenticated every ciphertext,
/// AEAD tag, plaintext digest, and the whole immutable Blob.
///
/// This capability is separate from a store's physical completion marker.
/// Durable remote publication must require both.
#[derive(Clone, Copy, Eq, PartialEq)]
pub struct VerifiedBlobContentCompletion {
    mission_authority_id: NodeId,
    source_envelope: EnvelopeId,
    blob_id: BlobId,
    manifest_digest: [u8; 32],
    physical_lineage: BlobPhysicalLineage,
    chunk_count: u64,
    plaintext_bytes: u64,
}

impl fmt::Debug for VerifiedBlobContentCompletion {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("VerifiedBlobContentCompletion")
            .field("mission_authority_id", &self.mission_authority_id)
            .field("source_envelope", &self.source_envelope)
            .field("blob_id", &self.blob_id)
            .field("manifest_digest", &"[REDACTED]")
            .field("physical_lineage", &self.physical_lineage)
            .field("chunk_count", &self.chunk_count)
            .field("plaintext_bytes", &self.plaintext_bytes)
            .finish()
    }
}

impl VerifiedBlobContentCompletion {
    pub(crate) const fn new(
        mission_authority_id: NodeId,
        source_envelope: EnvelopeId,
        blob_id: BlobId,
        manifest_digest: [u8; 32],
        physical_lineage: BlobPhysicalLineage,
        chunk_count: u64,
        plaintext_bytes: u64,
    ) -> Self {
        Self {
            mission_authority_id,
            source_envelope,
            blob_id,
            manifest_digest,
            physical_lineage,
            chunk_count,
            plaintext_bytes,
        }
    }

    pub const fn mission_authority_id(&self) -> NodeId {
        self.mission_authority_id
    }

    pub const fn source_envelope(&self) -> EnvelopeId {
        self.source_envelope
    }

    pub const fn blob_id(&self) -> BlobId {
        self.blob_id
    }

    pub const fn manifest_digest(&self) -> &[u8; 32] {
        &self.manifest_digest
    }

    pub const fn physical_lineage(&self) -> BlobPhysicalLineage {
        self.physical_lineage
    }

    pub const fn chunk_count(&self) -> u64 {
        self.chunk_count
    }

    pub const fn plaintext_bytes(&self) -> u64 {
        self.plaintext_bytes
    }
}

/// Durable seam for staged digests and independently verified encrypted chunks.
///
/// `commit_verified_chunk` must atomically make the bytes and record visible, or neither. All
/// methods are idempotent for identical data and must reject conflicting data for the same key.
/// The trait deliberately does not expose plaintext persistence.
pub trait BlobStore {
    type StoreError: Error + Send + Sync + 'static;

    fn begin_blob(&mut self, manifest: &BlobManifest) -> Result<(), Self::StoreError>;

    /// Begins one physical encrypted variant with its provider-owned content lineage.
    ///
    /// Existing adapters retain source compatibility through this conservative
    /// default. Adapters which co-locate multiple same-epoch content-key lineages
    /// must override it and include `lineage` in their physical variant identity.
    fn begin_blob_with_lineage(
        &mut self,
        manifest: &BlobManifest,
        _lineage: BlobPhysicalLineage,
    ) -> Result<(), Self::StoreError> {
        self.begin_blob(manifest)
    }

    /// Selects one exact existing physical variant for authenticated reads.
    ///
    /// The conservative default preserves compatibility for adapters whose
    /// begin operation is idempotent. Durable adapters should override this
    /// hook when reads must never create storage or enter a write transaction.
    fn select_blob_for_read_with_lineage(
        &mut self,
        manifest: &BlobManifest,
        lineage: BlobPhysicalLineage,
    ) -> Result<(), Self::StoreError> {
        self.begin_blob_with_lineage(manifest, lineage)
    }
    fn put_plaintext_digest(
        &mut self,
        id: BlobId,
        index: u64,
        digest: [u8; 32],
    ) -> Result<(), Self::StoreError>;
    fn plaintext_digest(
        &mut self,
        id: BlobId,
        index: u64,
    ) -> Result<Option<[u8; 32]>, Self::StoreError>;
    fn chunk_record(
        &mut self,
        id: BlobId,
        index: u64,
    ) -> Result<Option<BlobChunkRecord>, Self::StoreError>;
    fn put_expected_chunk_record(
        &mut self,
        id: BlobId,
        index: u64,
        record: BlobChunkRecord,
    ) -> Result<(), Self::StoreError>;
    fn expected_chunk_record(
        &mut self,
        id: BlobId,
        index: u64,
    ) -> Result<Option<BlobChunkRecord>, Self::StoreError>;
    fn commit_verified_chunk(
        &mut self,
        id: BlobId,
        index: u64,
        record: BlobChunkRecord,
        ciphertext: &[u8],
    ) -> Result<(), Self::StoreError>;
    fn read_verified_chunk(
        &mut self,
        id: BlobId,
        index: u64,
        output: &mut Vec<u8>,
    ) -> Result<bool, Self::StoreError>;
    fn finalize_blob(
        &mut self,
        id: BlobId,
        manifest_digest: [u8; 32],
    ) -> Result<(), Self::StoreError>;
    fn finalized_manifest_digest(
        &mut self,
        id: BlobId,
    ) -> Result<Option<[u8; 32]>, Self::StoreError>;
}

impl<S: BlobStore + ?Sized> BlobStore for &mut S {
    type StoreError = S::StoreError;

    fn begin_blob(&mut self, manifest: &BlobManifest) -> Result<(), Self::StoreError> {
        (**self).begin_blob(manifest)
    }

    fn begin_blob_with_lineage(
        &mut self,
        manifest: &BlobManifest,
        lineage: BlobPhysicalLineage,
    ) -> Result<(), Self::StoreError> {
        (**self).begin_blob_with_lineage(manifest, lineage)
    }

    fn select_blob_for_read_with_lineage(
        &mut self,
        manifest: &BlobManifest,
        lineage: BlobPhysicalLineage,
    ) -> Result<(), Self::StoreError> {
        (**self).select_blob_for_read_with_lineage(manifest, lineage)
    }

    fn put_plaintext_digest(
        &mut self,
        id: BlobId,
        index: u64,
        digest: [u8; 32],
    ) -> Result<(), Self::StoreError> {
        (**self).put_plaintext_digest(id, index, digest)
    }

    fn plaintext_digest(
        &mut self,
        id: BlobId,
        index: u64,
    ) -> Result<Option<[u8; 32]>, Self::StoreError> {
        (**self).plaintext_digest(id, index)
    }

    fn chunk_record(
        &mut self,
        id: BlobId,
        index: u64,
    ) -> Result<Option<BlobChunkRecord>, Self::StoreError> {
        (**self).chunk_record(id, index)
    }

    fn put_expected_chunk_record(
        &mut self,
        id: BlobId,
        index: u64,
        record: BlobChunkRecord,
    ) -> Result<(), Self::StoreError> {
        (**self).put_expected_chunk_record(id, index, record)
    }

    fn expected_chunk_record(
        &mut self,
        id: BlobId,
        index: u64,
    ) -> Result<Option<BlobChunkRecord>, Self::StoreError> {
        (**self).expected_chunk_record(id, index)
    }

    fn commit_verified_chunk(
        &mut self,
        id: BlobId,
        index: u64,
        record: BlobChunkRecord,
        ciphertext: &[u8],
    ) -> Result<(), Self::StoreError> {
        (**self).commit_verified_chunk(id, index, record, ciphertext)
    }

    fn read_verified_chunk(
        &mut self,
        id: BlobId,
        index: u64,
        output: &mut Vec<u8>,
    ) -> Result<bool, Self::StoreError> {
        (**self).read_verified_chunk(id, index, output)
    }

    fn finalize_blob(
        &mut self,
        id: BlobId,
        manifest_digest: [u8; 32],
    ) -> Result<(), Self::StoreError> {
        (**self).finalize_blob(id, manifest_digest)
    }

    fn finalized_manifest_digest(
        &mut self,
        id: BlobId,
    ) -> Result<Option<[u8; 32]>, Self::StoreError> {
        (**self).finalized_manifest_digest(id)
    }
}

/// Blob processing failure without cryptographic-oracle detail.
#[derive(Debug)]
pub enum BlobError {
    Io(io::Error),
    Store(Box<dyn Error + Send + Sync>),
    InvalidChunkSize,
    InvalidMetadata,
    InvalidManifest,
    InvalidChunkIndex,
    MissingChunk,
    LengthOverflow,
    SourceChanged,
    AuthenticationFailed,
    WorkLimitZero,
}

impl Display for BlobError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(error) => write!(formatter, "blob I/O failed: {error}"),
            Self::Store(error) => write!(formatter, "blob store failed: {error}"),
            Self::InvalidChunkSize => formatter.write_str("blob chunk size is outside 4-64 KiB"),
            Self::InvalidMetadata => formatter.write_str("blob metadata is invalid"),
            Self::InvalidManifest => formatter.write_str("blob manifest is invalid"),
            Self::InvalidChunkIndex => formatter.write_str("blob chunk index is invalid"),
            Self::MissingChunk => formatter.write_str("blob chunk is not durably available"),
            Self::LengthOverflow => formatter.write_str("blob length arithmetic overflow"),
            Self::SourceChanged => formatter.write_str("blob source changed after preparation"),
            Self::AuthenticationFailed => formatter.write_str("blob authentication failed"),
            Self::WorkLimitZero => formatter.write_str("blob work limit must be nonzero"),
        }
    }
}

impl Error for BlobError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Io(error) => Some(error),
            Self::Store(error) => Some(error.as_ref()),
            _ => None,
        }
    }
}

impl From<io::Error> for BlobError {
    fn from(value: io::Error) -> Self {
        Self::Io(value)
    }
}

fn store_error(error: impl Error + Send + Sync + 'static) -> BlobError {
    BlobError::Store(Box::new(error))
}

struct BlobSecret([u8; 32]);

impl BlobSecret {
    fn expose(&self) -> &[u8; 32] {
        &self.0
    }
}

impl Drop for BlobSecret {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

pub(crate) struct BlobAccess {
    epoch_seed: BlobSecret,
    content_group: [u8; 32],
    epoch: u64,
    physical_lineage: BlobPhysicalLineage,
}

impl BlobAccess {
    #[cfg(test)]
    pub(crate) fn new(epoch_seed: [u8; 32], scope: &Scope, topic: &Topic, epoch: u64) -> Self {
        Self {
            epoch_seed: BlobSecret(epoch_seed),
            content_group: content_group_id(scope, topic),
            epoch,
            physical_lineage: BlobPhysicalLineage::from_content_grant(
                [0_u8; 32],
                scope,
                topic,
                epoch,
                &epoch_seed,
            ),
        }
    }
}

/// Progress from a bounded encryption pass.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BlobWriteProgress {
    pub verified_chunks: u64,
    pub newly_committed_chunks: u64,
    pub complete: bool,
    /// Largest byte-buffer capacity used by the core Blob engine during this call.
    ///
    /// A generic store adapter may use additional independently bounded
    /// buffers; this is not a whole-operation peak-memory measurement.
    pub peak_working_buffer_bytes: usize,
}

/// Statistics from a complete verified read.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BlobReadStats {
    pub plaintext_bytes: u64,
    pub verified_chunks: u64,
    /// Largest byte-buffer capacity used by the core Blob engine during this call.
    ///
    /// A generic store adapter may use additional independently bounded
    /// buffers; this is not a whole-operation peak-memory measurement.
    pub peak_working_buffer_bytes: usize,
}

/// Statistics from one independently authenticated bounded Blob range.
///
/// Only chunks intersecting the requested range are decrypted. The exact
/// source-authenticated manifest still binds the whole Blob, while this result
/// makes no claim that unseen plaintext chunks were re-read during this call.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BlobRangeReadStats {
    pub plaintext_bytes: u64,
    pub verified_chunks: u64,
    /// Largest byte-buffer capacity used by the core Blob engine during this call.
    pub peak_working_buffer_bytes: usize,
}

/// Bounded, canonical manifest output from an idempotent finalization pass.
#[derive(Clone, Eq, PartialEq)]
pub struct FinishedBlob {
    id: BlobId,
    manifest_bytes: Vec<u8>,
    manifest_digest: [u8; 32],
    route_commitment: BlobRouteCommitment,
}

/// Heap ownership observed while constructing a finished manifest and route.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BlobFinishMemory {
    peak_owned_bytes: usize,
    retained_manifest_bytes: usize,
    route_working_bytes: usize,
}

impl BlobFinishMemory {
    pub const fn peak_owned_bytes(self) -> usize {
        self.peak_owned_bytes
    }

    pub const fn retained_manifest_bytes(self) -> usize {
        self.retained_manifest_bytes
    }

    pub const fn route_working_bytes(self) -> usize {
        self.route_working_bytes
    }
}

impl fmt::Debug for FinishedBlob {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("FinishedBlob")
            .field("id", &self.id)
            .field("manifest_len", &self.manifest_bytes.len())
            .field("manifest_bytes", &"[REDACTED]")
            .field("manifest_digest", &"[REDACTED]")
            .field("route_commitment", &self.route_commitment)
            .finish()
    }
}

impl FinishedBlob {
    pub fn id(&self) -> BlobId {
        self.id
    }

    pub fn manifest_bytes(&self) -> &[u8] {
        &self.manifest_bytes
    }

    pub fn manifest_digest(&self) -> &[u8; 32] {
        &self.manifest_digest
    }

    /// Commitment copied into the source-authenticated protected routing
    /// descriptor when the manifest envelope is published.
    pub const fn route_commitment(&self) -> BlobRouteCommitment {
        self.route_commitment
    }

    pub fn into_manifest_bytes(self) -> Vec<u8> {
        self.manifest_bytes
    }
}

/// Canonically decoded manifest summary and commitment. This type is intentionally not sufficient
/// to construct a reader; a higher layer must authenticate the exact commitment first.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct InspectedBlobManifest {
    manifest: BlobManifest,
    manifest_digest: [u8; 32],
}

impl InspectedBlobManifest {
    pub fn manifest(&self) -> &BlobManifest {
        &self.manifest
    }

    pub fn manifest_digest(&self) -> &[u8; 32] {
        &self.manifest_digest
    }
}

/// Parses and validates an exact canonical manifest with bounded, constant working memory.
/// It does not confer source authenticity and therefore cannot directly construct a Blob reader.
pub fn inspect_blob_manifest<R: Read>(input: &mut R) -> Result<InspectedBlobManifest, BlobError> {
    parse_manifest(input, |_index, _record| Ok(()))
}

fn inspect_manifest_route<R: Read + Seek>(
    input: &mut R,
) -> Result<(InspectedBlobManifest, BlobRouteCommitment), BlobError> {
    input.seek(SeekFrom::Start(0))?;
    let inspected = parse_manifest(input, |_index, _record| Ok(()))?;
    input.seek(SeekFrom::Start(0))?;
    let mut leaves = Vec::with_capacity(
        usize::try_from(inspected.manifest.chunk_count).map_err(|_| BlobError::LengthOverflow)?,
    );
    let blob_id = inspected.manifest.id;
    let repeated = parse_manifest(input, |index, record| {
        leaves.push(route_leaf(
            blob_id,
            index,
            record.ciphertext_sha256,
            record.ciphertext_len,
        ));
        Ok(())
    })?;
    if repeated != inspected {
        return Err(BlobError::AuthenticationFailed);
    }
    let commitment = BlobRouteCommitment {
        blob_id,
        chunk_count: inspected.manifest.chunk_count,
        root: route_root(blob_id, &leaves)?,
    };
    Ok((inspected, commitment))
}

/// Parses the exact canonical selected-profile manifest and recomputes its
/// complete route commitment.
pub(crate) fn inspect_selected_blob_manifest(
    bytes: &[u8],
) -> Result<(InspectedBlobManifest, BlobRouteCommitment), BlobError> {
    if bytes.is_empty() || bytes.len() as u64 > MAX_BLOB_MANIFEST_BYTES {
        return Err(BlobError::InvalidManifest);
    }
    let mut input = io::Cursor::new(bytes);
    let (inspected, route) = inspect_manifest_route(&mut input)?;
    validate_selected_manifest(inspected.manifest())?;
    if route.blob_id != inspected.manifest.id || route.chunk_count != inspected.manifest.chunk_count
    {
        return Err(BlobError::InvalidManifest);
    }
    Ok((inspected, route))
}

#[allow(dead_code)] // Reserved for the source-envelope receive path.
pub(crate) fn install_source_authenticated_manifest<R: Read + Seek, S: BlobStore>(
    input: &mut R,
    expected: &InspectedBlobManifest,
    store: &mut S,
) -> Result<VerifiedBlobManifest, BlobError> {
    install_source_authenticated_manifest_inner(input, expected, store, None)
}

pub(crate) fn install_source_authenticated_manifest_with_lineage<R: Read + Seek, S: BlobStore>(
    input: &mut R,
    expected: &InspectedBlobManifest,
    store: &mut S,
    lineage: BlobPhysicalLineage,
) -> Result<VerifiedBlobManifest, BlobError> {
    install_source_authenticated_manifest_inner(input, expected, store, Some(lineage))
}

fn install_source_authenticated_manifest_inner<R: Read + Seek, S: BlobStore>(
    input: &mut R,
    expected: &InspectedBlobManifest,
    store: &mut S,
    lineage: Option<BlobPhysicalLineage>,
) -> Result<VerifiedBlobManifest, BlobError> {
    input.seek(SeekFrom::Start(0))?;
    let checked = parse_manifest(input, |_index, _record| Ok(()))?;
    if &checked != expected {
        return Err(BlobError::AuthenticationFailed);
    }
    match lineage {
        Some(lineage) => store
            .begin_blob_with_lineage(&checked.manifest, lineage)
            .map_err(store_error)?,
        None => store.begin_blob(&checked.manifest).map_err(store_error)?,
    }
    input.seek(SeekFrom::Start(0))?;
    let installed = parse_manifest(input, |index, record| {
        store
            .put_plaintext_digest(checked.manifest.id, index, record.plaintext_sha256)
            .map_err(store_error)?;
        store
            .put_expected_chunk_record(checked.manifest.id, index, record)
            .map_err(store_error)
    })?;
    if installed != checked {
        return Err(BlobError::AuthenticationFailed);
    }
    Ok(VerifiedBlobManifest::new(checked.manifest))
}

/// Rechecks that a durable adapter's completion marker and every retained
/// record equal one exact source-authenticated manifest.
///
/// This is deliberately keyless: storage adapters can prove completion, but
/// cannot use this seam to derive content keys or mint source authenticity.
pub(crate) fn verify_source_authenticated_store_completion<S: BlobStore + ?Sized>(
    manifest_bytes: &[u8],
    expected: &InspectedBlobManifest,
    store: &mut S,
) -> Result<(), BlobError> {
    if manifest_bytes.is_empty() || manifest_bytes.len() as u64 > MAX_BLOB_MANIFEST_BYTES {
        return Err(BlobError::InvalidManifest);
    }
    let blob_id = expected.manifest.id;
    let mut input = io::Cursor::new(manifest_bytes);
    let inspected = parse_manifest(&mut input, |index, record| {
        let expected_record = store
            .expected_chunk_record(blob_id, index)
            .map_err(store_error)?;
        let committed_record = store.chunk_record(blob_id, index).map_err(store_error)?;
        if expected_record != Some(record) || committed_record != Some(record) {
            return Err(BlobError::AuthenticationFailed);
        }
        Ok(())
    })?;
    if &inspected != expected
        || store
            .finalized_manifest_digest(blob_id)
            .map_err(store_error)?
            != Some(*expected.manifest_digest())
    {
        return Err(BlobError::AuthenticationFailed);
    }
    Ok(())
}

/// One manifest's bounded ordered Merkle tree. Every level is retained once,
/// so deriving all chunk proofs is O(n log n) rather than rebuilding the tree
/// for every chunk.
type RouteLevels = Vec<Vec<[u8; 32]>>;

struct BlobRouteTree {
    blob_id: BlobId,
    records: Vec<BlobChunkRecord>,
    levels: RouteLevels,
}

impl BlobRouteTree {
    fn build(blob_id: BlobId, records: Vec<BlobChunkRecord>) -> Result<Self, BlobError> {
        if records.len() as u64 > MAX_BLOB_CHUNKS {
            return Err(BlobError::InvalidManifest);
        }
        let leaves = records
            .iter()
            .enumerate()
            .map(|(index, record)| {
                let index = u64::try_from(index).map_err(|_| BlobError::LengthOverflow)?;
                Ok(route_leaf(
                    blob_id,
                    index,
                    record.ciphertext_sha256,
                    record.ciphertext_len,
                ))
            })
            .collect::<Result<Vec<_>, BlobError>>()?;
        let levels = build_route_levels(leaves)?;
        Ok(Self {
            blob_id,
            records,
            levels,
        })
    }

    fn from_persisted(
        blob_id: BlobId,
        records: Vec<BlobChunkRecord>,
        levels: RouteLevels,
    ) -> Result<Self, BlobError> {
        let expected = Self::build(blob_id, records)?;
        if expected.levels != levels {
            return Err(BlobError::AuthenticationFailed);
        }
        Ok(Self { levels, ..expected })
    }

    fn commitment(&self) -> Result<BlobRouteCommitment, BlobError> {
        let chunk_count =
            u64::try_from(self.records.len()).map_err(|_| BlobError::LengthOverflow)?;
        let root = self
            .levels
            .last()
            .and_then(|level| level.first())
            .copied()
            .unwrap_or_else(|| empty_route_root(self.blob_id));
        Ok(BlobRouteCommitment {
            blob_id: self.blob_id,
            chunk_count,
            root,
        })
    }

    fn record(&self, index: u64) -> Result<BlobChunkRecord, BlobError> {
        self.records
            .get(usize::try_from(index).map_err(|_| BlobError::InvalidChunkIndex)?)
            .copied()
            .ok_or(BlobError::InvalidChunkIndex)
    }

    fn proof(&self, index: u64) -> Result<Vec<[u8; 32]>, BlobError> {
        route_proof_from_levels(&self.levels, index)
    }

    fn encode_levels(&self) -> Result<Vec<u8>, BlobError> {
        let level_count = u8::try_from(self.levels.len()).map_err(|_| BlobError::LengthOverflow)?;
        let mut length = 8_usize + 2 + 32 + 8 + 1;
        for level in &self.levels {
            length = length
                .checked_add(8)
                .and_then(|value| value.checked_add(level.len().checked_mul(32)?))
                .ok_or(BlobError::LengthOverflow)?;
        }
        if u64::try_from(length).map_err(|_| BlobError::LengthOverflow)? > MAX_ROUTE_TREE_BYTES {
            return Err(BlobError::InvalidManifest);
        }
        let mut bytes = Vec::with_capacity(length);
        bytes.extend_from_slice(ROUTE_TREE_MAGIC);
        bytes.extend_from_slice(&PROTOCOL_VERSION.to_be_bytes());
        bytes.extend_from_slice(self.blob_id.as_bytes());
        bytes.extend_from_slice(
            &u64::try_from(self.records.len())
                .map_err(|_| BlobError::LengthOverflow)?
                .to_be_bytes(),
        );
        bytes.push(level_count);
        for level in &self.levels {
            bytes.extend_from_slice(
                &u64::try_from(level.len())
                    .map_err(|_| BlobError::LengthOverflow)?
                    .to_be_bytes(),
            );
            for node in level {
                bytes.extend_from_slice(node);
            }
        }
        Ok(bytes)
    }
}

impl VerifiedBlobTransferPlan {
    pub(crate) fn from_authenticated_manifest(
        route: AuthenticatedBlobRoute,
        physical_lineage: BlobPhysicalLineage,
        manifest_bytes: &[u8],
        expected: &InspectedBlobManifest,
    ) -> Result<Self, BlobError> {
        if manifest_bytes.is_empty() || manifest_bytes.len() as u64 > MAX_BLOB_MANIFEST_BYTES {
            return Err(BlobError::InvalidManifest);
        }
        let capacity = usize::try_from(expected.manifest.chunk_count)
            .map_err(|_| BlobError::LengthOverflow)?;
        let mut records = Vec::with_capacity(capacity);
        let mut input = io::Cursor::new(manifest_bytes);
        let inspected = parse_manifest(&mut input, |_index, record| {
            records.push(record);
            Ok(())
        })?;
        if &inspected != expected {
            return Err(BlobError::AuthenticationFailed);
        }
        validate_selected_manifest(inspected.manifest())?;
        let tree = BlobRouteTree::build(inspected.manifest.id, records)?;
        if tree.commitment()? != route.commitment
            || inspected.manifest.id != route.commitment.blob_id
            || inspected.manifest.chunk_count != route.commitment.chunk_count
        {
            return Err(BlobError::AuthenticationFailed);
        }

        let mut carrier_indexes = BTreeMap::new();
        for index in 0..inspected.manifest.chunk_count {
            let record = tree.record(index)?;
            let proof = tree.proof(index)?;
            let object_id = transfer_object_id(
                route.source_envelope,
                inspected.manifest.id,
                index,
                record.ciphertext_sha256,
                record.ciphertext_len,
                &proof,
            );
            if carrier_indexes.insert(object_id, index).is_some() {
                return Err(BlobError::AuthenticationFailed);
            }
        }

        Ok(Self {
            route,
            manifest: inspected.manifest,
            manifest_bytes: manifest_bytes.to_vec(),
            manifest_digest: inspected.manifest_digest,
            physical_lineage,
            tree,
            carrier_indexes,
        })
    }

    /// Source envelope and route commitment which authenticate this plan.
    pub const fn authenticated_route(&self) -> AuthenticatedBlobRoute {
        self.route
    }

    /// Stable transfer identity of the exact source envelope.
    pub const fn source_envelope(&self) -> EnvelopeId {
        self.route.source_envelope
    }

    /// Exact selected manifest authenticated by the source envelope.
    pub const fn manifest(&self) -> &BlobManifest {
        &self.manifest
    }

    /// Exact canonical manifest encoding authenticated by the source envelope.
    pub fn manifest_bytes(&self) -> &[u8] {
        &self.manifest_bytes
    }

    /// Domain-separated digest of [`Self::manifest_bytes`].
    pub const fn manifest_digest(&self) -> &[u8; 32] {
        &self.manifest_digest
    }

    /// Exact content-key lineage which produced this physical encrypted variant.
    pub const fn physical_lineage(&self) -> BlobPhysicalLineage {
        self.physical_lineage
    }

    /// Complete ordered manifest records. The slice is bounded by
    /// [`MAX_BLOB_CHUNKS`] and is suitable for one adapter-owned atomic import.
    pub fn chunk_records(&self) -> &[BlobChunkRecord] {
        &self.tree.records
    }

    /// Canonical source-bound carrier identity for one manifest index.
    pub fn carrier_id(&self, index: u64) -> Result<BlobCarrierId, BlobError> {
        let record = self.tree.record(index)?;
        let proof = self.tree.proof(index)?;
        Ok(BlobCarrierId(transfer_object_id(
            self.route.source_envelope,
            self.manifest.id,
            index,
            record.ciphertext_sha256,
            record.ciphertext_len,
            &proof,
        )))
    }

    /// Iterates every canonical carrier ID in manifest order.
    pub fn carrier_ids(&self) -> impl Iterator<Item = BlobCarrierId> + '_ {
        (0..self.manifest.chunk_count).map(|index| {
            self.carrier_id(index)
                .expect("verified plan contains every bounded manifest record")
        })
    }

    /// Resolves an exact typed wire identity to its manifest index.
    pub fn carrier_index(&self, wire_id: &[u8; BlobCarrierId::WIRE_LEN]) -> Result<u64, BlobError> {
        let object_id =
            ObjectId::from_wire_bytes(*wire_id).ok_or(BlobError::AuthenticationFailed)?;
        self.carrier_indexes
            .get(&object_id)
            .copied()
            .ok_or(BlobError::MissingChunk)
    }

    /// Exact total encoded length of a canonical carrier, without reading its
    /// ciphertext from the durable adapter.
    pub fn carrier_total_len(
        &self,
        wire_id: &[u8; BlobCarrierId::WIRE_LEN],
    ) -> Result<u64, BlobError> {
        let index = self.carrier_index(wire_id)?;
        let record = self.tree.record(index)?;
        let proof = self.tree.proof(index)?;
        let length = TRANSFER_FIXED_LEN
            .checked_add(
                proof
                    .len()
                    .checked_mul(32)
                    .ok_or(BlobError::LengthOverflow)?,
            )
            .and_then(|value| value.checked_add(record.ciphertext_len as usize))
            .ok_or(BlobError::LengthOverflow)?;
        if length > MAX_BLOB_TRANSFER_OBJECT_BYTES {
            return Err(BlobError::InvalidManifest);
        }
        u64::try_from(length).map_err(|_| BlobError::LengthOverflow)
    }

    /// Builds the stable `ASTRBT01` carrier after proving that the adapter is
    /// finalized for this exact manifest and retains the exact encrypted chunk.
    pub fn build_carrier<S: BlobStore + ?Sized>(
        &self,
        store: &mut S,
        index: u64,
    ) -> Result<BuiltBlobTransferObject, BlobError> {
        if store
            .finalized_manifest_digest(self.manifest.id)
            .map_err(store_error)?
            != Some(self.manifest_digest)
        {
            return Err(BlobError::AuthenticationFailed);
        }
        let record = self.tree.record(index)?;
        validate_record(&self.manifest, index, &record)?;
        if store
            .chunk_record(self.manifest.id, index)
            .map_err(store_error)?
            != Some(record)
            || store
                .expected_chunk_record(self.manifest.id, index)
                .map_err(store_error)?
                .is_some_and(|expected| expected != record)
        {
            return Err(BlobError::AuthenticationFailed);
        }
        let mut ciphertext = Vec::with_capacity(
            usize::try_from(record.ciphertext_len).map_err(|_| BlobError::LengthOverflow)?,
        );
        if !store
            .read_verified_chunk(self.manifest.id, index, &mut ciphertext)
            .map_err(store_error)?
        {
            return Err(BlobError::MissingChunk);
        }
        let proof = self.tree.proof(index)?;
        let bytes = encode_transfer_object(
            self.route.source_envelope,
            self.manifest.id,
            index,
            record,
            &proof,
            &ciphertext,
        )?;
        let object_id = self.carrier_id(index)?;
        if u64::try_from(bytes.len()).map_err(|_| BlobError::LengthOverflow)?
            != self.carrier_total_len(&object_id.wire_bytes())?
        {
            return Err(BlobError::AuthenticationFailed);
        }
        Ok(BuiltBlobTransferObject { object_id, bytes })
    }

    /// Reads a bounded range from the canonical carrier identified by its
    /// exact typed wire ID. The returned total is stable across peers/resumes.
    pub fn read_carrier_range<S: BlobStore + ?Sized>(
        &self,
        store: &mut S,
        wire_id: &[u8; BlobCarrierId::WIRE_LEN],
        offset: u64,
        max_bytes: usize,
    ) -> Result<(u64, Vec<u8>), BlobError> {
        let index = self.carrier_index(wire_id)?;
        let carrier = self.build_carrier(store, index)?;
        if &carrier.object_id.wire_bytes() != wire_id {
            return Err(BlobError::AuthenticationFailed);
        }
        let total = u64::try_from(carrier.bytes.len()).map_err(|_| BlobError::LengthOverflow)?;
        let start = usize::try_from(offset).map_err(|_| BlobError::LengthOverflow)?;
        if start > carrier.bytes.len() {
            return Err(BlobError::InvalidManifest);
        }
        let end = start.saturating_add(max_bytes).min(carrier.bytes.len());
        Ok((total, carrier.bytes[start..end].to_vec()))
    }

    /// Authenticates one complete carrier against this exact source, canonical
    /// proof tree, and complete manifest record.
    pub fn verify_carrier(
        &self,
        wire_id: &[u8; BlobCarrierId::WIRE_LEN],
        bytes: &[u8],
    ) -> Result<VerifiedBlobTransferObject, BlobError> {
        let index = self.carrier_index(wire_id)?;
        let object_id =
            ObjectId::from_wire_bytes(*wire_id).ok_or(BlobError::AuthenticationFailed)?;
        let object = authenticate_blob_transfer_object_for_route(object_id, bytes, self.route)?;
        let expected_record = self.tree.record(index)?;
        if object.index != index
            || object.object_id != self.carrier_id(index)?.0
            || object.ciphertext_sha256 != expected_record.ciphertext_sha256
            || object.ciphertext_len != expected_record.ciphertext_len
        {
            return Err(BlobError::AuthenticationFailed);
        }
        Ok(VerifiedBlobTransferObject {
            object,
            expected_record,
            #[cfg(any(test, feature = "test-utils"))]
            zeroize_observer: None,
        })
    }

    /// Installs one plan-verified carrier through the adapter's atomic chunk
    /// commit seam. This does not finalize or publish the Blob.
    pub fn install_verified_carrier<S: BlobStore + ?Sized>(
        &self,
        store: &mut S,
        verified: &VerifiedBlobTransferObject,
    ) -> Result<(), BlobError> {
        let index = verified.object.index;
        let expected = self.tree.record(index)?;
        if verified.object.source_envelope != self.route.source_envelope
            || verified.object.blob_id != self.manifest.id
            || verified.expected_record != expected
            || verified.object.object_id != self.carrier_id(index)?.0
        {
            return Err(BlobError::AuthenticationFailed);
        }
        store
            .put_expected_chunk_record(self.manifest.id, index, expected)
            .map_err(store_error)?;
        store
            .commit_verified_chunk(
                self.manifest.id,
                index,
                expected,
                &verified.object.ciphertext,
            )
            .map_err(store_error)
    }

    /// Rechecks every expected/committed record and the exact durable
    /// finalization digest. This proves physical completeness, not plaintext
    /// authenticity; publication also requires [`VerifiedBlobContentCompletion`].
    pub fn verify_store_completion<S: BlobStore + ?Sized>(
        &self,
        store: &mut S,
    ) -> Result<(), BlobError> {
        for (index, record) in self.tree.records.iter().copied().enumerate() {
            let index = u64::try_from(index).map_err(|_| BlobError::LengthOverflow)?;
            if store
                .expected_chunk_record(self.manifest.id, index)
                .map_err(store_error)?
                != Some(record)
                || store
                    .chunk_record(self.manifest.id, index)
                    .map_err(store_error)?
                    != Some(record)
            {
                return Err(BlobError::AuthenticationFailed);
            }
        }
        if store
            .finalized_manifest_digest(self.manifest.id)
            .map_err(store_error)?
            != Some(self.manifest_digest)
        {
            return Err(BlobError::AuthenticationFailed);
        }
        Ok(())
    }
}

fn decode_route_levels(bytes: &[u8]) -> Result<(BlobId, u64, RouteLevels), BlobError> {
    if bytes.len() as u64 > MAX_ROUTE_TREE_BYTES {
        return Err(BlobError::InvalidManifest);
    }
    let mut cursor = io::Cursor::new(bytes);
    if read_array::<8, _>(&mut cursor)? != *ROUTE_TREE_MAGIC
        || read_u16(&mut cursor)? != PROTOCOL_VERSION
    {
        return Err(BlobError::InvalidManifest);
    }
    let blob_id = BlobId(read_array(&mut cursor)?);
    let chunk_count = read_u64(&mut cursor)?;
    if chunk_count > MAX_BLOB_CHUNKS {
        return Err(BlobError::InvalidManifest);
    }
    let level_count = usize::from(read_u8(&mut cursor)?);
    let expected_level_count = if chunk_count == 0 {
        0
    } else {
        usize::try_from(u64::BITS - chunk_count.saturating_sub(1).leading_zeros() + 1)
            .map_err(|_| BlobError::LengthOverflow)?
    };
    if level_count != expected_level_count || level_count > MAX_ROUTE_PROOF_HASHES + 1 {
        return Err(BlobError::InvalidManifest);
    }
    let mut levels = Vec::with_capacity(level_count);
    let mut expected_width = chunk_count;
    for _ in 0..level_count {
        let width = read_u64(&mut cursor)?;
        if width != expected_width {
            return Err(BlobError::InvalidManifest);
        }
        let capacity = usize::try_from(width).map_err(|_| BlobError::LengthOverflow)?;
        let mut level = Vec::with_capacity(capacity);
        for _ in 0..width {
            level.push(read_array(&mut cursor)?);
        }
        levels.push(level);
        expected_width = expected_width.div_ceil(2);
    }
    if cursor.position() != bytes.len() as u64 {
        return Err(BlobError::InvalidManifest);
    }
    for (level, pair) in levels.windows(2).enumerate() {
        let level = u16::try_from(level).map_err(|_| BlobError::LengthOverflow)?;
        let expected = pair[0]
            .chunks(2)
            .map(|children| {
                if children.len() == 2 {
                    route_parent(level, children[0], children[1])
                } else {
                    children[0]
                }
            })
            .collect::<Vec<_>>();
        if expected != pair[1] {
            return Err(BlobError::AuthenticationFailed);
        }
    }
    Ok((blob_id, chunk_count, levels))
}

/// Concrete crash-durable file store. Each chunk and its integrity record share one file and become
/// visible through a same-directory atomic rename after `sync_all`, preventing record/data splits.
pub struct FileBlobStore {
    root: PathBuf,
    config: BlobStoreConfig,
    used_bytes: u64,
    used_chunks: u64,
    route_tree: Option<BlobRouteTree>,
}

impl FileBlobStore {
    /// Opens or creates a protected Blob-store root. The caller owns directory access policy.
    pub fn open(path: impl AsRef<Path>) -> Result<Self, BlobError> {
        Self::open_with_config(path, BlobStoreConfig::default())
    }

    pub fn open_with_config(
        path: impl AsRef<Path>,
        config: BlobStoreConfig,
    ) -> Result<Self, BlobError> {
        if config.max_bytes == 0 || config.max_chunks == 0 {
            return Err(BlobError::InvalidManifest);
        }
        fs::create_dir_all(path.as_ref())?;
        let (used_bytes, used_chunks) = scan_store_usage(path.as_ref())?;
        if used_bytes > config.max_bytes || used_chunks > config.max_chunks {
            return Err(BlobError::Store(Box::new(io::Error::other(
                "existing Blob store exceeds configured quota",
            ))));
        }
        Ok(Self {
            root: path.as_ref().to_path_buf(),
            config,
            used_bytes,
            used_chunks,
            route_tree: None,
        })
    }

    pub fn root(&self) -> &Path {
        &self.root
    }

    pub fn config(&self) -> BlobStoreConfig {
        self.config
    }

    pub fn quota_usage(&self) -> (u64, u64) {
        (self.used_bytes, self.used_chunks)
    }

    pub fn load_manifest(&self, id: BlobId) -> Result<Option<BlobManifest>, BlobError> {
        let path = self.blob_dir(id).join("summary.bin");
        match fs::metadata(&path) {
            Ok(metadata) if metadata.len() > MAX_STORE_SUMMARY_BYTES => {
                return Err(BlobError::InvalidManifest);
            }
            Ok(_) => {}
            Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
            Err(error) => return Err(error.into()),
        }
        match fs::read(path) {
            Ok(bytes) if bytes.len() as u64 <= MAX_STORE_SUMMARY_BYTES => {
                let manifest = decode_store_summary(&bytes)?;
                if manifest.id != id {
                    return Err(BlobError::InvalidManifest);
                }
                Ok(Some(manifest))
            }
            Ok(_) => Err(BlobError::InvalidManifest),
            Err(error) => Err(error.into()),
        }
    }

    fn route_records(&mut self, id: BlobId) -> Result<Vec<BlobChunkRecord>, BlobError> {
        let manifest = self.load_manifest(id)?.ok_or(BlobError::InvalidManifest)?;
        let count = usize::try_from(manifest.chunk_count).map_err(|_| BlobError::LengthOverflow)?;
        let mut records = Vec::with_capacity(count);
        for index in 0..manifest.chunk_count {
            let record = match self.expected_chunk_record(id, index).map_err(store_error)? {
                Some(expected) => expected,
                None => self
                    .chunk_record(id, index)
                    .map_err(store_error)?
                    .ok_or(BlobError::MissingChunk)?,
            };
            validate_record(&manifest, index, &record)?;
            records.push(record);
        }
        Ok(records)
    }

    fn ensure_route_tree(&mut self, id: BlobId) -> Result<&BlobRouteTree, BlobError> {
        if self
            .route_tree
            .as_ref()
            .is_some_and(|cached| cached.blob_id == id)
        {
            return self.route_tree.as_ref().ok_or(BlobError::InvalidManifest);
        }

        let records = self.route_records(id)?;
        let path = self.blob_dir(id).join(ROUTE_TREE_FILE);
        let tree = match fs::read(&path) {
            Ok(bytes) => {
                let (stored_id, stored_count, levels) = decode_route_levels(&bytes)?;
                if stored_id != id
                    || stored_count
                        != u64::try_from(records.len()).map_err(|_| BlobError::LengthOverflow)?
                {
                    return Err(BlobError::AuthenticationFailed);
                }
                BlobRouteTree::from_persisted(id, records, levels)?
            }
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                let tree = BlobRouteTree::build(id, records)?;
                let encoded = tree.encode_levels()?;
                self.write_object(path, &encoded, false)?;
                tree
            }
            Err(error) => return Err(error.into()),
        };
        self.route_tree = Some(tree);
        self.route_tree.as_ref().ok_or(BlobError::InvalidManifest)
    }

    /// Computes the exact ordered route commitment from authenticated
    /// manifest records (or the identical locally produced records).
    pub fn route_commitment(&mut self, id: BlobId) -> Result<BlobRouteCommitment, BlobError> {
        self.ensure_route_tree(id)?.commitment()
    }

    /// Builds one bounded canonical carrier from a locally available encrypted
    /// chunk without exposing plaintext or content keys.
    pub fn transfer_object(
        &mut self,
        source_envelope: EnvelopeId,
        id: BlobId,
        index: u64,
    ) -> Result<Vec<u8>, BlobError> {
        let manifest = self.load_manifest(id)?.ok_or(BlobError::InvalidManifest)?;
        if index >= manifest.chunk_count {
            return Err(BlobError::InvalidChunkIndex);
        }
        let (record, proof) = {
            let tree = self.ensure_route_tree(id)?;
            (tree.record(index)?, tree.proof(index)?)
        };
        let mut ciphertext = Vec::with_capacity(
            usize::try_from(record.ciphertext_len).map_err(|_| BlobError::LengthOverflow)?,
        );
        if !self
            .read_verified_chunk(id, index, &mut ciphertext)
            .map_err(store_error)?
        {
            return Err(BlobError::MissingChunk);
        }
        encode_transfer_object(source_envelope, id, index, record, &proof, &ciphertext)
    }

    fn blob_dir(&self, id: BlobId) -> PathBuf {
        self.root.join(hex_id(id))
    }

    fn indexed_path(&self, id: BlobId, index: u64, suffix: &str) -> PathBuf {
        self.blob_dir(id).join(format!("{index:020}.{suffix}"))
    }

    fn write_object(&mut self, path: PathBuf, bytes: &[u8], is_chunk: bool) -> io::Result<()> {
        match fs::read(&path) {
            Ok(existing) => {
                return if existing == bytes {
                    Ok(())
                } else {
                    Err(io::Error::new(
                        io::ErrorKind::AlreadyExists,
                        "stored object conflict",
                    ))
                };
            }
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(error) => return Err(error),
        }
        let additional_bytes = u64::try_from(bytes.len()).map_err(io::Error::other)?;
        let next_bytes = self
            .used_bytes
            .checked_add(additional_bytes)
            .ok_or_else(|| io::Error::other("Blob byte quota overflow"))?;
        let next_chunks = self
            .used_chunks
            .checked_add(u64::from(is_chunk))
            .ok_or_else(|| io::Error::other("Blob chunk quota overflow"))?;
        if next_bytes > self.config.max_bytes || next_chunks > self.config.max_chunks {
            return Err(io::Error::new(
                io::ErrorKind::StorageFull,
                "Blob store quota",
            ));
        }
        atomic_write_identical(&path, bytes)?;
        self.used_bytes = next_bytes;
        self.used_chunks = next_chunks;
        Ok(())
    }
}

impl BlobStore for FileBlobStore {
    type StoreError = io::Error;

    fn begin_blob(&mut self, manifest: &BlobManifest) -> io::Result<()> {
        if manifest.chunk_count > self.config.max_chunks {
            return Err(io::Error::new(
                io::ErrorKind::StorageFull,
                "Blob chunk quota",
            ));
        }
        let directory = self.blob_dir(manifest.id);
        fs::create_dir_all(&directory)?;
        let summary = encode_store_summary(manifest)?;
        self.write_object(directory.join("summary.bin"), &summary, false)
    }

    fn put_plaintext_digest(&mut self, id: BlobId, index: u64, digest: [u8; 32]) -> io::Result<()> {
        self.write_object(self.indexed_path(id, index, "plain"), &digest, false)
    }

    fn plaintext_digest(&mut self, id: BlobId, index: u64) -> io::Result<Option<[u8; 32]>> {
        read_fixed_optional(&self.indexed_path(id, index, "plain"))
    }

    fn chunk_record(&mut self, id: BlobId, index: u64) -> io::Result<Option<BlobChunkRecord>> {
        let path = self.indexed_path(id, index, "chunk");
        let mut file = match File::open(path) {
            Ok(file) => file,
            Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
            Err(error) => return Err(error),
        };
        decode_chunk_file_header(&mut file, index).map(Some)
    }

    fn put_expected_chunk_record(
        &mut self,
        id: BlobId,
        index: u64,
        record: BlobChunkRecord,
    ) -> io::Result<()> {
        self.write_object(
            self.indexed_path(id, index, "expected"),
            &encode_record(record),
            false,
        )
    }

    fn expected_chunk_record(
        &mut self,
        id: BlobId,
        index: u64,
    ) -> io::Result<Option<BlobChunkRecord>> {
        let path = self.indexed_path(id, index, "expected");
        match fs::read(path) {
            Ok(bytes) => decode_record(&bytes).map(Some),
            Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(None),
            Err(error) => Err(error),
        }
    }

    fn commit_verified_chunk(
        &mut self,
        id: BlobId,
        index: u64,
        record: BlobChunkRecord,
        ciphertext: &[u8],
    ) -> io::Result<()> {
        if ciphertext.len() != usize::try_from(record.ciphertext_len).map_err(io::Error::other)?
            || sha256(ciphertext) != record.ciphertext_sha256
        {
            return Err(io::Error::new(io::ErrorKind::InvalidData, "chunk mismatch"));
        }
        if let Some(expected) = self.expected_chunk_record(id, index)?
            && expected != record
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "manifest chunk record mismatch",
            ));
        }
        validate_stored_chunk_record(record)?;
        let target = self.indexed_path(id, index, "chunk");
        let mut bytes = Vec::with_capacity(8 + 8 + 72 + ciphertext.len());
        bytes.extend_from_slice(CHUNK_FILE_MAGIC);
        bytes.extend_from_slice(&index.to_be_bytes());
        bytes.extend_from_slice(&encode_record(record));
        bytes.extend_from_slice(ciphertext);
        self.write_object(target, &bytes, true)
    }

    fn read_verified_chunk(
        &mut self,
        id: BlobId,
        index: u64,
        output: &mut Vec<u8>,
    ) -> io::Result<bool> {
        let path = self.indexed_path(id, index, "chunk");
        let mut file = match File::open(path) {
            Ok(file) => file,
            Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(false),
            Err(error) => return Err(error),
        };
        let record = decode_chunk_file_header(&mut file, index)?;
        output.clear();
        output.resize(
            usize::try_from(record.ciphertext_len).map_err(io::Error::other)?,
            0,
        );
        file.read_exact(output)?;
        let mut trailing = [0u8; 1];
        if file.read(&mut trailing)? != 0 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "chunk trailing bytes",
            ));
        }
        Ok(true)
    }

    fn finalize_blob(&mut self, id: BlobId, manifest_digest: [u8; 32]) -> io::Result<()> {
        self.write_object(
            self.blob_dir(id).join("manifest.digest"),
            &manifest_digest,
            false,
        )
    }

    fn finalized_manifest_digest(&mut self, id: BlobId) -> io::Result<Option<[u8; 32]>> {
        read_fixed_optional(&self.blob_dir(id).join("manifest.digest"))
    }
}

/// Outcome of an idempotent encrypted transfer-object commit.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BlobTransferCommit {
    pub newly_stored_carrier: bool,
    pub content_chunk_committed: bool,
    pub blob_finalized: bool,
}

/// Single-buffer directory cursor for retained encrypted carriers. The cursor
/// rejects directory growth beyond the configured chunk count and aggregate
/// reads beyond the configured byte quota.
struct StoredCarrierScan {
    entries: Option<fs::ReadDir>,
    max_entries: u64,
    max_bytes: u64,
    entries_seen: u64,
    bytes_seen: u64,
    peak_buffer_bytes: usize,
}

impl StoredCarrierScan {
    fn open(root: &Path, config: BlobStoreConfig) -> Result<Self, BlobError> {
        let directory = root.join(TRANSFER_DIRECTORY);
        let entries = match fs::read_dir(directory) {
            Ok(entries) => Some(entries),
            Err(error) if error.kind() == io::ErrorKind::NotFound => None,
            Err(error) => return Err(error.into()),
        };
        Ok(Self {
            entries,
            max_entries: config.max_chunks,
            max_bytes: config.max_bytes,
            entries_seen: 0,
            bytes_seen: 0,
            peak_buffer_bytes: 0,
        })
    }

    fn next_carrier(&mut self) -> Result<Option<(ObjectId, Vec<u8>)>, BlobError> {
        let Some(entries) = &mut self.entries else {
            return Ok(None);
        };
        loop {
            let Some(entry) = entries.next() else {
                return Ok(None);
            };
            let entry = entry?;
            self.entries_seen = self
                .entries_seen
                .checked_add(1)
                .ok_or(BlobError::LengthOverflow)?;
            if self.entries_seen > self.max_entries {
                return Err(BlobError::InvalidManifest);
            }
            if !entry.file_type()?.is_file() {
                return Err(BlobError::InvalidManifest);
            }
            let name = entry
                .file_name()
                .into_string()
                .map_err(|_| BlobError::InvalidManifest)?;
            let metadata = entry.metadata()?;
            let length = metadata.len();
            self.bytes_seen = self
                .bytes_seen
                .checked_add(length)
                .ok_or(BlobError::LengthOverflow)?;
            if self.bytes_seen > self.max_bytes || length > MAX_BLOB_TRANSFER_OBJECT_BYTES as u64 {
                return Err(BlobError::InvalidManifest);
            }
            if name.starts_with(".tmp-") {
                continue;
            }
            let Some(encoded) = name.strip_suffix(".carrier") else {
                return Err(BlobError::InvalidManifest);
            };
            let object_id = object_id_from_hex(encoded)?;
            let carrier = fs::read(entry.path())?;
            if u64::try_from(carrier.len()).map_err(|_| BlobError::LengthOverflow)? != length {
                return Err(BlobError::InvalidManifest);
            }
            self.peak_buffer_bytes = self.peak_buffer_bytes.max(carrier.len());
            let inspected = inspect_blob_transfer_object(&carrier)?;
            if inspected.object_id != object_id {
                return Err(BlobError::AuthenticationFailed);
            }
            return Ok(Some((object_id, carrier)));
        }
    }
}

fn insert_bounded_id(ids: &mut BTreeSet<ObjectId>, object_id: ObjectId, limit: usize) {
    ids.insert(object_id);
    if ids.len() > limit {
        ids.pop_last();
    }
}

fn read_bounded_carrier(path: &Path) -> io::Result<Vec<u8>> {
    let length = fs::metadata(path)?.len();
    if length > MAX_BLOB_TRANSFER_OBJECT_BYTES as u64 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "transfer object length",
        ));
    }
    let bytes = fs::read(path)?;
    if u64::try_from(bytes.len()).map_err(io::Error::other)? != length {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "transfer object changed while reading",
        ));
    }
    Ok(bytes)
}

/// Crash-durable bounded store-and-forward boundary for encrypted Blob chunk
/// carriers. It verifies route proofs without content keys and only installs a
/// reader-visible chunk when an authenticated content manifest supplies the
/// exact full expected record.
pub struct BlobTransferStore {
    store: FileBlobStore,
}

impl BlobTransferStore {
    pub fn open_with_config(
        path: impl AsRef<Path>,
        config: BlobStoreConfig,
    ) -> Result<Self, BlobError> {
        Ok(Self {
            store: FileBlobStore::open_with_config(path, config)?,
        })
    }

    pub fn root(&self) -> &Path {
        self.store.root()
    }

    pub fn quota_usage(&self) -> (u64, u64) {
        self.store.quota_usage()
    }

    pub fn config(&self) -> BlobStoreConfig {
        self.store.config()
    }

    fn carrier_path(&self, object_id: ObjectId) -> PathBuf {
        self.store
            .root()
            .join(TRANSFER_DIRECTORY)
            .join(format!("{}.carrier", hex_object_id(object_id)))
    }

    /// Installs records only after the calling envelope layer authenticated the
    /// exact manifest bytes and the protected route descriptor. Repeating this
    /// after any crash is safe and completes any already-held carriers.
    pub(crate) fn install_authenticated_manifest(
        &mut self,
        bytes: &[u8],
        scope: &Scope,
        topic: &Topic,
        content_epoch: u64,
        route: AuthenticatedBlobRoute,
    ) -> Result<BlobRouteCommitment, BlobError> {
        let mut cursor = io::Cursor::new(bytes);
        let (inspected, computed) = inspect_manifest_route(&mut cursor)?;
        if computed != route.commitment
            || inspected.manifest.id != route.commitment.blob_id
            || inspected.manifest.content_group != content_group_id(scope, topic)
            || inspected.manifest.content_epoch != content_epoch
        {
            return Err(BlobError::AuthenticationFailed);
        }
        cursor.seek(SeekFrom::Start(0))?;
        install_source_authenticated_manifest(&mut cursor, &inspected, &mut self.store)?;
        self.store.write_object(
            self.store
                .blob_dir(inspected.manifest.id)
                .join("expected-manifest.digest"),
            inspected.manifest_digest(),
            false,
        )?;
        let mut carriers = StoredCarrierScan::open(self.store.root(), self.store.config())?;
        while let Some((object_id, carrier)) = carriers.next_carrier()? {
            let inspected = inspect_blob_transfer_object(&carrier)?;
            if inspected.source_envelope == route.source_envelope
                && inspected.blob_id == route.commitment.blob_id
            {
                self.commit_carrier(object_id, &carrier, route)?;
            }
        }
        let _ = self.finalize_if_complete(inspected.manifest.id)?;
        Ok(computed)
    }

    /// Verifies source association, Merkle proof, full ciphertext digest, and
    /// quota before atomically retaining a carrier. Manifest-aware consumers
    /// additionally commit the exact expected chunk; route-only relays stop at
    /// the opaque carrier and never decrypt it.
    pub fn commit_carrier(
        &mut self,
        object_id: ObjectId,
        carrier: &[u8],
        route: AuthenticatedBlobRoute,
    ) -> Result<BlobTransferCommit, BlobError> {
        let inspected = authenticate_blob_transfer_object_for_route(object_id, carrier, route)?;
        let path = self.carrier_path(object_id);
        let newly_stored_carrier = !path.exists();
        self.store.write_object(path, carrier, true)?;

        let mut content_chunk_committed = false;
        if let Some(expected) = self
            .store
            .expected_chunk_record(inspected.blob_id, inspected.index)
            .map_err(store_error)?
        {
            if expected.ciphertext_sha256 != inspected.ciphertext_sha256
                || expected.ciphertext_len != inspected.ciphertext_len
            {
                return Err(BlobError::AuthenticationFailed);
            }
            self.store
                .commit_verified_chunk(
                    inspected.blob_id,
                    inspected.index,
                    expected,
                    &inspected.ciphertext,
                )
                .map_err(store_error)?;
            content_chunk_committed = true;
        }
        let blob_finalized = self.finalize_if_complete(inspected.blob_id)?;
        Ok(BlobTransferCommit {
            newly_stored_carrier,
            content_chunk_committed,
            blob_finalized,
        })
    }

    fn finalize_if_complete(&mut self, id: BlobId) -> Result<bool, BlobError> {
        let Some(manifest) = self.store.load_manifest(id)? else {
            return Ok(false);
        };
        let Some(expected_digest) =
            read_fixed_optional::<32>(&self.store.blob_dir(id).join("expected-manifest.digest"))?
        else {
            return Ok(false);
        };
        for index in 0..manifest.chunk_count {
            let Some(expected) = self
                .store
                .expected_chunk_record(id, index)
                .map_err(store_error)?
            else {
                return Ok(false);
            };
            let Some(actual) = self.store.chunk_record(id, index).map_err(store_error)? else {
                return Ok(false);
            };
            if actual != expected {
                return Err(BlobError::AuthenticationFailed);
            }
        }
        self.store
            .finalize_blob(id, expected_digest)
            .map_err(store_error)?;
        Ok(true)
    }

    /// Lists only locally complete carrier IDs covered by the authenticated
    /// route descriptor. Results are sorted and bounded.
    pub fn object_ids_for_route(
        &mut self,
        route: AuthenticatedBlobRoute,
        limit: usize,
    ) -> Result<Vec<ObjectId>, BlobError> {
        if limit == 0 {
            return Ok(Vec::new());
        }
        let mut ids = BTreeSet::new();
        if self
            .store
            .load_manifest(route.commitment.blob_id)?
            .is_some()
            && self.store.route_commitment(route.commitment.blob_id)? == route.commitment
        {
            for index_u64 in 0..route.commitment.chunk_count {
                if self
                    .store
                    .chunk_record(route.commitment.blob_id, index_u64)
                    .map_err(store_error)?
                    .is_none()
                {
                    continue;
                }
                let (record, proof) = {
                    let tree = self.store.ensure_route_tree(route.commitment.blob_id)?;
                    (tree.record(index_u64)?, tree.proof(index_u64)?)
                };
                insert_bounded_id(
                    &mut ids,
                    transfer_object_id(
                        route.source_envelope,
                        route.commitment.blob_id,
                        index_u64,
                        record.ciphertext_sha256,
                        record.ciphertext_len,
                        &proof,
                    ),
                    limit,
                );
            }
        }
        let mut carriers = StoredCarrierScan::open(self.store.root(), self.store.config())?;
        while let Some((object_id, carrier)) = carriers.next_carrier()? {
            let inspected = inspect_blob_transfer_object(&carrier)?;
            if inspected.source_envelope == route.source_envelope
                && inspected.blob_id == route.commitment.blob_id
            {
                if !verify_route_proof(
                    route,
                    inspected.index,
                    inspected.ciphertext_sha256,
                    inspected.ciphertext_len,
                    &inspected.proof,
                ) {
                    return Err(BlobError::AuthenticationFailed);
                }
                insert_bounded_id(&mut ids, object_id, limit);
            }
        }
        Ok(ids.into_iter().collect())
    }

    /// Reads a bounded byte range from a retained carrier or deterministically
    /// reconstructs it from the local encrypted chunk store.
    pub fn read_object_range(
        &mut self,
        route: AuthenticatedBlobRoute,
        object_id: ObjectId,
        offset: u64,
        max_bytes: usize,
    ) -> Result<(u64, Vec<u8>), BlobError> {
        if max_bytes == 0 {
            return Ok((0, Vec::new()));
        }
        let path = self.carrier_path(object_id);
        let carrier = match read_bounded_carrier(&path) {
            Ok(bytes) => bytes,
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                if self.store.route_commitment(route.commitment.blob_id)? != route.commitment {
                    return Err(BlobError::AuthenticationFailed);
                }
                let mut matched = None;
                for index_u64 in 0..route.commitment.chunk_count {
                    let (record, proof) = {
                        let tree = self.store.ensure_route_tree(route.commitment.blob_id)?;
                        (tree.record(index_u64)?, tree.proof(index_u64)?)
                    };
                    let candidate = transfer_object_id(
                        route.source_envelope,
                        route.commitment.blob_id,
                        index_u64,
                        record.ciphertext_sha256,
                        record.ciphertext_len,
                        &proof,
                    );
                    if candidate == object_id {
                        matched = Some(index_u64);
                        break;
                    }
                }
                let index = matched.ok_or(BlobError::MissingChunk)?;
                self.store.transfer_object(
                    route.source_envelope,
                    route.commitment.blob_id,
                    index,
                )?
            }
            Err(error) => return Err(error.into()),
        };
        let inspected = inspect_blob_transfer_object(&carrier)?;
        if inspected.object_id != object_id
            || !verify_route_proof(
                route,
                inspected.index,
                inspected.ciphertext_sha256,
                inspected.ciphertext_len,
                &inspected.proof,
            )
        {
            return Err(BlobError::AuthenticationFailed);
        }
        let total = u64::try_from(carrier.len()).map_err(|_| BlobError::LengthOverflow)?;
        let start = usize::try_from(offset).map_err(|_| BlobError::LengthOverflow)?;
        if start > carrier.len() {
            return Err(BlobError::InvalidManifest);
        }
        let end = start.saturating_add(max_bytes).min(carrier.len());
        Ok((total, carrier[start..end].to_vec()))
    }
}

/// Authenticates an exact transfer carrier against a source-derived route
/// commitment without mutating the Blob store. Semantic runtimes use this
/// before moving a completed transport transfer into private dependency state.
pub(crate) fn authenticate_blob_transfer_object_for_route(
    object_id: ObjectId,
    carrier: &[u8],
    route: AuthenticatedBlobRoute,
) -> Result<BlobTransferObject, BlobError> {
    let inspected = inspect_blob_transfer_object(carrier)?;
    if inspected.object_id != object_id
        || inspected.source_envelope != route.source_envelope
        || inspected.blob_id != route.commitment.blob_id
        || !verify_route_proof(
            route,
            inspected.index,
            inspected.ciphertext_sha256,
            inspected.ciphertext_len,
            &inspected.proof,
        )
    {
        return Err(BlobError::AuthenticationFailed);
    }
    Ok(inspected)
}

/// High-level Blob service authorized for exactly one scope/topic/content epoch.
///
/// The provider binds an arbitrary durable [`BlobStore`] without releasing a
/// key, nonce, or algorithm control to the adapter. The default store parameter
/// preserves the legacy concrete file-backed API.
pub struct ReferenceBlobService<S = FileBlobStore> {
    store: S,
    epoch_seed: BlobSecret,
    scope: Scope,
    topic: Topic,
    content_group: [u8; 32],
    epoch: u64,
    physical_lineage: BlobPhysicalLineage,
    mission_authority_id: Option<NodeId>,
    zeroized: bool,
}

impl fmt::Debug for ReferenceBlobService {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ReferenceBlobService")
            .field("store_root", &self.store.root)
            .field("content_group", &self.content_group)
            .field("epoch", &self.epoch)
            .field("key_material", &"[REDACTED]")
            .finish()
    }
}

impl ReferenceBlobService {
    pub(crate) fn open_with_config(
        path: impl AsRef<Path>,
        epoch_seed: [u8; 32],
        scope: &Scope,
        topic: &Topic,
        epoch: u64,
        config: BlobStoreConfig,
    ) -> Result<Self, BlobError> {
        Ok(Self {
            store: FileBlobStore::open_with_config(path, config)?,
            epoch_seed: BlobSecret(epoch_seed),
            scope: scope.clone(),
            topic: topic.clone(),
            content_group: content_group_id(scope, topic),
            epoch,
            physical_lineage: BlobPhysicalLineage::from_content_grant(
                [0_u8; 32],
                scope,
                topic,
                epoch,
                &epoch_seed,
            ),
            mission_authority_id: None,
            zeroized: false,
        })
    }

    pub fn store_root(&self) -> &Path {
        self.store.root()
    }

    pub fn store_config(&self) -> BlobStoreConfig {
        self.store.config()
    }

    pub fn quota_usage(&self) -> (u64, u64) {
        self.store.quota_usage()
    }

    pub fn prepare<R: Read + Seek, D: Read + Write + Seek>(
        &mut self,
        source: &mut R,
        digest_scratch: &mut D,
        chunk_size: u32,
        metadata: BlobMetadata,
    ) -> Result<BlobManifest, BlobError> {
        let access = self.access()?;
        BlobWriter::new(&mut self.store, access).prepare(
            source,
            digest_scratch,
            chunk_size,
            metadata,
        )
    }

    /// Idempotently finalizes a fully stored Blob by its full content identifier and returns its
    /// bounded canonical manifest bytes for source authentication and transport.
    pub fn finish(&mut self, id: BlobId) -> Result<FinishedBlob, BlobError> {
        let manifest = self
            .store
            .load_manifest(id)?
            .ok_or(BlobError::InvalidManifest)?;
        if manifest.id != id {
            return Err(BlobError::InvalidManifest);
        }
        let finished = self.finish_manifest(&manifest)?;
        if self.store.route_commitment(id)? != finished.route_commitment {
            return Err(BlobError::AuthenticationFailed);
        }
        Ok(finished)
    }

    pub fn load_manifest(&self, id: BlobId) -> Result<Option<BlobManifest>, BlobError> {
        self.store.load_manifest(id)
    }

    /// Opens an owned incremental reader for a locally finalized Blob. The stored manifest
    /// commitment is recomputed before the source-authenticated marker is created.
    pub fn reader_for_local(&mut self, id: BlobId) -> Result<ReferenceBlobReader, BlobError> {
        self.ensure_live()?;
        let manifest = self
            .store
            .load_manifest(id)?
            .ok_or(BlobError::InvalidManifest)?;
        let finalized = self
            .store
            .finalized_manifest_digest(id)
            .map_err(store_error)?
            .ok_or(BlobError::InvalidManifest)?;
        let access = self.access()?;
        let recomputed =
            BlobWriter::new(&mut self.store, access).write_manifest(&manifest, &mut io::sink())?;
        if recomputed != finalized {
            return Err(BlobError::AuthenticationFailed);
        }
        let owned_store = FileBlobStore::open_with_config(self.store.root(), self.store.config())?;
        BlobReader::new(
            owned_store,
            self.access()?,
            VerifiedBlobManifest::new(manifest),
        )
    }
}

impl<S: BlobStore> ReferenceBlobService<S> {
    pub(crate) fn from_store(
        store: S,
        epoch_seed: [u8; 32],
        scope: &Scope,
        topic: &Topic,
        epoch: u64,
        mission_authority_id: NodeId,
    ) -> Self {
        Self {
            store,
            epoch_seed: BlobSecret(epoch_seed),
            scope: scope.clone(),
            topic: topic.clone(),
            content_group: content_group_id(scope, topic),
            epoch,
            physical_lineage: BlobPhysicalLineage::from_content_grant(
                mission_authority_id,
                scope,
                topic,
                epoch,
                &epoch_seed,
            ),
            mission_authority_id: Some(mission_authority_id),
            zeroized: false,
        }
    }

    /// Installs a store-independent preparation result into this exact
    /// provider-owned scope/topic/epoch service.
    ///
    /// The selected application seam requires the canonical 64 KiB chunk
    /// size. Repeating an identical installation is
    /// idempotent when the backing store follows [`BlobStore`]'s contract.
    pub fn install_prepared(&mut self, prepared: &PreparedBlob) -> Result<BlobManifest, BlobError> {
        self.ensure_live()?;
        if prepared.chunk_size != SELECTED_BLOB_CHUNK_SIZE
            || usize::try_from(prepared.chunk_count).ok() != Some(prepared.plaintext_digests.len())
        {
            return Err(BlobError::InvalidManifest);
        }
        let manifest = BlobManifest {
            id: prepared.id,
            total_len: prepared.total_len,
            chunk_size: prepared.chunk_size,
            chunk_count: prepared.chunk_count,
            whole_plaintext_sha256: prepared.whole_plaintext_sha256,
            metadata: prepared.metadata.clone(),
            content_group: self.content_group,
            content_epoch: self.epoch,
        };
        validate_selected_manifest(&manifest)?;
        self.store
            .begin_blob_with_lineage(&manifest, self.physical_lineage)
            .map_err(store_error)?;
        for (index, digest) in prepared.plaintext_digests.iter().copied().enumerate() {
            self.store
                .put_plaintext_digest(
                    manifest.id,
                    u64::try_from(index).map_err(|_| BlobError::LengthOverflow)?,
                    digest,
                )
                .map_err(store_error)?;
        }
        Ok(manifest)
    }

    pub fn encrypt_some<R: Read + Seek>(
        &mut self,
        source: &mut R,
        manifest: &BlobManifest,
        max_new_chunks: u64,
    ) -> Result<BlobWriteProgress, BlobError> {
        let access = self.access()?;
        BlobWriter::new(&mut self.store, access).encrypt_some(source, manifest, max_new_chunks)
    }

    pub fn write_manifest<W: Write>(
        &mut self,
        manifest: &BlobManifest,
        output: &mut W,
    ) -> Result<[u8; 32], BlobError> {
        let access = self.access()?;
        BlobWriter::new(&mut self.store, access).write_manifest(manifest, output)
    }

    /// Finalizes an exact caller-held manifest through any provider-bound store.
    pub fn finish_manifest(&mut self, manifest: &BlobManifest) -> Result<FinishedBlob, BlobError> {
        self.finish_manifest_measured(manifest)
            .map(|(finished, _)| finished)
    }

    /// Finalizes while reporting every heap buffer owned by manifest/route
    /// construction. Route leaves are moved into the level tree, not cloned.
    pub fn finish_manifest_measured(
        &mut self,
        manifest: &BlobManifest,
    ) -> Result<(FinishedBlob, BlobFinishMemory), BlobError> {
        let encoded_len = manifest_encoded_len(manifest)?;
        let mut manifest_bytes = Vec::with_capacity(
            usize::try_from(encoded_len).map_err(|_| BlobError::LengthOverflow)?,
        );
        let manifest_digest = self.write_manifest(manifest, &mut manifest_bytes)?;
        let mut leaves = Vec::with_capacity(
            usize::try_from(manifest.chunk_count).map_err(|_| BlobError::LengthOverflow)?,
        );
        for index in 0..manifest.chunk_count {
            let record = self
                .store
                .chunk_record(manifest.id, index)
                .map_err(store_error)?
                .ok_or(BlobError::MissingChunk)?;
            validate_record(manifest, index, &record)?;
            leaves.push(route_leaf(
                manifest.id,
                index,
                record.ciphertext_sha256,
                record.ciphertext_len,
            ));
        }
        let levels = build_route_levels(leaves)?;
        let route_working_bytes = levels
            .capacity()
            .saturating_mul(std::mem::size_of::<Vec<[u8; 32]>>())
            .saturating_add(
                levels
                    .iter()
                    .map(|level| level.capacity().saturating_mul(32))
                    .sum::<usize>(),
            );
        let route_root = if levels.is_empty() {
            empty_route_root(manifest.id)
        } else {
            levels
                .last()
                .and_then(|level| level.first())
                .copied()
                .ok_or(BlobError::InvalidManifest)?
        };
        let route_commitment = BlobRouteCommitment {
            blob_id: manifest.id,
            chunk_count: manifest.chunk_count,
            root: route_root,
        };
        if manifest_bytes.len() as u64 != encoded_len
            || manifest_bytes.len() as u64 > MAX_BLOB_MANIFEST_BYTES
        {
            return Err(BlobError::InvalidManifest);
        }
        let retained_manifest_bytes = manifest_bytes.capacity();
        let memory = BlobFinishMemory {
            peak_owned_bytes: retained_manifest_bytes.saturating_add(route_working_bytes),
            retained_manifest_bytes,
            route_working_bytes,
        };
        Ok((
            FinishedBlob {
                id: manifest.id,
                manifest_bytes,
                manifest_digest,
                route_commitment,
            },
            memory,
        ))
    }

    /// Legacy authenticated-marker reader entry point, generalized over the
    /// provider-bound store while preserving its existing signature.
    pub fn reader(
        &mut self,
        manifest: VerifiedBlobManifest,
    ) -> Result<BlobReader<&'_ mut S>, BlobError> {
        let access = self.access()?;
        BlobReader::new(&mut self.store, access, manifest)
    }

    /// Reads one exact range by authenticating only its intersecting chunks.
    ///
    /// Unlike [`Self::reader`], this operation does not walk or re-hash the
    /// plaintext prefix before `offset`. The authenticated manifest binds every
    /// chunk and the whole-Blob identity; each disclosed chunk is independently
    /// checked against its ciphertext digest, AEAD tag, and plaintext digest.
    pub fn read_range(
        &mut self,
        manifest: VerifiedBlobManifest,
        offset: u64,
        output: &mut [u8],
    ) -> Result<BlobRangeReadStats, BlobError> {
        let access = self.access()?;
        validate_manifest(manifest.manifest())?;
        if manifest.0.content_group != access.content_group
            || manifest.0.content_epoch != access.epoch
        {
            return Err(BlobError::AuthenticationFailed);
        }
        // Range reads use a fresh store adapter in the live application path.
        // Select the exact provider-owned physical variant before any indexed
        // chunk lookup; durable adapters must reject a conflicting manifest or
        // lineage rather than silently reading another import.
        self.store
            .select_blob_for_read_with_lineage(manifest.manifest(), access.physical_lineage)
            .map_err(store_error)?;
        read_verified_range(
            &mut self.store,
            &access,
            manifest.manifest(),
            offset,
            output,
        )
    }

    pub(crate) fn install_authenticated_manifest<R: Read + Seek>(
        &mut self,
        input: &mut R,
        inspected: &InspectedBlobManifest,
    ) -> Result<VerifiedBlobManifest, BlobError> {
        self.ensure_live()?;
        if inspected.manifest.content_group != self.content_group
            || inspected.manifest.content_epoch != self.epoch
        {
            return Err(BlobError::AuthenticationFailed);
        }
        install_source_authenticated_manifest_with_lineage(
            input,
            inspected,
            &mut self.store,
            self.physical_lineage,
        )
    }

    pub(crate) const fn bound_mission_authority_id(&self) -> Option<NodeId> {
        self.mission_authority_id
    }

    pub(crate) fn bind_mission_authority_id(
        &mut self,
        mission_authority_id: NodeId,
    ) -> Result<(), BlobError> {
        if self
            .mission_authority_id
            .is_some_and(|existing| existing != mission_authority_id)
        {
            return Err(BlobError::AuthenticationFailed);
        }
        self.mission_authority_id = Some(mission_authority_id);
        self.physical_lineage = BlobPhysicalLineage::from_content_grant(
            mission_authority_id,
            &self.scope,
            &self.topic,
            self.epoch,
            self.epoch_seed.expose(),
        );
        Ok(())
    }

    pub(crate) const fn bound_content_group(&self) -> &[u8; 32] {
        &self.content_group
    }

    pub(crate) const fn bound_epoch(&self) -> u64 {
        self.epoch
    }

    /// Provider-owned physical lineage bound to this exact content service.
    pub const fn physical_lineage(&self) -> BlobPhysicalLineage {
        self.physical_lineage
    }

    pub(crate) fn store_mut(&mut self) -> &mut S {
        &mut self.store
    }

    pub fn zeroize(&mut self) {
        self.epoch_seed.0.zeroize();
        self.zeroized = true;
    }

    fn access(&self) -> Result<BlobAccess, BlobError> {
        self.ensure_live()?;
        Ok(BlobAccess {
            epoch_seed: BlobSecret(*self.epoch_seed.expose()),
            content_group: self.content_group,
            epoch: self.epoch,
            physical_lineage: self.physical_lineage,
        })
    }

    fn ensure_live(&self) -> Result<(), BlobError> {
        if self.zeroized {
            Err(BlobError::AuthenticationFailed)
        } else {
            Ok(())
        }
    }
}

impl<S> Drop for ReferenceBlobService<S> {
    fn drop(&mut self) {
        self.epoch_seed.0.zeroize();
        self.zeroized = true;
    }
}

fn encode_store_summary(manifest: &BlobManifest) -> io::Result<Vec<u8>> {
    let mut bytes = Vec::new();
    bytes.extend_from_slice(STORE_SUMMARY_MAGIC);
    write_manifest_prefix(&mut bytes, manifest)?;
    bytes.extend_from_slice(&manifest.whole_plaintext_sha256);
    Ok(bytes)
}

fn decode_store_summary(bytes: &[u8]) -> Result<BlobManifest, BlobError> {
    let mut cursor = io::Cursor::new(bytes);
    if read_array::<8, _>(&mut cursor)? != *STORE_SUMMARY_MAGIC
        || read_array::<8, _>(&mut cursor)? != *MANIFEST_MAGIC
        || read_u16(&mut cursor)? != MANIFEST_VERSION
        || read_u16(&mut cursor)? != PROTOCOL_VERSION
        || read_u16(&mut cursor)? != SUITE_ID
    {
        return Err(BlobError::InvalidManifest);
    }
    let id = BlobId(read_array(&mut cursor)?);
    let total_len = read_u64(&mut cursor)?;
    let chunk_size = read_u32(&mut cursor)?;
    let chunk_count = read_u64(&mut cursor)?;
    let content_group = read_array(&mut cursor)?;
    let content_epoch = read_u64(&mut cursor)?;
    let media_type = match read_u8(&mut cursor)? {
        0 => None,
        1 => {
            let len = usize::from(read_u16(&mut cursor)?);
            if len == 0 || len > MAX_MEDIA_TYPE_LEN {
                return Err(BlobError::InvalidManifest);
            }
            let mut value = vec![0u8; len];
            cursor.read_exact(&mut value)?;
            Some(String::from_utf8(value).map_err(|_| BlobError::InvalidManifest)?)
        }
        _ => return Err(BlobError::InvalidManifest),
    };
    let schema_len = usize::from(read_u16(&mut cursor)?);
    if schema_len > MAX_SCHEMA_ID_LEN {
        return Err(BlobError::InvalidManifest);
    }
    let mut schema_id = vec![0u8; schema_len];
    cursor.read_exact(&mut schema_id)?;
    let whole_plaintext_sha256 = read_array(&mut cursor)?;
    if cursor.position() != bytes.len() as u64 {
        return Err(BlobError::InvalidManifest);
    }
    let manifest = BlobManifest {
        id,
        total_len,
        chunk_size,
        chunk_count,
        whole_plaintext_sha256,
        metadata: BlobMetadata::new(media_type, schema_id)?,
        content_group,
        content_epoch,
    };
    validate_manifest(&manifest)?;
    Ok(manifest)
}

fn encode_record(record: BlobChunkRecord) -> [u8; 72] {
    let mut bytes = [0u8; 72];
    bytes[..32].copy_from_slice(&record.plaintext_sha256);
    bytes[32..64].copy_from_slice(&record.ciphertext_sha256);
    bytes[64..68].copy_from_slice(&record.plaintext_len.to_be_bytes());
    bytes[68..72].copy_from_slice(&record.ciphertext_len.to_be_bytes());
    bytes
}

fn decode_record(bytes: &[u8]) -> io::Result<BlobChunkRecord> {
    if bytes.len() != 72 {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "record length"));
    }
    let mut plaintext_sha256 = [0u8; 32];
    plaintext_sha256.copy_from_slice(&bytes[..32]);
    let mut ciphertext_sha256 = [0u8; 32];
    ciphertext_sha256.copy_from_slice(&bytes[32..64]);
    let plaintext_len = u32::from_be_bytes(
        bytes[64..68]
            .try_into()
            .map_err(|_| io::Error::other("record decode"))?,
    );
    let ciphertext_len = u32::from_be_bytes(
        bytes[68..72]
            .try_into()
            .map_err(|_| io::Error::other("record decode"))?,
    );
    let record = BlobChunkRecord {
        plaintext_sha256,
        ciphertext_sha256,
        plaintext_len,
        ciphertext_len,
    };
    validate_stored_chunk_record(record)?;
    Ok(record)
}

fn validate_stored_chunk_record(record: BlobChunkRecord) -> io::Result<()> {
    let plaintext_len = usize::try_from(record.plaintext_len).map_err(io::Error::other)?;
    let ciphertext_len = usize::try_from(record.ciphertext_len).map_err(io::Error::other)?;
    if plaintext_len == 0
        || plaintext_len > MAX_BLOB_CHUNK_SIZE as usize
        || plaintext_len.checked_add(GCM_TAG_LEN) != Some(ciphertext_len)
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "stored chunk lengths",
        ));
    }
    Ok(())
}

fn decode_chunk_file_header(file: &mut File, expected_index: u64) -> io::Result<BlobChunkRecord> {
    let mut magic = [0u8; 8];
    file.read_exact(&mut magic)?;
    let mut index = [0u8; 8];
    file.read_exact(&mut index)?;
    let mut record = [0u8; 72];
    file.read_exact(&mut record)?;
    if magic != *CHUNK_FILE_MAGIC || u64::from_be_bytes(index) != expected_index {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "chunk header"));
    }
    decode_record(&record)
}

fn scan_store_usage(root: &Path) -> io::Result<(u64, u64)> {
    let mut used_bytes = 0u64;
    let mut used_chunks = 0u64;
    for blob_entry in fs::read_dir(root)? {
        let blob_entry = blob_entry?;
        let file_type = blob_entry.file_type()?;
        let directory_name = blob_entry
            .file_name()
            .into_string()
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "non-UTF-8 store path"))?;
        if file_type.is_dir() && directory_name == TRANSFER_DIRECTORY {
            for transfer_entry in fs::read_dir(blob_entry.path())? {
                let transfer_entry = transfer_entry?;
                if !transfer_entry.file_type()?.is_file() {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "non-file Blob transfer object",
                    ));
                }
                let name = transfer_entry.file_name().into_string().map_err(|_| {
                    io::Error::new(io::ErrorKind::InvalidData, "non-UTF-8 transfer path")
                })?;
                let metadata = transfer_entry.metadata()?;
                used_bytes = used_bytes
                    .checked_add(metadata.len())
                    .ok_or_else(|| io::Error::other("Blob usage overflow"))?;
                if name.starts_with(".tmp-") {
                    continue;
                }
                let encoded = name.strip_suffix(".carrier").ok_or_else(|| {
                    io::Error::new(io::ErrorKind::InvalidData, "transfer object name")
                })?;
                let named_id = object_id_from_hex(encoded)?;
                if metadata.len() > MAX_BLOB_TRANSFER_OBJECT_BYTES as u64 {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "transfer object length",
                    ));
                }
                let bytes = fs::read(transfer_entry.path())?;
                let inspected = inspect_blob_transfer_object(&bytes).map_err(io::Error::other)?;
                if inspected.object_id != named_id {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "transfer object identity",
                    ));
                }
                used_chunks = used_chunks
                    .checked_add(1)
                    .ok_or_else(|| io::Error::other("Blob chunk count overflow"))?;
            }
            continue;
        }
        if !file_type.is_dir() || !is_canonical_hex_id(&directory_name) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "non-canonical Blob store path",
            ));
        }
        for object_entry in fs::read_dir(blob_entry.path())? {
            let object_entry = object_entry?;
            let object_type = object_entry.file_type()?;
            if !object_type.is_file() {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "non-file Blob store object",
                ));
            }
            let object_name = object_entry
                .file_name()
                .into_string()
                .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "non-UTF-8 object path"))?;
            let metadata = object_entry.metadata()?;
            used_bytes = used_bytes
                .checked_add(metadata.len())
                .ok_or_else(|| io::Error::other("Blob usage overflow"))?;
            if object_name.starts_with(".tmp-") {
                continue;
            }
            if object_name == "summary.bin" {
                if metadata.len() > MAX_STORE_SUMMARY_BYTES {
                    return Err(io::Error::new(io::ErrorKind::InvalidData, "summary length"));
                }
                continue;
            }
            if object_name == "manifest.digest" {
                if metadata.len() != 32 {
                    return Err(io::Error::new(io::ErrorKind::InvalidData, "digest length"));
                }
                continue;
            }
            if object_name == "expected-manifest.digest" {
                if metadata.len() != 32 {
                    return Err(io::Error::new(io::ErrorKind::InvalidData, "digest length"));
                }
                continue;
            }
            if object_name == ROUTE_TREE_FILE {
                if metadata.len() > MAX_ROUTE_TREE_BYTES {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "route tree length",
                    ));
                }
                let bytes = fs::read(object_entry.path())?;
                let (stored_id, _chunk_count, _levels) =
                    decode_route_levels(&bytes).map_err(io::Error::other)?;
                if hex_id(stored_id) != directory_name {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "route tree Blob identity",
                    ));
                }
                continue;
            }
            let (index, suffix) = parse_indexed_object_name(&object_name)?;
            match suffix {
                "plain" if metadata.len() == 32 => {}
                "expected" if metadata.len() == MANIFEST_RECORD_LEN => {}
                "chunk" => {
                    let mut file = File::open(object_entry.path())?;
                    let record = decode_chunk_file_header(&mut file, index)?;
                    let expected_file_len = 8u64
                        .checked_add(8)
                        .and_then(|value| value.checked_add(MANIFEST_RECORD_LEN))
                        .and_then(|value| value.checked_add(u64::from(record.ciphertext_len)))
                        .ok_or_else(|| io::Error::other("chunk file length overflow"))?;
                    if metadata.len() != expected_file_len {
                        return Err(io::Error::new(
                            io::ErrorKind::InvalidData,
                            "chunk file length",
                        ));
                    }
                    used_chunks = used_chunks
                        .checked_add(1)
                        .ok_or_else(|| io::Error::other("Blob chunk count overflow"))?;
                }
                _ => {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "non-canonical Blob object path",
                    ));
                }
            }
        }
    }
    Ok((used_bytes, used_chunks))
}

fn is_canonical_hex_id(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn parse_indexed_object_name(value: &str) -> io::Result<(u64, &str)> {
    let (index, suffix) = value
        .split_once('.')
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "indexed object name"))?;
    if index.len() != 20 || !index.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "indexed object name",
        ));
    }
    let parsed = index
        .parse::<u64>()
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "indexed object name"))?;
    if format!("{parsed:020}") != index {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "indexed object name",
        ));
    }
    Ok((parsed, suffix))
}

fn atomic_write_identical(path: &Path, bytes: &[u8]) -> io::Result<()> {
    if let Ok(existing) = fs::read(path) {
        return if existing == bytes {
            Ok(())
        } else {
            Err(io::Error::new(
                io::ErrorKind::AlreadyExists,
                "stored object conflict",
            ))
        };
    }
    let parent = path
        .parent()
        .ok_or_else(|| io::Error::other("store path has no parent"))?;
    fs::create_dir_all(parent)?;
    let sequence = STORE_TEMP_SEQUENCE.fetch_add(1, Ordering::Relaxed);
    let temporary = parent.join(format!(".tmp-{}-{sequence}", std::process::id()));
    let mut file = OpenOptions::new()
        .create_new(true)
        .write(true)
        .open(&temporary)?;
    file.write_all(bytes)?;
    file.sync_all()?;
    match fs::rename(&temporary, path) {
        Ok(()) => {
            File::open(parent)?.sync_all()?;
            Ok(())
        }
        Err(_error) if path.exists() => {
            let _ = fs::remove_file(&temporary);
            if fs::read(path)? == bytes {
                Ok(())
            } else {
                Err(io::Error::new(
                    io::ErrorKind::AlreadyExists,
                    "stored object conflict",
                ))
            }
        }
        Err(error) => {
            let _ = fs::remove_file(&temporary);
            Err(error)
        }
    }
}

fn read_fixed_optional<const N: usize>(path: &Path) -> io::Result<Option<[u8; N]>> {
    match fs::read(path) {
        Ok(bytes) => bytes
            .try_into()
            .map(Some)
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "fixed object length")),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(error),
    }
}

fn hex_id(id: BlobId) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(64);
    for byte in id.0 {
        output.push(char::from(HEX[usize::from(byte >> 4)]));
        output.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    output
}

fn hex_object_id(id: ObjectId) -> String {
    hex_bytes(&id.to_wire_bytes())
}

fn hex_bytes(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(bytes.len().saturating_mul(2));
    for byte in bytes {
        output.push(char::from(HEX[usize::from(byte >> 4)]));
        output.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    output
}

fn object_id_from_hex(value: &str) -> io::Result<ObjectId> {
    if value.len() != ObjectId::WIRE_LEN * 2 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "transfer identifier length",
        ));
    }
    let mut bytes = [0_u8; ObjectId::WIRE_LEN];
    for (index, pair) in value.as_bytes().chunks_exact(2).enumerate() {
        let high = hex_nibble(pair[0])?;
        let low = hex_nibble(pair[1])?;
        bytes[index] = high << 4 | low;
    }
    ObjectId::from_wire_bytes(bytes)
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "transfer identifier kind"))
}

fn hex_nibble(value: u8) -> io::Result<u8> {
    match value {
        b'0'..=b'9' => Ok(value - b'0'),
        b'a'..=b'f' => Ok(value - b'a' + 10),
        _ => Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "non-canonical hexadecimal identifier",
        )),
    }
}

/// Constant-memory two-pass Blob writer backed by a durable chunk store.
pub struct BlobWriter<'a, S: BlobStore> {
    store: &'a mut S,
    access: BlobAccess,
    observed_peak_working_buffer_bytes: usize,
}

impl<'a, S: BlobStore> BlobWriter<'a, S> {
    pub(crate) fn new(store: &'a mut S, access: BlobAccess) -> Self {
        Self {
            store,
            access,
            observed_peak_working_buffer_bytes: 0,
        }
    }

    /// Largest actual `Vec` capacity observed by this writer instance.
    pub fn observed_peak_working_buffer_bytes(&self) -> usize {
        self.observed_peak_working_buffer_bytes
    }

    /// First pass: hashes a seekable source, writes only 32-byte digest records to an empty scratch
    /// object, derives BlobID, and initializes the durable store. Scratch may be a staged file.
    pub fn prepare<R: Read + Seek, D: Read + Write + Seek>(
        &mut self,
        source: &mut R,
        digest_scratch: &mut D,
        chunk_size: u32,
        metadata: BlobMetadata,
    ) -> Result<BlobManifest, BlobError> {
        validate_chunk_size(chunk_size)?;
        if digest_scratch.seek(SeekFrom::End(0))? != 0 {
            return Err(BlobError::InvalidManifest);
        }
        let original = source.stream_position()?;
        let total_len = source.seek(SeekFrom::End(0))?;
        source.seek(SeekFrom::Start(0))?;
        let chunk_count = chunk_count(total_len, chunk_size)?;
        if chunk_count > MAX_BLOB_CHUNKS {
            source.seek(SeekFrom::Start(original))?;
            return Err(BlobError::InvalidManifest);
        }

        let mut id_hasher = domain_hasher(BLOB_ID_DOMAIN);
        encode_blob_identity_prefix(
            &mut id_hasher,
            total_len,
            chunk_size,
            chunk_count,
            &metadata,
        );
        let mut whole_hasher = Sha256::new();
        let capacity = usize::try_from(chunk_size).map_err(|_| BlobError::LengthOverflow)?;
        let mut buffer = Zeroizing::new(Vec::with_capacity(capacity));
        self.observed_peak_working_buffer_bytes = self
            .observed_peak_working_buffer_bytes
            .max(buffer.capacity());
        for index in 0..chunk_count {
            let expected = expected_plaintext_len(total_len, chunk_size, chunk_count, index)?;
            read_exact_chunk(source, &mut buffer, expected)?;
            whole_hasher.update(&buffer);
            let digest = sha256(&buffer);
            id_hasher.update(digest);
            digest_scratch.write_all(&digest)?;
            buffer.zeroize();
        }
        let mut trailing = Zeroizing::new([0u8; 1]);
        if source.read(&mut trailing[..])? != 0 {
            buffer.zeroize();
            source.seek(SeekFrom::Start(original))?;
            return Err(BlobError::SourceChanged);
        }
        buffer.zeroize();
        let whole_plaintext_sha256 = finalize_sha256(whole_hasher);
        id_hasher.update(whole_plaintext_sha256);
        let id = BlobId(finalize_sha256(id_hasher));
        let manifest = BlobManifest {
            id,
            total_len,
            chunk_size,
            chunk_count,
            whole_plaintext_sha256,
            metadata,
            content_group: self.access.content_group,
            content_epoch: self.access.epoch,
        };
        self.store
            .begin_blob_with_lineage(&manifest, self.access.physical_lineage)
            .map_err(store_error)?;
        digest_scratch.seek(SeekFrom::Start(0))?;
        for index in 0..chunk_count {
            let mut digest = [0u8; 32];
            digest_scratch.read_exact(&mut digest)?;
            self.store
                .put_plaintext_digest(id, index, digest)
                .map_err(store_error)?;
        }
        source.seek(SeekFrom::Start(original))?;
        Ok(manifest)
    }

    /// Second pass: commits at most `max_new_chunks` missing chunks. Repeating this call with the
    /// same source and manifest resumes and deduplicates already committed chunks.
    pub fn encrypt_some<R: Read + Seek>(
        &mut self,
        source: &mut R,
        manifest: &BlobManifest,
        max_new_chunks: u64,
    ) -> Result<BlobWriteProgress, BlobError> {
        if max_new_chunks == 0 && manifest.chunk_count != 0 {
            return Err(BlobError::WorkLimitZero);
        }
        self.validate_access(manifest)?;
        if source.seek(SeekFrom::End(0))? != manifest.total_len {
            return Err(BlobError::SourceChanged);
        }
        let buffer_capacity = usize::try_from(manifest.chunk_size)
            .map_err(|_| BlobError::LengthOverflow)?
            .checked_add(GCM_TAG_LEN)
            .ok_or(BlobError::LengthOverflow)?;
        let mut buffer = Zeroizing::new(Vec::with_capacity(buffer_capacity));
        let mut call_peak = buffer.capacity();
        let mut verified = 0u64;
        let mut committed = 0u64;
        let mut saw_existing = false;
        for index in 0..manifest.chunk_count {
            if let Some(record) = self
                .store
                .chunk_record(manifest.id, index)
                .map_err(store_error)?
            {
                validate_record(manifest, index, &record)?;
                saw_existing = true;
                verified = verified.saturating_add(1);
                continue;
            }
            if committed >= max_new_chunks {
                continue;
            }
            let expected = manifest.plaintext_len(index)?;
            let offset = index
                .checked_mul(u64::from(manifest.chunk_size))
                .ok_or(BlobError::LengthOverflow)?;
            source.seek(SeekFrom::Start(offset))?;
            read_exact_chunk(source, &mut buffer, expected)?;
            call_peak = call_peak.max(buffer.capacity());
            let expected_digest = self
                .store
                .plaintext_digest(manifest.id, index)
                .map_err(store_error)?
                .ok_or(BlobError::InvalidManifest)?;
            if sha256(&buffer) != expected_digest {
                buffer.zeroize();
                return Err(BlobError::SourceChanged);
            }
            encrypt_chunk(&self.access, manifest, index, &mut buffer)?;
            call_peak = call_peak.max(buffer.capacity());
            let ciphertext_digest = sha256(&buffer);
            let plaintext_len = u32::try_from(expected).map_err(|_| BlobError::LengthOverflow)?;
            let ciphertext_len =
                u32::try_from(buffer.len()).map_err(|_| BlobError::LengthOverflow)?;
            let record = BlobChunkRecord {
                plaintext_sha256: expected_digest,
                ciphertext_sha256: ciphertext_digest,
                plaintext_len,
                ciphertext_len,
            };
            self.store
                .commit_verified_chunk(manifest.id, index, record, &buffer)
                .map_err(store_error)?;
            buffer.zeroize();
            committed = committed.saturating_add(1);
            verified = verified.saturating_add(1);
        }
        // A resumed/deduplicated pass which would report completion must
        // re-read every source chunk against the immutable first-pass digest
        // set. Intermediate bounded resume passes remain proportional to newly
        // committed work, while a fresh two-pass publication already checked
        // every source chunk immediately before encrypting it.
        if saw_existing && verified == manifest.chunk_count {
            for index in 0..manifest.chunk_count {
                let expected = manifest.plaintext_len(index)?;
                let offset = index
                    .checked_mul(u64::from(manifest.chunk_size))
                    .ok_or(BlobError::LengthOverflow)?;
                source.seek(SeekFrom::Start(offset))?;
                read_exact_chunk(source, &mut buffer, expected)?;
                call_peak = call_peak.max(buffer.capacity());
                let expected_digest = self
                    .store
                    .plaintext_digest(manifest.id, index)
                    .map_err(store_error)?
                    .ok_or(BlobError::InvalidManifest)?;
                if sha256(&buffer) != expected_digest {
                    buffer.zeroize();
                    return Err(BlobError::SourceChanged);
                }
                buffer.zeroize();
            }
        }
        buffer.zeroize();
        self.observed_peak_working_buffer_bytes =
            self.observed_peak_working_buffer_bytes.max(call_peak);
        Ok(BlobWriteProgress {
            verified_chunks: verified,
            newly_committed_chunks: committed,
            complete: verified == manifest.chunk_count,
            peak_working_buffer_bytes: call_peak,
        })
    }

    /// Streams the exact manifest bytes, computes its commitment, and marks the Blob finalized.
    /// The returned bytes must be source-sealed by the envelope layer before remote acceptance.
    pub fn write_manifest<W: Write>(
        &mut self,
        manifest: &BlobManifest,
        output: &mut W,
    ) -> Result<[u8; 32], BlobError> {
        self.validate_access(manifest)?;
        let mut writer = HashingWriter::new(output, MANIFEST_DIGEST_DOMAIN);
        write_manifest_prefix(&mut writer, manifest)?;
        for index in 0..manifest.chunk_count {
            let record = self
                .store
                .chunk_record(manifest.id, index)
                .map_err(store_error)?
                .ok_or(BlobError::MissingChunk)?;
            validate_record(manifest, index, &record)?;
            writer.write_all(&record.plaintext_sha256)?;
            writer.write_all(&record.ciphertext_sha256)?;
            writer.write_all(&record.plaintext_len.to_be_bytes())?;
            writer.write_all(&record.ciphertext_len.to_be_bytes())?;
        }
        writer.write_all(&manifest.whole_plaintext_sha256)?;
        let digest = writer.finish();
        self.store
            .finalize_blob(manifest.id, digest)
            .map_err(store_error)?;
        Ok(digest)
    }

    fn validate_access(&self, manifest: &BlobManifest) -> Result<(), BlobError> {
        validate_manifest(manifest)?;
        if manifest.content_group != self.access.content_group
            || manifest.content_epoch != self.access.epoch
        {
            return Err(BlobError::AuthenticationFailed);
        }
        Ok(())
    }
}

/// Marker that a higher layer authenticated the exact manifest bytes and source identity.
/// Its constructor is crate-private so unverified application input cannot create it.
#[derive(Clone, Debug)]
pub struct VerifiedBlobManifest(BlobManifest);

impl VerifiedBlobManifest {
    pub(crate) fn new(manifest: BlobManifest) -> Self {
        Self(manifest)
    }

    pub fn manifest(&self) -> &BlobManifest {
        &self.0
    }
}

/// Incremental authenticated reader over independently encrypted stored chunks.
pub struct BlobReader<S: BlobStore> {
    store: S,
    access: BlobAccess,
    manifest: VerifiedBlobManifest,
    buffer: Vec<u8>,
    buffer_offset: usize,
    next_chunk: u64,
    whole_hasher: Option<Sha256>,
    plaintext_bytes: u64,
    observed_peak_working_buffer_bytes: usize,
    complete: bool,
}

/// Owned reader returned by [`ReferenceBlobService::reader_for_local`].
pub type ReferenceBlobReader = BlobReader<FileBlobStore>;

impl<S: BlobStore> BlobReader<S> {
    pub(crate) fn new(
        store: S,
        access: BlobAccess,
        manifest: VerifiedBlobManifest,
    ) -> Result<Self, BlobError> {
        validate_manifest(manifest.manifest())?;
        if manifest.0.content_group != access.content_group
            || manifest.0.content_epoch != access.epoch
        {
            return Err(BlobError::AuthenticationFailed);
        }
        let capacity = usize::try_from(manifest.0.chunk_size)
            .map_err(|_| BlobError::LengthOverflow)?
            .checked_add(GCM_TAG_LEN)
            .ok_or(BlobError::LengthOverflow)?;
        Ok(Self {
            store,
            access,
            manifest,
            buffer: Vec::with_capacity(capacity),
            buffer_offset: 0,
            next_chunk: 0,
            whole_hasher: Some(Sha256::new()),
            plaintext_bytes: 0,
            observed_peak_working_buffer_bytes: capacity,
            complete: false,
        })
    }

    /// Copies up to `output.len()` authenticated plaintext bytes and advances the cursor. For a
    /// nonempty output slice, returns zero only after every chunk and the whole-content digest have
    /// verified.
    pub fn read_some(&mut self, output: &mut [u8]) -> Result<usize, BlobError> {
        if output.is_empty() || self.complete {
            return Ok(0);
        }
        let mut written = 0usize;
        while written < output.len() {
            if self.buffer_offset < self.buffer.len() {
                let available = self.buffer.len() - self.buffer_offset;
                let count = available.min(output.len() - written);
                output[written..written + count]
                    .copy_from_slice(&self.buffer[self.buffer_offset..self.buffer_offset + count]);
                self.buffer_offset += count;
                written += count;
                continue;
            }
            self.buffer.zeroize();
            self.buffer.clear();
            self.buffer_offset = 0;
            if self.next_chunk == self.manifest.0.chunk_count {
                self.finish_whole_digest()?;
                break;
            }
            self.load_next_chunk()?;
        }
        Ok(written)
    }

    /// Streams and verifies the complete plaintext with independently bounded core chunk and
    /// transfer buffers.
    pub fn stream_into<W: Write>(&mut self, output: &mut W) -> Result<BlobReadStats, BlobError> {
        let mut transfer = Zeroizing::new([0u8; 8192]);
        loop {
            let count = self.read_some(&mut transfer[..])?;
            if count == 0 {
                break;
            }
            output.write_all(&transfer[..count])?;
        }
        Ok(BlobReadStats {
            plaintext_bytes: self.plaintext_bytes,
            verified_chunks: self.next_chunk,
            peak_working_buffer_bytes: self.observed_peak_working_buffer_bytes,
        })
    }

    fn load_next_chunk(&mut self) -> Result<(), BlobError> {
        let result = self.load_next_chunk_inner();
        if result.is_err() {
            self.buffer.zeroize();
            self.buffer.clear();
            self.buffer_offset = 0;
        }
        result
    }

    fn load_next_chunk_inner(&mut self) -> Result<(), BlobError> {
        let manifest = &self.manifest.0;
        let index = self.next_chunk;
        read_authenticated_chunk(
            &mut self.store,
            &self.access,
            manifest,
            index,
            &mut self.buffer,
        )?;
        self.observed_peak_working_buffer_bytes = self
            .observed_peak_working_buffer_bytes
            .max(self.buffer.capacity());
        let plaintext_bytes = self
            .plaintext_bytes
            .checked_add(u64::try_from(self.buffer.len()).map_err(|_| BlobError::LengthOverflow)?)
            .ok_or(BlobError::LengthOverflow)?;
        self.whole_hasher
            .as_mut()
            .ok_or(BlobError::AuthenticationFailed)?
            .update(&self.buffer);
        self.plaintext_bytes = plaintext_bytes;
        self.next_chunk = self.next_chunk.saturating_add(1);
        Ok(())
    }

    fn finish_whole_digest(&mut self) -> Result<(), BlobError> {
        if self.complete {
            return Ok(());
        }
        let whole = self
            .whole_hasher
            .take()
            .ok_or(BlobError::AuthenticationFailed)?;
        if finalize_sha256(whole) != self.manifest.0.whole_plaintext_sha256
            || self.plaintext_bytes != self.manifest.0.total_len
        {
            return Err(BlobError::AuthenticationFailed);
        }
        self.complete = true;
        Ok(())
    }
}

impl<S: BlobStore> Drop for BlobReader<S> {
    fn drop(&mut self) {
        self.buffer.zeroize();
    }
}

fn read_verified_range<S: BlobStore>(
    store: &mut S,
    access: &BlobAccess,
    manifest: &BlobManifest,
    offset: u64,
    output: &mut [u8],
) -> Result<BlobRangeReadStats, BlobError> {
    let result = read_verified_range_inner(store, access, manifest, offset, output);
    if result.is_err() {
        output.zeroize();
    }
    result
}

fn read_verified_range_inner<S: BlobStore>(
    store: &mut S,
    access: &BlobAccess,
    manifest: &BlobManifest,
    offset: u64,
    output: &mut [u8],
) -> Result<BlobRangeReadStats, BlobError> {
    validate_manifest(manifest)?;
    let output_len = u64::try_from(output.len()).map_err(|_| BlobError::LengthOverflow)?;
    let end = offset
        .checked_add(output_len)
        .filter(|end| *end <= manifest.total_len)
        .ok_or(BlobError::InvalidChunkIndex)?;
    if output.is_empty() {
        return Ok(BlobRangeReadStats {
            plaintext_bytes: 0,
            verified_chunks: 0,
            peak_working_buffer_bytes: 0,
        });
    }
    let chunk_size = u64::from(manifest.chunk_size);
    let first_chunk = offset / chunk_size;
    let last_chunk = (end - 1) / chunk_size;
    let capacity = usize::try_from(manifest.chunk_size)
        .map_err(|_| BlobError::LengthOverflow)?
        .checked_add(GCM_TAG_LEN)
        .ok_or(BlobError::LengthOverflow)?;
    let mut buffer = Zeroizing::new(Vec::with_capacity(capacity));
    (|| {
        let mut written = 0usize;
        for index in first_chunk..=last_chunk {
            read_authenticated_chunk(store, access, manifest, index, &mut buffer)?;
            let chunk_start = index
                .checked_mul(chunk_size)
                .ok_or(BlobError::LengthOverflow)?;
            let chunk_end = chunk_start
                .checked_add(u64::try_from(buffer.len()).map_err(|_| BlobError::LengthOverflow)?)
                .ok_or(BlobError::LengthOverflow)?;
            let selected_start = offset.max(chunk_start);
            let selected_end = end.min(chunk_end);
            let source_start = usize::try_from(selected_start - chunk_start)
                .map_err(|_| BlobError::LengthOverflow)?;
            let source_end = usize::try_from(selected_end - chunk_start)
                .map_err(|_| BlobError::LengthOverflow)?;
            let count = source_end
                .checked_sub(source_start)
                .ok_or(BlobError::AuthenticationFailed)?;
            let destination_end = written
                .checked_add(count)
                .ok_or(BlobError::LengthOverflow)?;
            output
                .get_mut(written..destination_end)
                .ok_or(BlobError::AuthenticationFailed)?
                .copy_from_slice(
                    buffer
                        .get(source_start..source_end)
                        .ok_or(BlobError::AuthenticationFailed)?,
                );
            written = destination_end;
            buffer.zeroize();
            buffer.clear();
        }
        if written != output.len() {
            return Err(BlobError::AuthenticationFailed);
        }
        Ok(BlobRangeReadStats {
            plaintext_bytes: output_len,
            verified_chunks: last_chunk - first_chunk + 1,
            peak_working_buffer_bytes: buffer.capacity(),
        })
    })()
}

fn read_authenticated_chunk<S: BlobStore>(
    store: &mut S,
    access: &BlobAccess,
    manifest: &BlobManifest,
    index: u64,
    buffer: &mut Vec<u8>,
) -> Result<(), BlobError> {
    buffer.zeroize();
    buffer.clear();
    let record = store
        .chunk_record(manifest.id, index)
        .map_err(store_error)?
        .ok_or(BlobError::MissingChunk)?;
    validate_record(manifest, index, &record)?;
    if !store
        .read_verified_chunk(manifest.id, index, buffer)
        .map_err(store_error)?
    {
        return Err(BlobError::MissingChunk);
    }
    if buffer.len()
        != usize::try_from(record.ciphertext_len).map_err(|_| BlobError::LengthOverflow)?
        || sha256(buffer) != record.ciphertext_sha256
    {
        buffer.zeroize();
        return Err(BlobError::AuthenticationFailed);
    }
    decrypt_chunk(access, manifest, index, buffer)?;
    if buffer.len()
        != usize::try_from(record.plaintext_len).map_err(|_| BlobError::LengthOverflow)?
        || sha256(buffer) != record.plaintext_sha256
    {
        buffer.zeroize();
        return Err(BlobError::AuthenticationFailed);
    }
    Ok(())
}

fn validate_chunk_size(chunk_size: u32) -> Result<(), BlobError> {
    if !(MIN_BLOB_CHUNK_SIZE..=MAX_BLOB_CHUNK_SIZE).contains(&chunk_size) {
        Err(BlobError::InvalidChunkSize)
    } else {
        Ok(())
    }
}

fn chunk_count(total_len: u64, chunk_size: u32) -> Result<u64, BlobError> {
    if total_len == 0 {
        return Ok(0);
    }
    total_len
        .checked_add(u64::from(chunk_size) - 1)
        .map(|value| value / u64::from(chunk_size))
        .ok_or(BlobError::LengthOverflow)
}

fn expected_plaintext_len(
    total_len: u64,
    chunk_size: u32,
    chunk_count: u64,
    index: u64,
) -> Result<usize, BlobError> {
    if index >= chunk_count {
        return Err(BlobError::InvalidChunkIndex);
    }
    let offset = index
        .checked_mul(u64::from(chunk_size))
        .ok_or(BlobError::LengthOverflow)?;
    let remaining = total_len
        .checked_sub(offset)
        .ok_or(BlobError::LengthOverflow)?;
    usize::try_from(remaining.min(u64::from(chunk_size))).map_err(|_| BlobError::LengthOverflow)
}

fn validate_manifest(manifest: &BlobManifest) -> Result<(), BlobError> {
    validate_chunk_size(manifest.chunk_size)?;
    if chunk_count(manifest.total_len, manifest.chunk_size)? != manifest.chunk_count
        || manifest.chunk_count > MAX_BLOB_CHUNKS
        || manifest_encoded_len(manifest)? > MAX_BLOB_MANIFEST_BYTES
    {
        return Err(BlobError::InvalidManifest);
    }
    Ok(())
}

fn validate_selected_manifest(manifest: &BlobManifest) -> Result<(), BlobError> {
    validate_manifest(manifest)?;
    if manifest.chunk_size != SELECTED_BLOB_CHUNK_SIZE {
        return Err(BlobError::InvalidManifest);
    }
    Ok(())
}

fn manifest_encoded_len(manifest: &BlobManifest) -> Result<u64, BlobError> {
    let media_len = manifest
        .metadata
        .media_type
        .as_ref()
        .map_or(0u64, |value| 2 + value.len() as u64);
    MANIFEST_FIXED_LEN
        .checked_add(media_len)
        .and_then(|value| value.checked_add(manifest.metadata.schema_id.len() as u64))
        .and_then(|value| {
            manifest
                .chunk_count
                .checked_mul(MANIFEST_RECORD_LEN)
                .and_then(|records| value.checked_add(records))
        })
        .ok_or(BlobError::LengthOverflow)
}

fn validate_record(
    manifest: &BlobManifest,
    index: u64,
    record: &BlobChunkRecord,
) -> Result<(), BlobError> {
    let plaintext = manifest.plaintext_len(index)?;
    let ciphertext = plaintext
        .checked_add(GCM_TAG_LEN)
        .ok_or(BlobError::LengthOverflow)?;
    if usize::try_from(record.plaintext_len).map_err(|_| BlobError::LengthOverflow)? != plaintext
        || usize::try_from(record.ciphertext_len).map_err(|_| BlobError::LengthOverflow)?
            != ciphertext
    {
        return Err(BlobError::InvalidManifest);
    }
    Ok(())
}

fn route_leaf(blob_id: BlobId, index: u64, ciphertext: [u8; 32], len: u32) -> [u8; 32] {
    let mut hasher = domain_hasher(BLOB_ROUTE_LEAF_DOMAIN);
    hasher.update(PROTOCOL_VERSION.to_be_bytes());
    hasher.update(blob_id.as_bytes());
    hasher.update(index.to_be_bytes());
    hasher.update(ciphertext);
    hasher.update(len.to_be_bytes());
    finalize_sha256(hasher)
}

fn route_parent(level: u16, left: [u8; 32], right: [u8; 32]) -> [u8; 32] {
    let mut hasher = domain_hasher(BLOB_ROUTE_NODE_DOMAIN);
    hasher.update(PROTOCOL_VERSION.to_be_bytes());
    hasher.update(level.to_be_bytes());
    hasher.update(left);
    hasher.update(right);
    finalize_sha256(hasher)
}

fn empty_route_root(blob_id: BlobId) -> [u8; 32] {
    let mut hasher = domain_hasher(BLOB_ROUTE_EMPTY_DOMAIN);
    hasher.update(PROTOCOL_VERSION.to_be_bytes());
    hasher.update(blob_id.as_bytes());
    hasher.update(0_u64.to_be_bytes());
    finalize_sha256(hasher)
}

fn route_root(blob_id: BlobId, leaves: &[[u8; 32]]) -> Result<[u8; 32], BlobError> {
    if leaves.is_empty() {
        return Ok(empty_route_root(blob_id));
    }
    let levels = build_route_levels(leaves.to_vec())?;
    levels
        .last()
        .and_then(|level| level.first())
        .copied()
        .ok_or(BlobError::InvalidManifest)
}

fn build_route_levels(leaves: Vec<[u8; 32]>) -> Result<RouteLevels, BlobError> {
    if u64::try_from(leaves.len()).map_err(|_| BlobError::LengthOverflow)? > MAX_BLOB_CHUNKS {
        return Err(BlobError::InvalidManifest);
    }
    if leaves.is_empty() {
        return Ok(Vec::new());
    }
    let mut levels = vec![leaves];
    let mut level = 0_u16;
    while levels.last().is_some_and(|current| current.len() > 1) {
        let current = levels.last().ok_or(BlobError::InvalidManifest)?;
        let mut next = Vec::with_capacity(current.len().div_ceil(2));
        for pair in current.chunks(2) {
            next.push(if pair.len() == 2 {
                route_parent(level, pair[0], pair[1])
            } else {
                pair[0]
            });
        }
        levels.push(next);
        level = level.checked_add(1).ok_or(BlobError::LengthOverflow)?;
        if levels.len() > MAX_ROUTE_PROOF_HASHES + 1 {
            return Err(BlobError::InvalidManifest);
        }
    }
    Ok(levels)
}

fn route_proof_from_levels(
    levels: &[Vec<[u8; 32]>],
    index: u64,
) -> Result<Vec<[u8; 32]>, BlobError> {
    let mut position = usize::try_from(index).map_err(|_| BlobError::InvalidChunkIndex)?;
    if levels.is_empty() || position >= levels[0].len() {
        return Err(BlobError::InvalidChunkIndex);
    }
    let mut proof = Vec::with_capacity(MAX_ROUTE_PROOF_HASHES);
    for current in levels.iter().take(levels.len().saturating_sub(1)) {
        let sibling = if position & 1 == 0 {
            position
                .checked_add(1)
                .filter(|value| *value < current.len())
        } else {
            Some(position - 1)
        };
        if let Some(sibling) = sibling {
            proof.push(current[sibling]);
        }
        if proof.len() > MAX_ROUTE_PROOF_HASHES {
            return Err(BlobError::InvalidManifest);
        }
        position /= 2;
    }
    Ok(proof)
}

fn verify_route_proof(
    route: AuthenticatedBlobRoute,
    index: u64,
    ciphertext_sha256: [u8; 32],
    ciphertext_len: u32,
    proof: &[[u8; 32]],
) -> bool {
    let commitment = route.commitment;
    if index >= commitment.chunk_count || proof.len() > MAX_ROUTE_PROOF_HASHES {
        return false;
    }
    let mut current = route_leaf(commitment.blob_id, index, ciphertext_sha256, ciphertext_len);
    let mut position = index;
    let mut width = commitment.chunk_count;
    let mut proof_index = 0_usize;
    let mut level = 0_u16;
    while width > 1 {
        let has_sibling = position & 1 == 1 || position.saturating_add(1) < width;
        if has_sibling {
            let Some(sibling) = proof.get(proof_index).copied() else {
                return false;
            };
            proof_index += 1;
            current = if position & 1 == 0 {
                route_parent(level, current, sibling)
            } else {
                route_parent(level, sibling, current)
            };
        }
        position /= 2;
        width = width.div_ceil(2);
        let Some(next) = level.checked_add(1) else {
            return false;
        };
        level = next;
    }
    proof_index == proof.len() && current == commitment.root
}

fn transfer_object_id(
    source_envelope: EnvelopeId,
    blob_id: BlobId,
    index: u64,
    ciphertext_sha256: [u8; 32],
    ciphertext_len: u32,
    proof: &[[u8; 32]],
) -> ObjectId {
    let mut hasher = domain_hasher(BLOB_TRANSFER_ID_DOMAIN);
    hasher.update(PROTOCOL_VERSION.to_be_bytes());
    hasher.update(source_envelope.as_bytes());
    hasher.update(blob_id.as_bytes());
    hasher.update(index.to_be_bytes());
    hasher.update(ciphertext_sha256);
    hasher.update(ciphertext_len.to_be_bytes());
    hasher.update([proof.len() as u8]);
    for sibling in proof {
        hasher.update(sibling);
    }
    ObjectId::for_blob_chunk_digest(finalize_sha256(hasher))
}

fn encode_transfer_object(
    source_envelope: EnvelopeId,
    blob_id: BlobId,
    index: u64,
    record: BlobChunkRecord,
    proof: &[[u8; 32]],
    ciphertext: &[u8],
) -> Result<Vec<u8>, BlobError> {
    if proof.len() > MAX_ROUTE_PROOF_HASHES
        || ciphertext.len()
            != usize::try_from(record.ciphertext_len).map_err(|_| BlobError::LengthOverflow)?
        || sha256(ciphertext) != record.ciphertext_sha256
    {
        return Err(BlobError::AuthenticationFailed);
    }
    let proof_len = proof
        .len()
        .checked_mul(32)
        .ok_or(BlobError::LengthOverflow)?;
    let capacity = TRANSFER_FIXED_LEN
        .checked_add(proof_len)
        .and_then(|value| value.checked_add(ciphertext.len()))
        .ok_or(BlobError::LengthOverflow)?;
    let mut bytes = Vec::with_capacity(capacity);
    bytes.extend_from_slice(TRANSFER_MAGIC);
    bytes.extend_from_slice(&PROTOCOL_VERSION.to_be_bytes());
    bytes.extend_from_slice(source_envelope.as_bytes());
    bytes.extend_from_slice(blob_id.as_bytes());
    bytes.extend_from_slice(&index.to_be_bytes());
    bytes.extend_from_slice(&record.ciphertext_sha256);
    bytes.extend_from_slice(&record.ciphertext_len.to_be_bytes());
    bytes.push(u8::try_from(proof.len()).map_err(|_| BlobError::LengthOverflow)?);
    for sibling in proof {
        bytes.extend_from_slice(sibling);
    }
    bytes.extend_from_slice(ciphertext);
    debug_assert_eq!(bytes.len(), capacity);
    Ok(bytes)
}

/// Parses, bounds, and content-address-verifies a complete Blob transfer
/// object. Route authorization is a separate required step.
pub fn inspect_blob_transfer_object(bytes: &[u8]) -> Result<BlobTransferObject, BlobError> {
    let maximum = TRANSFER_FIXED_LEN
        .checked_add(MAX_ROUTE_PROOF_HASHES * 32)
        .and_then(|value| value.checked_add(MAX_BLOB_CHUNK_SIZE as usize + GCM_TAG_LEN))
        .ok_or(BlobError::LengthOverflow)?;
    if bytes.len() < TRANSFER_FIXED_LEN || bytes.len() > maximum {
        return Err(BlobError::InvalidManifest);
    }
    let mut cursor = io::Cursor::new(bytes);
    if read_array::<8, _>(&mut cursor)? != *TRANSFER_MAGIC
        || read_u16(&mut cursor)? != PROTOCOL_VERSION
    {
        return Err(BlobError::InvalidManifest);
    }
    let source_envelope = EnvelopeId::from_bytes(read_array(&mut cursor)?);
    let blob_id = BlobId(read_array(&mut cursor)?);
    let index = read_u64(&mut cursor)?;
    if index >= MAX_BLOB_CHUNKS {
        return Err(BlobError::InvalidChunkIndex);
    }
    let ciphertext_sha256 = read_array(&mut cursor)?;
    let ciphertext_len = read_u32(&mut cursor)?;
    if !(GCM_TAG_LEN as u32 + 1..=MAX_BLOB_CHUNK_SIZE + GCM_TAG_LEN as u32)
        .contains(&ciphertext_len)
    {
        return Err(BlobError::InvalidManifest);
    }
    let proof_count = usize::from(read_u8(&mut cursor)?);
    if proof_count > MAX_ROUTE_PROOF_HASHES {
        return Err(BlobError::InvalidManifest);
    }
    let mut proof = Vec::with_capacity(proof_count);
    for _ in 0..proof_count {
        proof.push(read_array(&mut cursor)?);
    }
    let position = usize::try_from(cursor.position()).map_err(|_| BlobError::LengthOverflow)?;
    let ciphertext = bytes
        .get(position..)
        .ok_or(BlobError::InvalidManifest)?
        .to_vec();
    if ciphertext.len() != usize::try_from(ciphertext_len).map_err(|_| BlobError::LengthOverflow)?
        || sha256(&ciphertext) != ciphertext_sha256
    {
        return Err(BlobError::AuthenticationFailed);
    }
    Ok(BlobTransferObject {
        object_id: transfer_object_id(
            source_envelope,
            blob_id,
            index,
            ciphertext_sha256,
            ciphertext_len,
            &proof,
        ),
        source_envelope,
        blob_id,
        index,
        ciphertext_sha256,
        ciphertext_len,
        proof,
        ciphertext,
    })
}

fn read_exact_chunk<R: Read>(
    source: &mut R,
    buffer: &mut Vec<u8>,
    expected: usize,
) -> Result<(), BlobError> {
    buffer.clear();
    buffer.resize(expected, 0);
    source.read_exact(buffer)?;
    Ok(())
}

pub(crate) fn content_group_id(scope: &Scope, topic: &Topic) -> [u8; 32] {
    let mut hasher = domain_hasher(CONTENT_GROUP_DOMAIN);
    let input_len = scope
        .as_str()
        .len()
        .saturating_add(1)
        .saturating_add(topic.as_str().len());
    hasher.update((input_len as u64).to_be_bytes());
    hasher.update(scope.as_str().as_bytes());
    hasher.update([0]);
    hasher.update(topic.as_str().as_bytes());
    finalize_sha256(hasher)
}

fn encode_blob_identity_prefix(
    hasher: &mut Sha256,
    total_len: u64,
    chunk_size: u32,
    chunk_count: u64,
    metadata: &BlobMetadata,
) {
    hasher.update(MANIFEST_VERSION.to_be_bytes());
    hasher.update(total_len.to_be_bytes());
    hasher.update(chunk_size.to_be_bytes());
    hasher.update(chunk_count.to_be_bytes());
    match &metadata.media_type {
        Some(value) => {
            hasher.update([1]);
            hasher.update((value.len() as u64).to_be_bytes());
            hasher.update(value.as_bytes());
        }
        None => hasher.update([0]),
    }
    hasher.update((metadata.schema_id.len() as u64).to_be_bytes());
    hasher.update(&metadata.schema_id);
}

fn derive_chunk_material<const N: usize>(
    seed: &[u8; 32],
    label: &[u8],
    blob_id: BlobId,
    index: u64,
) -> Result<[u8; N], BlobError> {
    let mut context = Vec::with_capacity(32 + 8);
    context.extend_from_slice(blob_id.as_bytes());
    context.extend_from_slice(&index.to_be_bytes());
    let mut info = Vec::with_capacity(2 + label.len() + 4 + context.len());
    let label_len = u16::try_from(label.len()).map_err(|_| BlobError::LengthOverflow)?;
    let context_len = u32::try_from(context.len()).map_err(|_| BlobError::LengthOverflow)?;
    info.extend_from_slice(&label_len.to_be_bytes());
    info.extend_from_slice(label);
    info.extend_from_slice(&context_len.to_be_bytes());
    info.extend_from_slice(&context);
    let hkdf = Hkdf::<Sha256>::new(Some(BLOB_KDF_SALT), seed);
    let mut output = [0u8; N];
    hkdf.expand(&info, &mut output)
        .map_err(|_| BlobError::AuthenticationFailed)?;
    info.zeroize();
    context.zeroize();
    Ok(output)
}

fn chunk_aad(manifest: &BlobManifest, index: u64, plaintext_len: usize) -> Vec<u8> {
    let mut aad = Vec::with_capacity(CHUNK_AAD_DOMAIN.len() + 2 + 2 + 32 + 32 + 8 + 8 + 8);
    aad.extend_from_slice(CHUNK_AAD_DOMAIN);
    aad.extend_from_slice(&PROTOCOL_VERSION.to_be_bytes());
    aad.extend_from_slice(&SUITE_ID.to_be_bytes());
    aad.extend_from_slice(manifest.id.as_bytes());
    aad.extend_from_slice(&manifest.content_group);
    aad.extend_from_slice(&manifest.content_epoch.to_be_bytes());
    aad.extend_from_slice(&index.to_be_bytes());
    aad.extend_from_slice(&(plaintext_len as u64).to_be_bytes());
    aad
}

fn encrypt_chunk(
    access: &BlobAccess,
    manifest: &BlobManifest,
    index: u64,
    buffer: &mut Vec<u8>,
) -> Result<(), BlobError> {
    let plaintext_len = buffer.len();
    let mut key = derive_chunk_material::<32>(
        access.epoch_seed.expose(),
        CHUNK_KEY_LABEL,
        manifest.id,
        index,
    )?;
    let mut nonce = derive_chunk_material::<NONCE_LEN>(
        access.epoch_seed.expose(),
        CHUNK_NONCE_LABEL,
        manifest.id,
        index,
    )?;
    let mut key_array = Array(key);
    let cipher = Aes256Gcm::new(&key_array);
    key_array.as_mut_slice().zeroize();
    key.zeroize();
    let nonce_array = Array(nonce);
    let aad = chunk_aad(manifest, index, plaintext_len);
    cipher
        .encrypt_in_place(&nonce_array, &aad, buffer)
        .map_err(|_| BlobError::AuthenticationFailed)?;
    nonce.zeroize();
    Ok(())
}

fn decrypt_chunk(
    access: &BlobAccess,
    manifest: &BlobManifest,
    index: u64,
    buffer: &mut Vec<u8>,
) -> Result<(), BlobError> {
    let plaintext_len = manifest.plaintext_len(index)?;
    let mut key = derive_chunk_material::<32>(
        access.epoch_seed.expose(),
        CHUNK_KEY_LABEL,
        manifest.id,
        index,
    )?;
    let mut nonce = derive_chunk_material::<NONCE_LEN>(
        access.epoch_seed.expose(),
        CHUNK_NONCE_LABEL,
        manifest.id,
        index,
    )?;
    let mut key_array = Array(key);
    let cipher = Aes256Gcm::new(&key_array);
    key_array.as_mut_slice().zeroize();
    key.zeroize();
    let nonce_array = Array(nonce);
    let aad = chunk_aad(manifest, index, plaintext_len);
    let result = cipher
        .decrypt_in_place(&nonce_array, &aad, buffer)
        .map_err(|_| BlobError::AuthenticationFailed);
    nonce.zeroize();
    result
}

fn write_manifest_prefix<W: Write>(writer: &mut W, manifest: &BlobManifest) -> io::Result<()> {
    writer.write_all(MANIFEST_MAGIC)?;
    writer.write_all(&MANIFEST_VERSION.to_be_bytes())?;
    writer.write_all(&PROTOCOL_VERSION.to_be_bytes())?;
    writer.write_all(&SUITE_ID.to_be_bytes())?;
    writer.write_all(manifest.id.as_bytes())?;
    writer.write_all(&manifest.total_len.to_be_bytes())?;
    writer.write_all(&manifest.chunk_size.to_be_bytes())?;
    writer.write_all(&manifest.chunk_count.to_be_bytes())?;
    writer.write_all(&manifest.content_group)?;
    writer.write_all(&manifest.content_epoch.to_be_bytes())?;
    match &manifest.metadata.media_type {
        Some(value) => {
            writer.write_all(&[1])?;
            writer.write_all(&(value.len() as u16).to_be_bytes())?;
            writer.write_all(value.as_bytes())?;
        }
        None => writer.write_all(&[0])?,
    }
    writer.write_all(&(manifest.metadata.schema_id.len() as u16).to_be_bytes())?;
    writer.write_all(&manifest.metadata.schema_id)
}

fn parse_manifest<R: Read>(
    input: &mut R,
    mut on_record: impl FnMut(u64, BlobChunkRecord) -> Result<(), BlobError>,
) -> Result<InspectedBlobManifest, BlobError> {
    let mut reader = HashingReader::new(input, MANIFEST_DIGEST_DOMAIN);
    if read_array::<8, _>(&mut reader)? != *MANIFEST_MAGIC
        || read_u16(&mut reader)? != MANIFEST_VERSION
        || read_u16(&mut reader)? != PROTOCOL_VERSION
        || read_u16(&mut reader)? != SUITE_ID
    {
        return Err(BlobError::InvalidManifest);
    }
    let id = BlobId(read_array(&mut reader)?);
    let total_len = read_u64(&mut reader)?;
    let chunk_size = read_u32(&mut reader)?;
    let chunk_count = read_u64(&mut reader)?;
    let content_group = read_array(&mut reader)?;
    let content_epoch = read_u64(&mut reader)?;
    validate_chunk_size(chunk_size)?;
    if chunk_count != chunk_count_for_manifest(total_len, chunk_size)?
        || chunk_count > MAX_BLOB_CHUNKS
    {
        return Err(BlobError::InvalidManifest);
    }
    let media_type = match read_u8(&mut reader)? {
        0 => None,
        1 => {
            let len = usize::from(read_u16(&mut reader)?);
            if len == 0 || len > MAX_MEDIA_TYPE_LEN {
                return Err(BlobError::InvalidManifest);
            }
            let mut bytes = vec![0u8; len];
            reader.read_exact(&mut bytes)?;
            Some(String::from_utf8(bytes).map_err(|_| BlobError::InvalidManifest)?)
        }
        _ => return Err(BlobError::InvalidManifest),
    };
    let schema_len = usize::from(read_u16(&mut reader)?);
    if schema_len > MAX_SCHEMA_ID_LEN {
        return Err(BlobError::InvalidManifest);
    }
    let mut schema_id = vec![0u8; schema_len];
    reader.read_exact(&mut schema_id)?;
    let metadata = BlobMetadata::new(media_type, schema_id)?;
    let minimum_len = reader
        .count()
        .checked_add(
            chunk_count
                .checked_mul(MANIFEST_RECORD_LEN)
                .ok_or(BlobError::LengthOverflow)?,
        )
        .and_then(|value| value.checked_add(32))
        .ok_or(BlobError::LengthOverflow)?;
    if minimum_len > MAX_BLOB_MANIFEST_BYTES {
        return Err(BlobError::InvalidManifest);
    }
    let mut id_hasher = domain_hasher(BLOB_ID_DOMAIN);
    encode_blob_identity_prefix(
        &mut id_hasher,
        total_len,
        chunk_size,
        chunk_count,
        &metadata,
    );
    for index in 0..chunk_count {
        let record = BlobChunkRecord {
            plaintext_sha256: read_array(&mut reader)?,
            ciphertext_sha256: read_array(&mut reader)?,
            plaintext_len: read_u32(&mut reader)?,
            ciphertext_len: read_u32(&mut reader)?,
        };
        let placeholder = BlobManifest {
            id,
            total_len,
            chunk_size,
            chunk_count,
            whole_plaintext_sha256: [0u8; 32],
            metadata: metadata.clone(),
            content_group,
            content_epoch,
        };
        validate_record(&placeholder, index, &record)?;
        id_hasher.update(record.plaintext_sha256);
        on_record(index, record)?;
    }
    let whole_plaintext_sha256 = read_array(&mut reader)?;
    id_hasher.update(whole_plaintext_sha256);
    if BlobId(finalize_sha256(id_hasher)) != id {
        return Err(BlobError::InvalidManifest);
    }
    let mut trailing = [0u8; 1];
    if reader.read(&mut trailing)? != 0 {
        return Err(BlobError::InvalidManifest);
    }
    let (manifest_digest, count) = reader.finish();
    if count != minimum_len {
        return Err(BlobError::InvalidManifest);
    }
    let manifest = BlobManifest {
        id,
        total_len,
        chunk_size,
        chunk_count,
        whole_plaintext_sha256,
        metadata,
        content_group,
        content_epoch,
    };
    validate_manifest(&manifest)?;
    Ok(InspectedBlobManifest {
        manifest,
        manifest_digest,
    })
}

fn chunk_count_for_manifest(total_len: u64, chunk_size: u32) -> Result<u64, BlobError> {
    chunk_count(total_len, chunk_size)
}

fn read_array<const N: usize, R: Read>(reader: &mut R) -> Result<[u8; N], BlobError> {
    let mut output = [0u8; N];
    reader.read_exact(&mut output)?;
    Ok(output)
}

fn read_u8<R: Read>(reader: &mut R) -> Result<u8, BlobError> {
    Ok(read_array::<1, _>(reader)?[0])
}

fn read_u16<R: Read>(reader: &mut R) -> Result<u16, BlobError> {
    Ok(u16::from_be_bytes(read_array(reader)?))
}

fn read_u32<R: Read>(reader: &mut R) -> Result<u32, BlobError> {
    Ok(u32::from_be_bytes(read_array(reader)?))
}

fn read_u64<R: Read>(reader: &mut R) -> Result<u64, BlobError> {
    Ok(u64::from_be_bytes(read_array(reader)?))
}

struct HashingReader<'a, R> {
    input: &'a mut R,
    hasher: Sha256,
    count: u64,
}

impl<'a, R: Read> HashingReader<'a, R> {
    fn new(input: &'a mut R, domain: &[u8]) -> Self {
        Self {
            input,
            hasher: domain_hasher(domain),
            count: 0,
        }
    }

    fn count(&self) -> u64 {
        self.count
    }

    fn finish(self) -> ([u8; 32], u64) {
        (finalize_sha256(self.hasher), self.count)
    }
}

impl<R: Read> Read for HashingReader<'_, R> {
    fn read(&mut self, output: &mut [u8]) -> io::Result<usize> {
        let count = self.input.read(output)?;
        self.hasher.update(&output[..count]);
        self.count = self
            .count
            .checked_add(u64::try_from(count).map_err(io::Error::other)?)
            .ok_or_else(|| io::Error::other("manifest length overflow"))?;
        Ok(count)
    }
}

struct HashingWriter<'a, W> {
    output: &'a mut W,
    hasher: Sha256,
}

impl<'a, W: Write> HashingWriter<'a, W> {
    fn new(output: &'a mut W, domain: &[u8]) -> Self {
        Self {
            output,
            hasher: domain_hasher(domain),
        }
    }

    fn finish(self) -> [u8; 32] {
        finalize_sha256(self.hasher)
    }
}

impl<W: Write> Write for HashingWriter<'_, W> {
    fn write(&mut self, buffer: &[u8]) -> io::Result<usize> {
        let count = self.output.write(buffer)?;
        self.hasher.update(&buffer[..count]);
        Ok(count)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.output.flush()
    }
}

fn domain_hasher(domain: &[u8]) -> Sha256 {
    let mut hasher = Sha256::new();
    hasher.update((domain.len() as u64).to_be_bytes());
    hasher.update(domain);
    hasher
}

fn sha256(bytes: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    finalize_sha256(hasher)
}

fn finalize_sha256(hasher: Sha256) -> [u8; 32] {
    let digest = hasher.finalize();
    let mut output = [0u8; 32];
    output.copy_from_slice(&digest);
    output
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs::{File, OpenOptions};
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicU64, Ordering};

    static NEXT_FILE: AtomicU64 = AtomicU64::new(1);

    #[test]
    fn verified_transfer_object_zeroizes_ciphertext_on_drop() {
        let observed = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let ciphertext = vec![0xa5; 17];
        let digest: [u8; 32] = Sha256::digest(&ciphertext).into();
        let record =
            BlobChunkRecord::from_parts([0x11; 32], digest, 1, 17).expect("bounded chunk record");
        let verified = VerifiedBlobTransferObject {
            object: BlobTransferObject {
                object_id: ObjectId::new(crate::wire::ObjectKind::BlobChunk, [0x12; 32]),
                source_envelope: EnvelopeId::from_bytes([0x13; 32]),
                blob_id: BlobId([0x14; 32]),
                index: 0,
                ciphertext_sha256: digest,
                ciphertext_len: 17,
                proof: Vec::new(),
                ciphertext,
            },
            expected_record: record,
            zeroize_observer: None,
        }
        .observe_zeroize_for_test(std::sync::Arc::clone(&observed));

        drop(verified);

        assert_eq!(observed.load(Ordering::SeqCst), 1);
    }

    #[derive(Debug)]
    struct GeneratedSource {
        len: u64,
        position: u64,
    }

    impl GeneratedSource {
        fn new(len: u64) -> Self {
            Self { len, position: 0 }
        }

        fn byte_at(offset: u64) -> u8 {
            let mixed =
                offset.wrapping_mul(0x9e37_79b9_7f4a_7c15).rotate_left(17) ^ 0xa5a5_5a5a_c3c3_3c3c;
            mixed as u8
        }
    }

    impl Read for GeneratedSource {
        fn read(&mut self, output: &mut [u8]) -> io::Result<usize> {
            let remaining = self.len.saturating_sub(self.position);
            let count = output
                .len()
                .min(usize::try_from(remaining).unwrap_or(usize::MAX));
            for (index, byte) in output[..count].iter_mut().enumerate() {
                let offset = self.position + u64::try_from(index).unwrap_or(u64::MAX);
                *byte = Self::byte_at(offset);
            }
            self.position += u64::try_from(count).unwrap_or(0);
            Ok(count)
        }
    }

    impl Seek for GeneratedSource {
        fn seek(&mut self, position: SeekFrom) -> io::Result<u64> {
            let next = match position {
                SeekFrom::Start(value) => i128::from(value),
                SeekFrom::End(value) => i128::from(self.len) + i128::from(value),
                SeekFrom::Current(value) => i128::from(self.position) + i128::from(value),
            };
            if !(0..=i128::from(self.len)).contains(&next) {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "generated seek outside source",
                ));
            }
            self.position = u64::try_from(next).map_err(io::Error::other)?;
            Ok(self.position)
        }
    }

    struct VerifyingSink {
        position: u64,
    }

    impl Write for VerifyingSink {
        fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
            for (index, byte) in bytes.iter().enumerate() {
                let offset = self.position + u64::try_from(index).map_err(io::Error::other)?;
                if *byte != GeneratedSource::byte_at(offset) {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "content differs",
                    ));
                }
            }
            self.position += u64::try_from(bytes.len()).map_err(io::Error::other)?;
            Ok(bytes.len())
        }

        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    struct FileStore {
        path: PathBuf,
        chunks: File,
        manifest: Option<BlobManifest>,
        plaintext: Vec<Option<[u8; 32]>>,
        records: Vec<Option<BlobChunkRecord>>,
        expected: Vec<Option<BlobChunkRecord>>,
        finalized: Option<[u8; 32]>,
        commits: u64,
        fail_reads_after_fill: bool,
    }

    impl FileStore {
        fn new() -> io::Result<Self> {
            let number = NEXT_FILE.fetch_add(1, Ordering::Relaxed);
            let path = std::env::temp_dir().join(format!(
                "aster-blob-test-{}-{number}.bin",
                std::process::id()
            ));
            let chunks = OpenOptions::new()
                .create_new(true)
                .read(true)
                .write(true)
                .open(&path)?;
            Ok(Self {
                path,
                chunks,
                manifest: None,
                plaintext: Vec::new(),
                records: Vec::new(),
                expected: Vec::new(),
                finalized: None,
                commits: 0,
                fail_reads_after_fill: false,
            })
        }

        fn offset(&self, index: u64) -> io::Result<u64> {
            let manifest = self
                .manifest
                .as_ref()
                .ok_or_else(|| io::Error::other("manifest absent"))?;
            index
                .checked_mul(u64::from(manifest.chunk_size) + GCM_TAG_LEN as u64)
                .ok_or_else(|| io::Error::other("chunk offset overflow"))
        }

        fn tamper(&mut self, index: u64) -> io::Result<()> {
            let offset = self.offset(index)?;
            self.chunks.seek(SeekFrom::Start(offset))?;
            let mut byte = [0u8; 1];
            self.chunks.read_exact(&mut byte)?;
            byte[0] ^= 1;
            self.chunks.seek(SeekFrom::Start(offset))?;
            self.chunks.write_all(&byte)
        }
    }

    impl Drop for FileStore {
        fn drop(&mut self) {
            let _ = std::fs::remove_file(&self.path);
        }
    }

    impl BlobStore for FileStore {
        type StoreError = io::Error;

        fn begin_blob(&mut self, manifest: &BlobManifest) -> io::Result<()> {
            if let Some(existing) = &self.manifest {
                if existing != manifest {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "manifest conflict",
                    ));
                }
                return Ok(());
            }
            let count = usize::try_from(manifest.chunk_count).map_err(io::Error::other)?;
            self.plaintext.resize(count, None);
            self.records.resize(count, None);
            self.expected.resize(count, None);
            self.manifest = Some(manifest.clone());
            Ok(())
        }

        fn put_plaintext_digest(
            &mut self,
            _id: BlobId,
            index: u64,
            digest: [u8; 32],
        ) -> io::Result<()> {
            let slot = self
                .plaintext
                .get_mut(usize::try_from(index).map_err(io::Error::other)?)
                .ok_or_else(|| io::Error::other("digest index"))?;
            if slot.is_some_and(|value| value != digest) {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "digest conflict",
                ));
            }
            *slot = Some(digest);
            Ok(())
        }

        fn plaintext_digest(&mut self, _id: BlobId, index: u64) -> io::Result<Option<[u8; 32]>> {
            Ok(self
                .plaintext
                .get(usize::try_from(index).map_err(io::Error::other)?)
                .copied()
                .flatten())
        }

        fn chunk_record(&mut self, _id: BlobId, index: u64) -> io::Result<Option<BlobChunkRecord>> {
            Ok(self
                .records
                .get(usize::try_from(index).map_err(io::Error::other)?)
                .copied()
                .flatten())
        }

        fn put_expected_chunk_record(
            &mut self,
            _id: BlobId,
            index: u64,
            record: BlobChunkRecord,
        ) -> io::Result<()> {
            let slot = self
                .expected
                .get_mut(usize::try_from(index).map_err(io::Error::other)?)
                .ok_or_else(|| io::Error::other("expected record index"))?;
            if slot.is_some_and(|value| value != record) {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "expected conflict",
                ));
            }
            *slot = Some(record);
            Ok(())
        }

        fn expected_chunk_record(
            &mut self,
            _id: BlobId,
            index: u64,
        ) -> io::Result<Option<BlobChunkRecord>> {
            Ok(self
                .expected
                .get(usize::try_from(index).map_err(io::Error::other)?)
                .copied()
                .flatten())
        }

        fn commit_verified_chunk(
            &mut self,
            _id: BlobId,
            index: u64,
            record: BlobChunkRecord,
            ciphertext: &[u8],
        ) -> io::Result<()> {
            let slot_index = usize::try_from(index).map_err(io::Error::other)?;
            if let Some(existing) = self.records.get(slot_index).copied().flatten() {
                return if existing == record {
                    Ok(())
                } else {
                    Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "record conflict",
                    ))
                };
            }
            let offset = self.offset(index)?;
            self.chunks.seek(SeekFrom::Start(offset))?;
            self.chunks.write_all(ciphertext)?;
            self.chunks.flush()?;
            self.records[slot_index] = Some(record);
            self.commits += 1;
            Ok(())
        }

        fn read_verified_chunk(
            &mut self,
            _id: BlobId,
            index: u64,
            output: &mut Vec<u8>,
        ) -> io::Result<bool> {
            let Some(record) = self
                .records
                .get(usize::try_from(index).map_err(io::Error::other)?)
                .copied()
                .flatten()
            else {
                return Ok(false);
            };
            let offset = self.offset(index)?;
            self.chunks.seek(SeekFrom::Start(offset))?;
            output.clear();
            output.resize(
                usize::try_from(record.ciphertext_len).map_err(io::Error::other)?,
                0,
            );
            self.chunks.read_exact(output)?;
            if self.fail_reads_after_fill {
                return Err(io::Error::other(
                    "injected read failure after filling output",
                ));
            }
            Ok(true)
        }

        fn finalize_blob(&mut self, _id: BlobId, digest: [u8; 32]) -> io::Result<()> {
            if self.finalized.is_some_and(|value| value != digest) {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "finalize conflict",
                ));
            }
            self.finalized = Some(digest);
            Ok(())
        }

        fn finalized_manifest_digest(&mut self, _id: BlobId) -> io::Result<Option<[u8; 32]>> {
            Ok(self.finalized)
        }
    }

    fn access(seed: u8, epoch: u64) -> BlobAccess {
        let scope = Scope::new("mission/team/alpha")
            .unwrap_or_else(|error| panic!("scope failed: {error}"));
        let topic =
            Topic::new("imagery.current").unwrap_or_else(|error| panic!("topic failed: {error}"));
        BlobAccess::new([seed; 32], &scope, &topic, epoch)
    }

    fn scratch_file() -> (PathBuf, File) {
        let number = NEXT_FILE.fetch_add(1, Ordering::Relaxed);
        let path = std::env::temp_dir().join(format!(
            "aster-blob-digests-{}-{number}.bin",
            std::process::id()
        ));
        let file = OpenOptions::new()
            .create_new(true)
            .read(true)
            .write(true)
            .open(&path)
            .unwrap_or_else(|error| panic!("scratch open failed: {error}"));
        (path, file)
    }

    fn store_directory(label: &str) -> PathBuf {
        let number = NEXT_FILE.fetch_add(1, Ordering::Relaxed);
        std::env::temp_dir().join(format!(
            "aster-blob-store-{label}-{}-{number}",
            std::process::id()
        ))
    }

    fn scope_and_topic() -> (Scope, Topic) {
        let scope = Scope::new("mission/team/alpha")
            .unwrap_or_else(|error| panic!("scope failed: {error}"));
        let topic =
            Topic::new("imagery.current").unwrap_or_else(|error| panic!("topic failed: {error}"));
        (scope, topic)
    }

    #[test]
    fn deduplicated_chunks_are_rehashed_against_the_prepared_source() {
        let chunk_size = MIN_BLOB_CHUNK_SIZE;
        let length = usize::try_from(chunk_size).expect("chunk size") * 2 + 17;
        let mut source = io::Cursor::new(vec![0x41; length]);
        let mut scratch = io::Cursor::new(Vec::new());
        let mut store = FileStore::new().expect("dedup source store");
        let mut writer = BlobWriter::new(&mut store, access(0x41, 1));
        let manifest = writer
            .prepare(
                &mut source,
                &mut scratch,
                chunk_size,
                BlobMetadata::new(None, Vec::new()).expect("metadata"),
            )
            .expect("prepare source");
        let partial = writer
            .encrypt_some(&mut source, &manifest, 1)
            .expect("commit first chunk");
        assert_eq!(partial.newly_committed_chunks, 1);
        assert!(!partial.complete);

        source.get_mut()[0] ^= 1;
        assert!(matches!(
            writer.encrypt_some(&mut source, &manifest, u64::MAX),
            Err(BlobError::SourceChanged)
        ));
        source.get_mut()[0] ^= 1;
        let completed = writer
            .encrypt_some(&mut source, &manifest, u64::MAX)
            .expect("complete unchanged source");
        assert!(completed.complete);

        let second_chunk = usize::try_from(chunk_size).expect("chunk size") + 3;
        source.get_mut()[second_chunk] ^= 1;
        assert!(matches!(
            writer.encrypt_some(&mut source, &manifest, u64::MAX),
            Err(BlobError::SourceChanged)
        ));
        drop(writer);
        assert_eq!(store.commits, manifest.chunk_count());
    }

    #[test]
    fn generated_multichunk_blob_is_bounded_resumable_deduplicated_and_verified() {
        assert_generated_blob_pipeline(8 * u64::from(MAX_BLOB_CHUNK_SIZE) + 123);
    }

    #[test]
    #[ignore = "explicit 101 MiB Blob pipeline qualification"]
    fn qualify_generated_100mb_blob_pipeline() {
        assert_generated_blob_pipeline(101 * 1024 * 1024 + 123);
    }

    fn assert_generated_blob_pipeline(length: u64) {
        let mut source = GeneratedSource::new(length);
        let mut store =
            FileStore::new().unwrap_or_else(|error| panic!("test store failed: {error}"));
        let (scratch_path, mut scratch) = scratch_file();
        let metadata = BlobMetadata::new(
            Some("application/octet-stream".into()),
            b"schema:test:v1".to_vec(),
        )
        .unwrap_or_else(|error| panic!("metadata failed: {error}"));
        let manifest;
        {
            let mut writer = BlobWriter::new(&mut store, access(17, 4));
            manifest = writer
                .prepare(&mut source, &mut scratch, MAX_BLOB_CHUNK_SIZE, metadata)
                .unwrap_or_else(|error| panic!("prepare failed: {error}"));
            assert!(writer.observed_peak_working_buffer_bytes() <= MAX_BLOB_CHUNK_SIZE as usize);
            let interrupted = writer
                .encrypt_some(&mut source, &manifest, 7)
                .unwrap_or_else(|error| panic!("partial encrypt failed: {error}"));
            assert_eq!(interrupted.newly_committed_chunks, 7);
            assert!(!interrupted.complete);
            assert!(
                interrupted.peak_working_buffer_bytes <= MAX_BLOB_CHUNK_SIZE as usize + GCM_TAG_LEN
            );
        }
        assert_eq!(store.commits, 7);
        {
            let mut resumed = BlobWriter::new(&mut store, access(17, 4));
            let completed = resumed
                .encrypt_some(&mut source, &manifest, u64::MAX)
                .unwrap_or_else(|error| panic!("resume failed: {error}"));
            assert!(completed.complete);
            assert_eq!(completed.verified_chunks, manifest.chunk_count());
            let duplicate = resumed
                .encrypt_some(&mut source, &manifest, u64::MAX)
                .unwrap_or_else(|error| panic!("dedup pass failed: {error}"));
            assert_eq!(duplicate.newly_committed_chunks, 0);
            let mut manifest_sink = io::sink();
            let digest = resumed
                .write_manifest(&manifest, &mut manifest_sink)
                .unwrap_or_else(|error| panic!("manifest failed: {error}"));
            assert_ne!(digest, [0u8; 32]);
        }
        assert_eq!(store.commits, manifest.chunk_count());
        let verified = VerifiedBlobManifest::new(manifest.clone());
        let mut reader = BlobReader::new(&mut store, access(17, 4), verified)
            .unwrap_or_else(|error| panic!("reader failed: {error}"));
        let mut sink = VerifyingSink { position: 0 };
        let stats = reader
            .stream_into(&mut sink)
            .unwrap_or_else(|error| panic!("stream failed: {error}"));
        assert_eq!(stats.plaintext_bytes, length);
        assert_eq!(sink.position, length);
        assert!(stats.peak_working_buffer_bytes <= MAX_BLOB_CHUNK_SIZE as usize + GCM_TAG_LEN);
        drop(reader);

        let tail_offset = length - 1;
        let mut tail = [0u8; 1];
        let tail_stats = read_verified_range(
            &mut store,
            &access(17, 4),
            &manifest,
            tail_offset,
            &mut tail,
        )
        .unwrap_or_else(|error| panic!("tail range failed: {error}"));
        assert_eq!(tail, [GeneratedSource::byte_at(tail_offset)]);
        assert_eq!(tail_stats.plaintext_bytes, 1);
        assert_eq!(tail_stats.verified_chunks, 1);

        let crossing_offset = u64::from(manifest.chunk_size()) - 7;
        let mut crossing = [0u8; 20];
        let crossing_stats = read_verified_range(
            &mut store,
            &access(17, 4),
            &manifest,
            crossing_offset,
            &mut crossing,
        )
        .unwrap_or_else(|error| panic!("cross-chunk range failed: {error}"));
        assert_eq!(crossing_stats.verified_chunks, 2);
        for (index, byte) in crossing.iter().enumerate() {
            assert_eq!(
                *byte,
                GeneratedSource::byte_at(
                    crossing_offset + u64::try_from(index).expect("range index fits u64"),
                )
            );
        }
        let mut outside = [0xa5; 2];
        assert!(
            read_verified_range(
                &mut store,
                &access(17, 4),
                &manifest,
                length - 1,
                &mut outside,
            )
            .is_err()
        );
        assert_eq!(outside, [0; 2]);

        store
            .tamper(5)
            .unwrap_or_else(|error| panic!("tamper failed: {error}"));
        let mut reader = BlobReader::new(
            &mut store,
            access(17, 4),
            VerifiedBlobManifest::new(manifest),
        )
        .unwrap_or_else(|error| panic!("tamper reader failed: {error}"));
        assert!(
            reader
                .stream_into(&mut VerifyingSink { position: 0 })
                .is_err()
        );
        drop(scratch);
        std::fs::remove_file(scratch_path)
            .unwrap_or_else(|error| panic!("scratch cleanup failed: {error}"));
    }

    #[test]
    fn reader_clears_filled_adapter_output_after_error_before_every_retry() {
        let mut source = GeneratedSource::new(u64::from(MIN_BLOB_CHUNK_SIZE));
        let mut store =
            FileStore::new().unwrap_or_else(|error| panic!("test store failed: {error}"));
        let (scratch_path, mut scratch) = scratch_file();
        let manifest;
        {
            let mut writer = BlobWriter::new(&mut store, access(18, 5));
            manifest = writer
                .prepare(
                    &mut source,
                    &mut scratch,
                    MIN_BLOB_CHUNK_SIZE,
                    BlobMetadata::new(None, Vec::new())
                        .unwrap_or_else(|error| panic!("metadata failed: {error}")),
                )
                .unwrap_or_else(|error| panic!("prepare failed: {error}"));
            writer
                .encrypt_some(&mut source, &manifest, u64::MAX)
                .unwrap_or_else(|error| panic!("encrypt failed: {error}"));
        }
        store.fail_reads_after_fill = true;
        let mut reader = BlobReader::new(
            &mut store,
            access(18, 5),
            VerifiedBlobManifest::new(manifest),
        )
        .unwrap_or_else(|error| panic!("reader failed: {error}"));
        let mut output = [0xa5; 64];
        for _ in 0..2 {
            assert!(reader.read_some(&mut output).is_err());
            assert_eq!(output, [0xa5; 64]);
            assert!(reader.buffer.is_empty());
            assert_eq!(reader.buffer_offset, 0);
            assert_eq!(reader.next_chunk, 0);
        }
        drop(reader);
        drop(scratch);
        std::fs::remove_file(scratch_path)
            .unwrap_or_else(|error| panic!("scratch cleanup failed: {error}"));
    }

    #[test]
    fn blob_id_is_content_addressed_and_access_is_cryptographically_separated() {
        let metadata = BlobMetadata::new(Some("image/test".into()), vec![1, 2, 3])
            .unwrap_or_else(|error| panic!("metadata failed: {error}"));
        let mut first_source = GeneratedSource::new(80_001);
        let mut first_store =
            FileStore::new().unwrap_or_else(|error| panic!("store failed: {error}"));
        let (first_path, mut first_scratch) = scratch_file();
        let first_manifest;
        {
            let mut writer = BlobWriter::new(&mut first_store, access(20, 1));
            first_manifest = writer
                .prepare(
                    &mut first_source,
                    &mut first_scratch,
                    MIN_BLOB_CHUNK_SIZE,
                    metadata.clone(),
                )
                .unwrap_or_else(|error| panic!("prepare failed: {error}"));
            writer
                .encrypt_some(&mut first_source, &first_manifest, u64::MAX)
                .unwrap_or_else(|error| panic!("encrypt failed: {error}"));
        }

        let mut second_source = GeneratedSource::new(80_001);
        let mut second_store =
            FileStore::new().unwrap_or_else(|error| panic!("store failed: {error}"));
        let (second_path, mut second_scratch) = scratch_file();
        let second_manifest;
        {
            let mut writer = BlobWriter::new(&mut second_store, access(21, 2));
            second_manifest = writer
                .prepare(
                    &mut second_source,
                    &mut second_scratch,
                    MIN_BLOB_CHUNK_SIZE,
                    metadata,
                )
                .unwrap_or_else(|error| panic!("prepare failed: {error}"));
            writer
                .encrypt_some(&mut second_source, &second_manifest, u64::MAX)
                .unwrap_or_else(|error| panic!("encrypt failed: {error}"));
        }
        assert_eq!(first_manifest.id(), second_manifest.id());
        let mut first_chunk = Vec::new();
        let mut second_chunk = Vec::new();
        assert!(
            first_store
                .read_verified_chunk(first_manifest.id(), 0, &mut first_chunk)
                .unwrap_or_else(|error| panic!("read failed: {error}"))
        );
        assert!(
            second_store
                .read_verified_chunk(second_manifest.id(), 0, &mut second_chunk)
                .unwrap_or_else(|error| panic!("read failed: {error}"))
        );
        assert_ne!(first_chunk, second_chunk);
        drop(first_scratch);
        drop(second_scratch);
        std::fs::remove_file(first_path).unwrap_or_else(|error| panic!("cleanup failed: {error}"));
        std::fs::remove_file(second_path).unwrap_or_else(|error| panic!("cleanup failed: {error}"));
    }

    #[test]
    fn concrete_store_reopens_resumes_finishes_and_reads_incrementally() {
        let directory = store_directory("resume");
        let config = BlobStoreConfig {
            max_bytes: 2 * 1024 * 1024,
            max_chunks: 32,
        };
        let (scope, topic) = scope_and_topic();
        let length = u64::from(MIN_BLOB_CHUNK_SIZE) * 3 + 37;
        let mut source = GeneratedSource::new(length);
        let (scratch_path, mut scratch) = scratch_file();
        let metadata = BlobMetadata::new(
            Some("application/octet-stream".into()),
            b"schema:reopen:v1".to_vec(),
        )
        .unwrap_or_else(|error| panic!("metadata failed: {error}"));
        let mut service =
            ReferenceBlobService::open_with_config(&directory, [31; 32], &scope, &topic, 7, config)
                .unwrap_or_else(|error| panic!("service open failed: {error}"));
        let manifest = service
            .prepare(&mut source, &mut scratch, MIN_BLOB_CHUNK_SIZE, metadata)
            .unwrap_or_else(|error| panic!("prepare failed: {error}"));
        let interrupted = service
            .encrypt_some(&mut source, &manifest, 1)
            .unwrap_or_else(|error| panic!("initial encryption failed: {error}"));
        assert_eq!(interrupted.newly_committed_chunks, 1);
        assert!(!interrupted.complete);
        drop(service);

        let mut service =
            ReferenceBlobService::open_with_config(&directory, [31; 32], &scope, &topic, 7, config)
                .unwrap_or_else(|error| panic!("service reopen failed: {error}"));
        assert_eq!(
            service
                .load_manifest(manifest.id())
                .unwrap_or_else(|error| panic!("manifest reload failed: {error}")),
            Some(manifest.clone())
        );
        let resumed = service
            .encrypt_some(&mut source, &manifest, u64::MAX)
            .unwrap_or_else(|error| panic!("resume failed: {error}"));
        assert!(resumed.complete);
        let duplicate = service
            .encrypt_some(&mut source, &manifest, u64::MAX)
            .unwrap_or_else(|error| panic!("dedup failed: {error}"));
        assert_eq!(duplicate.newly_committed_chunks, 0);

        let finished = service
            .finish(manifest.id())
            .unwrap_or_else(|error| panic!("finish failed: {error}"));
        assert_eq!(finished.id(), manifest.id());
        assert!(finished.manifest_bytes().len() as u64 <= MAX_BLOB_MANIFEST_BYTES);
        let inspected = inspect_blob_manifest(&mut io::Cursor::new(finished.manifest_bytes()))
            .unwrap_or_else(|error| panic!("manifest inspection failed: {error}"));
        assert_eq!(inspected.manifest(), &manifest);
        assert_eq!(inspected.manifest_digest(), finished.manifest_digest());
        let second_finish = service
            .finish(manifest.id())
            .unwrap_or_else(|error| panic!("second finish failed: {error}"));
        assert_eq!(second_finish, finished);
        let mut trailing = finished.manifest_bytes().to_vec();
        trailing.push(0);
        assert!(inspect_blob_manifest(&mut io::Cursor::new(trailing)).is_err());

        let mut reader = service
            .reader_for_local(manifest.id())
            .unwrap_or_else(|error| panic!("owned reader failed: {error}"));
        let mut position = 0u64;
        let mut output = [0u8; 997];
        loop {
            let count = reader
                .read_some(&mut output)
                .unwrap_or_else(|error| panic!("incremental read failed: {error}"));
            if count == 0 {
                break;
            }
            for (index, byte) in output[..count].iter().enumerate() {
                assert_eq!(
                    *byte,
                    GeneratedSource::byte_at(position + index as u64),
                    "plaintext differs at offset {}",
                    position + index as u64
                );
            }
            position += count as u64;
        }
        assert_eq!(position, length);
        drop(reader);

        let chunk_path = directory
            .join(hex_id(manifest.id()))
            .join("00000000000000000000.chunk");
        let mut chunk = OpenOptions::new()
            .read(true)
            .write(true)
            .open(&chunk_path)
            .unwrap_or_else(|error| panic!("chunk open failed: {error}"));
        chunk
            .seek(SeekFrom::Start(8 + 8 + MANIFEST_RECORD_LEN))
            .unwrap_or_else(|error| panic!("chunk seek failed: {error}"));
        let mut byte = [0u8; 1];
        chunk
            .read_exact(&mut byte)
            .unwrap_or_else(|error| panic!("chunk read failed: {error}"));
        byte[0] ^= 1;
        chunk
            .seek(SeekFrom::Start(8 + 8 + MANIFEST_RECORD_LEN))
            .unwrap_or_else(|error| panic!("chunk seek failed: {error}"));
        chunk
            .write_all(&byte)
            .unwrap_or_else(|error| panic!("chunk tamper failed: {error}"));
        drop(chunk);
        let mut tampered = service
            .reader_for_local(manifest.id())
            .unwrap_or_else(|error| panic!("tampered reader open failed: {error}"));
        assert!(tampered.read_some(&mut output).is_err());
        drop(tampered);

        drop(scratch);
        std::fs::remove_file(scratch_path)
            .unwrap_or_else(|error| panic!("scratch cleanup failed: {error}"));
        std::fs::remove_dir_all(directory)
            .unwrap_or_else(|error| panic!("store cleanup failed: {error}"));
    }

    #[test]
    fn concrete_store_enforces_quota_before_chunk_commit() {
        let directory = store_directory("quota");
        let config = BlobStoreConfig {
            max_bytes: 1024,
            max_chunks: 8,
        };
        let (scope, topic) = scope_and_topic();
        let mut service =
            ReferenceBlobService::open_with_config(&directory, [44; 32], &scope, &topic, 1, config)
                .unwrap_or_else(|error| panic!("service open failed: {error}"));
        let mut source = GeneratedSource::new(u64::from(MIN_BLOB_CHUNK_SIZE));
        let (scratch_path, mut scratch) = scratch_file();
        let manifest = service
            .prepare(
                &mut source,
                &mut scratch,
                MIN_BLOB_CHUNK_SIZE,
                BlobMetadata::new(None, Vec::new())
                    .unwrap_or_else(|error| panic!("metadata failed: {error}")),
            )
            .unwrap_or_else(|error| panic!("prepare failed: {error}"));
        assert!(service.encrypt_some(&mut source, &manifest, 1).is_err());
        assert!(service.quota_usage().0 <= config.max_bytes);
        assert!(
            !directory
                .join(hex_id(manifest.id()))
                .join("00000000000000000000.chunk")
                .exists()
        );
        drop(scratch);
        std::fs::remove_file(scratch_path)
            .unwrap_or_else(|error| panic!("scratch cleanup failed: {error}"));
        std::fs::remove_dir_all(directory)
            .unwrap_or_else(|error| panic!("store cleanup failed: {error}"));
    }

    #[test]
    fn typed_chunk_carriers_are_proof_bound_relayable_and_manifest_finalized() {
        let producer_directory = store_directory("transfer-producer");
        let relay_directory = store_directory("transfer-relay");
        let consumer_directory = store_directory("transfer-consumer");
        let config = BlobStoreConfig {
            max_bytes: 8 * 1024 * 1024,
            max_chunks: 64,
        };
        let (scope, topic) = scope_and_topic();
        let mut source = GeneratedSource::new(u64::from(MIN_BLOB_CHUNK_SIZE) * 3 + 91);
        let (scratch_path, mut scratch) = scratch_file();
        let mut producer = ReferenceBlobService::open_with_config(
            &producer_directory,
            [55; 32],
            &scope,
            &topic,
            9,
            config,
        )
        .unwrap_or_else(|error| panic!("producer open failed: {error}"));
        let manifest = producer
            .prepare(
                &mut source,
                &mut scratch,
                MIN_BLOB_CHUNK_SIZE,
                BlobMetadata::new(Some("image/test".into()), b"route-proof-v1".to_vec())
                    .unwrap_or_else(|error| panic!("metadata failed: {error}")),
            )
            .unwrap_or_else(|error| panic!("prepare failed: {error}"));
        producer
            .encrypt_some(&mut source, &manifest, u64::MAX)
            .unwrap_or_else(|error| panic!("encrypt failed: {error}"));
        let finished = producer
            .finish(manifest.id())
            .unwrap_or_else(|error| panic!("finish failed: {error}"));
        let source_envelope = EnvelopeId::from_sealed_bytes(b"authenticated Blob envelope");
        let route = AuthenticatedBlobRoute::new(source_envelope, finished.route_commitment());

        let mut producer_transfers =
            BlobTransferStore::open_with_config(&producer_directory, config)
                .unwrap_or_else(|error| panic!("producer transfer open failed: {error}"));
        let object_ids = producer_transfers
            .object_ids_for_route(route, 64)
            .unwrap_or_else(|error| panic!("producer inventory failed: {error}"));
        assert_eq!(object_ids.len() as u64, manifest.chunk_count());
        assert!(
            object_ids
                .iter()
                .all(|id| id.kind() == crate::wire::ObjectKind::BlobChunk)
        );
        assert!(object_ids.iter().all(|id| id.digest().len() == 32));
        let route_tree_path = producer_directory
            .join(hex_id(manifest.id()))
            .join(ROUTE_TREE_FILE);
        let persisted_tree = fs::read(&route_tree_path)
            .unwrap_or_else(|error| panic!("persisted route tree missing: {error}"));
        assert!(persisted_tree.len() as u64 <= MAX_ROUTE_TREE_BYTES);
        let (persisted_id, persisted_count, persisted_levels) =
            decode_route_levels(&persisted_tree)
                .unwrap_or_else(|error| panic!("persisted route tree invalid: {error}"));
        assert_eq!(persisted_id, manifest.id());
        assert_eq!(persisted_count, manifest.chunk_count());
        assert!(persisted_levels.iter().map(Vec::len).sum::<usize>() < object_ids.len() * 2);
        drop(producer_transfers);
        let mut producer_transfers =
            BlobTransferStore::open_with_config(&producer_directory, config)
                .unwrap_or_else(|error| panic!("producer transfer reopen failed: {error}"));
        assert_eq!(
            producer_transfers
                .object_ids_for_route(route, 64)
                .unwrap_or_else(|error| panic!("persisted inventory failed: {error}")),
            object_ids
        );
        let mut carriers = Vec::new();
        for object_id in &object_ids {
            let (total, first) = producer_transfers
                .read_object_range(route, *object_id, 0, 257)
                .unwrap_or_else(|error| panic!("first carrier range failed: {error}"));
            assert!(first.len() <= 257);
            let (_, remainder) = producer_transfers
                .read_object_range(route, *object_id, first.len() as u64, total as usize)
                .unwrap_or_else(|error| panic!("carrier remainder failed: {error}"));
            let mut carrier = first;
            carrier.extend_from_slice(&remainder);
            assert_eq!(carrier.len() as u64, total);
            assert_eq!(
                inspect_blob_transfer_object(&carrier).unwrap().object_id(),
                *object_id
            );
            carriers.push(carrier);
        }

        // A route-only relay verifies the source-authenticated proof and keeps
        // ciphertext without a content seed or manifest plaintext.
        let mut relay = BlobTransferStore::open_with_config(&relay_directory, config)
            .unwrap_or_else(|error| panic!("relay open failed: {error}"));
        let relay_commit = relay
            .commit_carrier(object_ids[0], &carriers[0], route)
            .unwrap_or_else(|error| panic!("relay commit failed: {error}"));
        assert!(relay_commit.newly_stored_carrier);
        assert!(!relay_commit.content_chunk_committed);
        for (object_id, carrier) in object_ids.iter().zip(&carriers).skip(1) {
            relay
                .commit_carrier(*object_id, carrier, route)
                .unwrap_or_else(|error| panic!("relay carrier commit failed: {error}"));
        }
        drop(relay);
        let mut relay = BlobTransferStore::open_with_config(&relay_directory, config)
            .unwrap_or_else(|error| panic!("relay reopen failed: {error}"));
        assert_eq!(
            relay
                .object_ids_for_route(route, 8)
                .unwrap_or_else(|error| panic!("relay inventory failed: {error}")),
            object_ids
        );
        let mut bounded_scan = StoredCarrierScan::open(&relay_directory, config)
            .unwrap_or_else(|error| panic!("carrier scan open failed: {error}"));
        let mut scanned = 0_usize;
        while bounded_scan
            .next_carrier()
            .unwrap_or_else(|error| panic!("carrier scan failed: {error}"))
            .is_some()
        {
            scanned += 1;
        }
        assert_eq!(scanned, carriers.len());
        assert!(bounded_scan.peak_buffer_bytes <= MAX_BLOB_TRANSFER_OBJECT_BYTES);

        let wrong_route = AuthenticatedBlobRoute::new(
            EnvelopeId::from_sealed_bytes(b"different source envelope"),
            finished.route_commitment(),
        );
        assert!(
            relay
                .commit_carrier(object_ids[0], &carriers[0], wrong_route)
                .is_err()
        );
        let mut tampered = carriers[0].clone();
        let proof_or_ciphertext = TRANSFER_FIXED_LEN.min(tampered.len() - 1);
        tampered[proof_or_ciphertext] ^= 1;
        assert!(
            relay
                .commit_carrier(object_ids[0], &tampered, route)
                .is_err()
        );

        // A content-authorized consumer installs the exact authenticated
        // manifest, then commits chunks across a genuine store reopen.
        let mut consumer = BlobTransferStore::open_with_config(&consumer_directory, config)
            .unwrap_or_else(|error| panic!("consumer open failed: {error}"));
        consumer
            .install_authenticated_manifest(finished.manifest_bytes(), &scope, &topic, 9, route)
            .unwrap_or_else(|error| panic!("manifest install failed: {error}"));
        let first = consumer
            .commit_carrier(object_ids[0], &carriers[0], route)
            .unwrap_or_else(|error| panic!("consumer first chunk failed: {error}"));
        assert!(first.content_chunk_committed);
        assert!(!first.blob_finalized);
        drop(consumer);

        let mut consumer = BlobTransferStore::open_with_config(&consumer_directory, config)
            .unwrap_or_else(|error| panic!("consumer reopen failed: {error}"));
        consumer
            .install_authenticated_manifest(finished.manifest_bytes(), &scope, &topic, 9, route)
            .unwrap_or_else(|error| panic!("manifest reinstall failed: {error}"));
        let mut final_outcome = None;
        for (object_id, carrier) in object_ids.iter().zip(&carriers).skip(1) {
            final_outcome = Some(
                consumer
                    .commit_carrier(*object_id, carrier, route)
                    .unwrap_or_else(|error| panic!("consumer chunk failed: {error}")),
            );
        }
        assert!(final_outcome.is_some_and(|outcome| outcome.blob_finalized));

        let mut wrong_manifest = finished.manifest_bytes().to_vec();
        // The first route-visible ciphertext digest begins inside the first
        // manifest record; changing it makes the route root mismatch.
        let record_offset = wrong_manifest.len() - 32 - manifest.chunk_count() as usize * 72;
        wrong_manifest[record_offset + 32] ^= 1;
        assert!(
            consumer
                .install_authenticated_manifest(&wrong_manifest, &scope, &topic, 9, route)
                .is_err()
        );
        drop(consumer);

        let mut consumer_reader = ReferenceBlobService::open_with_config(
            &consumer_directory,
            [55; 32],
            &scope,
            &topic,
            9,
            config,
        )
        .and_then(|mut service| service.reader_for_local(manifest.id()))
        .unwrap_or_else(|error| panic!("consumer reader failed: {error}"));
        let mut sink = VerifyingSink { position: 0 };
        consumer_reader
            .stream_into(&mut sink)
            .unwrap_or_else(|error| panic!("consumer read failed: {error}"));
        assert_eq!(sink.position, manifest.total_len());

        drop(scratch);
        std::fs::remove_file(scratch_path)
            .unwrap_or_else(|error| panic!("scratch cleanup failed: {error}"));
        std::fs::remove_dir_all(producer_directory)
            .unwrap_or_else(|error| panic!("producer cleanup failed: {error}"));
        std::fs::remove_dir_all(relay_directory)
            .unwrap_or_else(|error| panic!("relay cleanup failed: {error}"));
        std::fs::remove_dir_all(consumer_directory)
            .unwrap_or_else(|error| panic!("consumer cleanup failed: {error}"));
    }

    #[test]
    fn manifest_cap_boundary_represents_eight_gibibytes() {
        let metadata = BlobMetadata::new(
            Some("a".repeat(MAX_MEDIA_TYPE_LEN)),
            vec![9; MAX_SCHEMA_ID_LEN],
        )
        .unwrap_or_else(|error| panic!("metadata failed: {error}"));
        let at_limit = BlobManifest {
            id: BlobId([7; 32]),
            total_len: MAX_BLOB_CHUNKS * u64::from(MAX_BLOB_CHUNK_SIZE),
            chunk_size: MAX_BLOB_CHUNK_SIZE,
            chunk_count: MAX_BLOB_CHUNKS,
            whole_plaintext_sha256: [8; 32],
            metadata: metadata.clone(),
            content_group: [9; 32],
            content_epoch: 3,
        };
        let encoded = manifest_encoded_len(&at_limit)
            .unwrap_or_else(|error| panic!("manifest length failed: {error}"));
        assert_eq!(MAX_BLOB_CHUNKS, 131_072);
        assert_eq!(MAX_BLOB_MANIFEST_BYTES, 9_438_606);
        assert_eq!(at_limit.total_len, 8 * 1024 * 1024 * 1024);
        assert_eq!(encoded, MAX_BLOB_MANIFEST_BYTES);
        validate_manifest(&at_limit)
            .unwrap_or_else(|error| panic!("boundary manifest failed: {error}"));

        let above_limit = BlobManifest {
            total_len: (MAX_BLOB_CHUNKS + 1) * u64::from(MAX_BLOB_CHUNK_SIZE),
            chunk_count: MAX_BLOB_CHUNKS + 1,
            ..at_limit
        };
        assert!(validate_manifest(&above_limit).is_err());
    }

    #[test]
    fn canonical_manifest_finalizes_above_one_gib_without_payload_bytes() {
        // Break caught: a canonical upload above the former ~953-MiB manifest
        // ceiling must be finalizable without requiring a payload-sized test.
        const TOTAL_LEN: u64 = 1024 * 1024 * 1024 + 64 * 1024;
        const CHUNK_COUNT: u64 = 16_385;
        let access = access(0x9a, 7);
        let manifest = BlobManifest {
            id: BlobId([0x51; 32]),
            total_len: TOTAL_LEN,
            chunk_size: SELECTED_BLOB_CHUNK_SIZE,
            chunk_count: CHUNK_COUNT,
            whole_plaintext_sha256: [0x52; 32],
            metadata: BlobMetadata::new(Some("application/octet-stream".into()), Vec::new())
                .expect("metadata"),
            content_group: access.content_group,
            content_epoch: access.epoch,
        };
        let record = BlobChunkRecord::from_parts(
            [0x53; 32],
            [0x54; 32],
            SELECTED_BLOB_CHUNK_SIZE,
            SELECTED_BLOB_CHUNK_SIZE + GCM_TAG_LEN as u32,
        )
        .expect("full canonical record");
        let mut store = FileStore::new().expect("synthetic canonical store");
        store.manifest = Some(manifest.clone());
        store.records = vec![Some(record); CHUNK_COUNT as usize];
        let mut encoded = Vec::new();
        BlobWriter::new(&mut store, access)
            .write_manifest(&manifest, &mut encoded)
            .expect("finalize >1-GiB canonical manifest");
        assert_eq!(encoded.len() as u64, 1_179_887);
        assert_eq!(store.chunks.metadata().expect("payload metadata").len(), 0);
        assert!(store.finalized.is_some());
    }
}
