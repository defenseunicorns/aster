use crate::{
    blob::{BlobError, BlobId, BlobMetadata},
    custody::CustodySample,
    model::{Dot, MAX_CAUSAL_CONTEXT_ENTRIES, NodeId, Priority, Scope, Topic, VersionVector},
};
use aes_gcm::{
    Aes256Gcm,
    aead::{Aead, KeyInit, Payload, array::Array},
};
use hkdf::Hkdf;
use sha2::{Digest, Sha256};
use zeroize::{Zeroize, Zeroizing};

pub const BLOB_STREAM_SEGMENT_BYTES: usize = 1024 * 1024;
/// Maximum plaintext length of one independently segmented Blob stream (8 GiB).
///
/// This is intentionally distinct from the legacy profile-4 network Blob
/// ceiling. Stream storage remains bounded separately by its aggregate durable
/// reservation pool, while the fixed-width Merkle frontier and offsets do not
/// grow with this value.
pub const MAX_BLOB_STREAM_BYTES: u64 = 8 * 1024 * 1024 * 1024;
pub const BLOB_STREAM_SEGMENT_ENCODED_OVERHEAD_BYTES: usize =
    8 + 2 + 32 + 32 + 8 + 8 + 8 + 8 + 4 + 4 + 16;
const FRONTIER_LEVELS: usize = 64;
const BLOB_STREAM_FORMAT_VERSION: u16 = 2;
const BLOB_STREAM_PACK_FORMAT_VERSION: u16 = 2;
const BLOB_STREAM_OPEN_MAGIC: &[u8; 8] = b"ASTRBO02";
const BLOB_STREAM_PUBLICATION_MAGIC: &[u8; 8] = b"ASTRBP02";
const BLOB_STREAM_PHYSICAL_SOURCE_MAGIC: &[u8; 8] = b"ASTRPP02";
const BLOB_STREAM_PUBLICATION_SOURCE_MAGIC: &[u8; 8] = b"ASTRPS02";
const BLOB_STREAM_COMMITMENT_MAGIC: &[u8; 8] = b"ASTRBF02";
const BLOB_STREAM_SEGMENT_MAGIC: &[u8; 8] = b"ASTRBS02";
const MAX_BLOB_STREAM_OPERATION_KEY_BYTES: usize = 256;
pub(crate) const MAX_BLOB_STREAM_OPEN_BYTES: usize = 2048 + 40 * MAX_CAUSAL_CONTEXT_ENTRIES;
pub(crate) const MAX_BLOB_STREAM_COMMITMENT_BODY_BYTES: usize = 512;
pub(crate) const MAX_BLOB_STREAM_PUBLICATION_BODY_BYTES: usize = MAX_BLOB_STREAM_OPEN_BYTES + 128;
const MAX_SOURCE_PROTOCOL_CREDENTIAL_BODY_BYTES: usize = 16 * 1024;
const SOURCE_PROTOCOL_SIGNATURE_BYTES: usize = crate::bridge::HYBRID_SIGNATURE_BYTES;
const SOURCE_PROTOCOL_OBJECT_OVERHEAD_BYTES: usize = 4
    + MAX_SOURCE_PROTOCOL_CREDENTIAL_BODY_BYTES
    + SOURCE_PROTOCOL_SIGNATURE_BYTES
    + 4
    + SOURCE_PROTOCOL_SIGNATURE_BYTES;
const MAX_AUTHENTICATED_BLOB_STREAM_OPEN_BYTES: usize =
    SOURCE_PROTOCOL_OBJECT_OVERHEAD_BYTES + MAX_BLOB_STREAM_OPEN_BYTES;
const MAX_AUTHENTICATED_BLOB_STREAM_COMMITMENT_BYTES: usize =
    SOURCE_PROTOCOL_OBJECT_OVERHEAD_BYTES + MAX_BLOB_STREAM_COMMITMENT_BODY_BYTES;
const MAX_AUTHENTICATED_BLOB_STREAM_PUBLICATION_BYTES: usize =
    SOURCE_PROTOCOL_OBJECT_OVERHEAD_BYTES + MAX_BLOB_STREAM_PUBLICATION_BODY_BYTES;
/// Maximum canonical ASTRPS02 SOURCE derived from the exact authenticated
/// semantic-publication, physical-OPEN, and physical-commitment envelope
/// bounds accepted by the reference verifier.
pub const MAX_BLOB_STREAM_PUBLICATION_SOURCE_BYTES: usize = 8
    + 2
    + 4
    + MAX_AUTHENTICATED_BLOB_STREAM_PUBLICATION_BYTES
    + 4
    + 8
    + 2
    + 4
    + MAX_AUTHENTICATED_BLOB_STREAM_OPEN_BYTES
    + 4
    + MAX_AUTHENTICATED_BLOB_STREAM_COMMITMENT_BYTES;

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct BlobPublicationStreamId([u8; 32]);

impl BlobPublicationStreamId {
    pub fn from_bytes(bytes: [u8; 32]) -> Result<Self, BlobError> {
        if bytes == [0; 32] {
            return Err(BlobError::InvalidManifest);
        }
        Ok(Self(bytes))
    }

    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

/// Stable opaque application token for one publisher-qualified local Blob
/// operation. The token is an index key only; it carries no semantic identity
/// or publication authority.
pub fn local_blob_publication_stream_id(
    publisher: NodeId,
    operation: &[u8],
) -> BlobPublicationStreamId {
    let mut digest = Sha256::new();
    digest.update(b"aster/local-blob-stream/id/v2");
    digest.update(publisher);
    digest.update((operation.len() as u64).to_be_bytes());
    digest.update(operation);
    let mut output: [u8; 32] = digest.finalize().into();
    if output == [0; 32] {
        output[31] = 1;
    }
    BlobPublicationStreamId(output)
}

/// Nonsemantic identity and bounds for one node-protected provisional upload.
///
/// Unlike [`BlobStreamOpen`], this value carries no publisher counter, causal
/// context, signed source metadata, or publication authority. It exists only
/// to bind staged ciphertext to the immutable upload reservation that owns it.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BlobUploadDescriptor {
    upload_id: BlobPublicationStreamId,
    request_digest: [u8; 32],
    total_len: u64,
    content_epoch: u64,
}

impl BlobUploadDescriptor {
    pub fn new(
        upload_id: BlobPublicationStreamId,
        request_digest: [u8; 32],
        total_len: u64,
        content_epoch: u64,
    ) -> Result<Self, BlobError> {
        if request_digest == [0; 32] || total_len > MAX_BLOB_STREAM_BYTES || content_epoch == 0 {
            return Err(BlobError::InvalidManifest);
        }
        Ok(Self {
            upload_id,
            request_digest,
            total_len,
            content_epoch,
        })
    }

    pub const fn upload_id(&self) -> BlobPublicationStreamId {
        self.upload_id
    }

    pub const fn request_digest(&self) -> &[u8; 32] {
        &self.request_digest
    }

    pub const fn total_len(&self) -> u64 {
        self.total_len
    }

    pub const fn content_epoch(&self) -> u64 {
        self.content_epoch
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BlobStreamOpen {
    stream_id: BlobPublicationStreamId,
    publisher: NodeId,
    operation_key: Vec<u8>,
    mission_id: [u8; 32],
    publisher_counter: u64,
    causal_context: VersionVector,
    topic: Topic,
    scope: Scope,
    metadata: BlobMetadata,
    priority: Priority,
    ttl_ms: Option<u64>,
    initial_custody: Option<CustodySample>,
    total_len: u64,
    content_epoch: u64,
    policy_revision: u64,
    authorization_digest: [u8; 32],
    publication_salt: [u8; 32],
}

impl BlobStreamOpen {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        stream_id: BlobPublicationStreamId,
        publisher: NodeId,
        operation_key: Vec<u8>,
        mission_id: [u8; 32],
        publisher_counter: u64,
        causal_context: VersionVector,
        topic: Topic,
        scope: Scope,
        metadata: BlobMetadata,
        priority: Priority,
        ttl_ms: Option<u64>,
        initial_custody: Option<CustodySample>,
        total_len: u64,
        content_epoch: u64,
        policy_revision: u64,
        authorization_digest: [u8; 32],
        publication_salt: [u8; 32],
    ) -> Result<Self, BlobError> {
        if publisher == [0; 32]
            || operation_key.is_empty()
            || operation_key.len() > MAX_BLOB_STREAM_OPERATION_KEY_BYTES
            || mission_id == [0; 32]
            || publisher_counter == 0
            || causal_context.len() > MAX_CAUSAL_CONTEXT_ENTRIES
            || causal_context.iter().any(|(node, counter)| {
                *counter == 0 || (*node == publisher && *counter >= publisher_counter)
            })
            || total_len > MAX_BLOB_STREAM_BYTES
            || content_epoch == 0
            || policy_revision == 0
            || authorization_digest == [0; 32]
            || publication_salt == [0; 32]
            || ttl_ms == Some(0)
            || ttl_ms.is_some() != initial_custody.is_some()
        {
            return Err(BlobError::InvalidManifest);
        }
        Ok(Self {
            stream_id,
            publisher,
            operation_key,
            mission_id,
            publisher_counter,
            causal_context,
            topic,
            scope,
            metadata,
            priority,
            ttl_ms,
            initial_custody,
            total_len,
            content_epoch,
            policy_revision,
            authorization_digest,
            publication_salt,
        })
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(512);
        out.extend_from_slice(BLOB_STREAM_OPEN_MAGIC);
        out.extend_from_slice(&BLOB_STREAM_FORMAT_VERSION.to_be_bytes());
        out.extend_from_slice(&BLOB_STREAM_PACK_FORMAT_VERSION.to_be_bytes());
        out.extend_from_slice(self.stream_id.as_bytes());
        out.extend_from_slice(&self.publisher);
        push_u16_bytes(&mut out, &self.operation_key).expect("validated operation key");
        out.extend_from_slice(&self.mission_id);
        out.extend_from_slice(&self.publisher_counter.to_be_bytes());
        out.extend_from_slice(&(self.causal_context.len() as u32).to_be_bytes());
        for (publisher, counter) in self.causal_context.iter() {
            out.extend_from_slice(publisher);
            out.extend_from_slice(&counter.to_be_bytes());
        }
        push_u16_bytes(&mut out, self.topic.as_str().as_bytes()).expect("validated topic");
        push_u16_bytes(&mut out, self.scope.as_str().as_bytes()).expect("validated scope");
        encode_metadata(&mut out, &self.metadata).expect("validated metadata");
        out.push(self.priority as u8);
        encode_optional_u64(&mut out, self.ttl_ms);
        encode_optional_custody(&mut out, self.initial_custody);
        out.extend_from_slice(&self.total_len.to_be_bytes());
        out.extend_from_slice(&self.content_epoch.to_be_bytes());
        out.extend_from_slice(&self.policy_revision.to_be_bytes());
        out.extend_from_slice(&self.authorization_digest);
        out.extend_from_slice(&self.publication_salt);
        out
    }

    pub fn decode(encoded: &[u8]) -> Result<Self, BlobError> {
        if encoded.len() > MAX_BLOB_STREAM_OPEN_BYTES {
            return Err(BlobError::InvalidManifest);
        }
        let mut reader = StreamReader::new(encoded);
        if reader.take(8)? != BLOB_STREAM_OPEN_MAGIC
            || reader.u16()? != BLOB_STREAM_FORMAT_VERSION
            || reader.u16()? != BLOB_STREAM_PACK_FORMAT_VERSION
        {
            return Err(BlobError::InvalidManifest);
        }
        let stream_id = BlobPublicationStreamId::from_bytes(reader.array()?)?;
        let publisher = reader.array()?;
        let operation_key = reader
            .u16_bytes(MAX_BLOB_STREAM_OPERATION_KEY_BYTES)?
            .to_vec();
        let mission_id = reader.array()?;
        let publisher_counter = reader.u64()?;
        let context_len = reader.u32()? as usize;
        if context_len > MAX_CAUSAL_CONTEXT_ENTRIES {
            return Err(BlobError::InvalidManifest);
        }
        let mut causal_context = VersionVector::default();
        for _ in 0..context_len {
            let node = reader.array()?;
            let counter = reader.u64()?;
            if counter == 0 || causal_context.counter(&node) != 0 {
                return Err(BlobError::InvalidManifest);
            }
            causal_context.observe(Dot {
                publisher: node,
                counter,
            });
        }
        let topic = Topic::new(reader.u16_string(128)?).map_err(|_| BlobError::InvalidManifest)?;
        let scope = Scope::new(reader.u16_string(128)?).map_err(|_| BlobError::InvalidManifest)?;
        let metadata = decode_metadata(&mut reader)?;
        let priority = Priority::from_wire(reader.u8()?).ok_or(BlobError::InvalidManifest)?;
        let ttl_ms = decode_optional_u64(&mut reader)?;
        let initial_custody = decode_optional_custody(&mut reader)?;
        let total_len = reader.u64()?;
        let content_epoch = reader.u64()?;
        let policy_revision = reader.u64()?;
        let authorization_digest = reader.array()?;
        let publication_salt = reader.array()?;
        reader.finish()?;
        Self::new(
            stream_id,
            publisher,
            operation_key,
            mission_id,
            publisher_counter,
            causal_context,
            topic,
            scope,
            metadata,
            priority,
            ttl_ms,
            initial_custody,
            total_len,
            content_epoch,
            policy_revision,
            authorization_digest,
            publication_salt,
        )
    }

    pub fn digest(&self) -> [u8; 32] {
        hash_parts(b"ASTER/blob-stream/open/v2\0", &[&self.encode()])
    }
    pub const fn stream_id(&self) -> BlobPublicationStreamId {
        self.stream_id
    }
    pub const fn total_len(&self) -> u64 {
        self.total_len
    }
    pub const fn content_epoch(&self) -> u64 {
        self.content_epoch
    }
    pub const fn metadata(&self) -> &BlobMetadata {
        &self.metadata
    }
    pub const fn ttl_ms(&self) -> Option<u64> {
        self.ttl_ms
    }
    pub const fn initial_custody(&self) -> Option<CustodySample> {
        self.initial_custody
    }
    pub const fn publisher(&self) -> NodeId {
        self.publisher
    }
    pub fn operation_key(&self) -> &[u8] {
        &self.operation_key
    }
    pub const fn mission_id(&self) -> &[u8; 32] {
        &self.mission_id
    }
    pub const fn publisher_counter(&self) -> u64 {
        self.publisher_counter
    }
    pub const fn causal_context(&self) -> &VersionVector {
        &self.causal_context
    }
    pub fn topic(&self) -> &Topic {
        &self.topic
    }
    pub fn scope(&self) -> &Scope {
        &self.scope
    }
    pub fn content_group(&self) -> [u8; 32] {
        crate::blob::content_group_id(&self.scope, &self.topic)
    }
    pub const fn priority(&self) -> Priority {
        self.priority
    }
    pub const fn policy_revision(&self) -> u64 {
        self.policy_revision
    }
    pub const fn authorization_digest(&self) -> &[u8; 32] {
        &self.authorization_digest
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VerifiedBlobStreamOpen {
    open: BlobStreamOpen,
    mission_authority_id: NodeId,
    authenticated_bytes: Vec<u8>,
}

/// Signed semantic authority for one publication which references a canonical
/// physical Profile-5 pack.
///
/// The embedded open owns publisher, operation, causal, policy, priority, TTL,
/// and metadata semantics. Blob identity, content group, epoch, metadata, and
/// physical lineage identify the logical pack variant; the enclosing source
/// record independently authenticates the exact physical OPEN and commitment
/// used on one transfer. Keeping these authorities separate lets a new
/// operation publish the same Blob without rereading plaintext or
/// manufacturing another physical variant, including when a receiver already
/// owns an equivalent canonical physical encoding.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BlobStreamPublication {
    open: BlobStreamOpen,
    blob_id: BlobId,
    final_custody: Option<CustodySample>,
    physical_lineage: [u8; 32],
}

impl BlobStreamPublication {
    pub fn new(
        open: BlobStreamOpen,
        blob_id: BlobId,
        final_custody: Option<CustodySample>,
        physical_lineage: [u8; 32],
    ) -> Result<Self, BlobError> {
        let custody_valid = match (open.ttl_ms(), open.initial_custody(), final_custody) {
            (None, None, None) => true,
            (Some(_), Some(initial), Some(final_sample)) => {
                initial.clock_id == final_sample.clock_id && final_sample.tick_ms >= initial.tick_ms
            }
            _ => false,
        };
        if physical_lineage == [0; 32] || !custody_valid {
            return Err(BlobError::InvalidManifest);
        }
        Ok(Self {
            open,
            blob_id,
            final_custody,
            physical_lineage,
        })
    }

    pub fn encode(&self) -> Vec<u8> {
        let open = self.open.encode();
        let mut out = Vec::with_capacity(open.len() + 128);
        out.extend_from_slice(BLOB_STREAM_PUBLICATION_MAGIC);
        out.extend_from_slice(&BLOB_STREAM_FORMAT_VERSION.to_be_bytes());
        out.extend_from_slice(&(open.len() as u32).to_be_bytes());
        out.extend_from_slice(&open);
        out.extend_from_slice(self.blob_id.as_bytes());
        encode_optional_custody(&mut out, self.final_custody);
        out.extend_from_slice(&self.physical_lineage);
        out
    }

    pub fn decode(encoded: &[u8]) -> Result<Self, BlobError> {
        if encoded.len() > MAX_BLOB_STREAM_PUBLICATION_BODY_BYTES {
            return Err(BlobError::InvalidManifest);
        }
        let mut reader = StreamReader::new(encoded);
        if reader.take(8)? != BLOB_STREAM_PUBLICATION_MAGIC
            || reader.u16()? != BLOB_STREAM_FORMAT_VERSION
        {
            return Err(BlobError::InvalidManifest);
        }
        let open_len = reader.u32()? as usize;
        let open = BlobStreamOpen::decode(reader.take(open_len)?)?;
        let blob_id = BlobId::from_bytes(reader.array()?);
        let final_custody = decode_optional_custody(&mut reader)?;
        let physical_lineage = reader.array()?;
        reader.finish()?;
        Self::new(open, blob_id, final_custody, physical_lineage)
    }

    pub const fn open(&self) -> &BlobStreamOpen {
        &self.open
    }

    pub const fn blob_id(&self) -> BlobId {
        self.blob_id
    }

    pub const fn final_custody(&self) -> Option<CustodySample> {
        self.final_custody
    }

    pub const fn physical_lineage(&self) -> &[u8; 32] {
        &self.physical_lineage
    }
}

/// Provider-authenticated semantic publication-to-pack binding.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VerifiedBlobStreamPublication {
    publication: BlobStreamPublication,
    authenticated_bytes: Vec<u8>,
}

impl VerifiedBlobStreamPublication {
    pub const fn publication(&self) -> &BlobStreamPublication {
        &self.publication
    }

    pub fn authenticated_bytes(&self) -> &[u8] {
        &self.authenticated_bytes
    }

    pub(crate) fn from_provider(
        publication: BlobStreamPublication,
        authenticated_bytes: Vec<u8>,
        _seal: crate::source_blob::BlobStreamProviderSeal,
    ) -> Self {
        Self {
            publication,
            authenticated_bytes,
        }
    }
}

/// Exact wire SOURCE for one signed semantic publication and the independently
/// authenticated physical pack used by this transfer.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BlobStreamPublicationSource {
    authenticated_publication: Vec<u8>,
    authenticated_open: Vec<u8>,
    authenticated_commitment: Vec<u8>,
}

impl BlobStreamPublicationSource {
    pub fn new(
        authenticated_publication: Vec<u8>,
        authenticated_open: Vec<u8>,
        authenticated_commitment: Vec<u8>,
    ) -> Result<Self, BlobError> {
        let source = Self {
            authenticated_publication,
            authenticated_open,
            authenticated_commitment,
        };
        if source.authenticated_publication.is_empty()
            || source.authenticated_open.is_empty()
            || source.authenticated_commitment.is_empty()
            || source.encoded_len()? > MAX_BLOB_STREAM_PUBLICATION_SOURCE_BYTES
        {
            return Err(BlobError::InvalidManifest);
        }
        Ok(source)
    }

    pub fn encode(&self) -> Result<Vec<u8>, BlobError> {
        let physical = self.physical_source_record()?;
        let publication_len = u32::try_from(self.authenticated_publication.len())
            .map_err(|_| BlobError::LengthOverflow)?;
        let physical_len = u32::try_from(physical.len()).map_err(|_| BlobError::LengthOverflow)?;
        let mut output = Vec::with_capacity(self.encoded_len()?);
        output.extend_from_slice(BLOB_STREAM_PUBLICATION_SOURCE_MAGIC);
        output.extend_from_slice(&BLOB_STREAM_FORMAT_VERSION.to_be_bytes());
        output.extend_from_slice(&publication_len.to_be_bytes());
        output.extend_from_slice(&self.authenticated_publication);
        output.extend_from_slice(&physical_len.to_be_bytes());
        output.extend_from_slice(&physical);
        Ok(output)
    }

    pub fn decode(encoded: &[u8]) -> Result<Self, BlobError> {
        if encoded.len() > MAX_BLOB_STREAM_PUBLICATION_SOURCE_BYTES {
            return Err(BlobError::InvalidManifest);
        }
        let mut source = StreamReader::new(encoded);
        if source.take(8)? != BLOB_STREAM_PUBLICATION_SOURCE_MAGIC
            || source.u16()? != BLOB_STREAM_FORMAT_VERSION
        {
            return Err(BlobError::InvalidManifest);
        }
        let publication_len =
            usize::try_from(source.u32()?).map_err(|_| BlobError::LengthOverflow)?;
        let authenticated_publication = source.take(publication_len)?.to_vec();
        let physical_len = usize::try_from(source.u32()?).map_err(|_| BlobError::LengthOverflow)?;
        let physical_bytes = source.take(physical_len)?;
        source.finish()?;
        let mut physical = StreamReader::new(physical_bytes);
        if physical.take(8)? != BLOB_STREAM_PHYSICAL_SOURCE_MAGIC
            || physical.u16()? != BLOB_STREAM_FORMAT_VERSION
        {
            return Err(BlobError::InvalidManifest);
        }
        let open_len = usize::try_from(physical.u32()?).map_err(|_| BlobError::LengthOverflow)?;
        let authenticated_open = physical.take(open_len)?.to_vec();
        let commitment_len =
            usize::try_from(physical.u32()?).map_err(|_| BlobError::LengthOverflow)?;
        let authenticated_commitment = physical.take(commitment_len)?.to_vec();
        physical.finish()?;
        let decoded = Self::new(
            authenticated_publication,
            authenticated_open,
            authenticated_commitment,
        )?;
        if decoded.encode()? != encoded {
            return Err(BlobError::InvalidManifest);
        }
        Ok(decoded)
    }

    pub fn authenticated_publication(&self) -> &[u8] {
        &self.authenticated_publication
    }

    pub fn authenticated_open(&self) -> &[u8] {
        &self.authenticated_open
    }

    pub fn authenticated_commitment(&self) -> &[u8] {
        &self.authenticated_commitment
    }

    pub fn physical_source_record(&self) -> Result<Vec<u8>, BlobError> {
        Self::encode_physical_source(&self.authenticated_open, &self.authenticated_commitment)
    }

    pub fn encode_physical_source(
        authenticated_open: &[u8],
        authenticated_commitment: &[u8],
    ) -> Result<Vec<u8>, BlobError> {
        let open_len =
            u32::try_from(authenticated_open.len()).map_err(|_| BlobError::LengthOverflow)?;
        let commitment_len =
            u32::try_from(authenticated_commitment.len()).map_err(|_| BlobError::LengthOverflow)?;
        let mut output = Vec::with_capacity(
            8 + 2 + 4 + authenticated_open.len() + 4 + authenticated_commitment.len(),
        );
        output.extend_from_slice(BLOB_STREAM_PHYSICAL_SOURCE_MAGIC);
        output.extend_from_slice(&BLOB_STREAM_FORMAT_VERSION.to_be_bytes());
        output.extend_from_slice(&open_len.to_be_bytes());
        output.extend_from_slice(authenticated_open);
        output.extend_from_slice(&commitment_len.to_be_bytes());
        output.extend_from_slice(authenticated_commitment);
        Ok(output)
    }

    fn encoded_len(&self) -> Result<usize, BlobError> {
        (8_usize + 2 + 4)
            .checked_add(self.authenticated_publication.len())
            .and_then(|len| len.checked_add(4))
            .and_then(|len| len.checked_add(8 + 2 + 4))
            .and_then(|len| len.checked_add(self.authenticated_open.len()))
            .and_then(|len| len.checked_add(4))
            .and_then(|len| len.checked_add(self.authenticated_commitment.len()))
            .ok_or(BlobError::LengthOverflow)
    }
}

/// Provider-authenticated semantic publication plus exact physical authority
/// for one Profile-5 transfer source.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VerifiedBlobStreamPublicationSource {
    source: BlobStreamPublicationSource,
    publication: VerifiedBlobStreamPublication,
    physical_open: VerifiedBlobStreamOpen,
    physical_commitment: VerifiedBlobStreamFinalCommitment,
}

impl VerifiedBlobStreamPublicationSource {
    pub const fn source(&self) -> &BlobStreamPublicationSource {
        &self.source
    }

    pub const fn publication(&self) -> &VerifiedBlobStreamPublication {
        &self.publication
    }

    pub const fn physical_open(&self) -> &VerifiedBlobStreamOpen {
        &self.physical_open
    }

    pub const fn physical_commitment(&self) -> &VerifiedBlobStreamFinalCommitment {
        &self.physical_commitment
    }

    pub(crate) fn from_provider(
        source: BlobStreamPublicationSource,
        publication: VerifiedBlobStreamPublication,
        physical_open: VerifiedBlobStreamOpen,
        physical_commitment: VerifiedBlobStreamFinalCommitment,
        _seal: crate::source_blob::BlobStreamProviderSeal,
    ) -> Self {
        Self {
            source,
            publication,
            physical_open,
            physical_commitment,
        }
    }
}

impl VerifiedBlobStreamOpen {
    pub const fn open(&self) -> &BlobStreamOpen {
        &self.open
    }
    pub fn authenticated_bytes(&self) -> &[u8] {
        &self.authenticated_bytes
    }
    pub(crate) fn from_provider(
        open: BlobStreamOpen,
        mission_authority_id: NodeId,
        authenticated_bytes: Vec<u8>,
        _seal: crate::source_blob::BlobStreamProviderSeal,
    ) -> Self {
        Self {
            open,
            mission_authority_id,
            authenticated_bytes,
        }
    }
    pub(crate) const fn mission_authority_id(&self) -> NodeId {
        self.mission_authority_id
    }

    #[cfg(test)]
    fn for_test(open: BlobStreamOpen) -> Self {
        let authenticated_bytes = open.encode();
        Self {
            mission_authority_id: open.mission_id,
            open,
            authenticated_bytes,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BlobStreamFinalCommitment {
    open_digest: [u8; 32],
    stream_id: BlobPublicationStreamId,
    total_len: u64,
    segment_count: u64,
    plaintext_root: [u8; 32],
    ciphertext_root: [u8; 32],
    blob_id: BlobId,
    metadata_commitment: [u8; 32],
    content_epoch: u64,
    ttl_ms: Option<u64>,
    final_custody: Option<CustodySample>,
}

impl BlobStreamFinalCommitment {
    pub fn new(
        open: &VerifiedBlobStreamOpen,
        plaintext_root: [u8; 32],
        ciphertext_root: [u8; 32],
        segment_count: u64,
        final_custody: Option<CustodySample>,
    ) -> Result<Self, BlobError> {
        let open = open.open();
        let expected = open
            .total_len
            .checked_add(BLOB_STREAM_SEGMENT_BYTES as u64 - 1)
            .ok_or(BlobError::LengthOverflow)?
            / BLOB_STREAM_SEGMENT_BYTES as u64;
        let custody_valid = match (open.ttl_ms, open.initial_custody, final_custody) {
            (None, None, None) => true,
            (Some(_), Some(initial), Some(final_sample)) => {
                initial.clock_id == final_sample.clock_id && final_sample.tick_ms >= initial.tick_ms
            }
            _ => false,
        };
        if plaintext_root == [0; 32]
            || ciphertext_root == [0; 32]
            || segment_count != expected
            || !custody_valid
        {
            return Err(BlobError::InvalidManifest);
        }
        let metadata_commitment = metadata_commitment(&open.metadata);
        let blob_id = derive_stream_blob_id(plaintext_root, open.total_len, metadata_commitment);
        Ok(Self {
            open_digest: open.digest(),
            stream_id: open.stream_id,
            total_len: open.total_len,
            segment_count,
            plaintext_root,
            ciphertext_root,
            blob_id,
            metadata_commitment,
            content_epoch: open.content_epoch,
            ttl_ms: open.ttl_ms,
            final_custody,
        })
    }

    pub const fn blob_id(&self) -> BlobId {
        self.blob_id
    }
    pub(crate) fn matches_metadata(&self, metadata: &BlobMetadata) -> bool {
        self.metadata_commitment == metadata_commitment(metadata)
    }
    pub const fn open_digest(&self) -> &[u8; 32] {
        &self.open_digest
    }
    pub const fn stream_id(&self) -> BlobPublicationStreamId {
        self.stream_id
    }
    pub const fn total_len(&self) -> u64 {
        self.total_len
    }
    pub const fn segment_count(&self) -> u64 {
        self.segment_count
    }
    pub const fn plaintext_root(&self) -> &[u8; 32] {
        &self.plaintext_root
    }
    pub const fn ciphertext_root(&self) -> &[u8; 32] {
        &self.ciphertext_root
    }
    pub const fn content_epoch(&self) -> u64 {
        self.content_epoch
    }
    pub const fn ttl_ms(&self) -> Option<u64> {
        self.ttl_ms
    }
    pub const fn final_custody(&self) -> Option<CustodySample> {
        self.final_custody
    }
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(256);
        out.extend_from_slice(BLOB_STREAM_COMMITMENT_MAGIC);
        out.extend_from_slice(&BLOB_STREAM_FORMAT_VERSION.to_be_bytes());
        out.extend_from_slice(&BLOB_STREAM_PACK_FORMAT_VERSION.to_be_bytes());
        out.extend_from_slice(&self.open_digest);
        out.extend_from_slice(self.stream_id.as_bytes());
        out.extend_from_slice(&self.total_len.to_be_bytes());
        out.extend_from_slice(&self.segment_count.to_be_bytes());
        out.extend_from_slice(&self.plaintext_root);
        out.extend_from_slice(&self.ciphertext_root);
        out.extend_from_slice(self.blob_id.as_bytes());
        out.extend_from_slice(&self.metadata_commitment);
        out.extend_from_slice(&self.content_epoch.to_be_bytes());
        encode_optional_u64(&mut out, self.ttl_ms);
        encode_optional_custody(&mut out, self.final_custody);
        out
    }

    pub fn decode(encoded: &[u8]) -> Result<Self, BlobError> {
        let mut reader = StreamReader::new(encoded);
        if reader.take(8)? != BLOB_STREAM_COMMITMENT_MAGIC
            || reader.u16()? != BLOB_STREAM_FORMAT_VERSION
            || reader.u16()? != BLOB_STREAM_PACK_FORMAT_VERSION
        {
            return Err(BlobError::InvalidManifest);
        }
        let open_digest = reader.array()?;
        let stream_id = BlobPublicationStreamId::from_bytes(reader.array()?)?;
        let total_len = reader.u64()?;
        let segment_count = reader.u64()?;
        let plaintext_root = reader.array()?;
        let ciphertext_root = reader.array()?;
        let blob_id = BlobId::from_bytes(reader.array()?);
        let metadata_commitment = reader.array()?;
        let content_epoch = reader.u64()?;
        let ttl_ms = decode_optional_u64(&mut reader)?;
        let final_custody = decode_optional_custody(&mut reader)?;
        reader.finish()?;
        let expected = total_len
            .checked_add(BLOB_STREAM_SEGMENT_BYTES as u64 - 1)
            .ok_or(BlobError::LengthOverflow)?
            / BLOB_STREAM_SEGMENT_BYTES as u64;
        if segment_count != expected
            || open_digest == [0; 32]
            || plaintext_root == [0; 32]
            || ciphertext_root == [0; 32]
            || content_epoch == 0
            || ttl_ms == Some(0)
            || ttl_ms.is_some() != final_custody.is_some()
            || blob_id != derive_stream_blob_id(plaintext_root, total_len, metadata_commitment)
        {
            return Err(BlobError::InvalidManifest);
        }
        Ok(Self {
            open_digest,
            stream_id,
            total_len,
            segment_count,
            plaintext_root,
            ciphertext_root,
            blob_id,
            metadata_commitment,
            content_epoch,
            ttl_ms,
            final_custody,
        })
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VerifiedBlobStreamFinalCommitment {
    commitment: BlobStreamFinalCommitment,
    authenticated_bytes: Vec<u8>,
}

impl VerifiedBlobStreamFinalCommitment {
    pub(crate) fn from_provider(
        commitment: BlobStreamFinalCommitment,
        authenticated_bytes: Vec<u8>,
        _seal: crate::source_blob::BlobStreamProviderSeal,
    ) -> Self {
        Self {
            commitment,
            authenticated_bytes,
        }
    }
    pub const fn commitment(&self) -> &BlobStreamFinalCommitment {
        &self.commitment
    }
    pub fn authenticated_bytes(&self) -> &[u8] {
        &self.authenticated_bytes
    }
}

#[derive(Debug)]
pub struct BlobStreamPlainPartition {
    stream_id: [u8; 32],
    open_digest: [u8; 32],
    content_epoch: u64,
    index: u64,
    offset: u64,
    total_len: u64,
    plaintext: Zeroizing<Vec<u8>>,
}

impl BlobStreamPlainPartition {
    pub fn new(
        stream_id: [u8; 32],
        open_digest: [u8; 32],
        content_epoch: u64,
        index: u64,
        offset: u64,
        total_len: u64,
        plaintext: Vec<u8>,
    ) -> Result<Self, BlobError> {
        Self::new_with_segment_bytes(
            stream_id,
            open_digest,
            content_epoch,
            index,
            offset,
            total_len,
            plaintext,
            BLOB_STREAM_SEGMENT_BYTES,
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn new_with_segment_bytes(
        stream_id: [u8; 32],
        open_digest: [u8; 32],
        content_epoch: u64,
        index: u64,
        offset: u64,
        total_len: u64,
        plaintext: Vec<u8>,
        segment_bytes: usize,
    ) -> Result<Self, BlobError> {
        let len = plaintext.len();
        let expected_offset = index
            .checked_mul(segment_bytes as u64)
            .ok_or(BlobError::LengthOverflow)?;
        let end = offset
            .checked_add(len as u64)
            .ok_or(BlobError::LengthOverflow)?;
        if stream_id == [0; 32]
            || open_digest == [0; 32]
            || content_epoch == 0
            || segment_bytes == 0
            || segment_bytes > BLOB_STREAM_SEGMENT_BYTES
            || total_len == 0
            || offset != expected_offset
            || len == 0
            || len > segment_bytes
            || end > total_len
            || (end < total_len && len != segment_bytes)
        {
            return Err(BlobError::InvalidManifest);
        }
        Ok(Self {
            stream_id,
            open_digest,
            content_epoch,
            index,
            offset,
            total_len,
            plaintext: Zeroizing::new(plaintext),
        })
    }

    #[cfg(test)]
    #[allow(clippy::too_many_arguments)]
    fn new_with_segment_bytes_for_test(
        stream_id: [u8; 32],
        open_digest: [u8; 32],
        content_epoch: u64,
        index: u64,
        offset: u64,
        total_len: u64,
        plaintext: Vec<u8>,
        segment_bytes: usize,
    ) -> Result<Self, BlobError> {
        assert!(
            segment_bytes > 0 && segment_bytes <= BLOB_STREAM_SEGMENT_BYTES,
            "test segment bound must be within the production limit"
        );
        Self::new_with_segment_bytes(
            stream_id,
            open_digest,
            content_epoch,
            index,
            offset,
            total_len,
            plaintext,
            segment_bytes,
        )
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BlobStreamSegmentLeaves {
    plaintext: [u8; 32],
    ciphertext: [u8; 32],
    plaintext_len: u64,
    ciphertext_len: u64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EncryptedBlobStreamSegment {
    stream_id: [u8; 32],
    open_digest: [u8; 32],
    content_epoch: u64,
    index: u64,
    offset: u64,
    total_len: u64,
    plaintext_len: u32,
    ciphertext: Vec<u8>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct EncryptedBlobStreamSegmentHeader {
    stream_id: [u8; 32],
    open_digest: [u8; 32],
    content_epoch: u64,
    index: u64,
    offset: u64,
    total_len: u64,
    plaintext_len: u32,
    ciphertext_len: u32,
}

impl EncryptedBlobStreamSegmentHeader {
    pub const fn stream_id(&self) -> &[u8; 32] {
        &self.stream_id
    }
    pub const fn open_digest(&self) -> &[u8; 32] {
        &self.open_digest
    }
    pub const fn index(&self) -> u64 {
        self.index
    }
    pub const fn offset(&self) -> u64 {
        self.offset
    }
    pub const fn total_len(&self) -> u64 {
        self.total_len
    }
    pub const fn plaintext_len(&self) -> u32 {
        self.plaintext_len
    }
    pub const fn ciphertext_len(&self) -> u32 {
        self.ciphertext_len
    }
}

impl EncryptedBlobStreamSegment {
    const FIXED_ENCODED_BYTES: usize = BLOB_STREAM_SEGMENT_ENCODED_OVERHEAD_BYTES - 16;

    pub fn index(&self) -> u64 {
        self.index
    }

    pub const fn stream_id(&self) -> &[u8; 32] {
        &self.stream_id
    }

    pub const fn open_digest(&self) -> &[u8; 32] {
        &self.open_digest
    }

    pub const fn offset(&self) -> u64 {
        self.offset
    }

    pub const fn plaintext_len(&self) -> u32 {
        self.plaintext_len
    }

    pub const fn total_len(&self) -> u64 {
        self.total_len
    }

    pub fn ciphertext(&self) -> &[u8] {
        &self.ciphertext
    }

    /// Heap bytes owned by this decoded provisional segment.
    pub fn owned_bytes(&self) -> usize {
        self.ciphertext.capacity()
    }

    /// Reconstructs the transport-visible ciphertext leaf without requiring
    /// plaintext or decryption authority. This is sufficient to audit a
    /// durable ciphertext frontier projected by a receiver.
    pub fn ciphertext_audit_leaves(&self) -> BlobStreamSegmentLeaves {
        let aad = segment_aad(
            self.stream_id,
            self.open_digest,
            self.content_epoch,
            self.index,
            self.offset,
            self.total_len,
            self.plaintext_len,
        );
        BlobStreamSegmentLeaves {
            plaintext: [0; 32],
            ciphertext: hash_parts(
                b"ASTER/blob-stream/cipher-leaf/v2\0",
                &[&aad, &self.ciphertext],
            ),
            plaintext_len: u64::from(self.plaintext_len),
            ciphertext_len: self.ciphertext.len() as u64,
        }
    }

    pub fn header(&self) -> EncryptedBlobStreamSegmentHeader {
        EncryptedBlobStreamSegmentHeader {
            stream_id: self.stream_id,
            open_digest: self.open_digest,
            content_epoch: self.content_epoch,
            index: self.index,
            offset: self.offset,
            total_len: self.total_len,
            plaintext_len: self.plaintext_len,
            ciphertext_len: self.ciphertext.len() as u32,
        }
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(Self::FIXED_ENCODED_BYTES + self.ciphertext.len());
        out.extend_from_slice(BLOB_STREAM_SEGMENT_MAGIC);
        out.extend_from_slice(&BLOB_STREAM_FORMAT_VERSION.to_be_bytes());
        out.extend_from_slice(&self.stream_id);
        out.extend_from_slice(&self.open_digest);
        out.extend_from_slice(&self.content_epoch.to_be_bytes());
        out.extend_from_slice(&self.index.to_be_bytes());
        out.extend_from_slice(&self.offset.to_be_bytes());
        out.extend_from_slice(&self.total_len.to_be_bytes());
        out.extend_from_slice(&self.plaintext_len.to_be_bytes());
        out.extend_from_slice(&(self.ciphertext.len() as u32).to_be_bytes());
        out.extend_from_slice(&self.ciphertext);
        out
    }

    pub fn decode(encoded: &[u8]) -> Result<Self, BlobError> {
        let (header, ciphertext) = Self::decode_borrowed(encoded)?;
        Ok(Self {
            stream_id: header.stream_id,
            open_digest: header.open_digest,
            content_epoch: header.content_epoch,
            index: header.index,
            offset: header.offset,
            total_len: header.total_len,
            plaintext_len: header.plaintext_len,
            ciphertext: ciphertext.to_vec(),
        })
    }

    pub fn inspect_encoded(encoded: &[u8]) -> Result<EncryptedBlobStreamSegmentHeader, BlobError> {
        Self::decode_borrowed(encoded).map(|(header, _)| header)
    }

    fn decode_borrowed(
        encoded: &[u8],
    ) -> Result<(EncryptedBlobStreamSegmentHeader, &[u8]), BlobError> {
        Self::decode_borrowed_with_segment_bytes(encoded, BLOB_STREAM_SEGMENT_BYTES)
    }

    fn decode_borrowed_with_segment_bytes(
        encoded: &[u8],
        segment_bytes: usize,
    ) -> Result<(EncryptedBlobStreamSegmentHeader, &[u8]), BlobError> {
        if segment_bytes == 0 || segment_bytes > BLOB_STREAM_SEGMENT_BYTES {
            return Err(BlobError::InvalidManifest);
        }
        let mut reader = StreamReader::new(encoded);
        if reader.take(8)? != BLOB_STREAM_SEGMENT_MAGIC
            || reader.u16()? != BLOB_STREAM_FORMAT_VERSION
        {
            return Err(BlobError::InvalidManifest);
        }
        let stream_id = reader.array()?;
        let open_digest = reader.array()?;
        let content_epoch = reader.u64()?;
        let index = reader.u64()?;
        let offset = reader.u64()?;
        let total_len = reader.u64()?;
        let plaintext_len = reader.u32()?;
        let ciphertext_len = reader.u32()? as usize;
        let end = offset
            .checked_add(u64::from(plaintext_len))
            .ok_or(BlobError::LengthOverflow)?;
        if stream_id == [0; 32]
            || open_digest == [0; 32]
            || content_epoch == 0
            || total_len == 0
            || plaintext_len == 0
            || plaintext_len as usize > segment_bytes
            || ciphertext_len != plaintext_len as usize + 16
            || offset
                != index
                    .checked_mul(segment_bytes as u64)
                    .ok_or(BlobError::LengthOverflow)?
            || end > total_len
            || (end < total_len && plaintext_len as usize != segment_bytes)
        {
            return Err(BlobError::InvalidManifest);
        }
        let ciphertext = reader.take(ciphertext_len)?;
        reader.finish()?;
        Ok((
            EncryptedBlobStreamSegmentHeader {
                stream_id,
                open_digest,
                content_epoch,
                index,
                offset,
                total_len,
                plaintext_len,
                ciphertext_len: ciphertext_len as u32,
            },
            ciphertext,
        ))
    }

    #[cfg(test)]
    fn identity_mutations_for_test(&self) -> Vec<Self> {
        let mut output = Vec::new();
        macro_rules! changed {
            ($field:ident, $value:expr) => {{
                let mut value = self.clone();
                value.$field = $value;
                output.push(value);
            }};
        }
        changed!(stream_id, [0x91; 32]);
        changed!(open_digest, [0x92; 32]);
        changed!(content_epoch, self.content_epoch + 1);
        changed!(index, self.index + 1);
        changed!(offset, self.offset + 1);
        changed!(total_len, self.total_len + 1);
        changed!(plaintext_len, self.plaintext_len - 1);
        let mut ciphertext = self.ciphertext.clone();
        ciphertext[0] ^= 1;
        changed!(ciphertext, ciphertext);
        let mut tag = self.ciphertext.clone();
        let last = tag.len() - 1;
        tag[last] ^= 1;
        changed!(ciphertext, tag);
        output
    }
}

#[derive(Clone)]
pub struct BlobStreamSegmentSealer {
    stream_id: [u8; 32],
    open_digest: [u8; 32],
    content_epoch: u64,
    key: [u8; 32],
    base_nonce: [u8; 12],
}

impl Drop for BlobStreamSegmentSealer {
    fn drop(&mut self) {
        self.key.zeroize();
        self.base_nonce.zeroize();
    }
}

#[derive(Clone)]
pub struct BlobStreamSegmentOpener(BlobStreamSegmentSealer);

impl BlobStreamSegmentSealer {
    pub(crate) fn new(
        stream_id: [u8; 32],
        open_digest: [u8; 32],
        content_epoch: u64,
        key: [u8; 32],
        base_nonce: [u8; 12],
    ) -> Self {
        Self {
            stream_id,
            open_digest,
            content_epoch,
            key,
            base_nonce,
        }
    }

    #[cfg(any(test, feature = "test-utils"))]
    #[doc(hidden)]
    pub fn from_test_key(
        stream_id: [u8; 32],
        open_digest: [u8; 32],
        content_epoch: u64,
        key: [u8; 32],
        base_nonce: [u8; 12],
    ) -> Self {
        Self::new(stream_id, open_digest, content_epoch, key, base_nonce)
    }

    pub(crate) fn from_provider(
        open: &VerifiedBlobStreamOpen,
        content_grant_seed: [u8; 32],
        _seal: crate::source_blob::BlobStreamProviderSeal,
    ) -> Result<Self, BlobError> {
        let mut seed = Zeroizing::new(content_grant_seed);
        let (key, nonce) = derive_stream_key(&seed, open.open())?;
        seed.zeroize();
        Ok(Self::new(
            *open.open().stream_id().as_bytes(),
            open.open().digest(),
            open.open().content_epoch(),
            key,
            nonce,
        ))
    }

    pub(crate) fn from_upload_provider(
        upload: &BlobUploadDescriptor,
        content_grant_seed: [u8; 32],
        _seal: crate::source_blob::BlobStreamProviderSeal,
    ) -> Result<Self, BlobError> {
        let mut seed = Zeroizing::new(content_grant_seed);
        let (key, nonce) = derive_upload_key(&seed, upload)?;
        seed.zeroize();
        Ok(Self::new(
            *upload.upload_id().as_bytes(),
            *upload.request_digest(),
            upload.content_epoch(),
            key,
            nonce,
        ))
    }

    pub fn seal(
        &self,
        partition: BlobStreamPlainPartition,
    ) -> Result<(EncryptedBlobStreamSegment, BlobStreamSegmentLeaves), BlobError> {
        if partition.stream_id != self.stream_id
            || partition.open_digest != self.open_digest
            || partition.content_epoch != self.content_epoch
        {
            return Err(BlobError::AuthenticationFailed);
        }
        let plaintext_len =
            u32::try_from(partition.plaintext.len()).map_err(|_| BlobError::LengthOverflow)?;
        let aad = segment_aad(
            partition.stream_id,
            partition.open_digest,
            partition.content_epoch,
            partition.index,
            partition.offset,
            partition.total_len,
            plaintext_len,
        );
        let cipher = Aes256Gcm::new(&Array(self.key));
        let nonce = Array(segment_nonce(self.base_nonce, partition.index)?);
        let ciphertext = cipher
            .encrypt(
                &nonce,
                Payload {
                    msg: &partition.plaintext,
                    aad: &aad,
                },
            )
            .map_err(|_| BlobError::AuthenticationFailed)?;
        let leaves = segment_leaves(
            partition.index,
            partition.offset,
            partition.total_len,
            &aad,
            &partition.plaintext,
            &ciphertext,
        );
        Ok((
            EncryptedBlobStreamSegment {
                stream_id: partition.stream_id,
                open_digest: partition.open_digest,
                content_epoch: partition.content_epoch,
                index: partition.index,
                offset: partition.offset,
                total_len: partition.total_len,
                plaintext_len,
                ciphertext,
            },
            leaves,
        ))
    }
}

impl BlobStreamSegmentOpener {
    #[cfg(any(test, feature = "test-utils"))]
    pub(crate) fn new(
        stream_id: [u8; 32],
        open_digest: [u8; 32],
        content_epoch: u64,
        key: [u8; 32],
        base_nonce: [u8; 12],
    ) -> Self {
        Self(BlobStreamSegmentSealer::new(
            stream_id,
            open_digest,
            content_epoch,
            key,
            base_nonce,
        ))
    }

    #[cfg(any(test, feature = "test-utils"))]
    #[doc(hidden)]
    pub fn from_test_key(
        stream_id: [u8; 32],
        open_digest: [u8; 32],
        content_epoch: u64,
        key: [u8; 32],
        base_nonce: [u8; 12],
    ) -> Self {
        Self::new(stream_id, open_digest, content_epoch, key, base_nonce)
    }

    pub(crate) fn from_provider(
        open: &VerifiedBlobStreamOpen,
        content_grant_seed: [u8; 32],
        seal: crate::source_blob::BlobStreamProviderSeal,
    ) -> Result<Self, BlobError> {
        Ok(Self(BlobStreamSegmentSealer::from_provider(
            open,
            content_grant_seed,
            seal,
        )?))
    }

    pub(crate) fn from_upload_provider(
        upload: &BlobUploadDescriptor,
        content_grant_seed: [u8; 32],
        seal: crate::source_blob::BlobStreamProviderSeal,
    ) -> Result<Self, BlobError> {
        Ok(Self(BlobStreamSegmentSealer::from_upload_provider(
            upload,
            content_grant_seed,
            seal,
        )?))
    }

    pub fn open(
        &self,
        segment: &EncryptedBlobStreamSegment,
    ) -> Result<(Zeroizing<Vec<u8>>, BlobStreamSegmentLeaves), BlobError> {
        self.open_borrowed(segment.header(), &segment.ciphertext)
            .map(|(_, plaintext, leaves)| (plaintext, leaves))
    }

    pub fn open_encoded(
        &self,
        encoded: &[u8],
    ) -> Result<
        (
            EncryptedBlobStreamSegmentHeader,
            Zeroizing<Vec<u8>>,
            BlobStreamSegmentLeaves,
        ),
        BlobError,
    > {
        let (header, ciphertext) = EncryptedBlobStreamSegment::decode_borrowed(encoded)?;
        self.open_borrowed(header, ciphertext)
    }

    #[cfg(test)]
    fn open_encoded_with_segment_bytes_for_test(
        &self,
        encoded: &[u8],
        segment_bytes: usize,
    ) -> Result<
        (
            EncryptedBlobStreamSegmentHeader,
            Zeroizing<Vec<u8>>,
            BlobStreamSegmentLeaves,
        ),
        BlobError,
    > {
        assert!(
            segment_bytes > 0 && segment_bytes <= BLOB_STREAM_SEGMENT_BYTES,
            "test segment bound must be within the production limit"
        );
        let (header, ciphertext) =
            EncryptedBlobStreamSegment::decode_borrowed_with_segment_bytes(encoded, segment_bytes)?;
        self.open_borrowed(header, ciphertext)
    }

    fn open_borrowed(
        &self,
        header: EncryptedBlobStreamSegmentHeader,
        ciphertext: &[u8],
    ) -> Result<
        (
            EncryptedBlobStreamSegmentHeader,
            Zeroizing<Vec<u8>>,
            BlobStreamSegmentLeaves,
        ),
        BlobError,
    > {
        if header.stream_id != self.0.stream_id
            || header.open_digest != self.0.open_digest
            || header.content_epoch != self.0.content_epoch
            || ciphertext.len() != header.ciphertext_len as usize
        {
            return Err(BlobError::AuthenticationFailed);
        }
        let aad = segment_aad(
            header.stream_id,
            header.open_digest,
            header.content_epoch,
            header.index,
            header.offset,
            header.total_len,
            header.plaintext_len,
        );
        let cipher = Aes256Gcm::new(&Array(self.0.key));
        let nonce = Array(segment_nonce(self.0.base_nonce, header.index)?);
        let plaintext = Zeroizing::new(
            cipher
                .decrypt(
                    &nonce,
                    Payload {
                        msg: ciphertext,
                        aad: &aad,
                    },
                )
                .map_err(|_| BlobError::AuthenticationFailed)?,
        );
        if plaintext.len() != header.plaintext_len as usize {
            return Err(BlobError::AuthenticationFailed);
        }
        let leaves = segment_leaves(
            header.index,
            header.offset,
            header.total_len,
            &aad,
            &plaintext,
            ciphertext,
        );
        Ok((header, plaintext, leaves))
    }
}

fn segment_nonce(mut base: [u8; 12], index: u64) -> Result<[u8; 12], BlobError> {
    let start = u64::from_be_bytes(base[4..].try_into().expect("eight-byte nonce suffix"));
    let value = start.checked_add(index).ok_or(BlobError::LengthOverflow)?;
    base[4..].copy_from_slice(&value.to_be_bytes());
    Ok(base)
}

fn derive_stream_key(
    content_grant_seed: &[u8; 32],
    open: &BlobStreamOpen,
) -> Result<([u8; 32], [u8; 12]), BlobError> {
    let mut salt = Vec::with_capacity(64);
    salt.extend_from_slice(b"ASTER/blob-stream/key/v2\0");
    salt.extend_from_slice(&open.publication_salt);
    let hkdf = Hkdf::<Sha256>::new(Some(&salt), content_grant_seed);
    let digest = open.digest();
    let mut key = [0; 32];
    let mut key_info = Vec::with_capacity(64);
    key_info.extend_from_slice(b"ASTER/blob-stream/aead-key/v2\0");
    key_info.extend_from_slice(&digest);
    hkdf.expand(&key_info, &mut key)
        .map_err(|_| BlobError::AuthenticationFailed)?;
    let mut nonce = [0; 12];
    let mut nonce_info = Vec::with_capacity(64);
    nonce_info.extend_from_slice(b"ASTER/blob-stream/base-nonce/v2\0");
    nonce_info.extend_from_slice(&digest);
    hkdf.expand(&nonce_info, &mut nonce)
        .map_err(|_| BlobError::AuthenticationFailed)?;
    Ok((key, nonce))
}

fn derive_upload_key(
    content_grant_seed: &[u8; 32],
    upload: &BlobUploadDescriptor,
) -> Result<([u8; 32], [u8; 12]), BlobError> {
    let hkdf = Hkdf::<Sha256>::new(Some(b"ASTER/blob-upload/key/v1\0"), content_grant_seed);
    let mut binding = Vec::with_capacity(72);
    binding.extend_from_slice(upload.upload_id().as_bytes());
    binding.extend_from_slice(upload.request_digest());
    binding.extend_from_slice(&upload.content_epoch().to_be_bytes());
    let mut key = [0; 32];
    let mut key_info = Vec::with_capacity(96);
    key_info.extend_from_slice(b"ASTER/blob-upload/aead-key/v1\0");
    key_info.extend_from_slice(&binding);
    hkdf.expand(&key_info, &mut key)
        .map_err(|_| BlobError::AuthenticationFailed)?;
    let mut nonce = [0; 12];
    let mut nonce_info = Vec::with_capacity(96);
    nonce_info.extend_from_slice(b"ASTER/blob-upload/base-nonce/v1\0");
    nonce_info.extend_from_slice(&binding);
    hkdf.expand(&nonce_info, &mut nonce)
        .map_err(|_| BlobError::AuthenticationFailed)?;
    Ok((key, nonce))
}

/// Upload-specific names keep provisional application code independent from
/// the legacy semantic stream-open representation while retaining the shared
/// bounded encrypted-segment codec.
pub type BlobUploadSegmentSealer = BlobStreamSegmentSealer;
pub type BlobUploadSegmentOpener = BlobStreamSegmentOpener;
pub type BlobUploadPlainPartition = BlobStreamPlainPartition;

fn segment_aad(
    stream_id: [u8; 32],
    open_digest: [u8; 32],
    content_epoch: u64,
    index: u64,
    offset: u64,
    total_len: u64,
    plaintext_len: u32,
) -> Vec<u8> {
    let mut aad = Vec::with_capacity(132);
    aad.extend_from_slice(b"ASTER/blob-stream/segment/v2\0");
    aad.extend_from_slice(&stream_id);
    aad.extend_from_slice(&open_digest);
    aad.extend_from_slice(&content_epoch.to_be_bytes());
    aad.extend_from_slice(&index.to_be_bytes());
    aad.extend_from_slice(&offset.to_be_bytes());
    aad.extend_from_slice(&total_len.to_be_bytes());
    aad.extend_from_slice(&plaintext_len.to_be_bytes());
    aad
}

fn hash_parts(domain: &[u8], parts: &[&[u8]]) -> [u8; 32] {
    let mut hash = Sha256::new();
    hash.update(domain);
    for part in parts {
        hash.update((*part).len().to_be_bytes());
        hash.update(part);
    }
    hash.finalize().into()
}

fn segment_leaves(
    index: u64,
    offset: u64,
    total_len: u64,
    aad: &[u8],
    plaintext: &[u8],
    ciphertext: &[u8],
) -> BlobStreamSegmentLeaves {
    let plaintext_position = [
        index.to_be_bytes(),
        offset.to_be_bytes(),
        total_len.to_be_bytes(),
        (plaintext.len() as u64).to_be_bytes(),
    ]
    .concat();
    BlobStreamSegmentLeaves {
        // Content identity must survive republishing the same bytes under a new stream,
        // publisher, epoch, or encryption key. Position and length remain committed so
        // segment insertion, deletion, duplication, and reordering still change the root.
        plaintext: hash_parts(
            b"ASTER/blob-stream/plain-leaf/v2\0",
            &[&plaintext_position, plaintext],
        ),
        ciphertext: hash_parts(b"ASTER/blob-stream/cipher-leaf/v2\0", &[aad, ciphertext]),
        plaintext_len: plaintext.len() as u64,
        ciphertext_len: ciphertext.len() as u64,
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BlobStreamSubtree {
    first_index: u64,
    count: u64,
    plaintext_len: u64,
    ciphertext_len: u64,
    plaintext_root: [u8; 32],
    ciphertext_root: [u8; 32],
}

impl BlobStreamSubtree {
    pub fn leaf(index: u64, leaves: BlobStreamSegmentLeaves) -> Self {
        Self {
            first_index: index,
            count: 1,
            plaintext_len: leaves.plaintext_len,
            ciphertext_len: leaves.ciphertext_len,
            plaintext_root: leaves.plaintext,
            ciphertext_root: leaves.ciphertext,
        }
    }

    pub fn first_index(&self) -> u64 {
        self.first_index
    }

    pub fn combine(left: Self, right: Self) -> Result<Self, BlobError> {
        if left.count != right.count
            || left.first_index.checked_add(left.count) != Some(right.first_index)
        {
            return Err(BlobError::InvalidManifest);
        }
        Self::combine_adjacent(left, right)
    }

    fn combine_adjacent(left: Self, right: Self) -> Result<Self, BlobError> {
        if left.first_index.checked_add(left.count) != Some(right.first_index) {
            return Err(BlobError::InvalidManifest);
        }
        let count = left
            .count
            .checked_add(right.count)
            .ok_or(BlobError::LengthOverflow)?;
        let plaintext_len = left
            .plaintext_len
            .checked_add(right.plaintext_len)
            .ok_or(BlobError::LengthOverflow)?;
        let ciphertext_len = left
            .ciphertext_len
            .checked_add(right.ciphertext_len)
            .ok_or(BlobError::LengthOverflow)?;
        let metadata = [
            left.first_index.to_be_bytes(),
            count.to_be_bytes(),
            plaintext_len.to_be_bytes(),
            ciphertext_len.to_be_bytes(),
        ]
        .concat();
        Ok(Self {
            first_index: left.first_index,
            count,
            plaintext_len,
            ciphertext_len,
            plaintext_root: hash_parts(
                b"ASTER/blob-stream/plain-node/v2\0",
                &[&metadata, &left.plaintext_root, &right.plaintext_root],
            ),
            ciphertext_root: hash_parts(
                b"ASTER/blob-stream/cipher-node/v2\0",
                &[&metadata, &left.ciphertext_root, &right.ciphertext_root],
            ),
        })
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BlobStreamCheckpoint {
    next_index: u64,
    plaintext_len: u64,
    ciphertext_len: u64,
    levels: [Option<BlobStreamSubtree>; FRONTIER_LEVELS],
}

impl BlobStreamCheckpoint {
    const SUBTREE_BYTES: usize = 8 * 4 + 32 * 2;
    pub const ENCODED_LEN: usize = 8 + 2 + 8 * 3 + FRONTIER_LEVELS * (1 + Self::SUBTREE_BYTES);

    pub const fn next_index(&self) -> u64 {
        self.next_index
    }

    pub const fn plaintext_len(&self) -> u64 {
        self.plaintext_len
    }

    pub const fn ciphertext_len(&self) -> u64 {
        self.ciphertext_len
    }

    /// Digest of every ciphertext-relevant frontier field. Plaintext roots are
    /// deliberately excluded so storage audit needs no content key.
    pub fn ciphertext_commitment(&self) -> [u8; 32] {
        let mut digest = Sha256::new();
        digest.update(b"ASTER/blob-stream/cipher-checkpoint/v1\0");
        digest.update(self.next_index.to_be_bytes());
        digest.update(self.plaintext_len.to_be_bytes());
        digest.update(self.ciphertext_len.to_be_bytes());
        for subtree in self.levels {
            match subtree {
                None => digest.update([0]),
                Some(subtree) => {
                    digest.update([1]);
                    digest.update(subtree.first_index.to_be_bytes());
                    digest.update(subtree.count.to_be_bytes());
                    digest.update(subtree.plaintext_len.to_be_bytes());
                    digest.update(subtree.ciphertext_len.to_be_bytes());
                    digest.update(subtree.ciphertext_root);
                }
            }
        }
        digest.finalize().into()
    }

    /// Digest of every plaintext-relevant frontier field.
    ///
    /// This is suitable for checking a caller-supplied prefix against a
    /// durable resume checkpoint without retaining plaintext or requiring the
    /// content-encryption key. It is not a Blob identity; complete content
    /// uses [`BlobStreamPlaintextFrontier::finish`].
    pub fn plaintext_commitment(&self) -> [u8; 32] {
        let mut digest = Sha256::new();
        digest.update(b"ASTER/blob-stream/plain-checkpoint/v1\0");
        digest.update(self.next_index.to_be_bytes());
        digest.update(self.plaintext_len.to_be_bytes());
        digest.update(self.ciphertext_len.to_be_bytes());
        for subtree in self.levels {
            match subtree {
                None => digest.update([0]),
                Some(subtree) => {
                    digest.update([1]);
                    digest.update(subtree.first_index.to_be_bytes());
                    digest.update(subtree.count.to_be_bytes());
                    digest.update(subtree.plaintext_len.to_be_bytes());
                    digest.update(subtree.ciphertext_len.to_be_bytes());
                    digest.update(subtree.plaintext_root);
                }
            }
        }
        digest.finalize().into()
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(Self::ENCODED_LEN);
        out.extend_from_slice(b"ASTRCK02");
        out.extend_from_slice(&BLOB_STREAM_FORMAT_VERSION.to_be_bytes());
        out.extend_from_slice(&self.next_index.to_be_bytes());
        out.extend_from_slice(&self.plaintext_len.to_be_bytes());
        out.extend_from_slice(&self.ciphertext_len.to_be_bytes());
        for subtree in self.levels {
            match subtree {
                None => {
                    out.push(0);
                    out.resize(out.len() + Self::SUBTREE_BYTES, 0);
                }
                Some(subtree) => {
                    out.push(1);
                    out.extend_from_slice(&subtree.first_index.to_be_bytes());
                    out.extend_from_slice(&subtree.count.to_be_bytes());
                    out.extend_from_slice(&subtree.plaintext_len.to_be_bytes());
                    out.extend_from_slice(&subtree.ciphertext_len.to_be_bytes());
                    out.extend_from_slice(&subtree.plaintext_root);
                    out.extend_from_slice(&subtree.ciphertext_root);
                }
            }
        }
        out
    }

    pub fn decode(encoded: &[u8]) -> Result<Self, BlobError> {
        if encoded.len() != Self::ENCODED_LEN {
            return Err(BlobError::InvalidManifest);
        }
        let mut reader = StreamReader::new(encoded);
        if reader.take(8)? != b"ASTRCK02" || reader.u16()? != BLOB_STREAM_FORMAT_VERSION {
            return Err(BlobError::InvalidManifest);
        }
        let next_index = reader.u64()?;
        let plaintext_len = reader.u64()?;
        let ciphertext_len = reader.u64()?;
        let mut levels = [None; FRONTIER_LEVELS];
        for (level, target) in levels.iter_mut().enumerate() {
            match reader.u8()? {
                0 => {
                    if reader
                        .take(Self::SUBTREE_BYTES)?
                        .iter()
                        .any(|byte| *byte != 0)
                    {
                        return Err(BlobError::InvalidManifest);
                    }
                }
                1 => {
                    let subtree = BlobStreamSubtree {
                        first_index: reader.u64()?,
                        count: reader.u64()?,
                        plaintext_len: reader.u64()?,
                        ciphertext_len: reader.u64()?,
                        plaintext_root: reader.array()?,
                        ciphertext_root: reader.array()?,
                    };
                    if subtree.count != 1_u64.checked_shl(level as u32).unwrap_or(0)
                        || subtree.plaintext_root == [0; 32]
                        || subtree.ciphertext_root == [0; 32]
                    {
                        return Err(BlobError::InvalidManifest);
                    }
                    *target = Some(subtree);
                }
                _ => return Err(BlobError::InvalidManifest),
            }
        }
        reader.finish()?;
        let checkpoint = Self {
            next_index,
            plaintext_len,
            ciphertext_len,
            levels,
        };
        BlobStreamFrontier::restore(checkpoint.clone())?;
        Ok(checkpoint)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BlobStreamFrontier {
    checkpoint: BlobStreamCheckpoint,
}

impl BlobStreamFrontier {
    pub fn new() -> Self {
        Self {
            checkpoint: BlobStreamCheckpoint {
                next_index: 0,
                plaintext_len: 0,
                ciphertext_len: 0,
                levels: [None; FRONTIER_LEVELS],
            },
        }
    }

    pub fn append(&mut self, mut subtree: BlobStreamSubtree) -> Result<(), BlobError> {
        if subtree.first_index != self.checkpoint.next_index || !subtree.count.is_power_of_two() {
            return Err(BlobError::InvalidManifest);
        }
        self.checkpoint.next_index = self
            .checkpoint
            .next_index
            .checked_add(subtree.count)
            .ok_or(BlobError::LengthOverflow)?;
        self.checkpoint.plaintext_len = self
            .checkpoint
            .plaintext_len
            .checked_add(subtree.plaintext_len)
            .ok_or(BlobError::LengthOverflow)?;
        self.checkpoint.ciphertext_len = self
            .checkpoint
            .ciphertext_len
            .checked_add(subtree.ciphertext_len)
            .ok_or(BlobError::LengthOverflow)?;
        let mut level = subtree.count.trailing_zeros() as usize;
        loop {
            if level >= FRONTIER_LEVELS {
                return Err(BlobError::LengthOverflow);
            }
            if let Some(left) = self.checkpoint.levels[level].take() {
                subtree = BlobStreamSubtree::combine(left, subtree)?;
                level += 1;
            } else {
                self.checkpoint.levels[level] = Some(subtree);
                return Ok(());
            }
        }
    }

    pub fn checkpoint(&self) -> BlobStreamCheckpoint {
        self.checkpoint.clone()
    }

    pub fn restore(checkpoint: BlobStreamCheckpoint) -> Result<Self, BlobError> {
        let rebuilt_plain = checkpoint
            .levels
            .iter()
            .flatten()
            .try_fold(0_u64, |sum, subtree| sum.checked_add(subtree.plaintext_len))
            .ok_or(BlobError::LengthOverflow)?;
        let rebuilt_cipher = checkpoint
            .levels
            .iter()
            .flatten()
            .try_fold(0_u64, |sum, subtree| {
                sum.checked_add(subtree.ciphertext_len)
            })
            .ok_or(BlobError::LengthOverflow)?;
        let rebuilt_count = checkpoint
            .levels
            .iter()
            .flatten()
            .try_fold(0_u64, |sum, subtree| sum.checked_add(subtree.count))
            .ok_or(BlobError::LengthOverflow)?;
        let mut subtrees = checkpoint
            .levels
            .iter()
            .flatten()
            .copied()
            .collect::<Vec<_>>();
        subtrees.sort_by_key(|subtree| subtree.first_index);
        let mut cursor = 0_u64;
        for subtree in subtrees {
            if subtree.first_index != cursor
                || subtree.count == 0
                || !subtree.count.is_power_of_two()
            {
                return Err(BlobError::InvalidManifest);
            }
            cursor = cursor
                .checked_add(subtree.count)
                .ok_or(BlobError::LengthOverflow)?;
        }
        if rebuilt_plain != checkpoint.plaintext_len
            || rebuilt_cipher != checkpoint.ciphertext_len
            || rebuilt_count != checkpoint.next_index
            || cursor != checkpoint.next_index
        {
            return Err(BlobError::InvalidManifest);
        }
        Ok(Self { checkpoint })
    }

    pub fn finish(self, total_len: u64) -> Result<([u8; 32], [u8; 32]), BlobError> {
        if self.checkpoint.plaintext_len != total_len {
            return Err(BlobError::InvalidManifest);
        }
        if total_len == 0 {
            if self.checkpoint.next_index != 0
                || self.checkpoint.ciphertext_len != 0
                || self.checkpoint.levels.iter().any(Option::is_some)
            {
                return Err(BlobError::InvalidManifest);
            }
            let fields = [0_u8; 24];
            return Ok((
                hash_parts(b"ASTER/blob-stream/plain-root/v2\0", &[&fields, &[]]),
                hash_parts(b"ASTER/blob-stream/cipher-root/v2\0", &[&fields, &[]]),
            ));
        }
        if self.checkpoint.next_index == 0 {
            return Err(BlobError::InvalidManifest);
        }
        let mut roots = self
            .checkpoint
            .levels
            .into_iter()
            .flatten()
            .collect::<Vec<_>>();
        roots.sort_by_key(|subtree| subtree.first_index);
        let mut roots = roots.into_iter();
        let mut root = roots.next().ok_or(BlobError::InvalidManifest)?;
        for right in roots {
            root = BlobStreamSubtree::combine_adjacent(root, right)?;
        }
        let final_fields = [
            total_len.to_be_bytes(),
            root.ciphertext_len.to_be_bytes(),
            root.count.to_be_bytes(),
        ]
        .concat();
        Ok((
            hash_parts(
                b"ASTER/blob-stream/plain-root/v2\0",
                &[&final_fields, &root.plaintext_root],
            ),
            hash_parts(
                b"ASTER/blob-stream/cipher-root/v2\0",
                &[&final_fields, &root.ciphertext_root],
            ),
        ))
    }
}

impl Default for BlobStreamFrontier {
    fn default() -> Self {
        Self::new()
    }
}

/// Incremental, key-independent reconstruction of the protocol plaintext
/// frontier.
///
/// One-shot resume adapters use this to authenticate caller bytes which the
/// encrypted pack has already durably accepted. It follows the same fixed
/// 1-MiB partition and Merkle reduction as the wire protocol, while never
/// encrypting, packaging, or retaining more than the caller's current segment.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BlobStreamPlaintextFrontier {
    frontier: BlobStreamFrontier,
}

impl BlobStreamPlaintextFrontier {
    pub fn new() -> Self {
        Self {
            frontier: BlobStreamFrontier::new(),
        }
    }

    pub fn append(
        &mut self,
        index: u64,
        offset: u64,
        total_len: u64,
        plaintext: &[u8],
    ) -> Result<(), BlobError> {
        let expected_offset = index
            .checked_mul(BLOB_STREAM_SEGMENT_BYTES as u64)
            .ok_or(BlobError::LengthOverflow)?;
        let end = offset
            .checked_add(plaintext.len() as u64)
            .ok_or(BlobError::LengthOverflow)?;
        if total_len == 0
            || offset != expected_offset
            || plaintext.is_empty()
            || plaintext.len() > BLOB_STREAM_SEGMENT_BYTES
            || end > total_len
            || (end < total_len && plaintext.len() != BLOB_STREAM_SEGMENT_BYTES)
        {
            return Err(BlobError::InvalidManifest);
        }
        let position = [
            index.to_be_bytes(),
            offset.to_be_bytes(),
            total_len.to_be_bytes(),
            (plaintext.len() as u64).to_be_bytes(),
        ]
        .concat();
        let ciphertext_len = plaintext
            .len()
            .checked_add(16)
            .ok_or(BlobError::LengthOverflow)? as u64;
        self.frontier.append(BlobStreamSubtree::leaf(
            index,
            BlobStreamSegmentLeaves {
                plaintext: hash_parts(
                    b"ASTER/blob-stream/plain-leaf/v2\0",
                    &[&position, plaintext],
                ),
                // The plaintext projection never consumes this value. Keep a
                // deterministic nonzero placeholder so the shared frontier
                // continues to enforce its structural invariants.
                ciphertext: hash_parts(
                    b"ASTER/blob-stream/plain-frontier-placeholder/v1\0",
                    &[&position],
                ),
                plaintext_len: plaintext.len() as u64,
                ciphertext_len,
            },
        ))
    }

    pub fn checkpoint(&self) -> BlobStreamCheckpoint {
        self.frontier.checkpoint()
    }

    pub fn finish(self, total_len: u64) -> Result<[u8; 32], BlobError> {
        self.frontier
            .finish(total_len)
            .map(|(plaintext, _)| plaintext)
    }
}

impl Default for BlobStreamPlaintextFrontier {
    fn default() -> Self {
        Self::new()
    }
}

fn metadata_commitment(metadata: &BlobMetadata) -> [u8; 32] {
    let mut encoded = Vec::new();
    encode_metadata(&mut encoded, metadata).expect("validated metadata");
    hash_parts(b"ASTER/blob-stream/metadata/v2\0", &[&encoded])
}

fn derive_stream_blob_id(plaintext_root: [u8; 32], total_len: u64, metadata: [u8; 32]) -> BlobId {
    BlobId::from_bytes(hash_parts(
        b"ASTER/blob-stream/blob-id/v2\0",
        &[
            &BLOB_STREAM_FORMAT_VERSION.to_be_bytes(),
            &total_len.to_be_bytes(),
            &plaintext_root,
            &metadata,
        ],
    ))
}

fn push_u16_bytes(output: &mut Vec<u8>, bytes: &[u8]) -> Result<(), BlobError> {
    let len = u16::try_from(bytes.len()).map_err(|_| BlobError::LengthOverflow)?;
    output.extend_from_slice(&len.to_be_bytes());
    output.extend_from_slice(bytes);
    Ok(())
}

fn encode_metadata(output: &mut Vec<u8>, metadata: &BlobMetadata) -> Result<(), BlobError> {
    match metadata.media_type() {
        None => output.push(0),
        Some(media_type) => {
            output.push(1);
            push_u16_bytes(output, media_type.as_bytes())?;
        }
    }
    push_u16_bytes(output, metadata.schema_id())
}

fn decode_metadata(reader: &mut StreamReader<'_>) -> Result<BlobMetadata, BlobError> {
    let media_type = match reader.u8()? {
        0 => None,
        1 => Some(reader.u16_string(crate::MAX_BLOB_MEDIA_TYPE_BYTES)?),
        _ => return Err(BlobError::InvalidMetadata),
    };
    let schema_id = reader.u16_bytes(crate::MAX_BLOB_SCHEMA_ID_BYTES)?.to_vec();
    BlobMetadata::new(media_type, schema_id)
}

fn encode_optional_u64(output: &mut Vec<u8>, value: Option<u64>) {
    match value {
        None => output.push(0),
        Some(value) => {
            output.push(1);
            output.extend_from_slice(&value.to_be_bytes());
        }
    }
}

fn decode_optional_u64(reader: &mut StreamReader<'_>) -> Result<Option<u64>, BlobError> {
    match reader.u8()? {
        0 => Ok(None),
        1 => Ok(Some(reader.u64()?)),
        _ => Err(BlobError::InvalidManifest),
    }
}

fn encode_optional_custody(output: &mut Vec<u8>, value: Option<CustodySample>) {
    match value {
        None => output.push(0),
        Some(value) => {
            output.push(1);
            output.extend_from_slice(&value.clock_id);
            output.extend_from_slice(&value.tick_ms.to_be_bytes());
        }
    }
}

fn decode_optional_custody(
    reader: &mut StreamReader<'_>,
) -> Result<Option<CustodySample>, BlobError> {
    match reader.u8()? {
        0 => Ok(None),
        1 => Ok(Some(CustodySample {
            clock_id: reader.array()?,
            tick_ms: reader.u64()?,
        })),
        _ => Err(BlobError::InvalidManifest),
    }
}

struct StreamReader<'a> {
    bytes: &'a [u8],
    position: usize,
}

impl<'a> StreamReader<'a> {
    const fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, position: 0 }
    }
    fn take(&mut self, len: usize) -> Result<&'a [u8], BlobError> {
        let end = self
            .position
            .checked_add(len)
            .ok_or(BlobError::LengthOverflow)?;
        let value = self
            .bytes
            .get(self.position..end)
            .ok_or(BlobError::InvalidManifest)?;
        self.position = end;
        Ok(value)
    }
    fn array<const N: usize>(&mut self) -> Result<[u8; N], BlobError> {
        self.take(N)?
            .try_into()
            .map_err(|_| BlobError::InvalidManifest)
    }
    fn u8(&mut self) -> Result<u8, BlobError> {
        Ok(self.take(1)?[0])
    }
    fn u16(&mut self) -> Result<u16, BlobError> {
        Ok(u16::from_be_bytes(self.array()?))
    }
    fn u32(&mut self) -> Result<u32, BlobError> {
        Ok(u32::from_be_bytes(self.array()?))
    }
    fn u64(&mut self) -> Result<u64, BlobError> {
        Ok(u64::from_be_bytes(self.array()?))
    }
    fn u16_bytes(&mut self, max: usize) -> Result<&'a [u8], BlobError> {
        let len = usize::from(self.u16()?);
        if len > max {
            return Err(BlobError::InvalidManifest);
        }
        self.take(len)
    }
    fn u16_string(&mut self, max: usize) -> Result<String, BlobError> {
        String::from_utf8(self.u16_bytes(max)?.to_vec()).map_err(|_| BlobError::InvalidManifest)
    }
    fn finish(self) -> Result<(), BlobError> {
        if self.position == self.bytes.len() {
            Ok(())
        } else {
            Err(BlobError::InvalidManifest)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{BlobMetadata, Priority, Scope, Topic, VersionVector};

    const TEST_SEGMENT_BYTES: usize = 32;

    fn identities() -> ([u8; 32], [u8; 32], [u8; 32], [u8; 12]) {
        ([0x11; 32], [0x22; 32], [0x33; 32], [0x44; 12])
    }

    fn partition(index: u64, byte: u8) -> BlobStreamPlainPartition {
        let (stream_id, open_digest, _, _) = identities();
        BlobStreamPlainPartition::new_with_segment_bytes_for_test(
            stream_id,
            open_digest,
            7,
            index,
            index * TEST_SEGMENT_BYTES as u64,
            4 * TEST_SEGMENT_BYTES as u64,
            vec![byte; TEST_SEGMENT_BYTES],
            TEST_SEGMENT_BYTES,
        )
        .expect("valid partition")
    }

    fn single_partition(byte: u8) -> BlobStreamPlainPartition {
        let (stream_id, open_digest, _, _) = identities();
        BlobStreamPlainPartition::new(
            stream_id,
            open_digest,
            7,
            0,
            0,
            TEST_SEGMENT_BYTES as u64,
            vec![byte; TEST_SEGMENT_BYTES],
        )
        .expect("valid final partition")
    }

    fn contexts() -> (BlobStreamSegmentSealer, BlobStreamSegmentOpener) {
        let (stream_id, open_digest, key, nonce) = identities();
        (
            BlobStreamSegmentSealer::new(stream_id, open_digest, 7, key, nonce),
            BlobStreamSegmentOpener::new(stream_id, open_digest, 7, key, nonce),
        )
    }

    fn open_with_len(metadata: BlobMetadata, total_len: u64) -> Result<BlobStreamOpen, BlobError> {
        BlobStreamOpen::new(
            BlobPublicationStreamId::from_bytes([0x11; 32]).expect("stream ID"),
            [0x21; 32],
            b"operation-1".to_vec(),
            [0x31; 32],
            1,
            VersionVector::default(),
            Topic::new("imagery").expect("topic"),
            Scope::new("mission/alpha").expect("scope"),
            metadata,
            Priority::Immediate,
            None,
            None,
            total_len,
            7,
            9,
            [0x41; 32],
            [0x51; 32],
        )
    }

    fn open_with_metadata(metadata: BlobMetadata) -> BlobStreamOpen {
        open_with_len(metadata, BLOB_STREAM_SEGMENT_BYTES as u64).expect("open")
    }

    #[test]
    fn blob_stream_open_has_a_distinct_multi_gibibyte_protocol_bound() {
        assert_eq!(BLOB_STREAM_SEGMENT_BYTES, 1024 * 1024);
        let metadata = BlobMetadata::new(None, Vec::new()).expect("metadata");
        assert!(open_with_len(metadata.clone(), 1024 * 1024 * 1024).is_ok());
        assert!(open_with_len(metadata.clone(), MAX_BLOB_STREAM_BYTES).is_ok());
        assert!(matches!(
            open_with_len(metadata, MAX_BLOB_STREAM_BYTES + 1),
            Err(BlobError::InvalidManifest)
        ));
    }

    #[test]
    fn blob_stream_open_and_final_commitment_round_trip_canonically() {
        let open = open_with_metadata(
            BlobMetadata::new(Some("image/tiff".to_owned()), b"geo".to_vec()).expect("metadata"),
        );
        assert_eq!(
            BlobStreamOpen::decode(&open.encode()).expect("decode"),
            open
        );
        assert_eq!(
            open.content_group(),
            crate::blob::content_group_id(open.scope(), open.topic())
        );
        let verified = VerifiedBlobStreamOpen::for_test(open.clone());
        let commitment = BlobStreamFinalCommitment::new(&verified, [0x61; 32], [0x71; 32], 1, None)
            .expect("commitment");
        assert_eq!(
            BlobStreamFinalCommitment::decode(&commitment.encode()).expect("decode commitment"),
            commitment
        );
    }

    #[test]
    fn blob_stream_final_identity_binds_metadata_and_both_roots() {
        let first = VerifiedBlobStreamOpen::for_test(open_with_metadata(
            BlobMetadata::new(Some("image/tiff".to_owned()), b"geo".to_vec()).expect("metadata"),
        ));
        let second = VerifiedBlobStreamOpen::for_test(open_with_metadata(
            BlobMetadata::new(Some("image/png".to_owned()), b"geo".to_vec()).expect("metadata"),
        ));
        let a =
            BlobStreamFinalCommitment::new(&first, [0x61; 32], [0x71; 32], 1, None).expect("first");
        let metadata_changed =
            BlobStreamFinalCommitment::new(&second, [0x61; 32], [0x71; 32], 1, None)
                .expect("metadata changed");
        let plaintext_changed =
            BlobStreamFinalCommitment::new(&first, [0x62; 32], [0x71; 32], 1, None)
                .expect("plaintext changed");
        let ciphertext_changed =
            BlobStreamFinalCommitment::new(&first, [0x61; 32], [0x72; 32], 1, None)
                .expect("ciphertext changed");
        assert_ne!(a.blob_id(), metadata_changed.blob_id());
        assert_ne!(a.blob_id(), plaintext_changed.blob_id());
        assert_ne!(a.encode(), ciphertext_changed.encode());
    }

    #[test]
    fn blob_stream_segments_seal_and_open_in_any_completion_order() {
        let (sealer, opener) = contexts();
        let mut sealed = (0..4)
            .map(|index| {
                sealer
                    .seal(partition(index, index as u8 + 1))
                    .expect("seal")
            })
            .collect::<Vec<_>>();
        sealed.swap(0, 3);
        sealed.swap(1, 2);
        for (segment, expected_leaves) in sealed {
            let encoded = segment.encode();
            let (header, plaintext, leaves) = opener
                .open_encoded_with_segment_bytes_for_test(&encoded, TEST_SEGMENT_BYTES)
                .expect("decode and open shuffled segment");
            assert_eq!(plaintext[0], header.index as u8 + 1);
            assert_eq!(leaves, expected_leaves);
        }
    }

    #[test]
    fn profile5_segment_is_the_storage_and_wire_partition() {
        let (stream_id, open_digest, key, nonce) = identities();
        let sealer = BlobStreamSegmentSealer::new(stream_id, open_digest, 7, key, nonce);
        let opener = BlobStreamSegmentOpener::new(stream_id, open_digest, 7, key, nonce);
        let total_len = BLOB_STREAM_SEGMENT_BYTES as u64 + 17;
        let plaintexts = [vec![0x5a; BLOB_STREAM_SEGMENT_BYTES], vec![0xa5; 17]];

        for (index, plaintext) in plaintexts.into_iter().enumerate() {
            let offset = index as u64 * BLOB_STREAM_SEGMENT_BYTES as u64;
            let partition = BlobStreamPlainPartition::new(
                stream_id,
                open_digest,
                7,
                index as u64,
                offset,
                total_len,
                plaintext.clone(),
            )
            .expect("canonical Profile-5 partition");
            let (segment, expected_leaves) = sealer.seal(partition).expect("seal segment");
            let encoded = segment.encode();

            assert_eq!(
                encoded.len(),
                plaintext.len() + BLOB_STREAM_SEGMENT_ENCODED_OVERHEAD_BYTES
            );
            assert_eq!(&encoded[..8], b"ASTRBS02");
            let header = EncryptedBlobStreamSegment::inspect_encoded(&encoded)
                .expect("inspect canonical segment");
            assert_eq!(header.stream_id(), &stream_id);
            assert_eq!(header.open_digest(), &open_digest);
            assert_eq!(header.index(), index as u64);
            assert_eq!(header.offset(), offset);
            assert_eq!(header.total_len(), total_len);
            assert_eq!(header.plaintext_len(), plaintext.len() as u32);
            assert_eq!(header.ciphertext_len(), plaintext.len() as u32 + 16);

            let (opened_header, opened, leaves) =
                opener.open_encoded(&encoded).expect("open wire segment");
            assert_eq!(opened_header, header);
            assert_eq!(&*opened, plaintext.as_slice());
            assert_eq!(leaves, expected_leaves);
        }
    }

    #[test]
    fn plaintext_frontier_matches_encrypted_protocol_root_and_prefix() {
        let (stream_id, open_digest, key, nonce) = identities();
        let sealer = BlobStreamSegmentSealer::new(stream_id, open_digest, 7, key, nonce);
        let total_len = BLOB_STREAM_SEGMENT_BYTES as u64 + 17;
        let plaintexts = [vec![0x5a; BLOB_STREAM_SEGMENT_BYTES], vec![0xa5; 17]];
        let mut encrypted = BlobStreamFrontier::new();
        let mut plaintext = BlobStreamPlaintextFrontier::new();

        for (index, bytes) in plaintexts.iter().enumerate() {
            let index = index as u64;
            let offset = index * BLOB_STREAM_SEGMENT_BYTES as u64;
            let partition = BlobStreamPlainPartition::new(
                stream_id,
                open_digest,
                7,
                index,
                offset,
                total_len,
                bytes.clone(),
            )
            .expect("canonical partition");
            let (_, leaves) = sealer.seal(partition).expect("seal partition");
            encrypted
                .append(BlobStreamSubtree::leaf(index, leaves))
                .expect("append encrypted frontier");
            plaintext
                .append(index, offset, total_len, bytes)
                .expect("append plaintext frontier");
            assert_eq!(
                plaintext.checkpoint().plaintext_commitment(),
                encrypted.checkpoint().plaintext_commitment(),
                "resume prefix commitment is independent of encryption"
            );
        }

        assert_eq!(
            plaintext.finish(total_len).expect("plaintext root"),
            encrypted.finish(total_len).expect("protocol roots").0
        );
    }

    #[test]
    fn profile5_empty_and_exact_boundaries_are_canonical() {
        let metadata = BlobMetadata::new(None, Vec::new()).expect("metadata");
        let empty_open = VerifiedBlobStreamOpen::for_test(
            open_with_len(metadata.clone(), 0).expect("empty open"),
        );
        let (empty_plain_root, empty_cipher_root) = BlobStreamFrontier::new()
            .finish(0)
            .expect("empty terminal roots");
        let empty_commitment = BlobStreamFinalCommitment::new(
            &empty_open,
            empty_plain_root,
            empty_cipher_root,
            0,
            None,
        )
        .expect("empty final commitment");
        assert_eq!(empty_commitment.total_len(), 0);
        assert_eq!(empty_commitment.segment_count(), 0);

        let exact_len = 2 * BLOB_STREAM_SEGMENT_BYTES as u64;
        let exact_open = VerifiedBlobStreamOpen::for_test(
            open_with_len(metadata, exact_len).expect("exact-boundary open"),
        );
        let (stream_id, open_digest, key, nonce) = identities();
        let sealer = BlobStreamSegmentSealer::new(stream_id, open_digest, 7, key, nonce);
        let mut frontier = BlobStreamFrontier::new();
        for index in 0..2 {
            let partition = BlobStreamPlainPartition::new(
                stream_id,
                open_digest,
                7,
                index,
                index * BLOB_STREAM_SEGMENT_BYTES as u64,
                exact_len,
                vec![index as u8; BLOB_STREAM_SEGMENT_BYTES],
            )
            .expect("full exact-boundary segment");
            let leaves = sealer.seal(partition).expect("seal").1;
            frontier
                .append(BlobStreamSubtree::leaf(index, leaves))
                .expect("ordered reduction");
        }
        let (plain_root, cipher_root) = frontier.finish(exact_len).expect("exact roots");
        let commitment =
            BlobStreamFinalCommitment::new(&exact_open, plain_root, cipher_root, 2, None)
                .expect("exact-boundary commitment");
        assert_eq!(commitment.segment_count(), 2);
    }

    fn roots_for_order(order: &[usize]) -> ([u8; 32], [u8; 32]) {
        let (sealer, _) = contexts();
        let leaves = (0..4)
            .map(|index| {
                sealer
                    .seal(partition(index, index as u8 + 1))
                    .expect("seal")
                    .1
            })
            .collect::<Vec<_>>();
        let mut ready = order
            .iter()
            .map(|index| BlobStreamSubtree::leaf(*index as u64, leaves[*index]))
            .collect::<Vec<_>>();
        ready.sort_by_key(BlobStreamSubtree::first_index);
        let left = BlobStreamSubtree::combine(ready[0], ready[1]).expect("left");
        let right = BlobStreamSubtree::combine(ready[2], ready[3]).expect("right");
        let mut frontier = BlobStreamFrontier::new();
        frontier
            .append(BlobStreamSubtree::combine(left, right).expect("root"))
            .expect("append");
        frontier
            .finish(4 * TEST_SEGMENT_BYTES as u64)
            .expect("finish")
    }

    #[test]
    fn blob_stream_reduction_matches_for_one_two_and_four_workers() {
        let expected = roots_for_order(&[0, 1, 2, 3]);
        assert_eq!(roots_for_order(&[1, 0, 3, 2]), expected);
        assert_eq!(roots_for_order(&[3, 1, 2, 0]), expected);
    }

    #[test]
    fn plaintext_root_is_stable_across_distinct_publication_contexts() {
        let plaintext = vec![0x5a; 32];
        let make_partition = |stream_id, open_digest| {
            BlobStreamPlainPartition::new(
                stream_id,
                open_digest,
                7,
                0,
                0,
                plaintext.len() as u64,
                plaintext.clone(),
            )
            .expect("partition")
        };
        let first = BlobStreamSegmentSealer::new([0x11; 32], [0x22; 32], 7, [0x33; 32], [0x44; 12])
            .seal(make_partition([0x11; 32], [0x22; 32]))
            .expect("first publication")
            .1;
        let second =
            BlobStreamSegmentSealer::new([0x61; 32], [0x62; 32], 7, [0x63; 32], [0x64; 12])
                .seal(make_partition([0x61; 32], [0x62; 32]))
                .expect("second publication")
                .1;

        assert_eq!(first.plaintext, second.plaintext);
        assert_ne!(first.ciphertext, second.ciphertext);

        let finish = |leaves| {
            let mut frontier = BlobStreamFrontier::new();
            frontier
                .append(BlobStreamSubtree::leaf(0, leaves))
                .expect("append");
            frontier.finish(plaintext.len() as u64).expect("finish")
        };
        let first_roots = finish(first);
        let second_roots = finish(second);
        assert_eq!(first_roots.0, second_roots.0);
        assert_ne!(first_roots.1, second_roots.1);
    }

    #[test]
    fn blob_stream_frontier_restores_the_same_final_roots() {
        let (sealer, _) = contexts();
        let mut frontier = BlobStreamFrontier::new();
        for index in 0..2 {
            let leaves = sealer
                .seal(partition(index, index as u8 + 1))
                .expect("seal")
                .1;
            frontier
                .append(BlobStreamSubtree::leaf(index, leaves))
                .expect("append");
        }
        let checkpoint = frontier.checkpoint();
        let mut restored = BlobStreamFrontier::restore(checkpoint).expect("restore");
        for index in 2..4 {
            let leaves = sealer
                .seal(partition(index, index as u8 + 1))
                .expect("seal")
                .1;
            restored
                .append(BlobStreamSubtree::leaf(index, leaves))
                .expect("append");
        }
        assert_eq!(
            restored
                .finish(4 * TEST_SEGMENT_BYTES as u64)
                .expect("finish"),
            roots_for_order(&[0, 1, 2, 3])
        );
    }

    #[test]
    fn blob_stream_checkpoint_round_trips_fixed_width() {
        let (sealer, _) = contexts();
        let mut frontier = BlobStreamFrontier::new();
        for index in 0..3 {
            let leaves = sealer
                .seal(partition(index, index as u8 + 1))
                .expect("seal")
                .1;
            frontier
                .append(BlobStreamSubtree::leaf(index, leaves))
                .expect("append");
        }
        let checkpoint = frontier.checkpoint();
        let encoded = checkpoint.encode();
        assert_eq!(encoded.len(), BlobStreamCheckpoint::ENCODED_LEN);
        assert_eq!(
            BlobStreamCheckpoint::decode(&encoded).expect("decode"),
            checkpoint
        );
    }

    #[test]
    fn blob_stream_frontier_finishes_non_power_of_two_segment_counts() {
        let (sealer, _) = contexts();
        let mut frontier = BlobStreamFrontier::new();
        for index in 0..3 {
            let leaves = sealer
                .seal(partition(index, index as u8 + 1))
                .expect("seal")
                .1;
            frontier
                .append(BlobStreamSubtree::leaf(index, leaves))
                .expect("append");
        }
        let roots = frontier
            .finish(3 * TEST_SEGMENT_BYTES as u64)
            .expect("three-segment root");
        assert_ne!(roots.0, [0; 32]);
        assert_ne!(roots.1, [0; 32]);
    }

    #[test]
    fn blob_stream_segment_rejects_every_changed_identity_field() {
        let (sealer, opener) = contexts();
        let (segment, _) = sealer.seal(partition(0, 9)).expect("seal");
        for changed in segment.identity_mutations_for_test() {
            assert!(opener.open(&changed).is_err());
        }
    }

    #[test]
    fn blob_stream_segment_round_trips_canonically() {
        let (sealer, opener) = contexts();
        let (segment, expected_leaves) = sealer.seal(single_partition(9)).expect("seal");
        let encoded = segment.encode();
        let decoded = EncryptedBlobStreamSegment::decode(&encoded).expect("decode");
        assert_eq!(decoded, segment);
        let audit = decoded.ciphertext_audit_leaves();
        assert_eq!(audit.ciphertext, expected_leaves.ciphertext);
        assert_eq!(audit.plaintext_len, expected_leaves.plaintext_len);
        assert_eq!(audit.ciphertext_len, expected_leaves.ciphertext_len);
        assert_eq!(opener.open(&decoded).expect("open").1, expected_leaves);
        let (header, plaintext, leaves) = opener.open_encoded(&encoded).expect("open encoded");
        assert_eq!(header, segment.header());
        assert_eq!(plaintext[0], 9);
        assert_eq!(leaves, expected_leaves);
    }
}
