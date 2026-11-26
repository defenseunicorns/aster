//! Canonical data layer for the semantic-v2 content-committing PQ batch profile.
//!
//! Cryptographic key operations, persistence, transport, and runtime policy are
//! deliberately outside this module.

use sha2::{Digest, Sha256};
use std::fmt;

pub(crate) const BATCH_FORMAT_VERSION: u16 = 1;
pub(crate) const ENVELOPE_FORMAT_VERSION: u16 = 3;
pub(crate) const SEMANTIC_PROTOCOL_VERSION: u16 = 2;
pub(crate) const CRYPTO_SUITE: u16 = 1;
pub(crate) const HASH_ALGORITHM: u16 = 1;
pub(crate) const TREE_ALGORITHM: u16 = 1;
pub(crate) const BATCH_SIGNATURE_ALGORITHM: u16 = 1;
pub(crate) const ITEM_SIGNATURE_ALGORITHM: u16 = 1;
pub(crate) const MIN_BATCH_ITEMS: u16 = 2;
pub(crate) const MAX_BATCH_ITEMS: u16 = 64;
pub(crate) const MAX_TOPIC_BYTES: usize = 128;
pub(crate) const MAX_SCOPE_BYTES: usize = 128;
pub(crate) const DATA_CLASS_EVENT: u8 = 1;
pub(crate) const MAX_DATA_CLASS: u8 = 3;
pub(crate) const LEAF_FORMAT_VERSION: u16 = 1;
pub(crate) const OBJECT_KIND_BATCH_PROOF: u8 = 3;
pub(crate) const COMPACT_AUTH_MODE: u8 = 1;
pub(crate) const P256_SIGNATURE_BYTES: usize = 64;
pub(crate) const ML_DSA_65_SIGNATURE_BYTES: usize = 3_309;
pub(crate) const HYBRID_SIGNATURE_BYTES: usize = 3_379;
pub(crate) const ITEM_SIGNATURE_BYTES: usize = 64;
pub(crate) const MIN_CREDENTIAL_GROUPS: u16 = 1;
pub(crate) const MAX_CREDENTIAL_GROUPS: u16 = 256;
pub(crate) const CREDENTIAL_BODY_BASE_BYTES: usize = 3_264;
pub(crate) const CREDENTIAL_BODY_GROUP_BYTES: usize = 32;
pub(crate) const PROOF_ENVELOPE_FIXED_OVERHEAD: usize = 60;
pub(crate) const SINGLETON_AUTH_BASE_BYTES: usize = 10_058;

const _: () =
    assert!(HYBRID_SIGNATURE_BYTES == 2 + P256_SIGNATURE_BYTES + 4 + ML_DSA_65_SIGNATURE_BYTES);

const PREAMBLE_DOMAIN: &[u8] = b"aster/pq-batch-preamble/v1";
const LEAF_DOMAIN: &[u8] = b"aster/pq-batch-leaf/v1";
const EMPTY_LEAF_DOMAIN: &[u8] = b"aster/pq-batch-empty/v1";
const TREE_NODE_DOMAIN: &[u8] = b"aster/pq-batch-node/v1";
const BATCH_ID_DOMAIN: &[u8] = b"aster/pq-batch-id/v1";
const BATCH_SIGNATURE_DOMAIN: &[u8] = b"aster/pq-batch-signature/v1";
const CREDENTIAL_ID_DOMAIN: &[u8] = b"aster/pq-batch-credential/v1";
const ITEM_SIGNATURE_DOMAIN: &[u8] = b"aster/pq-batch-item-ecdsa/v1";

pub(crate) type Hash32 = [u8; 32];
pub(crate) type BatchResult<T> = Result<T, BatchError>;

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum BatchError {
    InvalidConstant(&'static str),
    InvalidDataClass(u8),
    InvalidItemCount(u16),
    InvalidTopicLength(usize),
    InvalidScopeLength(usize),
    InvalidTopicSyntax,
    InvalidScopeSyntax,
    InvalidFirstCounter,
    InvalidEventSequence,
    CounterRangeOverflow,
    InvalidLeafFormat,
    InvalidItemIndex(u16),
    ItemCountMismatch,
    DuplicateItemId,
    InvalidHeaderLength(usize),
    CiphertextLengthMismatch,
    CiphertextHashMismatch,
    InvalidProofDepth { expected: usize, actual: usize },
    MerkleRootMismatch,
    InvalidObjectKind(u8),
    InvalidAuthMode(u8),
    InvalidCredentialLength(usize),
    InvalidSignatureLength { field: &'static str, actual: usize },
    InvalidSignatureEncoding(&'static str),
    CredentialIdMismatch,
    BatchIdMismatch,
    ProofEnvelopeIdMismatch,
    ItemIndexMismatch,
    LengthOverflow,
    Truncated,
    TrailingBytes,
    InvalidUtf8(&'static str),
}

impl fmt::Display for BatchError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidConstant(name) => write!(f, "invalid {name}"),
            Self::InvalidDataClass(value) => write!(f, "invalid data class {value}"),
            Self::InvalidItemCount(value) => write!(f, "invalid batch item count {value}"),
            Self::InvalidTopicLength(value) => write!(f, "invalid topic length {value}"),
            Self::InvalidScopeLength(value) => write!(f, "invalid scope length {value}"),
            Self::InvalidTopicSyntax => write!(f, "invalid canonical topic syntax"),
            Self::InvalidScopeSyntax => write!(f, "invalid canonical scope syntax"),
            Self::InvalidFirstCounter => write!(f, "first causal counter must be nonzero"),
            Self::InvalidEventSequence => write!(f, "invalid first event sequence"),
            Self::CounterRangeOverflow => write!(f, "batch counter range overflows"),
            Self::InvalidLeafFormat => write!(f, "invalid batch leaf format"),
            Self::InvalidItemIndex(value) => write!(f, "invalid batch item index {value}"),
            Self::ItemCountMismatch => write!(f, "batch item count does not match manifest"),
            Self::DuplicateItemId => write!(f, "duplicate item identifier in batch"),
            Self::InvalidHeaderLength(value) => {
                write!(f, "invalid canonical header length {value}")
            }
            Self::CiphertextLengthMismatch => write!(f, "content ciphertext length mismatch"),
            Self::CiphertextHashMismatch => write!(f, "content ciphertext hash mismatch"),
            Self::InvalidProofDepth { expected, actual } => {
                write!(f, "invalid proof depth {actual}; expected {expected}")
            }
            Self::MerkleRootMismatch => write!(f, "Merkle proof does not match manifest root"),
            Self::InvalidObjectKind(value) => write!(f, "invalid object kind {value}"),
            Self::InvalidAuthMode(value) => {
                write!(f, "invalid compact authentication mode {value}")
            }
            Self::InvalidCredentialLength(value) => {
                write!(f, "invalid credential body length {value}")
            }
            Self::InvalidSignatureLength { field, actual } => {
                write!(f, "invalid {field} length {actual}")
            }
            Self::InvalidSignatureEncoding(field) => {
                write!(f, "invalid canonical {field} encoding")
            }
            Self::CredentialIdMismatch => write!(f, "credential identifier mismatch"),
            Self::BatchIdMismatch => write!(f, "batch identifier mismatch"),
            Self::ProofEnvelopeIdMismatch => write!(f, "proof envelope identifier mismatch"),
            Self::ItemIndexMismatch => write!(f, "compact authentication item index mismatch"),
            Self::LengthOverflow => write!(f, "encoded length overflows"),
            Self::Truncated => write!(f, "truncated batch encoding"),
            Self::TrailingBytes => write!(f, "trailing bytes in batch encoding"),
            Self::InvalidUtf8(field) => write!(f, "invalid UTF-8 in {field}"),
        }
    }
}

impl std::error::Error for BatchError {}

fn hash_domain(domain: &[u8], input: &[u8]) -> BatchResult<Hash32> {
    let domain_len = u64::try_from(domain.len()).map_err(|_| BatchError::LengthOverflow)?;
    let input_len = u64::try_from(input.len()).map_err(|_| BatchError::LengthOverflow)?;
    let mut hasher = Sha256::new();
    hasher.update(domain_len.to_be_bytes());
    hasher.update(domain);
    hasher.update(input_len.to_be_bytes());
    hasher.update(input);
    Ok(hasher.finalize().into())
}

fn sha256(input: &[u8]) -> Hash32 {
    Sha256::digest(input).into()
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct BatchPreamble {
    pub(crate) data_class: u8,
    pub(crate) credential_id: Hash32,
    pub(crate) publisher: Hash32,
    pub(crate) topic: String,
    pub(crate) scope: String,
    pub(crate) key_epoch: u64,
    pub(crate) first_causal_counter: u64,
    pub(crate) first_event_sequence: u64,
    pub(crate) item_count: u16,
}

impl BatchPreamble {
    pub(crate) fn validate(&self) -> BatchResult<()> {
        if self.data_class > MAX_DATA_CLASS {
            return Err(BatchError::InvalidDataClass(self.data_class));
        }
        if !(MIN_BATCH_ITEMS..=MAX_BATCH_ITEMS).contains(&self.item_count) {
            return Err(BatchError::InvalidItemCount(self.item_count));
        }
        let topic_len = self.topic.len();
        if topic_len == 0 || topic_len > MAX_TOPIC_BYTES {
            return Err(BatchError::InvalidTopicLength(topic_len));
        }
        if !self.topic.bytes().all(is_topic_byte) {
            return Err(BatchError::InvalidTopicSyntax);
        }
        let scope_len = self.scope.len();
        if scope_len == 0 || scope_len > MAX_SCOPE_BYTES {
            return Err(BatchError::InvalidScopeLength(scope_len));
        }
        if !is_canonical_scope(&self.scope) {
            return Err(BatchError::InvalidScopeSyntax);
        }
        if self.first_causal_counter == 0 {
            return Err(BatchError::InvalidFirstCounter);
        }
        let span = u64::from(self.item_count - 1);
        self.first_causal_counter
            .checked_add(span)
            .ok_or(BatchError::CounterRangeOverflow)?;
        if self.data_class == DATA_CLASS_EVENT {
            if self.first_event_sequence == 0 {
                return Err(BatchError::InvalidEventSequence);
            }
            self.first_event_sequence
                .checked_add(span)
                .ok_or(BatchError::CounterRangeOverflow)?;
        } else if self.first_event_sequence != 0 {
            return Err(BatchError::InvalidEventSequence);
        }
        Ok(())
    }

    pub(crate) fn encode(&self) -> BatchResult<Vec<u8>> {
        self.validate()?;
        let mut out = Vec::with_capacity(111 + self.topic.len() + self.scope.len());
        put_u16(&mut out, BATCH_FORMAT_VERSION);
        put_u16(&mut out, ENVELOPE_FORMAT_VERSION);
        put_u16(&mut out, SEMANTIC_PROTOCOL_VERSION);
        put_u16(&mut out, CRYPTO_SUITE);
        put_u16(&mut out, HASH_ALGORITHM);
        put_u16(&mut out, TREE_ALGORITHM);
        put_u16(&mut out, BATCH_SIGNATURE_ALGORITHM);
        put_u16(&mut out, ITEM_SIGNATURE_ALGORITHM);
        out.push(self.data_class);
        out.extend_from_slice(&self.credential_id);
        out.extend_from_slice(&self.publisher);
        put_short_bytes(&mut out, self.topic.as_bytes())?;
        put_short_bytes(&mut out, self.scope.as_bytes())?;
        put_u64(&mut out, self.key_epoch);
        put_u64(&mut out, self.first_causal_counter);
        put_u64(&mut out, self.first_event_sequence);
        put_u16(&mut out, self.item_count);
        Ok(out)
    }

    pub(crate) fn decode(input: &[u8]) -> BatchResult<Self> {
        let mut cursor = Cursor::new(input);
        let value = Self::decode_from(&mut cursor)?;
        cursor.finish()?;
        Ok(value)
    }

    fn decode_from(cursor: &mut Cursor<'_>) -> BatchResult<Self> {
        expect_u16(cursor, BATCH_FORMAT_VERSION, "batch format")?;
        expect_u16(cursor, ENVELOPE_FORMAT_VERSION, "envelope format")?;
        expect_u16(cursor, SEMANTIC_PROTOCOL_VERSION, "semantic protocol")?;
        expect_u16(cursor, CRYPTO_SUITE, "crypto suite")?;
        expect_u16(cursor, HASH_ALGORITHM, "hash algorithm")?;
        expect_u16(cursor, TREE_ALGORITHM, "tree algorithm")?;
        expect_u16(
            cursor,
            BATCH_SIGNATURE_ALGORITHM,
            "batch signature algorithm",
        )?;
        expect_u16(cursor, ITEM_SIGNATURE_ALGORITHM, "item signature algorithm")?;
        let data_class = cursor.u8()?;
        let credential_id = cursor.array()?;
        let publisher = cursor.array()?;
        let topic = cursor.short_string("topic")?;
        let scope = cursor.short_string("scope")?;
        let value = Self {
            data_class,
            credential_id,
            publisher,
            topic,
            scope,
            key_epoch: cursor.u64()?,
            first_causal_counter: cursor.u64()?,
            first_event_sequence: cursor.u64()?,
            item_count: cursor.u16()?,
        };
        value.validate()?;
        Ok(value)
    }

    pub(crate) fn digest(&self) -> BatchResult<Hash32> {
        hash_domain(PREAMBLE_DOMAIN, &self.encode()?)
    }
}

fn is_topic_byte(value: u8) -> bool {
    value.is_ascii_alphanumeric() || matches!(value, b'.' | b'_' | b'-')
}

fn is_canonical_scope(scope: &str) -> bool {
    scope
        .bytes()
        .all(|value| is_topic_byte(value) || value == b'/')
        && scope
            .split('/')
            .all(|segment| !segment.is_empty() && segment != "." && segment != "..")
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct BatchManifest {
    pub(crate) preamble: BatchPreamble,
    pub(crate) merkle_root: Hash32,
}

impl BatchManifest {
    pub(crate) fn encode(&self) -> BatchResult<Vec<u8>> {
        let mut out = self.preamble.encode()?;
        out.extend_from_slice(&self.merkle_root);
        Ok(out)
    }

    pub(crate) fn decode(input: &[u8]) -> BatchResult<Self> {
        let mut cursor = Cursor::new(input);
        let value = Self::decode_from(&mut cursor)?;
        cursor.finish()?;
        Ok(value)
    }

    fn decode_from(cursor: &mut Cursor<'_>) -> BatchResult<Self> {
        Ok(Self {
            preamble: BatchPreamble::decode_from(cursor)?,
            merkle_root: cursor.array()?,
        })
    }

    pub(crate) fn batch_id(&self) -> BatchResult<Hash32> {
        hash_domain(BATCH_ID_DOMAIN, &self.encode()?)
    }

    pub(crate) fn signature_digest(&self) -> BatchResult<Hash32> {
        hash_domain(BATCH_SIGNATURE_DOMAIN, &self.encode()?)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct BatchLeaf {
    pub(crate) item_index: u16,
    pub(crate) item_id: Hash32,
    pub(crate) canonical_header: Vec<u8>,
    pub(crate) content_group: Hash32,
    pub(crate) content_nonce: [u8; 12],
    pub(crate) content_ciphertext_length: u64,
    pub(crate) content_ciphertext_hash: Hash32,
}

impl BatchLeaf {
    pub(crate) fn from_ciphertext(
        item_index: u16,
        item_id: Hash32,
        canonical_header: Vec<u8>,
        content_group: Hash32,
        content_nonce: [u8; 12],
        content_ciphertext: &[u8],
    ) -> BatchResult<Self> {
        let content_ciphertext_length =
            u64::try_from(content_ciphertext.len()).map_err(|_| BatchError::LengthOverflow)?;
        let value = Self {
            item_index,
            item_id,
            canonical_header,
            content_group,
            content_nonce,
            content_ciphertext_length,
            content_ciphertext_hash: sha256(content_ciphertext),
        };
        value.validate()?;
        Ok(value)
    }

    pub(crate) fn validate(&self) -> BatchResult<()> {
        if self.canonical_header.is_empty() || self.canonical_header.len() > u32::MAX as usize {
            return Err(BatchError::InvalidHeaderLength(self.canonical_header.len()));
        }
        Ok(())
    }

    pub(crate) fn verify_ciphertext(&self, ciphertext: &[u8]) -> BatchResult<()> {
        let actual_len = u64::try_from(ciphertext.len()).map_err(|_| BatchError::LengthOverflow)?;
        if actual_len != self.content_ciphertext_length {
            return Err(BatchError::CiphertextLengthMismatch);
        }
        if sha256(ciphertext) != self.content_ciphertext_hash {
            return Err(BatchError::CiphertextHashMismatch);
        }
        Ok(())
    }

    pub(crate) fn encode(&self) -> BatchResult<Vec<u8>> {
        self.validate()?;
        let capacity = 124usize
            .checked_add(self.canonical_header.len())
            .ok_or(BatchError::LengthOverflow)?;
        let mut out = Vec::with_capacity(capacity);
        put_u16(&mut out, LEAF_FORMAT_VERSION);
        put_u16(&mut out, self.item_index);
        out.extend_from_slice(&self.item_id);
        put_u32(
            &mut out,
            u32::try_from(self.canonical_header.len()).map_err(|_| BatchError::LengthOverflow)?,
        );
        out.extend_from_slice(&self.canonical_header);
        out.extend_from_slice(&self.content_group);
        out.extend_from_slice(&self.content_nonce);
        put_u64(&mut out, self.content_ciphertext_length);
        out.extend_from_slice(&self.content_ciphertext_hash);
        Ok(out)
    }

    pub(crate) fn decode(input: &[u8]) -> BatchResult<Self> {
        let mut cursor = Cursor::new(input);
        let value = Self::decode_from(&mut cursor)?;
        cursor.finish()?;
        Ok(value)
    }

    fn decode_from(cursor: &mut Cursor<'_>) -> BatchResult<Self> {
        if cursor.u16()? != LEAF_FORMAT_VERSION {
            return Err(BatchError::InvalidLeafFormat);
        }
        let item_index = cursor.u16()?;
        let item_id = cursor.array()?;
        let header_len = usize::try_from(cursor.u32()?).map_err(|_| BatchError::LengthOverflow)?;
        let canonical_header = cursor.take(header_len)?.to_vec();
        let value = Self {
            item_index,
            item_id,
            canonical_header,
            content_group: cursor.array()?,
            content_nonce: cursor.array()?,
            content_ciphertext_length: cursor.u64()?,
            content_ciphertext_hash: cursor.array()?,
        };
        value.validate()?;
        Ok(value)
    }

    pub(crate) fn leaf_hash(&self) -> BatchResult<Hash32> {
        hash_domain(LEAF_DOMAIN, &self.encode()?)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct BatchMerkleTree {
    pub(crate) root: Hash32,
    paths: Vec<Vec<Hash32>>,
}

impl BatchMerkleTree {
    pub(crate) fn build(preamble: &BatchPreamble, leaves: &[BatchLeaf]) -> BatchResult<Self> {
        preamble.validate()?;
        if leaves.len() != usize::from(preamble.item_count) {
            return Err(BatchError::ItemCountMismatch);
        }
        for (index, leaf) in leaves.iter().enumerate() {
            let expected = u16::try_from(index).map_err(|_| BatchError::LengthOverflow)?;
            if leaf.item_index != expected {
                return Err(BatchError::InvalidItemIndex(leaf.item_index));
            }
            leaf.validate()?;
            if leaves[..index]
                .iter()
                .any(|prior| prior.item_id == leaf.item_id)
            {
                return Err(BatchError::DuplicateItemId);
            }
        }

        let width = usize::from(preamble.item_count).next_power_of_two();
        let mut nodes = Vec::with_capacity(width);
        for leaf in leaves {
            nodes.push(leaf.leaf_hash()?);
        }
        let preamble_hash = preamble.digest()?;
        for index in usize::from(preamble.item_count)..width {
            let index = u16::try_from(index).map_err(|_| BatchError::LengthOverflow)?;
            let mut input = [0u8; 34];
            input[..32].copy_from_slice(&preamble_hash);
            input[32..].copy_from_slice(&index.to_be_bytes());
            nodes.push(hash_domain(EMPTY_LEAF_DOMAIN, &input)?);
        }

        let mut paths = vec![Vec::new(); leaves.len()];
        let mut level = 0usize;
        while nodes.len() > 1 {
            for (item_index, path) in paths.iter_mut().enumerate() {
                let position = item_index >> level;
                path.push(nodes[position ^ 1]);
            }
            let mut parents = Vec::with_capacity(nodes.len() / 2);
            for pair in nodes.chunks_exact(2) {
                let mut input = [0u8; 64];
                input[..32].copy_from_slice(&pair[0]);
                input[32..].copy_from_slice(&pair[1]);
                parents.push(hash_domain(TREE_NODE_DOMAIN, &input)?);
            }
            nodes = parents;
            level += 1;
        }
        Ok(Self {
            root: nodes[0],
            paths,
        })
    }

    pub(crate) fn path(&self, item_index: u16) -> BatchResult<&[Hash32]> {
        self.paths
            .get(usize::from(item_index))
            .map(Vec::as_slice)
            .ok_or(BatchError::InvalidItemIndex(item_index))
    }
}

pub(crate) fn expected_proof_depth(item_count: u16) -> BatchResult<usize> {
    if !(MIN_BATCH_ITEMS..=MAX_BATCH_ITEMS).contains(&item_count) {
        return Err(BatchError::InvalidItemCount(item_count));
    }
    Ok(usize::from(item_count).next_power_of_two().trailing_zeros() as usize)
}

pub(crate) fn verify_inclusion_path(
    manifest: &BatchManifest,
    leaf: &BatchLeaf,
    siblings: &[Hash32],
) -> BatchResult<()> {
    manifest.preamble.validate()?;
    if leaf.item_index >= manifest.preamble.item_count {
        return Err(BatchError::InvalidItemIndex(leaf.item_index));
    }
    let expected = expected_proof_depth(manifest.preamble.item_count)?;
    if siblings.len() != expected {
        return Err(BatchError::InvalidProofDepth {
            expected,
            actual: siblings.len(),
        });
    }
    let mut current = leaf.leaf_hash()?;
    let mut position = usize::from(leaf.item_index);
    for sibling in siblings {
        let mut input = [0u8; 64];
        if position & 1 == 0 {
            input[..32].copy_from_slice(&current);
            input[32..].copy_from_slice(sibling);
        } else {
            input[..32].copy_from_slice(sibling);
            input[32..].copy_from_slice(&current);
        }
        current = hash_domain(TREE_NODE_DOMAIN, &input)?;
        position >>= 1;
    }
    if current != manifest.merkle_root {
        return Err(BatchError::MerkleRootMismatch);
    }
    Ok(())
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct CompactAuthentication {
    pub(crate) proof_envelope_id: Hash32,
    pub(crate) batch_id: Hash32,
    pub(crate) item_index: u16,
    pub(crate) siblings: Vec<Hash32>,
    pub(crate) item_signature: [u8; ITEM_SIGNATURE_BYTES],
}

impl CompactAuthentication {
    pub(crate) fn validate(&self) -> BatchResult<()> {
        if self.siblings.is_empty() || self.siblings.len() > 6 {
            return Err(BatchError::InvalidProofDepth {
                expected: 1,
                actual: self.siblings.len(),
            });
        }
        Ok(())
    }

    pub(crate) fn encode(&self) -> BatchResult<Vec<u8>> {
        self.validate()?;
        let capacity = 132usize
            .checked_add(
                self.siblings
                    .len()
                    .checked_mul(32)
                    .ok_or(BatchError::LengthOverflow)?,
            )
            .ok_or(BatchError::LengthOverflow)?;
        let mut out = Vec::with_capacity(capacity);
        out.push(COMPACT_AUTH_MODE);
        out.extend_from_slice(&self.proof_envelope_id);
        out.extend_from_slice(&self.batch_id);
        put_u16(&mut out, self.item_index);
        out.push(u8::try_from(self.siblings.len()).map_err(|_| BatchError::LengthOverflow)?);
        for sibling in &self.siblings {
            out.extend_from_slice(sibling);
        }
        out.extend_from_slice(&self.item_signature);
        Ok(out)
    }

    pub(crate) fn decode(input: &[u8]) -> BatchResult<Self> {
        let mut cursor = Cursor::new(input);
        let mode = cursor.u8()?;
        if mode != COMPACT_AUTH_MODE {
            return Err(BatchError::InvalidAuthMode(mode));
        }
        let proof_envelope_id = cursor.array()?;
        let batch_id = cursor.array()?;
        let item_index = cursor.u16()?;
        let depth = usize::from(cursor.u8()?);
        if !(1..=6).contains(&depth) {
            return Err(BatchError::InvalidProofDepth {
                expected: 1,
                actual: depth,
            });
        }
        let mut siblings = Vec::with_capacity(depth);
        for _ in 0..depth {
            siblings.push(cursor.array()?);
        }
        let value = Self {
            proof_envelope_id,
            batch_id,
            item_index,
            siblings,
            item_signature: cursor.array()?,
        };
        cursor.finish()?;
        value.validate()?;
        Ok(value)
    }

    pub(crate) fn signature_digest(&self, leaf_hash: Hash32) -> BatchResult<Hash32> {
        let mut input = [0u8; 96];
        input[..32].copy_from_slice(&self.batch_id);
        input[32..64].copy_from_slice(&self.proof_envelope_id);
        input[64..].copy_from_slice(&leaf_hash);
        hash_domain(ITEM_SIGNATURE_DOMAIN, &input)
    }
}

pub(crate) fn verify_compact_commitment(
    manifest: &BatchManifest,
    proof_envelope_id: Hash32,
    leaf: &BatchLeaf,
    ciphertext: &[u8],
    authentication: &CompactAuthentication,
) -> BatchResult<Hash32> {
    authentication.validate()?;
    if authentication.proof_envelope_id != proof_envelope_id {
        return Err(BatchError::ProofEnvelopeIdMismatch);
    }
    if authentication.batch_id != manifest.batch_id()? {
        return Err(BatchError::BatchIdMismatch);
    }
    if authentication.item_index != leaf.item_index {
        return Err(BatchError::ItemIndexMismatch);
    }
    leaf.verify_ciphertext(ciphertext)?;
    verify_inclusion_path(manifest, leaf, &authentication.siblings)?;
    authentication.signature_digest(leaf.leaf_hash()?)
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct BatchProofRoute {
    pub(crate) credential_body: Vec<u8>,
    pub(crate) authority_signature: Vec<u8>,
    pub(crate) manifest: BatchManifest,
    pub(crate) source_signature: Vec<u8>,
}

impl BatchProofRoute {
    /// Validates only canonical framing, bounded lengths, and commitments.
    ///
    /// This method deliberately does not authenticate either signature. A
    /// provider must cryptographically verify the credential, authority
    /// signature, and source signature before treating the route as accepted.
    pub(crate) fn validate_structure(&self) -> BatchResult<()> {
        credential_group_count(self.credential_body.len())?;
        validate_hybrid_signature_encoding("authority signature", &self.authority_signature)?;
        validate_hybrid_signature_encoding("source signature", &self.source_signature)?;
        self.manifest.preamble.validate()?;
        if credential_id(&self.credential_body, &self.authority_signature)?
            != self.manifest.preamble.credential_id
        {
            return Err(BatchError::CredentialIdMismatch);
        }
        Ok(())
    }

    pub(crate) fn encode(&self) -> BatchResult<Vec<u8>> {
        self.validate_structure()?;
        let manifest = self.manifest.encode()?;
        let capacity = 5usize
            .checked_add(self.credential_body.len())
            .and_then(|value| value.checked_add(self.authority_signature.len()))
            .and_then(|value| value.checked_add(manifest.len()))
            .and_then(|value| value.checked_add(self.source_signature.len()))
            .ok_or(BatchError::LengthOverflow)?;
        let mut out = Vec::with_capacity(capacity);
        out.push(OBJECT_KIND_BATCH_PROOF);
        put_u32(
            &mut out,
            u32::try_from(self.credential_body.len()).map_err(|_| BatchError::LengthOverflow)?,
        );
        out.extend_from_slice(&self.credential_body);
        out.extend_from_slice(&self.authority_signature);
        out.extend_from_slice(&manifest);
        out.extend_from_slice(&self.source_signature);
        Ok(out)
    }

    pub(crate) fn decode(input: &[u8]) -> BatchResult<Self> {
        let mut cursor = Cursor::new(input);
        let kind = cursor.u8()?;
        if kind != OBJECT_KIND_BATCH_PROOF {
            return Err(BatchError::InvalidObjectKind(kind));
        }
        let credential_len =
            usize::try_from(cursor.u32()?).map_err(|_| BatchError::LengthOverflow)?;
        credential_group_count(credential_len)?;
        let credential_body = cursor.take(credential_len)?.to_vec();
        let authority_signature = cursor.take(HYBRID_SIGNATURE_BYTES)?.to_vec();
        let manifest = BatchManifest::decode_from(&mut cursor)?;
        let source_signature = cursor.take(HYBRID_SIGNATURE_BYTES)?.to_vec();
        cursor.finish()?;
        let value = Self {
            credential_body,
            authority_signature,
            manifest,
            source_signature,
        };
        value.validate_structure()?;
        Ok(value)
    }
}

pub(crate) fn credential_body_len(group_count: u16) -> BatchResult<usize> {
    if !(MIN_CREDENTIAL_GROUPS..=MAX_CREDENTIAL_GROUPS).contains(&group_count) {
        return Err(BatchError::InvalidCredentialLength(0));
    }
    CREDENTIAL_BODY_BASE_BYTES
        .checked_add(
            usize::from(group_count)
                .checked_mul(CREDENTIAL_BODY_GROUP_BYTES)
                .ok_or(BatchError::LengthOverflow)?,
        )
        .ok_or(BatchError::LengthOverflow)
}

pub(crate) fn credential_group_count(body_len: usize) -> BatchResult<u16> {
    let minimum = credential_body_len(MIN_CREDENTIAL_GROUPS)?;
    let maximum = credential_body_len(MAX_CREDENTIAL_GROUPS)?;
    if body_len < minimum || body_len > maximum {
        return Err(BatchError::InvalidCredentialLength(body_len));
    }
    let variable = body_len - CREDENTIAL_BODY_BASE_BYTES;
    if !variable.is_multiple_of(CREDENTIAL_BODY_GROUP_BYTES) {
        return Err(BatchError::InvalidCredentialLength(body_len));
    }
    let groups = variable / CREDENTIAL_BODY_GROUP_BYTES;
    u16::try_from(groups).map_err(|_| BatchError::InvalidCredentialLength(body_len))
}

fn validate_hybrid_signature_encoding(field: &'static str, signature: &[u8]) -> BatchResult<()> {
    if signature.len() != HYBRID_SIGNATURE_BYTES {
        return Err(BatchError::InvalidSignatureLength {
            field,
            actual: signature.len(),
        });
    }
    let p256_length = u16::from_be_bytes([signature[0], signature[1]]);
    let ml_dsa_length_offset = 2 + P256_SIGNATURE_BYTES;
    let ml_dsa_length = u32::from_be_bytes([
        signature[ml_dsa_length_offset],
        signature[ml_dsa_length_offset + 1],
        signature[ml_dsa_length_offset + 2],
        signature[ml_dsa_length_offset + 3],
    ]);
    if usize::from(p256_length) != P256_SIGNATURE_BYTES
        || usize::try_from(ml_dsa_length).ok() != Some(ML_DSA_65_SIGNATURE_BYTES)
    {
        return Err(BatchError::InvalidSignatureEncoding(field));
    }
    Ok(())
}

#[cfg(any(test, feature = "adapter-sdk"))]
fn structurally_valid_hybrid_signature(p256_fill: u8, ml_dsa_fill: u8) -> Vec<u8> {
    let mut signature = Vec::with_capacity(HYBRID_SIGNATURE_BYTES);
    put_u16(&mut signature, P256_SIGNATURE_BYTES as u16);
    signature.extend(std::iter::repeat_n(p256_fill, P256_SIGNATURE_BYTES));
    put_u32(&mut signature, ML_DSA_65_SIGNATURE_BYTES as u32);
    signature.extend(std::iter::repeat_n(ml_dsa_fill, ML_DSA_65_SIGNATURE_BYTES));
    debug_assert_eq!(signature.len(), HYBRID_SIGNATURE_BYTES);
    signature
}

pub(crate) fn credential_id(body: &[u8], authority_signature: &[u8]) -> BatchResult<Hash32> {
    credential_group_count(body.len())?;
    validate_hybrid_signature_encoding("authority signature", authority_signature)?;
    let mut input = Vec::with_capacity(body.len() + authority_signature.len());
    input.extend_from_slice(body);
    input.extend_from_slice(authority_signature);
    hash_domain(CREDENTIAL_ID_DOMAIN, &input)
}

pub(crate) fn proof_envelope_id(exact_envelope: &[u8]) -> Hash32 {
    sha256(exact_envelope)
}

pub(crate) fn singleton_auth_len(group_count: u16) -> BatchResult<usize> {
    if !(MIN_CREDENTIAL_GROUPS..=MAX_CREDENTIAL_GROUPS).contains(&group_count) {
        return Err(BatchError::InvalidCredentialLength(0));
    }
    SINGLETON_AUTH_BASE_BYTES
        .checked_add(
            usize::from(group_count)
                .checked_mul(CREDENTIAL_BODY_GROUP_BYTES)
                .ok_or(BatchError::LengthOverflow)?,
        )
        .ok_or(BatchError::LengthOverflow)
}

pub(crate) fn expected_proof_envelope_len(
    group_count: u16,
    topic_len: usize,
    scope_len: usize,
) -> BatchResult<usize> {
    if topic_len == 0 || topic_len > MAX_TOPIC_BYTES {
        return Err(BatchError::InvalidTopicLength(topic_len));
    }
    if scope_len == 0 || scope_len > MAX_SCOPE_BYTES {
        return Err(BatchError::InvalidScopeLength(scope_len));
    }
    let manifest_len = 143usize
        .checked_add(topic_len)
        .and_then(|value| value.checked_add(scope_len))
        .ok_or(BatchError::LengthOverflow)?;
    5usize
        .checked_add(credential_body_len(group_count)?)
        .and_then(|value| value.checked_add(HYBRID_SIGNATURE_BYTES))
        .and_then(|value| value.checked_add(manifest_len))
        .and_then(|value| value.checked_add(HYBRID_SIGNATURE_BYTES))
        .and_then(|value| value.checked_add(PROOF_ENVELOPE_FIXED_OVERHEAD))
        .ok_or(BatchError::LengthOverflow)
}

pub(crate) fn expected_compact_auth_len(item_count: u16) -> BatchResult<usize> {
    132usize
        .checked_add(
            expected_proof_depth(item_count)?
                .checked_mul(32)
                .ok_or(BatchError::LengthOverflow)?,
        )
        .ok_or(BatchError::LengthOverflow)
}

pub(crate) fn expected_batch_auth_len(
    group_count: u16,
    topic_len: usize,
    scope_len: usize,
    item_count: u16,
) -> BatchResult<usize> {
    expected_proof_envelope_len(group_count, topic_len, scope_len)?
        .checked_add(
            usize::from(item_count)
                .checked_mul(expected_compact_auth_len(item_count)?)
                .ok_or(BatchError::LengthOverflow)?,
        )
        .ok_or(BatchError::LengthOverflow)
}

fn put_u16(out: &mut Vec<u8>, value: u16) {
    out.extend_from_slice(&value.to_be_bytes());
}

fn put_u32(out: &mut Vec<u8>, value: u32) {
    out.extend_from_slice(&value.to_be_bytes());
}

fn put_u64(out: &mut Vec<u8>, value: u64) {
    out.extend_from_slice(&value.to_be_bytes());
}

fn put_short_bytes(out: &mut Vec<u8>, value: &[u8]) -> BatchResult<()> {
    let len = u16::try_from(value.len()).map_err(|_| BatchError::LengthOverflow)?;
    put_u16(out, len);
    out.extend_from_slice(value);
    Ok(())
}

fn expect_u16(cursor: &mut Cursor<'_>, expected: u16, name: &'static str) -> BatchResult<()> {
    if cursor.u16()? == expected {
        Ok(())
    } else {
        Err(BatchError::InvalidConstant(name))
    }
}

struct Cursor<'a> {
    input: &'a [u8],
    offset: usize,
}

impl<'a> Cursor<'a> {
    fn new(input: &'a [u8]) -> Self {
        Self { input, offset: 0 }
    }

    fn take(&mut self, len: usize) -> BatchResult<&'a [u8]> {
        let end = self
            .offset
            .checked_add(len)
            .ok_or(BatchError::LengthOverflow)?;
        let value = self
            .input
            .get(self.offset..end)
            .ok_or(BatchError::Truncated)?;
        self.offset = end;
        Ok(value)
    }

    fn array<const N: usize>(&mut self) -> BatchResult<[u8; N]> {
        self.take(N)?.try_into().map_err(|_| BatchError::Truncated)
    }

    fn u8(&mut self) -> BatchResult<u8> {
        Ok(self.take(1)?[0])
    }

    fn u16(&mut self) -> BatchResult<u16> {
        Ok(u16::from_be_bytes(self.array()?))
    }

    fn u32(&mut self) -> BatchResult<u32> {
        Ok(u32::from_be_bytes(self.array()?))
    }

    fn u64(&mut self) -> BatchResult<u64> {
        Ok(u64::from_be_bytes(self.array()?))
    }

    fn short_string(&mut self, field: &'static str) -> BatchResult<String> {
        let len = usize::from(self.u16()?);
        let bytes = self.take(len)?;
        std::str::from_utf8(bytes)
            .map(str::to_owned)
            .map_err(|_| BatchError::InvalidUtf8(field))
    }

    fn finish(self) -> BatchResult<()> {
        if self.offset == self.input.len() {
            Ok(())
        } else {
            Err(BatchError::TrailingBytes)
        }
    }
}

/// Stable self-conformance corpus support exposed only through the adapter SDK.
///
/// These vectors are emitted and checked by the reference implementation. They
/// are deterministic regression evidence, not an independent interoperability
/// oracle.
#[cfg(feature = "adapter-sdk")]
pub mod conformance {
    use super::*;

    /// Number of canonical standalone components with no authentication claim.
    pub const CANONICAL_COMPONENT_VECTOR_COUNT: usize = 4;
    /// Number of structurally valid vectors whose cryptography is unverified.
    pub const STRUCTURAL_UNVERIFIED_VECTOR_COUNT: usize = 8;
    /// Number of canonical format-3 components that remain pending without proof.
    pub const PENDING_VECTOR_COUNT: usize = 4;
    /// Number of malformed or profile-invalid rejected vectors.
    pub const REJECTED_VECTOR_COUNT: usize = 38;
    /// SHA-256 of the exact checked-in vector document.
    pub const VECTOR_DOCUMENT_SHA256_HEX: &str =
        "46b94199042576fdcbbfd7713f47d60995740e8cbdbb04e6459fef813a364979";

    const ENVELOPE3_MAGIC: &[u8; 8] = b"ASTRENV3";
    const ENVELOPE3_PUBLIC_HEADER_BYTES: usize = 44;
    const AEAD_TAG_BYTES: u32 = 16;
    const MERKLE_CASE_MAGIC: &[u8; 8] = b"ASTRMCV1";

    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    enum VectorKind {
        Preamble,
        Manifest,
        Leaf,
        Compact,
        ProofRoute,
        Envelope3Header,
        MerkleCase,
    }

    impl VectorKind {
        fn name(self) -> &'static str {
            match self {
                Self::Preamble => "preamble",
                Self::Manifest => "manifest",
                Self::Leaf => "leaf",
                Self::Compact => "compact",
                Self::ProofRoute => "proof-route",
                Self::Envelope3Header => "envelope3-header",
                Self::MerkleCase => "merkle-case",
            }
        }

        fn parse(value: &str) -> Result<Self, String> {
            match value {
                "preamble" => Ok(Self::Preamble),
                "manifest" => Ok(Self::Manifest),
                "leaf" => Ok(Self::Leaf),
                "compact" => Ok(Self::Compact),
                "proof-route" => Ok(Self::ProofRoute),
                "envelope3-header" => Ok(Self::Envelope3Header),
                "merkle-case" => Ok(Self::MerkleCase),
                _ => Err(format!("unknown batch vector kind {value}")),
            }
        }
    }

    struct Vector {
        disposition: &'static str,
        name: &'static str,
        kind: VectorKind,
        bytes: Vec<u8>,
    }

    /// Emits the deterministic semantic-v2 fixed-binary batch corpus.
    pub fn vector_document() -> Result<String, String> {
        let mut document = String::from(
            "# aster-batch-conformance-vectors/v1\tsemantic=2\tenvelope=3\toracle=self\tauthentication=not-provided\n",
        );
        for vector in vectors()? {
            document.push_str(vector.disposition);
            document.push('\t');
            document.push_str(vector.name);
            document.push('\t');
            document.push_str(vector.kind.name());
            document.push('\t');
            document.push_str(&to_hex(&vector.bytes));
            document.push('\n');
        }
        Ok(document)
    }

    /// Checks exact canonical re-encoding and each vector's expected disposition.
    ///
    /// This corpus intentionally has no `ACCEPT` disposition. Canonical
    /// components do not constitute application acceptance, and
    /// `STRUCTURAL-UNVERIFIED` proof-bearing vectors make no cryptographic
    /// authentication claim.
    ///
    /// A `PENDING` format-3 component must be canonical, but is deliberately
    /// not counted as accepted because its referenced proof is not present here.
    pub fn verify_vector_document(document: &str) -> Result<(usize, usize, usize, usize), String> {
        let mut canonical_components = 0usize;
        let mut structural_unverified = 0usize;
        let mut pending = 0usize;
        let mut rejected = 0usize;
        let mut merkle_depth_coverage = [false; 6];
        for (line_index, line) in document.lines().enumerate() {
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            let mut fields = line.split('\t');
            let disposition = field(&mut fields, line_index, "disposition")?;
            let name = field(&mut fields, line_index, "name")?;
            let kind = VectorKind::parse(field(&mut fields, line_index, "kind")?)?;
            let encoded = field(&mut fields, line_index, "bytes")?;
            if fields.next().is_some() {
                return Err(format!(
                    "batch vector row {} has extra fields",
                    line_index + 1
                ));
            }
            let bytes = from_hex(encoded).map_err(|error| format!("{name}: {error}"))?;
            match disposition {
                "CANONICAL-COMPONENT" => {
                    if !matches!(
                        kind,
                        VectorKind::Preamble | VectorKind::Manifest | VectorKind::Leaf
                    ) {
                        return Err(format!(
                            "{name}: only a non-authenticating standalone component may be CANONICAL-COMPONENT"
                        ));
                    }
                    let canonical = canonicalize(kind, &bytes)
                        .map_err(|error| format!("{name}: unexpected rejection: {error}"))?;
                    if canonical != bytes {
                        return Err(format!("{name}: canonical re-encoding changed bytes"));
                    }
                    canonical_components += 1;
                }
                "STRUCTURAL-UNVERIFIED" => {
                    if !matches!(kind, VectorKind::ProofRoute | VectorKind::MerkleCase) {
                        return Err(format!(
                            "{name}: STRUCTURAL-UNVERIFIED is limited to proof-bearing structures"
                        ));
                    }
                    let canonical = canonicalize(kind, &bytes)
                        .map_err(|error| format!("{name}: unexpected rejection: {error}"))?;
                    if canonical != bytes {
                        return Err(format!("{name}: canonical re-encoding changed bytes"));
                    }
                    if kind == VectorKind::MerkleCase {
                        let case = MerkleCase::decode(&bytes)
                            .map_err(|error| format!("{name}: invalid Merkle case: {error}"))?;
                        let count = case.manifest.preamble.item_count;
                        let depth = expected_proof_depth(count).map_err(show)?;
                        let expected_count = if depth == 1 {
                            2
                        } else {
                            (1u16 << (depth - 1)) + 1
                        };
                        if count != expected_count || case.selected_index != count - 1 {
                            return Err(format!(
                                "{name}: depth {depth} must use n={expected_count} and select its final real leaf"
                            ));
                        }
                        let covered = merkle_depth_coverage
                            .get_mut(depth - 1)
                            .ok_or_else(|| format!("{name}: unsupported Merkle depth {depth}"))?;
                        if *covered {
                            return Err(format!("{name}: duplicate Merkle depth {depth}"));
                        }
                        *covered = true;
                    }
                    structural_unverified += 1;
                }
                "PENDING" => {
                    if !matches!(kind, VectorKind::Compact | VectorKind::Envelope3Header) {
                        return Err(format!(
                            "{name}: only a proof-dependent format-3 component may be PENDING"
                        ));
                    }
                    let canonical = canonicalize(kind, &bytes)
                        .map_err(|error| format!("{name}: pending syntax rejected: {error}"))?;
                    if canonical != bytes {
                        return Err(format!(
                            "{name}: pending canonical re-encoding changed bytes"
                        ));
                    }
                    pending += 1;
                }
                "REJECT" => {
                    if canonicalize(kind, &bytes).is_ok() {
                        return Err(format!("{name}: malformed vector unexpectedly accepted"));
                    }
                    rejected += 1;
                }
                "ACCEPT" => {
                    return Err(format!(
                        "{name}: ACCEPT is forbidden because this corpus performs no provider authentication"
                    ));
                }
                _ => return Err(format!("{name}: unknown disposition {disposition}")),
            }
        }
        if (
            canonical_components,
            structural_unverified,
            pending,
            rejected,
        ) != (
            CANONICAL_COMPONENT_VECTOR_COUNT,
            STRUCTURAL_UNVERIFIED_VECTOR_COUNT,
            PENDING_VECTOR_COUNT,
            REJECTED_VECTOR_COUNT,
        ) {
            return Err(format!(
                "batch corpus counts changed: {canonical_components} canonical components, {structural_unverified} structural-unverified, {pending} pending, {rejected} rejected"
            ));
        }
        if !merkle_depth_coverage.into_iter().all(|covered| covered) {
            return Err("batch corpus does not cover every Merkle depth 1..6".to_owned());
        }
        let digest = to_hex(&sha256(document.as_bytes()));
        if digest != VECTOR_DOCUMENT_SHA256_HEX {
            return Err(format!(
                "batch corpus SHA-256 changed: expected {VECTOR_DOCUMENT_SHA256_HEX}, got {digest}"
            ));
        }
        Ok((
            canonical_components,
            structural_unverified,
            pending,
            rejected,
        ))
    }

    /// Serializes every batch size at both credential extremes and verifies the
    /// normative byte-accounting equations and headline values.
    pub fn verify_overhead_claims() -> Result<String, String> {
        for groups in [MIN_CREDENTIAL_GROUPS, MAX_CREDENTIAL_GROUPS] {
            for count in MIN_BATCH_ITEMS..=MAX_BATCH_ITEMS {
                let route = proof_route(count, groups, MAX_TOPIC_BYTES, MAX_SCOPE_BYTES)?;
                let route_bytes = route.encode().map_err(show)?;
                let authentication = compact(
                    count,
                    0,
                    [0x91; 32],
                    route.manifest.batch_id().map_err(show)?,
                )?;
                let compact_bytes = authentication.encode().map_err(show)?;
                let actual = route_bytes
                    .len()
                    .checked_add(PROOF_ENVELOPE_FIXED_OVERHEAD)
                    .and_then(|value| {
                        value.checked_add(usize::from(count).checked_mul(compact_bytes.len())?)
                    })
                    .ok_or_else(|| "actual overhead length overflow".to_owned())?;
                let expected =
                    expected_batch_auth_len(groups, MAX_TOPIC_BYTES, MAX_SCOPE_BYTES, count)
                        .map_err(show)?;
                if actual != expected {
                    return Err(format!(
                        "g={groups} n={count}: serialized {actual}, expected {expected}"
                    ));
                }
            }
        }

        let claims = [
            (expected_proof_envelope_len(256, 128, 128), 18_678usize),
            (expected_compact_auth_len(64), 324),
            (expected_batch_auth_len(256, 128, 128, 64), 39_414),
            (expected_batch_auth_len(1, 128, 128, 64), 31_254),
        ];
        for (actual, expected) in claims {
            if actual.map_err(show)? != expected {
                return Err(format!("overhead claim expected {expected}"));
            }
        }
        let singleton_256 = singleton_auth_len(256).map_err(show)? * 64;
        let singleton_1 = singleton_auth_len(1).map_err(show)? * 64;
        if singleton_256 != 1_168_000 || singleton_1 != 645_760 {
            return Err("singleton comparison claim changed".to_owned());
        }
        Ok("n=2..64; g=1/256; exact serialized overhead claims match".to_owned())
    }

    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    struct Envelope3Header {
        object_kind: u8,
        route_selector: [u8; 16],
        route_ciphertext_length: u32,
        content_ciphertext_length: u64,
    }

    impl Envelope3Header {
        fn validate(self) -> Result<(), String> {
            if !matches!(self.object_kind, 1 | OBJECT_KIND_BATCH_PROOF) {
                return Err(format!("invalid ASTRENV3 object kind {}", self.object_kind));
            }
            if self.route_ciphertext_length < AEAD_TAG_BYTES {
                return Err("ASTRENV3 route ciphertext is shorter than its tag".to_owned());
            }
            if self.object_kind == OBJECT_KIND_BATCH_PROOF && self.content_ciphertext_length != 0 {
                return Err("BatchProof ASTRENV3 content length is nonzero".to_owned());
            }
            if self.object_kind == 1 && self.content_ciphertext_length < u64::from(AEAD_TAG_BYTES) {
                return Err(
                    "compact ASTRENV3 content ciphertext is shorter than its tag".to_owned(),
                );
            }
            Ok(())
        }

        fn encode(self) -> Result<Vec<u8>, String> {
            self.validate()?;
            let mut out = Vec::with_capacity(ENVELOPE3_PUBLIC_HEADER_BYTES);
            out.extend_from_slice(ENVELOPE3_MAGIC);
            out.extend_from_slice(&ENVELOPE_FORMAT_VERSION.to_be_bytes());
            out.extend_from_slice(&SEMANTIC_PROTOCOL_VERSION.to_be_bytes());
            out.extend_from_slice(&CRYPTO_SUITE.to_be_bytes());
            out.push(self.object_kind);
            out.push(0);
            out.extend_from_slice(&self.route_selector);
            out.extend_from_slice(&self.route_ciphertext_length.to_be_bytes());
            out.extend_from_slice(&self.content_ciphertext_length.to_be_bytes());
            Ok(out)
        }

        fn decode(bytes: &[u8]) -> Result<Self, String> {
            if bytes.len() != ENVELOPE3_PUBLIC_HEADER_BYTES {
                return Err(format!(
                    "invalid ASTRENV3 public header length {}",
                    bytes.len()
                ));
            }
            if &bytes[..8] != ENVELOPE3_MAGIC {
                return Err("invalid ASTRENV3 magic".to_owned());
            }
            if u16::from_be_bytes([bytes[8], bytes[9]]) != ENVELOPE_FORMAT_VERSION {
                return Err("invalid ASTRENV3 envelope format".to_owned());
            }
            if u16::from_be_bytes([bytes[10], bytes[11]]) != SEMANTIC_PROTOCOL_VERSION {
                return Err("invalid ASTRENV3 semantic version".to_owned());
            }
            if u16::from_be_bytes([bytes[12], bytes[13]]) != CRYPTO_SUITE {
                return Err("invalid ASTRENV3 suite".to_owned());
            }
            if bytes[15] != 0 {
                return Err("invalid ASTRENV3 reserved byte".to_owned());
            }
            let value = Self {
                object_kind: bytes[14],
                route_selector: bytes[16..32]
                    .try_into()
                    .map_err(|_| "invalid ASTRENV3 selector".to_owned())?,
                route_ciphertext_length: u32::from_be_bytes(
                    bytes[32..36]
                        .try_into()
                        .map_err(|_| "invalid ASTRENV3 route length".to_owned())?,
                ),
                content_ciphertext_length: u64::from_be_bytes(
                    bytes[36..44]
                        .try_into()
                        .map_err(|_| "invalid ASTRENV3 content length".to_owned())?,
                ),
            };
            value.validate()?;
            Ok(value)
        }

        fn decode_for_semantic_version(
            bytes: &[u8],
            selected_semantic_version: u16,
        ) -> Result<Self, String> {
            if !matches!(
                selected_semantic_version,
                SEMANTIC_PROTOCOL_VERSION
                    | crate::MIN_CUSTODY_SEMANTIC_VERSION
                    | crate::crypto::SEMANTIC_PROTOCOL_V4
                    | crate::crypto::SEMANTIC_PROTOCOL_V5
                    | crate::crypto::SEMANTIC_PROTOCOL_V6
                    | crate::crypto::SEMANTIC_PROTOCOL_V7
                    | crate::crypto::SEMANTIC_PROTOCOL_V8
            ) {
                return Err(format!(
                    "semantic-v{selected_semantic_version} receiver rejects ASTRENV3"
                ));
            }
            Self::decode(bytes)
        }
    }

    /// Feeds raw ASTRENV3 bytes to the selected-version header decoder and
    /// proves that semantic v1 rejects them while semantic v2-v6 accept them.
    pub fn verify_semantic_v1_envelope_rejection() -> Result<String, String> {
        let header = Envelope3Header {
            object_kind: OBJECT_KIND_BATCH_PROOF,
            route_selector: [0xa3; 16],
            route_ciphertext_length: AEAD_TAG_BYTES,
            content_ciphertext_length: 0,
        };
        let bytes = header.encode()?;
        if Envelope3Header::decode_for_semantic_version(&bytes, SEMANTIC_PROTOCOL_VERSION)?
            != header
        {
            return Err("semantic-v2 ASTRENV3 decoder changed the header".to_owned());
        }
        if Envelope3Header::decode_for_semantic_version(
            &bytes,
            crate::MIN_CUSTODY_SEMANTIC_VERSION,
        )? != header
        {
            return Err("semantic-v3 ASTRENV3 decoder changed the header".to_owned());
        }
        if Envelope3Header::decode_for_semantic_version(
            &bytes,
            crate::crypto::SEMANTIC_PROTOCOL_V4,
        )? != header
        {
            return Err("semantic-v4 ASTRENV3 decoder changed the header".to_owned());
        }
        if Envelope3Header::decode_for_semantic_version(
            &bytes,
            crate::crypto::SEMANTIC_PROTOCOL_V5,
        )? != header
        {
            return Err("semantic-v5 ASTRENV3 decoder changed the header".to_owned());
        }
        if Envelope3Header::decode_for_semantic_version(
            &bytes,
            crate::crypto::SEMANTIC_PROTOCOL_V6,
        )? != header
        {
            return Err("semantic-v6 ASTRENV3 decoder changed the header".to_owned());
        }
        if Envelope3Header::decode_for_semantic_version(
            &bytes,
            crate::crypto::SEMANTIC_PROTOCOL_V7,
        )? != header
        {
            return Err("semantic-v7 ASTRENV3 decoder changed the header".to_owned());
        }
        if Envelope3Header::decode_for_semantic_version(
            &bytes,
            crate::crypto::SEMANTIC_PROTOCOL_V8,
        )? != header
        {
            return Err("semantic-v8 ASTRENV3 decoder changed the header".to_owned());
        }
        if Envelope3Header::decode_for_semantic_version(&bytes, 1).is_ok() {
            return Err("semantic-v1 decoder accepted raw ASTRENV3 bytes".to_owned());
        }
        Ok("semantic-v1 decoder rejected raw ASTRENV3 bytes".to_owned())
    }

    #[derive(Clone, Debug, Eq, PartialEq)]
    struct MerkleCaseItem {
        leaf: BatchLeaf,
        ciphertext: Vec<u8>,
    }

    /// Portable conformance container, not a protocol object.
    ///
    /// It carries the exact manifest, every leaf and ciphertext, and one
    /// compact path so an implementation can rebuild the complete padded tree
    /// and verify the selected leaf end to end.
    #[derive(Clone, Debug, Eq, PartialEq)]
    struct MerkleCase {
        manifest: BatchManifest,
        items: Vec<MerkleCaseItem>,
        selected_index: u16,
        authentication: CompactAuthentication,
    }

    impl MerkleCase {
        fn validate(&self) -> Result<(), String> {
            if self.items.len() != usize::from(self.manifest.preamble.item_count) {
                return Err("Merkle case item count does not match manifest".to_owned());
            }
            let leaves: Vec<_> = self.items.iter().map(|item| item.leaf.clone()).collect();
            for item in &self.items {
                item.leaf
                    .verify_ciphertext(&item.ciphertext)
                    .map_err(show)?;
            }
            let tree = BatchMerkleTree::build(&self.manifest.preamble, &leaves).map_err(show)?;
            if tree.root != self.manifest.merkle_root {
                return Err("Merkle case rebuilt root does not match manifest".to_owned());
            }
            let selected = self
                .items
                .get(usize::from(self.selected_index))
                .ok_or_else(|| "Merkle case selected index is out of range".to_owned())?;
            if selected.leaf.item_index != self.selected_index {
                return Err("Merkle case selected leaf index changed".to_owned());
            }
            if tree.path(self.selected_index).map_err(show)?
                != self.authentication.siblings.as_slice()
            {
                return Err("Merkle case path differs from complete-tree construction".to_owned());
            }
            verify_compact_commitment(
                &self.manifest,
                self.authentication.proof_envelope_id,
                &selected.leaf,
                &selected.ciphertext,
                &self.authentication,
            )
            .map(|_| ())
            .map_err(show)
        }

        fn encode(&self) -> Result<Vec<u8>, String> {
            self.validate()?;
            self.encode_components()
        }

        fn encode_components(&self) -> Result<Vec<u8>, String> {
            let manifest = self.manifest.encode().map_err(show)?;
            let authentication = self.authentication.encode().map_err(show)?;
            let mut encoded_items = Vec::with_capacity(self.items.len());
            for item in &self.items {
                encoded_items.push((item.leaf.encode().map_err(show)?, &item.ciphertext));
            }

            let mut out = Vec::new();
            out.extend_from_slice(MERKLE_CASE_MAGIC);
            put_u32(
                &mut out,
                u32::try_from(manifest.len())
                    .map_err(|_| "Merkle case manifest is too large".to_owned())?,
            );
            out.extend_from_slice(&manifest);
            put_u16(
                &mut out,
                u16::try_from(encoded_items.len())
                    .map_err(|_| "Merkle case has too many leaves".to_owned())?,
            );
            for (leaf, ciphertext) in encoded_items {
                put_u32(
                    &mut out,
                    u32::try_from(leaf.len())
                        .map_err(|_| "Merkle case leaf is too large".to_owned())?,
                );
                out.extend_from_slice(&leaf);
                put_u32(
                    &mut out,
                    u32::try_from(ciphertext.len())
                        .map_err(|_| "Merkle case ciphertext is too large".to_owned())?,
                );
                out.extend_from_slice(ciphertext);
            }
            put_u16(&mut out, self.selected_index);
            put_u32(
                &mut out,
                u32::try_from(authentication.len())
                    .map_err(|_| "Merkle case authentication is too large".to_owned())?,
            );
            out.extend_from_slice(&authentication);
            Ok(out)
        }

        fn decode(bytes: &[u8]) -> Result<Self, String> {
            let mut cursor = Cursor::new(bytes);
            if cursor.take(MERKLE_CASE_MAGIC.len()).map_err(show)? != MERKLE_CASE_MAGIC {
                return Err("invalid Merkle case magic".to_owned());
            }
            let manifest_len = usize::try_from(cursor.u32().map_err(show)?)
                .map_err(|_| "invalid manifest length")?;
            let manifest =
                BatchManifest::decode(cursor.take(manifest_len).map_err(show)?).map_err(show)?;
            let item_count = usize::from(cursor.u16().map_err(show)?);
            if !(usize::from(MIN_BATCH_ITEMS)..=usize::from(MAX_BATCH_ITEMS)).contains(&item_count)
            {
                return Err(format!("invalid Merkle case item count {item_count}"));
            }
            let mut items = Vec::with_capacity(item_count);
            for _ in 0..item_count {
                let leaf_len = usize::try_from(cursor.u32().map_err(show)?)
                    .map_err(|_| "invalid leaf length")?;
                let leaf = BatchLeaf::decode(cursor.take(leaf_len).map_err(show)?).map_err(show)?;
                let ciphertext_len = usize::try_from(cursor.u32().map_err(show)?)
                    .map_err(|_| "invalid ciphertext length")?;
                let ciphertext = cursor.take(ciphertext_len).map_err(show)?.to_vec();
                items.push(MerkleCaseItem { leaf, ciphertext });
            }
            let selected_index = cursor.u16().map_err(show)?;
            let authentication_len = usize::try_from(cursor.u32().map_err(show)?)
                .map_err(|_| "invalid authentication length")?;
            let authentication =
                CompactAuthentication::decode(cursor.take(authentication_len).map_err(show)?)
                    .map_err(show)?;
            cursor.finish().map_err(show)?;
            let value = Self {
                manifest,
                items,
                selected_index,
                authentication,
            };
            value.validate()?;
            Ok(value)
        }
    }

    fn vectors() -> Result<Vec<Vector>, String> {
        let event_min = preamble(DATA_CLASS_EVENT, 2, 1, 1);
        let state_max = preamble(0, 64, MAX_TOPIC_BYTES, MAX_SCOPE_BYTES);
        let manifest = BatchManifest {
            preamble: preamble(DATA_CLASS_EVENT, 3, 5, 5),
            merkle_root: [0x33; 32],
        };
        let leaf =
            BatchLeaf::from_ciphertext(0, [0x41; 32], vec![0x42], [0x43; 32], [0x44; 12], &[0x45])
                .map_err(show)?;
        let proof_min = proof_route(2, 1, 1, 1)?;
        let proof_max = proof_route(64, 256, 128, 128)?;
        let proof_route_length = u32::try_from(proof_min.encode().map_err(show)?.len())
            .map_err(|_| "proof route length does not fit u32".to_owned())?
            .checked_add(AEAD_TAG_BYTES)
            .ok_or_else(|| "proof route ciphertext length overflow".to_owned())?;
        let proof_header = Envelope3Header {
            object_kind: OBJECT_KIND_BATCH_PROOF,
            route_selector: [0x31; 16],
            route_ciphertext_length: proof_route_length,
            content_ciphertext_length: 0,
        };
        let compact_header = Envelope3Header {
            object_kind: 1,
            route_selector: [0x32; 16],
            route_ciphertext_length: 512,
            content_ciphertext_length: 64,
        };
        let merkle_specs = [
            ("merkle-depth1-n2", 2, 1),
            ("merkle-depth2-n3-padding", 3, 2),
            ("merkle-depth3-n5-padding", 5, 4),
            ("merkle-depth4-n9-padding", 9, 8),
            ("merkle-depth5-n17-padding", 17, 16),
            ("merkle-depth6-n33-padding", 33, 32),
        ];
        let merkle_cases = merkle_specs
            .iter()
            .map(|(_, count, selected_index)| merkle_case(*count, *selected_index))
            .collect::<Result<Vec<_>, _>>()?;

        let mut vectors = vec![
            canonical_component(
                "preamble-event-min",
                VectorKind::Preamble,
                event_min.encode().map_err(show)?,
            ),
            canonical_component(
                "preamble-state-max",
                VectorKind::Preamble,
                state_max.encode().map_err(show)?,
            ),
            canonical_component(
                "manifest-n3",
                VectorKind::Manifest,
                manifest.encode().map_err(show)?,
            ),
            canonical_component("leaf-min", VectorKind::Leaf, leaf.encode().map_err(show)?),
            structural_unverified(
                "proof-route-g1-structural-unverified",
                VectorKind::ProofRoute,
                proof_min.encode().map_err(show)?,
            ),
            structural_unverified(
                "proof-route-g256-structural-unverified",
                VectorKind::ProofRoute,
                proof_max.encode().map_err(show)?,
            ),
            pending(
                "compact-depth1",
                compact(2, 0, [0x51; 32], [0x52; 32])?
                    .encode()
                    .map_err(show)?,
            ),
            pending(
                "compact-depth6",
                compact(64, 63, [0x53; 32], [0x54; 32])?
                    .encode()
                    .map_err(show)?,
            ),
            pending_header("proof-envelope3-header", proof_header.encode()?),
            pending_header("compact-envelope3-header", compact_header.encode()?),
        ];
        for ((name, _, _), case) in merkle_specs.into_iter().zip(&merkle_cases) {
            vectors.push(structural_unverified(
                name,
                VectorKind::MerkleCase,
                case.encode()?,
            ));
        }

        let event_bytes = event_min.encode().map_err(show)?;
        let state_bytes = state_max.encode().map_err(show)?;
        let leaf_bytes = leaf.encode().map_err(show)?;
        let compact_bytes = compact(64, 0, [0x61; 32], [0x62; 32])?
            .encode()
            .map_err(show)?;
        let proof_bytes = proof_min.encode().map_err(show)?;
        let proof_header_bytes = proof_header.encode()?;
        let compact_header_bytes = compact_header.encode()?;
        let authority_signature_offset =
            5usize + credential_body_len(MIN_CREDENTIAL_GROUPS).map_err(show)?;
        let source_signature_offset = proof_bytes
            .len()
            .checked_sub(HYBRID_SIGNATURE_BYTES)
            .ok_or_else(|| "proof fixture is shorter than its source signature".to_owned())?;
        let mut invalid_padding_case = merkle_cases
            .last()
            .cloned()
            .ok_or_else(|| "missing depth-6 Merkle fixture".to_owned())?;
        invalid_padding_case.authentication.siblings[0][0] ^= 1;

        vectors.extend([
            reject_mutation(
                "preamble-batch-format",
                VectorKind::Preamble,
                &event_bytes,
                1,
            ),
            reject_mutation(
                "preamble-envelope-format",
                VectorKind::Preamble,
                &event_bytes,
                3,
            ),
            reject_mutation(
                "preamble-semantic-v1-downgrade",
                VectorKind::Preamble,
                &event_bytes,
                5,
            ),
            reject_mutation("preamble-suite", VectorKind::Preamble, &event_bytes, 7),
            reject_set(
                "preamble-topic-invalid-character",
                VectorKind::Preamble,
                &event_bytes,
                83,
                b'/',
            ),
            reject_set(
                "preamble-scope-dot-segment",
                VectorKind::Preamble,
                &event_bytes,
                86,
                b'.',
            ),
            reject_set(
                "preamble-data-class",
                VectorKind::Preamble,
                &event_bytes,
                16,
                4,
            ),
            reject_last_u16("preamble-count-one", VectorKind::Preamble, &event_bytes, 1),
            reject_last_u16(
                "preamble-count-sixty-five",
                VectorKind::Preamble,
                &event_bytes,
                65,
            ),
            reject_zero_range(
                "preamble-event-sequence-zero",
                VectorKind::Preamble,
                &event_bytes,
                event_bytes.len() - 10,
                8,
            ),
            reject_mutation(
                "preamble-non-event-sequence",
                VectorKind::Preamble,
                &event_bytes,
                16,
            ),
            reject_u64(
                "preamble-counter-overflow",
                VectorKind::Preamble,
                &state_bytes,
                state_bytes.len() - 18,
                u64::MAX - 62,
            ),
            reject_truncated("preamble-truncated", VectorKind::Preamble, &event_bytes),
            reject_trailing("preamble-trailing", VectorKind::Preamble, &event_bytes),
            reject_mutation("leaf-format", VectorKind::Leaf, &leaf_bytes, 1),
            reject_truncated("leaf-truncated", VectorKind::Leaf, &leaf_bytes),
            reject_trailing("leaf-trailing", VectorKind::Leaf, &leaf_bytes),
            reject_mutation("compact-mode", VectorKind::Compact, &compact_bytes, 0),
            reject_set(
                "compact-depth-zero",
                VectorKind::Compact,
                &compact_bytes,
                67,
                0,
            ),
            reject_set(
                "compact-depth-seven",
                VectorKind::Compact,
                &compact_bytes,
                67,
                7,
            ),
            reject_truncated("compact-truncated", VectorKind::Compact, &compact_bytes),
            reject_trailing("compact-trailing", VectorKind::Compact, &compact_bytes),
            reject_mutation("proof-route-kind", VectorKind::ProofRoute, &proof_bytes, 0),
            reject_mutation(
                "proof-route-credential-commitment",
                VectorKind::ProofRoute,
                &proof_bytes,
                5,
            ),
            reject_set(
                "proof-route-authority-p256-length",
                VectorKind::ProofRoute,
                &proof_bytes,
                authority_signature_offset + 1,
                63,
            ),
            reject_mutation(
                "proof-route-source-ml-dsa-length",
                VectorKind::ProofRoute,
                &proof_bytes,
                source_signature_offset + 2 + P256_SIGNATURE_BYTES + 3,
            ),
            reject_u32(
                "proof-route-credential-length-misaligned",
                VectorKind::ProofRoute,
                &proof_bytes,
                1,
                3_295,
            ),
            reject_truncated(
                "proof-route-truncated",
                VectorKind::ProofRoute,
                &proof_bytes,
            ),
            reject_trailing("proof-route-trailing", VectorKind::ProofRoute, &proof_bytes),
            reject_mutation(
                "envelope3-magic",
                VectorKind::Envelope3Header,
                &proof_header_bytes,
                0,
            ),
            reject_set(
                "envelope3-format2-downgrade",
                VectorKind::Envelope3Header,
                &proof_header_bytes,
                9,
                2,
            ),
            reject_set(
                "envelope3-semantic-v1-downgrade",
                VectorKind::Envelope3Header,
                &proof_header_bytes,
                11,
                1,
            ),
            reject_mutation(
                "envelope3-suite",
                VectorKind::Envelope3Header,
                &proof_header_bytes,
                13,
            ),
            reject_set(
                "envelope3-unknown-kind",
                VectorKind::Envelope3Header,
                &proof_header_bytes,
                14,
                2,
            ),
            reject_set(
                "envelope3-reserved",
                VectorKind::Envelope3Header,
                &proof_header_bytes,
                15,
                1,
            ),
            reject_u32(
                "envelope3-route-shorter-than-tag",
                VectorKind::Envelope3Header,
                &compact_header_bytes,
                32,
                AEAD_TAG_BYTES - 1,
            ),
            reject_set(
                "envelope3-proof-content-nonzero",
                VectorKind::Envelope3Header,
                &proof_header_bytes,
                43,
                1,
            ),
            reject(
                "merkle-padding-sibling-mismatch",
                VectorKind::MerkleCase,
                invalid_padding_case.encode_components()?,
            ),
        ]);
        Ok(vectors)
    }

    fn canonicalize(kind: VectorKind, bytes: &[u8]) -> Result<Vec<u8>, String> {
        match kind {
            VectorKind::Preamble => BatchPreamble::decode(bytes)
                .and_then(|value| value.encode())
                .map_err(show),
            VectorKind::Manifest => BatchManifest::decode(bytes)
                .and_then(|value| value.encode())
                .map_err(show),
            VectorKind::Leaf => BatchLeaf::decode(bytes)
                .and_then(|value| value.encode())
                .map_err(show),
            VectorKind::Compact => CompactAuthentication::decode(bytes)
                .and_then(|value| value.encode())
                .map_err(show),
            VectorKind::ProofRoute => BatchProofRoute::decode(bytes)
                .and_then(|value| value.encode())
                .map_err(show),
            VectorKind::Envelope3Header => Envelope3Header::decode(bytes)?.encode(),
            VectorKind::MerkleCase => MerkleCase::decode(bytes)?.encode(),
        }
    }

    fn preamble(data_class: u8, count: u16, topic_len: usize, scope_len: usize) -> BatchPreamble {
        BatchPreamble {
            data_class,
            credential_id: [0x11; 32],
            publisher: [0x22; 32],
            topic: "t".repeat(topic_len),
            scope: "s".repeat(scope_len),
            key_epoch: 7,
            first_causal_counter: 41,
            first_event_sequence: if data_class == DATA_CLASS_EVENT {
                91
            } else {
                0
            },
            item_count: count,
        }
    }

    fn proof_route(
        count: u16,
        groups: u16,
        topic_len: usize,
        scope_len: usize,
    ) -> Result<BatchProofRoute, String> {
        let credential_body = vec![0x71; credential_body_len(groups).map_err(show)?];
        let authority_signature = structurally_valid_hybrid_signature(0x72, 0x73);
        let mut preamble = preamble(DATA_CLASS_EVENT, count, topic_len, scope_len);
        preamble.credential_id =
            credential_id(&credential_body, &authority_signature).map_err(show)?;
        Ok(BatchProofRoute {
            credential_body,
            authority_signature,
            manifest: BatchManifest {
                preamble,
                merkle_root: [0x73; 32],
            },
            source_signature: structurally_valid_hybrid_signature(0x74, 0x75),
        })
    }

    fn merkle_case(count: u16, selected_index: u16) -> Result<MerkleCase, String> {
        let preamble = preamble(DATA_CLASS_EVENT, count, 5, 5);
        let items = (0..count)
            .map(|index| {
                let mut item_id = [0x81; 32];
                item_id[..2].copy_from_slice(&index.to_be_bytes());
                let ciphertext = vec![count as u8, index as u8, 0xc1];
                let leaf = BatchLeaf::from_ciphertext(
                    index,
                    item_id,
                    vec![0xa0, count as u8, index as u8],
                    [0x44; 32],
                    [index as u8; 12],
                    &ciphertext,
                )
                .map_err(show)?;
                Ok(MerkleCaseItem { leaf, ciphertext })
            })
            .collect::<Result<Vec<_>, String>>()?;
        let leaves: Vec<_> = items.iter().map(|item| item.leaf.clone()).collect();
        let tree = BatchMerkleTree::build(&preamble, &leaves).map_err(show)?;
        let manifest = BatchManifest {
            preamble,
            merkle_root: tree.root,
        };
        let authentication = CompactAuthentication {
            proof_envelope_id: [0x93; 32],
            batch_id: manifest.batch_id().map_err(show)?,
            item_index: selected_index,
            siblings: tree.path(selected_index).map_err(show)?.to_vec(),
            item_signature: [0x94; ITEM_SIGNATURE_BYTES],
        };
        let value = MerkleCase {
            manifest,
            items,
            selected_index,
            authentication,
        };
        value.validate()?;
        Ok(value)
    }

    fn compact(
        count: u16,
        item_index: u16,
        proof_envelope_id: Hash32,
        batch_id: Hash32,
    ) -> Result<CompactAuthentication, String> {
        let depth = expected_proof_depth(count).map_err(show)?;
        Ok(CompactAuthentication {
            proof_envelope_id,
            batch_id,
            item_index,
            siblings: (0..depth)
                .map(|level| {
                    let mut hash = [0u8; 32];
                    hash[..8].copy_from_slice(&(level as u64 + 1).to_be_bytes());
                    hash
                })
                .collect(),
            item_signature: [0x75; ITEM_SIGNATURE_BYTES],
        })
    }

    fn canonical_component(name: &'static str, kind: VectorKind, bytes: Vec<u8>) -> Vector {
        Vector {
            disposition: "CANONICAL-COMPONENT",
            name,
            kind,
            bytes,
        }
    }

    fn structural_unverified(name: &'static str, kind: VectorKind, bytes: Vec<u8>) -> Vector {
        Vector {
            disposition: "STRUCTURAL-UNVERIFIED",
            name,
            kind,
            bytes,
        }
    }

    fn pending(name: &'static str, bytes: Vec<u8>) -> Vector {
        Vector {
            disposition: "PENDING",
            name,
            kind: VectorKind::Compact,
            bytes,
        }
    }

    fn pending_header(name: &'static str, bytes: Vec<u8>) -> Vector {
        Vector {
            disposition: "PENDING",
            name,
            kind: VectorKind::Envelope3Header,
            bytes,
        }
    }

    fn reject(name: &'static str, kind: VectorKind, bytes: Vec<u8>) -> Vector {
        Vector {
            disposition: "REJECT",
            name,
            kind,
            bytes,
        }
    }

    fn reject_set(
        name: &'static str,
        kind: VectorKind,
        source: &[u8],
        offset: usize,
        value: u8,
    ) -> Vector {
        let mut bytes = source.to_vec();
        bytes[offset] = value;
        Vector {
            disposition: "REJECT",
            name,
            kind,
            bytes,
        }
    }

    fn reject_mutation(
        name: &'static str,
        kind: VectorKind,
        source: &[u8],
        offset: usize,
    ) -> Vector {
        let value = source[offset] ^ 1;
        reject_set(name, kind, source, offset, value)
    }

    fn reject_last_u16(name: &'static str, kind: VectorKind, source: &[u8], value: u16) -> Vector {
        let mut bytes = source.to_vec();
        let offset = bytes.len() - 2;
        bytes[offset..].copy_from_slice(&value.to_be_bytes());
        Vector {
            disposition: "REJECT",
            name,
            kind,
            bytes,
        }
    }

    fn reject_u64(
        name: &'static str,
        kind: VectorKind,
        source: &[u8],
        offset: usize,
        value: u64,
    ) -> Vector {
        let mut bytes = source.to_vec();
        bytes[offset..offset + 8].copy_from_slice(&value.to_be_bytes());
        Vector {
            disposition: "REJECT",
            name,
            kind,
            bytes,
        }
    }

    fn reject_u32(
        name: &'static str,
        kind: VectorKind,
        source: &[u8],
        offset: usize,
        value: u32,
    ) -> Vector {
        let mut bytes = source.to_vec();
        bytes[offset..offset + 4].copy_from_slice(&value.to_be_bytes());
        Vector {
            disposition: "REJECT",
            name,
            kind,
            bytes,
        }
    }

    fn reject_zero_range(
        name: &'static str,
        kind: VectorKind,
        source: &[u8],
        offset: usize,
        len: usize,
    ) -> Vector {
        let mut bytes = source.to_vec();
        bytes[offset..offset + len].fill(0);
        Vector {
            disposition: "REJECT",
            name,
            kind,
            bytes,
        }
    }

    fn reject_truncated(name: &'static str, kind: VectorKind, source: &[u8]) -> Vector {
        Vector {
            disposition: "REJECT",
            name,
            kind,
            bytes: source[..source.len() - 1].to_vec(),
        }
    }

    fn reject_trailing(name: &'static str, kind: VectorKind, source: &[u8]) -> Vector {
        let mut bytes = source.to_vec();
        bytes.push(0);
        Vector {
            disposition: "REJECT",
            name,
            kind,
            bytes,
        }
    }

    fn field<'a>(
        fields: &mut impl Iterator<Item = &'a str>,
        line_index: usize,
        name: &str,
    ) -> Result<&'a str, String> {
        fields
            .next()
            .ok_or_else(|| format!("batch vector row {} has no {name}", line_index + 1))
    }

    fn to_hex(bytes: &[u8]) -> String {
        const DIGITS: &[u8; 16] = b"0123456789abcdef";
        let mut output = String::with_capacity(bytes.len() * 2);
        for byte in bytes {
            output.push(char::from(DIGITS[usize::from(byte >> 4)]));
            output.push(char::from(DIGITS[usize::from(byte & 0x0f)]));
        }
        output
    }

    fn from_hex(value: &str) -> Result<Vec<u8>, &'static str> {
        if !value.len().is_multiple_of(2) {
            return Err("odd digit count");
        }
        value
            .as_bytes()
            .chunks_exact(2)
            .map(|pair| {
                let high = hex_nibble(pair[0]).ok_or("non-hex digit")?;
                let low = hex_nibble(pair[1]).ok_or("non-hex digit")?;
                Ok((high << 4) | low)
            })
            .collect()
    }

    fn hex_nibble(value: u8) -> Option<u8> {
        match value {
            b'0'..=b'9' => Some(value - b'0'),
            b'a'..=b'f' => Some(value - b'a' + 10),
            b'A'..=b'F' => Some(value - b'A' + 10),
            _ => None,
        }
    }

    fn show(error: BatchError) -> String {
        error.to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn preamble() -> BatchPreamble {
        BatchPreamble {
            data_class: DATA_CLASS_EVENT,
            credential_id: [0x11; 32],
            publisher: [0x22; 32],
            topic: "topic".to_owned(),
            scope: "scope".to_owned(),
            key_epoch: 7,
            first_causal_counter: 41,
            first_event_sequence: 91,
            item_count: 4,
        }
    }

    fn leaves(count: u16) -> Vec<(BatchLeaf, Vec<u8>)> {
        (0..count)
            .map(|index| {
                let ciphertext = vec![index as u8; usize::from(index) + 1];
                let mut item_id = [0u8; 32];
                item_id[..2].copy_from_slice(&index.to_be_bytes());
                let leaf = BatchLeaf::from_ciphertext(
                    index,
                    item_id,
                    vec![0xa0, index as u8],
                    [0x44; 32],
                    [index as u8; 12],
                    &ciphertext,
                )
                .unwrap();
                (leaf, ciphertext)
            })
            .collect()
    }

    fn proof_route(count: u16, groups: u16, topic_len: usize, scope_len: usize) -> BatchProofRoute {
        let credential_body = vec![0x51; credential_body_len(groups).unwrap()];
        let authority_signature = structurally_valid_hybrid_signature(0x52, 0x53);
        let mut preamble = preamble();
        preamble.item_count = count;
        preamble.topic = "t".repeat(topic_len);
        preamble.scope = "s".repeat(scope_len);
        preamble.credential_id = credential_id(&credential_body, &authority_signature).unwrap();
        BatchProofRoute {
            credential_body,
            authority_signature,
            manifest: BatchManifest {
                preamble,
                merkle_root: [0x53; 32],
            },
            source_signature: structurally_valid_hybrid_signature(0x54, 0x55),
        }
    }

    fn compact_auth(
        count: u16,
        item_index: u16,
        proof_id: Hash32,
        batch_id: Hash32,
    ) -> CompactAuthentication {
        let depth = expected_proof_depth(count).unwrap();
        CompactAuthentication {
            proof_envelope_id: proof_id,
            batch_id,
            item_index,
            siblings: (0..depth)
                .map(|level| {
                    let mut hash = [0u8; 32];
                    hash[..8].copy_from_slice(&(level as u64 + 1).to_be_bytes());
                    hash
                })
                .collect(),
            item_signature: [0x61; ITEM_SIGNATURE_BYTES],
        }
    }

    #[test]
    fn manifest_codec_is_exact_and_round_trips() {
        let manifest = BatchManifest {
            preamble: preamble(),
            merkle_root: [0x33; 32],
        };
        let encoded = manifest.encode().unwrap();
        assert_eq!(encoded.len(), 143 + "topic".len() + "scope".len());
        assert_eq!(BatchManifest::decode(&encoded).unwrap(), manifest);
        let preamble_bytes = manifest.preamble.encode().unwrap();
        assert_eq!(
            BatchPreamble::decode(&preamble_bytes).unwrap(),
            manifest.preamble
        );
        assert_eq!(
            manifest.batch_id().unwrap(),
            hash_domain(BATCH_ID_DOMAIN, &encoded).unwrap()
        );
        assert_eq!(
            manifest.signature_digest().unwrap(),
            hash_domain(BATCH_SIGNATURE_DOMAIN, &encoded).unwrap()
        );
    }

    #[test]
    fn manifest_decode_rejects_mutation_truncation_and_trailing_bytes() {
        let encoded = BatchManifest {
            preamble: preamble(),
            merkle_root: [0x33; 32],
        }
        .encode()
        .unwrap();
        for (offset, field) in [
            (0, "batch format"),
            (2, "envelope format"),
            (4, "semantic protocol"),
            (6, "crypto suite"),
            (8, "hash algorithm"),
            (10, "tree algorithm"),
            (12, "batch signature algorithm"),
            (14, "item signature algorithm"),
        ] {
            let mut mutated = encoded.clone();
            mutated[offset + 1] ^= 1;
            assert_eq!(
                BatchManifest::decode(&mutated),
                Err(BatchError::InvalidConstant(field))
            );
        }
        assert_eq!(
            BatchManifest::decode(&encoded[..encoded.len() - 1]),
            Err(BatchError::Truncated)
        );
        let mut extended = encoded;
        extended.push(0);
        assert_eq!(
            BatchManifest::decode(&extended),
            Err(BatchError::TrailingBytes)
        );
    }

    #[test]
    fn complete_tree_paths_verify_for_every_item_count() {
        for count in MIN_BATCH_ITEMS..=MAX_BATCH_ITEMS {
            let mut preamble = preamble();
            preamble.item_count = count;
            let fixtures = leaves(count);
            let leaves: Vec<_> = fixtures.iter().map(|(leaf, _)| leaf.clone()).collect();
            let tree = BatchMerkleTree::build(&preamble, &leaves).unwrap();
            let manifest = BatchManifest {
                preamble,
                merkle_root: tree.root,
            };
            for (leaf, ciphertext) in &fixtures {
                leaf.verify_ciphertext(ciphertext).unwrap();
                let path = tree.path(leaf.item_index).unwrap();
                assert_eq!(path.len(), expected_proof_depth(count).unwrap());
                verify_inclusion_path(&manifest, leaf, path).unwrap();
            }
        }
    }

    #[test]
    fn inclusion_path_rejects_depth_mutation_reordering_and_superfluous_nodes() {
        let mut preamble = preamble();
        preamble.item_count = 5;
        let leaves: Vec<_> = leaves(5).into_iter().map(|(leaf, _)| leaf).collect();
        let tree = BatchMerkleTree::build(&preamble, &leaves).unwrap();
        let manifest = BatchManifest {
            preamble,
            merkle_root: tree.root,
        };
        let leaf = &leaves[0];
        let path = tree.path(0).unwrap();

        assert!(matches!(
            verify_inclusion_path(&manifest, leaf, &path[..path.len() - 1]),
            Err(BatchError::InvalidProofDepth { .. })
        ));
        let mut mutated = path.to_vec();
        mutated[0][0] ^= 1;
        assert_eq!(
            verify_inclusion_path(&manifest, leaf, &mutated),
            Err(BatchError::MerkleRootMismatch)
        );
        let mut reordered = path.to_vec();
        reordered.swap(0, 1);
        assert_eq!(
            verify_inclusion_path(&manifest, leaf, &reordered),
            Err(BatchError::MerkleRootMismatch)
        );
        let mut superfluous = path.to_vec();
        superfluous.push([0x99; 32]);
        assert!(matches!(
            verify_inclusion_path(&manifest, leaf, &superfluous),
            Err(BatchError::InvalidProofDepth { .. })
        ));
    }

    #[test]
    fn leaf_codec_commits_to_exact_header_and_ciphertext() {
        let ciphertext = b"ciphertext";
        let leaf = BatchLeaf::from_ciphertext(
            1,
            [0x11; 32],
            b"canonical-header".to_vec(),
            [0x22; 32],
            [0x33; 12],
            ciphertext,
        )
        .unwrap();
        let encoded = leaf.encode().unwrap();
        assert_eq!(encoded.len(), 124 + b"canonical-header".len());
        assert_eq!(BatchLeaf::decode(&encoded).unwrap(), leaf);
        leaf.verify_ciphertext(ciphertext).unwrap();

        let mut wrong = ciphertext.to_vec();
        wrong[0] ^= 1;
        assert_eq!(
            leaf.verify_ciphertext(&wrong),
            Err(BatchError::CiphertextHashMismatch)
        );
        assert_eq!(
            leaf.verify_ciphertext(&wrong[..wrong.len() - 1]),
            Err(BatchError::CiphertextLengthMismatch)
        );

        let mut header_mutation = leaf.clone();
        header_mutation.canonical_header[0] ^= 1;
        assert_ne!(
            header_mutation.leaf_hash().unwrap(),
            leaf.leaf_hash().unwrap()
        );
    }

    #[test]
    fn compact_authentication_codec_is_exact_and_strict() {
        for count in MIN_BATCH_ITEMS..=MAX_BATCH_ITEMS {
            let authentication = compact_auth(count, 0, [0x71; 32], [0x72; 32]);
            let encoded = authentication.encode().unwrap();
            assert_eq!(encoded.len(), expected_compact_auth_len(count).unwrap());
            assert_eq!(
                CompactAuthentication::decode(&encoded).unwrap(),
                authentication
            );

            let mut wrong_mode = encoded.clone();
            wrong_mode[0] = 0;
            assert_eq!(
                CompactAuthentication::decode(&wrong_mode),
                Err(BatchError::InvalidAuthMode(0))
            );
            assert_eq!(
                CompactAuthentication::decode(&encoded[..encoded.len() - 1]),
                Err(BatchError::Truncated)
            );
            let mut trailing = encoded;
            trailing.push(0);
            assert_eq!(
                CompactAuthentication::decode(&trailing),
                Err(BatchError::TrailingBytes)
            );
        }

        let repeated_hashes_are_structurally_valid = CompactAuthentication {
            proof_envelope_id: [0; 32],
            batch_id: [0; 32],
            item_index: 0,
            siblings: vec![[1; 32], [1; 32]],
            item_signature: [0; ITEM_SIGNATURE_BYTES],
        };
        assert!(repeated_hashes_are_structurally_valid.encode().is_ok());
    }

    #[test]
    fn proof_route_codec_enforces_structural_signature_framing_and_credential_commitment() {
        for groups in [MIN_CREDENTIAL_GROUPS, MAX_CREDENTIAL_GROUPS] {
            let route = proof_route(64, groups, MAX_TOPIC_BYTES, MAX_SCOPE_BYTES);
            let encoded = route.encode().unwrap();
            assert_eq!(
                encoded.len() + PROOF_ENVELOPE_FIXED_OVERHEAD,
                expected_proof_envelope_len(groups, MAX_TOPIC_BYTES, MAX_SCOPE_BYTES).unwrap()
            );
            assert_eq!(BatchProofRoute::decode(&encoded).unwrap(), route);
            assert_eq!(proof_envelope_id(&encoded), sha256(&encoded));

            let mut credential_mutation = encoded.clone();
            credential_mutation[5] ^= 1;
            assert_eq!(
                BatchProofRoute::decode(&credential_mutation),
                Err(BatchError::CredentialIdMismatch)
            );
            assert_eq!(
                BatchProofRoute::decode(&encoded[..encoded.len() - 1]),
                Err(BatchError::Truncated)
            );
        }

        let mut short_signature = proof_route(2, 1, 1, 1);
        short_signature.source_signature.pop();
        assert_eq!(
            short_signature.encode(),
            Err(BatchError::InvalidSignatureLength {
                field: "source signature",
                actual: HYBRID_SIGNATURE_BYTES - 1,
            })
        );
        let mut wrong_p256_length = proof_route(2, 1, 1, 1);
        wrong_p256_length.source_signature[1] = 63;
        assert_eq!(
            wrong_p256_length.encode(),
            Err(BatchError::InvalidSignatureEncoding("source signature"))
        );
        let mut wrong_ml_dsa_length = proof_route(2, 1, 1, 1);
        wrong_ml_dsa_length.source_signature[2 + P256_SIGNATURE_BYTES + 3] ^= 1;
        assert_eq!(
            wrong_ml_dsa_length.encode(),
            Err(BatchError::InvalidSignatureEncoding("source signature"))
        );
        assert_eq!(
            credential_group_count(credential_body_len(1).unwrap() - 1),
            Err(BatchError::InvalidCredentialLength(3_295))
        );
        assert_eq!(
            credential_group_count(credential_body_len(256).unwrap() + 1),
            Err(BatchError::InvalidCredentialLength(11_457))
        );
    }

    #[test]
    fn compact_commitment_rejects_reference_path_and_ciphertext_mutations() {
        let mut preamble = preamble();
        preamble.item_count = 5;
        let fixtures = leaves(5);
        let leaves: Vec<_> = fixtures.iter().map(|(leaf, _)| leaf.clone()).collect();
        let tree = BatchMerkleTree::build(&preamble, &leaves).unwrap();
        let manifest = BatchManifest {
            preamble,
            merkle_root: tree.root,
        };
        let proof_id = [0x81; 32];
        let leaf = &leaves[2];
        let ciphertext = &fixtures[2].1;
        let authentication = CompactAuthentication {
            proof_envelope_id: proof_id,
            batch_id: manifest.batch_id().unwrap(),
            item_index: leaf.item_index,
            siblings: tree.path(leaf.item_index).unwrap().to_vec(),
            item_signature: [0x82; ITEM_SIGNATURE_BYTES],
        };
        let digest =
            verify_compact_commitment(&manifest, proof_id, leaf, ciphertext, &authentication)
                .unwrap();
        assert_eq!(
            digest,
            authentication
                .signature_digest(leaf.leaf_hash().unwrap())
                .unwrap()
        );

        let mut wrong_proof = authentication.clone();
        wrong_proof.proof_envelope_id[0] ^= 1;
        assert_eq!(
            verify_compact_commitment(&manifest, proof_id, leaf, ciphertext, &wrong_proof),
            Err(BatchError::ProofEnvelopeIdMismatch)
        );
        let mut wrong_batch = authentication.clone();
        wrong_batch.batch_id[0] ^= 1;
        assert_eq!(
            verify_compact_commitment(&manifest, proof_id, leaf, ciphertext, &wrong_batch),
            Err(BatchError::BatchIdMismatch)
        );
        let mut wrong_index = authentication.clone();
        wrong_index.item_index += 1;
        assert_eq!(
            verify_compact_commitment(&manifest, proof_id, leaf, ciphertext, &wrong_index),
            Err(BatchError::ItemIndexMismatch)
        );
        let mut wrong_path = authentication.clone();
        wrong_path.siblings[0][0] ^= 1;
        assert_eq!(
            verify_compact_commitment(&manifest, proof_id, leaf, ciphertext, &wrong_path),
            Err(BatchError::MerkleRootMismatch)
        );
        let mut wrong_ciphertext = ciphertext.clone();
        wrong_ciphertext[0] ^= 1;
        assert_eq!(
            verify_compact_commitment(
                &manifest,
                proof_id,
                leaf,
                &wrong_ciphertext,
                &authentication
            ),
            Err(BatchError::CiphertextHashMismatch)
        );
    }

    #[test]
    fn actual_serializations_match_overhead_formula_for_every_batch_size() {
        for groups in [MIN_CREDENTIAL_GROUPS, MAX_CREDENTIAL_GROUPS] {
            for count in MIN_BATCH_ITEMS..=MAX_BATCH_ITEMS {
                let route = proof_route(count, groups, MAX_TOPIC_BYTES, MAX_SCOPE_BYTES);
                let route_bytes = route.encode().unwrap();
                let authentication =
                    compact_auth(count, 0, [0x91; 32], route.manifest.batch_id().unwrap());
                let compact_bytes = authentication.encode().unwrap();
                let actual = route_bytes.len()
                    + PROOF_ENVELOPE_FIXED_OVERHEAD
                    + usize::from(count) * compact_bytes.len();
                assert_eq!(
                    actual,
                    expected_batch_auth_len(groups, MAX_TOPIC_BYTES, MAX_SCOPE_BYTES, count)
                        .unwrap()
                );
            }
        }

        let batch_256 = expected_batch_auth_len(256, 128, 128, 64).unwrap();
        assert_eq!(expected_proof_envelope_len(256, 128, 128).unwrap(), 18_678);
        assert_eq!(expected_compact_auth_len(64).unwrap(), 324);
        assert_eq!(batch_256, 39_414);
        assert_eq!(singleton_auth_len(256).unwrap() * 64, 1_168_000);
        assert_eq!(batch_256 + singleton_auth_len(256).unwrap() * 64, 1_207_414);

        let batch_1 = expected_batch_auth_len(1, 128, 128, 64).unwrap();
        assert_eq!(batch_1, 31_254);
        assert_eq!(singleton_auth_len(1).unwrap() * 64, 645_760);
        assert_eq!(batch_1 + singleton_auth_len(1).unwrap() * 64, 677_014);
    }

    #[test]
    fn preamble_rejects_count_class_sequence_and_range_overflow() {
        let mut value = preamble();
        value.item_count = 1;
        assert_eq!(value.validate(), Err(BatchError::InvalidItemCount(1)));
        value = preamble();
        value.data_class = 4;
        assert_eq!(value.validate(), Err(BatchError::InvalidDataClass(4)));
        value = preamble();
        value.data_class = 0;
        assert_eq!(value.validate(), Err(BatchError::InvalidEventSequence));
        value.first_event_sequence = 0;
        value.first_causal_counter = u64::MAX - 1;
        assert_eq!(value.validate(), Err(BatchError::CounterRangeOverflow));
        value = preamble();
        value.first_event_sequence = u64::MAX - 1;
        assert_eq!(value.validate(), Err(BatchError::CounterRangeOverflow));
    }

    #[test]
    fn preamble_enforces_canonical_topic_and_scope_grammar() {
        for topic in ["bad/topic", "has space", "café"] {
            let mut value = preamble();
            value.topic = topic.to_owned();
            assert_eq!(value.validate(), Err(BatchError::InvalidTopicSyntax));
        }
        for scope in [
            "/root",
            "root/",
            "root//leaf",
            ".",
            "..",
            "a/./b",
            "a/../b",
            "café",
        ] {
            let mut value = preamble();
            value.scope = scope.to_owned();
            assert_eq!(value.validate(), Err(BatchError::InvalidScopeSyntax));
        }
        for (topic, scope) in [
            ("a", "a"),
            ("Aster.v2_test-1", "team/unit-1"),
            ("..", "a.b/c_d/e-f"),
        ] {
            let mut value = preamble();
            value.topic = topic.to_owned();
            value.scope = scope.to_owned();
            value.validate().unwrap();
        }
    }

    #[cfg(feature = "adapter-sdk")]
    #[test]
    fn adapter_conformance_corpus_and_overhead_claims_are_self_consistent() {
        let document = conformance::vector_document().unwrap();
        assert_eq!(
            document,
            include_str!("../../../conformance/vectors/batch-semantic-v2.tsv")
        );
        assert!(!document.lines().any(|line| line.starts_with("ACCEPT\t")));
        for name in [
            "merkle-depth1-n2",
            "merkle-depth2-n3-padding",
            "merkle-depth3-n5-padding",
            "merkle-depth4-n9-padding",
            "merkle-depth5-n17-padding",
            "merkle-depth6-n33-padding",
        ] {
            assert!(document.contains(name));
        }
        assert_eq!(
            conformance::verify_vector_document(&document).unwrap(),
            (
                conformance::CANONICAL_COMPONENT_VECTOR_COUNT,
                conformance::STRUCTURAL_UNVERIFIED_VECTOR_COUNT,
                conformance::PENDING_VECTOR_COUNT,
                conformance::REJECTED_VECTOR_COUNT,
            )
        );
        let forged_accept = document.replacen(
            "STRUCTURAL-UNVERIFIED\tproof-route-g1-structural-unverified",
            "ACCEPT\tproof-route-g1-structural-unverified",
            1,
        );
        assert!(
            conformance::verify_vector_document(&forged_accept)
                .unwrap_err()
                .contains("ACCEPT is forbidden")
        );
        assert!(conformance::verify_overhead_claims().is_ok());
        assert!(conformance::verify_semantic_v1_envelope_rejection().is_ok());
    }
}
